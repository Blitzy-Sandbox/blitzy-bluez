//! BLE-MIDI bridge profile plugin.
//!
//! Bridges a BLE MIDI I/O GATT characteristic (UUID
//! `03B80E5A-EDE8-4B33-A751-6CE34EC4C700`) to ALSA Sequencer ports, enabling
//! BLE MIDI peripherals to appear as standard ALSA MIDI devices.
//!
//! This module is the Rust rewrite of `profiles/midi/midi.c` and
//! `profiles/midi/libmidi.c`/`libmidi.h`.  It replaces:
//!
//! - **C parser library** (`libmidi`) → [`MidiReadParser`], [`MidiWriteParser`]
//! - **C profile implementation** (`midi.c`) → [`Midi`] context, lifecycle
//!   callbacks, ALSA integration, GATT interaction
//! - **C plugin registration** (`BLUETOOTH_PLUGIN_DEFINE`) →
//!   `inventory::submit!` with [`PluginDesc`]
//!
//! # Architecture
//!
//! ```text
//!  BLE peripheral ──► GATT notify ──► MidiReadParser ──► ALSA sequencer
//!  BLE peripheral ◄── GATT write  ◄── MidiWriteParser ◄── ALSA sequencer
//! ```
//!
//! ## BLE-MIDI packet format
//!
//! Each BLE-MIDI packet begins with a header byte whose bit 7 is 1 and whose
//! lower 6 bits carry the high portion of a 13-bit millisecond timestamp.
//! Subsequent groups consist of an optional timestamp-low byte (bit 7 set),
//! an optional MIDI status byte, and zero or more data bytes.  Running status
//! and SysEx spanning multiple BLE packets are both supported.
//!
//! ## Design decisions
//!
//! - MIDI byte ↔ ALSA `Event` conversion is implemented in **pure safe Rust**
//!   rather than via the ALSA `snd_midi_event` API.  This avoids the
//!   non-`Send` raw-pointer wrapper (`MidiEvent`) and eliminates all `unsafe`
//!   blocks in this module, keeping them confined to the designated FFI
//!   boundary crate (`bluez-shared/src/sys/`).
//! - ALSA `Event` fields (source, dest, queue) are manipulated through the
//!   safe `set_source()`, `set_subs()`, and `set_direct()` methods.

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use alsa::Direction;
use alsa::PollDescriptors;
use alsa::seq::{EvCtrl, EvNote, EvQueueControl, Event, EventType, PortCap, PortType, Seq};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::GattDb;
use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::util::uuid::BtUuid;

use crate::error::BtdError;
use crate::log::{btd_debug, btd_error};
use crate::profile::{
    BTD_PROFILE_BEARER_LE, BtdProfile, btd_profile_register, btd_profile_unregister,
};

// ===========================================================================
// Constants
// ===========================================================================

/// MIDI GATT Service UUID.
pub const MIDI_UUID: &str = "03B80E5A-EDE8-4B33-A751-6CE34EC4C700";

/// MIDI I/O Characteristic UUID.
pub const MIDI_IO_UUID: &str = "7772E5DB-3868-4112-A1A9-F2669D106BF3";

/// Maximum SysEx buffer size for accumulation across BLE packets.
const MIDI_SYSEX_MAX_SIZE: usize = 4096;

/// Maximum BLE device name length used for ALSA port naming.
const MAX_NAME_LENGTH: usize = 248;

// ===========================================================================
// ALSA sequencer event-type integer values for `set_client_event_filter`.
// ===========================================================================

const EVENT_FILTER_LIST: &[EventType] = &[
    EventType::Noteoff,
    EventType::Noteon,
    EventType::Keypress,
    EventType::Controller,
    EventType::Pgmchange,
    EventType::Chanpress,
    EventType::Pitchbend,
    EventType::Sysex,
    EventType::Qframe,
    EventType::Songpos,
    EventType::Songsel,
    EventType::TuneRequest,
    EventType::Clock,
    EventType::Start,
    EventType::Continue,
    EventType::Stop,
    EventType::Sensing,
    EventType::Reset,
    EventType::Control14,
    EventType::Nonregparam,
    EventType::Regparam,
];

// ===========================================================================
// Static state — per-device MIDI contexts and stored profile
// ===========================================================================

/// Per-device MIDI contexts, keyed by Bluetooth address.
///
/// Access is synchronised with `std::sync::Mutex` (never held across await).
static MIDI_STATE: LazyLock<StdMutex<HashMap<BdAddr, Arc<StdMutex<Midi>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Stored profile definition for unregistration during plugin exit.
static MIDI_PROFILE: LazyLock<StdMutex<Option<BtdProfile>>> = LazyLock::new(|| StdMutex::new(None));

// ===========================================================================
// MidiReadParser — BLE-MIDI → ALSA direction
// ===========================================================================

/// Parser for incoming BLE-MIDI packets, converting them to ALSA sequencer
/// events via pure-Rust MIDI message decoding.
///
/// Implements the BLE-MIDI packet framing described in the Apple Bluetooth
/// Low Energy MIDI specification §2 — header byte, timestamp bytes, running
/// status, and SysEx continuation across packets.
pub struct MidiReadParser {
    /// Timestamp low byte from the most recent timestamp field.
    tstamp: u8,
    /// Accumulated 13-bit BLE-MIDI timestamp.
    timestamp: u16,
    /// Whether a SysEx message has been started but not yet terminated.
    sysex_started: bool,
    /// Running-status byte (the most recent channel status byte).
    running_status: u8,
    /// SysEx accumulation buffer for messages spanning multiple BLE packets.
    sysex_buf: Vec<u8>,
}

impl Default for MidiReadParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MidiReadParser {
    /// Create a new read parser with zeroed state.
    pub fn new() -> Self {
        Self {
            tstamp: 0,
            timestamp: 0,
            sysex_started: false,
            running_status: 0,
            sysex_buf: Vec::with_capacity(MIDI_SYSEX_MAX_SIZE),
        }
    }

    /// Reset the parser state between BLE connections.
    pub fn midi_read_reset(&mut self) {
        self.tstamp = 0;
        self.timestamp = 0;
        self.sysex_started = false;
        self.running_status = 0;
        self.sysex_buf.clear();
    }

    /// Parse a BLE-MIDI packet and produce ALSA sequencer events.
    ///
    /// Returns a `Vec` of owned `Event<'static>` values.  Each entry is one
    /// complete MIDI message decoded from the BLE-MIDI framing.
    ///
    /// Mirrors the C `midi_read_raw()` function from `libmidi.c`.
    pub fn midi_read_raw(&mut self, data: &[u8]) -> Vec<Event<'static>> {
        let mut events: Vec<Event<'static>> = Vec::new();
        let len = data.len();

        // A valid BLE-MIDI packet must be at least 3 bytes:
        //   header + timestamp_low + at least one MIDI byte
        if len < 3 {
            return events;
        }

        // Byte 0: header — bit 7 = 1, bits 5-0 = timestamp high 6 bits.
        self.timestamp = (u16::from(data[0]) & 0x3F) << 7;
        let mut i: usize = 1;

        while i < len {
            // Check for timestamp-low byte: bit 7 set and not a MIDI status
            // byte.  In the BLE-MIDI spec, a byte with bit 7 set that follows
            // the header or a completed message is always a timestamp byte
            // (even if it falls in the 0x80-0xBF range that overlaps with
            // channel status bytes).
            if data[i] & 0x80 != 0 && !self.sysex_started {
                // Could be timestamp-low or a new status byte.
                // BLE-MIDI rule: if we're expecting a timestamp (start of a
                // new message group), treat the byte as timestamp-low.
                if self.next_is_timestamp(data, i) {
                    self.tstamp = data[i] & 0x7F;
                    self.timestamp = (self.timestamp & 0x1F80) | u16::from(self.tstamp);
                    i += 1;
                    if i >= len {
                        break;
                    }
                }
            }

            // SysEx continuation: accumulate data bytes until F7.
            if self.sysex_started {
                while i < len {
                    let b = data[i];
                    if b == 0xF7 {
                        // SysEx end.
                        self.sysex_buf.push(0xF7);
                        self.sysex_started = false;
                        i += 1;
                        // Emit the complete SysEx event.
                        let sysex_data = std::mem::take(&mut self.sysex_buf);
                        events.push(Event::new_ext(EventType::Sysex, sysex_data));
                        break;
                    } else if is_midi_realtime(b) {
                        // Real-time messages can appear inside SysEx.
                        if let Some(ev) = realtime_to_event(b) {
                            events.push(ev);
                        }
                        i += 1;
                    } else if b & 0x80 != 0 {
                        // Timestamp byte inside SysEx — skip it.
                        self.tstamp = b & 0x7F;
                        self.timestamp = (self.timestamp & 0x1F80) | u16::from(self.tstamp);
                        i += 1;
                    } else {
                        // SysEx data byte.
                        if self.sysex_buf.len() < MIDI_SYSEX_MAX_SIZE {
                            self.sysex_buf.push(b);
                        }
                        i += 1;
                    }
                }
                continue;
            }

            if i >= len {
                break;
            }

            let b = data[i];

            // New status byte?
            if b & 0x80 != 0 {
                if b == 0xF0 {
                    // SysEx start.
                    self.sysex_started = true;
                    self.sysex_buf.clear();
                    self.sysex_buf.push(0xF0);
                    i += 1;
                    continue;
                }

                if is_midi_realtime(b) {
                    // Real-time status — emit immediately.
                    if let Some(ev) = realtime_to_event(b) {
                        events.push(ev);
                    }
                    i += 1;
                    continue;
                }

                // System common or channel status.
                let status = b;
                i += 1;

                // Update running status for channel messages.
                if (0x80..=0xEF).contains(&status) {
                    self.running_status = status;
                }

                let needed = midi_data_byte_count(status);
                let mut data_bytes = [0u8; 2];
                let mut got = 0usize;
                for _ in 0..needed {
                    if i < len && data[i] & 0x80 == 0 {
                        data_bytes[got] = data[i];
                        got += 1;
                        i += 1;
                    } else {
                        break;
                    }
                }

                if got == needed {
                    if let Some(ev) = midi_message_to_event(status, &data_bytes[..got]) {
                        events.push(ev);
                    }
                }
            } else {
                // Data byte without status → running status.
                if self.running_status == 0 {
                    // No running status set — skip.
                    i += 1;
                    continue;
                }

                let needed = midi_data_byte_count(self.running_status);
                let mut data_bytes = [0u8; 2];
                data_bytes[0] = b;
                let mut got = 1usize;
                i += 1;
                for _ in 1..needed {
                    if i < len && data[i] & 0x80 == 0 {
                        data_bytes[got] = data[i];
                        got += 1;
                        i += 1;
                    } else {
                        break;
                    }
                }

                if got == needed {
                    if let Some(ev) = midi_message_to_event(self.running_status, &data_bytes[..got])
                    {
                        events.push(ev);
                    }
                }
            }
        }

        events
    }

    /// Determine if the byte at position `i` is a timestamp-low byte
    /// rather than a MIDI status byte.
    ///
    /// BLE-MIDI disambiguation: after the header byte or after a completed
    /// message, a byte with bit 7 set is a timestamp.
    fn next_is_timestamp(&self, data: &[u8], i: usize) -> bool {
        let b = data[i];

        // Real-time status (0xF8-0xFF) is never a timestamp.
        if is_midi_realtime(b) {
            return false;
        }

        // If the next byte (i+1) exists and also has bit 7 set, the first
        // byte is likely a timestamp and the second is the status.
        if i + 1 < data.len() && data[i + 1] & 0x80 != 0 {
            return true;
        }

        // If the next byte is a data byte and this byte could be a channel
        // status, it might be a running-status continuation.  But in
        // standard BLE-MIDI framing, each message group starts with a
        // timestamp byte.
        true
    }
}

// ===========================================================================
// MidiWriteParser — ALSA → BLE-MIDI direction
// ===========================================================================

/// Parser for outgoing MIDI events from ALSA, converting them into BLE-MIDI
/// wire-format packets suitable for GATT write-without-response.
///
/// Mirrors the C `struct midi_write_parser` and the functions
/// `midi_read_ev()`, `midi_write_data()`, `midi_write_has_data()`,
/// `midi_write_reset()` from `libmidi.c`.
pub struct MidiWriteParser {
    /// Maximum BLE-MIDI payload size (MTU − 3).
    mtu: usize,
    /// Current timestamp low byte.
    tstamp: u8,
    /// Output buffer accumulating a BLE-MIDI packet.
    buf: Vec<u8>,
    /// Number of valid bytes in `buf`.
    buf_len: usize,
    /// Whether a SysEx is currently open in the output buffer.
    sysex_started: bool,
}

impl MidiWriteParser {
    /// Create a new write parser with the given MTU payload size.
    ///
    /// `mtu` should be `att_mtu − 3` (the usable payload after ATT header).
    pub fn new(mtu: usize) -> Self {
        Self { mtu, tstamp: 0, buf: vec![0u8; mtu.max(4)], buf_len: 0, sysex_started: false }
    }

    /// Convert an ALSA sequencer event into BLE-MIDI bytes, appending to the
    /// internal buffer.  When the buffer is full up to MTU, `flush_cb` is
    /// called with the current buffer contents, then the buffer is reset.
    ///
    /// Mirrors the C `midi_read_ev()` from `libmidi.c`.
    pub fn midi_read_ev(&mut self, ev: &Event<'_>, mut flush_cb: impl FnMut(&[u8])) {
        let midi_bytes = event_to_midi_bytes(ev);
        if midi_bytes.is_empty() {
            return;
        }

        // Build BLE-MIDI timestamp bytes from monotonic clock.
        let ts = get_timestamp_millis();
        let ts_low: u8 = 0x80 | ((ts & 0x7F) as u8);
        let ts_high: u8 = 0x80 | (((ts >> 7) & 0x3F) as u8);

        let is_sysex_start = midi_bytes.first().copied() == Some(0xF0);
        let is_sysex_end = midi_bytes.last().copied() == Some(0xF7);

        if is_sysex_start {
            // SysEx messages may span multiple BLE packets.
            self.flush_and_start_packet(&mut flush_cb, ts_high);
            // Timestamp + F0.
            self.try_push(ts_low);
            self.try_push(0xF0);
            self.sysex_started = true;

            // Write data bytes (skip F0 at start, maybe skip F7 at end).
            let end_idx = if is_sysex_end { midi_bytes.len() - 1 } else { midi_bytes.len() };
            for &b in &midi_bytes[1..end_idx] {
                if self.buf_len >= self.mtu {
                    flush_cb(&self.buf[..self.buf_len]);
                    self.buf_len = 0;
                    // Continuation packet header.
                    self.try_push(ts_high);
                }
                self.try_push(b);
            }

            if is_sysex_end {
                if self.buf_len + 2 > self.mtu {
                    flush_cb(&self.buf[..self.buf_len]);
                    self.buf_len = 0;
                    self.try_push(ts_high);
                }
                self.try_push(ts_low);
                self.try_push(0xF7);
                self.sysex_started = false;
            }
        } else {
            // Non-SysEx message.
            let needed = 1 + midi_bytes.len(); // timestamp-low + MIDI bytes
            if self.buf_len == 0 {
                // Start a new packet.
                self.try_push(ts_high);
            }
            if self.buf_len + needed > self.mtu {
                flush_cb(&self.buf[..self.buf_len]);
                self.buf_len = 0;
                self.try_push(ts_high);
            }
            self.try_push(ts_low);
            for &b in &midi_bytes {
                self.try_push(b);
            }
        }

        self.tstamp = ts_low;
    }

    /// Return a slice of the current buffered BLE-MIDI data.
    pub fn midi_write_data(&self) -> &[u8] {
        &self.buf[..self.buf_len]
    }

    /// Whether the buffer contains pending BLE-MIDI data.
    pub fn midi_write_has_data(&self) -> bool {
        self.buf_len > 0
    }

    /// Reset the output buffer for a new BLE packet.
    pub fn midi_write_reset(&mut self) {
        self.buf_len = 0;
        self.sysex_started = false;
    }

    // ---- helpers ----

    /// Push a byte into the output buffer if space remains.
    fn try_push(&mut self, b: u8) {
        if self.buf_len < self.buf.len() {
            self.buf[self.buf_len] = b;
            self.buf_len += 1;
        }
    }

    /// If the buffer is non-empty, flush it and start a new packet header.
    fn flush_and_start_packet(&mut self, flush_cb: &mut impl FnMut(&[u8]), ts_high: u8) {
        if self.buf_len > 0 {
            (flush_cb)(&self.buf[..self.buf_len]);
            self.buf_len = 0;
        }
        self.try_push(ts_high);
    }
}

// ===========================================================================
// Midi context
// ===========================================================================

/// Per-device BLE-MIDI bridge context.
///
/// Holds all state associated with one BLE MIDI connection: GATT handles,
/// ALSA sequencer resources, and the read/write parsers.
///
/// Replaces the C `struct midi` from `midi.c`.
pub struct Midi {
    /// The remote BLE device.
    pub device: Arc<tokio::sync::Mutex<crate::device::BtdDevice>>,
    /// The GATT database for this device (cloned Arc).
    pub gatt_db: Option<GattDb>,
    /// The GATT client for ATT operations.
    pub gatt_client: Option<Arc<BtGattClient>>,
    /// Registered GATT notification callback ID.
    pub notify_id: Option<u32>,
    /// MIDI I/O characteristic value handle.
    pub midi_io_handle: u16,
    /// ALSA sequencer handle.
    pub seq_handle: Option<Seq>,
    /// ALSA client ID.
    pub seq_client_id: i32,
    /// ALSA port ID.
    pub seq_port_id: i32,
    /// Incoming BLE → ALSA parser.
    pub midi_in: MidiReadParser,
    /// Outgoing ALSA → BLE parser.
    pub midi_out: MidiWriteParser,
    /// Tokio task monitoring ALSA sequencer fd for outgoing MIDI.
    pub io_task: Option<JoinHandle<()>>,
}

// ===========================================================================
// ALSA Sequencer Integration
// ===========================================================================

/// Open an ALSA sequencer, create a MIDI port, and configure the event
/// filter for all 21 relevant MIDI event types.
///
/// Returns `(Seq, client_id, port_id)` on success.
///
/// Mirrors the ALSA setup in the C `midi_accept()` function.
fn open_alsa_sequencer(device_name: &str) -> Result<(Seq, i32, i32), Box<dyn std::error::Error>> {
    let seq = Seq::open(None, Some(Direction::Playback), true)?;

    // Build the client name: "<device_name> Bluetooth" (capped).
    let safe_name = if device_name.len() > MAX_NAME_LENGTH {
        &device_name[..MAX_NAME_LENGTH]
    } else {
        device_name
    };
    let client_name = CString::new(format!("{safe_name} Bluetooth"))
        .unwrap_or_else(|_| CString::new("BLE-MIDI Bluetooth").expect("static"));
    seq.set_client_name(&client_name)?;

    let client_id = seq.client_id()?;

    // Create a port with read, write, and subscription capabilities.
    let port_name = CString::new(format!("{safe_name} Bluetooth"))
        .unwrap_or_else(|_| CString::new("BLE-MIDI Bluetooth").expect("static"));
    let caps = PortCap::READ | PortCap::WRITE | PortCap::SUBS_READ | PortCap::SUBS_WRITE;
    let ptype = PortType::MIDI_GENERIC | PortType::HARDWARE;
    let port_id = seq.create_simple_port(&port_name, caps, ptype)?;

    // Configure the client event filter for all 21 MIDI event types.
    for &et in EVENT_FILTER_LIST {
        let _ = seq.set_client_event_filter(et as i32);
    }

    btd_debug(
        0,
        &format!(
            "MIDI: opened ALSA seq client={client_id} port={port_id} for \
             \"{safe_name}\""
        ),
    );

    Ok((seq, client_id, port_id))
}

/// Spawn a tokio task that monitors the ALSA sequencer poll fd for incoming
/// ALSA events (i.e. MIDI data generated locally by other ALSA clients) and
/// forwards them as BLE-MIDI writes to the remote device.
///
/// Replaces the C `io_new(fd) + io_set_read_handler(io_cb)` pattern.
fn spawn_alsa_reader(midi_arc: Arc<StdMutex<Midi>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Obtain the poll fd from the ALSA sequencer.
        let raw_fd = {
            let midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());
            let seq = match midi.seq_handle.as_ref() {
                Some(s) => s,
                None => return,
            };
            let fds: Vec<libc::pollfd> = match (seq, Some(Direction::Capture)).get() {
                Ok(f) if !f.is_empty() => f,
                _ => return,
            };
            fds[0].fd
        };

        // Wrap the fd in an AsyncFd for non-blocking I/O with tokio.
        // SAFETY note: the fd is owned by the Seq handle, which lives for
        // the duration of the connection.  We must not close this fd
        // ourselves — see `std::mem::forget` below.
        let async_fd = match AsyncFd::new(raw_fd) {
            Ok(fd) => fd,
            Err(e) => {
                btd_error(0, &format!("MIDI: AsyncFd creation failed: {e}"));
                return;
            }
        };

        loop {
            // Wait for the fd to become readable.
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            // Read events from ALSA and convert to BLE-MIDI.
            //
            // To avoid overlapping borrows on `Midi` (seq_handle
            // immutably via `input`, midi_out mutably for encoding),
            // we temporarily take `midi_out` out of the struct using
            // `std::mem::replace`, process events, then put it back.
            {
                let mut midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());
                let client = match midi.gatt_client.as_ref() {
                    Some(c) => Arc::clone(c),
                    None => break,
                };
                let handle = midi.midi_io_handle;

                // Take midi_out temporarily so we can mutate it while
                // also reading from seq_handle.
                let mut writer = std::mem::replace(&mut midi.midi_out, MidiWriteParser::new(23));

                if let Some(ref seq) = midi.seq_handle {
                    let mut input = seq.input();
                    while let Ok(ev) = input.event_input() {
                        let wc = Arc::clone(&client);
                        writer.midi_read_ev(&ev, |pkt| {
                            wc.write_without_response(handle, false, pkt);
                        });
                    }
                }

                // Flush any remaining data in the write parser.
                if writer.midi_write_has_data() {
                    let data = writer.midi_write_data().to_vec();
                    client.write_without_response(handle, false, &data);
                    writer.midi_write_reset();
                }

                // Restore the writer into the struct.
                midi.midi_out = writer;
            }

            // Clear readiness so tokio re-polls the fd.
            guard.clear_ready();
        }

        // The AsyncFd must not close the fd — it is owned by the Seq.
        // Prevent the drop by forgetting the wrapper.
        std::mem::forget(async_fd);
    })
}

// ===========================================================================
// GATT Interaction
// ===========================================================================

/// After discovering the MIDI I/O characteristic, perform the initial read
/// and register for notifications.
///
/// Per BLE-MIDI 1.0 specification: the Central SHALL read the MIDI I/O
/// characteristic after connection establishment.
fn handle_midi_io(midi_arc: &Arc<StdMutex<Midi>>, value_handle: u16) {
    {
        let mut midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());
        midi.midi_io_handle = value_handle;
    }

    btd_debug(0, &format!("MIDI: I/O characteristic handle 0x{value_handle:04x}"));

    let client_arc = {
        let midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());
        match midi.gatt_client.as_ref() {
            Some(c) => Arc::clone(c),
            None => return,
        }
    };

    // Issue the mandatory initial read.
    let midi_for_read = Arc::clone(midi_arc);
    client_arc.read_value(
        value_handle,
        Box::new(move |success: bool, att_ecode: u8, _value: &[u8]| {
            if !success {
                btd_error(0, &format!("MIDI: initial read failed, ATT error 0x{att_ecode:02x}"));
                return;
            }
            btd_debug(0, "MIDI: initial read complete, registering notifications");

            // Register for notifications.
            let midi_for_notify = Arc::clone(&midi_for_read);
            let client = {
                let m = midi_for_read.lock().unwrap_or_else(|e| e.into_inner());
                match m.gatt_client.as_ref() {
                    Some(c) => Arc::clone(c),
                    None => return,
                }
            };

            let notify_midi = Arc::clone(&midi_for_notify);
            let register_cb: bluez_shared::gatt::client::RegisterCallback =
                Box::new(move |att_ecode: u16| {
                    if att_ecode != 0 {
                        btd_error(
                            0,
                            &format!(
                                "MIDI: notification registration failed, \
                                 ATT error 0x{att_ecode:04x}"
                            ),
                        );
                    } else {
                        btd_debug(0, "MIDI: notifications registered successfully");
                    }
                });

            let notify_cb: bluez_shared::gatt::client::NotifyCallback =
                Box::new(move |_value_handle: u16, value: &[u8]| {
                    midi_io_value_cb(&notify_midi, value);
                });

            let notify_id = client.register_notify(value_handle, register_cb, notify_cb);

            let mut m = midi_for_notify.lock().unwrap_or_else(|e| e.into_inner());
            m.notify_id = Some(notify_id);
        }),
    );
}

/// Notification callback for incoming BLE-MIDI data.
///
/// Called whenever the remote BLE MIDI device sends a notification on the
/// MIDI I/O characteristic.  Parses the BLE-MIDI packet and dispatches
/// the resulting ALSA sequencer events.
fn midi_io_value_cb(midi_arc: &Arc<StdMutex<Midi>>, value: &[u8]) {
    if value.len() < 3 {
        return;
    }

    let mut midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());
    let events = midi.midi_in.midi_read_raw(value);

    if let Some(ref seq) = midi.seq_handle {
        let port_id = midi.seq_port_id;
        for ev in events {
            let mut ev = ev;
            // Set source to our port, destination to subscribers, direct
            // delivery (no queue).
            ev.set_source(port_id);
            ev.set_subs();
            ev.set_direct();
            if let Err(e) = seq.event_output_direct(&mut ev) {
                btd_error(0, &format!("MIDI: event_output_direct failed: {e}"));
            }
        }
    }
}

/// Discover the MIDI I/O characteristic within the MIDI GATT service.
///
/// Iterates the characteristics of the given service attribute looking for
/// the MIDI I/O UUID.  On match, calls [`handle_midi_io`].
fn foreach_midi_service(
    midi_arc: &Arc<StdMutex<Midi>>,
    svc_attr: &bluez_shared::gatt::db::GattDbAttribute,
) {
    let midi_io_uuid: BtUuid = MIDI_IO_UUID.parse().expect("static MIDI_IO_UUID is valid");

    let svc = match svc_attr.get_service() {
        Some(s) => s,
        None => return,
    };
    svc.foreach_char(|char_attr: bluez_shared::gatt::db::GattDbAttribute| {
        if let Some(char_data) = char_attr.get_char_data() {
            if char_data.uuid == midi_io_uuid {
                btd_debug(
                    0,
                    &format!(
                        "MIDI: found I/O characteristic, value handle \
                         0x{:04x}",
                        char_data.value_handle
                    ),
                );
                handle_midi_io(midi_arc, char_data.value_handle);
            }
        }
    });
}

// ===========================================================================
// Profile Lifecycle Callbacks
// ===========================================================================

/// Probe callback: allocate per-device MIDI context.
///
/// Replaces C `midi_probe()`.
fn midi_probe(device: &Arc<tokio::sync::Mutex<crate::device::BtdDevice>>) -> Result<(), BtdError> {
    let addr = {
        let dev = device.blocking_lock();
        dev.address
    };
    btd_debug(0, &format!("MIDI: probe {addr}"));

    let mut state = MIDI_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if state.contains_key(&addr) {
        btd_debug(0, "MIDI: device already probed, skipping");
        return Ok(());
    }

    let midi = Midi {
        device: Arc::clone(device),
        gatt_db: None,
        gatt_client: None,
        notify_id: None,
        midi_io_handle: 0,
        seq_handle: None,
        seq_client_id: -1,
        seq_port_id: -1,
        midi_in: MidiReadParser::new(),
        // Will be updated in accept with real MTU.
        midi_out: MidiWriteParser::new(20),
        io_task: None,
    };

    state.insert(addr, Arc::new(StdMutex::new(midi)));
    Ok(())
}

/// Remove callback: full cleanup of per-device MIDI context.
///
/// Replaces C `midi_remove()`.
fn midi_remove(device: &Arc<tokio::sync::Mutex<crate::device::BtdDevice>>) {
    let addr = {
        let dev = device.blocking_lock();
        dev.address
    };
    btd_debug(0, &format!("MIDI: remove {addr}"));

    let midi_arc = {
        let mut state = MIDI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.remove(&addr)
    };

    if let Some(midi_arc) = midi_arc {
        midi_cleanup(&midi_arc);
    }
}

/// Accept callback: set up ALSA sequencer and GATT services.
///
/// Replaces C `midi_accept()`.
async fn midi_accept(
    device: &Arc<tokio::sync::Mutex<crate::device::BtdDevice>>,
) -> Result<(), BtdError> {
    let (addr, dev_name, gatt_db, gatt_client, mtu) = {
        let dev = device.lock().await;
        let name =
            dev.get_name().map(|n| n.to_owned()).unwrap_or_else(|| dev.get_address().to_string());
        let db = dev.get_gatt_db().cloned();
        let client = dev.get_gatt_client().cloned();
        let client_mtu = client.as_ref().map(|c| c.get_mtu()).unwrap_or(23);
        (dev.address, name, db, client, client_mtu)
    };

    btd_debug(0, &format!("MIDI: accept {addr} ({dev_name})"));

    let midi_arc = {
        let state = MIDI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match state.get(&addr) {
            Some(m) => Arc::clone(m),
            None => {
                btd_error(0, "MIDI: accept called without prior probe");
                return Err(BtdError::does_not_exist());
            }
        }
    };

    // Open ALSA sequencer.
    let (seq, client_id, port_id) = match open_alsa_sequencer(&dev_name) {
        Ok(v) => v,
        Err(e) => {
            btd_error(0, &format!("MIDI: failed to open ALSA sequencer: {e}"));
            return Err(BtdError::not_available());
        }
    };

    // Populate the MIDI context.
    {
        let mut midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());
        midi.gatt_db = gatt_db.clone();
        midi.gatt_client = gatt_client;
        midi.seq_handle = Some(seq);
        midi.seq_client_id = client_id;
        midi.seq_port_id = port_id;
        midi.midi_in.midi_read_reset();
        // MTU − 3 for ATT header.
        let payload_mtu = if mtu > 3 { (mtu - 3) as usize } else { 20 };
        midi.midi_out = MidiWriteParser::new(payload_mtu);
    }

    // Discover the MIDI service and I/O characteristic.
    if let Some(ref db) = gatt_db {
        let midi_svc_uuid: BtUuid = MIDI_UUID.parse().expect("static MIDI_UUID is valid");
        let midi_arc_clone = Arc::clone(&midi_arc);
        db.foreach_service(Some(&midi_svc_uuid), move |svc_attr| {
            foreach_midi_service(&midi_arc_clone, &svc_attr);
        });
    }

    // Spawn the ALSA reader task for outgoing MIDI.
    let task = spawn_alsa_reader(Arc::clone(&midi_arc));
    {
        let mut midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());
        midi.io_task = Some(task);
    }

    Ok(())
}

/// Disconnect callback: tear down ALSA and GATT resources.
///
/// Replaces C `midi_disconnect()`.
async fn midi_disconnect(
    device: &Arc<tokio::sync::Mutex<crate::device::BtdDevice>>,
) -> Result<(), BtdError> {
    let addr = {
        let dev = device.lock().await;
        dev.address
    };
    btd_debug(0, &format!("MIDI: disconnect {addr}"));

    let midi_arc = {
        let state = MIDI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match state.get(&addr) {
            Some(m) => Arc::clone(m),
            None => return Ok(()),
        }
    };

    midi_cleanup(&midi_arc);
    Ok(())
}

/// Perform full cleanup of a MIDI context: unregister notification, abort
/// ALSA reader task, close ALSA sequencer, release GATT references.
fn midi_cleanup(midi_arc: &Arc<StdMutex<Midi>>) {
    let mut midi = midi_arc.lock().unwrap_or_else(|e| e.into_inner());

    // Unregister GATT notification.
    if let (Some(client), Some(notify_id)) = (midi.gatt_client.as_ref(), midi.notify_id) {
        client.unregister_notify(notify_id);
        midi.notify_id = None;
    }

    // Abort the ALSA reader task.
    if let Some(task) = midi.io_task.take() {
        task.abort();
    }

    // Close ALSA sequencer: delete port, then drop handle.
    if let Some(ref seq) = midi.seq_handle {
        if midi.seq_port_id >= 0 {
            let _ = seq.delete_port(midi.seq_port_id);
        }
    }
    midi.seq_handle = None;
    midi.seq_client_id = -1;
    midi.seq_port_id = -1;

    // Release GATT references.
    midi.gatt_client = None;
    midi.gatt_db = None;
    midi.midi_io_handle = 0;
}

// ===========================================================================
// Plugin Lifecycle
// ===========================================================================

/// Initialize the MIDI GATT Driver plugin.
///
/// Creates and registers the BLE-MIDI profile with the daemon's profile
/// registry.  Replaces C `midi_init()`.
pub fn midi_init() -> Result<(), Box<dyn std::error::Error>> {
    btd_debug(0, "midi plugin init");

    let mut profile = BtdProfile::new("MIDI GATT Driver");
    profile.priority = crate::profile::BTD_PROFILE_PRIORITY_HIGH;
    profile.bearer = BTD_PROFILE_BEARER_LE;
    profile.remote_uuid = Some(MIDI_UUID.to_owned());
    profile.auto_connect = true;

    // Probe and remove are synchronous closures.
    profile.set_device_probe(Box::new(midi_probe));
    profile.set_device_remove(Box::new(midi_remove));

    // Accept and disconnect return pinned Futures.
    profile.set_accept(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { midi_accept(&device).await })
    }));
    profile.set_disconnect(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { midi_disconnect(&device).await })
    }));

    // Store a copy of the profile for unregistration during exit.
    {
        let stored = BtdProfile::new("MIDI GATT Driver");
        let mut guard = MIDI_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    // Register the profile asynchronously.
    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(profile).await {
            btd_error(0, &format!("Failed to register MIDI profile: {e}"));
        }
    });

    Ok(())
}

/// Shut down the MIDI GATT Driver plugin.
///
/// Unregisters the profile and clears all per-device state.
/// Replaces C `midi_exit()`.
pub fn midi_exit() {
    btd_debug(0, "midi plugin exit");

    // Unregister the profile.
    let profile_opt = {
        let mut guard = MIDI_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(profile) = profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }

    // Clean up all per-device MIDI contexts.
    let mut state = MIDI_STATE.lock().unwrap_or_else(|e| e.into_inner());
    for (_addr, midi_arc) in state.drain() {
        midi_cleanup(&midi_arc);
    }
}

// ===========================================================================
// Pure-Rust MIDI ↔ ALSA Event conversion helpers
// ===========================================================================

/// Convert a complete MIDI message (status + data bytes) into an ALSA
/// sequencer `Event`.  Returns `None` for unrecognised or incomplete
/// messages.
fn midi_message_to_event(status: u8, data: &[u8]) -> Option<Event<'static>> {
    let channel = status & 0x0F;

    match status & 0xF0 {
        0x80 => {
            // Note Off
            if data.len() >= 2 {
                Some(Event::new(
                    EventType::Noteoff,
                    &EvNote {
                        channel,
                        note: data[0] & 0x7F,
                        velocity: data[1] & 0x7F,
                        off_velocity: 0,
                        duration: 0,
                    },
                ))
            } else {
                None
            }
        }
        0x90 => {
            // Note On (velocity 0 = Note Off)
            if data.len() >= 2 {
                let vel = data[1] & 0x7F;
                let etype = if vel == 0 { EventType::Noteoff } else { EventType::Noteon };
                Some(Event::new(
                    etype,
                    &EvNote {
                        channel,
                        note: data[0] & 0x7F,
                        velocity: vel,
                        off_velocity: 0,
                        duration: 0,
                    },
                ))
            } else {
                None
            }
        }
        0xA0 => {
            // Key Pressure (Aftertouch)
            if data.len() >= 2 {
                Some(Event::new(
                    EventType::Keypress,
                    &EvNote {
                        channel,
                        note: data[0] & 0x7F,
                        velocity: data[1] & 0x7F,
                        off_velocity: 0,
                        duration: 0,
                    },
                ))
            } else {
                None
            }
        }
        0xB0 => {
            // Control Change
            if data.len() >= 2 {
                Some(Event::new(
                    EventType::Controller,
                    &EvCtrl {
                        channel,
                        param: u32::from(data[0] & 0x7F),
                        value: i32::from(data[1] & 0x7F),
                    },
                ))
            } else {
                None
            }
        }
        0xC0 => {
            // Program Change
            if !data.is_empty() {
                Some(Event::new(
                    EventType::Pgmchange,
                    &EvCtrl { channel, param: 0, value: i32::from(data[0] & 0x7F) },
                ))
            } else {
                None
            }
        }
        0xD0 => {
            // Channel Pressure
            if !data.is_empty() {
                Some(Event::new(
                    EventType::Chanpress,
                    &EvCtrl { channel, param: 0, value: i32::from(data[0] & 0x7F) },
                ))
            } else {
                None
            }
        }
        0xE0 => {
            // Pitch Bend (14-bit, centered at 8192)
            if data.len() >= 2 {
                let raw = i32::from(data[0] & 0x7F) | (i32::from(data[1] & 0x7F) << 7);
                Some(Event::new(
                    EventType::Pitchbend,
                    &EvCtrl { channel, param: 0, value: raw - 8192 },
                ))
            } else {
                None
            }
        }
        _ => {
            // System Common messages (status 0xF0-0xF7).
            match status {
                0xF1 => {
                    // MTC Quarter Frame
                    if !data.is_empty() {
                        Some(Event::new(
                            EventType::Qframe,
                            &EvCtrl { channel: 0, param: 0, value: i32::from(data[0] & 0x7F) },
                        ))
                    } else {
                        None
                    }
                }
                0xF2 => {
                    // Song Position Pointer (14-bit)
                    if data.len() >= 2 {
                        let pos = i32::from(data[0] & 0x7F) | (i32::from(data[1] & 0x7F) << 7);
                        Some(Event::new(
                            EventType::Songpos,
                            &EvCtrl { channel: 0, param: 0, value: pos },
                        ))
                    } else {
                        None
                    }
                }
                0xF3 => {
                    // Song Select
                    if !data.is_empty() {
                        Some(Event::new(
                            EventType::Songsel,
                            &EvCtrl { channel: 0, param: 0, value: i32::from(data[0] & 0x7F) },
                        ))
                    } else {
                        None
                    }
                }
                0xF6 => Some(Event::new(EventType::TuneRequest, &())),
                _ => None,
            }
        }
    }
}

/// Convert a MIDI real-time status byte to an ALSA sequencer `Event`.
fn realtime_to_event(status: u8) -> Option<Event<'static>> {
    // Clock, Start, Continue, Stop use EvQueueControl<()> data in the
    // alsa crate; Sensing and Reset use plain `()`.
    let qc_data = EvQueueControl { queue: 0, value: () };
    match status {
        0xF8 => Some(Event::new(EventType::Clock, &qc_data)),
        0xFA => Some(Event::new(EventType::Start, &qc_data)),
        0xFB => Some(Event::new(EventType::Continue, &qc_data)),
        0xFC => Some(Event::new(EventType::Stop, &qc_data)),
        0xFE => Some(Event::new(EventType::Sensing, &())),
        0xFF => Some(Event::new(EventType::Reset, &())),
        _ => None,
    }
}

/// Convert an ALSA sequencer `Event` into raw MIDI wire bytes.
///
/// Returns an empty `Vec` for unrecognised event types.
fn event_to_midi_bytes(ev: &Event<'_>) -> Vec<u8> {
    match ev.get_type() {
        EventType::Noteoff => {
            if let Some(n) = ev.get_data::<EvNote>() {
                vec![0x80 | (n.channel & 0x0F), n.note & 0x7F, n.velocity & 0x7F]
            } else {
                Vec::new()
            }
        }
        EventType::Noteon => {
            if let Some(n) = ev.get_data::<EvNote>() {
                vec![0x90 | (n.channel & 0x0F), n.note & 0x7F, n.velocity & 0x7F]
            } else {
                Vec::new()
            }
        }
        EventType::Keypress => {
            if let Some(n) = ev.get_data::<EvNote>() {
                vec![0xA0 | (n.channel & 0x0F), n.note & 0x7F, n.velocity & 0x7F]
            } else {
                Vec::new()
            }
        }
        EventType::Controller => {
            if let Some(c) = ev.get_data::<EvCtrl>() {
                vec![0xB0 | (c.channel & 0x0F), (c.param & 0x7F) as u8, (c.value & 0x7F) as u8]
            } else {
                Vec::new()
            }
        }
        EventType::Pgmchange => {
            if let Some(c) = ev.get_data::<EvCtrl>() {
                vec![0xC0 | (c.channel & 0x0F), (c.value & 0x7F) as u8]
            } else {
                Vec::new()
            }
        }
        EventType::Chanpress => {
            if let Some(c) = ev.get_data::<EvCtrl>() {
                vec![0xD0 | (c.channel & 0x0F), (c.value & 0x7F) as u8]
            } else {
                Vec::new()
            }
        }
        EventType::Pitchbend => {
            if let Some(c) = ev.get_data::<EvCtrl>() {
                // ALSA value is centered at 0 (-8192..8191); wire is 0..16383.
                let wire = (c.value + 8192).clamp(0, 16383);
                vec![0xE0 | (c.channel & 0x0F), (wire & 0x7F) as u8, ((wire >> 7) & 0x7F) as u8]
            } else {
                Vec::new()
            }
        }
        EventType::Sysex => {
            // Return raw SysEx bytes including F0 and F7.
            ev.get_ext().map(|d| d.to_vec()).unwrap_or_default()
        }
        EventType::Qframe => {
            if let Some(c) = ev.get_data::<EvCtrl>() {
                vec![0xF1, (c.value & 0x7F) as u8]
            } else {
                Vec::new()
            }
        }
        EventType::Songpos => {
            if let Some(c) = ev.get_data::<EvCtrl>() {
                vec![0xF2, (c.value & 0x7F) as u8, ((c.value >> 7) & 0x7F) as u8]
            } else {
                Vec::new()
            }
        }
        EventType::Songsel => {
            if let Some(c) = ev.get_data::<EvCtrl>() {
                vec![0xF3, (c.value & 0x7F) as u8]
            } else {
                Vec::new()
            }
        }
        EventType::TuneRequest => vec![0xF6],
        EventType::Clock => vec![0xF8],
        EventType::Start => vec![0xFA],
        EventType::Continue => vec![0xFB],
        EventType::Stop => vec![0xFC],
        EventType::Sensing => vec![0xFE],
        EventType::Reset => vec![0xFF],
        _ => Vec::new(),
    }
}

/// Test whether a byte is a MIDI real-time status byte (0xF8..=0xFF).
fn is_midi_realtime(byte: u8) -> bool {
    byte >= 0xF8
}

/// Return the number of data bytes expected for a MIDI status byte.
fn midi_data_byte_count(status: u8) -> usize {
    match status & 0xF0 {
        0x80 => 2, // Note Off
        0x90 => 2, // Note On
        0xA0 => 2, // Key Pressure
        0xB0 => 2, // Control Change
        0xC0 => 1, // Program Change
        0xD0 => 1, // Channel Pressure
        0xE0 => 2, // Pitch Bend
        _ => match status {
            0xF1 => 1,        // MTC Quarter Frame
            0xF2 => 2,        // Song Position
            0xF3 => 1,        // Song Select
            0xF6 => 0,        // Tune Request
            0xF8..=0xFF => 0, // Real-time
            _ => 0,
        },
    }
}

/// Get a low-resolution monotonic timestamp in milliseconds for BLE-MIDI
/// framing.  Only the lower 13 bits are meaningful.
fn get_timestamp_millis() -> u16 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    (ms & 0x1FFF) as u16
}

// ===========================================================================
// Plugin Registration via inventory
// ===========================================================================

/// Plugin registration using `inventory::submit!`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(midi, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_HIGH, midi_init, midi_exit)`.
mod _midi_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "midi",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::High,
            init: super::midi_init,
            exit: super::midi_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_midi_uuid_constants() {
        assert_eq!(MIDI_UUID, "03B80E5A-EDE8-4B33-A751-6CE34EC4C700");
        assert_eq!(MIDI_IO_UUID, "7772E5DB-3868-4112-A1A9-F2669D106BF3");
    }

    #[test]
    fn test_midi_data_byte_count() {
        assert_eq!(midi_data_byte_count(0x90), 2); // Note On
        assert_eq!(midi_data_byte_count(0x80), 2); // Note Off
        assert_eq!(midi_data_byte_count(0xB3), 2); // CC
        assert_eq!(midi_data_byte_count(0xC5), 1); // PgmChange
        assert_eq!(midi_data_byte_count(0xD2), 1); // ChanPress
        assert_eq!(midi_data_byte_count(0xE7), 2); // PitchBend
        assert_eq!(midi_data_byte_count(0xA1), 2); // KeyPress
        assert_eq!(midi_data_byte_count(0xF1), 1); // Qframe
        assert_eq!(midi_data_byte_count(0xF2), 2); // Songpos
        assert_eq!(midi_data_byte_count(0xF3), 1); // Songsel
        assert_eq!(midi_data_byte_count(0xF6), 0); // TuneReq
        assert_eq!(midi_data_byte_count(0xF8), 0); // Clock
        assert_eq!(midi_data_byte_count(0xFE), 0); // Sensing
        assert_eq!(midi_data_byte_count(0xFF), 0); // Reset
    }

    #[test]
    fn test_is_midi_realtime() {
        assert!(is_midi_realtime(0xF8));
        assert!(is_midi_realtime(0xFA));
        assert!(is_midi_realtime(0xFB));
        assert!(is_midi_realtime(0xFC));
        assert!(is_midi_realtime(0xFE));
        assert!(is_midi_realtime(0xFF));
        assert!(!is_midi_realtime(0xF0));
        assert!(!is_midi_realtime(0x90));
        assert!(!is_midi_realtime(0x00));
    }

    #[test]
    fn test_write_parser_basic() {
        let wp = MidiWriteParser::new(20);
        assert!(!wp.midi_write_has_data());
        assert!(wp.midi_write_data().is_empty());
    }

    #[test]
    fn test_write_parser_reset() {
        let mut wp = MidiWriteParser::new(20);
        wp.buf_len = 5;
        wp.sysex_started = true;
        wp.midi_write_reset();
        assert!(!wp.midi_write_has_data());
        assert!(!wp.sysex_started);
    }

    #[test]
    fn test_read_parser_reset() {
        let mut rp = MidiReadParser::new();
        rp.timestamp = 100;
        rp.sysex_started = true;
        rp.midi_read_reset();
        assert_eq!(rp.timestamp, 0);
        assert!(!rp.sysex_started);
    }

    #[test]
    fn test_read_parser_short_packet() {
        let mut rp = MidiReadParser::new();
        let events = rp.midi_read_raw(&[0x80, 0x80]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_read_parser_note_on() {
        let mut rp = MidiReadParser::new();
        // BLE-MIDI: header=0x80, ts_low=0x80, NoteOn ch0, note=60, vel=100
        let pkt = [0x80, 0x80, 0x90, 0x3C, 0x64];
        let events = rp.midi_read_raw(&pkt);
        assert!(!events.is_empty(), "Expected event from NoteOn");
        assert_eq!(events[0].get_type(), EventType::Noteon);
        let note: EvNote = events[0].get_data().expect("EvNote");
        assert_eq!(note.channel, 0);
        assert_eq!(note.note, 60);
        assert_eq!(note.velocity, 100);
    }

    #[test]
    fn test_read_parser_control_change() {
        let mut rp = MidiReadParser::new();
        // BLE-MIDI: header=0x80, ts_low=0x80, CC ch0, ctrl=7, val=64
        let pkt = [0x80, 0x80, 0xB0, 0x07, 0x40];
        let events = rp.midi_read_raw(&pkt);
        assert!(!events.is_empty());
        assert_eq!(events[0].get_type(), EventType::Controller);
        let ctrl: EvCtrl = events[0].get_data().expect("EvCtrl");
        assert_eq!(ctrl.channel, 0);
        assert_eq!(ctrl.param, 7);
        assert_eq!(ctrl.value, 64);
    }

    #[test]
    fn test_read_parser_program_change() {
        let mut rp = MidiReadParser::new();
        // BLE-MIDI: header=0x80, ts_low=0x80, PgmChange ch0, prog=10
        let pkt = [0x80, 0x80, 0xC0, 0x0A];
        let events = rp.midi_read_raw(&pkt);
        assert!(!events.is_empty());
        assert_eq!(events[0].get_type(), EventType::Pgmchange);
        let ctrl: EvCtrl = events[0].get_data().expect("EvCtrl");
        assert_eq!(ctrl.value, 10);
    }

    #[test]
    fn test_read_parser_pitch_bend() {
        let mut rp = MidiReadParser::new();
        // Pitch Bend center: LSB=0, MSB=64 = 8192
        let pkt = [0x80, 0x80, 0xE0, 0x00, 0x40];
        let events = rp.midi_read_raw(&pkt);
        assert!(!events.is_empty());
        assert_eq!(events[0].get_type(), EventType::Pitchbend);
        let ctrl: EvCtrl = events[0].get_data().expect("EvCtrl");
        assert_eq!(ctrl.value, 0); // Center = 0 in ALSA
    }

    #[test]
    fn test_event_to_midi_bytes_note_on() {
        let ev = Event::new(
            EventType::Noteon,
            &EvNote { channel: 3, note: 60, velocity: 100, off_velocity: 0, duration: 0 },
        );
        let bytes = event_to_midi_bytes(&ev);
        assert_eq!(bytes, vec![0x93, 60, 100]);
    }

    #[test]
    fn test_event_to_midi_bytes_pitch_bend() {
        // ALSA value 0 → wire 8192 → LSB=0, MSB=64
        let ev = Event::new(EventType::Pitchbend, &EvCtrl { channel: 0, param: 0, value: 0 });
        let bytes = event_to_midi_bytes(&ev);
        assert_eq!(bytes, vec![0xE0, 0x00, 0x40]);
    }

    #[test]
    fn test_event_to_midi_bytes_clock() {
        let qc = EvQueueControl { queue: 0, value: () };
        let ev = Event::new(EventType::Clock, &qc);
        let bytes = event_to_midi_bytes(&ev);
        assert_eq!(bytes, vec![0xF8]);
    }

    #[test]
    fn test_get_timestamp_millis_range() {
        let ts = get_timestamp_millis();
        assert!(ts <= 0x1FFF, "Timestamp must fit in 13 bits");
    }

    #[test]
    fn test_realtime_to_event() {
        assert!(realtime_to_event(0xF8).is_some()); // Clock
        assert!(realtime_to_event(0xFA).is_some()); // Start
        assert!(realtime_to_event(0xFB).is_some()); // Continue
        assert!(realtime_to_event(0xFC).is_some()); // Stop
        assert!(realtime_to_event(0xFE).is_some()); // Sensing
        assert!(realtime_to_event(0xFF).is_some()); // Reset
        assert!(realtime_to_event(0xF9).is_none()); // Undefined
    }

    #[test]
    fn test_midi_message_to_event_noteoff() {
        let ev = midi_message_to_event(0x84, &[60, 64]).unwrap();
        assert_eq!(ev.get_type(), EventType::Noteoff);
        let n: EvNote = ev.get_data().unwrap();
        assert_eq!(n.channel, 4);
        assert_eq!(n.note, 60);
        assert_eq!(n.velocity, 64);
    }

    #[test]
    fn test_midi_message_to_event_note_on_vel0_is_noteoff() {
        let ev = midi_message_to_event(0x90, &[60, 0]).unwrap();
        assert_eq!(ev.get_type(), EventType::Noteoff);
    }

    #[test]
    fn test_write_parser_single_note() {
        let mut wp = MidiWriteParser::new(20);
        let ev = Event::new(
            EventType::Noteon,
            &EvNote { channel: 0, note: 60, velocity: 100, off_velocity: 0, duration: 0 },
        );
        let mut flushed: Vec<Vec<u8>> = Vec::new();
        wp.midi_read_ev(&ev, |pkt| flushed.push(pkt.to_vec()));
        // No flush expected — data fits in MTU.
        assert!(flushed.is_empty());
        assert!(wp.midi_write_has_data());
        let data = wp.midi_write_data();
        // Expect: ts_high(1) + ts_low(1) + status(1) + note(1) + vel(1) = 5
        assert_eq!(data.len(), 5);
        // First byte is header (bit 7 set, bits 5-0 = ts high).
        assert_ne!(data[0] & 0x80, 0);
        // Second byte is timestamp low (bit 7 set).
        assert_ne!(data[1] & 0x80, 0);
        // Third byte is 0x90 (NoteOn ch0).
        assert_eq!(data[2], 0x90);
        assert_eq!(data[3], 60);
        assert_eq!(data[4], 100);
    }
}
