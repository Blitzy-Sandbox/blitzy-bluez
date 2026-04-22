// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
//! ASHA (Audio Streaming for Hearing Aid) client.
//!
//! Complete Rust rewrite of `src/shared/asha.c` (553 lines) and
//! `src/shared/asha.h` (72 lines).  Implements the ASHA hearing aid streaming
//! protocol: GATT service discovery, ReadOnlyProperties parsing, HiSync ID
//! management for binaural pairing, AudioControlPoint start/stop/status
//! commands, AudioStatusPoint notification monitoring, volume control, and
//! L2CAP PSM extraction for Connection-Oriented Channel (CoC) audio streaming.

use std::sync::{Arc, Mutex};

use thiserror::Error;
use tracing::{debug, error, warn};

use crate::gatt::client::{
    BtGattClient, ClientCallback, NotifyCallback, ReadCallback, RegisterCallback,
};
use crate::gatt::db::{CharData, GattDb, GattDbAttribute};
use crate::util::endian::get_le16;
use crate::util::queue::Queue;
use crate::util::uuid::BtUuid;

// ===========================================================================
// Constants
// ===========================================================================

/// ASHA Service UUID (16-bit Bluetooth SIG assigned number 0xFDF0).
pub const ASHA_SERVICE: u16 = 0xFDF0;

/// ASHA Profile UUID string (full 128-bit representation).
pub const ASHA_PROFILE_UUID: &str = "0000FDF0-0000-1000-8000-00805f9b34fb";

/// ASHA ReadOnlyProperties characteristic UUID (128-bit).
const ASHA_CHRC_READ_ONLY_PROPERTIES_UUID: &str = "6333651e-c481-4a3e-9169-7c902aad37bb";

/// ASHA AudioControlPoint characteristic UUID (128-bit).
const ASHA_CHRC_AUDIO_CONTROL_POINT_UUID: &str = "f0d4de7e-4a88-476c-9d9f-1937b0996cc0";

/// ASHA AudioStatus characteristic UUID (128-bit).
const ASHA_CHRC_AUDIO_STATUS_UUID: &str = "38663f1a-e711-4cac-b641-326b56404837";

/// ASHA Volume characteristic UUID (128-bit).
const ASHA_CHRC_VOLUME_UUID: &str = "00e4ca9e-ab14-41e4-8823-f9e70c7e91df";

/// ASHA LE_PSM_OUT characteristic UUID (128-bit).
const ASHA_CHRC_LE_PSM_OUT_UUID: &str = "2d410339-82b6-42aa-b34e-e2e01df8cc1a";

/// ACP opcode: START streaming.
const ACP_OPCODE_START: u8 = 0x01;
/// ACP opcode: STOP streaming.
const ACP_OPCODE_STOP: u8 = 0x02;
/// ACP opcode: STATUS update to other device.
const ACP_OPCODE_STATUS: u8 = 0x03;

/// G.722 at 16 kHz codec identifier.
const CODEC_G722_16KHZ: u8 = 0x01;

/// Expected length of the ReadOnlyProperties characteristic value (17 bytes).
const ROPS_LENGTH: usize = 17;
/// Expected ASHA protocol version in ROPs byte 0.
const ROPS_VERSION: u8 = 0x01;
/// Expected length of the LE_PSM_OUT characteristic value (2 bytes LE16).
const PSM_LENGTH: usize = 2;

// ===========================================================================
// Global binaural set tracking
// ===========================================================================

/// Module-level set tracking for binaural hearing aid pairing.
/// Lazily initialised on first `attach()`, destroyed when the last set is
/// removed — mirroring the C `static struct queue *asha_devices`.
static ASHA_DEVICES: Mutex<Option<Queue<BtAshaSet>>> = Mutex::new(None);

// ===========================================================================
// Enums
// ===========================================================================

/// ASHA streaming state machine.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AshaState {
    /// Audio streaming is stopped.
    Stopped = 0,
    /// START command sent, awaiting AudioStatusPoint notification.
    Starting = 1,
    /// AudioStatusPoint confirmed streaming active.
    Started = 2,
}

/// Errors that can occur during ASHA operations.
#[derive(Debug, Error)]
pub enum AshaError {
    /// A GATT read operation failed.
    #[error("GATT read operation failed")]
    GattReadFailed,
    /// A GATT write operation failed.
    #[error("GATT write operation failed")]
    GattWriteFailed,
    /// The current state does not allow the requested operation.
    #[error("invalid state for operation")]
    InvalidState,
    /// A required ASHA GATT characteristic was not discovered.
    #[error("missing required ASHA characteristic")]
    MissingCharacteristic,
    /// Data received from the remote device is malformed.
    #[error("malformed ASHA data")]
    MalformedData,
    /// No GATT client is attached — call `attach()` first.
    #[error("ASHA device not attached")]
    NotAttached,
}

// ===========================================================================
// Callback type aliases
// ===========================================================================

/// State-change callback.
///
/// Receives the raw AudioStatusPoint status byte as an `i32`:
/// - `0`  — operation completed successfully (STARTED)
/// - `-1` — GATT write to AudioControlPoint failed
/// - `>0` — error status from AudioStatusPoint notification
///
/// The callback is one-shot: it is cleared after being invoked, matching the
/// C `bt_asha_cb_t` semantics.  Use [`BtAsha::set_state_cb`] to register a
/// new callback before each [`BtAsha::start`] call.
type StateCallback = Arc<dyn Fn(i32) + Send + Sync>;

/// Attach-completion callback.
///
/// Invoked once the ReadOnlyProperties and LE_PSM_OUT reads have both
/// completed, indicating the ASHA service is fully probed.
type AttachCallback = Mutex<Option<Box<dyn FnOnce() + Send>>>;

// ===========================================================================
// Inner mutable state
// ===========================================================================

/// Private mutable state behind `BtAsha`'s `Arc<Mutex<…>>`.
struct BtAshaInner {
    // --- GATT handles ---
    client: Option<Arc<BtGattClient>>,
    db: Option<GattDb>,
    attr: Option<GattDbAttribute>,
    acp_handle: u16,
    volume_handle: u16,
    status_notify_id: u32,

    // --- Discovered properties ---
    psm: u16,
    right_side: bool,
    binaural: bool,
    csis_supported: bool,
    coc_streaming_supported: bool,
    hisync_id: [u8; 8],
    render_delay: u16,
    codec_ids: u16,
    volume: i8,

    // --- State machine ---
    state: AshaState,
    state_cb: Option<StateCallback>,

    // --- Attach callback (one-shot, behind inner Mutex for FnOnce) ---
    attach_cb: Arc<AttachCallback>,
}

impl Default for BtAshaInner {
    fn default() -> Self {
        Self {
            client: None,
            db: None,
            attr: None,
            acp_handle: 0,
            volume_handle: 0,
            status_notify_id: 0,
            psm: 0,
            right_side: false,
            binaural: false,
            csis_supported: false,
            coc_streaming_supported: false,
            hisync_id: [0u8; 8],
            render_delay: 0,
            codec_ids: 0,
            volume: 0,
            state: AshaState::Stopped,
            state_cb: None,
            attach_cb: Arc::new(Mutex::new(None)),
        }
    }
}

// ===========================================================================
// BtAsha — public handle
// ===========================================================================

/// ASHA hearing-aid streaming client.
///
/// Wraps an `Arc<Mutex<BtAshaInner>>` for safe shared access from GATT
/// callbacks.  All public methods take `&self` and lock the inner mutex
/// internally.
///
/// # Lifecycle
///
/// 1. [`BtAsha::new`] — create an instance.
/// 2. [`BtAsha::attach`] — attach to GATT client, discover ASHA service.
/// 3. [`BtAsha::set_state_cb`] + [`BtAsha::start`] — begin streaming.
/// 4. [`BtAsha::stop`] — end streaming.
/// 5. [`BtAsha::reset`] — detach and clean up.
pub struct BtAsha {
    inner: Arc<Mutex<BtAshaInner>>,
}

impl Clone for BtAsha {
    fn clone(&self) -> Self {
        BtAsha { inner: Arc::clone(&self.inner) }
    }
}

impl BtAsha {
    // -----------------------------------------------------------------
    // Construction / lifecycle
    // -----------------------------------------------------------------

    /// Create a new, unattached ASHA instance.
    ///
    /// Equivalent to C `bt_asha_new()`.
    pub fn new() -> Self {
        BtAsha { inner: Arc::new(Mutex::new(BtAshaInner::default())) }
    }

    /// Full reset: unregister notifications, release GATT client and DB
    /// references, reset all discovered properties, and unregister from the
    /// global binaural set.
    ///
    /// Equivalent to C `bt_asha_reset()`.
    pub fn reset(&self) {
        // Unregister notification before dropping the client reference.
        let (notify_id, client_ref) = {
            let inner = self.inner.lock().unwrap();
            (inner.status_notify_id, inner.client.clone())
        };
        if notify_id != 0 {
            if let Some(ref client) = client_ref {
                client.unregister_notify(notify_id);
            }
        }

        // Reset inner state.
        {
            let mut inner = self.inner.lock().unwrap();
            inner.db = None;
            inner.client = None;
            inner.attr = None;
            inner.status_notify_id = 0;
            inner.state = AshaState::Stopped;
            inner.state_cb = None;
            inner.psm = 0;
            inner.hisync_id = [0u8; 8];
            inner.acp_handle = 0;
            inner.volume_handle = 0;
            // Clear attach callback.
            if let Ok(mut cb_guard) = inner.attach_cb.lock() {
                *cb_guard = None;
            }
        }

        // Remove from the global binaural set.
        update_asha_set(self, false);
    }

    /// Reset only the streaming state and state callback.
    ///
    /// Equivalent to C `bt_asha_state_reset()`.
    pub fn state_reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.state = AshaState::Stopped;
        inner.state_cb = None;
    }

    // -----------------------------------------------------------------
    // Streaming control
    // -----------------------------------------------------------------

    /// Send the ACP START command to begin audio streaming.
    ///
    /// The state transitions from `Stopped` → `Starting`.  When the remote
    /// device replies via AudioStatusPoint notification with status `0`, the
    /// state advances to `Started` and the registered state callback is
    /// invoked.
    ///
    /// Returns `Err(AshaError::InvalidState)` if not in `Stopped` state,
    /// `Err(AshaError::NotAttached)` if no GATT client is attached.
    pub fn start(&self) -> Result<(), AshaError> {
        let other_connected = is_other_connected(&self.inner);

        let (acp_handle, volume, client_ref) = {
            let inner = self.inner.lock().unwrap();

            if inner.state != AshaState::Stopped {
                error!("ASHA device start failed. Bad state {:?}", inner.state);
                return Err(AshaError::InvalidState);
            }
            if inner.client.is_none() {
                return Err(AshaError::NotAttached);
            }
            if inner.acp_handle == 0 {
                return Err(AshaError::MissingCharacteristic);
            }

            (inner.acp_handle, inner.volume, inner.client.clone().unwrap())
        };

        let acp_start_cmd: [u8; 5] = [
            ACP_OPCODE_START,
            CODEC_G722_16KHZ,
            0, // Unknown media type
            volume as u8,
            other_connected,
        ];

        let inner_for_cb = Arc::clone(&self.inner);
        let write_cb: ClientCallback = Box::new(move |success, err| {
            acp_sent_handler(&inner_for_cb, success, err);
        });

        let req_id = client_ref.write_value(acp_handle, &acp_start_cmd, write_cb);
        if req_id == 0 {
            error!("Error writing ACP start command");
            return Err(AshaError::GattWriteFailed);
        }

        // Transition to Starting.
        {
            let mut inner = self.inner.lock().unwrap();
            inner.state = AshaState::Starting;
        }

        Ok(())
    }

    /// Send the ACP STOP command to cease audio streaming.
    ///
    /// The state is immediately set to `Stopped` without waiting for a
    /// response, matching C `bt_asha_stop()` semantics.
    pub fn stop(&self) -> Result<(), AshaError> {
        let (acp_handle, client_ref) = {
            let inner = self.inner.lock().unwrap();
            if inner.state != AshaState::Started {
                // Not started — nothing to do (matches C returning 0).
                return Ok(());
            }
            if inner.client.is_none() {
                return Err(AshaError::NotAttached);
            }
            (inner.acp_handle, inner.client.clone().unwrap())
        };

        // Immediately transition to Stopped.
        {
            let mut inner = self.inner.lock().unwrap();
            inner.state = AshaState::Stopped;
        }

        let acp_stop_cmd: [u8; 1] = [ACP_OPCODE_STOP];

        let inner_for_cb = Arc::clone(&self.inner);
        let write_cb: ClientCallback = Box::new(move |success, err| {
            acp_sent_handler(&inner_for_cb, success, err);
        });

        let req_id = client_ref.write_value(acp_handle, &acp_stop_cmd, write_cb);
        if req_id == 0 {
            error!("Error writing ACP stop command");
        }

        // Notify the other device in the set that streaming has stopped.
        asha_set_send_status(&self.inner, false);

        // Reset state (clears state_cb, matching C).
        self.state_reset();

        debug!("ASHA stop done");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Volume
    // -----------------------------------------------------------------

    /// Write a new volume level to the remote hearing aid.
    ///
    /// `volume` must be in the range `[-128, 0]` (mapped identically to the
    /// C `int8_t` range).  Returns `true` on success.
    pub fn set_volume(&self, volume: i8) -> bool {
        let (handle, client_ref) = {
            let inner = self.inner.lock().unwrap();
            match (&inner.client, inner.volume_handle) {
                (Some(c), h) if h != 0 => (h, Arc::clone(c)),
                _ => {
                    error!("Error writing volume");
                    return false;
                }
            }
        };

        let data = [volume as u8];
        let req_id = client_ref.write_without_response(handle, false, &data);
        if req_id == 0 {
            error!("Error writing volume");
            return false;
        }

        let mut inner = self.inner.lock().unwrap();
        inner.volume = volume;
        true
    }

    // -----------------------------------------------------------------
    // GATT attachment and service discovery
    // -----------------------------------------------------------------

    /// Attach to an ASHA GATT service on a remote device.
    ///
    /// Clones the provided GATT client, discovers the ASHA service UUID
    /// (`0xFDF0`), iterates its characteristics, reads ReadOnlyProperties
    /// and LE_PSM_OUT, registers for AudioStatusPoint notifications, and
    /// stores AudioControlPoint and Volume handles.
    ///
    /// `attach_cb` is invoked once both ReadOnlyProperties and LE_PSM_OUT
    /// reads have completed.
    ///
    /// Returns `false` if the ASHA service attribute was not found.
    pub fn attach(
        &self,
        db: &GattDb,
        client: &Arc<BtGattClient>,
        attach_cb: Option<Box<dyn FnOnce() + Send>>,
    ) -> bool {
        let client_clone = match BtGattClient::clone_client(client) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to clone GATT client: {}", e);
                return false;
            }
        };

        let attach_cb_arc = Arc::new(Mutex::new(attach_cb));

        {
            let mut inner = self.inner.lock().unwrap();
            inner.db = Some(db.clone());
            inner.client = Some(client_clone.clone());
            inner.attach_cb = Arc::clone(&attach_cb_arc);
        }

        // Discover ASHA service.
        let asha_uuid = BtUuid::from_u16(ASHA_SERVICE);
        let inner_ref = Arc::clone(&self.inner);
        let client_for_disc = Arc::clone(&client_clone);
        let mut service_found = false;

        db.foreach_service(Some(&asha_uuid), |attr| {
            if service_found {
                return; // Process only the first matching service.
            }
            debug!("Found ASHA GATT service");
            service_found = true;

            {
                let mut inner = inner_ref.lock().unwrap();
                inner.attr = Some(attr.clone());
            }

            if let Some(service) = attr.get_service() {
                service.set_claimed(true);

                let inner_for_char = Arc::clone(&inner_ref);
                let client_for_char = Arc::clone(&client_for_disc);
                service.foreach_char(|char_attr| {
                    handle_characteristic(&inner_for_char, &client_for_char, &char_attr);
                });
            }
        });

        // If no service was found, clean up and return false.
        let has_attr = {
            let inner = self.inner.lock().unwrap();
            inner.attr.is_some()
        };
        if !has_attr {
            error!("ASHA attribute not found");
            self.reset();
            return false;
        }

        // Ensure the global device-set queue exists.
        {
            let mut devices = ASHA_DEVICES.lock().unwrap();
            if devices.is_none() {
                *devices = Some(Queue::new());
            }
        }

        true
    }

    // -----------------------------------------------------------------
    // Accessors (property readers)
    // -----------------------------------------------------------------

    /// L2CAP PSM for audio streaming CoC, read from LE_PSM_OUT.
    pub fn psm(&self) -> u16 {
        self.inner.lock().unwrap().psm
    }

    /// Current streaming state.
    pub fn state(&self) -> AshaState {
        self.inner.lock().unwrap().state
    }

    /// 8-byte HiSyncId identifying the hearing-aid set.
    pub fn hisync_id(&self) -> [u8; 8] {
        self.inner.lock().unwrap().hisync_id
    }

    /// `true` if this is the right-ear device.
    pub fn right_side(&self) -> bool {
        self.inner.lock().unwrap().right_side
    }

    /// `true` if the device is part of a binaural pair.
    pub fn binaural(&self) -> bool {
        self.inner.lock().unwrap().binaural
    }

    /// `true` if the device supports CSIP set membership.
    pub fn csis_supported(&self) -> bool {
        self.inner.lock().unwrap().csis_supported
    }

    /// Supported codec IDs bitfield (bit 1 = G.722 at 16 kHz).
    pub fn codec_ids(&self) -> u16 {
        self.inner.lock().unwrap().codec_ids
    }

    /// Rendering delay in milliseconds.
    pub fn render_delay(&self) -> u16 {
        self.inner.lock().unwrap().render_delay
    }

    /// Current volume level (−128 to 0).
    pub fn volume(&self) -> i8 {
        self.inner.lock().unwrap().volume
    }

    // -----------------------------------------------------------------
    // Callback registration
    // -----------------------------------------------------------------

    /// Register (or clear) the state-change callback.
    ///
    /// The callback receives the raw status code as `i32`:
    /// `0` = success, `-1` = write failure, `>0` = ASHA error status.
    ///
    /// The callback is one-shot: it is cleared after invocation.  Set it
    /// again before each [`start`](Self::start) call.
    pub fn set_state_cb<F: Fn(i32) + Send + Sync + 'static>(&self, cb: Option<F>) {
        let mut inner = self.inner.lock().unwrap();
        inner.state_cb = cb.map(|f| Arc::new(f) as StateCallback);
    }
}

impl Default for BtAsha {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BtAsha {
    /// On drop, remove this device from the global binaural set.
    ///
    /// Equivalent to the cleanup path in C `bt_asha_free()`.
    fn drop(&mut self) {
        // Only run cleanup if this is the last Arc reference to the inner
        // state.  If other clones exist (e.g. in the global set), skip.
        if Arc::strong_count(&self.inner) <= 2 {
            update_asha_set(self, false);
        }
    }
}

// ===========================================================================
// BtAshaSet — binaural hearing-aid pair
// ===========================================================================

/// Tracks a binaural hearing-aid pair sharing the same HiSyncId.
pub struct BtAshaSet {
    hisync_id: [u8; 8],
    left: Option<BtAsha>,
    right: Option<BtAsha>,
}

impl BtAshaSet {
    /// Reference to the left-ear device, if connected.
    pub fn left(&self) -> Option<&BtAsha> {
        self.left.as_ref()
    }

    /// Reference to the right-ear device, if connected.
    pub fn right(&self) -> Option<&BtAsha> {
        self.right.as_ref()
    }

    /// The 8-byte HiSyncId shared by both devices in the pair.
    pub fn hisync_id(&self) -> &[u8; 8] {
        &self.hisync_id
    }
}

impl PartialEq for BtAshaSet {
    fn eq(&self, other: &Self) -> bool {
        self.hisync_id == other.hisync_id
    }
}

impl std::fmt::Debug for BtAshaSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtAshaSet")
            .field("hisync_id", &self.hisync_id)
            .field("left", &self.left.as_ref().map(|_| "<BtAsha>"))
            .field("right", &self.right.as_ref().map(|_| "<BtAsha>"))
            .finish()
    }
}

// ===========================================================================
// Internal helpers — GATT characteristic handling
// ===========================================================================

/// Compare a UUID string against a [`CharData`] UUID.
fn uuid_matches(uuid_str: &str, char_uuid: &BtUuid) -> bool {
    match uuid_str.parse::<BtUuid>() {
        Ok(ref parsed) => parsed == char_uuid,
        Err(_) => false,
    }
}

/// Process a single discovered characteristic within the ASHA service.
///
/// Mirrors C `handle_characteristic()`.
fn handle_characteristic(
    inner: &Arc<Mutex<BtAshaInner>>,
    client: &Arc<BtGattClient>,
    attr: &GattDbAttribute,
) {
    let char_data: CharData = match attr.get_char_data() {
        Some(cd) => cd,
        None => {
            error!("Failed to obtain characteristic data");
            return;
        }
    };

    let value_handle = char_data.value_handle;
    let uuid = &char_data.uuid;
    let uuid_str = uuid.to_string();

    if uuid_matches(ASHA_CHRC_LE_PSM_OUT_UUID, uuid) {
        debug!("Got chrc {}/0x{:x}: LE_PSM_ID", uuid_str, value_handle);
        let inner_clone = Arc::clone(inner);
        let read_cb: ReadCallback = Box::new(move |success, att_ecode, value| {
            read_psm_handler(&inner_clone, success, att_ecode, value);
        });
        if client.read_value(value_handle, read_cb) == 0 {
            debug!("Failed to send request to read LE_PSM_OUT");
        }
    } else if uuid_matches(ASHA_CHRC_READ_ONLY_PROPERTIES_UUID, uuid) {
        debug!("Got chrc {}/0x{:x}: READ_ONLY_PROPERTIES", uuid_str, value_handle);
        let inner_clone = Arc::clone(inner);
        let read_cb: ReadCallback = Box::new(move |success, att_ecode, value| {
            read_rops_handler(&inner_clone, success, att_ecode, value);
        });
        if client.read_value(value_handle, read_cb) == 0 {
            debug!("Failed to send request for readonly properties");
        }
    } else if uuid_matches(ASHA_CHRC_AUDIO_CONTROL_POINT_UUID, uuid) {
        debug!("Got chrc {}/0x{:x}: AUDIO_CONTROL_POINT", uuid_str, value_handle);
        let mut guard = inner.lock().unwrap();
        guard.acp_handle = value_handle;
    } else if uuid_matches(ASHA_CHRC_VOLUME_UUID, uuid) {
        debug!("Got chrc {}/0x{:x}: VOLUME", uuid_str, value_handle);
        let mut guard = inner.lock().unwrap();
        guard.volume_handle = value_handle;
    } else if uuid_matches(ASHA_CHRC_AUDIO_STATUS_UUID, uuid) {
        debug!("Got chrc {}/0x{:x}: AUDIO_STATUS", uuid_str, value_handle);
        let register_cb: RegisterCallback = Box::new(|att_ecode| {
            if att_ecode != 0 {
                debug!("AudioStatusPoint register failed 0x{:04x}", att_ecode);
            } else {
                debug!("AudioStatusPoint register succeeded");
            }
        });
        let notify_inner = Arc::clone(inner);
        let notify_cb: NotifyCallback = Box::new(move |_value_handle, value| {
            audio_status_notify_handler(&notify_inner, value);
        });
        let reg_id = client.register_notify(value_handle, register_cb, notify_cb);
        if reg_id == 0 {
            debug!("Failed to send request to notify AudioStatus");
        } else {
            let mut guard = inner.lock().unwrap();
            guard.status_notify_id = reg_id;
        }
    } else {
        debug!("Unsupported characteristic: {}", uuid_str);
    }
}

// ===========================================================================
// Internal helpers — GATT read callbacks
// ===========================================================================

/// Handler for LE_PSM_OUT read completion.
///
/// Mirrors C `read_psm()`.
fn read_psm_handler(inner: &Arc<Mutex<BtAshaInner>>, success: bool, att_ecode: u8, value: &[u8]) {
    if !success {
        debug!("Reading PSM failed with ATT error: {}", att_ecode);
        return;
    }
    if value.len() != PSM_LENGTH {
        debug!("Reading PSM failed: unexpected length {}", value.len());
        return;
    }

    let psm = get_le16(value);
    debug!("Got PSM: {}", psm);

    {
        let mut guard = inner.lock().unwrap();
        guard.psm = psm;
    }

    check_probe_done(inner);
}

/// Handler for ReadOnlyProperties read completion.
///
/// Parses the 17-byte ROPs blob:
/// - byte  0:      version (must be 0x01)
/// - byte  1:      device capabilities (bits 0-2)
/// - bytes 2-9:    HiSyncId (8 bytes, 2-byte company + 6-byte id)
/// - byte 10:      feature map (bit 0 = CoC streaming supported)
/// - bytes 11-12:  render delay (LE16, milliseconds)
/// - bytes 13-14:  reserved
/// - bytes 15-16:  codec IDs (LE16, bitfield)
///
/// Mirrors C `read_rops()`.
fn read_rops_handler(inner: &Arc<Mutex<BtAshaInner>>, success: bool, att_ecode: u8, value: &[u8]) {
    if !success {
        debug!("Reading ROPs failed with ATT error: {}", att_ecode);
        return;
    }
    if value.len() != ROPS_LENGTH {
        debug!("Reading ROPs failed: unexpected length {}", value.len());
        return;
    }
    if value[0] != ROPS_VERSION {
        debug!("Unexpected ASHA version: {}", value[0]);
        return;
    }

    {
        let mut guard = inner.lock().unwrap();
        // Device Capabilities (byte 1)
        guard.right_side = (value[1] & 0x01) != 0;
        guard.binaural = (value[1] & 0x02) != 0;
        guard.csis_supported = (value[1] & 0x04) != 0;
        // HiSyncId (bytes 2-9)
        guard.hisync_id.copy_from_slice(&value[2..10]);
        // Feature map (byte 10)
        guard.coc_streaming_supported = (value[10] & 0x01) != 0;
        // Render delay (bytes 11-12, LE16)
        guard.render_delay = get_le16(&value[11..13]);
        // Codec IDs (bytes 15-16, LE16) — bytes 13-14 are reserved
        guard.codec_ids = get_le16(&value[15..17]);
    }

    let guard = inner.lock().unwrap();
    debug!(
        "Got ROPS: side {}, binaural {}, csis: {}, delay {}, codecs: {}",
        guard.right_side, guard.binaural, guard.csis_supported, guard.render_delay, guard.codec_ids
    );
    drop(guard);

    check_probe_done(inner);
}

// ===========================================================================
// Internal helpers — probe completion & attach callback
// ===========================================================================

/// Check whether both ReadOnlyProperties and LE_PSM_OUT have been read.
///
/// If so, invoke the attach callback.  Mirrors C `check_probe_done()`.
fn check_probe_done(inner: &Arc<Mutex<BtAshaInner>>) {
    let attach_cb_arc = {
        let guard = inner.lock().unwrap();
        // Need both PSM and a non-zero HiSyncId to be done.
        if guard.psm == 0 || guard.hisync_id == [0u8; 8] {
            return;
        }
        Arc::clone(&guard.attach_cb)
    };

    // Take the one-shot callback.
    let cb = {
        let mut cb_guard = attach_cb_arc.lock().unwrap();
        cb_guard.take()
    };
    if let Some(cb) = cb {
        cb();
    }
}

// ===========================================================================
// Internal helpers — ACP write callback
// ===========================================================================

/// Handler for AudioControlPoint write completion.
///
/// On success: log.  On failure: invoke state callback with `−1` and reset
/// state.  Mirrors C `asha_acp_sent()`.
fn acp_sent_handler(inner: &Arc<Mutex<BtAshaInner>>, success: bool, err: u8) {
    if success {
        debug!("AudioControlPoint command successfully sent");
        return;
    }

    error!("Failed to send AudioControlPoint command: {}", err);

    // Back up and clear callback.
    let cb = {
        let mut guard = inner.lock().unwrap();
        let cb = guard.state_cb.clone();
        guard.state = AshaState::Stopped;
        guard.state_cb = None;
        cb
    };

    if let Some(cb) = cb {
        cb(-1);
    }
}

// ===========================================================================
// Internal helpers — AudioStatusPoint notification
// ===========================================================================

/// Handler for AudioStatusPoint notification.
///
/// Mirrors C `audio_status_notify()`.
fn audio_status_notify_handler(inner: &Arc<Mutex<BtAshaInner>>, value: &[u8]) {
    if value.is_empty() {
        warn!("Empty AudioStatusPoint notification");
        return;
    }

    let status = value[0];
    debug!("ASHA status {}", status);

    // Back up callback before potential state changes.
    let (state_before, cb) = {
        let mut guard = inner.lock().unwrap();
        let cb = guard.state_cb.clone();
        let state_before = guard.state;

        if guard.state == AshaState::Starting {
            if status == 0 {
                guard.state = AshaState::Started;
                debug!("ASHA start complete");
            } else {
                guard.state = AshaState::Stopped;
                guard.state_cb = None;
                debug!("ASHA start failed");
            }
        }
        (state_before, cb)
    };

    // If we just transitioned to Started, update the global binaural set
    // and notify the other device.  These functions acquire their own locks
    // so we must not hold the inner lock.
    if state_before == AshaState::Starting && status == 0 {
        // Build a temporary BtAsha handle for set operations.
        let asha_handle = BtAsha { inner: Arc::clone(inner) };
        update_asha_set(&asha_handle, true);
        asha_set_send_status(inner, true);
    }

    // Invoke and clear the one-shot state callback.
    if let Some(cb) = cb {
        cb(i32::from(status));
        let mut guard = inner.lock().unwrap();
        guard.state_cb = None;
    }
}

// ===========================================================================
// Internal helpers — binaural set management
// ===========================================================================

/// Determine whether the other ear of a binaural pair is connected.
///
/// Returns `1` if the other side is present in the global set, `0` otherwise.
/// Mirrors C `is_other_connected()`.
fn is_other_connected(inner: &Arc<Mutex<BtAshaInner>>) -> u8 {
    let (hisync_id, right_side) = {
        let guard = inner.lock().unwrap();
        (guard.hisync_id, guard.right_side)
    };

    let devices = ASHA_DEVICES.lock().unwrap();
    if let Some(ref devs) = *devices {
        if let Some(set) = devs.find(|s| s.hisync_id == hisync_id) {
            if right_side && set.left.is_some() {
                debug!("ASHA right and left side connected");
                return 1;
            }
            if !right_side && set.right.is_some() {
                debug!("ASHA left and right side connected");
                return 1;
            }
        }
    }

    if right_side {
        debug!("ASHA right side connected");
    } else {
        debug!("ASHA left side connected");
    }
    0
}

/// Add or remove a device from the global binaural set.
///
/// Mirrors C `update_asha_set()`.
fn update_asha_set(asha: &BtAsha, connected: bool) {
    let (hisync_id, right_side) = {
        let guard = asha.inner.lock().unwrap();
        (guard.hisync_id, guard.right_side)
    };

    let mut devices_guard = ASHA_DEVICES.lock().unwrap();

    if connected {
        let devices = devices_guard.get_or_insert_with(Queue::new);

        // Try to find an existing set with the same HiSyncId.
        let mut found = false;
        devices.foreach_mut(|set| {
            if set.hisync_id == hisync_id {
                if right_side {
                    set.right = Some(asha.clone());
                    debug!("Right side registered for ASHA set");
                } else {
                    set.left = Some(asha.clone());
                    debug!("Left side registered for ASHA set");
                }
                found = true;
            }
        });

        if !found {
            let mut set = BtAshaSet { hisync_id, left: None, right: None };
            if right_side {
                set.right = Some(asha.clone());
                debug!("Right side registered for ASHA set");
            } else {
                set.left = Some(asha.clone());
                debug!("Left side registered for ASHA set");
            }
            devices.push_tail(set);
            debug!("Created ASHA set");
        }
    } else {
        let devices = match devices_guard.as_mut() {
            Some(d) => d,
            None => {
                // No global queue — nothing to remove.
                return;
            }
        };

        // Clear this device from its set.
        let mut set_empty = false;
        devices.foreach_mut(|set| {
            if set.hisync_id == hisync_id {
                if right_side && set.right.is_some() {
                    set.right = None;
                    debug!("Right side unregistered for ASHA set");
                } else if !right_side && set.left.is_some() {
                    set.left = None;
                    debug!("Left side unregistered for ASHA set");
                }

                if set.right.is_none() && set.left.is_none() {
                    set_empty = true;
                }
            }
        });

        // Remove the set if both sides are gone.
        if set_empty {
            let sentinel = BtAshaSet { hisync_id, left: None, right: None };
            if devices.remove(&sentinel) {
                debug!("Freeing ASHA set");
            }

            // Destroy the queue if completely empty.
            if devices.peek_tail().is_none() {
                *devices_guard = None;
            }
        }
    }
}

/// Send an ACP STATUS command to the other device in the binaural set.
///
/// Mirrors C `asha_set_send_status()`.
fn asha_set_send_status(inner: &Arc<Mutex<BtAshaInner>>, other_connected: bool) {
    let (hisync_id, right_side) = {
        let guard = inner.lock().unwrap();
        (guard.hisync_id, guard.right_side)
    };

    let other_device: Option<BtAsha> = {
        let devices = ASHA_DEVICES.lock().unwrap();
        if let Some(ref devs) = *devices {
            if let Some(set) = devs.find(|s| s.hisync_id == hisync_id) {
                if right_side { set.left.clone() } else { set.right.clone() }
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(other) = other_device {
        let ret = send_asha_status(&other, other_connected);
        let side = if right_side { "left" } else { "right" };
        debug!("ASHA {} side update: {}, ret: {}", side, other_connected, ret);
    }
}

/// Send an ACP STATUS command to a specific device.
///
/// Mirrors C `bt_asha_status()`.
fn send_asha_status(asha: &BtAsha, other_connected: bool) -> i32 {
    let status_byte: u8 = if other_connected { 1 } else { 0 };
    let acp_status_cmd: [u8; 2] = [ACP_OPCODE_STATUS, status_byte];

    let (state, acp_handle, client_ref) = {
        let guard = asha.inner.lock().unwrap();
        (guard.state, guard.acp_handle, guard.client.clone())
    };

    if state != AshaState::Started {
        let side = {
            let guard = asha.inner.lock().unwrap();
            if guard.right_side { "right" } else { "left" }
        };
        debug!("ASHA {} device not started for status update", side);
        return 0;
    }

    let client = match client_ref {
        Some(c) => c,
        None => return -1,
    };

    let req_id = client.write_without_response(acp_handle, false, &acp_status_cmd);
    if req_id == 0 {
        error!("Error writing ACP status command");
        return -1;
    }

    0
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asha_state_values() {
        assert_eq!(AshaState::Stopped as u8, 0);
        assert_eq!(AshaState::Starting as u8, 1);
        assert_eq!(AshaState::Started as u8, 2);
    }

    #[test]
    fn test_asha_new_defaults() {
        let asha = BtAsha::new();
        assert_eq!(asha.psm(), 0);
        assert_eq!(asha.state(), AshaState::Stopped);
        assert_eq!(asha.hisync_id(), [0u8; 8]);
        assert!(!asha.right_side());
        assert!(!asha.binaural());
        assert!(!asha.csis_supported());
        assert_eq!(asha.codec_ids(), 0);
        assert_eq!(asha.render_delay(), 0);
        assert_eq!(asha.volume(), 0);
    }

    #[test]
    fn test_asha_state_reset() {
        let asha = BtAsha::new();
        // Manually set state via inner (for testing).
        {
            let mut inner = asha.inner.lock().unwrap();
            inner.state = AshaState::Starting;
            inner.state_cb = Some(Arc::new(|_| {}));
        }
        asha.state_reset();
        assert_eq!(asha.state(), AshaState::Stopped);
    }

    #[test]
    fn test_asha_set_equality() {
        let set_a = BtAshaSet { hisync_id: [1, 2, 3, 4, 5, 6, 7, 8], left: None, right: None };
        let set_b = BtAshaSet { hisync_id: [1, 2, 3, 4, 5, 6, 7, 8], left: None, right: None };
        let set_c = BtAshaSet { hisync_id: [0, 0, 0, 0, 0, 0, 0, 1], left: None, right: None };
        assert_eq!(set_a, set_b);
        assert_ne!(set_a, set_c);
    }

    #[test]
    fn test_asha_profile_uuid_constant() {
        assert_eq!(ASHA_PROFILE_UUID, "0000FDF0-0000-1000-8000-00805f9b34fb");
        assert_eq!(ASHA_SERVICE, 0xFDF0);
    }

    #[test]
    fn test_start_without_attach_returns_error() {
        let asha = BtAsha::new();
        let result = asha.start();
        assert!(result.is_err());
        match result {
            Err(AshaError::NotAttached) => {}
            other => panic!("Expected NotAttached, got {:?}", other),
        }
    }

    #[test]
    fn test_stop_when_not_started_is_ok() {
        let asha = BtAsha::new();
        let result = asha.stop();
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_volume_without_client() {
        let asha = BtAsha::new();
        assert!(!asha.set_volume(-10));
    }

    #[test]
    fn test_asha_clone_shares_state() {
        let asha = BtAsha::new();
        let clone = asha.clone();

        {
            let mut inner = asha.inner.lock().unwrap();
            inner.psm = 42;
        }

        assert_eq!(clone.psm(), 42);
    }

    #[test]
    fn test_asha_set_accessors() {
        let asha = BtAsha::new();
        let set = BtAshaSet {
            hisync_id: [10, 20, 30, 40, 50, 60, 70, 80],
            left: Some(asha.clone()),
            right: None,
        };
        assert!(set.left().is_some());
        assert!(set.right().is_none());
        assert_eq!(set.hisync_id(), &[10, 20, 30, 40, 50, 60, 70, 80]);
    }

    #[test]
    fn test_uuid_matches_valid() {
        let uuid = ASHA_CHRC_VOLUME_UUID.parse::<BtUuid>().expect("valid UUID");
        assert!(uuid_matches(ASHA_CHRC_VOLUME_UUID, &uuid));
        assert!(!uuid_matches(ASHA_CHRC_AUDIO_STATUS_UUID, &uuid));
    }

    #[test]
    fn test_asha_default_trait() {
        let asha = BtAsha::default();
        assert_eq!(asha.state(), AshaState::Stopped);
    }

    #[test]
    fn test_acp_start_command_format() {
        let volume: i8 = -20;
        let other_connected: u8 = 1;
        let cmd: [u8; 5] = [ACP_OPCODE_START, CODEC_G722_16KHZ, 0, volume as u8, other_connected];
        assert_eq!(cmd[0], 0x01);
        assert_eq!(cmd[1], 0x01);
        assert_eq!(cmd[2], 0x00);
        assert_eq!(cmd[3], 0xEC); // -20 as u8 = 236 = 0xEC
        assert_eq!(cmd[4], 0x01);
    }

    #[test]
    fn test_acp_stop_command_format() {
        let cmd: [u8; 1] = [ACP_OPCODE_STOP];
        assert_eq!(cmd[0], 0x02);
    }
}
