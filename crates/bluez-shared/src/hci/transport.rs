// SPDX-License-Identifier: GPL-2.0-or-later
//! Async HCI (Host Controller Interface) socket transport.
//!
//! Complete Rust rewrite of BlueZ `src/shared/hci.c` (676 lines) and
//! `src/shared/hci.h` (44 lines). Replaces the opaque ref-counted
//! `struct bt_hci` with an [`Arc`]-based [`HciTransport`] using
//! `tokio::io::unix::AsyncFd` for async I/O.
//!
//! # Architecture
//!
//! * **Ownership** — `Arc<HciTransport>` replaces manual `bt_hci_ref/unref`.
//! * **Async I/O** — `AsyncFd<OwnedFd>` replaces the GLib/ELL mainloop
//!   `struct io` wrapper.  Two spawned tasks (reader + writer) replace
//!   `io_read_callback` / `io_write_callback`.
//! * **Channels** — `oneshot` channels replace per-command callback+user_data;
//!   `mpsc` channels replace per-event callback+user_data.
//! * **Flow control** — The `num_cmds` credit system is faithfully preserved
//!   (starts at 1; updated from Command Complete / Command Status events).

use std::collections::VecDeque;
use std::os::unix::io::{AsFd, AsRawFd, OwnedFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::sys::bluetooth::AF_BLUETOOTH;
use crate::sys::hci::{
    EVT_CMD_COMPLETE, EVT_CMD_STATUS, HCI_ACLDATA_PKT, HCI_CHANNEL_RAW, HCI_CHANNEL_USER,
    HCI_COMMAND_PKT, HCI_EVENT_PKT, HCI_ISODATA_PKT, HCI_SCODATA_PKT, evt_cmd_complete,
    evt_cmd_status, hci_acl_hdr, hci_command_hdr, hci_event_hdr, hci_filter, hci_filter_all_events,
    hci_filter_clear, hci_filter_set_ptype, sockaddr_hci,
};

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum read buffer size matching the C implementation (hci.c line 298).
const READ_BUF_SIZE: usize = 512;

/// HCI Command NOP opcode — response wakes writer without matching a command.
const HCI_CMD_NOP: u16 = 0x0000;

/// Default bounded capacity for event subscription mpsc channels.
const EVT_CHANNEL_CAPACITY: usize = 32;

/// Header sizes derived from the packed C struct definitions.
/// Using `size_of` on the imported repr(C,packed) structs ensures these
/// stay in sync with the kernel ABI declarations in `crate::sys::hci`.
const CMD_HDR_SIZE: usize = std::mem::size_of::<hci_command_hdr>();
const EVT_HDR_SIZE: usize = std::mem::size_of::<hci_event_hdr>();
const ACL_HDR_SIZE: usize = std::mem::size_of::<hci_acl_hdr>();
const CMD_COMPLETE_SIZE: usize = std::mem::size_of::<evt_cmd_complete>();
const CMD_STATUS_SIZE: usize = std::mem::size_of::<evt_cmd_status>();

// ===========================================================================
// Error Type
// ===========================================================================

/// Errors produced by [`HciTransport`] operations.
#[derive(Debug, thiserror::Error)]
pub enum HciError {
    /// Low-level I/O failure on the HCI socket.
    #[error("HCI I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Socket creation or bind failure (wraps `nix::errno::Errno`).
    #[error("HCI socket creation failed: {0}")]
    SocketCreate(nix::Error),

    /// HCI command could not be completed.
    #[error("HCI command failed")]
    CommandFailed,

    /// The transport has been shut down.
    #[error("HCI transport shut down")]
    Shutdown,

    /// Invalid HCI data packet type byte.
    #[error("invalid HCI data packet type: 0x{ptype:02x}")]
    InvalidPacketType {
        /// The offending packet type byte.
        ptype: u8,
    },
}

// ===========================================================================
// Public Data Types
// ===========================================================================

/// Response data from an HCI command.
///
/// For `Command Complete` events this contains the return parameters
/// (everything after the `evt_cmd_complete` header).
/// For `Command Status` events this contains a single status byte.
#[derive(Debug, Clone)]
pub struct HciResponse {
    /// Raw response payload bytes.
    pub data: Vec<u8>,
}

/// Asynchronous HCI event notification delivered to subscribers.
#[derive(Debug, Clone)]
pub struct HciEvent {
    /// HCI event code (e.g. 0x0E for Command Complete).
    pub event: u8,
    /// Event payload (after the 2-byte `hci_event_hdr`).
    pub data: Vec<u8>,
}

// ===========================================================================
// Internal Types
// ===========================================================================

/// A command enqueued for transmission, awaiting its response.
struct PendingCommand {
    /// Monotonic command ID (wraps, skips 0).
    id: u32,
    /// HCI command opcode (host byte order).
    opcode: u16,
    /// Command parameter data (cleared after the packet is sent).
    data: Vec<u8>,
    /// One-shot channel for delivering the response (or error) back to the
    /// caller of [`HciTransport::send_command`].
    response_tx: oneshot::Sender<Result<HciResponse, HciError>>,
}

/// A registered event subscription.
struct EventSubscription {
    /// Monotonic subscription ID (wraps, skips 0).
    id: u32,
    /// HCI event code to match.
    event: u8,
    /// Channel sender for delivering matching events to the subscriber.
    sender: mpsc::Sender<HciEvent>,
}

/// A data packet (ACL/SCO/ISO) enqueued for transmission.
struct DataPacket {
    /// H4 packet type byte (ACL=0x02, SCO=0x03, ISO=0x05).
    packet_type: u8,
    /// Connection handle (little-endian on wire).
    handle: u16,
    /// Payload data bytes.
    data: Vec<u8>,
}

// ===========================================================================
// Mutex-Protected Inner State
// ===========================================================================

/// Shared mutable state protected by a [`Mutex`].
///
/// This mirrors the mutable fields of the C `struct bt_hci` (lines 50–62).
struct HciInner {
    /// Flow-control credits (starts at 1; updated from CMD_COMPLETE/STATUS).
    num_cmds: u8,
    /// Monotonic counter for command IDs (wraps, skips 0).
    next_cmd_id: u32,
    /// Monotonic counter for event subscription IDs (wraps, skips 0).
    next_evt_id: u32,
    /// Commands waiting to be sent (FIFO).
    cmd_queue: VecDeque<PendingCommand>,
    /// Commands already sent, awaiting a response (searched by opcode).
    rsp_queue: Vec<PendingCommand>,
    /// Registered event subscriptions.
    evt_list: Vec<EventSubscription>,
    /// Data packets waiting to be sent (FIFO).
    data_queue: VecDeque<DataPacket>,
}

impl HciInner {
    /// Create a new inner state with default initial values matching the C
    /// `create_hci()` function: `num_cmds = 1`, IDs start at 1, empty queues.
    fn new() -> Self {
        Self {
            num_cmds: 1,
            next_cmd_id: 1,
            next_evt_id: 1,
            cmd_queue: VecDeque::new(),
            rsp_queue: Vec::new(),
            evt_list: Vec::new(),
            data_queue: VecDeque::new(),
        }
    }

    /// Allocate the next command ID, wrapping around and skipping 0.
    ///
    /// Matches the C pattern: `if (hci->next_cmd_id < 1) hci->next_cmd_id = 1;`
    fn alloc_cmd_id(&mut self) -> u32 {
        let id = self.next_cmd_id;
        self.next_cmd_id = self.next_cmd_id.wrapping_add(1);
        if self.next_cmd_id == 0 {
            self.next_cmd_id = 1;
        }
        id
    }

    /// Allocate the next event subscription ID, wrapping around and skipping 0.
    fn alloc_evt_id(&mut self) -> u32 {
        let id = self.next_evt_id;
        self.next_evt_id = self.next_evt_id.wrapping_add(1);
        if self.next_evt_id == 0 {
            self.next_evt_id = 1;
        }
        id
    }
}

// ===========================================================================
// HciTransport
// ===========================================================================

/// Async HCI socket transport.
///
/// Provides command/response and event subscription APIs over an HCI socket,
/// with background reader and writer tasks handling the actual I/O.
///
/// # Lifecycle
///
/// Created via [`new`](Self::new), [`new_user_channel`](Self::new_user_channel),
/// or [`new_raw_device`](Self::new_raw_device).  Returned as `Arc<Self>` to
/// enable shared ownership (replaces C ref-counting).  Background tasks are
/// automatically cancelled when the last `Arc` drops or
/// [`shutdown`](Self::shutdown) is called.
pub struct HciTransport {
    /// Shared mutable inner state (command queues, subscriptions, counters).
    inner: Arc<Mutex<HciInner>>,
    /// Async file descriptor wrapping the HCI socket.
    /// Stored to keep the socket alive for the transport's lifetime.
    /// Background tasks hold their own Arc clones for I/O.
    _async_fd: Arc<AsyncFd<OwnedFd>>,
    /// Notifier to wake the writer task when new work is enqueued
    /// (replaces the C `wakeup_writer()` pattern).
    write_notify: Arc<Notify>,
    /// Sender half of the shutdown watch channel.
    shutdown_tx: watch::Sender<bool>,
    /// Background reader task handle (aborted on drop).
    reader_handle: JoinHandle<()>,
    /// Background writer task handle (aborted on drop).
    writer_handle: JoinHandle<()>,
}

impl HciTransport {
    // -----------------------------------------------------------------------
    // Private construction helper
    // -----------------------------------------------------------------------

    /// Core constructor shared by all public constructors.
    ///
    /// `is_stream` mirrors the C `create_hci()` flag: when `true` (stream
    /// mode, e.g. wrapping a serial port fd), the reader task exits
    /// immediately because stream framing is not implemented — matching the
    /// C `io_read_callback()` which returns `false` in stream mode.
    fn create(fd: OwnedFd, is_stream: bool) -> Result<Arc<Self>, HciError> {
        let async_fd = Arc::new(AsyncFd::new(fd)?);
        let inner = Arc::new(Mutex::new(HciInner::new()));
        let write_notify = Arc::new(Notify::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn the background reader task.
        let reader_handle = tokio::spawn(reader_task(
            Arc::clone(&async_fd),
            Arc::clone(&inner),
            Arc::clone(&write_notify),
            is_stream,
            shutdown_rx.clone(),
        ));

        // Spawn the background writer task.
        let writer_handle = tokio::spawn(writer_task(
            Arc::clone(&async_fd),
            Arc::clone(&inner),
            Arc::clone(&write_notify),
            shutdown_rx,
        ));

        Ok(Arc::new(Self {
            inner,
            _async_fd: async_fd,
            write_notify,
            shutdown_tx,
            reader_handle,
            writer_handle,
        }))
    }

    // -----------------------------------------------------------------------
    // Public constructors
    // -----------------------------------------------------------------------

    /// Wrap an existing file descriptor as an HCI transport (stream mode).
    ///
    /// Equivalent to the C `bt_hci_new(fd)`.  The reader task is spawned
    /// but exits immediately because stream-mode framing is not implemented,
    /// matching the C `io_read_callback()` behavior.
    pub fn new(fd: OwnedFd) -> Result<Arc<Self>, HciError> {
        Self::create(fd, true)
    }

    /// Open an HCI User Channel socket for the given adapter index.
    ///
    /// Equivalent to the C `bt_hci_new_user_channel(index)`.
    /// Creates an `AF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` socket bound to
    /// `HCI_CHANNEL_USER`, giving exclusive access to the controller.
    ///
    /// Socket creation and binding are delegated to `crate::sys::hci` FFI
    /// helpers which use `libc` syscall wrappers.
    pub fn new_user_channel(index: u16) -> Result<Arc<Self>, HciError> {
        let addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: index,
            hci_channel: HCI_CHANNEL_USER,
        };
        let fd = crate::sys::hci::create_hci_socket(&addr).map_err(HciError::SocketCreate)?;
        Self::create(fd, false)
    }

    /// Open an HCI Raw Device socket for the given adapter index.
    ///
    /// Equivalent to the C `bt_hci_new_raw_device(index)`.
    /// Creates an `AF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` socket bound to
    /// `HCI_CHANNEL_RAW` with an event-only HCI filter configured via
    /// `setsockopt(SOL_HCI, HCI_FILTER, ...)`.
    pub fn new_raw_device(index: u16) -> Result<Arc<Self>, HciError> {
        let addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: index,
            hci_channel: HCI_CHANNEL_RAW,
        };
        let fd = crate::sys::hci::create_hci_socket(&addr).map_err(HciError::SocketCreate)?;

        // Configure HCI filter: accept event packets only, all event codes.
        // Matches the C hci.c lines 432–437.
        let mut flt = hci_filter::default();
        hci_filter_clear(&mut flt);
        hci_filter_set_ptype(HCI_EVENT_PKT, &mut flt);
        hci_filter_all_events(&mut flt);
        crate::sys::hci::set_hci_filter_sockopt(fd.as_fd(), &flt)
            .map_err(HciError::SocketCreate)?;

        Self::create(fd, false)
    }

    // -----------------------------------------------------------------------
    // Command API
    // -----------------------------------------------------------------------

    /// Send an HCI command and await its response.
    ///
    /// The command is enqueued and sent by the background writer task when
    /// flow-control credits are available (`num_cmds > 0`).  The response
    /// arrives via the background reader task, which matches the response
    /// to this command by opcode.
    ///
    /// Returns the response payload from the matching `Command Complete` or
    /// `Command Status` event.
    pub async fn send_command(&self, opcode: u16, data: &[u8]) -> Result<HciResponse, HciError> {
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            let id = inner.alloc_cmd_id();
            inner.cmd_queue.push_back(PendingCommand {
                id,
                opcode,
                data: data.to_vec(),
                response_tx: tx,
            });
        }
        // Wake the writer task so it can send the queued command.
        self.write_notify.notify_one();

        // Await the response delivered by the reader task.
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(HciError::Shutdown),
        }
    }

    /// Cancel a pending command by its ID.
    ///
    /// Searches both the unsent command queue and the response-pending queue.
    /// Returns `true` if the command was found and removed.  The associated
    /// oneshot sender is dropped, causing the receiver to get a `RecvError`.
    pub async fn cancel(&self, id: u32) -> bool {
        let mut inner = self.inner.lock().await;

        // Try to remove from cmd_queue (not yet sent).
        if let Some(pos) = inner.cmd_queue.iter().position(|c| c.id == id) {
            let _cmd = inner.cmd_queue.remove(pos);
            drop(inner);
            self.write_notify.notify_one();
            return true;
        }

        // Try to remove from rsp_queue (sent, awaiting response).
        if let Some(pos) = inner.rsp_queue.iter().position(|c| c.id == id) {
            let _cmd = inner.rsp_queue.remove(pos);
            drop(inner);
            self.write_notify.notify_one();
            return true;
        }

        false
    }

    /// Flush all pending commands and data packets.
    ///
    /// All queued commands (both unsent and awaiting response) and data
    /// packets are dropped.  Callers awaiting responses via `send_command`
    /// will receive `Err(HciError::Shutdown)` because the oneshot senders
    /// are dropped.
    pub async fn flush(&self) {
        let mut inner = self.inner.lock().await;
        inner.cmd_queue.clear();
        inner.rsp_queue.clear();
        inner.data_queue.clear();
    }

    // -----------------------------------------------------------------------
    // Event subscription API
    // -----------------------------------------------------------------------

    /// Subscribe to HCI events with the given event code.
    ///
    /// Returns a `(subscription_id, Receiver)` pair.  The receiver yields
    /// [`HciEvent`] values for every matching event received by the reader
    /// task.  Use [`unsubscribe`](Self::unsubscribe) to remove the
    /// subscription.
    ///
    /// The channel is bounded to [`EVT_CHANNEL_CAPACITY`] (32) to prevent
    /// unbounded memory growth if the consumer falls behind.  Excess events
    /// are silently dropped (matching C behavior where slow callbacks could
    /// miss events).
    pub async fn subscribe(&self, event: u8) -> (u32, mpsc::Receiver<HciEvent>) {
        let (tx, rx) = mpsc::channel(EVT_CHANNEL_CAPACITY);
        let mut inner = self.inner.lock().await;
        let id = inner.alloc_evt_id();
        inner.evt_list.push(EventSubscription { id, event, sender: tx });
        (id, rx)
    }

    /// Remove an event subscription by its ID.
    ///
    /// Returns `true` if the subscription was found and removed.  The mpsc
    /// sender is dropped, causing the receiver to eventually return `None`.
    pub async fn unsubscribe(&self, id: u32) -> bool {
        let mut inner = self.inner.lock().await;
        if let Some(pos) = inner.evt_list.iter().position(|e| e.id == id) {
            inner.evt_list.remove(pos);
            true
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Data API
    // -----------------------------------------------------------------------

    /// Enqueue an HCI data packet (ACL, SCO, or ISO) for transmission.
    ///
    /// Only packet types ACL (0x02), SCO (0x03), and ISO (0x05) are
    /// accepted, matching the C `bt_hci_send_data()` validation (lines
    /// 620–627).
    pub async fn send_data(
        &self,
        packet_type: u8,
        handle: u16,
        data: &[u8],
    ) -> Result<(), HciError> {
        // Validate packet type: only ACL, SCO, ISO.
        match packet_type {
            HCI_ACLDATA_PKT | HCI_SCODATA_PKT | HCI_ISODATA_PKT => {}
            _ => return Err(HciError::InvalidPacketType { ptype: packet_type }),
        }

        {
            let mut inner = self.inner.lock().await;
            inner.data_queue.push_back(DataPacket { packet_type, handle, data: data.to_vec() });
        }
        self.write_notify.notify_one();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    /// Signal a graceful shutdown of the transport.
    ///
    /// Sends a shutdown signal to both background tasks and aborts them.
    /// The underlying socket fd is closed when all `Arc` references to the
    /// `AsyncFd` are dropped.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.reader_handle.abort();
        self.writer_handle.abort();
    }
}

impl Drop for HciTransport {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.reader_handle.abort();
        self.writer_handle.abort();
    }
}

// ===========================================================================
// Background Reader Task
// ===========================================================================

/// Background task that reads HCI packets from the socket and dispatches
/// events and command responses.
///
/// Mirrors the C `io_read_callback()` + `process_event()` +
/// `process_response()` + `process_notify()` logic.
async fn reader_task(
    async_fd: Arc<AsyncFd<OwnedFd>>,
    inner: Arc<Mutex<HciInner>>,
    write_notify: Arc<Notify>,
    is_stream: bool,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    // Stream mode: the C code immediately returns false (deregisters the
    // read handler).  We replicate this by exiting the task immediately.
    if is_stream {
        return;
    }

    let mut buf = [0u8; READ_BUF_SIZE];

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            ready = async_fd.readable() => {
                let mut guard = match ready {
                    Ok(g) => g,
                    Err(_) => break,
                };

                // Attempt a non-blocking read within the readiness guard.
                let n = match guard.try_io(|fd| {
                    nix::unistd::read(fd.get_ref().as_raw_fd(), &mut buf)
                        .map_err(std::io::Error::from)
                }) {
                    Ok(Ok(n)) if n > 0 => n,
                    Ok(Ok(_)) => continue,         // EOF or 0 bytes
                    Ok(Err(_)) => break,            // real I/O error
                    Err(_would_block) => continue,  // spurious wakeup
                };

                // Parse H4 packet type from the first byte.
                let ptype = buf[0];
                if ptype == HCI_EVENT_PKT {
                    process_event(&buf[1..n], &inner, &write_notify).await;
                }
                // ACL/SCO/ISO data from the controller is not dispatched
                // in the C implementation either — only events are processed.
            }
        }
    }
}

/// Process a received HCI event packet.
///
/// `data` points past the H4 type byte: `[evt_hdr(2), payload(plen)]`.
///
/// Mirrors the C `process_event()` (hci.c lines 255–293).
async fn process_event(data: &[u8], inner: &Arc<Mutex<HciInner>>, write_notify: &Notify) {
    // Need at least an event header (evt: u8, plen: u8).
    if data.len() < EVT_HDR_SIZE {
        return;
    }
    let evt = data[0];
    let plen = data[1] as usize;

    // Validate that the declared payload length fits the available data.
    if data.len() < EVT_HDR_SIZE + plen {
        return;
    }
    let payload = &data[EVT_HDR_SIZE..EVT_HDR_SIZE + plen];

    match evt {
        EVT_CMD_COMPLETE => {
            // Payload: ncmd(1) + opcode(2) + return_params(variable)
            if payload.len() < CMD_COMPLETE_SIZE {
                return;
            }
            let ncmd = payload[0];
            let opcode = u16::from_le_bytes([payload[1], payload[2]]);
            let response_data = payload[CMD_COMPLETE_SIZE..].to_vec();

            process_response(inner, write_notify, ncmd, opcode, response_data).await;
        }
        EVT_CMD_STATUS => {
            // Payload: status(1) + ncmd(1) + opcode(2)
            if payload.len() < CMD_STATUS_SIZE {
                return;
            }
            let status = payload[0];
            let ncmd = payload[1];
            let opcode = u16::from_le_bytes([payload[2], payload[3]]);
            // For Command Status the response data is just the status byte.
            let response_data = vec![status];

            process_response(inner, write_notify, ncmd, opcode, response_data).await;
        }
        _ => {
            // Dispatch to event subscribers (mirrors C process_notify).
            process_notify(inner, evt, payload).await;
        }
    }
}

/// Process a command response (from CMD_COMPLETE or CMD_STATUS).
///
/// Updates `num_cmds` flow-control credit, matches the response to a
/// pending command in `rsp_queue` by opcode, and delivers the response
/// via the oneshot channel.
///
/// Mirrors the C `process_response()` (hci.c lines 215–243).
async fn process_response(
    inner: &Arc<Mutex<HciInner>>,
    write_notify: &Notify,
    ncmd: u8,
    opcode: u16,
    response_data: Vec<u8>,
) {
    let mut state = inner.lock().await;
    state.num_cmds = ncmd;

    // NOP (opcode 0x0000): just wake the writer (new credits may be
    // available).  Do NOT match against any pending command.
    if opcode == HCI_CMD_NOP {
        drop(state);
        write_notify.notify_one();
        return;
    }

    // Find and remove the matching command from the response queue.
    if let Some(pos) = state.rsp_queue.iter().position(|c| c.opcode == opcode) {
        let cmd = state.rsp_queue.remove(pos);
        // Release the lock BEFORE sending the response — the receiver
        // might immediately enqueue a new command that needs the lock.
        drop(state);
        let _ = cmd.response_tx.send(Ok(HciResponse { data: response_data }));
    } else {
        drop(state);
    }

    // Wake writer: num_cmds may have been replenished.
    write_notify.notify_one();
}

/// Notify event subscribers for a non-command event.
///
/// Iterates all subscriptions and sends to those matching the event code.
///
/// Mirrors the C `process_notify()` (hci.c lines 245–253).
async fn process_notify(inner: &Arc<Mutex<HciInner>>, evt: u8, payload: &[u8]) {
    let state = inner.lock().await;
    for sub in &state.evt_list {
        if sub.event == evt {
            // Use try_send to avoid holding the lock across an await point.
            // If the receiver's buffer is full the event is silently dropped,
            // mirroring the C behavior where slow callbacks could miss events.
            let _ = sub.sender.try_send(HciEvent { event: evt, data: payload.to_vec() });
        }
    }
}

// ===========================================================================
// Background Writer Task
// ===========================================================================

/// Background task that sends pending commands and data packets.
///
/// Mirrors the C `io_write_callback()` (hci.c lines 169–191): each
/// activation sends at most one command (if flow-control credits allow)
/// and one data packet, then yields.  If more work remains the task
/// re-notifies itself.
async fn writer_task(
    async_fd: Arc<AsyncFd<OwnedFd>>,
    inner: Arc<Mutex<HciInner>>,
    write_notify: Arc<Notify>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        // Wait for work or shutdown.
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            _ = write_notify.notified() => {}
        }

        // --- Send one command (if flow-control credits allow) ---
        let cmd_packet = {
            let mut state = inner.lock().await;
            if state.num_cmds > 0 {
                if let Some(mut cmd) = state.cmd_queue.pop_front() {
                    // Build H4 command packet: [0x01, opcode_le16, plen, data…]
                    let plen = cmd.data.len() as u8;
                    let mut pkt = Vec::with_capacity(1 + CMD_HDR_SIZE + cmd.data.len());
                    pkt.push(HCI_COMMAND_PKT);
                    pkt.extend_from_slice(&cmd.opcode.to_le_bytes());
                    pkt.push(plen);
                    pkt.extend_from_slice(&cmd.data);

                    // Consume a flow-control credit.
                    state.num_cmds -= 1;

                    // Move command to rsp_queue (data no longer needed for
                    // sending — clear it to free memory).
                    cmd.data.clear();
                    state.rsp_queue.push(cmd);

                    Some(pkt)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(pkt) = cmd_packet {
            if write_packet(&async_fd, &pkt).await.is_err() {
                break;
            }
        }

        // --- Send one data packet ---
        let data_packet = {
            let mut state = inner.lock().await;
            state.data_queue.pop_front().map(|dp| {
                // Build H4 data packet: [type, handle_le16, dlen_le16, data…]
                let mut pkt = Vec::with_capacity(1 + ACL_HDR_SIZE + dp.data.len());
                pkt.push(dp.packet_type);
                pkt.extend_from_slice(&dp.handle.to_le_bytes());
                pkt.extend_from_slice(&(dp.data.len() as u16).to_le_bytes());
                pkt.extend_from_slice(&dp.data);
                pkt
            })
        };
        if let Some(pkt) = data_packet {
            if write_packet(&async_fd, &pkt).await.is_err() {
                break;
            }
        }

        // Check if more work remains; if so, re-notify to process next items.
        let more_work = {
            let state = inner.lock().await;
            (!state.cmd_queue.is_empty() && state.num_cmds > 0) || !state.data_queue.is_empty()
        };
        if more_work {
            write_notify.notify_one();
        }
    }
}

/// Write a complete packet to the socket via `AsyncFd`.
///
/// Retries on `EAGAIN`/`EWOULDBLOCK` by waiting for writable readiness.
async fn write_packet(async_fd: &AsyncFd<OwnedFd>, packet: &[u8]) -> Result<(), std::io::Error> {
    loop {
        let mut guard = async_fd.writable().await?;
        match guard
            .try_io(|fd| nix::unistd::write(fd.get_ref(), packet).map_err(std::io::Error::from))
        {
            Ok(Ok(_n)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}
