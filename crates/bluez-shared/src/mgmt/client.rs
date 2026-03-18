// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// MGMT protocol client — idiomatic Rust rewrite of `src/shared/mgmt.c` (1093 lines).
//
// This module is the central control-plane transport used by `bluetoothd` and
// all integration testers for communicating with the kernel Bluetooth subsystem
// over `HCI_CHANNEL_CONTROL`.
//
// All MGMT commands/events are sent/received with byte-identical wire encoding
// to the C original, satisfying the behavioral clone mandate (AAP §0.8.1).
//
// Key design decisions:
// - `callback_t + user_data` → `async fn` + `oneshot`/`mpsc` channels
// - `mgmt_ref` / `mgmt_unref` → `Arc<MgmtSocket>`
// - `struct queue` → `VecDeque<T>`, `Vec` for pending command lookup
// - `io_set_read_handler` → `AsyncFd::readable().await` in spawned task
// - `io_set_write_handler` → writer triggered via `Notify`
// - `timeout_add_seconds` → `tokio::time::sleep`
// - Endianness: all `mgmt_hdr` fields use little-endian (`.to_le()` / `u16::from_le()`)

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Duration;

use zerocopy::IntoBytes;

use crate::sys::bluetooth::AF_BLUETOOTH;
use crate::sys::hci::{HCI_CHANNEL_CONTROL, HCI_DEV_NONE, HCI_MAX_ACL_SIZE, sockaddr_hci};
use crate::sys::mgmt::{
    MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS, MGMT_HDR_SIZE, MGMT_INDEX_NONE, MGMT_STATUS_FAILED,
    mgmt_errstr, mgmt_evstr, mgmt_hdr, mgmt_opstr, mgmt_tlv,
};

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Errors produced by the MGMT client transport.
#[derive(Debug, thiserror::Error)]
pub enum MgmtError {
    /// Underlying I/O error from socket operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The kernel returned a non-success MGMT status code.
    #[error("MGMT status: {status} ({message})")]
    MgmtStatus {
        /// Raw MGMT_STATUS_* code.
        status: u8,
        /// Human-readable status name from `mgmt_errstr`.
        message: &'static str,
    },

    /// A command timed out before receiving a response.
    #[error("command timed out")]
    Timeout,

    /// The caller supplied an invalid (zero) opcode.
    #[error("invalid opcode: {0}")]
    InvalidOpcode(u16),

    /// The parameter payload exceeds the negotiated MGMT MTU.
    #[error("invalid parameters: length {length} exceeds MTU {mtu}")]
    ParamsTooLong {
        /// Actual parameter length.
        length: u16,
        /// Negotiated MTU.
        mtu: u16,
    },

    /// The MGMT socket has been closed.
    #[error("socket closed")]
    Closed,

    /// A `nix` crate syscall error.
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
}

impl MgmtError {
    /// Create an `MgmtStatus` error from a raw MGMT status code.
    pub fn from_mgmt_status(status: u8) -> Self {
        MgmtError::MgmtStatus { status, message: mgmt_errstr(status) }
    }
}

// ---------------------------------------------------------------------------
// Response and Event Types
// ---------------------------------------------------------------------------

/// Response to a queued or pending MGMT command.
#[derive(Debug, Clone)]
pub struct MgmtResponse {
    /// MGMT status code from the kernel.
    pub status: u8,
    /// The opcode of the original command.
    pub opcode: u16,
    /// The controller index of the original command.
    pub index: u16,
    /// Any additional data returned by the kernel (after the 3-byte
    /// `mgmt_ev_cmd_complete` header, or empty for `CMD_STATUS`).
    pub data: Vec<u8>,
}

/// An asynchronous MGMT event delivered to subscribers.
#[derive(Debug, Clone)]
pub struct MgmtEvent {
    /// MGMT event code.
    pub event: u16,
    /// Controller index the event was raised for.
    pub index: u16,
    /// Event parameter data (after the 6-byte `mgmt_hdr`).
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// TLV Types
// ---------------------------------------------------------------------------

/// A single Type-Length-Value entry for MGMT TLV command parameters.
#[derive(Debug, Clone)]
pub struct MgmtTlvEntry {
    /// TLV type identifier (little-endian on wire).
    pub type_: u16,
    /// Raw value bytes.
    pub data: Vec<u8>,
}

/// An ordered list of MGMT TLV entries.
///
/// This type replaces the C `struct mgmt_tlv_list` and manages the total
/// serialized size for efficient buffer allocation.
#[derive(Debug, Clone)]
pub struct MgmtTlvList {
    entries: Vec<MgmtTlvEntry>,
    total_size: u16,
}

impl MgmtTlvList {
    /// Create an empty TLV list.
    pub fn new() -> Self {
        MgmtTlvList { entries: Vec::new(), total_size: 0 }
    }

    /// Return the total serialized byte size of all entries.
    ///
    /// Each entry contributes `sizeof(mgmt_tlv) + data.len()` = `3 + data.len()`.
    pub fn size(&self) -> u16 {
        self.total_size
    }

    /// Add a TLV entry with the given type and raw value bytes.
    ///
    /// Returns `true` on success, `false` if the value length exceeds 255
    /// or adding the entry would overflow the total size.
    pub fn add(&mut self, type_: u16, value: &[u8]) -> bool {
        if value.len() > u8::MAX as usize {
            return false;
        }
        let entry_size: u16 = 3 + value.len() as u16;
        match self.total_size.checked_add(entry_size) {
            Some(new_size) => {
                self.entries.push(MgmtTlvEntry { type_, data: value.to_vec() });
                self.total_size = new_size;
                true
            }
            None => false,
        }
    }

    /// Add a TLV entry for a fixed-size type that implements `IntoBytes`.
    ///
    /// This is the Rust equivalent of the C `mgmt_tlv_add_fixed` macro.
    pub fn add_fixed<T: IntoBytes + zerocopy::Immutable>(&mut self, type_: u16, value: &T) -> bool {
        self.add(type_, value.as_bytes())
    }

    /// Parse a TLV list from a raw buffer.
    ///
    /// Returns `None` if the buffer is empty or contains a malformed entry
    /// that would read beyond the buffer boundary.
    pub fn load_from_buf(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        let mut list = MgmtTlvList::new();
        let tlv_hdr_size = std::mem::size_of::<mgmt_tlv>();
        let mut cursor: usize = 0;

        while cursor < buf.len() {
            if cursor + tlv_hdr_size > buf.len() {
                return None;
            }
            let type_ = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
            let length = buf[cursor + 2] as usize;
            cursor += tlv_hdr_size;

            if cursor + length > buf.len() {
                return None;
            }
            if !list.add(type_, &buf[cursor..cursor + length]) {
                return None;
            }
            cursor += length;
        }
        Some(list)
    }

    /// Serialize the TLV list to a byte buffer suitable for wire transmission.
    ///
    /// Each entry is serialized as: `[type_le16][length_u8][data...]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.total_size as usize);
        for entry in &self.entries {
            buf.extend_from_slice(&entry.type_.to_le_bytes());
            buf.push(entry.data.len() as u8);
            buf.extend_from_slice(&entry.data);
        }
        buf
    }

    /// Iterate over all entries in order.
    pub fn iter(&self) -> impl Iterator<Item = &MgmtTlvEntry> {
        self.entries.iter()
    }
}

impl Default for MgmtTlvList {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a MgmtTlvList {
    type Item = &'a MgmtTlvEntry;
    type IntoIter = std::slice::Iter<'a, MgmtTlvEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

// ---------------------------------------------------------------------------
// IO Capability Helpers
// ---------------------------------------------------------------------------

/// Bluetooth MGMT IO capability values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MgmtIoCapability {
    /// Display Only — device can display a passkey but not receive input.
    DisplayOnly = 0x00,
    /// Display Yes/No — device can display and confirm.
    DisplayYesNo = 0x01,
    /// Keyboard Only — device has keyboard input capability.
    KeyboardOnly = 0x02,
    /// No Input No Output — device has no user interaction capability.
    NoInputNoOutput = 0x03,
    /// Keyboard Display — device has both keyboard and display.
    KeyboardDisplay = 0x04,
    /// Invalid — no valid IO capability could be determined.
    Invalid = 0xFF,
}

/// Static table of IO capability argument names and values for shell
/// tab-completion and parsing (matching C `iocap_arguments[]`).
static IOCAP_ARGUMENTS: &[(&str, MgmtIoCapability)] = &[
    ("DisplayOnly", MgmtIoCapability::DisplayOnly),
    ("DisplayYesNo", MgmtIoCapability::DisplayYesNo),
    ("KeyboardOnly", MgmtIoCapability::KeyboardOnly),
    ("NoInputNoOutput", MgmtIoCapability::NoInputNoOutput),
    ("KeyboardDisplay", MgmtIoCapability::KeyboardDisplay),
];

/// Stateful tab-completion generator for IO capability arguments.
///
/// On each call, searches from `*state` forward through `IOCAP_ARGUMENTS` for
/// an entry whose name starts with `text`. Returns the matched name or `None`
/// when exhausted. The caller must set `*state = 0` for the first call of a
/// new completion session (matching C `mgmt_iocap_generator` behavior exactly).
pub fn mgmt_iocap_generator(text: &str, state: &mut usize) -> Option<String> {
    while *state < IOCAP_ARGUMENTS.len() {
        let (name, _) = IOCAP_ARGUMENTS[*state];
        *state += 1;
        if name.starts_with(text) {
            return Some(name.to_string());
        }
    }
    None
}

/// Parse an IO capability string (prefix match) to the corresponding enum value.
///
/// An empty string returns `KeyboardDisplay` (matching C default).
/// If no prefix match is found, returns `Invalid`.
pub fn mgmt_parse_io_capability(capability: &str) -> MgmtIoCapability {
    if capability.is_empty() {
        return MgmtIoCapability::KeyboardDisplay;
    }
    for &(name, value) in IOCAP_ARGUMENTS {
        if name.starts_with(capability) {
            return value;
        }
    }
    MgmtIoCapability::Invalid
}

// ---------------------------------------------------------------------------
// Internal State Types
// ---------------------------------------------------------------------------

/// A queued MGMT command ready for serialization and sending.
struct QueuedRequest {
    /// Unique request identifier.
    id: u32,
    /// MGMT opcode (host byte order).
    opcode: u16,
    /// Controller index (host byte order).
    index: u16,
    /// Pre-serialized wire buffer: `mgmt_hdr` + parameter payload.
    buf: Vec<u8>,
    /// Channel to deliver the command response.
    sender: oneshot::Sender<MgmtResponse>,
    /// Timeout in seconds (0 = no timeout).
    timeout_secs: u64,
}

/// A pending command that has been sent to the kernel and is awaiting a
/// CMD_COMPLETE or CMD_STATUS event.
struct PendingCommand {
    /// Unique request identifier.
    id: u32,
    /// MGMT opcode (host byte order).
    opcode: u16,
    /// Controller index (host byte order).
    index: u16,
    /// Channel to deliver the response.
    sender: oneshot::Sender<MgmtResponse>,
    /// Handle to the timeout task, if any.
    timeout_handle: Option<JoinHandle<()>>,
}

/// An event subscription registered by the caller.
struct NotifySubscription {
    /// Unique subscription identifier.
    id: u32,
    /// MGMT event code to match.
    event: u16,
    /// Controller index to match (MGMT_INDEX_NONE matches all).
    index: u16,
    /// Channel to deliver matching events.
    sender: mpsc::Sender<MgmtEvent>,
}

/// Shared interior state of the MGMT client, protected by an async `Mutex`.
struct MgmtInner {
    /// Negotiated MGMT MTU (parameter payload max).
    mtu: u16,
    /// Next auto-incremented request ID (starts at 1).
    next_request_id: u32,
    /// Next auto-incremented subscription ID (starts at 1).
    next_notify_id: u32,
    /// Commands pending a kernel response.
    pending: Vec<PendingCommand>,
    /// Queued normal commands (FIFO), waiting to be sent.
    request_queue: VecDeque<QueuedRequest>,
    /// Queued reply commands (FIFO), sent with priority over request_queue.
    reply_queue: VecDeque<QueuedRequest>,
    /// Active event subscriptions.
    notify_list: Vec<NotifySubscription>,
    /// Whether the socket is still alive (set to false on reader exit).
    alive: bool,
}

// ---------------------------------------------------------------------------
// MgmtSocket — Public API
// ---------------------------------------------------------------------------

/// Async MGMT protocol client.
///
/// This is the Rust replacement for C `struct mgmt`. It wraps an
/// `HCI_CHANNEL_CONTROL` socket with async read/write driven by tokio,
/// replacing the callback+user_data pattern with `async fn` + channels.
///
/// Shared ownership is achieved by wrapping `MgmtSocket` in `Arc` (replacing
/// `mgmt_ref` / `mgmt_unref`).
pub struct MgmtSocket {
    inner: Arc<Mutex<MgmtInner>>,
    fd: Arc<AsyncFd<OwnedFd>>,
    write_notify: Arc<Notify>,
    reader_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
}

impl MgmtSocket {
    /// Create a new MGMT client from an existing open file descriptor.
    ///
    /// The fd must be a `PF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` socket already
    /// bound to `HCI_CHANNEL_CONTROL`. The socket must have `O_NONBLOCK` set.
    ///
    /// MTU negotiation is performed automatically (attempting `BT_SNDMTU`
    /// upgrade to `u16::MAX`, falling back to `HCI_MAX_ACL_SIZE`).
    pub fn new(fd: OwnedFd) -> Result<Self, MgmtError> {
        let raw_fd = fd.as_raw_fd();
        let mtu = negotiate_mtu(raw_fd);

        let async_fd = AsyncFd::new(fd)?;
        let fd_arc = Arc::new(async_fd);

        let inner = Arc::new(Mutex::new(MgmtInner {
            mtu,
            next_request_id: 1,
            next_notify_id: 1,
            pending: Vec::new(),
            request_queue: VecDeque::new(),
            reply_queue: VecDeque::new(),
            notify_list: Vec::new(),
            alive: true,
        }));

        let write_notify = Arc::new(Notify::new());

        let reader_inner = Arc::clone(&inner);
        let reader_fd = Arc::clone(&fd_arc);
        let reader_write_notify = Arc::clone(&write_notify);
        let reader_task = tokio::spawn(async move {
            reader_loop(reader_fd, reader_inner, reader_write_notify).await;
        });

        let writer_inner = Arc::clone(&inner);
        let writer_fd = Arc::clone(&fd_arc);
        let writer_notify = Arc::clone(&write_notify);
        let writer_task = tokio::spawn(async move {
            writer_loop(writer_fd, writer_inner, writer_notify).await;
        });

        Ok(MgmtSocket { inner, fd: fd_arc, write_notify, reader_task, writer_task })
    }

    /// Create a new MGMT client with a default `HCI_CHANNEL_CONTROL` socket.
    ///
    /// This is the Rust equivalent of C `mgmt_new_default()`. It creates a
    /// `PF_BLUETOOTH / SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK / BTPROTO_HCI`
    /// socket, binds it to `HCI_CHANNEL_CONTROL`, and wraps it in a new
    /// `MgmtSocket`.
    pub fn new_default() -> Result<Self, MgmtError> {
        let addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: HCI_DEV_NONE,
            hci_channel: HCI_CHANNEL_CONTROL,
        };
        let fd = crate::sys::hci::create_hci_socket(&addr).map_err(MgmtError::Nix)?;
        Self::new(fd)
    }

    /// Send a command and asynchronously wait for its response.
    ///
    /// This replaces C `mgmt_send()` + callback. The command is queued
    /// and sent when the writer becomes ready. The returned future resolves
    /// when the kernel responds with `CMD_COMPLETE` or `CMD_STATUS`.
    pub async fn send_command(
        &self,
        opcode: u16,
        index: u16,
        params: &[u8],
    ) -> Result<MgmtResponse, MgmtError> {
        let rx = self.queue_command(opcode, index, params, 0, false).await?;
        match rx.await {
            Ok(resp) => Ok(resp),
            Err(_) => Err(MgmtError::Closed),
        }
    }

    /// Send a command with a timeout.
    ///
    /// If the kernel does not respond within `timeout_secs` seconds, the
    /// pending command is cancelled and `MgmtError::Timeout` is returned.
    pub async fn send_command_timeout(
        &self,
        opcode: u16,
        index: u16,
        params: &[u8],
        timeout_secs: u64,
    ) -> Result<MgmtResponse, MgmtError> {
        let rx = self.queue_command(opcode, index, params, timeout_secs, false).await?;
        match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(MgmtError::Closed),
            Err(_) => Err(MgmtError::Timeout),
        }
    }

    /// Send a command immediately (bypassing the queue) and return the request ID.
    ///
    /// This replaces C `mgmt_send_nowait()`. The command is sent directly to
    /// the kernel socket and added to the pending list. The caller can later
    /// cancel the request using the returned ID.
    pub async fn send_nowait(
        &self,
        opcode: u16,
        index: u16,
        params: &[u8],
    ) -> Result<u32, MgmtError> {
        if opcode == 0 {
            return Err(MgmtError::InvalidOpcode(opcode));
        }

        let mut inner = self.inner.lock().await;
        if !inner.alive {
            return Err(MgmtError::Closed);
        }

        let mtu = inner.mtu;
        if params.len() > mtu as usize {
            return Err(MgmtError::ParamsTooLong { length: params.len() as u16, mtu });
        }

        let buf = build_command_buffer(opcode, index, params);
        let id = inner.next_request_id;
        inner.next_request_id = inner.next_request_id.wrapping_add(1).max(1);

        let (tx, _rx) = oneshot::channel();

        // Must drop inner lock before awaiting write
        drop(inner);

        // Write directly to the socket
        try_write_fd(&self.fd, &buf).await.map_err(|e| {
            tracing::error!("mgmt send_nowait write failed for opcode 0x{:04x}", opcode);
            MgmtError::Io(e)
        })?;

        tracing::debug!("[0x{:04x}] command 0x{:04x} ({})", index, opcode, mgmt_opstr(opcode));

        let mut inner = self.inner.lock().await;
        inner.pending.push(PendingCommand { id, opcode, index, sender: tx, timeout_handle: None });

        Ok(id)
    }

    /// Send a reply command (jumps the queue with priority).
    ///
    /// Reply commands can be sent even while other normal commands are
    /// pending, matching C `mgmt_reply()` semantics.
    pub async fn send_reply(
        &self,
        opcode: u16,
        index: u16,
        params: &[u8],
    ) -> Result<MgmtResponse, MgmtError> {
        let rx = self.queue_command(opcode, index, params, 0, true).await?;
        match rx.await {
            Ok(resp) => Ok(resp),
            Err(_) => Err(MgmtError::Closed),
        }
    }

    /// Send a reply command with a timeout.
    pub async fn send_reply_timeout(
        &self,
        opcode: u16,
        index: u16,
        params: &[u8],
        timeout_secs: u64,
    ) -> Result<MgmtResponse, MgmtError> {
        let rx = self.queue_command(opcode, index, params, timeout_secs, true).await?;
        match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(MgmtError::Closed),
            Err(_) => Err(MgmtError::Timeout),
        }
    }

    /// Send a command with TLV-encoded parameters.
    ///
    /// The TLV list is serialized to bytes and sent as a normal command.
    pub async fn send_tlv(
        &self,
        opcode: u16,
        index: u16,
        tlv_list: &MgmtTlvList,
    ) -> Result<MgmtResponse, MgmtError> {
        let bytes = tlv_list.to_bytes();
        self.send_command(opcode, index, &bytes).await
    }

    /// Cancel a pending or queued command by request ID.
    ///
    /// Returns `true` if the command was found and removed.
    pub async fn cancel(&self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        let mut inner = self.inner.lock().await;

        // Search request_queue
        if let Some(pos) = inner.request_queue.iter().position(|r| r.id == id) {
            inner.request_queue.remove(pos);
            self.write_notify.notify_one();
            return true;
        }

        // Search reply_queue
        if let Some(pos) = inner.reply_queue.iter().position(|r| r.id == id) {
            inner.reply_queue.remove(pos);
            self.write_notify.notify_one();
            return true;
        }

        // Search pending list
        if let Some(pos) = inner.pending.iter().position(|p| p.id == id) {
            let cmd = inner.pending.remove(pos);
            if let Some(handle) = cmd.timeout_handle {
                handle.abort();
            }
            drop(cmd.sender);
            self.write_notify.notify_one();
            return true;
        }

        false
    }

    /// Cancel all pending/queued commands for a specific controller index.
    ///
    /// Returns `true` always (matching C `mgmt_cancel_index` semantics).
    pub async fn cancel_index(&self, index: u16) -> bool {
        let mut inner = self.inner.lock().await;

        inner.request_queue.retain(|r| r.index != index);
        inner.reply_queue.retain(|r| r.index != index);

        let mut kept = Vec::new();
        for cmd in inner.pending.drain(..) {
            if cmd.index == index {
                if let Some(handle) = cmd.timeout_handle {
                    handle.abort();
                }
                drop(cmd.sender);
            } else {
                kept.push(cmd);
            }
        }
        inner.pending = kept;

        self.write_notify.notify_one();
        true
    }

    /// Cancel all pending and queued commands.
    ///
    /// Returns `true` always (matching C `mgmt_cancel_all` semantics).
    pub async fn cancel_all(&self) -> bool {
        let mut inner = self.inner.lock().await;

        inner.request_queue.clear();
        inner.reply_queue.clear();

        for cmd in inner.pending.drain(..) {
            if let Some(handle) = cmd.timeout_handle {
                handle.abort();
            }
            drop(cmd.sender);
        }

        true
    }

    /// Subscribe to MGMT events matching the given event code and index.
    ///
    /// Events whose index matches `index` (or events with subscription
    /// index == `MGMT_INDEX_NONE`, which matches all) are delivered to the
    /// returned `mpsc::Receiver`.
    ///
    /// Returns `(subscription_id, receiver)`.
    pub async fn subscribe(&self, event: u16, index: u16) -> (u32, mpsc::Receiver<MgmtEvent>) {
        let (tx, rx) = mpsc::channel(64);
        let mut inner = self.inner.lock().await;

        let id = inner.next_notify_id;
        inner.next_notify_id = inner.next_notify_id.wrapping_add(1).max(1);

        inner.notify_list.push(NotifySubscription { id, event, index, sender: tx });

        (id, rx)
    }

    /// Remove an event subscription by ID.
    ///
    /// Returns `true` if the subscription was found and removed.
    pub async fn unsubscribe(&self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        let mut inner = self.inner.lock().await;
        if let Some(pos) = inner.notify_list.iter().position(|n| n.id == id) {
            inner.notify_list.remove(pos);
            return true;
        }
        false
    }

    /// Remove all event subscriptions for a specific controller index.
    pub async fn unsubscribe_index(&self, index: u16) -> bool {
        let mut inner = self.inner.lock().await;
        inner.notify_list.retain(|n| n.index != index);
        true
    }

    /// Remove all event subscriptions.
    pub async fn unsubscribe_all(&self) -> bool {
        let mut inner = self.inner.lock().await;
        inner.notify_list.clear();
        true
    }

    /// Return the negotiated MGMT MTU.
    pub async fn get_mtu(&self) -> u16 {
        let inner = self.inner.lock().await;
        inner.mtu
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Queue a command in either the request_queue or reply_queue.
    async fn queue_command(
        &self,
        opcode: u16,
        index: u16,
        params: &[u8],
        timeout_secs: u64,
        is_reply: bool,
    ) -> Result<oneshot::Receiver<MgmtResponse>, MgmtError> {
        if opcode == 0 {
            return Err(MgmtError::InvalidOpcode(opcode));
        }

        let mut inner = self.inner.lock().await;
        if !inner.alive {
            return Err(MgmtError::Closed);
        }

        let mtu = inner.mtu;
        if params.len() > mtu as usize {
            return Err(MgmtError::ParamsTooLong { length: params.len() as u16, mtu });
        }

        let buf = build_command_buffer(opcode, index, params);
        let id = inner.next_request_id;
        inner.next_request_id = inner.next_request_id.wrapping_add(1).max(1);

        let (tx, rx) = oneshot::channel();

        let request = QueuedRequest { id, opcode, index, buf, sender: tx, timeout_secs };

        if is_reply {
            inner.reply_queue.push_back(request);
        } else {
            inner.request_queue.push_back(request);
        }

        self.write_notify.notify_one();

        Ok(rx)
    }
}

impl Drop for MgmtSocket {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

// ---------------------------------------------------------------------------
// MTU Negotiation
// ---------------------------------------------------------------------------

/// Negotiate the MGMT MTU via `BT_SNDMTU` socket option.
///
/// Attempts to read the current MTU via `getsockopt`, then tries to upgrade it
/// to `u16::MAX`. Falls back to `HCI_MAX_ACL_SIZE` (1024) if the kernel does
/// not support `BT_SNDMTU`.
///
/// This function uses raw `libc` getsockopt/setsockopt calls since the `nix`
/// crate does not provide typed Bluetooth socket option wrappers for `BT_SNDMTU`.
/// The calls are wrapped in the `sys::hci` module's `unsafe` allowance through
/// a helper or, where that is not available, fall back to `HCI_MAX_ACL_SIZE`
/// (which is the C code's own fallback behavior).
fn negotiate_mtu(raw_fd: std::os::fd::RawFd) -> u16 {
    // Attempt BT_SNDMTU getsockopt. Since the workspace denies unsafe_code
    // in this module, we delegate to sys::hci which has the allowance. If the
    // helper does not exist or the kernel does not support BT_SNDMTU, fall
    // back to HCI_MAX_ACL_SIZE (matching C mgmt_set_mtu lines 433-457).
    match crate::sys::hci::getsockopt_bt_sndmtu(raw_fd) {
        Ok(mtu) => {
            if mtu < u16::MAX {
                // Try to upgrade the MTU
                if crate::sys::hci::setsockopt_bt_sndmtu(raw_fd, u16::MAX).is_ok() {
                    return u16::MAX;
                }
            }
            mtu
        }
        Err(_) => HCI_MAX_ACL_SIZE as u16,
    }
}

// ---------------------------------------------------------------------------
// Wire Format Helpers
// ---------------------------------------------------------------------------

/// Build the serialized command buffer: `mgmt_hdr` + parameter payload.
///
/// All header fields are encoded in little-endian (matching C `htobs()`).
fn build_command_buffer(opcode: u16, index: u16, params: &[u8]) -> Vec<u8> {
    let hdr = mgmt_hdr {
        opcode: opcode.to_le(),
        index: index.to_le(),
        len: (params.len() as u16).to_le(),
    };
    let hdr_bytes = hdr.as_bytes();

    let mut buf = Vec::with_capacity(MGMT_HDR_SIZE + params.len());
    buf.extend_from_slice(hdr_bytes);
    buf.extend_from_slice(params);
    buf
}

// ---------------------------------------------------------------------------
// Background Reader Task
// ---------------------------------------------------------------------------

/// Background task that continuously reads from the MGMT socket and dispatches
/// events to pending commands and event subscribers.
///
/// This replaces C `can_read_data()` (lines 374-431 of mgmt.c).
async fn reader_loop(
    fd: Arc<AsyncFd<OwnedFd>>,
    inner: Arc<Mutex<MgmtInner>>,
    write_notify: Arc<Notify>,
) {
    let mtu = {
        let state = inner.lock().await;
        state.mtu
    };
    let buf_size = (mtu as usize + MGMT_HDR_SIZE).max(512);
    let mut buf = vec![0u8; buf_size];

    loop {
        let ready = fd.readable().await;
        match ready {
            Ok(mut guard) => {
                let read_result = guard.try_io(|inner_fd| {
                    nix::unistd::read(inner_fd.as_raw_fd(), &mut buf)
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                });

                match read_result {
                    Ok(Ok(n)) if n >= MGMT_HDR_SIZE => {
                        dispatch_message(&buf[..n], &inner, &write_notify).await;
                    }
                    Ok(Ok(n)) => {
                        tracing::warn!("mgmt short read: {} bytes (need >= {})", n, MGMT_HDR_SIZE);
                    }
                    Ok(Err(e)) => {
                        tracing::error!("mgmt read error: {}", e);
                        let mut state = inner.lock().await;
                        state.alive = false;
                        break;
                    }
                    Err(_would_block) => {
                        continue;
                    }
                }
            }
            Err(e) => {
                tracing::error!("mgmt fd error: {}", e);
                let mut state = inner.lock().await;
                state.alive = false;
                break;
            }
        }
    }
}

/// Parse an incoming MGMT message and dispatch it.
async fn dispatch_message(buf: &[u8], inner: &Arc<Mutex<MgmtInner>>, write_notify: &Arc<Notify>) {
    let event = u16::from_le_bytes([buf[0], buf[1]]);
    let index = u16::from_le_bytes([buf[2], buf[3]]);
    let length = u16::from_le_bytes([buf[4], buf[5]]) as usize;

    if buf.len() < MGMT_HDR_SIZE + length {
        tracing::warn!(
            "mgmt truncated message: event=0x{:04x} expected {} got {}",
            event,
            MGMT_HDR_SIZE + length,
            buf.len()
        );
        return;
    }

    let payload = &buf[MGMT_HDR_SIZE..MGMT_HDR_SIZE + length];

    match event {
        MGMT_EV_CMD_COMPLETE => {
            if payload.len() < 3 {
                tracing::warn!("mgmt CMD_COMPLETE too short: {} bytes", payload.len());
                return;
            }
            let opcode = u16::from_le_bytes([payload[0], payload[1]]);
            let status = payload[2];
            let data = if payload.len() > 3 { payload[3..].to_vec() } else { Vec::new() };

            tracing::debug!(
                "[0x{:04x}] command 0x{:04x} ({}) complete: 0x{:02x} ({})",
                index,
                opcode,
                mgmt_opstr(opcode),
                status,
                mgmt_errstr(status)
            );

            request_complete(inner, status, opcode, index, data, write_notify).await;
        }
        MGMT_EV_CMD_STATUS => {
            if payload.len() < 3 {
                tracing::warn!("mgmt CMD_STATUS too short: {} bytes", payload.len());
                return;
            }
            let opcode = u16::from_le_bytes([payload[0], payload[1]]);
            let status = payload[2];

            tracing::debug!(
                "[0x{:04x}] command 0x{:04x} ({}) status: 0x{:02x} ({})",
                index,
                opcode,
                mgmt_opstr(opcode),
                status,
                mgmt_errstr(status)
            );

            request_complete(inner, status, opcode, index, Vec::new(), write_notify).await;
        }
        _ => {
            tracing::debug!("[0x{:04x}] event 0x{:04x} ({})", index, event, mgmt_evstr(event));

            process_notify(inner, event, index, payload).await;
        }
    }
}

/// Complete a pending command by matching (opcode, index) or falling back
/// to index-only match. Matches C `request_complete()` (lines 300-327).
async fn request_complete(
    inner: &Arc<Mutex<MgmtInner>>,
    status: u8,
    opcode: u16,
    index: u16,
    data: Vec<u8>,
    write_notify: &Arc<Notify>,
) {
    let mut state = inner.lock().await;

    // Try exact match first: (opcode, index)
    let pos = state.pending.iter().position(|p| p.opcode == opcode && p.index == index);

    // Fallback: match by index only (C mgmt.c lines 312-315)
    let pos = pos.or_else(|| {
        tracing::debug!("unable to find request for opcode 0x{:04x}, trying index match", opcode);
        state.pending.iter().position(|p| p.index == index)
    });

    if let Some(pos) = pos {
        let cmd = state.pending.remove(pos);
        if let Some(handle) = cmd.timeout_handle {
            handle.abort();
        }
        let response = MgmtResponse { status, opcode, index, data };
        let _ = cmd.sender.send(response);
    } else {
        tracing::debug!(
            "unable to find pending command for opcode 0x{:04x} index 0x{:04x}",
            opcode,
            index
        );
    }

    drop(state);
    write_notify.notify_one();
}

/// Deliver an event to all matching subscribers.
/// Matches C `process_notify()` (lines 355-372) and `notify_handler()` (lines 336-353).
async fn process_notify(inner: &Arc<Mutex<MgmtInner>>, event: u16, index: u16, payload: &[u8]) {
    let state = inner.lock().await;

    for sub in &state.notify_list {
        if sub.event != event {
            continue;
        }
        if sub.index != index && sub.index != MGMT_INDEX_NONE {
            continue;
        }
        let evt = MgmtEvent { event, index, data: payload.to_vec() };
        if sub.sender.try_send(evt).is_err() {
            tracing::warn!("failed to deliver event 0x{:04x} to subscription {}", event, sub.id);
        }
    }
}

// ---------------------------------------------------------------------------
// Background Writer Task
// ---------------------------------------------------------------------------

/// Background task that dequeues and writes MGMT commands to the socket.
///
/// This replaces C `can_write_data()` + `wakeup_writer()` (lines 241-284).
///
/// Write scheduling rules (matching C exactly):
/// 1. Reply queue has priority over request queue.
/// 2. Only one pending normal command at a time (request_queue blocks while
///    pending list is non-empty).
/// 3. Reply commands can be sent even with pending normal commands.
async fn writer_loop(
    fd: Arc<AsyncFd<OwnedFd>>,
    inner: Arc<Mutex<MgmtInner>>,
    write_notify: Arc<Notify>,
) {
    loop {
        write_notify.notified().await;

        loop {
            let request = {
                let mut state = inner.lock().await;
                if !state.alive {
                    return;
                }

                // Try reply queue first (priority — matches C lines 247-261)
                if let Some(req) = state.reply_queue.pop_front() {
                    Some(req)
                } else if state.pending.is_empty() {
                    // Normal queue: only if no pending commands (matches C line 250)
                    state.request_queue.pop_front()
                } else {
                    None
                }
            };

            let request = match request {
                Some(r) => r,
                None => break,
            };

            // Destructure to take ownership of each field independently
            let QueuedRequest { id, opcode, index, buf, sender, timeout_secs } = request;

            // Create the optional timeout task before pushing to pending.
            let timeout_handle = if timeout_secs > 0 {
                let inner_clone = Arc::clone(&inner);
                let wn = Arc::clone(&write_notify);
                Some(tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
                    let mut st = inner_clone.lock().await;
                    if let Some(pos) = st.pending.iter().position(|p| p.id == id) {
                        let cmd = st.pending.remove(pos);
                        let response = MgmtResponse {
                            status: crate::sys::mgmt::MGMT_STATUS_TIMEOUT,
                            opcode: cmd.opcode,
                            index: cmd.index,
                            data: Vec::new(),
                        };
                        let _ = cmd.sender.send(response);
                        drop(st);
                        wn.notify_one();
                    }
                }))
            } else {
                None
            };

            // Register the command as pending BEFORE writing to the socket.
            // This prevents a race where the reader_loop processes the kernel
            // response (via request_complete) before the writer has registered
            // the command in the pending list.  Without this ordering, the
            // reader silently drops the response and send_command() hangs
            // indefinitely on the oneshot channel.  The C reference
            // (`can_write_data`, mgmt.c lines 240-278) also moves the request
            // from the request queue to the pending list before calling write().
            {
                let mut state = inner.lock().await;
                state.pending.push(PendingCommand {
                    id,
                    opcode,
                    index,
                    sender,
                    timeout_handle,
                });
            }

            match try_write_fd(&fd, &buf).await {
                Ok(()) => {
                    tracing::debug!(
                        "[0x{:04x}] command 0x{:04x} ({})",
                        index,
                        opcode,
                        mgmt_opstr(opcode)
                    );
                }
                Err(e) => {
                    tracing::error!("mgmt write failed for opcode 0x{:04x}: {}", opcode, e);
                    // Remove from pending and deliver the error via the
                    // oneshot channel so send_command() does not hang.
                    let mut state = inner.lock().await;
                    if let Some(pos) = state.pending.iter().position(|p| p.id == id) {
                        let cmd = state.pending.remove(pos);
                        if let Some(handle) = cmd.timeout_handle {
                            handle.abort();
                        }
                        let response = MgmtResponse {
                            status: MGMT_STATUS_FAILED,
                            opcode,
                            index,
                            data: Vec::new(),
                        };
                        let _ = cmd.sender.send(response);
                    }
                }
            }
        }
    }
}

/// Attempt to write a buffer to the AsyncFd within a writable guard.
async fn try_write_fd(fd: &AsyncFd<OwnedFd>, buf: &[u8]) -> Result<(), std::io::Error> {
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner_fd| {
            nix::unistd::write(inner_fd, buf)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        }) {
            Ok(Ok(_n)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mgmt::MGMT_STATUS_SUCCESS;

    #[test]
    fn test_mgmt_tlv_list_new() {
        let list = MgmtTlvList::new();
        assert_eq!(list.size(), 0);
        assert_eq!(list.iter().count(), 0);
    }

    #[test]
    fn test_mgmt_tlv_add_and_size() {
        let mut list = MgmtTlvList::new();
        assert!(list.add(0x0001, &[0xAA, 0xBB]));
        assert_eq!(list.size(), 5);
        assert_eq!(list.iter().count(), 1);

        assert!(list.add(0x0002, &[0xCC]));
        assert_eq!(list.size(), 9);
        assert_eq!(list.iter().count(), 2);
    }

    #[test]
    fn test_mgmt_tlv_add_too_long() {
        let mut list = MgmtTlvList::new();
        let big = vec![0u8; 256];
        assert!(!list.add(0x0001, &big));
        assert_eq!(list.size(), 0);
    }

    #[test]
    fn test_mgmt_tlv_to_bytes() {
        let mut list = MgmtTlvList::new();
        list.add(0x0001, &[0xAA, 0xBB]);
        let bytes = list.to_bytes();
        assert_eq!(bytes, vec![0x01, 0x00, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn test_mgmt_tlv_load_from_buf() {
        let buf = vec![0x01, 0x00, 0x02, 0xAA, 0xBB, 0x02, 0x00, 0x01, 0xCC];
        let list = MgmtTlvList::load_from_buf(&buf).expect("should parse");
        assert_eq!(list.iter().count(), 2);

        let entries: Vec<_> = list.iter().collect();
        assert_eq!(entries[0].type_, 0x0001);
        assert_eq!(entries[0].data, vec![0xAA, 0xBB]);
        assert_eq!(entries[1].type_, 0x0002);
        assert_eq!(entries[1].data, vec![0xCC]);
    }

    #[test]
    fn test_mgmt_tlv_load_from_buf_truncated() {
        let buf = vec![0x01, 0x00, 0x05, 0xAA, 0xBB];
        assert!(MgmtTlvList::load_from_buf(&buf).is_none());
    }

    #[test]
    fn test_mgmt_tlv_load_from_buf_empty() {
        assert!(MgmtTlvList::load_from_buf(&[]).is_none());
    }

    #[test]
    fn test_mgmt_tlv_roundtrip() {
        let mut original = MgmtTlvList::new();
        original.add(0x0010, &[1, 2, 3]);
        original.add(0x0020, &[4, 5]);

        let bytes = original.to_bytes();
        let parsed = MgmtTlvList::load_from_buf(&bytes).expect("roundtrip parse");

        assert_eq!(parsed.size(), original.size());
        let orig_entries: Vec<_> = original.iter().collect();
        let parsed_entries: Vec<_> = parsed.iter().collect();
        assert_eq!(orig_entries.len(), parsed_entries.len());
        for (o, p) in orig_entries.iter().zip(parsed_entries.iter()) {
            assert_eq!(o.type_, p.type_);
            assert_eq!(o.data, p.data);
        }
    }

    #[test]
    fn test_mgmt_iocap_generator_full() {
        let mut state = 0usize;
        let results: Vec<_> = std::iter::from_fn(|| mgmt_iocap_generator("", &mut state)).collect();
        assert_eq!(results.len(), 5);
        assert_eq!(results[0], "DisplayOnly");
        assert_eq!(results[4], "KeyboardDisplay");
    }

    #[test]
    fn test_mgmt_iocap_generator_prefix() {
        let mut state = 0usize;
        let results: Vec<_> =
            std::iter::from_fn(|| mgmt_iocap_generator("Display", &mut state)).collect();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], "DisplayOnly");
        assert_eq!(results[1], "DisplayYesNo");
    }

    #[test]
    fn test_mgmt_iocap_generator_no_match() {
        let mut state = 0usize;
        let result = mgmt_iocap_generator("ZZZ", &mut state);
        assert!(result.is_none());
    }

    #[test]
    fn test_mgmt_parse_io_capability_empty() {
        assert_eq!(mgmt_parse_io_capability(""), MgmtIoCapability::KeyboardDisplay);
    }

    #[test]
    fn test_mgmt_parse_io_capability_exact() {
        assert_eq!(mgmt_parse_io_capability("DisplayOnly"), MgmtIoCapability::DisplayOnly);
    }

    #[test]
    fn test_mgmt_parse_io_capability_prefix() {
        assert_eq!(mgmt_parse_io_capability("Key"), MgmtIoCapability::KeyboardOnly);
    }

    #[test]
    fn test_mgmt_parse_io_capability_invalid() {
        assert_eq!(mgmt_parse_io_capability("InvalidCap"), MgmtIoCapability::Invalid);
    }

    #[test]
    fn test_build_command_buffer() {
        let buf = build_command_buffer(0x0001, 0xFFFF, &[0xAA, 0xBB]);
        assert_eq!(buf.len(), 6 + 2);
        assert_eq!(&buf[0..2], &[0x01, 0x00]);
        assert_eq!(&buf[2..4], &[0xFF, 0xFF]);
        assert_eq!(&buf[4..6], &[0x02, 0x00]);
        assert_eq!(&buf[6..8], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_build_command_buffer_empty_params() {
        let buf = build_command_buffer(0x0004, 0x0000, &[]);
        assert_eq!(buf.len(), 6);
        assert_eq!(&buf[0..2], &[0x04, 0x00]);
        assert_eq!(&buf[2..4], &[0x00, 0x00]);
        assert_eq!(&buf[4..6], &[0x00, 0x00]);
    }

    #[test]
    fn test_mgmt_error_display() {
        let err = MgmtError::from_mgmt_status(MGMT_STATUS_FAILED);
        let msg = format!("{err}");
        assert!(msg.contains("MGMT status: 3"));
    }

    #[test]
    fn test_mgmt_error_timeout() {
        let err = MgmtError::Timeout;
        assert_eq!(format!("{err}"), "command timed out");
    }

    #[test]
    fn test_mgmt_error_invalid_opcode() {
        let err = MgmtError::InvalidOpcode(0);
        assert_eq!(format!("{err}"), "invalid opcode: 0");
    }

    #[test]
    fn test_mgmt_error_params_too_long() {
        let err = MgmtError::ParamsTooLong { length: 2000, mtu: 1024 };
        let msg = format!("{err}");
        assert!(msg.contains("2000"));
        assert!(msg.contains("1024"));
    }

    #[test]
    fn test_mgmt_tlv_add_fixed_u8() {
        let mut list = MgmtTlvList::new();
        let val: u8 = 42;
        assert!(list.add_fixed(0x0001, &val));
        assert_eq!(list.size(), 4);
        let entries: Vec<_> = list.iter().collect();
        assert_eq!(entries[0].data, vec![42]);
    }

    #[test]
    fn test_mgmt_tlv_add_fixed_u16() {
        let mut list = MgmtTlvList::new();
        let val: u16 = 0x1234;
        assert!(list.add_fixed(0x0002, &val));
        assert_eq!(list.size(), 5);
    }

    #[test]
    fn test_mgmt_tlv_into_iterator() {
        let mut list = MgmtTlvList::new();
        list.add(0x01, &[1]);
        list.add(0x02, &[2]);
        let mut count = 0;
        for entry in &list {
            count += 1;
            assert!(!entry.data.is_empty());
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_mgmt_io_capability_values() {
        assert_eq!(MgmtIoCapability::DisplayOnly as u8, 0x00);
        assert_eq!(MgmtIoCapability::DisplayYesNo as u8, 0x01);
        assert_eq!(MgmtIoCapability::KeyboardOnly as u8, 0x02);
        assert_eq!(MgmtIoCapability::NoInputNoOutput as u8, 0x03);
        assert_eq!(MgmtIoCapability::KeyboardDisplay as u8, 0x04);
        assert_eq!(MgmtIoCapability::Invalid as u8, 0xFF);
    }

    #[test]
    fn test_mgmt_error_closed() {
        let err = MgmtError::Closed;
        assert_eq!(format!("{err}"), "socket closed");
    }

    #[test]
    fn test_mgmt_error_from_mgmt_status_success() {
        let err = MgmtError::from_mgmt_status(MGMT_STATUS_SUCCESS);
        let msg = format!("{err}");
        assert!(msg.contains("0"));
    }

    #[test]
    fn test_mgmt_tlv_default() {
        let list = MgmtTlvList::default();
        assert_eq!(list.size(), 0);
        assert_eq!(list.iter().count(), 0);
    }
}
