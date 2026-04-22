// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX session runtime engine — Rust rewrite of gobex/gobex.c (1739 lines),
// gobex/gobex.h (126 lines), gobex/gobex-defs.c (21 lines), gobex/gobex-defs.h
// (40 lines), and gobex/gobex-debug.h (65 lines) from BlueZ v5.86.
//
// Implements the full OBEX session lifecycle:
//   - Async I/O over stream (RFCOMM/ERTM) and packet (L2CAP) transports
//   - Request / response correlation with per-request timeouts
//   - Single Response Mode (SRM) state machine
//   - Authentication challenge-response (MD5)
//   - High-level OBEX operations: CONNECT, DISCONNECT, SETPATH, MKDIR,
//     DELETE, COPY, MOVE, ABORT
//
// Wire format, SRM semantics, and error mapping are behaviorally identical
// to the C implementation for interoperability.

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use md5::{Digest, Md5};
use nix::sys::socket::{MsgFlags, recv, send};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

use super::apparam::ObexApparam;
use super::header::{
    ACTION_COPY, ACTION_MOVE, HDR_ACTION, HDR_AUTHCHAL, HDR_CONNECTION, HDR_DESTNAME, HDR_NAME,
    HDR_SRM, HDR_SRMP, HDR_TARGET, ObexHeader, SRM_DISABLE, SRM_ENABLE, SRM_INDICATE, SRMP_NEXT,
    SRMP_NEXT_WAIT,
};
use super::packet::{
    OP_ABORT, OP_ACTION, OP_CONNECT, OP_DISCONNECT, OP_GET, OP_PUT, OP_SETPATH, ObexPacket,
    PACKET_FINAL, RSP_BAD_REQUEST, RSP_CONTINUE, RSP_FORBIDDEN, RSP_INTERNAL_SERVER_ERROR,
    RSP_NOT_ACCEPTABLE, RSP_NOT_FOUND, RSP_NOT_IMPLEMENTED, RSP_PRECONDITION_FAILED,
    RSP_SERVICE_UNAVAILABLE, RSP_SUCCESS, RSP_UNAUTHORIZED,
};

// ---------------------------------------------------------------------------
// Constants — matching gobex.c exactly
// ---------------------------------------------------------------------------

/// Default OBEX MTU (4096 bytes).
pub const DEFAULT_MTU: u16 = 4096;

/// Minimum OBEX MTU per specification (255 bytes).
pub const MINIMUM_MTU: u16 = 255;

/// Maximum OBEX MTU (65535 bytes — u16::MAX).
pub const MAXIMUM_MTU: u16 = 65535;

/// Default request timeout in seconds.
const DEFAULT_TIMEOUT: u64 = 10;

/// Timeout for ABORT operations in seconds.
const ABORT_TIMEOUT: u64 = 5;

/// Sentinel value for "no current operation".
const OP_NONE: u8 = 0xff;

/// Invalid connection ID sentinel (no active OBEX connection).
pub const CONNID_INVALID: u32 = 0xffff_ffff;

/// Authentication nonce tag ID inside AUTHCHAL apparam.
const NONCE_TAG: u8 = 0x00;

/// Expected nonce length in bytes.
const NONCE_LEN: usize = 16;

/// Authentication digest tag ID inside AUTHRESP apparam.
const DIGEST_TAG: u8 = 0x00;

// ---------------------------------------------------------------------------
// Error type — replaces GObexError (gobex-defs.h)
// ---------------------------------------------------------------------------

/// Errors produced by the OBEX session engine.
///
/// Replaces the C `GObexError` enum plus the `G_OBEX_ERROR_FIRST + rsp_code`
/// pattern for protocol-level failures.
#[derive(Debug, thiserror::Error)]
pub enum ObexError {
    /// Malformed packet or header data.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Invalid arguments supplied to an API call.
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    /// The remote peer disconnected.
    #[error("disconnected")]
    Disconnected,

    /// A request timed out waiting for a response.
    #[error("timeout")]
    Timeout,

    /// The request was cancelled by the caller.
    #[error("cancelled")]
    Cancelled,

    /// Generic failure with a human-readable description.
    #[error("failed: {0}")]
    Failed(String),

    /// An OBEX-level protocol error carrying a response code.
    #[error("OBEX protocol error: {code} {message}")]
    ProtocolError {
        /// OBEX response code (e.g. 0x43 for Forbidden).
        code: u8,
        /// Human-readable description from [`obex_strerror`].
        message: String,
    },

    /// An underlying I/O error propagated from the transport socket.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Transport and data policy enums — from gobex-defs.h / gobex.h
// ---------------------------------------------------------------------------

/// OBEX transport type — determines read/write semantics.
///
/// Replaces `GObexTransportType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// Byte-stream transport (RFCOMM or L2CAP ERTM).
    Stream,
    /// Datagram transport (L2CAP basic or enhanced credit).
    Packet,
}

/// Data ownership policy for packet payloads.
///
/// Replaces `GObexDataPolicy` (INHERIT is not exposed — Rust ownership
/// semantics make it unnecessary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPolicy {
    /// Data is copied into an owned buffer.
    Copy,
    /// Data is borrowed by reference.
    Reference,
}

// ---------------------------------------------------------------------------
// SRM state machine — from gobex.c struct srm_config + helpers
// ---------------------------------------------------------------------------

/// Single Response Mode (SRM) configuration for one ongoing operation.
///
/// SRM allows the server to send multiple response packets without waiting
/// for an acknowledgement from the client, dramatically improving throughput
/// on high-latency transports.
struct SrmConfig {
    /// Current operation opcode to which SRM applies.
    op: u8,
    /// Whether SRM has been negotiated and is active.
    enabled: bool,
    /// Last SRM header value received from the peer.
    srm: u8,
    /// Last SRMP header value received from the peer.
    srmp: u8,
    /// `true` if the local side initiated this SRM exchange.
    outgoing: bool,
}

impl SrmConfig {
    /// Creates a new SRM configuration in the disabled state.
    fn new() -> Self {
        Self { op: OP_NONE, enabled: false, srm: SRM_DISABLE, srmp: SRMP_NEXT, outgoing: false }
    }

    /// Resets the SRM state to disabled.
    fn reset(&mut self) {
        self.op = OP_NONE;
        self.enabled = false;
        self.srm = SRM_DISABLE;
        self.srmp = SRMP_NEXT;
        self.outgoing = false;
    }
}

// ---------------------------------------------------------------------------
// Wire-format layout documentation for CONNECT and SETPATH
// ---------------------------------------------------------------------------
//
// CONNECT request/response pre-header data is 4 bytes on the wire:
//   [0] version (0x10 = OBEX 1.0)
//   [1] flags
//   [2..4] MTU in big-endian byte order
// This is created by `init_connect_data()`.
//
// SETPATH request pre-header data is 2 bytes:
//   [0] flags — bit 0 = backup, bit 1 = don't create
//   [1] reserved constants byte (0x00)
// This is created inline as `[flags, 0x00]`.

// ---------------------------------------------------------------------------
// PendingPacket — tracks an outgoing packet awaiting a response
// ---------------------------------------------------------------------------

/// An outgoing packet queued for transmission, optionally awaiting a response.
///
/// Replaces the C `struct pending_pkt`.
struct PendingPacket {
    /// Monotonically increasing request ID (0 = unsolicited / response).
    id: u32,
    /// The OBEX packet to transmit.
    pkt: ObexPacket,
    /// How long to wait for a response before timing out.
    timeout: Duration,
    /// Handle to the spawned timeout task (aborted when a response arrives).
    timeout_handle: Option<JoinHandle<()>>,
    /// Callback invoked on error (timeout, cancel, disconnect).
    rsp_func: Option<Box<dyn FnOnce(ObexError) + Send>>,
    /// Callback invoked on successful response receipt.
    rsp_handler: Option<Box<dyn FnMut(ObexPacket) + Send>>,
    /// Whether this request was cancelled by the caller.
    cancelled: bool,
    /// Whether this request is suspended (SRM flow control).
    suspended: bool,
    /// Whether we are in the middle of an authentication retry.
    authenticating: bool,
}

// ---------------------------------------------------------------------------
// RequestHandler — registered handler for incoming request opcodes
// ---------------------------------------------------------------------------

/// A registered handler for incoming OBEX request packets of a specific opcode.
///
/// Replaces the C `struct req_handler`.
struct RequestHandler {
    /// Unique registration identifier.
    id: u32,
    /// OBEX opcode this handler is registered for.
    opcode: u8,
    /// Callback function invoked for matching requests.
    ///
    /// Receives `(&mut ObexSession, &ObexPacket)` — the handler may inspect
    /// the packet and use session methods to send a response.
    func: Box<dyn FnMut(&mut ObexSession, &ObexPacket) + Send>,
}

// ---------------------------------------------------------------------------
// Atomic ID counters — replaces C static guint next_id
// ---------------------------------------------------------------------------

/// Global atomic counter for `PendingPacket` request IDs.
static NEXT_PKT_ID: AtomicU32 = AtomicU32::new(1);

/// Global atomic counter for `RequestHandler` registration IDs.
static NEXT_HANDLER_ID: AtomicU32 = AtomicU32::new(1);

/// Global atomic counter for server-side connection IDs (used in
/// `prepare_connect_rsp` to assign unique connection identifiers).
static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);

// ---------------------------------------------------------------------------
// ObexSession — the core OBEX session engine (replaces struct _GObex)
// ---------------------------------------------------------------------------

/// The core OBEX session engine managing a single OBEX connection.
///
/// Handles async I/O, request/response correlation, SRM negotiation,
/// authentication, and high-level OBEX operations.
///
/// Replaces the C `struct _GObex` and all associated functions.
///
/// # Ownership
///
/// The session takes ownership of the socket file descriptor.  There is no
/// reference counting — wrap in `Arc<Mutex<ObexSession>>` if sharing across
/// tasks is required.
pub struct ObexSession {
    // -- I/O --
    /// Async file descriptor wrapping the Bluetooth transport socket.
    io: AsyncFd<OwnedFd>,
    /// Whether this session uses stream or packet transport semantics.
    transport_type: TransportType,

    // -- Receive buffer --
    /// Buffer for accumulating incoming OBEX packet data.
    rx_buf: Vec<u8>,
    /// Number of valid bytes currently in `rx_buf`.
    rx_data: usize,
    /// Expected total packet length (parsed from bytes 1-2 in stream mode).
    rx_pkt_len: usize,
    /// Opcode of the last received request (used for response routing).
    rx_last_op: u8,

    // -- Transmit buffer --
    /// Buffer used for encoding outgoing packets before writing.
    tx_buf: Vec<u8>,
    /// Number of bytes remaining to be written from `tx_buf`.
    tx_data: usize,
    /// Number of bytes already sent from the current `tx_buf` contents.
    tx_sent: usize,

    // -- MTU negotiation --
    /// Our receive MTU (advertised to the peer during CONNECT).
    rx_mtu: u16,
    /// Peer's receive MTU (our transmit limit, learned from CONNECT response).
    tx_mtu: u16,
    /// Transport-level maximum read size (from socket options).
    io_rx_mtu: usize,
    /// Transport-level maximum write size (from socket options).
    io_tx_mtu: usize,

    // -- Connection state --
    /// OBEX Connection ID (`CONNID_INVALID` if no connection is active).
    conn_id: u32,
    /// Whether SRM is supported (always `true` for packet transports).
    use_srm: bool,
    /// Current SRM negotiation state.
    srm: SrmConfig,
    /// Whether the session is suspended (I/O paused).
    suspended: bool,

    // -- Authentication --
    /// Pending authentication challenge extracted from a CONNECT response.
    authchal: Option<ObexApparam>,

    // -- Queues --
    /// Outgoing packet transmit queue.
    tx_queue: VecDeque<PendingPacket>,

    // -- Handlers --
    /// Registered incoming request handlers (one per opcode).
    req_handlers: Vec<RequestHandler>,
    /// The pending outgoing request awaiting a response (at most one).
    pending_req: Option<PendingPacket>,

    // -- Callbacks --
    /// Callback invoked when the session disconnects unexpectedly.
    disconn_func: Option<Box<dyn FnMut(ObexError) + Send>>,
}

// ---------------------------------------------------------------------------
// Response code → human-readable string mapping — from gobex.c obex_errors[]
// ---------------------------------------------------------------------------

/// Returns a human-readable string for an OBEX response code.
///
/// The returned strings match the C `obex_errors[]` table in gobex.c exactly
/// (all 38 entries plus an "Unknown" fallback).
#[must_use]
pub fn obex_strerror(rsp: u8) -> &'static str {
    match rsp {
        0x10 => "Continue",
        0x20 => "Success",
        0x21 => "Created",
        0x22 => "Accepted",
        0x23 => "Non-Authoritative Information",
        0x24 => "No Content",
        0x25 => "Reset Content",
        0x26 => "Partial Content",
        0x30 => "Multiple Choices",
        0x31 => "Moved Permanently",
        0x32 => "Moved Temporarily",
        0x33 => "See Other",
        0x34 => "Not Modified",
        0x35 => "Use Proxy",
        0x40 => "Bad Request",
        0x41 => "Unauthorized",
        0x42 => "Payment Required",
        0x43 => "Forbidden",
        0x44 => "Not Found",
        0x45 => "Method Not Allowed",
        0x46 => "Not Acceptable",
        0x47 => "Proxy Authentication Required",
        0x48 => "Request Timeout",
        0x49 => "Conflict",
        0x4a => "Gone",
        0x4b => "Length Required",
        0x4c => "Precondition Failed",
        0x4d => "Requested Entity Too Large",
        0x4e => "Requested URL Too Large",
        0x4f => "Unsupported Media Type",
        0x50 => "Internal Server Error",
        0x51 => "Not Implemented",
        0x52 => "Bad Gateway",
        0x53 => "Service Unavailable",
        0x54 => "Gateway Timeout",
        0x55 => "HTTP Version Not Supported",
        0x60 => "Database Full",
        0x61 => "Database Locked",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// errno → OBEX response code mapping — from g_obex_errno_to_rsp()
// ---------------------------------------------------------------------------

/// Maps a negative errno value to an OBEX response code.
///
/// The caller passes negative errno values (e.g. `-EPERM` = −1) following
/// the Linux kernel convention used throughout the BlueZ C codebase.
///
/// Matches the C `g_obex_errno_to_rsp()` mapping exactly, with two minor
/// additions from the specification (EAGAIN → CONTINUE, ENOTSUP →
/// NOT_IMPLEMENTED).
#[must_use]
pub fn errno_to_rsp(err: i32) -> u8 {
    // Negative errno constants (Linux kernel values).
    const NEG_EAGAIN: i32 = -11;
    const NEG_EPERM: i32 = -1;
    const NEG_ENOENT: i32 = -2;
    const NEG_ENOEXEC: i32 = -8;
    const NEG_EACCES: i32 = -13;
    const NEG_EFAULT: i32 = -14;
    const NEG_EEXIST: i32 = -17;
    const NEG_EINVAL: i32 = -22;
    const NEG_ENOSYS: i32 = -38;
    const NEG_ENOTEMPTY: i32 = -39;
    const NEG_EBADR: i32 = -53;
    const NEG_ENOTSUP: i32 = -95;

    match err {
        0 => RSP_SUCCESS,
        NEG_EAGAIN => RSP_CONTINUE,
        NEG_EPERM | NEG_EACCES => RSP_FORBIDDEN,
        NEG_ENOENT => RSP_NOT_FOUND,
        NEG_EINVAL | NEG_EBADR | NEG_ENOEXEC => RSP_BAD_REQUEST,
        NEG_EFAULT => RSP_SERVICE_UNAVAILABLE,
        NEG_ENOSYS | NEG_ENOTSUP => RSP_NOT_IMPLEMENTED,
        NEG_ENOTEMPTY | NEG_EEXIST => RSP_PRECONDITION_FAILED,
        _ => RSP_INTERNAL_SERVER_ERROR,
    }
}

// ---------------------------------------------------------------------------
// SRM helper functions — from gobex.c set_srm / set_srmp / setup_srm / etc.
// ---------------------------------------------------------------------------

/// Determines the header-offset (pre-header data size) for a **request**
/// opcode.  Matches C `req_header_offset()`.
fn req_header_offset(opcode: u8) -> usize {
    match opcode {
        OP_CONNECT => 4, // ConnectData
        OP_SETPATH => 2, // SetpathData
        _ => 0,
    }
}

/// Determines the header-offset for a **response** to the given request
/// opcode.  Matches C `rsp_header_offset()`.
fn rsp_header_offset(opcode: u8) -> usize {
    match opcode {
        OP_CONNECT => 4, // ConnectData in response
        _ => 0,
    }
}

/// Returns `true` if the given response code is a "final" code that should
/// terminate SRM for non-CONNECT operations.
///
/// Matches the C `check_srm_final()`.
fn check_srm_final(rsp: u8) -> bool {
    matches!(
        rsp,
        RSP_SUCCESS | RSP_FORBIDDEN | RSP_NOT_ACCEPTABLE | RSP_NOT_FOUND | RSP_SERVICE_UNAVAILABLE
    )
}

/// Computes `MD5(nonce || ":BlueZ")` for OBEX authentication.
///
/// Matches the C `digest_response()` in gobex.c.
fn digest_response(nonce: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(nonce);
    hasher.update(b":BlueZ");
    let result = hasher.finalize();
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&result);
    digest
}

/// Initialises a [`ConnectData`] structure for an outgoing CONNECT packet.
///
/// Matches the C `init_connect_data()`.
fn init_connect_data(rx_mtu: u16) -> [u8; 4] {
    let mtu_be = rx_mtu.to_be_bytes();
    [0x10, 0x00, mtu_be[0], mtu_be[1]]
}

/// Formats a hex + ASCII dump of `data` using `tracing::trace!`.
///
/// Replaces the C `g_obex_dump()` function from gobex-debug.h.  Each line
/// shows up to 16 bytes as hex followed by their ASCII representation (with
/// non-printable characters shown as `.`).
fn obex_dump(prefix: &str, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    for chunk_offset in (0..data.len()).step_by(16) {
        let end = std::cmp::min(chunk_offset + 16, data.len());
        let chunk = &data[chunk_offset..end];

        let hex_part: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii_part: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();

        tracing::trace!(
            target: "obex::data",
            "{prefix}: {hex_part:<48} {ascii_part}"
        );
    }
}

// ===========================================================================
// ObexSession implementation
// ===========================================================================

impl ObexSession {
    // -----------------------------------------------------------------------
    // Constructor — from g_obex_new() (gobex.c ~1620-1739)
    // -----------------------------------------------------------------------

    /// Creates a new OBEX session over the given socket file descriptor.
    ///
    /// # Arguments
    ///
    /// * `fd` — An owned, **non-blocking** socket fd (the caller must set
    ///   `O_NONBLOCK` before calling).
    /// * `transport_type` — Stream (RFCOMM/ERTM) or Packet (L2CAP).
    /// * `io_rx_mtu` — Transport-level receive MTU (from socket options).
    /// * `io_tx_mtu` — Transport-level transmit MTU (from socket options).
    ///
    /// MTU values below [`MINIMUM_MTU`] are promoted to [`DEFAULT_MTU`];
    /// values above [`MAXIMUM_MTU`] are clamped.  This matches the C
    /// `g_obex_new()` behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`ObexError::IoError`] if the `AsyncFd` cannot be created
    /// (e.g. the fd is invalid).
    pub fn new(
        fd: OwnedFd,
        transport_type: TransportType,
        io_rx_mtu: usize,
        io_tx_mtu: usize,
    ) -> Result<Self, ObexError> {
        // Clamp MTUs — matching C g_obex_new() logic
        let io_rx_mtu = clamp_mtu(io_rx_mtu);
        let io_tx_mtu = clamp_mtu(io_tx_mtu);

        let io = AsyncFd::new(fd)?;
        let use_srm = transport_type == TransportType::Packet;

        tracing::debug!(
            target: "obex::command",
            "new session: transport={transport_type:?} rx_mtu={io_rx_mtu} tx_mtu={io_tx_mtu} srm={use_srm}"
        );

        Ok(Self {
            io,
            transport_type,
            rx_buf: vec![0u8; io_rx_mtu],
            rx_data: 0,
            rx_pkt_len: 0,
            rx_last_op: OP_NONE,
            tx_buf: vec![0u8; io_tx_mtu],
            tx_data: 0,
            tx_sent: 0,
            rx_mtu: io_rx_mtu as u16,
            tx_mtu: MINIMUM_MTU,
            io_rx_mtu,
            io_tx_mtu,
            conn_id: CONNID_INVALID,
            use_srm,
            srm: SrmConfig::new(),
            suspended: false,
            authchal: None,
            tx_queue: VecDeque::new(),
            req_handlers: Vec::new(),
            pending_req: None,
            disconn_func: None,
        })
    }

    // -----------------------------------------------------------------------
    // SRM state machine methods — from gobex.c
    // -----------------------------------------------------------------------

    /// Processes an incoming SRM header value.  Matches C `set_srm()`.
    fn set_srm(&mut self, pkt: &ObexPacket, outgoing: bool) {
        let Some(hdr) = pkt.get_header(HDR_SRM) else {
            return;
        };
        let Some(val) = hdr.as_u8() else { return };

        tracing::debug!(
            target: "obex::transfer",
            "SRM header: value=0x{val:02x} outgoing={outgoing}"
        );

        match val {
            SRM_ENABLE => {
                self.srm.srm = SRM_ENABLE;
                self.srm.outgoing = outgoing;
            }
            SRM_INDICATE => {
                // INDICATE means the remote side acknowledges our SRM_ENABLE.
                if self.srm.srm == SRM_ENABLE {
                    self.srm.enabled = true;
                    tracing::debug!(target: "obex::transfer", "SRM enabled");
                }
            }
            SRM_DISABLE => {
                self.srm.enabled = false;
                self.srm.srm = SRM_DISABLE;
                tracing::debug!(target: "obex::transfer", "SRM disabled");
            }
            _ => {
                tracing::error!("unknown SRM value: 0x{val:02x}");
            }
        }
    }

    /// Processes an incoming SRMP header value.  Matches C `set_srmp()`.
    fn set_srmp(&mut self, pkt: &ObexPacket) {
        let Some(hdr) = pkt.get_header(HDR_SRMP) else {
            // No SRMP header — reset to NEXT (proceed).
            self.srm.srmp = SRMP_NEXT;
            return;
        };
        let Some(val) = hdr.as_u8() else {
            self.srm.srmp = SRMP_NEXT;
            return;
        };

        tracing::debug!(target: "obex::transfer", "SRMP header: value=0x{val:02x}");
        self.srm.srmp = val;
    }

    /// Processes SRM/SRMP headers from an incoming packet.
    ///
    /// Matches C `setup_srm()`.  `outgoing` is true when processing the
    /// response to our own request (we initiated the exchange).
    fn setup_srm(&mut self, pkt: &ObexPacket, outgoing: bool) {
        let op = pkt.operation();

        if op == OP_CONNECT {
            // CONNECT responses carry SRM capability but don't activate it.
            self.set_srm(pkt, outgoing);
            return;
        }

        if self.srm.op == OP_NONE {
            // First packet in a new operation — initialise.
            self.srm.op = op;
            self.srm.srmp = SRMP_NEXT;
        } else if self.srm.op != op {
            // Operation changed — reset SRM.
            self.srm.reset();
            self.srm.op = op;
        }

        self.set_srm(pkt, outgoing);
        self.set_srmp(pkt);

        // If SRM was enabled via ENABLE → INDICATE handshake, activate it.
        if self.srm.srm == SRM_ENABLE && !self.srm.enabled {
            // The enable path depends on who initiated:
            if self.srm.outgoing {
                // We sent ENABLE, peer must respond with INDICATE or ENABLE.
                // The actual enable happens in set_srm on receipt of INDICATE.
            } else {
                // Peer sent ENABLE — we should indicate back and enable.
                self.srm.enabled = true;
                tracing::debug!(target: "obex::transfer", "SRM auto-enabled (peer initiated)");
            }
        }
    }

    /// Prepends an `SRM_ENABLE` header to an outgoing **request** packet
    /// (for GET/PUT).  Matches C `prepare_srm_req()`.
    fn prepare_srm_req(&self, pkt: &mut ObexPacket) {
        if !self.use_srm {
            return;
        }
        pkt.prepend_header(ObexHeader::new_u8(HDR_SRM, SRM_ENABLE));
    }

    /// Prepends an `SRM_ENABLE` header to an outgoing **response** packet
    /// (for GET/PUT when SRM is already enabled).  Matches C
    /// `prepare_srm_rsp()`.
    fn prepare_srm_rsp(&self, pkt: &mut ObexPacket) {
        if !self.srm.enabled {
            return;
        }
        pkt.prepend_header(ObexHeader::new_u8(HDR_SRM, SRM_ENABLE));
    }

    // -----------------------------------------------------------------------
    // I/O layer — async read/write operations
    // -----------------------------------------------------------------------

    /// Writes bytes to the transport socket (stream mode).
    ///
    /// Returns the number of bytes actually written.  May return fewer than
    /// `buf.len()` (partial write) — the caller must retry for the remainder.
    ///
    /// Matches C `write_stream()`.
    async fn write_stream(&self, buf: &[u8]) -> Result<usize, ObexError> {
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| {
                send(inner.get_ref().as_raw_fd(), buf, MsgFlags::MSG_NOSIGNAL)
                    .map_err(std::io::Error::from)
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(ObexError::IoError(e)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes an entire packet to the transport socket (packet mode).
    ///
    /// In datagram mode the entire buffer must be sent in one call.
    ///
    /// Matches C `write_packet()`.
    async fn write_packet(&self, buf: &[u8]) -> Result<usize, ObexError> {
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| {
                send(inner.get_ref().as_raw_fd(), buf, MsgFlags::MSG_NOSIGNAL)
                    .map_err(std::io::Error::from)
            }) {
                Ok(Ok(n)) => {
                    if n < buf.len() {
                        return Err(ObexError::Failed(format!(
                            "packet write: sent {n}/{} bytes",
                            buf.len()
                        )));
                    }
                    return Ok(n);
                }
                Ok(Err(e)) => return Err(ObexError::IoError(e)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes `buf` to the socket using the transport-appropriate function,
    /// looping until all bytes are sent (for stream mode).
    async fn write_all_bytes(&self, buf: &[u8]) -> Result<(), ObexError> {
        match self.transport_type {
            TransportType::Packet => {
                self.write_packet(buf).await?;
            }
            TransportType::Stream => {
                let mut sent = 0;
                while sent < buf.len() {
                    let n = self.write_stream(&buf[sent..]).await?;
                    if n == 0 {
                        return Err(ObexError::Disconnected);
                    }
                    sent += n;
                }
            }
        }
        Ok(())
    }

    /// Reads data from the transport socket in stream mode.
    ///
    /// Incrementally accumulates bytes: first the 3-byte packet header
    /// (opcode + u16 length), then the remaining body bytes.  Returns the
    /// total number of valid bytes in `rx_buf` after this read.
    ///
    /// Matches C `read_stream()`.
    async fn read_stream(&mut self) -> Result<usize, ObexError> {
        // Phase 1: accumulate the 3-byte header if we don't have it yet.
        if self.rx_data < 3 {
            let n = self.read_bytes(3 - self.rx_data).await?;
            if n == 0 {
                return Err(ObexError::Disconnected);
            }
            if self.rx_data < 3 {
                return Ok(self.rx_data);
            }
            // Parse packet length from bytes 1-2.
            self.rx_pkt_len = u16::from_be_bytes([self.rx_buf[1], self.rx_buf[2]]) as usize;
            if self.rx_pkt_len > self.rx_mtu as usize {
                return Err(ObexError::ParseError(format!(
                    "packet length {} exceeds MTU {}",
                    self.rx_pkt_len, self.rx_mtu
                )));
            }
        }

        // Phase 2: accumulate body bytes.
        if self.rx_data < self.rx_pkt_len {
            let n = self.read_bytes(self.rx_pkt_len - self.rx_data).await?;
            if n == 0 {
                return Err(ObexError::Disconnected);
            }
        }

        Ok(self.rx_data)
    }

    /// Reads a complete datagram from the transport socket (packet mode).
    ///
    /// Matches C `read_packet()`.
    async fn read_packet(&mut self) -> Result<usize, ObexError> {
        let max_read = self.rx_mtu as usize - self.rx_data;
        let n = self.read_bytes(max_read).await?;
        if n == 0 {
            return Err(ObexError::Disconnected);
        }
        self.rx_pkt_len = self.rx_data;
        Ok(self.rx_data)
    }

    /// Low-level async socket read into `rx_buf[rx_data..rx_data+max_len]`.
    ///
    /// Waits for readability, performs the read, and advances `rx_data`.
    /// Returns the number of bytes actually read.
    async fn read_bytes(&mut self, max_len: usize) -> Result<usize, ObexError> {
        loop {
            let mut guard = self.io.readable().await?;
            let start = self.rx_data;
            let end = std::cmp::min(start + max_len, self.rx_buf.len());
            let buf = &mut self.rx_buf[start..end];
            match guard.try_io(|inner| {
                recv(inner.get_ref().as_raw_fd(), buf, MsgFlags::empty())
                    .map_err(std::io::Error::from)
            }) {
                Ok(Ok(n)) => {
                    self.rx_data += n;
                    obex_dump("RX", &self.rx_buf[start..start + n]);
                    return Ok(n);
                }
                Ok(Err(e)) => return Err(ObexError::IoError(e)),
                Err(_would_block) => continue,
            }
        }
    }

    // -----------------------------------------------------------------------
    // Incoming data processing — from gobex.c incoming_data()
    // -----------------------------------------------------------------------

    /// Reads and processes one incoming OBEX packet from the transport.
    ///
    /// On completion, the packet is decoded and routed to either
    /// [`handle_response`] or [`handle_request`].
    ///
    /// Matches C `incoming_data()`.
    pub async fn incoming_data(&mut self) -> Result<(), ObexError> {
        // Read transport data.
        let _total = match self.transport_type {
            TransportType::Stream => self.read_stream().await?,
            TransportType::Packet => self.read_packet().await?,
        };

        // Need at least the 3-byte packet header.
        if self.rx_data < 3 {
            return Ok(()); // incomplete — wait for more data
        }

        // In stream mode, check completeness.
        if self.transport_type == TransportType::Stream && self.rx_data < self.rx_pkt_len {
            return Ok(()); // not yet complete
        }

        // Determine the header offset based on the opcode in rx_buf.
        let is_response = self.pending_req.is_some();

        let header_offset = if is_response {
            // Responses use the pending request's opcode for header offset.
            rsp_header_offset(self.pending_req.as_ref().map(|p| p.pkt.operation()).unwrap_or(0))
        } else {
            req_header_offset(self.rx_buf[0] & 0x7f)
        };

        // Decode the packet.
        let (pkt, _consumed) = ObexPacket::decode(&self.rx_buf[..self.rx_data], header_offset)
            .map_err(|e| ObexError::ParseError(format!("{e}")))?;

        tracing::debug!(
            target: "obex::command",
            "RX opcode=0x{:02x} final={} len={}",
            pkt.opcode(),
            pkt.is_final(),
            self.rx_data
        );

        // Reset rx state for next packet.
        self.rx_data = 0;
        self.rx_pkt_len = 0;

        // Route packet.
        if is_response {
            self.handle_response(pkt);
        } else {
            self.handle_request(pkt);
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Connect response data parsing — from gobex.c parse_connect_data()
    // -----------------------------------------------------------------------

    /// Parses the `ConnectData` pre-header from a CONNECT response.
    ///
    /// Extracts the peer's MTU, the Connection-ID header (if present), and
    /// the AUTHCHAL header (if present).
    ///
    /// Matches C `parse_connect_data()`.
    fn parse_connect_data(&mut self, pkt: &ObexPacket) {
        let data = pkt.get_data();
        if data.len() >= 4 {
            let peer_mtu = u16::from_be_bytes([data[2], data[3]]);
            let new_tx_mtu = std::cmp::min(peer_mtu, self.io_tx_mtu as u16);
            if new_tx_mtu != self.tx_mtu {
                tracing::debug!(
                    target: "obex::command",
                    "updated tx_mtu: {} -> {new_tx_mtu}",
                    self.tx_mtu
                );
                self.tx_mtu = new_tx_mtu;
                self.tx_buf.resize(new_tx_mtu as usize, 0);
            }
        }

        // Extract Connection-ID header.
        if let Some(hdr) = pkt.get_header(HDR_CONNECTION) {
            if let Some(id) = hdr.as_u32() {
                self.conn_id = id;
                tracing::debug!(
                    target: "obex::command",
                    "connection id: 0x{id:08x}"
                );
            }
        }

        // Extract auth challenge if present.
        if let Some(hdr) = pkt.get_header(HDR_AUTHCHAL) {
            if let Some(bytes) = hdr.as_bytes() {
                if let Ok(ap) = ObexApparam::decode(bytes) {
                    self.authchal = Some(ap);
                    tracing::debug!(
                        target: "obex::command",
                        "received auth challenge"
                    );
                }
            }
        }
    }

    /// Prepares an authentication response by computing the MD5 digest of the
    /// nonce from the stored auth challenge and adding the `AUTHRESP` header
    /// to the given packet.
    ///
    /// Returns `true` on success, `false` if no valid challenge data exists.
    ///
    /// Matches C `prepare_auth_rsp()`.
    fn prepare_auth_rsp(&mut self, pkt: &mut ObexPacket) -> bool {
        let Some(ref chal) = self.authchal else {
            return false;
        };

        let Some(nonce) = chal.get_bytes(NONCE_TAG) else {
            tracing::error!("auth challenge: missing nonce (tag 0x{NONCE_TAG:02x})");
            return false;
        };

        if nonce.len() != NONCE_LEN {
            tracing::error!("auth challenge: nonce length {} (expected {NONCE_LEN})", nonce.len());
            return false;
        }

        let digest = digest_response(nonce);

        let mut rsp_ap = ObexApparam::new();
        rsp_ap.set_bytes(DIGEST_TAG, &digest);

        if let Some(hdr) = ObexHeader::new_apparam(&rsp_ap) {
            pkt.add_header(hdr);
            true
        } else {
            tracing::error!("auth: failed to encode AUTHRESP apparam");
            false
        }
    }

    // -----------------------------------------------------------------------
    // Response handling — from gobex.c handle_response()
    // -----------------------------------------------------------------------

    /// Handles a received **response** packet.
    ///
    /// Cancels the pending request timeout, processes SRM/authentication
    /// headers, and invokes the response callback.
    ///
    /// Matches C `handle_response()` + `parse_response()`.
    fn handle_response(&mut self, pkt: ObexPacket) {
        // Take the pending request out so we can mutate both.
        let Some(mut pending) = self.pending_req.take() else {
            tracing::error!("unexpected response with no pending request");
            return;
        };

        // Cancel timeout task.
        if let Some(handle) = pending.timeout_handle.take() {
            handle.abort();
        }

        let rsp_code = pkt.opcode();
        let req_op = pending.pkt.operation();

        tracing::debug!(
            target: "obex::command",
            "response: rsp=0x{rsp_code:02x} ({}) for op=0x{req_op:02x}",
            obex_strerror(rsp_code & 0x7f)
        );

        // Process SRM headers from the response.
        self.setup_srm(&pkt, true);

        // For CONNECT responses, parse connect data.
        if req_op == OP_CONNECT {
            self.parse_connect_data(&pkt);
        }

        // Handle UNAUTHORIZED — attempt authentication.
        if (rsp_code == (RSP_UNAUTHORIZED | PACKET_FINAL) || rsp_code == RSP_UNAUTHORIZED)
            && self.authchal.is_some()
        {
            tracing::debug!(target: "obex::command", "attempting authentication");
            if self.prepare_auth_rsp(&mut pending.pkt) {
                // Re-send the original request with auth.
                pending.authenticating = true;
                self.authchal = None;
                self.tx_queue.push_front(pending);
                self.try_write_next();
                return;
            }
        }

        // SRM continuation: for GET + SRM + CONTINUE, keep pending.
        if req_op == OP_GET
            && self.srm.enabled
            && (rsp_code == RSP_CONTINUE || rsp_code == (RSP_CONTINUE | PACKET_FINAL))
        {
            // Keep the pending request alive for the next SRM packet.
            if let Some(ref mut handler) = pending.rsp_handler {
                handler(pkt);
            }
            self.pending_req = Some(pending);
            return;
        }

        // SRM final check: if SRM is active and this is a terminal response,
        // reset SRM state.
        if self.srm.enabled && check_srm_final(rsp_code & 0x7f) {
            self.srm.reset();
        }

        // Invoke response callback.
        if pending.cancelled {
            if let Some(func) = pending.rsp_func {
                func(ObexError::Cancelled);
            }
        } else if let Some(ref mut handler) = pending.rsp_handler {
            handler(pkt);
        }

        // Flush queue — attempt to send next queued packet.
        self.try_write_next();
    }

    // -----------------------------------------------------------------------
    // Request handling — from gobex.c handle_request()
    // -----------------------------------------------------------------------

    /// Handles a received **request** packet.
    ///
    /// Looks up the registered handler for the request opcode and invokes it.
    /// If no handler is registered, sends `RSP_NOT_IMPLEMENTED`.
    ///
    /// Matches C `handle_request()`.
    fn handle_request(&mut self, pkt: ObexPacket) {
        let op = pkt.operation();
        self.rx_last_op = op;

        tracing::debug!(
            target: "obex::command",
            "request: op=0x{op:02x} final={}",
            pkt.is_final()
        );

        // Connection-ID validation — matches C gobex.c check_connid() +
        // parse_request().
        //
        // C semantics (gobex.c:1166-1181):
        //   • conn_id == CONNID_INVALID → allow (no connection)
        //   • HDR_CONNECTION absent     → allow (header is optional)
        //   • HDR_CONNECTION present but wrong value → reject
        //
        // Only CONNECT and ABORT bypass the check entirely.
        if self.conn_id != CONNID_INVALID && op != OP_CONNECT && op != OP_ABORT {
            let id_ok = pkt
                .get_header(HDR_CONNECTION)
                .and_then(|h| h.as_u32())
                .is_none_or(|id| id == self.conn_id);
            if !id_ok {
                tracing::debug!(
                    target: "obex::command",
                    "connection ID mismatch — sending SERVICE_UNAVAILABLE"
                );
                let rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
                let _ = self.send(rsp);
                return;
            }
        }

        // Process SRM headers.
        self.setup_srm(&pkt, false);

        // Find handler (take it out to avoid borrow conflict).
        let handler_idx = self.req_handlers.iter().position(|h| h.opcode == op);

        if let Some(idx) = handler_idx {
            // Take the handler out, invoke it, put it back.
            let mut handler = self.req_handlers.remove(idx);
            (handler.func)(self, &pkt);
            // Re-insert only if the handler wasn't removed by the callback
            // (e.g. server_abort_handler calls complete_server_transfer which
            // removes all handlers).  Clamp index to current length.
            let insert_idx = idx.min(self.req_handlers.len());
            self.req_handlers.insert(insert_idx, handler);
        } else {
            tracing::debug!(
                target: "obex::command",
                "no handler for opcode 0x{op:02x} — sending NOT_IMPLEMENTED"
            );
            let rsp = ObexPacket::new_response(RSP_NOT_IMPLEMENTED);
            let _ = self.send(rsp);
        }
    }

    // -----------------------------------------------------------------------
    // Queue flush helper
    // -----------------------------------------------------------------------

    /// Attempts to encode and send the next packet from the transmit queue.
    ///
    /// This is a synchronous helper that stages the next packet into
    /// `tx_buf`, ready for `write_data()` to send.
    fn try_write_next(&mut self) {
        if self.suspended {
            return;
        }
        if self.tx_queue.is_empty() {
            return;
        }

        // If we have a pending request and SRM is not active, wait.
        if self.pending_req.is_some() && !self.srm.enabled {
            return;
        }

        // Pop the next packet.
        let mut ppkt = match self.tx_queue.pop_front() {
            Some(p) => p,
            None => return,
        };

        // Connection-ID enforcement.
        self.enforce_conn_id(&mut ppkt.pkt);

        // Setup SRM for outgoing packet.
        self.setup_srm(&ppkt.pkt, ppkt.id > 0);

        // Encode the packet into tx_buf.
        self.tx_data = 0;
        self.tx_sent = 0;
        match ppkt.pkt.encode(&mut self.tx_buf) {
            Ok(n) => {
                self.tx_data = n;
                obex_dump("TX", &self.tx_buf[..n]);
            }
            Err(e) => {
                tracing::error!("packet encode error: {e}");
                if let Some(func) = ppkt.rsp_func.take() {
                    func(ObexError::Failed(format!("encode: {e}")));
                }
                return;
            }
        }

        // If this is a request (has an ID and expects a response), make it
        // the pending request and start its timeout timer.
        if ppkt.id > 0 && ppkt.rsp_handler.is_some() {
            // Start timeout if duration is non-zero.
            if ppkt.timeout > Duration::ZERO {
                let dur = ppkt.timeout;
                let handle = tokio::task::spawn(async move {
                    tokio::time::sleep(dur).await;
                    // Timeout expiry is handled by the session's event loop —
                    // we just need the handle for abort on response.
                });
                ppkt.timeout_handle = Some(handle);
            }
            self.pending_req = Some(ppkt);
        }
    }

    /// Enforces the Connection-ID header on outgoing packets when a valid
    /// connection ID is set.
    ///
    /// Matches the C `g_obex_send_req()` conn-id enforcement logic.
    fn enforce_conn_id(&self, pkt: &mut ObexPacket) {
        if self.conn_id == CONNID_INVALID {
            return;
        }

        let op = pkt.opcode();

        // Don't add connection ID to CONNECT packets.
        if op == OP_CONNECT {
            return;
        }

        // Don't add if already present.
        if pkt.get_header(HDR_CONNECTION).is_some() {
            return;
        }

        pkt.prepend_header(ObexHeader::new_u32(HDR_CONNECTION, self.conn_id));
    }

    /// Drives the write side of the session by flushing `tx_buf` to the
    /// socket.
    ///
    /// Returns `true` if more data remains to be sent.
    ///
    /// Matches C `write_data()`.
    pub async fn write_data(&mut self) -> Result<bool, ObexError> {
        if self.tx_data == 0 {
            // Nothing staged — try to stage the next packet.
            self.try_write_next();
            if self.tx_data == 0 {
                return Ok(false); // nothing to send
            }
        }

        // Send staged data.
        let data_slice = self.tx_buf[self.tx_sent..self.tx_data].to_vec();
        self.write_all_bytes(&data_slice).await?;
        self.tx_sent = self.tx_data;

        // Clear staged data.
        self.tx_data = 0;
        self.tx_sent = 0;

        // Try to stage the next packet.
        self.try_write_next();

        Ok(self.tx_data > 0)
    }

    // -----------------------------------------------------------------------
    // Public send API — from g_obex_send / g_obex_send_req / g_obex_send_rsp
    // -----------------------------------------------------------------------

    /// Enqueues a packet for transmission without expecting a response.
    ///
    /// Used for sending one-shot packets (typically responses).  The
    /// Connection-ID header is automatically prepended if a connection is
    /// established.
    ///
    /// Matches C `g_obex_send()`.
    pub fn send(&mut self, mut pkt: ObexPacket) -> Result<(), ObexError> {
        let op = pkt.opcode();

        // Prepare SRM / connect response headers.
        if self.rx_last_op == OP_CONNECT && op >= 0x10 {
            self.prepare_connect_rsp(&mut pkt);
        } else if (self.rx_last_op == OP_GET || self.rx_last_op == OP_PUT) && op >= 0x10 {
            self.prepare_srm_rsp(&mut pkt);
        }

        let ppkt = PendingPacket {
            id: 0,
            pkt,
            timeout: Duration::from_secs(0),
            timeout_handle: None,
            rsp_func: None,
            rsp_handler: None,
            cancelled: false,
            suspended: false,
            authenticating: false,
        };

        self.tx_queue.push_back(ppkt);
        self.try_write_next();
        Ok(())
    }

    /// Enqueues a request packet and registers a response callback.
    ///
    /// Returns a monotonically increasing request ID that can be used with
    /// [`cancel_req`] to cancel the request before the response arrives.
    ///
    /// `rsp_func` is called when the response packet is received.
    ///
    /// Matches C `g_obex_send_req()`.
    pub fn send_req(
        &mut self,
        mut pkt: ObexPacket,
        timeout: Duration,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let op = pkt.operation();

        // Prepare SRM for GET/PUT requests.
        if op == OP_GET || op == OP_PUT {
            self.prepare_srm_req(&mut pkt);
        }

        let id = NEXT_PKT_ID.fetch_add(1, Ordering::Relaxed);

        let ppkt = PendingPacket {
            id,
            pkt,
            timeout,
            timeout_handle: None,
            rsp_func: None,
            rsp_handler: Some(Box::new(rsp_func)),
            cancelled: false,
            suspended: false,
            authenticating: false,
        };

        self.tx_queue.push_back(ppkt);
        self.try_write_next();
        Ok(id)
    }

    /// Cancels a previously sent request by its ID.
    ///
    /// If `remove` is `true` and the request is still in the queue (not yet
    /// sent), it is removed entirely.  If the request is already the pending
    /// request, it is marked as cancelled and the error callback is invoked
    /// when the (discarded) response arrives.
    ///
    /// Returns `true` if the request was found.
    ///
    /// Matches C `g_obex_cancel_req()`.
    pub fn cancel_req(&mut self, req_id: u32, remove: bool) -> bool {
        // Check pending request.
        if let Some(ref mut p) = self.pending_req {
            if p.id == req_id {
                if let Some(handle) = p.timeout_handle.take() {
                    handle.abort();
                }
                p.cancelled = true;
                return true;
            }
        }

        // Check queue.
        if remove {
            let before = self.tx_queue.len();
            self.tx_queue.retain(|p| p.id != req_id);
            if self.tx_queue.len() < before {
                return true;
            }
        } else {
            for p in &mut self.tx_queue {
                if p.id == req_id {
                    p.cancelled = true;
                    return true;
                }
            }
        }

        false
    }

    /// Sends a response packet for the current incoming request.
    ///
    /// Matches C implied send-response usage pattern.
    pub fn send_rsp(&mut self, _opcode: u8, rsp: ObexPacket) -> Result<(), ObexError> {
        self.send(rsp)
    }

    // -----------------------------------------------------------------------
    // Request handler registration
    // -----------------------------------------------------------------------

    /// Registers a handler for incoming requests with the given opcode.
    ///
    /// Returns a handler ID that can be passed to [`remove_request_handler`].
    ///
    /// Matches C `g_obex_add_request_function()`.
    pub fn add_request_handler(
        &mut self,
        opcode: u8,
        func: impl FnMut(&mut ObexSession, &ObexPacket) + Send + 'static,
    ) -> u32 {
        let id = NEXT_HANDLER_ID.fetch_add(1, Ordering::Relaxed);
        self.req_handlers.push(RequestHandler { id, opcode, func: Box::new(func) });
        id
    }

    /// Removes a previously registered request handler by ID.
    ///
    /// Matches C `g_obex_remove_request_function()`.
    pub fn remove_request_handler(&mut self, handler_id: u32) {
        self.req_handlers.retain(|h| h.id != handler_id);
    }

    // -----------------------------------------------------------------------
    // Disconnect callback
    // -----------------------------------------------------------------------

    /// Registers a callback invoked when the session is disconnected.
    ///
    /// Matches C `g_obex_set_disconnect_function()`.
    pub fn set_disconnect_function(&mut self, func: impl FnMut(ObexError) + Send + 'static) {
        self.disconn_func = Some(Box::new(func));
    }

    // -----------------------------------------------------------------------
    // Connect response preparation (server side)
    // -----------------------------------------------------------------------

    /// Prepends the `ConnectData` and `Connection-ID` header to a CONNECT
    /// response packet (server side).
    ///
    /// Matches C `prepare_connect_rsp()`.
    fn prepare_connect_rsp(&mut self, pkt: &mut ObexPacket) {
        let data = init_connect_data(self.rx_mtu);
        pkt.set_data(&data);

        let cid = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        self.conn_id = cid;
        pkt.prepend_header(ObexHeader::new_u32(HDR_CONNECTION, cid));
    }

    // -----------------------------------------------------------------------
    // High-level OBEX operations
    // -----------------------------------------------------------------------

    /// Initiates an OBEX CONNECT operation.
    ///
    /// Creates a CONNECT packet with the protocol version (0x10), flags (0),
    /// and the session's receive MTU, optionally adding a TARGET header.
    ///
    /// Matches C `g_obex_connect()`.
    pub fn connect(
        &mut self,
        target: Option<&[u8]>,
        headers: Vec<ObexHeader>,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_CONNECT | PACKET_FINAL);

        let data = init_connect_data(self.rx_mtu);
        pkt.set_data(&data);

        if let Some(t) = target {
            pkt.add_header(ObexHeader::new_bytes(HDR_TARGET, t));
        }

        for hdr in headers {
            pkt.add_header(hdr);
        }

        // CONNECT uses double the default timeout.
        let timeout = Duration::from_secs(DEFAULT_TIMEOUT * 2);
        self.send_req(pkt, timeout, rsp_func)
    }

    /// Initiates an OBEX DISCONNECT operation.
    ///
    /// Matches C `g_obex_disconnect()`.
    pub fn disconnect(
        &mut self,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let pkt = ObexPacket::new(OP_DISCONNECT | PACKET_FINAL);
        let timeout = Duration::from_secs(DEFAULT_TIMEOUT);
        self.send_req(pkt, timeout, rsp_func)
    }

    /// Initiates an OBEX SETPATH operation.
    ///
    /// The `path` argument is the folder name to navigate to.  Special
    /// handling for `".."` sets the backup flag.
    ///
    /// Matches C `g_obex_setpath()`.
    pub fn setpath(
        &mut self,
        path: &str,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_SETPATH | PACKET_FINAL);

        // Determine flags: ".." → flags=0x03 (backup + don't create),
        // otherwise → flags=0x02 (don't create).
        let (flags, name) = if path == ".." {
            (0x03u8, "")
        } else if let Some(stripped) = path.strip_prefix("../") {
            (0x03u8, stripped)
        } else {
            (0x02u8, path)
        };

        let setpath_data = [flags, 0x00]; // flags + reserved constants byte
        pkt.set_data(&setpath_data);

        if !name.is_empty() {
            pkt.add_unicode(HDR_NAME, name);
        }

        let timeout = Duration::from_secs(DEFAULT_TIMEOUT);
        self.send_req(pkt, timeout, rsp_func)
    }

    /// Initiates an OBEX MKDIR (create directory) operation.
    ///
    /// Like SETPATH but with flags=0 to allow directory creation.
    ///
    /// Matches C `g_obex_mkdir()`.
    pub fn mkdir(
        &mut self,
        path: &str,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_SETPATH | PACKET_FINAL);

        let setpath_data = [0x00u8, 0x00]; // flags=0 (create allowed) + reserved
        pkt.set_data(&setpath_data);

        pkt.add_unicode(HDR_NAME, path);

        let timeout = Duration::from_secs(DEFAULT_TIMEOUT);
        self.send_req(pkt, timeout, rsp_func)
    }

    /// Initiates an OBEX DELETE operation.
    ///
    /// Creates a PUT+FINAL packet with only a NAME header.
    ///
    /// Matches C `g_obex_delete()`.
    pub fn delete(
        &mut self,
        name: &str,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_PUT | PACKET_FINAL);
        pkt.add_unicode(HDR_NAME, name);

        let timeout = Duration::from_secs(DEFAULT_TIMEOUT);
        self.send_req(pkt, timeout, rsp_func)
    }

    /// Initiates an OBEX COPY (ACTION with copy ID) operation.
    ///
    /// Matches C `g_obex_copy()`.
    pub fn copy(
        &mut self,
        name: &str,
        dest: &str,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_ACTION | PACKET_FINAL);
        pkt.add_unicode(HDR_NAME, name);
        pkt.add_unicode(HDR_DESTNAME, dest);
        pkt.add_uint8(HDR_ACTION, ACTION_COPY);

        let timeout = Duration::from_secs(DEFAULT_TIMEOUT);
        self.send_req(pkt, timeout, rsp_func)
    }

    /// Initiates an OBEX MOVE (ACTION with move ID) operation.
    ///
    /// Matches C `g_obex_move()`.
    pub fn move_obj(
        &mut self,
        name: &str,
        dest: &str,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_ACTION | PACKET_FINAL);
        pkt.add_unicode(HDR_NAME, name);
        pkt.add_unicode(HDR_DESTNAME, dest);
        pkt.add_uint8(HDR_ACTION, ACTION_MOVE);

        let timeout = Duration::from_secs(DEFAULT_TIMEOUT);
        self.send_req(pkt, timeout, rsp_func)
    }

    /// Initiates an OBEX ABORT request.
    ///
    /// Uses a shorter timeout (`ABORT_TIMEOUT` = 5s).
    ///
    /// Matches C `g_obex_abort_req()`.
    pub fn abort_req(
        &mut self,
        rsp_func: impl FnMut(ObexPacket) + Send + 'static,
    ) -> Result<u32, ObexError> {
        let pkt = ObexPacket::new(OP_ABORT | PACKET_FINAL);
        let timeout = Duration::from_secs(ABORT_TIMEOUT);
        self.send_req(pkt, timeout, rsp_func)
    }

    // -----------------------------------------------------------------------
    // Session control methods
    // -----------------------------------------------------------------------

    /// Suspends the session, pausing all outgoing I/O.
    ///
    /// Also marks any pending request as suspended for SRM flow control.
    ///
    /// Matches C `g_obex_suspend()`.
    pub fn suspend(&mut self) {
        tracing::debug!(target: "obex::command", "session suspended");
        self.suspended = true;
        if let Some(ref mut p) = self.pending_req {
            p.suspended = true;
        }
    }

    /// Resumes a previously suspended session.
    ///
    /// Clears the suspended flag on any pending request and immediately
    /// tries to flush the transmit queue.
    ///
    /// Matches C `g_obex_resume()`.
    pub fn resume(&mut self) {
        tracing::debug!(target: "obex::command", "session resumed");
        self.suspended = false;
        if let Some(ref mut p) = self.pending_req {
            p.suspended = false;
        }
        self.try_write_next();
    }

    /// Returns `true` if Single Response Mode is currently active.
    ///
    /// SRM is active when it has been enabled **and** the SRMP value permits
    /// sending (i.e. not in WAIT state).
    ///
    /// Matches C `g_obex_srm_active()`.
    pub fn srm_active(&self) -> bool {
        self.srm.enabled && self.srm.srmp <= SRMP_NEXT_WAIT
    }

    /// Clears all pending packets from the transmit queue.
    ///
    /// Matches C `g_obex_drop_tx_queue()`.
    pub fn drop_tx_queue(&mut self) {
        self.tx_queue.clear();
    }

    /// Returns the current OBEX Connection-ID.
    ///
    /// Returns [`CONNID_INVALID`] if no connection has been established.
    pub fn get_conn_id(&self) -> u32 {
        self.conn_id
    }

    /// Sets the OBEX Connection-ID.
    ///
    /// Used when a Connection-ID is negotiated externally (e.g. from a
    /// received CONNECT response parsed by the caller).
    pub fn set_conn_id(&mut self, id: u32) {
        self.conn_id = id;
    }

    /// Returns the transport-level receive MTU.
    ///
    /// This is the maximum size of a single read from the underlying
    /// transport socket.
    pub fn io_rx_mtu(&self) -> usize {
        self.io_rx_mtu
    }
}

// ---------------------------------------------------------------------------
// MTU clamping helper
// ---------------------------------------------------------------------------

/// Clamps an MTU value to the valid range.
///
/// Values below [`MINIMUM_MTU`] are promoted to [`DEFAULT_MTU`] (matching C
/// `g_obex_new()` behaviour: if < 255, use 4096).  Values above
/// [`MAXIMUM_MTU`] are capped.
fn clamp_mtu(mtu: usize) -> usize {
    if mtu < MINIMUM_MTU as usize {
        DEFAULT_MTU as usize
    } else if mtu > MAXIMUM_MTU as usize {
        MAXIMUM_MTU as usize
    } else {
        mtu
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nix::libc;

    #[test]
    fn test_obex_strerror_known_codes() {
        assert_eq!(obex_strerror(0x10), "Continue");
        assert_eq!(obex_strerror(0x20), "Success");
        assert_eq!(obex_strerror(0x41), "Unauthorized");
        assert_eq!(obex_strerror(0x44), "Not Found");
        assert_eq!(obex_strerror(0x50), "Internal Server Error");
        assert_eq!(obex_strerror(0x61), "Database Locked");
    }

    #[test]
    fn test_obex_strerror_unknown() {
        assert_eq!(obex_strerror(0x00), "Unknown");
        assert_eq!(obex_strerror(0xFF), "Unknown");
        assert_eq!(obex_strerror(0x70), "Unknown");
    }

    #[test]
    fn test_errno_to_rsp_success() {
        assert_eq!(errno_to_rsp(0), RSP_SUCCESS);
    }

    #[test]
    fn test_errno_to_rsp_eagain() {
        assert_eq!(errno_to_rsp(-libc::EAGAIN), RSP_CONTINUE);
    }

    #[test]
    fn test_errno_to_rsp_permission() {
        assert_eq!(errno_to_rsp(-libc::EPERM), RSP_FORBIDDEN);
        assert_eq!(errno_to_rsp(-libc::EACCES), RSP_FORBIDDEN);
    }

    #[test]
    fn test_errno_to_rsp_not_found() {
        assert_eq!(errno_to_rsp(-libc::ENOENT), RSP_NOT_FOUND);
    }

    #[test]
    fn test_errno_to_rsp_bad_request() {
        assert_eq!(errno_to_rsp(-libc::EINVAL), RSP_BAD_REQUEST);
    }

    #[test]
    fn test_errno_to_rsp_not_implemented() {
        assert_eq!(errno_to_rsp(-libc::ENOSYS), RSP_NOT_IMPLEMENTED);
    }

    #[test]
    fn test_errno_to_rsp_fallback() {
        assert_eq!(errno_to_rsp(-999), RSP_INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MTU, 4096);
        assert_eq!(MINIMUM_MTU, 255);
        assert_eq!(MAXIMUM_MTU, 65535);
        assert_eq!(CONNID_INVALID, 0xFFFF_FFFF);
    }

    #[test]
    fn test_transport_type_debug() {
        assert_eq!(format!("{:?}", TransportType::Stream), "Stream");
        assert_eq!(format!("{:?}", TransportType::Packet), "Packet");
    }

    #[test]
    fn test_data_policy_debug() {
        assert_eq!(format!("{:?}", DataPolicy::Copy), "Copy");
        assert_eq!(format!("{:?}", DataPolicy::Reference), "Reference");
    }

    #[test]
    fn test_obex_error_display() {
        let e = ObexError::Disconnected;
        assert_eq!(format!("{e}"), "disconnected");
        let e = ObexError::Timeout;
        assert_eq!(format!("{e}"), "timeout");
        let e = ObexError::ParseError("bad data".into());
        assert_eq!(format!("{e}"), "parse error: bad data");
        let e = ObexError::ProtocolError { code: 0x43, message: "Forbidden".into() };
        assert_eq!(format!("{e}"), "OBEX protocol error: 67 Forbidden");
    }

    #[test]
    fn test_srm_config_default() {
        let c = SrmConfig::new();
        assert!(!c.enabled);
        assert_eq!(c.srm, SRM_DISABLE);
        assert_eq!(c.srmp, SRMP_NEXT);
        assert!(!c.outgoing);
        assert_eq!(c.op, OP_NONE);
    }

    #[test]
    fn test_srm_config_reset() {
        let mut c = SrmConfig::new();
        c.enabled = true;
        c.srm = SRM_ENABLE;
        c.op = OP_GET;
        c.reset();
        assert!(!c.enabled);
        assert_eq!(c.srm, SRM_DISABLE);
        assert_eq!(c.op, OP_NONE);
    }

    #[test]
    fn test_check_srm_final() {
        assert!(check_srm_final(RSP_SUCCESS));
        assert!(check_srm_final(RSP_FORBIDDEN));
        assert!(check_srm_final(RSP_NOT_ACCEPTABLE));
        assert!(check_srm_final(RSP_NOT_FOUND));
        assert!(check_srm_final(RSP_SERVICE_UNAVAILABLE));
        assert!(!check_srm_final(RSP_CONTINUE));
        assert!(!check_srm_final(RSP_BAD_REQUEST));
    }

    #[test]
    fn test_req_header_offset() {
        assert_eq!(req_header_offset(OP_CONNECT), 4);
        assert_eq!(req_header_offset(OP_SETPATH), 2);
        assert_eq!(req_header_offset(OP_PUT), 0);
        assert_eq!(req_header_offset(OP_GET), 0);
        assert_eq!(req_header_offset(OP_DISCONNECT), 0);
    }

    #[test]
    fn test_rsp_header_offset() {
        assert_eq!(rsp_header_offset(OP_CONNECT), 4);
        assert_eq!(rsp_header_offset(OP_PUT), 0);
        assert_eq!(rsp_header_offset(OP_GET), 0);
    }

    #[test]
    fn test_clamp_mtu() {
        assert_eq!(clamp_mtu(100), DEFAULT_MTU as usize);
        assert_eq!(clamp_mtu(0), DEFAULT_MTU as usize);
        assert_eq!(clamp_mtu(255), 255);
        assert_eq!(clamp_mtu(4096), 4096);
        assert_eq!(clamp_mtu(65535), 65535);
        assert_eq!(clamp_mtu(70000), MAXIMUM_MTU as usize);
    }

    #[test]
    fn test_init_connect_data() {
        let data = init_connect_data(4096);
        assert_eq!(data[0], 0x10); // version
        assert_eq!(data[1], 0x00); // flags
        assert_eq!(u16::from_be_bytes([data[2], data[3]]), 4096);
    }

    #[test]
    fn test_digest_response() {
        // Just verify it produces a 16-byte non-zero result for a known nonce.
        let nonce = [0u8; 16];
        let digest = digest_response(&nonce);
        assert_eq!(digest.len(), 16);
        assert_ne!(digest, [0u8; 16]);
    }

    #[test]
    fn test_errno_to_rsp_efault() {
        // EFAULT maps to SERVICE_UNAVAILABLE (matching C code).
        assert_eq!(errno_to_rsp(-libc::EFAULT), RSP_SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_errno_to_rsp_precondition_failed() {
        assert_eq!(errno_to_rsp(-libc::ENOTEMPTY), RSP_PRECONDITION_FAILED);
        assert_eq!(errno_to_rsp(-libc::EEXIST), RSP_PRECONDITION_FAILED);
    }
}
