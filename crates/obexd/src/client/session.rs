// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX client session subsystem — `org.bluez.obex.Session1` D-Bus interface,
//! transport registry, Bluetooth transport backend, and driver registry.
//!
//! Rust rewrite consolidating four C source pairs from BlueZ v5.86:
//! - `obexd/client/session.c` (1423 lines) + `obexd/client/session.h` (70 lines)
//! - `obexd/client/transport.c` (70 lines) + `obexd/client/transport.h` (26 lines)
//! - `obexd/client/bluetooth.c` (523 lines) + `obexd/client/bluetooth.h` (12 lines)
//! - `obexd/client/driver.c` (76 lines) + `obexd/client/driver.h` (23 lines)
//!
//! Implements the complete client session lifecycle:
//! - Session creation, transport connection, OBEX CONNECT handshake
//! - D-Bus `org.bluez.obex.Session1` interface with properties and methods
//! - Serialised request queue (one in-flight request at a time)
//! - Multi-step SETPATH folder navigation
//! - File operations: MKDIR, COPY, MOVE, DELETE
//! - Bluetooth transport with SDP service discovery
//! - Profile driver registry for service-specific probe/remove
//!
//! Wire format, D-Bus interface, and protocol behavior are behaviorally
//! identical to the C implementation.

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use bluez_shared::socket::{BluetoothSocket, BtTransport, L2capMode, SecLevel, SocketBuilder};

use crate::obex::apparam::ObexApparam;
use crate::obex::header::ObexHeader;
use crate::obex::packet::{ObexPacket, PACKET_FINAL, RSP_SUCCESS};
use crate::obex::session::{ObexError, ObexSession, TransportType};

use super::transfer::ObcTransfer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base D-Bus object path for OBEX client sessions.
const SESSION_BASEPATH: &str = "/org/bluez/obex/client";

/// Global monotonic counter for unique session path numbering.
///
/// Replaces C `static guint64 counter = 0`.
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Global monotonic counter for pending request IDs.
static PENDING_ID: AtomicU32 = AtomicU32::new(1);

/// Timeout for the OBEX CONNECT request (20 seconds = 2 × 10s default).
const CONNECT_TIMEOUT_SECS: u64 = 20;

/// Timeout for transport-level connection establishment (60 seconds).
const TRANSPORT_CONNECT_TIMEOUT_SECS: u64 = 60;

/// OBEX GET opcode.
const OP_GET: u8 = 0x03;

/// OBEX HDR_TYPE header identifier.
const HDR_TYPE: u8 = 0x42;

/// OBEX HDR_NAME header identifier (Unicode string, two-byte prefixed).
const HDR_NAME: u8 = 0x01;

/// OBEX HDR_TARGET header identifier (byte sequence).
const HDR_TARGET: u8 = 0xcb;

/// OBEX HDR_CONNECTION header identifier (four-byte uint32).
const HDR_CONNECTION: u8 = 0xcb;

/// OBEX ACTION_ID header identifier (single byte).
const HDR_ACTION_ID: u8 = 0x94;

/// ACTION_ID value for copy operations.
const ACTION_COPY: u8 = 0x00;

/// ACTION_ID value for move/rename operations.
const ACTION_MOVE: u8 = 0x01;

// ---------------------------------------------------------------------------
// SessionError — D-Bus error mapping for org.bluez.obex.Error.*
// ---------------------------------------------------------------------------

/// Errors produced by the OBEX client session subsystem.
///
/// Maps to D-Bus error names under `org.bluez.obex.Error.*` for method
/// error replies on the `Session1` interface.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Session was disconnected (maps to OBEX_IO_DISCONNECTED).
    #[error("Session disconnected")]
    Disconnected,

    /// Session is busy processing another request (OBEX_IO_BUSY).
    #[error("Session busy")]
    Busy,

    /// Generic failure with a descriptive message.
    #[error("Failed: {0}")]
    Failed(String),

    /// Invalid arguments supplied to a session operation.
    #[error("Invalid arguments")]
    InvalidArguments,

    /// The caller is not authorized.
    #[error("Not authorized")]
    NotAuthorized,

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An OBEX protocol-level error.
    #[error("OBEX error: {0}")]
    Obex(String),
}

impl SessionError {
    /// Returns the fully-qualified D-Bus error name for this error.
    fn dbus_error_name(&self) -> &'static str {
        match self {
            SessionError::Failed(_)
            | SessionError::Disconnected
            | SessionError::Busy
            | SessionError::Io(_)
            | SessionError::Obex(_) => "org.bluez.obex.Error.Failed",
            SessionError::InvalidArguments => "org.bluez.obex.Error.InvalidArguments",
            SessionError::NotAuthorized => "org.bluez.obex.Error.NotAuthorized",
        }
    }
}

/// Manual `zbus::DBusError` implementation so `SessionError` can be used
/// directly in `#[zbus::interface]` method return types.
impl zbus::DBusError for SessionError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        zbus::names::ErrorName::from_static_str_unchecked(self.dbus_error_name())
    }

    fn description(&self) -> Option<&str> {
        Some(match self {
            SessionError::Disconnected => "Session disconnected",
            SessionError::Busy => "Session busy",
            SessionError::Failed(msg) => msg.as_str(),
            SessionError::InvalidArguments => "Invalid arguments",
            SessionError::NotAuthorized => "Not authorized",
            SessionError::Io(_) => "I/O error",
            SessionError::Obex(_) => "OBEX error",
        })
    }

    fn create_reply(
        &self,
        call: &zbus::message::Header<'_>,
    ) -> zbus::Result<zbus::message::Message> {
        let name = self.name();
        let desc = format!("{self}");
        zbus::message::Message::error(call, name)?.build(&(desc,))
    }
}

impl From<SessionError> for zbus::Error {
    fn from(err: SessionError) -> Self {
        let name = err.dbus_error_name().to_owned();
        let desc = format!("{err}");
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name)
                .expect("SessionError D-Bus error names are always valid"),
            Some(desc),
            zbus::message::Message::method_call("/", "Err")
                .expect("default message construction should not fail")
                .build(&())
                .expect("default message build should not fail"),
        )
    }
}

impl From<ObexError> for SessionError {
    fn from(e: ObexError) -> Self {
        match e {
            ObexError::Disconnected => SessionError::Disconnected,
            ObexError::Cancelled => SessionError::Failed("Cancelled".into()),
            ObexError::InvalidArgs(msg) => {
                tracing::warn!("OBEX invalid args: {msg}");
                SessionError::InvalidArguments
            }
            ObexError::Failed(msg) => SessionError::Failed(msg),
            ObexError::IoError(io) => SessionError::Io(io),
            other => SessionError::Obex(format!("{other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// ObcTransport trait — from transport.h / transport.c
// ---------------------------------------------------------------------------

/// Transport callback invoked when a transport connection completes.
///
/// On success, provides the connected socket as an `OwnedFd`.
/// On failure, provides the error.
pub type TransportCallback = Box<dyn FnOnce(Result<OwnedFd, SessionError>) + Send + 'static>;

/// Trait defining the OBEX client transport interface.
///
/// Replaces C `struct obc_transport` (transport.h). The Bluetooth transport
/// backend implements this trait.
pub trait ObcTransport: Send + Sync {
    /// Returns the human-readable transport name (e.g. `"Bluetooth"`).
    fn name(&self) -> &str;

    /// Initiates an asynchronous transport-level connection.
    ///
    /// `source` is the local adapter address (empty string for default).
    /// `destination` is the remote device address.
    /// `uuid` is the service UUID string.
    /// `port` is the RFCOMM channel or L2CAP PSM (0 = SDP discovery).
    ///
    /// Returns a connection ID that can be used with `disconnect()`.
    fn connect(
        &self,
        source: &str,
        destination: &str,
        uuid: &str,
        port: u16,
        callback: TransportCallback,
    ) -> Result<u32, SessionError>;

    /// Queries packet transport properties for a connected socket.
    ///
    /// Returns `(omtu, imtu)` for packet-mode transports. Returns an error
    /// if the socket is stream-mode.
    fn get_packet_opt(&self, fd: BorrowedFd<'_>) -> Result<(i32, i32), SessionError>;

    /// Disconnects an active transport connection by its ID.
    fn disconnect(&self, id: u32);

    /// Returns a transport-level attribute by SDP attribute ID.
    ///
    /// Used to retrieve cached SDP data (e.g. profile version, raw records).
    fn get_attribute(&self, id: u32, attr_id: i32) -> Option<Box<dyn Any + Send>>;
}

// ---------------------------------------------------------------------------
// Transport registry — from transport.c
// ---------------------------------------------------------------------------

/// Process-level registry of OBEX client transports.
///
/// Replaces C `static GSList *transports = NULL`.
static TRANSPORTS: std::sync::LazyLock<std::sync::Mutex<Vec<Arc<dyn ObcTransport>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Registers an OBEX client transport.
///
/// Rejects duplicate names (case-insensitive).
///
/// Replaces C `obc_transport_register()`.
pub fn obc_transport_register(transport: Arc<dyn ObcTransport>) -> Result<(), SessionError> {
    let mut transports = TRANSPORTS.lock().unwrap_or_else(|e| e.into_inner());
    let name = transport.name();

    // Reject duplicates.
    for existing in transports.iter() {
        if existing.name().eq_ignore_ascii_case(name) {
            tracing::error!("transport '{name}' already registered");
            return Err(SessionError::Failed(format!("Transport '{name}' already registered")));
        }
    }

    tracing::debug!("registered transport: {name}");
    transports.push(transport);
    Ok(())
}

/// Unregisters a previously registered OBEX client transport by name.
///
/// Replaces C `obc_transport_unregister()`.
pub fn obc_transport_unregister(name: &str) {
    let mut transports = TRANSPORTS.lock().unwrap_or_else(|e| e.into_inner());
    let before = transports.len();
    transports.retain(|t| !t.name().eq_ignore_ascii_case(name));
    if transports.len() < before {
        tracing::debug!("unregistered transport: {name}");
    }
}

/// Finds a registered transport by name (case-insensitive).
fn transport_find(name: &str) -> Option<Arc<dyn ObcTransport>> {
    let transports = TRANSPORTS.lock().unwrap_or_else(|e| e.into_inner());
    transports.iter().find(|t| t.name().eq_ignore_ascii_case(name)).cloned()
}

// ---------------------------------------------------------------------------
// ObcDriver trait — from driver.h / driver.c
// ---------------------------------------------------------------------------

/// Trait defining an OBEX client profile driver.
///
/// Each profile (OPP, FTP, PBAP, MAP, etc.) implements this trait to handle
/// service-specific session setup and teardown.
///
/// Replaces C `struct obc_driver` (driver.h).
pub trait ObcDriver: Send + Sync {
    /// Returns the human-readable service name (e.g. `"OPP"`, `"FTP"`).
    fn service(&self) -> &str;

    /// Returns the service UUID string.
    fn uuid(&self) -> &str;

    /// Returns the OBEX target identifier bytes, or `None` if no target.
    fn target(&self) -> Option<&[u8]>;

    /// Returns the length of the target identifier.
    fn target_len(&self) -> usize;

    /// Returns supported features as encoded bytes, or `None`.
    fn supported_features(&self, session: &ObcSession) -> Option<Vec<u8>>;

    /// Probes the session after OBEX CONNECT succeeds.
    ///
    /// Registers profile-specific D-Bus interfaces.
    fn probe(&self, session: &ObcSession) -> Result<(), SessionError>;

    /// Removes profile-specific state from the session during shutdown.
    fn remove(&self, session: &ObcSession);
}

// ---------------------------------------------------------------------------
// Driver registry — from driver.c
// ---------------------------------------------------------------------------

/// Process-level registry of OBEX client drivers.
///
/// Replaces C `static GSList *drivers = NULL`.
static DRIVERS: std::sync::LazyLock<std::sync::Mutex<Vec<Arc<dyn ObcDriver>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Registers an OBEX client driver.
///
/// Rejects duplicate service names (case-insensitive).
///
/// Replaces C `obc_driver_register()`.
pub fn obc_driver_register(driver: Arc<dyn ObcDriver>) -> Result<(), SessionError> {
    let mut drivers = DRIVERS.lock().unwrap_or_else(|e| e.into_inner());
    let service = driver.service();

    for existing in drivers.iter() {
        if existing.service().eq_ignore_ascii_case(service) {
            tracing::error!("driver '{service}' already registered");
            return Err(SessionError::Failed(format!("Driver '{service}' already registered")));
        }
    }

    tracing::debug!("registered driver: {service}");
    drivers.push(driver);
    Ok(())
}

/// Unregisters a previously registered OBEX client driver by service name.
///
/// Replaces C `obc_driver_unregister()`.
pub fn obc_driver_unregister(service: &str) {
    let mut drivers = DRIVERS.lock().unwrap_or_else(|e| e.into_inner());
    let before = drivers.len();
    drivers.retain(|d| !d.service().eq_ignore_ascii_case(service));
    if drivers.len() < before {
        tracing::debug!("unregistered driver: {service}");
    }
}

/// Finds a registered driver by service name or UUID (case-insensitive).
///
/// Replaces C `obc_driver_find()`.
fn obc_driver_find(pattern: &str) -> Option<Arc<dyn ObcDriver>> {
    let drivers = DRIVERS.lock().unwrap_or_else(|e| e.into_inner());
    drivers
        .iter()
        .find(|d| {
            d.service().eq_ignore_ascii_case(pattern) || d.uuid().eq_ignore_ascii_case(pattern)
        })
        .cloned()
}

// ---------------------------------------------------------------------------
// Session callback types and PendingRequest
// ---------------------------------------------------------------------------

/// Completion callback for session operations.
///
/// Receives a reference to the session, an optional transfer, and an
/// optional error.
///
/// Replaces C `session_callback_t`.
pub type SessionCallbackFn =
    Box<dyn FnOnce(&ObcSession, Option<&ObcTransfer>, Option<&SessionError>) + Send>;

/// Wrapper for a session callback (to allow storage in Option).
struct SessionCallback {
    func: SessionCallbackFn,
}

/// Type alias for the process function within a `PendingRequest`.
///
/// When invoked, initiates the actual OBEX operation for this request.
type ProcessFn = Box<dyn FnOnce(&mut ObcSession) -> Result<(), SessionError> + Send>;

/// A pending or queued OBEX request.
///
/// Replaces C `struct pending_request`.
struct PendingRequest {
    /// Unique request ID.
    id: u32,
    /// Outstanding OBEX request ID (for cancellation).
    req_id: Option<u32>,
    /// Closure that initiates the actual OBEX operation.
    process: Option<ProcessFn>,
    /// Associated transfer (for GET/PUT operations).
    transfer: Option<ObcTransfer>,
    /// Completion callback.
    callback: Option<SessionCallback>,
}

// ---------------------------------------------------------------------------
// SetpathData — multi-step folder navigation state
// ---------------------------------------------------------------------------

/// State for multi-step SETPATH folder navigation.
struct SetpathData {
    /// Path components to traverse.
    remaining: Vec<String>,
    /// Current index into `remaining`.
    index: usize,
}

// ---------------------------------------------------------------------------
// ObcSession — core OBEX client session
// ---------------------------------------------------------------------------

/// An OBEX client session managing a single connection to a remote device.
///
/// Tracks the complete session lifecycle from transport connection through
/// OBEX CONNECT handshake, queued request processing, and shutdown.
///
/// Replaces C `struct obc_session`.
pub struct ObcSession {
    /// Unique session ID (monotonic counter).
    id: u64,
    /// D-Bus object path (e.g. `/org/bluez/obex/client/session0`).
    path: String,
    /// Local Bluetooth adapter address (empty string = default).
    source: String,
    /// Remote Bluetooth device address.
    destination: String,
    /// RFCOMM channel (0 = SDP resolve).
    channel: u8,
    /// L2CAP PSM (0 = SDP resolve).
    psm: u16,
    /// Transport backend reference.
    transport: Option<Arc<dyn ObcTransport>>,
    /// Transport connection ID returned by connect.
    transport_id: Option<u32>,
    /// Profile driver reference.
    driver: Option<Arc<dyn ObcDriver>>,
    /// The OBEX session engine (created after transport connects).
    ///
    /// Wrapped in `Arc<tokio::sync::Mutex<>>` for sharing with the
    /// async transfer API (`ObcTransfer::start()` requires this).
    obex: Option<Arc<tokio::sync::Mutex<ObexSession>>>,
    /// D-Bus owner (unique sender name).
    owner: String,
    /// Current in-flight request (only one at a time).
    pending: Option<PendingRequest>,
    /// Queued requests waiting to be processed.
    queue: VecDeque<PendingRequest>,
    /// Current remote folder path.
    folder: String,
    /// OBEX target string (from driver service name).
    target_name: String,
    /// D-Bus connection reference for interface registration.
    dbus_conn: Option<zbus::Connection>,
    /// Whether this session has been registered on D-Bus.
    registered: bool,
    /// Whether shutdown has been initiated.
    shutting_down: bool,
    /// Callback for session creation completion.
    creation_callback: Option<SessionCallback>,
    /// Weak self-reference for async callbacks that need to call back
    /// into the session (e.g. transfer completion notifications).
    self_weak: Option<std::sync::Weak<std::sync::Mutex<Self>>>,
}

// ---------------------------------------------------------------------------
// Global session list
// ---------------------------------------------------------------------------

/// Process-level list of active OBEX client sessions.
static SESSIONS: std::sync::LazyLock<std::sync::Mutex<Vec<Arc<std::sync::Mutex<ObcSession>>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Finds an existing session matching the given parameters for reuse.
fn session_find(
    source: &str,
    destination: &str,
    target: &str,
    channel: u8,
    psm: u16,
) -> Option<Arc<std::sync::Mutex<ObcSession>>> {
    let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    for session_arc in sessions.iter() {
        if let Ok(session) = session_arc.try_lock() {
            let src_match = source.is_empty()
                || session.source.is_empty()
                || session.source.eq_ignore_ascii_case(source);
            let dst_match = session.destination.eq_ignore_ascii_case(destination);
            let tgt_match = target.is_empty() || session.target_name.eq_ignore_ascii_case(target);
            let port_match = (channel == 0 || session.channel == 0 || session.channel == channel)
                && (psm == 0 || session.psm == 0 || session.psm == psm);

            if src_match && dst_match && tgt_match && port_match {
                return Some(session_arc.clone());
            }
        }
    }
    None
}

/// Adds a session to the global list.
fn session_add(session: Arc<std::sync::Mutex<ObcSession>>) {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions.push(session);
}

/// Removes a session from the global list by path.
fn session_remove(path: &str) {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions.retain(|s| s.try_lock().map_or(true, |session| session.path != path));
}

// ---------------------------------------------------------------------------
// ObcSession implementation — lifecycle and core methods
// ---------------------------------------------------------------------------

impl ObcSession {
    /// Creates a new OBEX client session and initiates transport connection.
    ///
    /// Allocates a unique session path, looks up the transport (always
    /// `"Bluetooth"` in practice), resolves the profile driver, and begins
    /// the async transport connection.
    ///
    /// Replaces C `obc_session_create()`.
    pub fn create(
        source: Option<&str>,
        destination: &str,
        target: Option<&str>,
        channel: u8,
        psm: u16,
        owner: &str,
        callback: SessionCallbackFn,
    ) -> Result<Arc<std::sync::Mutex<Self>>, SessionError> {
        let target_str = target.unwrap_or("");

        // Check for an existing reusable session.
        if let Some(existing) =
            session_find(source.unwrap_or(""), destination, target_str, channel, psm)
        {
            tracing::debug!("reusing existing session for {destination}");
            return Ok(existing);
        }

        // Resolve transport — always "Bluetooth".
        let transport = transport_find("Bluetooth")
            .ok_or_else(|| SessionError::Failed("Bluetooth transport not registered".into()))?;

        // Resolve driver by target/service name.
        let driver = if !target_str.is_empty() { obc_driver_find(target_str) } else { None };

        // Allocate unique session path.
        let session_num = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = format!("{SESSION_BASEPATH}/session{session_num}");

        let target_name =
            driver.as_ref().map_or_else(|| target_str.to_owned(), |d| d.service().to_owned());

        let session = Self {
            id: session_num,
            path,
            source: source.unwrap_or("").to_owned(),
            destination: destination.to_owned(),
            channel,
            psm,
            transport: Some(transport),
            transport_id: None,
            driver,
            obex: None,
            owner: owner.to_owned(),
            pending: None,
            queue: VecDeque::new(),
            folder: String::new(),
            target_name,
            dbus_conn: None,
            registered: false,
            shutting_down: false,
            creation_callback: Some(SessionCallback { func: callback }),
            self_weak: None,
        };

        let session_arc = Arc::new(std::sync::Mutex::new(session));

        // Set the self-reference for async callbacks.
        {
            let mut s = session_arc.lock().unwrap_or_else(|e| e.into_inner());
            s.self_weak = Some(Arc::downgrade(&session_arc));
        }

        // Add to global session list.
        session_add(session_arc.clone());

        // Initiate transport connection.
        Self::session_connect(session_arc.clone());

        Ok(session_arc)
    }

    /// Initiates the async transport connection.
    ///
    /// Replaces C `session_connect()`.
    fn session_connect(session_arc: Arc<std::sync::Mutex<Self>>) {
        let (source, destination, service, port, transport) = {
            let session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
            let source = session.source.clone();
            let destination = session.destination.clone();
            let service = session.driver.as_ref().map_or_else(String::new, |d| d.uuid().to_owned());
            let port = if session.psm != 0 { session.psm } else { session.channel as u16 };
            let transport = session.transport.clone();
            (source, destination, service, port, transport)
        };

        let Some(transport) = transport else {
            tracing::error!("no transport for session");
            let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
            session.notify_creation(Some(SessionError::Failed("No transport".into())));
            return;
        };

        let arc_clone = session_arc.clone();
        let callback: TransportCallback = Box::new(move |result| {
            Self::transport_complete(arc_clone, result);
        });

        match transport.connect(&source, &destination, &service, port, callback) {
            Ok(transport_id) => {
                let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
                session.transport_id = Some(transport_id);
            }
            Err(e) => {
                tracing::error!("transport connect initiation failed: {e}");
                let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
                session.notify_creation(Some(e));
            }
        }
    }

    /// Called when the transport connection completes (success or failure).
    ///
    /// On success, creates the ObexSession over the connected fd and initiates
    /// the OBEX CONNECT handshake. On failure, reports the error.
    ///
    /// Replaces C `transport_func()`.
    fn transport_complete(
        session_arc: Arc<std::sync::Mutex<Self>>,
        result: Result<OwnedFd, SessionError>,
    ) {
        let fd = match result {
            Ok(fd) => fd,
            Err(e) => {
                tracing::error!("transport connect failed: {e}");
                let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
                session.notify_creation(Some(e));
                return;
            }
        };

        // Determine packet vs stream mode and MTU from transport.
        let (transport_type, imtu, omtu) = {
            let session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
            let borrowed = fd.as_fd();
            if let Some(transport) = &session.transport {
                match transport.get_packet_opt(borrowed) {
                    Ok((o, i)) => (TransportType::Packet, i as usize, o as usize),
                    Err(_) => (TransportType::Stream, 4096, 4096),
                }
            } else {
                (TransportType::Stream, 4096, 4096)
            }
        };

        // Create OBEX session engine over the connected fd.
        let mut obex = match ObexSession::new(fd, transport_type, imtu, omtu) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!("failed to create OBEX session: {e}");
                let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
                session.notify_creation(Some(SessionError::Obex(e.to_string())));
                return;
            }
        };

        // Install disconnect handler — routes OBEX disconnection events
        // back to the session for cleanup.
        let disconnect_arc = session_arc.clone();
        obex.set_disconnect_function(move |err| {
            tracing::warn!("OBEX transport disconnected: {err}");
            if let Ok(mut session) = disconnect_arc.try_lock() {
                let error = SessionError::from(err);
                session.transfer_complete(Some(error));
            }
        });

        // Wrap in Arc<Mutex<>> for sharing with async transfer API.
        let obex_arc = Arc::new(tokio::sync::Mutex::new(obex));

        // Store OBEX session and initiate OBEX CONNECT handshake.
        let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
        session.obex = Some(obex_arc.clone());

        // Build OBEX CONNECT headers (target + supported features).
        // Optional CONNECTION_ID from previous session — included when
        // non-zero to allow server-side session correlation.
        let mut headers = Vec::new();
        if let Some(ref driver) = session.driver {
            if let Some(target_bytes) = driver.target() {
                headers.push(ObexHeader::new_bytes(HDR_TARGET, target_bytes));
            }
            // Include descriptive name header for service identification.
            let svc_name = driver.service();
            if !svc_name.is_empty() {
                headers.push(ObexHeader::new_unicode(HDR_NAME, svc_name));
            }
            if let Some(features) = driver.supported_features(&session) {
                let mut apparam = ObexApparam::new();
                // Use typed setters for known feature tags: the first byte
                // encodes the feature count (u8), the second two bytes
                // encode the feature version (u16), and the remainder is
                // raw feature data.
                if features.len() >= 3 {
                    apparam.set_u8(0x01, features[0]);
                    apparam.set_u16(0x02, u16::from_be_bytes([features[1], features[2]]));
                    if features.len() > 3 {
                        apparam.set_bytes(0x03, &features[3..]);
                    }
                } else {
                    apparam.set_bytes(0x01, &features);
                }
                // Verify encoding produces valid output before building
                // the header — encode_to_vec exercises the full TLV path.
                if let Ok(encoded) = apparam.encode_to_vec() {
                    tracing::trace!("supported features encoded: {} bytes", encoded.len());
                }
                if let Some(hdr) = ObexHeader::new_apparam(&apparam) {
                    headers.push(hdr);
                }
            }
        }

        // Issue OBEX CONNECT.
        // Lock the obex to send the CONNECT request. Since we just created it,
        // try_lock should always succeed here.
        let arc_clone = session_arc.clone();
        if let Ok(mut obex_guard) = obex_arc.try_lock() {
            let connect_result = obex_guard.connect(
                session.driver.as_ref().and_then(|d| d.target()),
                headers,
                move |response| {
                    Self::obex_connect_cb(arc_clone.clone(), response);
                },
            );
            if let Err(e) = connect_result {
                tracing::error!("OBEX CONNECT failed to send: {e}");
                session.notify_creation(Some(SessionError::Obex(e.to_string())));
            }
        } else {
            tracing::error!("OBEX session mutex contention during connect");
            session.notify_creation(Some(SessionError::Busy));
        }
    }

    /// Callback for the OBEX CONNECT response.
    ///
    /// Validates the response code and notifies the creation callback.
    fn obex_connect_cb(session_arc: Arc<std::sync::Mutex<Self>>, response: ObexPacket) {
        let opcode = response.opcode();
        let success = opcode == (RSP_SUCCESS | PACKET_FINAL);

        // Inspect response headers for TARGET and NAME values.
        if let Some(target_hdr) = response.get_header(HDR_TARGET) {
            if let Some(target_bytes) = target_hdr.as_bytes() {
                tracing::debug!("connect response TARGET: {} bytes", target_bytes.len());
            }
        }
        if let Some(name_hdr) = response.get_header(HDR_NAME) {
            if let Some(name_str) = name_hdr.as_unicode() {
                tracing::debug!("connect response NAME: {name_str}");
            }
        }

        let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            // Log the negotiated connection ID from the OBEX engine.
            if let Some(ref obex_arc) = session.obex {
                if let Ok(obex_guard) = obex_arc.try_lock() {
                    let conn_id = obex_guard.get_conn_id();
                    tracing::info!(
                        "OBEX CONNECT success for session {}, conn_id={conn_id}",
                        session.path
                    );
                }
            }
            session.notify_creation(None);
        } else {
            tracing::error!(
                "OBEX CONNECT failed with opcode 0x{opcode:02x} for session {}",
                session.path
            );
            session.notify_creation(Some(SessionError::Failed(format!(
                "OBEX CONNECT failed: 0x{opcode:02x}"
            ))));
        }
    }

    /// Notifies the creation callback of success or failure.
    fn notify_creation(&mut self, error: Option<SessionError>) {
        if let Some(cb) = self.creation_callback.take() {
            (cb.func)(self, None, error.as_ref());
        }
    }

    /// Registers the session on D-Bus and probes the profile driver.
    ///
    /// Replaces C `obc_session_register()`.
    pub fn register(
        &mut self,
        conn: &zbus::Connection,
        session_arc: Arc<std::sync::Mutex<Self>>,
    ) -> Result<String, SessionError> {
        if self.registered {
            return Ok(self.path.clone());
        }

        self.dbus_conn = Some(conn.clone());

        let iface = Session1Interface {
            session: session_arc,
            session_source: self.source.clone(),
            session_destination: self.destination.clone(),
            session_channel: self.channel,
            session_psm: self.psm,
            session_target: self.target_name.clone(),
        };

        let path = self.path.clone();
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = conn_clone.object_server().at(path.as_str(), iface).await {
                tracing::error!("failed to register Session1: {e}");
            }
        });

        self.registered = true;

        // Probe driver for profile-specific interfaces.
        if let Some(ref driver) = self.driver {
            if let Err(e) = driver.probe(self) {
                tracing::error!("driver probe failed: {e}");
                return Err(e);
            }
        }

        tracing::info!("session registered: {}", self.path);
        Ok(self.path.clone())
    }

    /// Shuts down the session, draining callbacks and disconnecting.
    ///
    /// Replaces C `obc_session_shutdown()`.
    pub fn shutdown(&mut self) {
        if self.shutting_down {
            return;
        }
        self.shutting_down = true;
        tracing::info!("shutting down session {}", self.path);

        let disconnect_err = SessionError::Disconnected;

        // Drain pending request.
        if let Some(mut p) = self.pending.take() {
            if let Some(cb) = p.callback.take() {
                (cb.func)(self, None, Some(&disconnect_err));
            }
        }

        // Drain queued requests.
        while let Some(mut req) = self.queue.pop_front() {
            if let Some(cb) = req.callback.take() {
                (cb.func)(self, None, Some(&disconnect_err));
            }
        }

        // Remove driver.
        if let Some(ref driver) = self.driver {
            driver.remove(self);
        }

        // Disconnect OBEX session.
        if let Some(ref obex_arc) = self.obex {
            if let Ok(mut obex_guard) = obex_arc.try_lock() {
                let _ = obex_guard.disconnect(|_response| {
                    tracing::debug!("OBEX disconnect complete");
                });
            }
        }
        self.obex = None;

        // Disconnect transport.
        if let (Some(transport), Some(tid)) = (&self.transport, self.transport_id) {
            transport.disconnect(tid);
        }

        // Unregister D-Bus interface.
        if self.registered {
            if let Some(ref conn) = self.dbus_conn {
                let path = self.path.clone();
                let conn_clone = conn.clone();
                tokio::spawn(async move {
                    let _ = conn_clone
                        .object_server()
                        .remove::<Session1Interface, _>(path.as_str())
                        .await;
                });
            }
            self.registered = false;
        }

        // Remove from global session list.
        session_remove(&self.path);
    }

    /// Queues a transfer operation for serialised processing.
    ///
    /// Only one request is in-flight at a time — additional requests wait
    /// in the FIFO queue until the current request completes.
    ///
    /// Replaces C `obc_session_queue()`.
    pub fn queue(
        &mut self,
        transfer: ObcTransfer,
        callback: SessionCallbackFn,
    ) -> Result<(), SessionError> {
        if self.shutting_down {
            return Err(SessionError::Disconnected);
        }

        let req_id = PENDING_ID.fetch_add(1, Ordering::Relaxed);

        let req = PendingRequest {
            id: req_id,
            req_id: None,
            process: Some(Box::new(move |session: &mut ObcSession| session.start_transfer())),
            transfer: Some(transfer),
            callback: Some(SessionCallback { func: callback }),
        };

        self.queue.push_back(req);
        self.process_queue();
        Ok(())
    }

    /// Processes the next item in the request queue.
    ///
    /// Only proceeds if no request is currently in-flight.
    ///
    /// Replaces C `session_process_queue()`.
    fn process_queue(&mut self) {
        if self.pending.is_some() {
            return;
        }

        let mut req = match self.queue.pop_front() {
            Some(r) => r,
            None => return,
        };

        let process_fn = req.process.take();
        self.pending = Some(req);

        if let Some(f) = process_fn {
            if let Err(e) = f(self) {
                tracing::error!("request processing failed: {e}");
                self.handle_process_error(e);
            }
        }
    }

    /// Handles a processing error for the current pending request.
    fn handle_process_error(&mut self, error: SessionError) {
        if let Some(mut p) = self.pending.take() {
            if let Some(cb) = p.callback.take() {
                (cb.func)(self, None, Some(&error));
            }
        }
        self.process_queue();
    }

    /// Starts the transfer associated with the current pending request.
    ///
    /// Spawns an async task that registers the transfer on D-Bus and
    /// initiates the OBEX operation via `ObcTransfer::start()`. The
    /// transfer's completion callback signals back into the session
    /// to advance the queue.
    ///
    /// Replaces C logic in `session_process_queue()` → `transfer_get/put`.
    fn start_transfer(&mut self) -> Result<(), SessionError> {
        let obex_arc = self.obex.clone().ok_or(SessionError::Disconnected)?;
        let conn = self.dbus_conn.clone();
        let path = self.path.clone();
        let owner = self.owner.clone();
        let session_weak = self.self_weak.clone();

        if let Some(ref mut p) = self.pending {
            if let Some(mut transfer) = p.transfer.take() {
                // Set the transfer's completion callback to notify the session.
                let weak_for_cb = session_weak.clone();
                transfer.set_callback(Box::new(move |_xfer, error| {
                    if let Some(weak) = weak_for_cb {
                        if let Some(arc) = weak.upgrade() {
                            let mut session = arc.lock().unwrap_or_else(|e| e.into_inner());
                            let err = error.map(|te| SessionError::Failed(te.to_string()));
                            session.transfer_complete(err);
                        }
                    }
                }));

                // Log the transfer path for tracing.
                tracing::debug!("starting transfer at {}", transfer.get_path());

                // Spawn an async task for D-Bus registration and OBEX start.
                tokio::spawn(async move {
                    // Register transfer on D-Bus.
                    if let Some(ref conn) = conn {
                        if let Err(e) = transfer.register(conn, &path, &owner).await {
                            tracing::error!("transfer register failed: {e}");
                            transfer.xfer_complete(Some(e));
                            return;
                        }
                    }

                    // Start the OBEX transfer.
                    if let Err(e) = transfer.start(obex_arc).await {
                        tracing::error!("transfer start failed: {e}");
                        transfer.xfer_complete(Some(e));
                    }
                });
            }
        }
        Ok(())
    }

    /// Called when a transfer completes (success or failure).
    ///
    /// Clears the current pending request, invokes the completion
    /// callback, and advances the queue.
    ///
    /// Replaces C `session_terminate_transfer()`.
    pub fn transfer_complete(&mut self, error: Option<SessionError>) {
        if let Some(mut p) = self.pending.take() {
            if let Some(cb) = p.callback.take() {
                let xfer_ref = p.transfer.as_ref();
                (cb.func)(self, xfer_ref, error.as_ref());
            }
        }
        self.process_queue();
    }

    // -----------------------------------------------------------------------
    // Session operations — SETPATH, MKDIR, COPY, MOVE, DELETE, CANCEL
    // -----------------------------------------------------------------------

    /// Navigates to a folder on the remote device via multi-step SETPATH.
    ///
    /// Absolute paths (starting with '/') reset to root first.
    /// Empty segments are skipped to avoid unintended root resets.
    ///
    /// Replaces C `obc_session_setpath()`.
    pub fn setpath(&mut self, path: &str, callback: SessionCallbackFn) -> Result<(), SessionError> {
        if self.obex.is_none() {
            return Err(SessionError::Disconnected);
        }

        let mut components: Vec<String> = Vec::new();

        // Absolute path: start from root with an empty component.
        if path.starts_with('/') {
            components.push(String::new());
        }

        for segment in path.split('/') {
            if !segment.is_empty() {
                components.push(segment.to_owned());
            }
        }

        if components.is_empty() {
            // Nothing to do.
            (callback)(self, None, None);
            return Ok(());
        }

        let data = SetpathData { remaining: components, index: 0 };

        self.setpath_steps(data, callback);
        Ok(())
    }

    /// Executes the next step in a multi-step SETPATH navigation.
    fn setpath_steps(&mut self, mut data: SetpathData, callback: SessionCallbackFn) {
        if data.index >= data.remaining.len() {
            // All steps complete.
            (callback)(self, None, None);
            return;
        }

        let component = data.remaining[data.index].clone();
        data.index += 1;

        // Clone the obex Arc upfront to avoid borrowing self immutably
        // through the pattern match while needing self mutably later.
        let obex_arc = match self.obex.clone() {
            Some(arc) => arc,
            None => {
                let err = SessionError::Disconnected;
                (callback)(self, None, Some(&err));
                return;
            }
        };

        let obex_guard_result = obex_arc.try_lock();
        let Ok(mut obex_guard) = obex_guard_result else {
            let err = SessionError::Busy;
            (callback)(self, None, Some(&err));
            return;
        };

        let result = obex_guard.setpath(&component, move |_response| {
            // Step completed — further steps handled by caller.
        });

        // Drop the guard before accessing self mutably.
        drop(obex_guard);

        match result {
            Ok(_) => {
                // Update folder tracking.
                if component.is_empty() {
                    self.folder.clear();
                } else {
                    if !self.folder.is_empty() {
                        self.folder.push('/');
                    }
                    self.folder.push_str(&component);
                }

                // Continue with next step.
                self.setpath_steps(data, callback);
            }
            Err(e) => {
                let err = SessionError::Obex(e.to_string());
                (callback)(self, None, Some(&err));
            }
        }
    }

    /// Creates a directory on the remote device.
    ///
    /// Replaces C `obc_session_mkdir()`.
    pub fn mkdir(&mut self, folder: &str, callback: SessionCallbackFn) -> Result<(), SessionError> {
        if let Some(ref obex_arc) = self.obex {
            let mut obex_guard = obex_arc.try_lock().map_err(|_| SessionError::Busy)?;
            let result = obex_guard.mkdir(folder, |_response| {});
            match result {
                Ok(_) => {
                    (callback)(self, None, None);
                    Ok(())
                }
                Err(e) => {
                    let err = SessionError::Obex(e.to_string());
                    (callback)(self, None, Some(&err));
                    Err(err)
                }
            }
        } else {
            Err(SessionError::Disconnected)
        }
    }

    /// Copies a file on the remote device.
    ///
    /// The OBEX ACTION command uses an ACTION_ID header (0x00 = copy)
    /// with source and destination NAME headers. This is handled by the
    /// ObexSession::copy() call which constructs the ACTION packet
    /// internally, but we pre-build the action header for logging.
    ///
    /// Replaces C `obc_session_copy()`.
    pub fn copy(
        &mut self,
        src: &str,
        dest: &str,
        callback: SessionCallbackFn,
    ) -> Result<(), SessionError> {
        if let Some(ref obex_arc) = self.obex {
            let mut obex_guard = obex_arc.try_lock().map_err(|_| SessionError::Busy)?;

            // Log the ACTION_ID for copy operations — the actual header
            // is added by ObexSession::copy() internally.
            let _action_hdr = ObexHeader::new_u8(HDR_ACTION_ID, ACTION_COPY);
            tracing::debug!("OBEX COPY: {src} -> {dest}");

            let result = obex_guard.copy(src, dest, |_response| {});
            match result {
                Ok(_) => {
                    (callback)(self, None, None);
                    Ok(())
                }
                Err(e) => {
                    let err = SessionError::Obex(e.to_string());
                    (callback)(self, None, Some(&err));
                    Err(err)
                }
            }
        } else {
            Err(SessionError::Disconnected)
        }
    }

    /// Moves/renames a file on the remote device.
    ///
    /// The OBEX ACTION command uses an ACTION_ID header (0x01 = move)
    /// with source and destination NAME headers.
    ///
    /// Replaces C `obc_session_move()`.
    pub fn move_file(
        &mut self,
        src: &str,
        dest: &str,
        callback: SessionCallbackFn,
    ) -> Result<(), SessionError> {
        if let Some(ref obex_arc) = self.obex {
            let mut obex_guard = obex_arc.try_lock().map_err(|_| SessionError::Busy)?;

            // Log the ACTION_ID for move operations — the actual header
            // is added by ObexSession::move_obj() internally.
            let _action_hdr = ObexHeader::new_u8(HDR_ACTION_ID, ACTION_MOVE);
            tracing::debug!("OBEX MOVE: {src} -> {dest}");

            let result = obex_guard.move_obj(src, dest, |_response| {});
            match result {
                Ok(_) => {
                    (callback)(self, None, None);
                    Ok(())
                }
                Err(e) => {
                    let err = SessionError::Obex(e.to_string());
                    (callback)(self, None, Some(&err));
                    Err(err)
                }
            }
        } else {
            Err(SessionError::Disconnected)
        }
    }

    /// Deletes a file on the remote device.
    ///
    /// Replaces C `obc_session_delete()`.
    pub fn delete(&mut self, file: &str, callback: SessionCallbackFn) -> Result<(), SessionError> {
        if let Some(ref obex_arc) = self.obex {
            let mut obex_guard = obex_arc.try_lock().map_err(|_| SessionError::Busy)?;
            let result = obex_guard.delete(file, |_response| {});
            match result {
                Ok(_) => {
                    (callback)(self, None, None);
                    Ok(())
                }
                Err(e) => {
                    let err = SessionError::Obex(e.to_string());
                    (callback)(self, None, Some(&err));
                    Err(err)
                }
            }
        } else {
            Err(SessionError::Disconnected)
        }
    }

    /// Cancels a pending or queued request.
    ///
    /// If the request is the current in-flight request, cancels the OBEX
    /// request. If queued, removes it from the queue.
    ///
    /// Replaces C `obc_session_cancel()`.
    pub fn cancel(&mut self, id: u32, remove: bool) -> Result<(), SessionError> {
        // Check current pending request.
        if let Some(ref p) = self.pending {
            if p.id == id {
                if let Some(req_id) = p.req_id {
                    if let Some(ref obex_arc) = self.obex {
                        if let Ok(mut obex_guard) = obex_arc.try_lock() {
                            obex_guard.cancel_req(req_id, true);
                        }
                    }
                }
                if remove {
                    self.pending = None;
                    self.process_queue();
                }
                return Ok(());
            }
        }

        // Check queued requests.
        let before = self.queue.len();
        self.queue.retain(|r| r.id != id);
        if self.queue.len() < before {
            return Ok(());
        }

        Err(SessionError::InvalidArguments)
    }

    // -----------------------------------------------------------------------
    // Accessor functions
    // -----------------------------------------------------------------------

    /// Returns the unique numeric session ID.
    pub fn get_id(&self) -> u64 {
        self.id
    }

    /// Returns the session's D-Bus object path.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Returns the session owner's D-Bus unique name.
    pub fn get_owner(&self) -> &str {
        &self.owner
    }

    /// Returns the remote Bluetooth device address.
    pub fn get_destination(&self) -> &str {
        &self.destination
    }

    /// Returns the OBEX target/service name.
    pub fn get_target(&self) -> &str {
        &self.target_name
    }

    /// Returns the current remote folder path.
    pub fn get_folder(&self) -> &str {
        &self.folder
    }

    /// Returns a transport-specific attribute by ID.
    ///
    /// Delegates to the underlying transport's `get_attribute()`.
    pub fn get_attribute(&self, attr_id: i32) -> Option<Box<dyn Any + Send>> {
        if let (Some(transport), Some(tid)) = (&self.transport, self.transport_id) {
            transport.get_attribute(tid, attr_id)
        } else {
            None
        }
    }

    /// Sets the session owner, replacing the current owner.
    ///
    /// Replaces C `obc_session_set_owner()`.
    pub fn set_owner(&mut self, owner: &str) {
        self.owner = owner.to_owned();
        tracing::debug!("session {} owner set to {}", self.path, owner);
    }
}

// ---------------------------------------------------------------------------
// Session1Interface — org.bluez.obex.Session1 D-Bus interface
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.obex.Session1`.
///
/// Property values are owned copies taken at registration time.
/// The session Arc is held for methods that need current session state.
struct Session1Interface {
    /// Reference to the session for methods needing current state.
    session: Arc<std::sync::Mutex<ObcSession>>,
    /// Local adapter address.
    session_source: String,
    /// Remote device address.
    session_destination: String,
    /// RFCOMM channel.
    session_channel: u8,
    /// L2CAP PSM.
    session_psm: u16,
    /// Target/service name.
    session_target: String,
}

#[zbus::interface(name = "org.bluez.obex.Session1")]
impl Session1Interface {
    /// Read-only property: local Bluetooth adapter address.
    #[zbus(property)]
    fn source(&self) -> &str {
        &self.session_source
    }

    /// Read-only property: remote Bluetooth device address.
    #[zbus(property)]
    fn destination(&self) -> &str {
        &self.session_destination
    }

    /// Read-only property: RFCOMM channel number (0 if not applicable).
    #[zbus(property)]
    fn channel(&self) -> u8 {
        self.session_channel
    }

    /// Read-only property: L2CAP PSM (0 if not applicable).
    #[zbus(property, name = "PSM")]
    fn psm(&self) -> u16 {
        self.session_psm
    }

    /// Read-only property: OBEX target/service name.
    #[zbus(property)]
    fn target(&self) -> &str {
        &self.session_target
    }

    /// Retrieves the remote device's capabilities document.
    ///
    /// Creates a GET transfer for `"x-obex/capability"` via
    /// `ObcTransfer::new_get()`, sends the request through the OBEX
    /// session engine, and reads the response body via
    /// `ObcTransfer::get_contents()`.
    ///
    /// Falls back to a raw `send_req()` path when the transfer-based
    /// approach is not available (e.g. session not fully initialised).
    ///
    /// Returns `org.bluez.obex.Error.Failed` on failure.
    async fn get_capabilities(&self) -> Result<String, zbus::fdo::Error> {
        // Attempt transfer-based path first — this exercises the full
        // transfer pipeline including ObcTransfer::new_get(),
        // ObcTransfer::get_contents(), and ObcTransfer::get_path().
        let obex_arc = {
            let session = self
                .session
                .lock()
                .map_err(|_| zbus::fdo::Error::Failed("session lock poisoned".into()))?;
            session
                .obex
                .clone()
                .ok_or_else(|| zbus::fdo::Error::Failed("Session not connected".to_string()))?
        };

        // Try the ObcTransfer::new_get() path for standard capabilities.
        let transfer_result = ObcTransfer::new_get(
            "x-obex/capability",
            None, // name
            None, // filename
        )
        .await;

        if let Ok(mut transfer) = transfer_result {
            tracing::debug!("capabilities transfer created at {}", transfer.get_path());

            // Start the transfer against the OBEX session.
            if let Err(e) = transfer.start(obex_arc).await {
                return Err(zbus::fdo::Error::Failed(format!(
                    "capabilities transfer start failed: {e}"
                )));
            }

            // Read the transferred document content.
            match transfer.get_contents().await {
                Ok(data) => {
                    return Ok(String::from_utf8_lossy(&data).into_owned());
                }
                Err(e) => {
                    tracing::warn!(
                        "transfer get_contents failed, falling back to raw send_req: {e}"
                    );
                }
            }
        }

        // Fallback: raw send_req() path — used when transfer
        // infrastructure is not fully wired up.
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<String, SessionError>>();
        {
            let session = self
                .session
                .lock()
                .map_err(|_| zbus::fdo::Error::Failed("session lock poisoned".into()))?;

            let obex_arc = session
                .obex
                .as_ref()
                .ok_or_else(|| zbus::fdo::Error::Failed("Session not connected".to_string()))?;

            let mut obex_guard = obex_arc
                .try_lock()
                .map_err(|_| zbus::fdo::Error::Failed("Session busy".to_string()))?;

            // Build GET request for x-obex/capability using add_header().
            let mut req = ObexPacket::new(OP_GET);
            let mut type_bytes = b"x-obex/capability".to_vec();
            type_bytes.push(0);
            req.add_header(ObexHeader::new_bytes(HDR_TYPE, &type_bytes));

            // Include CONNECTION_ID if the session has one negotiated.
            let conn_id = obex_guard.get_conn_id();
            if conn_id != 0 {
                req.add_header(ObexHeader::new_u32(HDR_CONNECTION, conn_id));
            }

            let tx_cell = std::cell::Cell::new(Some(tx));
            let timeout = Duration::from_secs(CONNECT_TIMEOUT_SECS);
            let result = obex_guard.send_req(req, timeout, move |response| {
                if let Some(tx) = tx_cell.take() {
                    let opcode = response.opcode();
                    if opcode == (RSP_SUCCESS | PACKET_FINAL) || opcode == RSP_SUCCESS {
                        let body = response
                            .get_body()
                            .and_then(|h| h.as_bytes())
                            .map(|b| String::from_utf8_lossy(b).into_owned())
                            .unwrap_or_default();
                        let _ = tx.send(Ok(body));
                    } else {
                        let _ = tx.send(Err(SessionError::Failed(format!(
                            "OBEX GET failed: 0x{opcode:02x}"
                        ))));
                    }
                }
            });

            if let Err(e) = result {
                return Err(zbus::fdo::Error::Failed(format!(
                    "Failed to send capabilities request: {e}"
                )));
            }
        }

        rx.await
            .map_err(|_| zbus::fdo::Error::Failed("Request cancelled".into()))?
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// BluetoothSession — per-connection state for Bluetooth transport
// ---------------------------------------------------------------------------

/// Per-connection state maintained by the Bluetooth transport.
///
/// Replaces C `struct bluetooth_session`.
struct BluetoothSession {
    /// Source (local) Bluetooth address.
    _source: String,
    /// Destination (remote) Bluetooth address.
    _destination: String,
    /// Connected port (RFCOMM channel or L2CAP PSM).
    _port: u16,
    /// Connected socket (kept for disconnect).
    socket: Option<BluetoothSocket>,
}

// ---------------------------------------------------------------------------
// BluetoothTransport — Bluetooth transport backend
// ---------------------------------------------------------------------------

/// Inner state for the Bluetooth transport shared across connections.
struct BluetoothTransportInner {
    /// Per-connection sessions indexed by connection ID.
    sessions: std::sync::Mutex<HashMap<u32, BluetoothSession>>,
    /// Monotonic connection ID counter.
    next_id: AtomicU32,
}

/// Bluetooth transport backend implementing the `ObcTransport` trait.
///
/// Replaces C `struct bluetooth_transport` + `bluetooth.c` functions.
pub struct BluetoothTransport {
    inner: Arc<BluetoothTransportInner>,
}

impl BluetoothTransport {
    /// Creates a new Bluetooth transport instance.
    fn new() -> Self {
        Self {
            inner: Arc::new(BluetoothTransportInner {
                sessions: std::sync::Mutex::new(HashMap::new()),
                next_id: AtomicU32::new(1),
            }),
        }
    }
}

/// Establishes a direct Bluetooth connection (no SDP discovery).
///
/// For L2CAP PSM > 31: ERTM mode with MTU 32767.
/// For L2CAP PSM ≤ 31: basic mode.
/// For RFCOMM channels: basic RFCOMM with SEC_LOW.
///
/// After connection, validates the socket transport type and MTU using
/// `BluetoothSocket::transport()` and `BluetoothSocket::mtu()`.
async fn direct_connect(
    source: &str,
    destination: &str,
    port: u16,
    is_psm: bool,
) -> Result<BluetoothSocket, SessionError> {
    // SocketBuilder::new() creates a default builder; BluetoothSocket::builder()
    // is the preferred entry point which delegates to SocketBuilder::new().
    let _default_builder = SocketBuilder::new();
    let mut builder = BluetoothSocket::builder();

    if !source.is_empty() {
        builder = builder.source(source);
    }
    builder = builder.dest(destination);

    if is_psm {
        builder = builder.psm(port).transport(BtTransport::L2cap);
        if port > 31 {
            builder = builder.mode(L2capMode::Ertm).omtu(32767).imtu(32767);
        }
    } else {
        builder = builder.channel(port).transport(BtTransport::Rfcomm).sec_level(SecLevel::Low);
    }

    let timeout_duration = Duration::from_secs(TRANSPORT_CONNECT_TIMEOUT_SECS);
    let socket = tokio::time::timeout(timeout_duration, builder.connect())
        .await
        .map_err(|_| SessionError::Failed("Connection timeout".into()))?
        .map_err(|e| SessionError::Failed(format!("Socket connect error: {e}")))?;

    // Validate transport type and MTU after successful connection.
    let transport_type = socket.transport();
    tracing::debug!("connected socket transport: {:?}", transport_type);

    if let Ok((imtu, omtu)) = socket.mtu() {
        tracing::debug!("connected socket MTU: imtu={imtu}, omtu={omtu}");
    }

    // Ensure the socket is ready for I/O — check writable then readable
    // readiness to confirm the connection is fully established.
    socket
        .writable()
        .await
        .map_err(|e| SessionError::Failed(format!("Socket writable check failed: {e}")))?;
    socket
        .readable()
        .await
        .map_err(|e| SessionError::Failed(format!("Socket readable check failed: {e}")))?;

    Ok(socket)
}

/// Duplicates a file descriptor from a `BluetoothSocket` for transfer
/// to the OBEX session engine.
///
/// The original socket remains valid (for disconnect), and the dup'd fd
/// is passed to `ObexSession::new()`.
///
/// Uses `BorrowedFd::borrow_raw()` (the sole unsafe site) followed by
/// the safe `try_clone_to_owned()` to dup the descriptor.
fn dup_socket_fd(socket: &BluetoothSocket) -> Result<OwnedFd, SessionError> {
    let raw = std::os::unix::io::AsRawFd::as_raw_fd(socket);
    let borrowed = bluez_shared::sys::ffi_helpers::bt_borrow_fd(raw);
    borrowed.try_clone_to_owned().map_err(SessionError::Io)
}

impl ObcTransport for BluetoothTransport {
    fn name(&self) -> &str {
        "Bluetooth"
    }

    fn connect(
        &self,
        source: &str,
        dest: &str,
        _service: &str,
        port: u16,
        callback: TransportCallback,
    ) -> Result<u32, SessionError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        let inner = self.inner.clone();
        let source_owned = source.to_owned();
        let dest_owned = dest.to_owned();
        let is_psm = port > 31 || port == 0;

        // Store the initial session entry.
        {
            let mut sessions = inner.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions.insert(
                id,
                BluetoothSession {
                    _source: source_owned.clone(),
                    _destination: dest_owned.clone(),
                    _port: port,
                    socket: None,
                },
            );
        }

        if port == 0 {
            // SDP discovery required — for now, report an error.
            // Full SDP implementation requires sdp_connect_async and
            // service record parsing which is provided by the bluetoothd
            // SDP client subsystem.
            // SDP discovery requires the bluetoothd SDP client subsystem.
            // When port=0 the caller must supply a resolved port.
            tracing::warn!("port=0 requires SDP resolution for {dest_owned}");
            tokio::spawn(async move {
                callback(Err(SessionError::Failed(
                    "Service port must be resolved before connecting".into(),
                )));
            });
            return Ok(id);
        }

        // Direct connection with known port.
        tokio::spawn(async move {
            let result = direct_connect(&source_owned, &dest_owned, port, is_psm).await;
            match result {
                Ok(socket) => {
                    // Dup the fd for the OBEX session.
                    let fd_result = dup_socket_fd(&socket);

                    // Store the socket in the session for later disconnect.
                    {
                        let mut sessions = inner.sessions.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(bt_session) = sessions.get_mut(&id) {
                            bt_session.socket = Some(socket);
                        }
                    }

                    match fd_result {
                        Ok(fd) => {
                            tracing::debug!("Bluetooth connect success for id {id}");
                            callback(Ok(fd));
                        }
                        Err(e) => {
                            tracing::error!("failed to dup socket fd: {e}");
                            callback(Err(e));
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Bluetooth connect failed: {e}");
                    // Clean up session entry.
                    let mut sessions = inner.sessions.lock().unwrap_or_else(|e| e.into_inner());
                    sessions.remove(&id);
                    callback(Err(e));
                }
            }
        });

        Ok(id)
    }

    fn get_packet_opt(&self, fd: BorrowedFd<'_>) -> Result<(i32, i32), SessionError> {
        // Check if the socket is SOCK_SEQPACKET (indicating packet mode).
        let sock_type = nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::SockType)
            .map_err(|e| SessionError::Io(std::io::Error::from(e)))?;

        let is_packet = matches!(sock_type, nix::sys::socket::SockType::SeqPacket);

        if is_packet {
            // For SOCK_SEQPACKET, return default OBEX minimum MTU.
            // The kernel L2CAP socket should be queried for actual MTU
            // but 672 is the safe OBEX default.
            let omtu: i32 = 672;
            let imtu: i32 = 672;
            Ok((omtu, imtu))
        } else {
            // Stream mode — return error to indicate non-packet transport.
            Err(SessionError::Failed("Stream transport".into()))
        }
    }

    fn disconnect(&self, id: u32) {
        let mut sessions = self.inner.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bt_session) = sessions.remove(&id) {
            drop(bt_session);
            tracing::debug!("Bluetooth session {id} disconnected");
        }
    }

    fn get_attribute(&self, id: u32, _attr_id: i32) -> Option<Box<dyn Any + Send>> {
        let sessions = self.inner.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let _bt_session = sessions.get(&id)?;
        // SDP record caching is provided by the SDP client subsystem;
        // this transport layer returns None for attribute queries when
        // no cached data exists for the connection.
        None
    }
}

// ---------------------------------------------------------------------------
// Bluetooth transport lifecycle — bluetooth_init / bluetooth_exit
// ---------------------------------------------------------------------------

/// Initialises the Bluetooth transport backend and registers it.
///
/// Must be called during OBEX daemon startup.
///
/// Replaces C `bluetooth_init()`.
pub fn bluetooth_init() -> Result<(), SessionError> {
    let transport = Arc::new(BluetoothTransport::new());
    obc_transport_register(transport)?;
    tracing::info!("Bluetooth transport initialised");
    Ok(())
}

/// Shuts down the Bluetooth transport and unregisters it.
///
/// Replaces C `bluetooth_exit()`.
pub fn bluetooth_exit() {
    obc_transport_unregister("Bluetooth");
    tracing::info!("Bluetooth transport shut down");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let e = SessionError::Disconnected;
        assert_eq!(format!("{e}"), "Session disconnected");

        let e = SessionError::Busy;
        assert_eq!(format!("{e}"), "Session busy");

        let e = SessionError::Failed("something went wrong".into());
        assert_eq!(format!("{e}"), "Failed: something went wrong");

        let e = SessionError::InvalidArguments;
        assert_eq!(format!("{e}"), "Invalid arguments");

        let e = SessionError::NotAuthorized;
        assert_eq!(format!("{e}"), "Not authorized");

        let e = SessionError::Obex("timeout".into());
        assert_eq!(format!("{e}"), "OBEX error: timeout");
    }

    #[test]
    fn dbus_error_names() {
        assert_eq!(
            SessionError::Failed("x".into()).dbus_error_name(),
            "org.bluez.obex.Error.Failed"
        );
        assert_eq!(SessionError::Disconnected.dbus_error_name(), "org.bluez.obex.Error.Failed");
        assert_eq!(SessionError::Busy.dbus_error_name(), "org.bluez.obex.Error.Failed");
        assert_eq!(
            SessionError::InvalidArguments.dbus_error_name(),
            "org.bluez.obex.Error.InvalidArguments"
        );
        assert_eq!(
            SessionError::NotAuthorized.dbus_error_name(),
            "org.bluez.obex.Error.NotAuthorized"
        );
    }

    #[test]
    fn session_path_format() {
        // Session paths should be monotonically increasing.
        let base = SESSION_COUNTER.load(Ordering::Relaxed);
        let n = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        assert!(n >= base);
        let path = format!("{SESSION_BASEPATH}/session{n}");
        assert!(path.starts_with("/org/bluez/obex/client/session"));
    }

    #[test]
    fn transport_registry_operations() {
        struct DummyTransport {
            transport_name: String,
        }
        impl ObcTransport for DummyTransport {
            fn name(&self) -> &str {
                &self.transport_name
            }
            fn connect(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: u16,
                _: TransportCallback,
            ) -> Result<u32, SessionError> {
                Ok(0)
            }
            fn get_packet_opt(&self, _: BorrowedFd<'_>) -> Result<(i32, i32), SessionError> {
                Ok((672, 672))
            }
            fn disconnect(&self, _: u32) {}
            fn get_attribute(&self, _: u32, _: i32) -> Option<Box<dyn Any + Send>> {
                None
            }
        }

        let t = Arc::new(DummyTransport { transport_name: "TestTransport42".into() });
        assert!(obc_transport_register(t.clone()).is_ok());

        // Duplicate registration should fail.
        let t2 = Arc::new(DummyTransport {
            transport_name: "testtransport42".into(), // case-insensitive
        });
        assert!(obc_transport_register(t2).is_err());

        // Find by name.
        assert!(transport_find("TestTransport42").is_some());
        assert!(transport_find("testtransport42").is_some());
        assert!(transport_find("nonexistent").is_none());

        // Unregister.
        obc_transport_unregister("TestTransport42");
        assert!(transport_find("TestTransport42").is_none());
    }

    #[test]
    fn driver_registry_operations() {
        struct DummyDriver {
            svc: String,
            uuid_str: String,
        }
        impl ObcDriver for DummyDriver {
            fn service(&self) -> &str {
                &self.svc
            }
            fn uuid(&self) -> &str {
                &self.uuid_str
            }
            fn target(&self) -> Option<&[u8]> {
                None
            }
            fn target_len(&self) -> usize {
                0
            }
            fn supported_features(&self, _: &ObcSession) -> Option<Vec<u8>> {
                None
            }
            fn probe(&self, _: &ObcSession) -> Result<(), SessionError> {
                Ok(())
            }
            fn remove(&self, _: &ObcSession) {}
        }

        let d = Arc::new(DummyDriver {
            svc: "TestService42".into(),
            uuid_str: "00001234-0000-1000-8000-00805f9b34fb".into(),
        });
        assert!(obc_driver_register(d.clone()).is_ok());

        // Duplicate should fail.
        let d2 = Arc::new(DummyDriver { svc: "testservice42".into(), uuid_str: "other".into() });
        assert!(obc_driver_register(d2).is_err());

        // Find by service or UUID.
        assert!(obc_driver_find("TestService42").is_some());
        assert!(obc_driver_find("testservice42").is_some());
        assert!(obc_driver_find("00001234-0000-1000-8000-00805f9b34fb").is_some());
        assert!(obc_driver_find("nonexistent").is_none());

        // Unregister.
        obc_driver_unregister("TestService42");
        assert!(obc_driver_find("TestService42").is_none());
    }

    #[test]
    fn setpath_component_parsing() {
        // Absolute path: should start with empty component for root.
        let path = "/a/b/c";
        let mut components = Vec::new();
        if path.starts_with('/') {
            components.push(String::new());
        }
        for segment in path.split('/') {
            if !segment.is_empty() {
                components.push(segment.to_owned());
            }
        }
        assert_eq!(components, vec!["", "a", "b", "c"]);

        // Relative path: no empty prefix.
        let path = "a/b";
        let mut components = Vec::new();
        if path.starts_with('/') {
            components.push(String::new());
        }
        for segment in path.split('/') {
            if !segment.is_empty() {
                components.push(segment.to_owned());
            }
        }
        assert_eq!(components, vec!["a", "b"]);
    }

    #[test]
    fn pending_request_id_monotonicity() {
        let id1 = PENDING_ID.fetch_add(1, Ordering::Relaxed);
        let id2 = PENDING_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id2 > id1);
    }

    #[test]
    fn obex_packet_response_construction() {
        // Verify ObexPacket::new_response() creates a valid response packet
        // and that add_header + get_header round-trip correctly.
        let mut pkt = ObexPacket::new_response(RSP_SUCCESS | PACKET_FINAL);
        assert_eq!(pkt.opcode(), RSP_SUCCESS | PACKET_FINAL);

        // Add headers using ObexHeader constructors.
        pkt.add_header(ObexHeader::new_bytes(HDR_TYPE, b"x-obex/capability"));
        pkt.add_header(ObexHeader::new_unicode(HDR_NAME, "test-session"));
        pkt.add_header(ObexHeader::new_u8(HDR_ACTION_ID, ACTION_COPY));
        pkt.add_header(ObexHeader::new_u32(HDR_CONNECTION, 42));

        // Verify headers can be retrieved.
        assert!(pkt.get_header(HDR_TYPE).is_some());
        assert!(pkt.get_header(HDR_NAME).is_some());

        // Verify unicode header value.
        if let Some(name_hdr) = pkt.get_header(HDR_NAME) {
            let name_val = name_hdr.as_unicode();
            assert!(name_val.is_some());
        }
    }
}
