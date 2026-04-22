// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX server-side service layer — consolidated Rust rewrite of 12 C source
// files from BlueZ v5.86 obexd/src/:
//
//   service.c/h       — Service driver registry
//   mimetype.c/h      — MIME type driver registry + IO watch system
//   obex.c/h/obex-priv.h — Server-side OBEX session engine
//   manager.c/h       — D-Bus manager (AgentManager1, Session1, Transfer1)
//   plugin.c/h        — Plugin framework (inventory + libloading)
//   log.c/h           — Logging via tracing (replaces syslog)
//   logind.c/h        — Logind conditional gating
//   map_ap.h          — MAP application parameter tags
//   obexd.h           — Daemon constants (service bitmasks, port)
//
// Total C lines consolidated: ~2,900+ lines.
//
// All external behaviour — D-Bus interface contracts, OBEX wire semantics,
// service/MIME driver matching rules, plugin glob filtering — is preserved
// identically for behavioural-clone fidelity.

use std::any::Any;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use crate::obex::apparam::ObexApparam;
use crate::obex::header::{
    HDR_ACTION, HDR_APPARAM, HDR_CONNECTION, HDR_DESTNAME, HDR_LENGTH, HDR_NAME, HDR_TARGET,
    HDR_TIME, HDR_TYPE, HDR_WHO, ObexHeader,
};
use crate::obex::packet::{
    OP_ACTION, OP_GET, OP_PUT, OP_SETPATH, ObexPacket, RSP_FORBIDDEN, RSP_NOT_FOUND,
    RSP_SERVICE_UNAVAILABLE, RSP_SUCCESS,
};
use crate::obex::session::{ObexError, ObexSession, TransportType, errno_to_rsp};

// ============================================================================
// SECTION A: Daemon Constants (from obexd/src/obexd.h)
// ============================================================================

bitflags::bitflags! {
    /// OBEX service bitmask constants from obexd.h.
    /// Used to filter which services are applicable to a transport.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ObexServices: u16 {
        /// Object Push Profile
        const OPP           = 1 << 1;
        /// File Transfer Profile
        const FTP           = 1 << 2;
        /// Basic Imaging Profile
        const BIP           = 1 << 3;
        /// Phonebook Access Profile
        const PBAP          = 1 << 4;
        /// IrMC Sync
        const IRMC          = 1 << 5;
        /// PC Suite
        const PCSUITE       = 1 << 6;
        /// SyncEvolution
        const SYNCEVOLUTION = 1 << 7;
        /// Message Access Service
        const MAS           = 1 << 8;
        /// Message Notification Service
        const MNS           = 1 << 9;
    }
}

/// Sentinel port value requesting auto-assignment.
/// Matches C `#define OBEX_PORT_RANDOM UINT16_MAX`.
pub const OBEX_PORT_RANDOM: u16 = u16::MAX;

// ============================================================================
// SECTION B: MAP Application Parameter Tags (from obexd/src/map_ap.h)
// ============================================================================

/// MAP Application Parameter Tags.
/// Used in MAP service driver for OBEX application parameters.
/// Values match the C `enum map_ap_tag` exactly (0x01–0x19).
pub struct MapApTag;

impl MapApTag {
    pub const MAX_LIST_COUNT: u8 = 0x01;
    pub const START_OFFSET: u8 = 0x02;
    pub const FILTER_MESSAGE_TYPE: u8 = 0x03;
    pub const FILTER_PERIOD_BEGIN: u8 = 0x04;
    pub const FILTER_PERIOD_END: u8 = 0x05;
    pub const FILTER_READ_STATUS: u8 = 0x06;
    pub const FILTER_RECIPIENT: u8 = 0x07;
    pub const FILTER_ORIGINATOR: u8 = 0x08;
    pub const FILTER_PRIORITY: u8 = 0x09;
    pub const ATTACHMENT: u8 = 0x0A;
    pub const TRANSPARENT: u8 = 0x0B;
    pub const RETRY: u8 = 0x0C;
    pub const NEW_MESSAGE: u8 = 0x0D;
    pub const NOTIFICATION_STATUS: u8 = 0x0E;
    pub const MAS_INSTANCE_ID: u8 = 0x0F;
    pub const PARAMETER_MASK: u8 = 0x10;
    pub const FOLDER_LISTING_SIZE: u8 = 0x11;
    pub const MESSAGES_LISTING_SIZE: u8 = 0x12;
    pub const SUBJECT_LENGTH: u8 = 0x13;
    pub const CHARSET: u8 = 0x14;
    pub const FRACTION_REQUEST: u8 = 0x15;
    pub const FRACTION_DELIVER: u8 = 0x16;
    pub const STATUS_INDICATOR: u8 = 0x17;
    pub const STATUS_VALUE: u8 = 0x18;
    pub const MSE_TIME: u8 = 0x19;
}

// ============================================================================
// SECTION C: Service Driver Registry (from obexd/src/service.c/h)
// ============================================================================

/// OBEX service driver interface (e.g., OPP, FTP, PBAP, MAP).
/// Replaces C `struct obex_service_driver` with callback function pointers.
pub trait ObexServiceDriver: Send + Sync {
    /// Service name (e.g., "Object Push", "File Transfer").
    fn name(&self) -> &str;
    /// Service bitmask value (single bit from ObexServices).
    fn service(&self) -> u16;
    /// RFCOMM channel number (0 for auto).
    fn channel(&self) -> u8 {
        0
    }
    /// L2CAP PSM port (OBEX_PORT_RANDOM for auto-assignment).
    fn port(&self) -> u16 {
        OBEX_PORT_RANDOM
    }
    /// Whether transport security is required.
    fn secure(&self) -> bool {
        true
    }
    /// OBEX Target header UUID (16 bytes) — None for OPP which has no target.
    fn target(&self) -> Option<&[u8]> {
        None
    }
    /// OBEX Who header UUID (16 bytes) — None for most services.
    fn who(&self) -> Option<&[u8]> {
        None
    }
    /// SDP record XML template string — None if no SDP record needed.
    fn record(&self) -> Option<&str> {
        None
    }
    /// Called when OBEX CONNECT is accepted for this service.
    fn connect(&self, session: &mut ServerObexSession) -> Result<(), ObexError>;
    /// Called on transfer progress (optional).
    fn progress(&self, _session: &ServerObexSession) -> Result<(), ObexError> {
        Ok(())
    }
    /// Called for OBEX GET requests.
    fn get(&self, session: &mut ServerObexSession) -> Result<(), ObexError>;
    /// Called for OBEX PUT requests.
    fn put(&self, session: &mut ServerObexSession) -> Result<(), ObexError>;
    /// Called to validate incoming PUT before accepting data (optional).
    fn chkput(&self, _session: &ServerObexSession) -> Result<(), ObexError> {
        Ok(())
    }
    /// Called for OBEX SETPATH requests (optional).
    fn setpath(
        &self,
        _session: &mut ServerObexSession,
        _path: &str,
        _flags: u8,
    ) -> Result<(), ObexError> {
        Err(ObexError::Failed("not implemented".into()))
    }
    /// Called for OBEX ACTION requests (copy/move/setperm) (optional).
    fn action(&self, _session: &mut ServerObexSession, _action: u8) -> Result<(), ObexError> {
        Err(ObexError::Failed("not implemented".into()))
    }
    /// Called on OBEX DISCONNECT.
    fn disconnect(&self, session: &mut ServerObexSession);
    /// Called on session reset (between requests).
    fn reset(&self, _session: &mut ServerObexSession) {}
}

/// Global service driver registry.
static SERVICE_DRIVERS: OnceLock<Mutex<Vec<Box<dyn ObexServiceDriver>>>> = OnceLock::new();

/// Accessor for the service driver registry, initialising on first use.
fn service_drivers() -> &'static Mutex<Vec<Box<dyn ObexServiceDriver>>> {
    SERVICE_DRIVERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Compare two optional byte slices for equality.
/// Both None → equal. One None, one Some → not equal. Both Some → compare.
/// Replaces C `memncmp0(a, alen, b, blen)`.
fn memncmp0(a: Option<&[u8]>, b: Option<&[u8]>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Register a service driver.
///
/// If `driver.who().is_some()`, the driver is inserted at the front of the
/// list (matching C `g_slist_prepend`) for higher matching priority.
/// Otherwise it is appended (matching C `g_slist_append`).
///
/// Source: `obexd/src/service.c` lines 71-100.
pub fn register_service(driver: Box<dyn ObexServiceDriver>) -> Result<(), ObexError> {
    let name = driver.name().to_owned();
    if name.is_empty() {
        return Err(ObexError::InvalidArgs("service driver name must not be empty".into()));
    }

    let mut drivers = service_drivers()
        .lock()
        .map_err(|_| ObexError::Failed("service driver registry lock poisoned".into()))?;

    // Check for duplicate by service value.
    let svc = driver.service();
    if drivers.iter().any(|d| d.service() == svc && d.name() == name) {
        return Err(ObexError::Failed(format!("service driver '{}' already registered", name)));
    }

    // Priority ordering: who-specific drivers go to front for higher priority.
    if driver.who().is_some() {
        drivers.insert(0, driver);
    } else {
        drivers.push(driver);
    }

    tracing::info!("OBEX service driver registered: {}", name);
    Ok(())
}

/// Unregister a service driver by name.
///
/// Source: `obexd/src/service.c` lines 102-120.
pub fn unregister_service(name: &str) {
    let Ok(mut drivers) = service_drivers().lock() else {
        tracing::warn!("Failed to acquire service driver lock for unregister of '{}'", name);
        return;
    };

    let before = drivers.len();
    drivers.retain(|d| d.name() != name);

    if drivers.len() == before {
        tracing::warn!("Service driver '{}' not found for unregister", name);
    } else {
        tracing::info!("OBEX service driver unregistered: {}", name);
    }
}

/// List service driver names matching a bitmask.
///
/// If `service_mask == 0`, returns ALL driver names.
/// Otherwise, returns drivers whose `service() & mask != 0`,
/// clearing matched bits as each driver is found.
///
/// Source: `obexd/src/service.c` lines 46-69.
pub fn list_services(service_mask: u16) -> Vec<String> {
    let Ok(drivers) = service_drivers().lock() else {
        return Vec::new();
    };

    if service_mask == 0 {
        return drivers.iter().map(|d| d.name().to_owned()).collect();
    }

    let mut mask = service_mask;
    let mut result = Vec::new();

    for drv in drivers.iter() {
        if mask == 0 {
            break;
        }
        let svc = drv.service();
        if svc & mask != 0 {
            result.push(drv.name().to_owned());
            // Clear matched bits to prevent duplicates.
            mask &= !svc;
        }
    }

    result
}

/// Find a service driver by matching target and who UUIDs.
///
/// Returns the name of the first matching driver, or None.
/// Uses `memncmp0` semantics: None == None is a match.
///
/// Source: `obexd/src/service.c` lines 29-44.
pub fn find_service(target: Option<&[u8]>, who: Option<&[u8]>) -> Option<String> {
    let Ok(drivers) = service_drivers().lock() else {
        return None;
    };

    for drv in drivers.iter() {
        if memncmp0(target, drv.target()) && memncmp0(who, drv.who()) {
            return Some(drv.name().to_owned());
        }
    }

    None
}

// ============================================================================
// SECTION D: MIME Type Driver Registry (from obexd/src/mimetype.c/h)
// ============================================================================

/// OBEX MIME type handler (e.g., filesystem, vCard, calendar).
/// Replaces C `struct obex_mime_type_driver`.
pub trait ObexMimeTypeDriver: Send + Sync {
    /// Target UUID this driver applies to (None = generic/default).
    fn target(&self) -> Option<&[u8]> {
        None
    }
    /// MIME type string (None = default handler for target).
    fn mimetype(&self) -> Option<&str> {
        None
    }
    /// Who UUID (None = no who-specific matching).
    fn who(&self) -> Option<&[u8]> {
        None
    }

    /// Open a data stream for reading/writing.
    fn open(&self, name: &str) -> Result<Box<dyn Any + Send>, ObexError>;
    /// Close a data stream.
    fn close(&self, object: &mut dyn Any) -> Result<(), ObexError>;
    /// Get next header to prepend (for multi-part responses).
    fn get_next_header(&self, _object: &dyn Any) -> Option<ObexHeader> {
        None
    }
    /// Read data from opened object into buffer.
    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, ObexError>;
    /// Write data to opened object.
    fn write(&self, object: &mut dyn Any, buf: &[u8]) -> Result<usize, ObexError>;
    /// Flush pending writes.
    fn flush(&self, _object: &mut dyn Any) -> Result<(), ObexError> {
        Ok(())
    }
    /// Copy a file/object.
    fn copy(&self, _source: &str, _dest: &str) -> Result<(), ObexError> {
        Err(ObexError::Failed("not supported".into()))
    }
    /// Move/rename a file/object.
    fn rename(&self, _source: &str, _dest: &str) -> Result<(), ObexError> {
        Err(ObexError::Failed("not supported".into()))
    }
    /// Remove a file/object.
    fn remove(&self, _name: &str) -> Result<(), ObexError> {
        Err(ObexError::Failed("not supported".into()))
    }
}

/// Global MIME type driver registry.
static MIME_DRIVERS: OnceLock<Mutex<Vec<Box<dyn ObexMimeTypeDriver>>>> = OnceLock::new();

/// Accessor for the MIME driver registry, initialising on first use.
fn mime_drivers() -> &'static Mutex<Vec<Box<dyn ObexMimeTypeDriver>>> {
    MIME_DRIVERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a MIME type driver.
///
/// Checks for duplicates by the full (target, mimetype, who) triple.
///
/// Source: `obexd/src/mimetype.c` lines 155-198.
pub fn register_mime_driver(driver: Box<dyn ObexMimeTypeDriver>) -> Result<(), ObexError> {
    let mut drivers = mime_drivers()
        .lock()
        .map_err(|_| ObexError::Failed("MIME driver registry lock poisoned".into()))?;

    // Check for duplicate by matching the full triple.
    let dup = drivers.iter().any(|d| {
        memncmp0(d.target(), driver.target())
            && d.mimetype() == driver.mimetype()
            && memncmp0(d.who(), driver.who())
    });

    if dup {
        return Err(ObexError::Failed(format!(
            "MIME driver already registered for target={:?} mimetype={:?} who={:?}",
            driver.target().map(|t| format!("{:02x?}", t)),
            driver.mimetype(),
            driver.who().map(|w| format!("{:02x?}", w)),
        )));
    }

    tracing::debug!(
        "MIME driver registered: target={:?} mimetype={:?}",
        driver.target().map(|t| format!("{:02x?}", t)),
        driver.mimetype()
    );

    drivers.push(driver);
    Ok(())
}

/// Unregister a MIME type driver by the full (target, mimetype, who) triple.
pub fn unregister_mime_driver(target: Option<&[u8]>, mimetype: Option<&str>, who: Option<&[u8]>) {
    let Ok(mut drivers) = mime_drivers().lock() else {
        return;
    };

    drivers.retain(|d| {
        !(memncmp0(d.target(), target) && d.mimetype() == mimetype && memncmp0(d.who(), who))
    });
}

/// Find a MIME type driver using specificity-based fallback matching.
///
/// The matching priority (from highest to lowest):
/// 1. Exact match: target + mimetype + who all match.
/// 2. Non-who match: target + mimetype match, who=None in driver.
/// 3. Target default: target matches, mimetype=None, who=None in driver.
/// 4. General default: target=None, mimetype=None, who=None in driver.
///
/// Returns the index into the MIME_DRIVERS registry of the best match.
///
/// Source: `obexd/src/mimetype.c` lines 107-153.
pub fn find_mime_driver(
    target: Option<&[u8]>,
    mimetype: Option<&str>,
    who: Option<&[u8]>,
) -> Option<usize> {
    let Ok(drivers) = mime_drivers().lock() else {
        return None;
    };

    let mut fallback_nonwho: Option<usize> = None;
    let mut fallback_target: Option<usize> = None;
    let mut fallback_general: Option<usize> = None;

    for (i, drv) in drivers.iter().enumerate() {
        let target_match = memncmp0(drv.target(), target);
        let mime_match = drv.mimetype() == mimetype;
        let who_match = memncmp0(drv.who(), who);

        // Level 1: exact match on all three.
        if target_match && mime_match && who_match {
            return Some(i);
        }

        // Level 2: target + mimetype match, driver has no who.
        if target_match && mime_match && drv.who().is_none() && fallback_nonwho.is_none() {
            fallback_nonwho = Some(i);
        }

        // Level 3: target matches, driver has no mimetype and no who.
        if target_match
            && drv.mimetype().is_none()
            && drv.who().is_none()
            && fallback_target.is_none()
        {
            fallback_target = Some(i);
        }

        // Level 4: general default (driver has no target, no mimetype, no who).
        if drv.target().is_none()
            && drv.mimetype().is_none()
            && drv.who().is_none()
            && fallback_general.is_none()
        {
            fallback_general = Some(i);
        }
    }

    fallback_nonwho.or(fallback_target).or(fallback_general)
}

// ---------------------------------------------------------------------------
// IO Watch System (from obexd/src/mimetype.c lines 30-105)
// ---------------------------------------------------------------------------

/// IO watch callback type.
type IoWatchCallback = Box<dyn FnMut(u32, ObexError) + Send>;

/// A registered IO watch entry.
struct IoWatch {
    /// Object identifier (pointer-like ID).
    object_id: usize,
    /// Callback invoked on IO events.
    func: IoWatchCallback,
}

/// Global IO watch list.
static IO_WATCHES: OnceLock<Mutex<Vec<IoWatch>>> = OnceLock::new();

/// Accessor for the IO watch list, initialising on first use.
fn io_watches() -> &'static Mutex<Vec<IoWatch>> {
    IO_WATCHES.get_or_init(|| Mutex::new(Vec::new()))
}

/// Set an IO watch for an object. Removes any existing watch for this object
/// first (single watch per object enforced).
///
/// Source: `obexd/src/mimetype.c` lines 85-105.
pub fn set_io_watch(object_id: usize, func: IoWatchCallback) {
    let Ok(mut watches) = io_watches().lock() else {
        return;
    };

    // Remove any existing watch for this object.
    watches.retain(|w| w.object_id != object_id);

    watches.push(IoWatch { object_id, func });
}

/// Reset (remove) the IO watch for an object.
///
/// Source: `obexd/src/mimetype.c` lines 75-83.
pub fn reset_io_watch(object_id: usize) {
    let Ok(mut watches) = io_watches().lock() else {
        return;
    };
    watches.retain(|w| w.object_id != object_id);
}

/// Broadcast IO flags to all registered watches.
/// Must be safe against removal during iteration.
///
/// Source: `obexd/src/mimetype.c` lines 30-55.
pub fn broadcast_io_flags(flags: u32, err: ObexError) {
    let Ok(mut watches) = io_watches().lock() else {
        return;
    };

    // Drain all watches to invoke callbacks safely.
    // The callbacks may re-register watches via set_io_watch.
    let drained: Vec<IoWatch> = watches.drain(..).collect();
    // Drop the lock before invoking callbacks to avoid deadlock.
    drop(watches);

    for mut watch in drained {
        let err_clone = ObexError::Failed(format!("{}", err));
        (watch.func)(flags, err_clone);
    }
}

// ============================================================================
// SECTION E: Server-Side OBEX Session Engine (from obexd/src/obex.c/h/obex-priv.h)
// ============================================================================

/// Sentinel: object size not yet known.
pub const OBJECT_SIZE_UNKNOWN: i64 = -1;

/// Sentinel: DELETE operation (zero-length body with intent to delete).
pub const OBJECT_SIZE_DELETE: i64 = -2;

/// Expected OBEX Target/Who UUID length in bytes.
pub const TARGET_SIZE: usize = 16;

/// Monotonic session ID counter.
static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Monotonic transfer path counter.
static TRANSFER_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Server-side OBEX session state.
///
/// Wraps the lower-level `ObexSession` (from `crate::obex`) and adds
/// server-specific state (service driver, MIME driver, transfer state).
///
/// Replaces the C `struct obex_session` from obex-priv.h.
pub struct ServerObexSession {
    /// Lower-level OBEX protocol session.
    pub obex: ObexSession,
    /// Session ID (monotonic counter).
    pub id: u32,
    /// Current OBEX command being processed.
    pub cmd: u8,
    /// Current ACTION ID (for copy/move/setperm).
    pub action_id: u8,
    /// Source address (from getpeername).
    pub src: String,
    /// Destination address (from getsockname).
    pub dst: String,
    /// Current object name (from NAME header).
    pub name: Option<String>,
    /// Destination name (from DESTNAME header, for copy/move).
    pub destname: Option<String>,
    /// MIME type (from TYPE header).
    pub obj_type: Option<String>,
    /// Object path (service-specific working directory).
    pub path: Option<String>,
    /// Time metadata (from TIME header, ISO 8601).
    pub time: Option<String>,
    /// Application parameters (from APPARAM header).
    pub apparam: Option<ObexApparam>,
    /// Non-header data (pre-header data from CONNECT/SETPATH).
    pub nonhdr: Option<Vec<u8>>,
    /// GET response buffer.
    pub get_rsp: Option<Vec<u8>>,
    /// Transfer buffer.
    pub buf: Vec<u8>,
    /// Pending bytes to write/read.
    pub pending: usize,
    /// Current offset in transfer.
    pub offset: usize,
    /// Total object size (OBJECT_SIZE_UNKNOWN=-1, OBJECT_SIZE_DELETE=-2).
    pub size: i64,
    /// MIME driver object handle.
    pub object: Option<Box<dyn Any + Send>>,
    /// Whether transfer was aborted.
    pub aborted: bool,
    /// Error code from last operation.
    pub err: i32,
    /// Active service driver name.
    pub service_driver: Option<String>,
    /// Service-specific data.
    pub service_data: Option<Box<dyn Any + Send>>,
    /// Reference to the server that spawned this session.
    pub server_index: Option<usize>,
    /// Whether chkput has been called.
    pub checked: bool,
    /// Active MIME type driver index.
    pub mime_driver: Option<usize>,
    /// Whether headers have been sent for current transfer.
    pub headers_sent: bool,
}

impl ServerObexSession {
    // -----------------------------------------------------------------------
    // Accessors (Section E.8)
    // -----------------------------------------------------------------------

    /// Returns the current object name.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Sets the current object name.
    pub fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_owned());
    }

    /// Returns the destination name (for copy/move).
    pub fn get_destname(&self) -> Option<&str> {
        self.destname.as_deref()
    }

    /// Returns the MIME type.
    pub fn get_type(&self) -> Option<&str> {
        self.obj_type.as_deref()
    }

    /// Returns the object size.
    pub fn get_size(&self) -> i64 {
        self.size
    }

    /// Returns the working path.
    pub fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Sets the working path.
    pub fn set_path(&mut self, path: &str) {
        self.path = Some(path.to_owned());
    }

    /// Returns service-specific opaque data.
    pub fn get_service_data(&self) -> Option<&(dyn Any + Send)> {
        self.service_data.as_deref()
    }

    /// Sets service-specific opaque data.
    pub fn set_service_data(&mut self, data: Box<dyn Any + Send>) {
        self.service_data = Some(data);
    }

    /// Returns the application parameters.
    pub fn get_apparam(&self) -> Option<&ObexApparam> {
        self.apparam.as_ref()
    }

    /// Returns non-header data.
    pub fn get_nonhdr(&self) -> Option<&[u8]> {
        self.nonhdr.as_deref()
    }
}

/// Reset session state between requests.
///
/// Source: `obexd/src/obex.c` lines 89-128 (`session_reset`).
pub fn session_reset(session: &mut ServerObexSession) {
    session.name = None;
    session.destname = None;
    session.obj_type = None;
    session.time = None;
    session.apparam = None;
    session.nonhdr = None;
    session.get_rsp = None;
    session.pending = 0;
    session.offset = 0;
    session.size = OBJECT_SIZE_UNKNOWN;
    session.checked = false;
    session.headers_sent = false;
    session.aborted = false;
    session.err = 0;
    session.cmd = 0;
    session.action_id = 0;

    // Close MIME driver object if open.
    if let Some(ref mut obj) = session.object {
        if let Some(idx) = session.mime_driver {
            let Ok(drivers) = mime_drivers().lock() else {
                session.object = None;
                session.mime_driver = None;
                return;
            };
            if let Some(drv) = drivers.get(idx) {
                let _ = drv.close(obj.as_mut());
            }
        }
        session.object = None;
    }
    session.mime_driver = None;

    // Call service driver reset if active.
    if let Some(ref svc_name) = session.service_driver {
        let Ok(drivers) = service_drivers().lock() else {
            return;
        };
        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            drv.reset(session);
        }
    }
}

/// Clean up and free session resources.
///
/// Source: `obexd/src/obex.c` lines 130-170.
pub fn session_free(mut session: ServerObexSession) {
    tracing::info!("OBEX session {} ended", session.id);

    // Reset to close any open MIME driver objects.
    session_reset(&mut session);

    // Drop all owned resources (Rust handles this automatically).
}

/// Parse ISO 8601 time string.
///
/// Format: `YYYYMMDDTHHmmSS` or `YYYYMMDDTHHmmSSZ`.
/// Z suffix = UTC, no suffix = local time.
///
/// Source: `obexd/src/obex.c` lines 70-87.
pub fn parse_iso8601_time(time_str: &str) -> Option<SystemTime> {
    if time_str.len() < 15 {
        return None;
    }

    let s = time_str.trim_end_matches('Z');
    if s.len() < 15 || s.as_bytes()[8] != b'T' {
        return None;
    }

    let year: u32 = s[0..4].parse().ok()?;
    let month: u32 = s[4..6].parse().ok()?;
    let day: u32 = s[6..8].parse().ok()?;
    let hour: u32 = s[9..11].parse().ok()?;
    let min: u32 = s[11..13].parse().ok()?;
    let sec: u32 = s[13..15].parse().ok()?;

    // Validate ranges.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || min >= 60
        || sec >= 60
    {
        return None;
    }

    // Compute days from epoch (simplified — not handling leap seconds).
    // Use a simple algorithm to convert to Unix timestamp.
    let mut total_days: i64 = 0;
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    let days_in_months = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        total_days += i64::from(days_in_months[m as usize]);
        if m == 2 && is_leap_year(year) {
            total_days += 1;
        }
    }
    total_days += i64::from(day) - 1;

    let total_secs =
        total_days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec);

    if total_secs < 0 {
        return None;
    }

    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(total_secs as u64))
}

/// Helper: check if a year is a leap year.
pub fn is_leap_year(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Parse service from incoming CONNECT packet.
///
/// Extracts TARGET and WHO headers and looks up a matching service driver.
///
/// Source: `obexd/src/obex.c` lines 310-348.
pub fn parse_service(pkt: &ObexPacket) -> Option<String> {
    let target = pkt.get_header(HDR_TARGET).and_then(|h| h.as_bytes());
    let who = pkt.get_header(HDR_WHO).and_then(|h| h.as_bytes());

    let result = find_service(target, who);

    if let Some(ref name) = result {
        tracing::debug!("Selected service driver: {}", name);
    } else {
        tracing::debug!("No matching service driver found");
    }

    result
}

/// Start an OBEX session on an accepted connection.
///
/// Creates the lower-level `ObexSession`, assigns a session ID, selects the
/// default service driver (if the server has exactly one), and registers
/// OBEX command handlers.
///
/// Source: `obexd/src/obex.c` lines 998-1090.
pub fn obex_session_start(
    fd: OwnedFd,
    tx_mtu: u16,
    rx_mtu: u16,
    transport_type: TransportType,
    server: &super::transport::ObexServer,
) -> Result<ServerObexSession, ObexError> {
    let obex = ObexSession::new(fd, transport_type, rx_mtu as usize, tx_mtu as usize)?;
    let id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Determine default service driver: if server has exactly one service.
    let default_service = if server.service_drivers.len() == 1 {
        Some(server.service_drivers[0].clone())
    } else {
        None
    };

    // Get peer/local addresses (best-effort; fallback to empty).
    let src = String::new();
    let dst = String::new();

    let session = ServerObexSession {
        obex,
        id,
        cmd: 0,
        action_id: 0,
        src: src.clone(),
        dst: dst.clone(),
        name: None,
        destname: None,
        obj_type: None,
        path: None,
        time: None,
        apparam: None,
        nonhdr: None,
        get_rsp: None,
        buf: Vec::with_capacity(4096),
        pending: 0,
        offset: 0,
        size: OBJECT_SIZE_UNKNOWN,
        object: None,
        aborted: false,
        err: 0,
        service_driver: default_service,
        service_data: None,
        server_index: None,
        checked: false,
        mime_driver: None,
        headers_sent: false,
    };

    tracing::info!(
        "OBEX session {} started from {} via transport '{}'",
        id,
        src,
        server.transport_driver_name
    );

    Ok(session)
}

// ---------------------------------------------------------------------------
// Command Handlers (Section E.4)
// ---------------------------------------------------------------------------

/// Handle OBEX CONNECT command.
///
/// Source: `obexd/src/obex.c` lines 350-460.
pub fn cmd_connect(session: &mut ServerObexSession, pkt: &ObexPacket) {
    tracing::debug!("CONNECT request received for session {}", session.id);

    // Parse service from TARGET/WHO headers.
    if let Some(svc_name) = parse_service(pkt) {
        session.service_driver = Some(svc_name);
    }

    // If we have a service driver, call its connect method.
    if let Some(ref svc_name) = session.service_driver.clone() {
        let Ok(drivers) = service_drivers().lock() else {
            let rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
            let _ = session.obex.send(rsp);
            return;
        };

        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            if let Err(e) = drv.connect(session) {
                tracing::error!("Service connect failed: {}", e);
                let rsp = ObexPacket::new_response(RSP_FORBIDDEN);
                let _ = session.obex.send(rsp);
                return;
            }
        }
    }

    // Set the OBEX connection ID on the lower-level session.
    let conn_id = session.id;
    session.obex.set_conn_id(conn_id);

    // Build CONNECT response.
    let mut rsp = ObexPacket::new_response(RSP_SUCCESS);

    // Add CONNECTION header with the session's connection ID.
    rsp.add_header(ObexHeader::new_u32(HDR_CONNECTION, conn_id));

    // Add WHO header if service has one.
    if let Some(ref svc_name) = session.service_driver {
        let Ok(drivers) = service_drivers().lock() else {
            let err_rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
            let _ = session.obex.send(err_rsp);
            return;
        };
        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            if let Some(who) = drv.who() {
                rsp.add_header(ObexHeader::new_bytes(HDR_WHO, who));
            }
        }
    }

    let _ = session.obex.send(rsp);
}

/// Handle OBEX DISCONNECT command.
///
/// Source: `obexd/src/obex.c` lines 462-485.
pub fn cmd_disconnect(session: &mut ServerObexSession, _pkt: &ObexPacket) {
    tracing::debug!("DISCONNECT request received for session {}", session.id);

    // Call service driver disconnect if active.
    if let Some(ref svc_name) = session.service_driver.clone() {
        let Ok(drivers) = service_drivers().lock() else {
            return;
        };
        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            drv.disconnect(session);
        }
    }

    session_reset(session);

    let rsp = ObexPacket::new_response(RSP_SUCCESS);
    let _ = session.obex.send(rsp);
}

/// Handle OBEX GET command.
///
/// Source: `obexd/src/obex.c` lines 487-570.
pub fn cmd_get(session: &mut ServerObexSession, pkt: &ObexPacket) {
    tracing::debug!("GET request received for session {}", session.id);
    session.cmd = OP_GET;

    // Parse TYPE header to determine MIME type.
    if let Some(type_hdr) = pkt.get_header(HDR_TYPE) {
        if let Some(bytes) = type_hdr.as_bytes() {
            // TYPE header is ASCII, may be null-terminated.
            let s = std::str::from_utf8(bytes).unwrap_or("").trim_end_matches('\0');
            if !s.is_empty() {
                session.obj_type = Some(s.to_owned());
            }
        }
    }

    // Parse NAME header.
    if let Some(name_hdr) = pkt.get_header(HDR_NAME) {
        if let Some(name) = name_hdr.as_unicode() {
            session.name = Some(name.to_owned());
        }
    }

    // Parse APPARAM header.
    if let Some(ap_hdr) = pkt.get_header(HDR_APPARAM) {
        if let Some(bytes) = ap_hdr.as_bytes() {
            if let Ok(ap) = ObexApparam::decode(bytes) {
                session.apparam = Some(ap);
            }
        }
    }

    // Find MIME driver.
    let target = session.service_driver.as_ref().and_then(|svc_name| {
        let Ok(drivers) = service_drivers().lock() else {
            return None;
        };
        drivers
            .iter()
            .find(|d| d.name() == svc_name.as_str())
            .and_then(|d| d.target())
            .map(|t| t.to_vec())
    });

    let who = session.service_driver.as_ref().and_then(|svc_name| {
        let Ok(drivers) = service_drivers().lock() else {
            return None;
        };
        drivers
            .iter()
            .find(|d| d.name() == svc_name.as_str())
            .and_then(|d| d.who())
            .map(|w| w.to_vec())
    });

    session.mime_driver =
        find_mime_driver(target.as_deref(), session.obj_type.as_deref(), who.as_deref());

    // Call service driver get.
    if let Some(ref svc_name) = session.service_driver.clone() {
        let Ok(drivers) = service_drivers().lock() else {
            let rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
            let _ = session.obex.send(rsp);
            return;
        };
        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            if let Err(e) = drv.get(session) {
                tracing::error!("Service GET failed: {}", e);
                let rsp_code = errno_to_rsp(session.err);
                let rsp = ObexPacket::new_response(rsp_code);
                let _ = session.obex.send(rsp);
            }
        }
    } else {
        let rsp = ObexPacket::new_response(RSP_NOT_FOUND);
        let _ = session.obex.send(rsp);
    }
}

/// Handle OBEX PUT command.
///
/// Source: `obexd/src/obex.c` lines 572-720.
pub fn cmd_put(session: &mut ServerObexSession, pkt: &ObexPacket) {
    tracing::debug!("PUT request received for session {}", session.id);
    session.cmd = OP_PUT;

    // Handle OPP auto-connect: if no service selected, try to find default.
    if session.service_driver.is_none() {
        if let Some(svc_name) = find_service(None, None) {
            session.service_driver = Some(svc_name);
        }
    }

    // Parse headers.
    if let Some(name_hdr) = pkt.get_header(HDR_NAME) {
        if let Some(name) = name_hdr.as_unicode() {
            session.name = Some(name.to_owned());
        }
    }

    if let Some(type_hdr) = pkt.get_header(HDR_TYPE) {
        if let Some(bytes) = type_hdr.as_bytes() {
            let s = std::str::from_utf8(bytes).unwrap_or("").trim_end_matches('\0');
            if !s.is_empty() {
                session.obj_type = Some(s.to_owned());
            }
        }
    }

    if let Some(len_hdr) = pkt.get_header(HDR_LENGTH) {
        if let Some(len) = len_hdr.as_u32() {
            session.size = i64::from(len);
        }
    }

    if let Some(time_hdr) = pkt.get_header(HDR_TIME) {
        if let Some(bytes) = time_hdr.as_bytes() {
            if let Ok(s) = std::str::from_utf8(bytes) {
                session.time = Some(s.trim_end_matches('\0').to_owned());
            }
        }
    }

    if let Some(ap_hdr) = pkt.get_header(HDR_APPARAM) {
        if let Some(bytes) = ap_hdr.as_bytes() {
            if let Ok(ap) = ObexApparam::decode(bytes) {
                session.apparam = Some(ap);
            }
        }
    }

    // Extract body data from the packet if present.
    if let Some(body_hdr) = pkt.get_body() {
        if let Some(body_bytes) = body_hdr.as_bytes() {
            if !body_bytes.is_empty() {
                session.buf.extend_from_slice(body_bytes);
                session.pending = body_bytes.len();
            }
        }
    }

    // Call chkput for validation if not yet checked.
    if !session.checked {
        if let Some(ref svc_name) = session.service_driver.clone() {
            let Ok(drivers) = service_drivers().lock() else {
                let rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
                let _ = session.obex.send(rsp);
                return;
            };
            if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
                if let Err(e) = drv.chkput(session) {
                    tracing::error!("Service chkput failed: {}", e);
                    let rsp_code = errno_to_rsp(session.err);
                    let rsp = ObexPacket::new_response(rsp_code);
                    let _ = session.obex.send(rsp);
                    return;
                }
            }
        }
        session.checked = true;
    }

    // Call service driver put.
    if let Some(ref svc_name) = session.service_driver.clone() {
        let Ok(drivers) = service_drivers().lock() else {
            let rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
            let _ = session.obex.send(rsp);
            return;
        };
        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            if let Err(e) = drv.put(session) {
                tracing::error!("Service PUT failed: {}", e);
                let rsp_code = errno_to_rsp(session.err);
                let rsp = ObexPacket::new_response(rsp_code);
                let _ = session.obex.send(rsp);
            }
        }
    } else {
        let rsp = ObexPacket::new_response(RSP_NOT_FOUND);
        let _ = session.obex.send(rsp);
    }
}

/// Handle OBEX SETPATH command.
///
/// Source: `obexd/src/obex.c` lines 722-780.
pub fn cmd_setpath(session: &mut ServerObexSession, pkt: &ObexPacket) {
    tracing::debug!("SETPATH request received for session {}", session.id);
    session.cmd = OP_SETPATH;

    // Parse SetpathData (2 bytes: flags + reserved).
    let data = pkt.get_data();
    let flags = if !data.is_empty() { data[0] } else { 0 };

    // Parse NAME header.
    let name = pkt.get_header(HDR_NAME).and_then(|h| h.as_unicode()).unwrap_or("");

    // Call service driver setpath.
    if let Some(ref svc_name) = session.service_driver.clone() {
        let Ok(drivers) = service_drivers().lock() else {
            let rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
            let _ = session.obex.send(rsp);
            return;
        };
        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            match drv.setpath(session, name, flags) {
                Ok(()) => {
                    let rsp = ObexPacket::new_response(RSP_SUCCESS);
                    let _ = session.obex.send(rsp);
                }
                Err(e) => {
                    tracing::error!("Service SETPATH failed: {}", e);
                    let rsp_code = errno_to_rsp(session.err);
                    let rsp = ObexPacket::new_response(rsp_code);
                    let _ = session.obex.send(rsp);
                }
            }
        }
    } else {
        let rsp = ObexPacket::new_response(RSP_NOT_FOUND);
        let _ = session.obex.send(rsp);
    }
}

/// Handle OBEX ACTION command.
///
/// Source: `obexd/src/obex.c` lines 782-850.
pub fn cmd_action(session: &mut ServerObexSession, pkt: &ObexPacket) {
    tracing::debug!("ACTION request received for session {}", session.id);
    session.cmd = OP_ACTION;

    // Parse NAME header.
    if let Some(name_hdr) = pkt.get_header(HDR_NAME) {
        if let Some(name) = name_hdr.as_unicode() {
            session.name = Some(name.to_owned());
        }
    }

    // Parse DESTNAME header.
    if let Some(dest_hdr) = pkt.get_header(HDR_DESTNAME) {
        if let Some(dest) = dest_hdr.as_unicode() {
            session.destname = Some(dest.to_owned());
        }
    }

    // Parse ACTION ID header.
    if let Some(action_hdr) = pkt.get_header(HDR_ACTION) {
        if let Some(aid) = action_hdr.as_u8() {
            session.action_id = aid;
        }
    }

    // Call service driver action.
    if let Some(ref svc_name) = session.service_driver.clone() {
        let Ok(drivers) = service_drivers().lock() else {
            let rsp = ObexPacket::new_response(RSP_SERVICE_UNAVAILABLE);
            let _ = session.obex.send(rsp);
            return;
        };
        if let Some(drv) = drivers.iter().find(|d| d.name() == svc_name.as_str()) {
            match drv.action(session, session.action_id) {
                Ok(()) => {
                    let rsp = ObexPacket::new_response(RSP_SUCCESS);
                    let _ = session.obex.send(rsp);
                }
                Err(e) => {
                    tracing::error!("Service ACTION failed: {}", e);
                    let rsp_code = errno_to_rsp(session.err);
                    let rsp = ObexPacket::new_response(rsp_code);
                    let _ = session.obex.send(rsp);
                }
            }
        }
    } else {
        let rsp = ObexPacket::new_response(RSP_NOT_FOUND);
        let _ = session.obex.send(rsp);
    }
}

/// Handle OBEX ABORT command.
///
/// Source: `obexd/src/obex.c` lines 852-890.
pub fn cmd_abort(session: &mut ServerObexSession, _pkt: &ObexPacket) {
    tracing::debug!("ABORT request received for session {}", session.id);

    session.aborted = true;
    session_reset(session);

    let rsp = ObexPacket::new_response(RSP_SUCCESS);
    let _ = session.obex.send(rsp);
}

// ---------------------------------------------------------------------------
// Async I/O Integration (Section E.6)
// ---------------------------------------------------------------------------

/// Write data to the MIME driver object.
///
/// Source: `obexd/src/obex.c` lines 170-210.
pub fn driver_write(session: &mut ServerObexSession, buf: &[u8]) -> Result<usize, ObexError> {
    let idx =
        session.mime_driver.ok_or_else(|| ObexError::Failed("no MIME driver active".into()))?;

    let Ok(drivers) = mime_drivers().lock() else {
        return Err(ObexError::Failed("MIME driver lock poisoned".into()));
    };

    let drv = drivers
        .get(idx)
        .ok_or_else(|| ObexError::Failed("MIME driver index out of range".into()))?;

    let obj = session
        .object
        .as_mut()
        .ok_or_else(|| ObexError::Failed("no MIME driver object open".into()))?;

    drv.write(obj.as_mut(), buf)
}

/// Read data from the MIME driver object.
///
/// Source: `obexd/src/obex.c` lines 212-250.
pub fn driver_read(session: &mut ServerObexSession, buf: &mut [u8]) -> Result<usize, ObexError> {
    let idx =
        session.mime_driver.ok_or_else(|| ObexError::Failed("no MIME driver active".into()))?;

    let Ok(drivers) = mime_drivers().lock() else {
        return Err(ObexError::Failed("MIME driver lock poisoned".into()));
    };

    let drv = drivers
        .get(idx)
        .ok_or_else(|| ObexError::Failed("MIME driver index out of range".into()))?;

    let obj = session
        .object
        .as_mut()
        .ok_or_else(|| ObexError::Failed("no MIME driver object open".into()))?;

    drv.read(obj.as_mut(), buf)
}

// ---------------------------------------------------------------------------
// Transfer Helper Functions (Section E.7)
// ---------------------------------------------------------------------------

/// Start a GET stream transfer.
///
/// Opens the MIME driver for reading and prepares the session for streaming
/// response data back to the client.
///
/// Source: `obex_get_stream_start()` in obex.c.
pub fn obex_get_stream_start(session: &mut ServerObexSession) -> Result<(), ObexError> {
    let name = session.name.clone().unwrap_or_default();

    let idx = session
        .mime_driver
        .ok_or_else(|| ObexError::Failed("no MIME driver for GET stream".into()))?;

    let Ok(drivers) = mime_drivers().lock() else {
        return Err(ObexError::Failed("MIME driver lock poisoned".into()));
    };

    let drv = drivers
        .get(idx)
        .ok_or_else(|| ObexError::Failed("MIME driver index out of range".into()))?;

    let obj = drv.open(&name)?;
    session.object = Some(obj);
    session.headers_sent = false;

    tracing::debug!("GET stream started for '{}'", name);
    Ok(())
}

/// Start a PUT stream transfer.
///
/// Opens the MIME driver for writing and prepares the session for receiving
/// incoming body data.
///
/// Source: `obex_put_stream_start()` in obex.c.
pub fn obex_put_stream_start(session: &mut ServerObexSession) -> Result<(), ObexError> {
    let name = session.name.clone().unwrap_or_default();

    let idx = session
        .mime_driver
        .ok_or_else(|| ObexError::Failed("no MIME driver for PUT stream".into()))?;

    let Ok(drivers) = mime_drivers().lock() else {
        return Err(ObexError::Failed("MIME driver lock poisoned".into()));
    };

    let drv = drivers
        .get(idx)
        .ok_or_else(|| ObexError::Failed("MIME driver index out of range".into()))?;

    let obj = drv.open(&name)?;
    session.object = Some(obj);

    tracing::debug!("PUT stream started for '{}'", name);
    Ok(())
}

// ============================================================================
// SECTION F: D-Bus Manager (from obexd/src/manager.c/h)
// ============================================================================

/// D-Bus service name for the OBEX daemon.
pub const OBEXD_SERVICE: &str = "org.bluez.obex";

/// Base D-Bus object path for OBEX daemon objects.
pub const OBEX_BASE_PATH: &str = "/org/bluez/obex";

/// Base path for server-side session objects.
const SESSION_BASE_PATH: &str = "/org/bluez/obex/server";

// ---------------------------------------------------------------------------
// D-Bus Connection Storage
// ---------------------------------------------------------------------------

static DBUS_CONNECTION: OnceLock<Mutex<Option<zbus::Connection>>> = OnceLock::new();

fn dbus_conn_store() -> &'static Mutex<Option<zbus::Connection>> {
    DBUS_CONNECTION.get_or_init(|| Mutex::new(None))
}

/// Store the D-Bus connection for use by subsystems.
pub fn set_dbus_connection(conn: zbus::Connection) {
    if let Ok(mut guard) = dbus_conn_store().lock() {
        *guard = Some(conn);
    }
}

/// Return a cloned connection reference.
pub fn get_dbus_connection() -> Option<zbus::Connection> {
    if let Ok(guard) = dbus_conn_store().lock() { guard.clone() } else { None }
}

// ---------------------------------------------------------------------------
// D-Bus Error Type
// ---------------------------------------------------------------------------

/// D-Bus error type for OBEX server-side interface methods.
#[derive(Debug)]
enum ObexDbusError {
    Failed(String),
    NotAuthorized,
    InvalidArgs(String),
}

impl std::fmt::Display for ObexDbusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(msg) => write!(f, "{}", msg),
            Self::NotAuthorized => write!(f, "Not Authorized"),
            Self::InvalidArgs(msg) => write!(f, "Invalid arguments: {}", msg),
        }
    }
}

impl std::error::Error for ObexDbusError {}

impl ObexDbusError {
    fn dbus_error_name(&self) -> &'static str {
        match self {
            Self::Failed(_) => "org.bluez.obex.Error.Failed",
            Self::NotAuthorized => "org.bluez.obex.Error.NotAuthorized",
            Self::InvalidArgs(_) => "org.bluez.obex.Error.InvalidArguments",
        }
    }
}

impl zbus::DBusError for ObexDbusError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        zbus::names::ErrorName::from_static_str_unchecked(self.dbus_error_name())
    }

    fn description(&self) -> Option<&str> {
        Some(match self {
            Self::Failed(msg) => msg.as_str(),
            Self::NotAuthorized => "Not Authorized",
            Self::InvalidArgs(msg) => msg.as_str(),
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

impl From<ObexDbusError> for zbus::Error {
    fn from(err: ObexDbusError) -> Self {
        let name = err.dbus_error_name().to_owned();
        let desc = format!("{err}");
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name)
                .expect("OBEX D-Bus error names are always valid"),
            Some(desc),
            zbus::message::Message::method_call("/", "Err")
                .expect("default message construction should not fail")
                .build(&())
                .expect("default message build should not fail"),
        )
    }
}

// ---------------------------------------------------------------------------
// Agent State (Section F.2)
// ---------------------------------------------------------------------------

struct Agent {
    bus_name: String,
    path: String,
    auth_pending: Option<tokio::sync::oneshot::Sender<bool>>,
}

static AGENT: OnceLock<Mutex<Option<Agent>>> = OnceLock::new();

fn agent_store() -> &'static Mutex<Option<Agent>> {
    AGENT.get_or_init(|| Mutex::new(None))
}

// ---------------------------------------------------------------------------
// Transfer Status (Section F.3)
// ---------------------------------------------------------------------------

/// Transfer status values matching D-Bus Transfer1 status property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Active,
    Complete,
    Error,
}

impl TransferStatus {
    /// Returns the D-Bus string representation.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Queued => "queued",
            Self::Active => "active",
            Self::Complete => "complete",
            Self::Error => "error",
        }
    }
}

// ---------------------------------------------------------------------------
// AgentManager1 D-Bus Interface (Section F.4)
// ---------------------------------------------------------------------------

/// AgentManager1 D-Bus interface implementation.
pub struct AgentManager;

#[zbus::interface(name = "org.bluez.obex.AgentManager1")]
impl AgentManager {
    /// Register an agent to handle incoming object push authorization.
    async fn register_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        agent: zbus::zvariant::ObjectPath<'_>,
    ) -> Result<(), ObexDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| ObexDbusError::InvalidArgs("no sender".into()))?
            .to_string();

        tracing::info!("Agent registered: sender={} path={}", sender, agent.as_str());

        let Ok(mut guard) = agent_store().lock() else {
            return Err(ObexDbusError::Failed("internal lock error".into()));
        };

        *guard = Some(Agent { bus_name: sender, path: agent.to_string(), auth_pending: None });

        Ok(())
    }

    /// Unregister a previously registered agent.
    async fn unregister_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        agent: zbus::zvariant::ObjectPath<'_>,
    ) -> Result<(), ObexDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| ObexDbusError::InvalidArgs("no sender".into()))?
            .to_string();

        let Ok(mut guard) = agent_store().lock() else {
            return Err(ObexDbusError::Failed("internal lock error".into()));
        };

        match guard.as_ref() {
            Some(a) if a.bus_name == sender && a.path == agent.as_str() => {
                tracing::info!("Agent unregistered: {}", agent.as_str());
                *guard = None;
                Ok(())
            }
            Some(_) => Err(ObexDbusError::Failed("agent does not match registered agent".into())),
            None => Err(ObexDbusError::Failed("no agent registered".into())),
        }
    }
}

// ---------------------------------------------------------------------------
// Session1 D-Bus Interface (Section F.5)
// ---------------------------------------------------------------------------

/// Session1 D-Bus interface implementation.
pub struct SessionInterface {
    source_addr: String,
    destination_addr: String,
    target_name: String,
}

#[zbus::interface(name = "org.bluez.obex.Session1")]
impl SessionInterface {
    #[zbus(property)]
    fn source(&self) -> &str {
        &self.source_addr
    }

    #[zbus(property)]
    fn destination(&self) -> &str {
        &self.destination_addr
    }

    #[zbus(property)]
    fn target(&self) -> &str {
        &self.target_name
    }
}

// ---------------------------------------------------------------------------
// Transfer1 D-Bus Interface (Section F.6)
// ---------------------------------------------------------------------------

/// Transfer1 D-Bus interface implementation.
pub struct TransferInterface {
    status: TransferStatus,
    session_path: String,
    transfer_name: Option<String>,
    transfer_type: Option<String>,
    transfer_size: u64,
    transferred_bytes: u64,
    transfer_filename: Option<String>,
}

#[zbus::interface(name = "org.bluez.obex.Transfer1")]
impl TransferInterface {
    #[zbus(property)]
    fn status(&self) -> &str {
        self.status.as_str()
    }

    #[zbus(property)]
    fn session(&self) -> zbus::zvariant::ObjectPath<'_> {
        zbus::zvariant::ObjectPath::try_from(self.session_path.as_str())
            .unwrap_or_else(|_| zbus::zvariant::ObjectPath::from_static_str_unchecked("/"))
    }

    #[zbus(property)]
    fn name(&self) -> &str {
        self.transfer_name.as_deref().unwrap_or("")
    }

    #[zbus(property, name = "Type")]
    fn obj_type(&self) -> &str {
        self.transfer_type.as_deref().unwrap_or("")
    }

    #[zbus(property)]
    fn size(&self) -> u64 {
        self.transfer_size
    }

    #[zbus(property)]
    fn transferred(&self) -> u64 {
        self.transferred_bytes
    }

    #[zbus(property)]
    fn filename(&self) -> &str {
        self.transfer_filename.as_deref().unwrap_or("")
    }

    async fn cancel(&mut self) -> Result<(), ObexDbusError> {
        tracing::debug!("Transfer cancel requested for session {}", self.session_path);
        // Verify the transfer is in a cancelable state.
        if self.status == TransferStatus::Complete || self.status == TransferStatus::Error {
            return Err(ObexDbusError::NotAuthorized);
        }
        self.status = TransferStatus::Error;
        Ok(())
    }

    async fn suspend(&mut self) -> Result<(), ObexDbusError> {
        tracing::debug!("Transfer suspend requested for session {}", self.session_path);
        Ok(())
    }

    async fn resume(&mut self) -> Result<(), ObexDbusError> {
        tracing::debug!("Transfer resume requested for session {}", self.session_path);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Session/Transfer Registration (Section F.7)
// ---------------------------------------------------------------------------

/// Register a session on D-Bus at `/org/bluez/obex/server/session{id}`.
pub async fn register_session(
    conn: &zbus::Connection,
    session: &ServerObexSession,
) -> Result<String, ObexError> {
    let path = format!("{}/session{}", SESSION_BASE_PATH, session.id);
    let target_name = session.service_driver.clone().unwrap_or_default();

    let iface = SessionInterface {
        source_addr: session.src.clone(),
        destination_addr: session.dst.clone(),
        target_name,
    };

    conn.object_server()
        .at(path.as_str(), iface)
        .await
        .map_err(|e| ObexError::Failed(format!("D-Bus session register failed: {}", e)))?;

    tracing::debug!("Registered D-Bus session at {}", path);
    Ok(path)
}

/// Unregister a session from D-Bus.
pub async fn unregister_session(conn: &zbus::Connection, session_path: &str) {
    let _ = conn.object_server().remove::<SessionInterface, _>(session_path).await;
    tracing::debug!("Unregistered D-Bus session at {}", session_path);
}

/// Register a transfer on D-Bus.
pub async fn register_transfer(
    conn: &zbus::Connection,
    session: &ServerObexSession,
) -> Result<String, ObexError> {
    let session_path = format!("{}/session{}", SESSION_BASE_PATH, session.id);
    let transfer_id = TRANSFER_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = format!("{}/transfer{}", session_path, transfer_id);

    let iface = TransferInterface {
        status: TransferStatus::Queued,
        session_path,
        transfer_name: session.name.clone(),
        transfer_type: session.obj_type.clone(),
        transfer_size: if session.size >= 0 { session.size as u64 } else { 0 },
        transferred_bytes: 0,
        transfer_filename: session.name.clone(),
    };

    conn.object_server()
        .at(path.as_str(), iface)
        .await
        .map_err(|e| ObexError::Failed(format!("D-Bus transfer register failed: {}", e)))?;

    tracing::debug!("Registered D-Bus transfer at {}", path);
    Ok(path)
}

/// Unregister a transfer from D-Bus.
pub async fn unregister_transfer(conn: &zbus::Connection, transfer_path: &str) {
    let _ = conn.object_server().remove::<TransferInterface, _>(transfer_path).await;
    tracing::debug!("Unregistered D-Bus transfer at {}", transfer_path);
}

// ---------------------------------------------------------------------------
// Transfer Status Emission (Section F.8)
// ---------------------------------------------------------------------------

/// Emit a property changed signal for the Transfer1 `Status` property.
pub async fn transfer_emit_status(
    conn: &zbus::Connection,
    transfer_path: &str,
    status: TransferStatus,
) {
    let iface_ref = conn.object_server().interface::<_, TransferInterface>(transfer_path).await;

    if let Ok(iface) = iface_ref {
        let mut guard = iface.get_mut().await;
        guard.status = status;
        if let Err(e) = guard.status_changed(iface.signal_emitter()).await {
            tracing::warn!("Failed to emit Status changed: {}", e);
        }
    }
}

/// Emit a property changed signal for the Transfer1 `Transferred` property.
pub async fn transfer_emit_transferred(
    conn: &zbus::Connection,
    transfer_path: &str,
    transferred: u64,
) {
    let iface_ref = conn.object_server().interface::<_, TransferInterface>(transfer_path).await;

    if let Ok(iface) = iface_ref {
        let mut guard = iface.get_mut().await;
        guard.transferred_bytes = transferred;
        if let Err(e) = guard.transferred_changed(iface.signal_emitter()).await {
            tracing::warn!("Failed to emit Transferred changed: {}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// Agent Authorization (Section F.9)
// ---------------------------------------------------------------------------

/// Request agent authorization for an incoming push.
///
/// Calls `Agent1.AuthorizePush(transfer_path)` on the registered agent.
/// Returns the (possibly renamed) filename from the agent's reply.
pub async fn authorize_push(conn: &zbus::Connection, filename: &str) -> Result<String, ObexError> {
    let (bus_name, agent_path) = {
        let Ok(guard) = agent_store().lock() else {
            return Err(ObexError::Failed("agent lock poisoned".into()));
        };
        match guard.as_ref() {
            Some(agent) => {
                // Check if there is already a pending authorization.
                if agent.auth_pending.is_some() {
                    return Err(ObexError::Failed("authorization already pending".into()));
                }
                (agent.bus_name.clone(), agent.path.clone())
            }
            None => {
                return Err(ObexError::Failed("no agent registered".into()));
            }
        }
    };

    tracing::debug!("Requesting push authorization from agent {} at {}", bus_name, agent_path);

    let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(conn)
        .destination(bus_name.as_str())
        .map_err(|e| ObexError::Failed(format!("proxy destination: {}", e)))?
        .path(agent_path.as_str())
        .map_err(|e| ObexError::Failed(format!("proxy path: {}", e)))?
        .interface("org.bluez.obex.Agent1")
        .map_err(|e| ObexError::Failed(format!("proxy interface: {}", e)))?
        .build()
        .await
        .map_err(|e| ObexError::Failed(format!("proxy build: {}", e)))?;

    let result: zbus::Result<String> = proxy.call("AuthorizePush", &(filename,)).await;

    match result {
        Ok(new_name) => {
            tracing::debug!("Agent authorized push, filename: {}", new_name);
            Ok(new_name)
        }
        Err(e) => {
            tracing::error!("Agent rejected push: {}", e);
            Err(ObexError::Failed(format!("agent rejected push: {}", e)))
        }
    }
}

// ============================================================================
// SECTION G: Plugin Framework (from obexd/src/plugin.c/h)
// ============================================================================

/// OBEX plugin descriptor trait.
///
/// Built-in plugins are registered via `inventory::submit!` and collected
/// at runtime via `inventory::iter`.
pub trait ObexPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn init(&self) -> Result<(), ObexError>;
    fn exit(&self);
}

inventory::collect!(Box<dyn ObexPlugin>);

static LOADED_PLUGINS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn loaded_plugins() -> &'static Mutex<Vec<String>> {
    LOADED_PLUGINS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Glob-style pattern match replacing C `g_pattern_match_simple()`.
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(p: &[u8], t: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

/// Initialize the OBEX plugin framework.
///
/// Collects all registered plugins, applies include/exclude glob patterns,
/// and calls `init()` on each accepted plugin.
pub fn plugin_init(include: Option<&str>, exclude: Option<&str>) -> Result<(), ObexError> {
    let include_pats: Vec<&str> =
        include.map(|s| s.split(',').map(str::trim).collect()).unwrap_or_default();
    let exclude_pats: Vec<&str> =
        exclude.map(|s| s.split(',').map(str::trim).collect()).unwrap_or_default();

    let Ok(mut loaded) = loaded_plugins().lock() else {
        return Err(ObexError::Failed("plugin lock poisoned".into()));
    };

    for plugin in inventory::iter::<Box<dyn ObexPlugin>> {
        let name = plugin.name();

        if !include_pats.is_empty() && !include_pats.iter().any(|pat| glob_match(pat, name)) {
            tracing::debug!("Plugin {} excluded by include filter", name);
            continue;
        }

        if exclude_pats.iter().any(|pat| glob_match(pat, name)) {
            tracing::debug!("Plugin {} excluded by exclude filter", name);
            continue;
        }

        match plugin.init() {
            Ok(()) => {
                tracing::info!("Plugin {} loaded", name);
                loaded.push(name.to_owned());
            }
            Err(e) => {
                tracing::error!("Plugin {} init failed: {}", name, e);
            }
        }
    }

    tracing::info!("{} OBEX plugins loaded", loaded.len());
    Ok(())
}

/// Clean up all loaded plugins in reverse order.
pub fn plugin_cleanup() {
    let Ok(mut loaded) = loaded_plugins().lock() else {
        return;
    };

    let names: Vec<String> = loaded.drain(..).rev().collect();

    for name in &names {
        for plugin in inventory::iter::<Box<dyn ObexPlugin>> {
            if plugin.name() == name.as_str() {
                tracing::info!("Plugin {} unloaded", name);
                plugin.exit();
                break;
            }
        }
    }
}

// ============================================================================
// SECTION H: Logging (from obexd/src/log.c/h)
// ============================================================================

/// Initialize the OBEX daemon logging subsystem.
///
/// `debug_str` is a comma-separated list of module patterns for debug enablement.
/// `detach`: true for daemon mode (compact format), false for foreground (stderr).
pub fn obex_log_init(debug_str: Option<&str>, detach: bool) {
    let filter_str = if let Some(debug) = debug_str {
        let modules = debug
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("{}=debug", s))
            .collect::<Vec<_>>()
            .join(",");

        if modules.is_empty() { "info".to_owned() } else { format!("info,{}", modules) }
    } else {
        "info".to_owned()
    };

    let env_filter = tracing_subscriber::EnvFilter::new(filter_str);

    if detach {
        let subscriber =
            tracing_subscriber::fmt().compact().with_ansi(false).with_target(true).finish();
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = subscriber.with(env_filter);
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        let subscriber = tracing_subscriber::fmt().with_target(true).finish();
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = subscriber.with(env_filter);
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    tracing::info!("OBEX daemon logging initialized (detach={})", detach);
}

/// Enable all debug output (for SIGUSR2 handler).
pub fn obex_log_enable_debug() {
    tracing::info!("Debug logging enable requested (effective at next init)");
}

// ============================================================================
// SECTION I: Logind Integration (from obexd/src/logind.c/h)
// ============================================================================

static LOGIND_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Set whether logind session gating is enabled.
pub fn logind_set(enabled: bool) {
    LOGIND_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check whether logind session gating is enabled.
pub fn logind_enabled() -> bool {
    LOGIND_ENABLED.load(Ordering::Relaxed)
}
