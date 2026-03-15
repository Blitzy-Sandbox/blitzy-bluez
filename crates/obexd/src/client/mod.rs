// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX client subsystem — session management, transfer engine, and
//! profile-specific interfaces.
//!
//! This module replaces `obexd/client/manager.c` (311 lines) and
//! `obexd/client/manager.h` (12 lines).  It implements the
//! `org.bluez.obex.Client1` D-Bus interface at `/org/bluez/obex` and
//! orchestrates initialisation of all client sub-modules in the exact
//! order specified by the C original.

// ── Sub-module declarations ──────────────────────────────────────────
pub mod profiles;
pub mod session;
pub mod transfer;

// ── Re-exports ───────────────────────────────────────────────────────
pub use session::ObcSession;
pub use transfer::ObcTransfer;

// ── Standard library ─────────────────────────────────────────────────
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── External crates ──────────────────────────────────────────────────
use tracing::{debug, error};
use zbus::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

// ── Crate-internal imports ───────────────────────────────────────────
use profiles::{
    bip_exit, bip_init, ftp_exit, ftp_init, map_exit, map_init, opp_exit, opp_init, pbap_exit,
    pbap_init, sync_exit, sync_init,
};
use session::{SessionCallbackFn, bluetooth_exit, bluetooth_init};

// ── D-Bus path constant ─────────────────────────────────────────────

/// D-Bus object path where the Client1 interface is registered.
/// Matches the C `CLIENT_PATH` define (manager.c line 37).
const CLIENT_PATH: &str = "/org/bluez/obex";

// =====================================================================
// ClientError — D-Bus error type for Client1 methods
// =====================================================================

/// Errors returned by `org.bluez.obex.Client1` D-Bus methods.
///
/// Each variant maps to a fully-qualified `org.bluez.obex.Error.*`
/// D-Bus error name, preserving byte-identical behaviour with the C
/// original.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Invalid or missing arguments.
    /// C: `g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments", NULL)`
    #[error("Invalid arguments")]
    InvalidArguments,

    /// Generic failure during session creation or operation.
    /// C: `g_dbus_create_error(msg, ERROR_INTERFACE ".Failed", "%s", err->message)`
    #[error("{0}")]
    Failed(String),

    /// The caller is not the session owner.
    /// C: `g_dbus_create_error(msg, ERROR_INTERFACE ".NotAuthorized", "Not Authorized")`
    #[error("Not Authorized")]
    NotAuthorized,
}

impl ClientError {
    /// Fully-qualified D-Bus error name for this variant.
    fn dbus_error_name(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "org.bluez.obex.Error.InvalidArguments",
            Self::Failed(_) => "org.bluez.obex.Error.Failed",
            Self::NotAuthorized => "org.bluez.obex.Error.NotAuthorized",
        }
    }
}

/// Manual `zbus::DBusError` implementation so `ClientError` can be used
/// directly in `#[zbus::interface]` method return types.
impl zbus::DBusError for ClientError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        zbus::names::ErrorName::from_static_str_unchecked(self.dbus_error_name())
    }

    fn description(&self) -> Option<&str> {
        match self {
            Self::InvalidArguments => None,
            Self::Failed(msg) if msg.is_empty() => None,
            Self::Failed(msg) => Some(msg.as_str()),
            Self::NotAuthorized => Some("Not Authorized"),
        }
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

/// Conversion into `zbus::Error` for contexts that propagate through
/// the generic zbus error type (matching `session.rs` pattern).
impl From<ClientError> for zbus::Error {
    fn from(err: ClientError) -> Self {
        let name = err.dbus_error_name().to_owned();
        let desc = format!("{err}");
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name)
                .expect("ClientError D-Bus error names are always valid"),
            Some(desc),
            zbus::message::Message::method_call("/", "Err")
                .expect("default message construction should not fail")
                .build(&())
                .expect("default message build should not fail"),
        )
    }
}

// =====================================================================
// ClientManager — org.bluez.obex.Client1 implementation
// =====================================================================

/// OBEX client session manager exposed as the `org.bluez.obex.Client1`
/// D-Bus interface at [`CLIENT_PATH`].
///
/// Tracks active client sessions and enforces ownership verification on
/// session removal (matching the C `sessions` GSList and sender checks
/// in `manager.c`).
pub struct ClientManager {
    /// Shared D-Bus connection handle.
    conn: Connection,
    /// Active sessions, protected by a mutex for interior mutability
    /// because `#[zbus::interface]` methods receive `&self`.
    sessions: Mutex<Vec<Arc<Mutex<ObcSession>>>>,
}

impl ClientManager {
    /// Create a new `ClientManager` bound to the given D-Bus connection.
    fn new(conn: Connection) -> Self {
        Self { conn, sessions: Mutex::new(Vec::new()) }
    }

    /// Linear search for a session matching the given D-Bus object path.
    ///
    /// Mirrors the C `find_session()` helper (manager.c lines 147-159).
    fn find_session(&self, path: &str) -> Option<Arc<Mutex<ObcSession>>> {
        let sessions = self.sessions.lock().expect("sessions lock poisoned");
        sessions
            .iter()
            .find(|s| {
                let guard = s.lock().expect("session lock poisoned");
                guard.get_path() == path
            })
            .cloned()
    }

    /// Remove a session from the tracking list and shut it down.
    ///
    /// Mirrors the combined `release_session()` / `unregister_session()`
    /// helpers from the C source.
    fn release_session(&self, session: &Arc<Mutex<ObcSession>>) {
        {
            let mut sessions = self.sessions.lock().expect("sessions lock poisoned");
            sessions.retain(|s| !Arc::ptr_eq(s, session));
        }
        let mut guard = session.lock().expect("session lock poisoned");
        guard.shutdown();
    }
}

// ── D-Bus interface ──────────────────────────────────────────────────

#[zbus::interface(name = "org.bluez.obex.Client1")]
impl ClientManager {
    /// Create a new OBEX client session.
    ///
    /// D-Bus signature: `CreateSession(s destination, a{sv} args) → (o)`
    ///
    /// Dictionary keys recognised (matching C `parse_device_dict`):
    ///  - `"Source"`  — local adapter address (String)
    ///  - `"Target"`  — OBEX target service identifier (String)
    ///  - `"Channel"` — RFCOMM channel number (Byte / u8)
    ///  - `"PSM"`     — L2CAP PSM (UInt16 / u16)
    #[zbus(name = "CreateSession")]
    async fn create_session(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        destination: &str,
        args: HashMap<String, OwnedValue>,
    ) -> Result<OwnedObjectPath, ClientError> {
        // ── 1. Validate destination (manager.c line 196) ─────────────
        if destination.is_empty() {
            return Err(ClientError::InvalidArguments);
        }

        // ── 2. Parse device dictionary (manager.c lines 110-145) ─────
        let (source, target, channel, psm) = parse_device_dict(&args);

        // ── 3. Identify the D-Bus caller (session owner) ─────────────
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        // ── 4. Create a oneshot channel to bridge callback → async ───
        let (tx, rx) = tokio::sync::oneshot::channel::<Option<String>>();

        let callback: SessionCallbackFn = Box::new(move |_session, _transfer, err| {
            let err_msg = err.map(|e| format!("{e}"));
            // The receiver may already be dropped if the method was
            // cancelled; ignore send errors.
            let _ = tx.send(err_msg);
        });

        // ── 5. Create the session (transport connection starts) ──────
        let session_arc = ObcSession::create(
            source.as_deref(),
            destination,
            target.as_deref(),
            channel,
            psm,
            &sender,
            callback,
        )
        .map_err(|e| ClientError::Failed(format!("{e}")))?;

        // ── 5a. Set owner (matching C obc_session_set_owner) ─────────
        {
            let mut guard = session_arc.lock().expect("session lock poisoned");
            guard.set_owner(&sender);
        }

        // ── 6. Wait for the transport / OBEX connection callback ─────
        //
        // Three outcomes:
        //   Ok(None)       — new session connected successfully
        //   Ok(Some(msg))  — new session connection failed
        //   Err(_)         — callback was dropped (session-reuse case:
        //                    the session already existed and is connected)
        match rx.await {
            Ok(None) => {
                // New session — register on D-Bus and track.
                let path = {
                    let mut guard = session_arc.lock().expect("session lock poisoned");
                    guard
                        .register(&self.conn, Arc::clone(&session_arc))
                        .map_err(|e| ClientError::Failed(format!("{e}")))?
                };

                self.sessions
                    .lock()
                    .expect("sessions lock poisoned")
                    .push(Arc::clone(&session_arc));

                OwnedObjectPath::try_from(path)
                    .map_err(|e| ClientError::Failed(format!("invalid path: {e}")))
            }
            Ok(Some(err_msg)) => {
                // Connection failed — tear down.
                let mut guard = session_arc.lock().expect("session lock poisoned");
                guard.shutdown();
                Err(ClientError::Failed(err_msg))
            }
            Err(_recv_err) => {
                // Session-reuse case: callback closure was dropped because
                // `create()` returned an existing session.  The session is
                // already connected and registered on D-Bus.
                let path = {
                    let guard = session_arc.lock().expect("session lock poisoned");
                    guard.get_path().to_owned()
                };

                // Track if not already tracked.
                {
                    let mut sessions = self.sessions.lock().expect("sessions lock poisoned");
                    if !sessions.iter().any(|s| Arc::ptr_eq(s, &session_arc)) {
                        sessions.push(Arc::clone(&session_arc));
                    }
                }

                OwnedObjectPath::try_from(path)
                    .map_err(|e| ClientError::Failed(format!("invalid path: {e}")))
            }
        }
    }

    /// Remove an existing OBEX client session.
    ///
    /// D-Bus signature: `RemoveSession(o session_path)`
    ///
    /// The caller must be the original session owner; otherwise
    /// `org.bluez.obex.Error.NotAuthorized` is returned with the message
    /// `"Not Authorized"` (matching C manager.c line 233).
    #[zbus(name = "RemoveSession")]
    async fn remove_session(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        session: ObjectPath<'_>,
    ) -> Result<(), ClientError> {
        let path = session.as_str();

        // ── 1. Find session (manager.c lines 222-227) ────────────────
        let found = self.find_session(path).ok_or(ClientError::InvalidArguments)?;

        // ── 2. Verify ownership (manager.c lines 229-234) ────────────
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        {
            let guard = found.lock().expect("session lock poisoned");
            if guard.get_owner() != sender {
                return Err(ClientError::NotAuthorized);
            }
        }

        // ── 3. Release (remove + shutdown) ───────────────────────────
        self.release_session(&found);

        Ok(())
    }
}

// =====================================================================
// D-Bus dictionary parser — matches C parse_device_dict (lines 110-145)
// =====================================================================

/// Parse the `a{sv}` properties dictionary from a `CreateSession` call.
///
/// Returns `(source, target, channel, psm)`.  Unknown dictionary keys
/// are silently ignored, matching the C original.  Default values:
/// `source = None`, `target = None`, `channel = 0`, `psm = 0`.
fn parse_device_dict(
    args: &HashMap<String, OwnedValue>,
) -> (Option<String>, Option<String>, u8, u16) {
    let mut source: Option<String> = None;
    let mut target: Option<String> = None;
    let mut channel: u8 = 0;
    let mut psm: u16 = 0;

    for (key, value) in args {
        match key.as_str() {
            "Source" => {
                if let Ok(s) = String::try_from(value.clone()) {
                    source = Some(s);
                }
            }
            "Target" => {
                if let Ok(s) = String::try_from(value.clone()) {
                    target = Some(s);
                }
            }
            "Channel" => {
                if let Ok(v) = u8::try_from(value.clone()) {
                    channel = v;
                }
            }
            "PSM" => {
                if let Ok(v) = u16::try_from(value.clone()) {
                    psm = v;
                }
            }
            _ => { /* Ignore unknown keys — matching C behaviour. */ }
        }
    }

    (source, target, channel, psm)
}

// =====================================================================
// Module initialisation table — matches C modules[] (lines 251-264)
// =====================================================================

/// Init wrapper for the Bluetooth transport module.
///
/// `bluetooth_init` returns `Result<(), SessionError>` — this wrapper
/// normalises the error to `String` for the common [`ObcModule`]
/// contract.
fn bluetooth_init_wrapper() -> Result<(), String> {
    bluetooth_init().map_err(|e| format!("{e}"))
}

/// Init wrapper — OPP profile module.
fn opp_init_wrapper() -> Result<(), String> {
    opp_init();
    Ok(())
}

/// Init wrapper — FTP profile module.
fn ftp_init_wrapper() -> Result<(), String> {
    ftp_init();
    Ok(())
}

/// Init wrapper — PBAP profile module.
fn pbap_init_wrapper() -> Result<(), String> {
    pbap_init();
    Ok(())
}

/// Init wrapper — Synchronisation profile module.
fn sync_init_wrapper() -> Result<(), String> {
    sync_init();
    Ok(())
}

/// Init wrapper — MAP profile module.
fn map_init_wrapper() -> Result<(), String> {
    map_init();
    Ok(())
}

/// Init wrapper — BIP profile module.
fn bip_init_wrapper() -> Result<(), String> {
    bip_init();
    Ok(())
}

/// Descriptor for a single OBEX client sub-module carrying its name
/// and lifecycle hooks.
struct ObcModule {
    name: &'static str,
    init: fn() -> Result<(), String>,
    exit: fn(),
}

/// Module initialisation table.
///
/// The order **MUST** exactly match the C `modules[]` array
/// (manager.c lines 251-264):
///
///   `bluetooth` → `opp` → `ftp` → `pbap` → `sync` → `map` → `bip`
///
/// Module init is best-effort: failures are logged but do not prevent
/// subsequent modules from loading.
const MODULES: &[ObcModule] = &[
    ObcModule { name: "bluetooth", init: bluetooth_init_wrapper, exit: bluetooth_exit },
    ObcModule { name: "opp", init: opp_init_wrapper, exit: opp_exit },
    ObcModule { name: "ftp", init: ftp_init_wrapper, exit: ftp_exit },
    ObcModule { name: "pbap", init: pbap_init_wrapper, exit: pbap_exit },
    ObcModule { name: "sync", init: sync_init_wrapper, exit: sync_exit },
    ObcModule { name: "map", init: map_init_wrapper, exit: map_exit },
    ObcModule { name: "bip", init: bip_init_wrapper, exit: bip_exit },
];

// =====================================================================
// Top-level lifecycle — matches C client_manager_init/exit (lines 266-311)
// =====================================================================

/// Initialise the OBEX client manager.
///
/// Registers the `org.bluez.obex.Client1` D-Bus interface at
/// `/org/bluez/obex` and initialises all client sub-modules in the
/// defined order (matching C `client_manager_init`, lines 266-296).
///
/// Module init errors are logged but non-fatal: subsequent modules
/// continue to load.
pub async fn client_manager_init(
    conn: &Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = ClientManager::new(conn.clone());

    if let Err(e) = conn.object_server().at(CLIENT_PATH, manager).await {
        error!("Failed to register org.bluez.obex.Client1 at {}: {}", CLIENT_PATH, e);
        return Err(Box::new(e));
    }

    // Initialise modules in order — best effort.
    for module in MODULES {
        match (module.init)() {
            Ok(()) => {
                debug!("Module {} loaded", module.name);
            }
            Err(e) => {
                error!("Module {} init failed: {}", module.name, e);
            }
        }
    }

    Ok(())
}

/// Shut down the OBEX client manager.
///
/// Calls exit hooks for every sub-module and unregisters the Client1
/// interface from the D-Bus object server (matching C
/// `client_manager_exit`, lines 298-311).
pub async fn client_manager_exit(conn: &Connection) {
    // Exit all modules in table order.
    for module in MODULES {
        (module.exit)();
    }

    // Unregister the Client1 interface — ignore errors on shutdown.
    let _ = conn.object_server().remove::<ClientManager, _>(CLIENT_PATH).await;
}
