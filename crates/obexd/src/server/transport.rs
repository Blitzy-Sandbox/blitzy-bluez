// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX transport driver registry and server orchestration.
//
// Rust rewrite of obexd/src/transport.c (82 lines), obexd/src/transport.h
// (24 lines), obexd/src/server.c (116 lines), and obexd/src/server.h
// (33 lines) from BlueZ v5.86.
//
// Provides:
//   - [`ObexTransportDriver`] trait — replaces C `struct obex_transport_driver`
//   - [`ObexServer`] struct — replaces C `struct obex_server`
//   - Transport driver registry: [`register_transport`], [`unregister_transport`],
//     [`list_transports`], [`find_transport`]
//   - Server lifecycle: [`init_server`], [`obex_server_init`],
//     [`obex_server_exit`], [`obex_server_new_connection`]
//
// Global state uses `OnceLock<Mutex<Vec<…>>>` replacing the C static
// `GSList *drivers` and `GSList *servers` variables.
//
// All trait methods are synchronous (matching the C function-pointer semantics).
// Public server lifecycle functions are `async` for compatibility with the
// tokio-based daemon event loop.

use std::any::Any;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, OnceLock};

use crate::obex::session::{ObexError, TransportType};

// ---------------------------------------------------------------------------
// ObexTransportDriver trait — replaces C struct obex_transport_driver
// ---------------------------------------------------------------------------

/// OBEX transport driver interface.
///
/// Each transport back-end (e.g., Bluetooth RFCOMM, Bluetooth L2CAP)
/// implements this trait and registers itself via [`register_transport`].
///
/// The C original uses a struct with function pointers:
///
/// ```c
/// struct obex_transport_driver {
///     const char *name;
///     uint16_t service;
///     void *(*start)(struct obex_server *server, int *err);
///     int (*getpeername)(GIOChannel *io, char **name);
///     int (*getsockname)(GIOChannel *io, char **name);
///     void (*stop)(void *data);
/// };
/// ```
///
/// In Rust, these become trait methods with typed signatures and
/// `Result`-based error handling.
pub trait ObexTransportDriver: Send + Sync {
    /// Unique name identifying this transport (e.g., `"bluetooth"`).
    ///
    /// Must be non-empty and unique across all registered drivers.
    fn name(&self) -> &str;

    /// Service bitmask — which OBEX services this transport supports.
    ///
    /// Uses the OBEX service flag constants (OBEX_OPP = 1 << 1,
    /// OBEX_FTP = 1 << 2, etc.) from the service layer.  A value of `0`
    /// indicates support for all services.
    fn service(&self) -> u16;

    /// Start listening for incoming connections.
    ///
    /// Called once during server initialization.  Returns transport-specific
    /// opaque state (e.g., a listening socket handle, a spawned task
    /// `JoinHandle`) on success.
    ///
    /// Replaces: `void *(*start)(struct obex_server *server, int *err)`
    fn start(&self, server: &ObexServer) -> Result<Box<dyn Any + Send>, ObexError>;

    /// Retrieve the remote peer address string for an accepted connection.
    ///
    /// Replaces: `int (*getpeername)(GIOChannel *io, char **name)`
    fn getpeername(&self, fd: &OwnedFd) -> Result<String, ObexError>;

    /// Retrieve the local socket address string for a connection.
    ///
    /// Replaces: `int (*getsockname)(GIOChannel *io, char **name)`
    fn getsockname(&self, fd: &OwnedFd) -> Result<String, ObexError>;

    /// Stop the transport and release all resources.
    ///
    /// The `transport_data` parameter is the opaque value originally returned
    /// from [`start`](ObexTransportDriver::start).
    ///
    /// Replaces: `void (*stop)(void *data)`
    fn stop(&self, transport_data: Box<dyn Any + Send>);
}

// ---------------------------------------------------------------------------
// ObexServer — replaces C struct obex_server
// ---------------------------------------------------------------------------

/// An active OBEX server instance linking a transport driver to its
/// applicable service drivers.
///
/// The C original:
///
/// ```c
/// struct obex_server {
///     struct obex_transport_driver *transport_driver;
///     void *transport_data;
///     GSList *drivers;   // list of obex_service_driver
/// };
/// ```
///
/// In Rust, the transport driver is identified by name (looked up in the
/// global registry), `transport_data` is a type-erased `Box<dyn Any + Send>`
/// (replacing `void *`), and the service driver list is a `Vec<String>` of
/// driver names (replacing `GSList *` of raw pointers).
pub struct ObexServer {
    /// Name of the transport driver managing this server's connections.
    pub transport_driver_name: String,

    /// Opaque transport-specific state returned from
    /// [`ObexTransportDriver::start`].
    ///
    /// `None` until the transport has been successfully started.
    /// Replaces C `void *transport_data`.
    pub transport_data: Option<Box<dyn Any + Send>>,

    /// Names of OBEX service drivers applicable to this server
    /// (e.g., `"opp"`, `"ftp"`, `"pbap"`).
    ///
    /// Replaces C `GSList *drivers` (list of `struct obex_service_driver *`).
    pub service_drivers: Vec<String>,
}

// ---------------------------------------------------------------------------
// Global state — replaces C static GSList *drivers and GSList *servers
// ---------------------------------------------------------------------------

/// Global transport driver registry.
///
/// Uses `Arc<dyn ObexTransportDriver>` (rather than bare `Box`) so that
/// driver references can be cloned out of the lock scope for async
/// operations without holding the `Mutex` guard across `await` points.
static TRANSPORT_DRIVERS: OnceLock<Mutex<Vec<Arc<dyn ObexTransportDriver>>>> = OnceLock::new();

/// Global list of active OBEX server instances.
static SERVERS: OnceLock<Mutex<Vec<ObexServer>>> = OnceLock::new();

/// Accessor for the transport driver registry, initialising it on first use.
fn drivers() -> &'static Mutex<Vec<Arc<dyn ObexTransportDriver>>> {
    TRANSPORT_DRIVERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Accessor for the server list, initialising it on first use.
fn servers() -> &'static Mutex<Vec<ObexServer>> {
    SERVERS.get_or_init(|| Mutex::new(Vec::new()))
}

// ---------------------------------------------------------------------------
// Transport driver registry operations
// ---------------------------------------------------------------------------

/// Register a transport driver.
///
/// The driver name must be non-empty and unique.  Returns
/// [`ObexError::InvalidArgs`] for an empty name or [`ObexError::Failed`]
/// if a driver with the same name is already registered (matching the C
/// `-EALREADY` semantics).
///
/// Drivers are *prepended* to the registry list, preserving the C
/// `g_slist_prepend` insertion order.
///
/// Source: `obexd/src/transport.c` — `obex_transport_driver_register()`.
pub fn register_transport(driver: Box<dyn ObexTransportDriver>) -> Result<(), ObexError> {
    let name = driver.name().to_owned();
    if name.is_empty() {
        return Err(ObexError::InvalidArgs("transport driver name must not be empty".into()));
    }

    let mut drv_list = drivers()
        .lock()
        .map_err(|_| ObexError::Failed("transport driver registry lock poisoned".into()))?;

    // Check for duplicate — matches C `find(name)` guard.
    if drv_list.iter().any(|d| d.name() == name) {
        return Err(ObexError::Failed(format!("transport driver '{}' already registered", name)));
    }

    // Prepend, matching C g_slist_prepend semantics.
    drv_list.insert(0, Arc::from(driver));
    tracing::debug!("Transport driver registered: {}", name);
    Ok(())
}

/// Unregister a transport driver by name.
///
/// Logs a warning if no driver with the given name is found, matching the C
/// guard that checks `g_slist_find` before removal.
///
/// Source: `obexd/src/transport.c` — `obex_transport_driver_unregister()`.
pub fn unregister_transport(name: &str) {
    let Ok(mut drv_list) = drivers().lock() else {
        tracing::warn!(
            "Failed to acquire transport driver registry lock for unregister of '{}'",
            name
        );
        return;
    };

    let before = drv_list.len();
    drv_list.retain(|d| d.name() != name);

    if drv_list.len() == before {
        tracing::warn!("Transport driver '{}' not found for unregister", name);
    } else {
        tracing::info!("Transport driver unregistered: {}", name);
    }
}

/// Return the names of all registered transport drivers.
///
/// Source: `obexd/src/transport.c` — `obex_transport_driver_list()`.
pub fn list_transports() -> Vec<String> {
    let Ok(drv_list) = drivers().lock() else {
        return Vec::new();
    };
    drv_list.iter().map(|d| d.name().to_owned()).collect()
}

/// Check whether a transport driver with the given name is registered.
///
/// Source: `obexd/src/transport.c` — `find()` helper.
pub fn find_transport(name: &str) -> bool {
    let Ok(drv_list) = drivers().lock() else {
        return false;
    };
    drv_list.iter().any(|d| d.name() == name)
}

// ---------------------------------------------------------------------------
// Server lifecycle — replaces obexd/src/server.c
// ---------------------------------------------------------------------------

/// Create and start an OBEX server for a specific transport.
///
/// `service_drivers` lists the service driver names applicable to this
/// server (e.g., `["opp", "ftp"]`).  If the list is empty, no server is
/// created — matching the C behaviour where `init_server()` returns early
/// when `obex_service_driver_list(service)` yields an empty list.
///
/// The transport driver is located by name in the global registry, its
/// `start()` method is called to begin listening, and the resulting server
/// is prepended to the global server list.
///
/// Source: `obexd/src/server.c` — `init_server()`.
pub async fn init_server(
    transport_name: &str,
    service_drivers: Vec<String>,
) -> Result<(), ObexError> {
    if service_drivers.is_empty() {
        tracing::info!(
            "No service drivers for transport '{}', skipping server creation",
            transport_name
        );
        return Ok(());
    }

    // Clone an Arc handle to the transport driver so we can release the
    // registry lock before calling start().
    let transport = {
        let drv_list = drivers()
            .lock()
            .map_err(|_| ObexError::Failed("transport driver registry lock poisoned".into()))?;
        drv_list.iter().find(|d| d.name() == transport_name).cloned().ok_or_else(|| {
            ObexError::Failed(format!("transport '{}' not found in registry", transport_name))
        })?
    }; // Registry lock released.

    // Build the server struct (transport_data will be filled after start).
    let mut server = ObexServer {
        transport_driver_name: transport_name.to_owned(),
        transport_data: None,
        service_drivers,
    };

    // Start the transport listener.
    match transport.start(&server) {
        Ok(data) => {
            server.transport_data = Some(data);
        }
        Err(e) => {
            tracing::error!("Failed to start transport '{}': {}", transport_name, e);
            return Err(e);
        }
    }

    // Register the server (prepend, matching C g_slist_prepend).
    servers()
        .lock()
        .map_err(|_| ObexError::Failed("server registry lock poisoned".into()))?
        .insert(0, server);

    tracing::info!("OBEX server started for transport: {}", transport_name);
    Ok(())
}

/// Initialise the OBEX server subsystem.
///
/// Resets the server registry to a clean state.  The orchestration layer
/// (`server/mod.rs`) subsequently calls [`init_server`] for each
/// (transport, service-set) pair to create the cross-product of transport
/// drivers × service drivers.
///
/// The C `obex_server_init()` performs both the reset and the cross-product
/// iteration internally.  In the Rust architecture, the iteration is
/// separated into [`init_server`] calls driven by the module orchestrator
/// for cleaner dependency management.
///
/// Source: `obexd/src/server.c` — `obex_server_init()`.
pub async fn obex_server_init() -> Result<(), ObexError> {
    {
        let mut srv_list = servers()
            .lock()
            .map_err(|_| ObexError::Failed("server registry lock poisoned".into()))?;
        srv_list.clear();
    }
    tracing::info!("OBEX server subsystem initialized");
    Ok(())
}

/// Shut down all OBEX servers and release transport resources.
///
/// For each active server, calls the transport driver's `stop()` method
/// with the server's opaque transport data, then drops the server struct.
/// The server list is cleared.
///
/// Matches the C `obex_server_exit()` which iterates servers calling
/// `transport->stop(transport_data)` and then frees the list.
///
/// Source: `obexd/src/server.c` — `obex_server_exit()`.
pub async fn obex_server_exit() {
    // Drain the server list (brief lock).
    let server_list = {
        let mut srv_list = match servers().lock() {
            Ok(s) => s,
            Err(_) => {
                tracing::error!("Failed to lock server registry for shutdown");
                return;
            }
        };
        std::mem::take(&mut *srv_list)
    };

    // Stop each transport, releasing resources.
    for mut server in server_list {
        if let Some(data) = server.transport_data.take() {
            // Clone an Arc to the matching transport driver.
            let transport = {
                let drv_list = match drivers().lock() {
                    Ok(d) => d,
                    Err(_) => {
                        tracing::error!(
                            "Failed to lock transport registry while stopping '{}'",
                            server.transport_driver_name
                        );
                        continue;
                    }
                };
                drv_list.iter().find(|d| d.name() == server.transport_driver_name).cloned()
            };

            if let Some(t) = transport {
                t.stop(data);
            } else {
                tracing::warn!(
                    "Transport driver '{}' not found during server shutdown; \
                     transport data dropped without stop()",
                    server.transport_driver_name
                );
            }
        }
        // `server` dropped here — `service_drivers` Vec freed automatically.
    }

    tracing::info!("OBEX servers stopped");
}

/// Accept a new incoming connection on the given server.
///
/// Determines the [`TransportType`] (stream vs. packet) from the `stream`
/// parameter and creates an OBEX session for the connection via
/// [`ObexSession::new`](crate::obex::session::ObexSession::new).
///
/// In the C original, `obex_server_new_connection()` delegates directly to
/// `obex_session_start(io, tx_mtu, rx_mtu, stream, server)` which creates a
/// GObex session, registers service-specific request handlers, and starts
/// the I/O event loop.  In the Rust architecture, full service handler
/// registration is managed by the server module orchestrator (`service.rs`).
///
/// Source: `obexd/src/server.c` — `obex_server_new_connection()`.
pub async fn obex_server_new_connection(
    server_index: usize,
    fd: OwnedFd,
    tx_mtu: u16,
    rx_mtu: u16,
    stream: bool,
) -> Result<(), ObexError> {
    let transport_type = if stream { TransportType::Stream } else { TransportType::Packet };

    // Validate that the server index is valid and retrieve its name for logging.
    let driver_name = {
        let srv_list = servers()
            .lock()
            .map_err(|_| ObexError::Failed("server registry lock poisoned".into()))?;
        let srv = srv_list.get(server_index).ok_or_else(|| {
            ObexError::InvalidArgs(format!("invalid server index: {server_index}"))
        })?;
        srv.transport_driver_name.clone()
    };

    tracing::debug!(
        "New {} connection on transport '{}' (tx_mtu={}, rx_mtu={})",
        if stream { "stream" } else { "packet" },
        driver_name,
        tx_mtu,
        rx_mtu,
    );

    // Create OBEX session engine for this connection.
    // ObexSession::new() takes ownership of the fd and wraps it in an AsyncFd,
    // validating that the fd is usable for async I/O.  This corresponds to the
    // g_obex_new() call inside the C obex_session_start().
    //
    // The session is currently dropped at the end of this scope.  In the fully
    // integrated system, the service orchestration layer stores the session and
    // drives the OBEX request/response lifecycle by registering handlers for
    // the server's service_drivers.
    let _session = crate::obex::session::ObexSession::new(
        fd,
        transport_type,
        rx_mtu as usize,
        tx_mtu as usize,
    )?;

    tracing::info!("OBEX session accepted for transport '{}'", driver_name);
    Ok(())
}
