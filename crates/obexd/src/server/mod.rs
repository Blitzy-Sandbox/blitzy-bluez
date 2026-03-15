// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX server-side daemon core.
//!
//! This module provides the transport/service/MIME-type driver registries,
//! OBEX session engine, D-Bus manager layer, plugin framework, and server
//! lifecycle management for the BlueZ OBEX daemon.
//!
//! ## Architecture
//! - **transport** — Transport driver registry, [`ObexServer`] struct, connection acceptance
//! - **service** — Service driver registry, MIME type driver registry, OBEX session engine,
//!   D-Bus manager (AgentManager1/Session1/Transfer1), plugin framework, logging, and daemon constants
//!
//! ## Lifecycle
//!
//! The daemon calls the four lifecycle functions in this order during startup:
//!
//! 1. [`manager_init`] — Registers the AgentManager1 D-Bus interface and stores
//!    the D-Bus connection reference for subsystem access.
//! 2. [`obex_server_init`] — Creates the cross-product of registered transport
//!    drivers × service drivers, starting a listening server for each pair.
//!
//! During shutdown, the reverse sequence is:
//!
//! 1. [`obex_server_exit`] — Stops all active servers and releases transport resources.
//! 2. [`manager_cleanup`] — Unregisters the AgentManager1 interface and releases
//!    D-Bus connection resources.

pub mod service;
pub mod transport;

// ---------------------------------------------------------------------------
// Re-exports from transport sub-module
// ---------------------------------------------------------------------------

pub use transport::ObexServer;
pub use transport::ObexTransportDriver;
pub use transport::register_transport;
pub use transport::unregister_transport;

// ---------------------------------------------------------------------------
// Re-exports from service sub-module
// ---------------------------------------------------------------------------

pub use service::AgentManager;
pub use service::MapApTag;
pub use service::ObexMimeTypeDriver;
pub use service::ObexPlugin;
pub use service::ObexServiceDriver;
pub use service::ServerObexSession;
pub use service::register_mime_driver;
pub use service::register_service;
pub use service::unregister_mime_driver;
pub use service::unregister_service;

// ---------------------------------------------------------------------------
// Internal imports for lifecycle functions
// ---------------------------------------------------------------------------

use crate::obex::session::ObexError;

// ============================================================================
// Top-Level Lifecycle Functions
// ============================================================================

/// Initialise the OBEX D-Bus manager subsystem.
///
/// Performs the following steps (matching the C `manager_init()` from
/// `obexd/src/manager.c`):
///
/// 1. Stores the D-Bus connection reference so that other subsystems
///    (session registration, transfer emission, agent authorisation) can
///    access it via [`service::get_dbus_connection`].
/// 2. Registers the `org.bluez.obex.AgentManager1` D-Bus interface at the
///    OBEX base object path (`/org/bluez/obex`) using `zbus` ObjectServer.
/// 3. Logs successful initialisation via `tracing::info!`.
///
/// In the C original, `manager_init()` calls `obex_setup_dbus_connection()`
/// to acquire the well-known name `org.bluez.obex`, then
/// `g_dbus_attach_object_manager()` and `g_dbus_register_interface()` for
/// the AgentManager1 interface.  In the Rust version, well-known name
/// acquisition is handled by `main.rs`; this function handles only the
/// interface registration.
///
/// # Errors
///
/// Returns [`ObexError::Failed`] if the D-Bus interface registration fails.
pub async fn manager_init(conn: &zbus::Connection) -> Result<(), ObexError> {
    // Store the D-Bus connection for use by service subsystems (session
    // registration, transfer emission, agent authorisation proxy calls).
    service::set_dbus_connection(conn.clone());

    // Register the AgentManager1 interface at the OBEX base path.
    // This is the server-side equivalent of:
    //   g_dbus_register_interface(connection, OBEX_BASE_PATH,
    //       OBEX_MANAGER_INTERFACE, manager_methods, ..., ...)
    conn.object_server().at(service::OBEX_BASE_PATH, service::AgentManager).await.map_err(|e| {
        ObexError::Failed(format!(
            "Failed to register AgentManager1 at {}: {}",
            service::OBEX_BASE_PATH,
            e
        ))
    })?;

    tracing::info!("OBEX Manager initialized at {}", service::OBEX_BASE_PATH);

    Ok(())
}

/// Clean up the OBEX D-Bus manager subsystem.
///
/// Unregisters the `org.bluez.obex.AgentManager1` interface from the D-Bus
/// ObjectServer and releases any stored agent state.  This is called during
/// daemon shutdown, after [`obex_server_exit`] has stopped all servers.
///
/// Matches the C `manager_cleanup()` teardown sequence.
pub async fn manager_cleanup(conn: &zbus::Connection) {
    // Unregister the AgentManager1 interface from the D-Bus ObjectServer.
    // The remove() call returns a bool indicating success; we log on failure
    // but do not propagate the error since we are in shutdown.
    let removed =
        conn.object_server().remove::<service::AgentManager, _>(service::OBEX_BASE_PATH).await;

    match removed {
        Ok(true) => {
            tracing::debug!("AgentManager1 interface removed from {}", service::OBEX_BASE_PATH);
        }
        Ok(false) => {
            tracing::debug!(
                "AgentManager1 interface was not registered at {}",
                service::OBEX_BASE_PATH
            );
        }
        Err(e) => {
            tracing::error!(
                "Failed to remove AgentManager1 from {}: {}",
                service::OBEX_BASE_PATH,
                e
            );
        }
    }

    tracing::info!("OBEX Manager cleaned up");
}

/// Initialise the OBEX server subsystem.
///
/// Creates the cross-product of registered transport drivers × service
/// drivers.  For each transport driver, a server is created that combines
/// the transport with all applicable service drivers, and the transport's
/// `start()` method is called to begin listening for incoming connections.
///
/// Matches the C `obex_server_init()` in `obexd/src/server.c`:
///
/// ```text
/// 1. drivers = obex_service_driver_list(0)      // all service drivers
/// 2. transports = obex_transport_driver_list()   // all transport drivers
/// 3. for each driver:
///        init_server(driver.service, transports) // create servers
/// ```
///
/// In the Rust architecture, the server state is first reset via
/// [`transport::obex_server_init`], then the cross-product iteration is
/// driven from here, calling [`transport::init_server`] for each transport.
///
/// # Errors
///
/// Returns [`ObexError::Failed`] if no service drivers or no transport
/// drivers are registered (matching the C `-EINVAL` return).  Individual
/// transport start failures are logged and skipped (matching the C
/// `DBG("Unable to start %s transport: ...")` behavior).
pub async fn obex_server_init() -> Result<(), ObexError> {
    // Step 1: Reset the server registry to a clean state.
    transport::obex_server_init().await?;

    // Step 2: Retrieve all registered service drivers (mask=0 → all).
    let services = service::list_services(0);
    if services.is_empty() {
        tracing::debug!("No service driver registered");
        return Err(ObexError::Failed("No service driver registered".into()));
    }

    // Step 3: Retrieve all registered transport drivers.
    let transports = transport::list_transports();
    if transports.is_empty() {
        tracing::debug!("No transport driver registered");
        return Err(ObexError::Failed("No transport driver registered".into()));
    }

    // Step 4: Create servers — iterate transports and start a server for
    // each one that can accept connections.
    //
    // In the C original, the outer loop is over service drivers and the
    // inner loop over transports, with a service-mask compatibility check.
    // The Rust architecture uses a simpler model: each transport receives
    // the full service driver list.  Service matching at connection time
    // is handled by the session engine (service::parse_service).
    //
    // This produces one server per transport, each carrying all service
    // drivers — functionally equivalent to the C model for the Bluetooth
    // transport (which uses service=0 to indicate support for all
    // services).
    let mut server_count: usize = 0;

    for transport_name in &transports {
        match transport::init_server(transport_name, services.clone()).await {
            Ok(()) => {
                server_count += 1;
            }
            Err(e) => {
                // Match C behavior: log failure and continue to next transport.
                // The C code logs "Unable to start %s transport: %s (%d)" and
                // frees the server, then continues the loop.
                tracing::error!("Unable to start '{}' transport: {}", transport_name, e);
            }
        }
    }

    tracing::info!("{} OBEX server(s) initialized", server_count);

    Ok(())
}

/// Shut down all active OBEX servers and release transport resources.
///
/// Delegates to [`transport::obex_server_exit`] which iterates all active
/// servers, calls each transport driver's `stop()` method with the server's
/// opaque transport data, and clears the global server list.
///
/// Matches the C `obex_server_exit()` in `obexd/src/server.c`:
///
/// ```text
/// for each server:
///     server->transport->stop(server->transport_data)
///     g_slist_free(server->drivers)
///     g_free(server)
/// g_slist_free(servers)
/// ```
pub async fn obex_server_exit() {
    transport::obex_server_exit().await;
    tracing::info!("OBEX servers shut down");
}
