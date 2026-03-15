// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! Bluetooth transport plugin for the OBEX daemon.
//!
//! Complete Rust rewrite of `obexd/plugins/bluetooth.c` — the Bluetooth
//! transport plugin integrating obexd with BlueZ via the
//! `org.bluez.Profile1` D-Bus interface.
//!
//! This is the **sole** transport plugin: without it, obexd cannot accept
//! any Bluetooth connections.  The plugin:
//!
//! 1. Maps OBEX service types to Bluetooth SIG UUIDs.
//! 2. Registers a `org.bluez.Profile1` D-Bus object for each enabled
//!    service on the BlueZ `ProfileManager1`.
//! 3. Watches for the `org.bluez` well-known D-Bus name so profiles are
//!    re-registered whenever BlueZ restarts.
//! 4. Accepts incoming connections via `Profile1.NewConnection`, queries
//!    socket MTU, and forwards the fd to the OBEX session engine.
//! 5. Provides address lookup helpers for connection logging.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, OnceLock};

use futures::StreamExt;

use tokio::sync::Mutex as TokioMutex;

use bluez_shared::socket::{
    BtTransport, bt_get_dest_address, bt_get_source_address, bt_sockopt_get_int,
    bt_sockopt_get_l2cap_options,
};

use crate::server::transport::obex_server_new_connection;

use super::{
    OBEX_FTP, OBEX_IRMC, OBEX_MAS, OBEX_MNS, OBEX_OPP, OBEX_PBAP, OBEX_PCSUITE, OBEX_SYNCEVOLUTION,
    ObexPluginDesc, ObexServer, ObexServiceDriver, ObexTransportDriver, list_service_drivers,
    obex_transport_driver_register, obex_transport_driver_unregister,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum receive MTU used for RFCOMM (stream) transports.
const BT_RX_MTU: u16 = 32767;

/// Default maximum transmit MTU used for RFCOMM (stream) transports.
const BT_TX_MTU: u16 = 32767;

// ---------------------------------------------------------------------------
// Service ↔ UUID mapping  (from bluetooth.c service2uuid())
// ---------------------------------------------------------------------------

/// Map an OBEX service bitmask constant to the corresponding Bluetooth SIG
/// UUID string used for `ProfileManager1.RegisterProfile`.
///
/// Returns `None` for unrecognised service types.
fn service2uuid(service: u16) -> Option<&'static str> {
    match service {
        s if s == OBEX_OPP => Some("00001105-0000-1000-8000-00805f9b34fb"),
        s if s == OBEX_FTP => Some("00001106-0000-1000-8000-00805f9b34fb"),
        s if s == OBEX_PBAP => Some("0000112f-0000-1000-8000-00805f9b34fb"),
        s if s == OBEX_IRMC => Some("00001104-0000-1000-8000-00805f9b34fb"),
        s if s == OBEX_PCSUITE => Some("00005005-0000-1000-8000-0002ee000001"),
        s if s == OBEX_SYNCEVOLUTION => Some("00000002-0000-1000-8000-0002ee000002"),
        s if s == OBEX_MAS => Some("00001132-0000-1000-8000-00805f9b34fb"),
        s if s == OBEX_MNS => Some("00001133-0000-1000-8000-00805f9b34fb"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Internal state structures
// ---------------------------------------------------------------------------

/// Registered Bluetooth profile — one per OBEX service that maps to a UUID.
struct BluetoothProfile {
    /// Bluetooth SIG UUID (full 128-bit lowercase string).
    uuid: String,
    /// Reference to the service driver this profile was created from.
    driver: Arc<dyn ObexServiceDriver>,
    /// D-Bus object path where Profile1 is registered, or `None` if
    /// the profile is not currently registered (BlueZ is absent).
    path: Option<String>,
}

/// Module-level shared state protected by an async mutex.
struct BluetoothState {
    /// Active profiles (one per enabled OBEX service).
    profiles: Vec<BluetoothProfile>,
    /// System D-Bus connection (created on init, dropped on exit).
    conn: Option<zbus::Connection>,
    /// Handle for the BlueZ name-watcher background task.
    watcher_handle: Option<tokio::task::JoinHandle<()>>,
    /// Server index passed to `obex_server_new_connection`.
    server_index: usize,
}

impl BluetoothState {
    fn new() -> Self {
        Self { profiles: Vec::new(), conn: None, watcher_handle: None, server_index: 0 }
    }
}

/// Address cache for `getpeername` / `getsockname` lookups.
///
/// Populated when `Profile1.NewConnection` is called and the fd is
/// still available.  Keyed by the raw fd value passed to the OBEX
/// session engine.
struct AddressCache {
    peer: HashMap<RawFd, String>,
    local: HashMap<RawFd, String>,
}

impl AddressCache {
    fn new() -> Self {
        Self { peer: HashMap::new(), local: HashMap::new() }
    }
}

// ---------------------------------------------------------------------------
// Global singletons
// ---------------------------------------------------------------------------

/// Shared async state.
fn global_state() -> &'static TokioMutex<BluetoothState> {
    static STATE: OnceLock<TokioMutex<BluetoothState>> = OnceLock::new();
    STATE.get_or_init(|| TokioMutex::new(BluetoothState::new()))
}

/// Thread-safe address cache (sync mutex so getpeername/getsockname work in
/// sync trait methods).
fn address_cache() -> &'static std::sync::Mutex<AddressCache> {
    static CACHE: OnceLock<std::sync::Mutex<AddressCache>> = OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(AddressCache::new()))
}

// ---------------------------------------------------------------------------
// Bluetooth transport driver
// ---------------------------------------------------------------------------

/// OBEX transport driver implementation for Bluetooth connections.
///
/// Replaces the C `struct obex_transport_driver bluetooth_driver`.
pub struct BluetoothTransportDriver;

impl ObexTransportDriver for BluetoothTransportDriver {
    fn name(&self) -> &str {
        "bluetooth"
    }

    /// Start the Bluetooth transport for the given server.
    ///
    /// Iterates the server's service drivers, maps each service type to a
    /// Bluetooth SIG UUID via [`service2uuid`], and creates a
    /// [`BluetoothProfile`] entry for later D-Bus registration.
    fn start(&self, server: &ObexServer) -> Result<(), i32> {
        let all_service_drivers = list_service_drivers();
        let rt = tokio::runtime::Handle::try_current().map_err(|_| -libc::EINVAL)?;

        rt.block_on(async {
            let mut state = global_state().lock().await;

            for driver_name in &server.service_drivers {
                let driver =
                    match all_service_drivers.iter().find(|d| d.name() == driver_name.as_str()) {
                        Some(d) => Arc::clone(d),
                        None => {
                            tracing::warn!(
                                "bluetooth: service driver '{}' not found in registry",
                                driver_name
                            );
                            continue;
                        }
                    };

                let service = driver.service();
                let uuid = match service2uuid(service) {
                    Some(u) => u,
                    None => {
                        tracing::debug!(
                            "bluetooth: no UUID for service 0x{:04x} (driver '{}')",
                            service,
                            driver_name
                        );
                        continue;
                    }
                };

                tracing::info!(
                    "bluetooth: registered profile for '{}' (UUID {})",
                    driver_name,
                    uuid
                );

                state.profiles.push(BluetoothProfile {
                    uuid: uuid.to_string(),
                    driver,
                    path: None,
                });
            }

            Ok(())
        })
    }

    /// Stop the Bluetooth transport — unregister all profiles and clear state.
    fn stop(&self) {
        let rt = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => return,
        };

        rt.block_on(async {
            let mut state = global_state().lock().await;

            // Clone the connection before iterating profiles to satisfy borrow checker.
            let conn = state.conn.clone();
            if let Some(conn) = conn.as_ref() {
                for profile in &mut state.profiles {
                    unregister_profile(conn, profile).await;
                }
            }

            state.profiles.clear();
        });
    }

    /// Retrieve the remote (peer) Bluetooth address for a connection fd.
    ///
    /// Looks up the address from the cache populated in
    /// [`BluetoothProfileInterface::new_connection`].  Falls back to a
    /// direct socket query if the cache misses.
    fn getpeername(&self, fd: RawFd) -> Option<String> {
        // Try the cached value first.
        if let Ok(cache) = address_cache().lock() {
            if let Some(addr) = cache.peer.get(&fd) {
                return Some(addr.clone());
            }
        }

        // Direct query: determine socket type then read peer address.
        let transport = socket_transport(fd)?;
        let (addr, _) = bt_get_dest_address(fd, transport).ok()?;
        Some(addr.to_string())
    }

    /// Retrieve the local (source) Bluetooth address for a connection fd.
    fn getsockname(&self, fd: RawFd) -> Option<String> {
        // Try the cached value first.
        if let Ok(cache) = address_cache().lock() {
            if let Some(addr) = cache.local.get(&fd) {
                return Some(addr.clone());
            }
        }

        // Direct query.
        let transport = socket_transport(fd)?;
        let (addr, _) = bt_get_source_address(fd, transport).ok()?;
        Some(addr.to_string())
    }
}

// ---------------------------------------------------------------------------
// Profile1 D-Bus interface
// ---------------------------------------------------------------------------

/// D-Bus object implementing `org.bluez.Profile1` for a specific OBEX service.
///
/// One instance is created for each [`BluetoothProfile`] and registered at a
/// unique object path under `/org/bluez/obex/`.
pub struct BluetoothProfileInterface {
    /// Back-reference to the driver's service type (for logging).
    driver_name: String,
}

impl BluetoothProfileInterface {
    /// Create a new Profile1 interface for the given driver.
    fn new(driver_name: String) -> Self {
        Self { driver_name }
    }
}

#[zbus::interface(name = "org.bluez.Profile1")]
impl BluetoothProfileInterface {
    /// Called when BlueZ no longer needs this profile.
    async fn release(&self) -> zbus::fdo::Result<()> {
        tracing::debug!("bluetooth: Profile1.Release for '{}'", self.driver_name);
        Ok(())
    }

    /// Called when a new Bluetooth connection is established for this profile.
    ///
    /// Validates the fd, determines socket type and MTU, caches the
    /// connection addresses, and forwards the connection to the OBEX session
    /// engine.
    async fn new_connection(
        &self,
        device: zbus::zvariant::ObjectPath<'_>,
        fd: zbus::zvariant::Fd<'_>,
        _properties: HashMap<String, zbus::zvariant::Value<'_>>,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!(
            "bluetooth: Profile1.NewConnection from {} for '{}'",
            device.as_str(),
            self.driver_name
        );

        // Take ownership of the file descriptor by cloning it.
        let owned_fd: OwnedFd = OwnedFd::try_from(fd)
            .map_err(|e| zbus::fdo::Error::Failed(format!("fd clone failed: {e}")))?;

        let raw = owned_fd.as_raw_fd();

        // Validate the file descriptor with fcntl(F_GETFD).
        // Use bt_sockopt_get_int to query SO_TYPE — if that fails, fd is bad.
        if bt_sockopt_get_int(raw, libc::SOL_SOCKET, libc::SO_TYPE).is_err() {
            return Err(zbus::fdo::Error::InvalidArgs("received invalid file descriptor".into()));
        }

        // Determine socket type: SEQPACKET (L2CAP) vs STREAM (RFCOMM).
        let sock_type_int = bt_sockopt_get_int(raw, libc::SOL_SOCKET, libc::SO_TYPE)
            .map_err(|e| zbus::fdo::Error::Failed(format!("getsockopt(SO_TYPE): {e}")))?;
        let is_seqpacket = sock_type_int == libc::SOCK_SEQPACKET;
        let transport = if is_seqpacket { BtTransport::L2cap } else { BtTransport::Rfcomm };
        let is_stream = !is_seqpacket;

        // Read MTUs: use L2CAP socket options for packet-mode, defaults for stream.
        let (tx_mtu, rx_mtu) = if is_seqpacket {
            match bt_sockopt_get_l2cap_options(raw) {
                Ok(opts) => (opts.omtu, opts.imtu),
                Err(_) => (BT_TX_MTU, BT_RX_MTU),
            }
        } else {
            (BT_TX_MTU, BT_RX_MTU)
        };

        // Cache addresses for getpeername/getsockname.
        if let Ok(mut cache) = address_cache().lock() {
            if let Ok((peer_addr, _)) = bt_get_dest_address(raw, transport) {
                cache.peer.insert(raw, peer_addr.to_string());
            }
            if let Ok((local_addr, _)) = bt_get_source_address(raw, transport) {
                cache.local.insert(raw, local_addr.to_string());
            }
        }

        // Retrieve the server index.
        let server_idx = {
            let state = global_state().lock().await;
            state.server_index
        };

        tracing::info!(
            "bluetooth: new {} connection for '{}' (tx_mtu={}, rx_mtu={})",
            if is_stream { "stream" } else { "packet" },
            self.driver_name,
            tx_mtu,
            rx_mtu,
        );

        // Forward to OBEX session engine.
        obex_server_new_connection(server_idx, owned_fd, tx_mtu, rx_mtu, is_stream)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("session creation failed: {e}")))?;

        Ok(())
    }

    /// Called when BlueZ requests disconnection of a device.
    async fn request_disconnection(
        &self,
        device: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!(
            "bluetooth: Profile1.RequestDisconnection from {} for '{}'",
            device.as_str(),
            self.driver_name,
        );
        Ok(())
    }

    /// Called when a pending connection request is cancelled.
    async fn cancel(&self) -> zbus::fdo::Result<()> {
        tracing::debug!("bluetooth: Profile1.Cancel for '{}'", self.driver_name);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Profile registration / unregistration with BlueZ ProfileManager1
// ---------------------------------------------------------------------------

/// Generate a D-Bus object path for a profile UUID.
///
/// Path format: `/org/bluez/obex/<uuid>` with hyphens replaced by
/// underscores (matching the C implementation).
fn profile_path(uuid: &str) -> String {
    format!("/org/bluez/obex/{}", uuid.replace('-', "_"))
}

/// Register a single profile with BlueZ.
///
/// 1. Creates a D-Bus object at the profile path with the `Profile1` interface.
/// 2. Calls `ProfileManager1.RegisterProfile` on `/org/bluez`.
async fn register_profile(conn: &zbus::Connection, profile: &mut BluetoothProfile) {
    if profile.path.is_some() {
        return; // Already registered.
    }

    let path = profile_path(&profile.uuid);

    // Register the Profile1 D-Bus object.
    let iface = BluetoothProfileInterface::new(profile.driver.name().to_string());
    let obj_path = match zbus::zvariant::ObjectPath::try_from(path.as_str()) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("bluetooth: invalid object path '{}': {}", path, e);
            return;
        }
    };

    if let Err(e) = conn.object_server().at(obj_path.clone(), iface).await {
        tracing::error!("bluetooth: failed to register Profile1 at {}: {}", path, e);
        return;
    }

    // Build RegisterProfile options dictionary.
    let mut options: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
    options.insert("AutoConnect", zbus::zvariant::Value::Bool(false));

    // If the service driver provides an SDP record template, substitute
    // channel/name and add it to the options.
    if let Some(record_template) = profile.driver.record() {
        let record_xml =
            format_sdp_record(record_template, profile.driver.channel(), profile.driver.name());
        options.insert("ServiceRecord", zbus::zvariant::Value::from(record_xml));
    }

    // Call ProfileManager1.RegisterProfile.
    let result = call_register_profile(conn, &path, &profile.uuid, options).await;
    match result {
        Ok(()) => {
            tracing::info!("bluetooth: registered profile {} (UUID {})", path, profile.uuid);
            profile.path = Some(path);
        }
        Err(e) => {
            tracing::error!("bluetooth: RegisterProfile failed for UUID {}: {}", profile.uuid, e);
            // Clean up the D-Bus object we just registered.
            let _ = conn.object_server().remove::<BluetoothProfileInterface, _>(obj_path).await;
        }
    }
}

/// Call `org.bluez.ProfileManager1.RegisterProfile` via D-Bus.
async fn call_register_profile(
    conn: &zbus::Connection,
    object_path: &str,
    uuid: &str,
    options: HashMap<&str, zbus::zvariant::Value<'_>>,
) -> Result<(), String> {
    let proxy = zbus::Proxy::new(conn, "org.bluez", "/org/bluez", "org.bluez.ProfileManager1")
        .await
        .map_err(|e| format!("proxy creation: {e}"))?;

    let obj_path = zbus::zvariant::ObjectPath::try_from(object_path)
        .map_err(|e| format!("path conversion: {e}"))?;

    proxy
        .call_method("RegisterProfile", &(obj_path, uuid, options))
        .await
        .map_err(|e| format!("{e}"))?;

    Ok(())
}

/// Call `org.bluez.ProfileManager1.UnregisterProfile` via D-Bus.
async fn call_unregister_profile(conn: &zbus::Connection, object_path: &str) {
    let proxy = match zbus::Proxy::new(conn, "org.bluez", "/org/bluez", "org.bluez.ProfileManager1")
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("bluetooth: cannot create ProfileManager1 proxy: {}", e);
            return;
        }
    };

    let obj_path = match zbus::zvariant::ObjectPath::try_from(object_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("bluetooth: invalid path '{}': {}", object_path, e);
            return;
        }
    };

    if let Err(e) = proxy.call_method("UnregisterProfile", &(obj_path,)).await {
        tracing::error!("bluetooth: UnregisterProfile('{}') failed: {}", object_path, e);
    }
}

/// Unregister a profile from D-Bus and BlueZ.
async fn unregister_profile(conn: &zbus::Connection, profile: &mut BluetoothProfile) {
    let path = match profile.path.take() {
        Some(p) => p,
        None => return,
    };

    // Unregister from D-Bus object server.
    if let Ok(obj_path) = zbus::zvariant::ObjectPath::try_from(path.as_str()) {
        let _ = conn.object_server().remove::<BluetoothProfileInterface, _>(obj_path).await;
    }

    // Tell BlueZ to forget this profile.
    call_unregister_profile(conn, &path).await;
}

// ---------------------------------------------------------------------------
// SDP record formatting helper
// ---------------------------------------------------------------------------

/// Substitute `%u` (channel) and `%s` (name) placeholders in an SDP
/// record XML template.
///
/// This mirrors the C `register_profile` logic which performs:
///   `g_markup_printf_escaped(record, channel, name)`
fn format_sdp_record(template: &str, channel: u8, name: &str) -> String {
    // The C template uses printf-style `%u` for channel and `%s` for name.
    // We perform two simple replacements.  The first `%u` is the channel
    // number, the first `%s` is the service name.
    let result = template.replacen("%u", &channel.to_string(), 1);
    result.replacen("%s", &xml_escape(name), 1)
}

/// Minimal XML entity escaping for attribute values.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// BlueZ name watching  (replaces g_dbus_add_service_watch)
// ---------------------------------------------------------------------------

/// Start a background task watching for `org.bluez` name owner changes.
///
/// When BlueZ acquires the name, all unregistered profiles are registered.
/// When BlueZ releases the name, all profile paths are cleared (without
/// calling UnregisterProfile, since BlueZ is gone).
async fn start_name_watcher(state: Arc<TokioMutex<BluetoothState>>) {
    let conn = {
        let s = state.lock().await;
        match s.conn.as_ref() {
            Some(c) => c.clone(),
            None => return,
        }
    };

    let state_clone = Arc::clone(&state);
    let handle = tokio::spawn(async move {
        if let Err(e) = watch_bluez_name_loop(&conn, &state_clone).await {
            tracing::error!("bluetooth: name watcher failed: {}", e);
        }
    });

    let mut s = state.lock().await;
    s.watcher_handle = Some(handle);
}

/// Core name-watch loop — watches for `org.bluez` owner changes.
async fn watch_bluez_name_loop(
    conn: &zbus::Connection,
    state: &TokioMutex<BluetoothState>,
) -> Result<(), zbus::Error> {
    let dbus_proxy = zbus::fdo::DBusProxy::new(conn).await?;

    // Check if org.bluez is already running.
    if let Ok(owner) = dbus_proxy.get_name_owner("org.bluez".try_into().unwrap()).await {
        if !owner.as_str().is_empty() {
            name_acquired(state, conn).await;
        }
    }

    // Watch for subsequent changes.
    let mut stream = dbus_proxy.receive_name_owner_changed().await?;

    while let Some(signal) = stream.next().await {
        let args = match signal.args() {
            Ok(a) => a,
            Err(_) => continue,
        };

        if args.name.as_str() != "org.bluez" {
            continue;
        }

        let new_owner = args.new_owner.as_ref().map(|o| o.as_str()).unwrap_or("");
        let old_owner = args.old_owner.as_ref().map(|o| o.as_str()).unwrap_or("");

        if !new_owner.is_empty() && old_owner.is_empty() {
            tracing::info!("bluetooth: org.bluez name acquired");
            name_acquired(state, conn).await;
        } else if new_owner.is_empty() && !old_owner.is_empty() {
            tracing::info!("bluetooth: org.bluez name released");
            name_released(state).await;
        }
    }

    Ok(())
}

/// Handle org.bluez becoming available — register all profiles.
async fn name_acquired(state: &TokioMutex<BluetoothState>, conn: &zbus::Connection) {
    let mut s = state.lock().await;
    for profile in &mut s.profiles {
        register_profile(conn, profile).await;
    }
}

/// Handle org.bluez going away — clear all profile registrations.
///
/// We do NOT call UnregisterProfile because BlueZ is no longer running.
async fn name_released(state: &TokioMutex<BluetoothState>) {
    let mut s = state.lock().await;
    for profile in &mut s.profiles {
        profile.path = None;
    }
}

// ---------------------------------------------------------------------------
// Socket transport type helper
// ---------------------------------------------------------------------------

/// Determine the [`BtTransport`] for a raw socket fd by querying `SO_TYPE`.
fn socket_transport(fd: RawFd) -> Option<BtTransport> {
    let sock_type = bt_sockopt_get_int(fd, libc::SOL_SOCKET, libc::SO_TYPE).ok()?;
    if sock_type == libc::SOCK_SEQPACKET {
        Some(BtTransport::L2cap)
    } else {
        Some(BtTransport::Rfcomm)
    }
}

// ---------------------------------------------------------------------------
// Plugin lifecycle
// ---------------------------------------------------------------------------

/// Initialise the Bluetooth transport plugin.
///
/// Creates a system D-Bus connection, starts the BlueZ name watcher, and
/// registers the Bluetooth transport driver with the OBEX core.
pub fn bluetooth_init() -> Result<(), i32> {
    let rt = tokio::runtime::Handle::try_current().map_err(|_| -libc::EINVAL)?;

    rt.block_on(async {
        // Create a system-bus D-Bus connection.
        let conn = zbus::Connection::system().await.map_err(|e| {
            tracing::error!("bluetooth: failed to connect to system bus: {}", e);
            -libc::EIO
        })?;

        {
            let mut state = global_state().lock().await;
            state.conn = Some(conn.clone());
        }

        // Start the BlueZ name watcher.
        let state_arc = Arc::new(TokioMutex::new(BluetoothState::new()));
        // Swap the global state with a shared Arc.
        {
            let mut real_state = global_state().lock().await;
            let mut inner = state_arc.lock().await;
            inner.conn = real_state.conn.take();
            inner.profiles = std::mem::take(&mut real_state.profiles);
            inner.server_index = real_state.server_index;
        }
        // Store the connection back.
        {
            let inner = state_arc.lock().await;
            let mut real_state = global_state().lock().await;
            real_state.conn = inner.conn.clone();
            real_state.profiles = Vec::new(); // Will be populated by start()
        }

        start_name_watcher(state_arc).await;

        // Register the transport driver.
        let driver = Arc::new(BluetoothTransportDriver);
        obex_transport_driver_register(driver).inspect_err(|&e| {
            tracing::error!("bluetooth: transport driver registration failed: {}", e);
        })?;

        tracing::info!("bluetooth: transport plugin initialised");
        Ok(())
    })
}

/// Shut down the Bluetooth transport plugin.
///
/// Aborts the name watcher, unregisters all profiles, closes the D-Bus
/// connection, and unregisters the transport driver.
pub fn bluetooth_exit() {
    let rt = match tokio::runtime::Handle::try_current() {
        Ok(h) => h,
        Err(_) => return,
    };

    rt.block_on(async {
        let mut state = global_state().lock().await;

        // Stop the name watcher.
        if let Some(handle) = state.watcher_handle.take() {
            handle.abort();
        }

        // Unregister all profiles.
        let conn = state.conn.clone();
        if let Some(conn) = conn.as_ref() {
            for profile in &mut state.profiles {
                unregister_profile(conn, profile).await;
            }
        }

        state.profiles.clear();
        state.conn = None;
    });

    // Unregister the transport driver.
    let driver = BluetoothTransportDriver;
    obex_transport_driver_unregister(&driver);

    // Clear the address cache.
    if let Ok(mut cache) = address_cache().lock() {
        cache.peer.clear();
        cache.local.clear();
    }

    tracing::info!("bluetooth: transport plugin shut down");
}

// ---------------------------------------------------------------------------
// Plugin descriptor registration via inventory
// ---------------------------------------------------------------------------

inventory::submit! {
    ObexPluginDesc {
        name: "bluetooth",
        init: bluetooth_init,
        exit: bluetooth_exit,
    }
}
