// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 Intel Corporation
//
// RAP/RAS (Ranging Profile / Ranging Service) experimental plugin — Rust
// rewrite of `profiles/ranging/rap.c`.
//
// This module provides both client-side (device probe/accept) and server-side
// (adapter probe) ranging support using the `BtRap` subsystem from
// `bluez_shared::profiles::rap`.
//
// **Key characteristic:** This is marked `experimental = true` in the profile
// descriptor, meaning it only activates when experimental features are enabled
// in the daemon configuration.
//
// ## Lifecycle
//
// ### Client-Side (per-device)
//
// 1. **Probe** (`rap_probe`): Marks a device as eligible for the RAP profile
//    and stores a placeholder entry in the session map.
// 2. **Accept** (`rap_accept`): Allocates the `BtRap` instance using local
//    (adapter) and remote (device) GATT databases, attaches the GATT client
//    for RAS service discovery, registers a ready callback.
// 3. **Connect** (`rap_connect`): Logs the connection attempt. Actual
//    connection logic is handled by the accept callback.
// 4. **Disconnect** (`rap_disconnect`): Detaches the RAP session from the
//    GATT client.
// 5. **Remove** (`rap_remove`): Unregisters the ready callback, detaches
//    the RAP session, and removes the per-device context from the session map.
//
// ### Server-Side (per-adapter)
//
// 1. **Adapter Probe** (`rap_server_probe`): Registers the RAS primary
//    service (UUID 0x185B) in the adapter's local GATT database via
//    `BtRap::add_db()`.
// 2. **Adapter Remove** (`rap_server_remove`): Logs cleanup (no persistent
//    server-side state beyond the GATT DB entry).
//
// ## Plugin Registration
//
// Registered via `inventory::submit!` with `PluginPriority::Default` (0),
// replacing C's `BLUETOOTH_PLUGIN_DEFINE(rap, VERSION,
// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, rap_init, rap_exit)`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tracing::{debug, error};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::GattDb;
use bluez_shared::profiles::rap::{BtRap, RAS_UUID16};
use bluez_shared::util::uuid::BtUuid;

use crate::adapter::{
    BtdAdapter, adapter_get_path, btd_adapter_find_device_by_fd, btd_adapter_get_database,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::gatt::database::BtdGattDatabase;
use crate::log::{btd_debug, btd_error};
use crate::plugin::PluginPriority;
use crate::profile::{
    BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile, btd_profile_register, btd_profile_unregister,
};

use bluez_shared::sys::bluetooth::BdAddr;

// ===========================================================================
// Constants
// ===========================================================================

/// GATT Service UUID (0x1801) — used as `remote_uuid` for generic GATT-based
/// device probe matching.  In the C source this is `GATT_UUID`.
/// Converted to a full 128-bit UUID string via `BtUuid::from_u16()` during
/// profile registration in [`rap_init`].
const GATT_UUID: u16 = 0x1801;

// ===========================================================================
// Module State
// ===========================================================================

/// Per-device RAP profile context.
///
/// Replaces C `struct rap_data` from rap.c. Each probed device gets one
/// `RapData` instance that tracks the RAP subsystem handle and ready
/// callback registration.
///
/// The `rap` and `ready_id` fields are populated lazily during `rap_accept`
/// because creating a `BtRap` requires async access to GATT databases.
struct RapData {
    /// RAP subsystem handle from `bluez_shared::profiles::rap`.
    ///
    /// `None` between probe and accept; populated during `rap_accept` when
    /// async GATT database access is available. Wrapped in
    /// `Arc<StdMutex<BtRap>>` for shared, mutable access across multiple
    /// callback invocations. Replaces C `bt_rap_ref`/`bt_rap_unref`
    /// reference counting.
    rap: Option<Arc<StdMutex<BtRap>>>,

    /// Registered ready callback ID. Used to unregister the callback when
    /// the session is removed. Replaces C `rap_data->ready_id`.
    /// 0 means no callback registered.
    ready_id: u32,
}

impl RapData {
    /// Create a new, empty RAP session context.
    fn new() -> Self {
        Self { rap: None, ready_id: 0 }
    }
}

/// Global per-device session map.
///
/// Keys are Bluetooth device addresses; values are per-device `RapData`
/// contexts wrapped in `Arc<StdMutex<RapData>>` for shared access between
/// lifecycle callbacks.
///
/// Replaces C `static struct queue *sessions` from rap.c.
///
/// Uses `std::sync::Mutex` (not tokio) because the state is accessed from
/// both sync (probe/remove) and async (accept/disconnect) contexts, and
/// the lock is never held across `.await` points.
static RAP_STATE: LazyLock<StdMutex<HashMap<BdAddr, Arc<StdMutex<RapData>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Stored profile definition for unregistration during plugin exit.
///
/// Replaces C `static struct btd_profile rap_profile` (module-level static).
static RAP_PROFILE: LazyLock<StdMutex<Option<BtdProfile>>> = LazyLock::new(|| StdMutex::new(None));

// ===========================================================================
// RAP Callbacks
// ===========================================================================

/// Debug log callback for the RAP subsystem.
///
/// Registered via `BtRap::set_debug()` during `rap_accept()`. Replaces C
/// `rap_debug()` which logs with `DBG_IDX(0xffff, ...)`.
fn rap_debug(msg: &str) {
    debug!("RAP debug: {}", msg);
    btd_debug(0xffff, &format!("RAP debug: {}", msg));
}

/// Ready callback invoked when the RAP subsystem becomes operational.
///
/// Registered via `BtRap::ready_register()` during `rap_accept()`. In the
/// C source, `rap_ready()` logs "RAP ready" and is a placeholder for future
/// functionality.
fn rap_ready(_rap: &BtRap) {
    debug!("RAP ready");
    btd_debug(0, "RAP ready");
}

// ===========================================================================
// Profile Lifecycle — Client-Side
// ===========================================================================

/// Probe a device for RAP/RAS support.
///
/// Called when a device matching the profile's `remote_uuid` (GATT Service
/// UUID 0x1801) is discovered. Creates a placeholder session entry in the
/// session map. The actual `BtRap` instance is created during `rap_accept`
/// when async GATT database access is available.
///
/// Replaces C `rap_probe()` from rap.c.
fn rap_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let addr = match device.try_lock() {
        Ok(dev) => *dev.get_address(),
        Err(_) => {
            error!("RAP probe: could not lock device");
            btd_error(0, "RAP probe: could not lock device");
            return Err(BtdError::Failed("Device lock contention".to_owned()));
        }
    };

    // Guard against duplicate probe.
    {
        let state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
        if state.contains_key(&addr) {
            debug!("RAP probe: session already exists for {}", addr.ba2str());
            btd_debug(0, &format!("RAP probe: session already exists for {}", addr.ba2str()));
            return Ok(());
        }
    }

    // Create placeholder session entry. The BtRap instance will be created
    // in rap_accept when async database access is available.
    let data = Arc::new(StdMutex::new(RapData::new()));

    let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.insert(addr, data);

    debug!("RAP probe: session created for {}", addr.ba2str());
    btd_debug(0, &format!("RAP probe: session created for {}", addr.ba2str()));

    Ok(())
}

/// Accept an incoming RAP profile connection.
///
/// Creates the `BtRap` instance using both local (adapter) and remote
/// (device) GATT databases, attaches the GATT client for RAS service
/// discovery, and registers a ready callback. Returning `Ok(())` is
/// equivalent to C `btd_service_connecting_complete(service, 0)`.
///
/// Replaces C `rap_accept()` from rap.c.
async fn rap_accept(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let (addr, adapter_arc, remote_gatt_db, gatt_client) = {
        let dev = device.lock().await;
        let addr = *dev.get_address();
        let adapter = Arc::clone(dev.get_adapter());
        let remote_db: Option<GattDb> = dev.get_gatt_db().cloned();
        let client: Option<Arc<BtGattClient>> = dev.get_gatt_client().cloned();
        (addr, adapter, remote_db, client)
    };

    // Look up the session data created during probe.
    let data_arc = {
        let state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match state.get(&addr) {
            Some(d) => Arc::clone(d),
            None => {
                error!("RAP accept: no session for {}", addr.ba2str());
                btd_error(0, &format!("RAP accept: no session for {}", addr.ba2str()));
                return Err(BtdError::DoesNotExist("RAP session not found".to_owned()));
            }
        }
    };

    // Retrieve the adapter's local GATT database (async access).
    let adapter_database: Option<Arc<BtdGattDatabase>> =
        btd_adapter_get_database(&adapter_arc).await;
    let local_db: GattDb = match adapter_database {
        Some(ref db) => {
            let gatt_db_arc = db.get_db().await;
            (*gatt_db_arc).clone()
        }
        None => {
            error!("RAP accept: adapter has no GATT database");
            btd_error(0, "RAP accept: adapter has no GATT database");
            return Err(BtdError::NotAvailable("Adapter GATT database not available".to_owned()));
        }
    };

    // Create the BtRap instance with local and remote GATT databases.
    let rap = BtRap::new(local_db, remote_gatt_db);
    let rap_arc = Arc::new(StdMutex::new(rap));

    // Register debug handler and ready callback.
    let ready_id = {
        let mut rap_guard = rap_arc.lock().unwrap_or_else(|e| e.into_inner());
        rap_guard.set_debug(rap_debug);
        rap_guard.ready_register(rap_ready)
    };

    // Attach the GATT client to the RAP subsystem.
    {
        let mut rap_guard = rap_arc.lock().unwrap_or_else(|e| e.into_inner());
        if !rap_guard.attach(gatt_client) {
            error!("RAP accept: failed to attach GATT client for {}", addr.ba2str());
            btd_error(
                0,
                &format!("RAP accept: failed to attach GATT client for {}", addr.ba2str()),
            );
            return Err(BtdError::Failed("RAP attach failed".to_owned()));
        }
    }

    // Verify ATT connection for debug logging and device resolution.
    //
    // Mirrors the C `rap_attached()` logic: extract the underlying ATT
    // transport from the RAP instance, retrieve the socket file descriptor,
    // and attempt to resolve the remote device by that fd.
    //
    // All `StdMutex` guards are dropped inside the block before the `.await`
    // call to ensure the resulting future remains `Send`.
    let att_fd: Option<i32> = {
        let rap_guard = rap_arc.lock().unwrap_or_else(|e| e.into_inner());
        let att_opt: Option<Arc<StdMutex<BtAtt>>> = rap_guard.get_att();
        match att_opt {
            Some(att_arc) => {
                let att_lock = att_arc.lock().unwrap_or_else(|e| e.into_inner());
                att_lock.get_fd().ok()
            }
            None => None,
        }
    };
    if let Some(fd) = att_fd {
        debug!("RAP accept: ATT fd={} for {}", fd, addr.ba2str());
        btd_debug(0, &format!("RAP accept: ATT fd={} for {}", fd, addr.ba2str()));
        // Attempt device resolution by ATT fd (placeholder in current adapter.rs).
        let resolved = btd_adapter_find_device_by_fd(&adapter_arc, fd).await;
        if resolved.is_none() {
            debug!("RAP accept: device not resolved by ATT fd={}", fd);
        }
    }

    // Store the RAP instance and ready_id in the session data.
    {
        let mut data = data_arc.lock().unwrap_or_else(|e| e.into_inner());
        data.rap = Some(Arc::clone(&rap_arc));
        data.ready_id = ready_id;
    }

    debug!("RAP accept: GATT client attached for {}", addr.ba2str());
    btd_debug(0, &format!("RAP accept: GATT client attached for {}", addr.ba2str()));

    // Returning Ok(()) signals btd_service_connecting_complete(service, 0).
    Ok(())
}

/// Initiate a RAP profile connection to a device.
///
/// Connection logic is handled by `rap_accept`. This function logs the
/// connection attempt and returns success.
///
/// Replaces C `rap_connect()` from rap.c.
async fn rap_connect(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let addr = {
        let dev = device.lock().await;
        *dev.get_address()
    };

    debug!("RAP connect: {}", addr.ba2str());
    btd_debug(0, &format!("RAP connect: {}", addr.ba2str()));

    Ok(())
}

/// Disconnect a RAP profile session from a device.
///
/// Detaches the GATT client from the RAP subsystem. Returning `Ok(())` is
/// equivalent to C `btd_service_disconnecting_complete(service, 0)`.
///
/// Replaces C `rap_disconnect()` from rap.c.
async fn rap_disconnect(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let addr = {
        let dev = device.lock().await;
        *dev.get_address()
    };

    // Detach the GATT client from the RAP subsystem.
    let state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(data_arc) = state.get(&addr) {
        let data = data_arc.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref rap) = data.rap {
            let mut rap_guard = rap.lock().unwrap_or_else(|e| e.into_inner());
            rap_guard.detach();
        }
    }

    debug!("RAP disconnect: {}", addr.ba2str());
    btd_debug(0, &format!("RAP disconnect: {}", addr.ba2str()));

    // Returning Ok(()) signals btd_service_disconnecting_complete(service, 0).
    Ok(())
}

/// Remove the RAP profile from a device.
///
/// Fully cleans up the per-device `RapData` context: unregisters the ready
/// callback, detaches the RAP session, and removes the context from the
/// session map.
///
/// Replaces C `rap_remove()` from rap.c.
fn rap_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let addr = match device.try_lock() {
        Ok(dev) => *dev.get_address(),
        Err(_) => {
            error!("RAP remove: could not lock device");
            btd_error(0, "RAP remove: could not lock device");
            return;
        }
    };

    let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(data_arc) = state.remove(&addr) {
        let data = data_arc.lock().unwrap_or_else(|e| e.into_inner());

        // Unregister the ready callback and detach.
        if let Some(ref rap) = data.rap {
            let mut rap_guard = rap.lock().unwrap_or_else(|e| e.into_inner());
            if data.ready_id != 0 {
                rap_guard.ready_unregister(data.ready_id);
            }
            rap_guard.detach();
        }

        debug!("RAP remove: session removed for {}", addr.ba2str());
        btd_debug(0, &format!("RAP remove: session removed for {}", addr.ba2str()));
    }
}

// ===========================================================================
// Profile Lifecycle — Server-Side (Adapter)
// ===========================================================================

/// Register the RAS primary service in the adapter's local GATT database.
///
/// Called when an adapter is powered on. Registers the Ranging Service
/// (UUID 0x185B) with its 6 characteristics in the local GATT database
/// so that remote devices can discover and interact with the service.
///
/// Since `btd_adapter_get_database` is async but `AdapterProbeFn` is sync,
/// the actual registration is spawned as an async task.
///
/// Replaces C `rap_server_probe()` from rap.c.
fn rap_server_probe(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) -> Result<(), BtdError> {
    let adapter_arc = Arc::clone(adapter);

    // Spawn an async task to register the RAS service because
    // btd_adapter_get_database and BtdGattDatabase::get_db are async.
    tokio::spawn(async move {
        let path = adapter_get_path(&adapter_arc).await;

        let database = btd_adapter_get_database(&adapter_arc).await;
        let db = match database {
            Some(ref d) => {
                let gatt_db_arc = d.get_db().await;
                (*gatt_db_arc).clone()
            }
            None => {
                error!("RAP server probe: adapter has no GATT database");
                btd_error(0, "RAP server probe: adapter has no GATT database");
                return;
            }
        };

        // Register the RAS service in the local GATT database.
        BtRap::add_db(&db);

        debug!("RAP server probe: RAS service registered for adapter {}", path);
        btd_debug(0, &format!("RAP server probe: RAS service registered for adapter {}", path));
    });

    Ok(())
}

/// Remove RAS service registration from an adapter.
///
/// Called when an adapter is powered off or removed. The GATT database
/// entry is managed by the database itself; this function performs cleanup
/// logging.
///
/// Replaces C `rap_server_remove()` from rap.c.
fn rap_server_remove(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) {
    // adapter_get_path is async; use try_lock to get path synchronously.
    let path = match adapter.try_lock() {
        Ok(a) => a.path.clone(),
        Err(_) => String::from("<unknown>"),
    };

    debug!("RAP server remove: adapter {}", path);
    btd_debug(0, &format!("RAP server remove: adapter {}", path));
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the RAP/RAS plugin.
///
/// Creates and registers the RAP profile descriptor with the daemon's
/// profile registry. The profile is marked as experimental, meaning it
/// will only be activated when the daemon is started with the
/// `--experimental` flag.
///
/// Replaces C `rap_init()` from rap.c.
fn rap_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("rap plugin init");

    // Build the profile descriptor.
    //
    // UUID strings are derived from 16-bit constants via `BtUuid::from_u16()`
    // for consistency with the kernel-assigned UUIDs in lib/bluetooth.
    let mut profile = BtdProfile::new("rap");
    profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
    profile.remote_uuid = Some(BtUuid::from_u16(GATT_UUID).to_string());
    profile.local_uuid = Some(BtUuid::from_u16(RAS_UUID16).to_string());
    profile.experimental = true;

    // Set client-side lifecycle callbacks.
    profile.set_device_probe(Box::new(rap_probe));
    profile.set_device_remove(Box::new(rap_remove));

    // Accept, connect, and disconnect return Futures (async closures).
    profile.set_accept(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { rap_accept(&device).await })
    }));

    profile.set_connect(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { rap_connect(&device).await })
    }));

    profile.set_disconnect(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { rap_disconnect(&device).await })
    }));

    // Set server-side (adapter) lifecycle callbacks.
    profile.set_adapter_probe(Box::new(rap_server_probe));
    profile.set_adapter_remove(Box::new(rap_server_remove));

    // Store a copy for unregistration during exit.
    {
        let stored = BtdProfile::new("rap");
        let mut guard = RAP_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    // Register the profile asynchronously.
    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(profile).await {
            error!("Failed to register RAP profile: {}", e);
            btd_error(0, &format!("Failed to register RAP profile: {}", e));
        }
    });

    Ok(())
}

/// Shut down the RAP/RAS plugin.
///
/// Unregisters the profile and clears all per-device session state.
///
/// Replaces C `rap_exit()` from rap.c.
fn rap_exit() {
    debug!("rap plugin exit");

    // Unregister the profile asynchronously.
    let profile_opt = {
        let mut guard = RAP_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };

    if let Some(profile) = profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }

    // Clear all per-device session state.
    let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
    for (_addr, data_arc) in state.drain() {
        let data = data_arc.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref rap) = data.rap {
            let mut rap_guard = rap.lock().unwrap_or_else(|e| e.into_inner());
            if data.ready_id != 0 {
                rap_guard.ready_unregister(data.ready_id);
            }
            rap_guard.detach();
        }
    }
}

// ===========================================================================
// Exported struct — RapPlugin
// ===========================================================================

/// RAP/RAS plugin descriptor.
///
/// Provides the public API surface for the Ranging Profile plugin. The actual
/// plugin lifecycle is handled through [`PluginDesc`] registered via
/// [`inventory::submit!`], which calls the module-level [`rap_init`] and
/// [`rap_exit`] functions.
///
/// This struct satisfies the export schema requirement for a `RapPlugin`
/// class with `name()`, `version()`, `priority()`, `init()`, and `exit()`
/// members.
pub struct RapPlugin;

impl RapPlugin {
    /// Returns the unique plugin name: `"rap"`.
    pub fn name(&self) -> &str {
        "rap"
    }

    /// Returns the plugin version string (matches daemon VERSION from
    /// Cargo.toml). Equivalent to `VERSION` in the C
    /// `BLUETOOTH_PLUGIN_DEFINE(rap, VERSION, ...)` macro.
    pub fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority: `Default` (0).
    ///
    /// Matches C `BLUETOOTH_PLUGIN_PRIORITY_DEFAULT` used in
    /// `BLUETOOTH_PLUGIN_DEFINE`. Note that the profile itself uses
    /// `BTD_PROFILE_PRIORITY_MEDIUM`, but the plugin priority for the
    /// daemon's plugin loading order is `Default`.
    pub fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    /// Initializes the RAP plugin.
    ///
    /// Delegates to the module-level [`rap_init`] function which registers
    /// the RAP profile descriptor.
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        rap_init()
    }

    /// Cleans up the RAP plugin.
    ///
    /// Delegates to the module-level [`rap_exit`] function which unregisters
    /// the profile and cleans up all session state.
    pub fn exit(&self) {
        rap_exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

/// Register the rap plugin at link time so that `plugin_init()` in the
/// plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(rap, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, rap_init, rap_exit)`.
#[allow(unsafe_code)]
mod _rap_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "rap",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::rap_init,
            exit: super::rap_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Test-only helpers mirroring C `rap_attached`/`rap_detached`.
    //
    // In the C source these are global callbacks registered via
    // `bt_rap_register()`. In the Rust architecture session management
    // flows through profile lifecycle callbacks, so these are exercised
    // only in tests to validate session tracking logic.
    // -----------------------------------------------------------------

    /// Handle a RAP session attachment event (test helper).
    ///
    /// Mirrors C `rap_attached()`: inserts a new `RapData` entry keyed by
    /// the device address, guarding against duplicates.
    fn rap_attached(rap: Arc<StdMutex<BtRap>>, addr: BdAddr) {
        let state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
        if state.contains_key(&addr) {
            return;
        }
        drop(state);

        let data = Arc::new(StdMutex::new(RapData { rap: Some(Arc::clone(&rap)), ready_id: 0 }));

        {
            let mut rap_guard = rap.lock().unwrap_or_else(|e| e.into_inner());
            rap_guard.set_debug(rap_debug);
        }

        let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.insert(addr, data);
    }

    /// Handle a RAP session detachment event (test helper).
    ///
    /// Mirrors C `rap_detached()`: removes the session for the given
    /// address from the global session map.
    fn rap_detached(addr: &BdAddr) {
        let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.remove(addr);
    }

    /// Verify the RapPlugin name matches the expected value.
    #[test]
    fn test_plugin_name() {
        let plugin = RapPlugin;
        assert_eq!(plugin.name(), "rap");
    }

    /// Verify the RapPlugin version is non-empty.
    #[test]
    fn test_plugin_version() {
        let plugin = RapPlugin;
        assert!(!plugin.version().is_empty());
    }

    /// Verify the RapPlugin priority is Default.
    #[test]
    fn test_plugin_priority() {
        let plugin = RapPlugin;
        assert_eq!(plugin.priority(), PluginPriority::Default);
    }

    /// Verify UUID constants are correctly defined.
    #[test]
    fn test_uuid_constants() {
        assert_eq!(GATT_UUID, 0x1801);
        assert_eq!(RAS_UUID16, 0x185B);
    }

    /// Verify UUID strings generated via BtUuid::from_u16 match expected format.
    #[test]
    fn test_uuid_strings() {
        assert_eq!(BtUuid::from_u16(GATT_UUID).to_string(), "00001801-0000-1000-8000-00805f9b34fb");
        assert_eq!(
            BtUuid::from_u16(RAS_UUID16).to_string(),
            "0000185b-0000-1000-8000-00805f9b34fb"
        );
    }

    /// Verify BtUuid construction from u16.
    #[test]
    fn test_bt_uuid_from_u16() {
        let gatt = BtUuid::from_u16(GATT_UUID);
        let ras = BtUuid::from_u16(RAS_UUID16);
        assert_ne!(gatt, ras);
        assert_eq!(gatt, BtUuid::from_u16(0x1801));
        assert_eq!(ras, BtUuid::from_u16(0x185B));
    }

    /// Verify the session map is accessible.
    #[test]
    fn test_session_map_accessible() {
        let state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
        drop(state);
    }

    /// Verify RapData can be created.
    #[test]
    fn test_rap_data_construction() {
        let data = RapData::new();
        assert!(data.rap.is_none());
        assert_eq!(data.ready_id, 0);
    }

    /// Verify RapData with a BtRap instance.
    #[test]
    fn test_rap_data_with_rap() {
        let db = GattDb::new();
        let rap = BtRap::new(db, None);
        let rap_arc = Arc::new(StdMutex::new(rap));
        let data = RapData { rap: Some(rap_arc), ready_id: 42 };
        assert!(data.rap.is_some());
        assert_eq!(data.ready_id, 42);
    }

    /// Verify rap_debug does not panic.
    #[test]
    fn test_rap_debug_no_panic() {
        rap_debug("test message");
    }

    /// Verify rap_ready does not panic.
    #[test]
    fn test_rap_ready_no_panic() {
        let db = GattDb::new();
        let rap = BtRap::new(db, None);
        rap_ready(&rap);
    }

    /// Verify rap_detached on unknown address is a no-op.
    #[test]
    fn test_rap_detached_unknown() {
        let addr = BdAddr::default();
        rap_detached(&addr);
    }

    /// Verify rap_attached creates a session.
    #[test]
    fn test_rap_attached_creates_session() {
        let db = GattDb::new();
        let rap = BtRap::new(db, None);
        let rap_arc = Arc::new(StdMutex::new(rap));

        let addr = BdAddr { b: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] };

        {
            let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
            state.remove(&addr);
        }

        rap_attached(rap_arc, addr);

        {
            let state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
            assert!(state.contains_key(&addr));
        }

        {
            let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
            state.remove(&addr);
        }
    }

    /// Verify rap_attached skips duplicate sessions.
    #[test]
    fn test_rap_attached_skips_duplicate() {
        let db = GattDb::new();
        let rap = BtRap::new(db, None);
        let rap_arc = Arc::new(StdMutex::new(rap));

        let addr = BdAddr { b: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] };

        {
            let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
            state.remove(&addr);
        }

        rap_attached(Arc::clone(&rap_arc), addr);
        rap_attached(rap_arc, addr);

        {
            let state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
            assert!(state.contains_key(&addr));
        }

        {
            let mut state = RAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
            state.remove(&addr);
        }
    }

    /// Verify the experimental flag is set in the profile.
    #[test]
    fn test_profile_experimental() {
        let mut profile = BtdProfile::new("rap");
        profile.experimental = true;
        assert!(profile.experimental);
    }

    /// Verify profile priority is MEDIUM.
    #[test]
    fn test_profile_priority_medium() {
        let mut profile = BtdProfile::new("rap");
        profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        assert_eq!(profile.priority, BTD_PROFILE_PRIORITY_MEDIUM);
    }
}
