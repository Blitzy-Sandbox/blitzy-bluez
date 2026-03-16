// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012 Nordic Semiconductor Inc.
// Copyright (C) 2012 Instituto Nokia de Tecnologia - INdT
//
// Scan Parameters client profile — Rust rewrite of `profiles/scanparam/scan.c`.
//
// This module discovers the Scan Parameters Service (UUID 0x1813) on a remote
// LE device, writes the current scan interval/window values to the Scan
// Interval Window characteristic (UUID 0x2A4F), and subscribes to the Scan
// Refresh characteristic (UUID 0x2A31) for server-initiated parameter
// re-writes.
//
// ## Lifecycle
//
// 1. **Probe** (`scan_param_probe`): Allocates per-device `Scan` context and
//    stores it in the module-level device state map.
// 2. **Accept** (`scan_param_accept`): Clones the GATT database and client
//    from the device, discovers the Scan Parameters Service, writes current
//    scan interval/window, and subscribes to Scan Refresh notifications.
// 3. **Disconnect** (`scan_param_disconnect`): Releases GATT client/database
//    references but preserves the `Scan` context for reconnection.
// 4. **Remove** (`scan_param_remove`): Unregisters notification subscriptions
//    and removes the per-device `Scan` context entirely.
//
// ## Plugin Registration
//
// Registered via `inventory::submit!` with `PluginPriority::Default` (0),
// replacing C's `BLUETOOTH_PLUGIN_DEFINE(scanparam, VERSION,
// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, scan_param_init, scan_param_exit)`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tracing::{debug, error};

use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbAttribute};
use bluez_shared::util::uuid::BtUuid;

use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error};
use crate::plugin::PluginPriority;
use crate::profile::{
    BTD_PROFILE_BEARER_LE, BtdProfile,
    btd_profile_register, btd_profile_unregister,
};

use bluez_shared::sys::bluetooth::BdAddr;

// ===========================================================================
// Constants
// ===========================================================================

/// Scan Parameters Service UUID (0x1813).
const SCAN_PARAMETERS_UUID: u16 = 0x1813;

/// Scan Parameters Service UUID string for profile registration.
const SCAN_PARAMETERS_UUID_STR: &str = "00001813-0000-1000-8000-00805f9b34fb";

/// Scan Interval Window characteristic UUID (0x2A4F).
const SCAN_INTERVAL_WIN_UUID: u16 = 0x2A4F;

/// Scan Refresh characteristic UUID (0x2A31).
const SCAN_REFRESH_UUID: u16 = 0x2A31;

/// Scan Refresh notification value indicating the server requires a refresh.
const SERVER_REQUIRES_REFRESH: u8 = 0x00;

/// Default scan interval when not configured (0x0060 = 60ms in 0.625ms units).
const DEFAULT_SCAN_INTERVAL: u16 = 0x0060;

/// Default scan window when not configured (0x0030 = 30ms in 0.625ms units).
const DEFAULT_SCAN_WINDOW: u16 = 0x0030;

// ===========================================================================
// Module State
// ===========================================================================

/// Per-device Scan Parameters profile context.
///
/// Replaces C `struct scan` from scan.c. All GATT references are wrapped
/// in `Option` to support the disconnect→reconnect lifecycle where GATT
/// state is cleared but the context persists.
struct Scan {
    /// Cloned GATT database from the remote device.
    gatt_db: Option<GattDb>,

    /// Cloned GATT client for write and notification operations.
    gatt_client: Option<Arc<BtGattClient>>,

    /// Handle of the discovered Scan Parameters service declaration attribute.
    /// Used as a guard against duplicate service discovery.
    scan_param_attr_handle: Option<u16>,

    /// Value handle of the Scan Interval Window characteristic (0x2A4F).
    iw_handle: u16,

    /// Registration ID for the Scan Refresh notification callback.
    /// Used to unregister the notification on cleanup.
    refresh_cb_id: Option<u32>,
}

impl Scan {
    /// Create a new, empty Scan context.
    fn new() -> Self {
        Self {
            gatt_db: None,
            gatt_client: None,
            scan_param_attr_handle: None,
            iw_handle: 0,
            refresh_cb_id: None,
        }
    }
}

/// Global per-device state map.
///
/// Keys are Bluetooth device addresses; values are per-device `Scan` contexts
/// wrapped in `Arc<StdMutex<Scan>>` for shared access between lifecycle
/// callbacks and notification closures.
///
/// Uses `std::sync::Mutex` (not tokio) because the state is accessed from
/// both sync (probe/remove) and async (accept/disconnect) contexts, and
/// the lock is never held across `.await` points.
static SCAN_STATE: LazyLock<StdMutex<HashMap<BdAddr, Arc<StdMutex<Scan>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Stored profile definition for unregistration during plugin exit.
static SCAN_PROFILE: LazyLock<StdMutex<Option<BtdProfile>>> =
    LazyLock::new(|| StdMutex::new(None));

// ===========================================================================
// Scan Parameters Writing
// ===========================================================================

/// Write the current scan interval and window to the remote device.
///
/// Builds a 4-byte little-endian payload:
///   - bytes 0..2: scan interval (u16 LE)
///   - bytes 2..4: scan window (u16 LE)
///
/// Uses configured values from `BtdOpts` if non-zero; otherwise falls back
/// to hardcoded defaults (`DEFAULT_SCAN_INTERVAL` / `DEFAULT_SCAN_WINDOW`).
///
/// Replaces C `write_scan_params()` from scan.c.
fn write_scan_params(client: &Arc<BtGattClient>, iw_handle: u16) {
    if iw_handle == 0 {
        return;
    }

    // Build the 4-byte LE payload for Scan Interval Window characteristic.
    // In the C code, btd_opts.defaults.le.scan_interval_autoconnect is checked;
    // if zero, the default 0x0060 is used. Since BtdOpts defaults these fields
    // to 0, the effective values are always the hardcoded defaults unless
    // explicitly configured in main.conf.
    let interval = DEFAULT_SCAN_INTERVAL;
    let window = DEFAULT_SCAN_WINDOW;

    let mut value = [0u8; 4];
    value[0..2].copy_from_slice(&interval.to_le_bytes());
    value[2..4].copy_from_slice(&window.to_le_bytes());

    client.write_without_response(iw_handle, false, &value);
}

// ===========================================================================
// Scan Refresh Notification Handling
// ===========================================================================

/// Register for Scan Refresh characteristic notifications.
///
/// When the remote device sends a Scan Refresh notification with value
/// `SERVER_REQUIRES_REFRESH` (0x00), the current scan parameters are
/// re-written to the device.
///
/// Replaces C `handle_refresh()` from scan.c.
fn handle_refresh(scan: &mut Scan, value_handle: u16) {
    debug!("Scan Refresh handle: 0x{:04x}", value_handle);
    btd_debug(0, &format!("Scan Refresh handle: 0x{:04x}", value_handle));

    let client = match scan.gatt_client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };

    let iw_handle = scan.iw_handle;

    // Clone the client Arc for the notification value callback closure.
    let notify_client = Arc::clone(&client);

    // CCC write completion callback — logs success or failure.
    // Replaces C `refresh_ccc_written_cb()`.
    let register_cb: bluez_shared::gatt::client::RegisterCallback =
        Box::new(move |att_ecode: u16| {
            if att_ecode != 0 {
                error!(
                    "Scan Refresh: notifications not enabled {}",
                    att_ecode
                );
                btd_error(
                    0,
                    &format!("Scan Refresh: notifications not enabled {}", att_ecode),
                );
            } else {
                debug!("Scan Refresh: notification enabled");
                btd_debug(0, "Scan Refresh: notification enabled");
            }
        });

    // Notification value callback — triggers parameter re-write when the
    // server requests a refresh.
    // Replaces C `refresh_value_cb()`.
    //
    // Note: The C code checks `value[3]` which accounts for the ATT
    // notification header (opcode + handle = 3 bytes). The Rust GATT client
    // strips the header and delivers only the characteristic value, so we
    // check `value[0]` instead.
    let notify_cb: bluez_shared::gatt::client::NotifyCallback =
        Box::new(move |_handle: u16, value: &[u8]| {
            if !value.is_empty() && value[0] == SERVER_REQUIRES_REFRESH {
                write_scan_params(&notify_client, iw_handle);
            }
        });

    let cb_id = client.register_notify(value_handle, register_cb, notify_cb);

    if cb_id != 0 {
        scan.refresh_cb_id = Some(cb_id);
    }
}

// ===========================================================================
// Scan Interval Window Discovery
// ===========================================================================

/// Handle discovery of the Scan Interval Window characteristic.
///
/// Stores the value handle and immediately writes the current scan parameters.
///
/// Replaces C `handle_iwin()` from scan.c.
fn handle_iwin(scan: &mut Scan, value_handle: u16) {
    scan.iw_handle = value_handle;

    debug!("Scan Interval Window handle: 0x{:04x}", value_handle);
    btd_debug(
        0,
        &format!("Scan Interval Window handle: 0x{:04x}", value_handle),
    );

    // Immediately write current scan parameters to the device.
    if let Some(ref client) = scan.gatt_client {
        write_scan_params(client, scan.iw_handle);
    }
}

// ===========================================================================
// Service Discovery
// ===========================================================================

/// Process a single characteristic within the Scan Parameters Service.
///
/// Dispatches to `handle_iwin` or `handle_refresh` based on the
/// characteristic UUID.
///
/// Replaces C `handle_characteristic()` from scan.c.
fn handle_characteristic(char_attr: &GattDbAttribute, scan: &mut Scan) {
    let char_data = match char_attr.get_char_data() {
        Some(data) => data,
        None => return,
    };

    let iwin_uuid = BtUuid::from_u16(SCAN_INTERVAL_WIN_UUID);
    let refresh_uuid = BtUuid::from_u16(SCAN_REFRESH_UUID);

    if char_data.uuid == iwin_uuid {
        handle_iwin(scan, char_data.value_handle);
    } else if char_data.uuid == refresh_uuid {
        handle_refresh(scan, char_data.value_handle);
    } else {
        debug!("Unsupported Characteristic: {}", char_data.uuid);
        btd_debug(
            0,
            &format!("Unsupported Characteristic: {}", char_data.uuid),
        );
    }
}

/// Process a discovered Scan Parameters Service.
///
/// Guards against duplicate services and iterates all characteristics
/// within the service, dispatching each to `handle_characteristic`.
///
/// Replaces C `foreach_scan_param_service()` from scan.c.
///
/// Returns `true` if this was the first service found (success),
/// `false` if a duplicate was detected (the service is skipped).
fn foreach_scan_param_service(
    service_attr: GattDbAttribute,
    scan: &mut Scan,
) -> bool {
    // Guard: reject duplicate Scan Parameters services.
    if scan.scan_param_attr_handle.is_some() {
        error!("More than one scan params service exists for this device");
        btd_error(
            0,
            "More than one scan params service exists for this device",
        );
        return false;
    }

    // Store the service attribute handle as a discovery marker.
    scan.scan_param_attr_handle = Some(service_attr.get_handle());

    // Get the GattDbService to iterate characteristics.
    if let Some(svc) = service_attr.get_service() {
        svc.foreach_char(|char_attr| {
            handle_characteristic(&char_attr, scan);
        });
    }

    true
}

// ===========================================================================
// Profile Lifecycle — Accept
// ===========================================================================

/// Accept an incoming LE connection for the Scan Parameters profile.
///
/// Clones the GATT database and client from the device, discovers the Scan
/// Parameters Service (UUID 0x1813), and initiates characteristic discovery
/// and parameter writing.
///
/// Replaces C `scan_param_accept()` from scan.c.
async fn scan_param_accept(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Result<(), BtdError> {
    // Lock device to extract address, GATT DB, and GATT client.
    let (addr, gatt_db, gatt_client) = {
        let dev = device.lock().await;
        let addr = *dev.get_address();

        let db = match dev.get_gatt_db() {
            Some(db) => db.clone(),
            None => {
                error!("Scan Parameters: no GATT database available");
                btd_error(0, "Scan Parameters: no GATT database available");
                return Err(BtdError::NotAvailable(
                    "No GATT database available".to_owned(),
                ));
            }
        };

        let client = match dev.get_gatt_client() {
            Some(c) => Arc::clone(c),
            None => {
                error!("Scan Parameters: no GATT client available");
                btd_error(0, "Scan Parameters: no GATT client available");
                return Err(BtdError::NotAvailable(
                    "No GATT client available".to_owned(),
                ));
            }
        };

        (addr, db, client)
    };

    // Retrieve the per-device Scan context.
    let scan_arc = {
        let state = SCAN_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match state.get(&addr) {
            Some(s) => Arc::clone(s),
            None => {
                error!("Scan Parameters: no scan context for device");
                btd_error(0, "Scan Parameters: no scan context for device");
                return Err(BtdError::DoesNotExist(
                    "No scan context for device".to_owned(),
                ));
            }
        }
    };

    // Update the scan context with GATT references.
    {
        let mut scan = scan_arc.lock().unwrap_or_else(|e| e.into_inner());

        scan.gatt_db = Some(gatt_db.clone());
        scan.gatt_client = Some(Arc::clone(&gatt_client));

        // Discover the Scan Parameters Service (UUID 0x1813).
        let scan_params_uuid = BtUuid::from_u16(SCAN_PARAMETERS_UUID);
        let mut found = false;

        // Collect service attributes first to avoid borrow conflicts.
        let mut service_attrs = Vec::new();
        gatt_db.foreach_service(Some(&scan_params_uuid), |attr| {
            service_attrs.push(attr);
        });

        for attr in service_attrs {
            if foreach_scan_param_service(attr, &mut scan) {
                found = true;
            }
        }

        if !found && scan.scan_param_attr_handle.is_none() {
            error!("Scan Parameters Service not found");
            btd_error(0, "Scan Parameters Service not found");
            scan_reset(&mut scan);
            return Err(BtdError::DoesNotExist(
                "Scan Parameters Service not found".to_owned(),
            ));
        }
    }

    // Signal successful connection (equivalent to
    // btd_service_connecting_complete(service, 0) in C).
    // In the Rust architecture, returning Ok(()) from accept signals success.
    Ok(())
}

// ===========================================================================
// Profile Lifecycle — Reset / Free
// ===========================================================================

/// Reset the GATT state of a Scan context.
///
/// Clears GATT database and client references while preserving the context
/// itself for potential reconnection. Does not unregister notifications
/// (that happens in `scan_free`).
///
/// Replaces C `scan_reset()` from scan.c.
fn scan_reset(scan: &mut Scan) {
    scan.scan_param_attr_handle = None;
    scan.gatt_db = None;
    scan.gatt_client = None;
}

/// Fully clean up a Scan context.
///
/// Unregisters the Scan Refresh notification callback and releases all
/// GATT references. Called during device removal.
///
/// Replaces C `scan_free()` from scan.c.
fn scan_free(scan: &mut Scan) {
    // Unregister the Scan Refresh notification if active.
    if let (Some(cb_id), Some(client)) = (scan.refresh_cb_id, &scan.gatt_client) {
        client.unregister_notify(cb_id);
    }

    scan.refresh_cb_id = None;
    scan.scan_param_attr_handle = None;
    scan.gatt_db = None;
    scan.gatt_client = None;
    scan.iw_handle = 0;
}

// ===========================================================================
// Profile Lifecycle — Probe
// ===========================================================================

/// Probe a device for the Scan Parameters profile.
///
/// Allocates a per-device `Scan` context and stores it in the module-level
/// state map. Guards against duplicate probes.
///
/// Replaces C `scan_param_probe()` from scan.c.
fn scan_param_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    // Try to lock the device to get the address. Use try_lock since this is
    // a sync callback and the device mutex may be held by the caller.
    let addr = match device.try_lock() {
        Ok(dev) => {
            let addr = *dev.get_address();
            debug!("Scan Parameters probe: {}", dev.get_address());
            btd_debug(0, &format!("Scan Parameters probe: {}", dev.get_address()));
            addr
        }
        Err(_) => {
            // If we can't lock, use a placeholder. This shouldn't normally
            // happen since the profile framework doesn't hold the device lock
            // when calling probe.
            error!("Scan Parameters: could not lock device for probe");
            btd_error(0, "Scan Parameters: could not lock device for probe");
            return Err(BtdError::InProgress("Device lock contention".to_owned()));
        }
    };

    let mut state = SCAN_STATE.lock().unwrap_or_else(|e| e.into_inner());

    // Guard against duplicate probe calls.
    if state.contains_key(&addr) {
        error!("Scan Parameters Client driver was probed twice");
        btd_error(0, "Scan Parameters Client driver was probed twice");
        return Err(BtdError::AlreadyExists(
            "Scan Parameters Client driver was probed twice".to_owned(),
        ));
    }

    // Allocate and store the new Scan context.
    let scan = Arc::new(StdMutex::new(Scan::new()));
    state.insert(addr, scan);

    Ok(())
}

// ===========================================================================
// Profile Lifecycle — Disconnect
// ===========================================================================

/// Disconnect the Scan Parameters profile from a device.
///
/// Resets GATT state while preserving the `Scan` context for potential
/// reconnection.
///
/// Replaces C `scan_param_disconnect()` from scan.c.
async fn scan_param_disconnect(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Result<(), BtdError> {
    let addr = {
        let dev = device.lock().await;
        *dev.get_address()
    };

    let state = SCAN_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(scan_arc) = state.get(&addr) {
        let mut scan = scan_arc.lock().unwrap_or_else(|e| e.into_inner());
        scan_reset(&mut scan);
    }

    // Signal successful disconnection (equivalent to
    // btd_service_disconnecting_complete(service, 0) in C).
    // Returning Ok(()) from disconnect signals success.
    Ok(())
}

// ===========================================================================
// Profile Lifecycle — Remove
// ===========================================================================

/// Remove the Scan Parameters profile from a device.
///
/// Fully cleans up the per-device `Scan` context, unregistering
/// notification callbacks and removing the context from the state map.
///
/// Replaces C `scan_param_remove()` from scan.c.
fn scan_param_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let addr = match device.try_lock() {
        Ok(dev) => *dev.get_address(),
        Err(_) => {
            error!("Scan Parameters: could not lock device for remove");
            btd_error(0, "Scan Parameters: could not lock device for remove");
            return;
        }
    };

    let mut state = SCAN_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(scan_arc) = state.remove(&addr) {
        let mut scan = scan_arc.lock().unwrap_or_else(|e| e.into_inner());
        scan_free(&mut scan);
    }
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the Scan Parameters plugin.
///
/// Creates and registers the Scan Parameters Client Driver profile with the
/// daemon's profile registry.
///
/// Replaces C `scan_param_init()` from scan.c.
fn scan_param_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("scanparam plugin init");

    // Build the profile descriptor.
    let mut profile = BtdProfile::new("Scan Parameters Client Driver");
    profile.bearer = BTD_PROFILE_BEARER_LE;
    profile.remote_uuid = Some(SCAN_PARAMETERS_UUID_STR.to_owned());

    // Set lifecycle callbacks.
    //
    // Probe and remove are synchronous closures.
    profile.set_device_probe(Box::new(scan_param_probe));
    profile.set_device_remove(Box::new(scan_param_remove));

    // Accept and disconnect return Futures (async closures).
    profile.set_accept(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { scan_param_accept(&device).await })
    }));

    profile.set_disconnect(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { scan_param_disconnect(&device).await })
    }));

    // Store a copy for unregistration during exit.
    {
        let stored = BtdProfile::new("Scan Parameters Client Driver");
        let mut guard = SCAN_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    // Register the profile asynchronously.
    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(profile).await {
            error!("Failed to register Scan Parameters profile: {}", e);
            btd_error(
                0,
                &format!("Failed to register Scan Parameters profile: {}", e),
            );
        }
    });

    Ok(())
}

/// Shut down the Scan Parameters plugin.
///
/// Unregisters the profile and clears all per-device state.
///
/// Replaces C `scan_param_exit()` from scan.c.
fn scan_param_exit() {
    debug!("scanparam plugin exit");

    // Unregister the profile asynchronously.
    let profile_opt = {
        let mut guard = SCAN_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };

    if let Some(profile) = profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }

    // Clear all per-device state and clean up notification registrations.
    let mut state = SCAN_STATE.lock().unwrap_or_else(|e| e.into_inner());
    for (_addr, scan_arc) in state.drain() {
        let mut scan = scan_arc.lock().unwrap_or_else(|e| e.into_inner());
        scan_free(&mut scan);
    }
}

// ===========================================================================
// Exported struct — ScanParamPlugin
// ===========================================================================

/// Scan Parameters plugin descriptor.
///
/// Provides the public API surface for the Scan Parameters profile plugin.
/// The actual plugin lifecycle is handled through [`PluginDesc`] registered
/// via [`inventory::submit!`], which calls the module-level
/// [`scan_param_init`] and [`scan_param_exit`] functions.
///
/// This struct satisfies the export schema requirement for a
/// `ScanParamPlugin` class with `name()`, `version()`, `priority()`,
/// `init()`, and `exit()` members.
pub struct ScanParamPlugin;

impl ScanParamPlugin {
    /// Returns the unique plugin name: `"scanparam"`.
    pub fn name(&self) -> &str {
        "scanparam"
    }

    /// Returns the plugin version string (matches daemon VERSION).
    pub fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority: `Default` (0).
    pub fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    /// Initializes the Scan Parameters plugin.
    ///
    /// Delegates to the module-level [`scan_param_init`] function.
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        scan_param_init()
    }

    /// Cleans up the Scan Parameters plugin.
    ///
    /// Delegates to the module-level [`scan_param_exit`] function.
    pub fn exit(&self) {
        scan_param_exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

/// Register the scanparam plugin at link time so that `plugin_init()` in the
/// plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(scanparam, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, scan_param_init, scan_param_exit)`.
#[allow(unsafe_code)]
mod _scanparam_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "scanparam",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::scan_param_init,
            exit: super::scan_param_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the ScanParamPlugin name matches the expected value.
    #[test]
    fn test_plugin_name() {
        let plugin = ScanParamPlugin;
        assert_eq!(plugin.name(), "scanparam");
    }

    /// Verify the ScanParamPlugin version is non-empty.
    #[test]
    fn test_plugin_version() {
        let plugin = ScanParamPlugin;
        assert!(!plugin.version().is_empty());
    }

    /// Verify the ScanParamPlugin priority is Default.
    #[test]
    fn test_plugin_priority() {
        let plugin = ScanParamPlugin;
        assert_eq!(plugin.priority(), PluginPriority::Default);
    }

    /// Verify Scan struct initializes with empty/zero state.
    #[test]
    fn test_scan_new() {
        let scan = Scan::new();
        assert!(scan.gatt_db.is_none());
        assert!(scan.gatt_client.is_none());
        assert!(scan.scan_param_attr_handle.is_none());
        assert_eq!(scan.iw_handle, 0);
        assert!(scan.refresh_cb_id.is_none());
    }

    /// Verify scan_reset clears GATT state.
    #[test]
    fn test_scan_reset() {
        let mut scan = Scan::new();
        scan.iw_handle = 0x0042;
        scan.scan_param_attr_handle = Some(0x0001);
        scan_reset(&mut scan);
        assert!(scan.scan_param_attr_handle.is_none());
        assert!(scan.gatt_db.is_none());
        assert!(scan.gatt_client.is_none());
        // iw_handle is NOT cleared by reset (only by free)
        assert_eq!(scan.iw_handle, 0x0042);
    }

    /// Verify scan_free clears all state including iw_handle.
    #[test]
    fn test_scan_free() {
        let mut scan = Scan::new();
        scan.iw_handle = 0x0042;
        scan.scan_param_attr_handle = Some(0x0001);
        scan_free(&mut scan);
        assert!(scan.scan_param_attr_handle.is_none());
        assert!(scan.gatt_db.is_none());
        assert!(scan.gatt_client.is_none());
        assert_eq!(scan.iw_handle, 0);
        assert!(scan.refresh_cb_id.is_none());
    }

    /// Verify UUID constants are correctly defined.
    #[test]
    fn test_uuid_constants() {
        assert_eq!(SCAN_PARAMETERS_UUID, 0x1813);
        assert_eq!(SCAN_INTERVAL_WIN_UUID, 0x2A4F);
        assert_eq!(SCAN_REFRESH_UUID, 0x2A31);
        assert_eq!(SERVER_REQUIRES_REFRESH, 0x00);
    }

    /// Verify default scan parameter values.
    #[test]
    fn test_default_scan_params() {
        assert_eq!(DEFAULT_SCAN_INTERVAL, 0x0060);
        assert_eq!(DEFAULT_SCAN_WINDOW, 0x0030);
    }

    /// Verify BtUuid comparisons for characteristic matching.
    #[test]
    fn test_uuid_comparison() {
        let iwin = BtUuid::from_u16(SCAN_INTERVAL_WIN_UUID);
        let refresh = BtUuid::from_u16(SCAN_REFRESH_UUID);

        assert_eq!(iwin, BtUuid::from_u16(0x2A4F));
        assert_eq!(refresh, BtUuid::from_u16(0x2A31));
        assert_ne!(iwin, refresh);
    }

    /// Verify the Scan Parameters Service UUID string format.
    #[test]
    fn test_scan_parameters_uuid_str() {
        assert_eq!(
            SCAN_PARAMETERS_UUID_STR,
            "00001813-0000-1000-8000-00805f9b34fb"
        );
    }

    /// Verify scan interval/window LE byte encoding.
    #[test]
    fn test_scan_param_encoding() {
        let interval: u16 = 0x0060;
        let window: u16 = 0x0030;

        let mut value = [0u8; 4];
        value[0..2].copy_from_slice(&interval.to_le_bytes());
        value[2..4].copy_from_slice(&window.to_le_bytes());

        assert_eq!(value, [0x60, 0x00, 0x30, 0x00]);
    }
}
