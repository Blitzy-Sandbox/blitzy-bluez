// SPDX-License-Identifier: GPL-2.0-or-later
// ==========================================================================
// Admin policy allowlist plugin — Rust rewrite of plugins/admin.c (638 lines)
//
// Provides experimental `org.bluez.AdminPolicySet1` and
// `org.bluez.AdminPolicyStatus1` D-Bus interfaces for service UUID
// allow-listing with INI-based persistence via rust-ini.
//
// Plugin priority: DEFAULT (0)
// Adapter driver flag: experimental = true
// ==========================================================================

use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use tokio::sync::Mutex as TokioMutex;

use ini::Ini;
use tracing::{debug, error, info, warn};
use zbus::Connection;

use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::util::uuid::BtUuid;

use crate::adapter::{
    BtdAdapter, BtdAdapterDriver, adapter_find, adapter_get_path, btd_adapter_get_index,
    btd_adapter_get_storage_dir, btd_adapter_set_allowed_uuids, btd_register_adapter_driver,
    btd_unregister_adapter_driver,
};
use crate::dbus_common::btd_get_dbus_connection;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_info, btd_warn};
use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};

use crate::storage::create_filename;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface for admin policy control methods (adapter path).
const ADMIN_POLICY_SET_INTERFACE: &str = "org.bluez.AdminPolicySet1";

/// D-Bus interface for admin policy status properties (adapter + device paths).
const ADMIN_POLICY_STATUS_INTERFACE: &str = "org.bluez.AdminPolicyStatus1";

/// Storage file name suffix for admin policy settings.
const ADMIN_POLICY_STORAGE_FILE: &str = "admin_policy_settings";

/// INI section name used for policy persistence.
const INI_SECTION_GENERAL: &str = "General";

/// INI key name for the service allowlist.
const INI_KEY_SERVICE_ALLOWLIST: &str = "ServiceAllowlist";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Admin policy state for a single adapter.
///
/// Replaces C `struct btd_admin_policy` — holds the adapter identifier, its
/// D-Bus path, the storage directory for persistence, and the parsed service
/// UUID allowlist.
struct BtdAdminPolicy {
    /// HCI adapter index (for logging).
    adapter_index: u16,
    /// D-Bus object path of the owning adapter (e.g. `/org/bluez/hci0`).
    adapter_path: String,
    /// Adapter address string in `XX:XX:XX:XX:XX:XX` format (for storage path).
    adapter_address: String,
    /// Filesystem directory for adapter-specific storage.
    storage_dir: String,
    /// Current service UUID allowlist. An empty list means "allow everything".
    service_allowlist: Vec<BtUuid>,
}

/// Per-device tracking data for the admin policy.
///
/// Replaces C `struct device_data`. Tracks whether a device is affected by the
/// current admin UUID allowlist policy and holds the device's D-Bus path for
/// interface registration/removal.
struct DeviceData {
    /// Bluetooth device address.
    addr: BdAddr,
    /// D-Bus object path (e.g. `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX`).
    path: String,
    /// Whether the device is affected by the current allowlist policy.
    affected: bool,
}

/// Module-level admin plugin state.
///
/// Replaces the C module-level globals `policy_data`, `devices`, and
/// `dbus_conn`. Protected by a `std::sync::Mutex` (not tokio) since it is
/// accessed from both synchronous adapter-driver callbacks and asynchronous
/// D-Bus method handlers (without holding the lock across `.await` points).
struct AdminState {
    /// Current admin policy for the adapter (set during probe, cleared during
    /// remove). Only one adapter is supported at a time (matching C behavior).
    policy: Option<BtdAdminPolicy>,
    /// List of tracked devices whose status interface has been registered.
    devices: Vec<DeviceData>,
}

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

/// Cached D-Bus connection (set during `admin_init`).
static DBUS_CONN: OnceLock<Connection> = OnceLock::new();

/// Global admin plugin state protected by a blocking mutex.
static ADMIN_STATE: std::sync::LazyLock<StdMutex<AdminState>> =
    std::sync::LazyLock::new(|| StdMutex::new(AdminState { policy: None, devices: Vec::new() }));

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Construct the D-Bus object path for a device under the given adapter.
///
/// Produces `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX` from the adapter path and
/// the Bluetooth device address, matching the BlueZ path convention.
fn device_dbus_path(adapter_path: &str, addr: &BdAddr) -> String {
    let addr_str = addr.ba2str().replace(':', "_");
    format!("{}/dev_{}", adapter_path, addr_str)
}

/// Build the full filesystem path for the admin policy settings file.
///
/// Uses `create_filename` from the storage module to produce
/// `<STORAGEDIR>/<adapter_address>/admin_policy_settings`.
fn policy_settings_path(adapter_address: &str) -> PathBuf {
    let suffix = format!("/{}/{}", adapter_address, ADMIN_POLICY_STORAGE_FILE);
    create_filename(&suffix)
}

/// Parse a D-Bus array of UUID strings into a deduplicated list of `BtUuid`.
///
/// Replaces C `parse_allow_service_list`. Returns `Err(BtdError)` if any
/// string fails to parse as a valid Bluetooth UUID.
fn parse_allow_service_list(uuid_strings: &[String]) -> Result<Vec<BtUuid>, BtdError> {
    let mut result: Vec<BtUuid> = Vec::with_capacity(uuid_strings.len());
    for s in uuid_strings {
        let uuid = BtUuid::from_str(s).map_err(|_| {
            error!("Failed to parse UUID string: {}", s);
            BtdError::invalid_args()
        })?;
        // Deduplicate (matching C `queue_find(uuid_list, uuid_match, uuid)`)
        if !result.iter().any(|existing| existing.eq(&uuid)) {
            result.push(uuid);
        }
    }
    Ok(result)
}

/// Convert the allowlist from `Vec<BtUuid>` to `HashSet<String>` for the
/// adapter API (`btd_adapter_set_allowed_uuids` expects `HashSet<String>`).
fn allowlist_to_hashset(allowlist: &[BtUuid]) -> HashSet<String> {
    allowlist.iter().map(|u| u.to_string()).collect()
}

/// Convert the allowlist from `Vec<BtUuid>` to `Vec<String>` for D-Bus
/// property emission.
fn allowlist_to_strings(allowlist: &[BtUuid]) -> Vec<String> {
    allowlist.iter().map(|u| u.to_string()).collect()
}

/// Compute whether a device is "affected by policy" given the current
/// service allowlist. When the allowlist is empty, no policy is active and
/// no device is affected. When the allowlist is non-empty, we conservatively
/// mark the device as affected (the adapter layer handles per-service checks).
fn compute_device_affected(allowlist: &[BtUuid]) -> bool {
    !allowlist.is_empty()
}

// ---------------------------------------------------------------------------
// Persistence — store / load policy settings
// ---------------------------------------------------------------------------

/// Persist the current admin policy allowlist to the INI storage file.
///
/// File format (matching C `GKeyFile` behavior):
/// ```ini
/// [General]
/// ServiceAllowlist=uuid1;uuid2;uuid3
/// ```
///
/// Replaces C `store_policy_settings`.
fn store_policy_settings(policy: &BtdAdminPolicy) {
    let path = policy_settings_path(&policy.adapter_address);

    btd_debug(
        policy.adapter_index,
        &format!(
            "Storing admin policy for {} (storage_dir: {}) to {}",
            policy.adapter_path,
            policy.storage_dir,
            path.display()
        ),
    );

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            btd_error(policy.adapter_index, &format!("Failed to create storage directory: {}", e));
            return;
        }
    }

    let uuid_strs = allowlist_to_strings(&policy.service_allowlist);
    let allowlist_value = uuid_strs.join(";");

    let mut ini = Ini::new();
    ini.with_section(Some(INI_SECTION_GENERAL)).set(INI_KEY_SERVICE_ALLOWLIST, &allowlist_value);

    if let Err(e) = ini.write_to_file(&path) {
        btd_error(
            policy.adapter_index,
            &format!("Unable to write policy settings to {}: {}", path.display(), e),
        );
    } else {
        btd_debug(policy.adapter_index, &format!("Stored policy settings to {}", path.display()));
    }
}

/// Load admin policy allowlist from the INI storage file.
///
/// If the file does not exist, it is created with empty settings. If the file
/// exists but cannot be parsed, an error is logged and the allowlist remains
/// empty.
///
/// Replaces C `load_policy_settings` and `key_file_load_service_allowlist`.
fn load_policy_settings(policy: &mut BtdAdminPolicy) {
    let path = policy_settings_path(&policy.adapter_address);

    // If the file does not exist yet, create it with current (empty) settings
    // and return — matching the C behavior of creating the file on first probe.
    if std::fs::metadata(&path).is_err() {
        store_policy_settings(policy);
        return;
    }

    match Ini::load_from_file(&path) {
        Ok(ini) => {
            if let Some(section) = ini.section(Some(INI_SECTION_GENERAL)) {
                if let Some(allowlist_str) = section.get(INI_KEY_SERVICE_ALLOWLIST) {
                    let mut uuids: Vec<BtUuid> = Vec::new();
                    for uuid_str in allowlist_str.split(';') {
                        let trimmed = uuid_str.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        match BtUuid::from_str(trimmed) {
                            Ok(uuid) => {
                                // Deduplicate
                                if !uuids.iter().any(|u| u.eq(&uuid)) {
                                    uuids.push(uuid);
                                }
                            }
                            Err(_) => {
                                btd_error(
                                    policy.adapter_index,
                                    &format!("Failed to convert '{}' to UUID", trimmed),
                                );
                                // On parse failure, abort loading (match C behavior)
                                return;
                            }
                        }
                    }
                    policy.service_allowlist = uuids;
                    btd_debug(
                        policy.adapter_index,
                        &format!(
                            "Loaded {} service allowlist UUIDs from {}",
                            policy.service_allowlist.len(),
                            path.display()
                        ),
                    );
                }
            }
        }
        Err(e) => {
            btd_error(
                policy.adapter_index,
                &format!("Unable to load key file from {}: {}", path.display(), e),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface: org.bluez.AdminPolicySet1 (registered on adapter path)
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.AdminPolicySet1`.
///
/// Provides the `SetServiceAllowList` method to configure the service UUID
/// allowlist for an adapter. Registered at the adapter D-Bus path (e.g.
/// `/org/bluez/hci0`).
struct AdminPolicySetIface {
    /// HCI adapter index — used to look up the adapter for applying settings.
    adapter_index: u16,
    /// D-Bus adapter path — used for cross-interface signal emission.
    adapter_path: String,
    /// Adapter address — used for constructing the storage path.
    adapter_address: String,
}

#[zbus::interface(name = "org.bluez.AdminPolicySet1")]
impl AdminPolicySetIface {
    /// Set the list of allowed service UUIDs for the adapter.
    ///
    /// Replaces C `set_service_allowlist` D-Bus method handler.
    ///
    /// # Arguments
    /// * `uuids` — Array of UUID strings (e.g. `["0000110a-0000-1000-8000-00805f9b34fb"]`).
    ///
    /// # Errors
    /// * `org.bluez.Error.InvalidArguments` — if a UUID string cannot be parsed.
    /// * `org.bluez.Error.Failed` — if applying the allowlist to the adapter fails.
    async fn set_service_allow_list(&self, uuids: Vec<String>) -> Result<(), BtdError> {
        debug!("SetServiceAllowList called with {} UUIDs", uuids.len());

        // Parse and deduplicate the UUID list.
        let parsed_uuids = parse_allow_service_list(&uuids)?;

        // Convert to HashSet<String> for the adapter API.
        let uuid_set = allowlist_to_hashset(&parsed_uuids);

        // Apply allowlist to the adapter, using adapter lookup by index.
        let adapter_arc = adapter_find(self.adapter_index)
            .await
            .ok_or_else(|| BtdError::failed("Adapter not found"))?;

        // Log using adapter helper functions for diagnostic context.
        let adapter_index = btd_adapter_get_index(&adapter_arc).await;
        let adapter_path = adapter_get_path(&adapter_arc).await;
        let storage_dir = btd_adapter_get_storage_dir(&adapter_arc).await;
        debug!(
            "Applying service allowlist to adapter hci{} at {} (storage: {}, addr: {})",
            adapter_index, adapter_path, storage_dir, self.adapter_address
        );

        btd_adapter_set_allowed_uuids(&adapter_arc, uuid_set).await;

        // Update the module-level admin state and persist.
        {
            let mut state = ADMIN_STATE.lock().unwrap();
            if let Some(ref mut policy) = state.policy {
                policy.service_allowlist = parsed_uuids.clone();
                store_policy_settings(policy);
            }
        }

        // Emit ServiceAllowList property change on the AdminPolicyStatus1
        // interface at the adapter path.
        if let Some(conn) = DBUS_CONN.get() {
            let obj_server = conn.object_server();
            if let Ok(iface_ref) = obj_server
                .interface::<_, AdminPolicyStatusAdapterIface>(self.adapter_path.as_str())
                .await
            {
                let guard = iface_ref.get().await;
                let _ = guard.service_allow_list_changed(iface_ref.signal_emitter()).await;
                drop(guard);
            }

            // Update per-device affected status and emit AffectedByPolicy
            // property changes where the value actually changed.
            update_all_devices_affected(conn, &parsed_uuids).await;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface: org.bluez.AdminPolicyStatus1 (adapter variant)
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.AdminPolicyStatus1` on
/// adapter object paths.
///
/// Exposes the read-only `ServiceAllowList` property showing the current
/// list of allowed service UUIDs.
struct AdminPolicyStatusAdapterIface;

#[zbus::interface(name = "org.bluez.AdminPolicyStatus1")]
impl AdminPolicyStatusAdapterIface {
    /// The current list of allowed service UUIDs as strings.
    ///
    /// An empty list means all services are allowed (no restriction).
    /// The value is read from the module-level `ADMIN_STATE`.
    #[zbus(property)]
    fn service_allow_list(&self) -> Vec<String> {
        let state = ADMIN_STATE.lock().unwrap();
        state
            .policy
            .as_ref()
            .map(|p| allowlist_to_strings(&p.service_allowlist))
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface: org.bluez.AdminPolicyStatus1 (device variant)
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.AdminPolicyStatus1` on
/// device object paths.
///
/// Exposes the read-only `AffectedByPolicy` property indicating whether
/// the device is affected by the current admin allowlist policy.
struct AdminPolicyStatusDeviceIface {
    /// D-Bus path of the device — used to look up affected status in state.
    device_path: String,
}

#[zbus::interface(name = "org.bluez.AdminPolicyStatus1")]
impl AdminPolicyStatusDeviceIface {
    /// Whether this device is affected by the admin allowlist policy.
    ///
    /// `true` indicates at least one of the device's services is not in the
    /// allowlist. The value is read from the module-level `ADMIN_STATE`.
    #[zbus(property)]
    fn affected_by_policy(&self) -> bool {
        let state = ADMIN_STATE.lock().unwrap();
        state
            .devices
            .iter()
            .find(|d| d.path == self.device_path)
            .map(|d| d.affected)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Device affected-state management
// ---------------------------------------------------------------------------

/// Update the `affected` flag for all tracked devices after a policy change,
/// emitting `AffectedByPolicy` property-changed signals where the value
/// actually changed.
///
/// Replaces C `queue_foreach(devices, update_device_affected, NULL)`.
async fn update_all_devices_affected(conn: &Connection, allowlist: &[BtUuid]) {
    // Collect device paths whose affected status changed (to avoid holding
    // the blocking mutex across await points).
    let changed_paths: Vec<String>;
    {
        let mut state = ADMIN_STATE.lock().unwrap();
        let new_affected = compute_device_affected(allowlist);
        changed_paths = state
            .devices
            .iter_mut()
            .filter_map(|dev_data| {
                if new_affected != dev_data.affected {
                    dev_data.affected = new_affected;
                    Some(dev_data.path.clone())
                } else {
                    None
                }
            })
            .collect();
    } // Mutex released before any async work.

    // Emit property-changed signals for devices whose status changed.
    let obj_server = conn.object_server();
    for path in &changed_paths {
        if let Ok(iface_ref) =
            obj_server.interface::<_, AdminPolicyStatusDeviceIface>(path.as_str()).await
        {
            let guard = iface_ref.get().await;
            let _ = guard.affected_by_policy_changed(iface_ref.signal_emitter()).await;
            drop(guard);
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface registration helpers
// ---------------------------------------------------------------------------

/// Register `AdminPolicySet1` and `AdminPolicyStatus1` interfaces at the
/// adapter D-Bus path.
///
/// Returns an error if registration fails. Uses blocking async execution
/// since this is called from the synchronous adapter driver probe callback.
fn register_adapter_interfaces(
    conn: &Connection,
    adapter_path: &str,
    adapter_index: u16,
    adapter_address: &str,
) -> Result<(), BtdError> {
    let set_iface = AdminPolicySetIface {
        adapter_index,
        adapter_path: adapter_path.to_owned(),
        adapter_address: adapter_address.to_owned(),
    };
    let status_iface = AdminPolicyStatusAdapterIface;

    // Use block_in_place + block_on to perform async D-Bus registration from
    // a synchronous callback. Safe because: (a) bluetoothd uses a
    // multi-threaded tokio runtime, (b) we do NOT hold the adapter tokio mutex.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let obj_server = conn.object_server();

            if let Err(e) = obj_server.at(adapter_path, set_iface).await {
                btd_error(
                    adapter_index,
                    &format!(
                        "Failed to register {} at {}: {}",
                        ADMIN_POLICY_SET_INTERFACE, adapter_path, e
                    ),
                );
                return Err(BtdError::failed("Failed to register AdminPolicySet1"));
            }

            if let Err(e) = obj_server.at(adapter_path, status_iface).await {
                btd_error(
                    adapter_index,
                    &format!(
                        "Failed to register {} at {}: {}",
                        ADMIN_POLICY_STATUS_INTERFACE, adapter_path, e
                    ),
                );
                // Rollback the set interface.
                let _ = obj_server.remove::<AdminPolicySetIface, _>(adapter_path).await;
                return Err(BtdError::failed("Failed to register AdminPolicyStatus1"));
            }

            btd_info(
                adapter_index,
                &format!("Registered admin policy interfaces at {}", adapter_path),
            );

            Ok(())
        })
    })
}

/// Unregister `AdminPolicySet1` and `AdminPolicyStatus1` interfaces from the
/// adapter D-Bus path.
fn unregister_adapter_interfaces(conn: &Connection, adapter_path: &str, adapter_index: u16) {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let obj_server = conn.object_server();
            let _ = obj_server.remove::<AdminPolicySetIface, _>(adapter_path).await;
            let _ = obj_server.remove::<AdminPolicyStatusAdapterIface, _>(adapter_path).await;
            btd_debug(
                adapter_index,
                &format!("Unregistered admin policy interfaces from {}", adapter_path),
            );
        });
    });
}

/// Register `AdminPolicyStatus1` on a device D-Bus path.
fn register_device_interface(
    conn: &Connection,
    device_path: &str,
    adapter_index: u16,
) -> Result<(), BtdError> {
    let iface = AdminPolicyStatusDeviceIface { device_path: device_path.to_owned() };

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let obj_server = conn.object_server();
            if let Err(e) = obj_server.at(device_path, iface).await {
                btd_error(
                    adapter_index,
                    &format!(
                        "Failed to register {} at {}: {}",
                        ADMIN_POLICY_STATUS_INTERFACE, device_path, e
                    ),
                );
                return Err(BtdError::failed("Failed to register device AdminPolicyStatus1"));
            }
            btd_debug(
                adapter_index,
                &format!("Registered device status interface at {}", device_path),
            );
            Ok(())
        })
    })
}

/// Unregister `AdminPolicyStatus1` from a device D-Bus path.
fn unregister_device_interface(conn: &Connection, device_path: &str, adapter_index: u16) {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let obj_server = conn.object_server();
            let _ = obj_server.remove::<AdminPolicyStatusDeviceIface, _>(device_path).await;
            btd_debug(
                adapter_index,
                &format!("Unregistered device status interface from {}", device_path),
            );
        });
    });
}

// ---------------------------------------------------------------------------
// Adapter driver
// ---------------------------------------------------------------------------

/// Admin policy adapter driver.
///
/// Replaces C `static struct btd_adapter_driver admin_policy_driver`. This is
/// registered during `admin_init` and provides probe/remove/device callbacks
/// to manage admin policy D-Bus interfaces and persistent storage.
struct AdminPolicyDriver;

impl BtdAdapterDriver for AdminPolicyDriver {
    fn name(&self) -> &str {
        "admin_policy"
    }

    /// Probe callback — called when an adapter is powered on.
    ///
    /// Creates the admin policy state, loads stored allowlist settings, and
    /// registers D-Bus interfaces. If the policy data already exists (e.g.
    /// from a previous probe), a warning is logged and the probe succeeds
    /// without re-creating.
    ///
    /// Replaces C `admin_policy_adapter_probe`.
    fn probe(&self, adapter: Arc<TokioMutex<BtdAdapter>>) -> Result<(), BtdError> {
        let (adapter_index, adapter_path, adapter_address, storage_dir) =
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let a = adapter.lock().await;
                    (a.index, a.path.clone(), a.address.ba2str(), a.storage_dir.clone())
                })
            });

        btd_debug(adapter_index, &format!("Admin policy probe for adapter {}", adapter_path));

        // Check if policy data already exists (guard against double-probe).
        {
            let state = ADMIN_STATE.lock().unwrap();
            if state.policy.is_some() {
                warn!("Admin policy data already exists for adapter hci{}", adapter_index);
                btd_warn(adapter_index, "Policy data already exists");
                return Ok(());
            }
        }

        // Create the admin policy state.
        let mut policy = BtdAdminPolicy {
            adapter_index,
            adapter_path: adapter_path.clone(),
            adapter_address: adapter_address.clone(),
            storage_dir,
            service_allowlist: Vec::new(),
        };

        // Load stored settings from disk (may populate service_allowlist).
        load_policy_settings(&mut policy);

        // Capture the loaded allowlist for deferred adapter update.
        let loaded_uuids = allowlist_to_hashset(&policy.service_allowlist);
        let has_loaded_uuids = !loaded_uuids.is_empty();

        // Store policy in module state.
        {
            let mut state = ADMIN_STATE.lock().unwrap();
            state.policy = Some(policy);
        }

        // Register D-Bus interfaces on the adapter path.
        let conn = match DBUS_CONN.get() {
            Some(c) => c,
            None => {
                btd_error(adapter_index, "D-Bus connection not initialized");
                return Err(BtdError::failed("D-Bus connection not initialized"));
            }
        };

        if let Err(e) =
            register_adapter_interfaces(conn, &adapter_path, adapter_index, &adapter_address)
        {
            // Clean up policy state on failure.
            let mut state = ADMIN_STATE.lock().unwrap();
            state.policy = None;
            return Err(e);
        }

        // If we loaded a non-empty allowlist, apply it to the adapter.
        // The caller no longer holds any tokio Mutex on the adapter, so we
        // can safely use block_in_place + block_on to perform the async
        // allowlist update.
        if has_loaded_uuids {
            let idx = adapter_index;
            let uuids = loaded_uuids;
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    if let Some(adapter_arc) = adapter_find(idx).await {
                        btd_adapter_set_allowed_uuids(&adapter_arc, uuids).await;
                    }
                });
            });
        }

        btd_info(adapter_index, &format!("Admin policy plugin probed for {}", adapter_path));

        Ok(())
    }

    /// Remove callback — called when an adapter is powered off or removed.
    ///
    /// Unregisters all device status interfaces, then unregisters adapter
    /// interfaces, and clears the module-level policy state.
    ///
    /// Replaces C `admin_policy_remove`.
    fn remove(&self, adapter: Arc<TokioMutex<BtdAdapter>>) {
        let (adapter_index, adapter_path) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let a = adapter.lock().await;
                (a.index, a.path.clone())
            })
        });

        btd_debug(adapter_index, &format!("Admin policy remove for adapter {}", adapter_path));

        let conn = match DBUS_CONN.get() {
            Some(c) => c,
            None => return,
        };

        // Unregister all tracked device interfaces.
        let device_paths: Vec<String>;
        {
            let state = ADMIN_STATE.lock().unwrap();
            device_paths = state.devices.iter().map(|d| d.path.clone()).collect();
        }

        for path in &device_paths {
            unregister_device_interface(conn, path, adapter_index);
        }

        // Clear device list and policy.
        {
            let mut state = ADMIN_STATE.lock().unwrap();
            state.devices.clear();
            state.policy = None;
        }

        // Unregister adapter interfaces.
        unregister_adapter_interfaces(conn, &adapter_path, adapter_index);

        btd_info(adapter_index, &format!("Admin policy plugin removed for {}", adapter_path));
    }

    /// Device-resolved callback — called when a device's services are resolved.
    ///
    /// Registers the `AdminPolicyStatus1` interface on the device's D-Bus path
    /// and computes the initial `AffectedByPolicy` value.
    ///
    /// Replaces C `admin_policy_device_added`.
    fn device_resolved(&self, adapter: Arc<TokioMutex<BtdAdapter>>, addr: &BdAddr) {
        let (adapter_index, adapter_path) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let a = adapter.lock().await;
                (a.index, a.path.clone())
            })
        });
        let device_path = device_dbus_path(&adapter_path, addr);

        btd_debug(adapter_index, &format!("Admin policy device resolved: {}", device_path));

        let conn = match DBUS_CONN.get() {
            Some(c) => c,
            None => return,
        };

        // Compute initial affected state from the current allowlist.
        let affected: bool;
        {
            let state = ADMIN_STATE.lock().unwrap();
            affected = state
                .policy
                .as_ref()
                .map(|p| compute_device_affected(&p.service_allowlist))
                .unwrap_or(false);
        }

        // Register device status interface.
        if register_device_interface(conn, &device_path, adapter_index).is_err() {
            return;
        }

        // Track the device in module state.
        let mut state = ADMIN_STATE.lock().unwrap();
        // Avoid duplicate entries.
        if state.devices.iter().any(|d| d.addr == *addr) {
            return;
        }
        state.devices.push(DeviceData { addr: *addr, path: device_path, affected });
    }

    /// Device-removed callback — called when a device is forgotten or removed.
    ///
    /// Unregisters the device's `AdminPolicyStatus1` interface and removes the
    /// device from tracking.
    ///
    /// Replaces C `admin_policy_device_removed`.
    fn device_removed(&self, adapter: Arc<TokioMutex<BtdAdapter>>, addr: &BdAddr) {
        let (adapter_index, adapter_path) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let a = adapter.lock().await;
                (a.index, a.path.clone())
            })
        });
        let device_path = device_dbus_path(&adapter_path, addr);

        btd_debug(adapter_index, &format!("Admin policy device removed: {}", device_path));

        let conn = match DBUS_CONN.get() {
            Some(c) => c,
            None => return,
        };

        // Remove from tracking.
        {
            let mut state = ADMIN_STATE.lock().unwrap();
            state.devices.retain(|d| d.addr != *addr);
        }

        // Unregister the device status interface.
        unregister_device_interface(conn, &device_path, adapter_index);
    }

    /// This driver is gated behind the experimental flag.
    fn experimental(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Plugin init / exit
// ---------------------------------------------------------------------------

/// Initialize the admin policy plugin.
///
/// Caches the D-Bus connection and registers the adapter driver. Called by the
/// plugin framework during daemon startup.
///
/// Replaces C `admin_init`.
fn admin_init() -> Result<(), Box<dyn std::error::Error>> {
    let conn = btd_get_dbus_connection().clone();
    let _ = DBUS_CONN.set(conn);

    info!("Initializing admin policy plugin");

    // Register the adapter driver (async operation, block from sync context).
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            btd_register_adapter_driver(Arc::new(AdminPolicyDriver)).await;
        });
    });

    Ok(())
}

/// Clean up the admin policy plugin.
///
/// Unregisters the adapter driver. Called by the plugin framework during daemon
/// shutdown.
///
/// Replaces C `admin_exit`.
fn admin_exit() {
    info!("Exiting admin policy plugin");

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            btd_unregister_adapter_driver("admin_policy").await;
        });
    });
}

// ---------------------------------------------------------------------------
// Public plugin descriptor
// ---------------------------------------------------------------------------

/// Admin policy allowlist plugin.
///
/// Provides experimental `org.bluez.AdminPolicySet1` and
/// `org.bluez.AdminPolicyStatus1` D-Bus interfaces for restricting allowed
/// service UUIDs per adapter, with persistence via rust-ini.
///
/// This struct exposes the plugin metadata and lifecycle methods, matching the
/// `BluetoothPlugin` trait contract. The actual registration with the daemon's
/// plugin framework is performed via the `inventory::submit!` call at the
/// bottom of this module.
pub struct AdminPlugin;

impl AdminPlugin {
    /// Returns the plugin name (`"admin"`).
    pub fn name() -> &'static str {
        "admin"
    }

    /// Returns the plugin version (crate version from `Cargo.toml`).
    pub fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority (`Default = 0`).
    pub fn priority() -> PluginPriority {
        PluginPriority::Default
    }

    /// Initialize the admin policy plugin.
    ///
    /// Caches the D-Bus connection and registers the admin policy adapter
    /// driver with the daemon.
    pub fn init() -> Result<(), Box<dyn std::error::Error>> {
        admin_init()
    }

    /// Clean up the admin policy plugin.
    ///
    /// Unregisters the admin policy adapter driver.
    pub fn exit() {
        admin_exit()
    }
}

/// Implements `BluetoothPlugin` for `AdminPlugin` so it can be used
/// directly as a trait object in addition to the `PluginDesc` inventory path.
impl BluetoothPlugin for AdminPlugin {
    fn name(&self) -> &str {
        AdminPlugin::name()
    }

    fn version(&self) -> &str {
        AdminPlugin::version()
    }

    fn priority(&self) -> PluginPriority {
        AdminPlugin::priority()
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        AdminPlugin::init()
    }

    fn exit(&self) {
        AdminPlugin::exit()
    }
}

// ---------------------------------------------------------------------------
// Plugin registration via inventory
// ---------------------------------------------------------------------------

inventory::submit! {
    PluginDesc {
        name: "admin",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: admin_init,
        exit: admin_exit,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify AdminPlugin exports the correct plugin name.
    #[test]
    fn test_admin_plugin_name() {
        assert_eq!(AdminPlugin::name(), "admin");
    }

    /// Verify AdminPlugin exports the correct priority.
    #[test]
    fn test_admin_plugin_priority() {
        assert!(matches!(AdminPlugin::priority(), PluginPriority::Default));
    }

    /// Verify AdminPlugin version is non-empty.
    #[test]
    fn test_admin_plugin_version() {
        let version = AdminPlugin::version();
        assert!(!version.is_empty(), "Plugin version should not be empty");
    }

    /// Verify BluetoothPlugin trait implementation works for AdminPlugin.
    #[test]
    fn test_admin_plugin_trait() {
        let plugin = AdminPlugin;
        assert_eq!(plugin.name(), "admin");
        assert!(!plugin.version().is_empty());
        assert!(matches!(plugin.priority(), PluginPriority::Default));
    }

    /// Test UUID parsing with valid full UUIDs.
    #[test]
    fn test_parse_allow_service_list_valid() {
        let uuids = vec![
            "00001800-0000-1000-8000-00805f9b34fb".to_string(),
            "0000110a-0000-1000-8000-00805f9b34fb".to_string(),
        ];
        let result = parse_allow_service_list(&uuids);
        assert!(result.is_ok(), "Valid UUIDs should parse successfully");
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 2, "Should have 2 parsed UUIDs");
    }

    /// Test UUID parsing with deduplication.
    #[test]
    fn test_parse_allow_service_list_dedup() {
        let uuids = vec![
            "00001800-0000-1000-8000-00805f9b34fb".to_string(),
            "00001800-0000-1000-8000-00805f9b34fb".to_string(),
            "0000110a-0000-1000-8000-00805f9b34fb".to_string(),
        ];
        let result = parse_allow_service_list(&uuids);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 2, "Duplicate UUIDs should be deduplicated");
    }

    /// Test UUID parsing with invalid input.
    #[test]
    fn test_parse_allow_service_list_invalid() {
        let uuids = vec!["not-a-valid-uuid".to_string()];
        let result = parse_allow_service_list(&uuids);
        assert!(result.is_err(), "Invalid UUID should produce error");
    }

    /// Test empty UUID list parsing.
    #[test]
    fn test_parse_allow_service_list_empty() {
        let uuids: Vec<String> = Vec::new();
        let result = parse_allow_service_list(&uuids);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.is_empty(), "Empty input should produce empty output");
    }

    /// Test allowlist to HashSet conversion.
    #[test]
    fn test_allowlist_to_hashset_conversion() {
        let uuids = vec![
            BtUuid::from_str("00001800-0000-1000-8000-00805f9b34fb").unwrap(),
            BtUuid::from_str("0000110a-0000-1000-8000-00805f9b34fb").unwrap(),
        ];
        let set = allowlist_to_hashset(&uuids);
        assert_eq!(set.len(), 2, "HashSet should contain 2 entries");
    }

    /// Test allowlist to string vector conversion.
    #[test]
    fn test_allowlist_to_strings_conversion() {
        let uuids = vec![BtUuid::from_str("00001800-0000-1000-8000-00805f9b34fb").unwrap()];
        let strings = allowlist_to_strings(&uuids);
        assert_eq!(strings.len(), 1);
        // The exact string format depends on BtUuid::to_string()
        assert!(!strings[0].is_empty(), "UUID string should not be empty");
    }

    /// Test device affected computation with empty allowlist.
    #[test]
    fn test_compute_affected_empty_allowlist() {
        let allowlist: Vec<BtUuid> = Vec::new();
        assert!(!compute_device_affected(&allowlist), "Empty allowlist should not affect devices");
    }

    /// Test device affected computation with non-empty allowlist.
    #[test]
    fn test_compute_affected_nonempty_allowlist() {
        let allowlist = vec![BtUuid::from_str("00001800-0000-1000-8000-00805f9b34fb").unwrap()];
        assert!(compute_device_affected(&allowlist), "Non-empty allowlist should affect devices");
    }

    /// Test INI storage round-trip format.
    #[test]
    fn test_ini_storage_roundtrip() {
        let uuid_strs =
            vec!["00001800-0000-1000-8000-00805f9b34fb", "0000110a-0000-1000-8000-00805f9b34fb"];
        let joined = uuid_strs.join(";");

        let mut ini = Ini::new();
        ini.with_section(Some(INI_SECTION_GENERAL)).set(INI_KEY_SERVICE_ALLOWLIST, &joined);

        let tmpdir = std::env::temp_dir();
        let path = tmpdir.join("blitzy_adhoc_test_admin_roundtrip.conf");
        ini.write_to_file(&path).expect("Write should succeed");

        let loaded = Ini::load_from_file(&path).expect("Load should succeed");
        let section = loaded.section(Some(INI_SECTION_GENERAL)).expect("Section should exist");
        let value = section.get(INI_KEY_SERVICE_ALLOWLIST).expect("Key should exist");

        let parsed: Vec<&str> = value.split(';').filter(|s| !s.trim().is_empty()).collect();
        assert_eq!(parsed.len(), 2, "Should round-trip 2 UUIDs");

        let _ = std::fs::remove_file(&path);
    }

    /// Test empty INI storage.
    #[test]
    fn test_ini_storage_empty() {
        let mut ini = Ini::new();
        ini.with_section(Some(INI_SECTION_GENERAL)).set(INI_KEY_SERVICE_ALLOWLIST, "");

        let tmpdir = std::env::temp_dir();
        let path = tmpdir.join("blitzy_adhoc_test_admin_empty.conf");
        ini.write_to_file(&path).expect("Write should succeed");

        let loaded = Ini::load_from_file(&path).expect("Load should succeed");
        let section = loaded.section(Some(INI_SECTION_GENERAL)).expect("Section should exist");
        let value = section.get(INI_KEY_SERVICE_ALLOWLIST).expect("Key should exist");

        let parsed: Vec<&str> = value.split(';').filter(|s| !s.trim().is_empty()).collect();
        assert_eq!(parsed.len(), 0, "Empty should produce 0 UUIDs");

        let _ = std::fs::remove_file(&path);
    }

    /// Test policy settings path construction.
    #[test]
    fn test_policy_settings_path() {
        let path = policy_settings_path("/var/lib/bluetooth/00:11:22:33:44:55");
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("00:11:22:33:44:55"), "Path should contain adapter directory");
        assert!(
            path_str.ends_with("admin_policy_settings"),
            "Path should end with admin_policy_settings"
        );
    }

    /// Test AdminState default initialization.
    #[test]
    fn test_admin_state_default() {
        // Access the module-level state to verify it initializes correctly
        let state = ADMIN_STATE.lock().unwrap();
        assert!(state.policy.is_none(), "Initial policy should be None");
        assert!(state.devices.is_empty(), "Initial devices should be empty");
    }
}
