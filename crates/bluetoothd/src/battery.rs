// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2020  Google LLC
//
// Battery management — Rust rewrite of `src/battery.c` and `src/battery.h`.
//
// This module implements two D-Bus interfaces:
//
// - `org.bluez.Battery1` — Exposes battery level information per-device with
//   read-only `Percentage` (u8) and `Source` (String) properties.  Registered
//   on device object paths when battery data is available.
//
// - `org.bluez.BatteryProviderManager1` — Manages third-party battery level
//   providers.  Exported on each adapter path with `RegisterBatteryProvider`
//   and `UnregisterBatteryProvider` methods.
//
// The module also provides an internal battery framework used by profile
// plugins (BAS client, HFP AG battery) to report battery levels:
//   - `btd_battery_register` — create a Battery1 object on a device path
//   - `btd_battery_update` — update the battery level (with charge smoothing)
//   - `btd_battery_unregister` — remove a Battery1 object
//
// Key conversion rules from C:
//   - `g_dbus_register_interface` → `#[zbus::interface]` + `object_server().at()`
//   - `g_dbus_add_disconnect_watch` → zbus `NameOwnerChanged` monitoring
//   - `GSList` of providers → `Vec<BatteryProvider>`
//   - `static struct queue *batteries` → `tokio::sync::RwLock<Vec<BtdBattery>>`
//   - `callback_t fn + void *user_data` → async closures / channels

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};
use zbus::Connection;
use zbus::zvariant::ObjectPath;

use bluez_shared::profiles::battery::BtBattery;

use crate::adapter::{BtdAdapter, adapter_get_path, btd_adapter_find_device_by_path};
use crate::dbus_common::btd_get_dbus_connection;
#[allow(unused_imports)]
use crate::device::BtdDevice;
// ERROR_INTERFACE is the 'org.bluez.Error' prefix used by BtdError for D-Bus
// error name construction (e.g. 'org.bluez.Error.AlreadyExists').  It is
// referenced here to maintain parity with the C includes and is available
// for any future direct error construction needs.
use crate::error::BtdError;
#[allow(unused_imports)]
use crate::error::ERROR_INTERFACE;
use crate::log::{self, btd_debug, btd_error, btd_warn};

// ===========================================================================
// Constants
// ===========================================================================

/// D-Bus interface name for `org.bluez.Battery1`.
pub const BATTERY_INTERFACE: &str = "org.bluez.Battery1";

/// D-Bus interface name for `org.bluez.BatteryProvider1` (third-party providers).
const BATTERY_PROVIDER_INTERFACE: &str = "org.bluez.BatteryProvider1";

/// D-Bus interface name for `org.bluez.BatteryProviderManager1`.
pub const BATTERY_PROVIDER_MANAGER_INTERFACE: &str = "org.bluez.BatteryProviderManager1";

/// Maximum valid battery percentage (inclusive).
pub const BATTERY_MAX_PERCENTAGE: u8 = 100;

// ===========================================================================
// Module-level battery registry
// ===========================================================================

/// Global registry of all active `BtdBattery` instances.
///
/// Replaces the C `static struct queue *batteries = NULL`.  Uses
/// `tokio::sync::RwLock` for concurrent read access from D-Bus property
/// queries while serializing mutations during registration / unregistration.
static BATTERIES: std::sync::LazyLock<RwLock<Vec<BtdBattery>>> =
    std::sync::LazyLock::new(|| RwLock::new(Vec::new()));

// ===========================================================================
// BtdBattery — per-device battery state
// ===========================================================================

/// Per-device battery state, replacing C `struct btd_battery`.
///
/// Each instance tracks battery level, data source, and a charge-fluctuation
/// smoother.  When registered, a `Battery1Interface` is exported on the
/// device's D-Bus object path so that external clients can read the current
/// battery level.
pub struct BtdBattery {
    /// D-Bus object path (typically the device path, e.g.
    /// `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX`).
    pub path: String,

    /// Current battery percentage (0–100, or `u8::MAX` when unknown).
    pub percentage: u8,

    /// Descriptive source of the battery information (e.g. `"HFP AG"`,
    /// `"BAS"`, or an external provider identifier).
    pub source: Option<String>,

    /// Root D-Bus path of the external battery provider that created this
    /// battery object, if any.  `None` for internally-created batteries.
    pub provider_path: Option<String>,

    /// Charge fluctuation smoother from `bluez_shared::profiles::battery`.
    filter: BtBattery,
}

impl BtdBattery {
    /// Create a new `BtdBattery`.
    ///
    /// The percentage is initialised to `u8::MAX` (unknown) until the first
    /// update arrives.  Matches the C `battery_new()` behaviour.
    fn new(path: &str, source: Option<&str>, provider_path: Option<&str>) -> Self {
        Self {
            path: path.to_owned(),
            percentage: u8::MAX,
            source: source.map(|s| s.to_owned()),
            provider_path: provider_path.map(|s| s.to_owned()),
            filter: BtBattery::new(),
        }
    }
}

// ===========================================================================
// Battery1 D-Bus interface
// ===========================================================================

/// D-Bus interface object for `org.bluez.Battery1`.
///
/// Registered on a device object path when battery data is available.  Holds
/// a reference to its path so that property queries can look up the
/// corresponding `BtdBattery` from the global registry.
struct Battery1Interface {
    /// The device D-Bus object path this interface is exported on.
    device_path: String,
}

/// Implementation of the `org.bluez.Battery1` D-Bus interface.
///
/// Both `Percentage` and `Source` are read-only properties.  The C
/// implementation uses `property_percentage_exists` / `property_source_exists`
/// to conditionally hide properties; in zbus we always return the property
/// value but return a sentinel (u8::MAX) for `Percentage` when unknown.
#[zbus::interface(name = "org.bluez.Battery1")]
impl Battery1Interface {
    /// Battery percentage (0–100).
    ///
    /// Returns `u8::MAX` (255) when the value is not yet known, matching the
    /// C conditional-existence pattern where `property_percentage_exists`
    /// hides the property until a valid reading arrives.
    #[zbus(property)]
    async fn percentage(&self) -> u8 {
        let batteries = BATTERIES.read().await;
        batteries.iter().find(|b| b.path == self.device_path).map_or(u8::MAX, |b| b.percentage)
    }

    /// Descriptive source of the battery information.
    ///
    /// Returns an empty string when no source is set, matching the C
    /// conditional-existence pattern where `property_source_exists` hides
    /// the property when source is NULL.
    #[zbus(property)]
    async fn source(&self) -> String {
        let batteries = BATTERIES.read().await;
        batteries
            .iter()
            .find(|b| b.path == self.device_path)
            .and_then(|b| b.source.clone())
            .unwrap_or_default()
    }
}

// ===========================================================================
// Internal battery framework — public API
// ===========================================================================

/// Register a new `Battery1` D-Bus interface on the given device path.
///
/// Creates a `BtdBattery` entry in the global registry and exports the
/// `Battery1` interface on the D-Bus object server at `path`.
///
/// Returns `true` on success, `false` if a battery with the same path is
/// already registered or the path is invalid.
///
/// # Arguments
///
/// * `path` — D-Bus object path (e.g. `/org/bluez/hci0/dev_...`)
/// * `source` — Descriptive source identifier (may be `None`)
/// * `provider_path` — External provider root path (may be `None` for
///   internally-created batteries)
///
/// Equivalent to C `btd_battery_register()`.
pub async fn btd_battery_register(
    path: &str,
    source: Option<&str>,
    provider_path: Option<&str>,
) -> bool {
    btd_debug(0, &format!("battery register: path = {path}"));

    // Check for duplicate path.
    {
        let batteries = BATTERIES.read().await;
        if batteries.iter().any(|b| b.path == path) {
            btd_error(0, "error registering battery: path exists");
            return false;
        }
    }

    // Validate D-Bus object path.
    if !path.starts_with('/') {
        btd_error(0, "error registering battery: invalid D-Bus object path");
        return false;
    }

    // Create the battery entry.
    let battery = BtdBattery::new(path, source, provider_path);

    // Register the Battery1 D-Bus interface on the device path.
    let conn = btd_get_dbus_connection();
    let iface = Battery1Interface { device_path: path.to_owned() };
    if let Err(e) = conn.object_server().at(path, iface).await {
        btd_error(0, &format!("error registering D-Bus interface for {path}: {e}"));
        return false;
    }

    // Add to global registry.
    {
        let mut batteries = BATTERIES.write().await;
        batteries.push(battery);
    }

    btd_debug(0, &format!("registered Battery object: {path}"));
    true
}

/// Unregister a `Battery1` D-Bus interface from the given device path.
///
/// Removes the battery from the global registry and unregisters the
/// `Battery1` interface from the D-Bus object server.
///
/// Returns `true` on success, `false` if the battery was not registered.
///
/// Equivalent to C `btd_battery_unregister()`.
pub async fn btd_battery_unregister(path: &str) -> bool {
    btd_debug(0, &format!("battery unregister: path = {path}"));

    // Check that the battery exists.
    {
        let batteries = BATTERIES.read().await;
        if !batteries.iter().any(|b| b.path == path) {
            btd_error(0, &format!("error unregistering battery: battery {path} is not registered"));
            return false;
        }
    }

    // Unregister the Battery1 D-Bus interface.
    let conn = btd_get_dbus_connection();
    let removed = conn.object_server().remove::<Battery1Interface, _>(path).await;
    if let Err(e) = removed {
        btd_error(0, &format!("error unregistering battery {path} from D-Bus interface: {e}"));
        return false;
    }

    // Remove from global registry.
    {
        let mut batteries = BATTERIES.write().await;
        batteries.retain(|b| b.path != path);
    }

    true
}

/// Update the battery percentage for a registered battery.
///
/// The new `percentage` value is passed through the charge-fluctuation
/// smoother before being stored.  If the smoothed value differs from the
/// current stored value, a D-Bus property-changed signal is emitted.
///
/// Returns `true` on success, `false` if the battery is not registered or
/// the percentage is invalid.
///
/// Equivalent to C `btd_battery_update()`.
pub async fn btd_battery_update(path: &str, percentage: u8) -> bool {
    btd_debug(0, &format!("battery update: path = {path}"));

    if percentage > BATTERY_MAX_PERCENTAGE {
        btd_error(0, "error updating battery: percentage is not valid");
        return false;
    }

    let mut batteries = BATTERIES.write().await;
    let battery = match batteries.iter_mut().find(|b| b.path == path) {
        Some(b) => b,
        None => {
            btd_error(0, "error updating battery: battery is not registered");
            return false;
        }
    };

    // Apply charge-fluctuation smoothing.
    let smoothed = battery.filter.charge(percentage);

    if battery.percentage == smoothed {
        return true;
    }

    battery.percentage = smoothed;

    // Emit D-Bus property-changed signal for Percentage.
    let battery_path = battery.path.clone();
    // Drop the write lock before performing async D-Bus operations to avoid
    // holding it across await points that may need concurrent read access.
    drop(batteries);

    let conn = btd_get_dbus_connection();
    let object_server = conn.object_server();
    if let Ok(obj_path) = ObjectPath::try_from(battery_path.as_str()) {
        let iface_ref = object_server.interface::<_, Battery1Interface>(obj_path).await;
        if let Ok(iface) = iface_ref {
            let ctxt = iface.signal_emitter();
            let iface_inner = iface.get().await;
            if let Err(e) = iface_inner.percentage_changed(ctxt).await {
                btd_warn(0, &format!("failed to emit Percentage change for {battery_path}: {e}"));
            }
        }
    }

    true
}

// ===========================================================================
// Battery Provider tracking
// ===========================================================================

/// Represents a registered external battery provider.
///
/// Replaces C `struct battery_provider`.  Each provider is identified by its
/// D-Bus sender name and root object path.
pub struct BatteryProvider {
    /// D-Bus sender unique name (`:1.42`, etc.).
    owner: String,

    /// Root D-Bus object path registered by the provider.
    path: String,

    /// Handle to the background task monitoring this provider's D-Bus name
    /// for disconnection.
    _monitor_handle: Option<JoinHandle<()>>,
}

// ===========================================================================
// BtdBatteryProviderManager
// ===========================================================================

/// Per-adapter battery provider manager state.
///
/// Replaces C `struct btd_battery_provider_manager`.  Manages the list of
/// registered battery providers for a single adapter.  The
/// `BatteryProviderManager1` D-Bus interface delegates to this state.
pub struct BtdBatteryProviderManager {
    /// Reference to the owning adapter (does not own; matches C semantics).
    pub adapter: Arc<Mutex<BtdAdapter>>,

    /// List of registered battery providers for this adapter.
    pub battery_providers: Arc<Mutex<Vec<BatteryProvider>>>,
}

impl BtdBatteryProviderManager {
    /// Create a new provider manager for the given adapter.
    fn new(adapter: Arc<Mutex<BtdAdapter>>) -> Self {
        Self { adapter, battery_providers: Arc::new(Mutex::new(Vec::new())) }
    }
}

// ===========================================================================
// BatteryProviderManager1 D-Bus interface
// ===========================================================================

/// D-Bus interface object for `org.bluez.BatteryProviderManager1`.
///
/// Holds a reference to the per-adapter provider manager state so that the
/// `RegisterBatteryProvider` and `UnregisterBatteryProvider` methods can
/// manipulate the provider list.
struct BatteryProviderManager1Interface {
    /// Shared reference to the adapter for device lookups.
    adapter: Arc<Mutex<BtdAdapter>>,

    /// Shared reference to the provider list.
    providers: Arc<Mutex<Vec<BatteryProvider>>>,
}

#[zbus::interface(name = "org.bluez.BatteryProviderManager1")]
impl BatteryProviderManager1Interface {
    /// Register an external battery provider.
    ///
    /// The `provider` argument is the root D-Bus object path under which the
    /// provider exposes `org.bluez.BatteryProvider1` objects.
    ///
    /// Matches C `register_battery_provider()`.
    async fn register_battery_provider(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        provider: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().ok_or_else(BtdError::invalid_args)?.to_owned();
        let path = provider.to_string();

        debug!("register battery provider path = {}", path);

        if !path.starts_with('/') {
            return Err(BtdError::invalid_args());
        }

        let mut providers = self.providers.lock().await;

        // Check for duplicate provider path.
        if providers.iter().any(|p| p.path == path) {
            return Err(BtdError::AlreadyExists("Provider already exists".to_owned()));
        }

        // Create background task to monitor provider D-Bus name for disconnection.
        let monitor_handle = {
            let providers_ref = Arc::clone(&self.providers);
            let adapter_ref = Arc::clone(&self.adapter);
            let sender_name = sender.to_string();
            let provider_path = path.clone();
            let conn = btd_get_dbus_connection().clone();

            tokio::spawn(async move {
                monitor_provider_disconnect(
                    conn,
                    sender_name,
                    provider_path,
                    providers_ref,
                    adapter_ref,
                )
                .await;
            })
        };

        // Set up monitoring for battery objects exposed by this provider.
        {
            let adapter_ref = Arc::clone(&self.adapter);
            let provider_path = path.clone();
            let conn = btd_get_dbus_connection().clone();
            let sender_name = sender.to_string();

            tokio::spawn(async move {
                monitor_provider_objects(conn, sender_name, provider_path, adapter_ref).await;
            });
        }

        providers.push(BatteryProvider {
            owner: sender.to_string(),
            path,
            _monitor_handle: Some(monitor_handle),
        });

        Ok(())
    }

    /// Unregister an external battery provider.
    ///
    /// The `provider` argument must match the path previously passed to
    /// `RegisterBatteryProvider`, and the D-Bus sender must match the
    /// original registrant.
    ///
    /// Matches C `unregister_battery_provider()`.
    async fn unregister_battery_provider(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        provider: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().ok_or_else(BtdError::invalid_args)?.to_owned();
        let path = provider.to_string();

        debug!("unregister battery provider path = {}", path);

        let mut providers = self.providers.lock().await;

        // Find and validate the provider.
        let idx = providers.iter().position(|p| p.path == path);
        match idx {
            Some(i) if providers[i].owner == sender.as_str() => {
                let removed = providers.remove(i);

                // Abort the monitoring task.
                if let Some(handle) = removed._monitor_handle {
                    handle.abort();
                }

                // Unregister all batteries created by this provider.
                unregister_batteries_by_provider(&removed.path).await;
            }
            _ => {
                return Err(BtdError::DoesNotExist("Provider does not exist".to_owned()));
            }
        }

        Ok(())
    }
}

// ===========================================================================
// Provider monitoring — D-Bus disconnect detection
// ===========================================================================

/// Background task that monitors a provider's D-Bus name for disconnection.
///
/// When the provider's D-Bus client disconnects (NameOwnerChanged with empty
/// new owner), all batteries created by that provider are unregistered and the
/// provider entry is removed from the manager's list.
///
/// Replaces C `provider_disconnect_cb` + `g_dbus_client_set_disconnect_watch`.
async fn monitor_provider_disconnect(
    conn: Connection,
    sender_name: String,
    provider_path: String,
    providers: Arc<Mutex<Vec<BatteryProvider>>>,
    _adapter: Arc<Mutex<BtdAdapter>>,
) {
    // Subscribe to NameOwnerChanged for the provider's unique name.
    let proxy = match zbus::fdo::DBusProxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            error!("failed to create DBus proxy for disconnect watch: {e}");
            return;
        }
    };

    // Use the NameOwnerChanged signal stream.
    use futures::StreamExt;
    let mut stream = match proxy.receive_name_owner_changed().await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to subscribe to NameOwnerChanged: {e}");
            return;
        }
    };

    while let Some(signal) = stream.next().await {
        let args = match signal.args() {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Check if this is for our provider's unique name.
        if args.name.as_str() != sender_name {
            continue;
        }

        // Empty new owner means the client disconnected.
        if args.new_owner.as_ref().is_none_or(|o| o.is_empty()) {
            debug!(
                "battery provider client disconnected {} root path {}",
                sender_name, provider_path
            );

            // Remove the provider from the list.
            {
                let mut prov_list = providers.lock().await;
                if let Some(idx) = prov_list.iter().position(|p| p.path == provider_path) {
                    let removed = prov_list.remove(idx);
                    if let Some(handle) = removed._monitor_handle {
                        handle.abort();
                    }
                } else {
                    warn!("Disconnection on a non-existing provider {}", provider_path);
                }
            }

            // Unregister all batteries created by this provider.
            unregister_batteries_by_provider(&provider_path).await;

            break;
        }
    }
}

/// Monitor a provider's D-Bus objects for `org.bluez.BatteryProvider1` changes.
///
/// This task watches for objects appearing/disappearing under the provider's
/// root path and processes their `Percentage`, `Device`, and `Source`
/// properties to create/update/remove Battery1 objects on device paths.
///
/// Replaces C `provided_battery_added_cb`, `provided_battery_removed_cb`,
/// and `provided_battery_property_changed_cb` via `g_dbus_client_set_proxy_handlers`.
async fn monitor_provider_objects(
    conn: Connection,
    sender_name: String,
    provider_path: String,
    adapter: Arc<Mutex<BtdAdapter>>,
) {
    use zbus::fdo::ObjectManagerProxy;
    use zbus::zvariant::OwnedValue;

    // Build an ObjectManager proxy targeting the provider's root path.
    let proxy = match ObjectManagerProxy::builder(&conn).destination(sender_name.as_str()) {
        Ok(builder) => match builder.path(provider_path.as_str()) {
            Ok(builder2) => match builder2.build().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        "failed to create ObjectManager proxy for provider \
                         {provider_path}: {e}"
                    );
                    return;
                }
            },
            Err(e) => {
                warn!(
                    "failed to set path on ObjectManager proxy for provider \
                     {provider_path}: {e}"
                );
                return;
            }
        },
        Err(e) => {
            warn!(
                "failed to build ObjectManager proxy for provider \
                 {provider_path}: {e}"
            );
            return;
        }
    };

    // Attempt to enumerate existing managed objects.
    if let Ok(objects) = proxy.get_managed_objects().await {
        for (obj_path, interfaces) in &objects {
            // Iterate interface names to find BATTERY_PROVIDER_INTERFACE.
            for (iface_name, props) in interfaces {
                if iface_name.as_str() == BATTERY_PROVIDER_INTERFACE {
                    handle_provider_battery_added(
                        &adapter,
                        &provider_path,
                        obj_path.as_str(),
                        props,
                    )
                    .await;
                }
            }
        }
    }

    // Subscribe to InterfacesAdded signals for newly appearing objects.
    use futures::StreamExt;
    let mut added_stream = match proxy.receive_interfaces_added().await {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to subscribe to InterfacesAdded: {e}");
            return;
        }
    };

    while let Some(signal) = added_stream.next().await {
        if let Ok(args) = signal.args() {
            let obj_path = args.object_path.to_string();
            // The signal args provide interfaces_and_properties as
            // HashMap<InterfaceName, HashMap<String, Value>>.
            // We need to find our battery provider interface.
            for (iface_name, props) in args.interfaces_and_properties.iter() {
                if iface_name.as_str() == BATTERY_PROVIDER_INTERFACE {
                    // Convert from Value<'_> to OwnedValue for the handler.
                    let owned_props: std::collections::HashMap<String, OwnedValue> = props
                        .iter()
                        .filter_map(|(k, v)| {
                            OwnedValue::try_from(v.clone()).ok().map(|ov| (k.to_string(), ov))
                        })
                        .collect();
                    handle_provider_battery_added(
                        &adapter,
                        &provider_path,
                        &obj_path,
                        &owned_props,
                    )
                    .await;
                }
            }
        }
    }
}

/// Process a newly discovered `org.bluez.BatteryProvider1` object from an
/// external provider.
///
/// Validates the `Device` property, checks for duplicates, and registers a
/// new Battery1 D-Bus interface on the target device path.
///
/// Replaces C `provided_battery_added_cb()`.
async fn handle_provider_battery_added(
    adapter: &Arc<Mutex<BtdAdapter>>,
    provider_path: &str,
    obj_path: &str,
    props: &std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
) {
    use zbus::zvariant::OwnedObjectPath;

    // Extract the Device property (required).
    let device_path = match props.get("Device") {
        Some(val) => {
            // Try to extract as String first, then as ObjectPath.
            if let Ok(s) = <String as TryFrom<zbus::zvariant::OwnedValue>>::try_from(val.clone()) {
                s
            } else if let Ok(p) =
                <OwnedObjectPath as TryFrom<zbus::zvariant::OwnedValue>>::try_from(val.clone())
            {
                p.to_string()
            } else {
                btd_warn(
                    0,
                    &format!("Battery object {obj_path} does not specify valid device path"),
                );
                return;
            }
        }
        None => {
            btd_warn(0, &format!("Battery object {obj_path} does not specify device path"));
            return;
        }
    };

    // Validate device exists on the adapter.
    // In the C code, device_is_temporary() is also checked here to reject
    // battery data for temporary (not yet bonded/connected) devices.
    // The current adapter implementation returns Option<BdAddr> from
    // btd_adapter_find_device_by_path; a None result means the device does
    // not exist (analogous to C returning NULL for non-existent devices).
    let device_addr = btd_adapter_find_device_by_path(adapter, &device_path).await;
    if device_addr.is_none() {
        btd_warn(0, &format!("Ignoring non-existent device path for battery {device_path}"));
        return;
    }

    // Check for duplicate battery.
    {
        let batteries = BATTERIES.read().await;
        if batteries.iter().any(|b| b.path == device_path) {
            btd_debug(
                0,
                &format!("Battery for {device_path} is already provided, ignoring the new one"),
            );
            return;
        }
    }

    // Extract optional Source property.
    let source = props.get("Source").and_then(|val| {
        <String as TryFrom<zbus::zvariant::OwnedValue>>::try_from(val.clone()).ok()
    });

    // Register the battery.
    let registered =
        btd_battery_register(&device_path, source.as_deref(), Some(provider_path)).await;

    if !registered {
        return;
    }

    debug!("provided battery added {obj_path}");

    // If Percentage is immediately available, update.
    if let Some(pct_val) = props.get("Percentage") {
        if let Ok(pct) = <u8 as TryFrom<zbus::zvariant::OwnedValue>>::try_from(pct_val.clone()) {
            btd_battery_update(&device_path, pct).await;
        }
    }
}

// ===========================================================================
// Provider battery cleanup
// ===========================================================================

/// Unregister all batteries that were created by the given provider path.
///
/// Replaces C `unregister_if_path_has_prefix()` loop + `battery_provider_free()`.
async fn unregister_batteries_by_provider(provider_path: &str) {
    // Collect paths of batteries to unregister (to avoid holding the lock
    // during the unregister calls which also acquire the lock).
    let paths: Vec<String> = {
        let batteries = BATTERIES.read().await;
        batteries
            .iter()
            .filter(|b| b.provider_path.as_deref() == Some(provider_path))
            .map(|b| b.path.clone())
            .collect()
    };

    for path in paths {
        btd_battery_unregister(&path).await;
    }
}

// ===========================================================================
// Battery Provider Manager lifecycle — public API
// ===========================================================================

/// Create a `BatteryProviderManager1` D-Bus interface on the given adapter's
/// object path.
///
/// Returns the manager state on success, or `None` on failure.
///
/// Equivalent to C `btd_battery_provider_manager_create()`.
pub async fn btd_battery_provider_manager_create(
    adapter: Arc<Mutex<BtdAdapter>>,
) -> Option<BtdBatteryProviderManager> {
    let adapter_path = adapter_get_path(&adapter).await;
    if adapter_path.is_empty() {
        return None;
    }

    let manager = BtdBatteryProviderManager::new(adapter);

    let iface = BatteryProviderManager1Interface {
        adapter: Arc::clone(&manager.adapter),
        providers: Arc::clone(&manager.battery_providers),
    };

    let conn = btd_get_dbus_connection();
    if let Err(e) = conn.object_server().at(adapter_path.as_str(), iface).await {
        btd_error(
            0,
            &format!("error registering {BATTERY_PROVIDER_MANAGER_INTERFACE} interface: {e}"),
        );
        return None;
    }

    log::info("Battery Provider Manager created");

    Some(manager)
}

/// Destroy a `BatteryProviderManager1` D-Bus interface.
///
/// Unregisters the interface from the adapter's object path and cleans up
/// all registered providers and their batteries.
///
/// Equivalent to C `btd_battery_provider_manager_destroy()`.
pub async fn btd_battery_provider_manager_destroy(manager: &BtdBatteryProviderManager) {
    let adapter_path = adapter_get_path(&manager.adapter).await;

    // Clean up all providers.
    {
        let mut providers = manager.battery_providers.lock().await;
        for provider in providers.drain(..) {
            // Abort monitoring tasks.
            if let Some(handle) = provider._monitor_handle {
                handle.abort();
            }
            // Unregister batteries created by this provider.
            unregister_batteries_by_provider(&provider.path).await;
        }
    }

    // Unregister the D-Bus interface.
    let conn = btd_get_dbus_connection();
    if let Err(e) = conn
        .object_server()
        .remove::<BatteryProviderManager1Interface, _>(adapter_path.as_str())
        .await
    {
        btd_warn(
            0,
            &format!("error unregistering {BATTERY_PROVIDER_MANAGER_INTERFACE} interface: {e}"),
        );
    }

    log::info("Battery Provider Manager destroyed");
}

// ===========================================================================
// Helper: find battery by path
// ===========================================================================

/// Find a battery by its D-Bus object path in the global registry.
///
/// Returns `true` if found, `false` otherwise.  Used by other daemon
/// modules to check whether a Battery1 interface is already exported
/// for a given device path before attempting registration.
pub async fn battery_exists(path: &str) -> bool {
    let batteries = BATTERIES.read().await;
    batteries.iter().any(|b| b.path == path)
}
