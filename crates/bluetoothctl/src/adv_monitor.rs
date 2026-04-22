//! Advertisement Monitor subsystem for bluetoothctl.
//!
//! Complete Rust rewrite of `client/adv_monitor.c` and `client/adv_monitor.h`.
//! Manages `org.bluez.AdvertisementMonitor1` D-Bus objects with pattern and
//! RSSI configuration for Bluetooth advertisement monitoring.
//!
//! The module exposes a shell submenu ("monitor") with commands for creating,
//! inspecting, and removing advertisement monitors, as well as configuring
//! RSSI threshold, timeout, and sampling parameters.  The monitors are
//! registered as D-Bus objects under `/org/bluez/adv_monitor_app/` and exposed
//! to the BlueZ daemon via the `org.freedesktop.DBus.ObjectManager` interface.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, bt_shell_add_submenu, bt_shell_noninteractive_quit,
    bt_shell_printf, bt_shell_remove_submenu,
};
use bluez_shared::util::ad::BT_AD_MAX_DATA_LEN;

use zbus::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Str, Value};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus root path for the advertisement monitor application.
const ADV_MONITOR_APP_PATH: &str = "/org/bluez/adv_monitor_app";

/// Sentinel value indicating an RSSI threshold has not been configured.
const RSSI_THRESHOLD_UNSET: i16 = 127;

/// Sentinel value indicating an RSSI timeout has not been configured.
const RSSI_TIMEOUT_UNSET: u16 = 0;

/// Sentinel value indicating an RSSI sampling period has not been configured.
const RSSI_SAMPLING_PERIOD_UNSET: u16 = 256;

// ---------------------------------------------------------------------------
// Data Types
// ---------------------------------------------------------------------------

/// A single pattern entry for an advertisement monitor.
///
/// Corresponds to the C `struct pattern` in `client/adv_monitor.c`.
#[derive(Debug, Clone)]
struct AdvMonitorPattern {
    /// Byte offset within the advertisement data where matching begins.
    start_pos: u8,
    /// AD type code to match against.
    ad_type: u8,
    /// Raw content bytes for the pattern (max `BT_AD_MAX_DATA_LEN`).
    content: Vec<u8>,
}

/// RSSI threshold, timeout, and sampling configuration.
///
/// Mirrors the C `struct rssi_setting` in `client/adv_monitor.c`.
#[derive(Debug, Clone)]
struct RssiSetting {
    low_threshold: i16,
    high_threshold: i16,
    low_timeout: u16,
    high_timeout: u16,
    sampling_period: u16,
}

impl Default for RssiSetting {
    fn default() -> Self {
        Self {
            low_threshold: RSSI_THRESHOLD_UNSET,
            high_threshold: RSSI_THRESHOLD_UNSET,
            low_timeout: RSSI_TIMEOUT_UNSET,
            high_timeout: RSSI_TIMEOUT_UNSET,
            sampling_period: RSSI_SAMPLING_PERIOD_UNSET,
        }
    }
}

/// A registered advertisement monitor with its full configuration.
///
/// Mirrors the C `struct adv_monitor` in `client/adv_monitor.c`.
#[derive(Debug, Clone)]
struct AdvMonitor {
    /// Numeric index used for the D-Bus object path and display.
    idx: u8,
    /// Full D-Bus object path, e.g. `/org/bluez/adv_monitor_app/0`.
    path: String,
    /// Monitor type string — currently always `"or_patterns"`.
    monitor_type: String,
    /// RSSI configuration snapshot taken at creation time.
    rssi: RssiSetting,
    /// List of match patterns.
    patterns: Vec<AdvMonitorPattern>,
}

/// State of the `AdvertisementMonitorManager1` proxy connection.
#[derive(Debug, Default)]
struct AdvMonitorManager {
    /// Supported monitor types reported by the BlueZ daemon.
    supported_types: Vec<String>,
    /// Supported features reported by the BlueZ daemon.
    supported_features: Vec<String>,
    /// Active D-Bus connection used for manager operations.
    connection: Option<Connection>,
    /// Whether the monitor application has been registered with the daemon.
    app_registered: bool,
}

/// Module-level mutable state for the advertisement monitor subsystem.
#[derive(Default)]
struct ModuleState {
    /// Manager proxy and daemon metadata.
    manager: AdvMonitorManager,
    /// All currently registered monitors (keyed by `idx`).
    monitors: Vec<AdvMonitor>,
    /// Next index counter — wraps at `u8::MAX`.
    monitor_idx: u8,
    /// RSSI settings applied to newly created monitors.
    current_rssi: RssiSetting,
}

/// Global module state, protected by a standard mutex.
///
/// A `std::sync::Mutex` is used (rather than `tokio::sync::Mutex`) because
/// shell command handlers are synchronous `fn(args: &[&str])` callbacks and
/// cannot `.await`.  All lock scopes are short-lived and never held across
/// await points.
static STATE: LazyLock<Mutex<ModuleState>> = LazyLock::new(|| Mutex::new(ModuleState::default()));

// ---------------------------------------------------------------------------
// D-Bus Interface: org.bluez.AdvertisementMonitor1
// ---------------------------------------------------------------------------

/// D-Bus object implementing the `org.bluez.AdvertisementMonitor1` interface.
///
/// One instance is created per registered monitor and placed on the
/// `ObjectServer` at the monitor's path.  The BlueZ daemon invokes the
/// methods below for lifecycle events.
struct AdvMonitorObject {
    monitor_type: String,
    rssi_low_threshold: i16,
    rssi_high_threshold: i16,
    rssi_low_timeout: u16,
    rssi_high_timeout: u16,
    rssi_sampling_period: u16,
    patterns: Vec<(u8, u8, Vec<u8>)>,
}

#[zbus::interface(name = "org.bluez.AdvertisementMonitor1")]
impl AdvMonitorObject {
    /// Called by BlueZ when the monitor is released.
    fn release(&self) {
        bt_shell_printf(format_args!("Advertisement monitor released\n"));
    }

    /// Called when the monitor is activated by BlueZ.
    fn activate(&self) {
        bt_shell_printf(format_args!("Advertisement monitor activated\n"));
    }

    /// Called when a matching device is discovered.
    fn device_found(&self, device: ObjectPath<'_>) {
        bt_shell_printf(format_args!("Advertisement monitor device found: {}\n", device));
    }

    /// Called when a previously matched device is lost.
    fn device_lost(&self, device: ObjectPath<'_>) {
        bt_shell_printf(format_args!("Advertisement monitor device lost: {}\n", device));
    }

    /// The monitor type — currently `"or_patterns"`.
    #[zbus(property, name = "Type")]
    fn monitor_type(&self) -> &str {
        &self.monitor_type
    }

    /// RSSI low threshold in dBm.
    #[zbus(property, name = "RSSILowThreshold")]
    fn rssi_low_threshold(&self) -> i16 {
        self.rssi_low_threshold
    }

    /// RSSI high threshold in dBm.
    #[zbus(property, name = "RSSIHighThreshold")]
    fn rssi_high_threshold(&self) -> i16 {
        self.rssi_high_threshold
    }

    /// RSSI low timeout in seconds.
    #[zbus(property, name = "RSSILowTimeout")]
    fn rssi_low_timeout(&self) -> u16 {
        self.rssi_low_timeout
    }

    /// RSSI high timeout in seconds.
    #[zbus(property, name = "RSSIHighTimeout")]
    fn rssi_high_timeout(&self) -> u16 {
        self.rssi_high_timeout
    }

    /// RSSI sampling period (0–255, or 256 for unset).
    #[zbus(property, name = "RSSISamplingPeriod")]
    fn rssi_sampling_period(&self) -> u16 {
        self.rssi_sampling_period
    }

    /// Array of `(start_pos, ad_type, content)` pattern tuples.
    #[zbus(property, name = "Patterns")]
    fn patterns(&self) -> Vec<(u8, u8, Vec<u8>)> {
        self.patterns.clone()
    }
}

// ---------------------------------------------------------------------------
// D-Bus Interface: org.freedesktop.DBus.ObjectManager
// ---------------------------------------------------------------------------

/// Application root object registered at [`ADV_MONITOR_APP_PATH`].
///
/// Implements `GetManagedObjects` so that the BlueZ daemon can discover all
/// registered monitor objects and their properties.  RSSI properties are
/// conditionally included — they only appear when explicitly configured
/// (not equal to their sentinel "unset" values).
struct AdvMonitorApp;

#[zbus::interface(name = "org.freedesktop.DBus.ObjectManager")]
impl AdvMonitorApp {
    /// Returns all managed advertisement monitor objects with their
    /// interface properties.
    ///
    /// D-Bus signature: `a{oa{sa{sv}}}`.
    fn get_managed_objects(
        &self,
    ) -> HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>> {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let mut result: HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>> =
            HashMap::new();

        for monitor in &state.monitors {
            let mut iface_props: HashMap<String, OwnedValue> = HashMap::new();

            // Type is always present.
            iface_props.insert(
                "Type".to_string(),
                OwnedValue::from(Str::from(monitor.monitor_type.as_str())),
            );

            // RSSI properties are conditionally included.
            if monitor.rssi.low_threshold != RSSI_THRESHOLD_UNSET {
                iface_props.insert(
                    "RSSILowThreshold".to_string(),
                    OwnedValue::from(monitor.rssi.low_threshold),
                );
            }
            if monitor.rssi.high_threshold != RSSI_THRESHOLD_UNSET {
                iface_props.insert(
                    "RSSIHighThreshold".to_string(),
                    OwnedValue::from(monitor.rssi.high_threshold),
                );
            }
            if monitor.rssi.low_timeout != RSSI_TIMEOUT_UNSET {
                iface_props.insert(
                    "RSSILowTimeout".to_string(),
                    OwnedValue::from(monitor.rssi.low_timeout),
                );
            }
            if monitor.rssi.high_timeout != RSSI_TIMEOUT_UNSET {
                iface_props.insert(
                    "RSSIHighTimeout".to_string(),
                    OwnedValue::from(monitor.rssi.high_timeout),
                );
            }
            if monitor.rssi.sampling_period != RSSI_SAMPLING_PERIOD_UNSET {
                iface_props.insert(
                    "RSSISamplingPeriod".to_string(),
                    OwnedValue::from(monitor.rssi.sampling_period),
                );
            }

            // Patterns are always present — serialized as a(yyay).
            let patterns_tuples: Vec<(u8, u8, Vec<u8>)> = monitor
                .patterns
                .iter()
                .map(|p| (p.start_pos, p.ad_type, p.content.clone()))
                .collect();
            if let Ok(val) = OwnedValue::try_from(Value::from(patterns_tuples)) {
                iface_props.insert("Patterns".to_string(), val);
            }

            let mut interfaces: HashMap<String, HashMap<String, OwnedValue>> = HashMap::new();
            interfaces.insert("org.bluez.AdvertisementMonitor1".to_string(), iface_props);

            if let Ok(obj_path) = OwnedObjectPath::try_from(monitor.path.clone()) {
                result.insert(obj_path, interfaces);
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Fire-and-forget an async task on the current tokio runtime.
///
/// This bridges synchronous shell command handlers to asynchronous D-Bus
/// operations.  The task is spawned on the runtime and results are printed
/// asynchronously — matching the C behaviour of `g_dbus_proxy_method_call`.
fn spawn_async<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(future);
    }
}

/// Find the next available monitor index not already in use.
///
/// Wraps around at `u8::MAX` and returns `None` if all 256 indices are taken.
fn next_monitor_idx(state: &ModuleState) -> Option<u8> {
    let start = state.monitor_idx;
    let mut idx = start;
    loop {
        if !state.monitors.iter().any(|m| m.idx == idx) {
            return Some(idx);
        }
        idx = idx.wrapping_add(1);
        if idx == start {
            // All 256 indices are occupied.
            return None;
        }
    }
}

/// Decode a hexadecimal string into raw bytes.
///
/// Returns `None` if the string has an odd length or contains non-hex
/// characters.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return None,
        }
    }
    Some(bytes)
}

/// Parse a single pattern argument of the form `start_pos:ad_type:hex`.
///
/// Returns `None` on any parse error or if the content exceeds
/// `BT_AD_MAX_DATA_LEN`.
fn parse_pattern(arg: &str) -> Option<AdvMonitorPattern> {
    let parts: Vec<&str> = arg.split(':').collect();
    if parts.len() != 3 {
        return None;
    }

    let start_pos: u8 = parts[0].parse().ok()?;
    let ad_type: u8 = parts[1].parse().ok()?;
    let content = hex_to_bytes(parts[2])?;

    if content.is_empty() || content.len() > BT_AD_MAX_DATA_LEN as usize {
        return None;
    }

    Some(AdvMonitorPattern { start_pos, ad_type, content })
}

/// Print detailed information about a single monitor to the shell.
fn print_monitor_info(monitor: &AdvMonitor) {
    bt_shell_printf(format_args!("Monitor: {}\n", monitor.path));
    bt_shell_printf(format_args!("\ttype: {}\n", monitor.monitor_type));

    if monitor.rssi.low_threshold != RSSI_THRESHOLD_UNSET {
        bt_shell_printf(format_args!("\trssi_low_threshold: {}\n", monitor.rssi.low_threshold));
    }
    if monitor.rssi.high_threshold != RSSI_THRESHOLD_UNSET {
        bt_shell_printf(format_args!("\trssi_high_threshold: {}\n", monitor.rssi.high_threshold));
    }
    if monitor.rssi.low_timeout != RSSI_TIMEOUT_UNSET {
        bt_shell_printf(format_args!("\trssi_low_timeout: {}\n", monitor.rssi.low_timeout));
    }
    if monitor.rssi.high_timeout != RSSI_TIMEOUT_UNSET {
        bt_shell_printf(format_args!("\trssi_high_timeout: {}\n", monitor.rssi.high_timeout));
    }
    if monitor.rssi.sampling_period != RSSI_SAMPLING_PERIOD_UNSET {
        bt_shell_printf(format_args!("\trssi_sampling_period: {}\n", monitor.rssi.sampling_period));
    }

    for (i, pattern) in monitor.patterns.iter().enumerate() {
        let hex: String = pattern.content.iter().map(|b| format!("{b:02x}")).collect();
        bt_shell_printf(format_args!(
            "\tpattern {}: start_pos: {}, ad_type: {}, content: {}\n",
            i + 1,
            pattern.start_pos,
            pattern.ad_type,
            hex,
        ));
    }
}

// ---------------------------------------------------------------------------
// Shell Command Handlers
// ---------------------------------------------------------------------------

/// Shell command: `set-rssi-threshold <low> <high>`.
fn cmd_set_rssi_threshold(args: &[&str]) {
    adv_monitor_set_rssi_threshold(args);
}

/// Shell command: `set-rssi-timeout <low> <high>`.
fn cmd_set_rssi_timeout(args: &[&str]) {
    adv_monitor_set_rssi_timeout(args);
}

/// Shell command: `set-rssi-sampling-period <period>`.
fn cmd_set_rssi_sampling_period(args: &[&str]) {
    adv_monitor_set_rssi_sampling_period(args);
}

/// Shell command: `add-or-monitor-pattern <start:type:hex> ...`.
fn cmd_add_or_monitor_pattern(args: &[&str]) {
    let conn = {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.manager.connection.clone()
    };
    match conn {
        Some(ref c) => adv_monitor_add_monitor(c, args),
        None => {
            bt_shell_printf(format_args!("No D-Bus connection available\n"));
            bt_shell_noninteractive_quit(1);
        }
    }
}

/// Shell command: `get-pattern <monitor_idx>`.
fn cmd_get_pattern(args: &[&str]) {
    let conn = {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.manager.connection.clone()
    };
    match conn {
        Some(ref c) => adv_monitor_print_monitor(c, args),
        None => {
            bt_shell_printf(format_args!("No D-Bus connection available\n"));
            bt_shell_noninteractive_quit(1);
        }
    }
}

/// Shell command: `remove-pattern <monitor_idx>`.
fn cmd_remove_pattern(args: &[&str]) {
    let conn = {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.manager.connection.clone()
    };
    match conn {
        Some(ref c) => adv_monitor_remove_monitor(c, args),
        None => {
            bt_shell_printf(format_args!("No D-Bus connection available\n"));
            bt_shell_noninteractive_quit(1);
        }
    }
}

/// Shell command: `get-supported-info`.
fn cmd_get_supported_info(args: &[&str]) {
    let conn = {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.manager.connection.clone()
    };
    match conn {
        Some(ref c) => adv_monitor_get_supported_info(c, args),
        None => {
            bt_shell_printf(format_args!("No D-Bus connection available\n"));
            bt_shell_noninteractive_quit(1);
        }
    }
}

/// Shell command: `print-monitor [monitor_idx]`.
fn cmd_print_monitor(args: &[&str]) {
    let conn = {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.manager.connection.clone()
    };
    match conn {
        Some(ref c) => adv_monitor_print_monitor(c, args),
        None => {
            bt_shell_printf(format_args!("No D-Bus connection available\n"));
            bt_shell_noninteractive_quit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Shell Menu Definition
// ---------------------------------------------------------------------------

/// Menu entry table for the advertisement monitor submenu.
static ADV_MONITOR_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "set-rssi-threshold",
        arg: Some("<low_threshold> <high_threshold>"),
        func: cmd_set_rssi_threshold,
        desc: "Set RSSI threshold parameter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "set-rssi-timeout",
        arg: Some("<low_timeout> <high_timeout>"),
        func: cmd_set_rssi_timeout,
        desc: "Set RSSI timeout parameter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "set-rssi-sampling-period",
        arg: Some("<sampling_period>"),
        func: cmd_set_rssi_sampling_period,
        desc: "Set RSSI sampling period parameter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-or-monitor-pattern",
        arg: Some("[patterns=<start_pos:ad_type:content>...]"),
        func: cmd_add_or_monitor_pattern,
        desc: "Register advertisement monitor with OR patterns",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "get-pattern",
        arg: Some("<monitor_idx>"),
        func: cmd_get_pattern,
        desc: "Get advertisement monitor pattern",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "remove-pattern",
        arg: Some("<monitor_idx>"),
        func: cmd_remove_pattern,
        desc: "Remove advertisement monitor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "get-supported-info",
        arg: None,
        func: cmd_get_supported_info,
        desc: "Get advertisement monitor supported features and types",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "print-monitor",
        arg: Some("[monitor_idx]"),
        func: cmd_print_monitor,
        desc: "Print advertisement monitor",
        r#gen: None,
        disp: None,
        exists: None,
    },
];

/// The advertisement monitor submenu definition.
static ADV_MONITOR_MENU: BtShellMenu = BtShellMenu {
    name: "monitor",
    desc: Some("Advertisement Monitor Submenu"),
    pre_run: None,
    entries: ADV_MONITOR_MENU_ENTRIES,
};

// ---------------------------------------------------------------------------
// Public API — Exported Functions
// ---------------------------------------------------------------------------

/// Register the advertisement monitor shell submenu.
///
/// Called once during `bluetoothctl` initialization to make the `monitor`
/// submenu available.
pub fn adv_monitor_add_submenu() {
    bt_shell_add_submenu(&ADV_MONITOR_MENU);
}

/// Remove the advertisement monitor shell submenu and clean up all state.
///
/// Unregisters all monitors from D-Bus and clears internal bookkeeping.
pub fn adv_monitor_remove_submenu() {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(conn) = &state.manager.connection {
        let conn = conn.clone();
        // Remove all monitor objects from the ObjectServer.
        for monitor in &state.monitors {
            let path = monitor.path.clone();
            let c = conn.clone();
            spawn_async(async move {
                let _ = c.object_server().remove::<AdvMonitorObject, _>(path.as_str()).await;
            });
        }
        // Remove the ObjectManager root object.
        spawn_async(async move {
            let _ = conn.object_server().remove::<AdvMonitorApp, _>(ADV_MONITOR_APP_PATH).await;
        });
    }
    state.monitors.clear();
    state.monitor_idx = 0;
    drop(state);

    bt_shell_remove_submenu(&ADV_MONITOR_MENU);
}

/// Store the D-Bus connection used for manager operations.
///
/// Called when the `AdvertisementMonitorManager1` interface becomes available
/// on the BlueZ daemon.
pub fn adv_monitor_add_manager(connection: Connection) {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.manager.connection = Some(connection);
}

/// Clear all manager state.
///
/// Called when the `AdvertisementMonitorManager1` interface disappears from
/// the BlueZ daemon.
pub fn adv_monitor_remove_manager() {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.manager.connection = None;
    state.manager.supported_types.clear();
    state.manager.supported_features.clear();
    state.manager.app_registered = false;
}

/// Register the monitor application with the BlueZ daemon.
///
/// Registers the `ObjectManager` at [`ADV_MONITOR_APP_PATH`] and calls
/// `RegisterMonitor` on the daemon's `AdvertisementMonitorManager1`.
/// The result is printed asynchronously.
pub fn adv_monitor_register_app(connection: &Connection) {
    {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        if state.manager.connection.is_none() || state.manager.app_registered {
            bt_shell_printf(format_args!("adv_monitor_register_app failed\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    }

    let conn = connection.clone();
    spawn_async(async move {
        // Register the ObjectManager interface at the application root path.
        if let Err(e) = conn.object_server().at(ADV_MONITOR_APP_PATH, AdvMonitorApp).await {
            bt_shell_printf(format_args!("Failed to register ObjectManager: {}\n", e));
            bt_shell_noninteractive_quit(1);
            return;
        }

        // Build the object path for the RegisterMonitor call.
        let app_path = match ObjectPath::try_from(ADV_MONITOR_APP_PATH) {
            Ok(p) => p,
            Err(e) => {
                bt_shell_printf(format_args!("Invalid app path: {}\n", e));
                bt_shell_noninteractive_quit(1);
                return;
            }
        };

        // Call RegisterMonitor on the daemon.
        let result = conn
            .call_method(
                Some("org.bluez"),
                "/org/bluez",
                Some("org.bluez.AdvertisementMonitorManager1"),
                "RegisterMonitor",
                &(app_path,),
            )
            .await;

        match result {
            Ok(_) => {
                bt_shell_printf(format_args!("Advertisement monitor registered\n"));
                let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
                state.manager.app_registered = true;
                bt_shell_noninteractive_quit(0);
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to register app: {}\n", e));
                bt_shell_noninteractive_quit(1);
            }
        }
    });
}

/// Unregister the monitor application from the BlueZ daemon.
///
/// Calls `UnregisterMonitor` and removes the `ObjectManager` root.
pub fn adv_monitor_unregister_app(connection: &Connection) {
    {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        if state.manager.connection.is_none() || !state.manager.app_registered {
            bt_shell_printf(format_args!("adv_monitor_unregister_app failed\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    }

    let conn = connection.clone();
    spawn_async(async move {
        let app_path = match ObjectPath::try_from(ADV_MONITOR_APP_PATH) {
            Ok(p) => p,
            Err(e) => {
                bt_shell_printf(format_args!("Invalid app path: {}\n", e));
                bt_shell_noninteractive_quit(1);
                return;
            }
        };

        let result = conn
            .call_method(
                Some("org.bluez"),
                "/org/bluez",
                Some("org.bluez.AdvertisementMonitorManager1"),
                "UnregisterMonitor",
                &(app_path,),
            )
            .await;

        match result {
            Ok(_) => {
                bt_shell_printf(format_args!("Advertisement monitor unregistered\n"));
                let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
                state.manager.app_registered = false;
                bt_shell_noninteractive_quit(0);
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to unregister app: {}\n", e));
                bt_shell_noninteractive_quit(1);
            }
        }

        // Remove the ObjectManager root object.
        let _ = conn.object_server().remove::<AdvMonitorApp, _>(ADV_MONITOR_APP_PATH).await;
    });
}

/// Set RSSI low and high thresholds for newly created monitors.
///
/// Usage: `set-rssi-threshold <low_threshold> <high_threshold>`
pub fn adv_monitor_set_rssi_threshold(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_printf(format_args!(
            "Usage: set-rssi-threshold <low_threshold> <high_threshold>\n"
        ));
        bt_shell_noninteractive_quit(1);
        return;
    }

    let low: i16 = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid low_threshold value\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let high: i16 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid high_threshold value\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.current_rssi.low_threshold = low;
    state.current_rssi.high_threshold = high;
    bt_shell_noninteractive_quit(0);
}

/// Set RSSI low and high timeouts for newly created monitors.
///
/// Usage: `set-rssi-timeout <low_timeout> <high_timeout>`
pub fn adv_monitor_set_rssi_timeout(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_printf(format_args!("Usage: set-rssi-timeout <low_timeout> <high_timeout>\n"));
        bt_shell_noninteractive_quit(1);
        return;
    }

    let low: u16 = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid low_timeout value\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let high: u16 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid high_timeout value\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.current_rssi.low_timeout = low;
    state.current_rssi.high_timeout = high;
    bt_shell_noninteractive_quit(0);
}

/// Set the RSSI sampling period for newly created monitors.
///
/// Usage: `set-rssi-sampling-period <sampling_period>`
pub fn adv_monitor_set_rssi_sampling_period(args: &[&str]) {
    if args.is_empty() {
        bt_shell_printf(format_args!("Usage: set-rssi-sampling-period <sampling_period>\n"));
        bt_shell_noninteractive_quit(1);
        return;
    }

    let period: u16 = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid sampling_period value\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.current_rssi.sampling_period = period;
    bt_shell_noninteractive_quit(0);
}

/// Create and register a new advertisement monitor with OR patterns.
///
/// Patterns are provided as positional arguments in the format
/// `start_pos:ad_type:hex_content`.  The monitor inherits the current RSSI
/// settings and is registered on D-Bus at a unique path under the
/// application root.
pub fn adv_monitor_add_monitor(connection: &Connection, args: &[&str]) {
    if args.is_empty() {
        bt_shell_printf(format_args!(
            "Usage: add-or-monitor-pattern \
             [patterns=<start_pos:ad_type:content>...]\n"
        ));
        bt_shell_noninteractive_quit(1);
        return;
    }

    // Parse all pattern arguments.
    let mut patterns = Vec::new();
    for arg in args {
        match parse_pattern(arg) {
            Some(p) => patterns.push(p),
            None => {
                bt_shell_printf(format_args!("Invalid pattern: {}\n", arg));
                bt_shell_noninteractive_quit(1);
                return;
            }
        }
    }

    if patterns.is_empty() {
        bt_shell_printf(format_args!("No valid patterns provided\n"));
        bt_shell_noninteractive_quit(1);
        return;
    }

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());

    // Allocate the next available index.
    let idx = match next_monitor_idx(&state) {
        Some(i) => i,
        None => {
            bt_shell_printf(format_args!("Maximum number of monitors reached\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let path = format!("{ADV_MONITOR_APP_PATH}/{idx}");

    let monitor = AdvMonitor {
        idx,
        path: path.clone(),
        monitor_type: "or_patterns".to_string(),
        rssi: state.current_rssi.clone(),
        patterns: patterns.clone(),
    };

    // Build the D-Bus object with a snapshot of the current state.
    let dbus_patterns: Vec<(u8, u8, Vec<u8>)> =
        patterns.iter().map(|p| (p.start_pos, p.ad_type, p.content.clone())).collect();

    let obj = AdvMonitorObject {
        monitor_type: "or_patterns".to_string(),
        rssi_low_threshold: monitor.rssi.low_threshold,
        rssi_high_threshold: monitor.rssi.high_threshold,
        rssi_low_timeout: monitor.rssi.low_timeout,
        rssi_high_timeout: monitor.rssi.high_timeout,
        rssi_sampling_period: monitor.rssi.sampling_period,
        patterns: dbus_patterns,
    };

    state.monitors.push(monitor);
    state.monitor_idx = idx.wrapping_add(1);
    drop(state);

    // Register the monitor interface on D-Bus asynchronously.
    let conn = connection.clone();
    let path_for_dbus = path.clone();
    spawn_async(async move {
        if let Err(e) = conn.object_server().at(path_for_dbus.as_str(), obj).await {
            bt_shell_printf(format_args!("Failed to register monitor on D-Bus: {}\n", e));
        }
    });

    bt_shell_printf(format_args!("Advertisement Monitor {} added\n", idx));
    bt_shell_noninteractive_quit(0);
}

/// Print information about one or all registered monitors.
///
/// If called with no arguments, prints all monitors.  If called with a
/// monitor index, prints only that monitor's details.
pub fn adv_monitor_print_monitor(_connection: &Connection, args: &[&str]) {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());

    if args.is_empty() {
        // Print all monitors.
        if state.monitors.is_empty() {
            bt_shell_printf(format_args!("No advertisement monitors registered\n"));
        } else {
            for monitor in &state.monitors {
                print_monitor_info(monitor);
            }
        }
    } else {
        // Print a specific monitor by index.
        let idx: u8 = match args[0].parse() {
            Ok(v) => v,
            Err(_) => {
                bt_shell_printf(format_args!("Invalid monitor index\n"));
                bt_shell_noninteractive_quit(1);
                return;
            }
        };

        match state.monitors.iter().find(|m| m.idx == idx) {
            Some(monitor) => print_monitor_info(monitor),
            None => {
                bt_shell_printf(format_args!("Monitor {} not found\n", idx));
            }
        }
    }

    bt_shell_noninteractive_quit(0);
}

/// Remove a registered advertisement monitor by index.
///
/// Removes the monitor from internal state and unregisters its D-Bus
/// interface from the `ObjectServer`.
pub fn adv_monitor_remove_monitor(connection: &Connection, args: &[&str]) {
    if args.is_empty() {
        bt_shell_printf(format_args!("Usage: remove-pattern <monitor_idx>\n"));
        bt_shell_noninteractive_quit(1);
        return;
    }

    let idx: u8 = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid monitor index\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let pos = state.monitors.iter().position(|m| m.idx == idx);

    match pos {
        Some(p) => {
            let monitor = state.monitors.remove(p);
            drop(state);

            let conn = connection.clone();
            let path = monitor.path.clone();
            spawn_async(async move {
                let _ = conn.object_server().remove::<AdvMonitorObject, _>(path.as_str()).await;
            });

            bt_shell_printf(format_args!("Advertisement Monitor {} removed\n", idx));
            bt_shell_noninteractive_quit(0);
        }
        None => {
            bt_shell_printf(format_args!("Monitor {} not found\n", idx));
            bt_shell_noninteractive_quit(1);
        }
    }
}

/// Display supported monitor types and features from the daemon.
///
/// Reads the `SupportedMonitorTypes` and `SupportedFeatures` properties
/// from the daemon's `AdvertisementMonitorManager1` interface.  Results are
/// printed asynchronously.
pub fn adv_monitor_get_supported_info(connection: &Connection, _args: &[&str]) {
    let conn = connection.clone();
    spawn_async(async move {
        // Build a proxy for the manager interface.
        let proxy = match zbus::Proxy::new(
            &conn,
            "org.bluez",
            "/org/bluez",
            "org.bluez.AdvertisementMonitorManager1",
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                bt_shell_printf(format_args!("Failed to create manager proxy: {}\n", e));
                bt_shell_noninteractive_quit(1);
                return;
            }
        };

        // Read SupportedMonitorTypes.
        match proxy.get_property::<Vec<String>>("SupportedMonitorTypes").await {
            Ok(types) => {
                bt_shell_printf(format_args!("Supported Monitor Types:\n"));
                for t in &types {
                    bt_shell_printf(format_args!("\t{}\n", t));
                }
                let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
                state.manager.supported_types = types;
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to read SupportedMonitorTypes: {}\n", e));
            }
        }

        // Read SupportedFeatures.
        match proxy.get_property::<Vec<String>>("SupportedFeatures").await {
            Ok(features) => {
                bt_shell_printf(format_args!("Supported Features:\n"));
                for f in &features {
                    bt_shell_printf(format_args!("\t{}\n", f));
                }
                let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
                state.manager.supported_features = features;
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to read SupportedFeatures: {}\n", e));
            }
        }

        bt_shell_noninteractive_quit(0);
    });
}
