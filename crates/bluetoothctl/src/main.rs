// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! `bluetoothctl` — Interactive Bluetooth management CLI.
//!
//! Complete Rust rewrite of `client/main.c` (3978 lines of C).
//!
//! This binary connects to the `org.bluez` D-Bus daemon and provides an
//! interactive shell for Bluetooth management, including adapter control,
//! device pairing/connection, GATT operations, advertising, and more.
//!
//! **Runtime:** `tokio::runtime::Builder::new_current_thread()` (per AAP §0.7.1)

// ---------------------------------------------------------------------------
// Module declarations — all 12 sibling modules
// ---------------------------------------------------------------------------
pub mod admin;
pub mod adv_monitor;
pub mod advertising;
pub mod agent;
pub mod assistant;
pub mod display;
pub mod gatt;
pub mod hci;
pub mod mgmt;
pub mod player;
pub mod print;
pub mod telephony;

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------
use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::{LazyLock, Mutex};

use tracing::{debug, error};
use zbus::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

// ---------------------------------------------------------------------------
// Internal imports — bluez-shared
// ---------------------------------------------------------------------------
use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, BtShellOpt, ShellOption, bt_shell_add_submenu, bt_shell_cleanup,
    bt_shell_get_timeout, bt_shell_handle_non_interactive_help, bt_shell_init,
    bt_shell_noninteractive_quit, bt_shell_printf, bt_shell_remove_submenu, bt_shell_run,
    bt_shell_set_env, bt_shell_set_menu, bt_shell_set_prompt,
};
use bluez_shared::util::ad::{BT_AD_FLAG_GENERAL, BT_AD_FLAG_LIMITED};
use bluez_shared::util::uuid::bt_uuidstr_to_str;

// ---------------------------------------------------------------------------
// Internal imports — sibling modules
// ---------------------------------------------------------------------------

use crate::advertising::{
    AD_TYPE_AD, AD_TYPE_SRD, ad_advertise_appearance, ad_advertise_data, ad_advertise_discoverable,
    ad_advertise_discoverable_timeout, ad_advertise_duration, ad_advertise_interval,
    ad_advertise_local_appearance, ad_advertise_local_name, ad_advertise_manufacturer,
    ad_advertise_name, ad_advertise_rsi, ad_advertise_secondary, ad_advertise_service,
    ad_advertise_solicit, ad_advertise_timeout, ad_advertise_tx_power, ad_advertise_uuids,
    ad_disable_data, ad_disable_manufacturer, ad_disable_service, ad_disable_solicit,
    ad_disable_uuids, ad_register, ad_unregister,
};
use crate::agent::{agent_default, agent_register, agent_unregister};
use crate::display::{
    COLOR_BLUE, COLOR_BOLDGRAY, COLOR_BOLDWHITE, COLOR_GREEN, COLOR_OFF, COLOR_RED, COLOR_YELLOW,
};
use crate::gatt::{
    ProxyInfo, gatt_acquire_notify, gatt_acquire_write, gatt_add_characteristic,
    gatt_add_descriptor, gatt_add_manager, gatt_add_service, gatt_attribute_generator,
    gatt_clone_attribute, gatt_list_attributes, gatt_notify_attribute, gatt_read_attribute,
    gatt_read_local_attribute, gatt_register_app, gatt_register_chrc, gatt_register_desc,
    gatt_register_include, gatt_register_service, gatt_release_notify, gatt_release_write,
    gatt_remove_characteristic, gatt_remove_descriptor, gatt_remove_manager, gatt_remove_service,
    gatt_select_attribute, gatt_select_local_attribute, gatt_unregister_app, gatt_unregister_chrc,
    gatt_unregister_desc, gatt_unregister_include, gatt_unregister_service, gatt_write_attribute,
    gatt_write_local_attribute,
};
use crate::print::{print_iter, print_property, print_uuid};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prompt displayed when an adapter is available.
const PROMPT_ON: &str = "[bluetooth]";
/// Prompt displayed when no adapter is available.
const PROMPT_OFF: &str = "Bluetooth is not available";

/// Sentinel value meaning "no RSSI/pathloss filter".
const DISTANCE_VAL_INVALID: i16 = 0x7FFF;

/// Exit codes matching C EXIT_SUCCESS / EXIT_FAILURE.
const EXIT_SUCCESS: i32 = 0;
const EXIT_FAILURE: i32 = 1;

// D-Bus service and interface names.
const BLUEZ_SERVICE: &str = "org.bluez";
const BLUEZ_ROOT_PATH: &str = "/";
const ADAPTER_IFACE: &str = "org.bluez.Adapter1";
const DEVICE_IFACE: &str = "org.bluez.Device1";
const AGENT_MANAGER_IFACE: &str = "org.bluez.AgentManager1";
const GATT_SERVICE_IFACE: &str = "org.bluez.GattService1";
const GATT_CHAR_IFACE: &str = "org.bluez.GattCharacteristic1";
const GATT_DESC_IFACE: &str = "org.bluez.GattDescriptor1";
const GATT_MANAGER_IFACE: &str = "org.bluez.GattManager1";
const LE_ADV_MANAGER_IFACE: &str = "org.bluez.LEAdvertisingManager1";
const BATTERY_IFACE: &str = "org.bluez.Battery1";
const ADV_MONITOR_MANAGER_IFACE: &str = "org.bluez.AdvertisementMonitorManager1";
const DEVICE_SET_IFACE: &str = "org.bluez.DeviceSet1";
const BEARER_BREDR_IFACE: &str = "org.bluez.Bearer.BREDR1";
const BEARER_LE_IFACE: &str = "org.bluez.Bearer.LE1";

// ---------------------------------------------------------------------------
// Argument tables — must be byte-identical to C source
// ---------------------------------------------------------------------------

static AGENT_ARGUMENTS: &[&str] = &[
    "",
    "on",
    "off",
    "auto",
    "DisplayOnly",
    "DisplayYesNo",
    "KeyboardDisplay",
    "KeyboardOnly",
    "NoInputNoOutput",
];

static AD_ARGUMENTS: &[&str] = &["on", "off", "peripheral", "broadcast"];

static DEVICE_ARGUMENTS: &[&str] = &["Paired", "Bonded", "Trusted", "Connected"];

static SCAN_ARGUMENTS: &[&str] = &["on", "off", "bredr", "le"];

// ---------------------------------------------------------------------------
// CachedProxy — lightweight D-Bus object with local property cache
// ---------------------------------------------------------------------------

/// Cached representation of a D-Bus proxy.
///
/// Replaces `GDBusProxy *` from the C codebase. Stores the object path,
/// interface name, and a local property cache updated via `PropertiesChanged`
/// signals. Property reads are synchronous (from cache).
#[derive(Clone, Debug)]
struct CachedProxy {
    path: String,
    interface: String,
    properties: HashMap<String, OwnedValue>,
}

impl CachedProxy {
    /// Create a new cached proxy with the given path and interface.
    fn new(path: &str, interface: &str) -> Self {
        Self {
            path: path.to_string(),
            interface: interface.to_string(),
            properties: HashMap::new(),
        }
    }

    /// Create a cached proxy with initial properties.
    fn with_properties(
        path: &str,
        interface: &str,
        properties: HashMap<String, OwnedValue>,
    ) -> Self {
        Self { path: path.to_string(), interface: interface.to_string(), properties }
    }

    /// Get a string property from cache.
    fn get_str(&self, name: &str) -> Option<String> {
        self.properties.get(name).and_then(|v| {
            let val: &Value<'_> = v.downcast_ref().ok()?;
            match val {
                Value::Str(s) => Some(s.to_string()),
                _ => None,
            }
        })
    }

    /// Get a bool property from cache.
    fn get_bool(&self, name: &str) -> Option<bool> {
        self.properties.get(name).and_then(|v| {
            let val: &Value<'_> = v.downcast_ref().ok()?;
            match val {
                Value::Bool(b) => Some(*b),
                _ => None,
            }
        })
    }

    /// Get a u16 property from cache.
    /// Get a u32 property from cache.
    fn get_u32(&self, name: &str) -> Option<u32> {
        self.properties.get(name).and_then(|v| {
            let val: &Value<'_> = v.downcast_ref().ok()?;
            match val {
                Value::U32(n) => Some(*n),
                _ => None,
            }
        })
    }

    /// Get a raw `OwnedValue` property from cache.
    fn get_property(&self, name: &str) -> Option<&OwnedValue> {
        self.properties.get(name)
    }

    /// Update a property in the cache.
    fn set_property(&mut self, name: &str, value: OwnedValue) {
        self.properties.insert(name.to_string(), value);
    }

    /// Print a property from cache using `print_iter`.
    fn print_property_cached(&self, name: &str) {
        if let Some(value) = self.properties.get(name) {
            print_iter("\t", name, value);
        }
    }
}

impl PartialEq for CachedProxy {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.interface == other.interface
    }
}

// ---------------------------------------------------------------------------
// Adapter — controller representation
// ---------------------------------------------------------------------------

/// Represents a local Bluetooth controller (adapter).
///
/// Replaces C `struct adapter` from `client/main.c` lines 85-93.
struct Adapter {
    proxy: CachedProxy,
    ad_proxy: Option<CachedProxy>,
    adv_monitor_proxy: Option<CachedProxy>,
    devices: Vec<CachedProxy>,
    sets: Vec<CachedProxy>,
    bearers: Vec<CachedProxy>,
}

// ---------------------------------------------------------------------------
// DiscoveryFilterArgs — scan filter configuration
// ---------------------------------------------------------------------------

/// Discovery filter arguments for `SetDiscoveryFilter`.
struct DiscoveryFilterArgs {
    transport: Option<String>,
    pattern: Option<String>,
    rssi: i16,
    pathloss: i16,
    uuids: Vec<String>,
    duplicate: bool,
    discoverable: bool,
    auto_connect: bool,
    set: bool,
    active: bool,
}

impl Default for DiscoveryFilterArgs {
    fn default() -> Self {
        Self {
            transport: None,
            pattern: None,
            rssi: DISTANCE_VAL_INVALID,
            pathloss: DISTANCE_VAL_INVALID,
            uuids: Vec::new(),
            duplicate: false,
            discoverable: false,
            auto_connect: false,
            set: true,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ClearEntry — name → clear-function mapping
// ---------------------------------------------------------------------------

struct ClearEntry {
    name: &'static str,
    clear: fn(),
}

// ---------------------------------------------------------------------------
// AppState — central application state
// ---------------------------------------------------------------------------

struct AppState {
    default_ctrl: Option<usize>,
    default_dev: Option<CachedProxy>,
    default_attr: Option<ProxyInfo>,
    default_local_attr: Option<String>,
    ctrl_list: Vec<Adapter>,
    battery_proxies: Vec<CachedProxy>,
    agent_manager: Option<CachedProxy>,
    dbus_conn: Option<Connection>,
    auto_register_agent: Option<String>,
    filter: DiscoveryFilterArgs,
}

impl AppState {
    fn new() -> Self {
        Self {
            default_ctrl: None,
            default_dev: None,
            default_attr: None,
            default_local_attr: None,
            ctrl_list: Vec::new(),
            battery_proxies: Vec::new(),
            agent_manager: None,
            dbus_conn: None,
            auto_register_agent: None,
            filter: DiscoveryFilterArgs::default(),
        }
    }

    fn get_default_ctrl(&self) -> Option<&Adapter> {
        self.default_ctrl.and_then(|idx| self.ctrl_list.get(idx))
    }

    fn get_default_ctrl_mut(&mut self) -> Option<&mut Adapter> {
        self.default_ctrl.and_then(|idx| self.ctrl_list.get_mut(idx))
    }

    fn find_ctrl_index(&self, path: &str) -> Option<usize> {
        self.ctrl_list.iter().position(|a| a.proxy.path.eq_ignore_ascii_case(path))
    }

    fn find_ctrl_index_by_address(&self, address: &str) -> Option<usize> {
        self.ctrl_list.iter().position(|a| {
            a.proxy.get_str("Address").is_some_and(|addr| addr.eq_ignore_ascii_case(address))
        })
    }

    fn conn(&self) -> Connection {
        self.dbus_conn.clone().expect("D-Bus connection not initialized")
    }
}

static STATE: LazyLock<Mutex<AppState>> = LazyLock::new(|| Mutex::new(AppState::new()));

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&AppState) -> R,
{
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    f(&state)
}

fn with_state_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut AppState) -> R,
{
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut state)
}

fn spawn_async<F>(f: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(f);
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Return a colorized description prefix for `[NEW]`, `[DEL]`, or other tags.
fn colored_description(desc: Option<&str>) -> String {
    match desc {
        Some("[NEW]") => format!("{COLOR_GREEN}[NEW]{COLOR_OFF} "),
        Some("[DEL]") => format!("{COLOR_RED}[DEL]{COLOR_OFF} "),
        Some("[CHG]") => format!("{COLOR_YELLOW}[CHG]{COLOR_OFF} "),
        Some(other) => format!("{other} "),
        None => String::new(),
    }
}

fn print_adapter(proxy: &CachedProxy, description: Option<&str>) {
    let address = proxy_address(proxy);
    let alias = proxy.get_str("Alias").unwrap_or_default();
    let is_default = with_state(|state| {
        state.get_default_ctrl().is_some_and(|ctrl| ctrl.proxy.path == proxy.path)
    });
    let default_marker = if is_default { " [default]" } else { "" };
    let color = if is_default { COLOR_BOLDWHITE } else { "" };
    let off = if is_default { COLOR_OFF } else { "" };
    let prefix = colored_description(description);
    bt_shell_printf(format_args!(
        "{prefix}{color}Controller {address} {alias}{default_marker}{off}\n",
    ));
}

fn print_device(proxy: &CachedProxy, description: Option<&str>) {
    let address = proxy_address(proxy);
    let alias = proxy.get_str("Alias").unwrap_or_default();
    let flags = proxy.get_property("AdvertisingFlags");
    let mut use_gray = false;
    if let Some(flags_val) = flags {
        if let Some(bytes) = value_to_byte_vec(flags_val) {
            if !bytes.is_empty() {
                let f = bytes[0];
                let discoverable = (f & BT_AD_FLAG_LIMITED) != 0 || (f & BT_AD_FLAG_GENERAL) != 0;
                if !discoverable {
                    use_gray = true;
                }
                let filter_disc = with_state(|s| s.filter.discoverable);
                if filter_disc && !discoverable {
                    return;
                }
            }
        }
    }
    let prefix = colored_description(description);
    let color = if use_gray { COLOR_BOLDGRAY } else { "" };
    let color_off = if use_gray { COLOR_OFF } else { "" };
    bt_shell_printf(format_args!("{prefix}{color}Device {address} {alias}{color_off}\n",));
}

fn value_to_byte_vec(value: &OwnedValue) -> Option<Vec<u8>> {
    let val: &Value<'_> = value.downcast_ref().ok()?;
    match val {
        Value::Array(arr) => {
            let mut bytes = Vec::new();
            for item in arr.iter() {
                if let Value::U8(b) = item {
                    bytes.push(*b);
                }
            }
            Some(bytes)
        }
        _ => None,
    }
}

fn value_to_string_vec(value: &OwnedValue) -> Option<Vec<String>> {
    let val: &Value<'_> = value.downcast_ref().ok()?;
    match val {
        Value::Array(arr) => {
            let mut strings = Vec::new();
            for item in arr.iter() {
                if let Value::Str(s) = item {
                    strings.push(s.to_string());
                }
            }
            Some(strings)
        }
        _ => None,
    }
}

fn print_uuids(proxy: &CachedProxy) {
    let uuids_val = match proxy.get_property("UUIDs") {
        Some(v) => v,
        None => return,
    };
    if let Some(uuids) = value_to_string_vec(uuids_val) {
        for uuid in &uuids {
            let name = bt_uuidstr_to_str(uuid).map(|s| s.to_string()).unwrap_or_default();
            print_uuid("\t", &name, uuid);
        }
    }
}

fn print_experimental(proxy: &CachedProxy) {
    let val = match proxy.get_property("ExperimentalFeatures") {
        Some(v) => v,
        None => return,
    };
    if let Some(uuids) = value_to_string_vec(val) {
        for uuid in &uuids {
            let name = bt_uuidstr_to_str(uuid).unwrap_or_default();
            if name.is_empty() {
                bt_shell_printf(format_args!("\tExperimentalFeatures: {uuid}\n"));
            } else {
                bt_shell_printf(format_args!("\tExperimentalFeatures: {uuid} ({name})\n"));
            }
        }
    }
}

fn proxy_is_child(device: &CachedProxy, parent: &CachedProxy) -> bool {
    device.get_str("Adapter").is_some_and(|adapter| adapter == parent.path)
}

fn service_is_child(service: &CachedProxy) -> bool {
    let device_path = match service.get_str("Device") {
        Some(p) => p,
        None => return false,
    };
    with_state(|state| {
        state
            .get_default_ctrl()
            .is_some_and(|ctrl| ctrl.devices.iter().any(|d| d.path == device_path))
    })
}

fn find_parent(proxy: &CachedProxy, ctrl_list: &[Adapter]) -> Option<usize> {
    ctrl_list.iter().position(|adapter| {
        proxy.get_str("Adapter").is_some_and(|adapter_path| adapter_path == adapter.proxy.path)
    })
}

fn set_default_device(proxy: Option<&CachedProxy>, attribute: Option<&str>) {
    with_state_mut(|state| {
        state.default_dev = proxy.cloned();
        state.default_attr = None;
        state.default_local_attr = None;
    });

    if let Some(p) = proxy {
        let alias = p.get_str("Alias").unwrap_or_default();
        let desc = if let Some(attr) = attribute {
            format!("[{}:{}]", alias, attr)
        } else {
            format!("[{}]", alias)
        };
        bt_shell_set_prompt(&desc, COLOR_BLUE);
    } else {
        let has_ctrl = with_state(|state| state.default_ctrl.is_some());
        if has_ctrl {
            let prompt = with_state(|state| {
                state
                    .get_default_ctrl()
                    .and_then(|ctrl| ctrl.proxy.get_str("Alias"))
                    .map(|alias| format!("[{}]", alias))
                    .unwrap_or_else(|| PROMPT_ON.to_string())
            });
            bt_shell_set_prompt(&prompt, COLOR_BLUE);
        } else {
            bt_shell_set_prompt(PROMPT_OFF, "");
        }
    }
}

fn set_default_attribute(proxy: &ProxyInfo) {
    with_state_mut(|state| {
        state.default_attr = Some(proxy.clone());
        state.default_local_attr = None;
    });
    let desc = format!("[{}]", proxy.path());
    bt_shell_set_prompt(&desc, COLOR_BLUE);
}

fn check_default_ctrl() -> bool {
    let has = with_state(|state| state.default_ctrl.is_some());
    if !has {
        bt_shell_printf(format_args!("No default controller available\n"));
    }
    has
}

fn proxy_address(proxy: &CachedProxy) -> String {
    proxy.get_str("Address").unwrap_or_default()
}

fn find_proxy_by_address<'a>(source: &'a [CachedProxy], address: &str) -> Option<&'a CachedProxy> {
    source.iter().find(|p| p.get_str("Address").is_some_and(|a| a.eq_ignore_ascii_case(address)))
}

fn find_proxies_by_path<'a>(source: &'a [CachedProxy], path: &str) -> Option<&'a CachedProxy> {
    source.iter().find(|p| p.path == path)
}

fn find_proxies_by_iface<'a>(
    source: &'a [CachedProxy],
    path: &str,
    iface: &str,
) -> Option<&'a CachedProxy> {
    source.iter().find(|p| p.path == path && p.interface == iface)
}

fn format_connection_profile(uuid: &str) -> String {
    let text = bt_uuidstr_to_str(uuid).unwrap_or(uuid);
    format!(" profile \"{}\"", text)
}

fn generic_callback_msg(result: Result<(), String>, context: &str) {
    match result {
        Ok(()) => {
            bt_shell_printf(format_args!("Changing {} succeeded\n", context));
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to set {}: {}\n", context, e));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        }
    }
}

fn parse_argument(
    args: &[&str],
    arg_table: Option<&[&str]>,
    msg: Option<&str>,
    value: &mut bool,
    option: &mut Option<String>,
) -> bool {
    if args.len() < 2 {
        bt_shell_printf(format_args!("Missing {} argument\n", msg.unwrap_or("on/off")));
        return false;
    }
    let arg = args[1];
    if arg.eq_ignore_ascii_case("on") || arg.eq_ignore_ascii_case("yes") {
        *value = true;
        if option.is_some() {
            *option = Some("on".to_string());
        }
        return true;
    }
    if arg.eq_ignore_ascii_case("off") || arg.eq_ignore_ascii_case("no") {
        *value = false;
        if option.is_some() {
            *option = Some("off".to_string());
        }
        return true;
    }
    if let Some(table) = arg_table {
        for entry in table {
            if entry.eq_ignore_ascii_case(arg) {
                *value = true;
                *option = Some(entry.to_string());
                return true;
            }
        }
    }
    bt_shell_printf(format_args!("Invalid argument {}\n", arg));
    false
}

fn parse_argument_devices(args: &[&str]) -> Option<String> {
    if args.len() < 2 || args[1].is_empty() {
        return None;
    }
    let arg = args[1];
    for entry in DEVICE_ARGUMENTS {
        if entry.eq_ignore_ascii_case(arg) {
            return Some(entry.to_string());
        }
    }
    bt_shell_printf(format_args!("Invalid argument {}\n", arg));
    None
}

fn find_device_proxy(args: &[&str]) -> Option<CachedProxy> {
    with_state(|state| {
        let ctrl = state.get_default_ctrl()?;
        if args.len() > 1 && !args[1].is_empty() {
            find_proxy_by_address(&ctrl.devices, args[1]).cloned()
        } else {
            state.default_dev.clone()
        }
    })
}

fn find_set_proxy(args: &[&str]) -> Option<CachedProxy> {
    with_state(|state| {
        let ctrl = state.get_default_ctrl()?;
        if args.len() > 1 && !args[1].is_empty() {
            ctrl.sets.iter().find(|s| s.path == args[1]).cloned()
        } else {
            None
        }
    })
}

fn data_clear(entries: &[ClearEntry], name: &str) -> bool {
    if name == "all" {
        for entry in entries {
            (entry.clear)();
        }
        return true;
    }
    for entry in entries {
        if entry.name == name {
            (entry.clear)();
            return true;
        }
    }
    bt_shell_printf(format_args!("Invalid argument {}\n", name));
    false
}

// ---------------------------------------------------------------------------
// Adapter / Device / Set / Bearer lifecycle helpers
// ---------------------------------------------------------------------------

fn adapter_new(proxy: CachedProxy) -> usize {
    with_state_mut(|state| {
        let adapter = Adapter {
            proxy,
            ad_proxy: None,
            adv_monitor_proxy: None,
            devices: Vec::new(),
            sets: Vec::new(),
            bearers: Vec::new(),
        };
        state.ctrl_list.push(adapter);
        let idx = state.ctrl_list.len() - 1;
        if state.default_ctrl.is_none() {
            state.default_ctrl = Some(idx);
        }
        idx
    })
}

fn adapter_added(proxy: CachedProxy) {
    let path = proxy.path.clone();
    let existing = with_state(|state| state.find_ctrl_index(&path));
    let _idx = match existing {
        Some(idx) => {
            with_state_mut(|state| {
                state.ctrl_list[idx].proxy = proxy.clone();
            });
            idx
        }
        None => adapter_new(proxy.clone()),
    };
    print_adapter(&proxy, Some("[NEW]"));

    let alias = proxy.get_str("Alias").unwrap_or_default();
    bt_shell_set_env("default-controller", Box::new(alias.clone()));

    let is_default = with_state(|state| state.default_ctrl == Some(_idx));
    if is_default {
        let prompt = format!("[{}]", alias);
        bt_shell_set_prompt(&prompt, COLOR_BLUE);
    }
}

fn ad_manager_added(proxy: CachedProxy) {
    let path = proxy.path.clone();
    let existing = with_state(|state| state.find_ctrl_index(&path));
    let idx = match existing {
        Some(idx) => idx,
        None => adapter_new(CachedProxy::new(&path, ADAPTER_IFACE)),
    };
    with_state_mut(|state| {
        state.ctrl_list[idx].ad_proxy = Some(proxy);
    });
}

fn admon_manager_added(proxy: CachedProxy) {
    let path = proxy.path.clone();
    let existing = with_state(|state| state.find_ctrl_index(&path));
    let idx = match existing {
        Some(idx) => idx,
        None => adapter_new(CachedProxy::new(&path, ADAPTER_IFACE)),
    };
    with_state_mut(|state| {
        state.ctrl_list[idx].adv_monitor_proxy = Some(proxy);
    });

    let conn = with_state(|state| state.dbus_conn.clone());
    if let Some(conn) = conn {
        adv_monitor::adv_monitor_add_manager(conn.clone());
        adv_monitor::adv_monitor_register_app(&conn);
    }
}

fn device_added(proxy: CachedProxy) {
    let parent_idx = with_state(|state| find_parent(&proxy, &state.ctrl_list));
    let parent_idx = match parent_idx {
        Some(idx) => idx,
        None => return,
    };

    with_state_mut(|state| {
        // Verify proxy is indeed a child of this adapter before adding
        if proxy_is_child(&proxy, &state.ctrl_list[parent_idx].proxy)
            && !state.ctrl_list[parent_idx].devices.iter().any(|d| d.path == proxy.path)
        {
            state.ctrl_list[parent_idx].devices.push(proxy.clone());
        }
    });

    print_device(&proxy, Some("[NEW]"));

    let alias = proxy.get_str("Alias").unwrap_or_default();
    bt_shell_set_env("default-device", Box::new(alias));

    // Auto-select as default device if connected.
    if proxy.get_bool("Connected").unwrap_or(false) {
        set_default_device(Some(&proxy), None);
    }
}

fn device_removed(proxy: &CachedProxy) {
    let adapter_path = match proxy.get_str("Adapter") {
        Some(p) => p,
        None => return,
    };

    with_state_mut(|state| {
        if let Some(idx) = state.find_ctrl_index(&adapter_path) {
            state.ctrl_list[idx].devices.retain(|d| d.path != proxy.path);
        }
        if state.default_dev.as_ref().is_some_and(|d| d.path == proxy.path) {
            state.default_dev = None;
            state.default_attr = None;
            state.default_local_attr = None;
        }
    });

    print_device(proxy, Some("[DEL]"));
    set_default_device(None, None);
}

fn adapter_removed(proxy: &CachedProxy) {
    let idx = with_state(|state| state.find_ctrl_index(&proxy.path));
    let idx = match idx {
        Some(i) => i,
        None => return,
    };

    print_adapter(proxy, Some("[DEL]"));

    with_state_mut(|state| {
        state.ctrl_list.remove(idx);

        // Fix up default_ctrl index.
        if state.default_ctrl == Some(idx) {
            state.default_ctrl = if state.ctrl_list.is_empty() { None } else { Some(0) };
            state.default_dev = None;
            state.default_attr = None;
            state.default_local_attr = None;
        } else if let Some(ref mut dc) = state.default_ctrl {
            if *dc > idx {
                *dc -= 1;
            }
        }
    });

    set_default_device(None, None);
}

fn battery_added(proxy: CachedProxy) {
    with_state_mut(|state| {
        if !state.battery_proxies.iter().any(|b| b.path == proxy.path) {
            state.battery_proxies.push(proxy);
        }
    });
}

fn battery_removed(proxy: &CachedProxy) {
    with_state_mut(|state| {
        state.battery_proxies.retain(|b| b.path != proxy.path);
    });
}

fn print_set(proxy: &CachedProxy, description: Option<&str>) {
    let prefix = colored_description(description);
    bt_shell_printf(format_args!("{prefix}DeviceSet {path}\n", path = proxy.path,));
}

fn set_added(proxy: CachedProxy) {
    let path = proxy.path.clone();
    let adapter_path = path
        .rfind("/dev_")
        .map(|i| &path[..path[..i].rfind('/').unwrap_or(0)])
        .unwrap_or("")
        .to_string();

    let ctrl_idx = with_state(|state| state.find_ctrl_index(&adapter_path));
    if let Some(idx) = ctrl_idx {
        with_state_mut(|state| {
            if !state.ctrl_list[idx].sets.iter().any(|s| s.path == proxy.path) {
                state.ctrl_list[idx].sets.push(proxy.clone());
            }
        });
        print_set(&proxy, Some("[NEW]"));
    }
}

fn set_removed(proxy: &CachedProxy) {
    with_state_mut(|state| {
        for adapter in &mut state.ctrl_list {
            adapter.sets.retain(|s| s.path != proxy.path);
        }
    });
    print_set(proxy, Some("[DEL]"));
}

fn print_bearer(proxy: &CachedProxy, label: &str, description: Option<&str>) {
    let prefix = colored_description(description);
    bt_shell_printf(format_args!("{prefix}{label} {path}\n", path = proxy.path,));
}

fn bearer_added(proxy: CachedProxy) {
    let device_path = proxy.path.clone();
    // Bearer path matches device path.
    let ctrl_idx = with_state(|state| {
        state.ctrl_list.iter().position(|a| {
            a.devices.iter().any(|d| d.path == device_path)
                || device_path.starts_with(&a.proxy.path)
        })
    });
    if let Some(idx) = ctrl_idx {
        with_state_mut(|state| {
            if !state.ctrl_list[idx]
                .bearers
                .iter()
                .any(|b| b.path == proxy.path && b.interface == proxy.interface)
            {
                state.ctrl_list[idx].bearers.push(proxy.clone());
            }
        });
        let label = if proxy.interface == BEARER_LE_IFACE { "LE" } else { "BREDR" };
        print_bearer(&proxy, label, Some("[NEW]"));
    }
}

fn bearer_removed(proxy: &CachedProxy) {
    with_state_mut(|state| {
        for adapter in &mut state.ctrl_list {
            adapter.bearers.retain(|b| !(b.path == proxy.path && b.interface == proxy.interface));
        }
    });
    let label = if proxy.interface == BEARER_LE_IFACE { "LE" } else { "BREDR" };
    print_bearer(proxy, label, Some("[DEL]"));
}

// ---------------------------------------------------------------------------
// Proxy event handlers
// ---------------------------------------------------------------------------

fn proxy_added(path: &str, interface: &str, props: HashMap<String, OwnedValue>) {
    let proxy = CachedProxy::with_properties(path, interface, props);

    match interface {
        DEVICE_IFACE => device_added(proxy),
        ADAPTER_IFACE => adapter_added(proxy),
        AGENT_MANAGER_IFACE => {
            with_state_mut(|state| {
                state.agent_manager = Some(proxy.clone());
            });
            // Auto-register agent if configured.
            let auto_cap = with_state(|state| state.auto_register_agent.clone());
            if let Some(cap) = auto_cap {
                let conn = with_state(|state| state.conn());
                let path_owned = path.to_string();
                spawn_async(async move {
                    let mgr_proxy = zbus::Proxy::new(
                        &conn,
                        BLUEZ_SERVICE,
                        path_owned.as_str(),
                        AGENT_MANAGER_IFACE,
                    )
                    .await;
                    if let Ok(mgr_proxy) = mgr_proxy {
                        agent_register(&conn, &mgr_proxy, &cap).await;
                    }
                });
            }
        }
        GATT_SERVICE_IFACE if service_is_child(&proxy) => {
            let pi = ProxyInfo::new(path, interface);
            gatt_add_service(&pi);
        }
        GATT_CHAR_IFACE => {
            let pi = ProxyInfo::new(path, interface);
            gatt_add_characteristic(&pi);
        }
        GATT_DESC_IFACE => {
            let pi = ProxyInfo::new(path, interface);
            gatt_add_descriptor(&pi);
        }
        GATT_MANAGER_IFACE => {
            let pi = ProxyInfo::new(path, interface);
            gatt_add_manager(&pi);
        }
        LE_ADV_MANAGER_IFACE => ad_manager_added(proxy),
        BATTERY_IFACE => battery_added(proxy),
        ADV_MONITOR_MANAGER_IFACE => admon_manager_added(proxy),
        DEVICE_SET_IFACE => set_added(proxy),
        BEARER_BREDR_IFACE | BEARER_LE_IFACE => bearer_added(proxy),
        _ => {}
    }
}

fn proxy_removed(path: &str, interface: &str) {
    let proxy = CachedProxy::new(path, interface);

    match interface {
        DEVICE_IFACE => {
            let full = with_state(|state| {
                state
                    .get_default_ctrl()
                    .and_then(|ctrl| ctrl.devices.iter().find(|d| d.path == path).cloned())
            });
            if let Some(dev) = full {
                device_removed(&dev);
            }
        }
        ADAPTER_IFACE => {
            let full = with_state(|state| {
                state.ctrl_list.iter().find(|a| a.proxy.path == path).map(|a| a.proxy.clone())
            });
            if let Some(a) = full {
                adapter_removed(&a);
            }
        }
        AGENT_MANAGER_IFACE => {
            let conn = with_state(|state| state.dbus_conn.clone());
            with_state_mut(|state| {
                state.agent_manager = None;
            });
            if let Some(conn) = conn {
                spawn_async(async move {
                    agent_unregister(&conn, None).await;
                });
            }
        }
        GATT_SERVICE_IFACE => {
            let pi = ProxyInfo::new(path, interface);
            gatt_remove_service(&pi);
            with_state_mut(|state| {
                if state.default_attr.as_ref().is_some_and(|a| a.path() == path) {
                    state.default_attr = None;
                }
            });
        }
        GATT_CHAR_IFACE => {
            let pi = ProxyInfo::new(path, interface);
            gatt_remove_characteristic(&pi);
            with_state_mut(|state| {
                if state.default_attr.as_ref().is_some_and(|a| a.path() == path) {
                    state.default_attr = None;
                }
            });
        }
        GATT_DESC_IFACE => {
            let pi = ProxyInfo::new(path, interface);
            gatt_remove_descriptor(&pi);
            with_state_mut(|state| {
                if state.default_attr.as_ref().is_some_and(|a| a.path() == path) {
                    state.default_attr = None;
                }
            });
        }
        GATT_MANAGER_IFACE => {
            let pi = ProxyInfo::new(path, interface);
            gatt_remove_manager(&pi);
        }
        LE_ADV_MANAGER_IFACE => {
            let conn = with_state(|state| state.dbus_conn.clone());
            if let Some(conn) = conn {
                ad_unregister(&conn, Some(""));
            }
        }
        BATTERY_IFACE => battery_removed(&proxy),
        ADV_MONITOR_MANAGER_IFACE => {
            adv_monitor::adv_monitor_remove_manager();
        }
        DEVICE_SET_IFACE => set_removed(&proxy),
        BEARER_BREDR_IFACE | BEARER_LE_IFACE => bearer_removed(&proxy),
        _ => {}
    }
}

fn property_changed(path: &str, interface: &str, name: &str, value: &OwnedValue) {
    match interface {
        DEVICE_IFACE => {
            let address = with_state(|state| {
                state
                    .get_default_ctrl()
                    .and_then(|ctrl| find_proxies_by_path(&ctrl.devices, path).map(proxy_address))
            });
            if let Some(addr) = address {
                bt_shell_printf(format_args!(
                    "{color}[CHG]{off} Device {addr} ",
                    color = COLOR_YELLOW,
                    off = COLOR_OFF
                ));
                print_iter("", name, value);
            }

            // Update property in cache.
            with_state_mut(|state| {
                if let Some(ctrl) = state.get_default_ctrl_mut() {
                    if let Some(dev) = ctrl.devices.iter_mut().find(|d| d.path == path) {
                        dev.set_property(name, value.clone());
                    }
                }
                // Update default_dev cache too.
                if let Some(ref mut dev) = state.default_dev {
                    if dev.path == path {
                        dev.set_property(name, value.clone());
                    }
                }
            });

            // Handle Connected property change for default_dev.
            if name == "Connected" {
                let connected = value.downcast_ref::<bool>().unwrap_or(false);
                let is_default =
                    with_state(|s| s.default_dev.as_ref().is_some_and(|d| d.path == path));
                if !connected && is_default {
                    set_default_device(None, None);
                }
            }
        }
        ADAPTER_IFACE => {
            let address = with_state(|state| {
                state
                    .ctrl_list
                    .iter()
                    .find(|a| a.proxy.path == path)
                    .and_then(|a| a.proxy.get_str("Address"))
            });
            if let Some(addr) = address {
                bt_shell_printf(format_args!(
                    "{color}[CHG]{off} Controller {addr} ",
                    color = COLOR_YELLOW,
                    off = COLOR_OFF
                ));
                print_iter("", name, value);
            }
            // Update cache.
            with_state_mut(|state| {
                if let Some(a) = state.ctrl_list.iter_mut().find(|a| a.proxy.path == path) {
                    a.proxy.set_property(name, value.clone());
                }
            });
        }
        LE_ADV_MANAGER_IFACE => {
            let address = with_state(|state| {
                state
                    .ctrl_list
                    .iter()
                    .find(|a| a.ad_proxy.as_ref().is_some_and(|p| p.path == path))
                    .and_then(|a| a.proxy.get_str("Address"))
            });
            if let Some(addr) = address {
                bt_shell_printf(format_args!(
                    "{color}[CHG]{off} Controller {addr} ",
                    color = COLOR_YELLOW,
                    off = COLOR_OFF
                ));
                print_iter("", name, value);
            }
        }
        BEARER_BREDR_IFACE | BEARER_LE_IFACE => {
            let label = if interface == BEARER_LE_IFACE { "LE" } else { "BREDR" };
            let addr = with_state(|state| {
                state
                    .get_default_ctrl()
                    .and_then(|ctrl| find_proxies_by_path(&ctrl.devices, path).map(proxy_address))
            });
            if let Some(addr) = addr {
                bt_shell_printf(format_args!(
                    "{color}[CHG]{off} {label} {addr} ",
                    color = COLOR_YELLOW,
                    off = COLOR_OFF
                ));
                print_iter("", name, value);
            }
            // Update bearer cache using find_proxies_by_iface for precision.
            with_state_mut(|state| {
                if let Some(ctrl) = state.get_default_ctrl_mut() {
                    if let Some(b) = find_proxies_by_iface(&ctrl.bearers, path, interface) {
                        // Found the bearer, update via mutable lookup
                        let idx = ctrl
                            .bearers
                            .iter()
                            .position(|x| x.path == b.path && x.interface == b.interface);
                        if let Some(idx) = idx {
                            ctrl.bearers[idx].set_property(name, value.clone());
                        }
                    }
                }
            });
        }
        _ => {
            // Check if it's the default attribute.
            let is_default_attr =
                with_state(|s| s.default_attr.as_ref().is_some_and(|a| a.path() == path));
            if is_default_attr {
                bt_shell_printf(format_args!(
                    "{color}[CHG]{off} Attribute {path} ",
                    color = COLOR_YELLOW,
                    off = COLOR_OFF
                ));
                print_iter("", name, value);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main menu command handlers
// ---------------------------------------------------------------------------

fn cmd_list(args: &[&str]) {
    let _ = args;
    with_state(|state| {
        for adapter in &state.ctrl_list {
            print_adapter(&adapter.proxy, None);
        }
    });
}

fn cmd_show(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }

    let proxy = if args.len() > 1 && !args[1].is_empty() {
        let idx = with_state(|state| state.find_ctrl_index_by_address(args[1]));
        match idx {
            Some(i) => with_state(|state| state.ctrl_list[i].proxy.clone()),
            None => {
                bt_shell_printf(format_args!("Controller {} not available\n", args[1]));
                return;
            }
        }
    } else {
        with_state(|state| {
            state
                .get_default_ctrl()
                .map(|c| c.proxy.clone())
                .unwrap_or_else(|| CachedProxy::new("", ""))
        })
    };

    let address = proxy.get_str("Address").unwrap_or_default();
    bt_shell_printf(format_args!("Controller {}\n", address));

    for prop in &[
        "Address",
        "AddressType",
        "Manufacturer",
        "Version",
        "Name",
        "Alias",
        "Class",
        "Powered",
        "PowerState",
        "Discoverable",
        "DiscoverableTimeout",
        "Pairable",
    ] {
        proxy.print_property_cached(prop);
    }
    print_uuids(&proxy);

    for prop in &["Modalias", "Discovering", "Roles"] {
        proxy.print_property_cached(prop);
    }
    print_experimental(&proxy);

    // Print advertising manager properties.
    let ad_proxy = with_state(|state| state.get_default_ctrl().and_then(|c| c.ad_proxy.clone()));
    if let Some(ap) = ad_proxy {
        let ad_props = &[
            "ActiveInstances",
            "SupportedInstances",
            "SupportedIncludes",
            "SupportedSecondaryChannels",
            "SupportedCapabilities",
            "SupportedFeatures",
        ];
        for prop in ad_props {
            if let Some(val) = ap.get_property(prop) {
                print_iter("\t", prop, val);
            }
        }
    }

    // Print adv monitor manager properties.
    let adm_proxy =
        with_state(|state| state.get_default_ctrl().and_then(|c| c.adv_monitor_proxy.clone()));
    if let Some(am) = adm_proxy {
        let adm_props = &["SupportedMonitorTypes", "SupportedFeatures"];
        for prop in adm_props {
            if let Some(val) = am.get_property(prop) {
                print_iter("\t", prop, val);
            }
        }
    }
}

fn cmd_select(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing controller address argument\n"));
        return;
    }
    let idx = with_state(|state| state.find_ctrl_index_by_address(args[1]));
    match idx {
        Some(i) => {
            with_state_mut(|state| {
                state.default_ctrl = Some(i);
                state.default_dev = None;
                state.default_attr = None;
            });
            let alias =
                with_state(|state| state.ctrl_list[i].proxy.get_str("Alias").unwrap_or_default());
            let prompt = format!("[{}]", alias);
            bt_shell_set_prompt(&prompt, COLOR_BLUE);
        }
        None => {
            bt_shell_printf(format_args!("Controller {} not available\n", args[1]));
        }
    }
}

fn cmd_devices(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    let property = if args.len() > 1 && !args[1].is_empty() {
        match parse_argument_devices(args) {
            Some(p) => Some(p),
            None => return,
        }
    } else {
        None
    };

    with_state(|state| {
        let ctrl = match state.get_default_ctrl() {
            Some(c) => c,
            None => return,
        };
        for dev in &ctrl.devices {
            if let Some(ref prop) = property {
                if !dev.get_bool(prop).unwrap_or(false) {
                    continue;
                }
            }
            print_device(dev, None);
        }
    });
}

fn set_property_async(path: String, iface: String, name: &'static str, value: OwnedValue) {
    let conn = with_state(|state| state.conn());
    let context = name.to_string();
    spawn_async(async move {
        let proxy =
            zbus::Proxy::new(&conn, BLUEZ_SERVICE, path, "org.freedesktop.DBus.Properties").await;
        match proxy {
            Ok(p) => {
                let result = p
                    .call_method("Set", &(iface, &context, &value))
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string());
                generic_callback_msg(result, &context);
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to set {}: {}\n", context, e));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        }
    });
}

fn cmd_system_alias(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing name argument\n"));
        return;
    }
    let (path, iface) = with_state(|state| {
        let ctrl = state.get_default_ctrl().unwrap();
        (ctrl.proxy.path.clone(), ctrl.proxy.interface.clone())
    });
    set_property_async(
        path,
        iface,
        "Alias",
        OwnedValue::from(zbus::zvariant::Str::from(args[1].to_string())),
    );
}

fn cmd_reset_alias(args: &[&str]) {
    let _ = args;
    if !check_default_ctrl() {
        return;
    }
    let (path, iface) = with_state(|state| {
        let ctrl = state.get_default_ctrl().unwrap();
        (ctrl.proxy.path.clone(), ctrl.proxy.interface.clone())
    });
    set_property_async(path, iface, "Alias", OwnedValue::from(zbus::zvariant::Str::from("")));
}

fn cmd_power(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    let mut value = false;
    let mut option = Some(String::new());
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    let (path, iface) = with_state(|state| {
        let ctrl = state.get_default_ctrl().unwrap();
        (ctrl.proxy.path.clone(), ctrl.proxy.interface.clone())
    });
    set_property_async(path, iface, "Powered", OwnedValue::from(value));
}

fn cmd_pairable(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    let mut value = false;
    let mut option = Some(String::new());
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    let (path, iface) = with_state(|state| {
        let ctrl = state.get_default_ctrl().unwrap();
        (ctrl.proxy.path.clone(), ctrl.proxy.interface.clone())
    });
    set_property_async(path, iface, "Pairable", OwnedValue::from(value));
}

fn cmd_discoverable(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    let mut value = false;
    let mut option = Some(String::new());
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    // Warn if DiscoverableTimeout is 0 and turning on.
    if value {
        let timeout = with_state(|state| {
            state
                .get_default_ctrl()
                .and_then(|c| c.proxy.get_u32("DiscoverableTimeout"))
                .unwrap_or(0)
        });
        if timeout == 0 {
            bt_shell_printf(format_args!(
                "Discoverable timeout has not been set. Use 'discoverable-timeout' to set.\n"
            ));
        }
    }
    let (path, iface) = with_state(|state| {
        let ctrl = state.get_default_ctrl().unwrap();
        (ctrl.proxy.path.clone(), ctrl.proxy.interface.clone())
    });
    set_property_async(path, iface, "Discoverable", OwnedValue::from(value));
}

fn cmd_discoverable_timeout(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    if args.len() < 2 || args[1].is_empty() {
        let timeout = with_state(|state| {
            state
                .get_default_ctrl()
                .and_then(|c| c.proxy.get_u32("DiscoverableTimeout"))
                .unwrap_or(0)
        });
        bt_shell_printf(format_args!("DiscoverableTimeout: {}\n", timeout));
        return;
    }
    let val: u32 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid argument {}\n", args[1]));
            return;
        }
    };
    let (path, iface) = with_state(|state| {
        let ctrl = state.get_default_ctrl().unwrap();
        (ctrl.proxy.path.clone(), ctrl.proxy.interface.clone())
    });
    set_property_async(path, iface, "DiscoverableTimeout", OwnedValue::from(val));
}

fn cmd_agent(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if !parse_argument(args, Some(AGENT_ARGUMENTS), Some("capability"), &mut value, &mut option) {
        return;
    }

    let capability = option.unwrap_or_default();
    let conn = with_state(|state| state.conn());
    let agent_mgr = with_state(|state| state.agent_manager.clone());

    if value {
        if let Some(ref mgr) = agent_mgr {
            let mgr_path = mgr.path.clone();
            let cap = capability.clone();
            spawn_async(async move {
                let proxy =
                    zbus::Proxy::new(&conn, BLUEZ_SERVICE, mgr_path, AGENT_MANAGER_IFACE).await;
                if let Ok(proxy) = proxy {
                    agent_register(&conn, &proxy, &cap).await;
                }
            });
        } else {
            bt_shell_printf(format_args!("AgentManager1 interface not available\n"));
        }
    } else {
        spawn_async(async move {
            let mgr_proxy = if let Some(ref mgr) = agent_mgr {
                zbus::Proxy::new(&conn, BLUEZ_SERVICE, mgr.path.clone(), AGENT_MANAGER_IFACE)
                    .await
                    .ok()
            } else {
                None
            };
            agent_unregister(&conn, mgr_proxy.as_ref()).await;
        });
    }
}

fn cmd_default_agent(args: &[&str]) {
    let _ = args;
    let conn = with_state(|state| state.conn());
    let agent_mgr = with_state(|state| state.agent_manager.clone());
    if let Some(ref mgr) = agent_mgr {
        let mgr_path = mgr.path.clone();
        spawn_async(async move {
            let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, mgr_path, AGENT_MANAGER_IFACE).await;
            if let Ok(proxy) = proxy {
                agent_default(&conn, &proxy).await;
            }
        });
    } else {
        bt_shell_printf(format_args!("AgentManager1 interface not available\n"));
    }
}

fn cmd_advertise(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if !parse_argument(args, Some(AD_ARGUMENTS), Some("type"), &mut value, &mut option) {
        return;
    }
    let conn = with_state(|state| state.conn());
    if value {
        let ad_type = option.unwrap_or_else(|| "peripheral".to_string());
        let mgr_path = with_state(|s| {
            s.default_ctrl
                .and_then(|idx| s.ctrl_list.get(idx))
                .and_then(|a| a.ad_proxy.as_ref())
                .map(|p| p.path.clone())
                .unwrap_or_default()
        });
        ad_register(&conn, &mgr_path, &ad_type);
    } else {
        let mgr_path = with_state(|s| {
            s.default_ctrl
                .and_then(|idx| s.ctrl_list.get(idx))
                .and_then(|a| a.ad_proxy.as_ref())
                .map(|p| p.path.clone())
        });
        ad_unregister(&conn, mgr_path.as_deref());
    }
}

fn call_method_async(proxy_path: String, method: &'static str, success_msg: &'static str) {
    let conn = with_state(|state| state.conn());
    spawn_async(async move {
        let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, proxy_path, DEVICE_IFACE).await;
        match proxy {
            Ok(p) => {
                let result: Result<(), zbus::Error> = p.call_method(method, &()).await.map(|_| ());
                match result {
                    Ok(()) => {
                        bt_shell_printf(format_args!("{} successful\n", success_msg));
                        bt_shell_noninteractive_quit(EXIT_SUCCESS);
                    }
                    Err(e) => {
                        bt_shell_printf(format_args!("Failed to {}: {}\n", method, e));
                        bt_shell_noninteractive_quit(EXIT_FAILURE);
                    }
                }
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to {}: {}\n", method, e));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        }
    });
}

fn set_device_property_async(args: &[&str], name: &'static str, value: bool) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };
    set_property_async(dev.path.clone(), DEVICE_IFACE.to_string(), name, OwnedValue::from(value));
}

fn cmd_set_alias(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing name argument\n"));
        return;
    }
    let dev = with_state(|state| state.default_dev.clone());
    match dev {
        Some(d) => {
            set_property_async(
                d.path.clone(),
                DEVICE_IFACE.to_string(),
                "Alias",
                OwnedValue::from(zbus::zvariant::Str::from(args[1].to_string())),
            );
        }
        None => {
            bt_shell_printf(format_args!("No device connected\n"));
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery filter setup / commands
// ---------------------------------------------------------------------------

fn set_discovery_filter_setup() -> HashMap<String, Value<'static>> {
    let mut dict: HashMap<String, Value<'static>> = HashMap::new();
    with_state(|state| {
        let f = &state.filter;
        if !f.uuids.is_empty() {
            let uuids: Vec<Value<'_>> = f.uuids.iter().map(|u| Value::new(u.clone())).collect();
            dict.insert("UUIDs".to_string(), Value::new(uuids));
        }
        if f.pathloss != DISTANCE_VAL_INVALID {
            dict.insert("Pathloss".to_string(), Value::U16(f.pathloss as u16));
        }
        if f.rssi != DISTANCE_VAL_INVALID {
            dict.insert("RSSI".to_string(), Value::I16(f.rssi));
        }
        if let Some(ref t) = f.transport {
            dict.insert("Transport".to_string(), Value::new(t.clone()));
        }
        if f.duplicate {
            dict.insert("DuplicateData".to_string(), Value::Bool(f.duplicate));
        }
        if f.discoverable {
            dict.insert("Discoverable".to_string(), Value::Bool(f.discoverable));
        }
        if let Some(ref p) = f.pattern {
            dict.insert("Pattern".to_string(), Value::new(p.clone()));
        }
        if f.auto_connect {
            dict.insert("AutoConnect".to_string(), Value::Bool(f.auto_connect));
        }
    });
    dict
}

fn set_discovery_filter(cleared: bool) {
    if !check_default_ctrl() {
        return;
    }
    let (path, active, set_flag) = with_state(|state| {
        let ctrl = state.get_default_ctrl().unwrap();
        (ctrl.proxy.path.clone(), state.filter.active, state.filter.set)
    });

    if !set_flag && !cleared && !active {
        return;
    }

    let dict = if cleared { HashMap::new() } else { set_discovery_filter_setup() };

    let conn = with_state(|state| state.conn());
    spawn_async(async move {
        let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, path, ADAPTER_IFACE).await;
        if let Ok(p) = proxy {
            let result: Result<zbus::Message, zbus::Error> =
                p.call_method("SetDiscoveryFilter", &(dict,)).await;
            match result {
                Ok(_) => {
                    with_state_mut(|state| {
                        state.filter.active = !cleared;
                    });
                    bt_shell_printf(format_args!("SetDiscoveryFilter success\n"));
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                }
                Err(e) => {
                    bt_shell_printf(format_args!("SetDiscoveryFilter failed: {}\n", e));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        }
    });
}

fn cmd_scan(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    let mut value = false;
    let mut option = Some(String::new());
    if !parse_argument(args, Some(SCAN_ARGUMENTS), Some("on/off/bredr/le"), &mut value, &mut option)
    {
        return;
    }

    let opt = option.unwrap_or_default();
    if opt == "bredr" || opt == "le" {
        with_state_mut(|state| {
            state.filter.transport = Some(opt.clone());
            state.filter.set = true;
        });
        set_discovery_filter(false);
    }

    let path = with_state(|state| {
        state.get_default_ctrl().map(|c| c.proxy.path.clone()).unwrap_or_default()
    });

    let method = if value { "StartDiscovery" } else { "StopDiscovery" };
    let conn = with_state(|state| state.conn());
    spawn_async(async move {
        let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, path, ADAPTER_IFACE).await;
        if let Ok(p) = proxy {
            let result: Result<zbus::Message, zbus::Error> = p.call_method(method, &()).await;
            match result {
                Ok(_) => {
                    bt_shell_printf(format_args!(
                        "Discovery {}\n",
                        if value { "started" } else { "stopped" }
                    ));
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                }
                Err(e) => {
                    bt_shell_printf(format_args!("Failed to {}: {}\n", method, e));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        }
    });
}

fn cmd_scan_filter_uuids(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        with_state(|state| {
            if state.filter.uuids.is_empty() {
                bt_shell_printf(format_args!("UUID filter: (none)\n"));
            } else {
                for uuid in &state.filter.uuids {
                    bt_shell_printf(format_args!("UUID: {}\n", uuid));
                }
            }
        });
        return;
    }
    with_state_mut(|state| {
        state.filter.uuids.clear();
        for arg in &args[1..] {
            if !arg.is_empty() {
                state.filter.uuids.push(arg.to_string());
            }
        }
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn cmd_scan_filter_rssi(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        let rssi = with_state(|s| s.filter.rssi);
        if rssi == DISTANCE_VAL_INVALID {
            bt_shell_printf(format_args!("RSSI: (not set)\n"));
        } else {
            bt_shell_printf(format_args!("RSSI: {}\n", rssi));
        }
        return;
    }
    let val: i16 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid argument {}\n", args[1]));
            return;
        }
    };
    with_state_mut(|state| {
        state.filter.rssi = val;
        state.filter.pathloss = DISTANCE_VAL_INVALID;
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn cmd_scan_filter_pathloss(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        let pl = with_state(|s| s.filter.pathloss);
        if pl == DISTANCE_VAL_INVALID {
            bt_shell_printf(format_args!("Pathloss: (not set)\n"));
        } else {
            bt_shell_printf(format_args!("Pathloss: {}\n", pl));
        }
        return;
    }
    let val: i16 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Invalid argument {}\n", args[1]));
            return;
        }
    };
    with_state_mut(|state| {
        state.filter.pathloss = val;
        state.filter.rssi = DISTANCE_VAL_INVALID;
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn cmd_scan_filter_transport(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        let t = with_state(|s| s.filter.transport.clone());
        bt_shell_printf(format_args!("Transport: {}\n", t.unwrap_or_else(|| "(not set)".into())));
        return;
    }
    with_state_mut(|state| {
        state.filter.transport = Some(args[1].to_string());
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn cmd_scan_filter_duplicate_data(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if args.len() < 2 || args[1].is_empty() {
        let d = with_state(|s| s.filter.duplicate);
        bt_shell_printf(format_args!("DuplicateData: {}\n", if d { "on" } else { "off" }));
        return;
    }
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    with_state_mut(|state| {
        state.filter.duplicate = value;
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn cmd_scan_filter_discoverable(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if args.len() < 2 || args[1].is_empty() {
        let d = with_state(|s| s.filter.discoverable);
        bt_shell_printf(format_args!("Discoverable: {}\n", if d { "on" } else { "off" }));
        return;
    }
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    with_state_mut(|state| {
        state.filter.discoverable = value;
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn cmd_scan_filter_pattern(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        let p = with_state(|s| s.filter.pattern.clone());
        bt_shell_printf(format_args!("Pattern: {}\n", p.unwrap_or_else(|| "(not set)".into())));
        return;
    }
    with_state_mut(|state| {
        state.filter.pattern = Some(args[1].to_string());
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn cmd_scan_filter_auto_connect(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if args.len() < 2 || args[1].is_empty() {
        let a = with_state(|s| s.filter.auto_connect);
        bt_shell_printf(format_args!("AutoConnect: {}\n", if a { "on" } else { "off" }));
        return;
    }
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    with_state_mut(|state| {
        state.filter.auto_connect = value;
        state.filter.set = true;
    });
    set_discovery_filter(false);
}

fn filter_clear_uuids() {
    with_state_mut(|state| state.filter.uuids.clear());
}
fn filter_clear_rssi() {
    with_state_mut(|state| state.filter.rssi = DISTANCE_VAL_INVALID);
}
fn filter_clear_pathloss() {
    with_state_mut(|state| state.filter.pathloss = DISTANCE_VAL_INVALID);
}
fn filter_clear_transport() {
    with_state_mut(|state| state.filter.transport = None);
}
fn filter_clear_duplicate_data() {
    with_state_mut(|state| state.filter.duplicate = false);
}
fn filter_clear_discoverable() {
    with_state_mut(|state| state.filter.discoverable = false);
}
fn filter_clear_pattern() {
    with_state_mut(|state| state.filter.pattern = None);
}
fn filter_clear_auto_connect() {
    with_state_mut(|state| state.filter.auto_connect = false);
}

static FILTER_CLEAR: &[ClearEntry] = &[
    ClearEntry { name: "uuids", clear: filter_clear_uuids },
    ClearEntry { name: "rssi", clear: filter_clear_rssi },
    ClearEntry { name: "pathloss", clear: filter_clear_pathloss },
    ClearEntry { name: "transport", clear: filter_clear_transport },
    ClearEntry { name: "duplicate-data", clear: filter_clear_duplicate_data },
    ClearEntry { name: "discoverable", clear: filter_clear_discoverable },
    ClearEntry { name: "pattern", clear: filter_clear_pattern },
    ClearEntry { name: "auto-connect", clear: filter_clear_auto_connect },
];

fn cmd_scan_filter_clear(args: &[&str]) {
    let name = if args.len() > 1 && !args[1].is_empty() { args[1] } else { "all" };
    if data_clear(FILTER_CLEAR, name) {
        set_discovery_filter(name == "all");
    }
}

// ---------------------------------------------------------------------------
// Device info and operation commands
// ---------------------------------------------------------------------------

fn cmd_info(args: &[&str]) {
    let dev = find_device_proxy(args);
    if dev.is_none() {
        // Try set info.
        cmd_set_info(args);
        return;
    }
    let dev = dev.unwrap();
    let address = dev.get_str("Address").unwrap_or_default();
    bt_shell_printf(format_args!("Device {}\n", address));

    let props = &[
        "Address",
        "AddressType",
        "Name",
        "Alias",
        "Class",
        "Appearance",
        "Icon",
        "Paired",
        "Bonded",
        "Trusted",
        "Blocked",
        "Connected",
        "WakeAllowed",
        "LegacyPairing",
        "CablePairing",
    ];
    for prop in props {
        if let Some(val) = dev.get_property(prop) {
            print_iter("\t", prop, val);
        }
    }
    print_uuids(&dev);

    let extra = &[
        "Modalias",
        "ManufacturerData",
        "ServiceData",
        "RSSI",
        "TxPower",
        "AdvertisingFlags",
        "AdvertisingData",
    ];
    for prop in extra {
        if let Some(val) = dev.get_property(prop) {
            print_iter("\t", prop, val);
        }
    }

    // Print sets.
    let sets = with_state(|state| {
        state.get_default_ctrl().map(|c| {
            c.sets.iter().filter(|s| s.path.starts_with(&dev.path)).cloned().collect::<Vec<_>>()
        })
    });
    if let Some(sets) = sets {
        for set in &sets {
            print_set(set, Some("\t"));
        }
    }

    let bearer_props = &["PreferredBearer"];
    for prop in bearer_props {
        if let Some(val) = dev.get_property(prop) {
            print_iter("\t", prop, val);
        }
    }

    // Print battery info.
    let battery =
        with_state(|state| state.battery_proxies.iter().find(|b| b.path == dev.path).cloned());
    if let Some(bat) = battery {
        if let Some(pct) = bat.get_property("Percentage") {
            print_iter("\tBattery ", "Percentage", pct);
        }
    }

    // Print bearer-specific properties.
    let bearers = with_state(|state| {
        state
            .get_default_ctrl()
            .map(|c| c.bearers.iter().filter(|b| b.path == dev.path).cloned().collect::<Vec<_>>())
    });
    if let Some(bearers) = bearers {
        for b in &bearers {
            let label = if b.interface == BEARER_LE_IFACE { "LE" } else { "BREDR" };
            for prop in &["Paired", "Bonded", "Connected"] {
                if let Some(val) = b.get_property(prop) {
                    let full_label = format!("{}.{}", label, prop);
                    print_iter("\t", &full_label, val);
                }
            }
        }
    }
}

fn cmd_set_info(args: &[&str]) {
    let set = find_set_proxy(args);
    let set = match set {
        Some(s) => s,
        None => {
            bt_shell_printf(format_args!("Missing device/set argument\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };
    bt_shell_printf(format_args!("DeviceSet {}\n", set.path));
    for prop in &["AutoConnect", "Devices", "Size"] {
        if let Some(val) = set.get_property(prop) {
            print_iter("\t", prop, val);
        }
    }
}

fn cmd_pair(args: &[&str]) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };
    call_method_async(dev.path.clone(), "Pair", "Pairing");
}

fn cmd_cancel_pairing(args: &[&str]) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };
    call_method_async(dev.path.clone(), "CancelPairing", "Cancel pairing");
}

fn cmd_trust(args: &[&str]) {
    set_device_property_async(args, "Trusted", true);
}

fn cmd_untrust(args: &[&str]) {
    set_device_property_async(args, "Trusted", false);
}

fn cmd_block(args: &[&str]) {
    set_device_property_async(args, "Blocked", true);
}

fn cmd_unblock(args: &[&str]) {
    set_device_property_async(args, "Blocked", false);
}

fn cmd_remove(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing device address argument\n"));
        return;
    }

    if args[1] == "*" {
        // Remove all devices.
        let devices: Vec<CachedProxy> = with_state(|state| {
            state.get_default_ctrl().map(|c| c.devices.clone()).unwrap_or_default()
        });
        for dev in devices {
            let adapter_path = with_state(|state| {
                state.get_default_ctrl().map(|c| c.proxy.path.clone()).unwrap_or_default()
            });
            let dev_path = dev.path.clone();
            let conn = with_state(|state| state.conn());
            spawn_async(async move {
                let proxy =
                    zbus::Proxy::new(&conn, BLUEZ_SERVICE, adapter_path, ADAPTER_IFACE).await;
                if let Ok(p) = proxy {
                    let objpath = OwnedObjectPath::try_from(dev_path.clone()).ok();
                    if let Some(obj) = objpath {
                        let result: Result<zbus::Message, zbus::Error> =
                            p.call_method("RemoveDevice", &(obj,)).await;
                        match result {
                            Ok(_) => {
                                bt_shell_printf(format_args!("Device {} removed\n", dev_path));
                            }
                            Err(e) => {
                                bt_shell_printf(format_args!(
                                    "Failed to remove {}: {}\n",
                                    dev_path, e
                                ));
                            }
                        }
                    }
                }
            });
        }
        return;
    }

    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Device {} not available\n", args[1]));
            return;
        }
    };

    let adapter_path = with_state(|state| {
        state.get_default_ctrl().map(|c| c.proxy.path.clone()).unwrap_or_default()
    });
    let dev_path = dev.path.clone();
    let conn = with_state(|state| state.conn());

    spawn_async(async move {
        let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, adapter_path, ADAPTER_IFACE).await;
        if let Ok(p) = proxy {
            let objpath = OwnedObjectPath::try_from(dev_path.clone()).ok();
            if let Some(obj) = objpath {
                let result: Result<zbus::Message, zbus::Error> =
                    p.call_method("RemoveDevice", &(obj,)).await;
                match result {
                    Ok(_) => {
                        bt_shell_printf(format_args!("Device has been removed\n"));
                        bt_shell_noninteractive_quit(EXIT_SUCCESS);
                    }
                    Err(e) => {
                        bt_shell_printf(format_args!("Failed to remove device: {}\n", e));
                        bt_shell_noninteractive_quit(EXIT_FAILURE);
                    }
                }
            }
        }
    });
}

fn cmd_connect(args: &[&str]) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };

    let dev_path = dev.path.clone();
    let conn = with_state(|state| state.conn());
    let uuid = if args.len() > 2 && !args[2].is_empty() { Some(args[2].to_string()) } else { None };

    spawn_async(async move {
        let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, dev_path.as_str(), DEVICE_IFACE).await;
        if let Ok(p) = proxy {
            let result: Result<zbus::Message, zbus::Error> = if let Some(ref u) = uuid {
                p.call_method("ConnectProfile", &(u.as_str(),)).await
            } else {
                p.call_method("Connect", &()).await
            };
            let profile_str = uuid.as_deref().map(format_connection_profile).unwrap_or_default();
            match result {
                Ok(_) => {
                    bt_shell_printf(format_args!("Connection successful{}\n", profile_str));
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                }
                Err(e) => {
                    bt_shell_printf(format_args!("Failed to connect{}: {}\n", profile_str, e));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        }
    });
}

fn cmd_disconn(args: &[&str]) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };

    let dev_path = dev.path.clone();
    let conn = with_state(|state| state.conn());
    let uuid = if args.len() > 2 && !args[2].is_empty() { Some(args[2].to_string()) } else { None };

    spawn_async(async move {
        let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, dev_path.as_str(), DEVICE_IFACE).await;
        if let Ok(p) = proxy {
            let result: Result<zbus::Message, zbus::Error> = if let Some(ref u) = uuid {
                p.call_method("DisconnectProfile", &(u.as_str(),)).await
            } else {
                p.call_method("Disconnect", &()).await
            };
            let profile_str = uuid.as_deref().map(format_connection_profile).unwrap_or_default();
            match result {
                Ok(_) => {
                    bt_shell_printf(format_args!("Successful disconnected{}\n", profile_str));
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                }
                Err(e) => {
                    bt_shell_printf(format_args!("Failed to disconnect{}: {}\n", profile_str, e));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        }
    });
}

fn cmd_wake(args: &[&str]) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };
    if args.len() < 2 || args[1].eq_ignore_ascii_case(args.first().copied().unwrap_or("")) {
        // Get current value.
        if let Some(val) = dev.get_property("WakeAllowed") {
            print_iter("\t", "WakeAllowed", val);
        }
        return;
    }
    let mut value = false;
    let mut option = Some(String::new());
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    set_property_async(
        dev.path.clone(),
        DEVICE_IFACE.to_string(),
        "WakeAllowed",
        OwnedValue::from(value),
    );
}

fn cmd_bearer(args: &[&str]) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };
    if args.len() < 3 || args[2].is_empty() {
        if let Some(val) = dev.get_property("PreferredBearer") {
            print_iter("\t", "PreferredBearer", val);
        }
        return;
    }
    set_property_async(
        dev.path.clone(),
        DEVICE_IFACE.to_string(),
        "PreferredBearer",
        OwnedValue::from(zbus::zvariant::Str::from(args[2].to_string())),
    );
}

// ---------------------------------------------------------------------------
// GATT command handlers (defined in main.c, delegate to gatt module)
// ---------------------------------------------------------------------------

fn cmd_list_attributes(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    if args.len() > 1 && args[1] == "local" {
        gatt_list_attributes(Some("local"));
        return;
    }
    let dev = find_device_proxy(args);
    let path = dev.map(|d| d.path.clone());
    gatt_list_attributes(path.as_deref());
}

fn cmd_select_attribute(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing attribute argument\n"));
        return;
    }
    let arg = args[1];

    // Check if it's a local attribute path.
    if arg.starts_with("local") || !arg.starts_with('/') {
        gatt_select_local_attribute(arg);
        return;
    }
    let parent = with_state(|s| s.default_attr.clone());
    let parent_info = parent.as_ref().map(|p| gatt::ProxyInfo::new(p.path(), p.interface()));
    if let Some(selected) = gatt_select_attribute(parent_info.as_ref(), arg) {
        set_default_attribute(&selected);
    }
}

fn cmd_attribute_info(args: &[&str]) {
    let attr = with_state(|state| state.default_attr.clone());
    let local = with_state(|state| state.default_local_attr.clone());

    if attr.is_none() && local.is_none() {
        bt_shell_printf(format_args!("No attribute selected\n"));
        return;
    }

    if let Some(ref a) = attr {
        let path = a.path();
        let iface = a.interface();
        bt_shell_printf(format_args!("Attribute {}\n", path));

        // Determine what to show based on the interface.
        let conn = with_state(|state| state.conn());
        let path_owned = path.to_string();
        let iface_owned = iface.to_string();
        spawn_async(async move {
            let proxy =
                zbus::Proxy::new(&conn, BLUEZ_SERVICE, path_owned.clone(), iface_owned.as_str())
                    .await;
            if let Ok(p) = proxy {
                print_property(&p, "UUID").await;
                if iface_owned == GATT_SERVICE_IFACE {
                    print_property(&p, "Primary").await;
                    print_property(&p, "Includes").await;
                } else if iface_owned == GATT_CHAR_IFACE {
                    print_property(&p, "Service").await;
                    print_property(&p, "Value").await;
                    print_property(&p, "Flags").await;
                    print_property(&p, "Notifying").await;
                    print_property(&p, "MTU").await;
                } else if iface_owned == GATT_DESC_IFACE {
                    print_property(&p, "Characteristic").await;
                    print_property(&p, "Value").await;
                    print_property(&p, "Flags").await;
                }
            }
        });
    }
    if let Some(ref _l) = local {
        bt_shell_printf(format_args!("Local attribute {}\n", _l));
    }
    let _ = args;
}

fn cmd_read(args: &[&str]) {
    let local = with_state(|state| state.default_local_attr.clone());
    if let Some(ref path) = local {
        gatt_read_local_attribute(path, args.len(), args);
        return;
    }
    let attr = with_state(|state| state.default_attr.clone());
    match attr {
        Some(a) => {
            let conn = with_state(|state| state.conn());
            let proxy_info = gatt::ProxyInfo::new(a.path(), a.interface());
            let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            spawn_async(async move {
                let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
                gatt_read_attribute(&conn, &proxy_info, refs.len(), &refs).await;
            });
        }
        None => {
            bt_shell_printf(format_args!("No attribute selected\n"));
        }
    }
}

fn cmd_write(args: &[&str]) {
    let local = with_state(|state| state.default_local_attr.clone());
    if let Some(ref path) = local {
        gatt_write_local_attribute(path, args.len(), args);
        return;
    }
    let attr = with_state(|state| state.default_attr.clone());
    match attr {
        Some(a) => {
            let conn = with_state(|state| state.conn());
            let proxy_info = gatt::ProxyInfo::new(a.path(), a.interface());
            let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            spawn_async(async move {
                let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
                gatt_write_attribute(&conn, &proxy_info, refs.len(), &refs).await;
            });
        }
        None => {
            bt_shell_printf(format_args!("No attribute selected\n"));
        }
    }
}

fn cmd_acquire_write(args: &[&str]) {
    let attr = with_state(|state| state.default_attr.clone());
    match attr {
        Some(a) => {
            let conn = with_state(|state| state.conn());
            let proxy_info = gatt::ProxyInfo::new(a.path(), a.interface());
            let arg0 = args.get(1).map(|s| s.to_string());
            spawn_async(async move {
                gatt_acquire_write(&conn, &proxy_info, arg0.as_deref()).await;
            });
        }
        None => bt_shell_printf(format_args!("No attribute selected\n")),
    }
}

fn cmd_release_write(args: &[&str]) {
    let attr = with_state(|state| state.default_attr.clone());
    if let Some(a) = attr {
        let proxy_info = gatt::ProxyInfo::new(a.path(), a.interface());
        let arg0 = args.get(1).map(|s| s.to_string());
        gatt_release_write(&proxy_info, arg0.as_deref());
    } else {
        bt_shell_printf(format_args!("No attribute selected\n"));
    }
}

fn cmd_acquire_notify(args: &[&str]) {
    let attr = with_state(|state| state.default_attr.clone());
    match attr {
        Some(a) => {
            let conn = with_state(|state| state.conn());
            let proxy_info = gatt::ProxyInfo::new(a.path(), a.interface());
            let arg0 = args.get(1).map(|s| s.to_string());
            spawn_async(async move {
                gatt_acquire_notify(&conn, &proxy_info, arg0.as_deref()).await;
            });
        }
        None => bt_shell_printf(format_args!("No attribute selected\n")),
    }
}

fn cmd_release_notify(args: &[&str]) {
    let attr = with_state(|state| state.default_attr.clone());
    if let Some(a) = attr {
        let proxy_info = gatt::ProxyInfo::new(a.path(), a.interface());
        let arg0 = args.get(1).map(|s| s.to_string());
        gatt_release_notify(&proxy_info, arg0.as_deref());
    } else {
        bt_shell_printf(format_args!("No attribute selected\n"));
    }
}

fn cmd_notify(args: &[&str]) {
    let attr = with_state(|state| state.default_attr.clone());
    match attr {
        Some(a) => {
            let mut value = false;
            let mut option = Some(String::new());
            if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
                return;
            }
            let conn = with_state(|state| state.conn());
            let proxy_info = gatt::ProxyInfo::new(a.path(), a.interface());
            spawn_async(async move {
                gatt_notify_attribute(&conn, &proxy_info, value).await;
            });
        }
        None => bt_shell_printf(format_args!("No attribute selected\n")),
    }
}

fn cmd_clone(args: &[&str]) {
    let dev = find_device_proxy(args);
    let attr = with_state(|state| state.default_attr.clone());

    let conn = with_state(|state| state.conn());

    // Build ProxyInfo from the current default attribute or device.
    let attr_info = attr.as_ref().map(|a| gatt::ProxyInfo::new(a.path(), a.interface()));
    let dev_info = dev.map(|d| gatt::ProxyInfo::new(&d.path, DEVICE_IFACE));

    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        if let Some(ref pi) = attr_info {
            gatt_clone_attribute(&conn, pi, refs.len(), &refs).await;
            return;
        }
        if let Some(ref pi) = dev_info {
            gatt_clone_attribute(&conn, pi, refs.len(), &refs).await;
        }
    });
}

fn cmd_register_app(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let attr = with_state(|s| s.default_attr.clone());
    let proxy_info = attr
        .as_ref()
        .map(|a| gatt::ProxyInfo::new(a.path(), a.interface()))
        .unwrap_or_else(|| gatt::ProxyInfo::new("", ""));
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_register_app(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_unregister_app(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let attr = with_state(|s| s.default_attr.clone());
    let proxy_info = attr
        .as_ref()
        .map(|a| gatt::ProxyInfo::new(a.path(), a.interface()))
        .unwrap_or_else(|| gatt::ProxyInfo::new("", ""));
    spawn_async(async move {
        gatt_unregister_app(&conn, &proxy_info).await;
    });
    let _ = args;
}

fn cmd_register_service(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_register_service(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_unregister_service(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_unregister_service(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_register_includes(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_register_include(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_unregister_includes(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_unregister_include(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_register_characteristic(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_register_chrc(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_unregister_characteristic(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_unregister_chrc(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_register_descriptor(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_register_desc(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

fn cmd_unregister_descriptor(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    let proxy_info = gatt::ProxyInfo::new("", "");
    let owned_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    spawn_async(async move {
        let refs: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
        gatt_unregister_desc(&conn, &proxy_info, refs.len(), &refs).await;
    });
}

// ---------------------------------------------------------------------------
// Advertise command handlers
// ---------------------------------------------------------------------------

fn cmd_advertise_uuids(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_uuids(&conn, AD_TYPE_AD, args);
}
fn cmd_advertise_solicit(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_solicit(&conn, AD_TYPE_AD, args);
}
fn cmd_advertise_service(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_service(&conn, AD_TYPE_AD, args);
}
fn cmd_advertise_manufacturer(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_manufacturer(&conn, AD_TYPE_AD, args);
}
fn cmd_advertise_data(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_data(&conn, AD_TYPE_AD, args);
}
fn cmd_advertise_sr_uuids(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_uuids(&conn, AD_TYPE_SRD, args);
}
fn cmd_advertise_sr_solicit(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_solicit(&conn, AD_TYPE_SRD, args);
}
fn cmd_advertise_sr_service(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_service(&conn, AD_TYPE_SRD, args);
}
fn cmd_advertise_sr_manufacturer(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_manufacturer(&conn, AD_TYPE_SRD, args);
}
fn cmd_advertise_sr_data(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    ad_advertise_data(&conn, AD_TYPE_SRD, args);
}
fn cmd_advertise_discoverable(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing on/off argument\n"));
        return;
    }
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    let conn = with_state(|s| s.conn());
    ad_advertise_discoverable(&conn, Some(value));
}
fn cmd_advertise_discoverable_timeout(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing timeout value\n"));
        return;
    }
    let conn = with_state(|s| s.conn());
    match args[1].parse::<u16>() {
        Ok(v) => ad_advertise_discoverable_timeout(&conn, Some(v)),
        Err(_) => bt_shell_printf(format_args!("Invalid argument {}\n", args[1])),
    }
}
fn cmd_advertise_tx_power(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing on/off argument\n"));
        return;
    }
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    let conn = with_state(|s| s.conn());
    ad_advertise_tx_power(&conn, Some(value));
}
fn cmd_advertise_name(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    if args.len() < 2 || args[1].is_empty() {
        ad_advertise_name(&conn, true);
        return;
    }
    let arg = args[1];
    if arg.eq_ignore_ascii_case("on") {
        ad_advertise_name(&conn, true);
    } else if arg.eq_ignore_ascii_case("off") {
        ad_advertise_name(&conn, false);
    } else {
        ad_advertise_local_name(&conn, Some(arg));
    }
}
fn cmd_advertise_appearance(args: &[&str]) {
    let conn = with_state(|s| s.conn());
    if args.len() < 2 || args[1].is_empty() {
        ad_advertise_appearance(&conn, true);
        return;
    }
    let arg = args[1];
    if arg.eq_ignore_ascii_case("on") {
        ad_advertise_appearance(&conn, true);
    } else if arg.eq_ignore_ascii_case("off") {
        ad_advertise_appearance(&conn, false);
    } else {
        match arg.parse::<u16>() {
            Ok(v) => ad_advertise_local_appearance(&conn, Some(v)),
            Err(_) => bt_shell_printf(format_args!("Invalid argument {}\n", arg)),
        }
    }
}
fn cmd_advertise_duration(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing duration value\n"));
        return;
    }
    let conn = with_state(|s| s.conn());
    match args[1].parse::<u16>() {
        Ok(v) => ad_advertise_duration(&conn, Some(v)),
        Err(_) => bt_shell_printf(format_args!("Invalid argument {}\n", args[1])),
    }
}
fn cmd_advertise_timeout(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing timeout value\n"));
        return;
    }
    let conn = with_state(|s| s.conn());
    match args[1].parse::<u16>() {
        Ok(v) => ad_advertise_timeout(&conn, Some(v)),
        Err(_) => bt_shell_printf(format_args!("Invalid argument {}\n", args[1])),
    }
}
fn cmd_advertise_secondary(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing secondary channel\n"));
        return;
    }
    let conn = with_state(|s| s.conn());
    ad_advertise_secondary(&conn, Some(args[1]));
}
fn cmd_advertise_interval(args: &[&str]) {
    if args.len() < 3 || args[1].is_empty() || args[2].is_empty() {
        bt_shell_printf(format_args!("Usage: interval <min> <max>\n"));
        return;
    }
    let min: u32 = match args[1].parse() {
        Ok(v) if (20..=10485).contains(&v) => v,
        _ => {
            bt_shell_printf(format_args!("Invalid min interval (20-10485)\n"));
            return;
        }
    };
    let max: u32 = match args[2].parse() {
        Ok(v) if (20..=10485).contains(&v) => v,
        _ => {
            bt_shell_printf(format_args!("Invalid max interval (20-10485)\n"));
            return;
        }
    };
    if min > max {
        bt_shell_printf(format_args!("Min interval must be <= max interval\n"));
        return;
    }
    let conn = with_state(|s| s.conn());
    ad_advertise_interval(&conn, Some(min), Some(max));
}
fn cmd_advertise_rsi(args: &[&str]) {
    let mut value = false;
    let mut option = Some(String::new());
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing on/off argument\n"));
        return;
    }
    if !parse_argument(args, None, Some("on/off"), &mut value, &mut option) {
        return;
    }
    let conn = with_state(|s| s.conn());
    ad_advertise_rsi(&conn, Some(value));
}

fn ad_clear_uuids() {
    let conn = with_state(|s| s.conn());
    ad_disable_uuids(&conn, AD_TYPE_AD);
}
fn ad_clear_solicit() {
    let conn = with_state(|s| s.conn());
    ad_disable_solicit(&conn, AD_TYPE_AD);
}
fn ad_clear_service() {
    let conn = with_state(|s| s.conn());
    ad_disable_service(&conn, AD_TYPE_AD);
}
fn ad_clear_manufacturer() {
    let conn = with_state(|s| s.conn());
    ad_disable_manufacturer(&conn, AD_TYPE_AD);
}
fn ad_clear_data() {
    let conn = with_state(|s| s.conn());
    ad_disable_data(&conn, AD_TYPE_AD);
}
fn ad_clear_sr_uuids() {
    let conn = with_state(|s| s.conn());
    ad_disable_uuids(&conn, AD_TYPE_SRD);
}
fn ad_clear_sr_solicit() {
    let conn = with_state(|s| s.conn());
    ad_disable_solicit(&conn, AD_TYPE_SRD);
}
fn ad_clear_sr_service() {
    let conn = with_state(|s| s.conn());
    ad_disable_service(&conn, AD_TYPE_SRD);
}
fn ad_clear_sr_manufacturer() {
    let conn = with_state(|s| s.conn());
    ad_disable_manufacturer(&conn, AD_TYPE_SRD);
}
fn ad_clear_sr_data() {
    let conn = with_state(|s| s.conn());
    ad_disable_data(&conn, AD_TYPE_SRD);
}
fn ad_clear_tx_power() {
    let conn = with_state(|s| s.conn());
    ad_advertise_tx_power(&conn, Some(false));
}
fn ad_clear_name() {
    let conn = with_state(|s| s.conn());
    ad_advertise_name(&conn, false);
}
fn ad_clear_appearance() {
    let conn = with_state(|s| s.conn());
    ad_advertise_appearance(&conn, false);
}
fn ad_clear_duration() {
    let conn = with_state(|s| s.conn());
    ad_advertise_duration(&conn, Some(0));
}
fn ad_clear_timeout() {
    let conn = with_state(|s| s.conn());
    ad_advertise_timeout(&conn, Some(0));
}
fn ad_clear_secondary() {
    let conn = with_state(|s| s.conn());
    ad_advertise_secondary(&conn, Some(""));
}
fn ad_clear_interval() {
    let conn = with_state(|s| s.conn());
    ad_advertise_interval(&conn, Some(0), Some(0));
}

static AD_CLEAR: &[ClearEntry] = &[
    ClearEntry { name: "uuids", clear: ad_clear_uuids },
    ClearEntry { name: "solicit", clear: ad_clear_solicit },
    ClearEntry { name: "service", clear: ad_clear_service },
    ClearEntry { name: "manufacturer", clear: ad_clear_manufacturer },
    ClearEntry { name: "data", clear: ad_clear_data },
    ClearEntry { name: "sr-uuids", clear: ad_clear_sr_uuids },
    ClearEntry { name: "sr-solicit", clear: ad_clear_sr_solicit },
    ClearEntry { name: "sr-service", clear: ad_clear_sr_service },
    ClearEntry { name: "sr-manufacturer", clear: ad_clear_sr_manufacturer },
    ClearEntry { name: "sr-data", clear: ad_clear_sr_data },
    ClearEntry { name: "tx-power", clear: ad_clear_tx_power },
    ClearEntry { name: "name", clear: ad_clear_name },
    ClearEntry { name: "appearance", clear: ad_clear_appearance },
    ClearEntry { name: "duration", clear: ad_clear_duration },
    ClearEntry { name: "timeout", clear: ad_clear_timeout },
    ClearEntry { name: "secondary", clear: ad_clear_secondary },
    ClearEntry { name: "interval", clear: ad_clear_interval },
];

fn cmd_ad_clear(args: &[&str]) {
    let name = if args.len() > 1 && !args[1].is_empty() { args[1] } else { "all" };
    data_clear(AD_CLEAR, name);
}

// ---------------------------------------------------------------------------
// Advertisement Monitor command handlers
// ---------------------------------------------------------------------------

fn cmd_adv_monitor_print_usage(args: &[&str]) {
    let _ = args;
    bt_shell_printf(format_args!("Usage:\n"));
    bt_shell_printf(format_args!("  set-rssi-threshold <high_threshold> <low_threshold>\n"));
    bt_shell_printf(format_args!("  set-rssi-timeout <low_timeout> <high_timeout>\n"));
    bt_shell_printf(format_args!("  set-rssi-sampling-period <sampling_period>\n"));
    bt_shell_printf(format_args!("  add-or-pattern <type> <offset> <content>\n"));
    bt_shell_printf(format_args!("  get-pattern <monitor_id>\n"));
    bt_shell_printf(format_args!("  remove-pattern <monitor_id>\n"));
    bt_shell_printf(format_args!("  get-supported-info\n"));
}

fn cmd_adv_monitor_set_rssi_threshold(args: &[&str]) {
    adv_monitor::adv_monitor_set_rssi_threshold(args);
}

fn cmd_adv_monitor_set_rssi_timeout(args: &[&str]) {
    adv_monitor::adv_monitor_set_rssi_timeout(args);
}

fn cmd_adv_monitor_set_rssi_sampling_period(args: &[&str]) {
    adv_monitor::adv_monitor_set_rssi_sampling_period(args);
}

fn cmd_adv_monitor_add_or_monitor(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    adv_monitor::adv_monitor_add_monitor(&conn, args);
}

fn cmd_adv_monitor_print_monitor(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    adv_monitor::adv_monitor_print_monitor(&conn, args);
}

fn cmd_adv_monitor_remove_monitor(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    adv_monitor::adv_monitor_remove_monitor(&conn, args);
}

fn cmd_adv_monitor_get_supported_info(args: &[&str]) {
    let conn = with_state(|state| state.conn());
    adv_monitor::adv_monitor_get_supported_info(&conn, args);
}

// ---------------------------------------------------------------------------
// LE/BREDR Bearer submenu command handlers
// ---------------------------------------------------------------------------

fn print_le_properties(dev: &CachedProxy) {
    let bearers = with_state(|state| {
        state.get_default_ctrl().map(|c| {
            c.bearers
                .iter()
                .filter(|b| b.path == dev.path && b.interface == BEARER_LE_IFACE)
                .cloned()
                .collect::<Vec<_>>()
        })
    });
    if let Some(bearers) = bearers {
        for b in &bearers {
            for prop in &["Paired", "Bonded", "Connected"] {
                if let Some(val) = b.get_property(prop) {
                    print_iter("\t", prop, val);
                }
            }
        }
    }
}

fn print_bredr_properties(dev: &CachedProxy) {
    let bearers = with_state(|state| {
        state.get_default_ctrl().map(|c| {
            c.bearers
                .iter()
                .filter(|b| b.path == dev.path && b.interface == BEARER_BREDR_IFACE)
                .cloned()
                .collect::<Vec<_>>()
        })
    });
    if let Some(bearers) = bearers {
        for b in &bearers {
            for prop in &["Paired", "Bonded", "Connected"] {
                if let Some(val) = b.get_property(prop) {
                    print_iter("\t", prop, val);
                }
            }
        }
    }
}

fn cmd_list_le(args: &[&str]) {
    let _ = args;
    if !check_default_ctrl() {
        return;
    }
    with_state(|state| {
        let ctrl = match state.get_default_ctrl() {
            Some(c) => c,
            None => return,
        };
        for dev in &ctrl.devices {
            let has_le =
                ctrl.bearers.iter().any(|b| b.path == dev.path && b.interface == BEARER_LE_IFACE);
            if has_le {
                print_device(dev, None);
            }
        }
    });
}

fn cmd_list_bredr(args: &[&str]) {
    let _ = args;
    if !check_default_ctrl() {
        return;
    }
    with_state(|state| {
        let ctrl = match state.get_default_ctrl() {
            Some(c) => c,
            None => return,
        };
        for dev in &ctrl.devices {
            let has_bredr = ctrl
                .bearers
                .iter()
                .any(|b| b.path == dev.path && b.interface == BEARER_BREDR_IFACE);
            if has_bredr {
                print_device(dev, None);
            }
        }
    });
}

fn cmd_show_le(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    if args.len() > 1 && !args[1].is_empty() {
        let dev = find_device_proxy(args);
        if let Some(d) = dev {
            let address = d.get_str("Address").unwrap_or_default();
            bt_shell_printf(format_args!("LE Device {}\n", address));
            print_le_properties(&d);
        } else {
            bt_shell_printf(format_args!("Device {} not available\n", args[1]));
        }
        return;
    }
    with_state(|state| {
        let ctrl = match state.get_default_ctrl() {
            Some(c) => c,
            None => return,
        };
        for dev in &ctrl.devices {
            let has_le =
                ctrl.bearers.iter().any(|b| b.path == dev.path && b.interface == BEARER_LE_IFACE);
            if has_le {
                let address = dev.get_str("Address").unwrap_or_default();
                bt_shell_printf(format_args!("LE Device {}\n", address));
                print_le_properties(dev);
            }
        }
    });
}

fn cmd_show_bredr(args: &[&str]) {
    if !check_default_ctrl() {
        return;
    }
    if args.len() > 1 && !args[1].is_empty() {
        let dev = find_device_proxy(args);
        if let Some(d) = dev {
            let address = d.get_str("Address").unwrap_or_default();
            bt_shell_printf(format_args!("BREDR Device {}\n", address));
            print_bredr_properties(&d);
        } else {
            bt_shell_printf(format_args!("Device {} not available\n", args[1]));
        }
        return;
    }
    with_state(|state| {
        let ctrl = match state.get_default_ctrl() {
            Some(c) => c,
            None => return,
        };
        for dev in &ctrl.devices {
            let has_bredr = ctrl
                .bearers
                .iter()
                .any(|b| b.path == dev.path && b.interface == BEARER_BREDR_IFACE);
            if has_bredr {
                let address = dev.get_str("Address").unwrap_or_default();
                bt_shell_printf(format_args!("BREDR Device {}\n", address));
                print_bredr_properties(dev);
            }
        }
    });
}

fn cmd_bearer_method_handler(args: &[&str], bearer_iface: &'static str, method: &'static str) {
    let dev = match find_device_proxy(args) {
        Some(d) => d,
        None => {
            bt_shell_printf(format_args!("Missing device address argument\n"));
            return;
        }
    };
    let dev_path = dev.path.clone();
    let conn = with_state(|state| state.conn());
    spawn_async(async move {
        let proxy = zbus::Proxy::new(&conn, BLUEZ_SERVICE, dev_path.as_str(), bearer_iface).await;
        if let Ok(p) = proxy {
            let result: Result<zbus::Message, zbus::Error> = p.call_method(method, &()).await;
            match result {
                Ok(_) => {
                    bt_shell_printf(format_args!("{} successful\n", method));
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                }
                Err(e) => {
                    bt_shell_printf(format_args!("Failed to {}: {}\n", method, e));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        }
    });
}

fn cmd_connect_le(args: &[&str]) {
    cmd_bearer_method_handler(args, BEARER_LE_IFACE, "Connect");
}
fn cmd_disconnect_le(args: &[&str]) {
    cmd_bearer_method_handler(args, BEARER_LE_IFACE, "Disconnect");
}
fn cmd_connect_bredr(args: &[&str]) {
    cmd_bearer_method_handler(args, BEARER_BREDR_IFACE, "Connect");
}
fn cmd_disconnect_bredr(args: &[&str]) {
    cmd_bearer_method_handler(args, BEARER_BREDR_IFACE, "Disconnect");
}

// ---------------------------------------------------------------------------
// Tab completion generators
// ---------------------------------------------------------------------------

fn generic_generator(
    text: &str,
    state: i32,
    proxies: &[CachedProxy],
    property: &str,
) -> Option<String> {
    let mut count = 0i32;
    for p in proxies {
        if let Some(val) = p.get_str(property) {
            if val.to_lowercase().starts_with(&text.to_lowercase()) {
                if count == state {
                    return Some(val);
                }
                count += 1;
            }
        }
    }
    None
}

fn ctrl_generator(text: &str, state: i32) -> Option<String> {
    with_state(|s| {
        let proxies: Vec<CachedProxy> = s.ctrl_list.iter().map(|a| a.proxy.clone()).collect();
        generic_generator(text, state, &proxies, "Address")
    })
}

fn dev_generator(text: &str, state: i32) -> Option<String> {
    with_state(|s| {
        let devs = s.get_default_ctrl().map(|c| c.devices.clone()).unwrap_or_default();
        generic_generator(text, state, &devs, "Address")
    })
}

fn set_generator(text: &str, state: i32) -> Option<String> {
    let mut count = 0i32;
    with_state(|s| {
        let sets = s.get_default_ctrl().map(|c| c.sets.clone()).unwrap_or_default();
        for set in &sets {
            if set.path.to_lowercase().starts_with(&text.to_lowercase()) {
                if count == state {
                    return Some(set.path.clone());
                }
                count += 1;
            }
        }
        None
    })
}

fn dev_set_generator(text: &str, state: i32) -> Option<String> {
    if let Some(v) = dev_generator(text, state) {
        return Some(v);
    }
    // Count how many device completions there were to offset.
    let dev_count = with_state(|s| {
        s.get_default_ctrl()
            .map(|c| {
                c.devices
                    .iter()
                    .filter(|d| {
                        d.get_str("Address")
                            .is_some_and(|a| a.to_lowercase().starts_with(&text.to_lowercase()))
                    })
                    .count() as i32
            })
            .unwrap_or(0)
    });
    set_generator(text, state - dev_count)
}

fn bearer_dev_generator_with_iface(text: &str, state: i32, iface: &str) -> Option<String> {
    let mut count = 0i32;
    with_state(|s| {
        let ctrl = s.get_default_ctrl()?;
        for dev in &ctrl.devices {
            let has = ctrl.bearers.iter().any(|b| b.path == dev.path && b.interface == iface);
            if !has {
                continue;
            }
            if let Some(addr) = dev.get_str("Address") {
                if addr.to_lowercase().starts_with(&text.to_lowercase()) {
                    if count == state {
                        return Some(addr);
                    }
                    count += 1;
                }
            }
        }
        None
    })
}

fn le_dev_generator(text: &str, state: i32) -> Option<String> {
    bearer_dev_generator_with_iface(text, state, BEARER_LE_IFACE)
}

fn bredr_dev_generator(text: &str, state: i32) -> Option<String> {
    bearer_dev_generator_with_iface(text, state, BEARER_BREDR_IFACE)
}

fn attribute_generator(text: &str, state: i32) -> Option<String> {
    gatt_attribute_generator(text, state)
}

fn argument_generator_from(text: &str, state: i32, options: &[&str]) -> Option<String> {
    let mut count = 0i32;
    for opt in options {
        if opt.to_lowercase().starts_with(&text.to_lowercase()) {
            if count == state {
                return Some(opt.to_string());
            }
            count += 1;
        }
    }
    None
}

fn capability_generator(text: &str, state: i32) -> Option<String> {
    argument_generator_from(text, state, AGENT_ARGUMENTS)
}

fn scan_generator(text: &str, state: i32) -> Option<String> {
    argument_generator_from(text, state, SCAN_ARGUMENTS)
}

fn ad_generator(text: &str, state: i32) -> Option<String> {
    argument_generator_from(text, state, AD_ARGUMENTS)
}

fn device_argument_generator(text: &str, state: i32) -> Option<String> {
    argument_generator_from(text, state, DEVICE_ARGUMENTS)
}

fn filter_clear_generator(text: &str, state: i32) -> Option<String> {
    let names: Vec<&str> = FILTER_CLEAR.iter().map(|e| e.name).collect();
    argument_generator_from(text, state, &names)
}

fn ad_clear_generator(text: &str, state: i32) -> Option<String> {
    let names: Vec<&str> = AD_CLEAR.iter().map(|e| e.name).collect();
    argument_generator_from(text, state, &names)
}

// ---------------------------------------------------------------------------
// Menu definitions
// ---------------------------------------------------------------------------

static MAIN_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "list",
        arg: None,
        func: cmd_list,
        desc: "List available controllers",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "show",
        arg: Some("[ctrl]"),
        func: cmd_show,
        desc: "Controller information",
        r#gen: Some(ctrl_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "select",
        arg: Some("<ctrl>"),
        func: cmd_select,
        desc: "Select default controller",
        r#gen: Some(ctrl_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "devices",
        arg: Some("[attr]"),
        func: cmd_devices,
        desc: "List available devices, with optional property as filter",
        r#gen: Some(device_argument_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "system-alias",
        arg: Some("<name>"),
        func: cmd_system_alias,
        desc: "Set controller alias",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "reset-alias",
        arg: None,
        func: cmd_reset_alias,
        desc: "Reset controller alias",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "power",
        arg: Some("<on/off>"),
        func: cmd_power,
        desc: "Set controller power",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "pairable",
        arg: Some("<on/off>"),
        func: cmd_pairable,
        desc: "Set controller pairable mode",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "discoverable",
        arg: Some("<on/off>"),
        func: cmd_discoverable,
        desc: "Set controller discoverable mode",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "discoverable-timeout",
        arg: Some("[value]"),
        func: cmd_discoverable_timeout,
        desc: "Set discoverable timeout",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "agent",
        arg: Some("<on/off/capability>"),
        func: cmd_agent,
        desc: "Enable/disable agent with given capability",
        r#gen: Some(capability_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "default-agent",
        arg: None,
        func: cmd_default_agent,
        desc: "Set agent as the default one",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "advertise",
        arg: Some("<on/off/type>"),
        func: cmd_advertise,
        desc: "Enable/disable advertising with given type",
        r#gen: Some(ad_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "set-alias",
        arg: Some("<alias>"),
        func: cmd_set_alias,
        desc: "Set device alias",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "scan",
        arg: Some("<on/off/bredr/le>"),
        func: cmd_scan,
        desc: "Scan for devices",
        r#gen: Some(scan_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "info",
        arg: Some("[dev/set]"),
        func: cmd_info,
        desc: "Device/Set information",
        r#gen: Some(dev_set_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "pair",
        arg: Some("[dev]"),
        func: cmd_pair,
        desc: "Pair with device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "cancel-pairing",
        arg: Some("[dev]"),
        func: cmd_cancel_pairing,
        desc: "Cancel pairing with device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "trust",
        arg: Some("[dev]"),
        func: cmd_trust,
        desc: "Trust device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "untrust",
        arg: Some("[dev]"),
        func: cmd_untrust,
        desc: "Untrust device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "block",
        arg: Some("[dev]"),
        func: cmd_block,
        desc: "Block device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unblock",
        arg: Some("[dev]"),
        func: cmd_unblock,
        desc: "Unblock device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "remove",
        arg: Some("<dev>"),
        func: cmd_remove,
        desc: "Remove device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "connect",
        arg: Some("<dev> [uuid]"),
        func: cmd_connect,
        desc: "Connect device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "disconnect",
        arg: Some("[dev]"),
        func: cmd_disconn,
        desc: "Disconnect device",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "wake",
        arg: Some("[dev] [on/off]"),
        func: cmd_wake,
        desc: "Get/Set device wake support",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "bearer",
        arg: Some("[dev] [bearer]"),
        func: cmd_bearer,
        desc: "Get/Set device preferred bearer",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
];

static MAIN_MENU: BtShellMenu =
    BtShellMenu { name: "main", desc: None, pre_run: None, entries: MAIN_MENU_ENTRIES };

static ADVERTISE_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "uuids",
        arg: Some("[uuid1 uuid2 ...]"),
        func: cmd_advertise_uuids,
        desc: "Set/Get advertise uuids",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "solicit",
        arg: Some("[uuid1 uuid2 ...]"),
        func: cmd_advertise_solicit,
        desc: "Set/Get advertise solicit uuids",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "service",
        arg: Some("[uuid] [data=xx xx ...]"),
        func: cmd_advertise_service,
        desc: "Set/Get advertise service data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "manufacturer",
        arg: Some("[id] [data=xx xx ...]"),
        func: cmd_advertise_manufacturer,
        desc: "Set/Get advertise manufacturer data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "data",
        arg: Some("[type] [data=xx xx ...]"),
        func: cmd_advertise_data,
        desc: "Set/Get advertise data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "sr-uuids",
        arg: Some("[uuid1 uuid2 ...]"),
        func: cmd_advertise_sr_uuids,
        desc: "Set/Get scan response uuids",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "sr-solicit",
        arg: Some("[uuid1 uuid2 ...]"),
        func: cmd_advertise_sr_solicit,
        desc: "Set/Get scan response solicit uuids",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "sr-service",
        arg: Some("[uuid] [data=xx xx ...]"),
        func: cmd_advertise_sr_service,
        desc: "Set/Get scan response service data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "sr-manufacturer",
        arg: Some("[id] [data=xx xx ...]"),
        func: cmd_advertise_sr_manufacturer,
        desc: "Set/Get scan response manufacturer data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "sr-data",
        arg: Some("[type] [data=xx xx ...]"),
        func: cmd_advertise_sr_data,
        desc: "Set/Get scan response data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "discoverable",
        arg: Some("[on/off]"),
        func: cmd_advertise_discoverable,
        desc: "Set/Get advertise discoverable",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "discoverable-timeout",
        arg: Some("[seconds]"),
        func: cmd_advertise_discoverable_timeout,
        desc: "Set/Get advertise discoverable timeout",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "tx-power",
        arg: Some("[on/off]"),
        func: cmd_advertise_tx_power,
        desc: "Show/Enable/Disable TX power to be advertised",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "name",
        arg: Some("[on/off/name]"),
        func: cmd_advertise_name,
        desc: "Configure local name to be advertised",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "appearance",
        arg: Some("[on/off/value]"),
        func: cmd_advertise_appearance,
        desc: "Configure custom appearance to be advertised",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "duration",
        arg: Some("[seconds]"),
        func: cmd_advertise_duration,
        desc: "Set/Get advertise duration",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "timeout",
        arg: Some("[seconds]"),
        func: cmd_advertise_timeout,
        desc: "Set/Get advertise timeout",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "secondary",
        arg: Some("[1M/2M/Coded]"),
        func: cmd_advertise_secondary,
        desc: "Set/Get advertise secondary channel",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "interval",
        arg: Some("<min> <max>"),
        func: cmd_advertise_interval,
        desc: "Set advertise interval",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "rsi",
        arg: Some("[on/off]"),
        func: cmd_advertise_rsi,
        desc: "Show/Enable/Disable RSI to be advertised",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "clear",
        arg: Some("[data]"),
        func: cmd_ad_clear,
        desc: "Clear advertise config",
        r#gen: Some(ad_clear_generator),
        disp: None,
        exists: None,
    },
];

static ADVERTISE_MENU: BtShellMenu = BtShellMenu {
    name: "advertise",
    desc: Some("Advertise Options Submenu"),
    pre_run: None,
    entries: ADVERTISE_MENU_ENTRIES,
};

static ADV_MONITOR_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "set-rssi-threshold",
        arg: Some("<high_threshold> <low_threshold>"),
        func: cmd_adv_monitor_set_rssi_threshold,
        desc: "Set RSSI threshold parameter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "set-rssi-timeout",
        arg: Some("<low_timeout> <high_timeout>"),
        func: cmd_adv_monitor_set_rssi_timeout,
        desc: "Set RSSI timeout parameter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "set-rssi-sampling-period",
        arg: Some("<sampling_period>"),
        func: cmd_adv_monitor_set_rssi_sampling_period,
        desc: "Set RSSI sampling period parameter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-or-pattern",
        arg: Some("<type> <offset> <content>"),
        func: cmd_adv_monitor_add_or_monitor,
        desc: "Register advertisement monitor with an OR pattern",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "get-pattern",
        arg: Some("<monitor_id>"),
        func: cmd_adv_monitor_print_monitor,
        desc: "Get advertisement monitor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "remove-pattern",
        arg: Some("<monitor_id>"),
        func: cmd_adv_monitor_remove_monitor,
        desc: "Remove advertisement monitor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "get-supported-info",
        arg: None,
        func: cmd_adv_monitor_get_supported_info,
        desc: "Get advertisement monitor supported features and monitors",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "print-usage",
        arg: None,
        func: cmd_adv_monitor_print_usage,
        desc: "Print advertisement monitor usage",
        r#gen: None,
        disp: None,
        exists: None,
    },
];

static ADV_MONITOR_MENU: BtShellMenu = BtShellMenu {
    name: "monitor",
    desc: Some("Advertisement Monitor Options Submenu"),
    pre_run: None,
    entries: ADV_MONITOR_MENU_ENTRIES,
};

static SCAN_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "uuids",
        arg: Some("[all/uuid1 uuid2 ...]"),
        func: cmd_scan_filter_uuids,
        desc: "Set/Get UUIDs filter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "rssi",
        arg: Some("[rssi]"),
        func: cmd_scan_filter_rssi,
        desc: "Set/Get RSSI filter, and target pathloss",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "pathloss",
        arg: Some("[pathloss]"),
        func: cmd_scan_filter_pathloss,
        desc: "Set/Get Pathloss filter, and target RSSI",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "transport",
        arg: Some("[transport]"),
        func: cmd_scan_filter_transport,
        desc: "Set/Get transport filter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "duplicate-data",
        arg: Some("[on/off]"),
        func: cmd_scan_filter_duplicate_data,
        desc: "Set/Get duplicate data filter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "discoverable",
        arg: Some("[on/off]"),
        func: cmd_scan_filter_discoverable,
        desc: "Set/Get discoverable filter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "pattern",
        arg: Some("[value]"),
        func: cmd_scan_filter_pattern,
        desc: "Set/Get pattern filter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "auto-connect",
        arg: Some("[on/off]"),
        func: cmd_scan_filter_auto_connect,
        desc: "Set/Get auto-connect filter",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "clear",
        arg: Some("[filter]"),
        func: cmd_scan_filter_clear,
        desc: "Clear discovery filter",
        r#gen: Some(filter_clear_generator),
        disp: None,
        exists: None,
    },
];

static SCAN_MENU: BtShellMenu = BtShellMenu {
    name: "scan",
    desc: Some("Scan Options Submenu"),
    pre_run: None,
    entries: SCAN_MENU_ENTRIES,
};

static GATT_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "list-attributes",
        arg: Some("[dev/local]"),
        func: cmd_list_attributes,
        desc: "List attributes",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "select-attribute",
        arg: Some("<attribute/UUID>"),
        func: cmd_select_attribute,
        desc: "Select attribute",
        r#gen: Some(attribute_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "attribute-info",
        arg: Some("[attribute/UUID]"),
        func: cmd_attribute_info,
        desc: "Select attribute",
        r#gen: Some(attribute_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "read",
        arg: Some("[offset]"),
        func: cmd_read,
        desc: "Read attribute value",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "write",
        arg: Some("<data=xx xx ...> [offset] [type]"),
        func: cmd_write,
        desc: "Write attribute value",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "acquire-write",
        arg: None,
        func: cmd_acquire_write,
        desc: "Acquire Write file descriptor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "release-write",
        arg: None,
        func: cmd_release_write,
        desc: "Release Write file descriptor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "acquire-notify",
        arg: None,
        func: cmd_acquire_notify,
        desc: "Acquire Notify file descriptor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "release-notify",
        arg: None,
        func: cmd_release_notify,
        desc: "Release Notify file descriptor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "notify",
        arg: Some("<on/off>"),
        func: cmd_notify,
        desc: "Notify attribute value",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "clone",
        arg: Some("[dev/attribute/UUID]"),
        func: cmd_clone,
        desc: "Clone a device or attribute",
        r#gen: Some(dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "register-application",
        arg: Some("[UUID ...]"),
        func: cmd_register_app,
        desc: "Register profile to connect",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unregister-application",
        arg: None,
        func: cmd_unregister_app,
        desc: "Unregister profile",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "register-service",
        arg: Some("<UUID> [handle]"),
        func: cmd_register_service,
        desc: "Register application service",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unregister-service",
        arg: Some("<UUID/object>"),
        func: cmd_unregister_service,
        desc: "Unregister application service",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "register-includes",
        arg: Some("<UUID>"),
        func: cmd_register_includes,
        desc: "Register as Included service in",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unregister-includes",
        arg: Some("<UUID>"),
        func: cmd_unregister_includes,
        desc: "Unregister Included service",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "register-characteristic",
        arg: Some("<UUID> <Flags=read,write,notify...> [handle]"),
        func: cmd_register_characteristic,
        desc: "Register application characteristic",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unregister-characteristic",
        arg: Some("<UUID/object>"),
        func: cmd_unregister_characteristic,
        desc: "Unregister application characteristic",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "register-descriptor",
        arg: Some("<UUID> <Flags=read,write...> [handle]"),
        func: cmd_register_descriptor,
        desc: "Register application descriptor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unregister-descriptor",
        arg: Some("<UUID/object>"),
        func: cmd_unregister_descriptor,
        desc: "Unregister application descriptor",
        r#gen: None,
        disp: None,
        exists: None,
    },
];

static GATT_MENU: BtShellMenu = BtShellMenu {
    name: "gatt",
    desc: Some("Generic Attribute Submenu"),
    pre_run: None,
    entries: GATT_MENU_ENTRIES,
};

static LE_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "list",
        arg: None,
        func: cmd_list_le,
        desc: "List LE devices",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "show",
        arg: Some("[dev]"),
        func: cmd_show_le,
        desc: "LE Device information",
        r#gen: Some(le_dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "connect",
        arg: Some("[dev]"),
        func: cmd_connect_le,
        desc: "Connect LE device",
        r#gen: Some(le_dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "disconnect",
        arg: Some("[dev]"),
        func: cmd_disconnect_le,
        desc: "Disconnect LE device",
        r#gen: Some(le_dev_generator),
        disp: None,
        exists: None,
    },
];

static LE_MENU: BtShellMenu =
    BtShellMenu { name: "le", desc: Some("LE Submenu"), pre_run: None, entries: LE_MENU_ENTRIES };

static BREDR_MENU_ENTRIES: &[BtShellMenuEntry] = &[
    BtShellMenuEntry {
        cmd: "list",
        arg: None,
        func: cmd_list_bredr,
        desc: "List BR/EDR devices",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "show",
        arg: Some("[dev]"),
        func: cmd_show_bredr,
        desc: "BR/EDR Device information",
        r#gen: Some(bredr_dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "connect",
        arg: Some("[dev]"),
        func: cmd_connect_bredr,
        desc: "Connect BR/EDR device",
        r#gen: Some(bredr_dev_generator),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "disconnect",
        arg: Some("[dev]"),
        func: cmd_disconnect_bredr,
        desc: "Disconnect BR/EDR device",
        r#gen: Some(bredr_dev_generator),
        disp: None,
        exists: None,
    },
];

static BREDR_MENU: BtShellMenu = BtShellMenu {
    name: "bredr",
    desc: Some("BR/EDR Submenu"),
    pre_run: None,
    entries: BREDR_MENU_ENTRIES,
};

// ---------------------------------------------------------------------------
// D-Bus ObjectManager integration
// ---------------------------------------------------------------------------

async fn process_managed_objects(conn: &Connection) {
    let proxy = match zbus::Proxy::new(
        conn,
        BLUEZ_SERVICE,
        BLUEZ_ROOT_PATH,
        "org.freedesktop.DBus.ObjectManager",
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            debug!("Failed to create ObjectManager proxy: {}", e);
            return;
        }
    };

    let result: Result<
        HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>,
        zbus::Error,
    > = proxy.call_method("GetManagedObjects", &()).await.and_then(|msg| msg.body().deserialize());

    match result {
        Ok(objects) => {
            for (path, ifaces) in &objects {
                for (iface, props) in ifaces {
                    proxy_added(path.as_str(), iface, props.clone());
                }
            }
        }
        Err(e) => {
            debug!("GetManagedObjects failed: {}", e);
        }
    }
}

async fn run_signal_loop(conn: Connection) {
    use futures::StreamExt as _;

    let rule_added = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(BLUEZ_SERVICE)
        .expect("valid sender")
        .interface("org.freedesktop.DBus.ObjectManager")
        .expect("valid iface")
        .member("InterfacesAdded")
        .expect("valid member")
        .build();

    let rule_removed = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(BLUEZ_SERVICE)
        .expect("valid sender")
        .interface("org.freedesktop.DBus.ObjectManager")
        .expect("valid iface")
        .member("InterfacesRemoved")
        .expect("valid member")
        .build();

    let rule_props = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(BLUEZ_SERVICE)
        .expect("valid sender")
        .interface("org.freedesktop.DBus.Properties")
        .expect("valid iface")
        .member("PropertiesChanged")
        .expect("valid member")
        .build();

    // Subscribe to signals.
    let proxy = match zbus::Proxy::new(
        &conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create DBus proxy: {}", e);
            return;
        }
    };

    // Add match rules.
    let _ = proxy.call_method("AddMatch", &(rule_added.to_string(),)).await;
    let _ = proxy.call_method("AddMatch", &(rule_removed.to_string(),)).await;
    let _ = proxy.call_method("AddMatch", &(rule_props.to_string(),)).await;

    let mut stream = zbus::MessageStream::from(&conn);
    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(_) => continue,
        };
        let header = msg.header();
        let member = match header.member() {
            Some(m) => m.to_string(),
            None => continue,
        };
        let iface = header.interface().map(|i| i.to_string()).unwrap_or_default();
        let path = header.path().map(|p| p.to_string()).unwrap_or_default();

        if iface == "org.freedesktop.DBus.ObjectManager" {
            if member == "InterfacesAdded" {
                let body = msg.body();
                let result: Result<
                    (OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>),
                    _,
                > = body.deserialize();
                if let Ok((obj_path, ifaces_props)) = result {
                    for (iface_name, props) in ifaces_props {
                        proxy_added(obj_path.as_str(), &iface_name, props);
                    }
                }
            } else if member == "InterfacesRemoved" {
                let body = msg.body();
                let result: Result<(OwnedObjectPath, Vec<String>), _> = body.deserialize();
                if let Ok((obj_path, ifaces)) = result {
                    for iface_name in &ifaces {
                        proxy_removed(obj_path.as_str(), iface_name);
                    }
                }
            }
        } else if iface == "org.freedesktop.DBus.Properties" && member == "PropertiesChanged" {
            let body = msg.body();
            let result: Result<(String, HashMap<String, OwnedValue>, Vec<String>), _> =
                body.deserialize();
            if let Ok((iface_name, changed, _invalidated)) = result {
                for (prop_name, value) in &changed {
                    property_changed(&path, &iface_name, prop_name, value);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// main() entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    // Initialize logging.
    tracing_subscriber::fmt::init();

    // Parse command-line options.
    let args_vec: Vec<String> = std::env::args().collect();
    let mut auto_register_agent: Option<String> = None;
    let mut auto_register_endpoints = false;

    let mut i = 1;
    while i < args_vec.len() {
        match args_vec[i].as_str() {
            "-a" | "--agent" => {
                if i + 1 < args_vec.len() {
                    auto_register_agent = Some(args_vec[i + 1].clone());
                    i += 1;
                } else {
                    auto_register_agent = Some(String::new());
                }
            }
            "-e" | "--endpoints" => {
                auto_register_endpoints = true;
            }
            _ => {}
        }
        i += 1;
    }

    // Build the tokio runtime — current_thread per AAP Section 0.7.1.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    // Initialize shell framework.
    let options = vec![
        ShellOption {
            name: "agent".to_string(),
            has_arg: true,
            description: "Register agent handler: <capability>".to_string(),
            short: 'a',
        },
        ShellOption {
            name: "endpoints".to_string(),
            has_arg: false,
            description: "Register Media endpoints".to_string(),
            short: 'e',
        },
    ];

    let opt = BtShellOpt { options, optstr: "a:e".to_string() };

    bt_shell_init(&args_vec, Some(&opt));

    // Set main menu and inline submenus.
    bt_shell_set_menu(&MAIN_MENU);
    bt_shell_add_submenu(&ADVERTISE_MENU);
    bt_shell_add_submenu(&ADV_MONITOR_MENU);
    bt_shell_add_submenu(&SCAN_MENU);
    bt_shell_add_submenu(&GATT_MENU);
    bt_shell_add_submenu(&LE_MENU);
    bt_shell_add_submenu(&BREDR_MENU);

    // Add external submenus from sibling modules.
    admin::admin_add_submenu();
    player::player_add_submenu();
    mgmt::mgmt_add_submenu();
    assistant::assistant_add_submenu();
    hci::hci_add_submenu();
    telephony::telephony_add_submenu();

    // Set initial prompt.
    bt_shell_set_prompt(PROMPT_OFF, "");

    // Handle non-interactive help early (function returns () — no early exit needed;
    // it prints help and quits internally if --help was passed in non-interactive mode).
    bt_shell_handle_non_interactive_help();

    // Store auto-register agent capability.
    if let Some(ref cap) = auto_register_agent {
        with_state_mut(|state| {
            state.auto_register_agent = Some(cap.clone());
        });
    }

    // Set endpoints env if requested.
    if auto_register_endpoints {
        bt_shell_set_env("AUTO_REGISTER_ENDPOINT", Box::new(true));
    }

    // Run the async event loop.
    let exit_code = rt.block_on(async {
        // Connect to system D-Bus.
        let conn = match Connection::system().await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to connect to D-Bus: {}", e);
                return EXIT_FAILURE;
            }
        };

        // Store connection in state.
        with_state_mut(|state| {
            state.dbus_conn = Some(conn.clone());
        });

        // Set controller index for mgmt submenu.
        mgmt::mgmt_set_index("0xFFFF");

        // Process existing managed objects.
        process_managed_objects(&conn).await;

        // Handle shell timeout.
        if let Some(dur) = bt_shell_get_timeout() {
            tokio::spawn(async move {
                tokio::time::sleep(dur).await;
                bt_shell_printf(format_args!("Timed out\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            });
        }

        // Spawn signal processing loop.
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            run_signal_loop(conn_clone).await;
        });

        // Run shell event loop.
        let result = bt_shell_run().await;

        // Cleanup.
        admin::admin_remove_submenu();
        player::player_remove_submenu();
        mgmt::mgmt_remove_submenu();
        assistant::assistant_remove_submenu();
        hci::hci_remove_submenu();
        telephony::telephony_remove_submenu();
        adv_monitor::adv_monitor_remove_submenu();

        // Remove inline submenus before cleanup.
        bt_shell_remove_submenu(&ADVERTISE_MENU);
        bt_shell_remove_submenu(&ADV_MONITOR_MENU);
        bt_shell_remove_submenu(&SCAN_MENU);
        bt_shell_remove_submenu(&GATT_MENU);
        bt_shell_remove_submenu(&LE_MENU);
        bt_shell_remove_submenu(&BREDR_MENU);

        with_state_mut(|state| {
            state.ctrl_list.clear();
            state.battery_proxies.clear();
            state.default_ctrl = None;
            state.default_dev = None;
            state.default_attr = None;
            state.default_local_attr = None;
            state.agent_manager = None;
            state.dbus_conn = None;
        });

        bt_shell_cleanup();

        result
    });

    if exit_code == EXIT_SUCCESS { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
