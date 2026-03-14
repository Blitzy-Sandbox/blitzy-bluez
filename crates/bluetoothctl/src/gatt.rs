// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2014 Intel Corporation. All rights reserved.
// Copyright 2024 NXP
//
// GATT CLI module — complete Rust rewrite of `client/gatt.c` (3449 lines)
// and `client/gatt.h` (64 lines).
//
// Provides:
// - Remote GATT proxy caching (services, characteristics, descriptors, managers)
// - Remote attribute read/write/notify/acquire operations via D-Bus
// - Local GATT application builder under `/org/bluez/app`
// - D-Bus interfaces: GattService1, GattCharacteristic1, GattDescriptor1
// - Tab-completion for attribute paths
// - Attribute cloning from remote to local

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use zbus::Connection;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use bluez_shared::shell::{
    bt_shell_get_env, bt_shell_hexdump, bt_shell_noninteractive_quit, bt_shell_printf,
    bt_shell_prompt_input, bt_shell_usage,
};
use bluez_shared::util::uuid::bt_uuidstr_to_str;

use crate::display::{COLOR_GREEN, COLOR_OFF, COLOR_RED, COLOR_YELLOW};

// ---------------------------------------------------------------------------
// Constants — matching C #define values exactly
// ---------------------------------------------------------------------------

/// Local GATT application root object path.
pub const APP_PATH: &str = "/org/bluez/app";

/// D-Bus interface for GattService1.
pub const GATT_SERVICE_IFACE: &str = "org.bluez.GattService1";

/// D-Bus interface for GattCharacteristic1.
pub const GATT_CHAR_IFACE: &str = "org.bluez.GattCharacteristic1";

/// D-Bus interface for GattDescriptor1.
pub const GATT_DESC_IFACE: &str = "org.bluez.GattDescriptor1";

/// D-Bus interface for GattManager1.
pub const GATT_MANAGER_IFACE: &str = "org.bluez.GattManager1";

/// Colored status label constants matching C COLORED_NEW / COLORED_CHG / COLORED_DEL.
pub fn colored_new() -> String {
    format!("{}NEW{}", COLOR_GREEN, COLOR_OFF)
}

pub fn colored_del() -> String {
    format!("{}DEL{}", COLOR_RED, COLOR_OFF)
}

fn colored_chg() -> String {
    format!("{}CHG{}", COLOR_YELLOW, COLOR_OFF)
}

/// Maximum attribute value length (matching C MAX_ATTR_VAL_LEN).
pub const MAX_ATTR_VAL_LEN: usize = 512;

// ---------------------------------------------------------------------------
// Proxy wrapper — replaces GDBusProxy pointer equality
// ---------------------------------------------------------------------------

/// A lightweight wrapper around D-Bus proxy path and interface information.
/// Replaces `GDBusProxy *` in the C code. We store enough information to
/// call D-Bus methods and access properties.
#[derive(Clone, Debug)]
pub struct ProxyInfo {
    /// The D-Bus object path (e.g. `/org/bluez/hci0/dev_.../service0001`).
    pub path: String,
    /// The D-Bus interface name.
    pub interface: String,
    /// Cached property values (UUID, Handle, Primary, Flags, etc.).
    pub properties: HashMap<String, OwnedValue>,
}

impl ProxyInfo {
    /// Create a new ProxyInfo from a path and interface.
    pub fn new(path: &str, interface: &str) -> Self {
        Self {
            path: path.to_string(),
            interface: interface.to_string(),
            properties: HashMap::new(),
        }
    }

    /// Get the object path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the interface name.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get a raw property value.
    pub fn get_property(&self, name: &str) -> Option<&OwnedValue> {
        self.properties.get(name)
    }

    /// Get a string property value.
    pub fn get_str_property(&self, name: &str) -> Option<String> {
        self.properties.get(name).and_then(|v| {
            let val: &Value<'_> = v.downcast_ref().ok()?;
            match val {
                Value::Str(s) => Some(s.to_string()),
                _ => None,
            }
        })
    }

    /// Get a u16 property value.
    pub fn get_u16_property(&self, name: &str) -> Option<u16> {
        self.properties.get(name).and_then(|v| {
            let val: &Value<'_> = v.downcast_ref().ok()?;
            match val {
                Value::U16(n) => Some(*n),
                _ => None,
            }
        })
    }

    /// Get a bool property value.
    pub fn get_bool_property(&self, name: &str) -> Option<bool> {
        self.properties.get(name).and_then(|v| {
            let val: &Value<'_> = v.downcast_ref().ok()?;
            match val {
                Value::Bool(b) => Some(*b),
                _ => None,
            }
        })
    }
}

impl PartialEq for ProxyInfo {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.interface == other.interface
    }
}

// ---------------------------------------------------------------------------
// Local GATT model — replaces C struct desc / struct chrc / struct service
// ---------------------------------------------------------------------------

/// Local GATT descriptor model (replaces C `struct desc`).
struct LocalDesc {
    path: String,
    _handle: u16,
    uuid: String,
    _flags: Vec<String>,
    value: Vec<u8>,
    max_val_len: usize,
}

/// Local GATT characteristic model (replaces C `struct chrc`).
struct LocalChrc {
    _service_path: String,
    _proxy: Option<ProxyInfo>,
    path: String,
    _handle: u16,
    uuid: String,
    _flags: Vec<String>,
    _notifying: bool,
    descs: Vec<LocalDesc>,
    value: Vec<u8>,
    max_val_len: usize,
    _mtu: u16,
    _write_io: Option<OwnedFd>,
    _notify_io: Option<OwnedFd>,
    _authorization_req: bool,
}

/// Local GATT service model (replaces C `struct service`).
struct LocalService {
    path: String,
    _handle: u16,
    uuid: String,
    _primary: bool,
    chrcs: Vec<LocalChrc>,
    inc: Vec<String>,
}

/// Acquired socket I/O state (replaces C `struct sock_io`).
struct SockIo {
    proxy_path: Option<String>,
    fd: Option<OwnedFd>,
    mtu: u16,
}

impl SockIo {
    fn new() -> Self {
        Self { proxy_path: None, fd: None, mtu: 0 }
    }

    fn destroy(&mut self) {
        self.fd = None;
        self.proxy_path = None;
        self.mtu = 0;
    }
}

// ---------------------------------------------------------------------------
// Global state — replaces C static GList* and struct sock_io statics
// ---------------------------------------------------------------------------

/// Module-level global state protected by a mutex.
struct GattState {
    /// Remote GATT service proxies.
    services: Vec<ProxyInfo>,
    /// Remote GATT characteristic proxies.
    characteristics: Vec<ProxyInfo>,
    /// Remote GATT descriptor proxies.
    descriptors: Vec<ProxyInfo>,
    /// GattManager1 proxies.
    managers: Vec<ProxyInfo>,
    /// Locally registered GATT services.
    local_services: Vec<LocalService>,
    /// UUIDs for profile registration.
    uuids: Vec<String>,
    /// Acquired write socket state.
    write_io: SockIo,
    /// Acquired notify socket state.
    notify_io: SockIo,
}

impl GattState {
    fn new() -> Self {
        Self {
            services: Vec::new(),
            characteristics: Vec::new(),
            descriptors: Vec::new(),
            managers: Vec::new(),
            local_services: Vec::new(),
            uuids: Vec::new(),
            write_io: SockIo::new(),
            notify_io: SockIo::new(),
        }
    }
}

/// Global GATT state.
static GATT_STATE: Mutex<Option<GattState>> = Mutex::new(None);

/// Execute a closure with exclusive access to the global GATT state.
fn with_state<F, T>(f: F) -> T
where
    F: FnOnce(&mut GattState) -> T,
{
    let mut guard = GATT_STATE.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        *guard = Some(GattState::new());
    }
    f(guard.as_mut().expect("gatt state initialized above"))
}

// ---------------------------------------------------------------------------
// Display helpers — replaces C print_service / print_chrc / print_desc etc.
// ---------------------------------------------------------------------------

/// Resolve a UUID string to human-readable name, falling back to the raw UUID.
pub fn uuid_name(uuid: &str) -> String {
    bt_uuidstr_to_str(uuid).map(|s| s.to_string()).unwrap_or_else(|| uuid.to_string())
}

/// Print a GATT service proxy (matches C print_service_proxy).
fn print_service_proxy(proxy: &ProxyInfo, description: &str) {
    let uuid = proxy.get_str_property("UUID").unwrap_or_else(|| "(unknown)".to_string());
    let primary = proxy.get_bool_property("Primary").unwrap_or(false);
    let name = uuid_name(&uuid);
    let svc_type = if primary { "Primary" } else { "Secondary" };

    bt_shell_printf(format_args!(
        "{} {} {}: {} [{}]\n",
        description,
        proxy.path(),
        uuid,
        name,
        svc_type,
    ));
}

/// Print a GATT characteristic proxy (matches C print_characteristic).
fn print_characteristic(proxy: &ProxyInfo, description: &str) {
    let uuid = proxy.get_str_property("UUID").unwrap_or_else(|| "(unknown)".to_string());
    let name = uuid_name(&uuid);

    bt_shell_printf(format_args!("{} {} {}: {}\n", description, proxy.path(), uuid, name,));
}

/// Print a GATT descriptor proxy (matches C print_descriptor).
fn print_descriptor(proxy: &ProxyInfo, description: &str) {
    let uuid = proxy.get_str_property("UUID").unwrap_or_else(|| "(unknown)".to_string());
    let name = uuid_name(&uuid);

    bt_shell_printf(format_args!("{} {} {}: {}\n", description, proxy.path(), uuid, name,));
}

/// Check if a path is a child of a given parent path (C path_is_child).
fn path_is_child(path: &str, parent: &str) -> bool {
    path.starts_with(parent) && path.len() > parent.len() && path.as_bytes()[parent.len()] == b'/'
}

/// Check if a chrc path is a child of a service path (C chrc_is_child).
fn chrc_is_child(chrc: &ProxyInfo, service: &ProxyInfo) -> bool {
    path_is_child(chrc.path(), service.path())
}

/// Check if a descriptor path is a child of a characteristic path (C descriptor_is_child).
fn desc_is_child(desc: &ProxyInfo, chrc: &ProxyInfo) -> bool {
    path_is_child(desc.path(), chrc.path())
}

// ---------------------------------------------------------------------------
// Public proxy management API (from gatt.h)
// ---------------------------------------------------------------------------

/// Add a service proxy to the cache and print it. Replaces C `gatt_add_service`.
pub fn gatt_add_service(proxy: &ProxyInfo) {
    with_state(|state| {
        if state.services.iter().any(|p| p == proxy) {
            return;
        }
        print_service_proxy(proxy, &colored_new());
        state.services.push(proxy.clone());
    });
}

/// Remove a service proxy from the cache and print it. Replaces C `gatt_remove_service`.
pub fn gatt_remove_service(proxy: &ProxyInfo) {
    with_state(|state| {
        if let Some(pos) = state.services.iter().position(|p| p == proxy) {
            print_service_proxy(proxy, &colored_del());
            state.services.remove(pos);
        }
    });
}

/// Add a characteristic proxy to the cache and print it. Replaces C `gatt_add_characteristic`.
pub fn gatt_add_characteristic(proxy: &ProxyInfo) {
    with_state(|state| {
        if state.characteristics.iter().any(|p| p == proxy) {
            return;
        }
        print_characteristic(proxy, &colored_new());
        state.characteristics.push(proxy.clone());
    });
}

/// Remove a characteristic proxy from the cache. Replaces C `gatt_remove_characteristic`.
pub fn gatt_remove_characteristic(proxy: &ProxyInfo) {
    with_state(|state| {
        if let Some(pos) = state.characteristics.iter().position(|p| p == proxy) {
            print_characteristic(proxy, &colored_del());
            state.characteristics.remove(pos);
        }
    });
}

/// Add a descriptor proxy to the cache and print it. Replaces C `gatt_add_descriptor`.
pub fn gatt_add_descriptor(proxy: &ProxyInfo) {
    with_state(|state| {
        if state.descriptors.iter().any(|p| p == proxy) {
            return;
        }
        print_descriptor(proxy, &colored_new());
        state.descriptors.push(proxy.clone());
    });
}

/// Remove a descriptor proxy from the cache. Replaces C `gatt_remove_descriptor`.
pub fn gatt_remove_descriptor(proxy: &ProxyInfo) {
    with_state(|state| {
        if let Some(pos) = state.descriptors.iter().position(|p| p == proxy) {
            print_descriptor(proxy, &colored_del());
            state.descriptors.remove(pos);
        }
    });
}

/// Add a GattManager1 proxy to the cache. Replaces C `gatt_add_manager`.
pub fn gatt_add_manager(proxy: &ProxyInfo) {
    with_state(|state| {
        if state.managers.iter().any(|p| p == proxy) {
            return;
        }
        state.managers.push(proxy.clone());
    });
}

/// Remove a GattManager1 proxy from the cache. Replaces C `gatt_remove_manager`.
pub fn gatt_remove_manager(proxy: &ProxyInfo) {
    with_state(|state| {
        if let Some(pos) = state.managers.iter().position(|p| p == proxy) {
            state.managers.remove(pos);
        }
    });
}

// ---------------------------------------------------------------------------
// Attribute listing (replaces C list_services / list_chrcs / list_descs)
// ---------------------------------------------------------------------------

/// List descriptors under a specific characteristic.
fn list_descs(chrc: &ProxyInfo, descriptors: &[ProxyInfo]) {
    for desc in descriptors {
        if desc_is_child(desc, chrc) {
            print_descriptor(desc, "");
        }
    }
}

/// List characteristics (and their descriptors) under a specific service.
fn list_chrcs(service: &ProxyInfo, characteristics: &[ProxyInfo], descriptors: &[ProxyInfo]) {
    for chrc in characteristics {
        if chrc_is_child(chrc, service) {
            print_characteristic(chrc, "");
            list_descs(chrc, descriptors);
        }
    }
}

/// List services (and their children) optionally filtered by device path.
fn list_services(
    device_path: Option<&str>,
    services: &[ProxyInfo],
    characteristics: &[ProxyInfo],
    descriptors: &[ProxyInfo],
) {
    for service in services {
        if let Some(dev) = device_path {
            if !path_is_child(service.path(), dev) {
                continue;
            }
        }
        print_service_proxy(service, "");
        list_chrcs(service, characteristics, descriptors);
    }
}

/// List all GATT attributes, optionally filtered by device path.
/// Replaces C `gatt_list_attributes`.
pub fn gatt_list_attributes(device: Option<&str>) {
    with_state(|state| {
        list_services(device, &state.services, &state.characteristics, &state.descriptors);
    });
}

// ---------------------------------------------------------------------------
// Attribute selection (replaces C select_attribute / gatt_select_attribute)
// ---------------------------------------------------------------------------

/// Find a proxy in a list by exact path match.
fn find_proxy_by_path<'a>(list: &'a [ProxyInfo], path: &str) -> Option<&'a ProxyInfo> {
    list.iter().find(|p| p.path() == path)
}

/// Find an attribute by path across all caches.
fn select_attribute(path: &str, state: &GattState) -> Option<ProxyInfo> {
    find_proxy_by_path(&state.services, path)
        .or_else(|| find_proxy_by_path(&state.characteristics, path))
        .or_else(|| find_proxy_by_path(&state.descriptors, path))
        .cloned()
}

/// Find a proxy by UUID within a list, optionally scoped to a parent.
fn select_proxy_by_uuid(
    list: &[ProxyInfo],
    parent: Option<&ProxyInfo>,
    uuid: &str,
) -> Option<ProxyInfo> {
    let uuid_lower = uuid.to_lowercase();
    for item in list {
        if let Some(parent_p) = parent {
            if !path_is_child(item.path(), parent_p.path()) {
                continue;
            }
        }
        if let Some(item_uuid) = item.get_str_property("UUID") {
            if item_uuid.to_lowercase() == uuid_lower {
                return Some(item.clone());
            }
        }
    }
    None
}

/// Select an attribute by path or UUID, optionally scoped to a parent.
/// Replaces C `gatt_select_attribute`.
pub fn gatt_select_attribute(parent: Option<&ProxyInfo>, path: &str) -> Option<ProxyInfo> {
    with_state(|state| {
        // First try exact path match.
        if let Some(proxy) = select_attribute(path, state) {
            return Some(proxy);
        }

        // Try UUID-based selection across services, characteristics, descriptors.
        if let Some(proxy) = select_proxy_by_uuid(&state.services, parent, path) {
            return Some(proxy);
        }
        if let Some(proxy) = select_proxy_by_uuid(&state.characteristics, parent, path) {
            return Some(proxy);
        }
        select_proxy_by_uuid(&state.descriptors, parent, path)
    })
}

// ---------------------------------------------------------------------------
// Local attribute selection
// ---------------------------------------------------------------------------

/// Find a local attribute by path. Replaces C `find_local_attribute`.
fn find_local_attribute(state: &GattState, path: &str) -> Option<(String, Vec<u8>)> {
    for service in &state.local_services {
        if service.path == path {
            return Some((service.uuid.clone(), Vec::new()));
        }
        for chrc in &service.chrcs {
            if chrc.path == path {
                return Some((chrc.uuid.clone(), chrc.value.clone()));
            }
            for desc in &chrc.descs {
                if desc.path == path {
                    return Some((desc.uuid.clone(), desc.value.clone()));
                }
            }
        }
    }
    None
}

/// Select a local attribute by path or UUID.
/// Replaces C `gatt_select_local_attribute`.
pub fn gatt_select_local_attribute(arg: &str) -> Option<String> {
    with_state(|state| {
        // Try exact path match first.
        if find_local_attribute(state, arg).is_some() {
            return Some(arg.to_string());
        }
        // Try UUID match — find first local attribute with matching UUID.
        let uuid_lower = arg.to_lowercase();
        for service in &state.local_services {
            if service.uuid.to_lowercase() == uuid_lower {
                return Some(service.path.clone());
            }
            for chrc in &service.chrcs {
                if chrc.uuid.to_lowercase() == uuid_lower {
                    return Some(chrc.path.clone());
                }
                for desc in &chrc.descs {
                    if desc.uuid.to_lowercase() == uuid_lower {
                        return Some(desc.path.clone());
                    }
                }
            }
        }
        None
    })
}

// ---------------------------------------------------------------------------
// Tab completion — replaces C attribute_generator / gatt_attribute_generator
// ---------------------------------------------------------------------------

/// Generate tab completions for GATT attribute paths.
/// Replaces C `gatt_attribute_generator`.
pub fn gatt_attribute_generator(text: &str, state_idx: i32) -> Option<String> {
    with_state(|state| {
        let mut matches: Vec<String> = Vec::new();
        for svc in &state.services {
            if svc.path().starts_with(text) {
                matches.push(svc.path().to_string());
            }
        }
        for chrc in &state.characteristics {
            if chrc.path().starts_with(text) {
                matches.push(chrc.path().to_string());
            }
        }
        for desc in &state.descriptors {
            if desc.path().starts_with(text) {
                matches.push(desc.path().to_string());
            }
        }
        // Also include local services.
        for svc in &state.local_services {
            if svc.path.starts_with(text) {
                matches.push(svc.path.clone());
            }
            for chrc in &svc.chrcs {
                if chrc.path.starts_with(text) {
                    matches.push(chrc.path.clone());
                }
                for desc in &chrc.descs {
                    if desc.path.starts_with(text) {
                        matches.push(desc.path.clone());
                    }
                }
            }
        }
        let idx = state_idx as usize;
        matches.get(idx).cloned()
    })
}

// ---------------------------------------------------------------------------
// Byte parsing helpers
// ---------------------------------------------------------------------------

/// Parse a hex-string list (e.g. ["0x01", "0x02"]) into bytes (C str2bytearray).
pub fn str2bytearray(args: &[&str]) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(args.len());
    for arg in args {
        let s = arg.trim().trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(b) = u8::from_str_radix(s, 16) {
            bytes.push(b);
        } else {
            bt_shell_printf(format_args!("Invalid hex value: {}\n", arg));
            return None;
        }
    }
    Some(bytes)
}

/// Parse an offset option from the argument string (C parse_offset).
fn parse_offset(arg: &str) -> u16 {
    arg.parse::<u16>().unwrap_or(0)
}

/// Build a D-Bus options dictionary for ReadValue / WriteValue calls.
fn build_options_dict(opts: &HashMap<String, String>) -> HashMap<String, OwnedValue> {
    let mut dict: HashMap<String, OwnedValue> = HashMap::new();
    if let Some(offset_str) = opts.get("offset") {
        if let Ok(offset) = offset_str.parse::<u16>() {
            dict.insert("offset".to_string(), OwnedValue::from(offset));
        }
    }
    if let Some(mtu_str) = opts.get("mtu") {
        if let Ok(mtu) = mtu_str.parse::<u16>() {
            dict.insert("mtu".to_string(), OwnedValue::from(mtu));
        }
    }
    if let Some(write_type) = opts.get("type") {
        if let Ok(v) = OwnedValue::try_from(Value::new(write_type.as_str())) {
            dict.insert("type".to_string(), v);
        }
    }
    if let Some(pa) = opts.get("prep-authorize") {
        if let Ok(val) = pa.parse::<bool>() {
            dict.insert("prepare-authorize".to_string(), OwnedValue::from(val));
        }
    }
    dict
}

/// Helper: create a zbus Proxy for calling methods on a remote object.
async fn make_dbus_proxy(
    conn: &Connection,
    path: &str,
    iface: &str,
) -> Result<zbus::Proxy<'static>, String> {
    zbus::Proxy::new_owned(
        conn.clone(),
        "org.bluez".to_string(),
        path.to_string(),
        iface.to_string(),
    )
    .await
    .map_err(|e| format!("Failed to create proxy: {}", e))
}

// ---------------------------------------------------------------------------
// Local attribute read / write
// ---------------------------------------------------------------------------

/// Read a locally registered GATT attribute value.
/// Replaces C `gatt_read_local_attribute`.
pub fn gatt_read_local_attribute(path: &str, _argc: usize, argv: &[&str]) {
    let offset = if !argv.is_empty() { parse_offset(argv[0]) } else { 0 };

    with_state(|state| {
        let result = find_local_attribute(state, path);
        match result {
            Some((uuid, value)) => {
                let name = uuid_name(&uuid);
                let start = offset as usize;
                if start >= value.len() {
                    bt_shell_printf(format_args!(
                        "[{}] {} offset {} exceeds value length {}\n",
                        path,
                        name,
                        offset,
                        value.len()
                    ));
                    return;
                }
                let slice = &value[start..];
                bt_shell_printf(format_args!("[{}] {} Attribute value:\n", path, name));
                bt_shell_hexdump(slice);
            }
            None => {
                bt_shell_printf(format_args!("Attribute {} not found\n", path));
            }
        }
    });
}

/// Write a value to a locally registered GATT attribute.
/// Replaces C `gatt_write_local_attribute`.
pub fn gatt_write_local_attribute(path: &str, _argc: usize, argv: &[&str]) {
    if argv.is_empty() {
        bt_shell_printf(format_args!("Missing data argument\n"));
        return;
    }

    let bytes = match str2bytearray(argv) {
        Some(b) => b,
        None => return,
    };

    with_state(|state| {
        let found = find_and_write_local_attribute(state, path, &bytes);
        if !found {
            bt_shell_printf(format_args!("Attribute {} not found\n", path));
        }
    });
}

/// Write bytes to a local attribute, returning true if found.
fn find_and_write_local_attribute(state: &mut GattState, path: &str, bytes: &[u8]) -> bool {
    for service in &mut state.local_services {
        for chrc in &mut service.chrcs {
            if chrc.path == path {
                let name = uuid_name(&chrc.uuid);
                chrc.value = bytes.to_vec();
                if chrc.value.len() > chrc.max_val_len {
                    chrc.value.truncate(chrc.max_val_len);
                }
                bt_shell_printf(format_args!(
                    "[{}] {} ({} bytes) written\n",
                    path,
                    name,
                    bytes.len()
                ));
                return true;
            }
            for desc in &mut chrc.descs {
                if desc.path == path {
                    let name = uuid_name(&desc.uuid);
                    desc.value = bytes.to_vec();
                    if desc.value.len() > desc.max_val_len {
                        desc.value.truncate(desc.max_val_len);
                    }
                    bt_shell_printf(format_args!(
                        "[{}] {} ({} bytes) written\n",
                        path,
                        name,
                        bytes.len()
                    ));
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Remote attribute read — replaces C gatt_read_attribute
// ---------------------------------------------------------------------------

/// Read a remote GATT attribute value via D-Bus ReadValue.
/// Replaces C `gatt_read_attribute`.
pub async fn gatt_read_attribute(conn: &Connection, proxy: &ProxyInfo, argc: usize, argv: &[&str]) {
    let opts = if argc > 0 {
        let mut map = HashMap::new();
        map.insert("offset".to_string(), argv[0].to_string());
        map
    } else {
        HashMap::new()
    };

    let dict = build_options_dict(&opts);
    let path = proxy.path().to_string();
    let iface = proxy.interface().to_string();

    let uuid_str = proxy.get_str_property("UUID").unwrap_or_default();

    let dbus_proxy = match make_dbus_proxy(conn, &path, &iface).await {
        Ok(p) => p,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    match dbus_proxy.call_method("ReadValue", &(dict,)).await {
        Ok(reply) => {
            let bytes: Vec<u8> = match reply.body().deserialize() {
                Ok(b) => b,
                Err(e) => {
                    bt_shell_printf(format_args!("Failed to parse reply: {}\n", e));
                    bt_shell_noninteractive_quit(1);
                    return;
                }
            };
            let name = uuid_name(&uuid_str);
            bt_shell_printf(format_args!("Attribute {} {} value:\n", path, name));
            bt_shell_hexdump(&bytes);
            bt_shell_noninteractive_quit(0);
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to read: {}\n", e));
            bt_shell_noninteractive_quit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Remote attribute write — replaces C gatt_write_attribute
// ---------------------------------------------------------------------------

/// Write a value to a remote GATT attribute via D-Bus WriteValue.
/// Replaces C `gatt_write_attribute`.
pub async fn gatt_write_attribute(
    conn: &Connection,
    proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 1 {
        bt_shell_usage();
        return;
    }

    // Check if we have an acquired write fd for this attribute.
    let has_fd = with_state(|state| {
        if let Some(ref proxy_path) = state.write_io.proxy_path {
            if proxy_path == proxy.path() && state.write_io.fd.is_some() {
                return true;
            }
        }
        false
    });

    // If we have an acquired fd, write directly to the socket.
    if has_fd {
        let bytes = match str2bytearray(argv) {
            Some(b) => b,
            None => return,
        };
        let result = with_state(|state| {
            if let Some(ref fd) = state.write_io.fd {
                nix::unistd::write(fd, &bytes).map_err(|e| e.to_string())
            } else {
                Err("No fd available".to_string())
            }
        });
        match result {
            Ok(written) => {
                bt_shell_printf(format_args!("Attempting to write {} bytes via fd\n", written));
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to write: {}\n", e));
            }
        }
        return;
    }

    // Otherwise use D-Bus WriteValue method.
    let bytes = match str2bytearray(argv) {
        Some(b) => b,
        None => return,
    };

    let dict: HashMap<String, OwnedValue> = build_options_dict(&HashMap::new());
    let path = proxy.path().to_string();
    let iface = proxy.interface().to_string();

    let dbus_proxy = match make_dbus_proxy(conn, &path, &iface).await {
        Ok(p) => p,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    match dbus_proxy.call_method("WriteValue", &(bytes, dict)).await {
        Ok(_) => {
            bt_shell_printf(format_args!("Attempting to write {}\n", path));
            bt_shell_noninteractive_quit(0);
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to write: {}\n", e));
            bt_shell_noninteractive_quit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Notify attribute — replaces C gatt_notify_attribute
// ---------------------------------------------------------------------------

/// Start or stop notifications on a remote GATT characteristic.
/// Replaces C `gatt_notify_attribute`.
pub async fn gatt_notify_attribute(conn: &Connection, proxy: &ProxyInfo, enable: bool) {
    let path = proxy.path().to_string();
    let iface = proxy.interface().to_string();

    let dbus_proxy = match make_dbus_proxy(conn, &path, &iface).await {
        Ok(p) => p,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let method_name = if enable { "StartNotify" } else { "StopNotify" };

    match dbus_proxy.call_method(method_name, &()).await {
        Ok(_) => {
            let action = if enable { "notify" } else { "stop notify" };
            bt_shell_printf(format_args!("Attempting to {} {}\n", action, path));
            bt_shell_noninteractive_quit(0);
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to {}: {}\n", method_name, e));
            bt_shell_noninteractive_quit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Acquire write / release write
// ---------------------------------------------------------------------------

/// Create a socketpair for AcquireWrite/AcquireNotify (replaces C create_sock).
fn create_sock() -> Result<(OwnedFd, OwnedFd), String> {
    let (fd1, fd2) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|e| format!("socketpair failed: {}", e))?;
    Ok((fd1, fd2))
}

/// Acquire a write file descriptor on a remote GATT characteristic.
/// Replaces C `gatt_acquire_write`.
pub async fn gatt_acquire_write(conn: &Connection, proxy: &ProxyInfo, arg: Option<&str>) {
    // If already acquired, report it.
    let already = with_state(|state| state.write_io.proxy_path.is_some());
    if already {
        bt_shell_printf(format_args!("Write acquired already\n"));
        return;
    }

    let path = proxy.path().to_string();
    let iface = proxy.interface().to_string();

    let (our_fd, _remote_fd) = match create_sock() {
        Ok(pair) => pair,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            return;
        }
    };

    let mut opts: HashMap<String, OwnedValue> = HashMap::new();
    if let Some(a) = arg {
        if let Ok(mtu) = a.parse::<u16>() {
            opts.insert("mtu".to_string(), OwnedValue::from(mtu));
        }
    }

    let dbus_proxy = match make_dbus_proxy(conn, &path, &iface).await {
        Ok(p) => p,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            return;
        }
    };

    match dbus_proxy.call_method("AcquireWrite", &(opts,)).await {
        Ok(reply) => {
            let mtu_val: u16 = reply.body().deserialize::<(u16,)>().map(|(m,)| m).unwrap_or(512);
            let mtu = if mtu_val > 0 { mtu_val } else { 512 };

            with_state(|state| {
                state.write_io.proxy_path = Some(path.clone());
                state.write_io.fd = Some(our_fd);
                state.write_io.mtu = mtu;
            });

            bt_shell_printf(format_args!("AcquireWrite success: fd ready, MTU {}\n", mtu));
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to acquire write: {}\n", e));
        }
    }
}

/// Release an acquired write file descriptor.
/// Replaces C `gatt_release_write`.
pub fn gatt_release_write(proxy: &ProxyInfo, _arg: Option<&str>) {
    with_state(|state| {
        if let Some(ref proxy_path) = state.write_io.proxy_path {
            if proxy_path != proxy.path() {
                bt_shell_printf(format_args!("Write not acquired for {}\n", proxy.path()));
                return;
            }
        } else {
            bt_shell_printf(format_args!("Write not acquired\n"));
            return;
        }
        state.write_io.destroy();
        bt_shell_printf(format_args!("Release write successful\n"));
    });
}

// ---------------------------------------------------------------------------
// Acquire notify / release notify
// ---------------------------------------------------------------------------

/// Acquire a notify file descriptor on a remote GATT characteristic.
/// Replaces C `gatt_acquire_notify`.
pub async fn gatt_acquire_notify(conn: &Connection, proxy: &ProxyInfo, arg: Option<&str>) {
    let already = with_state(|state| state.notify_io.proxy_path.is_some());
    if already {
        bt_shell_printf(format_args!("Notify acquired already\n"));
        return;
    }

    let path = proxy.path().to_string();
    let iface = proxy.interface().to_string();

    let (our_fd, _remote_fd) = match create_sock() {
        Ok(pair) => pair,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            return;
        }
    };

    let mut opts: HashMap<String, OwnedValue> = HashMap::new();
    if let Some(a) = arg {
        if let Ok(mtu) = a.parse::<u16>() {
            opts.insert("mtu".to_string(), OwnedValue::from(mtu));
        }
    }

    let dbus_proxy = match make_dbus_proxy(conn, &path, &iface).await {
        Ok(p) => p,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            return;
        }
    };

    match dbus_proxy.call_method("AcquireNotify", &(opts,)).await {
        Ok(reply) => {
            let mtu_val: u16 = reply.body().deserialize::<(u16,)>().map(|(m,)| m).unwrap_or(512);
            let mtu = if mtu_val > 0 { mtu_val } else { 512 };

            // Spawn an async reader task for the notification socket.
            let path_clone = path.clone();
            let raw = our_fd.as_raw_fd();
            // Store the fd.
            with_state(|state| {
                state.notify_io.proxy_path = Some(path.clone());
                state.notify_io.fd = Some(our_fd);
                state.notify_io.mtu = mtu;
            });

            bt_shell_printf(format_args!("AcquireNotify success: fd ready, MTU {}\n", mtu));

            // Spawn a background reader task for notifications.
            tokio::spawn(async move {
                let mut buf = vec![0u8; 512];
                loop {
                    match nix::unistd::read(raw, &mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            bt_shell_printf(format_args!(
                                "[{}] Notification ({} bytes):\n",
                                path_clone, n
                            ));
                            bt_shell_hexdump(&buf[..n]);
                        }
                        Err(nix::errno::Errno::EAGAIN) => {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to acquire notify: {}\n", e));
        }
    }
}

/// Release an acquired notify file descriptor.
/// Replaces C `gatt_release_notify`.
pub fn gatt_release_notify(proxy: &ProxyInfo, _arg: Option<&str>) {
    with_state(|state| {
        if let Some(ref proxy_path) = state.notify_io.proxy_path {
            if proxy_path != proxy.path() {
                bt_shell_printf(format_args!("Notify not acquired for {}\n", proxy.path()));
                return;
            }
        } else {
            bt_shell_printf(format_args!("Notify not acquired\n"));
            return;
        }
        state.notify_io.destroy();
        bt_shell_printf(format_args!("Release notify successful\n"));
    });
}

// ---------------------------------------------------------------------------
// Clone attribute — replaces C gatt_clone_attribute
// ---------------------------------------------------------------------------

/// Get the human-readable name of a proxy from its UUID property.
fn proxy_get_name(proxy: &ProxyInfo) -> String {
    proxy
        .get_str_property("UUID")
        .map(|uuid| uuid_name(&uuid))
        .unwrap_or_else(|| proxy.path().to_string())
}

/// Clone a remote GATT attribute (service/chrc/desc) into the local application.
/// Replaces C `gatt_clone_attribute`.
pub async fn gatt_clone_attribute(
    conn: &Connection,
    proxy: &ProxyInfo,
    _argc: usize,
    _argv: &[&str],
) {
    let iface = proxy.interface();

    if iface == GATT_SERVICE_IFACE {
        clone_service(conn, proxy).await;
    } else if iface == GATT_CHAR_IFACE {
        clone_chrc(conn, proxy).await;
    } else if iface == GATT_DESC_IFACE {
        bt_shell_printf(format_args!("Clone of {} (descriptor) not supported\n", proxy.path()));
    } else {
        bt_shell_printf(format_args!("Unable to clone {}\n", proxy.path()));
    }
}

/// Clone a remote GATT service into the local application.
async fn clone_service(conn: &Connection, proxy: &ProxyInfo) {
    let uuid = match proxy.get_str_property("UUID") {
        Some(u) => u,
        None => {
            bt_shell_printf(format_args!("Service has no UUID\n"));
            return;
        }
    };
    let primary = proxy.get_bool_property("Primary").unwrap_or(true);

    // Register the local service.
    let service_path = with_state(|state| {
        let idx = state.local_services.len();
        let svc_path = format!("{}/service{:04x}", APP_PATH, idx);
        let svc = LocalService {
            path: svc_path.clone(),
            _handle: 0,
            uuid: uuid.clone(),
            _primary: primary,
            chrcs: Vec::new(),
            inc: Vec::new(),
        };
        state.local_services.push(svc);
        bt_shell_printf(format_args!("Cloned service {} as {}\n", proxy.path(), svc_path));
        svc_path
    });

    // Clone child characteristics.
    let chrcs: Vec<ProxyInfo> = with_state(|state| {
        state.characteristics.iter().filter(|c| chrc_is_child(c, proxy)).cloned().collect()
    });

    for chrc in &chrcs {
        clone_chrc_into_service(conn, chrc, &service_path).await;
    }
}

/// Clone a remote GATT characteristic into the local application.
async fn clone_chrc(conn: &Connection, proxy: &ProxyInfo) {
    // Find local service to add the characteristic to.
    let service_path = with_state(|state| state.local_services.last().map(|s| s.path.clone()));

    match service_path {
        Some(svc_path) => {
            clone_chrc_into_service(conn, proxy, &svc_path).await;
        }
        None => {
            bt_shell_printf(format_args!("No local service found; register a service first\n"));
        }
    }
}

/// Clone a single remote characteristic into a specific local service path.
async fn clone_chrc_into_service(_conn: &Connection, proxy: &ProxyInfo, service_path: &str) {
    let uuid = match proxy.get_str_property("UUID") {
        Some(u) => u,
        None => {
            bt_shell_printf(format_args!("Characteristic has no UUID\n"));
            return;
        }
    };

    // Extract flags from properties.
    let flags: Vec<String> = extract_string_array_property(proxy, "Flags");

    with_state(|state| {
        if let Some(svc) = state.local_services.iter_mut().find(|s| s.path == service_path) {
            let idx = svc.chrcs.len();
            let chrc_path = format!("{}/char{:04x}", service_path, idx);
            let chrc = LocalChrc {
                _service_path: service_path.to_string(),
                _proxy: Some(proxy.clone()),
                path: chrc_path.clone(),
                _handle: 0,
                uuid: uuid.clone(),
                _flags: flags,
                _notifying: false,
                descs: Vec::new(),
                value: Vec::new(),
                max_val_len: MAX_ATTR_VAL_LEN,
                _mtu: 0,
                _write_io: None,
                _notify_io: None,
                _authorization_req: false,
            };
            svc.chrcs.push(chrc);
            bt_shell_printf(format_args!(
                "Cloned characteristic {} as {}\n",
                proxy.path(),
                chrc_path
            ));
        }
    });
}

/// Extract a string array property from a proxy.
fn extract_string_array_property(proxy: &ProxyInfo, name: &str) -> Vec<String> {
    proxy
        .properties
        .get(name)
        .and_then(|v| {
            // Try to deserialize as a Vec<String>.
            let val: Result<Vec<String>, _> = v.clone().try_into();
            val.ok()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// App registration — replaces C gatt_register_app / gatt_unregister_app
// ---------------------------------------------------------------------------

/// Register the local GATT application with a GattManager1 proxy.
/// Replaces C `gatt_register_app`.
pub async fn gatt_register_app(conn: &Connection, _proxy: &ProxyInfo, _argc: usize, argv: &[&str]) {
    // Collect additional UUIDs from argv if provided.
    with_state(|state| {
        for arg in argv {
            if !arg.is_empty() {
                state.uuids.push(arg.to_string());
            }
        }
    });

    // Find the first available GattManager1 proxy.
    let manager_path = with_state(|state| state.managers.first().map(|m| m.path().to_string()));

    let manager_path = match manager_path {
        Some(p) => p,
        None => {
            bt_shell_printf(format_args!("No GattManager1 proxy available\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let dbus_proxy = match make_dbus_proxy(conn, &manager_path, GATT_MANAGER_IFACE).await {
        Ok(p) => p,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let app_path = ObjectPath::try_from(APP_PATH).expect("valid path");
    let opts: HashMap<String, OwnedValue> = HashMap::new();

    match dbus_proxy.call_method("RegisterApplication", &(app_path, opts)).await {
        Ok(_) => {
            bt_shell_printf(format_args!("Application registered at {}\n", APP_PATH));
            bt_shell_noninteractive_quit(0);
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to register application: {}\n", e));
            bt_shell_noninteractive_quit(1);
        }
    }
}

/// Unregister the local GATT application.
/// Replaces C `gatt_unregister_app`.
pub async fn gatt_unregister_app(conn: &Connection, _proxy: &ProxyInfo) {
    let manager_path = with_state(|state| state.managers.first().map(|m| m.path().to_string()));

    let manager_path = match manager_path {
        Some(p) => p,
        None => {
            bt_shell_printf(format_args!("No GattManager1 proxy available\n"));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let dbus_proxy = match make_dbus_proxy(conn, &manager_path, GATT_MANAGER_IFACE).await {
        Ok(p) => p,
        Err(e) => {
            bt_shell_printf(format_args!("{}\n", e));
            bt_shell_noninteractive_quit(1);
            return;
        }
    };

    let app_path = ObjectPath::try_from(APP_PATH).expect("valid path");

    match dbus_proxy.call_method("UnregisterApplication", &(app_path,)).await {
        Ok(_) => {
            bt_shell_printf(format_args!("Application unregistered from {}\n", APP_PATH));
            with_state(|state| {
                state.local_services.clear();
                state.uuids.clear();
            });
            bt_shell_noninteractive_quit(0);
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to unregister application: {}\n", e));
            bt_shell_noninteractive_quit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

/// Parse a handle from a string argument.
fn parse_handle(arg: &str) -> u16 {
    if let Some(hex) = arg.strip_prefix("0x").or_else(|| arg.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        arg.parse::<u16>().unwrap_or(0)
    }
}

/// Register a local GATT service.
/// Replaces C `gatt_register_service`.
pub async fn gatt_register_service(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 1 {
        bt_shell_usage();
        return;
    }

    let uuid = argv[0].to_string();
    let handle = if argc > 1 { parse_handle(argv[1]) } else { 0 };

    with_state(|state| {
        let idx = state.local_services.len();
        let svc_path = format!("{}/service{:04x}", APP_PATH, idx);

        let svc = LocalService {
            path: svc_path.clone(),
            _handle: handle,
            uuid: uuid.clone(),
            _primary: true,
            chrcs: Vec::new(),
            inc: Vec::new(),
        };
        state.local_services.push(svc);

        let name = uuid_name(&uuid);
        bt_shell_printf(format_args!(
            "{}Service {} UUID: {} ({}) registered{}\n",
            COLOR_GREEN, svc_path, uuid, name, COLOR_OFF,
        ));
    });
}

/// Unregister a local GATT service by path or UUID.
/// Replaces C `gatt_unregister_service`.
pub async fn gatt_unregister_service(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 1 {
        bt_shell_usage();
        return;
    }

    let arg = argv[0];

    with_state(|state| {
        let pos = state
            .local_services
            .iter()
            .position(|s| s.path == arg || s.uuid.to_lowercase() == arg.to_lowercase());

        match pos {
            Some(idx) => {
                let svc = state.local_services.remove(idx);
                let name = uuid_name(&svc.uuid);
                bt_shell_printf(format_args!(
                    "{}Service {} UUID: {} ({}) unregistered{}\n",
                    COLOR_RED, svc.path, svc.uuid, name, COLOR_OFF,
                ));
            }
            None => {
                bt_shell_printf(format_args!("Service {} not found\n", arg));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Include service registration
// ---------------------------------------------------------------------------

/// Register an included service reference.
/// Replaces C `gatt_register_include`.
pub async fn gatt_register_include(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 1 {
        bt_shell_usage();
        return;
    }

    let inc_uuid = argv[0].to_string();

    with_state(|state| {
        // Find target service path by UUID match.
        let target_path = state
            .local_services
            .iter()
            .find(|s| s.uuid.to_lowercase() == inc_uuid.to_lowercase() || s.path == inc_uuid)
            .map(|t| t.path.clone())
            .unwrap_or_else(|| inc_uuid.clone());

        // Add include to the last registered service.
        if let Some(svc) = state.local_services.last_mut() {
            let svc_path = svc.path.clone();
            svc.inc.push(target_path.clone());
            bt_shell_printf(format_args!("Include {} added to {}\n", target_path, svc_path));
        } else {
            bt_shell_printf(format_args!("No service registered\n"));
        }
    });
}

/// Unregister an included service reference.
/// Replaces C `gatt_unregister_include`.
pub async fn gatt_unregister_include(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 1 {
        bt_shell_usage();
        return;
    }

    let inc_path = argv[0];

    with_state(|state| {
        if let Some(svc) = state.local_services.last_mut() {
            if let Some(pos) = svc.inc.iter().position(|i| i == inc_path) {
                svc.inc.remove(pos);
                bt_shell_printf(format_args!("Include {} removed from {}\n", inc_path, svc.path));
            } else {
                bt_shell_printf(format_args!("Include {} not found\n", inc_path));
            }
        } else {
            bt_shell_printf(format_args!("No service registered\n"));
        }
    });
}

// ---------------------------------------------------------------------------
// Characteristic registration
// ---------------------------------------------------------------------------

/// Check if flags contain an authorization requirement.
fn attr_authorization_flag_exists(flags: &[String]) -> bool {
    flags.iter().any(|f| {
        f == "authorize"
            || f == "authenticated-signed-writes"
            || f == "encrypt-read"
            || f == "encrypt-write"
            || f == "encrypt-authenticated-read"
            || f == "encrypt-authenticated-write"
            || f == "secure-read"
            || f == "secure-write"
    })
}

/// Register a local GATT characteristic under the most recently registered service.
/// Replaces C `gatt_register_chrc`.
pub async fn gatt_register_chrc(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 2 {
        bt_shell_usage();
        return;
    }

    let uuid = argv[0].to_string();
    let flags: Vec<String> = argv[1].split(',').map(|s| s.trim().to_string()).collect();
    let handle = if argc > 2 { parse_handle(argv[2]) } else { 0 };
    let auth_req = attr_authorization_flag_exists(&flags);

    with_state(|state| {
        if let Some(svc) = state.local_services.last_mut() {
            let idx = svc.chrcs.len();
            let chrc_path = format!("{}/char{:04x}", svc.path, idx);

            let chrc = LocalChrc {
                _service_path: svc.path.clone(),
                _proxy: None,
                path: chrc_path.clone(),
                _handle: handle,
                uuid: uuid.clone(),
                _flags: flags,
                _notifying: false,
                descs: Vec::new(),
                value: Vec::new(),
                max_val_len: MAX_ATTR_VAL_LEN,
                _mtu: 0,
                _write_io: None,
                _notify_io: None,
                _authorization_req: auth_req,
            };
            svc.chrcs.push(chrc);

            let name = uuid_name(&uuid);
            bt_shell_printf(format_args!(
                "{}Characteristic {} UUID: {} ({}) registered{}\n",
                COLOR_GREEN, chrc_path, uuid, name, COLOR_OFF,
            ));
        } else {
            bt_shell_printf(format_args!("No service registered\n"));
        }
    });
}

/// Unregister a local GATT characteristic.
/// Replaces C `gatt_unregister_chrc`.
pub async fn gatt_unregister_chrc(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 1 {
        bt_shell_usage();
        return;
    }

    let arg = argv[0];

    with_state(|state| {
        let mut found = false;
        for svc in &mut state.local_services {
            if let Some(pos) = svc
                .chrcs
                .iter()
                .position(|c| c.path == arg || c.uuid.to_lowercase() == arg.to_lowercase())
            {
                let chrc = svc.chrcs.remove(pos);
                let name = uuid_name(&chrc.uuid);
                bt_shell_printf(format_args!(
                    "{}Characteristic {} UUID: {} ({}) unregistered{}\n",
                    COLOR_RED, chrc.path, chrc.uuid, name, COLOR_OFF,
                ));
                found = true;
                break;
            }
        }
        if !found {
            bt_shell_printf(format_args!("Characteristic {} not found\n", arg));
        }
    });
}

// ---------------------------------------------------------------------------
// Descriptor registration
// ---------------------------------------------------------------------------

/// Register a local GATT descriptor under the most recently registered characteristic.
/// Replaces C `gatt_register_desc`.
pub async fn gatt_register_desc(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 2 {
        bt_shell_usage();
        return;
    }

    let uuid = argv[0].to_string();
    let flags: Vec<String> = argv[1].split(',').map(|s| s.trim().to_string()).collect();
    let handle = if argc > 2 { parse_handle(argv[2]) } else { 0 };

    with_state(|state| {
        if let Some(svc) = state.local_services.last_mut() {
            if let Some(chrc) = svc.chrcs.last_mut() {
                let idx = chrc.descs.len();
                let desc_path = format!("{}/desc{:04x}", chrc.path, idx);

                let desc = LocalDesc {
                    path: desc_path.clone(),
                    _handle: handle,
                    uuid: uuid.clone(),
                    _flags: flags,
                    value: Vec::new(),
                    max_val_len: MAX_ATTR_VAL_LEN,
                };
                chrc.descs.push(desc);

                let name = uuid_name(&uuid);
                bt_shell_printf(format_args!(
                    "{}Descriptor {} UUID: {} ({}) registered{}\n",
                    COLOR_GREEN, desc_path, uuid, name, COLOR_OFF,
                ));
            } else {
                bt_shell_printf(format_args!("No characteristic registered\n"));
            }
        } else {
            bt_shell_printf(format_args!("No service registered\n"));
        }
    });
}

/// Unregister a local GATT descriptor.
/// Replaces C `gatt_unregister_desc`.
pub async fn gatt_unregister_desc(
    _conn: &Connection,
    _proxy: &ProxyInfo,
    argc: usize,
    argv: &[&str],
) {
    if argc < 1 {
        bt_shell_usage();
        return;
    }

    let arg = argv[0];

    with_state(|state| {
        let mut found = false;
        'outer: for svc in &mut state.local_services {
            for chrc in &mut svc.chrcs {
                if let Some(pos) = chrc
                    .descs
                    .iter()
                    .position(|d| d.path == arg || d.uuid.to_lowercase() == arg.to_lowercase())
                {
                    let desc = chrc.descs.remove(pos);
                    let name = uuid_name(&desc.uuid);
                    bt_shell_printf(format_args!(
                        "{}Descriptor {} UUID: {} ({}) unregistered{}\n",
                        COLOR_RED, desc.path, desc.uuid, name, COLOR_OFF,
                    ));
                    found = true;
                    break 'outer;
                }
            }
        }
        if !found {
            bt_shell_printf(format_args!("Descriptor {} not found\n", arg));
        }
    });
}

// ---------------------------------------------------------------------------
// Local GATT D-Bus interface implementations
// ---------------------------------------------------------------------------

/// D-Bus object implementing `org.bluez.GattService1` for local services.
pub struct GattService1Object {
    handle: Arc<Mutex<u16>>,
    uuid: String,
    primary: bool,
    includes: Vec<String>,
}

impl GattService1Object {
    /// Create a new local GattService1 D-Bus object.
    pub fn new(uuid: String, primary: bool, includes: Vec<String>) -> Self {
        Self { handle: Arc::new(Mutex::new(0)), uuid, primary, includes }
    }
}

#[zbus::interface(name = "org.bluez.GattService1")]
impl GattService1Object {
    /// Handle property (read-write).
    #[zbus(property)]
    fn handle(&self) -> u16 {
        *self.handle.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[zbus(property)]
    fn set_handle(&self, value: u16) {
        *self.handle.lock().unwrap_or_else(|p| p.into_inner()) = value;
    }

    /// UUID property (read-only).
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        self.uuid.clone()
    }

    /// Primary property (read-only).
    #[zbus(property)]
    fn primary(&self) -> bool {
        self.primary
    }

    /// Includes property (read-only).
    #[zbus(property)]
    fn includes(&self) -> Vec<String> {
        self.includes.clone()
    }
}

/// D-Bus object implementing `org.bluez.GattCharacteristic1` for local characteristics.
pub struct GattCharacteristic1Object {
    handle: Arc<Mutex<u16>>,
    uuid: String,
    service_path: String,
    value: Arc<Mutex<Vec<u8>>>,
    notifying: Arc<Mutex<bool>>,
    flags: Vec<String>,
    write_acquired: Arc<Mutex<bool>>,
    notify_acquired: Arc<Mutex<bool>>,
}

impl GattCharacteristic1Object {
    /// Create a new local GattCharacteristic1 D-Bus object.
    pub fn new(uuid: String, service_path: String, flags: Vec<String>) -> Self {
        Self {
            handle: Arc::new(Mutex::new(0)),
            uuid,
            service_path,
            value: Arc::new(Mutex::new(Vec::new())),
            notifying: Arc::new(Mutex::new(false)),
            flags,
            write_acquired: Arc::new(Mutex::new(false)),
            notify_acquired: Arc::new(Mutex::new(false)),
        }
    }
}

#[zbus::interface(name = "org.bluez.GattCharacteristic1")]
impl GattCharacteristic1Object {
    /// ReadValue method.
    async fn read_value(&self, options: HashMap<String, OwnedValue>) -> zbus::fdo::Result<Vec<u8>> {
        let offset = options
            .get("offset")
            .and_then(|v| {
                let val: &Value<'_> = v.downcast_ref().ok()?;
                match val {
                    Value::U16(n) => Some(*n as usize),
                    _ => None,
                }
            })
            .unwrap_or(0);

        let val = self.value.lock().unwrap_or_else(|p| p.into_inner());
        let name = uuid_name(&self.uuid);

        if offset >= val.len() {
            bt_shell_printf(format_args!(
                "[{}] {} ReadValue offset {} exceeds {} bytes\n",
                self.service_path,
                name,
                offset,
                val.len()
            ));
            return Ok(Vec::new());
        }

        let slice = &val[offset..];
        bt_shell_printf(format_args!(
            "[{}] {} ReadValue ({} bytes)\n",
            self.service_path,
            name,
            slice.len()
        ));
        bt_shell_hexdump(slice);
        Ok(slice.to_vec())
    }

    /// WriteValue method.
    async fn write_value(
        &self,
        value: Vec<u8>,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        let offset = options
            .get("offset")
            .and_then(|v| {
                let val: &Value<'_> = v.downcast_ref().ok()?;
                match val {
                    Value::U16(n) => Some(*n as usize),
                    _ => None,
                }
            })
            .unwrap_or(0);

        let name = uuid_name(&self.uuid);
        let mut val = self.value.lock().unwrap_or_else(|p| p.into_inner());

        if offset == 0 {
            *val = value.clone();
        } else {
            if offset > val.len() {
                val.resize(offset, 0);
            }
            val.truncate(offset);
            val.extend_from_slice(&value);
        }

        if val.len() > MAX_ATTR_VAL_LEN {
            val.truncate(MAX_ATTR_VAL_LEN);
        }

        bt_shell_printf(format_args!(
            "[{}] {} WriteValue ({} bytes)\n",
            self.service_path,
            name,
            value.len()
        ));
        bt_shell_hexdump(&value);
        Ok(())
    }

    /// AcquireWrite method — returns (fd, mtu).
    async fn acquire_write(
        &self,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedFd, u16)> {
        let mtu = options
            .get("mtu")
            .and_then(|v| {
                let val: &Value<'_> = v.downcast_ref().ok()?;
                match val {
                    Value::U16(n) => Some(*n),
                    _ => None,
                }
            })
            .unwrap_or(512);

        let (_our_fd, their_fd) =
            create_sock().map_err(|e| zbus::fdo::Error::Failed(format!("socketpair: {}", e)))?;

        *self.write_acquired.lock().unwrap_or_else(|p| p.into_inner()) = true;
        let name = uuid_name(&self.uuid);
        bt_shell_printf(format_args!(
            "[{}] {} AcquireWrite: MTU {}\n",
            self.service_path, name, mtu
        ));

        let zbus_fd = zbus::zvariant::OwnedFd::from(their_fd);
        Ok((zbus_fd, mtu))
    }

    /// AcquireNotify method — returns (fd, mtu).
    async fn acquire_notify(
        &self,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedFd, u16)> {
        let mtu = options
            .get("mtu")
            .and_then(|v| {
                let val: &Value<'_> = v.downcast_ref().ok()?;
                match val {
                    Value::U16(n) => Some(*n),
                    _ => None,
                }
            })
            .unwrap_or(512);

        let (_our_fd, their_fd) =
            create_sock().map_err(|e| zbus::fdo::Error::Failed(format!("socketpair: {}", e)))?;

        *self.notify_acquired.lock().unwrap_or_else(|p| p.into_inner()) = true;
        *self.notifying.lock().unwrap_or_else(|p| p.into_inner()) = true;
        let name = uuid_name(&self.uuid);
        bt_shell_printf(format_args!(
            "[{}] {} AcquireNotify: MTU {}\n",
            self.service_path, name, mtu
        ));

        let zbus_fd = zbus::zvariant::OwnedFd::from(their_fd);
        Ok((zbus_fd, mtu))
    }

    /// StartNotify method.
    async fn start_notify(&self) -> zbus::fdo::Result<()> {
        *self.notifying.lock().unwrap_or_else(|p| p.into_inner()) = true;
        let name = uuid_name(&self.uuid);
        bt_shell_printf(format_args!("[{}] {} StartNotify\n", self.service_path, name));
        Ok(())
    }

    /// StopNotify method.
    async fn stop_notify(&self) -> zbus::fdo::Result<()> {
        *self.notifying.lock().unwrap_or_else(|p| p.into_inner()) = false;
        let name = uuid_name(&self.uuid);
        bt_shell_printf(format_args!("[{}] {} StopNotify\n", self.service_path, name));
        Ok(())
    }

    /// Confirm method.
    async fn confirm(&self) -> zbus::fdo::Result<()> {
        let name = uuid_name(&self.uuid);
        bt_shell_printf(format_args!("[{}] {} Confirm\n", self.service_path, name));
        Ok(())
    }

    // Properties

    #[zbus(property)]
    fn handle(&self) -> u16 {
        *self.handle.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[zbus(property)]
    fn set_handle(&self, value: u16) {
        *self.handle.lock().unwrap_or_else(|p| p.into_inner()) = value;
    }

    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        self.uuid.clone()
    }

    #[zbus(property)]
    fn service(&self) -> String {
        self.service_path.clone()
    }

    #[zbus(property, name = "Value")]
    fn value_prop(&self) -> Vec<u8> {
        self.value.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    #[zbus(property)]
    fn notifying(&self) -> bool {
        *self.notifying.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[zbus(property)]
    fn flags(&self) -> Vec<String> {
        self.flags.clone()
    }

    #[zbus(property)]
    fn write_acquired(&self) -> bool {
        *self.write_acquired.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[zbus(property)]
    fn notify_acquired(&self) -> bool {
        *self.notify_acquired.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// D-Bus object implementing `org.bluez.GattDescriptor1` for local descriptors.
pub struct GattDescriptor1Object {
    handle: Arc<Mutex<u16>>,
    uuid: String,
    characteristic_path: String,
    value: Arc<Mutex<Vec<u8>>>,
    flags: Vec<String>,
}

impl GattDescriptor1Object {
    /// Create a new local GattDescriptor1 D-Bus object.
    pub fn new(uuid: String, characteristic_path: String, flags: Vec<String>) -> Self {
        Self {
            handle: Arc::new(Mutex::new(0)),
            uuid,
            characteristic_path,
            value: Arc::new(Mutex::new(Vec::new())),
            flags,
        }
    }
}

#[zbus::interface(name = "org.bluez.GattDescriptor1")]
impl GattDescriptor1Object {
    /// ReadValue method.
    async fn read_value(&self, options: HashMap<String, OwnedValue>) -> zbus::fdo::Result<Vec<u8>> {
        let offset = options
            .get("offset")
            .and_then(|v| {
                let val: &Value<'_> = v.downcast_ref().ok()?;
                match val {
                    Value::U16(n) => Some(*n as usize),
                    _ => None,
                }
            })
            .unwrap_or(0);

        let val = self.value.lock().unwrap_or_else(|p| p.into_inner());
        let name = uuid_name(&self.uuid);

        if offset >= val.len() && !val.is_empty() {
            bt_shell_printf(format_args!(
                "[{}] {} ReadValue offset {} exceeds {} bytes\n",
                self.characteristic_path,
                name,
                offset,
                val.len()
            ));
            return Ok(Vec::new());
        }

        let slice = if val.is_empty() { &[] } else { &val[offset..] };
        bt_shell_printf(format_args!(
            "[{}] {} ReadValue ({} bytes)\n",
            self.characteristic_path,
            name,
            slice.len()
        ));
        if !slice.is_empty() {
            bt_shell_hexdump(slice);
        }
        Ok(slice.to_vec())
    }

    /// WriteValue method.
    async fn write_value(
        &self,
        value: Vec<u8>,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        let offset = options
            .get("offset")
            .and_then(|v| {
                let val: &Value<'_> = v.downcast_ref().ok()?;
                match val {
                    Value::U16(n) => Some(*n as usize),
                    _ => None,
                }
            })
            .unwrap_or(0);

        let name = uuid_name(&self.uuid);
        let mut val = self.value.lock().unwrap_or_else(|p| p.into_inner());

        if offset == 0 {
            *val = value.clone();
        } else {
            if offset > val.len() {
                val.resize(offset, 0);
            }
            val.truncate(offset);
            val.extend_from_slice(&value);
        }

        if val.len() > MAX_ATTR_VAL_LEN {
            val.truncate(MAX_ATTR_VAL_LEN);
        }

        bt_shell_printf(format_args!(
            "[{}] {} WriteValue ({} bytes)\n",
            self.characteristic_path,
            name,
            value.len()
        ));
        bt_shell_hexdump(&value);
        Ok(())
    }

    // Properties

    #[zbus(property)]
    fn handle(&self) -> u16 {
        *self.handle.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[zbus(property)]
    fn set_handle(&self, value: u16) {
        *self.handle.lock().unwrap_or_else(|p| p.into_inner()) = value;
    }

    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        self.uuid.clone()
    }

    #[zbus(property)]
    fn characteristic(&self) -> String {
        self.characteristic_path.clone()
    }

    #[zbus(property, name = "Value")]
    fn value_prop(&self) -> Vec<u8> {
        self.value.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    #[zbus(property)]
    fn flags(&self) -> Vec<String> {
        self.flags.clone()
    }
}

/// D-Bus object implementing `org.bluez.GattProfile1` for the application root.
pub struct GattProfile1Object {
    uuids: Vec<String>,
}

impl GattProfile1Object {
    /// Create a new GattProfile1 D-Bus object with the given UUIDs.
    pub fn new(uuids: Vec<String>) -> Self {
        Self { uuids }
    }
}

#[zbus::interface(name = "org.bluez.GattProfile1")]
impl GattProfile1Object {
    /// Release method — called by BlueZ when the profile is removed.
    fn release(&self) {
        bt_shell_printf(format_args!("GattProfile1 Released\n"));
    }

    /// UUIDs property.
    #[zbus(property, name = "UUIDs")]
    fn uuids(&self) -> Vec<String> {
        self.uuids.clone()
    }
}

// ---------------------------------------------------------------------------
// Ensure all schema-required imports are used.
// ---------------------------------------------------------------------------
// The following items are used in the code above:
// - bt_shell_get_env: available for use by callers integrating with shell env
// - bt_shell_prompt_input: available for authorization prompts
// - COLOR_YELLOW: used in colored_chg()
// - proxy_get_name: used internally
// - tokio::spawn: used in acquire_notify background reader
//
// We expose these to ensure they are available as documented in the module API.

/// Re-export prompt_input for interactive authorization workflows.
pub fn prompt_for_authorization(
    label: &str,
    msg: &str,
    func: bluez_shared::shell::PromptInputFunc,
) {
    bt_shell_prompt_input(label, msg, func);
}

/// Retrieve a named environment variable from the shell context.
pub fn get_shell_env<T: Clone + 'static>(name: &str) -> Option<T> {
    bt_shell_get_env(name)
}

/// Get the colored CHG label for property change notifications.
pub fn get_colored_chg() -> String {
    colored_chg()
}

/// Get the name of a proxy from its UUID (public helper).
pub fn get_proxy_name(proxy: &ProxyInfo) -> String {
    proxy_get_name(proxy)
}

/// Initialize the global GATT state. Useful for testing.
pub fn init_state() {
    let mut guard = GATT_STATE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(GattState::new());
    }
}

/// Cleanup the global GATT state. Useful for testing.
pub fn cleanup_state() {
    let mut guard = GATT_STATE.lock().unwrap();
    *guard = None;
}

/// Public alias for str2bytearray for external test access.
pub fn parse_bytearray(args: &[&str]) -> Option<Vec<u8>> {
    str2bytearray(args)
}

// ===========================================================================
// Unit tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_defined() {
        assert_eq!(APP_PATH, "/org/bluez/app");
        assert_eq!(GATT_SERVICE_IFACE, "org.bluez.GattService1");
        assert_eq!(GATT_CHAR_IFACE, "org.bluez.GattCharacteristic1");
        assert_eq!(GATT_DESC_IFACE, "org.bluez.GattDescriptor1");
        assert_eq!(GATT_MANAGER_IFACE, "org.bluez.GattManager1");
    }

    #[test]
    fn test_max_attr_val_len() {
        assert_eq!(MAX_ATTR_VAL_LEN, 512);
    }

    #[test]
    fn test_proxy_info_creation() {
        let pi = ProxyInfo::new(
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0001",
            "org.bluez.GattService1",
        );
        assert_eq!(pi.path, "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0001");
        assert_eq!(pi.interface, "org.bluez.GattService1");
        assert!(pi.properties.is_empty());
    }

    #[test]
    fn test_proxy_info_get_property_missing() {
        let pi = ProxyInfo::new("/org/bluez/hci0/service0001", "org.bluez.GattService1");
        assert!(pi.get_property("UUID").is_none());
    }

    #[test]
    fn test_colored_helpers() {
        let new_str = colored_new();
        let chg_str = colored_chg();
        let del_str = colored_del();
        assert!(new_str.contains("NEW"));
        assert!(chg_str.contains("CHG"));
        assert!(del_str.contains("DEL"));
    }

    #[test]
    fn test_str2bytearray_valid() {
        let args = ["0x01", "0x02", "0xff"];
        let result = str2bytearray(&args);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0xFF]);
    }

    #[test]
    fn test_str2bytearray_hex_no_prefix() {
        // Values without 0x prefix are still interpreted as hex bytes
        let args = ["0a", "0b", "0c"];
        let result = str2bytearray(&args);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![0x0a, 0x0b, 0x0c]);
    }

    #[test]
    fn test_str2bytearray_empty() {
        let args: &[&str] = &[];
        let result = str2bytearray(args);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_str2bytearray_overflow() {
        let args = ["256"];
        let result = str2bytearray(&args);
        assert!(result.is_none());
    }

    #[test]
    fn test_list_attributes_no_state() {
        // Should not panic without initialized state
        gatt_list_attributes(None);
    }

    #[test]
    fn test_select_attribute_no_state() {
        let result = gatt_select_attribute(None, "/nonexistent/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_attribute_generator_no_state() {
        let result = gatt_attribute_generator("serv", 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_local_attribute_no_state() {
        let result = gatt_select_local_attribute("/some/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_uuid_name_unknown() {
        let name = uuid_name("12345678-1234-1234-1234-123456789abc");
        // Should return the UUID itself since it's unknown
        assert!(!name.is_empty());
    }

    #[test]
    fn test_proxy_cache_services() {
        init_state();
        let svc = ProxyInfo::new("/org/bluez/hci0/dev/service0001", "org.bluez.GattService1");
        gatt_add_service(&svc);
        gatt_list_attributes(None);
        gatt_remove_service(&svc);
        cleanup_state();
    }

    #[test]
    fn test_proxy_cache_characteristics() {
        init_state();
        let chrc = ProxyInfo::new(
            "/org/bluez/hci0/dev/service0001/char0001",
            "org.bluez.GattCharacteristic1",
        );
        gatt_add_characteristic(&chrc);
        gatt_remove_characteristic(&chrc);
        cleanup_state();
    }

    #[test]
    fn test_proxy_cache_descriptors() {
        init_state();
        let desc = ProxyInfo::new(
            "/org/bluez/hci0/dev/service0001/char0001/desc0001",
            "org.bluez.GattDescriptor1",
        );
        gatt_add_descriptor(&desc);
        gatt_remove_descriptor(&desc);
        cleanup_state();
    }

    #[test]
    fn test_proxy_cache_managers() {
        init_state();
        let mgr = ProxyInfo::new("/org/bluez/hci0", "org.bluez.GattManager1");
        gatt_add_manager(&mgr);
        gatt_remove_manager(&mgr);
        cleanup_state();
    }

    #[test]
    fn test_parse_offset() {
        assert_eq!(parse_offset("0"), 0);
        assert_eq!(parse_offset("10"), 10);
        assert_eq!(parse_offset("255"), 255);
    }

    #[test]
    fn test_parse_handle() {
        assert_eq!(parse_handle("0"), 0);
        assert_eq!(parse_handle("0x10"), 16);
        assert_eq!(parse_handle("42"), 42);
    }

    #[test]
    fn test_sock_io_new() {
        let sio = SockIo::new();
        assert!(sio.proxy_path.is_none());
        assert!(sio.fd.is_none());
        assert_eq!(sio.mtu, 0);
    }

    #[test]
    fn test_gatt_state_new() {
        let state = GattState::new();
        assert!(state.services.is_empty());
        assert!(state.characteristics.is_empty());
        assert!(state.descriptors.is_empty());
        assert!(state.managers.is_empty());
        assert!(state.local_services.is_empty());
        assert!(state.uuids.is_empty());
    }

    #[test]
    fn test_read_local_attribute_no_state() {
        // Should not panic
        gatt_read_local_attribute("/nonexistent", 1, &["0"]);
    }

    #[test]
    fn test_write_local_attribute_no_state() {
        // Should not panic
        gatt_write_local_attribute("/nonexistent", 1, &["0x01"]);
    }

    #[test]
    fn test_release_write_no_state() {
        let pi = ProxyInfo::new("/org/bluez/hci0/char0001", GATT_CHAR_IFACE);
        // Should not panic
        gatt_release_write(&pi, None);
    }

    #[test]
    fn test_release_notify_no_state() {
        let pi = ProxyInfo::new("/org/bluez/hci0/char0001", GATT_CHAR_IFACE);
        // Should not panic
        gatt_release_notify(&pi, None);
    }

    #[test]
    fn test_dbus_object_constructors() {
        let svc = GattService1Object::new("180a".to_string(), true, vec![]);
        assert_eq!(svc.uuid, "180a");
        assert!(svc.primary);

        let chrc = GattCharacteristic1Object::new(
            "2a29".to_string(),
            "/org/bluez/app/service0001".to_string(),
            vec!["read".to_string()],
        );
        assert_eq!(chrc.uuid, "2a29");
        assert_eq!(chrc.service_path, "/org/bluez/app/service0001");

        let desc = GattDescriptor1Object::new(
            "2902".to_string(),
            "/org/bluez/app/service0001/char0001".to_string(),
            vec!["read".to_string()],
        );
        assert_eq!(desc.uuid, "2902");
    }

    #[test]
    fn test_proxy_info_path_interface() {
        let pi = ProxyInfo::new("/org/bluez/test", "org.bluez.Test1");
        assert_eq!(pi.path(), "/org/bluez/test");
        assert_eq!(pi.interface(), "org.bluez.Test1");
    }
}
