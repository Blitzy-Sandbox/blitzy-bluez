// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2004‑2010  Marcel Holtmann <marcel@holtmann.org>
//
// Hostname synchronisation plugin — Rust rewrite of plugins/hostname.c
//
// Watches the `org.freedesktop.hostname1` D‑Bus service for hostname and
// chassis changes, and monitors `/proc/sys/kernel/hostname` for kernel
// hostname changes.  Updates adapter names and Bluetooth device classes
// accordingly.

use std::sync::{Arc, Mutex};

use futures::StreamExt;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;

use crate::adapter::{
    BtdAdapter, BtdAdapterDriver, adapter_find, btd_adapter_foreach, btd_adapter_get_index,
    btd_adapter_is_default, btd_adapter_set_class, btd_adapter_set_name,
    btd_register_adapter_driver, btd_unregister_adapter_driver,
};
use crate::dbus_common::btd_get_dbus_connection;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error};
use crate::plugin::{BluetoothPlugin, PluginPriority};

// ---------------------------------------------------------------------------
// Bluetooth Class of Device constants (matching C lines 33‑43)
// ---------------------------------------------------------------------------

/// Major Class: Miscellaneous (default when chassis type is unknown).
const MAJOR_CLASS_MISCELLANEOUS: u8 = 0x00;

/// Major Class: Computer.
const MAJOR_CLASS_COMPUTER: u8 = 0x01;

/// Minor Class: Uncategorized (default).
const MINOR_CLASS_UNCATEGORIZED: u8 = 0x00;

/// Minor Class: Desktop workstation.
const MINOR_CLASS_DESKTOP: u8 = 0x01;

/// Minor Class: Server‑class computer.
const MINOR_CLASS_SERVER: u8 = 0x02;

/// Minor Class: Laptop.
const MINOR_CLASS_LAPTOP: u8 = 0x03;

/// Minor Class: Handheld PC / PDA, clamshell.
const MINOR_CLASS_HANDHELD: u8 = 0x04;

/// Minor Class: Palm‑size PC / PDA.
/// Kept for specification completeness; not referenced by current chassis table.
#[allow(dead_code)]
const MINOR_CLASS_PALM_SIZED: u8 = 0x05;

/// Minor Class: Wearable computer (watch‑size).
/// Kept for specification completeness; not referenced by current chassis table.
#[allow(dead_code)]
const MINOR_CLASS_WEARABLE: u8 = 0x06;

/// Minor Class: Tablet.
const MINOR_CLASS_TABLET: u8 = 0x07;

// ---------------------------------------------------------------------------
// Chassis → Bluetooth Class mapping table  (matching C lines 111‑122)
// ---------------------------------------------------------------------------

/// One entry of the chassis→class lookup table.
struct ChassisEntry {
    chassis: &'static str,
    major_class: u8,
    minor_class: u8,
}

/// Static table mapping chassis strings from `org.freedesktop.hostname1`
/// (or from the DMI → string translation) to Bluetooth major/minor class.
static CHASSIS_TABLE: &[ChassisEntry] = &[
    ChassisEntry {
        chassis: "desktop",
        major_class: MAJOR_CLASS_COMPUTER,
        minor_class: MINOR_CLASS_DESKTOP,
    },
    ChassisEntry {
        chassis: "server",
        major_class: MAJOR_CLASS_COMPUTER,
        minor_class: MINOR_CLASS_SERVER,
    },
    ChassisEntry {
        chassis: "laptop",
        major_class: MAJOR_CLASS_COMPUTER,
        minor_class: MINOR_CLASS_LAPTOP,
    },
    ChassisEntry {
        chassis: "handset",
        major_class: MAJOR_CLASS_COMPUTER,
        minor_class: MINOR_CLASS_HANDHELD,
    },
    ChassisEntry {
        chassis: "tablet",
        major_class: MAJOR_CLASS_COMPUTER,
        minor_class: MINOR_CLASS_TABLET,
    },
];

// ---------------------------------------------------------------------------
// Module‑level state  (replaces C file‑scope globals)
// ---------------------------------------------------------------------------

/// Plugin state protected by a `std::sync::Mutex` for safe access from both
/// synchronous (plugin init/exit, adapter driver probe/remove) and
/// asynchronous (D‑Bus watcher, `/proc` watcher) contexts.
struct HostnameState {
    /// Bluetooth major device class derived from chassis type.
    major_class: u8,
    /// Bluetooth minor device class derived from chassis type.
    minor_class: u8,
    /// Pretty hostname from D‑Bus `PrettyHostname` property.
    /// `None` → never received from D‑Bus yet.
    /// `Some("")` → received but empty.
    pretty_hostname: Option<String>,
    /// Static hostname from D‑Bus `StaticHostname` property.
    static_hostname: Option<String>,
    /// Transient (kernel) hostname, read from `/proc/sys/kernel/hostname`.
    transient_hostname: Option<String>,
    /// Handle of the D‑Bus property watcher task.
    dbus_watch_handle: Option<JoinHandle<()>>,
    /// Handle of the `/proc/sys/kernel/hostname` watcher task.
    hostname_watch_handle: Option<JoinHandle<()>>,
}

/// Global plugin state.  All fields are `const`‑initialisable so the `Mutex`
/// can live in a `static`.
static STATE: Mutex<HostnameState> = Mutex::new(HostnameState {
    major_class: MAJOR_CLASS_MISCELLANEOUS,
    minor_class: MINOR_CLASS_UNCATEGORIZED,
    pretty_hostname: None,
    static_hostname: None,
    transient_hostname: None,
    dbus_watch_handle: None,
    hostname_watch_handle: None,
});

// ---------------------------------------------------------------------------
// Hostname resolution  (matching C `get_hostname()` lines 57‑73)
// ---------------------------------------------------------------------------

/// Determine the effective hostname for adapter naming.
///
/// Priority order (identical to C):
/// 1. Non‑empty `pretty_hostname` (if received from D‑Bus).
/// 2. Non‑empty `static_hostname` (if pretty was received but empty).
/// 3. Non‑empty `transient_hostname` (fallback to kernel hostname).
/// 4. `None` if `pretty_hostname` was never received.
fn get_hostname_from_state(state: &HostnameState) -> Option<&str> {
    // C: if (!pretty_hostname) return NULL;
    let pretty = state.pretty_hostname.as_ref()?;

    // C: if (strlen(pretty_hostname) > 0) return pretty_hostname;
    if !pretty.is_empty() {
        return Some(pretty.as_str());
    }

    // pretty was received but empty — fall through to static
    if let Some(ref static_h) = state.static_hostname {
        if !static_h.is_empty() {
            return Some(static_h.as_str());
        }
    }

    // Both empty — try transient
    if let Some(ref transient) = state.transient_hostname {
        if !transient.is_empty() {
            return Some(transient.as_str());
        }
    }

    // C: return NULL;  (pretty was received but all candidates empty)
    None
}

/// Convenience wrapper that returns an owned `String` for use across `await`
/// points.
fn get_hostname_owned() -> Option<String> {
    let state = STATE.lock().unwrap();
    get_hostname_from_state(&state).map(String::from)
}

// ---------------------------------------------------------------------------
// Adapter update helpers (async)
// ---------------------------------------------------------------------------

/// Update adapter names for all adapters.
///
/// Replicates C `btd_adapter_foreach(update_name, NULL)`.
/// Default adapter gets the bare hostname; non‑default adapters get a
/// suffixed name like `"MyHost #2"` (matching C line 91).
async fn update_all_names() {
    let hostname = match get_hostname_owned() {
        Some(h) => h,
        None => return,
    };

    // Collect Arcs from the `Fn` (not `FnMut`) foreach closure using a Mutex
    // for interior mutability.
    let collector: Mutex<Vec<_>> = Mutex::new(Vec::new());
    btd_adapter_foreach(|a| {
        collector.lock().unwrap().push(a.clone());
    })
    .await;
    let adapters = collector.into_inner().unwrap();

    for adapter_arc in &adapters {
        let is_default = btd_adapter_is_default(adapter_arc).await;
        let index = btd_adapter_get_index(adapter_arc).await;

        let name =
            if is_default { hostname.clone() } else { format!("{} #{}", hostname, index + 1) };

        btd_debug(index, &format!("name: {}", name));
        let _ = btd_adapter_set_name(adapter_arc, &name).await;
    }
}

/// Update device class for all adapters.
///
/// Replicates C `btd_adapter_foreach(update_class, NULL)`.
/// Only sets the class if a meaningful chassis type was detected
/// (major class ≠ MISCELLANEOUS).
async fn update_all_classes() {
    let (major, minor) = {
        let state = STATE.lock().unwrap();
        (state.major_class, state.minor_class)
    };

    if major == MAJOR_CLASS_MISCELLANEOUS {
        return;
    }

    let collector: Mutex<Vec<_>> = Mutex::new(Vec::new());
    btd_adapter_foreach(|a| {
        collector.lock().unwrap().push(a.clone());
    })
    .await;
    let adapters = collector.into_inner().unwrap();

    for adapter_arc in &adapters {
        let index = btd_adapter_get_index(adapter_arc).await;
        btd_debug(index, &format!("major: 0x{:02x} minor: 0x{:02x}", major, minor));
        let _ = btd_adapter_set_class(adapter_arc, major, minor).await;
    }
}

// ---------------------------------------------------------------------------
// DMI chassis‑type fallback  (matching C `read_dmi_fallback()` lines 238‑289)
// ---------------------------------------------------------------------------

/// Read `/sys/class/dmi/id/chassis_type`, map the integer to a chassis
/// string, and look up the corresponding Bluetooth major/minor class.
fn read_dmi_fallback() {
    let contents = match std::fs::read_to_string("/sys/class/dmi/id/chassis_type") {
        Ok(c) => c,
        Err(_) => return,
    };

    let chassis_type: i32 = match contents.trim().parse() {
        Ok(t) => t,
        Err(_) => return,
    };

    // Range check matching C: `if (type < 0 || type > 0x1D) return;`
    if !(0..=0x1D).contains(&chassis_type) {
        return;
    }

    // Map DMI chassis type integer to chassis string.
    let chassis_str = match chassis_type {
        0x3 | 0x4 | 0x6 | 0x7 => "desktop",
        0x8 | 0x9 | 0xA | 0xE => "laptop",
        0xB => "handset",
        0x11 | 0x1C => "server",
        _ => return,
    };

    tracing::debug!("chassis: {}", chassis_str);

    // Look up in the chassis table.
    for entry in CHASSIS_TABLE {
        if entry.chassis == chassis_str {
            let mut state = STATE.lock().unwrap();
            state.major_class = entry.major_class;
            state.minor_class = entry.minor_class;
            tracing::debug!(
                "major: 0x{:02x} minor: 0x{:02x}",
                entry.major_class,
                entry.minor_class
            );
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Transient hostname reading  (matching C `read_transient_hostname()` 191‑206)
// ---------------------------------------------------------------------------

/// Read the transient hostname from `/proc/sys/kernel/hostname`.
///
/// The C code uses `uname(2)` which reads the same kernel value.
/// Reading the procfs file directly is equivalent and avoids an
/// additional nix feature‑gate dependency.
fn read_transient_hostname() {
    match std::fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(raw) => {
            let hostname = raw.trim().to_string();
            tracing::debug!("read transient hostname: '{}'", hostname);
            STATE.lock().unwrap().transient_hostname = Some(hostname);
        }
        Err(e) => {
            btd_error(0xFFFF, &format!("read /proc/sys/kernel/hostname: {}", e));
            STATE.lock().unwrap().transient_hostname = None;
        }
    }
}

// ---------------------------------------------------------------------------
// Chassis string handling
// ---------------------------------------------------------------------------

/// Look up a chassis string in the chassis table and update the module
/// state's major/minor class if found.
fn handle_chassis_change(chassis: &str) {
    tracing::debug!("chassis: '{}'", chassis);

    for entry in CHASSIS_TABLE {
        if entry.chassis == chassis {
            let mut state = STATE.lock().unwrap();
            state.major_class = entry.major_class;
            state.minor_class = entry.minor_class;
            tracing::debug!(
                "major: 0x{:02x} minor: 0x{:02x}",
                entry.major_class,
                entry.minor_class
            );
            return;
        }
    }
    // Unknown chassis string — leave class unchanged (matches C default).
}

// ---------------------------------------------------------------------------
// D‑Bus hostname1 property watcher
// ---------------------------------------------------------------------------

/// zbus proxy definition for `org.freedesktop.hostname1`.
///
/// The `#[zbus::proxy]` macro generates `Hostname1Proxy` with typed getters
/// and `receive_<property>_changed()` streams for each `#[zbus(property)]`
/// annotation.
#[zbus::proxy(
    interface = "org.freedesktop.hostname1",
    default_service = "org.freedesktop.hostname1",
    default_path = "/org/freedesktop/hostname1"
)]
trait Hostname1 {
    /// The pretty hostname (user‑visible, may contain special characters).
    #[zbus(property)]
    fn pretty_hostname(&self) -> zbus::Result<String>;

    /// The static hostname (lower‑case, no special characters).
    #[zbus(property)]
    fn static_hostname(&self) -> zbus::Result<String>;

    /// The chassis type string (desktop, laptop, server, etc.).
    #[zbus(property)]
    fn chassis(&self) -> zbus::Result<String>;
}

/// Background task that monitors hostname1 D‑Bus properties.
///
/// Creates a zbus proxy to `org.freedesktop.hostname1` and watches for
/// `PrettyHostname`, `StaticHostname`, and `Chassis` property changes.
/// On change, updates module state and triggers adapter name/class updates.
///
/// Replaces C `hostname_client` + `hostname_proxy` + `property_changed`
/// callback (lines 291‑317 of `plugins/hostname.c`).
async fn dbus_property_watcher() {
    let conn = btd_get_dbus_connection().clone();

    // Build the hostname1 proxy.
    let proxy = match Hostname1Proxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to create hostname1 proxy: {}", e);
            return;
        }
    };

    // Read initial property values.
    if let Ok(pretty) = proxy.pretty_hostname().await {
        tracing::debug!("pretty hostname: '{}'", pretty);
        STATE.lock().unwrap().pretty_hostname = Some(pretty);
    }
    if let Ok(static_h) = proxy.static_hostname().await {
        tracing::debug!("static hostname: '{}'", static_h);
        STATE.lock().unwrap().static_hostname = Some(static_h);
    }
    if let Ok(chassis) = proxy.chassis().await {
        handle_chassis_change(&chassis);
    }

    // Trigger initial adapter updates now that D‑Bus values are available.
    update_all_names().await;
    update_all_classes().await;

    // Subscribe to property change streams.
    let mut pretty_stream = proxy.receive_pretty_hostname_changed().await;
    let mut static_stream = proxy.receive_static_hostname_changed().await;
    let mut chassis_stream = proxy.receive_chassis_changed().await;

    // Event loop — watch all three properties concurrently.
    loop {
        tokio::select! {
            Some(change) = pretty_stream.next() => {
                if let Ok(val) = change.get().await {
                    tracing::debug!("pretty hostname: '{}'", val);
                    STATE.lock().unwrap().pretty_hostname = Some(val);
                    update_all_names().await;
                }
            }
            Some(change) = static_stream.next() => {
                if let Ok(val) = change.get().await {
                    tracing::debug!("static hostname: '{}'", val);
                    STATE.lock().unwrap().static_hostname = Some(val);
                    update_all_names().await;
                }
            }
            Some(change) = chassis_stream.next() => {
                if let Ok(val) = change.get().await {
                    handle_chassis_change(&val);
                    update_all_classes().await;
                }
            }
            else => break,
        }
    }
}

// ---------------------------------------------------------------------------
// /proc/sys/kernel/hostname watcher  (matching C hostname_cb lines 208‑215)
// ---------------------------------------------------------------------------

/// Background task monitoring `/proc/sys/kernel/hostname` for changes.
///
/// Opens the file read‑only and monitors it with `AsyncFd`.  On procfs
/// sysctl nodes, the kernel signals changes via `POLLERR | EPOLLPRI` which
/// epoll delivers even when only `EPOLLIN` is requested.
///
/// When a change is detected the transient hostname is re‑read and —
/// matching the original C behaviour — `update_all_classes()` is called
/// (the C code calls `btd_adapter_foreach(update_class, NULL)` here, which
/// appears intentional in the original even though one might expect
/// `update_name`).
async fn proc_hostname_watcher() {
    let file = match std::fs::File::open("/proc/sys/kernel/hostname") {
        Ok(f) => f,
        Err(e) => {
            btd_error(0xFFFF, &format!("open /proc/sys/kernel/hostname: {}", e));
            return;
        }
    };

    let async_fd = match AsyncFd::with_interest(file, Interest::READABLE) {
        Ok(fd) => fd,
        Err(e) => {
            btd_error(0xFFFF, &format!("AsyncFd for /proc/sys/kernel/hostname: {}", e));
            return;
        }
    };

    loop {
        // Wait for any event on the fd.  POLLERR on procfs sysctl nodes
        // triggers EPOLLIN readiness in epoll as well.
        match async_fd.readable().await {
            Ok(mut guard) => {
                guard.clear_ready();
            }
            Err(e) => {
                btd_error(0xFFFF, &format!("hostname watch error: {}", e));
                break;
            }
        }

        tracing::debug!("transient hostname changed");
        read_transient_hostname();

        // Note: the original C code calls update_class here, not
        // update_name.  We preserve this behaviour exactly.
        update_all_classes().await;
    }
}

// ---------------------------------------------------------------------------
// Adapter driver  (matching C `hostname_driver` lines 224‑232)
// ---------------------------------------------------------------------------

/// Adapter driver that sets the Bluetooth adapter name and class when a
/// new adapter is probed.
struct HostnameAdapterDriver;

impl BtdAdapterDriver for HostnameAdapterDriver {
    fn name(&self) -> &str {
        "hostname"
    }

    /// Called when an adapter becomes available.
    ///
    /// Reads the current hostname and chassis state from module globals and
    /// spawns an async task to set the adapter's name and class via MGMT.
    fn probe(&self, adapter: Arc<TokioMutex<BtdAdapter>>) -> Result<(), BtdError> {
        let index = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { adapter.lock().await.index })
        });
        tracing::debug!("hostname driver probe for hci{}", index);

        // Spawn an async task to update this adapter.  We cannot perform
        // async MGMT operations from within the synchronous `probe`
        // callback, so we look the adapter up again by index.
        tokio::spawn(async move {
            if let Some(adapter_arc) = adapter_find(index).await {
                // -- update name --
                let hostname = get_hostname_owned();
                if let Some(hostname) = hostname {
                    let is_default = btd_adapter_is_default(&adapter_arc).await;
                    let name =
                        if is_default { hostname } else { format!("{} #{}", hostname, index + 1) };
                    btd_debug(index, &format!("name: {}", name));
                    let _ = btd_adapter_set_name(&adapter_arc, &name).await;
                }

                // -- update class --
                let (major, minor) = {
                    let state = STATE.lock().unwrap();
                    (state.major_class, state.minor_class)
                };
                if major != MAJOR_CLASS_MISCELLANEOUS {
                    btd_debug(index, &format!("major: 0x{:02x} minor: 0x{:02x}", major, minor));
                    let _ = btd_adapter_set_class(&adapter_arc, major, minor).await;
                }
            }
        });

        Ok(())
    }

    /// Called when an adapter is removed — no‑op, matching C `hostname_remove`.
    fn remove(&self, _adapter: Arc<TokioMutex<BtdAdapter>>) {}
}

// ---------------------------------------------------------------------------
// Plugin init / exit  (matching C lines 291‑362)
// ---------------------------------------------------------------------------

/// Plugin initialisation entry point.
///
/// 1. Read DMI chassis type from sysfs.
/// 2. Read transient hostname from `/proc/sys/kernel/hostname`.
/// 3. Spawn the D‑Bus property watcher task.
/// 4. Register the hostname adapter driver (spawned async).
/// 5. Spawn the `/proc/sys/kernel/hostname` watcher task.
fn hostname_init() -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!("hostname plugin init");

    // Synchronous preparatory work.
    read_dmi_fallback();
    read_transient_hostname();

    // Spawn the D‑Bus property watcher.
    let dbus_handle = tokio::spawn(dbus_property_watcher());

    // Spawn the /proc hostname watcher.
    let proc_handle = tokio::spawn(proc_hostname_watcher());

    {
        let mut state = STATE.lock().unwrap();
        state.dbus_watch_handle = Some(dbus_handle);
        state.hostname_watch_handle = Some(proc_handle);
    }

    // Register the adapter driver asynchronously.  We cannot use
    // `block_in_place` in all contexts (e.g. current‑thread runtime), so
    // we spawn instead.  The driver will be registered very shortly after
    // init returns which is acceptable because MGMT operations are also
    // inherently async.
    tokio::spawn(async {
        let driver: Arc<dyn BtdAdapterDriver> = Arc::new(HostnameAdapterDriver);
        btd_register_adapter_driver(driver).await;
    });

    Ok(())
}

/// Plugin exit entry point.
///
/// Unregisters the adapter driver, aborts background watcher tasks, and
/// resets module state.
fn hostname_exit() {
    tracing::debug!("hostname plugin exit");

    // Unregister adapter driver — spawn async since exit is synchronous.
    tokio::spawn(async {
        btd_unregister_adapter_driver("hostname").await;
    });

    // Abort watcher tasks and clear state.
    let mut state = STATE.lock().unwrap();
    if let Some(handle) = state.dbus_watch_handle.take() {
        handle.abort();
    }
    if let Some(handle) = state.hostname_watch_handle.take() {
        handle.abort();
    }
    state.pretty_hostname = None;
    state.static_hostname = None;
    state.transient_hostname = None;
    state.major_class = MAJOR_CLASS_MISCELLANEOUS;
    state.minor_class = MINOR_CLASS_UNCATEGORIZED;
}

// ---------------------------------------------------------------------------
// Exported plugin struct  (schema: HostnamePlugin)
// ---------------------------------------------------------------------------

/// Public plugin descriptor implementing `BluetoothPlugin`.
///
/// Exposes `name()`, `version()`, `priority()`, `init()`, `exit()` as
/// required by the export schema.
pub struct HostnamePlugin;

impl BluetoothPlugin for HostnamePlugin {
    fn name(&self) -> &str {
        "hostname"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        hostname_init()
    }

    fn exit(&self) {
        hostname_exit();
    }
}

// ---------------------------------------------------------------------------
// Plugin registration via inventory  (replaces BLUETOOTH_PLUGIN_DEFINE)
// ---------------------------------------------------------------------------

/// Register the hostname plugin at link time so that `plugin_init()` in the
/// plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
#[allow(unsafe_code)]
mod _hostname_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "hostname",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::hostname_init,
            exit: super::hostname_exit,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit‑test helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_hostname_priority_pretty() {
        let state = HostnameState {
            major_class: 0,
            minor_class: 0,
            pretty_hostname: Some("My Pretty Host".to_string()),
            static_hostname: Some("statichost".to_string()),
            transient_hostname: Some("transienthost".to_string()),
            dbus_watch_handle: None,
            hostname_watch_handle: None,
        };
        assert_eq!(get_hostname_from_state(&state), Some("My Pretty Host"));
    }

    #[test]
    fn test_get_hostname_priority_static_when_pretty_empty() {
        let state = HostnameState {
            major_class: 0,
            minor_class: 0,
            pretty_hostname: Some(String::new()),
            static_hostname: Some("statichost".to_string()),
            transient_hostname: Some("transienthost".to_string()),
            dbus_watch_handle: None,
            hostname_watch_handle: None,
        };
        assert_eq!(get_hostname_from_state(&state), Some("statichost"));
    }

    #[test]
    fn test_get_hostname_priority_transient_when_both_empty() {
        let state = HostnameState {
            major_class: 0,
            minor_class: 0,
            pretty_hostname: Some(String::new()),
            static_hostname: Some(String::new()),
            transient_hostname: Some("transienthost".to_string()),
            dbus_watch_handle: None,
            hostname_watch_handle: None,
        };
        assert_eq!(get_hostname_from_state(&state), Some("transienthost"));
    }

    #[test]
    fn test_get_hostname_none_when_pretty_never_received() {
        let state = HostnameState {
            major_class: 0,
            minor_class: 0,
            pretty_hostname: None,
            static_hostname: Some("statichost".to_string()),
            transient_hostname: Some("transienthost".to_string()),
            dbus_watch_handle: None,
            hostname_watch_handle: None,
        };
        assert_eq!(get_hostname_from_state(&state), None);
    }

    #[test]
    fn test_get_hostname_none_when_all_empty() {
        let state = HostnameState {
            major_class: 0,
            minor_class: 0,
            pretty_hostname: Some(String::new()),
            static_hostname: Some(String::new()),
            transient_hostname: Some(String::new()),
            dbus_watch_handle: None,
            hostname_watch_handle: None,
        };
        assert_eq!(get_hostname_from_state(&state), None);
    }

    #[test]
    fn test_chassis_table_desktop() {
        for entry in CHASSIS_TABLE {
            if entry.chassis == "desktop" {
                assert_eq!(entry.major_class, MAJOR_CLASS_COMPUTER);
                assert_eq!(entry.minor_class, MINOR_CLASS_DESKTOP);
                return;
            }
        }
        panic!("desktop entry missing from chassis table");
    }

    #[test]
    fn test_chassis_table_server() {
        for entry in CHASSIS_TABLE {
            if entry.chassis == "server" {
                assert_eq!(entry.major_class, MAJOR_CLASS_COMPUTER);
                assert_eq!(entry.minor_class, MINOR_CLASS_SERVER);
                return;
            }
        }
        panic!("server entry missing from chassis table");
    }

    #[test]
    fn test_chassis_table_laptop() {
        for entry in CHASSIS_TABLE {
            if entry.chassis == "laptop" {
                assert_eq!(entry.major_class, MAJOR_CLASS_COMPUTER);
                assert_eq!(entry.minor_class, MINOR_CLASS_LAPTOP);
                return;
            }
        }
        panic!("laptop entry missing from chassis table");
    }

    #[test]
    fn test_chassis_table_handset() {
        for entry in CHASSIS_TABLE {
            if entry.chassis == "handset" {
                assert_eq!(entry.major_class, MAJOR_CLASS_COMPUTER);
                assert_eq!(entry.minor_class, MINOR_CLASS_HANDHELD);
                return;
            }
        }
        panic!("handset entry missing from chassis table");
    }

    #[test]
    fn test_chassis_table_tablet() {
        for entry in CHASSIS_TABLE {
            if entry.chassis == "tablet" {
                assert_eq!(entry.major_class, MAJOR_CLASS_COMPUTER);
                assert_eq!(entry.minor_class, MINOR_CLASS_TABLET);
                return;
            }
        }
        panic!("tablet entry missing from chassis table");
    }

    #[test]
    fn test_constants_match_c() {
        assert_eq!(MAJOR_CLASS_MISCELLANEOUS, 0x00);
        assert_eq!(MAJOR_CLASS_COMPUTER, 0x01);
        assert_eq!(MINOR_CLASS_UNCATEGORIZED, 0x00);
        assert_eq!(MINOR_CLASS_DESKTOP, 0x01);
        assert_eq!(MINOR_CLASS_SERVER, 0x02);
        assert_eq!(MINOR_CLASS_LAPTOP, 0x03);
        assert_eq!(MINOR_CLASS_HANDHELD, 0x04);
        assert_eq!(MINOR_CLASS_PALM_SIZED, 0x05);
        assert_eq!(MINOR_CLASS_WEARABLE, 0x06);
        assert_eq!(MINOR_CLASS_TABLET, 0x07);
    }
}
