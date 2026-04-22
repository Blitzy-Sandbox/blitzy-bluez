// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2021 Google LLC
//
//! Admin policy submenu — Rust rewrite of `client/admin.c`.
//!
//! Provides the "admin" submenu for viewing and updating
//! `AdminPolicySet1`/`AdminPolicyStatus1` D-Bus proxy interfaces.
//!
//! # Behavioral Fidelity
//!
//! This module produces identical shell output and accepts identical command
//! arguments as the C original (`client/admin.c`, 217 lines).  The "allow"
//! command reads or sets the `ServiceAllowList` through the `org.bluez`
//! admin-policy D-Bus interfaces, replicating the exact error messages,
//! output formatting, and non-interactive exit behavior.

use std::sync::{Arc, LazyLock};

use futures::StreamExt as _;
use tokio::sync::Mutex;
use zbus::Connection;
use zbus::zvariant::OwnedValue;

use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, bt_shell_add_submenu, bt_shell_get_env,
    bt_shell_noninteractive_quit, bt_shell_printf, bt_shell_remove_submenu,
};

// ---------------------------------------------------------------------------
// Constants — matching libc EXIT_SUCCESS / EXIT_FAILURE
// ---------------------------------------------------------------------------

/// Successful exit status for `bt_shell_noninteractive_quit`.
const EXIT_SUCCESS: i32 = 0;
/// Failure exit status for `bt_shell_noninteractive_quit`.
const EXIT_FAILURE: i32 = 1;

/// D-Bus well-known name of the BlueZ daemon.
const BLUEZ_SERVICE: &str = "org.bluez";
/// D-Bus interface for admin policy configuration (write path).
const ADMIN_POLICY_SET_IFACE: &str = "org.bluez.AdminPolicySet1";
/// D-Bus interface for admin policy status (read path).
const ADMIN_POLICY_STATUS_IFACE: &str = "org.bluez.AdminPolicyStatus1";

// ---------------------------------------------------------------------------
// Module state — replaces C static variables (admin.c lines 25-28, 188)
// ---------------------------------------------------------------------------

/// Module-level mutable state replacing the C static variables:
///
/// - `DBusConnection *dbus_conn`  → `dbus_conn: Option<Connection>`
/// - `GList *admin_proxies`       → `admin_proxy_paths: Vec<String>`
/// - `GDBusProxy *set_proxy`      → `set_proxy_path: Option<String>`
/// - `GDBusProxy *status_proxy`   → `status_proxy_path: Option<String>`
/// - `GDBusClient *client`        → `watcher_active: bool`
///
/// Proxies are not cached directly because `zbus::proxy::Proxy<'a>` carries a
/// lifetime tied to the `Connection` reference.  Instead we store the object
/// paths and create short-lived proxies on demand within async helpers.
struct AdminState {
    /// D-Bus connection retrieved from the shell environment.
    dbus_conn: Option<Connection>,
    /// Object path where `AdminPolicySet1` was discovered.
    set_proxy_path: Option<String>,
    /// Object path where the most-recently-added `AdminPolicyStatus1` lives.
    status_proxy_path: Option<String>,
    /// All discovered `AdminPolicyStatus1` object paths (replaces `GList`).
    admin_proxy_paths: Vec<String>,
    /// Whether the background D-Bus watcher task has been spawned.
    watcher_active: bool,
}

impl AdminState {
    /// Create a fresh, empty state.
    fn new() -> Self {
        AdminState {
            dbus_conn: None,
            set_proxy_path: None,
            status_proxy_path: None,
            admin_proxy_paths: Vec::new(),
            watcher_active: false,
        }
    }

    /// Reset all fields — equivalent to the C disconnect handler + client unref.
    fn clear(&mut self) {
        self.dbus_conn = None;
        self.set_proxy_path = None;
        self.status_proxy_path = None;
        self.admin_proxy_paths.clear();
        self.watcher_active = false;
    }
}

/// Global admin module state, protected by a `tokio::sync::Mutex` for safe
/// access from both synchronous shell callbacks (via `blocking_lock`) and
/// asynchronous watcher tasks (via `.lock().await`).
static STATE: LazyLock<Arc<Mutex<AdminState>>> =
    LazyLock::new(|| Arc::new(Mutex::new(AdminState::new())));

// ---------------------------------------------------------------------------
// Admin menu definition — replaces C `admin_menu` (admin.c lines 142-150)
// ---------------------------------------------------------------------------

/// The "admin" submenu registered with the shell framework.
static ADMIN_MENU: BtShellMenu = BtShellMenu {
    name: "admin",
    desc: Some("Admin Policy Submenu"),
    pre_run: Some(admin_menu_pre_run),
    entries: &[BtShellMenuEntry {
        cmd: "allow",
        arg: Some("[clear/uuid1 uuid2 ...]"),
        func: cmd_admin_allow,
        desc: "Allow service UUIDs and block rest of them",
        r#gen: None,
        disp: None,
        exists: None,
    }],
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register the admin submenu with the shell.
///
/// Replaces C `admin_add_submenu()` (admin.c lines 196-199).
pub fn admin_add_submenu() {
    bt_shell_add_submenu(&ADMIN_MENU);
}

/// Unregister the admin submenu and clean up D-Bus client state.
///
/// Replaces C `admin_remove_submenu()` (admin.c lines 213-217).
/// The C original calls `g_dbus_client_unref(client); client = NULL;`.
pub fn admin_remove_submenu() {
    let state = STATE.clone();
    // Use blocking_lock because this is called from a synchronous context.
    state.blocking_lock().clear();
    bt_shell_remove_submenu(&ADMIN_MENU);
}

// ---------------------------------------------------------------------------
// Menu pre-run hook — replaces C `admin_menu_pre_run` (admin.c lines 201-211)
// ---------------------------------------------------------------------------

/// Lazy D-Bus client initialization, called each time the admin submenu is
/// entered.  Retrieves the D-Bus connection from the shell environment and
/// spawns a background watcher that monitors `org.bluez` for the appearance
/// and removal of `AdminPolicySet1` / `AdminPolicyStatus1` interfaces.
///
/// Replaces:
/// ```c
/// dbus_conn = bt_shell_get_env("DBUS_CONNECTION");
/// if (!dbus_conn || client) return;
/// client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");
/// g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed, NULL, NULL);
/// g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);
/// ```
fn admin_menu_pre_run(_menu: &BtShellMenu) {
    let conn: Connection = match bt_shell_get_env::<Connection>("DBUS_CONNECTION") {
        Some(c) => c,
        None => return,
    };

    let state = STATE.clone();

    // Guard: if watcher already active, nothing to do (mirrors `if (client) return;`).
    {
        let guard = state.blocking_lock();
        if guard.watcher_active {
            return;
        }
    }

    // Store the connection and mark watcher as active.
    {
        let mut guard = state.blocking_lock();
        guard.dbus_conn = Some(conn.clone());
        guard.watcher_active = true;
    }

    // Spawn background task to discover and monitor admin policy interfaces.
    let state_for_task = state;
    tokio::spawn(async move {
        run_proxy_watcher(conn, state_for_task).await;
    });
}

// ---------------------------------------------------------------------------
// Background D-Bus watcher — replaces GDBusClient proxy tracking
// ---------------------------------------------------------------------------

/// Background task that uses the D-Bus `ObjectManager` interface to discover
/// existing admin-policy interfaces and monitor for future additions/removals.
///
/// Replaces:
/// - `proxy_added` (admin.c lines 158-168)
/// - `proxy_removed` (admin.c lines 176-186)
/// - `disconnect_handler` (admin.c lines 190-194)
async fn run_proxy_watcher(conn: Connection, state: Arc<Mutex<AdminState>>) {
    // Build an ObjectManagerProxy for org.bluez at the ObjectManager root.
    let om_proxy = match zbus::fdo::ObjectManagerProxy::builder(&conn)
        .destination(BLUEZ_SERVICE)
        .expect("valid well-known name")
        .path("/org/bluez")
        .expect("valid object path")
        .build()
        .await
    {
        Ok(p) => p,
        Err(_) => return, // Service not available; silently exit.
    };

    // Phase 1: Discover already-exported objects.
    if let Ok(objects) = om_proxy.get_managed_objects().await {
        let mut guard = state.lock().await;
        for (path, interfaces) in &objects {
            let path_str = path.to_string();
            for iface_name in interfaces.keys() {
                match iface_name.as_str() {
                    iface if iface == ADMIN_POLICY_SET_IFACE => {
                        guard.set_proxy_path = Some(path_str.clone());
                    }
                    iface if iface == ADMIN_POLICY_STATUS_IFACE => {
                        guard.admin_proxy_paths.push(path_str.clone());
                        guard.status_proxy_path = Some(path_str.clone());
                    }
                    _ => {}
                }
            }
        }
    }

    // Phase 2: Monitor for future interface additions / removals.
    let added_stream = om_proxy.receive_interfaces_added().await;
    let removed_stream = om_proxy.receive_interfaces_removed().await;

    let (Ok(mut added_stream), Ok(mut removed_stream)) = (added_stream, removed_stream) else {
        return; // Signal subscription failed; give up silently.
    };

    loop {
        tokio::select! {
            added = added_stream.next() => {
                let Some(signal) = added else { break; };
                if let Ok(args) = signal.args() {
                    let path_str = args.object_path().to_string();
                    let mut guard = state.lock().await;
                    for iface_name in args.interfaces_and_properties().keys() {
                        match iface_name.as_str() {
                            iface if iface == ADMIN_POLICY_SET_IFACE => {
                                guard.set_proxy_path = Some(path_str.clone());
                            }
                            iface if iface == ADMIN_POLICY_STATUS_IFACE => {
                                guard.admin_proxy_paths.push(path_str.clone());
                                guard.status_proxy_path = Some(path_str.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
            removed = removed_stream.next() => {
                let Some(signal) = removed else { break; };
                if let Ok(args) = signal.args() {
                    let path_str = args.object_path().to_string();
                    let mut guard = state.lock().await;
                    for iface_name in args.interfaces().iter() {
                        match iface_name.as_str() {
                            iface if iface == ADMIN_POLICY_SET_IFACE => {
                                guard.set_proxy_path = None;
                            }
                            iface if iface == ADMIN_POLICY_STATUS_IFACE => {
                                guard.admin_proxy_paths.retain(|p| *p != path_str);
                                guard.status_proxy_path = None;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Streams ended — service disconnected.  Clear state (disconnect handler).
    let mut guard = state.lock().await;
    guard.admin_proxy_paths.clear();
    guard.set_proxy_path = None;
    guard.status_proxy_path = None;
}

// ---------------------------------------------------------------------------
// Command handler — replaces C `cmd_admin_allow` (admin.c lines 129-140)
// ---------------------------------------------------------------------------

/// Shell command handler for the "allow" command.
///
/// - No arguments: reads and prints the current `ServiceAllowList`.
/// - `clear`: sends an empty array (clears the allowlist).
/// - `uuid1 uuid2 ...`: sets the allowlist to the given UUIDs.
///
/// The "clear" keyword handling replicates the C behavior exactly:
/// when "clear" is the first argument, the argument count is decremented
/// by one but the argument pointer is *not* advanced past "clear".
/// This means `allow clear` sends `[]`, and `allow clear uuid1` sends
/// `["clear"]` — matching the C original byte-for-byte.
fn cmd_admin_allow(args: &[&str]) {
    if args.len() <= 1 {
        // No arguments — read the current allowlist.
        let state = STATE.clone();
        tokio::spawn(async move {
            let guard = state.lock().await;
            let (conn, path) = match (&guard.dbus_conn, &guard.status_proxy_path) {
                (Some(c), Some(p)) => (c.clone(), p.clone()),
                _ => {
                    bt_shell_printf(format_args!("Failed to get property\n"));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                    return;
                }
            };
            drop(guard);
            admin_policy_read_service_allowlist(&conn, &path).await;
        });
        return;
    }

    // Compute UUID count — "clear" keyword decrements count (C: argc--).
    let mut count = args.len() - 1;
    if args.get(1) == Some(&"clear") {
        count = count.saturating_sub(1);
    }

    // Take first `count` items from args[1..], replicating C argv+1 semantics.
    let uuids: Vec<String> = args[1..1 + count].iter().map(|s| (*s).to_string()).collect();

    let state = STATE.clone();
    tokio::spawn(async move {
        let guard = state.lock().await;
        let (conn, path) = match (&guard.dbus_conn, &guard.set_proxy_path) {
            (Some(c), Some(p)) => (c.clone(), p.clone()),
            _ => {
                bt_shell_printf(format_args!("Set proxy not ready\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        };
        drop(guard);
        admin_policy_set_service_allowlist(&conn, &path, &uuids).await;
    });
}

// ---------------------------------------------------------------------------
// D-Bus operations — async helpers
// ---------------------------------------------------------------------------

/// Read and print the `ServiceAllowList` property from `AdminPolicyStatus1`.
///
/// Replaces C `admin_policy_read_service_allowlist` (admin.c lines 42-68).
///
/// Output format (identical to C):
/// ```text
/// Service AllowedList:
/// \t<uuid1>
/// \t<uuid2>
/// ```
async fn admin_policy_read_service_allowlist(conn: &Connection, path: &str) {
    // Create a short-lived proxy for the status interface.
    let proxy: zbus::proxy::Proxy<'_> = match zbus::proxy::Builder::new(conn)
        .destination(BLUEZ_SERVICE)
        .expect("valid destination")
        .path(path)
        .expect("valid path")
        .interface(ADMIN_POLICY_STATUS_IFACE)
        .expect("valid interface")
        .build()
        .await
    {
        Ok(p) => p,
        Err(_) => {
            bt_shell_printf(format_args!("Failed to get property\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Fetch the property as a generic OwnedValue first, then attempt typed
    // extraction. This mirrors the C two-step check:
    //   1. g_dbus_proxy_get_property → "Failed to get property"
    //   2. dbus_message_iter_get_arg_type != DBUS_TYPE_ARRAY → "Unexpected return type"
    let value: OwnedValue = match proxy.get_property("ServiceAllowList").await {
        Ok(v) => v,
        Err(_) => {
            bt_shell_printf(format_args!("Failed to get property\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Attempt to extract a Vec<String> from the D-Bus array-of-strings value.
    let uuid_list: Vec<String> = match value.try_into() {
        Ok(list) => list,
        Err(_) => {
            bt_shell_printf(format_args!("Unexpected return type\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    bt_shell_printf(format_args!("Service AllowedList:\n"));
    for uuid in &uuid_list {
        bt_shell_printf(format_args!("\t{uuid}\n"));
    }
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Set the `ServiceAllowList` via the `SetServiceAllowList` method on
/// `AdminPolicySet1`.
///
/// Replaces C `admin_policy_set_service_allowlist` + `set_service_setup` +
/// `set_service_reply` (admin.c lines 75-127).
async fn admin_policy_set_service_allowlist(conn: &Connection, path: &str, uuids: &[String]) {
    // Create a short-lived proxy for the set interface.
    let proxy: zbus::proxy::Proxy<'_> = match zbus::proxy::Builder::new(conn)
        .destination(BLUEZ_SERVICE)
        .expect("valid destination")
        .path(path)
        .expect("valid path")
        .interface(ADMIN_POLICY_SET_IFACE)
        .expect("valid interface")
        .build()
        .await
    {
        Ok(p) => p,
        Err(_) => {
            bt_shell_printf(format_args!("Failed to call method\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Build the method argument: a D-Bus array of strings (signature `as`).
    let uuid_refs: Vec<&str> = uuids.iter().map(String::as_str).collect();

    match proxy.call_method("SetServiceAllowList", &(uuid_refs,)).await {
        Ok(_) => {
            bt_shell_printf(format_args!("Set allowed service successfully\n"));
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Err(zbus::Error::MethodError(ref name, _, _)) => {
            bt_shell_printf(format_args!(
                "Failed to set service allowed list: {}\n",
                name.as_str()
            ));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        }
        Err(_) => {
            bt_shell_printf(format_args!("Failed to call method\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `AdminState::new()` produces an empty state.
    #[test]
    fn test_admin_state_new() {
        let state = AdminState::new();
        assert!(state.dbus_conn.is_none());
        assert!(state.set_proxy_path.is_none());
        assert!(state.status_proxy_path.is_none());
        assert!(state.admin_proxy_paths.is_empty());
        assert!(!state.watcher_active);
    }

    /// Verify that `AdminState::clear()` resets all fields.
    #[test]
    fn test_admin_state_clear() {
        let mut state = AdminState::new();
        state.set_proxy_path = Some("/org/bluez/hci0".to_string());
        state.status_proxy_path = Some("/org/bluez/hci0".to_string());
        state.admin_proxy_paths.push("/org/bluez/hci0".to_string());
        state.watcher_active = true;

        state.clear();
        assert!(state.dbus_conn.is_none());
        assert!(state.set_proxy_path.is_none());
        assert!(state.status_proxy_path.is_none());
        assert!(state.admin_proxy_paths.is_empty());
        assert!(!state.watcher_active);
    }

    /// Verify the static menu definition has correct name and descriptor.
    #[test]
    fn test_admin_menu_definition() {
        assert_eq!(ADMIN_MENU.name, "admin");
        assert_eq!(ADMIN_MENU.desc, Some("Admin Policy Submenu"));
        assert!(ADMIN_MENU.pre_run.is_some());
        assert_eq!(ADMIN_MENU.entries.len(), 1);

        let entry = &ADMIN_MENU.entries[0];
        assert_eq!(entry.cmd, "allow");
        assert_eq!(entry.arg, Some("[clear/uuid1 uuid2 ...]"));
        assert_eq!(entry.desc, "Allow service UUIDs and block rest of them");
        assert!(entry.r#gen.is_none());
        assert!(entry.disp.is_none());
        assert!(entry.exists.is_none());
    }

    /// Verify constants match expected D-Bus interface names.
    #[test]
    fn test_dbus_constants() {
        assert_eq!(BLUEZ_SERVICE, "org.bluez");
        assert_eq!(ADMIN_POLICY_SET_IFACE, "org.bluez.AdminPolicySet1");
        assert_eq!(ADMIN_POLICY_STATUS_IFACE, "org.bluez.AdminPolicyStatus1");
    }

    /// Verify exit code constants.
    #[test]
    fn test_exit_codes() {
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_FAILURE, 1);
    }

    /// Verify state tracks multiple admin proxy paths (replaces GList).
    #[test]
    fn test_admin_state_multiple_proxies() {
        let mut state = AdminState::new();
        state.admin_proxy_paths.push("/org/bluez/hci0".to_string());
        state.admin_proxy_paths.push("/org/bluez/hci1".to_string());
        assert_eq!(state.admin_proxy_paths.len(), 2);

        // Simulate remove: retain all except hci0
        state.admin_proxy_paths.retain(|p| p != "/org/bluez/hci0");
        assert_eq!(state.admin_proxy_paths.len(), 1);
        assert_eq!(state.admin_proxy_paths[0], "/org/bluez/hci1");
    }

    /// Verify clear on an already-empty state is safe.
    #[test]
    fn test_admin_state_double_clear() {
        let mut state = AdminState::new();
        state.clear();
        state.clear();
        assert!(state.admin_proxy_paths.is_empty());
    }
}
