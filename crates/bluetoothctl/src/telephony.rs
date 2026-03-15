// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
//! Telephony submenu — Rust rewrite of `client/telephony.c` (528 lines) and
//! `client/telephony.h` (12 lines).
//!
//! Provides the "telephony" submenu for `org.bluez.Telephony1` and
//! `org.bluez.Call1` D-Bus interfaces.  All shell commands, output formatting,
//! and error messages are behaviorally identical to the C original, including
//! the EXIT_FAILURE-on-success quirk in `dial_reply` / `answer_reply` /
//! `hangup_reply` / `hangupall_reply`.
//!
//! # Behavioral Fidelity
//!
//! This module produces identical shell output and accepts identical command
//! arguments as the C original.  The nine commands are:
//!
//! | Command      | Args        | Description                      |
//! |--------------|-------------|----------------------------------|
//! | `list`       | —           | List available audio gateways    |
//! | `show`       | `[ag]`      | Telephony Audio Gateway info     |
//! | `select`     | `<ag>`      | Select default audio gateway     |
//! | `dial`       | `<number>`  | Dial a number                    |
//! | `hangup-all` | —           | Hang up all calls                |
//! | `list-calls` | —           | List available calls             |
//! | `show-call`  | `[call]`    | Call information                 |
//! | `answer`     | `[call]`    | Answer a call                    |
//! | `hangup`     | `[call]`    | Hang up a call                   |

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use futures::StreamExt as _;
use tokio::sync::Mutex;
use zbus::Connection;
use zbus::zvariant::OwnedValue;

use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, bt_shell_add_submenu, bt_shell_get_env,
    bt_shell_noninteractive_quit, bt_shell_printf, bt_shell_remove_submenu,
};

use crate::display;
use crate::print;

// ---------------------------------------------------------------------------
// Constants — matching C telephony.c lines 27-32
// ---------------------------------------------------------------------------

/// Successful exit status for `bt_shell_noninteractive_quit`.
const EXIT_SUCCESS: i32 = 0;
/// Failure exit status for `bt_shell_noninteractive_quit`.
const EXIT_FAILURE: i32 = 1;

/// D-Bus well-known name of the BlueZ daemon.
const BLUEZ_SERVICE: &str = "org.bluez";
/// D-Bus interface for the telephony audio gateway.
const BLUEZ_TELEPHONY_INTERFACE: &str = "org.bluez.Telephony1";
/// D-Bus interface for an individual call.
const BLUEZ_TELEPHONY_CALL_INTERFACE: &str = "org.bluez.Call1";

// ---------------------------------------------------------------------------
// Module state — replaces C static variables (telephony.c lines 34-38)
// ---------------------------------------------------------------------------

/// Module-level mutable state replacing the C static variables:
///
/// - `DBusConnection *dbus_conn`  → `dbus_conn: Option<Connection>`
/// - `GDBusProxy *default_ag`     → `default_ag_path: Option<String>`
/// - `GList *ags`                 → `ags: Vec<String>`
/// - `GList *calls`               → `calls: Vec<String>`
/// - `GDBusClient *client`        → `watcher_active: bool`
///
/// Proxies are not cached directly because `zbus::proxy::Proxy<'a>` carries a
/// lifetime tied to the `Connection` reference.  Instead we store the object
/// paths and create short-lived proxies on demand within async helpers.
struct TelephonyState {
    /// D-Bus connection retrieved from the shell environment.
    dbus_conn: Option<Connection>,
    /// Object path of the currently selected default audio gateway.
    default_ag_path: Option<String>,
    /// All discovered `Telephony1` object paths (replaces `GList *ags`).
    ags: Vec<String>,
    /// All discovered `Call1` object paths (replaces `GList *calls`).
    calls: Vec<String>,
    /// Whether the background D-Bus watcher task has been spawned.
    watcher_active: bool,
}

impl TelephonyState {
    /// Create a fresh, empty state.
    fn new() -> Self {
        Self {
            dbus_conn: None,
            default_ag_path: None,
            ags: Vec::new(),
            calls: Vec::new(),
            watcher_active: false,
        }
    }

    /// Reset all fields — equivalent to the C disconnect handler + client unref.
    fn clear(&mut self) {
        self.dbus_conn = None;
        self.default_ag_path = None;
        self.ags.clear();
        self.calls.clear();
        self.watcher_active = false;
    }
}

/// Global telephony module state, protected by a `tokio::sync::Mutex` for safe
/// access from both synchronous shell callbacks (via `blocking_lock`) and
/// asynchronous watcher tasks (via `.lock().await`).
static STATE: LazyLock<Arc<Mutex<TelephonyState>>> =
    LazyLock::new(|| Arc::new(Mutex::new(TelephonyState::new())));

// ---------------------------------------------------------------------------
// Colored display prefixes — replaces C macros (telephony.c lines 27-29)
// ---------------------------------------------------------------------------

/// Format the "NEW" prefix with green coloring.
fn colored_new() -> String {
    format!("{}NEW{}", display::COLOR_GREEN, display::COLOR_OFF)
}

/// Format the "CHG" prefix with yellow coloring.
fn colored_chg() -> String {
    format!("{}CHG{}", display::COLOR_YELLOW, display::COLOR_OFF)
}

/// Format the "DEL" prefix with red coloring.
fn colored_del() -> String {
    format!("{}DEL{}", display::COLOR_RED, display::COLOR_OFF)
}

// ---------------------------------------------------------------------------
// Menu definition — replaces C `telephony_menu` (telephony.c lines 584-617)
// ---------------------------------------------------------------------------

/// The "telephony" submenu registered with the shell framework.
///
/// Nine commands matching the C original exactly:
/// list, show, select, dial, hangup-all, list-calls, show-call, answer, hangup.
static TELEPHONY_MENU: BtShellMenu = BtShellMenu {
    name: "telephony",
    desc: Some("Telephony Submenu"),
    pre_run: Some(telephony_menu_pre_run),
    entries: &[
        BtShellMenuEntry {
            cmd: "list",
            arg: None,
            func: cmd_list,
            desc: "List available audio gateways",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "show",
            arg: Some("[ag]"),
            func: cmd_show,
            desc: "Telephony Audio Gateway information",
            r#gen: Some(ag_generator),
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "select",
            arg: Some("<ag>"),
            func: cmd_select,
            desc: "Select default audio gateway",
            r#gen: Some(ag_generator),
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "dial",
            arg: Some("<number>"),
            func: cmd_dial,
            desc: "Dial a number",
            r#gen: Some(ag_generator),
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "hangup-all",
            arg: None,
            func: cmd_hangupall,
            desc: "Hang up all calls",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "list-calls",
            arg: None,
            func: cmd_list_calls,
            desc: "List available calls",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "show-call",
            arg: Some("[call]"),
            func: cmd_show_call,
            desc: "Call information",
            r#gen: Some(call_generator),
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "answer",
            arg: Some("[call]"),
            func: cmd_answer_call,
            desc: "Answer a call",
            r#gen: Some(call_generator),
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "hangup",
            arg: Some("[call]"),
            func: cmd_hangup_call,
            desc: "Hangup a call",
            r#gen: Some(call_generator),
            disp: None,
            exists: None,
        },
    ],
};

// ---------------------------------------------------------------------------
// Public API — replaces telephony.h declarations
// ---------------------------------------------------------------------------

/// Register the telephony submenu with the shell framework.
///
/// Replaces C `telephony_add_submenu()` (telephony.c lines 619-622).
pub fn telephony_add_submenu() {
    bt_shell_add_submenu(&TELEPHONY_MENU);
}

/// Unregister the telephony submenu and clean up D-Bus client state.
///
/// Replaces C `telephony_remove_submenu()` (telephony.c lines 624-638).
pub fn telephony_remove_submenu() {
    let state = STATE.clone();
    state.blocking_lock().clear();
    bt_shell_remove_submenu(&TELEPHONY_MENU);
}

// ---------------------------------------------------------------------------
// Menu pre-run hook — replaces C `telephony_menu_pre_run` (lines 567-582)
// ---------------------------------------------------------------------------

/// Lazy D-Bus client initialization, called each time the telephony submenu is
/// entered.  Retrieves the D-Bus connection from the shell environment and
/// spawns a background watcher that monitors `org.bluez` for the appearance
/// and removal of `Telephony1` / `Call1` interfaces.
///
/// Replaces:
/// ```c
/// dbus_conn = bt_shell_get_env("DBUS_CONNECTION");
/// if (!dbus_conn || client) return;
/// client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");
/// g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
///                                  property_changed, NULL);
/// ```
fn telephony_menu_pre_run(_menu: &BtShellMenu) {
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

    // Spawn background task to discover and monitor telephony interfaces.
    let state_for_task = state;
    tokio::spawn(async move {
        run_proxy_watcher(conn, state_for_task).await;
    });
}

// ---------------------------------------------------------------------------
// Background D-Bus watcher — replaces GDBusClient proxy tracking
// ---------------------------------------------------------------------------

/// Background task that uses the D-Bus `ObjectManager` interface to discover
/// existing telephony interfaces and monitor for future additions/removals
/// and property changes.
///
/// Replaces the `GDBusClient` proxy handler callbacks:
/// - `proxy_added`   (telephony.c lines 484-495)
/// - `proxy_removed` (telephony.c lines 519-530)
/// - `property_changed` (telephony.c lines 554-565)
async fn run_proxy_watcher(conn: Connection, state: Arc<Mutex<TelephonyState>>) {
    // Build an ObjectManagerProxy for org.bluez at the ObjectManager root.
    let om_proxy = match zbus::fdo::ObjectManagerProxy::builder(&conn)
        .destination(BLUEZ_SERVICE)
        .expect("valid well-known name")
        .path("/")
        .expect("valid object path")
        .build()
        .await
    {
        Ok(p) => p,
        Err(_) => return, // Service not available; silently exit.
    };

    // Phase 1: Discover already-exported objects.
    if let Ok(objects) = om_proxy.get_managed_objects().await {
        for (path, interfaces) in &objects {
            let path_str = path.to_string();
            for iface_name in interfaces.keys() {
                match iface_name.as_str() {
                    iface if iface == BLUEZ_TELEPHONY_INTERFACE => {
                        ag_added(&state, &path_str).await;
                    }
                    iface if iface == BLUEZ_TELEPHONY_CALL_INTERFACE => {
                        call_added(&state, &path_str).await;
                    }
                    _ => {}
                }
            }
        }
    }

    // Phase 2: Set up signal streams for dynamic changes.
    let added_stream = om_proxy.receive_interfaces_added().await;
    let removed_stream = om_proxy.receive_interfaces_removed().await;

    let (Ok(mut added_stream), Ok(mut removed_stream)) = (added_stream, removed_stream) else {
        return; // Signal subscription failed; give up silently.
    };

    // Set up a PropertiesChanged signal stream for real-time notifications.
    let props_stream_result = zbus::MessageStream::for_match_rule(
        zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(BLUEZ_SERVICE)
            .expect("valid sender")
            .interface("org.freedesktop.DBus.Properties")
            .expect("valid interface")
            .member("PropertiesChanged")
            .expect("valid member")
            .build(),
        &conn,
        Some(64),
    )
    .await;

    let mut props_stream = props_stream_result.ok();

    loop {
        tokio::select! {
            added = added_stream.next() => {
                let Some(signal) = added else { break; };
                if let Ok(args) = signal.args() {
                    let path_str = args.object_path().to_string();
                    for iface_name in args.interfaces_and_properties().keys() {
                        match iface_name.as_str() {
                            iface if iface == BLUEZ_TELEPHONY_INTERFACE => {
                                ag_added(&state, &path_str).await;
                            }
                            iface if iface == BLUEZ_TELEPHONY_CALL_INTERFACE => {
                                call_added(&state, &path_str).await;
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
                    for iface_name in args.interfaces().iter() {
                        match iface_name.as_ref() {
                            iface if iface == BLUEZ_TELEPHONY_INTERFACE => {
                                ag_removed(&state, &path_str).await;
                            }
                            iface if iface == BLUEZ_TELEPHONY_CALL_INTERFACE => {
                                call_removed(&state, &path_str).await;
                            }
                            _ => {}
                        }
                    }
                }
            }
            prop_msg = async {
                match props_stream.as_mut() {
                    Some(s) => s.next().await,
                    None => futures::future::pending::<Option<zbus::Result<zbus::Message>>>().await,
                }
            } => {
                if let Some(Ok(msg)) = prop_msg {
                    handle_property_changed_msg(&msg, &state).await;
                }
            }
        }
    }

    // Streams ended — service disconnected.  Clear state (disconnect handler).
    let mut guard = state.lock().await;
    guard.ags.clear();
    guard.calls.clear();
    guard.default_ag_path = None;
}

// ---------------------------------------------------------------------------
// Proxy tracking functions — replaces C callbacks
// ---------------------------------------------------------------------------

/// Handle a new Telephony1 proxy discovery.
///
/// Replaces C `ag_added` (telephony.c lines 466-472).
async fn ag_added(state: &Arc<Mutex<TelephonyState>>, path: &str) {
    let mut guard = state.lock().await;
    if guard.ags.contains(&path.to_string()) {
        return;
    }
    guard.ags.push(path.to_string());
    drop(guard);
    print_ag(path, Some(&colored_new()));
}

/// Handle a new Call1 proxy discovery.
///
/// Replaces C `call_added` (telephony.c lines 474-482).
async fn call_added(state: &Arc<Mutex<TelephonyState>>, path: &str) {
    let mut guard = state.lock().await;
    if guard.calls.contains(&path.to_string()) {
        return;
    }
    guard.calls.push(path.to_string());
    let conn = guard.dbus_conn.clone();
    drop(guard);

    // Fetch current State for display, defaulting to "unknown".
    let state_val = match conn {
        Some(ref c) => fetch_call_state(c, path).await,
        None => "unknown".to_string(),
    };
    print_call(path, &state_val, Some(&colored_new()));
}

/// Handle removal of a Telephony1 proxy.
///
/// Replaces C `ag_removed` (telephony.c lines 497-509).
async fn ag_removed(state: &Arc<Mutex<TelephonyState>>, path: &str) {
    let mut guard = state.lock().await;
    guard.ags.retain(|p| p != path);
    if guard.default_ag_path.as_deref() == Some(path) {
        guard.default_ag_path = None;
    }
    drop(guard);
    print_ag(path, Some(&colored_del()));
}

/// Handle removal of a Call1 proxy.
///
/// Replaces C `call_removed` (telephony.c lines 511-517).
async fn call_removed(state: &Arc<Mutex<TelephonyState>>, path: &str) {
    let mut guard = state.lock().await;
    guard.calls.retain(|p| p != path);
    drop(guard);
    bt_shell_printf(format_args!("{} Call {} removed\n", colored_del(), path));
}

/// Handle a PropertiesChanged D-Bus signal message.
///
/// Dispatches to the appropriate property change printer based on the
/// interface name in the signal payload.
///
/// Replaces C `property_changed` (telephony.c lines 554-565) which
/// dispatches to `ag_property_changed` and `call_property_changed`.
async fn handle_property_changed_msg(msg: &zbus::Message, state: &Arc<Mutex<TelephonyState>>) {
    // PropertiesChanged signature: (s, a{sv}, as)
    let Ok(body) = msg.body().deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
    else {
        return;
    };

    let (iface_name, changed_props, _invalidated) = body;
    let path = match msg.header().path() {
        Some(p) => p.to_string(),
        None => return,
    };

    // Check if this path belongs to our tracked proxies.
    let guard = state.lock().await;
    let is_ag = guard.ags.contains(&path);
    let is_call = guard.calls.contains(&path);
    drop(guard);

    if !is_ag && !is_call {
        return;
    }

    for (name, value) in &changed_props {
        if iface_name == BLUEZ_TELEPHONY_INTERFACE && is_ag {
            // Replaces C `ag_property_changed` (telephony.c lines 532-541).
            let desc = proxy_description(&path, "Audio gateway", Some(&colored_chg()));
            print::print_iter(&desc, name, value);
        } else if iface_name == BLUEZ_TELEPHONY_CALL_INTERFACE && is_call {
            // Replaces C `call_property_changed` (telephony.c lines 543-552).
            let desc = proxy_description(&path, "Call", Some(&colored_chg()));
            print::print_iter(&desc, name, value);
        }
    }
}

// ---------------------------------------------------------------------------
// Utility functions — replaces C helpers
// ---------------------------------------------------------------------------

/// Build a description string for a proxy.
///
/// Replaces C `proxy_description` (telephony.c lines 89-103).
///
/// If `description` is `Some(d)`, returns `"{d} {title} {path}"`.
/// If `description` is `None`, returns `"{title} {path}"`.
fn proxy_description(path: &str, title: &str, description: Option<&str>) -> String {
    match description {
        Some(desc) => format!("{desc} {title} {path}"),
        None => format!("{title} {path}"),
    }
}

/// Print an audio gateway proxy.
///
/// Replaces C `print_ag` (telephony.c lines 105-112).
fn print_ag(path: &str, description: Option<&str>) {
    let text = proxy_description(path, "Audio gateway", description);
    bt_shell_printf(format_args!("{text}\n"));
}

/// Print a call proxy with its current state.
///
/// Replaces C `print_call` (telephony.c lines 114-123).
fn print_call(path: &str, state_val: &str, description: Option<&str>) {
    let text = proxy_description(path, "Call", description);
    bt_shell_printf(format_args!("{text} State: {state_val}\n"));
}

/// Create a short-lived D-Bus proxy for the given path and interface.
///
/// Replaces the implicit proxy creation in C via `g_dbus_proxy_lookup`.
async fn make_proxy(
    conn: &Connection,
    path: &str,
    interface: &str,
) -> zbus::Result<zbus::proxy::Proxy<'static>> {
    let owned_path = path.to_string();
    let owned_iface = interface.to_string();
    zbus::proxy::Builder::new(conn)
        .destination(BLUEZ_SERVICE)
        .expect("valid destination")
        .path(owned_path)
        .expect("valid path")
        .interface(owned_iface)
        .expect("valid interface")
        .build()
        .await
}

/// Fetch the "State" property of a Call1 proxy, returning "unknown" on failure.
async fn fetch_call_state(conn: &Connection, path: &str) -> String {
    match make_proxy(conn, path, BLUEZ_TELEPHONY_CALL_INTERFACE).await {
        Ok(proxy) => match proxy.get_property::<String>("State").await {
            Ok(s) => s,
            Err(_) => "unknown".to_string(),
        },
        Err(_) => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tab completion generators — replaces C ag_generator / call_generator
// ---------------------------------------------------------------------------

/// Tab-completion generator for audio gateway object paths.
///
/// Replaces C `ag_generator` (telephony.c lines 79-82) which delegates to
/// `generic_generator(text, state, ags, NULL)`.  When `property` is NULL the
/// C helper completes against the proxy path.
fn ag_generator(text: &str, state: i32) -> Option<String> {
    use std::cell::{Cell, RefCell};

    thread_local! {
        static MATCHES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static INDEX: Cell<usize> = const { Cell::new(0) };
    }

    if state == 0 {
        let guard = STATE.blocking_lock();
        let matches: Vec<String> =
            guard.ags.iter().filter(|p| p.starts_with(text)).cloned().collect();
        MATCHES.with(|m| *m.borrow_mut() = matches);
        INDEX.with(|i| i.set(0));
    }

    MATCHES.with(|m| {
        let matches = m.borrow();
        let idx = INDEX.with(|i| i.get());
        if idx < matches.len() {
            INDEX.with(|i| i.set(idx + 1));
            Some(matches[idx].clone())
        } else {
            None
        }
    })
}

/// Tab-completion generator for call object paths.
///
/// Replaces C `call_generator` (telephony.c lines 84-87) which delegates to
/// `generic_generator(text, state, calls, NULL)`.
fn call_generator(text: &str, state: i32) -> Option<String> {
    use std::cell::{Cell, RefCell};

    thread_local! {
        static MATCHES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static INDEX: Cell<usize> = const { Cell::new(0) };
    }

    if state == 0 {
        let guard = STATE.blocking_lock();
        let matches: Vec<String> =
            guard.calls.iter().filter(|p| p.starts_with(text)).cloned().collect();
        MATCHES.with(|m| *m.borrow_mut() = matches);
        INDEX.with(|i| i.set(0));
    }

    MATCHES.with(|m| {
        let matches = m.borrow();
        let idx = INDEX.with(|i| i.get());
        if idx < matches.len() {
            INDEX.with(|i| i.set(idx + 1));
            Some(matches[idx].clone())
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Shell command implementations — replaces C cmd_* functions
// ---------------------------------------------------------------------------

/// List available audio gateways.
///
/// Replaces C `cmd_list` (telephony.c lines 125-134).
fn cmd_list(_args: &[&str]) {
    let guard = STATE.blocking_lock();
    for path in &guard.ags {
        print_ag(path, None);
    }
    drop(guard);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Show telephony audio gateway information.
///
/// If no argument is given, shows the default audio gateway.
/// Otherwise shows the specified one.
///
/// Replaces C `cmd_show` (telephony.c lines 136-184).
fn cmd_show(args: &[&str]) {
    let state = STATE.clone();
    let guard = state.blocking_lock();

    let path = if args.len() < 2 {
        // No argument: use default AG.
        match guard.default_ag_path.clone() {
            Some(p) => p,
            None => {
                bt_shell_printf(format_args!("No default audio gateway available\n"));
                drop(guard);
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    } else {
        // Specific AG given.
        let arg = args[1];
        match guard.ags.iter().find(|p| p.as_str() == arg) {
            Some(p) => p.clone(),
            None => {
                bt_shell_printf(format_args!("Audio gateway {arg} not available\n"));
                drop(guard);
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    };

    let conn = match guard.dbus_conn.clone() {
        Some(c) => c,
        None => {
            drop(guard);
            return;
        }
    };
    drop(guard);

    tokio::spawn(async move {
        match make_proxy(&conn, &path, BLUEZ_TELEPHONY_INTERFACE).await {
            Ok(proxy) => {
                bt_shell_printf(format_args!("Audio gateway {path}\n"));
                print::print_property(&proxy, "UUID").await;
                print::print_property(&proxy, "Technology").await;
                print::print_property(&proxy, "OperatorName").await;
                print::print_property(&proxy, "SubscriberNumber").await;
                print::print_property(&proxy, "Strength").await;
                print::print_property(&proxy, "Features").await;
                print::print_property(&proxy, "Calls").await;
                bt_shell_noninteractive_quit(EXIT_SUCCESS);
            }
            Err(_) => {
                bt_shell_printf(format_args!("Audio gateway {path} not available\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        }
    });
}

/// Select the default audio gateway.
///
/// Replaces C `cmd_select` (telephony.c lines 186-215).
fn cmd_select(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    let state = STATE.clone();
    let mut guard = state.blocking_lock();
    let arg = args[1];

    let found = guard.ags.iter().any(|p| p.as_str() == arg);
    if !found {
        bt_shell_printf(format_args!("Audio gateway {arg} not available\n"));
        drop(guard);
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    if guard.default_ag_path.as_deref() == Some(arg) {
        drop(guard);
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
        return;
    }

    guard.default_ag_path = Some(arg.to_string());
    drop(guard);

    print_ag(arg, None);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Dial a number on the default or specified audio gateway.
///
/// Replaces C `cmd_dial` (telephony.c lines 246-282).
///
/// Note: The C `dial_reply` callback returns `EXIT_FAILURE` on success —
/// this is a bug in the original C code that is faithfully replicated here
/// for behavioral clone fidelity.
fn cmd_dial(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    let number = args[1].to_string();
    let state = STATE.clone();
    let guard = state.blocking_lock();

    // If a third argument is given, use it as the AG path (C: argv[2]).
    let path = if args.len() > 2 {
        let ag_arg = args[2];
        match guard.ags.iter().find(|p| p.as_str() == ag_arg) {
            Some(p) => p.clone(),
            None => {
                bt_shell_printf(format_args!("Audio gateway {ag_arg} not available\n"));
                drop(guard);
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    } else {
        match guard.default_ag_path.clone() {
            Some(p) => p,
            None => {
                bt_shell_printf(format_args!("No default audio gateway available\n"));
                drop(guard);
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    };

    let conn = match guard.dbus_conn.clone() {
        Some(c) => c,
        None => {
            drop(guard);
            return;
        }
    };
    drop(guard);

    tokio::spawn(async move {
        match make_proxy(&conn, &path, BLUEZ_TELEPHONY_INTERFACE).await {
            Ok(proxy) => {
                // Replaces C dial_setup (puts number as string arg) + dial_reply.
                match proxy.call_method("Dial", &(&number,)).await {
                    Ok(_) => {
                        bt_shell_printf(format_args!("Dial successful\n"));
                        // C bug: EXIT_FAILURE on success (telephony.c line 233)
                        bt_shell_noninteractive_quit(EXIT_FAILURE);
                    }
                    Err(e) => {
                        bt_shell_printf(format_args!("Failed to Dial: {e}\n"));
                        bt_shell_noninteractive_quit(EXIT_FAILURE);
                    }
                }
            }
            Err(_) => {
                bt_shell_printf(format_args!("Failed to call Dial\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        }
    });
}

/// Hang up all calls on the default audio gateway.
///
/// Replaces C `cmd_hangupall` (telephony.c lines 304-315).
///
/// Note: The C `hangupall_reply` returns `EXIT_FAILURE` on success —
/// behavioral clone fidelity.
fn cmd_hangupall(_args: &[&str]) {
    let state = STATE.clone();
    let guard = state.blocking_lock();

    let path = match guard.default_ag_path.clone() {
        Some(p) => p,
        None => {
            bt_shell_printf(format_args!("No default audio gateway available\n"));
            drop(guard);
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    let conn = match guard.dbus_conn.clone() {
        Some(c) => c,
        None => {
            drop(guard);
            return;
        }
    };
    drop(guard);

    tokio::spawn(async move {
        match make_proxy(&conn, &path, BLUEZ_TELEPHONY_INTERFACE).await {
            Ok(proxy) => {
                match proxy.call_method("HangupAll", &()).await {
                    Ok(_) => {
                        bt_shell_printf(format_args!("HangupAll successful\n"));
                        // C bug: EXIT_FAILURE on success (telephony.c line 302)
                        bt_shell_noninteractive_quit(EXIT_FAILURE);
                    }
                    Err(e) => {
                        bt_shell_printf(format_args!("Failed to hangup all: {e}\n"));
                        bt_shell_noninteractive_quit(EXIT_FAILURE);
                    }
                }
            }
            Err(_) => {
                bt_shell_printf(format_args!("Failed to call HangupAll\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        }
    });
}

/// List available calls with their states.
///
/// Replaces C `cmd_list_calls` (telephony.c lines 317-328).
fn cmd_list_calls(_args: &[&str]) {
    let state = STATE.clone();
    let guard = state.blocking_lock();
    let call_paths: Vec<String> = guard.calls.clone();
    let conn = guard.dbus_conn.clone();
    drop(guard);

    match conn {
        Some(conn) => {
            tokio::spawn(async move {
                for path in &call_paths {
                    let state_val = fetch_call_state(&conn, path).await;
                    print_call(path, &state_val, None);
                }
                bt_shell_noninteractive_quit(EXIT_SUCCESS);
            });
        }
        None => {
            // No connection — print without state info.
            for path in &call_paths {
                print_call(path, "unknown", None);
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Show call information.
///
/// If no argument is given, shows all calls.
/// Otherwise shows the specified call.
///
/// Replaces C `cmd_show_call` (telephony.c lines 330-360).
fn cmd_show_call(args: &[&str]) {
    let state = STATE.clone();
    let guard = state.blocking_lock();

    let conn = match guard.dbus_conn.clone() {
        Some(c) => c,
        None => {
            drop(guard);
            return;
        }
    };

    if args.len() < 2 {
        // Show all calls.
        let call_paths: Vec<String> = guard.calls.clone();
        drop(guard);

        tokio::spawn(async move {
            for path in &call_paths {
                match make_proxy(&conn, path, BLUEZ_TELEPHONY_CALL_INTERFACE).await {
                    Ok(proxy) => {
                        bt_shell_printf(format_args!("Call {path}\n"));
                        print::print_property(&proxy, "State").await;
                        print::print_property(&proxy, "Name").await;
                        print::print_property(&proxy, "Multiparty").await;
                        print::print_property(&proxy, "LineIdentification").await;
                        print::print_property(&proxy, "IncomingLine").await;
                    }
                    Err(_) => {
                        bt_shell_printf(format_args!("Call {path} not available\n"));
                    }
                }
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        });
    } else {
        // Show specific call.
        let arg = args[1];
        let found = guard.calls.iter().any(|p| p.as_str() == arg);
        if !found {
            bt_shell_printf(format_args!("Call {arg} not available\n"));
            drop(guard);
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
        let path = arg.to_string();
        drop(guard);

        tokio::spawn(async move {
            match make_proxy(&conn, &path, BLUEZ_TELEPHONY_CALL_INTERFACE).await {
                Ok(proxy) => {
                    bt_shell_printf(format_args!("Call {path}\n"));
                    print::print_property(&proxy, "State").await;
                    print::print_property(&proxy, "Name").await;
                    print::print_property(&proxy, "Multiparty").await;
                    print::print_property(&proxy, "LineIdentification").await;
                    print::print_property(&proxy, "IncomingLine").await;
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                }
                Err(_) => {
                    bt_shell_printf(format_args!("Call {path} not available\n"));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        });
    }
}

/// Answer a call.
///
/// If no argument is given, answers the first incoming call.
/// Otherwise answers the specified call.
///
/// Replaces C `cmd_answer_call` (telephony.c lines 382-412).
///
/// Note: The C `answer_reply` returns `EXIT_FAILURE` on success —
/// behavioral clone fidelity.
fn cmd_answer_call(args: &[&str]) {
    let state = STATE.clone();
    let guard = state.blocking_lock();

    let conn = match guard.dbus_conn.clone() {
        Some(c) => c,
        None => {
            drop(guard);
            return;
        }
    };

    if args.len() > 1 {
        // Specific call path given.
        let arg = args[1];
        let found = guard.calls.iter().any(|p| p.as_str() == arg);
        if !found {
            bt_shell_printf(format_args!("Call {arg} not available\n"));
            drop(guard);
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
        let path = arg.to_string();
        drop(guard);

        tokio::spawn(async move {
            answer_call_async(&conn, &path).await;
        });
    } else {
        // No argument: find first incoming call.
        let call_paths: Vec<String> = guard.calls.clone();
        drop(guard);

        tokio::spawn(async move {
            for path in &call_paths {
                let state_val = fetch_call_state(&conn, path).await;
                if state_val != "incoming" {
                    continue;
                }
                answer_call_async(&conn, path).await;
                return;
            }
            bt_shell_printf(format_args!("No incoming call\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        });
    }
}

/// Hang up a call.
///
/// If no argument is given, hangs up the first active call.
/// Otherwise hangs up the specified call.
///
/// Replaces C `cmd_hangup_call` (telephony.c lines 434-464).
///
/// Note: The C `hangup_reply` returns `EXIT_FAILURE` on success —
/// behavioral clone fidelity.
fn cmd_hangup_call(args: &[&str]) {
    let state = STATE.clone();
    let guard = state.blocking_lock();

    let conn = match guard.dbus_conn.clone() {
        Some(c) => c,
        None => {
            drop(guard);
            return;
        }
    };

    if args.len() > 1 {
        // Specific call path given.
        let arg = args[1];
        let found = guard.calls.iter().any(|p| p.as_str() == arg);
        if !found {
            bt_shell_printf(format_args!("Call {arg} not available\n"));
            drop(guard);
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
        let path = arg.to_string();
        drop(guard);

        tokio::spawn(async move {
            hangup_call_async(&conn, &path).await;
        });
    } else {
        // No argument: find first active call.
        let call_paths: Vec<String> = guard.calls.clone();
        drop(guard);

        tokio::spawn(async move {
            for path in &call_paths {
                let state_val = fetch_call_state(&conn, path).await;
                if state_val != "active" {
                    continue;
                }
                hangup_call_async(&conn, path).await;
                return;
            }
            bt_shell_printf(format_args!("No active call\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        });
    }
}

// ---------------------------------------------------------------------------
// Async D-Bus method call helpers
// ---------------------------------------------------------------------------

/// Invoke the `Answer` method on a Call1 object and report the result.
///
/// Replaces C `answer_reply` callback (telephony.c lines 362-380).
async fn answer_call_async(conn: &Connection, path: &str) {
    match make_proxy(conn, path, BLUEZ_TELEPHONY_CALL_INTERFACE).await {
        Ok(proxy) => match proxy.call_method("Answer", &()).await {
            Ok(_) => {
                bt_shell_printf(format_args!("Answer successful\n"));
                // C bug: EXIT_FAILURE on success (telephony.c line 378)
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to answer: {e}\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        },
        Err(_) => {
            bt_shell_printf(format_args!("Failed to call answer\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        }
    }
}

/// Invoke the `Hangup` method on a Call1 object and report the result.
///
/// Replaces C `hangup_reply` callback (telephony.c lines 414-432).
async fn hangup_call_async(conn: &Connection, path: &str) {
    match make_proxy(conn, path, BLUEZ_TELEPHONY_CALL_INTERFACE).await {
        Ok(proxy) => match proxy.call_method("Hangup", &()).await {
            Ok(_) => {
                bt_shell_printf(format_args!("Hangup successful\n"));
                // C bug: EXIT_FAILURE on success (telephony.c line 430)
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
            Err(e) => {
                bt_shell_printf(format_args!("Failed to hangup: {e}\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        },
        Err(_) => {
            bt_shell_printf(format_args!("Failed to call hangup\n"));
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

    #[test]
    fn test_colored_new() {
        let s = colored_new();
        assert!(s.contains("NEW"));
        assert!(s.contains(display::COLOR_GREEN));
        assert!(s.contains(display::COLOR_OFF));
    }

    #[test]
    fn test_colored_chg() {
        let s = colored_chg();
        assert!(s.contains("CHG"));
        assert!(s.contains(display::COLOR_YELLOW));
        assert!(s.contains(display::COLOR_OFF));
    }

    #[test]
    fn test_colored_del() {
        let s = colored_del();
        assert!(s.contains("DEL"));
        assert!(s.contains(display::COLOR_RED));
        assert!(s.contains(display::COLOR_OFF));
    }

    #[test]
    fn test_proxy_description_no_desc() {
        let result = proxy_description("/org/bluez/hci0", "Audio gateway", None);
        assert!(result.contains("/org/bluez/hci0"));
        assert!(result.contains("Audio gateway"));
    }

    #[test]
    fn test_proxy_description_with_desc() {
        let result = proxy_description("/org/bluez/hci0", "Audio gateway", Some("NEW"));
        assert!(result.contains("/org/bluez/hci0"));
        assert!(result.contains("Audio gateway"));
        assert!(result.contains("NEW"));
    }

    #[test]
    fn test_telephony_state_default() {
        let st = TelephonyState::new();
        assert!(st.dbus_conn.is_none());
        assert!(st.default_ag_path.is_none());
        assert!(st.ags.is_empty());
        assert!(st.calls.is_empty());
        assert!(!st.watcher_active);
    }

    #[test]
    fn test_telephony_menu_name() {
        assert_eq!(TELEPHONY_MENU.name, "telephony");
    }

    #[test]
    fn test_telephony_menu_has_9_entries() {
        // 9 commands — no sentinel needed in Rust (slice length is known).
        assert_eq!(TELEPHONY_MENU.entries.len(), 9);
    }

    #[test]
    fn test_telephony_menu_command_names() {
        let cmds: Vec<&str> = TELEPHONY_MENU.entries.iter().map(|e| e.cmd).collect();
        assert!(cmds.contains(&"list"));
        assert!(cmds.contains(&"show"));
        assert!(cmds.contains(&"select"));
        assert!(cmds.contains(&"dial"));
        assert!(cmds.contains(&"hangup-all"));
        assert!(cmds.contains(&"list-calls"));
        assert!(cmds.contains(&"show-call"));
        assert!(cmds.contains(&"answer"));
        assert!(cmds.contains(&"hangup"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(BLUEZ_TELEPHONY_INTERFACE, "org.bluez.Telephony1");
        assert_eq!(BLUEZ_TELEPHONY_CALL_INTERFACE, "org.bluez.Call1");
        assert_eq!(BLUEZ_SERVICE, "org.bluez");
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_FAILURE, 1);
    }

    #[test]
    fn test_exports_exist() {
        // Verify public API functions exist and are callable as function pointers.
        let _add: fn() = telephony_add_submenu;
        let _remove: fn() = telephony_remove_submenu;
    }
}
