// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright 2024 NXP
//
//! Media assistant submenu — Rust rewrite of `client/assistant.c` (581 lines)
//! and `client/assistant.h` (13 lines).
//!
//! Provides the "assistant" submenu for `org.bluez.MediaAssistant1` discovery,
//! listing, and interactive `Push` configuration.
//!
//! # Behavioral Fidelity
//!
//! This module produces identical shell output and accepts identical command
//! arguments as the C original.  The `list`, `show`, and `push` commands
//! replicate the exact error messages, output formatting, and non-interactive
//! exit behavior of `client/assistant.c`.
//!
//! # Transformation Summary
//!
//! - `GDBusProxy`      → `zbus::proxy::Proxy` (created on demand from cached paths)
//! - `GDBusClient`     → `zbus::fdo::ObjectManagerProxy` signal subscriptions
//! - `GList`           → `Vec<AssistantData>`
//! - `DBusConnection`  → `zbus::Connection`
//! - `g_dbus_proxy_method_call("Push", ...)` → `proxy.call_method("Push", &args).await`
//! - `g_dbus_proxy_get_property` → cached `OwnedValue` or `proxy.get_property().await`
//! - `struct bt_iso_qos` → `bt_iso_qos` from `bluez_shared::sys::bluetooth`
//! - `rl_prompt_input` chain → `bt_shell_prompt_input` with `FnOnce` closures
//! - `g_strdup_printf` → `format!()`
//! - `g_free` → automatic `Drop`

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use futures::StreamExt as _;
use tokio::sync::Mutex;
use zbus::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, bt_shell_add_submenu, bt_shell_get_env,
    bt_shell_noninteractive_quit, bt_shell_printf, bt_shell_prompt_input, bt_shell_remove_submenu,
};
use bluez_shared::sys::bluetooth::{bt_iso_bcast_qos, bt_iso_io_qos, bt_iso_qos};

use crate::display::{COLOR_GREEN, COLOR_OFF, COLOR_RED, COLOR_YELLOW};
use crate::print::{print_iter, print_property};

// ---------------------------------------------------------------------------
// Constants — matching C `assistant.c` lines 39-46
// ---------------------------------------------------------------------------

/// Successful exit status for `bt_shell_noninteractive_quit`.
const EXIT_SUCCESS: i32 = 0;

/// Failure exit status for `bt_shell_noninteractive_quit`.
const EXIT_FAILURE: i32 = 1;

/// D-Bus interface name for the MediaAssistant1 proxy.
const MEDIA_ASSISTANT_INTERFACE: &str = "org.bluez.MediaAssistant1";

/// Broadcast code length in bytes.
const BCODE_LEN: usize = 16;

/// D-Bus well-known name of the BlueZ daemon.
const BLUEZ_SERVICE: &str = "org.bluez";

// ---------------------------------------------------------------------------
// Color display helpers — replacing C macros (assistant.c lines 39-42)
// ---------------------------------------------------------------------------

/// Formatted "NEW" label in green — replaces C `COLORED_NEW`.
fn colored_new() -> String {
    format!("{COLOR_GREEN}NEW{COLOR_OFF}")
}

/// Formatted "CHG" label in yellow — replaces C `COLORED_CHG`.
fn colored_chg() -> String {
    format!("{COLOR_YELLOW}CHG{COLOR_OFF}")
}

/// Formatted "DEL" label in red — replaces C `COLORED_DEL`.
fn colored_del() -> String {
    format!("{COLOR_RED}DEL{COLOR_OFF}")
}

// ---------------------------------------------------------------------------
// Data types — replacing C structs (assistant.c lines 48-54)
// ---------------------------------------------------------------------------

/// Cached data for a tracked `MediaAssistant1` D-Bus proxy.
///
/// Replaces the C `GList *assistants` entries.  Instead of holding a live
/// `GDBusProxy *`, we store the object path and a local property cache.
/// Short-lived `zbus::proxy::Proxy` instances are created on demand for
/// D-Bus operations, avoiding lifetime issues.
struct AssistantData {
    /// D-Bus object path (e.g., `/org/bluez/hci0/dev_XX_XX/.../assistant0`).
    path: String,
    /// Cached D-Bus properties from the `InterfacesAdded` signal and
    /// subsequent `PropertiesChanged` updates.
    properties: HashMap<String, OwnedValue>,
}

/// Configuration accumulated during the interactive `Push` flow.
///
/// Replaces C `struct assistant_config` (assistant.c lines 48-54).
/// Passed through the prompt callback chain via `Box` captures.
struct PushConfig {
    /// D-Bus object path of the target assistant.
    path: String,
    /// Cached assistant state from the `State` property.
    state: Option<String>,
    /// Device object path entered by the user (for "local" state).
    device: Option<String>,
    /// Metadata LTV bytes entered by the user.
    meta: Option<Vec<u8>>,
    /// ISO QoS parameters — `bcast` variant is accessed for encryption
    /// flag and broadcast code during the push configuration flow.
    qos: bt_iso_qos,
}

// ---------------------------------------------------------------------------
// Module state — replacing C statics (assistant.c lines 56-58, 556)
// ---------------------------------------------------------------------------

/// Module-level mutable state replacing the C static variables:
///
/// - `DBusConnection *dbus_conn` → `dbus_conn: Option<Connection>`
/// - `GList *assistants`         → `assistants: Vec<AssistantData>`
/// - `GDBusClient *client`       → `watcher_active: bool`
struct AssistantState {
    /// D-Bus connection retrieved from the shell environment.
    dbus_conn: Option<Connection>,
    /// Tracked assistant proxies (replaces `GList *assistants`).
    assistants: Vec<AssistantData>,
    /// Whether the background D-Bus watcher task has been spawned.
    watcher_active: bool,
}

impl AssistantState {
    /// Create a fresh, empty state.
    fn new() -> Self {
        Self { dbus_conn: None, assistants: Vec::new(), watcher_active: false }
    }

    /// Clear all state (disconnect handler).
    fn clear(&mut self) {
        for a in &self.assistants {
            bt_shell_printf(format_args!("Assistant {} unregistered\n", a.path));
        }
        self.assistants.clear();
        self.dbus_conn = None;
        self.watcher_active = false;
    }
}

/// Global assistant module state, protected by a `tokio::sync::Mutex` for
/// safe access from both synchronous shell callbacks (via `blocking_lock`)
/// and asynchronous watcher tasks (via `.lock().await`).
static STATE: LazyLock<Arc<Mutex<AssistantState>>> =
    LazyLock::new(|| Arc::new(Mutex::new(AssistantState::new())));

// ---------------------------------------------------------------------------
// Utility functions — replacing C helpers (assistant.c lines 62-85)
// ---------------------------------------------------------------------------

/// Format a proxy description string.
///
/// Replaces C `proxy_description` (assistant.c lines 62-74).
///
/// Returns:
/// - With description: `"[description] title path "`
/// - Without description: `"title path "`
fn proxy_description(path: &str, title: &str, description: Option<&str>) -> String {
    match description {
        Some(desc) => format!("[{desc}] {title} {path} "),
        None => format!("{title} {path} "),
    }
}

/// Print a formatted assistant description to the shell.
///
/// Replaces C `print_assistant` (assistant.c lines 76-85).
fn print_assistant(path: &str, description: Option<&str>) {
    let desc = proxy_description(path, "Assistant", description);
    bt_shell_printf(format_args!("{desc}\n"));
}

/// Print all properties of a `MediaAssistant1` proxy.
///
/// Replaces C `print_assistant_properties` (assistant.c lines 487-494).
///
/// This is an async function because `print_property` (from the `print`
/// module) performs D-Bus property reads through `zbus::proxy::Proxy`.
async fn print_assistant_properties(conn: &Connection, path: &str) {
    bt_shell_printf(format_args!("Transport {path}\n"));

    let proxy = match create_assistant_proxy(conn, path).await {
        Some(p) => p,
        None => return,
    };

    print_property(&proxy, "State").await;
    print_property(&proxy, "Metadata").await;
    print_property(&proxy, "QoS").await;
}

// ---------------------------------------------------------------------------
// D-Bus proxy creation helper
// ---------------------------------------------------------------------------

/// Create a short-lived `zbus::proxy::Proxy` for the `MediaAssistant1`
/// interface at the given path.
async fn create_assistant_proxy<'a>(
    conn: &'a Connection,
    path: &'a str,
) -> Option<zbus::proxy::Proxy<'a>> {
    zbus::proxy::Builder::new(conn)
        .destination(BLUEZ_SERVICE)
        .ok()?
        .path(path)
        .ok()?
        .interface(MEDIA_ASSISTANT_INTERFACE)
        .ok()?
        .build()
        .await
        .ok()
}

// ---------------------------------------------------------------------------
// Byte array parser — replacing C str2bytearray (assistant.c lines 156-186)
// ---------------------------------------------------------------------------

/// Parse a whitespace-separated string of integer tokens into a byte vector.
///
/// Replaces C `str2bytearray` (assistant.c lines 156-186).
///
/// Each token is parsed as an integer via `strtol(entry, ..., 0)` semantics —
/// supporting decimal, hex (`0x` prefix), and octal (`0` prefix). Values must
/// be in `0..=255`. The maximum number of bytes is 255 (`UINT8_MAX`).
///
/// Returns `None` on parse errors (matching C returning `NULL`).
fn str2bytearray(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();

    for (i, token) in input.split_whitespace().enumerate() {
        if token.is_empty() {
            continue;
        }
        if i >= u8::MAX as usize {
            bt_shell_printf(format_args!("Too much data\n"));
            return None;
        }

        // Parse with C `strtol(..., 0)` semantics:
        // - "0x..." → hex
        // - "0..."  → octal
        // - else    → decimal
        let val: i64 =
            if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
                i64::from_str_radix(hex, 16).ok()?
            } else if token.starts_with('0') && token.len() > 1 {
                i64::from_str_radix(token, 8).unwrap_or_else(|_| {
                    // Fall back to decimal if not valid octal
                    token.parse::<i64>().unwrap_or(-1)
                })
            } else {
                token.parse::<i64>().unwrap_or_else(|_| {
                    bt_shell_printf(format_args!("Invalid value at index {i}\n"));
                    -1
                })
            };

        if val < 0 || val > i64::from(u8::MAX) {
            bt_shell_printf(format_args!("Invalid value at index {i}\n"));
            return None;
        }

        result.push(val as u8);
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// QoS property parsing — replacing C assistant_get_qos (assistant.c 294-349)
// ---------------------------------------------------------------------------

/// Parse QoS data from cached D-Bus property values.
///
/// Replaces C `assistant_get_qos` (assistant.c lines 294-349) which reads
/// the "QoS" property from the proxy's cache. The QoS is a `a{sv}` dict
/// containing "Encryption" (byte) and "BCode" (byte array `ay`) entries.
///
/// Returns `true` if QoS was successfully parsed; `false` otherwise.
fn parse_qos_from_properties(
    properties: &HashMap<String, OwnedValue>,
    qos: &mut bt_iso_qos,
) -> bool {
    let qos_val = match properties.get("QoS") {
        Some(v) => v,
        None => return false,
    };

    // Unwrap variant wrapper if present
    let inner: &Value<'_> = match &**qos_val {
        Value::Value(inner) => inner,
        other => other,
    };

    // Expect a dict (a{sv})
    let dict = match inner {
        Value::Dict(d) => d,
        _ => return false,
    };

    let mut bcast = qos.as_bcast();

    for (key, val) in dict.iter() {
        let key_str = match key {
            Value::Str(s) => s.as_str(),
            _ => continue,
        };

        // Unwrap variant wrapper on value
        let unwrapped = match val {
            Value::Value(inner) => &**inner,
            other => other,
        };

        if key_str.eq_ignore_ascii_case("Encryption") {
            match unwrapped {
                Value::U8(v) => bcast.encryption = *v,
                _ => return false,
            }
        } else if key_str.eq_ignore_ascii_case("BCode") {
            match unwrapped {
                Value::Array(arr) => {
                    let bytes: Vec<u8> = arr
                        .inner()
                        .iter()
                        .filter_map(|v| if let Value::U8(b) = v { Some(*b) } else { None })
                        .collect();

                    if bytes.len() != BCODE_LEN {
                        bt_shell_printf(format_args!(
                            "Invalid size for BCode: {} != {BCODE_LEN}\n",
                            bytes.len()
                        ));
                        return false;
                    }

                    bcast.bcode.copy_from_slice(&bytes);
                }
                _ => return false,
            }
        }
    }

    *qos = bt_iso_qos::new_bcast(bcast);
    true
}

/// Create a zero-initialized broadcast QoS value.
fn zeroed_bcast_qos() -> bt_iso_qos {
    bt_iso_qos::new_bcast(bt_iso_bcast_qos {
        big: 0,
        bis: 0,
        sync_factor: 0,
        packing: 0,
        framing: 0,
        in_qos: bt_iso_io_qos::default(),
        out_qos: bt_iso_io_qos::default(),
        encryption: 0,
        bcode: [0u8; 16],
        options: 0,
        skip: 0,
        sync_timeout: 0,
        sync_cte_type: 0,
        mse: 0,
        timeout: 0,
    })
}

// ---------------------------------------------------------------------------
// Push D-Bus method call — replacing C push_setup/push_reply
// (assistant.c lines 188-261)
// ---------------------------------------------------------------------------

/// Execute the `Push` D-Bus method call on the assistant proxy.
///
/// Replaces C `push_setup` + `push_reply` (assistant.c lines 215-261).
///
/// Builds a `a{sv}` dict argument containing:
/// - `"Metadata"`: byte array (if metadata was provided)
/// - `"Device"`: object path (if device path was provided)
/// - `"QoS"`: nested dict with `"BCode"` byte array (if encryption is set)
async fn execute_push(conn: &Connection, cfg: &PushConfig) {
    let proxy = match create_assistant_proxy(conn, &cfg.path).await {
        Some(p) => p,
        None => {
            bt_shell_printf(format_args!("Failed to push assistant\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Build the argument dict: a{sv}
    let mut dict_entries: HashMap<String, Value<'_>> = HashMap::new();

    // Add Metadata if present
    let meta_clone;
    if let Some(ref meta) = cfg.meta {
        meta_clone = meta.clone();
        dict_entries.insert("Metadata".to_string(), Value::Array(meta_clone.as_slice().into()));
    }

    // Add Device if present
    let device_path;
    if let Some(ref device) = cfg.device {
        device_path = OwnedObjectPath::try_from(device.as_str())
            .unwrap_or_else(|_| OwnedObjectPath::try_from("/").expect("root path is valid"));
        dict_entries.insert("Device".to_string(), Value::ObjectPath(device_path.as_ref()));
    }

    // Add QoS if encryption is set
    let bcast = cfg.qos.as_bcast();
    let bcode_vec;
    if bcast.encryption != 0 {
        bcode_vec = bcast.bcode.to_vec();
        let mut qos_inner: HashMap<String, Value<'_>> = HashMap::new();
        qos_inner.insert("BCode".to_string(), Value::Array(bcode_vec.as_slice().into()));
        dict_entries.insert("QoS".to_string(), Value::Value(Box::new(Value::from(qos_inner))));
    }

    match proxy.call_method("Push", &(dict_entries,)).await {
        Ok(_) => {
            bt_shell_printf(format_args!("Assistant {} pushed\n", cfg.path));
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Err(zbus::Error::MethodError(ref name, _, _)) => {
            bt_shell_printf(format_args!("Failed to push assistant: {}\n", name.as_str()));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        }
        Err(_) => {
            bt_shell_printf(format_args!("Failed to push assistant\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive prompt chain — replacing C callback functions
// (assistant.c lines 263-473)
// ---------------------------------------------------------------------------

/// Final step of the push flow: set broadcast code and execute Push.
///
/// Replaces C `assistant_set_bcode_cfg` (assistant.c lines 263-292).
///
/// If input is "a" or "auto", the broadcast code is zeroed. Otherwise the
/// input string is copied byte-by-byte into the broadcast code (up to 16
/// bytes). Then the Push method is called.
fn assistant_set_bcode_cfg(input: &str, mut cfg: PushConfig) {
    if input.eq_ignore_ascii_case("a") || input.eq_ignore_ascii_case("auto") {
        // Zero the broadcast code
        let mut bcast = cfg.qos.as_bcast();
        bcast.bcode = [0u8; BCODE_LEN];
        cfg.qos = bt_iso_qos::new_bcast(bcast);
    } else {
        let input_bytes = input.as_bytes();
        if input_bytes.len() > BCODE_LEN {
            bt_shell_printf(format_args!("Input string too long {input}\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }

        let mut bcast = cfg.qos.as_bcast();
        let mut new_bcode = [0u8; BCODE_LEN];
        new_bcode[..input_bytes.len()].copy_from_slice(input_bytes);
        bcast.bcode = new_bcode;
        cfg.qos = bt_iso_qos::new_bcast(bcast);
    }

    // Spawn the async Push call
    let state = STATE.clone();
    tokio::spawn(async move {
        let guard = state.lock().await;
        let conn = match &guard.dbus_conn {
            Some(c) => c.clone(),
            None => {
                bt_shell_printf(format_args!("Failed to push assistant\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        };
        drop(guard);
        execute_push(&conn, &cfg).await;
    });
}

/// Check QoS encryption and either prompt for broadcast code or execute Push.
///
/// This is the common tail of `assistant_set_metadata_cfg` and
/// `assistant_set_device_cfg`. If the stream is encrypted and no broadcast
/// code is set, the user is prompted to enter one.
fn check_encryption_and_push(cfg: PushConfig) {
    let bcast = cfg.qos.as_bcast();
    let no_bcode = [0u8; BCODE_LEN];

    if bcast.encryption != 0 && bcast.bcode == no_bcode {
        // Prompt user to enter the Broadcast Code to decrypt the stream
        bt_shell_prompt_input(
            "Assistant",
            "Enter Broadcast Code (auto/value):",
            Box::new(move |input| {
                assistant_set_bcode_cfg(input, cfg);
            }),
        );
    } else {
        // No encryption or broadcast code already set — push directly
        let state = STATE.clone();
        tokio::spawn(async move {
            let guard = state.lock().await;
            let conn = match &guard.dbus_conn {
                Some(c) => c.clone(),
                None => {
                    bt_shell_printf(format_args!("Failed to push assistant\n"));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                    return;
                }
            };
            drop(guard);
            execute_push(&conn, &cfg).await;
        });
    }
}

/// Prompt callback for metadata entry.
///
/// Replaces C `assistant_set_metadata_cfg` (assistant.c lines 351-396).
fn assistant_set_metadata_cfg(input: &str, mut cfg: PushConfig) {
    if !input.eq_ignore_ascii_case("a") && !input.eq_ignore_ascii_case("auto") {
        match str2bytearray(input) {
            Some(bytes) if !bytes.is_empty() => {
                cfg.meta = Some(bytes);
            }
            Some(_) => {
                // Empty result — leave meta as None
            }
            None => {
                // Parse error — str2bytearray already printed the error
                cfg.meta = None;
            }
        }
    }

    // Get QoS from cached properties
    let got_qos = {
        let state = STATE.clone();
        let guard = state.blocking_lock();
        if let Some(assistant) = guard.assistants.iter().find(|a| a.path == cfg.path) {
            parse_qos_from_properties(&assistant.properties, &mut cfg.qos)
        } else {
            false
        }
    };

    if !got_qos {
        bt_shell_printf(format_args!("Failed to push assistant\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    check_encryption_and_push(cfg);
}

/// Prompt callback for device path entry.
///
/// Replaces C `assistant_set_device_cfg` (assistant.c lines 398-433).
fn assistant_set_device_cfg(input: &str, mut cfg: PushConfig) {
    cfg.device = Some(input.to_string());

    // Get QoS from cached properties
    let got_qos = {
        let state = STATE.clone();
        let guard = state.blocking_lock();
        if let Some(assistant) = guard.assistants.iter().find(|a| a.path == cfg.path) {
            parse_qos_from_properties(&assistant.properties, &mut cfg.qos)
        } else {
            false
        }
    };

    if !got_qos {
        bt_shell_printf(format_args!("Failed to push assistant\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    check_encryption_and_push(cfg);
}

// ---------------------------------------------------------------------------
// Shell command handlers — replacing C cmd_* functions
// (assistant.c lines 435-539)
// ---------------------------------------------------------------------------

/// Shell command: `push <assistant>` — send stream information to peer.
///
/// Replaces C `cmd_push_assistant` (assistant.c lines 435-473).
///
/// Creates a `PushConfig`, looks up the assistant by path, checks the cached
/// `State` property, and starts the appropriate interactive prompt chain.
fn cmd_push_assistant(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_printf(format_args!("Missing assistant argument\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    let path = args[1].to_string();

    let mut cfg = PushConfig {
        path: path.clone(),
        state: None,
        device: None,
        meta: None,
        qos: zeroed_bcast_qos(),
    };

    // Look up the assistant and read cached State property
    let found = {
        let state = STATE.clone();
        let guard = state.blocking_lock();
        if let Some(assistant) = guard.assistants.iter().find(|a| a.path == path) {
            // Read cached State property
            if let Some(state_val) = assistant.properties.get("State") {
                if let Value::Str(s) = &**state_val {
                    cfg.state = Some(s.to_string());
                } else if let Value::Value(inner) = &**state_val {
                    if let Value::Str(s) = &**inner {
                        cfg.state = Some(s.to_string());
                    }
                }
            }
            true
        } else {
            false
        }
    };

    if !found {
        bt_shell_printf(format_args!("Assistant {} not found\n", args[1]));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    // Route based on state — identical to C logic (assistant.c lines 452-468)
    if cfg.state.as_deref() == Some("local") {
        // Prompt user to enter device path
        bt_shell_prompt_input(
            "Assistant",
            "Enter Device (path):",
            Box::new(move |input| {
                assistant_set_device_cfg(input, cfg);
            }),
        );
    } else {
        // Prompt user to enter metadata
        bt_shell_prompt_input(
            "Assistant",
            "Enter Metadata (auto/value):",
            Box::new(move |input| {
                assistant_set_metadata_cfg(input, cfg);
            }),
        );
    }
}

/// Shell command: `list` — list available assistants.
///
/// Replaces C `cmd_list_assistant` (assistant.c lines 475-485).
fn cmd_list_assistant(args: &[&str]) {
    let _ = args;
    let state = STATE.clone();
    let guard = state.blocking_lock();
    for assistant in &guard.assistants {
        print_assistant(&assistant.path, None);
    }
    drop(guard);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Shell command: `show [assistant]` — display assistant properties.
///
/// Replaces C `cmd_show_assistant` (assistant.c lines 519-539).
///
/// If no argument is given, shows all assistants. If a path is specified,
/// shows properties for that specific assistant.
fn cmd_show_assistant(args: &[&str]) {
    let state = STATE.clone();

    if args.len() < 2 {
        // Show all assistants
        let paths: Vec<String> = {
            let guard = state.blocking_lock();
            guard.assistants.iter().map(|a| a.path.clone()).collect()
        };

        let state_clone = state.clone();
        tokio::spawn(async move {
            let guard = state_clone.lock().await;
            let conn = match &guard.dbus_conn {
                Some(c) => c.clone(),
                None => {
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                    return;
                }
            };
            drop(guard);

            for path in &paths {
                print_assistant_properties(&conn, path).await;
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        });
        return;
    }

    let path = args[1].to_string();

    // Check that the assistant exists
    let found = {
        let guard = state.blocking_lock();
        guard.assistants.iter().any(|a| a.path == path)
    };

    if !found {
        bt_shell_printf(format_args!("Assistant {} not found\n", args[1]));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    tokio::spawn(async move {
        let guard = state.lock().await;
        let conn = match &guard.dbus_conn {
            Some(c) => c.clone(),
            None => {
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        };
        drop(guard);

        print_assistant_properties(&conn, &path).await;
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
    });
}

// ---------------------------------------------------------------------------
// Tab completion generator — replacing C assistant_generator
// (assistant.c lines 501-517)
// ---------------------------------------------------------------------------

/// Tab-completion generator for assistant object paths.
///
/// Replaces C `assistant_generator` (assistant.c lines 514-517) and
/// `generic_generator` (assistant.c lines 501-512).
fn assistant_generator(text: &str, state: i32) -> Option<String> {
    let guard = STATE.blocking_lock();
    let mut index = 0i32;
    for assistant in &guard.assistants {
        if index < state {
            index += 1;
            continue;
        }
        if assistant.path.starts_with(text) || text.is_empty() {
            return Some(assistant.path.clone());
        }
        index += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Menu definition — replacing C assistant_menu (assistant.c lines 541-554)
// ---------------------------------------------------------------------------

/// The "assistant" submenu registered with the shell framework.
///
/// Replaces C `assistant_menu` (assistant.c lines 541-554).
static ASSISTANT_MENU: BtShellMenu = BtShellMenu {
    name: "assistant",
    desc: Some("Media Assistant Submenu"),
    pre_run: Some(assistant_menu_pre_run),
    entries: &[
        BtShellMenuEntry {
            cmd: "list",
            arg: None,
            func: cmd_list_assistant,
            desc: "List available assistants",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "show",
            arg: Some("[assistant]"),
            func: cmd_show_assistant,
            desc: "Assistant information",
            r#gen: Some(assistant_generator),
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "push",
            arg: Some("<assistant>"),
            func: cmd_push_assistant,
            desc: "Send stream information to peer",
            r#gen: Some(assistant_generator),
            disp: None,
            exists: None,
        },
    ],
};

// ---------------------------------------------------------------------------
// Background D-Bus watcher — replacing GDBusClient proxy tracking
// (assistant.c lines 87-154, 563-574)
// ---------------------------------------------------------------------------

/// Background task that uses the D-Bus `ObjectManager` interface to discover
/// existing `MediaAssistant1` interfaces and monitor for future
/// additions/removals.
///
/// Replaces:
/// - `proxy_added` (assistant.c lines 94-102)
/// - `proxy_removed` (assistant.c lines 111-119)
/// - `property_changed` (assistant.c lines 131-140)
/// - `disconnect_handler` (assistant.c lines 150-154)
async fn run_proxy_watcher(conn: Connection, state: Arc<Mutex<AssistantState>>) {
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
        Err(_) => return,
    };

    // Phase 1: Discover already-exported MediaAssistant1 objects.
    if let Ok(objects) = om_proxy.get_managed_objects().await {
        let mut guard = state.lock().await;
        for (path, interfaces) in &objects {
            if let Some(props) = interfaces.get(MEDIA_ASSISTANT_INTERFACE) {
                let path_str = path.to_string();
                let properties: HashMap<String, OwnedValue> =
                    props.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();

                // Print discovery notification (same as C proxy_added)
                print_assistant(&path_str, Some(&colored_new()));

                guard.assistants.push(AssistantData { path: path_str, properties });
            }
        }
    }

    // Phase 2: Subscribe to PropertiesChanged for property tracking.
    // This uses a connection-level match rule to monitor all
    // MediaAssistant1 property changes from the BlueZ service.
    let props_stream_result: Result<zbus::MessageStream, zbus::Error> = async {
        let props_rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(BLUEZ_SERVICE)?
            .interface("org.freedesktop.DBus.Properties")?
            .member("PropertiesChanged")?
            .build();
        zbus::MessageStream::for_match_rule(props_rule, &conn, None).await
    }
    .await;

    // Phase 3: Monitor for future interface additions / removals.
    let added_result = om_proxy.receive_interfaces_added().await;
    let removed_result = om_proxy.receive_interfaces_removed().await;

    let (Ok(mut added_stream), Ok(mut removed_stream)) = (added_result, removed_result) else {
        return;
    };
    let mut props_stream = props_stream_result.ok();

    loop {
        // Build the select! arms dynamically based on whether we have
        // a props stream.
        tokio::select! {
            added = added_stream.next() => {
                let Some(signal) = added else { break; };
                if let Ok(args) = signal.args() {
                    let path_str = args.object_path().to_string();
                    if let Some(props) = args.interfaces_and_properties().get(MEDIA_ASSISTANT_INTERFACE) {
                        let properties: HashMap<String, OwnedValue> = props
                            .iter()
                            .filter_map(|(k, v)| {
                                OwnedValue::try_from(v.clone())
                                    .ok()
                                    .map(|owned| (k.to_string(), owned))
                            })
                            .collect();

                        print_assistant(&path_str, Some(&colored_new()));

                        let mut guard = state.lock().await;
                        guard.assistants.push(AssistantData {
                            path: path_str,
                            properties,
                        });
                    }
                }
            }
            removed = removed_stream.next() => {
                let Some(signal) = removed else { break; };
                if let Ok(args) = signal.args() {
                    let path_str = args.object_path().to_string();
                    let has_assistant = args.interfaces().iter().any(|iface| {
                        iface.as_str() == MEDIA_ASSISTANT_INTERFACE
                    });
                    if has_assistant {
                        print_assistant(&path_str, Some(&colored_del()));

                        let mut guard = state.lock().await;
                        guard.assistants.retain(|a| a.path != path_str);
                    }
                }
            }
            props_msg = async {
                match &mut props_stream {
                    Some(stream) => stream.next().await,
                    None => std::future::pending().await,
                }
            } => {
                match props_msg {
                    Some(Ok(msg)) => {
                        handle_properties_changed(&msg, &state).await;
                    }
                    Some(Err(_)) => { /* skip malformed messages */ }
                    None => break,
                }
            }
        }
    }

    // Streams ended — service disconnected.  Clear state.
    let mut guard = state.lock().await;
    guard.clear();
}

// ---------------------------------------------------------------------------
// PropertiesChanged handler — replacing C property_changed
// (assistant.c lines 131-140)
// ---------------------------------------------------------------------------

/// Handle a `PropertiesChanged` D-Bus signal by updating the cached
/// properties of the corresponding assistant and printing the change
/// notification.
///
/// Replaces C `property_changed` (assistant.c lines 131-140):
/// ```c
/// str = proxy_description(proxy, "Assistant", COLORED_CHG);
/// print_iter(str, name, iter);
/// ```
async fn handle_properties_changed(msg: &zbus::Message, state: &Arc<Mutex<AssistantState>>) {
    // PropertiesChanged signal body: (interface: s, changed: a{sv}, invalidated: as)
    let body = msg.body();
    let Ok((iface_name, changed_props, _invalidated)): Result<
        (String, HashMap<String, OwnedValue>, Vec<String>),
        _,
    > = body.deserialize() else {
        return;
    };

    // Only process changes for MediaAssistant1.
    if iface_name != MEDIA_ASSISTANT_INTERFACE {
        return;
    }

    // Get the path from the message header.
    let header = msg.header();
    let Some(path) = header.path() else {
        return;
    };
    let path_str = path.to_string();

    // Update cached properties and print change notification.
    let mut guard = state.lock().await;
    let Some(assistant) = guard.assistants.iter_mut().find(|a| a.path == path_str) else {
        return;
    };

    for (name, value) in &changed_props {
        // Print the change notification using print_iter (from print module).
        let desc = proxy_description(&path_str, "Assistant", Some(&colored_chg()));
        print_iter(&desc, name, &Value::from(value.clone()));

        // Update the property cache.
        assistant.properties.insert(name.clone(), value.clone());
    }
}

// ---------------------------------------------------------------------------
// Menu pre-run hook — replacing C assistant_menu_pre_run
// (assistant.c lines 563-574)
// ---------------------------------------------------------------------------

/// Lazy D-Bus client initialization, called each time the assistant submenu
/// is entered.
///
/// Retrieves the D-Bus connection from the shell environment and spawns a
/// background watcher that monitors `org.bluez` for the appearance and
/// removal of `MediaAssistant1` interfaces.
///
/// Replaces C `assistant_menu_pre_run` (assistant.c lines 563-574):
/// ```c
/// dbus_conn = bt_shell_get_env("DBUS_CONNECTION");
/// if (!dbus_conn || client) return;
/// client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");
/// g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
///                                  property_changed, NULL);
/// g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);
/// ```
fn assistant_menu_pre_run(_menu: &BtShellMenu) {
    let conn: Connection = match bt_shell_get_env::<Connection>("DBUS_CONNECTION") {
        Some(c) => c,
        None => return,
    };

    let state = STATE.clone();

    // Guard: if watcher already active, nothing to do.
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

    // Spawn background task to discover and monitor assistant interfaces.
    let state_for_task = state;
    tokio::spawn(async move {
        run_proxy_watcher(conn, state_for_task).await;
    });
}

// ---------------------------------------------------------------------------
// Public API — replacing C assistant_add_submenu / assistant_remove_submenu
// (assistant.c lines 558-561, 576-580)
// ---------------------------------------------------------------------------

/// Register the assistant submenu with the shell.
///
/// Replaces C `assistant_add_submenu()` (assistant.c lines 558-561).
pub fn assistant_add_submenu() {
    bt_shell_add_submenu(&ASSISTANT_MENU);
}

/// Unregister the assistant submenu and clean up D-Bus client state.
///
/// Replaces C `assistant_remove_submenu()` (assistant.c lines 576-580).
/// The C original calls `g_dbus_client_unref(client); client = NULL;`.
pub fn assistant_remove_submenu() {
    let state = STATE.clone();
    state.blocking_lock().clear();
    bt_shell_remove_submenu(&ASSISTANT_MENU);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_description_with_description() {
        let result = proxy_description("/org/bluez/hci0/assistant0", "Assistant", Some("NEW"));
        assert_eq!(result, "[NEW] Assistant /org/bluez/hci0/assistant0 ");
    }

    #[test]
    fn test_proxy_description_without_description() {
        let result = proxy_description("/org/bluez/hci0/assistant0", "Assistant", None);
        assert_eq!(result, "Assistant /org/bluez/hci0/assistant0 ");
    }

    #[test]
    fn test_str2bytearray_valid_decimal() {
        let result = str2bytearray("1 2 3 255");
        assert_eq!(result, Some(vec![1, 2, 3, 255]));
    }

    #[test]
    fn test_str2bytearray_valid_hex() {
        let result = str2bytearray("0x01 0xFF 0x10");
        assert_eq!(result, Some(vec![1, 255, 16]));
    }

    #[test]
    fn test_str2bytearray_empty() {
        let result = str2bytearray("");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn test_str2bytearray_overflow() {
        let result = str2bytearray("256");
        assert!(result.is_none());
    }

    #[test]
    fn test_zeroed_bcast_qos() {
        let qos = zeroed_bcast_qos();
        let bcast = qos.as_bcast();
        assert_eq!(bcast.encryption, 0);
        assert_eq!(bcast.bcode, [0u8; 16]);
        assert_eq!(bcast.big, 0);
        assert_eq!(bcast.bis, 0);
    }

    #[test]
    fn test_colored_labels() {
        let new_label = colored_new();
        assert!(new_label.contains("NEW"));
        assert!(new_label.starts_with(COLOR_GREEN));
        assert!(new_label.ends_with(COLOR_OFF));

        let chg_label = colored_chg();
        assert!(chg_label.contains("CHG"));
        assert!(chg_label.starts_with(COLOR_YELLOW));

        let del_label = colored_del();
        assert!(del_label.contains("DEL"));
        assert!(del_label.starts_with(COLOR_RED));
    }

    #[test]
    fn test_assistant_state_new() {
        let state = AssistantState::new();
        assert!(state.dbus_conn.is_none());
        assert!(state.assistants.is_empty());
        assert!(!state.watcher_active);
    }
}
