// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! HCI submenu — Rust rewrite of `client/hci.c` (333 lines) and `client/hci.h`.
//!
//! Provides the **hci** submenu for raw/user HCI channel access, arbitrary
//! command/event handling in `bluetoothctl`.
//!
//! # Shell Commands
//!
//! | Command      | Arguments                            | Description                   |
//! |--------------|--------------------------------------|-------------------------------|
//! | `open`       | `<index> <chan=raw,user>`             | Open an HCI channel           |
//! | `cmd`        | `<opcode> [parameters...]`           | Send an HCI command           |
//! | `send`       | `<type=acl,sco,iso> <handle> [data]` | Send HCI data                 |
//! | `register`   | `<event>`                            | Register HCI event handler    |
//! | `unregister` | `<event>`                            | Unregister HCI event handler  |
//! | `close`      | —                                    | Close the HCI channel         |
//!
//! # Transformation Notes
//!
//! - `struct bt_hci *` → `Arc<HciTransport>` via `bluez_shared::hci::transport`
//! - `struct queue *events` → `Vec<HciEventEntry>`
//! - Callback + user_data patterns → `tokio::spawn` + closures
//! - `strtol(…, 0)` base‐0 parsing → [`parse_strtol`] helper
//! - GLib containers removed entirely

use std::sync::{Arc, Mutex};

use bluez_shared::hci::transport::{HciEvent, HciTransport};
use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, bt_shell_add_submenu, bt_shell_hexdump,
    bt_shell_noninteractive_quit, bt_shell_printf, bt_shell_remove_submenu,
};
use bluez_shared::sys::hci::{HCI_ACLDATA_PKT, HCI_ISODATA_PKT, HCI_SCODATA_PKT, cmd_opcode_pack};

// ---------------------------------------------------------------------------
// Constants — match C EXIT_SUCCESS / EXIT_FAILURE
// ---------------------------------------------------------------------------

/// Success exit status for non-interactive quit.
const EXIT_SUCCESS: i32 = 0;
/// Failure exit status for non-interactive quit.
const EXIT_FAILURE: i32 = 1;

// ---------------------------------------------------------------------------
// Local types — replaces C `struct hci_event` (hci.c lines 30-33)
// ---------------------------------------------------------------------------

/// Tracks a registered HCI event handler.
///
/// Replaces the C `struct hci_event` which stored the event code and the
/// `bt_hci_register()` subscription ID returned by the transport layer.
struct HciEventEntry {
    /// HCI event code (0x00..0xFF).
    event: u8,
    /// Subscription ID returned by [`HciTransport::subscribe`].
    id: u32,
}

// ---------------------------------------------------------------------------
// Module state — replaces C statics (hci.c lines 27-28)
// ---------------------------------------------------------------------------

/// Module-level mutable state, protected by a `std::sync::Mutex` because
/// shell command handlers are synchronous callbacks.
struct HciState {
    /// Active HCI transport handle (`None` when no channel is open).
    /// Replaces `static struct bt_hci *hci`.
    hci: Option<Arc<HciTransport>>,
    /// Registered event entries.  Replaces `static struct queue *events`.
    events: Vec<HciEventEntry>,
}

/// Global module state instance.
static STATE: Mutex<HciState> = Mutex::new(HciState { hci: None, events: Vec::new() });

// ---------------------------------------------------------------------------
// Helper — strtol(…, 0) compatible number parsing
// ---------------------------------------------------------------------------

/// Parse a string as an integer with automatic radix detection, matching the
/// behaviour of C `strtol(s, &endptr, 0)` with full-string validation.
///
/// Supported formats:
/// - `"0x1A"` / `"0X1A"` → hexadecimal (base 16)
/// - `"0777"` → octal (base 8)
/// - `"123"` → decimal (base 10)
/// - `"-42"` → negative decimal
///
/// Returns `None` if the string is empty, contains invalid characters, or
/// represents a number that cannot be stored in an `i64` (matching the C
/// `strtol` `*endptr != '\0'` rejection).
fn parse_strtol(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (negative, digits) =
        if let Some(rest) = s.strip_prefix('-') { (true, rest) } else { (false, s) };

    if digits.is_empty() {
        return None;
    }

    let magnitude: u64 =
        if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
            if hex.is_empty() {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()?
        } else if digits.starts_with('0') && digits.len() > 1 {
            // Octal: leading '0' followed by additional digits.
            // Digits 8/9 are rejected by from_str_radix(…, 8), matching
            // strtol base-0 which stops at the first non-octal character
            // and then fails the *endptr check.
            u64::from_str_radix(&digits[1..], 8).ok()?
        } else {
            digits.parse::<u64>().ok()?
        };

    if negative {
        // For practical HCI values this never overflows.  Extreme values
        // are caught by the subsequent range checks in each command.
        Some(-(magnitude as i64))
    } else {
        Some(magnitude as i64)
    }
}

// ---------------------------------------------------------------------------
// Helper — hex byte array parsing (replaces C str2bytearray, lines 73-103)
// ---------------------------------------------------------------------------

/// Parse a whitespace-separated string of numeric values into a byte vector.
///
/// Each token is interpreted via [`parse_strtol`] (supporting decimal, hex,
/// and octal formats).  Values must fit in a `u8` (0–255); negative values
/// wrap as in C unsigned truncation.  A maximum of 255 bytes is accepted.
///
/// Returns `None` on any parsing error, printing the appropriate error
/// message to the shell (matching C output exactly).
fn str2bytearray(arg: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();

    for (i, entry) in arg.split([' ', '\t']).enumerate() {
        if entry.is_empty() {
            continue;
        }

        if result.len() >= usize::from(u8::MAX) {
            bt_shell_printf(format_args!("Too much data\n"));
            return None;
        }

        let val = match parse_strtol(entry) {
            Some(v) => v,
            None => {
                bt_shell_printf(format_args!("Invalid value at index {i}\n"));
                return None;
            }
        };

        if val > i64::from(u8::MAX) {
            bt_shell_printf(format_args!("Invalid value at index {i}\n"));
            return None;
        }

        // Negative values wrap identically to C unsigned truncation.
        result.push(val as u8);
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Shell command: open  (replaces C hci_open, lines 35-71)
// ---------------------------------------------------------------------------

/// Open a raw or user HCI channel on the specified controller index.
///
/// Usage: `open <index> <raw|user>`
fn hci_open(args: &[&str]) {
    if args.len() < 3 {
        bt_shell_printf(format_args!("Missing arguments\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    // Reject if a channel is already open.
    {
        let state = STATE.lock().unwrap();
        if state.hci.is_some() {
            bt_shell_printf(format_args!("HCI channel already open\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    }

    // Parse controller index.
    let index = match parse_strtol(args[1]) {
        Some(v) if v >= 0 && v <= i64::from(u16::MAX) => v as u16,
        _ => {
            bt_shell_printf(format_args!("Invalid index: {}\n", args[1]));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Parse channel type (case-insensitive).
    let channel = args[2];
    let transport_result = if channel.eq_ignore_ascii_case("raw") {
        HciTransport::new_raw_device(index)
    } else if channel.eq_ignore_ascii_case("user") {
        HciTransport::new_user_channel(index)
    } else {
        bt_shell_printf(format_args!("Invalid channel: {channel}\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    };

    match transport_result {
        Ok(transport) => {
            STATE.lock().unwrap().hci = Some(transport);
            bt_shell_printf(format_args!("HCI index {index} {channel} channel opened\n"));
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Err(_) => {
            bt_shell_printf(format_args!(
                "Unable to open {} channel\n",
                channel.to_ascii_lowercase()
            ));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
        }
    }
}

// ---------------------------------------------------------------------------
// Shell command: close  (replaces C hci_close, lines 283-296)
// ---------------------------------------------------------------------------

/// Close the currently open HCI channel.
///
/// Usage: `close`
fn hci_close(_args: &[&str]) {
    let mut state = STATE.lock().unwrap();

    if state.hci.is_none() {
        bt_shell_printf(format_args!("HCI channel not open\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    // Drop the transport (decrements Arc, replaces bt_hci_unref).
    state.hci = None;

    bt_shell_printf(format_args!("HCI channel closed\n"));
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

// ---------------------------------------------------------------------------
// Shell command: cmd  (replaces C hci_cmd + hci_cmd_complete, lines 105-146)
// ---------------------------------------------------------------------------

/// Send an HCI command and print the response.
///
/// Usage: `cmd <opcode> [parameters...]`
///
/// The opcode is a pre-packed u16 value (OGF << 10 | OCF).  Optional
/// parameters are whitespace-separated numeric byte values.
fn hci_cmd(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_printf(format_args!("Missing opcode\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    let transport = {
        let state = STATE.lock().unwrap();
        match state.hci.as_ref() {
            Some(hci) => Arc::clone(hci),
            None => {
                bt_shell_printf(format_args!("HCI channel not open\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    };

    // Parse opcode (accepts decimal, hex, octal via parse_strtol).
    let opcode_val = match parse_strtol(args[1]) {
        Some(v) if v >= 0 && v <= i64::from(u16::MAX) => v as u16,
        _ => {
            bt_shell_printf(format_args!("Invalid opcode: {}\n", args[1]));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Reconstruct through cmd_opcode_pack to validate OGF/OCF decomposition.
    let ogf = opcode_val >> 10;
    let ocf = opcode_val & 0x03FF;
    let opcode = cmd_opcode_pack(ogf, ocf);

    // Parse optional parameter bytes.
    let params = if args.len() > 2 {
        match str2bytearray(args[2]) {
            Some(data) => data,
            None => {
                bt_shell_printf(format_args!("Invalid parameters: {}\n", args[2]));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    } else {
        Vec::new()
    };

    // Spawn async task to send the command and handle the response
    // (replaces C callback hci_cmd_complete).
    tokio::spawn(async move {
        match transport.send_command(opcode, &params).await {
            Ok(response) => {
                bt_shell_printf(format_args!("HCI Command complete:\n"));
                bt_shell_hexdump(&response.data);
                bt_shell_noninteractive_quit(EXIT_SUCCESS);
            }
            Err(_) => {
                bt_shell_noninteractive_quit(EXIT_FAILURE);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Shell command: send  (replaces C hci_send, lines 148-191)
// ---------------------------------------------------------------------------

/// Send raw HCI data (ACL, SCO, or ISO).
///
/// Usage: `send <type=acl,sco,iso> <handle> [data...]`
fn hci_send(args: &[&str]) {
    if args.len() < 3 {
        bt_shell_printf(format_args!("Missing arguments\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    let transport = {
        let state = STATE.lock().unwrap();
        match state.hci.as_ref() {
            Some(hci) => Arc::clone(hci),
            None => {
                bt_shell_printf(format_args!("HCI channel not open\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    };

    // Parse packet type (case-insensitive).
    let ptype = if args[1].eq_ignore_ascii_case("acl") {
        HCI_ACLDATA_PKT
    } else if args[1].eq_ignore_ascii_case("sco") {
        HCI_SCODATA_PKT
    } else if args[1].eq_ignore_ascii_case("iso") {
        HCI_ISODATA_PKT
    } else {
        bt_shell_printf(format_args!("Invalid type: {}\n", args[1]));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    };

    // Parse connection handle.
    let handle = match parse_strtol(args[2]) {
        Some(v) if v >= 0 && v <= i64::from(u16::MAX) => v as u16,
        _ => {
            bt_shell_printf(format_args!("Invalid handle: {}\n", args[2]));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Parse optional data bytes.
    let data = if args.len() > 3 {
        match str2bytearray(args[3]) {
            Some(d) => d,
            None => {
                bt_shell_printf(format_args!("Invalid data: {}\n", args[3]));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    } else {
        Vec::new()
    };

    // Spawn async task to send the data packet.
    tokio::spawn(async move {
        let ret = transport.send_data(ptype, handle, &data).await.is_ok();
        bt_shell_noninteractive_quit(if ret { EXIT_SUCCESS } else { EXIT_FAILURE });
    });
}

// ---------------------------------------------------------------------------
// Shell command: register  (replaces C hci_register + hci_evt_received,
//                           lines 193-249)
// ---------------------------------------------------------------------------

/// Register an HCI event handler.
///
/// Usage: `register <event>`
///
/// When the specified event code fires, its payload is printed as a hex dump.
fn hci_register(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_printf(format_args!("Missing event code\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    // Parse event code (0..255).
    let event = match parse_strtol(args[1]) {
        Some(v) if v >= 0 && v <= i64::from(u8::MAX) => v as u8,
        _ => {
            bt_shell_printf(format_args!("Invalid event: {}\n", args[1]));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Validate state and check for duplicates.
    let transport = {
        let state = STATE.lock().unwrap();
        if state.hci.is_none() {
            bt_shell_printf(format_args!("HCI channel not open\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
        if state.events.iter().any(|e| e.event == event) {
            bt_shell_printf(format_args!("Event already registered\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
        Arc::clone(state.hci.as_ref().unwrap())
    };

    // Spawn async task to subscribe and then receive events.
    tokio::spawn(async move {
        let (id, mut rx): (u32, tokio::sync::mpsc::Receiver<HciEvent>) =
            transport.subscribe(event).await;

        if id == 0 {
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }

        // Store the registration in module state.
        {
            let mut state = STATE.lock().unwrap();
            state.events.push(HciEventEntry { event, id });
        }

        bt_shell_printf(format_args!("HCI Event 0x{event:02x} registered\n"));
        bt_shell_noninteractive_quit(EXIT_SUCCESS);

        // Event receiver loop — runs until the sender is dropped
        // (replaces C hci_evt_received callback, lines 201-207).
        while let Some(evt) = rx.recv().await {
            bt_shell_printf(format_args!("HCI Event 0x{:02x} received:\n", evt.event));
            bt_shell_hexdump(&evt.data);
        }
    });
}

// ---------------------------------------------------------------------------
// Shell command: unregister  (replaces C hci_unregister, lines 251-281)
// ---------------------------------------------------------------------------

/// Unregister a previously registered HCI event handler.
///
/// Usage: `unregister <event>`
fn hci_unregister(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_printf(format_args!("Missing event code\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
        return;
    }

    // Parse event code (0..255).
    let event = match parse_strtol(args[1]) {
        Some(v) if v >= 0 && v <= i64::from(u8::MAX) => v as u8,
        _ => {
            bt_shell_printf(format_args!("Invalid event: {}\n", args[1]));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    // Find the matching event entry and extract the transport + ID.
    let (transport, evt_id) = {
        let state = STATE.lock().unwrap();
        if state.hci.is_none() {
            bt_shell_printf(format_args!("HCI channel not open\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
        match state.events.iter().find(|e| e.event == event) {
            Some(entry) => (Arc::clone(state.hci.as_ref().unwrap()), entry.id),
            None => {
                bt_shell_printf(format_args!("Event not registered\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }
        }
    };

    // Spawn async task to unsubscribe from the transport.
    tokio::spawn(async move {
        transport.unsubscribe(evt_id).await;

        // Remove the entry from module state.
        {
            let mut state = STATE.lock().unwrap();
            state.events.retain(|e| e.event != event);
        }

        bt_shell_printf(format_args!("HCI Event 0x{event:02x} unregistered\n"));
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
    });
}

// ---------------------------------------------------------------------------
// Menu definition  (replaces C hci_menu, lines 298-314)
// ---------------------------------------------------------------------------

/// HCI submenu definition.
///
/// Command table matches the C `hci_menu.entries` exactly:
/// open, cmd, send, register, unregister, close.
static HCI_MENU: BtShellMenu = BtShellMenu {
    name: "hci",
    desc: Some("HCI Submenu"),
    pre_run: None,
    entries: &[
        BtShellMenuEntry {
            cmd: "open",
            arg: Some("<index> <chan=raw,user>"),
            func: hci_open,
            desc: "Open HCI channel",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "cmd",
            arg: Some("<opcode> [parameters...]"),
            func: hci_cmd,
            desc: "Send HCI command",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "send",
            arg: Some("<type=acl,sco,iso> <handle> [data...]"),
            func: hci_send,
            desc: "Send HCI data",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "register",
            arg: Some("<event>"),
            func: hci_register,
            desc: "Register HCI event handler",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "unregister",
            arg: Some("<event>"),
            func: hci_unregister,
            desc: "Unregister HCI event handler",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "close",
            arg: None,
            func: hci_close,
            desc: "Close HCI channel",
            r#gen: None,
            disp: None,
            exists: None,
        },
    ],
};

// ---------------------------------------------------------------------------
// Public API  (replaces C hci_add_submenu/hci_remove_submenu, lines 316-333)
// ---------------------------------------------------------------------------

/// Register the HCI submenu with the shell framework.
///
/// Called during `bluetoothctl` initialization.
pub fn hci_add_submenu() {
    bt_shell_add_submenu(&HCI_MENU);
}

/// Unregister the HCI submenu, closing any open channel and cleaning up
/// all registered event handlers.
///
/// Called during `bluetoothctl` shutdown.
pub fn hci_remove_submenu() {
    bt_shell_remove_submenu(&HCI_MENU);

    let mut state = STATE.lock().unwrap();

    if state.hci.is_none() {
        return;
    }

    // Clear all registered event entries (replaces queue_destroy(events, free)).
    state.events.clear();

    // Drop the transport (replaces bt_hci_unref(hci); hci = NULL).
    if let Some(transport) = state.hci.take() {
        transport.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_strtol tests --

    #[test]
    fn parse_decimal() {
        assert_eq!(parse_strtol("0"), Some(0));
        assert_eq!(parse_strtol("123"), Some(123));
        assert_eq!(parse_strtol("65535"), Some(65535));
    }

    #[test]
    fn parse_hex() {
        assert_eq!(parse_strtol("0x0"), Some(0));
        assert_eq!(parse_strtol("0x1A"), Some(26));
        assert_eq!(parse_strtol("0XFF"), Some(255));
        assert_eq!(parse_strtol("0xFFFF"), Some(65535));
    }

    #[test]
    fn parse_octal() {
        assert_eq!(parse_strtol("010"), Some(8));
        assert_eq!(parse_strtol("0777"), Some(511));
        assert_eq!(parse_strtol("00"), Some(0));
    }

    #[test]
    fn parse_negative() {
        assert_eq!(parse_strtol("-1"), Some(-1));
        assert_eq!(parse_strtol("-0xff"), Some(-255));
        assert_eq!(parse_strtol("-010"), Some(-8));
    }

    #[test]
    fn parse_invalid() {
        assert_eq!(parse_strtol(""), None);
        assert_eq!(parse_strtol("-"), None);
        assert_eq!(parse_strtol("0x"), None);
        assert_eq!(parse_strtol("abc"), None);
        // 08 is invalid: leading 0 triggers octal, but 8 is invalid in octal.
        assert_eq!(parse_strtol("08"), None);
    }

    // -- str2bytearray tests --

    #[test]
    fn bytearray_basic() {
        let result = str2bytearray("0x01 0x02 0x03");
        assert_eq!(result, Some(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn bytearray_decimal() {
        let result = str2bytearray("1 2 255");
        assert_eq!(result, Some(vec![1, 2, 255]));
    }

    #[test]
    fn bytearray_mixed() {
        let result = str2bytearray("0x0a 10 012");
        assert_eq!(result, Some(vec![10, 10, 10]));
    }

    #[test]
    fn bytearray_empty() {
        let result = str2bytearray("");
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn bytearray_single() {
        let result = str2bytearray("0xff");
        assert_eq!(result, Some(vec![255]));
    }

    #[test]
    fn bytearray_overflow_value() {
        // 256 > 255, should fail.
        let result = str2bytearray("256");
        assert_eq!(result, None);
    }

    #[test]
    fn bytearray_negative_wraps() {
        // Negative values wrap to u8, matching C unsigned truncation.
        let result = str2bytearray("-1");
        assert_eq!(result, Some(vec![255]));
    }

    // -- Menu structure tests --

    #[test]
    fn menu_has_correct_name() {
        assert_eq!(HCI_MENU.name, "hci");
        assert_eq!(HCI_MENU.desc, Some("HCI Submenu"));
    }

    #[test]
    fn menu_has_six_commands() {
        assert_eq!(HCI_MENU.entries.len(), 6);
    }

    #[test]
    fn menu_command_names() {
        let names: Vec<&str> = HCI_MENU.entries.iter().map(|e| e.cmd).collect();
        assert_eq!(names, vec!["open", "cmd", "send", "register", "unregister", "close"]);
    }

    #[test]
    fn menu_close_has_no_args() {
        let close = HCI_MENU.entries.iter().find(|e| e.cmd == "close").unwrap();
        assert!(close.arg.is_none());
    }

    #[test]
    fn menu_open_has_args() {
        let open = HCI_MENU.entries.iter().find(|e| e.cmd == "open").unwrap();
        assert_eq!(open.arg, Some("<index> <chan=raw,user>"));
    }

    // -- State initialization tests --

    #[test]
    fn initial_state_hci_is_none() {
        let state = STATE.lock().unwrap();
        assert!(state.hci.is_none());
    }

    // -- HciEventEntry tests --

    #[test]
    fn event_entry_fields() {
        let entry = HciEventEntry { event: 0x0E, id: 42 };
        assert_eq!(entry.event, 0x0E);
        assert_eq!(entry.id, 42);
    }

    // -- cmd_opcode_pack integration --

    #[test]
    fn opcode_pack_round_trip() {
        let ogf: u16 = 0x04;
        let ocf: u16 = 0x001;
        let opcode = cmd_opcode_pack(ogf, ocf);
        assert_eq!(opcode, 0x1001);
        assert_eq!(opcode >> 10, ogf);
        assert_eq!(opcode & 0x03FF, ocf);
    }
}
