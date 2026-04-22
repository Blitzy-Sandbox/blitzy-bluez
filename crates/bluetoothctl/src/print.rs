// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2012 Intel Corporation. All rights reserved.
//
// D-Bus property/value formatting and printing utilities for bluetoothctl.
//
// Complete Rust rewrite of `client/print.c` (238 lines) and `client/print.h`.
// Provides `print_property`, `print_property_with_label`, `print_iter`, and
// `print_uuid` functions that format D-Bus message values for human-readable
// terminal display.
//
// Transformation:
//   - DBusMessageIter → zbus::zvariant::Value recursive traversal
//   - GDBusProxy      → zbus::proxy::Proxy async property access
//   - g_strdup_printf → format!()
//   - g_strconcat     → format!("{}.{}", ...)
//   - g_free          → automatic Drop
//   - bt_uuidstr_to_str from bluez-shared::util::uuid
//   - bt_shell_printf / bt_shell_hexdump from bluez-shared::shell

use bluez_shared::shell::{bt_shell_hexdump, bt_shell_printf};
use bluez_shared::util::uuid::bt_uuidstr_to_str;
use zbus::zvariant::{OwnedValue, Value};

// ---------------------------------------------------------------------------
// print_uuid — UUID display with human-readable name resolution
// ---------------------------------------------------------------------------

/// Print a formatted UUID with human-readable SIG name resolution.
///
/// Replaces C `print_uuid` from `client/print.c` lines 213-238.
///
/// Resolution logic:
/// 1. Call `bt_uuidstr_to_str(uuid)` to get the human-readable UUID name.
/// 2. If a name is found, truncate it to a maximum of 25 characters, appending
///    `".."` (or `"..."` when position 22 is a space) for overflow, and pad
///    to align the `"(uuid)"` portion to column 26 from the name field start.
/// 3. If no name is found, output 26 spaces of padding before `"(uuid)"`.
///
/// # Output format (with name)
///
/// ```text
/// {label}{name}: {text}{padding}({uuid})
/// ```
///
/// where `text + padding` always occupies exactly 26 characters.
///
/// # Output format (without name)
///
/// ```text
/// {label}{name}: {26 spaces}({uuid})
/// ```
pub fn print_uuid(label: &str, name: &str, uuid: &str) {
    if let Some(text) = bt_uuidstr_to_str(uuid) {
        // Build a display buffer of at most 25 usable characters,
        // matching the C `char str[26]` (25 chars + NUL terminator).
        let text_bytes = text.as_bytes();
        let max_display = 25;

        let mut buf = [0u8; 25];
        let copy_len = text_bytes.len().min(max_display);
        buf[..copy_len].copy_from_slice(&text_bytes[..copy_len]);

        let n;
        if text_bytes.len() > max_display {
            // Overflow: truncate with ".." suffix.
            // C: str[sizeof(str) - 2] = '.'; str[sizeof(str) - 3] = '.';
            buf[24] = b'.';
            buf[23] = b'.';
            // C: if (str[sizeof(str) - 4] == ' ') str[sizeof(str) - 4] = '.';
            if buf[22] == b' ' {
                buf[22] = b'.';
            }
            n = max_display;
        } else {
            n = text_bytes.len();
        }

        // Convert the used portion to a string slice for display.
        let display = core::str::from_utf8(&buf[..n]).unwrap_or(text);

        // Pad so that text + padding occupies exactly 26 characters.
        // C: bt_shell_printf("%s%s: %s%*c(%s)\n", label, name, str, 26 - n, ' ', uuid);
        // %*c with width W and char ' ' produces W characters (W-1 spaces + ' ').
        let padding = 26_usize.saturating_sub(n);
        bt_shell_printf(format_args!(
            "{}{}: {}{:padding$}({})\n",
            label,
            name,
            display,
            " ",
            uuid,
            padding = padding,
        ));
    } else {
        // No name found: 26 spaces of padding before "(uuid)".
        // C: bt_shell_printf("%s%s: %*c(%s)\n", label, name, 26, ' ', uuid);
        bt_shell_printf(format_args!("{}{}: {:>26}({})\n", label, name, " ", uuid,));
    }
}

// ---------------------------------------------------------------------------
// print_fixed_iter — hex dump of fixed-type D-Bus arrays
// ---------------------------------------------------------------------------

/// Print a hex dump of a fixed-type D-Bus array.
///
/// Replaces C `print_fixed_iter` from `client/print.c` lines 32-96.
///
/// Handles arrays of fixed-size D-Bus types (BOOLEAN/UINT32 as 4-byte native,
/// UINT16/INT16 as 2-byte native, BYTE as 1-byte) by extracting element values,
/// converting them to their native-endian byte representations, and delegating
/// to `bt_shell_hexdump` for formatted output.
///
/// Empty arrays produce no output (matching the C `len <= 0` early return).
fn print_fixed_iter(label: &str, name: &str, array: &zbus::zvariant::Array<'_>) {
    if array.is_empty() {
        return;
    }

    let sig = array.element_signature();
    let bytes: Vec<u8> = match sig {
        // C: DBUS_TYPE_BOOLEAN / DBUS_TYPE_UINT32 — 4 bytes per element
        // dbus_bool_t is uint32_t, so booleans are stored as 4-byte integers.
        zbus::zvariant::Signature::Bool | zbus::zvariant::Signature::U32 => array
            .inner()
            .iter()
            .flat_map(|v| match v {
                Value::Bool(b) => (*b as u32).to_ne_bytes(),
                Value::U32(n) => n.to_ne_bytes(),
                _ => 0u32.to_ne_bytes(),
            })
            .collect(),

        // C: DBUS_TYPE_UINT16 / DBUS_TYPE_INT16 — 2 bytes per element
        zbus::zvariant::Signature::U16 | zbus::zvariant::Signature::I16 => array
            .inner()
            .iter()
            .flat_map(|v| match v {
                Value::U16(n) => n.to_ne_bytes(),
                Value::I16(n) => n.to_ne_bytes(),
                _ => 0u16.to_ne_bytes(),
            })
            .collect(),

        // C: DBUS_TYPE_BYTE — 1 byte per element
        zbus::zvariant::Signature::U8 => array
            .inner()
            .iter()
            .filter_map(|v| match v {
                Value::U8(b) => Some(*b),
                _ => None,
            })
            .collect(),

        // All other types: no output (matching C default case).
        _ => return,
    };

    if bytes.is_empty() {
        return;
    }

    // C: bt_shell_printf("%s%s:\n", label, name); bt_shell_hexdump(vals, ...);
    bt_shell_printf(format_args!("{}{}:\n", label, name));
    bt_shell_hexdump(&bytes);
}

// ---------------------------------------------------------------------------
// print_iter — recursive D-Bus value formatter
// ---------------------------------------------------------------------------

/// Print a formatted representation of a D-Bus value, recursively traversing
/// container types (Variant, Array, Dict).
///
/// Replaces C `print_iter` from `client/print.c` lines 98-195.
///
/// This is the core recursive formatter that handles all D-Bus types used in
/// BlueZ property values:
///
/// | D-Bus Type   | Format                           |
/// |-------------|----------------------------------|
/// | String      | `{label}{name}: {value}\n` (UUID special-case) |
/// | ObjectPath  | `{label}{name}: {value}\n`       |
/// | Boolean     | `{label}{name}: yes\n` / `no\n`  |
/// | UInt32      | `{label}{name}: 0x{:08x} ({})\n` |
/// | UInt16      | `{label}{name}: 0x{:04x} ({})\n` |
/// | Int16       | `{label}{name}: 0x{:04x} ({})\n` |
/// | Byte        | `{label}{name}: 0x{:02x} ({})\n` |
/// | Variant     | Recurse into inner value         |
/// | Array       | Fixed → hexdump; others → recurse |
/// | Dict        | String key → `name.key`; else Key/Value |
///
/// # UUID special case
///
/// When `name` case-insensitively equals `"UUID"` and the value is a string,
/// `print_uuid` is called instead of the default string formatter.
pub fn print_iter(label: &str, name: &str, value: &Value<'_>) {
    match value {
        // ----------------------------------------------------------------
        // String type (C lines 118-123)
        // UUID special case: if name case-insensitively equals "UUID",
        // delegate to print_uuid for formatted UUID display.
        // Otherwise fall through to the ObjectPath-style display.
        // ----------------------------------------------------------------
        Value::Str(s) => {
            let s_str = s.as_str();
            if name.eq_ignore_ascii_case("UUID") {
                print_uuid(label, name, s_str);
            } else {
                // C: bt_shell_printf("%s%s: %s\n", label, name, valstr);
                bt_shell_printf(format_args!("{}{}: {}\n", label, name, s_str));
            }
        }

        // ----------------------------------------------------------------
        // ObjectPath type (C lines 125-128)
        // C: bt_shell_printf("%s%s: %s\n", label, name, valstr);
        // ----------------------------------------------------------------
        Value::ObjectPath(p) => {
            bt_shell_printf(format_args!("{}{}: {}\n", label, name, p.as_str()));
        }

        // ----------------------------------------------------------------
        // Boolean type (C lines 129-133)
        // C: bt_shell_printf("%s%s: %s\n", label, name, valbool ? "yes" : "no");
        // ----------------------------------------------------------------
        Value::Bool(b) => {
            let yesno = if *b { "yes" } else { "no" };
            bt_shell_printf(format_args!("{}{}: {}\n", label, name, yesno));
        }

        // ----------------------------------------------------------------
        // UInt32 type (C lines 134-138)
        // C: bt_shell_printf("%s%s: 0x%08x (%d)\n", label, name, valu32, valu32);
        // ----------------------------------------------------------------
        Value::U32(v) => {
            bt_shell_printf(format_args!("{}{}: 0x{:08x} ({})\n", label, name, v, v,));
        }

        // ----------------------------------------------------------------
        // UInt16 type (C lines 139-143)
        // C: bt_shell_printf("%s%s: 0x%04x (%d)\n", label, name, valu16, valu16);
        // ----------------------------------------------------------------
        Value::U16(v) => {
            bt_shell_printf(format_args!("{}{}: 0x{:04x} ({})\n", label, name, v, v,));
        }

        // ----------------------------------------------------------------
        // Int16 type (C lines 144-148)
        // C: bt_shell_printf("%s%s: 0x%04x (%d)\n", label, name, vals16, vals16);
        // Note: C uses %04x which prints the unsigned hex representation,
        // and %d for the signed decimal value.
        // ----------------------------------------------------------------
        Value::I16(v) => {
            bt_shell_printf(format_args!("{}{}: 0x{:04x} ({})\n", label, name, *v as u16, v,));
        }

        // ----------------------------------------------------------------
        // Byte type (C lines 149-152)
        // C: bt_shell_printf("%s%s: 0x%02x (%d)\n", label, name, byte, byte);
        // ----------------------------------------------------------------
        Value::U8(v) => {
            bt_shell_printf(format_args!("{}{}: 0x{:02x} ({})\n", label, name, v, v,));
        }

        // ----------------------------------------------------------------
        // Variant type (C lines 153-156)
        // Recurse into the inner value.
        // ----------------------------------------------------------------
        Value::Value(inner) => {
            print_iter(label, name, inner);
        }

        // ----------------------------------------------------------------
        // Array type (C lines 157-171)
        // If the element type is a fixed type (bool, u32, u16, i16, byte),
        // delegate to print_fixed_iter for hex dump display.
        // Otherwise, iterate elements and recurse.
        // ----------------------------------------------------------------
        Value::Array(array) => {
            let sig = array.element_signature();
            let is_fixed = matches!(
                sig,
                zbus::zvariant::Signature::Bool
                    | zbus::zvariant::Signature::U32
                    | zbus::zvariant::Signature::U16
                    | zbus::zvariant::Signature::I16
                    | zbus::zvariant::Signature::U8
            );

            if is_fixed {
                print_fixed_iter(label, name, array);
            } else {
                // C: iterate sub-elements, recurse for each
                for elem in array.inner() {
                    print_iter(label, name, elem);
                }
            }
        }

        // ----------------------------------------------------------------
        // Dict type (C lines 172-190)
        // If the key is a string, use it to build a dotted label
        // (e.g., "name.key_value"). Otherwise print as generic
        // Key/Value pairs.
        // ----------------------------------------------------------------
        Value::Dict(dict) => {
            for (key, val) in dict.iter() {
                if let Value::Str(key_str) = key {
                    // C: entry = g_strconcat(name, ".", valstr, NULL);
                    //    print_iter(label, entry, &value);
                    let entry = format!("{}.{}", name, key_str.as_str());
                    print_iter(label, &entry, val);
                } else {
                    // C: print_iter(label, name ".Key", &key);
                    //    print_iter(label, name ".Value", &value);
                    let key_label = format!("{}.Key", name);
                    let val_label = format!("{}.Value", name);
                    print_iter(label, &key_label, key);
                    print_iter(label, &val_label, val);
                }
            }
        }

        // ----------------------------------------------------------------
        // Default / unsupported types (C lines 191-193)
        // C: bt_shell_printf("%s%s has unsupported type\n", label, name);
        // ----------------------------------------------------------------
        _ => {
            bt_shell_printf(format_args!("{}{} has unsupported type\n", label, name));
        }
    }
}

// ---------------------------------------------------------------------------
// print_property_with_label — D-Bus property printer with custom label
// ---------------------------------------------------------------------------

/// Retrieve a D-Bus property from a proxy and print it with a custom label.
///
/// Replaces C `print_property_with_label` from `client/print.c` lines 197-206.
///
/// The property value is fetched via `proxy.get_property::<OwnedValue>(name)`.
/// If the property is not available (e.g., not cached or not present on the
/// remote object), the function returns silently, matching the C behavior
/// where `g_dbus_proxy_get_property` returning `FALSE` causes an early return.
///
/// The label defaults to `name` when `None` is provided.
///
/// # Arguments
///
/// * `proxy` — A `zbus::proxy::Proxy` connected to the remote D-Bus object.
/// * `name`  — The D-Bus property name to retrieve.
/// * `label` — Optional display label. When `None`, `name` is used.
pub async fn print_property_with_label(
    proxy: &zbus::proxy::Proxy<'_>,
    name: &str,
    label: Option<&str>,
) {
    // C: if (g_dbus_proxy_get_property(proxy, name, &iter) == FALSE) return;
    let value: OwnedValue = match proxy.get_property(name).await {
        Ok(v) => v,
        Err(_) => return,
    };

    // C: print_iter("\t", label ? label : name, &iter);
    let display_label = label.unwrap_or(name);
    print_iter("\t", display_label, &value);
}

// ---------------------------------------------------------------------------
// print_property — D-Bus property printer
// ---------------------------------------------------------------------------

/// Retrieve and print a D-Bus property using the property name as the label.
///
/// Replaces C `print_property` from `client/print.c` lines 208-211.
///
/// This is a convenience wrapper that calls `print_property_with_label` with
/// `label = None`, causing the property name itself to be used as the display
/// label.
///
/// # Arguments
///
/// * `proxy` — A `zbus::proxy::Proxy` connected to the remote D-Bus object.
/// * `name`  — The D-Bus property name to retrieve and display.
pub async fn print_property(proxy: &zbus::proxy::Proxy<'_>, name: &str) {
    print_property_with_label(proxy, name, None).await;
}
