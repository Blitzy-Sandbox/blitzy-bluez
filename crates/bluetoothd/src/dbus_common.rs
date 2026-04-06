// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2006-2010  Nokia Corporation
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
//
// D-Bus utility helpers — shared connection cache, dictionary append convenience
// wrappers, and icon mapping functions for Bluetooth device class and GAP appearance
// values. Rewritten from src/dbus-common.c and src/dbus-common.h.

use std::collections::HashMap;
use std::sync::OnceLock;

use zbus::Connection;
use zbus::zvariant::{OwnedValue, Value};

// ---------------------------------------------------------------------------
// Shared D-Bus connection cache
// ---------------------------------------------------------------------------

/// Global thread-safe cache for the shared system D-Bus connection.
///
/// Initialised once during daemon startup via [`set_dbus_connection`] and
/// accessed throughout the daemon lifetime via [`btd_get_dbus_connection`].
/// Uses [`OnceLock`] for lock-free reads after initialisation.
static DBUS_CONNECTION: OnceLock<Connection> = OnceLock::new();

/// Cache the shared D-Bus connection for the daemon.
///
/// This must be called exactly once during daemon initialisation, after the
/// system bus connection has been established.  Subsequent calls are silently
/// ignored (the first connection wins), matching the C behaviour where the
/// static global `DBusConnection *connection` is only assigned once.
pub fn set_dbus_connection(conn: Connection) {
    // OnceLock::set returns Err(value) if already initialised — we
    // intentionally drop the error to match C's single-assignment semantics.
    let _ = DBUS_CONNECTION.set(conn);
}

/// Retrieve the shared D-Bus connection.
///
/// Returns a static reference to the cached [`Connection`].  The connection
/// is internally `Arc`-backed, so cloning the returned reference is cheap if
/// the caller needs ownership.
///
/// # Panics
///
/// Panics if called before [`set_dbus_connection`].  This mirrors the C
/// behaviour where dereferencing the uninitialised `DBusConnection *` pointer
/// would crash.
pub fn btd_get_dbus_connection() -> &'static Connection {
    DBUS_CONNECTION.get().expect("btd_get_dbus_connection called before set_dbus_connection")
}

/// Try to retrieve the shared D-Bus connection without panicking.
///
/// Returns `None` if [`set_dbus_connection`] has not yet been called.
/// Useful in contexts where the D-Bus connection may not be initialised
/// (e.g. unit tests or early daemon startup).
pub fn try_get_dbus_connection() -> Option<&'static Connection> {
    DBUS_CONNECTION.get()
}

// ---------------------------------------------------------------------------
// D-Bus dictionary append helpers
// ---------------------------------------------------------------------------

/// Append a key–value entry to a D-Bus variant dictionary.
///
/// This is a convenience wrapper matching the C `dict_append_entry` semantics.
/// In the C codebase this delegates to `g_dbus_dict_append_entry`; in Rust the
/// dictionary is a plain `HashMap<String, OwnedValue>` which gets serialised
/// to D-Bus `a{sv}` by zbus automatically.
///
/// The [`Value`] parameter accepts any zvariant `Value` (strings, integers,
/// booleans, byte arrays, etc.).  It is converted to an [`OwnedValue`] for
/// storage in the dictionary.
///
/// # Examples
///
/// ```ignore
/// use std::collections::HashMap;
/// use zbus::zvariant::{OwnedValue, Value};
///
/// let mut dict = HashMap::new();
/// dict_append_entry(&mut dict, "Powered", Value::from(true));
/// dict_append_entry(&mut dict, "Alias", Value::from("My Device"));
/// ```
pub fn dict_append_entry(dict: &mut HashMap<String, OwnedValue>, key: &str, value: Value<'_>) {
    let owned = OwnedValue::try_from(value)
        .expect("dict_append_entry: failed to convert Value to OwnedValue");
    dict.insert(key.to_owned(), owned);
}

/// Append a key–array entry to a D-Bus variant dictionary.
///
/// Equivalent to C `dict_append_array`.  The caller constructs the array
/// value (e.g. `Value::Array(...)`) and this helper inserts it into the
/// dictionary under the given key, converting to [`OwnedValue`] for storage.
///
/// # Examples
///
/// ```ignore
/// use std::collections::HashMap;
/// use zbus::zvariant::{OwnedValue, Value, Array};
///
/// let mut dict = HashMap::new();
/// let uuids: Vec<Value<'_>> = vec![
///     Value::from("0000110a-0000-1000-8000-00805f9b34fb"),
///     Value::from("0000110b-0000-1000-8000-00805f9b34fb"),
/// ];
/// dict_append_array(&mut dict, "UUIDs", Value::Array(uuids.into()));
/// ```
pub fn dict_append_array(dict: &mut HashMap<String, OwnedValue>, key: &str, value: Value<'_>) {
    let owned = OwnedValue::try_from(value)
        .expect("dict_append_array: failed to convert Value to OwnedValue");
    dict.insert(key.to_owned(), owned);
}

// ---------------------------------------------------------------------------
// Icon mapping — Class of Device
// ---------------------------------------------------------------------------

/// Map a Bluetooth Class of Device value to a freedesktop icon name.
///
/// The mapping is based on the major device class bits
/// `(class & 0x1f00) >> 8` with minor class refinement
/// `(class & 0xfc) >> 2` for Phone, Audio/Video, Peripheral, and Imaging
/// major classes.
///
/// Returns `None` when the class does not map to a known icon, matching the
/// C implementation which returns `NULL`.
pub fn class_to_icon(class: u32) -> Option<&'static str> {
    let major = (class & 0x1f00) >> 8;
    let minor = (class & 0xfc) >> 2;

    match major {
        // Computer
        0x01 => Some("computer"),

        // Phone — only specific minor classes yield an icon
        0x02 => match minor {
            0x01..=0x05 => Some("phone"),
            _ => None,
        },

        // Networking (LAN / Access Point)
        0x03 => Some("network-wireless"),

        // Audio / Video
        0x04 => match minor {
            // Wearable Headset Device
            0x01 => Some("audio-headset"),
            // Hands-free
            0x02 => Some("audio-headphones"),
            // Loudspeaker
            0x05 => Some("audio-speakers"),
            // Headphones
            0x06 => Some("audio-headphones"),
            _ => None,
        },

        // Peripheral (HID)
        0x05 => match minor {
            // Keyboard
            0x10 => Some("input-keyboard"),
            // Pointing device
            0x20 => Some("input-mouse"),
            // Combo keyboard/pointing or gamepad
            0x30 | 0x40 => Some("input-gaming"),
            _ => None,
        },

        // Imaging
        0x06 => {
            // Printer (bit 7 of minor field)
            if class & 0x80 != 0 {
                Some("printer")
            // Camera (bit 5 of minor field)
            } else if class & 0x20 != 0 {
                Some("camera-photo")
            } else {
                None
            }
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Icon mapping — GAP Appearance
// ---------------------------------------------------------------------------

/// Map a GAP Appearance value to a freedesktop icon name.
///
/// The mapping is based on the appearance category
/// `(appearance & 0xffc0) >> 6` with sub-category refinement
/// `appearance & 0x3f` for Clock and HID Generic categories.
///
/// Returns `None` when the appearance does not map to a known icon, matching
/// the C implementation which returns `NULL`.
pub fn gap_appearance_to_icon(appearance: u16) -> Option<&'static str> {
    let category = (appearance & 0xffc0) >> 6;
    let sub = appearance & 0x3f;

    match category {
        // Unknown
        0x00 => Some("unknown"),

        // Phone
        0x01 => Some("phone"),

        // Computer
        0x02 => Some("computer"),

        // Clock
        0x03 => match sub {
            // Watch
            0x01 => Some("watch"),
            // Clock
            0x02 => Some("clock"),
            _ => None,
        },

        // Display
        0x05 => Some("video-display"),

        // Media Player
        0x0a => Some("multimedia-player"),

        // Barcode Scanner
        0x0b => Some("scanner"),

        // HID Generic
        0x0f => match sub {
            // Keyboard
            0x01 => Some("input-keyboard"),
            // Mouse
            0x02 => Some("input-mouse"),
            // Joystick / Gamepad
            0x03 | 0x04 => Some("input-gaming"),
            // Digitizer Tablet
            0x05 => Some("input-tablet"),
            _ => None,
        },

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- class_to_icon -------------------------------------------------------

    #[test]
    fn class_computer() {
        // Major 0x01 — any minor value yields "computer"
        assert_eq!(class_to_icon(0x0100), Some("computer"));
        assert_eq!(class_to_icon(0x010C), Some("computer"));
    }

    #[test]
    fn class_phone_valid_minors() {
        // Major 0x02, minor 0x01..=0x05 → "phone"
        assert_eq!(class_to_icon(0x0204), Some("phone")); // minor 0x01
        assert_eq!(class_to_icon(0x0208), Some("phone")); // minor 0x02
        assert_eq!(class_to_icon(0x020C), Some("phone")); // minor 0x03
        assert_eq!(class_to_icon(0x0210), Some("phone")); // minor 0x04
        assert_eq!(class_to_icon(0x0214), Some("phone")); // minor 0x05
    }

    #[test]
    fn class_phone_invalid_minors() {
        // Major 0x02, minor outside 0x01..=0x05 → None
        assert_eq!(class_to_icon(0x0200), None); // minor 0x00
        assert_eq!(class_to_icon(0x0218), None); // minor 0x06
    }

    #[test]
    fn class_network() {
        assert_eq!(class_to_icon(0x0300), Some("network-wireless"));
    }

    #[test]
    fn class_audio_video() {
        assert_eq!(class_to_icon(0x0404), Some("audio-headset")); // minor 0x01
        assert_eq!(class_to_icon(0x0408), Some("audio-headphones")); // minor 0x02
        assert_eq!(class_to_icon(0x0414), Some("audio-speakers")); // minor 0x05
        assert_eq!(class_to_icon(0x0418), Some("audio-headphones")); // minor 0x06
        assert_eq!(class_to_icon(0x0400), None); // minor 0x00
        assert_eq!(class_to_icon(0x040C), None); // minor 0x03
    }

    #[test]
    fn class_peripheral() {
        // minor field = (class & 0xfc) >> 2
        assert_eq!(class_to_icon(0x0540), Some("input-keyboard")); // minor 0x10
        assert_eq!(class_to_icon(0x0580), Some("input-mouse")); // minor 0x20
        assert_eq!(class_to_icon(0x05C0), Some("input-gaming")); // minor 0x30
        assert_eq!(class_to_icon(0x0500), None); // minor 0x00
    }

    #[test]
    fn class_imaging() {
        assert_eq!(class_to_icon(0x0680), Some("printer")); // bit 7
        assert_eq!(class_to_icon(0x0620), Some("camera-photo")); // bit 5
        assert_eq!(class_to_icon(0x0600), None); // no bits
    }

    #[test]
    fn class_unmapped_major() {
        assert_eq!(class_to_icon(0x0000), None); // major 0x00
        assert_eq!(class_to_icon(0x0700), None); // major 0x07
        assert_eq!(class_to_icon(0x1F00), None); // major 0x1F
    }

    // -- gap_appearance_to_icon -----------------------------------------------

    #[test]
    fn appearance_unknown() {
        // Category 0x00 → "unknown"
        assert_eq!(gap_appearance_to_icon(0x0000), Some("unknown"));
    }

    #[test]
    fn appearance_phone() {
        // Category 0x01 → (0x01 << 6) = 0x0040
        assert_eq!(gap_appearance_to_icon(0x0040), Some("phone"));
    }

    #[test]
    fn appearance_computer() {
        // Category 0x02 → (0x02 << 6) = 0x0080
        assert_eq!(gap_appearance_to_icon(0x0080), Some("computer"));
    }

    #[test]
    fn appearance_clock_watch() {
        // Category 0x03 → (0x03 << 6) = 0x00C0
        assert_eq!(gap_appearance_to_icon(0x00C1), Some("watch")); // sub 0x01
        assert_eq!(gap_appearance_to_icon(0x00C2), Some("clock")); // sub 0x02
        assert_eq!(gap_appearance_to_icon(0x00C0), None); // sub 0x00
        assert_eq!(gap_appearance_to_icon(0x00C3), None); // sub 0x03
    }

    #[test]
    fn appearance_display() {
        // Category 0x05 → (0x05 << 6) = 0x0140
        assert_eq!(gap_appearance_to_icon(0x0140), Some("video-display"));
    }

    #[test]
    fn appearance_media_player() {
        // Category 0x0a → (0x0a << 6) = 0x0280
        assert_eq!(gap_appearance_to_icon(0x0280), Some("multimedia-player"));
    }

    #[test]
    fn appearance_scanner() {
        // Category 0x0b → (0x0b << 6) = 0x02C0
        assert_eq!(gap_appearance_to_icon(0x02C0), Some("scanner"));
    }

    #[test]
    fn appearance_hid_generic() {
        // Category 0x0f → (0x0f << 6) = 0x03C0
        assert_eq!(gap_appearance_to_icon(0x03C1), Some("input-keyboard")); // sub 0x01
        assert_eq!(gap_appearance_to_icon(0x03C2), Some("input-mouse")); // sub 0x02
        assert_eq!(gap_appearance_to_icon(0x03C3), Some("input-gaming")); // sub 0x03
        assert_eq!(gap_appearance_to_icon(0x03C4), Some("input-gaming")); // sub 0x04
        assert_eq!(gap_appearance_to_icon(0x03C5), Some("input-tablet")); // sub 0x05
        assert_eq!(gap_appearance_to_icon(0x03C0), None); // sub 0x00
        assert_eq!(gap_appearance_to_icon(0x03C6), None); // sub 0x06
    }

    #[test]
    fn appearance_unmapped_category() {
        // Category 0x04 is not mapped → None
        assert_eq!(gap_appearance_to_icon(0x0100), None);
        // Large unmapped value
        assert_eq!(gap_appearance_to_icon(0xFFC0), None);
    }

    // -- dict_append_entry / dict_append_array ---------------------------------

    #[test]
    fn dict_append_entry_bool() {
        let mut dict = HashMap::new();
        dict_append_entry(&mut dict, "Powered", Value::from(true));
        assert!(dict.contains_key("Powered"));
        let v: bool = dict["Powered"].clone().try_into().unwrap();
        assert!(v);
    }

    #[test]
    fn dict_append_entry_u32() {
        let mut dict = HashMap::new();
        dict_append_entry(&mut dict, "Class", Value::from(0x001F00u32));
        assert!(dict.contains_key("Class"));
        let v: u32 = dict["Class"].clone().try_into().unwrap();
        assert_eq!(v, 0x001F00);
    }

    #[test]
    fn dict_append_entry_string() {
        let mut dict = HashMap::new();
        dict_append_entry(&mut dict, "Alias", Value::from("TestAdapter".to_owned()));
        assert!(dict.contains_key("Alias"));
    }

    #[test]
    fn dict_append_entry_overwrites() {
        let mut dict = HashMap::new();
        dict_append_entry(&mut dict, "Key", Value::from(1u32));
        dict_append_entry(&mut dict, "Key", Value::from(2u32));
        assert_eq!(dict.len(), 1);
        let v: u32 = dict["Key"].clone().try_into().unwrap();
        assert_eq!(v, 2);
    }

    #[test]
    fn dict_append_array_strings() {
        let mut dict = HashMap::new();
        let arr = vec!["uuid1".to_owned(), "uuid2".to_owned()];
        dict_append_array(&mut dict, "UUIDs", Value::from(arr));
        assert!(dict.contains_key("UUIDs"));
    }

    // -- class_to_icon additional edge cases -----------------------------------

    #[test]
    fn class_imaging_both_bits_printer_wins() {
        // When both printer (bit 7) and camera (bit 5) are set, printer wins
        let class = 0x0600 | 0x80 | 0x20;
        assert_eq!(class_to_icon(class), Some("printer"));
    }
}
