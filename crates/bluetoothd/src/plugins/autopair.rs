// SPDX-License-Identifier: GPL-2.0-or-later
//
// autopair — Automatic PIN code pairing plugin.
//
// Replaces plugins/autopair.c (~301 LOC).  Handles legacy Bluetooth pairing
// by providing well-known PIN codes for specific device classes and known
// devices (e.g. Nintendo Wii Remotes).

use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};

// ---------------------------------------------------------------------------
// Known device databases
// ---------------------------------------------------------------------------

/// Vendor/Product ID pairs for Nintendo Wii Remote variants.
pub const WII_IDS: &[[u16; 2]] = &[
    [0x057e, 0x0306], // 1st gen
    [0x054c, 0x0306], // LEGO wiimote
    [0x057e, 0x0330], // 2nd gen
];

/// Known Wii Remote device name prefixes.
pub const WII_NAMES: &[&str] = &[
    "Nintendo RVL-CNT-01",
    "Nintendo RVL-CNT-01-TR",
    "Nintendo RVL-CNT-01-UC",
    "Nintendo RVL-WBC-01",
];

/// Standard PIN codes attempted during auto-pairing, in order of preference.
pub const DEFAULT_PINS: &[&str] = &[
    "0000", // Most common default
    "1234", // Second most common
    "1111", // Some headsets
    "9999", // Rare
];

// ---------------------------------------------------------------------------
// Device class helpers (from Bluetooth Baseband Assigned Numbers)
// ---------------------------------------------------------------------------

/// Major device class: Audio/Video (0x04).
const MAJOR_CLASS_AV: u32 = 0x04;

/// Major device class: Peripheral (0x05) — keyboards, mice, etc.
const MAJOR_CLASS_PERIPHERAL: u32 = 0x05;

/// Extract the major device class from a Bluetooth CoD value.
pub fn major_class(cod: u32) -> u32 {
    (cod >> 8) & 0x1f
}

/// Extract the minor device class from a Bluetooth CoD value.
pub fn minor_class(cod: u32) -> u32 {
    (cod >> 2) & 0x3f
}

/// Determine the automatic PIN to try for a device based on its class,
/// vendor/product IDs, and name.
///
/// Returns `Some(pin_bytes)` if a PIN should be attempted, or `None` if
/// no automatic PIN is appropriate.
pub fn suggest_pin(
    cod: u32,
    vendor: u16,
    product: u16,
    name: &str,
    attempt: u32,
) -> Option<PinSuggestion> {
    // Only try once per strategy.
    if attempt > 4 {
        return None;
    }

    // Check for Wii Remote first.
    if is_wii_remote(vendor, product, name) {
        // Wii Remotes use the host BD_ADDR as the PIN.
        return Some(PinSuggestion::HostAddress);
    }

    // Skip iCade devices — they should not get random PINs.
    if name.contains("iCade") {
        return None;
    }

    // Ignore devices with unknown class.
    if cod == 0 {
        return None;
    }

    match major_class(cod) {
        MAJOR_CLASS_AV => {
            // Audio/Video devices typically use "0000".
            match attempt {
                1 => Some(PinSuggestion::Fixed("0000")),
                2 => Some(PinSuggestion::Fixed("1234")),
                _ => None,
            }
        }
        MAJOR_CLASS_PERIPHERAL => {
            let minor = minor_class(cod);
            if minor & 0x10 != 0 {
                // Keyboard — generate random 6-digit numeric PIN and
                // instruct the agent to display it.
                Some(PinSuggestion::RandomNumeric)
            } else {
                // Other peripherals (mice, gamepads).
                match attempt {
                    1 => Some(PinSuggestion::Fixed("0000")),
                    2 => Some(PinSuggestion::Fixed("1234")),
                    _ => None,
                }
            }
        }
        _ => None,
    }
}

/// Check whether a device is a Nintendo Wii Remote.
fn is_wii_remote(vendor: u16, product: u16, name: &str) -> bool {
    for &[v, p] in WII_IDS {
        if vendor == v && product == p {
            return true;
        }
    }
    for &n in WII_NAMES {
        if name == n {
            return true;
        }
    }
    false
}

/// The kind of PIN suggestion returned by [`suggest_pin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSuggestion {
    /// Use a fixed, well-known PIN string.
    Fixed(&'static str),
    /// Use the host adapter's BD_ADDR as a 6-byte PIN (Wii Remote protocol).
    HostAddress,
    /// Generate a random 6-digit numeric PIN and display it to the user.
    RandomNumeric,
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct AutopairPlugin;

impl BluetoothPlugin for AutopairPlugin {
    fn desc(&self) -> PluginDesc {
        PluginDesc {
            name: "autopair",
            version: env!("CARGO_PKG_VERSION"),
            priority: PluginPriority::Default,
        }
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: register pin-callback with the adapter subsystem
        Ok(())
    }

    fn exit(&self) {
        // TODO: unregister pin-callback
    }
}

inventory::submit! { &AutopairPlugin as &dyn BluetoothPlugin }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wii_remote_detection() {
        assert!(is_wii_remote(0x057e, 0x0306, ""));
        assert!(is_wii_remote(0x0000, 0x0000, "Nintendo RVL-CNT-01"));
        assert!(!is_wii_remote(0x0000, 0x0000, "Some Other Device"));
    }

    #[test]
    fn test_suggest_pin_audio_device() {
        // Audio/Video device, minor class "wearable headset"
        let cod: u32 = (MAJOR_CLASS_AV << 8) | (0x01 << 2);
        let pin = suggest_pin(cod, 0, 0, "BT Headset", 1);
        assert_eq!(pin, Some(PinSuggestion::Fixed("0000")));
    }

    #[test]
    fn test_suggest_pin_keyboard() {
        // Peripheral keyboard: major 0x05, minor bit 4 set (0x10 = keyboard)
        let cod: u32 = (MAJOR_CLASS_PERIPHERAL << 8) | (0x10 << 2);
        let pin = suggest_pin(cod, 0, 0, "BT Keyboard", 1);
        assert_eq!(pin, Some(PinSuggestion::RandomNumeric));
    }

    #[test]
    fn test_suggest_pin_unknown_class() {
        assert_eq!(suggest_pin(0, 0, 0, "Unknown", 1), None);
    }
}
