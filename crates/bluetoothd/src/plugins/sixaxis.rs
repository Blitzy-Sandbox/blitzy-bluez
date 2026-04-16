// SPDX-License-Identifier: GPL-2.0-or-later
//
// sixaxis — PlayStation SixAxis / DualShock controller pairing plugin.
//
// Replaces plugins/sixaxis.c (~556 LOC).  Handles USB-based cable pairing
// for PlayStation controllers by writing the host Bluetooth address into the
// controller's HID report via hidraw.

use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};

// ---------------------------------------------------------------------------
// Controller identification
// ---------------------------------------------------------------------------

/// Types of PlayStation controllers supported for cable pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CablePairingType {
    /// Sony SixAxis / DualShock 3 (PS3).
    SixAxis,
    /// Sony DualShock 4 (PS4).
    DualShock4,
}

/// Known PlayStation controller USB vendor/product IDs.
///
/// Each entry is `(vendor_id, product_id, CablePairingType)`.
pub const KNOWN_CONTROLLERS: &[(u16, u16, CablePairingType)] = &[
    (0x054c, 0x0268, CablePairingType::SixAxis), // SixAxis / DualShock 3
    (0x054c, 0x042f, CablePairingType::SixAxis), // PS Move Navigation
    (0x054c, 0x03d5, CablePairingType::SixAxis), // PS Move Motion
    (0x054c, 0x05c4, CablePairingType::DualShock4), // DualShock 4 v1
    (0x054c, 0x09cc, CablePairingType::DualShock4), // DualShock 4 v2
];

/// HID report ID used to read the current master address on a SixAxis.
pub const SIXAXIS_GET_REPORT_ID: u8 = 0xf2;

/// HID report ID used to write the new master address on a SixAxis.
pub const SIXAXIS_SET_REPORT_ID: u8 = 0xf5;

/// HID feature report ID for DualShock 4 master address read.
pub const DS4_GET_REPORT_ID: u8 = 0x12;

/// HID feature report ID for DualShock 4 master address write.
pub const DS4_SET_REPORT_ID: u8 = 0x13;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up a controller type from USB vendor and product IDs.
pub fn identify_controller(vendor: u16, product: u16) -> Option<CablePairingType> {
    KNOWN_CONTROLLERS
        .iter()
        .find(|&&(v, p, _)| v == vendor && p == product)
        .map(|&(_, _, t)| t)
}

/// Build the HID feature report to set the master BD_ADDR on a SixAxis
/// controller.  `master_addr` must be 6 bytes (little-endian wire order).
///
/// Returns the full report buffer to be sent via `HIDIOCSFEATURE`.
pub fn build_sixaxis_set_master_report(master_addr: &[u8; 6]) -> [u8; 8] {
    let mut report = [0u8; 8];
    report[0] = SIXAXIS_SET_REPORT_ID;
    report[1] = 0x00; // padding
    report[2..8].copy_from_slice(master_addr);
    report
}

/// Build the HID feature report to set the master BD_ADDR on a DualShock 4.
/// `master_addr` must be 6 bytes (little-endian wire order).
pub fn build_ds4_set_master_report(master_addr: &[u8; 6]) -> [u8; 16] {
    let mut report = [0u8; 16];
    report[0] = DS4_SET_REPORT_ID;
    // The DS4 report places link key (zeros here) in bytes 1-8 and the
    // master address in bytes 10-15 (big-endian display order, reversed).
    for (i, &b) in master_addr.iter().rev().enumerate() {
        report[10 + i] = b;
    }
    report
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct SixaxisPlugin;

impl BluetoothPlugin for SixaxisPlugin {
    fn desc(&self) -> PluginDesc {
        PluginDesc {
            name: "sixaxis",
            version: env!("CARGO_PKG_VERSION"),
            priority: PluginPriority::Default,
        }
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: set up udev monitor for hidraw devices
        // TODO: on new device, check if it matches KNOWN_CONTROLLERS
        // TODO: request authentication and write master address

        Ok(())
    }

    fn exit(&self) {
        // TODO: tear down udev monitor and pending authentications
    }
}

inventory::submit! { &SixaxisPlugin as &dyn BluetoothPlugin }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_controller() {
        assert_eq!(
            identify_controller(0x054c, 0x0268),
            Some(CablePairingType::SixAxis)
        );
        assert_eq!(
            identify_controller(0x054c, 0x05c4),
            Some(CablePairingType::DualShock4)
        );
        assert_eq!(identify_controller(0x1234, 0x5678), None);
    }

    #[test]
    fn test_sixaxis_set_master_report() {
        let addr: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let report = build_sixaxis_set_master_report(&addr);
        assert_eq!(report[0], SIXAXIS_SET_REPORT_ID);
        assert_eq!(&report[2..8], &addr);
    }
}
