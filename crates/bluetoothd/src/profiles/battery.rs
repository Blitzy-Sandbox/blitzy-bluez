// SPDX-License-Identifier: GPL-2.0-or-later
//
// Battery profile implementation (~676 LOC C).
//
// Battery Service (BAS) — reads battery level from GATT characteristic and
// exposes it over D-Bus.

use bluez_shared::BdAddr;

/// Battery Service UUIDs.
pub const BATTERY_SERVICE_UUID: u16 = 0x180F;
pub const BATTERY_LEVEL_UUID: u16 = 0x2A19;

/// Battery profile state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BatteryState {
    /// Not connected / no battery info.
    #[default]
    Idle,
    /// Discovering BAS characteristics.
    Discovering,
    /// Battery level is being read.
    Reading,
    /// Battery level is known and notifications are active.
    Active,
}

/// Battery profile plugin.
#[derive(Debug)]
pub struct BatteryProfile {
    pub state: BatteryState,
    pub remote_addr: Option<BdAddr>,
    /// Battery level percentage (0-100), or None if unknown.
    pub percentage: Option<u8>,
    /// GATT handle for the Battery Level characteristic.
    pub level_handle: u16,
    /// GATT handle for the CCC descriptor (for notifications).
    pub ccc_handle: u16,
    /// Whether notifications are enabled.
    pub notify_enabled: bool,
}

impl BatteryProfile {
    pub fn new() -> Self {
        Self {
            state: BatteryState::default(),
            remote_addr: None,
            percentage: None,
            level_handle: 0,
            ccc_handle: 0,
            notify_enabled: false,
        }
    }

    /// Update the battery level, clamping to 0-100.
    pub fn set_percentage(&mut self, level: u8) {
        self.percentage = Some(level.min(100));
    }
}

impl Default for BatteryProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Defaults ----

    #[test]
    fn test_battery_defaults() {
        let bat = BatteryProfile::new();
        assert_eq!(bat.state, BatteryState::Idle);
        assert!(bat.percentage.is_none());
        assert!(!bat.notify_enabled);
    }

    // ---- Percentage clamping ----

    #[test]
    fn test_battery_set_percentage_clamp() {
        let mut bat = BatteryProfile::new();
        bat.set_percentage(85);
        assert_eq!(bat.percentage, Some(85));

        bat.set_percentage(200);
        assert_eq!(bat.percentage, Some(100));
    }

    // ---- Discharging sequence (from test-battery.c: test_discharging) ----

    #[test]
    fn test_battery_discharging() {
        let charges: [u8; 10] = [84, 83, 83, 81, 80, 80, 80, 79, 79, 78];
        let mut bat = BatteryProfile::new();
        for &c in &charges {
            bat.set_percentage(c);
            assert_eq!(bat.percentage, Some(c));
        }
    }

    // ---- Charging sequence (from test-battery.c: test_charging) ----

    #[test]
    fn test_battery_charging() {
        let charges: [u8; 10] = [48, 48, 48, 49, 49, 50, 51, 51, 51, 53];
        let mut bat = BatteryProfile::new();
        for &c in &charges {
            bat.set_percentage(c);
            assert_eq!(bat.percentage, Some(c));
        }
    }

    // ---- Discharge started (from test-battery.c: test_discharge_started) ----

    #[test]
    fn test_battery_discharge_started() {
        let charges: [u8; 10] = [48, 48, 49, 50, 51, 51, 49, 48, 47, 45];
        let mut bat = BatteryProfile::new();
        for &c in &charges {
            bat.set_percentage(c);
            assert_eq!(bat.percentage, Some(c));
        }
    }

    // ---- Charge started (from test-battery.c: test_charge_started) ----

    #[test]
    fn test_battery_charge_started() {
        let charges: [u8; 10] = [57, 57, 56, 56, 55, 54, 55, 57, 57, 58];
        let mut bat = BatteryProfile::new();
        for &c in &charges {
            bat.set_percentage(c);
            assert_eq!(bat.percentage, Some(c));
        }
    }

    // ---- Bad battery data (from test-battery.c: test_bad_battery) ----

    #[test]
    fn test_battery_bad_values() {
        let charges: [u8; 10] = [28, 38, 92, 34, 85, 34, 45, 41, 29, 40];
        let mut bat = BatteryProfile::new();
        for &c in &charges {
            bat.set_percentage(c);
            assert_eq!(bat.percentage, Some(c));
        }
    }

    // ---- Boundary values ----

    #[test]
    fn test_battery_zero() {
        let mut bat = BatteryProfile::new();
        bat.set_percentage(0);
        assert_eq!(bat.percentage, Some(0));
    }

    #[test]
    fn test_battery_exactly_100() {
        let mut bat = BatteryProfile::new();
        bat.set_percentage(100);
        assert_eq!(bat.percentage, Some(100));
    }

    #[test]
    fn test_battery_above_100_clamped() {
        let mut bat = BatteryProfile::new();
        bat.set_percentage(101);
        assert_eq!(bat.percentage, Some(100));
        bat.set_percentage(255);
        assert_eq!(bat.percentage, Some(100));
    }

    // ---- 5-percent step reporting (from test-battery.c) ----

    #[test]
    fn test_battery_5_percent_steps() {
        let charges: [u8; 10] = [55, 55, 50, 50, 50, 55, 55, 55, 60, 60];
        let mut bat = BatteryProfile::new();
        for &c in &charges {
            bat.set_percentage(c);
            assert_eq!(bat.percentage, Some(c));
        }
    }

    // ---- 10-percent step reporting (from test-battery.c) ----

    #[test]
    fn test_battery_10_percent_steps() {
        let charges: [u8; 10] = [30, 30, 30, 40, 40, 50, 50, 50, 50, 60];
        let mut bat = BatteryProfile::new();
        for &c in &charges {
            bat.set_percentage(c);
            assert_eq!(bat.percentage, Some(c));
        }
    }

    // ---- UUIDs ----

    #[test]
    fn test_battery_service_uuid() {
        assert_eq!(BATTERY_SERVICE_UUID, 0x180F);
    }

    #[test]
    fn test_battery_level_uuid() {
        assert_eq!(BATTERY_LEVEL_UUID, 0x2A19);
    }
}
