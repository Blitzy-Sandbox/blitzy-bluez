//! Battery charge fluctuation smoother unit tests.
//!
//! Converted from `unit/test-battery.c`.  Tests the [`BtBattery`] charge
//! smoothing state machine with ten test scenarios covering monotonic
//! discharge, monotonic charge, direction reversals, fluctuation averaging,
//! anomaly handling, erratic batteries, and 5 %/10 % step devices.
//!
//! Conversion patterns applied:
//!
//! | C                            | Rust                             |
//! |------------------------------|----------------------------------|
//! | `bt_battery_new()`           | `BtBattery::new()`               |
//! | `bt_battery_charge(b, pct)`  | `battery.charge(pct)`            |
//! | `bt_battery_free(b); free(b)`| automatic `Drop`                 |
//! | `g_assert(x == y)`           | `assert_eq!(x, y)`               |
//! | `tester_test_passed()`       | test returns without panic        |

use bluez_shared::profiles::battery::{BtBattery, LAST_CHARGES_SIZE};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of charge readings fed per test (matches C `DATA_SIZE`).
const DATA_SIZE: usize = 10;

// ---------------------------------------------------------------------------
// Helpers  (mirrors the C helper functions exactly)
// ---------------------------------------------------------------------------

/// Compute the integer-division average of the last [`LAST_CHARGES_SIZE`]
/// entries in a `DATA_SIZE`-length charge array.
///
/// This is a faithful translation of the C `calculate_average()` helper:
///
/// ```c
/// for (i = DATA_SIZE - LAST_CHARGES_SIZE; i < DATA_SIZE; i++)
///     sum += charges[i];
/// return sum / LAST_CHARGES_SIZE;
/// ```
fn calculate_average(charges: &[u8; DATA_SIZE]) -> u8 {
    let start = DATA_SIZE - LAST_CHARGES_SIZE;
    let sum: u32 = charges[start..].iter().map(|&c| u32::from(c)).sum();
    (sum / LAST_CHARGES_SIZE as u32) as u8
}

/// Feed every charge reading through a fresh [`BtBattery`] and return the
/// result of the **last** `charge()` call.
///
/// This is a faithful translation of the C `process_data()` helper:
///
/// ```c
/// struct bt_battery *battery = bt_battery_new();
/// for (i = 0; i < DATA_SIZE; i++)
///     result = bt_battery_charge(battery, charges[i]);
/// bt_battery_free(battery);
/// free(battery);
/// return result;
/// ```
fn process_data(charges: &[u8; DATA_SIZE]) -> u8 {
    let mut battery = BtBattery::new();
    let mut result: u8 = 0;
    for &c in charges.iter() {
        result = battery.charge(c);
    }
    result
}

// ---------------------------------------------------------------------------
// Test 1: Monotonic discharge
// ---------------------------------------------------------------------------

/// Monotonically decreasing charge readings should pass through without
/// smoothing — every `charge()` call returns the raw input.
#[test]
fn test_discharging() {
    let charges: [u8; DATA_SIZE] = [84, 83, 83, 81, 80, 80, 80, 79, 79, 78];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(battery.charge(c), c, "Discharging: charge({c}) should return {c}");
    }
}

// ---------------------------------------------------------------------------
// Test 2: Monotonic charge
// ---------------------------------------------------------------------------

/// Monotonically increasing charge readings should pass through without
/// smoothing — every `charge()` call returns the raw input.
#[test]
fn test_charging() {
    let charges: [u8; DATA_SIZE] = [48, 48, 48, 49, 49, 50, 51, 51, 51, 53];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(battery.charge(c), c, "Charging: charge({c}) should return {c}");
    }
}

// ---------------------------------------------------------------------------
// Test 3: Discharge started after an initial increase
// ---------------------------------------------------------------------------

/// An initial increase followed by a sustained decrease.  The step sizes
/// are large enough that the smoother does not flag fluctuation.
#[test]
fn test_discharge_started() {
    let charges: [u8; DATA_SIZE] = [48, 48, 49, 50, 51, 51, 49, 48, 47, 45];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(battery.charge(c), c, "Discharge-started: charge({c}) should return {c}");
    }
}

// ---------------------------------------------------------------------------
// Test 4: Charge started after an initial decrease
// ---------------------------------------------------------------------------

/// An initial decrease followed by a sustained increase.  Again, step
/// sizes are large enough to avoid the fluctuation detector.
#[test]
fn test_charge_started() {
    let charges: [u8; DATA_SIZE] = [57, 57, 56, 56, 55, 54, 55, 57, 57, 58];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(battery.charge(c), c, "Charge-started: charge({c}) should return {c}");
    }
}

// ---------------------------------------------------------------------------
// Test 5: Small fluctuations → smoothed average
// ---------------------------------------------------------------------------

/// Small oscillations around a mean value.  After the rolling window
/// fills, the smoother detects the fluctuation pattern and returns the
/// average of the last [`LAST_CHARGES_SIZE`] readings instead of the raw
/// input.
#[test]
fn test_fluctuations() {
    let charges: [u8; DATA_SIZE] = [74, 73, 75, 72, 74, 72, 73, 71, 75, 73];

    let result = process_data(&charges);
    let expected = calculate_average(&charges);

    assert_eq!(
        result, expected,
        "Fluctuations: final result ({result}) should equal average ({expected})"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Fluctuations with a mid-stream anomaly
// ---------------------------------------------------------------------------

/// A stream with a single large jump (94) in the middle.  Because the
/// step from 32 → 94 exceeds `MAX_CHARGE_STEP`, the smoother resets its
/// fluctuation flag, so every reading returns the raw input.
#[test]
fn test_fluctuations_with_anomaly() {
    let charges: [u8; DATA_SIZE] = [33, 33, 34, 32, 94, 33, 31, 33, 34, 32];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(
            battery.charge(c),
            c,
            "Fluctuations-with-anomaly: charge({c}) should return {c}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 7: Fluctuations with an old anomaly
// ---------------------------------------------------------------------------

/// The anomaly (94) is at the very start and quickly ages out of the
/// rolling window.  Once the window fills with small oscillations, the
/// smoother engages and returns the average.
#[test]
fn test_fluctuations_with_old_anomaly() {
    let charges: [u8; DATA_SIZE] = [94, 22, 22, 21, 21, 20, 21, 20, 21, 20];

    let result = process_data(&charges);
    let expected = calculate_average(&charges);

    assert_eq!(
        result, expected,
        "Old-anomaly: final result ({result}) should equal average ({expected})"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Erratic ("bad") battery
// ---------------------------------------------------------------------------

/// Wildly varying charge readings where most consecutive steps exceed
/// `MAX_CHARGE_STEP`.  The fluctuation detector keeps resetting, so every
/// reading passes through raw.
#[test]
fn test_bad_battery() {
    let charges: [u8; DATA_SIZE] = [28, 38, 92, 34, 85, 34, 45, 41, 29, 40];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(battery.charge(c), c, "Bad-battery: charge({c}) should return {c}");
    }
}

// ---------------------------------------------------------------------------
// Test 9: Device reporting in 5 % steps
// ---------------------------------------------------------------------------

/// A device that reports charge in 5 % increments.  The step sizes
/// (0 or 5) mean consecutive readings often differ by ≥ `MAX_CHARGE_STEP`,
/// so the smoother does not engage.
#[test]
fn test_device_report_5_percent() {
    let charges: [u8; DATA_SIZE] = [55, 55, 50, 50, 50, 55, 55, 55, 60, 60];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(battery.charge(c), c, "5%-step: charge({c}) should return {c}");
    }
}

// ---------------------------------------------------------------------------
// Test 10: Device reporting in 10 % steps
// ---------------------------------------------------------------------------

/// A device that reports charge in 10 % increments.  Every real step
/// exceeds `MAX_CHARGE_STEP`, preventing fluctuation detection.
#[test]
fn test_device_report_10_percent() {
    let charges: [u8; DATA_SIZE] = [30, 30, 30, 40, 40, 50, 50, 50, 50, 60];

    let mut battery = BtBattery::new();
    for &c in &charges {
        assert_eq!(battery.charge(c), c, "10%-step: charge({c}) should return {c}");
    }
}
