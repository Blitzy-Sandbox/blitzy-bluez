// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2025  Open Mobile Platform LLC <community@omp.ru>
//
// Battery charge fluctuation smoother — idiomatic Rust rewrite of
// `src/shared/battery.c` and `src/shared/battery.h` from BlueZ v5.86.
//
// This module tracks recent battery charge readings and smooths out
// oscillations by returning a windowed average when rapid fluctuations
// (frequent direction reversals) are detected.

use std::collections::VecDeque;

/// Rolling window size for charge history.
///
/// The battery smoother collects up to this many consecutive charge readings
/// before the fluctuation-detection algorithm activates.  Matches the C
/// constant `LAST_CHARGES_SIZE` in `src/shared/battery.h`.
pub const LAST_CHARGES_SIZE: usize = 8;

/// Maximum per-step charge delta that is still considered a fluctuation.
///
/// If any consecutive pair of readings in the window has an absolute
/// difference **greater than or equal to** this threshold, the readings are
/// considered a genuine charge change rather than noise, and the
/// fluctuation-smoothing logic is bypassed.  Matches the C constant
/// `MAX_CHARGE_STEP` in `src/shared/battery.h`.
pub const MAX_CHARGE_STEP: u8 = 5;

/// Battery charge fluctuation smoother.
///
/// Tracks recent battery charge readings and smooths out oscillations by
/// returning a windowed average when rapid fluctuations are detected.
///
/// # Algorithm (behavioral clone of `bt_battery_charge` in battery.c)
///
/// 1. Each new percentage is pushed into a sliding window.
/// 2. Once the window reaches [`LAST_CHARGES_SIZE`] entries the
///    fluctuation-check routine runs:
///    - If any consecutive pair has `|step| >= MAX_CHARGE_STEP` the
///      readings represent a genuine change and `is_fluctuating` is
///      cleared.
///    - Otherwise the number of direction-reversals ("spikes") is
///      counted.  If `spikes > 1` the sensor is deemed fluctuating.
///    - The windowed average is stored for use as the smoothed value.
/// 3. After the check the oldest entry is discarded (window stays at
///    `LAST_CHARGES_SIZE - 1` entries between calls).
/// 4. If `is_fluctuating` is true the cached average is returned;
///    otherwise the raw percentage is returned.
///
/// # Replaces
///
/// - `struct bt_battery` (opaque C struct with `struct queue *` + void*
///   pointer casting via `UINT_TO_PTR`/`PTR_TO_UINT`)
/// - `bt_battery_new()` / `bt_battery_free()` — replaced by Rust
///   construction and automatic `Drop`.
/// - `bt_battery_charge()` — replaced by [`BtBattery::charge`].
#[derive(Debug)]
pub struct BtBattery {
    /// Rolling window of recent charge percentages.
    ///
    /// Replaces the C `struct queue *last_charges` which stored `u8`
    /// values disguised as `void *` pointers.
    last_charges: VecDeque<u8>,

    /// Cached running average of the charge window, used as the smoothed
    /// output while the sensor is fluctuating.
    avg_charge: u8,

    /// Whether the charge sensor is currently exhibiting rapid direction
    /// reversals that indicate unreliable readings.
    is_fluctuating: bool,
}

impl BtBattery {
    /// Creates a new, empty battery charge smoother.
    ///
    /// Equivalent to `bt_battery_new()` in the C source.  The internal
    /// queue is pre-allocated with capacity for the full window plus one
    /// extra slot (the entry that triggers the check before being
    /// evicted).
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_charges: VecDeque::with_capacity(LAST_CHARGES_SIZE + 1),
            avg_charge: 0,
            is_fluctuating: false,
        }
    }

    /// Processes a new battery charge reading and returns the
    /// (potentially smoothed) charge percentage.
    ///
    /// This is a faithful behavioral clone of `bt_battery_charge()` in
    /// `battery.c` (lines 86-96) combined with
    /// `bt_battery_check_fluctuations()` (lines 42-84).
    ///
    /// # Arguments
    ///
    /// * `percentage` — The raw battery charge percentage (0–100,
    ///   although any `u8` value is accepted to match C behavior).
    ///
    /// # Returns
    ///
    /// The smoothed charge percentage.  When the sensor is fluctuating
    /// the windowed average is returned; otherwise the raw `percentage`
    /// is passed through.
    pub fn charge(&mut self, percentage: u8) -> u8 {
        // Step 1: Push the new reading into the sliding window.
        self.last_charges.push_back(percentage);

        // Step 2: If we have accumulated exactly LAST_CHARGES_SIZE entries
        //         run the fluctuation-detection algorithm, then discard
        //         the oldest entry.
        if self.last_charges.len() == LAST_CHARGES_SIZE {
            self.check_fluctuations();
            self.last_charges.pop_front();
        }

        // Step 3: Return smoothed or raw value.
        if self.is_fluctuating { self.avg_charge } else { percentage }
    }

    /// Fluctuation-detection algorithm — behavioral clone of
    /// `bt_battery_check_fluctuations()` in `battery.c` (lines 42-84).
    ///
    /// The function iterates over consecutive pairs in the window,
    /// tracking:
    ///
    /// - **Direction** of each step (+1 for charge increasing, −1 for
    ///   decreasing, unchanged for equal readings).
    /// - **Spikes** — direction reversals from the previous non-zero
    ///   direction.
    /// - **Sum** of all charge values for average computation.
    ///
    /// If any single step has `|step| >= MAX_CHARGE_STEP` the readings
    /// represent a real charge change and `is_fluctuating` is cleared
    /// immediately.  Otherwise `is_fluctuating` is set when `spikes > 1`.
    fn check_fluctuations(&mut self) {
        let mut spikes: u8 = 0;
        let mut direction: i8 = 0;
        let mut sum_charge: u16 = 0;
        let mut last_value: u8 = 0;

        // We need indexed access to consecutive pairs — collect a
        // reference slice from the VecDeque.  The `make_contiguous`
        // approach would require `&mut self` but we already have it;
        // however, since we only read the charges, we collect into
        // a small stack buffer via the iterator.
        let entries: Vec<u8> = self.last_charges.iter().copied().collect();
        let len = entries.len();

        // Iterate pairs [i, i+1] for i in 0..len-1, mirroring the C
        // linked-list traversal `for (entry = …; entry->next; …)`.
        for i in 0..len - 1 {
            let prev_direction = direction;
            let prev_charge = entries[i];
            let next_charge = entries[i + 1];

            // Signed step — computed as i16 to avoid truncation issues
            // that arise with the C `int8_t step = next - prev` pattern.
            // For battery percentages (0–100) both representations are
            // identical.
            let step = i16::from(next_charge) - i16::from(prev_charge);

            // Accumulate sum (only `prev_charge` per iteration, matching
            // the C loop which adds `prev_charge` inside the loop body
            // and `next_charge` after the loop).
            sum_charge += u16::from(prev_charge);

            // If the absolute step is at or above the threshold the
            // readings represent a genuine charge change — clear the
            // fluctuation flag and return immediately.
            if step.unsigned_abs() >= u16::from(MAX_CHARGE_STEP) {
                self.is_fluctuating = false;
                return;
            }

            // Track direction: +1 for increasing, −1 for decreasing.
            // A zero step leaves direction unchanged (matches C behavior
            // where neither branch of `if (step > 0) … else if (step < 0)`
            // fires for step == 0).
            if step > 0 {
                direction = 1;
            } else if step < 0 {
                direction = -1;
            }

            // A "spike" is a direction reversal from a previous non-zero
            // direction.  The very first iteration always has
            // `prev_direction == 0` so it never counts as a spike.
            if direction != prev_direction && prev_direction != 0 {
                spikes += 1;
            }

            // Remember the last element for the post-loop sum addition.
            last_value = next_charge;
        }

        // Add the final element to the running sum (mirrors the C
        // `sum_charge += next_charge` after the loop).
        sum_charge += u16::from(last_value);

        // Integer-division average, matching C `sum / LAST_CHARGES_SIZE`.
        self.avg_charge = (sum_charge / LAST_CHARGES_SIZE as u16) as u8;

        // More than one direction reversal indicates noisy/fluctuating
        // sensor readings.
        self.is_fluctuating = spikes > 1;
    }
}

impl Default for BtBattery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the constants match the C header values.
    #[test]
    fn constants_match_c() {
        assert_eq!(LAST_CHARGES_SIZE, 8);
        assert_eq!(MAX_CHARGE_STEP, 5);
    }

    /// A freshly created battery smoother is not fluctuating.
    #[test]
    fn new_battery_not_fluctuating() {
        let bat = BtBattery::new();
        assert!(!bat.is_fluctuating);
        assert_eq!(bat.avg_charge, 0);
        assert!(bat.last_charges.is_empty());
    }

    /// Default trait delegates to new().
    #[test]
    fn default_is_new() {
        let bat = BtBattery::default();
        assert!(!bat.is_fluctuating);
        assert_eq!(bat.avg_charge, 0);
        assert!(bat.last_charges.is_empty());
    }

    /// Fewer than LAST_CHARGES_SIZE readings always return the raw value.
    #[test]
    fn fewer_than_window_returns_raw() {
        let mut bat = BtBattery::new();
        for i in 0..LAST_CHARGES_SIZE - 1 {
            let pct = (50 + i) as u8;
            assert_eq!(bat.charge(pct), pct);
        }
    }

    /// Stable readings (constant value) should never trigger fluctuation.
    #[test]
    fn stable_readings_no_fluctuation() {
        let mut bat = BtBattery::new();
        for _ in 0..20 {
            assert_eq!(bat.charge(75), 75);
        }
        assert!(!bat.is_fluctuating);
    }

    /// Monotonically increasing values with small steps — no spikes,
    /// so not fluctuating.  The raw percentage is returned.
    #[test]
    fn monotonic_increase_no_fluctuation() {
        let mut bat = BtBattery::new();
        // Readings: 50, 51, 52, 53, 54, 55, 56, 57, 58, 59 …
        for i in 0u8..16 {
            let pct = 50 + i;
            let result = bat.charge(pct);
            // Before the 8th reading the raw value is returned.
            // At and after the 8th reading, direction is always +1
            // → zero spikes → not fluctuating → raw value.
            assert_eq!(result, pct);
        }
        assert!(!bat.is_fluctuating);
    }

    /// Large step (>= MAX_CHARGE_STEP) clears fluctuation flag.
    #[test]
    fn large_step_clears_fluctuation() {
        let mut bat = BtBattery::new();
        // Fill with oscillating small values to trigger fluctuation.
        // Pattern: 50, 52, 50, 52, 50, 52, 50, 52 — 2-unit oscillation,
        // many direction reversals.
        let oscillating = [50u8, 52, 50, 52, 50, 52, 50];
        for &v in &oscillating {
            bat.charge(v);
        }
        // The 8th entry triggers the check.
        bat.charge(52); // window = [50,52,50,52,50,52,50,52]
        assert!(bat.is_fluctuating);

        // Now inject a large step — 60 is 8 units above 52.
        // After the previous charge call, the window is
        // [52,50,52,50,52,50,52].  Push 60 → window becomes
        // [52,50,52,50,52,50,52,60].
        bat.charge(60);
        // The check sees |52 - 60| = 8 >= 5 → clears fluctuation.
        assert!(!bat.is_fluctuating);
    }

    /// Direction-reversal oscillation with small steps triggers
    /// fluctuation and returns the average.
    #[test]
    fn oscillation_triggers_fluctuation() {
        let mut bat = BtBattery::new();
        // Pattern: 50, 53, 50, 53, 50, 53, 50 — 3-unit oscillation
        // with many direction reversals, all steps < 5.
        let readings = [50u8, 53, 50, 53, 50, 53, 50];
        for &v in &readings {
            bat.charge(v);
        }
        // 8th reading triggers the check.
        let result = bat.charge(53);
        assert!(bat.is_fluctuating);
        // Average of [50,53,50,53,50,53,50,53] = 412/8 = 51
        assert_eq!(result, 51);
    }

    /// Queue length never exceeds LAST_CHARGES_SIZE - 1 after the
    /// check + pop cycle.
    #[test]
    fn queue_length_management() {
        let mut bat = BtBattery::new();
        for i in 0u8..30 {
            bat.charge(i % 100);
            // After each call the length should be at most
            // LAST_CHARGES_SIZE - 1 (the check pops when full).
            assert!(bat.last_charges.len() < LAST_CHARGES_SIZE);
        }
    }

    /// Verify average computation uses integer division (truncation).
    #[test]
    fn average_uses_integer_division() {
        let mut bat = BtBattery::new();
        // Feed a pattern that oscillates and produces a non-integer
        // average.  [51, 54, 51, 54, 51, 54, 51, 54] → sum=420, avg=52
        let readings = [51u8, 54, 51, 54, 51, 54, 51];
        for &v in &readings {
            bat.charge(v);
        }
        let result = bat.charge(54);
        // Sum = 51+54+51+54+51+54+51+54 = 420, 420/8 = 52 (integer)
        assert!(bat.is_fluctuating);
        assert_eq!(result, 52);
    }

    /// Debug formatting works without panic.
    #[test]
    fn debug_format() {
        let bat = BtBattery::new();
        let s = format!("{bat:?}");
        assert!(s.contains("BtBattery"));
    }
}
