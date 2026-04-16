// SPDX-License-Identifier: GPL-2.0-or-later
//
// Scan Parameters profile implementation (~624 LOC C).
//
// Allows a GATT client to inform the server of its preferred scan
// interval and window for LE scanning.

/// Scan Parameters Service UUID.
pub const SCAN_PARAMETERS_SERVICE_UUID: u16 = 0x1813;
pub const SCAN_INTERVAL_WINDOW_UUID: u16 = 0x2A4F;
pub const SCAN_REFRESH_UUID: u16 = 0x2A31;

/// Scan refresh requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRefreshValue {
    /// Server requires refresh of scan parameters.
    ServerRequiresRefresh,
}

/// Scan Parameters profile plugin.
#[derive(Debug)]
pub struct ScanParamProfile {
    /// Scan interval in 0.625ms units (range 0x0004-0x4000).
    pub scan_interval: u16,
    /// Scan window in 0.625ms units (range 0x0004-0x4000).
    pub scan_window: u16,
    /// GATT handle for the Scan Interval Window characteristic.
    pub interval_window_handle: u16,
    /// GATT handle for Scan Refresh characteristic CCC.
    pub refresh_ccc_handle: u16,
    /// Whether notifications for scan refresh are enabled.
    pub refresh_notify_enabled: bool,
}

impl ScanParamProfile {
    pub fn new() -> Self {
        Self {
            // Default: 60ms interval, 30ms window in 0.625ms units
            scan_interval: 0x0060,
            scan_window: 0x0030,
            interval_window_handle: 0,
            refresh_ccc_handle: 0,
            refresh_notify_enabled: false,
        }
    }

    /// Validate that interval and window are within spec range and
    /// window <= interval.
    pub fn validate_params(interval: u16, window: u16) -> bool {
        let valid_range = 0x0004..=0x4000;
        valid_range.contains(&interval) && valid_range.contains(&window) && window <= interval
    }

    /// Set scan parameters if valid.
    pub fn set_params(&mut self, interval: u16, window: u16) -> bool {
        if Self::validate_params(interval, window) {
            self.scan_interval = interval;
            self.scan_window = window;
            true
        } else {
            false
        }
    }
}

impl Default for ScanParamProfile {
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

    #[test]
    fn test_scanparam_defaults() {
        let sp = ScanParamProfile::new();
        assert_eq!(sp.scan_interval, 0x0060);
        assert_eq!(sp.scan_window, 0x0030);
    }

    #[test]
    fn test_scanparam_validation() {
        assert!(ScanParamProfile::validate_params(0x0060, 0x0030));
        assert!(ScanParamProfile::validate_params(0x0004, 0x0004));
        // Window > interval is invalid
        assert!(!ScanParamProfile::validate_params(0x0010, 0x0020));
        // Below minimum
        assert!(!ScanParamProfile::validate_params(0x0003, 0x0003));
        // Above maximum
        assert!(!ScanParamProfile::validate_params(0x4001, 0x0010));
    }
}
