// SPDX-License-Identifier: GPL-2.0-or-later
//
// Channel Sounding ranging profile implementation (~333 LOC C).
//
// CS-based distance measurement — uses Channel Sounding procedures to
// estimate physical distance between two Bluetooth devices.

/// Ranging method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingMethod {
    /// Round-Trip Time based ranging.
    Rtt,
    /// Phase-Based Ranging.
    PhaseBased,
    /// RTT + Phase combined.
    RttPhaseCombined,
}

/// Ranging procedure state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RangingState {
    #[default]
    Idle,
    /// CS Security procedure in progress.
    SecuritySetup,
    /// CS configuration exchange.
    Configuring,
    /// Actively performing CS procedures.
    Measuring,
    /// Measurement complete, results available.
    Complete,
    /// Error occurred during ranging.
    Error,
}


/// Ranging role in a CS procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingRole {
    Initiator,
    Reflector,
}

/// A single ranging measurement result.
#[derive(Debug, Clone, Copy)]
pub struct RangingResult {
    /// Estimated distance in centimeters.
    pub distance_cm: u32,
    /// Quality / confidence indicator (0-100).
    pub quality: u8,
    /// RSSI at time of measurement (dBm).
    pub rssi: i8,
    /// Measurement timestamp (monotonic, microseconds).
    pub timestamp_us: u64,
}

/// Ranging profile plugin.
#[derive(Debug)]
pub struct RangingProfile {
    pub state: RangingState,
    pub role: RangingRole,
    pub method: RangingMethod,
    /// CS configuration ID agreed upon.
    pub config_id: u8,
    /// Maximum number of CS procedures per measurement.
    pub max_procedures: u8,
    /// Most recent measurement results.
    pub results: Vec<RangingResult>,
}

impl RangingProfile {
    pub fn new(role: RangingRole) -> Self {
        Self {
            state: RangingState::default(),
            role,
            method: RangingMethod::Rtt,
            config_id: 0,
            max_procedures: 1,
            results: Vec::new(),
        }
    }

    /// Record a measurement result.
    pub fn add_result(&mut self, result: RangingResult) {
        self.results.push(result);
    }

    /// Clear all stored results.
    pub fn clear_results(&mut self) {
        self.results.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranging_defaults() {
        let rng = RangingProfile::new(RangingRole::Initiator);
        assert_eq!(rng.state, RangingState::Idle);
        assert_eq!(rng.role, RangingRole::Initiator);
        assert!(rng.results.is_empty());
    }

    #[test]
    fn test_ranging_add_result() {
        let mut rng = RangingProfile::new(RangingRole::Reflector);
        rng.add_result(RangingResult {
            distance_cm: 150,
            quality: 85,
            rssi: -45,
            timestamp_us: 1000000,
        });
        assert_eq!(rng.results.len(), 1);
        assert_eq!(rng.results[0].distance_cm, 150);

        rng.clear_results();
        assert!(rng.results.is_empty());
    }
}
