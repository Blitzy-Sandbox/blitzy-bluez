// SPDX-License-Identifier: GPL-2.0-or-later
//
// GAP profile implementation (~388 LOC C).
//
// Generic Access Profile — exposes device name, appearance, and peripheral
// preferred connection parameters via GATT.

/// GAP Service UUID.
pub const GAP_SERVICE_UUID: u16 = 0x1800;
pub const DEVICE_NAME_UUID: u16 = 0x2A00;
pub const APPEARANCE_UUID: u16 = 0x2A01;
pub const PERIPHERAL_PREFERRED_CONN_UUID: u16 = 0x2A04;
pub const CENTRAL_ADDRESS_RESOLUTION_UUID: u16 = 0x2AA6;

/// Well-known GAP appearance values (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum GapAppearance {
    Unknown = 0x0000,
    Phone = 0x0040,
    Computer = 0x0080,
    Watch = 0x00C0,
    Clock = 0x0100,
    Display = 0x0140,
    RemoteControl = 0x0180,
    EyeGlasses = 0x01C0,
    Tag = 0x0200,
    Keyring = 0x0240,
    GenericMediaPlayer = 0x0280,
    Keyboard = 0x03C1,
    Mouse = 0x03C2,
    Gamepad = 0x03C4,
    GenericHearingAid = 0x0A40,
    GenericAudioSink = 0x0841,
    GenericAudioSource = 0x0842,
}

impl GapAppearance {
    /// Create from a raw 16-bit value.
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0040 => Self::Phone,
            0x0080 => Self::Computer,
            0x00C0 => Self::Watch,
            0x0100 => Self::Clock,
            0x0140 => Self::Display,
            0x0180 => Self::RemoteControl,
            0x01C0 => Self::EyeGlasses,
            0x0200 => Self::Tag,
            0x0240 => Self::Keyring,
            0x0280 => Self::GenericMediaPlayer,
            0x03C1 => Self::Keyboard,
            0x03C2 => Self::Mouse,
            0x03C4 => Self::Gamepad,
            0x0A40 => Self::GenericHearingAid,
            0x0841 => Self::GenericAudioSink,
            0x0842 => Self::GenericAudioSource,
            _ => Self::Unknown,
        }
    }
}

/// Peripheral preferred connection parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreferredConnectionParams {
    /// Minimum connection interval (1.25ms units).
    pub min_interval: u16,
    /// Maximum connection interval (1.25ms units).
    pub max_interval: u16,
    /// Peripheral latency (number of events).
    pub latency: u16,
    /// Supervision timeout (10ms units).
    pub timeout: u16,
}

impl PreferredConnectionParams {
    /// Parse from an 8-byte GATT characteristic value (little-endian).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self {
            min_interval: u16::from_le_bytes([data[0], data[1]]),
            max_interval: u16::from_le_bytes([data[2], data[3]]),
            latency: u16::from_le_bytes([data[4], data[5]]),
            timeout: u16::from_le_bytes([data[6], data[7]]),
        })
    }
}

/// GAP profile plugin.
#[derive(Debug)]
pub struct GapProfile {
    pub device_name: Option<String>,
    pub appearance: GapAppearance,
    pub preferred_params: Option<PreferredConnectionParams>,
    pub central_address_resolution: bool,
}

impl GapProfile {
    pub fn new() -> Self {
        Self {
            device_name: None,
            appearance: GapAppearance::Unknown,
            preferred_params: None,
            central_address_resolution: false,
        }
    }
}

impl Default for GapProfile {
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
    fn test_gap_defaults() {
        let gap = GapProfile::new();
        assert!(gap.device_name.is_none());
        assert_eq!(gap.appearance, GapAppearance::Unknown);
    }

    #[test]
    fn test_preferred_conn_params_parse() {
        // min=6, max=12, latency=0, timeout=200 (all LE)
        let data = [0x06, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xC8, 0x00];
        let params = PreferredConnectionParams::from_bytes(&data).unwrap();
        assert_eq!(params.min_interval, 6);
        assert_eq!(params.max_interval, 12);
        assert_eq!(params.latency, 0);
        assert_eq!(params.timeout, 200);
    }

    #[test]
    fn test_appearance_from_u16() {
        assert_eq!(GapAppearance::from_u16(0x03C1), GapAppearance::Keyboard);
        assert_eq!(GapAppearance::from_u16(0xFFFF), GapAppearance::Unknown);
    }
}
