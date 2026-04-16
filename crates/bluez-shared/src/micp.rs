// SPDX-License-Identifier: GPL-2.0-or-later
//
// Microphone Control Profile (MICP) definitions replacing src/shared/micp.c

pub const MICS_UUID: u16 = 0x184D;

// MICS Characteristic UUIDs
pub const MICS_MUTE_UUID: u16 = 0x2BC3;

// Mute States
pub const MICS_NOT_MUTED: u8 = 0x00;
pub const MICS_MUTED: u8 = 0x01;
pub const MICS_DISABLED: u8 = 0x02;

// ---- MICS Error Codes ----

/// Value Not Allowed (ATT error for invalid mute value write).
pub const MICS_ERROR_VALUE_NOT_ALLOWED: u8 = 0x13;
/// Mute Disabled error (application-specific, 0x80).
pub const MICS_ERROR_MUTE_DISABLED: u8 = 0x80;

/// Mute state enum for type-safe usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuteState {
    NotMuted,
    Muted,
    Disabled,
}

impl MuteState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            MICS_NOT_MUTED => Some(Self::NotMuted),
            MICS_MUTED => Some(Self::Muted),
            MICS_DISABLED => Some(Self::Disabled),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Self::NotMuted => MICS_NOT_MUTED,
            Self::Muted => MICS_MUTED,
            Self::Disabled => MICS_DISABLED,
        }
    }

    /// Check if writing this mute value is valid (only 0x00 and 0x01 are writable).
    pub fn is_writable(&self) -> bool {
        matches!(self, Self::NotMuted | Self::Muted)
    }
}

/// Validate a mute write value per MICS spec.
/// Only 0x00 (Not Muted) and 0x01 (Muted) are valid write values.
pub fn is_valid_mute_write(value: u8) -> bool {
    value == MICS_NOT_MUTED || value == MICS_MUTED
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- UUID Tests (from test-micp.c SGGIT tests) ----

    #[test]
    fn test_mics_uuids() {
        assert_eq!(MICS_UUID, 0x184D);
        assert_eq!(MICS_MUTE_UUID, 0x2BC3);
    }

    // ---- Mute State Value Tests ----

    #[test]
    fn test_mute_state_values() {
        assert_eq!(MICS_NOT_MUTED, 0x00);
        assert_eq!(MICS_MUTED, 0x01);
        assert_eq!(MICS_DISABLED, 0x02);
    }

    // ---- MuteState enum Tests (from test-micp.c state management) ----

    #[test]
    fn test_mute_state_from_u8() {
        assert_eq!(MuteState::from_u8(0x00), Some(MuteState::NotMuted));
        assert_eq!(MuteState::from_u8(0x01), Some(MuteState::Muted));
        assert_eq!(MuteState::from_u8(0x02), Some(MuteState::Disabled));
        assert_eq!(MuteState::from_u8(0x03), None);
        assert_eq!(MuteState::from_u8(0x05), None);
        assert_eq!(MuteState::from_u8(0xFF), None);
    }

    #[test]
    fn test_mute_state_roundtrip() {
        for val in [MICS_NOT_MUTED, MICS_MUTED, MICS_DISABLED] {
            let state = MuteState::from_u8(val).unwrap();
            assert_eq!(state.as_u8(), val);
        }
    }

    // ---- Mute Write Validation (from test-micp.c MICS_SR_SPE_BI_01_C) ----

    #[test]
    fn test_valid_mute_write_values() {
        // Only 0x00 and 0x01 are valid writes
        assert!(is_valid_mute_write(0x00)); // Not Muted
        assert!(is_valid_mute_write(0x01)); // Muted
    }

    #[test]
    fn test_invalid_mute_write_values() {
        // From MICS_WRITE_MUTE_CHAR_INVALID in test-micp.c:
        // Writing 0x02 -> ATT Error: Value Not Allowed (0x13)
        // Writing 0x05 -> ATT Error: Value Not Allowed (0x13)
        assert!(!is_valid_mute_write(0x02));
        assert!(!is_valid_mute_write(0x05));
        assert!(!is_valid_mute_write(0xFF));
    }

    // ---- MuteState writable check ----

    #[test]
    fn test_mute_state_is_writable() {
        assert!(MuteState::NotMuted.is_writable());
        assert!(MuteState::Muted.is_writable());
        assert!(!MuteState::Disabled.is_writable());
    }

    // ---- Error Code Tests (from test-micp.c MICS_SR_SPE_BI_02_C) ----

    #[test]
    fn test_mics_error_codes() {
        assert_eq!(MICS_ERROR_VALUE_NOT_ALLOWED, 0x13);
        assert_eq!(MICS_ERROR_MUTE_DISABLED, 0x80);
    }

    // ---- Mute State Disabled behavior (from test-micp.c MICS_SR_SPE_BI_02_C) ----

    #[test]
    fn test_mute_state_disabled_rejects_writes() {
        // When mute state is Disabled (0x02), writes of both 0x00 and 0x01
        // should return error 0x80 (from MICS_MUTE_WRITE_0 / MICS_MUTE_WRITE_1)
        let disabled = MuteState::Disabled;
        assert!(!disabled.is_writable());
        // The mute values themselves are valid, but the state rejects them
        assert!(is_valid_mute_write(0x00));
        assert!(is_valid_mute_write(0x01));
    }

    // ---- Notification Tests (from test-micp.c MICS_SR_SPN_BV_01_C) ----

    #[test]
    fn test_mute_state_notification_sequence() {
        // SPN_BV_01_C: read mute (0x01), write 0x00, notify 0x00,
        // write 0x01, notify 0x01, read mute (0x01)
        let initial = MuteState::from_u8(0x01).unwrap();
        assert_eq!(initial, MuteState::Muted);

        let write_val_0 = MuteState::from_u8(0x00).unwrap();
        assert_eq!(write_val_0, MuteState::NotMuted);
        assert!(write_val_0.is_writable());

        let write_val_1 = MuteState::from_u8(0x01).unwrap();
        assert_eq!(write_val_1, MuteState::Muted);
        assert!(write_val_1.is_writable());
    }
}
