// SPDX-License-Identifier: GPL-2.0-or-later
//
// Volume Control Profile (VCP) definitions replacing src/shared/vcp.c

pub const VCS_UUID: u16 = 0x1844;
pub const VOCS_UUID: u16 = 0x1845;
pub const AICS_UUID: u16 = 0x1843;

// VCS Characteristic UUIDs
pub const VCS_STATE_UUID: u16 = 0x2B7D;
pub const VCS_CP_UUID: u16 = 0x2B7E;
pub const VCS_FLAGS_UUID: u16 = 0x2B7F;

// VCS Control Point Opcodes
pub const VCS_CP_RELATIVE_VOL_DOWN: u8 = 0x00;
pub const VCS_CP_RELATIVE_VOL_UP: u8 = 0x01;
pub const VCS_CP_UNMUTE_RELATIVE_VOL_DOWN: u8 = 0x02;
pub const VCS_CP_UNMUTE_RELATIVE_VOL_UP: u8 = 0x03;
pub const VCS_CP_SET_ABSOLUTE_VOL: u8 = 0x04;
pub const VCS_CP_UNMUTE: u8 = 0x05;
pub const VCS_CP_MUTE: u8 = 0x06;

// VOCS Offsets
pub const VOCS_STATE_UUID: u16 = 0x2B80;
pub const VOCS_LOCATION_UUID: u16 = 0x2B81;
pub const VOCS_CP_UUID: u16 = 0x2B82;
pub const VOCS_AUDIO_DESC_UUID: u16 = 0x2B83;

// AICS
pub const AICS_STATE_UUID: u16 = 0x2B77;
pub const AICS_GAIN_SETTING_UUID: u16 = 0x2B78;
pub const AICS_INPUT_TYPE_UUID: u16 = 0x2B79;
pub const AICS_INPUT_STATUS_UUID: u16 = 0x2B7A;
pub const AICS_CP_UUID: u16 = 0x2B7B;
pub const AICS_INPUT_DESC_UUID: u16 = 0x2B7C;

// ---- VCS Volume State ----

/// Volume state as read from the VCS Volume State characteristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeState {
    /// Current volume setting (0-255).
    pub volume: u8,
    /// Mute state (0=unmuted, 1=muted).
    pub mute: u8,
    /// Change counter for detecting concurrent modifications.
    pub change_counter: u8,
}

impl VolumeState {
    /// Parse from 3-byte characteristic value.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        Some(Self {
            volume: data[0],
            mute: data[1],
            change_counter: data[2],
        })
    }

    /// Serialize to 3 bytes.
    pub fn to_bytes(&self) -> [u8; 3] {
        [self.volume, self.mute, self.change_counter]
    }
}

// ---- VCS Control Point PDU ----

/// VCS control point write PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcsCpPdu {
    pub opcode: u8,
    pub change_counter: u8,
    /// Optional parameter (e.g., volume setting for Set Absolute Volume).
    pub param: Option<u8>,
}

impl VcsCpPdu {
    /// Build a Relative Volume Down command.
    pub fn relative_vol_down(change_counter: u8) -> Self {
        Self { opcode: VCS_CP_RELATIVE_VOL_DOWN, change_counter, param: None }
    }

    /// Build a Relative Volume Up command.
    pub fn relative_vol_up(change_counter: u8) -> Self {
        Self { opcode: VCS_CP_RELATIVE_VOL_UP, change_counter, param: None }
    }

    /// Build an Unmute + Relative Volume Down command.
    pub fn unmute_relative_vol_down(change_counter: u8) -> Self {
        Self { opcode: VCS_CP_UNMUTE_RELATIVE_VOL_DOWN, change_counter, param: None }
    }

    /// Build an Unmute + Relative Volume Up command.
    pub fn unmute_relative_vol_up(change_counter: u8) -> Self {
        Self { opcode: VCS_CP_UNMUTE_RELATIVE_VOL_UP, change_counter, param: None }
    }

    /// Build a Set Absolute Volume command.
    pub fn set_absolute_volume(change_counter: u8, volume: u8) -> Self {
        Self { opcode: VCS_CP_SET_ABSOLUTE_VOL, change_counter, param: Some(volume) }
    }

    /// Build an Unmute command.
    pub fn unmute(change_counter: u8) -> Self {
        Self { opcode: VCS_CP_UNMUTE, change_counter, param: None }
    }

    /// Build a Mute command.
    pub fn mute(change_counter: u8) -> Self {
        Self { opcode: VCS_CP_MUTE, change_counter, param: None }
    }

    /// Encode to bytes for writing to the control point.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.opcode, self.change_counter];
        if let Some(p) = self.param {
            out.push(p);
        }
        out
    }

    /// Parse from control point write bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let opcode = data[0];
        let change_counter = data[1];
        let param = if opcode == VCS_CP_SET_ABSOLUTE_VOL {
            if data.len() < 3 {
                return None;
            }
            Some(data[2])
        } else {
            None
        };
        Some(Self { opcode, change_counter, param })
    }
}

// ---- VOCS Offset State ----

/// Volume Offset state (VOCS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VocsOffsetState {
    /// Volume offset (-255 to +255).
    pub offset: i16,
    /// Change counter.
    pub change_counter: u8,
}

impl VocsOffsetState {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        let offset = i16::from_le_bytes([data[0], data[1]]);
        Some(Self {
            offset,
            change_counter: data[2],
        })
    }

    pub fn to_bytes(&self) -> [u8; 3] {
        let off = self.offset.to_le_bytes();
        [off[0], off[1], self.change_counter]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- UUID Tests (from test-vcp.c SGGIT tests) ----

    #[test]
    fn test_vcs_uuids() {
        assert_eq!(VCS_UUID, 0x1844);
        assert_eq!(VCS_STATE_UUID, 0x2B7D);
        assert_eq!(VCS_CP_UUID, 0x2B7E);
        assert_eq!(VCS_FLAGS_UUID, 0x2B7F);
    }

    #[test]
    fn test_vocs_uuids() {
        assert_eq!(VOCS_UUID, 0x1845);
        assert_eq!(VOCS_STATE_UUID, 0x2B80);
        assert_eq!(VOCS_LOCATION_UUID, 0x2B81);
        assert_eq!(VOCS_CP_UUID, 0x2B82);
        assert_eq!(VOCS_AUDIO_DESC_UUID, 0x2B83);
    }

    #[test]
    fn test_aics_uuids() {
        assert_eq!(AICS_UUID, 0x1843);
        assert_eq!(AICS_STATE_UUID, 0x2B77);
        assert_eq!(AICS_GAIN_SETTING_UUID, 0x2B78);
        assert_eq!(AICS_INPUT_TYPE_UUID, 0x2B79);
        assert_eq!(AICS_INPUT_STATUS_UUID, 0x2B7A);
        assert_eq!(AICS_CP_UUID, 0x2B7B);
        assert_eq!(AICS_INPUT_DESC_UUID, 0x2B7C);
    }

    // ---- VCS CP Opcode Tests ----

    #[test]
    fn test_vcs_cp_opcodes() {
        assert_eq!(VCS_CP_RELATIVE_VOL_DOWN, 0x00);
        assert_eq!(VCS_CP_RELATIVE_VOL_UP, 0x01);
        assert_eq!(VCS_CP_UNMUTE_RELATIVE_VOL_DOWN, 0x02);
        assert_eq!(VCS_CP_UNMUTE_RELATIVE_VOL_UP, 0x03);
        assert_eq!(VCS_CP_SET_ABSOLUTE_VOL, 0x04);
        assert_eq!(VCS_CP_UNMUTE, 0x05);
        assert_eq!(VCS_CP_MUTE, 0x06);
    }

    // ---- Volume State Tests (from test-vcp.c VCS operations) ----

    #[test]
    fn test_volume_state_parse() {
        // Volume=100, Mute=0, Change_Counter=5
        let data = [100, 0, 5];
        let state = VolumeState::from_bytes(&data).unwrap();
        assert_eq!(state.volume, 100);
        assert_eq!(state.mute, 0);
        assert_eq!(state.change_counter, 5);
    }

    #[test]
    fn test_volume_state_roundtrip() {
        let state = VolumeState { volume: 200, mute: 1, change_counter: 42 };
        let bytes = state.to_bytes();
        let parsed = VolumeState::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn test_volume_state_parse_too_short() {
        assert!(VolumeState::from_bytes(&[]).is_none());
        assert!(VolumeState::from_bytes(&[100]).is_none());
        assert!(VolumeState::from_bytes(&[100, 0]).is_none());
    }

    #[test]
    fn test_volume_state_boundaries() {
        // Min values
        let min = VolumeState { volume: 0, mute: 0, change_counter: 0 };
        assert_eq!(min.to_bytes(), [0, 0, 0]);
        // Max values
        let max = VolumeState { volume: 255, mute: 1, change_counter: 255 };
        assert_eq!(max.to_bytes(), [255, 1, 255]);
    }

    // ---- VCS CP PDU Tests (from test-vcp.c CP operations) ----

    #[test]
    fn test_vcs_cp_set_absolute_volume() {
        let pdu = VcsCpPdu::set_absolute_volume(5, 128);
        let bytes = pdu.to_bytes();
        assert_eq!(bytes, [0x04, 0x05, 0x80]);
        let parsed = VcsCpPdu::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, pdu);
    }

    #[test]
    fn test_vcs_cp_mute() {
        let pdu = VcsCpPdu::mute(10);
        let bytes = pdu.to_bytes();
        assert_eq!(bytes, [0x06, 0x0A]);
        let parsed = VcsCpPdu::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.opcode, VCS_CP_MUTE);
        assert_eq!(parsed.change_counter, 10);
        assert_eq!(parsed.param, None);
    }

    #[test]
    fn test_vcs_cp_unmute() {
        let pdu = VcsCpPdu::unmute(7);
        let bytes = pdu.to_bytes();
        assert_eq!(bytes, [0x05, 0x07]);
        let parsed = VcsCpPdu::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.opcode, VCS_CP_UNMUTE);
    }

    #[test]
    fn test_vcs_cp_relative_vol_down() {
        let pdu = VcsCpPdu::relative_vol_down(3);
        let bytes = pdu.to_bytes();
        assert_eq!(bytes, [0x00, 0x03]);
    }

    #[test]
    fn test_vcs_cp_relative_vol_up() {
        let pdu = VcsCpPdu::relative_vol_up(3);
        let bytes = pdu.to_bytes();
        assert_eq!(bytes, [0x01, 0x03]);
    }

    #[test]
    fn test_vcs_cp_unmute_relative_vol_down() {
        let pdu = VcsCpPdu::unmute_relative_vol_down(1);
        let bytes = pdu.to_bytes();
        assert_eq!(bytes, [0x02, 0x01]);
    }

    #[test]
    fn test_vcs_cp_unmute_relative_vol_up() {
        let pdu = VcsCpPdu::unmute_relative_vol_up(1);
        let bytes = pdu.to_bytes();
        assert_eq!(bytes, [0x03, 0x01]);
    }

    #[test]
    fn test_vcs_cp_parse_too_short() {
        assert!(VcsCpPdu::from_bytes(&[]).is_none());
        assert!(VcsCpPdu::from_bytes(&[0x04]).is_none());
        // Set Absolute Volume needs 3 bytes
        assert!(VcsCpPdu::from_bytes(&[0x04, 0x00]).is_none());
    }

    // ---- VOCS Offset State Tests (from test-vcp.c VOCS tests) ----

    #[test]
    fn test_vocs_offset_state_parse() {
        // Offset=0, Counter=0
        let data = [0x00, 0x00, 0x00];
        let state = VocsOffsetState::from_bytes(&data).unwrap();
        assert_eq!(state.offset, 0);
        assert_eq!(state.change_counter, 0);
    }

    #[test]
    fn test_vocs_offset_state_positive() {
        let state = VocsOffsetState { offset: 100, change_counter: 1 };
        let bytes = state.to_bytes();
        let parsed = VocsOffsetState::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn test_vocs_offset_state_negative() {
        let state = VocsOffsetState { offset: -50, change_counter: 2 };
        let bytes = state.to_bytes();
        let parsed = VocsOffsetState::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, state);
        assert_eq!(parsed.offset, -50);
    }

    #[test]
    fn test_vocs_offset_state_boundaries() {
        // Min offset -255
        let neg = VocsOffsetState { offset: -255, change_counter: 0 };
        let bytes = neg.to_bytes();
        let parsed = VocsOffsetState::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.offset, -255);

        // Max offset +255
        let pos = VocsOffsetState { offset: 255, change_counter: 255 };
        let bytes = pos.to_bytes();
        let parsed = VocsOffsetState::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.offset, 255);
    }

    #[test]
    fn test_vocs_offset_state_too_short() {
        assert!(VocsOffsetState::from_bytes(&[]).is_none());
        assert!(VocsOffsetState::from_bytes(&[0x00, 0x00]).is_none());
    }
}
