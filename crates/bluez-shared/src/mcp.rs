// SPDX-License-Identifier: GPL-2.0-or-later
//
// Media Control Profile (MCP) definitions replacing src/shared/mcp.c

pub const GMCS_UUID: u16 = 0x1849;
pub const MCS_UUID: u16 = 0x1848;

// MCS Characteristic UUIDs
pub const MCS_PLAYER_NAME_UUID: u16 = 0x2B93;
pub const MCS_TRACK_CHANGED_UUID: u16 = 0x2B96;
pub const MCS_TRACK_TITLE_UUID: u16 = 0x2B97;
pub const MCS_TRACK_DURATION_UUID: u16 = 0x2B98;
pub const MCS_TRACK_POSITION_UUID: u16 = 0x2B99;
pub const MCS_PLAYBACK_SPEED_UUID: u16 = 0x2B9A;
pub const MCS_SEEKING_SPEED_UUID: u16 = 0x2B9B;
pub const MCS_PLAYING_ORDER_UUID: u16 = 0x2BA1;
pub const MCS_PLAYING_ORDER_SUP_UUID: u16 = 0x2BA2;
pub const MCS_MEDIA_STATE_UUID: u16 = 0x2BA3;
pub const MCS_MEDIA_CP_UUID: u16 = 0x2BA4;
pub const MCS_MEDIA_CP_OP_SUP_UUID: u16 = 0x2BA5;
pub const MCS_CONTENT_CTRL_ID_UUID: u16 = 0x2BBA;

// Media State values
pub const MCS_MEDIA_STATE_INACTIVE: u8 = 0x00;
pub const MCS_MEDIA_STATE_PLAYING: u8 = 0x01;
pub const MCS_MEDIA_STATE_PAUSED: u8 = 0x02;
pub const MCS_MEDIA_STATE_SEEKING: u8 = 0x03;

// Media CP Opcodes
pub const MCS_CP_PLAY: u8 = 0x01;
pub const MCS_CP_PAUSE: u8 = 0x02;
pub const MCS_CP_FAST_REWIND: u8 = 0x03;
pub const MCS_CP_FAST_FORWARD: u8 = 0x04;
pub const MCS_CP_STOP: u8 = 0x05;
pub const MCS_CP_MOVE_RELATIVE: u8 = 0x10;
pub const MCS_CP_PREV_SEGMENT: u8 = 0x20;
pub const MCS_CP_NEXT_SEGMENT: u8 = 0x21;
pub const MCS_CP_FIRST_SEGMENT: u8 = 0x22;
pub const MCS_CP_LAST_SEGMENT: u8 = 0x23;
pub const MCS_CP_GOTO_SEGMENT: u8 = 0x24;
pub const MCS_CP_PREV_TRACK: u8 = 0x30;
pub const MCS_CP_NEXT_TRACK: u8 = 0x31;
pub const MCS_CP_FIRST_TRACK: u8 = 0x32;
pub const MCS_CP_LAST_TRACK: u8 = 0x33;
pub const MCS_CP_GOTO_TRACK: u8 = 0x34;
pub const MCS_CP_PREV_GROUP: u8 = 0x40;
pub const MCS_CP_NEXT_GROUP: u8 = 0x41;
pub const MCS_CP_FIRST_GROUP: u8 = 0x42;
pub const MCS_CP_LAST_GROUP: u8 = 0x43;
pub const MCS_CP_GOTO_GROUP: u8 = 0x44;

// Media CP Result Codes
pub const MCS_CP_RESULT_SUCCESS: u8 = 0x01;
pub const MCS_CP_RESULT_NOT_SUPPORTED: u8 = 0x02;
pub const MCS_CP_RESULT_PLAYER_INACTIVE: u8 = 0x03;
pub const MCS_CP_RESULT_CANNOT_BE_COMPLETED: u8 = 0x04;

// Playing Order values
pub const MCS_PLAYING_ORDER_SINGLE_ONCE: u8 = 0x01;
pub const MCS_PLAYING_ORDER_SINGLE_REPEAT: u8 = 0x02;
pub const MCS_PLAYING_ORDER_IN_ORDER_ONCE: u8 = 0x03;
pub const MCS_PLAYING_ORDER_IN_ORDER_REPEAT: u8 = 0x04;
pub const MCS_PLAYING_ORDER_OLDEST_ONCE: u8 = 0x05;
pub const MCS_PLAYING_ORDER_OLDEST_REPEAT: u8 = 0x06;
pub const MCS_PLAYING_ORDER_NEWEST_ONCE: u8 = 0x07;
pub const MCS_PLAYING_ORDER_NEWEST_REPEAT: u8 = 0x08;
pub const MCS_PLAYING_ORDER_SHUFFLE_ONCE: u8 = 0x09;
pub const MCS_PLAYING_ORDER_SHUFFLE_REPEAT: u8 = 0x0A;

// Playing Order Supported bitmask
pub const MCS_PLAYING_ORDER_SUPP_SINGLE_ONCE: u16 = 0x0001;
pub const MCS_PLAYING_ORDER_SUPP_SINGLE_REPEAT: u16 = 0x0002;
pub const MCS_PLAYING_ORDER_SUPP_IN_ORDER_ONCE: u16 = 0x0004;
pub const MCS_PLAYING_ORDER_SUPP_IN_ORDER_REPEAT: u16 = 0x0008;
pub const MCS_PLAYING_ORDER_SUPP_OLDEST_ONCE: u16 = 0x0010;
pub const MCS_PLAYING_ORDER_SUPP_OLDEST_REPEAT: u16 = 0x0020;

// Supported opcodes bitmask
pub const MCS_OP_SUPP_PLAY: u32 = 0x00000001;
pub const MCS_OP_SUPP_PAUSE: u32 = 0x00000002;
pub const MCS_OP_SUPP_FAST_REWIND: u32 = 0x00000004;
pub const MCS_OP_SUPP_FAST_FORWARD: u32 = 0x00000008;
pub const MCS_OP_SUPP_STOP: u32 = 0x00000010;
pub const MCS_OP_SUPP_MOVE_RELATIVE: u32 = 0x00000020;
pub const MCS_OP_SUPP_PREV_SEGMENT: u32 = 0x00000040;
pub const MCS_OP_SUPP_NEXT_SEGMENT: u32 = 0x00000080;
pub const MCS_OP_SUPP_FIRST_SEGMENT: u32 = 0x00000100;
pub const MCS_OP_SUPP_LAST_SEGMENT: u32 = 0x00000200;
pub const MCS_OP_SUPP_GOTO_SEGMENT: u32 = 0x00000400;
pub const MCS_OP_SUPP_PREV_TRACK: u32 = 0x00000800;
pub const MCS_OP_SUPP_NEXT_TRACK: u32 = 0x00001000;
pub const MCS_OP_SUPP_FIRST_TRACK: u32 = 0x00002000;
pub const MCS_OP_SUPP_LAST_TRACK: u32 = 0x00004000;
pub const MCS_OP_SUPP_GOTO_TRACK: u32 = 0x00008000;
pub const MCS_OP_SUPP_PREV_GROUP: u32 = 0x00010000;
pub const MCS_OP_SUPP_NEXT_GROUP: u32 = 0x00020000;
pub const MCS_OP_SUPP_FIRST_GROUP: u32 = 0x00040000;
pub const MCS_OP_SUPP_LAST_GROUP: u32 = 0x00080000;
pub const MCS_OP_SUPP_GOTO_GROUP: u32 = 0x00100000;

/// Media state enum for type-safe usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaState {
    Inactive,
    Playing,
    Paused,
    Seeking,
}

impl MediaState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            MCS_MEDIA_STATE_INACTIVE => Some(Self::Inactive),
            MCS_MEDIA_STATE_PLAYING => Some(Self::Playing),
            MCS_MEDIA_STATE_PAUSED => Some(Self::Paused),
            MCS_MEDIA_STATE_SEEKING => Some(Self::Seeking),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Inactive => MCS_MEDIA_STATE_INACTIVE,
            Self::Playing => MCS_MEDIA_STATE_PLAYING,
            Self::Paused => MCS_MEDIA_STATE_PAUSED,
            Self::Seeking => MCS_MEDIA_STATE_SEEKING,
        }
    }
}

/// Validate a media control point state transition.
/// Returns true if the given opcode is valid for the current state.
pub fn is_valid_cp_for_state(state: MediaState, opcode: u8) -> bool {
    match state {
        MediaState::Inactive => matches!(opcode, MCS_CP_PLAY | MCS_CP_STOP),
        MediaState::Playing => matches!(
            opcode,
            MCS_CP_PAUSE
                | MCS_CP_FAST_REWIND
                | MCS_CP_FAST_FORWARD
                | MCS_CP_STOP
                | MCS_CP_MOVE_RELATIVE
                | MCS_CP_PREV_SEGMENT
                | MCS_CP_NEXT_SEGMENT
                | MCS_CP_FIRST_SEGMENT
                | MCS_CP_LAST_SEGMENT
                | MCS_CP_GOTO_SEGMENT
                | MCS_CP_PREV_TRACK
                | MCS_CP_NEXT_TRACK
                | MCS_CP_FIRST_TRACK
                | MCS_CP_LAST_TRACK
                | MCS_CP_GOTO_TRACK
                | MCS_CP_PREV_GROUP
                | MCS_CP_NEXT_GROUP
                | MCS_CP_FIRST_GROUP
                | MCS_CP_LAST_GROUP
                | MCS_CP_GOTO_GROUP
        ),
        MediaState::Paused => matches!(
            opcode,
            MCS_CP_PLAY
                | MCS_CP_FAST_REWIND
                | MCS_CP_FAST_FORWARD
                | MCS_CP_STOP
                | MCS_CP_MOVE_RELATIVE
                | MCS_CP_PREV_SEGMENT
                | MCS_CP_NEXT_SEGMENT
                | MCS_CP_FIRST_SEGMENT
                | MCS_CP_LAST_SEGMENT
                | MCS_CP_GOTO_SEGMENT
                | MCS_CP_PREV_TRACK
                | MCS_CP_NEXT_TRACK
                | MCS_CP_FIRST_TRACK
                | MCS_CP_LAST_TRACK
                | MCS_CP_GOTO_TRACK
                | MCS_CP_PREV_GROUP
                | MCS_CP_NEXT_GROUP
                | MCS_CP_FIRST_GROUP
                | MCS_CP_LAST_GROUP
                | MCS_CP_GOTO_GROUP
        ),
        MediaState::Seeking => matches!(
            opcode,
            MCS_CP_PLAY
                | MCS_CP_PAUSE
                | MCS_CP_STOP
                | MCS_CP_FAST_REWIND
                | MCS_CP_FAST_FORWARD
        ),
    }
}

/// Check if an opcode is supported given the supported opcodes bitmask.
pub fn is_opcode_supported(supported: u32, opcode: u8) -> bool {
    let bit = match opcode {
        MCS_CP_PLAY => MCS_OP_SUPP_PLAY,
        MCS_CP_PAUSE => MCS_OP_SUPP_PAUSE,
        MCS_CP_FAST_REWIND => MCS_OP_SUPP_FAST_REWIND,
        MCS_CP_FAST_FORWARD => MCS_OP_SUPP_FAST_FORWARD,
        MCS_CP_STOP => MCS_OP_SUPP_STOP,
        MCS_CP_MOVE_RELATIVE => MCS_OP_SUPP_MOVE_RELATIVE,
        MCS_CP_PREV_SEGMENT => MCS_OP_SUPP_PREV_SEGMENT,
        MCS_CP_NEXT_SEGMENT => MCS_OP_SUPP_NEXT_SEGMENT,
        MCS_CP_FIRST_SEGMENT => MCS_OP_SUPP_FIRST_SEGMENT,
        MCS_CP_LAST_SEGMENT => MCS_OP_SUPP_LAST_SEGMENT,
        MCS_CP_GOTO_SEGMENT => MCS_OP_SUPP_GOTO_SEGMENT,
        MCS_CP_PREV_TRACK => MCS_OP_SUPP_PREV_TRACK,
        MCS_CP_NEXT_TRACK => MCS_OP_SUPP_NEXT_TRACK,
        MCS_CP_FIRST_TRACK => MCS_OP_SUPP_FIRST_TRACK,
        MCS_CP_LAST_TRACK => MCS_OP_SUPP_LAST_TRACK,
        MCS_CP_GOTO_TRACK => MCS_OP_SUPP_GOTO_TRACK,
        MCS_CP_PREV_GROUP => MCS_OP_SUPP_PREV_GROUP,
        MCS_CP_NEXT_GROUP => MCS_OP_SUPP_NEXT_GROUP,
        MCS_CP_FIRST_GROUP => MCS_OP_SUPP_FIRST_GROUP,
        MCS_CP_LAST_GROUP => MCS_OP_SUPP_LAST_GROUP,
        MCS_CP_GOTO_GROUP => MCS_OP_SUPP_GOTO_GROUP,
        _ => return false,
    };
    (supported & bit) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- UUID Tests (from test-mcp.c SGGIT tests) ----

    #[test]
    fn test_mcs_uuids() {
        assert_eq!(GMCS_UUID, 0x1849);
        assert_eq!(MCS_UUID, 0x1848);
    }

    #[test]
    fn test_mcs_characteristic_uuids() {
        assert_eq!(MCS_PLAYER_NAME_UUID, 0x2B93);
        assert_eq!(MCS_TRACK_CHANGED_UUID, 0x2B96);
        assert_eq!(MCS_TRACK_TITLE_UUID, 0x2B97);
        assert_eq!(MCS_TRACK_DURATION_UUID, 0x2B98);
        assert_eq!(MCS_TRACK_POSITION_UUID, 0x2B99);
        assert_eq!(MCS_PLAYBACK_SPEED_UUID, 0x2B9A);
        assert_eq!(MCS_SEEKING_SPEED_UUID, 0x2B9B);
        assert_eq!(MCS_PLAYING_ORDER_UUID, 0x2BA1);
        assert_eq!(MCS_PLAYING_ORDER_SUP_UUID, 0x2BA2);
        assert_eq!(MCS_MEDIA_STATE_UUID, 0x2BA3);
        assert_eq!(MCS_MEDIA_CP_UUID, 0x2BA4);
        assert_eq!(MCS_MEDIA_CP_OP_SUP_UUID, 0x2BA5);
        assert_eq!(MCS_CONTENT_CTRL_ID_UUID, 0x2BBA);
    }

    // ---- Media State Tests (from test-mcp.c state transitions) ----

    #[test]
    fn test_media_state_values() {
        assert_eq!(MCS_MEDIA_STATE_INACTIVE, 0x00);
        assert_eq!(MCS_MEDIA_STATE_PLAYING, 0x01);
        assert_eq!(MCS_MEDIA_STATE_PAUSED, 0x02);
        assert_eq!(MCS_MEDIA_STATE_SEEKING, 0x03);
    }

    #[test]
    fn test_media_state_from_u8() {
        assert_eq!(MediaState::from_u8(0x00), Some(MediaState::Inactive));
        assert_eq!(MediaState::from_u8(0x01), Some(MediaState::Playing));
        assert_eq!(MediaState::from_u8(0x02), Some(MediaState::Paused));
        assert_eq!(MediaState::from_u8(0x03), Some(MediaState::Seeking));
        assert_eq!(MediaState::from_u8(0x04), None);
        assert_eq!(MediaState::from_u8(0xFF), None);
    }

    #[test]
    fn test_media_state_roundtrip() {
        for val in 0..=3u8 {
            let state = MediaState::from_u8(val).unwrap();
            assert_eq!(state.as_u8(), val);
        }
    }

    // ---- CP Opcode Tests ----

    #[test]
    fn test_cp_opcodes() {
        assert_eq!(MCS_CP_PLAY, 0x01);
        assert_eq!(MCS_CP_PAUSE, 0x02);
        assert_eq!(MCS_CP_FAST_REWIND, 0x03);
        assert_eq!(MCS_CP_FAST_FORWARD, 0x04);
        assert_eq!(MCS_CP_STOP, 0x05);
        assert_eq!(MCS_CP_MOVE_RELATIVE, 0x10);
        assert_eq!(MCS_CP_PREV_TRACK, 0x30);
        assert_eq!(MCS_CP_NEXT_TRACK, 0x31);
        assert_eq!(MCS_CP_GOTO_TRACK, 0x34);
        assert_eq!(MCS_CP_GOTO_GROUP, 0x44);
    }

    // ---- Player State Transition Tests (from test-mcp.c MCS/SR/MCP/* tests) ----

    #[test]
    fn test_play_from_paused() {
        // MCS/SR/MCP/BV-01-C: Play from Paused
        assert!(is_valid_cp_for_state(MediaState::Paused, MCS_CP_PLAY));
    }

    #[test]
    fn test_play_from_seeking() {
        // MCS/SR/MCP/BV-02-C: Play from Seeking
        assert!(is_valid_cp_for_state(MediaState::Seeking, MCS_CP_PLAY));
    }

    #[test]
    fn test_play_from_inactive() {
        // MCS/SR/MCP/BV-70-C: Play from Inactive
        assert!(is_valid_cp_for_state(MediaState::Inactive, MCS_CP_PLAY));
    }

    #[test]
    fn test_pause_from_playing() {
        // MCS/SR/MCP/BV-03-C: Pause from Playing
        assert!(is_valid_cp_for_state(MediaState::Playing, MCS_CP_PAUSE));
    }

    #[test]
    fn test_pause_from_seeking() {
        // MCS/SR/MCP/BV-04-C: Pause from Seeking
        assert!(is_valid_cp_for_state(MediaState::Seeking, MCS_CP_PAUSE));
    }

    #[test]
    fn test_pause_from_inactive_not_valid() {
        // MCS/SR/MCP/BV-71-C: Pause from Inactive should not be valid
        assert!(!is_valid_cp_for_state(MediaState::Inactive, MCS_CP_PAUSE));
    }

    #[test]
    fn test_stop_from_playing() {
        // MCS/SR/MCP/BV-09-C: Stop from Playing
        assert!(is_valid_cp_for_state(MediaState::Playing, MCS_CP_STOP));
    }

    #[test]
    fn test_stop_from_paused() {
        // MCS/SR/MCP/BV-10-C: Stop from Paused
        assert!(is_valid_cp_for_state(MediaState::Paused, MCS_CP_STOP));
    }

    #[test]
    fn test_stop_from_seeking() {
        // MCS/SR/MCP/BV-11-C: Stop from Seeking
        assert!(is_valid_cp_for_state(MediaState::Seeking, MCS_CP_STOP));
    }

    #[test]
    fn test_stop_from_inactive() {
        // MCS/SR/MCP/BV-74-C: Stop from Inactive
        assert!(is_valid_cp_for_state(MediaState::Inactive, MCS_CP_STOP));
    }

    // ---- Supported Opcodes Tests (from test-mcp.c CGGIT tests) ----

    #[test]
    fn test_all_opcodes_supported() {
        // From test-mcp.c: CGGIT uses 0x001fffff as all-supported mask
        let all_supported: u32 = 0x001FFFFF;
        assert!(is_opcode_supported(all_supported, MCS_CP_PLAY));
        assert!(is_opcode_supported(all_supported, MCS_CP_PAUSE));
        assert!(is_opcode_supported(all_supported, MCS_CP_FAST_REWIND));
        assert!(is_opcode_supported(all_supported, MCS_CP_FAST_FORWARD));
        assert!(is_opcode_supported(all_supported, MCS_CP_STOP));
        assert!(is_opcode_supported(all_supported, MCS_CP_MOVE_RELATIVE));
        assert!(is_opcode_supported(all_supported, MCS_CP_PREV_TRACK));
        assert!(is_opcode_supported(all_supported, MCS_CP_NEXT_TRACK));
        assert!(is_opcode_supported(all_supported, MCS_CP_GOTO_TRACK));
        assert!(is_opcode_supported(all_supported, MCS_CP_GOTO_GROUP));
    }

    #[test]
    fn test_no_opcodes_supported() {
        let none_supported: u32 = 0x00000000;
        assert!(!is_opcode_supported(none_supported, MCS_CP_PLAY));
        assert!(!is_opcode_supported(none_supported, MCS_CP_STOP));
    }

    #[test]
    fn test_partial_opcodes_supported() {
        // Only Play and Pause
        let partial = MCS_OP_SUPP_PLAY | MCS_OP_SUPP_PAUSE;
        assert!(is_opcode_supported(partial, MCS_CP_PLAY));
        assert!(is_opcode_supported(partial, MCS_CP_PAUSE));
        assert!(!is_opcode_supported(partial, MCS_CP_STOP));
        assert!(!is_opcode_supported(partial, MCS_CP_FAST_FORWARD));
    }

    #[test]
    fn test_unknown_opcode_not_supported() {
        let all: u32 = 0xFFFFFFFF;
        assert!(!is_opcode_supported(all, 0x00)); // Invalid opcode
        assert!(!is_opcode_supported(all, 0xFF)); // Invalid opcode
    }

    // ---- Playing Order Tests ----

    #[test]
    fn test_playing_order_values() {
        // From test-mcp.c: initial play order = 0x04 (in order repeat)
        assert_eq!(MCS_PLAYING_ORDER_IN_ORDER_REPEAT, 0x04);
        assert_eq!(MCS_PLAYING_ORDER_OLDEST_ONCE, 0x05);
    }

    #[test]
    fn test_playing_order_supported_bitmask() {
        // From test-mcp.c: 0x0018 = in order repeat + oldest once
        let supp = MCS_PLAYING_ORDER_SUPP_IN_ORDER_REPEAT
            | MCS_PLAYING_ORDER_SUPP_OLDEST_ONCE;
        assert_eq!(supp, 0x0018);
    }

    // ---- Result Code Tests ----

    #[test]
    fn test_cp_result_codes() {
        assert_eq!(MCS_CP_RESULT_SUCCESS, 0x01);
        assert_eq!(MCS_CP_RESULT_NOT_SUPPORTED, 0x02);
        assert_eq!(MCS_CP_RESULT_PLAYER_INACTIVE, 0x03);
        assert_eq!(MCS_CP_RESULT_CANNOT_BE_COMPLETED, 0x04);
    }

    // ---- Track Position Tests (from test-mcp.c CGGIT_CHA_BV_07_C) ----

    #[test]
    fn test_track_position_encoding() {
        // -777 in i32 LE: 0xf7fcffff
        let pos: i32 = -777;
        let bytes = pos.to_le_bytes();
        assert_eq!(bytes, [0xf7, 0xfc, 0xff, 0xff]);
        let decoded = i32::from_le_bytes(bytes);
        assert_eq!(decoded, -777);
    }

    #[test]
    fn test_track_position_unavailable() {
        // 0xffffffff as i32 = -1, used for "unavailable"
        let unavail = i32::from_le_bytes([0xff, 0xff, 0xff, 0xff]);
        assert_eq!(unavail, -1);
    }

    #[test]
    fn test_track_duration_unavailable() {
        // 0xffffffff as i32 = -1, used for "unknown"
        let unknown = i32::from_le_bytes([0xff, 0xff, 0xff, 0xff]);
        assert_eq!(unknown, -1);
    }

    // ---- Playback Speed Tests (from test-mcp.c CGGIT_CHA_BV_08_C) ----

    #[test]
    fn test_playback_speed_encoding() {
        // Speed is i8, 0x07 = slightly faster than 1x
        let speed: i8 = 0x07;
        assert_eq!(speed, 7);
        // Default speed
        let default_speed: i8 = 0x00;
        assert_eq!(default_speed, 0);
    }
}
