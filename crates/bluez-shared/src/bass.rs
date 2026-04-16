// SPDX-License-Identifier: GPL-2.0-or-later
//
// Broadcast Audio Scan Service (BASS) definitions replacing src/shared/bass.c
//
// BASS allows a client to control broadcast audio reception on a server.

// ---- BASS UUIDs ----

pub const BASS_UUID: u16 = 0x184F;
pub const BCAST_AUDIO_SCAN_CP_UUID: u16 = 0x2BC7;
pub const BCAST_RECV_STATE_UUID: u16 = 0x2BC8;

// ---- BASS Control Point Opcodes ----

pub const BASS_CP_REMOTE_SCAN_STOP: u8 = 0x00;
pub const BASS_CP_REMOTE_SCAN_START: u8 = 0x01;
pub const BASS_CP_ADD_SOURCE: u8 = 0x02;
pub const BASS_CP_MODIFY_SOURCE: u8 = 0x03;
pub const BASS_CP_SET_BCAST_CODE: u8 = 0x04;
pub const BASS_CP_REMOVE_SOURCE: u8 = 0x05;

// ---- BIG Encryption States ----

pub const BASS_BIG_ENC_NOT_ENCRYPTED: u8 = 0x00;
pub const BASS_BIG_ENC_BCAST_CODE_REQUIRED: u8 = 0x01;
pub const BASS_BIG_ENC_DECRYPTING: u8 = 0x02;
pub const BASS_BIG_ENC_BAD_CODE: u8 = 0x03;

// ---- PA Sync States ----

pub const BASS_PA_NOT_SYNCED: u8 = 0x00;
pub const BASS_PA_SYNC_INFO_REQ: u8 = 0x01;
pub const BASS_PA_SYNCED: u8 = 0x02;
pub const BASS_PA_FAILED: u8 = 0x03;
pub const BASS_PA_NO_PAST: u8 = 0x04;

/// Broadcast Receive State.
#[derive(Debug, Clone)]
pub struct BcastRecvState {
    /// Source ID.
    pub source_id: u8,
    /// Advertiser address type.
    pub addr_type: u8,
    /// Advertiser address (6 bytes).
    pub addr: [u8; 6],
    /// Advertising SID.
    pub adv_sid: u8,
    /// Broadcast ID (3 bytes LE).
    pub broadcast_id: u32,
    /// PA sync state.
    pub pa_sync_state: u8,
    /// BIG encryption state.
    pub big_encryption: u8,
    /// Bad broadcast code (16 bytes, if big_encryption == BAD_CODE).
    pub bad_code: Option<[u8; 16]>,
    /// Number of subgroups.
    pub num_subgroups: u8,
}

// ---- BASS Error Codes (ATT application errors) ----

pub const BASS_ERROR_OPCODE_NOT_SUPPORTED: u8 = 0x80;
pub const BASS_ERROR_INVALID_SOURCE_ID: u8 = 0x81;
pub const BASS_ERROR_WRITE_REQUEST_REJECTED: u8 = 0xFC;

// ---- Add Source PDU ----

/// BASS Add Source operation parameters.
#[derive(Debug, Clone)]
pub struct BassAddSource {
    /// Advertiser address type.
    pub addr_type: u8,
    /// Advertiser address (6 bytes).
    pub addr: [u8; 6],
    /// Advertising SID.
    pub adv_sid: u8,
    /// Broadcast ID (24-bit, stored in low 3 bytes).
    pub broadcast_id: u32,
    /// PA Sync value.
    pub pa_sync: u8,
    /// PA Interval.
    pub pa_interval: u16,
    /// Subgroup BIS sync configurations.
    pub subgroups: Vec<BassSubgroup>,
}

/// BASS subgroup configuration for Add/Modify Source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BassSubgroup {
    /// BIS sync bitmask (4 bytes).
    pub bis_sync: u32,
    /// Metadata.
    pub metadata: Vec<u8>,
}

impl BassAddSource {
    /// Encode to bytes (opcode 0x02 prefix NOT included).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.addr_type);
        out.extend_from_slice(&self.addr);
        out.push(self.adv_sid);
        // Broadcast ID is 3 bytes LE
        out.push((self.broadcast_id & 0xFF) as u8);
        out.push(((self.broadcast_id >> 8) & 0xFF) as u8);
        out.push(((self.broadcast_id >> 16) & 0xFF) as u8);
        out.push(self.pa_sync);
        out.extend_from_slice(&self.pa_interval.to_le_bytes());
        out.push(self.subgroups.len() as u8);
        for sg in &self.subgroups {
            out.extend_from_slice(&sg.bis_sync.to_le_bytes());
            out.push(sg.metadata.len() as u8);
            out.extend_from_slice(&sg.metadata);
        }
        out
    }

    /// Parse from bytes (after opcode byte has been stripped).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 15 {
            return None;
        }
        let addr_type = data[0];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[1..7]);
        let adv_sid = data[7];
        let broadcast_id = data[8] as u32
            | ((data[9] as u32) << 8)
            | ((data[10] as u32) << 16);
        let pa_sync = data[11];
        let pa_interval = u16::from_le_bytes([data[12], data[13]]);
        let num_subgroups = data[14] as usize;

        let mut pos = 15;
        let mut subgroups = Vec::new();
        for _ in 0..num_subgroups {
            if pos + 5 > data.len() {
                return None;
            }
            let bis_sync = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let meta_len = data[pos + 4] as usize;
            pos += 5;
            if pos + meta_len > data.len() {
                return None;
            }
            let metadata = data[pos..pos + meta_len].to_vec();
            pos += meta_len;
            subgroups.push(BassSubgroup { bis_sync, metadata });
        }

        Some(Self {
            addr_type,
            addr,
            adv_sid,
            broadcast_id,
            pa_sync,
            pa_interval,
            subgroups,
        })
    }
}

/// Validate a PA Sync value per BASS spec.
pub fn is_valid_pa_sync(pa_sync: u8) -> bool {
    pa_sync <= 0x02 || pa_sync == 0x04
}

/// Validate an address type per BASS spec.
pub fn is_valid_addr_type(addr_type: u8) -> bool {
    addr_type <= 0x01
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Opcode Tests (from test-bass.c) ----

    #[test]
    fn test_bass_opcodes() {
        assert_eq!(BASS_CP_REMOTE_SCAN_STOP, 0x00);
        assert_eq!(BASS_CP_REMOTE_SCAN_START, 0x01);
        assert_eq!(BASS_CP_ADD_SOURCE, 0x02);
        assert_eq!(BASS_CP_MODIFY_SOURCE, 0x03);
        assert_eq!(BASS_CP_SET_BCAST_CODE, 0x04);
        assert_eq!(BASS_CP_REMOVE_SOURCE, 0x05);
    }

    // ---- PA Sync State Tests ----

    #[test]
    fn test_pa_sync_states() {
        assert_eq!(BASS_PA_NOT_SYNCED, 0x00);
        assert_eq!(BASS_PA_SYNC_INFO_REQ, 0x01);
        assert_eq!(BASS_PA_SYNCED, 0x02);
        assert_eq!(BASS_PA_FAILED, 0x03);
        assert_eq!(BASS_PA_NO_PAST, 0x04);
    }

    // ---- BIG Encryption Tests ----

    #[test]
    fn test_big_encryption_states() {
        assert_eq!(BASS_BIG_ENC_NOT_ENCRYPTED, 0x00);
        assert_eq!(BASS_BIG_ENC_BCAST_CODE_REQUIRED, 0x01);
        assert_eq!(BASS_BIG_ENC_DECRYPTING, 0x02);
        assert_eq!(BASS_BIG_ENC_BAD_CODE, 0x03);
    }

    // ---- Error Code Tests (from test-bass.c OPCODE_NOT_SUPPORTED, INVALID_SRC_ID) ----

    #[test]
    fn test_bass_error_codes() {
        assert_eq!(BASS_ERROR_OPCODE_NOT_SUPPORTED, 0x80);
        assert_eq!(BASS_ERROR_INVALID_SOURCE_ID, 0x81);
        assert_eq!(BASS_ERROR_WRITE_REQUEST_REJECTED, 0xFC);
    }

    // ---- UUID Tests (from test-bass.c SGGIT discovery) ----

    #[test]
    fn test_bass_uuids() {
        assert_eq!(BASS_UUID, 0x184F);
        assert_eq!(BCAST_AUDIO_SCAN_CP_UUID, 0x2BC7);
        assert_eq!(BCAST_RECV_STATE_UUID, 0x2BC8);
    }

    // ---- Broadcast Receive State Tests ----

    #[test]
    fn test_recv_state_default() {
        let state = BcastRecvState {
            source_id: 0,
            addr_type: 0,
            addr: [0; 6],
            adv_sid: 0,
            broadcast_id: 0,
            pa_sync_state: BASS_PA_NOT_SYNCED,
            big_encryption: BASS_BIG_ENC_NOT_ENCRYPTED,
            bad_code: None,
            num_subgroups: 0,
        };
        assert_eq!(state.source_id, 0);
        assert_eq!(state.pa_sync_state, 0);
        assert!(state.bad_code.is_none());
    }

    #[test]
    fn test_recv_state_with_bad_code() {
        let code = [0x55, 0x54, 0x27, 0x73, 0x70, 0x59, 0x65, 0x34,
                    0x61, 0x26, 0x55, 0x68, 0x72, 0x45, 0x3c, 0x69];
        let state = BcastRecvState {
            source_id: 1,
            addr_type: 0,
            addr: [0xC0, 0x07, 0xE8, 0x8B, 0x69, 0xF2],
            adv_sid: 0,
            broadcast_id: 0x001234,
            pa_sync_state: BASS_PA_SYNCED,
            big_encryption: BASS_BIG_ENC_BAD_CODE,
            bad_code: Some(code),
            num_subgroups: 0,
        };
        assert_eq!(state.big_encryption, BASS_BIG_ENC_BAD_CODE);
        assert_eq!(state.bad_code.unwrap()[0], 0x55);
    }

    // ---- PA Sync Validation (from test-bass.c ADD_SRC_INVALID_PARAMS) ----

    #[test]
    fn test_pa_sync_valid_values() {
        assert!(is_valid_pa_sync(0x00)); // Do not sync
        assert!(is_valid_pa_sync(0x01)); // Sync info request
        assert!(is_valid_pa_sync(0x02)); // Sync to PA (PAST not available)
        assert!(!is_valid_pa_sync(0x03)); // RFU
        assert!(is_valid_pa_sync(0x04)); // No PAST
        assert!(!is_valid_pa_sync(0x05)); // RFU
        assert!(!is_valid_pa_sync(0x06)); // RFU - matches BI-03-C test
        assert!(!is_valid_pa_sync(0xFF)); // RFU
    }

    #[test]
    fn test_addr_type_valid_values() {
        assert!(is_valid_addr_type(0x00)); // Public
        assert!(is_valid_addr_type(0x01)); // Random
        assert!(!is_valid_addr_type(0x02)); // RFU
        assert!(!is_valid_addr_type(0x05)); // RFU - matches BI-03-C test
        assert!(!is_valid_addr_type(0xFF)); // RFU
    }

    // ---- Add Source PDU Tests (from test-bass.c Add Source operations) ----

    #[test]
    fn test_add_source_encode_two_subgroups() {
        // Matches ADD_SRC_INVALID_PARAMS from test-bass.c
        let src = BassAddSource {
            addr_type: 0x00,
            addr: [0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0],
            adv_sid: 0x00,
            broadcast_id: 0x001234,
            pa_sync: 0x02,
            pa_interval: 0x2710,
            subgroups: vec![
                BassSubgroup { bis_sync: 0x00000000, metadata: vec![] },
                BassSubgroup { bis_sync: 0x00000000, metadata: vec![] },
            ],
        };
        let bytes = src.to_bytes();
        // addr_type(1) + addr(6) + sid(1) + bid(3) + pa_sync(1) + pa_interval(2)
        // + num_subgroups(1) + 2*(bis_sync(4) + meta_len(1)) = 1+6+1+3+1+2+1+10 = 25
        assert_eq!(bytes.len(), 25);
        assert_eq!(bytes[0], 0x00); // addr_type
        assert_eq!(&bytes[1..7], &[0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0]);
        assert_eq!(bytes[7], 0x00); // adv_sid
        assert_eq!(&bytes[8..11], &[0x34, 0x12, 0x00]); // broadcast_id LE
        assert_eq!(bytes[11], 0x02); // pa_sync
        assert_eq!(&bytes[12..14], &[0x10, 0x27]); // pa_interval LE
        assert_eq!(bytes[14], 0x02); // num_subgroups
    }

    #[test]
    fn test_add_source_roundtrip() {
        let src = BassAddSource {
            addr_type: 0x00,
            addr: [0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0],
            adv_sid: 0x00,
            broadcast_id: 0x001234,
            pa_sync: 0x02,
            pa_interval: 0x2710,
            subgroups: vec![
                BassSubgroup { bis_sync: 0x00000001, metadata: vec![] },
            ],
        };
        let bytes = src.to_bytes();
        let parsed = BassAddSource::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.addr_type, src.addr_type);
        assert_eq!(parsed.addr, src.addr);
        assert_eq!(parsed.adv_sid, src.adv_sid);
        assert_eq!(parsed.broadcast_id, src.broadcast_id);
        assert_eq!(parsed.pa_sync, src.pa_sync);
        assert_eq!(parsed.pa_interval, src.pa_interval);
        assert_eq!(parsed.subgroups.len(), 1);
        assert_eq!(parsed.subgroups[0].bis_sync, 0x00000001);
    }

    #[test]
    fn test_add_source_from_bytes_too_short() {
        assert!(BassAddSource::from_bytes(&[]).is_none());
        assert!(BassAddSource::from_bytes(&[0; 14]).is_none());
    }

    #[test]
    fn test_add_source_with_metadata() {
        let src = BassAddSource {
            addr_type: 0x01,
            addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            adv_sid: 0x01,
            broadcast_id: 0xABCDEF,
            pa_sync: 0x01,
            pa_interval: 0x0020,
            subgroups: vec![
                BassSubgroup {
                    bis_sync: 0x00000003,
                    metadata: vec![0x03, 0x02, 0x04, 0x00],
                },
            ],
        };
        let bytes = src.to_bytes();
        let parsed = BassAddSource::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.subgroups[0].metadata, vec![0x03, 0x02, 0x04, 0x00]);
    }

    #[test]
    fn test_recv_state_debug() {
        let state = BcastRecvState {
            source_id: 1,
            addr_type: 0,
            addr: [0; 6],
            adv_sid: 0,
            broadcast_id: 0,
            pa_sync_state: BASS_PA_NOT_SYNCED,
            big_encryption: BASS_BIG_ENC_NOT_ENCRYPTED,
            bad_code: None,
            num_subgroups: 0,
        };
        let dbg = format!("{:?}", state);
        assert!(dbg.contains("BcastRecvState"));
    }
}
