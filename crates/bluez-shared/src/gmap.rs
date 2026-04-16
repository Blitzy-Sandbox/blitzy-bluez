// SPDX-License-Identifier: GPL-2.0-or-later
//
// Gaming Audio Profile (GMAP) definitions

pub const GMAS_UUID: u16 = 0x1858;
pub const GMAP_ROLE_UUID: u16 = 0x2C00;

// GMAP Roles (bitmask)
pub const GMAP_ROLE_UGG: u8 = 0x01; // Unicast Game Gateway
pub const GMAP_ROLE_UGT: u8 = 0x02; // Unicast Game Terminal
pub const GMAP_ROLE_BGS: u8 = 0x04; // Broadcast Game Sender
pub const GMAP_ROLE_BGR: u8 = 0x08; // Broadcast Game Receiver

// GMAP Feature UUIDs
pub const GMAP_UGG_FEAT_UUID: u16 = 0x2C01;
pub const GMAP_UGT_FEAT_UUID: u16 = 0x2C02;
pub const GMAP_BGS_FEAT_UUID: u16 = 0x2C03;
pub const GMAP_BGR_FEAT_UUID: u16 = 0x2C04;

// GMAP Feature flags — from test-gmap.c
pub const GMAP_UGG_MULTIPLEX: u32 = 0x01;
pub const GMAP_UGT_SOURCE: u32 = 0x01;
pub const GMAP_BGS_96KBPS: u32 = 0x01;
pub const GMAP_BGR_MULTISINK: u32 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Role bitmask tests (from test-gmap.c) ----

    #[test]
    fn test_gmap_role_ugg() {
        assert_eq!(GMAP_ROLE_UGG, 0x01);
    }

    #[test]
    fn test_gmap_role_ugt() {
        assert_eq!(GMAP_ROLE_UGT, 0x02);
    }

    #[test]
    fn test_gmap_role_bgs() {
        assert_eq!(GMAP_ROLE_BGS, 0x04);
    }

    #[test]
    fn test_gmap_role_bgr() {
        assert_eq!(GMAP_ROLE_BGR, 0x08);
    }

    #[test]
    fn test_gmap_role_combined() {
        assert_eq!(GMAP_ROLE_UGG | GMAP_ROLE_UGT, 0x03);
        assert_eq!(GMAP_ROLE_BGS | GMAP_ROLE_BGR, 0x0C);
        assert_eq!(
            GMAP_ROLE_UGG | GMAP_ROLE_UGT | GMAP_ROLE_BGS | GMAP_ROLE_BGR,
            0x0F
        );
    }

    #[test]
    fn test_gmap_role_rfu_bits_masked() {
        // From test-gmap.c: client ignores RFU bits — e.g. role 0xF1
        // only low 4 bits carry role information
        let raw_role: u8 = 0xF1;
        let masked = raw_role & 0x0F;
        assert_eq!(masked, GMAP_ROLE_UGG);
    }

    #[test]
    fn test_gmas_uuid() {
        assert_eq!(GMAS_UUID, 0x1858);
    }

    #[test]
    fn test_gmap_feature_uuids() {
        assert_eq!(GMAP_UGG_FEAT_UUID, 0x2C01);
        assert_eq!(GMAP_UGT_FEAT_UUID, 0x2C02);
        assert_eq!(GMAP_BGS_FEAT_UUID, 0x2C03);
        assert_eq!(GMAP_BGR_FEAT_UUID, 0x2C04);
    }

    #[test]
    fn test_gmap_role_uuid() {
        assert_eq!(GMAP_ROLE_UUID, 0x2C00);
    }

    // Features flag tests from test-gmap.c config structs

    #[test]
    fn test_gmap_ugg_features_rfu_masked() {
        // From test-gmap.c: client ignores RFU bits in UGG features (0xF1 -> 0x01)
        let raw_feat: u32 = 0xF1;
        let masked = raw_feat & 0x01;
        assert_eq!(masked, GMAP_UGG_MULTIPLEX);
    }

    #[test]
    fn test_gmap_ugt_features_rfu_masked() {
        let raw_feat: u32 = 0x81;
        let masked = raw_feat & 0x01;
        assert_eq!(masked, GMAP_UGT_SOURCE);
    }
}
