// SPDX-License-Identifier: GPL-2.0-or-later
//
// Telephony and Media Audio Profile (TMAP) definitions

pub const TMAS_UUID: u16 = 0x1855;
pub const TMAP_ROLE_UUID: u16 = 0x2B51;

// TMAP Roles (bitmask)
pub const TMAP_ROLE_CG: u16 = 0x0001; // Call Gateway
pub const TMAP_ROLE_CT: u16 = 0x0002; // Call Terminal
pub const TMAP_ROLE_UMS: u16 = 0x0004; // Unicast Media Sender
pub const TMAP_ROLE_UMR: u16 = 0x0008; // Unicast Media Receiver
pub const TMAP_ROLE_BMS: u16 = 0x0010; // Broadcast Media Sender
pub const TMAP_ROLE_BMR: u16 = 0x0020; // Broadcast Media Receiver

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Role bitmask tests (from test-tmap.c) ----

    #[test]
    fn test_tmap_role_cg() {
        assert_eq!(TMAP_ROLE_CG, 0x0001);
    }

    #[test]
    fn test_tmap_role_ct() {
        assert_eq!(TMAP_ROLE_CT, 0x0002);
    }

    #[test]
    fn test_tmap_role_ums() {
        assert_eq!(TMAP_ROLE_UMS, 0x0004);
    }

    #[test]
    fn test_tmap_role_umr() {
        assert_eq!(TMAP_ROLE_UMR, 0x0008);
    }

    #[test]
    fn test_tmap_role_bms() {
        assert_eq!(TMAP_ROLE_BMS, 0x0010);
    }

    #[test]
    fn test_tmap_role_bmr() {
        assert_eq!(TMAP_ROLE_BMR, 0x0020);
    }

    #[test]
    fn test_tmap_role_combined_ums_bmr() {
        // From test-tmap.c: cfg_read_role uses UMS | BMR = 0x0024
        assert_eq!(TMAP_ROLE_UMS | TMAP_ROLE_BMR, 0x0024);
    }

    #[test]
    fn test_tmap_role_rfu_bits_ignored() {
        // From test-tmap.c: client ignores RFU bits in TMAP Role (value 0xff24)
        // Only the defined role bits matter
        let raw_role: u16 = 0xff24;
        let defined_mask: u16 = TMAP_ROLE_CG | TMAP_ROLE_CT | TMAP_ROLE_UMS
            | TMAP_ROLE_UMR | TMAP_ROLE_BMS | TMAP_ROLE_BMR;
        let masked = raw_role & defined_mask;
        assert_eq!(masked, TMAP_ROLE_UMS | TMAP_ROLE_BMR);
    }

    #[test]
    fn test_tmap_role_all_combined() {
        let all = TMAP_ROLE_CG | TMAP_ROLE_CT | TMAP_ROLE_UMS
            | TMAP_ROLE_UMR | TMAP_ROLE_BMS | TMAP_ROLE_BMR;
        assert_eq!(all, 0x003F);
    }

    #[test]
    fn test_tmas_uuid() {
        assert_eq!(TMAS_UUID, 0x1855);
    }

    #[test]
    fn test_tmap_role_uuid() {
        assert_eq!(TMAP_ROLE_UUID, 0x2B51);
    }
}
