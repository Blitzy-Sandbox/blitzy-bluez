// SPDX-License-Identifier: GPL-2.0-or-later
//
// Coordinated Set Identification Profile (CSIP) definitions replacing src/shared/csip.c

pub const CSIS_UUID: u16 = 0x1846;

// CSIS Characteristic UUIDs
pub const CSIS_SIRK_UUID: u16 = 0x2B84;
pub const CSIS_SIZE_UUID: u16 = 0x2B85;
pub const CSIS_LOCK_UUID: u16 = 0x2B86;
pub const CSIS_RANK_UUID: u16 = 0x2B87;

// SIRK Types
pub const CSIS_SIRK_ENCRYPTED: u8 = 0x00;
pub const CSIS_SIRK_CLEARTEXT: u8 = 0x01;

// Lock States
pub const CSIS_UNLOCKED: u8 = 0x01;
pub const CSIS_LOCKED: u8 = 0x02;

/// SIRK (Set Identity Resolving Key) — 16 bytes.
pub const CSIS_SIRK_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csis_uuids() {
        assert_eq!(CSIS_UUID, 0x1846);
        assert_eq!(CSIS_SIRK_UUID, 0x2B84);
    }

    #[test]
    fn test_lock_states() {
        assert_eq!(CSIS_UNLOCKED, 0x01);
        assert_eq!(CSIS_LOCKED, 0x02);
    }
}
