// SPDX-License-Identifier: GPL-2.0-or-later
//
// ISO protocol definitions from lib/bluetooth/iso.h

use crate::addr::BdAddr;

// ---- Defaults ----
pub const ISO_DEFAULT_MTU: u16 = 251;
pub const ISO_MAX_NUM_BIS: usize = 0x1F;

// ---- Socket Address ----

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockAddrIsoBc {
    pub bc_bdaddr: BdAddr,
    pub bc_bdaddr_type: u8,
    pub bc_sid: u8,
    pub bc_num_bis: u8,
    pub bc_bis: [u8; ISO_MAX_NUM_BIS],
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockAddrIso {
    pub iso_family: u16,
    pub iso_bdaddr: BdAddr,
    pub iso_bdaddr_type: u8,
    // Followed by optional SockAddrIsoBc for broadcast
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_sock_addr_iso_size() {
        // u16 family + 6-byte bdaddr + u8 type + 1 pad = 10
        assert_eq!(mem::size_of::<SockAddrIso>(), 10);
    }

    #[test]
    fn test_sock_addr_iso_bc_size() {
        // 6 bdaddr + 1 type + 1 sid + 1 num_bis + 31 bis = 40
        assert_eq!(mem::size_of::<SockAddrIsoBc>(), 40);
    }
}
