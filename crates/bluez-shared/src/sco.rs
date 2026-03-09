// SPDX-License-Identifier: GPL-2.0-or-later
//
// SCO protocol definitions from lib/bluetooth/sco.h

use crate::addr::BdAddr;

// ---- Defaults ----
pub const SCO_DEFAULT_MTU: u16 = 500;
pub const SCO_DEFAULT_FLUSH_TO: u16 = 0xFFFF;

// ---- Socket Address ----

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockAddrSco {
    pub sco_family: u16,
    pub sco_bdaddr: BdAddr,
}

// ---- Socket Options ----

pub const SCO_OPTIONS: u32 = 0x01;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ScoOptions {
    pub mtu: u16,
}

pub const SCO_CONNINFO: u32 = 0x02;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ScoConninfo {
    pub hci_handle: u16,
    pub dev_class: [u8; 3],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_sock_addr_sco_size() {
        // u16 family + 6-byte bdaddr = 8
        assert_eq!(mem::size_of::<SockAddrSco>(), 8);
    }

    #[test]
    fn test_sco_conninfo_size() {
        // u16 + [u8;3] + 1 pad = 6
        assert_eq!(mem::size_of::<ScoConninfo>(), 6);
    }
}
