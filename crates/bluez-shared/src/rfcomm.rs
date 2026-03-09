// SPDX-License-Identifier: GPL-2.0-or-later
//
// RFCOMM protocol definitions from lib/bluetooth/rfcomm.h

use bitflags::bitflags;
use crate::addr::BdAddr;

// ---- Defaults ----
pub const RFCOMM_DEFAULT_MTU: u16 = 127;
pub const RFCOMM_PSM: u16 = 3;

// ---- Socket Address ----

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockAddrRc {
    pub rc_family: u16,
    pub rc_bdaddr: BdAddr,
    pub rc_channel: u8,
}

// ---- Socket Options ----

pub const RFCOMM_CONNINFO: u32 = 0x02;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RfcommConninfo {
    pub hci_handle: u16,
    pub dev_class: [u8; 3],
}

pub const RFCOMM_LM: u32 = 0x03;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RfcommLm: u16 {
        const MASTER   = 0x0001;
        const AUTH     = 0x0002;
        const ENCRYPT  = 0x0004;
        const TRUSTED  = 0x0008;
        const RELIABLE = 0x0010;
        const SECURE   = 0x0020;
    }
}

// ---- TTY Support ----

pub const RFCOMM_MAX_DEV: u16 = 256;

// Device request flags
pub const RFCOMM_REUSE_DLC: u32 = 0;
pub const RFCOMM_RELEASE_ONHUP: u32 = 1;
pub const RFCOMM_HANGUP_NOW: u32 = 2;
pub const RFCOMM_TTY_ATTACHED: u32 = 3;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RfcommDevReq {
    pub dev_id: i16,
    pub flags: u32,
    pub src: BdAddr,
    pub dst: BdAddr,
    pub channel: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RfcommDevInfo {
    pub id: i16,
    pub flags: u32,
    pub state: u16,
    pub src: BdAddr,
    pub dst: BdAddr,
    pub channel: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RfcommDevListReq {
    pub dev_num: u16,
    // Followed by variable-length dev_info array
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_sock_addr_rc_size() {
        // u16 family + 6-byte bdaddr + u8 channel + 1 pad = 10
        assert_eq!(mem::size_of::<SockAddrRc>(), 10);
    }

    #[test]
    fn test_conninfo_size() {
        // u16 + [u8;3] + 1 pad = 6
        assert_eq!(mem::size_of::<RfcommConninfo>(), 6);
    }
}
