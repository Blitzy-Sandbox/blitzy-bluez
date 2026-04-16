// SPDX-License-Identifier: GPL-2.0-or-later
//
// L2CAP protocol definitions from lib/bluetooth/l2cap.h

use bitflags::bitflags;
use crate::addr::BdAddr;

// ---- Defaults ----
pub const L2CAP_DEFAULT_MTU: u16 = 672;
pub const L2CAP_DEFAULT_FLUSH_TO: u16 = 0xFFFF;

// ---- Socket Address ----

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockAddrL2 {
    pub l2_family: u16,
    pub l2_psm: u16,
    pub l2_bdaddr: BdAddr,
    pub l2_cid: u16,
    pub l2_bdaddr_type: u8,
}

// ---- Socket Options ----

pub const L2CAP_OPTIONS: u32 = 0x01;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct L2capOptions {
    pub omtu: u16,
    pub imtu: u16,
    pub flush_to: u16,
    pub mode: u8,
    pub fcs: u8,
    pub max_tx: u8,
    pub txwin_size: u16,
}

pub const L2CAP_CONNINFO: u32 = 0x02;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct L2capConninfo {
    pub hci_handle: u16,
    pub dev_class: [u8; 3],
}

// ---- Link Mode Flags ----

pub const L2CAP_LM: u32 = 0x03;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct L2capLm: u16 {
        const MASTER   = 0x0001;
        const AUTH     = 0x0002;
        const ENCRYPT  = 0x0004;
        const TRUSTED  = 0x0008;
        const RELIABLE = 0x0010;
        const SECURE   = 0x0020;
    }
}

// ---- Command Codes ----

pub const L2CAP_COMMAND_REJ: u8 = 0x01;
pub const L2CAP_CONN_REQ: u8 = 0x02;
pub const L2CAP_CONN_RSP: u8 = 0x03;
pub const L2CAP_CONF_REQ: u8 = 0x04;
pub const L2CAP_CONF_RSP: u8 = 0x05;
pub const L2CAP_DISCONN_REQ: u8 = 0x06;
pub const L2CAP_DISCONN_RSP: u8 = 0x07;
pub const L2CAP_ECHO_REQ: u8 = 0x08;
pub const L2CAP_ECHO_RSP: u8 = 0x09;
pub const L2CAP_INFO_REQ: u8 = 0x0A;
pub const L2CAP_INFO_RSP: u8 = 0x0B;
pub const L2CAP_CREATE_REQ: u8 = 0x0C;
pub const L2CAP_CREATE_RSP: u8 = 0x0D;
pub const L2CAP_MOVE_REQ: u8 = 0x0E;
pub const L2CAP_MOVE_RSP: u8 = 0x0F;
pub const L2CAP_MOVE_CFM: u8 = 0x10;
pub const L2CAP_MOVE_CFM_RSP: u8 = 0x11;

// ---- Extended Feature Mask ----

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct L2capFeat: u32 {
        const FLOWCTL    = 0x00000001;
        const RETRANS    = 0x00000002;
        const BIDIR_QOS  = 0x00000004;
        const ERTM       = 0x00000008;
        const STREAMING  = 0x00000010;
        const FCS        = 0x00000020;
        const EXT_FLOW   = 0x00000040;
        const FIXED_CHAN = 0x00000080;
        const EXT_WINDOW = 0x00000100;
        const UCD        = 0x00000200;
    }
}

// ---- Fixed Channels ----
pub const L2CAP_FC_L2CAP: u8 = 0x02;
pub const L2CAP_FC_CONNLESS: u8 = 0x04;
pub const L2CAP_FC_A2MP: u8 = 0x08;

// ---- Wire Format Structs ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct L2capHdr {
    pub len: u16,
    pub cid: u16,
}
pub const L2CAP_HDR_SIZE: usize = 4;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct L2capCmdHdr {
    pub code: u8,
    pub ident: u8,
    pub len: u16,
}
pub const L2CAP_CMD_HDR_SIZE: usize = 4;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct L2capConnReq {
    pub psm: u16,
    pub scid: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct L2capConnRsp {
    pub dcid: u16,
    pub scid: u16,
    pub result: u16,
    pub status: u16,
}

// Connect results
pub const L2CAP_CR_SUCCESS: u16 = 0x0000;
pub const L2CAP_CR_PEND: u16 = 0x0001;
pub const L2CAP_CR_BAD_PSM: u16 = 0x0002;
pub const L2CAP_CR_SEC_BLOCK: u16 = 0x0003;
pub const L2CAP_CR_NO_MEM: u16 = 0x0004;

// Connect status
pub const L2CAP_CS_NO_INFO: u16 = 0x0000;
pub const L2CAP_CS_AUTHEN_PEND: u16 = 0x0001;
pub const L2CAP_CS_AUTHOR_PEND: u16 = 0x0002;

// Config results
pub const L2CAP_CONF_SUCCESS: u16 = 0x0000;
pub const L2CAP_CONF_UNACCEPT: u16 = 0x0001;
pub const L2CAP_CONF_REJECT: u16 = 0x0002;
pub const L2CAP_CONF_UNKNOWN: u16 = 0x0003;
pub const L2CAP_CONF_PENDING: u16 = 0x0004;
pub const L2CAP_CONF_EFS_REJECT: u16 = 0x0005;

// Config option types
pub const L2CAP_CONF_MTU: u8 = 0x01;
pub const L2CAP_CONF_FLUSH_TO: u8 = 0x02;
pub const L2CAP_CONF_QOS: u8 = 0x03;
pub const L2CAP_CONF_RFC: u8 = 0x04;
pub const L2CAP_CONF_FCS: u8 = 0x05;
pub const L2CAP_CONF_EFS: u8 = 0x06;
pub const L2CAP_CONF_EWS: u8 = 0x07;

// L2CAP modes
pub const L2CAP_MODE_BASIC: u8 = 0x00;
pub const L2CAP_MODE_RETRANS: u8 = 0x01;
pub const L2CAP_MODE_FLOWCTL: u8 = 0x02;
pub const L2CAP_MODE_ERTM: u8 = 0x03;
pub const L2CAP_MODE_STREAMING: u8 = 0x04;
pub const L2CAP_MODE_LE_FLOWCTL: u8 = 0x80;
pub const L2CAP_MODE_ECRED: u8 = 0x81;

// FCS types
pub const L2CAP_FCS_NONE: u8 = 0x00;
pub const L2CAP_FCS_CRC16: u8 = 0x01;

// Info types
pub const L2CAP_IT_CL_MTU: u16 = 0x0001;
pub const L2CAP_IT_FEAT_MASK: u16 = 0x0002;

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_l2cap_hdr_size() {
        assert_eq!(mem::size_of::<L2capHdr>(), L2CAP_HDR_SIZE);
        assert_eq!(mem::size_of::<L2capCmdHdr>(), L2CAP_CMD_HDR_SIZE);
    }

    #[test]
    fn test_conn_req_size() {
        assert_eq!(mem::size_of::<L2capConnReq>(), 4);
        assert_eq!(mem::size_of::<L2capConnRsp>(), 8);
    }
}
