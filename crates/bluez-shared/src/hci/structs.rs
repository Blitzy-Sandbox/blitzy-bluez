// SPDX-License-Identifier: GPL-2.0-or-later
//
// HCI command/event parameter structs from monitor/bt.h
// All structs use #[repr(C, packed)] to match the C wire format.

use crate::addr::BdAddr;

// ---- HCI Header ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCommandHdr {
    pub opcode: u16,
    pub plen: u8,
}

pub const HCI_COMMAND_HDR_SIZE: usize = 3;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciAclHdr {
    pub handle: u16, // 12 bits handle + 2 bits PB flag + 2 bits BC flag
    pub dlen: u16,
}

pub const HCI_ACL_HDR_SIZE: usize = 4;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciScoHdr {
    pub handle: u16, // 12 bits handle + 2 bits status + 2 bits reserved
    pub dlen: u8,
}

pub const HCI_SCO_HDR_SIZE: usize = 3;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciIsoHdr {
    pub handle: u16,
    pub dlen: u16,
}

pub const HCI_ISO_HDR_SIZE: usize = 4;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEventHdr {
    pub evt: u8,
    pub plen: u8,
}

pub const HCI_EVENT_HDR_SIZE: usize = 2;

// ---- Link Control Command Parameters ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdInquiry {
    pub lap: [u8; 3],
    pub length: u8,
    pub num_rsp: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdCreateConn {
    pub bdaddr: BdAddr,
    pub pkt_type: u16,
    pub pscan_rep_mode: u8,
    pub reserved: u8,
    pub clock_offset: u16,
    pub role_switch: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdDisconnect {
    pub handle: u16,
    pub reason: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdAcceptConnRequest {
    pub bdaddr: BdAddr,
    pub role: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdRejectConnRequest {
    pub bdaddr: BdAddr,
    pub reason: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLinkKeyRequestReply {
    pub bdaddr: BdAddr,
    pub link_key: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdPinCodeRequestReply {
    pub bdaddr: BdAddr,
    pub pin_len: u8,
    pub pin_code: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdRemoteNameRequest {
    pub bdaddr: BdAddr,
    pub pscan_rep_mode: u8,
    pub reserved: u8,
    pub clock_offset: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdIoCapabilityRequestReply {
    pub bdaddr: BdAddr,
    pub capability: u8,
    pub oob_data: u8,
    pub authentication: u8,
}

// ---- Controller & Baseband Command Parameters ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdSetEventMask {
    pub mask: [u8; 8],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdWriteLocalName {
    pub name: [u8; 248],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdWriteClassOfDev {
    pub dev_class: [u8; 3],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdWriteScanEnable {
    pub enable: u8,
}

// ---- Informational Command Return Parameters ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciRspReadLocalVersion {
    pub status: u8,
    pub hci_ver: u8,
    pub hci_rev: u16,
    pub lmp_ver: u8,
    pub manufacturer: u16,
    pub lmp_subver: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciRspReadLocalCommands {
    pub status: u8,
    pub commands: [u8; 64],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciRspReadLocalFeatures {
    pub status: u8,
    pub features: [u8; 8],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciRspReadBufferSize {
    pub status: u8,
    pub acl_mtu: u16,
    pub sco_mtu: u8,
    pub acl_max_pkt: u16,
    pub sco_max_pkt: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciRspReadBdAddr {
    pub status: u8,
    pub bdaddr: BdAddr,
}

// ---- Event Parameters ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtConnComplete {
    pub status: u8,
    pub handle: u16,
    pub bdaddr: BdAddr,
    pub link_type: u8,
    pub encr_mode: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtDisconnComplete {
    pub status: u8,
    pub handle: u16,
    pub reason: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtCmdComplete {
    pub ncmd: u8,
    pub opcode: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtCmdStatus {
    pub status: u8,
    pub ncmd: u8,
    pub opcode: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtEncryptChange {
    pub status: u8,
    pub handle: u16,
    pub encrypt: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtRemoteNameRequestComplete {
    pub status: u8,
    pub bdaddr: BdAddr,
    pub name: [u8; 248],
}

// ---- LE Command Parameters ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLeSetAdvParameters {
    pub min_interval: u16,
    pub max_interval: u16,
    pub adv_type: u8,
    pub own_addr_type: u8,
    pub direct_addr_type: u8,
    pub direct_addr: BdAddr,
    pub channel_map: u8,
    pub filter_policy: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLeSetAdvData {
    pub len: u8,
    pub data: [u8; 31],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLeSetScanParameters {
    pub scan_type: u8,
    pub interval: u16,
    pub window: u16,
    pub own_addr_type: u8,
    pub filter_policy: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLeSetScanEnable {
    pub enable: u8,
    pub filter_dup: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLeCreateConn {
    pub scan_interval: u16,
    pub scan_window: u16,
    pub filter_policy: u8,
    pub peer_addr_type: u8,
    pub peer_addr: BdAddr,
    pub own_addr_type: u8,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub supv_timeout: u16,
    pub min_length: u16,
    pub max_length: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLeStartEncrypt {
    pub handle: u16,
    pub rand: u64,
    pub ediv: u16,
    pub ltk: [u8; 16],
}

// ---- LE Event Parameters ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtLeConnComplete {
    pub status: u8,
    pub handle: u16,
    pub role: u8,
    pub peer_addr_type: u8,
    pub peer_addr: BdAddr,
    pub interval: u16,
    pub latency: u16,
    pub supv_timeout: u16,
    pub clock_accuracy: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtLeEnhancedConnComplete {
    pub status: u8,
    pub handle: u16,
    pub role: u8,
    pub peer_addr_type: u8,
    pub peer_addr: BdAddr,
    pub local_rpa: BdAddr,
    pub peer_rpa: BdAddr,
    pub interval: u16,
    pub latency: u16,
    pub supv_timeout: u16,
    pub clock_accuracy: u8,
}

// ---- LE Read Buffer Size V2 Return Parameters ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciRspLeReadBufferSizeV2 {
    pub status: u8,
    pub acl_mtu: u16,
    pub acl_max_pkt: u8,
    pub iso_mtu: u16,
    pub iso_max_pkt: u8,
}

// ---- ISO structs ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciCmdLeSetCigParams {
    pub cig_id: u8,
    pub sdu_interval_c_to_p: [u8; 3], // 24-bit LE
    pub sdu_interval_p_to_c: [u8; 3], // 24-bit LE
    pub sca: u8,
    pub packing: u8,
    pub framing: u8,
    pub max_latency_c_to_p: u16,
    pub max_latency_p_to_c: u16,
    pub num_cis: u8,
    // Followed by variable-length CIS params
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct HciEvtLeCisEstablished {
    pub status: u8,
    pub handle: u16,
    pub cig_sync_delay: [u8; 3], // 24-bit LE
    pub cis_sync_delay: [u8; 3], // 24-bit LE
    pub latency_c_to_p: [u8; 3], // 24-bit LE
    pub latency_p_to_c: [u8; 3], // 24-bit LE
    pub phy_c_to_p: u8,
    pub phy_p_to_c: u8,
    pub nse: u8,
    pub bn_c_to_p: u8,
    pub bn_p_to_c: u8,
    pub ft_c_to_p: u8,
    pub ft_p_to_c: u8,
    pub max_pdu_c_to_p: u16,
    pub max_pdu_p_to_c: u16,
    pub iso_interval: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(mem::size_of::<HciCommandHdr>(), HCI_COMMAND_HDR_SIZE);
        assert_eq!(mem::size_of::<HciAclHdr>(), HCI_ACL_HDR_SIZE);
        assert_eq!(mem::size_of::<HciScoHdr>(), HCI_SCO_HDR_SIZE);
        assert_eq!(mem::size_of::<HciIsoHdr>(), HCI_ISO_HDR_SIZE);
        assert_eq!(mem::size_of::<HciEventHdr>(), HCI_EVENT_HDR_SIZE);
    }

    #[test]
    fn test_command_struct_sizes() {
        assert_eq!(mem::size_of::<HciCmdInquiry>(), 5);
        assert_eq!(mem::size_of::<HciCmdDisconnect>(), 3);
        assert_eq!(mem::size_of::<HciCmdSetEventMask>(), 8);
    }

    #[test]
    fn test_event_struct_sizes() {
        assert_eq!(mem::size_of::<HciEvtCmdComplete>(), 3);
        assert_eq!(mem::size_of::<HciEvtCmdStatus>(), 4);
        assert_eq!(mem::size_of::<HciEvtDisconnComplete>(), 4);
        assert_eq!(mem::size_of::<HciEvtConnComplete>(), 11);
    }

    #[test]
    fn test_le_conn_complete_size() {
        assert_eq!(mem::size_of::<HciEvtLeConnComplete>(), 18);
    }

    #[test]
    fn test_rsp_read_bd_addr_size() {
        assert_eq!(mem::size_of::<HciRspReadBdAddr>(), 7);
    }
}
