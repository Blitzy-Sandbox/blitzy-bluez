// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ Management API definitions from lib/bluetooth/mgmt.h
// All opcodes, events, settings bitflags, and packed structs.

use bitflags::bitflags;
use crate::addr::BdAddr;

/// Index value used for non-controller specific commands.
pub const MGMT_INDEX_NONE: u16 = 0xFFFF;

/// Maximum name lengths (including null terminator space).
pub const MGMT_MAX_NAME_LENGTH: usize = 249;
pub const MGMT_MAX_SHORT_NAME_LENGTH: usize = 11;

// ---- Management Header ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtHdr {
    pub opcode: u16,
    pub index: u16,
    pub len: u16,
}

pub const MGMT_HDR_SIZE: usize = 6;

// ---- Common Structures ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtAddrInfo {
    pub bdaddr: BdAddr,
    pub addr_type: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtMode {
    pub val: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCod {
    pub val: [u8; 3],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtTlv {
    pub tlv_type: u16,
    pub length: u8,
    // value follows (variable length)
}

// ---- Settings Bitflags ----

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MgmtSettings: u32 {
        const POWERED           = 1 << 0;
        const CONNECTABLE       = 1 << 1;
        const FAST_CONNECTABLE  = 1 << 2;
        const DISCOVERABLE      = 1 << 3;
        const BONDABLE          = 1 << 4;
        const LINK_SECURITY     = 1 << 5;
        const SSP               = 1 << 6;
        const BREDR             = 1 << 7;
        const HS                = 1 << 8;
        const LE                = 1 << 9;
        const ADVERTISING       = 1 << 10;
        const SECURE_CONN       = 1 << 11;
        const DEBUG_KEYS        = 1 << 12;
        const PRIVACY           = 1 << 13;
        const CONFIGURATION     = 1 << 14;
        const STATIC_ADDRESS    = 1 << 15;
        const PHY_CONFIGURATION = 1 << 16;
        const WIDEBAND_SPEECH   = 1 << 17;
        const CIS_CENTRAL       = 1 << 18;
        const CIS_PERIPHERAL    = 1 << 19;
        const ISO_BROADCASTER   = 1 << 20;
        const ISO_SYNC_RECEIVER = 1 << 21;
        const LL_PRIVACY        = 1 << 22;
        const PAST_SENDER       = 1 << 23;
        const PAST_RECEIVER     = 1 << 24;
    }
}

// ---- Management Command Opcodes ----

pub const MGMT_OP_READ_VERSION: u16 = 0x0001;
pub const MGMT_OP_READ_COMMANDS: u16 = 0x0002;
pub const MGMT_OP_READ_INDEX_LIST: u16 = 0x0003;
pub const MGMT_OP_READ_INFO: u16 = 0x0004;
pub const MGMT_OP_SET_POWERED: u16 = 0x0005;
pub const MGMT_OP_SET_DISCOVERABLE: u16 = 0x0006;
pub const MGMT_OP_SET_CONNECTABLE: u16 = 0x0007;
pub const MGMT_OP_SET_FAST_CONNECTABLE: u16 = 0x0008;
pub const MGMT_OP_SET_BONDABLE: u16 = 0x0009;
pub const MGMT_OP_SET_LINK_SECURITY: u16 = 0x000A;
pub const MGMT_OP_SET_SSP: u16 = 0x000B;
pub const MGMT_OP_SET_HS: u16 = 0x000C;
pub const MGMT_OP_SET_LE: u16 = 0x000D;
pub const MGMT_OP_SET_DEV_CLASS: u16 = 0x000E;
pub const MGMT_OP_SET_LOCAL_NAME: u16 = 0x000F;
pub const MGMT_OP_ADD_UUID: u16 = 0x0010;
pub const MGMT_OP_REMOVE_UUID: u16 = 0x0011;
pub const MGMT_OP_LOAD_LINK_KEYS: u16 = 0x0012;
pub const MGMT_OP_LOAD_LONG_TERM_KEYS: u16 = 0x0013;
pub const MGMT_OP_DISCONNECT: u16 = 0x0014;
pub const MGMT_OP_GET_CONNECTIONS: u16 = 0x0015;
pub const MGMT_OP_PIN_CODE_REPLY: u16 = 0x0016;
pub const MGMT_OP_PIN_CODE_NEG_REPLY: u16 = 0x0017;
pub const MGMT_OP_SET_IO_CAPABILITY: u16 = 0x0018;
pub const MGMT_OP_PAIR_DEVICE: u16 = 0x0019;
pub const MGMT_OP_CANCEL_PAIR_DEVICE: u16 = 0x001A;
pub const MGMT_OP_UNPAIR_DEVICE: u16 = 0x001B;
pub const MGMT_OP_USER_CONFIRM_REPLY: u16 = 0x001C;
pub const MGMT_OP_USER_CONFIRM_NEG_REPLY: u16 = 0x001D;
pub const MGMT_OP_USER_PASSKEY_REPLY: u16 = 0x001E;
pub const MGMT_OP_USER_PASSKEY_NEG_REPLY: u16 = 0x001F;
pub const MGMT_OP_READ_LOCAL_OOB_DATA: u16 = 0x0020;
pub const MGMT_OP_ADD_REMOTE_OOB_DATA: u16 = 0x0021;
pub const MGMT_OP_REMOVE_REMOTE_OOB_DATA: u16 = 0x0022;
pub const MGMT_OP_START_DISCOVERY: u16 = 0x0023;
pub const MGMT_OP_STOP_DISCOVERY: u16 = 0x0024;
pub const MGMT_OP_CONFIRM_NAME: u16 = 0x0025;
pub const MGMT_OP_BLOCK_DEVICE: u16 = 0x0026;
pub const MGMT_OP_UNBLOCK_DEVICE: u16 = 0x0027;
pub const MGMT_OP_SET_DEVICE_ID: u16 = 0x0028;
pub const MGMT_OP_SET_ADVERTISING: u16 = 0x0029;
pub const MGMT_OP_SET_BREDR: u16 = 0x002A;
pub const MGMT_OP_SET_STATIC_ADDRESS: u16 = 0x002B;
pub const MGMT_OP_SET_SCAN_PARAMS: u16 = 0x002C;
pub const MGMT_OP_SET_SECURE_CONN: u16 = 0x002D;
pub const MGMT_OP_SET_DEBUG_KEYS: u16 = 0x002E;
pub const MGMT_OP_SET_PRIVACY: u16 = 0x002F;
pub const MGMT_OP_LOAD_IRKS: u16 = 0x0030;
pub const MGMT_OP_GET_CONN_INFO: u16 = 0x0031;
pub const MGMT_OP_GET_CLOCK_INFO: u16 = 0x0032;
pub const MGMT_OP_ADD_DEVICE: u16 = 0x0033;
pub const MGMT_OP_REMOVE_DEVICE: u16 = 0x0034;
pub const MGMT_OP_LOAD_CONN_PARAM: u16 = 0x0035;
pub const MGMT_OP_READ_UNCONF_INDEX_LIST: u16 = 0x0036;
pub const MGMT_OP_READ_CONFIG_INFO: u16 = 0x0037;
pub const MGMT_OP_SET_EXTERNAL_CONFIG: u16 = 0x0038;
pub const MGMT_OP_SET_PUBLIC_ADDRESS: u16 = 0x0039;
pub const MGMT_OP_START_SERVICE_DISCOVERY: u16 = 0x003A;
pub const MGMT_OP_READ_LOCAL_OOB_EXT_DATA: u16 = 0x003B;
pub const MGMT_OP_READ_EXT_INDEX_LIST: u16 = 0x003C;
pub const MGMT_OP_READ_ADV_FEATURES: u16 = 0x003D;
pub const MGMT_OP_ADD_ADVERTISING: u16 = 0x003E;
pub const MGMT_OP_REMOVE_ADVERTISING: u16 = 0x003F;
pub const MGMT_OP_GET_ADV_SIZE_INFO: u16 = 0x0040;
pub const MGMT_OP_START_LIMITED_DISCOVERY: u16 = 0x0041;
pub const MGMT_OP_READ_EXT_INFO: u16 = 0x0042;
pub const MGMT_OP_SET_APPEARANCE: u16 = 0x0043;
pub const MGMT_OP_GET_PHY_CONFIGURATION: u16 = 0x0044;
pub const MGMT_OP_SET_PHY_CONFIGURATION: u16 = 0x0045;
pub const MGMT_OP_SET_BLOCKED_KEYS: u16 = 0x0046;
pub const MGMT_OP_SET_WIDEBAND_SPEECH: u16 = 0x0047;
pub const MGMT_OP_READ_CONTROLLER_CAP: u16 = 0x0048;
pub const MGMT_OP_READ_EXP_FEATURES_INFO: u16 = 0x0049;
pub const MGMT_OP_SET_EXP_FEATURE: u16 = 0x004A;
pub const MGMT_OP_READ_DEF_SYSTEM_CONFIG: u16 = 0x004B;
pub const MGMT_OP_SET_DEF_SYSTEM_CONFIG: u16 = 0x004C;
pub const MGMT_OP_READ_DEF_RUNTIME_CONFIG: u16 = 0x004D;
pub const MGMT_OP_SET_DEF_RUNTIME_CONFIG: u16 = 0x004E;
pub const MGMT_OP_GET_DEVICE_FLAGS: u16 = 0x004F;
pub const MGMT_OP_SET_DEVICE_FLAGS: u16 = 0x0050;
pub const MGMT_OP_READ_ADV_MONITOR_FEATURES: u16 = 0x0051;
pub const MGMT_OP_ADD_ADV_PATTERNS_MONITOR: u16 = 0x0052;
pub const MGMT_OP_REMOVE_ADV_MONITOR: u16 = 0x0053;
pub const MGMT_OP_ADD_EXT_ADV_PARAMS: u16 = 0x0054;
pub const MGMT_OP_ADD_EXT_ADV_DATA: u16 = 0x0055;
pub const MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI: u16 = 0x0056;
pub const MGMT_OP_SET_MESH_RECEIVER: u16 = 0x0057;
pub const MGMT_OP_MESH_READ_FEATURES: u16 = 0x0058;
pub const MGMT_OP_MESH_SEND: u16 = 0x0059;
pub const MGMT_OP_MESH_SEND_CANCEL: u16 = 0x005A;
pub const MGMT_OP_HCI_CMD_SYNC: u16 = 0x005B;

// ---- Management Event Codes ----

pub const MGMT_EV_CMD_COMPLETE: u16 = 0x0001;
pub const MGMT_EV_CMD_STATUS: u16 = 0x0002;
pub const MGMT_EV_CONTROLLER_ERROR: u16 = 0x0003;
pub const MGMT_EV_INDEX_ADDED: u16 = 0x0004;
pub const MGMT_EV_INDEX_REMOVED: u16 = 0x0005;
pub const MGMT_EV_NEW_SETTINGS: u16 = 0x0006;
pub const MGMT_EV_CLASS_OF_DEV_CHANGED: u16 = 0x0007;
pub const MGMT_EV_LOCAL_NAME_CHANGED: u16 = 0x0008;
pub const MGMT_EV_NEW_LINK_KEY: u16 = 0x0009;
pub const MGMT_EV_NEW_LONG_TERM_KEY: u16 = 0x000A;
pub const MGMT_EV_DEVICE_CONNECTED: u16 = 0x000B;
pub const MGMT_EV_DEVICE_DISCONNECTED: u16 = 0x000C;
pub const MGMT_EV_CONNECT_FAILED: u16 = 0x000D;
pub const MGMT_EV_PIN_CODE_REQUEST: u16 = 0x000E;
pub const MGMT_EV_USER_CONFIRM_REQUEST: u16 = 0x000F;
pub const MGMT_EV_USER_PASSKEY_REQUEST: u16 = 0x0010;
pub const MGMT_EV_AUTH_FAILED: u16 = 0x0011;
pub const MGMT_EV_DEVICE_FOUND: u16 = 0x0012;
pub const MGMT_EV_DISCOVERING: u16 = 0x0013;
pub const MGMT_EV_DEVICE_BLOCKED: u16 = 0x0014;
pub const MGMT_EV_DEVICE_UNBLOCKED: u16 = 0x0015;
pub const MGMT_EV_DEVICE_UNPAIRED: u16 = 0x0016;
pub const MGMT_EV_PASSKEY_NOTIFY: u16 = 0x0017;
pub const MGMT_EV_NEW_IRK: u16 = 0x0018;
pub const MGMT_EV_NEW_CSRK: u16 = 0x0019;
pub const MGMT_EV_DEVICE_ADDED: u16 = 0x001A;
pub const MGMT_EV_DEVICE_REMOVED: u16 = 0x001B;
pub const MGMT_EV_NEW_CONN_PARAM: u16 = 0x001C;
pub const MGMT_EV_UNCONF_INDEX_ADDED: u16 = 0x001D;
pub const MGMT_EV_UNCONF_INDEX_REMOVED: u16 = 0x001E;
pub const MGMT_EV_NEW_CONFIG_OPTIONS: u16 = 0x001F;
pub const MGMT_EV_EXT_INDEX_ADDED: u16 = 0x0020;
pub const MGMT_EV_EXT_INDEX_REMOVED: u16 = 0x0021;
pub const MGMT_EV_LOCAL_OOB_DATA_UPDATED: u16 = 0x0022;
pub const MGMT_EV_ADVERTISING_ADDED: u16 = 0x0023;
pub const MGMT_EV_ADVERTISING_REMOVED: u16 = 0x0024;
pub const MGMT_EV_EXT_INFO_CHANGED: u16 = 0x0025;
pub const MGMT_EV_PHY_CONFIGURATION_CHANGED: u16 = 0x0026;
pub const MGMT_EV_EXP_FEATURE_CHANGE: u16 = 0x0027;
pub const MGMT_EV_DEVICE_FLAGS_CHANGED: u16 = 0x002A;
pub const MGMT_EV_ADV_MONITOR_ADDED: u16 = 0x002B;
pub const MGMT_EV_ADV_MONITOR_REMOVED: u16 = 0x002C;
pub const MGMT_EV_CONTROLLER_SUSPEND: u16 = 0x002D;
pub const MGMT_EV_CONTROLLER_RESUME: u16 = 0x002E;
pub const MGMT_EV_ADV_MONITOR_DEVICE_FOUND: u16 = 0x002F;
pub const MGMT_EV_ADV_MONITOR_DEVICE_LOST: u16 = 0x0030;
pub const MGMT_EV_MESH_DEVICE_FOUND: u16 = 0x0031;
pub const MGMT_EV_MESH_PACKET_CMPLT: u16 = 0x0032;

// ---- Command Parameter Structs ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtRpReadVersion {
    pub version: u8,
    pub revision: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtRpReadInfo {
    pub bdaddr: BdAddr,
    pub version: u8,
    pub manufacturer: u16,
    pub supported_settings: u32,
    pub current_settings: u32,
    pub dev_class: [u8; 3],
    pub name: [u8; MGMT_MAX_NAME_LENGTH],
    pub short_name: [u8; MGMT_MAX_SHORT_NAME_LENGTH],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetDiscoverable {
    pub val: u8,
    pub timeout: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetDevClass {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetLocalName {
    pub name: [u8; MGMT_MAX_NAME_LENGTH],
    pub short_name: [u8; MGMT_MAX_SHORT_NAME_LENGTH],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpAddUuid {
    pub uuid: [u8; 16],
    pub svc_hint: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpRemoveUuid {
    pub uuid: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtLinkKeyInfo {
    pub addr: MgmtAddrInfo,
    pub key_type: u8,
    pub val: [u8; 16],
    pub pin_len: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtLtkInfo {
    pub addr: MgmtAddrInfo,
    pub key_type: u8,
    pub central: u8,
    pub enc_size: u8,
    pub ediv: u16,
    pub rand: u64,
    pub val: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpDisconnect {
    pub addr: MgmtAddrInfo,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpPinCodeReply {
    pub addr: MgmtAddrInfo,
    pub pin_len: u8,
    pub pin_code: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetIoCapability {
    pub io_capability: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpPairDevice {
    pub addr: MgmtAddrInfo,
    pub io_cap: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtRpPairDevice {
    pub addr: MgmtAddrInfo,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpUnpairDevice {
    pub addr: MgmtAddrInfo,
    pub disconnect: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpUserPasskeyReply {
    pub addr: MgmtAddrInfo,
    pub passkey: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpStartDiscovery {
    pub addr_type: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpConfirmName {
    pub addr: MgmtAddrInfo,
    pub name_known: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetDeviceId {
    pub source: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetStaticAddress {
    pub bdaddr: BdAddr,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetScanParams {
    pub interval: u16,
    pub window: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetPrivacy {
    pub privacy: u8,
    pub irk: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtIrkInfo {
    pub addr: MgmtAddrInfo,
    pub val: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpAddDevice {
    pub addr: MgmtAddrInfo,
    pub action: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtCpSetAppearance {
    pub appearance: u16,
}

// ---- Event Parameter Structs ----

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvCmdComplete {
    pub opcode: u16,
    pub status: u8,
    // data follows
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvCmdStatus {
    pub opcode: u16,
    pub status: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvControllerError {
    pub error_code: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvDeviceConnected {
    pub addr: MgmtAddrInfo,
    pub flags: u32,
    pub eir_len: u16,
    // eir data follows
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvDeviceDisconnected {
    pub addr: MgmtAddrInfo,
    pub reason: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvConnectFailed {
    pub addr: MgmtAddrInfo,
    pub status: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvAuthFailed {
    pub addr: MgmtAddrInfo,
    pub status: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvDeviceFound {
    pub addr: MgmtAddrInfo,
    pub rssi: i8,
    pub flags: u32,
    pub eir_len: u16,
    // eir data follows
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvDiscovering {
    pub addr_type: u8,
    pub discovering: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvPasskeyNotify {
    pub addr: MgmtAddrInfo,
    pub passkey: u32,
    pub entered: u8,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MgmtEvNewConnParam {
    pub addr: MgmtAddrInfo,
    pub store_hint: u8,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

// ---- Address Type Constants ----

pub const MGMT_ADDR_BREDR: u8 = 0x01;
pub const MGMT_ADDR_LE_PUBLIC: u8 = 0x02;
pub const MGMT_ADDR_LE_RANDOM: u8 = 0x03;

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    // ---- Header and struct sizes (from test-mgmt.c packet construction) ----

    #[test]
    fn test_mgmt_hdr_size() {
        assert_eq!(mem::size_of::<MgmtHdr>(), MGMT_HDR_SIZE);
    }

    #[test]
    fn test_mgmt_hdr_size_is_6() {
        assert_eq!(MGMT_HDR_SIZE, 6);
    }

    #[test]
    fn test_mgmt_addr_info_size() {
        assert_eq!(mem::size_of::<MgmtAddrInfo>(), 7);
    }

    // ---- Settings bitflags (from test-mgmt.c command parameter encoding) ----

    #[test]
    fn test_settings_bitflags() {
        let settings = MgmtSettings::POWERED | MgmtSettings::LE | MgmtSettings::BREDR;
        assert!(settings.contains(MgmtSettings::POWERED));
        assert!(settings.contains(MgmtSettings::LE));
        assert!(settings.contains(MgmtSettings::BREDR));
        assert!(!settings.contains(MgmtSettings::SSP));

        assert_eq!(MgmtSettings::POWERED.bits(), 1 << 0);
        assert_eq!(MgmtSettings::LE.bits(), 1 << 9);
        assert_eq!(MgmtSettings::PAST_RECEIVER.bits(), 1 << 24);
    }

    #[test]
    fn test_settings_all_individual_bits() {
        assert_eq!(MgmtSettings::CONNECTABLE.bits(), 1 << 1);
        assert_eq!(MgmtSettings::FAST_CONNECTABLE.bits(), 1 << 2);
        assert_eq!(MgmtSettings::DISCOVERABLE.bits(), 1 << 3);
        assert_eq!(MgmtSettings::BONDABLE.bits(), 1 << 4);
        assert_eq!(MgmtSettings::LINK_SECURITY.bits(), 1 << 5);
        assert_eq!(MgmtSettings::SSP.bits(), 1 << 6);
        assert_eq!(MgmtSettings::BREDR.bits(), 1 << 7);
        assert_eq!(MgmtSettings::HS.bits(), 1 << 8);
        assert_eq!(MgmtSettings::ADVERTISING.bits(), 1 << 10);
        assert_eq!(MgmtSettings::SECURE_CONN.bits(), 1 << 11);
        assert_eq!(MgmtSettings::DEBUG_KEYS.bits(), 1 << 12);
        assert_eq!(MgmtSettings::PRIVACY.bits(), 1 << 13);
        assert_eq!(MgmtSettings::STATIC_ADDRESS.bits(), 1 << 15);
        assert_eq!(MgmtSettings::WIDEBAND_SPEECH.bits(), 1 << 17);
    }

    #[test]
    fn test_settings_empty() {
        let empty = MgmtSettings::empty();
        assert_eq!(empty.bits(), 0);
        assert!(!empty.contains(MgmtSettings::POWERED));
    }

    // ---- Command opcodes (from test-mgmt.c command_test_data) ----

    #[test]
    fn test_opcode_values() {
        assert_eq!(MGMT_OP_READ_VERSION, 0x0001);
        assert_eq!(MGMT_OP_READ_COMMANDS, 0x0002);
        assert_eq!(MGMT_OP_READ_INDEX_LIST, 0x0003);
        assert_eq!(MGMT_OP_READ_INFO, 0x0004);
        assert_eq!(MGMT_OP_SET_POWERED, 0x0005);
        assert_eq!(MGMT_OP_START_DISCOVERY, 0x0023);
        assert_eq!(MGMT_OP_HCI_CMD_SYNC, 0x005B);
    }

    #[test]
    fn test_opcode_sequential() {
        // Verify opcodes are sequential from test-mgmt.c expectations
        assert_eq!(MGMT_OP_SET_DISCOVERABLE, MGMT_OP_SET_POWERED + 1);
        assert_eq!(MGMT_OP_SET_CONNECTABLE, MGMT_OP_SET_DISCOVERABLE + 1);
        assert_eq!(MGMT_OP_SET_FAST_CONNECTABLE, MGMT_OP_SET_CONNECTABLE + 1);
        assert_eq!(MGMT_OP_SET_BONDABLE, MGMT_OP_SET_FAST_CONNECTABLE + 1);
    }

    #[test]
    fn test_opcode_pair_device_range() {
        assert_eq!(MGMT_OP_PAIR_DEVICE, 0x0019);
        assert_eq!(MGMT_OP_CANCEL_PAIR_DEVICE, 0x001A);
        assert_eq!(MGMT_OP_UNPAIR_DEVICE, 0x001B);
    }

    // ---- Event codes (from test-mgmt.c handler matching) ----

    #[test]
    fn test_event_values() {
        assert_eq!(MGMT_EV_CMD_COMPLETE, 0x0001);
        assert_eq!(MGMT_EV_CMD_STATUS, 0x0002);
        assert_eq!(MGMT_EV_CONTROLLER_ERROR, 0x0003);
        assert_eq!(MGMT_EV_INDEX_ADDED, 0x0004);
        assert_eq!(MGMT_EV_INDEX_REMOVED, 0x0005);
        assert_eq!(MGMT_EV_DEVICE_CONNECTED, 0x000B);
        assert_eq!(MGMT_EV_DEVICE_FOUND, 0x0012);
        assert_eq!(MGMT_EV_MESH_PACKET_CMPLT, 0x0032);
    }

    #[test]
    fn test_event_discovery() {
        assert_eq!(MGMT_EV_DISCOVERING, 0x0013);
    }

    // ---- Struct sizes (from test-mgmt.c wire format) ----

    #[test]
    fn test_read_version_rsp_size() {
        assert_eq!(mem::size_of::<MgmtRpReadVersion>(), 3);
    }

    #[test]
    fn test_cmd_complete_size() {
        assert_eq!(mem::size_of::<MgmtEvCmdComplete>(), 3);
    }

    #[test]
    fn test_mgmt_mode_size() {
        assert_eq!(mem::size_of::<MgmtMode>(), 1);
    }

    #[test]
    fn test_mgmt_cod_size() {
        assert_eq!(mem::size_of::<MgmtCod>(), 3);
    }

    // ---- Index constants ----

    #[test]
    fn test_index_none() {
        assert_eq!(MGMT_INDEX_NONE, 0xFFFF);
    }

    // ---- Address type constants ----

    #[test]
    fn test_addr_types() {
        assert_eq!(MGMT_ADDR_BREDR, 0x01);
        assert_eq!(MGMT_ADDR_LE_PUBLIC, 0x02);
        assert_eq!(MGMT_ADDR_LE_RANDOM, 0x03);
    }

    // ---- Name length constants ----

    #[test]
    fn test_name_lengths() {
        assert_eq!(MGMT_MAX_NAME_LENGTH, 249);
        assert_eq!(MGMT_MAX_SHORT_NAME_LENGTH, 11);
    }
}
