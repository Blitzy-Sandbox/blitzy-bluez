// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Rust re-declaration of the Linux Kernel Bluetooth Management (MGMT) protocol
// definitions from `lib/bluetooth/mgmt.h`.  This module contains:
//
// - MGMT packet header (`mgmt_hdr`) and TLV framing (`mgmt_tlv`)
// - Address info struct (`mgmt_addr_info`) used in most command/event params
// - All MGMT status codes (`MGMT_STATUS_*`)
// - All MGMT setting flags (`MgmtSettings` bitflags)
// - All MGMT opcodes (`MGMT_OP_*`) with their command parameter (`cp_*`)
//   and return parameter (`rp_*`) packed structs
// - All MGMT event codes (`MGMT_EV_*`) with their event parameter (`ev_*`)
//   packed structs
// - Advertising flags (`MgmtAdvFlags`), PHY flags (`MgmtPhys`), device
//   disconnect reasons, and device-found flags
// - String lookup tables and stringification functions (`mgmt_opstr`,
//   `mgmt_evstr`, `mgmt_errstr`) matching the C originals character-for-character
//
// All packed structs are `#[repr(C, packed)]` for kernel ABI wire compatibility.
// All multi-byte integer fields are little-endian on the wire.

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// Core Constants
// ---------------------------------------------------------------------------

/// Sentinel value indicating a non-controller-specific (global) MGMT command.
pub const MGMT_INDEX_NONE: u16 = 0xFFFF;

/// Size of the MGMT packet header in bytes.
pub const MGMT_HDR_SIZE: usize = 6;

// ---------------------------------------------------------------------------
// Core Framing Structs
// ---------------------------------------------------------------------------

/// MGMT protocol packet header (6 bytes, little-endian on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_hdr {
    /// Command opcode or event code (little-endian).
    pub opcode: u16,
    /// Controller index or `MGMT_INDEX_NONE` (little-endian).
    pub index: u16,
    /// Length of the parameter payload following this header (little-endian).
    pub len: u16,
}

/// MGMT Type-Length-Value entry used in system/runtime configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_tlv {
    /// TLV type identifier (little-endian).
    pub type_: u16,
    /// Length of the value data following this header.
    pub length: u8,
}

/// MGMT address info — a Bluetooth device address plus address type (7 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_addr_info {
    /// 6-byte Bluetooth device address.
    pub bdaddr: bdaddr_t,
    /// Address type (`MGMT_ADDR_BREDR`, `MGMT_ADDR_LE_PUBLIC`, or `MGMT_ADDR_LE_RANDOM`).
    pub type_: u8,
}

// ---------------------------------------------------------------------------
// Address Type Constants
// ---------------------------------------------------------------------------

/// Address type: BR/EDR (classic Bluetooth).
pub const MGMT_ADDR_BREDR: u8 = 0x00;
/// Address type: LE Public.
pub const MGMT_ADDR_LE_PUBLIC: u8 = 0x01;
/// Address type: LE Random.
pub const MGMT_ADDR_LE_RANDOM: u8 = 0x02;

// ---------------------------------------------------------------------------
// Status Codes
// ---------------------------------------------------------------------------

pub const MGMT_STATUS_SUCCESS: u8 = 0x00;
pub const MGMT_STATUS_UNKNOWN_COMMAND: u8 = 0x01;
pub const MGMT_STATUS_NOT_CONNECTED: u8 = 0x02;
pub const MGMT_STATUS_FAILED: u8 = 0x03;
pub const MGMT_STATUS_CONNECT_FAILED: u8 = 0x04;
pub const MGMT_STATUS_AUTH_FAILED: u8 = 0x05;
pub const MGMT_STATUS_NOT_PAIRED: u8 = 0x06;
pub const MGMT_STATUS_NO_RESOURCES: u8 = 0x07;
pub const MGMT_STATUS_TIMEOUT: u8 = 0x08;
pub const MGMT_STATUS_ALREADY_CONNECTED: u8 = 0x09;
pub const MGMT_STATUS_BUSY: u8 = 0x0a;
pub const MGMT_STATUS_REJECTED: u8 = 0x0b;
pub const MGMT_STATUS_NOT_SUPPORTED: u8 = 0x0c;
pub const MGMT_STATUS_INVALID_PARAMS: u8 = 0x0d;
pub const MGMT_STATUS_DISCONNECTED: u8 = 0x0e;
pub const MGMT_STATUS_NOT_POWERED: u8 = 0x0f;
pub const MGMT_STATUS_CANCELLED: u8 = 0x10;
pub const MGMT_STATUS_INVALID_INDEX: u8 = 0x11;
pub const MGMT_STATUS_RFKILLED: u8 = 0x12;
pub const MGMT_STATUS_ALREADY_PAIRED: u8 = 0x13;
pub const MGMT_STATUS_PERMISSION_DENIED: u8 = 0x14;
pub const MGMT_STATUS_NOT_ESTABLISHED: u8 = 0x15;

// ---------------------------------------------------------------------------
// Settings Bitflags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Controller setting flags reported in `mgmt_rp_read_info`.
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

// ---------------------------------------------------------------------------
// Name Length Constants
// ---------------------------------------------------------------------------

/// Maximum length of a Bluetooth device name (248 + 1 for NUL terminator).
pub const MGMT_MAX_NAME_LENGTH: usize = 249;
/// Maximum length of a short Bluetooth device name (10 + 1 for NUL terminator).
pub const MGMT_MAX_SHORT_NAME_LENGTH: usize = 11;

// ---------------------------------------------------------------------------
// Helper Structs
// ---------------------------------------------------------------------------

/// Boolean mode value used by SET_POWERED, SET_CONNECTABLE, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_mode {
    pub val: u8,
}

/// Class of Device (3-byte packed value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cod {
    pub val: [u8; 3],
}

// ---------------------------------------------------------------------------
// Key Info Structs
// ---------------------------------------------------------------------------

/// Link key information for BR/EDR pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_link_key_info {
    pub addr: mgmt_addr_info,
    pub type_: u8,
    pub val: [u8; 16],
    pub pin_len: u8,
}

/// Long-Term Key information for LE pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ltk_info {
    pub addr: mgmt_addr_info,
    pub type_: u8,
    pub master: u8,
    pub enc_size: u8,
    pub ediv: u16,
    pub rand: u64,
    pub val: [u8; 16],
}

/// Identity Resolving Key information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_irk_info {
    pub addr: mgmt_addr_info,
    pub val: [u8; 16],
}

/// Connection Signature Resolving Key information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_csrk_info {
    pub addr: mgmt_addr_info,
    pub type_: u8,
    pub val: [u8; 16],
}

/// LE connection parameter entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_conn_param {
    pub addr: mgmt_addr_info,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

/// Blocked key entry for SET_BLOCKED_KEYS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_blocked_key_info {
    pub type_: u8,
    pub val: [u8; 16],
}

/// Advertisement monitor pattern entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_adv_pattern {
    pub ad_type: u8,
    pub offset: u8,
    pub length: u8,
    pub value: [u8; 31],
}

/// RSSI threshold parameters for advertisement monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_adv_rssi_thresholds {
    pub high_threshold: i8,
    pub high_threshold_timeout: u16,
    pub low_threshold: i8,
    pub low_threshold_timeout: u16,
    pub sampling_period: u8,
}

// ---------------------------------------------------------------------------
// Blocked Key Type Constants
// ---------------------------------------------------------------------------

pub const HCI_BLOCKED_KEY_TYPE_LINKKEY: u8 = 0x00;
pub const HCI_BLOCKED_KEY_TYPE_LTK: u8 = 0x01;
pub const HCI_BLOCKED_KEY_TYPE_IRK: u8 = 0x02;

// ---------------------------------------------------------------------------
// Controller Capability TLV Type Constants
// ---------------------------------------------------------------------------

pub const MGMT_CAP_SEC_FLAGS: u8 = 0x01;
pub const MGMT_CAP_MAX_ENC_KEY_SIZE: u8 = 0x02;
pub const MGMT_CAP_SMP_MAX_ENC_KEY_SIZE: u8 = 0x03;
pub const MGMT_CAP_LE_TX_PWR: u8 = 0x04;

// ---------------------------------------------------------------------------
// Configuration Option Constants
// ---------------------------------------------------------------------------

pub const MGMT_OPTION_EXTERNAL_CONFIG: u32 = 0x0000_0001;
pub const MGMT_OPTION_PUBLIC_ADDRESS: u32 = 0x0000_0002;

// ---------------------------------------------------------------------------
// Device Flag Constants
// ---------------------------------------------------------------------------

pub const DEVICE_FLAG_REMOTE_WAKEUP: u32 = 1 << 0;
pub const DEVICE_FLAG_DEVICE_PRIVACY: u32 = 1 << 1;
pub const DEVICE_FLAG_ADDRESS_RESOLUTION: u32 = 1 << 2;
pub const DEVICE_FLAG_PAST: u32 = 1 << 3;

// ===========================================================================
// MGMT Opcodes and Command/Return Parameter Structs
// ===========================================================================

pub const MGMT_OP_READ_VERSION: u16 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_version {
    pub version: u8,
    pub revision: u16,
}

pub const MGMT_OP_READ_COMMANDS: u16 = 0x0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_commands {
    pub num_commands: u16,
    pub num_events: u16,
}

pub const MGMT_OP_READ_INDEX_LIST: u16 = 0x0003;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_index_list {
    pub num_controllers: u16,
    pub index: [u16; 0],
}

pub const MGMT_OP_READ_INFO: u16 = 0x0004;

#[derive(Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_info {
    pub bdaddr: bdaddr_t,
    pub version: u8,
    pub manufacturer: u16,
    pub supported_settings: u32,
    pub current_settings: u32,
    pub dev_class: [u8; 3],
    pub name: [u8; MGMT_MAX_NAME_LENGTH],
    pub short_name: [u8; MGMT_MAX_SHORT_NAME_LENGTH],
}

impl core::fmt::Debug for mgmt_rp_read_info {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("mgmt_rp_read_info")
            .field("bdaddr", &self.bdaddr)
            .field("version", &{ self.version })
            .field("manufacturer", &{ self.manufacturer })
            .field("supported_settings", &{ self.supported_settings })
            .field("current_settings", &{ self.current_settings })
            .field("dev_class", &self.dev_class)
            .finish()
    }
}

pub const MGMT_OP_SET_POWERED: u16 = 0x0005;

pub const MGMT_OP_SET_DISCOVERABLE: u16 = 0x0006;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_discoverable {
    pub val: u8,
    pub timeout: u16,
}

pub const MGMT_OP_SET_CONNECTABLE: u16 = 0x0007;
pub const MGMT_OP_SET_FAST_CONNECTABLE: u16 = 0x0008;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_fast_connectable {
    pub val: u8,
}

pub const MGMT_OP_SET_BONDABLE: u16 = 0x0009;
pub const MGMT_OP_SET_LINK_SECURITY: u16 = 0x000A;
pub const MGMT_OP_SET_SSP: u16 = 0x000B;
pub const MGMT_OP_SET_HS: u16 = 0x000C;
pub const MGMT_OP_SET_LE: u16 = 0x000D;

pub const MGMT_OP_SET_DEV_CLASS: u16 = 0x000E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_dev_class {
    pub major: u8,
    pub minor: u8,
}

pub const MGMT_OP_SET_LOCAL_NAME: u16 = 0x000F;

#[derive(Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_local_name {
    pub name: [u8; MGMT_MAX_NAME_LENGTH],
    pub short_name: [u8; MGMT_MAX_SHORT_NAME_LENGTH],
}

impl core::fmt::Debug for mgmt_cp_set_local_name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("mgmt_cp_set_local_name").finish()
    }
}

pub const MGMT_OP_ADD_UUID: u16 = 0x0010;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_uuid {
    pub uuid: [u8; 16],
    pub svc_hint: u8,
}

pub const MGMT_OP_REMOVE_UUID: u16 = 0x0011;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_remove_uuid {
    pub uuid: [u8; 16],
}

pub const MGMT_OP_LOAD_LINK_KEYS: u16 = 0x0012;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_load_link_keys {
    pub debug_keys: u8,
    pub key_count: u16,
    pub keys: [mgmt_link_key_info; 0],
}

pub const MGMT_OP_LOAD_LONG_TERM_KEYS: u16 = 0x0013;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_load_long_term_keys {
    pub key_count: u16,
    pub keys: [mgmt_ltk_info; 0],
}

pub const MGMT_OP_DISCONNECT: u16 = 0x0014;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_disconnect {
    pub addr: mgmt_addr_info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_disconnect {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_GET_CONNECTIONS: u16 = 0x0015;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_get_connections {
    pub conn_count: u16,
}

pub const MGMT_OP_PIN_CODE_REPLY: u16 = 0x0016;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_pin_code_reply {
    pub addr: mgmt_addr_info,
    pub pin_len: u8,
    pub pin_code: [u8; 16],
}

pub const MGMT_OP_PIN_CODE_NEG_REPLY: u16 = 0x0017;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_pin_code_neg_reply {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_SET_IO_CAPABILITY: u16 = 0x0018;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_io_capability {
    pub io_capability: u8,
}

pub const MGMT_OP_PAIR_DEVICE: u16 = 0x0019;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_pair_device {
    pub addr: mgmt_addr_info,
    pub io_cap: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_pair_device {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_CANCEL_PAIR_DEVICE: u16 = 0x001A;

pub const MGMT_OP_UNPAIR_DEVICE: u16 = 0x001B;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_unpair_device {
    pub addr: mgmt_addr_info,
    pub disconnect: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_unpair_device {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_USER_CONFIRM_REPLY: u16 = 0x001C;
pub const MGMT_OP_USER_CONFIRM_NEG_REPLY: u16 = 0x001D;
pub const MGMT_OP_USER_PASSKEY_REPLY: u16 = 0x001E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_user_passkey_reply {
    pub addr: mgmt_addr_info,
    pub passkey: u32,
}

pub const MGMT_OP_USER_PASSKEY_NEG_REPLY: u16 = 0x001F;

pub const MGMT_OP_READ_LOCAL_OOB_DATA: u16 = 0x0020;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_local_oob_data {
    pub hash192: [u8; 16],
    pub rand192: [u8; 16],
    pub hash256: [u8; 16],
    pub rand256: [u8; 16],
}

pub const MGMT_OP_ADD_REMOTE_OOB_DATA: u16 = 0x0021;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_remote_oob_data {
    pub addr: mgmt_addr_info,
    pub hash192: [u8; 16],
    pub rand192: [u8; 16],
    pub hash256: [u8; 16],
    pub rand256: [u8; 16],
}

pub const MGMT_OP_REMOVE_REMOTE_OOB_DATA: u16 = 0x0022;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_remove_remote_oob_data {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_START_DISCOVERY: u16 = 0x0023;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_start_discovery {
    pub type_: u8,
}

pub const MGMT_OP_STOP_DISCOVERY: u16 = 0x0024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_stop_discovery {
    pub type_: u8,
}

pub const MGMT_OP_CONFIRM_NAME: u16 = 0x0025;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_confirm_name {
    pub addr: mgmt_addr_info,
    pub name_known: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_confirm_name {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_BLOCK_DEVICE: u16 = 0x0026;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_block_device {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_UNBLOCK_DEVICE: u16 = 0x0027;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_unblock_device {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_SET_DEVICE_ID: u16 = 0x0028;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_device_id {
    pub source: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

pub const MGMT_OP_SET_ADVERTISING: u16 = 0x0029;
pub const MGMT_OP_SET_BREDR: u16 = 0x002A;

pub const MGMT_OP_SET_STATIC_ADDRESS: u16 = 0x002B;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_static_address {
    pub bdaddr: bdaddr_t,
}

pub const MGMT_OP_SET_SCAN_PARAMS: u16 = 0x002C;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_scan_params {
    pub interval: u16,
    pub window: u16,
}

pub const MGMT_OP_SET_SECURE_CONN: u16 = 0x002D;
pub const MGMT_OP_SET_DEBUG_KEYS: u16 = 0x002E;

pub const MGMT_OP_SET_PRIVACY: u16 = 0x002F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_privacy {
    pub privacy: u8,
    pub irk: [u8; 16],
}

pub const MGMT_OP_LOAD_IRKS: u16 = 0x0030;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_load_irks {
    pub irk_count: u16,
    pub irks: [mgmt_irk_info; 0],
}

pub const MGMT_OP_GET_CONN_INFO: u16 = 0x0031;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_get_conn_info {
    pub addr: mgmt_addr_info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_get_conn_info {
    pub addr: mgmt_addr_info,
    pub rssi: i8,
    pub tx_power: i8,
    pub max_tx_power: i8,
}

pub const MGMT_OP_GET_CLOCK_INFO: u16 = 0x0032;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_get_clock_info {
    pub addr: mgmt_addr_info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_get_clock_info {
    pub addr: mgmt_addr_info,
    pub local_clock: u32,
    pub piconet_clock: u32,
    pub accuracy: u16,
}

pub const MGMT_OP_ADD_DEVICE: u16 = 0x0033;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_device {
    pub addr: mgmt_addr_info,
    pub action: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_add_device {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_REMOVE_DEVICE: u16 = 0x0034;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_remove_device {
    pub addr: mgmt_addr_info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_remove_device {
    pub addr: mgmt_addr_info,
}

pub const MGMT_OP_LOAD_CONN_PARAM: u16 = 0x0035;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_load_conn_param {
    pub param_count: u16,
}

pub const MGMT_OP_READ_UNCONF_INDEX_LIST: u16 = 0x0036;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_unconf_index_list {
    pub num_controllers: u16,
}

pub const MGMT_OP_READ_CONFIG_INFO: u16 = 0x0037;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_config_info {
    pub manufacturer: u16,
    pub supported_options: u32,
    pub missing_options: u32,
}

pub const MGMT_OP_SET_EXTERNAL_CONFIG: u16 = 0x0038;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_external_config {
    pub config: u8,
}

pub const MGMT_OP_SET_PUBLIC_ADDRESS: u16 = 0x0039;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_public_address {
    pub bdaddr: bdaddr_t,
}

pub const MGMT_OP_START_SERVICE_DISCOVERY: u16 = 0x003A;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_start_service_discovery {
    pub type_: u8,
    pub rssi: i8,
    pub uuid_count: u16,
}

pub const MGMT_OP_READ_LOCAL_OOB_EXT_DATA: u16 = 0x003B;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_read_local_oob_ext_data {
    pub type_: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_local_oob_ext_data {
    pub type_: u8,
    pub eir_len: u16,
}

pub const MGMT_OP_READ_EXT_INDEX_LIST: u16 = 0x003C;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_ext_index_list {
    pub num_controllers: u16,
}

pub const MGMT_OP_READ_ADV_FEATURES: u16 = 0x003D;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_adv_features {
    pub supported_flags: u32,
    pub max_adv_data_len: u8,
    pub max_scan_rsp_len: u8,
    pub max_instances: u8,
    pub num_instances: u8,
}

pub const MGMT_OP_ADD_ADVERTISING: u16 = 0x003E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_advertising {
    pub instance: u8,
    pub flags: u32,
    pub duration: u16,
    pub timeout: u16,
    pub adv_data_len: u8,
    pub scan_rsp_len: u8,
    pub data: [u8; 0],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_add_advertising {
    pub instance: u8,
}

// ---------------------------------------------------------------------------
// Advertising Flags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Advertising flags for ADD_ADVERTISING and ADD_EXT_ADV_PARAMS.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MgmtAdvFlags: u32 {
        const CONNECTABLE          = 1 << 0;
        const DISCOVERABLE         = 1 << 1;
        const LIMITED_DISCOVERABLE = 1 << 2;
        const MANAGED_FLAGS        = 1 << 3;
        const TX_POWER             = 1 << 4;
        const APPEARANCE           = 1 << 5;
        const LOCAL_NAME           = 1 << 6;
        const SEC_1M               = 1 << 7;
        const SEC_2M               = 1 << 8;
        const SEC_CODED            = 1 << 9;
        const CAN_SET_TX_POWER     = 1 << 10;
        const HW_OFFLOAD           = 1 << 11;
        const PARAM_DURATION       = 1 << 12;
        const PARAM_TIMEOUT        = 1 << 13;
        const PARAM_INTERVALS      = 1 << 14;
        const PARAM_TX_POWER       = 1 << 15;
        const PARAM_SCAN_RSP       = 1 << 16;
    }
}

/// Bitmask of secondary advertising PHY flags.
pub const MGMT_ADV_FLAG_SEC_MASK: u32 =
    MgmtAdvFlags::SEC_1M.bits() | MgmtAdvFlags::SEC_2M.bits() | MgmtAdvFlags::SEC_CODED.bits();

// ---------------------------------------------------------------------------
// Remaining Opcodes (0x003F – 0x005B)
// ---------------------------------------------------------------------------

pub const MGMT_OP_REMOVE_ADVERTISING: u16 = 0x003F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_remove_advertising {
    pub instance: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_remove_advertising {
    pub instance: u8,
}

pub const MGMT_OP_GET_ADV_SIZE_INFO: u16 = 0x0040;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_get_adv_size_info {
    pub instance: u8,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_get_adv_size_info {
    pub instance: u8,
    pub flags: u32,
    pub max_adv_data_len: u8,
    pub max_scan_rsp_len: u8,
}

pub const MGMT_OP_START_LIMITED_DISCOVERY: u16 = 0x0041;

pub const MGMT_OP_READ_EXT_INFO: u16 = 0x0042;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_ext_info {
    pub bdaddr: bdaddr_t,
    pub version: u8,
    pub manufacturer: u16,
    pub supported_settings: u32,
    pub current_settings: u32,
    pub eir_len: u16,
}

pub const MGMT_OP_SET_APPEARANCE: u16 = 0x0043;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_appearance {
    pub appearance: u16,
}

pub const MGMT_OP_GET_PHY_CONFIGURATION: u16 = 0x0044;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_get_phy_confguration {
    pub supported_phys: u32,
    pub configurable_phys: u32,
    pub selected_phys: u32,
}

pub const MGMT_OP_SET_PHY_CONFIGURATION: u16 = 0x0045;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_phy_confguration {
    pub selected_phys: u32,
}

// ---------------------------------------------------------------------------
// PHY Flags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// PHY configuration flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MgmtPhys: u32 {
        const BR_1M_1SLOT   = 1 << 0;
        const BR_1M_3SLOT   = 1 << 1;
        const BR_1M_5SLOT   = 1 << 2;
        const EDR_2M_1SLOT  = 1 << 3;
        const EDR_2M_3SLOT  = 1 << 4;
        const EDR_2M_5SLOT  = 1 << 5;
        const EDR_3M_1SLOT  = 1 << 6;
        const EDR_3M_3SLOT  = 1 << 7;
        const EDR_3M_5SLOT  = 1 << 8;
        const LE_1M_TX      = 1 << 9;
        const LE_1M_RX      = 1 << 10;
        const LE_2M_TX      = 1 << 11;
        const LE_2M_RX      = 1 << 12;
        const LE_CODED_TX   = 1 << 13;
        const LE_CODED_RX   = 1 << 14;
    }
}

/// Bitmask of LE TX PHY flags.
pub const MGMT_PHY_LE_TX_MASK: u32 =
    MgmtPhys::LE_1M_TX.bits() | MgmtPhys::LE_2M_TX.bits() | MgmtPhys::LE_CODED_TX.bits();
/// Bitmask of LE RX PHY flags.
pub const MGMT_PHY_LE_RX_MASK: u32 =
    MgmtPhys::LE_1M_RX.bits() | MgmtPhys::LE_2M_RX.bits() | MgmtPhys::LE_CODED_RX.bits();

pub const MGMT_OP_SET_BLOCKED_KEYS: u16 = 0x0046;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_blocked_keys {
    pub key_count: u16,
    pub keys: [mgmt_blocked_key_info; 0],
}

pub const MGMT_OP_SET_WIDEBAND_SPEECH: u16 = 0x0047;

pub const MGMT_OP_READ_CONTROLLER_CAP: u16 = 0x0048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_controller_cap {
    pub cap_len: u16,
}

pub const MGMT_OP_READ_EXP_FEATURES_INFO: u16 = 0x0049;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_exp_features {
    pub feature_count: u16,
    pub features: [u8; 0],
}

pub const MGMT_OP_SET_EXP_FEATURE: u16 = 0x004A;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_exp_feature {
    pub uuid: [u8; 16],
    pub action: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_set_exp_feature {
    pub uuid: [u8; 16],
    pub flags: u32,
}

pub const MGMT_OP_READ_DEF_SYSTEM_CONFIG: u16 = 0x004B;
pub const MGMT_OP_SET_DEF_SYSTEM_CONFIG: u16 = 0x004C;
pub const MGMT_OP_READ_DEF_RUNTIME_CONFIG: u16 = 0x004D;
pub const MGMT_OP_SET_DEF_RUNTIME_CONFIG: u16 = 0x004E;

pub const MGMT_OP_GET_DEVICE_FLAGS: u16 = 0x004F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_get_device_flags {
    pub addr: mgmt_addr_info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_get_device_flags {
    pub addr: mgmt_addr_info,
    pub supported_flags: u32,
    pub current_flags: u32,
}

pub const MGMT_OP_SET_DEVICE_FLAGS: u16 = 0x0050;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_device_flags {
    pub addr: mgmt_addr_info,
    pub current_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_set_device_flags {
    pub addr: mgmt_addr_info,
}

/// Advertisement monitor feature: OR-based pattern matching.
pub const MGMT_ADV_MONITOR_FEATURE_MASK_OR_PATTERNS: u32 = 1 << 0;

pub const MGMT_OP_READ_ADV_MONITOR_FEATURES: u16 = 0x0051;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_read_adv_monitor_features {
    pub supported_features: u32,
    pub enabled_features: u32,
    pub max_num_handles: u16,
    pub max_num_patterns: u8,
    pub num_handles: u16,
}

pub const MGMT_OP_ADD_ADV_PATTERNS_MONITOR: u16 = 0x0052;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_adv_monitor {
    pub pattern_count: u8,
    pub patterns: [mgmt_adv_pattern; 0],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_add_adv_patterns_monitor {
    pub monitor_handle: u16,
}

pub const MGMT_OP_REMOVE_ADV_MONITOR: u16 = 0x0053;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_remove_adv_monitor {
    pub monitor_handle: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_remove_adv_monitor {
    pub monitor_handle: u16,
}

pub const MGMT_OP_ADD_EXT_ADV_PARAMS: u16 = 0x0054;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_ext_adv_params {
    pub instance: u8,
    pub flags: u32,
    pub duration: u16,
    pub timeout: u16,
    pub min_interval: u32,
    pub max_interval: u32,
    pub tx_power: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_add_ext_adv_params {
    pub instance: u8,
    pub tx_power: i8,
    pub max_adv_data_len: u8,
    pub max_scan_rsp_len: u8,
}

pub const MGMT_OP_ADD_EXT_ADV_DATA: u16 = 0x0055;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_ext_adv_data {
    pub instance: u8,
    pub adv_data_len: u8,
    pub scan_rsp_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_add_ext_adv_data {
    pub instance: u8,
}

pub const MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI: u16 = 0x0056;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_add_adv_patterns_monitor_rssi {
    pub rssi: mgmt_adv_rssi_thresholds,
    pub pattern_count: u8,
    pub patterns: [mgmt_adv_pattern; 0],
}

pub const MGMT_OP_SET_MESH_RECEIVER: u16 = 0x0057;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_set_mesh {
    pub enable: u8,
    pub window: u16,
    pub period: u16,
    pub num_ad_types: u8,
    pub ad_types: [u8; 0],
}

pub const MGMT_OP_MESH_READ_FEATURES: u16 = 0x0058;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_rp_mesh_read_features {
    pub index: u16,
    pub max_handles: u8,
    pub used_handles: u8,
}

pub const MGMT_OP_MESH_SEND: u16 = 0x0059;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_mesh_send {
    pub addr: mgmt_addr_info,
    pub instant: u64,
    pub delay: u16,
    pub cnt: u8,
    pub adv_data_len: u8,
    pub adv_data: [u8; 0],
}

pub const MGMT_OP_MESH_SEND_CANCEL: u16 = 0x005A;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_mesh_send_cancel {
    pub handle: u8,
}

pub const MGMT_OP_HCI_CMD_SYNC: u16 = 0x005B;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_cp_hci_cmd_sync {
    pub opcode: u16,
    pub event: u8,
    pub timeout: u8,
    pub params_len: u16,
    pub params: [u8; 0],
}

// ===========================================================================
// MGMT Event Codes and Event Parameter Structs
// ===========================================================================

pub const MGMT_EV_CMD_COMPLETE: u16 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_cmd_complete {
    pub opcode: u16,
    pub status: u8,
    pub data: [u8; 0],
}

pub const MGMT_EV_CMD_STATUS: u16 = 0x0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_cmd_status {
    pub opcode: u16,
    pub status: u8,
}

pub const MGMT_EV_CONTROLLER_ERROR: u16 = 0x0003;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_controller_error {
    pub error_code: u8,
}

pub const MGMT_EV_INDEX_ADDED: u16 = 0x0004;
pub const MGMT_EV_INDEX_REMOVED: u16 = 0x0005;
pub const MGMT_EV_NEW_SETTINGS: u16 = 0x0006;

pub const MGMT_EV_CLASS_OF_DEV_CHANGED: u16 = 0x0007;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_class_of_dev_changed {
    pub dev_class: [u8; 3],
}

pub const MGMT_EV_LOCAL_NAME_CHANGED: u16 = 0x0008;

#[derive(Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_local_name_changed {
    pub name: [u8; MGMT_MAX_NAME_LENGTH],
    pub short_name: [u8; MGMT_MAX_SHORT_NAME_LENGTH],
}

impl core::fmt::Debug for mgmt_ev_local_name_changed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("mgmt_ev_local_name_changed").finish()
    }
}

pub const MGMT_EV_NEW_LINK_KEY: u16 = 0x0009;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_new_link_key {
    pub store_hint: u8,
    pub key: mgmt_link_key_info,
}

pub const MGMT_EV_NEW_LONG_TERM_KEY: u16 = 0x000A;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_new_long_term_key {
    pub store_hint: u8,
    pub key: mgmt_ltk_info,
}

pub const MGMT_EV_DEVICE_CONNECTED: u16 = 0x000B;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_device_connected {
    pub addr: mgmt_addr_info,
    pub flags: u32,
    pub eir_len: u16,
    pub eir: [u8; 0],
}

// Disconnect reason constants
pub const MGMT_DEV_DISCONN_UNKNOWN: u8 = 0x00;
pub const MGMT_DEV_DISCONN_TIMEOUT: u8 = 0x01;
pub const MGMT_DEV_DISCONN_LOCAL_HOST: u8 = 0x02;
pub const MGMT_DEV_DISCONN_REMOTE: u8 = 0x03;
pub const MGMT_DEV_DISCONN_AUTH_FAILURE: u8 = 0x04;
pub const MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND: u8 = 0x05;

pub const MGMT_EV_DEVICE_DISCONNECTED: u16 = 0x000C;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_device_disconnected {
    pub addr: mgmt_addr_info,
    pub reason: u8,
}

pub const MGMT_EV_CONNECT_FAILED: u16 = 0x000D;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_connect_failed {
    pub addr: mgmt_addr_info,
    pub status: u8,
}

pub const MGMT_EV_PIN_CODE_REQUEST: u16 = 0x000E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_pin_code_request {
    pub addr: mgmt_addr_info,
    pub secure: u8,
}

pub const MGMT_EV_USER_CONFIRM_REQUEST: u16 = 0x000F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_user_confirm_request {
    pub addr: mgmt_addr_info,
    pub confirm_hint: u8,
    pub value: u32,
}

pub const MGMT_EV_USER_PASSKEY_REQUEST: u16 = 0x0010;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_user_passkey_request {
    pub addr: mgmt_addr_info,
}

pub const MGMT_EV_AUTH_FAILED: u16 = 0x0011;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_auth_failed {
    pub addr: mgmt_addr_info,
    pub status: u8,
}

// Device Found flags
pub const MGMT_DEV_FOUND_CONFIRM_NAME: u32 = 1 << 0;
pub const MGMT_DEV_FOUND_LEGACY_PAIRING: u32 = 1 << 1;
pub const MGMT_DEV_FOUND_NOT_CONNECTABLE: u32 = 1 << 2;
pub const MGMT_DEV_FOUND_INITIATED_CONN: u32 = 1 << 3;
pub const MGMT_DEV_FOUND_NAME_REQUEST_FAILED: u32 = 1 << 4;
pub const MGMT_DEV_FOUND_SCAN_RSP: u32 = 1 << 5;

pub const MGMT_EV_DEVICE_FOUND: u16 = 0x0012;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_device_found {
    pub addr: mgmt_addr_info,
    pub rssi: i8,
    pub flags: u32,
    pub eir_len: u16,
    pub eir: [u8; 0],
}

pub const MGMT_EV_DISCOVERING: u16 = 0x0013;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_discovering {
    pub type_: u8,
    pub discovering: u8,
}

pub const MGMT_EV_DEVICE_BLOCKED: u16 = 0x0014;
pub const MGMT_EV_DEVICE_UNBLOCKED: u16 = 0x0015;
pub const MGMT_EV_DEVICE_UNPAIRED: u16 = 0x0016;

pub const MGMT_EV_PASSKEY_NOTIFY: u16 = 0x0017;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_passkey_notify {
    pub addr: mgmt_addr_info,
    pub passkey: u32,
    pub entered: u8,
}

pub const MGMT_EV_NEW_IRK: u16 = 0x0018;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_new_irk {
    pub store_hint: u8,
    pub rpa: bdaddr_t,
    pub key: mgmt_irk_info,
}

pub const MGMT_EV_NEW_CSRK: u16 = 0x0019;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_new_csrk {
    pub store_hint: u8,
    pub key: mgmt_csrk_info,
}

pub const MGMT_EV_DEVICE_ADDED: u16 = 0x001A;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_device_added {
    pub addr: mgmt_addr_info,
    pub action: u8,
}

pub const MGMT_EV_DEVICE_REMOVED: u16 = 0x001B;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_device_removed {
    pub addr: mgmt_addr_info,
}

pub const MGMT_EV_NEW_CONN_PARAM: u16 = 0x001C;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_new_conn_param {
    pub addr: mgmt_addr_info,
    pub store_hint: u8,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

pub const MGMT_EV_UNCONF_INDEX_ADDED: u16 = 0x001D;
pub const MGMT_EV_UNCONF_INDEX_REMOVED: u16 = 0x001E;
pub const MGMT_EV_NEW_CONFIG_OPTIONS: u16 = 0x001F;

pub const MGMT_EV_EXT_INDEX_ADDED: u16 = 0x0020;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_ext_index {
    pub type_: u8,
    pub bus: u8,
}

pub const MGMT_EV_EXT_INDEX_REMOVED: u16 = 0x0021;

pub const MGMT_EV_LOCAL_OOB_DATA_UPDATED: u16 = 0x0022;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_local_oob_data_updated {
    pub type_: u8,
    pub eir_len: u16,
}

pub const MGMT_EV_ADVERTISING_ADDED: u16 = 0x0023;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_advertising_added {
    pub instance: u8,
}

pub const MGMT_EV_ADVERTISING_REMOVED: u16 = 0x0024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_advertising_removed {
    pub instance: u8,
}

pub const MGMT_EV_EXT_INFO_CHANGED: u16 = 0x0025;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_ext_info_changed {
    pub eir_len: u16,
}

pub const MGMT_EV_PHY_CONFIGURATION_CHANGED: u16 = 0x0026;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_phy_configuration_changed {
    pub selected_phys: u16,
}

pub const MGMT_EV_EXP_FEATURE_CHANGE: u16 = 0x0027;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_exp_feature_changed {
    pub uuid: [u8; 16],
    pub flags: u32,
}

pub const MGMT_EV_DEVICE_FLAGS_CHANGED: u16 = 0x002A;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_device_flags_changed {
    pub addr: mgmt_addr_info,
    pub supported_flags: u32,
    pub current_flags: u32,
}

pub const MGMT_EV_ADV_MONITOR_ADDED: u16 = 0x002B;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_adv_monitor_added {
    pub monitor_handle: u16,
}

pub const MGMT_EV_ADV_MONITOR_REMOVED: u16 = 0x002C;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_adv_monitor_removed {
    pub monitor_handle: u16,
}

pub const MGMT_EV_CONTROLLER_SUSPEND: u16 = 0x002D;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_controller_suspend {
    pub suspend_state: u8,
}

pub const MGMT_EV_CONTROLLER_RESUME: u16 = 0x002E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_controller_resume {
    pub addr: mgmt_addr_info,
    pub wake_reason: u8,
}

pub const MGMT_EV_ADV_MONITOR_DEVICE_FOUND: u16 = 0x002F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_adv_monitor_device_found {
    pub monitor_handle: u16,
    pub addr: mgmt_addr_info,
    pub rssi: i8,
    pub flags: u32,
    pub ad_data_len: u16,
    pub ad_data: [u8; 0],
}

pub const MGMT_EV_ADV_MONITOR_DEVICE_LOST: u16 = 0x0030;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_adv_monitor_device_lost {
    pub monitor_handle: u16,
    pub addr: mgmt_addr_info,
}

pub const MGMT_EV_MESH_DEVICE_FOUND: u16 = 0x0031;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_mesh_device_found {
    pub addr: mgmt_addr_info,
    pub rssi: i8,
    pub instant: u64,
    pub flags: u32,
    pub eir_len: u16,
    pub eir: [u8; 0],
}

pub const MGMT_EV_MESH_PACKET_CMPLT: u16 = 0x0032;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct mgmt_ev_mesh_pkt_cmplt {
    pub handle: u8,
}

// ===========================================================================
// String Lookup Tables (matching C mgmt_op[], mgmt_ev[], mgmt_status[])
// ===========================================================================

/// Opcode name lookup table — index by opcode value.
pub static MGMT_OP_NAMES: &[&str] = &[
    "<0x0000>",                                  // 0x0000
    "Read Version",                              // 0x0001
    "Read Commands",                             // 0x0002
    "Read Index List",                           // 0x0003
    "Read Controller Info",                      // 0x0004
    "Set Powered",                               // 0x0005
    "Set Discoverable",                          // 0x0006
    "Set Connectable",                           // 0x0007
    "Set Fast Connectable",                      // 0x0008
    "Set Bondable",                              // 0x0009
    "Set Link Security",                         // 0x000a
    "Set Secure Simple Pairing",                 // 0x000b
    "Set High Speed",                            // 0x000c
    "Set Low Energy",                            // 0x000d
    "Set Dev Class",                             // 0x000e
    "Set Local Name",                            // 0x000f
    "Add UUID",                                  // 0x0010
    "Remove UUID",                               // 0x0011
    "Load Link Keys",                            // 0x0012
    "Load Long Term Keys",                       // 0x0013
    "Disconnect",                                // 0x0014
    "Get Connections",                           // 0x0015
    "PIN Code Reply",                            // 0x0016
    "PIN Code Neg Reply",                        // 0x0017
    "Set IO Capability",                         // 0x0018
    "Pair Device",                               // 0x0019
    "Cancel Pair Device",                        // 0x001a
    "Unpair Device",                             // 0x001b
    "User Confirm Reply",                        // 0x001c
    "User Confirm Neg Reply",                    // 0x001d
    "User Passkey Reply",                        // 0x001e
    "User Passkey Neg Reply",                    // 0x001f
    "Read Local OOB Data",                       // 0x0020
    "Add Remote OOB Data",                       // 0x0021
    "Remove Remove OOB Data",                    // 0x0022
    "Start Discovery",                           // 0x0023
    "Stop Discovery",                            // 0x0024
    "Confirm Name",                              // 0x0025
    "Block Device",                              // 0x0026
    "Unblock Device",                            // 0x0027
    "Set Device ID",                             // 0x0028
    "Set Advertising",                           // 0x0029
    "Set BR/EDR",                                // 0x002a
    "Set Static Address",                        // 0x002b
    "Set Scan Parameters",                       // 0x002c
    "Set Secure Connections",                    // 0x002d
    "Set Debug Keys",                            // 0x002e
    "Set Privacy",                               // 0x002f
    "Load Identity Resolving Keys",              // 0x0030
    "Get Connection Information",                // 0x0031
    "Get Clock Information",                     // 0x0032
    "Add Device",                                // 0x0033
    "Remove Device",                             // 0x0034
    "Load Connection Parameters",                // 0x0035
    "Read Unconfigured Controller Index List",   // 0x0036
    "Read Controller Configuration Information", // 0x0037
    "Set External Configuration",                // 0x0038
    "Set Public Address",                        // 0x0039
    "Start Service Discovery",                   // 0x003a
    "Read Local Out Of Band Extended Data",      // 0x003b
    "Read Extended Controller Index List",       // 0x003c
    "Read Advertising Features",                 // 0x003d
    "Add Advertising",                           // 0x003e
    "Remove Advertising",                        // 0x003f
    "Get Advertising Size Information",          // 0x0040
    "Start Limited Discovery",                   // 0x0041
    "Read Extended Controller Information",      // 0x0042
    "Set Appearance",                            // 0x0043
    "Get PHY Configuration",                     // 0x0044
    "Set PHY Configuration",                     // 0x0045
    "Set Blocked Keys",                          // 0x0046
    "Set Wideband Speech",                       // 0x0047
    "Read Controller Capabilities Information",  // 0x0048
    "Read Experimental Features Information",    // 0x0049
    "Set Experimental Feature",                  // 0x004a
    "Read Default System Configuration",         // 0x004b
    "Set Default System Configuration",          // 0x004c
    "Read Default Runtime Configuration",        // 0x004d
    "Set Default Runtime Configuration",         // 0x004e
    "Get Device Flags",                          // 0x004f
    "Set Device Flags",                          // 0x0050
    "Read Advertisement Monitor Features",       // 0x0051
    "Add Advertisement Patterns Monitor",        // 0x0052
    "Remove Advertisement Monitor",              // 0x0053
    "Add Extended Advertisement Parameters",     // 0x0054
    "Add Extended Advertisement Data",           // 0x0055
    "Add Advertisement Patterns Monitor RSSI",   // 0x0056
    "Set Mesh Receiver",                         // 0x0057
    "Read Mesh Features",                        // 0x0058
    "Mesh Send",                                 // 0x0059
    "Mesh Send Cancel",                          // 0x005a
];

/// Event name lookup table — index by event code value.
pub static MGMT_EV_NAMES: &[&str] = &[
    "<0x0000>",                                // 0x0000
    "Command Complete",                        // 0x0001
    "Command Status",                          // 0x0002
    "Controller Error",                        // 0x0003
    "Index Added",                             // 0x0004
    "Index Removed",                           // 0x0005
    "New Settings",                            // 0x0006
    "Class of Device Changed",                 // 0x0007
    "Local Name Changed",                      // 0x0008
    "New Link Key",                            // 0x0009
    "New Long Term Key",                       // 0x000a
    "Device Connected",                        // 0x000b
    "Device Disconnected",                     // 0x000c
    "Connect Failed",                          // 0x000d
    "PIN Code Request",                        // 0x000e
    "User Confirm Request",                    // 0x000f
    "User Passkey Request",                    // 0x0010
    "Authentication Failed",                   // 0x0011
    "Device Found",                            // 0x0012
    "Discovering",                             // 0x0013
    "Device Blocked",                          // 0x0014
    "Device Unblocked",                        // 0x0015
    "Device Unpaired",                         // 0x0016
    "Passkey Notify",                          // 0x0017
    "New Identity Resolving Key",              // 0x0018
    "New Signature Resolving Key",             // 0x0019
    "Device Added",                            // 0x001a
    "Device Removed",                          // 0x001b
    "New Connection Parameter",                // 0x001c
    "Unconfigured Index Added",                // 0x001d
    "Unconfigured Index Removed",              // 0x001e
    "New Configuration Options",               // 0x001f
    "Extended Index Added",                    // 0x0020
    "Extended Index Removed",                  // 0x0021
    "Local Out Of Band Extended Data Updated", // 0x0022
    "Advertising Added",                       // 0x0023
    "Advertising Removed",                     // 0x0024
    "Extended Controller Information Changed", // 0x0025
    "PHY Configuration Changed",               // 0x0026
    "Experimental Feature Changed",            // 0x0027
    "Default System Configuration Changed",    // 0x0028
    "Default Runtime Configuration Changed",   // 0x0029
    "Device Flags Changed",                    // 0x002a
    "Advertisement Monitor Added",             // 0x002b
    "Advertisement Monitor Removed",           // 0x002c
    "Controller Suspend",                      // 0x002d
    "Controller Resume",                       // 0x002e
    "Advertisement Monitor Device Found",      // 0x002f
    "Advertisement Monitor Device Lost",       // 0x0030
    "Mesh Packet Found",                       // 0x0031
    "Mesh Packet Complete",                    // 0x0032
    "PA Sync Established",                     // 0x0033
    "BIG Sync Established",                    // 0x0034
    "BIG Sync Lost",                           // 0x0035
];

/// Status name lookup table — index by status code value.
pub static MGMT_STATUS_NAMES: &[&str] = &[
    "Success",                    // 0x00
    "Unknown Command",            // 0x01
    "Not Connected",              // 0x02
    "Failed",                     // 0x03
    "Connect Failed",             // 0x04
    "Authentication Failed",      // 0x05
    "Not Paired",                 // 0x06
    "No Resources",               // 0x07
    "Timeout",                    // 0x08
    "Already Connected",          // 0x09
    "Busy",                       // 0x0a
    "Rejected",                   // 0x0b
    "Not Supported",              // 0x0c
    "Invalid Parameters",         // 0x0d
    "Disconnected",               // 0x0e
    "Not Powered",                // 0x0f
    "Cancelled",                  // 0x10
    "Invalid Index",              // 0x11
    "Blocked through rfkill",     // 0x12
    "Already Paired",             // 0x13
    "Permission Denied",          // 0x14
    "Connection Not Established", // 0x15
];

// ===========================================================================
// Stringification Functions
// ===========================================================================

/// Returns a human-readable name for the given MGMT opcode.
///
/// Returns `"<unknown opcode>"` if the opcode is out of range.
pub fn mgmt_opstr(op: u16) -> &'static str {
    let idx = op as usize;
    if idx < MGMT_OP_NAMES.len() { MGMT_OP_NAMES[idx] } else { "<unknown opcode>" }
}

/// Returns a human-readable name for the given MGMT event code.
///
/// Returns `"<unknown event>"` if the event code is out of range.
pub fn mgmt_evstr(ev: u16) -> &'static str {
    let idx = ev as usize;
    if idx < MGMT_EV_NAMES.len() { MGMT_EV_NAMES[idx] } else { "<unknown event>" }
}

/// Returns a human-readable name for the given MGMT status code.
///
/// Returns `"<unknown status>"` if the status code is out of range.
pub fn mgmt_errstr(status: u8) -> &'static str {
    let idx = status as usize;
    if idx < MGMT_STATUS_NAMES.len() { MGMT_STATUS_NAMES[idx] } else { "<unknown status>" }
}
