// SPDX-License-Identifier: GPL-2.0-or-later
//! Rust re-declaration of the Linux kernel HCI (Host Controller Interface)
//! definitions from `lib/bluetooth/hci.h` and `lib/bluetooth/hci_lib.h`.
//!
//! All structs use `#[repr(C, packed)]` for kernel ABI wire compatibility.
//! Constant values are exact matches of the C header definitions.

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ===========================================================================
// Size and Device Constants
// ===========================================================================

pub const HCI_MAX_DEV: u16 = 16;
pub const HCI_MAX_AMP_SIZE: usize = 1496;
pub const HCI_MAX_ACL_SIZE: usize = 1024;
pub const HCI_MAX_SCO_SIZE: usize = 255;
pub const HCI_MAX_EVENT_SIZE: usize = 260;
pub const HCI_MAX_FRAME_SIZE: usize = 1500;
pub const HCI_MAX_NAME_LENGTH: usize = 248;
pub const HCI_MAX_EIR_LENGTH: usize = 240;

// HCI Device Events
pub const HCI_DEV_REG: u8 = 1;
pub const HCI_DEV_UNREG: u8 = 2;
pub const HCI_DEV_UP: u8 = 3;
pub const HCI_DEV_DOWN: u8 = 4;
pub const HCI_DEV_SUSPEND: u8 = 5;
pub const HCI_DEV_RESUME: u8 = 6;

// HCI Bus Types
pub const HCI_VIRTUAL: u8 = 0;
pub const HCI_USB: u8 = 1;
pub const HCI_PCCARD: u8 = 2;
pub const HCI_UART: u8 = 3;
pub const HCI_RS232: u8 = 4;
pub const HCI_PCI: u8 = 5;
pub const HCI_SDIO: u8 = 6;
pub const HCI_SPI: u8 = 7;
pub const HCI_I2C: u8 = 8;
pub const HCI_SMD: u8 = 9;
pub const HCI_VIRTIO: u8 = 10;
pub const HCI_IPC: u8 = 11;

// Controller Types
pub const HCI_PRIMARY: u8 = 0x00;
pub const HCI_AMP: u8 = 0x01;
pub const HCI_BREDR: u8 = HCI_PRIMARY;

// LE Address Types and Link Types
pub const LE_PUBLIC_ADDRESS: u8 = 0x00;
pub const LE_RANDOM_ADDRESS: u8 = 0x01;
pub const SCO_LINK: u8 = 0x00;
pub const ACL_LINK: u8 = 0x01;
pub const ESCO_LINK: u8 = 0x02;

// ===========================================================================
// HCI Ioctl Definitions
// ===========================================================================

const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2;
const _IOC_NRBITS: u32 = 8;
const _IOC_TYPEBITS: u32 = 8;
const _IOC_SIZEBITS: u32 = 14;
const _IOC_NRSHIFT: u32 = 0;
const _IOC_TYPESHIFT: u32 = _IOC_NRSHIFT + _IOC_NRBITS;
const _IOC_SIZESHIFT: u32 = _IOC_TYPESHIFT + _IOC_TYPEBITS;
const _IOC_DIRSHIFT: u32 = _IOC_SIZESHIFT + _IOC_SIZEBITS;

const fn _ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
    (dir << _IOC_DIRSHIFT)
        | (ty << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
}
const fn _iow(ty: u32, nr: u32, size: u32) -> u32 {
    _ioc(_IOC_WRITE, ty, nr, size)
}
const fn _ior(ty: u32, nr: u32, size: u32) -> u32 {
    _ioc(_IOC_READ, ty, nr, size)
}
const HCI_IOC_TYPE: u32 = b'H' as u32;

pub const HCIDEVUP: u32 = _iow(HCI_IOC_TYPE, 201, 4);
pub const HCIDEVDOWN: u32 = _iow(HCI_IOC_TYPE, 202, 4);
pub const HCIDEVRESET: u32 = _iow(HCI_IOC_TYPE, 203, 4);
pub const HCIDEVRESTAT: u32 = _iow(HCI_IOC_TYPE, 204, 4);
pub const HCIGETDEVLIST: u32 = _ior(HCI_IOC_TYPE, 210, 4);
pub const HCIGETDEVINFO: u32 = _ior(HCI_IOC_TYPE, 211, 4);
pub const HCIGETCONNLIST: u32 = _ior(HCI_IOC_TYPE, 212, 4);
pub const HCIGETCONNINFO: u32 = _ior(HCI_IOC_TYPE, 213, 4);
pub const HCIGETAUTHINFO: u32 = _ior(HCI_IOC_TYPE, 215, 4);
pub const HCISETRAW: u32 = _iow(HCI_IOC_TYPE, 220, 4);
pub const HCISETSCAN: u32 = _iow(HCI_IOC_TYPE, 221, 4);
pub const HCISETAUTH: u32 = _iow(HCI_IOC_TYPE, 222, 4);
pub const HCISETENCRYPT: u32 = _iow(HCI_IOC_TYPE, 223, 4);
pub const HCISETPTYPE: u32 = _iow(HCI_IOC_TYPE, 224, 4);
pub const HCISETLINKPOL: u32 = _iow(HCI_IOC_TYPE, 225, 4);
pub const HCISETLINKMODE: u32 = _iow(HCI_IOC_TYPE, 226, 4);
pub const HCISETACLMTU: u32 = _iow(HCI_IOC_TYPE, 227, 4);
pub const HCISETSCOMTU: u32 = _iow(HCI_IOC_TYPE, 228, 4);
pub const HCIBLOCKADDR: u32 = _iow(HCI_IOC_TYPE, 230, 4);
pub const HCIUNBLOCKADDR: u32 = _iow(HCI_IOC_TYPE, 231, 4);
pub const HCIINQUIRY: u32 = _ior(HCI_IOC_TYPE, 240, 4);

// ===========================================================================
// HCI Packet Types and Error Codes
// ===========================================================================

pub const HCI_COMMAND_PKT: u8 = 0x01;
pub const HCI_ACLDATA_PKT: u8 = 0x02;
pub const HCI_SCODATA_PKT: u8 = 0x03;
pub const HCI_EVENT_PKT: u8 = 0x04;
pub const HCI_ISODATA_PKT: u8 = 0x05;
pub const HCI_VENDOR_PKT: u8 = 0xff;

pub const HCI_SUCCESS: u8 = 0x00;
pub const HCI_UNKNOWN_COMMAND: u8 = 0x01;
pub const HCI_NO_CONNECTION: u8 = 0x02;
pub const HCI_HARDWARE_FAILURE: u8 = 0x03;
pub const HCI_PAGE_TIMEOUT: u8 = 0x04;
pub const HCI_AUTHENTICATION_FAILURE: u8 = 0x05;
pub const HCI_PIN_OR_KEY_MISSING: u8 = 0x06;
pub const HCI_MEMORY_FULL: u8 = 0x07;
pub const HCI_CONNECTION_TIMEOUT: u8 = 0x08;
pub const HCI_MAX_CONNECTIONS: u8 = 0x09;
pub const HCI_MAX_SCO_CONNECTIONS: u8 = 0x0A;
pub const HCI_ACL_CONNECTION_EXISTS: u8 = 0x0B;
pub const HCI_COMMAND_DISALLOWED: u8 = 0x0C;
pub const HCI_REJECTED_LIMITED_RESOURCES: u8 = 0x0D;
pub const HCI_REJECTED_SECURITY: u8 = 0x0E;
pub const HCI_REJECTED_PERSONAL: u8 = 0x0F;
pub const HCI_HOST_TIMEOUT: u8 = 0x10;
pub const HCI_UNSUPPORTED_FEATURE: u8 = 0x11;
pub const HCI_INVALID_PARAMETERS: u8 = 0x12;
pub const HCI_OE_USER_ENDED_CONNECTION: u8 = 0x13;
pub const HCI_OE_LOW_RESOURCES: u8 = 0x14;
pub const HCI_OE_POWER_OFF: u8 = 0x15;
pub const HCI_CONNECTION_TERMINATED: u8 = 0x16;
pub const HCI_REPEATED_ATTEMPTS: u8 = 0x17;
pub const HCI_PAIRING_NOT_ALLOWED: u8 = 0x18;
pub const HCI_UNKNOWN_LMP_PDU: u8 = 0x19;
pub const HCI_UNSUPPORTED_REMOTE_FEATURE: u8 = 0x1A;
pub const HCI_UNSPECIFIED_ERROR: u8 = 0x1F;
pub const HCI_INSUFFICIENT_SECURITY: u8 = 0x2F;
pub const HCI_PAIRING_NOT_SUPPORTED: u8 = 0x29;
pub const HCI_HOST_BUSY_PAIRING: u8 = 0x38;
pub const HCI_ROLE_SWITCH_FAILED: u8 = 0x35;
pub const HCI_INSTANT_PASSED: u8 = 0x28;

// ACL/Scan/Link Key/Filter Constants
pub const ACL_START: u8 = 0x00;
pub const ACL_CONT: u8 = 0x01;
pub const ACL_START_NO_FLUSH: u8 = 0x02;
pub const ACL_ACTIVE_BCAST: u8 = 0x04;
pub const ACL_PICO_BCAST: u8 = 0x08;
pub const SCAN_DISABLED: u8 = 0x00;
pub const SCAN_INQUIRY: u8 = 0x01;
pub const SCAN_PAGE: u8 = 0x02;
pub const HCI_LK_COMBINATION: u8 = 0x00;
pub const HCI_LK_DEBUG_COMBINATION: u8 = 0x03;
pub const HCI_LK_UNAUTH_COMBINATION_P192: u8 = 0x04;
pub const HCI_LK_AUTH_COMBINATION_P192: u8 = 0x05;
pub const HCI_LK_CHANGED_COMBINATION: u8 = 0x06;
pub const HCI_LK_UNAUTH_COMBINATION_P256: u8 = 0x07;
pub const HCI_LK_AUTH_COMBINATION_P256: u8 = 0x08;
pub const FLT_CLEAR_ALL: u8 = 0x00;
pub const FLT_INQ_RESULT: u8 = 0x01;
pub const FLT_CONN_SETUP: u8 = 0x02;

// ===========================================================================
// Bitflags Type Definitions
// ===========================================================================

bitflags::bitflags! {
    /// HCI device flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HciDevFlags: u32 {
        const HCI_UP = 1 << 0;
        const HCI_INIT = 1 << 1;
        const HCI_RUNNING = 1 << 2;
        const HCI_PSCAN = 1 << 3;
        const HCI_ISCAN = 1 << 4;
        const HCI_AUTH = 1 << 5;
        const HCI_ENCRYPT = 1 << 6;
        const HCI_INQUIRY = 1 << 7;
        const HCI_RAW = 1 << 8;
    }
}

bitflags::bitflags! {
    /// HCI packet type bitmask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HciPacketType: u32 {
        const DM1 = 0x0008;
        const DM3 = 0x0400;
        const DM5 = 0x4000;
        const DH1 = 0x0010;
        const DH3 = 0x0800;
        const DH5 = 0x8000;
        const HV1 = 0x0020;
        const HV2 = 0x0040;
        const HV3 = 0x0080;
        const EV3 = 0x0008;
        const EV4 = 0x0010;
        const EV5 = 0x0020;
        const NO_2_DH1 = 0x0002;
        const NO_2_DH3 = 0x0100;
        const NO_2_DH5 = 0x1000;
        const NO_3_DH1 = 0x0004;
        const NO_3_DH3 = 0x0200;
        const NO_3_DH5 = 0x2000;
        const SCO_PTYPE_MASK = 0x003F;
        const ACL_PTYPE_MASK = 0xCC18;
    }
}

bitflags::bitflags! {
    /// HCI link policy flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HciLinkPolicy: u16 {
        const HCI_LP_RSWITCH = 0x0001;
        const HCI_LP_HOLD = 0x0002;
        const HCI_LP_SNIFF = 0x0004;
        const HCI_LP_PARK = 0x0008;
    }
}

bitflags::bitflags! {
    /// HCI link mode flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HciLinkMode: u32 {
        const HCI_LM_ACCEPT = 0x8000;
        const HCI_LM_MASTER = 0x0001;
        const HCI_LM_AUTH = 0x0002;
        const HCI_LM_ENCRYPT = 0x0004;
        const HCI_LM_TRUSTED = 0x0008;
        const HCI_LM_RELIABLE = 0x0010;
        const HCI_LM_SECURE = 0x0020;
    }
}

bitflags::bitflags! {
    /// LMP feature bits (page 0).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LmpFeatures: u64 {
        const LMP_3SLOT = 1 << 0;
        const LMP_5SLOT = 1 << 1;
        const LMP_ENCRYPT = 1 << 2;
        const LMP_SOFFSET = 1 << 3;
        const LMP_TACCURACY = 1 << 4;
        const LMP_RSWITCH = 1 << 5;
        const LMP_HOLD = 1 << 6;
        const LMP_SNIFF = 1 << 7;
        const LMP_PARK = 1 << 8;
        const LMP_RSSI = 1 << 9;
        const LMP_QUALITY = 1 << 10;
        const LMP_SCO = 1 << 11;
        const LMP_HV2 = 1 << 12;
        const LMP_HV3 = 1 << 13;
        const LMP_ULAW = 1 << 14;
        const LMP_ALAW = 1 << 15;
        const LMP_CVSD = 1 << 16;
        const LMP_PSCHEME = 1 << 17;
        const LMP_PCONTROL = 1 << 18;
        const LMP_TRSP_SCO = 1 << 19;
        const LMP_BCAST_ENC = 1 << 21;
        const LMP_EDR_ACL_2M = 1 << 25;
        const LMP_EDR_ACL_3M = 1 << 26;
        const LMP_ENH_ISCAN = 1 << 27;
        const LMP_INTERLACE_ISCAN = 1 << 28;
        const LMP_INTERLACE_PSCAN = 1 << 29;
        const LMP_INQ_TX_PWR = 1 << 30;
        const LMP_EXT_FEAT = 1u64 << 31;
        const LMP_SIMPLE_PAIR = 1u64 << 51;
        const LMP_NO_FLUSH = 1u64 << 54;
        const LMP_LSTO = 1u64 << 56;
        const LMP_EXT_INQ = 1u64 << 48;
        const LMP_LE_BREDR = 1u64 << 49;
    }
}

// ===========================================================================
// HCI Opcode Group Field (OGF) and Helper Functions
// ===========================================================================

pub const OGF_LINK_CONTROL: u16 = 0x01;
pub const OGF_LINK_POLICY: u16 = 0x02;
pub const OGF_HOST_CTL: u16 = 0x03;
pub const OGF_INFO_PARAM: u16 = 0x04;
pub const OGF_STATUS_PARAM: u16 = 0x05;
pub const OGF_LE_CTL: u16 = 0x08;
pub const OGF_TESTING_CMD: u16 = 0x3E;
pub const OGF_VENDOR_CMD: u16 = 0x3F;

/// Construct an HCI opcode from OGF and OCF.
#[inline]
pub const fn opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | ocf
}
/// Pack OGF and OCF into a command opcode.
#[inline]
pub const fn cmd_opcode_pack(ogf: u16, ocf: u16) -> u16 {
    opcode(ogf, ocf)
}
/// Extract the OGF from an opcode.
#[inline]
pub const fn cmd_opcode_ogf(op: u16) -> u16 {
    op >> 10
}
/// Extract the OCF from an opcode.
#[inline]
pub const fn cmd_opcode_ocf(op: u16) -> u16 {
    op & 0x03FF
}
/// Pack ACL handle and flags.
#[inline]
pub const fn acl_handle_pack(handle: u16, flags: u16) -> u16 {
    (handle & 0x0FFF) | (flags << 12)
}
/// Extract ACL connection handle.
#[inline]
pub const fn acl_handle(h: u16) -> u16 {
    h & 0x0FFF
}
/// Extract ACL packet boundary and broadcast flags.
#[inline]
pub const fn acl_flags(h: u16) -> u8 {
    (h >> 12) as u8
}

// ===========================================================================
// Link Control OCFs (OGF = 0x01)
// ===========================================================================

pub const OCF_INQUIRY: u16 = 0x0001;
pub const OCF_INQUIRY_CANCEL: u16 = 0x0002;
pub const OCF_CREATE_CONN: u16 = 0x0005;
pub const OCF_DISCONNECT: u16 = 0x0006;
pub const OCF_ACCEPT_CONN_REQ: u16 = 0x0009;
pub const OCF_REJECT_CONN_REQ: u16 = 0x000A;
pub const OCF_LINK_KEY_REPLY: u16 = 0x000B;
pub const OCF_LINK_KEY_NEG_REPLY: u16 = 0x000C;
pub const OCF_PIN_CODE_REPLY: u16 = 0x000D;
pub const OCF_PIN_CODE_NEG_REPLY: u16 = 0x000E;
pub const OCF_SET_CONN_ENCRYPT: u16 = 0x0013;
pub const OCF_AUTH_REQUESTED: u16 = 0x0011;
pub const OCF_CHANGE_CONN_PTYPE: u16 = 0x000F;
pub const OCF_REMOTE_NAME_REQ: u16 = 0x0019;
pub const OCF_REMOTE_NAME_REQ_CANCEL: u16 = 0x001A;
pub const OCF_READ_REMOTE_FEATURES: u16 = 0x001B;
pub const OCF_READ_REMOTE_VERSION: u16 = 0x001D;
pub const OCF_READ_REMOTE_EXT_FEATURES: u16 = 0x001C;
pub const OCF_SETUP_SYNC_CONN: u16 = 0x0028;
pub const OCF_ACCEPT_SYNC_CONN_REQ: u16 = 0x0029;
pub const OCF_REJECT_SYNC_CONN_REQ: u16 = 0x002A;
pub const OCF_IO_CAPABILITY_REPLY: u16 = 0x002B;
pub const OCF_USER_CONFIRM_REPLY: u16 = 0x002C;
pub const OCF_USER_CONFIRM_NEG_REPLY: u16 = 0x002D;

// Link Control command parameter structs

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct inquiry_cp {
    pub lap: [u8; 3],
    pub length: u8,
    pub num_rsp: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct create_conn_cp {
    pub bdaddr: bdaddr_t,
    pub pkt_type: u16,
    pub pscan_rep_mode: u8,
    pub pscan_mode: u8,
    pub clock_offset: u16,
    pub role_switch: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct disconnect_cp {
    pub handle: u16,
    pub reason: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct accept_conn_req_cp {
    pub bdaddr: bdaddr_t,
    pub role: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct reject_conn_req_cp {
    pub bdaddr: bdaddr_t,
    pub reason: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct link_key_reply_cp {
    pub bdaddr: bdaddr_t,
    pub link_key: [u8; 16],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct pin_code_reply_cp {
    pub bdaddr: bdaddr_t,
    pub pin_len: u8,
    pub pin_code: [u8; 16],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct remote_name_req_cp {
    pub bdaddr: bdaddr_t,
    pub pscan_rep_mode: u8,
    pub pscan_mode: u8,
    pub clock_offset: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_stored_link_key_cp {
    pub bdaddr: bdaddr_t,
    pub read_all: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct delete_stored_link_key_cp {
    pub bdaddr: bdaddr_t,
    pub delete_all: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct send_keypress_notify_cp {
    pub bdaddr: bdaddr_t,
    pub type_: u8,
}

// ===========================================================================
// Link Policy OCFs (OGF = 0x02)
// ===========================================================================

pub const OCF_HOLD_MODE: u16 = 0x0001;
pub const OCF_SNIFF_MODE: u16 = 0x0003;
pub const OCF_EXIT_SNIFF_MODE: u16 = 0x0004;
pub const OCF_SWITCH_ROLE: u16 = 0x000B;
pub const OCF_READ_LINK_POLICY: u16 = 0x000C;
pub const OCF_WRITE_LINK_POLICY: u16 = 0x000D;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_qos {
    pub service_type: u8,
    pub token_rate: u32,
    pub peak_bandwidth: u32,
    pub latency: u32,
    pub delay_variation: u32,
}

// ===========================================================================
// Host Controller & Baseband OCFs (OGF = 0x03)
// ===========================================================================

pub const OCF_SET_EVENT_MASK: u16 = 0x0001;
pub const OCF_RESET: u16 = 0x0003;
pub const OCF_SET_EVENT_FLT: u16 = 0x0005;
pub const OCF_CHANGE_LOCAL_NAME: u16 = 0x0013;
pub const OCF_READ_LOCAL_NAME: u16 = 0x0014;
pub const OCF_WRITE_SCAN_ENABLE: u16 = 0x001A;
pub const OCF_READ_SCAN_ENABLE: u16 = 0x0019;
pub const OCF_WRITE_AUTH_ENABLE: u16 = 0x0020;
pub const OCF_WRITE_CLASS_OF_DEV: u16 = 0x0024;
pub const OCF_READ_CLASS_OF_DEV: u16 = 0x0023;
pub const OCF_WRITE_VOICE_SETTING: u16 = 0x0026;
pub const OCF_READ_VOICE_SETTING: u16 = 0x0025;
pub const OCF_WRITE_INQUIRY_MODE: u16 = 0x0045;
pub const OCF_WRITE_EXT_INQUIRY_RESPONSE: u16 = 0x0052;
pub const OCF_WRITE_SIMPLE_PAIRING_MODE: u16 = 0x0056;
pub const OCF_READ_LOCAL_OOB_DATA: u16 = 0x0057;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct set_event_mask_cp {
    pub mask: [u8; 8],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct set_event_flt_cp {
    pub flt_type: u8,
    pub cond_type: u8,
    pub condition: [u8; 7],
}

#[repr(C, packed)]
pub struct change_local_name_cp {
    pub name: [u8; 248],
}

impl Default for change_local_name_cp {
    fn default() -> Self {
        Self { name: [0u8; 248] }
    }
}

impl Clone for change_local_name_cp {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for change_local_name_cp {}

#[repr(C, packed)]
pub struct read_local_name_rp {
    pub status: u8,
    pub name: [u8; 248],
}

impl Default for read_local_name_rp {
    fn default() -> Self {
        Self { status: 0, name: [0u8; 248] }
    }
}

impl Clone for read_local_name_rp {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for read_local_name_rp {}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct write_scan_enable_cp {
    pub scan_enable: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct write_class_of_dev_cp {
    pub dev_class: [u8; 3],
}

#[repr(C, packed)]
pub struct write_ext_inquiry_response_cp {
    pub fec: u8,
    pub data: [u8; 240],
}

impl Default for write_ext_inquiry_response_cp {
    fn default() -> Self {
        Self { fec: 0, data: [0u8; 240] }
    }
}

impl Clone for write_ext_inquiry_response_cp {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for write_ext_inquiry_response_cp {}

// ===========================================================================
// Informational Parameter OCFs (OGF = 0x04)
// ===========================================================================

pub const OCF_READ_LOCAL_VERSION: u16 = 0x0001;
pub const OCF_READ_LOCAL_COMMANDS: u16 = 0x0002;
pub const OCF_READ_LOCAL_FEATURES: u16 = 0x0003;
pub const OCF_READ_LOCAL_EXT_FEATURES: u16 = 0x0004;
pub const OCF_READ_BUFFER_SIZE: u16 = 0x0005;
pub const OCF_READ_BD_ADDR: u16 = 0x0009;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_local_version_rp {
    pub status: u8,
    pub hci_ver: u8,
    pub hci_rev: u16,
    pub lmp_ver: u8,
    pub manufacturer: u16,
    pub lmp_subver: u16,
}

#[repr(C, packed)]
pub struct read_local_commands_rp {
    pub status: u8,
    pub commands: [u8; 64],
}

impl Default for read_local_commands_rp {
    fn default() -> Self {
        Self { status: 0, commands: [0u8; 64] }
    }
}

impl Clone for read_local_commands_rp {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for read_local_commands_rp {}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_local_features_rp {
    pub status: u8,
    pub features: [u8; 8],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_local_ext_features_rp {
    pub status: u8,
    pub page_num: u8,
    pub max_page_num: u8,
    pub features: [u8; 8],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_buffer_size_rp {
    pub status: u8,
    pub acl_mtu: u16,
    pub sco_mtu: u8,
    pub acl_max_pkt: u16,
    pub sco_max_pkt: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_bd_addr_rp {
    pub status: u8,
    pub bdaddr: bdaddr_t,
}

// ===========================================================================
// Status Parameter OCFs (OGF = 0x05)
// ===========================================================================

pub const OCF_READ_RSSI: u16 = 0x0005;
pub const OCF_READ_AFH_MAP: u16 = 0x0006;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_rssi_rp {
    pub status: u8,
    pub handle: u16,
    pub rssi: i8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_local_amp_info_rp {
    pub status: u8,
    pub amp_status: u8,
    pub total_bw: u32,
    pub max_bw: u32,
    pub min_latency: u32,
    pub max_pdu: u32,
    pub amp_type: u8,
    pub pal_cap: u16,
    pub max_assoc_size: u16,
    pub max_flush_to: u32,
    pub be_flush_to: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct read_local_oob_data_rp {
    pub status: u8,
    pub hash: [u8; 16],
    pub randomizer: [u8; 16],
}

// ===========================================================================
// Testing OCFs (OGF = 0x3E)
// ===========================================================================

pub const OCF_READ_LOOPBACK_MODE: u16 = 0x0001;
pub const OCF_WRITE_LOOPBACK_MODE: u16 = 0x0002;
pub const OCF_ENABLE_DEVICE_UNDER_TEST_MODE: u16 = 0x0003;
pub const OCF_WRITE_SIMPLE_PAIRING_DEBUG_MODE: u16 = 0x0004;

// ===========================================================================
// LE Controller OCFs (OGF = 0x08)
// ===========================================================================

pub const OCF_LE_SET_EVENT_MASK: u16 = 0x0001;
pub const OCF_LE_READ_BUFFER_SIZE: u16 = 0x0002;
pub const OCF_LE_READ_LOCAL_SUPPORTED_FEATURES: u16 = 0x0003;
pub const OCF_LE_SET_RANDOM_ADDRESS: u16 = 0x0005;
pub const OCF_LE_SET_ADVERTISING_PARAMETERS: u16 = 0x0006;
pub const OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER: u16 = 0x0007;
pub const OCF_LE_SET_ADVERTISING_DATA: u16 = 0x0008;
pub const OCF_LE_SET_SCAN_RESPONSE_DATA: u16 = 0x0009;
pub const OCF_LE_SET_ADVERTISE_ENABLE: u16 = 0x000A;
pub const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
pub const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
pub const OCF_LE_CREATE_CONN: u16 = 0x000D;
pub const OCF_LE_CREATE_CONN_CANCEL: u16 = 0x000E;
pub const OCF_LE_READ_WHITE_LIST_SIZE: u16 = 0x000F;
pub const OCF_LE_CLEAR_WHITE_LIST: u16 = 0x0010;
pub const OCF_LE_ADD_DEVICE_TO_WHITE_LIST: u16 = 0x0011;
pub const OCF_LE_CONN_UPDATE: u16 = 0x0013;
pub const OCF_LE_SET_HOST_CHANNEL_CLASSIFICATION: u16 = 0x0014;
pub const OCF_LE_READ_CHANNEL_MAP: u16 = 0x0015;
pub const OCF_LE_READ_REMOTE_USED_FEATURES: u16 = 0x0016;
pub const OCF_LE_ENCRYPT: u16 = 0x0017;
pub const OCF_LE_RAND: u16 = 0x0018;
pub const OCF_LE_START_ENCRYPTION: u16 = 0x0019;
pub const OCF_LE_LTK_REPLY: u16 = 0x001A;
pub const OCF_LE_LTK_NEG_REPLY: u16 = 0x001B;
pub const OCF_LE_READ_SUPPORTED_STATES: u16 = 0x001C;
pub const OCF_LE_RECEIVER_TEST: u16 = 0x001D;
pub const OCF_LE_TRANSMITTER_TEST: u16 = 0x001E;
pub const OCF_LE_TEST_END: u16 = 0x001F;
pub const OCF_LE_ADD_DEVICE_TO_RESOLV_LIST: u16 = 0x0027;
pub const OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST: u16 = 0x0028;
pub const OCF_LE_CLEAR_RESOLV_LIST: u16 = 0x0029;
pub const OCF_LE_SET_ADDRESS_RESOLUTION_ENABLE: u16 = 0x002D;
pub const OCF_LE_SET_EXT_ADV_ENABLE: u16 = 0x0039;

// LE command parameter structs

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_random_address_cp {
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_advertising_parameters_cp {
    pub min_interval: u16,
    pub max_interval: u16,
    pub advtype: u8,
    pub own_bdaddr_type: u8,
    pub direct_bdaddr_type: u8,
    pub direct_bdaddr: bdaddr_t,
    pub chan_map: u8,
    pub filter: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_advertising_data_cp {
    pub length: u8,
    pub data: [u8; 31],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_scan_response_data_cp {
    pub length: u8,
    pub data: [u8; 31],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_advertise_enable_cp {
    pub enable: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_scan_parameters_cp {
    pub type_: u8,
    pub interval: u16,
    pub window: u16,
    pub own_bdaddr_type: u8,
    pub filter: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_scan_enable_cp {
    pub enable: u8,
    pub filter_dup: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_create_connection_cp {
    pub interval: u16,
    pub window: u16,
    pub initiator_filter: u8,
    pub peer_bdaddr_type: u8,
    pub peer_bdaddr: bdaddr_t,
    pub own_bdaddr_type: u8,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub supervision_timeout: u16,
    pub min_ce_length: u16,
    pub max_ce_length: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_conn_update_cp {
    pub handle: u16,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub supervision_timeout: u16,
    pub min_ce_length: u16,
    pub max_ce_length: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_add_device_to_white_list_cp {
    pub bdaddr_type: u8,
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_encrypt_cp {
    pub key: [u8; 16],
    pub plaintext: [u8; 16],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_encrypt_rp {
    pub status: u8,
    pub data: [u8; 16],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_start_encryption_cp {
    pub handle: u16,
    pub random: u64,
    pub diversifier: u16,
    pub ltk: [u8; 16],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_ltk_reply_cp {
    pub handle: u16,
    pub ltk: [u8; 16],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_ltk_neg_reply_cp {
    pub handle: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_add_device_to_resolv_list_cp {
    pub bdaddr_type: u8,
    pub bdaddr: bdaddr_t,
    pub peer_irk: [u8; 16],
    pub local_irk: [u8; 16],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_read_buffer_size_rp {
    pub status: u8,
    pub pkt_len: u16,
    pub max_pkt: u8,
}

// ===========================================================================
// HCI Event Codes
// ===========================================================================

pub const EVT_INQUIRY_COMPLETE: u8 = 0x01;
pub const EVT_INQUIRY_RESULT: u8 = 0x02;
pub const EVT_CONN_COMPLETE: u8 = 0x03;
pub const EVT_CONN_REQUEST: u8 = 0x04;
pub const EVT_DISCONN_COMPLETE: u8 = 0x05;
pub const EVT_AUTH_COMPLETE: u8 = 0x06;
pub const EVT_REMOTE_NAME_REQ_COMPLETE: u8 = 0x07;
pub const EVT_ENCRYPT_CHANGE: u8 = 0x08;
pub const EVT_READ_REMOTE_FEATURES_COMPLETE: u8 = 0x0B;
pub const EVT_READ_REMOTE_VERSION_COMPLETE: u8 = 0x0C;
pub const EVT_QOS_SETUP_COMPLETE: u8 = 0x0D;
pub const EVT_CMD_COMPLETE: u8 = 0x0E;
pub const EVT_CMD_STATUS: u8 = 0x0F;
pub const EVT_HARDWARE_ERROR: u8 = 0x10;
pub const EVT_FLUSH_OCCURRED: u8 = 0x11;
pub const EVT_ROLE_CHANGE: u8 = 0x12;
pub const EVT_NUM_COMP_PKTS: u8 = 0x13;
pub const EVT_MODE_CHANGE: u8 = 0x14;
pub const EVT_RETURN_LINK_KEYS: u8 = 0x15;
pub const EVT_PIN_CODE_REQ: u8 = 0x16;
pub const EVT_LINK_KEY_REQ: u8 = 0x17;
pub const EVT_LINK_KEY_NOTIFY: u8 = 0x18;
pub const EVT_IO_CAPABILITY_REQUEST: u8 = 0x31;
pub const EVT_IO_CAPABILITY_RESPONSE: u8 = 0x32;
pub const EVT_USER_CONFIRM_REQUEST: u8 = 0x33;
pub const EVT_USER_PASSKEY_REQUEST: u8 = 0x34;
pub const EVT_REMOTE_OOB_DATA_REQUEST: u8 = 0x35;
pub const EVT_SIMPLE_PAIRING_COMPLETE: u8 = 0x36;
pub const EVT_USER_PASSKEY_NOTIFY: u8 = 0x3B;
pub const EVT_KEYPRESS_NOTIFY: u8 = 0x3C;
pub const EVT_REMOTE_HOST_FEATURES_NOTIFY: u8 = 0x3D;
pub const EVT_LE_META_EVENT: u8 = 0x3E;
pub const EVT_PSCAN_REP_MODE_CHANGE: u8 = 0x20;
pub const EVT_PHYSICAL_LINK_COMPLETE: u8 = 0x40;
pub const EVT_CHANNEL_SELECTED: u8 = 0x41;
pub const EVT_DISCONNECT_PHYSICAL_LINK_COMPLETE: u8 = 0x42;
pub const EVT_LOGICAL_LINK_COMPLETE: u8 = 0x45;
pub const EVT_DISCONNECT_LOGICAL_LINK_COMPLETE: u8 = 0x46;
pub const EVT_NUMBER_COMPLETED_BLOCKS: u8 = 0x48;
pub const EVT_AMP_STATUS_CHANGE: u8 = 0x4D;
pub const EVT_TESTING: u8 = 0xFE;
pub const EVT_VENDOR: u8 = 0xFF;
pub const EVT_STACK_INTERNAL: u8 = 0xFD;
pub const EVT_SI_DEVICE: u8 = 0x01;

// LE sub-event codes
pub const EVT_LE_CONN_COMPLETE: u8 = 0x01;
pub const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;
pub const EVT_LE_CONN_UPDATE_COMPLETE: u8 = 0x03;
pub const EVT_LE_READ_REMOTE_USED_FEATURES: u8 = 0x04;
pub const EVT_LE_LTK_REQUEST: u8 = 0x05;

// ===========================================================================
// Event Parameter Structs
// ===========================================================================

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_conn_complete {
    pub status: u8,
    pub handle: u16,
    pub bdaddr: bdaddr_t,
    pub link_type: u8,
    pub encr_mode: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_conn_request {
    pub bdaddr: bdaddr_t,
    pub dev_class: [u8; 3],
    pub link_type: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_disconn_complete {
    pub status: u8,
    pub handle: u16,
    pub reason: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_auth_complete {
    pub status: u8,
    pub handle: u16,
}

#[repr(C, packed)]
pub struct evt_remote_name_req_complete {
    pub status: u8,
    pub bdaddr: bdaddr_t,
    pub name: [u8; 248],
}

impl Default for evt_remote_name_req_complete {
    fn default() -> Self {
        Self { status: 0, bdaddr: bdaddr_t::default(), name: [0u8; 248] }
    }
}

impl Clone for evt_remote_name_req_complete {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for evt_remote_name_req_complete {}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_encrypt_change {
    pub status: u8,
    pub handle: u16,
    pub encrypt: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_read_remote_features_complete {
    pub status: u8,
    pub handle: u16,
    pub features: [u8; 8],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_read_remote_version_complete {
    pub status: u8,
    pub handle: u16,
    pub lmp_ver: u8,
    pub manufacturer: u16,
    pub lmp_subver: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_cmd_complete {
    pub ncmd: u8,
    pub opcode: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_cmd_status {
    pub status: u8,
    pub ncmd: u8,
    pub opcode: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_role_change {
    pub status: u8,
    pub bdaddr: bdaddr_t,
    pub role: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_pin_code_req {
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_link_key_req {
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_link_key_notify {
    pub bdaddr: bdaddr_t,
    pub link_key: [u8; 16],
    pub key_type: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_io_capability_request {
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_io_capability_response {
    pub bdaddr: bdaddr_t,
    pub capability: u8,
    pub oob_data: u8,
    pub authentication: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_user_confirm_request {
    pub bdaddr: bdaddr_t,
    pub passkey: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_user_passkey_request {
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_remote_oob_data_request {
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_simple_pairing_complete {
    pub status: u8,
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_user_passkey_notify {
    pub bdaddr: bdaddr_t,
    pub passkey: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_keypress_notify {
    pub bdaddr: bdaddr_t,
    pub type_: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_remote_host_features_notify {
    pub bdaddr: bdaddr_t,
    pub features: [u8; 8],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_pscan_rep_mode_change {
    pub bdaddr: bdaddr_t,
    pub pscan_rep_mode: u8,
}

// Inquiry info structs

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct inquiry_info {
    pub bdaddr: bdaddr_t,
    pub pscan_rep_mode: u8,
    pub pscan_period_mode: u8,
    pub pscan_mode: u8,
    pub dev_class: [u8; 3],
    pub clock_offset: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct inquiry_info_with_rssi {
    pub bdaddr: bdaddr_t,
    pub pscan_rep_mode: u8,
    pub pscan_period_mode: u8,
    pub dev_class: [u8; 3],
    pub clock_offset: u16,
    pub rssi: i8,
}

#[repr(C, packed)]
pub struct extended_inquiry_info {
    pub bdaddr: bdaddr_t,
    pub pscan_rep_mode: u8,
    pub pscan_period_mode: u8,
    pub dev_class: [u8; 3],
    pub clock_offset: u16,
    pub rssi: i8,
    pub data: [u8; 240],
}

impl Default for extended_inquiry_info {
    fn default() -> Self {
        Self {
            bdaddr: bdaddr_t::default(),
            pscan_rep_mode: 0,
            pscan_period_mode: 0,
            dev_class: [0; 3],
            clock_offset: 0,
            rssi: 0,
            data: [0u8; 240],
        }
    }
}

impl Clone for extended_inquiry_info {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for extended_inquiry_info {}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_inquiry_result {
    pub num_responses: u8,
    pub bdaddr: bdaddr_t,
    pub pscan_rep_mode: u8,
    pub pscan_period_mode: u8,
    pub pscan_mode: u8,
    pub dev_class: [u8; 3],
    pub clock_offset: u16,
}

// LE event structs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct evt_le_meta_event {
    pub subevent: u8,
    pub data: [u8; 0],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_le_connection_complete {
    pub status: u8,
    pub handle: u16,
    pub role: u8,
    pub peer_bdaddr_type: u8,
    pub peer_bdaddr: bdaddr_t,
    pub interval: u16,
    pub latency: u16,
    pub supervision_timeout: u16,
    pub master_clock_accuracy: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct le_advertising_info {
    pub evt_type: u8,
    pub bdaddr_type: u8,
    pub bdaddr: bdaddr_t,
    pub length: u8,
    pub data: [u8; 0],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_le_conn_update_complete {
    pub status: u8,
    pub handle: u16,
    pub interval: u16,
    pub latency: u16,
    pub supervision_timeout: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_le_read_remote_used_features_complete {
    pub status: u8,
    pub handle: u16,
    pub features: [u8; 8],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_le_ltk_request {
    pub handle: u16,
    pub random: u64,
    pub diversifier: u16,
}

// AMP / Physical Link event structs

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_physical_link_complete {
    pub status: u8,
    pub handle: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_disconn_physical_link_complete {
    pub status: u8,
    pub handle: u8,
    pub reason: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_logical_link_complete {
    pub status: u8,
    pub log_handle: u16,
    pub handle: u8,
    pub tx_flow_id: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct cmplt_handle {
    pub handle: u16,
    pub count: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_amp_status_change {
    pub status: u8,
    pub amp_status: u8,
}

// Stack internal event structs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct evt_stack_internal {
    pub type_: u16,
    pub data: [u8; 0],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct evt_si_device {
    pub event: u16,
    pub dev_id: u16,
}

// ===========================================================================
// Additional LE command/response structs
// ===========================================================================

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_host_channel_classification_cp {
    pub map: [u8; 5],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_read_channel_map_cp {
    pub handle: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_read_channel_map_rp {
    pub status: u8,
    pub handle: u16,
    pub map: [u8; 5],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_rand_rp {
    pub status: u8,
    pub random: u64,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_ltk_reply_rp {
    pub status: u8,
    pub handle: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_ltk_neg_reply_rp {
    pub status: u8,
    pub handle: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_read_supported_states_rp {
    pub status: u8,
    pub states: [u8; 8],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_receiver_test_cp {
    pub frequency: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_transmitter_test_cp {
    pub frequency: u8,
    pub length: u8,
    pub payload: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_test_end_rp {
    pub status: u8,
    pub num_pkts: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_remove_device_from_resolv_list_cp {
    pub bdaddr_type: u8,
    pub bdaddr: bdaddr_t,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_read_resolv_list_size_rp {
    pub status: u8,
    pub size: u8,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct le_set_address_resolution_enable_cp {
    pub enable: u8,
}

// ===========================================================================
// HCI Packet Header Structs
// ===========================================================================

pub const HCI_TYPE_LEN: usize = 1;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_command_hdr {
    pub opcode: u16,
    pub plen: u8,
}

pub const HCI_COMMAND_HDR_SIZE: usize = 3;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_event_hdr {
    pub evt: u8,
    pub plen: u8,
}

pub const HCI_EVENT_HDR_SIZE: usize = 2;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_acl_hdr {
    pub handle: u16,
    pub dlen: u16,
}

pub const HCI_ACL_HDR_SIZE: usize = 4;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_sco_hdr {
    pub handle: u16,
    pub dlen: u8,
}

pub const HCI_SCO_HDR_SIZE: usize = 3;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_iso_hdr {
    pub handle: u16,
    pub dlen: u16,
}

pub const HCI_ISO_HDR_SIZE: usize = 4;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_msg_hdr {
    pub device: u16,
    pub type_: u16,
    pub plen: u16,
}

// ===========================================================================
// ISO Handle / Flags helpers
// ===========================================================================

/// Extract PB (packet boundary) flag from ISO handle field.
#[inline]
pub const fn iso_flags_pb(handle: u16) -> u8 {
    ((handle >> 12) & 0x03) as u8
}

/// Extract TS (timestamp) flag from ISO handle field.
#[inline]
pub const fn iso_flags_ts(handle: u16) -> u8 {
    ((handle >> 14) & 0x01) as u8
}

/// Pack ISO handle with PB and TS flags.
#[inline]
pub const fn iso_flags_pack(handle: u16, pb: u8, ts: u8) -> u16 {
    (handle & 0x0fff) | ((pb as u16 & 0x03) << 12) | ((ts as u16 & 0x01) << 14)
}

// ===========================================================================
// Socket Options and CMSG
// ===========================================================================

/// Socket option to set direction for HCI frames.
pub const HCI_DATA_DIR: i32 = 1;
/// Socket option to set the HCI filter.
pub const HCI_FILTER: i32 = 2;
/// Socket option to get timestamps on received frames.
pub const HCI_TIME_STAMP: i32 = 3;

/// CMSG type for direction info.
pub const HCI_CMSG_DIR: i32 = 0x0001;
/// CMSG type for timestamp.
pub const HCI_CMSG_TSTAMP: i32 = 0x0002;

// ===========================================================================
// sockaddr_hci and HCI Channel Constants
// ===========================================================================

/// Special device id meaning "no device".
pub const HCI_DEV_NONE: u16 = 0xFFFF;

/// Raw HCI channel.
pub const HCI_CHANNEL_RAW: u16 = 0;
/// User channel (exclusive access).
pub const HCI_CHANNEL_USER: u16 = 1;
/// Monitor channel (btmon).
pub const HCI_CHANNEL_MONITOR: u16 = 2;
/// Control channel (management).
pub const HCI_CHANNEL_CONTROL: u16 = 3;
/// Logging channel.
pub const HCI_CHANNEL_LOGGING: u16 = 4;

/// HCI socket address structure matching `struct sockaddr_hci` from the kernel.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct sockaddr_hci {
    pub hci_family: u16,
    pub hci_dev: u16,
    pub hci_channel: u16,
}

// ===========================================================================
// HCI Filter
// ===========================================================================

/// Filter bit constants.
pub const HCI_FLT_TYPE_BITS: u32 = 31;
pub const HCI_FLT_EVENT_BITS: u32 = 63;
pub const HCI_FLT_OGF_BITS: u32 = 63;
pub const HCI_FLT_OCF_BITS: u32 = 127;

/// HCI socket filter structure matching `struct hci_filter` from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct hci_filter {
    pub type_mask: u32,
    pub event_mask: [u32; 2],
    pub opcode: u16,
}

// ===========================================================================
// Filter Manipulation Helpers
// ===========================================================================

/// Set a bit in a u32 mask array.
#[inline]
pub fn hci_set_bit(nr: u32, addr: &mut u32) {
    *addr |= 1u32 << (nr & 31);
}

/// Clear a bit in a u32 mask.
#[inline]
pub fn hci_clear_bit(nr: u32, addr: &mut u32) {
    *addr &= !(1u32 << (nr & 31));
}

/// Test a bit in a u32 mask.
#[inline]
pub fn hci_test_bit(nr: u32, addr: u32) -> bool {
    (addr & (1u32 << (nr & 31))) != 0
}

/// Clear an entire HCI filter to zero state.
#[inline]
pub fn hci_filter_clear(f: &mut hci_filter) {
    f.type_mask = 0;
    f.event_mask = [0; 2];
    f.opcode = 0;
}

/// Set a packet type bit in the filter.
#[inline]
pub fn hci_filter_set_ptype(t: u8, f: &mut hci_filter) {
    hci_set_bit(t as u32, &mut f.type_mask);
}

/// Clear a packet type bit in the filter.
#[inline]
pub fn hci_filter_clear_ptype(t: u8, f: &mut hci_filter) {
    hci_clear_bit(t as u32, &mut f.type_mask);
}

/// Test if a packet type bit is set in the filter.
#[inline]
pub fn hci_filter_test_ptype(t: u8, f: &hci_filter) -> bool {
    hci_test_bit(t as u32, f.type_mask)
}

/// Set all packet type bits in the filter.
#[inline]
pub fn hci_filter_all_ptypes(f: &mut hci_filter) {
    f.type_mask = 0xFFFF_FFFF;
}

/// Set an event bit in the filter.
#[inline]
pub fn hci_filter_set_event(e: u8, f: &mut hci_filter) {
    let idx = (e as usize) >> 5;
    if idx < 2 {
        hci_set_bit(e as u32 & 31, &mut f.event_mask[idx]);
    }
}

/// Clear an event bit in the filter.
#[inline]
pub fn hci_filter_clear_event(e: u8, f: &mut hci_filter) {
    let idx = (e as usize) >> 5;
    if idx < 2 {
        hci_clear_bit(e as u32 & 31, &mut f.event_mask[idx]);
    }
}

/// Test if an event bit is set in the filter.
#[inline]
pub fn hci_filter_test_event(e: u8, f: &hci_filter) -> bool {
    let idx = (e as usize) >> 5;
    if idx < 2 { hci_test_bit(e as u32 & 31, f.event_mask[idx]) } else { false }
}

/// Set all event bits in the filter.
#[inline]
pub fn hci_filter_all_events(f: &mut hci_filter) {
    f.event_mask = [0xFFFF_FFFF; 2];
}

/// Set the opcode filter.
#[inline]
pub fn hci_filter_set_opcode(opcode: u16, f: &mut hci_filter) {
    f.opcode = opcode;
}

// ===========================================================================
// Device Info and List Structures (ioctl data)
// ===========================================================================

/// HCI device statistics counters.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_dev_stats {
    pub err_rx: u32,
    pub err_tx: u32,
    pub cmd_tx: u32,
    pub evt_rx: u32,
    pub acl_tx: u32,
    pub acl_rx: u32,
    pub sco_tx: u32,
    pub sco_rx: u32,
    pub byte_rx: u32,
    pub byte_tx: u32,
}

/// HCI device information structure returned by HCIGETDEVINFO ioctl.
#[derive(Default, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct hci_dev_info {
    pub dev_id: u16,
    pub name: [u8; 8],
    pub bdaddr: bdaddr_t,
    pub flags: u32,
    pub type_: u8,
    pub features: [u8; 8],
    pub pkt_type: u32,
    pub link_policy: u32,
    pub link_mode: u32,
    pub acl_mtu: u16,
    pub acl_pkts: u16,
    pub sco_mtu: u16,
    pub sco_pkts: u16,
    pub stat: hci_dev_stats,
}

impl core::fmt::Debug for hci_dev_info {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let dev_id = self.dev_id;
        let flags = self.flags;
        let type_ = self.type_;
        let pkt_type = self.pkt_type;
        let link_policy = self.link_policy;
        let link_mode = self.link_mode;
        let acl_mtu = self.acl_mtu;
        let acl_pkts = self.acl_pkts;
        let sco_mtu = self.sco_mtu;
        let sco_pkts = self.sco_pkts;
        f.debug_struct("hci_dev_info")
            .field("dev_id", &dev_id)
            .field("name", &self.name)
            .field("bdaddr", &self.bdaddr)
            .field("flags", &flags)
            .field("type_", &type_)
            .field("features", &self.features)
            .field("pkt_type", &pkt_type)
            .field("link_policy", &link_policy)
            .field("link_mode", &link_mode)
            .field("acl_mtu", &acl_mtu)
            .field("acl_pkts", &acl_pkts)
            .field("sco_mtu", &sco_mtu)
            .field("sco_pkts", &sco_pkts)
            .field("stat", &self.stat)
            .finish()
    }
}

/// HCI connection info (returned by HCIGETCONNINFO).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_conn_info {
    pub handle: u16,
    pub bdaddr: bdaddr_t,
    pub type_: u8,
    pub out: u8,
    pub state: u16,
    pub link_mode: u32,
}

/// HCI device request (for dev list ioctls).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_dev_req {
    pub dev_id: u16,
    pub dev_opt: u32,
}

/// Request to list HCI devices (HCIGETDEVLIST ioctl).
/// `dev_req` is a flexible array member; in Rust we use a single element placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct hci_dev_list_req {
    pub dev_num: u16,
    pub dev_req: [hci_dev_req; 0],
}

/// Request to list HCI connections (HCIGETCONNLIST ioctl).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct hci_conn_list_req {
    pub dev_id: u16,
    pub conn_num: u16,
    pub conn_info: [hci_conn_info; 0],
}

/// Connection info request (HCIGETCONNINFO).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct hci_conn_info_req {
    pub bdaddr: bdaddr_t,
    pub type_: u8,
    pub conn_info: [hci_conn_info; 0],
}

/// Auth info request (HCIGETAUTHINFO).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_auth_info_req {
    pub bdaddr: bdaddr_t,
    pub type_: u8,
}

/// Inquiry cache flush flag.
pub const IREQ_CACHE_FLUSH: u16 = 0x0001;

/// HCI inquiry request (HCIINQUIRY ioctl).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct hci_inquiry_req {
    pub dev_id: u16,
    pub flags: u16,
    pub lap: [u8; 3],
    pub length: u8,
    pub num_rsp: u8,
}

// ===========================================================================
// hci_request (from hci_lib.h) — NOT zerocopy (contains usize pointers)
// ===========================================================================

/// HCI ioctl request structure from `hci_lib.h`.
/// Contains raw pointers as `usize` for FFI compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct hci_request {
    pub ogf: u16,
    pub ocf: u16,
    pub event: i32,
    pub cparam: usize,
    pub clen: i32,
    pub rparam: usize,
    pub rlen: i32,
}

// ===========================================================================
// hci_version (from hci_lib.h)
// ===========================================================================

/// HCI version information structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct hci_version {
    pub manufacturer: u16,
    pub hci_ver: u8,
    pub hci_rev: u16,
    pub lmp_ver: u8,
    pub lmp_subver: u16,
}

// ===========================================================================
// HCI QoS (already defined above, but alias for the version struct)
// ===========================================================================

// hci_qos is already defined above near Link Policy section.

// ===========================================================================
// String Conversion Utilities (from hci_lib.h)
// ===========================================================================

/// Convert HCI bus type to a human-readable string.
pub fn hci_bustostr(bus: u8) -> &'static str {
    match bus {
        HCI_VIRTUAL => "VIRTUAL",
        HCI_USB => "USB",
        HCI_PCCARD => "PCCARD",
        HCI_UART => "UART",
        HCI_RS232 => "RS232",
        HCI_PCI => "PCI",
        HCI_SDIO => "SDIO",
        HCI_SPI => "SPI",
        HCI_I2C => "I2C",
        HCI_SMD => "SMD",
        HCI_VIRTIO => "VIRTIO",
        HCI_IPC => "IPC",
        _ => "UNKNOWN",
    }
}

/// Convert HCI controller type to a human-readable string.
pub fn hci_typetostr(type_: u8) -> &'static str {
    match type_ {
        HCI_PRIMARY => "BR/EDR",
        HCI_AMP => "AMP",
        _ => "UNKNOWN",
    }
}

/// Convert HCI link mode flags to a human-readable string.
pub fn hci_lmtostr(link_mode: u32) -> String {
    let mut parts = Vec::new();
    let flags = HciLinkMode::from_bits_truncate(link_mode);
    if flags.contains(HciLinkMode::HCI_LM_ACCEPT) {
        parts.push("ACCEPT");
    }
    if flags.contains(HciLinkMode::HCI_LM_MASTER) {
        parts.push("MASTER");
    }
    if flags.contains(HciLinkMode::HCI_LM_AUTH) {
        parts.push("AUTH");
    }
    if flags.contains(HciLinkMode::HCI_LM_ENCRYPT) {
        parts.push("ENCRYPT");
    }
    if flags.contains(HciLinkMode::HCI_LM_TRUSTED) {
        parts.push("TRUSTED");
    }
    if flags.contains(HciLinkMode::HCI_LM_RELIABLE) {
        parts.push("RELIABLE");
    }
    if flags.contains(HciLinkMode::HCI_LM_SECURE) {
        parts.push("SECURE");
    }
    if parts.is_empty() { "NONE".to_string() } else { parts.join(", ") }
}

/// Convert an HCI command opcode to a human-readable string.
pub fn hci_cmdtostr(opcode: u16) -> String {
    let ogf = cmd_opcode_ogf(opcode);
    let ocf = cmd_opcode_ocf(opcode);
    format!("OGF 0x{:02x} OCF 0x{:04x}", ogf, ocf)
}

/// Convert HCI device type (bus) to a human-readable string.
/// This is an alias to `hci_bustostr` for historical compatibility.
pub fn hci_dtypetostr(dtype: u8) -> &'static str {
    hci_bustostr(dtype)
}

/// Convert HCI version number to a human-readable string.
pub fn hci_vertostr(ver: u8) -> &'static str {
    match ver {
        0 => "1.0b",
        1 => "1.1",
        2 => "1.2",
        3 => "2.0",
        4 => "2.1",
        5 => "3.0",
        6 => "4.0",
        7 => "4.1",
        8 => "4.2",
        9 => "5.0",
        10 => "5.1",
        11 => "5.2",
        12 => "5.3",
        13 => "5.4",
        14 => "6.0",
        _ => "UNKNOWN",
    }
}
