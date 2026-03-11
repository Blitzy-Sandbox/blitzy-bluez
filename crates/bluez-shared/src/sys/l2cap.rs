// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// L2CAP (Logical Link Control and Adaptation Protocol) kernel ABI definitions.
//
// Complete Rust re-declaration of `lib/bluetooth/l2cap.h` (271 lines).
// Contains the L2CAP socket address structure, socket option structures,
// link manager flags, signaling command codes and packed command structs,
// connection result/status codes, configuration option types and result codes,
// L2CAP modes, FCS types, QoS service types, info types/results, extended
// feature mask bitflags, fixed channel constants, and struct size constants.
//
// # Wire Compatibility
//
// Signaling command structures use `#[repr(C, packed)]` with `zerocopy`
// derive macros to guarantee identical memory layout to the corresponding
// C kernel structures defined with `__attribute__((packed))`.
//
// Socket address and socket option structures use `#[repr(C)]` to match
// the unpacked kernel ABI. Explicit padding fields are included where the
// C compiler would insert implicit padding bytes, enabling safe `zerocopy`
// `IntoBytes` derivation.

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// L2CAP Default Constants
// ---------------------------------------------------------------------------

/// Default Maximum Transmission Unit for L2CAP connections (672 bytes).
///
/// Corresponds to `#define L2CAP_DEFAULT_MTU 672` in `lib/bluetooth/l2cap.h`.
pub const L2CAP_DEFAULT_MTU: u16 = 672;

/// Default flush timeout for L2CAP connections (0xFFFF = infinite / no flush).
///
/// Corresponds to `#define L2CAP_DEFAULT_FLUSH_TO 0xFFFF` in `lib/bluetooth/l2cap.h`.
pub const L2CAP_DEFAULT_FLUSH_TO: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// L2CAP Socket Address
// ---------------------------------------------------------------------------

/// L2CAP socket address structure for `bind(2)`, `connect(2)`, and `accept(2)`.
///
/// Matches the kernel's `struct sockaddr_l2` exactly. An explicit trailing
/// padding byte (`_pad`) is included because the C compiler inserts 1 byte
/// of padding after `l2_bdaddr_type` (u8) to satisfy the 2-byte alignment
/// imposed by the `u16` members.
///
/// # C Layout
/// ```text
/// Offset  Size  Field
///   0       2   l2_family      (sa_family_t)
///   2       2   l2_psm         (unsigned short, little-endian PSM)
///   4       6   l2_bdaddr      (bdaddr_t)
///  10       2   l2_cid         (unsigned short, channel ID)
///  12       1   l2_bdaddr_type (uint8_t)
///  13       1   <padding>
/// Total: 14 bytes
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct sockaddr_l2 {
    /// Address family — must be `AF_BLUETOOTH` (31) for L2CAP sockets.
    pub l2_family: u16,
    /// Protocol/Service Multiplexer in little-endian byte order.
    pub l2_psm: u16,
    /// Bluetooth device address.
    pub l2_bdaddr: bdaddr_t,
    /// L2CAP channel identifier (CID).
    pub l2_cid: u16,
    /// Bluetooth address type (`BDADDR_BREDR`, `BDADDR_LE_PUBLIC`, `BDADDR_LE_RANDOM`).
    pub l2_bdaddr_type: u8,
    /// Trailing padding byte for C ABI compatibility.
    ///
    /// In the C `struct sockaddr_l2`, the compiler inserts 1 byte of
    /// trailing padding after `l2_bdaddr_type` to satisfy the 2-byte
    /// alignment requirement imposed by the `u16` members. This field
    /// makes the padding explicit so that `zerocopy::IntoBytes` can be
    /// safely derived.
    _pad: u8,
}

impl Default for sockaddr_l2 {
    fn default() -> Self {
        Self {
            l2_family: 0,
            l2_psm: 0,
            l2_bdaddr: bdaddr_t { b: [0u8; 6] },
            l2_cid: 0,
            l2_bdaddr_type: 0,
            _pad: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// L2CAP Socket Options
// ---------------------------------------------------------------------------

/// Socket option number for L2CAP connection options.
///
/// Used with `getsockopt(SOL_L2CAP, L2CAP_OPTIONS, ...)` to query or set
/// negotiated L2CAP parameters.
///
/// Corresponds to `#define L2CAP_OPTIONS 0x01` in `lib/bluetooth/l2cap.h`.
pub const L2CAP_OPTIONS: i32 = 0x01;

/// L2CAP connection options for `getsockopt` / `setsockopt`.
///
/// Matches the kernel's `struct l2cap_options` exactly. An explicit padding
/// byte (`_pad`) is included between `max_tx` and `txwin_size` because the
/// C compiler inserts 1 byte of padding to align the `uint16_t txwin_size`
/// field to a 2-byte boundary.
///
/// # C Layout
/// ```text
/// Offset  Size  Field
///   0       2   omtu       (uint16_t)
///   2       2   imtu       (uint16_t)
///   4       2   flush_to   (uint16_t)
///   6       1   mode       (uint8_t)
///   7       1   fcs        (uint8_t)
///   8       1   max_tx     (uint8_t)
///   9       1   <padding>
///  10       2   txwin_size (uint16_t)
/// Total: 12 bytes
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct l2cap_options {
    /// Outgoing Maximum Transmission Unit.
    pub omtu: u16,
    /// Incoming Maximum Transmission Unit.
    pub imtu: u16,
    /// Flush timeout value.
    pub flush_to: u16,
    /// L2CAP mode (see `L2CAP_MODE_*` constants).
    pub mode: u8,
    /// Frame Check Sequence option (see `L2CAP_FCS_*` constants).
    pub fcs: u8,
    /// Maximum number of transmit attempts.
    pub max_tx: u8,
    /// Internal padding byte for C ABI alignment compatibility.
    ///
    /// The C compiler inserts 1 byte of padding after `max_tx` (u8) to
    /// satisfy the 2-byte alignment of `txwin_size` (uint16_t).
    _pad: u8,
    /// Transmit window size for retransmission modes.
    pub txwin_size: u16,
}

/// Socket option number for L2CAP connection information.
///
/// Used with `getsockopt(SOL_L2CAP, L2CAP_CONNINFO, ...)` to retrieve
/// the HCI handle and device class for an L2CAP connection.
///
/// Corresponds to `#define L2CAP_CONNINFO 0x02` in `lib/bluetooth/l2cap.h`.
pub const L2CAP_CONNINFO: i32 = 0x02;

/// L2CAP connection information returned by `getsockopt`.
///
/// Matches the kernel's `struct l2cap_conninfo` exactly. An explicit
/// trailing padding byte is included because the C compiler inserts 1 byte
/// after `dev_class[3]` to satisfy the 2-byte alignment of `hci_handle`.
///
/// # C Layout
/// ```text
/// Offset  Size  Field
///   0       2   hci_handle (uint16_t)
///   2       3   dev_class  (uint8_t[3])
///   5       1   <padding>
/// Total: 6 bytes
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct l2cap_conninfo {
    /// HCI connection handle for the L2CAP link.
    pub hci_handle: u16,
    /// Device class of the remote peer (3-byte Class of Device field).
    pub dev_class: [u8; 3],
    /// Trailing padding byte for C ABI compatibility.
    _pad: u8,
}

// ---------------------------------------------------------------------------
// Link Manager Flags
// ---------------------------------------------------------------------------

/// Socket option number for L2CAP Link Manager flags.
///
/// Used with `getsockopt(SOL_L2CAP, L2CAP_LM, ...)` / `setsockopt(...)`.
///
/// Corresponds to `#define L2CAP_LM 0x03` in `lib/bluetooth/l2cap.h`.
pub const L2CAP_LM: i32 = 0x03;

/// Link Manager flag: require master role.
pub const L2CAP_LM_MASTER: u16 = 0x0001;

/// Link Manager flag: require authentication.
pub const L2CAP_LM_AUTH: u16 = 0x0002;

/// Link Manager flag: require encryption.
pub const L2CAP_LM_ENCRYPT: u16 = 0x0004;

/// Link Manager flag: trusted device.
pub const L2CAP_LM_TRUSTED: u16 = 0x0008;

/// Link Manager flag: reliable connection.
pub const L2CAP_LM_RELIABLE: u16 = 0x0010;

/// Link Manager flag: secure connection.
pub const L2CAP_LM_SECURE: u16 = 0x0020;

// ---------------------------------------------------------------------------
// L2CAP Command Codes
// ---------------------------------------------------------------------------

/// L2CAP signaling command code: Command Reject.
pub const L2CAP_COMMAND_REJ: u8 = 0x01;

/// L2CAP signaling command code: Connection Request.
pub const L2CAP_CONN_REQ: u8 = 0x02;

/// L2CAP signaling command code: Connection Response.
pub const L2CAP_CONN_RSP: u8 = 0x03;

/// L2CAP signaling command code: Configuration Request.
pub const L2CAP_CONF_REQ: u8 = 0x04;

/// L2CAP signaling command code: Configuration Response.
pub const L2CAP_CONF_RSP: u8 = 0x05;

/// L2CAP signaling command code: Disconnection Request.
pub const L2CAP_DISCONN_REQ: u8 = 0x06;

/// L2CAP signaling command code: Disconnection Response.
pub const L2CAP_DISCONN_RSP: u8 = 0x07;

/// L2CAP signaling command code: Echo Request.
pub const L2CAP_ECHO_REQ: u8 = 0x08;

/// L2CAP signaling command code: Echo Response.
pub const L2CAP_ECHO_RSP: u8 = 0x09;

/// L2CAP signaling command code: Information Request.
pub const L2CAP_INFO_REQ: u8 = 0x0a;

/// L2CAP signaling command code: Information Response.
pub const L2CAP_INFO_RSP: u8 = 0x0b;

/// L2CAP signaling command code: Create Channel Request (AMP).
pub const L2CAP_CREATE_REQ: u8 = 0x0c;

/// L2CAP signaling command code: Create Channel Response (AMP).
pub const L2CAP_CREATE_RSP: u8 = 0x0d;

/// L2CAP signaling command code: Move Channel Request (AMP).
pub const L2CAP_MOVE_REQ: u8 = 0x0e;

/// L2CAP signaling command code: Move Channel Response (AMP).
pub const L2CAP_MOVE_RSP: u8 = 0x0f;

/// L2CAP signaling command code: Move Channel Confirmation (AMP).
pub const L2CAP_MOVE_CFM: u8 = 0x10;

/// L2CAP signaling command code: Move Channel Confirmation Response (AMP).
pub const L2CAP_MOVE_CFM_RSP: u8 = 0x11;

/// L2CAP LE signaling command code: LE Credit Based Connection Request.
///
/// Defined in BT Core Spec v4.1+ for LE credit-based flow control mode.
/// Value from `monitor/bt.h` (`BT_L2CAP_PDU_LE_CONN_REQ`).
pub const L2CAP_LE_CONN_REQ: u8 = 0x14;

/// L2CAP LE signaling command code: LE Credit Based Connection Response.
///
/// Defined in BT Core Spec v4.1+ for LE credit-based flow control mode.
/// Value from `monitor/bt.h` (`BT_L2CAP_PDU_LE_CONN_RSP`).
pub const L2CAP_LE_CONN_RSP: u8 = 0x15;

/// L2CAP signaling command code: Enhanced Credit Based Connection Request.
///
/// Defined in BT Core Spec v5.2+ for enhanced credit-based flow control.
/// Value from `monitor/bt.h` (`BT_L2CAP_PDU_ECRED_CONN_REQ`).
pub const L2CAP_ECRED_CONN_REQ: u8 = 0x17;

/// L2CAP signaling command code: Enhanced Credit Based Connection Response.
///
/// Defined in BT Core Spec v5.2+ for enhanced credit-based flow control.
/// Value from `monitor/bt.h` (`BT_L2CAP_PDU_ECRED_CONN_RSP`).
pub const L2CAP_ECRED_CONN_RSP: u8 = 0x18;

// ---------------------------------------------------------------------------
// L2CAP Extended Feature Mask (bitflags)
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// L2CAP extended feature mask bitmask.
    ///
    /// Represents the negotiable features advertised via L2CAP Information
    /// Response (type = `L2CAP_IT_FEAT_MASK`). Each flag corresponds to an
    /// `L2CAP_FEAT_*` constant from `lib/bluetooth/l2cap.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct L2capFeatures: u32 {
        /// Flow control mode supported.
        const FLOWCTL     = 0x0000_0001;
        /// Retransmission mode supported.
        const RETRANS     = 0x0000_0002;
        /// Bidirectional QoS supported.
        const BIDIR_QOS   = 0x0000_0004;
        /// Enhanced Retransmission Mode supported.
        const ERTM        = 0x0000_0008;
        /// Streaming Mode supported.
        const STREAMING   = 0x0000_0010;
        /// FCS option supported.
        const FCS         = 0x0000_0020;
        /// Extended Flow Specification supported.
        const EXT_FLOW    = 0x0000_0040;
        /// Fixed Channels supported.
        const FIXED_CHAN  = 0x0000_0080;
        /// Extended Window Size supported.
        const EXT_WINDOW  = 0x0000_0100;
        /// Unicast Connectionless Data supported.
        const UCD         = 0x0000_0200;
    }
}

// ---------------------------------------------------------------------------
// L2CAP Fixed Channels
// ---------------------------------------------------------------------------

/// Fixed channel: L2CAP signaling channel.
pub const L2CAP_FC_L2CAP: u8 = 0x02;

/// Fixed channel: Connectionless data channel.
pub const L2CAP_FC_CONNLESS: u8 = 0x04;

/// Fixed channel: AMP Manager Protocol channel.
pub const L2CAP_FC_A2MP: u8 = 0x08;

// ---------------------------------------------------------------------------
// L2CAP Packed Signaling Command Structures
// ---------------------------------------------------------------------------
//
// All signaling command structs use `#[repr(C, packed)]` matching the
// C `__attribute__((packed))` on the kernel definitions.

/// L2CAP basic header prepended to all L2CAP PDUs.
///
/// ```text
/// Offset  Size  Field
///   0       2   len  (uint16_t) — payload length
///   2       2   cid  (uint16_t) — channel ID
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_hdr {
    /// Payload length (excludes this header).
    pub len: u16,
    /// Channel identifier.
    pub cid: u16,
}

/// Size of [`l2cap_hdr`] in bytes.
pub const L2CAP_HDR_SIZE: usize = 4;

/// L2CAP signaling command header.
///
/// ```text
/// Offset  Size  Field
///   0       1   code  (uint8_t)  — command code
///   1       1   ident (uint8_t)  — identifier (matches req/rsp)
///   2       2   len   (uint16_t) — data length
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_cmd_hdr {
    /// Command code (see `L2CAP_*` command code constants).
    pub code: u8,
    /// Command identifier (matches request with response).
    pub ident: u8,
    /// Length of command-specific data following this header.
    pub len: u16,
}

/// Size of [`l2cap_cmd_hdr`] in bytes.
pub const L2CAP_CMD_HDR_SIZE: usize = 4;

/// L2CAP Command Reject payload.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_cmd_rej {
    /// Rejection reason code.
    pub reason: u16,
}

/// Size of [`l2cap_cmd_rej`] in bytes.
pub const L2CAP_CMD_REJ_SIZE: usize = 2;

/// L2CAP Connection Request payload.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_conn_req {
    /// Protocol/Service Multiplexer.
    pub psm: u16,
    /// Source Channel Identifier.
    pub scid: u16,
}

/// Size of [`l2cap_conn_req`] in bytes.
pub const L2CAP_CONN_REQ_SIZE: usize = 4;

/// L2CAP Connection Response payload.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_conn_rsp {
    /// Destination Channel Identifier.
    pub dcid: u16,
    /// Source Channel Identifier.
    pub scid: u16,
    /// Connection result (see `L2CAP_CR_*` constants).
    pub result: u16,
    /// Connection status (see `L2CAP_CS_*` constants).
    pub status: u16,
}

/// Size of [`l2cap_conn_rsp`] in bytes.
pub const L2CAP_CONN_RSP_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Connection Result Codes
// ---------------------------------------------------------------------------

/// Connection successful.
pub const L2CAP_CR_SUCCESS: u16 = 0x0000;

/// Connection pending.
pub const L2CAP_CR_PEND: u16 = 0x0001;

/// Connection refused — PSM not supported.
pub const L2CAP_CR_BAD_PSM: u16 = 0x0002;

/// Connection refused — security block.
pub const L2CAP_CR_SEC_BLOCK: u16 = 0x0003;

/// Connection refused — no resources available.
pub const L2CAP_CR_NO_MEM: u16 = 0x0004;

// ---------------------------------------------------------------------------
// Connection Status Codes
// ---------------------------------------------------------------------------

/// No further information available.
pub const L2CAP_CS_NO_INFO: u16 = 0x0000;

/// Authentication pending.
pub const L2CAP_CS_AUTHEN_PEND: u16 = 0x0001;

/// Authorization pending.
pub const L2CAP_CS_AUTHOR_PEND: u16 = 0x0002;

// ---------------------------------------------------------------------------
// Configuration Request / Response Structures
// ---------------------------------------------------------------------------

/// L2CAP Configuration Request payload (fixed portion).
///
/// In C, this struct has a trailing flexible array member `data[0]` for
/// configuration options. In Rust, only the fixed header is represented;
/// option data follows immediately in the containing buffer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_conf_req {
    /// Destination Channel Identifier being configured.
    pub dcid: u16,
    /// Continuation flags.
    pub flags: u16,
}

/// Size of [`l2cap_conf_req`] fixed portion in bytes (excludes trailing data).
pub const L2CAP_CONF_REQ_SIZE: usize = 4;

/// L2CAP Configuration Response payload (fixed portion).
///
/// In C, this struct has a trailing flexible array member `data[0]` for
/// configuration options. In Rust, only the fixed header is represented;
/// option data follows immediately in the containing buffer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_conf_rsp {
    /// Source Channel Identifier being configured.
    pub scid: u16,
    /// Continuation flags.
    pub flags: u16,
    /// Configuration result (see `L2CAP_CONF_SUCCESS` through `L2CAP_CONF_EFS_REJECT`).
    pub result: u16,
}

/// Size of [`l2cap_conf_rsp`] fixed portion in bytes (excludes trailing data).
pub const L2CAP_CONF_RSP_SIZE: usize = 6;

// ---------------------------------------------------------------------------
// Configuration Result Codes
// ---------------------------------------------------------------------------

/// Configuration successful.
pub const L2CAP_CONF_SUCCESS: u16 = 0x0000;

/// Configuration parameters unacceptable.
pub const L2CAP_CONF_UNACCEPT: u16 = 0x0001;

/// Configuration rejected (no reason given).
pub const L2CAP_CONF_REJECT: u16 = 0x0002;

/// Unknown configuration option received.
pub const L2CAP_CONF_UNKNOWN: u16 = 0x0003;

/// Configuration pending.
pub const L2CAP_CONF_PENDING: u16 = 0x0004;

/// Configuration rejected — Extended Flow Specification.
pub const L2CAP_CONF_EFS_REJECT: u16 = 0x0005;

// ---------------------------------------------------------------------------
// Configuration Option Structure
// ---------------------------------------------------------------------------

/// L2CAP Configuration Option header.
///
/// In C, this struct has a trailing flexible array member `val[0]`.
/// In Rust, only the fixed header is represented; option value data
/// follows immediately in the containing buffer.
///
/// The field is named `type_` to avoid collision with the Rust `type` keyword.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_conf_opt {
    /// Option type (see `L2CAP_CONF_MTU` through `L2CAP_CONF_EWS`).
    pub type_: u8,
    /// Length of option value data following this header.
    pub len: u8,
}

/// Size of [`l2cap_conf_opt`] fixed portion in bytes (excludes trailing val data).
pub const L2CAP_CONF_OPT_SIZE: usize = 2;

// ---------------------------------------------------------------------------
// Configuration Option Types
// ---------------------------------------------------------------------------

/// Configuration option type: Maximum Transmission Unit.
pub const L2CAP_CONF_MTU: u8 = 0x01;

/// Configuration option type: Flush Timeout.
pub const L2CAP_CONF_FLUSH_TO: u8 = 0x02;

/// Configuration option type: Quality of Service.
pub const L2CAP_CONF_QOS: u8 = 0x03;

/// Configuration option type: Retransmission and Flow Control.
pub const L2CAP_CONF_RFC: u8 = 0x04;

/// Configuration option type: Frame Check Sequence.
pub const L2CAP_CONF_FCS: u8 = 0x05;

/// Configuration option type: Extended Flow Specification.
pub const L2CAP_CONF_EFS: u8 = 0x06;

/// Configuration option type: Extended Window Size.
pub const L2CAP_CONF_EWS: u8 = 0x07;

/// Maximum size of configuration option data.
pub const L2CAP_CONF_MAX_SIZE: usize = 22;

// ---------------------------------------------------------------------------
// L2CAP Modes
// ---------------------------------------------------------------------------

/// L2CAP mode: Basic (no retransmission, no flow control).
pub const L2CAP_MODE_BASIC: u8 = 0x00;

/// L2CAP mode: Retransmission.
pub const L2CAP_MODE_RETRANS: u8 = 0x01;

/// L2CAP mode: Flow Control.
pub const L2CAP_MODE_FLOWCTL: u8 = 0x02;

/// L2CAP mode: Enhanced Retransmission Mode (ERTM).
pub const L2CAP_MODE_ERTM: u8 = 0x03;

/// L2CAP mode: Streaming.
pub const L2CAP_MODE_STREAMING: u8 = 0x04;

/// L2CAP mode: LE Flow Control (credit-based, BT 4.1+).
pub const L2CAP_MODE_LE_FLOWCTL: u8 = 0x80;

/// L2CAP mode: Enhanced Credit-based flow control (BT 5.2+).
pub const L2CAP_MODE_ECRED: u8 = 0x81;

// ---------------------------------------------------------------------------
// FCS Types
// ---------------------------------------------------------------------------

/// FCS type: No FCS.
pub const L2CAP_FCS_NONE: u8 = 0x00;

/// FCS type: CRC-16 checksum.
pub const L2CAP_FCS_CRC16: u8 = 0x01;

// ---------------------------------------------------------------------------
// QoS Service Types
// ---------------------------------------------------------------------------

/// QoS service type: No traffic.
pub const L2CAP_SERVTYPE_NOTRAFFIC: u8 = 0x00;

/// QoS service type: Best effort.
pub const L2CAP_SERVTYPE_BESTEFFORT: u8 = 0x01;

/// QoS service type: Guaranteed.
pub const L2CAP_SERVTYPE_GUARANTEED: u8 = 0x02;

// ---------------------------------------------------------------------------
// Disconnection Request / Response Structures
// ---------------------------------------------------------------------------

/// L2CAP Disconnection Request payload.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_disconn_req {
    /// Destination Channel Identifier.
    pub dcid: u16,
    /// Source Channel Identifier.
    pub scid: u16,
}

/// Size of [`l2cap_disconn_req`] in bytes.
pub const L2CAP_DISCONN_REQ_SIZE: usize = 4;

/// L2CAP Disconnection Response payload.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_disconn_rsp {
    /// Destination Channel Identifier.
    pub dcid: u16,
    /// Source Channel Identifier.
    pub scid: u16,
}

/// Size of [`l2cap_disconn_rsp`] in bytes.
pub const L2CAP_DISCONN_RSP_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// Information Request / Response Structures
// ---------------------------------------------------------------------------

/// L2CAP Information Request payload.
///
/// The field is named `type_` to avoid collision with the Rust `type` keyword.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_info_req {
    /// Information type (see `L2CAP_IT_*` constants).
    pub type_: u16,
}

/// Size of [`l2cap_info_req`] in bytes.
pub const L2CAP_INFO_REQ_SIZE: usize = 2;

/// L2CAP Information Response payload (fixed portion).
///
/// In C, this struct has a trailing flexible array member `data[0]`.
/// In Rust, only the fixed header is represented.
///
/// The field is named `type_` to avoid collision with the Rust `type` keyword.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_info_rsp {
    /// Information type (see `L2CAP_IT_*` constants).
    pub type_: u16,
    /// Information result (see `L2CAP_IR_*` constants).
    pub result: u16,
}

/// Size of [`l2cap_info_rsp`] fixed portion in bytes (excludes trailing data).
pub const L2CAP_INFO_RSP_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// Information Type Constants
// ---------------------------------------------------------------------------

/// Information type: Connectionless MTU.
pub const L2CAP_IT_CL_MTU: u16 = 0x0001;

/// Information type: Extended Feature Mask.
pub const L2CAP_IT_FEAT_MASK: u16 = 0x0002;

// ---------------------------------------------------------------------------
// Information Result Constants
// ---------------------------------------------------------------------------

/// Information result: Success.
pub const L2CAP_IR_SUCCESS: u16 = 0x0000;

/// Information result: Not supported.
pub const L2CAP_IR_NOTSUPP: u16 = 0x0001;

// ---------------------------------------------------------------------------
// Create Channel (AMP) Structures
// ---------------------------------------------------------------------------

/// L2CAP Create Channel Request payload (AMP).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_create_req {
    /// Protocol/Service Multiplexer.
    pub psm: u16,
    /// Source Channel Identifier.
    pub scid: u16,
    /// AMP controller identifier.
    pub id: u8,
}

/// Size of [`l2cap_create_req`] in bytes.
pub const L2CAP_CREATE_REQ_SIZE: usize = 5;

/// L2CAP Create Channel Response payload (AMP).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_create_rsp {
    /// Destination Channel Identifier.
    pub dcid: u16,
    /// Source Channel Identifier.
    pub scid: u16,
    /// Connection result (see `L2CAP_CR_*` constants).
    pub result: u16,
    /// Connection status (see `L2CAP_CS_*` constants).
    pub status: u16,
}

/// Size of [`l2cap_create_rsp`] in bytes.
pub const L2CAP_CREATE_RSP_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Move Channel (AMP) Structures
// ---------------------------------------------------------------------------

/// L2CAP Move Channel Request payload (AMP).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_move_req {
    /// Initiator's Channel Identifier.
    pub icid: u16,
    /// Destination AMP controller identifier.
    pub id: u8,
}

/// Size of [`l2cap_move_req`] in bytes.
pub const L2CAP_MOVE_REQ_SIZE: usize = 3;

/// L2CAP Move Channel Response payload (AMP).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_move_rsp {
    /// Initiator's Channel Identifier.
    pub icid: u16,
    /// Move result code.
    pub result: u16,
}

/// Size of [`l2cap_move_rsp`] in bytes.
pub const L2CAP_MOVE_RSP_SIZE: usize = 4;

/// L2CAP Move Channel Confirmation payload (AMP).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_move_cfm {
    /// Initiator's Channel Identifier.
    pub icid: u16,
    /// Move confirmation result code.
    pub result: u16,
}

/// Size of [`l2cap_move_cfm`] in bytes.
pub const L2CAP_MOVE_CFM_SIZE: usize = 4;

/// L2CAP Move Channel Confirmation Response payload (AMP).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct l2cap_move_cfm_rsp {
    /// Initiator's Channel Identifier.
    pub icid: u16,
}

/// Size of [`l2cap_move_cfm_rsp`] in bytes.
pub const L2CAP_MOVE_CFM_RSP_SIZE: usize = 2;

// ---------------------------------------------------------------------------
// Compile-Time Size Assertions
// ---------------------------------------------------------------------------
//
// Verify that all struct sizes match the C ABI definitions exactly.

const _: () = assert!(core::mem::size_of::<sockaddr_l2>() == 14);
const _: () = assert!(core::mem::size_of::<l2cap_options>() == 12);
const _: () = assert!(core::mem::size_of::<l2cap_conninfo>() == 6);
const _: () = assert!(core::mem::size_of::<l2cap_hdr>() == L2CAP_HDR_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_cmd_hdr>() == L2CAP_CMD_HDR_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_cmd_rej>() == L2CAP_CMD_REJ_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_conn_req>() == L2CAP_CONN_REQ_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_conn_rsp>() == L2CAP_CONN_RSP_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_conf_req>() == L2CAP_CONF_REQ_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_conf_rsp>() == L2CAP_CONF_RSP_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_conf_opt>() == L2CAP_CONF_OPT_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_disconn_req>() == L2CAP_DISCONN_REQ_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_disconn_rsp>() == L2CAP_DISCONN_RSP_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_info_req>() == L2CAP_INFO_REQ_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_info_rsp>() == L2CAP_INFO_RSP_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_create_req>() == L2CAP_CREATE_REQ_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_create_rsp>() == L2CAP_CREATE_RSP_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_move_req>() == L2CAP_MOVE_REQ_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_move_rsp>() == L2CAP_MOVE_RSP_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_move_cfm>() == L2CAP_MOVE_CFM_SIZE);
const _: () = assert!(core::mem::size_of::<l2cap_move_cfm_rsp>() == L2CAP_MOVE_CFM_RSP_SIZE);
