// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// BNEP (Bluetooth Network Encapsulation Protocol) kernel ABI definitions.
//
// Rust re-declaration of the Linux kernel `bluetooth/bnep.h` header.
// Provides PAN service class UUIDs, BNEP packet and control type constants,
// response/error codes, L2CAP connection settings, packed control/message
// structures for wire-format serialization, and ioctl definitions with
// associated request and info structures for the BNEP kernel driver.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// Ethernet Address Length (from <net/ethernet.h>)
// ---------------------------------------------------------------------------

/// Ethernet hardware address length in bytes (from `<net/ethernet.h>`).
pub const ETH_ALEN: usize = 6;

// ---------------------------------------------------------------------------
// BNEP UUID Constants
// ---------------------------------------------------------------------------

/// Bluetooth Base UUID as a 128-bit byte array (big-endian):
/// `00000000-0000-1000-8000-00805F9B34FB`.
pub const BNEP_BASE_UUID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
];

/// BNEP UUID size indicator: 16-bit UUID (2 bytes).
pub const BNEP_UUID16: u8 = 0x02;

/// BNEP UUID size indicator: 32-bit UUID (4 bytes).
pub const BNEP_UUID32: u8 = 0x04;

/// BNEP UUID size indicator: 128-bit UUID (16 bytes).
pub const BNEP_UUID128: u8 = 0x16;

// ---------------------------------------------------------------------------
// PAN Service Class UUIDs
// ---------------------------------------------------------------------------

/// PAN User (PANU) service class UUID.
pub const BNEP_SVC_PANU: u16 = 0x1115;

/// Network Access Point (NAP) service class UUID.
pub const BNEP_SVC_NAP: u16 = 0x1116;

/// Group Ad-hoc Network (GN) service class UUID.
pub const BNEP_SVC_GN: u16 = 0x1117;

// ---------------------------------------------------------------------------
// BNEP Packet Type Constants
// ---------------------------------------------------------------------------

/// BNEP general Ethernet packet type.
pub const BNEP_GENERAL: u8 = 0x00;

/// BNEP control packet type.
pub const BNEP_CONTROL: u8 = 0x01;

/// BNEP compressed Ethernet packet (no addresses).
pub const BNEP_COMPRESSED: u8 = 0x02;

/// BNEP compressed packet with source address only.
pub const BNEP_COMPRESSED_SRC_ONLY: u8 = 0x03;

/// BNEP compressed packet with destination address only.
pub const BNEP_COMPRESSED_DST_ONLY: u8 = 0x04;

// ---------------------------------------------------------------------------
// BNEP Control Type Constants
// ---------------------------------------------------------------------------

/// BNEP control: command not understood.
pub const BNEP_CMD_NOT_UNDERSTOOD: u8 = 0x00;

/// BNEP control: setup connection request.
pub const BNEP_SETUP_CONN_REQ: u8 = 0x01;

/// BNEP control: setup connection response.
pub const BNEP_SETUP_CONN_RSP: u8 = 0x02;

/// BNEP control: network type filter set.
pub const BNEP_FILTER_NET_TYPE_SET: u8 = 0x03;

/// BNEP control: network type filter response.
pub const BNEP_FILTER_NET_TYPE_RSP: u8 = 0x04;

/// BNEP control: multicast address filter set.
pub const BNEP_FILTER_MULT_ADDR_SET: u8 = 0x05;

/// BNEP control: multicast address filter response.
pub const BNEP_FILTER_MULT_ADDR_RSP: u8 = 0x06;

// ---------------------------------------------------------------------------
// BNEP Response / Error Code Constants
// ---------------------------------------------------------------------------

/// BNEP response: operation successful.
pub const BNEP_SUCCESS: u16 = 0x00;

/// BNEP connection response: invalid destination service UUID.
pub const BNEP_CONN_INVALID_DST: u16 = 0x01;

/// BNEP connection response: invalid source service UUID.
pub const BNEP_CONN_INVALID_SRC: u16 = 0x02;

/// BNEP connection response: invalid service UUID.
pub const BNEP_CONN_INVALID_SVC: u16 = 0x03;

/// BNEP connection response: connection not allowed.
pub const BNEP_CONN_NOT_ALLOWED: u16 = 0x04;

/// BNEP filter response: unsupported request.
pub const BNEP_FILTER_UNSUPPORTED_REQ: u16 = 0x01;

/// BNEP filter response: invalid network protocol type range.
pub const BNEP_FILTER_INVALID_RANGE: u16 = 0x02;

/// BNEP filter response: invalid multicast address.
pub const BNEP_FILTER_INVALID_MCADDR: u16 = 0x02;

/// BNEP filter response: maximum filter limit reached.
pub const BNEP_FILTER_LIMIT_REACHED: u16 = 0x03;

/// BNEP filter response: denied due to security restrictions.
pub const BNEP_FILTER_DENIED_SECURITY: u16 = 0x04;

// ---------------------------------------------------------------------------
// L2CAP / BNEP Settings Constants
// ---------------------------------------------------------------------------

/// BNEP minimum MTU in bytes.
pub const BNEP_MTU: u16 = 1691;

/// BNEP flush timeout value (0xFFFF = infinite / no flush).
pub const BNEP_FLUSH_TO: u16 = 0xffff;

/// BNEP connection timeout in seconds.
pub const BNEP_CONNECT_TO: u16 = 15;

/// BNEP filter operation timeout in seconds.
pub const BNEP_FILTER_TO: u16 = 15;

/// L2CAP Protocol/Service Multiplexer for BNEP.
pub const BNEP_PSM: u16 = 0x0f;

// ---------------------------------------------------------------------------
// BNEP Header Constants
// ---------------------------------------------------------------------------

/// Mask for extracting the BNEP packet type from the type/extension byte.
pub const BNEP_TYPE_MASK: u8 = 0x7f;

/// Bit flag indicating an extension header follows.
pub const BNEP_EXT_HEADER: u8 = 0x80;

/// BNEP setup response indicator value.
pub const BNEP_SETUP_RESPONSE: u8 = 0;

// ---------------------------------------------------------------------------
// BNEP Packed Control / Message Structures (wire format)
// ---------------------------------------------------------------------------

/// BNEP setup connection request header.
///
/// On the wire this is followed by a variable-length service UUID pair
/// whose total size is `2 * uuid_size` bytes (the flexible `service[0]`
/// array in the C definition).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct bnep_setup_conn_req {
    /// BNEP packet type byte (includes extension header flag).
    pub type_: u8,
    /// BNEP control type (`BNEP_SETUP_CONN_REQ`).
    pub ctrl: u8,
    /// Size of each UUID in the following service UUID pair (2, 4, or 16).
    pub uuid_size: u8,
}

/// BNEP set filter request header.
///
/// On the wire this is followed by `len` bytes of filter entries
/// (the flexible `list[0]` array in the C definition).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct bnep_set_filter_req {
    /// BNEP packet type byte (includes extension header flag).
    pub type_: u8,
    /// BNEP control type (`BNEP_FILTER_NET_TYPE_SET` or `BNEP_FILTER_MULT_ADDR_SET`).
    pub ctrl: u8,
    /// Length in bytes of the filter list that follows this header.
    pub len: u16,
}

/// BNEP control command not understood response.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct bnep_ctrl_cmd_not_understood_cmd {
    /// BNEP packet type byte (includes extension header flag).
    pub type_: u8,
    /// BNEP control type (`BNEP_CMD_NOT_UNDERSTOOD`).
    pub ctrl: u8,
    /// The unrecognized control type that triggered this response.
    pub unkn_ctrl: u8,
}

/// BNEP control response message.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct bnep_control_rsp {
    /// BNEP packet type byte (includes extension header flag).
    pub type_: u8,
    /// BNEP control type (e.g., `BNEP_SETUP_CONN_RSP`).
    pub ctrl: u8,
    /// Response code (e.g., `BNEP_SUCCESS`, `BNEP_CONN_INVALID_DST`).
    pub resp: u16,
}

/// BNEP extension header.
///
/// On the wire this is followed by `len` bytes of extension data
/// (the flexible `data[0]` array in the C definition).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct bnep_ext_hdr {
    /// Extension type byte (includes chained extension flag in bit 7).
    pub type_: u8,
    /// Length in bytes of the extension data that follows this header.
    pub len: u8,
}

// ---------------------------------------------------------------------------
// BNEP Ioctl Definitions
// ---------------------------------------------------------------------------

/// Helper: construct a Linux ioctl request number from direction, type, number, and data size.
///
/// Mirrors the kernel `_IOC(dir, type, nr, size)` macro:
/// `(dir << 30) | (size << 16) | (type << 8) | nr`
const fn _ioc(dir: u64, type_: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (type_ << 8) | nr
}

/// Helper: `_IOW(type, nr, size)` — ioctl with write (userspace → kernel) semantics.
const fn _iow(type_: u64, nr: u64, size: u64) -> u64 {
    _ioc(1, type_, nr, size)
}

/// Helper: `_IOR(type, nr, size)` — ioctl with read (kernel → userspace) semantics.
const fn _ior(type_: u64, nr: u64, size: u64) -> u64 {
    _ioc(2, type_, nr, size)
}

/// `sizeof(int)` on Linux — used as the size parameter for BNEP ioctls.
const SIZEOF_INT: u64 = 4;

/// Ioctl: add a BNEP connection — `_IOW('B', 200, int)`.
pub const BNEPCONNADD: u64 = _iow(b'B' as u64, 200, SIZEOF_INT);

/// Ioctl: delete a BNEP connection — `_IOW('B', 201, int)`.
pub const BNEPCONNDEL: u64 = _iow(b'B' as u64, 201, SIZEOF_INT);

/// Ioctl: get BNEP connection list — `_IOR('B', 210, int)`.
pub const BNEPGETCONNLIST: u64 = _ior(b'B' as u64, 210, SIZEOF_INT);

/// Ioctl: get BNEP connection info — `_IOR('B', 211, int)`.
pub const BNEPGETCONNINFO: u64 = _ior(b'B' as u64, 211, SIZEOF_INT);

/// Ioctl: get BNEP supported features — `_IOR('B', 212, int)`.
pub const BNEPGETSUPPFEAT: u64 = _ior(b'B' as u64, 212, SIZEOF_INT);

// ---------------------------------------------------------------------------
// BNEP Ioctl Request / Info Structures (kernel driver interface)
// ---------------------------------------------------------------------------

/// BNEP connection add request passed to the `BNEPCONNADD` ioctl.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct bnep_connadd_req {
    /// Connected L2CAP socket file descriptor.
    pub sock: i32,
    /// Connection flags.
    pub flags: u32,
    /// PAN role (`BNEP_SVC_PANU`, `BNEP_SVC_NAP`, or `BNEP_SVC_GN`).
    pub role: u16,
    /// Name of the Ethernet network device to create (null-terminated).
    pub device: [u8; 16],
}

/// BNEP connection delete request passed to the `BNEPCONNDEL` ioctl.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct bnep_conndel_req {
    /// Connection flags.
    pub flags: u32,
    /// Destination Ethernet (MAC) address of the connection to remove.
    pub dst: [u8; ETH_ALEN],
}

/// BNEP connection information returned by the `BNEPGETCONNINFO` ioctl.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct bnep_conninfo {
    /// Connection flags.
    pub flags: u32,
    /// PAN role of this connection.
    pub role: u16,
    /// Current connection state.
    pub state: u16,
    /// Destination Ethernet (MAC) address.
    pub dst: [u8; ETH_ALEN],
    /// Name of the associated Ethernet network device (null-terminated).
    pub device: [u8; 16],
}

/// BNEP connection list request passed to the `BNEPGETCONNLIST` ioctl.
///
/// The `ci` field is a pointer to a caller-allocated array of
/// [`bnep_conninfo`] structures. On input, `cnum` specifies the maximum
/// number of entries the array can hold; on output, the kernel updates
/// `cnum` to the actual number of entries written.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct bnep_connlist_req {
    /// On input: maximum number of entries in the `ci` array.
    /// On output: actual number of entries filled by the kernel.
    pub cnum: u32,
    /// Pointer to a caller-allocated array of [`bnep_conninfo`] entries.
    pub ci: *mut bnep_conninfo,
}
