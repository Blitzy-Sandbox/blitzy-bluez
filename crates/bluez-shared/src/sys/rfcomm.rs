// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// RFCOMM (Radio Frequency Communication) kernel ABI definitions.
//
// Complete Rust re-declaration of the Linux `lib/bluetooth/rfcomm.h` header.
// Provides the RFCOMM socket address structure (`sockaddr_rc`), default MTU
// and PSM constants, socket option identifiers and structures (CONNINFO,
// link-mode flags), TTY device management ioctl command numbers, and the
// associated request, info, and list structures used with the kernel RFCOMM
// driver through `ioctl(2)` and `setsockopt(2)` / `getsockopt(2)` calls.
//
// All structures use `#[repr(C)]` to match the exact memory layout of the
// corresponding C kernel structures, with explicit padding fields where
// the C compiler inserts implicit alignment padding.  `zerocopy` derive
// macros are applied to enable safe zero-copy byte-level serialization
// and deserialization for socket and ioctl operations.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// RFCOMM Default Constants
// ---------------------------------------------------------------------------

/// Default Maximum Transmission Unit for RFCOMM connections (127 bytes).
///
/// Corresponds to `RFCOMM_DEFAULT_MTU` in the kernel header.
pub const RFCOMM_DEFAULT_MTU: u16 = 127;

/// L2CAP Protocol/Service Multiplexer for RFCOMM (PSM 3).
///
/// RFCOMM runs on top of L2CAP using this well-known PSM value.
pub const RFCOMM_PSM: u16 = 3;

// ---------------------------------------------------------------------------
// RFCOMM TTY Support Constants
// ---------------------------------------------------------------------------

/// Maximum number of RFCOMM TTY devices supported by the kernel driver.
///
/// Corresponds to `RFCOMM_MAX_DEV` in the kernel header.
pub const RFCOMM_MAX_DEV: u16 = 256;

// ---------------------------------------------------------------------------
// RFCOMM Socket Address
// ---------------------------------------------------------------------------

/// RFCOMM socket address structure for `bind(2)`, `connect(2)`, and
/// `accept(2)` operations on `AF_BLUETOOTH` / `BTPROTO_RFCOMM` sockets.
///
/// # Layout
///
/// Matches the C struct (with 1 byte of trailing padding due to
/// `u16` alignment of `rc_family`):
/// ```c
/// struct sockaddr_rc {
///     sa_family_t rc_family;   /* AF_BLUETOOTH */
///     bdaddr_t    rc_bdaddr;   /* remote device address */
///     uint8_t     rc_channel;  /* RFCOMM channel number (1–30) */
/// };
/// ```
///
/// C `sizeof(struct sockaddr_rc)` = 10 bytes (9 data + 1 trailing pad).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct sockaddr_rc {
    /// Address family — must be `AF_BLUETOOTH` (31).
    pub rc_family: u16,
    /// Bluetooth device address of the remote peer.
    pub rc_bdaddr: bdaddr_t,
    /// RFCOMM channel number (1–30, or 0 for auto-bind on listen).
    pub rc_channel: u8,
    /// Explicit trailing padding byte to match C ABI `sizeof` of 10.
    _pad: u8,
}

impl sockaddr_rc {
    /// Create a new RFCOMM socket address.
    ///
    /// # Arguments
    ///
    /// * `family` — Address family (typically `AF_BLUETOOTH`).
    /// * `bdaddr` — Remote Bluetooth device address.
    /// * `channel` — RFCOMM channel number (1–30).
    pub const fn new(family: u16, bdaddr: bdaddr_t, channel: u8) -> Self {
        Self { rc_family: family, rc_bdaddr: bdaddr, rc_channel: channel, _pad: 0 }
    }

    /// Create a zeroed RFCOMM socket address.
    pub const fn zeroed() -> Self {
        Self { rc_family: 0, rc_bdaddr: bdaddr_t { b: [0u8; 6] }, rc_channel: 0, _pad: 0 }
    }
}

// ---------------------------------------------------------------------------
// RFCOMM Socket Options — Connection Info
// ---------------------------------------------------------------------------

/// Socket option name for retrieving RFCOMM connection information.
///
/// Used with `getsockopt(fd, SOL_RFCOMM, RFCOMM_CONNINFO, ...)` to obtain
/// the underlying HCI handle and remote device class for an active RFCOMM
/// connection.
///
/// Corresponds to `RFCOMM_CONNINFO 0x02` in the kernel header.
pub const RFCOMM_CONNINFO: i32 = 0x02;

/// RFCOMM connection information returned by the `RFCOMM_CONNINFO`
/// socket option via `getsockopt(2)`.
///
/// # Layout
///
/// Matches the C struct (with 1 byte of trailing padding):
/// ```c
/// struct rfcomm_conninfo {
///     uint16_t hci_handle;
///     uint8_t  dev_class[3];
/// };
/// ```
///
/// C `sizeof(struct rfcomm_conninfo)` = 6 bytes (5 data + 1 trailing pad).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct rfcomm_conninfo {
    /// HCI connection handle for the underlying ACL link.
    pub hci_handle: u16,
    /// Class of Device of the remote peer (3-byte big-endian encoding).
    pub dev_class: [u8; 3],
    /// Explicit trailing padding byte to match C ABI `sizeof` of 6.
    _pad: u8,
}

impl rfcomm_conninfo {
    /// Create a zeroed connection info structure.
    pub const fn zeroed() -> Self {
        Self { hci_handle: 0, dev_class: [0u8; 3], _pad: 0 }
    }
}

// ---------------------------------------------------------------------------
// RFCOMM Socket Options — Link Mode
// ---------------------------------------------------------------------------

/// Socket option name for RFCOMM link mode configuration.
///
/// Used with `getsockopt(2)` / `setsockopt(2)` on `SOL_RFCOMM` to query or
/// set the link mode bitmask for an RFCOMM connection.  The value is a
/// bitmask of `RFCOMM_LM_*` flags.
///
/// Corresponds to `RFCOMM_LM 0x03` in the kernel header.
pub const RFCOMM_LM: i32 = 0x03;

/// Link mode flag: request/require master role on the ACL link.
pub const RFCOMM_LM_MASTER: u32 = 0x0001;

/// Link mode flag: require authentication before connection completion.
pub const RFCOMM_LM_AUTH: u32 = 0x0002;

/// Link mode flag: require encryption on the ACL link.
pub const RFCOMM_LM_ENCRYPT: u32 = 0x0004;

/// Link mode flag: trusted device (bypass authorization prompts).
pub const RFCOMM_LM_TRUSTED: u32 = 0x0008;

/// Link mode flag: reliable channel (ERTM-like reliability).
pub const RFCOMM_LM_RELIABLE: u32 = 0x0010;

/// Link mode flag: require Secure Connections (authenticated P-256).
pub const RFCOMM_LM_SECURE: u32 = 0x0020;

// ---------------------------------------------------------------------------
// RFCOMM TTY Device Ioctl Command Numbers
// ---------------------------------------------------------------------------
//
// Linux ioctl encoding (most architectures):
//   _IOC(dir, type, nr, size) = (dir << 30) | (size << 16) | (type << 8) | nr
//   _IOW = dir 1 (write: userspace → kernel)
//   _IOR = dir 2 (read:  kernel → userspace)
//
// RFCOMM uses type 'R' (0x52) for all ioctl commands.

/// Encode a raw ioctl number from direction, type, number, and size fields.
const fn _ioc(dir: u64, type_: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (type_ << 8) | nr
}

/// Encode a write-direction ioctl number (userspace → kernel).
const fn _iow(type_: u64, nr: u64, size: u64) -> u64 {
    _ioc(1, type_, nr, size)
}

/// Encode a read-direction ioctl number (kernel → userspace).
const fn _ior(type_: u64, nr: u64, size: u64) -> u64 {
    _ioc(2, type_, nr, size)
}

/// Size of a C `int` in bytes, used in ioctl size parameter encoding.
const SIZEOF_INT: u64 = 4;

/// Ioctl: create an RFCOMM TTY device — `_IOW('R', 200, int)`.
///
/// Takes an [`rfcomm_dev_req`] structure describing the RFCOMM connection
/// parameters for the new TTY device.
pub const RFCOMMCREATEDEV: u64 = _iow(b'R' as u64, 200, SIZEOF_INT);

/// Ioctl: release an RFCOMM TTY device — `_IOW('R', 201, int)`.
///
/// Takes an [`rfcomm_dev_req`] identifying the device to release.
pub const RFCOMMRELEASEDEV: u64 = _iow(b'R' as u64, 201, SIZEOF_INT);

/// Ioctl: retrieve the list of RFCOMM TTY devices — `_IOR('R', 210, int)`.
///
/// Takes an [`rfcomm_dev_list_req`] with a trailing array of
/// [`rfcomm_dev_info`] entries filled by the kernel on return.
pub const RFCOMMGETDEVLIST: u64 = _ior(b'R' as u64, 210, SIZEOF_INT);

/// Ioctl: retrieve info about a specific RFCOMM TTY device — `_IOR('R', 211, int)`.
///
/// Takes an [`rfcomm_dev_info`] structure filled by the kernel on return.
pub const RFCOMMGETDEVINFO: u64 = _ior(b'R' as u64, 211, SIZEOF_INT);

// ---------------------------------------------------------------------------
// RFCOMM TTY Device Request Structure
// ---------------------------------------------------------------------------

/// RFCOMM TTY device creation/release request passed to the
/// [`RFCOMMCREATEDEV`] and [`RFCOMMRELEASEDEV`] ioctls.
///
/// # Layout
///
/// Matches the C struct (with alignment padding):
/// ```c
/// struct rfcomm_dev_req {
///     int16_t   dev_id;    /* offset 0, 2 bytes */
///     /* 2 bytes padding */
///     uint32_t  flags;     /* offset 4, 4 bytes */
///     bdaddr_t  src;       /* offset 8, 6 bytes */
///     bdaddr_t  dst;       /* offset 14, 6 bytes */
///     uint8_t   channel;   /* offset 20, 1 byte */
///     /* 3 bytes trailing padding */
/// };
/// ```
///
/// C `sizeof(struct rfcomm_dev_req)` = 24 bytes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct rfcomm_dev_req {
    /// Device ID (−1 to allocate automatically, or a specific device index).
    pub dev_id: i16,
    /// Explicit padding between `dev_id` (i16, align 2) and `flags` (u32, align 4).
    _pad1: [u8; 2],
    /// Device flags — bitmask of `(1 << RFCOMM_REUSE_DLC)`, `(1 << RFCOMM_RELEASE_ONHUP)`, etc.
    pub flags: u32,
    /// Local adapter Bluetooth address (or `BDADDR_ANY` for any adapter).
    pub src: bdaddr_t,
    /// Remote device Bluetooth address.
    pub dst: bdaddr_t,
    /// RFCOMM channel number (1–30).
    pub channel: u8,
    /// Explicit trailing padding to match C ABI `sizeof` of 24.
    _pad2: [u8; 3],
}

impl rfcomm_dev_req {
    /// Create a zeroed device request structure.
    pub const fn zeroed() -> Self {
        Self {
            dev_id: 0,
            _pad1: [0u8; 2],
            flags: 0,
            src: bdaddr_t { b: [0u8; 6] },
            dst: bdaddr_t { b: [0u8; 6] },
            channel: 0,
            _pad2: [0u8; 3],
        }
    }
}

// ---------------------------------------------------------------------------
// RFCOMM TTY Device Flag Bit Indices
// ---------------------------------------------------------------------------
//
// These are BIT INDICES (not masks) — use as `(1u32 << RFCOMM_REUSE_DLC)`.

/// Bit index: reuse an existing DLC connection for the TTY device.
pub const RFCOMM_REUSE_DLC: u32 = 0;

/// Bit index: automatically release the TTY device on HUP.
pub const RFCOMM_RELEASE_ONHUP: u32 = 1;

/// Bit index: hang up the device immediately.
pub const RFCOMM_HANGUP_NOW: u32 = 2;

/// Bit index: TTY device is currently attached to a line discipline.
pub const RFCOMM_TTY_ATTACHED: u32 = 3;

// ---------------------------------------------------------------------------
// RFCOMM TTY Device Info Structure
// ---------------------------------------------------------------------------

/// RFCOMM TTY device information returned by the [`RFCOMMGETDEVINFO`]
/// ioctl and as array elements in [`rfcomm_dev_list_req`].
///
/// # Layout
///
/// Matches the C struct (with alignment padding):
/// ```c
/// struct rfcomm_dev_info {
///     int16_t   id;        /* offset 0, 2 bytes */
///     /* 2 bytes padding */
///     uint32_t  flags;     /* offset 4, 4 bytes */
///     uint16_t  state;     /* offset 8, 2 bytes */
///     bdaddr_t  src;       /* offset 10, 6 bytes */
///     bdaddr_t  dst;       /* offset 16, 6 bytes */
///     uint8_t   channel;   /* offset 22, 1 byte */
///     /* 1 byte trailing padding */
/// };
/// ```
///
/// C `sizeof(struct rfcomm_dev_info)` = 24 bytes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct rfcomm_dev_info {
    /// Device ID (index in the RFCOMM TTY device table).
    pub id: i16,
    /// Explicit padding between `id` (i16, align 2) and `flags` (u32, align 4).
    _pad1: [u8; 2],
    /// Device flags — bitmask of `(1 << RFCOMM_REUSE_DLC)`, etc.
    pub flags: u32,
    /// Current device state (kernel-defined state machine value).
    pub state: u16,
    /// Local adapter Bluetooth address.
    pub src: bdaddr_t,
    /// Remote device Bluetooth address.
    pub dst: bdaddr_t,
    /// RFCOMM channel number (1–30).
    pub channel: u8,
    /// Explicit trailing padding byte to match C ABI `sizeof` of 24.
    _pad2: u8,
}

impl rfcomm_dev_info {
    /// Create a zeroed device info structure.
    pub const fn zeroed() -> Self {
        Self {
            id: 0,
            _pad1: [0u8; 2],
            flags: 0,
            state: 0,
            src: bdaddr_t { b: [0u8; 6] },
            dst: bdaddr_t { b: [0u8; 6] },
            channel: 0,
            _pad2: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// RFCOMM TTY Device List Request Structure
// ---------------------------------------------------------------------------

/// RFCOMM TTY device list request header passed to the [`RFCOMMGETDEVLIST`]
/// ioctl.
///
/// In C, this struct contains a zero-length flexible array member
/// `dev_info[0]` following `dev_num`.  The caller allocates a buffer of
/// `sizeof(rfcomm_dev_list_req) + n * sizeof(rfcomm_dev_info)` bytes,
/// sets `dev_num` to `n`, and passes the buffer to the ioctl.  The kernel
/// fills the trailing `dev_info` entries and updates `dev_num` to the
/// actual count.
///
/// In Rust, the flexible array member is not represented as a field.
/// Callers should allocate an appropriately sized byte buffer and
/// compute the offset of the first [`rfcomm_dev_info`] entry as
/// `size_of::<rfcomm_dev_list_req>()` (4 bytes, matching the C struct).
///
/// # Layout
///
/// Matches the C struct (padded to 4 bytes due to the zero-length
/// `rfcomm_dev_info` array member enforcing alignment):
/// ```c
/// struct rfcomm_dev_list_req {
///     uint16_t            dev_num;
///     struct rfcomm_dev_info dev_info[0];
/// };
/// ```
///
/// C `sizeof(struct rfcomm_dev_list_req)` = 4 bytes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct rfcomm_dev_list_req {
    /// Number of device entries: on input the maximum capacity, on
    /// output the actual count filled by the kernel.
    pub dev_num: u16,
    /// Explicit padding to match C `sizeof` of 4 bytes (alignment
    /// imposed by the zero-length `rfcomm_dev_info` array member
    /// in the C definition, whose alignment is 4 due to `uint32_t`).
    _pad: [u8; 2],
}

impl rfcomm_dev_list_req {
    /// Create a new device list request header with the given capacity.
    ///
    /// # Arguments
    ///
    /// * `dev_num` — Maximum number of [`rfcomm_dev_info`] entries the
    ///   caller has allocated space for.
    pub const fn new(dev_num: u16) -> Self {
        Self { dev_num, _pad: [0u8; 2] }
    }
}
