// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (C) 2002-2003  Marcel Holtmann <marcel@holtmann.org>
 */

//! CMTP (CAPI Message Transport Protocol) ioctl ABI definitions.
//!
//! Complete Rust re-declaration of `lib/bluetooth/cmtp.h`.
//! Contains MTU bound constants, ioctl command numbers, and the
//! connection add / delete / info / list structures that are passed
//! to the kernel CMTP driver through `ioctl(2)` calls.

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ─── MTU constants ───────────────────────────────────────────────────────────

/// Minimum MTU for CMTP connections.
pub const CMTP_MINIMUM_MTU: u16 = 152;

/// Default MTU for CMTP connections.
pub const CMTP_DEFAULT_MTU: u16 = 672;

// ─── Flag constants ──────────────────────────────────────────────────────────

/// CMTP loopback flag value.
pub const CMTP_LOOPBACK: u32 = 0;

// ─── Ioctl number encoding helpers (private) ─────────────────────────────────
//
// Linux ioctl encoding:
//   _IOC(dir, type, nr, size) = (dir << 30) | (size << 16) | (type << 8) | nr
//   _IOW = dir 1 (write: user → kernel)
//   _IOR = dir 2 (read:  kernel → user)

/// Encode a raw ioctl number from direction, type, number, and size fields.
const fn _ioc(dir: u64, type_: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (type_ << 8) | nr
}

/// Encode a write-direction ioctl number (user → kernel).
const fn _iow(type_: u64, nr: u64, size: u64) -> u64 {
    _ioc(1, type_, nr, size)
}

/// Encode a read-direction ioctl number (kernel → user).
const fn _ior(type_: u64, nr: u64, size: u64) -> u64 {
    _ioc(2, type_, nr, size)
}

/// Size of a C `int` in bytes, used in ioctl size parameter.
const SIZEOF_INT: u64 = 4;

// ─── Ioctl command definitions ───────────────────────────────────────────────

/// Add a new CMTP connection.
///
/// Corresponds to `_IOW('C', 200, int)` in the kernel header.
pub const CMTPCONNADD: u64 = _iow(b'C' as u64, 200, SIZEOF_INT);

/// Delete an existing CMTP connection.
///
/// Corresponds to `_IOW('C', 201, int)` in the kernel header.
pub const CMTPCONNDEL: u64 = _iow(b'C' as u64, 201, SIZEOF_INT);

/// Retrieve the list of active CMTP connections.
///
/// Corresponds to `_IOR('C', 210, int)` in the kernel header.
pub const CMTPGETCONNLIST: u64 = _ior(b'C' as u64, 210, SIZEOF_INT);

/// Retrieve information about a specific CMTP connection.
///
/// Corresponds to `_IOR('C', 211, int)` in the kernel header.
pub const CMTPGETCONNINFO: u64 = _ior(b'C' as u64, 211, SIZEOF_INT);

// ─── Ioctl request / info structures ─────────────────────────────────────────

/// CMTP connection add request passed to the [`CMTPCONNADD`] ioctl.
///
/// Provides a connected L2CAP socket file descriptor and behavioural flags
/// to the kernel CMTP driver when establishing a new connection.
///
/// # Layout
///
/// Matches the C struct:
/// ```c
/// struct cmtp_connadd_req {
///     int      sock;   /* connected L2CAP socket */
///     uint32_t flags;
/// };
/// ```
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct cmtp_connadd_req {
    /// Connected L2CAP socket file descriptor.
    pub sock: i32,
    /// Connection flags (e.g., [`CMTP_LOOPBACK`]).
    pub flags: u32,
}

/// CMTP connection delete request passed to the [`CMTPCONNDEL`] ioctl.
///
/// Identifies the connection to tear down by the remote device's Bluetooth
/// address.
///
/// # Layout
///
/// Matches the C struct (note: implicit padding between `bdaddr` and `flags`):
/// ```c
/// struct cmtp_conndel_req {
///     bdaddr_t bdaddr;
///     uint32_t flags;
/// };
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct cmtp_conndel_req {
    /// Bluetooth address of the remote device whose connection is deleted.
    pub bdaddr: bdaddr_t,
    /// Connection flags.
    pub flags: u32,
}

/// CMTP connection information returned by the [`CMTPGETCONNINFO`] ioctl.
///
/// Reports the current state of an active CMTP connection including the
/// remote device address, operational flags, connection state, and the
/// assigned CMTP channel number.
///
/// # Layout
///
/// Matches the C struct (note: implicit padding between fields):
/// ```c
/// struct cmtp_conninfo {
///     bdaddr_t bdaddr;
///     uint32_t flags;
///     uint16_t state;
///     int      num;
/// };
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct cmtp_conninfo {
    /// Bluetooth address of the remote device.
    pub bdaddr: bdaddr_t,
    /// Connection flags.
    pub flags: u32,
    /// Current connection state.
    pub state: u16,
    /// CMTP channel number.
    pub num: i32,
}

/// CMTP connection list request passed to the [`CMTPGETCONNLIST`] ioctl.
///
/// Provides a caller-allocated buffer for the kernel to fill with
/// [`cmtp_conninfo`] entries describing all active CMTP connections.
///
/// # Safety
///
/// The `ci` pointer must reference a valid, writable buffer of at least
/// `cnum` contiguous [`cmtp_conninfo`] entries.  The caller is responsible
/// for ensuring the pointer remains valid for the entire duration of the
/// ioctl system call.  On return the kernel overwrites `cnum` with the
/// actual number of entries written.
///
/// # Layout
///
/// Matches the C struct:
/// ```c
/// struct cmtp_connlist_req {
///     uint32_t             cnum;
///     struct cmtp_conninfo *ci;
/// };
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct cmtp_connlist_req {
    /// Number of entries: on input the maximum capacity of the `ci` array,
    /// on output the number of entries actually written by the kernel.
    pub cnum: u32,
    /// Pointer to a caller-allocated array of [`cmtp_conninfo`] entries.
    pub ci: *mut cmtp_conninfo,
}
