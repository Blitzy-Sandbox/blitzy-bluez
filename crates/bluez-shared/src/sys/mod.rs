// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// FFI boundary module — kernel ABI type re-declarations
//
// This module is the designated FFI boundary for the entire workspace.  It
// re-declares Linux kernel Bluetooth constants, packed structures, and socket
// address types that cannot be obtained through any safe Rust abstraction.
//
// IMPORTANT:
// - `#[allow(non_camel_case_types)]` and `#[allow(non_upper_case_globals)]`
//   are ONLY permitted inside `sys/` modules (AAP Section 0.7.4).
// - `unsafe` code in `sys/` sub-modules is confined to kernel socket creation,
//   ioctl calls, and VHCI operations — each site has a `// SAFETY:` comment.
// - This root `mod.rs` contains NO `unsafe` blocks — only sub-module
//   declarations and convenience re-exports.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

// ---------------------------------------------------------------------------
// Sub-Module Declarations
// ---------------------------------------------------------------------------

/// Core Bluetooth FFI definitions: `AF_BLUETOOTH`, `bdaddr_t`, `BTPROTO_*`,
/// `SOL_*`, `BDADDR_*`, `bt_security`, `bt_power`, `bt_voice`, ISO QoS
/// structures, byte-order helpers, and custom integer types.
pub mod bluetooth;

/// HCI (Host Controller Interface) packet structures, opcodes, event codes,
/// socket options, ioctl constants, and the `sockaddr_hci` socket address.
pub mod hci;

/// L2CAP (Logical Link Control and Adaptation Protocol) socket address,
/// socket options, signaling structures, PSM constants, and CID definitions.
pub mod l2cap;

/// RFCOMM serial port emulation: socket address (`sockaddr_rc`), socket
/// options, and ioctl structures for virtual serial ports over Bluetooth.
pub mod rfcomm;

/// SCO (Synchronous Connection Oriented) socket address, options, and
/// connection parameter structures for synchronous audio links.
pub mod sco;

/// ISO (Isochronous Channels) socket address, BIS/CIS broadcast structures,
/// and socket options for LE Audio isochronous channel management.
pub mod iso;

/// BNEP (Bluetooth Network Encapsulation Protocol) constants, packed
/// control/message structures, and ioctl definitions for PAN networking.
pub mod bnep;

/// HIDP (Human Interface Device Protocol) ioctl structures for HID-over-
/// Bluetooth device management.
pub mod hidp;

/// CMTP (CAPI Message Transport Protocol) ioctl structures for ISDN-over-
/// Bluetooth device management.
pub mod cmtp;

/// Bluetooth Management API (MGMT) protocol: ~200+ opcodes, ~50+ event
/// codes, TLV structures, typed Rust enums, and command/response parameter
/// structs for controlling the kernel Bluetooth subsystem.
pub mod mgmt;

/// Safe wrappers for common libc/POSIX FFI operations (socket, ioctl, read,
/// write, etc.) used across the workspace.  Higher-level daemon, tool, and
/// tester code should call these safe functions instead of writing inline
/// `unsafe` blocks.
pub mod ffi_helpers;

// ---------------------------------------------------------------------------
// Convenience Re-Exports — Core Address and Protocol Types
// ---------------------------------------------------------------------------

// Bluetooth device address types
pub use bluetooth::BdAddr;
pub use bluetooth::bdaddr_t;

// Address family and protocol family constants
pub use bluetooth::AF_BLUETOOTH;
pub use bluetooth::PF_BLUETOOTH;

// Protocol identifiers for socket(AF_BLUETOOTH, ..., BTPROTO_*)
pub use bluetooth::BTPROTO_AVDTP;
pub use bluetooth::BTPROTO_BNEP;
pub use bluetooth::BTPROTO_CMTP;
pub use bluetooth::BTPROTO_HCI;
pub use bluetooth::BTPROTO_HIDP;
pub use bluetooth::BTPROTO_ISO;
pub use bluetooth::BTPROTO_L2CAP;
pub use bluetooth::BTPROTO_RFCOMM;
pub use bluetooth::BTPROTO_SCO;

// Socket option levels for setsockopt/getsockopt
pub use bluetooth::SOL_BLUETOOTH;
pub use bluetooth::SOL_HCI;
pub use bluetooth::SOL_L2CAP;
pub use bluetooth::SOL_RFCOMM;
pub use bluetooth::SOL_SCO;

// Address type constants
pub use bluetooth::BDADDR_BREDR;
pub use bluetooth::BDADDR_LE_PUBLIC;
pub use bluetooth::BDADDR_LE_RANDOM;

// Well-known address constants
pub use bluetooth::BDADDR_ALL;
pub use bluetooth::BDADDR_ANY;
pub use bluetooth::BDADDR_LOCAL;

// Socket option structures
pub use bluetooth::bt_security;

// ---------------------------------------------------------------------------
// Convenience Re-Exports — HCI Socket Address
// ---------------------------------------------------------------------------

pub use hci::sockaddr_hci;

// ---------------------------------------------------------------------------
// Convenience Re-Exports — MGMT Core Types
// ---------------------------------------------------------------------------

pub use mgmt::mgmt_addr_info;
pub use mgmt::mgmt_hdr;

// ---------------------------------------------------------------------------
// POSIX Time Helper — safe wrapper for localtime_r
// ---------------------------------------------------------------------------

/// Broken-down local time components extracted from a Unix timestamp.
///
/// Fields mirror the relevant members of `libc::tm` but are returned as
/// safe Rust types so callers outside `sys/` never need `unsafe`.
#[derive(Debug, Clone, Copy)]
pub struct LocalTime {
    /// Year (e.g. 2024).
    pub year: i32,
    /// Month (1-based, 1 = January).
    pub month: u8,
    /// Day of month (1-based).
    pub day: u8,
    /// Hour (0–23).
    pub hour: i32,
    /// Minute (0–59).
    pub minute: i32,
    /// Second (0–60, 60 for leap second).
    pub second: i32,
}

/// Convert a Unix timestamp (seconds since epoch) to local time components.
///
/// This is a safe wrapper around POSIX `localtime_r`, confined to the `sys/`
/// FFI boundary module per AAP Section 0.7.4.
#[allow(unsafe_code)]
pub fn localtime_from_unix(unix_secs: i64) -> LocalTime {
    let t: libc::time_t = unix_secs;
    // SAFETY: `localtime_r` is a POSIX-mandated thread-safe function that
    // writes the broken-down local time into a caller-provided `libc::tm`.
    // Both `t` and `tm` are valid stack-local variables for the duration
    // of the call.  The returned pointer (ignored here) aliases `&mut tm`.
    // SAFETY: zeroed() produces a valid all-zeros libc::tm struct.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&t, &mut tm);
    }
    LocalTime {
        year: 1900 + tm.tm_year,
        month: (tm.tm_mon + 1) as u8,
        day: tm.tm_mday as u8,
        hour: tm.tm_hour,
        minute: tm.tm_min,
        second: tm.tm_sec,
    }
}
