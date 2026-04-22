// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// SCO (Synchronous Connection-Oriented) kernel ABI definitions.
//
// Complete Rust re-declaration of `lib/bluetooth/sco.h` (49 lines).
// Contains the SCO socket address structure, default MTU and flush-timeout
// constants, kernel-side connection timeout reference values, and socket
// option structures for retrieving SCO connection parameters via
// `getsockopt(2)`.
//
// # Wire Compatibility
//
// All structures use `#[repr(C)]` to guarantee identical memory layout to
// the corresponding C kernel structures.  `zerocopy` derive macros enable
// safe zero-copy serialization and deserialization for socket operations.
//
// # Kernel Timeout Constants
//
// The `SCO_CONN_TIMEOUT`, `SCO_DISCONN_TIMEOUT`, and `SCO_CONN_IDLE_TIMEOUT`
// constants are kernel-internal values expressed in jiffies (`HZ * N`).
// `HZ` is a kernel configuration parameter (`CONFIG_HZ`), commonly 250 on
// modern x86_64 Linux desktops/servers.  These constants are provided here
// as reference values using `HZ = 250`; they are not directly used in
// userspace but are preserved for documentation parity with the C header.

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// SCO Default Constants
// ---------------------------------------------------------------------------

/// Default Maximum Transmission Unit for SCO connections (500 bytes).
///
/// Corresponds to `SCO_DEFAULT_MTU` in `lib/bluetooth/sco.h`.
pub const SCO_DEFAULT_MTU: u16 = 500;

/// Default flush timeout for SCO connections (0xFFFF = infinite / no flush).
///
/// Corresponds to `SCO_DEFAULT_FLUSH_TO` in `lib/bluetooth/sco.h`.
pub const SCO_DEFAULT_FLUSH_TO: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Kernel Timeout Reference Constants (HZ-based)
// ---------------------------------------------------------------------------
//
// In the C kernel header these are defined as:
//   #define SCO_CONN_TIMEOUT       (HZ * 40)
//   #define SCO_DISCONN_TIMEOUT    (HZ * 2)
//   #define SCO_CONN_IDLE_TIMEOUT  (HZ * 60)
//
// `HZ` is determined by `CONFIG_HZ` in the kernel configuration.
// Common values: 100 (embedded), 250 (desktop/server), 1000 (low-latency).
// The constants below use HZ = 250 as the reference baseline.

/// Kernel timer frequency assumed for timeout constant computation.
///
/// The actual value depends on `CONFIG_HZ` in the running kernel.
/// Common values: 100, 250, 1000.  This constant is provided for
/// transparent computation of the HZ-dependent timeout values below.
const KERNEL_HZ: u32 = 250;

/// SCO connection establishment timeout in kernel jiffies.
///
/// Kernel definition: `HZ * 40` (40 seconds at the default HZ).
/// With `HZ = 250`, this equals 10,000 jiffies.
pub const SCO_CONN_TIMEOUT: u32 = KERNEL_HZ * 40;

/// SCO disconnection timeout in kernel jiffies.
///
/// Kernel definition: `HZ * 2` (2 seconds at the default HZ).
/// With `HZ = 250`, this equals 500 jiffies.
pub const SCO_DISCONN_TIMEOUT: u32 = KERNEL_HZ * 2;

/// SCO idle connection timeout in kernel jiffies.
///
/// Kernel definition: `HZ * 60` (60 seconds at the default HZ).
/// With `HZ = 250`, this equals 15,000 jiffies.
pub const SCO_CONN_IDLE_TIMEOUT: u32 = KERNEL_HZ * 60;

// ---------------------------------------------------------------------------
// SCO Socket Address
// ---------------------------------------------------------------------------

/// SCO socket address structure.
///
/// Used with `bind(2)`, `connect(2)`, and `accept(2)` on `AF_BLUETOOTH`
/// sockets created with `BTPROTO_SCO`.
///
/// # C Definition
/// ```c
/// struct sockaddr_sco {
///     sa_family_t  sco_family;   // Always AF_BLUETOOTH
///     bdaddr_t     sco_bdaddr;   // Bluetooth device address
/// };
/// ```
///
/// # Layout
/// ```text
/// Offset  Size  Field
/// 0       2     sco_family (u16 / sa_family_t)
/// 2       6     sco_bdaddr (bdaddr_t)
/// Total: 8 bytes
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct sockaddr_sco {
    /// Address family — must be `AF_BLUETOOTH` (31) for SCO sockets.
    pub sco_family: u16,
    /// Bluetooth device address for the SCO endpoint.
    pub sco_bdaddr: bdaddr_t,
}

impl Default for sockaddr_sco {
    fn default() -> Self {
        Self { sco_family: 0, sco_bdaddr: bdaddr_t { b: [0u8; 6] } }
    }
}

// ---------------------------------------------------------------------------
// SCO Socket Options
// ---------------------------------------------------------------------------

/// Socket option number for retrieving SCO connection options.
///
/// Used with `getsockopt(SOL_SCO, SCO_OPTIONS, ...)` to obtain the
/// negotiated MTU for a SCO connection.
///
/// Corresponds to `#define SCO_OPTIONS 0x01` in `lib/bluetooth/sco.h`.
pub const SCO_OPTIONS: i32 = 0x01;

/// SCO connection options returned by `getsockopt(SOL_SCO, SCO_OPTIONS)`.
///
/// # C Definition
/// ```c
/// struct sco_options {
///     uint16_t mtu;
/// };
/// ```
///
/// # Layout
/// ```text
/// Offset  Size  Field
/// 0       2     mtu (u16)
/// Total: 2 bytes
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct sco_options {
    /// Negotiated Maximum Transmission Unit for the SCO connection.
    pub mtu: u16,
}

/// Socket option number for retrieving SCO connection information.
///
/// Used with `getsockopt(SOL_SCO, SCO_CONNINFO, ...)` to obtain the
/// HCI handle and device class of the remote SCO peer.
///
/// Corresponds to `#define SCO_CONNINFO 0x02` in `lib/bluetooth/sco.h`.
pub const SCO_CONNINFO: i32 = 0x02;

/// SCO connection information returned by `getsockopt(SOL_SCO, SCO_CONNINFO)`.
///
/// # C Definition
/// ```c
/// struct sco_conninfo {
///     uint16_t hci_handle;
///     uint8_t  dev_class[3];
/// };
/// ```
///
/// # Layout
/// ```text
/// Offset  Size  Field
/// 0       2     hci_handle (u16)
/// 2       3     dev_class ([u8; 3])
/// 5       1     _pad (trailing padding for C ABI alignment)
/// Total: 6 bytes (sizeof in C = 6 due to u16 alignment)
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct sco_conninfo {
    /// HCI connection handle for the SCO link.
    pub hci_handle: u16,
    /// Device class of the remote peer (3-byte Class of Device field).
    pub dev_class: [u8; 3],
    /// Trailing padding byte for C ABI compatibility.
    ///
    /// In the C `struct sco_conninfo`, the compiler inserts 1 byte of
    /// trailing padding after `dev_class[3]` to satisfy the 2-byte
    /// alignment requirement imposed by the `uint16_t hci_handle` member.
    /// This field makes the padding explicit so that `zerocopy::IntoBytes`
    /// can be safely derived.
    _pad: u8,
}
