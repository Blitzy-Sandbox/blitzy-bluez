// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// ISO (Isochronous Channels) socket ABI definitions.
//
// Complete Rust re-declaration of `lib/bluetooth/iso.h`.
// Provides default MTU and BIS count constants, the broadcast socket
// address structure (`sockaddr_iso_bc`), the unicast ISO socket address
// (`sockaddr_iso`), and a combined helper (`sockaddr_iso_with_bc`) that
// represents the full kernel buffer layout including the flexible-array
// broadcast member.
//
// # Kernel ABI Notes
//
// The C `struct sockaddr_iso` ends with a flexible array member:
//
// ```c
// struct sockaddr_iso {
//     sa_family_t     iso_family;
//     bdaddr_t        iso_bdaddr;
//     __u8            iso_bdaddr_type;
//     struct sockaddr_iso_bc iso_bc[];
// };
// ```
//
// Flexible array members cannot be represented directly in Rust.
// Instead, [`sockaddr_iso`] contains only the fixed-size portion and
// [`sockaddr_iso_with_bc`] appends a single [`sockaddr_iso_bc`] element
// at exactly the same byte offset the kernel expects (`iso_bc[0]`).
//
// When performing unicast-only operations, callers must ensure the
// buffer passed to `bind(2)` / `connect(2)` is at least 10 bytes
// (the C `sizeof(struct sockaddr_iso)` which includes 1 byte of
// trailing padding at alignment 2).  The kernel validates
// `addr_len >= sizeof(struct sockaddr_iso)` and rejects shorter
// buffers with `EINVAL`.  For broadcast operations, pass the full
// [`sockaddr_iso_with_bc`] (49 bytes), which satisfies both the
// minimum-size check and the broadcast-presence check
// (`addr_len > sizeof(struct sockaddr_iso)`).

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// ISO Default Constants
// ---------------------------------------------------------------------------

/// Default Maximum Transmission Unit for ISO channels (in bytes).
///
/// Mirrors `#define ISO_DEFAULT_MTU 251` from `iso.h`.
pub const ISO_DEFAULT_MTU: u16 = 251;

/// Maximum number of BIS (Broadcast Isochronous Stream) indices that
/// can be specified in a broadcast socket address.
///
/// Mirrors `#define ISO_MAX_NUM_BIS 0x1f` from `iso.h`.  The value 31
/// matches the Bluetooth Core Specification limit for BIS indices
/// within a single BIG (Broadcast Isochronous Group).
pub const ISO_MAX_NUM_BIS: u8 = 0x1f;

// ---------------------------------------------------------------------------
// Broadcast Socket Address
// ---------------------------------------------------------------------------

/// ISO broadcast socket address — identifies a broadcast source and the
/// set of BIS indices to connect to.
///
/// Mirrors the C `struct sockaddr_iso_bc` from `iso.h`:
///
/// ```c
/// struct sockaddr_iso_bc {
///     bdaddr_t    bc_bdaddr;
///     __u8        bc_bdaddr_type;
///     __u8        bc_sid;
///     __u8        bc_num_bis;
///     __u8        bc_bis[ISO_MAX_NUM_BIS];
/// };
/// ```
///
/// # Layout
///
/// All fields have alignment 1 (`bdaddr_t` is `repr(C, packed)`
/// with byte alignment, remaining fields are `u8` / `[u8; N]`).
/// Total size is 40 bytes with no implicit padding under `repr(C)`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct sockaddr_iso_bc {
    /// Broadcast source Bluetooth device address.
    pub bc_bdaddr: bdaddr_t,

    /// Address type of `bc_bdaddr` (e.g., public or random).
    pub bc_bdaddr_type: u8,

    /// Advertising Set Identifier (SID) of the periodic advertising
    /// train carrying the BIG.
    pub bc_sid: u8,

    /// Number of valid BIS indices in `bc_bis`.
    /// Must not exceed [`ISO_MAX_NUM_BIS`] (31).
    pub bc_num_bis: u8,

    /// Array of BIS indices (1-based) to synchronize with.
    /// Only the first `bc_num_bis` entries are meaningful.
    /// The array is sized to [`ISO_MAX_NUM_BIS`] (31) to match the
    /// kernel structure layout.
    pub bc_bis: [u8; ISO_MAX_NUM_BIS as usize],
}

// ---------------------------------------------------------------------------
// Unicast Socket Address
// ---------------------------------------------------------------------------

/// ISO unicast socket address — the fixed-size portion of the kernel
/// `struct sockaddr_iso` (without the trailing flexible array member).
///
/// Mirrors the fixed fields of the C `struct sockaddr_iso` from `iso.h`:
///
/// ```c
/// struct sockaddr_iso {
///     sa_family_t     iso_family;   // AF_BLUETOOTH (31)
///     bdaddr_t        iso_bdaddr;   // source / destination address
///     __u8            iso_bdaddr_type;
///     struct sockaddr_iso_bc iso_bc[];  // flexible array (0 or 1 element)
/// };
/// ```
///
/// # Layout
///
/// The struct is `repr(C, packed)` so that its size equals the sum of
/// its field sizes (2 + 6 + 1 = 9 bytes) with no trailing padding.
/// This ensures that in [`sockaddr_iso_with_bc`], the broadcast member
/// is placed at the exact byte offset (9) where the kernel reads
/// `iso_bc[0]`.
///
/// # Kernel Size Requirement
///
/// The C compiler assigns `sizeof(struct sockaddr_iso) == 10` because
/// `sa_family_t` (`u16`) gives the struct alignment 2, producing 1 byte
/// of trailing padding.  The kernel's `iso_sock_bind()` and
/// `iso_sock_connect()` validate `addr_len >= sizeof(struct sockaddr_iso)`.
///
/// When using this struct for **unicast-only** operations without
/// [`sockaddr_iso_with_bc`], callers must ensure the buffer passed to
/// the kernel is at least 10 bytes (e.g., by embedding the struct in a
/// 10-byte `[u8; 10]` zeroed buffer or by using `std::mem::size_of`
/// with manual padding).  The [`sockaddr_iso_with_bc`] wrapper (49
/// bytes) inherently satisfies this requirement.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct sockaddr_iso {
    /// Socket address family — always `AF_BLUETOOTH` (31).
    pub iso_family: u16,

    /// Source or destination Bluetooth device address.
    pub iso_bdaddr: bdaddr_t,

    /// Address type of `iso_bdaddr` (e.g., public or random).
    pub iso_bdaddr_type: u8,
}

// ---------------------------------------------------------------------------
// Combined Unicast + Broadcast Socket Address
// ---------------------------------------------------------------------------

/// Combined ISO socket address with one broadcast element — the full
/// buffer layout the kernel expects when establishing a broadcast ISO
/// connection.
///
/// This struct concatenates [`sockaddr_iso`] (9 bytes, packed) and
/// [`sockaddr_iso_bc`] (40 bytes) to produce a 49-byte buffer where
/// the broadcast data sits at the exact offset of the C flexible array
/// member `iso_bc[0]`.
///
/// # Kernel Interaction
///
/// * **Unicast path:** `addr_len == sizeof(struct sockaddr_iso)` (10).
///   Use [`sockaddr_iso`] directly with appropriate padding.
/// * **Broadcast path:** `addr_len > sizeof(struct sockaddr_iso)` (10).
///   Pass this struct (49 bytes), which satisfies the broadcast check
///   and places `bc` at the correct offset for the kernel to read.
///
/// # Layout
///
/// ```text
/// Offset  Size  Field
///  0       9    base (sockaddr_iso, packed)
///  9      40    bc   (sockaddr_iso_bc)
/// ─────────────────────
/// Total:  49 bytes
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct sockaddr_iso_with_bc {
    /// The fixed unicast portion of the ISO socket address.
    pub base: sockaddr_iso,

    /// Broadcast address element occupying the position of `iso_bc[0]`
    /// in the kernel structure.
    pub bc: sockaddr_iso_bc,
}

// ---------------------------------------------------------------------------
// Compile-time layout assertions
// ---------------------------------------------------------------------------

// Verify struct sizes match expected kernel ABI layout.
const _: () = {
    assert!(core::mem::size_of::<sockaddr_iso_bc>() == 40);
    assert!(core::mem::size_of::<sockaddr_iso>() == 9);
    assert!(core::mem::size_of::<sockaddr_iso_with_bc>() == 49);
};
