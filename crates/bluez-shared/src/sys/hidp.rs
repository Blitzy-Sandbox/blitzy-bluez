// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// HIDP (Human Interface Device Protocol) kernel ABI definitions.
//
// Complete Rust re-declaration of `lib/bluetooth/hidp.h`.
// Contains MTU default constants, ioctl command numbers for connection
// management, flag and vendor-ID constants, and the four kernel ioctl
// structures: connection add, connection delete, connection info, and
// connection list requests.  These structures are passed directly to
// the kernel HIDP driver through `ioctl(2)` calls on a Bluetooth
// socket.
//
// # Safety
//
// `hidp_connadd_req` contains a `*mut u8` raw pointer (`rd_data`)
// pointing to a caller-owned report descriptor buffer.
// `hidp_connlist_req` contains a `*mut hidp_conninfo` raw pointer
// (`ci`) pointing to a caller-allocated array for the kernel to fill.
// Both pointers must remain valid for the entire duration of the
// corresponding ioctl call.  Callers are responsible for ensuring
// proper lifetime and alignment of the referenced buffers.

use super::bluetooth::bdaddr_t;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// HIDP MTU Constants
// ---------------------------------------------------------------------------

/// Minimum acceptable MTU for HIDP connections (48 bytes).
pub const HIDP_MINIMUM_MTU: u16 = 48;

/// Default MTU for HIDP connections (48 bytes).
pub const HIDP_DEFAULT_MTU: u16 = 48;

// ---------------------------------------------------------------------------
// Ioctl Number Encoding Helpers (private)
// ---------------------------------------------------------------------------
//
// Linux ioctl encoding (most architectures):
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

// ---------------------------------------------------------------------------
// HIDP Ioctl Command Definitions
// ---------------------------------------------------------------------------

/// Add a new HIDP connection.
///
/// Corresponds to `_IOW('H', 200, int)` in the kernel header.
/// Takes a [`hidp_connadd_req`] structure describing the new connection.
pub const HIDPCONNADD: u64 = _iow(b'H' as u64, 200, SIZEOF_INT);

/// Delete an existing HIDP connection.
///
/// Corresponds to `_IOW('H', 201, int)` in the kernel header.
/// Takes a [`hidp_conndel_req`] structure identifying the connection.
pub const HIDPCONNDEL: u64 = _iow(b'H' as u64, 201, SIZEOF_INT);

/// Retrieve the list of active HIDP connections.
///
/// Corresponds to `_IOR('H', 210, int)` in the kernel header.
/// Takes a [`hidp_connlist_req`] structure with a caller-allocated buffer.
pub const HIDPGETCONNLIST: u64 = _ior(b'H' as u64, 210, SIZEOF_INT);

/// Retrieve information about a specific HIDP connection.
///
/// Corresponds to `_IOR('H', 211, int)` in the kernel header.
/// Takes a [`hidp_conninfo`] structure filled by the kernel.
pub const HIDPGETCONNINFO: u64 = _ior(b'H' as u64, 211, SIZEOF_INT);

// ---------------------------------------------------------------------------
// HIDP Flag and Vendor Constants
// ---------------------------------------------------------------------------

/// HIDP virtual cable unplug flag (used in `hidp_conndel_req.flags`).
pub const HIDP_VIRTUAL_CABLE_UNPLUG: u32 = 0;

/// HIDP boot protocol mode flag (used in `hidp_connadd_req.flags`).
pub const HIDP_BOOT_PROTOCOL_MODE: u32 = 1;

/// Bluetooth SIG vendor ID for the Bluetooth specification itself.
pub const HIDP_BLUETOOTH_VENDOR_ID: u32 = 9;

// ---------------------------------------------------------------------------
// HIDP Connection Add Request
// ---------------------------------------------------------------------------

/// HIDP connection add request passed to the [`HIDPCONNADD`] ioctl.
///
/// Provides connected L2CAP control and interrupt channel socket file
/// descriptors, the HID report descriptor, and device identification
/// metadata to the kernel HIDP driver when establishing a new HID
/// connection.
///
/// # Safety
///
/// The `rd_data` field is a raw pointer to a caller-owned buffer
/// containing the HID report descriptor of `rd_size` bytes.  The
/// pointer must remain valid and the buffer must not be freed or
/// moved for the entire duration of the `HIDPCONNADD` ioctl call.
///
/// # Layout
///
/// Matches the C struct:
/// ```c
/// struct hidp_connadd_req {
///     int       ctrl_sock;
///     int       intr_sock;
///     uint16_t  parser;
///     uint16_t  rd_size;
///     uint8_t  *rd_data;
///     uint8_t   country;
///     uint8_t   subclass;
///     uint16_t  vendor;
///     uint16_t  product;
///     uint16_t  version;
///     uint32_t  flags;
///     uint32_t  idle_to;
///     char      name[128];
/// };
/// ```
///
/// Note: zerocopy derive macros are NOT applied to this struct because
/// it contains a raw pointer field (`rd_data`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct hidp_connadd_req {
    /// Connected L2CAP control channel socket file descriptor.
    pub ctrl_sock: i32,
    /// Connected L2CAP interrupt channel socket file descriptor.
    pub intr_sock: i32,
    /// HID parser version number.
    pub parser: u16,
    /// Size of the report descriptor pointed to by `rd_data`, in bytes.
    pub rd_size: u16,
    /// Pointer to the HID report descriptor data buffer.
    ///
    /// # Safety
    ///
    /// Must point to a valid, readable buffer of at least `rd_size` bytes
    /// that remains valid for the duration of the ioctl call.
    pub rd_data: *mut u8,
    /// HID country code.
    pub country: u8,
    /// HID subclass code.
    pub subclass: u8,
    /// USB Vendor ID of the HID device.
    pub vendor: u16,
    /// USB Product ID of the HID device.
    pub product: u16,
    /// USB device version number.
    pub version: u16,
    /// Connection flags (e.g., [`HIDP_BOOT_PROTOCOL_MODE`]).
    pub flags: u32,
    /// Idle timeout in milliseconds (0 = no timeout).
    pub idle_to: u32,
    /// Device name as a NUL-terminated UTF-8 byte array.
    pub name: [u8; 128],
}

// ---------------------------------------------------------------------------
// HIDP Connection Delete Request
// ---------------------------------------------------------------------------

/// HIDP connection delete request passed to the [`HIDPCONNDEL`] ioctl.
///
/// Identifies the HIDP connection to tear down by the remote device's
/// Bluetooth address and operational flags.
///
/// # Layout
///
/// Matches the C struct (with implicit 2-byte padding between `bdaddr`
/// and `flags` due to alignment):
/// ```c
/// struct hidp_conndel_req {
///     bdaddr_t bdaddr;
///     uint32_t flags;
/// };
/// ```
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct hidp_conndel_req {
    /// Bluetooth address of the remote HID device whose connection
    /// is to be deleted.
    pub bdaddr: bdaddr_t,
    /// Explicit padding to match the C ABI layout where the compiler
    /// inserts 2 bytes between the 6-byte `bdaddr_t` and the 4-byte
    /// aligned `flags` field.
    _pad: [u8; 2],
    /// Connection flags (e.g., [`HIDP_VIRTUAL_CABLE_UNPLUG`]).
    pub flags: u32,
}

impl hidp_conndel_req {
    /// Create a new connection delete request for the given device address
    /// and flags.
    pub const fn new(bdaddr: bdaddr_t, flags: u32) -> Self {
        Self { bdaddr, _pad: [0u8; 2], flags }
    }
}

// ---------------------------------------------------------------------------
// HIDP Connection Info
// ---------------------------------------------------------------------------

/// HIDP connection information returned by the [`HIDPGETCONNINFO`] ioctl.
///
/// Reports the current state of an active HIDP connection including the
/// remote device address, operational flags, connection state, device
/// identification metadata, and the device name string.
///
/// # Layout
///
/// Matches the C struct (with implicit 2-byte padding between `bdaddr`
/// and `flags` due to alignment):
/// ```c
/// struct hidp_conninfo {
///     bdaddr_t bdaddr;
///     uint32_t flags;
///     uint16_t state;
///     uint16_t vendor;
///     uint16_t product;
///     uint16_t version;
///     char     name[128];
/// };
/// ```
#[derive(Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct hidp_conninfo {
    /// Bluetooth address of the remote HID device.
    pub bdaddr: bdaddr_t,
    /// Explicit padding to match the C ABI layout where the compiler
    /// inserts 2 bytes between the 6-byte `bdaddr_t` and the 4-byte
    /// aligned `flags` field.
    _pad: [u8; 2],
    /// Connection flags.
    pub flags: u32,
    /// Current connection state.
    pub state: u16,
    /// USB Vendor ID of the HID device.
    pub vendor: u16,
    /// USB Product ID of the HID device.
    pub product: u16,
    /// USB device version number.
    pub version: u16,
    /// Device name as a NUL-terminated UTF-8 byte array.
    pub name: [u8; 128],
}

// Manual Debug implementation to provide a more readable name field
// representation (showing only the valid portion up to the first NUL byte).
impl core::fmt::Debug for hidp_conninfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Find the NUL terminator position for a cleaner debug display.
        let name_len = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        let name_str = core::str::from_utf8(&self.name[..name_len]).unwrap_or("<invalid UTF-8>");
        f.debug_struct("hidp_conninfo")
            .field("bdaddr", &self.bdaddr)
            .field("flags", &self.flags)
            .field("state", &self.state)
            .field("vendor", &self.vendor)
            .field("product", &self.product)
            .field("version", &self.version)
            .field("name", &name_str)
            .finish()
    }
}

impl hidp_conninfo {
    /// Create a zeroed connection info structure.
    pub const fn zeroed() -> Self {
        Self {
            bdaddr: bdaddr_t { b: [0u8; 6] },
            _pad: [0u8; 2],
            flags: 0,
            state: 0,
            vendor: 0,
            product: 0,
            version: 0,
            name: [0u8; 128],
        }
    }
}

// ---------------------------------------------------------------------------
// HIDP Connection List Request
// ---------------------------------------------------------------------------

/// HIDP connection list request passed to the [`HIDPGETCONNLIST`] ioctl.
///
/// Provides a caller-allocated buffer for the kernel to fill with
/// [`hidp_conninfo`] entries describing all active HIDP connections.
///
/// # Safety
///
/// The `ci` pointer must reference a valid, writable buffer of at least
/// `cnum` contiguous [`hidp_conninfo`] entries.  The caller is
/// responsible for ensuring the pointer remains valid for the entire
/// duration of the ioctl system call.  On return, the kernel overwrites
/// `cnum` with the actual number of entries written.
///
/// # Layout
///
/// Matches the C struct:
/// ```c
/// struct hidp_connlist_req {
///     uint32_t             cnum;
///     struct hidp_conninfo *ci;
/// };
/// ```
///
/// Note: zerocopy derive macros are NOT applied to this struct because
/// it contains a raw pointer field (`ci`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct hidp_connlist_req {
    /// Number of entries: on input the maximum capacity of the `ci` array,
    /// on output the number of entries actually written by the kernel.
    pub cnum: u32,
    /// Pointer to a caller-allocated array of [`hidp_conninfo`] entries.
    ///
    /// # Safety
    ///
    /// Must point to a valid, writable buffer of at least `cnum` contiguous
    /// [`hidp_conninfo`] entries for the duration of the ioctl call.
    pub ci: *mut hidp_conninfo,
}
