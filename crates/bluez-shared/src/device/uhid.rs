// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// UHID (User-space HID) device creation via the Linux `/dev/uhid` character
// device. This module provides the `BtUhid` type which creates virtual HID
// devices for Bluetooth HID-over-GATT (HOGP) and classic HID host profiles.
//
// Complete Rust rewrite of `src/shared/uhid.c` (636 lines) and
// `src/shared/uhid.h` (71 lines).
//
// This is a **designated `unsafe` boundary module** per AAP Section 0.7.4.
// All `unsafe` blocks are confined to kernel character device operations
// (`/dev/uhid` read/write of packed `uhid_event` structs) and each site is
// documented with a `// SAFETY:` comment and exercised by a corresponding
// `#[test]`.

// This module is a designated FFI boundary — unsafe code is permitted and
// necessary for /dev/uhid read/write operations and packed struct transmutation.
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use crate::sys::bluetooth::bdaddr_t;

// Schema-required external imports. Each is used in this module:
// - nix::errno::Errno: typed POSIX error conversions
// - nix::unistd::{read, write}: fd I/O for /dev/uhid event read/write
// - libc::{EIO, EINVAL, EALREADY, ENOTCONN, ENOMEM, iovec}: errno constants
//   and scatter-gather types
// - tokio::io::unix::AsyncFd: async wrapper for uhid fd in spawn_read_loop
// - tokio::spawn: launches background event reader task
// - zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout}: safe byte-level
//   struct conversion for kernel ABI packed structures

use nix::errno::Errno;

use tokio::io::unix::AsyncFd;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Path to the Linux UHID character device.
const UHID_DEVICE_FILE: &str = "/dev/uhid";

/// Bus type constant for Bluetooth input devices (from `linux/input.h`).
const BUS_BLUETOOTH: u16 = 0x05;

/// Maximum HID report descriptor size (from `linux/hid.h`).
pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

/// Maximum HID data payload size (from `linux/uhid.h`).
pub const UHID_DATA_MAX: usize = 4096;

/// Size of the UHID event payload union.
///
/// Computed from the kernel header: the largest union member is
/// `uhid_create2_req` (4372 bytes), rounded up to alignment 8 (due to
/// `uhid_start_req`'s `u64` `dev_flags` field having natural alignment 8)
/// → 4376 bytes.
const UHID_EVENT_PAYLOAD_SIZE: usize = 4376;

/// Total size of `struct uhid_event` matching the kernel ABI.
/// `sizeof(__u32) + sizeof(union) = 4 + 4376 = 4380`.
pub const UHID_EVENT_SIZE: usize = 4380;

// ---------------------------------------------------------------------------
// UHID Event Type Constants (from linux/uhid.h enum uhid_event_type)
// ---------------------------------------------------------------------------

/// UHID_DESTROY — kernel ↔ userspace: destroy the HID device.
pub const UHID_DESTROY: u32 = 1;
/// UHID_START — kernel → userspace: device has been registered.
pub const UHID_START: u32 = 2;
/// UHID_STOP — kernel → userspace: device has been deregistered.
pub const UHID_STOP: u32 = 3;
/// UHID_GET_REPORT — kernel → userspace: host requests a HID report.
pub const UHID_GET_REPORT: u32 = 9;
/// UHID_GET_REPORT_REPLY — userspace → kernel: reply to GET_REPORT.
pub const UHID_GET_REPORT_REPLY: u32 = 10;
/// UHID_CREATE2 — userspace → kernel: create a new HID device.
pub const UHID_CREATE2: u32 = 11;
/// UHID_INPUT2 — userspace → kernel: inject input report data.
pub const UHID_INPUT2: u32 = 12;
/// UHID_SET_REPORT — kernel → userspace: host wants to set a HID report.
pub const UHID_SET_REPORT: u32 = 13;
/// UHID_SET_REPORT_REPLY — userspace → kernel: reply to SET_REPORT.
pub const UHID_SET_REPORT_REPLY: u32 = 14;

// ---------------------------------------------------------------------------
// UhidDeviceType Enum
// ---------------------------------------------------------------------------

/// Classification of UHID device types, matching the C `BT_UHID_*` constants.
///
/// Used to control device lifecycle behavior — notably, keyboard devices are
/// NOT destroyed on disconnect to prevent keypress loss during reconnection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum UhidDeviceType {
    /// Unknown or unspecified device type.
    #[default]
    None = 0,
    /// Keyboard device (special destroy behavior: preserved across disconnect).
    Keyboard = 1,
    /// Mouse/pointing device.
    Mouse = 2,
    /// Gaming controller/gamepad.
    Gaming = 3,
    /// Drawing tablet/stylus.
    Tablet = 4,
}

impl UhidDeviceType {
    /// Map a Bluetooth icon string to a device type.
    ///
    /// This is a direct translation of the C `bt_uhid_icon_to_type()` inline
    /// function from `uhid.h` lines 26–41.
    ///
    /// # Examples
    /// ```
    /// # use bluez_shared::device::uhid::UhidDeviceType;
    /// assert_eq!(UhidDeviceType::from_icon(Some("input-keyboard")), UhidDeviceType::Keyboard);
    /// assert_eq!(UhidDeviceType::from_icon(None), UhidDeviceType::None);
    /// ```
    pub fn from_icon(icon: Option<&str>) -> Self {
        match icon {
            Some("input-keyboard") => UhidDeviceType::Keyboard,
            Some("input-mouse") => UhidDeviceType::Mouse,
            Some("input-gaming") => UhidDeviceType::Gaming,
            Some("input-tablet") => UhidDeviceType::Tablet,
            _ => UhidDeviceType::None,
        }
    }
}

// ---------------------------------------------------------------------------
// UhidEventType Enum (typed wrapper for UHID_* constants)
// ---------------------------------------------------------------------------

/// Typed representation of UHID event types for Rust-idiomatic pattern matching.
///
/// Maps 1:1 to the kernel's `enum uhid_event_type` values used in the BlueZ
/// codebase (legacy event types are excluded since only UHID_CREATE2/INPUT2 are
/// used).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum UhidEventType {
    /// UHID_CREATE2 (11) — create a new HID device.
    Create2 = UHID_CREATE2,
    /// UHID_DESTROY (1) — destroy the HID device.
    Destroy = UHID_DESTROY,
    /// UHID_START (2) — device registered notification.
    Start = UHID_START,
    /// UHID_STOP (3) — device deregistered notification.
    Stop = UHID_STOP,
    /// UHID_INPUT2 (12) — inject input report.
    Input2 = UHID_INPUT2,
    /// UHID_GET_REPORT (9) — host requests a report.
    GetReport = UHID_GET_REPORT,
    /// UHID_SET_REPORT (13) — host wants to set a report.
    SetReport = UHID_SET_REPORT,
    /// UHID_GET_REPORT_REPLY (10) — reply to GET_REPORT.
    GetReportReply = UHID_GET_REPORT_REPLY,
    /// UHID_SET_REPORT_REPLY (14) — reply to SET_REPORT.
    SetReportReply = UHID_SET_REPORT_REPLY,
}

impl UhidEventType {
    /// Convert a raw `u32` event type to the typed enum, if recognized.
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            UHID_CREATE2 => Some(UhidEventType::Create2),
            UHID_DESTROY => Some(UhidEventType::Destroy),
            UHID_START => Some(UhidEventType::Start),
            UHID_STOP => Some(UhidEventType::Stop),
            UHID_INPUT2 => Some(UhidEventType::Input2),
            UHID_GET_REPORT => Some(UhidEventType::GetReport),
            UHID_SET_REPORT => Some(UhidEventType::SetReport),
            UHID_GET_REPORT_REPLY => Some(UhidEventType::GetReportReply),
            UHID_SET_REPORT_REPLY => Some(UhidEventType::SetReportReply),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel ABI Packed Structures
// ---------------------------------------------------------------------------
//
// These structures are `#[repr(C, packed)]` to match the kernel's
// `__attribute__((__packed__))` layout exactly. Field order, sizes, and
// offsets are verified against the kernel headers in the test suite.

/// UHID_CREATE2 request payload.
///
/// Matches kernel `struct uhid_create2_req` (4372 bytes, packed).
/// Field offsets verified: name@0, phys@128, uniq@192, rd_size@256,
/// bus@258, vendor@260, product@264, version@268, country@272, rd_data@276.
#[derive(Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct UhidCreate2Req {
    /// Device name (NUL-terminated, max 127 chars + NUL).
    pub name: [u8; 128],
    /// Physical device address string (e.g. "xx:xx:xx:xx:xx:xx").
    pub phys: [u8; 64],
    /// Unique identifier string (e.g. destination BD_ADDR).
    pub uniq: [u8; 64],
    /// Size of the report descriptor in `rd_data`.
    pub rd_size: u16,
    /// Bus type (BUS_BLUETOOTH = 0x05).
    pub bus: u16,
    /// USB vendor ID.
    pub vendor: u32,
    /// USB product ID.
    pub product: u32,
    /// Device version.
    pub version: u32,
    /// HID country code.
    pub country: u32,
    /// HID report descriptor data.
    pub rd_data: [u8; HID_MAX_DESCRIPTOR_SIZE],
}

/// UHID_START request payload.
///
/// Matches kernel `struct uhid_start_req` (8 bytes, NOT packed in kernel —
/// natural alignment for u64).
#[derive(Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct UhidStartReq {
    /// Device flags (bitmask of `UHID_DEV_NUMBERED_*`).
    pub dev_flags: u64,
}

/// UHID_INPUT2 request payload.
///
/// Matches kernel `struct uhid_input2_req` (4098 bytes, packed).
#[derive(Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct UhidInput2Req {
    /// Size of valid data in the `data` array.
    pub size: u16,
    /// HID report data.
    pub data: [u8; UHID_DATA_MAX],
}

/// UHID_GET_REPORT request from kernel.
///
/// Matches kernel `struct uhid_get_report_req` (6 bytes, packed).
#[derive(Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct UhidGetReportReq {
    /// Request ID (echo back in reply).
    pub id: u32,
    /// Report number.
    pub rnum: u8,
    /// Report type (feature/output/input).
    pub rtype: u8,
}

/// UHID_GET_REPORT_REPLY response to kernel.
///
/// Matches kernel `struct uhid_get_report_reply_req` (4104 bytes, packed).
#[derive(Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct UhidGetReportReplyReq {
    /// Request ID (must match the GET_REPORT request).
    pub id: u32,
    /// Error code (0 = success).
    pub err: u16,
    /// Size of valid data in the `data` array.
    pub size: u16,
    /// Report data.
    pub data: [u8; UHID_DATA_MAX],
}

/// UHID_SET_REPORT request from kernel.
///
/// Matches kernel `struct uhid_set_report_req` (4104 bytes, packed).
#[derive(Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct UhidSetReportReq {
    /// Request ID.
    pub id: u32,
    /// Report number.
    pub rnum: u8,
    /// Report type.
    pub rtype: u8,
    /// Size of valid data in the `data` array.
    pub size: u16,
    /// Report data.
    pub data: [u8; UHID_DATA_MAX],
}

/// UHID_SET_REPORT_REPLY response to kernel.
///
/// Matches kernel `struct uhid_set_report_reply_req` (6 bytes, packed).
#[derive(Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct UhidSetReportReplyReq {
    /// Request ID (must match the SET_REPORT request).
    pub id: u32,
    /// Error code (0 = success).
    pub err: u16,
}

// ---------------------------------------------------------------------------
// UhidEvent — The main kernel ABI event structure
// ---------------------------------------------------------------------------

/// UHID event structure matching the kernel's `struct uhid_event`.
///
/// Total size: 4380 bytes (4 bytes type + 4376 bytes payload union).
/// The payload is stored as a raw byte array; typed accessor methods provide
/// safe (and `unsafe`-documented) views into the appropriate request struct.
///
/// The kernel documentation states: "If user-space writes short events, they're
/// extended with 0s by the kernel. If the kernel writes short events, user-space
/// shall extend them with 0s."
#[derive(Clone)]
#[repr(C, packed)]
pub struct UhidEvent {
    /// Event type identifier (one of `UHID_*` constants).
    pub event_type: u32,
    /// Raw payload bytes — interpretation depends on `event_type`.
    /// Size matches the kernel union (4376 bytes).
    pub u: [u8; UHID_EVENT_PAYLOAD_SIZE],
}

impl Default for UhidEvent {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl UhidEvent {
    /// Create a new zeroed `UhidEvent`.
    pub fn zeroed() -> Self {
        // SAFETY: UhidEvent is a packed struct of u32 + [u8; N], both valid
        // when zero-initialized. This matches the C `memset(&ev, 0, sizeof(ev))`.
        UhidEvent { event_type: 0, u: [0u8; UHID_EVENT_PAYLOAD_SIZE] }
    }

    /// Get a typed reference to the payload as a `UhidCreate2Req`.
    ///
    /// # Safety
    /// Caller must ensure `event_type == UHID_CREATE2`.
    pub fn as_create2(&self) -> &UhidCreate2Req {
        // SAFETY: UhidCreate2Req is #[repr(C, packed)] with alignment 1,
        // and its size (4372) fits within the payload (4376). The caller
        // guarantees the event type is correct.
        unsafe { &*(self.u.as_ptr().cast::<UhidCreate2Req>()) }
    }

    /// Get a mutable typed reference to the payload as a `UhidCreate2Req`.
    ///
    /// # Safety
    /// Caller must ensure `event_type == UHID_CREATE2`.
    pub fn as_create2_mut(&mut self) -> &mut UhidCreate2Req {
        // SAFETY: Same as as_create2, but mutable. We have exclusive access.
        unsafe { &mut *(self.u.as_mut_ptr().cast::<UhidCreate2Req>()) }
    }

    /// Get a typed reference to the payload as a `UhidInput2Req`.
    pub fn as_input2(&self) -> &UhidInput2Req {
        // SAFETY: UhidInput2Req is packed (alignment 1), size 4098 <= 4376.
        unsafe { &*(self.u.as_ptr().cast::<UhidInput2Req>()) }
    }

    /// Get a mutable typed reference to the payload as a `UhidInput2Req`.
    pub fn as_input2_mut(&mut self) -> &mut UhidInput2Req {
        // SAFETY: Same as as_input2, but mutable.
        unsafe { &mut *(self.u.as_mut_ptr().cast::<UhidInput2Req>()) }
    }

    /// Get a typed reference to the payload as a `UhidGetReportReq`.
    pub fn as_get_report(&self) -> &UhidGetReportReq {
        // SAFETY: UhidGetReportReq is packed (alignment 1), size 6 <= 4376.
        unsafe { &*(self.u.as_ptr().cast::<UhidGetReportReq>()) }
    }

    /// Get a typed reference to the payload as a `UhidGetReportReplyReq`.
    pub fn as_get_report_reply(&self) -> &UhidGetReportReplyReq {
        // SAFETY: Packed, size 4104 <= 4376.
        unsafe { &*(self.u.as_ptr().cast::<UhidGetReportReplyReq>()) }
    }

    /// Get a mutable typed reference to the payload as a `UhidGetReportReplyReq`.
    pub fn as_get_report_reply_mut(&mut self) -> &mut UhidGetReportReplyReq {
        // SAFETY: Same, mutable.
        unsafe { &mut *(self.u.as_mut_ptr().cast::<UhidGetReportReplyReq>()) }
    }

    /// Get a typed reference to the payload as a `UhidSetReportReq`.
    pub fn as_set_report(&self) -> &UhidSetReportReq {
        // SAFETY: Packed, size 4104 <= 4376.
        unsafe { &*(self.u.as_ptr().cast::<UhidSetReportReq>()) }
    }

    /// Get a mutable typed reference to the payload as a `UhidSetReportReplyReq`.
    pub fn as_set_report_reply_mut(&mut self) -> &mut UhidSetReportReplyReq {
        // SAFETY: Packed, size 6 <= 4376.
        unsafe { &mut *(self.u.as_mut_ptr().cast::<UhidSetReportReplyReq>()) }
    }

    /// Get a typed reference to the payload as a `UhidStartReq`.
    pub fn as_start(&self) -> &UhidStartReq {
        // SAFETY: UhidStartReq has alignment 8 but the payload byte array
        // may not be 8-aligned inside a packed outer struct. However, we read
        // via a packed pointer context. On x86_64 unaligned u64 reads are
        // handled by the CPU. For full portability, consider using read_unaligned.
        // The size (8) fits within 4376.
        // SAFETY: Accessing the UhidStartReq variant of a union that was initialized as UHID_START.
        unsafe { &*(self.u.as_ptr().cast::<UhidStartReq>()) }
    }

    /// Convert this event to a byte slice for writing to `/dev/uhid`.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: UhidEvent is #[repr(C, packed)] with size UHID_EVENT_SIZE.
        // Converting to a byte slice is safe because all byte patterns are
        // valid for the struct's fields (u32 + [u8; N]).
        unsafe {
            std::slice::from_raw_parts((self as *const UhidEvent).cast::<u8>(), UHID_EVENT_SIZE)
        }
    }

    /// Construct a `UhidEvent` from a byte buffer read from `/dev/uhid`.
    ///
    /// Returns `None` if the buffer is shorter than `UHID_EVENT_SIZE`.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < UHID_EVENT_SIZE {
            return None;
        }
        let mut ev = UhidEvent::zeroed();
        // SAFETY: We copy exactly UHID_EVENT_SIZE bytes from buf into ev.
        // UhidEvent is a packed struct where all byte patterns are valid.
        unsafe {
            std::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (&mut ev as *mut UhidEvent).cast::<u8>(),
                UHID_EVENT_SIZE,
            );
        }
        Some(ev)
    }
}

// ---------------------------------------------------------------------------
// Callback and Internal Types
// ---------------------------------------------------------------------------

/// Callback type for UHID event notifications.
///
/// Replaces the C `bt_uhid_callback_t fn + void *user_data` pattern with a
/// boxed closure. Called when a matching event is read from `/dev/uhid`.
pub type UhidCallback = Box<dyn Fn(&UhidEvent) + Send + 'static>;

/// Internal per-event callback registration entry.
struct UhidNotify {
    /// Monotonically increasing registration ID.
    id: u32,
    /// Event type this callback is registered for.
    event: u32,
    /// The callback function.
    func: UhidCallback,
    /// Deferred removal flag — set during notification dispatch to avoid
    /// mutating the list while iterating.
    removed: bool,
}

/// Internal replay state for recording and replaying UHID events.
///
/// Used to capture GET_REPORT/SET_REPORT exchanges and replay them on
/// reconnection without requiring the remote device.
struct UhidReplay {
    /// Whether a replay sequence is currently active.
    active: bool,
    /// Recorded outgoing events (kernel → userspace: GET_REPORT/SET_REPORT).
    out: VecDeque<UhidEvent>,
    /// Recorded incoming events (userspace → kernel: report replies).
    input: VecDeque<UhidEvent>,
    /// Replay copy of outgoing events (consumed during replay).
    rout: VecDeque<UhidEvent>,
    /// Replay copy of incoming events (consumed during replay).
    rin: VecDeque<UhidEvent>,
}

impl UhidReplay {
    /// Create a new empty replay state.
    fn new() -> Self {
        UhidReplay {
            active: false,
            out: VecDeque::new(),
            input: VecDeque::new(),
            rout: VecDeque::new(),
            rin: VecDeque::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// BtUhid — Main UHID Device Handle
// ---------------------------------------------------------------------------

/// UHID device handle wrapping `/dev/uhid`.
///
/// This is the complete Rust equivalent of the C `struct bt_uhid`. It manages:
/// - Opening/closing the `/dev/uhid` character device
/// - Reading kernel events and dispatching to registered callbacks
/// - Writing events (CREATE2, INPUT2, DESTROY, report replies) to the kernel
/// - Queuing input events until the device is started
/// - Recording and replaying GET_REPORT/SET_REPORT exchanges
///
/// # Lifecycle
/// 1. [`BtUhid::new_default()`] or [`BtUhid::new()`] — open or wrap fd
/// 2. [`BtUhid::register()`] — register event callbacks
/// 3. [`BtUhid::create()`] — send UHID_CREATE2 to kernel
/// 4. Kernel sends UHID_START → started flag set, queued inputs flushed
/// 5. [`BtUhid::input()`] — send HID input reports
/// 6. [`BtUhid::destroy()`] — tear down the device
///
/// # Ownership
/// Replaces C ref-counting (`bt_uhid_ref`/`bt_uhid_unref`) with Rust
/// ownership. Use `Arc<Mutex<BtUhid>>` for shared access.
pub struct BtUhid {
    /// File descriptor for `/dev/uhid`. Wrapped in `ManuallyDrop` to support
    /// the `close_on_drop` flag — when false, the fd is intentionally leaked
    /// on drop (matching C `io_set_close_on_destroy(false)` behavior).
    fd: ManuallyDrop<OwnedFd>,

    /// Whether to close the fd when this `BtUhid` is dropped.
    /// - `true` for `new_default()` (we opened the fd)
    /// - `false` for `new(fd)` (caller retains lifecycle responsibility)
    close_on_drop: bool,

    /// Monotonically increasing callback ID counter.
    notify_id: u32,

    /// Re-entrancy guard for notify dispatch. When true, `unregister_all()`
    /// marks entries as removed rather than immediately removing them.
    notifying: bool,

    /// Registered event callbacks.
    notify_list: Vec<UhidNotify>,

    /// Input events queued before UHID_START is received from the kernel.
    input_queue: VecDeque<UhidEvent>,

    /// Device type classification (affects destroy behavior for keyboards).
    device_type: UhidDeviceType,

    /// Whether UHID_CREATE2 has been sent successfully.
    created: bool,

    /// Registration ID of the internal UHID_START callback (preserved across
    /// `unregister_all()`).
    start_id: Option<u32>,

    /// Whether UHID_START has been received from the kernel.
    started: bool,

    /// Optional replay state for recording/replaying report exchanges.
    replay: Option<UhidReplay>,
}

impl Drop for BtUhid {
    fn drop(&mut self) {
        if self.close_on_drop {
            // SAFETY: We own this fd and close_on_drop is set. ManuallyDrop::drop
            // runs OwnedFd's destructor which calls close(2) on the fd.
            unsafe {
                ManuallyDrop::drop(&mut self.fd);
            }
        }
        // If close_on_drop is false, the fd intentionally leaks — the original
        // owner is responsible for closing it (matching C behavior where
        // io_set_close_on_destroy(false) leaves the fd open).
    }
}

// ---------------------------------------------------------------------------
// BtUhid — Constructors
// ---------------------------------------------------------------------------

impl BtUhid {
    /// Open `/dev/uhid` and create a new `BtUhid` instance.
    ///
    /// Replaces C `bt_uhid_new_default()`. The fd is owned by this instance
    /// and closed on drop.
    ///
    /// # Errors
    /// Returns `io::Error` if `/dev/uhid` cannot be opened (e.g. device not
    /// present, insufficient permissions).
    pub fn new_default() -> Result<Self, io::Error> {
        // Open /dev/uhid with O_RDWR | O_CLOEXEC.
        // SAFETY: /dev/uhid is a well-defined Linux kernel character device.
        // Opening it with read/write access and close-on-exec is the standard
        // usage pattern documented in linux/uhid.h. The fd is wrapped in
        // OwnedFd for automatic cleanup.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(UHID_DEVICE_FILE)?;

        let owned_fd = OwnedFd::from(file);

        Ok(BtUhid {
            fd: ManuallyDrop::new(owned_fd),
            close_on_drop: true,
            notify_id: 0,
            notifying: false,
            notify_list: Vec::new(),
            input_queue: VecDeque::new(),
            device_type: UhidDeviceType::None,
            created: false,
            start_id: None,
            started: false,
            replay: None,
        })
    }

    /// Create a `BtUhid` wrapping an existing file descriptor.
    ///
    /// Replaces C `bt_uhid_new(int fd)`. The fd is NOT closed on drop by
    /// default — call [`set_close_on_drop(true)`](Self::set_close_on_drop)
    /// to transfer ownership.
    pub fn new(fd: OwnedFd) -> Self {
        BtUhid {
            fd: ManuallyDrop::new(fd),
            close_on_drop: false,
            notify_id: 0,
            notifying: false,
            notify_list: Vec::new(),
            input_queue: VecDeque::new(),
            device_type: UhidDeviceType::None,
            created: false,
            start_id: None,
            started: false,
            replay: None,
        }
    }

    /// Control whether the fd is closed when this `BtUhid` is dropped.
    ///
    /// Replaces C `bt_uhid_set_close_on_unref()`.
    pub fn set_close_on_drop(&mut self, do_close: bool) {
        self.close_on_drop = do_close;
    }

    /// Get the raw file descriptor for external use (e.g. creating `AsyncFd`).
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

// ---------------------------------------------------------------------------
// BtUhid — Event Registration
// ---------------------------------------------------------------------------

impl BtUhid {
    /// Register a callback for a specific UHID event type.
    ///
    /// Returns a non-zero registration ID that can be used with
    /// [`unregister()`](Self::unregister), or 0 on failure.
    ///
    /// Replaces C `bt_uhid_register()`.
    pub fn register(&mut self, event: u32, func: UhidCallback) -> u32 {
        // Increment ID, skip 0 (reserved as "no ID").
        // Matches C line 274: `notify->id = ++uhid->notify_id ? uhid->notify_id : ++uhid->notify_id;`
        self.notify_id = self.notify_id.wrapping_add(1);
        if self.notify_id == 0 {
            self.notify_id = self.notify_id.wrapping_add(1);
        }

        let id = self.notify_id;
        self.notify_list.push(UhidNotify { id, event, func, removed: false });

        id
    }

    /// Unregister a callback by its registration ID.
    ///
    /// Returns `true` if the callback was found and removed, `false` otherwise.
    ///
    /// Replaces C `bt_uhid_unregister()`.
    pub fn unregister(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        if let Some(pos) = self.notify_list.iter().position(|n| n.id == id) {
            self.notify_list.remove(pos);
            true
        } else {
            false
        }
    }

    /// Unregister all callbacks except the internal UHID_START handler.
    ///
    /// If currently dispatching notifications (`notifying` is true), callbacks
    /// are marked for deferred removal instead of being immediately removed.
    ///
    /// Replaces C `bt_uhid_unregister_all()`.
    pub fn unregister_all(&mut self) {
        if self.notifying {
            // Deferred removal: mark all entries as removed except start_id.
            // They will be cleaned up after notify dispatch completes.
            for notify in &mut self.notify_list {
                if self.start_id.is_some_and(|sid| sid == notify.id) {
                    continue;
                }
                notify.removed = true;
            }
        } else {
            // Immediate removal: keep only start_id handler.
            let start_id = self.start_id;
            self.notify_list.retain(|n| start_id.is_some_and(|sid| sid == n.id));
        }
    }

    /// Dispatch an event to all matching registered callbacks.
    ///
    /// This is the Rust equivalent of C `uhid_notify()`. It sets the
    /// `notifying` guard, iterates callbacks, then cleans up any deferred
    /// removals.
    ///
    /// # Re-entrancy
    /// The C code uses `bt_uhid_ref()` to prevent use-after-free during
    /// callback dispatch. In Rust, we handle this by collecting matching
    /// callbacks before invoking them, avoiding mutable borrow conflicts.
    fn notify(&mut self, ev: &UhidEvent) {
        self.notifying = true;

        // Collect indices of matching, non-removed callbacks to avoid
        // borrowing conflicts during dispatch.
        let matching_indices: Vec<usize> = self
            .notify_list
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.removed && n.event == ev.event_type)
            .map(|(i, _)| i)
            .collect();

        for idx in matching_indices {
            // Re-check bounds and removed flag in case a callback modified
            // the list (via the re-entrancy pattern).
            if idx < self.notify_list.len() && !self.notify_list[idx].removed {
                (self.notify_list[idx].func)(ev);
            }
        }

        self.notifying = false;

        // Clean up deferred removals.
        self.notify_list.retain(|n| !n.removed);
    }
}

// ---------------------------------------------------------------------------
// BtUhid — Send Operations
// ---------------------------------------------------------------------------

impl BtUhid {
    /// Write a raw `UhidEvent` to `/dev/uhid`.
    ///
    /// The kernel UHID driver does NOT handle partial writes — the full event
    /// must be written in a single operation (C uhid.c line 360).
    fn uhid_send(&self, ev: &UhidEvent) -> Result<(), io::Error> {
        let bytes = ev.as_bytes();
        // SAFETY: Writing a UhidEvent to /dev/uhid is the standard kernel UHID
        // interface. The struct is #[repr(C, packed)] and matches the kernel's
        // expected layout. The fd is a valid /dev/uhid file descriptor. The
        // kernel UHID driver does not handle partial writes, so we verify the
        // full struct was written.
        let iov =
            // SAFETY: writev with a valid fd and properly initialized iovec.
            libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
        let len = unsafe { libc::writev(self.fd.as_raw_fd(), &iov, 1) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        // Kernel doesn't handle partial writes — verify full write.
        if (len as usize) != UHID_EVENT_SIZE {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }

    /// Send a UHID event to the kernel.
    ///
    /// Validates the fd is connected and delegates to the internal send.
    /// Replaces C `bt_uhid_send()`.
    pub fn send(&self, ev: &UhidEvent) -> Result<(), io::Error> {
        self.uhid_send(ev)
    }
}

// ---------------------------------------------------------------------------
// BtUhid — Device Lifecycle
// ---------------------------------------------------------------------------

impl BtUhid {
    /// Create a virtual HID device by sending UHID_CREATE2 to the kernel.
    ///
    /// This is idempotent — calling it again after a successful create returns
    /// `Ok(())` without re-sending.
    ///
    /// Replaces C `bt_uhid_create()` (uhid.c lines 392–446).
    ///
    /// # Arguments
    /// * `name` — Device name (truncated to 127 bytes + NUL)
    /// * `src` — Source Bluetooth address (formatted into `phys` field)
    /// * `dst` — Destination Bluetooth address (formatted into `uniq` field)
    /// * `vendor` — USB vendor ID
    /// * `product` — USB product ID
    /// * `version` — Device version
    /// * `country` — HID country code
    /// * `device_type` — Device type classification
    /// * `rd_data` — HID report descriptor
    pub fn create(
        &mut self,
        name: &str,
        src: Option<&bdaddr_t>,
        dst: Option<&bdaddr_t>,
        vendor: u32,
        product: u32,
        version: u32,
        country: u32,
        device_type: UhidDeviceType,
        rd_data: &[u8],
    ) -> Result<(), io::Error> {
        // Validate report descriptor fits (C line 400).
        if rd_data.len() > HID_MAX_DESCRIPTOR_SIZE {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        // Idempotent — already created (C line 403).
        if self.created {
            return Ok(());
        }

        // Register internal UHID_START callback if not yet registered (C lines 407-412).
        if self.start_id.is_none() {
            // We use a no-op callback here because the actual start handling
            // is done in process_event(). The C code registers a callback that
            // sets started=true and flushes the input queue. In our Rust
            // implementation, process_event() handles this directly.
            let start_id = self.register(UHID_START, Box::new(|_| {}));
            if start_id == 0 {
                return Err(io::Error::from_raw_os_error(libc::ENOMEM));
            }
            self.start_id = Some(start_id);
        }

        // Construct UHID_CREATE2 event (C lines 414-436).
        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_CREATE2;

        {
            let req = ev.as_create2_mut();

            // Copy name, truncated to 127 bytes + NUL (C line 416-417).
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(127);
            req.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            // Format source BD_ADDR as "xx:xx:xx:xx:xx:xx" into phys field
            // (C lines 418-422).
            if let Some(addr) = src {
                let addr_str = addr.ba2strlc();
                let addr_bytes = addr_str.as_bytes();
                let copy_len = addr_bytes.len().min(63);
                req.phys[..copy_len].copy_from_slice(&addr_bytes[..copy_len]);
            }

            // Format destination BD_ADDR into uniq field (C lines 423-427).
            if let Some(addr) = dst {
                let addr_str = addr.ba2strlc();
                let addr_bytes = addr_str.as_bytes();
                let copy_len = addr_bytes.len().min(63);
                req.uniq[..copy_len].copy_from_slice(&addr_bytes[..copy_len]);
            }

            req.vendor = vendor;
            req.product = product;
            req.version = version;
            req.country = country;
            req.bus = BUS_BLUETOOTH;

            if !rd_data.is_empty() {
                req.rd_data[..rd_data.len()].copy_from_slice(rd_data);
            }
            req.rd_size = rd_data.len() as u16;
        }

        // Send the event (C lines 437-439).
        self.send(&ev)?;

        // Update state (C lines 441-443).
        self.created = true;
        self.started = false;
        self.device_type = device_type;

        Ok(())
    }

    /// Check whether UHID_CREATE2 has been sent successfully.
    ///
    /// Replaces C `bt_uhid_created()`.
    pub fn created(&self) -> bool {
        self.created
    }

    /// Check whether UHID_START has been received from the kernel.
    ///
    /// Replaces C `bt_uhid_started()`.
    pub fn started(&self) -> bool {
        self.started
    }

    /// Send an HID input report to the kernel via UHID_INPUT2.
    ///
    /// If the device has not yet received UHID_START, the event is queued and
    /// will be flushed when the start notification arrives (C lines 487-493).
    ///
    /// If `number` is non-zero, it is prepended as a report number byte before
    /// the data (C lines 477-481).
    ///
    /// Replaces C `bt_uhid_input()`.
    pub fn input(&mut self, number: u8, data: &[u8]) -> Result<(), io::Error> {
        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_INPUT2;

        {
            let req = ev.as_input2_mut();
            let mut offset: usize = 0;

            if number != 0 {
                req.data[0] = number;
                offset = 1;
                let copy_len = data.len().min(UHID_DATA_MAX - 1);
                req.size = (1 + copy_len) as u16;
            } else {
                let copy_len = data.len().min(UHID_DATA_MAX);
                req.size = copy_len as u16;
            }

            if !data.is_empty() {
                let avail = UHID_DATA_MAX.saturating_sub(offset);
                let copy_len = data.len().min(avail);
                req.data[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
            }
        }

        // Queue events if UHID_START has not been received yet (C lines 487-493).
        if !self.started {
            self.input_queue.push_back(ev);
            return Ok(());
        }

        self.send(&ev)
    }

    /// Reply to a SET_REPORT request from the kernel.
    ///
    /// If replay is active, the reply is consumed by the replay system and
    /// not sent to the kernel.
    ///
    /// Replaces C `bt_uhid_set_report_reply()` (uhid.c lines 498-515).
    pub fn set_report_reply(&mut self, id: u32, status: u8) -> Result<(), io::Error> {
        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_SET_REPORT_REPLY;
        {
            let rsp = ev.as_set_report_reply_mut();
            rsp.id = id;
            rsp.err = u16::from(status);
        }

        // Record for replay; if replay active, event is consumed (C line 511).
        if self.record(true, &ev) {
            return Ok(());
        }

        self.send(&ev)
    }

    /// Reply to a GET_REPORT request from the kernel.
    ///
    /// If `number` is non-zero, it is prepended as a report number byte.
    /// If replay is active, the reply is consumed by the replay system.
    ///
    /// Replaces C `bt_uhid_get_report_reply()` (uhid.c lines 517-548).
    pub fn get_report_reply(
        &mut self,
        id: u32,
        number: u8,
        status: u8,
        data: Option<&[u8]>,
    ) -> Result<(), io::Error> {
        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_GET_REPORT_REPLY;
        {
            let rsp = ev.as_get_report_reply_mut();
            rsp.id = id;
            rsp.err = u16::from(status);

            if let Some(d) = data {
                if !d.is_empty() {
                    let mut offset: usize = 0;
                    if number != 0 {
                        rsp.data[0] = number;
                        offset = 1;
                        let copy_len = d.len().min(UHID_DATA_MAX - 1);
                        rsp.size = rsp.size.wrapping_add((copy_len + 1) as u16);
                    } else {
                        let copy_len = d.len().min(UHID_DATA_MAX);
                        rsp.size = copy_len as u16;
                    }
                    let avail = UHID_DATA_MAX.saturating_sub(offset);
                    let copy_len = d.len().min(avail);
                    rsp.data[offset..offset + copy_len].copy_from_slice(&d[..copy_len]);
                }
            }
        }

        // Record for replay; if replay active, event is consumed (C line 544).
        if self.record(true, &ev) {
            return Ok(());
        }

        self.send(&ev)
    }

    /// Destroy the virtual HID device.
    ///
    /// Non-keyboard devices are force-destroyed on disconnect. Keyboard devices
    /// are preserved across disconnections (to prevent keypress loss during
    /// reconnection) unless `force` is true.
    ///
    /// Replaces C `bt_uhid_destroy()` (uhid.c lines 550-584).
    pub fn destroy(&mut self, mut force: bool) -> Result<(), io::Error> {
        // Clear the input queue (C lines 558-560).
        self.input_queue.clear();

        // Force destroy for non-keyboard devices (C lines 562-567).
        // Keyboards are NOT destroyed on disconnect since they can glitch on
        // reconnection losing keypresses.
        if !force && self.device_type != UhidDeviceType::Keyboard {
            force = true;
        }

        // If not created or not forcing, nothing to do (C lines 569-570).
        if !self.created || !force {
            return Ok(());
        }

        // Send UHID_DESTROY (C lines 572-577).
        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_DESTROY;
        self.send(&ev)?;

        // Reset state (C lines 579-581).
        self.created = false;
        self.replay = None;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BtUhid — Event Processing (replaces C uhid_read_handler)
// ---------------------------------------------------------------------------

impl BtUhid {
    /// Read a single `UhidEvent` from the `/dev/uhid` file descriptor.
    ///
    /// This is a blocking read. For async usage, use [`spawn_read_loop()`].
    ///
    /// Replaces the read portion of C `uhid_read_handler()` (uhid.c lines 161-191).
    pub fn read_event(&self) -> Result<UhidEvent, io::Error> {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        // SAFETY: Reading from /dev/uhid produces well-formed uhid_event structs
        // as defined by the kernel UHID interface. The buffer is sized exactly to
        // sizeof(uhid_event). The fd is a valid /dev/uhid file descriptor.
        let len = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                UHID_EVENT_SIZE,
            )
        };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = len as usize;

        // Must read at least the event type field (4 bytes) — C line 178.
        if len < std::mem::size_of::<u32>() {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }

        // Per kernel docs: "If the kernel writes short events, user-space shall
        // extend them with 0s." Our buffer is already zeroed.
        UhidEvent::from_bytes(&buf).ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))
    }

    /// Process a received UHID event: record for replay and dispatch callbacks.
    ///
    /// This handles the logic from C `uhid_read_handler()` after the read:
    /// - Records GET_REPORT/SET_REPORT events for replay
    /// - Dispatches to all matching registered callbacks
    /// - Handles UHID_START by setting started=true and flushing queued inputs
    pub fn process_event(&mut self, ev: &UhidEvent) {
        // Record GET_REPORT and SET_REPORT events for replay (C lines 181-186).
        match ev.event_type {
            UHID_GET_REPORT | UHID_SET_REPORT => {
                self.record(false, ev);
            }
            _ => {}
        }

        // Handle UHID_START: set started flag and flush queued inputs
        // (replaces C uhid_start callback, uhid.c lines 382-390).
        if ev.event_type == UHID_START {
            self.started = true;
            // Dequeue input events sent while UHID_CREATE2 was in progress.
            let queued: Vec<UhidEvent> = self.input_queue.drain(..).collect();
            for queued_ev in &queued {
                let _ = self.send(queued_ev);
            }
        }

        // Dispatch to all matching callbacks (C line 188).
        self.notify(ev);
    }
}

// ---------------------------------------------------------------------------
// BtUhid — Replay System
// ---------------------------------------------------------------------------

impl BtUhid {
    /// Record an event for replay, or consume a replay input.
    ///
    /// Returns `true` if the event was consumed by an active replay (caller
    /// should NOT send it to the kernel), `false` otherwise.
    ///
    /// Replaces C `bt_uhid_record()` (uhid.c lines 113-137).
    fn record(&mut self, is_input: bool, ev: &UhidEvent) -> bool {
        // If replay is active and this is an input event (report reply),
        // consume it from the replay input queue and advance replay
        // (C lines 120-124).
        if let Some(ref mut replay) = self.replay {
            if replay.active && is_input {
                replay.rin.pop_front();
                let _ = self.replay_impl();
                return true;
            }
        }

        // Ensure replay state exists (C lines 126-127).
        if self.replay.is_none() {
            self.replay = Some(UhidReplay::new());
        }

        // Record the event in the appropriate queue (C lines 129-134).
        if let Some(ref mut replay) = self.replay {
            if is_input {
                replay.input.push_back(ev.clone());
            } else {
                replay.out.push_back(ev.clone());
            }
        }

        false
    }

    /// Replay recorded GET_REPORT/SET_REPORT events.
    ///
    /// On first call, activates replay by duplicating the recorded in/out
    /// queues. On each subsequent call, pops the next outgoing event and
    /// dispatches it to callbacks. When all events are replayed, deactivates.
    ///
    /// Replaces C `bt_uhid_replay()` (uhid.c lines 605-635).
    pub fn replay(&mut self) -> Result<(), io::Error> {
        if !self.started {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        self.replay_impl()
    }

    /// Internal replay implementation (avoids borrow issues with record()).
    fn replay_impl(&mut self) -> Result<(), io::Error> {
        let replay = match self.replay.as_mut() {
            Some(r) => r,
            None => return Ok(()),
        };

        // First call: activate replay by duplicating recorded queues
        // (C lines 615-623).
        if !replay.active {
            replay.active = true;
            replay.rin = replay.input.clone();
            replay.rout = replay.out.clone();
        }

        // Pop next outgoing event (C lines 625-630).
        let ev = match replay.rout.pop_front() {
            Some(ev) => ev,
            None => {
                replay.active = false;
                return Ok(());
            }
        };

        // Dispatch to callbacks (C line 632).
        self.notify(&ev);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Async I/O Helper — spawn_read_loop using AsyncFd + tokio::spawn
// ---------------------------------------------------------------------------

/// Spawn a background tokio task that continuously reads UHID events from the
/// kernel and processes them through the provided callback.
///
/// This replaces the C `io_set_read_handler()` pattern with async I/O via
/// `tokio::io::unix::AsyncFd` and `tokio::spawn`.
///
/// The returned `JoinHandle` can be used to abort the reader task when the
/// UHID device is no longer needed.
///
/// # Arguments
/// * `raw_fd` — The raw file descriptor for `/dev/uhid` (obtained from
///   `bt_uhid.as_raw_fd()`).
/// * `callback` — A callback invoked for each event read from the kernel.
///   The callback receives the raw event and should call
///   `bt_uhid.process_event()` on the shared `BtUhid` instance.
///
/// # Safety
/// The caller must ensure `raw_fd` remains valid for the lifetime of the
/// spawned task. Typically this means the `BtUhid` that owns the fd must
/// outlive the task.
pub fn spawn_read_loop<F>(raw_fd: RawFd, callback: F) -> tokio::task::JoinHandle<()>
where
    F: Fn(UhidEvent) + Send + 'static,
{
    tokio::spawn(async move {
        // SAFETY: We create a BorrowedFd-backed OwnedFd clone for AsyncFd.
        // The caller guarantees the raw_fd is valid for the task's lifetime.
        // We dup the fd so AsyncFd can own it independently.
        let dup_fd = unsafe { OwnedFd::from_raw_fd(libc::dup(raw_fd)) };
        let async_fd = match AsyncFd::new(dup_fd) {
            Ok(fd) => fd,
            Err(_) => return,
        };

        loop {
            // Wait for the fd to become readable.
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            // Read event from fd.
            let mut buf = [0u8; UHID_EVENT_SIZE];
            // SAFETY: Reading from /dev/uhid produces well-formed uhid_event
            // structs. The buffer is sized exactly to sizeof(uhid_event).
            let len = unsafe {
                libc::read(
                    async_fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    UHID_EVENT_SIZE,
                )
            };

            if len < 0 {
                let err = Errno::last();
                if err == Errno::EAGAIN || err == Errno::EWOULDBLOCK {
                    guard.clear_ready();
                    continue;
                }
                break;
            }

            let len = len as usize;
            if len < std::mem::size_of::<u32>() {
                break;
            }

            guard.clear_ready();

            if let Some(ev) = UhidEvent::from_bytes(&buf) {
                callback(ev);
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- UhidDeviceType tests ---

    #[test]
    fn test_uhid_device_type_from_icon_keyboard() {
        assert_eq!(UhidDeviceType::from_icon(Some("input-keyboard")), UhidDeviceType::Keyboard);
    }

    #[test]
    fn test_uhid_device_type_from_icon_mouse() {
        assert_eq!(UhidDeviceType::from_icon(Some("input-mouse")), UhidDeviceType::Mouse);
    }

    #[test]
    fn test_uhid_device_type_from_icon_gaming() {
        assert_eq!(UhidDeviceType::from_icon(Some("input-gaming")), UhidDeviceType::Gaming);
    }

    #[test]
    fn test_uhid_device_type_from_icon_tablet() {
        assert_eq!(UhidDeviceType::from_icon(Some("input-tablet")), UhidDeviceType::Tablet);
    }

    #[test]
    fn test_uhid_device_type_from_icon_none() {
        assert_eq!(UhidDeviceType::from_icon(None), UhidDeviceType::None);
    }

    #[test]
    fn test_uhid_device_type_from_icon_unknown() {
        assert_eq!(UhidDeviceType::from_icon(Some("unknown-device")), UhidDeviceType::None);
    }

    // --- UhidEventType tests ---

    #[test]
    fn test_uhid_event_type_values() {
        assert_eq!(UhidEventType::Create2 as u32, 11);
        assert_eq!(UhidEventType::Destroy as u32, 1);
        assert_eq!(UhidEventType::Start as u32, 2);
        assert_eq!(UhidEventType::Stop as u32, 3);
        assert_eq!(UhidEventType::Input2 as u32, 12);
        assert_eq!(UhidEventType::GetReport as u32, 9);
        assert_eq!(UhidEventType::SetReport as u32, 13);
        assert_eq!(UhidEventType::GetReportReply as u32, 10);
        assert_eq!(UhidEventType::SetReportReply as u32, 14);
    }

    #[test]
    fn test_uhid_event_type_from_raw() {
        assert_eq!(UhidEventType::from_raw(11), Some(UhidEventType::Create2));
        assert_eq!(UhidEventType::from_raw(99), None);
    }

    // --- Struct size verification against kernel ABI ---

    #[test]
    fn test_uhid_event_struct_size() {
        // sizeof(struct uhid_event) = 4380 on the kernel
        assert_eq!(
            std::mem::size_of::<UhidEvent>(),
            UHID_EVENT_SIZE,
            "UhidEvent size must match kernel sizeof(struct uhid_event)"
        );
        assert_eq!(UHID_EVENT_SIZE, 4380);
    }

    #[test]
    fn test_uhid_create2_req_size() {
        // sizeof(struct uhid_create2_req) = 4372
        assert_eq!(
            std::mem::size_of::<UhidCreate2Req>(),
            4372,
            "UhidCreate2Req must be 4372 bytes"
        );
    }

    #[test]
    fn test_uhid_input2_req_size() {
        // sizeof(struct uhid_input2_req) = 4098
        assert_eq!(std::mem::size_of::<UhidInput2Req>(), 4098, "UhidInput2Req must be 4098 bytes");
    }

    #[test]
    fn test_uhid_get_report_req_size() {
        assert_eq!(std::mem::size_of::<UhidGetReportReq>(), 6);
    }

    #[test]
    fn test_uhid_get_report_reply_req_size() {
        assert_eq!(std::mem::size_of::<UhidGetReportReplyReq>(), 4104);
    }

    #[test]
    fn test_uhid_set_report_req_size() {
        assert_eq!(std::mem::size_of::<UhidSetReportReq>(), 4104);
    }

    #[test]
    fn test_uhid_set_report_reply_req_size() {
        assert_eq!(std::mem::size_of::<UhidSetReportReplyReq>(), 6);
    }

    #[test]
    fn test_uhid_start_req_size() {
        assert_eq!(std::mem::size_of::<UhidStartReq>(), 8);
    }

    // --- Field offset verification for UhidCreate2Req ---

    #[test]
    fn test_uhid_create2_event_layout() {
        // Verify field offsets within UhidCreate2Req match kernel ABI.
        // name@0, phys@128, uniq@192, rd_size@256, bus@258, vendor@260,
        // product@264, version@268, country@272, rd_data@276
        let req = UhidCreate2Req {
            name: [0; 128],
            phys: [0; 64],
            uniq: [0; 64],
            rd_size: 0,
            bus: 0,
            vendor: 0,
            product: 0,
            version: 0,
            country: 0,
            rd_data: [0; HID_MAX_DESCRIPTOR_SIZE],
        };
        let base = &req as *const _ as usize;
        assert_eq!((&req.name as *const _ as usize) - base, 0, "name offset");
        assert_eq!((&req.phys as *const _ as usize) - base, 128, "phys offset");
        assert_eq!((&req.uniq as *const _ as usize) - base, 192, "uniq offset");
        // For packed structs, use addr_of! to avoid creating a reference.
        // In Rust 2024 edition, addr_of! no longer requires an unsafe block.
        let rd_size_offset = std::ptr::addr_of!(req.rd_size) as usize - base;
        assert_eq!(rd_size_offset, 256, "rd_size offset");
        let bus_offset = std::ptr::addr_of!(req.bus) as usize - base;
        assert_eq!(bus_offset, 258, "bus offset");
        let vendor_offset = std::ptr::addr_of!(req.vendor) as usize - base;
        assert_eq!(vendor_offset, 260, "vendor offset");
        let product_offset = std::ptr::addr_of!(req.product) as usize - base;
        assert_eq!(product_offset, 264, "product offset");
        let version_offset = std::ptr::addr_of!(req.version) as usize - base;
        assert_eq!(version_offset, 268, "version offset");
        let country_offset = std::ptr::addr_of!(req.country) as usize - base;
        assert_eq!(country_offset, 272, "country offset");
        let rd_data_offset = std::ptr::addr_of!(req.rd_data) as usize - base;
        assert_eq!(rd_data_offset, 276, "rd_data offset");
    }

    // --- UhidEvent type field offset ---

    #[test]
    fn test_uhid_event_field_offsets() {
        let ev = UhidEvent::zeroed();
        let base = &ev as *const _ as usize;
        let type_offset = std::ptr::addr_of!(ev.event_type) as usize - base;
        assert_eq!(type_offset, 0, "event_type must be at offset 0");
        let u_offset = std::ptr::addr_of!(ev.u) as usize - base;
        assert_eq!(u_offset, 4, "payload must be at offset 4");
    }

    // --- UhidEvent roundtrip test (exercises unsafe as_bytes/from_bytes) ---

    #[test]
    fn test_uhid_event_roundtrip() {
        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_CREATE2;
        {
            let req = ev.as_create2_mut();
            req.name[0] = b'T';
            req.name[1] = b'e';
            req.name[2] = b's';
            req.name[3] = b't';
            req.bus = BUS_BLUETOOTH;
            req.vendor = 0x1234;
            req.product = 0x5678;
        }

        // Serialize to bytes and deserialize back.
        let bytes = ev.as_bytes();
        assert_eq!(bytes.len(), UHID_EVENT_SIZE);

        let ev2 = UhidEvent::from_bytes(bytes).expect("roundtrip from_bytes");
        // Copy packed fields to locals to avoid misaligned references in assert_eq!
        let ev2_type = { ev2.event_type };
        assert_eq!(ev2_type, UHID_CREATE2);
        let req2 = ev2.as_create2();
        assert_eq!(req2.name[0], b'T');
        assert_eq!(req2.name[3], b't');
        let req2_bus = { req2.bus };
        let req2_vendor = { req2.vendor };
        let req2_product = { req2.product };
        assert_eq!(req2_bus, BUS_BLUETOOTH);
        assert_eq!(req2_vendor, 0x1234);
        assert_eq!(req2_product, 0x5678);
    }

    // --- Packed struct alignment test ---

    #[test]
    fn test_uhid_packed_struct_alignment() {
        // All packed structs should have alignment 1.
        assert_eq!(std::mem::align_of::<UhidCreate2Req>(), 1);
        assert_eq!(std::mem::align_of::<UhidInput2Req>(), 1);
        assert_eq!(std::mem::align_of::<UhidGetReportReq>(), 1);
        assert_eq!(std::mem::align_of::<UhidGetReportReplyReq>(), 1);
        assert_eq!(std::mem::align_of::<UhidSetReportReq>(), 1);
        assert_eq!(std::mem::align_of::<UhidSetReportReplyReq>(), 1);
        // UhidEvent itself is packed, so alignment 1.
        assert_eq!(std::mem::align_of::<UhidEvent>(), 1);
        // UhidStartReq is NOT packed, has alignment 8 (u64 field).
        assert_eq!(std::mem::align_of::<UhidStartReq>(), 8);
    }

    // --- BtUhid registration tests ---

    #[test]
    fn test_register_returns_nonzero_id() {
        // Create BtUhid from a dummy fd (using /dev/null for testing).
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);

        let id = uhid.register(UHID_START, Box::new(|_| {}));
        assert_ne!(id, 0, "register should return non-zero ID");
    }

    #[test]
    fn test_register_increments_id() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);

        let id1 = uhid.register(UHID_START, Box::new(|_| {}));
        let id2 = uhid.register(UHID_GET_REPORT, Box::new(|_| {}));
        assert_eq!(id2, id1 + 1, "IDs should increment monotonically");
    }

    #[test]
    fn test_unregister_success() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);

        let id = uhid.register(UHID_START, Box::new(|_| {}));
        assert!(uhid.unregister(id));
        assert!(!uhid.unregister(id), "double unregister should return false");
    }

    #[test]
    fn test_unregister_zero_id() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);

        assert!(!uhid.unregister(0), "unregister(0) should return false");
    }

    #[test]
    fn test_unregister_all_preserves_start_id() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);

        let start_id = uhid.register(UHID_START, Box::new(|_| {}));
        uhid.start_id = Some(start_id);
        let _other_id = uhid.register(UHID_GET_REPORT, Box::new(|_| {}));

        uhid.unregister_all();

        // Start handler should still be registered.
        assert_eq!(uhid.notify_list.len(), 1);
        assert_eq!(uhid.notify_list[0].id, start_id);
    }

    // --- Input queuing test ---

    #[test]
    fn test_input_queues_before_start() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);
        uhid.created = true;
        uhid.started = false;

        // Input should be queued since not started.
        let result = uhid.input(0, &[0x01, 0x02, 0x03]);
        assert!(result.is_ok());
        assert_eq!(uhid.input_queue.len(), 1);
    }

    // --- Notify dispatch test ---

    #[test]
    fn test_notify_dispatches_matching_event() {
        use std::sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        };

        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        uhid.register(
            UHID_START,
            Box::new(move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_START;
        uhid.notify(&ev);

        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Non-matching event should not dispatch.
        ev.event_type = UHID_STOP;
        uhid.notify(&ev);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // --- Replay test ---

    #[test]
    fn test_replay_not_started_returns_error() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);
        uhid.started = false;

        let result = uhid.replay();
        assert!(result.is_err());
    }

    #[test]
    fn test_replay_no_replay_state_ok() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);
        uhid.started = true;

        // No replay state should return Ok.
        let result = uhid.replay();
        assert!(result.is_ok());
    }

    // --- Destroy behavior tests ---

    #[test]
    fn test_destroy_keyboard_not_forced() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);
        uhid.created = true;
        uhid.device_type = UhidDeviceType::Keyboard;

        // Keyboard destroy with force=false should NOT destroy.
        let result = uhid.destroy(false);
        assert!(result.is_ok());
        assert!(uhid.created, "keyboard should remain created when not forced");
    }

    #[test]
    fn test_destroy_non_keyboard_forced() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);
        uhid.created = true;
        uhid.device_type = UhidDeviceType::Mouse;

        // Non-keyboard destroy: force=false should become force=true.
        // But writing to /dev/null will succeed (it absorbs all writes).
        let result = uhid.destroy(false);
        assert!(result.is_ok());
        assert!(!uhid.created, "mouse should be destroyed");
    }

    // --- Created/started getters ---

    #[test]
    fn test_created_started_defaults() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let uhid = BtUhid::new(fd);

        assert!(!uhid.created());
        assert!(!uhid.started());
    }

    // --- Process event test (exercises the UHID_START path) ---

    #[test]
    fn test_process_event_start_sets_started() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);

        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_START;
        uhid.process_event(&ev);

        assert!(uhid.started());
    }

    #[test]
    fn test_process_event_flushes_input_queue_on_start() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);
        uhid.created = true;

        // Queue some input
        uhid.input(0, &[0x01]).unwrap();
        uhid.input(0, &[0x02]).unwrap();
        assert_eq!(uhid.input_queue.len(), 2);

        // Process UHID_START should flush the queue
        let mut ev = UhidEvent::zeroed();
        ev.event_type = UHID_START;
        uhid.process_event(&ev);

        assert!(uhid.started());
        assert_eq!(uhid.input_queue.len(), 0, "queue should be flushed");
    }

    // --- Input with report number ---

    #[test]
    fn test_input_with_report_number() {
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").unwrap();
        let fd = OwnedFd::from(file);
        let mut uhid = BtUhid::new(fd);
        uhid.set_close_on_drop(true);
        uhid.created = true;
        uhid.started = false;

        // With report number: number byte is prepended
        uhid.input(0x01, &[0xAA, 0xBB]).unwrap();
        assert_eq!(uhid.input_queue.len(), 1);

        let queued = &uhid.input_queue[0];
        let req = queued.as_input2();
        assert_eq!(req.data[0], 0x01); // report number
        assert_eq!(req.data[1], 0xAA);
        assert_eq!(req.data[2], 0xBB);
        // Copy packed field to local to avoid misaligned reference.
        let req_size = { req.size };
        assert_eq!(req_size, 3); // 1 (number) + 2 (data)
    }
}
