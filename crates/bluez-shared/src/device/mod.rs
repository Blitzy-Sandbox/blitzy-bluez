// SPDX-License-Identifier: LGPL-2.1-or-later
//
//! Linux virtual input/HID device creation helpers.
//!
//! This module provides two sub-modules for creating virtual devices via the
//! Linux kernel's character device interfaces:
//!
//! - [`uhid`] — UHID (User-space HID) device creation via `/dev/uhid` (used by
//!   the HOGP profile for HID-over-GATT devices)
//! - [`uinput`] — Virtual input device creation via `/dev/uinput` (used by the
//!   AVRCP profile for media key passthrough)
//!
//! This is a **designated unsafe boundary module group** per AAP Section 0.7.4 —
//! raw character device I/O and ioctl calls in the child modules require
//! `unsafe` blocks. All `unsafe` blocks within child modules have `// SAFETY:`
//! documentation comments explaining the invariant being upheld.
//!
//! Replaces C source files: `src/shared/uhid.c/h`, `src/shared/uinput.c/h`.

pub mod uhid;
pub mod uinput;

// ---------------------------------------------------------------------------
// Re-exports — primary types for ergonomic access
// ---------------------------------------------------------------------------
//
// Allows callers to write `use bluez_shared::device::BtUhid` instead of
// `use bluez_shared::device::uhid::BtUhid`.

pub use uhid::BtUhid;
pub use uhid::UhidCallback;
pub use uhid::UhidDeviceType;
pub use uhid::UhidEvent;
pub use uhid::UhidEventType;
pub use uinput::BtUinput;
pub use uinput::BtUinputKeyMap;
pub use uinput::InputId;

// ---------------------------------------------------------------------------
// Shared Constants
// ---------------------------------------------------------------------------

/// Linux `BUS_BLUETOOTH` constant from `<linux/input.h>`.
///
/// Bluetooth bus type identifier used for virtual input device registration.
/// Both the [`uhid`] and [`uinput`] subsystems use this value to identify
/// Bluetooth input devices to the kernel input layer.
pub const BUS_BLUETOOTH: u16 = 0x05;
