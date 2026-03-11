// SPDX-License-Identifier: LGPL-2.1-or-later
//
//! Linux virtual input/HID device creation helpers.
//!
//! This module provides two sub-modules for creating virtual devices via the
//! Linux kernel's character device interfaces:
//!
//! - [`uinput`] — Virtual input device creation via `/dev/uinput` (used by the
//!   AVRCP profile for media key passthrough)
//! - `uhid` — UHID (User-space HID) device creation via `/dev/uhid` (used by
//!   the HOGP profile for HID-over-GATT)
//!
//! These are **designated unsafe boundary modules** per the architecture spec —
//! raw character device I/O and ioctl calls require `unsafe` blocks, and each
//! site is documented with a `// SAFETY:` comment.
//!
//! Replaces C source files: `src/shared/uhid.c/h`, `src/shared/uinput.c/h`.

pub mod uhid;
pub mod uinput;

// Re-export primary types for ergonomic access.
pub use uhid::BtUhid;
pub use uhid::UhidCallback;
pub use uhid::UhidDeviceType;
pub use uhid::UhidEvent;
pub use uhid::UhidEventType;
pub use uinput::BUS_BLUETOOTH;
pub use uinput::BtUinput;
pub use uinput::BtUinputKeyMap;
pub use uinput::InputId;
