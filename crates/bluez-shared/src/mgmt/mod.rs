// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux

//! Kernel Bluetooth Management (MGMT) protocol client.
//!
//! Provides async command/reply and event subscription over the
//! `HCI_CHANNEL_CONTROL` socket, replacing the C `struct mgmt` API
//! from `src/shared/mgmt.h`.
//!
//! # Architecture
//!
//! - [`MgmtSocket`] — Primary client handle wrapping an async
//!   `HCI_CHANNEL_CONTROL` socket with background read dispatch.
//! - [`MgmtResponse`] — Command completion response.
//! - [`MgmtEvent`] — Asynchronous event notification.
//! - [`MgmtTlvList`] — Type-Length-Value parameter list builder.
//! - [`MgmtIoCapability`] — I/O capability enum for pairing.
//! - [`MgmtError`] — Error type for MGMT operations.
//!
//! # Usage
//!
//! Downstream crates can access types via convenient re-exports:
//!
//! ```rust,ignore
//! use bluez_shared::mgmt::MgmtSocket;
//! ```
//!
//! Or via the fully qualified path:
//!
//! ```rust,ignore
//! use bluez_shared::mgmt::client::MgmtSocket;
//! ```

pub mod client;

// Re-export primary public types from the `client` sub-module for ergonomic
// access by downstream crates (bluetoothd, bluetoothctl, bluez-tools, etc.).
pub use client::MgmtError;
pub use client::MgmtEvent;
pub use client::MgmtIoCapability;
pub use client::MgmtResponse;
pub use client::MgmtSocket;
pub use client::MgmtTlvEntry;
pub use client::MgmtTlvList;
pub use client::mgmt_iocap_generator;
pub use client::mgmt_parse_io_capability;
