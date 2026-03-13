// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! Bluetooth socket abstraction layer.
//!
//! This module provides [`BluetoothSocket`] and [`BluetoothListener`] — async
//! Bluetooth socket types wrapping `nix::sys::socket` and
//! `tokio::io::unix::AsyncFd` for L2CAP, RFCOMM, SCO, and ISO transport
//! protocols.
//!
//! This replaces the GLib-based `btio/` library from the C BlueZ codebase.
//! The variadic option-driven C API is replaced with a type-safe builder
//! pattern, and GLib `GIOChannel` is replaced with tokio's `AsyncFd`.
//!
//! # Example
//!
//! ```rust,no_run
//! use bluez_shared::socket::{BluetoothSocket, SecLevel};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let socket = BluetoothSocket::builder()
//!     .psm(1)
//!     .sec_level(SecLevel::Medium)
//!     .connect()
//!     .await?;
//! # Ok(())
//! # }
//! ```

mod bluetooth_socket;

pub use bluetooth_socket::{
    BluetoothListener,
    BluetoothSocket,
    BtSocketError,
    BtTransport,
    L2capMode,
    Result,
    SecLevel,
    SocketBuilder,
    SocketOptions,
    SocketPriority,
    // Safe socket-option helpers (used by att/transport.rs, sdp/client.rs, etc.)
    bt_getsockname_l2,
    bt_sockopt_get_int,
    bt_sockopt_get_l2cap_options,
    bt_sockopt_get_security,
    bt_sockopt_set_int,
    bt_sockopt_set_priority,
    bt_sockopt_set_security,
    bt_writev,
};
