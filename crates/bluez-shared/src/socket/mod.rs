// SPDX-License-Identifier: GPL-2.0-or-later
//! Bluetooth socket abstraction layer.
//!
//! Provides async Bluetooth socket types wrapping Linux kernel AF_BLUETOOTH
//! sockets via `tokio::io::unix::AsyncFd`. This replaces the BtIO socket
//! library from `btio/btio.c`.

pub mod bluetooth_socket;

pub use bluetooth_socket::{
    BluetoothListener, BluetoothSocket, BtSocketError, BtTransport, L2capMode, Result, SecLevel,
    SocketBuilder, SocketOptions, SocketPriority,
};
