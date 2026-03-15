// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Library target for the `bluetoothd` crate.  Exposes the daemon's internal
// modules so workspace-level integration tests (`tests/unit/test_sdp.rs`,
// etc.) can exercise SDP server, record database, and D-Bus error mapping
// logic without requiring a running daemon instance.
//
// The binary target (`main.rs`) retains its own module declarations — Cargo
// compiles both targets independently.

pub mod adapter;
pub mod config;
pub mod dbus_common;
pub mod error;
pub mod gatt;
pub mod legacy_gatt;
pub mod log;
pub mod plugin;
pub mod plugins;
pub mod profiles;
pub mod sdp;
pub mod storage;
