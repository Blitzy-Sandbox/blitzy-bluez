// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluez-emulator/src/lib.rs — BlueZ HCI emulator library
//
// Provides virtual Bluetooth controllers via VHCI for integration testing.
// This crate replaces the C emulator/ directory from the BlueZ source tree.

/// Virtual HCI controller — core emulation of BR/EDR + LE behavior.
pub mod btdev;

/// In-memory Bluetooth Host model: H:4 transport, HCI command/event processing,
/// L2CAP signaling (BR/EDR and LE), minimal RFCOMM, SCO, and ISO support.
pub mod bthost;

/// Simulated PHY layer for inter-emulator communication over UDP broadcast.
pub mod phy;
