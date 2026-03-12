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

/// LE-specific HCI controller emulator — opens /dev/vhci and emulates
/// a Bluetooth Low Energy controller with advertising, scanning,
/// accept list, resolving list, and all LE HCI commands.
pub mod le;

/// Virtual HCI (VHCI) bridge — creates kernel-visible `hciN` virtual
/// controllers via `/dev/vhci` and shuttles H:4 frames between the kernel
/// and a [`btdev::BtDev`] virtual controller through `AsyncFd`.
/// This is a **designated `unsafe` boundary module** for kernel device I/O.
pub mod vhci;
