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

/// PTY-backed H:4 HCI transport — creates a pseudo-terminal, prints the
/// slave path for external tools, and forwards HCI command packets between
/// the PTY and a [`btdev::BtDev`] virtual controller. Supports
/// reconnect-on-hangup behavior for continuous emulation.
pub mod serial;

/// Socket server transport — exposes emulated HCI controllers to external
/// H:4 clients over UNIX-domain sockets or loopback TCP.  Each accepted
/// connection creates a [`btdev::BtDev`] virtual controller with an async
/// read loop and a non-blocking send handler.
pub mod server;

/// Security Manager Protocol (SMP) pairing emulation — implements the SMP
/// state machine for LE and BR/EDR fixed-channel pairing. Supports legacy
/// pairing (c1/s1 functions) and Secure Connections pairing (ECC keygen,
/// ECDH, f4/f5/f6 crypto). Replaces `emulator/smp.c`.
pub mod smp;

/// HCI emulator harness — coordinates a VHCI virtual controller, one or
/// more emulated client devices (`BtDev` + `BtHost` pairs connected via
/// socketpairs), and hook-based packet interception.  This is the primary
/// entry point used by ALL integration testers (`mgmt-tester`,
/// `l2cap-tester`, `iso-tester`, etc.).  Replaces `emulator/hciemu.c`.
pub mod hciemu;
