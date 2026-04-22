// SPDX-License-Identifier: LGPL-2.1-or-later

//! BlueZ HCI Emulator Library
//!
//! Provides virtual Bluetooth controllers via VHCI for integration testing.
//! This crate is a Rust rewrite of the BlueZ emulator subsystem
//! (`emulator/btdev.c`, `emulator/bthost.c`, `emulator/hciemu.c`,
//! `emulator/vhci.c`, `emulator/le.c`, `emulator/smp.c`, `emulator/phy.c`,
//! `emulator/server.c`, `emulator/serial.c`).
//!
//! # Architecture
//!
//! - [`BtDev`] — Virtual HCI controller with table-driven command dispatch
//! - [`BtHost`] — In-memory Bluetooth host for protocol testing
//! - [`HciEmulator`] — Test harness wiring VHCI + BtDev + BtHost
//! - [`Vhci`] — `/dev/vhci` kernel bridge
//! - [`BtLe`] — LE-specific controller emulation
//! - [`BtPhy`] — UDP broadcast simulated PHY layer
//! - [`Server`] — UNIX/TCP server transport for external H:4 clients
//! - [`Serial`] — PTY-backed H:4 transport
//! - [`Smp`] — SMP pairing state machine
//!
//! # Usage
//!
//! The primary entry point for integration testing is [`HciEmulator`], which
//! coordinates a VHCI virtual controller with one or more emulated client
//! devices ([`BtDev`] + [`BtHost`] pairs connected via socketpairs).
//!
//! ```text
//! ┌────────────┐          ┌───────────────────────┐
//! │ kernel HCI │◄──VHCI──►│ HciEmulator (central) │
//! └────────────┘          │  ├─ Vhci               │
//!                         │  ├─ post_command_hooks  │
//!                         │  └─ clients[]           │
//!                         │      ├─ EmulatorClient  │
//!                         │      │   ├─ BtDev       │
//!                         │      │   ├─ BtHost      │
//!                         │      │   └─ socketpair  │
//!                         │      └─ …               │
//!                         └───────────────────────┘
//! ```
//!
//! For lower-level testing, individual components such as [`BtDev`],
//! [`BtHost`], [`Vhci`], [`BtLe`], [`BtPhy`], [`Server`], and [`Serial`]
//! can be used directly.

#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Module declarations
// ---------------------------------------------------------------------------

/// Virtual HCI controller — core emulation of BR/EDR + LE behavior.
///
/// Provides [`BtDev`], [`BtDevType`], [`BtDevHookType`], and
/// [`BtDevCallback`] for table-driven command dispatch and connection
/// management.
pub mod btdev;

/// In-memory Bluetooth Host model: H:4 transport, HCI command/event
/// processing, L2CAP signaling (BR/EDR and LE), minimal RFCOMM, SCO,
/// and ISO support.
///
/// Provides [`BtHost`] for command credit tracking, L2CAP/SMP/RFCOMM
/// protocol processing, and emulated host-side behavior.
pub mod bthost;

/// HCI emulator harness — coordinates a VHCI virtual controller, one or
/// more emulated client devices ([`BtDev`] + [`BtHost`] pairs connected
/// via socketpairs), and hook-based packet interception.
///
/// Provides [`HciEmulator`], [`EmulatorType`], and [`HookType`] — the
/// primary entry point used by all integration testers (`mgmt-tester`,
/// `l2cap-tester`, `iso-tester`, etc.).
pub mod hciemu;

/// Virtual HCI (VHCI) bridge — creates kernel-visible `hciN` virtual
/// controllers via `/dev/vhci` and shuttles H:4 frames between the kernel
/// and a [`BtDev`] virtual controller through `AsyncFd`.
///
/// This is a **designated `unsafe` boundary module** for kernel device I/O.
pub mod vhci;

/// LE-specific HCI controller emulator — opens `/dev/vhci` and emulates
/// a Bluetooth Low Energy controller with advertising, scanning,
/// accept list, resolving list, and all LE HCI commands.
pub mod le;

/// Security Manager Protocol (SMP) pairing emulation — implements the SMP
/// state machine for LE and BR/EDR fixed-channel pairing. Supports legacy
/// pairing (c1/s1 functions) and Secure Connections pairing (ECC keygen,
/// ECDH, f4/f5/f6 crypto).
///
/// Provides [`Smp`] and [`SmpConn`] for pairing state management.
/// This module is `pub` for test access even though it is primarily
/// consumed internally by [`BtHost`].
pub mod smp;

/// Simulated PHY layer for inter-emulator communication over UDP broadcast.
///
/// Provides [`BtPhy`], packed PHY packet structs ([`BtPhyPktAdv`],
/// [`BtPhyPktConn`]), and PHY packet type constants ([`BT_PHY_PKT_NULL`],
/// [`BT_PHY_PKT_ADV`], [`BT_PHY_PKT_CONN`]).
pub mod phy;

/// UNIX/TCP server transport — exposes emulated HCI controllers to external
/// H:4 clients over UNIX-domain sockets or loopback TCP.
///
/// Provides [`Server`] and [`ServerType`].
pub mod server;

/// PTY-backed H:4 transport — creates a pseudo-terminal, prints the
/// slave path for external tools, and forwards HCI command packets between
/// the PTY and a [`BtDev`] virtual controller.
///
/// Provides [`Serial`] and [`SerialType`].
pub mod serial;

// ---------------------------------------------------------------------------
// Public re-exports — flat crate-level access to all primary types
// ---------------------------------------------------------------------------

// From btdev: virtual HCI controller types
pub use btdev::{BtDev, BtDevCallback, BtDevHookType, BtDevType};

// From bthost: in-memory Bluetooth host
pub use bthost::BtHost;

// From hciemu: emulator harness types
pub use hciemu::{EmulatorType, HciEmulator, HookType};

// From vhci: VHCI kernel bridge
pub use vhci::Vhci;

// From le: LE-specific controller emulator
pub use le::BtLe;

// From smp: SMP pairing state machine
pub use smp::{Smp, SmpConn};

// From phy: simulated PHY layer types and constants
pub use phy::{BT_PHY_PKT_ADV, BT_PHY_PKT_CONN, BT_PHY_PKT_NULL, BtPhy, BtPhyPktAdv, BtPhyPktConn};

// From server: server transport types
pub use server::{Server, ServerType};

// From serial: PTY transport types
pub use serial::{Serial, SerialType};
