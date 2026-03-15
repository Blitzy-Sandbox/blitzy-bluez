// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Legacy ATT/GATT client stack
//
// Copyright 2024 BlueZ Project
//
// This module provides the legacy ATT/GATT client stack for the `bluetoothd`
// daemon, replacing the C `attrib/` directory (`att.c`/`att.h`,
// `gatt.c`/`gatt.h`, `gattrib.c`/`gattrib.h`).
//
// The three submodules are:
//
// - **`att`** — ATT PDU encode/decode helpers: opcode constants, error code
//   constants, the `AttDataList` container used by discovery procedures, the
//   `AttRange` handle-range type, and encoder/decoder functions for every ATT
//   operation defined in the Core Specification.
//
// - **`gatt`** — Client-side GATT procedures: primary service discovery,
//   included service discovery, characteristic and descriptor discovery,
//   read/write operations (single, long, prepared, reliable, signed), MTU
//   exchange, and SDP record parsing for GATT.
//
// - **`gattrib`** — The `GAttrib` transport abstraction that bridges the
//   legacy GATT procedure API with the modern `BtAtt` engine from
//   `bluez_shared::att::transport`, providing request tracking, cancellation,
//   PDU buffering, notification routing, and GATT client attachment.
//
// # Scope
//
// The standalone `gatttool` CLI utility is **not** included in this module —
// it is out of scope for the rewrite.
//
// # Relationship to the Modern GATT Subsystem
//
// This is the *legacy* ATT/GATT stack, distinct from the modern GATT
// subsystem provided by `bluez_shared::gatt` and exposed through the
// `crate::gatt` module. It exists for backward-compatible interactions with
// bluetoothd profile plugins that still use the `GAttrib` transport path.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// ATT PDU encode/decode helpers — opcode constants, error codes, data
/// structures (`AttDataList`, `AttRange`), and encoder/decoder functions for
/// all ATT PDU types.
pub mod att;

/// Client-side GATT procedures — service/characteristic/descriptor discovery,
/// read/write operations, MTU exchange, and SDP record parsing.
pub mod gatt;

/// GAttrib transport abstraction — bridges the legacy GATT procedure API with
/// the modern `BtAtt` engine, providing request tracking, cancellation, PDU
/// buffering, notification routing, and GATT client attachment.
pub mod gattrib;

// ---------------------------------------------------------------------------
// Convenience re-exports
// ---------------------------------------------------------------------------

// Re-export key ATT types for ergonomic access from other bluetoothd modules.
pub use att::{AttDataList, AttRange};

// Re-export key GATT result types used by profile plugins.
pub use gatt::{GattChar, GattDesc, GattIncluded, GattPrimary};

// Re-export the GAttrib transport abstraction.
pub use gattrib::GAttrib;
