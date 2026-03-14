// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Profile protocol modules for the BlueZ shared library.
//
// This module declares and re-exports the four Bluetooth profile protocol
// sub-modules that live under `bluez_shared::profiles`.  Each sub-module is
// the idiomatic Rust replacement for the corresponding `src/shared/*.c`
// compilation unit in the C codebase:
//
//   - `gap`     — GAP management capability probe  (`src/shared/gap.c`)
//   - `hfp`     — HFP AT command engine             (`src/shared/hfp.c`)
//   - `battery` — Battery charge fluctuation smoother (`src/shared/battery.c`)
//   - `rap`     — RAP / RAS ranging profile skeleton (`src/shared/rap.c`)
//
// Primary public types are re-exported at this level so that downstream
// crates (primarily `bluetoothd`) can import them with a single `use`
// path, e.g. `use bluez_shared::profiles::BtGap`.

// ---------------------------------------------------------------------------
// Module declarations
// ---------------------------------------------------------------------------

/// GAP (Generic Access Profile) management capability probe.
///
/// Communicates with the Linux kernel Bluetooth Management subsystem to query
/// the MGMT protocol version, enumerate supported commands, manage static
/// addresses, and load Identity Resolving Keys (IRKs).
pub mod gap;

/// HFP (Hands-Free Profile) AT command engine.
///
/// Implements both the Audio Gateway (AG) side ([`HfpGw`]) and the
/// Hands-Free (HF) side ([`HfpHf`]) of the HFP protocol, including AT
/// command parsing/generation, SLC establishment, indicator negotiation,
/// and call management.
pub mod hfp;

/// Battery charge fluctuation smoother.
///
/// Tracks recent battery charge readings and smooths out oscillations by
/// returning a windowed average when rapid fluctuations (frequent direction
/// reversals) are detected.
pub mod battery;

/// RAP (Ranging Profile) / RAS (Ranging Service) skeleton.
///
/// Implements an experimental Bluetooth Ranging Profile with server-side
/// GATT service registration (6 characteristics) and client-side service
/// discovery/attachment.
pub mod rap;

// ---------------------------------------------------------------------------
// Re-exports — GAP profile
// ---------------------------------------------------------------------------

pub use gap::BtGap;
pub use gap::GapError;
pub use gap::IrkEntry;
pub use gap::{BT_GAP_ADDR_TYPE_BREDR, BT_GAP_ADDR_TYPE_LE_PUBLIC, BT_GAP_ADDR_TYPE_LE_RANDOM};

// ---------------------------------------------------------------------------
// Re-exports — HFP profile
// ---------------------------------------------------------------------------

// Core structs: gateway (AG side), hands-free (HF side), AT parser context
pub use hfp::{HfpContext, HfpGw, HfpHf};

// Bitflag types: feature negotiation and call-hold operations
pub use hfp::{AgFeatures, ChldFlags, HfFeatures};

// Enumerations: result codes, error codes, command types
pub use hfp::{HfpError, HfpGwCmdType, HfpResult};

// Enumerations: CIND indicators and call state
pub use hfp::{HfpCall, HfpCallHeld, HfpCallSetup, HfpCallStatus, HfpIndicator};

// HF-side callback trait object
pub use hfp::HfpHfCallbacks;

// ---------------------------------------------------------------------------
// Re-exports — Battery profile
// ---------------------------------------------------------------------------

pub use battery::BtBattery;
pub use battery::{LAST_CHARGES_SIZE, MAX_CHARGE_STEP};

// ---------------------------------------------------------------------------
// Re-exports — RAP (Ranging) profile
// ---------------------------------------------------------------------------

pub use rap::BtRap;
pub use rap::RAS_UUID16;
pub use rap::RapError;
