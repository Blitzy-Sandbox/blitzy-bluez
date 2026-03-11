// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth-specific cryptographic primitives
//
// This module provides the cryptographic building blocks required by
// the Bluetooth Core Specification.

//! Bluetooth-specific cryptographic primitives.
//!
//! This module provides two categories of cryptographic operations:
//!
//! - **AES/CMAC** (`aes_cmac`) — AES-128/CMAC-based crypto for LE pairing,
//!   ATT signing, GATT hashing, and CSIS/SIRK operations
//! - **ECC** (`ecc`) — P-256 elliptic curve operations for LE Secure
//!   Connections key exchange

pub mod ecc;

// Re-export the ECC error type for convenient access
pub use ecc::EccError;
