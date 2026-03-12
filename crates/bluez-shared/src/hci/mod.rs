// SPDX-License-Identifier: GPL-2.0-or-later
//! HCI (Host Controller Interface) transport and crypto modules.
//!
//! This module provides async socket transport for communicating with
//! Bluetooth controllers via the HCI protocol, and HCI-assisted LE
//! cryptographic operations.

pub mod transport;

// Re-export primary public types for ergonomic access.
pub use transport::{HciError, HciEvent, HciResponse, HciTransport};
