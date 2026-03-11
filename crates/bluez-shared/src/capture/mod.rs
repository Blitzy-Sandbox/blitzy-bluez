// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux

//! Capture file format parsers for Bluetooth packet traces.
//!
//! This module provides parsers for capture file formats used by `btmon`
//! (the Bluetooth packet monitor):
//!
//! - [`pcap`] — Standard PCAP format with PPI (Per-Packet Information) header
//!   support (read-only).
//!
//! Replaces C implementations in `src/shared/pcap.c/h`.

pub mod pcap;

pub use pcap::{Pcap, PcapType};
