// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux

//! Capture file format parsers for Bluetooth packet traces.
//!
//! This module provides parsers for capture file formats used by `btmon`
//! (the Bluetooth packet monitor):
//!
//! - [`btsnoop`] — BTSnoop capture file format with Apple PacketLogger (PKLG)
//!   support, file rotation, and both read/write capability.
//! - [`pcap`] — Standard PCAP format with PPI (Per-Packet Information) header
//!   support (read-only).
//!
//! Replaces C implementations in `src/shared/btsnoop.c/h` and
//! `src/shared/pcap.c/h`.

pub mod btsnoop;
pub mod pcap;

pub use btsnoop::{
    BTSNOOP_FLAG_PKLG_SUPPORT, BtSnoop, BtSnoopBus, BtSnoopError, BtSnoopFormat, BtSnoopOpcode,
    BtSnoopOpcodeIndexInfo, BtSnoopOpcodeNewIndex, BtSnoopOpcodeUserLogging, BtSnoopPriority,
    HciRecord, MAX_PACKET_SIZE, TYPE_AMP, TYPE_PRIMARY,
};
pub use pcap::{Pcap, PcapType};
