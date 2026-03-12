// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Kernel Management (MGMT) protocol client module.
//
// This module provides the async MGMT client transport used by bluetoothd
// and integration testers for communicating with the kernel Bluetooth
// subsystem over HCI_CHANNEL_CONTROL.

pub mod client;

// Re-export primary public types for ergonomic access.
pub use client::{
    MgmtError, MgmtEvent, MgmtIoCapability, MgmtResponse, MgmtSocket, MgmtTlvEntry, MgmtTlvList,
    mgmt_iocap_generator, mgmt_parse_io_capability,
};
