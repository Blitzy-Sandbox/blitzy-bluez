// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite
//
// HCI (Host Controller Interface) protocol definitions.
// Corresponds to monitor/bt.h + lib/bluetooth/hci.h

pub mod opcodes;
pub mod events;
pub mod structs;
pub mod transport;
