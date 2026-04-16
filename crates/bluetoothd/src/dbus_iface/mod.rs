// SPDX-License-Identifier: GPL-2.0-or-later
//
// D-Bus interface implementations for bluetoothd.
//
// Each sub-module provides a zbus `#[interface]` implementation that wraps
// the corresponding internal state types (BtdAdapter, BtdDevice, etc.) and
// exposes them on the system bus following the BlueZ D-Bus API.

pub mod adapter1;
pub mod advertising;
pub mod agent;
pub mod battery;
pub mod device1;
pub mod gatt;
pub mod profile_mgr;
