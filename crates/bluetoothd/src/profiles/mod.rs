// SPDX-License-Identifier: GPL-2.0-or-later
//
// Profile plugin implementations for bluetoothd.
//
// Each sub-module corresponds to a family of Bluetooth profiles and provides
// stub structures capturing the essential data model, state machines, and
// configuration from the original C plugin code (~46K LOC total).

pub mod audio;
pub mod battery;
pub mod deviceinfo;
pub mod gap;
pub mod iap;
pub mod input;
pub mod midi;
pub mod network;
pub mod ranging;
pub mod scanparam;
