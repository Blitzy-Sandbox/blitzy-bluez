// SPDX-License-Identifier: GPL-2.0-or-later
//
// plugins — Built-in daemon plugins.
//
// Each sub-module implements a `BluetoothPlugin` and registers itself via
// `inventory::submit!`.  The modules are deliberately `pub` so that the
// linker pulls them in and the `inventory` registrations take effect.

pub mod admin;
pub mod autopair;
pub mod hostname;
pub mod neard;
pub mod policy;
pub mod sixaxis;
