// SPDX-License-Identifier: GPL-2.0-or-later
//
// Profile protocol modules for BlueZ shared library.
//
// Declares and re-exports the profile sub-modules: GAP, HFP, Battery, RAP.

pub mod battery;
pub mod hfp;

// Re-export primary public types for convenient access.
pub use battery::BtBattery;
