// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux

//! GATT subsystem for bluetoothd.
//!
//! This module implements the local GATT database management (GattManager1 D-Bus interface),
//! remote GATT client D-Bus export (GattService1/GattCharacteristic1/GattDescriptor1),
//! and GATT database persistence in INI format.
//!
//! - [`database`] — Per-adapter local GATT DB, external app registration, core GAP/GATT services
//! - [`client`] — Per-device remote GATT D-Bus object export
//! - [`settings`] — GATT DB load/store in INI format for persistent storage

pub mod client;
pub mod database;
pub mod settings;

// Re-export primary public types for convenient access by the rest of the
// bluetoothd crate (e.g. `crate::gatt::BtdGattDatabase` instead of
// `crate::gatt::database::BtdGattDatabase`).
pub use client::BtdGattClient;
pub use database::BtdGattDatabase;
pub use settings::{btd_settings_gatt_db_load, btd_settings_gatt_db_store};
