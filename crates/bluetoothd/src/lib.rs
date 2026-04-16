// SPDX-License-Identifier: GPL-2.0-or-later
//
// bluetoothd — Bluetooth daemon library
//
// Replaces src/ + profiles/ + plugins/ + gdbus/ + btio/ + attrib/ (~120K LOC).
// Core daemon providing D-Bus interfaces for Bluetooth adapter and device
// management, GATT services, profile dispatch, and plugin loading.

pub mod config;
pub mod btio;
pub mod plugin;
pub mod error;
pub mod agent;
pub mod profile;
pub mod adapter;
pub mod device;
pub mod advertising;
pub mod gatt_database;
pub mod gatt_client;
pub mod storage;
pub mod sdpd;
pub mod dbus_iface;
pub mod plugins;
pub mod profiles;
