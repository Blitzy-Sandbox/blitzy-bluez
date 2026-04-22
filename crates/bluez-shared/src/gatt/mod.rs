// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
//! GATT Protocol Module
//!
//! Module root for the Generic Attribute Profile (GATT) protocol engines.
//! Declares all sub-modules and provides convenient re-exports for the
//! primary public types used by consumers (`bluetoothd`, `bluetoothctl`,
//! tests).
//!
//! # Sub-modules
//!
//! - [`db`] — In-memory GATT database (`GattDb`, `GattDbAttribute`,
//!   `GattDbService`). Port of `src/shared/gatt-db.c` / `gatt-db.h`.
//! - [`client`] — GATT client engine (`BtGattClient`). Port of
//!   `src/shared/gatt-client.c` / `gatt-client.h`.
//! - [`server`] — GATT server engine (`BtGattServer`). Port of
//!   `src/shared/gatt-server.c` / `gatt-server.h`.
//! - [`helpers`] — Discovery utilities and result iterators
//!   (`BtGattResult`, `BtGattIter`, discovery functions). Port of
//!   `src/shared/gatt-helpers.c` / `gatt-helpers.h`.
//!
//! # Re-exports
//!
//! The most frequently used types are re-exported at this module level
//! so consumers can write `use bluez_shared::gatt::GattDb` instead of
//! the fully qualified `use bluez_shared::gatt::db::GattDb`.

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

pub mod client;
pub mod db;
pub mod helpers;
pub mod server;

// ---------------------------------------------------------------------------
// Re-exports — Primary types (used by lib.rs re-exports)
// ---------------------------------------------------------------------------

pub use client::BtGattClient;
pub use db::GattDb;
pub use server::BtGattServer;

// ---------------------------------------------------------------------------
// Re-exports — Discovery helpers (frequently imported by consumers)
// ---------------------------------------------------------------------------

pub use helpers::{BtGattIter, BtGattResult};

// ---------------------------------------------------------------------------
// Re-exports — Entry types returned by iterators
// ---------------------------------------------------------------------------

pub use helpers::{CharEntry, DescEntry, InclEntry, ReadByTypeEntry, ServiceEntry};

// ---------------------------------------------------------------------------
// Re-exports — Error type
// ---------------------------------------------------------------------------

pub use helpers::GattError;
