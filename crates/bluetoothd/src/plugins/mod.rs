// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (C) 2024 BlueZ Contributors
 */

//! Daemon plugin module declarations for `bluetoothd`.
//!
//! This module contains the six built-in daemon plugins that extend the core
//! Bluetooth daemon with additional functionality. Each plugin implements the
//! [`BluetoothPlugin`](crate::plugin::BluetoothPlugin) trait from
//! `crate::plugin` and self-registers via [`inventory::submit!`] for automatic
//! collection at daemon startup.
//!
//! # Plugin Registration
//!
//! Plugins use the [`inventory`] crate's compile-time collection mechanism.
//! Each plugin file contains an `inventory::submit!` call that registers a
//! [`PluginDesc`](crate::plugin::PluginDesc) descriptor. At startup, the
//! plugin framework in [`crate::plugin`] collects all registered descriptors
//! via `inventory::iter::<PluginDesc>()`, applies enable/disable glob filters,
//! sorts by priority, and invokes each plugin's initialization function.
//!
//! This replaces the C pattern where `BLUETOOTH_PLUGIN_DEFINE()` macros
//! emitted `const struct bluetooth_plugin_desc` entries into a linker section,
//! and the generated `src/builtin.h` collected them into the
//! `__bluetooth_builtin[]` array.
//!
//! # Priority Ordering
//!
//! Plugin initialization order is determined by priority values:
//!
//! | Priority | Value | Description |
//! |----------|-------|-------------|
//! | Low      | -100  | Initialized last, for non-critical or dependent plugins |
//! | Default  |    0  | Standard initialization order |
//! | High     |  100  | Initialized first, for foundational plugins |
//!
//! # Plugins
//!
//! The following six plugins are declared:
//!
//! - **`sixaxis`** — PlayStation controller cable pairing via udev/hidraw.
//!   Handles DualShock 3/4 and DualSense controller authentication over USB
//!   and registers them for Bluetooth pairing. Priority: **Low** (-100).
//!
//! - **`admin`** — Administrative policy allowlist enforcement. Provides the
//!   `org.bluez.AdminPolicySet1` and `org.bluez.AdminPolicyStatus1` D-Bus
//!   interfaces for restricting allowed service UUIDs. Priority: **Default** (0).
//!   Marked as **Experimental**.
//!
//! - **`autopair`** — Automatic PIN code heuristics for legacy pairing.
//!   Recognizes common device types (Wii remotes, keyboards, etc.) and
//!   supplies appropriate PIN codes without user interaction. Priority:
//!   **Default** (0).
//!
//! - **`hostname`** — System hostname synchronization. Monitors hostname
//!   changes via D-Bus (`org.freedesktop.hostname1`) and updates the local
//!   Bluetooth adapter name and device class accordingly. Priority:
//!   **Default** (0).
//!
//! - **`neard`** — NFC pairing bridge via the neard daemon. Implements
//!   Bluetooth Secure Simple Pairing using NFC out-of-band (OOB) data
//!   exchange through the `org.neard` D-Bus service. Priority:
//!   **Default** (0).
//!
//! - **`policy`** — Reconnection and auto-connect policy engine. Manages
//!   automatic reconnection attempts for bonded devices, service-level
//!   connection policies, and idle disconnect timeouts. Priority:
//!   **Default** (0).

pub mod admin;
pub mod autopair;
pub mod hostname;
pub mod neard;
pub mod policy;
pub mod sixaxis;
