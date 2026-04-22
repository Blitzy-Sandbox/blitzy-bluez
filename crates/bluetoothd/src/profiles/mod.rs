// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2004-2010 Marcel Holtmann <marcel@holtmann.org>
// Copyright (C) 2024 BlueZ contributors

//! Bluetooth profile plugin implementations.
//!
//! This module contains all profile plugins that provide Bluetooth service
//! functionality in `bluetoothd`. Each profile registers itself via
//! `inventory::submit!` and is automatically discovered by the plugin
//! framework during daemon initialization.
//!
//! # Module Organization
//!
//! This module consolidates what were previously 11 separate C directories
//! under `profiles/`, each with their own `BLUETOOTH_PLUGIN_DEFINE`
//! registrations, into a single Rust module hierarchy. In the C codebase,
//! individual profiles were conditionally compiled via `configure.ac` /
//! `Makefile.am`; in Rust, all profiles are compiled unconditionally and
//! runtime conditional activation is handled by the plugin framework's
//! enable/disable glob filters in `plugin.rs`.
//!
//! The declaration order below does **not** affect initialization order.
//! Plugin initialization order is determined by the `priority` field in each
//! plugin descriptor, sorted by `plugin.rs` during startup.
//!
//! # Profile Categories
//!
//! ## Classic Bluetooth Profiles
//! - [`input`] — HID Host (HIDP) and HID over GATT (HOGP) with UHID
//!   integration
//! - [`network`] — Personal Area Network (PAN) over BNEP with PANU/GN/NAP
//!   roles
//!
//! ## LE GATT Profiles
//! - [`battery`] — Battery Service (BAS) client feeding `Battery1` D-Bus
//!   framework
//! - [`deviceinfo`] — Device Information Service (DIS) PnP ID reader
//! - [`gap`] — GAP service characteristics reader (Device Name, Appearance,
//!   Preferred Connection Parameters)
//! - [`midi`] — BLE-MIDI bridge to ALSA Sequencer
//! - [`ranging`] — Ranging Profile/Service (RAP/RAS) experimental support
//! - [`scanparam`] — Scan Parameters service client
//!
//! ## Audio Profiles (subfolder)
//! - [`audio`] — Complete audio stack: A2DP, AVRCP, AVDTP, AVCTP, BAP, BASS,
//!   VCP, MICP, MCP, CCP, CSIP, TMAP, GMAP, ASHA, HFP, media/transport/player
//!
//! # Plugin Registration
//!
//! Each child module performs its own plugin registration via
//! `inventory::submit!` at the module level. The `inventory` crate's
//! `collect!` macro automatically aggregates all submitted plugin descriptors
//! at link time. No explicit initialization function is required in this
//! module — the mere act of compiling these child modules ensures their plugin
//! descriptors are collected and made available to the plugin framework.
//!
//! # Excluded Profiles
//!
//! The following C profile directories are explicitly out of scope and have no
//! corresponding Rust module:
//! - `profiles/cups/` — Printing support excluded from this rewrite
//! - `profiles/iap/` — Standalone iAP helper daemon, not a profile plugin

// ---------------------------------------------------------------------------
// Child Module Declarations
// ---------------------------------------------------------------------------
//
// Audio profiles subfolder — A2DP, AVRCP, AVDTP, AVCTP, BAP, BASS, VCP,
// MICP, MCP, CCP, CSIP, TMAP, GMAP, ASHA, HFP, media/transport/player,
// sink/source/control, and telephony.
pub mod audio;

// HID Host (HIDP) and HID over GATT (HOGP) profile plugin with UHID
// integration. Replaces profiles/input/*.c.
pub mod input;

// Personal Area Network (PAN) over BNEP profile plugin with PANU/GN/NAP
// roles. Replaces profiles/network/*.c.
pub mod network;

// Battery Service (BAS) client profile plugin feeding the Battery1 D-Bus
// framework. Replaces profiles/battery/*.c.
pub mod battery;

// Device Information Service (DIS) PnP ID reader profile plugin. Replaces
// profiles/deviceinfo/*.c.
pub mod deviceinfo;

// GAP service characteristics reader profile plugin for Device Name,
// Appearance, and Preferred Connection Parameters. Replaces profiles/gap/*.c.
pub mod gap;

// BLE-MIDI bridge profile plugin connecting BLE MIDI service to ALSA
// Sequencer. Replaces profiles/midi/*.c.
pub mod midi;

// Ranging Profile/Service (RAP/RAS) experimental support profile plugin.
// Replaces profiles/ranging/*.c.
pub mod ranging;

// Scan Parameters service client profile plugin. Replaces
// profiles/scanparam/*.c.
pub mod scanparam;
