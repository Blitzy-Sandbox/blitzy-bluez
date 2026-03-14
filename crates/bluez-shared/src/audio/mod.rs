// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors

//! LE Audio state machines and protocol engines.
//!
//! This module provides Rust implementations of the Bluetooth LE Audio
//! protocol state machines originally implemented in C within `src/shared/`.
//! These are core protocol engines consumed by the `bluetoothd` audio
//! profile plugins.
//!
//! # Modules
//!
//! - [`bap`] — Basic Audio Profile (PAC, ASE, streams, codec/QoS config)
//! - [`bass`] — Broadcast Audio Scan Service (broadcast assistant)
//! - [`vcp`] — Volume Control Service (VCS/VOCS/AICS)
//! - [`mcp`] — Media Control Service (MCS/GMCS, media player)
//! - [`micp`] — Microphone Control (MICS mute)
//! - [`ccp`] — Call Control (GTBS/CCP, telephony)
//! - [`csip`] — Coordinated Set Identification (CSIS/CSIP, SIRK)
//! - [`tmap`] — Telephony and Media Audio (TMAS roles)
//! - [`gmap`] — Gaming Audio (GMAS roles/features)
//! - [`asha`] — Audio Streaming for Hearing Aid

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// Basic Audio Profile (BAP) state machine — PAC records, ASE lifecycle,
/// codec/QoS configuration, CIS establishment, and broadcast audio.
pub mod bap;

/// Broadcast Audio Scan Service (BASS) — broadcast source add/modify/remove,
/// PA sync state, BIS sync management, and broadcast code handling.
pub mod bass;

/// Volume Control Profile (VCP) — VCS, VOCS, and AICS server and client
/// for volume control.
pub mod vcp;

/// Media Control Profile (MCP) / Media Control Service (MCS) / GMCS —
/// media player registration and remote media control.
pub mod mcp;

/// Microphone Control Profile (MICP) / MICS — server-side mute state
/// management and client-side remote mute control.
pub mod micp;

/// Call Control Profile (CCP) / Generic Telephone Bearer Service (GTBS) —
/// telephone call control, bearer info access, call state notifications.
pub mod ccp;

/// Coordinated Set Identification Profile (CSIP) / CSIS — set member
/// service registration and set discovery via SIRK.
pub mod csip;

/// Telephony and Media Audio Profile (TMAP) / TMAS — TMAP role
/// characteristic client and server.
pub mod tmap;

/// Gaming Audio Profile (GMAP) / GMAS — gaming audio role and per-role
/// feature characteristics.
pub mod gmap;

/// Audio Streaming for Hearing Aid (ASHA) — HiSync ID management, audio
/// streaming via L2CAP CoC, AudioStatusPoint monitoring.
pub mod asha;

// ---------------------------------------------------------------------------
// Convenience re-exports — primary public types from each sub-module
// ---------------------------------------------------------------------------

// BAP — largest LE Audio module
pub use bap::{
    BapBcastQos, BapCodec, BapQos, BapStreamState, BapStreamType, BapUcastQos, BtBap, BtBapPac,
    BtBapStream,
};

// BASS — broadcast assistant
pub use bass::{BassAddSrcParams, BassModSrcParams, BtBass};

// VCP — volume control
pub use vcp::{BtVcp, VcpType};

// MCP — media control
pub use mcp::{BtMcp, BtMcs, CpOpcode, McpCallback, McsCallback, MediaState, PlayingOrder};

// MICP — microphone control
pub use micp::{BtMicp, BtMics};

// CCP — call control
pub use ccp::BtCcp;

// CSIP — coordinated set identification
pub use csip::{BtCsip, CsipSirkType};

// TMAP — telephony and media audio
pub use tmap::{BtTmap, TmapRole};

// GMAP — gaming audio
pub use gmap::{
    BtGmap, GmapBgrFeatures, GmapBgsFeatures, GmapRole, GmapUggFeatures, GmapUgtFeatures,
};

// ASHA — hearing aid streaming
pub use asha::{AshaState, BtAsha, BtAshaSet};
