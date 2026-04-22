// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Audio Profiles Subsystem Module Root
//
// Copyright 2024 BlueZ Project
//
//! Module root for the audio profiles subsystem.
//!
//! Declares all 22 child modules and provides shared types, constants, and
//! utilities used across the audio stack. This is the foundational file that
//! ties together the entire audio profile implementation within the
//! `bluetoothd` daemon.
//!
//! # Child Module Organization
//!
//! Modules are declared in dependency order:
//!
//! 1. **Protocol transport engines** — foundational L2CAP-based transports
//!    (`avdtp`, `avctp`)
//! 2. **D-Bus infrastructure** — media transport, player, and hub interfaces
//!    (`transport`, `player`, `media`)
//! 3. **Classic audio profiles** — BR/EDR signaling and control (`a2dp`,
//!    `avrcp`)
//! 4. **LE Audio profiles** — BAP ecosystem (`bap`, `bass`, `vcp`, `micp`,
//!    `mcp`, `ccp`, `csip`, `tmap`, `gmap`)
//! 5. **Role-specific modules** — A2DP roles and legacy control (`sink`,
//!    `source`, `control`)
//! 6. **Hearing aid & telephony** — ASHA, HFP, telephony interface (`asha`,
//!    `hfp`, `telephony`)
//!
//! # Shared Types
//!
//! - [`AudioError`] — Common error type for the audio subsystem
//! - [`codec`] — Bluetooth SIG assigned codec identifiers
//! - [`uuid`] — Standard Bluetooth service UUID constants
//! - D-Bus interface name constants (`MEDIA_INTERFACE`, etc.)
//!
//! # Re-exports
//!
//! Commonly used types are re-exported at this level for convenience:
//! [`MediaAdapter`], [`MediaTransport`], [`MediaPlayer`], [`AvdtpSession`],
//! [`AvdtpSep`], [`AvdtpStream`], [`AvctpSession`], [`A2dpSep`].

use std::io;

use thiserror::Error;

// ===========================================================================
// Child Module Declarations (dependency order)
// ===========================================================================

// --- Protocol transport engines (foundational) ---

/// AVDTP (Audio/Video Distribution Transport Protocol) signaling and stream
/// state machine module.  Foundational transport protocol for A2DP audio
/// streaming, managing L2CAP signaling channels, SEP registration, and stream
/// lifecycle.
pub mod avdtp;

/// AVCTP (Audio/Video Control Transport Protocol) control and browsing
/// transport module.  L2CAP-based transport for AVRCP, handling per-adapter
/// server listen, per-device session management, and passthrough key
/// translation.
pub mod avctp;

// --- D-Bus infrastructure ---

/// `MediaTransport1` D-Bus interface module.  Transport ownership model,
/// `Acquire`/`TryAcquire`/`Release` lifecycle, per-profile transport ops
/// (A2DP/BAP/ASHA), and state machine.
pub mod transport;

/// Media player D-Bus object module.  `MediaPlayer1`/`MediaFolder1`/
/// `MediaItem1` interfaces for playback control, metadata, and media browsing.
pub mod player;

/// `Media1` D-Bus hub module.  Per-adapter central hub for endpoint
/// management, player management, `RegisterApplication`, and UUID/feature
/// computation bridging to A2DP/BAP/ASHA.
pub mod media;

// --- Classic audio profiles ---

/// A2DP (Advanced Audio Distribution Profile) signaling and endpoint
/// management module.  Core BR/EDR audio signaling, SEP registration, SDP
/// records, remote SEP discovery/caching, stream configuration lifecycle.
pub mod a2dp;

/// AVRCP (Audio/Video Remote Control Profile) controller/target module.
/// Media control and metadata exchange over AVCTP.
pub mod avrcp;

// --- LE Audio profiles (BAP ecosystem) ---

/// BAP (Basic Audio Profile) unicast/broadcast audio module.  LE Audio
/// streaming over ISO channels.
pub mod bap;

/// BASS (Broadcast Audio Scan Service) broadcast assistant module.  Managing
/// broadcast audio sources.
pub mod bass;

/// VCP (Volume Control Profile) volume control module.  Managing device
/// volume via GATT (VCS/VOCS/AICS).
pub mod vcp;

/// MICP (Microphone Control Profile) module.  Managing device mute state via
/// GATT (MICS).
pub mod micp;

/// MCP (Media Control Profile) module.  LE Audio media player control via
/// GATT (MCS/GMCS).
pub mod mcp;

/// CCP (Call Control Profile) module.  Telephone call management over LE
/// Audio (GTBS/TBS).
pub mod ccp;

/// CSIP (Coordinated Set Identification Profile) module.  Managing device
/// sets (e.g., left/right earbuds) via CSIS.
pub mod csip;

/// TMAP (Telephony and Media Audio Profile) module.  Role advertisement and
/// discovery for telephony/media audio devices.
pub mod tmap;

/// GMAP (Gaming Audio Profile) module.  Low-latency gaming audio role
/// management.
pub mod gmap;

// --- Role-specific modules ---

/// A2DP Sink role module.  Handles incoming audio streams from remote A2DP
/// source devices.
pub mod sink;

/// A2DP Source role module.  Handles outgoing audio streams to remote A2DP
/// sink devices.
pub mod source;

/// AVRCP control channel module.  Legacy AVRCP control channel management.
pub mod control;

// --- Hearing aid & telephony ---

/// ASHA (Audio Streaming for Hearing Aid) module.  Hearing aid streaming
/// over LE CoC (Connection-oriented Channels).
pub mod asha;

/// HFP (Hands-Free Profile) module.  Voice call audio and telephony features
/// over RFCOMM/SCO.
pub mod hfp;

/// Telephony interface module.  Telephony state management and D-Bus interface
/// for call control integration.
pub mod telephony;

// ===========================================================================
// Shared Audio Codec Identifiers
// ===========================================================================

/// Audio codec identifiers matching Bluetooth SIG assigned numbers.
///
/// These constants represent the codec type field in A2DP/BAP codec
/// capability structures.  Values are defined by the Bluetooth SIG
/// Assigned Numbers document.
pub mod codec {
    /// SBC (Sub-Band Coding) — mandatory A2DP codec.
    pub const SBC: u8 = 0x00;

    /// MPEG-1,2 Audio — optional A2DP codec (includes MP3).
    pub const MPEG12: u8 = 0x01;

    /// AAC (Advanced Audio Coding) — MPEG-2/4 AAC, optional A2DP codec.
    pub const AAC: u8 = 0x02;

    /// ATRAC (Adaptive Transform Acoustic Coding) — Sony codec, optional.
    pub const ATRAC: u8 = 0x04;

    /// Vendor-specific codec identifier.  Actual codec is determined by the
    /// vendor ID and codec ID fields in the codec information element.
    pub const VENDOR: u8 = 0xFF;

    /// LC3 (Low Complexity Communication Codec) — mandatory LE Audio codec.
    /// Used with BAP unicast and broadcast audio streams.
    pub const LC3: u8 = 0x06;
}

// ===========================================================================
// Shared Bluetooth Service UUID Constants
// ===========================================================================

/// Standard Bluetooth service UUID constants for audio profiles.
///
/// All UUIDs are in the full 128-bit string format
/// (`xxxxxxxx-0000-1000-8000-00805f9b34fb`) derived from the 16-bit
/// Bluetooth SIG assigned numbers.
pub mod uuid {
    /// A2DP Source service UUID (AudioSource — 0x110A).
    pub const A2DP_SOURCE: &str = "0000110a-0000-1000-8000-00805f9b34fb";

    /// A2DP Sink service UUID (AudioSink — 0x110B).
    pub const A2DP_SINK: &str = "0000110b-0000-1000-8000-00805f9b34fb";

    /// AVRCP Remote Controller service UUID (A/V Remote Control — 0x110E).
    pub const AVRCP_REMOTE: &str = "0000110e-0000-1000-8000-00805f9b34fb";

    /// AVRCP Target service UUID (A/V Remote Control Target — 0x110C).
    pub const AVRCP_TARGET: &str = "0000110c-0000-1000-8000-00805f9b34fb";

    /// Published Audio Capabilities Service UUID (PACS — 0x1850).
    pub const PACS: &str = "00001850-0000-1000-8000-00805f9b34fb";

    /// Broadcast Audio Announcement Service UUID (BCAAS — 0x1852).
    pub const BCAAS: &str = "00001852-0000-1000-8000-00805f9b34fb";

    /// Broadcast Audio Scan Service UUID (BASS — 0x184F).
    pub const BASS: &str = "0000184f-0000-1000-8000-00805f9b34fb";

    /// Volume Control Service UUID (VCS — 0x1844).
    pub const VCS: &str = "00001844-0000-1000-8000-00805f9b34fb";

    /// Microphone Control Service UUID (MICS — 0x184D).
    pub const MICS: &str = "0000184d-0000-1000-8000-00805f9b34fb";

    /// Generic Media Control Service UUID (GMCS — 0x1849).
    pub const GMCS: &str = "00001849-0000-1000-8000-00805f9b34fb";

    /// Generic Telephone Bearer Service UUID (GTBS — 0x184C).
    pub const GTBS: &str = "0000184c-0000-1000-8000-00805f9b34fb";

    /// Coordinated Set Identification Service UUID (CSIS — 0x1846).
    pub const CSIS: &str = "00001846-0000-1000-8000-00805f9b34fb";

    /// Telephony and Media Audio Service UUID (TMAS — 0x1855).
    pub const TMAS: &str = "00001855-0000-1000-8000-00805f9b34fb";

    /// Gaming Audio Service UUID (GMAS — 0x1858).
    pub const GMAS: &str = "00001858-0000-1000-8000-00805f9b34fb";

    /// Audio Streaming for Hearing Aid service UUID (ASHA — 0xFDF0).
    pub const ASHA: &str = "0000fdf0-0000-1000-8000-00805f9b34fb";

    /// Hands-Free service UUID (HFP HF — 0x111E).
    pub const HFP_HF: &str = "0000111e-0000-1000-8000-00805f9b34fb";

    /// Audio Gateway service UUID (HFP AG — 0x111F).
    pub const HFP_AG: &str = "0000111f-0000-1000-8000-00805f9b34fb";
}

// ===========================================================================
// Shared D-Bus Interface Name Constants
// ===========================================================================

/// D-Bus interface name for `org.bluez.Media1` — the per-adapter media hub
/// managing endpoints, players, and application registration.
pub const MEDIA_INTERFACE: &str = "org.bluez.Media1";

/// D-Bus interface name for `org.bluez.MediaEndpoint1` — codec endpoint
/// registration and configuration.
pub const MEDIA_ENDPOINT_INTERFACE: &str = "org.bluez.MediaEndpoint1";

/// D-Bus interface name for `org.bluez.MediaPlayer1` — media playback
/// control and status.
pub const MEDIA_PLAYER_INTERFACE: &str = "org.bluez.MediaPlayer1";

/// D-Bus interface name for `org.bluez.MediaFolder1` — media browsing
/// folder navigation.
pub const MEDIA_FOLDER_INTERFACE: &str = "org.bluez.MediaFolder1";

/// D-Bus interface name for `org.bluez.MediaItem1` — individual media
/// item metadata.
pub const MEDIA_ITEM_INTERFACE: &str = "org.bluez.MediaItem1";

/// D-Bus interface name for `org.bluez.MediaTransport1` — audio transport
/// acquisition and management.
pub const MEDIA_TRANSPORT_INTERFACE: &str = "org.bluez.MediaTransport1";

/// D-Bus interface name for `org.bluez.MediaAssistant1` — broadcast
/// assistant interface for managing broadcast audio streams.
pub const MEDIA_ASSISTANT_INTERFACE: &str = "org.bluez.MediaAssistant1";

// ===========================================================================
// Shared Audio Error Type
// ===========================================================================

/// Common error type for the audio profiles subsystem.
///
/// Variants map to common failure modes across A2DP, AVRCP, BAP, HFP, and
/// other audio profiles.  The error type is designed to integrate with D-Bus
/// error reply mapping in the daemon's error module.
#[derive(Error, Debug)]
pub enum AudioError {
    /// The device or transport is not connected.
    #[error("Not connected")]
    NotConnected,

    /// The requested operation or feature is not supported.
    #[error("Not supported")]
    NotSupported,

    /// A connection already exists for this device/profile.
    #[error("Already connected")]
    AlreadyConnected,

    /// An operation is already in progress (e.g., stream setup, pairing).
    #[error("In progress")]
    InProgress,

    /// The requested resource (endpoint, transport, stream) is not available.
    #[error("Not available")]
    NotAvailable,

    /// A general failure with a descriptive message.
    #[error("Failed: {0}")]
    Failed(String),

    /// An I/O error from the underlying transport or socket.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

// ===========================================================================
// Re-exports
// ===========================================================================

// Re-export commonly used types for convenient access by other daemon modules
// (e.g., `crate::profiles::audio::MediaAdapter` instead of
// `crate::profiles::audio::media::MediaAdapter`).

pub use a2dp::A2dpSep;
pub use avctp::AvctpSession;
pub use avdtp::{AvdtpSep, AvdtpSession, AvdtpStream};
pub use media::MediaAdapter;
pub use player::MediaPlayer;
pub use transport::MediaTransport;
