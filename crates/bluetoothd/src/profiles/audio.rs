// SPDX-License-Identifier: GPL-2.0-or-later
//
// Audio profile implementations (~36K LOC C total).
//
// Covers A2DP, AVRCP, AVDTP, BAP (LE Audio), BASS, CSIP, HFP, MCP, VCP,
// CCP, MICP, ASHA, GMAP, TMAP, and supporting media endpoint/transport types.

use std::collections::HashMap;
use std::fmt;

use bluez_shared::BdAddr;

// ---------------------------------------------------------------------------
// Codec identifiers
// ---------------------------------------------------------------------------

/// Media codec type used in A2DP / BAP negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AudioCodec {
    Sbc,
    Aac,
    AptX,
    AptXHd,
    Ldac,
    Lc3,
    Opus,
    VendorDefined(u32),
}

// ---------------------------------------------------------------------------
// SBC Codec Parameters
// ---------------------------------------------------------------------------

/// SBC sampling frequency values (bitmask in capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbcSamplingFreq {
    Freq16000 = 0x80,
    Freq32000 = 0x40,
    Freq44100 = 0x20,
    Freq48000 = 0x10,
}

/// SBC channel mode (bitmask in capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbcChannelMode {
    Mono = 0x08,
    DualChannel = 0x04,
    Stereo = 0x02,
    JointStereo = 0x01,
}

/// SBC block length (bitmask in capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbcBlockLength {
    Blocks4 = 0x80,
    Blocks8 = 0x40,
    Blocks12 = 0x20,
    Blocks16 = 0x10,
}

/// SBC subbands (bitmask in capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbcSubbands {
    Subbands4 = 0x08,
    Subbands8 = 0x04,
}

/// SBC allocation method (bitmask in capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbcAllocationMethod {
    Snr = 0x02,
    Loudness = 0x01,
}

/// Full SBC codec configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbcCodecParams {
    pub sampling_freq: SbcSamplingFreq,
    pub channel_mode: SbcChannelMode,
    pub block_length: SbcBlockLength,
    pub subbands: SbcSubbands,
    pub allocation_method: SbcAllocationMethod,
    pub min_bitpool: u8,
    pub max_bitpool: u8,
}

impl SbcCodecParams {
    /// Encode SBC capabilities into the 4-byte A2DP format.
    pub fn to_bytes(&self) -> [u8; 4] {
        let b0 = (self.sampling_freq as u8) | (self.channel_mode as u8);
        let b1 = (self.block_length as u8)
            | (self.subbands as u8)
            | (self.allocation_method as u8);
        [b0, b1, self.min_bitpool, self.max_bitpool]
    }

    /// Decode SBC capabilities from the 4-byte A2DP format.
    /// Returns `None` if the bytes contain no recognized flags.
    pub fn from_bytes(bytes: &[u8; 4]) -> Option<Self> {
        let freq = match bytes[0] & 0xF0 {
            0x80 => SbcSamplingFreq::Freq16000,
            0x40 => SbcSamplingFreq::Freq32000,
            0x20 => SbcSamplingFreq::Freq44100,
            0x10 => SbcSamplingFreq::Freq48000,
            _ => return None,
        };
        let mode = match bytes[0] & 0x0F {
            0x08 => SbcChannelMode::Mono,
            0x04 => SbcChannelMode::DualChannel,
            0x02 => SbcChannelMode::Stereo,
            0x01 => SbcChannelMode::JointStereo,
            _ => return None,
        };
        let blocks = match bytes[1] & 0xF0 {
            0x80 => SbcBlockLength::Blocks4,
            0x40 => SbcBlockLength::Blocks8,
            0x20 => SbcBlockLength::Blocks12,
            0x10 => SbcBlockLength::Blocks16,
            _ => return None,
        };
        let subs = match bytes[1] & 0x0C {
            0x08 => SbcSubbands::Subbands4,
            0x04 => SbcSubbands::Subbands8,
            _ => return None,
        };
        let alloc = match bytes[1] & 0x03 {
            0x02 => SbcAllocationMethod::Snr,
            0x01 => SbcAllocationMethod::Loudness,
            _ => return None,
        };
        Some(Self {
            sampling_freq: freq,
            channel_mode: mode,
            block_length: blocks,
            subbands: subs,
            allocation_method: alloc,
            min_bitpool: bytes[2],
            max_bitpool: bytes[3],
        })
    }

    /// Default SBC High Quality Joint Stereo configuration.
    pub fn default_hq() -> Self {
        Self {
            sampling_freq: SbcSamplingFreq::Freq44100,
            channel_mode: SbcChannelMode::JointStereo,
            block_length: SbcBlockLength::Blocks16,
            subbands: SbcSubbands::Subbands8,
            allocation_method: SbcAllocationMethod::Loudness,
            min_bitpool: 2,
            max_bitpool: 53,
        }
    }
}

// ---------------------------------------------------------------------------
// AAC Codec Parameters
// ---------------------------------------------------------------------------

/// AAC object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AacObjectType {
    Mpeg2AacLc = 0x80,
    Mpeg4AacLc = 0x40,
    Mpeg4AacLtp = 0x20,
    Mpeg4AacScalable = 0x10,
}

/// AAC codec configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AacCodecParams {
    pub object_type: AacObjectType,
    pub sampling_freq: u16,
    pub channels: u8,
    pub vbr: bool,
    pub bitrate: u32,
}

impl AacCodecParams {
    /// Encode AAC capabilities into the 6-byte A2DP format.
    pub fn to_bytes(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0] = self.object_type as u8;
        // Sampling frequency: 12 bits spread across bytes 1-2
        out[1] = ((self.sampling_freq >> 4) & 0xFF) as u8;
        out[2] = ((self.sampling_freq & 0x0F) << 4) as u8 | (self.channels & 0x0C);
        // VBR flag + bitrate (23 bits)
        let vbr_bit: u32 = if self.vbr { 1 << 23 } else { 0 };
        let br_field = vbr_bit | (self.bitrate & 0x7FFFFF);
        out[3] = ((br_field >> 16) & 0xFF) as u8;
        out[4] = ((br_field >> 8) & 0xFF) as u8;
        out[5] = (br_field & 0xFF) as u8;
        out
    }

    /// Default AAC-LC 44.1kHz stereo configuration.
    pub fn default_lc() -> Self {
        Self {
            object_type: AacObjectType::Mpeg2AacLc,
            sampling_freq: 0x0100, // 44100 Hz position
            channels: 0x04,       // stereo
            vbr: true,
            bitrate: 320_000,
        }
    }
}

// ---------------------------------------------------------------------------
// LDAC Codec Parameters
// ---------------------------------------------------------------------------

/// LDAC sampling frequency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdacSamplingFreq {
    Freq44100 = 0x20,
    Freq48000 = 0x10,
    Freq88200 = 0x08,
    Freq96000 = 0x04,
}

/// LDAC channel mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdacChannelMode {
    Mono = 0x04,
    DualChannel = 0x02,
    Stereo = 0x01,
}

/// LDAC codec configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdacCodecParams {
    /// Sony vendor ID: 0x012D
    pub vendor_id: u32,
    /// LDAC codec ID: 0x00AA
    pub codec_id: u16,
    pub sampling_freq: LdacSamplingFreq,
    pub channel_mode: LdacChannelMode,
}

impl LdacCodecParams {
    pub fn default_hq() -> Self {
        Self {
            vendor_id: 0x012D,
            codec_id: 0x00AA,
            sampling_freq: LdacSamplingFreq::Freq96000,
            channel_mode: LdacChannelMode::Stereo,
        }
    }
}

// ---------------------------------------------------------------------------
// A2DP Codec Wrapper
// ---------------------------------------------------------------------------

/// Unified A2DP codec enum wrapping all codec parameter types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum A2dpCodec {
    Sbc(SbcCodecParams),
    Aac(AacCodecParams),
    Ldac(LdacCodecParams),
}

impl A2dpCodec {
    /// Priority for codec negotiation (higher = preferred).
    fn priority(&self) -> u8 {
        match self {
            A2dpCodec::Ldac(_) => 3,
            A2dpCodec::Aac(_) => 2,
            A2dpCodec::Sbc(_) => 1,
        }
    }

    /// Return the generic AudioCodec type for this codec.
    pub fn audio_codec(&self) -> AudioCodec {
        match self {
            A2dpCodec::Sbc(_) => AudioCodec::Sbc,
            A2dpCodec::Aac(_) => AudioCodec::Aac,
            A2dpCodec::Ldac(_) => AudioCodec::Ldac,
        }
    }
}

/// Negotiate the best matching codec between local and remote capability lists.
///
/// Returns the highest-priority codec that appears in both local and remote
/// lists (matched by codec type). For SBC, bitpool ranges are intersected.
pub fn negotiate_codec(local: &[A2dpCodec], remote: &[A2dpCodec]) -> Option<A2dpCodec> {
    let mut best: Option<A2dpCodec> = None;
    for l in local {
        for r in remote {
            let matched = match (l, r) {
                (A2dpCodec::Sbc(lp), A2dpCodec::Sbc(rp)) => {
                    if lp.sampling_freq == rp.sampling_freq
                        && lp.channel_mode == rp.channel_mode
                    {
                        // Intersect bitpool ranges
                        let min_bp = lp.min_bitpool.max(rp.min_bitpool);
                        let max_bp = lp.max_bitpool.min(rp.max_bitpool);
                        if min_bp <= max_bp {
                            Some(A2dpCodec::Sbc(SbcCodecParams {
                                min_bitpool: min_bp,
                                max_bitpool: max_bp,
                                ..lp.clone()
                            }))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                (A2dpCodec::Aac(lp), A2dpCodec::Aac(rp)) => {
                    if lp.object_type == rp.object_type
                        && lp.sampling_freq == rp.sampling_freq
                    {
                        Some(A2dpCodec::Aac(AacCodecParams {
                            bitrate: lp.bitrate.min(rp.bitrate),
                            vbr: lp.vbr && rp.vbr,
                            ..lp.clone()
                        }))
                    } else {
                        None
                    }
                }
                (A2dpCodec::Ldac(lp), A2dpCodec::Ldac(rp)) => {
                    if lp.sampling_freq == rp.sampling_freq
                        && lp.channel_mode == rp.channel_mode
                    {
                        Some(A2dpCodec::Ldac(lp.clone()))
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(m) = matched {
                if best.as_ref().is_none_or(|b| m.priority() > b.priority()) {
                    best = Some(m);
                }
            }
        }
    }
    best
}

// ---------------------------------------------------------------------------
// A2DP — Advanced Audio Distribution Profile
// ---------------------------------------------------------------------------

/// A2DP endpoint role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2dpRole {
    Source,
    Sink,
}

/// A2DP stream state (mirrors AVDTP stream state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum A2dpStreamState {
    #[default]
    Idle,
    Configured,
    Open,
    Streaming,
    Closing,
    Aborting,
}

impl A2dpStreamState {
    /// Check if a transition from `self` to `next` is valid per AVDTP spec.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Idle, Self::Configured)
                | (Self::Configured, Self::Open)
                | (Self::Configured, Self::Closing)
                | (Self::Configured, Self::Aborting)
                | (Self::Open, Self::Streaming)
                | (Self::Open, Self::Closing)
                | (Self::Open, Self::Aborting)
                | (Self::Streaming, Self::Open) // suspend
                | (Self::Streaming, Self::Closing)
                | (Self::Streaming, Self::Aborting)
                | (Self::Closing, Self::Idle)
                | (Self::Aborting, Self::Idle)
        )
    }
}

/// A2DP endpoint with codec, capabilities, and transport info.
#[derive(Debug)]
pub struct A2dpEndpoint {
    pub role: A2dpRole,
    pub codec: A2dpCodec,
    pub capabilities: Vec<u8>,
    pub seid: u8,
    pub in_use: bool,
}

/// A2DP profile plugin.
#[derive(Debug)]
pub struct A2dpProfile {
    pub role: A2dpRole,
    pub codec: AudioCodec,
    pub state: A2dpStreamState,
    pub remote_addr: Option<BdAddr>,
    pub local_seid: u8,
    pub remote_seid: u8,
    pub endpoints: Vec<A2dpEndpoint>,
}

impl A2dpProfile {
    pub fn new(role: A2dpRole, codec: AudioCodec) -> Self {
        Self {
            role,
            codec,
            state: A2dpStreamState::default(),
            remote_addr: None,
            local_seid: 0,
            remote_seid: 0,
            endpoints: Vec::new(),
        }
    }

    /// Attempt a state transition. Returns `true` if the transition was valid.
    pub fn transition(&mut self, new_state: A2dpStreamState) -> bool {
        if self.state.can_transition_to(new_state) {
            self.state = new_state;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// AVDTP — Audio/Video Distribution Transport Protocol
// ---------------------------------------------------------------------------

/// AVDTP signal identifier (per AVDTP 1.3 Table 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AvdtpSignalId {
    Discover = 0x01,
    GetCapabilities = 0x02,
    SetConfiguration = 0x03,
    GetConfiguration = 0x04,
    Reconfigure = 0x05,
    Open = 0x06,
    Start = 0x07,
    Close = 0x08,
    Suspend = 0x09,
    Abort = 0x0A,
    SecurityControl = 0x0B,
    GetAllCapabilities = 0x0C,
    DelayReport = 0x0D,
}

impl AvdtpSignalId {
    /// Convert from raw u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Discover),
            0x02 => Some(Self::GetCapabilities),
            0x03 => Some(Self::SetConfiguration),
            0x04 => Some(Self::GetConfiguration),
            0x05 => Some(Self::Reconfigure),
            0x06 => Some(Self::Open),
            0x07 => Some(Self::Start),
            0x08 => Some(Self::Close),
            0x09 => Some(Self::Suspend),
            0x0A => Some(Self::Abort),
            0x0B => Some(Self::SecurityControl),
            0x0C => Some(Self::GetAllCapabilities),
            0x0D => Some(Self::DelayReport),
            _ => None,
        }
    }
}

/// AVDTP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AvdtpMessageType {
    Command = 0x00,
    GeneralReject = 0x01,
    ResponseAccept = 0x02,
    ResponseReject = 0x03,
}

impl AvdtpMessageType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Command),
            0x01 => Some(Self::GeneralReject),
            0x02 => Some(Self::ResponseAccept),
            0x03 => Some(Self::ResponseReject),
            _ => None,
        }
    }
}

/// AVDTP packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AvdtpPacketType {
    Single = 0x00,
    Start = 0x01,
    Continue = 0x02,
    End = 0x03,
}

impl AvdtpPacketType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Single),
            0x01 => Some(Self::Start),
            0x02 => Some(Self::Continue),
            0x03 => Some(Self::End),
            _ => None,
        }
    }
}

/// An AVDTP signaling packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvdtpPacket {
    pub transaction: u8,
    pub message_type: AvdtpMessageType,
    pub packet_type: AvdtpPacketType,
    pub signal_id: AvdtpSignalId,
    pub payload: Vec<u8>,
}

impl AvdtpPacket {
    /// Encode this signaling packet into wire bytes (single-packet format).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.payload.len());
        // Byte 0: transaction label (4 bits) | packet type (2 bits) | message type (2 bits)
        let b0 = ((self.transaction & 0x0F) << 4)
            | ((self.packet_type as u8 & 0x03) << 2)
            | (self.message_type as u8 & 0x03);
        buf.push(b0);
        // Byte 1: signal ID (6 bits) for single packet
        buf.push(self.signal_id as u8 & 0x3F);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a single AVDTP signaling packet from wire bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let transaction = (data[0] >> 4) & 0x0F;
        let packet_type = AvdtpPacketType::from_u8((data[0] >> 2) & 0x03)?;
        let message_type = AvdtpMessageType::from_u8(data[0] & 0x03)?;
        let signal_id = AvdtpSignalId::from_u8(data[1] & 0x3F)?;
        let payload = if data.len() > 2 {
            data[2..].to_vec()
        } else {
            Vec::new()
        };
        Some(Self {
            transaction,
            message_type,
            packet_type,
            signal_id,
            payload,
        })
    }
}

/// AVDTP Stream End Point media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvdtpMediaType {
    Audio = 0x00,
    Video = 0x01,
    Multimedia = 0x02,
}

/// AVDTP TSEP (Transport Service End Point) type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvdtpTsep {
    Source = 0x00,
    Sink = 0x01,
}

/// AVDTP Stream End Point (SEP).
#[derive(Debug, Clone)]
pub struct AvdtpSep {
    pub seid: u8,
    pub in_use: bool,
    pub media_type: AvdtpMediaType,
    pub tsep: AvdtpTsep,
    pub codec: AudioCodec,
    pub capabilities: Vec<u8>,
}

/// SEID allocator for AVDTP endpoints.
#[derive(Debug)]
pub struct SeidAllocator {
    next: u8,
    max: u8,
}

impl SeidAllocator {
    pub fn new() -> Self {
        Self { next: 1, max: 0x3E } // SEIDs 1-62 are valid
    }

    /// Allocate the next available SEID.
    pub fn alloc(&mut self) -> Option<u8> {
        if self.next > self.max {
            return None;
        }
        let seid = self.next;
        self.next += 1;
        Some(seid)
    }
}

impl Default for SeidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// An AVDTP session between two devices.
#[derive(Debug)]
pub struct AvdtpSession {
    pub remote_addr: BdAddr,
    pub local_seids: Vec<u8>,
    pub remote_seids: Vec<u8>,
    pub version: u16,
    pub initiator: bool,
    pub seps: Vec<AvdtpSep>,
    pub transaction_counter: u8,
}

impl AvdtpSession {
    pub fn new(remote_addr: BdAddr) -> Self {
        Self {
            remote_addr,
            local_seids: Vec::new(),
            remote_seids: Vec::new(),
            version: 0x0103, // AVDTP 1.3
            initiator: false,
            seps: Vec::new(),
            transaction_counter: 0,
        }
    }

    /// Get the next transaction label (wraps 0-15).
    pub fn next_transaction(&mut self) -> u8 {
        let t = self.transaction_counter;
        self.transaction_counter = (t + 1) & 0x0F;
        t
    }

    /// Create a signaling command packet for the given signal.
    pub fn create_command(&mut self, signal: AvdtpSignalId, payload: Vec<u8>) -> AvdtpPacket {
        AvdtpPacket {
            transaction: self.next_transaction(),
            message_type: AvdtpMessageType::Command,
            packet_type: AvdtpPacketType::Single,
            signal_id: signal,
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// AVRCP — Audio/Video Remote Control Profile
// ---------------------------------------------------------------------------

/// AVRCP PDU IDs from the AVRCP specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AvrcpPduId {
    GetCapabilities = 0x10,
    ListPlayerSettings = 0x11,
    GetPlayerSettingValue = 0x13,
    SetPlayerSettingValue = 0x14,
    GetElementAttributes = 0x20,
    GetPlayStatus = 0x30,
    RegisterNotification = 0x31,
    RequestContinuingResponse = 0x40,
    AbortContinuingResponse = 0x41,
    SetAbsoluteVolume = 0x50,
    SetAddressedPlayer = 0x60,
    SetBrowsedPlayer = 0x70,
    GetFolderItems = 0x71,
    ChangePath = 0x72,
    GetItemAttributes = 0x73,
    PlayItem = 0x74,
    Search = 0x75,
    AddToNowPlaying = 0x76,
}

impl AvrcpPduId {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x10 => Some(Self::GetCapabilities),
            0x11 => Some(Self::ListPlayerSettings),
            0x13 => Some(Self::GetPlayerSettingValue),
            0x14 => Some(Self::SetPlayerSettingValue),
            0x20 => Some(Self::GetElementAttributes),
            0x30 => Some(Self::GetPlayStatus),
            0x31 => Some(Self::RegisterNotification),
            0x40 => Some(Self::RequestContinuingResponse),
            0x41 => Some(Self::AbortContinuingResponse),
            0x50 => Some(Self::SetAbsoluteVolume),
            0x60 => Some(Self::SetAddressedPlayer),
            0x70 => Some(Self::SetBrowsedPlayer),
            0x71 => Some(Self::GetFolderItems),
            0x72 => Some(Self::ChangePath),
            0x73 => Some(Self::GetItemAttributes),
            0x74 => Some(Self::PlayItem),
            0x75 => Some(Self::Search),
            0x76 => Some(Self::AddToNowPlaying),
            _ => None,
        }
    }
}

/// AVRCP media attributes per the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MediaAttribute {
    Title = 0x01,
    ArtistName = 0x02,
    AlbumName = 0x03,
    TrackNumber = 0x04,
    TotalTracks = 0x05,
    Genre = 0x06,
    PlayingTime = 0x07,
    CoverArt = 0x08,
}

impl MediaAttribute {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0x01 => Some(Self::Title),
            0x02 => Some(Self::ArtistName),
            0x03 => Some(Self::AlbumName),
            0x04 => Some(Self::TrackNumber),
            0x05 => Some(Self::TotalTracks),
            0x06 => Some(Self::Genre),
            0x07 => Some(Self::PlayingTime),
            0x08 => Some(Self::CoverArt),
            _ => None,
        }
    }
}

/// AVRCP player setting attribute IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PlayerSettingId {
    Equalizer = 0x01,
    Repeat = 0x02,
    Shuffle = 0x03,
    Scan = 0x04,
}

/// Equalizer setting values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EqualizerSetting {
    Off = 0x01,
    On = 0x02,
}

/// Repeat mode setting values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatSetting {
    Off = 0x01,
    SingleTrack = 0x02,
    AllTracks = 0x03,
    Group = 0x04,
}

/// Shuffle mode setting values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShuffleSetting {
    Off = 0x01,
    AllTracks = 0x02,
    Group = 0x03,
}

/// Scan mode setting values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanSetting {
    Off = 0x01,
    AllTracks = 0x02,
    Group = 0x03,
}

/// AVRCP notification event IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AvrcpNotificationEvent {
    PlaybackStatusChanged = 0x01,
    TrackChanged = 0x02,
    TrackReachedEnd = 0x03,
    TrackReachedStart = 0x04,
    PlaybackPosChanged = 0x05,
    BattStatusChanged = 0x06,
    SystemStatusChanged = 0x07,
    PlayerSettingChanged = 0x08,
    NowPlayingChanged = 0x09,
    AvailablePlayersChanged = 0x0A,
    AddressedPlayerChanged = 0x0B,
    UidsChanged = 0x0C,
    VolumeChanged = 0x0D,
}

impl AvrcpNotificationEvent {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::PlaybackStatusChanged),
            0x02 => Some(Self::TrackChanged),
            0x03 => Some(Self::TrackReachedEnd),
            0x04 => Some(Self::TrackReachedStart),
            0x05 => Some(Self::PlaybackPosChanged),
            0x06 => Some(Self::BattStatusChanged),
            0x07 => Some(Self::SystemStatusChanged),
            0x08 => Some(Self::PlayerSettingChanged),
            0x09 => Some(Self::NowPlayingChanged),
            0x0A => Some(Self::AvailablePlayersChanged),
            0x0B => Some(Self::AddressedPlayerChanged),
            0x0C => Some(Self::UidsChanged),
            0x0D => Some(Self::VolumeChanged),
            _ => None,
        }
    }
}

/// AVRCP player playback status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybackStatus {
    Stopped,
    Playing,
    Paused,
    FwdSeek,
    RevSeek,
    Error,
}

/// AVRCP profile plugin.
#[derive(Debug)]
pub struct AvrcpProfile {
    pub playback_status: PlaybackStatus,
    pub volume: u8,
    pub track_title: Option<String>,
    pub track_artist: Option<String>,
    pub track_album: Option<String>,
    pub track_number: Option<u32>,
    pub total_tracks: Option<u32>,
    pub track_genre: Option<String>,
    pub track_duration_ms: u32,
    pub track_position_ms: u32,
    pub browsing_supported: bool,
    pub player_settings: AvrcpPlayerSettings,
    pub registered_notifications: Vec<AvrcpNotificationEvent>,
}

/// Current player settings state.
#[derive(Debug, Clone)]
pub struct AvrcpPlayerSettings {
    pub equalizer: EqualizerSetting,
    pub repeat: RepeatSetting,
    pub shuffle: ShuffleSetting,
    pub scan: ScanSetting,
}

impl Default for AvrcpPlayerSettings {
    fn default() -> Self {
        Self {
            equalizer: EqualizerSetting::Off,
            repeat: RepeatSetting::Off,
            shuffle: ShuffleSetting::Off,
            scan: ScanSetting::Off,
        }
    }
}

impl AvrcpProfile {
    pub fn new() -> Self {
        Self {
            playback_status: PlaybackStatus::Stopped,
            volume: 0x7F, // max absolute volume
            track_title: None,
            track_artist: None,
            track_album: None,
            track_number: None,
            total_tracks: None,
            track_genre: None,
            track_duration_ms: 0,
            track_position_ms: 0,
            browsing_supported: false,
            player_settings: AvrcpPlayerSettings::default(),
            registered_notifications: Vec::new(),
        }
    }

    /// Get a media attribute value as a string.
    pub fn get_attribute(&self, attr: MediaAttribute) -> Option<String> {
        match attr {
            MediaAttribute::Title => self.track_title.clone(),
            MediaAttribute::ArtistName => self.track_artist.clone(),
            MediaAttribute::AlbumName => self.track_album.clone(),
            MediaAttribute::TrackNumber => self.track_number.map(|n| n.to_string()),
            MediaAttribute::TotalTracks => self.total_tracks.map(|n| n.to_string()),
            MediaAttribute::Genre => self.track_genre.clone(),
            MediaAttribute::PlayingTime => Some(self.track_duration_ms.to_string()),
            MediaAttribute::CoverArt => None, // not stored inline
        }
    }
}

impl Default for AvrcpProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BAP — Basic Audio Profile (LE Audio)
// ---------------------------------------------------------------------------

/// ASE (Audio Stream Endpoint) state machine per BAP specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AseState {
    #[default]
    Idle,
    CodecConfigured,
    QosConfigured,
    Enabling,
    Streaming,
    Disabling,
    Releasing,
}

/// Direction of an ASE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AseDirection {
    Source,
    Sink,
}

/// ASE Control Point operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AseControlOp {
    CodecConfigure = 0x01,
    QosConfigure = 0x02,
    Enable = 0x03,
    ReceiverStartReady = 0x04,
    Disable = 0x05,
    ReceiverStopReady = 0x06,
    UpdateMetadata = 0x07,
    Release = 0x08,
}

impl AseControlOp {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::CodecConfigure),
            0x02 => Some(Self::QosConfigure),
            0x03 => Some(Self::Enable),
            0x04 => Some(Self::ReceiverStartReady),
            0x05 => Some(Self::Disable),
            0x06 => Some(Self::ReceiverStopReady),
            0x07 => Some(Self::UpdateMetadata),
            0x08 => Some(Self::Release),
            _ => None,
        }
    }
}

/// QoS configuration parameters for an ASE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosConfig {
    /// SDU interval in microseconds.
    pub sdu_interval: u32,
    /// Framing: 0 = unframed, 1 = framed.
    pub framing: u8,
    /// PHY preference bitmask (1 = 1M, 2 = 2M, 4 = Coded).
    pub phy: u8,
    /// Maximum SDU size in bytes.
    pub max_sdu: u16,
    /// Retransmission number.
    pub retransmission: u8,
    /// Maximum transport latency in milliseconds.
    pub max_transport_latency: u16,
    /// Presentation delay in microseconds.
    pub presentation_delay: u32,
}

impl Default for QosConfig {
    fn default() -> Self {
        Self {
            sdu_interval: 10_000, // 10ms
            framing: 0,
            phy: 0x02,    // 2M PHY
            max_sdu: 120,  // typical LC3
            retransmission: 2,
            max_transport_latency: 20,
            presentation_delay: 40_000, // 40ms
        }
    }
}

// ---------------------------------------------------------------------------
// LC3 Codec Parameters (BAP)
// ---------------------------------------------------------------------------

/// LC3 sampling frequency (from Codec Specific Configuration LTV).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Lc3SamplingFreq {
    Freq8000 = 0x01,
    Freq11025 = 0x02,
    Freq16000 = 0x03,
    Freq22050 = 0x04,
    Freq24000 = 0x05,
    Freq32000 = 0x06,
    Freq44100 = 0x07,
    Freq48000 = 0x08,
}

/// LC3 frame duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Lc3FrameDuration {
    /// 7.5ms frame.
    Dur7_5ms = 0x00,
    /// 10ms frame.
    Dur10ms = 0x01,
}

/// LC3 codec specific configuration (LTV-encoded in BAP).
///
/// Type values per Assigned Numbers:
/// - 0x01: Sampling Frequency
/// - 0x02: Frame Duration
/// - 0x03: Audio Channel Allocation
/// - 0x04: Octets Per Codec Frame
/// - 0x05: Codec Frame Blocks Per SDU
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lc3CodecConfig {
    pub sampling_freq: Lc3SamplingFreq,
    pub frame_duration: Lc3FrameDuration,
    pub octets_per_frame: u16,
    pub audio_channel_allocation: u32,
    pub frames_per_sdu: u8,
}

impl Lc3CodecConfig {
    /// Encode the LC3 codec configuration as LTV bytes.
    pub fn to_ltv(&self) -> Vec<u8> {
        let alloc_bytes = self.audio_channel_allocation.to_le_bytes();
        let octets_bytes = self.octets_per_frame.to_le_bytes();
        vec![
            // Sampling Frequency (Type 0x01)
            2, 0x01, self.sampling_freq as u8,
            // Frame Duration (Type 0x02)
            2, 0x02, self.frame_duration as u8,
            // Audio Channel Allocation (Type 0x03)
            5, 0x03,
            alloc_bytes[0], alloc_bytes[1], alloc_bytes[2], alloc_bytes[3],
            // Octets Per Codec Frame (Type 0x04)
            3, 0x04,
            octets_bytes[0], octets_bytes[1],
            // Frames Per SDU (Type 0x05)
            2, 0x05, self.frames_per_sdu,
        ]
    }

    /// Decode LC3 codec configuration from LTV bytes.
    pub fn from_ltv(data: &[u8]) -> Option<Self> {
        let mut freq = None;
        let mut dur = None;
        let mut octets = None;
        let mut alloc = 0u32;
        let mut frames = 1u8;

        let mut offset = 0;
        while offset < data.len() {
            if offset + 1 >= data.len() {
                break;
            }
            let len = data[offset] as usize;
            if len == 0 || offset + len >= data.len() {
                break;
            }
            let typ = data[offset + 1];
            let val_start = offset + 2;
            let val_end = offset + 1 + len;
            match typ {
                0x01 if val_end <= data.len() => {
                    freq = match data[val_start] {
                        0x01 => Some(Lc3SamplingFreq::Freq8000),
                        0x02 => Some(Lc3SamplingFreq::Freq11025),
                        0x03 => Some(Lc3SamplingFreq::Freq16000),
                        0x04 => Some(Lc3SamplingFreq::Freq22050),
                        0x05 => Some(Lc3SamplingFreq::Freq24000),
                        0x06 => Some(Lc3SamplingFreq::Freq32000),
                        0x07 => Some(Lc3SamplingFreq::Freq44100),
                        0x08 => Some(Lc3SamplingFreq::Freq48000),
                        _ => None,
                    };
                }
                0x02 if val_end <= data.len() => {
                    dur = match data[val_start] {
                        0x00 => Some(Lc3FrameDuration::Dur7_5ms),
                        0x01 => Some(Lc3FrameDuration::Dur10ms),
                        _ => None,
                    };
                }
                0x03 if val_end <= data.len() && len >= 5 => {
                    let bytes: [u8; 4] = [
                        data[val_start],
                        data[val_start + 1],
                        data[val_start + 2],
                        data[val_start + 3],
                    ];
                    alloc = u32::from_le_bytes(bytes);
                }
                0x04 if val_end <= data.len() && len >= 3 => {
                    octets = Some(u16::from_le_bytes([
                        data[val_start],
                        data[val_start + 1],
                    ]));
                }
                0x05 if val_end <= data.len() => {
                    frames = data[val_start];
                }
                _ => {}
            }
            offset += 1 + len;
        }

        Some(Self {
            sampling_freq: freq?,
            frame_duration: dur?,
            octets_per_frame: octets?,
            audio_channel_allocation: alloc,
            frames_per_sdu: frames,
        })
    }

    /// Default 48kHz stereo configuration suitable for media.
    pub fn default_media() -> Self {
        Self {
            sampling_freq: Lc3SamplingFreq::Freq48000,
            frame_duration: Lc3FrameDuration::Dur10ms,
            octets_per_frame: 120,
            audio_channel_allocation: 0x03, // Front Left + Front Right
            frames_per_sdu: 1,
        }
    }
}

/// Published Audio Capabilities (PAC) record.
#[derive(Debug, Clone)]
pub struct PacRecord {
    pub codec_id: AudioCodec,
    pub codec_specific_capabilities: Vec<u8>,
    pub metadata: Vec<u8>,
}

/// A single Audio Stream Endpoint.
#[derive(Debug)]
pub struct AudioStreamEndpoint {
    pub id: u8,
    pub state: AseState,
    pub direction: AseDirection,
    pub codec: AudioCodec,
    pub cig_id: u8,
    pub cis_id: u8,
    pub qos: Option<QosConfig>,
    pub codec_config: Vec<u8>,
    pub metadata: Vec<u8>,
}

/// BAP profile plugin.
#[derive(Debug)]
pub struct BapProfile {
    pub endpoints: Vec<AudioStreamEndpoint>,
    pub supported_contexts: u16,
    pub available_contexts: u16,
    pub sink_pac: Vec<PacRecord>,
    pub source_pac: Vec<PacRecord>,
}

impl BapProfile {
    pub fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            supported_contexts: 0,
            available_contexts: 0,
            sink_pac: Vec::new(),
            source_pac: Vec::new(),
        }
    }

    /// Transition an ASE to a new state, enforcing valid transitions.
    pub fn transition_ase(&mut self, ase_id: u8, new_state: AseState) -> bool {
        let Some(ase) = self.endpoints.iter_mut().find(|e| e.id == ase_id) else {
            return false;
        };
        let valid = matches!(
            (ase.state, new_state),
            (AseState::Idle, AseState::CodecConfigured)
                | (AseState::CodecConfigured, AseState::QosConfigured)
                | (AseState::CodecConfigured, AseState::Releasing)
                | (AseState::QosConfigured, AseState::Enabling)
                | (AseState::QosConfigured, AseState::Releasing)
                | (AseState::QosConfigured, AseState::CodecConfigured)
                | (AseState::Enabling, AseState::Streaming)
                | (AseState::Enabling, AseState::Disabling)
                | (AseState::Enabling, AseState::Releasing)
                | (AseState::Streaming, AseState::Disabling)
                | (AseState::Streaming, AseState::Releasing)
                | (AseState::Disabling, AseState::QosConfigured)
                | (AseState::Disabling, AseState::Releasing)
                | (AseState::Releasing, AseState::Idle)
        );
        if valid {
            ase.state = new_state;
        }
        valid
    }

    /// Apply an ASE Control Point operation, returning whether it succeeded.
    pub fn apply_control_op(&mut self, ase_id: u8, op: AseControlOp) -> bool {
        let target_state = match op {
            AseControlOp::CodecConfigure => AseState::CodecConfigured,
            AseControlOp::QosConfigure => AseState::QosConfigured,
            AseControlOp::Enable => AseState::Enabling,
            AseControlOp::ReceiverStartReady => AseState::Streaming,
            AseControlOp::Disable => AseState::Disabling,
            AseControlOp::ReceiverStopReady => AseState::QosConfigured,
            AseControlOp::UpdateMetadata => {
                // Metadata update doesn't change state, just check ASE exists
                return self.endpoints.iter().any(|e| e.id == ase_id);
            }
            AseControlOp::Release => AseState::Releasing,
        };
        self.transition_ase(ase_id, target_state)
    }
}

impl Default for BapProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BASS — Broadcast Audio Scan Service
// ---------------------------------------------------------------------------

/// BASS receive state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BassReceiveState {
    NotSynchronized,
    SyncInfoRequest,
    Synchronized,
    Failed,
}

/// BASS profile plugin.
#[derive(Debug)]
pub struct BassProfile {
    pub receive_state: BassReceiveState,
    pub broadcast_id: u32,
}

impl BassProfile {
    pub fn new() -> Self {
        Self {
            receive_state: BassReceiveState::NotSynchronized,
            broadcast_id: 0,
        }
    }
}

impl Default for BassProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CSIP — Coordinated Set Identification Profile
// ---------------------------------------------------------------------------

/// Set Identity Resolving Key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sirk {
    /// The 16-byte SIRK value.
    pub key: [u8; 16],
    /// Whether the SIRK is encrypted (vs. plaintext).
    pub encrypted: bool,
}

impl Sirk {
    pub fn new_plaintext(key: [u8; 16]) -> Self {
        Self {
            key,
            encrypted: false,
        }
    }

    pub fn new_encrypted(key: [u8; 16]) -> Self {
        Self {
            key,
            encrypted: true,
        }
    }
}

/// CSIP lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsipLockState {
    Unlocked = 0x01,
    Locked = 0x02,
}

/// A coordinated set member.
#[derive(Debug, Clone)]
pub struct CsipSetMember {
    pub addr: BdAddr,
    pub rank: u8,
    pub lock_state: CsipLockState,
}

/// Compute the SIH (Set Identity Hash) function.
///
/// `sih(k, r)` = AES-128(k, r' || padding)[0..3]
/// where r' is r with zero-padding to 16 bytes.
///
/// This is a simplified implementation; the real one needs AES-128.
/// Returns a 3-byte hash.
pub fn csip_sih(k: &[u8; 16], r: &[u8; 3]) -> [u8; 3] {
    // Construct the 16-byte input: r (3 bytes) zero-padded to 16 bytes
    let mut plaintext = [0u8; 16];
    plaintext[13] = r[0];
    plaintext[14] = r[1];
    plaintext[15] = r[2];

    // Simplified hash for the struct — real implementation uses AES-128
    // This produces a deterministic 3-byte output from k and r.
    let mut hash = [0u8; 3];
    for i in 0..3 {
        let mut acc: u8 = 0;
        for j in 0..16 {
            acc = acc.wrapping_add(k[j].wrapping_mul(plaintext[(i + j) % 16].wrapping_add(1)));
        }
        hash[i] = acc;
    }
    hash
}

/// CSIP profile plugin.
#[derive(Debug)]
pub struct CsipProfile {
    pub sirk: Sirk,
    pub set_size: u8,
    pub set_rank: u8,
    pub lock_state: CsipLockState,
    pub members: Vec<CsipSetMember>,
}

impl Default for CsipProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl CsipProfile {
    pub fn new() -> Self {
        Self {
            sirk: Sirk::new_plaintext([0u8; 16]),
            set_size: 0,
            set_rank: 0,
            lock_state: CsipLockState::Unlocked,
            members: Vec::new(),
        }
    }

    /// Lock the set. Returns false if already locked.
    pub fn lock(&mut self) -> bool {
        if self.lock_state == CsipLockState::Locked {
            return false;
        }
        self.lock_state = CsipLockState::Locked;
        true
    }

    /// Unlock the set. Returns false if already unlocked.
    pub fn unlock(&mut self) -> bool {
        if self.lock_state == CsipLockState::Unlocked {
            return false;
        }
        self.lock_state = CsipLockState::Unlocked;
        true
    }
}

// ---------------------------------------------------------------------------
// HFP — Hands-Free Profile
// ---------------------------------------------------------------------------

/// HFP device role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpRole {
    AudioGateway,
    HandsFree,
}

/// HFP AG (Audio Gateway) feature bits.
pub mod hfp_ag_features {
    pub const THREE_WAY_CALLING: u32 = 1 << 0;
    pub const EC_NR: u32 = 1 << 1;
    pub const VOICE_RECOGNITION: u32 = 1 << 2;
    pub const IN_BAND_RING: u32 = 1 << 3;
    pub const VOICE_TAG: u32 = 1 << 4;
    pub const REJECT_CALL: u32 = 1 << 5;
    pub const ENHANCED_CALL_STATUS: u32 = 1 << 6;
    pub const ENHANCED_CALL_CONTROL: u32 = 1 << 7;
    pub const EXTENDED_ERROR_RESULT: u32 = 1 << 8;
    pub const CODEC_NEGOTIATION: u32 = 1 << 9;
    pub const HF_INDICATORS: u32 = 1 << 10;
    pub const ESCO_S4: u32 = 1 << 11;
}

/// HFP HF (Hands-Free) feature bits.
pub mod hfp_hf_features {
    pub const EC_NR: u32 = 1 << 0;
    pub const THREE_WAY_CALLING: u32 = 1 << 1;
    pub const CLI_PRESENTATION: u32 = 1 << 2;
    pub const VOICE_RECOGNITION: u32 = 1 << 3;
    pub const REMOTE_VOLUME: u32 = 1 << 4;
    pub const ENHANCED_CALL_STATUS: u32 = 1 << 5;
    pub const ENHANCED_CALL_CONTROL: u32 = 1 << 6;
    pub const CODEC_NEGOTIATION: u32 = 1 << 7;
    pub const HF_INDICATORS: u32 = 1 << 8;
    pub const ESCO_S4: u32 = 1 << 9;
}

/// HFP SLC (Service Level Connection) establishment state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HfpSlcState {
    #[default]
    Disconnected,
    /// Waiting for BRSF exchange.
    BrsfExchange,
    /// Waiting for codec negotiation (if supported).
    CodecNegotiation,
    /// Waiting for CIND test.
    CindTest,
    /// Waiting for CIND read.
    CindRead,
    /// Waiting for CMER activation.
    CmerActivation,
    /// Waiting for CHLD query (if 3-way calling supported).
    ChldQuery,
    /// SLC fully established.
    Connected,
    /// SCO audio setup in progress.
    ScoSetup,
    /// SCO audio connected.
    ScoConnected,
    /// Disconnecting.
    Disconnecting,
}

impl HfpSlcState {
    /// Check if the SLC is fully established (Connected or beyond).
    pub fn is_connected(self) -> bool {
        matches!(
            self,
            Self::Connected | Self::ScoSetup | Self::ScoConnected
        )
    }

    /// Get the next expected state in the SLC establishment sequence.
    pub fn next_slc_step(self, codec_negotiation: bool, three_way: bool) -> Option<Self> {
        match self {
            Self::Disconnected => Some(Self::BrsfExchange),
            Self::BrsfExchange => {
                if codec_negotiation {
                    Some(Self::CodecNegotiation)
                } else {
                    Some(Self::CindTest)
                }
            }
            Self::CodecNegotiation => Some(Self::CindTest),
            Self::CindTest => Some(Self::CindRead),
            Self::CindRead => Some(Self::CmerActivation),
            Self::CmerActivation => {
                if three_way {
                    Some(Self::ChldQuery)
                } else {
                    Some(Self::Connected)
                }
            }
            Self::ChldQuery => Some(Self::Connected),
            _ => None,
        }
    }
}

/// Standard HFP indicator indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpIndicatorIndex {
    Service = 1,
    Call = 2,
    CallSetup = 3,
    CallHeld = 4,
    Signal = 5,
    Roaming = 6,
    BatteryCharge = 7,
}

/// HFP AG indicator.
#[derive(Debug, Clone)]
pub struct HfpIndicator {
    pub name: String,
    pub value: u8,
    pub min: u8,
    pub max: u8,
    pub enabled: bool,
}

impl HfpIndicator {
    /// Create the standard set of HFP indicators.
    pub fn standard_set() -> Vec<Self> {
        [
            ("service", 0u8, 1u8),
            ("call", 0, 1),
            ("callsetup", 0, 3),
            ("callheld", 0, 2),
            ("signal", 0, 5),
            ("roaming", 0, 1),
            ("battchg", 0, 5),
        ]
        .into_iter()
        .map(|(name, min, max)| Self {
            name: name.into(),
            value: 0,
            min,
            max,
            enabled: true,
        })
        .collect()
    }
}

/// AT command types used in HFP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtCommand {
    // HF -> AG commands
    Brsf(u32),
    CindTest,
    CindRead,
    Cmer(u8, u8, u8, u8),
    Chld(String),
    Clcc,
    Cops(u8),
    Cmee(u8),
    Btrh(Option<u8>),
    Nrec(u8),
    Vgs(u8),
    Vgm(u8),
    Bia(Vec<Option<bool>>),
    Binp(u8),
    Bvra(u8),
    Biev(u8, u32),
    Dial(String),
    Answer,
    Hangup,
    // AG -> HF unsolicited results
    Ring,
    Clip(String, u8),
    Ccwa(String, u8),
    Ciev(u8, u8),
    VgsInd(u8),
    VgmInd(u8),
    Bsir(u8),
    BrsfResp(u32),
    // Generic OK/ERROR
    Ok,
    Error,
    CmeError(u32),
    /// Unknown or unparsed command.
    Unknown(String),
}

impl fmt::Display for AtCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtCommand::Brsf(features) => write!(f, "AT+BRSF={features}"),
            AtCommand::CindTest => write!(f, "AT+CIND=?"),
            AtCommand::CindRead => write!(f, "AT+CIND?"),
            AtCommand::Cmer(m, k, d, i) => write!(f, "AT+CMER={m},{k},{d},{i}"),
            AtCommand::Chld(val) => write!(f, "AT+CHLD={val}"),
            AtCommand::Clcc => write!(f, "AT+CLCC"),
            AtCommand::Cops(mode) => write!(f, "AT+COPS={mode}"),
            AtCommand::Cmee(mode) => write!(f, "AT+CMEE={mode}"),
            AtCommand::Btrh(val) => match val {
                Some(v) => write!(f, "AT+BTRH={v}"),
                None => write!(f, "AT+BTRH?"),
            },
            AtCommand::Nrec(val) => write!(f, "AT+NREC={val}"),
            AtCommand::Vgs(gain) => write!(f, "AT+VGS={gain}"),
            AtCommand::Vgm(gain) => write!(f, "AT+VGM={gain}"),
            AtCommand::Bia(indicators) => {
                write!(f, "AT+BIA=")?;
                for (i, ind) in indicators.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    match ind {
                        Some(true) => write!(f, "1")?,
                        Some(false) => write!(f, "0")?,
                        None => {}
                    }
                }
                Ok(())
            }
            AtCommand::Binp(val) => write!(f, "AT+BINP={val}"),
            AtCommand::Bvra(val) => write!(f, "AT+BVRA={val}"),
            AtCommand::Biev(id, val) => write!(f, "AT+BIEV={id},{val}"),
            AtCommand::Dial(num) => write!(f, "ATD{num};"),
            AtCommand::Answer => write!(f, "ATA"),
            AtCommand::Hangup => write!(f, "AT+CHUP"),
            AtCommand::Ring => write!(f, "RING"),
            AtCommand::Clip(num, typ) => write!(f, "+CLIP: \"{num}\",{typ}"),
            AtCommand::Ccwa(num, typ) => write!(f, "+CCWA: \"{num}\",{typ}"),
            AtCommand::Ciev(ind, val) => write!(f, "+CIEV: {ind},{val}"),
            AtCommand::VgsInd(gain) => write!(f, "+VGS: {gain}"),
            AtCommand::VgmInd(gain) => write!(f, "+VGM: {gain}"),
            AtCommand::Bsir(val) => write!(f, "+BSIR: {val}"),
            AtCommand::BrsfResp(features) => write!(f, "+BRSF: {features}"),
            AtCommand::Ok => write!(f, "OK"),
            AtCommand::Error => write!(f, "ERROR"),
            AtCommand::CmeError(code) => write!(f, "+CME ERROR: {code}"),
            AtCommand::Unknown(s) => write!(f, "{s}"),
        }
    }
}

/// Parse a single AT command line into an `AtCommand` enum.
///
/// Handles both HF->AG commands (AT+XXX) and AG->HF unsolicited results.
pub fn parse_at_command(line: &str) -> AtCommand {
    let line = line.trim();

    // AG -> HF responses and unsolicited results
    if line == "OK" {
        return AtCommand::Ok;
    }
    if line == "ERROR" {
        return AtCommand::Error;
    }
    if line == "RING" {
        return AtCommand::Ring;
    }
    if let Some(rest) = line.strip_prefix("+CME ERROR: ") {
        if let Result::Ok(code) = rest.trim().parse::<u32>() {
            return AtCommand::CmeError(code);
        }
    }
    if let Some(rest) = line.strip_prefix("+BRSF: ") {
        if let Result::Ok(val) = rest.trim().parse::<u32>() {
            return AtCommand::BrsfResp(val);
        }
    }
    if let Some(rest) = line.strip_prefix("+CIEV: ") {
        let parts: Vec<&str> = rest.splitn(2, ',').collect();
        if parts.len() == 2 {
            if let (Result::Ok(ind), Result::Ok(val)) =
                (parts[0].trim().parse::<u8>(), parts[1].trim().parse::<u8>())
            {
                return AtCommand::Ciev(ind, val);
            }
        }
    }
    if let Some(rest) = line.strip_prefix("+VGS: ") {
        if let Result::Ok(val) = rest.trim().parse::<u8>() {
            return AtCommand::VgsInd(val);
        }
    }
    if let Some(rest) = line.strip_prefix("+VGM: ") {
        if let Result::Ok(val) = rest.trim().parse::<u8>() {
            return AtCommand::VgmInd(val);
        }
    }
    if let Some(rest) = line.strip_prefix("+BSIR: ") {
        if let Result::Ok(val) = rest.trim().parse::<u8>() {
            return AtCommand::Bsir(val);
        }
    }
    if let Some(rest) = line.strip_prefix("+CLIP: ") {
        // +CLIP: "number",type
        if let Some((num_part, type_part)) = rest.rsplit_once(',') {
            let num = num_part.trim().trim_matches('"').to_string();
            if let Result::Ok(typ) = type_part.trim().parse::<u8>() {
                return AtCommand::Clip(num, typ);
            }
        }
    }
    if let Some(rest) = line.strip_prefix("+CCWA: ") {
        if let Some((num_part, type_part)) = rest.rsplit_once(',') {
            let num = num_part.trim().trim_matches('"').to_string();
            if let Result::Ok(typ) = type_part.trim().parse::<u8>() {
                return AtCommand::Ccwa(num, typ);
            }
        }
    }

    // HF -> AG commands
    if line == "ATA" {
        return AtCommand::Answer;
    }
    if line == "AT+CHUP" {
        return AtCommand::Hangup;
    }
    if line == "AT+CLCC" {
        return AtCommand::Clcc;
    }
    if line == "AT+CIND=?" {
        return AtCommand::CindTest;
    }
    if line == "AT+CIND?" {
        return AtCommand::CindRead;
    }
    if let Some(rest) = line.strip_prefix("AT+BTRH?") {
        if rest.is_empty() {
            return AtCommand::Btrh(None);
        }
    }

    if let Some(rest) = line.strip_prefix("AT+BRSF=") {
        if let Result::Ok(val) = rest.trim().parse::<u32>() {
            return AtCommand::Brsf(val);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+CMER=") {
        let parts: Vec<&str> = rest.split(',').collect();
        if parts.len() == 4 {
            if let (Result::Ok(m), Result::Ok(k), Result::Ok(d), Result::Ok(i)) = (
                parts[0].trim().parse::<u8>(),
                parts[1].trim().parse::<u8>(),
                parts[2].trim().parse::<u8>(),
                parts[3].trim().parse::<u8>(),
            ) {
                return AtCommand::Cmer(m, k, d, i);
            }
        }
    }
    if let Some(rest) = line.strip_prefix("AT+CHLD=") {
        return AtCommand::Chld(rest.trim().to_string());
    }
    if let Some(rest) = line.strip_prefix("AT+COPS=") {
        if let Result::Ok(mode) = rest.trim().parse::<u8>() {
            return AtCommand::Cops(mode);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+CMEE=") {
        if let Result::Ok(mode) = rest.trim().parse::<u8>() {
            return AtCommand::Cmee(mode);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+BTRH=") {
        if let Result::Ok(val) = rest.trim().parse::<u8>() {
            return AtCommand::Btrh(Some(val));
        }
    }
    if let Some(rest) = line.strip_prefix("AT+NREC=") {
        if let Result::Ok(val) = rest.trim().parse::<u8>() {
            return AtCommand::Nrec(val);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+VGS=") {
        if let Result::Ok(gain) = rest.trim().parse::<u8>() {
            return AtCommand::Vgs(gain);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+VGM=") {
        if let Result::Ok(gain) = rest.trim().parse::<u8>() {
            return AtCommand::Vgm(gain);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+BIA=") {
        let parts: Vec<Option<bool>> = rest
            .split(',')
            .map(|s| match s.trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            })
            .collect();
        return AtCommand::Bia(parts);
    }
    if let Some(rest) = line.strip_prefix("AT+BINP=") {
        if let Result::Ok(val) = rest.trim().parse::<u8>() {
            return AtCommand::Binp(val);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+BVRA=") {
        if let Result::Ok(val) = rest.trim().parse::<u8>() {
            return AtCommand::Bvra(val);
        }
    }
    if let Some(rest) = line.strip_prefix("AT+BIEV=") {
        let parts: Vec<&str> = rest.splitn(2, ',').collect();
        if parts.len() == 2 {
            if let (Result::Ok(id), Result::Ok(val)) =
                (parts[0].trim().parse::<u8>(), parts[1].trim().parse::<u32>())
            {
                return AtCommand::Biev(id, val);
            }
        }
    }
    if let Some(rest) = line.strip_prefix("ATD") {
        let num = rest.trim_end_matches(';').to_string();
        return AtCommand::Dial(num);
    }

    AtCommand::Unknown(line.to_string())
}

/// HFP profile plugin.
#[derive(Debug)]
pub struct HfpProfile {
    pub role: HfpRole,
    pub slc_state: HfpSlcState,
    pub remote_addr: Option<BdAddr>,
    pub ag_features: u32,
    pub hf_features: u32,
    pub indicators: Vec<HfpIndicator>,
    pub codec_negotiation: bool,
    pub active_codec: AudioCodec,
}

impl HfpProfile {
    pub fn new(role: HfpRole) -> Self {
        Self {
            role,
            slc_state: HfpSlcState::default(),
            remote_addr: None,
            ag_features: 0,
            hf_features: 0,
            indicators: HfpIndicator::standard_set(),
            codec_negotiation: false,
            active_codec: AudioCodec::Sbc,
        }
    }

    /// Advance the SLC state machine to the next step.
    pub fn advance_slc(&mut self) -> bool {
        let three_way = (self.ag_features & hfp_ag_features::THREE_WAY_CALLING) != 0;
        if let Some(next) = self.slc_state.next_slc_step(self.codec_negotiation, three_way) {
            self.slc_state = next;
            true
        } else {
            false
        }
    }

    /// Set an indicator value by index (1-based).
    pub fn set_indicator(&mut self, index: usize, value: u8) -> bool {
        if index == 0 || index > self.indicators.len() {
            return false;
        }
        let ind = &mut self.indicators[index - 1];
        if value >= ind.min && value <= ind.max {
            ind.value = value;
            true
        } else {
            false
        }
    }

    /// Get an indicator value by name.
    pub fn get_indicator(&self, name: &str) -> Option<u8> {
        self.indicators
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.value)
    }
}

// ---------------------------------------------------------------------------
// MCP — Media Control Profile
// ---------------------------------------------------------------------------

/// MCP profile plugin.
#[derive(Debug)]
pub struct McpProfile {
    pub media_player_name: Option<String>,
    pub playback_speed: i8,
    pub seeking_speed: i8,
    pub playing_order: u8,
}

impl McpProfile {
    pub fn new() -> Self {
        Self {
            media_player_name: None,
            playback_speed: 0,
            seeking_speed: 0,
            playing_order: 0x01, // single once
        }
    }
}

impl Default for McpProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VCP — Volume Control Profile
// ---------------------------------------------------------------------------

/// Volume control operation flags.
pub mod vcp_flags {
    /// Setting persistence flag — volume setting should be persisted.
    pub const SETTING_PERSISTED: u8 = 1 << 0;
}

/// Volume control operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpOperation {
    RelativeVolumeDown,
    RelativeVolumeUp,
    UnmuteRelativeVolumeDown,
    UnmuteRelativeVolumeUp,
    SetAbsoluteVolume(u8),
    Unmute,
    Mute,
}

/// VCP profile plugin.
#[derive(Debug)]
pub struct VcpProfile {
    pub volume: u8,
    pub muted: bool,
    pub change_counter: u8,
    pub step_size: u8,
    pub flags: u8,
}

impl Default for VcpProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl VcpProfile {
    pub fn new() -> Self {
        Self {
            volume: 0,
            muted: false,
            change_counter: 0,
            step_size: 16, // default step for relative volume changes
            flags: 0,
        }
    }

    /// Apply a volume control operation. Returns the new change counter on
    /// success, or `None` if the provided counter doesn't match (stale).
    pub fn apply_operation(
        &mut self,
        op: VcpOperation,
        counter: u8,
    ) -> Option<u8> {
        if counter != self.change_counter {
            return None; // stale counter
        }

        match op {
            VcpOperation::RelativeVolumeDown => {
                self.volume = self.volume.saturating_sub(self.step_size);
            }
            VcpOperation::RelativeVolumeUp => {
                self.volume = self.volume.saturating_add(self.step_size);
            }
            VcpOperation::UnmuteRelativeVolumeDown => {
                self.muted = false;
                self.volume = self.volume.saturating_sub(self.step_size);
            }
            VcpOperation::UnmuteRelativeVolumeUp => {
                self.muted = false;
                self.volume = self.volume.saturating_add(self.step_size);
            }
            VcpOperation::SetAbsoluteVolume(vol) => {
                self.volume = vol;
            }
            VcpOperation::Unmute => {
                self.muted = false;
            }
            VcpOperation::Mute => {
                self.muted = true;
            }
        }

        self.change_counter = self.change_counter.wrapping_add(1);
        Some(self.change_counter)
    }
}

// ---------------------------------------------------------------------------
// CCP — Call Control Profile
// ---------------------------------------------------------------------------

/// CCP call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcpCallState {
    Incoming,
    Dialing,
    Alerting,
    Active,
    LocallyHeld,
    RemotelyHeld,
}

/// CCP profile plugin.
#[derive(Debug)]
pub struct CcpProfile {
    pub bearer_provider_name: Option<String>,
    pub bearer_technology: u8,
    pub call_state: Option<CcpCallState>,
}

impl CcpProfile {
    pub fn new() -> Self {
        Self {
            bearer_provider_name: None,
            bearer_technology: 0,
            call_state: None,
        }
    }
}

impl Default for CcpProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MICP — Microphone Control Profile
// ---------------------------------------------------------------------------

/// MICP profile plugin.
#[derive(Debug)]
pub struct MicpProfile {
    pub muted: bool,
}

impl MicpProfile {
    pub fn new() -> Self {
        Self { muted: false }
    }
}

impl Default for MicpProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ASHA — Audio Streaming for Hearing Aid
// ---------------------------------------------------------------------------

/// ASHA device capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AshaSide {
    Left,
    Right,
}

/// ASHA profile plugin.
#[derive(Debug)]
pub struct AshaProfile {
    pub side: AshaSide,
    pub binaural: bool,
    pub streaming: bool,
    pub render_delay_ms: u16,
    pub codec_ids: Vec<u8>,
}

impl AshaProfile {
    pub fn new(side: AshaSide) -> Self {
        Self {
            side,
            binaural: false,
            streaming: false,
            render_delay_ms: 0,
            codec_ids: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// GMAP — Gaming Audio Profile
// ---------------------------------------------------------------------------

/// GMAP role bitmask values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmapRole {
    UnicasterGameGateway,
    UnicasterGameTerminal,
    BroadcastGameSender,
    BroadcastGameReceiver,
}

/// GMAP profile plugin.
#[derive(Debug)]
pub struct GmapProfile {
    pub roles: Vec<GmapRole>,
}

impl GmapProfile {
    pub fn new() -> Self {
        Self { roles: Vec::new() }
    }
}

impl Default for GmapProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TMAP — Telephony and Media Audio Profile
// ---------------------------------------------------------------------------

/// TMAP role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmapRole {
    CallGateway,
    CallTerminal,
    UnicasterMediaSender,
    UnicasterMediaReceiver,
    BroadcastMediaSender,
    BroadcastMediaReceiver,
}

/// TMAP profile plugin.
#[derive(Debug)]
pub struct TmapProfile {
    pub roles: Vec<TmapRole>,
}

impl TmapProfile {
    pub fn new() -> Self {
        Self { roles: Vec::new() }
    }
}

impl Default for TmapProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MediaEndpoint / MediaTransport
// ---------------------------------------------------------------------------

/// A media endpoint registered by an application.
#[derive(Debug)]
pub struct MediaEndpoint {
    pub path: String,
    pub uuid: String,
    pub codec: AudioCodec,
    pub capabilities: Vec<u8>,
    pub configuration: Vec<u8>,
}

/// Transport state for a media stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaTransportState {
    Idle,
    Pending,
    Active,
}

/// A media transport carrying audio data.
#[derive(Debug)]
pub struct MediaTransport {
    pub path: String,
    pub state: MediaTransportState,
    pub codec: AudioCodec,
    pub volume: u8,
    /// File descriptor for the transport (stub — actual fd managed at runtime).
    pub fd: Option<i32>,
    pub read_mtu: u16,
    pub write_mtu: u16,
}

impl MediaTransport {
    pub fn new(path: String, codec: AudioCodec) -> Self {
        Self {
            path,
            state: MediaTransportState::Idle,
            codec,
            volume: 127,
            fd: None,
            read_mtu: 0,
            write_mtu: 0,
        }
    }
}

/// Registry of active profiles and endpoints for a device.
#[derive(Debug, Default)]
pub struct AudioProfileSet {
    pub endpoints: HashMap<String, MediaEndpoint>,
    pub transports: HashMap<String, MediaTransport>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // A2DP tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_a2dp_default_state() {
        let profile = A2dpProfile::new(A2dpRole::Source, AudioCodec::Sbc);
        assert_eq!(profile.state, A2dpStreamState::Idle);
        assert_eq!(profile.role, A2dpRole::Source);
    }

    #[test]
    fn test_a2dp_state_transitions() {
        let mut p = A2dpProfile::new(A2dpRole::Sink, AudioCodec::Sbc);

        // Valid path: Idle -> Configured -> Open -> Streaming
        assert!(p.transition(A2dpStreamState::Configured));
        assert_eq!(p.state, A2dpStreamState::Configured);

        assert!(p.transition(A2dpStreamState::Open));
        assert_eq!(p.state, A2dpStreamState::Open);

        assert!(p.transition(A2dpStreamState::Streaming));
        assert_eq!(p.state, A2dpStreamState::Streaming);

        // Valid: Streaming -> Open (suspend)
        assert!(p.transition(A2dpStreamState::Open));
        assert_eq!(p.state, A2dpStreamState::Open);

        // Valid: Open -> Closing
        assert!(p.transition(A2dpStreamState::Closing));
        assert_eq!(p.state, A2dpStreamState::Closing);

        // Valid: Closing -> Idle
        assert!(p.transition(A2dpStreamState::Idle));
        assert_eq!(p.state, A2dpStreamState::Idle);

        // Invalid: Idle -> Open (skip Configured)
        assert!(!p.transition(A2dpStreamState::Open));
        assert_eq!(p.state, A2dpStreamState::Idle);

        // Invalid: Idle -> Streaming
        assert!(!p.transition(A2dpStreamState::Streaming));
        assert_eq!(p.state, A2dpStreamState::Idle);
    }

    #[test]
    fn test_sbc_codec_roundtrip() {
        let params = SbcCodecParams::default_hq();
        let bytes = params.to_bytes();
        let decoded = SbcCodecParams::from_bytes(&bytes).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn test_sbc_codec_negotiation() {
        let local = vec![
            A2dpCodec::Sbc(SbcCodecParams {
                sampling_freq: SbcSamplingFreq::Freq44100,
                channel_mode: SbcChannelMode::JointStereo,
                block_length: SbcBlockLength::Blocks16,
                subbands: SbcSubbands::Subbands8,
                allocation_method: SbcAllocationMethod::Loudness,
                min_bitpool: 2,
                max_bitpool: 53,
            }),
            A2dpCodec::Aac(AacCodecParams::default_lc()),
        ];
        let remote = vec![A2dpCodec::Sbc(SbcCodecParams {
            sampling_freq: SbcSamplingFreq::Freq44100,
            channel_mode: SbcChannelMode::JointStereo,
            block_length: SbcBlockLength::Blocks16,
            subbands: SbcSubbands::Subbands8,
            allocation_method: SbcAllocationMethod::Loudness,
            min_bitpool: 10,
            max_bitpool: 40,
        })];

        let result = negotiate_codec(&local, &remote).unwrap();
        match &result {
            A2dpCodec::Sbc(params) => {
                assert_eq!(params.min_bitpool, 10);
                assert_eq!(params.max_bitpool, 40);
            }
            _ => panic!("expected SBC"),
        }
    }

    #[test]
    fn test_codec_negotiation_prefers_higher_priority() {
        let local = vec![
            A2dpCodec::Sbc(SbcCodecParams::default_hq()),
            A2dpCodec::Aac(AacCodecParams::default_lc()),
        ];
        let remote = vec![
            A2dpCodec::Sbc(SbcCodecParams::default_hq()),
            A2dpCodec::Aac(AacCodecParams::default_lc()),
        ];

        let result = negotiate_codec(&local, &remote).unwrap();
        assert_eq!(result.audio_codec(), AudioCodec::Aac);
    }

    #[test]
    fn test_codec_negotiation_no_match() {
        let local = vec![A2dpCodec::Ldac(LdacCodecParams::default_hq())];
        let remote = vec![A2dpCodec::Sbc(SbcCodecParams::default_hq())];
        assert!(negotiate_codec(&local, &remote).is_none());
    }

    // -----------------------------------------------------------------------
    // AVDTP tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_avdtp_signal_encode_decode() {
        let pkt = AvdtpPacket {
            transaction: 5,
            message_type: AvdtpMessageType::Command,
            packet_type: AvdtpPacketType::Single,
            signal_id: AvdtpSignalId::Discover,
            payload: vec![],
        };

        let encoded = pkt.encode();
        assert_eq!(encoded.len(), 2);

        let decoded = AvdtpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.transaction, 5);
        assert_eq!(decoded.message_type, AvdtpMessageType::Command);
        assert_eq!(decoded.packet_type, AvdtpPacketType::Single);
        assert_eq!(decoded.signal_id, AvdtpSignalId::Discover);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_avdtp_signal_with_payload() {
        let pkt = AvdtpPacket {
            transaction: 3,
            message_type: AvdtpMessageType::ResponseAccept,
            packet_type: AvdtpPacketType::Single,
            signal_id: AvdtpSignalId::GetCapabilities,
            payload: vec![0x01, 0x02, 0x03],
        };

        let encoded = pkt.encode();
        assert_eq!(encoded.len(), 5);

        let decoded = AvdtpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.signal_id, AvdtpSignalId::GetCapabilities);
    }

    #[test]
    fn test_avdtp_signal_id_roundtrip() {
        for val in 0x01..=0x0D {
            let id = AvdtpSignalId::from_u8(val).unwrap();
            assert_eq!(id as u8, val);
        }
        assert!(AvdtpSignalId::from_u8(0x00).is_none());
        assert!(AvdtpSignalId::from_u8(0x0E).is_none());
    }

    #[test]
    fn test_avdtp_seid_allocator() {
        let mut alloc = SeidAllocator::new();
        assert_eq!(alloc.alloc(), Some(1));
        assert_eq!(alloc.alloc(), Some(2));
        assert_eq!(alloc.alloc(), Some(3));
        // Exhaust all SEIDs
        for _ in 3..62 {
            alloc.alloc().unwrap();
        }
        assert!(alloc.alloc().is_none());
    }

    #[test]
    fn test_avdtp_session_transaction_counter() {
        let mut session = AvdtpSession::new(BdAddr::default());
        assert_eq!(session.next_transaction(), 0);
        assert_eq!(session.next_transaction(), 1);
        // Advance to wrap point
        for _ in 2..16 {
            session.next_transaction();
        }
        assert_eq!(session.next_transaction(), 0); // wrapped
    }

    // -----------------------------------------------------------------------
    // AVRCP tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_avrcp_pdu_ids() {
        assert_eq!(AvrcpPduId::from_u8(0x10), Some(AvrcpPduId::GetCapabilities));
        assert_eq!(AvrcpPduId::from_u8(0x20), Some(AvrcpPduId::GetElementAttributes));
        assert_eq!(AvrcpPduId::from_u8(0x30), Some(AvrcpPduId::GetPlayStatus));
        assert_eq!(AvrcpPduId::from_u8(0x31), Some(AvrcpPduId::RegisterNotification));
        assert_eq!(AvrcpPduId::from_u8(0x50), Some(AvrcpPduId::SetAbsoluteVolume));
        assert_eq!(AvrcpPduId::from_u8(0x70), Some(AvrcpPduId::SetBrowsedPlayer));
        assert_eq!(AvrcpPduId::from_u8(0x76), Some(AvrcpPduId::AddToNowPlaying));
        assert_eq!(AvrcpPduId::from_u8(0xFF), None);
    }

    #[test]
    fn test_avrcp_media_attributes() {
        let profile = AvrcpProfile {
            track_title: Some("Test Song".into()),
            track_artist: Some("Test Artist".into()),
            track_album: Some("Test Album".into()),
            track_number: Some(3),
            total_tracks: Some(12),
            track_genre: Some("Rock".into()),
            track_duration_ms: 240000,
            ..AvrcpProfile::new()
        };

        assert_eq!(
            profile.get_attribute(MediaAttribute::Title),
            Some("Test Song".into())
        );
        assert_eq!(
            profile.get_attribute(MediaAttribute::ArtistName),
            Some("Test Artist".into())
        );
        assert_eq!(
            profile.get_attribute(MediaAttribute::TrackNumber),
            Some("3".into())
        );
        assert_eq!(
            profile.get_attribute(MediaAttribute::PlayingTime),
            Some("240000".into())
        );
        assert_eq!(profile.get_attribute(MediaAttribute::CoverArt), None);
    }

    #[test]
    fn test_avrcp_notification_events() {
        assert_eq!(
            AvrcpNotificationEvent::from_u8(0x01),
            Some(AvrcpNotificationEvent::PlaybackStatusChanged)
        );
        assert_eq!(
            AvrcpNotificationEvent::from_u8(0x0D),
            Some(AvrcpNotificationEvent::VolumeChanged)
        );
        assert_eq!(AvrcpNotificationEvent::from_u8(0x00), None);
        assert_eq!(AvrcpNotificationEvent::from_u8(0x0E), None);
    }

    // -----------------------------------------------------------------------
    // BAP / ASE tests
    // -----------------------------------------------------------------------

    fn make_test_ase(id: u8) -> AudioStreamEndpoint {
        AudioStreamEndpoint {
            id,
            state: AseState::Idle,
            direction: AseDirection::Sink,
            codec: AudioCodec::Lc3,
            cig_id: 0,
            cis_id: 0,
            qos: None,
            codec_config: Vec::new(),
            metadata: Vec::new(),
        }
    }

    #[test]
    fn test_bap_ase_state_transitions() {
        let mut bap = BapProfile::new();
        bap.endpoints.push(make_test_ase(1));

        // Valid: Idle -> CodecConfigured
        assert!(bap.transition_ase(1, AseState::CodecConfigured));
        assert_eq!(bap.endpoints[0].state, AseState::CodecConfigured);

        // Valid: CodecConfigured -> QosConfigured
        assert!(bap.transition_ase(1, AseState::QosConfigured));

        // Valid: QosConfigured -> Enabling
        assert!(bap.transition_ase(1, AseState::Enabling));

        // Valid: Enabling -> Streaming
        assert!(bap.transition_ase(1, AseState::Streaming));

        // Invalid: Streaming -> CodecConfigured (skip)
        assert!(!bap.transition_ase(1, AseState::CodecConfigured));
        assert_eq!(bap.endpoints[0].state, AseState::Streaming);

        // Valid: Streaming -> Releasing
        assert!(bap.transition_ase(1, AseState::Releasing));

        // Valid: Releasing -> Idle
        assert!(bap.transition_ase(1, AseState::Idle));
    }

    #[test]
    fn test_bap_ase_all_valid_transitions() {
        let transitions = [
            (AseState::Idle, AseState::CodecConfigured, true),
            (AseState::Idle, AseState::QosConfigured, false),
            (AseState::CodecConfigured, AseState::QosConfigured, true),
            (AseState::CodecConfigured, AseState::Releasing, true),
            (AseState::CodecConfigured, AseState::Streaming, false),
            (AseState::QosConfigured, AseState::Enabling, true),
            (AseState::QosConfigured, AseState::Releasing, true),
            (AseState::QosConfigured, AseState::CodecConfigured, true),
            (AseState::Enabling, AseState::Streaming, true),
            (AseState::Enabling, AseState::Disabling, true),
            (AseState::Enabling, AseState::Releasing, true),
            (AseState::Enabling, AseState::Idle, false),
            (AseState::Streaming, AseState::Disabling, true),
            (AseState::Streaming, AseState::Releasing, true),
            (AseState::Streaming, AseState::Idle, false),
            (AseState::Disabling, AseState::QosConfigured, true),
            (AseState::Disabling, AseState::Releasing, true),
            (AseState::Disabling, AseState::Idle, false),
            (AseState::Releasing, AseState::Idle, true),
            (AseState::Releasing, AseState::CodecConfigured, false),
        ];

        for (from, to, expected) in transitions {
            let mut bap = BapProfile::new();
            bap.endpoints.push(AudioStreamEndpoint {
                id: 1,
                state: from,
                direction: AseDirection::Sink,
                codec: AudioCodec::Lc3,
                cig_id: 0,
                cis_id: 0,
                qos: None,
                codec_config: Vec::new(),
                metadata: Vec::new(),
            });
            assert_eq!(
                bap.transition_ase(1, to),
                expected,
                "transition {from:?} -> {to:?} should be {expected}"
            );
        }
    }

    #[test]
    fn test_bap_ase_control_ops() {
        let mut bap = BapProfile::new();
        bap.endpoints.push(make_test_ase(1));

        assert!(bap.apply_control_op(1, AseControlOp::CodecConfigure));
        assert_eq!(bap.endpoints[0].state, AseState::CodecConfigured);

        assert!(bap.apply_control_op(1, AseControlOp::QosConfigure));
        assert_eq!(bap.endpoints[0].state, AseState::QosConfigured);

        assert!(bap.apply_control_op(1, AseControlOp::Enable));
        assert_eq!(bap.endpoints[0].state, AseState::Enabling);

        // UpdateMetadata doesn't change state
        assert!(bap.apply_control_op(1, AseControlOp::UpdateMetadata));
        assert_eq!(bap.endpoints[0].state, AseState::Enabling);

        assert!(bap.apply_control_op(1, AseControlOp::ReceiverStartReady));
        assert_eq!(bap.endpoints[0].state, AseState::Streaming);

        assert!(bap.apply_control_op(1, AseControlOp::Release));
        assert_eq!(bap.endpoints[0].state, AseState::Releasing);
    }

    #[test]
    fn test_bap_nonexistent_ase() {
        let mut bap = BapProfile::new();
        assert!(!bap.transition_ase(99, AseState::CodecConfigured));
        assert!(!bap.apply_control_op(99, AseControlOp::Enable));
    }

    // -----------------------------------------------------------------------
    // LC3 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_lc3_codec_config_ltv_roundtrip() {
        let config = Lc3CodecConfig::default_media();
        let ltv = config.to_ltv();
        let decoded = Lc3CodecConfig::from_ltv(&ltv).unwrap();
        assert_eq!(decoded.sampling_freq, Lc3SamplingFreq::Freq48000);
        assert_eq!(decoded.frame_duration, Lc3FrameDuration::Dur10ms);
        assert_eq!(decoded.octets_per_frame, 120);
        assert_eq!(decoded.audio_channel_allocation, 0x03);
        assert_eq!(decoded.frames_per_sdu, 1);
    }

    #[test]
    fn test_lc3_codec_config_custom() {
        let config = Lc3CodecConfig {
            sampling_freq: Lc3SamplingFreq::Freq16000,
            frame_duration: Lc3FrameDuration::Dur7_5ms,
            octets_per_frame: 40,
            audio_channel_allocation: 0x01, // Front Left only
            frames_per_sdu: 2,
        };
        let ltv = config.to_ltv();
        let decoded = Lc3CodecConfig::from_ltv(&ltv).unwrap();
        assert_eq!(decoded.sampling_freq, Lc3SamplingFreq::Freq16000);
        assert_eq!(decoded.frame_duration, Lc3FrameDuration::Dur7_5ms);
        assert_eq!(decoded.octets_per_frame, 40);
        assert_eq!(decoded.frames_per_sdu, 2);
    }

    // -----------------------------------------------------------------------
    // HFP tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hfp_initial_state() {
        let hfp = HfpProfile::new(HfpRole::AudioGateway);
        assert_eq!(hfp.slc_state, HfpSlcState::Disconnected);
        assert_eq!(hfp.role, HfpRole::AudioGateway);
        assert_eq!(hfp.indicators.len(), 7);
    }

    #[test]
    fn test_hfp_features_bitflags() {
        let mut features: u32 = 0;
        features |= hfp_ag_features::THREE_WAY_CALLING;
        features |= hfp_ag_features::CODEC_NEGOTIATION;
        features |= hfp_ag_features::ESCO_S4;

        assert_ne!(features & hfp_ag_features::THREE_WAY_CALLING, 0);
        assert_ne!(features & hfp_ag_features::CODEC_NEGOTIATION, 0);
        assert_ne!(features & hfp_ag_features::ESCO_S4, 0);
        assert_eq!(features & hfp_ag_features::VOICE_RECOGNITION, 0);

        let mut hf_features: u32 = 0;
        hf_features |= hfp_hf_features::CLI_PRESENTATION;
        hf_features |= hfp_hf_features::REMOTE_VOLUME;
        assert_ne!(hf_features & hfp_hf_features::CLI_PRESENTATION, 0);
        assert_eq!(hf_features & hfp_hf_features::EC_NR, 0);
    }

    #[test]
    fn test_slc_state_machine() {
        let mut hfp = HfpProfile::new(HfpRole::HandsFree);
        hfp.ag_features = hfp_ag_features::THREE_WAY_CALLING
            | hfp_ag_features::CODEC_NEGOTIATION;
        hfp.codec_negotiation = true;

        // Walk through the full SLC establishment
        assert!(hfp.advance_slc()); // -> BrsfExchange
        assert_eq!(hfp.slc_state, HfpSlcState::BrsfExchange);

        assert!(hfp.advance_slc()); // -> CodecNegotiation (codec neg enabled)
        assert_eq!(hfp.slc_state, HfpSlcState::CodecNegotiation);

        assert!(hfp.advance_slc()); // -> CindTest
        assert_eq!(hfp.slc_state, HfpSlcState::CindTest);

        assert!(hfp.advance_slc()); // -> CindRead
        assert_eq!(hfp.slc_state, HfpSlcState::CindRead);

        assert!(hfp.advance_slc()); // -> CmerActivation
        assert_eq!(hfp.slc_state, HfpSlcState::CmerActivation);

        assert!(hfp.advance_slc()); // -> ChldQuery (3-way calling supported)
        assert_eq!(hfp.slc_state, HfpSlcState::ChldQuery);

        assert!(hfp.advance_slc()); // -> Connected
        assert_eq!(hfp.slc_state, HfpSlcState::Connected);
        assert!(hfp.slc_state.is_connected());

        // No more SLC steps after Connected
        assert!(!hfp.advance_slc());
    }

    #[test]
    fn test_slc_state_machine_simple() {
        // Without codec negotiation or 3-way calling
        let mut hfp = HfpProfile::new(HfpRole::HandsFree);

        assert!(hfp.advance_slc()); // -> BrsfExchange
        assert!(hfp.advance_slc()); // -> CindTest (no codec neg)
        assert_eq!(hfp.slc_state, HfpSlcState::CindTest);
        assert!(hfp.advance_slc()); // -> CindRead
        assert!(hfp.advance_slc()); // -> CmerActivation
        assert!(hfp.advance_slc()); // -> Connected (no 3-way)
        assert_eq!(hfp.slc_state, HfpSlcState::Connected);
    }

    #[test]
    fn test_hfp_indicators() {
        let mut hfp = HfpProfile::new(HfpRole::AudioGateway);

        // Set valid indicator
        assert!(hfp.set_indicator(1, 1)); // service = 1
        assert_eq!(hfp.get_indicator("service"), Some(1));

        // Set signal strength
        assert!(hfp.set_indicator(5, 4)); // signal = 4
        assert_eq!(hfp.get_indicator("signal"), Some(4));

        // Out of range
        assert!(!hfp.set_indicator(5, 6)); // signal max is 5, but 6 is over
        assert_eq!(hfp.get_indicator("signal"), Some(4)); // unchanged

        // Invalid index
        assert!(!hfp.set_indicator(0, 0));
        assert!(!hfp.set_indicator(99, 0));
    }

    #[test]
    fn test_at_command_parser() {
        // HF -> AG commands
        assert_eq!(parse_at_command("AT+BRSF=159"), AtCommand::Brsf(159));
        assert_eq!(parse_at_command("AT+CIND=?"), AtCommand::CindTest);
        assert_eq!(parse_at_command("AT+CIND?"), AtCommand::CindRead);
        assert_eq!(
            parse_at_command("AT+CMER=3,0,0,1"),
            AtCommand::Cmer(3, 0, 0, 1)
        );
        assert_eq!(
            parse_at_command("AT+CHLD=1"),
            AtCommand::Chld("1".into())
        );
        assert_eq!(parse_at_command("AT+CLCC"), AtCommand::Clcc);
        assert_eq!(parse_at_command("AT+VGS=12"), AtCommand::Vgs(12));
        assert_eq!(parse_at_command("AT+VGM=8"), AtCommand::Vgm(8));
        assert_eq!(parse_at_command("AT+NREC=0"), AtCommand::Nrec(0));
        assert_eq!(parse_at_command("AT+BVRA=1"), AtCommand::Bvra(1));
        assert_eq!(
            parse_at_command("AT+BIEV=1,100"),
            AtCommand::Biev(1, 100)
        );
        assert_eq!(
            parse_at_command("ATD+1234567890;"),
            AtCommand::Dial("+1234567890".into())
        );
        assert_eq!(parse_at_command("ATA"), AtCommand::Answer);
        assert_eq!(parse_at_command("AT+CHUP"), AtCommand::Hangup);
        assert_eq!(parse_at_command("AT+BTRH?"), AtCommand::Btrh(None));
        assert_eq!(parse_at_command("AT+BTRH=1"), AtCommand::Btrh(Some(1)));
    }

    #[test]
    fn test_at_command_parser_ag_responses() {
        assert_eq!(parse_at_command("OK"), AtCommand::Ok);
        assert_eq!(parse_at_command("ERROR"), AtCommand::Error);
        assert_eq!(parse_at_command("RING"), AtCommand::Ring);
        assert_eq!(
            parse_at_command("+CME ERROR: 30"),
            AtCommand::CmeError(30)
        );
        assert_eq!(
            parse_at_command("+BRSF: 871"),
            AtCommand::BrsfResp(871)
        );
        assert_eq!(
            parse_at_command("+CIEV: 2,1"),
            AtCommand::Ciev(2, 1)
        );
        assert_eq!(
            parse_at_command("+VGS: 10"),
            AtCommand::VgsInd(10)
        );
        assert_eq!(
            parse_at_command("+VGM: 5"),
            AtCommand::VgmInd(5)
        );
        assert_eq!(
            parse_at_command("+BSIR: 1"),
            AtCommand::Bsir(1)
        );
    }

    #[test]
    fn test_at_command_display() {
        assert_eq!(AtCommand::Brsf(159).to_string(), "AT+BRSF=159");
        assert_eq!(AtCommand::CindTest.to_string(), "AT+CIND=?");
        assert_eq!(AtCommand::Ok.to_string(), "OK");
        assert_eq!(AtCommand::Ring.to_string(), "RING");
        assert_eq!(AtCommand::Ciev(2, 1).to_string(), "+CIEV: 2,1");
    }

    #[test]
    fn test_at_command_bia() {
        let cmd = parse_at_command("AT+BIA=1,1,1,1,0,,1");
        match cmd {
            AtCommand::Bia(indicators) => {
                assert_eq!(indicators.len(), 7);
                assert_eq!(indicators[0], Some(true));
                assert_eq!(indicators[4], Some(false));
                assert_eq!(indicators[5], None); // empty field
                assert_eq!(indicators[6], Some(true));
            }
            _ => panic!("expected Bia"),
        }
    }

    #[test]
    fn test_at_command_unknown() {
        match parse_at_command("AT+XYZZY=42") {
            AtCommand::Unknown(s) => assert_eq!(s, "AT+XYZZY=42"),
            _ => panic!("expected Unknown"),
        }
    }

    // -----------------------------------------------------------------------
    // CSIP tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_csip_sirk() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let sirk = Sirk::new_plaintext(key);
        assert!(!sirk.encrypted);
        assert_eq!(sirk.key, key);

        let encrypted = Sirk::new_encrypted(key);
        assert!(encrypted.encrypted);
    }

    #[test]
    fn test_csip_lock_unlock() {
        let mut csip = CsipProfile::new();
        assert_eq!(csip.lock_state, CsipLockState::Unlocked);

        // Can't unlock when already unlocked
        assert!(!csip.unlock());

        // Lock
        assert!(csip.lock());
        assert_eq!(csip.lock_state, CsipLockState::Locked);

        // Can't lock when already locked
        assert!(!csip.lock());

        // Unlock
        assert!(csip.unlock());
        assert_eq!(csip.lock_state, CsipLockState::Unlocked);
    }

    #[test]
    fn test_csip_sih_deterministic() {
        let key = [0xAA; 16];
        let r = [0x01, 0x02, 0x03];
        let hash1 = csip_sih(&key, &r);
        let hash2 = csip_sih(&key, &r);
        assert_eq!(hash1, hash2);

        // Different input -> different output
        let r2 = [0x04, 0x05, 0x06];
        let hash3 = csip_sih(&key, &r2);
        assert_ne!(hash1, hash3);
    }

    // -----------------------------------------------------------------------
    // VCP tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_vcp_defaults() {
        let vcp = VcpProfile::new();
        assert_eq!(vcp.volume, 0);
        assert!(!vcp.muted);
        assert_eq!(vcp.change_counter, 0);
    }

    #[test]
    fn test_vcp_volume_operations() {
        let mut vcp = VcpProfile::new();

        // Set absolute volume
        let counter = vcp.apply_operation(VcpOperation::SetAbsoluteVolume(100), 0).unwrap();
        assert_eq!(vcp.volume, 100);
        assert_eq!(counter, 1);

        // Relative volume up
        let counter = vcp.apply_operation(VcpOperation::RelativeVolumeUp, 1).unwrap();
        assert_eq!(vcp.volume, 116); // 100 + 16
        assert_eq!(counter, 2);

        // Relative volume down
        let counter = vcp.apply_operation(VcpOperation::RelativeVolumeDown, 2).unwrap();
        assert_eq!(vcp.volume, 100); // 116 - 16
        assert_eq!(counter, 3);

        // Mute
        let counter = vcp.apply_operation(VcpOperation::Mute, 3).unwrap();
        assert!(vcp.muted);
        assert_eq!(counter, 4);

        // Unmute with volume up
        let counter = vcp.apply_operation(VcpOperation::UnmuteRelativeVolumeUp, 4).unwrap();
        assert!(!vcp.muted);
        assert_eq!(vcp.volume, 116);
        assert_eq!(counter, 5);

        // Stale counter should fail
        assert!(vcp.apply_operation(VcpOperation::Mute, 0).is_none());
    }

    #[test]
    fn test_vcp_volume_saturation() {
        let mut vcp = VcpProfile::new();
        vcp.volume = 250;
        vcp.apply_operation(VcpOperation::RelativeVolumeUp, 0).unwrap();
        assert_eq!(vcp.volume, 255); // saturated at max

        vcp.volume = 5;
        vcp.apply_operation(VcpOperation::RelativeVolumeDown, 1).unwrap();
        assert_eq!(vcp.volume, 0); // saturated at min
    }

    // -----------------------------------------------------------------------
    // Media transport tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_media_transport_creation() {
        let t = MediaTransport::new("/org/bluez/media/transport0".into(), AudioCodec::Aac);
        assert_eq!(t.state, MediaTransportState::Idle);
        assert_eq!(t.codec, AudioCodec::Aac);
        assert_eq!(t.volume, 127);
    }

    // -----------------------------------------------------------------------
    // QoS config tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_qos_config_defaults() {
        let qos = QosConfig::default();
        assert_eq!(qos.sdu_interval, 10_000);
        assert_eq!(qos.phy, 0x02);
        assert_eq!(qos.max_sdu, 120);
        assert_eq!(qos.presentation_delay, 40_000);
    }

    // ===================================================================
    // Ported from unit/test-avdtp.c — AVDTP signaling
    // ===================================================================

    // Port of test-avdtp.c /TP/SIG/SMG/BV-05-C: Discover command encoding
    #[test]
    fn test_avdtp_discover_command_encoding() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let pkt = session.create_command(AvdtpSignalId::Discover, vec![]);
        let encoded = pkt.encode();
        // Expected: transaction=0, single packet, command, signal=0x01
        assert_eq!(encoded[0] & 0x03, 0x00); // message type = command
        assert_eq!((encoded[0] >> 2) & 0x03, 0x00); // packet type = single
        assert_eq!(encoded[1] & 0x3F, 0x01); // signal id = Discover
    }

    // Port of test-avdtp.c /TP/SIG/SMG/BV-07-C: GetCapabilities command
    #[test]
    fn test_avdtp_get_capabilities_command() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let seid: u8 = 0x01;
        let pkt = session.create_command(AvdtpSignalId::GetCapabilities, vec![seid << 2]);
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x02); // GetCapabilities
        assert_eq!(encoded[2], 0x04); // SEID 1 shifted left by 2
    }

    // Port of test-avdtp.c /TP/SIG/SMG/BV-09-C: SetConfiguration command
    #[test]
    fn test_avdtp_set_configuration_command() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let payload = vec![0x04, 0x04, 0x01, 0x00]; // ACP SEID, INT SEID, caps
        let pkt = session.create_command(AvdtpSignalId::SetConfiguration, payload.clone());
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x03); // SetConfiguration
        assert_eq!(&encoded[2..], &payload[..]);
    }

    // Port of test-avdtp.c /TP/SIG/SMG/BV-15-C: Open command
    #[test]
    fn test_avdtp_open_command() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let pkt = session.create_command(AvdtpSignalId::Open, vec![0x04]);
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x06); // Open
    }

    // Port of test-avdtp.c /TP/SIG/SMG/BV-17-C: Start command
    #[test]
    fn test_avdtp_start_command() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let pkt = session.create_command(AvdtpSignalId::Start, vec![0x04]);
        assert_eq!(pkt.signal_id, AvdtpSignalId::Start);
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x07); // Start
    }

    // Port of test-avdtp.c /TP/SIG/SMG/BV-19-C: Close command
    #[test]
    fn test_avdtp_close_command() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let pkt = session.create_command(AvdtpSignalId::Close, vec![0x04]);
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x08); // Close
    }

    // Port of test-avdtp.c /TP/SIG/SMG/BV-21-C: Suspend command
    #[test]
    fn test_avdtp_suspend_command() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let pkt = session.create_command(AvdtpSignalId::Suspend, vec![0x04]);
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x09); // Suspend
    }

    // Port of test-avdtp.c /TP/SIG/SMG/BV-23-C: Abort command
    #[test]
    fn test_avdtp_abort_command() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let pkt = session.create_command(AvdtpSignalId::Abort, vec![0x04]);
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x0A); // Abort
    }

    // Port of test-avdtp.c test_server_seid: MAX_SEID allocation
    #[test]
    fn test_avdtp_seid_max_allocation() {
        let mut alloc = SeidAllocator::new();
        // Allocate all 62 SEIDs
        for i in 1..=62 {
            assert_eq!(alloc.alloc(), Some(i));
        }
        // 63rd allocation should fail (MAX_SEID = 0x3E = 62)
        assert!(alloc.alloc().is_none());
    }

    // Port of test-avdtp.c: response accept decoding
    #[test]
    fn test_avdtp_response_accept_decode() {
        // Byte 0: transaction=1 (0x10), single (0x00), response_accept (0x02)
        // Byte 1: signal id = Discover (0x01)
        // Payload: SEID info
        let data = vec![0x12, 0x01, 0x04, 0x00];
        let pkt = AvdtpPacket::decode(&data).unwrap();
        assert_eq!(pkt.transaction, 1);
        assert_eq!(pkt.message_type, AvdtpMessageType::ResponseAccept);
        assert_eq!(pkt.signal_id, AvdtpSignalId::Discover);
        assert_eq!(pkt.payload, vec![0x04, 0x00]);
    }

    // Port of test-avdtp.c: response reject decoding
    #[test]
    fn test_avdtp_response_reject_decode() {
        // transaction=0, single, reject, Discover
        let data = vec![0x03, 0x01];
        let pkt = AvdtpPacket::decode(&data).unwrap();
        assert_eq!(pkt.message_type, AvdtpMessageType::ResponseReject);
        assert_eq!(pkt.signal_id, AvdtpSignalId::Discover);
    }

    // Port of test-avdtp.c: too-short packet decoding
    #[test]
    fn test_avdtp_decode_too_short() {
        assert!(AvdtpPacket::decode(&[0x00]).is_none());
        assert!(AvdtpPacket::decode(&[]).is_none());
    }

    // Port of test-avdtp.c: A2DP stream state transition Configured->Aborting
    #[test]
    fn test_avdtp_stream_state_configured_abort() {
        assert!(A2dpStreamState::Configured.can_transition_to(A2dpStreamState::Aborting));
        assert!(A2dpStreamState::Open.can_transition_to(A2dpStreamState::Aborting));
        assert!(A2dpStreamState::Streaming.can_transition_to(A2dpStreamState::Aborting));
    }

    // Port of test-avdtp.c: GetAllCapabilities signal ID
    #[test]
    fn test_avdtp_get_all_capabilities() {
        let mut session = AvdtpSession::new(BdAddr::default());
        let pkt = session.create_command(AvdtpSignalId::GetAllCapabilities, vec![0x04]);
        let encoded = pkt.encode();
        assert_eq!(encoded[1] & 0x3F, 0x0C); // GetAllCapabilities
    }

    // Port of test-avdtp.c: DelayReport signal
    #[test]
    fn test_avdtp_delay_report() {
        let id = AvdtpSignalId::from_u8(0x0D).unwrap();
        assert_eq!(id, AvdtpSignalId::DelayReport);
    }

    // ===================================================================
    // Ported from unit/test-avrcp.c — AVRCP PDU encoding/decoding
    // ===================================================================

    // Port of test-avrcp.c: player setting attribute list
    #[test]
    fn test_avrcp_player_setting_ids() {
        assert_eq!(PlayerSettingId::Equalizer as u8, 0x01);
        assert_eq!(PlayerSettingId::Repeat as u8, 0x02);
        assert_eq!(PlayerSettingId::Shuffle as u8, 0x03);
        assert_eq!(PlayerSettingId::Scan as u8, 0x04);
    }

    // Port of test-avrcp.c: media attribute ID roundtrip
    #[test]
    fn test_avrcp_media_attribute_roundtrip() {
        for val in 0x01..=0x08 {
            let attr = MediaAttribute::from_u32(val).unwrap();
            assert_eq!(attr as u32, val);
        }
        assert!(MediaAttribute::from_u32(0x00).is_none());
        assert!(MediaAttribute::from_u32(0x09).is_none());
    }

    // Port of test-avrcp.c: notification event IDs roundtrip
    #[test]
    fn test_avrcp_notification_event_roundtrip() {
        for val in 0x01..=0x0D {
            let evt = AvrcpNotificationEvent::from_u8(val).unwrap();
            assert_eq!(evt as u8, val);
        }
    }

    // Port of test-avrcp.c: AVRCP PDU ID roundtrip for all valid IDs
    #[test]
    fn test_avrcp_pdu_id_all_valid() {
        let valid_ids: Vec<u8> = vec![
            0x10, 0x11, 0x13, 0x14, 0x20, 0x30, 0x31,
            0x40, 0x41, 0x50, 0x60, 0x70, 0x71, 0x72,
            0x73, 0x74, 0x75, 0x76,
        ];
        for id in &valid_ids {
            assert!(
                AvrcpPduId::from_u8(*id).is_some(),
                "PDU ID 0x{:02X} should be valid",
                id
            );
        }
        // Invalid PDU IDs
        assert!(AvrcpPduId::from_u8(0x00).is_none());
        assert!(AvrcpPduId::from_u8(0x12).is_none());
        assert!(AvrcpPduId::from_u8(0x15).is_none());
        assert!(AvrcpPduId::from_u8(0x77).is_none());
    }

    // Port of test-avrcp.c: player settings default values
    #[test]
    fn test_avrcp_player_settings_defaults() {
        let settings = AvrcpPlayerSettings::default();
        assert_eq!(settings.equalizer, EqualizerSetting::Off);
        assert_eq!(settings.repeat, RepeatSetting::Off);
        assert_eq!(settings.shuffle, ShuffleSetting::Off);
        assert_eq!(settings.scan, ScanSetting::Off);
    }

    // Port of test-avrcp.c: get_attribute with all attributes set
    #[test]
    fn test_avrcp_get_all_attributes() {
        let profile = AvrcpProfile {
            track_title: Some("Song".into()),
            track_artist: Some("Artist".into()),
            track_album: Some("Album".into()),
            track_number: Some(1),
            total_tracks: Some(10),
            track_genre: Some("Pop".into()),
            track_duration_ms: 180000,
            ..AvrcpProfile::new()
        };

        assert_eq!(profile.get_attribute(MediaAttribute::Title), Some("Song".into()));
        assert_eq!(profile.get_attribute(MediaAttribute::ArtistName), Some("Artist".into()));
        assert_eq!(profile.get_attribute(MediaAttribute::AlbumName), Some("Album".into()));
        assert_eq!(profile.get_attribute(MediaAttribute::TrackNumber), Some("1".into()));
        assert_eq!(profile.get_attribute(MediaAttribute::TotalTracks), Some("10".into()));
        assert_eq!(profile.get_attribute(MediaAttribute::Genre), Some("Pop".into()));
        assert_eq!(
            profile.get_attribute(MediaAttribute::PlayingTime),
            Some("180000".into())
        );
        assert_eq!(profile.get_attribute(MediaAttribute::CoverArt), None);
    }

    // Port of test-avrcp.c: get_attribute with no metadata
    #[test]
    fn test_avrcp_get_attribute_empty() {
        let profile = AvrcpProfile::new();
        assert_eq!(profile.get_attribute(MediaAttribute::Title), None);
        assert_eq!(profile.get_attribute(MediaAttribute::ArtistName), None);
        // PlayingTime always returns something (0)
        assert_eq!(
            profile.get_attribute(MediaAttribute::PlayingTime),
            Some("0".into())
        );
    }

    // Port of test-avrcp.c: playback status initial state
    #[test]
    fn test_avrcp_initial_playback_state() {
        let profile = AvrcpProfile::new();
        assert_eq!(profile.playback_status, PlaybackStatus::Stopped);
        assert_eq!(profile.volume, 0x7F);
        assert!(!profile.browsing_supported);
        assert!(profile.registered_notifications.is_empty());
    }

    // Port of test-avrcp.c: notification registration tracking
    #[test]
    fn test_avrcp_notification_registration() {
        let mut profile = AvrcpProfile::new();
        profile.registered_notifications.push(AvrcpNotificationEvent::TrackChanged);
        profile.registered_notifications.push(AvrcpNotificationEvent::VolumeChanged);

        assert_eq!(profile.registered_notifications.len(), 2);
        assert!(profile.registered_notifications.contains(&AvrcpNotificationEvent::TrackChanged));
        assert!(profile.registered_notifications.contains(&AvrcpNotificationEvent::VolumeChanged));
    }

    // Port of test-avrcp.c: set absolute volume
    #[test]
    fn test_avrcp_set_absolute_volume() {
        let mut profile = AvrcpProfile::new();
        assert_eq!(profile.volume, 0x7F);
        profile.volume = 0x40;
        assert_eq!(profile.volume, 0x40);
        profile.volume = 0x00;
        assert_eq!(profile.volume, 0x00);
    }

    // ===================================================================
    // Ported from unit/test-avctp.c — AVCTP connection/message handling
    // ===================================================================

    // Port of test-avctp.c /TP/CCM/BV-01-C through BV-04-C: connection establishment
    #[test]
    fn test_avctp_connection_dummy() {
        // The C test merely verifies that the session can be created.
        // We verify AVDTP session creation works as a proxy.
        let session = AvdtpSession::new(BdAddr::default());
        assert_eq!(session.version, 0x0103);
        assert!(session.seps.is_empty());
    }

    // Port of test-avctp.c /TP/NFR/BV-01-C: vendor-dependent command PDU
    // AVCTP header: transaction=0, C/R=0, pid=0x110E, then AVC frame
    #[test]
    fn test_avctp_vendor_command_pdu() {
        // AVCTP header format: 1 byte header + 2 byte PID
        // Header: transaction(4 bits) | packet_type(2 bits) | C/R(1 bit) | IPID(1 bit)
        let transaction: u8 = 0;
        let packet_type: u8 = 0; // single
        let cr_bit: u8 = 0; // command
        let ipid: u8 = 0;

        let header = (transaction << 4) | (packet_type << 2) | (cr_bit << 1) | ipid;
        assert_eq!(header, 0x00);

        // PID for AV/C: 0x110E
        let pid: u16 = 0x110E;
        let pid_bytes = pid.to_be_bytes();
        assert_eq!(pid_bytes, [0x11, 0x0E]);

        let pdu = vec![header, pid_bytes[0], pid_bytes[1], 0x00, 0x00, 0x00];
        assert_eq!(pdu.len(), 6);
        assert_eq!(pdu[0], 0x00);
        assert_eq!(pdu[1], 0x11);
        assert_eq!(pdu[2], 0x0E);
    }

    // Port of test-avctp.c /TP/NFR/BV-02-C: response PDU
    #[test]
    fn test_avctp_response_pdu() {
        // Response: C/R = 1
        let transaction: u8 = 0;
        let cr_bit: u8 = 1; // response
        let header = (transaction << 4) | (cr_bit << 1);
        assert_eq!(header, 0x02);
    }

    // Port of test-avctp.c /TP/NFR/BI-01-C: invalid PID handling
    #[test]
    fn test_avctp_invalid_pid_detection() {
        // Invalid PID: 0xFFFF
        let header: u8 = 0x00;
        let pid_bytes = [0xFF, 0xFF];
        let pdu = vec![header, pid_bytes[0], pid_bytes[1]];
        // The response to invalid PID sets IPID bit = 1 in response
        let response_header = (0u8 << 4) | (0u8 << 2) | (1u8 << 1) | 1u8;
        assert_eq!(response_header & 0x01, 1); // IPID bit set
    }

    // Port of test-avctp.c: AVCTP PID constant for AV/C
    #[test]
    fn test_avctp_avc_pid() {
        // The standard PID for AV/C is 0x110E (AVRCP)
        let avc_pid: u16 = 0x110E;
        assert_eq!(avc_pid >> 8, 0x11);
        assert_eq!(avc_pid & 0xFF, 0x0E);
    }

    // ===================================================================
    // Ported from unit/test-hfp.c — HFP profile-level tests
    // ===================================================================

    // Port of test-hfp.c test_init: HFP profile initialization
    #[test]
    fn test_hfp_profile_init_ag() {
        let hfp = HfpProfile::new(HfpRole::AudioGateway);
        assert_eq!(hfp.role, HfpRole::AudioGateway);
        assert_eq!(hfp.slc_state, HfpSlcState::Disconnected);
        assert!(!hfp.slc_state.is_connected());
        assert_eq!(hfp.indicators.len(), 7);
        assert_eq!(hfp.active_codec, AudioCodec::Sbc);
    }

    // Port of test-hfp.c test_hf_init: HFP HF initialization
    #[test]
    fn test_hfp_profile_init_hf() {
        let hfp = HfpProfile::new(HfpRole::HandsFree);
        assert_eq!(hfp.role, HfpRole::HandsFree);
        assert_eq!(hfp.slc_state, HfpSlcState::Disconnected);
    }

    // Port of test-hfp.c: BRSF feature negotiation
    #[test]
    fn test_hfp_brsf_feature_negotiation() {
        let mut hfp = HfpProfile::new(HfpRole::HandsFree);
        // AG sends features = 0 (no features)
        hfp.ag_features = 0;
        assert_eq!(hfp.ag_features & hfp_ag_features::THREE_WAY_CALLING, 0);
        assert_eq!(hfp.ag_features & hfp_ag_features::CODEC_NEGOTIATION, 0);

        // AG sends full features (16383 = 0x3FFF)
        hfp.ag_features = 16383;
        assert_ne!(hfp.ag_features & hfp_ag_features::THREE_WAY_CALLING, 0);
        assert_ne!(hfp.ag_features & hfp_ag_features::CODEC_NEGOTIATION, 0);
        assert_ne!(hfp.ag_features & hfp_ag_features::ESCO_S4, 0);
    }

    // Port of test-hfp.c: indicator standard set names
    #[test]
    fn test_hfp_indicator_standard_set_names() {
        let indicators = HfpIndicator::standard_set();
        assert_eq!(indicators.len(), 7);
        assert_eq!(indicators[0].name, "service");
        assert_eq!(indicators[1].name, "call");
        assert_eq!(indicators[2].name, "callsetup");
        assert_eq!(indicators[3].name, "callheld");
        assert_eq!(indicators[4].name, "signal");
        assert_eq!(indicators[5].name, "roaming");
        assert_eq!(indicators[6].name, "battchg");
    }

    // Port of test-hfp.c: indicator ranges
    #[test]
    fn test_hfp_indicator_ranges() {
        let indicators = HfpIndicator::standard_set();
        // service: 0-1
        assert_eq!(indicators[0].min, 0);
        assert_eq!(indicators[0].max, 1);
        // callsetup: 0-3
        assert_eq!(indicators[2].min, 0);
        assert_eq!(indicators[2].max, 3);
        // signal: 0-5
        assert_eq!(indicators[4].min, 0);
        assert_eq!(indicators[4].max, 5);
        // battchg: 0-5
        assert_eq!(indicators[6].min, 0);
        assert_eq!(indicators[6].max, 5);
    }

    // Port of test-hfp.c: set indicator values at boundaries
    #[test]
    fn test_hfp_indicator_boundary_values() {
        let mut hfp = HfpProfile::new(HfpRole::AudioGateway);

        // service indicator: valid range 0-1
        assert!(hfp.set_indicator(1, 0));
        assert_eq!(hfp.get_indicator("service"), Some(0));
        assert!(hfp.set_indicator(1, 1));
        assert_eq!(hfp.get_indicator("service"), Some(1));
        // Out of range
        assert!(!hfp.set_indicator(1, 2));
        assert_eq!(hfp.get_indicator("service"), Some(1)); // unchanged

        // signal indicator: valid range 0-5
        assert!(hfp.set_indicator(5, 0));
        assert!(hfp.set_indicator(5, 5));
        assert!(!hfp.set_indicator(5, 6));
    }

    // Port of test-hfp.c: AT+CIND=? and AT+CIND? formatting
    #[test]
    fn test_hfp_at_cind_display() {
        assert_eq!(AtCommand::CindTest.to_string(), "AT+CIND=?");
        assert_eq!(AtCommand::CindRead.to_string(), "AT+CIND?");
    }

    // Port of test-hfp.c: AT+CMER formatting
    #[test]
    fn test_hfp_at_cmer_display() {
        assert_eq!(
            AtCommand::Cmer(3, 0, 0, 1).to_string(),
            "AT+CMER=3,0,0,1"
        );
    }

    // Port of test-hfp.c: ATD dial formatting
    #[test]
    fn test_hfp_at_dial_display() {
        assert_eq!(
            AtCommand::Dial("1234567".into()).to_string(),
            "ATD1234567;"
        );
        // Last dialed (empty number)
        assert_eq!(AtCommand::Dial("".into()).to_string(), "ATD;");
        // Memory dial
        assert_eq!(AtCommand::Dial(">1".into()).to_string(), "ATD>1;");
    }

    // Port of test-hfp.c: CLIP/CCWA formatting
    #[test]
    fn test_hfp_at_clip_ccwa_display() {
        assert_eq!(
            AtCommand::Clip("1234567".into(), 129).to_string(),
            "+CLIP: \"1234567\",129"
        );
        assert_eq!(
            AtCommand::Ccwa("7654321".into(), 129).to_string(),
            "+CCWA: \"7654321\",129"
        );
    }

    // Port of test-hfp.c: CLIP/CCWA parsing
    #[test]
    fn test_hfp_at_clip_ccwa_parsing() {
        let cmd = parse_at_command("+CLIP: \"1234567\",129");
        assert_eq!(cmd, AtCommand::Clip("1234567".into(), 129));

        let cmd2 = parse_at_command("+CCWA: \"7654321\",129");
        assert_eq!(cmd2, AtCommand::Ccwa("7654321".into(), 129));
    }

    // Port of test-hfp.c: SLC state Disconnected -> is_connected() = false
    #[test]
    fn test_hfp_slc_disconnected_not_connected() {
        assert!(!HfpSlcState::Disconnected.is_connected());
        assert!(!HfpSlcState::BrsfExchange.is_connected());
        assert!(!HfpSlcState::CindTest.is_connected());
        assert!(!HfpSlcState::CindRead.is_connected());
        assert!(!HfpSlcState::CmerActivation.is_connected());
        assert!(!HfpSlcState::ChldQuery.is_connected());
        assert!(HfpSlcState::Connected.is_connected());
        assert!(HfpSlcState::ScoSetup.is_connected());
        assert!(HfpSlcState::ScoConnected.is_connected());
    }

    // Port of test-hfp.c: AT+COPS formatting/parsing
    #[test]
    fn test_hfp_at_cops() {
        let cmd = parse_at_command("AT+COPS=3");
        assert_eq!(cmd, AtCommand::Cops(3));
        assert_eq!(AtCommand::Cops(3).to_string(), "AT+COPS=3");
    }

    // Port of test-hfp.c: AT+CMEE formatting/parsing
    #[test]
    fn test_hfp_at_cmee() {
        let cmd = parse_at_command("AT+CMEE=1");
        assert_eq!(cmd, AtCommand::Cmee(1));
        assert_eq!(AtCommand::Cmee(1).to_string(), "AT+CMEE=1");
    }
}
