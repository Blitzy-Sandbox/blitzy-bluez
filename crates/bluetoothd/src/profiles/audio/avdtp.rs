// SPDX-License-Identifier: GPL-2.0-or-later
//! AVDTP (Audio/Video Distribution Transport Protocol) implementation.
//!
//! Rust rewrite of `profiles/audio/avdtp.c` (~4010 lines).  Manages L2CAP
//! signaling (PSM 25) and media transport channels, SEP registration, stream
//! lifecycle, request queuing, packet fragmentation/reassembly, and timer
//! management.

use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::Arc;

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, trace, warn};

use bluez_shared::socket::BluetoothSocket;

use crate::adapter::BtdAdapter;
use crate::device::BtdDevice;

// ===========================================================================
// Protocol Constants
// ===========================================================================

/// AVDTP signaling channel PSM.
pub const AVDTP_PSM: u16 = 25;
/// Maximum valid SEID value (6-bit field, 1..62).
pub const AVDTP_MAX_SEID: u8 = 0x3E;

// --- Service Capability Categories ---
pub const AVDTP_CAP_MEDIA_TRANSPORT: u8 = 0x01;
pub const AVDTP_CAP_REPORTING: u8 = 0x02;
pub const AVDTP_CAP_RECOVERY: u8 = 0x03;
pub const AVDTP_CAP_CONTENT_PROTECTION: u8 = 0x04;
pub const AVDTP_CAP_HEADER_COMPRESSION: u8 = 0x05;
pub const AVDTP_CAP_MULTIPLEXING: u8 = 0x06;
pub const AVDTP_CAP_MEDIA_CODEC: u8 = 0x07;
pub const AVDTP_CAP_DELAY_REPORTING: u8 = 0x08;

// --- Error Category for POSIX errors ---
const AVDTP_ERRNO: u8 = 0xFF;

// --- AVDTP Error Codes ---
const AVDTP_BAD_HEADER_FORMAT: u8 = 0x01;
const AVDTP_BAD_LENGTH: u8 = 0x11;
const AVDTP_BAD_ACP_SEID: u8 = 0x12;
const AVDTP_SEP_IN_USE: u8 = 0x13;
const AVDTP_SEP_NOT_IN_USE: u8 = 0x14;
const AVDTP_BAD_SERV_CATEGORY: u8 = 0x17;
const AVDTP_BAD_PAYLOAD_FORMAT: u8 = 0x18;
const AVDTP_NOT_SUPPORTED_COMMAND: u8 = 0x19;
const AVDTP_INVALID_CAPABILITIES: u8 = 0x1A;
const AVDTP_BAD_RECOVERY_TYPE: u8 = 0x22;
const AVDTP_BAD_MEDIA_TRANSPORT_FORMAT: u8 = 0x23;
const AVDTP_BAD_RECOVERY_FORMAT: u8 = 0x25;
const AVDTP_BAD_ROHC_FORMAT: u8 = 0x26;
const AVDTP_BAD_CP_FORMAT: u8 = 0x27;
const AVDTP_BAD_MULTIPLEXING_FORMAT: u8 = 0x28;
const AVDTP_UNSUPPORTED_CONFIGURATION: u8 = 0x29;
const AVDTP_BAD_STATE: u8 = 0x31;

// --- Signal Identifiers ---
const AVDTP_DISCOVER: u8 = 0x01;
const AVDTP_GET_CAPABILITIES: u8 = 0x02;
const AVDTP_SET_CONFIGURATION: u8 = 0x03;
const AVDTP_GET_CONFIGURATION: u8 = 0x04;
const AVDTP_RECONFIGURE: u8 = 0x05;
const AVDTP_OPEN: u8 = 0x06;
const AVDTP_START: u8 = 0x07;
const AVDTP_CLOSE: u8 = 0x08;
const AVDTP_SUSPEND: u8 = 0x09;
const AVDTP_ABORT: u8 = 0x0A;
const AVDTP_SECURITY_CONTROL: u8 = 0x0B;
const AVDTP_GET_ALL_CAPABILITIES: u8 = 0x0C;
const AVDTP_DELAY_REPORT: u8 = 0x0D;

// --- Packet Types ---
const AVDTP_PKT_TYPE_SINGLE: u8 = 0x00;
const AVDTP_PKT_TYPE_START: u8 = 0x01;
const AVDTP_PKT_TYPE_CONTINUE: u8 = 0x02;
const AVDTP_PKT_TYPE_END: u8 = 0x03;

// --- Message Types ---
const AVDTP_MSG_TYPE_COMMAND: u8 = 0x00;
const AVDTP_MSG_TYPE_GEN_REJECT: u8 = 0x01;
const AVDTP_MSG_TYPE_ACCEPT: u8 = 0x02;
const AVDTP_MSG_TYPE_REJECT: u8 = 0x03;

// --- Timeouts ---
const REQ_TIMEOUT: Duration = Duration::from_secs(6);
const ABORT_TIMEOUT: Duration = Duration::from_secs(2);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const _STREAM_TIMEOUT: Duration = Duration::from_secs(20);
const _START_TIMEOUT: Duration = Duration::from_secs(1);

// --- Buffer Sizes ---
const AVDTP_BUF_SIZE: usize = 1024;

// --- Raw SEP/Media type constants (wire values) ---
const AVDTP_SEP_TYPE_SOURCE_RAW: u8 = 0x00;
const AVDTP_SEP_TYPE_SINK_RAW: u8 = 0x01;
const AVDTP_MEDIA_TYPE_AUDIO_RAW: u8 = 0x00;
const AVDTP_MEDIA_TYPE_VIDEO_RAW: u8 = 0x01;
const AVDTP_MEDIA_TYPE_MULTIMEDIA_RAW: u8 = 0x02;

// ===========================================================================
// Enumerations
// ===========================================================================

/// AVDTP stream state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvdtpStreamState {
    Idle,
    Configured,
    Open,
    Streaming,
    Closing,
    Aborting,
}

impl fmt::Display for AvdtpStreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => f.write_str("IDLE"),
            Self::Configured => f.write_str("CONFIGURED"),
            Self::Open => f.write_str("OPEN"),
            Self::Streaming => f.write_str("STREAMING"),
            Self::Closing => f.write_str("CLOSING"),
            Self::Aborting => f.write_str("ABORTING"),
        }
    }
}

/// AVDTP session-level states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvdtpSessionState {
    Idle,
    Connecting,
    Connected,
}

impl fmt::Display for AvdtpSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => f.write_str("IDLE"),
            Self::Connecting => f.write_str("CONNECTING"),
            Self::Connected => f.write_str("CONNECTED"),
        }
    }
}

/// AVDTP SEP Type (Source or Sink).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvdtpSepType {
    Source,
    Sink,
}

impl AvdtpSepType {
    /// Create from raw wire value.
    pub fn from_raw(val: u8) -> Option<Self> {
        match val {
            AVDTP_SEP_TYPE_SOURCE_RAW => Some(Self::Source),
            AVDTP_SEP_TYPE_SINK_RAW => Some(Self::Sink),
            _ => None,
        }
    }

    /// Convert to raw wire value.
    pub fn to_raw(self) -> u8 {
        match self {
            Self::Source => AVDTP_SEP_TYPE_SOURCE_RAW,
            Self::Sink => AVDTP_SEP_TYPE_SINK_RAW,
        }
    }
}

impl fmt::Display for AvdtpSepType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => f.write_str("Source"),
            Self::Sink => f.write_str("Sink"),
        }
    }
}

/// AVDTP Media Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvdtpMediaType {
    Audio,
    Video,
    Multimedia,
}

impl AvdtpMediaType {
    /// Create from raw wire value.
    pub fn from_raw(val: u8) -> Option<Self> {
        match val {
            AVDTP_MEDIA_TYPE_AUDIO_RAW => Some(Self::Audio),
            AVDTP_MEDIA_TYPE_VIDEO_RAW => Some(Self::Video),
            AVDTP_MEDIA_TYPE_MULTIMEDIA_RAW => Some(Self::Multimedia),
            _ => None,
        }
    }

    /// Convert to raw wire value.
    pub fn to_raw(self) -> u8 {
        match self {
            Self::Audio => AVDTP_MEDIA_TYPE_AUDIO_RAW,
            Self::Video => AVDTP_MEDIA_TYPE_VIDEO_RAW,
            Self::Multimedia => AVDTP_MEDIA_TYPE_MULTIMEDIA_RAW,
        }
    }
}

impl fmt::Display for AvdtpMediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audio => f.write_str("Audio"),
            Self::Video => f.write_str("Video"),
            Self::Multimedia => f.write_str("Multimedia"),
        }
    }
}

// ===========================================================================
// Error Type
// ===========================================================================

/// AVDTP error, unifying signaling errors, protocol violations, and I/O
/// failures.
#[derive(Debug, Error)]
pub enum AvdtpError {
    #[error("AVDTP signaling error: category={category:#x} code={code:#x}")]
    SignalingError { category: u8, code: u8 },
    #[error("AVDTP protocol error: {0}")]
    ProtocolError(String),
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("AVDTP request timed out")]
    Timeout,
    #[error("Invalid state for this operation: {0}")]
    InvalidState(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("POSIX error: errno={0}")]
    Errno(i32),
}

impl AvdtpError {
    pub fn category(&self) -> u8 {
        match self {
            Self::SignalingError { category, .. } => *category,
            _ => AVDTP_ERRNO,
        }
    }
    pub fn code(&self) -> u8 {
        match self {
            Self::SignalingError { code, .. } => *code,
            _ => 0,
        }
    }
    pub fn errno(&self) -> i32 {
        match self {
            Self::Errno(e) => *e,
            Self::IoError(e) => e.raw_os_error().unwrap_or(0),
            Self::Timeout => 110,
            _ => 0,
        }
    }
}

pub fn avdtp_error_init(category: u8, id: i32) -> AvdtpError {
    if category == AVDTP_ERRNO {
        AvdtpError::Errno(id)
    } else {
        AvdtpError::SignalingError { category, code: id as u8 }
    }
}

pub fn avdtp_strerror(err: &AvdtpError) -> &'static str {
    match err {
        AvdtpError::SignalingError { code, .. } => match *code {
            AVDTP_BAD_HEADER_FORMAT => "Bad Header Format",
            AVDTP_BAD_LENGTH => "Bad Packet Length",
            AVDTP_BAD_ACP_SEID => "Bad Acceptor SEID",
            AVDTP_SEP_IN_USE => "Stream End Point in Use",
            AVDTP_SEP_NOT_IN_USE => "Stream End Point Not in Use",
            AVDTP_BAD_SERV_CATEGORY => "Bad Service Category",
            AVDTP_BAD_PAYLOAD_FORMAT => "Bad Payload format",
            AVDTP_NOT_SUPPORTED_COMMAND => "Command Not Supported",
            AVDTP_INVALID_CAPABILITIES => "Invalid Capabilities",
            AVDTP_BAD_RECOVERY_TYPE => "Bad Recovery Type",
            AVDTP_BAD_MEDIA_TRANSPORT_FORMAT => "Bad Media Transport Format",
            AVDTP_BAD_RECOVERY_FORMAT => "Bad Recovery Format",
            AVDTP_BAD_ROHC_FORMAT => "Bad Header Compression Format",
            AVDTP_BAD_CP_FORMAT => "Bad Content Protection Format",
            AVDTP_BAD_MULTIPLEXING_FORMAT => "Bad Multiplexing Format",
            AVDTP_UNSUPPORTED_CONFIGURATION => "Configuration not supported",
            AVDTP_BAD_STATE => "Bad State",
            _ => "Unknown error",
        },
        AvdtpError::Errno(_) => "POSIX error",
        AvdtpError::IoError(_) => "I/O error",
        AvdtpError::Timeout => "Request timed out",
        AvdtpError::InvalidState(_) => "Invalid state",
        AvdtpError::NotSupported(_) => "Not supported",
        AvdtpError::ProtocolError(_) => "Protocol error",
    }
}

pub type AvdtpResult<T> = Result<T, AvdtpError>;

// ===========================================================================
// Bitflags
// ===========================================================================

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StreamFlags: u32 {
        const STARTING        = 0x01;
        const OPEN_ACP        = 0x02;
        const CLOSE_INT       = 0x04;
        const ABORT_INT       = 0x08;
        const DELAY_REPORTING = 0x10;
    }
}

// ===========================================================================
// Wire Format Structures
// ===========================================================================

/// AVDTP SEID information element (2 bytes on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvdtpSepInfo {
    pub seid: u8,
    pub in_use: bool,
    pub media_type: u8,
    pub sep_type: u8,
}

impl AvdtpSepInfo {
    pub fn to_bytes(&self) -> [u8; 2] {
        let b0 = (self.seid & 0x3F) << 2 | (u8::from(self.in_use) << 1);
        let b1 = (self.media_type & 0x0F) << 4 | (self.sep_type & 0x01) << 3;
        [b0, b1]
    }
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        Some(Self {
            seid: (data[0] >> 2) & 0x3F,
            in_use: (data[0] & 0x02) != 0,
            media_type: (data[1] >> 4) & 0x0F,
            sep_type: (data[1] >> 3) & 0x01,
        })
    }
}

/// AVDTP Service Capability TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvdtpServiceCapability {
    pub category: u8,
    pub data: Vec<u8>,
}

impl AvdtpServiceCapability {
    pub fn len(&self) -> usize {
        2 + self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.category == 0
    }
    pub fn to_bytes(&self, buf: &mut BytesMut) {
        buf.put_u8(self.category);
        buf.put_u8(self.data.len() as u8);
        buf.put_slice(&self.data);
    }
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }
        let cat = data[0];
        let length = data[1] as usize;
        if data.len() < 2 + length {
            return None;
        }
        Some((Self { category: cat, data: data[2..2 + length].to_vec() }, 2 + length))
    }
}

pub fn avdtp_service_cap_new(category: u8, data: &[u8]) -> AvdtpServiceCapability {
    AvdtpServiceCapability { category, data: data.to_vec() }
}

fn caps_to_list(data: &[u8]) -> AvdtpResult<Vec<AvdtpServiceCapability>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        match AvdtpServiceCapability::from_bytes(&data[offset..]) {
            Some((cap, consumed)) => {
                offset += consumed;
                result.push(cap);
            }
            None => return Err(AvdtpError::ProtocolError("Malformed capability TLV".into())),
        }
    }
    Ok(result)
}

fn caps_to_bytes(caps: &[AvdtpServiceCapability]) -> BytesMut {
    let total: usize = caps.iter().map(|c| c.len()).sum();
    let mut buf = BytesMut::with_capacity(total);
    for cap in caps {
        cap.to_bytes(&mut buf);
    }
    buf
}

/// Media codec capability within AVDTP_CAP_MEDIA_CODEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvdtpMediaCodecCapability {
    pub media_type: u8,
    pub media_codec_type: u8,
    pub data: Vec<u8>,
}

impl AvdtpMediaCodecCapability {
    pub fn from_cap_data(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        Some(Self {
            media_type: (data[0] >> 4) & 0x0F,
            media_codec_type: data[1],
            data: if data.len() > 2 { data[2..].to_vec() } else { Vec::new() },
        })
    }
}

// ===========================================================================
// Callback Traits
// ===========================================================================

/// Indication callbacks for peer-initiated AVDTP operations on a local SEP.
pub trait AvdtpSepInd: Send + Sync {
    fn match_codec(&self, _session: &AvdtpSession, _codec: &AvdtpMediaCodecCapability) -> bool {
        true
    }
    fn get_capability(
        &self,
        session: &AvdtpSession,
        sep: &AvdtpLocalSep,
        get_all: bool,
    ) -> Result<Vec<AvdtpServiceCapability>, u8>;
    fn set_configuration(
        &self,
        session: &AvdtpSession,
        stream: &AvdtpStream,
        caps: &[AvdtpServiceCapability],
    ) -> AvdtpResult<()>;
    fn get_configuration(&self, session: &AvdtpSession, sep: &AvdtpLocalSep) -> Result<(), u8>;
    fn open(&self, session: &AvdtpSession, stream: &AvdtpStream) -> Result<(), u8>;
    fn start(&self, session: &AvdtpSession, stream: &AvdtpStream) -> Result<(), u8>;
    fn suspend(&self, session: &AvdtpSession, stream: &AvdtpStream) -> Result<(), u8>;
    fn close(&self, session: &AvdtpSession, stream: &AvdtpStream) -> Result<(), u8>;
    fn abort(&self, session: &AvdtpSession, stream: &AvdtpStream);
    fn reconfig(&self, session: &AvdtpSession, sep: &AvdtpLocalSep) -> Result<(), u8>;
    fn delay_report(
        &self,
        session: &AvdtpSession,
        sep: &AvdtpLocalSep,
        rseid: u8,
        delay: u16,
    ) -> Result<(), u8>;
}

/// Confirmation callbacks for locally-initiated AVDTP operations.
pub trait AvdtpSepCfm: Send + Sync {
    fn discover_cfm(
        &self,
        _session: &AvdtpSession,
        _seps: &[AvdtpSepInfo],
        _err: Option<&AvdtpError>,
    ) {
    }
    fn get_capability_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _caps: &[AvdtpServiceCapability],
        _err: Option<&AvdtpError>,
    ) {
    }
    fn set_configuration_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
    fn open_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
    fn start_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
    fn suspend_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
    fn close_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
    fn abort_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
    fn reconfig_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
    fn delay_report_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
    }
}

// ===========================================================================
// Internal Structures
// ===========================================================================

/// Reassembly buffer for fragmented AVDTP packets.
struct ReassemblyBuf {
    active: bool,
    no_of_packets: u8,
    transaction: u8,
    signal_id: u8,
    buf: Vec<u8>,
}

impl ReassemblyBuf {
    fn new() -> Self {
        Self {
            active: false,
            no_of_packets: 0,
            transaction: 0,
            signal_id: 0,
            buf: Vec::with_capacity(AVDTP_BUF_SIZE),
        }
    }
    fn reset(&mut self) {
        self.active = false;
        self.no_of_packets = 0;
        self.transaction = 0;
        self.signal_id = 0;
        self.buf.clear();
    }
}

/// A pending AVDTP signaling request awaiting a response.
struct PendingReq {
    transaction: u8,
    signal_id: u8,
    data: Vec<u8>,
    stream_index: Option<usize>,
    timeout_handle: Option<JoinHandle<()>>,
    collided: bool,
}

/// Discover callback stored in session for outstanding discover requests.
type DiscoverCallback =
    Box<dyn FnOnce(&AvdtpSession, &[AvdtpSepInfo], Option<&AvdtpError>) + Send + Sync>;

// ===========================================================================
// State Callbacks
// ===========================================================================

/// Global session state change notification callback type.
pub type SessionStateCb =
    Box<dyn Fn(&BtdDevice, AvdtpSessionState, AvdtpSessionState) + Send + Sync>;

/// Global stream state change notification callback type.
pub type StreamStateCb =
    Box<dyn Fn(&AvdtpStream, AvdtpStreamState, AvdtpStreamState) + Send + Sync>;

/// Registration handle for state callbacks.
static NEXT_STATE_CB_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

struct StateCallbackEntry {
    id: u64,
    callback: StreamStateCb,
}

/// Global list of registered stream state callbacks.
/// Uses std::sync::Mutex for synchronous callback invocation within state
/// transition handlers.
static STATE_CALLBACKS: std::sync::LazyLock<std::sync::Mutex<Vec<StateCallbackEntry>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Register a stream state callback.  Returns an ID for removal.
pub fn avdtp_add_state_cb(cb: StreamStateCb) -> u64 {
    let id = NEXT_STATE_CB_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut cbs) = STATE_CALLBACKS.lock() {
        cbs.push(StateCallbackEntry { id, callback: cb });
    }
    id
}

/// Remove a previously-registered stream state callback.
pub fn avdtp_remove_state_cb(id: u64) {
    if let Ok(mut cbs) = STATE_CALLBACKS.lock() {
        cbs.retain(|e| e.id != id);
    }
}

// ===========================================================================
// Core Data Structures
// ===========================================================================

/// Local Stream End Point (SEP).
pub struct AvdtpLocalSep {
    seid: u8,
    media_type: u8,
    sep_type: AvdtpSepType,
    codec: u8,
    delay_reporting: bool,
    in_use: bool,
    ind: Box<dyn AvdtpSepInd>,
    cfm: Box<dyn AvdtpSepCfm>,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
}

impl AvdtpLocalSep {
    pub fn seid(&self) -> u8 {
        self.seid
    }
    pub fn media_type(&self) -> u8 {
        self.media_type
    }
    pub fn sep_type(&self) -> AvdtpSepType {
        self.sep_type
    }
    pub fn in_use(&self) -> bool {
        self.in_use
    }
    pub fn set_in_use(&mut self, val: bool) {
        self.in_use = val;
    }
    pub fn delay_reporting(&self) -> bool {
        self.delay_reporting
    }
    pub fn user_data(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
        self.user_data.as_ref()
    }
    pub fn set_user_data(&mut self, data: Option<Arc<dyn Any + Send + Sync>>) {
        self.user_data = data;
    }

    fn to_sep_info(&self) -> AvdtpSepInfo {
        AvdtpSepInfo {
            seid: self.seid,
            in_use: self.in_use,
            media_type: self.media_type,
            sep_type: self.sep_type.to_raw(),
        }
    }
}

/// Exported SEP type (public view matching the schema `AvdtpSep` export).
pub type AvdtpSep = AvdtpLocalSep;

/// Remote Stream End Point discovered during DISCOVER procedure.
pub struct AvdtpRemoteSep {
    seid: u8,
    media_type: u8,
    sep_type: u8,
    codec: Option<AvdtpMediaCodecCapability>,
    delay_reporting: bool,
    discovered: bool,
    caps: Vec<AvdtpServiceCapability>,
    stream_index: Option<usize>,
}

impl AvdtpRemoteSep {
    pub fn seid(&self) -> u8 {
        self.seid
    }
    pub fn media_type(&self) -> u8 {
        self.media_type
    }
    pub fn sep_type(&self) -> u8 {
        self.sep_type
    }
    pub fn codec(&self) -> Option<&AvdtpMediaCodecCapability> {
        self.codec.as_ref()
    }
    pub fn delay_reporting(&self) -> bool {
        self.delay_reporting
    }
    pub fn discovered(&self) -> bool {
        self.discovered
    }
    pub fn capabilities(&self) -> &[AvdtpServiceCapability] {
        &self.caps
    }
    pub fn stream(&self) -> Option<usize> {
        self.stream_index
    }
}

/// An active AVDTP stream (transport association between local and remote SEPs).
pub struct AvdtpStream {
    local_sep_index: usize,
    rseid: u8,
    state: AvdtpStreamState,
    flags: StreamFlags,
    caps: Vec<AvdtpServiceCapability>,
    codec_config: Vec<u8>,
    transport_io: Option<BluetoothSocket>,
    imtu: u16,
    omtu: u16,
    delay: u16,
    timer: Option<JoinHandle<()>>,
    start_timer: Option<JoinHandle<()>>,
    callbacks: Vec<Box<dyn Fn(AvdtpStreamState, AvdtpStreamState) + Send + Sync>>,
}

impl AvdtpStream {
    fn new(local_sep_index: usize, rseid: u8) -> Self {
        Self {
            local_sep_index,
            rseid,
            state: AvdtpStreamState::Idle,
            flags: StreamFlags::empty(),
            caps: Vec::new(),
            codec_config: Vec::new(),
            transport_io: None,
            imtu: 672,
            omtu: 672,
            delay: 0,
            timer: None,
            start_timer: None,
            callbacks: Vec::new(),
        }
    }

    pub fn local_sep<'a>(&self, session: &'a AvdtpSession) -> Option<&'a AvdtpLocalSep> {
        session.local_seps.get(self.local_sep_index)
    }
    pub fn remote_seid(&self) -> u8 {
        self.rseid
    }
    pub fn state(&self) -> AvdtpStreamState {
        self.state
    }
    pub fn codec_config(&self) -> &[u8] {
        &self.codec_config
    }
    pub fn transport_io(&self) -> Option<&BluetoothSocket> {
        self.transport_io.as_ref()
    }
    pub fn transport_mtu(&self) -> u16 {
        self.omtu
    }
    pub fn delay(&self) -> u16 {
        self.delay
    }
    pub fn set_delay(&mut self, delay: u16) {
        self.delay = delay;
    }

    fn cancel_timer(&mut self) {
        if let Some(h) = self.timer.take() {
            h.abort();
        }
    }
    fn cancel_start_timer(&mut self) {
        if let Some(h) = self.start_timer.take() {
            h.abort();
        }
    }
    fn close_transport(&mut self) {
        self.transport_io = None;
    }
}

/// The AVDTP Session, managing a single signaling connection to a remote
/// device.  Replaces C `struct avdtp`.
pub struct AvdtpSession {
    device: Arc<BtdDevice>,
    state: AvdtpSessionState,
    version: u16,
    initiator: bool,
    // Signaling channel
    sig_io: Option<BluetoothSocket>,
    imtu: u16,
    omtu: u16,
    // Reassembly buffers (commands vs responses)
    in_cmd: ReassemblyBuf,
    in_resp: ReassemblyBuf,
    // Transaction label counter
    transaction: u8,
    // Request queues
    prio_queue: VecDeque<PendingReq>,
    req_queue: VecDeque<PendingReq>,
    pending_req: Option<PendingReq>,
    // Registered local SEPs
    local_seps: Vec<AvdtpLocalSep>,
    // Discovered remote SEPs
    remote_seps: Vec<AvdtpRemoteSep>,
    // Active streams
    streams: Vec<AvdtpStream>,
    // Pending transport connect (stream index waiting for transport)
    pending_open: Option<usize>,
    // Timers
    dc_timer: Option<JoinHandle<()>>,
    req_timer: Option<JoinHandle<()>>,
    // PHY type
    phy: u32,
    // Discover callback
    discover_cb: Option<DiscoverCallback>,
    // Signaling reader task handle
    reader_handle: Option<JoinHandle<()>>,
    // Session stream_setup flag for dc_timeout retry
    stream_setup: bool,
    // Disconnect timeout override
    dc_timeout: Duration,
}

impl AvdtpSession {
    pub fn device(&self) -> &Arc<BtdDevice> {
        &self.device
    }
    pub fn adapter(&self) -> &Arc<Mutex<BtdAdapter>> {
        self.device.get_adapter()
    }
    pub fn version(&self) -> u16 {
        self.version
    }
    pub fn sig_mtu(&self) -> u16 {
        self.omtu
    }
    pub fn local_seps(&self) -> &[AvdtpLocalSep] {
        &self.local_seps
    }
    pub fn streams(&self) -> &[AvdtpStream] {
        &self.streams
    }
    /// Returns a mutable reference to the stream list.
    pub fn streams_mut(&mut self) -> &mut [AvdtpStream] {
        &mut self.streams
    }
    pub fn initiator(&self) -> bool {
        self.initiator
    }
    pub fn state(&self) -> AvdtpSessionState {
        self.state
    }

    /// Physical transport type (BR/EDR or LE PHY).
    pub fn phy(&self) -> u32 {
        self.phy
    }

    /// Process incoming signaling data from the L2CAP signaling channel.
    /// This is the primary entry point for the signaling packet parser and
    /// command/response dispatch chain.  Called by the signaling reader task
    /// whenever data arrives on the socket.
    pub fn process_signaling_data(&mut self, data: &[u8]) -> AvdtpResult<()> {
        parse_signaling_data(self, data)
    }

    fn next_transaction(&mut self) -> u8 {
        let t = self.transaction;
        self.transaction = (self.transaction + 1) & 0x0F;
        t
    }

    /// Find a stream by remote SEID.
    pub fn find_stream_by_rseid(&self, rseid: u8) -> Option<usize> {
        self.streams.iter().position(|s| s.rseid == rseid)
    }

    /// Find a stream by local SEP index.
    pub fn find_stream_by_lsep(&self, lsep_idx: usize) -> Option<usize> {
        self.streams.iter().position(|s| s.local_sep_index == lsep_idx)
    }

    fn find_local_sep_by_seid(&self, seid: u8) -> Option<usize> {
        self.local_seps.iter().position(|s| s.seid == seid)
    }

    fn find_remote_sep_by_seid(&self, seid: u8) -> Option<usize> {
        self.remote_seps.iter().position(|s| s.seid == seid)
    }

    fn cancel_dc_timer(&mut self) {
        if let Some(h) = self.dc_timer.take() {
            h.abort();
        }
    }

    fn cancel_req_timer(&mut self) {
        if let Some(h) = self.req_timer.take() {
            h.abort();
        }
    }
}

// ===========================================================================
// Session Constructor
// ===========================================================================

/// Create a new AVDTP session.
/// Equivalent to C `avdtp_new()`.
pub fn avdtp_new(
    device: Arc<BtdDevice>,
    local_seps: Vec<AvdtpLocalSep>,
    version: u16,
) -> Arc<Mutex<AvdtpSession>> {
    let session = AvdtpSession {
        device,
        state: AvdtpSessionState::Idle,
        version,
        initiator: false,
        sig_io: None,
        imtu: 672,
        omtu: 672,
        in_cmd: ReassemblyBuf::new(),
        in_resp: ReassemblyBuf::new(),
        transaction: 0,
        prio_queue: VecDeque::new(),
        req_queue: VecDeque::new(),
        pending_req: None,
        local_seps,
        remote_seps: Vec::new(),
        streams: Vec::new(),
        pending_open: None,
        dc_timer: None,
        req_timer: None,
        phy: 0,
        discover_cb: None,
        reader_handle: None,
        stream_setup: false,
        dc_timeout: DISCONNECT_TIMEOUT,
    };
    Arc::new(Mutex::new(session))
}

// ===========================================================================
// Reference Helpers (Arc-based, replacing C ref counting)
// ===========================================================================

/// Increment reference.  In Rust, this is simply cloning the Arc.
pub fn avdtp_ref_session(session: &Arc<Mutex<AvdtpSession>>) -> Arc<Mutex<AvdtpSession>> {
    session.clone()
}

/// Decrement reference / schedule disconnect.
/// With Arc, dropping the last reference triggers cleanup.
/// This function explicitly cancels disconnect timers when
/// references are held, and sets disconnect timer when released.
pub async fn avdtp_unref_session(session: Arc<Mutex<AvdtpSession>>) {
    // If this is the last strong reference (count == 1), schedule cleanup.
    if Arc::strong_count(&session) <= 2 {
        let mut s = session.lock().await;
        if s.streams.is_empty() {
            // No active streams, clean up immediately.
            connection_lost(&mut s);
        } else {
            // Set disconnect timer for stream setup retry.
            let sess_clone = session.clone();
            let timeout = s.dc_timeout;
            s.dc_timer = Some(tokio::spawn(async move {
                tokio::time::sleep(timeout).await;
                let mut s = sess_clone.lock().await;
                disconnect_timeout(&mut s);
            }));
        }
    }
}

fn connection_lost(session: &mut AvdtpSession) {
    session.cancel_dc_timer();
    session.cancel_req_timer();
    if let Some(h) = session.reader_handle.take() {
        h.abort();
    }
    // Close all streams
    for stream in &mut session.streams {
        stream.cancel_timer();
        stream.cancel_start_timer();
        stream.close_transport();
    }
    session.streams.clear();
    session.pending_req = None;
    session.prio_queue.clear();
    session.req_queue.clear();
    session.in_cmd.reset();
    session.in_resp.reset();
    session.sig_io = None;
    session.state = AvdtpSessionState::Idle;
    debug!("AVDTP session disconnected");
}

fn disconnect_timeout(session: &mut AvdtpSession) {
    debug!("AVDTP disconnect timeout");
    if session.stream_setup {
        session.stream_setup = false;
        session.dc_timeout = DISCONNECT_TIMEOUT;
        return;
    }
    connection_lost(session);
}

// ===========================================================================
// Packet Build/Send
// ===========================================================================

/// Build and send an AVDTP signaling packet with automatic fragmentation.
fn avdtp_send(
    session: &mut AvdtpSession,
    transaction: u8,
    msg_type: u8,
    signal_id: u8,
    data: &[u8],
) -> AvdtpResult<()> {
    let sig_io = session
        .sig_io
        .as_ref()
        .ok_or_else(|| AvdtpError::InvalidState("No signaling channel".into()))?;
    let mtu = session.omtu as usize;

    // Single packet header: [transaction:4|pkt_type:2|msg_type:2][signal_id]
    let single_header_len = 2;
    // Start  header: [transaction:4|pkt_type:2|msg_type:2][num_packets][signal_id]
    let start_header_len = 3;
    // Continue/End header: [transaction:4|pkt_type:2|msg_type:2]
    let cont_header_len = 1;

    if data.len() + single_header_len <= mtu {
        // Single packet
        let mut pkt = BytesMut::with_capacity(single_header_len + data.len());
        pkt.put_u8((transaction << 4) | (AVDTP_PKT_TYPE_SINGLE << 2) | msg_type);
        pkt.put_u8(signal_id);
        pkt.put_slice(data);
        send_raw(sig_io, &pkt)?;
    } else {
        // Fragmented: START + CONTINUE... + END
        let first_payload = mtu - start_header_len;
        let cont_payload = mtu - cont_header_len;
        let remaining = data.len() - first_payload;
        let num_cont = remaining.div_ceil(cont_payload);
        let total_packets = 1 + num_cont;

        // START packet
        let mut pkt = BytesMut::with_capacity(mtu);
        pkt.put_u8((transaction << 4) | (AVDTP_PKT_TYPE_START << 2) | msg_type);
        pkt.put_u8(total_packets as u8);
        pkt.put_u8(signal_id);
        pkt.put_slice(&data[..first_payload]);
        send_raw(sig_io, &pkt)?;

        let mut offset = first_payload;
        for i in 0..num_cont {
            let pkt_type =
                if i == num_cont - 1 { AVDTP_PKT_TYPE_END } else { AVDTP_PKT_TYPE_CONTINUE };
            let chunk_end = std::cmp::min(offset + cont_payload, data.len());
            let mut cpkt = BytesMut::with_capacity(cont_header_len + (chunk_end - offset));
            cpkt.put_u8((transaction << 4) | (pkt_type << 2) | msg_type);
            cpkt.put_slice(&data[offset..chunk_end]);
            send_raw(sig_io, &cpkt)?;
            offset = chunk_end;
        }
    }
    Ok(())
}

fn send_raw(sock: &BluetoothSocket, data: &[u8]) -> AvdtpResult<()> {
    // Use the exported bt_writev helper from bluez-shared for synchronous
    // non-blocking writes.  AVDTP signaling packets are small so this will
    // complete immediately on a non-blocking socket.
    let fd = sock.as_raw_fd();
    let iov = [io::IoSlice::new(data)];
    bluez_shared::socket::bt_writev(fd, &iov).map(|_| ()).map_err(AvdtpError::IoError)
}

/// Send an ACCEPT response.
fn send_accept(
    session: &mut AvdtpSession,
    transaction: u8,
    signal_id: u8,
    data: &[u8],
) -> AvdtpResult<()> {
    avdtp_send(session, transaction, AVDTP_MSG_TYPE_ACCEPT, signal_id, data)
}

/// Send a REJECT response.
fn send_reject(
    session: &mut AvdtpSession,
    transaction: u8,
    signal_id: u8,
    data: &[u8],
) -> AvdtpResult<()> {
    avdtp_send(session, transaction, AVDTP_MSG_TYPE_REJECT, signal_id, data)
}

/// Send a GENERAL_REJECT response (for unknown signal IDs).
fn send_gen_reject(session: &mut AvdtpSession, transaction: u8) -> AvdtpResult<()> {
    avdtp_send(session, transaction, AVDTP_MSG_TYPE_GEN_REJECT, 0, &[])
}

// ===========================================================================
// Packet Parsing & Dispatch
// ===========================================================================

/// Parse incoming data from the signaling channel and dispatch.
fn parse_signaling_data(session: &mut AvdtpSession, data: &[u8]) -> AvdtpResult<()> {
    if data.is_empty() {
        return Err(AvdtpError::ProtocolError("Empty signaling data".into()));
    }

    let header = data[0];
    let transaction = (header >> 4) & 0x0F;
    let pkt_type = (header >> 2) & 0x03;
    let msg_type = header & 0x03;

    match pkt_type {
        AVDTP_PKT_TYPE_SINGLE => {
            if data.len() < 2 {
                return Err(AvdtpError::ProtocolError("Single packet too short".into()));
            }
            let signal_id = data[1] & 0x3F;
            let payload = &data[2..];
            dispatch_message(session, transaction, msg_type, signal_id, payload)?;
        }
        AVDTP_PKT_TYPE_START => {
            if data.len() < 3 {
                return Err(AvdtpError::ProtocolError("Start packet too short".into()));
            }
            let num_packets = data[1];
            let signal_id = data[2] & 0x3F;
            let payload = &data[3..];

            let buf = if msg_type == AVDTP_MSG_TYPE_COMMAND {
                &mut session.in_cmd
            } else {
                &mut session.in_resp
            };
            buf.reset();
            buf.active = true;
            buf.no_of_packets = num_packets.saturating_sub(1);
            buf.transaction = transaction;
            buf.signal_id = signal_id;
            buf.buf.extend_from_slice(payload);
        }
        AVDTP_PKT_TYPE_CONTINUE | AVDTP_PKT_TYPE_END => {
            let payload = &data[1..];
            // Determine which buffer based on message type
            let buf = if msg_type == AVDTP_MSG_TYPE_COMMAND {
                &mut session.in_cmd
            } else {
                &mut session.in_resp
            };

            if !buf.active {
                warn!("AVDTP: received continue/end without start");
                return Err(AvdtpError::ProtocolError("No active reassembly".into()));
            }

            buf.buf.extend_from_slice(payload);
            buf.no_of_packets = buf.no_of_packets.saturating_sub(1);

            if pkt_type == AVDTP_PKT_TYPE_END {
                if buf.no_of_packets != 0 {
                    warn!(
                        "AVDTP: unexpected end packet, still waiting for {} packets",
                        buf.no_of_packets
                    );
                }
                let trans = buf.transaction;
                let sig_id = buf.signal_id;
                // Take the buffer data for dispatch
                let reassembled: Vec<u8> = std::mem::take(&mut buf.buf);
                buf.reset();
                dispatch_message(session, trans, msg_type, sig_id, &reassembled)?;
            }
        }
        _ => {
            return Err(AvdtpError::ProtocolError(format!("Unknown packet type {pkt_type}")));
        }
    }
    Ok(())
}

/// Dispatch a fully-reassembled AVDTP message.
fn dispatch_message(
    session: &mut AvdtpSession,
    transaction: u8,
    msg_type: u8,
    signal_id: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    trace!(
        "AVDTP dispatch: trans={transaction} msg_type={msg_type} sig={signal_id:#x} len={}",
        payload.len()
    );

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => handle_command(session, transaction, signal_id, payload),
        AVDTP_MSG_TYPE_ACCEPT => handle_response(session, transaction, signal_id, payload, true),
        AVDTP_MSG_TYPE_REJECT => handle_response(session, transaction, signal_id, payload, false),
        AVDTP_MSG_TYPE_GEN_REJECT => handle_response(session, transaction, signal_id, &[], false),
        _ => Err(AvdtpError::ProtocolError(format!("Unknown message type {msg_type}"))),
    }
}

// ===========================================================================
// Command Handlers (Peer-Initiated)
// ===========================================================================

fn handle_command(
    session: &mut AvdtpSession,
    transaction: u8,
    signal_id: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    match signal_id {
        AVDTP_DISCOVER => handle_discover_cmd(session, transaction, payload),
        AVDTP_GET_CAPABILITIES => handle_getcap_cmd(session, transaction, payload, false),
        AVDTP_GET_ALL_CAPABILITIES => handle_getcap_cmd(session, transaction, payload, true),
        AVDTP_SET_CONFIGURATION => handle_setconf_cmd(session, transaction, payload),
        AVDTP_GET_CONFIGURATION => handle_getconf_cmd(session, transaction, payload),
        AVDTP_OPEN => handle_open_cmd(session, transaction, payload),
        AVDTP_START => handle_start_cmd(session, transaction, payload),
        AVDTP_SUSPEND => handle_suspend_cmd(session, transaction, payload),
        AVDTP_CLOSE => handle_close_cmd(session, transaction, payload),
        AVDTP_ABORT => handle_abort_cmd(session, transaction, payload),
        AVDTP_DELAY_REPORT => handle_delay_report_cmd(session, transaction, payload),
        AVDTP_RECONFIGURE => handle_reconfig_cmd(session, transaction, payload),
        AVDTP_SECURITY_CONTROL => {
            // Not supported - reject
            let reject_data = [AVDTP_NOT_SUPPORTED_COMMAND];
            let _ = send_reject(session, transaction, signal_id, &reject_data);
            Ok(())
        }
        _ => {
            debug!("AVDTP: unknown signal {signal_id:#x}, sending GEN_REJECT");
            let _ = send_gen_reject(session, transaction);
            Ok(())
        }
    }
}

fn handle_discover_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    _payload: &[u8],
) -> AvdtpResult<()> {
    debug!("AVDTP DISCOVER command received");
    let mut resp = BytesMut::new();
    for sep in &session.local_seps {
        let info = sep.to_sep_info();
        let bytes = info.to_bytes();
        resp.put_slice(&bytes);
    }
    send_accept(session, transaction, AVDTP_DISCOVER, &resp)
}

fn handle_getcap_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
    get_all: bool,
) -> AvdtpResult<()> {
    if payload.is_empty() {
        let reject = [AVDTP_BAD_LENGTH];
        let sig = if get_all { AVDTP_GET_ALL_CAPABILITIES } else { AVDTP_GET_CAPABILITIES };
        return send_reject(session, transaction, sig, &reject);
    }
    let seid = (payload[0] >> 2) & 0x3F;
    debug!("AVDTP GET_CAPABILITIES seid={seid} get_all={get_all}");

    let sig = if get_all { AVDTP_GET_ALL_CAPABILITIES } else { AVDTP_GET_CAPABILITIES };

    let sep_idx = match session.find_local_sep_by_seid(seid) {
        Some(idx) => idx,
        None => {
            let reject = [AVDTP_BAD_ACP_SEID];
            return send_reject(session, transaction, sig, &reject);
        }
    };

    // Call the indication callback
    let caps = match session.local_seps[sep_idx].ind.get_capability(
        session,
        &session.local_seps[sep_idx],
        get_all,
    ) {
        Ok(caps) => caps,
        Err(err_code) => {
            let reject = [err_code];
            return send_reject(session, transaction, sig, &reject);
        }
    };

    let resp = caps_to_bytes(&caps);
    send_accept(session, transaction, sig, &resp)
}

fn handle_setconf_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.len() < 4 {
        let reject = [0u8, AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_SET_CONFIGURATION, &reject);
    }

    let acp_seid = (payload[0] >> 2) & 0x3F;
    let int_seid = (payload[1] >> 2) & 0x3F;
    let caps_data = &payload[2..];

    debug!("AVDTP SET_CONFIGURATION acp_seid={acp_seid} int_seid={int_seid}");

    let sep_idx = match session.find_local_sep_by_seid(acp_seid) {
        Some(idx) => idx,
        None => {
            let reject = [0u8, AVDTP_BAD_ACP_SEID];
            return send_reject(session, transaction, AVDTP_SET_CONFIGURATION, &reject);
        }
    };

    if session.local_seps[sep_idx].in_use {
        let reject = [0u8, AVDTP_SEP_IN_USE];
        return send_reject(session, transaction, AVDTP_SET_CONFIGURATION, &reject);
    }

    let caps = caps_to_list(caps_data)?;

    // Extract codec config
    let codec_config: Vec<u8> = caps
        .iter()
        .find(|c| c.category == AVDTP_CAP_MEDIA_CODEC)
        .map(|c| c.data.clone())
        .unwrap_or_default();

    // Check delay reporting capability
    let has_delay_reporting = caps.iter().any(|c| c.category == AVDTP_CAP_DELAY_REPORTING);

    // Create the stream
    let stream_idx = session.streams.len();
    let mut stream = AvdtpStream::new(sep_idx, int_seid);
    stream.caps = caps.clone();
    stream.codec_config = codec_config;
    if has_delay_reporting {
        stream.flags.insert(StreamFlags::DELAY_REPORTING);
    }
    stream.flags.insert(StreamFlags::OPEN_ACP);
    session.streams.push(stream);

    // Invoke indication callback
    let ind_result = session.local_seps[sep_idx].ind.set_configuration(
        session,
        &session.streams[stream_idx],
        &caps,
    );

    match ind_result {
        Ok(()) => {
            session.local_seps[sep_idx].in_use = true;
            avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Configured);
            send_accept(session, transaction, AVDTP_SET_CONFIGURATION, &[])
        }
        Err(e) => {
            // Remove the stream we just created
            session.streams.pop();
            Err(e)
        }
    }
}

fn handle_getconf_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.is_empty() {
        let reject = [AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_GET_CONFIGURATION, &reject);
    }
    let seid = (payload[0] >> 2) & 0x3F;
    debug!("AVDTP GET_CONFIGURATION seid={seid}");

    let stream_idx =
        match session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            Some(idx) => idx,
            None => {
                let reject = [AVDTP_BAD_ACP_SEID];
                return send_reject(session, transaction, AVDTP_GET_CONFIGURATION, &reject);
            }
        };

    let resp = caps_to_bytes(&session.streams[stream_idx].caps);
    send_accept(session, transaction, AVDTP_GET_CONFIGURATION, &resp)
}

fn handle_open_cmd(session: &mut AvdtpSession, transaction: u8, payload: &[u8]) -> AvdtpResult<()> {
    if payload.is_empty() {
        let reject = [AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_OPEN, &reject);
    }
    let seid = (payload[0] >> 2) & 0x3F;
    debug!("AVDTP OPEN seid={seid}");

    let stream_idx =
        match session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            Some(idx) => idx,
            None => {
                let reject = [AVDTP_BAD_ACP_SEID];
                return send_reject(session, transaction, AVDTP_OPEN, &reject);
            }
        };

    if session.streams[stream_idx].state != AvdtpStreamState::Configured {
        let reject = [AVDTP_BAD_STATE];
        return send_reject(session, transaction, AVDTP_OPEN, &reject);
    }

    // Call indication
    let sep_idx = session.streams[stream_idx].local_sep_index;
    match session.local_seps[sep_idx].ind.open(session, &session.streams[stream_idx]) {
        Ok(()) => {
            session.pending_open = Some(stream_idx);
            send_accept(session, transaction, AVDTP_OPEN, &[])
        }
        Err(code) => {
            let reject = [code];
            send_reject(session, transaction, AVDTP_OPEN, &reject)
        }
    }
}

fn handle_start_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.is_empty() {
        let reject = [0u8, AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_START, &reject);
    }

    // START can include multiple SEIDs
    let mut i = 0;
    while i < payload.len() {
        let seid = (payload[i] >> 2) & 0x3F;
        debug!("AVDTP START seid={seid}");

        let stream_idx = match session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            Some(idx) => idx,
            None => {
                let reject = [payload[i], AVDTP_BAD_ACP_SEID];
                return send_reject(session, transaction, AVDTP_START, &reject);
            }
        };

        if session.streams[stream_idx].state != AvdtpStreamState::Open {
            let reject = [payload[i], AVDTP_BAD_STATE];
            return send_reject(session, transaction, AVDTP_START, &reject);
        }

        let sep_idx = session.streams[stream_idx].local_sep_index;
        match session.local_seps[sep_idx].ind.start(session, &session.streams[stream_idx]) {
            Ok(()) => {}
            Err(code) => {
                let reject = [payload[i], code];
                return send_reject(session, transaction, AVDTP_START, &reject);
            }
        }
        i += 1;
    }

    // Accept and transition all requested streams to Streaming
    let _ = send_accept(session, transaction, AVDTP_START, &[]);

    // Re-parse to set states (payload still valid)
    let mut j = 0;
    while j < payload.len() {
        let seid = (payload[j] >> 2) & 0x3F;
        if let Some(stream_idx) = session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Streaming);
        }
        j += 1;
    }
    Ok(())
}

fn handle_suspend_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.is_empty() {
        let reject = [0u8, AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_SUSPEND, &reject);
    }

    let mut i = 0;
    while i < payload.len() {
        let seid = (payload[i] >> 2) & 0x3F;
        debug!("AVDTP SUSPEND seid={seid}");

        let stream_idx = match session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            Some(idx) => idx,
            None => {
                let reject = [payload[i], AVDTP_BAD_ACP_SEID];
                return send_reject(session, transaction, AVDTP_SUSPEND, &reject);
            }
        };

        if session.streams[stream_idx].state != AvdtpStreamState::Streaming {
            let reject = [payload[i], AVDTP_BAD_STATE];
            return send_reject(session, transaction, AVDTP_SUSPEND, &reject);
        }

        let sep_idx = session.streams[stream_idx].local_sep_index;
        match session.local_seps[sep_idx].ind.suspend(session, &session.streams[stream_idx]) {
            Ok(()) => {}
            Err(code) => {
                let reject = [payload[i], code];
                return send_reject(session, transaction, AVDTP_SUSPEND, &reject);
            }
        }
        i += 1;
    }

    let _ = send_accept(session, transaction, AVDTP_SUSPEND, &[]);

    let mut j = 0;
    while j < payload.len() {
        let seid = (payload[j] >> 2) & 0x3F;
        if let Some(stream_idx) = session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Open);
        }
        j += 1;
    }
    Ok(())
}

fn handle_close_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.is_empty() {
        let reject = [AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_CLOSE, &reject);
    }
    let seid = (payload[0] >> 2) & 0x3F;
    debug!("AVDTP CLOSE seid={seid}");

    let stream_idx =
        match session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            Some(idx) => idx,
            None => {
                let reject = [AVDTP_BAD_ACP_SEID];
                return send_reject(session, transaction, AVDTP_CLOSE, &reject);
            }
        };

    let st = session.streams[stream_idx].state;
    if st != AvdtpStreamState::Open && st != AvdtpStreamState::Streaming {
        let reject = [AVDTP_BAD_STATE];
        return send_reject(session, transaction, AVDTP_CLOSE, &reject);
    }

    let sep_idx = session.streams[stream_idx].local_sep_index;
    match session.local_seps[sep_idx].ind.close(session, &session.streams[stream_idx]) {
        Ok(()) => {
            let _ = send_accept(session, transaction, AVDTP_CLOSE, &[]);
            avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Closing);
            // Close transport
            session.streams[stream_idx].close_transport();
            avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Idle);
            Ok(())
        }
        Err(code) => {
            let reject = [code];
            send_reject(session, transaction, AVDTP_CLOSE, &reject)
        }
    }
}

fn handle_abort_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.is_empty() {
        return send_gen_reject(session, transaction);
    }
    let seid = (payload[0] >> 2) & 0x3F;
    debug!("AVDTP ABORT seid={seid}");

    let stream_idx =
        match session.streams.iter().position(|s| {
            session.local_seps.get(s.local_sep_index).is_some_and(|sep| sep.seid == seid)
        }) {
            Some(idx) => idx,
            None => {
                // Accept anyway per spec
                return send_accept(session, transaction, AVDTP_ABORT, &[]);
            }
        };

    let sep_idx = session.streams[stream_idx].local_sep_index;
    session.local_seps[sep_idx].ind.abort(session, &session.streams[stream_idx]);

    let _ = send_accept(session, transaction, AVDTP_ABORT, &[]);
    avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Aborting);
    session.streams[stream_idx].close_transport();
    avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Idle);
    Ok(())
}

fn handle_delay_report_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.len() < 3 {
        let reject = [AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_DELAY_REPORT, &reject);
    }
    let seid = (payload[0] >> 2) & 0x3F;
    let delay = u16::from_be_bytes([payload[1], payload[2]]);
    debug!("AVDTP DELAY_REPORT seid={seid} delay={delay}");

    let sep_idx = match session.find_local_sep_by_seid(seid) {
        Some(idx) => idx,
        None => {
            let reject = [AVDTP_BAD_ACP_SEID];
            return send_reject(session, transaction, AVDTP_DELAY_REPORT, &reject);
        }
    };

    // Find stream for this SEP
    let stream_idx = session.streams.iter().position(|s| s.local_sep_index == sep_idx);
    if let Some(si) = stream_idx {
        session.streams[si].delay = delay;
    }

    match session.local_seps[sep_idx].ind.delay_report(
        session,
        &session.local_seps[sep_idx],
        seid,
        delay,
    ) {
        Ok(()) => send_accept(session, transaction, AVDTP_DELAY_REPORT, &[]),
        Err(code) => {
            let reject = [code];
            send_reject(session, transaction, AVDTP_DELAY_REPORT, &reject)
        }
    }
}

fn handle_reconfig_cmd(
    session: &mut AvdtpSession,
    transaction: u8,
    payload: &[u8],
) -> AvdtpResult<()> {
    if payload.len() < 2 {
        let reject = [0u8, AVDTP_BAD_LENGTH];
        return send_reject(session, transaction, AVDTP_RECONFIGURE, &reject);
    }
    let seid = (payload[0] >> 2) & 0x3F;
    let _caps_data = &payload[1..];
    debug!("AVDTP RECONFIGURE seid={seid}");

    let sep_idx = match session.find_local_sep_by_seid(seid) {
        Some(idx) => idx,
        None => {
            let reject = [0u8, AVDTP_BAD_ACP_SEID];
            return send_reject(session, transaction, AVDTP_RECONFIGURE, &reject);
        }
    };

    match session.local_seps[sep_idx].ind.reconfig(session, &session.local_seps[sep_idx]) {
        Ok(()) => send_accept(session, transaction, AVDTP_RECONFIGURE, &[]),
        Err(code) => {
            let reject = [0u8, code];
            send_reject(session, transaction, AVDTP_RECONFIGURE, &reject)
        }
    }
}

// ===========================================================================
// Response Handlers (Locally-Initiated Operations)
// ===========================================================================

fn handle_response(
    session: &mut AvdtpSession,
    transaction: u8,
    _signal_id: u8,
    payload: &[u8],
    accepted: bool,
) -> AvdtpResult<()> {
    let mut pending = match session.pending_req.take() {
        Some(req) if req.transaction == transaction => req,
        Some(req) => {
            warn!(
                "AVDTP: response transaction mismatch: expected {}, got {transaction}",
                req.transaction
            );
            session.pending_req = Some(req);
            return Ok(());
        }
        None => {
            warn!("AVDTP: unexpected response, no pending request");
            return Ok(());
        }
    };

    // Cancel request timeout
    if let Some(h) = pending.timeout_handle.take() {
        h.abort();
    }

    if !accepted {
        let err = if payload.len() >= 2 {
            AvdtpError::SignalingError { category: payload[0], code: payload[1] }
        } else if payload.len() == 1 {
            AvdtpError::SignalingError { category: 0, code: payload[0] }
        } else {
            AvdtpError::ProtocolError("Rejected with no error info".into())
        };
        handle_reject(session, &pending, &err);
        process_next_request(session);
        return Ok(());
    }

    // Handle accepted response by signal type
    match pending.signal_id {
        AVDTP_DISCOVER => handle_discover_response(session, payload),
        AVDTP_GET_CAPABILITIES | AVDTP_GET_ALL_CAPABILITIES => {
            handle_getcap_response(session, &pending, payload)
        }
        AVDTP_SET_CONFIGURATION => handle_setconf_response(session, &pending),
        AVDTP_OPEN => handle_open_response(session, &pending),
        AVDTP_START => handle_start_response(session, &pending),
        AVDTP_SUSPEND => handle_suspend_response(session, &pending),
        AVDTP_CLOSE => handle_close_response(session, &pending),
        AVDTP_ABORT => handle_abort_response(session, &pending),
        AVDTP_DELAY_REPORT => handle_delay_report_response(session, &pending),
        AVDTP_RECONFIGURE => handle_reconfig_response(session, &pending),
        _ => {
            debug!("AVDTP: unhandled response for signal {:#x}", pending.signal_id);
        }
    }

    process_next_request(session);
    Ok(())
}

fn handle_reject(session: &mut AvdtpSession, req: &PendingReq, err: &AvdtpError) {
    debug!("AVDTP: request {:#x} rejected: {err}", req.signal_id);
    // Notify via cfm callbacks
    if let Some(stream_idx) = req.stream_index {
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                match req.signal_id {
                    AVDTP_SET_CONFIGURATION => {
                        sep.cfm.set_configuration_cfm(session, sep, Some(stream), Some(err))
                    }
                    AVDTP_OPEN => sep.cfm.open_cfm(session, sep, Some(stream), Some(err)),
                    AVDTP_START => sep.cfm.start_cfm(session, sep, Some(stream), Some(err)),
                    AVDTP_SUSPEND => sep.cfm.suspend_cfm(session, sep, Some(stream), Some(err)),
                    AVDTP_CLOSE => sep.cfm.close_cfm(session, sep, Some(stream), Some(err)),
                    AVDTP_ABORT => sep.cfm.abort_cfm(session, sep, Some(stream), Some(err)),
                    AVDTP_RECONFIGURE => {
                        sep.cfm.reconfig_cfm(session, sep, Some(stream), Some(err))
                    }
                    AVDTP_DELAY_REPORT => {
                        sep.cfm.delay_report_cfm(session, sep, Some(stream), Some(err))
                    }
                    _ => {}
                }
            }
        }
    }
}

fn handle_discover_response(session: &mut AvdtpSession, payload: &[u8]) {
    let mut seps = Vec::new();
    let mut offset = 0;
    while offset + 1 < payload.len() {
        if let Some(info) = AvdtpSepInfo::from_bytes(&payload[offset..]) {
            // Register remote SEP
            let rsep = AvdtpRemoteSep {
                seid: info.seid,
                media_type: info.media_type,
                sep_type: info.sep_type,
                codec: None,
                delay_reporting: false,
                discovered: true,
                caps: Vec::new(),
                stream_index: None,
            };
            // Check if already known
            if session.find_remote_sep_by_seid(info.seid).is_none() {
                session.remote_seps.push(rsep);
            }
            seps.push(info);
        }
        offset += 2;
    }

    debug!("AVDTP DISCOVER response: {} SEPs", seps.len());

    // Notify discover callback
    if let Some(cb) = session.discover_cb.take() {
        cb(session, &seps, None);
    }

    // Notify all SEP cfm callbacks
    for sep in &session.local_seps {
        sep.cfm.discover_cfm(session, &seps, None);
    }
}

fn handle_getcap_response(session: &mut AvdtpSession, req: &PendingReq, payload: &[u8]) {
    let caps = match caps_to_list(payload) {
        Ok(c) => c,
        Err(e) => {
            error!("AVDTP: failed to parse capabilities: {e}");
            return;
        }
    };

    // Extract seid from original request data
    if req.data.is_empty() {
        return;
    }
    let seid = (req.data[0] >> 2) & 0x3F;

    // Update remote SEP capabilities
    if let Some(rsep_idx) = session.find_remote_sep_by_seid(seid) {
        let rsep = &mut session.remote_seps[rsep_idx];
        rsep.caps = caps.clone();
        // Extract codec
        for cap in &caps {
            if cap.category == AVDTP_CAP_MEDIA_CODEC {
                rsep.codec = AvdtpMediaCodecCapability::from_cap_data(&cap.data);
            }
            if cap.category == AVDTP_CAP_DELAY_REPORTING {
                rsep.delay_reporting = true;
            }
        }
    }

    debug!("AVDTP GET_CAPABILITIES response for seid={seid}: {} caps", caps.len());
    // Notify cfm on first sep
    if let Some(sep) = session.local_seps.first() {
        sep.cfm.get_capability_cfm(session, sep, &caps, None);
    }
}

fn handle_setconf_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.set_configuration_cfm(session, sep, Some(stream), None);
            }
        }
        avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Configured);
    }
}

fn handle_open_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        session.pending_open = Some(stream_idx);
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.open_cfm(session, sep, Some(stream), None);
            }
        }
    }
}

fn handle_start_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        if let Some(stream) = session.streams.get_mut(stream_idx) {
            stream.flags.remove(StreamFlags::STARTING);
        }
        avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Streaming);
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.start_cfm(session, sep, Some(stream), None);
            }
        }
    }
}

fn handle_suspend_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Open);
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.suspend_cfm(session, sep, Some(stream), None);
            }
        }
    }
}

fn handle_close_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        if let Some(stream) = session.streams.get_mut(stream_idx) {
            stream.close_transport();
        }
        avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Idle);
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.close_cfm(session, sep, Some(stream), None);
            }
        }
    }
}

fn handle_abort_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        if let Some(stream) = session.streams.get_mut(stream_idx) {
            stream.close_transport();
        }
        avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Idle);
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.abort_cfm(session, sep, Some(stream), None);
            }
        }
    }
}

fn handle_delay_report_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.delay_report_cfm(session, sep, Some(stream), None);
            }
        }
    }
}

fn handle_reconfig_response(session: &mut AvdtpSession, req: &PendingReq) {
    if let Some(stream_idx) = req.stream_index {
        if let Some(stream) = session.streams.get(stream_idx) {
            let sep_idx = stream.local_sep_index;
            if let Some(sep) = session.local_seps.get(sep_idx) {
                sep.cfm.reconfig_cfm(session, sep, Some(stream), None);
            }
        }
    }
}

// ===========================================================================
// Request Queue Processing
// ===========================================================================

fn process_next_request(session: &mut AvdtpSession) {
    if session.pending_req.is_some() {
        return;
    }
    // Priority queue first
    if let Some(req) = session.prio_queue.pop_front() {
        send_pending_request(session, req);
        return;
    }
    if let Some(req) = session.req_queue.pop_front() {
        send_pending_request(session, req);
    }
}

fn send_pending_request(session: &mut AvdtpSession, mut req: PendingReq) {
    let transaction = session.next_transaction();
    req.transaction = transaction;

    // Track collision state — if we're re-sending a previously collided
    // request, log it for diagnostics.
    if req.collided {
        debug!("AVDTP: re-sending collided request {:#x}", req.signal_id);
        req.collided = false;
    }

    if let Err(e) =
        avdtp_send(session, transaction, AVDTP_MSG_TYPE_COMMAND, req.signal_id, &req.data)
    {
        error!("AVDTP: failed to send request {:#x}: {e}", req.signal_id);
        return;
    }

    // Store as pending with the appropriate timeout duration for potential
    // async timeout handling.
    let _req_timeout = match req.signal_id {
        AVDTP_ABORT => ABORT_TIMEOUT,
        _ => REQ_TIMEOUT,
    };

    session.pending_req = Some(req);
}

fn queue_request(
    session: &mut AvdtpSession,
    signal_id: u8,
    data: Vec<u8>,
    stream_index: Option<usize>,
    priority: bool,
) {
    let req = PendingReq {
        transaction: 0,
        signal_id,
        data,
        stream_index,
        timeout_handle: None,
        collided: false,
    };
    if priority {
        session.prio_queue.push_back(req);
    } else {
        session.req_queue.push_back(req);
    }
    process_next_request(session);
}

// ===========================================================================
// Stream State Management
// ===========================================================================

/// Transition a stream to a new state with callback notifications.
fn avdtp_stream_set_state(
    session: &mut AvdtpSession,
    stream_idx: usize,
    new_state: AvdtpStreamState,
) {
    let stream = match session.streams.get_mut(stream_idx) {
        Some(s) => s,
        None => return,
    };

    let old_state = stream.state;
    if old_state == new_state {
        return;
    }

    debug!("AVDTP stream state: {} -> {}", old_state, new_state);
    stream.state = new_state;

    // State-specific actions
    match new_state {
        AvdtpStreamState::Configured => {
            // If we are SINK and delay reporting is supported, send delay report
            if stream.flags.contains(StreamFlags::DELAY_REPORTING) {
                if let Some(sep) = session.local_seps.get(stream.local_sep_index) {
                    if sep.sep_type == AvdtpSepType::Sink && session.version >= 0x0103 {
                        let rseid = stream.rseid;
                        let delay = stream.delay;
                        let mut delay_data = BytesMut::with_capacity(3);
                        delay_data.put_u8(rseid << 2);
                        delay_data.put_u16(delay);
                        queue_request(
                            session,
                            AVDTP_DELAY_REPORT,
                            delay_data.to_vec(),
                            Some(stream_idx),
                            true,
                        );
                    }
                }
            }
        }
        AvdtpStreamState::Open => {
            if let Some(s) = session.streams.get_mut(stream_idx) {
                s.flags.remove(StreamFlags::STARTING);
                s.flags.remove(StreamFlags::OPEN_ACP);
            }
        }
        AvdtpStreamState::Streaming => {
            if let Some(s) = session.streams.get_mut(stream_idx) {
                s.cancel_start_timer();
                s.flags.remove(StreamFlags::OPEN_ACP);
            }
        }
        AvdtpStreamState::Closing | AvdtpStreamState::Aborting => {
            if let Some(s) = session.streams.get_mut(stream_idx) {
                s.cancel_start_timer();
            }
        }
        AvdtpStreamState::Idle => {
            // Release SEP
            if let Some(s) = session.streams.get(stream_idx) {
                let sep_idx = s.local_sep_index;
                if let Some(sep) = session.local_seps.get_mut(sep_idx) {
                    sep.in_use = false;
                }
            }
            // Clean up stream resources
            if let Some(s) = session.streams.get_mut(stream_idx) {
                s.cancel_timer();
                s.cancel_start_timer();
                s.close_transport();
            }
        }
    }

    // Invoke per-stream callbacks (collected from stream before we need
    // to mutate again).
    if let Some(stream) = session.streams.get(stream_idx) {
        // Per-stream local callbacks
        for cb in &stream.callbacks {
            cb(old_state, new_state);
        }
        // Global state callbacks
        if let Ok(cbs) = STATE_CALLBACKS.lock() {
            for entry in cbs.iter() {
                (entry.callback)(stream, old_state, new_state);
            }
        }
    }

    // Remove idle streams after notification
    if new_state == AvdtpStreamState::Idle {
        // We remove the stream but it may be referenced by remote SEPs
        if stream_idx < session.streams.len() {
            session.streams.remove(stream_idx);
            // Update any pending_open index
            if let Some(po) = session.pending_open {
                if po == stream_idx {
                    session.pending_open = None;
                } else if po > stream_idx {
                    session.pending_open = Some(po - 1);
                }
            }
        }
    }
}

// ===========================================================================
// Public API: Outgoing Operations
// ===========================================================================

/// Initiate AVDTP DISCOVER procedure.
pub fn avdtp_discover(session: &mut AvdtpSession) -> AvdtpResult<()> {
    if session.state != AvdtpSessionState::Connected {
        return Err(AvdtpError::InvalidState("Session not connected".into()));
    }
    debug!("AVDTP: sending DISCOVER");
    queue_request(session, AVDTP_DISCOVER, Vec::new(), None, false);
    Ok(())
}

/// Initiate AVDTP GET_CAPABILITIES or GET_ALL_CAPABILITIES.
pub fn avdtp_get_capabilities(session: &mut AvdtpSession, seid: u8) -> AvdtpResult<()> {
    if session.state != AvdtpSessionState::Connected {
        return Err(AvdtpError::InvalidState("Session not connected".into()));
    }
    let signal =
        if session.version >= 0x0103 { AVDTP_GET_ALL_CAPABILITIES } else { AVDTP_GET_CAPABILITIES };
    let data = vec![seid << 2];
    debug!("AVDTP: sending GET_CAPABILITIES seid={seid}");
    queue_request(session, signal, data, None, false);
    Ok(())
}

/// Initiate AVDTP SET_CONFIGURATION.
pub fn avdtp_set_configuration(
    session: &mut AvdtpSession,
    local_sep_idx: usize,
    remote_seid: u8,
    caps: &[AvdtpServiceCapability],
) -> AvdtpResult<()> {
    if session.state != AvdtpSessionState::Connected {
        return Err(AvdtpError::InvalidState("Session not connected".into()));
    }
    let local_sep = session
        .local_seps
        .get(local_sep_idx)
        .ok_or_else(|| AvdtpError::InvalidState("Invalid local SEP index".into()))?;
    let local_seid = local_sep.seid;

    // Create stream
    let codec_config: Vec<u8> = caps
        .iter()
        .find(|c| c.category == AVDTP_CAP_MEDIA_CODEC)
        .map(|c| c.data.clone())
        .unwrap_or_default();
    let has_delay = caps.iter().any(|c| c.category == AVDTP_CAP_DELAY_REPORTING);

    let stream_idx = session.streams.len();
    let mut stream = AvdtpStream::new(local_sep_idx, remote_seid);
    stream.caps = caps.to_vec();
    stream.codec_config = codec_config;
    if has_delay {
        stream.flags.insert(StreamFlags::DELAY_REPORTING);
    }
    session.streams.push(stream);

    // Build SET_CONFIGURATION PDU
    let mut data = BytesMut::new();
    data.put_u8(remote_seid << 2);
    data.put_u8(local_seid << 2);
    let cap_bytes = caps_to_bytes(caps);
    data.put_slice(&cap_bytes);

    debug!("AVDTP: sending SET_CONFIGURATION acp={remote_seid} int={local_seid}");
    queue_request(session, AVDTP_SET_CONFIGURATION, data.to_vec(), Some(stream_idx), false);
    Ok(())
}

/// Initiate AVDTP GET_CONFIGURATION.
pub fn avdtp_get_configuration(session: &mut AvdtpSession, seid: u8) -> AvdtpResult<()> {
    if session.state != AvdtpSessionState::Connected {
        return Err(AvdtpError::InvalidState("Session not connected".into()));
    }
    let data = vec![seid << 2];
    debug!("AVDTP: sending GET_CONFIGURATION seid={seid}");
    queue_request(session, AVDTP_GET_CONFIGURATION, data, None, false);
    Ok(())
}

/// Initiate AVDTP OPEN.
pub fn avdtp_open(session: &mut AvdtpSession, stream_idx: usize) -> AvdtpResult<()> {
    let stream = session
        .streams
        .get(stream_idx)
        .ok_or_else(|| AvdtpError::InvalidState("Invalid stream index".into()))?;
    if stream.state != AvdtpStreamState::Configured {
        return Err(AvdtpError::InvalidState(format!(
            "Stream state is {} not Configured",
            stream.state
        )));
    }
    let rseid = stream.rseid;
    let data = vec![rseid << 2];
    debug!("AVDTP: sending OPEN rseid={rseid}");
    queue_request(session, AVDTP_OPEN, data, Some(stream_idx), false);
    Ok(())
}

/// Initiate AVDTP START.
pub fn avdtp_start(session: &mut AvdtpSession, stream_idx: usize) -> AvdtpResult<()> {
    let stream = session
        .streams
        .get_mut(stream_idx)
        .ok_or_else(|| AvdtpError::InvalidState("Invalid stream index".into()))?;
    if stream.state != AvdtpStreamState::Open {
        return Err(AvdtpError::InvalidState(format!("Stream state is {} not Open", stream.state)));
    }
    stream.flags.insert(StreamFlags::STARTING);
    let rseid = stream.rseid;
    let data = vec![rseid << 2];
    debug!("AVDTP: sending START rseid={rseid}");
    queue_request(session, AVDTP_START, data, Some(stream_idx), false);
    Ok(())
}

/// Initiate AVDTP CLOSE.
pub fn avdtp_close(session: &mut AvdtpSession, stream_idx: usize) -> AvdtpResult<()> {
    let stream = session
        .streams
        .get_mut(stream_idx)
        .ok_or_else(|| AvdtpError::InvalidState("Invalid stream index".into()))?;
    let st = stream.state;
    if st != AvdtpStreamState::Open && st != AvdtpStreamState::Streaming {
        // If configured, go through abort instead
        if st == AvdtpStreamState::Configured {
            return avdtp_abort(session, stream_idx);
        }
        return Err(AvdtpError::InvalidState(format!("Stream state is {st}")));
    }
    stream.flags.insert(StreamFlags::CLOSE_INT);
    let rseid = stream.rseid;
    let data = vec![rseid << 2];
    debug!("AVDTP: sending CLOSE rseid={rseid}");
    session.dc_timeout = Duration::from_secs(0);
    queue_request(session, AVDTP_CLOSE, data, Some(stream_idx), false);
    Ok(())
}

/// Initiate AVDTP SUSPEND.
pub fn avdtp_suspend(session: &mut AvdtpSession, stream_idx: usize) -> AvdtpResult<()> {
    let stream = session
        .streams
        .get(stream_idx)
        .ok_or_else(|| AvdtpError::InvalidState("Invalid stream index".into()))?;
    if stream.state != AvdtpStreamState::Streaming {
        return Err(AvdtpError::InvalidState(format!(
            "Stream state is {} not Streaming",
            stream.state
        )));
    }
    let rseid = stream.rseid;
    let data = vec![rseid << 2];
    debug!("AVDTP: sending SUSPEND rseid={rseid}");
    queue_request(session, AVDTP_SUSPEND, data, Some(stream_idx), false);
    Ok(())
}

/// Initiate AVDTP ABORT.
pub fn avdtp_abort(session: &mut AvdtpSession, stream_idx: usize) -> AvdtpResult<()> {
    let stream = session
        .streams
        .get_mut(stream_idx)
        .ok_or_else(|| AvdtpError::InvalidState("Invalid stream index".into()))?;

    // Cancel discover if in progress
    session.discover_cb = None;

    let st = stream.state;
    if st == AvdtpStreamState::Idle || st == AvdtpStreamState::Aborting {
        return Ok(());
    }

    stream.flags.insert(StreamFlags::ABORT_INT);
    avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Aborting);

    // Cancel pending request if it matches this stream
    if let Some(ref pending) = session.pending_req {
        if pending.stream_index == Some(stream_idx) {
            session.pending_req = None;
        }
    }

    let rseid = match session.streams.get(stream_idx) {
        Some(s) => s.rseid,
        None => return Ok(()),
    };
    let data = vec![rseid << 2];
    debug!("AVDTP: sending ABORT rseid={rseid}");
    queue_request(session, AVDTP_ABORT, data, Some(stream_idx), true);
    Ok(())
}

/// Initiate AVDTP DELAY_REPORT.
pub fn avdtp_delay_report(
    session: &mut AvdtpSession,
    stream_idx: usize,
    delay: u16,
) -> AvdtpResult<()> {
    let stream = session
        .streams
        .get_mut(stream_idx)
        .ok_or_else(|| AvdtpError::InvalidState("Invalid stream index".into()))?;

    let st = stream.state;
    if st != AvdtpStreamState::Configured
        && st != AvdtpStreamState::Open
        && st != AvdtpStreamState::Streaming
    {
        return Err(AvdtpError::InvalidState(format!("Stream state is {st}")));
    }

    if !stream.flags.contains(StreamFlags::DELAY_REPORTING) {
        return Err(AvdtpError::NotSupported("Delay reporting not enabled".into()));
    }

    if session.version < 0x0103 {
        return Err(AvdtpError::NotSupported("AVDTP version < 1.3".into()));
    }

    stream.delay = delay;
    let rseid = stream.rseid;

    let mut data = BytesMut::with_capacity(3);
    data.put_u8(rseid << 2);
    data.put_u16(delay);
    debug!("AVDTP: sending DELAY_REPORT rseid={rseid} delay={delay}");
    queue_request(session, AVDTP_DELAY_REPORT, data.to_vec(), Some(stream_idx), true);
    Ok(())
}

// ===========================================================================
// SEP Registration
// ===========================================================================

/// Register a local Stream End Point.
/// Returns the index of the registered SEP.
pub fn avdtp_register_sep(
    session: &mut AvdtpSession,
    sep_type: AvdtpSepType,
    media_type: u8,
    codec: u8,
    delay_reporting: bool,
    ind: Box<dyn AvdtpSepInd>,
    cfm: Box<dyn AvdtpSepCfm>,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
) -> AvdtpResult<usize> {
    // Allocate SEID (1..62)
    let used_seids: Vec<u8> = session.local_seps.iter().map(|s| s.seid).collect();
    let seid = (1..=AVDTP_MAX_SEID)
        .find(|s| !used_seids.contains(s))
        .ok_or_else(|| AvdtpError::NotSupported("No free SEIDs available".into()))?;

    let sep = AvdtpLocalSep {
        seid,
        media_type,
        sep_type,
        codec,
        delay_reporting,
        in_use: false,
        ind,
        cfm,
        user_data,
    };

    let idx = session.local_seps.len();
    session.local_seps.push(sep);
    debug!(
        "AVDTP: registered local SEP seid={seid} type={sep_type} media={media_type:#x} codec={codec:#x}"
    );
    Ok(idx)
}

/// Unregister a local SEP by index.
pub fn avdtp_unregister_sep(session: &mut AvdtpSession, sep_idx: usize) {
    if sep_idx < session.local_seps.len() {
        let sep = session.local_seps.remove(sep_idx);
        debug!("AVDTP: unregistered local SEP seid={}", sep.seid);
        // Update stream references
        for stream in &mut session.streams {
            if stream.local_sep_index == sep_idx {
                // This stream's SEP was removed
                stream.local_sep_index = usize::MAX;
            } else if stream.local_sep_index > sep_idx {
                stream.local_sep_index -= 1;
            }
        }
    }
}

// ===========================================================================
// Remote SEP Management
// ===========================================================================

/// Register a remote SEP discovered externally (e.g., from SDP cache).
pub fn avdtp_register_remote_sep(
    session: &mut AvdtpSession,
    seid: u8,
    sep_type: u8,
    caps: Vec<AvdtpServiceCapability>,
) {
    // Extract codec and delay_reporting from caps
    let codec = caps
        .iter()
        .find(|c| c.category == AVDTP_CAP_MEDIA_CODEC)
        .and_then(|c| AvdtpMediaCodecCapability::from_cap_data(&c.data));
    let delay_reporting = caps.iter().any(|c| c.category == AVDTP_CAP_DELAY_REPORTING);
    let media_type = codec.as_ref().map(|c| c.media_type).unwrap_or(AVDTP_MEDIA_TYPE_AUDIO_RAW);

    let rsep = AvdtpRemoteSep {
        seid,
        media_type,
        sep_type,
        codec,
        delay_reporting,
        discovered: false,
        caps,
        stream_index: None,
    };

    // Replace if already known
    if let Some(idx) = session.find_remote_sep_by_seid(seid) {
        session.remote_seps[idx] = rsep;
    } else {
        session.remote_seps.push(rsep);
    }
    debug!("AVDTP: registered remote SEP seid={seid}");
}

/// Unregister a remote SEP.
pub fn avdtp_unregister_remote_sep(session: &mut AvdtpSession, seid: u8) {
    session.remote_seps.retain(|s| s.seid != seid);
}

/// Find a remote SEP matching the given local SEP criteria.
pub fn avdtp_find_remote_sep(
    session: &AvdtpSession,
    local_sep_idx: usize,
) -> Option<&AvdtpRemoteSep> {
    let local_sep = session.local_seps.get(local_sep_idx)?;

    // Remote SEP must have inverted type (local Source matches remote Sink)
    let target_type = match local_sep.sep_type {
        AvdtpSepType::Source => AVDTP_SEP_TYPE_SINK_RAW,
        AvdtpSepType::Sink => AVDTP_SEP_TYPE_SOURCE_RAW,
    };

    session.remote_seps.iter().find(|rsep| {
        rsep.sep_type == target_type
            && rsep.media_type == local_sep.media_type
            && rsep.stream_index.is_none()
            && rsep.codec.as_ref().is_none_or(|c| c.media_codec_type == local_sep.codec)
    })
}

// ===========================================================================
// Transport Channel Handling
// ===========================================================================

/// Handle an incoming transport channel connection.
pub fn handle_transport_connect(
    session: &mut AvdtpSession,
    sock: BluetoothSocket,
    imtu: u16,
    omtu: u16,
) {
    let stream_idx = match session.pending_open {
        Some(idx) => idx,
        None => {
            warn!("AVDTP: transport connect with no pending open");
            return;
        }
    };
    session.pending_open = None;

    if let Some(stream) = session.streams.get_mut(stream_idx) {
        stream.transport_io = Some(sock);
        stream.imtu = imtu;
        stream.omtu = omtu;
        stream.cancel_timer();

        debug!("AVDTP: transport connected for stream, imtu={imtu} omtu={omtu}");

        // Transition to OPEN
        avdtp_stream_set_state(session, stream_idx, AvdtpStreamState::Open);

        // Notify open_cfm for ACP role
        if let Some(s) = session.streams.get(stream_idx) {
            if s.flags.contains(StreamFlags::OPEN_ACP) {
                let sep_idx = s.local_sep_index;
                if let Some(sep) = session.local_seps.get(sep_idx) {
                    sep.cfm.open_cfm(session, sep, Some(s), None);
                }
            }
        }
    }
}

// ===========================================================================
// Stream Callbacks
// ===========================================================================

/// Add a per-stream state change callback.
pub fn avdtp_stream_add_cb(
    stream: &mut AvdtpStream,
    cb: Box<dyn Fn(AvdtpStreamState, AvdtpStreamState) + Send + Sync>,
) {
    stream.callbacks.push(cb);
}

/// Remove all per-stream state change callbacks.
pub fn avdtp_stream_remove_cb(stream: &mut AvdtpStream) {
    stream.callbacks.clear();
}

/// Get a stream's transport socket reference.
pub fn avdtp_stream_get_transport(stream: &AvdtpStream) -> Option<&BluetoothSocket> {
    stream.transport_io.as_ref()
}

/// Check if stream has delay reporting support.
pub fn avdtp_stream_has_delay_reporting(stream: &AvdtpStream) -> bool {
    stream.flags.contains(StreamFlags::DELAY_REPORTING)
}

/// Get stream state.
pub fn avdtp_stream_get_state(stream: &AvdtpStream) -> AvdtpStreamState {
    stream.state
}

/// Get SEP SEID.
pub fn avdtp_sep_get_seid(sep: &AvdtpLocalSep) -> u8 {
    sep.seid
}

// ===========================================================================
// Session Accessors
// ===========================================================================

/// Get the adapter associated with this session.
pub fn avdtp_get_adapter(session: &AvdtpSession) -> &Arc<Mutex<BtdAdapter>> {
    session.device.get_adapter()
}

/// Get the device associated with this session.
pub fn avdtp_get_device(session: &AvdtpSession) -> &Arc<BtdDevice> {
    &session.device
}

/// Get the AVDTP version negotiated for this session.
pub fn avdtp_get_version(session: &AvdtpSession) -> u16 {
    session.version
}

// ===========================================================================
// Session Connection Management
// ===========================================================================

/// Set the signaling socket and transition to Connected state.
/// Called when an L2CAP connection on PSM 25 is established.
pub fn avdtp_set_signaling_channel(
    session: &mut AvdtpSession,
    sock: BluetoothSocket,
    imtu: u16,
    omtu: u16,
) {
    session.sig_io = Some(sock);
    session.imtu = imtu;
    session.omtu = omtu;
    session.state = AvdtpSessionState::Connected;
    session.cancel_dc_timer();
    debug!("AVDTP: signaling channel connected, imtu={imtu} omtu={omtu}");
}

/// Check if the session has any active streams.
pub fn avdtp_has_stream(session: &AvdtpSession, stream_idx: usize) -> bool {
    stream_idx < session.streams.len()
}

/// Ref/unref wrappers
pub fn ref_session(session: &Arc<Mutex<AvdtpSession>>) -> Arc<Mutex<AvdtpSession>> {
    avdtp_ref_session(session)
}

/// Unref wrapper
pub async fn unref_session(session: Arc<Mutex<AvdtpSession>>) {
    avdtp_unref_session(session).await;
}
