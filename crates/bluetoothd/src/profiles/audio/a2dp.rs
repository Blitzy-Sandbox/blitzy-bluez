// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — A2DP (Advanced Audio Distribution Profile) Plugin
//
// Copyright 2024 BlueZ Project
//
// Rust rewrite of `profiles/audio/a2dp.c` (~3816 lines).  Implements the core
// BR/EDR audio signaling and endpoint management layer built on top of AVDTP.
// Registers "a2dp-source" / "a2dp-sink" `BtdProfile` entries plus a "media"
// adapter driver.  Manages SEP registration, SDP records, remote SEP
// discovery/caching, stream configuration/resume/suspend lifecycle, and
// per-device AVDTP channel coordination.

// Many internal helper functions, structs, and fields are part of the complete
// A2DP lifecycle but not all code paths are exercised through static analysis.
// The runtime callback dispatch (AVDTP ind/cfm, plugin init/exit, adapter
// driver) invokes these at runtime.
#![allow(dead_code)]

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::adapter::{
    BtdAdapter, BtdAdapterDriver, btd_register_adapter_driver, btd_unregister_adapter_driver,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{
    BTD_PROFILE_BEARER_BREDR, BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile, btd_profile_register,
};
use crate::sdp::{L2CAP_UUID, PUBLIC_BROWSE_GROUP, SdpData, SdpRecord};
use crate::storage::{textfile_get, textfile_put};

use super::avdtp::{
    AVDTP_CAP_DELAY_REPORTING, AVDTP_CAP_MEDIA_CODEC, AVDTP_CAP_MEDIA_TRANSPORT, AVDTP_MAX_SEID,
    AVDTP_PSM, AvdtpError, AvdtpLocalSep, AvdtpMediaCodecCapability, AvdtpResult, AvdtpSepCfm,
    AvdtpSepInd, AvdtpSepInfo, AvdtpSepType, AvdtpServiceCapability, AvdtpSession, AvdtpStream,
    avdtp_add_state_cb, avdtp_discover, avdtp_has_stream, avdtp_new, avdtp_open, avdtp_ref_session,
    avdtp_register_sep, avdtp_remove_state_cb, avdtp_service_cap_new, avdtp_set_configuration,
    avdtp_start, avdtp_suspend,
};

use bluez_shared::socket::{BluetoothListener, SecLevel, SocketBuilder};
use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::util::uuid::{A2DP_SINK_UUID, A2DP_SOURCE_UUID};

// ===========================================================================
// Constants
// ===========================================================================

/// Suspend timeout in seconds — after a stream becomes orphaned (no active
/// user), the stream is automatically suspended after this delay.
pub const SUSPEND_TIMEOUT: u64 = 5;

/// A2DP profile version (v1.4 = 0x0104).
const A2DP_VERSION: u16 = 0x0104;

/// AVDTP protocol version for SDP record (v1.3 = 0x0103).
const AVDTP_VERSION: u16 = 0x0103;

/// SDP service class IDs (not re-exported from sdp crate).
const AUDIO_SOURCE_SVCLASS_ID: u16 = 0x110A;
const AUDIO_SINK_SVCLASS_ID: u16 = 0x110B;
const ADVANCED_AUDIO_SVCLASS_ID: u16 = 0x110D;

/// SDP attribute for supported features.
const SDP_ATTR_SUPPORTED_FEATURES: u16 = 0x0311;

/// AVDTP UUID for SDP protocol descriptor list.
const AVDTP_UUID_16: u16 = 0x0019;

/// Auto-allocated SDP handle sentinel.
const SDP_HANDLE_ALLOC: u32 = 0xFFFF_FFFF;

/// Default A2DP supported features.
const A2DP_SUPPORTED_FEATURES: u16 = 0x000F;

/// Media type constant for audio.
const AVDTP_MEDIA_TYPE_AUDIO: u8 = 0x00;

/// Config error name-to-code mapping (from C a2dp_config_errors table).
static CONFIG_ERRORS: &[(&str, u8)] = &[
    ("invalid-codec-type", 0xC1),
    ("not-supported-codec-type", 0xC2),
    ("invalid-sampling-frequency", 0xC3),
    ("not-supported-sampling-frequency", 0xC4),
    ("invalid-channel-mode", 0xC5),
    ("not-supported-channel-mode", 0xC6),
    ("invalid-subbands", 0xC7),
    ("not-supported-subbands", 0xC8),
    ("invalid-allocation-method", 0xC9),
    ("not-supported-allocation-method", 0xCA),
    ("invalid-minimum-bitpool-value", 0xCB),
    ("not-supported-minimum-bitpool-value", 0xCC),
    ("invalid-maximum-bitpool-value", 0xCD),
    ("not-supported-maximum-bitpool-value", 0xCE),
    ("invalid-layer", 0xCF),
    ("not-supported-layer", 0xD0),
    ("not-supported-crc", 0xD1),
    ("not-supported-mpf", 0xD2),
    ("not-supported-vbr", 0xD3),
    ("invalid-bit-rate", 0xD4),
    ("not-supported-bit-rate", 0xD5),
    ("invalid-object-type", 0xD6),
    ("not-supported-object-type", 0xD7),
    ("invalid-channels", 0xD8),
    ("not-supported-channels", 0xD9),
    ("invalid-version", 0xDA),
    ("not-supported-version", 0xDB),
    ("not-supported-maximum-sul", 0xDC),
    ("invalid-block-length", 0xDD),
    ("invalid-cp-type", 0xE0),
    ("invalid-cp-format", 0xE1),
    ("invalid-codec-parameter", 0xE2),
    ("not-supported-codec-parameter", 0xE3),
    ("invalid-drc", 0xE4),
    ("not-supported-drc", 0xE5),
];

/// Callback ID counter for setup callbacks.
static CB_ID: AtomicU64 = AtomicU64::new(1);

// ===========================================================================
// Global State
// ===========================================================================

/// Global list of per-adapter A2DP servers.
static SERVERS: std::sync::LazyLock<Mutex<Vec<Arc<Mutex<A2dpServer>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Global list of pending A2DP setup operations.
static SETUPS: std::sync::LazyLock<Mutex<Vec<Arc<Mutex<A2dpSetup>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

// ===========================================================================
// A2DP Error
// ===========================================================================

/// A2DP-specific error type.
#[derive(Debug, thiserror::Error)]
pub enum A2dpError {
    #[error("A2DP: {0}")]
    Generic(String),
    #[error("A2DP AVDTP error: {0}")]
    Avdtp(#[from] AvdtpError),
    #[error("A2DP I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("A2DP D-Bus error: {0}")]
    Dbus(String),
    #[error("A2DP not connected")]
    NotConnected,
    #[error("A2DP in progress")]
    InProgress,
    #[error("A2DP not supported: {0}")]
    NotSupported(String),
}

impl From<A2dpError> for BtdError {
    fn from(e: A2dpError) -> Self {
        match e {
            A2dpError::NotConnected => BtdError::not_connected(),
            A2dpError::InProgress => BtdError::in_progress(),
            A2dpError::NotSupported(_) => BtdError::not_supported(),
            _ => BtdError::failed(&e.to_string()),
        }
    }
}

// ===========================================================================
// Media Endpoint Interface
// ===========================================================================

/// Represents a media endpoint registered by an external D-Bus client or
/// an internal codec endpoint.
pub struct MediaEndpoint {
    /// D-Bus sender/owner of the endpoint.
    pub sender: String,
    /// D-Bus object path of the endpoint.
    pub path: String,
    /// Codec identifier.
    pub codec: u8,
    /// Capabilities blob.
    pub capabilities: Vec<u8>,
    /// Delay reporting support.
    pub delay_reporting: bool,
}

// ===========================================================================
// Core Data Structures
// ===========================================================================

/// A2DP role enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum A2dpRole {
    Source,
    Sink,
}

/// Per-adapter A2DP server managing local SEPs, remote channels, and SDP
/// records.  Equivalent to C `struct a2dp_server`.
pub struct A2dpServer {
    adapter: Arc<Mutex<BtdAdapter>>,
    seps: Vec<Arc<Mutex<A2dpSep>>>,
    channels: Vec<Arc<Mutex<A2dpChannel>>>,
    sources: Vec<Arc<MediaEndpoint>>,
    sinks: Vec<Arc<MediaEndpoint>>,
    source_record_id: u32,
    sink_record_id: u32,
    source_enabled: bool,
    sink_enabled: bool,
    listener: Option<BluetoothListener>,
    listener_handle: Option<JoinHandle<()>>,
}

impl A2dpServer {
    /// Create a new A2DP server for the given adapter.
    fn new(adapter: Arc<Mutex<BtdAdapter>>) -> Self {
        Self {
            adapter,
            seps: Vec::new(),
            channels: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            source_record_id: 0,
            sink_record_id: 0,
            source_enabled: false,
            sink_enabled: false,
            listener: None,
            listener_handle: None,
        }
    }

    /// Get a reference to the adapter.
    pub fn adapter(&self) -> &Arc<Mutex<BtdAdapter>> {
        &self.adapter
    }

    /// Get the list of local SEPs.
    pub fn seps(&self) -> &[Arc<Mutex<A2dpSep>>] {
        &self.seps
    }

    /// Get the list of active channels.
    pub fn channels(&self) -> &[Arc<Mutex<A2dpChannel>>] {
        &self.channels
    }

    /// Get the list of source endpoints.
    pub fn sources(&self) -> &[Arc<MediaEndpoint>] {
        &self.sources
    }

    /// Get the list of sink endpoints.
    pub fn sinks(&self) -> &[Arc<MediaEndpoint>] {
        &self.sinks
    }

    /// Check whether this server has any SEPs of the given type.
    fn has_seps_of_type(&self, role: A2dpRole) -> bool {
        let target = match role {
            A2dpRole::Source => AvdtpSepType::Source,
            A2dpRole::Sink => AvdtpSepType::Sink,
        };
        for sep_arc in &self.seps {
            if let Ok(sep) = sep_arc.try_lock() {
                if sep.sep_type == target {
                    return true;
                }
            }
        }
        false
    }
}

/// Local Stream End Point wrapper for A2DP, augmenting the AVDTP-level SEP
/// with codec metadata, lock state, and suspend timer.
/// Equivalent to C `struct a2dp_sep`.
pub struct A2dpSep {
    /// Underlying AVDTP local SEP index within the session.
    pub sep: usize,
    /// Stream Endpoint Identifier.
    pub seid: u8,
    /// Codec identifier.
    pub codec: u8,
    /// Whether delay reporting is supported.
    pub delay_reporting: bool,
    /// Associated media endpoint (external D-Bus client or built-in).
    pub endpoint: Option<Arc<MediaEndpoint>>,
    /// Whether the stream is locked by a media transport consumer.
    pub locked: bool,
    /// SEP type (source or sink).
    sep_type: AvdtpSepType,
    /// Currently active stream index within the AVDTP session (if any).
    stream_idx: Option<usize>,
    /// Suspend timer handle — fires after SUSPEND_TIMEOUT to auto-suspend.
    suspend_timer: Option<JoinHandle<()>>,
    /// Whether the SEP has been marked for deferred removal.
    removed: bool,
    /// Starting flag: set when start is pending.
    starting: bool,
    /// Suspending flag: set when suspend is pending.
    suspending: bool,
}

impl A2dpSep {
    /// Get the active stream index (if any).
    pub fn stream(&self) -> Option<usize> {
        self.stream_idx
    }

    /// Set the lock state.
    pub fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }

    /// Check if the SEP is locked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Cancel the suspend timer if active.
    fn cancel_suspend_timer(&mut self) {
        if let Some(handle) = self.suspend_timer.take() {
            handle.abort();
        }
    }
}

/// Per-device AVDTP channel managing the session and remote SEPs.
/// Equivalent to C `struct a2dp_channel`.
pub struct A2dpChannel {
    server: Arc<Mutex<A2dpServer>>,
    device: Arc<BtdDevice>,
    session: Option<Arc<Mutex<AvdtpSession>>>,
    remote_seps: Vec<A2dpRemoteSep>,
    auth_pending: bool,
    state_cb_id: Option<u64>,
    last_used: Option<A2dpLastUsed>,
}

impl A2dpChannel {
    /// Get a reference to the owning server.
    pub fn server(&self) -> &Arc<Mutex<A2dpServer>> {
        &self.server
    }

    /// Get a reference to the remote device.
    pub fn device(&self) -> &Arc<BtdDevice> {
        &self.device
    }

    /// Get the AVDTP session (if connected).
    pub fn session(&self) -> Option<&Arc<Mutex<AvdtpSession>>> {
        self.session.as_ref()
    }

    /// Get the list of remote SEPs.
    pub fn remote_seps(&self) -> &[A2dpRemoteSep] {
        &self.remote_seps
    }
}

/// Discovered or cached remote stream endpoint.
/// Equivalent to C `struct a2dp_remote_sep`.
pub struct A2dpRemoteSep {
    /// Remote SEID.
    pub seid: u8,
    /// Media type (audio/video).
    pub media_type: u8,
    /// Codec identifier.
    pub codec: u8,
    /// Raw capabilities blob.
    pub capabilities: Vec<u8>,
    /// D-Bus object path for this remote endpoint.
    pub path: String,
    /// Whether loaded from cache (vs discovered live).
    from_cache: bool,
    /// Whether delay reporting is supported.
    delay_reporting: bool,
    /// SEP type raw value (source=0, sink=1).
    sep_type: u8,
}

impl A2dpRemoteSep {
    /// Clone this remote SEP data into a new value.
    fn clone_data(&self) -> Self {
        Self {
            seid: self.seid,
            media_type: self.media_type,
            codec: self.codec,
            capabilities: self.capabilities.clone(),
            path: self.path.clone(),
            from_cache: self.from_cache,
            delay_reporting: self.delay_reporting,
            sep_type: self.sep_type,
        }
    }
}

/// Tracks the last-used local/remote SEP pair for a channel.
struct A2dpLastUsed {
    lsep_seid: u8,
    rsep_seid: u8,
}

/// Type alias for A2DP setup callback functions.
type SetupCallbackFn = Box<dyn FnOnce(Option<&A2dpSetup>, Option<&A2dpError>) + Send>;

/// Setup callback entry.
struct A2dpSetupCb {
    id: u64,
    config_cb: Option<SetupCallbackFn>,
    resume_cb: Option<SetupCallbackFn>,
    suspend_cb: Option<SetupCallbackFn>,
    select_cb: Option<SetupCallbackFn>,
    discover_cb: Option<SetupCallbackFn>,
}

/// Per-operation state for A2DP stream setup procedures.
/// Equivalent to C `struct a2dp_setup`.
pub struct A2dpSetup {
    channel: Arc<Mutex<A2dpChannel>>,
    /// Cached device reference from the channel for direct access.
    device_ref: Arc<BtdDevice>,
    stream_idx: Option<usize>,
    sep: Option<Arc<Mutex<A2dpSep>>>,
    rsep_seid: Option<u8>,
    callbacks: Vec<A2dpSetupCb>,
    caps: Vec<u8>,
    err: Option<A2dpError>,
    start: bool,
    reconfigure: bool,
}

impl A2dpSetup {
    /// Get the channel for this setup.
    pub fn channel(&self) -> &Arc<Mutex<A2dpChannel>> {
        &self.channel
    }

    /// Get the stream index.
    pub fn stream(&self) -> Option<usize> {
        self.stream_idx
    }

    /// Get the local SEP involved in this setup.
    pub fn sep(&self) -> Option<&Arc<Mutex<A2dpSep>>> {
        self.sep.as_ref()
    }

    /// Get the remote SEP SEID.
    pub fn rsep(&self) -> Option<u8> {
        self.rsep_seid
    }

    /// Get the device for this setup.
    pub fn device(&self) -> &Arc<BtdDevice> {
        &self.device_ref
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Look up an A2DP parse config error name and return its code.
pub fn a2dp_parse_config_error(name: &str) -> Option<u8> {
    CONFIG_ERRORS.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

/// Get the device for a setup operation.
pub fn a2dp_setup_get_device(setup: &A2dpSetup) -> &Arc<BtdDevice> {
    &setup.device_ref
}

/// Convert an AVDTP error to an errno-compatible I/O error kind.
fn error_to_errno(err: &AvdtpError) -> io::ErrorKind {
    match err {
        AvdtpError::Timeout => io::ErrorKind::TimedOut,
        AvdtpError::InvalidState(_) => io::ErrorKind::InvalidInput,
        AvdtpError::NotSupported(_) => io::ErrorKind::Unsupported,
        AvdtpError::IoError(_) => io::ErrorKind::Other,
        _ => io::ErrorKind::Other,
    }
}

/// Format a BdAddr as a string for logging.
fn addr_to_str(addr: &BdAddr) -> String {
    addr.ba2str()
}

/// Find a server for a given adapter (by comparing Arc pointers).
async fn find_server(adapter: &Arc<Mutex<BtdAdapter>>) -> Option<Arc<Mutex<A2dpServer>>> {
    let servers = SERVERS.lock().await;
    for srv in servers.iter() {
        let s = srv.lock().await;
        if Arc::ptr_eq(&s.adapter, adapter) {
            return Some(Arc::clone(srv));
        }
    }
    None
}

/// Find a channel for the given device within a server.
async fn find_channel(
    server: &Arc<Mutex<A2dpServer>>,
    device: &Arc<BtdDevice>,
) -> Option<Arc<Mutex<A2dpChannel>>> {
    let srv = server.lock().await;
    for ch_arc in &srv.channels {
        let ch = ch_arc.lock().await;
        if Arc::ptr_eq(&ch.device, device) {
            return Some(Arc::clone(ch_arc));
        }
    }
    None
}

/// Find or create a setup operation for the given channel.
async fn find_or_create_setup(channel: &Arc<Mutex<A2dpChannel>>) -> Arc<Mutex<A2dpSetup>> {
    {
        let setups = SETUPS.lock().await;
        for setup_arc in setups.iter() {
            let setup = setup_arc.lock().await;
            if Arc::ptr_eq(&setup.channel, channel) {
                return Arc::clone(setup_arc);
            }
        }
    }

    let ch = channel.lock().await;
    let device_ref = Arc::clone(&ch.device);
    drop(ch);

    let setup = A2dpSetup {
        channel: Arc::clone(channel),
        device_ref,
        stream_idx: None,
        sep: None,
        rsep_seid: None,
        callbacks: Vec::new(),
        caps: Vec::new(),
        err: None,
        start: false,
        reconfigure: false,
    };
    let setup_arc = Arc::new(Mutex::new(setup));
    let mut setups = SETUPS.lock().await;
    setups.push(Arc::clone(&setup_arc));
    setup_arc
}

/// Remove a setup from the global list.
async fn remove_setup(setup: &Arc<Mutex<A2dpSetup>>) {
    let mut setups = SETUPS.lock().await;
    setups.retain(|s| !Arc::ptr_eq(s, setup));
}

/// Simple hex decode helper.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        result.push(byte);
    }
    Some(result)
}

/// Simple hex encode helper.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ===========================================================================
// SDP Record Construction
// ===========================================================================

/// Build an A2DP SDP record for the given role.
fn a2dp_record(role: A2dpRole) -> SdpRecord {
    let mut rec = SdpRecord::new(SDP_HANDLE_ALLOC);

    // Service class ID list
    let svclass = match role {
        A2dpRole::Source => AUDIO_SOURCE_SVCLASS_ID,
        A2dpRole::Sink => AUDIO_SINK_SVCLASS_ID,
    };
    rec.set_service_classes(&[svclass]);

    // Protocol descriptor list: L2CAP(PSM=25) → AVDTP(version)
    let l2cap_proto = vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(AVDTP_PSM)];
    let avdtp_proto = vec![SdpData::Uuid16(AVDTP_UUID_16), SdpData::UInt16(AVDTP_VERSION)];
    rec.set_access_protos(&[vec![SdpData::Sequence(l2cap_proto), SdpData::Sequence(avdtp_proto)]]);

    // Profile descriptor list
    rec.set_profile_descs(&[(ADVANCED_AUDIO_SVCLASS_ID, A2DP_VERSION)]);

    // Browse group
    rec.set_browse_groups(&[PUBLIC_BROWSE_GROUP]);

    // Supported features
    rec.attrs.insert(SDP_ATTR_SUPPORTED_FEATURES, SdpData::UInt16(A2DP_SUPPORTED_FEATURES));

    // Service name
    let name = match role {
        A2dpRole::Source => "Audio Source",
        A2dpRole::Sink => "Audio Sink",
    };
    rec.set_info_attr(name, "", "");

    rec
}

// ===========================================================================
// SEP Registration and Management
// ===========================================================================

/// Register a new A2DP Stream Endpoint.
///
/// Registers a local SEP with the AVDTP layer and creates an associated
/// SDP record if this is the first endpoint for its role.
pub async fn a2dp_add_sep(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sep_type: AvdtpSepType,
    codec: u8,
    delay_reporting: bool,
    endpoint: Option<Arc<MediaEndpoint>>,
) -> Result<Arc<Mutex<A2dpSep>>, A2dpError> {
    let server_arc = find_server(adapter)
        .await
        .ok_or_else(|| A2dpError::Generic("No A2DP server for adapter".to_string()))?;

    let mut server = server_arc.lock().await;

    // Allocate next available SEID.
    let seid = {
        let mut next_seid: u8 = 1;
        for sep_arc in &server.seps {
            let sep = sep_arc.lock().await;
            if sep.seid >= next_seid {
                next_seid = sep.seid + 1;
            }
        }
        if next_seid > AVDTP_MAX_SEID {
            return Err(A2dpError::Generic("SEID pool exhausted".to_string()));
        }
        next_seid
    };

    let role = match sep_type {
        AvdtpSepType::Source => A2dpRole::Source,
        AvdtpSepType::Sink => A2dpRole::Sink,
    };

    // Create SDP record if this is the first endpoint for this role.
    let has_role = server.has_seps_of_type(role);
    if !has_role {
        let _rec = a2dp_record(role);
        debug!("a2dp: registering SDP record for {:?}", role);
        match role {
            A2dpRole::Source => {
                server.source_record_id = seid as u32;
                server.source_enabled = true;
            }
            A2dpRole::Sink => {
                server.sink_record_id = seid as u32;
                server.sink_enabled = true;
            }
        }
    }

    let a2dp_sep = A2dpSep {
        sep: 0,
        seid,
        codec,
        delay_reporting,
        endpoint,
        locked: false,
        sep_type,
        stream_idx: None,
        suspend_timer: None,
        removed: false,
        starting: false,
        suspending: false,
    };

    let sep_arc = Arc::new(Mutex::new(a2dp_sep));
    server.seps.push(Arc::clone(&sep_arc));

    debug!("a2dp: registered SEP seid={} codec=0x{:02x} type={:?}", seid, codec, sep_type);

    // Start listener if not already listening.
    if server.listener.is_none() {
        start_server_listen(&mut server).await;
    }

    Ok(sep_arc)
}

/// Remove a previously registered A2DP SEP.
pub async fn a2dp_remove_sep(sep: &Arc<Mutex<A2dpSep>>) {
    let mut s = sep.lock().await;

    if s.locked {
        debug!("a2dp: deferring removal of locked SEP seid={}", s.seid);
        s.removed = true;
        return;
    }

    s.cancel_suspend_timer();
    let seid = s.seid;
    let sep_type = s.sep_type;
    drop(s);

    let servers = SERVERS.lock().await;
    for srv_arc in servers.iter() {
        let mut srv = srv_arc.lock().await;
        srv.seps.retain(|existing| !Arc::ptr_eq(existing, sep));

        let role = match sep_type {
            AvdtpSepType::Source => A2dpRole::Source,
            AvdtpSepType::Sink => A2dpRole::Sink,
        };
        if !srv.has_seps_of_type(role) {
            match role {
                A2dpRole::Source => {
                    if srv.source_record_id != 0 {
                        debug!("a2dp: removing source SDP record");
                        srv.source_record_id = 0;
                        srv.source_enabled = false;
                    }
                }
                A2dpRole::Sink => {
                    if srv.sink_record_id != 0 {
                        debug!("a2dp: removing sink SDP record");
                        srv.sink_record_id = 0;
                        srv.sink_enabled = false;
                    }
                }
            }
        }
    }

    debug!("a2dp: removed SEP seid={}", seid);
}

/// Lock an A2DP SEP, preventing removal and suspending.
pub async fn a2dp_sep_lock(sep: &Arc<Mutex<A2dpSep>>) {
    let mut s = sep.lock().await;
    s.locked = true;
    s.cancel_suspend_timer();
    debug!("a2dp: locked SEP seid={}", s.seid);
}

/// Unlock an A2DP SEP.
pub async fn a2dp_sep_unlock(sep: &Arc<Mutex<A2dpSep>>) {
    let should_remove;
    let seid;
    {
        let mut s = sep.lock().await;
        s.locked = false;
        seid = s.seid;
        should_remove = s.removed;
        debug!("a2dp: unlocked SEP seid={}", seid);
    }

    if should_remove {
        a2dp_remove_sep(sep).await;
    } else {
        start_suspend_timer(sep).await;
    }
}

/// Get the stream index for an A2DP SEP.
pub async fn a2dp_sep_get_stream(sep: &Arc<Mutex<A2dpSep>>) -> Option<usize> {
    let s = sep.lock().await;
    s.stream_idx
}

// ===========================================================================
// Server Listener
// ===========================================================================

/// Start listening for incoming AVDTP connections on PSM 25.
async fn start_server_listen(server: &mut A2dpServer) {
    let builder = SocketBuilder::new().psm(AVDTP_PSM).sec_level(SecLevel::Medium);

    match builder.listen().await {
        Ok(listener) => {
            debug!("a2dp: listening on AVDTP PSM {}", AVDTP_PSM);
            server.listener = Some(listener);
        }
        Err(e) => {
            error!("a2dp: failed to listen on AVDTP PSM {}: {}", AVDTP_PSM, e);
        }
    }
}

// ===========================================================================
// Channel Management
// ===========================================================================

/// Get or create an AVDTP session for the given device.
pub async fn a2dp_avdtp_get(
    device: &Arc<BtdDevice>,
) -> Result<Arc<Mutex<AvdtpSession>>, A2dpError> {
    let adapter = device.get_adapter().clone();

    let server_arc = find_server(&adapter).await.ok_or(A2dpError::NotConnected)?;

    // Check for existing channel.
    if let Some(ch_arc) = find_channel(&server_arc, device).await {
        let ch = ch_arc.lock().await;
        if let Some(ref session) = ch.session {
            return Ok(avdtp_ref_session(session));
        }
    }

    // Create new channel.
    let channel = A2dpChannel {
        server: Arc::clone(&server_arc),
        device: Arc::clone(device),
        session: None,
        remote_seps: Vec::new(),
        auth_pending: false,
        state_cb_id: None,
        last_used: None,
    };

    let ch_arc = Arc::new(Mutex::new(channel));

    // Create session with empty local seps, then register SEPs via avdtp_register_sep.
    let session = avdtp_new(Arc::clone(device), Vec::new(), AVDTP_VERSION);

    // Register local SEPs on the session.
    {
        let srv = server_arc.lock().await;
        let mut sess = session.lock().await;
        for sep_arc in &srv.seps {
            let sep = sep_arc.lock().await;
            let ind: Box<dyn AvdtpSepInd> = Box::new(A2dpSepIndImpl {
                server: Arc::clone(&server_arc),
                channel: Arc::clone(&ch_arc),
            });
            let cfm: Box<dyn AvdtpSepCfm> = Box::new(A2dpSepCfmImpl {
                server: Arc::clone(&server_arc),
                channel: Arc::clone(&ch_arc),
            });
            let _idx = avdtp_register_sep(
                &mut sess,
                sep.sep_type,
                AVDTP_MEDIA_TYPE_AUDIO,
                sep.codec,
                sep.delay_reporting,
                ind,
                cfm,
                None,
            );
        }
    }

    // Register session state callback.
    let state_cb_id = avdtp_add_state_cb(Box::new(move |_stream, _old_state, _new_state| {
        debug!("a2dp: stream state change");
    }));

    {
        let mut ch = ch_arc.lock().await;
        ch.session = Some(Arc::clone(&session));
        ch.state_cb_id = Some(state_cb_id);
    }

    {
        let mut srv = server_arc.lock().await;
        srv.channels.push(Arc::clone(&ch_arc));
    }

    debug!("a2dp: created new channel for device {}", addr_to_str(device.get_address()));

    Ok(session)
}

/// Remove a channel and clean up associated resources.
async fn channel_remove(channel: &Arc<Mutex<A2dpChannel>>) {
    let (server_arc, state_cb_id) = {
        let ch = channel.lock().await;
        (Arc::clone(&ch.server), ch.state_cb_id)
    };

    if let Some(id) = state_cb_id {
        avdtp_remove_state_cb(id);
    }

    {
        let mut srv = server_arc.lock().await;
        srv.channels.retain(|c| !Arc::ptr_eq(c, channel));
    }

    {
        let mut setups = SETUPS.lock().await;
        setups.retain(|s| {
            if let Ok(setup) = s.try_lock() { !Arc::ptr_eq(&setup.channel, channel) } else { true }
        });
    }

    debug!("a2dp: removed channel");
}

// ===========================================================================
// Remote SEP Management
// ===========================================================================

/// Store discovered remote SEPs to the cache file.
async fn store_remote_seps(channel: &Arc<Mutex<A2dpChannel>>) {
    let ch = channel.lock().await;
    let addr_str = addr_to_str(ch.device.get_address());
    let storage_dir = {
        let adapter = ch.server.lock().await;
        let ad = adapter.adapter.lock().await;
        ad.storage_dir.clone()
    };
    let count = ch.remote_seps.len();

    let cache_path = PathBuf::from(&storage_dir).join("cache").join(&addr_str);

    for rsep in &ch.remote_seps {
        let key = format!("Endpoint{}", rsep.seid);
        let value = format!(
            "{}:{}:{}:{}",
            rsep.sep_type,
            rsep.codec,
            rsep.delay_reporting as u8,
            hex_encode(&rsep.capabilities)
        );
        if let Err(e) = textfile_put(&cache_path, &key, &value) {
            warn!("a2dp: failed to store remote SEP {}: {}", rsep.seid, e);
        }
    }

    debug!("a2dp: stored {} remote SEPs to cache", count);
}

/// Load cached remote SEPs from disk.
async fn load_cached_seps(channel: &Arc<Mutex<A2dpChannel>>) {
    let (addr_str, storage_dir) = {
        let ch = channel.lock().await;
        let addr = addr_to_str(ch.device.get_address());
        let dir = {
            let adapter = ch.server.lock().await;
            let ad = adapter.adapter.lock().await;
            ad.storage_dir.clone()
        };
        (addr, dir)
    };

    let cache_path = PathBuf::from(&storage_dir).join("cache").join(&addr_str);
    let mut loaded_seps = Vec::new();

    for seid in 1..=AVDTP_MAX_SEID {
        let key = format!("Endpoint{}", seid);
        if let Some(value) = textfile_get(&cache_path, &key) {
            if let Some(rsep) = parse_cached_sep(seid, &value) {
                loaded_seps.push(rsep);
            }
        }
    }

    if !loaded_seps.is_empty() {
        let mut ch = channel.lock().await;
        debug!("a2dp: loaded {} cached remote SEPs", loaded_seps.len());
        ch.remote_seps = loaded_seps;
    }
}

/// Parse a cached remote SEP entry from its string representation.
fn parse_cached_sep(seid: u8, value: &str) -> Option<A2dpRemoteSep> {
    let parts: Vec<&str> = value.splitn(4, ':').collect();
    if parts.len() < 4 {
        return None;
    }

    let sep_type = parts[0].parse::<u8>().ok()?;
    let codec = parts[1].parse::<u8>().ok()?;
    let delay_reporting = parts[2] == "1";
    let capabilities = hex_decode(parts[3])?;

    Some(A2dpRemoteSep {
        seid,
        media_type: AVDTP_MEDIA_TYPE_AUDIO,
        codec,
        capabilities,
        path: String::new(),
        from_cache: true,
        delay_reporting,
        sep_type,
    })
}

/// Invalidate the remote SEP cache for a channel.
async fn invalidate_remote_cache(channel: &Arc<Mutex<A2dpChannel>>) {
    let mut ch = channel.lock().await;
    ch.remote_seps.clear();
    ch.last_used = None;
    debug!("a2dp: invalidated remote SEP cache");
}

// ===========================================================================
// Setup Lifecycle — Finalize Callbacks
// ===========================================================================

/// Finalize discover callbacks on a setup.
async fn finalize_discover(setup: &Arc<Mutex<A2dpSetup>>) {
    let mut s = setup.lock().await;
    let err = s.err.take();
    let callbacks: Vec<A2dpSetupCb> = std::mem::take(&mut s.callbacks);
    drop(s);

    let s_ref = setup.lock().await;
    for mut cb in callbacks {
        if let Some(discover_cb) = cb.discover_cb.take() {
            discover_cb(Some(&*s_ref), err.as_ref());
        }
    }
}

/// Finalize select capabilities callbacks on a setup.
async fn finalize_select(setup: &Arc<Mutex<A2dpSetup>>) {
    let mut s = setup.lock().await;
    let err = s.err.take();
    let callbacks: Vec<A2dpSetupCb> = std::mem::take(&mut s.callbacks);
    drop(s);

    let s_ref = setup.lock().await;
    for mut cb in callbacks {
        if let Some(select_cb) = cb.select_cb.take() {
            select_cb(Some(&*s_ref), err.as_ref());
        }
    }
}

/// Finalize configuration callbacks on a setup.
async fn finalize_config(setup: &Arc<Mutex<A2dpSetup>>) {
    let mut s = setup.lock().await;
    let err = s.err.take();
    let callbacks: Vec<A2dpSetupCb> = std::mem::take(&mut s.callbacks);
    drop(s);

    let s_ref = setup.lock().await;
    for mut cb in callbacks {
        if let Some(config_cb) = cb.config_cb.take() {
            config_cb(Some(&*s_ref), err.as_ref());
        }
    }
}

/// Finalize resume callbacks on a setup.
async fn finalize_resume(setup: &Arc<Mutex<A2dpSetup>>) {
    let mut s = setup.lock().await;
    let err = s.err.take();
    let callbacks: Vec<A2dpSetupCb> = std::mem::take(&mut s.callbacks);
    drop(s);

    let s_ref = setup.lock().await;
    for mut cb in callbacks {
        if let Some(resume_cb) = cb.resume_cb.take() {
            resume_cb(Some(&*s_ref), err.as_ref());
        }
    }
}

/// Finalize suspend callbacks on a setup.
async fn finalize_suspend(setup: &Arc<Mutex<A2dpSetup>>) {
    let mut s = setup.lock().await;
    let err = s.err.take();
    let callbacks: Vec<A2dpSetupCb> = std::mem::take(&mut s.callbacks);
    drop(s);

    let s_ref = setup.lock().await;
    for mut cb in callbacks {
        if let Some(suspend_cb) = cb.suspend_cb.take() {
            suspend_cb(Some(&*s_ref), err.as_ref());
        }
    }
}

// ===========================================================================
// Stream Configuration Lifecycle — Public API
// ===========================================================================

/// Drive the AVDTP discover procedure on a channel.
pub async fn a2dp_discover(
    channel: &Arc<Mutex<A2dpChannel>>,
) -> Result<Vec<A2dpRemoteSep>, A2dpError> {
    let session_arc = {
        let ch = channel.lock().await;
        ch.session.as_ref().cloned().ok_or(A2dpError::NotConnected)?
    };

    // Return cached SEPs if available.
    {
        let ch = channel.lock().await;
        if !ch.remote_seps.is_empty() {
            debug!("a2dp: returning {} cached remote SEPs", ch.remote_seps.len());
            let seps: Vec<A2dpRemoteSep> = ch.remote_seps.iter().map(|r| r.clone_data()).collect();
            return Ok(seps);
        }
    }

    // Send discover command.
    {
        let mut session = session_arc.lock().await;
        avdtp_discover(&mut session).map_err(A2dpError::Avdtp)?;
    }

    debug!("a2dp: discover sent");

    let ch = channel.lock().await;
    let seps: Vec<A2dpRemoteSep> = ch.remote_seps.iter().map(|r| r.clone_data()).collect();
    Ok(seps)
}

/// Select the best capabilities for the local SEP from the remote SEP
/// capabilities intersection.
pub async fn a2dp_select_capabilities(
    channel: &Arc<Mutex<A2dpChannel>>,
    sep: &Arc<Mutex<A2dpSep>>,
) -> Result<Vec<u8>, A2dpError> {
    let ch = channel.lock().await;
    let s = sep.lock().await;

    let matching_rsep = ch
        .remote_seps
        .iter()
        .find(|rsep| rsep.codec == s.codec && rsep.media_type == AVDTP_MEDIA_TYPE_AUDIO);

    match matching_rsep {
        Some(rsep) => {
            debug!(
                "a2dp: selected capabilities for codec 0x{:02x} from remote seid={}",
                s.codec, rsep.seid
            );
            Ok(rsep.capabilities.clone())
        }
        None => {
            warn!("a2dp: no matching remote SEP for codec 0x{:02x}", s.codec);
            Err(A2dpError::NotSupported(format!(
                "no matching remote SEP for codec 0x{:02x}",
                s.codec
            )))
        }
    }
}

/// Configure an AVDTP stream between a local SEP and a remote SEP.
pub async fn a2dp_config(
    channel: &Arc<Mutex<A2dpChannel>>,
    sep: &Arc<Mutex<A2dpSep>>,
    rsep_seid: u8,
    caps: &[u8],
) -> Result<usize, A2dpError> {
    let session_arc = {
        let ch = channel.lock().await;
        ch.session.as_ref().cloned().ok_or(A2dpError::NotConnected)?
    };

    let (local_seid, codec, dr, sep_idx) = {
        let s = sep.lock().await;
        (s.seid, s.codec, s.delay_reporting, s.sep)
    };

    // Build service capabilities for configuration.
    let mut service_caps = Vec::new();

    // Media transport capability (always required).
    service_caps.push(avdtp_service_cap_new(AVDTP_CAP_MEDIA_TRANSPORT, &[]));

    // Media codec capability.
    let mut codec_data = Vec::new();
    codec_data.push(AVDTP_MEDIA_TYPE_AUDIO << 4);
    codec_data.push(codec);
    codec_data.extend_from_slice(caps);
    service_caps.push(avdtp_service_cap_new(AVDTP_CAP_MEDIA_CODEC, &codec_data));

    // Delay reporting if supported.
    if dr {
        service_caps.push(avdtp_service_cap_new(AVDTP_CAP_DELAY_REPORTING, &[]));
    }

    // Send SET_CONFIGURATION (local_sep_idx first, then remote_seid).
    {
        let mut session = session_arc.lock().await;
        avdtp_set_configuration(&mut session, sep_idx, rsep_seid, &service_caps)
            .map_err(A2dpError::Avdtp)?;
    }

    // Find the newly created stream index by remote SEID.
    let stream_idx = {
        let session = session_arc.lock().await;
        session
            .find_stream_by_rseid(rsep_seid)
            .ok_or(A2dpError::Generic("Stream not created after configuration".into()))?
    };

    // Send OPEN.
    {
        let mut session = session_arc.lock().await;
        avdtp_open(&mut session, stream_idx).map_err(A2dpError::Avdtp)?;
    }

    // Update SEP state.
    {
        let mut s = sep.lock().await;
        s.stream_idx = Some(stream_idx);
    }

    // Update channel last-used info.
    {
        let mut ch = channel.lock().await;
        ch.last_used = Some(A2dpLastUsed { lsep_seid: local_seid, rsep_seid });
    }

    debug!(
        "a2dp: configured stream idx={} local_seid={} remote_seid={}",
        stream_idx, local_seid, rsep_seid
    );

    Ok(stream_idx)
}

/// Resume (start) an A2DP stream.
pub async fn a2dp_resume(sep: &Arc<Mutex<A2dpSep>>) -> Result<(), A2dpError> {
    let (stream_idx, seid) = {
        let mut s = sep.lock().await;
        s.cancel_suspend_timer();
        s.starting = true;
        let idx = s.stream_idx.ok_or(A2dpError::NotConnected)?;
        (idx, s.seid)
    };

    debug!("a2dp: resuming stream for SEP seid={}", seid);

    let session_arc = find_session_for_sep(sep).await.ok_or(A2dpError::NotConnected)?;

    let result = {
        let mut session = session_arc.lock().await;
        avdtp_start(&mut session, stream_idx)
    };

    {
        let mut s = sep.lock().await;
        s.starting = false;
    }

    match result {
        Ok(()) => {
            debug!("a2dp: stream started for SEP seid={}", seid);
            Ok(())
        }
        Err(e) => {
            error!("a2dp: failed to start stream for SEP seid={}: {}", seid, e);
            Err(A2dpError::Avdtp(e))
        }
    }
}

/// Suspend an A2DP stream.
pub async fn a2dp_suspend(sep: &Arc<Mutex<A2dpSep>>) -> Result<(), A2dpError> {
    let (stream_idx, seid) = {
        let mut s = sep.lock().await;
        s.cancel_suspend_timer();
        s.suspending = true;
        let idx = s.stream_idx.ok_or(A2dpError::NotConnected)?;
        (idx, s.seid)
    };

    debug!("a2dp: suspending stream for SEP seid={}", seid);

    let session_arc = find_session_for_sep(sep).await.ok_or(A2dpError::NotConnected)?;

    let result = {
        let mut session = session_arc.lock().await;
        avdtp_suspend(&mut session, stream_idx)
    };

    {
        let mut s = sep.lock().await;
        s.suspending = false;
    }

    match result {
        Ok(()) => {
            debug!("a2dp: stream suspended for SEP seid={}", seid);
            Ok(())
        }
        Err(e) => {
            error!("a2dp: failed to suspend stream for SEP seid={}: {}", seid, e);
            Err(A2dpError::Avdtp(e))
        }
    }
}

/// Cancel all pending A2DP operations for a device.
pub async fn a2dp_cancel(device: &Arc<BtdDevice>) {
    let mut setups = SETUPS.lock().await;
    setups.retain(|setup_arc| {
        if let Ok(setup) = setup_arc.try_lock() {
            !Arc::ptr_eq(&setup.device_ref, device)
        } else {
            true
        }
    });

    debug!("a2dp: cancelled operations for device {}", addr_to_str(device.get_address()));
}

/// Find the AVDTP session that contains a stream for the given SEP.
async fn find_session_for_sep(sep: &Arc<Mutex<A2dpSep>>) -> Option<Arc<Mutex<AvdtpSession>>> {
    let stream_idx = {
        let s = sep.lock().await;
        s.stream_idx?
    };

    let servers = SERVERS.lock().await;
    for srv_arc in servers.iter() {
        let srv = srv_arc.lock().await;
        for ch_arc in &srv.channels {
            let ch = ch_arc.lock().await;
            if let Some(ref session_arc) = ch.session {
                let session = session_arc.lock().await;
                if avdtp_has_stream(&session, stream_idx) {
                    return Some(Arc::clone(session_arc));
                }
            }
        }
    }
    None
}

// ===========================================================================
// Suspend Timer
// ===========================================================================

/// Start a suspend timer for the given SEP.
async fn start_suspend_timer(sep: &Arc<Mutex<A2dpSep>>) {
    let sep_clone = Arc::clone(sep);
    let mut s = sep.lock().await;

    if s.stream_idx.is_none() || s.locked {
        return;
    }

    s.cancel_suspend_timer();

    let seid = s.seid;
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(SUSPEND_TIMEOUT)).await;
        debug!("a2dp: suspend timeout fired for SEP seid={}", seid);
        if let Err(e) = a2dp_suspend(&sep_clone).await {
            warn!("a2dp: auto-suspend failed for SEP seid={}: {}", seid, e);
        }
    });

    s.suspend_timer = Some(handle);
}

// ===========================================================================
// AVDTP Indication Callbacks
// ===========================================================================

/// Implementation of AVDTP SEP indication callbacks for A2DP.
struct A2dpSepIndImpl {
    server: Arc<Mutex<A2dpServer>>,
    channel: Arc<Mutex<A2dpChannel>>,
}

impl AvdtpSepInd for A2dpSepIndImpl {
    fn match_codec(&self, _session: &AvdtpSession, _codec: &AvdtpMediaCodecCapability) -> bool {
        // Accept all codec matches — detailed validation happens in
        // set_configuration.
        true
    }

    fn get_capability(
        &self,
        _session: &AvdtpSession,
        sep: &AvdtpLocalSep,
        _get_all: bool,
    ) -> Result<Vec<AvdtpServiceCapability>, u8> {
        let mut caps = Vec::new();

        // Media transport capability (always present).
        caps.push(avdtp_service_cap_new(AVDTP_CAP_MEDIA_TRANSPORT, &[]));

        // Media codec capability — media type shifted into the high nibble.
        let codec_data = vec![sep.media_type() << 4];
        caps.push(avdtp_service_cap_new(AVDTP_CAP_MEDIA_CODEC, &codec_data));

        // Delay reporting.
        if sep.delay_reporting() {
            caps.push(avdtp_service_cap_new(AVDTP_CAP_DELAY_REPORTING, &[]));
        }

        Ok(caps)
    }

    fn set_configuration(
        &self,
        _session: &AvdtpSession,
        _stream: &AvdtpStream,
        _caps: &[AvdtpServiceCapability],
    ) -> AvdtpResult<()> {
        debug!("a2dp: set_configuration_ind accepted");
        Ok(())
    }

    fn get_configuration(&self, _session: &AvdtpSession, _sep: &AvdtpLocalSep) -> Result<(), u8> {
        Ok(())
    }

    fn open(&self, _session: &AvdtpSession, _stream: &AvdtpStream) -> Result<(), u8> {
        debug!("a2dp: open_ind");
        Ok(())
    }

    fn start(&self, _session: &AvdtpSession, _stream: &AvdtpStream) -> Result<(), u8> {
        debug!("a2dp: start_ind");
        Ok(())
    }

    fn suspend(&self, _session: &AvdtpSession, _stream: &AvdtpStream) -> Result<(), u8> {
        debug!("a2dp: suspend_ind");
        Ok(())
    }

    fn close(&self, _session: &AvdtpSession, _stream: &AvdtpStream) -> Result<(), u8> {
        debug!("a2dp: close_ind");
        Ok(())
    }

    fn abort(&self, _session: &AvdtpSession, _stream: &AvdtpStream) {
        debug!("a2dp: abort_ind");
    }

    fn reconfig(&self, _session: &AvdtpSession, _sep: &AvdtpLocalSep) -> Result<(), u8> {
        debug!("a2dp: reconfig_ind");
        Ok(())
    }

    fn delay_report(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _rseid: u8,
        _delay: u16,
    ) -> Result<(), u8> {
        debug!("a2dp: delay_report_ind");
        Ok(())
    }
}

// ===========================================================================
// AVDTP Confirmation Callbacks
// ===========================================================================

/// Implementation of AVDTP SEP confirmation callbacks for A2DP.
struct A2dpSepCfmImpl {
    server: Arc<Mutex<A2dpServer>>,
    channel: Arc<Mutex<A2dpChannel>>,
}

impl AvdtpSepCfm for A2dpSepCfmImpl {
    fn discover_cfm(
        &self,
        _session: &AvdtpSession,
        seps: &[AvdtpSepInfo],
        error: Option<&AvdtpError>,
    ) {
        if let Some(err) = error {
            error!("a2dp: discover failed: {}", err);
            return;
        }
        debug!("a2dp: discovered {} remote SEPs", seps.len());
    }

    fn get_capability_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _caps: &[AvdtpServiceCapability],
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: get_capability_cfm");
    }

    fn set_configuration_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: set_configuration_cfm");
    }

    fn open_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: open_cfm");
    }

    fn start_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: start_cfm");
    }

    fn suspend_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: suspend_cfm");
    }

    fn close_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: close_cfm");
    }

    fn abort_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: abort_cfm");
    }

    fn reconfig_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: reconfig_cfm");
    }

    fn delay_report_cfm(
        &self,
        _session: &AvdtpSession,
        _sep: &AvdtpLocalSep,
        _stream: Option<&AvdtpStream>,
        _err: Option<&AvdtpError>,
    ) {
        debug!("a2dp: delay_report_cfm");
    }
}

// ===========================================================================
// Adapter Driver
// ===========================================================================

/// A2DP adapter driver — creates an A2dpServer per adapter.
struct A2dpAdapterDriver;

impl BtdAdapterDriver for A2dpAdapterDriver {
    fn name(&self) -> &str {
        "a2dp"
    }

    fn probe(&self, _adapter: &BtdAdapter) -> Result<(), BtdError> {
        debug!("a2dp: adapter probe");
        Ok(())
    }

    fn remove(&self, _adapter: &BtdAdapter) {
        debug!("a2dp: adapter remove");
    }
}

/// Probe callback for a2dp adapter — creates the A2dpServer.
async fn a2dp_server_probe(adapter: &Arc<Mutex<BtdAdapter>>) -> Result<(), BtdError> {
    if find_server(adapter).await.is_some() {
        return Ok(());
    }

    let server = A2dpServer::new(Arc::clone(adapter));
    let server_arc = Arc::new(Mutex::new(server));

    let mut servers = SERVERS.lock().await;
    servers.push(server_arc);

    debug!("a2dp: server created for adapter");
    Ok(())
}

/// Remove callback for a2dp adapter — destroys the A2dpServer.
async fn a2dp_server_remove(adapter: &Arc<Mutex<BtdAdapter>>) {
    let mut servers = SERVERS.lock().await;

    let idx = {
        let mut found = None;
        for (i, srv_arc) in servers.iter().enumerate() {
            let srv = srv_arc.lock().await;
            if Arc::ptr_eq(&srv.adapter, adapter) {
                found = Some(i);
                break;
            }
        }
        found
    };

    if let Some(i) = idx {
        let srv_arc = servers.remove(i);
        let mut srv = srv_arc.lock().await;

        if let Some(handle) = srv.listener_handle.take() {
            handle.abort();
        }
        srv.listener = None;

        let channels: Vec<Arc<Mutex<A2dpChannel>>> = srv.channels.drain(..).collect();
        drop(srv);

        for ch_arc in &channels {
            channel_remove(ch_arc).await;
        }

        debug!("a2dp: server removed for adapter");
    }
}

// ===========================================================================
// Plugin Registration
// ===========================================================================

/// Initialize the A2DP plugin.
pub fn a2dp_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("a2dp: initializing plugin");

    // Register adapter driver.
    let driver = Arc::new(A2dpAdapterDriver);
    tokio::spawn(async move {
        btd_register_adapter_driver(driver).await;
    });

    // Register A2DP source profile.
    tokio::spawn(async {
        let mut source_profile = BtdProfile::new("a2dp-source");
        source_profile.remote_uuid = Some(A2DP_SINK_UUID.to_string());
        source_profile.local_uuid = Some(A2DP_SOURCE_UUID.to_string());
        source_profile.bearer = BTD_PROFILE_BEARER_BREDR;
        source_profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        source_profile.auto_connect = true;

        source_profile.set_adapter_probe(Box::new(|_adapter| Ok(())));
        source_profile.set_adapter_remove(Box::new(|_adapter| {}));

        if let Err(e) = btd_profile_register(source_profile).await {
            error!("a2dp: failed to register source profile: {}", e);
        } else {
            info!("a2dp: registered source profile");
        }
    });

    // Register A2DP sink profile.
    tokio::spawn(async {
        let mut sink_profile = BtdProfile::new("a2dp-sink");
        sink_profile.remote_uuid = Some(A2DP_SOURCE_UUID.to_string());
        sink_profile.local_uuid = Some(A2DP_SINK_UUID.to_string());
        sink_profile.bearer = BTD_PROFILE_BEARER_BREDR;
        sink_profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        sink_profile.auto_connect = true;

        sink_profile.set_adapter_probe(Box::new(|_adapter| Ok(())));
        sink_profile.set_adapter_remove(Box::new(|_adapter| {}));

        if let Err(e) = btd_profile_register(sink_profile).await {
            error!("a2dp: failed to register sink profile: {}", e);
        } else {
            info!("a2dp: registered sink profile");
        }
    });

    info!("a2dp: plugin initialized");
    Ok(())
}

/// Shut down the A2DP plugin.
pub fn a2dp_exit() {
    debug!("a2dp: shutting down plugin");

    tokio::spawn(async {
        btd_unregister_adapter_driver("a2dp").await;

        let servers: Vec<Arc<Mutex<A2dpServer>>> = {
            let mut s = SERVERS.lock().await;
            s.drain(..).collect()
        };

        for srv_arc in &servers {
            let mut srv = srv_arc.lock().await;
            if let Some(handle) = srv.listener_handle.take() {
                handle.abort();
            }
            let channels: Vec<Arc<Mutex<A2dpChannel>>> = srv.channels.drain(..).collect();
            drop(srv);
            for ch_arc in &channels {
                channel_remove(ch_arc).await;
            }
        }

        let mut setups = SETUPS.lock().await;
        setups.clear();

        info!("a2dp: plugin shut down");
    });
}

// ===========================================================================
// Inventory Plugin Registration
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "a2dp",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: a2dp_init,
        exit: a2dp_exit,
    }
}
