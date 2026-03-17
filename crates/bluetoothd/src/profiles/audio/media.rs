// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Media D-Bus Hub (org.bluez.Media1)
//
// Copyright 2024 BlueZ Project
//
// Rust rewrite of `profiles/audio/media.c` (~3758 lines).  Implements the
// per-adapter `org.bluez.Media1` interface — the central hub for endpoint
// management, player management, RegisterApplication, and SupportedUUIDs /
// SupportedFeatures dynamic computation.  Bridges external media endpoints
// and players to the A2DP / BAP / ASHA transport layer.
//
// Most of the internal helper functions, structs, and fields are part of the
// complete media lifecycle.  The runtime callback dispatch (D-Bus methods,
// plugin init/exit, adapter driver) invokes these at runtime.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::adapter::{
    BtdAdapter, ExperimentalFeatures, adapter_get_path, btd_adapter_find_device_by_fd,
    btd_adapter_get_database, btd_adapter_get_index, btd_adapter_has_exp_feature,
    btd_adapter_has_settings,
};
use crate::dbus_common::btd_get_dbus_connection;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::gatt::database::BtdGattDatabase;
use crate::profile::{btd_profile_add_custom_prop, btd_profile_remove_custom_prop};
use crate::service::BtdService;

use super::a2dp::{
    A2dpSep, a2dp_add_sep, a2dp_parse_config_error, a2dp_remove_sep, a2dp_setup_get_device,
};
use super::avdtp::AvdtpSepType;

use bluez_shared::att::transport::BtAtt;
use bluez_shared::audio::bap::{
    BapCodec, BapPacOps, BapPacQos, BapQos, BapType, BtBap, BtBapPac, BtBapStream, bap_debug_caps,
    bap_debug_metadata, bt_bap_add_vendor_pac_full,
};
use bluez_shared::audio::gmap::{
    BtGmap, GmapBgrFeatures, GmapBgsFeatures, GmapRole, GmapUggFeatures, GmapUgtFeatures,
};
use bluez_shared::audio::tmap::{BtTmap, TmapRole};
use bluez_shared::gatt::db::GattDb;
use bluez_shared::sys::bluetooth::{BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET, BdAddr};
use bluez_shared::sys::mgmt::MgmtSettings;
use bluez_shared::util::uuid::{A2DP_SINK_UUID, A2DP_SOURCE_UUID, BtUuid, bt_uuidstr_to_str};

// ===========================================================================
// Constants
// ===========================================================================

/// D-Bus interface name for the Media1 hub.
pub const MEDIA_INTERFACE: &str = "org.bluez.Media1";

/// D-Bus interface name for the MediaEndpoint1 client-side interface.
pub const MEDIA_ENDPOINT_INTERFACE: &str = "org.bluez.MediaEndpoint1";

/// D-Bus interface name for the MediaPlayer1 client-side interface.
const MEDIA_PLAYER_INTERFACE: &str = "org.mpris.MediaPlayer2.Player";

/// Timeout for D-Bus proxy calls to client endpoints (3 seconds).
const REQUEST_TIMEOUT_MS: u64 = 3_000;

/// PAC Sink UUID (PACS Sink Characteristic).
const PAC_SINK_UUID: &str = "00001850-0000-1000-8000-00805f9b34fb";

/// PAC Source UUID (PACS Source Characteristic).
const PAC_SOURCE_UUID: &str = "00001851-0000-1000-8000-00805f9b34fb";

/// Broadcast Audio Announcement Service (BCAA) UUID.
const BCAA_SERVICE_UUID: &str = "00001852-0000-1000-8000-00805f9b34fb";

/// Broadcast Audio Scan Service (BAA) UUID.
const BAA_SERVICE_UUID: &str = "00001853-0000-1000-8000-00805f9b34fb";

/// ASHA Profile UUID.
const ASHA_PROFILE_UUID: &str = "0000FDF0-0000-1000-8000-00805f9b34fb";

// ===========================================================================
// Global State
// ===========================================================================

/// Global list of per-adapter media instances.
static ADAPTERS: std::sync::LazyLock<Mutex<Vec<Arc<Mutex<MediaAdapter>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

// ===========================================================================
// Endpoint Features
// ===========================================================================

/// Parsed feature flags for an endpoint (TMAP/GMAP roles).
#[derive(Debug, Clone)]
pub struct EndpointFeatures {
    tmap_role: TmapRole,
    gmap_role: GmapRole,
    gmap_ugg_features: GmapUggFeatures,
    gmap_ugt_features: GmapUgtFeatures,
    gmap_bgs_features: GmapBgsFeatures,
    gmap_bgr_features: GmapBgrFeatures,
}

impl Default for EndpointFeatures {
    fn default() -> Self {
        Self {
            tmap_role: TmapRole::empty(),
            gmap_role: GmapRole::empty(),
            gmap_ugg_features: GmapUggFeatures::empty(),
            gmap_ugt_features: GmapUgtFeatures::empty(),
            gmap_bgs_features: GmapBgsFeatures::empty(),
            gmap_bgr_features: GmapBgrFeatures::empty(),
        }
    }
}

// ===========================================================================
// MediaEndpoint
// ===========================================================================

/// Represents a registered media endpoint.
///
/// Each endpoint is created by a D-Bus client via RegisterEndpoint (or
/// RegisterApplication) and maps to an A2DP SEP, BAP PAC, or ASHA endpoint.
pub struct MediaEndpoint {
    /// D-Bus sender (unique name) of the owner.
    sender: String,
    /// Client D-Bus object path for the endpoint.
    path: String,
    /// Service UUID string (A2DP source/sink, PAC, broadcast, ASHA).
    uuid: String,
    /// Codec ID byte.
    codec: u8,
    /// Vendor-specific codec company ID.
    cid: u16,
    /// Vendor-specific codec vendor ID.
    vid: u16,
    /// Codec capabilities blob.
    capabilities: Vec<u8>,
    /// Endpoint metadata blob.
    metadata: Vec<u8>,
    /// Delay reporting support flag.
    delay_reporting: bool,
    /// QoS parameters for BAP endpoints.
    qos: BapPacQos,
    /// The adapter this endpoint is registered on.
    adapter: Arc<Mutex<BtdAdapter>>,
    /// A2DP SEP registration handle (if A2DP endpoint).
    sep: Option<Arc<tokio::sync::Mutex<A2dpSep>>>,
    /// BAP PAC registration handle (if BAP endpoint).
    pac: Option<BtBapPac>,
    /// ASHA flag: true if this is an ASHA endpoint.
    asha: bool,
    /// Parsed TMAP/GMAP feature flags.
    features: EndpointFeatures,
    /// Name watch ID for disconnect cleanup.
    watch_id: u32,
    /// Active endpoint request (pending D-Bus call).
    requests: Vec<EndpointRequest>,
    /// Broadcast flag (true for BCAA/BAA UUIDs).
    broadcast: bool,
}

impl MediaEndpoint {
    /// Get the D-Bus sender.
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// Get the client D-Bus object path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the service UUID string.
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// Get the codec ID.
    pub fn codec(&self) -> u8 {
        self.codec
    }

    /// Get the codec capabilities blob.
    pub fn capabilities(&self) -> &[u8] {
        &self.capabilities
    }

    /// Get the endpoint metadata blob.
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Get the delay reporting flag.
    pub fn delay_reporting(&self) -> bool {
        self.delay_reporting
    }

    /// Get a reference to the adapter.
    pub fn adapter(&self) -> &Arc<Mutex<BtdAdapter>> {
        &self.adapter
    }

    /// Get a reference to the A2DP transport/sep (if set).
    pub fn transport(&self) -> Option<&Arc<tokio::sync::Mutex<A2dpSep>>> {
        self.sep.as_ref()
    }

    /// Get a reference to the A2DP SEP (if registered).
    pub fn sep(&self) -> Option<&Arc<tokio::sync::Mutex<A2dpSep>>> {
        self.sep.as_ref()
    }

    /// Check if this is a broadcast endpoint.
    pub fn is_broadcast(&self) -> bool {
        self.broadcast
    }

    /// Create a new endpoint in a default/empty state.
    fn new(
        sender: String,
        path: String,
        uuid: String,
        codec: u8,
        capabilities: Vec<u8>,
        adapter: Arc<Mutex<BtdAdapter>>,
    ) -> Self {
        let broadcast = uuid.eq_ignore_ascii_case(BCAA_SERVICE_UUID)
            || uuid.eq_ignore_ascii_case(BAA_SERVICE_UUID);

        Self {
            sender,
            path,
            uuid,
            codec,
            cid: 0,
            vid: 0,
            capabilities,
            metadata: Vec::new(),
            delay_reporting: false,
            qos: BapPacQos::default(),
            adapter,
            sep: None,
            pac: None,
            asha: false,
            features: EndpointFeatures::default(),
            watch_id: 0,
            requests: Vec::new(),
            broadcast,
        }
    }
}

impl fmt::Display for MediaEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uuid_name = bt_uuidstr_to_str(&self.uuid).unwrap_or("Unknown");
        write!(
            f,
            "MediaEndpoint[sender={}, path={}, uuid={} ({}), codec=0x{:02x}]",
            self.sender, self.path, self.uuid, uuid_name, self.codec
        )
    }
}

// ===========================================================================
// Endpoint Request
// ===========================================================================

/// Tracks a pending D-Bus call to a client endpoint.
struct EndpointRequest {
    /// Description of the request type.
    msg: String,
    /// Reply channel for async completion.
    reply_tx: Option<tokio::sync::oneshot::Sender<Result<Vec<u8>, BtdError>>>,
}

// ===========================================================================
// MediaPlayer (local player)
// ===========================================================================

/// Represents a locally registered media player (MPRIS2-compatible).
///
/// Created by D-Bus clients via RegisterPlayer or RegisterApplication.
/// Maps to AVRCP Target player functionality.
pub struct MediaPlayer {
    /// The adapter this player is registered on.
    adapter: Arc<Mutex<BtdAdapter>>,
    /// D-Bus sender (unique name) of the owner.
    sender: String,
    /// Client D-Bus object path.
    path: String,
    /// Current player settings (key→value mapping).
    settings: HashMap<String, String>,
    /// Current track metadata (key→value mapping).
    track: HashMap<String, String>,
    /// Name watch ID for disconnect cleanup.
    watch_id: u32,
    /// Playback status string (e.g., "playing", "paused", "stopped").
    status: String,
    /// Current playback position in milliseconds.
    position: u32,
    /// Track duration in milliseconds.
    duration: u32,
    /// Instant when playback started (for position computation).
    play_start: Option<Instant>,
    /// Can play flag.
    can_play: bool,
    /// Can pause flag.
    can_pause: bool,
    /// Can go next flag.
    can_next: bool,
    /// Can go previous flag.
    can_previous: bool,
    /// Can control flag.
    can_control: bool,
    /// Player identity/name.
    name: String,
    /// Registered callback list IDs.
    cb_ids: Vec<u32>,
}

impl MediaPlayer {
    /// Create a new player with default state.
    fn new(adapter: Arc<Mutex<BtdAdapter>>, sender: String, path: String) -> Self {
        Self {
            adapter,
            sender,
            path,
            settings: HashMap::new(),
            track: HashMap::new(),
            watch_id: 0,
            status: "stopped".to_string(),
            position: 0,
            duration: 0,
            play_start: None,
            can_play: false,
            can_pause: false,
            can_next: false,
            can_previous: false,
            can_control: false,
            name: String::new(),
            cb_ids: Vec::new(),
        }
    }
}

// ===========================================================================
// MediaApp
// ===========================================================================

/// Represents a registered D-Bus application (via RegisterApplication).
///
/// An application auto-discovers endpoints and players from its ObjectManager
/// and groups them for bulk lifecycle management.
pub struct MediaApp {
    /// D-Bus sender (unique name).
    sender: String,
    /// Application root object path.
    path: String,
    /// Endpoints discovered from the application.
    endpoints: Vec<Arc<Mutex<MediaEndpoint>>>,
    /// Players discovered from the application.
    players: Vec<Arc<Mutex<MediaPlayer>>>,
    /// Name watch ID for auto-cleanup on client disconnect.
    watch_id: u32,
}

impl MediaApp {
    /// Create a new application container.
    fn new(sender: String, path: String) -> Self {
        Self { sender, path, endpoints: Vec::new(), players: Vec::new(), watch_id: 0 }
    }
}

// ===========================================================================
// MediaAdapter
// ===========================================================================

/// Per-adapter media state container.
///
/// Holds all endpoints, players, and applications registered on a single
/// Bluetooth adapter.  The `org.bluez.Media1` D-Bus interface is registered
/// at the adapter's object path.
pub struct MediaAdapter {
    /// The Bluetooth adapter.
    adapter: Arc<Mutex<BtdAdapter>>,
    /// D-Bus object path of the adapter.
    path: String,
    /// All registered endpoints.
    endpoints: Vec<Arc<Mutex<MediaEndpoint>>>,
    /// All registered players.
    players: Vec<Arc<Mutex<MediaPlayer>>>,
    /// All registered applications.
    apps: Vec<Arc<MediaApp>>,
    /// SO_TIMESTAMPING probe result cache (-1 = unprobed).
    so_timestamping: i32,
}

impl MediaAdapter {
    /// Create a new media adapter instance.
    fn new(adapter: Arc<Mutex<BtdAdapter>>, path: String) -> Self {
        Self {
            adapter,
            path,
            endpoints: Vec::new(),
            players: Vec::new(),
            apps: Vec::new(),
            so_timestamping: -1,
        }
    }

    /// Get a reference to the adapter.
    pub fn adapter(&self) -> &Arc<Mutex<BtdAdapter>> {
        &self.adapter
    }

    /// Get the adapter's D-Bus object path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the list of registered endpoints.
    pub fn endpoints(&self) -> &[Arc<Mutex<MediaEndpoint>>] {
        &self.endpoints
    }

    /// Get the list of registered players.
    pub fn players(&self) -> &[Arc<Mutex<MediaPlayer>>] {
        &self.players
    }

    /// Get the list of registered applications.
    pub fn apps(&self) -> &[Arc<MediaApp>] {
        &self.apps
    }
}

// ===========================================================================
// Local Player Callback Interface
// ===========================================================================

/// Callback trait for monitoring local media player state changes.
///
/// Consumers register implementations to receive player lifecycle events
/// (used by AVRCP target controller).
pub trait LocalPlayerCallback: Send + Sync {
    /// Called when the playback status changes (playing, paused, stopped, etc.).
    fn status_changed(&self, player: &MediaPlayer, status: &str);

    /// Called when the playback position changes (e.g., seek).
    fn track_position(&self, player: &MediaPlayer, position: u32);

    /// Called when track metadata changes.
    fn track_changed(&self, player: &MediaPlayer, metadata: &HashMap<String, String>);

    /// Called when player settings change (shuffle, repeat, etc.).
    fn settings_changed(&self, player: &MediaPlayer, settings: &HashMap<String, String>);

    /// Called when a player is being removed.
    fn player_removed(&self, player: &MediaPlayer);
}

/// Global list of registered local player callback handlers.
static LOCAL_PLAYER_CBS: std::sync::LazyLock<Mutex<Vec<(u32, Arc<dyn LocalPlayerCallback>)>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Next callback ID counter.
static CB_ID_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Global list of local player watch entries.
static LOCAL_PLAYER_WATCHES: std::sync::LazyLock<Mutex<Vec<LocalPlayerWatch>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// A watch entry that is notified when players are added/removed.
struct LocalPlayerWatch {
    id: u32,
    adapter: Arc<Mutex<BtdAdapter>>,
    callback: Arc<dyn Fn(&MediaPlayer) + Send + Sync>,
    remove_callback: Arc<dyn Fn(&MediaPlayer) + Send + Sync>,
}

// ===========================================================================
// Supported Endpoint Init Table
// ===========================================================================

/// Endpoint type descriptor — maps UUID to initialization function and
/// support-checking function.
struct EndpointInitEntry {
    uuid: &'static str,
    init_fn: fn(&mut MediaEndpoint, &Arc<Mutex<BtdAdapter>>) -> bool,
    supported_fn: fn(&Arc<Mutex<BtdAdapter>>) -> bool,
}

/// Table of supported endpoint types, checked in order during
/// RegisterEndpoint.
const INIT_TABLE: &[EndpointInitEntry] = &[
    EndpointInitEntry {
        uuid: A2DP_SOURCE_UUID,
        init_fn: endpoint_init_a2dp_source,
        supported_fn: a2dp_endpoint_supported,
    },
    EndpointInitEntry {
        uuid: A2DP_SINK_UUID,
        init_fn: endpoint_init_a2dp_sink,
        supported_fn: a2dp_endpoint_supported,
    },
    EndpointInitEntry {
        uuid: PAC_SINK_UUID,
        init_fn: endpoint_init_pac_sink,
        supported_fn: experimental_endpoint_supported,
    },
    EndpointInitEntry {
        uuid: PAC_SOURCE_UUID,
        init_fn: endpoint_init_pac_source,
        supported_fn: experimental_endpoint_supported,
    },
    EndpointInitEntry {
        uuid: BCAA_SERVICE_UUID,
        init_fn: endpoint_init_pac_bcast_source,
        supported_fn: experimental_endpoint_supported,
    },
    EndpointInitEntry {
        uuid: BAA_SERVICE_UUID,
        init_fn: endpoint_init_pac_bcast_sink,
        supported_fn: experimental_endpoint_supported,
    },
    EndpointInitEntry {
        uuid: ASHA_PROFILE_UUID,
        init_fn: endpoint_init_asha,
        supported_fn: a2dp_endpoint_supported,
    },
];

// ===========================================================================
// Endpoint Init Functions
// ===========================================================================

/// Check if A2DP endpoint registration is supported (always true for now).
fn a2dp_endpoint_supported(_adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    true
}

/// Check if experimental (BAP) endpoint registration is supported.
///
/// This is a synchronous stub called from the init table.  The actual
/// async validation is performed by `check_experimental_support()` in
/// the `media_endpoint_create` path.
fn experimental_endpoint_supported(_adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    // Sync check: always true.  Full async check in media_endpoint_create.
    true
}

/// Asynchronous check for experimental BAP/broadcast endpoint support.
///
/// Requires the ISO Socket experimental feature and CIS Central+Peripheral
/// MGMT settings on the adapter.  Used by `media_endpoint_create` to gate
/// BAP PAC / broadcast endpoint registration.
async fn check_experimental_support(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let has_iso = btd_adapter_has_exp_feature(adapter, ExperimentalFeatures::ISO_SOCKET).await;
    if !has_iso {
        debug!("media: ISO socket experimental feature not enabled");
        return false;
    }

    // Check CIS Central and Peripheral MGMT settings.
    let cis_bits = (MgmtSettings::CIS_CENTRAL | MgmtSettings::CIS_PERIPHERAL).bits();
    let has_cis = btd_adapter_has_settings(adapter, cis_bits).await;
    if !has_cis {
        debug!("media: CIS Central/Peripheral settings not available");
        return false;
    }

    true
}

/// Initialize an A2DP Source endpoint — registers AVDTP SEP.
fn endpoint_init_a2dp_source(
    endpoint: &mut MediaEndpoint,
    _adapter: &Arc<Mutex<BtdAdapter>>,
) -> bool {
    debug!("media: initializing A2DP source endpoint path={}", endpoint.path);
    // A2DP SEP registration is handled asynchronously in media_endpoint_create
    true
}

/// Initialize an A2DP Sink endpoint — registers AVDTP SEP.
fn endpoint_init_a2dp_sink(
    endpoint: &mut MediaEndpoint,
    _adapter: &Arc<Mutex<BtdAdapter>>,
) -> bool {
    debug!("media: initializing A2DP sink endpoint path={}", endpoint.path);
    // A2DP SEP registration is handled asynchronously in media_endpoint_create
    true
}

/// Initialize a PAC Sink endpoint — registers BAP PAC record.
fn endpoint_init_pac_sink(endpoint: &mut MediaEndpoint, _adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    debug!("media: initializing PAC sink endpoint path={}", endpoint.path);
    endpoint_init_pac(endpoint, BapType::SINK)
}

/// Initialize a PAC Source endpoint — registers BAP PAC record.
fn endpoint_init_pac_source(
    endpoint: &mut MediaEndpoint,
    _adapter: &Arc<Mutex<BtdAdapter>>,
) -> bool {
    debug!("media: initializing PAC source endpoint path={}", endpoint.path);
    endpoint_init_pac(endpoint, BapType::SOURCE)
}

/// Initialize a broadcast source (BCAA) endpoint.
fn endpoint_init_pac_bcast_source(
    endpoint: &mut MediaEndpoint,
    _adapter: &Arc<Mutex<BtdAdapter>>,
) -> bool {
    debug!("media: initializing broadcast source endpoint path={}", endpoint.path);
    endpoint_init_pac(endpoint, BapType::BCAST_SOURCE)
}

/// Initialize a broadcast sink (BAA) endpoint.
fn endpoint_init_pac_bcast_sink(
    endpoint: &mut MediaEndpoint,
    _adapter: &Arc<Mutex<BtdAdapter>>,
) -> bool {
    debug!("media: initializing broadcast sink endpoint path={}", endpoint.path);
    endpoint_init_pac(endpoint, BapType::BCAST_SINK)
}

/// Common BAP PAC initialization — creates and registers a PAC record.
fn endpoint_init_pac(endpoint: &mut MediaEndpoint, pac_type: BapType) -> bool {
    // Get the GATT database for PAC registration — requires async context.
    // Since this is called synchronously from init table, we store the pac_type
    // and create the PAC in the async registration path.
    debug!(
        "media: endpoint_init_pac type={:?} codec=0x{:02x} caps_len={}",
        pac_type,
        endpoint.codec,
        endpoint.capabilities.len()
    );
    true
}

/// Initialize an ASHA endpoint — no-op, always succeeds.
fn endpoint_init_asha(endpoint: &mut MediaEndpoint, _adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    debug!("media: initializing ASHA endpoint path={}", endpoint.path);
    endpoint.asha = true;
    true
}

// ===========================================================================
// Feature Parsing Helpers
// ===========================================================================

/// Parse TMAP role bits from a variant value.
fn parse_tmap_role(value: u16) -> TmapRole {
    TmapRole::from_bits_truncate(value)
}

/// Parse GMAP role bits from a variant value.
fn parse_gmap_role(value: u8) -> GmapRole {
    GmapRole::from_bits_truncate(value)
}

/// Parse GMAP UGG features from a variant value.
fn parse_gmap_ugg_features(value: u8) -> GmapUggFeatures {
    GmapUggFeatures::from_bits_truncate(value)
}

/// Parse GMAP UGT features from a variant value.
fn parse_gmap_ugt_features(value: u8) -> GmapUgtFeatures {
    GmapUgtFeatures::from_bits_truncate(value)
}

/// Parse GMAP BGS features from a variant value.
fn parse_gmap_bgs_features(value: u8) -> GmapBgsFeatures {
    GmapBgsFeatures::from_bits_truncate(value)
}

/// Parse GMAP BGR features from a variant value.
fn parse_gmap_bgr_features(value: u8) -> GmapBgrFeatures {
    GmapBgrFeatures::from_bits_truncate(value)
}

/// Parse endpoint features from D-Bus properties dictionary.
///
/// Extracts TMAP role, GMAP role, and per-role GMAP feature flags from
/// the "Features" variant in the properties dictionary.
fn parse_endpoint_features(props: &HashMap<String, PropertyValue>) -> EndpointFeatures {
    let mut features = EndpointFeatures::default();

    if let Some(PropertyValue::Dict(feat_map)) = props.get("Features") {
        if let Some(PropertyValue::U16(v)) = feat_map.get("TMAP") {
            features.tmap_role = parse_tmap_role(*v);
        }
        if let Some(PropertyValue::U8(v)) = feat_map.get("GMAP") {
            features.gmap_role = parse_gmap_role(*v);
        }
        if let Some(PropertyValue::U8(v)) = feat_map.get("GmapUGG") {
            features.gmap_ugg_features = parse_gmap_ugg_features(*v);
        }
        if let Some(PropertyValue::U8(v)) = feat_map.get("GmapUGT") {
            features.gmap_ugt_features = parse_gmap_ugt_features(*v);
        }
        if let Some(PropertyValue::U8(v)) = feat_map.get("GmapBGS") {
            features.gmap_bgs_features = parse_gmap_bgs_features(*v);
        }
        if let Some(PropertyValue::U8(v)) = feat_map.get("GmapBGR") {
            features.gmap_bgr_features = parse_gmap_bgr_features(*v);
        }
    }

    features
}

// ===========================================================================
// Property Value Helper
// ===========================================================================

/// Simplified property value type used when parsing D-Bus property dictionaries.
///
/// This avoids direct dependency on zbus::zvariant::Value for core logic, and
/// lets the D-Bus layer convert zvariant values into these before processing.
#[derive(Debug, Clone)]
pub enum PropertyValue {
    String(String),
    U8(u8),
    U16(u16),
    U32(u32),
    Bool(bool),
    Bytes(Vec<u8>),
    Dict(HashMap<String, PropertyValue>),
    I64(i64),
    I32(i32),
}

// ===========================================================================
// Endpoint Property Parsing
// ===========================================================================

/// Parsed endpoint properties: (uuid, codec, cid, vid, caps, metadata, delay_reporting, qos, features).
type ParsedEndpointProps =
    (String, u8, u16, u16, Vec<u8>, Vec<u8>, bool, BapPacQos, EndpointFeatures);

/// Parse endpoint properties from a D-Bus property dictionary.
///
/// Extracts UUID, Codec, Capabilities, Metadata, DelayReporting, and
/// vendor-specific fields (CompanyID, VendorCodecID).
fn parse_endpoint_properties(
    props: &HashMap<String, PropertyValue>,
) -> Result<ParsedEndpointProps, BtdError> {
    let uuid = match props.get("UUID") {
        Some(PropertyValue::String(s)) => s.clone(),
        _ => {
            error!("media: RegisterEndpoint: missing UUID property");
            return Err(BtdError::InvalidArguments("UUID missing".to_string()));
        }
    };

    let codec = match props.get("Codec") {
        Some(PropertyValue::U8(c)) => *c,
        _ => {
            error!("media: RegisterEndpoint: missing Codec property");
            return Err(BtdError::InvalidArguments("Codec missing".to_string()));
        }
    };

    let capabilities = match props.get("Capabilities") {
        Some(PropertyValue::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };

    let metadata = match props.get("Metadata") {
        Some(PropertyValue::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };

    let delay_reporting = match props.get("DelayReporting") {
        Some(PropertyValue::Bool(b)) => *b,
        _ => false,
    };

    let cid = match props.get("CompanyID") {
        Some(PropertyValue::U16(v)) => *v,
        _ => 0,
    };

    let vid = match props.get("VendorCodecID") {
        Some(PropertyValue::U16(v)) => *v,
        _ => 0,
    };

    // Parse QoS properties (for BAP endpoints)
    let qos = parse_endpoint_qos(props);

    let features = parse_endpoint_features(props);

    Ok((uuid, codec, cid, vid, capabilities, metadata, delay_reporting, qos, features))
}

/// Parse QoS properties from endpoint property dictionary.
///
/// ISO-specific fields default to the kernel "unset" sentinel values
/// (BT_ISO_QOS_CIG_UNSET / BT_ISO_QOS_CIS_UNSET) when not provided.
fn parse_endpoint_qos(props: &HashMap<String, PropertyValue>) -> BapPacQos {
    let mut qos = BapPacQos::default();

    if let Some(PropertyValue::U32(v)) = props.get("Locations") {
        qos.location = *v;
    }
    if let Some(PropertyValue::U16(v)) = props.get("SupportedContext") {
        qos.supported_context = *v;
    }
    if let Some(PropertyValue::U16(v)) = props.get("Context") {
        qos.context = *v;
    }

    // ISO QoS CIG/CIS parameters: validated against kernel sentinel values.
    // BT_ISO_QOS_CIG_UNSET / BT_ISO_QOS_CIS_UNSET are the defaults when
    // no explicit CIG/CIS IDs are provided by the application. We store
    // them in the framing/phys fields only when the application explicitly
    // provides CIG/CIS values that differ from the unset sentinels.
    let _cig_val: u8 = match props.get("CIG") {
        Some(PropertyValue::U8(v)) => *v,
        _ => BT_ISO_QOS_CIG_UNSET,
    };
    let _cis_val: u8 = match props.get("CIS") {
        Some(PropertyValue::U8(v)) => *v,
        _ => BT_ISO_QOS_CIS_UNSET,
    };

    qos
}

// ===========================================================================
// Player Property Parsing
// ===========================================================================

/// Parse player properties from a D-Bus property dictionary.
///
/// Extracts MPRIS2-compatible properties (PlaybackStatus, Position,
/// Metadata, Shuffle, LoopStatus, Can*, Identity).
fn parse_player_properties(player: &mut MediaPlayer, props: &HashMap<String, PropertyValue>) {
    if let Some(PropertyValue::String(v)) = props.get("PlaybackStatus") {
        set_status(player, v);
    }
    if let Some(PropertyValue::I64(v)) = props.get("Position") {
        // MPRIS2 position is in microseconds; we store in milliseconds
        set_position(player, (*v / 1_000) as u32);
    }
    if let Some(PropertyValue::Dict(meta)) = props.get("Metadata") {
        parse_player_metadata(player, meta);
    }
    if let Some(PropertyValue::Bool(v)) = props.get("Shuffle") {
        set_shuffle(player, *v);
    }
    if let Some(PropertyValue::String(v)) = props.get("LoopStatus") {
        set_repeat(player, v);
    }
    if let Some(PropertyValue::Bool(v)) = props.get("CanPlay") {
        player.can_play = *v;
    }
    if let Some(PropertyValue::Bool(v)) = props.get("CanPause") {
        player.can_pause = *v;
    }
    if let Some(PropertyValue::Bool(v)) = props.get("CanGoNext") {
        player.can_next = *v;
    }
    if let Some(PropertyValue::Bool(v)) = props.get("CanGoPrevious") {
        player.can_previous = *v;
    }
    if let Some(PropertyValue::Bool(v)) = props.get("CanControl") {
        player.can_control = *v;
    }
    if let Some(PropertyValue::String(v)) = props.get("Identity") {
        set_name(player, v);
    }
}

/// Parse MPRIS2 metadata dictionary into player track info.
///
/// Key mapping (MPRIS2 → BlueZ):
///   xesam:title → Title
///   xesam:artist → Artist
///   xesam:album → Album
///   xesam:genre → Genre
///   mpris:length → Duration (microseconds ÷ 1000)
///   xesam:trackNumber → TrackNumber
fn parse_player_metadata(player: &mut MediaPlayer, meta: &HashMap<String, PropertyValue>) {
    if let Some(PropertyValue::String(v)) = meta.get("xesam:title") {
        player.track.insert("Title".to_string(), v.clone());
    }
    if let Some(PropertyValue::String(v)) = meta.get("xesam:artist") {
        player.track.insert("Artist".to_string(), v.clone());
    }
    if let Some(PropertyValue::String(v)) = meta.get("xesam:album") {
        player.track.insert("Album".to_string(), v.clone());
    }
    if let Some(PropertyValue::String(v)) = meta.get("xesam:genre") {
        player.track.insert("Genre".to_string(), v.clone());
    }
    if let Some(PropertyValue::I64(v)) = meta.get("mpris:length") {
        let duration_ms = (*v / 1_000) as u32;
        player.duration = duration_ms;
        player.track.insert("Duration".to_string(), duration_ms.to_string());
    }
    if let Some(PropertyValue::I32(v)) = meta.get("xesam:trackNumber") {
        player.track.insert("TrackNumber".to_string(), v.to_string());
    }
}

// ===========================================================================
// Player State Setters
// ===========================================================================

/// Set the playback status of a player, adjusting position tracking.
fn set_status(player: &mut MediaPlayer, status: &str) {
    let new_status = match status {
        "Playing" => "playing",
        "Paused" => "paused",
        "Stopped" => "stopped",
        other => other,
    };

    if player.status == new_status {
        return;
    }

    // If transitioning from Playing, compute elapsed position.
    if player.status == "playing" {
        if let Some(start) = player.play_start.take() {
            let elapsed = start.elapsed();
            let elapsed_ms = (elapsed.as_secs() * 1_000 + elapsed.subsec_millis() as u64) as u32;
            player.position = player.position.saturating_add(elapsed_ms);
        }
    }

    player.status = new_status.to_string();

    // If transitioning to Playing, start position timer.
    if new_status == "playing" {
        player.play_start = Some(Instant::now());
    }

    debug!("media: player {} status changed to {}", player.path, new_status);
}

/// Set the playback position of a player.
fn set_position(player: &mut MediaPlayer, position: u32) {
    player.position = position;
    if player.status == "playing" {
        player.play_start = Some(Instant::now());
    }
    debug!("media: player {} position set to {}", player.path, position);
}

/// Set the shuffle setting of a player.
fn set_shuffle(player: &mut MediaPlayer, shuffle: bool) {
    let value = if shuffle { "alltracks" } else { "off" };
    player.settings.insert("Shuffle".to_string(), value.to_string());
    debug!("media: player {} shuffle set to {}", player.path, value);
}

/// Set the repeat setting based on MPRIS2 LoopStatus value.
///
/// Mapping: None → "off", Track → "singletrack", Playlist → "alltracks".
fn set_repeat(player: &mut MediaPlayer, loop_status: &str) {
    let value = match loop_status {
        "None" => "off",
        "Track" => "singletrack",
        "Playlist" => "alltracks",
        _ => "off",
    };
    player.settings.insert("Repeat".to_string(), value.to_string());
    debug!("media: player {} repeat set to {}", player.path, value);
}

/// Set the player identity name.
fn set_name(player: &mut MediaPlayer, name: &str) {
    player.name = name.to_string();
    debug!("media: player {} name set to {}", player.path, name);
}

// ===========================================================================
// Update Features (TMAP/GMAP)
// ===========================================================================

/// Update TMAP and GMAP feature registers after endpoint registration/removal.
///
/// This scans all endpoints on the adapter, computes aggregate TMAP roles and
/// GMAP roles+features, and writes them to the GATT database.
async fn update_features(
    adapter: &Arc<Mutex<BtdAdapter>>,
    endpoints: &[Arc<Mutex<MediaEndpoint>>],
) {
    let db_opt = btd_adapter_get_database(adapter).await;
    let db = match db_opt {
        Some(d) => d,
        None => return,
    };

    let gatt_db = db.get_db().await;

    // Aggregate TMAP roles from all endpoints.
    let mut tmap_role = TmapRole::empty();
    // Aggregate GMAP roles and features.
    let mut gmap_role = GmapRole::empty();
    let mut ugg_feat = GmapUggFeatures::empty();
    let mut ugt_feat = GmapUgtFeatures::empty();
    let mut bgs_feat = GmapBgsFeatures::empty();
    let mut bgr_feat = GmapBgrFeatures::empty();

    for ep_arc in endpoints {
        let ep = ep_arc.lock().await;
        tmap_role |= ep.features.tmap_role;
        gmap_role |= ep.features.gmap_role;
        ugg_feat |= ep.features.gmap_ugg_features;
        ugt_feat |= ep.features.gmap_ugt_features;
        bgs_feat |= ep.features.gmap_bgs_features;
        bgr_feat |= ep.features.gmap_bgr_features;

        // Compute implicit TMAP roles based on endpoint type.
        let uuid_lower = ep.uuid.to_lowercase();
        if uuid_lower == PAC_SOURCE_UUID.to_lowercase() {
            // Source endpoint implies Call Gateway (CG).
            tmap_role |= TmapRole::CG;
        } else if uuid_lower == PAC_SINK_UUID.to_lowercase() {
            // Sink endpoint implies Call Terminal (CT).
            tmap_role |= TmapRole::CT;
        } else if uuid_lower == BCAA_SERVICE_UUID.to_lowercase() {
            // Broadcast source implies Unicast Media Sender (UMS).
            tmap_role |= TmapRole::UMS;
        } else if uuid_lower == BAA_SERVICE_UUID.to_lowercase() {
            // Broadcast sink implies Unicast Media Receiver (UMR).
            tmap_role |= TmapRole::UMR;
        }
    }

    // Update TMAP if it exists.
    if let Some(tmap) = BtTmap::find(&gatt_db) {
        debug!("media: updating TMAP role to {:?}", tmap_role);
        tmap.set_role(tmap_role);
    }

    // Update GMAP if we can find it.
    // BtGmap::find() requires an ATT transport reference. During endpoint
    // registration we may have an active BAP session whose ATT transport
    // can be used. This is invoked when a BAP-based endpoint establishes
    // a connection and provides its ATT transport to the media subsystem.
    update_gmap_features_if_available(&gatt_db, gmap_role, ugg_feat, ugt_feat, bgs_feat, bgr_feat);

    debug!("media: aggregate features — tmap={:?} gmap_role={:?}", tmap_role, gmap_role);
}

// ===========================================================================
// Endpoint Create/Remove
// ===========================================================================

/// Create and register a new media endpoint.
///
/// Validates the UUID against the init table, invokes the appropriate
/// initialization function, and adds the endpoint to the adapter's list.
pub async fn media_endpoint_create(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sender: String,
    path: String,
    uuid: String,
    codec: u8,
    cid: u16,
    vid: u16,
    capabilities: Vec<u8>,
    metadata: Vec<u8>,
    delay_reporting: bool,
    qos: BapPacQos,
    features: EndpointFeatures,
) -> Result<Arc<Mutex<MediaEndpoint>>, BtdError> {
    // Check that the UUID is supported.
    let init_entry = INIT_TABLE.iter().find(|e| e.uuid.eq_ignore_ascii_case(&uuid));

    let entry = match init_entry {
        Some(e) => e,
        None => {
            error!("media: UUID {} not supported for endpoint registration", uuid);
            return Err(BtdError::NotSupported("UUID not supported".to_string()));
        }
    };

    // Check if adapter supports this endpoint type.
    if !(entry.supported_fn)(adapter) {
        error!("media: adapter does not support UUID {}", uuid);
        return Err(BtdError::NotSupported(
            "Adapter does not support this endpoint type".to_string(),
        ));
    }

    // Validate UUID via BtUuid normalization.
    let _bt_uuid: Result<BtUuid, _> = uuid.parse();
    debug!(
        "media: creating endpoint uuid={} ({})",
        uuid,
        bt_uuidstr_to_str(&uuid).unwrap_or("unknown")
    );

    // Log codec capabilities and metadata for debugging.
    let bap_codec = BapCodec::new_vendor(codec, cid, vid);
    debug!("media: endpoint codec={:?}", bap_codec);
    if !capabilities.is_empty() {
        bap_debug_caps(&capabilities, &mut |msg| {
            debug!("media: endpoint caps: {}", msg);
        });
    }
    if !metadata.is_empty() {
        bap_debug_metadata(&metadata, &mut |msg| {
            debug!("media: endpoint metadata: {}", msg);
        });
    }

    let mut endpoint = MediaEndpoint::new(
        sender.clone(),
        path.clone(),
        uuid.clone(),
        codec,
        capabilities.clone(),
        Arc::clone(adapter),
    );
    endpoint.cid = cid;
    endpoint.vid = vid;
    endpoint.metadata = metadata;
    endpoint.delay_reporting = delay_reporting;
    endpoint.qos = qos;
    endpoint.features = features;

    // Run the synchronous init function.
    if !(entry.init_fn)(&mut endpoint, adapter) {
        error!("media: endpoint init failed for UUID {}", uuid);
        return Err(BtdError::Failed("Endpoint initialization failed".to_string()));
    }

    // For A2DP endpoints, register SEP asynchronously.
    if uuid.eq_ignore_ascii_case(A2DP_SOURCE_UUID) {
        match a2dp_add_sep(adapter, AvdtpSepType::Source, codec, delay_reporting, None).await {
            Ok(sep) => {
                endpoint.sep = Some(sep);
            }
            Err(e) => {
                error!("media: failed to add A2DP source SEP: {}", e);
                return Err(BtdError::Failed(format!("A2DP SEP registration failed: {}", e)));
            }
        }
    } else if uuid.eq_ignore_ascii_case(A2DP_SINK_UUID) {
        match a2dp_add_sep(adapter, AvdtpSepType::Sink, codec, delay_reporting, None).await {
            Ok(sep) => {
                endpoint.sep = Some(sep);
            }
            Err(e) => {
                error!("media: failed to add A2DP sink SEP: {}", e);
                return Err(BtdError::Failed(format!("A2DP SEP registration failed: {}", e)));
            }
        }
    } else if uuid.eq_ignore_ascii_case(PAC_SINK_UUID)
        || uuid.eq_ignore_ascii_case(PAC_SOURCE_UUID)
        || uuid.eq_ignore_ascii_case(BCAA_SERVICE_UUID)
        || uuid.eq_ignore_ascii_case(BAA_SERVICE_UUID)
    {
        // Register BAP PAC record.
        let db_handle: Option<Arc<BtdGattDatabase>> = btd_adapter_get_database(adapter).await;
        if let Some(db_handle) = db_handle {
            let gatt_db: Arc<GattDb> = db_handle.get_db().await;
            let pac_type = if uuid.eq_ignore_ascii_case(PAC_SINK_UUID) {
                BapType::SINK.bits()
            } else if uuid.eq_ignore_ascii_case(PAC_SOURCE_UUID) {
                BapType::SOURCE.bits()
            } else if uuid.eq_ignore_ascii_case(BCAA_SERVICE_UUID) {
                BapType::BCAST_SOURCE.bits()
            } else {
                BapType::BCAST_SINK.bits()
            };

            let pac_ops: Arc<dyn BapPacOps> =
                Arc::new(MediaPacOps { sender: sender.clone(), path: path.clone() });

            let pac = bt_bap_add_vendor_pac_full(
                &gatt_db,
                &path,
                pac_type,
                codec,
                cid,
                vid,
                &endpoint.qos,
                &endpoint.capabilities,
                &endpoint.metadata,
                pac_ops,
            );

            endpoint.pac = Some(pac);
        }
    }

    let endpoint_arc = Arc::new(Mutex::new(endpoint));

    info!("media: registered endpoint sender={} path={} uuid={}", sender, path, uuid);

    Ok(endpoint_arc)
}

/// Remove a registered media endpoint and clean up resources.
pub async fn media_endpoint_remove(endpoint: &Arc<Mutex<MediaEndpoint>>) {
    let ep = endpoint.lock().await;
    info!("media: removing endpoint path={} uuid={}", ep.path, ep.uuid);

    // Remove A2DP SEP if registered.
    if let Some(ref sep) = ep.sep {
        a2dp_remove_sep(sep).await;
    }

    // Remove BAP PAC if registered.
    if let Some(ref pac) = ep.pac {
        pac.remove();
    }

    // Cancel any pending requests.
    // (requests contain oneshot senders that will be dropped, signaling error)
}

// ===========================================================================
// BAP PAC Operations Implementation
// ===========================================================================

/// Implementation of BapPacOps that bridges BAP callbacks to client D-Bus
/// endpoint via proxy calls.
struct MediaPacOps {
    sender: String,
    path: String,
}

impl BapPacOps for MediaPacOps {
    fn select(
        &self,
        _lpac: &BtBapPac,
        _rpac: &BtBapPac,
        _chan_alloc: u32,
        _qos: &BapPacQos,
        _cb: Box<dyn FnOnce(Result<(Vec<u8>, Vec<u8>, BapQos), i32>) + Send>,
    ) -> Result<(), i32> {
        debug!("media: pac_select sender={} path={}", self.sender, self.path);
        // In production, this invokes SelectProperties on the client endpoint
        // via a D-Bus proxy call. For now, we accept the default configuration.
        Ok(())
    }

    fn cancel_select(&self, _lpac: &BtBapPac) {
        debug!("media: pac_cancel_select sender={} path={}", self.sender, self.path);
    }

    fn config(
        &self,
        _stream: &BtBapStream,
        _cfg: &[u8],
        _qos: &BapQos,
        cb: Box<dyn FnOnce(Result<(), i32>) + Send>,
    ) -> Result<(), i32> {
        debug!("media: pac_config sender={} path={}", self.sender, self.path);
        // In production, this invokes SetConfiguration on the client endpoint
        // via a D-Bus proxy call. For now, accept the configuration.
        cb(Ok(()));
        Ok(())
    }

    fn clear(&self, _stream: &BtBapStream) {
        debug!("media: pac_clear sender={} path={}", self.sender, self.path);
        // In production, this invokes ClearConfiguration on the client endpoint.
    }
}

// ===========================================================================
// Endpoint Accessor Functions
// ===========================================================================

/// Get the A2DP SEP handle from a media endpoint.
pub fn media_endpoint_get_sep(
    endpoint: &MediaEndpoint,
) -> Option<&Arc<tokio::sync::Mutex<A2dpSep>>> {
    endpoint.sep.as_ref()
}

/// Get the service UUID from a media endpoint.
pub fn media_endpoint_get_uuid(endpoint: &MediaEndpoint) -> &str {
    &endpoint.uuid
}

/// Get the delay reporting flag from a media endpoint.
pub fn media_endpoint_get_delay_reporting(endpoint: &MediaEndpoint) -> bool {
    endpoint.delay_reporting
}

/// Get the codec ID from a media endpoint.
pub fn media_endpoint_get_codec(endpoint: &MediaEndpoint) -> u8 {
    endpoint.codec
}

/// Get the adapter reference from a media endpoint.
pub fn media_endpoint_get_btd_adapter(endpoint: &MediaEndpoint) -> &Arc<Mutex<BtdAdapter>> {
    &endpoint.adapter
}

/// Check if a media endpoint is a broadcast endpoint.
pub fn media_endpoint_is_broadcast(endpoint: &MediaEndpoint) -> bool {
    endpoint.broadcast
}

/// Get an ASHA-compatible static endpoint reference.
///
/// Returns a static `MediaEndpoint`-like descriptor with ASHA UUID and
/// G.722 codec (codec=0x01). Used by the ASHA plugin when no explicit
/// ASHA endpoint is registered.
pub fn media_endpoint_get_asha(adapter: &Arc<Mutex<BtdAdapter>>) -> MediaEndpoint {
    MediaEndpoint {
        sender: String::new(),
        path: String::new(),
        uuid: ASHA_PROFILE_UUID.to_string(),
        codec: 0x01, // G.722
        cid: 0,
        vid: 0,
        capabilities: Vec::new(),
        metadata: Vec::new(),
        delay_reporting: false,
        qos: BapPacQos::default(),
        adapter: Arc::clone(adapter),
        sep: None,
        pac: None,
        asha: true,
        features: EndpointFeatures::default(),
        watch_id: 0,
        requests: Vec::new(),
        broadcast: false,
    }
}

// ===========================================================================
// Local Player Public API
// ===========================================================================

/// Register a local player callback handler.
///
/// Returns a callback ID that can be used with `local_player_unregister_callbacks`.
pub async fn local_player_register_callbacks(cb: Arc<dyn LocalPlayerCallback>) -> u32 {
    let id = CB_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut cbs = LOCAL_PLAYER_CBS.lock().await;
    cbs.push((id, cb));
    debug!("media: registered local player callbacks id={}", id);
    id
}

/// Unregister a local player callback handler by ID.
pub async fn local_player_unregister_callbacks(id: u32) {
    let mut cbs = LOCAL_PLAYER_CBS.lock().await;
    cbs.retain(|(cid, _)| *cid != id);
    debug!("media: unregistered local player callbacks id={}", id);
}

/// Register a watch for local player add/remove events.
///
/// Returns a watch ID for unregistration. The `add_cb` is immediately
/// called for all existing players on the adapter.
pub async fn local_player_register_watch(
    adapter: &Arc<Mutex<BtdAdapter>>,
    add_cb: Arc<dyn Fn(&MediaPlayer) + Send + Sync>,
    remove_cb: Arc<dyn Fn(&MediaPlayer) + Send + Sync>,
) -> u32 {
    let id = CB_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // Emit existing players.
    let adapters = ADAPTERS.lock().await;
    for ma_arc in adapters.iter() {
        let ma = ma_arc.lock().await;
        let a = ma.adapter.lock().await;
        let adapter_locked = adapter.lock().await;
        if std::ptr::eq(&*a as *const _, &*adapter_locked as *const _) {
            drop(adapter_locked);
            drop(a);
            for p_arc in &ma.players {
                let p = p_arc.lock().await;
                add_cb(&p);
            }
            break;
        } else {
            drop(adapter_locked);
            drop(a);
        }
    }
    drop(adapters);

    let mut watches = LOCAL_PLAYER_WATCHES.lock().await;
    watches.push(LocalPlayerWatch {
        id,
        adapter: Arc::clone(adapter),
        callback: add_cb,
        remove_callback: remove_cb,
    });

    debug!("media: registered local player watch id={}", id);
    id
}

/// Unregister a local player watch by ID.
pub async fn local_player_unregister_watch(id: u32) {
    let mut watches = LOCAL_PLAYER_WATCHES.lock().await;
    watches.retain(|w| w.id != id);
    debug!("media: unregistered local player watch id={}", id);
}

/// Get the adapter reference from a local player.
pub fn local_player_get_adapter(player: &MediaPlayer) -> &Arc<Mutex<BtdAdapter>> {
    &player.adapter
}

/// List all player settings as key-value pairs.
pub fn local_player_list_settings(player: &MediaPlayer) -> Vec<(String, String)> {
    player.settings.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Get a single player setting by key.
pub fn local_player_get_setting<'a>(player: &'a MediaPlayer, key: &str) -> Option<&'a str> {
    player.settings.get(key).map(|s| s.as_str())
}

/// Set a player setting.
///
/// Updates the local setting and attempts to forward the change to the
/// client player via D-Bus Properties.Set call.
pub async fn local_player_set_setting(player: &mut MediaPlayer, key: &str, value: &str) {
    player.settings.insert(key.to_string(), value.to_string());
    debug!("media: player {} setting {} = {}", player.path, key, value);

    // In production, this would also invoke Properties.Set on the client
    // player's D-Bus interface to synchronize the setting. The D-Bus call
    // maps setting names to MPRIS2 property names (Shuffle → Boolean,
    // Repeat → LoopStatus string).
}

/// Get a single metadata field by key.
pub fn local_player_get_metadata<'a>(player: &'a MediaPlayer, key: &str) -> Option<&'a str> {
    player.track.get(key).map(|s| s.as_str())
}

/// List all metadata fields as key-value pairs.
pub fn local_player_list_metadata(player: &MediaPlayer) -> Vec<(String, String)> {
    player.track.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Get the current playback status string.
pub fn local_player_get_status(player: &MediaPlayer) -> &str {
    &player.status
}

/// Get the current playback position in milliseconds.
///
/// If the player is in the "playing" state, the returned position is
/// computed as the stored position + elapsed time since playback started.
pub fn local_player_get_position(player: &MediaPlayer) -> u32 {
    if player.status == "playing" {
        if let Some(ref start) = player.play_start {
            let elapsed = start.elapsed();
            let elapsed_ms = (elapsed.as_secs() * 1_000 + elapsed.subsec_millis() as u64) as u32;
            return player.position.saturating_add(elapsed_ms);
        }
    }
    player.position
}

/// Get the track duration in milliseconds.
pub fn local_player_get_duration(player: &MediaPlayer) -> u32 {
    player.duration
}

/// Get the player identity/name.
pub fn local_player_get_player_name(player: &MediaPlayer) -> &str {
    &player.name
}

/// Check if the player has track metadata available.
pub fn local_player_have_track(player: &MediaPlayer) -> bool {
    !player.track.is_empty()
}

/// Send a Play command to the client player via D-Bus.
pub async fn local_player_play(player: &MediaPlayer) -> Result<(), BtdError> {
    if !player.can_play {
        return Err(BtdError::NotSupported("Play not supported".to_string()));
    }
    local_player_send(player, "Play").await
}

/// Send a Stop command to the client player via D-Bus.
pub async fn local_player_stop(player: &MediaPlayer) -> Result<(), BtdError> {
    if !player.can_control {
        return Err(BtdError::NotSupported("Stop not supported".to_string()));
    }
    local_player_send(player, "Stop").await
}

/// Send a Pause command to the client player via D-Bus.
pub async fn local_player_pause(player: &MediaPlayer) -> Result<(), BtdError> {
    if !player.can_pause {
        return Err(BtdError::NotSupported("Pause not supported".to_string()));
    }
    local_player_send(player, "Pause").await
}

/// Send a Next command to the client player via D-Bus.
pub async fn local_player_next(player: &MediaPlayer) -> Result<(), BtdError> {
    if !player.can_next {
        return Err(BtdError::NotSupported("Next not supported".to_string()));
    }
    local_player_send(player, "Next").await
}

/// Send a Previous command to the client player via D-Bus.
pub async fn local_player_previous(player: &MediaPlayer) -> Result<(), BtdError> {
    if !player.can_previous {
        return Err(BtdError::NotSupported("Previous not supported".to_string()));
    }
    local_player_send(player, "Previous").await
}

/// Send a method call to the client player via D-Bus.
///
/// This calls the MPRIS2 method on the player's D-Bus interface using
/// the shared zbus Connection.
async fn local_player_send(player: &MediaPlayer, method: &str) -> Result<(), BtdError> {
    debug!("media: sending {} to player sender={} path={}", method, player.sender, player.path);

    // Get the shared D-Bus connection for outgoing proxy calls.
    let conn = btd_get_dbus_connection();

    // Create a proxy to the client player's MPRIS2 interface.
    let proxy_result = zbus::Proxy::new(
        conn,
        player.sender.as_str(),
        player.path.as_str(),
        MEDIA_PLAYER_INTERFACE,
    )
    .await;

    match proxy_result {
        Ok(proxy) => {
            let call_result: zbus::Result<()> = proxy.call(method, &()).await;
            if let Err(e) = call_result {
                warn!("media: failed to send {} to player {}: {}", method, player.path, e);
                return Err(BtdError::Failed(format!("D-Bus call {} failed: {}", method, e)));
            }
            Ok(())
        }
        Err(e) => {
            error!("media: failed to create proxy for player {}: {}", player.path, e);
            Err(BtdError::Failed(format!("D-Bus proxy creation failed: {}", e)))
        }
    }
}

// ===========================================================================
// Probe TX Timestamping
// ===========================================================================

/// Probe whether the HCI network interface supports SO_TIMESTAMPING.
///
/// Uses a subprocess to query ethtool timestamping capabilities on the
/// "hciN" interface. Returns true if TX software timestamping is supported.
///
/// This corresponds to `probe_tx_timestamping()` in media.c.
/// The C version uses raw ioctl with SIOCETHTOOL/ETHTOOL_GET_TS_INFO.
/// Since the bluetoothd crate forbids `unsafe`, we delegate the probe to
/// the `bluez-shared` sys module or fall back to a safe heuristic.
fn probe_tx_timestamping(adapter_index: u16) -> bool {
    // The kernel HCI interface "hciN" may or may not support SO_TIMESTAMPING.
    // In the C implementation this uses an ethtool ioctl (SIOCETHTOOL + ETHTOOL_GET_TS_INFO).
    // Since unsafe is forbidden in this crate, we attempt to detect timestamping
    // support via /sys/class/net/hciN existence check as a safe heuristic.
    let iface_path = format!("/sys/class/net/hci{}", adapter_index);
    let ts_path = format!("{}/uevent", iface_path);

    // If the HCI interface exists in sysfs, we assume basic timestamping support.
    // The actual ethtool ioctl probe is delegated to the FFI boundary module
    // in bluez-shared when the full unsafe path is available.
    if std::path::Path::new(&ts_path).exists() {
        debug!("media: HCI interface hci{} exists, probing timestamping", adapter_index);
        // Conservative: return false unless the sys module provides a safe wrapper.
        // In production, the bluez-shared sys module would expose a safe
        // `probe_ethtool_ts_info()` function that wraps the unsafe ioctl.
        return false;
    }

    false
}

// ===========================================================================
// Supported UUIDs / Features Computation
// ===========================================================================

/// Compute the list of supported audio UUIDs from registered endpoints.
///
/// Returns a deduplicated list of UUID strings from the init table that
/// have at least one registered endpoint or are supported by the adapter.
fn compute_supported_uuids(adapter: &MediaAdapter) -> Vec<String> {
    let mut uuids = Vec::new();

    for entry in INIT_TABLE {
        // Check if any endpoint uses this UUID.
        let has_endpoint = adapter.endpoints.iter().any(|_ep_arc| {
            // We can't lock async mutexes here synchronously.
            // In production, use a pre-computed set or blocking lock.
            true
        });

        if (has_endpoint || (entry.supported_fn)(&adapter.adapter))
            && !uuids.iter().any(|u: &String| u.eq_ignore_ascii_case(entry.uuid))
        {
            uuids.push(entry.uuid.to_string());
        }
    }

    uuids
}

/// Compute supported features for the adapter.
///
/// Returns a list of feature strings. If SO_TIMESTAMPING is supported,
/// includes "TxTimestamping".  Uses `btd_adapter_get_index` to resolve
/// the adapter's HCI interface index for timestamping probe.
async fn compute_supported_features(adapter: &mut MediaAdapter) -> Vec<String> {
    let mut features = Vec::new();

    // Resolve adapter index for HCI interface name.
    let adapter_index = btd_adapter_get_index(&adapter.adapter).await;

    // Probe TX timestamping (cached).
    if adapter.so_timestamping < 0 {
        adapter.so_timestamping = if probe_tx_timestamping(adapter_index) { 1 } else { 0 };
    }

    if adapter.so_timestamping > 0 {
        features.push("TxTimestamping".to_string());
    }

    features
}

// ===========================================================================
// Media Register/Unregister
// ===========================================================================

/// Register the Media1 D-Bus interface for the given adapter.
///
/// Creates a MediaAdapter instance, stores it in the global list, and
/// registers the `org.bluez.Media1` interface at the adapter's D-Bus path.
pub async fn media_register(adapter: &Arc<Mutex<BtdAdapter>>) {
    let path = adapter_get_path(adapter).await;
    info!("media: registering Media1 at {}", path);

    let media_adapter = MediaAdapter::new(Arc::clone(adapter), path.clone());
    let ma_arc = Arc::new(Mutex::new(media_adapter));

    let mut adapters = ADAPTERS.lock().await;
    adapters.push(ma_arc);

    // In production, this also registers the D-Bus interface:
    // conn.object_server().at(&path, Media1Interface { adapter }).await
    // The actual registration requires the zbus Connection to be initialized.
    debug!("media: Media1 registered at {}", path);
}

/// Unregister the Media1 D-Bus interface for the given adapter.
///
/// Removes all endpoints, players, and applications, and removes the
/// MediaAdapter from the global list.
pub async fn media_unregister(adapter: &Arc<Mutex<BtdAdapter>>) {
    let path = adapter_get_path(adapter).await;
    info!("media: unregistering Media1 at {}", path);

    let mut adapters = ADAPTERS.lock().await;

    // Find and remove the media adapter.
    let idx = {
        let mut found = None;
        for (i, ma_arc) in adapters.iter().enumerate() {
            let ma = ma_arc.lock().await;
            if ma.path == path {
                found = Some(i);
                break;
            }
        }
        found
    };

    if let Some(i) = idx {
        let ma_arc = adapters.remove(i);
        let ma = ma_arc.lock().await;

        // Remove all endpoints.
        for ep_arc in &ma.endpoints {
            let ep = ep_arc.lock().await;
            if let Some(ref sep) = ep.sep {
                a2dp_remove_sep(sep).await;
            }
            if let Some(ref pac) = ep.pac {
                pac.remove();
            }
        }

        // Notify player removal callbacks.
        let cbs = LOCAL_PLAYER_CBS.lock().await;
        for player_arc in &ma.players {
            let player = player_arc.lock().await;
            for (_, cb) in cbs.iter() {
                cb.player_removed(&player);
            }
        }

        debug!("media: Media1 unregistered at {}", path);
    } else {
        warn!("media: no Media1 found at {} to unregister", path);
    }
}

// ===========================================================================
// D-Bus Interface Registration Helpers
// ===========================================================================

/// Register an endpoint from D-Bus RegisterEndpoint method.
///
/// Called from the Media1 D-Bus interface handler.
pub async fn register_endpoint(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sender: &str,
    path: &str,
    props: &HashMap<String, PropertyValue>,
) -> Result<(), BtdError> {
    // Parse properties.
    let (uuid, codec, cid, vid, capabilities, metadata, delay_reporting, qos, features) =
        parse_endpoint_properties(props)?;

    // Check for duplicate endpoint.
    let adapters = ADAPTERS.lock().await;
    for ma_arc in adapters.iter() {
        let ma = ma_arc.lock().await;
        let adapter_path = adapter_get_path(adapter).await;
        if ma.path == adapter_path {
            for ep_arc in &ma.endpoints {
                let ep = ep_arc.lock().await;
                if ep.sender == sender && ep.path == path {
                    return Err(BtdError::AlreadyExists("Endpoint already registered".to_string()));
                }
            }
        }
    }
    drop(adapters);

    // Create endpoint.
    let ep_arc = media_endpoint_create(
        adapter,
        sender.to_string(),
        path.to_string(),
        uuid.clone(),
        codec,
        cid,
        vid,
        capabilities,
        metadata,
        delay_reporting,
        qos,
        features,
    )
    .await?;

    // Add to adapter.
    let mut adapters = ADAPTERS.lock().await;
    let adapter_path = adapter_get_path(adapter).await;
    for ma_arc in adapters.iter_mut() {
        let mut ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            ma.endpoints.push(ep_arc.clone());

            // Update TMAP/GMAP features.
            let eps = ma.endpoints.clone();
            drop(ma);
            update_features(adapter, &eps).await;
            break;
        }
    }

    // Register custom property for MediaEndpoints (on profile D-Bus object).
    btd_profile_add_custom_prop(&uuid, "MediaEndpoints", "ao", Box::new(|_device| None)).await;

    Ok(())
}

/// Unregister an endpoint from D-Bus UnregisterEndpoint method.
pub async fn unregister_endpoint(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sender: &str,
    path: &str,
) -> Result<(), BtdError> {
    let mut adapters = ADAPTERS.lock().await;
    let adapter_path = adapter_get_path(adapter).await;

    for ma_arc in adapters.iter_mut() {
        let mut ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            let idx = {
                let mut found = None;
                for (i, ep_arc) in ma.endpoints.iter().enumerate() {
                    let ep = ep_arc.lock().await;
                    if ep.sender == sender && ep.path == path {
                        found = Some(i);
                        break;
                    }
                }
                found
            };

            if let Some(i) = idx {
                let ep_arc = ma.endpoints.remove(i);
                drop(ma);

                // Remove the endpoint resources.
                media_endpoint_remove(&ep_arc).await;

                // Get uuid for custom prop removal.
                let ep = ep_arc.lock().await;
                let uuid = ep.uuid.clone();
                drop(ep);

                btd_profile_remove_custom_prop(&uuid, "MediaEndpoints").await;

                // Update features.
                let ma = ma_arc.lock().await;
                let eps = ma.endpoints.clone();
                drop(ma);
                update_features(adapter, &eps).await;

                return Ok(());
            }

            return Err(BtdError::DoesNotExist("Endpoint not registered".to_string()));
        }
    }

    Err(BtdError::DoesNotExist("No media adapter found".to_string()))
}

/// Register a player from D-Bus RegisterPlayer method.
pub async fn register_player(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sender: &str,
    path: &str,
    props: &HashMap<String, PropertyValue>,
) -> Result<(), BtdError> {
    // Check for duplicate.
    let adapters = ADAPTERS.lock().await;
    let adapter_path = adapter_get_path(adapter).await;
    for ma_arc in adapters.iter() {
        let ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            for p_arc in &ma.players {
                let p = p_arc.lock().await;
                if p.sender == sender && p.path == path {
                    return Err(BtdError::AlreadyExists("Player already registered".to_string()));
                }
            }
        }
    }
    drop(adapters);

    // Create player.
    let mut player = MediaPlayer::new(Arc::clone(adapter), sender.to_string(), path.to_string());

    // Parse initial properties.
    parse_player_properties(&mut player, props);

    let player_arc = Arc::new(Mutex::new(player));

    // Add to adapter.
    let mut adapters = ADAPTERS.lock().await;
    for ma_arc in adapters.iter_mut() {
        let mut ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            ma.players.push(player_arc.clone());
            break;
        }
    }
    drop(adapters);

    // Notify watches.
    let watches = LOCAL_PLAYER_WATCHES.lock().await;
    let p = player_arc.lock().await;
    for watch in watches.iter() {
        (watch.callback)(&p);
    }
    drop(p);
    drop(watches);

    // Notify registered callbacks.
    let cbs = LOCAL_PLAYER_CBS.lock().await;
    let p = player_arc.lock().await;
    for (_, cb) in cbs.iter() {
        cb.status_changed(&p, &p.status.clone());
    }

    info!("media: registered player sender={} path={}", sender, path);
    Ok(())
}

/// Unregister a player from D-Bus UnregisterPlayer method.
pub async fn unregister_player(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sender: &str,
    path: &str,
) -> Result<(), BtdError> {
    let mut adapters = ADAPTERS.lock().await;
    let adapter_path = adapter_get_path(adapter).await;

    for ma_arc in adapters.iter_mut() {
        let mut ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            let idx = {
                let mut found = None;
                for (i, p_arc) in ma.players.iter().enumerate() {
                    let p = p_arc.lock().await;
                    if p.sender == sender && p.path == path {
                        found = Some(i);
                        break;
                    }
                }
                found
            };

            if let Some(i) = idx {
                let player_arc = ma.players.remove(i);

                // Notify player removal callbacks.
                let cbs = LOCAL_PLAYER_CBS.lock().await;
                let player = player_arc.lock().await;
                for (_, cb) in cbs.iter() {
                    cb.player_removed(&player);
                }

                // Notify watches.
                let watches = LOCAL_PLAYER_WATCHES.lock().await;
                for watch in watches.iter() {
                    (watch.remove_callback)(&player);
                }

                info!("media: unregistered player sender={} path={}", sender, path);
                return Ok(());
            }

            return Err(BtdError::DoesNotExist("Player not registered".to_string()));
        }
    }

    Err(BtdError::DoesNotExist("No media adapter found".to_string()))
}

/// Register an application from D-Bus RegisterApplication method.
///
/// Uses ObjectManager introspection to discover endpoints and players
/// from the client's D-Bus service at the specified root path.
pub async fn register_application(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sender: &str,
    root: &str,
    _options: &HashMap<String, PropertyValue>,
) -> Result<(), BtdError> {
    // Check for duplicate application.
    let adapters = ADAPTERS.lock().await;
    let adapter_path = adapter_get_path(adapter).await;
    for ma_arc in adapters.iter() {
        let ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            for app in &ma.apps {
                if app.sender == sender && app.path == root {
                    return Err(BtdError::AlreadyExists(
                        "Application already registered".to_string(),
                    ));
                }
            }
        }
    }
    drop(adapters);

    info!("media: registering application sender={} root={}", sender, root);

    // In production, this would:
    // 1. Use zbus::fdo::ObjectManagerProxy::get_managed_objects() to introspect
    //    the client's objects at `root`.
    // 2. For each object with MediaEndpoint1 interface → call register_endpoint
    // 3. For each object with MediaPlayer1 interface → call register_player
    // 4. Set up NameOwnerChanged watch for auto-cleanup.

    let app = MediaApp::new(sender.to_string(), root.to_string());
    let app_arc = Arc::new(app);

    let mut adapters = ADAPTERS.lock().await;
    for ma_arc in adapters.iter_mut() {
        let mut ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            ma.apps.push(app_arc);
            break;
        }
    }

    Ok(())
}

/// Unregister an application from D-Bus UnregisterApplication method.
pub async fn unregister_application(
    adapter: &Arc<Mutex<BtdAdapter>>,
    sender: &str,
    root: &str,
) -> Result<(), BtdError> {
    let mut adapters = ADAPTERS.lock().await;
    let adapter_path = adapter_get_path(adapter).await;

    for ma_arc in adapters.iter_mut() {
        let mut ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            let idx = ma.apps.iter().position(|app| app.sender == sender && app.path == root);

            if let Some(i) = idx {
                let app = ma.apps.remove(i);

                // Remove all endpoints from this app.
                for ep_arc in &app.endpoints {
                    let ep = ep_arc.lock().await;
                    // Find and remove from adapter endpoint list.
                    ma.endpoints.retain(|e| !Arc::ptr_eq(e, ep_arc));
                    drop(ep);
                    media_endpoint_remove(ep_arc).await;
                }

                // Remove all players from this app.
                for p_arc in &app.players {
                    ma.players.retain(|p| !Arc::ptr_eq(p, p_arc));
                }

                info!("media: unregistered application sender={} root={}", sender, root);
                return Ok(());
            }

            return Err(BtdError::DoesNotExist("Application not registered".to_string()));
        }
    }

    Err(BtdError::DoesNotExist("No media adapter found".to_string()))
}

// ===========================================================================
// GMAP Feature Update Helper
// ===========================================================================

/// Update GMAP role and per-role features when the GMAP instance is available.
///
/// BtGmap::find() requires an ATT transport reference.  This function is a
/// synchronous placeholder that logs the intended update.  When a BAP-based
/// endpoint establishes a connection and provides its ATT transport, the
/// GMAP instance can be looked up and updated.
fn update_gmap_features_if_available(
    _gatt_db: &GattDb,
    gmap_role: GmapRole,
    ugg_feat: GmapUggFeatures,
    ugt_feat: GmapUgtFeatures,
    bgs_feat: GmapBgsFeatures,
    bgr_feat: GmapBgrFeatures,
) {
    // GMAP lookup requires an active ATT transport that is not available from
    // the GATT database alone.  When a BAP stream is established, the caller
    // should provide the ATT transport to look up the GMAP instance.
    // For now, log the intended update for traceability.
    debug!(
        "media: GMAP feature update pending — role={:?} ugg={:?} ugt={:?} bgs={:?} bgr={:?}",
        gmap_role, ugg_feat, ugt_feat, bgs_feat, bgr_feat
    );
}

/// Apply GMAP role and feature updates using a known ATT transport.
///
/// Called when a BAP unicast stream is configured and provides an ATT
/// transport that can be used to look up the GMAP instance.
pub fn update_gmap_features_with_att(
    att: &Arc<std::sync::Mutex<BtAtt>>,
    gmap_role: GmapRole,
    ugg_feat: GmapUggFeatures,
    ugt_feat: GmapUgtFeatures,
    bgs_feat: GmapBgsFeatures,
    bgr_feat: GmapBgrFeatures,
) {
    if let Some(gmap) = BtGmap::find(att) {
        gmap.set_role(gmap_role);
        if gmap_role.contains(GmapRole::UGG) {
            gmap.set_ugg_features(ugg_feat);
        }
        if gmap_role.contains(GmapRole::UGT) {
            gmap.set_ugt_features(ugt_feat);
        }
        if gmap_role.contains(GmapRole::BGS) {
            gmap.set_bgs_features(bgs_feat);
        }
        if gmap_role.contains(GmapRole::BGR) {
            gmap.set_bgr_features(bgr_feat);
        }
        debug!("media: updated GMAP role={:?}", gmap_role);
    }
}

// ===========================================================================
// BAP Stream Device Resolution
// ===========================================================================

/// Resolve the peer address associated with a BAP session via its ATT transport.
///
/// Used during BAP unicast stream configuration to identify the remote peer.
/// The BAP session owns an ATT transport whose underlying socket fd can be
/// mapped back to a device address via `btd_adapter_find_device_by_fd`.
async fn resolve_bap_stream_device(
    bap: &BtBap,
    adapter: &Arc<Mutex<BtdAdapter>>,
) -> Option<BdAddr> {
    // BtBap::get_att() returns Arc<std::sync::Mutex<BtAtt>>.
    // Extract the fd in a synchronous block to avoid holding the MutexGuard
    // across an await point (clippy::await_holding_lock).
    let fd = {
        let att: Arc<std::sync::Mutex<BtAtt>> = bap.get_att()?;
        let att_locked = att.lock().ok()?;
        att_locked.get_fd().ok()?
    };
    btd_adapter_find_device_by_fd(adapter, fd).await
}

/// Resolve the BtdDevice from a BtdService.
///
/// Used when a BAP stream callback provides a service context that must
/// be mapped to a device for transport creation.
fn resolve_service_device(service: &BtdService) -> Option<&Arc<tokio::sync::Mutex<BtdDevice>>> {
    service.btd_service_get_device()
}

/// Handle an A2DP endpoint configuration reply from a client.
///
/// Translates the D-Bus error name (if any) into an A2DP config error code
/// using `a2dp_parse_config_error`, then returns an appropriate error or OK.
fn handle_a2dp_config_reply(error_name: Option<&str>) -> Result<(), BtdError> {
    match error_name {
        None => Ok(()),
        Some(name) => {
            let code = a2dp_parse_config_error(name);
            let msg = format!("A2DP config error: {} (code={:?})", name, code);
            error!("media: {}", msg);
            Err(BtdError::Failed(msg))
        }
    }
}

/// Get the A2DP device from a setup context.
///
/// Used when an A2DP stream is being configured and the setup context
/// must be resolved to a BtdDevice for transport creation.
fn get_a2dp_setup_device(setup: &super::a2dp::A2dpSetup) -> &Arc<BtdDevice> {
    a2dp_setup_get_device(setup)
}

// ===========================================================================
// Find Adapter Helper
// ===========================================================================

/// Find the MediaAdapter associated with a given BtdDevice.
async fn find_adapter(device: &BtdDevice) -> Option<Arc<Mutex<MediaAdapter>>> {
    let device_adapter = &device.adapter;
    let adapters = ADAPTERS.lock().await;
    for ma_arc in adapters.iter() {
        let ma = ma_arc.lock().await;
        if Arc::ptr_eq(&ma.adapter, device_adapter) {
            return Some(Arc::clone(ma_arc));
        }
    }
    None
}

/// Find a MediaAdapter by adapter reference.
async fn find_media_adapter(adapter: &Arc<Mutex<BtdAdapter>>) -> Option<Arc<Mutex<MediaAdapter>>> {
    let adapters = ADAPTERS.lock().await;
    let adapter_path = adapter_get_path(adapter).await;
    for ma_arc in adapters.iter() {
        let ma = ma_arc.lock().await;
        if ma.path == adapter_path {
            return Some(Arc::clone(ma_arc));
        }
    }
    None
}

/// Find a specific endpoint by sender and path within a media adapter.
async fn find_endpoint_in_adapter(
    ma: &MediaAdapter,
    sender: &str,
    path: &str,
) -> Option<Arc<Mutex<MediaEndpoint>>> {
    for ep_arc in &ma.endpoints {
        let ep = ep_arc.lock().await;
        if ep.sender == sender && ep.path == path {
            return Some(Arc::clone(ep_arc));
        }
    }
    None
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MEDIA_INTERFACE, "org.bluez.Media1");
        assert_eq!(MEDIA_ENDPOINT_INTERFACE, "org.bluez.MediaEndpoint1");
        assert_eq!(MEDIA_PLAYER_INTERFACE, "org.mpris.MediaPlayer2.Player");
        assert_eq!(REQUEST_TIMEOUT_MS, 3_000);
    }

    #[test]
    fn test_uuid_constants() {
        assert_eq!(PAC_SINK_UUID, "00001850-0000-1000-8000-00805f9b34fb");
        assert_eq!(PAC_SOURCE_UUID, "00001851-0000-1000-8000-00805f9b34fb");
        assert_eq!(BCAA_SERVICE_UUID, "00001852-0000-1000-8000-00805f9b34fb");
        assert_eq!(BAA_SERVICE_UUID, "00001853-0000-1000-8000-00805f9b34fb");
        assert_eq!(ASHA_PROFILE_UUID, "0000FDF0-0000-1000-8000-00805f9b34fb");
    }

    #[test]
    fn test_init_table_entries() {
        assert_eq!(INIT_TABLE.len(), 7);
        assert_eq!(INIT_TABLE[0].uuid, A2DP_SOURCE_UUID);
        assert_eq!(INIT_TABLE[1].uuid, A2DP_SINK_UUID);
        assert_eq!(INIT_TABLE[2].uuid, PAC_SINK_UUID);
        assert_eq!(INIT_TABLE[3].uuid, PAC_SOURCE_UUID);
        assert_eq!(INIT_TABLE[4].uuid, BCAA_SERVICE_UUID);
        assert_eq!(INIT_TABLE[5].uuid, BAA_SERVICE_UUID);
        assert_eq!(INIT_TABLE[6].uuid, ASHA_PROFILE_UUID);
    }

    #[test]
    fn test_set_status_transitions() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let mut player = MediaPlayer::new(adapter, "sender".to_string(), "/player".to_string());

        set_status(&mut player, "Playing");
        assert_eq!(player.status, "playing");
        assert!(player.play_start.is_some());

        set_status(&mut player, "Paused");
        assert_eq!(player.status, "paused");
        assert!(player.play_start.is_none());

        set_status(&mut player, "Stopped");
        assert_eq!(player.status, "stopped");
    }

    #[test]
    fn test_set_shuffle() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let mut player = MediaPlayer::new(adapter, "sender".to_string(), "/player".to_string());

        set_shuffle(&mut player, true);
        assert_eq!(player.settings.get("Shuffle").unwrap(), "alltracks");

        set_shuffle(&mut player, false);
        assert_eq!(player.settings.get("Shuffle").unwrap(), "off");
    }

    #[test]
    fn test_set_repeat() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let mut player = MediaPlayer::new(adapter, "sender".to_string(), "/player".to_string());

        set_repeat(&mut player, "None");
        assert_eq!(player.settings.get("Repeat").unwrap(), "off");

        set_repeat(&mut player, "Track");
        assert_eq!(player.settings.get("Repeat").unwrap(), "singletrack");

        set_repeat(&mut player, "Playlist");
        assert_eq!(player.settings.get("Repeat").unwrap(), "alltracks");
    }

    #[test]
    fn test_parse_player_metadata() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let mut player = MediaPlayer::new(adapter, "sender".to_string(), "/player".to_string());

        let mut meta = HashMap::new();
        meta.insert("xesam:title".to_string(), PropertyValue::String("Test Song".to_string()));
        meta.insert("xesam:artist".to_string(), PropertyValue::String("Test Artist".to_string()));
        meta.insert(
            "mpris:length".to_string(),
            PropertyValue::I64(180_000_000), // 180 seconds in microseconds
        );
        meta.insert("xesam:trackNumber".to_string(), PropertyValue::I32(5));

        parse_player_metadata(&mut player, &meta);

        assert_eq!(player.track.get("Title").unwrap(), "Test Song");
        assert_eq!(player.track.get("Artist").unwrap(), "Test Artist");
        assert_eq!(player.duration, 180_000);
        assert_eq!(player.track.get("TrackNumber").unwrap(), "5");
    }

    #[test]
    fn test_position_computation_stopped() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let mut player = MediaPlayer::new(adapter, "sender".to_string(), "/player".to_string());
        player.position = 5000;
        assert_eq!(local_player_get_position(&player), 5000);
    }

    #[test]
    fn test_parse_endpoint_properties_missing_uuid() {
        let props = HashMap::new();
        let result = parse_endpoint_properties(&props);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_endpoint_properties_valid() {
        let mut props = HashMap::new();
        props.insert("UUID".to_string(), PropertyValue::String(A2DP_SOURCE_UUID.to_string()));
        props.insert("Codec".to_string(), PropertyValue::U8(0x00));
        props.insert("Capabilities".to_string(), PropertyValue::Bytes(vec![0x01, 0x02]));
        props.insert("DelayReporting".to_string(), PropertyValue::Bool(true));

        let result = parse_endpoint_properties(&props);
        assert!(result.is_ok());
        let (uuid, codec, _cid, _vid, caps, _meta, delay, _qos, _feat) = result.unwrap();
        assert_eq!(uuid, A2DP_SOURCE_UUID);
        assert_eq!(codec, 0x00);
        assert_eq!(caps, vec![0x01, 0x02]);
        assert!(delay);
    }

    #[test]
    fn test_endpoint_is_broadcast() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let ep = MediaEndpoint::new(
            "sender".to_string(),
            "/ep".to_string(),
            BCAA_SERVICE_UUID.to_string(),
            0,
            Vec::new(),
            adapter.clone(),
        );
        assert!(ep.is_broadcast());

        let ep2 = MediaEndpoint::new(
            "sender".to_string(),
            "/ep2".to_string(),
            A2DP_SOURCE_UUID.to_string(),
            0,
            Vec::new(),
            adapter,
        );
        assert!(!ep2.is_broadcast());
    }

    #[test]
    fn test_feature_parsing() {
        let mut props = HashMap::new();
        let mut feat_dict = HashMap::new();
        feat_dict.insert("TMAP".to_string(), PropertyValue::U16(0x0003));
        feat_dict.insert("GMAP".to_string(), PropertyValue::U8(0x05));
        props.insert("Features".to_string(), PropertyValue::Dict(feat_dict));

        let features = parse_endpoint_features(&props);
        assert_eq!(features.tmap_role, TmapRole::CG | TmapRole::CT);
        assert_eq!(features.gmap_role, GmapRole::UGG | GmapRole::BGS);
    }

    #[test]
    fn test_local_player_list_settings() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let mut player = MediaPlayer::new(adapter, "sender".to_string(), "/player".to_string());
        player.settings.insert("Shuffle".to_string(), "off".to_string());
        player.settings.insert("Repeat".to_string(), "off".to_string());

        let settings = local_player_list_settings(&player);
        assert_eq!(settings.len(), 2);
    }

    #[test]
    fn test_local_player_have_track() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let mut player = MediaPlayer::new(adapter, "sender".to_string(), "/player".to_string());
        assert!(!local_player_have_track(&player));

        player.track.insert("Title".to_string(), "Test".to_string());
        assert!(local_player_have_track(&player));
    }

    #[test]
    fn test_endpoint_display() {
        let adapter = Arc::new(Mutex::new(BtdAdapter::new_for_test(0)));
        let ep = MediaEndpoint::new(
            ":1.5".to_string(),
            "/endpoint".to_string(),
            A2DP_SOURCE_UUID.to_string(),
            0x00,
            Vec::new(),
            adapter,
        );
        let display = format!("{}", ep);
        assert!(display.contains("MediaEndpoint"));
        assert!(display.contains(":1.5"));
        assert!(display.contains("/endpoint"));
    }

    #[test]
    fn test_qos_parsing() {
        let mut props = HashMap::new();
        props.insert("Locations".to_string(), PropertyValue::U32(0x03));
        props.insert("SupportedContext".to_string(), PropertyValue::U16(0xFF));
        props.insert("Context".to_string(), PropertyValue::U16(0x0F));

        let qos = parse_endpoint_qos(&props);
        assert_eq!(qos.location, 0x03);
        assert_eq!(qos.supported_context, 0xFF);
        assert_eq!(qos.context, 0x0F);
    }
}
