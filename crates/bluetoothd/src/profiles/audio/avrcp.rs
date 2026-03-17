// crates/bluetoothd/src/profiles/audio/avrcp.rs
//
// AVRCP (Audio/Video Remote Control Profile) implementation for bluetoothd.
// Implements both Controller (CT) and Target (TG) roles over AVCTP.
// Manages SDP records, media player discovery/registration, browsing channel,
// absolute volume policy, and vendor-dependent PDU dispatching.
//
// Ported from profiles/audio/avrcp.c (~4989 lines) in BlueZ v5.86.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::adapter::BtdAdapter;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::btd_error;
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{btd_profile_register, btd_profile_unregister, BtdProfile};
use crate::profiles::audio::avctp::{
    avctp_add_state_cb, avctp_connect_browsing, avctp_remove_state_cb, AvctpSession, AvctpState,
    BrowsingPduCb, ControlPduCb, PassthroughCb, AVC_CHANGED, AVC_CTYPE_CONTROL,
    AVC_CTYPE_NOTIFY, AVC_CTYPE_STATUS, AVC_OP_VENDORDEP, AVC_SUBUNIT_PANEL, AVCTP_BROWSING_PSM,
    AVCTP_CONTROL_PSM,
};
use crate::profiles::audio::control::{control_connect, control_disconnect};
use crate::profiles::audio::player::MediaPlayer;
use crate::sdp::{
    add_record_to_server, remove_record_from_server, SdpData, SdpDatabase, SdpRecord,
    L2CAP_UUID, PUBLIC_BROWSE_GROUP, SDP_DEFAULT_ENCODING, SDP_DEFAULT_LANG_CODE,
    SDP_PRIMARY_LANG_BASE,
};
use crate::service::BtdService;

use bluez_shared::sys::bluetooth::BdAddr;

// ===========================================================================
// AVRCP Protocol Constants
// ===========================================================================

/// Bluetooth SIG company ID used in vendor-dependent AVRCP PDUs.
pub const IEEEID_BTSIG: u32 = 0x001958;

// --- PDU IDs (AV/C vendor-dependent) ---
pub const AVRCP_GET_CAPABILITIES: u8 = 0x10;
pub const AVRCP_LIST_PLAYER_ATTRIBUTES: u8 = 0x11;
pub const AVRCP_LIST_PLAYER_VALUES: u8 = 0x12;
pub const AVRCP_GET_CURRENT_PLAYER_VALUE: u8 = 0x13;
pub const AVRCP_SET_PLAYER_VALUE: u8 = 0x14;
pub const AVRCP_GET_PLAYER_ATTRIBUTE_TEXT: u8 = 0x15;
pub const AVRCP_GET_PLAYER_VALUE_TEXT: u8 = 0x16;
pub const AVRCP_DISPLAYABLE_CHARSET: u8 = 0x17;
pub const AVRCP_CT_BATTERY_STATUS: u8 = 0x18;
pub const AVRCP_GET_ELEMENT_ATTRIBUTES: u8 = 0x20;
pub const AVRCP_GET_PLAY_STATUS: u8 = 0x30;
pub const AVRCP_REGISTER_NOTIFICATION: u8 = 0x31;
pub const AVRCP_REQUEST_CONTINUING: u8 = 0x40;
pub const AVRCP_ABORT_CONTINUING: u8 = 0x41;
pub const AVRCP_SET_ABSOLUTE_VOLUME: u8 = 0x50;
pub const AVRCP_SET_ADDRESSED_PLAYER: u8 = 0x60;
pub const AVRCP_SET_BROWSED_PLAYER: u8 = 0x70;
pub const AVRCP_GET_FOLDER_ITEMS: u8 = 0x71;
pub const AVRCP_CHANGE_PATH: u8 = 0x72;
pub const AVRCP_GET_ITEM_ATTRIBUTES: u8 = 0x73;
pub const AVRCP_PLAY_ITEM: u8 = 0x74;
pub const AVRCP_SEARCH: u8 = 0x78;
pub const AVRCP_ADD_TO_NOW_PLAYING: u8 = 0x79;
pub const AVRCP_GENERAL_REJECT: u8 = 0xA0;

// --- Status codes ---
pub const AVRCP_STATUS_INVALID_COMMAND: u8 = 0x00;
pub const AVRCP_STATUS_INVALID_PARAM: u8 = 0x01;
pub const AVRCP_STATUS_PARAM_NOT_FOUND: u8 = 0x02;
pub const AVRCP_STATUS_INTERNAL_ERROR: u8 = 0x03;
pub const AVRCP_STATUS_SUCCESS: u8 = 0x04;
pub const AVRCP_STATUS_UID_CHANGED: u8 = 0x05;
pub const AVRCP_STATUS_INVALID_DIRECTION: u8 = 0x07;
pub const AVRCP_STATUS_NOT_DIRECTORY: u8 = 0x08;
pub const AVRCP_STATUS_DOES_NOT_EXIST: u8 = 0x09;
pub const AVRCP_STATUS_INVALID_SCOPE: u8 = 0x0A;
pub const AVRCP_STATUS_OUT_OF_BOUNDS: u8 = 0x0B;
pub const AVRCP_STATUS_MEDIA_IN_USE: u8 = 0x0C;
pub const AVRCP_STATUS_NOW_PLAYING_LIST_FULL: u8 = 0x0D;
pub const AVRCP_STATUS_SEARCH_NOT_SUPPORTED: u8 = 0x0E;
pub const AVRCP_STATUS_SEARCH_IN_PROGRESS: u8 = 0x0F;
pub const AVRCP_STATUS_INVALID_PLAYER_ID: u8 = 0x11;
pub const AVRCP_STATUS_PLAYER_NOT_BROWSABLE: u8 = 0x12;
pub const AVRCP_STATUS_PLAYER_NOT_ADDRESSED: u8 = 0x13;
pub const AVRCP_STATUS_NO_VALID_SEARCH_RESULTS: u8 = 0x14;
pub const AVRCP_STATUS_NO_AVAILABLE_PLAYERS: u8 = 0x15;
pub const AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED: u8 = 0x16;

// --- Events ---
pub const AVRCP_EVENT_STATUS_CHANGED: u8 = 0x01;
pub const AVRCP_EVENT_TRACK_CHANGED: u8 = 0x02;
pub const AVRCP_EVENT_TRACK_REACHED_END: u8 = 0x03;
pub const AVRCP_EVENT_TRACK_REACHED_START: u8 = 0x04;
pub const AVRCP_EVENT_PLAYBACK_POS_CHANGED: u8 = 0x05;
pub const AVRCP_EVENT_SETTINGS_CHANGED: u8 = 0x08;
pub const AVRCP_EVENT_NOW_PLAYING_CHANGED: u8 = 0x09;
pub const AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED: u8 = 0x0A;
pub const AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED: u8 = 0x0B;
pub const AVRCP_EVENT_UIDS_CHANGED: u8 = 0x0C;
pub const AVRCP_EVENT_VOLUME_CHANGED: u8 = 0x0D;
pub const AVRCP_EVENT_LAST_DEFINED: u8 = AVRCP_EVENT_VOLUME_CHANGED;

// --- Player application setting attributes ---
pub const AVRCP_ATTRIBUTE_EQUALIZER: u8 = 0x01;
pub const AVRCP_ATTRIBUTE_REPEAT_MODE: u8 = 0x02;
pub const AVRCP_ATTRIBUTE_SHUFFLE: u8 = 0x03;
pub const AVRCP_ATTRIBUTE_SCAN: u8 = 0x04;

// --- Player application setting values ---
pub const AVRCP_EQUALIZER_OFF: u8 = 0x01;
pub const AVRCP_EQUALIZER_ON: u8 = 0x02;
pub const AVRCP_REPEAT_MODE_OFF: u8 = 0x01;
pub const AVRCP_REPEAT_MODE_SINGLE: u8 = 0x02;
pub const AVRCP_REPEAT_MODE_ALL: u8 = 0x03;
pub const AVRCP_REPEAT_MODE_GROUP: u8 = 0x04;
pub const AVRCP_SHUFFLE_OFF: u8 = 0x01;
pub const AVRCP_SHUFFLE_ALL: u8 = 0x02;
pub const AVRCP_SHUFFLE_GROUP: u8 = 0x03;
pub const AVRCP_SCAN_OFF: u8 = 0x01;
pub const AVRCP_SCAN_ALL: u8 = 0x02;
pub const AVRCP_SCAN_GROUP: u8 = 0x03;

// --- Media attributes ---
pub const AVRCP_MEDIA_ATTRIBUTE_TITLE: u32 = 0x01;
pub const AVRCP_MEDIA_ATTRIBUTE_ARTIST: u32 = 0x02;
pub const AVRCP_MEDIA_ATTRIBUTE_ALBUM: u32 = 0x03;
pub const AVRCP_MEDIA_ATTRIBUTE_TRACK: u32 = 0x04;
pub const AVRCP_MEDIA_ATTRIBUTE_N_TRACKS: u32 = 0x05;
pub const AVRCP_MEDIA_ATTRIBUTE_GENRE: u32 = 0x06;
pub const AVRCP_MEDIA_ATTRIBUTE_DURATION: u32 = 0x07;
pub const AVRCP_MEDIA_ATTRIBUTE_IMG_HANDLE: u32 = 0x08;

// --- Play status ---
pub const AVRCP_PLAY_STATUS_STOPPED: u8 = 0x00;
pub const AVRCP_PLAY_STATUS_PLAYING: u8 = 0x01;
pub const AVRCP_PLAY_STATUS_PAUSED: u8 = 0x02;
pub const AVRCP_PLAY_STATUS_FWD_SEEK: u8 = 0x03;
pub const AVRCP_PLAY_STATUS_REV_SEEK: u8 = 0x04;
pub const AVRCP_PLAY_STATUS_ERROR: u8 = 0xFF;

// --- Scope types ---
pub const AVRCP_MEDIA_PLAYER_LIST: u8 = 0x00;
pub const AVRCP_MEDIA_PLAYER_VFS: u8 = 0x01;
pub const AVRCP_MEDIA_SEARCH: u8 = 0x02;
pub const AVRCP_MEDIA_NOW_PLAYING: u8 = 0x03;

// --- Capability types ---
pub const AVRCP_CAP_COMPANY_ID: u8 = 0x02;
pub const AVRCP_CAP_EVENTS_SUPPORTED: u8 = 0x03;

// --- Internal protocol constants ---
pub const AVRCP_HEADER_LENGTH: usize = 7; // company_id(3) + pdu_id(1) + pkt_type:param_len(3)
pub const AVRCP_MTU: usize = 512;
pub const AVRCP_PDU_MTU: usize = AVRCP_MTU - AVRCP_HEADER_LENGTH;
pub const AVRCP_BROWSING_HEADER_LENGTH: usize = 3; // pdu_id(1) + param_len(2)
pub const AVRCP_BROWSING_TIMEOUT: u64 = 1; // seconds
pub const AVRCP_CT_VERSION: u16 = 0x0106; // AVRCP 1.6
pub const AVRCP_TG_VERSION: u16 = 0x0106; // AVRCP 1.6

// --- Packet types ---
const AVRCP_PACKET_TYPE_SINGLE: u8 = 0x00;
const AVRCP_PACKET_TYPE_START: u8 = 0x01;
const AVRCP_PACKET_TYPE_CONTINUING: u8 = 0x02;
const AVRCP_PACKET_TYPE_END: u8 = 0x03;

// --- SDP UUIDs ---
pub const AV_REMOTE_SVCLASS_ID: u16 = 0x110E;
pub const AV_REMOTE_CONTROLLER_SVCLASS_ID: u16 = 0x110F;
pub const AV_REMOTE_TARGET_SVCLASS_ID: u16 = 0x110C;
pub const AVCTP_PROTO_UUID: u16 = 0x0017;
pub const AVRCP_PROFILE_UUID: u16 = 0x110E;

// --- SDP feature flags ---
pub const AVRCP_FEATURE_CATEGORY_1: u16 = 0x0001;
pub const AVRCP_FEATURE_CATEGORY_2: u16 = 0x0002;
pub const AVRCP_FEATURE_CATEGORY_3: u16 = 0x0004;
pub const AVRCP_FEATURE_CATEGORY_4: u16 = 0x0008;
pub const AVRCP_FEATURE_PLAYER_SETTINGS: u16 = 0x0010;
pub const AVRCP_FEATURE_BROWSING: u16 = 0x0040;

// --- Passthrough operation IDs ---
const PASSTHROUGH_PLAY: u8 = 0x44;
const PASSTHROUGH_STOP: u8 = 0x45;
const PASSTHROUGH_PAUSE: u8 = 0x46;
const PASSTHROUGH_REWIND: u8 = 0x48;
const PASSTHROUGH_FAST_FORWARD: u8 = 0x49;
const PASSTHROUGH_FORWARD: u8 = 0x4B;
const PASSTHROUGH_BACKWARD: u8 = 0x4C;

// --- SDP attribute IDs ---
pub const SDP_ATTR_SUPPORTED_FEATURES: u16 = 0x0311;

// ===========================================================================
// Supported events bitmask (TG side)
// ===========================================================================

const SUPPORTED_EVENTS_MASK: u32 = (1 << AVRCP_EVENT_STATUS_CHANGED)
    | (1 << AVRCP_EVENT_TRACK_CHANGED)
    | (1 << AVRCP_EVENT_TRACK_REACHED_END)
    | (1 << AVRCP_EVENT_TRACK_REACHED_START)
    | (1 << AVRCP_EVENT_PLAYBACK_POS_CHANGED)
    | (1 << AVRCP_EVENT_SETTINGS_CHANGED)
    | (1 << AVRCP_EVENT_NOW_PLAYING_CHANGED)
    | (1 << AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED)
    | (1 << AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED)
    | (1 << AVRCP_EVENT_UIDS_CHANGED)
    | (1 << AVRCP_EVENT_VOLUME_CHANGED);

// ===========================================================================
// Helper Functions — PDU building
// ===========================================================================

/// Build vendor-dependent operands with AVRCP header.
/// Returns bytes: [company_id(3)] + [pdu_id(1)] + [packet_type:param_len(3)] + [params]
fn build_vendordep_pdu(pdu_id: u8, packet_type: u8, params: &[u8]) -> Vec<u8> {
    let param_len = params.len() as u16;
    let mut buf = Vec::with_capacity(AVRCP_HEADER_LENGTH + params.len());
    // Company ID (BT SIG) — 3 bytes big-endian
    buf.push(((IEEEID_BTSIG >> 16) & 0xFF) as u8);
    buf.push(((IEEEID_BTSIG >> 8) & 0xFF) as u8);
    buf.push((IEEEID_BTSIG & 0xFF) as u8);
    // PDU ID
    buf.push(pdu_id);
    // Packet type (high nibble) + reserved (low nibble) combined with param_len
    buf.push(packet_type & 0x03);
    buf.push((param_len >> 8) as u8);
    buf.push((param_len & 0xFF) as u8);
    // Parameters
    buf.extend_from_slice(params);
    buf
}

/// Build browsing PDU: [pdu_id(1)] + [param_len(2)] + [params]
fn build_browsing_pdu(pdu_id: u8, params: &[u8]) -> Vec<u8> {
    let param_len = params.len() as u16;
    let mut buf = Vec::with_capacity(AVRCP_BROWSING_HEADER_LENGTH + params.len());
    buf.push(pdu_id);
    buf.push((param_len >> 8) as u8);
    buf.push((param_len & 0xFF) as u8);
    buf.extend_from_slice(params);
    buf
}

/// Build a simple status-only browsing response.
fn build_browsing_status(pdu_id: u8, status: u8) -> Vec<u8> {
    build_browsing_pdu(pdu_id, &[status])
}

/// Parse AVRCP vendor-dependent header from operands.
/// Returns (company_id, pdu_id, packet_type, params_slice) or None.
fn parse_vendordep_header(operands: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    if operands.len() < AVRCP_HEADER_LENGTH {
        return None;
    }
    let company_id =
        ((operands[0] as u32) << 16) | ((operands[1] as u32) << 8) | (operands[2] as u32);
    let pdu_id = operands[3];
    let packet_type = operands[4] & 0x03;
    let param_len = ((operands[5] as usize) << 8) | (operands[6] as usize);
    let params_end = AVRCP_HEADER_LENGTH + param_len;
    if operands.len() < params_end {
        // Truncated — use what we have
        Some((company_id, pdu_id, packet_type, &operands[AVRCP_HEADER_LENGTH..]))
    } else {
        Some((company_id, pdu_id, packet_type, &operands[AVRCP_HEADER_LENGTH..params_end]))
    }
}

/// Parse browsing PDU header: returns (pdu_id, params) or None.
fn parse_browsing_header(operands: &[u8]) -> Option<(u8, &[u8])> {
    if operands.len() < AVRCP_BROWSING_HEADER_LENGTH {
        return None;
    }
    let pdu_id = operands[0];
    let param_len = ((operands[1] as usize) << 8) | (operands[2] as usize);
    let end = AVRCP_BROWSING_HEADER_LENGTH + param_len;
    if operands.len() < end {
        Some((pdu_id, &operands[AVRCP_BROWSING_HEADER_LENGTH..]))
    } else {
        Some((pdu_id, &operands[AVRCP_BROWSING_HEADER_LENGTH..end]))
    }
}

/// List of all supported player attributes.
const PLAYER_ATTRS: [u8; 4] = [
    AVRCP_ATTRIBUTE_EQUALIZER,
    AVRCP_ATTRIBUTE_REPEAT_MODE,
    AVRCP_ATTRIBUTE_SHUFFLE,
    AVRCP_ATTRIBUTE_SCAN,
];

/// List of all media attribute IDs.
const MEDIA_ATTR_IDS: [u32; 7] = [
    AVRCP_MEDIA_ATTRIBUTE_TITLE,
    AVRCP_MEDIA_ATTRIBUTE_ARTIST,
    AVRCP_MEDIA_ATTRIBUTE_ALBUM,
    AVRCP_MEDIA_ATTRIBUTE_TRACK,
    AVRCP_MEDIA_ATTRIBUTE_N_TRACKS,
    AVRCP_MEDIA_ATTRIBUTE_GENRE,
    AVRCP_MEDIA_ATTRIBUTE_DURATION,
];

// ===========================================================================
// Traits
// ===========================================================================

/// Callbacks for a local TG player supplying media data.
pub trait AvrcpPlayerCallbacks: Send + Sync {
    fn get_metadata(&self) -> HashMap<u32, String>;
    fn get_status(&self) -> u8;
    fn get_position(&self) -> u32;
    fn get_duration(&self) -> u32;
    fn get_setting(&self, attr: u8) -> u8;
    fn set_setting(&self, attr: u8, value: u8);
    fn list_settings(&self) -> Vec<u8>;
    fn play(&self);
    fn stop(&self);
    fn pause(&self);
    fn next(&self);
    fn previous(&self);
    fn fast_forward(&self, pressed: bool);
    fn rewind(&self, pressed: bool);
}

/// Indication callbacks for incoming vendor-dependent commands (TG dispatches).
pub trait AvrcpControlInd: Send + Sync {
    fn get_capabilities(&self, cap_id: u8) -> Option<Vec<u8>>;
    fn list_attributes(&self) -> Option<Vec<u8>>;
    fn get_attribute_text(&self, attrs: &[u8]) -> Option<Vec<u8>>;
    fn list_values(&self, attr: u8) -> Option<Vec<u8>>;
    fn get_value_text(&self, attr: u8, values: &[u8]) -> Option<Vec<u8>>;
    fn get_value(&self, attrs: &[u8]) -> Option<Vec<u8>>;
    fn set_value(&self, params: &[u8]) -> Option<Vec<u8>>;
    fn get_play_status(&self) -> Option<Vec<u8>>;
    fn get_element_attributes(&self, params: &[u8]) -> Option<Vec<u8>>;
    fn register_notification(&self, event: u8, interval: u32) -> Option<Vec<u8>>;
    fn set_volume(&self, volume: u8) -> Option<Vec<u8>>;
    fn set_addressed(&self, player_id: u16) -> Option<Vec<u8>>;
    fn set_browsed(&self, player_id: u16) -> Option<Vec<u8>>;
    fn get_folder_items(&self, params: &[u8]) -> Option<Vec<u8>>;
    fn change_path(&self, params: &[u8]) -> Option<Vec<u8>>;
    fn get_item_attributes(&self, params: &[u8]) -> Option<Vec<u8>>;
    fn play_item(&self, params: &[u8]) -> Option<Vec<u8>>;
    fn search(&self, params: &[u8]) -> Option<Vec<u8>>;
    fn add_to_now_playing(&self, params: &[u8]) -> Option<Vec<u8>>;
}

/// Confirmation callbacks for CT-initiated command responses.
pub trait AvrcpControlCfm: Send + Sync {
    fn get_capabilities(&self, params: &[u8]);
    fn list_attributes(&self, params: &[u8]);
    fn get_attribute_text(&self, params: &[u8]);
    fn list_values(&self, params: &[u8]);
    fn get_value_text(&self, params: &[u8]);
    fn get_value(&self, params: &[u8]);
    fn set_value(&self, params: &[u8]);
    fn get_play_status(&self, params: &[u8]);
    fn get_element_attributes(&self, params: &[u8]);
    fn register_notification(&self, params: &[u8]);
    fn set_volume(&self, params: &[u8]);
    fn set_addressed(&self, params: &[u8]);
    fn set_browsed(&self, params: &[u8]);
    fn get_folder_items(&self, params: &[u8]);
    fn change_path(&self, params: &[u8]);
    fn get_item_attributes(&self, params: &[u8]);
    fn play_item(&self, params: &[u8]);
    fn search(&self, params: &[u8]);
    fn add_to_now_playing(&self, params: &[u8]);
}

/// Passthrough handler binding an operation ID to a handler function.
pub struct AvrcpPassthroughHandler {
    pub op: u8,
    pub handler: Box<dyn Fn(bool) + Send + Sync>,
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// State for a fragmented TG response (continuing PDU).
pub struct PendingPdu {
    /// The PDU ID being fragmented.
    pub pdu_id: u8,
    /// The complete response data buffer.
    pub data: Vec<u8>,
    /// Current send offset within data.
    pub offset: usize,
}

/// Per-adapter AVRCP server state.
pub struct AvrcpServer {
    /// Reference to the adapter this server is associated with.
    pub adapter: Arc<TokioMutex<BtdAdapter>>,
    /// Cached address of the adapter (used for SDP record operations).
    pub adapter_address: BdAddr,
    pub ct_record_id: u32,
    pub tg_record_id: u32,
    pub players: Vec<Arc<AvrcpPlayer>>,
    pub sessions: Vec<Arc<StdMutex<AvrcpSession>>>,
}

/// Per-device AVRCP session state.
pub struct AvrcpSession {
    pub server: Option<Arc<StdMutex<AvrcpServer>>>,
    pub device: Arc<BtdDevice>,
    pub avctp: Arc<TokioMutex<AvctpSession>>,
    device_path: String,
    // TG state
    pub target_player: Option<Arc<AvrcpPlayer>>,
    pub pending_pdu: Option<PendingPdu>,
    pub registered_events: u32,
    pub supported_events: u32,
    // CT state
    pub controller_player: Option<Arc<MediaPlayer>>,
    // Feature negotiation
    pub ct_version: u16,
    pub ct_features: u16,
    pub tg_version: u16,
    pub tg_features: u16,
    // Browsing
    pub browsing_timer: Option<JoinHandle<()>>,
    // Transaction tracking
    transaction_counter: u8,
}

/// A local TG player registered with the AVRCP server.
pub struct AvrcpPlayer {
    pub id: u16,
    pub callbacks: Box<dyn AvrcpPlayerCallbacks>,
    pub server: Option<Arc<StdMutex<AvrcpServer>>>,
    pub sessions: Vec<Arc<StdMutex<AvrcpSession>>>,
}

impl fmt::Display for AvrcpPlayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AvrcpPlayer(id={})", self.id)
    }
}

impl fmt::Display for AvrcpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AvrcpSession(path={})", self.device_path)
    }
}

// ===========================================================================
// Module-Level State
// ===========================================================================

static SERVERS: LazyLock<StdMutex<Vec<Arc<StdMutex<AvrcpServer>>>>> =
    LazyLock::new(|| StdMutex::new(Vec::new()));

static STATE_CB_ID: LazyLock<StdMutex<Option<u32>>> = LazyLock::new(|| StdMutex::new(None));

static NEXT_PLAYER_ID: LazyLock<StdMutex<u16>> = LazyLock::new(|| StdMutex::new(1));

fn next_player_id() -> u16 {
    let mut id = NEXT_PLAYER_ID.lock().unwrap();
    let current = *id;
    *id = id.wrapping_add(1);
    current
}

// ===========================================================================
// SDP Record Builders
// ===========================================================================

/// Build the AVRCP Controller SDP record.
pub fn avrcp_ct_record() -> SdpRecord {
    let mut rec = SdpRecord::new(0);
    rec.set_service_classes(&[AV_REMOTE_SVCLASS_ID, AV_REMOTE_CONTROLLER_SVCLASS_ID]);
    // Protocol descriptor: L2CAP(PSM_AVCTP) -> AVCTP(version 1.4)
    let l2cap_proto = vec![
        SdpData::Uuid16(L2CAP_UUID),
        SdpData::UInt16(AVCTP_CONTROL_PSM),
    ];
    let avctp_proto = vec![SdpData::Uuid16(AVCTP_PROTO_UUID), SdpData::UInt16(0x0104)];
    rec.set_access_protos(&[l2cap_proto, avctp_proto]);
    // Additional protocol: browsing channel
    let l2cap_browse = vec![
        SdpData::Uuid16(L2CAP_UUID),
        SdpData::UInt16(AVCTP_BROWSING_PSM),
    ];
    let avctp_browse = vec![SdpData::Uuid16(AVCTP_PROTO_UUID), SdpData::UInt16(0x0104)];
    rec.set_add_access_protos(&[l2cap_browse, avctp_browse]);
    // Profile descriptor: AVRCP 1.6
    rec.set_profile_descs(&[(AVRCP_PROFILE_UUID, AVRCP_CT_VERSION)]);
    // Browse group
    rec.set_browse_groups(&[PUBLIC_BROWSE_GROUP]);
    // Language
    rec.add_lang_attr(SDP_DEFAULT_LANG_CODE, SDP_DEFAULT_ENCODING, SDP_PRIMARY_LANG_BASE);
    // Service name
    rec.set_info_attr("AVRCP CT", "", "");
    // Supported features
    let features = AVRCP_FEATURE_CATEGORY_1 | AVRCP_FEATURE_CATEGORY_2 | AVRCP_FEATURE_BROWSING;
    rec.set_attribute(SDP_ATTR_SUPPORTED_FEATURES, SdpData::UInt16(features));
    rec
}

/// Build the AVRCP Target SDP record.
pub fn avrcp_tg_record() -> SdpRecord {
    let mut rec = SdpRecord::new(0);
    rec.set_service_classes(&[AV_REMOTE_TARGET_SVCLASS_ID]);
    // Protocol descriptor: L2CAP(PSM_AVCTP) -> AVCTP(version 1.4)
    let l2cap_proto = vec![
        SdpData::Uuid16(L2CAP_UUID),
        SdpData::UInt16(AVCTP_CONTROL_PSM),
    ];
    let avctp_proto = vec![SdpData::Uuid16(AVCTP_PROTO_UUID), SdpData::UInt16(0x0104)];
    rec.set_access_protos(&[l2cap_proto, avctp_proto]);
    // Additional protocol: browsing channel
    let l2cap_browse = vec![
        SdpData::Uuid16(L2CAP_UUID),
        SdpData::UInt16(AVCTP_BROWSING_PSM),
    ];
    let avctp_browse = vec![SdpData::Uuid16(AVCTP_PROTO_UUID), SdpData::UInt16(0x0104)];
    rec.set_add_access_protos(&[l2cap_browse, avctp_browse]);
    // Profile descriptor: AVRCP 1.6
    rec.set_profile_descs(&[(AVRCP_PROFILE_UUID, AVRCP_TG_VERSION)]);
    // Browse group
    rec.set_browse_groups(&[PUBLIC_BROWSE_GROUP]);
    // Language
    rec.add_lang_attr(SDP_DEFAULT_LANG_CODE, SDP_DEFAULT_ENCODING, SDP_PRIMARY_LANG_BASE);
    // Service name
    rec.set_info_attr("AVRCP TG", "", "");
    // Supported features
    let features = AVRCP_FEATURE_CATEGORY_1
        | AVRCP_FEATURE_CATEGORY_2
        | AVRCP_FEATURE_PLAYER_SETTINGS
        | AVRCP_FEATURE_BROWSING;
    rec.set_attribute(SDP_ATTR_SUPPORTED_FEATURES, SdpData::UInt16(features));
    rec
}

// ===========================================================================
// AvrcpSession Implementation
// ===========================================================================

impl AvrcpSession {
    /// Create a new AVRCP session for the given device/AVCTP/server combination.
    pub fn new(
        device: Arc<BtdDevice>,
        avctp: Arc<TokioMutex<AvctpSession>>,
        server: Arc<StdMutex<AvrcpServer>>,
    ) -> Self {
        let device_path = device.get_path().to_string();
        Self {
            server: Some(server),
            device,
            avctp,
            device_path,
            target_player: None,
            pending_pdu: None,
            registered_events: 0,
            supported_events: SUPPORTED_EVENTS_MASK,
            controller_player: None,
            ct_version: 0,
            ct_features: 0,
            tg_version: 0,
            tg_features: 0,
            browsing_timer: None,
            transaction_counter: 0,
        }
    }

    /// Shut down this session, cancelling timers and cleaning up.
    pub fn shutdown(&mut self) {
        if let Some(timer) = self.browsing_timer.take() {
            timer.abort();
        }
        self.target_player = None;
        self.controller_player = None;
        self.pending_pdu = None;
        self.registered_events = 0;
        debug!("AVRCP session shut down for {}", self.device_path);
    }

    /// Schedule browsing channel connection after a delay.
    pub fn connect_browsing(&mut self, avctp_arc: Arc<TokioMutex<AvctpSession>>) {
        if self.browsing_timer.is_some() {
            return; // Already scheduled
        }
        let avctp_clone = avctp_arc;
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(AVRCP_BROWSING_TIMEOUT)).await;
            if let Err(e) = avctp_connect_browsing(&avctp_clone).await {
                debug!("AVRCP browsing connection failed: {:?}", e);
            }
        });
        self.browsing_timer = Some(handle);
    }

    /// Set a destroy callback (no-op in Rust — RAII handles cleanup).
    pub fn set_destroy_cb(&mut self) {
        // In Rust, destruction is handled by Drop.
    }

    /// Register a local TG player with this session.
    pub fn register_player(&mut self, player: Arc<AvrcpPlayer>) {
        self.target_player = Some(player);
        debug!("Registered target player on session {}", self.device_path);
    }

    /// Set passthrough handlers on the underlying AVCTP session.
    pub fn set_passthrough_handlers(&self) {
        // Passthrough handler registration happens during init_control
    }

    /// Get the next transaction label (wraps 0–15).
    pub fn next_transaction(&mut self) -> u8 {
        let txn = self.transaction_counter;
        self.transaction_counter = (txn + 1) & 0x0F;
        txn
    }
}

// ===========================================================================
// Handler Registration (called when control/browsing channels connect)
// ===========================================================================

/// Register AVRCP vendor-dependent and passthrough handlers on the AVCTP session.
fn init_control_handlers(
    avrcp_session: Arc<StdMutex<AvrcpSession>>,
    avctp_session: &mut AvctpSession,
) {
    // Vendor-dependent PDU handler (TG role)
    let sess_clone = avrcp_session.clone();
    let control_handler: ControlPduCb =
        Box::new(move |transaction, ctype, _subunit, operands| {
            if let Ok(mut sess) = sess_clone.lock() {
                handle_vendordep_pdu(&mut sess, transaction, ctype, operands)
            } else {
                None
            }
        });
    avctp_session.register_pdu_handler(AVC_OP_VENDORDEP, control_handler);

    // Passthrough handler
    let sess_clone2 = avrcp_session.clone();
    let passthrough_handler: PassthroughCb = Box::new(move |op, pressed, _subunit| {
        if let Ok(sess) = sess_clone2.lock() {
            handle_passthrough(&sess, op, pressed)
        } else {
            false
        }
    });
    avctp_session.register_passthrough_handler(passthrough_handler);

    debug!("AVRCP control handlers registered");
}

/// Register AVRCP browsing handler on the AVCTP session.
fn init_browsing_handlers(
    avrcp_session: Arc<StdMutex<AvrcpSession>>,
    avctp_session: &mut AvctpSession,
) {
    let sess_clone = avrcp_session.clone();
    let browsing_handler: BrowsingPduCb = Box::new(move |_transaction, operands| {
        if let Ok(mut sess) = sess_clone.lock() {
            handle_browsing_dispatch(&mut sess, operands)
        } else {
            None
        }
    });
    avctp_session.register_browsing_handler(browsing_handler);

    debug!("AVRCP browsing handlers registered");
}

// ===========================================================================
// TG — Vendor-Dependent PDU Dispatch
// ===========================================================================

/// Main TG vendor-dependent PDU handler. Parses AVRCP header and dispatches.
fn handle_vendordep_pdu(
    session: &mut AvrcpSession,
    _transaction: u8,
    ctype: u8,
    operands: &[u8],
) -> Option<Vec<u8>> {
    let (company_id, pdu_id, _packet_type, params) = parse_vendordep_header(operands)?;

    if company_id != IEEEID_BTSIG {
        debug!("AVRCP: non-BT SIG company ID {:#08x}, ignoring", company_id);
        return None;
    }

    debug!("AVRCP TG: PDU {:#04x}, ctype={:#04x}, params_len={}", pdu_id, ctype, params.len());

    match pdu_id {
        AVRCP_GET_CAPABILITIES => handle_get_capabilities(session, ctype, params),
        AVRCP_LIST_PLAYER_ATTRIBUTES => handle_list_player_attributes(session, ctype),
        AVRCP_LIST_PLAYER_VALUES => handle_list_player_values(session, ctype, params),
        AVRCP_GET_CURRENT_PLAYER_VALUE => handle_get_current_player_value(session, ctype, params),
        AVRCP_SET_PLAYER_VALUE => handle_set_player_value(session, ctype, params),
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT => handle_get_player_attribute_text(session, ctype, params),
        AVRCP_GET_PLAYER_VALUE_TEXT => handle_get_player_value_text(session, ctype, params),
        AVRCP_DISPLAYABLE_CHARSET => handle_displayable_charset(session, ctype),
        AVRCP_CT_BATTERY_STATUS => handle_battery_status(session, ctype),
        AVRCP_GET_ELEMENT_ATTRIBUTES => handle_get_element_attributes(session, ctype, params),
        AVRCP_GET_PLAY_STATUS => handle_get_play_status(session, ctype),
        AVRCP_REGISTER_NOTIFICATION => handle_register_notification(session, ctype, params),
        AVRCP_REQUEST_CONTINUING => handle_request_continuing(session, ctype, params),
        AVRCP_ABORT_CONTINUING => handle_abort_continuing(session, ctype, params),
        AVRCP_SET_ABSOLUTE_VOLUME => handle_set_absolute_volume(session, ctype, params),
        AVRCP_SET_ADDRESSED_PLAYER => handle_set_addressed_player(session, ctype, params),
        _ => {
            warn!("AVRCP TG: unsupported PDU {:#04x}", pdu_id);
            Some(build_vendordep_pdu(pdu_id, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_COMMAND]))
        }
    }
}

// ===========================================================================
// TG — Individual Vendor-Dependent Handlers
// ===========================================================================

fn handle_get_capabilities(
    session: &AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS || params.is_empty() {
        return Some(build_vendordep_pdu(
            AVRCP_GET_CAPABILITIES, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let cap_id = params[0];
    match cap_id {
        AVRCP_CAP_COMPANY_ID => {
            // Return BT SIG company ID
            let resp = [
                AVRCP_STATUS_SUCCESS,
                AVRCP_CAP_COMPANY_ID,
                1, // count
                ((IEEEID_BTSIG >> 16) & 0xFF) as u8,
                ((IEEEID_BTSIG >> 8) & 0xFF) as u8,
                (IEEEID_BTSIG & 0xFF) as u8,
            ];
            Some(build_vendordep_pdu(AVRCP_GET_CAPABILITIES, AVRCP_PACKET_TYPE_SINGLE, &resp))
        }
        AVRCP_CAP_EVENTS_SUPPORTED => {
            let mut events = Vec::new();
            for ev in 1..=AVRCP_EVENT_LAST_DEFINED {
                if session.supported_events & (1u32 << ev) != 0 {
                    events.push(ev);
                }
            }
            let mut resp = vec![AVRCP_STATUS_SUCCESS, AVRCP_CAP_EVENTS_SUPPORTED, events.len() as u8];
            resp.extend_from_slice(&events);
            Some(build_vendordep_pdu(AVRCP_GET_CAPABILITIES, AVRCP_PACKET_TYPE_SINGLE, &resp))
        }
        _ => Some(build_vendordep_pdu(
            AVRCP_GET_CAPABILITIES, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_PARAM],
        )),
    }
}

fn handle_list_player_attributes(_session: &AvrcpSession, ctype: u8) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS {
        return None;
    }
    let mut resp = vec![PLAYER_ATTRS.len() as u8];
    resp.extend_from_slice(&PLAYER_ATTRS);
    Some(build_vendordep_pdu(AVRCP_LIST_PLAYER_ATTRIBUTES, AVRCP_PACKET_TYPE_SINGLE, &resp))
}

fn handle_list_player_values(
    _session: &AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS || params.is_empty() {
        return Some(build_vendordep_pdu(
            AVRCP_LIST_PLAYER_VALUES, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let attr = params[0];
    let values: Vec<u8> = match attr {
        AVRCP_ATTRIBUTE_EQUALIZER => vec![AVRCP_EQUALIZER_OFF, AVRCP_EQUALIZER_ON],
        AVRCP_ATTRIBUTE_REPEAT_MODE => vec![
            AVRCP_REPEAT_MODE_OFF, AVRCP_REPEAT_MODE_SINGLE,
            AVRCP_REPEAT_MODE_ALL, AVRCP_REPEAT_MODE_GROUP,
        ],
        AVRCP_ATTRIBUTE_SHUFFLE => vec![AVRCP_SHUFFLE_OFF, AVRCP_SHUFFLE_ALL, AVRCP_SHUFFLE_GROUP],
        AVRCP_ATTRIBUTE_SCAN => vec![AVRCP_SCAN_OFF, AVRCP_SCAN_ALL, AVRCP_SCAN_GROUP],
        _ => {
            return Some(build_vendordep_pdu(
                AVRCP_LIST_PLAYER_VALUES, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_PARAM],
            ));
        }
    };
    let mut resp = vec![values.len() as u8];
    resp.extend_from_slice(&values);
    Some(build_vendordep_pdu(AVRCP_LIST_PLAYER_VALUES, AVRCP_PACKET_TYPE_SINGLE, &resp))
}

fn handle_get_current_player_value(
    session: &AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS || params.is_empty() {
        return Some(build_vendordep_pdu(
            AVRCP_GET_CURRENT_PLAYER_VALUE, AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let num_attrs = params[0] as usize;
    if params.len() < 1 + num_attrs {
        return Some(build_vendordep_pdu(
            AVRCP_GET_CURRENT_PLAYER_VALUE, AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let player = session.target_player.as_ref()?;
    let mut resp = Vec::new();
    let mut count: u8 = 0;
    resp.push(0); // placeholder for count
    for i in 0..num_attrs {
        let attr = params[1 + i];
        let value = player.callbacks.get_setting(attr);
        resp.push(attr);
        resp.push(value);
        count += 1;
    }
    resp[0] = count;
    Some(build_vendordep_pdu(
        AVRCP_GET_CURRENT_PLAYER_VALUE, AVRCP_PACKET_TYPE_SINGLE, &resp,
    ))
}

fn handle_set_player_value(
    session: &AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_CONTROL || params.is_empty() {
        return Some(build_vendordep_pdu(
            AVRCP_SET_PLAYER_VALUE, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let num_attrs = params[0] as usize;
    if params.len() < 1 + num_attrs * 2 {
        return Some(build_vendordep_pdu(
            AVRCP_SET_PLAYER_VALUE, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let player = session.target_player.as_ref()?;
    for i in 0..num_attrs {
        let attr = params[1 + i * 2];
        let value = params[2 + i * 2];
        player.callbacks.set_setting(attr, value);
    }
    Some(build_vendordep_pdu(
        AVRCP_SET_PLAYER_VALUE, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_SUCCESS],
    ))
}

fn handle_get_player_attribute_text(
    _session: &AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS || params.is_empty() {
        return None;
    }
    let num_attrs = params[0] as usize;
    if params.len() < 1 + num_attrs {
        return None;
    }
    let mut resp = vec![num_attrs as u8];
    for i in 0..num_attrs {
        let attr = params[1 + i];
        let text = match attr {
            AVRCP_ATTRIBUTE_EQUALIZER => "Equalizer",
            AVRCP_ATTRIBUTE_REPEAT_MODE => "Repeat",
            AVRCP_ATTRIBUTE_SHUFFLE => "Shuffle",
            AVRCP_ATTRIBUTE_SCAN => "Scan",
            _ => "Unknown",
        };
        resp.push(attr);
        // Character set: UTF-8 (106)
        resp.push(0x00);
        resp.push(106);
        let text_bytes = text.as_bytes();
        resp.push(text_bytes.len() as u8);
        resp.extend_from_slice(text_bytes);
    }
    Some(build_vendordep_pdu(
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT, AVRCP_PACKET_TYPE_SINGLE, &resp,
    ))
}

fn handle_get_player_value_text(
    _session: &AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS || params.len() < 2 {
        return None;
    }
    let _attr = params[0];
    let num_values = params[1] as usize;
    if params.len() < 2 + num_values {
        return None;
    }
    // Return generic value text
    let mut resp = vec![num_values as u8];
    for i in 0..num_values {
        let value = params[2 + i];
        let text = format!("Value {}", value);
        resp.push(value);
        resp.push(0x00);
        resp.push(106); // UTF-8
        let text_bytes = text.as_bytes();
        resp.push(text_bytes.len() as u8);
        resp.extend_from_slice(text_bytes);
    }
    Some(build_vendordep_pdu(
        AVRCP_GET_PLAYER_VALUE_TEXT, AVRCP_PACKET_TYPE_SINGLE, &resp,
    ))
}

fn handle_displayable_charset(_session: &AvrcpSession, ctype: u8) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS {
        return None;
    }
    Some(build_vendordep_pdu(
        AVRCP_DISPLAYABLE_CHARSET, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_SUCCESS],
    ))
}

fn handle_battery_status(_session: &AvrcpSession, ctype: u8) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS {
        return None;
    }
    Some(build_vendordep_pdu(
        AVRCP_CT_BATTERY_STATUS, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_SUCCESS],
    ))
}

fn handle_get_element_attributes(
    session: &mut AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS {
        return None;
    }
    let player = session.target_player.as_ref()?;
    let metadata = player.callbacks.get_metadata();

    // Build attribute response
    let mut resp_params = Vec::new();

    // If num_attrs == 0, return all attributes
    let attr_ids: Vec<u32> = if params.len() < 12 || params.get(8).copied().unwrap_or(0) == 0 {
        MEDIA_ATTR_IDS.to_vec()
    } else {
        let count = u32::from_be_bytes([0, 0, 0, params[8]]) as usize;
        let mut ids = Vec::new();
        for i in 0..count {
            let offset = 9 + i * 4;
            if offset + 4 <= params.len() {
                let id = u32::from_be_bytes([
                    params[offset],
                    params[offset + 1],
                    params[offset + 2],
                    params[offset + 3],
                ]);
                ids.push(id);
            }
        }
        if ids.is_empty() { MEDIA_ATTR_IDS.to_vec() } else { ids }
    };

    let mut count: u8 = 0;
    let count_offset = resp_params.len();
    resp_params.push(0); // placeholder for count

    for &attr_id in &attr_ids {
        if let Some(value) = metadata.get(&attr_id) {
            let value_bytes = value.as_bytes();
            // Attribute ID (4 bytes)
            resp_params.extend_from_slice(&attr_id.to_be_bytes());
            // Character set: UTF-8 (0x006A)
            resp_params.push(0x00);
            resp_params.push(0x6A);
            // Value length (2 bytes)
            let vlen = value_bytes.len() as u16;
            resp_params.push((vlen >> 8) as u8);
            resp_params.push((vlen & 0xFF) as u8);
            // Value
            resp_params.extend_from_slice(value_bytes);
            count += 1;
        }
    }
    resp_params[count_offset] = count;

    // Handle fragmentation if response is too large
    if resp_params.len() > AVRCP_PDU_MTU {
        let first_chunk = &resp_params[..AVRCP_PDU_MTU];
        let remaining = resp_params[AVRCP_PDU_MTU..].to_vec();
        session.pending_pdu = Some(PendingPdu {
            pdu_id: AVRCP_GET_ELEMENT_ATTRIBUTES,
            data: remaining,
            offset: 0,
        });
        Some(build_vendordep_pdu(
            AVRCP_GET_ELEMENT_ATTRIBUTES, AVRCP_PACKET_TYPE_START, first_chunk,
        ))
    } else {
        Some(build_vendordep_pdu(
            AVRCP_GET_ELEMENT_ATTRIBUTES, AVRCP_PACKET_TYPE_SINGLE, &resp_params,
        ))
    }
}

fn handle_get_play_status(session: &AvrcpSession, ctype: u8) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_STATUS {
        return None;
    }
    let player = session.target_player.as_ref()?;
    let duration = player.callbacks.get_duration();
    let position = player.callbacks.get_position();
    let status = player.callbacks.get_status();
    let mut resp = Vec::with_capacity(9);
    resp.extend_from_slice(&duration.to_be_bytes());
    resp.extend_from_slice(&position.to_be_bytes());
    resp.push(status);
    Some(build_vendordep_pdu(
        AVRCP_GET_PLAY_STATUS, AVRCP_PACKET_TYPE_SINGLE, &resp,
    ))
}

fn handle_register_notification(
    session: &mut AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_NOTIFY || params.is_empty() {
        return Some(build_vendordep_pdu(
            AVRCP_REGISTER_NOTIFICATION, AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let event_id = params[0];
    if event_id == 0 || event_id > AVRCP_EVENT_LAST_DEFINED {
        return Some(build_vendordep_pdu(
            AVRCP_REGISTER_NOTIFICATION, AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    if session.supported_events & (1u32 << event_id) == 0 {
        return Some(build_vendordep_pdu(
            AVRCP_REGISTER_NOTIFICATION, AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }

    // Register this event for future CHANGED notifications
    session.registered_events |= 1u32 << event_id;
    debug!("AVRCP: registered notification for event {:#04x}", event_id);

    // Send INTERIM response with current state
    let interim_params = build_notification_interim(session, event_id);
    let mut resp = vec![event_id];
    resp.extend_from_slice(&interim_params);
    // Note: For interim responses, the ctype in the response should be AVC_INTERIM.
    // The return value is used by AVCTP to send with AVC_INTERIM.
    Some(build_vendordep_pdu(
        AVRCP_REGISTER_NOTIFICATION, AVRCP_PACKET_TYPE_SINGLE, &resp,
    ))
}

/// Build the interim notification payload for a given event.
fn build_notification_interim(session: &AvrcpSession, event_id: u8) -> Vec<u8> {
    match event_id {
        AVRCP_EVENT_STATUS_CHANGED => {
            if let Some(ref player) = session.target_player {
                vec![player.callbacks.get_status()]
            } else {
                vec![AVRCP_PLAY_STATUS_ERROR]
            }
        }
        AVRCP_EVENT_TRACK_CHANGED => {
            // Track identifier (8 bytes) — 0xFFFFFFFF_FFFFFFFF means no track
            if session.target_player.is_some() {
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            } else {
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            }
        }
        AVRCP_EVENT_PLAYBACK_POS_CHANGED => {
            if let Some(ref player) = session.target_player {
                player.callbacks.get_position().to_be_bytes().to_vec()
            } else {
                0xFFFFFFFFu32.to_be_bytes().to_vec()
            }
        }
        AVRCP_EVENT_SETTINGS_CHANGED => {
            // Return current settings
            let mut data = vec![PLAYER_ATTRS.len() as u8];
            if let Some(ref player) = session.target_player {
                for &attr in &PLAYER_ATTRS {
                    data.push(attr);
                    data.push(player.callbacks.get_setting(attr));
                }
            } else {
                for &attr in &PLAYER_ATTRS {
                    data.push(attr);
                    data.push(0);
                }
            }
            data
        }
        AVRCP_EVENT_VOLUME_CHANGED => {
            vec![0x00] // Current volume
        }
        AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED => {
            let player_id: u16 = session
                .target_player
                .as_ref()
                .map(|p| p.id)
                .unwrap_or(0);
            let mut data = Vec::new();
            data.extend_from_slice(&player_id.to_be_bytes());
            data.extend_from_slice(&0u16.to_be_bytes()); // UID counter
            data
        }
        _ => Vec::new(), // Other events: empty payload
    }
}

fn handle_request_continuing(
    session: &mut AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_CONTROL || params.is_empty() {
        return None;
    }
    let requested_pdu = params[0];
    let pending = session.pending_pdu.as_mut()?;
    if pending.pdu_id != requested_pdu {
        session.pending_pdu = None;
        return Some(build_vendordep_pdu(
            AVRCP_ABORT_CONTINUING, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let remaining = &pending.data[pending.offset..];
    if remaining.len() <= AVRCP_PDU_MTU {
        // Final fragment
        let resp = build_vendordep_pdu(pending.pdu_id, AVRCP_PACKET_TYPE_END, remaining);
        session.pending_pdu = None;
        Some(resp)
    } else {
        // More fragments
        let chunk = &remaining[..AVRCP_PDU_MTU];
        let resp = build_vendordep_pdu(pending.pdu_id, AVRCP_PACKET_TYPE_CONTINUING, chunk);
        pending.offset += AVRCP_PDU_MTU;
        Some(resp)
    }
}

fn handle_abort_continuing(
    session: &mut AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_CONTROL || params.is_empty() {
        return None;
    }
    let _requested_pdu = params[0];
    session.pending_pdu = None;
    Some(build_vendordep_pdu(
        AVRCP_ABORT_CONTINUING, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_SUCCESS],
    ))
}

fn handle_set_absolute_volume(
    _session: &mut AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_CONTROL || params.is_empty() {
        return Some(build_vendordep_pdu(
            AVRCP_SET_ABSOLUTE_VOLUME, AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let volume = params[0] & 0x7F;
    info!("AVRCP: SetAbsoluteVolume = {}", volume);
    Some(build_vendordep_pdu(
        AVRCP_SET_ABSOLUTE_VOLUME, AVRCP_PACKET_TYPE_SINGLE, &[volume],
    ))
}

fn handle_set_addressed_player(
    _session: &AvrcpSession,
    ctype: u8,
    params: &[u8],
) -> Option<Vec<u8>> {
    if ctype != AVC_CTYPE_CONTROL || params.len() < 2 {
        return Some(build_vendordep_pdu(
            AVRCP_SET_ADDRESSED_PLAYER, AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_STATUS_INVALID_PARAM],
        ));
    }
    let _player_id = u16::from_be_bytes([params[0], params[1]]);
    Some(build_vendordep_pdu(
        AVRCP_SET_ADDRESSED_PLAYER, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_SUCCESS],
    ))
}

// ===========================================================================
// TG — Browsing Channel Handler Dispatch
// ===========================================================================

fn handle_browsing_dispatch(session: &mut AvrcpSession, operands: &[u8]) -> Option<Vec<u8>> {
    let (pdu_id, params) = parse_browsing_header(operands)?;
    debug!("AVRCP TG browsing: PDU {:#04x}, params_len={}", pdu_id, params.len());

    match pdu_id {
        AVRCP_SET_BROWSED_PLAYER => handle_browsing_set_browsed_player(session, params),
        AVRCP_GET_FOLDER_ITEMS => handle_browsing_get_folder_items(session, params),
        AVRCP_CHANGE_PATH => handle_browsing_change_path(session, params),
        AVRCP_GET_ITEM_ATTRIBUTES => handle_browsing_get_item_attributes(session, params),
        AVRCP_PLAY_ITEM => handle_browsing_play_item(session, params),
        AVRCP_SEARCH => handle_browsing_search(session, params),
        AVRCP_ADD_TO_NOW_PLAYING => handle_browsing_add_to_now_playing(session, params),
        _ => {
            warn!("AVRCP TG browsing: unsupported PDU {:#04x}", pdu_id);
            Some(build_browsing_status(AVRCP_GENERAL_REJECT, AVRCP_STATUS_INVALID_COMMAND))
        }
    }
}

// ===========================================================================
// TG — Individual Browsing Handlers
// ===========================================================================

fn handle_browsing_set_browsed_player(
    _session: &mut AvrcpSession,
    params: &[u8],
) -> Option<Vec<u8>> {
    if params.len() < 2 {
        return Some(build_browsing_status(AVRCP_SET_BROWSED_PLAYER, AVRCP_STATUS_INVALID_PARAM));
    }
    let _player_id = u16::from_be_bytes([params[0], params[1]]);
    // Respond with success + 0 items in root folder
    let mut resp = vec![AVRCP_STATUS_SUCCESS];
    resp.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    resp.extend_from_slice(&0u32.to_be_bytes()); // Number of items
    resp.extend_from_slice(&0u16.to_be_bytes()); // Character set: UTF-8
    resp.push(0); // Folder depth
    Some(build_browsing_pdu(AVRCP_SET_BROWSED_PLAYER, &resp))
}

fn handle_browsing_get_folder_items(
    _session: &AvrcpSession,
    params: &[u8],
) -> Option<Vec<u8>> {
    if params.len() < 10 {
        return Some(build_browsing_status(AVRCP_GET_FOLDER_ITEMS, AVRCP_STATUS_INVALID_PARAM));
    }
    let scope = params[0];
    let _start = u32::from_be_bytes([params[1], params[2], params[3], params[4]]);
    let _end = u32::from_be_bytes([params[5], params[6], params[7], params[8]]);
    debug!("AVRCP: GetFolderItems scope={}", scope);
    // Return empty item list
    let mut resp = vec![AVRCP_STATUS_SUCCESS];
    resp.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    resp.extend_from_slice(&0u16.to_be_bytes()); // Number of items
    Some(build_browsing_pdu(AVRCP_GET_FOLDER_ITEMS, &resp))
}

fn handle_browsing_change_path(
    _session: &AvrcpSession,
    params: &[u8],
) -> Option<Vec<u8>> {
    if params.len() < 11 {
        return Some(build_browsing_status(AVRCP_CHANGE_PATH, AVRCP_STATUS_INVALID_PARAM));
    }
    // Return success with 0 items
    let mut resp = vec![AVRCP_STATUS_SUCCESS];
    resp.extend_from_slice(&0u32.to_be_bytes()); // Number of items
    Some(build_browsing_pdu(AVRCP_CHANGE_PATH, &resp))
}

fn handle_browsing_get_item_attributes(
    _session: &AvrcpSession,
    params: &[u8],
) -> Option<Vec<u8>> {
    if params.len() < 12 {
        return Some(build_browsing_status(
            AVRCP_GET_ITEM_ATTRIBUTES, AVRCP_STATUS_INVALID_PARAM,
        ));
    }
    // Return success with 0 attributes
    let mut resp = vec![AVRCP_STATUS_SUCCESS];
    resp.push(0); // Number of attributes
    Some(build_browsing_pdu(AVRCP_GET_ITEM_ATTRIBUTES, &resp))
}

fn handle_browsing_play_item(
    _session: &AvrcpSession,
    params: &[u8],
) -> Option<Vec<u8>> {
    if params.len() < 11 {
        return Some(build_browsing_status(AVRCP_PLAY_ITEM, AVRCP_STATUS_INVALID_PARAM));
    }
    Some(build_browsing_status(AVRCP_PLAY_ITEM, AVRCP_STATUS_SUCCESS))
}

fn handle_browsing_search(
    _session: &AvrcpSession,
    params: &[u8],
) -> Option<Vec<u8>> {
    if params.len() < 4 {
        return Some(build_browsing_status(AVRCP_SEARCH, AVRCP_STATUS_INVALID_PARAM));
    }
    // Return success with 0 results
    let mut resp = vec![AVRCP_STATUS_SUCCESS];
    resp.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    resp.extend_from_slice(&0u32.to_be_bytes()); // Number of items
    Some(build_browsing_pdu(AVRCP_SEARCH, &resp))
}

fn handle_browsing_add_to_now_playing(
    _session: &AvrcpSession,
    params: &[u8],
) -> Option<Vec<u8>> {
    if params.len() < 11 {
        return Some(build_browsing_status(
            AVRCP_ADD_TO_NOW_PLAYING, AVRCP_STATUS_INVALID_PARAM,
        ));
    }
    Some(build_browsing_status(AVRCP_ADD_TO_NOW_PLAYING, AVRCP_STATUS_SUCCESS))
}

// ===========================================================================
// Passthrough Handler Dispatch
// ===========================================================================

fn handle_passthrough(session: &AvrcpSession, op: u8, pressed: bool) -> bool {
    let player = match session.target_player.as_ref() {
        Some(p) => p,
        None => return false,
    };
    match op {
        PASSTHROUGH_PLAY => {
            if pressed { player.callbacks.play(); }
            true
        }
        PASSTHROUGH_STOP => {
            if pressed { player.callbacks.stop(); }
            true
        }
        PASSTHROUGH_PAUSE => {
            if pressed { player.callbacks.pause(); }
            true
        }
        PASSTHROUGH_FORWARD => {
            if pressed { player.callbacks.next(); }
            true
        }
        PASSTHROUGH_BACKWARD => {
            if pressed { player.callbacks.previous(); }
            true
        }
        PASSTHROUGH_FAST_FORWARD => {
            player.callbacks.fast_forward(pressed);
            true
        }
        PASSTHROUGH_REWIND => {
            player.callbacks.rewind(pressed);
            true
        }
        _ => false,
    }
}

// ===========================================================================
// CT — Request Methods (async, called by controller code)
// ===========================================================================

impl AvrcpSession {
    /// CT: Send GetCapabilities to remote TG.
    pub fn get_capabilities(&mut self, cap_id: u8) {
        let params = vec![cap_id];
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_GET_CAPABILITIES,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send RegisterNotification to remote TG.
    pub fn register_notification(&mut self, event_id: u8, interval: u32) {
        let mut params = vec![event_id];
        params.extend_from_slice(&interval.to_be_bytes());
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_NOTIFY,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_REGISTER_NOTIFICATION,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send ListPlayerApplicationSettingAttributes to remote TG.
    pub fn list_player_attributes(&mut self) {
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_LIST_PLAYER_ATTRIBUTES,
                    Vec::new(),
                    None,
                );
            });
        }
    }

    /// CT: Send GetPlayerAttributeText to remote TG.
    pub fn get_player_attribute_text(&mut self, attrs: &[u8]) {
        let mut params = vec![attrs.len() as u8];
        params.extend_from_slice(attrs);
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send ListPlayerValues for an attribute to remote TG.
    pub fn list_player_values(&mut self, attr: u8) {
        let params = vec![attr];
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_LIST_PLAYER_VALUES,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send GetPlayerValueText to remote TG.
    pub fn get_player_value_text(&mut self, attr: u8, values: &[u8]) {
        let mut params = vec![attr, values.len() as u8];
        params.extend_from_slice(values);
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_GET_PLAYER_VALUE_TEXT,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send SetPlayerApplicationSettingValue to remote TG.
    pub fn set_player_value(&mut self, attrs_values: &[(u8, u8)]) {
        let mut params = vec![attrs_values.len() as u8];
        for &(attr, val) in attrs_values {
            params.push(attr);
            params.push(val);
        }
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_CONTROL,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_SET_PLAYER_VALUE,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send GetCurrentPlayerApplicationSettingValue to remote TG.
    pub fn get_current_player_value(&mut self, attrs: &[u8]) {
        let mut params = vec![attrs.len() as u8];
        params.extend_from_slice(attrs);
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_GET_CURRENT_PLAYER_VALUE,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send GetPlayStatus to remote TG.
    pub fn get_play_status(&mut self) {
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_GET_PLAY_STATUS,
                    Vec::new(),
                    None,
                );
            });
        }
    }

    /// CT: Send GetElementAttributes to remote TG.
    pub fn get_element_attributes(&mut self, attr_ids: &[u32]) {
        let mut params = Vec::new();
        // Identifier (8 bytes) — playing track = 0
        params.extend_from_slice(&[0u8; 8]);
        params.push(attr_ids.len() as u8);
        for &id in attr_ids {
            params.extend_from_slice(&id.to_be_bytes());
        }
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_STATUS,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_GET_ELEMENT_ATTRIBUTES,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send SetAbsoluteVolume to remote TG.
    pub fn set_volume(&mut self, volume: u8) {
        let params = vec![volume & 0x7F];
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_CONTROL,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_SET_ABSOLUTE_VOLUME,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send SetAddressedPlayer to remote TG.
    pub fn set_addressed_player(&mut self, player_id: u16) {
        let params = player_id.to_be_bytes().to_vec();
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_vendordep_req(
                    AVC_CTYPE_CONTROL,
                    AVC_SUBUNIT_PANEL,
                    AVRCP_SET_ADDRESSED_PLAYER,
                    params,
                    None,
                );
            });
        }
    }

    /// CT: Send SetBrowsedPlayer on browsing channel.
    pub fn set_browsed_player(&mut self, player_id: u16) {
        let params = player_id.to_be_bytes().to_vec();
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_browsing(AVRCP_SET_BROWSED_PLAYER, params, None);
            });
        }
    }

    /// CT: Send GetFolderItems on browsing channel.
    pub fn get_folder_items(&mut self, scope: u8, start: u32, end: u32) {
        let mut params = vec![scope];
        params.extend_from_slice(&start.to_be_bytes());
        params.extend_from_slice(&end.to_be_bytes());
        params.push(0); // attribute count = 0
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_browsing(AVRCP_GET_FOLDER_ITEMS, params, None);
            });
        }
    }

    /// CT: Send ChangePath on browsing channel.
    pub fn change_path(&mut self, uid_counter: u16, direction: u8, folder_uid: u64) {
        let mut params = Vec::new();
        params.extend_from_slice(&uid_counter.to_be_bytes());
        params.push(direction);
        params.extend_from_slice(&folder_uid.to_be_bytes());
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_browsing(AVRCP_CHANGE_PATH, params, None);
            });
        }
    }

    /// CT: Send GetItemAttributes on browsing channel.
    pub fn get_item_attributes(&mut self, scope: u8, uid: u64, uid_counter: u16) {
        let mut params = vec![scope];
        params.extend_from_slice(&uid.to_be_bytes());
        params.extend_from_slice(&uid_counter.to_be_bytes());
        params.push(0); // attribute count = 0 (all)
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_browsing(AVRCP_GET_ITEM_ATTRIBUTES, params, None);
            });
        }
    }

    /// CT: Send PlayItem on browsing channel.
    pub fn play_item(&mut self, scope: u8, uid: u64, uid_counter: u16) {
        let mut params = vec![scope];
        params.extend_from_slice(&uid.to_be_bytes());
        params.extend_from_slice(&uid_counter.to_be_bytes());
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_browsing(AVRCP_PLAY_ITEM, params, None);
            });
        }
    }

    /// CT: Send Search on browsing channel.
    pub fn search(&mut self, search_text: &str) {
        let text_bytes = search_text.as_bytes();
        let mut params = Vec::new();
        // Character set: UTF-8 (0x006A)
        params.push(0x00);
        params.push(0x6A);
        let len = text_bytes.len() as u16;
        params.push((len >> 8) as u8);
        params.push((len & 0xFF) as u8);
        params.extend_from_slice(text_bytes);
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_browsing(AVRCP_SEARCH, params, None);
            });
        }
    }

    /// CT: Send AddToNowPlaying on browsing channel.
    pub fn add_to_now_playing(&mut self, scope: u8, uid: u64, uid_counter: u16) {
        let mut params = vec![scope];
        params.extend_from_slice(&uid.to_be_bytes());
        params.extend_from_slice(&uid_counter.to_be_bytes());
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                sess.send_browsing(AVRCP_ADD_TO_NOW_PLAYING, params, None);
            });
        }
    }

    /// CT: Send passthrough command to remote TG.
    pub fn send_passthrough(&mut self, op: u8, pressed: bool) {
        let avctp = self.avctp.clone();
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                let mut sess = avctp.lock().await;
                if let Err(e) = sess.send_passthrough(op, pressed).await {
                    debug!("AVRCP: passthrough send failed: {:?}", e);
                }
            });
        }
    }
}

// ===========================================================================
// TG — Response Methods (returning response bytes from handler)
// These are used when the AvrcpSession needs to build response PDUs.
// ===========================================================================

impl AvrcpSession {
    /// Build a vendor-dependent response PDU for returning from handler.
    pub fn get_capabilities_rsp(&self, cap_id: u8) -> Option<Vec<u8>> {
        handle_get_capabilities(self, AVC_CTYPE_STATUS, &[cap_id])
    }

    pub fn list_player_attributes_rsp(&self) -> Option<Vec<u8>> {
        handle_list_player_attributes(self, AVC_CTYPE_STATUS)
    }

    pub fn get_player_attribute_text_rsp(&self, attrs: &[u8]) -> Option<Vec<u8>> {
        let mut params = vec![attrs.len() as u8];
        params.extend_from_slice(attrs);
        handle_get_player_attribute_text(self, AVC_CTYPE_STATUS, &params)
    }

    pub fn list_player_values_rsp(&self, attr: u8) -> Option<Vec<u8>> {
        handle_list_player_values(self, AVC_CTYPE_STATUS, &[attr])
    }

    pub fn get_player_values_text_rsp(&self, attr: u8, values: &[u8]) -> Option<Vec<u8>> {
        let mut params = vec![attr, values.len() as u8];
        params.extend_from_slice(values);
        handle_get_player_value_text(self, AVC_CTYPE_STATUS, &params)
    }

    pub fn get_current_player_value_rsp(&self, attrs: &[u8]) -> Option<Vec<u8>> {
        let mut params = vec![attrs.len() as u8];
        params.extend_from_slice(attrs);
        handle_get_current_player_value(self, AVC_CTYPE_STATUS, &params)
    }

    pub fn set_player_value_rsp(&self, _params: &[u8]) -> Option<Vec<u8>> {
        // This is a confirmation; the handler already processes the set
        Some(build_vendordep_pdu(
            AVRCP_SET_PLAYER_VALUE, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_SUCCESS],
        ))
    }

    pub fn get_play_status_rsp(&self) -> Option<Vec<u8>> {
        handle_get_play_status(self, AVC_CTYPE_STATUS)
    }

    pub fn get_element_attrs_rsp(&mut self, attr_ids: &[u32]) -> Option<Vec<u8>> {
        let mut params = Vec::new();
        params.extend_from_slice(&[0u8; 8]); // identifier
        params.push(attr_ids.len() as u8);
        for &id in attr_ids {
            params.extend_from_slice(&id.to_be_bytes());
        }
        handle_get_element_attributes(self, AVC_CTYPE_STATUS, &params)
    }

    pub fn register_notification_rsp(&mut self, event: u8, interval: u32) -> Option<Vec<u8>> {
        let mut params = vec![event];
        params.extend_from_slice(&interval.to_be_bytes());
        handle_register_notification(self, AVC_CTYPE_NOTIFY, &params)
    }

    pub fn set_volume_rsp(&self, volume: u8) -> Option<Vec<u8>> {
        Some(build_vendordep_pdu(
            AVRCP_SET_ABSOLUTE_VOLUME, AVRCP_PACKET_TYPE_SINGLE, &[volume & 0x7F],
        ))
    }

    pub fn set_addressed_player_rsp(&self) -> Option<Vec<u8>> {
        Some(build_vendordep_pdu(
            AVRCP_SET_ADDRESSED_PLAYER, AVRCP_PACKET_TYPE_SINGLE, &[AVRCP_STATUS_SUCCESS],
        ))
    }

    pub fn set_browsed_player_rsp(&self) -> Option<Vec<u8>> {
        let mut resp = vec![AVRCP_STATUS_SUCCESS];
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.push(0);
        Some(build_browsing_pdu(AVRCP_SET_BROWSED_PLAYER, &resp))
    }

    pub fn get_folder_items_rsp(&self) -> Option<Vec<u8>> {
        let mut resp = vec![AVRCP_STATUS_SUCCESS];
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        Some(build_browsing_pdu(AVRCP_GET_FOLDER_ITEMS, &resp))
    }

    pub fn change_path_rsp(&self) -> Option<Vec<u8>> {
        let mut resp = vec![AVRCP_STATUS_SUCCESS];
        resp.extend_from_slice(&0u32.to_be_bytes());
        Some(build_browsing_pdu(AVRCP_CHANGE_PATH, &resp))
    }

    pub fn get_item_attributes_rsp(&self) -> Option<Vec<u8>> {
        let mut resp = vec![AVRCP_STATUS_SUCCESS];
        resp.push(0);
        Some(build_browsing_pdu(AVRCP_GET_ITEM_ATTRIBUTES, &resp))
    }

    pub fn play_item_rsp(&self) -> Option<Vec<u8>> {
        Some(build_browsing_status(AVRCP_PLAY_ITEM, AVRCP_STATUS_SUCCESS))
    }

    pub fn search_rsp(&self) -> Option<Vec<u8>> {
        let mut resp = vec![AVRCP_STATUS_SUCCESS];
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        Some(build_browsing_pdu(AVRCP_SEARCH, &resp))
    }

    pub fn add_to_now_playing_rsp(&self) -> Option<Vec<u8>> {
        Some(build_browsing_status(AVRCP_ADD_TO_NOW_PLAYING, AVRCP_STATUS_SUCCESS))
    }
}

// ===========================================================================
// AVCTP State Change Handler
// ===========================================================================

/// Handle AVCTP connection state changes — called from the state callback.
/// This runs in a tokio::spawn context so it can lock async mutexes.
async fn avrcp_state_changed_async(
    device_path: String,
    old_state: AvctpState,
    new_state: AvctpState,
) {
    debug!(
        "AVRCP: state change {} -> {} for {}",
        old_state, new_state, device_path
    );

    match new_state {
        AvctpState::Connected => {
            // Control channel just connected — find or create AVRCP session
            // Look up which server and AVCTP session this belongs to
            if let Some((avrcp_session, avctp_arc)) =
                find_or_create_avrcp_session(&device_path).await
            {
                // Register handlers on the AVCTP session
                let mut avctp_sess = avctp_arc.lock().await;
                init_control_handlers(avrcp_session.clone(), &mut avctp_sess);

                // Assign a target player if available
                if let Ok(mut sess) = avrcp_session.lock() {
                    if sess.target_player.is_none() {
                        if let Some(player) = find_available_player() {
                            sess.register_player(player);
                        }
                    }
                }
            }
        }
        AvctpState::BrowsingConnected => {
            // Browsing channel connected — register browsing handlers
            if let Some((avrcp_session, avctp_arc)) = find_avrcp_session(&device_path) {
                let mut avctp_sess = avctp_arc.lock().await;
                init_browsing_handlers(avrcp_session, &mut avctp_sess);
            }
        }
        AvctpState::Disconnected => {
            // Connection lost — clean up AVRCP session
            remove_avrcp_session(&device_path);
        }
        _ => {
            // Connecting/BrowsingConnecting — no action needed
        }
    }
}

/// Find or create an AVRCP session for the given device path.
async fn find_or_create_avrcp_session(
    device_path: &str,
) -> Option<(Arc<StdMutex<AvrcpSession>>, Arc<TokioMutex<AvctpSession>>)> {
    let servers = SERVERS.lock().ok()?;

    // First, check for existing session
    for server in servers.iter() {
        if let Ok(srv) = server.lock() {
            for session_arc in &srv.sessions {
                if let Ok(sess) = session_arc.lock() {
                    if sess.device_path == device_path {
                        let avctp = sess.avctp.clone();
                        return Some((session_arc.clone(), avctp));
                    }
                }
            }
        }
    }

    // No existing session — create one
    // We need to find the AVCTP session for this device path
    // This requires looking at the AVCTP layer, which we access via avctp_connect
    // For now, the session creation is handled by the AVCTP layer when it connects.
    // We'll create the AVRCP session wrapper when the state changes.

    // Find a server to associate with (use first available).
    // The actual AVRCP session creation happens when the control handler is
    // first invoked, because the AVCTP state callback does not provide the
    // AVCTP session Arc needed for AvrcpSession::new().
    if let Some(server_arc) = servers.first() {
        if server_arc.lock().is_ok() {
            debug!("AVRCP: server found for new session for {}", device_path);
        }
    }

    None
}

/// Find an existing AVRCP session by device path.
fn find_avrcp_session(
    device_path: &str,
) -> Option<(Arc<StdMutex<AvrcpSession>>, Arc<TokioMutex<AvctpSession>>)> {
    let servers = SERVERS.lock().ok()?;
    for server in servers.iter() {
        if let Ok(srv) = server.lock() {
            for session_arc in &srv.sessions {
                if let Ok(sess) = session_arc.lock() {
                    if sess.device_path == device_path {
                        let avctp = sess.avctp.clone();
                        return Some((session_arc.clone(), avctp));
                    }
                }
            }
        }
    }
    None
}

/// Remove an AVRCP session for the given device path.
fn remove_avrcp_session(device_path: &str) {
    if let Ok(servers) = SERVERS.lock() {
        for server in servers.iter() {
            if let Ok(mut srv) = server.lock() {
                srv.sessions.retain(|session_arc| {
                    if let Ok(mut sess) = session_arc.lock() {
                        if sess.device_path == device_path {
                            sess.shutdown();
                            return false;
                        }
                    }
                    true
                });
            }
        }
    }
    debug!("AVRCP: session removed for {}", device_path);
}

/// Find an available player from any server.
fn find_available_player() -> Option<Arc<AvrcpPlayer>> {
    let servers = SERVERS.lock().ok()?;
    for server in servers.iter() {
        if let Ok(srv) = server.lock() {
            if let Some(player) = srv.players.first() {
                return Some(player.clone());
            }
        }
    }
    None
}

// ===========================================================================
// Event Notification (proactive sends from TG)
// ===========================================================================

/// Send an AVRCP event notification to the remote CT (if registered).
pub async fn avrcp_player_event(
    session: &Arc<StdMutex<AvrcpSession>>,
    event_id: u8,
    params: &[u8],
) {
    let (should_send, avctp_arc) = {
        let mut sess = session.lock().unwrap();
        if sess.registered_events & (1u32 << event_id) == 0 {
            return; // CT has not registered for this event
        }
        // Clear the registration — CT must re-register for subsequent notifications
        sess.registered_events &= !(1u32 << event_id);
        (true, sess.avctp.clone())
    };

    if should_send {
        let mut full_params = Vec::with_capacity(1 + params.len());
        full_params.push(event_id);
        full_params.extend_from_slice(params);
        let pdu = build_vendordep_pdu(
            AVRCP_REGISTER_NOTIFICATION,
            AVRCP_PACKET_TYPE_SINGLE,
            &full_params,
        );
        let mut avctp = avctp_arc.lock().await;
        // Send with AVC_CHANGED response type and transaction 0 (best effort)
        if let Err(err) = avctp.send_vendordep(0, AVC_CHANGED, AVC_SUBUNIT_PANEL, &pdu).await {
            error!("Failed to send AVRCP event notification: {:?}", err);
        }
    }
}

/// Handle vendor reject from remote — used by other modules.
pub fn avrcp_handle_vendor_reject(pdu_id: u8, params: &[u8]) {
    warn!(
        "AVRCP vendor reject for PDU {:#04x}, params len={}",
        pdu_id,
        params.len()
    );
}

/// Send a general reject on the browsing channel.
pub async fn avrcp_browsing_general_reject(session: &Arc<StdMutex<AvrcpSession>>) {
    let avctp_arc = {
        let sess = session.lock().unwrap();
        sess.avctp.clone()
    };
    let mut avctp = avctp_arc.lock().await;
    let resp = build_browsing_status(AVRCP_GENERAL_REJECT, AVRCP_STATUS_INVALID_COMMAND);
    avctp.send_browsing(AVRCP_GENERAL_REJECT, resp, None);
}

/// Find the AVRCP target player for a given device.
pub fn avrcp_get_target_player_by_device(
    device: &Arc<BtdDevice>,
) -> Option<Arc<AvrcpPlayer>> {
    let servers = SERVERS.lock().ok()?;
    let device_path = device.get_path();
    for server in servers.iter() {
        if let Ok(srv) = server.lock() {
            for session_arc in &srv.sessions {
                if let Ok(sess) = session_arc.lock() {
                    if sess.device_path == device_path {
                        return sess.target_player.clone();
                    }
                }
            }
        }
    }
    None
}

// ===========================================================================
// Absolute Volume Control
// ===========================================================================

/// Set the volume on the remote device via AVRCP.
/// If the remote CT has registered for VOLUME_CHANGED, send a notification.
/// Otherwise, send a SetAbsoluteVolume command.
pub async fn avrcp_set_volume(device: &Arc<BtdDevice>, volume: u8) {
    let device_path = device.get_path().to_string();
    let clamped = volume & 0x7F;

    let (use_notification, avctp_arc) = {
        let servers = match SERVERS.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut found = None;
        for server in servers.iter() {
            if let Ok(srv) = server.lock() {
                for session_arc in &srv.sessions {
                    if let Ok(mut sess) = session_arc.lock() {
                        if sess.device_path == device_path {
                            let has_reg =
                                sess.registered_events & (1u32 << AVRCP_EVENT_VOLUME_CHANGED) != 0;
                            if has_reg {
                                sess.registered_events &=
                                    !(1u32 << AVRCP_EVENT_VOLUME_CHANGED);
                            }
                            found = Some((has_reg, sess.avctp.clone()));
                            break;
                        }
                    }
                }
                if found.is_some() {
                    break;
                }
            }
        }
        match found {
            Some(f) => f,
            None => {
                debug!("No AVRCP session found for device to set volume");
                return;
            }
        }
    };

    let mut avctp = avctp_arc.lock().await;
    if use_notification {
        // Send CHANGED notification for volume
        let pdu = build_vendordep_pdu(
            AVRCP_REGISTER_NOTIFICATION,
            AVRCP_PACKET_TYPE_SINGLE,
            &[AVRCP_EVENT_VOLUME_CHANGED, clamped],
        );
        if let Err(err) = avctp
            .send_vendordep(0, AVC_CHANGED, AVC_SUBUNIT_PANEL, &pdu)
            .await
        {
            error!("Failed to send volume notification: {:?}", err);
        }
    } else {
        // Send SetAbsoluteVolume command
        avctp.send_vendordep_req(
            AVC_CTYPE_CONTROL,
            AVC_SUBUNIT_PANEL,
            AVRCP_SET_ABSOLUTE_VOLUME,
            vec![clamped],
            None,
        );
    }
    info!("AVRCP set volume {} on device {}", clamped, device_path);
}

// ===========================================================================
// Player Registration API
// ===========================================================================

/// Register a local TG player with the AVRCP server for the given adapter.
pub fn avrcp_register_player(
    _adapter: &Arc<TokioMutex<BtdAdapter>>,
    callbacks: Box<dyn AvrcpPlayerCallbacks>,
) -> Result<Arc<AvrcpPlayer>, BtdError> {
    let player_id = next_player_id();
    let player = Arc::new(AvrcpPlayer {
        id: player_id,
        callbacks,
        server: None,
        sessions: Vec::new(),
    });
    if let Ok(servers) = SERVERS.lock() {
        for server in servers.iter() {
            if let Ok(mut srv) = server.lock() {
                srv.players.push(player.clone());
                // Attach to existing sessions lacking a target player
                for session_arc in &srv.sessions {
                    if let Ok(mut sess) = session_arc.lock() {
                        if sess.target_player.is_none() {
                            sess.register_player(player.clone());
                        }
                    }
                }
            }
        }
    }
    info!("AVRCP player {} registered", player_id);
    Ok(player)
}

/// Unregister a local TG player.
pub fn avrcp_unregister_player(player: &Arc<AvrcpPlayer>) {
    if let Ok(servers) = SERVERS.lock() {
        for server in servers.iter() {
            if let Ok(mut srv) = server.lock() {
                srv.players.retain(|p| p.id != player.id);
                // Detach from sessions
                for session_arc in &srv.sessions {
                    if let Ok(mut sess) = session_arc.lock() {
                        if let Some(ref tp) = sess.target_player {
                            if tp.id == player.id {
                                sess.target_player = None;
                            }
                        }
                    }
                }
            }
        }
    }
    info!("AVRCP player {} unregistered", player.id);
}

// ===========================================================================
// Connection Management
// ===========================================================================

/// Initiate an AVRCP connection to a remote device.
pub async fn avrcp_connect(service: &BtdService) -> Result<(), BtdError> {
    debug!("AVRCP connect requested");
    control_connect(service).await?;
    Ok(())
}

/// Disconnect an AVRCP session from a remote device.
pub async fn avrcp_disconnect(service: &BtdService) -> Result<(), BtdError> {
    debug!("AVRCP disconnect requested");
    control_disconnect(service).await?;
    Ok(())
}

// ===========================================================================
// Server Lifecycle (per-adapter)
// ===========================================================================

/// Register an AVRCP server for the given adapter.
pub fn avrcp_server_register(adapter: Arc<TokioMutex<BtdAdapter>>) -> Result<(), BtdError> {
    let adapter_address = {
        // Access adapter address synchronously via try_lock
        // In practice, this is called during adapter probe which is async,
        // but we store the address for later sync access.
        if let Ok(a) = adapter.try_lock() {
            a.address
        } else {
            BdAddr::default()
        }
    };

    let mut ct_record = avrcp_ct_record();
    let mut tg_record = avrcp_tg_record();

    // Register SDP records
    let mut db = SdpDatabase::new();
    let ct_id = add_record_to_server(&mut db, &adapter_address, &mut ct_record)
        .map_err(|e| {
            btd_error(0xFFFF, &format!("AVRCP CT SDP record registration failed: {}", e));
            BtdError::Failed(e)
        })?;
    let tg_id = add_record_to_server(&mut db, &adapter_address, &mut tg_record)
        .map_err(|e| {
            btd_error(0xFFFF, &format!("AVRCP TG SDP record registration failed: {}", e));
            BtdError::Failed(e)
        })?;

    let server = Arc::new(StdMutex::new(AvrcpServer {
        adapter,
        adapter_address,
        ct_record_id: ct_id,
        tg_record_id: tg_id,
        players: Vec::new(),
        sessions: Vec::new(),
    }));

    if let Ok(mut server_list) = SERVERS.lock() {
        server_list.push(server);
    }

    info!(
        "AVRCP server registered (CT record={}, TG record={})",
        ct_id, tg_id
    );
    Ok(())
}

/// Unregister the AVRCP server for the given adapter.
pub fn avrcp_server_unregister(adapter: &Arc<TokioMutex<BtdAdapter>>) {
    let adapter_ptr = Arc::as_ptr(adapter);
    let mut removed_ids = Vec::new();

    if let Ok(mut server_list) = SERVERS.lock() {
        server_list.retain(|server_arc| {
            if let Ok(srv) = server_arc.lock() {
                if Arc::as_ptr(&srv.adapter) == adapter_ptr {
                    removed_ids.push((srv.ct_record_id, srv.tg_record_id));
                    return false;
                }
            }
            true
        });
    }

    for (ct_id, tg_id) in removed_ids {
        let mut db = SdpDatabase::new();
        let _ = remove_record_from_server(&mut db, ct_id);
        let _ = remove_record_from_server(&mut db, tg_id);
        info!(
            "AVRCP server unregistered (CT record={}, TG record={})",
            ct_id, tg_id
        );
    }
}

// ===========================================================================
// Profile Definitions
// ===========================================================================

/// Build the AVRCP controller (CT) profile definition.
fn avrcp_controller_profile() -> BtdProfile {
    BtdProfile::new("avrcp-controller")
}

/// Build the AVRCP target (TG) profile definition.
fn avrcp_target_profile() -> BtdProfile {
    BtdProfile::new("avrcp-target")
}

// ===========================================================================
// Plugin Lifecycle
// ===========================================================================

/// Initialize the AVRCP plugin — register profiles and adapter driver.
pub fn avrcp_init() -> Result<(), Box<dyn std::error::Error>> {
    info!("AVRCP plugin initializing");

    // Register AVCTP state callback
    let cb_id = avctp_add_state_cb(Box::new(|device_path, old_state, new_state| {
        let path = device_path.to_string();
        tokio::spawn(async move {
            avrcp_state_changed_async(path, old_state, new_state).await;
        });
    }));

    if let Ok(mut lock) = STATE_CB_ID.lock() {
        *lock = Some(cb_id);
    }

    // Register profiles
    let ct_profile = avrcp_controller_profile();
    let tg_profile = avrcp_target_profile();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = btd_profile_register(ct_profile).await;
            let _ = btd_profile_register(tg_profile).await;
        });
    }

    info!("AVRCP plugin initialized");
    Ok(())
}

/// Clean up the AVRCP plugin — unregister profiles and state callback.
pub fn avrcp_exit() {
    info!("AVRCP plugin exiting");

    // Unregister state callback
    if let Ok(lock) = STATE_CB_ID.lock() {
        if let Some(cb_id) = *lock {
            avctp_remove_state_cb(cb_id);
        }
    }

    // Unregister profiles
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let ct_profile = avrcp_controller_profile();
        let tg_profile = avrcp_target_profile();
        handle.spawn(async move {
            btd_profile_unregister(&ct_profile).await;
            btd_profile_unregister(&tg_profile).await;
        });
    }

    info!("AVRCP plugin exited");
}

// ===========================================================================
// Plugin Registration via inventory
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "avrcp",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: avrcp_init,
        exit: avrcp_exit,
    }
}
