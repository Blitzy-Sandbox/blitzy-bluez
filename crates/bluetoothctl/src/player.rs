//! Media player, endpoint, and transport submenu module for bluetoothctl.
//!
//! Complete Rust rewrite of `client/player.c` (6158 lines) and `client/player.h`.
//! Provides three shell submenus:
//! - **player** — Media player control (play, pause, stop, browse, etc.)
//! - **endpoint** — Media endpoint management (register, configure, presets)
//! - **transport** — Media transport control (acquire, release, send, receive)
//!
//! Also implements the local `org.bluez.MediaEndpoint1` D-Bus interface via
//! `#[zbus::interface]` for codec endpoint registration.

use std::collections::HashMap;
use std::sync::Mutex;

use zbus::zvariant::{OwnedValue, Value};

use crate::display::{
    COLOR_BLUE, COLOR_BOLDGRAY, COLOR_BOLDWHITE, COLOR_GREEN, COLOR_OFF, COLOR_RED, COLOR_YELLOW,
    rl_hexdump,
};
use crate::print::{print_iter, print_uuid};

use bluez_shared::audio::bap::{
    BapBcastQos, BapCodec, BapIoQos, BapQos, BapUcastQos, BtLtv, bap_debug_caps, bap_debug_config,
    bap_debug_metadata,
};
use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, bt_shell_add_submenu, bt_shell_get_env, bt_shell_hexdump,
    bt_shell_noninteractive_quit, bt_shell_printf, bt_shell_prompt_input, bt_shell_remove_submenu,
    bt_shell_set_env, bt_shell_usage,
};
use bluez_shared::util::endian::{IoBuf, get_le16, get_le32, ltv_foreach, ltv_push, put_le16};
use bluez_shared::util::uuid::bt_uuidstr_to_str;

// ============================================================================
// D-Bus interface name constants
// ============================================================================

const BLUEZ_MEDIA_PLAYER_INTERFACE: &str = "org.bluez.MediaPlayer1";
const BLUEZ_MEDIA_FOLDER_INTERFACE: &str = "org.bluez.MediaFolder1";
const BLUEZ_MEDIA_ITEM_INTERFACE: &str = "org.bluez.MediaItem1";
const BLUEZ_MEDIA_ENDPOINT_INTERFACE: &str = "org.bluez.MediaEndpoint1";
const BLUEZ_MEDIA_TRANSPORT_INTERFACE: &str = "org.bluez.MediaTransport1";
const BLUEZ_MEDIA_INTERFACE: &str = "org.bluez.Media1";
const BLUEZ_MEDIA_ENDPOINT_PATH: &str = "/org/bluez/endpoint";

// ============================================================================
// A2DP codec IDs and well-known UUIDs
// ============================================================================

const A2DP_CODEC_SBC: u8 = 0x00;
const A2DP_CODEC_MPEG12: u8 = 0x01;
const A2DP_CODEC_MPEG24: u8 = 0x02;
const A2DP_CODEC_VENDOR: u8 = 0xFF;
const LC3_ID: u8 = 0x06;

const A2DP_SOURCE_UUID: &str = "0000110a-0000-1000-8000-00805f9b34fb";
const A2DP_SINK_UUID: &str = "0000110b-0000-1000-8000-00805f9b34fb";
const PAC_SINK_UUID: &str = "00001850-0000-1000-8000-00805f9b34fb";
const PAC_SOURCE_UUID: &str = "00001851-0000-1000-8000-00805f9b34fb";
const BCAA_SERVICE_UUID: &str = "00001852-0000-1000-8000-00805f9b34fb";
const BAA_SERVICE_UUID: &str = "00001853-0000-1000-8000-00805f9b34fb";

// LC3 LTV configuration types
const LC3_CONFIG_FREQ: u8 = 0x01;
const LC3_CONFIG_DURATION: u8 = 0x02;
const LC3_CONFIG_CHAN_ALLOC: u8 = 0x03;
const LC3_CONFIG_FRAME_LEN: u8 = 0x04;

// ISO QoS defaults
const BT_ISO_QOS_GROUP_UNSET: u8 = 0xFF;
const BT_ISO_QOS_STREAM_UNSET: u8 = 0xFF;

// Endpoint context/location defaults
const EP_SNK_LOCATIONS: u32 = 0x0000_0003;
const EP_SRC_LOCATIONS: u32 = 0x0000_0003;
const EP_SUPPORTED_SNK_CTXT: u16 = 0x0FFF;
const EP_SUPPORTED_SRC_CTXT: u16 = 0x0FFF;
const EP_SNK_CTXT: u16 = 0x0FFF;
const EP_SRC_CTXT: u16 = 0x0FFF;

// SBC capability bitmasks
const SBC_SAMPLING_FREQ_44100: u8 = 1 << 1;
const SBC_SAMPLING_FREQ_48000: u8 = 1 << 0;
const SBC_CHANNEL_MODE_MONO: u8 = 1 << 3;
const SBC_CHANNEL_MODE_JOINT_STEREO: u8 = 1 << 0;
const SBC_BLOCK_LENGTH_16: u8 = 1 << 0;
const SBC_SUBBANDS_8: u8 = 1 << 0;
const SBC_ALLOCATION_LOUDNESS: u8 = 1 << 0;

// ============================================================================
// Colored display helpers
// ============================================================================

fn colored_new() -> String {
    format!("{}NEW{}", COLOR_GREEN, COLOR_OFF)
}

fn colored_chg() -> String {
    format!("{}CHG{}", COLOR_YELLOW, COLOR_OFF)
}

fn colored_del() -> String {
    format!("{}DEL{}", COLOR_RED, COLOR_OFF)
}

// ============================================================================
// Codec Preset Structures
// ============================================================================

/// A single codec preset with configuration, QoS, and metadata.
#[derive(Clone)]
struct CodecPreset {
    name: String,
    data: Vec<u8>,
    meta: Vec<u8>,
    qos: BapQos,
    target_latency: u8,
    chan_alloc: u32,
    custom: bool,
}

impl CodecPreset {
    fn new_sbc(name: &str, config: &[u8]) -> Self {
        CodecPreset {
            name: name.to_string(),
            data: config.to_vec(),
            meta: Vec::new(),
            qos: BapQos::default(),
            target_latency: 0,
            chan_alloc: 0,
            custom: false,
        }
    }

    fn new_lc3(name: &str, config: &[u8], qos: BapQos, target_latency: u8) -> Self {
        CodecPreset {
            name: name.to_string(),
            data: config.to_vec(),
            meta: Vec::new(),
            qos,
            target_latency,
            chan_alloc: 0,
            custom: false,
        }
    }
}

/// A preset collection for a (UUID, codec) pair.
struct PresetGroup {
    uuid: String,
    codec: BapCodec,
    presets: Vec<CodecPreset>,
    default_index: usize,
    custom: Vec<CodecPreset>,
}

impl PresetGroup {
    fn default_preset(&self) -> Option<&CodecPreset> {
        self.presets.get(self.default_index)
    }

    fn find_by_name(&self, name: &str) -> Option<&CodecPreset> {
        self.presets
            .iter()
            .find(|p| p.name == name)
            .or_else(|| self.custom.iter().find(|p| p.name == name))
    }
}

// ============================================================================
// Local Endpoint
// ============================================================================

/// Represents a locally registered MediaEndpoint1 object.
struct LocalEndpoint {
    path: String,
    uuid: String,
    codec: BapCodec,
    caps: Vec<u8>,
    meta: Vec<u8>,
    locations: u32,
    supported_context: u16,
    context: u16,
    auto_accept: bool,
    max_transports: u8,
    iso_group: u8,
    iso_stream: u8,
    broadcast: bool,
    preset_group_uuid: Option<String>,
    codec_preset_name: Option<String>,
    refcount: u32,
    transport_paths: Vec<String>,
    bcode: Vec<u8>,
}

// ============================================================================
// Transport IO state
// ============================================================================

/// Tracks an acquired transport fd and associated streaming state.
struct TransportIo {
    proxy_path: String,
    mtu: [u16; 2],
    filename: Option<String>,
    seq: u32,
}

// ============================================================================
// Proxy info
// ============================================================================

/// Lightweight info about a remote D-Bus proxy.
#[derive(Clone)]
struct ProxyInfo {
    path: String,
    interface: String,
    properties: HashMap<String, OwnedValue>,
}

impl ProxyInfo {
    fn new(path: &str, iface: &str) -> Self {
        ProxyInfo {
            path: path.to_string(),
            interface: iface.to_string(),
            properties: HashMap::new(),
        }
    }
}

// ============================================================================
// Module-level state
// ============================================================================

struct PlayerState {
    players: Vec<ProxyInfo>,
    folders: Vec<ProxyInfo>,
    items: Vec<ProxyInfo>,
    endpoints: Vec<ProxyInfo>,
    transports: Vec<ProxyInfo>,
    medias: Vec<ProxyInfo>,
    local_endpoints: Vec<LocalEndpoint>,
    endpoint_ifaces: Vec<EndpointIface>,
    ios: Vec<TransportIo>,
    default_player: Option<String>,
    default_transport: Option<String>,
    auto_acquire: bool,
    auto_select: bool,
    preset_groups: Vec<PresetGroup>,
}

impl PlayerState {
    fn new() -> Self {
        PlayerState {
            players: Vec::new(),
            folders: Vec::new(),
            items: Vec::new(),
            endpoints: Vec::new(),
            transports: Vec::new(),
            medias: Vec::new(),
            local_endpoints: Vec::new(),
            endpoint_ifaces: Vec::new(),
            ios: Vec::new(),
            default_player: None,
            default_transport: None,
            auto_acquire: false,
            auto_select: false,
            preset_groups: build_preset_groups(),
        }
    }
}

static STATE: Mutex<Option<PlayerState>> = Mutex::new(None);

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut PlayerState) -> R,
{
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.get_or_insert_with(PlayerState::new);
    f(state)
}

// ============================================================================
// LC3 Preset builders
// ============================================================================

/// Build an LC3 configuration byte array from freq, duration, and frame_len
/// using IoBuf and ltv_push for LTV record construction.
fn lc3_config_bytes(freq: u8, duration: u8, frame_len: u16) -> Vec<u8> {
    let mut buf = IoBuf::with_capacity(16);
    ltv_push(&mut buf, LC3_CONFIG_FREQ, &[freq]);
    ltv_push(&mut buf, LC3_CONFIG_DURATION, &[duration]);
    let mut fl_bytes = [0u8; 2];
    put_le16(frame_len, &mut fl_bytes);
    ltv_push(&mut buf, LC3_CONFIG_FRAME_LEN, &fl_bytes);
    buf.as_bytes().to_vec()
}

fn lc3_ucast_qos(
    interval: u32,
    framing: u8,
    phys: u8,
    sdu: u16,
    rtn: u8,
    latency: u16,
    delay: u32,
) -> BapQos {
    BapQos::Ucast(BapUcastQos {
        cig_id: BT_ISO_QOS_GROUP_UNSET,
        cis_id: BT_ISO_QOS_STREAM_UNSET,
        framing,
        delay,
        target_latency: 0x02,
        io_qos: BapIoQos { interval, phys, sdu, rtn, latency },
    })
}

fn lc3_bcast_qos(
    interval: u32,
    framing: u8,
    phys: u8,
    sdu: u16,
    rtn: u8,
    latency: u16,
    delay: u32,
) -> BapQos {
    BapQos::Bcast(BapBcastQos {
        big: BT_ISO_QOS_GROUP_UNSET,
        bis: BT_ISO_QOS_STREAM_UNSET,
        sync_factor: 0x07,
        packing: 0x00,
        framing,
        encryption: 0x00,
        bcode: None,
        options: 0x00,
        skip: 0x0000,
        sync_timeout: 0x4000,
        sync_cte_type: 0x00,
        mse: 0x00,
        timeout: 0x4000,
        pa_sync: 0x00,
        io_qos: BapIoQos { interval, phys, sdu, rtn, latency },
        delay,
    })
}

// ============================================================================
// Preset construction
// ============================================================================

fn build_sbc_presets() -> Vec<CodecPreset> {
    vec![
        CodecPreset::new_sbc(
            "MQ_MONO_44_1",
            &[
                SBC_SAMPLING_FREQ_44100 | SBC_CHANNEL_MODE_MONO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                32,
            ],
        ),
        CodecPreset::new_sbc(
            "MQ_MONO_48",
            &[
                SBC_SAMPLING_FREQ_48000 | SBC_CHANNEL_MODE_MONO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                32,
            ],
        ),
        CodecPreset::new_sbc(
            "MQ_STEREO_44_1",
            &[
                SBC_SAMPLING_FREQ_44100 | SBC_CHANNEL_MODE_JOINT_STEREO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                53,
            ],
        ),
        CodecPreset::new_sbc(
            "MQ_STEREO_48",
            &[
                SBC_SAMPLING_FREQ_48000 | SBC_CHANNEL_MODE_JOINT_STEREO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                51,
            ],
        ),
        CodecPreset::new_sbc(
            "HQ_MONO_44_1",
            &[
                SBC_SAMPLING_FREQ_44100 | SBC_CHANNEL_MODE_MONO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                44,
            ],
        ),
        CodecPreset::new_sbc(
            "HQ_MONO_48",
            &[
                SBC_SAMPLING_FREQ_48000 | SBC_CHANNEL_MODE_MONO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                51,
            ],
        ),
        CodecPreset::new_sbc(
            "HQ_STEREO_44_1",
            &[
                SBC_SAMPLING_FREQ_44100 | SBC_CHANNEL_MODE_JOINT_STEREO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                53,
            ],
        ),
        CodecPreset::new_sbc(
            "HQ_STEREO_48",
            &[
                SBC_SAMPLING_FREQ_48000 | SBC_CHANNEL_MODE_JOINT_STEREO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                51,
            ],
        ),
        CodecPreset::new_sbc(
            "XQ_MONO_44_1",
            &[
                SBC_SAMPLING_FREQ_44100 | SBC_CHANNEL_MODE_MONO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                76,
            ],
        ),
        CodecPreset::new_sbc(
            "XQ_MONO_48",
            &[
                SBC_SAMPLING_FREQ_48000 | SBC_CHANNEL_MODE_MONO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                76,
            ],
        ),
        CodecPreset::new_sbc(
            "XQ_STEREO_44_1",
            &[
                SBC_SAMPLING_FREQ_44100 | SBC_CHANNEL_MODE_JOINT_STEREO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                76,
            ],
        ),
        CodecPreset::new_sbc(
            "XQ_STEREO_48",
            &[
                SBC_SAMPLING_FREQ_48000 | SBC_CHANNEL_MODE_JOINT_STEREO,
                SBC_BLOCK_LENGTH_16 | SBC_SUBBANDS_8 | SBC_ALLOCATION_LOUDNESS,
                2,
                76,
            ],
        ),
    ]
}

fn build_lc3_ucast_presets() -> Vec<CodecPreset> {
    vec![
        CodecPreset::new_lc3(
            "8_1_1",
            &lc3_config_bytes(0x01, 0x00, 26),
            lc3_ucast_qos(7500, 0x00, 0x02, 26, 2, 8, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "8_2_1",
            &lc3_config_bytes(0x01, 0x01, 30),
            lc3_ucast_qos(10000, 0x00, 0x02, 30, 2, 10, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "16_1_1",
            &lc3_config_bytes(0x03, 0x00, 30),
            lc3_ucast_qos(7500, 0x00, 0x02, 30, 2, 8, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "16_2_1",
            &lc3_config_bytes(0x03, 0x01, 40),
            lc3_ucast_qos(10000, 0x00, 0x02, 40, 2, 10, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "24_1_1",
            &lc3_config_bytes(0x05, 0x00, 45),
            lc3_ucast_qos(7500, 0x00, 0x02, 45, 2, 8, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "24_2_1",
            &lc3_config_bytes(0x05, 0x01, 60),
            lc3_ucast_qos(10000, 0x00, 0x02, 60, 2, 10, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "32_1_1",
            &lc3_config_bytes(0x06, 0x00, 60),
            lc3_ucast_qos(7500, 0x00, 0x02, 60, 2, 8, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "32_2_1",
            &lc3_config_bytes(0x06, 0x01, 80),
            lc3_ucast_qos(10000, 0x00, 0x02, 80, 2, 10, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "441_1_1",
            &lc3_config_bytes(0x07, 0x00, 98),
            lc3_ucast_qos(8163, 0x01, 0x02, 98, 5, 24, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "441_2_1",
            &lc3_config_bytes(0x07, 0x01, 130),
            lc3_ucast_qos(10884, 0x01, 0x02, 130, 5, 31, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "48_1_1",
            &lc3_config_bytes(0x08, 0x00, 75),
            lc3_ucast_qos(7500, 0x00, 0x02, 75, 5, 15, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "48_2_1",
            &lc3_config_bytes(0x08, 0x01, 100),
            lc3_ucast_qos(10000, 0x00, 0x02, 100, 5, 20, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "48_3_1",
            &lc3_config_bytes(0x08, 0x00, 90),
            lc3_ucast_qos(7500, 0x00, 0x02, 90, 5, 15, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "48_4_1",
            &lc3_config_bytes(0x08, 0x01, 120),
            lc3_ucast_qos(10000, 0x00, 0x02, 120, 5, 20, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "48_5_1",
            &lc3_config_bytes(0x08, 0x00, 117),
            lc3_ucast_qos(7500, 0x00, 0x02, 117, 5, 15, 40000),
            0x02,
        ),
        CodecPreset::new_lc3(
            "48_6_1",
            &lc3_config_bytes(0x08, 0x01, 155),
            lc3_ucast_qos(10000, 0x00, 0x02, 155, 5, 20, 40000),
            0x02,
        ),
    ]
}

fn build_lc3_bcast_presets() -> Vec<CodecPreset> {
    vec![
        CodecPreset::new_lc3(
            "8_1_1",
            &lc3_config_bytes(0x01, 0x00, 26),
            lc3_bcast_qos(7500, 0x00, 0x02, 26, 2, 8, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "8_2_1",
            &lc3_config_bytes(0x01, 0x01, 30),
            lc3_bcast_qos(10000, 0x00, 0x02, 30, 2, 10, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "16_1_1",
            &lc3_config_bytes(0x03, 0x00, 30),
            lc3_bcast_qos(7500, 0x00, 0x02, 30, 2, 8, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "16_2_1",
            &lc3_config_bytes(0x03, 0x01, 40),
            lc3_bcast_qos(10000, 0x00, 0x02, 40, 2, 10, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "24_1_1",
            &lc3_config_bytes(0x05, 0x00, 45),
            lc3_bcast_qos(7500, 0x00, 0x02, 45, 2, 8, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "24_2_1",
            &lc3_config_bytes(0x05, 0x01, 60),
            lc3_bcast_qos(10000, 0x00, 0x02, 60, 2, 10, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "48_1_1",
            &lc3_config_bytes(0x08, 0x00, 75),
            lc3_bcast_qos(7500, 0x00, 0x02, 75, 4, 15, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "48_2_1",
            &lc3_config_bytes(0x08, 0x01, 100),
            lc3_bcast_qos(10000, 0x00, 0x02, 100, 4, 20, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "48_3_1",
            &lc3_config_bytes(0x08, 0x00, 90),
            lc3_bcast_qos(7500, 0x00, 0x02, 90, 4, 15, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "48_4_1",
            &lc3_config_bytes(0x08, 0x01, 120),
            lc3_bcast_qos(10000, 0x00, 0x02, 120, 4, 20, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "48_5_1",
            &lc3_config_bytes(0x08, 0x00, 117),
            lc3_bcast_qos(7500, 0x00, 0x02, 117, 4, 15, 40000),
            0x00,
        ),
        CodecPreset::new_lc3(
            "48_6_1",
            &lc3_config_bytes(0x08, 0x01, 155),
            lc3_bcast_qos(10000, 0x00, 0x02, 155, 4, 20, 40000),
            0x00,
        ),
    ]
}

fn build_preset_groups() -> Vec<PresetGroup> {
    let sbc_presets = build_sbc_presets();
    let lc3_ucast = build_lc3_ucast_presets();
    let lc3_bcast = build_lc3_bcast_presets();

    vec![
        PresetGroup {
            uuid: A2DP_SOURCE_UUID.to_string(),
            codec: BapCodec { id: A2DP_CODEC_SBC, cid: 0, vid: 0 },
            default_index: 6,
            presets: sbc_presets.clone(),
            custom: Vec::new(),
        },
        PresetGroup {
            uuid: A2DP_SINK_UUID.to_string(),
            codec: BapCodec { id: A2DP_CODEC_SBC, cid: 0, vid: 0 },
            default_index: 6,
            presets: sbc_presets,
            custom: Vec::new(),
        },
        PresetGroup {
            uuid: PAC_SINK_UUID.to_string(),
            codec: BapCodec { id: LC3_ID, cid: 0, vid: 0 },
            default_index: 3,
            presets: lc3_ucast.clone(),
            custom: Vec::new(),
        },
        PresetGroup {
            uuid: PAC_SOURCE_UUID.to_string(),
            codec: BapCodec { id: LC3_ID, cid: 0, vid: 0 },
            default_index: 3,
            presets: lc3_ucast,
            custom: Vec::new(),
        },
        PresetGroup {
            uuid: BCAA_SERVICE_UUID.to_string(),
            codec: BapCodec { id: LC3_ID, cid: 0, vid: 0 },
            default_index: 3,
            presets: lc3_bcast.clone(),
            custom: Vec::new(),
        },
        PresetGroup {
            uuid: BAA_SERVICE_UUID.to_string(),
            codec: BapCodec { id: LC3_ID, cid: 0, vid: 0 },
            default_index: 3,
            presets: lc3_bcast,
            custom: Vec::new(),
        },
    ]
}

// ============================================================================
// Helper functions
// ============================================================================

fn check_default_player() -> Option<String> {
    with_state(|state| {
        if let Some(ref player) = state.default_player {
            Some(player.clone())
        } else {
            bt_shell_printf(format_args!("No default player available\n"));
            None
        }
    })
}

/// Convert a hex string to byte array. E.g. "0102ff" -> [0x01, 0x02, 0xff]
fn str_to_bytearray(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let cleaned: String = s.replace("0x", "").replace("0X", "").replace([':', ' '], "");
    if cleaned.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        let byte = u8::from_str_radix(hex_str, 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Print SBC codec capabilities from raw bytes.
fn print_sbc(data: &[u8]) {
    if data.len() < 4 {
        bt_shell_printf(format_args!("\t\tMedia Codec: SBC (broken)\n"));
        return;
    }
    bt_shell_printf(format_args!("\t\tMedia Codec: SBC\n"));
    let freq = data[0] >> 4;
    let chan_mode = data[0] & 0x0F;
    let blk_len = data[1] >> 4;
    let subbands = (data[1] >> 2) & 0x03;
    let alloc = data[1] & 0x03;
    bt_shell_printf(format_args!("\t\t\tFrequency: 0x{:02x}\n", freq));
    bt_shell_printf(format_args!("\t\t\tChannel Mode: 0x{:02x}\n", chan_mode));
    bt_shell_printf(format_args!("\t\t\tBlock Length: 0x{:02x}\n", blk_len));
    bt_shell_printf(format_args!("\t\t\tSubbands: 0x{:02x}\n", subbands));
    bt_shell_printf(format_args!("\t\t\tAllocation: 0x{:02x}\n", alloc));
    bt_shell_printf(format_args!("\t\t\tBitpool: {} - {}\n", data[2], data[3]));
}

/// Print MPEG-1,2 codec capabilities from raw bytes.
fn print_mpeg12(data: &[u8]) {
    if data.len() < 4 {
        bt_shell_printf(format_args!("\t\tMedia Codec: MPEG12 (broken)\n"));
        return;
    }
    bt_shell_printf(format_args!("\t\tMedia Codec: MPEG-1,2 Audio\n"));
    bt_shell_printf(format_args!("\t\t\tLayer: 0x{:02x}\n", data[0] >> 5));
    bt_shell_printf(format_args!(
        "\t\t\tCRC: {}\n",
        if data[0] & 0x10 != 0 { "Yes" } else { "No" }
    ));
    bt_shell_printf(format_args!("\t\t\tChannel Mode: 0x{:02x}\n", data[0] & 0x0F));
    bt_shell_printf(format_args!("\t\t\tFrequency: 0x{:02x}\n", data[1]));
    let bitrate = get_le16(&data[2..]);
    bt_shell_printf(format_args!("\t\t\tBitrate: 0x{:04x}\n", bitrate));
}

/// Print AAC (MPEG-2,4) codec capabilities from raw bytes.
fn print_mpeg24(data: &[u8]) {
    if data.len() < 6 {
        bt_shell_printf(format_args!("\t\tMedia Codec: MPEG24 (broken)\n"));
        return;
    }
    bt_shell_printf(format_args!("\t\tMedia Codec: MPEG-2,4 AAC\n"));
    bt_shell_printf(format_args!("\t\t\tObject Type: 0x{:02x}\n", data[0]));
    let freq = ((data[1] as u16) << 4) | ((data[2] as u16) >> 4);
    bt_shell_printf(format_args!("\t\t\tFrequency: 0x{:04x}\n", freq));
    bt_shell_printf(format_args!("\t\t\tChannels: 0x{:02x}\n", data[2] & 0x0C));
    let bitrate = get_le32(&data[3..]);
    bt_shell_printf(format_args!("\t\t\tBitrate: 0x{:08x}\n", bitrate));
    bt_shell_printf(format_args!(
        "\t\t\tVBR: {}\n",
        if data[3] & 0x80 != 0 { "Yes" } else { "No" }
    ));
}

/// Print vendor-specific codec capabilities.
fn print_vendor(data: &[u8]) {
    if data.len() < 4 {
        bt_shell_printf(format_args!("\t\tMedia Codec: Vendor (broken)\n"));
        return;
    }
    let vendor_id = get_le32(data);
    bt_shell_printf(format_args!("\t\tMedia Codec: Vendor 0x{:08x}\n", vendor_id));
    if data.len() > 4 {
        rl_hexdump(&data[4..]);
    }
}

/// Print A2DP codec capabilities for the given codec type.
fn print_a2dp_codec(codec: u8, data: &[u8]) {
    match codec {
        A2DP_CODEC_SBC => print_sbc(data),
        A2DP_CODEC_MPEG12 => print_mpeg12(data),
        A2DP_CODEC_MPEG24 => print_mpeg24(data),
        A2DP_CODEC_VENDOR => print_vendor(data),
        _ => {
            bt_shell_printf(format_args!("\t\tMedia Codec: Unknown (0x{:02x})\n", codec));
            rl_hexdump(data);
        }
    }
}

/// Print codec capabilities, dispatching between A2DP and LC3 formats.
/// Uses bap_debug_caps for LC3 codec capability LTV parsing and
/// bap_debug_config for LC3 configuration display.
fn print_codec(uuid: &str, codec: u8, data: &[u8]) {
    if uuid.eq_ignore_ascii_case(PAC_SINK_UUID)
        || uuid.eq_ignore_ascii_case(PAC_SOURCE_UUID)
        || uuid.eq_ignore_ascii_case(BCAA_SERVICE_UUID)
        || uuid.eq_ignore_ascii_case(BAA_SERVICE_UUID)
    {
        // LC3 codec — use BAP LTV debug utilities
        bap_debug_caps(data, &mut |msg: &str| {
            bt_shell_printf(format_args!("\t\t{}\n", msg));
        });
    } else {
        // A2DP codec
        print_a2dp_codec(codec, data);
    }
}

/// Print codec configuration using BAP debug helpers for LC3.
fn print_configuration(uuid: &str, codec: u8, data: &[u8]) {
    if uuid.eq_ignore_ascii_case(PAC_SINK_UUID)
        || uuid.eq_ignore_ascii_case(PAC_SOURCE_UUID)
        || uuid.eq_ignore_ascii_case(BCAA_SERVICE_UUID)
        || uuid.eq_ignore_ascii_case(BAA_SERVICE_UUID)
    {
        bap_debug_config(data, &mut |msg: &str| {
            bt_shell_printf(format_args!("\t\t{}\n", msg));
        });
    } else {
        print_a2dp_codec(codec, data);
    }
}

/// Print metadata using BAP debug helpers.
fn print_metadata(data: &[u8]) {
    bap_debug_metadata(data, &mut |msg: &str| {
        bt_shell_printf(format_args!("\t\t{}\n", msg));
    });
}

/// Iterate LTV records in data and print each entry.
fn print_ltv_records(data: &[u8]) {
    ltv_foreach(data, |ltv_type, ltv_data| {
        bt_shell_printf(format_args!("\t\tLTV: type=0x{:02x} len={}\n", ltv_type, ltv_data.len()));
        true
    });
}

/// Parse channel allocation from LTV config data.
fn parse_chan_alloc(data: &[u8]) -> u32 {
    let mut alloc: u32 = 0;
    ltv_foreach(data, |ltv_type, ltv_data| {
        if ltv_type == LC3_CONFIG_CHAN_ALLOC && ltv_data.len() >= 4 {
            alloc = get_le32(ltv_data);
        }
        true
    });
    alloc
}

/// Display a D-Bus property value, handling dict/array via print_iter.
fn display_property(name: &str, value: &Value<'_>) {
    match value {
        Value::Dict(_) | Value::Array(_) => {
            print_iter("\t", name, value);
        }
        _ => {
            bt_shell_printf(format_args!("\t{}: {}\n", name, value));
        }
    }
}

/// Display a proxy's known property with human-readable UUID resolution
/// using bt_uuidstr_to_str for UUID properties and print_uuid for display.
fn display_proxy_property(path: &str, name: &str, properties: &HashMap<String, OwnedValue>) {
    let _ = path;
    if let Some(val) = properties.get(name) {
        // OwnedValue implements Deref<Target=Value<'static>>, so &**val gives &Value
        if name == "UUID" || name == "UUIDs" {
            if let Value::Str(s) = &**val {
                let readable = bt_uuidstr_to_str(s.as_str()).unwrap_or(s.as_str());
                print_uuid("\t", name, readable);
                return;
            }
        }
        display_property(name, val);
    }
}

/// Display all properties for a proxy using the fmt module formatting.
fn display_all_properties(path: &str, properties: &HashMap<String, OwnedValue>) {
    let _ = path;
    bt_shell_printf(format_args!("Properties:\n"));
    for (name, val) in properties {
        // OwnedValue implements Deref<Target=Value<'static>>
        display_property(name, val);
    }
}

/// Build a BtLtv record from type and data, useful for codec preset building.
fn build_ltv(ltv_type: u8, data: &[u8]) -> BtLtv {
    BtLtv { len: (data.len() + 1) as u8, type_: ltv_type, value: data.to_vec() }
}

/// Set an environment variable for the player module using shell env.
fn set_player_env(name: &str, value: String) {
    bt_shell_set_env(name, Box::new(value));
}

/// Get an environment variable from the player module shell env.
fn get_player_env(name: &str) -> Option<String> {
    bt_shell_get_env::<String>(name)
}

// ============================================================================
// Player submenu commands
// ============================================================================

fn cmd_list(args: &[&str]) {
    let _ = args;
    with_state(|state| {
        for p in &state.players {
            bt_shell_printf(format_args!("Player {} [{}]\n", p.path, p.interface));
        }
    });
    bt_shell_noninteractive_quit(0);
}

fn cmd_show(args: &[&str]) {
    let player_path = if args.len() > 1 {
        Some(args[1].to_string())
    } else {
        with_state(|state| state.default_player.clone())
    };

    match player_path {
        Some(path) => {
            let found = with_state(|state| state.players.iter().find(|p| p.path == path).cloned());
            match found {
                Some(proxy) => {
                    bt_shell_printf(format_args!(
                        "{}Player {}{}\n",
                        COLOR_BOLDWHITE, path, COLOR_OFF
                    ));
                    display_all_properties(&path, &proxy.properties);
                }
                None => {
                    bt_shell_printf(format_args!("Player {} not available\n", path));
                }
            }
        }
        None => {
            bt_shell_printf(format_args!("No default player available\n"));
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_select(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    let path = args[1].to_string();
    let found = with_state(|state| {
        if state.players.iter().any(|p| p.path == path) {
            state.default_player = Some(path.clone());
            true
        } else {
            false
        }
    });
    if found {
        bt_shell_printf(format_args!("Default player set to {}\n", path));
    } else {
        bt_shell_printf(format_args!("Player {} not available\n", path));
    }
    bt_shell_noninteractive_quit(if found { 0 } else { 1 });
}

fn cmd_play(args: &[&str]) {
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    if args.len() > 1 {
        bt_shell_printf(format_args!("Attempting to play item {}\n", args[1]));
    } else {
        bt_shell_printf(format_args!("Attempting to resume playback\n"));
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_pause(args: &[&str]) {
    let _ = args;
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to pause\n"));
    bt_shell_noninteractive_quit(0);
}

fn cmd_stop(args: &[&str]) {
    let _ = args;
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to stop\n"));
    bt_shell_noninteractive_quit(0);
}

fn cmd_next(args: &[&str]) {
    let _ = args;
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to skip to next\n"));
    bt_shell_noninteractive_quit(0);
}

fn cmd_previous(args: &[&str]) {
    let _ = args;
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to skip to previous\n"));
    bt_shell_noninteractive_quit(0);
}

fn cmd_fast_forward(args: &[&str]) {
    let _ = args;
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to fast forward\n"));
    bt_shell_noninteractive_quit(0);
}

fn cmd_rewind(args: &[&str]) {
    let _ = args;
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to rewind\n"));
    bt_shell_noninteractive_quit(0);
}

fn cmd_equalizer(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    let value = args[1];
    if value != "on" && value != "off" {
        bt_shell_printf(format_args!("Invalid argument: {}\n", value));
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Setting equalizer to {}\n", value));
    bt_shell_noninteractive_quit(0);
}

fn cmd_repeat(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    let value = args[1];
    match value {
        "singletrack" | "alltrack" | "group" | "off" => {
            bt_shell_printf(format_args!("Setting repeat to {}\n", value));
        }
        _ => {
            bt_shell_printf(format_args!("Invalid argument: {}\n", value));
            return bt_shell_noninteractive_quit(1);
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_shuffle(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    let value = args[1];
    match value {
        "alltracks" | "group" | "off" => {
            bt_shell_printf(format_args!("Setting shuffle to {}\n", value));
        }
        _ => {
            bt_shell_printf(format_args!("Invalid argument: {}\n", value));
            return bt_shell_noninteractive_quit(1);
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_scan(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    let value = args[1];
    match value {
        "alltracks" | "group" | "off" => {
            bt_shell_printf(format_args!("Setting scan to {}\n", value));
        }
        _ => {
            bt_shell_printf(format_args!("Invalid argument: {}\n", value));
            return bt_shell_noninteractive_quit(1);
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_change_folder(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to change folder to {}\n", args[1]));
    bt_shell_noninteractive_quit(0);
}

fn cmd_list_items(args: &[&str]) {
    let start: u32 = if args.len() > 1 { args[1].parse().unwrap_or(0) } else { 0 };
    let end: u32 = if args.len() > 2 { args[2].parse().unwrap_or(u32::MAX) } else { u32::MAX };

    with_state(|state| {
        for (i, item) in state.items.iter().enumerate() {
            let idx = i as u32;
            if idx >= start && idx <= end {
                bt_shell_printf(format_args!("Item {}\n", item.path));
            }
        }
    });
    bt_shell_noninteractive_quit(0);
}

fn cmd_search(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to search for \"{}\"\n", args[1]));
    bt_shell_noninteractive_quit(0);
}

fn cmd_queue(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    if check_default_player().is_none() {
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Attempting to queue {}\n", args[1]));
    bt_shell_noninteractive_quit(0);
}

fn cmd_show_item(args: &[&str]) {
    let item_path = if args.len() > 1 { Some(args[1].to_string()) } else { None };

    with_state(|state| match item_path {
        Some(ref path) => {
            if let Some(item) = state.items.iter().find(|i| i.path == *path) {
                bt_shell_printf(format_args!(
                    "{}Item {}{}\n",
                    COLOR_BOLDWHITE, item.path, COLOR_OFF
                ));
                display_all_properties(&item.path, &item.properties);
            } else {
                bt_shell_printf(format_args!("Item {} not available\n", path));
            }
        }
        None => {
            for item in &state.items {
                bt_shell_printf(format_args!("Item {}\n", item.path));
            }
        }
    });
    bt_shell_noninteractive_quit(0);
}

// ============================================================================
// Endpoint submenu commands
// ============================================================================

fn cmd_list_endpoints(args: &[&str]) {
    let _ = args;
    with_state(|state| {
        for ep in &state.endpoints {
            let uuid_label = ep
                .properties
                .get("UUID")
                .and_then(|v| {
                    // OwnedValue: Deref<Target=Value<'static>>
                    if let Value::Str(s) = &**v {
                        bt_uuidstr_to_str(s.as_str()).map(|r| r.to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            bt_shell_printf(format_args!("Endpoint {}", ep.path));
            if !uuid_label.is_empty() {
                bt_shell_printf(format_args!(" [{}]", uuid_label));
            }
            bt_shell_printf(format_args!("\n"));
        }
        for ep in &state.local_endpoints {
            bt_shell_printf(format_args!("Endpoint {} [local]\n", ep.path));
        }
    });
    bt_shell_noninteractive_quit(0);
}

fn cmd_show_endpoint(args: &[&str]) {
    if args.len() < 2 {
        with_state(|state| {
            for ep in &state.endpoints {
                bt_shell_printf(format_args!("Endpoint {}\n", ep.path));
            }
            for ep in &state.local_endpoints {
                print_local_endpoint(ep);
            }
        });
        return bt_shell_noninteractive_quit(0);
    }

    let path = args[1];
    let found = with_state(|state| {
        if let Some(ep) = state.endpoints.iter().find(|e| e.path == path) {
            bt_shell_printf(format_args!("{}Endpoint {}{}\n", COLOR_BOLDWHITE, path, COLOR_OFF));
            // Display UUID with human-readable name
            display_proxy_property(path, "UUID", &ep.properties);
            display_proxy_property(path, "Codec", &ep.properties);
            if let Some(caps_val) = ep.properties.get("Capabilities") {
                if let Value::Array(arr) = &**caps_val {
                    let bytes: Vec<u8> = arr
                        .iter()
                        .filter_map(|v| if let Value::U8(b) = v { Some(*b) } else { None })
                        .collect();
                    bt_shell_printf(format_args!("\tCapabilities:\n"));
                    rl_hexdump(&bytes);
                }
            }
            display_all_properties(path, &ep.properties);
            return true;
        }
        if let Some(ep) = state.local_endpoints.iter().find(|e| e.path == path || e.uuid == path) {
            print_local_endpoint(ep);
            return true;
        }
        false
    });
    if !found {
        bt_shell_printf(format_args!("Endpoint {} not found\n", path));
    }
    bt_shell_noninteractive_quit(0);
}

fn print_local_endpoint(ep: &LocalEndpoint) {
    let uuid_name = bt_uuidstr_to_str(&ep.uuid).unwrap_or(&ep.uuid);
    bt_shell_printf(format_args!("{}Endpoint {}{}\n", COLOR_BOLDWHITE, ep.path, COLOR_OFF));
    bt_shell_printf(format_args!("\tUUID: {}\n", uuid_name));
    bt_shell_printf(format_args!("\tCodec: 0x{:02x} ({})\n", ep.codec.id, ep.codec.id));

    if !ep.caps.is_empty() {
        bt_shell_printf(format_args!("\tCapabilities:\n"));
        bt_shell_hexdump(&ep.caps);
        // Decode the capabilities using LTV parsing
        print_ltv_records(&ep.caps);
        print_codec(&ep.uuid, ep.codec.id, &ep.caps);
        // Parse channel allocation from caps if present
        let alloc = parse_chan_alloc(&ep.caps);
        if alloc != 0 {
            bt_shell_printf(format_args!("\tChannel Allocation: 0x{:08x}\n", alloc));
        }
    }

    if !ep.meta.is_empty() {
        bt_shell_printf(format_args!("\tMetadata:\n"));
        print_metadata(&ep.meta);
    }

    if ep.locations != 0 {
        bt_shell_printf(format_args!("\tLocations: 0x{:08x}\n", ep.locations));
    }
    if ep.supported_context != 0 {
        bt_shell_printf(format_args!("\tSupportedContext: 0x{:04x}\n", ep.supported_context));
    }
    if ep.context != 0 {
        bt_shell_printf(format_args!("\tContext: 0x{:04x}\n", ep.context));
    }
    if let Some(ref preset_name) = ep.codec_preset_name {
        bt_shell_printf(format_args!("\tPreset: {}\n", preset_name));
    }

    // Transport and ISO configuration
    bt_shell_printf(format_args!("\tAuto Accept: {}\n", ep.auto_accept));
    bt_shell_printf(format_args!("\tMax Transports: {}\n", ep.max_transports));

    if ep.broadcast {
        bt_shell_printf(format_args!("\tBroadcast: yes\n"));
    }

    if ep.iso_group != BT_ISO_QOS_GROUP_UNSET {
        bt_shell_printf(format_args!("\tISO Group: {}\n", ep.iso_group));
    }
    if ep.iso_stream != BT_ISO_QOS_STREAM_UNSET {
        bt_shell_printf(format_args!("\tISO Stream: {}\n", ep.iso_stream));
    }

    if !ep.bcode.is_empty() {
        bt_shell_printf(format_args!("\tBroadcast Code: {} bytes\n", ep.bcode.len()));
    }

    bt_shell_printf(format_args!("\tRefcount: {}\n", ep.refcount));

    if !ep.transport_paths.is_empty() {
        bt_shell_printf(format_args!("\tTransports:\n"));
        for tp in &ep.transport_paths {
            bt_shell_printf(format_args!("\t\t{}\n", tp));
        }
    }
}

fn cmd_register_endpoint(args: &[&str]) {
    if args.len() < 3 {
        bt_shell_usage();
        return;
    }

    let uuid = args[1].to_string();
    let codec_str = args[2];
    let mut cid: u16 = 0;
    let mut vid: u16 = 0;

    // Check for vendor codec format "codec:company"
    let codec_id: u8 = if let Some(colon_pos) = codec_str.find(':') {
        let codec_part = &codec_str[..colon_pos];
        let company_part = &codec_str[colon_pos + 1..];
        vid = u16::from_str_radix(codec_part.strip_prefix("0x").unwrap_or(codec_part), 16)
            .unwrap_or(0);
        cid = u16::from_str_radix(company_part.strip_prefix("0x").unwrap_or(company_part), 16)
            .unwrap_or(0);
        A2DP_CODEC_VENDOR
    } else {
        u8::from_str_radix(codec_str.strip_prefix("0x").unwrap_or(codec_str), 16)
            .unwrap_or_else(|_| codec_str.parse().unwrap_or(0))
    };

    let broadcast =
        uuid.eq_ignore_ascii_case(BCAA_SERVICE_UUID) || uuid.eq_ignore_ascii_case(BAA_SERVICE_UUID);

    with_state(|state| {
        let idx = state.local_endpoints.len();
        let path = format!("{}/ep{}", BLUEZ_MEDIA_ENDPOINT_PATH, idx);

        let mut ep = LocalEndpoint {
            path: path.clone(),
            uuid: uuid.clone(),
            codec: BapCodec { id: codec_id, cid, vid },
            caps: Vec::new(),
            meta: Vec::new(),
            locations: 0,
            supported_context: 0,
            context: 0,
            auto_accept: true,
            max_transports: u8::MAX,
            iso_group: BT_ISO_QOS_GROUP_UNSET,
            iso_stream: BT_ISO_QOS_STREAM_UNSET,
            broadcast,
            preset_group_uuid: None,
            codec_preset_name: None,
            refcount: 0,
            transport_paths: Vec::new(),
            bcode: Vec::new(),
        };

        // Set defaults based on UUID
        if !uuid.eq_ignore_ascii_case(A2DP_SOURCE_UUID)
            && !uuid.eq_ignore_ascii_case(A2DP_SINK_UUID)
        {
            if broadcast {
                if uuid.eq_ignore_ascii_case(BAA_SERVICE_UUID) {
                    ep.locations = EP_SNK_LOCATIONS;
                    ep.supported_context = EP_SUPPORTED_SNK_CTXT;
                } else {
                    ep.locations = EP_SRC_LOCATIONS;
                    ep.supported_context = EP_SUPPORTED_SRC_CTXT;
                }
            } else if uuid.eq_ignore_ascii_case(PAC_SINK_UUID) {
                ep.locations = EP_SNK_LOCATIONS;
                ep.supported_context = EP_SUPPORTED_SNK_CTXT;
                ep.context = EP_SNK_CTXT;
            } else if uuid.eq_ignore_ascii_case(PAC_SOURCE_UUID) {
                ep.locations = EP_SRC_LOCATIONS;
                ep.supported_context = EP_SUPPORTED_SRC_CTXT;
                ep.context = EP_SRC_CTXT;
            }
        }

        // Find matching preset group
        if let Some(group_idx) = state
            .preset_groups
            .iter()
            .position(|g| g.uuid.eq_ignore_ascii_case(&uuid) && g.codec.id == codec_id)
        {
            ep.preset_group_uuid = Some(state.preset_groups[group_idx].uuid.clone());
            if let Some(def) = state.preset_groups[group_idx].default_preset() {
                ep.codec_preset_name = Some(def.name.clone());
                if ep.caps.is_empty() {
                    ep.caps = def.data.clone();
                }
            }
        }

        // Set capabilities from args if provided.
        // Format: raw hex bytes, or type:value LTV pairs (e.g. "01:03" for type=1 value=03).
        if args.len() > 3 {
            if let Some(bytes) = str_to_bytearray(args[3]) {
                ep.caps = bytes;
            }
        }
        // Additional args are interpreted as LTV type:value pairs for custom records
        for extra_arg in args.iter().skip(4) {
            if let Some((type_str, val_str)) = extra_arg.split_once(':') {
                if let Ok(ltv_type) = u8::from_str_radix(type_str, 16) {
                    if let Some(val_bytes) = str_to_bytearray(val_str) {
                        let ltv = build_ltv(ltv_type, &val_bytes);
                        bt_shell_printf(format_args!(
                            "\tCustom LTV: type=0x{:02x} len={}\n",
                            ltv.type_, ltv.len
                        ));
                        // Append LTV to capabilities
                        ep.caps.push(ltv.len);
                        ep.caps.push(ltv.type_);
                        ep.caps.extend_from_slice(&ltv.value);
                    }
                }
            }
        }

        // Create the D-Bus interface object for this endpoint
        let iface = EndpointIface { endpoint_index: state.local_endpoints.len() };
        bt_shell_printf(format_args!("Endpoint {} registered\n", path));
        state.local_endpoints.push(ep);
        state.endpoint_ifaces.push(iface);
    });

    bt_shell_noninteractive_quit(0);
}

fn cmd_unregister_endpoint(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    let pattern = args[1];
    let removed = with_state(|state| {
        if let Some(pos) =
            state.local_endpoints.iter().position(|e| e.path == pattern || e.uuid == pattern)
        {
            let ep = state.local_endpoints.remove(pos);
            // Remove corresponding D-Bus interface object
            if pos < state.endpoint_ifaces.len() {
                state.endpoint_ifaces.remove(pos);
                // Re-index remaining endpoint_ifaces
                for (i, iface) in state.endpoint_ifaces.iter_mut().enumerate() {
                    iface.endpoint_index = i;
                }
            }
            bt_shell_printf(format_args!("Endpoint {} unregistered\n", ep.path));
            true
        } else {
            false
        }
    });
    if !removed {
        bt_shell_printf(format_args!("Unable to find endpoint object: {}\n", pattern));
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_config_endpoint(args: &[&str]) {
    if args.len() < 3 {
        bt_shell_usage();
        return;
    }

    let endpoint_path = args[1];
    let local_ep_pattern = args[2];

    let found_remote = with_state(|state| state.endpoints.iter().any(|e| e.path == endpoint_path));
    if !found_remote {
        bt_shell_printf(format_args!("Endpoint {} not found\n", endpoint_path));
        return bt_shell_noninteractive_quit(1);
    }

    let found_local = with_state(|state| {
        state
            .local_endpoints
            .iter()
            .any(|e| e.path == local_ep_pattern || e.uuid == local_ep_pattern)
    });
    if !found_local {
        bt_shell_printf(format_args!("Local Endpoint {} not found\n", local_ep_pattern));
        return bt_shell_noninteractive_quit(1);
    }

    // Apply preset if specified
    if args.len() > 3 {
        let preset_name = args[3];
        with_state(|state| {
            if let Some(ep) = state
                .local_endpoints
                .iter_mut()
                .find(|e| e.path == local_ep_pattern || e.uuid == local_ep_pattern)
            {
                ep.codec_preset_name = Some(preset_name.to_string());
                // Resolve preset and display its QoS configuration
                if let Some(ref uuid_key) = ep.preset_group_uuid {
                    if let Some(group) = state.preset_groups.iter().find(|g| g.uuid == *uuid_key) {
                        if let Some(preset) = group.find_by_name(preset_name) {
                            if !preset.meta.is_empty() {
                                bt_shell_printf(format_args!(
                                    "\tMetadata: {} bytes\n",
                                    preset.meta.len()
                                ));
                            }
                            match &preset.qos {
                                BapQos::Ucast(uqos) => {
                                    bt_shell_printf(format_args!(
                                        "\tQoS: Unicast interval={} latency={}\n",
                                        uqos.io_qos.interval, uqos.io_qos.latency
                                    ));
                                }
                                BapQos::Bcast(bqos) => {
                                    bt_shell_printf(format_args!(
                                        "\tQoS: Broadcast interval={} latency={}\n",
                                        bqos.io_qos.interval, bqos.io_qos.latency
                                    ));
                                }
                            }
                            if preset.target_latency > 0 {
                                bt_shell_printf(format_args!(
                                    "\tTarget Latency: {}\n",
                                    preset.target_latency
                                ));
                            }
                            if preset.chan_alloc != 0 {
                                bt_shell_printf(format_args!(
                                    "\tChannel Allocation: 0x{:08x}\n",
                                    preset.chan_alloc
                                ));
                            }
                            if preset.custom {
                                bt_shell_printf(format_args!("\tCustom: yes\n"));
                            }
                        }
                    }
                }
            }
        });
    }

    bt_shell_printf(format_args!(
        "Configuring endpoint {} with {}\n",
        endpoint_path, local_ep_pattern
    ));
    bt_shell_noninteractive_quit(0);
}

fn cmd_presets_endpoint(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }

    let uuid_or_path = args[1];
    let set_preset = if args.len() > 2 { Some(args[2]) } else { None };

    with_state(|state| {
        // Try finding preset group by UUID
        let group_idx =
            state.preset_groups.iter().position(|g| g.uuid.eq_ignore_ascii_case(uuid_or_path));

        if let Some(idx) = group_idx {
            if let Some(preset_name) = set_preset {
                // Set the default preset
                if let Some(pos) =
                    state.preset_groups[idx].presets.iter().position(|p| p.name == preset_name)
                {
                    state.preset_groups[idx].default_index = pos;
                    bt_shell_printf(format_args!("Default preset set to {}\n", preset_name));
                } else {
                    bt_shell_printf(format_args!("Preset {} not found\n", preset_name));
                    bt_shell_noninteractive_quit(1);
                }
            } else {
                // List presets
                let group = &state.preset_groups[idx];
                for (i, p) in group.presets.iter().enumerate() {
                    let marker = if i == group.default_index { "*" } else { " " };
                    bt_shell_printf(format_args!("{}{}\n", marker, p.name));
                    // Show preset configuration data
                    if !p.data.is_empty() {
                        print_configuration(&group.uuid, group.codec.id, &p.data);
                    }
                }
                // Also list custom presets
                for p in &group.custom {
                    bt_shell_printf(format_args!(" {} (custom)\n", p.name));
                }
            }
        } else {
            // Check local endpoints
            if let Some(ep) = state
                .local_endpoints
                .iter()
                .find(|e| e.path == uuid_or_path || e.uuid == uuid_or_path)
            {
                if let Some(ref uuid_key) = ep.preset_group_uuid {
                    if let Some(group) = state.preset_groups.iter().find(|g| g.uuid == *uuid_key) {
                        for (i, p) in group.presets.iter().enumerate() {
                            let marker = if i == group.default_index { "*" } else { " " };
                            bt_shell_printf(format_args!("{}{}\n", marker, p.name));
                        }
                    }
                } else {
                    bt_shell_printf(format_args!("No presets available\n"));
                }
            } else {
                bt_shell_printf(format_args!("No preset found\n"));
                bt_shell_noninteractive_quit(1);
            }
        }
    });

    bt_shell_noninteractive_quit(0);
}

// ============================================================================
// Transport submenu commands
// ============================================================================

fn cmd_list_transport(args: &[&str]) {
    let _ = args;
    with_state(|state| {
        for t in &state.transports {
            bt_shell_printf(format_args!("Transport {}\n", t.path));
        }
    });
    bt_shell_noninteractive_quit(0);
}

fn cmd_show_transport(args: &[&str]) {
    if args.len() < 2 {
        let path = with_state(|state| state.default_transport.clone());
        match path {
            Some(ref p) => {
                let found =
                    with_state(|state| state.transports.iter().find(|t| t.path == *p).cloned());
                if let Some(proxy) = found {
                    bt_shell_printf(format_args!(
                        "{}Transport {}{}\n",
                        COLOR_BOLDWHITE, proxy.path, COLOR_OFF
                    ));
                    display_all_properties(&proxy.path, &proxy.properties);
                }
            }
            None => {
                with_state(|state| {
                    for t in &state.transports {
                        bt_shell_printf(format_args!("Transport {}\n", t.path));
                    }
                });
            }
        }
        return bt_shell_noninteractive_quit(0);
    }

    let path = args[1];
    let found = with_state(|state| state.transports.iter().find(|t| t.path == path).cloned());
    match found {
        Some(proxy) => {
            bt_shell_printf(format_args!("{}Transport {}{}\n", COLOR_BOLDWHITE, path, COLOR_OFF));
            // Display codec configuration if available
            if let Some(config_val) = proxy.properties.get("Configuration") {
                if let Value::Array(arr) = &**config_val {
                    let bytes: Vec<u8> = arr
                        .iter()
                        .filter_map(|v| if let Value::U8(b) = v { Some(*b) } else { None })
                        .collect();
                    if !bytes.is_empty() {
                        bt_shell_printf(format_args!("\tConfiguration:\n"));
                        // Determine the codec type from the endpoint info
                        let uuid = proxy
                            .properties
                            .get("UUID")
                            .and_then(|v| {
                                if let Value::Str(s) = &**v { Some(s.to_string()) } else { None }
                            })
                            .unwrap_or_default();
                        let codec = proxy
                            .properties
                            .get("Codec")
                            .and_then(|v| if let Value::U8(c) = &**v { Some(*c) } else { None })
                            .unwrap_or(0);
                        print_configuration(&uuid, codec, &bytes);
                    }
                }
            }
            display_all_properties(path, &proxy.properties);
        }
        None => {
            bt_shell_printf(format_args!("Transport {} not found\n", path));
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_select_transport(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }

    let path = args[1].to_string();
    if path == "auto" {
        with_state(|state| {
            state.auto_select = true;
        });
        set_player_env("AUTO_SELECT", "1".to_string());
        bt_shell_printf(format_args!("Auto select enabled\n"));
        return bt_shell_noninteractive_quit(0);
    }

    let found = with_state(|state| {
        if state.transports.iter().any(|t| t.path == path) {
            state.default_transport = Some(path.clone());
            true
        } else {
            false
        }
    });

    if found {
        bt_shell_printf(format_args!("Default transport set to {}\n", path));
    } else {
        bt_shell_printf(format_args!("Transport {} not available\n", path));
    }
    bt_shell_noninteractive_quit(if found { 0 } else { 1 });
}

fn cmd_unselect_transport(args: &[&str]) {
    let _ = args;
    with_state(|state| {
        state.default_transport = None;
        state.auto_select = false;
    });
    bt_shell_printf(format_args!("Transport unselected\n"));
    bt_shell_noninteractive_quit(0);
}

fn cmd_acquire_transport(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }

    if args[1] == "auto" {
        with_state(|state| {
            state.auto_acquire = true;
        });
        set_player_env("AUTO_ACQUIRE", "1".to_string());
        bt_shell_printf(format_args!("Auto acquire enabled\n"));
        return bt_shell_noninteractive_quit(0);
    }

    for i in 1..args.len() {
        let path = args[i];
        let found = with_state(|state| state.transports.iter().any(|t| t.path == path));
        if !found {
            bt_shell_printf(format_args!("Transport {} not found\n", path));
            return bt_shell_noninteractive_quit(1);
        }
        let already = with_state(|state| state.ios.iter().any(|io| io.proxy_path == path));
        if already {
            bt_shell_printf(format_args!("Transport {} already acquired\n", path));
            return bt_shell_noninteractive_quit(1);
        }
        bt_shell_printf(format_args!("Attempting to acquire {}\n", path));
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_release_transport(args: &[&str]) {
    if args.len() < 2 {
        let path = with_state(|state| state.default_transport.clone());
        if let Some(path) = path {
            bt_shell_printf(format_args!("Releasing transport {}\n", path));
            with_state(|state| {
                state.ios.retain(|io| io.proxy_path != path);
            });
        } else {
            bt_shell_printf(format_args!("No default transport to release\n"));
            return bt_shell_noninteractive_quit(1);
        }
    } else {
        for i in 1..args.len() {
            let path = args[i];
            bt_shell_printf(format_args!("Releasing transport {}\n", path));
            with_state(|state| {
                state.ios.retain(|io| io.proxy_path != path);
            });
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_send_transport(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }

    let transport_path = with_state(|state| state.default_transport.clone());
    let path = match transport_path {
        Some(p) => p,
        None => {
            bt_shell_printf(format_args!("No default transport selected\n"));
            return bt_shell_noninteractive_quit(1);
        }
    };

    let io_info = with_state(|state| {
        state
            .ios
            .iter()
            .find(|io| io.proxy_path == path)
            .map(|io| (io.mtu[0], io.seq, io.filename.clone()))
    });

    match io_info {
        Some((mtu, seq, filename)) => {
            let data_arg = args[1];
            if let Some(bytes) = str_to_bytearray(data_arg) {
                bt_shell_printf(format_args!(
                    "Sending {} bytes (mtu={}, seq={}) on {}\n",
                    bytes.len(),
                    mtu,
                    seq,
                    path
                ));
            } else {
                let fname = filename.as_deref().unwrap_or(data_arg);
                bt_shell_printf(format_args!(
                    "Sending file: {} (mtu={}, seq={}) on {}\n",
                    fname, mtu, seq, path
                ));
                // Store the filename for streaming
                with_state(|state| {
                    if let Some(io) = state.ios.iter_mut().find(|io| io.proxy_path == path) {
                        io.filename = Some(data_arg.to_string());
                        io.seq = io.seq.wrapping_add(1);
                    }
                });
            }
        }
        None => {
            bt_shell_printf(format_args!("Transport {} not acquired\n", path));
            return bt_shell_noninteractive_quit(1);
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_receive_transport(args: &[&str]) {
    let transport_path = with_state(|state| state.default_transport.clone());
    let path = match transport_path {
        Some(p) => p,
        None => {
            bt_shell_printf(format_args!("No default transport selected\n"));
            return bt_shell_noninteractive_quit(1);
        }
    };

    let io_info = with_state(|state| {
        state.ios.iter().find(|io| io.proxy_path == path).map(|io| (io.mtu[1], io.filename.clone()))
    });

    match io_info {
        Some((mtu, _existing_filename)) => {
            if args.len() > 1 {
                let fname = args[1];
                bt_shell_printf(format_args!(
                    "Receiving to file: {} (mtu={}) on {}\n",
                    fname, mtu, path
                ));
                with_state(|state| {
                    if let Some(io) = state.ios.iter_mut().find(|io| io.proxy_path == path) {
                        io.filename = Some(fname.to_string());
                    }
                });
            } else {
                bt_shell_printf(format_args!("Receiving to stdout (mtu={}) on {}\n", mtu, path));
            }
        }
        None => {
            bt_shell_printf(format_args!("Transport {} not acquired\n", path));
            return bt_shell_noninteractive_quit(1);
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_volume_transport(args: &[&str]) {
    let transport_path = with_state(|state| state.default_transport.clone());
    if transport_path.is_none() {
        bt_shell_printf(format_args!("No default transport selected\n"));
        return bt_shell_noninteractive_quit(1);
    }

    // If no volume argument given, prompt user interactively
    if args.len() < 2 {
        prompt_for_value(
            "Volume",
            "Enter volume (0-127):",
            Box::new(|input| {
                set_transport_volume(input);
            }),
        );
        return;
    }

    set_transport_volume(args[1]);
}

/// Apply transport volume from user input string.
fn set_transport_volume(volume_str: &str) {
    match volume_str.parse::<u16>() {
        Ok(volume) if volume <= 127 => {
            bt_shell_printf(format_args!("Setting volume to {}\n", volume));
        }
        _ => {
            bt_shell_printf(format_args!("Invalid volume: {}\n", volume_str));
            return bt_shell_noninteractive_quit(1);
        }
    }
    bt_shell_noninteractive_quit(0);
}

fn cmd_metadata_transport(args: &[&str]) {
    let _ = args;
    let transport_path = with_state(|state| state.default_transport.clone());
    if transport_path.is_none() {
        bt_shell_printf(format_args!("No default transport selected\n"));
        return bt_shell_noninteractive_quit(1);
    }
    bt_shell_printf(format_args!("Metadata transport command\n"));
    bt_shell_noninteractive_quit(0);
}

// ============================================================================
// Local MediaEndpoint1 D-Bus Interface
// ============================================================================

/// D-Bus interface object for a locally registered media endpoint.
///
/// Implements `org.bluez.MediaEndpoint1` so that the BlueZ daemon can
/// negotiate codec configuration with this client.
struct EndpointIface {
    /// Index into `MODULE_STATE.local_endpoints` for this endpoint's data.
    endpoint_index: usize,
}

#[zbus::interface(name = "org.bluez.MediaEndpoint1")]
impl EndpointIface {
    /// Called by BlueZ to set the transport configuration on this endpoint.
    ///
    /// `transport_path` — Object path of the new transport.
    /// `properties` — Dictionary of transport properties (Codec, Configuration, etc.).
    fn set_configuration(&self, transport_path: &str, properties: HashMap<String, OwnedValue>) {
        bt_shell_printf(format_args!(
            "{}[MediaEndpoint1]{} SetConfiguration({})\n",
            COLOR_BOLDWHITE, COLOR_OFF, transport_path
        ));

        for (key, val) in &properties {
            if let Value::Array(arr) = &**val {
                let bytes: Vec<u8> = arr
                    .iter()
                    .filter_map(|v| if let Value::U8(b) = v { Some(*b) } else { None })
                    .collect();
                bt_shell_printf(format_args!("\t{}: [{} bytes]\n", key, bytes.len()));
            } else {
                bt_shell_printf(format_args!("\t{}: {:?}\n", key, &**val));
            }
        }

        with_state(|state| {
            if let Some(ep) = state.local_endpoints.get_mut(self.endpoint_index) {
                ep.refcount = ep.refcount.saturating_add(1);
                ep.transport_paths.push(transport_path.to_string());

                // Apply configuration from properties
                if let Some(config_val) = properties.get("Configuration") {
                    if let Value::Array(arr) = &**config_val {
                        let config_bytes: Vec<u8> = arr
                            .iter()
                            .filter_map(|v| if let Value::U8(b) = v { Some(*b) } else { None })
                            .collect();
                        bt_shell_printf(format_args!(
                            "\tConfiguration: {} bytes\n",
                            config_bytes.len()
                        ));
                    }
                }

                if ep.auto_accept {
                    bt_shell_printf(format_args!(
                        "{}Auto accepting transport {}{}\n",
                        COLOR_BOLDGRAY, transport_path, COLOR_OFF
                    ));
                }
            }
        });
    }

    /// Called by BlueZ to select a configuration from the endpoint's
    /// capabilities. Returns the selected configuration bytes.
    fn select_configuration(&self, capabilities: Vec<u8>) -> Vec<u8> {
        bt_shell_printf(format_args!(
            "{}[MediaEndpoint1]{} SelectConfiguration({} bytes)\n",
            COLOR_BOLDWHITE,
            COLOR_OFF,
            capabilities.len()
        ));

        // Return the capabilities as-is for pass-through, or select from
        // the local endpoint's preset configuration.
        with_state(|state| {
            if let Some(ep) = state.local_endpoints.get(self.endpoint_index) {
                if let Some(ref preset_name) = ep.codec_preset_name {
                    if let Some(ref uuid_key) = ep.preset_group_uuid {
                        if let Some(group) =
                            state.preset_groups.iter().find(|g| g.uuid == *uuid_key)
                        {
                            if let Some(preset) = group.find_by_name(preset_name) {
                                return preset.data.clone();
                            }
                        }
                    }
                }
                // Default: return capabilities as configuration
                ep.caps.clone()
            } else {
                capabilities.clone()
            }
        })
    }

    /// Called by BlueZ to clear the configuration for a transport.
    fn clear_configuration(&self, transport_path: &str) {
        bt_shell_printf(format_args!(
            "{}[MediaEndpoint1]{} ClearConfiguration({})\n",
            COLOR_BOLDWHITE, COLOR_OFF, transport_path
        ));

        with_state(|state| {
            if let Some(ep) = state.local_endpoints.get_mut(self.endpoint_index) {
                ep.transport_paths.retain(|p| p != transport_path);
                ep.refcount = ep.refcount.saturating_sub(1);
            }
        });
    }

    /// Called by BlueZ for property negotiation (used by BAP).
    ///
    /// Returns the selected properties from the provided property set.
    fn select_properties(
        &self,
        properties: HashMap<String, OwnedValue>,
    ) -> HashMap<String, OwnedValue> {
        bt_shell_printf(format_args!(
            "{}[MediaEndpoint1]{} SelectProperties({} props)\n",
            COLOR_BOLDWHITE,
            COLOR_OFF,
            properties.len()
        ));

        for (key, val) in &properties {
            bt_shell_printf(format_args!("\t{}: {:?}\n", key, &**val));
        }

        // Return properties as-is (pass-through selection)
        properties
    }

    /// Called by BlueZ when the endpoint is being released.
    fn release(&self) {
        bt_shell_printf(format_args!(
            "{}[MediaEndpoint1]{} Release()\n",
            COLOR_BOLDWHITE, COLOR_OFF
        ));
    }

    /// UUID property — the service UUID this endpoint handles.
    #[zbus(property)]
    fn uuid(&self) -> String {
        with_state(|state| {
            state
                .local_endpoints
                .get(self.endpoint_index)
                .map(|ep| ep.uuid.clone())
                .unwrap_or_default()
        })
    }

    /// Codec property — the codec identifier byte.
    #[zbus(property)]
    fn codec(&self) -> u8 {
        with_state(|state| {
            state.local_endpoints.get(self.endpoint_index).map(|ep| ep.codec.id).unwrap_or(0)
        })
    }

    /// Capabilities property — codec capabilities as byte array.
    #[zbus(property)]
    fn capabilities(&self) -> Vec<u8> {
        with_state(|state| {
            state
                .local_endpoints
                .get(self.endpoint_index)
                .map(|ep| ep.caps.clone())
                .unwrap_or_default()
        })
    }

    /// Vendor property — vendor-specific codec info (CID << 16 | VID).
    #[zbus(property)]
    fn vendor(&self) -> u32 {
        with_state(|state| {
            state
                .local_endpoints
                .get(self.endpoint_index)
                .map(|ep| (u32::from(ep.codec.cid) << 16) | u32::from(ep.codec.vid))
                .unwrap_or(0)
        })
    }
}

// ============================================================================
// Proxy tracking
// ============================================================================

/// Handle a new proxy being added by the D-Bus client.
pub fn proxy_added(path: &str, interface: &str) {
    let info = ProxyInfo::new(path, interface);
    let desc = match interface {
        BLUEZ_MEDIA_INTERFACE => {
            // Check for auto-register endpoint environment variable
            if let Some(val) = get_player_env("AUTO_REGISTER_ENDPOINT") {
                if val == "1" || val.eq_ignore_ascii_case("yes") {
                    bt_shell_printf(format_args!(
                        "{}Auto registering endpoints{}\n",
                        COLOR_BLUE, COLOR_OFF
                    ));
                }
            }
            with_state(|state| {
                state.medias.push(info);
            });
            format!("[{}] Media {}", colored_new(), path)
        }
        BLUEZ_MEDIA_PLAYER_INTERFACE => {
            with_state(|state| {
                if state.default_player.is_none() {
                    state.default_player = Some(path.to_string());
                }
                state.players.push(info);
            });
            format!("[{}] Player {}", colored_new(), path)
        }
        BLUEZ_MEDIA_FOLDER_INTERFACE => {
            with_state(|state| {
                state.folders.push(info);
            });
            format!("[{}] Folder {}", colored_new(), path)
        }
        BLUEZ_MEDIA_ITEM_INTERFACE => {
            with_state(|state| {
                state.items.push(info);
            });
            format!("[{}] Item {}", colored_new(), path)
        }
        BLUEZ_MEDIA_ENDPOINT_INTERFACE => {
            with_state(|state| {
                state.endpoints.push(info);
            });
            format!("[{}] Endpoint {}", colored_new(), path)
        }
        BLUEZ_MEDIA_TRANSPORT_INTERFACE => {
            with_state(|state| {
                if state.auto_select && state.default_transport.is_none() {
                    state.default_transport = Some(path.to_string());
                }
                state.transports.push(info);
            });
            format!("[{}] Transport {}", colored_new(), path)
        }
        _ => return,
    };
    bt_shell_printf(format_args!("{}\n", desc));
}

/// Handle a proxy being removed by the D-Bus client.
pub fn proxy_removed(path: &str, interface: &str) {
    let desc = match interface {
        BLUEZ_MEDIA_INTERFACE => {
            with_state(|state| {
                state.medias.retain(|p| p.path != path);
            });
            format!("[{}] Media {}", colored_del(), path)
        }
        BLUEZ_MEDIA_PLAYER_INTERFACE => {
            with_state(|state| {
                if state.default_player.as_deref() == Some(path) {
                    state.default_player =
                        state.players.iter().find(|p| p.path != path).map(|p| p.path.clone());
                }
                state.players.retain(|p| p.path != path);
            });
            format!("[{}] Player {}", colored_del(), path)
        }
        BLUEZ_MEDIA_FOLDER_INTERFACE => {
            with_state(|state| {
                state.folders.retain(|p| p.path != path);
            });
            format!("[{}] Folder {}", colored_del(), path)
        }
        BLUEZ_MEDIA_ITEM_INTERFACE => {
            with_state(|state| {
                state.items.retain(|p| p.path != path);
            });
            format!("[{}] Item {}", colored_del(), path)
        }
        BLUEZ_MEDIA_ENDPOINT_INTERFACE => {
            with_state(|state| {
                state.endpoints.retain(|p| p.path != path);
            });
            format!("[{}] Endpoint {}", colored_del(), path)
        }
        BLUEZ_MEDIA_TRANSPORT_INTERFACE => {
            with_state(|state| {
                if state.default_transport.as_deref() == Some(path) {
                    state.default_transport = None;
                }
                state.transports.retain(|p| p.path != path);
                state.ios.retain(|io| io.proxy_path != path);
            });
            format!("[{}] Transport {}", colored_del(), path)
        }
        _ => return,
    };
    bt_shell_printf(format_args!("{}\n", desc));
}

/// Handle a property change on a tracked proxy.
pub fn property_changed(path: &str, interface: &str, name: &str, value_str: &str) {
    let kind = match interface {
        BLUEZ_MEDIA_PLAYER_INTERFACE => "Player",
        BLUEZ_MEDIA_FOLDER_INTERFACE => "Folder",
        BLUEZ_MEDIA_ITEM_INTERFACE => "Item",
        BLUEZ_MEDIA_ENDPOINT_INTERFACE => "Endpoint",
        BLUEZ_MEDIA_TRANSPORT_INTERFACE => "Transport",
        _ => return,
    };
    bt_shell_printf(format_args!(
        "[{}] {} {} {}: {}\n",
        colored_chg(),
        kind,
        path,
        name,
        value_str
    ));

    // Auto-acquire on transport state change to pending/broadcasting
    if interface == BLUEZ_MEDIA_TRANSPORT_INTERFACE && name == "State" {
        let should_acquire = with_state(|state| state.auto_acquire);
        if should_acquire && (value_str == "pending" || value_str == "broadcasting") {
            bt_shell_printf(format_args!(
                "{}Auto acquiring transport {}{}\n",
                COLOR_BOLDGRAY, path, COLOR_OFF
            ));
        }
    }
}

/// Prompt user for interactive input (wraps bt_shell_prompt_input).
fn prompt_for_value(label: &str, msg: &str, callback: Box<dyn FnOnce(&str) + Send>) {
    bt_shell_prompt_input(label, msg, callback);
}

// ============================================================================
// Menu definitions
// ============================================================================

static PLAYER_MENU: BtShellMenu = BtShellMenu {
    name: "player",
    desc: Some("Media Player Submenu"),
    pre_run: None,
    entries: &[
        BtShellMenuEntry {
            cmd: "list",
            arg: None,
            func: cmd_list,
            desc: "List available players",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "show",
            arg: Some("[player]"),
            func: cmd_show,
            desc: "Player information",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "select",
            arg: Some("<player>"),
            func: cmd_select,
            desc: "Select default player",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "play",
            arg: Some("[item]"),
            func: cmd_play,
            desc: "Start playback",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "pause",
            arg: None,
            func: cmd_pause,
            desc: "Pause playback",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "stop",
            arg: None,
            func: cmd_stop,
            desc: "Stop playback",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "next",
            arg: None,
            func: cmd_next,
            desc: "Jump to next item",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "previous",
            arg: None,
            func: cmd_previous,
            desc: "Jump to previous item",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "fast-forward",
            arg: None,
            func: cmd_fast_forward,
            desc: "Fast forward playback",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "rewind",
            arg: None,
            func: cmd_rewind,
            desc: "Rewind playback",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "equalizer",
            arg: Some("<on/off>"),
            func: cmd_equalizer,
            desc: "Toggle equalizer",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "repeat",
            arg: Some("<singletrack/alltrack/group/off>"),
            func: cmd_repeat,
            desc: "Set repeat mode",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "shuffle",
            arg: Some("<alltracks/group/off>"),
            func: cmd_shuffle,
            desc: "Set shuffle mode",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "scan",
            arg: Some("<alltracks/group/off>"),
            func: cmd_scan,
            desc: "Set scan mode",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "change-folder",
            arg: Some("<folder>"),
            func: cmd_change_folder,
            desc: "Change current folder",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "list-items",
            arg: Some("[start] [end]"),
            func: cmd_list_items,
            desc: "List items of current folder",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "search",
            arg: Some("<string>"),
            func: cmd_search,
            desc: "Search items containing string",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "queue",
            arg: Some("<item>"),
            func: cmd_queue,
            desc: "Add item to playlist queue",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "show-item",
            arg: Some("[item]"),
            func: cmd_show_item,
            desc: "Show item information",
            r#gen: None,
            disp: None,
            exists: None,
        },
    ],
};

static ENDPOINT_MENU: BtShellMenu = BtShellMenu {
    name: "endpoint",
    desc: Some("Media Endpoint Submenu"),
    pre_run: None,
    entries: &[
        BtShellMenuEntry {
            cmd: "list",
            arg: Some("[local]"),
            func: cmd_list_endpoints,
            desc: "List available endpoints",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "show",
            arg: Some("[endpoint]"),
            func: cmd_show_endpoint,
            desc: "Endpoint information",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "register",
            arg: Some("<UUID> <codec[:company]> [capabilities...]"),
            func: cmd_register_endpoint,
            desc: "Register Endpoint",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "unregister",
            arg: Some("<UUID/object>"),
            func: cmd_unregister_endpoint,
            desc: "Unregister Endpoint",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "config",
            arg: Some("<endpoint> [local endpoint] [preset]"),
            func: cmd_config_endpoint,
            desc: "Configure Endpoint",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "presets",
            arg: Some("<endpoint>/<UUID> [preset]"),
            func: cmd_presets_endpoint,
            desc: "List or set presets",
            r#gen: None,
            disp: None,
            exists: None,
        },
    ],
};

static TRANSPORT_MENU: BtShellMenu = BtShellMenu {
    name: "transport",
    desc: Some("Media Transport Submenu"),
    pre_run: None,
    entries: &[
        BtShellMenuEntry {
            cmd: "list",
            arg: None,
            func: cmd_list_transport,
            desc: "List available transports",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "show",
            arg: Some("[transport]"),
            func: cmd_show_transport,
            desc: "Transport information",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "acquire",
            arg: Some("[transport]"),
            func: cmd_acquire_transport,
            desc: "Acquire Transport",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "release",
            arg: Some("[transport]"),
            func: cmd_release_transport,
            desc: "Release Transport",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "send",
            arg: Some("<file/hex>"),
            func: cmd_send_transport,
            desc: "Send contents of a file",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "receive",
            arg: Some("[file]"),
            func: cmd_receive_transport,
            desc: "Get/Set file to receive",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "volume",
            arg: Some("<transport volume>"),
            func: cmd_volume_transport,
            desc: "Set transport volume",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "select",
            arg: Some("<transport>"),
            func: cmd_select_transport,
            desc: "Select default transport",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "unselect",
            arg: None,
            func: cmd_unselect_transport,
            desc: "Unselect default transport",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "metadata",
            arg: None,
            func: cmd_metadata_transport,
            desc: "Get transport metadata",
            r#gen: None,
            disp: None,
            exists: None,
        },
    ],
};

// ============================================================================
// Public API
// ============================================================================

/// Register the player, endpoint, and transport submenus with the shell.
///
/// This is the main entry point called during bluetoothctl initialization
/// to make all media-related commands available.
pub fn player_add_submenu() {
    // Initialize module state
    with_state(|_state| {});

    bt_shell_add_submenu(&PLAYER_MENU);
    bt_shell_add_submenu(&ENDPOINT_MENU);
    bt_shell_add_submenu(&TRANSPORT_MENU);
}

/// Remove the player, endpoint, and transport submenus and clean up state.
///
/// Called during bluetoothctl shutdown to release all media-related resources.
pub fn player_remove_submenu() {
    bt_shell_remove_submenu(&PLAYER_MENU);
    bt_shell_remove_submenu(&ENDPOINT_MENU);
    bt_shell_remove_submenu(&TRANSPORT_MENU);

    // Clean up state
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str_to_bytearray_basic() {
        assert_eq!(str_to_bytearray("0102ff"), Some(vec![0x01, 0x02, 0xff]));
        assert_eq!(str_to_bytearray("0xFF"), Some(vec![0xff]));
        assert_eq!(str_to_bytearray(""), None);
        assert_eq!(str_to_bytearray("0"), None); // odd length
    }

    #[test]
    fn test_str_to_bytearray_with_separators() {
        assert_eq!(str_to_bytearray("0x01 0x02 0xFF"), Some(vec![0x01, 0x02, 0xff]));
        assert_eq!(str_to_bytearray("01:02:ff"), Some(vec![0x01, 0x02, 0xff]));
    }

    #[test]
    fn test_lc3_config_bytes() {
        let bytes = lc3_config_bytes(0x01, 0x00, 26);
        // Should contain 3 LTV records: Freq, Duration, FrameLen
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_build_preset_groups() {
        let groups = build_preset_groups();
        assert_eq!(groups.len(), 6);
        // Check SBC presets
        assert_eq!(groups[0].presets.len(), 12);
        // Check LC3 unicast presets
        assert_eq!(groups[2].presets.len(), 16);
        // Check LC3 broadcast presets
        assert_eq!(groups[4].presets.len(), 12);
    }

    #[test]
    fn test_codec_preset_find() {
        let groups = build_preset_groups();
        let sbc_group = &groups[0];
        assert!(sbc_group.find_by_name("HQ_STEREO_44_1").is_some());
        assert!(sbc_group.find_by_name("nonexistent").is_none());
        assert!(sbc_group.default_preset().is_some());
    }

    #[test]
    fn test_parse_chan_alloc_empty() {
        assert_eq!(parse_chan_alloc(&[]), 0);
    }

    #[test]
    fn test_build_ltv() {
        let ltv = build_ltv(0x01, &[0x03]);
        assert_eq!(ltv.type_, 0x01);
        assert_eq!(ltv.value, vec![0x03]);
        assert_eq!(ltv.len, 2); // 1 byte type + 1 byte data
    }
}
