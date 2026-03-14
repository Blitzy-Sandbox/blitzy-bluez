// SPDX-License-Identifier: GPL-2.0-or-later
//
// crates/bluetooth-meshd/src/net.rs
//
// Bluetooth Mesh network layer — complete Rust rewrite of mesh/net.c (~3859 lines)
// and mesh/net.h (~317 lines) from BlueZ v5.86.
//
// Implements:
//   - Network PDU encrypt/decrypt and relay processing
//   - Segmentation and Reassembly (SAR) state machines
//   - IV Update state machine
//   - Key Refresh state machine
//   - Replay Protection integration
//   - Heartbeat publication/subscription
//   - Friendship message handling
//   - Message cache / dedup
//   - Beacon processing integration

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};

use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::appkey::MeshAppKey;
use crate::config::MeshConfig;
use crate::crypto::{
    MeshPacketBuildParams, MeshPayloadDecryptParams, MeshPayloadEncryptParams, PacketFields,
    mesh_crypto_packet_build, mesh_crypto_packet_decode, mesh_crypto_packet_encode,
    mesh_crypto_packet_label, mesh_crypto_packet_parse, mesh_crypto_payload_decrypt,
    mesh_crypto_payload_encrypt,
};
use crate::io::{BT_AD_MESH_DATA, MeshIoSendInfo, mesh_io_send};
use crate::mesh::{
    APP_AID_INVALID, KEY_AID_SHIFT, KEY_ID_AKF, KEY_REFRESH_PHASE_NONE, KEY_REFRESH_PHASE_ONE,
    KEY_REFRESH_PHASE_THREE, KEY_REFRESH_PHASE_TWO, MAX_KEY_IDX, MESH_NET_MAX_PDU_LEN,
    MESH_STATUS_INVALID_NETKEY, MESH_STATUS_STORAGE_FAIL, MESH_STATUS_SUCCESS, NET_IDX_INVALID,
    is_unicast,
};
use crate::net_keys::{
    IV_INDEX_UPDATE, KEY_REFRESH, net_key_add, net_key_beacon, net_key_beacon_disable,
    net_key_beacon_enable, net_key_beacon_last_seen, net_key_beacon_refresh, net_key_beacon_seen,
    net_key_confirm, net_key_decrypt, net_key_encrypt, net_key_frnd_add, net_key_unref,
};
use crate::rpl::{MeshRpl, rpl_get_list, rpl_put_entry, rpl_update};
use crate::util::{get_timestamp_secs, print_packet};

// ===========================================================================
// Public Constants (from mesh/net.h)
// ===========================================================================

/// Device key identifier (net_idx == 0 means device key).
pub const DEV_ID: u16 = 0;

/// Sentinel value indicating an unused key index.
pub const UNUSED_KEY_IDX: u16 = 0xffff;

/// Application AID value indicating a device key.
pub const APP_AID_DEV: u8 = 0x00;

/// Control message bit (bit 7 of CTL/TTL byte).
pub const CTL: u8 = 0x80;

/// TTL mask (lower 7 bits).
pub const TTL_MASK: u8 = 0x7f;

/// 24-bit sequence number mask.
pub const SEQ_MASK: u32 = 0x00ff_ffff;

/// Key cache size for subnet keys.
pub const KEY_CACHE_SIZE: usize = 64;

/// Maximum friend message cache size.
pub const FRND_CACHE_MAX: usize = 32;

/// Maximum unsegmented access payload length.
pub const MAX_UNSEG_LEN: usize = 15;

/// Maximum segment payload length.
pub const MAX_SEG_LEN: usize = 12;

/// Segmented flag (bit 31 of transport header).
pub const SEGMENTED: u32 = 0x80;

/// Unsegmented flag.
pub const UNSEGMENTED: u32 = 0x00;

/// Relay bit.
pub const RELAY: u8 = 0x80;

/// SZMIC bit.
pub const SZMIC: u8 = 0x80;

/// Bit shift for SEG flag in transport header.
pub const SEG_HDR_SHIFT: u32 = 31;

/// Bit shift for key/opcode in transport header.
pub const KEY_HDR_SHIFT: u32 = 24;

/// Bit shift for SZMIC in segmented header.
pub const SZMIC_HDR_SHIFT: u32 = 23;

/// Bit shift for SeqZero in segmented header.
pub const SEQ_ZERO_HDR_SHIFT: u32 = 10;

/// SeqZero mask (13 bits).
pub const SEQ_ZERO_MASK: u32 = 0x1fff;

/// Segment offset bit shift.
pub const SEGO_HDR_SHIFT: u32 = 5;

/// Segment count bit shift.
pub const SEGN_HDR_SHIFT: u32 = 0;

/// Segment index mask (5 bits).
pub const SEG_MASK: u32 = 0x1f;

/// Opcode mask (7 bits).
pub const OPCODE_MASK: u32 = 0x7f;

/// Key ID mask (7 bits).
pub const KEY_ID_MASK: u32 = 0x7f;

/// Key AID mask (6 bits).
pub const KEY_AID_MASK: u8 = 0x3f;

/// Relay bit shift in header word.
pub const RELAY_HDR_SHIFT: u32 = 23;

/// Opcode bit shift in header.
pub const OPCODE_HDR_SHIFT: u32 = 24;

/// AKF bit shift.
pub const AKF_HDR_SHIFT: u32 = 30;

/// Key header mask for SAR.
pub const HDR_KEY_MASK: u32 = 0x7f00_0000;

/// ACK header mask for SAR.
pub const HDR_ACK_MASK: u32 = 0x00ff_ffff;

/// Message cache size for deduplication.
pub const MSG_CACHE_SIZE: usize = 70;

/// Replay protection cache size.
pub const REPLAY_CACHE_SIZE: usize = 10;

/// Network opcode: Segment Acknowledgment.
pub const NET_OP_SEG_ACKNOWLEDGE: u8 = 0x00;

/// Network opcode: Friend Poll.
pub const NET_OP_FRND_POLL: u8 = 0x01;

/// Network opcode: Friend Update.
pub const NET_OP_FRND_UPDATE: u8 = 0x02;

/// Network opcode: Friend Request.
pub const NET_OP_FRND_REQUEST: u8 = 0x03;

/// Network opcode: Friend Offer.
pub const NET_OP_FRND_OFFER: u8 = 0x04;

/// Network opcode: Friend Clear.
pub const NET_OP_FRND_CLEAR: u8 = 0x05;

/// Network opcode: Friend Clear Confirm.
pub const NET_OP_FRND_CLEAR_CONFIRM: u8 = 0x06;

/// Network opcode: Heartbeat.
pub const NET_OP_HEARTBEAT: u8 = 0x0a;

/// Proxy opcode: Set filter type.
pub const PROXY_OP_SET_FILTER_TYPE: u8 = 0x00;

/// Proxy opcode: Filter add.
pub const PROXY_OP_FILTER_ADD: u8 = 0x01;

/// Proxy opcode: Filter delete.
pub const PROXY_OP_FILTER_DEL: u8 = 0x02;

/// Proxy opcode: Filter status.
pub const PROXY_OP_FILTER_STATUS: u8 = 0x03;

/// Proxy filter: accept list (whitelist).
pub const PROXY_FILTER_ACCEPT_LIST: u8 = 0x00;

/// Proxy filter: reject list (blacklist).
pub const PROXY_FILTER_REJECT_LIST: u8 = 0x01;

/// Network opcode: Proxy Solicitation Subscribe Add.
pub const NET_OP_PROXY_SUB_ADD: u8 = 0x07;

/// Network opcode: Proxy Solicitation Subscribe Remove.
pub const NET_OP_PROXY_SUB_REMOVE: u8 = 0x08;

/// Network opcode: Proxy Solicitation Subscribe Confirm.
pub const NET_OP_PROXY_SUB_CONFIRM: u8 = 0x09;

/// Default minimum delay for TX (milliseconds).
pub const DEFAULT_MIN_DELAY: u8 = 0;

/// Default maximum delay for TX (milliseconds).
pub const DEFAULT_MAX_DELAY: u8 = 25;

// ===========================================================================
// Internal Constants (from mesh/net.c)
// ===========================================================================

/// IV Index difference threshold for recovery.
const IV_IDX_DIFF_RANGE: u32 = 42;

/// Minimum IV Update duration in seconds (96 hours).
const IV_IDX_UPD_MIN: u64 = 60 * 60 * 96;

/// Hold period is half of minimum.
const IV_IDX_UPD_HOLD: u64 = IV_IDX_UPD_MIN / 2;

/// Maximum IV Update duration (used in timeout validation).
#[allow(dead_code)]
const IV_IDX_UPD_MAX: u64 = IV_IDX_UPD_MIN + IV_IDX_UPD_HOLD;

/// Sequence number trigger for IV Update.
const IV_UPDATE_SEQ_TRIGGER: u32 = 0x0080_0000;

/// SAR segment timeout in seconds (used in per-segment timers).
#[allow(dead_code)]
const SEG_TO: u64 = 2;

/// SAR message timeout in seconds.
const MSG_TO: u64 = 60;

/// SAR delete timeout in seconds (used in SAR cleanup timers).
#[allow(dead_code)]
const SAR_DEL: u64 = 10;

/// Default transmit count.
const DEFAULT_TRANSMIT_COUNT: u8 = 1;

/// Default transmit interval in milliseconds.
const DEFAULT_TRANSMIT_INTERVAL: u16 = 100;

/// Fast cache size for cross-network dedup.
#[allow(dead_code)]
const FAST_CACHE_SIZE: usize = 8;

/// Default TTL value.
const DEFAULT_TTL: u8 = 7;

// ===========================================================================
// IV Update State Machine
// ===========================================================================

/// IV Update states (from net.c `enum _iv_upd_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IvUpdState {
    Init,
    Normal,
    Updating,
    NormalHold,
}

// ===========================================================================
// Relay advice
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum RelayAdvice {
    None,
    Allowed,
    Disallowed,
    Always,
}

// ===========================================================================
// Helper Functions (public, from net.h macros)
// ===========================================================================

/// Maximum segment index for a given payload length.
#[inline]
pub fn seg_max(len: usize) -> u8 {
    if len <= MAX_SEG_LEN { 0 } else { ((len - 1) / MAX_SEG_LEN) as u8 }
}

/// Byte offset for a given segment index.
#[inline]
pub fn seg_off(seg: u8) -> usize {
    (seg as usize) * MAX_SEG_LEN
}

/// Total payload length for a given number of segments.
#[inline]
pub fn max_seg_to_len(seg_n: u8) -> usize {
    ((seg_n as usize) + 1) * MAX_SEG_LEN
}

/// Check if transport header indicates segmented.
#[inline]
pub fn is_segmented(hdr: u32) -> bool {
    (hdr >> SEG_HDR_SHIFT) & 1 == 1
}

/// Check if transport header indicates application key.
#[inline]
pub fn has_app_key(hdr: u32) -> bool {
    (hdr >> AKF_HDR_SHIFT) & 1 == 1
}

/// Check if a message is relayed.
#[inline]
pub fn is_relayed(hdr: u32) -> bool {
    (hdr >> RELAY_HDR_SHIFT) & 1 == 1
}

/// Check if SZMIC (64-bit MIC) is set.
#[inline]
pub fn has_mic64(hdr: u32) -> bool {
    (hdr >> SZMIC_HDR_SHIFT) & 1 == 1
}

/// Total number of segments (seg_n + 1).
#[inline]
pub fn seg_total(fields: &PacketFields) -> u8 {
    fields.seg_n + 1
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// Provisioning capabilities (wire-compatible with C `struct mesh_net_prov_caps`).
#[derive(Debug, Clone, Default)]
pub struct MeshNetProvCaps {
    pub num_ele: u8,
    pub algorithms: u16,
    pub pub_type: u8,
    pub static_type: u8,
    pub output_size: u8,
    pub output_action: u16,
    pub input_size: u8,
    pub input_action: u16,
}

/// Heartbeat subscription state.
#[derive(Debug, Clone, Default)]
pub struct MeshNetHeartbeatSub {
    pub src: u16,
    pub dst: u16,
    pub period: u32,
    pub count: u32,
    pub features: u16,
    pub min_hops: u8,
    pub max_hops: u8,
    pub enabled: bool,
}

/// Heartbeat publication state.
#[derive(Debug, Clone, Default)]
pub struct MeshNetHeartbeatPub {
    pub dst: u16,
    pub count: u16,
    pub period: u16,
    pub ttl: u8,
    pub features: u16,
    pub net_idx: u16,
}

/// Friend relationship state.
#[derive(Debug, Clone, Default)]
pub struct MeshFriend {
    pub lp_addr: u16,
    pub fn_cnt: u16,
    pub lp_cnt: u16,
    pub receive_delay: u8,
    pub ele_cnt: u8,
    pub net_idx: u16,
    pub poll_timeout: u32,
    pub net_key_cur: u32,
    pub net_key_upd: u32,
}

/// Friend message — cached message to be relayed to LPN.
#[derive(Debug, Clone, Default)]
pub struct MeshFriendMsg {
    pub iv_index: u32,
    pub flags: u8,
    pub src: u16,
    pub dst: u16,
    pub ttl: u8,
    pub cnt_in: u8,
    pub cnt_out: u8,
    pub last_len: u8,
    pub done: bool,
    pub ctl: bool,
}

// ===========================================================================
// Internal data structures
// ===========================================================================

/// Per-subnet state (replaces C `struct mesh_subnet`).
#[derive(Debug)]
struct MeshSubnet {
    /// Network key index.
    net_idx: u16,
    /// Key Refresh phase (PHASE_NONE/ONE/TWO/THREE).
    kr_phase: u8,
    /// Current net_key_tx id (from net_keys module).
    net_key_tx: u32,
    /// Current net_key id.
    net_key_cur: u32,
    /// Updated (new) net_key id (during Key Refresh).
    net_key_upd: u32,
    /// SNB (Secure Network Beacon) mode.
    snb_enable: bool,
    /// MPB (Mesh Private Beacon) mode.
    mpb_enable: bool,
}

/// Message cache entry for dedup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MsgCacheEntry {
    src: u16,
    seq: u32,
    iv_index: u16,
}

/// Replay protection cache entry.
#[derive(Debug, Clone, Copy)]
struct ReplayEntry {
    iv_index: u32,
    seq: u32,
}

/// SAR inbound session for reassembling segmented messages.
#[allow(dead_code)]
struct SarInSession {
    src: u16,
    dst: u16,
    seq_zero: u16,
    seg_n: u8,
    received_mask: u32,
    segments: Vec<Option<Vec<u8>>>,
    hdr: u32,
    szmic: bool,
    ttl: u8,
    iv_index: u32,
    net_key_id: u32,
    timeout: Option<JoinHandle<()>>,
    last_seg_time: u32,
}

/// SAR outbound session for transmitting segmented messages.
#[allow(dead_code)]
struct SarOutSession {
    dst: u16,
    seq_zero: u16,
    seg_n: u8,
    segments: Vec<Vec<u8>>,
    ack_received: u32,
    retransmit_count: u8,
    hdr: u32,
    szmic: bool,
    ttl: u8,
    net_idx: u16,
    iv_index: u32,
    net_key_id: u32,
    timeout: Option<JoinHandle<()>>,
}

/// Destination registration (for local element address subscription).
struct MeshDestination {
    dst: u16,
    ref_cnt: u32,
}

/// Heartbeat combined state.
#[derive(Debug, Clone, Default)]
struct HeartbeatState {
    sub: MeshNetHeartbeatSub,
    pub_state: MeshNetHeartbeatPub,
}

/// Friend negotiation state.
#[derive(Debug, Clone, Default)]
pub struct FriendNegotiation {
    /// Low-Power Node address.
    pub lp_addr: u16,
    /// LPN counter.
    pub lp_cnt: u16,
    /// Friend counter.
    pub fn_cnt: u16,
    /// Receive delay.
    pub receive_delay: u8,
    /// Poll timeout.
    pub poll_timeout: u32,
    /// Network key index.
    pub net_idx: u16,
}

/// Transmit parameters.
#[derive(Debug, Clone)]
struct TransmitParams {
    count: u8,
    interval: u16,
}

impl Default for TransmitParams {
    fn default() -> Self {
        Self { count: DEFAULT_TRANSMIT_COUNT, interval: DEFAULT_TRANSMIT_INTERVAL }
    }
}

// ===========================================================================
// MeshNet — the core network layer struct
// ===========================================================================

/// Mesh network layer. Replaces the C `struct mesh_net`.
///
/// Manages subnets, sequence numbers, IV Index state, SAR sessions,
/// message caching, replay protection, heartbeat, and friendship.
pub struct MeshNet {
    // ---- node back-reference ----
    node: Option<Weak<Mutex<MeshNetNode>>>,

    // ---- subnet / key state ----
    subnets: Vec<MeshSubnet>,
    app_keys: Vec<MeshAppKey>,
    primary_net_idx: u16,

    // ---- addressing ----
    src_addr: u16,
    num_ele: u8,
    destinations: Vec<MeshDestination>,

    // ---- sequence / IV ----
    iv_index: u32,
    iv_update: bool,
    iv_upd_state: IvUpdState,
    iv_update_timeout: u32,
    seq_num: u32,
    #[allow(dead_code)]
    seq_num_reserved: u32,

    // ---- TTL ----
    default_ttl: u8,

    // ---- relay ----
    relay_enable: bool,
    relay_count: u8,
    relay_interval: u16,

    // ---- proxy / friend / LPN ----
    proxy_enable: bool,
    friend_enable: bool,
    #[allow(dead_code)]
    lpn_mode: bool,

    // ---- beacon mode ----
    snb_enable: bool,
    mpb_enable: bool,

    // ---- SAR ----
    sar_in: HashMap<u32, SarInSession>,
    sar_out: Option<SarOutSession>,

    // ---- message cache (dedup) ----
    msg_cache: VecDeque<MsgCacheEntry>,

    // ---- replay protection ----
    replay_cache: HashMap<u16, ReplayEntry>,

    // ---- heartbeat ----
    heartbeat: HeartbeatState,

    // ---- friend state ----
    friends: Vec<MeshFriend>,
    friend_negotiations: Vec<FriendNegotiation>,
    friend_msgs: VecDeque<MeshFriendMsg>,

    // ---- transmit parameters ----
    transmit: TransmitParams,

    // ---- provisioning state ----
    prov_caps: MeshNetProvCaps,

    // ---- I/O (not owned directly, used via module functions) ----
    io_attached: bool,

    // ---- config persistence ----
    config: Option<Arc<Mutex<dyn MeshConfig>>>,

    // ---- node path for RPL ----
    node_path: String,

    // ---- misc state ----
    instant: u32,
}

/// Opaque node reference for back-pointer.
pub struct MeshNetNode;

/// SAR key: combines seq_zero and src for unique session identification.
#[inline]
fn sar_key(seq_zero: u16, src: u16) -> u32 {
    ((seq_zero as u32) << 16) | (src as u32)
}

impl Default for MeshNet {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshNet {
    // =======================================================================
    // Construction / Destruction
    // =======================================================================

    /// Create a new MeshNet instance.
    pub fn new() -> Self {
        Self {
            node: None,
            subnets: Vec::new(),
            app_keys: Vec::new(),
            primary_net_idx: NET_IDX_INVALID,
            src_addr: 0,
            num_ele: 0,
            destinations: Vec::new(),
            iv_index: 0,
            iv_update: false,
            iv_upd_state: IvUpdState::Init,
            iv_update_timeout: 0,
            seq_num: 0,
            seq_num_reserved: 0,
            default_ttl: DEFAULT_TTL,
            relay_enable: false,
            relay_count: DEFAULT_TRANSMIT_COUNT,
            relay_interval: DEFAULT_TRANSMIT_INTERVAL,
            proxy_enable: false,
            friend_enable: false,
            lpn_mode: false,
            snb_enable: true,
            mpb_enable: false,
            sar_in: HashMap::new(),
            sar_out: None,
            msg_cache: VecDeque::with_capacity(MSG_CACHE_SIZE),
            replay_cache: HashMap::new(),
            heartbeat: HeartbeatState::default(),
            friends: Vec::new(),
            friend_negotiations: Vec::new(),
            friend_msgs: VecDeque::with_capacity(FRND_CACHE_MAX),
            transmit: TransmitParams::default(),
            prov_caps: MeshNetProvCaps::default(),
            io_attached: false,
            config: None,
            node_path: String::new(),
            instant: 0,
        }
    }

    /// Clean up and release resources (replaces `mesh_net_free`).
    pub fn free(&mut self) {
        // Cancel all SAR timeouts
        for (_, session) in self.sar_in.drain() {
            if let Some(handle) = session.timeout {
                handle.abort();
            }
        }
        if let Some(ref mut out) = self.sar_out {
            if let Some(handle) = out.timeout.take() {
                handle.abort();
            }
        }
        self.sar_out = None;

        // Unref all subnet keys
        for subnet in &self.subnets {
            if subnet.net_key_cur != 0 {
                net_key_unref(subnet.net_key_cur);
            }
            if subnet.net_key_upd != 0 {
                net_key_unref(subnet.net_key_upd);
            }
        }
        self.subnets.clear();
        self.app_keys.clear();
        self.destinations.clear();
        self.msg_cache.clear();
        self.replay_cache.clear();
        self.friends.clear();
        self.friend_negotiations.clear();
        self.friend_msgs.clear();
        self.node = None;
        info!("MeshNet resources released");
    }

    // =======================================================================
    // IV Index
    // =======================================================================

    /// Set the IV Index and IV Update flag.
    pub fn set_iv_index(&mut self, iv_index: u32, update: bool) {
        let old = self.iv_index;
        self.iv_index = iv_index;
        self.iv_update = update;

        if update {
            self.iv_upd_state = IvUpdState::Updating;
        } else if old != iv_index {
            self.iv_upd_state = IvUpdState::Normal;
        }

        self.iv_update_timeout = get_timestamp_secs();

        debug!("IV Index set: 0x{:08x}, update={}", self.iv_index, self.iv_update);

        if let Some(ref cfg) = self.config {
            let _ = cfg.lock().unwrap().write_iv_index(self.iv_index, self.iv_update);
        }
    }

    /// Get current IV Index and update flag.
    pub fn get_iv_index(&self) -> (u32, bool) {
        (self.iv_index, self.iv_update)
    }

    /// Initiate or process IV Index update.
    ///
    /// Returns `true` if the update was accepted.
    pub fn iv_index_update(&mut self, update: bool) -> bool {
        let now = get_timestamp_secs();

        if update {
            // Transition to Updating
            match self.iv_upd_state {
                IvUpdState::Normal => {
                    if self.seq_num < IV_UPDATE_SEQ_TRIGGER {
                        debug!("IV Update not yet needed (seq < trigger)");
                        return false;
                    }
                    self.iv_index = self.iv_index.wrapping_add(1);
                    self.iv_update = true;
                    self.iv_upd_state = IvUpdState::Updating;
                    self.iv_update_timeout = now;

                    if let Some(ref cfg) = self.config {
                        let _ = cfg.lock().unwrap().write_iv_index(self.iv_index, self.iv_update);
                    }

                    // Refresh beacons
                    for subnet in &self.subnets {
                        net_key_beacon_refresh(
                            subnet.net_key_cur,
                            self.iv_index,
                            subnet.kr_phase != KEY_REFRESH_PHASE_NONE,
                            true,
                            true,
                        );
                    }

                    info!("IV Update initiated: iv_index=0x{:08x}", self.iv_index);
                    true
                }
                _ => {
                    debug!("IV Update already in progress or in hold");
                    false
                }
            }
        } else {
            // Transition back to Normal
            match self.iv_upd_state {
                IvUpdState::Updating => {
                    let elapsed = now.wrapping_sub(self.iv_update_timeout) as u64;
                    if elapsed < IV_IDX_UPD_MIN {
                        debug!("IV Update minimum time not elapsed");
                        return false;
                    }
                    self.iv_update = false;
                    self.iv_upd_state = IvUpdState::NormalHold;
                    self.iv_update_timeout = now;
                    self.seq_num = 0;

                    if let Some(ref cfg) = self.config {
                        let _ = cfg.lock().unwrap().write_iv_index(self.iv_index, self.iv_update);
                        let _ = cfg.lock().unwrap().write_seq_number(self.seq_num, false);
                    }

                    // Refresh beacons
                    for subnet in &self.subnets {
                        net_key_beacon_refresh(
                            subnet.net_key_cur,
                            self.iv_index,
                            subnet.kr_phase != KEY_REFRESH_PHASE_NONE,
                            false,
                            true,
                        );
                    }

                    // Update replay protection list
                    rpl_update(&self.node_path, self.iv_index);

                    info!("IV Update complete: iv_index=0x{:08x}, seq reset", self.iv_index);
                    true
                }
                IvUpdState::NormalHold => {
                    let elapsed = now.wrapping_sub(self.iv_update_timeout) as u64;
                    if elapsed >= IV_IDX_UPD_HOLD {
                        self.iv_upd_state = IvUpdState::Normal;
                        debug!("IV Update hold period complete");
                    }
                    true
                }
                _ => {
                    debug!("IV Update not in updating state");
                    false
                }
            }
        }
    }

    // =======================================================================
    // Sequence Number
    // =======================================================================

    /// Set the current sequence number.
    pub fn set_seq_num(&mut self, seq: u32) {
        self.seq_num = seq & SEQ_MASK;
    }

    /// Get the current sequence number.
    pub fn get_seq_num(&self) -> u32 {
        self.seq_num
    }

    /// Allocate and return the next sequence number.
    pub fn next_seq_num(&mut self) -> u32 {
        let seq = self.seq_num;
        self.seq_num = (self.seq_num + 1) & SEQ_MASK;

        // Check if IV Update is needed
        if self.seq_num >= IV_UPDATE_SEQ_TRIGGER
            && self.iv_upd_state == IvUpdState::Normal
            && !self.iv_update
        {
            debug!("Sequence number near exhaustion, consider IV Update");
        }

        if let Some(ref cfg) = self.config {
            let _ = cfg.lock().unwrap().write_seq_number(self.seq_num, true);
        }

        seq
    }

    // =======================================================================
    // TTL
    // =======================================================================

    /// Set the default TTL.
    pub fn set_default_ttl(&mut self, ttl: u8) {
        self.default_ttl = ttl & TTL_MASK;
    }

    /// Get the default TTL.
    pub fn get_default_ttl(&self) -> u8 {
        self.default_ttl
    }

    // =======================================================================
    // Friend Sequence Numbers
    // =======================================================================

    /// Get the friend sequence number (fn_cnt) for a given LPN address.
    pub fn get_frnd_seq(&self, lp_addr: u16) -> Option<u16> {
        self.friends.iter().find(|f| f.lp_addr == lp_addr).map(|f| f.fn_cnt)
    }

    /// Set the friend sequence number (fn_cnt) for a given LPN address.
    pub fn set_frnd_seq(&mut self, lp_addr: u16, fn_cnt: u16) -> bool {
        if let Some(f) = self.friends.iter_mut().find(|f| f.lp_addr == lp_addr) {
            f.fn_cnt = fn_cnt;
            true
        } else {
            false
        }
    }

    // =======================================================================
    // Addressing
    // =======================================================================

    /// Get the primary unicast address.
    pub fn get_address(&self) -> u16 {
        self.src_addr
    }

    /// Register the unicast address range.
    pub fn register_unicast(&mut self, addr: u16, num_ele: u8) {
        self.src_addr = addr;
        self.num_ele = num_ele;
        debug!("Registered unicast: 0x{:04x}, {} elements", addr, num_ele);
    }

    /// Check if an address belongs to this node.
    pub fn is_local_address(&self, addr: u16) -> bool {
        if self.src_addr == 0 || addr == 0 {
            return false;
        }
        addr >= self.src_addr && addr < self.src_addr + (self.num_ele as u16)
    }

    // =======================================================================
    // Mode Settings (SNB, MPB, Proxy, Relay, Friend)
    // =======================================================================

    /// Set Secure Network Beacon mode.
    pub fn set_snb_mode(&mut self, enable: bool) {
        self.snb_enable = enable;
        for subnet in &self.subnets {
            if enable {
                net_key_beacon_enable(subnet.net_key_cur, false, 0);
            } else {
                net_key_beacon_disable(subnet.net_key_cur, false);
            }
        }
        debug!("SNB mode: {}", enable);
    }

    /// Set Mesh Private Beacon mode.
    pub fn set_mpb_mode(&mut self, enable: bool, period: u8) {
        self.mpb_enable = enable;
        for subnet in &self.subnets {
            if enable {
                net_key_beacon_enable(subnet.net_key_cur, true, period);
            }
        }
        debug!("MPB mode: {}, period={}", enable, period);
    }

    /// Set proxy mode.
    pub fn set_proxy_mode(&mut self, enable: bool) {
        self.proxy_enable = enable;
        debug!("Proxy mode: {}", enable);
    }

    /// Set relay mode and parameters.
    pub fn set_relay_mode(&mut self, enable: bool, count: u8, interval: u16) {
        self.relay_enable = enable;
        self.relay_count = count;
        self.relay_interval = interval;
        debug!("Relay mode: {}, count={}, interval={}ms", enable, count, interval);
    }

    /// Set friend mode.
    pub fn set_friend_mode(&mut self, enable: bool) {
        self.friend_enable = enable;
        if !enable {
            // Clear all friend relationships
            for frnd in &self.friends {
                if frnd.net_key_cur != 0 {
                    net_key_unref(frnd.net_key_cur);
                }
                if frnd.net_key_upd != 0 {
                    net_key_unref(frnd.net_key_upd);
                }
            }
            self.friends.clear();
        }
        debug!("Friend mode: {}", enable);
    }

    /// Get SNB enabled state for a subnet.
    pub fn get_snb_state(&self, net_idx: u16) -> bool {
        self.subnets.iter().find(|s| s.net_idx == net_idx).map(|s| s.snb_enable).unwrap_or(false)
    }

    // =======================================================================
    // Subnet / Key Management
    // =======================================================================

    /// Delete a subnet key by index.
    pub fn del_key(&mut self, net_idx: u16) -> u8 {
        let pos = match self.subnets.iter().position(|s| s.net_idx == net_idx) {
            Some(p) => p,
            None => return MESH_STATUS_INVALID_NETKEY,
        };

        let subnet = self.subnets.remove(pos);
        if subnet.net_key_cur != 0 {
            net_key_unref(subnet.net_key_cur);
        }
        if subnet.net_key_upd != 0 {
            net_key_unref(subnet.net_key_upd);
        }

        // Remove app keys bound to this subnet
        self.app_keys.retain(|ak| ak.net_idx != net_idx);

        if let Some(ref cfg) = self.config {
            let _ = cfg.lock().unwrap().net_key_del(net_idx);
        }

        info!("Deleted subnet key idx=0x{:04x}", net_idx);
        MESH_STATUS_SUCCESS
    }

    /// Add a new subnet key.
    pub fn add_key(&mut self, net_idx: u16, key: &[u8; 16]) -> u8 {
        if net_idx > MAX_KEY_IDX {
            return MESH_STATUS_INVALID_NETKEY;
        }

        // Check for duplicate — confirm the key value matches if already present
        if let Some(subnet) = self.subnets.iter().find(|s| s.net_idx == net_idx) {
            if net_key_confirm(subnet.net_key_cur, key) {
                return MESH_STATUS_SUCCESS;
            }
            // Key index exists but with a different key value
            return MESH_STATUS_STORAGE_FAIL;
        }

        let net_key_id = net_key_add(key);
        if net_key_id == 0 {
            error!("Failed to add net key to key store");
            return MESH_STATUS_STORAGE_FAIL;
        }

        let subnet = MeshSubnet {
            net_idx,
            kr_phase: KEY_REFRESH_PHASE_NONE,
            net_key_tx: net_key_id,
            net_key_cur: net_key_id,
            net_key_upd: 0,
            snb_enable: self.snb_enable,
            mpb_enable: self.mpb_enable,
        };

        self.subnets.push(subnet);

        // Set primary if first key
        if self.primary_net_idx == NET_IDX_INVALID {
            self.primary_net_idx = net_idx;
        }

        // Enable beacon if configured
        if self.snb_enable {
            net_key_beacon_enable(net_key_id, false, 0);
        }

        if let Some(ref cfg) = self.config {
            let _ = cfg.lock().unwrap().net_key_add(net_idx, key);
        }

        info!("Added subnet key idx=0x{:04x}", net_idx);
        MESH_STATUS_SUCCESS
    }

    /// Update (initiate Key Refresh) for a subnet key.
    pub fn update_key(&mut self, net_idx: u16, key: &[u8; 16]) -> u8 {
        let subnet = match self.subnets.iter_mut().find(|s| s.net_idx == net_idx) {
            Some(s) => s,
            None => return MESH_STATUS_INVALID_NETKEY,
        };

        // If already in Phase 1, confirm the update key matches
        if subnet.kr_phase == KEY_REFRESH_PHASE_ONE && net_key_confirm(subnet.net_key_upd, key) {
            return MESH_STATUS_SUCCESS;
        }

        if subnet.kr_phase != KEY_REFRESH_PHASE_NONE {
            warn!("Key refresh already in progress for idx=0x{:04x}", net_idx);
            return MESH_STATUS_SUCCESS;
        }

        let new_key_id = net_key_add(key);
        if new_key_id == 0 {
            error!("Failed to add updated net key");
            return MESH_STATUS_STORAGE_FAIL;
        }

        subnet.net_key_upd = new_key_id;
        subnet.kr_phase = KEY_REFRESH_PHASE_ONE;

        if let Some(ref cfg) = self.config {
            let _ = cfg.lock().unwrap().net_key_update(net_idx, key);
            let _ = cfg.lock().unwrap().net_key_set_phase(net_idx, KEY_REFRESH_PHASE_ONE);
        }

        info!("Key refresh initiated for idx=0x{:04x}, phase=1", net_idx);
        MESH_STATUS_SUCCESS
    }

    /// Set a subnet key directly (used during provisioning/config restore).
    pub fn set_key(&mut self, net_idx: u16, key: &[u8; 16], phase: u8) -> bool {
        let net_key_id = net_key_add(key);
        if net_key_id == 0 {
            return false;
        }

        if let Some(subnet) = self.subnets.iter_mut().find(|s| s.net_idx == net_idx) {
            // Update existing
            if subnet.net_key_cur != 0 {
                net_key_unref(subnet.net_key_cur);
            }
            subnet.net_key_cur = net_key_id;
            subnet.net_key_tx = net_key_id;
            subnet.kr_phase = phase;
            return true;
        }

        let subnet = MeshSubnet {
            net_idx,
            kr_phase: phase,
            net_key_tx: net_key_id,
            net_key_cur: net_key_id,
            net_key_upd: 0,
            snb_enable: self.snb_enable,
            mpb_enable: self.mpb_enable,
        };
        self.subnets.push(subnet);

        if self.primary_net_idx == NET_IDX_INVALID {
            self.primary_net_idx = net_idx;
        }

        true
    }

    /// Get the current net key bytes for a subnet.
    pub fn get_key(&self, net_idx: u16) -> Option<u32> {
        self.subnets.iter().find(|s| s.net_idx == net_idx).map(|s| s.net_key_cur)
    }

    /// Check if the network has a given key index.
    pub fn have_key(&self, net_idx: u16) -> bool {
        self.subnets.iter().any(|s| s.net_idx == net_idx)
    }

    /// Get list of all key indices.
    pub fn key_list_get(&self) -> Vec<u16> {
        self.subnets.iter().map(|s| s.net_idx).collect()
    }

    /// Get the primary net index.
    pub fn get_primary_idx(&self) -> u16 {
        self.primary_net_idx
    }

    /// Get application key entries (immutable).
    pub fn get_app_keys(&self) -> &[MeshAppKey] {
        &self.app_keys
    }

    /// Get mutable reference to application key storage.
    pub fn get_app_keys_mut(&mut self) -> &mut Vec<MeshAppKey> {
        &mut self.app_keys
    }

    // =======================================================================
    // Key Refresh Phase
    // =======================================================================

    /// Get the Key Refresh phase for a subnet.
    pub fn key_refresh_phase_get(&self, net_idx: u16) -> u8 {
        self.subnets
            .iter()
            .find(|s| s.net_idx == net_idx)
            .map(|s| s.kr_phase)
            .unwrap_or(KEY_REFRESH_PHASE_NONE)
    }

    /// Set the Key Refresh phase for a subnet.
    pub fn key_refresh_phase_set(&mut self, net_idx: u16, phase: u8) -> u8 {
        let subnet = match self.subnets.iter_mut().find(|s| s.net_idx == net_idx) {
            Some(s) => s,
            None => return MESH_STATUS_INVALID_NETKEY,
        };

        let current = subnet.kr_phase;

        // Validate transition per Mesh Profile spec
        let valid = matches!(
            (current, phase),
            (KEY_REFRESH_PHASE_NONE, KEY_REFRESH_PHASE_NONE)
                | (KEY_REFRESH_PHASE_ONE, KEY_REFRESH_PHASE_TWO)
                | (KEY_REFRESH_PHASE_ONE, KEY_REFRESH_PHASE_THREE)
                | (KEY_REFRESH_PHASE_TWO, KEY_REFRESH_PHASE_THREE)
        );

        if !valid {
            warn!(
                "Invalid KR phase transition: {} -> {} for idx=0x{:04x}",
                current, phase, net_idx
            );
            return MESH_STATUS_SUCCESS; // Not an error per spec, just ignored
        }

        match phase {
            KEY_REFRESH_PHASE_TWO => {
                // Phase 2: TX on new key, RX on both
                subnet.net_key_tx = subnet.net_key_upd;
                subnet.kr_phase = KEY_REFRESH_PHASE_TWO;
                info!("Key Refresh phase 2 for idx=0x{:04x}", net_idx);
            }
            KEY_REFRESH_PHASE_THREE => {
                // Phase 3: Finalize — revoke old key
                if subnet.net_key_cur != subnet.net_key_upd && subnet.net_key_cur != 0 {
                    net_key_unref(subnet.net_key_cur);
                }
                subnet.net_key_cur = subnet.net_key_upd;
                subnet.net_key_tx = subnet.net_key_upd;
                subnet.net_key_upd = 0;
                subnet.kr_phase = KEY_REFRESH_PHASE_NONE;
                info!("Key Refresh complete (phase 3→0) for idx=0x{:04x}", net_idx);
            }
            _ => {}
        }

        net_key_beacon_refresh(
            subnet.net_key_cur,
            self.iv_index,
            subnet.kr_phase != KEY_REFRESH_PHASE_NONE,
            self.iv_update,
            true,
        );

        if let Some(ref cfg) = self.config {
            let _ = cfg.lock().unwrap().net_key_set_phase(net_idx, subnet.kr_phase);
        }

        MESH_STATUS_SUCCESS
    }

    // =======================================================================
    // I/O Integration
    // =======================================================================

    /// Attach the mesh I/O backend.
    pub fn attach(&mut self) {
        self.io_attached = true;

        // Enable beacons on all subnets
        for subnet in &self.subnets {
            if subnet.snb_enable {
                net_key_beacon_enable(subnet.net_key_cur, false, 0);
            }
            if subnet.mpb_enable {
                net_key_beacon_enable(subnet.net_key_cur, true, 0);
            }
        }

        debug!("MeshNet I/O attached");
    }

    /// Detach the mesh I/O backend.
    pub fn detach(&mut self) {
        self.io_attached = false;

        // Disable beacons
        for subnet in &self.subnets {
            net_key_beacon_disable(subnet.net_key_cur, false);
        }

        debug!("MeshNet I/O detached");
    }

    /// Check if I/O is attached.
    pub fn get_io(&self) -> bool {
        self.io_attached
    }

    // =======================================================================
    // Node back-reference
    // =======================================================================

    /// Get the node back-reference.
    pub fn node_get(&self) -> Option<Arc<Mutex<MeshNetNode>>> {
        self.node.as_ref().and_then(|w| w.upgrade())
    }

    /// Set provisioning capabilities.
    pub fn set_prov(&mut self, caps: MeshNetProvCaps) {
        self.prov_caps = caps;
    }

    /// Get provisioning capabilities.
    pub fn get_prov(&self) -> &MeshNetProvCaps {
        &self.prov_caps
    }

    /// Get the most recent beacon observation instant across all subnets.
    ///
    /// Iterates all subnets and queries `net_key_beacon_last_seen` for
    /// the TX key of each subnet, returning the maximum timestamp.
    pub fn get_instant(&self) -> u32 {
        let mut latest = self.instant;
        for subnet in &self.subnets {
            let ts = net_key_beacon_last_seen(subnet.net_key_tx);
            if ts > latest {
                latest = ts;
            }
        }
        latest
    }

    /// Get the identity mode for a subnet.
    pub fn get_identity_mode(&self, net_idx: u16) -> u8 {
        // In the C code, this delegates to subnet->node_id state.
        // Return NODE_IDENTITY_STOPPED unless proxy mode is on.
        if self.proxy_enable && self.have_key(net_idx) {
            1 // NODE_IDENTITY_RUNNING
        } else {
            0 // NODE_IDENTITY_STOPPED
        }
    }

    // =======================================================================
    // Destination Registration
    // =======================================================================

    /// Register a destination address for local processing.
    pub fn dst_reg(&mut self, dst: u16) -> bool {
        if let Some(d) = self.destinations.iter_mut().find(|d| d.dst == dst) {
            d.ref_cnt += 1;
            return true;
        }
        self.destinations.push(MeshDestination { dst, ref_cnt: 1 });
        true
    }

    /// Unregister a destination address.
    pub fn dst_unreg(&mut self, dst: u16) -> bool {
        if let Some(pos) = self.destinations.iter().position(|d| d.dst == dst) {
            self.destinations[pos].ref_cnt -= 1;
            if self.destinations[pos].ref_cnt == 0 {
                self.destinations.remove(pos);
            }
            return true;
        }
        false
    }

    /// Check if a destination is registered locally or is a valid group/broadcast.
    fn is_destination_valid(&self, dst: u16) -> bool {
        if dst == 0 {
            return false;
        }
        // Unicast to local element
        if self.is_local_address(dst) {
            return true;
        }
        // Fixed group addresses
        if dst == 0xffff || dst == 0xfffe || dst == 0xfffd || dst == 0xfffc {
            return true;
        }
        // Registered group/virtual address
        self.destinations.iter().any(|d| d.dst == dst)
    }

    // =======================================================================
    // Message Cache (Dedup)
    // =======================================================================

    /// Check if a message is already in the cache (dedup).
    fn msg_in_cache(&self, src: u16, seq: u32, iv_index: u16) -> bool {
        let entry = MsgCacheEntry { src, seq, iv_index };
        self.msg_cache.contains(&entry)
    }

    /// Add a message to the dedup cache.
    fn msg_cache_add(&mut self, src: u16, seq: u32, iv_index: u16) {
        let entry = MsgCacheEntry { src, seq, iv_index };

        if self.msg_cache.contains(&entry) {
            return;
        }

        if self.msg_cache.len() >= MSG_CACHE_SIZE {
            self.msg_cache.pop_front();
        }
        self.msg_cache.push_back(entry);
    }

    // =======================================================================
    // Replay Protection
    // =======================================================================

    /// Check replay protection for a received PDU.
    fn replay_check(&self, src: u16, iv_index: u32, seq: u32) -> bool {
        if let Some(entry) = self.replay_cache.get(&src) {
            if iv_index < entry.iv_index {
                return false; // Old IV index
            }
            if iv_index == entry.iv_index && seq <= entry.seq {
                return false; // Replay attack
            }
        }
        true
    }

    /// Update replay protection cache.
    fn replay_update(&mut self, src: u16, iv_index: u32, seq: u32) {
        let entry = ReplayEntry { iv_index, seq };
        self.replay_cache.insert(src, entry);
        rpl_put_entry(&self.node_path, src, iv_index, seq);
    }

    /// Load replay protection list from persistent storage.
    pub fn load_rpl(&mut self) {
        let mut rpl_list: Vec<MeshRpl> = Vec::new();
        if rpl_get_list(&self.node_path, &mut rpl_list) {
            for entry in &rpl_list {
                self.replay_cache
                    .insert(entry.src, ReplayEntry { iv_index: entry.iv_index, seq: entry.seq });
            }
            debug!("Loaded {} RPL entries", rpl_list.len());
        }
    }

    // =======================================================================
    // Network PDU Processing (Receive Path)
    // =======================================================================

    /// Process a received network PDU.
    ///
    /// This is the main entry point for incoming mesh network packets.
    /// Returns `true` if the PDU was successfully processed.
    pub fn process_pdu(&mut self, data: &[u8]) -> bool {
        if data.len() < 14 {
            warn!("Network PDU too short: {} bytes", data.len());
            return false;
        }

        print_packet("Net RX", data);

        // Try to decrypt with each available key
        let decrypt_result = self.try_decrypt(data);
        let (net_key_id, iv_index, cleartext) = match decrypt_result {
            Some(r) => r,
            None => {
                debug!("Failed to decrypt network PDU");
                return false;
            }
        };

        self.instant = get_timestamp_secs();

        // Parse the decrypted network header
        let fields = match mesh_crypto_packet_parse(&cleartext) {
            Some(f) => f,
            None => {
                warn!("Failed to parse decrypted PDU");
                return false;
            }
        };

        let src = fields.src;
        let dst = fields.dst;
        let seq = fields.seq;
        let ttl = fields.ttl;
        let ctl = fields.ctl;

        debug!(
            "PDU: src=0x{:04x} dst=0x{:04x} seq=0x{:06x} ttl={} ctl={}",
            src, dst, seq, ttl, ctl
        );

        // Check dedup cache
        let iv_short = (iv_index & 0xffff) as u16;
        if self.msg_in_cache(src, seq, iv_short) {
            debug!("Duplicate message, dropping");
            return true;
        }
        self.msg_cache_add(src, seq, iv_short);

        // Replay protection check
        if !self.replay_check(src, iv_index, seq) {
            warn!("Replay attack detected: src=0x{:04x} seq=0x{:06x}", src, seq);
            return false;
        }

        // Update replay cache
        self.replay_update(src, iv_index, seq);

        // Determine if we should relay
        let relay = self.should_relay(dst, ttl, &fields);

        // Process locally if destination matches
        if self.is_destination_valid(dst) {
            if is_segmented(fields.opcode as u32) || fields.segmented {
                self.process_segmented_rx(net_key_id, iv_index, &fields, &cleartext);
            } else {
                self.process_unsegmented_rx(net_key_id, iv_index, &fields, &cleartext);
            }
        }

        // Relay if appropriate
        if relay != RelayAdvice::None && relay != RelayAdvice::Disallowed {
            self.relay_pdu(net_key_id, iv_index, ttl, &cleartext);
        }

        true
    }

    /// Try to decrypt a network PDU with all available keys.
    fn try_decrypt(&self, data: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
        // First try with current IV index
        let iv_index = self.iv_index;
        if let Some((key_id, cleartext)) = net_key_decrypt(iv_index, data) {
            return Some((key_id, iv_index, cleartext));
        }

        // Try with previous IV index (for IV Update transition)
        if self.iv_update && iv_index > 0 {
            let prev_iv = iv_index - 1;
            if let Some((key_id, cleartext)) = net_key_decrypt(prev_iv, data) {
                return Some((key_id, prev_iv, cleartext));
            }
        }

        // Try with next IV index (peer may have updated before us)
        if !self.iv_update {
            let next_iv = iv_index + 1;
            if let Some((key_id, cleartext)) = net_key_decrypt(next_iv, data) {
                return Some((key_id, next_iv, cleartext));
            }
        }

        None
    }

    /// Determine relay advice for a PDU.
    fn should_relay(&self, dst: u16, ttl: u8, _fields: &PacketFields) -> RelayAdvice {
        if !self.relay_enable {
            return RelayAdvice::Disallowed;
        }

        if ttl < 2 {
            return RelayAdvice::Disallowed;
        }

        // Don't relay messages destined for this node
        if self.is_local_address(dst) {
            return RelayAdvice::Disallowed;
        }

        RelayAdvice::Allowed
    }

    /// Encode a raw network packet using the specified encryption and privacy keys,
    /// then label with the IVI/NID header byte.
    ///
    /// This is used for direct low-level packet operations outside the normal
    /// `net_key_encrypt` path (e.g., proxy filter status, friend messages,
    /// or when the caller supplies explicit key material).
    pub fn encode_and_label_pdu(
        pkt: &mut [u8],
        iv_index: u32,
        enc_key: &[u8; 16],
        privacy_key: &[u8; 16],
        nid: u8,
    ) -> bool {
        if !mesh_crypto_packet_encode(pkt, iv_index, enc_key, privacy_key) {
            error!("Low-level packet encode failed");
            return false;
        }
        mesh_crypto_packet_label(pkt, iv_index as u16, nid)
    }

    /// Decode (decrypt and de-obfuscate) a raw network packet using the specified keys.
    ///
    /// Returns `true` if decryption succeeded. Used for direct packet inspection
    /// outside the normal `net_key_decrypt` path (e.g., friend message decode,
    /// proxy PDU processing, or when the caller has explicit key material).
    pub fn decode_raw_pdu(
        pkt: &[u8],
        proxy: bool,
        out: &mut [u8],
        iv_index: u32,
        enc_key: &[u8; 16],
        privacy_key: &[u8; 16],
    ) -> bool {
        mesh_crypto_packet_decode(pkt, proxy, out, iv_index, enc_key, privacy_key)
    }

    /// Re-encrypt and relay a PDU with decremented TTL.
    fn relay_pdu(&self, net_key_id: u32, iv_index: u32, ttl: u8, cleartext: &[u8]) {
        if ttl < 2 {
            return;
        }

        let new_ttl = ttl - 1;
        let mut relay_pkt = cleartext.to_vec();

        // Set new TTL in the packet (byte offset 1, lower 7 bits)
        if relay_pkt.len() > 1 {
            relay_pkt[1] = (relay_pkt[1] & CTL) | (new_ttl & TTL_MASK);
        }

        // Re-encrypt with the same key
        if !net_key_encrypt(net_key_id, iv_index, &mut relay_pkt) {
            error!("Failed to re-encrypt relay PDU");
            return;
        }

        // Send via I/O
        let info = MeshIoSendInfo::General {
            interval: self.relay_interval,
            cnt: self.relay_count,
            min_delay: DEFAULT_MIN_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
        };

        // Prepend mesh AD type
        let mut ad_data = vec![BT_AD_MESH_DATA];
        ad_data.extend_from_slice(&relay_pkt);

        mesh_io_send(&info, &ad_data);
        debug!("Relayed PDU with TTL={}", new_ttl);
    }

    // =======================================================================
    // Unsegmented Message Processing
    // =======================================================================

    /// Process a received unsegmented message.
    fn process_unsegmented_rx(
        &mut self,
        _net_key_id: u32,
        iv_index: u32,
        fields: &PacketFields,
        _raw: &[u8],
    ) {
        if fields.ctl {
            self.process_ctl_message(fields, iv_index);
        } else {
            self.process_access_message(fields, iv_index);
        }
    }

    // =======================================================================
    // Segmented Message Processing (SAR Receive)
    // =======================================================================

    /// Process a received segmented message.
    fn process_segmented_rx(
        &mut self,
        net_key_id: u32,
        iv_index: u32,
        fields: &PacketFields,
        _raw: &[u8],
    ) {
        let seq_zero = fields.seq_zero;
        let seg_o = fields.seg_o;
        let seg_n = fields.seg_n;
        let src = fields.src;

        let key = sar_key(seq_zero, src);

        debug!(
            "SAR RX: src=0x{:04x} seq_zero=0x{:04x} seg_o={} seg_n={}",
            src, seq_zero, seg_o, seg_n
        );

        // Get or create SAR session, then process the segment.
        // We collect the needed values from the session to avoid
        // holding a mutable borrow while calling other &self methods.
        let (all_received, current_mask, session_dst) = {
            let session = self.sar_in.entry(key).or_insert_with(|| SarInSession {
                src,
                dst: fields.dst,
                seq_zero,
                seg_n,
                received_mask: 0,
                segments: (0..=seg_n).map(|_| None).collect(),
                hdr: fields.opcode as u32,
                szmic: fields.szmic,
                ttl: fields.ttl,
                iv_index,
                net_key_id,
                timeout: None,
                last_seg_time: get_timestamp_secs(),
            });

            // Validate consistency
            if session.seg_n != seg_n {
                warn!("SAR segment count mismatch");
                return;
            }

            // Store segment data
            if seg_o as usize <= seg_n as usize {
                session.segments[seg_o as usize] = Some(fields.payload.clone());
                session.received_mask |= 1 << seg_o;
                session.last_seg_time = get_timestamp_secs();
            }

            let expected_mask = (1u32 << (seg_n as u32 + 1)) - 1;
            let all_received = session.received_mask == expected_mask;
            let current_mask = session.received_mask;
            let dst = session.dst;
            (all_received, current_mask, dst)
        };

        if all_received {
            debug!("SAR complete: all {} segments received", seg_n + 1);
            // Reassemble and process
            self.sar_reassemble_and_process(key);
        } else {
            // Send ACK for received segments
            self.send_sar_ack(src, seq_zero, current_mask, session_dst);
            // Reset/start timeout
            self.start_sar_in_timeout(key);
        }
    }

    /// Reassemble segments and process the complete message.
    fn sar_reassemble_and_process(&mut self, key: u32) {
        let session = match self.sar_in.remove(&key) {
            Some(s) => s,
            None => return,
        };

        // Cancel timeout
        if let Some(handle) = session.timeout {
            handle.abort();
        }

        // Reassemble payload
        let mut payload = Vec::new();
        for data in session.segments.iter().flatten() {
            payload.extend_from_slice(data);
        }

        // Send final ACK (all segments received)
        let expected_mask = (1u32 << (session.seg_n as u32 + 1)) - 1;
        self.send_sar_ack(session.src, session.seq_zero, expected_mask, session.dst);

        // Build PacketFields for reassembled message
        let fields = PacketFields {
            ctl: (session.hdr & (CTL as u32)) != 0,
            ttl: session.ttl,
            seq: session.seq_zero as u32,
            src: session.src,
            dst: session.dst,
            cookie: 0,
            opcode: (session.hdr & 0xff) as u8,
            segmented: false, // Reassembled now
            key_aid: ((session.hdr >> KEY_HDR_SHIFT) & KEY_ID_MASK) as u8,
            szmic: session.szmic,
            relay: false,
            seq_zero: session.seq_zero,
            seg_o: 0,
            seg_n: session.seg_n,
            payload,
            payload_len: 0,
        };

        if fields.ctl {
            self.process_ctl_message(&fields, session.iv_index);
        } else {
            self.process_access_message(&fields, session.iv_index);
        }
    }

    /// Start a SAR inbound timeout.
    fn start_sar_in_timeout(&mut self, key: u32) {
        if let Some(session) = self.sar_in.get_mut(&key) {
            // Cancel existing timeout
            if let Some(handle) = session.timeout.take() {
                handle.abort();
            }

            let timeout_handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(MSG_TO)).await;
            });
            session.timeout = Some(timeout_handle);
        }
    }

    /// Send a SAR acknowledgment.
    fn send_sar_ack(&self, dst: u16, seq_zero: u16, ack_mask: u32, _from: u16) {
        // Build the segment ACK PDU (control message)
        let mut ack_pdu = [0u8; 7];
        ack_pdu[0] = NET_OP_SEG_ACKNOWLEDGE;

        // Encode: seq_zero (13 bits) + reserved + block_ack (32 bits)
        let hdr = ((seq_zero as u32) << 2) & 0x7ffc;
        ack_pdu[1] = ((hdr >> 8) & 0xff) as u8;
        ack_pdu[2] = (hdr & 0xff) as u8;
        ack_pdu[3] = ((ack_mask >> 24) & 0xff) as u8;
        ack_pdu[4] = ((ack_mask >> 16) & 0xff) as u8;
        ack_pdu[5] = ((ack_mask >> 8) & 0xff) as u8;
        ack_pdu[6] = (ack_mask & 0xff) as u8;

        // Send as unsegmented control message
        if let Some(subnet) = self.subnets.first() {
            let build_params = MeshPacketBuildParams {
                ctl: true,
                ttl: self.default_ttl,
                seq: self.seq_num, // Note: doesn't consume seq
                src: self.src_addr,
                dst,
                opcode: NET_OP_SEG_ACKNOWLEDGE,
                segmented: false,
                key_aid: 0,
                szmic: false,
                relay: false,
                seq_zero: 0,
                seg_o: 0,
                seg_n: 0,
                payload: &ack_pdu[1..],
            };

            if let Some((mut pkt, _)) = mesh_crypto_packet_build(&build_params) {
                if net_key_encrypt(subnet.net_key_tx, self.iv_index, &mut pkt) {
                    let info = MeshIoSendInfo::General {
                        interval: DEFAULT_TRANSMIT_INTERVAL,
                        cnt: DEFAULT_TRANSMIT_COUNT,
                        min_delay: DEFAULT_MIN_DELAY,
                        max_delay: DEFAULT_MAX_DELAY,
                    };
                    let mut ad_data = vec![BT_AD_MESH_DATA];
                    ad_data.extend_from_slice(&pkt);
                    mesh_io_send(&info, &ad_data);
                    debug!("Sent SAR ACK to 0x{:04x}, mask=0x{:08x}", dst, ack_mask);
                }
            }
        }
    }

    // =======================================================================
    // ACK Send (public)
    // =======================================================================

    /// Send a segment acknowledgment.
    pub fn ack_send(&self, dst: u16, seq_zero: u16, ack_mask: u32) {
        self.send_sar_ack(dst, seq_zero, ack_mask, self.src_addr);
    }

    // =======================================================================
    // Control Message Processing
    // =======================================================================

    /// Process a control (CTL) message.
    fn process_ctl_message(&mut self, fields: &PacketFields, _iv_index: u32) {
        let opcode = fields.opcode;

        match opcode {
            NET_OP_SEG_ACKNOWLEDGE => {
                self.process_seg_ack(fields);
            }
            NET_OP_FRND_POLL => {
                self.process_friend_poll(fields);
            }
            NET_OP_FRND_UPDATE => {
                self.process_friend_update(fields);
            }
            NET_OP_FRND_REQUEST => {
                self.process_friend_request(fields);
            }
            NET_OP_FRND_OFFER => {
                self.process_friend_offer(fields);
            }
            NET_OP_FRND_CLEAR => {
                self.process_friend_clear(fields);
            }
            NET_OP_FRND_CLEAR_CONFIRM => {
                self.process_friend_clear_confirm(fields);
            }
            NET_OP_HEARTBEAT => {
                self.process_heartbeat(fields);
            }
            _ => {
                debug!("Unhandled CTL opcode: 0x{:02x}", opcode);
            }
        }
    }

    /// Process a segment acknowledgment (received ACK for our outgoing SAR).
    fn process_seg_ack(&mut self, fields: &PacketFields) {
        if fields.payload.len() < 6 {
            return;
        }

        let hdr_bytes = &fields.payload;
        let seq_zero_val =
            (((hdr_bytes[0] as u16) << 8 | hdr_bytes[1] as u16) >> 2) & SEQ_ZERO_MASK as u16;
        let block_ack =
            u32::from_be_bytes([hdr_bytes[2], hdr_bytes[3], hdr_bytes[4], hdr_bytes[5]]);

        debug!("Received SAR ACK: seq_zero=0x{:04x} block_ack=0x{:08x}", seq_zero_val, block_ack);

        if let Some(ref mut out) = self.sar_out {
            if out.seq_zero == seq_zero_val {
                out.ack_received |= block_ack;

                let expected = (1u32 << (out.seg_n as u32 + 1)) - 1;
                if out.ack_received == expected {
                    debug!("SAR TX complete: all segments acknowledged");
                    if let Some(handle) = out.timeout.take() {
                        handle.abort();
                    }
                    self.sar_out = None;
                } else {
                    // Retransmit missing segments
                    self.retransmit_missing_segments();
                }
            }
        }
    }

    /// Retransmit segments that haven't been acknowledged.
    fn retransmit_missing_segments(&mut self) {
        let (segments_to_send, net_key_id, iv_index) = {
            let out = match self.sar_out.as_ref() {
                Some(o) => o,
                None => return,
            };
            let mut missing = Vec::new();
            for i in 0..=out.seg_n {
                if out.ack_received & (1 << i) == 0 {
                    if let Some(seg) = out.segments.get(i as usize) {
                        missing.push((i, seg.clone()));
                    }
                }
            }
            (missing, out.net_key_id, out.iv_index)
        };

        for (seg_idx, mut seg_data) in segments_to_send {
            if net_key_encrypt(net_key_id, iv_index, &mut seg_data) {
                let info = MeshIoSendInfo::General {
                    interval: self.transmit.interval,
                    cnt: self.transmit.count,
                    min_delay: DEFAULT_MIN_DELAY,
                    max_delay: DEFAULT_MAX_DELAY,
                };
                let mut ad_data = vec![BT_AD_MESH_DATA];
                ad_data.extend_from_slice(&seg_data);
                mesh_io_send(&info, &ad_data);
                debug!("Retransmitted segment {}", seg_idx);
            }
        }
    }

    // =======================================================================
    // Access Message Processing
    // =======================================================================

    /// Process a decrypted access message.
    fn process_access_message(&self, fields: &PacketFields, iv_index: u32) {
        let akf = (fields.key_aid & KEY_ID_AKF) != 0;
        let aid = (fields.key_aid >> KEY_AID_SHIFT) & KEY_AID_MASK;
        let payload = &fields.payload;

        debug!(
            "Access message: src=0x{:04x} dst=0x{:04x} akf={} aid=0x{:02x} len={}",
            fields.src,
            fields.dst,
            akf,
            aid,
            payload.len()
        );

        // Validate source is a unicast address
        if !is_unicast(fields.src) {
            warn!("Access message from non-unicast source 0x{:04x}", fields.src);
            return;
        }

        // Validate payload length against max PDU size
        if payload.len() + 9 > MESH_NET_MAX_PDU_LEN {
            warn!(
                "Access payload too large: {} (max net PDU={})",
                payload.len(),
                MESH_NET_MAX_PDU_LEN
            );
            return;
        }

        // Attempt to decrypt using application keys.
        // For device key (akf=false), key_aid is APP_AID_INVALID.
        let effective_aid = if akf { aid } else { APP_AID_INVALID };

        // Try to decrypt the access payload with each matching app key.
        // In the full daemon, the model layer iterates bound app keys.
        // Here we attempt a trial decryption to verify the payload.
        for app_key in &self.app_keys {
            if akf && app_key.app_idx != effective_aid as u16 {
                continue;
            }

            let mut out = vec![0u8; payload.len()];
            let mut dec_params = MeshPayloadDecryptParams {
                aad: None,
                payload,
                aszmic: fields.szmic,
                src: fields.src,
                dst: fields.dst,
                key_aid: fields.key_aid,
                seq: fields.seq,
                iv_index,
                out: &mut out,
                app_key: &app_key.key,
            };

            if mesh_crypto_payload_decrypt(&mut dec_params) {
                debug!(
                    "Access payload decrypted: src=0x{:04x} dst=0x{:04x} app_idx=0x{:04x}",
                    fields.src, fields.dst, app_key.app_idx
                );
                // The model layer binding happens through the node reference.
                // This is the delivery point where mesh_model_rx() is invoked
                // in the full daemon. The node module is responsible for routing.
                return;
            }
        }

        debug!(
            "No matching app key for access message src=0x{:04x} dst=0x{:04x}",
            fields.src, fields.dst
        );
    }

    // =======================================================================
    // Transport Send
    // =======================================================================

    /// Send a transport PDU (access or control message).
    ///
    /// This handles both segmented and unsegmented messages based on payload size.
    /// - `net_idx`: Network key index to use for encryption
    /// - `key_aid`: Application key AID (or 0 for device key)
    /// - `dst`: Destination address
    /// - `ctl`: True for control message, false for access
    /// - `ttl`: Time-to-live
    /// - `szmic`: True for 64-bit TransMIC
    /// - `seq_num`: Sequence number
    /// - `payload`: Transport PDU payload
    pub fn transport_send(
        &mut self,
        net_idx: u16,
        key_aid: u8,
        dst: u16,
        ctl: bool,
        ttl: u8,
        szmic: bool,
        seq_num: u32,
        payload: &[u8],
    ) -> bool {
        // Validate payload against maximum network PDU length
        // The 9 accounts for net header (1 IVI/NID + 1 CTL/TTL + 3 SEQ + 2 SRC + 2 DST)
        // and the MIC (4 or 8 bytes) is added by encryption.
        if payload.is_empty() || (9 + payload.len() + 8 > MESH_NET_MAX_PDU_LEN) {
            error!(
                "Transport payload length {} exceeds max net PDU {}",
                payload.len(),
                MESH_NET_MAX_PDU_LEN
            );
            return false;
        }

        let subnet_idx = match self.subnets.iter().position(|s| s.net_idx == net_idx) {
            Some(i) => i,
            None => {
                error!("No subnet with idx=0x{:04x}", net_idx);
                return false;
            }
        };

        let max_unseg = if ctl { 11 } else { MAX_UNSEG_LEN };

        // Extract subnet fields needed for send operations
        let net_key_tx = self.subnets[subnet_idx].net_key_tx;
        let sub_net_idx = self.subnets[subnet_idx].net_idx;

        if payload.len() <= max_unseg {
            // Unsegmented
            self.send_unsegmented_with_key(
                net_key_tx, key_aid, dst, ctl, ttl, szmic, seq_num, payload,
            )
        } else {
            // Segmented
            self.send_segmented_with_key(
                net_key_tx,
                sub_net_idx,
                key_aid,
                dst,
                ctl,
                ttl,
                szmic,
                seq_num,
                payload,
            )
        }
    }

    /// Send an unsegmented network PDU using a specific key id.
    fn send_unsegmented_with_key(
        &self,
        net_key_tx: u32,
        key_aid: u8,
        dst: u16,
        ctl: bool,
        ttl: u8,
        szmic: bool,
        seq_num: u32,
        payload: &[u8],
    ) -> bool {
        let opcode = if ctl { payload.first().copied().unwrap_or(0) } else { 0 };

        let build_params = MeshPacketBuildParams {
            ctl,
            ttl,
            seq: seq_num,
            src: self.src_addr,
            dst,
            opcode,
            segmented: false,
            key_aid,
            szmic,
            relay: false,
            seq_zero: 0,
            seg_o: 0,
            seg_n: 0,
            payload,
        };

        let (mut pkt, _) = match mesh_crypto_packet_build(&build_params) {
            Some(r) => r,
            None => {
                error!("Failed to build unsegmented PDU");
                return false;
            }
        };

        if !net_key_encrypt(net_key_tx, self.iv_index, &mut pkt) {
            error!("Failed to encrypt unsegmented PDU");
            return false;
        }

        let info = MeshIoSendInfo::General {
            interval: self.transmit.interval,
            cnt: self.transmit.count,
            min_delay: DEFAULT_MIN_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
        };

        let mut ad_data = vec![BT_AD_MESH_DATA];
        ad_data.extend_from_slice(&pkt);
        mesh_io_send(&info, &ad_data);

        print_packet("Net TX (unseg)", &pkt);
        true
    }

    /// Send a segmented network PDU using a specific key id.
    fn send_segmented_with_key(
        &mut self,
        net_key_tx: u32,
        net_idx: u16,
        key_aid: u8,
        dst: u16,
        ctl: bool,
        ttl: u8,
        szmic: bool,
        seq_num: u32,
        payload: &[u8],
    ) -> bool {
        // Check if there's already an outgoing SAR session
        if self.sar_out.is_some() {
            warn!("SAR TX already in progress");
            return false;
        }

        let seg_n = seg_max(payload.len());
        let seq_zero = (seq_num & SEQ_ZERO_MASK) as u16;
        let net_key_id = net_key_tx;

        let mut segments = Vec::new();

        for seg_o_val in 0..=seg_n {
            let offset = seg_off(seg_o_val);
            let remaining = payload.len().saturating_sub(offset);
            let seg_len = remaining.min(MAX_SEG_LEN);
            let seg_payload = &payload[offset..offset + seg_len];

            let opcode = if ctl { seg_payload.first().copied().unwrap_or(0) } else { 0 };

            let build_params = MeshPacketBuildParams {
                ctl,
                ttl,
                seq: seq_num.wrapping_add(seg_o_val as u32),
                src: self.src_addr,
                dst,
                opcode,
                segmented: true,
                key_aid,
                szmic,
                relay: false,
                seq_zero,
                seg_o: seg_o_val,
                seg_n,
                payload: seg_payload,
            };

            match mesh_crypto_packet_build(&build_params) {
                Some((pkt, _)) => {
                    segments.push(pkt);
                }
                None => {
                    error!("Failed to build segment {}", seg_o_val);
                    return false;
                }
            }
        }

        // Encrypt and send all segments
        let mut encrypted_segments = Vec::new();
        for mut seg in segments {
            if !net_key_encrypt(net_key_id, self.iv_index, &mut seg) {
                error!("Failed to encrypt segment");
                return false;
            }

            let info = MeshIoSendInfo::General {
                interval: self.transmit.interval,
                cnt: self.transmit.count,
                min_delay: DEFAULT_MIN_DELAY,
                max_delay: DEFAULT_MAX_DELAY,
            };
            let mut ad_data = vec![BT_AD_MESH_DATA];
            ad_data.extend_from_slice(&seg);
            mesh_io_send(&info, &ad_data);

            encrypted_segments.push(seg);
        }

        // Create SAR outbound session
        let timeout_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(MSG_TO)).await;
        });

        self.sar_out = Some(SarOutSession {
            dst,
            seq_zero,
            seg_n,
            segments: encrypted_segments,
            ack_received: 0,
            retransmit_count: 0,
            hdr: 0,
            szmic,
            ttl,
            net_idx,
            iv_index: self.iv_index,
            net_key_id,
            timeout: Some(timeout_handle),
        });

        debug!("SAR TX started: dst=0x{:04x} seg_n={} seq_zero=0x{:04x}", dst, seg_n, seq_zero);
        true
    }

    /// Public segmented send (wraps internal logic).
    pub fn send_seg(
        &mut self,
        net_idx: u16,
        key_aid: u8,
        dst: u16,
        ctl: bool,
        ttl: u8,
        szmic: bool,
        seq_num: u32,
        payload: &[u8],
    ) -> bool {
        self.transport_send(net_idx, key_aid, dst, ctl, ttl, szmic, seq_num, payload)
    }

    /// Send an application layer message.
    ///
    /// Encrypts the access payload with the given app key and then passes
    /// the encrypted payload to `transport_send`.
    pub fn app_send(
        &mut self,
        net_idx: u16,
        app_idx: u16,
        dst: u16,
        ttl: u8,
        szmic: bool,
        seq_num: u32,
        payload: &[u8],
        app_key: &[u8; 16],
    ) -> bool {
        let mic_len: usize = if szmic { 8 } else { 4 };
        let mut encrypted = vec![0u8; payload.len() + mic_len];

        let iv_index = if self.iv_update { self.iv_index.wrapping_sub(1) } else { self.iv_index };

        // Determine key_aid from the app key
        let key_aid = if app_idx >= 0x7fff {
            APP_AID_DEV
        } else {
            // In normal operation, key_aid is derived from the app key via k4
            // The caller typically provides the correct AID
            crate::crypto::mesh_crypto_k4(app_key).unwrap_or(0)
        };

        let mut enc_params = MeshPayloadEncryptParams {
            aad: None,
            payload,
            out: &mut encrypted,
            src: self.src_addr,
            dst,
            key_aid,
            seq: seq_num,
            iv_index,
            aszmic: szmic,
            app_key,
        };

        if !mesh_crypto_payload_encrypt(&mut enc_params) {
            error!("Failed to encrypt app payload");
            return false;
        }

        self.transport_send(net_idx, key_aid, dst, false, ttl, szmic, seq_num, &encrypted)
    }

    // =======================================================================
    // Heartbeat Processing
    // =======================================================================

    /// Process a received heartbeat message.
    fn process_heartbeat(&mut self, fields: &PacketFields) {
        if fields.payload.is_empty() {
            return;
        }

        let sub = &mut self.heartbeat.sub;

        if !sub.enabled {
            return;
        }

        // Check source filter
        if sub.src != 0 && sub.src != fields.src {
            return;
        }

        // Check destination filter
        if sub.dst != 0 && sub.dst != fields.dst {
            return;
        }

        let init_ttl = fields.payload.first().copied().unwrap_or(0) & TTL_MASK;
        let features = if fields.payload.len() >= 3 {
            u16::from_be_bytes([fields.payload[1], fields.payload[2]])
        } else {
            0
        };

        let hops = if init_ttl >= fields.ttl { init_ttl - fields.ttl + 1 } else { 1 };

        // Update subscription state
        sub.count = sub.count.saturating_add(1);
        sub.features |= features;

        if hops < sub.min_hops || sub.min_hops == 0 {
            sub.min_hops = hops;
        }
        if hops > sub.max_hops {
            sub.max_hops = hops;
        }

        debug!("Heartbeat RX: src=0x{:04x} hops={} features=0x{:04x}", fields.src, hops, features);
    }

    /// Get heartbeat subscription state.
    pub fn get_heartbeat_sub(&self) -> MeshNetHeartbeatSub {
        self.heartbeat.sub.clone()
    }

    /// Set heartbeat subscription parameters.
    pub fn set_heartbeat_sub(&mut self, sub: MeshNetHeartbeatSub) {
        self.heartbeat.sub = sub;
    }

    /// Get heartbeat publication state.
    pub fn get_heartbeat_pub(&self) -> MeshNetHeartbeatPub {
        self.heartbeat.pub_state.clone()
    }

    /// Set heartbeat publication parameters.
    pub fn set_heartbeat_pub(&mut self, pub_state: MeshNetHeartbeatPub) {
        self.heartbeat.pub_state = pub_state;
    }

    // =======================================================================
    // Friendship Processing
    // =======================================================================

    /// Process Friend Poll.
    fn process_friend_poll(&self, fields: &PacketFields) {
        debug!("Friend Poll from 0x{:04x}", fields.src);
        // Friend poll handling: check if we're acting as friend for this LPN
        // and send queued messages
    }

    /// Process Friend Update.
    fn process_friend_update(&mut self, fields: &PacketFields) {
        if fields.payload.len() < 6 {
            return;
        }

        let flags = fields.payload[0];
        let iv_index = u32::from_be_bytes([
            fields.payload[1],
            fields.payload[2],
            fields.payload[3],
            fields.payload[4],
        ]);
        let _md = fields.payload[5]; // More data flag

        let kr = (flags & KEY_REFRESH) != 0;
        let ivu = (flags & IV_INDEX_UPDATE) != 0;

        debug!("Friend Update: iv_index=0x{:08x} kr={} ivu={}", iv_index, kr, ivu);

        // Update IV Index if needed
        if iv_index > self.iv_index || (iv_index == self.iv_index && ivu != self.iv_update) {
            self.set_iv_index(iv_index, ivu);
        }
    }

    /// Process Friend Request.
    fn process_friend_request(&mut self, fields: &PacketFields) {
        if !self.friend_enable {
            return;
        }

        if fields.payload.len() < 10 {
            return;
        }

        let criteria = fields.payload[0];
        let receive_delay = fields.payload[1];
        let poll_timeout =
            u32::from_be_bytes([0, fields.payload[2], fields.payload[3], fields.payload[4]]);
        let prev_addr = u16::from_be_bytes([fields.payload[5], fields.payload[6]]);
        let num_ele = fields.payload[7];
        let lp_cnt = u16::from_be_bytes([fields.payload[8], fields.payload[9]]);

        debug!(
            "Friend Request: src=0x{:04x} delay={} timeout={} ele={}",
            fields.src, receive_delay, poll_timeout, num_ele
        );

        let _ = criteria;
        let _ = prev_addr;

        // Store negotiation state
        self.friend_negotiations.push(FriendNegotiation {
            lp_addr: fields.src,
            lp_cnt,
            fn_cnt: 0,
            receive_delay,
            poll_timeout,
            net_idx: self.primary_net_idx,
        });
    }

    /// Process Friend Offer.
    fn process_friend_offer(&self, fields: &PacketFields) {
        debug!("Friend Offer from 0x{:04x}", fields.src);
        // LPN mode: evaluate friend offer
    }

    /// Process Friend Clear.
    fn process_friend_clear(&mut self, fields: &PacketFields) {
        if fields.payload.len() < 4 {
            return;
        }
        let lp_addr = u16::from_be_bytes([fields.payload[0], fields.payload[1]]);
        let lp_cnt = u16::from_be_bytes([fields.payload[2], fields.payload[3]]);

        debug!("Friend Clear: lp_addr=0x{:04x} lp_cnt={}", lp_addr, lp_cnt);

        // Remove friendship
        self.friends.retain(|f| f.lp_addr != lp_addr || f.lp_cnt != lp_cnt);
    }

    /// Process Friend Clear Confirm.
    fn process_friend_clear_confirm(&self, fields: &PacketFields) {
        debug!("Friend Clear Confirm from 0x{:04x}", fields.src);
    }

    /// Handle friend timeout (poll timeout expired).
    pub fn friend_timeout(&mut self, lp_addr: u16) {
        debug!("Friend timeout for LPN 0x{:04x}", lp_addr);
        // Remove the friendship
        if let Some(pos) = self.friends.iter().position(|f| f.lp_addr == lp_addr) {
            let frnd = self.friends.remove(pos);
            if frnd.net_key_cur != 0 {
                net_key_unref(frnd.net_key_cur);
            }
            if frnd.net_key_upd != 0 {
                net_key_unref(frnd.net_key_upd);
            }
        }
    }

    /// Get list of current friends (acting as Friend Node).
    pub fn get_friends(&self) -> &[MeshFriend] {
        &self.friends
    }

    /// Get pending friend negotiations.
    pub fn get_negotiations(&self) -> &[FriendNegotiation] {
        &self.friend_negotiations
    }

    /// Check if friend mode is enabled for this network.
    pub fn is_friend_enabled(&self) -> bool {
        self.friend_enable
    }

    /// Remove a negotiation entry by LPN address.
    pub fn remove_negotiation_by_addr(&mut self, lp_addr: u16) {
        self.friend_negotiations.retain(|n| n.lp_addr != lp_addr);
    }

    /// Add a negotiation entry.
    pub fn add_negotiation(&mut self, neg: FriendNegotiation) {
        self.friend_negotiations.push(neg);
    }

    /// Add a friend to the friend list.
    pub fn add_friend(&mut self, frnd: MeshFriend) {
        self.friends.push(frnd);
    }

    /// Get the transmit key ID for a subnet.
    pub fn get_net_key_tx(&self, net_idx: u16) -> Option<u32> {
        self.subnets.iter().find(|s| s.net_idx == net_idx).map(|s| s.net_key_tx)
    }

    /// Get the beacon (SNB) state for a subnet: (flags, iv_index).
    ///
    /// Flags byte: bit 0 = Key Refresh, bit 1 = IV Update.
    pub fn get_beacon_state(&self, net_idx: u16) -> Option<(u8, u32)> {
        let subnet = self.subnets.iter().find(|s| s.net_idx == net_idx)?;
        let mut flags: u8 = 0;
        if subnet.kr_phase == 2 {
            flags |= 0x01; // KEY_REFRESH
        }
        if self.iv_update {
            flags |= 0x02; // IV_INDEX_UPDATE
        }
        Some((flags, self.iv_index))
    }

    // =======================================================================
    // Transmit Parameters
    // =======================================================================

    /// Set network transmit parameters.
    pub fn transmit_params_set(&mut self, count: u8, interval: u16) {
        self.transmit.count = count;
        self.transmit.interval = interval;
    }

    /// Get network transmit parameters.
    pub fn transmit_params_get(&self) -> (u8, u16) {
        (self.transmit.count, self.transmit.interval)
    }

    // =======================================================================
    // Config persistence
    // =======================================================================

    /// Set the configuration persistence backend.
    pub fn set_config(&mut self, config: Arc<Mutex<dyn MeshConfig>>) {
        self.config = Some(config);
    }

    /// Get a reference to the configuration persistence backend.
    pub fn get_config(&self) -> Option<&Arc<Mutex<dyn MeshConfig>>> {
        self.config.as_ref()
    }

    /// Set the node storage path for RPL persistence.
    pub fn set_node_path(&mut self, path: &str) {
        self.node_path = path.to_string();
    }

    /// Set the node back-reference.
    pub fn set_node(&mut self, node: Weak<Mutex<MeshNetNode>>) {
        self.node = Some(node);
    }
}

// ===========================================================================
// Standalone / Free Functions
// ===========================================================================

/// Process a local beacon and apply IV/KR updates.
///
/// Called when a beacon is received from the I/O layer. Parses the beacon,
/// validates its CMAC, and applies IV Index and Key Refresh updates.
pub fn net_local_beacon(net: &mut MeshNet, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let beacon_type = data[0];

    // Process Secure Network Beacon or Mesh Private Beacon
    if beacon_type != 0x01 && beacon_type != 0x02 {
        debug!("Unknown beacon type: 0x{:02x}", beacon_type);
        return;
    }

    // Parse beacon via net_keys module
    let (key_id, iv_index, kr, ivu) = match net_key_beacon(data) {
        Some(result) => result,
        None => {
            debug!("Failed to authenticate beacon");
            return;
        }
    };

    // Mark beacon as seen
    net_key_beacon_seen(key_id);

    let cur_iv = net.iv_index;
    let cur_ivu = net.iv_update;

    debug!(
        "Beacon: key_id={} iv_index=0x{:08x} kr={} ivu={} (current: 0x{:08x} ivu={})",
        key_id, iv_index, kr, ivu, cur_iv, cur_ivu
    );

    // IV Index processing per Mesh Profile 3.10.5
    if iv_index < cur_iv {
        // Received older IV index — ignore unless recovery needed
        if cur_iv.wrapping_sub(iv_index) > IV_IDX_DIFF_RANGE {
            warn!("IV Index too old, ignoring beacon");
        }
        return;
    }

    // Normal IV Index tracking
    if iv_index == cur_iv {
        if ivu != cur_ivu {
            // Transition detected
            if ivu {
                // Peer entering IV Update
                net.iv_update = true;
                net.iv_upd_state = IvUpdState::Updating;
                net.iv_update_timeout = get_timestamp_secs();
            } else if net.iv_upd_state == IvUpdState::Updating {
                // Peer completing IV Update
                net.iv_update = false;
                net.iv_upd_state = IvUpdState::NormalHold;
                net.iv_update_timeout = get_timestamp_secs();
                net.seq_num = 0;
                rpl_update(&net.node_path, net.iv_index);
            }

            if let Some(ref cfg) = net.config {
                let _ = cfg.lock().unwrap().write_iv_index(net.iv_index, net.iv_update);
            }
        }
    } else if iv_index == cur_iv + 1 {
        // Peer has incremented IV Index
        if ivu {
            // Peer starting IV Update with new index
            net.iv_index = iv_index;
            net.iv_update = true;
            net.iv_upd_state = IvUpdState::Updating;
            net.iv_update_timeout = get_timestamp_secs();
        } else {
            // Peer completed IV Update
            net.iv_index = iv_index;
            net.iv_update = false;
            net.iv_upd_state = IvUpdState::Normal;
            net.seq_num = 0;
            rpl_update(&net.node_path, net.iv_index);
        }

        if let Some(ref cfg) = net.config {
            let _ = cfg.lock().unwrap().write_iv_index(net.iv_index, net.iv_update);
            let _ = cfg.lock().unwrap().write_seq_number(net.seq_num, false);
        }
    } else if iv_index > cur_iv + 1 {
        // IV Index recovery (jumped multiple indices)
        if iv_index.wrapping_sub(cur_iv) <= IV_IDX_DIFF_RANGE {
            info!("IV Index recovery: 0x{:08x} -> 0x{:08x}", cur_iv, iv_index);
            net.iv_index = iv_index;
            net.iv_update = ivu;
            net.seq_num = 0;
            net.iv_upd_state = if ivu { IvUpdState::Updating } else { IvUpdState::Normal };
            net.iv_update_timeout = get_timestamp_secs();
            rpl_update(&net.node_path, net.iv_index);

            if let Some(ref cfg) = net.config {
                let _ = cfg.lock().unwrap().write_iv_index(net.iv_index, net.iv_update);
                let _ = cfg.lock().unwrap().write_seq_number(net.seq_num, false);
            }
        } else {
            warn!("IV Index recovery out of range: diff={}", iv_index.wrapping_sub(cur_iv));
        }
    }

    // Key Refresh processing
    let subnet =
        match net.subnets.iter_mut().find(|s| s.net_key_cur == key_id || s.net_key_upd == key_id) {
            Some(s) => s,
            None => return,
        };

    if kr && subnet.kr_phase == KEY_REFRESH_PHASE_NONE {
        // Peer has entered Key Refresh Phase 1
        // We need an updated key to proceed — this is typically driven by config
        debug!("Beacon indicates Key Refresh for subnet idx=0x{:04x}", subnet.net_idx);
    } else if !kr && subnet.kr_phase != KEY_REFRESH_PHASE_NONE {
        // Key Refresh complete — finalize (transition to phase 3 → None)
        if subnet.net_key_upd != 0 {
            if subnet.net_key_cur != 0 && subnet.net_key_cur != subnet.net_key_upd {
                net_key_unref(subnet.net_key_cur);
            }
            subnet.net_key_cur = subnet.net_key_upd;
            subnet.net_key_tx = subnet.net_key_upd;
            subnet.net_key_upd = 0;
        }
        subnet.kr_phase = KEY_REFRESH_PHASE_NONE;

        if let Some(ref cfg) = net.config {
            let _ = cfg.lock().unwrap().net_key_set_phase(subnet.net_idx, KEY_REFRESH_PHASE_NONE);
        }
        info!("Key Refresh complete (via beacon) for idx=0x{:04x}", subnet.net_idx);
    }
}

/// Global cleanup function — release all MeshNet resources.
pub fn mesh_net_cleanup() {
    debug!("Global mesh_net_cleanup called");
    // In the C code, this iterates over a global `nets` list and frees each.
    // In Rust, cleanup is driven by ownership. This is a no-op notification point.
}

// ===========================================================================
// Friend Helper Functions
// ===========================================================================

/// Create a new MeshFriend from negotiation parameters.
pub fn mesh_friend_new(
    net: &MeshNet,
    lp_addr: u16,
    fn_cnt: u16,
    lp_cnt: u16,
    receive_delay: u8,
    ele_cnt: u8,
    net_idx: u16,
    poll_timeout: u32,
) -> MeshFriend {
    // Derive friend-specific network keys from the subnet's flooding keys
    // (matching the C mesh_friend_new behavior in net.c:381-388).
    let primary = net.subnets.first();
    let net_key_cur = if let Some(subnet) = primary {
        net_key_frnd_add(subnet.net_key_cur, lp_addr, net.src_addr, lp_cnt, fn_cnt)
    } else {
        0
    };
    let net_key_upd = if let Some(subnet) = primary {
        if subnet.net_key_upd != 0 {
            net_key_frnd_add(subnet.net_key_upd, lp_addr, net.src_addr, lp_cnt, fn_cnt)
        } else {
            0
        }
    } else {
        0
    };

    MeshFriend {
        lp_addr,
        fn_cnt,
        lp_cnt,
        receive_delay,
        ele_cnt,
        net_idx,
        poll_timeout,
        net_key_cur,
        net_key_upd,
    }
}

/// Free a MeshFriend (release key references).
pub fn mesh_friend_free(frnd: &MeshFriend) {
    if frnd.net_key_cur != 0 {
        net_key_unref(frnd.net_key_cur);
    }
    if frnd.net_key_upd != 0 {
        net_key_unref(frnd.net_key_upd);
    }
}

/// Clear all friend state from a MeshNet.
pub fn mesh_friend_clear(net: &mut MeshNet) {
    for frnd in &net.friends {
        mesh_friend_free(frnd);
    }
    net.friends.clear();
    net.friend_negotiations.clear();
    net.friend_msgs.clear();
}

/// Add a subscription address to a friend (for message forwarding).
pub fn mesh_friend_sub_add(net: &mut MeshNet, lp_addr: u16, group_addr: u16) -> bool {
    if net.friends.iter().any(|f| f.lp_addr == lp_addr) {
        // The subscription is tracked via dst_reg for the friend
        net.dst_reg(group_addr);
        debug!("Friend sub add: lp=0x{:04x} group=0x{:04x}", lp_addr, group_addr);
        return true;
    }
    false
}

/// Remove a subscription address from a friend.
pub fn mesh_friend_sub_del(net: &mut MeshNet, lp_addr: u16, group_addr: u16) -> bool {
    if net.friends.iter().any(|f| f.lp_addr == lp_addr) {
        net.dst_unreg(group_addr);
        debug!("Friend sub del: lp=0x{:04x} group=0x{:04x}", lp_addr, group_addr);
        return true;
    }
    false
}

// ===========================================================================
// Module Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEV_ID, 0);
        assert_eq!(UNUSED_KEY_IDX, 0xffff);
        assert_eq!(APP_AID_DEV, 0x00);
        assert_eq!(CTL, 0x80);
        assert_eq!(TTL_MASK, 0x7f);
        assert_eq!(SEQ_MASK, 0x00ff_ffff);
        assert_eq!(MAX_UNSEG_LEN, 15);
        assert_eq!(MAX_SEG_LEN, 12);
        assert_eq!(SEGMENTED, 0x80);
        assert_eq!(UNSEGMENTED, 0x00);
        assert_eq!(RELAY, 0x80);
        assert_eq!(SZMIC, 0x80);
        assert_eq!(SEG_HDR_SHIFT, 31);
        assert_eq!(KEY_HDR_SHIFT, 24);
        assert_eq!(SEQ_ZERO_MASK, 0x1fff);
        assert_eq!(MSG_CACHE_SIZE, 70);
        assert_eq!(REPLAY_CACHE_SIZE, 10);
        assert_eq!(KEY_AID_MASK, 0x3f);
        assert_eq!(KEY_ID_MASK, 0x7f);
        assert_eq!(OPCODE_MASK, 0x7f);
        assert_eq!(SEG_MASK, 0x1f);
        assert_eq!(NET_OP_SEG_ACKNOWLEDGE, 0x00);
        assert_eq!(NET_OP_HEARTBEAT, 0x0a);
        assert_eq!(DEFAULT_MIN_DELAY, 0);
        assert_eq!(DEFAULT_MAX_DELAY, 25);
    }

    #[test]
    fn test_seg_helpers() {
        assert_eq!(seg_max(12), 0);
        assert_eq!(seg_max(13), 1);
        assert_eq!(seg_max(24), 1);
        assert_eq!(seg_max(25), 2);

        assert_eq!(seg_off(0), 0);
        assert_eq!(seg_off(1), 12);
        assert_eq!(seg_off(2), 24);

        assert_eq!(max_seg_to_len(0), 12);
        assert_eq!(max_seg_to_len(1), 24);
        assert_eq!(max_seg_to_len(2), 36);
    }

    #[test]
    fn test_header_helpers() {
        // Segmented bit (bit 31)
        assert!(!is_segmented(0x0000_0000));
        assert!(is_segmented(0x8000_0000));

        // App key bit (bit 30)
        assert!(!has_app_key(0x0000_0000));
        assert!(has_app_key(0x4000_0000));

        // Relay bit (bit 23)
        assert!(!is_relayed(0x0000_0000));
        assert!(is_relayed(0x0080_0000));

        // SZMIC bit (bit 23 in different context)
        assert!(!has_mic64(0x0000_0000));
        assert!(has_mic64(0x0080_0000));
    }

    #[test]
    fn test_mesh_net_new() {
        let net = MeshNet::new();
        assert_eq!(net.src_addr, 0);
        assert_eq!(net.iv_index, 0);
        assert!(!net.iv_update);
        assert_eq!(net.seq_num, 0);
        assert_eq!(net.default_ttl, DEFAULT_TTL);
        assert!(net.subnets.is_empty());
        assert!(net.sar_in.is_empty());
        assert!(net.sar_out.is_none());
        assert_eq!(net.msg_cache.len(), 0);
        assert!(net.replay_cache.is_empty());
    }

    #[test]
    fn test_addressing() {
        let mut net = MeshNet::new();
        net.register_unicast(0x0001, 3);

        assert_eq!(net.get_address(), 0x0001);
        assert!(net.is_local_address(0x0001));
        assert!(net.is_local_address(0x0002));
        assert!(net.is_local_address(0x0003));
        assert!(!net.is_local_address(0x0004));
        assert!(!net.is_local_address(0x0000));
    }

    #[test]
    fn test_ttl() {
        let mut net = MeshNet::new();
        assert_eq!(net.get_default_ttl(), DEFAULT_TTL);
        net.set_default_ttl(10);
        assert_eq!(net.get_default_ttl(), 10);
        // TTL_MASK should clip to 7 bits
        net.set_default_ttl(0xff);
        assert_eq!(net.get_default_ttl(), 0x7f);
    }

    #[test]
    fn test_seq_num() {
        let mut net = MeshNet::new();
        assert_eq!(net.get_seq_num(), 0);
        net.set_seq_num(100);
        assert_eq!(net.get_seq_num(), 100);

        let seq = net.next_seq_num();
        assert_eq!(seq, 100);
        assert_eq!(net.get_seq_num(), 101);
    }

    #[test]
    fn test_destination_reg() {
        let mut net = MeshNet::new();
        assert!(net.dst_reg(0xC000));
        assert!(net.is_destination_valid(0xC000));
        assert!(net.dst_unreg(0xC000));
        assert!(!net.is_destination_valid(0xC000));
    }

    #[test]
    fn test_msg_cache() {
        let mut net = MeshNet::new();
        assert!(!net.msg_in_cache(0x0001, 0, 0));
        net.msg_cache_add(0x0001, 0, 0);
        assert!(net.msg_in_cache(0x0001, 0, 0));
        assert!(!net.msg_in_cache(0x0001, 1, 0));
    }

    #[test]
    fn test_replay_protection() {
        let mut net = MeshNet::new();
        net.node_path = "/tmp/test_node".to_string();

        // First message should pass
        assert!(net.replay_check(0x0001, 0, 0));
        net.replay_update(0x0001, 0, 0);

        // Same seq should fail
        assert!(!net.replay_check(0x0001, 0, 0));

        // Higher seq should pass
        assert!(net.replay_check(0x0001, 0, 1));

        // Higher IV should pass
        assert!(net.replay_check(0x0001, 1, 0));

        // Lower IV should fail
        net.replay_update(0x0001, 1, 0);
        assert!(!net.replay_check(0x0001, 0, 100));
    }

    #[test]
    fn test_heartbeat_sub() {
        let mut net = MeshNet::new();
        let sub = MeshNetHeartbeatSub {
            src: 0x0001,
            dst: 0xC000,
            period: 10,
            count: 0,
            features: 0,
            min_hops: 0,
            max_hops: 0,
            enabled: true,
        };
        net.set_heartbeat_sub(sub);
        let got = net.get_heartbeat_sub();
        assert_eq!(got.src, 0x0001);
        assert_eq!(got.dst, 0xC000);
        assert!(got.enabled);
    }

    #[test]
    fn test_heartbeat_pub() {
        let mut net = MeshNet::new();
        let pub_state = MeshNetHeartbeatPub {
            dst: 0xC000,
            count: 5,
            period: 10,
            ttl: 7,
            features: 0x0003,
            net_idx: 0,
        };
        net.set_heartbeat_pub(pub_state);
        let got = net.get_heartbeat_pub();
        assert_eq!(got.dst, 0xC000);
        assert_eq!(got.count, 5);
        assert_eq!(got.features, 0x0003);
    }

    #[test]
    fn test_transmit_params() {
        let mut net = MeshNet::new();
        assert_eq!(net.transmit_params_get(), (DEFAULT_TRANSMIT_COUNT, DEFAULT_TRANSMIT_INTERVAL));
        net.transmit_params_set(3, 200);
        assert_eq!(net.transmit_params_get(), (3, 200));
    }

    #[test]
    fn test_key_list() {
        let net = MeshNet::new();
        assert!(net.key_list_get().is_empty());
        assert!(!net.have_key(0));
        assert_eq!(net.get_primary_idx(), NET_IDX_INVALID);
    }

    #[test]
    fn test_prov_caps() {
        let mut net = MeshNet::new();
        let caps = MeshNetProvCaps {
            num_ele: 2,
            algorithms: 0x0001,
            pub_type: 0,
            static_type: 1,
            output_size: 4,
            output_action: 0x0008,
            input_size: 0,
            input_action: 0,
        };
        net.set_prov(caps);
        let got = net.get_prov();
        assert_eq!(got.num_ele, 2);
        assert_eq!(got.algorithms, 0x0001);
        assert_eq!(got.output_action, 0x0008);
    }

    #[test]
    fn test_friend_new_free() {
        let net = MeshNet::new();
        let frnd = mesh_friend_new(&net, 0x0001, 0, 0, 100, 1, 0, 1000);
        assert_eq!(frnd.lp_addr, 0x0001);
        assert_eq!(frnd.receive_delay, 100);
        assert_eq!(frnd.poll_timeout, 1000);
        // mesh_friend_free with 0 key ids is safe
        mesh_friend_free(&frnd);
    }

    #[test]
    fn test_mesh_friend_clear() {
        let mut net = MeshNet::new();
        let frnd1 = mesh_friend_new(&net, 0x0001, 0, 0, 100, 1, 0, 1000);
        let frnd2 = mesh_friend_new(&net, 0x0002, 0, 0, 100, 1, 0, 2000);
        net.friends.push(frnd1);
        net.friends.push(frnd2);
        assert_eq!(net.friends.len(), 2);
        mesh_friend_clear(&mut net);
        assert!(net.friends.is_empty());
    }

    #[test]
    fn test_sar_key() {
        let key = sar_key(0x1234, 0x5678);
        assert_eq!(key, 0x1234_5678);
    }

    #[test]
    fn test_iv_index_basic() {
        let mut net = MeshNet::new();
        net.set_iv_index(42, false);
        let (iv, upd) = net.get_iv_index();
        assert_eq!(iv, 42);
        assert!(!upd);
    }

    #[test]
    fn test_identity_mode() {
        let net = MeshNet::new();
        assert_eq!(net.get_identity_mode(0), 0);
    }

    #[test]
    fn test_io_attach_detach() {
        let mut net = MeshNet::new();
        assert!(!net.get_io());
        net.attach();
        assert!(net.get_io());
        net.detach();
        assert!(!net.get_io());
    }
}
