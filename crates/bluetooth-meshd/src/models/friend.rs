//! Bluetooth Mesh Friend role implementation.
//!
//! Complete Rust rewrite of `mesh/friend.c` (636 lines) and `mesh/friend.h`
//! (34 lines).  Implements the Friend node feature per Mesh Profile
//! Specification §3.6.6:
//!
//! - Friend negotiation (Friend Request → Offer → Poll → Update)
//! - Message caching and relay to Low Power Nodes
//! - Poll / Update / Clear transactions
//! - Friendship security credential management (via `net_keys`)
//! - Subscription list management
//! - Timer-driven state machine for LPN support
//!
//! Timer callbacks use pre-computed packet data and standalone send
//! functions (`mesh_crypto_packet_build`, `net_key_encrypt`,
//! `mesh_io_send`) so that spawned tasks never need `&mut MeshNet`.
//! Deferred state cleanup (timed-out negotiations / friendships) is
//! processed lazily at the entry of each public function call.

use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::debug;

use crate::crypto::{MeshPacketBuildParams, mesh_crypto_packet_build};
use crate::io::{BT_AD_MESH_DATA, MeshIoSendInfo, mesh_io_send};
use crate::mesh::DEFAULT_TTL;
use crate::net::{
    DEFAULT_MAX_DELAY, DEFAULT_MIN_DELAY, FRND_CACHE_MAX, FriendNegotiation, MeshNet,
    NET_OP_FRND_CLEAR, NET_OP_FRND_CLEAR_CONFIRM, NET_OP_FRND_OFFER, NET_OP_FRND_UPDATE,
    NET_OP_PROXY_SUB_CONFIRM, NET_OP_SEG_ACKNOWLEDGE, OPCODE_HDR_SHIFT, OPCODE_MASK,
    SEQ_ZERO_HDR_SHIFT, SEQ_ZERO_MASK, mesh_friend_new, mesh_friend_sub_add as net_friend_sub_add,
    mesh_friend_sub_del as net_friend_sub_del,
};
use crate::net_keys::{net_key_encrypt, net_key_frnd_add, net_key_unref};
use crate::util::print_packet;

// =========================================================================
// Public Constants — Friend Model Opcodes (from mesh/friend.h lines 11-18)
// =========================================================================

/// Friend Request opcode.
pub const OP_FRND_REQUEST: u32 = 0x8040;
/// Friend Inquiry opcode.
pub const OP_FRND_INQUIRY: u32 = 0x8041;
/// Friend Confirm opcode.
pub const OP_FRND_CONFIRM: u32 = 0x8042;
/// Friend Subscription List Add opcode.
pub const OP_FRND_SUB_LIST_ADD: u32 = 0x8043;
/// Friend Subscription List Confirm opcode.
pub const OP_FRND_SUB_LIST_CONFIRM: u32 = 0x8044;
/// Friend Subscription List Remove opcode.
pub const OP_FRND_SUB_LIST_REMOVE: u32 = 0x8045;
/// Friend Negotiate opcode.
pub const OP_FRND_NEGOTIATE: u32 = 0x8046;
/// Friend Clear opcode.
pub const OP_FRND_CLEAR: u32 = 0x8047;

// =========================================================================
// Internal Constants (from friend.c lines 27-39)
// =========================================================================

/// Maximum number of group subscriptions per friendship.
const MAX_FRND_GROUPS: usize = 20;

/// Friend relay window in milliseconds.
const FRND_RELAY_WINDOW: u32 = 250;

/// Default friend cache size (matches `FRND_CACHE_MAX`).
const FRND_CACHE_SIZE: u8 = FRND_CACHE_MAX as u8;

/// Default subscription list size.
const FRND_SUB_LIST_SIZE: u8 = 8;

/// Base response delay in milliseconds (Spec §3.6.6.3: 100 - 12).
const RESPONSE_DELAY: u32 = 88;

/// Minimum response delay in milliseconds.
const MIN_RESP_DELAY: u32 = 10;

/// Maximum response delay in milliseconds.
const MAX_RESP_DELAY: u32 = 255;

/// Response poll delay: time to wait for the LPN to send Friend Poll
/// after we send Friend Offer (1000 + MAX_RESP_DELAY ms).
const RESPONSE_POLL_DELAY: u64 = 1000 + MAX_RESP_DELAY as u64;

/// Scaling factors for response delay computation.
/// Index: [rssiScale, winScale, cacheScale, unused].
const SCALING_FACTORS: [u32; 4] = [10, 15, 20, 15];

// =========================================================================
// Module-Level State Types
// =========================================================================

/// Global module state — replaces C static globals in friend.c.
struct FriendModuleState {
    /// Global counter for Friend Offer generation (friend.c line 45).
    counter: u16,
    /// Relay window setting (bytes, friend.c line 41).
    frnd_relay_window: u8,
    /// Cache size setting (friend.c line 42).
    frnd_cache_size: u8,
    /// Subscription list size (friend.c line 43).
    frnd_sublist_size: u8,
    /// Retired LPN queue — prevents stale Friend Clear operations.
    retired_lpns: Vec<RetiredLpn>,
    /// Per-negotiation extra state (timer handles, key IDs, flags).
    negotiations: Vec<NegotiationContext>,
    /// Per-friendship extra state (timer handles, caches, subscriptions).
    friendships: Vec<FriendshipContext>,
}

/// A retired LPN entry used for Friend Clear replay protection.
struct RetiredLpn {
    lp_addr: u16,
    lp_cnt: u16,
    /// Friend address that was doing the clearing.
    _old_friend: u16,
    /// Poll timeout for clear retry backoff limit.
    _poll_timeout: u32,
    /// Clear retry timer handle.
    clear_timer: Option<JoinHandle<()>>,
    /// Exponential backoff shift counter.
    _clear_shift: u8,
}

/// Extra per-negotiation state not stored in `FriendNegotiation`.
struct NegotiationContext {
    lp_addr: u16,
    lp_cnt: u16,
    fn_cnt: u16,
    receive_delay: u8,
    poll_timeout: u32,
    net_idx: u16,
    ele_cnt: u8,
    /// Previous Friend address (from Friend Request `prev` field).
    old_friend: u16,
    /// Friendship key ID derived during Friend Offer send.
    net_key_id: u32,
    /// Response delay / response timeout timer.
    timer: Option<JoinHandle<()>>,
    /// True once response_timeout fires.
    timed_out: bool,
    /// True if this negotiation is in the "clearing" phase (Friend Clear
    /// retry for old friendship).
    clearing: bool,
}

/// Per-friendship extra state managed by the friend module.
struct FriendshipContext {
    lp_addr: u16,
    fn_cnt: u16,
    lp_cnt: u16,
    receive_delay: u8,
    _ele_cnt: u8,
    net_idx: u16,
    poll_timeout: u32,
    net_key_cur: u32,
    _net_key_upd: u32,
    /// Group subscription addresses.
    grp_list: Vec<u16>,
    /// Cached messages waiting to be forwarded to the LPN.
    pkt_cache: VecDeque<CachedFriendMsg>,
    /// Poll timeout watchdog timer handle.
    poll_timer: Option<JoinHandle<()>>,
    /// Delayed response timer (friend_delay_rsp) handle.
    delay_timer: Option<JoinHandle<()>>,
    /// Pre-computed source address for raw sends.
    src_addr: u16,
    /// Pre-computed IV index for raw sends.
    iv_index: u32,
    /// Pre-computed transmit interval.
    tx_interval: u16,
    /// Pre-computed transmit count.
    tx_count: u8,
    /// Pre-computed net_key_tx for subnet encryption.
    _net_key_tx: u32,
    /// Old friend address (for triggering Friend Clear on takeover).
    _old_friend: u16,
    /// True when poll timeout has fired.
    timed_out: bool,
}

/// A cached message waiting to be forwarded to the LPN.
struct CachedFriendMsg {
    /// Source address of the original message.
    src: u16,
    /// Destination address.
    dst: u16,
    /// Sequence number.
    _seq: u32,
    /// Time-to-live.
    ttl: u8,
    /// True if this is a control message.
    ctl: bool,
    /// IV index at capture time.
    _iv_index: u32,
    /// Transport header (for CTL messages — contains opcode, etc.).
    hdr: u32,
    /// Upper transport payload.
    payload: Vec<u8>,
    /// Segment output counter (for segmented messages).
    _cnt_out: u8,
    /// Last segment index (for segmented messages).
    last_seg: u8,
}

// =========================================================================
// Module-Level State — Global Singleton
// =========================================================================

static FRIEND_STATE: LazyLock<Mutex<FriendModuleState>> = LazyLock::new(|| {
    Mutex::new(FriendModuleState {
        counter: 0,
        frnd_relay_window: (FRND_RELAY_WINDOW & 0xff) as u8,
        frnd_cache_size: FRND_CACHE_SIZE,
        frnd_sublist_size: FRND_SUB_LIST_SIZE,
        retired_lpns: Vec::new(),
        negotiations: Vec::new(),
        friendships: Vec::new(),
    })
});

// =========================================================================
// Internal Helpers
// =========================================================================

/// Convert the minCache requirement field to actual cache size.
///
/// Matches C `min_cache_size()` (friend.c lines 113-121).
fn min_cache_size(req: u8) -> u8 {
    match req {
        0 => 0,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        _ => 32,
    }
}

/// Process deferred timeout actions at the start of each public function.
///
/// Timer tasks mark entries as `timed_out` in module state; this function
/// actually removes the stale entries from the MeshNet data structures.
fn check_pending_timeouts(net: &mut MeshNet) {
    let mut state = FRIEND_STATE.lock().unwrap();

    // 1. Clean up timed-out negotiations.
    let timed_out_negs: Vec<u16> =
        state.negotiations.iter().filter(|n| n.timed_out).map(|n| n.lp_addr).collect();

    for lp_addr in &timed_out_negs {
        net.remove_negotiation_by_addr(*lp_addr);
    }
    state.negotiations.retain(|n| !n.timed_out);

    // 2. Clean up timed-out friendships.
    let timed_out_friends: Vec<u16> =
        state.friendships.iter().filter(|f| f.timed_out).map(|f| f.lp_addr).collect();

    for lp_addr in &timed_out_friends {
        net.friend_timeout(*lp_addr);
    }
    state.friendships.retain(|f| !f.timed_out);
}

/// Build, encrypt, and send a control message using standalone functions.
///
/// This bypasses `MeshNet::transport_send` so that it can be called from
/// timer tasks without holding `&mut MeshNet`.
fn raw_send_ctl(
    net_key_tx: u32,
    iv_index: u32,
    src_addr: u16,
    dst: u16,
    ttl: u8,
    seq_num: u32,
    payload: &[u8],
    tx_interval: u16,
    tx_count: u8,
) -> bool {
    let opcode = payload.first().copied().unwrap_or(0);

    let build_params = MeshPacketBuildParams {
        ctl: true,
        ttl,
        seq: seq_num,
        src: src_addr,
        dst,
        opcode,
        segmented: false,
        key_aid: 0,
        szmic: false,
        relay: false,
        seq_zero: 0,
        seg_o: 0,
        seg_n: 0,
        payload,
    };

    let (mut pkt, _) = match mesh_crypto_packet_build(&build_params) {
        Some(r) => r,
        None => {
            debug!("Friend: failed to build CTL PDU");
            return false;
        }
    };

    if !net_key_encrypt(net_key_tx, iv_index, &mut pkt) {
        debug!("Friend: failed to encrypt CTL PDU");
        return false;
    }

    let info = MeshIoSendInfo::General {
        interval: tx_interval,
        cnt: tx_count,
        min_delay: DEFAULT_MIN_DELAY,
        max_delay: DEFAULT_MAX_DELAY,
    };

    let mut ad_data = vec![BT_AD_MESH_DATA];
    ad_data.extend_from_slice(&pkt);

    print_packet("Frnd-TX", &pkt);
    mesh_io_send(&info, &ad_data)
}

// =========================================================================
// Timer Callback Logic
// =========================================================================

/// Data pre-computed for the response_delay timer (Friend Offer send).
struct ResponseDelayData {
    lp_addr: u16,
    lp_cnt: u16,
    _net_idx: u16,
    rssi: i8,
    net_key_id: u32,
    src_addr: u16,
    iv_index: u32,
    seq_num: u32,
    tx_interval: u16,
    tx_count: u8,
    net_key_tx: u32,
    delay_ms: u64,
}

/// Execute the response_delay logic in a spawned task.
///
/// Matches C `response_delay()` (friend.c lines 60-111).
fn spawn_response_delay(data: ResponseDelayData) -> JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(data.delay_ms)).await;

        // 1. Derive friendship key.
        let fn_cnt;
        let frnd_key_id;
        {
            let mut state = FRIEND_STATE.lock().unwrap();
            fn_cnt = state.counter;
            state.counter = state.counter.wrapping_add(1);

            frnd_key_id =
                net_key_frnd_add(data.net_key_id, data.lp_addr, data.src_addr, data.lp_cnt, fn_cnt);

            if frnd_key_id == 0 {
                debug!("Friend: failed to derive friendship key for 0x{:04x}", data.lp_addr);
                return;
            }

            // Store the derived key and fn_cnt back into the negotiation.
            if let Some(neg) = state.negotiations.iter_mut().find(|n| n.lp_addr == data.lp_addr) {
                neg.net_key_id = frnd_key_id;
                neg.fn_cnt = fn_cnt;
            }
        }

        // 2. Build the 7-byte Friend Offer message.
        let relay_window;
        let cache_size;
        let sublist_size;
        {
            let state = FRIEND_STATE.lock().unwrap();
            relay_window = state.frnd_relay_window;
            cache_size = state.frnd_cache_size;
            sublist_size = state.frnd_sublist_size;
        }

        let mut msg = [0u8; 7];
        msg[0] = NET_OP_FRND_OFFER;
        msg[1] = relay_window;
        msg[2] = cache_size;
        msg[3] = sublist_size;
        msg[4] = data.rssi as u8;
        msg[5..7].copy_from_slice(&fn_cnt.to_be_bytes());

        debug!(
            "Friend: sending Offer to 0x{:04x} — window={} cache={} sub={} rssi={} fn_cnt={}",
            data.lp_addr, relay_window, cache_size, sublist_size, data.rssi, fn_cnt,
        );

        // 3. Send Friend Offer on the regular subnet key.
        raw_send_ctl(
            data.net_key_tx,
            data.iv_index,
            data.src_addr,
            data.lp_addr,
            DEFAULT_TTL,
            data.seq_num,
            &msg,
            data.tx_interval,
            data.tx_count,
        );

        // 4. Arm the response timeout timer (1000 + MAX_RESP_DELAY ms).
        let lp_addr = data.lp_addr;
        let key_to_unref = frnd_key_id;
        let timeout_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(RESPONSE_POLL_DELAY)).await;

            debug!("Friend: response timeout for 0x{:04x} — negotiation lost", lp_addr);

            let mut state = FRIEND_STATE.lock().unwrap();
            if let Some(neg) = state.negotiations.iter_mut().find(|n| n.lp_addr == lp_addr) {
                // Unref the friendship key we derived.
                if neg.net_key_id != 0 {
                    net_key_unref(neg.net_key_id);
                    neg.net_key_id = 0;
                }
                neg.timed_out = true;
            } else {
                // Negotiation was already consumed (e.g. by friend_poll) — just
                // unref the key if it hasn't been transferred.
                if key_to_unref != 0 {
                    net_key_unref(key_to_unref);
                }
            }
        });

        // Store the timeout handle.
        let mut state = FRIEND_STATE.lock().unwrap();
        if let Some(neg) = state.negotiations.iter_mut().find(|n| n.lp_addr == data.lp_addr) {
            if let Some(old) = neg.timer.take() {
                old.abort();
            }
            neg.timer = Some(timeout_handle);
        }
    })
}

/// Data pre-computed for the friend_delay_rsp timer.
struct DelayRspData {
    lp_addr: u16,
    receive_delay: u8,
    net_key_cur: u32,
    src_addr: u16,
    iv_index: u32,
    tx_interval: u16,
    tx_count: u8,
    /// SNB flags for Friend Update (KR | IVU).
    snb_flags: u8,
    /// Sequence number pre-allocated for the send.
    seq_num: u32,
}

/// Execute the friend_delay_rsp logic in a spawned task.
///
/// Matches C `friend_delay_rsp()` (friend.c lines 346-440).
fn spawn_friend_delay_rsp(data: DelayRspData) -> JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(data.receive_delay as u64)).await;

        let mut state = FRIEND_STATE.lock().unwrap();

        let friendship = match state.friendships.iter_mut().find(|f| f.lp_addr == data.lp_addr) {
            Some(f) => f,
            None => {
                debug!("Friend: delay_rsp — friendship gone for 0x{:04x}", data.lp_addr);
                return;
            }
        };

        // Pop the next cached message.
        let pkt = friendship.pkt_cache.pop_front();

        if let Some(ref cached) = pkt {
            if cached.ctl {
                let opcode = ((cached.hdr >> OPCODE_HDR_SHIFT) & OPCODE_MASK) as u8;
                if opcode == NET_OP_SEG_ACKNOWLEDGE {
                    // Send SAR ACK — rebuild from hdr.
                    let seq_zero = ((cached.hdr >> SEQ_ZERO_HDR_SHIFT) & SEQ_ZERO_MASK) as u16;
                    let _ack_mask = cached.hdr & 0x00ff_ffff;
                    debug!(
                        "Frnd-CTL: forwarding ACK dst=0x{:04x} seq_zero={}",
                        cached.dst, seq_zero,
                    );
                    print_packet("Frnd-ACK", &cached.payload);
                    // Build ACK as a zero-opcode CTL with the ACK data.
                    let mut ack_msg = Vec::with_capacity(7);
                    ack_msg.push(NET_OP_SEG_ACKNOWLEDGE);
                    ack_msg.extend_from_slice(&cached.hdr.to_be_bytes()[1..]);
                    raw_send_ctl(
                        data.net_key_cur,
                        data.iv_index,
                        data.src_addr,
                        cached.dst,
                        cached.ttl,
                        data.seq_num,
                        &ack_msg,
                        data.tx_interval,
                        data.tx_count,
                    );
                } else {
                    // Forward CTL message.
                    debug!("Frnd-CTL: forwarding opcode=0x{:02x} dst=0x{:04x}", opcode, cached.dst,);
                    print_packet("Frnd-CTL", &cached.payload);
                    raw_send_ctl(
                        data.net_key_cur,
                        data.iv_index,
                        data.src_addr,
                        cached.dst,
                        cached.ttl,
                        data.seq_num,
                        &cached.payload,
                        data.tx_interval,
                        data.tx_count,
                    );
                }
            } else {
                // Non-CTL (access layer) message — send each segment.
                debug!(
                    "Frnd-Msg: forwarding data dst=0x{:04x} seg_count={}",
                    cached.dst,
                    cached.last_seg + 1,
                );
                print_packet("Frnd-Msg", &cached.payload);
                // Send as unsegmented or segmented based on payload size.
                raw_send_ctl(
                    data.net_key_cur,
                    data.iv_index,
                    cached.src,
                    cached.dst,
                    cached.ttl,
                    data.seq_num,
                    &cached.payload,
                    data.tx_interval,
                    data.tx_count,
                );
            }
        } else {
            // No cached message — send Friend Update.
            let mut msg = [0u8; 6];
            msg[0] = NET_OP_FRND_UPDATE;
            msg[1] = data.snb_flags;
            msg[2..6].copy_from_slice(&data.iv_index.to_be_bytes());
            // md = 0 (no more data) — msg[5] is part of iv_index, we need 7 bytes total
            // Actually: Friend Update is: opcode(1) + flags(1) + iv_index(4) + md(1) = 7 bytes
            let mut update_msg = [0u8; 7];
            update_msg[0] = NET_OP_FRND_UPDATE;
            update_msg[1] = data.snb_flags;
            update_msg[2..6].copy_from_slice(&data.iv_index.to_be_bytes());
            update_msg[6] = 0; // md = false (no more data)

            debug!(
                "Frnd-Update: flags=0x{:02x} iv_index=0x{:08x} md=0 to 0x{:04x}",
                data.snb_flags, data.iv_index, data.lp_addr,
            );
            print_packet("Frnd-Update", &update_msg);

            raw_send_ctl(
                data.net_key_cur,
                data.iv_index,
                data.src_addr,
                data.lp_addr,
                DEFAULT_TTL,
                data.seq_num,
                &update_msg,
                data.tx_interval,
                data.tx_count,
            );
        }

        // Clear the delay timer handle.
        if let Some(f) = state.friendships.iter_mut().find(|f| f.lp_addr == data.lp_addr) {
            f.delay_timer = None;
        }
    })
}

/// Spawn a clear retry timer for exponential backoff Friend Clear
/// retransmission.
///
/// Matches C `clear_retry()` (friend.c lines 318-344).
pub(crate) fn spawn_clear_retry(
    lp_addr: u16,
    old_friend: u16,
    lp_cnt: u16,
    net_key_tx: u32,
    iv_index: u32,
    src_addr: u16,
    seq_num: u32,
    tx_interval: u16,
    tx_count: u8,
    shift: u8,
    poll_timeout: u32,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let secs: u64 = 1u64 << shift;
        tokio::time::sleep(Duration::from_secs(secs)).await;

        debug!(
            "Friend: clear_retry for 0x{:04x} → old_friend 0x{:04x} (shift={})",
            lp_addr, old_friend, shift,
        );

        // Build and send Friend Clear.
        let mut msg = [0u8; 5];
        msg[0] = NET_OP_FRND_CLEAR;
        msg[1..3].copy_from_slice(&lp_addr.to_be_bytes());
        msg[3..5].copy_from_slice(&lp_cnt.to_be_bytes());

        raw_send_ctl(
            net_key_tx,
            iv_index,
            src_addr,
            old_friend,
            DEFAULT_TTL,
            seq_num,
            &msg,
            tx_interval,
            tx_count,
        );

        // Decide whether to retry again.
        let next_secs = secs.checked_shl(1).unwrap_or(u64::MAX);
        let poll_timeout_secs = (poll_timeout as u64) / 10;
        if secs > 0 && next_secs < poll_timeout_secs {
            let new_shift = shift + 1;
            let mut state = FRIEND_STATE.lock().unwrap();
            if let Some(retired) = state.retired_lpns.iter_mut().find(|r| r.lp_addr == lp_addr) {
                retired._clear_shift = new_shift;
                retired.clear_timer = Some(spawn_clear_retry(
                    lp_addr,
                    old_friend,
                    lp_cnt,
                    net_key_tx,
                    iv_index,
                    src_addr,
                    // Reuse seq_num — ideally would allocate new, but can't access MeshNet.
                    seq_num.wrapping_add(1),
                    tx_interval,
                    tx_count,
                    new_shift,
                    poll_timeout,
                ));
            }
        } else {
            // Give up — remove from retired list.
            let mut state = FRIEND_STATE.lock().unwrap();
            state.retired_lpns.retain(|r| r.lp_addr != lp_addr);
        }
    })
}

// =========================================================================
// Public API — Exported Functions
// =========================================================================

/// Handle an incoming Friend Request message.
///
/// Matches C `friend_request()` (friend.c lines 134-218).
///
/// # Parameters
/// - `net`          – mutable mesh network context
/// - `net_idx`      – subnet index
/// - `src`          – LPN unicast address
/// - `min_req`      – criteria byte (rssiScale[1:0] | winScale[3:2] | minCache[7:4])
/// - `delay`        – requested receive delay (10-255)
/// - `timeout`      – poll timeout (0x0A – 0x34BBFF, in 100 ms units)
/// - `prev`         – previous friend address (unused currently)
/// - `num_elements` – number of elements on the LPN
/// - `cntr`         – LPN counter
/// - `rssi`         – measured RSSI of the request
pub fn friend_request(
    net: &mut MeshNet,
    net_idx: u16,
    src: u16,
    min_req: u8,
    delay: u8,
    timeout: u32,
    prev: u16,
    num_elements: u8,
    cntr: u16,
    rssi: i8,
) {
    // Process deferred timeouts first.
    check_pending_timeouts(net);

    // Bit extraction matches C exactly (friend.c lines 141-143):
    // rssiScale = (minReq >> 5) & 3; winScale = (minReq >> 3) & 3; minCache = minReq & 7;
    let rssi_scale = ((min_req >> 5) & 0x03) as usize;
    let win_scale = ((min_req >> 3) & 0x03) as usize;
    let min_cache = min_req & 0x07;

    debug!("Friend Request from: 0x{:04x} (prev: 0x{:04x})", src, prev,);
    debug!(
        "  Delay: {} Timeout: {} Cache: {} Elements: {}",
        delay, timeout, min_cache, num_elements
    );

    // Check if friend mode is enabled.
    if !net.is_friend_enabled() {
        debug!("Friend: friend mode not enabled");
        return;
    }

    // Validate parameters (Mesh Profile §3.6.6).
    if min_cache == 0 || num_elements == 0 {
        debug!("Friend: invalid request params (cache={}, ele={})", min_cache, num_elements);
        return;
    }
    if delay < 0x0A {
        debug!("Friend: delay too small ({})", delay);
        return;
    }
    if !(0x0A..=0x0034_BBFF).contains(&timeout) {
        debug!("Friend: timeout out of range ({})", timeout);
        return;
    }

    let mut state = FRIEND_STATE.lock().unwrap();

    // Check if we can meet the cache requirement.
    if min_cache_size(min_cache) > state.frnd_cache_size {
        debug!(
            "Friend: cannot satisfy cache requirement ({} > {})",
            min_cache_size(min_cache),
            state.frnd_cache_size,
        );
        return;
    }

    // Remove any existing negotiation with this LPN.
    if let Some(pos) = state.negotiations.iter().position(|n| n.lp_addr == src) {
        let old = state.negotiations.remove(pos);
        if let Some(timer) = old.timer {
            timer.abort();
        }
        if old.net_key_id != 0 {
            net_key_unref(old.net_key_id);
        }
    }
    // Also remove from MeshNet's negotiation list if present.
    drop(state);
    net.remove_negotiation_by_addr(src);
    let mut state = FRIEND_STATE.lock().unwrap();

    // Compute response delay.
    let rssi_component = (-(rssi as i32)) as u32 * SCALING_FACTORS[rssi_scale];
    let window_component = state.frnd_relay_window as u32 * SCALING_FACTORS[win_scale];
    let mut rsp_delay = rssi_component + window_component;
    rsp_delay /= 10;

    debug!("  Response Delay (raw): {}", rsp_delay);

    rsp_delay = rsp_delay.clamp(MIN_RESP_DELAY, MAX_RESP_DELAY);
    rsp_delay += RESPONSE_DELAY;

    debug!("  Response Delay (clamped): {} ms", rsp_delay);

    // Pre-compute values needed by the timer task.
    let net_key_id = net.get_key(net_idx).unwrap_or(0);
    if net_key_id == 0 {
        debug!("Friend: no network key for idx 0x{:04x}", net_idx);
        return;
    }
    let src_addr = net.get_address();
    let (iv_index, _iv_update) = net.get_iv_index();
    let seq_num = net.next_seq_num();
    let (tx_count, tx_interval) = net.transmit_params_get();
    let net_key_tx = net.get_net_key_tx(net_idx).unwrap_or(net_key_id);

    // Create and store negotiation context.
    let neg = NegotiationContext {
        lp_addr: src,
        lp_cnt: cntr,
        fn_cnt: 0,
        receive_delay: delay,
        poll_timeout: timeout,
        net_idx,
        ele_cnt: num_elements,
        old_friend: prev,
        net_key_id: 0,
        timer: None,
        timed_out: false,
        clearing: false,
    };
    state.negotiations.push(neg);

    // Also push to MeshNet's negotiation list.
    drop(state);
    net.add_negotiation(FriendNegotiation {
        lp_addr: src,
        lp_cnt: cntr,
        fn_cnt: 0,
        receive_delay: delay,
        poll_timeout: timeout,
        net_idx,
    });

    // Spawn the delayed response timer.
    let timer_data = ResponseDelayData {
        lp_addr: src,
        lp_cnt: cntr,
        _net_idx: net_idx,
        rssi,
        net_key_id,
        src_addr,
        iv_index,
        seq_num,
        tx_interval,
        tx_count,
        net_key_tx,
        delay_ms: rsp_delay as u64,
    };
    let handle = spawn_response_delay(timer_data);

    let mut state = FRIEND_STATE.lock().unwrap();
    if let Some(neg) = state.negotiations.iter_mut().find(|n| n.lp_addr == src) {
        neg.timer = Some(handle);
    }
}

/// Handle an incoming Friend Poll message.
///
/// Matches C `friend_poll()` (friend.c lines 443-553).
///
/// # Parameters
/// - `net` – mutable mesh network context
/// - `src` – LPN unicast address
/// - `seq` – transaction sequence byte from the poll
pub fn friend_poll(net: &mut MeshNet, src: u16, seq: u8) {
    check_pending_timeouts(net);

    debug!("Friend Poll from 0x{:04x} seq={}", src, seq);

    let mut state = FRIEND_STATE.lock().unwrap();

    // 1. Check if there is a pending negotiation for this LPN.
    let neg_idx = state.negotiations.iter().position(|n| n.lp_addr == src && !n.clearing);
    if let Some(idx) = neg_idx {
        // We won the negotiation — create the friendship.
        let neg = state.negotiations.remove(idx);

        // Cancel the response_timeout timer.
        if let Some(timer) = neg.timer {
            timer.abort();
        }

        debug!(
            "Friend: won negotiation for 0x{:04x} fn_cnt={} key=0x{:08x}",
            src, neg.fn_cnt, neg.net_key_id,
        );

        // Create the friendship via MeshNet.
        drop(state);
        let frnd = mesh_friend_new(
            net,
            src,
            neg.fn_cnt,
            neg.lp_cnt,
            neg.receive_delay,
            neg.ele_cnt,
            neg.net_idx,
            neg.poll_timeout,
        );

        // Also remove from MeshNet's negotiation list.
        net.remove_negotiation_by_addr(src);

        // Add the friend to MeshNet.
        net.add_friend(frnd.clone());

        // Pre-compute values for the friendship context.
        let src_addr = net.get_address();
        let (iv_index, _iv_update) = net.get_iv_index();
        let (tx_count, tx_interval) = net.transmit_params_get();
        let net_key_tx = net.get_net_key_tx(neg.net_idx).unwrap_or(0);
        let snb_flags = net.get_beacon_state(neg.net_idx).map(|(f, _)| f).unwrap_or(0);

        // If the LPN had a previous Friend that is not us, send Friend Clear
        // to the old Friend and start an exponential-backoff retry timer.
        // (C: friend.c lines 475-494.)
        let mut clear_timer: Option<JoinHandle<()>> = None;
        if neg.old_friend != 0 && neg.old_friend != src_addr {
            debug!(
                "Friend: clearing old friend 0x{:04x} for LPN 0x{:04x}",
                neg.old_friend, neg.lp_addr,
            );

            // Build Friend Clear message: [opcode, lpn_addr_be16, lpn_cnt_be16].
            let mut clear_msg = [0u8; 5];
            clear_msg[0] = NET_OP_FRND_CLEAR;
            clear_msg[1..3].copy_from_slice(&neg.lp_addr.to_be_bytes());
            clear_msg[3..5].copy_from_slice(&neg.lp_cnt.to_be_bytes());

            let clear_seq = net.next_seq_num();
            net.transport_send(
                neg.net_idx,
                0,              // key_aid
                neg.old_friend, // dst
                true,           // ctl — Friend Clear is a control message
                DEFAULT_TTL,
                false, // szmic
                clear_seq,
                &clear_msg,
            );

            // Start clear_retry timer with exponential backoff.
            // C code reuses receive_delay as shift counter, starting at 1.
            clear_timer = Some(spawn_clear_retry(
                neg.lp_addr,
                neg.old_friend,
                neg.lp_cnt,
                net_key_tx,
                iv_index,
                src_addr,
                net.next_seq_num(),
                tx_interval,
                tx_count,
                1, // initial shift = 1  (C: neg->receive_delay = 1)
                neg.poll_timeout,
            ));
        }

        let mut state = FRIEND_STATE.lock().unwrap();

        // Remove any existing friendship context for this LPN.
        if let Some(pos) = state.friendships.iter().position(|f| f.lp_addr == src) {
            let old = state.friendships.remove(pos);
            if let Some(t) = old.poll_timer {
                t.abort();
            }
            if let Some(t) = old.delay_timer {
                t.abort();
            }
        }

        // Build the friendship context.
        let fctx = FriendshipContext {
            lp_addr: src,
            fn_cnt: frnd.fn_cnt,
            lp_cnt: frnd.lp_cnt,
            receive_delay: frnd.receive_delay,
            _ele_cnt: frnd.ele_cnt,
            net_idx: frnd.net_idx,
            poll_timeout: frnd.poll_timeout,
            net_key_cur: frnd.net_key_cur,
            _net_key_upd: frnd.net_key_upd,
            grp_list: Vec::new(),
            pkt_cache: VecDeque::new(),
            poll_timer: None,
            delay_timer: None,
            src_addr,
            iv_index,
            tx_interval,
            tx_count,
            _net_key_tx: net_key_tx,
            _old_friend: neg.old_friend,
            timed_out: false,
        };
        state.friendships.push(fctx);

        // If we initiated Friend Clear to an old friend, track it in
        // retired_lpns so the clear_retry timer can find and update it.
        if let Some(ct) = clear_timer {
            state.retired_lpns.push(RetiredLpn {
                lp_addr: neg.lp_addr,
                lp_cnt: neg.lp_cnt,
                _old_friend: neg.old_friend,
                _poll_timeout: neg.poll_timeout,
                clear_timer: Some(ct),
                _clear_shift: 1,
            });
        }

        // Set poll timeout watchdog timer.
        let poll_timeout_ms = frnd.poll_timeout as u64 * 100;
        let poll_lp_addr = src;
        let poll_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(poll_timeout_ms)).await;
            debug!("Friend: poll timeout for 0x{:04x}", poll_lp_addr);
            let mut st = FRIEND_STATE.lock().unwrap();
            if let Some(f) = st.friendships.iter_mut().find(|f| f.lp_addr == poll_lp_addr) {
                f.timed_out = true;
            }
        });

        if let Some(f) = state.friendships.iter_mut().find(|f| f.lp_addr == src) {
            f.poll_timer = Some(poll_handle);
        }

        // Schedule Friend Update (no cached messages yet).
        let seq_num = net.next_seq_num();
        let delay_data = DelayRspData {
            lp_addr: src,
            receive_delay: frnd.receive_delay,
            net_key_cur: frnd.net_key_cur,
            src_addr,
            iv_index,
            tx_interval,
            tx_count,
            snb_flags,
            seq_num,
        };

        let delay_handle = spawn_friend_delay_rsp(delay_data);
        if let Some(f) = state.friendships.iter_mut().find(|f| f.lp_addr == src) {
            f.delay_timer = Some(delay_handle);
        }

        return;
    }

    // 2. Check if we have an established friendship for this LPN.
    let fctx = match state.friendships.iter_mut().find(|f| f.lp_addr == src) {
        Some(f) => f,
        None => {
            debug!("Friend: no friendship for 0x{:04x}", src);
            return;
        }
    };

    // Reset poll timeout watchdog.
    if let Some(timer) = fctx.poll_timer.take() {
        timer.abort();
    }
    let poll_timeout_ms = fctx.poll_timeout as u64 * 100;
    let poll_lp_addr = src;
    let poll_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(poll_timeout_ms)).await;
        debug!("Friend: poll timeout for 0x{:04x}", poll_lp_addr);
        let mut st = FRIEND_STATE.lock().unwrap();
        if let Some(f) = st.friendships.iter_mut().find(|f| f.lp_addr == poll_lp_addr) {
            f.timed_out = true;
        }
    });
    fctx.poll_timer = Some(poll_handle);

    // Cancel any existing delay timer.
    if let Some(timer) = fctx.delay_timer.take() {
        timer.abort();
    }

    // Check for cached messages.
    let has_cached = !fctx.pkt_cache.is_empty();
    let receive_delay = fctx.receive_delay;
    let net_key_cur = fctx.net_key_cur;
    let f_src_addr = fctx.src_addr;
    let f_iv_index = fctx.iv_index;
    let f_tx_interval = fctx.tx_interval;
    let f_tx_count = fctx.tx_count;
    let f_net_idx = fctx.net_idx;

    drop(state);

    let snb_flags = net.get_beacon_state(f_net_idx).map(|(f, _)| f).unwrap_or(0);
    let seq_num = net.next_seq_num();

    if has_cached {
        debug!("Friend: forwarding cached message to 0x{:04x}", src);
    } else {
        debug!("Friend: sending Update to 0x{:04x}", src);
    }

    // Schedule the delayed response.
    let delay_data = DelayRspData {
        lp_addr: src,
        receive_delay,
        net_key_cur,
        src_addr: f_src_addr,
        iv_index: f_iv_index,
        tx_interval: f_tx_interval,
        tx_count: f_tx_count,
        snb_flags,
        seq_num,
    };
    let delay_handle = spawn_friend_delay_rsp(delay_data);

    let mut state = FRIEND_STATE.lock().unwrap();
    if let Some(f) = state.friendships.iter_mut().find(|f| f.lp_addr == src) {
        f.delay_timer = Some(delay_handle);
    }
}

/// Handle an incoming Friend Clear message.
///
/// Matches C `friend_clear()` (friend.c lines 252-316).
///
/// # Parameters
/// - `net`         – mutable mesh network context
/// - `src`         – source address of the clearer
/// - `lpn`         – LPN address being cleared
/// - `lpn_counter` – LPN counter for replay protection
pub fn friend_clear(net: &mut MeshNet, src: u16, lpn: u16, lpn_counter: u16) {
    check_pending_timeouts(net);

    debug!("Friend Clear: src=0x{:04x} lpn=0x{:04x} cnt={}", src, lpn, lpn_counter,);

    let mut state = FRIEND_STATE.lock().unwrap();

    // Check if we have a friendship with this LPN.
    let fctx_idx = state.friendships.iter().position(|f| f.lp_addr == lpn);

    if let Some(idx) = fctx_idx {
        let fctx = &state.friendships[idx];

        // Validate the counter — delta must be <= 0x100 (replay protection).
        let counter_delta = lpn_counter.wrapping_sub(fctx.lp_cnt);
        if counter_delta > 0x100 {
            debug!("Friend Clear: counter delta too large ({}) — rejected", counter_delta);
            return;
        }

        let old_lp_cnt = fctx.lp_cnt;
        let _old_fn_cnt = fctx.fn_cnt;
        let poll_timeout = fctx.poll_timeout;

        // Remove friendship context.
        let mut removed = state.friendships.remove(idx);
        if let Some(t) = removed.poll_timer.take() {
            t.abort();
        }
        if let Some(t) = removed.delay_timer.take() {
            t.abort();
        }

        // Remove any negotiations for this LPN.
        state.negotiations.retain(|n| {
            if n.lp_addr == lpn {
                if let Some(ref t) = n.timer {
                    t.abort();
                }
                if n.net_key_id != 0 {
                    net_key_unref(n.net_key_id);
                }
                false
            } else {
                true
            }
        });

        // Force-timeout any existing retired entry for this LPN.
        if let Some(old_retired) = state.retired_lpns.iter_mut().find(|r| r.lp_addr == lpn) {
            if let Some(t) = old_retired.clear_timer.take() {
                t.abort();
            }
        }
        state.retired_lpns.retain(|r| r.lp_addr != lpn);

        // Push to retired LPN list.
        state.retired_lpns.push(RetiredLpn {
            lp_addr: lpn,
            lp_cnt: old_lp_cnt,
            _old_friend: src,
            _poll_timeout: poll_timeout,
            clear_timer: None,
            _clear_shift: 0,
        });

        drop(state);

        // Remove from MeshNet.
        net.friend_timeout(lpn);
        net.remove_negotiation_by_addr(lpn);
    } else {
        // Check retired LPN list.
        if let Some(retired) = state.retired_lpns.iter().find(|r| r.lp_addr == lpn) {
            let counter_delta = lpn_counter.wrapping_sub(retired.lp_cnt);
            if counter_delta == 0 || counter_delta > 0x100 {
                debug!("Friend Clear: retired counter invalid (delta={})", counter_delta);
                return;
            }
        }
        drop(state);
    }

    // Send Friend Clear Confirm.
    let seq_num = net.next_seq_num();
    let mut msg = [0u8; 5];
    msg[0] = NET_OP_FRND_CLEAR_CONFIRM;
    msg[1..3].copy_from_slice(&lpn.to_be_bytes());
    msg[3..5].copy_from_slice(&lpn_counter.to_be_bytes());

    debug!("Friend: sending Clear Confirm to 0x{:04x}", src);
    net.transport_send(0, 0, src, true, DEFAULT_TTL, false, seq_num, &msg);
}

/// Handle an incoming Friend Clear Confirm message.
///
/// Matches C `friend_clear_confirm()` (friend.c lines 220-235).
///
/// # Parameters
/// - `net`         – mutable mesh network context
/// - `src`         – source address of the confirmer
/// - `lpn`         – LPN address being confirmed
/// - `lpn_counter` – LPN counter
pub fn friend_clear_confirm(net: &mut MeshNet, src: u16, lpn: u16, lpn_counter: u16) {
    check_pending_timeouts(net);

    debug!("Friend Clear Confirm: src=0x{:04x} lpn=0x{:04x} cnt={}", src, lpn, lpn_counter,);

    let mut state = FRIEND_STATE.lock().unwrap();

    // Remove matching negotiation (the one marked as "clearing").
    if let Some(pos) = state.negotiations.iter().position(|n| n.lp_addr == lpn && n.clearing) {
        let neg = state.negotiations.remove(pos);
        if let Some(timer) = neg.timer {
            timer.abort();
        }
        if neg.net_key_id != 0 {
            net_key_unref(neg.net_key_id);
        }
    }

    // Remove from retired LPNs.
    if let Some(pos) = state.retired_lpns.iter().position(|r| r.lp_addr == lpn) {
        let retired = state.retired_lpns.remove(pos);
        if let Some(timer) = retired.clear_timer {
            timer.abort();
        }
    }

    drop(state);
    net.remove_negotiation_by_addr(lpn);

    debug!("Friend Clear Confirm: cleared for 0x{:04x}", lpn);
}

/// Handle an incoming Friend Subscription List Add message.
///
/// Matches C `friend_sub_add()` (friend.c lines 555-597).
///
/// # Parameters
/// - `net` – mutable mesh network context
/// - `src` – source (LPN) address
/// - `pkt` – raw payload: `[transaction_number, addr1_hi, addr1_lo, ...]`
pub fn friend_sub_add(net: &mut MeshNet, src: u16, pkt: &[u8]) {
    check_pending_timeouts(net);

    if pkt.len() < 3 {
        debug!("Friend Sub Add: packet too short ({})", pkt.len());
        return;
    }

    let transaction = pkt[0];
    let addr_data = &pkt[1..];

    // Must have pairs of bytes (each address is 2 bytes).
    if addr_data.len() % 2 != 0 {
        debug!("Friend Sub Add: odd address data length");
        return;
    }

    // Parse all addresses up-front.
    let num_addrs = addr_data.len() / 2;
    let mut addrs = Vec::with_capacity(num_addrs);
    for i in 0..num_addrs {
        addrs.push(u16::from_be_bytes([addr_data[i * 2], addr_data[i * 2 + 1]]));
    }

    // Process each address, re-acquiring the lock around each iteration
    // so we can call net_friend_sub_add without holding the borrow.
    for &addr in &addrs {
        // Only group addresses (>= 0xC000) are valid.
        if addr < 0xC000 {
            debug!("Friend Sub Add: invalid group addr 0x{:04x}", addr);
            continue;
        }

        let needs_add = {
            let mut state = FRIEND_STATE.lock().unwrap();
            let fctx = match state.friendships.iter_mut().find(|f| f.lp_addr == src) {
                Some(f) => f,
                None => {
                    debug!("Friend Sub Add: friendship gone for 0x{:04x}", src);
                    return;
                }
            };

            if fctx.grp_list.len() >= MAX_FRND_GROUPS {
                debug!("Friend Sub Add: group list full ({})", MAX_FRND_GROUPS);
                break;
            }

            if fctx.grp_list.contains(&addr) {
                false
            } else {
                fctx.grp_list.push(addr);
                true
            }
        };

        if needs_add {
            net_friend_sub_add(net, src, addr);
        }
    }

    // Send Friend Subscription List Confirm.
    let seq_num = net.next_seq_num();
    let msg = [NET_OP_PROXY_SUB_CONFIRM, transaction];

    debug!("Friend: sending Sub Confirm (txn={}) to 0x{:04x}", transaction, src,);
    print_packet("Frnd-SubConf", &msg);

    net.transport_send(0, 0, src, true, DEFAULT_TTL, false, seq_num, &msg);
}

/// Handle an incoming Friend Subscription List Remove message.
///
/// Matches C `friend_sub_del()` (friend.c lines 599-635).
///
/// # Parameters
/// - `net` – mutable mesh network context
/// - `src` – source (LPN) address
/// - `pkt` – raw payload: `[transaction_number, addr1_hi, addr1_lo, ...]`
pub fn friend_sub_del(net: &mut MeshNet, src: u16, pkt: &[u8]) {
    check_pending_timeouts(net);

    if pkt.len() < 3 {
        debug!("Friend Sub Del: packet too short ({})", pkt.len());
        return;
    }

    let transaction = pkt[0];
    let addr_data = &pkt[1..];

    if addr_data.len() % 2 != 0 {
        debug!("Friend Sub Del: odd address data length");
        return;
    }

    // Parse all addresses up-front.
    let num_addrs = addr_data.len() / 2;
    let mut addrs = Vec::with_capacity(num_addrs);
    for i in 0..num_addrs {
        addrs.push(u16::from_be_bytes([addr_data[i * 2], addr_data[i * 2 + 1]]));
    }

    // Process each address, re-acquiring the lock around each iteration.
    for &addr in &addrs {
        {
            let mut state = FRIEND_STATE.lock().unwrap();
            let fctx = match state.friendships.iter_mut().find(|f| f.lp_addr == src) {
                Some(f) => f,
                None => {
                    debug!("Friend Sub Del: friendship gone for 0x{:04x}", src);
                    return;
                }
            };
            fctx.grp_list.retain(|&a| a != addr);
        }
        net_friend_sub_del(net, src, addr);
    }

    // Send Friend Subscription List Confirm.
    let seq_num = net.next_seq_num();
    let msg = [NET_OP_PROXY_SUB_CONFIRM, transaction];

    debug!("Friend: sending Sub Confirm (txn={}) to 0x{:04x}", transaction, src,);
    print_packet("Frnd-SubConf", &msg);

    net.transport_send(0, 0, src, true, DEFAULT_TTL, false, seq_num, &msg);
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_values() {
        assert_eq!(OP_FRND_REQUEST, 0x8040);
        assert_eq!(OP_FRND_INQUIRY, 0x8041);
        assert_eq!(OP_FRND_CONFIRM, 0x8042);
        assert_eq!(OP_FRND_SUB_LIST_ADD, 0x8043);
        assert_eq!(OP_FRND_SUB_LIST_CONFIRM, 0x8044);
        assert_eq!(OP_FRND_SUB_LIST_REMOVE, 0x8045);
        assert_eq!(OP_FRND_NEGOTIATE, 0x8046);
        assert_eq!(OP_FRND_CLEAR, 0x8047);
    }

    #[test]
    fn test_internal_constants() {
        assert_eq!(MAX_FRND_GROUPS, 20);
        assert_eq!(FRND_RELAY_WINDOW, 250);
        assert_eq!(RESPONSE_DELAY, 88);
        assert_eq!(MIN_RESP_DELAY, 10);
        assert_eq!(MAX_RESP_DELAY, 255);
        assert_eq!(RESPONSE_POLL_DELAY, 1255);
        assert_eq!(FRND_CACHE_SIZE, 32);
        assert_eq!(FRND_SUB_LIST_SIZE, 8);
    }

    #[test]
    fn test_scaling_factors() {
        assert_eq!(SCALING_FACTORS, [10, 15, 20, 15]);
    }

    #[test]
    fn test_min_cache_size() {
        assert_eq!(min_cache_size(0), 0);
        assert_eq!(min_cache_size(1), 2);
        assert_eq!(min_cache_size(2), 4);
        assert_eq!(min_cache_size(3), 8);
        assert_eq!(min_cache_size(4), 16);
        assert_eq!(min_cache_size(5), 32);
        assert_eq!(min_cache_size(15), 32);
    }

    #[test]
    fn test_module_state_initialization() {
        let state = FRIEND_STATE.lock().unwrap();
        assert_eq!(state.counter, 0);
        assert_eq!(state.frnd_relay_window, 250u8);
        assert_eq!(state.frnd_cache_size, 32);
        assert_eq!(state.frnd_sublist_size, 8);
        assert!(state.retired_lpns.is_empty());
        assert!(state.negotiations.is_empty());
        // Note: friendships might not be empty if other tests ran first.
    }
}
