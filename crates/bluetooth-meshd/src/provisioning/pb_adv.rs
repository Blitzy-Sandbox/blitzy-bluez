// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
// PB-ADV (Provisioning Bearer over Advertising) transport layer.
//
// Complete Rust rewrite of mesh/pb-adv.c. Implements link-layer sessions with
// Segmentation and Reassembly (SAR), ACK/CLOSE protocol, link open/close
// handshake, transaction tracking, and loopback support for local provisioning.
//
// All wire formats, FCS computation, segment sizes, and state transitions match
// the C original byte-for-byte.

use std::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use tracing::{debug, warn};

use super::{ProvAckCb, ProvCloseCb, ProvOpenCb, ProvRxCb, ProvTransTx, TRANSPORT_PB_ADV};
use crate::crypto::{mesh_crypto_check_fcs, mesh_crypto_compute_fcs};
use crate::io::{BT_AD_MESH_PROV, MESH_IO_TX_COUNT_UNLIMITED};
use crate::mesh;

// ─── Protocol Constants ────────────────────────────────────────────────────────

/// Maximum payload per PB-ADV advertising PDU segment (Mesh Spec 5.3.1).
const PB_ADV_MTU: usize = 24;

/// Bearer control: Transaction ACK — GPCF = 0x01.
const PB_ADV_ACK: u8 = 0x01;

/// Bearer control: Link Open Request — (BearerOpcode=0x00 << 2) | GPCF=0x03.
const PB_ADV_OPEN_REQ: u8 = 0x03;

/// Bearer control: Link Open Confirm — (BearerOpcode=0x01 << 2) | GPCF=0x03.
const PB_ADV_OPEN_CFM: u8 = 0x07;

/// Bearer control: Link Close — (BearerOpcode=0x02 << 2) | GPCF=0x03.
const PB_ADV_CLOSE: u8 = 0x0B;

/// Maximum provisioning PDU reassembly buffer size (bytes).
const SAR_MAX: usize = 80;

/// Maximum data bytes in the first SAR segment.
/// First segment header overhead after common prefix: total_len(2) + FCS(1) + GPCF(1) = 4.
const SAR_FIRST_DATA_MAX: usize = PB_ADV_MTU - 4;

/// Maximum data bytes in a continuation SAR segment.
/// Continuation overhead after common prefix: GPCF(1) = 1.
const SAR_CONT_DATA_MAX: usize = PB_ADV_MTU - 1;

/// Transaction timeout in seconds (waiting for ACK after SAR send).
const TX_TIMEOUT_SECS: u64 = 30;

/// Initial link-open timeout in seconds for the initiator.
const OPEN_TIMEOUT_SECS: u64 = 60;

/// Provisioning close reason: timeout (passed to close_cb on tx_timeout).
const PB_CLOSE_TIMEOUT: u8 = 0x01;

/// Send interval for data and control packets (milliseconds).
const SEND_INTERVAL: u16 = 500;

/// Send count for close indication (sent multiple times for reliability).
const CLOSE_SEND_COUNT: u8 = 10;

/// Send interval for close indication (milliseconds).
const CLOSE_SEND_INTERVAL: u16 = 100;

// ─── Session State ─────────────────────────────────────────────────────────────

/// PB-ADV session representing one endpoint of a provisioning bearer link.
///
/// Tracks link state, SAR reassembly buffers, transaction numbers, timeouts,
/// and upper-layer callbacks. Matches the C `struct pb_adv_session` field-by-field.
struct PbAdvSession {
    /// Upper-layer callback invoked when the link opens.
    open_cb: Option<ProvOpenCb>,
    /// Upper-layer callback invoked when the link closes.
    close_cb: Option<ProvCloseCb>,
    /// Upper-layer callback invoked when a complete provisioning PDU arrives.
    rx_cb: Option<ProvRxCb>,
    /// Upper-layer callback invoked when an ACK is received for our last send.
    ack_cb: Option<ProvAckCb>,
    /// Pending timeout task handle (aborted on ACK or session removal).
    tx_timeout: Option<JoinHandle<()>>,
    /// user_data of the loopback peer session, if local provisioning is active.
    loop_peer: Option<usize>,
    /// Random 32-bit link identifier for this PB-ADV link.
    link_id: u32,
    /// Expected total PDU length from the first SAR segment header.
    exp_len: u16,
    /// Expected 8-bit FCS from the first SAR segment header.
    exp_fcs: u8,
    /// Bitmask of expected segments (set once from first-segment header).
    exp_segs: u8,
    /// Bitmask of received segments (accumulated as segments arrive).
    got_segs: u8,
    /// Last acknowledged outbound transaction number.
    local_acked: u8,
    /// Current outbound transaction number (incremented before each send).
    local_trans_num: u8,
    /// Last received inbound transaction number.
    peer_trans_num: u8,
    /// Previous completed inbound transaction (for duplicate detection).
    last_peer_trans_num: u8,
    /// SAR reassembly buffer.
    sar: [u8; SAR_MAX],
    /// Device UUID for session matching (loopback detection).
    uuid: [u8; 16],
    /// `true` if this session is the provisioning initiator.
    initiator: bool,
    /// `true` if the link has been established (OPEN_CFM exchanged).
    opened: bool,
    /// Opaque handle identifying this session to the upper provisioning layer.
    user_data: usize,
}

impl Default for PbAdvSession {
    fn default() -> Self {
        Self {
            open_cb: None,
            close_cb: None,
            rx_cb: None,
            ack_cb: None,
            tx_timeout: None,
            loop_peer: None,
            link_id: 0,
            exp_len: 0,
            exp_fcs: 0,
            exp_segs: 0,
            got_segs: 0,
            local_acked: 0,
            local_trans_num: 0,
            peer_trans_num: 0,
            last_peer_trans_num: 0,
            sar: [0u8; SAR_MAX],
            uuid: [0u8; 16],
            initiator: false,
            opened: false,
            user_data: 0,
        }
    }
}

// ─── Global Session Queue ──────────────────────────────────────────────────────

/// Module-level session storage. Replaces C `static struct l_queue *pb_sessions`.
///
/// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because all lock-holding
/// sections are synchronous and short. Callbacks are invoked via a take-call-restore
/// pattern to prevent deadlock from re-entrant PB-ADV calls.
static PB_SESSIONS: Mutex<Vec<PbAdvSession>> = Mutex::new(Vec::new());

// ─── Packet Sending Helpers ────────────────────────────────────────────────────

/// Send a Link Open Request advertising packet.
///
/// Wire format: [AD_TYPE(1), link_id_be(4), trans_num=0(1), OPEN_REQ(1), uuid(16)] = 23 bytes.
fn send_open_req(link_id: u32, uuid: &[u8; 16]) {
    mesh::mesh_send_cancel(&[BT_AD_MESH_PROV]);

    let mut buf = Vec::with_capacity(23);
    buf.push(BT_AD_MESH_PROV);
    buf.extend_from_slice(&link_id.to_be_bytes());
    buf.push(0x00);
    buf.push(PB_ADV_OPEN_REQ);
    buf.extend_from_slice(uuid);

    mesh::mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, SEND_INTERVAL, &buf);
}

/// Send a Link Open Confirm advertising packet.
///
/// Wire format: [AD_TYPE(1), link_id_be(4), trans_num=0(1), OPEN_CFM(1)] = 7 bytes.
fn send_open_cfm(link_id: u32) {
    mesh::mesh_send_cancel(&[BT_AD_MESH_PROV]);

    let mut buf = Vec::with_capacity(7);
    buf.push(BT_AD_MESH_PROV);
    buf.extend_from_slice(&link_id.to_be_bytes());
    buf.push(0x00);
    buf.push(PB_ADV_OPEN_CFM);

    mesh::mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, SEND_INTERVAL, &buf);
}

/// Send a Transaction ACK advertising packet.
///
/// Wire format: [AD_TYPE(1), link_id_be(4), trans_num(1), ACK(1)] = 7 bytes.
fn send_ack(link_id: u32, trans_num: u8) {
    let mut buf = Vec::with_capacity(7);
    buf.push(BT_AD_MESH_PROV);
    buf.extend_from_slice(&link_id.to_be_bytes());
    buf.push(trans_num);
    buf.push(PB_ADV_ACK);

    mesh::mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, SEND_INTERVAL, &buf);
}

/// Send a Link Close indication advertising packet.
///
/// Wire format: [AD_TYPE(1), link_id_be(4), trans_num=0(1), CLOSE(1), reason(1)] = 8 bytes.
/// Sent with count=10 at 100ms interval for reliability.
fn send_close_ind(link_id: u32, reason: u8) {
    if link_id == 0 {
        return;
    }

    mesh::mesh_send_cancel(&[BT_AD_MESH_PROV]);

    let mut buf = Vec::with_capacity(8);
    buf.push(BT_AD_MESH_PROV);
    buf.extend_from_slice(&link_id.to_be_bytes());
    buf.push(0x00);
    buf.push(PB_ADV_CLOSE);
    buf.push(reason);

    mesh::mesh_send_pkt(CLOSE_SEND_COUNT, CLOSE_SEND_INTERVAL, &buf);
}

// ─── SAR Segmentation (Outbound) ──────────────────────────────────────────────

/// Segment a provisioning PDU into PB-ADV advertising packets and transmit.
///
/// Implements the Generic Provisioning PDU segmentation algorithm:
/// - First segment: `[AD(1), link_id(4), trans_num(1), GPCF(1), len(2), FCS(1), data...]`
/// - Continuation:  `[AD(1), link_id(4), trans_num(1), GPCF(1), data...]`
///
/// Called with the PB_SESSIONS lock held. Only calls `mesh_send_pkt` and
/// `tokio::spawn` (for timeout), neither of which re-locks PB_SESSIONS.
fn send_adv_segs(session: &mut PbAdvSession, data: &[u8]) {
    let size = data.len();
    if size == 0 || size > SAR_MAX {
        return;
    }

    let (max_seg, init_size) = if size > SAR_FIRST_DATA_MAX {
        let ms = 1 + (size - SAR_FIRST_DATA_MAX - 1) / SAR_CONT_DATA_MAX;
        (ms as u8, SAR_FIRST_DATA_MAX)
    } else {
        (0u8, size)
    };

    debug!("Sending {} segments for {} byte message", u16::from(max_seg) + 1, size);

    mesh::mesh_send_cancel(&[BT_AD_MESH_PROV]);

    // Increment transaction number (pre-increment matches C `++session->local_trans_num`)
    session.local_trans_num = session.local_trans_num.wrapping_add(1);

    // Build and send first segment (GPCF = 0x00, Transaction Start)
    let mut buf = Vec::with_capacity(init_size + 10);
    buf.push(BT_AD_MESH_PROV);
    buf.extend_from_slice(&session.link_id.to_be_bytes());
    buf.push(session.local_trans_num);
    buf.push(max_seg << 2); // (SegN << 2) | GPCF=0x00
    buf.extend_from_slice(&(size as u16).to_be_bytes());
    buf.push(mesh_crypto_compute_fcs(data));
    buf.extend_from_slice(&data[..init_size]);

    debug!("max_seg {:02x}", max_seg);
    debug!("size {}, init_size {}", size, init_size);

    mesh::mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, SEND_INTERVAL, &buf);

    // Build and send continuation segments (GPCF = 0x02)
    let mut consumed = init_size;
    for i in 1..=max_seg {
        let seg_size =
            if size - consumed > SAR_CONT_DATA_MAX { SAR_CONT_DATA_MAX } else { size - consumed };

        let mut seg_buf = Vec::with_capacity(seg_size + 7);
        seg_buf.push(BT_AD_MESH_PROV);
        seg_buf.extend_from_slice(&session.link_id.to_be_bytes());
        seg_buf.push(session.local_trans_num);
        seg_buf.push((i << 2) | 0x02); // (SegIndex << 2) | GPCF=0x02
        seg_buf.extend_from_slice(&data[consumed..consumed + seg_size]);

        mesh::mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, SEND_INTERVAL, &seg_buf);
        consumed += seg_size;
    }

    // Cancel any previous timeout and start a new one
    if let Some(handle) = session.tx_timeout.take() {
        handle.abort();
    }

    let ud = session.user_data;
    session.tx_timeout = Some(tokio::spawn(async move {
        sleep(Duration::from_secs(TX_TIMEOUT_SECS)).await;
        handle_tx_timeout(ud);
    }));
}

// ─── Callback Invoke Helpers (Take-Call-Restore Pattern) ───────────────────────
//
// Each helper:
//   1. Locks PB_SESSIONS, takes the callback out of the session (Option::take).
//   2. Drops the lock.
//   3. Invokes the callback — safe because the lock is not held, so re-entrant
//      calls from within the callback (e.g. ProvTransTx → pb_adv_tx) can re-lock.
//   4. Re-locks PB_SESSIONS and restores the callback if the session still exists.

/// Invoke open_cb for a session, creating the appropriate ProvTransTx closure.
///
/// `loopback`: if `true`, the ProvTransTx will check for a loop peer and deliver
/// locally; otherwise it always sends over the ADV bearer.
fn invoke_open_cb(user_data: usize, loopback: bool) {
    let mut cb = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        sessions.iter_mut().find(|s| s.user_data == user_data).and_then(|s| s.open_cb.take())
    };

    if let Some(ref mut f) = cb {
        let ud = user_data;
        let tx: ProvTransTx = if loopback {
            Box::new(move |data: &[u8]| -> bool { pb_adv_send_impl(ud, data) })
        } else {
            Box::new(move |data: &[u8]| -> bool { pb_adv_tx(ud, data) })
        };
        f(user_data, tx, user_data, TRANSPORT_PB_ADV);
    }

    // Restore callback if session still exists
    let mut sessions = PB_SESSIONS.lock().unwrap();
    if let Some(session) = sessions.iter_mut().find(|s| s.user_data == user_data) {
        if session.open_cb.is_none() {
            session.open_cb = cb;
        }
    }
}

/// Invoke close_cb for a session with the given reason code.
fn invoke_close_cb(user_data: usize, reason: u8) {
    let mut cb = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        sessions.iter_mut().find(|s| s.user_data == user_data).and_then(|s| s.close_cb.take())
    };

    if let Some(ref mut f) = cb {
        f(user_data, reason);
    }

    let mut sessions = PB_SESSIONS.lock().unwrap();
    if let Some(session) = sessions.iter_mut().find(|s| s.user_data == user_data) {
        if session.close_cb.is_none() {
            session.close_cb = cb;
        }
    }
}

/// Invoke rx_cb for a session with the reassembled provisioning PDU.
fn invoke_rx_cb(user_data: usize, data: &[u8]) {
    let mut cb = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        sessions.iter_mut().find(|s| s.user_data == user_data).and_then(|s| s.rx_cb.take())
    };

    if let Some(ref mut f) = cb {
        f(user_data, data);
    }

    let mut sessions = PB_SESSIONS.lock().unwrap();
    if let Some(session) = sessions.iter_mut().find(|s| s.user_data == user_data) {
        if session.rx_cb.is_none() {
            session.rx_cb = cb;
        }
    }
}

/// Invoke ack_cb for a session with the acknowledged transaction number.
fn invoke_ack_cb(user_data: usize, msg_num: u8) {
    let mut cb = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        sessions.iter_mut().find(|s| s.user_data == user_data).and_then(|s| s.ack_cb.take())
    };

    if let Some(ref mut f) = cb {
        f(user_data, msg_num);
    }

    let mut sessions = PB_SESSIONS.lock().unwrap();
    if let Some(session) = sessions.iter_mut().find(|s| s.user_data == user_data) {
        if session.ack_cb.is_none() {
            session.ack_cb = cb;
        }
    }
}

// ─── TX Functions ──────────────────────────────────────────────────────────────

/// Non-loopback transmit: always sends over the ADV bearer via SAR segmentation.
///
/// Passed as `ProvTransTx` to open_cb for non-loopback sessions. Corresponds to
/// the C `pb_adv_tx` function.
fn pb_adv_tx(user_data: usize, data: &[u8]) -> bool {
    let mut sessions = PB_SESSIONS.lock().unwrap();
    let session = match sessions.iter_mut().find(|s| s.user_data == user_data) {
        Some(s) if s.opened => s,
        _ => return false,
    };
    send_adv_segs(session, data);
    true
}

/// Loopback-aware transmit: delivers locally if a loop peer exists, otherwise
/// falls through to ADV SAR segmentation.
///
/// Passed as `ProvTransTx` to open_cb for loopback sessions. Corresponds to
/// the C `pb_adv_send` function.
fn pb_adv_send_impl(user_data: usize, data: &[u8]) -> bool {
    let loopback_info = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        let session = match sessions.iter_mut().find(|s| s.user_data == user_data) {
            Some(s) if s.opened => s,
            _ => return false,
        };

        if let Some(peer_ud) = session.loop_peer {
            Some((peer_ud, session.local_trans_num))
        } else {
            send_adv_segs(session, data);
            None
        }
    };

    if let Some((peer_ud, local_trans_num)) = loopback_info {
        // Schedule deferred delivery to the peer session (mirrors C l_idle_oneshot)
        let data_vec = data.to_vec();
        tokio::spawn(async move {
            invoke_rx_cb(peer_ud, &data_vec);
        });

        // Immediately acknowledge on the sender session
        invoke_ack_cb(user_data, local_trans_num);
    }

    true
}

// ─── Timeout Handler ───────────────────────────────────────────────────────────

/// Handle SAR transmission timeout (no ACK received within TX_TIMEOUT_SECS).
///
/// Cancels pending mesh sends and notifies the upper layer via close_cb.
/// Runs asynchronously from a spawned tokio task.
fn handle_tx_timeout(user_data: usize) {
    {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        match sessions.iter_mut().find(|s| s.user_data == user_data) {
            Some(session) => {
                warn!("PB-ADV TX timeout on link {:08x}", session.link_id);
                session.tx_timeout = None;
            }
            None => return,
        }
    }

    mesh::mesh_send_cancel(&[BT_AD_MESH_PROV]);
    invoke_close_cb(user_data, PB_CLOSE_TIMEOUT);
}

// --- SAR Data Segment Processing -----------------------------------------------

/// Attempt to complete SAR reassembly: verify FCS and return the assembled PDU.
///
/// On success returns `(user_data, pdu_vec, link_id, peer_trans_num)`
/// for delivery to the upper provisioning layer.
fn try_complete_sar(session: &mut PbAdvSession) -> Option<(usize, Vec<u8>, u32, u8)> {
    let len = session.exp_len as usize;
    if len == 0 || len > SAR_MAX {
        return None;
    }

    if !mesh_crypto_check_fcs(&session.sar[..len], session.exp_fcs) {
        debug!("Invalid FCS for {} byte PDU", len);
        return None;
    }

    let data = session.sar[..len].to_vec();
    session.last_peer_trans_num = session.peer_trans_num;

    Some((session.user_data, data, session.link_id, session.peer_trans_num))
}

/// Process a received SAR data segment (Transaction Start or Continuation).
///
/// GPCF 0x00 (Transaction Start): extracts total_len, FCS, seg count, and
/// copies the first data chunk into the SAR buffer.
///
/// GPCF 0x02 (Transaction Continue): validates segment index, computes the
/// byte offset in the SAR buffer, and copies the continuation data.
///
/// Returns delivery info if the reassembly is complete and FCS-valid.
fn process_data_segment(
    session: &mut PbAdvSession,
    gpcf: u8,
    msg_type: u8,
    trans_num: u8,
    pkt: &[u8],
) -> Option<(usize, Vec<u8>, u32, u8)> {
    match gpcf {
        0x00 => {
            // SAR First Segment (Transaction Start)
            // Byte layout (with AD type prefix):
            //   pkt[0]=AD, pkt[1..5]=link_id, pkt[5]=trans_num, pkt[6]=GPCF,
            //   pkt[7..9]=total_len(BE16), pkt[9]=FCS, pkt[10+]=data
            let total_segs = u32::from(msg_type >> 2) + 1;
            session.exp_segs = if total_segs >= 8 {
                0xFF
            } else {
                0xFFu8 >> (8u8.saturating_sub(total_segs as u8))
            };

            if pkt.len() < 10 {
                return None;
            }

            session.exp_len = u16::from_be_bytes([pkt[7], pkt[8]]);
            session.exp_fcs = pkt[9];
            session.peer_trans_num = trans_num;
            session.got_segs = 1; // Bit 0 = segment 0 received

            debug!(
                "RX First: {} bytes, FCS: {:02x}, total_segs: {}",
                session.exp_len, session.exp_fcs, total_segs
            );

            if session.exp_len as usize > SAR_MAX {
                debug!("Invalid Length: {}", session.exp_len);
                return None;
            }

            let avail = pkt.len() - 10;
            let data_len = avail.min(session.exp_len as usize);
            session.sar[..data_len].copy_from_slice(&pkt[10..10 + data_len]);

            if session.exp_segs == session.got_segs {
                return try_complete_sar(session);
            }

            None
        }
        0x02 => {
            // SAR Continuation Segment
            // Byte layout: pkt[0]=AD, pkt[1..5]=link_id, pkt[5]=trans_num,
            //   pkt[6]=GPCF, pkt[7+]=data
            let seg_idx = usize::from(msg_type >> 2);

            debug!("RX Continuation seg_idx={}", seg_idx);

            // Guard: segment index must be 1..=7 for continuations
            if seg_idx == 0 || seg_idx > 7 {
                return None;
            }

            session.got_segs |= 1u8 << seg_idx;

            // Byte offset in SAR buffer:
            // First segment occupies [0..SAR_FIRST_DATA_MAX),
            // continuation i occupies [20 + (i-1)*23 .. 20 + i*23)
            let offset = SAR_FIRST_DATA_MAX + (seg_idx - 1) * SAR_CONT_DATA_MAX;

            if pkt.len() < 7 {
                return None;
            }

            let data_len = pkt.len() - 7;

            if offset + data_len > SAR_MAX {
                return None;
            }

            session.sar[offset..offset + data_len].copy_from_slice(&pkt[7..7 + data_len]);

            if session.exp_segs == session.got_segs {
                return try_complete_sar(session);
            }

            None
        }
        _ => None,
    }
}

// --- Link Control Message Handlers --------------------------------------------

/// Handle an incoming Link Open Confirm (bearer control, BearerOpcode=0x01).
///
/// Validates that there is an initiator session with a matching link_id that
/// is not yet opened. On match: marks opened, resets local_trans_num to 0xFF,
/// cancels the open timeout, and notifies the upper layer via open_cb.
fn handle_open_cfm(link_id: u32) {
    let user_data = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        let session =
            match sessions.iter_mut().find(|s| s.link_id == link_id && s.initiator && !s.opened) {
                Some(s) => s,
                None => return,
            };

        session.opened = true;
        session.local_trans_num = 0xFF;

        if let Some(handle) = session.tx_timeout.take() {
            handle.abort();
        }

        session.user_data
    }; // lock dropped

    invoke_open_cb(user_data, true);
}

/// Handle an incoming Link Open Request (bearer control, BearerOpcode=0x00).
///
/// Finds an acceptor session whose UUID matches the 16-byte UUID in the packet
/// payload. On match: copies the link_id from the packet, initialises
/// transaction tracking, marks opened, sends OPEN_CFM, and notifies open_cb.
fn handle_open_req(link_id: u32, pkt: &[u8]) {
    // OPEN_REQ packet: [AD(1), link_id(4), trans_num(1), OPEN_REQ(1), uuid(16)] = 23
    if pkt.len() < 23 {
        return;
    }

    let uuid: [u8; 16] = match pkt[7..23].try_into() {
        Ok(u) => u,
        Err(_) => return,
    };

    let user_data = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        let session =
            match sessions.iter_mut().find(|s| !s.initiator && !s.opened && s.uuid == uuid) {
                Some(s) => s,
                None => return,
            };

        session.link_id = link_id;
        session.last_peer_trans_num = 0xFF;
        session.peer_trans_num = 0x00;
        session.local_trans_num = 0x7F;
        session.opened = true;

        session.user_data
    }; // lock dropped

    send_open_cfm(link_id);
    invoke_open_cb(user_data, true);
}

/// Handle an incoming Link Close indication (bearer control, BearerOpcode=0x02).
///
/// Extracts the reason code from the packet and notifies close_cb. Then
/// unregisters the session via `pb_adv_unreg`.
fn handle_close(link_id: u32, pkt: &[u8]) {
    // CLOSE packet: [AD(1), link_id(4), trans_num(1), CLOSE(1), reason(1)] = 8
    if pkt.len() < 8 {
        return;
    }

    let reason = pkt[7];

    let user_data = {
        let sessions = PB_SESSIONS.lock().unwrap();
        match sessions.iter().find(|s| s.link_id == link_id) {
            Some(s) => s.user_data,
            None => return,
        }
    };

    invoke_close_cb(user_data, reason);
    pb_adv_unreg(user_data);
}

/// Handle an incoming Transaction ACK (GPCF=0x01).
///
/// Validates that the acknowledged transaction number matches the most recent
/// outbound transaction. On match: updates local_acked, cancels tx_timeout,
/// and notifies ack_cb so the upper layer can send the next PDU.
fn handle_ack(link_id: u32, trans_num: u8) {
    let user_data = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        let session = match sessions.iter_mut().find(|s| s.link_id == link_id && s.opened) {
            Some(s) => s,
            None => return,
        };

        // ACK must be for the current outstanding transaction
        if trans_num != session.local_trans_num {
            return;
        }

        // Skip if already acknowledged (duplicate ACK)
        if session.local_acked == session.local_trans_num {
            return;
        }

        session.local_acked = trans_num;

        if let Some(handle) = session.tx_timeout.take() {
            handle.abort();
        }

        session.user_data
    }; // lock dropped

    invoke_ack_cb(user_data, trans_num);
}

/// Handle an incoming data segment (Transaction Start GPCF=0x00 or
/// Transaction Continue GPCF=0x02).
///
/// Uses an internal `Action` enum to collect the decision while holding
/// the lock, then executes the action (send ACK, deliver PDU) after
/// releasing the lock — preventing deadlock from callback re-entry.
fn handle_data(link_id: u32, trans_num: u8, pkt: &[u8]) {
    if pkt.len() < 7 {
        return;
    }

    let msg_type = pkt[6];
    let gpcf = msg_type & 0x03;

    if gpcf != 0x00 && gpcf != 0x02 {
        return;
    }

    // Actions that must be performed outside the lock
    enum Action {
        /// Resend ACK for a previously completed transaction (duplicate first segment)
        ResendAck(u8),
        /// Full PDU reassembled: deliver to upper layer and ACK
        Deliver(usize, Vec<u8>, u8),
        /// No action needed (segment buffered, waiting for more)
        Nothing,
    }

    let action = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        let session = match sessions.iter_mut().find(|s| s.link_id == link_id && s.opened) {
            Some(s) => s,
            None => return,
        };

        // Duplicate first-segment detection: if this is a Transaction Start with
        // the same trans_num as the last completed transaction, resend the ACK.
        if gpcf == 0x00 && trans_num == session.last_peer_trans_num {
            Action::ResendAck(trans_num)
        } else if gpcf == 0x02 && trans_num != session.peer_trans_num {
            // Continuation for a different transaction — discard
            Action::Nothing
        } else {
            match process_data_segment(session, gpcf, msg_type, trans_num, pkt) {
                Some((ud, data, _, pt)) => Action::Deliver(ud, data, pt),
                None => Action::Nothing,
            }
        }
    }; // lock dropped

    match action {
        Action::ResendAck(tn) => {
            send_ack(link_id, tn);
        }
        Action::Deliver(user_data, data, peer_trans) => {
            send_ack(link_id, peer_trans);
            invoke_rx_cb(user_data, &data);
        }
        Action::Nothing => {}
    }
}

// --- Main Packet Handler -------------------------------------------------------

/// Central PB-ADV packet handler registered with `mesh::mesh_reg_prov_rx`.
///
/// Parses the 7-byte common header:
///   `[AD_TYPE(1), link_id(4), trans_num(1), GPCF/type(1)]`
///
/// Dispatches to the appropriate handler based on the GPCF field (bits 0-1):
///   0x00 → Transaction Start (first SAR segment)
///   0x01 → Transaction ACK
///   0x02 → Transaction Continue (continuation SAR segment)
///   0x03 → Bearer Control (OPEN_REQ, OPEN_CFM, CLOSE)
fn pb_adv_packet(pkt: &[u8]) {
    if pkt.len() < 7 {
        warn!("PB-ADV packet too short: {} bytes", pkt.len());
        return;
    }

    let link_id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
    let trans_num = pkt[5];
    let msg_type = pkt[6];
    let gpcf = msg_type & 0x03;

    match gpcf {
        0x03 => {
            // Bearer Control — dispatch by full msg_type (includes bearer opcode)
            match msg_type {
                PB_ADV_OPEN_REQ => handle_open_req(link_id, pkt),
                PB_ADV_OPEN_CFM => handle_open_cfm(link_id),
                PB_ADV_CLOSE => handle_close(link_id, pkt),
                _ => {
                    debug!("Unknown bearer control: {:02x}", msg_type);
                }
            }
        }
        0x01 => {
            // Transaction ACK
            handle_ack(link_id, trans_num);
        }
        0x00 | 0x02 => {
            // Data segment (first or continuation)
            handle_data(link_id, trans_num, pkt);
        }
        _ => {
            // Unreachable (2-bit field), but silently ignore
        }
    }
}

// --- Public Registration API ---------------------------------------------------

/// Register a PB-ADV provisioning session.
///
/// If `initiator` is `true`, generates a random link_id, sends a Link Open
/// Request, and starts a 60-second open timeout. If `false` (acceptor), the
/// session waits for an incoming Link Open Request matching the provided UUID.
///
/// **Loopback detection:** If a session with the same UUID but opposite role
/// already exists, both sessions are linked for direct local delivery without
/// advertising — enabling local (on-device) provisioning.
///
/// Returns `true` on success, `false` if a same-role duplicate already exists.
pub fn pb_adv_reg(
    initiator: bool,
    open_cb: ProvOpenCb,
    close_cb: ProvCloseCb,
    rx_cb: ProvRxCb,
    ack_cb: ProvAckCb,
    uuid: &[u8; 16],
    user_data: usize,
) -> bool {
    // Pre-check: reject same-role UUID duplicate
    let (first_session, loopback_peer_ud) = {
        let sessions = PB_SESSIONS.lock().unwrap();

        if sessions.iter().any(|s| s.uuid == *uuid && s.initiator == initiator) {
            return false;
        }

        let is_first = sessions.is_empty();

        // Check for a loopback peer (opposite role, same UUID)
        let peer_ud = sessions
            .iter()
            .find(|s| s.uuid == *uuid && s.initiator != initiator)
            .map(|s| s.user_data);

        (is_first, peer_ud)
    };

    // Build the new session
    let mut session = PbAdvSession {
        open_cb: Some(open_cb),
        close_cb: Some(close_cb),
        rx_cb: Some(rx_cb),
        ack_cb: Some(ack_cb),
        uuid: *uuid,
        user_data,
        initiator,
        ..PbAdvSession::default()
    };

    if initiator {
        // Generate random link_id
        let link_id: u32 = rand::random();
        session.link_id = link_id;
        session.local_trans_num = 0xFF;
    }

    if let Some(peer_ud) = loopback_peer_ud {
        // Loopback mode: link both sessions
        session.loop_peer = Some(peer_ud);
        session.opened = true;

        // Copy link_id from the peer if we are the acceptor
        {
            let mut sessions = PB_SESSIONS.lock().unwrap();
            if let Some(peer) = sessions.iter_mut().find(|s| s.user_data == peer_ud) {
                peer.loop_peer = Some(user_data);
                if !peer.opened {
                    peer.opened = true;
                }
                if !initiator {
                    session.link_id = peer.link_id;
                }
                // Cancel any pending timeout on the peer (e.g. open timeout)
                if let Some(handle) = peer.tx_timeout.take() {
                    handle.abort();
                }
            }
        }

        // Add session to queue
        {
            let mut sessions = PB_SESSIONS.lock().unwrap();
            sessions.push(session);
        }

        // Unregister mesh I/O — not needed for loopback
        mesh::mesh_unreg_prov_rx();

        // Fire open callbacks for both sessions.
        // Initiator's open_cb fires first (matches C ordering).
        if initiator {
            invoke_open_cb(user_data, true);
            invoke_open_cb(peer_ud, true);
        } else {
            invoke_open_cb(peer_ud, true);
            invoke_open_cb(user_data, true);
        }
    } else {
        // Non-loopback: register I/O handler if first session
        if first_session {
            mesh::mesh_reg_prov_rx(pb_adv_packet);
        }

        // For initiator: save link_id before pushing to queue
        let link_id = session.link_id;
        let uuid_copy = session.uuid;

        // Add session to queue
        {
            let mut sessions = PB_SESSIONS.lock().unwrap();
            sessions.push(session);
        }

        if initiator {
            // Send Link Open Request
            send_open_req(link_id, &uuid_copy);

            // Start 60-second open timeout
            let ud = user_data;
            let handle = tokio::spawn(async move {
                sleep(Duration::from_secs(OPEN_TIMEOUT_SECS)).await;
                handle_tx_timeout(ud);
            });

            let mut sessions = PB_SESSIONS.lock().unwrap();
            if let Some(s) = sessions.iter_mut().find(|s| s.user_data == user_data) {
                s.tx_timeout = Some(handle);
            }
        }
    }

    true
}

/// Unregister and clean up a PB-ADV provisioning session.
///
/// If the link was open and not in loopback mode, sends a Link Close
/// indication (reason=0x00 success) for reliability.
///
/// If this was the last session, unregisters the mesh I/O packet handler.
/// If this was a loopback session, re-registers the mesh I/O handler for
/// the remaining peer (which now needs advertising I/O).
pub fn pb_adv_unreg(user_data: usize) {
    let session_info = {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        let idx = match sessions.iter().position(|s| s.user_data == user_data) {
            Some(i) => i,
            None => return,
        };

        // Extract info before removal
        let link_id = sessions[idx].link_id;
        let was_opened = sessions[idx].opened;
        let is_loopback = sessions[idx].loop_peer.is_some();
        let peer_ud = sessions[idx].loop_peer;

        // Cancel timeout
        if let Some(handle) = sessions[idx].tx_timeout.take() {
            handle.abort();
        }

        // Remove the session
        sessions.remove(idx);

        // Clear peer's loop_peer reference (session already removed, safe to iterate)
        if let Some(pud) = peer_ud {
            if let Some(peer) = sessions.iter_mut().find(|s| s.user_data == pud) {
                peer.loop_peer = None;
            }
        }

        let is_empty = sessions.is_empty();

        (link_id, was_opened, is_loopback, is_empty)
    }; // lock dropped

    let (link_id, was_opened, is_loopback, is_empty) = session_info;

    // Send close indication for non-loopback open links
    if was_opened && !is_loopback {
        send_close_ind(link_id, 0x00);
    }

    if is_empty {
        // No sessions left — unregister mesh I/O handler
        mesh::mesh_unreg_prov_rx();
    } else if is_loopback {
        // Former loopback peer now needs advertising I/O
        mesh::mesh_reg_prov_rx(pb_adv_packet);
    }
}

// ─── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to drain all sessions (for test isolation).
    fn clear_sessions() {
        let mut sessions = PB_SESSIONS.lock().unwrap();
        for s in sessions.iter_mut() {
            if let Some(h) = s.tx_timeout.take() {
                h.abort();
            }
        }
        sessions.clear();
    }

    /// Verify protocol constants match the Mesh spec.
    #[test]
    fn test_protocol_constants() {
        assert_eq!(PB_ADV_MTU, 24);
        assert_eq!(PB_ADV_ACK, 0x01);
        assert_eq!(PB_ADV_OPEN_REQ, 0x03);
        assert_eq!(PB_ADV_OPEN_CFM, 0x07);
        assert_eq!(PB_ADV_CLOSE, 0x0B);
        assert_eq!(SAR_MAX, 80);
        // First data = 24 - 4 = 20
        assert_eq!(SAR_FIRST_DATA_MAX, 20);
        // Continuation data = 24 - 1 = 23
        assert_eq!(SAR_CONT_DATA_MAX, 23);
    }

    /// Verify SAR segment count calculations.
    #[test]
    fn test_sar_segment_count() {
        // Exactly fits in one segment (≤ 20 bytes)
        assert_eq!(calc_max_seg(1), 0);
        assert_eq!(calc_max_seg(20), 0);
        // 21 bytes = 1 first + 1 continuation
        assert_eq!(calc_max_seg(21), 1);
        // 20 + 23 = 43 bytes = 1 + 1
        assert_eq!(calc_max_seg(43), 1);
        // 44 bytes = 1 + 2
        assert_eq!(calc_max_seg(44), 2);
        // 80 bytes (max) = 1 first (20) + 3 cont (3*23=69 > 60 remaining)
        // 80 - 20 = 60, (60-1)/23 = 2, so 1 + 2 = max_seg 3
        assert_eq!(calc_max_seg(80), 3);
    }

    /// Helper function matching send_adv_segs logic for max_seg computation.
    fn calc_max_seg(size: usize) -> u8 {
        if size > SAR_FIRST_DATA_MAX {
            (1 + (size - SAR_FIRST_DATA_MAX - 1) / SAR_CONT_DATA_MAX) as u8
        } else {
            0
        }
    }

    /// Verify exp_segs bitmask calculation.
    #[test]
    fn test_exp_segs_bitmask() {
        // 1 segment: total_segs = 1, mask = 0x01
        let total_segs: u32 = 1;
        let exp = 0xFFu8 >> (8u8.saturating_sub(total_segs as u8));
        assert_eq!(exp, 0x01);

        // 4 segments: mask = 0x0F
        let total_segs: u32 = 4;
        let exp = 0xFFu8 >> (8u8.saturating_sub(total_segs as u8));
        assert_eq!(exp, 0x0F);

        // 8 segments (max): mask = 0xFF
        let total_segs: u32 = 8;
        let exp =
            if total_segs >= 8 { 0xFF } else { 0xFFu8 >> (8u8.saturating_sub(total_segs as u8)) };
        assert_eq!(exp, 0xFF);
    }

    /// Verify process_data_segment first segment parses correctly.
    #[test]
    fn test_process_data_first_segment() {
        let mut session = PbAdvSession { opened: true, ..Default::default() };

        // Build a fake first-segment packet:
        // [AD(1), link_id(4), trans_num(1), GPCF(1), total_len(2), FCS(1), data...]
        let data = [0x42u8; 10]; // 10-byte provisioning PDU
        let fcs = crate::crypto::mesh_crypto_compute_fcs(&data);

        let mut pkt = Vec::new();
        pkt.push(BT_AD_MESH_PROV); // pkt[0] = AD type
        pkt.extend_from_slice(&[0, 0, 0, 1]); // pkt[1..5] = link_id
        pkt.push(0x00); // pkt[5] = trans_num
        pkt.push(0x00); // pkt[6] = (max_seg=0 << 2) | GPCF=0x00
        pkt.extend_from_slice(&(10u16).to_be_bytes()); // pkt[7..9] = total_len
        pkt.push(fcs); // pkt[9] = FCS
        pkt.extend_from_slice(&data); // pkt[10..20] = data

        let result = process_data_segment(&mut session, 0x00, 0x00, 0x00, &pkt);
        assert!(result.is_some(), "Single-segment PDU should complete immediately");

        let (_, assembled_data, _, _) = result.unwrap();
        assert_eq!(assembled_data, data);
    }

    /// Verify process_data_segment continuation index validation.
    #[test]
    fn test_process_data_invalid_continuation_index() {
        let mut session = PbAdvSession {
            opened: true,
            exp_len: 50,
            exp_segs: 0x07, // 3 segments expected
            ..Default::default()
        };

        // GPCF header byte: continuation seg_idx encoded in high 6 bits
        // `(seg_idx << 2) | 0x02` with seg_idx = 0 => 0x02 (seg_idx=0, GPCF=0x02)
        const SEG_IDX0_CONT_HEADER: u8 = 0x02;

        // Continuation with seg_idx = 0 is invalid
        let mut pkt = vec![BT_AD_MESH_PROV, 0, 0, 0, 1, 0x01, SEG_IDX0_CONT_HEADER];
        pkt.extend_from_slice(&[0xAA; 10]);

        let result = process_data_segment(&mut session, 0x02, SEG_IDX0_CONT_HEADER, 0x01, &pkt);
        assert!(result.is_none(), "Continuation with seg_idx=0 should be rejected");
    }

    /// Verify PbAdvSession default values.
    #[test]
    fn test_session_defaults() {
        let s = PbAdvSession::default();
        assert_eq!(s.link_id, 0);
        assert_eq!(s.exp_len, 0);
        assert!(!s.initiator);
        assert!(!s.opened);
        assert_eq!(s.local_trans_num, 0);
        assert_eq!(s.peer_trans_num, 0);
        assert!(s.open_cb.is_none());
        assert!(s.close_cb.is_none());
        assert!(s.rx_cb.is_none());
        assert!(s.ack_cb.is_none());
        assert!(s.tx_timeout.is_none());
        assert!(s.loop_peer.is_none());
    }

    /// Verify acceptor registration and duplicate rejection.
    #[test]
    fn test_register_acceptor_duplicate_rejection() {
        clear_sessions();

        let uuid: [u8; 16] = [0xCC; 16];

        let result1 = pb_adv_reg(
            false,
            Box::new(|_, _, _, _| {}),
            Box::new(|_, _| {}),
            Box::new(|_, _| {}),
            Box::new(|_, _| {}),
            &uuid,
            200,
        );
        assert!(result1, "First acceptor registration should succeed");

        let result2 = pb_adv_reg(
            false,
            Box::new(|_, _, _, _| {}),
            Box::new(|_, _| {}),
            Box::new(|_, _| {}),
            Box::new(|_, _| {}),
            &uuid,
            201,
        );
        assert!(!result2, "Duplicate same-role registration should fail");

        // Cleanup
        pb_adv_unreg(200);
        clear_sessions();
    }

    /// Verify unreg of non-existent session doesn't panic.
    #[test]
    fn test_unreg_nonexistent() {
        clear_sessions();
        pb_adv_unreg(999_999);
    }
}
