//! Bluetooth Mesh Remote Provisioning Server model.
//!
//! Complete Rust rewrite of `mesh/remprv-server.c` (920 lines) and
//! `mesh/remprv.h` (79 lines).  Implements scan start/stop with extended
//! scan, link open/close, PDU tunnelling (send/report/ack), NPPI (Node
//! Provisioning Protocol Interface) device-key refresh, scan
//! deduplication, and AD-type registration.
//!
//! All models register via the [`MeshModelOps`] trait from `crate::model`.

use std::sync::{Arc, Mutex};

use tokio::task::JoinHandle;
use tracing::{debug, error};

use crate::io::{
    BT_AD_MESH_BEACON, BT_AD_MESH_DATA, BT_AD_MESH_PROV, MeshIoRecvFn, MeshIoRecvInfo,
    mesh_io_deregister_recv_cb, mesh_io_register_recv_cb, mesh_io_send_cancel,
};
use crate::mesh::{APP_IDX_DEV_LOCAL, DEFAULT_TTL};
use crate::model::{
    MeshModelOps, MeshModelPub, SIG_VENDOR, mesh_model_opcode_get, mesh_model_opcode_set,
    mesh_model_register, mesh_model_send, set_id,
};
use crate::node::MeshNode;
use crate::provisioning::pb_adv::{pb_adv_reg, pb_adv_unreg};
use crate::provisioning::{
    MeshProvNodeInfo, PROV_ERR_CANT_ASSIGN_ADDR, PROV_FAILED, ProvAckCb, ProvCloseCb, ProvOpenCb,
    ProvRxCb, ProvTransTx,
};
use crate::util::print_packet;

// =========================================================================
// Phase 1 — Public Constants (from mesh/remprv.h)
// =========================================================================

// ── 1.1 Model IDs ────────────────────────────────────────────────────────
/// Remote Provisioning Server Model ID (SIG, 0x0004).
pub const REM_PROV_SRV_MODEL: u32 = set_id(SIG_VENDOR, 0x0004);
/// Remote Provisioning Client Model ID (SIG, 0x0005).
pub const REM_PROV_CLI_MODEL: u32 = set_id(SIG_VENDOR, 0x0005);

// ── 1.2 Scan Queue Size ─────────────────────────────────────────────────
/// Maximum number of scanned devices kept in the deduplication queue.
pub const PB_REMOTE_MAX_SCAN_QUEUE_SIZE: usize = 5;

// ── 1.3 Link States ─────────────────────────────────────────────────────
pub const PB_REMOTE_STATE_IDLE: u8 = 0x00;
pub const PB_REMOTE_STATE_LINK_OPENING: u8 = 0x01;
pub const PB_REMOTE_STATE_LINK_ACTIVE: u8 = 0x02;
pub const PB_REMOTE_STATE_OB_PKT_TX: u8 = 0x03;
pub const PB_REMOTE_STATE_LINK_CLOSING: u8 = 0x04;

// ── 1.4 Type Bitmasks ───────────────────────────────────────────────────
pub const PB_REMOTE_TYPE_LOCAL: u8 = 0x01;
pub const PB_REMOTE_TYPE_ADV: u8 = 0x02;
pub const PB_REMOTE_TYPE_GATT: u8 = 0x04;

// ── 1.5 Scan Types ──────────────────────────────────────────────────────
pub const PB_REMOTE_SCAN_NONE: u8 = 0x00;
pub const PB_REMOTE_SCAN_UNLIMITED: u8 = 0x01;
pub const PB_REMOTE_SCAN_LIMITED: u8 = 0x02;
pub const PB_REMOTE_SCAN_DETAILED: u8 = 0x03;

// ── 1.6 Remote Provisioning Opcodes (0x804F – 0x805F) ───────────────────
pub const OP_REM_PROV_SCAN_CAP_GET: u32 = 0x804F;
pub const OP_REM_PROV_SCAN_CAP_STATUS: u32 = 0x8050;
pub const OP_REM_PROV_SCAN_GET: u32 = 0x8051;
pub const OP_REM_PROV_SCAN_START: u32 = 0x8052;
pub const OP_REM_PROV_SCAN_STOP: u32 = 0x8053;
pub const OP_REM_PROV_SCAN_STATUS: u32 = 0x8054;
pub const OP_REM_PROV_SCAN_REPORT: u32 = 0x8055;
pub const OP_REM_PROV_EXT_SCAN_START: u32 = 0x8056;
pub const OP_REM_PROV_EXT_SCAN_REPORT: u32 = 0x8057;
pub const OP_REM_PROV_LINK_GET: u32 = 0x8058;
pub const OP_REM_PROV_LINK_OPEN: u32 = 0x8059;
pub const OP_REM_PROV_LINK_CLOSE: u32 = 0x805A;
pub const OP_REM_PROV_LINK_STATUS: u32 = 0x805B;
pub const OP_REM_PROV_LINK_REPORT: u32 = 0x805C;
pub const OP_REM_PROV_PDU_SEND: u32 = 0x805D;
pub const OP_REM_PROV_PDU_OB_REPORT: u32 = 0x805E;
pub const OP_REM_PROV_PDU_REPORT: u32 = 0x805F;

// ── 1.7 Error Codes ─────────────────────────────────────────────────────
pub const PB_REM_ERR_SUCCESS: u8 = 0x00;
pub const PB_REM_ERR_SCANNING_CANNOT_START: u8 = 0x01;
pub const PB_REM_ERR_INVALID_STATE: u8 = 0x02;
pub const PB_REM_ERR_LIMITED_RESOURCES: u8 = 0x03;
pub const PB_REM_ERR_LINK_CANNOT_OPEN: u8 = 0x04;
pub const PB_REM_ERR_LINK_OPEN_FAILED: u8 = 0x05;
pub const PB_REM_ERR_LINK_CLOSED_AS_CANNOT_RX_PDU: u8 = 0x06;
pub const PB_REM_ERR_LINK_CLOSED_AS_CANNOT_TX_PDU: u8 = 0x07;
pub const PB_REM_ERR_LINK_CLOSED_BY_DEVICE: u8 = 0x08;
pub const PB_REM_ERR_LINK_CLOSED_BY_SERVER: u8 = 0x09;
pub const PB_REM_ERR_LINK_CLOSED_CANNOT_TX_PDU: u8 = 0x0A;

// ── 1.8 Internal Constants (from remprv-server.c lines 42-47) ───────────
const EXT_LIST_SIZE: usize = 60;
/// NPPI procedure type: device key refresh only.
const _RPR_DEV_KEY: u8 = 0x00;
/// NPPI procedure type: device key + address refresh.
const _RPR_ADDR: u8 = 0x01;
/// NPPI procedure type: device key + composition refresh.
const RPR_COMP: u8 = 0x02;
const RPR_ADV: u8 = 0xFF;

/// BLE AD-type constants needed by ext-scan (not exported from deps).
const BT_AD_UUID16_SOME: u8 = 0x02;
const BT_AD_UUID16_ALL: u8 = 0x03;
const BT_AD_UUID32_SOME: u8 = 0x04;
const BT_AD_UUID32_ALL: u8 = 0x05;
const BT_AD_UUID128_SOME: u8 = 0x06;
const BT_AD_UUID128_ALL: u8 = 0x07;
const BT_AD_NAME_SHORT: u8 = 0x08;
const BT_AD_NAME_COMPLETE: u8 = 0x09;

/// Beacon filter for unprovisioned device beacon.
const PRVB: [u8; 2] = [BT_AD_MESH_BEACON, 0x00];
/// Packet filter for PB-ADV advertising.
const PKT_FILTER: u8 = BT_AD_MESH_PROV;
/// Default name returned in extended scan local-info (matches C).
const LOCAL_NAME: &str = "Test Name";
/// Sixteen zero bytes for comparison / initialization.
const ZERO_16: [u8; 16] = [0u8; 16];

/// Scan list entry size for regular scanning: rssi(1) + uuid(16) = 17.
const SCAN_ENTRY_SIZE: usize = 17;

// =========================================================================
// Phase 2 — State Structures
// =========================================================================

/// Link-specific union data for the Remote Provisioning session.
enum ProvLinkData {
    /// No link data yet (initial / idle state).
    Idle,
    /// PB-ADV bearer link.
    Adv { uuid: [u8; 16], tx: Option<ProvTransTx> },
    /// NPPI (Node Provisioning Protocol Interface) link.
    ///
    /// `close_cb` and `ack_cb` are retained for lifetime management
    /// (mirroring the C union's stored pointers) even though they are
    /// only invoked by the acceptor side via `trans_data`.
    Nppi {
        _close_cb: Option<ProvCloseCb>,
        rx_cb: Option<ProvRxCb>,
        _ack_cb: Option<ProvAckCb>,
        info: MeshProvNodeInfo,
    },
}

/// Remote Provisioning link session data.
///
/// Mirrors C `struct rem_prov_data` (remprv-server.c lines 69-92).
struct RemProvData {
    node: Arc<MeshNode>,
    timeout: Option<JoinHandle<()>>,
    trans_data: usize,
    client: u16,
    net_idx: u16,
    svr_pdu_num: u8,
    cli_pdu_num: u8,
    state: u8,
    nppi_proc: u8,
    link: ProvLinkData,
}

/// Remote Provisioning scan session data.
///
/// Mirrors C `struct rem_scan_data` (remprv-server.c lines 49-65).
struct RemScanData {
    node: Arc<MeshNode>,
    timeout: Option<JoinHandle<()>>,
    /// Raw scan list.
    /// - Regular scan: entries of `SCAN_ENTRY_SIZE` bytes each
    ///   (`rssi(1) + uuid(16)`), pre-allocated.
    /// - Extended scan: TLV buffer `[len][data…][len][data…]…[0]`.
    list: Vec<u8>,
    client: u16,
    oob_info: u16,
    net_idx: u16,
    state: u8,
    scanned_limit: u8,
    addr: [u8; 6],
    uuid: [u8; 16],
    to_secs: u8,
    rxed_ads: u8,
    ext_cnt: u8,
    fltr: bool,
    ext: Vec<u8>,
}

// ── Global state (replaces C static pointers) ───────────────────────────

static RPB_SCAN: Mutex<Option<RemScanData>> = Mutex::new(None);
static RPB_PROV: Mutex<Option<RemProvData>> = Mutex::new(None);

// =========================================================================
// Phase 3 — Helper Functions
// =========================================================================

/// Build and send `OP_REM_PROV_LINK_STATUS` to the provisioning client.
///
/// Mirrors C `send_prov_status()` (remprv-server.c lines 187-202).
fn send_prov_status(node: &MeshNode, client: u16, net_idx: u16, state: u8, status: u8) {
    let mut msg = [0u8; 5];
    let mut n = mesh_model_opcode_set(OP_REM_PROV_LINK_STATUS, &mut msg);
    msg[n] = status;
    n += 1;
    msg[n] = state;
    n += 1;

    debug!("RPB-Link Status({}): dst {:04x}", state, client);

    mesh_model_send(node, 0, client, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
}

/// Cancel and deallocate a provisioning session.
///
/// Mirrors C `remprv_prov_cancel()` (remprv-server.c lines 204-215).
fn remprv_prov_cancel() {
    let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(ref mut prov) = *guard {
        if let Some(handle) = prov.timeout.take() {
            handle.abort();
        }
    }
    *guard = None;
}

// =========================================================================
// Phase 4 — Extended AD-Type Registration / Deregistration
// =========================================================================

/// Deregister extended AD type filter from mesh I/O layer.
///
/// Mirrors C `deregister_ext_ad_type()` (remprv-server.c lines 217-243).
fn deregister_ext_ad_type(ad_type: u8) {
    match ad_type {
        BT_AD_MESH_BEACON | BT_AD_MESH_DATA | BT_AD_MESH_PROV | BT_AD_UUID16_SOME
        | BT_AD_UUID32_SOME | BT_AD_UUID128_SOME | BT_AD_NAME_SHORT => {
            // These are either auto-managed or disallowed; skip.
        }
        BT_AD_UUID16_ALL | BT_AD_UUID32_ALL | BT_AD_UUID128_ALL | BT_AD_NAME_COMPLETE => {
            // Deregister the short variant first.
            let short_ad = ad_type - 1;
            mesh_io_deregister_recv_cb(&[short_ad]);
            mesh_io_deregister_recv_cb(&[ad_type]);
        }
        _ => {
            mesh_io_deregister_recv_cb(&[ad_type]);
        }
    }
}

/// Register an extended AD type filter and return success/failure.
///
/// Mirrors C `register_ext_ad_type()` (remprv-server.c lines 437-470).
fn register_ext_ad_type(ad_type: u8, cb: MeshIoRecvFn) -> bool {
    match ad_type {
        BT_AD_MESH_PROV | BT_AD_UUID16_SOME | BT_AD_UUID32_SOME | BT_AD_UUID128_SOME
        | BT_AD_NAME_SHORT => {
            // Illegal requests.
            false
        }
        BT_AD_UUID16_ALL | BT_AD_UUID32_ALL | BT_AD_UUID128_ALL | BT_AD_NAME_COMPLETE => {
            // Automatically register short versions too.
            let short_ad = ad_type - 1;
            mesh_io_register_recv_cb(&[short_ad], Arc::clone(&cb));
            mesh_io_register_recv_cb(&[ad_type], cb);
            true
        }
        BT_AD_MESH_BEACON => {
            // Ignored / auto request — treated as success.
            true
        }
        _ => {
            mesh_io_register_recv_cb(&[ad_type], cb);
            true
        }
    }
}

// =========================================================================
// Phase 5 — Scan Cancel
// =========================================================================

/// Cancel and deallocate a scan session, optionally sending a final
/// extended scan report.
///
/// Mirrors C `remprv_scan_cancel()` (remprv-server.c lines 246-289).
/// Called with `from_timeout = true` when triggered by the scan timeout
/// task, `false` otherwise.
fn remprv_scan_cancel(from_timeout: bool) {
    // Extract everything we need while holding the lock, then release.
    let scan_opt = {
        let mut guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        guard.take()
    };

    let scan = match scan_opt {
        Some(s) => s,
        None => return,
    };

    // Deregister all extended AD type filters.
    for i in 0..scan.ext_cnt as usize {
        if let Some(&ad) = scan.ext.get(i) {
            deregister_ext_ad_type(ad);
        }
    }

    // Abort timeout task if we are not coming from the timeout itself.
    if !from_timeout {
        if let Some(handle) = &scan.timeout {
            handle.abort();
        }
    }

    // If the timeout fired AND we were doing an extended scan, send the
    // accumulated extended-scan report.
    if from_timeout && scan.ext_cnt > 0 {
        let mut msg = [0u8; 22 + EXT_LIST_SIZE];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_EXT_SCAN_REPORT, &mut msg);
        msg[n] = PB_REM_ERR_SUCCESS;
        n += 1;
        msg[n..n + 16].copy_from_slice(&scan.uuid);
        n += 16;

        if scan.oob_info != 0 {
            msg[n..n + 2].copy_from_slice(&0u16.to_le_bytes());
            n += 2;
        }

        // Walk TLV list: [len][data…][len][data…]…[0]
        let mut i: usize = 0;
        while i < scan.list.len() && scan.list[i] != 0 {
            let entry_len = scan.list[i] as usize;
            msg[n] = scan.list[i];
            n += 1;
            if i + 1 + entry_len <= scan.list.len() && n + entry_len <= msg.len() {
                msg[n..n + entry_len].copy_from_slice(&scan.list[i + 1..i + 1 + entry_len]);
                n += entry_len;
            }
            i += entry_len + 1; // Correct stride (matches C line 280).
        }

        mesh_model_send(
            &scan.node,
            0,
            scan.client,
            APP_IDX_DEV_LOCAL,
            scan.net_idx,
            DEFAULT_TTL,
            true,
            &msg[..n],
        );
    }
}

// =========================================================================
// Phase 6 — Scan Packet Callback
// =========================================================================

/// Build the `scan_pkt` callback closure to register with mesh I/O.
///
/// Mirrors C `scan_pkt()` (remprv-server.c lines 291-435).
fn build_scan_pkt_cb() -> MeshIoRecvFn {
    Arc::new(move |info: &MeshIoRecvInfo, data: &[u8]| {
        scan_pkt_handler(info, data);
    })
}

/// Core scan-packet handler, extracted for clarity.
fn scan_pkt_handler(info: &MeshIoRecvInfo, data: &[u8]) {
    let len = data.len();

    // Extract RSSI and address from info.
    let rssi: i8 = info.rssi;
    let addr: [u8; 6] = info.addr;

    // ── Determine if this is an extended scan ────────────────────────
    let is_ext = {
        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        match guard.as_ref() {
            Some(s) => s.ext_cnt > 0,
            None => return,
        }
    };

    if is_ext {
        ext_scan_pkt(rssi, &addr, data, len);
    } else {
        regular_scan_pkt(rssi, data, len);
    }
}

/// Handle a regular (non-extended) scan advertisement.
fn regular_scan_pkt(rssi: i8, data: &[u8], len: usize) {
    // Validate: unprovisioned device beacon.
    if len < 2 || data[0] != BT_AD_MESH_BEACON || data[1] != 0x00 {
        return;
    }
    if len != 18 && len != 20 && len != 24 {
        return;
    }

    let pkt = &data[2..];
    let pkt_len = len - 2;

    // Lock, dedup, store, and prepare the response.
    let send_data = {
        let mut guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        let scan = match guard.as_mut() {
            Some(s) => s,
            None => return,
        };

        // UUID filter check.
        if scan.fltr && pkt[..16] != scan.uuid {
            return;
        }

        let mut report = false;
        let mut filled: u8 = 0;

        for slot in 0..scan.scanned_limit as usize {
            let base = slot * SCAN_ENTRY_SIZE;
            if base + SCAN_ENTRY_SIZE > scan.list.len() {
                break;
            }

            let stored_uuid = &scan.list[base + 1..base + 1 + 16];
            if stored_uuid == &pkt[..16] {
                // Repeat UUID — update RSSI if stronger.
                if (scan.list[base] as i8) < rssi {
                    report = true;
                    scan.list[base] = rssi as u8;
                }
            } else if stored_uuid == ZERO_16 {
                // Empty slot — store new entry.
                report = true;
                scan.list[base] = rssi as u8;
                scan.list[base + 1..base + 1 + 16].copy_from_slice(&pkt[..16]);
            }

            filled += 1;

            if report {
                break;
            }
        }

        if !report {
            return;
        }

        // Build scan report message.
        let mut msg = [0u8; 22 + EXT_LIST_SIZE];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_SCAN_REPORT, &mut msg);
        msg[n] = rssi as u8;
        n += 1;
        let copy_len = pkt_len.min(msg.len() - n);
        msg[n..n + copy_len].copy_from_slice(&pkt[..copy_len]);
        n += copy_len;

        // Always include oob_info even if not in beacon.
        if pkt_len == 16 {
            msg[n..n + 2].copy_from_slice(&0u16.to_le_bytes());
            n += 2;
        }

        print_packet("App Tx", &msg[..n]);
        let node = Arc::clone(&scan.node);
        let client = scan.client;
        let net_idx = scan.net_idx;
        let scanned_limit = scan.scanned_limit;

        mesh_model_send(&node, 0, client, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);

        // Check if scanning is complete.
        filled == scanned_limit
    };

    // If scan list is full, cancel the scan.
    if send_data {
        remprv_scan_cancel(false);
    }
}

/// Handle an extended scan advertisement.
fn ext_scan_pkt(_rssi: i8, addr: &[u8; 6], data: &[u8], len: usize) {
    let ready_to_report: bool;

    {
        let mut guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        let scan = match guard.as_mut() {
            Some(s) => s,
            None => return,
        };

        if data[0] == BT_AD_MESH_BEACON && len >= 2 && data[1] == 0x00 {
            // Unprovisioned beacon in extended scan context.
            if len != 18 && len != 20 && len != 24 {
                return;
            }

            // Check UUID match.
            if data.len() < 18 || data[2..18] != scan.uuid {
                return;
            }

            // If address changed, reset collected AD data.
            if scan.addr != *addr {
                if !scan.list.is_empty() {
                    scan.list[0] = 0;
                }
                scan.rxed_ads = 0;
            }

            scan.addr = *addr;
            scan.fltr = true;

            if len >= 20 {
                scan.oob_info = u16::from_le_bytes([data[18], data[19]]);
            }

            if scan.rxed_ads != scan.ext_cnt {
                return;
            }
        } else if data[0] != BT_AD_MESH_BEACON {
            // Non-beacon AD type in extended scan.
            if !scan.fltr || scan.addr != *addr {
                // Walk existing TLV list and check for duplicate AD type.
                let mut i: usize = 0;
                while i < scan.list.len() && scan.list[i] != 0 {
                    let entry_len = scan.list[i] as usize;
                    if i + 1 < scan.list.len() && scan.list[i + 1] == data[0] {
                        // Already seen this AD type.
                        return;
                    }
                    i += entry_len + 1;
                }

                // Overflow protection.
                if i + len + 1 > EXT_LIST_SIZE {
                    return;
                }

                // Store TLV entry: [len][data…][0-terminator].
                if i + 1 + len < scan.list.len() {
                    scan.list[i] = len as u8;
                    scan.list[i + 1..i + 1 + len].copy_from_slice(data);
                    if i + len + 1 < scan.list.len() {
                        scan.list[i + len + 1] = 0;
                    }
                }
                scan.rxed_ads += 1;
            }

            if scan.rxed_ads != scan.ext_cnt {
                return;
            }
        } else {
            // Other beacon types — ignore.
            return;
        }

        // All AD types collected — build extended scan report.
        let mut msg = [0u8; 22 + EXT_LIST_SIZE];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_EXT_SCAN_REPORT, &mut msg);
        msg[n] = PB_REM_ERR_SUCCESS;
        n += 1;
        msg[n..n + 16].copy_from_slice(&scan.uuid);
        n += 16;
        msg[n..n + 2].copy_from_slice(&scan.oob_info.to_le_bytes());
        n += 2;

        // Walk TLV list (replicates C line 419-425 stride: i += list[i]).
        let mut i: usize = 0;
        while i < scan.list.len() && scan.list[i] != 0 {
            let entry_len = scan.list[i] as usize;
            if n < msg.len() {
                msg[n] = scan.list[i];
                n += 1;
            }
            if i + 1 + entry_len <= scan.list.len() && n + entry_len <= msg.len() {
                msg[n..n + entry_len].copy_from_slice(&scan.list[i + 1..i + 1 + entry_len]);
                n += entry_len;
            }
            // Replicate C scan_pkt stride (line 424).
            i += entry_len;
        }

        print_packet("App Tx", &msg[..n]);
        mesh_model_send(
            &scan.node,
            0,
            scan.client,
            APP_IDX_DEV_LOCAL,
            scan.net_idx,
            DEFAULT_TTL,
            true,
            &msg[..n],
        );

        ready_to_report = true;
    }

    // Extended scan always cleans up after reporting.
    if ready_to_report {
        remprv_scan_cancel(false);
    }
}

// =========================================================================
// Phase 7 — PB-ADV Bearer Callbacks
// =========================================================================

/// PB-ADV open callback: transitions LINK_OPENING → LINK_ACTIVE and
/// sends `OP_REM_PROV_LINK_REPORT`.
///
/// Mirrors C `srv_open()` (remprv-server.c lines 102-123).
fn srv_open(_user_data: usize, adv_tx: ProvTransTx, _trans_data: usize, _nppi_proc: u8) {
    let (node, client, net_idx) = {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        let prov = match guard.as_mut() {
            Some(p) => p,
            None => return,
        };
        if prov.state != PB_REMOTE_STATE_LINK_OPENING {
            return;
        }

        debug!("Remote Link open confirmed");

        // Store the PB-ADV transmit function.
        if let ProvLinkData::Adv { ref mut tx, .. } = prov.link {
            *tx = Some(adv_tx);
        }
        prov.state = PB_REMOTE_STATE_LINK_ACTIVE;

        (Arc::clone(&prov.node), prov.client, prov.net_idx)
    };

    let mut msg = [0u8; 5];
    let mut n = mesh_model_opcode_set(OP_REM_PROV_LINK_REPORT, &mut msg);
    msg[n] = PB_REM_ERR_SUCCESS;
    n += 1;
    msg[n] = PB_REMOTE_STATE_LINK_ACTIVE;
    n += 1;

    mesh_model_send(&node, 0, client, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
}

/// PB-ADV receive callback: increments `svr_pdu_num` and forwards the
/// inbound PDU as `OP_REM_PROV_PDU_REPORT`.
///
/// Mirrors C `srv_rx()` (remprv-server.c lines 125-146).
fn srv_rx(_user_data: usize, dptr: &[u8]) {
    if dptr.len() > 65 {
        return;
    }

    let (node, client, net_idx, pdu_num) = {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        let prov = match guard.as_mut() {
            Some(p) => p,
            None => return,
        };
        if prov.state < PB_REMOTE_STATE_LINK_ACTIVE {
            return;
        }
        debug!("Remote PB IB-PDU");
        prov.svr_pdu_num = prov.svr_pdu_num.wrapping_add(1);
        (Arc::clone(&prov.node), prov.client, prov.net_idx, prov.svr_pdu_num)
    };

    let mut msg = [0u8; 69];
    let mut n = mesh_model_opcode_set(OP_REM_PROV_PDU_REPORT, &mut msg);
    msg[n] = pdu_num;
    n += 1;
    let copy_len = dptr.len().min(65);
    msg[n..n + copy_len].copy_from_slice(&dptr[..copy_len]);
    n += copy_len;

    mesh_model_send(&node, 0, client, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
}

/// PB-ADV acknowledge callback: transitions OB_PKT_TX → LINK_ACTIVE and
/// sends `OP_REM_PROV_PDU_OB_REPORT`.
///
/// Mirrors C `srv_ack()` (remprv-server.c lines 148-165).
fn srv_ack(_user_data: usize, _msg_num: u8) {
    let (node, client, net_idx, cli_pdu) = {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        let prov = match guard.as_mut() {
            Some(p) => p,
            None => return,
        };
        if prov.state != PB_REMOTE_STATE_OB_PKT_TX {
            return;
        }
        debug!("Remote PB ACK");
        prov.state = PB_REMOTE_STATE_LINK_ACTIVE;
        (Arc::clone(&prov.node), prov.client, prov.net_idx, prov.cli_pdu_num)
    };

    let mut msg = [0u8; 4];
    let mut n = mesh_model_opcode_set(OP_REM_PROV_PDU_OB_REPORT, &mut msg);
    msg[n] = cli_pdu;
    n += 1;

    mesh_model_send(&node, 0, client, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
}

/// PB-ADV close callback: transitions to LINK_CLOSING and sends
/// `OP_REM_PROV_LINK_REPORT` with the reason.
///
/// Mirrors C `srv_close()` (remprv-server.c lines 167-185).
fn srv_close(_user_data: usize, reason: u8) {
    let (node, client, net_idx, state) = {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        let prov = match guard.as_mut() {
            Some(p) => p,
            None => return,
        };
        if prov.state < PB_REMOTE_STATE_LINK_ACTIVE {
            return;
        }
        debug!("Remote PB Close");
        prov.state = PB_REMOTE_STATE_LINK_CLOSING;
        (Arc::clone(&prov.node), prov.client, prov.net_idx, prov.state)
    };

    let mut msg = [0u8; 5];
    let mut n = mesh_model_opcode_set(OP_REM_PROV_LINK_REPORT, &mut msg);
    msg[n] = state;
    n += 1;
    msg[n] = reason;
    n += 1;

    mesh_model_send(&node, 0, client, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
}

// =========================================================================
// Phase 8 — NPPI (Node Provisioning Protocol Interface)
// =========================================================================

/// Deferred link-active notification for NPPI path.
///
/// Mirrors C `link_active()` (remprv-server.c lines 472-490), invoked
/// via `l_idle_oneshot` in the original code.  Here we `tokio::spawn` so
/// the caller returns first, preserving the deferred semantics.
fn link_active_deferred() {
    tokio::spawn(async {
        tokio::task::yield_now().await;

        let (node, client, net_idx) = {
            let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
            let prov = match guard.as_mut() {
                Some(p) => p,
                None => return,
            };
            if prov.state != PB_REMOTE_STATE_LINK_OPENING {
                return;
            }
            debug!("Remote Link open confirmed (NPPI)");
            prov.state = PB_REMOTE_STATE_LINK_ACTIVE;
            (Arc::clone(&prov.node), prov.client, prov.net_idx)
        };

        let mut msg = [0u8; 5];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_LINK_REPORT, &mut msg);
        msg[n] = PB_REM_ERR_SUCCESS;
        n += 1;
        msg[n] = PB_REMOTE_STATE_LINK_ACTIVE;
        n += 1;

        mesh_model_send(&node, 0, client, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
    });
}

/// Register NPPI acceptor callbacks for device-key refresh.
///
/// Mirrors C `register_nppi_acceptor()` (remprv-server.c lines 492-514).
///
/// The provisioning acceptor calls this to supply its open/close/rx/ack
/// callbacks.  The RP server stores them, invokes `open_cb` immediately
/// with a transmit function (that relays PDUs as `PDU_REPORT`), and
/// schedules a deferred link-active notification.
pub fn register_nppi_acceptor(
    mut open_cb: ProvOpenCb,
    close_cb: ProvCloseCb,
    rx_cb: ProvRxCb,
    ack_cb: ProvAckCb,
    user_data: usize,
) -> bool {
    // Extract info needed before calling open_cb.
    let (nppi_proc, trans_data_val) = {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        let prov = match guard.as_mut() {
            Some(p) => p,
            None => return false,
        };
        if prov.nppi_proc == RPR_ADV {
            return false;
        }
        let proc_val = prov.nppi_proc;

        // Store NPPI callbacks.
        prov.link = ProvLinkData::Nppi {
            _close_cb: Some(close_cb),
            rx_cb: Some(rx_cb),
            _ack_cb: Some(ack_cb),
            info: MeshProvNodeInfo {
                device_key: [0u8; 16],
                net_key: [0u8; 16],
                net_index: 0,
                flags: 0,
                iv_index: 0,
                unicast: 0,
                num_ele: 0,
            },
        };
        prov.trans_data = user_data;

        (proc_val, user_data)
    };

    // Build the ProvTransTx closure that relays PDUs as PDU_REPORT
    // (equivalent of passing srv_rx to open_cb in the C code).
    let tx: ProvTransTx = Box::new(move |data: &[u8]| -> bool {
        srv_rx(0, data);
        true
    });

    // Call the acceptor's open_cb.
    open_cb(trans_data_val, tx, trans_data_val, nppi_proc);

    // Schedule deferred link-active notification.
    link_active_deferred();

    true
}

/// NPPI completion callback.
///
/// Mirrors C `nppi_cmplt()` (remprv-server.c lines 516-527).
/// Called by the provisioning acceptor when NPPI finishes.  Saves the
/// resulting node info for application during link close.
fn nppi_cmplt(_caller_data: usize, _status: u8, info: Option<MeshProvNodeInfo>) {
    let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
    let prov = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };
    if let Some(node_info) = info {
        if let ProvLinkData::Nppi { ref mut info, .. } = prov.link {
            *info = node_info;
        }
    }
}

/// Initiate an NPPI device-key refresh via the provisioning acceptor.
///
/// Mirrors C `start_dev_key_refresh()` (remprv-server.c lines 529-537).
fn start_dev_key_refresh(node: &Arc<MeshNode>, nppi_proc: u8) -> bool {
    let num_ele = node.get_num_elements();

    // Set nppi_proc on the current provisioning session.
    {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut prov) = *guard {
            prov.nppi_proc = nppi_proc;
        }
    }

    // Obtain the node's agent for the acceptor.
    let agent_opt = {
        let agent_ref = node.get_agent();
        agent_ref.clone()
    };
    let agent = match agent_opt {
        Some(a) => Arc::new(a),
        None => {
            // Create a minimal agent if none exists (C passes NULL).
            Arc::new(crate::agent::MeshAgent {
                path: String::new(),
                owner: String::new(),
                caps: crate::agent::MeshAgentProvCaps::default(),
            })
        }
    };

    // Spawn the async acceptor_start in a background task.
    let node_clone = Arc::clone(node);
    tokio::spawn(async move {
        let result = crate::provisioning::acceptor::acceptor_start(
            num_ele,
            None,
            0x0001,
            60,
            agent,
            move |_caller_data: usize, status: u8, info: Option<MeshProvNodeInfo>| {
                nppi_cmplt(0, status, info);
            },
            0,
        )
        .await;

        if !result {
            error!("NPPI acceptor_start failed for node {:04x}", node_clone.get_primary());
        }
    });

    true
}

// =========================================================================
// Phase 9 — Main Opcode Dispatcher
// =========================================================================

/// Process an incoming access-layer message for the Remote Provisioning
/// Server model.
///
/// Mirrors C `remprv_srv_pkt()` (remprv-server.c lines 539-903).
///
/// Returns `true` if the opcode was handled (even if silently dropped),
/// `false` if the opcode is unrecognised.
fn remprv_srv_pkt(
    node: &Arc<MeshNode>,
    src: u16,
    _unicast: u16,
    app_idx: u16,
    net_idx: u16,
    data: &[u8],
) -> bool {
    if app_idx != APP_IDX_DEV_LOCAL {
        return false;
    }

    let (opcode, consumed) = match mesh_model_opcode_get(data) {
        Some(v) => v,
        None => return false,
    };

    let pkt = &data[consumed..];
    let size = data.len() - consumed;

    // Working message buffer — 69 bytes covers the longest possible
    // response (extended scan report with AD data).
    let mut msg = [0u8; 69];
    let mut n: usize;
    let segmented = false;

    match opcode {
        // ── Scan Capability Get ──────────────────────────────────────
        OP_REM_PROV_SCAN_CAP_GET => {
            if size != 0 {
                return true;
            }
            n = mesh_model_opcode_set(OP_REM_PROV_SCAN_CAP_STATUS, &mut msg);
            msg[n] = PB_REMOTE_MAX_SCAN_QUEUE_SIZE as u8;
            n += 1;
            msg[n] = 1; // Active scanning supported
            n += 1;
        }

        // ── Extended Scan Start ──────────────────────────────────────
        OP_REM_PROV_EXT_SCAN_START => {
            return handle_ext_scan_start(node, src, net_idx, pkt, size);
        }

        // ── Scan Start ───────────────────────────────────────────────
        OP_REM_PROV_SCAN_START => {
            return handle_scan_start(node, src, net_idx, pkt, size);
        }

        // ── Scan Get ─────────────────────────────────────────────────
        OP_REM_PROV_SCAN_GET => {
            n = mesh_model_opcode_set(OP_REM_PROV_SCAN_STATUS, &mut msg);
            let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
            msg[n] = PB_REM_ERR_SUCCESS;
            n += 1;
            msg[n] = guard.as_ref().map_or(0, |s| s.state);
            n += 1;
            msg[n] =
                guard.as_ref().map_or(PB_REMOTE_MAX_SCAN_QUEUE_SIZE as u8, |s| s.scanned_limit);
            n += 1;
            msg[n] = guard.as_ref().map_or(0, |s| s.to_secs);
            n += 1;
        }

        // ── Scan Stop ────────────────────────────────────────────────
        OP_REM_PROV_SCAN_STOP => {
            if size != 0 {
                return true;
            }
            {
                let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
                if guard.is_none() {
                    return true;
                }
            }
            remprv_scan_cancel(false);
            return true;
        }

        // ── Link Get ─────────────────────────────────────────────────
        OP_REM_PROV_LINK_GET => {
            if size != 0 {
                return true;
            }
            let guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref prov) = *guard {
                let pnode = Arc::clone(&prov.node);
                let pclient = prov.client;
                let pnet = prov.net_idx;
                let pstate = prov.state;
                drop(guard);
                send_prov_status(&pnode, pclient, pnet, pstate, PB_REM_ERR_SUCCESS);
            }
            return true;
        }

        // ── Link Open ────────────────────────────────────────────────
        OP_REM_PROV_LINK_OPEN => {
            return handle_link_open(node, src, net_idx, pkt, size);
        }

        // ── Link Close ───────────────────────────────────────────────
        OP_REM_PROV_LINK_CLOSE => {
            return handle_link_close(node, src, pkt, size);
        }

        // ── PDU Send ─────────────────────────────────────────────────
        OP_REM_PROV_PDU_SEND => {
            return handle_pdu_send(node, src, pkt, size);
        }

        // ── Unknown opcode ───────────────────────────────────────────
        _ => {
            return false;
        }
    }

    // ── Common send path (mirrors C `send_pkt:` label) ───────────────
    debug!("PB-SVR: src {:04x} dst {:04x}", _unicast, src);
    print_packet("App Tx", &msg[..n]);
    mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, segmented, &msg[..n]);

    true
}

// =========================================================================
// Phase 10 — Extended Scan Start Handler
// =========================================================================

/// Handle `OP_REM_PROV_EXT_SCAN_START`.
///
/// Mirrors C lines 583-684.  Three sub-cases:
///   1. `ad_cnt + 1 == size` — local device info request (no UUID).
///   2. `ad_cnt + 18 == size` — remote device extended scan.
///   3. Otherwise — malformed, silently dropped.
fn handle_ext_scan_start(
    node: &Arc<MeshNode>,
    src: u16,
    net_idx: u16,
    pkt: &[u8],
    size: usize,
) -> bool {
    if size == 0 || pkt[0] == 0 {
        return true;
    }

    let ad_cnt = pkt[0] as usize;

    // Determine sub-case.
    let remote = ad_cnt + 18 == size;
    let local = ad_cnt + 1 == size;

    if !remote && !local {
        return true;
    }

    if remote {
        // Last byte is timeout (1..5 seconds).
        let timeout_val = pkt[size - 1];
        if timeout_val == 0 || timeout_val > 5 {
            return true;
        }
    }

    // ── Sub-case 1: local device extended info ───────────────────────
    if local {
        let mut msg = [0u8; 69];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_EXT_SCAN_REPORT, &mut msg);
        msg[n] = PB_REM_ERR_SUCCESS;
        n += 1;
        let uuid = node.get_uuid();
        msg[n..n + 16].copy_from_slice(&uuid);
        n += 16;
        // OOB info = 0.
        msg[n] = 0;
        n += 1;
        msg[n] = 0;
        n += 1;

        // Walk the AD type list looking for NAME_COMPLETE.
        for ad_idx in 0..ad_cnt {
            let ad_type = pkt[1 + ad_idx];
            if ad_type == BT_AD_NAME_COMPLETE {
                let name_bytes = LOCAL_NAME.as_bytes();
                let avail = msg.len().saturating_sub(n + 1);
                let ad_len = (name_bytes.len() + 1).min(avail);
                msg[n] = ad_len as u8;
                n += 1;
                msg[n] = BT_AD_NAME_COMPLETE;
                n += 1;
                let copy_len = (ad_len.saturating_sub(1)).min(name_bytes.len());
                msg[n..n + copy_len].copy_from_slice(&name_bytes[..copy_len]);
                n += copy_len;
                break;
            }
        }

        debug!("Send internal extended info {}", n);
        print_packet("App Tx", &msg[..n]);
        mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
        return true;
    }

    // ── Sub-case 2: remote device extended scan ──────────────────────

    // Check for conflict with an existing scan session.
    let mut conflict = false;
    {
        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref scan) = *guard {
            if scan.client != src
                || !Arc::ptr_eq(&scan.node, node)
                || scan.ext_cnt as usize != ad_cnt
                || (scan.ext.len() >= ad_cnt
                    && pkt.len() > ad_cnt
                    && scan.ext[..ad_cnt] != pkt[1..1 + ad_cnt])
                || (pkt.len() >= ad_cnt + 17 && scan.uuid != pkt[ad_cnt + 1..ad_cnt + 17])
            {
                conflict = true;
            }
        }
    }

    if conflict {
        let mut msg = [0u8; 69];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_EXT_SCAN_REPORT, &mut msg);
        msg[n] = PB_REM_ERR_SCANNING_CANNOT_START;
        n += 1;
        msg[n..n + 16].fill(0);
        n += 16;
        print_packet("App Tx", &msg[..n]);
        mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, true, &msg[..n]);
        return true;
    }

    // Reject if a scan is already in progress (from this same client).
    {
        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_some() {
            return true;
        }
    }

    // Build the scan callback closure.
    let scan_cb = build_scan_pkt_cb();

    // Validate and register extended AD type filters.
    let mut registered: Vec<u8> = Vec::with_capacity(ad_cnt);
    for idx in 0..ad_cnt {
        let ad = pkt[1 + idx];
        if !register_ext_ad_type(ad, Arc::clone(&scan_cb)) {
            // Undo partial registrations.
            for &prev in &registered {
                deregister_ext_ad_type(prev);
            }
            return true;
        }
        registered.push(ad);
    }

    // Extract target UUID from the request.
    let uuid_start = ad_cnt + 1;
    let mut scan_uuid = [0u8; 16];
    scan_uuid.copy_from_slice(&pkt[uuid_start..uuid_start + 16]);

    // Build ext AD type list.
    let mut ext_list = vec![0u8; ad_cnt];
    ext_list.copy_from_slice(&pkt[1..1 + ad_cnt]);

    let timeout_secs = pkt[size - 1];

    // Create new scan context.
    let scan = RemScanData {
        node: Arc::clone(node),
        timeout: None,
        list: vec![0u8; EXT_LIST_SIZE],
        client: src,
        oob_info: 0,
        net_idx,
        state: PB_REMOTE_SCAN_DETAILED,
        scanned_limit: 0,
        addr: [0u8; 6],
        uuid: scan_uuid,
        to_secs: timeout_secs,
        rxed_ads: 0,
        ext_cnt: ad_cnt as u8,
        fltr: true,
        ext: ext_list,
    };

    {
        let mut guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(scan);
    }

    // Register the unprovisioned beacon filter.
    mesh_io_register_recv_cb(&PRVB, scan_cb);

    // Create timeout for the extended scan.
    let timeout_handle = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(timeout_secs as u64)).await;
        remprv_scan_cancel(true);
    });

    {
        let mut guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut s) = *guard {
            s.timeout = Some(timeout_handle);
        }
    }

    true
}

// =========================================================================
// Phase 10b — Scan Start Handler
// =========================================================================

/// Handle `OP_REM_PROV_SCAN_START`.
///
/// Mirrors C lines 685-744.  The message is either 2 or 18 bytes:
///   - `[scan_limit, timeout]` — unlimited scan
///   - `[scan_limit, timeout, uuid[16]]` — UUID-filtered scan
///
/// After starting the scan, falls through to compose and send a
/// `SCAN_STATUS` response (same as SCAN_GET).
fn handle_scan_start(
    node: &Arc<MeshNode>,
    src: u16,
    net_idx: u16,
    pkt: &[u8],
    size: usize,
) -> bool {
    if size != 2 && size != 18 {
        return true;
    }
    // Timeout must be non-zero.
    if pkt[1] == 0 {
        return true;
    }

    let has_uuid = size == 18;
    let mut scan_conflict = false;

    // Check for conflict with an existing scan.
    {
        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref scan) = *guard {
            if scan.ext_cnt > 0
                || scan.client != src
                || !Arc::ptr_eq(&scan.node, node)
                || scan.fltr != has_uuid
                || (scan.fltr && pkt.len() >= 18 && scan.uuid != pkt[2..18])
            {
                scan_conflict = true;
            }
        }
    }

    if scan_conflict {
        let mut msg = [0u8; 8];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_SCAN_STATUS, &mut msg);
        msg[n] = PB_REM_ERR_SCANNING_CANNOT_START;
        n += 1;

        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        msg[n] = guard.as_ref().map_or(0, |s| s.state);
        n += 1;
        msg[n] = guard.as_ref().map_or(PB_REMOTE_MAX_SCAN_QUEUE_SIZE as u8, |s| s.scanned_limit);
        n += 1;
        msg[n] = guard.as_ref().map_or(0, |s| s.to_secs);
        n += 1;
        drop(guard);

        print_packet("App Tx", &msg[..n]);
        mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, false, &msg[..n]);
        return true;
    }

    // Build the scan callback closure.
    let scan_cb = build_scan_pkt_cb();

    // Create or reuse scan state.
    {
        let mut guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(RemScanData {
                node: Arc::clone(node),
                timeout: None,
                list: vec![0u8; EXT_LIST_SIZE],
                client: src,
                oob_info: 0,
                net_idx,
                state: PB_REMOTE_SCAN_NONE,
                scanned_limit: PB_REMOTE_MAX_SCAN_QUEUE_SIZE as u8,
                addr: [0u8; 6],
                uuid: [0u8; 16],
                to_secs: 0,
                rxed_ads: 0,
                ext_cnt: 0,
                fltr: false,
                ext: Vec::new(),
            });
        }

        let scan = guard.as_mut().unwrap();
        if has_uuid {
            scan.uuid.copy_from_slice(&pkt[2..18]);
            scan.fltr = true;
            scan.state = PB_REMOTE_SCAN_LIMITED;
        } else {
            scan.uuid = [0u8; 16];
            scan.fltr = false;
            scan.state = PB_REMOTE_SCAN_UNLIMITED;
        }

        scan.client = src;
        scan.net_idx = net_idx;
        scan.node = Arc::clone(node);
        scan.to_secs = pkt[1];

        if pkt[0] != 0 {
            scan.scanned_limit = pkt[0];
        } else {
            scan.scanned_limit = PB_REMOTE_MAX_SCAN_QUEUE_SIZE as u8;
        }
    }

    // Register beacon filter.
    mesh_io_register_recv_cb(&PRVB, scan_cb);

    // Create timeout.
    let to_secs = pkt[1];
    let timeout_handle = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(to_secs as u64)).await;
        remprv_scan_cancel(true);
    });

    {
        let mut guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut s) = *guard {
            if let Some(old) = s.timeout.take() {
                old.abort();
            }
            s.timeout = Some(timeout_handle);
        }
    }

    // Compose and send SCAN_STATUS (falls through like SCAN_GET in C).
    let mut msg = [0u8; 8];
    let mut n = mesh_model_opcode_set(OP_REM_PROV_SCAN_STATUS, &mut msg);
    {
        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        msg[n] = PB_REM_ERR_SUCCESS;
        n += 1;
        msg[n] = guard.as_ref().map_or(0, |s| s.state);
        n += 1;
        msg[n] = guard.as_ref().map_or(PB_REMOTE_MAX_SCAN_QUEUE_SIZE as u8, |s| s.scanned_limit);
        n += 1;
        msg[n] = guard.as_ref().map_or(0, |s| s.to_secs);
        n += 1;
    }

    print_packet("App Tx", &msg[..n]);
    mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, false, &msg[..n]);

    true
}

// =========================================================================
// Phase 10c — Link Open Handler
// =========================================================================

/// Handle `OP_REM_PROV_LINK_OPEN`.
///
/// Mirrors C lines 766-838.  Three sub-cases by size:
///   - 16: PB-ADV link open with UUID (no timeout).
///   - 17: PB-ADV link open with UUID + timeout byte.
///   - 1:  NPPI device-key refresh with procedure type.
fn handle_link_open(node: &Arc<MeshNode>, src: u16, net_idx: u16, pkt: &[u8], size: usize) -> bool {
    if size != 16 && size != 17 && size != 1 {
        return true;
    }
    // Validate timeout range for the 17-byte variant.
    if size == 17 && (pkt[16] == 0 || pkt[16] > 0x3c) {
        return true;
    }
    // Validate NPPI procedure for the 1-byte variant.
    if size == 1 && pkt[0] > 0x02 {
        return true;
    }

    // Check for an existing provisioning session.
    {
        let guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref prov) = *guard {
            // Determine whether the existing session conflicts.
            let mismatch = if prov.client != src || !Arc::ptr_eq(&prov.node, node) {
                true
            } else if size == 1 {
                prov.nppi_proc != pkt[0]
            } else if prov.nppi_proc == RPR_ADV {
                if let ProvLinkData::Adv { ref uuid, .. } = prov.link {
                    *uuid != pkt[..16]
                } else {
                    true
                }
            } else {
                true
            };

            if mismatch {
                // Reject: link in progress with different parameters.
                let prov_node = Arc::clone(&prov.node);
                let prov_client = prov.client;
                let prov_net_idx = prov.net_idx;
                let prov_state = prov.state;
                drop(guard);

                send_prov_status(
                    &prov_node,
                    prov_client,
                    prov_net_idx,
                    prov_state,
                    PB_REM_ERR_LINK_CANNOT_OPEN,
                );

                let mut msg = [0u8; 5];
                let mut nn = mesh_model_opcode_set(OP_REM_PROV_LINK_STATUS, &mut msg);
                msg[nn] = PB_REM_ERR_LINK_CANNOT_OPEN;
                nn += 1;
                msg[nn] = PB_REMOTE_STATE_LINK_ACTIVE;
                nn += 1;

                mesh_model_send(
                    node,
                    0,
                    src,
                    APP_IDX_DEV_LOCAL,
                    net_idx,
                    DEFAULT_TTL,
                    false,
                    &msg[..nn],
                );
                return true;
            }

            // Redundant success — same link already open.
            let prov_node = Arc::clone(&prov.node);
            let prov_client = prov.client;
            let prov_net_idx = prov.net_idx;
            let prov_state = prov.state;
            drop(guard);
            send_prov_status(&prov_node, prov_client, prov_net_idx, prov_state, PB_REM_ERR_SUCCESS);
            return true;
        }
    }

    // Check conflict with an active scan from a different client.
    {
        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref scan) = *guard {
            if scan.client != src || !Arc::ptr_eq(&scan.node, node) {
                drop(guard);
                let mut msg = [0u8; 5];
                let mut nn = mesh_model_opcode_set(OP_REM_PROV_LINK_STATUS, &mut msg);
                msg[nn] = PB_REM_ERR_LINK_CANNOT_OPEN;
                nn += 1;
                msg[nn] = PB_REMOTE_STATE_IDLE;
                nn += 1;
                mesh_model_send(
                    node,
                    0,
                    src,
                    APP_IDX_DEV_LOCAL,
                    net_idx,
                    DEFAULT_TTL,
                    false,
                    &msg[..nn],
                );
                return true;
            }
        }
    }

    print_packet("Remote Prov Link Open", pkt);

    // Cancel any active scan.
    remprv_scan_cancel(false);

    // Create new provisioning session.
    let prov = RemProvData {
        node: Arc::clone(node),
        timeout: None,
        trans_data: 0,
        client: src,
        net_idx,
        svr_pdu_num: 0,
        cli_pdu_num: 0,
        state: PB_REMOTE_STATE_LINK_OPENING,
        nppi_proc: RPR_ADV,
        link: ProvLinkData::Idle,
    };

    {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(prov);
    }

    let link_status: bool;

    if size == 1 {
        // NPPI device-key refresh.
        link_status = start_dev_key_refresh(node, pkt[0]);
    } else {
        // PB-ADV link.
        if size == 17 {
            let timeout_secs = pkt[16];
            let timeout_handle = tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(timeout_secs as u64)).await;
                remprv_prov_cancel();
            });
            let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref mut p) = *guard {
                p.timeout = Some(timeout_handle);
            }
        }

        {
            let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref mut p) = *guard {
                p.nppi_proc = RPR_ADV;
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&pkt[..16]);
                p.link = ProvLinkData::Adv { uuid, tx: None };
            }
        }

        // Build PB-ADV bearer callbacks.
        let open_cb: ProvOpenCb = Box::new(srv_open);
        let close_cb: ProvCloseCb = Box::new(srv_close);
        let rx_cb: ProvRxCb = Box::new(srv_rx);
        let ack_cb: ProvAckCb = Box::new(srv_ack);

        let mut uuid_arr = [0u8; 16];
        uuid_arr.copy_from_slice(&pkt[..16]);

        link_status = pb_adv_reg(true, open_cb, close_cb, rx_cb, ack_cb, &uuid_arr, 0);
    }

    if link_status {
        let guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref prov) = *guard {
            let n = Arc::clone(&prov.node);
            let c = prov.client;
            let ni = prov.net_idx;
            let st = prov.state;
            drop(guard);
            send_prov_status(&n, c, ni, st, PB_REM_ERR_SUCCESS);
        }
    } else {
        let mut msg = [0u8; 5];
        let mut nn = mesh_model_opcode_set(OP_REM_PROV_LINK_STATUS, &mut msg);
        msg[nn] = PB_REM_ERR_LINK_CANNOT_OPEN;
        nn += 1;
        msg[nn] = PB_REMOTE_STATE_IDLE;
        nn += 1;

        mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, false, &msg[..nn]);

        remprv_prov_cancel();
    }

    true
}

// =========================================================================
// Phase 10d — Link Close Handler
// =========================================================================

/// Handle `OP_REM_PROV_LINK_CLOSE`.
///
/// Mirrors C lines 840-872.
fn handle_link_close(node: &Arc<MeshNode>, src: u16, pkt: &[u8], size: usize) -> bool {
    if size != 1 {
        return true;
    }

    // Extract needed state under the lock, then release.
    let (old_state, nppi_proc, prov_node, _prov_client, _prov_net_idx) = {
        let guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        let prov = match guard.as_ref() {
            Some(p) => p,
            None => return true,
        };
        if !Arc::ptr_eq(&prov.node, node) || prov.client != src {
            return true;
        }
        (prov.state, prov.nppi_proc, Arc::clone(&prov.node), prov.client, prov.net_idx)
    };

    // Transition to LINK_CLOSING.
    {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut prov) = *guard {
            prov.state = PB_REMOTE_STATE_LINK_CLOSING;
        }
    }

    // Cancel outbound packets.
    mesh_io_send_cancel(&[PKT_FILTER]);

    // Send link status.
    {
        let guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref prov) = *guard {
            let n = Arc::clone(&prov.node);
            let c = prov.client;
            let ni = prov.net_idx;
            let st = prov.state;
            drop(guard);
            send_prov_status(&n, c, ni, st, PB_REM_ERR_SUCCESS);
        }
    }

    // If reason is 0x02 (PROV_FAILED) and link was active, send a
    // failure PDU through the transport.
    if pkt[0] == 0x02 && old_state >= PB_REMOTE_STATE_LINK_ACTIVE {
        let fail_msg: [u8; 2] = [PROV_FAILED, PROV_ERR_CANT_ASSIGN_ADDR];

        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut prov) = *guard {
            if prov.nppi_proc == RPR_ADV {
                if let ProvLinkData::Adv { tx: Some(tx_fn), .. } = &mut prov.link {
                    let _ = tx_fn(&fail_msg);
                }
            } else if let ProvLinkData::Nppi { rx_cb: Some(cb), .. } = &mut prov.link {
                let td = prov.trans_data;
                cb(td, &fail_msg);
            }
        }
    }

    // Clean up.
    if nppi_proc == RPR_ADV {
        pb_adv_unreg(0);
    } else if nppi_proc <= RPR_COMP {
        // Apply NPPI device-key refresh to local node.
        let info_opt = {
            let guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref prov) = *guard {
                if let ProvLinkData::Nppi { ref info, .. } = prov.link {
                    Some(info.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(ref info) = info_opt {
            crate::node::node_refresh(&prov_node, info);
        }
    }

    remprv_prov_cancel();
    true
}

// =========================================================================
// Phase 10e — PDU Send Handler
// =========================================================================

/// Handle `OP_REM_PROV_PDU_SEND`.
///
/// Mirrors C lines 874-893.
fn handle_pdu_send(node: &Arc<MeshNode>, src: u16, pkt: &[u8], size: usize) -> bool {
    if size < 2 {
        return true;
    }

    let nppi_proc;
    let trans_data;

    {
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        let prov = match guard.as_mut() {
            Some(p) => p,
            None => return true,
        };
        if !Arc::ptr_eq(&prov.node, node) || prov.client != src {
            return true;
        }

        prov.cli_pdu_num = pkt[0];
        prov.state = PB_REMOTE_STATE_OB_PKT_TX;

        nppi_proc = prov.nppi_proc;
        trans_data = prov.trans_data;
    }

    let pdu_data = &pkt[1..];

    if nppi_proc == RPR_ADV {
        // Forward via PB-ADV transport.
        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut prov) = *guard {
            if let ProvLinkData::Adv { tx: Some(tx_fn), .. } = &mut prov.link {
                let _ = tx_fn(pdu_data);
            }
        }
    } else {
        // NPPI path: ACK immediately, then forward to acceptor.
        srv_ack(0, 0);

        let mut guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut prov) = *guard {
            if let ProvLinkData::Nppi { rx_cb: Some(cb), .. } = &mut prov.link {
                cb(trans_data, pdu_data);
            }
        }
    }

    true
}

// =========================================================================
// Phase 11 — MeshModelOps Implementation and Init Functions
// =========================================================================

/// Remote Provisioning Server model operations.
///
/// The `MeshModelOps` trait dispatches incoming access-layer messages to
/// `remprv_srv_pkt()`, and rejects binding, subscription, and publication
/// requests (these operations are not applicable to the Remote Provisioning
/// Server model per the Mesh specification).
struct RemProvServerOps {
    node: Arc<MeshNode>,
}

impl MeshModelOps for RemProvServerOps {
    fn unregister(&self) {
        // Mirrors C `remprv_srv_unregister()` — clean up both scan and
        // provisioning state.
        remprv_scan_cancel(false);
        remprv_prov_cancel();
    }

    fn recv(&self, src: u16, unicast: u16, app_idx: u16, net_idx: u16, data: &[u8]) -> bool {
        remprv_srv_pkt(&self.node, src, unicast, app_idx, net_idx, data)
    }

    fn bind(&self, _app_idx: u16, _action: u8) -> i32 {
        // Binding is not permitted for this model.
        -1
    }

    fn publish(&self, _pub_state: &MeshModelPub) -> i32 {
        // Publication is not supported.
        -1
    }

    fn subscribe(&self, _sub_addr: u16, _action: u8) -> i32 {
        // Subscription is not supported.
        -1
    }
}

/// Remote Provisioning Client model operations (minimal — the client side
/// is only registered to satisfy the model composition; actual client
/// functionality is driven by the configuration server).
struct RemProvClientOps;

impl MeshModelOps for RemProvClientOps {
    fn unregister(&self) {
        // No state to clean up on the client side.
    }

    fn recv(&self, _src: u16, _unicast: u16, _app_idx: u16, _net_idx: u16, _data: &[u8]) -> bool {
        // The client model does not handle incoming messages in this
        // implementation; the provisioning client in bluetoothd drives
        // the protocol.
        false
    }

    fn bind(&self, _app_idx: u16, _action: u8) -> i32 {
        -1
    }

    fn publish(&self, _pub_state: &MeshModelPub) -> i32 {
        -1
    }

    fn subscribe(&self, _sub_addr: u16, _action: u8) -> i32 {
        -1
    }
}

/// Initialise the Remote Provisioning Server model on the given node
/// element.
///
/// Mirrors C `remote_prov_server_init()` (remprv-server.c lines 917-920).
pub fn remote_prov_server_init(node: &Arc<MeshNode>, ele_idx: u8) {
    let ops = RemProvServerOps { node: Arc::clone(node) };
    mesh_model_register(node, ele_idx, REM_PROV_SRV_MODEL, Box::new(ops));
}

/// Initialise the Remote Provisioning Client model on the given node
/// element.
///
/// Declared in `mesh/remprv.h` — registers a minimal client-side model.
pub fn remote_prov_client_init(node: &Arc<MeshNode>, ele_idx: u8) {
    let ops = RemProvClientOps;
    mesh_model_register(node, ele_idx, REM_PROV_CLI_MODEL, Box::new(ops));
}

// =========================================================================
// Unit tests — exercised via `cargo test -p bluetooth-meshd`
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ── Model IDs ───────────────────────────────────────────────────────
    #[test]
    fn model_id_srv() {
        assert_eq!(REM_PROV_SRV_MODEL, 0xFFFF_0004);
    }

    #[test]
    fn model_id_cli() {
        assert_eq!(REM_PROV_CLI_MODEL, 0xFFFF_0005);
    }

    // ── Scan queue size ─────────────────────────────────────────────────
    #[test]
    fn max_scan_queue_size() {
        assert_eq!(PB_REMOTE_MAX_SCAN_QUEUE_SIZE, 5);
    }

    // ── Link states ─────────────────────────────────────────────────────
    #[test]
    fn link_states_values() {
        assert_eq!(PB_REMOTE_STATE_IDLE, 0x00);
        assert_eq!(PB_REMOTE_STATE_LINK_OPENING, 0x01);
        assert_eq!(PB_REMOTE_STATE_LINK_ACTIVE, 0x02);
        assert_eq!(PB_REMOTE_STATE_OB_PKT_TX, 0x03);
        assert_eq!(PB_REMOTE_STATE_LINK_CLOSING, 0x04);
    }

    #[test]
    fn link_states_ordered() {
        // Static ordering checks — verified at compile time to match the C enum order.
        const _: () = assert!(PB_REMOTE_STATE_IDLE < PB_REMOTE_STATE_LINK_OPENING);
        const _: () = assert!(PB_REMOTE_STATE_LINK_OPENING < PB_REMOTE_STATE_LINK_ACTIVE);
        const _: () = assert!(PB_REMOTE_STATE_LINK_ACTIVE < PB_REMOTE_STATE_OB_PKT_TX);
        const _: () = assert!(PB_REMOTE_STATE_OB_PKT_TX < PB_REMOTE_STATE_LINK_CLOSING);
    }

    // ── Type bitmasks ───────────────────────────────────────────────────
    #[test]
    fn type_bitmasks() {
        assert_eq!(PB_REMOTE_TYPE_LOCAL, 0x01);
        assert_eq!(PB_REMOTE_TYPE_ADV, 0x02);
        assert_eq!(PB_REMOTE_TYPE_GATT, 0x04);
        assert_eq!(PB_REMOTE_TYPE_LOCAL & PB_REMOTE_TYPE_ADV, 0);
        assert_eq!(PB_REMOTE_TYPE_LOCAL & PB_REMOTE_TYPE_GATT, 0);
        assert_eq!(PB_REMOTE_TYPE_ADV & PB_REMOTE_TYPE_GATT, 0);
    }

    // ── Scan types ──────────────────────────────────────────────────────
    #[test]
    fn scan_types() {
        assert_eq!(PB_REMOTE_SCAN_NONE, 0x00);
        assert_eq!(PB_REMOTE_SCAN_UNLIMITED, 0x01);
        assert_eq!(PB_REMOTE_SCAN_LIMITED, 0x02);
        assert_eq!(PB_REMOTE_SCAN_DETAILED, 0x03);
    }

    // ── Opcodes ─────────────────────────────────────────────────────────
    #[test]
    fn opcodes_values() {
        assert_eq!(OP_REM_PROV_SCAN_CAP_GET, 0x804F);
        assert_eq!(OP_REM_PROV_SCAN_CAP_STATUS, 0x8050);
        assert_eq!(OP_REM_PROV_SCAN_GET, 0x8051);
        assert_eq!(OP_REM_PROV_SCAN_START, 0x8052);
        assert_eq!(OP_REM_PROV_SCAN_STOP, 0x8053);
        assert_eq!(OP_REM_PROV_SCAN_STATUS, 0x8054);
        assert_eq!(OP_REM_PROV_SCAN_REPORT, 0x8055);
        assert_eq!(OP_REM_PROV_EXT_SCAN_START, 0x8056);
        assert_eq!(OP_REM_PROV_EXT_SCAN_REPORT, 0x8057);
        assert_eq!(OP_REM_PROV_LINK_GET, 0x8058);
        assert_eq!(OP_REM_PROV_LINK_OPEN, 0x8059);
        assert_eq!(OP_REM_PROV_LINK_CLOSE, 0x805A);
        assert_eq!(OP_REM_PROV_LINK_STATUS, 0x805B);
        assert_eq!(OP_REM_PROV_LINK_REPORT, 0x805C);
        assert_eq!(OP_REM_PROV_PDU_SEND, 0x805D);
        assert_eq!(OP_REM_PROV_PDU_OB_REPORT, 0x805E);
        assert_eq!(OP_REM_PROV_PDU_REPORT, 0x805F);
    }

    #[test]
    fn opcodes_sequential() {
        let opcodes = [
            OP_REM_PROV_SCAN_CAP_GET,
            OP_REM_PROV_SCAN_CAP_STATUS,
            OP_REM_PROV_SCAN_GET,
            OP_REM_PROV_SCAN_START,
            OP_REM_PROV_SCAN_STOP,
            OP_REM_PROV_SCAN_STATUS,
            OP_REM_PROV_SCAN_REPORT,
            OP_REM_PROV_EXT_SCAN_START,
            OP_REM_PROV_EXT_SCAN_REPORT,
            OP_REM_PROV_LINK_GET,
            OP_REM_PROV_LINK_OPEN,
            OP_REM_PROV_LINK_CLOSE,
            OP_REM_PROV_LINK_STATUS,
            OP_REM_PROV_LINK_REPORT,
            OP_REM_PROV_PDU_SEND,
            OP_REM_PROV_PDU_OB_REPORT,
            OP_REM_PROV_PDU_REPORT,
        ];
        assert_eq!(opcodes.len(), 17);
        for (i, &op) in opcodes.iter().enumerate() {
            assert_eq!(op, 0x804F + i as u32, "Opcode at index {i}");
        }
    }

    // ── Error codes ─────────────────────────────────────────────────────
    #[test]
    fn error_codes_values() {
        assert_eq!(PB_REM_ERR_SUCCESS, 0x00);
        assert_eq!(PB_REM_ERR_SCANNING_CANNOT_START, 0x01);
        assert_eq!(PB_REM_ERR_INVALID_STATE, 0x02);
        assert_eq!(PB_REM_ERR_LIMITED_RESOURCES, 0x03);
        assert_eq!(PB_REM_ERR_LINK_CANNOT_OPEN, 0x04);
        assert_eq!(PB_REM_ERR_LINK_OPEN_FAILED, 0x05);
        assert_eq!(PB_REM_ERR_LINK_CLOSED_AS_CANNOT_RX_PDU, 0x06);
        assert_eq!(PB_REM_ERR_LINK_CLOSED_AS_CANNOT_TX_PDU, 0x07);
        assert_eq!(PB_REM_ERR_LINK_CLOSED_BY_DEVICE, 0x08);
        assert_eq!(PB_REM_ERR_LINK_CLOSED_BY_SERVER, 0x09);
        assert_eq!(PB_REM_ERR_LINK_CLOSED_CANNOT_TX_PDU, 0x0A);
    }

    #[test]
    fn error_codes_unique() {
        let mut codes = vec![
            PB_REM_ERR_SUCCESS,
            PB_REM_ERR_SCANNING_CANNOT_START,
            PB_REM_ERR_INVALID_STATE,
            PB_REM_ERR_LIMITED_RESOURCES,
            PB_REM_ERR_LINK_CANNOT_OPEN,
            PB_REM_ERR_LINK_OPEN_FAILED,
            PB_REM_ERR_LINK_CLOSED_AS_CANNOT_RX_PDU,
            PB_REM_ERR_LINK_CLOSED_AS_CANNOT_TX_PDU,
            PB_REM_ERR_LINK_CLOSED_BY_DEVICE,
            PB_REM_ERR_LINK_CLOSED_BY_SERVER,
            PB_REM_ERR_LINK_CLOSED_CANNOT_TX_PDU,
        ];
        let original_len = codes.len();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), original_len, "All error codes must be unique");
    }

    // ── Internal constants ──────────────────────────────────────────────
    #[test]
    fn internal_constants() {
        assert_eq!(EXT_LIST_SIZE, 60);
        assert_eq!(RPR_COMP, 0x02);
        assert_eq!(RPR_ADV, 0xFF);
    }

    // ── ProvLinkData variants ───────────────────────────────────────────
    #[test]
    fn prov_link_data_idle() {
        let link = ProvLinkData::Idle;
        assert!(matches!(link, ProvLinkData::Idle));
    }

    #[test]
    fn prov_link_data_adv() {
        let link = ProvLinkData::Adv { uuid: [0u8; 16], tx: None };
        if let ProvLinkData::Adv { tx, uuid } = &link {
            assert!(tx.is_none());
            assert_eq!(uuid, &[0u8; 16]);
        } else {
            panic!("Expected Adv variant");
        }
    }

    #[test]
    fn prov_link_data_nppi() {
        let link = ProvLinkData::Nppi {
            _close_cb: None,
            rx_cb: None,
            _ack_cb: None,
            info: MeshProvNodeInfo {
                device_key: [0u8; 16],
                net_key: [0u8; 16],
                net_index: 0,
                flags: 0,
                iv_index: 0,
                unicast: 0,
                num_ele: 0,
            },
        };
        if let ProvLinkData::Nppi { info, .. } = &link {
            assert_eq!(info.unicast, 0);
        } else {
            panic!("Expected Nppi variant");
        }
    }

    // ── Global mutex accessibility ──────────────────────────────────────
    #[test]
    fn global_scan_mutex() {
        let guard = RPB_SCAN.lock().unwrap_or_else(|p| p.into_inner());
        // Default is None (not initialized)
        assert!(guard.is_none());
    }

    #[test]
    fn global_prov_mutex() {
        let guard = RPB_PROV.lock().unwrap_or_else(|p| p.into_inner());
        assert!(guard.is_none());
    }
}
