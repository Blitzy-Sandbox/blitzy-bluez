// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Rust rewrite of `mesh/mesh-io-generic.c` (836 lines) +
// `mesh/mesh-io-generic.h` (12 lines) from BlueZ v5.86.
//
// This module implements the **generic HCI I/O backend** that communicates
// directly with the Bluetooth controller via raw HCI user-channel sockets
// for mesh LE advertising and passive/active scanning.  This is the
// fallback backend used when kernel MGMT mesh extensions are unavailable.
//
// Architecture notes
// ------------------
// * All callback chains in the C code (`bt_hci_send` with nested callbacks)
//   are replaced by sequential `.await` on `HciTransport::send_command`.
// * `l_timeout` / `l_idle_oneshot` are replaced by `tokio::spawn` +
//   `tokio::time::sleep`.
// * `l_queue` is replaced by `VecDeque<TxPkt>`.
// * `l_getrandom` is replaced by `rand::RngCore::fill_bytes`.
// * `struct mesh_io_private` is replaced by `GenericIoPrivate` protected
//   by `Arc<tokio::sync::Mutex<…>>`.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use rand::RngCore;
use zerocopy::IntoBytes;

use bluez_shared::hci::transport::{HciError, HciResponse, HciTransport};
use bluez_shared::sys::hci::{
    EVT_LE_ADVERTISING_REPORT,
    // Event constants
    EVT_LE_META_EVENT,
    OCF_LE_SET_ADVERTISE_ENABLE,
    OCF_LE_SET_ADVERTISING_DATA,
    OCF_LE_SET_ADVERTISING_PARAMETERS,
    OCF_LE_SET_EVENT_MASK,
    OCF_LE_SET_RANDOM_ADDRESS,
    OCF_LE_SET_SCAN_ENABLE,
    OCF_LE_SET_SCAN_PARAMETERS,
    OCF_READ_LOCAL_COMMANDS,
    OCF_READ_LOCAL_FEATURES,
    // OCF constants
    OCF_RESET,
    OCF_SET_EVENT_MASK,
    // OGF constants
    OGF_HOST_CTL,
    OGF_INFO_PARAM,
    OGF_LE_CTL,
    le_set_advertise_enable_cp,
    // (read_local_commands_rp, read_local_features_rp, le_advertising_info
    // are available from bluez_shared::sys::hci but are used by raw byte
    // parsing in this module via manual offsets to match C semantics.)
    le_set_advertising_data_cp,
    le_set_advertising_parameters_cp,
    le_set_random_address_cp,
    le_set_scan_enable_cp,
    le_set_scan_parameters_cp,
    opcode,
    // Packed command parameter structs
    set_event_mask_cp,
};

use super::mgmt::mesh_mgmt_clear;
use super::{
    BT_AD_MESH_BEACON, BT_AD_MESH_DATA, BT_AD_MESH_PROV, MESH_AD_MAX_LEN,
    MESH_IO_TX_COUNT_UNLIMITED, MeshIoBackend, MeshIoCaps, MeshIoOpts, MeshIoRecvFn,
    MeshIoRecvInfo, MeshIoReg, MeshIoSendInfo, MeshIoState,
};

// ===========================================================================
// Constants
// ===========================================================================

/// ADV_NONCONN_IND event type used for mesh advertising reports.
const ADV_NONCONN_IND: u8 = 0x03;

/// LE Meta Event sub-event code for Extended Advertising Report.
const EVT_LE_EXT_ADV_REPORT: u8 = 0x0D;

// ===========================================================================
// Support Structs
// ===========================================================================

/// A queued transmit packet carrying both timing information and payload.
///
/// Replaces C `struct tx_pkt` (mesh-io-generic.c lines 52-57).
#[derive(Clone)]
struct TxPkt {
    info: MeshIoSendInfo,
    delete: bool,
    len: u8,
    pkt: [u8; MESH_AD_MAX_LEN],
}

impl TxPkt {
    fn new() -> Self {
        Self {
            info: MeshIoSendInfo::General { interval: 0, cnt: 0, min_delay: 0, max_delay: 0 },
            delete: false,
            len: 0,
            pkt: [0u8; MESH_AD_MAX_LEN],
        }
    }
}

// ===========================================================================
// Internal State
// ===========================================================================

/// Private mutable state for the generic HCI backend.
///
/// Replaces C `struct mesh_io_private` (mesh-io-generic.c lines 34-43).
/// Protected by `Arc<TokioMutex<…>>` for shared access across async tasks.
struct GenericIoPrivate {
    /// HCI user-channel transport (replaces `struct bt_hci*`).
    hci: Option<Arc<HciTransport>>,
    /// Handle for the active TX timeout task (replaces `l_timeout`).
    tx_timeout: Option<JoinHandle<()>>,
    /// LE meta event listener task handle.
    event_task: Option<JoinHandle<()>>,
    /// Transmit packet queue (replaces `l_queue *tx_pkts`).
    tx_pkts: VecDeque<TxPkt>,
    /// Currently transmitting packet.
    tx: Option<TxPkt>,
    /// True if HCI advertising is currently enabled.
    sending: bool,
    /// True if active scanning is required (non-mesh AD types registered).
    active: bool,
    /// Snapshot of registered RX filters + callbacks — kept in sync with
    /// `MeshIoState::rx_regs` by the `register_recv`/`deregister_recv`
    /// trait methods.  The event handler task reads this to dispatch
    /// received LE advertising reports to the correct callback.
    /// Each entry is `(filter_bytes, callback_arc)`.
    rx_snapshot: Vec<(Vec<u8>, MeshIoRecvFn)>,
}

impl GenericIoPrivate {
    fn new() -> Self {
        Self {
            hci: None,
            tx_timeout: None,
            event_task: None,
            tx_pkts: VecDeque::new(),
            tx: None,
            sending: false,
            active: false,
            rx_snapshot: Vec::new(),
        }
    }
}

// ===========================================================================
// Timestamp Helpers
// ===========================================================================

/// Obtain a millisecond-precision timestamp truncated to u32.
///
/// Wraps every ~49 days — identical to the C `gettimeofday`-based
/// `get_instant()` (mesh-io-generic.c lines 64-74).
fn get_instant() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u32
}

/// Calculate the number of milliseconds remaining until `target`.
///
/// Replaces C `instant_remaining_ms()` (mesh-io-generic.c lines 76-80).
/// Uses wrapping arithmetic to handle clock wrap.
fn instant_remaining_ms(target: u32) -> u32 {
    target.wrapping_sub(get_instant())
}

// ===========================================================================
// RX Processing
// ===========================================================================

/// Iterate registered RX filters and invoke callbacks for matching data.
///
/// Replaces C `process_rx_callbacks()` (mesh-io-generic.c lines 82-89).
/// Operates on the `(filter, callback)` snapshot stored in `GenericIoPrivate`.
fn process_rx_callbacks(
    rx_snapshot: &[(Vec<u8>, MeshIoRecvFn)],
    info: &MeshIoRecvInfo,
    data: &[u8],
) {
    for (filter, cb) in rx_snapshot {
        if filter.is_empty() || data.starts_with(filter) {
            cb(info, data);
        }
    }
}

/// Construct a `MeshIoRecvInfo` and dispatch through registered callbacks.
///
/// Replaces C `process_rx()` (mesh-io-generic.c lines 91-106).
fn process_rx(
    rx_snapshot: &[(Vec<u8>, MeshIoRecvFn)],
    rssi: i8,
    instant: u32,
    addr: &[u8; 6],
    data: &[u8],
    _len: u8,
) {
    let info = MeshIoRecvInfo { addr: *addr, instant, chan: 7, rssi };

    process_rx_callbacks(rx_snapshot, &info, data);
}

// ===========================================================================
// Active Scan Detection
// ===========================================================================

/// Return `true` if the given RX registration requires active scanning.
///
/// Mesh-specific AD types (BT_AD_MESH_PROV .. BT_AD_MESH_BEACON) do *not*
/// require active scanning; all others do.
///
/// Replaces C `find_active()` (mesh-io-generic.c lines 349-361).
fn reg_requires_active(reg: &MeshIoReg) -> bool {
    if reg.filter.is_empty() {
        return false;
    }
    let ad_type = reg.filter[0];
    // Mesh-specific AD types (PROV=0x29, DATA=0x2A, BEACON=0x2B) use
    // passive scanning; all others require active scanning.
    !(ad_type == BT_AD_MESH_PROV || ad_type == BT_AD_MESH_DATA || ad_type == BT_AD_MESH_BEACON)
}

/// Check whether any registered filter requires active scanning.
fn any_active(rx_regs: &[MeshIoReg]) -> bool {
    rx_regs.iter().any(reg_requires_active)
}

// ===========================================================================
// Static Random Address Generation
// ===========================================================================

/// Generate a 6-byte static random BLE address.
///
/// Fills 6 random bytes and sets bits [7:6] of byte[5] to 0b11 per the
/// Bluetooth specification for static random address type.
fn generate_static_random_addr() -> [u8; 6] {
    let mut addr = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut addr);
    addr[5] |= 0xc0;
    addr
}

// ===========================================================================
// HCI Command Helpers (async)
// ===========================================================================

/// Send HCI RESET command.
async fn hci_cmd_reset(hci: &HciTransport) -> Result<HciResponse, HciError> {
    hci.send_command(opcode(OGF_HOST_CTL, OCF_RESET), &[]).await
}

/// Send HCI READ_LOCAL_COMMANDS command.
async fn hci_cmd_read_local_commands(hci: &HciTransport) -> Result<HciResponse, HciError> {
    hci.send_command(opcode(OGF_INFO_PARAM, OCF_READ_LOCAL_COMMANDS), &[]).await
}

/// Send HCI READ_LOCAL_FEATURES command.
async fn hci_cmd_read_local_features(hci: &HciTransport) -> Result<HciResponse, HciError> {
    hci.send_command(opcode(OGF_INFO_PARAM, OCF_READ_LOCAL_FEATURES), &[]).await
}

/// Send HCI SET_EVENT_MASK command with the mesh-required mask.
///
/// Mask: 0x2000800002008890
async fn hci_cmd_set_event_mask(hci: &HciTransport) -> Result<HciResponse, HciError> {
    let cmd = set_event_mask_cp { mask: [0x90, 0x88, 0x00, 0x02, 0x00, 0x80, 0x00, 0x20] };
    hci.send_command(opcode(OGF_HOST_CTL, OCF_SET_EVENT_MASK), cmd.as_bytes()).await
}

/// Send HCI LE_SET_EVENT_MASK command with the mesh-required mask.
///
/// Mask: 0x000000000000087f
async fn hci_cmd_set_le_event_mask(hci: &HciTransport) -> Result<HciResponse, HciError> {
    let cmd = set_event_mask_cp { mask: [0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] };
    hci.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_EVENT_MASK), cmd.as_bytes()).await
}

/// Send HCI LE_SET_RANDOM_ADDRESS command with the given address.
async fn hci_cmd_set_random_address(
    hci: &HciTransport,
    addr: &[u8; 6],
) -> Result<HciResponse, HciError> {
    let cmd =
        le_set_random_address_cp { bdaddr: bluez_shared::sys::bluetooth::bdaddr_t { b: *addr } };
    hci.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_RANDOM_ADDRESS), cmd.as_bytes()).await
}

/// Send HCI LE_SET_SCAN_PARAMETERS command.
async fn hci_cmd_set_scan_parameters(
    hci: &HciTransport,
    scan_type: u8,
    interval: u16,
    window: u16,
    own_addr_type: u8,
    filter_policy: u8,
) -> Result<HciResponse, HciError> {
    let cmd = le_set_scan_parameters_cp {
        type_: scan_type,
        interval: interval.to_le(),
        window: window.to_le(),
        own_bdaddr_type: own_addr_type,
        filter: filter_policy,
    };
    hci.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS), cmd.as_bytes()).await
}

/// Send HCI LE_SET_SCAN_ENABLE command.
async fn hci_cmd_set_scan_enable(
    hci: &HciTransport,
    enable: bool,
    filter_dup: bool,
) -> Result<HciResponse, HciError> {
    let cmd = le_set_scan_enable_cp { enable: u8::from(enable), filter_dup: u8::from(filter_dup) };
    hci.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE), cmd.as_bytes()).await
}

/// Send HCI LE_SET_ADVERTISING_PARAMETERS command.
async fn hci_cmd_set_adv_parameters(
    hci: &HciTransport,
    interval_ms: u16,
) -> Result<HciResponse, HciError> {
    let hci_interval = ((interval_ms as u32) * 16 / 10) as u16;
    let cmd = le_set_advertising_parameters_cp {
        min_interval: hci_interval.to_le(),
        max_interval: hci_interval.to_le(),
        advtype: 0x03,         // ADV_NONCONN_IND
        own_bdaddr_type: 0x01, // ADDR_TYPE_RANDOM
        direct_bdaddr_type: 0x00,
        direct_bdaddr: bluez_shared::sys::bluetooth::bdaddr_t::default(),
        chan_map: 0x07, // All three advertising channels
        filter: 0x03,
    };
    hci.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS), cmd.as_bytes()).await
}

/// Send HCI LE_SET_ADVERTISING_DATA command.
async fn hci_cmd_set_adv_data(
    hci: &HciTransport,
    pkt: &[u8],
    pkt_len: u8,
) -> Result<HciResponse, HciError> {
    let mut cmd = le_set_advertising_data_cp { length: pkt_len + 1, data: [0u8; 31] };
    cmd.data[0] = pkt_len;
    let copy_len = (pkt_len as usize).min(30);
    cmd.data[1..1 + copy_len].copy_from_slice(&pkt[..copy_len]);
    hci.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA), cmd.as_bytes()).await
}

/// Send HCI LE_SET_ADV_ENABLE command.
async fn hci_cmd_set_adv_enable(hci: &HciTransport, enable: bool) -> Result<HciResponse, HciError> {
    let cmd = le_set_advertise_enable_cp { enable: u8::from(enable) };
    hci.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE), cmd.as_bytes()).await
}

// ===========================================================================
// HCI Configuration Sequence
// ===========================================================================

/// Configure the HCI controller for mesh operation.
///
/// Sends the full command sequence: RESET → READ_LOCAL_COMMANDS →
/// READ_LOCAL_FEATURES → SET_EVENT_MASK → SET_LE_EVENT_MASK →
/// SET_RANDOM_ADDRESS → SET_SCAN_PARAMETERS.
///
/// Replaces C `configure_hci()` (mesh-io-generic.c lines 191-281).
async fn configure_hci(hci: &HciTransport) {
    // HCI Reset
    if let Err(e) = hci_cmd_reset(hci).await {
        error!("HCI RESET failed: {}", e);
    }

    // Read local supported commands
    match hci_cmd_read_local_commands(hci).await {
        Ok(rsp) => {
            if !rsp.data.is_empty() && rsp.data[0] != 0 {
                error!("Failed to read local commands");
            }
        }
        Err(e) => error!("READ_LOCAL_COMMANDS failed: {}", e),
    }

    // Read local supported features
    match hci_cmd_read_local_features(hci).await {
        Ok(rsp) => {
            if !rsp.data.is_empty() && rsp.data[0] != 0 {
                error!("Failed to read local features");
            }
        }
        Err(e) => error!("READ_LOCAL_FEATURES failed: {}", e),
    }

    // Set event mask
    if let Err(e) = hci_cmd_set_event_mask(hci).await {
        error!("SET_EVENT_MASK failed: {}", e);
    }

    // Set LE event mask
    if let Err(e) = hci_cmd_set_le_event_mask(hci).await {
        error!("SET_LE_EVENT_MASK failed: {}", e);
    }

    // Set LE random address
    let addr = generate_static_random_addr();
    if let Err(e) = hci_cmd_set_random_address(hci, &addr).await {
        error!("SET_RANDOM_ADDRESS failed: {}", e);
    }

    // Set LE scan parameters — passive scanning, interval/window 0x0030
    if let Err(e) = hci_cmd_set_scan_parameters(hci, 0x00, 0x0030, 0x0030, 0x00, 0x00).await {
        error!("SET_SCAN_PARAMETERS failed: {}", e);
    }
}

// ===========================================================================
// LE Advertising Report Parser
// ===========================================================================

/// Parse an HCI LE Advertising Report event and dispatch to RX callbacks.
///
/// Replaces C `event_adv_report()` (mesh-io-generic.c lines 108-147).
/// Processes each report in the event, extracting AD fields and filtering
/// for mesh-relevant AD types before delivering to registered callbacks.
fn event_adv_report(rx_snapshot: &[(Vec<u8>, MeshIoRecvFn)], buf: &[u8]) {
    // The C code treats buf as pointing to the data after the sub-event code.
    // Minimum size: evt_type(1) + addr_type(1) + addr(6) + data_len(1) = 9
    if buf.len() < 9 {
        return;
    }

    let evt_type = buf[0];
    // Only process ADV_NONCONN_IND (0x03)
    if evt_type != ADV_NONCONN_IND {
        return;
    }

    let instant = get_instant();

    let addr_type = buf[1];
    let _ = addr_type; // Not currently used beyond parsing
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&buf[2..8]);
    let adv_len = buf[8] as usize;

    // Data starts at offset 9
    if buf.len() < 9 + adv_len {
        return;
    }
    let adv = &buf[9..9 + adv_len];

    // RSSI is the byte immediately after the advertising data
    let rssi = if buf.len() > 9 + adv_len { buf[9 + adv_len] as i8 } else { 0i8 };

    // Parse AD structures
    let mut offset: usize = 0;
    while offset < adv_len.saturating_sub(1) {
        let field_len = adv[offset] as usize;
        if field_len == 0 {
            break;
        }
        let next = offset + field_len + 1;
        if next > adv_len {
            break;
        }
        // Data for this AD field starts at offset+1, length is field_len
        let ad_data = &adv[offset + 1..next];
        process_rx(rx_snapshot, rssi, instant, &addr, ad_data, field_len as u8);
        offset = next;
    }
}

// ===========================================================================
// LE Meta Event Dispatcher
// ===========================================================================

/// Dispatch LE Meta Events to the appropriate handler.
///
/// Replaces C `event_callback()` (mesh-io-generic.c lines 149-162).
fn handle_le_meta_event(rx_snapshot: &[(Vec<u8>, MeshIoRecvFn)], data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let sub_event = data[0];
    match sub_event {
        EVT_LE_ADVERTISING_REPORT => {
            // data[1] = num_reports, followed by report data.
            // For simplicity we pass everything after sub-event code.
            if data.len() > 2 {
                // Skip sub_event(1) + num_reports(1), pass report body
                event_adv_report(rx_snapshot, &data[2..]);
            }
        }
        EVT_LE_EXT_ADV_REPORT => {
            if data.len() > 2 {
                event_adv_report(rx_snapshot, &data[2..]);
            }
        }
        other => {
            debug!("Other LE Meta sub-event: 0x{:02x}", other);
        }
    }
}

// ===========================================================================
// Scan Control
// ===========================================================================

/// Re-configure scan parameters and re-enable scanning.
///
/// Called after disabling scan to apply updated active/passive mode and
/// scan intervals.  Replaces C `scan_disable_rsp()` chain
/// (mesh-io-generic.c lines 304-323).
async fn reconfigure_and_enable_scan(hci: &HciTransport, active: bool) {
    let scan_type = if active { 0x01 } else { 0x00 };
    // Active scan uses interval/window 0x0010; passive uses 0x0010 as well
    // (from scan_disable_rsp — C line 315-316).
    if let Err(e) = hci_cmd_set_scan_parameters(hci, scan_type, 0x0010, 0x0010, 0x01, 0x00).await {
        error!("SET_SCAN_PARAMETERS (reconfigure) failed: {}", e);
    }

    // Enable scanning with duplicate reporting
    if let Err(e) = hci_cmd_set_scan_enable(hci, true, false).await {
        error!("LE Scan enable failed: {}", e);
    }
}

// ===========================================================================
// TX Engine — Advertising Pipeline
// ===========================================================================

/// Rotate the random address after completing a burst of advertisements.
///
/// Replaces C `send_cancel_done()` (mesh-io-generic.c lines 457-473).
async fn send_cancel_done(hci: &HciTransport, sending: &mut bool) {
    *sending = false;

    // Rotate random address
    let addr = generate_static_random_addr();
    let _ = hci_cmd_set_random_address(hci, &addr).await;
}

/// Cancel current advertising: disable if active, then rotate address.
///
/// Replaces C `send_cancel()` (mesh-io-generic.c lines 475-491).
async fn send_cancel_async(hci: &HciTransport, sending: &mut bool) {
    if !*sending {
        send_cancel_done(hci, sending).await;
        return;
    }

    // Disable advertising
    let _ = hci_cmd_set_adv_enable(hci, false).await;
    send_cancel_done(hci, sending).await;
}

/// Execute the 4-stage advertising pipeline for one packet:
/// params → data → enable.  If already sending, first disable.
///
/// Replaces C `send_pkt()` chain (mesh-io-generic.c lines 565-588)
/// and the chained callbacks `set_send_adv_params` → `set_send_adv_data`
/// → `set_send_adv_enable`.
async fn send_pkt_async(hci: &HciTransport, tx: &TxPkt, interval: u16, sending: &mut bool) {
    // If currently advertising, disable first
    if *sending {
        let _ = hci_cmd_set_adv_enable(hci, false).await;
    }

    // Stage 1: Set advertising parameters
    if let Err(e) = hci_cmd_set_adv_parameters(hci, interval).await {
        warn!("SET_ADV_PARAMETERS failed: {}", e);
    }

    // Stage 2: Set advertising data
    if tx.len as usize >= 31 {
        // Data too large for standard advertising
        warn!("TX packet length {} exceeds advertising data limit", tx.len);
    } else {
        if let Err(e) = hci_cmd_set_adv_data(hci, &tx.pkt, tx.len).await {
            warn!("SET_ADV_DATA failed: {}", e);
        }
    }

    // Stage 3: Enable advertising
    *sending = true;
    if let Err(e) = hci_cmd_set_adv_enable(hci, true).await {
        error!("SET_ADV_ENABLE failed: {}", e);
        *sending = false;
    }
}

/// TX timeout handler — pop head of queue, send packet, reschedule.
///
/// Replaces C `tx_to()` (mesh-io-generic.c lines 590-638).
///
/// Returns `Pin<Box<dyn Future + Send>>` so the compiler can verify
/// `Send` for the recursive (self-scheduling) call chain used by
/// `tokio::spawn`.
fn tx_to(pvt: Arc<TokioMutex<GenericIoPrivate>>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let mut guard = pvt.lock().await;

        let tx = match guard.tx_pkts.pop_front() {
            Some(t) => t,
            None => {
                // Queue empty — cancel sending and remove timeout
                guard.tx_timeout = None;
                if let Some(hci) = guard.hci.clone() {
                    send_cancel_async(&hci, &mut guard.sending).await;
                }
                return;
            }
        };

        let (ms, count) = match &tx.info {
            MeshIoSendInfo::General { interval, cnt, .. } => (*interval, *cnt),
            _ => (25, 1),
        };

        let mut tx = tx;
        tx.delete = count == 1;

        let interval = ms;
        let hci = guard.hci.clone();

        if let Some(ref hci) = hci {
            send_pkt_async(hci, &tx, interval, &mut guard.sending).await;
        }

        if count == 1 {
            // Recalculate wakeup if responding to POLL
            if let Some(front) = guard.tx_pkts.front() {
                if let MeshIoSendInfo::PollRsp { instant, delay } = front.info {
                    let remaining = instant_remaining_ms(instant + delay as u32);
                    let pvt_clone = Arc::clone(&pvt);
                    guard.tx_timeout = Some(tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(remaining as u64)).await;
                        tx_to(pvt_clone).await;
                    }));
                    return;
                }
            }
            // If tx.delete was set and not re-queued, the packet is consumed
        } else {
            // Decrement count and re-queue
            if let MeshIoSendInfo::General { cnt, .. } = &mut tx.info {
                if *cnt != MESH_IO_TX_COUNT_UNLIMITED {
                    *cnt -= 1;
                }
            }
            guard.tx_pkts.push_back(tx);
        }

        // Reschedule timeout
        let pvt_clone = Arc::clone(&pvt);
        let sleep_ms = ms as u64;
        guard.tx_timeout = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            tx_to(pvt_clone).await;
        }));
    })
}

/// TX worker — compute initial delay and schedule first tx_to.
///
/// Replaces C `tx_worker()` (mesh-io-generic.c lines 640-691).
///
/// Takes `Arc` by value so the returned future is `Send + 'static`.
async fn tx_worker(pvt: Arc<TokioMutex<GenericIoPrivate>>) {
    let delay: u32;
    {
        let guard = pvt.lock().await;
        let tx = match guard.tx_pkts.front() {
            Some(t) => t,
            None => return,
        };

        delay = match &tx.info {
            MeshIoSendInfo::General { min_delay, max_delay, .. } => {
                if *min_delay == *max_delay {
                    *min_delay as u32
                } else {
                    let mut rng = rand::thread_rng();
                    let range = (*max_delay as u32).saturating_sub(*min_delay as u32);
                    if range == 0 {
                        *min_delay as u32
                    } else {
                        let mut val = [0u8; 4];
                        rng.fill_bytes(&mut val);
                        (u32::from_le_bytes(val) % range) + *min_delay as u32
                    }
                }
            }
            MeshIoSendInfo::Poll { min_delay, max_delay, .. } => {
                if *min_delay == *max_delay {
                    *min_delay as u32
                } else {
                    let mut rng = rand::thread_rng();
                    let range = (*max_delay as u32).saturating_sub(*min_delay as u32);
                    if range == 0 {
                        *min_delay as u32
                    } else {
                        let mut val = [0u8; 4];
                        rng.fill_bytes(&mut val);
                        (u32::from_le_bytes(val) % range) + *min_delay as u32
                    }
                }
            }
            MeshIoSendInfo::PollRsp { instant, delay } => {
                let remaining = instant_remaining_ms(*instant + *delay as u32);
                if remaining > 255 { 0 } else { remaining }
            }
        };
    }

    if delay == 0 {
        tx_to(Arc::clone(&pvt)).await;
    } else {
        // Schedule after delay
        let pvt_clone = Arc::clone(&pvt);
        let mut guard = pvt.lock().await;
        if let Some(handle) = guard.tx_timeout.take() {
            handle.abort();
        }
        guard.tx_timeout = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
            tx_to(pvt_clone).await;
        }));
    }
}

// ===========================================================================
// GenericBackend
// ===========================================================================

/// Generic HCI I/O backend using raw HCI user-channel sockets.
///
/// Communicates directly with the Bluetooth controller for mesh LE
/// advertising and scanning.  Replaces the C `mesh_io_generic` vtable
/// and `struct mesh_io_private`.
#[derive(Default)]
pub struct GenericBackend {
    /// Arc-protected private state shared with async tasks.
    pvt: Option<Arc<TokioMutex<GenericIoPrivate>>>,
}

impl GenericBackend {
    /// Create a new (uninitialised) generic backend instance.
    pub fn new() -> Self {
        Self::default()
    }
}

impl MeshIoBackend for GenericBackend {
    /// Initialize the backend: allocate private state, schedule HCI init.
    ///
    /// Replaces C `dev_init()` (mesh-io-generic.c lines 410-424).
    fn init(&mut self, io: &mut MeshIoState, opts: &MeshIoOpts) -> bool {
        if self.pvt.is_some() {
            return false;
        }

        let pvt = Arc::new(TokioMutex::new(GenericIoPrivate::new()));
        self.pvt = Some(Arc::clone(&pvt));

        // Capture parameters for the init task
        let index = opts.index;

        // We need to move the ready callback out of io for use in the async task.
        // The broker passes it once; we consume it here.
        let ready_cb = io.ready.take();

        // Schedule hci_init as an idle oneshot (replaces l_idle_oneshot)
        tokio::spawn(async move {
            // Step 1: Clear MGMT state
            mesh_mgmt_clear().await;

            // Step 2: Open HCI user channel
            let hci_result = HciTransport::new_user_channel(index);
            let hci = match hci_result {
                Ok(h) => h,
                Err(e) => {
                    error!("Failed to start mesh io (hci {}): {}", index, e);
                    if let Some(cb) = ready_cb {
                        cb(false);
                    }
                    return;
                }
            };

            // Step 3: Configure HCI controller
            configure_hci(&hci).await;

            // Step 4: Register LE Meta Event handler.
            //   The event handler task reads `pvt.rx_snapshot` to
            //   dispatch received LE advertising reports.
            let (_sub_id, mut event_rx) = hci.subscribe(EVT_LE_META_EVENT).await;
            let pvt_for_events = Arc::clone(&pvt);
            let event_handle = tokio::spawn(async move {
                while let Some(evt) = event_rx.recv().await {
                    let guard = pvt_for_events.lock().await;
                    handle_le_meta_event(&guard.rx_snapshot, &evt.data);
                }
            });

            // Store HCI transport and event task in private state
            {
                let mut guard = pvt.lock().await;
                guard.hci = Some(hci.clone());
                guard.event_task = Some(event_handle);
            }

            info!("Started mesh on hci {}", index);

            // Step 5: Invoke ready callback
            if let Some(cb) = ready_cb {
                cb(true);
            }
        });

        true
    }

    /// Tear down the backend and release hardware resources.
    ///
    /// Replaces C `dev_destroy()` (mesh-io-generic.c lines 426-442).
    fn destroy(&mut self, _io: &mut MeshIoState) -> bool {
        if let Some(pvt) = self.pvt.take() {
            // Use try_lock to avoid async in a sync context; spawn cleanup
            let pvt_clone = pvt;
            tokio::spawn(async move {
                let mut guard = pvt_clone.lock().await;

                // Shutdown HCI transport
                if let Some(ref hci) = guard.hci {
                    hci.shutdown();
                }
                guard.hci = None;

                // Cancel TX timeout
                if let Some(handle) = guard.tx_timeout.take() {
                    handle.abort();
                }

                // Cancel event listener task
                if let Some(handle) = guard.event_task.take() {
                    handle.abort();
                }

                // Drain TX queue
                guard.tx_pkts.clear();
                guard.tx = None;
            });
        }
        true
    }

    /// Query backend capabilities.
    ///
    /// Replaces C `dev_caps()` (mesh-io-generic.c lines 444-455).
    /// Returns fixed capability constants — the generic HCI backend supports
    /// up to 255 concurrent filters with 50-unit window accuracy.  These
    /// values are independent of initialisation state, matching the C original
    /// which never gates on `pvt`.
    fn caps(&self, _io: &MeshIoState) -> Option<MeshIoCaps> {
        Some(MeshIoCaps { max_num_filters: 255, window_accuracy: 50 })
    }

    /// Transmit mesh advertising data with the specified timing.
    ///
    /// Replaces C `send_tx()` (mesh-io-generic.c lines 693-732).
    fn send(&mut self, _io: &mut MeshIoState, info: &MeshIoSendInfo, data: &[u8]) -> bool {
        if data.is_empty() || data.len() > MESH_AD_MAX_LEN {
            return false;
        }

        let pvt = match &self.pvt {
            Some(p) => Arc::clone(p),
            None => return false,
        };

        let mut tx = TxPkt::new();
        tx.info = info.clone();
        tx.len = data.len() as u8;
        tx.pkt[..data.len()].copy_from_slice(data);

        let pvt_for_task = Arc::clone(&pvt);
        let info_clone = info.clone();

        // Enqueue and potentially schedule — use spawn to avoid blocking
        tokio::spawn(async move {
            let mut guard = pvt_for_task.lock().await;

            match &info_clone {
                MeshIoSendInfo::PollRsp { .. } => {
                    guard.tx_pkts.push_front(tx);
                }
                MeshIoSendInfo::General { cnt, .. } => {
                    // Guard: if transmitter idle and cnt==1, bump to 2
                    let mut tx = tx;
                    if guard.tx.is_none() && guard.tx_pkts.is_empty() && *cnt == 1 {
                        if let MeshIoSendInfo::General { cnt: ref mut c, .. } = tx.info {
                            *c = 2;
                        }
                    }
                    guard.tx_pkts.push_back(tx);
                }
                _ => {
                    guard.tx_pkts.push_back(tx);
                }
            }

            // If not already sending, schedule tx_worker
            if guard.tx.is_none() {
                if let Some(handle) = guard.tx_timeout.take() {
                    handle.abort();
                }
                let pvt_worker = Arc::clone(&pvt_for_task);
                drop(guard);
                tokio::spawn(async move {
                    tx_worker(pvt_worker).await;
                });
            }
        });

        true
    }

    /// Register an RX filter and associated callback, managing scan state.
    ///
    /// Replaces C `recv_register()` (mesh-io-generic.c lines 778-802).
    fn register_recv(&mut self, io: &mut MeshIoState, filter: &[u8], cb: MeshIoRecvFn) -> bool {
        let pvt = match &self.pvt {
            Some(p) => Arc::clone(p),
            None => return false,
        };

        let already_scanning = !io.rx_regs.is_empty();
        let active = any_active(&io.rx_regs);

        // Clone filter and callback for snapshot update inside the async task
        let filter_vec = filter.to_vec();
        let cb_clone = Arc::clone(&cb);

        let pvt_for_scan = Arc::clone(&pvt);

        // Update snapshot and manage scan state asynchronously
        tokio::spawn(async move {
            let mut guard = pvt_for_scan.lock().await;

            // Add this registration to the RX snapshot
            guard.rx_snapshot.push((filter_vec, cb_clone));

            if let Some(ref hci) = guard.hci.clone() {
                if !already_scanning || guard.active != active {
                    guard.active = active;
                    // Disable scan, reconfigure, re-enable
                    if let Err(e) = hci_cmd_set_scan_enable(hci, false, false).await {
                        error!("LE Scan disable failed: {}", e);
                    }
                    reconfigure_and_enable_scan(hci, active).await;
                }
            }
        });

        true
    }

    /// Remove an RX filter from the backend, managing scan state.
    ///
    /// Replaces C `recv_deregister()` (mesh-io-generic.c lines 804-826).
    fn deregister_recv(&mut self, io: &mut MeshIoState, filter: &[u8]) -> bool {
        let pvt = match &self.pvt {
            Some(p) => Arc::clone(p),
            None => return false,
        };

        let is_empty = io.rx_regs.is_empty();
        let active = any_active(&io.rx_regs);
        let filter_vec = filter.to_vec();

        let pvt_for_scan = Arc::clone(&pvt);

        tokio::spawn(async move {
            let mut guard = pvt_for_scan.lock().await;

            // Remove matching entry from the RX snapshot
            guard.rx_snapshot.retain(|(f, _)| f != &filter_vec);

            if let Some(ref hci) = guard.hci.clone() {
                if is_empty {
                    // No more registrations — disable scanning
                    let _ = hci_cmd_set_scan_enable(hci, false, false).await;
                } else if active != guard.active {
                    guard.active = active;
                    // Mode changed — disable and restart
                    if let Err(e) = hci_cmd_set_scan_enable(hci, false, false).await {
                        error!("LE Scan disable failed: {}", e);
                    }
                    reconfigure_and_enable_scan(hci, active).await;
                }
            }
        });

        true
    }

    /// Cancel an in-progress or queued TX matching the given pattern.
    ///
    /// Replaces C `tx_cancel()` (mesh-io-generic.c lines 734-776).
    fn cancel(&mut self, _io: &mut MeshIoState, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let pvt = match &self.pvt {
            Some(p) => Arc::clone(p),
            None => return false,
        };

        let pattern = data.to_vec();

        tokio::spawn(async move {
            let mut guard = pvt.lock().await;

            if pattern.len() == 1 {
                // Remove by AD type
                let ad_type = pattern[0];
                guard.tx_pkts.retain(|tx| {
                    let matches = ad_type == 0 || (tx.len > 0 && tx.pkt[0] == ad_type);
                    if matches {
                        // Check if this was the current tx
                        // (simplified: we compare pkt contents)
                    }
                    !matches
                });
                // Also clear current tx if it matches
                if let Some(ref cur_tx) = guard.tx {
                    if ad_type == 0 || (cur_tx.len > 0 && cur_tx.pkt[0] == ad_type) {
                        guard.tx = None;
                    }
                }
            } else {
                // Remove by pattern match
                guard.tx_pkts.retain(|tx| {
                    if (tx.len as usize) < pattern.len() {
                        return true; // Keep — too short to match
                    }
                    let matches = tx.pkt[..pattern.len()] == pattern[..];
                    !matches
                });
                if let Some(ref cur_tx) = guard.tx {
                    if (cur_tx.len as usize) >= pattern.len()
                        && cur_tx.pkt[..pattern.len()] == pattern[..]
                    {
                        guard.tx = None;
                    }
                }
            }

            // If queue is now empty, cancel sending
            if guard.tx_pkts.is_empty() {
                if let Some(ref hci) = guard.hci.clone() {
                    send_cancel_async(hci, &mut guard.sending).await;
                }
                if let Some(handle) = guard.tx_timeout.take() {
                    handle.abort();
                }
            }
        });

        true
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Helper to create a default MeshIoState for testing.
    fn make_state() -> MeshIoState {
        MeshIoState {
            index: 0xFFFF_u16 as i32,
            favored_index: 0xFFFF_u16 as i32,
            ready: None,
            rx_regs: Vec::new(),
            user_data: (),
        }
    }

    #[test]
    fn test_generic_backend_new() {
        let backend = GenericBackend::new();
        let state = make_state();
        // caps() always returns fixed constants
        assert!(backend.caps(&state).is_some());
    }

    #[test]
    fn test_generic_backend_default() {
        let backend = GenericBackend::default();
        let state = make_state();
        assert!(backend.caps(&state).is_some());
    }

    #[test]
    fn test_send_before_init_returns_false() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        let info = MeshIoSendInfo::General { interval: 100, cnt: 1, min_delay: 0, max_delay: 0 };
        let data = [0x29u8, 0x01, 0x02];
        assert!(!backend.send(&mut state, &info, &data));
    }

    #[test]
    fn test_cancel_before_init_returns_false() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        assert!(!backend.cancel(&mut state, &[0x29]));
    }

    #[test]
    fn test_register_recv_before_init_returns_false() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        let cb: MeshIoRecvFn = Arc::new(|_info, _data| {});
        assert!(!backend.register_recv(&mut state, &[0x29], cb));
    }

    #[test]
    fn test_deregister_recv_before_init_returns_false() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        assert!(!backend.deregister_recv(&mut state, &[0x29]));
    }

    #[test]
    fn test_destroy_before_init_is_safe() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        assert!(backend.destroy(&mut state));
    }

    #[test]
    fn test_send_empty_data_rejected() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        let info = MeshIoSendInfo::General { interval: 100, cnt: 1, min_delay: 0, max_delay: 0 };
        assert!(!backend.send(&mut state, &info, &[]));
    }

    #[test]
    fn test_send_oversized_data_rejected() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        let info = MeshIoSendInfo::General { interval: 100, cnt: 1, min_delay: 0, max_delay: 0 };
        let data = [0u8; 32]; // exceeds MESH_AD_MAX_LEN
        assert!(!backend.send(&mut state, &info, &data));
    }

    #[test]
    fn test_cancel_empty_pattern_rejected() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        assert!(!backend.cancel(&mut state, &[]));
    }

    #[test]
    fn test_double_destroy_is_safe() {
        let mut backend = GenericBackend::new();
        let mut state = make_state();
        assert!(backend.destroy(&mut state));
        assert!(backend.destroy(&mut state));
    }

    #[test]
    fn test_get_instant_returns_nonzero() {
        let ts = get_instant();
        assert!(ts > 0);
    }

    #[test]
    fn test_instant_remaining_ms_wrapping() {
        let now = get_instant();
        // Target in the past wraps to a large value
        let past = now.wrapping_sub(100);
        let remaining = instant_remaining_ms(past);
        // remaining should be a large u32 (wrapping)
        assert!(remaining > 0);
    }

    #[test]
    fn test_generate_static_random_addr() {
        let addr = generate_static_random_addr();
        // Bits [7:6] of byte[5] must be 0b11
        assert_eq!(addr[5] & 0xC0, 0xC0);
    }

    #[test]
    fn test_reg_requires_active_mesh_prov() {
        let reg =
            MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 1, filter: vec![BT_AD_MESH_PROV] };
        // Mesh PROV AD type should NOT require active scanning
        assert!(!reg_requires_active(&reg));
    }

    #[test]
    fn test_reg_requires_active_mesh_data() {
        let reg =
            MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 1, filter: vec![BT_AD_MESH_DATA] };
        assert!(!reg_requires_active(&reg));
    }

    #[test]
    fn test_reg_requires_active_mesh_beacon() {
        let reg =
            MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 1, filter: vec![BT_AD_MESH_BEACON] };
        assert!(!reg_requires_active(&reg));
    }

    #[test]
    fn test_reg_requires_active_non_mesh() {
        let reg = MeshIoReg {
            cb: Arc::new(|_info, _data| {}),
            len: 1,
            filter: vec![0x01], // Not a mesh AD type
        };
        assert!(reg_requires_active(&reg));
    }

    #[test]
    fn test_reg_requires_active_empty_filter() {
        let reg = MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 0, filter: vec![] };
        assert!(!reg_requires_active(&reg));
    }

    #[test]
    fn test_any_active_mixed() {
        let regs = vec![
            MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 1, filter: vec![BT_AD_MESH_PROV] },
            MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 1, filter: vec![0x01] },
        ];
        assert!(any_active(&regs));
    }

    #[test]
    fn test_any_active_all_mesh() {
        let regs = vec![
            MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 1, filter: vec![BT_AD_MESH_PROV] },
            MeshIoReg { cb: Arc::new(|_info, _data| {}), len: 1, filter: vec![BT_AD_MESH_BEACON] },
        ];
        assert!(!any_active(&regs));
    }

    #[test]
    fn test_process_rx_callbacks_matching() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let snapshot: Vec<(Vec<u8>, MeshIoRecvFn)> = vec![(
            vec![0x29],
            Arc::new(move |_info, _data| {
                called_clone.store(true, Ordering::SeqCst);
            }),
        )];

        let info = MeshIoRecvInfo { addr: [0u8; 6], instant: 0, chan: 7, rssi: -50 };

        // Data starts with filter byte
        process_rx_callbacks(&snapshot, &info, &[0x29, 0x01, 0x02]);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_process_rx_callbacks_no_match() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let snapshot: Vec<(Vec<u8>, MeshIoRecvFn)> = vec![(
            vec![0x29],
            Arc::new(move |_info, _data| {
                called_clone.store(true, Ordering::SeqCst);
            }),
        )];

        let info = MeshIoRecvInfo { addr: [0u8; 6], instant: 0, chan: 7, rssi: -50 };

        // Data does NOT start with filter
        process_rx_callbacks(&snapshot, &info, &[0x2A, 0x01, 0x02]);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_tx_pkt_new() {
        let pkt = TxPkt::new();
        assert_eq!(pkt.len, 0);
        assert!(!pkt.delete);
        assert_eq!(pkt.pkt, [0u8; MESH_AD_MAX_LEN]);
    }

    #[test]
    fn test_caps_returns_expected_values() {
        // caps() should always return fixed constants, even before init()
        let backend = GenericBackend::new();
        let state = make_state();
        let caps = backend.caps(&state).unwrap();
        assert_eq!(caps.max_num_filters, 255);
        assert_eq!(caps.window_accuracy, 50);
    }

    #[test]
    fn test_caps_same_after_pvt_set() {
        // Caps remain identical once pvt is allocated
        let mut backend = GenericBackend::new();
        let state = make_state();
        backend.pvt = Some(Arc::new(TokioMutex::new(GenericIoPrivate::new())));
        let caps = backend.caps(&state).unwrap();
        assert_eq!(caps.max_num_filters, 255);
        assert_eq!(caps.window_accuracy, 50);
    }

    #[test]
    fn test_process_rx_callbacks_multi_filter_prefix() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        // Filter with multiple bytes must all match
        let snapshot: Vec<(Vec<u8>, MeshIoRecvFn)> = vec![(
            vec![0x29, 0xAA],
            Arc::new(move |_info, _data| {
                called_clone.store(true, Ordering::SeqCst);
            }),
        )];

        let info = MeshIoRecvInfo { addr: [0u8; 6], instant: 0, chan: 7, rssi: -50 };

        // Data starts with matching prefix
        process_rx_callbacks(&snapshot, &info, &[0x29, 0xAA, 0x55]);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_process_rx_callbacks_partial_prefix_no_match() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let snapshot: Vec<(Vec<u8>, MeshIoRecvFn)> = vec![(
            vec![0x29, 0xAA],
            Arc::new(move |_info, _data| {
                called_clone.store(true, Ordering::SeqCst);
            }),
        )];

        let info = MeshIoRecvInfo { addr: [0u8; 6], instant: 0, chan: 7, rssi: -50 };

        // Data matches first byte but not second
        process_rx_callbacks(&snapshot, &info, &[0x29, 0xBB, 0x55]);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_process_rx_callbacks_data_shorter_than_filter() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let snapshot: Vec<(Vec<u8>, MeshIoRecvFn)> = vec![(
            vec![0x29, 0xAA, 0x55],
            Arc::new(move |_info, _data| {
                called_clone.store(true, Ordering::SeqCst);
            }),
        )];

        let info = MeshIoRecvInfo { addr: [0u8; 6], instant: 0, chan: 7, rssi: -50 };

        // Data is shorter than filter
        process_rx_callbacks(&snapshot, &info, &[0x29, 0xAA]);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_generate_static_random_addr_different_each_time() {
        let addr1 = generate_static_random_addr();
        let addr2 = generate_static_random_addr();
        // Very high probability these are different
        // (2^48 collision chance is negligible)
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_any_active_empty() {
        let regs: Vec<MeshIoReg> = vec![];
        assert!(!any_active(&regs));
    }

    #[test]
    fn test_instant_remaining_future() {
        let now = get_instant();
        let future = now.wrapping_add(100);
        let remaining = instant_remaining_ms(future);
        // Should be close to 100ms
        assert!(remaining <= 100);
    }
}
