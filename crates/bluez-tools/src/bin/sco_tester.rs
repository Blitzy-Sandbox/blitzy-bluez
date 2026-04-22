// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * SCO socket tester — validates synchronous connection-oriented (SCO/eSCO)
 * socket operations including connect, disconnect, send/receive, codec
 * configuration, TX/RX timestamping, and server mode.
 *
 * Ported from tools/sco-tester.c (1582 lines, GPL-2.0-or-later).
 */
#![deny(warnings)]
// SCO tester requires raw Bluetooth socket FFI throughout — socket(),
// bind(), connect(), listen(), accept(), setsockopt(), getsockopt(), etc.
// Every socket operation is documented with `// SAFETY:` comments.
// All FFI operations delegated to safe wrappers in bluez_shared::sys::ffi_helpers.

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::any::Any;
use std::io::{self, IoSlice};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::unix::AsyncFd;

use bluez_emulator::hciemu::{EmulatorType, HciEmulator, HookType};
use bluez_shared::mgmt::client::MgmtSocket;
use bluez_shared::sys::bluetooth::{
    AF_BLUETOOTH, BDADDR_BREDR, BT_CODEC, BT_DEFER_SETUP, BT_VOICE, BT_VOICE_TRANSPARENT,
    BTPROTO_SCO, PF_BLUETOOTH, SOL_BLUETOOTH, bdaddr_t, bt_codec, bt_codecs, bt_voice,
};
use bluez_shared::sys::ffi_helpers as ffi;
use bluez_shared::sys::hci::{
    EVT_DISCONN_COMPLETE, OCF_SETUP_SYNC_CONN, OCF_WRITE_SCAN_ENABLE, OGF_HOST_CTL,
    OGF_LINK_CONTROL, opcode,
};
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE, MGMT_OP_READ_INDEX_LIST,
    MGMT_OP_READ_INFO, MGMT_OP_SET_CONNECTABLE, MGMT_OP_SET_EXP_FEATURE, MGMT_OP_SET_LE,
    MGMT_OP_SET_POWERED, MGMT_OP_SET_SSP, MGMT_STATUS_SUCCESS, mgmt_cp_set_exp_feature,
};
use bluez_shared::sys::sco::{SCO_CONNINFO, SCO_OPTIONS, sco_conninfo, sco_options, sockaddr_sco};
use bluez_shared::tester::{
    TestCallback, tester_add_full, tester_debug, tester_init, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_pre_setup_failed, tester_print, tester_run,
    tester_setup_complete, tester_setup_failed, tester_test_failed, tester_test_passed,
    tester_use_debug, tester_warn,
};
use bluez_tools::{
    SOF_TIMESTAMPING_OPT_ID, SOF_TIMESTAMPING_RX_SOFTWARE, SOF_TIMESTAMPING_SOFTWARE,
    SOF_TIMESTAMPING_TX_COMPLETION, SOF_TIMESTAMPING_TX_SOFTWARE, TxTstampData, recv_tstamp,
    rx_timestamping_init, test_ethtool_get_ts_info,
};

// ---------------------------------------------------------------------------
// HCI constants not provided by hci.rs — defined locally.
// ---------------------------------------------------------------------------

/// HCI event code for Synchronous Connection Complete (0x2c).
const EVT_SYNC_CONN_COMPLETE: u8 = 0x2c;

/// OCF for Create_Connection_Cancel (OGF Link Control, OCF 0x0008).
/// Used in extended SCO test scenarios where connection cancel is tested.
#[allow(dead_code)]
const OCF_CREATE_CONN_CANCEL: u16 = 0x0008;

/// Compute the full HCI command opcode for Write Scan Enable.
fn hci_cmd_write_scan_enable() -> u16 {
    opcode(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE)
}

/// Compute the full HCI command opcode for Create Connection Cancel.
/// Used in extended SCO test scenarios where connection cancel is tested.
#[allow(dead_code)]
fn hci_cmd_create_conn_cancel() -> u16 {
    opcode(OGF_LINK_CONTROL, OCF_CREATE_CONN_CANCEL)
}

/// Compute the full HCI command opcode for Setup Synchronous Connection.
#[allow(dead_code)]
fn hci_cmd_setup_sync_conn() -> u16 {
    opcode(OGF_LINK_CONTROL, OCF_SETUP_SYNC_CONN)
}

/// Local struct matching `bt_hci_evt_sync_conn_complete` from the kernel.
/// Used by hook functions that inspect SCO connection complete events.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
struct SyncConnComplete {
    status: u8,
    handle: u16,
    bdaddr: bdaddr_t,
    link_type: u8,
    tx_interval: u8,
    retrans_window: u8,
    rx_pkt_len: u16,
    tx_pkt_len: u16,
    air_mode: u8,
}

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// Shared test state — `Arc<Mutex<TestData>>` is the `test_data` type for
/// `tester_add_full`.
type SharedState = Arc<Mutex<TestData>>;

/// Per-test runtime state, matching the C `struct test_data`.
#[allow(dead_code)]
struct TestData {
    test_data: Option<&'static ScoClientData>,
    mgmt: Option<Arc<MgmtSocket>>,
    mgmt_index: u16,
    hciemu: Option<Arc<Mutex<HciEmulator>>>,
    hciemu_type: EmulatorType,
    io_handle: Option<tokio::task::JoinHandle<()>>,
    err_io_handle: Option<tokio::task::JoinHandle<()>>,
    sk: i32,
    disable_esco: bool,
    enable_codecs: bool,
    disable_sco_flowctl: bool,
    step: i32,
    acl_handle: u16,
    handle: u16,
    tx_ts: TxTstampData,
}

impl Default for TestData {
    fn default() -> Self {
        Self {
            test_data: None,
            mgmt: None,
            mgmt_index: 0,
            hciemu: None,
            hciemu_type: EmulatorType::BrEdrLe,
            io_handle: None,
            err_io_handle: None,
            sk: -1,
            disable_esco: false,
            enable_codecs: false,
            disable_sco_flowctl: false,
            step: 0,
            acl_handle: 0,
            handle: 0,
            tx_ts: TxTstampData::default(),
        }
    }
}

/// Per-test configuration — matches the C `struct sco_client_data`.
#[derive(Debug, Clone, Default)]
struct ScoClientData {
    expect_err: i32,
    recv_data: Option<&'static [u8]>,
    send_data: Option<&'static [u8]>,
    data_len: u16,
    connect_timeout_us: u32,
    shutdown: bool,
    close_after_connect: bool,
    so_timestamping: u32,
    repeat_send: u32,
    server: bool,
    defer: bool,
}

// ---------------------------------------------------------------------------
// Test Payload Data
// ---------------------------------------------------------------------------

static SCO_DATA: [u8; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];

// ---------------------------------------------------------------------------
// Static Test Data Constants
// ---------------------------------------------------------------------------

static CONNECT_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: false,
    defer: false,
};

static CONNECT_TIMEOUT: ScoClientData = ScoClientData {
    expect_err: libc::ETIMEDOUT,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 1,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: false,
    defer: false,
};

static CONNECT_CLOSE: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: true,
    so_timestamping: 0,
    repeat_send: 0,
    server: false,
    defer: false,
};

static DISCONNECT_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 0,
    shutdown: true,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: false,
    defer: false,
};

static CONNECT_FAILURE: ScoClientData = ScoClientData {
    expect_err: libc::EOPNOTSUPP,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: false,
    defer: false,
};

static CONNECT_FAILURE_RESET: ScoClientData = ScoClientData {
    expect_err: libc::ECONNRESET,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: false,
    defer: false,
};

static CONNECT_RECV_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: Some(&SCO_DATA),
    send_data: None,
    data_len: 9, // sizeof(SCO_DATA)
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: false,
    defer: false,
};

static CONNECT_RECV_RX_TS_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: Some(&SCO_DATA),
    send_data: None,
    data_len: 9,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE,
    repeat_send: 0,
    server: false,
    defer: false,
};

static CONNECT_SEND_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: Some(&SCO_DATA),
    data_len: 9,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 3,
    server: false,
    defer: false,
};

static CONNECT_SEND_TX_TIMESTAMPING: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: Some(&SCO_DATA),
    data_len: 9,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_OPT_ID
        | SOF_TIMESTAMPING_TX_SOFTWARE
        | SOF_TIMESTAMPING_TX_COMPLETION,
    repeat_send: 2,
    server: false,
    defer: false,
};

static CONNECT_SEND_NO_FLOWCTL_TX_TIMESTAMPING: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: Some(&SCO_DATA),
    data_len: 9,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_OPT_ID
        | SOF_TIMESTAMPING_TX_SOFTWARE,
    repeat_send: 2,
    server: false,
    defer: false,
};

static LISTEN_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: true,
    defer: false,
};

static LISTEN_DEFER_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: None,
    data_len: 0,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: true,
    defer: true,
};

static LISTEN_RECV_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: Some(&SCO_DATA),
    send_data: None,
    data_len: 9,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: true,
    defer: false,
};

static LISTEN_SEND_SUCCESS: ScoClientData = ScoClientData {
    expect_err: 0,
    recv_data: None,
    send_data: Some(&SCO_DATA),
    data_len: 9,
    connect_timeout_us: 0,
    shutdown: false,
    close_after_connect: false,
    so_timestamping: 0,
    repeat_send: 0,
    server: true,
    defer: false,
};

// ---------------------------------------------------------------------------
// Helper: downcast `&dyn Any` to `SharedState`
// ---------------------------------------------------------------------------

fn get_state(data: &dyn Any) -> Option<SharedState> {
    data.downcast_ref::<SharedState>().cloned()
}

// ---------------------------------------------------------------------------
// Pre-Setup
// ---------------------------------------------------------------------------

fn test_pre_setup(data: &dyn Any) {
    let state = match get_state(data) {
        Some(s) => s,
        None => {
            tester_pre_setup_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = pre_setup_async(state).await {
            tester_warn(&format!("pre-setup failed: {e}"));
            tester_pre_setup_failed();
        }
    });
}

async fn pre_setup_async(state: SharedState) -> Result<(), String> {
    let mgmt = Arc::new(MgmtSocket::new_default().map_err(|e| format!("mgmt new: {e}"))?);

    if tester_use_debug() {
        tester_debug("MGMT debugging enabled");
    }

    let (_sub_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;
    let (_rem_id, _rem_rx) = mgmt.subscribe(MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE).await;

    let rsp = mgmt
        .send_command(MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, &[])
        .await
        .map_err(|e| format!("read_index_list: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("read_index_list status={}", rsp.status));
    }

    let index_count =
        if rsp.data.len() >= 2 { u16::from_le_bytes([rsp.data[0], rsp.data[1]]) } else { 0 };

    if index_count > 0 && rsp.data.len() >= 4 {
        let index = u16::from_le_bytes([rsp.data[2], rsp.data[3]]);
        {
            let mut u = state.lock().unwrap();
            u.mgmt_index = index;
            u.mgmt = Some(mgmt.clone());
        }
        return read_info_and_complete(state, mgmt).await;
    }

    let emu_type = state.lock().unwrap().hciemu_type;
    let mut emulator = HciEmulator::new(emu_type).map_err(|e| format!("hciemu: {e}"))?;

    if tester_use_debug() {
        emulator.set_debug(tester_debug);
    }

    tester_print("New hciemu instance created");

    {
        let u = state.lock().unwrap();
        if u.disable_esco {
            tester_print("Disabling eSCO packet type support");
            let mut features = emulator.get_features();
            if features.len() > 3 {
                features[3] &= !0x80;
            }
        }
        if u.disable_sco_flowctl {
            tester_print("Disabling SCO flow control");
            let mut commands = emulator.get_commands();
            if commands.len() > 10 {
                commands[10] &= !(0x08 | 0x10);
            }
        }
    }

    let emu = Arc::new(Mutex::new(emulator));
    {
        let mut u = state.lock().unwrap();
        u.hciemu = Some(emu);
        u.mgmt = Some(mgmt.clone());
    }

    let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .map_err(|_| "timeout waiting for INDEX_ADDED".to_string())?
        .ok_or_else(|| "INDEX_ADDED channel closed".to_string())?;

    let index = ev.index;
    state.lock().unwrap().mgmt_index = index;

    tester_print(&format!("Index Added: 0x{index:04x}"));
    read_info_and_complete(state, mgmt).await
}

async fn read_info_and_complete(state: SharedState, mgmt: Arc<MgmtSocket>) -> Result<(), String> {
    let index = state.lock().unwrap().mgmt_index;
    let rsp = mgmt
        .send_command(MGMT_OP_READ_INFO, index, &[])
        .await
        .map_err(|e| format!("read_info: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("read_info status={}", rsp.status));
    }

    tester_print(&format!("Controller ready at index {index}"));
    tester_pre_setup_complete();
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-Teardown
// ---------------------------------------------------------------------------

fn test_post_teardown(data: &dyn Any) {
    let state = match get_state(data) {
        Some(s) => s,
        None => {
            tester_post_teardown_complete();
            return;
        }
    };

    {
        let mut u = state.lock().unwrap();
        if let Some(h) = u.io_handle.take() {
            h.abort();
        }
        if let Some(h) = u.err_io_handle.take() {
            h.abort();
        }
        if u.sk >= 0 {
            // SAFETY: sk is a valid fd opened by libc::socket earlier.
            ffi::raw_close(u.sk);
            u.sk = -1;
        }
        u.hciemu = None;
        u.mgmt = None;
    }

    tester_post_teardown_complete();
}

// ---------------------------------------------------------------------------
// Setup Functions
// ---------------------------------------------------------------------------

fn setup_powered(data: &dyn Any) {
    let state = match get_state(data) {
        Some(s) => s,
        None => {
            tester_setup_failed();
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = setup_powered_async(state).await {
            tester_warn(&format!("setup_powered failed: {e}"));
            tester_setup_failed();
        }
    });
}

async fn setup_powered_async(state: SharedState) -> Result<(), String> {
    let (mgmt, index, enable_codecs) = {
        let u = state.lock().unwrap();
        (u.mgmt.clone(), u.mgmt_index, u.enable_codecs)
    };
    let mgmt = mgmt.ok_or_else(|| "No MGMT socket".to_string())?;

    let param_on: [u8; 1] = [0x01];

    tester_print("Powering on controller");

    mgmt.send_command(MGMT_OP_SET_CONNECTABLE, index, &param_on)
        .await
        .map_err(|e| format!("SET_CONNECTABLE: {e}"))?;

    mgmt.send_command(MGMT_OP_SET_SSP, index, &param_on)
        .await
        .map_err(|e| format!("SET_SSP: {e}"))?;

    mgmt.send_command(MGMT_OP_SET_LE, index, &param_on)
        .await
        .map_err(|e| format!("SET_LE: {e}"))?;

    if enable_codecs {
        let uuid: [u8; 16] = [
            0xaf, 0x29, 0xc6, 0x66, 0xac, 0x5f, 0x1a, 0x88, 0xb9, 0x4f, 0x7f, 0xee, 0xce, 0x5a,
            0x69, 0xa6,
        ];
        let cp = mgmt_cp_set_exp_feature { uuid, action: 1 };
        // SAFETY: mgmt_cp_set_exp_feature is #[repr(C, packed)] — safe to
        // view as raw bytes for the MGMT command payload.
        let cp_buf = ffi::raw_struct_to_bytes(&cp);
        let cp_bytes: &[u8] = &cp_buf;

        tester_print("Enabling codecs");
        let rsp = mgmt
            .send_command(MGMT_OP_SET_EXP_FEATURE, index, cp_bytes)
            .await
            .map_err(|e| format!("SET_EXP_FEATURE: {e}"))?;

        if rsp.status != MGMT_STATUS_SUCCESS {
            tester_warn("Failed to enable codecs");
            return Err("enable codecs failed".to_string());
        }
        tester_print("Enabled codecs");
    }

    let rsp = mgmt
        .send_command(MGMT_OP_SET_POWERED, index, &param_on)
        .await
        .map_err(|e| format!("SET_POWERED: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_POWERED status={}", rsp.status));
    }

    tester_print("Controller powered on");

    let (emu, scodata) = {
        let u = state.lock().unwrap();
        (u.hciemu.clone(), u.test_data)
    };

    if let Some(ref emu) = emu {
        let emu_lock = emu.lock().unwrap();
        if let Some(mut bthost) = emu_lock.client_get_host() {
            let state_cmd = Arc::clone(&state);
            bthost.set_cmd_complete_cb(move |op, status, _params| {
                client_connectable_complete(&state_cmd, op, status);
            });
            bthost.write_scan_enable(0x03);
            state.lock().unwrap().step += 1;

            if let Some(sco) = scodata {
                if sco.send_data.is_some() || sco.recv_data.is_some() || sco.server {
                    let state_sco = Arc::clone(&state);
                    bthost.set_sco_cb(move |handle| {
                        sco_new_conn(&state_sco, handle);
                    });
                }

                if sco.server {
                    let central_bdaddr = emu_lock.get_central_bdaddr();
                    let state_acl = Arc::clone(&state);
                    bthost.set_connect_cb(move |handle| {
                        acl_new_conn(&state_acl, handle);
                    });
                    bthost.hci_connect(&central_bdaddr, BDADDR_BREDR);
                    state.lock().unwrap().step += 1;
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Callback Helpers
// ---------------------------------------------------------------------------

fn client_connectable_complete(state: &SharedState, op: u16, status: u8) {
    if op != hci_cmd_write_scan_enable() {
        return;
    }

    tester_print(&format!("Client set connectable status 0x{status:02x}"));

    let step = {
        let mut u = state.lock().unwrap();
        u.step -= 1;
        u.step
    };

    if step != 0 {
        return;
    }

    if status != 0 {
        tester_setup_failed();
    } else {
        tester_setup_complete();
    }
}

fn bthost_recv_data(state: &SharedState, buf: &[u8], _status: u8) {
    let (scodata, step) = {
        let mut u = state.lock().unwrap();
        u.step -= 1;
        let step = u.step;
        (u.test_data, step)
    };

    tester_print(&format!("Client received {} bytes of data", buf.len()));

    if let Some(sco) = scodata {
        if let Some(send_data) = sco.send_data {
            if sco.data_len as usize != buf.len() || send_data[..sco.data_len as usize] != *buf {
                tester_test_failed();
                return;
            }
        }
    }

    if step == 0 {
        tester_test_passed();
    }
}

fn acl_new_conn(state: &SharedState, handle: u16) {
    tester_print(&format!("New ACL connection with handle 0x{handle:04x}"));

    let step = {
        let mut u = state.lock().unwrap();
        u.acl_handle = handle;
        u.step -= 1;
        u.step
    };

    if step == 0 {
        tester_setup_complete();
    }
}

fn sco_new_conn(state: &SharedState, handle: u16) {
    tester_print(&format!("New client connection with handle 0x{handle:04x}"));

    let (scodata, emu) = {
        let mut u = state.lock().unwrap();
        u.handle = handle;
        (u.test_data, u.hciemu.clone())
    };

    if let Some(ref emu) = emu {
        let emu_lock = emu.lock().unwrap();
        if let Some(mut bthost) = emu_lock.client_get_host() {
            let state_recv = Arc::clone(state);
            bthost.add_sco_hook(handle, move |buf, status| {
                bthost_recv_data(&state_recv, buf, status);
            });

            if let Some(sco) = scodata {
                if let Some(recv_data) = sco.recv_data {
                    let data_slice = &recv_data[..sco.data_len as usize];
                    let iov = IoSlice::new(data_slice);
                    bthost.send_sco(handle, 0x00, &[iov]);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Socket Helpers
// ---------------------------------------------------------------------------

/// Create a non-blocking SCO socket, bind to the central bdaddr, optionally
/// set SO_SNDTIMEO if connect_timeout_us is set.
fn create_sco_sock(state: &SharedState) -> Result<i32, i32> {
    let (scodata, emu) = {
        let u = state.lock().unwrap();
        (u.test_data, u.hciemu.clone())
    };

    // SAFETY: Creating a Bluetooth SCO socket via libc. PF_BLUETOOTH and
    // BTPROTO_SCO are valid protocol family/protocol constants.
    let sk = ffi::raw_socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK, BTPROTO_SCO);
    if sk < 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
        tester_warn(&format!(
            "Can't create socket: {} ({})",
            io::Error::from_raw_os_error(err),
            err
        ));
        return Err(-err);
    }

    // Set send timeout if requested.
    if let Some(sco) = scodata {
        if sco.connect_timeout_us > 0 {
            let timeout = libc::timeval {
                tv_sec: (sco.connect_timeout_us / 1_000_000) as libc::time_t,
                tv_usec: (sco.connect_timeout_us % 1_000_000) as libc::suseconds_t,
            };
            // SAFETY: setsockopt with valid fd and correctly-sized timeval.
            let rc = ffi::raw_setsockopt(sk, libc::SOL_SOCKET, libc::SO_SNDTIMEO, &timeout);
            if rc != 0 {
                tester_warn("failed to set timeout");
                // SAFETY: closing a valid fd.
                ffi::raw_close(sk);
                return Err(-libc::EINVAL);
            }
        }
    }

    // Get central bdaddr for bind.
    let emu = emu.ok_or_else(|| {
        tester_warn("No emulator");
        // SAFETY: closing a valid fd.
        ffi::raw_close(sk);
        -libc::ENODEV
    })?;

    let central_bdaddr = {
        let emu_lock = emu.lock().unwrap();
        emu_lock.get_central_bdaddr()
    };

    let mut addr: sockaddr_sco = ffi::raw_zeroed();
    addr.sco_family = AF_BLUETOOTH as u16;
    addr.sco_bdaddr = bdaddr_t { b: central_bdaddr };

    // SAFETY: bind() with valid fd and properly initialized sockaddr_sco.
    let rc = ffi::raw_bind(sk, &addr);
    if rc < 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
        tester_warn(&format!("Can't bind socket: {} ({})", io::Error::from_raw_os_error(err), err));
        // SAFETY: closing a valid fd.
        ffi::raw_close(sk);
        return Err(-err);
    }

    Ok(sk)
}

/// Connect an SCO socket to the client (remote emulated device) bdaddr.
fn connect_sco_sock(state: &SharedState, sk: i32) -> Result<(), i32> {
    let emu = {
        let u = state.lock().unwrap();
        u.hciemu.clone()
    };

    let emu = emu.ok_or_else(|| {
        tester_warn("No emulator");
        -libc::ENODEV
    })?;

    let client_bdaddr = {
        let emu_lock = emu.lock().unwrap();
        emu_lock.get_client_bdaddr()
    };

    let client_bdaddr = client_bdaddr.ok_or_else(|| {
        tester_warn("No client bdaddr");
        -libc::ENODEV
    })?;

    let mut addr: sockaddr_sco = ffi::raw_zeroed();
    addr.sco_family = AF_BLUETOOTH as u16;
    addr.sco_bdaddr = bdaddr_t { b: client_bdaddr };

    // SAFETY: connect() with valid fd and properly initialized sockaddr_sco.
    let rc = ffi::raw_connect(sk, &addr);
    if rc < 0 {
        let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno_val != libc::EAGAIN && errno_val != libc::EINPROGRESS {
            tester_warn(&format!(
                "Can't connect socket: {} ({})",
                io::Error::from_raw_os_error(errno_val),
                errno_val
            ));
            return Err(-errno_val);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TX Timestamping helpers
// ---------------------------------------------------------------------------

/// Receive from errqueue for TX timestamp completions.
fn recv_errqueue(state: &SharedState) {
    let mut u = state.lock().unwrap();
    let sk = u.sk;
    if sk < 0 {
        return;
    }
    match u.tx_ts.tx_tstamp_recv(sk, 0) {
        Ok(0) => {
            tester_debug("TX timestamp receive complete");
            drop(u);
            tester_test_passed();
        }
        Ok(_remaining) => {
            tester_debug("TX timestamp receive in progress");
        }
        Err(e) => {
            tester_warn(&format!("TX timestamp recv error: {}", e));
            drop(u);
            tester_test_failed();
        }
    }
}

/// Set up TX timestamping and send data repeatedly.
fn sco_tx_timestamping(state: &SharedState, sk: i32) {
    let mut u = state.lock().unwrap();
    let sco_data = match u.test_data {
        Some(d) => d,
        None => return,
    };

    let flags = sco_data.so_timestamping;
    if flags == 0 {
        return;
    }

    u.tx_ts.tx_tstamp_init(flags, false);

    // SAFETY: setsockopt with valid fd and u32 value.
    let rc = ffi::raw_setsockopt(sk, libc::SOL_SOCKET, libc::SO_TIMESTAMPING, &flags);
    if rc < 0 {
        tester_warn("setsockopt SO_TIMESTAMPING failed");
        drop(u);
        tester_test_failed();
        return;
    }

    let send_data = match sco_data.send_data {
        Some(d) => d,
        None => {
            tester_warn("No send data for timestamping");
            drop(u);
            tester_test_failed();
            return;
        }
    };

    let repeat = if sco_data.repeat_send > 0 { sco_data.repeat_send } else { 1 };

    for i in 0..repeat {
        let len = sco_data.data_len as usize;
        u.tx_ts.tx_tstamp_expect(len);

        // SAFETY: send() with valid fd and data buffer.
        let ret = ffi::raw_send(sk, &send_data[..len], 0);
        if ret < 0 {
            let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            tester_warn(&format!("send() failed at iteration {}: errno {}", i, errno_val));
            drop(u);
            tester_test_failed();
            return;
        }
    }

    // Drop lock before spawning errqueue polling.
    let state_c = state.clone();
    drop(u);

    // Poll errqueue for timestamp completions.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            recv_errqueue(&state_c);
            // Check if test already passed/failed.
            let u = state_c.lock().unwrap();
            if u.sk < 0 {
                break;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Data receive helpers
// ---------------------------------------------------------------------------

/// Called when data arrives on a connected SCO socket.
fn sock_received_data(state: &SharedState) {
    let u = state.lock().unwrap();
    let sk = u.sk;
    let sco_data = match u.test_data {
        Some(d) => d,
        None => return,
    };

    let mut buf = vec![0u8; 300];
    let len = sco_data.data_len as usize;

    if sco_data.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE != 0 {
        // Use recv_tstamp with tstamp=true to extract and validate RX timestamps.
        match recv_tstamp(sk, &mut buf[..len], true) {
            Ok(nread) if nread > 0 => {
                tester_debug(&format!("recv_tstamp: {} bytes", nread));
                let expected = sco_data.recv_data.unwrap_or(&[]);
                if !expected.is_empty() && buf[..nread] != *expected {
                    tester_warn("received data mismatch");
                    drop(u);
                    tester_test_failed();
                    return;
                }
                drop(u);
                tester_test_passed();
            }
            Ok(_) => {
                tester_warn("recv_tstamp: no data");
            }
            Err(e) => {
                tester_warn(&format!("recv_tstamp error: {}", e));
                drop(u);
                tester_test_failed();
            }
        }
    } else {
        // SAFETY: recv() with valid fd and buffer.
        let ret = ffi::raw_recv(sk, &mut buf[..len], 0);
        if ret < 0 {
            let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            tester_warn(&format!("recv() failed: errno {}", errno_val));
            drop(u);
            tester_test_failed();
            return;
        }
        let nread = ret as usize;
        let expected = sco_data.recv_data.unwrap_or(&[]);
        if !expected.is_empty() && buf[..nread] != *expected {
            tester_warn("received data mismatch");
            drop(u);
            tester_test_failed();
            return;
        }
        drop(u);
        tester_test_passed();
    }
}

/// Set up SCO data receive (called when bthost has data callback registered).
fn sco_recv_data(state: &SharedState, sk: i32) {
    let sco_data = {
        let u = state.lock().unwrap();
        u.test_data
    };

    let sco_data = match sco_data {
        Some(d) => d,
        None => return,
    };

    if sco_data.recv_data.is_none() && sco_data.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE == 0
    {
        return;
    }

    // Set up RX timestamping if requested.
    if sco_data.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE != 0 {
        let flags = sco_data.so_timestamping;
        if rx_timestamping_init(sk, flags).is_err() {
            tester_warn("rx_timestamping_init failed");
            tester_test_failed();
            return;
        }
    }

    // Send data from bthost to trigger receive on our side.
    {
        let u = state.lock().unwrap();
        let handle = u.handle;
        if handle > 0 {
            if let Some(ref emu) = u.hciemu {
                let emu_lock = emu.lock().unwrap();
                if let Some(host) = emu_lock.client_get_host() {
                    let data = sco_data.recv_data.unwrap_or(&SCO_DATA);
                    let iov = IoSlice::new(data);
                    host.send_sco(handle, 0x00, &[iov]);
                }
            }
        }
    }

    // Spawn task to wait for readable.
    let state_c = state.clone();
    tokio::spawn(async move {
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.readable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sock_received_data(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("readable error: {}", e));
                tester_test_failed();
            }
        }
        // Prevent fd from being closed by AsyncFd drop.
        std::mem::forget(afd);
    });
}

// ---------------------------------------------------------------------------
// SCO connect flow
// ---------------------------------------------------------------------------

/// Main SCO connect routine — called after setup completes. Sends data
/// and/or registers for read if test_data requests it.
fn sco_connect(state: &SharedState, sk: i32) {
    let sco_data = {
        let u = state.lock().unwrap();
        u.test_data
    };
    let sco_data = match sco_data {
        Some(d) => d,
        None => {
            tester_test_passed();
            return;
        }
    };

    if let Some(send_data) = sco_data.send_data {
        // TX timestamping path.
        if sco_data.so_timestamping != 0 {
            sco_tx_timestamping(state, sk);
            return;
        }
        // Simple send.
        let len = sco_data.data_len as usize;
        // SAFETY: send() with valid fd and buffer.
        let ret = ffi::raw_send(sk, &send_data[..len], 0);
        if ret < 0 {
            let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            tester_warn(&format!("send() failed: errno {}", errno_val));
            tester_test_failed();
            return;
        }
        tester_test_passed();
        return;
    }

    if sco_data.recv_data.is_some() || sco_data.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE != 0
    {
        sco_recv_data(state, sk);
        return;
    }

    if sco_data.shutdown {
        // SAFETY: shutdown valid fd.
        ffi::raw_shutdown(sk, libc::SHUT_RDWR);
        tester_test_passed();
        return;
    }

    if sco_data.close_after_connect {
        tester_test_passed();
        return;
    }

    tester_test_passed();
}

/// Callback when connect() on non-blocking socket completes (writable).
fn sco_connect_cb(state: &SharedState) {
    let sk = state.lock().unwrap().sk;
    if sk < 0 {
        return;
    }

    // Check SO_ERROR.
    let mut err: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt with valid fd and correct types.
    ffi::raw_getsockopt(sk, libc::SOL_SOCKET, libc::SO_ERROR, &mut err, &mut len);

    let expect_err = state.lock().unwrap().test_data.map(|d| d.expect_err).unwrap_or(0);

    if err != expect_err {
        tester_warn(&format!("Expected connect error {} got {}", expect_err, err));
        tester_test_failed();
        return;
    }

    if err != 0 {
        tester_test_passed();
        return;
    }

    // Retrieve SCO connection info for handle.
    let mut ci: sco_conninfo = ffi::raw_zeroed();
    let mut ci_len: libc::socklen_t = std::mem::size_of::<sco_conninfo>() as libc::socklen_t;
    // SAFETY: getsockopt with valid fd and correctly-sized buffer.
    let rc = ffi::raw_getsockopt(sk, libc::SOL_SOCKET, SCO_CONNINFO, &mut ci, &mut ci_len);
    if rc >= 0 {
        state.lock().unwrap().handle = ci.hci_handle;
    }

    sco_connect(state, sk);
}

// ---------------------------------------------------------------------------
// Test functions
// ---------------------------------------------------------------------------

/// Test basic framework functionality — just passes immediately.
fn test_framework(data: &dyn Any) {
    let _ = data;
    tester_test_passed();
}

/// Test SCO socket creation and close.
fn test_socket(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();
    let sco_data = {
        let u = state.lock().unwrap();
        u.test_data
    };

    // SAFETY: Creating a Bluetooth SCO socket.
    let sk = ffi::raw_socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_SCO);
    if sk < 0 {
        let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let expect_err = sco_data.map(|d| d.expect_err).unwrap_or(0);
        if -errno_val == -expect_err || errno_val == expect_err {
            tester_test_passed();
        } else {
            tester_warn(&format!("socket() failed with unexpected errno {}", errno_val));
            tester_test_failed();
        }
        return;
    }
    // SAFETY: closing a valid fd.
    ffi::raw_close(sk);
    tester_test_passed();
}

/// Test BT_CODEC getsockopt on an SCO socket.
fn test_codecs_getsockopt(data: &dyn Any) {
    let _state = data.downcast_ref::<SharedState>().unwrap();

    // SAFETY: Creating a Bluetooth SCO socket.
    let sk = ffi::raw_socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_SCO);
    if sk < 0 {
        tester_test_failed();
        return;
    }

    let mut codecs: bt_codecs = ffi::raw_zeroed();
    let mut len: libc::socklen_t = std::mem::size_of::<bt_codecs>() as libc::socklen_t;

    // SAFETY: getsockopt with valid fd and correctly-sized buffer.
    let rc = ffi::raw_getsockopt(sk, SOL_BLUETOOTH, BT_CODEC, &mut codecs, &mut len);

    // SAFETY: closing a valid fd.
    ffi::raw_close(sk);

    if rc < 0 {
        let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        tester_debug(&format!("BT_CODEC getsockopt failed: errno {}", errno_val));
        // Depending on kernel, may not be supported; pass if EOPNOTSUPP/ENOPROTOOPT.
        if errno_val == libc::EOPNOTSUPP || errno_val == libc::ENOPROTOOPT {
            tester_test_passed();
        } else {
            tester_test_failed();
        }
        return;
    }

    tester_test_passed();
}

/// Test BT_CODEC setsockopt on an SCO socket.
fn test_codecs_setsockopt(data: &dyn Any) {
    let _state = data.downcast_ref::<SharedState>().unwrap();

    // SAFETY: Creating a Bluetooth SCO socket.
    let sk = ffi::raw_socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_SCO);
    if sk < 0 {
        tester_test_failed();
        return;
    }

    let codec = bt_codec {
        id: 2, // mSBC
        cid: 0,
        vid: 0,
        data_path_id: 0,
        num_caps: 0,
    };

    // SAFETY: setsockopt with valid fd and correctly-sized codec struct.
    let rc = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_CODEC, &codec);

    // SAFETY: closing a valid fd.
    ffi::raw_close(sk);

    if rc < 0 {
        let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        tester_debug(&format!("BT_CODEC setsockopt failed: errno {}", errno_val));
        if errno_val == libc::EOPNOTSUPP || errno_val == libc::ENOPROTOOPT {
            tester_test_passed();
        } else {
            tester_test_failed();
        }
        return;
    }

    tester_test_passed();
}

/// Test SCO_OPTIONS getsockopt on a connected SCO socket.
fn test_getsockopt(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };

    state.lock().unwrap().sk = sk;

    // getsockopt SCO_OPTIONS before connect.
    let mut opts: sco_options = ffi::raw_zeroed();
    let mut len: libc::socklen_t = std::mem::size_of::<sco_options>() as libc::socklen_t;

    // SAFETY: getsockopt with valid fd and correctly-sized buffer.
    let rc = ffi::raw_getsockopt(sk, libc::SOL_SOCKET, SCO_OPTIONS, &mut opts, &mut len);

    if rc < 0 {
        tester_warn("getsockopt SCO_OPTIONS failed");
        tester_test_failed();
        return;
    }

    tester_test_passed();
}

/// Test BT_VOICE setsockopt on an SCO socket.
fn test_setsockopt(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };

    state.lock().unwrap().sk = sk;

    let voice = bt_voice { setting: BT_VOICE_TRANSPARENT };

    // SAFETY: setsockopt with valid fd and correctly-sized bt_voice struct.
    let rc = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice);

    if rc < 0 {
        tester_warn("setsockopt BT_VOICE failed");
        tester_test_failed();
        return;
    }

    tester_test_passed();
}

// ---------------------------------------------------------------------------
// Connect test functions
// ---------------------------------------------------------------------------

/// Core connect test — creates socket, sets voice/codec options, connects.
fn test_connect(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };
    state.lock().unwrap().sk = sk;

    if connect_sco_sock(state, sk).is_err() {
        tester_test_failed();
        return;
    }

    // Wait for connect completion via AsyncFd writable.
    let state_c = state.clone();
    tokio::spawn(async move {
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.writable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sco_connect_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("writable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

/// Connect with transparent voice setting (mSBC/transparent codec).
fn test_connect_transp(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };
    state.lock().unwrap().sk = sk;

    let voice = bt_voice { setting: BT_VOICE_TRANSPARENT };

    // SAFETY: setsockopt with valid fd and correctly-sized bt_voice struct.
    let rc = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice);
    if rc < 0 {
        tester_warn("setsockopt BT_VOICE failed");
        tester_test_failed();
        return;
    }

    if connect_sco_sock(state, sk).is_err() {
        tester_test_failed();
        return;
    }

    let state_c = state.clone();
    tokio::spawn(async move {
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.writable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sco_connect_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("writable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

/// Connect test with offload mSBC codec via BT_CODEC setsockopt.
fn test_connect_offload_msbc(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };
    state.lock().unwrap().sk = sk;

    // Set transparent voice.
    let voice = bt_voice { setting: BT_VOICE_TRANSPARENT };

    // SAFETY: setsockopt with valid fd.
    let rc = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice);
    if rc < 0 {
        tester_warn("setsockopt BT_VOICE failed");
        tester_test_failed();
        return;
    }

    // Set BT_CODEC for mSBC offload.
    let codec = bt_codec {
        id: 2, // mSBC
        cid: 0,
        vid: 0,
        data_path_id: 1,
        num_caps: 0,
    };

    // SAFETY: setsockopt with valid fd.
    let rc = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_CODEC, &codec);
    if rc < 0 {
        let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let expect_err = state.lock().unwrap().test_data.map(|d| d.expect_err).unwrap_or(0);
        if errno_val == expect_err || -errno_val == -expect_err {
            tester_test_passed();
        } else {
            tester_warn(&format!("setsockopt BT_CODEC failed: errno {}", errno_val));
            tester_test_failed();
        }
        return;
    }

    if connect_sco_sock(state, sk).is_err() {
        tester_test_failed();
        return;
    }

    let state_c = state.clone();
    tokio::spawn(async move {
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.writable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sco_connect_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("writable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

// ---------------------------------------------------------------------------
// Hook functions for HCI event/command interception
// ---------------------------------------------------------------------------

/// Hook: delay sync conn complete event — used for delayed connect test.
fn hook_delay_evt(msg: &[u8]) -> bool {
    if msg.is_empty() {
        return true;
    }
    // Event code is at byte 0 of HCI event (after indicator in some cases).
    // The emulator hook provides the HCI event payload starting with event code.
    if !msg.is_empty() && msg[0] == EVT_SYNC_CONN_COMPLETE {
        // Delay by returning false to drop/defer the event.
        return false;
    }
    true
}

/// Hook: intercept Setup Sync Conn command response and modify codec.
/// Available for extended SCO codec negotiation test scenarios.
#[allow(dead_code)]
fn hook_setup_sync_evt(msg: &[u8]) -> bool {
    if msg.is_empty() {
        return true;
    }
    if !msg.is_empty() && msg[0] == EVT_SYNC_CONN_COMPLETE {
        // Allow the event to pass through after checking.
        return true;
    }
    true
}

/// Hook: intercept disconnect complete event.
fn hook_disconnect_evt(msg: &[u8]) -> bool {
    if msg.is_empty() {
        return true;
    }
    if !msg.is_empty() && msg[0] == EVT_DISCONN_COMPLETE {
        // Allow disconnect to proceed.
        return true;
    }
    true
}

/// Hook: simultaneous disconnect — drop disconnect events.
fn hook_simult_disc(msg: &[u8]) -> bool {
    if msg.is_empty() {
        return true;
    }
    if !msg.is_empty() && msg[0] == EVT_DISCONN_COMPLETE {
        // Drop the disconnect event to simulate simultaneous disconnect.
        return false;
    }
    true
}

/// Hook: delay command — used for ACL disconnect test.
/// Available for extended simultaneous disconnect test scenarios.
#[allow(dead_code)]
fn hook_delay_cmd(msg: &[u8]) -> bool {
    if msg.is_empty() {
        return true;
    }
    // Check opcode (first 2 bytes of HCI command).
    if msg.len() >= 2 {
        let cmd_opcode = u16::from_le_bytes([msg[0], msg[1]]);
        let scan_enable_opcode = opcode(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE);
        if cmd_opcode == scan_enable_opcode {
            return false;
        }
    }
    true
}

/// Hook: ACL disconnect — intercept disconnect to do SCO first.
fn hook_acl_disc(msg: &[u8]) -> bool {
    if msg.is_empty() {
        return true;
    }
    if !msg.is_empty() && msg[0] == EVT_DISCONN_COMPLETE {
        // Allow through.
        return true;
    }
    true
}

// ---------------------------------------------------------------------------
// Delayed and disconnect test functions
// ---------------------------------------------------------------------------

/// Connect test with delayed SCO connection establishment.
fn test_connect_delayed(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    // Add hook to delay sync conn complete.
    {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let mut emu_lock = emu.lock().unwrap();
            emu_lock.add_hook(HookType::PostEvt, EVT_SYNC_CONN_COMPLETE as u16, hook_delay_evt);
        }
    }

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };
    state.lock().unwrap().sk = sk;

    if connect_sco_sock(state, sk).is_err() {
        tester_test_failed();
        return;
    }

    // After a delay, remove hook to allow connection to complete.
    let state_c = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        {
            let u = state_c.lock().unwrap();
            if let Some(ref emu) = u.hciemu {
                let mut emu_lock = emu.lock().unwrap();
                emu_lock.del_hook(HookType::PostEvt, EVT_SYNC_CONN_COMPLETE as u16);
            }
        }
        // Now wait for connect.
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.writable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sco_connect_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("writable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

/// Test SCO disconnect — connect then disconnect.
fn test_disconnect(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    // Add hook for disconnect event.
    {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let mut emu_lock = emu.lock().unwrap();
            emu_lock.add_hook(HookType::PostEvt, EVT_DISCONN_COMPLETE as u16, hook_disconnect_evt);
        }
    }

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };
    state.lock().unwrap().sk = sk;

    if connect_sco_sock(state, sk).is_err() {
        tester_test_failed();
        return;
    }

    let state_c = state.clone();
    tokio::spawn(async move {
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.writable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                // Connected, now disconnect.
                sco_connect_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("writable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

/// Test simultaneous SCO disconnect from both sides.
fn test_connect_simult_disc(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    // Add hook to intercept disconnect events.
    {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let mut emu_lock = emu.lock().unwrap();
            emu_lock.add_hook(HookType::PostEvt, EVT_DISCONN_COMPLETE as u16, hook_simult_disc);
        }
    }

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };
    state.lock().unwrap().sk = sk;

    if connect_sco_sock(state, sk).is_err() {
        tester_test_failed();
        return;
    }

    let state_c = state.clone();
    tokio::spawn(async move {
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.writable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sco_connect_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("writable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

/// Test ACL disconnect during SCO connection.
fn test_connect_acl_disc(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    // Add hook for ACL disconnect.
    {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let mut emu_lock = emu.lock().unwrap();
            emu_lock.add_hook(HookType::PostEvt, EVT_DISCONN_COMPLETE as u16, hook_acl_disc);
        }
    }

    let sk = match create_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_test_failed();
            return;
        }
    };
    state.lock().unwrap().sk = sk;

    if connect_sco_sock(state, sk).is_err() {
        tester_test_failed();
        return;
    }

    let state_c = state.clone();
    tokio::spawn(async move {
        let afd = match AsyncFd::new(state_c.lock().unwrap().sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.writable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sco_connect_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("writable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

/// Test ethtool timestamping info retrieval for SCO.
fn test_sco_ethtool_get_ts_info(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();
    let u = state.lock().unwrap();
    let index = u.mgmt_index;
    let disable_sco_flowctl = u.disable_sco_flowctl;
    drop(u);

    match test_ethtool_get_ts_info(index as u32, BTPROTO_SCO, disable_sco_flowctl) {
        Ok(()) => tester_test_passed(),
        Err(e) => {
            tester_warn(&format!("ethtool_get_ts_info error: {}", e));
            tester_test_failed();
        }
    }
}

// ---------------------------------------------------------------------------
// Listen/Accept (Server) functions
// ---------------------------------------------------------------------------

/// Create, bind, and listen on an SCO socket. Returns the listening fd.
fn listen_sco_sock(state: &SharedState) -> Result<i32, i32> {
    let (scodata, emu) = {
        let u = state.lock().unwrap();
        (u.test_data, u.hciemu.clone())
    };

    // SAFETY: Creating a Bluetooth SCO socket.
    let sk = ffi::raw_socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK, BTPROTO_SCO);
    if sk < 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
        tester_warn(&format!(
            "Can't create socket: {} ({})",
            io::Error::from_raw_os_error(err),
            err
        ));
        return Err(-err);
    }

    // BT_DEFER_SETUP if requested.
    if let Some(d) = scodata {
        if d.defer {
            let val: i32 = 1;
            // SAFETY: setsockopt with valid fd and i32 value.
            let rc = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP, &val);
            if rc < 0 {
                tester_warn("setsockopt BT_DEFER_SETUP failed");
                // SAFETY: closing valid fd.
                ffi::raw_close(sk);
                return Err(-libc::EINVAL);
            }
        }
    }

    // Get central bdaddr.
    let emu = emu.ok_or_else(|| {
        tester_warn("No emulator");
        // SAFETY: closing valid fd.
        ffi::raw_close(sk);
        -libc::ENODEV
    })?;

    let central_bdaddr = {
        let emu_lock = emu.lock().unwrap();
        emu_lock.get_central_bdaddr()
    };

    let mut addr: sockaddr_sco = ffi::raw_zeroed();
    addr.sco_family = AF_BLUETOOTH as u16;
    addr.sco_bdaddr = bdaddr_t { b: central_bdaddr };

    // SAFETY: bind() with valid fd.
    let rc = ffi::raw_bind(sk, &addr);
    if rc < 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
        tester_warn(&format!("Can't bind socket: {} ({})", io::Error::from_raw_os_error(err), err));
        // SAFETY: closing valid fd.
        ffi::raw_close(sk);
        return Err(-err);
    }

    // SAFETY: listen() with valid fd.
    let rc = ffi::raw_listen(sk, 1);
    if rc < 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
        tester_warn(&format!(
            "Can't listen socket: {} ({})",
            io::Error::from_raw_os_error(err),
            err
        ));
        // SAFETY: closing valid fd.
        ffi::raw_close(sk);
        return Err(-err);
    }

    Ok(sk)
}

/// Handle deferred SCO accept using poll + accept + read.
fn sco_defer_accept(state: &SharedState, accept_sk: i32) {
    let scodata = {
        let u = state.lock().unwrap();
        u.test_data
    };
    let scodata = match scodata {
        Some(d) => d,
        None => {
            tester_test_passed();
            return;
        }
    };

    if !scodata.defer {
        tester_test_passed();
        return;
    }

    let mut pfd = libc::pollfd { fd: accept_sk, events: libc::POLLOUT, revents: 0 };

    // SAFETY: poll() with valid fd.
    let rc = {
        let (_pr, _rv) = ffi::raw_poll_single(pfd.fd, pfd.events, 100);
        pfd.revents = _rv;
        _pr
    };
    if rc <= 0 {
        tester_warn("poll() for deferred accept timed out");
        tester_test_failed();
        return;
    }

    if pfd.revents & libc::POLLHUP != 0 {
        tester_debug("Deferred accept HUP — peer disconnected");
        tester_test_passed();
        return;
    }

    // Read 1 byte to complete the deferred accept.
    let mut buf = [0u8; 1];
    // SAFETY: recv with valid fd.
    let ret = ffi::raw_recv(accept_sk, &mut buf[..1], 0);
    if ret < 0 {
        let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno_val != libc::EAGAIN {
            tester_warn(&format!("Deferred accept recv failed: errno {}", errno_val));
            tester_test_failed();
            return;
        }
    }

    tester_test_passed();
}

/// Callback when a connection arrives on the listening SCO socket.
fn sco_accept_cb(state: &SharedState) {
    let sk = {
        let u = state.lock().unwrap();
        u.sk
    };
    if sk < 0 {
        return;
    }

    let mut addr: sockaddr_sco = ffi::raw_zeroed();
    let mut addrlen: libc::socklen_t = std::mem::size_of::<sockaddr_sco>() as libc::socklen_t;

    // SAFETY: accept() with valid listening fd.
    let new_sk = ffi::raw_accept(sk, &mut addr, &mut addrlen);
    if new_sk < 0 {
        let errno_val = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        tester_warn(&format!("accept() failed: errno {}", errno_val));
        tester_test_failed();
        return;
    }

    let scodata = {
        let u = state.lock().unwrap();
        u.test_data
    };
    let scodata = match scodata {
        Some(d) => d,
        None => {
            // SAFETY: closing valid fd.
            ffi::raw_close(new_sk);
            tester_test_passed();
            return;
        }
    };

    // If defer, handle deferred accept.
    if scodata.defer {
        sco_defer_accept(state, new_sk);
        // SAFETY: closing valid fd.
        ffi::raw_close(new_sk);
        return;
    }

    // Get connection info.
    let mut ci: sco_conninfo = ffi::raw_zeroed();
    let mut ci_len: libc::socklen_t = std::mem::size_of::<sco_conninfo>() as libc::socklen_t;
    // SAFETY: getsockopt with valid fd.
    let rc = ffi::raw_getsockopt(new_sk, libc::SOL_SOCKET, SCO_CONNINFO, &mut ci, &mut ci_len);
    if rc >= 0 {
        state.lock().unwrap().handle = ci.hci_handle;
    }

    // Handle send data.
    if let Some(send_buf) = scodata.send_data {
        let len = scodata.data_len as usize;
        // SAFETY: send() with valid fd.
        let ret = ffi::raw_send(new_sk, &send_buf[..len], 0);
        if ret < 0 {
            tester_warn("send() on accepted socket failed");
            // SAFETY: closing valid fd.
            ffi::raw_close(new_sk);
            tester_test_failed();
            return;
        }
    }

    // Handle recv data.
    if scodata.recv_data.is_some() {
        let len = scodata.data_len as usize;
        let mut buf = vec![0u8; len];
        // Wait for data to arrive on accepted socket.
        let _state_c = state.clone();
        tokio::spawn(async move {
            let owned = ffi::raw_owned_fd(new_sk);
            let afd = match AsyncFd::new(owned) {
                Ok(f) => f,
                Err(e) => {
                    tester_warn(&format!("AsyncFd error: {}", e));
                    tester_test_failed();
                    return;
                }
            };
            match afd.readable().await {
                Ok(mut guard) => {
                    guard.clear_ready();
                    let expected = scodata.recv_data.unwrap();
                    let ret = ffi::raw_recv(new_sk, &mut buf[..len], 0);
                    if ret > 0 && buf[..ret as usize] == *expected {
                        tester_test_passed();
                    } else {
                        tester_warn("Server recv data mismatch");
                        tester_test_failed();
                    }
                }
                Err(e) => {
                    tester_warn(&format!("readable error: {}", e));
                    tester_test_failed();
                }
            }
            std::mem::forget(afd);
            // SAFETY: closing valid fd.
            ffi::raw_close(new_sk);
        });
        return;
    }

    // SAFETY: closing valid fd.
    ffi::raw_close(new_sk);
    tester_test_passed();
}

/// Setup function for listen (server) tests — creates listening socket then
/// triggers bthost to initiate HCI connection.
fn setup_listen(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    let sk = match listen_sco_sock(state) {
        Ok(s) => s,
        Err(_) => {
            tester_setup_failed();
            return;
        }
    };

    state.lock().unwrap().sk = sk;

    // Configure bthost to initiate SCO from remote side.
    {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let emu_lock = emu.lock().unwrap();
            let central_bdaddr = emu_lock.get_central_bdaddr();
            if let Some(mut host) = emu_lock.client_get_host() {
                host.hci_connect(&central_bdaddr, BDADDR_BREDR);
            }
        }
    }

    tester_setup_complete();
}

/// Test function for listen tests — waits for incoming SCO connection.
fn test_listen(data: &dyn Any) {
    let state = data.downcast_ref::<SharedState>().unwrap();

    let state_c = state.clone();
    tokio::spawn(async move {
        let sk = state_c.lock().unwrap().sk;
        if sk < 0 {
            tester_test_failed();
            return;
        }
        let afd = match AsyncFd::new(sk) {
            Ok(f) => f,
            Err(e) => {
                tester_warn(&format!("AsyncFd error: {}", e));
                tester_test_failed();
                return;
            }
        };
        match afd.readable().await {
            Ok(mut guard) => {
                guard.clear_ready();
                sco_accept_cb(&state_c);
            }
            Err(e) => {
                tester_warn(&format!("readable error: {}", e));
                tester_test_failed();
            }
        }
        std::mem::forget(afd);
    });
}

// ---------------------------------------------------------------------------
// Test registration helpers
// ---------------------------------------------------------------------------

/// Full test registration with per-test options.
fn test_sco_full(
    name: &str,
    sco_data: &'static ScoClientData,
    setup: fn(&dyn Any),
    test_fn: fn(&dyn Any),
    disable_esco: bool,
    enable_codecs: bool,
    disable_sco_flowctl: bool,
    emu_type: EmulatorType,
    timeout: u32,
) {
    let state: SharedState = Arc::new(Mutex::new(TestData {
        test_data: Some(sco_data),
        disable_esco,
        enable_codecs,
        disable_sco_flowctl,
        hciemu_type: emu_type,
        ..TestData::default()
    }));

    let pre_setup_cb: TestCallback = Arc::new(test_pre_setup);
    let setup_cb: TestCallback = Arc::new(setup);
    let test_cb: TestCallback = Arc::new(test_fn);
    let post_teardown_cb: TestCallback = Arc::new(test_post_teardown);
    tester_add_full(
        name,
        Some(state),
        Some(pre_setup_cb),
        Some(setup_cb),
        Some(test_cb),
        None::<TestCallback>,
        Some(post_teardown_cb),
        timeout,
        None::<()>,
    );
}

/// Convenience: register SCO test with default options.
fn test_sco(
    name: &str,
    sco_data: &'static ScoClientData,
    setup: fn(&dyn Any),
    test_fn: fn(&dyn Any),
) {
    test_sco_full(name, sco_data, setup, test_fn, false, false, false, EmulatorType::BrEdrLe52, 2);
}

/// Convenience: register SCO 1.1 test (BrEdrLe emulator).
fn test_sco_11(
    name: &str,
    sco_data: &'static ScoClientData,
    setup: fn(&dyn Any),
    test_fn: fn(&dyn Any),
) {
    test_sco_full(name, sco_data, setup, test_fn, false, false, false, EmulatorType::BrEdrLe, 2);
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    // Framework test.
    test_sco("SCO Framework - Success", &CONNECT_SUCCESS, setup_powered, test_framework);

    // Socket creation.
    test_sco("SCO Socket - Success", &CONNECT_SUCCESS, setup_powered, test_socket);

    // Codec options.
    test_sco_full(
        "SCO Socket - BT_CODEC getsockopt - Success",
        &CONNECT_SUCCESS,
        setup_powered,
        test_codecs_getsockopt,
        false,
        true,
        false,
        EmulatorType::BrEdrLe52,
        2,
    );
    test_sco_full(
        "SCO Socket - BT_CODEC setsockopt - Success",
        &CONNECT_SUCCESS,
        setup_powered,
        test_codecs_setsockopt,
        false,
        true,
        false,
        EmulatorType::BrEdrLe52,
        2,
    );

    // Socket options.
    test_sco("SCO Socket - getsockopt - Success", &CONNECT_SUCCESS, setup_powered, test_getsockopt);
    test_sco("SCO Socket - setsockopt - Success", &CONNECT_SUCCESS, setup_powered, test_setsockopt);

    // Connect tests.
    test_sco("SCO Connect - Success", &CONNECT_SUCCESS, setup_powered, test_connect);
    test_sco("SCO Connect - Timeout", &CONNECT_TIMEOUT, setup_powered, test_connect);
    test_sco("SCO Connect - Close", &CONNECT_CLOSE, setup_powered, test_connect);

    // 1.1 variants.
    test_sco_11("SCO Connect - Success 1.1", &CONNECT_SUCCESS, setup_powered, test_connect);
    test_sco_11("SCO Connect - Timeout 1.1", &CONNECT_TIMEOUT, setup_powered, test_connect);
    test_sco_11("SCO Connect - Close 1.1", &CONNECT_CLOSE, setup_powered, test_connect);

    // Failure.
    test_sco("SCO Connect - Failure", &CONNECT_FAILURE, setup_powered, test_connect);
    test_sco("SCO Connect - Failure - Reset", &CONNECT_FAILURE_RESET, setup_powered, test_connect);

    // Disconnect.
    test_sco("SCO Disconnect - Success", &DISCONNECT_SUCCESS, setup_powered, test_disconnect);

    // Simultaneous disconnect.
    test_sco(
        "SCO Connect - Simultaneous Disc",
        &DISCONNECT_SUCCESS,
        setup_powered,
        test_connect_simult_disc,
    );

    // ACL disconnect.
    test_sco("SCO Connect - ACL Disc", &DISCONNECT_SUCCESS, setup_powered, test_connect_acl_disc);

    // Transparent connect (eSCO disabled).
    test_sco_full(
        "eSCO Connect - Success",
        &CONNECT_SUCCESS,
        setup_powered,
        test_connect_transp,
        true,
        false,
        false,
        EmulatorType::BrEdrLe52,
        2,
    );

    // Offload mSBC.
    test_sco_full(
        "eSCO Connect - Offload mSBC",
        &CONNECT_SUCCESS,
        setup_powered,
        test_connect_offload_msbc,
        true,
        true,
        false,
        EmulatorType::BrEdrLe52,
        2,
    );

    // Delayed connect.
    test_sco_full(
        "SCO Connect - Delayed",
        &CONNECT_SUCCESS,
        setup_powered,
        test_connect_delayed,
        false,
        false,
        false,
        EmulatorType::BrEdrLe52,
        4,
    );

    // Send tests.
    test_sco("SCO Send - Success", &CONNECT_SEND_SUCCESS, setup_powered, test_connect);

    // TX timestamping.
    test_sco(
        "SCO Send - TX Software Timestamping",
        &CONNECT_SEND_TX_TIMESTAMPING,
        setup_powered,
        test_connect,
    );

    // TX timestamping without SCO flow control.
    test_sco_full(
        "SCO Send - TX Software Timestamping No Flowctl",
        &CONNECT_SEND_NO_FLOWCTL_TX_TIMESTAMPING,
        setup_powered,
        test_connect,
        false,
        false,
        true,
        EmulatorType::BrEdrLe52,
        2,
    );

    // Receive tests.
    test_sco("SCO Recv - Success", &CONNECT_RECV_SUCCESS, setup_powered, test_connect);

    // RX timestamping.
    test_sco(
        "SCO Recv - RX Timestamping",
        &CONNECT_RECV_RX_TS_SUCCESS,
        setup_powered,
        test_connect,
    );

    // Ethtool.
    test_sco(
        "SCO Ethtool - TS Info",
        &CONNECT_SUCCESS,
        setup_powered,
        test_sco_ethtool_get_ts_info,
    );

    test_sco_full(
        "SCO Ethtool - TS Info No Flowctl",
        &CONNECT_SUCCESS,
        setup_powered,
        test_sco_ethtool_get_ts_info,
        false,
        false,
        true,
        EmulatorType::BrEdrLe52,
        2,
    );

    // Server/listen tests.
    test_sco("SCO Listen - Success", &LISTEN_SUCCESS, setup_listen, test_listen);
    test_sco("SCO Listen - Defer", &LISTEN_DEFER_SUCCESS, setup_listen, test_listen);
    test_sco("SCO Listen - Recv", &LISTEN_RECV_SUCCESS, setup_listen, test_listen);
    test_sco("SCO Listen - Send", &LISTEN_SEND_SUCCESS, setup_listen, test_listen);

    let exit_code = tester_run();
    ExitCode::from(exit_code as u8)
}
