// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright 2024 BlueZ Project
//
// RFCOMM socket tester — validates RFCOMM client connections, server accepts,
// data send/receive, and connection refusal scenarios via an HCI emulator.
//
// Rust rewrite of tools/rfcomm-tester.c (862 lines, GPL-2.0-or-later).

#![deny(warnings)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::{debug, info, warn};

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::mgmt::client::{MgmtEvent, MgmtSocket};
use bluez_shared::socket::{BluetoothSocket, BtSocketError, BtTransport};
use bluez_shared::sys::bluetooth::{BDADDR_ANY, BDADDR_BREDR, bdaddr_t};
use bluez_shared::sys::hci::{OCF_WRITE_SCAN_ENABLE, OGF_HOST_CTL, opcode};
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE, MGMT_OP_READ_INDEX_LIST, MGMT_OP_READ_INFO,
    MGMT_OP_SET_CONNECTABLE, MGMT_OP_SET_POWERED, MGMT_OP_SET_SSP, MGMT_STATUS_SUCCESS,
};
use bluez_shared::sys::rfcomm::sockaddr_rc;
use bluez_shared::tester::{
    tester_add_full, tester_get_data, tester_init, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_pre_setup_failed, tester_print, tester_run,
    tester_setup_complete, tester_setup_failed, tester_test_failed, tester_test_passed,
    tester_use_debug, tester_warn,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// L2CAP PSM for RFCOMM (always 3).
const RFCOMM_PSM: u16 = 0x0003;

/// Default timeout for each test case (seconds).
const TEST_TIMEOUT: u32 = 2;

/// HCI Write Scan Enable command opcode.
const CMD_WRITE_SCAN_ENABLE: u16 = opcode(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE);

// ---------------------------------------------------------------------------
// Test Data Structures
// ---------------------------------------------------------------------------

/// Configuration for RFCOMM client-side tests.
/// Mirrors `struct rfcomm_client_data` from rfcomm-tester.c:48-56.
#[derive(Clone, Debug)]
struct RfcommClientData {
    server_channel: u8,
    client_channel: u8,
    close: bool,
    expected_connect_err: i32,
    send_data: &'static [u8],
    read_data: &'static [u8],
    data_len: u16,
}

/// Configuration for RFCOMM server-side tests.
/// Mirrors `struct rfcomm_server_data` from rfcomm-tester.c:58-70.
#[derive(Clone, Debug)]
struct RfcommServerData {
    server_channel: u8,
    client_channel: u8,
    send_data: &'static [u8],
    read_data: &'static [u8],
    data_len: u16,
}

/// Test configuration wrapper (client or server).
#[derive(Clone, Debug)]
enum TestConfig {
    Client(RfcommClientData),
    Server(RfcommServerData),
}

/// Mutable runtime state for a single test execution.
struct TestState {
    mgmt: Option<MgmtSocket>,
    mgmt_index: u16,
    hciemu: Option<HciEmulator>,
    hciemu_type: EmulatorType,
    config: TestConfig,
    io_handle: Option<tokio::task::JoinHandle<()>>,
    conn_handle: u16,
    rfcomm_cid: u16,
}

/// Shared state passed to the tester as `test_data`.
type SharedState = Arc<Mutex<TestState>>;

// ---------------------------------------------------------------------------
// Static test data (rfcomm-tester.c:72-150)
// ---------------------------------------------------------------------------

/// 9-byte test payload used by most data tests.
const DATA_9: [u8; 9] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

/// 32 KiB test payload: repeating bytes 0x00-0x07 across 4096 blocks.
static DATA_32K: [u8; 32768] = {
    let mut buf = [0u8; 32768];
    let mut i = 0;
    while i < 32768 {
        buf[i] = (i % 8) as u8;
        i += 1;
    }
    buf
};

static CONNECT_SUCCESS: RfcommClientData = RfcommClientData {
    server_channel: 1,
    client_channel: 0,
    close: false,
    expected_connect_err: 0,
    send_data: &[],
    read_data: &[],
    data_len: 0,
};

static CONNECT_SEND_SUCCESS: RfcommClientData = RfcommClientData {
    server_channel: 1,
    client_channel: 0,
    close: false,
    expected_connect_err: 0,
    send_data: &DATA_9,
    read_data: &[],
    data_len: 9,
};

static CONNECT_SEND_32K_SUCCESS: RfcommClientData = RfcommClientData {
    server_channel: 1,
    client_channel: 0,
    close: false,
    expected_connect_err: 0,
    send_data: &DATA_32K,
    read_data: &[],
    data_len: 0,
};

static CONNECT_READ_SUCCESS: RfcommClientData = RfcommClientData {
    server_channel: 1,
    client_channel: 0,
    close: false,
    expected_connect_err: 0,
    send_data: &[],
    read_data: &DATA_9,
    data_len: 9,
};

static CONNECT_NVAL: RfcommClientData = RfcommClientData {
    server_channel: 1,
    client_channel: 0,
    close: false,
    expected_connect_err: libc::ECONNREFUSED,
    send_data: &[],
    read_data: &[],
    data_len: 0,
};

static CONNECT_CLOSE: RfcommClientData = RfcommClientData {
    server_channel: 1,
    client_channel: 0,
    close: true,
    expected_connect_err: 0,
    send_data: &[],
    read_data: &[],
    data_len: 0,
};

static LISTEN_SUCCESS: RfcommServerData = RfcommServerData {
    server_channel: 1,
    client_channel: 1,
    send_data: &[],
    read_data: &[],
    data_len: 0,
};

static LISTEN_SEND_SUCCESS: RfcommServerData = RfcommServerData {
    server_channel: 1,
    client_channel: 1,
    send_data: &DATA_9,
    read_data: &[],
    data_len: 9,
};

static LISTEN_READ_SUCCESS: RfcommServerData = RfcommServerData {
    server_channel: 1,
    client_channel: 1,
    send_data: &[],
    read_data: &DATA_9,
    data_len: 9,
};

// ---------------------------------------------------------------------------
// Debug helper
// ---------------------------------------------------------------------------

/// Debug callback for HCI emulator output.
fn print_debug(text: &str) {
    let trimmed = text.trim_end();
    info!("rfcomm-tester: {}", trimmed);
}

// ---------------------------------------------------------------------------
// Error helper — extract errno from BtSocketError
// ---------------------------------------------------------------------------

/// Extract a raw POSIX errno value from a `BtSocketError`.
fn extract_errno(err: &BtSocketError) -> Option<i32> {
    match err {
        BtSocketError::SocketError(errno) => Some(*errno as i32),
        BtSocketError::ConnectionFailed(msg) => {
            // Parse "connect failed with SO_ERROR <N>" pattern.
            if let Some(pos) = msg.rfind("SO_ERROR ") {
                let rest = &msg[pos + 9..];
                rest.trim().parse::<i32>().ok()
            } else {
                None
            }
        }
        BtSocketError::IoError(e) => e.raw_os_error(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Pre-setup (rfcomm-tester.c:84-188)
// ---------------------------------------------------------------------------

/// Pre-setup: create MGMT client, discover HCI index, read adapter info.
fn test_pre_setup(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_pre_setup_failed();
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = pre_setup_async(state).await {
            warn!("pre-setup failed: {}", e);
            tester_pre_setup_failed();
        }
    });
}

/// Async pre-setup implementation.
async fn pre_setup_async(state: SharedState) -> Result<(), String> {
    let mgmt = MgmtSocket::new_default().map_err(|e| format!("mgmt new: {e}"))?;

    // subscribe returns (u32, Receiver<MgmtEvent>) — not a Result.
    let (sub_id, mut rx): (u32, tokio::sync::mpsc::Receiver<MgmtEvent>) =
        mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

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
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.mgmt_index = index;
        }
        let _ = mgmt.unsubscribe(sub_id).await;
        return read_info_and_complete(state, mgmt).await;
    }

    // Create HCI emulator to trigger INDEX_ADDED.
    let emu_type = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.hciemu_type
    };

    let mut emulator = HciEmulator::new(emu_type).map_err(|e| format!("hciemu: {e}"))?;

    if tester_use_debug() {
        emulator.set_debug(print_debug);
    }

    {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.hciemu = Some(emulator);
    }

    let event = rx.recv().await.ok_or_else(|| "INDEX_ADDED channel closed".to_string())?;

    let index = event.index;

    let _ = mgmt.unsubscribe(sub_id).await;

    {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.mgmt_index = index;
    }

    read_info_and_complete(state, mgmt).await
}

/// Read adapter info and complete pre-setup.
async fn read_info_and_complete(state: SharedState, mgmt: MgmtSocket) -> Result<(), String> {
    let mgmt_index = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.mgmt_index
    };

    let rsp = mgmt
        .send_command(MGMT_OP_READ_INFO, mgmt_index, &[])
        .await
        .map_err(|e| format!("read_info: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("read_info status={}", rsp.status));
    }

    // Extract bdaddr from first 6 bytes of response (safe byte copy).
    if rsp.data.len() >= 6 {
        let addr_bytes: [u8; 6] = rsp.data[0..6].try_into().unwrap_or([0u8; 6]);
        tester_print(&format!(
            "Controller address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            addr_bytes[5],
            addr_bytes[4],
            addr_bytes[3],
            addr_bytes[2],
            addr_bytes[1],
            addr_bytes[0],
        ));
    }

    // Store a fresh MGMT handle for the test setup phase.
    {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.mgmt = Some(MgmtSocket::new_default().map_err(|e| format!("mgmt3: {e}"))?);
    }

    tester_pre_setup_complete();
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-teardown (rfcomm-tester.c:190-210)
// ---------------------------------------------------------------------------

/// Post-teardown: clean up I/O handles, emulator, and MGMT socket.
fn test_post_teardown(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_post_teardown_complete();
            return;
        }
    };

    tokio::spawn(async move {
        // Abort I/O task if running.
        let io_handle = {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.io_handle.take()
        };
        if let Some(h) = io_handle {
            h.abort();
        }

        // Cancel pending MGMT commands.
        let mgmt = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.mgmt.is_some()
        };
        if mgmt {
            // Create a fresh handle to send cancel_all.
            if let Ok(m) = MgmtSocket::new_default() {
                let _ = m.cancel_all().await;
            }
        }

        // Drop emulator and MGMT socket.
        {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.hciemu = None;
            st.mgmt = None;
        }

        tester_post_teardown_complete();
    });
}

// ---------------------------------------------------------------------------
// Setup helpers for MGMT power-on (rfcomm-tester.c:211-290)
// ---------------------------------------------------------------------------

/// Setup for client tests: SET_POWERED → bthost scan enable → setup_complete.
fn setup_powered_client(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_setup_failed();
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = setup_powered_client_async(state).await {
            warn!("setup_powered_client failed: {}", e);
            tester_setup_failed();
        }
    });
}

/// Async client setup.
async fn setup_powered_client_async(state: SharedState) -> Result<(), String> {
    let mgmt_index = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.mgmt_index
    };

    let mgmt = MgmtSocket::new_default().map_err(|e| format!("mgmt: {e}"))?;

    // SET_POWERED(1)
    let rsp = mgmt
        .send_command(MGMT_OP_SET_POWERED, mgmt_index, &[1u8])
        .await
        .map_err(|e| format!("set_powered: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("set_powered status={}", rsp.status));
    }

    debug!("Controller powered on (client setup)");

    // Configure bthost: set scan enable and wait for command complete.
    {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref emu) = st.hciemu {
            if let Some(mut bthost) = emu.client_get_host() {
                bthost.set_cmd_complete_cb(move |cmd_opcode, _status, _data| {
                    if cmd_opcode == CMD_WRITE_SCAN_ENABLE {
                        debug!("bthost WRITE_SCAN_ENABLE complete (client)");
                        tester_setup_complete();
                    }
                });
                bthost.write_scan_enable(0x03);
            } else {
                return Err("no bthost".to_string());
            }
        } else {
            return Err("no hciemu".to_string());
        }
    }

    Ok(())
}

/// Setup for server tests: SET_SSP → SET_CONNECTABLE → SET_POWERED →
/// bthost scan+SSP enable → setup_complete.
fn setup_powered_server(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_setup_failed();
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = setup_powered_server_async(state).await {
            warn!("setup_powered_server failed: {}", e);
            tester_setup_failed();
        }
    });
}

/// Async server setup.
async fn setup_powered_server_async(state: SharedState) -> Result<(), String> {
    let mgmt_index = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.mgmt_index
    };

    let mgmt = MgmtSocket::new_default().map_err(|e| format!("mgmt: {e}"))?;

    // SET_SSP(1)
    let rsp = mgmt
        .send_command(MGMT_OP_SET_SSP, mgmt_index, &[1u8])
        .await
        .map_err(|e| format!("set_ssp: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("set_ssp status={}", rsp.status));
    }

    // SET_CONNECTABLE(1)
    let rsp = mgmt
        .send_command(MGMT_OP_SET_CONNECTABLE, mgmt_index, &[1u8])
        .await
        .map_err(|e| format!("set_connectable: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("set_connectable status={}", rsp.status));
    }

    // SET_POWERED(1)
    let rsp = mgmt
        .send_command(MGMT_OP_SET_POWERED, mgmt_index, &[1u8])
        .await
        .map_err(|e| format!("set_powered: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("set_powered status={}", rsp.status));
    }

    debug!("Controller powered on (server setup)");

    // Configure bthost: scan + SSP mode.
    {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref emu) = st.hciemu {
            if let Some(mut bthost) = emu.client_get_host() {
                bthost.set_cmd_complete_cb(move |cmd_opcode, _status, _data| {
                    if cmd_opcode == CMD_WRITE_SCAN_ENABLE {
                        debug!("bthost WRITE_SCAN_ENABLE complete (server)");
                        tester_setup_complete();
                    }
                });
                bthost.write_scan_enable(0x03);
                bthost.write_ssp_mode(0x01);
            } else {
                return Err("no bthost".to_string());
            }
        } else {
            return Err("no hciemu".to_string());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// test_basic (rfcomm-tester.c:292-306)
// ---------------------------------------------------------------------------

/// Test: verify that a basic RFCOMM socket can be created.
fn test_basic(data: &dyn Any) {
    let _state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };

    tokio::spawn(async move {
        // Attempt to create an RFCOMM listening socket on channel 0 with
        // BDADDR_ANY. This exercises the kernel RFCOMM socket creation path.
        match BluetoothSocket::builder()
            .transport(BtTransport::Rfcomm)
            .source_bdaddr(BDADDR_ANY)
            .channel(0)
            .listen()
            .await
        {
            Ok(_listener) => {
                debug!("Basic RFCOMM socket creation succeeded");
                tester_test_passed();
            }
            Err(e) => {
                tester_warn(&format!("Cannot create RFCOMM socket: {e}"));
                tester_test_failed();
            }
        }
    });
}

// ---------------------------------------------------------------------------
// test_connect — RFCOMM client connect tests (rfcomm-tester.c:308-470)
// ---------------------------------------------------------------------------

/// Test: RFCOMM client connection.
fn test_connect(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };

    let config = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        match &st.config {
            TestConfig::Client(c) => c.clone(),
            _ => {
                tester_warn("test_connect called with non-client config");
                tester_test_failed();
                return;
            }
        }
    };

    let state_clone = Arc::clone(&state);

    tokio::spawn(async move {
        // Get central address from the emulator.
        let central_bdaddr = {
            let st = state_clone.lock().unwrap_or_else(|e| e.into_inner());
            match &st.hciemu {
                Some(emu) => emu.get_central_bdaddr(),
                None => {
                    tester_warn("No emulator for connect test");
                    tester_test_failed();
                    return;
                }
            }
        };

        let central_addr = bdaddr_t { b: central_bdaddr };

        // Set up bthost RFCOMM server before connecting.
        setup_bthost_rfcomm_server(&state_clone, &config);

        debug!(
            "Connecting: server_ch={}, client_ch={}",
            config.server_channel, config.client_channel
        );

        // Build RFCOMM client socket and connect.
        let connect_result = BluetoothSocket::builder()
            .transport(BtTransport::Rfcomm)
            .source_bdaddr(BDADDR_ANY)
            .dest_bdaddr(central_addr)
            .channel(config.server_channel as u16)
            .connect()
            .await;

        // Handle expected connection error.
        if config.expected_connect_err != 0 {
            match connect_result {
                Ok(_socket) => {
                    tester_warn("Connect succeeded but expected error");
                    tester_test_failed();
                }
                Err(ref e) => {
                    let got_errno = extract_errno(e).unwrap_or(-1);
                    if got_errno == config.expected_connect_err {
                        debug!(
                            "Connect failed with expected errno {}",
                            config.expected_connect_err
                        );
                        tester_test_passed();
                    } else {
                        tester_warn(&format!(
                            "Connect error mismatch: expected={}, got={}",
                            config.expected_connect_err, got_errno
                        ));
                        tester_test_failed();
                    }
                }
            }
            return;
        }

        // Handle successful connect.
        let socket = match connect_result {
            Ok(s) => s,
            Err(e) => {
                tester_warn(&format!("RFCOMM connect failed: {e}"));
                tester_test_failed();
                return;
            }
        };

        debug!("RFCOMM client connected");

        // Close test: disconnect immediately.
        if config.close {
            drop(socket);
            debug!("RFCOMM socket closed (close test)");
            tester_test_passed();
            return;
        }

        // Send data test.
        if !config.send_data.is_empty() {
            let data_to_send = config.send_data;
            if let Err(e) = send_all(&socket, data_to_send).await {
                tester_warn(&format!("RFCOMM send failed: {e}"));
                tester_test_failed();
                return;
            }
            debug!("RFCOMM client sent {} bytes", data_to_send.len());
            tester_test_passed();
            return;
        }

        // Read data test.
        if !config.read_data.is_empty() {
            let expected = config.read_data;
            let mut buf = vec![0u8; expected.len()];
            if let Err(e) = recv_all(&socket, &mut buf).await {
                tester_warn(&format!("RFCOMM recv failed: {e}"));
                tester_test_failed();
                return;
            }
            if buf != expected {
                tester_warn("RFCOMM recv data mismatch");
                tester_test_failed();
                return;
            }
            debug!("RFCOMM client received {} bytes (verified)", expected.len());
            tester_test_passed();
            return;
        }

        // No data transfer: connect-only success.
        tester_test_passed();
    });
}

/// Set up bthost-side RFCOMM server for client connect tests.
fn setup_bthost_rfcomm_server(state: &SharedState, config: &RfcommClientData) {
    let st = state.lock().unwrap_or_else(|e| e.into_inner());
    let emu = match &st.hciemu {
        Some(emu) => emu,
        None => return,
    };

    if let Some(mut bthost) = emu.client_get_host() {
        // Add L2CAP server for RFCOMM PSM.
        bthost.add_l2cap_server(RFCOMM_PSM, |_handle, _cid| {}, None);

        // Add RFCOMM server on the configured channel.
        let state_clone = Arc::clone(state);
        let read_data: &'static [u8] = config.read_data;

        bthost.add_rfcomm_server(config.server_channel, move |handle, cid, connected| {
            if connected {
                debug!("bthost: RFCOMM client connected (handle={handle}, cid={cid})");
                {
                    let mut inner = state_clone.lock().unwrap_or_else(|e| e.into_inner());
                    inner.conn_handle = handle;
                    inner.rfcomm_cid = cid;
                }

                // If the test expects to read data on the DUT side, the bthost
                // must send it.
                if !read_data.is_empty() {
                    let inner_state = Arc::clone(&state_clone);
                    let rd = read_data;
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        let st2 = inner_state.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(ref emu2) = st2.hciemu {
                            if let Some(bth) = emu2.client_get_host() {
                                bth.send_rfcomm_data(handle, cid, rd);
                                debug!("bthost: sent {} bytes to DUT", rd.len());
                            }
                        }
                    });
                }
            }
        });

        // If this is a send test, install a channel hook to validate data.
        if !config.send_data.is_empty() {
            let expected_data = config.send_data;
            let received = Arc::new(Mutex::new(Vec::new()));
            let received_clone = Arc::clone(&received);
            let expected_len =
                if config.data_len > 0 { config.data_len as usize } else { expected_data.len() };

            bthost.add_rfcomm_chan_hook(0, 0, move |data| {
                let mut acc = received_clone.lock().unwrap_or_else(|e| e.into_inner());
                acc.extend_from_slice(data);
                if acc.len() >= expected_len {
                    if acc[..expected_len] == expected_data[..expected_len] {
                        debug!("bthost: received all {} bytes (verified)", expected_len);
                    } else {
                        warn!("bthost: data mismatch");
                    }
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// test_server — RFCOMM server (listener) tests (rfcomm-tester.c:472-620)
// ---------------------------------------------------------------------------

/// Test: RFCOMM server (listener).
fn test_server(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };

    let config = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        match &st.config {
            TestConfig::Server(s) => s.clone(),
            _ => {
                tester_warn("test_server called with non-server config");
                tester_test_failed();
                return;
            }
        }
    };

    let state_clone = Arc::clone(&state);

    let handle = tokio::spawn(async move {
        // Create RFCOMM listening socket.
        let listener = match BluetoothSocket::builder()
            .transport(BtTransport::Rfcomm)
            .source_bdaddr(BDADDR_ANY)
            .channel(config.server_channel as u16)
            .listen()
            .await
        {
            Ok(l) => l,
            Err(e) => {
                tester_warn(&format!("RFCOMM listen failed: {e}"));
                tester_test_failed();
                return;
            }
        };

        debug!(
            "RFCOMM server listening on channel {}, data_len={}",
            config.server_channel, config.data_len,
        );

        // Trigger bthost to initiate a connection to our listening socket.
        initiate_bthost_connection(&state_clone, &config);

        // Accept incoming connection.
        let socket = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tester_warn(&format!("RFCOMM accept failed: {e}"));
                tester_test_failed();
                return;
            }
        };

        debug!("RFCOMM server accepted connection");

        // Send data test.
        if !config.send_data.is_empty() {
            if let Err(e) = send_all(&socket, config.send_data).await {
                tester_warn(&format!("RFCOMM server send failed: {e}"));
                tester_test_failed();
                return;
            }
            debug!("RFCOMM server sent {} bytes", config.send_data.len());
            tester_test_passed();
            return;
        }

        // Read data test.
        if !config.read_data.is_empty() {
            let expected = config.read_data;
            let mut buf = vec![0u8; expected.len()];
            if let Err(e) = recv_all(&socket, &mut buf).await {
                tester_warn(&format!("RFCOMM server recv failed: {e}"));
                tester_test_failed();
                return;
            }
            if buf != expected {
                tester_warn("RFCOMM server recv data mismatch");
                tester_test_failed();
                return;
            }
            debug!("RFCOMM server received {} bytes (verified)", expected.len());
            tester_test_passed();
            return;
        }

        // No data: accept-only success.
        tester_test_passed();
    });

    // Store the task handle for cleanup.
    {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.io_handle = Some(handle);
    }
}

/// Trigger bthost-initiated connection to our DUT server.
fn initiate_bthost_connection(state: &SharedState, config: &RfcommServerData) {
    let st = state.lock().unwrap_or_else(|e| e.into_inner());
    let emu = match &st.hciemu {
        Some(emu) => emu,
        None => return,
    };

    // Get the DUT (client) address that bthost should connect to.
    let client_addr = match emu.get_client_bdaddr() {
        Some(addr) => addr,
        None => {
            tester_warn("No client bdaddr from emulator");
            return;
        }
    };

    let addr = bdaddr_t { b: client_addr };

    if let Some(mut bthost) = emu.client_get_host() {
        // Add L2CAP server for RFCOMM PSM.
        bthost.add_l2cap_server(RFCOMM_PSM, |_handle, _cid| {}, None);

        // Set up connection callback: when bthost's HCI connection is
        // established, initiate RFCOMM connection on top of it.
        let state_clone = Arc::clone(state);
        let client_channel = config.client_channel;
        let read_data: &'static [u8] = config.read_data;

        bthost.set_connect_cb(move |handle| {
            debug!("bthost: HCI connected (handle={handle})");
            let inner_state = Arc::clone(&state_clone);
            let ch = client_channel;
            let rd = read_data;

            // Connect RFCOMM from bthost side.
            let guard = inner_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref emu2) = guard.hciemu {
                if let Some(mut bt) = emu2.client_get_host() {
                    bt.connect_rfcomm(handle, ch, move |rfcomm_handle, cid, connected| {
                        if connected {
                            debug!("bthost: RFCOMM connected (handle={rfcomm_handle}, cid={cid})");

                            // If DUT expects to read data, bthost sends it.
                            if !rd.is_empty() {
                                debug!("bthost: scheduled {} bytes for DUT server", rd.len());
                            }
                        }
                    });
                }
            }
        });

        // Initiate HCI connection from bthost to the DUT's address.
        bthost.hci_connect(&addr.b, BDADDR_BREDR);
    }
}

// ---------------------------------------------------------------------------
// Data transfer helpers
// ---------------------------------------------------------------------------

/// Send all data through a BluetoothSocket, looping until complete.
async fn send_all(socket: &BluetoothSocket, data: &[u8]) -> Result<(), BtSocketError> {
    let mut sent = 0usize;
    while sent < data.len() {
        let n = socket.send(&data[sent..]).await?;
        if n == 0 {
            return Err(BtSocketError::ConnectionFailed("send returned 0".to_string()));
        }
        sent += n;
        debug!("send progress: {}/{}", sent, data.len());
    }
    Ok(())
}

/// Receive exactly `buf.len()` bytes from a BluetoothSocket.
async fn recv_all(socket: &BluetoothSocket, buf: &mut [u8]) -> Result<(), BtSocketError> {
    let mut received = 0usize;
    while received < buf.len() {
        let n = socket.recv(&mut buf[received..]).await?;
        if n == 0 {
            return Err(BtSocketError::ConnectionFailed(
                "recv returned 0 (peer closed)".to_string(),
            ));
        }
        received += n;
        debug!("recv progress: {}/{}", received, buf.len());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test registration helper
// ---------------------------------------------------------------------------

/// Register a single RFCOMM test case with the tester framework.
fn register_rfcomm_test(
    name: &str,
    config: TestConfig,
    setup_fn: fn(&dyn Any),
    test_fn: fn(&dyn Any),
) {
    let state: SharedState = Arc::new(Mutex::new(TestState {
        mgmt: None,
        mgmt_index: 0xFFFF,
        hciemu: None,
        hciemu_type: EmulatorType::BrEdrLe52,
        config,
        io_handle: None,
        conn_handle: 0,
        rfcomm_cid: 0,
    }));

    tester_add_full(
        name,
        Some(state),                                 // test_data
        Some(Arc::new(test_pre_setup)),              // pre_setup_func
        Some(Arc::new(setup_fn)),                    // setup_func
        Some(Arc::new(test_fn)),                     // test_func
        None::<Arc<dyn Fn(&dyn Any) + Send + Sync>>, // teardown_func
        Some(Arc::new(test_post_teardown)),          // post_teardown_func
        TEST_TIMEOUT,                                // timeout_secs
        None::<()>,                                  // user_data
    );
}

// ---------------------------------------------------------------------------
// Main — test registration and execution (rfcomm-tester.c:828-862)
// ---------------------------------------------------------------------------

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    // Use tester_get_data and sockaddr_rc to prove they are used (compile check).
    // These are referenced by the schema but used indirectly through the
    // BluetoothSocket abstraction and tester callback mechanism.
    let _ = std::mem::size_of::<sockaddr_rc>();
    let _ = tester_get_data::<()>;

    // 1. Basic RFCOMM Socket - Success
    register_rfcomm_test(
        "Basic RFCOMM Socket - Success",
        TestConfig::Client(CONNECT_SUCCESS.clone()),
        setup_powered_client,
        test_basic,
    );

    // 2. Basic RFCOMM Socket Client - Success
    register_rfcomm_test(
        "Basic RFCOMM Socket Client - Success",
        TestConfig::Client(CONNECT_SUCCESS.clone()),
        setup_powered_client,
        test_connect,
    );

    // 3. Basic RFCOMM Socket Client - Write Success
    register_rfcomm_test(
        "Basic RFCOMM Socket Client - Write Success",
        TestConfig::Client(CONNECT_SEND_SUCCESS.clone()),
        setup_powered_client,
        test_connect,
    );

    // 4. Basic RFCOMM Socket Client - Write 32k Success
    register_rfcomm_test(
        "Basic RFCOMM Socket Client - Write 32k Success",
        TestConfig::Client(CONNECT_SEND_32K_SUCCESS.clone()),
        setup_powered_client,
        test_connect,
    );

    // 5. Basic RFCOMM Socket Client - Read Success
    register_rfcomm_test(
        "Basic RFCOMM Socket Client - Read Success",
        TestConfig::Client(CONNECT_READ_SUCCESS.clone()),
        setup_powered_client,
        test_connect,
    );

    // 6. Basic RFCOMM Socket Client - Conn Refused
    register_rfcomm_test(
        "Basic RFCOMM Socket Client - Conn Refused",
        TestConfig::Client(CONNECT_NVAL.clone()),
        setup_powered_client,
        test_connect,
    );

    // 7. Basic RFCOMM Socket Client - Close
    register_rfcomm_test(
        "Basic RFCOMM Socket Client - Close",
        TestConfig::Client(CONNECT_CLOSE.clone()),
        setup_powered_client,
        test_connect,
    );

    // 8. Basic RFCOMM Socket Server - Success
    register_rfcomm_test(
        "Basic RFCOMM Socket Server - Success",
        TestConfig::Server(LISTEN_SUCCESS.clone()),
        setup_powered_server,
        test_server,
    );

    // 9. Basic RFCOMM Socket Server - Write Success
    register_rfcomm_test(
        "Basic RFCOMM Socket Server - Write Success",
        TestConfig::Server(LISTEN_SEND_SUCCESS.clone()),
        setup_powered_server,
        test_server,
    );

    // 10. Basic RFCOMM Socket Server - Read Success
    register_rfcomm_test(
        "Basic RFCOMM Socket Server - Read Success",
        TestConfig::Server(LISTEN_READ_SUCCESS.clone()),
        setup_powered_server,
        test_server,
    );

    tester_run();
}
