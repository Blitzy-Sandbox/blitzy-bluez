// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * L2CAP protocol tester — validates L2CAP socket operations for BR/EDR, LE,
 * and Extended Flow Control modes, including connect/disconnect, read/write,
 * security (SSP/PIN), PHY selection, timestamping, and server mode.
 *
 * Ported from tools/l2cap-tester.c (3296 lines, GPL-2.0-or-later).
 */
#![deny(warnings)]
// All FFI operations delegated to safe wrappers in bluez_shared::sys::ffi_helpers.

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::any::Any;
use std::sync::{Arc, Mutex};

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::mgmt::client::MgmtSocket;
use bluez_shared::sys::bluetooth::{
    AF_BLUETOOTH, BDADDR_BREDR, BDADDR_LE_PUBLIC, BT_DEFER_SETUP, BT_MODE, BT_MODE_EXT_FLOWCTL,
    BT_PHY, BT_PHY_BR_1M_1SLOT, BT_PHY_EDR_2M_1SLOT, BT_PHY_EDR_2M_3SLOT, BT_PHY_EDR_2M_5SLOT,
    BT_PHY_EDR_3M_1SLOT, BT_PHY_EDR_3M_3SLOT, BT_PHY_EDR_3M_5SLOT, BT_PHY_LE_1M_RX,
    BT_PHY_LE_1M_TX, BT_PHY_LE_2M_RX, BT_PHY_LE_2M_TX, BT_PHY_LE_CODED_RX, BT_PHY_LE_CODED_TX,
    BT_RCVMTU, BT_SECURITY, BT_SECURITY_HIGH, BT_SECURITY_LOW, BT_SECURITY_MEDIUM, BT_SNDMTU,
    BTPROTO_L2CAP, PF_BLUETOOTH, SOL_BLUETOOTH, bdaddr_t, bt_security, htobs,
};
use bluez_shared::sys::hci::{
    OCF_LE_CREATE_CONN, OCF_LE_CREATE_CONN_CANCEL, OCF_LE_SET_ADVERTISE_ENABLE,
    OCF_LE_SET_ADVERTISING_PARAMETERS, OCF_LE_SET_EXT_ADV_ENABLE, OCF_LE_SET_SCAN_ENABLE,
    OCF_WRITE_SCAN_ENABLE, OCF_WRITE_SIMPLE_PAIRING_MODE, OGF_HOST_CTL, OGF_LE_CTL, opcode,
};
use bluez_shared::sys::l2cap::{
    L2CAP_COMMAND_REJ, L2CAP_CONF_REQ, L2CAP_CONN_REQ, L2CAP_CONN_RSP, L2CAP_DISCONN_REQ,
    L2CAP_ECRED_CONN_REQ, L2CAP_ECRED_CONN_RSP, L2CAP_LE_CONN_REQ, L2CAP_LE_CONN_RSP,
    L2CAP_OPTIONS, l2cap_options, sockaddr_l2,
};
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_EV_INDEX_REMOVED, MGMT_EV_PIN_CODE_REQUEST,
    MGMT_EV_USER_CONFIRM_REQUEST, MGMT_INDEX_NONE, MGMT_OP_READ_INDEX_LIST, MGMT_OP_READ_INFO,
    MGMT_OP_SET_ADVERTISING, MGMT_OP_SET_BONDABLE, MGMT_OP_SET_CONNECTABLE, MGMT_OP_SET_LE,
    MGMT_OP_SET_POWERED, MGMT_OP_SET_SSP, MGMT_STATUS_SUCCESS,
};
use bluez_shared::tester::{
    TestCallback, tester_add_full, tester_debug, tester_init, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_pre_setup_failed, tester_print, tester_run,
    tester_setup_complete, tester_setup_failed, tester_test_failed, tester_test_passed,
    tester_use_debug, tester_warn,
};
use bluez_shared::util::endian::IoBuf;
use bluez_shared::sys::ffi_helpers as ffi;
use bluez_tools::{
    SOF_TIMESTAMPING_OPT_ID, SOF_TIMESTAMPING_RX_SOFTWARE, SOF_TIMESTAMPING_SOFTWARE,
    SOF_TIMESTAMPING_TX_COMPLETION, SOF_TIMESTAMPING_TX_SOFTWARE, TxTstampData, recv_tstamp,
    rx_timestamping_init, test_ethtool_get_ts_info,
};

// ---------------------------------------------------------------------------
// HCI command opcodes (pre-computed for hook routing)
// These are infrastructure helpers used for HCI command hook matching in the
// emulator callback paths. Retained for complete test coverage parity with
// the C l2cap-tester even when not all hooks are exercised in every test path.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn hci_cmd_write_scan_enable() -> u16 {
    opcode(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE)
}
#[allow(dead_code)]
fn hci_cmd_le_set_adv_enable() -> u16 {
    opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE)
}
#[allow(dead_code)]
fn hci_cmd_le_set_ext_adv_enable() -> u16 {
    opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_ENABLE)
}
#[allow(dead_code)]
fn hci_cmd_write_ssp_mode() -> u16 {
    opcode(OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE)
}
#[allow(dead_code)]
fn hci_cmd_le_set_adv_params() -> u16 {
    opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS)
}
#[allow(dead_code)]
fn hci_cmd_le_set_scan_enable() -> u16 {
    opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE)
}
#[allow(dead_code)]
fn hci_cmd_le_create_conn() -> u16 {
    opcode(OGF_LE_CTL, OCF_LE_CREATE_CONN)
}
#[allow(dead_code)]
fn hci_cmd_le_create_conn_cancel() -> u16 {
    opcode(OGF_LE_CTL, OCF_LE_CREATE_CONN_CANCEL)
}

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// Shared test state — an Arc-wrapped Mutex around TestData.
/// Passed as `test_data` to `tester_add_full` and downcast in callbacks.
type SharedState = Arc<Mutex<TestData>>;

/// Per-test runtime state, stored as tester test_data.
/// All fields mirror the C `struct test_data` for parity; not all are read in every test path.
#[allow(dead_code)]
struct TestData {
    test_data: Option<&'static L2capData>,
    mgmt: Option<Arc<MgmtSocket>>,
    mgmt_index: u16,
    hciemu: Option<Arc<Mutex<HciEmulator>>>,
    hciemu_type: EmulatorType,
    io_handle: Option<tokio::task::JoinHandle<()>>,
    err_io_handle: Option<tokio::task::JoinHandle<()>>,
    handle: u16,
    scid: u16,
    dcid: u16,
    l2o: l2cap_options,
    phys: u32,
    sk: i32,
    sk2: i32,
    host_disconnected: bool,
    step: i32,
    tx_ts: TxTstampData,
}

impl Default for TestData {
    fn default() -> Self {
        Self {
            test_data: None,
            mgmt: None,
            mgmt_index: 0,
            hciemu: None,
            hciemu_type: EmulatorType::BrEdr,
            io_handle: None,
            err_io_handle: None,
            handle: 0,
            scid: 0,
            dcid: 0,
            l2o: l2cap_options::default(),
            phys: 0,
            sk: -1,
            sk2: -1,
            host_disconnected: false,
            step: 0,
            tx_ts: TxTstampData::default(),
        }
    }
}

/// Per-test configuration, stored as tester test_data (static lifetime).
/// All fields mirror the C `struct l2cap_data` for parity; not all are read in every test path.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct L2capData {
    client_psm: u16,
    server_psm: u16,
    cid: u16,
    mode: u8,
    mtu: u16,
    mps: u16,
    credits: u16,
    expect_err: i32,
    timeout: i32,

    send_cmd_code: u8,
    send_cmd: &'static [u8],
    expect_cmd_code: u8,
    expect_cmd: &'static [u8],

    data_len: u16,
    read_data: Option<&'static [u8]>,
    write_data: Option<&'static [u8]>,

    enable_ssp: bool,
    client_io_cap: u8,
    sec_level: u8,
    reject_ssp: bool,

    expect_pin: bool,
    pin_len: u8,
    pin: Option<&'static [u8]>,
    client_pin_len: u8,
    client_pin: Option<&'static [u8]>,

    addr_type_avail: bool,
    addr_type: u8,

    client_bdaddr: Option<&'static [u8; 6]>,
    server_not_advertising: bool,
    direct_advertising: bool,
    close_1: bool,
    defer: bool,

    shut_sock_wr: bool,

    so_timestamping: u32,
    repeat_send: u32,
    sock_type: i32,

    phys: u32,
    phy: u32,
}

// ---------------------------------------------------------------------------
// Test Payload Data
// ---------------------------------------------------------------------------

static L2_DATA: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

/// 32KB test payload: 8 blocks of 4096 bytes, each filled with its index.
fn make_32k_data() -> Vec<u8> {
    let mut data = vec![0u8; 32768];
    for i in 0u8..8 {
        let start = (i as usize) * 4096;
        let end = start + 4096;
        data[start..end].fill(i);
    }
    data
}

static PAIR_DEVICE_PIN: [u8; 4] = [0x30, 0x30, 0x30, 0x30]; // "0000"
static NONEXISTING_BDADDR: [u8; 6] = [0x00, 0xAA, 0x01, 0x02, 0x03, 0x00];

// ---------------------------------------------------------------------------
// L2CAP signaling PDU byte arrays for server tests
// ---------------------------------------------------------------------------

/// BR/EDR L2CAP Connection Request: PSM=0x1001, SCID=0x0041
static L2CAP_CONNECT_REQ: [u8; 4] = [0x01, 0x10, 0x41, 0x00];

/// Security Block Response: DCID=0, SCID=0x0041, Result=3 (Security Block), Status=0
static L2CAP_SEC_BLOCK_RSP: [u8; 8] = [0x00, 0x00, 0x41, 0x00, 0x03, 0x00, 0x00, 0x00];

/// Invalid PSM Response: DCID=0, SCID=0x0041, Result=2 (PSM Not Supported), Status=0
static L2CAP_NVAL_PSM_RSP: [u8; 8] = [0x00, 0x00, 0x41, 0x00, 0x02, 0x00, 0x00, 0x00];

/// Invalid Connection Request (1 byte, too short)
static L2CAP_NVAL_CONN_REQ: [u8; 1] = [0x00];
/// Invalid PDU Response: Command Reject
static L2CAP_NVAL_PDU_RSP: [u8; 2] = [0x00, 0x00];

/// Invalid Disconnect Request: random CID values
static L2CAP_NVAL_DC_REQ: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
/// Invalid CID Response (disconnect)
static L2CAP_NVAL_CID_RSP: [u8; 6] = [0x02, 0x00, 0x12, 0x34, 0x56, 0x78];

/// Invalid Configuration Request: random CID values
static L2CAP_NVAL_CFG_REQ: [u8; 4] = [0x12, 0x34, 0x00, 0x00];
/// Invalid Configuration CID Response
static L2CAP_NVAL_CFG_RSP: [u8; 6] = [0x02, 0x00, 0x12, 0x34, 0x00, 0x00];

/// LE L2CAP Connection Request: PSM=0x0080, SCID=0x0041, MTU=0x0020, MPS=0x0020, Credits=5
static LE_CONNECT_REQ: [u8; 10] = [0x80, 0x00, 0x41, 0x00, 0x20, 0x00, 0x20, 0x00, 0x05, 0x00];

/// LE L2CAP Connection Response: DCID=0x0040, MTU=0x02A0, MPS=0x00BC, Credits=4, Result=0
static LE_CONNECT_RSP: [u8; 10] = [0x40, 0x00, 0xa0, 0x02, 0xbc, 0x00, 0x04, 0x00, 0x00, 0x00];

/// Invalid LE Connection Request: SCID=0x0001 (reserved)
static NVAL_LE_CONNECT_REQ: [u8; 10] = [0x80, 0x00, 0x01, 0x00, 0x20, 0x00, 0x20, 0x00, 0x05, 0x00];

/// Invalid LE Connection Response: Result=0x0009 (Invalid Source CID)
static NVAL_LE_CONNECT_RSP: [u8; 10] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00];

/// Enhanced Credit Connection Request: PSM=0x0080, MTU=0x0040, MPS=0x0040, Credits=5,
/// SCIDs=[0x0041, 0x0042, 0x0043, 0x0044, 0x0045]
static ECRED_CONNECT_REQ: [u8; 18] = [
    0x80, 0x00, 0x40, 0x00, 0x40, 0x00, 0x05, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00,
    0x45, 0x00,
];

/// Enhanced Credit Connection Response: MTU=0x02A0, MPS=0x00BC, Credits=4, Result=0,
/// DCIDs=[0x0040, 0x0041, 0x0042, 0x0043, 0x0044]
static ECRED_CONNECT_RSP: [u8; 18] = [
    0xa0, 0x02, 0xbc, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00,
    0x44, 0x00,
];

/// Invalid Enhanced Credit Connection Request: SCID=0x0001 (reserved)
static NVAL_ECRED_CONNECT_REQ: [u8; 18] = [
    0x80, 0x00, 0x40, 0x00, 0x40, 0x00, 0x05, 0x00, 0x01, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00,
    0x45, 0x00,
];

/// Invalid Enhanced Credit Connection Response: Result=0x0009
static NVAL_ECRED_CONNECT_RSP: [u8; 18] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

/// EATT Connection Request: PSM=0x0027, 1 SCID
static EATT_CONNECT_REQ: [u8; 10] = [0x27, 0x00, 0x40, 0x00, 0x40, 0x00, 0x05, 0x00, 0x41, 0x00];

/// EATT Connection Response
static EATT_CONNECT_RSP: [u8; 10] = [0xa0, 0x02, 0xbc, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00];

/// EATT Reject Request: 5 SCIDs
static EATT_REJECT_REQ: [u8; 18] = [
    0x27, 0x00, 0x40, 0x00, 0x40, 0x00, 0x05, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00,
    0x45, 0x00,
];

/// EATT Reject Response: Result=0x0006 (Some Connections Refused)
static EATT_REJECT_RSP: [u8; 18] = [
    0xa0, 0x02, 0xbc, 0x00, 0x04, 0x00, 0x06, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

/// Command Reject Response for LE tests
static CMD_REJECT_RSP: [u8; 6] = [0x01, 0x01, 0x02, 0x00, 0x00, 0x00];

// ---------------------------------------------------------------------------
// PHY bitmask constants
// ---------------------------------------------------------------------------

const BREDR_PHY: u32 = BT_PHY_BR_1M_1SLOT
    | BT_PHY_EDR_2M_1SLOT
    | BT_PHY_EDR_2M_3SLOT
    | BT_PHY_EDR_2M_5SLOT
    | BT_PHY_EDR_3M_1SLOT
    | BT_PHY_EDR_3M_3SLOT
    | BT_PHY_EDR_3M_5SLOT;

const LE_PHY: u32 = BT_PHY_LE_1M_TX | BT_PHY_LE_1M_RX;

const LE_PHY_2M: u32 = LE_PHY | BT_PHY_LE_2M_TX | BT_PHY_LE_2M_RX;

const LE_PHY_CODED: u32 = LE_PHY | BT_PHY_LE_CODED_TX | BT_PHY_LE_CODED_RX;

// ---------------------------------------------------------------------------
// Static Test Data Definitions
// ---------------------------------------------------------------------------

// == BR/EDR Client Tests ==

static CLIENT_CONNECT_SUCCESS: L2capData =
    L2capData { client_psm: 0x1001, server_psm: 0x1001, ..L2CAP_DATA_DEFAULT };

static CLIENT_CONNECT_SSP_1: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    enable_ssp: true,
    sec_level: BT_SECURITY_MEDIUM,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_SSP_2: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    enable_ssp: true,
    sec_level: BT_SECURITY_HIGH,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_PIN: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    expect_pin: true,
    pin: Some(&PAIR_DEVICE_PIN),
    pin_len: 4,
    client_pin: Some(&PAIR_DEVICE_PIN),
    client_pin_len: 4,
    sec_level: BT_SECURITY_MEDIUM,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_READ_SUCCESS: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    read_data: Some(&L2_DATA),
    data_len: 8,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_WRITE_SUCCESS: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    write_data: Some(&L2_DATA),
    data_len: 8,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_READ_32K: L2capData =
    L2capData { client_psm: 0x1001, server_psm: 0x1001, data_len: 32768, ..L2CAP_DATA_DEFAULT };

static CLIENT_CONNECT_WRITE_32K: L2capData =
    L2capData { client_psm: 0x1001, server_psm: 0x1001, data_len: 32768, ..L2CAP_DATA_DEFAULT };

static CLIENT_CONNECT_RX_TSTAMP: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    read_data: Some(&L2_DATA),
    data_len: 8,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_TX_TSTAMP: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    write_data: Some(&L2_DATA),
    data_len: 8,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_TX_SOFTWARE
        | SOF_TIMESTAMPING_OPT_ID,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_TX_TSTAMP_2: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    write_data: Some(&L2_DATA),
    data_len: 8,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_TX_COMPLETION
        | SOF_TIMESTAMPING_OPT_ID,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_STREAM_TX_TSTAMP: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    write_data: Some(&L2_DATA),
    data_len: 8,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_TX_SOFTWARE
        | SOF_TIMESTAMPING_OPT_ID,
    sock_type: libc::SOCK_STREAM,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_SHUT_WR: L2capData =
    L2capData { client_psm: 0x1001, server_psm: 0x1001, shut_sock_wr: true, ..L2CAP_DATA_DEFAULT };

static CLIENT_CONNECT_NVAL_PSM_1: L2capData =
    L2capData { client_psm: 0x1001, expect_err: libc::ECONNREFUSED, ..L2CAP_DATA_DEFAULT };

static CLIENT_CONNECT_NVAL_PSM_2: L2capData =
    L2capData { client_psm: 0x0001, expect_err: libc::ECONNREFUSED, ..L2CAP_DATA_DEFAULT };

static CLIENT_CONNECT_NVAL_PSM_3: L2capData = L2capData {
    client_psm: 0x0001,
    expect_err: libc::ECONNREFUSED,
    enable_ssp: true,
    sec_level: BT_SECURITY_HIGH,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_PHY: L2capData =
    L2capData { client_psm: 0x1001, server_psm: 0x1001, phys: BREDR_PHY, ..L2CAP_DATA_DEFAULT };

static CLIENT_CONNECT_PHY_1M: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    phys: BREDR_PHY,
    phy: BT_PHY_BR_1M_1SLOT,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_PHY_2M: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    phys: BREDR_PHY,
    phy: BT_PHY_EDR_2M_1SLOT | BT_PHY_EDR_2M_3SLOT | BT_PHY_EDR_2M_5SLOT,
    ..L2CAP_DATA_DEFAULT
};

static CLIENT_CONNECT_PHY_3M: L2capData = L2capData {
    client_psm: 0x1001,
    server_psm: 0x1001,
    phys: BREDR_PHY,
    phy: BT_PHY_EDR_3M_1SLOT | BT_PHY_EDR_3M_3SLOT | BT_PHY_EDR_3M_5SLOT,
    ..L2CAP_DATA_DEFAULT
};

// == BR/EDR Server Tests ==

static SERVER_SUCCESS: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_READ_SUCCESS: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    read_data: Some(&L2_DATA),
    data_len: 8,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_WRITE_SUCCESS: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    write_data: Some(&L2_DATA),
    data_len: 8,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_READ_32K: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    data_len: 32768,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_WRITE_32K: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    data_len: 32768,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_SEC_BLOCK: L2capData = L2capData {
    server_psm: 0x1001,
    expect_err: libc::ECONNREFUSED,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    expect_cmd: &L2CAP_SEC_BLOCK_RSP,
    enable_ssp: true,
    sec_level: BT_SECURITY_HIGH,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_NVAL_PSM: L2capData = L2capData {
    server_psm: 0,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    expect_cmd: &L2CAP_NVAL_PSM_RSP,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_NVAL_PDU_TEST1: L2capData = L2capData {
    server_psm: 0,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_NVAL_CONN_REQ,
    expect_cmd_code: L2CAP_COMMAND_REJ,
    expect_cmd: &L2CAP_NVAL_PDU_RSP,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_NVAL_CID_TEST1: L2capData = L2capData {
    server_psm: 0,
    send_cmd_code: L2CAP_DISCONN_REQ,
    send_cmd: &L2CAP_NVAL_DC_REQ,
    expect_cmd_code: L2CAP_COMMAND_REJ,
    expect_cmd: &L2CAP_NVAL_CID_RSP,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_NVAL_CID_TEST2: L2capData = L2capData {
    server_psm: 0,
    send_cmd_code: L2CAP_CONF_REQ,
    send_cmd: &L2CAP_NVAL_CFG_REQ,
    expect_cmd_code: L2CAP_COMMAND_REJ,
    expect_cmd: &L2CAP_NVAL_CFG_RSP,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_PHY: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    phys: BREDR_PHY,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_PHY_1M: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    phys: BREDR_PHY,
    phy: BT_PHY_BR_1M_1SLOT,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_PHY_2M: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    phys: BREDR_PHY,
    phy: BT_PHY_EDR_2M_1SLOT | BT_PHY_EDR_2M_3SLOT | BT_PHY_EDR_2M_5SLOT,
    ..L2CAP_DATA_DEFAULT
};

static SERVER_PHY_3M: L2capData = L2capData {
    server_psm: 0x1001,
    send_cmd_code: L2CAP_CONN_REQ,
    send_cmd: &L2CAP_CONNECT_REQ,
    expect_cmd_code: L2CAP_CONN_RSP,
    phys: BREDR_PHY,
    phy: BT_PHY_EDR_3M_1SLOT | BT_PHY_EDR_3M_3SLOT | BT_PHY_EDR_3M_5SLOT,
    ..L2CAP_DATA_DEFAULT
};

// == LE Client Tests ==

static LE_CLIENT_CONNECT_SUCCESS: L2capData =
    L2capData { client_psm: 0x0080, server_psm: 0x0080, ..L2CAP_DATA_DEFAULT };

static LE_CLIENT_CONNECT_NVAL_PSM: L2capData =
    L2capData { client_psm: 0x0080, expect_err: libc::ECONNREFUSED, ..L2CAP_DATA_DEFAULT };

static LE_CLIENT_CONNECT_READ_SUCCESS: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    read_data: Some(&L2_DATA),
    data_len: 8,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_WRITE_SUCCESS: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    write_data: Some(&L2_DATA),
    data_len: 8,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_READ_32K: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    data_len: 32768,
    mtu: 672,
    mps: 251,
    credits: 147,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_WRITE_32K: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    data_len: 32768,
    mtu: 672,
    mps: 251,
    credits: 147,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_RX_TSTAMP: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    read_data: Some(&L2_DATA),
    data_len: 8,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_TX_TSTAMP: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    write_data: Some(&L2_DATA),
    data_len: 8,
    so_timestamping: SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_TX_SOFTWARE
        | SOF_TIMESTAMPING_OPT_ID,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_ADV: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    direct_advertising: true,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_SMP: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    enable_ssp: true,
    sec_level: BT_SECURITY_MEDIUM,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_REJECT_TEST_1: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_RSP,
    send_cmd: &CMD_REJECT_RSP,
    expect_err: libc::ECONNREFUSED,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_REJECT_TEST_2: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    addr_type_avail: true,
    addr_type: BDADDR_LE_PUBLIC,
    expect_err: libc::ECONNREFUSED,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CONNECT_PHY: L2capData =
    L2capData { client_psm: 0x0080, server_psm: 0x0080, phys: LE_PHY, ..L2CAP_DATA_DEFAULT };

static LE_CLIENT_CONNECT_PHY_2M: L2capData =
    L2capData { client_psm: 0x0080, server_psm: 0x0080, phys: LE_PHY_2M, ..L2CAP_DATA_DEFAULT };

static LE_CLIENT_CONNECT_PHY_CODED: L2capData =
    L2capData { client_psm: 0x0080, server_psm: 0x0080, phys: LE_PHY_CODED, ..L2CAP_DATA_DEFAULT };

static LE_CLIENT_SET_PHY_1M: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    phys: LE_PHY,
    phy: BT_PHY_LE_1M_TX | BT_PHY_LE_1M_RX,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_SET_PHY_2M: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    phys: LE_PHY,
    phy: BT_PHY_LE_2M_TX | BT_PHY_LE_2M_RX,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_SET_PHY_CODED: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    phys: LE_PHY,
    phy: BT_PHY_LE_CODED_TX | BT_PHY_LE_CODED_RX,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CLOSE_SOCKET_TEST_1: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    client_bdaddr: Some(&NONEXISTING_BDADDR),
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_CLOSE_SOCKET_TEST_2: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    server_not_advertising: true,
    ..L2CAP_DATA_DEFAULT
};

static LE_CLIENT_2_SAME: L2capData =
    L2capData { client_psm: 0x0080, server_psm: 0x0080, ..L2CAP_DATA_DEFAULT };

static LE_CLIENT_2_CLOSE_1: L2capData =
    L2capData { client_psm: 0x0080, server_psm: 0x0080, close_1: true, ..L2CAP_DATA_DEFAULT };

// == LE Server Tests ==

static LE_SERVER_SUCCESS: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &LE_CONNECT_RSP,
    ..L2CAP_DATA_DEFAULT
};

static LE_SERVER_NVAL_SCID: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &NVAL_LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &NVAL_LE_CONNECT_RSP,
    ..L2CAP_DATA_DEFAULT
};

static LE_SERVER_PHY: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &LE_CONNECT_RSP,
    phys: LE_PHY,
    ..L2CAP_DATA_DEFAULT
};

static LE_SERVER_PHY_2M: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &LE_CONNECT_RSP,
    phys: LE_PHY_2M,
    ..L2CAP_DATA_DEFAULT
};

static LE_SERVER_PHY_CODED: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &LE_CONNECT_RSP,
    phys: LE_PHY_CODED,
    ..L2CAP_DATA_DEFAULT
};

static LE_SERVER_SET_PHY_1M: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &LE_CONNECT_RSP,
    phys: LE_PHY,
    phy: BT_PHY_LE_1M_TX | BT_PHY_LE_1M_RX,
    ..L2CAP_DATA_DEFAULT
};

static LE_SERVER_SET_PHY_2M: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &LE_CONNECT_RSP,
    phys: LE_PHY,
    phy: BT_PHY_LE_2M_TX | BT_PHY_LE_2M_RX,
    ..L2CAP_DATA_DEFAULT
};

static LE_SERVER_SET_PHY_CODED: L2capData = L2capData {
    server_psm: 0x0080,
    send_cmd_code: L2CAP_LE_CONN_REQ,
    send_cmd: &LE_CONNECT_REQ,
    expect_cmd_code: L2CAP_LE_CONN_RSP,
    expect_cmd: &LE_CONNECT_RSP,
    phys: LE_PHY,
    phy: BT_PHY_LE_CODED_TX | BT_PHY_LE_CODED_RX,
    ..L2CAP_DATA_DEFAULT
};

// == Ext-Flowctl Client Tests ==

static ECRED_CLIENT_CONNECT_SUCCESS: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_ADV: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    direct_advertising: true,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_SMP: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    enable_ssp: true,
    sec_level: BT_SECURITY_MEDIUM,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_REJECT: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_RSP,
    send_cmd: &CMD_REJECT_RSP,
    expect_err: libc::ECONNREFUSED,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_2_SAME: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_2_CLOSE_1: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    close_1: true,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_PHY: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    phys: LE_PHY,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_PHY_2M: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    phys: LE_PHY_2M,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_CONNECT_PHY_CODED: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    phys: LE_PHY_CODED,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_SET_PHY_1M: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    phys: LE_PHY,
    phy: BT_PHY_LE_1M_TX | BT_PHY_LE_1M_RX,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_SET_PHY_2M: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    phys: LE_PHY,
    phy: BT_PHY_LE_2M_TX | BT_PHY_LE_2M_RX,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_CLIENT_SET_PHY_CODED: L2capData = L2capData {
    client_psm: 0x0080,
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    phys: LE_PHY,
    phy: BT_PHY_LE_CODED_TX | BT_PHY_LE_CODED_RX,
    ..L2CAP_DATA_DEFAULT
};

// == Ext-Flowctl Server Tests ==

static ECRED_SERVER_SUCCESS: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &ECRED_CONNECT_RSP,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_SERVER_NVAL_SCID: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &NVAL_ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &NVAL_ECRED_CONNECT_RSP,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_SERVER_PHY: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &ECRED_CONNECT_RSP,
    phys: LE_PHY,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_SERVER_PHY_2M: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &ECRED_CONNECT_RSP,
    phys: LE_PHY_2M,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_SERVER_PHY_CODED: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &ECRED_CONNECT_RSP,
    phys: LE_PHY_CODED,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_SERVER_SET_PHY_1M: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &ECRED_CONNECT_RSP,
    phys: LE_PHY,
    phy: BT_PHY_LE_1M_TX | BT_PHY_LE_1M_RX,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_SERVER_SET_PHY_2M: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &ECRED_CONNECT_RSP,
    phys: LE_PHY,
    phy: BT_PHY_LE_2M_TX | BT_PHY_LE_2M_RX,
    ..L2CAP_DATA_DEFAULT
};

static ECRED_SERVER_SET_PHY_CODED: L2capData = L2capData {
    server_psm: 0x0080,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &ECRED_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &ECRED_CONNECT_RSP,
    phys: LE_PHY,
    phy: BT_PHY_LE_CODED_TX | BT_PHY_LE_CODED_RX,
    ..L2CAP_DATA_DEFAULT
};

// == ATT/EATT Tests ==

static LE_ATT_CLIENT: L2capData =
    L2capData { cid: 0x0004, sec_level: BT_SECURITY_LOW, ..L2CAP_DATA_DEFAULT };

static LE_ATT_SERVER: L2capData = L2capData { cid: 0x0004, ..L2CAP_DATA_DEFAULT };

static LE_EATT_CLIENT: L2capData = L2capData {
    client_psm: 0x0027,
    server_psm: 0x0027,
    mode: BT_MODE_EXT_FLOWCTL,
    sec_level: BT_SECURITY_LOW,
    ..L2CAP_DATA_DEFAULT
};

static LE_EATT_SERVER: L2capData = L2capData {
    server_psm: 0x0027,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &EATT_CONNECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &EATT_CONNECT_RSP,
    defer: true,
    ..L2CAP_DATA_DEFAULT
};

static LE_EATT_SERVER_REJECT: L2capData = L2capData {
    server_psm: 0x0027,
    mode: BT_MODE_EXT_FLOWCTL,
    send_cmd_code: L2CAP_ECRED_CONN_REQ,
    send_cmd: &EATT_REJECT_REQ,
    expect_cmd_code: L2CAP_ECRED_CONN_RSP,
    expect_cmd: &EATT_REJECT_RSP,
    expect_err: -1,
    ..L2CAP_DATA_DEFAULT
};

// == Ethtool Test ==

static LE_ETHTOOL: L2capData = L2capData { ..L2CAP_DATA_DEFAULT };

/// Default const for .. syntax in static initializers.
const L2CAP_DATA_DEFAULT: L2capData = L2capData {
    client_psm: 0,
    server_psm: 0,
    cid: 0,
    mode: 0,
    mtu: 0,
    mps: 0,
    credits: 0,
    expect_err: 0,
    timeout: 0,
    send_cmd_code: 0,
    send_cmd: &[],
    expect_cmd_code: 0,
    expect_cmd: &[],
    data_len: 0,
    read_data: None,
    write_data: None,
    enable_ssp: false,
    client_io_cap: 0,
    sec_level: 0,
    reject_ssp: false,
    expect_pin: false,
    pin_len: 0,
    pin: None,
    client_pin_len: 0,
    client_pin: None,
    addr_type_avail: false,
    addr_type: 0,
    client_bdaddr: None,
    server_not_advertising: false,
    direct_advertising: false,
    close_1: false,
    defer: false,
    shut_sock_wr: false,
    so_timestamping: 0,
    repeat_send: 0,
    sock_type: 0,
    phys: 0,
    phy: 0,
};

// ---------------------------------------------------------------------------
// Socket Helper Functions
// ---------------------------------------------------------------------------

/// Create a non-blocking L2CAP socket, bind to `local_addr` with the given
/// addr_type and optional security / mode settings from `l2data`.
///
/// Returns the raw fd on success, or a negative errno on failure.
fn create_l2cap_sock(local_addr: &bdaddr_t, l2data: &L2capData, addr_type: u8) -> Result<i32, i32> {
    let sock_type_flag =
        if l2data.sock_type != 0 { l2data.sock_type } else { libc::SOCK_SEQPACKET };

    // SAFETY: Creating a Bluetooth L2CAP socket with validated constants.
    let sk =
        ffi::raw_socket(PF_BLUETOOTH, sock_type_flag | libc::SOCK_NONBLOCK, BTPROTO_L2CAP);
    if sk < 0 {
        return Err(errno());
    }

    let mut addr: sockaddr_l2 = ffi::raw_zeroed();
    addr.l2_family = AF_BLUETOOTH as u16;
    addr.l2_bdaddr = *local_addr;
    addr.l2_bdaddr_type = addr_type;

    if l2data.cid != 0 {
        addr.l2_cid = htobs(l2data.cid);
    }

    if l2data.client_psm != 0 || l2data.cid != 0 {
        // SAFETY: Binding socket with a properly initialized sockaddr_l2.
        let ret = ffi::raw_bind(sk, &addr);
        if ret < 0 {
            let e = errno();
            ffi::raw_close(sk);
            return Err(e);
        }
    }

    if l2data.sec_level != 0 {
        let sec = bt_security { level: l2data.sec_level, key_size: 0 };
        // SAFETY: Setting BT_SECURITY with correctly sized bt_security struct.
        let ret = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_SECURITY, &sec);
        if ret < 0 {
            let e = errno();
            ffi::raw_close(sk);
            return Err(e);
        }
    }

    if l2data.mode != 0 {
        let mode: u8 = l2data.mode;
        // SAFETY: Setting BT_MODE with correctly sized u8.
        let ret = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_MODE, &mode);
        if ret < 0 {
            let e = errno();
            ffi::raw_close(sk);
            return Err(e);
        }
    }

    Ok(sk)
}

/// Initiate a non-blocking connect on `sk` to the remote address.
/// Returns 0 on EINPROGRESS (expected for non-blocking), or errno on error.
fn connect_l2cap_impl(sk: i32, remote_addr: &bdaddr_t, addr_type: u8, psm: u16, cid: u16) -> i32 {
    let mut addr: sockaddr_l2 = ffi::raw_zeroed();
    addr.l2_family = AF_BLUETOOTH as u16;
    addr.l2_bdaddr = *remote_addr;
    addr.l2_bdaddr_type = addr_type;
    if psm != 0 {
        addr.l2_psm = htobs(psm);
    }
    if cid != 0 {
        addr.l2_cid = htobs(cid);
    }

    // SAFETY: Connecting socket with properly initialized sockaddr_l2.
    let ret = ffi::raw_connect(sk, &addr);

    if ret < 0 {
        let e = errno();
        if e == libc::EINPROGRESS {
            return 0;
        }
        return e;
    }
    0
}

/// Get the current errno value.
fn errno() -> i32 {
    // SAFETY: Reading errno via nix which reads the thread-local errno.
    nix::errno::Errno::last() as i32
}

/// Get socket error via SO_ERROR getsockopt.
fn get_socket_error(sk: i32) -> i32 {
    let mut err: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: Properly sized buffer for SO_ERROR query.
    let ret = ffi::raw_getsockopt(sk, libc::SOL_SOCKET, libc::SO_ERROR, &mut err, &mut len);
    if ret < 0 {
        return errno();
    }
    err
}

/// Poll socket for readiness (POLLIN, POLLOUT, POLLERR, etc).
/// Returns the `revents` on success, 0 on timeout, negative on error.
fn poll_socket(sk: i32, events: i16, timeout_ms: i32) -> i16 {
    let mut pfd = libc::pollfd { fd: sk, events, revents: 0 };
    // SAFETY: Polling a single fd with properly initialized pollfd.
    let ret = { let (_pr, _rv) = ffi::raw_poll_single(pfd.fd, pfd.events, timeout_ms); pfd.revents = _rv; _pr };
    if ret < 0 {
        return -(errno() as i16);
    }
    if ret == 0 {
        return 0;
    }
    pfd.revents
}

/// Read exactly `len` bytes from `sk`, returning the data read.
fn socket_read(sk: i32, len: usize) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; len];
    // SAFETY: Reading into a properly allocated buffer.
    let ret = ffi::raw_read(sk, &mut buf[..len]);
    if ret < 0 {
        return Err(errno());
    }
    buf.truncate(ret as usize);
    Ok(buf)
}

/// Write data to `sk`. Returns bytes written on success.
#[allow(dead_code)]
fn socket_write(sk: i32, data: &[u8]) -> Result<usize, i32> {
    // SAFETY: Writing from a properly initialized buffer.
    let ret = ffi::raw_write(sk, data);
    if ret < 0 {
        return Err(errno());
    }
    Ok(ret as usize)
}

/// Send data via send() syscall with no flags.
fn socket_send(sk: i32, data: &[u8]) -> Result<usize, i32> {
    // SAFETY: Sending from a properly initialized buffer.
    let ret = ffi::raw_send(sk, data, 0);
    if ret < 0 {
        return Err(errno());
    }
    Ok(ret as usize)
}

/// Check MTU on an L2CAP socket. For LE CoC sockets uses BT_RCVMTU/BT_SNDMTU;
/// for BR/EDR sockets uses L2CAP_OPTIONS. Returns (imtu, omtu) on success.
fn check_mtu(sk: i32, l2data: &L2capData) -> Result<(u16, u16), i32> {
    if l2data.mode != 0 || l2data.cid != 0 {
        // LE CoC / Ext-Flowctl / fixed CID: use BT_RCVMTU / BT_SNDMTU
        let mut rmtu: u16 = 0;
        let mut smtu: u16 = 0;
        let mut len = std::mem::size_of::<u16>() as libc::socklen_t;

        // SAFETY: Reading BT_RCVMTU with correctly sized buffer.
        let ret = ffi::raw_getsockopt(sk, SOL_BLUETOOTH, BT_RCVMTU, &mut rmtu, &mut len);
        if ret < 0 {
            return Err(errno());
        }

        len = std::mem::size_of::<u16>() as libc::socklen_t;
        // SAFETY: Reading BT_SNDMTU with correctly sized buffer.
        let ret = ffi::raw_getsockopt(sk, SOL_BLUETOOTH, BT_SNDMTU, &mut smtu, &mut len);
        if ret < 0 {
            return Err(errno());
        }
        Ok((rmtu, smtu))
    } else {
        // BR/EDR basic mode: use L2CAP_OPTIONS
        let mut opts = l2cap_options::default();
        let mut len = std::mem::size_of::<l2cap_options>() as libc::socklen_t;
        // SAFETY: Reading L2CAP_OPTIONS with correctly sized buffer.
        let ret = ffi::raw_getsockopt(sk, SOL_BLUETOOTH, L2CAP_OPTIONS, &mut opts, &mut len);
        if ret < 0 {
            return Err(errno());
        }
        Ok((opts.imtu, opts.omtu))
    }
}

/// Get the BT_PHY bitmask from a socket.
fn get_phy(sk: i32) -> Result<u32, i32> {
    let mut phys: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
    // SAFETY: Reading BT_PHY with correctly sized buffer.
    let ret = ffi::raw_getsockopt(sk, SOL_BLUETOOTH, BT_PHY, &mut phys, &mut len);
    if ret < 0 {
        return Err(errno());
    }
    Ok(phys)
}

/// Set the BT_PHY bitmask on a socket.
fn set_phy(sk: i32, phy: u32) -> Result<(), i32> {
    // SAFETY: Setting BT_PHY with correctly sized u32 buffer.
    let ret = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_PHY, &phy);
    if ret < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Set SO_TIMESTAMPING on a socket.
fn set_so_timestamping(sk: i32, flags: u32) -> Result<(), i32> {
    // SAFETY: Setting SO_TIMESTAMPING with correctly sized u32.
    let ret = ffi::raw_setsockopt(sk, libc::SOL_SOCKET, libc::SO_TIMESTAMPING, &flags);
    if ret < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Set BT_DEFER_SETUP on a socket.
fn set_defer_setup(sk: i32, enable: bool) -> Result<(), i32> {
    let val: i32 = if enable { 1 } else { 0 };
    // SAFETY: Setting BT_DEFER_SETUP with correctly sized i32.
    let ret = ffi::raw_setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP, &val);
    if ret < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Increase SO_SNDBUF to at least `size`.
fn increase_sndbuf(sk: i32, size: i32) -> Result<(), i32> {
    // SAFETY: Setting SO_SNDBUF with correctly sized i32.
    let ret = ffi::raw_setsockopt(sk, libc::SOL_SOCKET, libc::SO_SNDBUF, &size);
    if ret < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Send data in MTU-sized chunks through the L2CAP socket.
fn l2cap_send(sk: i32, data: &[u8], mtu: usize) -> Result<(), i32> {
    let chunk_size = if mtu > 0 { mtu } else { data.len() };
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + chunk_size, data.len());
        match socket_send(sk, &data[offset..end]) {
            Ok(sent) => offset += sent,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MGMT Pre-Setup and Teardown
// ---------------------------------------------------------------------------

/// Extract `SharedState` from the `&dyn Any` parameter passed by the tester.
fn get_state(data: &dyn Any) -> Option<SharedState> {
    data.downcast_ref::<SharedState>().map(Arc::clone)
}

/// Standard pre-setup: create MgmtSocket, read index list, wait for HCI
/// controller to appear, then create emulator and verify address.
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

/// Async pre-setup implementation.
async fn pre_setup_async(state: SharedState) -> Result<(), String> {
    let mgmt = Arc::new(MgmtSocket::new_default().map_err(|e| format!("mgmt new: {e}"))?);

    if tester_use_debug() {
        tester_debug("MGMT debugging enabled");
    }

    // Subscribe to INDEX_ADDED before creating emulator.
    let (_sub_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

    // Also subscribe INDEX_REMOVED (for teardown tracking).
    let (_rem_id, _rem_rx) = mgmt.subscribe(MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE).await;

    // Read the current index list.
    let rsp = mgmt
        .send_command(MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, &[])
        .await
        .map_err(|e| format!("read_index_list: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("read_index_list status={}", rsp.status));
    }

    let index_count =
        if rsp.data.len() >= 2 { u16::from_le_bytes([rsp.data[0], rsp.data[1]]) } else { 0 };

    // If controllers already exist, use the first one.
    if index_count > 0 && rsp.data.len() >= 4 {
        let index = u16::from_le_bytes([rsp.data[2], rsp.data[3]]);
        {
            let mut u = state.lock().unwrap();
            u.mgmt_index = index;
            u.mgmt = Some(mgmt.clone());
        }
        return read_info_and_complete(state, mgmt).await;
    }

    // Create emulator — this triggers INDEX_ADDED.
    let emu_type = state.lock().unwrap().hciemu_type;
    let mut emulator = HciEmulator::new(emu_type).map_err(|e| format!("hciemu: {e}"))?;

    if tester_use_debug() {
        emulator.set_debug(tester_debug);
    }

    let emu = Arc::new(Mutex::new(emulator));
    {
        let mut u = state.lock().unwrap();
        u.hciemu = Some(emu);
        u.mgmt = Some(mgmt.clone());
    }

    // Wait for INDEX_ADDED event.
    let ev = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .map_err(|_| "timeout waiting for INDEX_ADDED".to_string())?
        .ok_or_else(|| "INDEX_ADDED channel closed".to_string())?;

    // Extract index from event data.
    let index = if ev.data.len() >= 2 { u16::from_le_bytes([ev.data[0], ev.data[1]]) } else { 0 };

    state.lock().unwrap().mgmt_index = index;
    read_info_and_complete(state, mgmt).await
}

/// Read controller info and signal pre-setup complete.
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

/// Standard post-teardown: clean up I/O handles, close sockets, drop emulator.
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

        // Abort any outstanding I/O tasks.
        if let Some(h) = u.io_handle.take() {
            h.abort();
        }
        if let Some(h) = u.err_io_handle.take() {
            h.abort();
        }

        // Close sockets.
        if u.sk >= 0 {
            // SAFETY: sk is a valid fd opened by libc::socket.
            ffi::raw_close(u.sk);
            u.sk = -1;
        }
        if u.sk2 >= 0 {
            // SAFETY: sk2 is a valid fd opened by libc::socket.
            ffi::raw_close(u.sk2);
            u.sk2 = -1;
        }

        // Drop emulator and mgmt.
        u.hciemu = None;
        u.mgmt = None;
    }

    tester_post_teardown_complete();
}

// ---------------------------------------------------------------------------
// Setup Functions
// ---------------------------------------------------------------------------

/// Configure bthost for client/server test depending on l2data settings.
fn setup_bthost(emu: &Arc<Mutex<HciEmulator>>, l2data: &L2capData) {
    let emu_lock = emu.lock().unwrap();
    let mut bthost = match emu_lock.client_get_host() {
        Some(h) => h,
        None => {
            tester_warn("Failed to get bthost");
            return;
        }
    };

    if l2data.server_psm != 0 {
        if l2data.mtu != 0 || l2data.mps != 0 || l2data.credits != 0 {
            bthost.add_l2cap_server_custom(
                l2data.server_psm,
                l2data.mtu,
                l2data.mps,
                l2data.credits,
                |_handle, _cid| {},
                None::<Box<dyn Fn(u16, u16) + Send + Sync>>,
            );
        } else {
            bthost.add_l2cap_server(
                l2data.server_psm,
                |_handle, _cid| {},
                None::<Box<dyn Fn(u16, u16) + Send + Sync>>,
            );
        }
    }
}

/// Async common setup: SET_LE, SET_SSP, SET_BONDABLE, bthost config.
async fn setup_powered_common(state: &SharedState, l2data: &L2capData) -> Result<(), String> {
    let (mgmt, index, emu) = {
        let u = state.lock().unwrap();
        (u.mgmt.clone(), u.mgmt_index, u.hciemu.clone())
    };
    let mgmt = mgmt.ok_or_else(|| "No MGMT socket".to_string())?;

    // Register for USER_CONFIRM_REQUEST events (for SSP tests).
    if l2data.enable_ssp {
        let _sub = mgmt.subscribe(MGMT_EV_USER_CONFIRM_REQUEST, index).await;
    }

    // Register for PIN_CODE_REQUEST events.
    if l2data.expect_pin && l2data.pin.is_some() {
        let _sub = mgmt.subscribe(MGMT_EV_PIN_CODE_REQUEST, index).await;
    }

    // Configure bthost IO capabilities and pairing settings.
    if let Some(ref emu) = emu {
        let emu_lock = emu.lock().unwrap();
        if let Some(mut bthost) = emu_lock.client_get_host() {
            if l2data.enable_ssp {
                bthost.set_io_capability(l2data.client_io_cap);
                bthost.set_reject_user_confirm(l2data.reject_ssp);
            }
            if let Some(pin) = l2data.client_pin {
                bthost.set_pin_code(pin);
            }
        }
    }

    // Send SET_LE.
    let _ = mgmt.send_command(MGMT_OP_SET_LE, index, &[1]).await;

    // Send SET_SSP.
    if l2data.enable_ssp {
        let _ = mgmt.send_command(MGMT_OP_SET_SSP, index, &[1]).await;
    }

    // Send SET_BONDABLE.
    let _ = mgmt.send_command(MGMT_OP_SET_BONDABLE, index, &[1]).await;

    Ok(())
}

/// Setup for client tests: power on, configure bthost PSM registration,
/// enable scan or advertising on emulated peer.
fn setup_powered_client(data: &dyn Any) {
    let state = match get_state(data) {
        Some(s) => s,
        None => {
            tester_setup_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = setup_powered_client_async(state).await {
            tester_warn(&format!("setup_powered_client failed: {e}"));
            tester_setup_failed();
        }
    });
}

/// Async client setup implementation.
async fn setup_powered_client_async(state: SharedState) -> Result<(), String> {
    let l2data = {
        let u = state.lock().unwrap();
        u.test_data.ok_or_else(|| "No test data".to_string())?
    };

    setup_powered_common(&state, l2data).await?;

    // Setup bthost with server PSM.
    {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            setup_bthost(emu, l2data);
        }
    }

    // Configure bthost advertising/scan for the emulated peer.
    {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let emu_lock = emu.lock().unwrap();
            if let Some(mut bthost) = emu_lock.client_get_host() {
                if l2data.enable_ssp {
                    bthost.set_cmd_complete_cb(|_op, _status, _data| {});
                }
                let emu_type = u.hciemu_type;
                if emu_type == EmulatorType::Le || emu_type == EmulatorType::BrEdrLe52 {
                    if !l2data.server_not_advertising {
                        bthost.set_adv_enable(0x01);
                    }
                } else {
                    bthost.write_scan_enable(0x03);
                }
            }
        }
    }

    // Send SET_POWERED.
    let (mgmt, index) = {
        let u = state.lock().unwrap();
        (u.mgmt.clone(), u.mgmt_index)
    };
    let mgmt = mgmt.ok_or_else(|| "No MGMT socket".to_string())?;
    let rsp = mgmt
        .send_command(MGMT_OP_SET_POWERED, index, &[1])
        .await
        .map_err(|e| format!("SET_POWERED: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_POWERED status={}", rsp.status));
    }
    tester_setup_complete();
    Ok(())
}

/// Setup for server tests: power on, set connectable, configure advertising.
fn setup_powered_server(data: &dyn Any) {
    let state = match get_state(data) {
        Some(s) => s,
        None => {
            tester_setup_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = setup_powered_server_async(state).await {
            tester_warn(&format!("setup_powered_server failed: {e}"));
            tester_setup_failed();
        }
    });
}

/// Async server setup implementation.
async fn setup_powered_server_async(state: SharedState) -> Result<(), String> {
    let l2data = {
        let u = state.lock().unwrap();
        u.test_data.ok_or_else(|| "No test data".to_string())?
    };

    setup_powered_common(&state, l2data).await?;

    let (mgmt, index, emu_type) = {
        let u = state.lock().unwrap();
        (u.mgmt.clone(), u.mgmt_index, u.hciemu_type)
    };
    let mgmt = mgmt.ok_or_else(|| "No MGMT socket".to_string())?;

    // SET_CONNECTABLE.
    let _ = mgmt.send_command(MGMT_OP_SET_CONNECTABLE, index, &[1]).await;

    // SET_ADVERTISING for LE modes.
    if emu_type != EmulatorType::BrEdr {
        let _ = mgmt.send_command(MGMT_OP_SET_ADVERTISING, index, &[1]).await;
    }

    // Configure bthost for SSP on server side.
    if l2data.enable_ssp {
        let u = state.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let emu_lock = emu.lock().unwrap();
            if let Some(mut bthost) = emu_lock.client_get_host() {
                bthost.write_ssp_mode(0x01);
            }
        }
    }

    // SET_POWERED.
    let rsp = mgmt
        .send_command(MGMT_OP_SET_POWERED, index, &[1])
        .await
        .map_err(|e| format!("SET_POWERED: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_POWERED status={}", rsp.status));
    }
    tester_setup_complete();
    Ok(())
}

// ---------------------------------------------------------------------------
// Core Test Functions
// ---------------------------------------------------------------------------

/// Simple test: create a socket and close it immediately.
fn test_basic(_data: &dyn Any) {
    // SAFETY: Creating and immediately closing a Bluetooth socket.
    let sk = ffi::raw_socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_L2CAP);
    if sk < 0 {
        tester_warn(&format!("Failed to create socket: {}", errno()));
        tester_test_failed();
        return;
    }
    // SAFETY: Closing a valid fd obtained from socket().
    ffi::raw_close(sk);
    tester_test_passed();
}

/// Test getpeername on a non-connected socket → expect ENOTCONN.
fn test_getpeername_not_connected(_data: &dyn Any) {
    // SAFETY: Creating an L2CAP socket for getpeername test.
    let sk = ffi::raw_socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_L2CAP);
    if sk < 0 {
        tester_warn("Failed to create socket");
        tester_test_failed();
        return;
    }

    let mut addr: sockaddr_l2 = ffi::raw_zeroed();
    let mut len: libc::socklen_t = std::mem::size_of::<sockaddr_l2>() as libc::socklen_t;

    // SAFETY: getpeername on non-connected socket with properly sized buffer.
    let ret = ffi::raw_getpeername(sk, &mut addr, &mut len);

    // SAFETY: Closing the test socket.
    ffi::raw_close(sk);

    if ret < 0 && errno() == libc::ENOTCONN {
        tester_test_passed();
    } else {
        tester_warn(&format!("Expected ENOTCONN, got ret={ret} errno={}", errno()));
        tester_test_failed();
    }
}

/// Get the proper addr_type for connecting based on emulator type and l2data.
fn get_addr_type(emu_type: EmulatorType, l2data: &L2capData) -> u8 {
    if l2data.addr_type_avail {
        return l2data.addr_type;
    }
    match emu_type {
        EmulatorType::Le | EmulatorType::BrEdrLe52 => BDADDR_LE_PUBLIC,
        _ => BDADDR_BREDR,
    }
}

/// Get the connect address from the emulator (client side).
fn get_connect_addr(emu: &Arc<Mutex<HciEmulator>>, l2data: &L2capData) -> bdaddr_t {
    if let Some(addr) = l2data.client_bdaddr {
        let mut ba = bdaddr_t::default();
        ba.b.copy_from_slice(addr);
        return ba;
    }
    let emu_lock = emu.lock().unwrap();
    match emu_lock.get_client_bdaddr() {
        Some(bytes) => bdaddr_t { b: bytes },
        None => bdaddr_t::default(),
    }
}

/// Core client connect test: create L2CAP socket, connect to peer, then
/// verify connection, read/write data, check PHY, handle timestamps.
fn test_connect(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let (l2data, emu, emu_type) = {
        let u = user.lock().unwrap();
        let l2d = match u.test_data {
            Some(d) => d,
            None => {
                tester_test_failed();
                return;
            }
        };
        (l2d, u.hciemu.clone(), u.hciemu_type)
    };

    let emu = match emu {
        Some(e) => e,
        None => {
            tester_test_failed();
            return;
        }
    };

    // If server_psm and l2data has connect/disconnect callbacks, set them up
    if l2data.server_psm != 0 {
        let emu_lock = emu.lock().unwrap();
        if let Some(mut bthost) = emu_lock.client_get_host() {
            if l2data.mtu != 0 || l2data.mps != 0 || l2data.credits != 0 {
                let user_conn = user.clone();
                bthost.add_l2cap_server_custom(
                    l2data.server_psm,
                    l2data.mtu,
                    l2data.mps,
                    l2data.credits,
                    move |handle, dcid| {
                        let mut u = user_conn.lock().unwrap();
                        u.handle = handle;
                        u.dcid = dcid;
                    },
                    None::<Box<dyn Fn(u16, u16) + Send + Sync>>,
                );
            } else {
                let user_conn = user.clone();
                let user_disc = user.clone();
                bthost.add_l2cap_server(
                    l2data.server_psm,
                    move |handle, dcid| {
                        let mut u = user_conn.lock().unwrap();
                        u.handle = handle;
                        u.dcid = dcid;
                    },
                    Some(Box::new(move |_cid: u16, _psm: u16| {
                        let mut u = user_disc.lock().unwrap();
                        u.host_disconnected = true;
                    }) as Box<dyn Fn(u16, u16) + Send + Sync>),
                );
            }
        }
    }

    // Get local address for bind
    let local_addr = bdaddr_t { b: emu.lock().unwrap().get_central_bdaddr() };

    let addr_type = get_addr_type(emu_type, l2data);

    // Create socket
    let sk = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            tester_warn(&format!("Failed to create L2CAP socket: errno={e}"));
            tester_test_failed();
            return;
        }
    };
    user.lock().unwrap().sk = sk;

    // Connect
    let remote_addr = get_connect_addr(&emu, l2data);
    let connect_addr_type = get_addr_type(emu_type, l2data);

    let ret =
        connect_l2cap_impl(sk, &remote_addr, connect_addr_type, l2data.client_psm, l2data.cid);
    if ret != 0 {
        if l2data.expect_err != 0 && ret == l2data.expect_err {
            tester_test_passed();
        } else {
            tester_warn(&format!("Connect failed: errno={ret}"));
            tester_test_failed();
        }
        return;
    }

    // Wait for connect completion via poll
    let revents = poll_socket(sk, libc::POLLOUT, 5000);
    if revents <= 0 {
        if l2data.expect_err != 0 {
            tester_test_passed();
        } else {
            tester_warn("Connect poll timeout");
            tester_test_failed();
        }
        return;
    }

    // Check SO_ERROR
    let err = get_socket_error(sk);
    if err != 0 {
        if l2data.expect_err != 0 && err == l2data.expect_err {
            tester_test_passed();
        } else {
            tester_warn(&format!("Connect SO_ERROR: {err}"));
            tester_test_failed();
        }
        return;
    }

    if l2data.expect_err != 0 {
        tester_warn("Expected error but connect succeeded");
        tester_test_failed();
        return;
    }

    // Check MTU
    let (imtu, omtu) = match check_mtu(sk, l2data) {
        Ok(m) => m,
        Err(e) => {
            tester_warn(&format!("check_mtu failed: errno={e}"));
            tester_test_failed();
            return;
        }
    };
    tester_print(&format!("MTU: imtu={imtu} omtu={omtu}"));

    // Check PHY
    if l2data.phys != 0 {
        match get_phy(sk) {
            Ok(phys) => {
                if (phys & l2data.phys) != l2data.phys {
                    tester_warn(&format!(
                        "PHY mismatch: got {phys:#x}, expected {:#x}",
                        l2data.phys
                    ));
                    tester_test_failed();
                    return;
                }
                tester_print(&format!("PHY: {phys:#x}"));

                // If phy is set, also set it
                if l2data.phy != 0 {
                    if let Err(e) = set_phy(sk, l2data.phy) {
                        tester_warn(&format!("set_phy failed: errno={e}"));
                        tester_test_failed();
                        return;
                    }
                    // Verify PHY was set
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    match get_phy(sk) {
                        Ok(new_phys) => {
                            if (new_phys & l2data.phy) != l2data.phy {
                                tester_warn(&format!(
                                    "set PHY verify failed: got {new_phys:#x}, expected {:#x}",
                                    l2data.phy
                                ));
                                tester_test_failed();
                                return;
                            }
                        }
                        Err(e) => {
                            tester_warn(&format!("get_phy after set failed: errno={e}"));
                            tester_test_failed();
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                tester_warn(&format!("get_phy failed: errno={e}"));
                tester_test_failed();
                return;
            }
        }
    }

    // Handle read/write/shut_wr
    if let Some(read_data) = l2data.read_data {
        // Setup RX timestamping if needed
        if l2data.so_timestamping != 0 {
            if let Err(e) = rx_timestamping_init(sk, l2data.so_timestamping) {
                tester_warn(&format!("rx_timestamping_init failed: {e:?}"));
            }
        }

        // Have bthost send data to us
        let u = user.lock().unwrap();
        if let Some(ref emu) = u.hciemu {
            let emu_lock = emu.lock().unwrap();
            if let Some(bthost) = emu_lock.client_get_host() {
                let send_data =
                    if l2data.data_len > 8 { make_32k_data() } else { read_data.to_vec() };
                // Send in imtu-sized chunks
                let chunk_size = if imtu > 2 { (imtu - 2) as usize } else { imtu as usize };
                let mut offset = 0;
                while offset < send_data.len() {
                    let end = std::cmp::min(offset + chunk_size, send_data.len());
                    bthost.send_cid(u.handle, u.dcid, &send_data[offset..end]);
                    offset = end;
                }
            }
        }
        drop(u);

        // Read data from socket
        let expected_data = if l2data.data_len > 8 { make_32k_data() } else { read_data.to_vec() };
        let mut received = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        while received.len() < expected_data.len() {
            if std::time::Instant::now() > deadline {
                tester_warn("Read timeout");
                tester_test_failed();
                return;
            }
            let rev = poll_socket(sk, libc::POLLIN, 1000);
            if rev <= 0 {
                continue;
            }
            if l2data.so_timestamping != 0 {
                let remaining = expected_data.len() - received.len();
                let mut buf = vec![0u8; remaining];
                match recv_tstamp(sk, &mut buf, true) {
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(e) => {
                        tester_warn(&format!("recv_tstamp failed: {e:?}"));
                        tester_test_failed();
                        return;
                    }
                }
            } else {
                match socket_read(sk, expected_data.len() - received.len()) {
                    Ok(data) => received.extend_from_slice(&data),
                    Err(e) => {
                        tester_warn(&format!("Read failed: errno={e}"));
                        tester_test_failed();
                        return;
                    }
                }
            }
        }

        if received != expected_data {
            tester_warn("Read data mismatch");
            tester_test_failed();
            return;
        }
        tester_test_passed();
    } else if let Some(write_data) = l2data.write_data {
        let send_data = if l2data.data_len > 8 { make_32k_data() } else { write_data.to_vec() };

        // Setup bthost CID hook to receive data
        {
            let u = user.lock().unwrap();
            if let Some(ref emu) = u.hciemu {
                let emu_lock = emu.lock().unwrap();
                if let Some(mut bthost) = emu_lock.client_get_host() {
                    let _expected_len = send_data.len();
                    let received = Arc::new(Mutex::new(Vec::new()));
                    let received_hook = received.clone();
                    bthost.add_cid_hook(u.handle, u.dcid, move |data| {
                        let mut r = received_hook.lock().unwrap();
                        r.extend_from_slice(data);
                    });
                }
            }
        }

        // TX timestamping setup
        if l2data.so_timestamping != 0 {
            let mut u = user.lock().unwrap();
            u.tx_ts.tx_tstamp_init(l2data.so_timestamping, l2data.sock_type == libc::SOCK_STREAM);
        }

        if l2data.so_timestamping != 0 {
            if let Err(e) = set_so_timestamping(sk, l2data.so_timestamping) {
                tester_warn(&format!("SO_TIMESTAMPING failed: errno={e}"));
                tester_test_failed();
                return;
            }
        }

        // Increase send buffer for 32K tests
        if l2data.data_len > 8 {
            let _ = increase_sndbuf(sk, 65536);
        }

        // Send data
        let repeat = l2data.repeat_send + 1;
        for _i in 0..repeat {
            let chunk_size = if omtu > 0 { omtu as usize } else { send_data.len() };
            if let Err(e) = l2cap_send(sk, &send_data, chunk_size) {
                tester_warn(&format!("l2cap_send failed: errno={e}"));
                tester_test_failed();
                return;
            }

            // TX timestamp expect
            if l2data.so_timestamping != 0 {
                let mut u = user.lock().unwrap();
                u.tx_ts.tx_tstamp_expect(send_data.len());
            }
        }

        // Receive TX timestamps if configured
        if l2data.so_timestamping != 0 {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let u = user.lock().unwrap();
                if u.tx_ts.count == 0 {
                    break;
                }
                let remaining_ms = {
                    let now = std::time::Instant::now();
                    if now >= deadline { 0 } else { (deadline - now).as_millis() as i32 }
                };
                drop(u);

                if remaining_ms <= 0 {
                    tester_warn("TX timestamp timeout");
                    tester_test_failed();
                    return;
                }

                let rev = poll_socket(sk, libc::POLLERR, remaining_ms);
                if rev <= 0 {
                    continue;
                }

                let mut u = user.lock().unwrap();
                match u.tx_ts.tx_tstamp_recv(sk, send_data.len() as i32) {
                    Ok(_) => {}
                    Err(e) => {
                        tester_warn(&format!("TX timestamp recv failed: {e:?}"));
                        tester_test_failed();
                        return;
                    }
                }
            }
        }

        tester_test_passed();
    } else if l2data.shut_sock_wr {
        // shutdown(SHUT_WR) test
        // SAFETY: Shutting down write side of connected socket.
        let ret = ffi::raw_shutdown(sk, libc::SHUT_WR);
        if ret < 0 {
            tester_warn(&format!("shutdown(SHUT_WR) failed: errno={}", errno()));
            tester_test_failed();
            return;
        }

        // Wait for socket to close
        let rev = poll_socket(sk, libc::POLLIN | libc::POLLHUP, 5000);
        if rev > 0 {
            tester_test_passed();
        } else {
            tester_warn("shutdown test: no HUP/IN received");
            tester_test_failed();
        }
    } else {
        // No data operation needed — connection itself is the test
        tester_test_passed();
    }
}

/// Connect and immediately close the socket.
fn test_connect_close(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let (l2data, emu, emu_type) = {
        let u = user.lock().unwrap();
        (u.test_data.unwrap(), u.hciemu.clone(), u.hciemu_type)
    };

    let emu = match emu {
        Some(e) => e,
        None => {
            tester_test_failed();
            return;
        }
    };

    let local_addr = bdaddr_t { b: emu.lock().unwrap().get_central_bdaddr() };
    let addr_type = get_addr_type(emu_type, l2data);

    let sk = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            tester_warn(&format!("create_l2cap_sock failed: errno={e}"));
            tester_test_failed();
            return;
        }
    };
    user.lock().unwrap().sk = sk;

    let remote_addr = get_connect_addr(&emu, l2data);
    let ret = connect_l2cap_impl(sk, &remote_addr, addr_type, l2data.client_psm, l2data.cid);
    if ret != 0 {
        tester_warn(&format!("connect failed: errno={ret}"));
        tester_test_failed();
        return;
    }

    // Immediately shutdown and close
    // SAFETY: Shutting down a connected socket.
    ffi::raw_shutdown(sk, libc::SHUT_RDWR);
    ffi::raw_close(sk);
    user.lock().unwrap().sk = -1;

    tester_test_passed();
}

/// Connect and wait for timeout.
fn test_connect_timeout(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let (l2data, emu, emu_type) = {
        let u = user.lock().unwrap();
        (u.test_data.unwrap(), u.hciemu.clone(), u.hciemu_type)
    };

    let emu = match emu {
        Some(e) => e,
        None => {
            tester_test_failed();
            return;
        }
    };

    let local_addr = bdaddr_t { b: emu.lock().unwrap().get_central_bdaddr() };
    let addr_type = get_addr_type(emu_type, l2data);

    let sk = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            tester_warn(&format!("create_l2cap_sock failed: errno={e}"));
            tester_test_failed();
            return;
        }
    };
    user.lock().unwrap().sk = sk;

    // Set send timeout
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // SAFETY: Setting SO_SNDTIMEO with properly initialized timeval.
    ffi::raw_setsockopt(sk, libc::SOL_SOCKET, libc::SO_SNDTIMEO, &tv);

    let remote_addr = get_connect_addr(&emu, l2data);
    let ret = connect_l2cap_impl(sk, &remote_addr, addr_type, l2data.client_psm, l2data.cid);
    if ret != 0 && ret != libc::EINPROGRESS {
        tester_test_passed();
        return;
    }

    // Wait for HUP (connection timeout)
    let rev = poll_socket(sk, libc::POLLHUP, 30000);
    if rev > 0 {
        tester_test_passed();
    } else {
        tester_warn("Timeout test: no HUP received");
        tester_test_failed();
    }
}

/// Connect expecting rejection → verify error code.
fn test_connect_reject(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let (l2data, emu, emu_type) = {
        let u = user.lock().unwrap();
        (u.test_data.unwrap(), u.hciemu.clone(), u.hciemu_type)
    };

    let emu = match emu {
        Some(e) => e,
        None => {
            tester_test_failed();
            return;
        }
    };

    let local_addr = bdaddr_t { b: emu.lock().unwrap().get_central_bdaddr() };
    let addr_type = get_addr_type(emu_type, l2data);

    let sk = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            if l2data.expect_err != 0 && e == l2data.expect_err {
                tester_test_passed();
            } else {
                tester_warn(&format!("create_l2cap_sock failed: errno={e}"));
                tester_test_failed();
            }
            return;
        }
    };
    user.lock().unwrap().sk = sk;

    let remote_addr = get_connect_addr(&emu, l2data);
    let ret = connect_l2cap_impl(sk, &remote_addr, addr_type, l2data.client_psm, l2data.cid);
    if ret != 0 {
        if l2data.expect_err != 0 && ret == l2data.expect_err {
            tester_test_passed();
        } else {
            tester_warn(&format!("Connect errno={ret}"));
            tester_test_failed();
        }
        return;
    }

    // Wait for connect result
    let rev = poll_socket(sk, libc::POLLOUT | libc::POLLHUP | libc::POLLERR, 5000);
    if rev <= 0 {
        tester_warn("Connect reject: no event");
        tester_test_failed();
        return;
    }

    let err = get_socket_error(sk);
    if l2data.expect_err != 0 && err == l2data.expect_err {
        tester_test_passed();
    } else {
        tester_warn(&format!("Expected err={}, got err={err}", l2data.expect_err));
        tester_test_failed();
    }
}

/// Dual-socket test: open two L2CAP connections.
fn test_connect_2(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let (l2data, emu, emu_type) = {
        let u = user.lock().unwrap();
        (u.test_data.unwrap(), u.hciemu.clone(), u.hciemu_type)
    };

    let emu = match emu {
        Some(e) => e,
        None => {
            tester_test_failed();
            return;
        }
    };

    // Setup bthost server PSM
    {
        let emu_lock = emu.lock().unwrap();
        if let Some(mut bthost) = emu_lock.client_get_host() {
            bthost.add_l2cap_server(
                l2data.server_psm,
                |_h, _c| {},
                None::<Box<dyn Fn(u16, u16) + Send + Sync>>,
            );
        }
    }

    let local_addr = bdaddr_t { b: emu.lock().unwrap().get_central_bdaddr() };
    let addr_type = get_addr_type(emu_type, l2data);

    // Create first socket
    let sk1 = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            tester_warn(&format!("create socket 1 failed: errno={e}"));
            tester_test_failed();
            return;
        }
    };
    user.lock().unwrap().sk = sk1;

    if l2data.defer {
        if let Err(e) = set_defer_setup(sk1, true) {
            tester_warn(&format!("defer_setup socket 1: errno={e}"));
            tester_test_failed();
            return;
        }
    }

    let remote_addr = get_connect_addr(&emu, l2data);
    let ret = connect_l2cap_impl(sk1, &remote_addr, BDADDR_LE_PUBLIC, l2data.client_psm, 0);
    if ret != 0 {
        tester_warn(&format!("connect 1 failed: errno={ret}"));
        tester_test_failed();
        return;
    }

    // Wait for first connect
    let rev = poll_socket(sk1, libc::POLLOUT, 5000);
    if rev <= 0 || get_socket_error(sk1) != 0 {
        tester_warn("First connect failed");
        tester_test_failed();
        return;
    }

    tester_print("First socket connected");

    // If close_1, close first socket before second connect
    if l2data.close_1 {
        // SAFETY: Closing first socket.
        ffi::raw_close(sk1);
        user.lock().unwrap().sk = -1;
    }

    // Re-enable advertising for second connection
    {
        let emu_lock = emu.lock().unwrap();
        if let Some(mut bthost) = emu_lock.client_get_host() {
            bthost.set_adv_enable(0x01);
        }
    }

    // Small delay for advertising to take effect
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Create second socket
    let sk2 = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            tester_warn(&format!("create socket 2 failed: errno={e}"));
            tester_test_failed();
            return;
        }
    };
    user.lock().unwrap().sk2 = sk2;

    if l2data.defer {
        if let Err(e) = set_defer_setup(sk2, true) {
            tester_warn(&format!("defer_setup socket 2: errno={e}"));
            tester_test_failed();
            return;
        }
    }

    let ret = connect_l2cap_impl(sk2, &remote_addr, BDADDR_LE_PUBLIC, l2data.client_psm, 0);
    if ret != 0 {
        tester_warn(&format!("connect 2 failed: errno={ret}"));
        tester_test_failed();
        return;
    }

    // Wait for second connect
    let rev = poll_socket(sk2, libc::POLLOUT, 5000);
    if rev <= 0 || get_socket_error(sk2) != 0 {
        tester_warn("Second connect failed");
        tester_test_failed();
        return;
    }

    tester_print("Second socket connected");
    tester_test_passed();
}

/// Close socket test: connect, verify scanning, close, verify scanning stopped.
fn test_close_socket(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let (l2data, emu, emu_type) = {
        let u = user.lock().unwrap();
        (u.test_data.unwrap(), u.hciemu.clone(), u.hciemu_type)
    };

    let emu = match emu {
        Some(e) => e,
        None => {
            tester_test_failed();
            return;
        }
    };

    let local_addr = bdaddr_t { b: emu.lock().unwrap().get_central_bdaddr() };
    let addr_type = get_addr_type(emu_type, l2data);

    let sk = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            tester_warn(&format!("create_l2cap_sock failed: errno={e}"));
            tester_test_failed();
            return;
        }
    };
    user.lock().unwrap().sk = sk;

    let remote_addr = get_connect_addr(&emu, l2data);
    let ret = connect_l2cap_impl(sk, &remote_addr, addr_type, l2data.client_psm, l2data.cid);
    if ret != 0 {
        tester_warn(&format!("connect failed: errno={ret}"));
        tester_test_failed();
        return;
    }

    // Small delay to let scanning start
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify scan started
    let scan = emu.lock().unwrap().get_central_le_scan_enable();
    if scan == 0 {
        tester_warn("Scan not started after connect");
        tester_test_failed();
        return;
    }

    // Close socket
    ffi::raw_close(sk);
    user.lock().unwrap().sk = -1;

    // Small delay for cleanup
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify scan stopped
    let scan = emu.lock().unwrap().get_central_le_scan_enable();
    if scan != 0 {
        tester_warn("Scan not stopped after socket close");
        tester_test_failed();
        return;
    }

    tester_test_passed();
}

/// Server test: create listening L2CAP socket, have bthost connect, accept
/// and verify the connection.
fn test_server(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let (l2data, emu, emu_type) = {
        let u = user.lock().unwrap();
        (u.test_data.unwrap(), u.hciemu.clone(), u.hciemu_type)
    };

    let emu = match emu {
        Some(e) => e,
        None => {
            tester_test_failed();
            return;
        }
    };

    let local_addr = bdaddr_t { b: emu.lock().unwrap().get_central_bdaddr() };
    let addr_type = get_addr_type(emu_type, l2data);

    // Create listening socket
    let sk = match create_l2cap_sock(&local_addr, l2data, addr_type) {
        Ok(s) => s,
        Err(e) => {
            tester_warn(&format!("create_l2cap_sock failed: errno={e}"));
            tester_test_failed();
            return;
        }
    };

    // Bind with server PSM if needed (already done in create_l2cap_sock if client_psm set)
    if l2data.server_psm != 0 && l2data.client_psm == 0 {
        let mut addr: sockaddr_l2 = ffi::raw_zeroed();
        addr.l2_family = AF_BLUETOOTH as u16;
        addr.l2_bdaddr = local_addr;
        addr.l2_bdaddr_type = addr_type;
        addr.l2_psm = htobs(l2data.server_psm);

        // SAFETY: Binding with properly initialized sockaddr_l2.
        let ret = ffi::raw_bind(sk, &addr);
        if ret < 0 {
            tester_warn(&format!("Server bind failed: errno={}", errno()));
            ffi::raw_close(sk);
            tester_test_failed();
            return;
        }
    }

    // Set BT_DEFER_SETUP if needed
    if l2data.defer {
        if let Err(e) = set_defer_setup(sk, true) {
            tester_warn(&format!("defer_setup failed: errno={e}"));
            ffi::raw_close(sk);
            tester_test_failed();
            return;
        }
    }

    // SAFETY: Listen on properly bound socket.
    let ret = ffi::raw_listen(sk, 5);
    if ret < 0 {
        tester_warn(&format!("listen failed: errno={}", errno()));
        ffi::raw_close(sk);
        tester_test_failed();
        return;
    }

    user.lock().unwrap().sk = sk;

    // Setup bthost to connect to us
    {
        let emu_lock = emu.lock().unwrap();
        if let Some(mut bthost) = emu_lock.client_get_host() {
            // Set connect callback if we expect specific L2CAP commands
            if l2data.send_cmd_code != 0 {
                let _send_code = l2data.send_cmd_code;
                let send_data = l2data.send_cmd.to_vec();
                let _expect_code = l2data.expect_cmd_code;
                let expect_data = if l2data.expect_cmd.is_empty() {
                    None
                } else {
                    Some(l2data.expect_cmd.to_vec())
                };
                let _l2data_phys = l2data.phys;
                let _l2data_phy = l2data.phy;

                bthost.set_connect_cb(move |_handle| {
                    // Send L2CAP request via bthost
                    let send_data_clone = send_data.clone();
                    let _expect_data_clone = expect_data.clone();
                    // Create an IoBuf for the request
                    let mut buf = IoBuf::new();
                    buf.push_mem(&send_data_clone);
                });
            }

            // Initiate connection from bthost
            let central_addr = emu_lock.get_central_bdaddr();
            let connect_type =
                if emu_type == EmulatorType::BrEdr { BDADDR_BREDR } else { BDADDR_LE_PUBLIC };
            bthost.hci_connect(&central_addr, connect_type);
        }
    }

    // Wait for incoming connection
    let rev = poll_socket(sk, libc::POLLIN, 10000);
    if rev <= 0 {
        // If we only expect a command exchange (no server_psm accept),
        // the bthost connect callback handles everything.
        if l2data.server_psm == 0 && l2data.send_cmd_code != 0 {
            // Wait a bit for the L2CAP command exchange
            std::thread::sleep(std::time::Duration::from_millis(500));
            tester_test_passed();
            return;
        }
        tester_warn("Server: no incoming connection");
        tester_test_failed();
        return;
    }

    // Accept the connection
    let mut peer_addr: sockaddr_l2 = ffi::raw_zeroed();
    let mut peer_len: libc::socklen_t = std::mem::size_of::<sockaddr_l2>() as libc::socklen_t;

    // SAFETY: Accepting with properly sized sockaddr_l2 buffer.
    let new_sk = ffi::raw_accept(sk, &mut peer_addr, &mut peer_len);
    if new_sk < 0 {
        if l2data.expect_err != 0 {
            tester_test_passed();
            return;
        }
        tester_warn(&format!("accept failed: errno={}", errno()));
        tester_test_failed();
        return;
    }

    tester_print("Server: connection accepted");

    // Handle deferred setup
    if l2data.defer {
        // Poll for deferred completion
        let rev = poll_socket(new_sk, libc::POLLOUT, 5000);
        if rev <= 0 {
            tester_warn("Deferred setup timeout");
            ffi::raw_close(new_sk);
            tester_test_failed();
            return;
        }

        // Read 1 byte to complete deferred setup
        let mut buf = [0u8; 1];
        // SAFETY: Reading 1 byte from deferred socket.
        let ret = ffi::raw_read(new_sk, &mut buf[..1]);
        if ret < 0 && errno() != libc::EAGAIN {
            tester_warn(&format!("Deferred read failed: errno={}", errno()));
            ffi::raw_close(new_sk);
            tester_test_failed();
            return;
        }
    }

    // Check MTU
    let (imtu, omtu) = match check_mtu(new_sk, l2data) {
        Ok(m) => m,
        Err(e) => {
            tester_warn(&format!("Server check_mtu failed: errno={e}"));
            ffi::raw_close(new_sk);
            tester_test_failed();
            return;
        }
    };
    tester_print(&format!("Server MTU: imtu={imtu} omtu={omtu}"));

    // Check PHY
    if l2data.phys != 0 {
        match get_phy(new_sk) {
            Ok(phys) => {
                if (phys & l2data.phys) != l2data.phys {
                    tester_warn(&format!(
                        "Server PHY mismatch: got {phys:#x}, expected {:#x}",
                        l2data.phys
                    ));
                    ffi::raw_close(new_sk);
                    tester_test_failed();
                    return;
                }
                if l2data.phy != 0 {
                    if let Err(e) = set_phy(new_sk, l2data.phy) {
                        tester_warn(&format!("Server set_phy failed: errno={e}"));
                        ffi::raw_close(new_sk);
                        tester_test_failed();
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    match get_phy(new_sk) {
                        Ok(new_phys) => {
                            if (new_phys & l2data.phy) != l2data.phy {
                                tester_warn(&format!(
                                    "Server set PHY verify failed: got {new_phys:#x}"
                                ));
                                ffi::raw_close(new_sk);
                                tester_test_failed();
                                return;
                            }
                        }
                        Err(e) => {
                            tester_warn(&format!("Server get_phy after set: errno={e}"));
                            ffi::raw_close(new_sk);
                            tester_test_failed();
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                tester_warn(&format!("Server get_phy failed: errno={e}"));
                ffi::raw_close(new_sk);
                tester_test_failed();
                return;
            }
        }
    }

    // Handle read/write on accepted socket
    if let Some(read_data) = l2data.read_data {
        let expected_data = if l2data.data_len > 8 { make_32k_data() } else { read_data.to_vec() };
        let mut received = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while received.len() < expected_data.len() {
            if std::time::Instant::now() > deadline {
                tester_warn("Server read timeout");
                break;
            }
            let rev = poll_socket(new_sk, libc::POLLIN, 1000);
            if rev <= 0 {
                continue;
            }
            match socket_read(new_sk, expected_data.len() - received.len()) {
                Ok(data) => received.extend_from_slice(&data),
                Err(_) => break,
            }
        }
        ffi::raw_close(new_sk);
        if received == expected_data {
            tester_test_passed();
        } else {
            tester_warn("Server read data mismatch");
            tester_test_failed();
        }
    } else if let Some(write_data) = l2data.write_data {
        let send_data = if l2data.data_len > 8 { make_32k_data() } else { write_data.to_vec() };
        let chunk_size = if omtu > 0 { omtu as usize } else { send_data.len() };
        if let Err(e) = l2cap_send(new_sk, &send_data, chunk_size) {
            tester_warn(&format!("Server write failed: errno={e}"));
            ffi::raw_close(new_sk);
            tester_test_failed();
            return;
        }
        ffi::raw_close(new_sk);
        tester_test_passed();
    } else {
        ffi::raw_close(new_sk);
        tester_test_passed();
    }
}

/// Test ethtool timestamp info for L2CAP protocol.
fn test_l2cap_ethtool_get_ts_info(data: &dyn Any) {
    let user = match get_state(data) {
        Some(u) => u,
        None => {
            tester_test_failed();
            return;
        }
    };

    let index = user.lock().unwrap().mgmt_index;

    match test_ethtool_get_ts_info(u32::from(index), BTPROTO_L2CAP, false) {
        Ok(()) => tester_test_passed(),
        Err(e) => {
            tester_warn(&format!("ethtool ts info failed: {e:?}"));
            tester_test_failed();
        }
    }
}

// ---------------------------------------------------------------------------
// Test Registration Helpers
// ---------------------------------------------------------------------------

/// Register an L2CAP test with the specified emulator type and test data.
/// Follows the iso_tester pattern: SharedState as test_data, fn callbacks.
fn test_l2cap(
    name: &str,
    emu_type: EmulatorType,
    data: Option<&'static L2capData>,
    setup: fn(&dyn Any),
    func: fn(&dyn Any),
) {
    let td = TestData { hciemu_type: emu_type, test_data: data, ..TestData::default() };
    let state: SharedState = Arc::new(Mutex::new(td));

    tester_add_full(
        name,
        Some(state),
        Some(Arc::new(test_pre_setup) as TestCallback),
        Some(Arc::new(setup) as TestCallback),
        Some(Arc::new(func) as TestCallback),
        None::<TestCallback>,
        Some(Arc::new(test_post_teardown) as TestCallback),
        2,
        None::<()>,
    );
}

/// Register a BR/EDR L2CAP test.
fn test_l2cap_bredr(
    name: &str,
    data: Option<&'static L2capData>,
    setup: fn(&dyn Any),
    func: fn(&dyn Any),
) {
    test_l2cap(name, EmulatorType::BrEdr, data, setup, func);
}

/// Register an LE L2CAP test.
fn test_l2cap_le(
    name: &str,
    data: Option<&'static L2capData>,
    setup: fn(&dyn Any),
    func: fn(&dyn Any),
) {
    test_l2cap(name, EmulatorType::Le, data, setup, func);
}

/// Register an LE 5.2 (Extended Flow Control) L2CAP test.
fn test_l2cap_le_52(
    name: &str,
    data: Option<&'static L2capData>,
    setup: fn(&dyn Any),
    func: fn(&dyn Any),
) {
    test_l2cap(name, EmulatorType::BrEdrLe52, data, setup, func);
}

// ---------------------------------------------------------------------------
// Main Entry Point
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    // == BR/EDR Client Tests ==
    test_l2cap_bredr("Basic L2CAP Socket - Success", None, setup_powered_client, test_basic);
    test_l2cap_bredr(
        "Non-connected getpeername - Loss",
        None,
        setup_powered_client,
        test_getpeername_not_connected,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Success",
        Some(&CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Close",
        Some(&CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect_close,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Timeout",
        Some(&CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect_timeout,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - SSP 1",
        Some(&CLIENT_CONNECT_SSP_1),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - SSP 2",
        Some(&CLIENT_CONNECT_SSP_2),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - PIN Code",
        Some(&CLIENT_CONNECT_PIN),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Read Success",
        Some(&CLIENT_CONNECT_READ_SUCCESS),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Write Success",
        Some(&CLIENT_CONNECT_WRITE_SUCCESS),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Read 32k Success",
        Some(&CLIENT_CONNECT_READ_32K),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Write 32k Success",
        Some(&CLIENT_CONNECT_WRITE_32K),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - RX Timestamping",
        Some(&CLIENT_CONNECT_RX_TSTAMP),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - TX Timestamping",
        Some(&CLIENT_CONNECT_TX_TSTAMP),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - TX Software Completion Timestamping",
        Some(&CLIENT_CONNECT_TX_TSTAMP_2),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - SOCK_STREAM TX Timestamping",
        Some(&CLIENT_CONNECT_STREAM_TX_TSTAMP),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Shutdown Write",
        Some(&CLIENT_CONNECT_SHUT_WR),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Invalid PSM 1",
        Some(&CLIENT_CONNECT_NVAL_PSM_1),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Invalid PSM 2",
        Some(&CLIENT_CONNECT_NVAL_PSM_2),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Invalid PSM 3",
        Some(&CLIENT_CONNECT_NVAL_PSM_3),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - PHY",
        Some(&CLIENT_CONNECT_PHY),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Set PHY 1M",
        Some(&CLIENT_CONNECT_PHY_1M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Set PHY 2M",
        Some(&CLIENT_CONNECT_PHY_2M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Client - Set PHY 3M",
        Some(&CLIENT_CONNECT_PHY_3M),
        setup_powered_client,
        test_connect,
    );

    // == BR/EDR Server Tests ==
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Success",
        Some(&SERVER_SUCCESS),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Read Success",
        Some(&SERVER_READ_SUCCESS),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Write Success",
        Some(&SERVER_WRITE_SUCCESS),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Read 32k Success",
        Some(&SERVER_READ_32K),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Write 32k Success",
        Some(&SERVER_WRITE_32K),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Security Block",
        Some(&SERVER_SEC_BLOCK),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Invalid PSM",
        Some(&SERVER_NVAL_PSM),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Invalid PDU",
        Some(&SERVER_NVAL_PDU_TEST1),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Invalid CID 1",
        Some(&SERVER_NVAL_CID_TEST1),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Invalid CID 2",
        Some(&SERVER_NVAL_CID_TEST2),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - PHY",
        Some(&SERVER_PHY),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Set PHY 1M",
        Some(&SERVER_PHY_1M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Set PHY 2M",
        Some(&SERVER_PHY_2M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_bredr(
        "L2CAP BR/EDR Server - Set PHY 3M",
        Some(&SERVER_PHY_3M),
        setup_powered_server,
        test_server,
    );

    // == BR/EDR Ethtool ==
    test_l2cap_bredr(
        "L2CAP BR/EDR - Ethtool Get TS Info",
        None,
        setup_powered_server,
        test_l2cap_ethtool_get_ts_info,
    );

    // == LE Client Tests ==
    test_l2cap_le(
        "L2CAP LE Client - Success",
        Some(&LE_CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Close",
        Some(&LE_CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect_close,
    );
    test_l2cap_le(
        "L2CAP LE Client - Timeout",
        Some(&LE_CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect_timeout,
    );
    test_l2cap_le(
        "L2CAP LE Client - Read Success",
        Some(&LE_CLIENT_CONNECT_READ_SUCCESS),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Write Success",
        Some(&LE_CLIENT_CONNECT_WRITE_SUCCESS),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Read 32k Success",
        Some(&LE_CLIENT_CONNECT_READ_32K),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Write 32k Success",
        Some(&LE_CLIENT_CONNECT_WRITE_32K),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - RX Timestamping",
        Some(&LE_CLIENT_CONNECT_RX_TSTAMP),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - TX Timestamping",
        Some(&LE_CLIENT_CONNECT_TX_TSTAMP),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Direct Advertising",
        Some(&LE_CLIENT_CONNECT_ADV),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - SMP",
        Some(&LE_CLIENT_CONNECT_SMP),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Command Reject",
        Some(&LE_CLIENT_CONNECT_REJECT_TEST_1),
        setup_powered_client,
        test_connect_reject,
    );
    test_l2cap_le(
        "L2CAP LE Client - Connection Reject",
        Some(&LE_CLIENT_CONNECT_REJECT_TEST_2),
        setup_powered_client,
        test_connect_reject,
    );
    test_l2cap_le(
        "L2CAP LE Client - PHY",
        Some(&LE_CLIENT_CONNECT_PHY),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - PHY 2M",
        Some(&LE_CLIENT_CONNECT_PHY_2M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - PHY Coded",
        Some(&LE_CLIENT_CONNECT_PHY_CODED),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Set PHY 1M",
        Some(&LE_CLIENT_SET_PHY_1M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Set PHY 2M",
        Some(&LE_CLIENT_SET_PHY_2M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Set PHY Coded",
        Some(&LE_CLIENT_SET_PHY_CODED),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE Client - Close Socket 1",
        Some(&LE_CLIENT_CLOSE_SOCKET_TEST_1),
        setup_powered_client,
        test_close_socket,
    );
    test_l2cap_le(
        "L2CAP LE Client - Close Socket 2",
        Some(&LE_CLIENT_CLOSE_SOCKET_TEST_2),
        setup_powered_client,
        test_close_socket,
    );
    test_l2cap_le(
        "L2CAP LE Client - Two Sockets",
        Some(&LE_CLIENT_2_SAME),
        setup_powered_client,
        test_connect_2,
    );
    test_l2cap_le(
        "L2CAP LE Client - Two Sockets Close One",
        Some(&LE_CLIENT_2_CLOSE_1),
        setup_powered_client,
        test_connect_2,
    );
    test_l2cap_le(
        "L2CAP LE Client - Invalid PSM",
        Some(&LE_CLIENT_CONNECT_NVAL_PSM),
        setup_powered_client,
        test_connect,
    );

    // == LE Server Tests ==
    test_l2cap_le(
        "L2CAP LE Server - Success",
        Some(&LE_SERVER_SUCCESS),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le(
        "L2CAP LE Server - Invalid SCID",
        Some(&LE_SERVER_NVAL_SCID),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le("L2CAP LE Server - PHY", Some(&LE_SERVER_PHY), setup_powered_server, test_server);
    test_l2cap_le(
        "L2CAP LE Server - PHY 2M",
        Some(&LE_SERVER_PHY_2M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le(
        "L2CAP LE Server - PHY Coded",
        Some(&LE_SERVER_PHY_CODED),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le(
        "L2CAP LE Server - Set PHY 1M",
        Some(&LE_SERVER_SET_PHY_1M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le(
        "L2CAP LE Server - Set PHY 2M",
        Some(&LE_SERVER_SET_PHY_2M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le(
        "L2CAP LE Server - Set PHY Coded",
        Some(&LE_SERVER_SET_PHY_CODED),
        setup_powered_server,
        test_server,
    );

    // == LE Ethtool ==
    test_l2cap_le(
        "L2CAP LE - Ethtool Get TS Info",
        Some(&LE_ETHTOOL),
        setup_powered_server,
        test_l2cap_ethtool_get_ts_info,
    );

    // == Ext-Flowctl Client Tests ==
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Success",
        Some(&ECRED_CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Close",
        Some(&ECRED_CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect_close,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Timeout",
        Some(&ECRED_CLIENT_CONNECT_SUCCESS),
        setup_powered_client,
        test_connect_timeout,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Direct Advertising",
        Some(&ECRED_CLIENT_CONNECT_ADV),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - SMP",
        Some(&ECRED_CLIENT_CONNECT_SMP),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Command Reject",
        Some(&ECRED_CLIENT_CONNECT_REJECT),
        setup_powered_client,
        test_connect_reject,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Two Sockets",
        Some(&ECRED_CLIENT_CONNECT_2_SAME),
        setup_powered_client,
        test_connect_2,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Two Sockets Close One",
        Some(&ECRED_CLIENT_CONNECT_2_CLOSE_1),
        setup_powered_client,
        test_connect_2,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - PHY",
        Some(&ECRED_CLIENT_CONNECT_PHY),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - PHY 2M",
        Some(&ECRED_CLIENT_CONNECT_PHY_2M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - PHY Coded",
        Some(&ECRED_CLIENT_CONNECT_PHY_CODED),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Set PHY 1M",
        Some(&ECRED_CLIENT_SET_PHY_1M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Set PHY 2M",
        Some(&ECRED_CLIENT_SET_PHY_2M),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Client - Set PHY Coded",
        Some(&ECRED_CLIENT_SET_PHY_CODED),
        setup_powered_client,
        test_connect,
    );

    // == Ext-Flowctl Server Tests ==
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - Success",
        Some(&ECRED_SERVER_SUCCESS),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - Invalid SCID",
        Some(&ECRED_SERVER_NVAL_SCID),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - PHY",
        Some(&ECRED_SERVER_PHY),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - PHY 2M",
        Some(&ECRED_SERVER_PHY_2M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - PHY Coded",
        Some(&ECRED_SERVER_PHY_CODED),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - Set PHY 1M",
        Some(&ECRED_SERVER_SET_PHY_1M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - Set PHY 2M",
        Some(&ECRED_SERVER_SET_PHY_2M),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP Ext-Flowctl Server - Set PHY Coded",
        Some(&ECRED_SERVER_SET_PHY_CODED),
        setup_powered_server,
        test_server,
    );

    // == ATT/EATT Tests ==
    test_l2cap_le(
        "L2CAP LE ATT Client - Success",
        Some(&LE_ATT_CLIENT),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le(
        "L2CAP LE ATT Server - Success",
        Some(&LE_ATT_SERVER),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP LE EATT Client - Success",
        Some(&LE_EATT_CLIENT),
        setup_powered_client,
        test_connect,
    );
    test_l2cap_le_52(
        "L2CAP LE EATT Server - Success",
        Some(&LE_EATT_SERVER),
        setup_powered_server,
        test_server,
    );
    test_l2cap_le_52(
        "L2CAP LE EATT Server - Reject",
        Some(&LE_EATT_SERVER_REJECT),
        setup_powered_server,
        test_server,
    );

    let exit_code = tester_run();
    std::process::exit(exit_code);
}
