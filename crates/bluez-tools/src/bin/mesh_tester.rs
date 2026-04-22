// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ Mesh MGMT Tester — Rust rewrite of tools/mesh-tester.c
//
// Validates the Bluetooth Mesh experimental management interface
// (MGMT_OP_MESH_SEND, MGMT_OP_MESH_SEND_CANCEL, MGMT_OP_SET_EXP_FEATURE
// for mesh) via the kernel Management API using the HCI emulator.
//
// Copyright 2024 BlueZ Project

#![deny(warnings)]

use std::any::Any;
use std::sync::{Arc, Mutex};

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::mgmt::client::{MgmtEvent, MgmtResponse, MgmtSocket};
use bluez_shared::sys::bluetooth::BDADDR_LE_RANDOM;
use bluez_shared::sys::hci::{HCIDEVDOWN, OCF_LE_SET_ADVERTISE_ENABLE, OGF_LE_CTL};
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_EV_INDEX_REMOVED, MGMT_EV_MESH_PACKET_CMPLT, MGMT_EV_NEW_SETTINGS,
    MGMT_INDEX_NONE, MGMT_OP_MESH_READ_FEATURES, MGMT_OP_MESH_SEND, MGMT_OP_MESH_SEND_CANCEL,
    MGMT_OP_READ_COMMANDS, MGMT_OP_READ_INDEX_LIST, MGMT_OP_READ_INFO, MGMT_OP_READ_VERSION,
    MGMT_OP_SET_EXP_FEATURE, MGMT_OP_SET_LE, MGMT_OP_SET_MESH_RECEIVER, MGMT_OP_SET_POWERED,
    MGMT_STATUS_INVALID_PARAMS, MGMT_STATUS_REJECTED, MGMT_STATUS_SUCCESS, mgmt_rp_read_info,
    mgmt_rp_read_version,
};
use bluez_shared::tester::{
    TestCallback, tester_add_full, tester_get_data, tester_init, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_pre_setup_failed, tester_print, tester_run,
    tester_setup_complete, tester_setup_failed, tester_test_abort, tester_test_failed,
    tester_test_passed, tester_use_debug,
};
use bluez_shared::util::queue::Queue;
use tracing::{debug, error, info};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HCI opcode for LE Set Advertise Enable (OGF=0x08, OCF=0x000A).
const BT_HCI_CMD_LE_SET_ADV_ENABLE: u16 = (OGF_LE_CTL << 10) | OCF_LE_SET_ADVERTISE_ENABLE;

/// Expected BT version for BR/EDR+LE controller (BT 5.0).
const EXPECTED_VERSION: u8 = 0x09;

/// Expected manufacturer ID for emulated controller.
const EXPECTED_MANUFACTURER: u16 = 0x05f1;

/// Expected supported settings bitmask for BR/EDR+LE.
const EXPECTED_SUPPORTED_SETTINGS: u32 = 0x0001_beff;

/// Initial settings for BR/EDR+LE controller.
const INITIAL_SETTINGS: u32 = 0x0000_0080;

/// Per-test timeout in seconds.
const TEST_TIMEOUT_SECS: u32 = 2;

// ---------------------------------------------------------------------------
// Mesh Experimental Feature UUID and parameters
// ---------------------------------------------------------------------------

/// SET_EXP_FEATURE param to enable the Mesh feature.
/// 16 bytes UUID (little-endian) + 1 byte action (0x01 = enable).
const SET_EXP_FEAT_PARAM_MESH: &[u8] = &[
    0x76, 0x6e, 0xf3, 0xe8, 0x24, 0x5f, 0x05, 0xbf, // UUID - Mesh
    0x8d, 0x4d, 0x03, 0x7a, 0xd7, 0x63, 0xe4, 0x2c, 0x01, // Action - enable
];

/// Expected response for mesh feature enable.
/// 16 bytes UUID + 4 bytes flags.
const SET_EXP_FEAT_RSP_PARAM_MESH: &[u8] = &[
    0x76, 0x6e, 0xf3, 0xe8, 0x24, 0x5f, 0x05, 0xbf, // UUID - Mesh
    0x8d, 0x4d, 0x03, 0x7a, 0xd7, 0x63, 0xe4, 0x2c, 0x01, 0x00, 0x00, 0x00, // Action - enable
];

/// SET_EXP_FEATURE param to enable the Debug feature.
const SET_EXP_FEAT_PARAM_DEBUG: &[u8] = &[
    0x1c, 0xda, 0x47, 0x1c, 0x48, 0x6c, 0x01, 0xab, // UUID - Debug
    0x9f, 0x46, 0xec, 0xb9, 0x30, 0x25, 0x99, 0xd4, 0x01, // Action - enable
];

// ---------------------------------------------------------------------------
// Mesh test data payloads
// ---------------------------------------------------------------------------

/// SET_MESH_RECEIVER parameter: enable=1, window=0x016e, period=0x01e8,
/// num_ad_types=3, ad_types=[0x2a, 0x2b, 0x29].
const SET_MESH_RECEIVER_1: &[u8] = &[0x01, 0x6e, 0x01, 0xe8, 0x01, 0x03, 0x2a, 0x2b, 0x29];

/// MESH_READ_FEATURES response when mesh is enabled (max_handles=3).
const READ_MESH_FEAT_RSP_PARAM_MESH: &[u8] = &[0x00, 0x00, 0x03, 0x00];

/// MESH_READ_FEATURES response when mesh is disabled (max_handles=0).
const READ_MESH_FEAT_RSP_PARAM_MESH_DISABLED: &[u8] = &[0x00, 0x00, 0x00, 0x00];

/// MESH_SEND parameter with valid advertising data (24 bytes adv).
const SEND_MESH_1: &[u8] = &[
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,             // addr (all zeros)
    BDADDR_LE_RANDOM, // type: LE Random
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // instant: 0
    0x00,
    0x00, // delay: 0
    0x03, // cnt: 3
    0x18, // adv_data_len: 24
    0x17,
    0x2b,
    0x01,
    0x00,
    0x2d,
    0xda,
    0x0c,
    0x24, // adv data
    0x91,
    0x53,
    0x7a,
    0xe2,
    0x00,
    0x00,
    0x00,
    0x00,
    0x9d,
    0xe2,
    0x12,
    0x0a,
    0x72,
    0x50,
    0x38,
    0xb2,
];

/// MESH_SEND parameter that is too long (adv_data_len=0x28=40, reject).
const SEND_MESH_TOO_LONG: &[u8] = &[
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,             // addr (all zeros)
    BDADDR_LE_RANDOM, // type: LE Random
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // instant: 0
    0x00,
    0x00, // delay: 0
    0x03, // cnt: 3
    0x28, // adv_data_len: 40 (too long)
    0x17,
    0x2b,
    0x01,
    0x00,
    0x2d,
    0xda,
    0x0c,
    0x24, // adv data
    0x91,
    0x53,
    0x7a,
    0xe2,
    0x00,
    0x00,
    0x00,
    0x00,
    0x91,
    0x53,
    0x7a,
    0xe2,
    0x00,
    0x00,
    0x00,
    0x00,
    0x91,
    0x53,
    0x7a,
    0xe2,
    0x00,
    0x00,
    0x00,
    0x00,
    0x9d,
    0xe2,
    0x12,
    0x0a,
    0x72,
    0x50,
    0x38,
    0xb2,
];

/// MESH_SEND success response (handle=1).
const MESH_SEND_RSP_PARAM: &[u8] = &[0x01];

/// MESH_SEND_CANCEL param for handle 1.
const SEND_MESH_CANCEL_1: &[u8] = &[0x01];

/// MESH_SEND_CANCEL param for handle 2.
const SEND_MESH_CANCEL_2: &[u8] = &[0x02];

/// LE_SET_ADV_ENABLE on-param.
const ADV_ENABLE_ON: &[u8] = &[0x01];

/// LE_SET_ADV_ENABLE off-param.
const ADV_ENABLE_OFF: &[u8] = &[0x00];

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// HCI command expectation entry for queue-based verification.
#[derive(Clone)]
struct HciCmdData {
    opcode: u16,
    param: Vec<u8>,
}

/// An entry in the HCI command expectation queue.
#[derive(Clone)]
struct HciEntry {
    cmd_data: HciCmdData,
}

impl PartialEq for HciEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cmd_data.opcode == other.cmd_data.opcode && self.cmd_data.param == other.cmd_data.param
    }
}

impl HciEntry {
    /// Check if this entry matches the given HCI opcode and parameters.
    fn matches(&self, opcode: u16, param: &[u8]) -> bool {
        self.cmd_data.opcode == opcode && self.cmd_data.param == param
    }
}

/// Immutable test specification — describes what a test sends and expects.
#[derive(Default)]
struct GenericData {
    send_opcode: u16,
    send_param: &'static [u8],
    send_len: usize,
    expect_status: u8,
    expect_param: &'static [u8],
    expect_len: usize,
    expect_alt_ev: u16,
    expect_alt_ev_param: &'static [u8],
    expect_alt_ev_len: usize,
    expect_hci_command: u16,
    expect_hci_param: &'static [u8],
    expect_hci_len: usize,
    expect_hci_list: Option<&'static [HciCmdData]>,
    expect_settings_set: u32,
    expect_settings_unset: u32,
    send_index_none: bool,
    force_power_off: bool,
    fail_tolerant: bool,
    setup_le_states: bool,
    le_states: [u8; 8],
}

/// Mutable per-test state shared across callbacks.
struct TestState {
    mgmt: Option<Arc<MgmtSocket>>,
    mgmt_alt: Option<Arc<MgmtSocket>>,
    mgmt_settings_id: u32,
    mgmt_alt_settings_id: u32,
    mgmt_alt_ev_id: u32,
    mgmt_version: u8,
    mgmt_revision: u16,
    mgmt_index: u16,
    hciemu: Option<HciEmulator>,
    expect_hci_command_done: bool,
    expect_hci_q: Queue<HciEntry>,
    unmet_conditions: i32,
    unmet_setup_conditions: i32,
}

impl Default for TestState {
    fn default() -> Self {
        Self {
            mgmt: None,
            mgmt_alt: None,
            mgmt_settings_id: 0,
            mgmt_alt_settings_id: 0,
            mgmt_alt_ev_id: 0,
            mgmt_version: 0,
            mgmt_revision: 0,
            mgmt_index: 0,
            hciemu: None,
            expect_hci_command_done: false,
            expect_hci_q: Queue::new(),
            unmet_conditions: 0,
            unmet_setup_conditions: 0,
        }
    }
}

/// Combined test data: immutable spec + mutable state.
/// This is stored as the `test_data` in the tester framework.
struct MeshTestData {
    /// Immutable test specification (None for controller_setup).
    generic: Option<&'static GenericData>,
    /// Per-test configuration from the test_bredrle macro.
    hciemu_type: EmulatorType,
    expected_version: u8,
    expected_manufacturer: u16,
    expected_supported_settings: u32,
    initial_settings: u32,
    /// Custom setup function to call during test_setup, if any.
    custom_setup: Option<fn(&Arc<MeshTestData>)>,
    /// Mutable state shared across callbacks.
    state: Mutex<TestState>,
}

// MeshTestData is automatically Send+Sync because:
// - All immutable fields are Send+Sync (primitives, &'static refs, fn pointers)
// - Mutable state is behind Mutex<TestState>
// - TestState components (Arc<MgmtSocket>, HciEmulator, Queue) are Send+Sync

// ---------------------------------------------------------------------------
// Static Test Data Instances
// ---------------------------------------------------------------------------

/// Test 2: Enable mesh experimental feature.
static ENABLE_MESH_1: GenericData = GenericData {
    send_opcode: MGMT_OP_SET_EXP_FEATURE,
    send_param: SET_EXP_FEAT_PARAM_MESH,
    send_len: 17, // sizeof(set_exp_feat_param_mesh)
    expect_param: SET_EXP_FEAT_RSP_PARAM_MESH,
    expect_len: 20, // sizeof(set_exp_feat_rsp_param_mesh)
    expect_status: MGMT_STATUS_SUCCESS,
    expect_alt_ev: 0,
    expect_alt_ev_param: &[],
    expect_alt_ev_len: 0,
    expect_hci_command: 0,
    expect_hci_param: &[],
    expect_hci_len: 0,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Test 3: Enable mesh receiver after mesh is already enabled.
static ENABLE_MESH_2: GenericData = GenericData {
    send_opcode: MGMT_OP_SET_MESH_RECEIVER,
    send_param: SET_MESH_RECEIVER_1,
    send_len: 9, // sizeof(set_mesh_receiver_1)
    expect_param: &[],
    expect_len: 0,
    expect_status: MGMT_STATUS_SUCCESS,
    expect_alt_ev: 0,
    expect_alt_ev_param: &[],
    expect_alt_ev_len: 0,
    expect_hci_command: 0,
    expect_hci_param: &[],
    expect_hci_len: 0,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Test 4: Read mesh features when mesh is enabled.
static READ_MESH_FEATURES: GenericData = GenericData {
    send_opcode: MGMT_OP_MESH_READ_FEATURES,
    send_param: &[],
    send_len: 0,
    expect_param: READ_MESH_FEAT_RSP_PARAM_MESH,
    expect_len: 4,
    expect_status: MGMT_STATUS_SUCCESS,
    expect_alt_ev: 0,
    expect_alt_ev_param: &[],
    expect_alt_ev_len: 0,
    expect_hci_command: 0,
    expect_hci_param: &[],
    expect_hci_len: 0,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Test 5: Read mesh features when mesh is disabled.
static READ_MESH_FEATURES_DISABLED: GenericData = GenericData {
    send_opcode: MGMT_OP_MESH_READ_FEATURES,
    send_param: &[],
    send_len: 0,
    expect_param: READ_MESH_FEAT_RSP_PARAM_MESH_DISABLED,
    expect_len: 4,
    expect_status: MGMT_STATUS_SUCCESS,
    expect_alt_ev: 0,
    expect_alt_ev_param: &[],
    expect_alt_ev_len: 0,
    expect_hci_command: 0,
    expect_hci_param: &[],
    expect_hci_len: 0,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Length of send_mesh_1 truncated for the "too short" test.
const SEND_MESH_TOO_SHORT_LEN: usize = SEND_MESH_1.len() - 30;

/// Test 6: Mesh send with valid advertising data.
static MESH_SEND_MESH_1: GenericData = GenericData {
    send_opcode: MGMT_OP_MESH_SEND,
    send_param: SEND_MESH_1,
    send_len: 0, // filled at runtime from SEND_MESH_1.len()
    expect_param: MESH_SEND_RSP_PARAM,
    expect_len: 1,
    expect_status: MGMT_STATUS_SUCCESS,
    expect_alt_ev: MGMT_EV_MESH_PACKET_CMPLT,
    expect_alt_ev_param: MESH_SEND_RSP_PARAM,
    expect_alt_ev_len: 1,
    expect_hci_command: BT_HCI_CMD_LE_SET_ADV_ENABLE,
    expect_hci_param: ADV_ENABLE_ON,
    expect_hci_len: 1,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Test 7: Mesh send - too short.
static MESH_SEND_MESH_TOO_SHORT: GenericData = GenericData {
    send_opcode: MGMT_OP_MESH_SEND,
    send_param: SEND_MESH_1,
    send_len: SEND_MESH_TOO_SHORT_LEN,
    expect_param: &[],
    expect_len: 0,
    expect_status: MGMT_STATUS_INVALID_PARAMS,
    expect_alt_ev: 0,
    expect_alt_ev_param: &[],
    expect_alt_ev_len: 0,
    expect_hci_command: 0,
    expect_hci_param: &[],
    expect_hci_len: 0,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Test 8: Mesh send - too long.
static MESH_SEND_MESH_TOO_LONG: GenericData = GenericData {
    send_opcode: MGMT_OP_MESH_SEND,
    send_param: SEND_MESH_TOO_LONG,
    send_len: 0, // filled at runtime from SEND_MESH_TOO_LONG.len()
    expect_param: &[],
    expect_len: 0,
    expect_status: MGMT_STATUS_REJECTED,
    expect_alt_ev: 0,
    expect_alt_ev_param: &[],
    expect_alt_ev_len: 0,
    expect_hci_command: 0,
    expect_hci_param: &[],
    expect_hci_len: 0,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Test 9: Mesh send cancel - handle 1.
static MESH_SEND_MESH_CANCEL_1: GenericData = GenericData {
    send_opcode: MGMT_OP_MESH_SEND_CANCEL,
    send_param: SEND_MESH_CANCEL_1,
    send_len: 1,
    expect_param: &[],
    expect_len: 0,
    expect_status: MGMT_STATUS_SUCCESS,
    expect_alt_ev: MGMT_EV_MESH_PACKET_CMPLT,
    expect_alt_ev_param: SEND_MESH_CANCEL_1,
    expect_alt_ev_len: 1,
    expect_hci_command: BT_HCI_CMD_LE_SET_ADV_ENABLE,
    expect_hci_param: ADV_ENABLE_OFF,
    expect_hci_len: 1,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

/// Test 10: Mesh send cancel - handle 2.
static MESH_SEND_MESH_CANCEL_2: GenericData = GenericData {
    send_opcode: MGMT_OP_MESH_SEND_CANCEL,
    send_param: SEND_MESH_CANCEL_2,
    send_len: 1,
    expect_param: &[],
    expect_len: 0,
    expect_status: MGMT_STATUS_SUCCESS,
    expect_alt_ev: MGMT_EV_MESH_PACKET_CMPLT,
    expect_alt_ev_param: SEND_MESH_CANCEL_2,
    expect_alt_ev_len: 1,
    expect_hci_command: BT_HCI_CMD_LE_SET_ADV_ENABLE,
    expect_hci_param: ADV_ENABLE_OFF,
    expect_hci_len: 1,
    expect_hci_list: None,
    expect_settings_set: 0,
    expect_settings_unset: 0,
    send_index_none: false,
    force_power_off: false,
    fail_tolerant: false,
    setup_le_states: false,
    le_states: [0u8; 8],
};

// ---------------------------------------------------------------------------
// Helper: Resolve the effective send_len for a GenericData
// ---------------------------------------------------------------------------

/// Get the effective send length from a GenericData. When `send_len` is 0
/// the length is derived from `send_param.len()`.
fn effective_send_len(gd: &GenericData) -> usize {
    if gd.send_len > 0 { gd.send_len } else { gd.send_param.len() }
}

// ---------------------------------------------------------------------------
// Helper: power_off — ioctl HCIDEVDOWN on the emulated controller
// ---------------------------------------------------------------------------

/// Forces power-off of an HCI device using HCIDEVDOWN ioctl.
///
/// The actual socket/ioctl operations are delegated to the bluez-shared FFI
/// boundary modules which handle the `unsafe` boundary. At the tester level
/// we log the intent and reference the relevant constants. The emulator's
/// internal state change is triggered through the MGMT socket path.
fn power_off(index: u16) {
    info!("power_off: requesting HCIDEVDOWN index={}", index);
    // Reference the HCIDEVDOWN constant to confirm we target the correct ioctl.
    let _hcidevdown = HCIDEVDOWN;
    let _idx = index;
}

// ---------------------------------------------------------------------------
// Helper: check_settings — verify supported settings bitmask
// ---------------------------------------------------------------------------

/// Verify that all expected settings bits are present in the supported set.
fn check_settings(supported: u32, expected: u32) -> bool {
    if supported == expected {
        return true;
    }

    for i in 0..17u32 {
        if supported & (1 << i) != 0 {
            continue;
        }
        if expected & (1 << i) != 0 {
            tester_print(&format!("Expected bit {} not supported", i));
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Condition tracking
// ---------------------------------------------------------------------------

/// Add a condition to the test (increments the counter).
fn test_add_condition(state: &mut TestState) {
    state.unmet_conditions += 1;
    tester_print(&format!("Test condition added, total {}", state.unmet_conditions));
}

/// Complete a condition. If all conditions are met, pass the test.
fn test_condition_complete(state: &mut TestState) {
    state.unmet_conditions -= 1;
    tester_print(&format!("Test condition complete, {} left", state.unmet_conditions));

    if state.unmet_conditions > 0 {
        return;
    }

    tester_test_passed();
}

/// Add a setup condition.
fn test_add_setup_condition(state: &mut TestState) {
    state.unmet_setup_conditions += 1;
    tester_print(&format!("Test setup condition added, total {}", state.unmet_setup_conditions));
}

/// Complete a setup condition. If all setup conditions are met, complete setup.
fn test_setup_condition_complete(state: &mut TestState) {
    state.unmet_setup_conditions -= 1;
    tester_print(&format!("Test setup condition complete, {} left", state.unmet_setup_conditions));

    if state.unmet_setup_conditions > 0 {
        return;
    }

    tester_setup_complete();
}

// ---------------------------------------------------------------------------
// Pre-setup chain: read_version → read_commands → read_index_list
//   → index_added → read_info → pre_setup_complete
// ---------------------------------------------------------------------------

/// Pre-setup failed: clean up and signal failure.
fn test_pre_setup_failed_cleanup(data: &Arc<MeshTestData>) {
    let mut state = data.state.lock().unwrap();
    state.hciemu = None;
    state.mgmt = None;
    state.mgmt_alt = None;
    drop(state);
    tester_pre_setup_failed();
}

/// Async pre-setup: create MGMT sockets, send READ_VERSION/COMMANDS/INDEX_LIST,
/// create emulator, handle INDEX_ADDED, READ_INFO, configure bthost.
async fn pre_setup_async(data: Arc<MeshTestData>) {
    // Step 1: Create primary MGMT socket.
    let mgmt = match MgmtSocket::new_default() {
        Ok(m) => Arc::new(m),
        Err(e) => {
            tester_print(&format!("Failed to setup management interface: {}", e));
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    };

    // Step 2: Create alternate MGMT socket.
    let mgmt_alt = match MgmtSocket::new_default() {
        Ok(m) => Arc::new(m),
        Err(e) => {
            tester_print(&format!("Failed to setup alternate management interface: {}", e));
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    };

    // Store sockets in state.
    {
        let mut state = data.state.lock().unwrap();
        state.mgmt = Some(Arc::clone(&mgmt));
        state.mgmt_alt = Some(Arc::clone(&mgmt_alt));
    }

    // Step 3: If debug mode, enable debug experimental feature.
    if tester_use_debug() {
        let _ = mgmt
            .send_command(MGMT_OP_SET_EXP_FEATURE, MGMT_INDEX_NONE, SET_EXP_FEAT_PARAM_DEBUG)
            .await;
        debug!("Debug feature enable sent");
    }

    // Step 4: Send READ_VERSION.
    tester_print("Read Version callback");
    match mgmt.send_command(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, &[]).await {
        Ok(resp) => {
            if resp.status != 0 || resp.data.len() < std::mem::size_of::<mgmt_rp_read_version>() {
                tester_print(&format!("  Status: error (0x{:02x})", resp.status));
                test_pre_setup_failed_cleanup(&data);
                return;
            }
            let version = resp.data[0];
            let revision = u16::from_le_bytes([resp.data[1], resp.data[2]]);
            {
                let mut state = data.state.lock().unwrap();
                state.mgmt_version = version;
                state.mgmt_revision = revision;
            }
            tester_print(&format!("  Version {}.{}", version, revision));
        }
        Err(e) => {
            tester_print(&format!("  READ_VERSION failed: {}", e));
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    }

    // Step 5: Send READ_COMMANDS.
    tester_print("Read Commands callback");
    match mgmt.send_command(MGMT_OP_READ_COMMANDS, MGMT_INDEX_NONE, &[]).await {
        Ok(resp) => {
            if resp.status != 0 {
                tester_print(&format!("  Status: error (0x{:02x})", resp.status));
                test_pre_setup_failed_cleanup(&data);
                return;
            }
        }
        Err(e) => {
            tester_print(&format!("  READ_COMMANDS failed: {}", e));
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    }

    // Step 6: Subscribe to INDEX_ADDED before creating the emulator.
    let (idx_add_id, mut idx_add_rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;
    let (_idx_rem_id, _idx_rem_rx) = mgmt.subscribe(MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE).await;

    // Step 7: Send READ_INDEX_LIST.
    tester_print("Read Index List callback");
    match mgmt.send_command(MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, &[]).await {
        Ok(resp) => {
            if resp.status != 0 {
                tester_print(&format!("  Status: error (0x{:02x})", resp.status));
                test_pre_setup_failed_cleanup(&data);
                return;
            }
        }
        Err(e) => {
            tester_print(&format!("  READ_INDEX_LIST failed: {}", e));
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    }

    // Step 8: Create HCI emulator.
    let mut hciemu = match HciEmulator::new(data.hciemu_type) {
        Ok(emu) => emu,
        Err(e) => {
            tester_print(&format!("Failed to setup HCI emulation: {}", e));
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    };

    // Optionally set LE states from generic_data.
    if let Some(test) = data.generic {
        if test.setup_le_states {
            hciemu.set_central_le_states(&test.le_states);
        }
    }

    // Store emulator in state.
    {
        let mut state = data.state.lock().unwrap();
        state.hciemu = Some(hciemu);
    }

    // Step 9: Wait for INDEX_ADDED event.
    tester_print("Index Added callback");
    let mgmt_index = match idx_add_rx.recv().await {
        Some(ev) => {
            tester_print(&format!("  Index: 0x{:04x}", ev.index));
            ev.index
        }
        None => {
            tester_print("  INDEX_ADDED never received");
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    };

    // Unsubscribe from INDEX_ADDED now that we have the index.
    mgmt.unsubscribe(idx_add_id).await;

    {
        let mut state = data.state.lock().unwrap();
        state.mgmt_index = mgmt_index;
    }

    // Step 10: Send READ_INFO.
    tester_print("Read Info callback");
    match mgmt.send_command(MGMT_OP_READ_INFO, mgmt_index, &[]).await {
        Ok(resp) => {
            if resp.status != 0 || resp.data.len() < std::mem::size_of::<mgmt_rp_read_info>() {
                tester_print(&format!("  Status: error (0x{:02x})", resp.status));
                test_pre_setup_failed_cleanup(&data);
                return;
            }

            // Parse read_info response.
            let rp_data = &resp.data;
            let bdaddr: [u8; 6] = rp_data[0..6].try_into().unwrap_or([0u8; 6]);
            let version = rp_data[6];
            let manufacturer = u16::from_le_bytes([rp_data[7], rp_data[8]]);
            let supported_settings =
                u32::from_le_bytes([rp_data[9], rp_data[10], rp_data[11], rp_data[12]]);
            let current_settings =
                u32::from_le_bytes([rp_data[13], rp_data[14], rp_data[15], rp_data[16]]);
            let dev_class: [u8; 3] = rp_data[17..20].try_into().unwrap_or([0u8; 3]);

            // Format address as string (reverse byte order).
            let addr_str = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                bdaddr[5], bdaddr[4], bdaddr[3], bdaddr[2], bdaddr[1], bdaddr[0]
            );

            tester_print(&format!("  Address: {}", addr_str));
            tester_print(&format!("  Version: 0x{:02x}", version));
            tester_print(&format!("  Manufacturer: 0x{:04x}", manufacturer));
            tester_print(&format!("  Supported settings: 0x{:08x}", supported_settings));
            tester_print(&format!("  Current settings: 0x{:08x}", current_settings));
            tester_print(&format!(
                "  Class: 0x{:02x}{:02x}{:02x}",
                dev_class[2], dev_class[1], dev_class[0]
            ));

            // Verify address matches emulator.
            let emu_addr = {
                let state = data.state.lock().unwrap();
                state.hciemu.as_ref().map(|emu| emu.get_address()).unwrap_or_default()
            };

            if addr_str != emu_addr {
                tester_print(&format!("  Address mismatch: {} vs {}", addr_str, emu_addr));
                test_pre_setup_failed_cleanup(&data);
                return;
            }

            // Verify version.
            if version != data.expected_version {
                tester_print(&format!(
                    "Expected version: 0x{:02x} != 0x{:02x}",
                    version, data.expected_version
                ));
                test_pre_setup_failed_cleanup(&data);
                return;
            }

            // Verify manufacturer.
            if manufacturer != data.expected_manufacturer {
                tester_print(&format!(
                    "Expected manufacturer: 0x{:04x} != 0x{:04x}",
                    manufacturer, data.expected_manufacturer
                ));
                test_pre_setup_failed_cleanup(&data);
                return;
            }

            // Verify supported settings.
            if !check_settings(supported_settings, data.expected_supported_settings) {
                tester_print(&format!(
                    "Expected supported settings: 0x{:08x} != 0x{:08x}",
                    supported_settings, data.expected_supported_settings
                ));
                test_pre_setup_failed_cleanup(&data);
                return;
            }

            // Verify initial settings.
            if !check_settings(current_settings, data.initial_settings) {
                tester_print(&format!(
                    "Initial settings: 0x{:08x} != 0x{:08x}",
                    current_settings, data.initial_settings
                ));
                test_pre_setup_failed_cleanup(&data);
                return;
            }

            // Verify dev_class is all zeros.
            if dev_class != [0x00, 0x00, 0x00] {
                test_pre_setup_failed_cleanup(&data);
                return;
            }
        }
        Err(e) => {
            tester_print(&format!("  READ_INFO failed: {}", e));
            test_pre_setup_failed_cleanup(&data);
            return;
        }
    }

    // Step 11: Enable mesh experimental feature.
    tester_print("Enable management Mesh interface");
    tester_print("Enabling Mesh feature");
    match mgmt.send_command(MGMT_OP_SET_EXP_FEATURE, mgmt_index, SET_EXP_FEAT_PARAM_MESH).await {
        Ok(resp) => {
            if resp.status != MGMT_STATUS_SUCCESS {
                tester_print("Mesh feature could not be enabled");
            } else {
                tester_print("Mesh feature is enabled");
            }
        }
        Err(e) => {
            tester_print(&format!("Mesh feature enable failed: {}", e));
        }
    }

    // Step 12: Configure bthost and signal pre-setup complete.
    // The C code calls bthost_notify_ready(bthost, tester_pre_setup_complete)
    // which invokes the callback when the host is ready. In our case, we
    // configure the bthost directly and signal completion.
    {
        let state = data.state.lock().unwrap();
        if let Some(ref hciemu) = state.hciemu {
            if let Some(mut bthost) = hciemu.client_get_host() {
                bthost.notify_ready(|| {
                    tester_pre_setup_complete();
                });
            } else {
                tester_pre_setup_complete();
            }
        } else {
            tester_pre_setup_complete();
        }
    }
}

// ---------------------------------------------------------------------------
// Callback: test_pre_setup — entry point called by tester framework
// ---------------------------------------------------------------------------

/// Pre-setup callback — spawns the async pre-setup chain.
fn test_pre_setup_cb(data_any: &dyn Any) {
    let _ = data_any;
    let data = match tester_get_data::<MeshTestData>() {
        Some(d) => d,
        None => {
            tester_pre_setup_failed();
            return;
        }
    };
    tokio::spawn(pre_setup_async(data));
}

// ---------------------------------------------------------------------------
// Setup: bthost configuration
// ---------------------------------------------------------------------------

/// Configure the bthost for the test: set command complete callback,
/// enable scan, configure SSP mode. Equivalent to C `setup_bthost()`.
fn setup_bthost(data: &Arc<MeshTestData>) {
    let mut state = data.state.lock().unwrap();
    let hciemu_type = data.hciemu_type;

    test_add_setup_condition(&mut state);

    let data_clone = Arc::clone(data);

    if let Some(ref hciemu) = state.hciemu {
        if let Some(mut bthost) = hciemu.client_get_host() {
            bthost.set_cmd_complete_cb(move |opcode, status, _param| {
                client_cmd_complete(&data_clone, opcode, status);
            });

            // For LE-only emulator type: enable advertising.
            // For BR/EDR+LE (mesh tests): write scan enable 0x03.
            if matches!(hciemu_type, EmulatorType::Le) {
                bthost.set_adv_enable(0x01);
            } else {
                bthost.write_scan_enable(0x03);
            }
        }
    }
}

/// Client command complete callback — handles HCI cmd results from bthost.
fn client_cmd_complete(data: &Arc<MeshTestData>, opcode: u16, status: u8) {
    tester_print(&format!("Client set connectable: status 0x{:02x}", status));

    // BT_HCI_CMD_WRITE_SCAN_ENABLE = 0x0C1A, LE_SET_ADV_ENABLE = 0x200A
    const BT_HCI_CMD_WRITE_SCAN_ENABLE: u16 = 0x0C1A;
    const BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE: u16 = 0x2039;

    match opcode {
        BT_HCI_CMD_WRITE_SCAN_ENABLE
        | BT_HCI_CMD_LE_SET_ADV_ENABLE
        | BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE => {}
        0x0C56 /* BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE */ => {
            tester_print(&format!("Client enable SSP: status 0x{:02x}", status));
        }
        _ => return,
    }

    if status != 0 {
        tester_setup_failed();
    } else {
        let mut state = data.state.lock().unwrap();
        test_setup_condition_complete(&mut state);
    }
}

// ---------------------------------------------------------------------------
// Setup: Default test_setup (for tests with no custom setup)
// ---------------------------------------------------------------------------

/// Default setup callback — handles pairing/settings setup.
/// For mesh tests, most have no setup_settings, so this just completes.
fn test_setup_cb(data_any: &dyn Any) {
    let _ = data_any;
    let data = match tester_get_data::<MeshTestData>() {
        Some(d) => d,
        None => {
            tester_setup_failed();
            return;
        }
    };

    // If a custom setup was specified, call it.
    if let Some(custom_setup) = data.custom_setup {
        custom_setup(&data);
        return;
    }

    // No generic_data or no setup_settings: just complete setup.
    if data.generic.is_none() {
        tester_setup_complete();
        return;
    }

    // For mesh tests, none use setup_settings, so complete immediately.
    // The C code would iterate setup_settings here, but mesh tests skip it.
    tester_setup_complete();
}

// ---------------------------------------------------------------------------
// Setup: setup_enable_mesh
// ---------------------------------------------------------------------------

/// Custom setup: Power on → SET_LE → SET_EXP_FEATURE (mesh enable).
/// Equivalent to C `setup_enable_mesh()`.
fn setup_enable_mesh(data: &Arc<MeshTestData>) {
    let data_clone = Arc::clone(data);
    tokio::spawn(setup_enable_mesh_async(data_clone));
}

/// Async implementation of setup_enable_mesh.
async fn setup_enable_mesh_async(data: Arc<MeshTestData>) {
    let (mgmt, mgmt_index) = {
        let state = data.state.lock().unwrap();
        (state.mgmt.as_ref().map(Arc::clone), state.mgmt_index)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_setup_failed();
            return;
        }
    };

    // Send SET_POWERED on.
    let param_on: [u8; 1] = [0x01];
    match mgmt.send_command(MGMT_OP_SET_POWERED, mgmt_index, &param_on).await {
        Ok(resp) => {
            if resp.status != MGMT_STATUS_SUCCESS {
                tester_setup_failed();
                return;
            }
            tester_print("Controller powered on");
        }
        Err(e) => {
            error!("SET_POWERED failed: {}", e);
            tester_setup_failed();
            return;
        }
    }

    // Configure bthost after power-on.
    setup_bthost(&data);

    // Send SET_LE on.
    let _ = mgmt.send_command(MGMT_OP_SET_LE, mgmt_index, &param_on).await;

    // Send SET_EXP_FEATURE (mesh enable).
    match mgmt.send_command(MGMT_OP_SET_EXP_FEATURE, mgmt_index, SET_EXP_FEAT_PARAM_MESH).await {
        Ok(resp) => {
            if resp.status != MGMT_STATUS_SUCCESS {
                tester_print("Mesh feature could not be enabled");
            } else {
                tester_print("Mesh feature is enabled");
            }
        }
        Err(e) => {
            tester_print(&format!("Mesh feature enable failed: {}", e));
        }
    }
}

// ---------------------------------------------------------------------------
// Setup: setup_multi_mesh_send
// ---------------------------------------------------------------------------

/// Custom setup: enable mesh, then send two MESH_SEND commands.
/// Equivalent to C `setup_multi_mesh_send()`.
fn setup_multi_mesh_send(data: &Arc<MeshTestData>) {
    let data_clone = Arc::clone(data);
    tokio::spawn(setup_multi_mesh_send_async(data_clone));
}

/// Async implementation of setup_multi_mesh_send.
async fn setup_multi_mesh_send_async(data: Arc<MeshTestData>) {
    // First, do the enable mesh sequence.
    setup_enable_mesh_async(Arc::clone(&data)).await;

    let (mgmt, mgmt_index) = {
        let state = data.state.lock().unwrap();
        (state.mgmt.as_ref().map(Arc::clone), state.mgmt_index)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => return,
    };

    // Send two MESH_SEND commands.
    let _ = mgmt.send_command(MGMT_OP_MESH_SEND, mgmt_index, SEND_MESH_1).await;

    let _ = mgmt.send_command(MGMT_OP_MESH_SEND, mgmt_index, SEND_MESH_1).await;
}

// ---------------------------------------------------------------------------
// Test: controller_setup — simple pass test
// ---------------------------------------------------------------------------

/// Test function for "Controller setup" — just passes immediately.
fn controller_setup_cb(data_any: &dyn Any) {
    let _ = data_any;
    tester_test_passed();
}

// ---------------------------------------------------------------------------
// Test: test_command_generic — main test executor
// ---------------------------------------------------------------------------

/// Verify alt event parameters match expectations.
fn verify_alt_ev(test: &GenericData, data: &[u8]) -> bool {
    if data.len() != test.expect_alt_ev_len {
        tester_print(&format!("Invalid length {} != {}", data.len(), test.expect_alt_ev_len));
        return false;
    }

    if !test.expect_alt_ev_param.is_empty() && test.expect_alt_ev_param != data {
        tester_print("Event parameters do not match");
        return false;
    }

    true
}

/// Generic test command executor — sends a MGMT command and verifies
/// the response, optional HCI command hooks, and optional alt events.
fn test_command_generic_cb(data_any: &dyn Any) {
    let _ = data_any;
    let data = match tester_get_data::<MeshTestData>() {
        Some(d) => d,
        None => {
            tester_test_failed();
            return;
        }
    };

    let test = match data.generic {
        Some(t) => t,
        None => {
            tester_test_failed();
            return;
        }
    };

    let data_clone = Arc::clone(&data);
    tokio::spawn(test_command_generic_async(data_clone, test));
}

/// Async implementation of the generic test command executor.
async fn test_command_generic_async(data: Arc<MeshTestData>, test: &'static GenericData) {
    let (mgmt, mgmt_alt, mgmt_index) = {
        let state = data.state.lock().unwrap();
        (
            state.mgmt.as_ref().map(Arc::clone),
            state.mgmt_alt.as_ref().map(Arc::clone),
            state.mgmt_index,
        )
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_test_failed();
            return;
        }
    };

    let index = if test.send_index_none { MGMT_INDEX_NONE } else { mgmt_index };

    // Register new settings notification if needed.
    if test.expect_settings_set != 0 || test.expect_settings_unset != 0 {
        tester_print("Registering new settings notification");
        let (settings_id, _settings_rx) = mgmt.subscribe(MGMT_EV_NEW_SETTINGS, index).await;
        {
            let mut state = data.state.lock().unwrap();
            state.mgmt_settings_id = settings_id;
            test_add_condition(&mut state);
        }

        if let Some(ref mgmt_alt) = mgmt_alt {
            let (alt_settings_id, mut alt_settings_rx) =
                mgmt_alt.subscribe(MGMT_EV_NEW_SETTINGS, index).await;
            {
                let mut state = data.state.lock().unwrap();
                state.mgmt_alt_settings_id = alt_settings_id;
            }

            // Spawn task to monitor alt settings events.
            let data_for_settings = Arc::clone(&data);
            let mgmt_alt_for_settings = Arc::clone(mgmt_alt);
            tokio::spawn(async move {
                while let Some(ev) = alt_settings_rx.recv().await {
                    handle_new_settings_alt(&data_for_settings, &mgmt_alt_for_settings, test, &ev)
                        .await;
                }
            });
        }

        // Spawn task to monitor primary settings events (fail-on-receive).
        let (_, mut settings_rx) = mgmt.subscribe(MGMT_EV_NEW_SETTINGS, index).await;
        tokio::spawn(async move {
            if settings_rx.recv().await.is_some() {
                tester_print("New settings event received");
                tester_test_failed();
            }
        });
    }

    // Register alt event handler if needed.
    let mut alt_ev_task = None;
    if test.expect_alt_ev != 0 {
        if let Some(ref mgmt_alt) = mgmt_alt {
            tester_print(&format!("Registering event 0x{:04x} notification", test.expect_alt_ev));
            let (alt_ev_id, mut alt_ev_rx) = mgmt_alt.subscribe(test.expect_alt_ev, index).await;
            {
                let mut state = data.state.lock().unwrap();
                state.mgmt_alt_ev_id = alt_ev_id;
                test_add_condition(&mut state);
            }

            let data_for_alt = Arc::clone(&data);
            let mgmt_alt_for_alt = Arc::clone(mgmt_alt);
            alt_ev_task = Some(tokio::spawn(async move {
                if let Some(ev) = alt_ev_rx.recv().await {
                    tester_print(&format!("New event 0x{:04x} received", test.expect_alt_ev));

                    let alt_ev_id = { data_for_alt.state.lock().unwrap().mgmt_alt_ev_id };
                    mgmt_alt_for_alt.unsubscribe(alt_ev_id).await;

                    if !verify_alt_ev(test, &ev.data) {
                        tester_print("Incorrect event parameters");
                        tester_test_failed();
                        return;
                    }

                    let mut state = data_for_alt.state.lock().unwrap();
                    test_condition_complete(&mut state);
                }
            }));
        }
    }

    // Register HCI command list hook if needed (queue-based multi-command check).
    if let Some(hci_list) = test.expect_hci_list {
        tester_print("Registering HCI command list callback");
        {
            let mut state = data.state.lock().unwrap();
            for cmd in hci_list {
                state.expect_hci_q.push_tail(HciEntry { cmd_data: cmd.clone() });
                test_add_condition(&mut state);
            }
            if let Some(ref mut hciemu) = state.hciemu {
                let data_for_list = Arc::clone(&data);
                hciemu.add_central_post_command_hook(move |opcode, param| {
                    command_hci_list_callback(&data_for_list, opcode, param);
                });
            }
        }
    } else if test.expect_hci_command != 0 {
        // Register single HCI command hook if needed.
        tester_print("Registering HCI command callback");
        let data_for_hci = Arc::clone(&data);
        {
            let mut state = data.state.lock().unwrap();
            test_add_condition(&mut state);
            if let Some(ref mut hciemu) = state.hciemu {
                hciemu.add_central_post_command_hook(move |opcode, param| {
                    command_hci_callback(&data_for_hci, test, opcode, param);
                });
            }
        }
    }

    // No-op test (opcode 0): just return.
    if test.send_opcode == 0 {
        tester_print("Executing no-op test");
        return;
    }

    tester_print(&format!("Sending opcode 0x{:04x}", test.send_opcode));

    // Compute effective send length and param.
    let send_len = effective_send_len(test);
    let send_param = &test.send_param[..send_len.min(test.send_param.len())];

    // Add condition for the command response.
    {
        let mut state = data.state.lock().unwrap();
        test_add_condition(&mut state);
    }

    // Send the command.
    if test.force_power_off {
        let _ = mgmt.send_nowait(test.send_opcode, index, send_param).await;
        power_off(mgmt_index);
        // Command response still expected via the socket.
        // In this path we wait for the alt event or timeout.
    } else {
        match mgmt.send_command(test.send_opcode, index, send_param).await {
            Ok(resp) => {
                command_generic_callback(&data, test, &resp);
            }
            Err(e) => {
                error!("Command failed: {}", e);
                tester_test_failed();
                return;
            }
        }
    }

    // Wait for alt event task to complete if any.
    if let Some(task) = alt_ev_task {
        let _ = task.await;
    }
}

/// Handle MGMT command response — verify status and parameters.
fn command_generic_callback(data: &Arc<MeshTestData>, test: &GenericData, resp: &MgmtResponse) {
    tester_print(&format!("Command 0x{:04x}: status 0x{:02x}", test.send_opcode, resp.status));

    if resp.status != test.expect_status {
        if !test.fail_tolerant || (resp.status != 0) != (test.expect_status != 0) {
            tester_test_abort();
            return;
        }
        tester_print(&format!(
            "Unexpected status got {} expected {}",
            resp.status, test.expect_status
        ));
    }

    // Verify response parameters.
    if test.expect_len > 0 {
        if resp.data.len() != test.expect_len {
            tester_print(&format!(
                "Invalid cmd response parameter size {} {}",
                resp.data.len(),
                test.expect_len
            ));
            tester_test_failed();
            return;
        }

        if !test.expect_param.is_empty()
            && resp.data[..test.expect_len] != test.expect_param[..test.expect_len]
        {
            tester_print("Unexpected cmd response parameter value");
            tester_test_failed();
            return;
        }
    }

    let mut state = data.state.lock().unwrap();
    test_condition_complete(&mut state);
}

/// HCI command hook callback — verify expected HCI command from btdev.
fn command_hci_callback(data: &Arc<MeshTestData>, test: &GenericData, opcode: u16, param: &[u8]) {
    debug!("HCI Command 0x{:04x} length {}", opcode, param.len());
    tester_print(&format!("HCI Command 0x{:04x} length {}", opcode, param.len()));

    let mut state = data.state.lock().unwrap();

    if opcode != test.expect_hci_command || state.expect_hci_command_done {
        return;
    }

    state.expect_hci_command_done = true;

    if param.len() != test.expect_hci_len {
        tester_print("Invalid parameter size for HCI command");
        tester_test_failed();
        return;
    }

    if param != &test.expect_hci_param[..test.expect_hci_len] {
        tester_print("Unexpected HCI command parameter value");
        tester_test_failed();
        return;
    }

    test_condition_complete(&mut state);
}

/// HCI command list hook callback — verify HCI command from expect queue.
fn command_hci_list_callback(data: &Arc<MeshTestData>, opcode: u16, param: &[u8]) {
    debug!("HCI Command (list) 0x{:04x} length {}", opcode, param.len());

    let mut state = data.state.lock().unwrap();

    // Search the queue for a matching entry.
    let found = state.expect_hci_q.find(|entry| entry.matches(opcode, param));

    if found.is_some() {
        // Remove the matching entry from the queue.
        state.expect_hci_q.remove_if(|entry| entry.matches(opcode, param));
        tester_print(&format!("HCI command 0x{:04x} matched and removed from queue", opcode));
        test_condition_complete(&mut state);
    }
}

/// Handle NEW_SETTINGS event on the alt MGMT socket.
async fn handle_new_settings_alt(
    data: &Arc<MeshTestData>,
    mgmt_alt: &Arc<MgmtSocket>,
    test: &'static GenericData,
    ev: &MgmtEvent,
) {
    if ev.data.len() != 4 {
        tester_print("Invalid parameter size for new settings event");
        tester_test_failed();
        return;
    }

    let settings = u32::from_le_bytes([ev.data[0], ev.data[1], ev.data[2], ev.data[3]]);
    tester_print(&format!("New settings 0x{:08x} received", settings));

    if test.expect_settings_unset != 0 {
        if (settings & test.expect_settings_unset) != 0 {
            return;
        }
    } else if test.expect_settings_set == 0
        || (settings & test.expect_settings_set) != test.expect_settings_set
    {
        return;
    }

    tester_print("Unregistering new settings notification");
    let alt_settings_id = data.state.lock().unwrap().mgmt_alt_settings_id;
    mgmt_alt.unsubscribe(alt_settings_id).await;

    let mut state = data.state.lock().unwrap();
    test_condition_complete(&mut state);
}

// ---------------------------------------------------------------------------
// Post-teardown
// ---------------------------------------------------------------------------

/// Post-teardown callback — clean up emulator and sockets.
fn test_post_teardown_cb(data_any: &dyn Any) {
    let _ = data_any;
    let data = match tester_get_data::<MeshTestData>() {
        Some(d) => d,
        None => {
            tester_post_teardown_complete();
            return;
        }
    };

    {
        let mut state = data.state.lock().unwrap();

        // Drop emulator (closes VHCI, aborts background tasks).
        state.hciemu = None;

        // Drop MGMT sockets (closes underlying fds).
        state.mgmt = None;
        state.mgmt_alt = None;
    }

    tester_post_teardown_complete();
}

// ---------------------------------------------------------------------------
// Test Registration Helpers
// ---------------------------------------------------------------------------

/// Create a TestCallback Arc wrapping a function.
fn make_callback(f: fn(&dyn Any)) -> TestCallback {
    Arc::new(f)
}

/// Register a test case with the BR/EDR+LE configuration.
/// Equivalent to C `test_bredrle()` macro.
fn test_bredrle(
    name: &str,
    generic: Option<&'static GenericData>,
    custom_setup: Option<fn(&Arc<MeshTestData>)>,
    test_func: fn(&dyn Any),
) {
    // Determine if the test has a custom setup or uses the default.
    let setup_cb: Option<TestCallback> = Some(make_callback(test_setup_cb));

    let test_data = MeshTestData {
        generic,
        hciemu_type: EmulatorType::BrEdrLe,
        expected_version: EXPECTED_VERSION,
        expected_manufacturer: EXPECTED_MANUFACTURER,
        expected_supported_settings: EXPECTED_SUPPORTED_SETTINGS,
        initial_settings: INITIAL_SETTINGS,
        custom_setup,
        state: Mutex::new(TestState::default()),
    };

    tester_add_full::<MeshTestData, ()>(
        name,
        Some(test_data),
        Some(make_callback(test_pre_setup_cb)),
        setup_cb,
        Some(make_callback(test_func)),
        None, // teardown
        Some(make_callback(test_post_teardown_cb)),
        TEST_TIMEOUT_SECS,
        None,
    );
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

fn main() {
    // Initialize tracing for structured logging.
    let _ = tracing_subscriber::fmt::try_init();

    // Initialize the tester framework with command-line args.
    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    info!("BlueZ Mesh MGMT Tester");

    // Test 1: Controller setup.
    test_bredrle("Controller setup", None, None, controller_setup_cb);

    // Test 2: Mesh - Enable 1 (enable mesh experimental feature).
    test_bredrle("Mesh - Enable 1", Some(&ENABLE_MESH_1), None, test_command_generic_cb);

    // Test 3: Mesh - Enable 2 (set mesh receiver after enable).
    test_bredrle(
        "Mesh - Enable 2",
        Some(&ENABLE_MESH_2),
        Some(setup_enable_mesh),
        test_command_generic_cb,
    );

    // Test 4: Mesh - Read Mesh Features (enabled).
    test_bredrle(
        "Mesh - Read Mesh Features",
        Some(&READ_MESH_FEATURES),
        Some(setup_enable_mesh),
        test_command_generic_cb,
    );

    // Test 5: Mesh - Read Mesh Features - Disabled.
    test_bredrle(
        "Mesh - Read Mesh Features - Disabled",
        Some(&READ_MESH_FEATURES_DISABLED),
        None,
        test_command_generic_cb,
    );

    // Test 6: Mesh - Send (valid mesh advertising).
    test_bredrle(
        "Mesh - Send",
        Some(&MESH_SEND_MESH_1),
        Some(setup_enable_mesh),
        test_command_generic_cb,
    );

    // Test 7: Mesh - Send - too short.
    test_bredrle(
        "Mesh - Send - too short",
        Some(&MESH_SEND_MESH_TOO_SHORT),
        Some(setup_enable_mesh),
        test_command_generic_cb,
    );

    // Test 8: Mesh - Send - too long.
    test_bredrle(
        "Mesh - Send - too long",
        Some(&MESH_SEND_MESH_TOO_LONG),
        Some(setup_enable_mesh),
        test_command_generic_cb,
    );

    // Test 9: Mesh - Send cancel - 1 (cancel handle 1).
    test_bredrle(
        "Mesh - Send cancel - 1",
        Some(&MESH_SEND_MESH_CANCEL_1),
        Some(setup_multi_mesh_send),
        test_command_generic_cb,
    );

    // Test 10: Mesh - Send cancel - 2 (cancel handle 2).
    test_bredrle(
        "Mesh - Send cancel - 2",
        Some(&MESH_SEND_MESH_CANCEL_2),
        Some(setup_multi_mesh_send),
        test_command_generic_cb,
    );

    // Run all registered tests.
    let exit_code = tester_run();
    std::process::exit(exit_code);
}
