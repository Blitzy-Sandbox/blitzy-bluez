// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright 2024 BlueZ Project
//
// SMP (Security Manager Protocol) pairing tester — validates SMP pairing
// flows (legacy and Secure Connections) by exchanging SMP PDUs over L2CAP
// CID 0x0006 against an HCI emulator, with cryptographic validation of
// pairing material.
//
// Rust rewrite of tools/smp-tester.c (930 lines).

#![deny(warnings)]

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::warn;

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::crypto::aes_cmac::{bt_crypto_c1, bt_crypto_f4, bt_crypto_s1, random_bytes};
use bluez_shared::crypto::ecc::{ecc_make_key, ecdh_shared_secret};
use bluez_shared::mgmt::client::MgmtSocket;
use bluez_shared::sys::bluetooth::BDADDR_LE_PUBLIC;
use bluez_shared::sys::hci::LE_PUBLIC_ADDRESS;
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_EV_USER_CONFIRM_REQUEST, MGMT_INDEX_NONE, MGMT_OP_PAIR_DEVICE,
    MGMT_OP_READ_INFO, MGMT_OP_SET_ADVERTISING, MGMT_OP_SET_BONDABLE, MGMT_OP_SET_CONNECTABLE,
    MGMT_OP_SET_LE, MGMT_OP_SET_POWERED, MGMT_OP_SET_SECURE_CONN, MGMT_OP_SET_SSP,
    MGMT_OP_USER_CONFIRM_REPLY, MGMT_STATUS_SUCCESS,
};
use bluez_shared::tester::{
    tester_add_full, tester_init, tester_post_teardown_complete, tester_pre_setup_complete,
    tester_pre_setup_failed, tester_print, tester_run, tester_setup_complete, tester_setup_failed,
    tester_test_failed, tester_test_passed, tester_warn,
};

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Callback type for tester lifecycle functions (pre-setup, setup, test, teardown).
type TestCb = Option<Arc<dyn Fn(&dyn Any) + Send + Sync>>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// L2CAP Channel ID for SMP (Security Manager Protocol).
const SMP_CID: u16 = 0x0006;

// SMP PDU opcodes
const SMP_OP_PAIRING_REQUEST: u8 = 0x01;
const SMP_OP_PAIRING_RESPONSE: u8 = 0x02;
const SMP_OP_PAIRING_CONFIRM: u8 = 0x03;
const SMP_OP_PAIRING_RANDOM: u8 = 0x04;
const SMP_OP_PUBLIC_KEY: u8 = 0x0c;

// ---------------------------------------------------------------------------
// SMP PDU request/response definitions
// ---------------------------------------------------------------------------

/// A single SMP PDU exchange step: what to send and what to expect back.
/// `None` means no action for that direction.
struct SmpReqRsp {
    send: Option<&'static [u8]>,
    send_len: u16,
    expect: Option<&'static [u8]>,
    expect_len: u16,
}

/// Per-test SMP data: a sequence of PDU exchanges plus optional flags.
struct SmpData {
    req: &'static [SmpReqRsp],
    mitm: bool,
    sc: bool,
    expect_hci_command: u16,
}

// ---------------------------------------------------------------------------
// Test PDU byte arrays (exactly matching C source)
// ---------------------------------------------------------------------------

// Invalid request 1: reserved opcode 0x0b
static SMP_NVAL_REQ_1: [u8; 2] = [0x0b, 0x00];
static SMP_NVAL_REQ_1_RSP: [u8; 2] = [0x05, 0x07]; // Pairing Failed, Command Not Supported

// Invalid request 2: pairing request with all-zero fields (7 bytes, first = 0x01)
static SMP_NVAL_REQ_2: [u8; 7] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
static SMP_NVAL_REQ_2_RSP: [u8; 2] = [0x05, 0x06]; // Pairing Failed, Encryption Key Size

// Invalid request 3: short pairing request (only 2 bytes)
static SMP_NVAL_REQ_3: [u8; 2] = [0x01, 0xff];
static SMP_NVAL_REQ_3_RSP: [u8; 2] = [0x05, 0x0a]; // Pairing Failed, Invalid Parameters

// Basic pairing request/response
static SMP_BASIC_REQ_1: [u8; 7] = [
    0x01, // Pairing Request
    0x03, // NoInputNoOutput
    0x00, // OOB Flag
    0x01, // Bonding - no MITM
    0x10, // Max key size
    0x05, // Init. key dist.
    0x05, // Rsp. key dist.
];
static SMP_BASIC_RSP_1: [u8; 7] = [
    0x02, // Pairing Response
    0x03, // NoInputNoOutput
    0x00, // OOB Flag
    0x01, // Bonding - no MITM
    0x10, // Max key size
    0x05, // Init. key dist.
    0x05, // Rsp. key dist.
];

// Confirm and Random PDU templates (opcode + 16 zero bytes)
static SMP_CONFIRM_1: [u8; 17] = [0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
static SMP_RANDOM_1: [u8; 17] = [0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// Basic pairing request with MITM
static SMP_BASIC_REQ_2: [u8; 7] = [
    0x01, // Pairing Request
    0x04, // KeyboardDisplay
    0x00, // OOB Flag
    0x05, // Bonding - MITM
    0x10, // Max key size
    0x05, // Init. key dist.
    0x05, // Rsp. key dist.
];

// SC pairing request
static SMP_SC_REQ_1: [u8; 7] = [
    0x01, // Pairing Request
    0x03, // NoInputNoOutput
    0x00, // OOB Flag
    0x29, // Bonding - no MITM, SC, CT2
    0x10, // Max key size
    0x0d, // Init. key dist.
    0x0d, // Rsp. key dist.
];

// SC pairing response
static SMP_SC_RSP_1: [u8; 7] = [
    0x02, // Pairing Response
    0x03, // NoInputNoOutput
    0x00, // OOB Flag
    0x09, // Bonding - no MITM, SC
    0x10, // Max key size
    0x0d, // Init. key dist.
    0x0d, // Rsp. key dist.
];

// SC public key template (opcode + 64 zero bytes)
static SMP_SC_PK: [u8; 65] = [0x0c; 65];

// ---------------------------------------------------------------------------
// Test step sequences (exactly matching C smp_req_rsp arrays)
// ---------------------------------------------------------------------------

// Server - Invalid Request 1: send invalid opcode, expect error
static NVAL_REQ_1_STEPS: [SmpReqRsp; 1] = [SmpReqRsp {
    send: Some(&SMP_NVAL_REQ_1),
    send_len: 2,
    expect: Some(&SMP_NVAL_REQ_1_RSP),
    expect_len: 2,
}];

// Server - Invalid Request 2: send all-zero pairing request
static SRV_NVAL_REQ_1_STEPS: [SmpReqRsp; 1] = [SmpReqRsp {
    send: Some(&SMP_NVAL_REQ_2),
    send_len: 7,
    expect: Some(&SMP_NVAL_REQ_2_RSP),
    expect_len: 2,
}];

// Server - Invalid Request 3: short pairing request
static SRV_NVAL_REQ_2_STEPS: [SmpReqRsp; 1] = [SmpReqRsp {
    send: Some(&SMP_NVAL_REQ_3),
    send_len: 2,
    expect: Some(&SMP_NVAL_REQ_3_RSP),
    expect_len: 2,
}];

// Server - Basic Request 1: full legacy pairing exchange
static SRV_BASIC_REQ_1_STEPS: [SmpReqRsp; 3] = [
    SmpReqRsp {
        send: Some(&SMP_BASIC_REQ_1),
        send_len: 7,
        expect: Some(&SMP_BASIC_RSP_1),
        expect_len: 7,
    },
    SmpReqRsp {
        send: Some(&SMP_CONFIRM_1),
        send_len: 17,
        expect: Some(&SMP_CONFIRM_1),
        expect_len: 17,
    },
    SmpReqRsp {
        send: Some(&SMP_RANDOM_1),
        send_len: 17,
        expect: Some(&SMP_RANDOM_1),
        expect_len: 17,
    },
];

// Client - Basic Request 1: expect pairing req, send response, confirm, random
static CLI_BASIC_REQ_1_STEPS: [SmpReqRsp; 4] = [
    SmpReqRsp { send: None, send_len: 0, expect: Some(&SMP_BASIC_REQ_1), expect_len: 7 },
    SmpReqRsp {
        send: Some(&SMP_BASIC_RSP_1),
        send_len: 7,
        expect: Some(&SMP_CONFIRM_1),
        expect_len: 17,
    },
    SmpReqRsp {
        send: Some(&SMP_CONFIRM_1),
        send_len: 17,
        expect: Some(&SMP_RANDOM_1),
        expect_len: 17,
    },
    SmpReqRsp { send: Some(&SMP_RANDOM_1), send_len: 17, expect: None, expect_len: 0 },
];

// Client - Basic Request 2: same as 1 but with MITM (different pairing req)
static CLI_BASIC_REQ_2_STEPS: [SmpReqRsp; 4] = [
    SmpReqRsp { send: None, send_len: 0, expect: Some(&SMP_BASIC_REQ_2), expect_len: 7 },
    SmpReqRsp {
        send: Some(&SMP_BASIC_RSP_1),
        send_len: 7,
        expect: Some(&SMP_CONFIRM_1),
        expect_len: 17,
    },
    SmpReqRsp {
        send: Some(&SMP_CONFIRM_1),
        send_len: 17,
        expect: Some(&SMP_RANDOM_1),
        expect_len: 17,
    },
    SmpReqRsp { send: Some(&SMP_RANDOM_1), send_len: 17, expect: None, expect_len: 0 },
];

// Client - SC Request 1: legacy-like flow but SC flags in pairing req
static CLI_SC_REQ_1_STEPS: [SmpReqRsp; 4] = [
    SmpReqRsp { send: None, send_len: 0, expect: Some(&SMP_SC_REQ_1), expect_len: 7 },
    SmpReqRsp {
        send: Some(&SMP_BASIC_RSP_1),
        send_len: 7,
        expect: Some(&SMP_CONFIRM_1),
        expect_len: 17,
    },
    SmpReqRsp {
        send: Some(&SMP_CONFIRM_1),
        send_len: 17,
        expect: Some(&SMP_RANDOM_1),
        expect_len: 17,
    },
    SmpReqRsp { send: Some(&SMP_RANDOM_1), send_len: 17, expect: None, expect_len: 0 },
];

// Client - SC Request 2: full SC flow with public key exchange
static CLI_SC_REQ_2_STEPS: [SmpReqRsp; 5] = [
    SmpReqRsp { send: None, send_len: 0, expect: Some(&SMP_SC_REQ_1), expect_len: 7 },
    SmpReqRsp { send: Some(&SMP_SC_RSP_1), send_len: 7, expect: Some(&SMP_SC_PK), expect_len: 65 },
    SmpReqRsp { send: Some(&SMP_SC_PK), send_len: 65, expect: None, expect_len: 0 },
    SmpReqRsp {
        send: Some(&SMP_CONFIRM_1),
        send_len: 17,
        expect: Some(&SMP_RANDOM_1),
        expect_len: 17,
    },
    SmpReqRsp { send: Some(&SMP_RANDOM_1), send_len: 17, expect: None, expect_len: 0 },
];

// ---------------------------------------------------------------------------
// Test definitions (static SmpData)
// ---------------------------------------------------------------------------

static SMP_SERVER_BASIC_REQ_1_TEST: SmpData =
    SmpData { req: &SRV_BASIC_REQ_1_STEPS, mitm: false, sc: false, expect_hci_command: 0 };

static SMP_SERVER_NVAL_REQ_1_TEST: SmpData =
    SmpData { req: &NVAL_REQ_1_STEPS, mitm: false, sc: false, expect_hci_command: 0 };

static SMP_SERVER_NVAL_REQ_2_TEST: SmpData =
    SmpData { req: &SRV_NVAL_REQ_1_STEPS, mitm: false, sc: false, expect_hci_command: 0 };

static SMP_SERVER_NVAL_REQ_3_TEST: SmpData =
    SmpData { req: &SRV_NVAL_REQ_2_STEPS, mitm: false, sc: false, expect_hci_command: 0 };

static SMP_CLIENT_BASIC_REQ_1_TEST: SmpData =
    SmpData { req: &CLI_BASIC_REQ_1_STEPS, mitm: false, sc: false, expect_hci_command: 0 };

static SMP_CLIENT_BASIC_REQ_2_TEST: SmpData =
    SmpData { req: &CLI_BASIC_REQ_2_STEPS, mitm: true, sc: false, expect_hci_command: 0 };

static SMP_CLIENT_SC_REQ_1_TEST: SmpData =
    SmpData { req: &CLI_SC_REQ_1_STEPS, mitm: false, sc: true, expect_hci_command: 0 };

static SMP_CLIENT_SC_REQ_2_TEST: SmpData =
    SmpData { req: &CLI_SC_REQ_2_STEPS, mitm: false, sc: true, expect_hci_command: 0 };

// ---------------------------------------------------------------------------
// Per-test mutable state
// ---------------------------------------------------------------------------

/// Mutable state carried through a single test's lifecycle.
/// Replaces C `struct test_data`. Wrapped in `Arc<Mutex<>>` for sharing
/// between async tasks and callbacks.
struct TestState {
    smp_data: &'static SmpData,
    mgmt: Option<Arc<MgmtSocket>>,
    mgmt_index: u16,
    hciemu: Option<HciEmulator>,
    hciemu_type: EmulatorType,
    ia: [u8; 6],
    ia_type: u8,
    ra: [u8; 6],
    ra_type: u8,
    out: bool,
    handle: u16,
    counter: usize,
    tk: [u8; 16],
    prnd: [u8; 16],
    rrnd: [u8; 16],
    pcnf: [u8; 16],
    preq: [u8; 7],
    prsp: [u8; 7],
    ltk: [u8; 16],
    remote_pk: [u8; 64],
    local_pk: [u8; 64],
    local_sk: [u8; 32],
    dhkey: [u8; 32],
    unmet_conditions: i32,
}

impl TestState {
    fn new(smp_data: &'static SmpData) -> Self {
        Self {
            smp_data,
            mgmt: None,
            mgmt_index: 0,
            hciemu: None,
            hciemu_type: EmulatorType::BrEdrLe,
            ia: [0u8; 6],
            ia_type: 0,
            ra: [0u8; 6],
            ra_type: 0,
            out: false,
            handle: 0,
            counter: 0,
            tk: [0u8; 16],
            prnd: [0u8; 16],
            rrnd: [0u8; 16],
            pcnf: [0u8; 16],
            preq: [0u8; 7],
            prsp: [0u8; 7],
            ltk: [0u8; 16],
            remote_pk: [0u8; 64],
            local_pk: [0u8; 64],
            local_sk: [0u8; 32],
            dhkey: [0u8; 32],
            unmet_conditions: 0,
        }
    }
}

type SharedState = Arc<Mutex<TestState>>;

// ---------------------------------------------------------------------------
// Condition tracking (mirrors C test_add_condition / test_condition_complete)
// ---------------------------------------------------------------------------

fn test_add_condition(state: &SharedState) {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.unmet_conditions += 1;
    tester_print(&format!("Test condition added, total {}", s.unmet_conditions));
}

fn test_condition_complete(state: &SharedState) {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.unmet_conditions -= 1;
    tester_print(&format!("Test condition complete, {} left", s.unmet_conditions));
    if s.unmet_conditions > 0 {
        return;
    }
    drop(s);
    tester_test_passed();
}

// ---------------------------------------------------------------------------
// Debug print callback for hciemu
// ---------------------------------------------------------------------------

fn print_debug(msg: &str) {
    tester_print(&format!("hciemu: {msg}"));
}

/// Validate send_len matches the slice length (debug assertion).
fn validate_send_len(req: &SmpReqRsp) {
    if let Some(data) = req.send {
        debug_assert_eq!(req.send_len as usize, data.len(), "send_len mismatch for SMP PDU");
    }
}

// ---------------------------------------------------------------------------
// Init BD addresses from emulator (mirrors C init_bdaddr)
// ---------------------------------------------------------------------------

fn init_bdaddr(state: &SharedState) {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let emu = match s.hciemu.as_ref() {
        Some(e) => e,
        None => {
            tester_warn("No hciemu in init_bdaddr");
            tester_test_failed();
            return;
        }
    };

    let central_addr = emu.get_central_bdaddr();
    let client_addr = match emu.get_client_bdaddr() {
        Some(a) => a,
        None => {
            tester_warn("No client bdaddr");
            tester_test_failed();
            return;
        }
    };

    s.ia_type = LE_PUBLIC_ADDRESS;
    s.ra_type = LE_PUBLIC_ADDRESS;

    if s.out {
        s.ia.copy_from_slice(&client_addr);
        s.ra.copy_from_slice(&central_addr);
    } else {
        s.ia.copy_from_slice(&central_addr);
        s.ra.copy_from_slice(&client_addr);
    }
}

// ---------------------------------------------------------------------------
// make_pk: Generate P-256 key pair for SC pairing (mirrors C make_pk)
// ---------------------------------------------------------------------------

fn make_pk(state: &SharedState) {
    let (pk, sk) = match ecc_make_key() {
        Ok(pair) => pair,
        Err(e) => {
            tester_print(&format!("Failed to generate local ECDH keypair: {e}"));
            tester_setup_failed();
            return;
        }
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.local_pk = pk;
    s.local_sk = sk;
}

// ---------------------------------------------------------------------------
// get_pdu: Build the actual PDU to send based on opcode template.
// For confirm/random/pk, generates dynamic content.
// For request/response, captures preq/prsp and returns the original.
// (mirrors C get_pdu)
// ---------------------------------------------------------------------------

fn get_pdu(state: &SharedState, pdu: &[u8]) -> Vec<u8> {
    if pdu.is_empty() {
        return pdu.to_vec();
    }
    let opcode = pdu[0];
    match opcode {
        SMP_OP_PAIRING_REQUEST => {
            // Capture preq
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let copy_len = pdu.len().min(s.preq.len());
            s.preq[..copy_len].copy_from_slice(&pdu[..copy_len]);
            pdu.to_vec()
        }
        SMP_OP_PAIRING_RESPONSE => {
            // Capture prsp
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let copy_len = pdu.len().min(s.prsp.len());
            s.prsp[..copy_len].copy_from_slice(&pdu[..copy_len]);
            pdu.to_vec()
        }
        SMP_OP_PAIRING_CONFIRM => {
            // Generate random nonce and compute confirm value
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let _ = random_bytes(&mut s.prnd);
            let sc = s.smp_data.sc;
            let mut buf = vec![opcode; 17];
            if sc {
                // SC: f4(local_pk_x, remote_pk_x, prnd, 0)
                let local_pk_x: [u8; 32] = s.local_pk[..32].try_into().unwrap_or([0u8; 32]);
                let remote_pk_x: [u8; 32] = s.remote_pk[..32].try_into().unwrap_or([0u8; 32]);
                match bt_crypto_f4(&local_pk_x, &remote_pk_x, &s.prnd, 0) {
                    Ok(cfm) => buf[1..17].copy_from_slice(&cfm),
                    Err(e) => warn!("bt_crypto_f4 failed: {e}"),
                }
            } else {
                // Legacy: c1(tk, prnd, prsp, preq, ia_type, ia, ra_type, ra)
                let tk = s.tk;
                let prnd = s.prnd;
                let prsp = s.prsp;
                let preq = s.preq;
                let iat = s.ia_type;
                let ia = s.ia;
                let rat = s.ra_type;
                let ra = s.ra;
                match bt_crypto_c1(&tk, &prnd, &prsp, &preq, iat, &ia, rat, &ra) {
                    Ok(cfm) => buf[1..17].copy_from_slice(&cfm),
                    Err(e) => warn!("bt_crypto_c1 failed: {e}"),
                }
            }
            buf
        }
        SMP_OP_PAIRING_RANDOM => {
            // Return our random nonce
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut buf = vec![opcode; 17];
            buf[1..17].copy_from_slice(&s.prnd);
            buf
        }
        SMP_OP_PUBLIC_KEY => {
            // Return our local public key
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut buf = vec![opcode; 65];
            buf[1..65].copy_from_slice(&s.local_pk);
            buf
        }
        _ => pdu.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// verify_random: Verify remote random, compute STK, optionally start encrypt.
// (mirrors C verify_random)
// ---------------------------------------------------------------------------

fn verify_random(state: &SharedState, _rnd: &[u8]) -> bool {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());

    // Verify confirm: c1(tk, rrnd, prsp, preq, iat, ia, rat, ra)
    let tk = s.tk;
    let rrnd = s.rrnd;
    let prsp = s.prsp;
    let preq = s.preq;
    let iat = s.ia_type;
    let ia = s.ia;
    let rat = s.ra_type;
    let ra = s.ra;
    let pcnf = s.pcnf;

    match bt_crypto_c1(&tk, &rrnd, &prsp, &preq, iat, &ia, rat, &ra) {
        Ok(confirm) => {
            if confirm != pcnf {
                tester_warn("Confirmation values don't match");
                return false;
            }
        }
        Err(e) => {
            warn!("bt_crypto_c1 verify failed: {e}");
            return false;
        }
    }

    // Compute STK
    let prnd = s.prnd;
    let is_out = s.out;
    if is_out {
        // Server mode: s1(tk, rrnd, prnd) and start encryption
        match bt_crypto_s1(&tk, &rrnd, &prnd) {
            Ok(ltk) => {
                s.ltk = ltk;
                let handle = s.handle;
                let ltk_copy = ltk;
                // Start encryption via bthost
                if let Some(emu) = s.hciemu.as_ref() {
                    if let Some(mut host) = emu.client_get_host() {
                        host.le_start_encrypt(handle, &ltk_copy);
                    }
                }
            }
            Err(e) => {
                warn!("bt_crypto_s1 failed: {e}");
                return false;
            }
        }
    } else {
        // Client mode: s1(tk, prnd, rrnd)
        match bt_crypto_s1(&tk, &prnd, &rrnd) {
            Ok(ltk) => s.ltk = ltk,
            Err(e) => {
                warn!("bt_crypto_s1 failed: {e}");
                return false;
            }
        }
    }

    true
}

/// SC random verification (mirrors C sc_random — currently a no-op that returns true).
fn sc_random(_state: &SharedState) -> bool {
    true
}

// ---------------------------------------------------------------------------
// smp_server: Core SMP PDU handler registered via bthost CID hook.
// Called when bthost receives SMP data on the connection.
// Exactly mirrors C smp_server (tools/smp-tester.c:613-702).
// ---------------------------------------------------------------------------

fn smp_server(state: &SharedState, data: &[u8]) {
    if data.is_empty() {
        tester_warn("Received too small SMP PDU");
        tester_test_failed();
        return;
    }

    let opcode = data[0];
    tester_print(&format!("Received SMP opcode 0x{opcode:02x}"));

    let (smp_req, req_count, counter) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        (s.smp_data.req, s.smp_data.req.len(), s.counter)
    };

    if counter >= req_count {
        test_condition_complete(state);
        return;
    }

    // Fetch current step and post-increment counter
    let req = &smp_req[counter];
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.counter += 1;
    }

    // If no expected data for this step, skip verification
    if req.expect.is_none() {
        // Process opcode for state capture (request/response)
        process_received_opcode(state, opcode, data);
        send_next_pdus(state);
        return;
    }

    let expect_len = req.expect_len as usize;
    let len = data.len();

    if expect_len != len {
        tester_warn(&format!("Unexpected SMP PDU length ({len} != {expect_len})"));
        tester_test_failed();
        return;
    }

    // Opcode-specific processing with special "goto next" semantics
    match opcode {
        SMP_OP_PAIRING_REQUEST => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let copy_len = data.len().min(s.preq.len());
            s.preq[..copy_len].copy_from_slice(&data[..copy_len]);
        }
        SMP_OP_PAIRING_RESPONSE => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let copy_len = data.len().min(s.prsp.len());
            s.prsp[..copy_len].copy_from_slice(&data[..copy_len]);
        }
        SMP_OP_PAIRING_CONFIRM => {
            // Capture peer confirm and skip memcmp (goto next)
            {
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                if data.len() > 16 {
                    s.pcnf.copy_from_slice(&data[1..17]);
                }
            }
            send_next_pdus(state);
            return;
        }
        SMP_OP_PAIRING_RANDOM => {
            // Capture remote random and verify
            {
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                if data.len() > 16 {
                    s.rrnd.copy_from_slice(&data[1..17]);
                }
            }
            let is_sc = {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.smp_data.sc
            };
            if is_sc {
                if !sc_random(state) {
                    tester_test_failed();
                    return;
                }
            } else if !verify_random(state, &data[1..]) {
                tester_test_failed();
                return;
            }
            send_next_pdus(state);
            return;
        }
        SMP_OP_PUBLIC_KEY => {
            // Capture remote public key and compute ECDH shared secret
            {
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                if data.len() > 64 {
                    s.remote_pk.copy_from_slice(&data[1..65]);
                }
                let remote_pk = s.remote_pk;
                let local_sk = s.local_sk;
                match ecdh_shared_secret(&remote_pk, &local_sk) {
                    Ok(dhkey) => s.dhkey = dhkey,
                    Err(e) => warn!("ecdh_shared_secret failed: {e}"),
                }
            }
            send_next_pdus(state);
            return;
        }
        _ => {}
    }

    // For Pairing Request/Response, verify exact memcmp
    if let Some(expect) = req.expect {
        if data[..len] != expect[..len.min(expect.len())] {
            tester_warn("Unexpected SMP PDU");
            tester_test_failed();
            return;
        }
    }

    send_next_pdus(state);
}

/// Process received opcode for state capture (preq/prsp) without verification.
fn process_received_opcode(state: &SharedState, opcode: u8, data: &[u8]) {
    match opcode {
        SMP_OP_PAIRING_REQUEST => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let copy_len = data.len().min(s.preq.len());
            s.preq[..copy_len].copy_from_slice(&data[..copy_len]);
        }
        SMP_OP_PAIRING_RESPONSE => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let copy_len = data.len().min(s.prsp.len());
            s.prsp[..copy_len].copy_from_slice(&data[..copy_len]);
        }
        _ => {}
    }
}

/// Send the next PDU(s) in the sequence. Mirrors the C "next:" loop:
/// keep sending steps that have send data, stop at one that expects a response.
fn send_next_pdus(state: &SharedState) {
    loop {
        let (counter, req_count) = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            (s.counter, s.smp_data.req.len())
        };

        if counter >= req_count {
            test_condition_complete(state);
            return;
        }

        let smp_req = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.smp_data.req
        };
        let req = &smp_req[counter];
        validate_send_len(req);

        if let Some(send_data) = req.send {
            let pdu = get_pdu(state, send_data);
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let handle = s.handle;
            if let Some(emu) = s.hciemu.as_ref() {
                if let Some(host) = emu.client_get_host() {
                    host.send_cid(handle, SMP_CID, &pdu);
                }
            }
        }

        if req.expect.is_some() {
            // Wait for the response
            break;
        }

        // No expect → advance counter and continue to next step
        {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.counter += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// smp_new_conn: Callback when a new LE connection is established on bthost.
// Mirrors C smp_new_conn (tools/smp-tester.c:735-764).
// ---------------------------------------------------------------------------

fn smp_new_conn(state: &SharedState, handle: u16) {
    tester_print(&format!("New SMP client connection with handle 0x{handle:04x}"));

    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.handle = handle;
    }

    // Register SMP CID hook on this connection
    let state_hook = state.clone();
    {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(emu) = s.hciemu.as_ref() {
            if let Some(mut host) = emu.client_get_host() {
                host.add_cid_hook(handle, SMP_CID, move |data: &[u8]| {
                    smp_server(&state_hook, data);
                });
            }
        }
    }

    let (counter, req_count) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        (s.counter, s.smp_data.req.len())
    };

    if counter >= req_count {
        return;
    }

    let smp_req = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.smp_data.req
    };
    let req = &smp_req[counter];

    // Validate send length matches slice (debug check)
    validate_send_len(req);

    // If the first step has nothing to send, just wait
    let send_data = match req.send {
        Some(d) => d,
        None => return,
    };

    tester_print("Sending SMP PDU");

    let pdu = get_pdu(state, send_data);
    {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(emu) = s.hciemu.as_ref() {
            if let Some(host) = emu.client_get_host() {
                host.send_cid(handle, SMP_CID, &pdu);
            }
        }
    }

    // If this step expects no response, the exchange is done for this step
    if req.expect.is_none() {
        test_condition_complete(state);
    }
}

// ---------------------------------------------------------------------------
// user_confirm_request_callback: MGMT event handler for pairing confirmation.
// Mirrors C user_confirm_request_callback (tools/smp-tester.c:391-404).
// ---------------------------------------------------------------------------

fn user_confirm_request_callback(state: &SharedState, ev_data: &[u8]) {
    // ev_data is the MGMT event param for USER_CONFIRM_REQUEST
    // Contains: addr (6) + addr_type (1) + confirm_hint (1) + value (4)
    if ev_data.len() < 7 {
        tester_warn("Invalid user confirm request event");
        return;
    }

    tester_print("User Confirm Request, accepting");

    // Build user confirm reply: addr_info (6 bytes addr + 1 byte type)
    let reply_data = ev_data[..7].to_vec();

    let mgmt_index = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.mgmt_index
    };

    let state_clone = state.clone();
    tokio::spawn(async move {
        let mgmt = {
            let s = state_clone.lock().unwrap_or_else(|e| e.into_inner());
            s.mgmt.clone()
        };
        if let Some(mgmt) = mgmt {
            match mgmt.send_command(MGMT_OP_USER_CONFIRM_REPLY, mgmt_index, &reply_data).await {
                Ok(_) => tester_print("User Confirm Reply sent successfully"),
                Err(e) => tester_warn(&format!("User Confirm Reply failed: {e}")),
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Lifecycle Functions
// ---------------------------------------------------------------------------

/// Pre-setup: Create MgmtSocket, subscribe to INDEX_ADDED, create HciEmulator,
/// wait for controller index, send READ_INFO.
/// Mirrors C test_pre_setup (tools/smp-tester.c:116-170).
fn test_pre_setup(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => s.clone(),
        None => {
            tester_pre_setup_failed();
            return;
        }
    };

    tokio::spawn(async move {
        // Create MGMT socket (synchronous)
        let mgmt: Arc<MgmtSocket> = match MgmtSocket::new_default() {
            Ok(m) => Arc::new(m),
            Err(e) => {
                tester_warn(&format!("Failed to create MgmtSocket: {e}"));
                tester_pre_setup_failed();
                return;
            }
        };

        {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.mgmt = Some(mgmt.clone());
        }

        // Subscribe to INDEX_ADDED events (subscribe returns tuple directly)
        let (idx_add_id, mut idx_rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

        // Create HCI emulator
        let hciemu_type = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.hciemu_type
        };
        let mut emu = match HciEmulator::new(hciemu_type) {
            Ok(e) => e,
            Err(e) => {
                tester_warn(&format!("Failed to create HciEmulator: {e}"));
                tester_pre_setup_failed();
                return;
            }
        };

        emu.set_debug(print_debug);

        {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.hciemu = Some(emu);
        }

        // Wait for INDEX_ADDED event
        match tokio::time::timeout(std::time::Duration::from_secs(5), idx_rx.recv()).await {
            Ok(Some(ev)) => {
                let index = if ev.index != MGMT_INDEX_NONE { ev.index } else { 0 };
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.mgmt_index = index;
                tester_print(&format!("Controller index: {index}"));
            }
            _ => {
                tester_warn("Timeout waiting for INDEX_ADDED");
                tester_pre_setup_failed();
                return;
            }
        }

        // Unsubscribe from INDEX_ADDED (returns bool)
        mgmt.unsubscribe(idx_add_id).await;

        // Send READ_INFO
        let mgmt_index = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.mgmt_index
        };
        match mgmt.send_command(MGMT_OP_READ_INFO, mgmt_index, &[]).await {
            Ok(resp) => {
                if resp.status == MGMT_STATUS_SUCCESS && resp.data.len() >= 280 {
                    // Extract current settings at offset 10 (4 bytes LE)
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    let addr: [u8; 6] = resp.data[0..6].try_into().unwrap_or([0u8; 6]);
                    s.ra = addr;
                    s.ra_type = BDADDR_LE_PUBLIC;
                    tester_print(&format!(
                        "Controller address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
                    ));
                } else {
                    tester_warn("READ_INFO failed or short response");
                }
            }
            Err(e) => {
                tester_warn(&format!("READ_INFO command failed: {e}"));
                tester_pre_setup_failed();
                return;
            }
        }

        tester_pre_setup_complete();
    });
}

/// Post-teardown: Clean up emulator and MGMT.
/// Mirrors C test_post_teardown (tools/smp-tester.c:172-190).
fn test_post_teardown(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => s.clone(),
        None => {
            tester_post_teardown_complete();
            return;
        }
    };

    tokio::spawn(async move {
        // Extract mgmt Arc before dropping mutex for async call
        let mgmt = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.mgmt.clone()
        };
        if let Some(mgmt) = mgmt {
            let _ = mgmt.cancel_all().await;
        }
        {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.hciemu = None;
            s.mgmt = None;
        }
        tester_post_teardown_complete();
    });
}

// ---------------------------------------------------------------------------
// Setup functions
// ---------------------------------------------------------------------------

/// Send a MGMT mode command (SET_LE, SET_BONDABLE, SET_SSP, etc.)
async fn send_mode(mgmt: &MgmtSocket, opcode: u16, index: u16, val: u8) -> bool {
    let param = [val, 0x00]; // mgmt_mode { val, reserved }
    match mgmt.send_command(opcode, index, &param).await {
        Ok(r) => r.status == MGMT_STATUS_SUCCESS,
        Err(_) => false,
    }
}

/// setup_powered_server: Powers on the controller in server (peripheral) mode.
/// Mirrors C setup_powered_server (tools/smp-tester.c:842-872).
fn setup_powered_server(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => s.clone(),
        None => {
            tester_setup_failed();
            return;
        }
    };

    tokio::spawn(async move {
        let (mgmt, index, sc) = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let m = s.mgmt.clone();
            let i = s.mgmt_index;
            let sc = s.smp_data.sc;
            (m, i, sc)
        };

        let mgmt = match mgmt {
            Some(m) => m,
            None => {
                tester_setup_failed();
                return;
            }
        };

        // Register user confirm callback (subscribe returns tuple directly)
        {
            let state_ev = state.clone();
            let (_, mut rx) = mgmt.subscribe(MGMT_EV_USER_CONFIRM_REQUEST, index).await;
            tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    user_confirm_request_callback(&state_ev, &ev.data);
                }
            });
        }

        // Send MGMT setup commands
        if !send_mode(&mgmt, MGMT_OP_SET_LE, index, 0x01).await {
            tester_setup_failed();
            return;
        }
        if !send_mode(&mgmt, MGMT_OP_SET_BONDABLE, index, 0x01).await {
            tester_setup_failed();
            return;
        }
        if !send_mode(&mgmt, MGMT_OP_SET_CONNECTABLE, index, 0x01).await {
            tester_setup_failed();
            return;
        }
        if !send_mode(&mgmt, MGMT_OP_SET_ADVERTISING, index, 0x01).await {
            tester_setup_failed();
            return;
        }

        if sc {
            if !send_mode(&mgmt, MGMT_OP_SET_SSP, index, 0x01).await {
                tester_setup_failed();
                return;
            }
            if !send_mode(&mgmt, MGMT_OP_SET_SECURE_CONN, index, 0x01).await {
                tester_setup_failed();
                return;
            }
            make_pk(&state);
        }

        // SET_POWERED
        if !send_mode(&mgmt, MGMT_OP_SET_POWERED, index, 0x01).await {
            tester_setup_failed();
            return;
        }

        tester_setup_complete();
    });
}

/// setup_powered_client: Powers on the controller in client (central) mode.
/// Mirrors C setup_powered_client (tools/smp-tester.c:498-526).
fn setup_powered_client(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => s.clone(),
        None => {
            tester_setup_failed();
            return;
        }
    };

    tokio::spawn(async move {
        let (mgmt, index, sc) = {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let m = s.mgmt.clone();
            let i = s.mgmt_index;
            let sc = s.smp_data.sc;
            (m, i, sc)
        };

        let mgmt = match mgmt {
            Some(m) => m,
            None => {
                tester_setup_failed();
                return;
            }
        };

        // Register user confirm callback (subscribe returns tuple directly)
        {
            let state_ev = state.clone();
            let (_, mut rx) = mgmt.subscribe(MGMT_EV_USER_CONFIRM_REQUEST, index).await;
            tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    user_confirm_request_callback(&state_ev, &ev.data);
                }
            });
        }

        // Send MGMT setup commands
        if !send_mode(&mgmt, MGMT_OP_SET_LE, index, 0x01).await {
            tester_setup_failed();
            return;
        }
        if !send_mode(&mgmt, MGMT_OP_SET_BONDABLE, index, 0x01).await {
            tester_setup_failed();
            return;
        }

        if sc {
            if !send_mode(&mgmt, MGMT_OP_SET_SSP, index, 0x01).await {
                tester_setup_failed();
                return;
            }
            if !send_mode(&mgmt, MGMT_OP_SET_SECURE_CONN, index, 0x01).await {
                tester_setup_failed();
                return;
            }
            make_pk(&state);
        }

        // SET_POWERED, then configure bthost for advertising
        if !send_mode(&mgmt, MGMT_OP_SET_POWERED, index, 0x01).await {
            tester_setup_failed();
            return;
        }

        // Enable advertising on the bthost (emulator client)
        {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(emu) = s.hciemu.as_ref() {
                if let Some(mut host) = emu.client_get_host() {
                    host.write_le_host_supported(0x01);
                    host.set_adv_enable(0x01);
                }
            }
        }

        tester_setup_complete();
    });
}

// ---------------------------------------------------------------------------
// Test execution functions
// ---------------------------------------------------------------------------

/// test_server: Execute server-side SMP test.
/// Mirrors C test_server (tools/smp-tester.c:874-896).
fn test_server(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => s.clone(),
        None => {
            tester_test_failed();
            return;
        }
    };

    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.out = true;
    }

    init_bdaddr(&state);

    // Register connection callback on bthost
    let state_conn = state.clone();
    {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(emu) = s.hciemu.as_ref() {
            if let Some(mut host) = emu.client_get_host() {
                host.set_connect_cb(move |handle| {
                    smp_new_conn(&state_conn, handle);
                });
            }
        }
    }

    // Add condition: SMP exchange must complete
    test_add_condition(&state);

    // Connect to the DUT's address from the emulator client
    let (ra, expect_hci) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        (s.ra, s.smp_data.expect_hci_command)
    };
    {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(emu) = s.hciemu.as_ref() {
            if let Some(mut host) = emu.client_get_host() {
                host.hci_connect(&ra, BDADDR_LE_PUBLIC);
            }
        }
    }

    // If the test expects a specific HCI command, register a post-command hook
    if expect_hci != 0 {
        let state_hook = state.clone();
        test_add_condition(&state);
        {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(emu) = s.hciemu.as_mut() {
                emu.add_central_post_command_hook(move |opcode, _data| {
                    if opcode == expect_hci {
                        tester_print(&format!("Expected HCI command 0x{opcode:04x} received"));
                        test_condition_complete(&state_hook);
                    }
                });
            }
        }
    }
}

/// test_client: Execute client-side SMP test (MGMT pairing).
/// Mirrors C test_client (tools/smp-tester.c:796-827).
fn test_client(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => s.clone(),
        None => {
            tester_test_failed();
            return;
        }
    };

    init_bdaddr(&state);

    // Register connection callback on bthost
    let state_conn = state.clone();
    {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(emu) = s.hciemu.as_ref() {
            if let Some(mut host) = emu.client_get_host() {
                host.set_connect_cb(move |handle| {
                    smp_new_conn(&state_conn, handle);
                });
            }
        }
    }

    // Add condition: SMP exchange must complete
    test_add_condition(&state);

    // Build PAIR_DEVICE command param
    // io_cap: 0x04 (KeyboardDisplay) for MITM, 0x03 (NoInputNoOutput) otherwise
    let (ra, mgmt_index, io_cap) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        let cap = if s.smp_data.mitm { 0x04_u8 } else { 0x03_u8 };
        (s.ra, s.mgmt_index, cap)
    };

    // mgmt_cp_pair_device: addr (6) + addr_type (1) + io_cap (1)
    let mut pair_param = Vec::with_capacity(8);
    pair_param.extend_from_slice(&ra);
    pair_param.push(BDADDR_LE_PUBLIC);
    pair_param.push(io_cap);

    let state_pair = state.clone();
    tokio::spawn(async move {
        let mgmt = {
            let s = state_pair.lock().unwrap_or_else(|e| e.into_inner());
            s.mgmt.clone()
        };
        if let Some(mgmt) = mgmt {
            match mgmt.send_command(MGMT_OP_PAIR_DEVICE, mgmt_index, &pair_param).await {
                Ok(r) => {
                    tester_print(&format!("Pair Device complete, status: {}", r.status));
                }
                Err(e) => {
                    tester_warn(&format!("Pair Device failed: {e}"));
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Main: register all 8 test cases and run the tester.
// Mirrors C main (tools/smp-tester.c:898-930).
// ---------------------------------------------------------------------------

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    // Helper to create Arc callbacks for the tester framework
    fn make_cb<F>(f: F) -> TestCb
    where
        F: Fn(&dyn Any) + Send + Sync + 'static,
    {
        Some(Arc::new(f) as Arc<dyn Fn(&dyn Any) + Send + Sync>)
    }

    // ---------------------------------------------------------------------------
    // Server tests (setup_powered_server + test_server)
    // ---------------------------------------------------------------------------

    // 1. "SMP Server - Basic Request 1"
    tester_add_full(
        "SMP Server - Basic Request 1",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_SERVER_BASIC_REQ_1_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_server),
        make_cb(test_server),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // 2. "SMP Server - Invalid Request 1"
    tester_add_full(
        "SMP Server - Invalid Request 1",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_SERVER_NVAL_REQ_1_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_server),
        make_cb(test_server),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // 3. "SMP Server - Invalid Request 2"
    tester_add_full(
        "SMP Server - Invalid Request 2",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_SERVER_NVAL_REQ_2_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_server),
        make_cb(test_server),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // 4. "SMP Server - Invalid Request 3"
    tester_add_full(
        "SMP Server - Invalid Request 3",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_SERVER_NVAL_REQ_3_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_server),
        make_cb(test_server),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // ---------------------------------------------------------------------------
    // Client tests (setup_powered_client + test_client)
    // ---------------------------------------------------------------------------

    // 5. "SMP Client - Basic Request 1"
    tester_add_full(
        "SMP Client - Basic Request 1",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_CLIENT_BASIC_REQ_1_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_client),
        make_cb(test_client),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // 6. "SMP Client - Basic Request 2"
    tester_add_full(
        "SMP Client - Basic Request 2",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_CLIENT_BASIC_REQ_2_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_client),
        make_cb(test_client),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // 7. "SMP Client - SC Request 1"
    tester_add_full(
        "SMP Client - SC Request 1",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_CLIENT_SC_REQ_1_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_client),
        make_cb(test_client),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // 8. "SMP Client - SC Request 2"
    tester_add_full(
        "SMP Client - SC Request 2",
        Some(Arc::new(Mutex::new(TestState::new(&SMP_CLIENT_SC_REQ_2_TEST))) as SharedState),
        make_cb(test_pre_setup),
        make_cb(setup_powered_client),
        make_cb(test_client),
        None,
        make_cb(test_post_teardown),
        30,
        None::<()>,
    );

    // Run all registered tests
    let exit_code = tester_run();
    std::process::exit(exit_code);
}
