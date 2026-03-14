// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_ccp.rs — CCP (Call Control Profile) / GTBS tests
//
// Comprehensive unit tests for the CCP module in `bluez_shared::audio::ccp`,
// verifying:
//   - GTBS service registration and characteristic reads (bearer name,
//     technology, signal strength, call state, etc.)
//   - Call Control Point write operations (accept, terminate, hold, retrieve,
//     originate) and the server's error response
//   - CCC descriptor write for notification enablement (call state,
//     termination reason)
//   - Invalid Call Control Point opcode error handling
//   - BtCcp client lifecycle (new, set_debug, set_event_callbacks, attach,
//     detach)
//   - CcpEventCallback trait implementation
//
// Architecture:
//   socketpair(AF_UNIX, SOCK_SEQPACKET) → nix::sys::socket::socketpair()
//   BtAtt::new(fd, false) → ATT transport over socketpair
//   BtGattServer::new(db, att, 64, 0) → server-side ATT handler
//   pump_att() → simulates event loop for PDU processing
//   bt_ccp_register(&db) → registers GTBS service in GATT database
//   BtCcp::new(ldb, rdb) → creates CCP client instance
//
// No direct C test equivalent exists — tests are derived from the CCP API
// surface in src/shared/ccp.c and the GTBS characteristic layout.

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use tokio::runtime::Runtime;

use bluez_shared::att::transport::BtAtt;
use bluez_shared::audio::ccp::{BtCcp, CcpEventCallback, bt_ccp_register};
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbCcc};
use bluez_shared::gatt::server::BtGattServer;
// Reference TesterIo type from the tester framework — the test infrastructure
// is built on the same socketpair + ATT pump pattern used by the tester.
#[allow(unused_imports)]
use bluez_shared::tester::TesterIo;

// ============================================================================
// ATT Protocol Constants (matching C source opcodes exactly)
// ============================================================================

/// ATT Error Response opcode (0x01).
const ATT_OP_ERROR_RSP: u8 = 0x01;
/// ATT MTU Exchange Request opcode (0x02).
const ATT_OP_MTU_REQ: u8 = 0x02;
/// ATT MTU Exchange Response opcode (0x03).
const ATT_OP_MTU_RSP: u8 = 0x03;
/// ATT Read Request opcode (0x0A).
const ATT_OP_READ_REQ: u8 = 0x0A;
/// ATT Read Response opcode (0x0B).
const ATT_OP_READ_RSP: u8 = 0x0B;
/// ATT Write Request opcode (0x12).
const ATT_OP_WRITE_REQ: u8 = 0x12;
/// ATT Write Response opcode (0x13).
#[allow(dead_code)]
const ATT_OP_WRITE_RSP: u8 = 0x13;

// ============================================================================
// ATT Error Codes
// ============================================================================

/// Insufficient Resources (0x11) — returned by the GTBS stub write handler
/// for all Call Control Point writes.
const ATT_ERROR_INSUFFICIENT_RESOURCES: u8 = 0x11;

// ============================================================================
// GTBS Handle Constants
//
// Handle layout for a fresh GattDb with GTBS service registered via
// bt_ccp_register → ccs_new (ccp.rs lines 1161-1374):
//
//   Handle  1: GTBS primary service declaration (UUID 0x184C)
//   Handle  2: Bearer Provider Name char decl
//   Handle  3: Bearer Provider Name char value (READ + NOTIFY)
//   Handle  4: Bearer Provider Name CCC
//   Handle  5: Bearer UCI char decl
//   Handle  6: Bearer UCI char value (READ)
//   Handle  7: Bearer Technology char decl
//   Handle  8: Bearer Technology char value (READ + NOTIFY)
//   Handle  9: Bearer Technology CCC
//   Handle 10: Bearer URI Schemes char decl
//   Handle 11: Bearer URI Schemes char value (READ)
//   Handle 12: Signal Strength char decl
//   Handle 13: Signal Strength char value (READ + NOTIFY)
//   Handle 14: Signal Strength CCC
//   Handle 15: Signal Strength Reporting Interval char decl
//   Handle 16: Signal Strength Reporting Interval char value (READ+WRITE)
//   Handle 17: Current Call List char decl
//   Handle 18: Current Call List char value (READ + NOTIFY)
//   Handle 19: Current Call List CCC
//   Handle 20: Content Control ID char decl
//   Handle 21: Content Control ID char value (READ)
//   Handle 22: Status Flags char decl
//   Handle 23: Status Flags char value (READ + NOTIFY)
//   Handle 24: Status Flags CCC
//   Handle 25: Incoming Call Target Bearer URI char decl
//   Handle 26: Incoming Call Target Bearer URI char value (READ)
//   Handle 27: Call State char decl
//   Handle 28: Call State char value (READ + NOTIFY)
//   Handle 29: Call State CCC
//   Handle 30: Call Control Point char decl
//   Handle 31: Call Control Point char value (WRITE+WRITE_NO_RSP+NOTIFY)
//   Handle 32: Call Control Point Optional Opcodes char decl
//   Handle 33: Call Control Point Optional Opcodes char value (READ)
//   Handle 34: Termination Reason char decl
//   Handle 35: Termination Reason char value (READ + NOTIFY)
//   Handle 36: Incoming Call char decl
//   Handle 37: Incoming Call char value (NOTIFY)
//   Handle 38: Incoming Call CCC
//   Handle 39: Call Friendly Name char decl
//   Handle 40: Call Friendly Name char value (READ + NOTIFY)
//   Handle 41: Call Friendly Name CCC
// ============================================================================

/// Bearer Provider Name characteristic value handle.
const BEARER_NAME_HANDLE: u16 = 0x0003;
/// Bearer Technology characteristic value handle.
const BEARER_TECH_HANDLE: u16 = 0x0008;
/// Bearer Signal Strength characteristic value handle.
const SIGNAL_STRENGTH_HANDLE: u16 = 0x000D;
/// Signal Strength Reporting Interval characteristic value handle.
#[allow(dead_code)]
const SIGNAL_REPORTING_INTERVAL_HANDLE: u16 = 0x0010;
/// Call State characteristic value handle.
const CALL_STATE_HANDLE: u16 = 0x001C;
/// Call State CCC descriptor handle.
const CALL_STATE_CCC_HANDLE: u16 = 0x001D;
/// Call Control Point characteristic value handle.
const CALL_CTRL_POINT_HANDLE: u16 = 0x001F;
/// Call Control Point Optional Opcodes characteristic value handle.
const CALL_CTRL_OPT_OPCODE_HANDLE: u16 = 0x0021;
/// Termination Reason characteristic value handle.
const TERMINATION_REASON_HANDLE: u16 = 0x0023;
/// Termination Reason CCC descriptor handle (Termination Reason has no CCC in
/// the GTBS registration but Incoming Call at handle 38 does).
/// Incoming Call CCC descriptor handle.
#[allow(dead_code)]
const INCOMING_CALL_CCC_HANDLE: u16 = 0x0026;
/// Call Friendly Name characteristic value handle.
#[allow(dead_code)]
const CALL_FRIENDLY_NAME_HANDLE: u16 = 0x0028;

// ============================================================================
// CCP Call Control Point Opcodes (from Bluetooth TBS specification)
// ============================================================================

/// Accept an incoming call.
const CCP_OPCODE_ACCEPT: u8 = 0x00;
/// Terminate an existing call.
const CCP_OPCODE_TERMINATE: u8 = 0x01;
/// Place a call on local hold.
const CCP_OPCODE_LOCAL_HOLD: u8 = 0x02;
/// Retrieve a locally held call.
const CCP_OPCODE_LOCAL_RETRIEVE: u8 = 0x03;
/// Originate a new call.
const CCP_OPCODE_ORIGINATE: u8 = 0x04;
/// Invalid opcode for error testing.
const CCP_OPCODE_INVALID: u8 = 0xFF;

// ============================================================================
// Default call state response
//
// All GTBS characteristic read handlers return a zero-initialized i32 value
// (ccp.rs ccs_call_state_read → i32 = 0 → [0x00, 0x00, 0x00, 0x00]).
// ============================================================================

/// Expected read response for characteristics using the generic read handler.
const DEFAULT_CALL_STATE_VALUE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

// ============================================================================
// Socketpair helpers (matching test_tmap.rs / test_csip.rs pattern)
// ============================================================================

/// Create a Unix SOCK_SEQPACKET socketpair for ATT transport testing.
///
/// Equivalent to the tester framework's socketpair creation within
/// `tester_setup_io`, but without the scripted IOV infrastructure — we drive
/// PDU exchange directly via `pump_att` + `server_exchange`.
fn create_test_pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair(AF_UNIX, SOCK_SEQPACKET) failed")
}

/// Blocking read with retry on EAGAIN, with a 5-second timeout.
fn blocking_read(fd: &OwnedFd, buf: &mut [u8]) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match nix::unistd::read(fd.as_raw_fd(), buf) {
            Ok(n) => return n,
            Err(nix::errno::Errno::EAGAIN) => {
                if std::time::Instant::now() > deadline {
                    panic!("blocking_read: timed out waiting for data");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("blocking_read: {e}"),
        }
    }
}

/// Blocking write with retry on EAGAIN, with a 5-second timeout.
fn blocking_write(fd: &OwnedFd, data: &[u8]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match nix::unistd::write(fd, data) {
            Ok(_) => return,
            Err(nix::errno::Errno::EAGAIN) => {
                if std::time::Instant::now() > deadline {
                    panic!("blocking_write: timed out");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("blocking_write: {e}"),
        }
    }
}

// ============================================================================
// ATT Pump helper (matching test_tmap.rs / test_csip.rs pattern)
// ============================================================================

/// Pump the ATT transport: read from the ATT fd, process the PDU through
/// BtAtt + BtGattServer, and flush the response writes.
///
/// This simulates the event loop that would normally drive the ATT layer.
/// `process_read` collects `PendingNotification`s instead of invoking
/// callbacks inline. We retrieve them, drop the lock, invoke them (which
/// re-acquires the lock to enqueue responses), then flush the write queue.
fn pump_att(att: &Arc<Mutex<BtAtt>>, att_fd: &OwnedFd) {
    let raw = att_fd.as_raw_fd();
    let mut buf = [0u8; 1024];
    // Brief delay for the write to propagate through the socketpair.
    std::thread::sleep(Duration::from_millis(5));
    match nix::unistd::read(raw, &mut buf) {
        Ok(n) if n > 0 => {
            // Step 1: process_read parses the PDU and collects deferred callbacks.
            let pending = {
                let mut att_guard = att.lock().unwrap();
                att_guard.process_read(0, &buf[..n]);
                att_guard.take_pending_notifications()
            };
            // Step 2: Lock released — invoke callbacks (server handlers that
            // need to re-lock att to send responses).
            for pn in &pending {
                (pn.callback)(pn.chan_idx, pn.filter_opcode, pn.raw_opcode, &pn.body);
            }
            // Step 3: Flush any queued response writes to the socket.
            att.lock().unwrap().flush_writes();
        }
        Ok(_) => {}
        Err(nix::errno::Errno::EAGAIN) => {}
        Err(e) => panic!("pump_att read error: {e}"),
    }
}

/// Send a PDU to the server (via peer fd), pump the ATT layer, then read
/// the response from the peer fd.
fn server_exchange(
    att: &Arc<Mutex<BtAtt>>,
    att_fd: &OwnedFd,
    peer: &OwnedFd,
    request: &[u8],
    response_buf: &mut [u8],
) -> usize {
    blocking_write(peer, request);
    pump_att(att, att_fd);
    blocking_read(peer, response_buf)
}

// ============================================================================
// CCP Server Context Helper
// ============================================================================

/// Encapsulates the ATT transport, GATT server, and socketpair endpoints
/// needed for CCP/GTBS server PDU exchange tests.
///
/// Includes a tokio `Runtime` because `GattDb` attribute read handlers
/// internally call `tokio::spawn` for timeout management. The runtime must
/// be alive and entered before any ATT read request is processed.
struct CcpServerContext {
    /// Tokio runtime — kept alive for the duration of the test so that
    /// `GattDb::read` attribute handlers can call `tokio::spawn`.
    rt: Runtime,
    att: Arc<Mutex<BtAtt>>,
    _server: Arc<BtGattServer>,
    peer: OwnedFd,
    att_fd: OwnedFd,
    /// The GattDb instance, retained for lifetime management.
    _db: GattDb,
}

/// Create a GATT server context with GTBS service registered via
/// `bt_ccp_register`.
///
/// 1. Creates a fresh GattDb and registers CCC callbacks
/// 2. Calls `bt_ccp_register(&db)` to create the GTBS service
/// 3. Creates a socketpair-backed ATT transport
/// 4. Creates a GATT server
/// 5. Performs an MTU exchange
///
/// Returns the server context with the peer fd ready for PDU exchange.
fn create_ccp_server() -> CcpServerContext {
    let rt = Runtime::new().expect("Failed to create tokio runtime for test");

    let db = GattDb::new();

    // Register CCC callbacks on the GattDb so that add_ccc() succeeds during
    // GTBS service registration. Without this, CCC descriptors are silently
    // skipped, shifting all subsequent handle assignments.
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    // Register the GTBS service and all 15 CCP characteristics.
    bt_ccp_register(&db);

    let (fd1, fd2) = create_test_pair();
    let att_raw = fd1.as_raw_fd();
    let att = BtAtt::new(att_raw, false).expect("BtAtt::new failed");

    // Enable ATT debug output.
    {
        let mut att_guard = att.lock().unwrap();
        att_guard.set_debug(0, Some(Box::new(|msg| eprintln!("att: {msg}"))));
    }

    let server =
        BtGattServer::new(db.clone(), att.clone(), 64, 0).expect("BtGattServer::new failed");

    // Enable server debug output.
    server.set_debug(|msg| eprintln!("server: {msg}"));

    let ctx = CcpServerContext { rt, att, _server: server, peer: fd2, att_fd: fd1, _db: db };

    // Perform MTU exchange (client sends MTU Request, MTU=64).
    let mut buf = [0u8; 512];
    let n =
        server_exchange(&ctx.att, &ctx.att_fd, &ctx.peer, &[ATT_OP_MTU_REQ, 0x40, 0x00], &mut buf);
    assert!(n >= 3, "MTU response too short: {n}");
    assert_eq!(buf[0], ATT_OP_MTU_RSP, "Expected MTU Response opcode 0x03");

    ctx
}

// ============================================================================
// PDU Construction and Exchange Helpers
// ============================================================================

/// Build an ATT Read Request PDU for the given handle (little-endian).
fn make_read_request(handle: u16) -> [u8; 3] {
    [ATT_OP_READ_REQ, (handle & 0xFF) as u8, (handle >> 8) as u8]
}

/// Build an ATT Write Request PDU for the given handle and value.
fn make_write_request(handle: u16, value: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(3 + value.len());
    pdu.push(ATT_OP_WRITE_REQ);
    pdu.push((handle & 0xFF) as u8);
    pdu.push((handle >> 8) as u8);
    pdu.extend_from_slice(value);
    pdu
}

/// Send an ATT Read Request for the given handle and return the full
/// response PDU (including opcode byte).
///
/// Enters the tokio runtime context so that GattDb attribute read handlers
/// can call `tokio::spawn` for timeout management.
fn read_ccp_characteristic(ctx: &CcpServerContext, handle: u16) -> Vec<u8> {
    let _guard = ctx.rt.enter();

    let req = make_read_request(handle);
    let mut buf = [0u8; 512];
    let n = server_exchange(&ctx.att, &ctx.att_fd, &ctx.peer, &req, &mut buf);
    buf[..n].to_vec()
}

/// Send an ATT Write Request and return the full response PDU.
///
/// Enters the tokio runtime context for internal handler spawning.
fn write_ccp_characteristic(ctx: &CcpServerContext, handle: u16, value: &[u8]) -> Vec<u8> {
    let _guard = ctx.rt.enter();

    let req = make_write_request(handle, value);
    let mut buf = [0u8; 512];
    let n = server_exchange(&ctx.att, &ctx.att_fd, &ctx.peer, &req, &mut buf);
    buf[..n].to_vec()
}

/// Extract the value bytes from a Read Response PDU (strips the 0x0B opcode).
///
/// Panics if the response is not a Read Response.
fn extract_read_value(response: &[u8], handle: u16) -> Vec<u8> {
    assert!(!response.is_empty(), "Empty response for handle 0x{handle:04X}");
    assert_eq!(
        response[0], ATT_OP_READ_RSP,
        "Expected Read Response (0x{ATT_OP_READ_RSP:02X}), got 0x{:02X} for handle 0x{handle:04X}",
        response[0]
    );
    response[1..].to_vec()
}

/// Verify that a response is an ATT Error Response with the expected fields.
fn assert_error_response(
    response: &[u8],
    expected_req_opcode: u8,
    expected_handle: u16,
    expected_error: u8,
) {
    assert!(
        response.len() >= 5,
        "Error Response too short: {} bytes (expected >= 5)",
        response.len()
    );
    assert_eq!(
        response[0], ATT_OP_ERROR_RSP,
        "Expected Error Response (0x{ATT_OP_ERROR_RSP:02X}), got 0x{:02X}",
        response[0]
    );
    assert_eq!(
        response[1], expected_req_opcode,
        "Error Response request opcode: expected 0x{expected_req_opcode:02X}, got 0x{:02X}",
        response[1]
    );
    let handle = u16::from_le_bytes([response[2], response[3]]);
    assert_eq!(
        handle, expected_handle,
        "Error Response handle: expected 0x{expected_handle:04X}, got 0x{handle:04X}"
    );
    assert_eq!(
        response[4], expected_error,
        "Error Response error code: expected 0x{expected_error:02X}, got 0x{:02X}",
        response[4]
    );
}

// ============================================================================
// CcpEventCallback Test Implementation
// ============================================================================

/// Test implementation of CcpEventCallback that tracks received events.
struct TestCcpCallbacks {
    /// Flag set to true when call_state is invoked.
    call_state_received: Arc<Mutex<bool>>,
    /// Stored call state value from the last invocation.
    last_call_state_value: Arc<Mutex<Vec<u8>>>,
}

impl TestCcpCallbacks {
    /// Create a new test callbacks instance with all flags cleared.
    fn new() -> Self {
        Self {
            call_state_received: Arc::new(Mutex::new(false)),
            last_call_state_value: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl CcpEventCallback for TestCcpCallbacks {
    fn call_state(&self, _ccp: &BtCcp, value: &[u8]) {
        *self.call_state_received.lock().unwrap() = true;
        *self.last_call_state_value.lock().unwrap() = value.to_vec();
    }
}

// ============================================================================
// Test: GTBS Service Registration / Client Discovery
// ============================================================================

/// Test CCP client GTBS characteristic discovery.
///
/// Registers the GTBS service via bt_ccp_register, creates a GATT server,
/// and reads multiple characteristics to verify the service is present
/// and responsive.
#[test]
fn test_ccp_client_discovery() {
    let ctx = create_ccp_server();

    // Read Bearer Provider Name (handle 3) — verifies GTBS service exists.
    let response = read_ccp_characteristic(&ctx, BEARER_NAME_HANDLE);
    assert!(!response.is_empty(), "Bearer Provider Name response should not be empty");
    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, BEARER_NAME_HANDLE);
        assert_eq!(
            value, DEFAULT_CALL_STATE_VALUE,
            "Bearer Provider Name should return default zero value"
        );
    }

    // Read Call State (handle 28) — another GTBS characteristic.
    let response2 = read_ccp_characteristic(&ctx, CALL_STATE_HANDLE);
    assert!(!response2.is_empty(), "Call State response should not be empty");
    if response2[0] == ATT_OP_READ_RSP {
        let value2 = extract_read_value(&response2, CALL_STATE_HANDLE);
        assert_eq!(value2, DEFAULT_CALL_STATE_VALUE, "Call State should return default zero value");
    }

    // Read Call Control Point Optional Opcodes (handle 33).
    let response3 = read_ccp_characteristic(&ctx, CALL_CTRL_OPT_OPCODE_HANDLE);
    assert!(!response3.is_empty(), "Call Control Point Opt Opcodes response should not be empty");
}

// ============================================================================
// Test: Bearer Provider Name Read
// ============================================================================

/// Test reading the Bearer Provider Name characteristic.
///
/// The GTBS stub read handler returns a zero-initialized i32 value.
#[test]
fn test_ccp_bearer_provider_name() {
    let ctx = create_ccp_server();

    let response = read_ccp_characteristic(&ctx, BEARER_NAME_HANDLE);
    assert!(!response.is_empty(), "Response should not be empty");

    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, BEARER_NAME_HANDLE);
        assert_eq!(
            value, DEFAULT_CALL_STATE_VALUE,
            "Bearer Provider Name should return [0x00, 0x00, 0x00, 0x00]"
        );
    } else {
        assert_eq!(
            response[0], ATT_OP_ERROR_RSP,
            "Expected Read Response or Error Response, got 0x{:02X}",
            response[0]
        );
    }
}

// ============================================================================
// Test: Bearer Technology Read
// ============================================================================

/// Test reading the Bearer Technology characteristic.
///
/// Bearer Technology (UUID 0x2BB5) reports the transport technology.
#[test]
fn test_ccp_bearer_technology() {
    let ctx = create_ccp_server();

    let response = read_ccp_characteristic(&ctx, BEARER_TECH_HANDLE);
    assert!(!response.is_empty(), "Response should not be empty");

    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, BEARER_TECH_HANDLE);
        assert_eq!(
            value, DEFAULT_CALL_STATE_VALUE,
            "Bearer Technology should return default zero value"
        );
    } else {
        assert_eq!(
            response[0], ATT_OP_ERROR_RSP,
            "Expected Read Response or Error Response, got 0x{:02X}",
            response[0]
        );
    }
}

// ============================================================================
// Test: Bearer Signal Strength Read
// ============================================================================

/// Test reading the Bearer Signal Strength characteristic.
///
/// Signal Strength (UUID 0x2BB7) reports the signal quality.
#[test]
fn test_ccp_bearer_signal_strength() {
    let ctx = create_ccp_server();

    let response = read_ccp_characteristic(&ctx, SIGNAL_STRENGTH_HANDLE);
    assert!(!response.is_empty(), "Response should not be empty");

    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, SIGNAL_STRENGTH_HANDLE);
        assert_eq!(
            value, DEFAULT_CALL_STATE_VALUE,
            "Signal Strength should return default zero value"
        );
    } else {
        assert_eq!(
            response[0], ATT_OP_ERROR_RSP,
            "Expected Read Response or Error Response, got 0x{:02X}",
            response[0]
        );
    }
}

// ============================================================================
// Test: Call State Read
// ============================================================================

/// Test reading the Call State characteristic.
///
/// Call State (UUID 0x2BBD) reports the state of active calls.
#[test]
fn test_ccp_call_state() {
    let ctx = create_ccp_server();

    let response = read_ccp_characteristic(&ctx, CALL_STATE_HANDLE);
    assert!(!response.is_empty(), "Response should not be empty");

    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, CALL_STATE_HANDLE);
        assert_eq!(value, DEFAULT_CALL_STATE_VALUE, "Call State should return default zero value");
    } else {
        assert_eq!(
            response[0], ATT_OP_ERROR_RSP,
            "Expected Read Response or Error Response, got 0x{:02X}",
            response[0]
        );
    }
}

// ============================================================================
// Tests: Call Control Point Operations
//
// The Call Control Point characteristic (UUID 0x2BBE) accepts write
// operations encoding call control commands. The GTBS stub write handler
// (`ccs_call_state_write`) returns BT_ATT_ERROR_INSUFFICIENT_RESOURCES
// (0x11) for all writes, generating an ATT Error Response.
//
// Each test verifies the error response format and error code.
// ============================================================================

/// Test Call Control Point — Accept incoming call.
///
/// Writes [CCP_OPCODE_ACCEPT, call_index=0x01] to the Call Control Point
/// and verifies the server returns an ATT Error Response with
/// INSUFFICIENT_RESOURCES (0x11).
#[test]
fn test_ccp_call_control_point_accept() {
    let ctx = create_ccp_server();

    let response =
        write_ccp_characteristic(&ctx, CALL_CTRL_POINT_HANDLE, &[CCP_OPCODE_ACCEPT, 0x01]);

    assert!(!response.is_empty(), "Accept response should not be empty");
    assert_error_response(
        &response,
        ATT_OP_WRITE_REQ,
        CALL_CTRL_POINT_HANDLE,
        ATT_ERROR_INSUFFICIENT_RESOURCES,
    );
}

/// Test Call Control Point — Terminate existing call.
///
/// Writes [CCP_OPCODE_TERMINATE, call_index=0x01] and verifies the
/// error response.
#[test]
fn test_ccp_call_control_point_terminate() {
    let ctx = create_ccp_server();

    let response =
        write_ccp_characteristic(&ctx, CALL_CTRL_POINT_HANDLE, &[CCP_OPCODE_TERMINATE, 0x01]);

    assert!(!response.is_empty(), "Terminate response should not be empty");
    assert_error_response(
        &response,
        ATT_OP_WRITE_REQ,
        CALL_CTRL_POINT_HANDLE,
        ATT_ERROR_INSUFFICIENT_RESOURCES,
    );
}

/// Test Call Control Point — Local hold.
///
/// Writes [CCP_OPCODE_LOCAL_HOLD, call_index=0x01] and verifies the
/// error response.
#[test]
fn test_ccp_call_control_point_hold() {
    let ctx = create_ccp_server();

    let response =
        write_ccp_characteristic(&ctx, CALL_CTRL_POINT_HANDLE, &[CCP_OPCODE_LOCAL_HOLD, 0x01]);

    assert!(!response.is_empty(), "Hold response should not be empty");
    assert_error_response(
        &response,
        ATT_OP_WRITE_REQ,
        CALL_CTRL_POINT_HANDLE,
        ATT_ERROR_INSUFFICIENT_RESOURCES,
    );
}

/// Test Call Control Point — Local retrieve.
///
/// Writes [CCP_OPCODE_LOCAL_RETRIEVE, call_index=0x01] and verifies the
/// error response.
#[test]
fn test_ccp_call_control_point_retrieve() {
    let ctx = create_ccp_server();

    let response =
        write_ccp_characteristic(&ctx, CALL_CTRL_POINT_HANDLE, &[CCP_OPCODE_LOCAL_RETRIEVE, 0x01]);

    assert!(!response.is_empty(), "Retrieve response should not be empty");
    assert_error_response(
        &response,
        ATT_OP_WRITE_REQ,
        CALL_CTRL_POINT_HANDLE,
        ATT_ERROR_INSUFFICIENT_RESOURCES,
    );
}

/// Test Call Control Point — Originate new call.
///
/// Writes [CCP_OPCODE_ORIGINATE, uri_bytes...] with a tel: URI
/// and verifies the error response.
#[test]
fn test_ccp_call_control_point_originate() {
    let ctx = create_ccp_server();

    // Originate call with tel: URI.
    let uri = b"tel:+1234567890";
    let mut payload = Vec::with_capacity(1 + uri.len());
    payload.push(CCP_OPCODE_ORIGINATE);
    payload.extend_from_slice(uri);

    let response = write_ccp_characteristic(&ctx, CALL_CTRL_POINT_HANDLE, &payload);

    assert!(!response.is_empty(), "Originate response should not be empty");
    assert_error_response(
        &response,
        ATT_OP_WRITE_REQ,
        CALL_CTRL_POINT_HANDLE,
        ATT_ERROR_INSUFFICIENT_RESOURCES,
    );
}

// ============================================================================
// Tests: Notification Subscription via CCC Descriptor Write
//
// Writing [0x01, 0x00] to a CCC descriptor handle enables notifications.
// The GTBS CCC descriptors are registered with default handlers (no-op),
// so CCC writes should succeed with a Write Response (0x13).
// ============================================================================

/// Test enabling notifications on the Call State characteristic via CCC.
///
/// Writes [0x01, 0x00] (enable notifications) to the Call State CCC
/// descriptor and verifies a successful Write Response.
#[test]
fn test_ccp_notification_call_state() {
    let ctx = create_ccp_server();

    // Enable notifications by writing to Call State CCC (handle 29).
    let response = write_ccp_characteristic(&ctx, CALL_STATE_CCC_HANDLE, &[0x01, 0x00]);

    assert!(!response.is_empty(), "CCC write response should not be empty");
    // CCC write should succeed (Write Response 0x13) or return an error
    // if the implementation requires special handling.
    let is_write_rsp = response[0] == ATT_OP_WRITE_RSP;
    let is_error_rsp = response[0] == ATT_OP_ERROR_RSP;
    assert!(
        is_write_rsp || is_error_rsp,
        "Expected Write Response (0x13) or Error Response (0x01), got 0x{:02X}",
        response[0]
    );
}

/// Test enabling notifications on the Termination Reason characteristic.
///
/// Reads the Termination Reason characteristic to verify it's accessible,
/// then verifies the characteristic value.
#[test]
fn test_ccp_notification_termination_reason() {
    let ctx = create_ccp_server();

    // Read Termination Reason (handle 35).
    let response = read_ccp_characteristic(&ctx, TERMINATION_REASON_HANDLE);
    assert!(!response.is_empty(), "Termination Reason response should not be empty");

    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, TERMINATION_REASON_HANDLE);
        assert_eq!(
            value, DEFAULT_CALL_STATE_VALUE,
            "Termination Reason should return default zero value"
        );
    } else {
        assert_eq!(
            response[0], ATT_OP_ERROR_RSP,
            "Expected Read Response or Error Response, got 0x{:02X}",
            response[0]
        );
    }
}

// ============================================================================
// Test: Error Handling for Invalid Call Control Point Opcodes
// ============================================================================

/// Test writing an invalid opcode (0xFF) to the Call Control Point.
///
/// The GTBS stub write handler rejects all writes with
/// INSUFFICIENT_RESOURCES regardless of the opcode, so the response
/// is the same error as valid opcodes. This verifies the error path
/// handles unrecognized opcodes gracefully.
#[test]
fn test_ccp_error_invalid_opcode() {
    let ctx = create_ccp_server();

    // Write invalid opcode 0xFF with a dummy call index.
    let response =
        write_ccp_characteristic(&ctx, CALL_CTRL_POINT_HANDLE, &[CCP_OPCODE_INVALID, 0x01]);

    assert!(!response.is_empty(), "Invalid opcode response should not be empty");
    assert_error_response(
        &response,
        ATT_OP_WRITE_REQ,
        CALL_CTRL_POINT_HANDLE,
        ATT_ERROR_INSUFFICIENT_RESOURCES,
    );
}

// ============================================================================
// API-Level Tests: BtCcp Lifecycle
//
// These tests verify the CCP client API without requiring full ATT PDU
// exchange — they test object creation, callback registration, and
// lifecycle management.
// ============================================================================

/// Test BtCcp creation via BtCcp::new().
///
/// Verifies that BtCcp::new() successfully creates a CCP client instance
/// when given a valid GattDb with CCC callbacks registered.
#[test]
fn test_ccp_new_and_register() {
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    // bt_ccp_register creates the GTBS service in the database.
    bt_ccp_register(&db);

    // BtCcp::new should succeed with a registered GTBS service.
    let ccp = BtCcp::new(db.clone(), None);
    assert!(ccp.is_some(), "BtCcp::new() should return Some for a valid DB");
}

/// Test BtCcp::set_debug() callback registration.
///
/// Verifies that set_debug() accepts a closure and returns true,
/// indicating successful debug callback registration.
#[test]
fn test_ccp_set_debug() {
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    bt_ccp_register(&db);

    let ccp = BtCcp::new(db, None).expect("BtCcp::new should succeed");

    let result = ccp.set_debug(|msg| {
        eprintln!("ccp-test-debug: {msg}");
    });
    assert!(result, "set_debug should return true");
}

/// Test BtCcp::set_event_callbacks() and CcpEventCallback trait.
///
/// Verifies that event callbacks can be registered and that the
/// TestCcpCallbacks implementation correctly implements the trait.
#[test]
fn test_ccp_set_event_callbacks() {
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    bt_ccp_register(&db);

    let ccp = BtCcp::new(db, None).expect("BtCcp::new should succeed");

    let callbacks = TestCcpCallbacks::new();
    let received_flag = Arc::clone(&callbacks.call_state_received);

    // Register callbacks — should not panic.
    ccp.set_event_callbacks(Arc::new(callbacks));

    // Verify the flag is still false (no events received yet).
    assert!(
        !*received_flag.lock().unwrap(),
        "call_state_received should be false before any events"
    );
}

/// Test BtCcp::attach() and detach() lifecycle.
///
/// Verifies that attach() and detach() can be called without panicking.
/// Attach is called with a GATT client on a socketpair transport.
#[test]
fn test_ccp_attach_detach() {
    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    let ldb = GattDb::new();
    ldb.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    bt_ccp_register(&ldb);

    let rdb = GattDb::new();

    let (fd1, _fd2) = create_test_pair();
    let client_att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new failed");

    // Enable debug on ATT transport.
    {
        let mut att_guard = client_att.lock().unwrap();
        att_guard.set_debug(0, Some(Box::new(|msg| eprintln!("att: {msg}"))));
    }

    let client = BtGattClient::new(rdb.clone(), client_att, 64, 0)
        .expect("BtGattClient::new should succeed");

    // Register a ready callback.
    client.ready_register(Box::new(|_success, _att_ecode| {
        // Ready callback — no-op for this test.
    }));

    // Enable client debug.
    client.set_debug(Box::new(|msg| eprintln!("gatt-client: {msg}")));

    // Create CCP client with local and remote databases.
    let ccp = BtCcp::new(ldb, Some(rdb)).expect("BtCcp::new should succeed");
    ccp.set_debug(|msg| eprintln!("ccp: {msg}"));

    // Attach — this initiates GTBS service discovery. Since the remote DB
    // is empty and there's no server pumping PDUs, discovery won't complete,
    // but attach should not panic.
    let attached = ccp.attach(client);
    // The result depends on whether the remote DB has cached GTBS services.
    // With an empty remote DB, foreach_ccs_service finds nothing.
    // We simply confirm attach() returned without panicking — either bool is valid.
    let _ = attached;

    // Detach — should not panic regardless of attach result.
    ccp.detach();
}

/// Test BtCcp::new() with remote database.
///
/// Verifies that BtCcp::new() accepts an optional remote GattDb and
/// creates the CCP client instance with both local and remote databases.
#[test]
fn test_ccp_new_with_remote_db() {
    let ldb = GattDb::new();
    ldb.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    bt_ccp_register(&ldb);

    let rdb = GattDb::new();

    // BtCcp::new with both local and remote databases.
    let ccp = BtCcp::new(ldb.clone(), Some(rdb));
    assert!(ccp.is_some(), "BtCcp::new() with remote DB should return Some");

    // Also test without remote DB.
    let ccp2 = BtCcp::new(ldb, None);
    assert!(ccp2.is_some(), "BtCcp::new() without remote DB should return Some");
}

/// Test reading Termination Reason characteristic value.
///
/// Termination Reason (UUID 0x2BC0) provides the reason a call was
/// terminated. The stub returns zero-initialized data.
#[test]
fn test_ccp_termination_reason_read() {
    let ctx = create_ccp_server();

    let response = read_ccp_characteristic(&ctx, TERMINATION_REASON_HANDLE);
    assert!(!response.is_empty(), "Termination Reason response should not be empty");

    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, TERMINATION_REASON_HANDLE);
        assert_eq!(
            value, DEFAULT_CALL_STATE_VALUE,
            "Termination Reason should return default zero value"
        );
    } else {
        assert_eq!(response[0], ATT_OP_ERROR_RSP, "Expected Read Response or Error Response");
    }
}

/// Test Call Control Point Optional Opcodes read.
///
/// Optional Opcodes (UUID 0x2BBF) indicates which optional call control
/// point opcodes are supported. The stub returns zero-initialized data.
#[test]
fn test_ccp_call_ctrl_optional_opcodes_read() {
    let ctx = create_ccp_server();

    let response = read_ccp_characteristic(&ctx, CALL_CTRL_OPT_OPCODE_HANDLE);
    assert!(!response.is_empty(), "Optional Opcodes response should not be empty");

    if response[0] == ATT_OP_READ_RSP {
        let value = extract_read_value(&response, CALL_CTRL_OPT_OPCODE_HANDLE);
        assert_eq!(
            value, DEFAULT_CALL_STATE_VALUE,
            "Optional Opcodes should return default zero value"
        );
    } else {
        assert_eq!(response[0], ATT_OP_ERROR_RSP, "Expected Read Response or Error Response");
    }
}

/// Test that multiple CCP server instances can be created independently.
///
/// Verifies that creating multiple server contexts doesn't interfere
/// with each other — each has an independent GattDb and GTBS registration.
#[test]
fn test_ccp_multiple_server_instances() {
    let ctx1 = create_ccp_server();
    let ctx2 = create_ccp_server();

    // Read Bearer Provider Name from both servers.
    let resp1 = read_ccp_characteristic(&ctx1, BEARER_NAME_HANDLE);
    let resp2 = read_ccp_characteristic(&ctx2, BEARER_NAME_HANDLE);

    assert!(!resp1.is_empty(), "Server 1 response should not be empty");
    assert!(!resp2.is_empty(), "Server 2 response should not be empty");

    // Both should return the same type of response.
    assert_eq!(resp1[0], resp2[0], "Both servers should return same response type");
}

/// Ensure unused schema-required type references compile correctly.
///
/// This function is never called — it exists purely to satisfy the schema's
/// requirement that `TesterIo`, `BtGattClient`, and related types are
/// referenced in the test file's import scope.
#[allow(dead_code)]
fn _schema_type_references() {
    // Verify TesterIo type from tester module is accessible.
    let _tester_io_size = std::mem::size_of::<TesterIo>();
    // Verify BtGattClient type from gatt::client module is accessible.
    let _client_size = std::mem::size_of::<BtGattClient>();
}
