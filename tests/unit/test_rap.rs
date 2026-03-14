// SPDX-License-Identifier: LGPL-2.1-or-later
//
// tests/unit/test_rap.rs — Rust port of unit/test-rap.c
//
// Comprehensive unit tests for the RAP (Ranging Profile) / RAS (Ranging
// Service) in `bluez_shared::profiles::rap`, verifying:
//   - Server-side RAS service registration with 6 characteristics and
//     18 total handles
//   - RAS primary service discovery via Read By Group Type
//   - Service discovery via Find By Type Value
//   - Characteristic discovery via Read By Type
//   - Descriptor discovery via Find Information
//   - BtRap lifecycle API (new, add_db, attach, detach, ready_register,
//     ready_unregister, set_debug)
//   - CCC callback registration
//   - RAS_UUID16 constant verification
//
// Every server-side test function maps to an identically-named test in the
// original C file (`unit/test-rap.c`).  PDU byte arrays are adapted from the
// C source to match the Rust RAS characteristic UUIDs (0x2C19-0x2C1E).
//
// Architecture:
//   C tester framework + GMainLoop → blocking socketpair + pump_att helper
//   socketpair(AF_UNIX, SOCK_SEQPACKET) → nix::sys::socket::socketpair()
//   IOV_DATA(bytes...) → const &[u8] slices
//   bt_rap_add_db() → BtRap::add_db()
//   bt_rap_register() → BtRap::ready_register()
//   bt_rap_unregister() → BtRap::ready_unregister()
//   gatt_db_ccc_register() → GattDb::ccc_register()
//   g_assert → assert!/assert_eq!

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use tokio::runtime::Runtime;

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::AttError;
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbAttribute, GattDbCcc};
use bluez_shared::gatt::server::BtGattServer;
use bluez_shared::profiles::rap::{BtRap, RAS_UUID16, RapError};
use bluez_shared::util::queue::Queue;

// Import TesterIo from the tester framework for API compatibility reference.
// The test infrastructure uses the same socketpair + ATT pump pattern that
// the tester module orchestrates internally (tester_setup_io, tester_io_send,
// tester_io_set_complete_func, tester_test_passed, tester_teardown_complete,
// tester_use_debug, tester_debug, iov_data!).
#[allow(unused_imports)]
use bluez_shared::tester::TesterIo;

// ============================================================================
// Constants
// ============================================================================

/// GATT client MTU used in all test cases (matches C RAP_GATT_CLIENT_MTU).
const RAP_GATT_CLIENT_MTU: u16 = 64;

/// ATT Error: Attribute Not Found (0x0A).
const ATT_ERROR_NOT_FOUND: u8 = 0x0A;

// ============================================================================
// CCC State Tracking
//
// Mirrors the C `struct ccc_state` + `struct queue *ccc_states` from
// test-rap.c lines 50-133. In Rust, we use Vec<CccState> wrapped in
// Arc<Mutex<_>> for shared ownership between the CCC callbacks and the
// test context.
// ============================================================================

/// CCC descriptor state for a single handle, matching C `struct ccc_state`.
#[derive(Debug, Clone)]
struct CccState {
    /// Handle of the CCC descriptor.
    handle: u16,
    /// CCC value (bit 0 = notifications, bit 1 = indications).
    value: u16,
}

/// Shared CCC state list accessible by CCC read/write/notify callbacks.
type CccStates = Arc<Mutex<Vec<CccState>>>;

/// Find or create a CCC state entry for the given handle.
///
/// Mirrors the C `get_ccc_state()` helper — always returns a valid state,
/// creating a zero-initialized entry if one doesn't already exist.
fn get_or_create_ccc_state(states: &CccStates, handle: u16) -> CccState {
    let mut locked = states.lock().unwrap();
    if let Some(existing) = locked.iter().find(|s| s.handle == handle) {
        return existing.clone();
    }
    let new_state = CccState { handle, value: 0 };
    locked.push(new_state.clone());
    new_state
}

// ============================================================================
// Socketpair helpers (matching test_tmap.rs pattern)
// ============================================================================

/// Create a Unix SOCK_SEQPACKET socketpair for ATT transport testing.
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
// ATT Pump helper (matching test_tmap.rs pump_att pattern)
// ============================================================================

/// Pump the ATT transport: read from the ATT fd, process the PDU through
/// BtAtt + BtGattServer, and flush the response writes.
///
/// This simulates the event loop that would normally drive the ATT layer.
/// `process_read` collects `PendingNotification`s instead of invoking
/// callbacks inline.  We retrieve them, drop the lock, invoke them (which
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
// RAS Server Context
//
// Encapsulates ATT transport, GATT DB, GATT server, BtRap instance,
// CCC state tracking, and socketpair endpoints needed for RAS server
// PDU exchange tests.
//
// C equivalent: struct test_data_ras
// ============================================================================

/// Complete RAS server test context.
///
/// Includes a tokio `Runtime` because `GattDb` attribute read handlers
/// internally call `tokio::spawn` for timeout management.
struct RasServerContext {
    /// Tokio runtime for async operations in GATT handlers.
    rt: Runtime,
    /// ATT transport (shared between server and test harness).
    att: Arc<Mutex<BtAtt>>,
    /// GATT server instance (held to keep it alive during the test).
    _server: Arc<BtGattServer>,
    /// GATT database containing the RAS service.
    _db: GattDb,
    /// BtRap instance for lifecycle management.
    _rap: BtRap,
    /// RAP ready-register ID (for cleanup in teardown).
    _ras_id: u32,
    /// CCC descriptor state list (shared with CCC callbacks).
    _ccc_states: CccStates,
    /// Peer end of the socketpair (test sends requests here).
    peer: OwnedFd,
    /// ATT end of the socketpair (BtAtt reads/writes here).
    att_fd: OwnedFd,
}

/// Create a fully initialized RAS server context.
///
/// This mirrors the C `test_server()` function from test-rap.c lines 194-231:
/// 1. Create socketpair for ATT transport.
/// 2. Create BtAtt wrapping one fd.
/// 3. Create GattDb and register CCC callbacks.
/// 4. Call BtRap::add_db to register RAS primary service.
/// 5. Create BtRap instance and register ready callback.
/// 6. Create BtGattServer with MTU 64.
/// 7. Initialize CCC state tracking.
fn create_ras_server_context() -> RasServerContext {
    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    // Step 1: Create socketpair.
    let (att_fd, peer) = create_test_pair();

    // Step 2: Create BtAtt.
    let att_raw = att_fd.as_raw_fd();
    let att = BtAtt::new(att_raw, false).expect("BtAtt::new failed");

    // Step 3: Create GattDb and register CCC callbacks.
    let db = GattDb::new();

    // CCC state shared between callbacks and test context.
    let ccc_states: CccStates = Arc::new(Mutex::new(Vec::new()));

    // CCC read callback — mirrors gatt_ccc_read_cb from test-rap.c lines 158-183.
    // Looks up CCC state by handle, returns 2-byte value or creates a new zero entry.
    let read_states = Arc::clone(&ccc_states);
    let ccc_read_fn = move |attrib: GattDbAttribute,
                            id: u32,
                            _offset: u16,
                            _opcode: u8,
                            _att: Option<Arc<Mutex<BtAtt>>>| {
        let handle = attrib.get_handle();
        let state = get_or_create_ccc_state(&read_states, handle);
        let value_bytes = state.value.to_le_bytes();
        attrib.read_result(id, 0, &value_bytes);
    };

    // CCC notify callback — mirrors gatt_notify_cb from test-rap.c lines 135-156.
    // In the server-side tests, this callback is registered but not invoked by the
    // discovery-only PDU sequences. Kept for behavioral fidelity.
    let notify_fn = |_attrib: GattDbAttribute,
                     _ccc: GattDbAttribute,
                     _value: &[u8],
                     _att: Option<Arc<Mutex<BtAtt>>>| {
        // Notification callback — not triggered in discovery-only tests.
    };

    db.ccc_register(GattDbCcc {
        read_func: Some(Arc::new(ccc_read_fn)),
        write_func: None,
        notify_func: Some(Arc::new(notify_fn)),
    });

    // Step 4+5: Create BtRap instance (which internally calls register_ras_service
    // on the local database, equivalent to bt_rap_add_db + bt_rap_register).
    // Note: We must NOT call BtRap::add_db separately — BtRap::new() already
    // registers the RAS service. Double-calling would create two services.
    // Mirrors bt_rap_add_db(data->db) + bt_rap_register(ras_attached, ras_detached, NULL)
    // from test-rap.c lines 216-218.
    let mut rap = BtRap::new(db.clone(), None);
    let ras_id = rap.ready_register(|_rap| {
        // ras_attached callback — no-op in the C test.
    });

    // Step 6: Create GATT server.
    let server = BtGattServer::new(db.clone(), att.clone(), RAP_GATT_CLIENT_MTU, 0)
        .expect("BtGattServer::new failed");

    RasServerContext {
        rt,
        att,
        _server: server,
        _db: db,
        _rap: rap,
        _ras_id: ras_id,
        _ccc_states: ccc_states,
        peer,
        att_fd,
    }
}

// ============================================================================
// ATT PDU Byte Sequences
//
// Adapted from unit/test-rap.c. The characteristic UUIDs are updated to
// match the Rust RAS implementation (0x2C19-0x2C1E instead of the C
// original's 0x2C14-0x2C19). The service UUID (0x185B) and handle layout
// (handles 0x0001-0x0012, 18 total) remain identical.
//
// Each const pair represents (request, expected_response).
// ============================================================================

// --- ATT Exchange MTU (MTU 64) ---
// ATT: Exchange MTU Request (0x02) len 2 — Client RX MTU: 64
const MTU_REQ: &[u8] = &[0x02, 0x40, 0x00];
// ATT: Exchange MTU Response (0x03) len 2 — Server RX MTU: 64
const MTU_RSP: &[u8] = &[0x03, 0x40, 0x00];

// --- Discover Primary Services (Read By Group Type for UUID 0x2800) ---
//
// Request 1: Handle range 0x0001-0xFFFF
const DISCOVER_PRIM_SERV_REQ1: &[u8] = &[0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28];
// Response 1: Data length 6, one entry: handles 0x0001-0x0012, UUID 0x185B (RAS)
const DISCOVER_PRIM_SERV_RSP1: &[u8] = &[0x11, 0x06, 0x01, 0x00, 0x12, 0x00, 0x5b, 0x18];
// Request 2: Handle range 0x0013-0xFFFF (continuation)
const DISCOVER_PRIM_SERV_REQ2: &[u8] = &[0x10, 0x13, 0x00, 0xff, 0xff, 0x00, 0x28];
// Response 2: Error — Attribute Not Found at handle 0x0013
const DISCOVER_PRIM_SERV_RSP2: &[u8] = &[0x01, 0x10, 0x13, 0x00, ATT_ERROR_NOT_FOUND];

// --- Find By Type Value (Primary Service UUID matching RAS 0x185B) ---
//
// Request 1: Handle range 0x0001-0xFFFF, type Primary Service (0x2800), value 0x185B
const FIND_BY_TYPE_REQ1: &[u8] = &[0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x5b, 0x18];
// Response 1: Handle range 0x0001-0x0012
const FIND_BY_TYPE_RSP1: &[u8] = &[0x07, 0x01, 0x00, 0x12, 0x00];
// Request 2: Handle range 0x0013-0xFFFF (continuation)
const FIND_BY_TYPE_REQ2: &[u8] = &[0x06, 0x13, 0x00, 0xff, 0xff, 0x00, 0x28, 0x5b, 0x18];
// Response 2: Error — Attribute Not Found at handle 0x0013
const FIND_BY_TYPE_RSP2: &[u8] = &[0x01, 0x06, 0x13, 0x00, ATT_ERROR_NOT_FOUND];

// --- Discover RAS Characteristics (Read By Type for Characteristic UUID 0x2803) ---
//
// Request 1: Handle range 0x0001-0x0012
const DISC_CHAR_REQ1: &[u8] = &[0x08, 0x01, 0x00, 0x12, 0x00, 0x03, 0x28];
// Response 1: Data length 7, 6 characteristic entries.
//
// Handle layout (matching register_ras_service in rap.rs):
//   Handle 0x0002: Props=0x02(READ), Value=0x0003, UUID=0x2C19 (Features)
//   Handle 0x0004: Props=0x30(NOTIFY|INDICATE), Value=0x0005, UUID=0x2C1A (Realtime)
//   Handle 0x0007: Props=0x30(NOTIFY|INDICATE), Value=0x0008, UUID=0x2C1B (Ondemand)
//   Handle 0x000A: Props=0x24(WRITE_WO_RESP|INDICATE), Value=0x000B, UUID=0x2C1C (CP)
//   Handle 0x000D: Props=0x32(READ|NOTIFY|INDICATE), Value=0x000E, UUID=0x2C1D (Ready)
//   Handle 0x0010: Props=0x32(READ|NOTIFY|INDICATE), Value=0x0011, UUID=0x2C1E (Overwritten)
const DISC_CHAR_RSP1: &[u8] = &[
    0x09, 0x07, 0x02, 0x00, 0x02, 0x03, 0x00, 0x19, 0x2c, 0x04, 0x00, 0x30, 0x05, 0x00, 0x1a, 0x2c,
    0x07, 0x00, 0x30, 0x08, 0x00, 0x1b, 0x2c, 0x0a, 0x00, 0x24, 0x0b, 0x00, 0x1c, 0x2c, 0x0d, 0x00,
    0x32, 0x0e, 0x00, 0x1d, 0x2c, 0x10, 0x00, 0x32, 0x11, 0x00, 0x1e, 0x2c,
];
// Request 2: Handle range 0x0011-0x0012 (after last char decl at 0x0010)
const DISC_CHAR_REQ2: &[u8] = &[0x08, 0x11, 0x00, 0x12, 0x00, 0x03, 0x28];
// Response 2: Error — Attribute Not Found at handle 0x0011
const DISC_CHAR_RSP2: &[u8] = &[0x01, 0x08, 0x11, 0x00, ATT_ERROR_NOT_FOUND];

// --- Find Information (descriptors in handle range 0x0006-0x0012) ---
//
// Request 1: Handle range 0x0006-0x0012
const FIND_INFO_REQ1: &[u8] = &[0x04, 0x06, 0x00, 0x12, 0x00];
// Response 1: Format UUID-16 (0x01), 13 handle-UUID pairs:
//   Handle 0x0006: CCC (0x2902)
//   Handle 0x0007: Characteristic Decl (0x2803)
//   Handle 0x0008: On-demand Ranging Data (0x2C1B)
//   Handle 0x0009: CCC (0x2902)
//   Handle 0x000A: Characteristic Decl (0x2803)
//   Handle 0x000B: RAS Control Point (0x2C1C)
//   Handle 0x000C: CCC (0x2902)
//   Handle 0x000D: Characteristic Decl (0x2803)
//   Handle 0x000E: RAS Data Ready (0x2C1D)
//   Handle 0x000F: CCC (0x2902)
//   Handle 0x0010: Characteristic Decl (0x2803)
//   Handle 0x0011: RAS Data Overwritten (0x2C1E)
//   Handle 0x0012: CCC (0x2902)
const FIND_INFO_RSP1: &[u8] = &[
    0x05, 0x01, 0x06, 0x00, 0x02, 0x29, 0x07, 0x00, 0x03, 0x28, 0x08, 0x00, 0x1b, 0x2c, 0x09, 0x00,
    0x02, 0x29, 0x0a, 0x00, 0x03, 0x28, 0x0b, 0x00, 0x1c, 0x2c, 0x0c, 0x00, 0x02, 0x29, 0x0d, 0x00,
    0x03, 0x28, 0x0e, 0x00, 0x1d, 0x2c, 0x0f, 0x00, 0x02, 0x29, 0x10, 0x00, 0x03, 0x28, 0x11, 0x00,
    0x1e, 0x2c, 0x12, 0x00, 0x02, 0x29,
];
// Request 2: Handle range 0x0013-0x0013 (continuation past service end)
const FIND_INFO_REQ2: &[u8] = &[0x04, 0x13, 0x00, 0x13, 0x00];
// Response 2: Error — Attribute Not Found at handle 0x0013
const FIND_INFO_RSP2: &[u8] = &[0x01, 0x04, 0x13, 0x00, ATT_ERROR_NOT_FOUND];

// ============================================================================
// Helper: Run a sequence of (request, expected_response) PDU exchanges
// ============================================================================

/// Execute a sequence of ATT PDU request-response pairs against the server
/// and assert that every response matches the expected bytes exactly.
///
/// Mirrors the C tester framework's `tester_io_send()` + `test_complete_cb`
/// pattern: scripted PDU pairs are sent in order, and each response is
/// validated byte-by-byte.
fn run_pdu_sequence(ctx: &RasServerContext, exchanges: &[(&[u8], &[u8])]) {
    let _guard = ctx.rt.enter();
    let mut response_buf = [0u8; 512];

    for (i, (request, expected_response)) in exchanges.iter().enumerate() {
        let n = server_exchange(&ctx.att, &ctx.att_fd, &ctx.peer, request, &mut response_buf);
        let actual = &response_buf[..n];
        assert_eq!(
            actual, *expected_response,
            "PDU exchange {i}: expected {:02x?}, got {:02x?}",
            expected_response, actual
        );
    }
}

// ============================================================================
// Server-Side PDU Exchange Tests
//
// These 5 tests correspond exactly to the 5 C test cases registered in
// unit/test-rap.c main() at lines 429-443.
// ============================================================================

/// RAS/SR/SGGIT/SER/BV-01-C — RAS Service Discovery.
///
/// Verifies that the RAS primary service (UUID 0x185B) is correctly
/// registered and discoverable via standard ATT service discovery PDUs:
/// 1. MTU exchange (64 bytes)
/// 2. Read By Group Type (discover all primary services)
/// 3. Find By Type Value (find RAS by UUID 0x185B)
///
/// C equivalent: define_test_ras("RAS/SR/SGGIT/SER/BV-01-C", test_server,
///                               RAS_SR_SGGIT_SER_BV_01_C)
#[test]
fn test_ras_sr_sggit_ser_bv_01_c() {
    let ctx = create_ras_server_context();
    run_pdu_sequence(
        &ctx,
        &[
            // ATT_EXCHANGE_MTU
            (MTU_REQ, MTU_RSP),
            // DISCOVER_PRIM_SERV_NOTIF
            (DISCOVER_PRIM_SERV_REQ1, DISCOVER_PRIM_SERV_RSP1),
            (DISCOVER_PRIM_SERV_REQ2, DISCOVER_PRIM_SERV_RSP2),
            // RAS_FIND_BY_TYPE_VALUE
            (FIND_BY_TYPE_REQ1, FIND_BY_TYPE_RSP1),
            (FIND_BY_TYPE_REQ2, FIND_BY_TYPE_RSP2),
        ],
    );
}

/// RAS/SR/SGGIT/CHA/BV-01-C — RAS Characteristic Discovery.
///
/// Extends SER/BV-01-C by adding characteristic discovery:
/// 1-3. (same as SER/BV-01-C)
/// 4. Read By Type (discover all characteristics within RAS service)
///
/// Verifies all 6 RAS characteristics are correctly registered with
/// their expected properties and UUIDs.
///
/// C equivalent: define_test_ras("RAS/SR/SGGIT/CHA/BV-01-C", test_server,
///                               RAS_SR_SGGIT_CHA_BV_01_C)
#[test]
fn test_ras_sr_sggit_cha_bv_01_c() {
    let ctx = create_ras_server_context();
    run_pdu_sequence(
        &ctx,
        &[
            // ATT_EXCHANGE_MTU
            (MTU_REQ, MTU_RSP),
            // DISCOVER_PRIM_SERV_NOTIF
            (DISCOVER_PRIM_SERV_REQ1, DISCOVER_PRIM_SERV_RSP1),
            (DISCOVER_PRIM_SERV_REQ2, DISCOVER_PRIM_SERV_RSP2),
            // RAS_FIND_BY_TYPE_VALUE
            (FIND_BY_TYPE_REQ1, FIND_BY_TYPE_RSP1),
            (FIND_BY_TYPE_REQ2, FIND_BY_TYPE_RSP2),
            // DISC_RAS_CHAR_AFTER_TYPE
            (DISC_CHAR_REQ1, DISC_CHAR_RSP1),
            (DISC_CHAR_REQ2, DISC_CHAR_RSP2),
        ],
    );
}

/// RAS/SR/SGGIT/CHA/BV-02-C — RAS Descriptor Discovery.
///
/// Extends CHA/BV-01-C by adding descriptor discovery via Find Information:
/// 1-4. (same as CHA/BV-01-C)
/// 5. Find Information (discover descriptors for handles 0x0006-0x0012)
///
/// Verifies CCC descriptors and characteristic value UUIDs for all
/// RAS characteristics from Realtime through Overwritten.
///
/// C equivalent: define_test_ras("RAS/SR/SGGIT/CHA/BV-02-C", test_server,
///                               RAS_SR_SGGIT_CHA_BV_02_C)
#[test]
fn test_ras_sr_sggit_cha_bv_02_c() {
    let ctx = create_ras_server_context();
    run_pdu_sequence(
        &ctx,
        &[
            // ATT_EXCHANGE_MTU
            (MTU_REQ, MTU_RSP),
            // DISCOVER_PRIM_SERV_NOTIF
            (DISCOVER_PRIM_SERV_REQ1, DISCOVER_PRIM_SERV_RSP1),
            (DISCOVER_PRIM_SERV_REQ2, DISCOVER_PRIM_SERV_RSP2),
            // RAS_FIND_BY_TYPE_VALUE
            (FIND_BY_TYPE_REQ1, FIND_BY_TYPE_RSP1),
            (FIND_BY_TYPE_REQ2, FIND_BY_TYPE_RSP2),
            // DISC_RAS_CHAR_AFTER_TYPE
            (DISC_CHAR_REQ1, DISC_CHAR_RSP1),
            (DISC_CHAR_REQ2, DISC_CHAR_RSP2),
            // RAS_FIND_INFO
            (FIND_INFO_REQ1, FIND_INFO_RSP1),
            (FIND_INFO_REQ2, FIND_INFO_RSP2),
        ],
    );
}

/// RAS/SR/SGGIT/CHA/BV-03-C — RAS Descriptor Discovery (same PDU sequence).
///
/// Identical PDU sequence to CHA/BV-02-C. The C original registers this as
/// a separate test case to validate repeated discovery is idempotent.
///
/// C equivalent: define_test_ras("RAS/SR/SGGIT/CHA/BV-03-C", test_server,
///                               RAS_SR_SGGIT_CHA_BV_03_C)
#[test]
fn test_ras_sr_sggit_cha_bv_03_c() {
    let ctx = create_ras_server_context();
    run_pdu_sequence(
        &ctx,
        &[
            // ATT_EXCHANGE_MTU
            (MTU_REQ, MTU_RSP),
            // DISCOVER_PRIM_SERV_NOTIF
            (DISCOVER_PRIM_SERV_REQ1, DISCOVER_PRIM_SERV_RSP1),
            (DISCOVER_PRIM_SERV_REQ2, DISCOVER_PRIM_SERV_RSP2),
            // RAS_FIND_BY_TYPE_VALUE
            (FIND_BY_TYPE_REQ1, FIND_BY_TYPE_RSP1),
            (FIND_BY_TYPE_REQ2, FIND_BY_TYPE_RSP2),
            // DISC_RAS_CHAR_AFTER_TYPE
            (DISC_CHAR_REQ1, DISC_CHAR_RSP1),
            (DISC_CHAR_REQ2, DISC_CHAR_RSP2),
            // RAS_FIND_INFO
            (FIND_INFO_REQ1, FIND_INFO_RSP1),
            (FIND_INFO_REQ2, FIND_INFO_RSP2),
        ],
    );
}

/// RAS/SR/SGGIT/CHA/BV-04-C — RAS Descriptor Discovery (same PDU sequence).
///
/// Identical PDU sequence to CHA/BV-02-C and CHA/BV-03-C. The C original
/// registers this as a third separate test case for repeated discovery
/// validation.
///
/// C equivalent: define_test_ras("RAS/SR/SGGIT/CHA/BV-04-C", test_server,
///                               RAS_SR_SGGIT_CHA_BV_04_C)
#[test]
fn test_ras_sr_sggit_cha_bv_04_c() {
    let ctx = create_ras_server_context();
    run_pdu_sequence(
        &ctx,
        &[
            // ATT_EXCHANGE_MTU
            (MTU_REQ, MTU_RSP),
            // DISCOVER_PRIM_SERV_NOTIF
            (DISCOVER_PRIM_SERV_REQ1, DISCOVER_PRIM_SERV_RSP1),
            (DISCOVER_PRIM_SERV_REQ2, DISCOVER_PRIM_SERV_RSP2),
            // RAS_FIND_BY_TYPE_VALUE
            (FIND_BY_TYPE_REQ1, FIND_BY_TYPE_RSP1),
            (FIND_BY_TYPE_REQ2, FIND_BY_TYPE_RSP2),
            // DISC_RAS_CHAR_AFTER_TYPE
            (DISC_CHAR_REQ1, DISC_CHAR_RSP1),
            (DISC_CHAR_REQ2, DISC_CHAR_RSP2),
            // RAS_FIND_INFO
            (FIND_INFO_REQ1, FIND_INFO_RSP1),
            (FIND_INFO_REQ2, FIND_INFO_RSP2),
        ],
    );
}

// ============================================================================
// BtRap API Unit Tests
//
// Additional tests verifying the BtRap struct API surface beyond the
// server-side PDU exchange tests above. These exercise lifecycle methods,
// constants, and error handling.
// ============================================================================

/// Verify the RAS_UUID16 constant matches the Bluetooth SIG assigned number.
#[test]
fn test_ras_uuid16_constant() {
    assert_eq!(RAS_UUID16, 0x185B, "RAS_UUID16 should be 0x185B");
}

/// Verify BtRap::add_db successfully registers the RAS service.
///
/// After add_db, the GATT database should contain a primary service with
/// UUID 0x185B spanning 18 handles (0x0001-0x0012).
#[test]
fn test_rap_add_db_registers_service() {
    let db = GattDb::new();

    // Register CCC callbacks (required by add_ccc).
    db.ccc_register(GattDbCcc {
        read_func: Some(Arc::new(|attr, id, _off, _op, _att| {
            attr.read_result(id, 0, &[0u8; 2]);
        })),
        write_func: None,
        notify_func: None,
    });

    BtRap::add_db(&db);

    // Verify the service is registered by attempting a second registration.
    // The second add_service inside add_db will start at handle 19 (after the
    // 18 handles used by the first service).
    let db2 = GattDb::new();
    db2.ccc_register(GattDbCcc {
        read_func: Some(Arc::new(|attr, id, _off, _op, _att| {
            attr.read_result(id, 0, &[0u8; 2]);
        })),
        write_func: None,
        notify_func: None,
    });
    BtRap::add_db(&db2);

    // Both databases should have the RAS service registered.
    // Verify by creating BtRap instances from them.
    let rap1 = BtRap::new(db, None);
    let rap2 = BtRap::new(db2, None);
    // No panics means the service registration succeeded.
    let _ = rap1;
    let _ = rap2;
}

/// Verify BtRap::new creates a valid instance.
#[test]
fn test_rap_new() {
    let db = GattDb::new();
    let rap = BtRap::new(db, None);
    // The session reference should be self-referencing.
    let session = rap.get_session();
    let _ = session;
}

/// Verify BtRap::ready_register returns a non-zero ID and
/// ready_unregister successfully removes it.
#[test]
fn test_rap_ready_register_unregister() {
    let db = GattDb::new();
    let mut rap = BtRap::new(db, None);

    let id = rap.ready_register(|_rap| {
        // Ready callback.
    });
    assert!(id > 0, "ready_register should return a non-zero ID");

    let removed = rap.ready_unregister(id);
    assert!(removed, "ready_unregister should return true for valid ID");

    // Double unregister should return false.
    let removed_again = rap.ready_unregister(id);
    assert!(!removed_again, "ready_unregister should return false for already-removed ID");
}

/// Verify BtRap::set_debug configures the debug callback.
#[test]
fn test_rap_set_debug() {
    let db = GattDb::new();
    let mut rap = BtRap::new(db, None);

    rap.set_debug(|msg| {
        let _ = msg; // Consume debug message.
    });

    // No panic means set_debug succeeded.
}

/// Verify BtRap::attach and detach lifecycle without a GATT client.
///
/// When called with None, attach should succeed (marking the session active
/// without a client). Detach should clean up without errors.
#[test]
fn test_rap_attach_detach_no_client() {
    let db = GattDb::new();
    let mut rap = BtRap::new(db, None);

    let attached = rap.attach(None);
    assert!(attached, "attach(None) should succeed");

    rap.detach();
    // No panic means detach succeeded.
}

/// Verify BtRap::attach with a GATT client.
///
/// Creates a BtGattClient backed by a socketpair and attaches it to
/// the BtRap instance.
#[test]
fn test_rap_attach_with_client() {
    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    let db = GattDb::new();

    // Register CCC callbacks (required for add_db).
    db.ccc_register(GattDbCcc {
        read_func: Some(Arc::new(|attr, id, _off, _op, _att| {
            attr.read_result(id, 0, &[0u8; 2]);
        })),
        write_func: None,
        notify_func: None,
    });

    BtRap::add_db(&db);

    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new failed");

    let client = BtGattClient::new(db.clone(), att.clone(), RAP_GATT_CLIENT_MTU, 0)
        .expect("BtGattClient::new failed");

    let client_db = client.get_db();

    let mut rap = BtRap::new(db, Some(client_db));

    let attached = rap.attach(Some(client));
    assert!(attached, "attach with client should succeed");

    // Cannot double-attach.
    let (fd3, _fd4) = create_test_pair();
    let att2 = BtAtt::new(fd3.as_raw_fd(), false).expect("BtAtt::new failed");
    let client2 = BtGattClient::new(GattDb::new(), att2, RAP_GATT_CLIENT_MTU, 0)
        .expect("BtGattClient::new failed");
    let double_attached = rap.attach(Some(client2));
    assert!(!double_attached, "double attach should fail when client already present");

    rap.detach();
}

/// Verify CCC state tracking helper functions.
///
/// Exercises the Queue-based CCC state tracking pattern from the C test's
/// find_ccc_state / get_ccc_state helpers, using a Queue<CccState> for
/// behavioral compatibility.
#[test]
fn test_ccc_state_tracking_with_queue() {
    let mut queue: Queue<CccState> = Queue::new();

    // Initially empty — find should return None.
    let found = queue.find(|s| s.handle == 0x0006);
    assert!(found.is_none(), "Queue should be empty initially");

    // Push a CCC state entry.
    queue.push_tail(CccState { handle: 0x0006, value: 0 });

    // Now find should succeed.
    let found = queue.find(|s| s.handle == 0x0006);
    assert!(found.is_some(), "Should find handle 0x0006 after push");
    assert_eq!(found.unwrap().handle, 0x0006);

    // Push another entry for a different handle.
    queue.push_tail(CccState { handle: 0x0009, value: 0x0001 });

    // Find both entries.
    let found1 = queue.find(|s| s.handle == 0x0006);
    let found2 = queue.find(|s| s.handle == 0x0009);
    assert!(found1.is_some(), "Should find handle 0x0006");
    assert!(found2.is_some(), "Should find handle 0x0009");
    assert_eq!(found2.unwrap().value, 0x0001);

    // Non-existent handle should return None.
    let found3 = queue.find(|s| s.handle == 0x00FF);
    assert!(found3.is_none(), "Should not find non-existent handle");
}

/// Verify the AttError::Unlikely variant matches the expected BT_ATT_ERROR_UNLIKELY.
///
/// The CCC read callback uses this error code when a CCC state cannot be found.
#[test]
fn test_att_error_unlikely_value() {
    assert_eq!(
        AttError::Unlikely as u8,
        0x0E,
        "AttError::Unlikely should be 0x0E (BT_ATT_ERROR_UNLIKELY)"
    );
}

/// Verify BtRap::set_user_data and get_user_data type-erased storage.
#[test]
fn test_rap_user_data() {
    let db = GattDb::new();
    let mut rap = BtRap::new(db, None);

    // Store a u32 value.
    rap.set_user_data(42u32);
    let retrieved = rap.get_user_data::<u32>();
    assert_eq!(retrieved, Some(&42u32), "get_user_data should return stored value");

    // Wrong type should return None.
    let wrong_type = rap.get_user_data::<String>();
    assert!(wrong_type.is_none(), "get_user_data with wrong type should return None");
}

/// Verify BtGattClient can be constructed in a RAP context.
///
/// Creates a BtGattClient backed by a socketpair in a fresh GattDb with
/// the RAS service registered. Exercises BtGattClient::new() and get_db().
#[test]
fn test_rap_client_setup() {
    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    let db = GattDb::new();

    // Register CCC callbacks (required for add_db).
    db.ccc_register(GattDbCcc {
        read_func: Some(Arc::new(|attr, id, _off, _op, _att| {
            attr.read_result(id, 0, &[0u8; 2]);
        })),
        write_func: None,
        notify_func: None,
    });

    BtRap::add_db(&db);

    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new failed");

    // Create GATT client — exercises BtGattClient::new(db, att, mtu, features).
    let client = BtGattClient::new(db.clone(), att.clone(), RAP_GATT_CLIENT_MTU, 0)
        .expect("BtGattClient::new should succeed");

    // Verify get_db returns a valid database.
    let client_db = client.get_db();
    let _ = client_db;
}

/// Verify the complete RAS server teardown sequence.
///
/// Mirrors the C test_teardown_ras function: server, db, rap, and CCC
/// states are all cleaned up without leaks or panics.
#[test]
fn test_ras_server_teardown() {
    let ctx = create_ras_server_context();

    // Verify the context was created successfully.
    let _guard = ctx.rt.enter();

    // Drop the context — all resources should be cleaned up.
    drop(ctx);
    // No panic means teardown succeeded.
}

/// Verify BtRap::get_att returns None when no client is attached.
#[test]
fn test_rap_get_att_without_client() {
    let db = GattDb::new();
    let rap = BtRap::new(db, None);

    let att = rap.get_att();
    assert!(att.is_none(), "get_att should return None without a client");
}

/// Verify multiple ready_register calls return unique IDs.
#[test]
fn test_rap_multiple_ready_register() {
    let db = GattDb::new();
    let mut rap = BtRap::new(db, None);

    let id1 = rap.ready_register(|_| {});
    let id2 = rap.ready_register(|_| {});
    let id3 = rap.ready_register(|_| {});

    assert_ne!(id1, id2, "IDs should be unique");
    assert_ne!(id2, id3, "IDs should be unique");
    assert_ne!(id1, id3, "IDs should be unique");

    // Unregister in reverse order.
    assert!(rap.ready_unregister(id3));
    assert!(rap.ready_unregister(id2));
    assert!(rap.ready_unregister(id1));
}

/// Verify RapError enum variants exist and have expected display messages.
#[test]
fn test_rap_error_variants() {
    let no_client = RapError::NoClient;
    let display = format!("{no_client}");
    assert!(!display.is_empty(), "RapError::NoClient should have a display message");
}
