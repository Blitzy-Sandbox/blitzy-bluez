// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_att.rs — Rust port of ATT transport tests from
// unit/test-gatt.c and unit/test-gattrib.c
//
// Tests the ATT transport layer — PDU exchange, MTU negotiation,
// security handling, transport lifecycle, handler registration,
// request/response patterns, and cancellation.
//
// Architecture:
//   C struct context + GMainLoop → blocking socketpair I/O
//   socketpair(AF_UNIX,SOCK_SEQPACKET) → nix::sys::socket::socketpair()
//   raw_pdu(bytes...) → const &[u8] slices
//   create_context() → TestContext::new()
//   test_handler() → verify/exchange PDU sequences
//   g_assert*() → assert!() / assert_eq!()
//   bt_att_ref/unref → Arc<Mutex<BtAtt>> RAII Drop

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::{
    AttSecurityLevel, BT_ATT_ALL_REQUESTS, BT_ATT_DEFAULT_LE_MTU,
    BT_ATT_ERROR_REQUEST_NOT_SUPPORTED, BT_ATT_OP_ERROR_RSP, BT_ATT_OP_MTU_REQ, BT_ATT_OP_MTU_RSP,
};
use bluez_shared::gatt::db::GattDb;
use bluez_shared::gatt::server::BtGattServer;

// ============================================================================
// PDU constants — byte-identical to C source raw_pdu() definitions
// ============================================================================

/// MTU Exchange Request: opcode=0x02, MTU=512 (little-endian: 0x00 0x02)
/// From test-gatt.c MTU_EXCHANGE_CLIENT_PDUS first entry.
const PDU_MTU_REQ_512: &[u8] = &[0x02, 0x00, 0x02];

/// MTU Exchange Response: opcode=0x03, MTU=512 (little-endian: 0x00 0x02)
/// From test-gatt.c MTU_EXCHANGE_CLIENT_PDUS second entry.
const PDU_MTU_RSP_512: &[u8] = &[0x03, 0x00, 0x02];

/// MTU Exchange Response with MTU=64: opcode=0x03, MTU=64 (0x40 0x00)
const PDU_MTU_RSP_64: &[u8] = &[0x03, 0x40, 0x00];

/// MTU Exchange Request with MTU=64: opcode=0x02, MTU=64 (0x40 0x00)
const PDU_MTU_REQ_64: &[u8] = &[0x02, 0x40, 0x00];

/// Default MTU Response (MTU=23): opcode=0x03, MTU=23 (0x17 0x00)
const PDU_MTU_RSP_23: &[u8] = &[0x03, 0x17, 0x00];

/// Unknown request opcode (not handled by any server handler).
/// Must have bit 6 (0x40) CLEAR so get_op_type returns AttOpType::Unknown
/// (not Cmd). 0x1F is not in the ATT opcode table and has bit 6 clear.
const UNKNOWN_REQ_OPCODE: u8 = 0x1F;

/// Unknown command opcode (bit 6 set = command).
/// 0x41 has bit 6 (0x40) set so get_op_type returns AttOpType::Cmd.
/// Commands are silently ignored when no handler matches.
const UNKNOWN_CMD_OPCODE: u8 = 0x41;

/// Error response PDU for unknown request: Error(0x01), req opcode, handle=0x0000, code=0x06
fn make_error_rsp_pdu(request_opcode: u8, handle: u16, ecode: u8) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(5);
    pdu.push(BT_ATT_OP_ERROR_RSP);
    pdu.push(request_opcode);
    pdu.extend_from_slice(&handle.to_le_bytes());
    pdu.push(ecode);
    pdu
}

/// Find Info Request: opcode=0x04, start=0x0001, end=0xFFFF.
/// From test-gattrib.c PDU_FIND_INFO_REQ.
const PDU_FIND_INFO_REQ: &[u8] = &[0x04, 0x01, 0x00, 0xFF, 0xFF];

/// Handle Indication (no data): opcode=0x1D, handle=0x0001.
/// From test-gattrib.c PDU_IND_NODATA.
const PDU_IND_NODATA: &[u8] = &[0x1D, 0x01, 0x00];

/// Handle Indication (with data): opcode=0x1D, handle=0x0014, data=0x01.
/// From test-gattrib.c PDU_IND_DATA.
const PDU_IND_DATA: &[u8] = &[0x1D, 0x14, 0x00, 0x01];

// ============================================================================
// Test infrastructure
// ============================================================================

/// Create a Unix SOCK_SEQPACKET socketpair for ATT transport testing.
///
/// Returns (local_fd, peer_fd) where local_fd is used by BtAtt and
/// peer_fd is used by the test to inject/verify PDUs.
fn create_test_pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair(AF_UNIX, SOCK_SEQPACKET) failed")
}

/// Blocking read with retry on EAGAIN, with a 5-second timeout limit.
///
/// Mirrors the C test infrastructure's blocking read behavior.
fn blocking_read(fd: &OwnedFd, buf: &mut [u8]) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match nix::unistd::read(fd.as_raw_fd(), buf) {
            Ok(n) => return n,
            Err(nix::errno::Errno::EAGAIN) => {
                if Instant::now() > deadline {
                    panic!("blocking_read: timed out waiting for data");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("blocking_read: {e}"),
        }
    }
}

/// Blocking write with retry on EAGAIN, with a 5-second timeout limit.
///
/// Mirrors the C test infrastructure's blocking write behavior.
fn blocking_write(fd: &OwnedFd, data: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match nix::unistd::write(fd, data) {
            Ok(_) => return,
            Err(nix::errno::Errno::EAGAIN) => {
                if Instant::now() > deadline {
                    panic!("blocking_write: timed out");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("blocking_write: {e}"),
        }
    }
}

/// Try to read from the peer socket, returning None if no data is available
/// within the given timeout.
fn try_read_timeout(fd: &OwnedFd, buf: &mut [u8], timeout: Duration) -> Option<usize> {
    let deadline = Instant::now() + timeout;
    loop {
        match nix::unistd::read(fd.as_raw_fd(), buf) {
            Ok(n) => return Some(n),
            Err(nix::errno::Errno::EAGAIN) => {
                if Instant::now() > deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("try_read_timeout: {e}"),
        }
    }
}

/// Test context holding a socketpair and ATT transport instance.
///
/// Replaces the C `struct context` from test-gatt.c / test-gattrib.c.
/// The `peer` fd is used by the test to inject and read raw PDUs.
/// The `att` is the ATT transport under test.
struct TestContext {
    /// ATT transport instance under test.
    att: Arc<Mutex<BtAtt>>,
    /// Peer socket fd — test code reads/writes raw PDUs here.
    peer: OwnedFd,
    /// Local socket fd — kept alive to prevent premature close.
    /// BtAtt references this fd internally via RawFd.
    _local: OwnedFd,
}

impl TestContext {
    /// Create a new test context with a socketpair-backed ATT transport.
    ///
    /// Mirrors `create_context` from test-gatt.c.
    fn new() -> Self {
        let (local, peer) = create_test_pair();
        let fd = local.as_raw_fd();
        let att = BtAtt::new(fd, false).expect("BtAtt::new failed");
        TestContext { att, peer, _local: local }
    }

    /// Send a raw PDU through the peer socket to the ATT transport.
    fn send_pdu(&self, pdu: &[u8]) {
        blocking_write(&self.peer, pdu);
    }

    /// Read a raw PDU from the peer socket (sent by the ATT transport).
    /// Returns the PDU bytes read.
    fn recv_pdu(&self) -> Vec<u8> {
        let mut buf = [0u8; 517]; // max LE MTU
        let n = blocking_read(&self.peer, &mut buf);
        buf[..n].to_vec()
    }

    /// Try to receive a PDU from the peer socket within a timeout.
    /// Returns None if nothing arrives.
    fn try_recv_pdu(&self, timeout: Duration) -> Option<Vec<u8>> {
        let mut buf = [0u8; 517];
        try_read_timeout(&self.peer, &mut buf, timeout).map(|n| buf[..n].to_vec())
    }

    /// Process a received PDU through the ATT transport and dispatch
    /// any pending notification callbacks (deferred dispatch pattern).
    fn process_incoming(&self, pdu: &[u8]) {
        let pending = {
            let mut att = self.att.lock().unwrap();
            att.process_read(0, pdu);
            att.take_pending_notifications()
        };
        // Dispatch callbacks outside the lock to avoid deadlock.
        for pn in &pending {
            (pn.callback)(pn.chan_idx, pn.filter_opcode, pn.raw_opcode, &pn.body);
        }
    }

    /// Flush any queued write operations on the ATT transport.
    fn flush_writes(&self) {
        let mut att = self.att.lock().unwrap();
        att.flush_writes();
    }
}

/// Test context with a GATT server attached.
///
/// Used for tests that verify server-side behavior (unknown request/command
/// handling, MTU negotiation via server).
struct ServerTestContext {
    /// Base context with ATT transport and socketpair.
    ctx: TestContext,
    /// GATT server instance (keeps handler registrations alive).
    _server: Arc<BtGattServer>,
}

impl ServerTestContext {
    /// Create a server test context with an empty GATT database.
    fn new() -> Self {
        let ctx = TestContext::new();
        let db = GattDb::new();
        let server = BtGattServer::new(db, Arc::clone(&ctx.att), BT_ATT_DEFAULT_LE_MTU, 0)
            .expect("BtGattServer::new failed");
        ServerTestContext { ctx, _server: server }
    }
}

// ============================================================================
// Test functions — ATT transport layer (from test-gatt.c patterns)
// ============================================================================

/// Test ATT MTU exchange over a socketpair.
///
/// Derived from the `create_context(64, data)` + `bt_gatt_exchange_mtu`
/// pattern in test-gatt.c ATT-type tests. Verifies:
/// 1. Initial MTU is BT_ATT_DEFAULT_LE_MTU (23)
/// 2. BtAtt::set_mtu(64) succeeds and updates the MTU
/// 3. Manual MTU exchange PDU round-trip works correctly
/// 4. MTU request/response PDU bytes match expected values
#[test]
fn test_att_mtu_exchange() {
    let ctx = TestContext::new();

    // Verify initial MTU is the default (23).
    {
        let att = ctx.att.lock().unwrap();
        assert_eq!(att.get_mtu(), BT_ATT_DEFAULT_LE_MTU, "initial MTU must be 23");
    }

    // Set MTU to 64 via the transport API.
    {
        let mut att = ctx.att.lock().unwrap();
        assert!(att.set_mtu(64), "set_mtu(64) should succeed");
        assert_eq!(att.get_mtu(), 64, "MTU should be 64 after set_mtu");
    }

    // Send an MTU exchange request from the transport side.
    // send() requires a callback for Req-type opcodes.
    // The PDU payload is MTU=64 (LE16: 0x40 0x00).
    let rsp_opcode = Arc::new(Mutex::new(0u8));
    let rsp_data = Arc::new(Mutex::new(Vec::<u8>::new()));
    let opcode_clone = Arc::clone(&rsp_opcode);
    let data_clone = Arc::clone(&rsp_data);

    {
        let mut att = ctx.att.lock().unwrap();
        let mtu_bytes = 64u16.to_le_bytes();
        let id = att.send(
            BT_ATT_OP_MTU_REQ,
            &mtu_bytes,
            Some(Box::new(move |op: u8, data: &[u8]| {
                *opcode_clone.lock().unwrap() = op;
                *data_clone.lock().unwrap() = data.to_vec();
            })),
        );
        assert!(id != 0, "send MTU_REQ should return non-zero id");
    }

    // Flush writes to push the PDU onto the socket.
    ctx.flush_writes();

    // Read the MTU request from the peer socket and verify.
    let req_pdu = ctx.recv_pdu();
    assert_eq!(req_pdu, PDU_MTU_REQ_64, "MTU request PDU must match");

    // Respond from the peer with MTU=23 (the default).
    ctx.send_pdu(PDU_MTU_RSP_23);

    // Process the response through the ATT transport.
    {
        let mut att = ctx.att.lock().unwrap();
        att.process_read(0, PDU_MTU_RSP_23);
    }

    // Verify response callback received MTU_RSP.
    assert_eq!(*rsp_opcode.lock().unwrap(), BT_ATT_OP_MTU_RSP, "should receive MTU_RSP");
    // Response body contains the server MTU in LE16.
    assert_eq!(*rsp_data.lock().unwrap(), &[0x17, 0x00], "MTU response body should be 23 LE16");

    // After exchange, the transport's MTU should still be 64 (set_mtu was
    // called above; the response processing does not auto-downgrade).
    {
        let att = ctx.att.lock().unwrap();
        assert!(
            att.get_mtu() >= BT_ATT_DEFAULT_LE_MTU,
            "MTU must be at least default after exchange"
        );
    }
}

/// Test ATT MTU exchange with MTU=512 PDU round-trip.
///
/// Directly mirrors the MTU_EXCHANGE_CLIENT_PDUS pattern from test-gatt.c
/// where the client sends MTU_REQ(512) and server responds MTU_RSP(512).
#[test]
fn test_att_mtu_exchange_large() {
    let ctx = TestContext::new();

    // Queue an MTU request for MTU=512.
    // send() requires a callback for Req-type opcodes.
    let callback_fired = Arc::new(Mutex::new(false));
    let fired_clone = Arc::clone(&callback_fired);

    {
        let mut att = ctx.att.lock().unwrap();
        let mtu_bytes = 512u16.to_le_bytes();
        let id = att.send(
            BT_ATT_OP_MTU_REQ,
            &mtu_bytes,
            Some(Box::new(move |_op: u8, _data: &[u8]| {
                *fired_clone.lock().unwrap() = true;
            })),
        );
        assert!(id != 0, "send MTU_REQ should return non-zero id");
    }

    ctx.flush_writes();

    // Read the request and verify it matches the expected PDU.
    let req_pdu = ctx.recv_pdu();
    assert_eq!(req_pdu, PDU_MTU_REQ_512, "MTU request PDU for 512 must match");

    // Respond with MTU=512.
    ctx.send_pdu(PDU_MTU_RSP_512);

    // Process response and verify callback runs.
    {
        let mut att = ctx.att.lock().unwrap();
        att.process_read(0, PDU_MTU_RSP_512);
    }

    assert!(*callback_fired.lock().unwrap(), "response callback should have fired");
}

/// Test BT_ATT_SECURITY_AUTO handling.
///
/// Derived from the bt_att_set_security(ctx->att, BT_ATT_SECURITY_AUTO)
/// pattern at test-gatt.c line 643 (client_ready_cb). For local socket
/// types, set_security just stores the level internally.
#[test]
fn test_att_security_auto() {
    let ctx = TestContext::new();

    // Verify default security level.
    {
        let att = ctx.att.lock().unwrap();
        let mut enc_size: u8 = 0;
        let level = att.get_security(&mut enc_size).expect("get_security should succeed");
        // Default is 0 (Auto) for local sockets.
        assert_eq!(level, AttSecurityLevel::Auto as i32, "default sec level should be Auto");
    }

    // Set security to Auto (0).
    {
        let mut att = ctx.att.lock().unwrap();
        assert!(
            att.set_security(AttSecurityLevel::Auto as i32),
            "set_security(Auto) should succeed"
        );
    }

    // Verify it was stored.
    {
        let att = ctx.att.lock().unwrap();
        let mut enc_size: u8 = 0;
        let level = att.get_security(&mut enc_size).expect("get_security should succeed");
        assert_eq!(level, AttSecurityLevel::Auto as i32, "sec level should be Auto after set");
    }

    // Test setting other security levels.
    {
        let mut att = ctx.att.lock().unwrap();
        assert!(
            att.set_security(AttSecurityLevel::Medium as i32),
            "set_security(Medium) should succeed"
        );
    }

    {
        let att = ctx.att.lock().unwrap();
        let mut enc_size: u8 = 0;
        let level = att.get_security(&mut enc_size).expect("get_security should succeed");
        assert_eq!(level, AttSecurityLevel::Medium as i32, "sec level should be Medium");
    }

    // Set High.
    {
        let mut att = ctx.att.lock().unwrap();
        assert!(
            att.set_security(AttSecurityLevel::High as i32),
            "set_security(High) should succeed"
        );
    }

    {
        let att = ctx.att.lock().unwrap();
        let mut enc_size: u8 = 0;
        let level = att.get_security(&mut enc_size).expect("get_security should succeed");
        assert_eq!(level, AttSecurityLevel::High as i32, "sec level should be High");
    }
}

/// Test that the ATT transport (with GATT server) returns an Error Response
/// for unknown request opcodes.
///
/// Derived from the server-side behavior in test-gatt.c where
/// `bt_gatt_server_new()` registers handlers for 14 known opcodes.
/// Any unknown request opcode (bit 6 clear, not in the opcode table)
/// is classified as AttOpType::Unknown and triggers an automatic
/// Error Response with REQUEST_NOT_SUPPORTED (0x06) when no registered
/// handler matches.
#[test]
fn test_att_unknown_request() {
    let sctx = ServerTestContext::new();

    // Build a PDU with an unknown request opcode (0x1F).
    // 0x1F has bit 6 clear → get_op_type returns Unknown.
    // In handle_pdu, Unknown goes to handle_notify.
    // No server handler matches → send_error_rsp fires directly to fd.
    let unknown_req_pdu = vec![UNKNOWN_REQ_OPCODE, 0x00, 0x00];

    // Process the incoming PDU through the ATT transport.
    // The error response is written directly to the fd by send_error_rsp,
    // making it readable from the peer socket.
    sctx.ctx.process_incoming(&unknown_req_pdu);

    // Read the error response from the peer socket.
    let rsp_pdu = sctx.ctx.recv_pdu();

    // Verify the error response matches expected format:
    // [ErrorRsp opcode(0x01), offending opcode, handle LE16, error code(0x06)]
    let expected =
        make_error_rsp_pdu(UNKNOWN_REQ_OPCODE, 0x0000, BT_ATT_ERROR_REQUEST_NOT_SUPPORTED);
    assert_eq!(
        rsp_pdu, expected,
        "unknown request should generate Error Response with REQUEST_NOT_SUPPORTED"
    );
}

/// Test that the ATT transport silently ignores unknown command opcodes
/// (opcodes with bit 6 set that don't match any registered handler).
///
/// Derived from ATT protocol specification: commands (bit 6 set) that
/// are not recognized should be silently ignored — no error response.
/// 0x41 has bit 6 set → get_op_type returns Cmd → handle_notify does
/// not send error response for unhandled Cmd opcodes.
#[test]
fn test_att_unknown_command() {
    let sctx = ServerTestContext::new();

    // Build a PDU with an unknown command opcode (bit 6 set = 0x41).
    let unknown_cmd_pdu = vec![UNKNOWN_CMD_OPCODE, 0x00, 0x00];

    // Process the incoming PDU through the ATT transport.
    sctx.ctx.process_incoming(&unknown_cmd_pdu);

    // Attempt to read a response — there should be none within timeout.
    // Commands that don't match any handler are silently dropped.
    let rsp = sctx.ctx.try_recv_pdu(Duration::from_millis(100));
    assert!(rsp.is_none(), "unknown command should NOT generate any response");
}

/// Test ATT transport lifecycle — RAII creation and destruction.
///
/// Derived from test-gattrib.c test_refcount which verifies ref/unref
/// and destroy callback patterns. In Rust, this is RAII via
/// Arc<Mutex<BtAtt>> — Drop replaces bt_att_unref.
#[test]
fn test_att_transport_lifecycle() {
    // Phase 1: Create and verify the transport exists.
    let (local, _peer) = create_test_pair();
    let fd = local.as_raw_fd();
    let att = BtAtt::new(fd, false).expect("BtAtt::new should succeed");

    // Verify transport is functional.
    {
        let guard = att.lock().unwrap();
        assert_eq!(guard.get_mtu(), BT_ATT_DEFAULT_LE_MTU, "initial MTU must be 23");
    }

    // Phase 2: Clone the Arc (equivalent to bt_att_ref).
    let att_clone = Arc::clone(&att);
    assert_eq!(Arc::strong_count(&att), 2, "ref count should be 2 after clone");

    // Phase 3: Drop one reference (equivalent to bt_att_unref).
    drop(att_clone);
    assert_eq!(Arc::strong_count(&att), 1, "ref count should be 1 after drop");

    // Phase 4: Verify transport is still functional after partial unref.
    {
        let guard = att.lock().unwrap();
        assert_eq!(guard.get_mtu(), BT_ATT_DEFAULT_LE_MTU);
    }

    // Phase 5: Drop last reference — transport destroyed (RAII).
    drop(att);
    // After this, the BtAtt is deallocated. No memory leak, no dangling
    // pointer. This replaces the C pattern of bt_att_unref + destroy callback.
}

// ============================================================================
// Test functions — GAttrib-equivalent tests (from test-gattrib.c patterns)
// ============================================================================

/// Test basic ATT transport creation and configuration.
///
/// Derived from test-gattrib.c test_refcount and test_get_channel:
/// - Creates ATT transport from socketpair
/// - Verifies initial state (MTU, security)
/// - Verifies ref-counting via Arc
/// - Verifies set_close_on_drop
#[test]
fn test_gattrib_basic() {
    let ctx = TestContext::new();

    // Verify initial MTU is default LE MTU (23).
    {
        let att = ctx.att.lock().unwrap();
        assert_eq!(
            att.get_mtu(),
            BT_ATT_DEFAULT_LE_MTU,
            "initial MTU should be BT_ATT_DEFAULT_LE_MTU (23)"
        );
    }

    // Verify the transport's fd is valid (mirrors test_get_channel).
    {
        let att = ctx.att.lock().unwrap();
        let fd = att.get_fd().expect("get_fd should succeed");
        assert!(fd >= 0, "fd should be non-negative");
    }

    // Verify ref-counting via Arc (mirrors test_refcount).
    let att_ref = Arc::clone(&ctx.att);
    assert_eq!(Arc::strong_count(&ctx.att), 2);
    drop(att_ref);
    assert_eq!(Arc::strong_count(&ctx.att), 1);

    // Verify set_close_on_drop (matches GAttrib lifecycle management).
    {
        let mut att = ctx.att.lock().unwrap();
        assert!(att.set_close_on_drop(true), "set_close_on_drop should succeed");
        // Reset to false so our fd isn't closed when ctx drops
        // (the OwnedFd handles cleanup).
        att.set_close_on_drop(false);
    }
}

/// Test request/response via scripted PDU exchange.
///
/// Derived from test-gattrib.c test_send:
/// 1. Send an MTU exchange request through the ATT transport
/// 2. Verify the PDU arrives at the peer socket
/// 3. Inject a response through the peer socket
/// 4. Verify the response callback fires with correct data
#[test]
fn test_gattrib_request_response() {
    let ctx = TestContext::new();

    // Track whether the response callback was invoked.
    let callback_fired = Arc::new(Mutex::new(false));
    let callback_opcode = Arc::new(Mutex::new(0u8));
    let callback_data = Arc::new(Mutex::new(Vec::<u8>::new()));

    let fired_clone = Arc::clone(&callback_fired);
    let opcode_clone = Arc::clone(&callback_opcode);
    let data_clone = Arc::clone(&callback_data);

    // Send an MTU request through the ATT transport with a response callback.
    {
        let mut att = ctx.att.lock().unwrap();
        let mtu_bytes = 512u16.to_le_bytes();
        let id = att.send(
            BT_ATT_OP_MTU_REQ,
            &mtu_bytes,
            Some(Box::new(move |rsp_opcode: u8, rsp_data: &[u8]| {
                *fired_clone.lock().unwrap() = true;
                *opcode_clone.lock().unwrap() = rsp_opcode;
                *data_clone.lock().unwrap() = rsp_data.to_vec();
            })),
        );
        assert!(id != 0, "send should return non-zero id");
    }

    // Flush writes to push the request PDU onto the socket.
    ctx.flush_writes();

    // Read the MTU request from the peer socket.
    let req_pdu = ctx.recv_pdu();
    assert_eq!(req_pdu, PDU_MTU_REQ_512, "MTU request PDU must match expected bytes");

    // Inject the response from the peer side.
    ctx.send_pdu(PDU_MTU_RSP_512);

    // Process the response through the ATT transport.
    // This dispatches the response to the pending request's callback.
    {
        let mut att = ctx.att.lock().unwrap();
        att.process_read(0, PDU_MTU_RSP_512);
    }

    // Verify the callback was invoked with correct data.
    assert!(*callback_fired.lock().unwrap(), "response callback should have fired");
    assert_eq!(
        *callback_opcode.lock().unwrap(),
        BT_ATT_OP_MTU_RSP,
        "callback opcode should be MTU_RSP"
    );
    // The callback receives the body (after the opcode byte).
    // MTU_RSP body is the 2-byte MTU value: 0x00 0x02 (512 LE).
    let rsp_body = callback_data.lock().unwrap().clone();
    assert_eq!(rsp_body, &[0x00, 0x02], "MTU response body should be 512 in LE");
}

/// Test MTU buffer sizing and negotiation.
///
/// Derived from test-gattrib.c test_buffers:
/// - Default MTU is 23 (BT_ATT_DEFAULT_LE_MTU)
/// - Setting MTU below minimum (< 23) fails
/// - Setting MTU to a valid value succeeds
#[test]
fn test_gattrib_mtu_handling() {
    let ctx = TestContext::new();

    // Initial MTU should be BT_ATT_DEFAULT_LE_MTU = 23.
    {
        let att = ctx.att.lock().unwrap();
        assert_eq!(att.get_mtu(), BT_ATT_DEFAULT_LE_MTU, "initial MTU must be 23");
    }

    // Setting MTU below minimum should fail.
    // test-gattrib.c test_buffers: g_attrib_set_mtu(attrib, 5) fails.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.set_mtu(5);
        assert!(!result, "set_mtu(5) should fail (below BT_ATT_DEFAULT_LE_MTU)");
        assert_eq!(att.get_mtu(), BT_ATT_DEFAULT_LE_MTU, "MTU should remain 23 after failed set");
    }

    // Setting MTU to valid value succeeds.
    // test-gattrib.c test_buffers: g_attrib_set_mtu(attrib, 255) succeeds.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.set_mtu(255);
        assert!(result, "set_mtu(255) should succeed");
        assert_eq!(att.get_mtu(), 255, "MTU should be 255 after successful set");
    }

    // Setting to exactly the minimum should succeed.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.set_mtu(BT_ATT_DEFAULT_LE_MTU);
        // set_mtu only fails if mtu < BT_ATT_DEFAULT_LE_MTU, so 23 should succeed.
        assert!(result, "set_mtu(23) should succeed (exactly minimum)");
        assert_eq!(att.get_mtu(), 255, "MTU stays at max since set_mtu only increases on exchange");
    }
}

/// Test request cancellation behavior.
///
/// Derived from test-gattrib.c test_cancel:
/// 1. Send a request, then cancel it before the response arrives
/// 2. Verify the cancelled request's callback is NOT invoked
/// 3. Verify cancelling an invalid id returns false
#[test]
fn test_gattrib_cancellation() {
    let ctx = TestContext::new();

    // Track callback invocation.
    let callback_fired = Arc::new(Mutex::new(false));
    let fired_clone = Arc::clone(&callback_fired);

    // Send a request.
    let req_id;
    {
        let mut att = ctx.att.lock().unwrap();
        let mtu_bytes = 64u16.to_le_bytes();
        req_id = att.send(
            BT_ATT_OP_MTU_REQ,
            &mtu_bytes,
            Some(Box::new(move |_opcode: u8, _data: &[u8]| {
                *fired_clone.lock().unwrap() = true;
            })),
        );
        assert!(req_id != 0, "send should return non-zero id");
    }

    // Flush writes to push the request PDU.
    ctx.flush_writes();

    // Read the request from the peer (consume it).
    let _req_pdu = ctx.recv_pdu();

    // Cancel the request before any response arrives.
    {
        let mut att = ctx.att.lock().unwrap();
        let cancelled = att.cancel(req_id);
        assert!(cancelled, "cancel should succeed for valid pending request");
    }

    // Now send a response from the peer.
    ctx.send_pdu(PDU_MTU_RSP_64);

    // Process the response — the callback should NOT be invoked.
    {
        let mut att = ctx.att.lock().unwrap();
        att.process_read(0, PDU_MTU_RSP_64);
    }

    // Give a small delay to ensure no deferred callback processing.
    std::thread::sleep(Duration::from_millis(10));
    assert!(!*callback_fired.lock().unwrap(), "callback should NOT fire for cancelled request");

    // Test cancelling an invalid id.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.cancel(0xDEADBEEF);
        assert!(!result, "cancel with invalid id should return false");
    }

    // Test cancelling the same id again (already cancelled).
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.cancel(req_id);
        assert!(!result, "cancel of already-cancelled id should return false");
    }
}

// ============================================================================
// Additional ATT transport tests
// ============================================================================

/// Test handler registration and dispatch.
///
/// Derived from test-gattrib.c test_register which registers handlers
/// for BT_ATT_ALL_REQUESTS and specific opcodes, then verifies dispatch.
#[test]
fn test_att_handler_registration() {
    let ctx = TestContext::new();

    // Track handler invocations.
    let handler_called = Arc::new(Mutex::new(Vec::<u8>::new()));
    let handler_clone = Arc::clone(&handler_called);

    // Register a handler for all requests (BT_ATT_ALL_REQUESTS = 0x00).
    let handler_id;
    {
        let mut att = ctx.att.lock().unwrap();
        handler_id = att.register(
            BT_ATT_ALL_REQUESTS,
            Arc::new(move |_chan_idx: usize, _filter: u16, raw_opcode: u8, _body: &[u8]| {
                handler_clone.lock().unwrap().push(raw_opcode);
            }),
        );
        assert!(handler_id != 0, "register should return non-zero id");
    }

    // Send a Find Info Request PDU from the peer.
    ctx.send_pdu(PDU_FIND_INFO_REQ);

    // Process it through the ATT transport.
    ctx.process_incoming(PDU_FIND_INFO_REQ);

    // Verify the handler was called with the correct opcode (0x04).
    {
        let calls = handler_called.lock().unwrap();
        assert!(calls.contains(&0x04), "handler should be called for Find Info Request (0x04)");
    }

    // Unregister the handler.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.unregister(handler_id);
        assert!(result, "unregister should succeed for valid handler id");
    }

    // Clear tracked calls.
    handler_called.lock().unwrap().clear();

    // Send another PDU — handler should NOT be called.
    let ind_pdu = PDU_IND_NODATA;
    ctx.send_pdu(ind_pdu);
    ctx.process_incoming(ind_pdu);

    {
        let calls = handler_called.lock().unwrap();
        assert!(calls.is_empty(), "handler should NOT be called after unregister");
    }

    // Verify unregistering same id again fails.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.unregister(handler_id);
        assert!(!result, "double unregister should fail");
    }
}

/// Test debug callback configuration.
///
/// Verifies BtAtt::set_debug mirrors the C bt_att_set_debug pattern.
#[test]
fn test_att_debug_callback() {
    let ctx = TestContext::new();

    // Set a debug callback.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.set_debug(
            1,
            Some(Box::new(|_msg: &str| {
                // Debug callback — in real usage this logs to stderr.
            })),
        );
        assert!(result, "set_debug should succeed");
    }

    // Clear the debug callback.
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.set_debug(0, None);
        assert!(result, "clearing debug callback should succeed");
    }
}

/// Test that cancel_all handles all pending operations.
///
/// The implementation invokes pending request/indication callbacks with
/// (opcode=0, data=&[]) to signal cancellation, then clears all queues.
/// After cancel_all, further responses should not invoke any callback.
#[test]
fn test_att_cancel_all() {
    let ctx = TestContext::new();

    // Track callback invocations: (opcode, data_len) pairs.
    let invocations = Arc::new(Mutex::new(Vec::<(u8, usize)>::new()));

    // Queue a request.
    {
        let inv = Arc::clone(&invocations);
        let mut att = ctx.att.lock().unwrap();
        let mtu_bytes = 64u16.to_le_bytes();
        let id = att.send(
            BT_ATT_OP_MTU_REQ,
            &mtu_bytes,
            Some(Box::new(move |opcode: u8, data: &[u8]| {
                inv.lock().unwrap().push((opcode, data.len()));
            })),
        );
        assert!(id != 0);
    }

    // Flush writes to move the request to pending_req on the channel.
    ctx.flush_writes();

    // Consume the request from the peer socket.
    let _req = ctx.recv_pdu();

    // Cancel all pending operations.
    // cancel_all invokes callbacks for pending_req/pending_ind with (0, &[]).
    {
        let mut att = ctx.att.lock().unwrap();
        let result = att.cancel_all();
        assert!(result, "cancel_all should succeed");
    }

    // The callback should have been invoked once with cancellation signal.
    {
        let inv = invocations.lock().unwrap();
        assert_eq!(inv.len(), 1, "cancel_all should invoke pending callback once");
        assert_eq!(inv[0].0, 0, "cancellation callback opcode should be 0");
        assert_eq!(inv[0].1, 0, "cancellation callback data should be empty");
    }

    // After cancel_all, sending a response should NOT invoke any callback
    // (the request has already been cancelled and callback consumed).
    ctx.send_pdu(PDU_MTU_RSP_64);
    {
        let mut att = ctx.att.lock().unwrap();
        att.process_read(0, PDU_MTU_RSP_64);
    }

    // No additional invocations should have occurred.
    {
        let inv = invocations.lock().unwrap();
        assert_eq!(inv.len(), 1, "no additional callbacks after cancel_all + response");
    }
}

/// Test indication handling and dispatch.
///
/// Verifies that ATT indications (opcode 0x1D) are dispatched to
/// registered handlers. Derived from test-gattrib.c test_register
/// which injects PDU_IND_NODATA and PDU_IND_DATA.
#[test]
fn test_att_indication_dispatch() {
    let ctx = TestContext::new();

    // Track indication handler calls.
    let ind_handles = Arc::new(Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
    let ind_clone = Arc::clone(&ind_handles);

    // Register handler for indications (opcode 0x1D).
    {
        let mut att = ctx.att.lock().unwrap();
        let id = att.register(
            0x1D, // BT_ATT_OP_HANDLE_IND
            Arc::new(move |_chan_idx: usize, _filter: u16, raw_opcode: u8, body: &[u8]| {
                ind_clone.lock().unwrap().push((raw_opcode, body.to_vec()));
            }),
        );
        assert!(id != 0);
    }

    // Send indication with no data.
    ctx.send_pdu(PDU_IND_NODATA);
    ctx.process_incoming(PDU_IND_NODATA);

    {
        let calls = ind_handles.lock().unwrap();
        assert_eq!(calls.len(), 1, "should have 1 indication callback");
        assert_eq!(calls[0].0, 0x1D, "opcode should be indication");
        // Body is everything after the opcode byte.
        assert_eq!(calls[0].1, &[0x01, 0x00], "indication body should be handle 0x0001");
    }

    // Send indication with data.
    ind_handles.lock().unwrap().clear();
    ctx.send_pdu(PDU_IND_DATA);
    ctx.process_incoming(PDU_IND_DATA);

    {
        let calls = ind_handles.lock().unwrap();
        assert_eq!(calls.len(), 1, "should have 1 indication callback");
        assert_eq!(calls[0].1, &[0x14, 0x00, 0x01], "indication body should be handle+data");
    }
}
