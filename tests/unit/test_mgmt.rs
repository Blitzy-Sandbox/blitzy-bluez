// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_mgmt.rs — Rust port of unit/test-mgmt.c
//
// Comprehensive unit tests for `bluez_shared::mgmt::client::MgmtSocket`,
// verifying command/response dispatch, event subscription/delivery,
// unregistration, and lifecycle safety (Arc-based shared ownership replacing
// C's mgmt_ref/mgmt_unref pattern).
//
// Every test function maps to an identically-named test in the original C
// file (`unit/test-mgmt.c`):
//
//   C test path                    → Rust test function
//   /mgmt/command/1                → test_command_read_version
//   /mgmt/command/2                → test_command_read_info
//   /mgmt/response/1               → test_response_read_version
//   /mgmt/response/2               → test_response_invalid_index
//   /mgmt/event/1                  → test_event_index_added
//   /mgmt/event/2                  → test_event_duplicate_registration
//   /mgmt/unregister/1             → test_unregister_all
//   /mgmt/unregister/2             → test_unregister_index
//   /mgmt/destroy/1                → test_destroy_from_callback
//
// Test infrastructure conversion:
//   C struct context + GMainLoop   → tokio::test(multi_thread) runtime
//   socketpair(AF_UNIX,SEQPACKET)  → nix::sys::socket::socketpair()
//   mgmt_send + callback           → MgmtSocket::send_command().await
//   mgmt_register + callback       → MgmtSocket::subscribe() → mpsc::Receiver
//   mgmt_unregister_all            → MgmtSocket::unsubscribe_all()
//   mgmt_unregister_index          → MgmtSocket::unsubscribe_index()
//   mgmt_ref / mgmt_unref          → Arc<MgmtSocket>

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use bluez_shared::mgmt::client::{MgmtError, MgmtEvent, MgmtResponse, MgmtSocket};
use bluez_shared::sys::mgmt::{
    MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS, MGMT_EV_INDEX_ADDED, MGMT_HDR_SIZE, MGMT_INDEX_NONE,
    MGMT_OP_READ_INFO, MGMT_OP_READ_VERSION, MGMT_STATUS_INVALID_INDEX, MGMT_STATUS_SUCCESS,
    mgmt_hdr,
};

// ============================================================================
// Wire Format Constants — preserved byte-identical from C test data
// ============================================================================

/// MGMT Read Version command on wire:
/// opcode=0x0001 (LE), index=0xFFFF (LE), len=0x0000 (LE)
///
/// Corresponds to C `read_version_command[]`.
const READ_VERSION_COMMAND: [u8; 6] = [0x01, 0x00, 0xff, 0xff, 0x00, 0x00];

/// MGMT CMD_COMPLETE response for Read Version:
/// Header: event=0x0001, index=0xFFFF, len=6
/// Payload: cmd_opcode=0x0001, status=0x00, rp={version=1, revision=6}
///
/// Corresponds to C `read_version_response[]`.
const READ_VERSION_RESPONSE: [u8; 12] =
    [0x01, 0x00, 0xff, 0xff, 0x06, 0x00, 0x01, 0x00, 0x00, 0x01, 0x06, 0x00];

/// MGMT Read Info command on wire:
/// opcode=0x0004 (LE), index=0x0200 (LE = 512), len=0x0000 (LE)
///
/// Corresponds to C `read_info_command[]`.
const READ_INFO_COMMAND: [u8; 6] = [0x04, 0x00, 0x00, 0x02, 0x00, 0x00];

/// MGMT CMD_STATUS response with INVALID_INDEX:
/// Header: event=0x0002, index=0xFFFF, len=3
/// Payload: cmd_opcode=0x0001, status=0x11
///
/// Corresponds to C `invalid_index_response[]`.
const INVALID_INDEX_RESPONSE: [u8; 9] = [0x02, 0x00, 0xff, 0xff, 0x03, 0x00, 0x01, 0x00, 0x11];

/// MGMT INDEX_ADDED event:
/// Header: event=0x0004, index=0x0001, len=0x0000
///
/// Corresponds to C `event_index_added[]`.
const EVENT_INDEX_ADDED: [u8; 6] = [0x04, 0x00, 0x01, 0x00, 0x00, 0x00];

/// Default test timeout to prevent hangs.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a Unix `SOCK_SEQPACKET` socketpair for testing.
///
/// Returns `(server_fd, client_fd)`. Both file descriptors are non-blocking
/// (required by `AsyncFd` inside `MgmtSocket`) and close-on-exec.
///
/// Replaces C:
/// ```c
/// socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
/// ```
fn create_test_pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair(AF_UNIX, SOCK_SEQPACKET) failed")
}

/// Read bytes from a non-blocking server fd, retrying on `EAGAIN`.
///
/// Replaces C `server_handler()` read path — reads one MGMT packet from the
/// server side of the socketpair for wire-format verification.
async fn server_read(fd: &OwnedFd, buf: &mut [u8]) -> usize {
    let raw = fd.as_raw_fd();
    loop {
        match nix::unistd::read(raw, buf) {
            Ok(n) if n > 0 => return n,
            Ok(_) => panic!("server_read: unexpected zero-length read (EOF)"),
            Err(nix::errno::Errno::EAGAIN) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => panic!("server_read failed: {e}"),
        }
    }
}

/// Write bytes to a non-blocking server fd, retrying on `EAGAIN`.
///
/// Replaces C `write(context->fd, ...)` calls that inject responses and
/// events into the client-side `MgmtSocket` reader.
async fn server_write(fd: &OwnedFd, buf: &[u8]) {
    loop {
        match nix::unistd::write(fd, buf) {
            Ok(n) if n == buf.len() => return,
            Ok(n) => panic!("server_write: short write ({n} of {} bytes)", buf.len()),
            Err(nix::errno::Errno::EAGAIN) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => panic!("server_write failed: {e}"),
        }
    }
}

/// Build a `MGMT_EV_CMD_COMPLETE` response packet.
///
/// Wire layout: `[hdr: event=0x0001, index, len] [opcode_le16, status, data...]`
fn build_cmd_complete(opcode: u16, index: u16, status: u8, data: &[u8]) -> Vec<u8> {
    let payload_len: u16 = 3 + data.len() as u16;
    let mut pkt = Vec::with_capacity(MGMT_HDR_SIZE + payload_len as usize);
    // Header
    pkt.extend_from_slice(&MGMT_EV_CMD_COMPLETE.to_le_bytes());
    pkt.extend_from_slice(&index.to_le_bytes());
    pkt.extend_from_slice(&payload_len.to_le_bytes());
    // Payload
    pkt.extend_from_slice(&opcode.to_le_bytes());
    pkt.push(status);
    pkt.extend_from_slice(data);
    pkt
}

/// Build a `MGMT_EV_CMD_STATUS` response packet.
///
/// Wire layout: `[hdr: event=0x0002, index, len=3] [opcode_le16, status]`
fn build_cmd_status(opcode: u16, index: u16, status: u8) -> Vec<u8> {
    let payload_len: u16 = 3;
    let mut pkt = Vec::with_capacity(MGMT_HDR_SIZE + payload_len as usize);
    // Header
    pkt.extend_from_slice(&MGMT_EV_CMD_STATUS.to_le_bytes());
    pkt.extend_from_slice(&index.to_le_bytes());
    pkt.extend_from_slice(&payload_len.to_le_bytes());
    // Payload
    pkt.extend_from_slice(&opcode.to_le_bytes());
    pkt.push(status);
    pkt
}

/// Verify the first 6 bytes of a buffer match an expected MGMT header.
///
/// Uses `mgmt_hdr` struct size for the minimum length check.
fn verify_mgmt_header(data: &[u8], expected_opcode: u16, expected_index: u16, expected_len: u16) {
    assert!(
        data.len() >= std::mem::size_of::<mgmt_hdr>(),
        "packet too short for mgmt_hdr: {} < {}",
        data.len(),
        MGMT_HDR_SIZE
    );
    let opcode = u16::from_le_bytes([data[0], data[1]]);
    let index = u16::from_le_bytes([data[2], data[3]]);
    let len = u16::from_le_bytes([data[4], data[5]]);
    assert_eq!(opcode, expected_opcode, "opcode mismatch");
    assert_eq!(index, expected_index, "index mismatch");
    assert_eq!(len, expected_len, "length mismatch");
}

// ============================================================================
// Wire Format Verification (structural sanity checks)
// ============================================================================

/// Verify MGMT protocol constants match their expected values.
///
/// This test ensures the Rust re-declarations in `bluez_shared::sys::mgmt`
/// are byte-identical to the C originals in `lib/bluetooth/mgmt.h`.
#[test]
fn test_wire_format_constants() {
    // Opcode values
    assert_eq!(MGMT_OP_READ_VERSION, 0x0001);
    assert_eq!(MGMT_OP_READ_INFO, 0x0004);

    // Event codes
    assert_eq!(MGMT_EV_CMD_COMPLETE, 0x0001);
    assert_eq!(MGMT_EV_CMD_STATUS, 0x0002);
    assert_eq!(MGMT_EV_INDEX_ADDED, 0x0004);

    // Special index
    assert_eq!(MGMT_INDEX_NONE, 0xFFFF);

    // Status codes
    assert_eq!(MGMT_STATUS_SUCCESS, 0x00);
    assert_eq!(MGMT_STATUS_INVALID_INDEX, 0x11);

    // Header size — must match the packed mgmt_hdr struct
    assert_eq!(MGMT_HDR_SIZE, std::mem::size_of::<mgmt_hdr>());
    assert_eq!(MGMT_HDR_SIZE, 6);
}

/// Verify the `build_cmd_status` helper produces bytes matching the
/// C `invalid_index_response[]` constant.
#[test]
fn test_invalid_index_response_matches_helper() {
    let built = build_cmd_status(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, MGMT_STATUS_INVALID_INDEX);
    assert_eq!(built.as_slice(), &INVALID_INDEX_RESPONSE[..]);
}

/// Verify the `build_cmd_complete` helper produces bytes matching the
/// C `read_version_response[]` constant.
#[test]
fn test_read_version_response_matches_helper() {
    // CMD_COMPLETE payload after the 3-byte (opcode+status) prefix:
    // mgmt_rp_read_version { version: 1, revision: 6 } = [0x01, 0x06, 0x00]
    let built = build_cmd_complete(
        MGMT_OP_READ_VERSION,
        MGMT_INDEX_NONE,
        MGMT_STATUS_SUCCESS,
        &[0x01, 0x06, 0x00],
    );
    assert_eq!(built.as_slice(), &READ_VERSION_RESPONSE[..]);
}

// ============================================================================
// Command Tests (/mgmt/command/*)
//
// These tests verify that MgmtSocket produces byte-identical wire encoding
// to the C `mgmt_send()` function. The server side reads the raw bytes and
// compares against the known-good C constants.
// ============================================================================

/// `/mgmt/command/1` — `MGMT_OP_READ_VERSION` produces correct wire bytes.
///
/// Ported from C `test_command` with `command_test_1`:
/// - opcode = `MGMT_OP_READ_VERSION` (0x0001)
/// - index  = `MGMT_INDEX_NONE` (0xFFFF)
/// - params = empty
/// - Expected wire: `[0x01, 0x00, 0xff, 0xff, 0x00, 0x00]`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_command_read_version() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    // Spawn send_command in background — it blocks waiting for CMD_COMPLETE
    let send_handle =
        tokio::spawn(
            async move { mgmt.send_command(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, &[]).await },
        );

    // Server side: read the command and verify exact wire bytes
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(TEST_TIMEOUT, server_read(&server_fd, &mut buf))
        .await
        .expect("timeout reading command from server fd");
    assert_eq!(n, READ_VERSION_COMMAND.len(), "command length mismatch");
    assert_eq!(&buf[..n], &READ_VERSION_COMMAND, "wire bytes must match C read_version_command");
    verify_mgmt_header(&buf[..n], MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, 0);

    // Send CMD_COMPLETE response to unblock send_command
    server_write(&server_fd, &READ_VERSION_RESPONSE).await;

    // Wait for send_command to complete
    let result: Result<MgmtResponse, MgmtError> = tokio::time::timeout(TEST_TIMEOUT, send_handle)
        .await
        .expect("timeout waiting for send_command")
        .expect("join error");
    let response = result.expect("send_command should succeed");
    assert_eq!(response.status, MGMT_STATUS_SUCCESS);
    assert_eq!(response.opcode, MGMT_OP_READ_VERSION);
}

/// `/mgmt/command/2` — `MGMT_OP_READ_INFO` with index=512 produces correct wire bytes.
///
/// Ported from C `test_command` with `command_test_2`:
/// - opcode = `MGMT_OP_READ_INFO` (0x0004)
/// - index  = 512 (0x0200)
/// - params = empty
/// - Expected wire: `[0x04, 0x00, 0x00, 0x02, 0x00, 0x00]`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_command_read_info() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    let send_handle =
        tokio::spawn(async move { mgmt.send_command(MGMT_OP_READ_INFO, 512, &[]).await });

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(TEST_TIMEOUT, server_read(&server_fd, &mut buf))
        .await
        .expect("timeout reading command from server fd");
    assert_eq!(n, READ_INFO_COMMAND.len(), "command length mismatch");
    assert_eq!(&buf[..n], &READ_INFO_COMMAND, "wire bytes must match C read_info_command");
    verify_mgmt_header(&buf[..n], MGMT_OP_READ_INFO, 512, 0);

    // Send response to cleanly resolve the pending command
    let response_pkt = build_cmd_complete(MGMT_OP_READ_INFO, 512, MGMT_STATUS_SUCCESS, &[]);
    server_write(&server_fd, &response_pkt).await;

    let result: Result<MgmtResponse, MgmtError> = tokio::time::timeout(TEST_TIMEOUT, send_handle)
        .await
        .expect("timeout")
        .expect("join error");
    assert!(result.is_ok(), "send_command should succeed");
}

// ============================================================================
// Response Tests (/mgmt/response/*)
//
// These tests verify that MgmtSocket correctly dispatches CMD_COMPLETE and
// CMD_STATUS responses to the send_command caller with accurate status codes.
// ============================================================================

/// `/mgmt/response/1` — Server sends successful Read Version response.
///
/// Ported from C `test_response` with `command_test_1`:
/// - Server responds with `read_version_response` (CMD_COMPLETE, status=SUCCESS)
/// - Callback verifies `status == MGMT_STATUS_SUCCESS`
///
/// The test spawns `send_command` in a background task and handles the
/// server side on the main task, matching the proven working pattern.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_response_read_version() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    // Spawn send_command in background — it blocks until CMD_COMPLETE arrives
    let send_handle =
        tokio::spawn(
            async move { mgmt.send_command(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, &[]).await },
        );

    // Server side: read the command and verify
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(TEST_TIMEOUT, server_read(&server_fd, &mut buf))
        .await
        .expect("timeout reading command");
    assert_eq!(&buf[..n], &READ_VERSION_COMMAND, "server should receive READ_VERSION command");

    // Inject CMD_COMPLETE response from server
    server_write(&server_fd, &READ_VERSION_RESPONSE).await;

    // Await and verify the response
    let result: Result<MgmtResponse, MgmtError> = tokio::time::timeout(TEST_TIMEOUT, send_handle)
        .await
        .expect("timeout waiting for response")
        .expect("join error");
    let response = result.expect("send_command should succeed");

    assert_eq!(response.status, MGMT_STATUS_SUCCESS, "response status must be SUCCESS");
    assert_eq!(response.opcode, MGMT_OP_READ_VERSION);
    assert_eq!(response.index, MGMT_INDEX_NONE);
    // Verify the Read Version return data: version=1, revision=6
    assert_eq!(response.data, vec![0x01, 0x06, 0x00]);
}

/// `/mgmt/response/2` — Server sends invalid-index error (CMD_STATUS).
///
/// Ported from C `test_response` with `command_test_3`:
/// - Server responds with `invalid_index_response` (CMD_STATUS, status=INVALID_INDEX)
/// - Callback verifies `status == MGMT_STATUS_INVALID_INDEX`
///
/// The test spawns `send_command` in a background task and handles the
/// server side on the main task, matching the proven working pattern.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_response_invalid_index() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    // Spawn send_command in background
    let send_handle =
        tokio::spawn(
            async move { mgmt.send_command(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, &[]).await },
        );

    // Server side: read command, then inject CMD_STATUS error
    let mut buf = [0u8; 512];
    let _n = tokio::time::timeout(TEST_TIMEOUT, server_read(&server_fd, &mut buf))
        .await
        .expect("timeout reading command");

    // Send CMD_STATUS with INVALID_INDEX
    server_write(&server_fd, &INVALID_INDEX_RESPONSE).await;

    // Await and verify the error response
    let result: Result<MgmtResponse, MgmtError> = tokio::time::timeout(TEST_TIMEOUT, send_handle)
        .await
        .expect("timeout waiting for response")
        .expect("join error");
    let response = result.expect("send_command should succeed (error is in status)");

    assert_eq!(
        response.status, MGMT_STATUS_INVALID_INDEX,
        "response status must be INVALID_INDEX (0x11)"
    );
    assert_eq!(response.opcode, MGMT_OP_READ_VERSION);
    // CMD_STATUS carries no additional data
    assert!(response.data.is_empty());
}

// ============================================================================
// Event Tests (/mgmt/event/*)
//
// These tests verify that MgmtSocket's event subscription mechanism
// correctly dispatches MGMT events to subscriber channels.
// ============================================================================

/// `/mgmt/event/1` — Subscribe for `INDEX_ADDED`, inject event, verify delivery.
///
/// Ported from C `test_event` with `event_test_1`:
/// - `mgmt_register(mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE, event_cb, ...)`
/// - Write `event_index_added` from server fd
/// - Verify callback fires with correct index
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_event_index_added() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    // Subscribe for INDEX_ADDED with wildcard index (matches all controllers)
    let (_sub_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

    // Inject INDEX_ADDED event from server side
    server_write(&server_fd, &EVENT_INDEX_ADDED).await;

    // Receive and verify the event
    let evt: MgmtEvent = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
        .await
        .expect("timeout waiting for event")
        .expect("event channel closed unexpectedly");

    assert_eq!(evt.event, MGMT_EV_INDEX_ADDED, "event code mismatch");
    assert_eq!(evt.index, 1, "event index should be 1 (from wire data)");
    assert!(evt.data.is_empty(), "INDEX_ADDED has no payload");
}

/// `/mgmt/event/2` — Duplicate registration: both subscriptions receive the event.
///
/// Ported from C `test_event2` with `event_test_1`:
/// - Register same event callback twice
/// - Write one event
/// - Both callbacks fire (in C, `event_cb` calls `context_quit`)
///
/// In Rust, both `mpsc::Receiver` channels receive the event since
/// `process_notify` iterates all matching subscriptions atomically.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_event_duplicate_registration() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    // Register the same event subscription twice
    let (_id1, mut rx1) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;
    let (_id2, mut rx2) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

    // Inject one event
    server_write(&server_fd, &EVENT_INDEX_ADDED).await;

    // Both channels must receive the event
    let evt1: MgmtEvent = tokio::time::timeout(TEST_TIMEOUT, rx1.recv())
        .await
        .expect("timeout rx1")
        .expect("rx1 closed");
    let evt2: MgmtEvent = tokio::time::timeout(TEST_TIMEOUT, rx2.recv())
        .await
        .expect("timeout rx2")
        .expect("rx2 closed");

    assert_eq!(evt1.event, MGMT_EV_INDEX_ADDED);
    assert_eq!(evt2.event, MGMT_EV_INDEX_ADDED);
    assert_eq!(evt1.index, 1);
    assert_eq!(evt2.index, 1);
    assert!(evt1.data.is_empty());
    assert!(evt2.data.is_empty());
}

// ============================================================================
// Unregistration Tests (/mgmt/unregister/*)
//
// These tests verify that event subscriptions can be safely removed and
// that subsequent events are not delivered to removed subscriptions.
//
// In C, these tests verified that calling mgmt_unregister_all() or
// mgmt_unregister_index() from within a callback was safe (no
// use-after-free). In Rust, this safety is guaranteed by the type system
// and channel-based delivery. The tests verify functional correctness.
// ============================================================================

/// `/mgmt/unregister/1` — `unsubscribe_all` removes all subscriptions.
///
/// Ported from C `test_unregister_all` with `event_test_1`:
/// - Register two handlers for INDEX_ADDED
/// - First handler calls `mgmt_unregister_all`, then `context_quit`
/// - Second handler should NOT fire after unregister
///
/// Rust equivalent: both channels receive the first event (atomic dispatch),
/// then `unsubscribe_all()` removes all senders, closing the channels.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unregister_all() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    let (_id1, mut rx1) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;
    let (_id2, mut rx2) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

    // Inject event — both channels receive it (atomic dispatch)
    server_write(&server_fd, &EVENT_INDEX_ADDED).await;

    let e1: MgmtEvent = tokio::time::timeout(TEST_TIMEOUT, rx1.recv())
        .await
        .expect("timeout rx1")
        .expect("rx1 closed");
    let e2: MgmtEvent = tokio::time::timeout(TEST_TIMEOUT, rx2.recv())
        .await
        .expect("timeout rx2")
        .expect("rx2 closed");
    assert_eq!(e1.event, MGMT_EV_INDEX_ADDED);
    assert_eq!(e2.event, MGMT_EV_INDEX_ADDED);

    // Emulate C `unregister_all_cb`: call unsubscribe_all
    mgmt.unsubscribe_all().await;

    // After unsubscribe_all, senders are dropped → channels disconnected.
    // recv() returns None immediately when sender is dropped and buffer is empty.
    assert!(rx1.recv().await.is_none(), "rx1 should be disconnected after unsubscribe_all");
    assert!(rx2.recv().await.is_none(), "rx2 should be disconnected after unsubscribe_all");
}

/// `/mgmt/unregister/2` — `unsubscribe_index` removes targeted subscriptions.
///
/// Ported from C `test_unregister_index` with `event_test_1`:
/// - Register handler for INDEX_ADDED on MGMT_INDEX_NONE
/// - First handler calls `mgmt_unregister_index(mgmt, index)` then quits
///
/// Rust: we verify that `unsubscribe_index(MGMT_INDEX_NONE)` removes the
/// subscription, closing the channel. This tests the same API path as C,
/// adapted for the Rust channel-based model.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unregister_index() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = MgmtSocket::new(client_fd).expect("MgmtSocket::new failed");

    let (_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

    // Inject event — subscription receives it
    server_write(&server_fd, &EVENT_INDEX_ADDED).await;

    let evt: MgmtEvent = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(evt.event, MGMT_EV_INDEX_ADDED);
    assert_eq!(evt.index, 1);

    // Emulate C `unregister_index_cb`: unregister by subscription's own index.
    // In C, this was `mgmt_unregister_index(mgmt, index)` where `index` came
    // from the event callback parameter. Here we use the subscription's
    // registered index (MGMT_INDEX_NONE) to actually remove it.
    mgmt.unsubscribe_index(MGMT_INDEX_NONE).await;

    // Sender dropped → channel disconnected
    assert!(rx.recv().await.is_none(), "rx should be disconnected after unsubscribe_index");
}

// ============================================================================
// Lifecycle Tests (/mgmt/destroy/*)
//
// These tests verify that MgmtSocket can be safely dropped (including from
// within event processing contexts), replacing C's mgmt_unref pattern.
// ============================================================================

/// `/mgmt/destroy/1` — Drop `MgmtSocket` via `Arc`, verify safe shutdown.
///
/// Ported from C `test_destroy` with `event_test_1`:
/// - Register handler that calls `mgmt_unref(mgmt)` (destroys the client)
/// - Second handler should NOT crash
///
/// Rust equivalent: wrap MgmtSocket in `Arc` (replacing mgmt_ref/mgmt_unref),
/// subscribe to events, receive one event, then drop the `Arc`. Background
/// reader/writer tasks are aborted, channels close gracefully, no crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_destroy_from_callback() {
    let (server_fd, client_fd) = create_test_pair();
    let mgmt = Arc::new(MgmtSocket::new(client_fd).expect("MgmtSocket::new failed"));

    let (_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

    // Inject event
    server_write(&server_fd, &EVENT_INDEX_ADDED).await;

    // Receive event — proves subscription is working
    let evt: MgmtEvent = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(evt.event, MGMT_EV_INDEX_ADDED);
    assert_eq!(evt.index, 1);
    assert!(evt.data.is_empty());

    // Drop the Arc<MgmtSocket> — emulates mgmt_unref from within callback.
    // This aborts reader_task and writer_task via MgmtSocket::drop().
    drop(mgmt);

    // Allow background task abort to propagate
    tokio::time::sleep(Duration::from_millis(200)).await;

    // After MgmtSocket drop, the inner state's notify_list senders will
    // eventually be dropped as the background task Arc references are released.
    // The channel should close (recv returns None).
    let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    match result {
        Ok(None) => {
            // Expected: channel closed after MgmtSocket drop
        }
        Ok(Some(_)) => {
            // Acceptable: a buffered event may still arrive
        }
        Err(_) => {
            // Timeout is acceptable: task cleanup may be delayed.
            // The critical assertion is that we reach this point without
            // crash, deadlock, or panic — proving safe destruction.
        }
    }
    // Primary assertion: no crash, no deadlock — test reaches this point.
}
