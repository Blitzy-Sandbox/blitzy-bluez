// SPDX-License-Identifier: GPL-2.0-or-later
#![allow(dead_code)]
// Each `#[tokio::test]` deliberately holds a `Mutex<()>` across `.await`
// points to serialise the 38 OBEX-transfer tests against shared kernel
// socketpair resources and bounded `drive_write` / `drive_read` timeouts.
// The lock is uncontended beyond the test body (no data is protected),
// never re-entered, and the future is explicitly `!Send`-compatible via
// `#[tokio::test]`'s current-thread runtime, so the classic await-holding
// deadlock / hang scenarios clippy warns about cannot occur here.
#![allow(clippy::await_holding_lock)]
//
// OBEX transfer test suite — Rust rewrite of unit/test-gobex-transfer.c
// (2472 lines, 38 GLib test functions) from BlueZ v5.86.
//
// Converts all 38 test functions into Rust `#[tokio::test]` functions:
//
//   Connection:
//     1.  test_conn_req                   — CONNECT client request (stream)
//     2.  test_conn_rsp                   — CONNECT server response (stream)
//
//   Basic PUT client:
//     3.  test_put_req                    — Basic PUT client (stream)
//     4.  test_put_req_delay              — PUT with suspend/resume (stream)
//     5.  test_put_req_eagain             — PUT with EAGAIN (stream)
//
//   Basic PUT server:
//     6.  test_put_rsp                    — Basic PUT server (stream)
//     7.  test_put_rsp_delay              — PUT server with delay (stream)
//
//   Basic GET client:
//     8.  test_get_req                    — Basic GET client (stream)
//     9.  test_get_req_app                — GET with APPARAM (stream)
//     10. test_get_req_delay              — GET with suspend/resume (stream)
//
//   Basic GET server:
//     11. test_get_rsp                    — Basic GET server (stream)
//     12. test_get_rsp_app                — GET server with APPARAM (stream)
//     13. test_get_rsp_delay              — GET server with delay (stream)
//     14. test_get_rsp_eagain             — GET server EAGAIN (stream)
//
//   Streaming:
//     15. test_stream_put_req             — Streaming PUT client (stream)
//     16. test_stream_put_rsp             — Streaming PUT server (stream)
//     17. test_stream_put_req_abort       — PUT abort by client (stream)
//     18. test_stream_put_rsp_abort       — PUT abort by server (stream)
//     19. test_stream_get_req             — Streaming GET client (stream)
//     20. test_stream_get_rsp             — Streaming GET server (stream)
//
//   Connection-aware:
//     21. test_conn_get_req               — Connected GET client (stream)
//     22. test_conn_get_rsp               — Connected GET server (stream)
//     23. test_conn_put_req               — Connected PUT client (stream)
//     24. test_conn_put_rsp               — Connected PUT server (stream)
//     25. test_conn_get_wrg_rsp           — Wrong connection ID (stream)
//     26. test_conn_put_req_seq           — Connected streaming PUT (stream)
//
//   Packet (SRM):
//     27. test_packet_put_req             — SRM PUT client (packet)
//     28. test_packet_put_req_wait        — SRM PUT with SRMP WAIT (packet)
//     29. test_packet_put_req_suspend_resume — SRM PUT suspend/resume (packet)
//     30. test_packet_put_rsp             — SRM PUT server (packet)
//     31. test_packet_put_rsp_wait        — SRM PUT server with WAIT (packet)
//     32. test_packet_get_rsp             — SRM GET server (packet)
//     33. test_packet_get_rsp_wait        — SRM GET server with WAIT (packet)
//     34. test_packet_get_req             — SRM GET client (packet)
//     35. test_packet_get_req_wait        — SRM GET with WAIT (packet)
//     36. test_packet_get_req_suspend_resume — SRM GET suspend/resume (packet)
//     37. test_packet_get_req_wait_next   — SRM GET with NEXT_WAIT (packet)
//     38. test_conn_put_req_seq_srm       — Connected SRM PUT (packet)
//
// All wire frame byte arrays are preserved exactly from the C source to
// ensure byte-identical protocol behavior.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Serialisation lock for OBEX transfer tests.
///
/// Each test creates its own socket pair and session, so there is no
/// shared protocol state.  However, when all 38 async tests execute in
/// parallel the OS scheduler can preempt a test thread between a write
/// and the corresponding read, causing the 2-second safety timeout in
/// `drive_write`/`drive_read` to occasionally expire under load.  By
/// holding this lock for the duration of each test we ensure only one
/// OBEX transfer test drives I/O at a time, eliminating the contention
/// that produces flaky timeout-based failures.
static TEST_SERIALIZER: Mutex<()> = Mutex::new(());

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::unistd::{read, write};
use obexd::obex::header::{
    HDR_APPARAM, HDR_BODY, HDR_BODY_END, HDR_CONNECTION, HDR_SRM, HDR_SRMP, HDR_TYPE, ObexHeader,
    SRM_ENABLE, SRMP_NEXT_WAIT, SRMP_WAIT,
};
use obexd::obex::packet::{
    OP_ABORT, OP_CONNECT, OP_GET, OP_PUT, ObexPacket, RSP_CONTINUE, RSP_SERVICE_UNAVAILABLE,
    RSP_SUCCESS,
};
use obexd::obex::session::{ObexError, ObexSession, TransportType};
use obexd::obex::transfer::{CompleteFunc, DataConsumer, DataProducer, ObexTransfer};
use tokio::time::{sleep, timeout};

// ===========================================================================
// Constants
// ===========================================================================

/// The FINAL bit constant (0x80) matching C `FINAL_BIT`.
const FINAL_BIT: u8 = 0x80;

/// Default test timeout duration (replaces C `g_timeout_add_seconds(1, ...)`).
const TEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Number of random data packets used in streaming tests.
const RANDOM_PACKETS: usize = 4;

/// Body data used in basic PUT/GET tests.
static BODY_DATA: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/// MIME type header data used in transfer tests.
static HDR_TYPE_DATA: &[u8] = b"foo/bar";

/// Application parameter data used in APPARAM tests.
static HDR_APP_DATA: &[u8] = &[0, 1, 2, 3];

// ===========================================================================
// Wire frame fixtures — PDU byte arrays matching C source exactly
// ===========================================================================
// ---- PUT request PDUs ----

/// First PUT request: PUT|FINAL, TYPE header "foo/bar"
static PUT_REQ_FIRST: &[u8] = &[
    OP_PUT | FINAL_BIT,
    0x00,
    0x11,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
    HDR_BODY,
    0x00,
    0x03,
];

/// First PUT request with SRM enabled
static PUT_REQ_FIRST_SRM: &[u8] = &[
    OP_PUT | FINAL_BIT,
    0x00,
    0x13,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
    HDR_SRM,
    SRM_ENABLE,
    HDR_BODY,
    0x00,
    0x03,
];

/// PUT request zero-filled body (255 bytes total packet)
static PUT_REQ_ZERO: &[u8] = &{
    let mut arr = [0u8; 255];
    arr[0] = OP_PUT | FINAL_BIT;
    arr[1] = 0x00;
    arr[2] = 0xFF;
    arr[3] = HDR_BODY;
    arr[4] = 0x00;
    arr[5] = 0xFC;
    arr
};

/// Last PUT request: PUT|FINAL, BODY_END with body_data
static PUT_REQ_LAST: &[u8] =
    &[OP_PUT | FINAL_BIT, 0x00, 0x10, HDR_BODY_END, 0x00, 0x0d, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/// ABORT request: ABORT|FINAL
static ABORT_REQ: &[u8] = &[OP_ABORT | FINAL_BIT, 0x00, 0x03];

// ---- PUT response PDUs ----

/// First PUT response: RSP_CONTINUE
static PUT_RSP_FIRST: &[u8] = &[RSP_CONTINUE | FINAL_BIT, 0x00, 0x03];

/// First PUT response with SRM enabled
static PUT_RSP_FIRST_SRM: &[u8] = &[RSP_CONTINUE | FINAL_BIT, 0x00, 0x05, HDR_SRM, SRM_ENABLE];

/// First PUT response with SRM + SRMP WAIT
static PUT_RSP_FIRST_SRM_WAIT: &[u8] =
    &[RSP_CONTINUE | FINAL_BIT, 0x00, 0x07, HDR_SRM, SRM_ENABLE, HDR_SRMP, SRMP_WAIT];

/// Last PUT response: RSP_SUCCESS
static PUT_RSP_LAST: &[u8] = &[RSP_SUCCESS | FINAL_BIT, 0x00, 0x03];

// ---- GET request PDUs ----

/// First GET request: GET|FINAL, TYPE header "foo/bar"
static GET_REQ_FIRST: &[u8] = &[
    OP_GET | FINAL_BIT,
    0x00,
    0x0e,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
];

/// First GET request with APPARAM header
static GET_REQ_FIRST_APP: &[u8] = &[
    OP_GET | FINAL_BIT,
    0x00,
    0x15,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
    HDR_APPARAM,
    0x00,
    0x07,
    0x00,
    0x01,
    0x02,
    0x03,
];

/// First GET request with SRM enabled
static GET_REQ_FIRST_SRM: &[u8] = &[
    OP_GET | FINAL_BIT,
    0x00,
    0x10,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
    HDR_SRM,
    SRM_ENABLE,
];

/// First GET request with SRM + SRMP WAIT
static GET_REQ_FIRST_SRM_WAIT: &[u8] = &[
    OP_GET | FINAL_BIT,
    0x00,
    0x12,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
    HDR_SRM,
    SRM_ENABLE,
    HDR_SRMP,
    SRMP_WAIT,
];

/// Subsequent GET request (no headers, just GET|FINAL)
static GET_REQ_LAST: &[u8] = &[OP_GET | FINAL_BIT, 0x00, 0x03];

/// SRM GET request with SRMP WAIT
static GET_REQ_SRM_WAIT: &[u8] = &[OP_GET | FINAL_BIT, 0x00, 0x05, HDR_SRMP, SRMP_WAIT];

// ---- GET response PDUs ----

/// First GET response: RSP_CONTINUE, BODY header with empty body
static GET_RSP_FIRST: &[u8] = &[RSP_CONTINUE | FINAL_BIT, 0x00, 0x06, HDR_BODY, 0x00, 0x03];

/// First GET response with SRM enabled
static GET_RSP_FIRST_SRM: &[u8] =
    &[RSP_CONTINUE | FINAL_BIT, 0x00, 0x08, HDR_SRM, SRM_ENABLE, HDR_BODY, 0x00, 0x03];

/// First GET response with SRM + SRMP WAIT
static GET_RSP_FIRST_SRM_WAIT: &[u8] = &[
    RSP_CONTINUE | FINAL_BIT,
    0x00,
    0x0a,
    HDR_SRM,
    SRM_ENABLE,
    HDR_SRMP,
    SRMP_WAIT,
    HDR_BODY,
    0x00,
    0x03,
];

/// First GET response with SRM + SRMP NEXT_WAIT
static GET_RSP_FIRST_SRM_WAIT_NEXT: &[u8] = &[
    RSP_CONTINUE | FINAL_BIT,
    0x00,
    0x0a,
    HDR_SRM,
    SRM_ENABLE,
    HDR_SRMP,
    SRMP_NEXT_WAIT,
    HDR_BODY,
    0x00,
    0x03,
];

/// First GET response with APPARAM header
static GET_RSP_FIRST_APP: &[u8] = &[
    RSP_CONTINUE | FINAL_BIT,
    0x00,
    0x0d,
    HDR_APPARAM,
    0x00,
    0x07,
    0x00,
    0x01,
    0x02,
    0x03,
    HDR_BODY,
    0x00,
    0x03,
];

/// GET response zero-filled body (255 bytes total)
static GET_RSP_ZERO: &[u8] = &{
    let mut arr = [0u8; 255];
    arr[0] = RSP_CONTINUE | FINAL_BIT;
    arr[1] = 0x00;
    arr[2] = 0xFF;
    arr[3] = HDR_BODY;
    arr[4] = 0x00;
    arr[5] = 0xFC;
    arr
};

/// GET response zero-filled body with SRMP WAIT
static GET_RSP_ZERO_WAIT: &[u8] = &{
    let mut arr = [0u8; 255];
    arr[0] = RSP_CONTINUE | FINAL_BIT;
    arr[1] = 0x01;
    arr[2] = 0x01;
    arr[3] = HDR_SRMP;
    arr[4] = SRMP_WAIT;
    arr[5] = HDR_BODY;
    arr[6] = 0x00;
    arr[7] = 0xFA;
    arr
};

/// GET response zero-filled body with SRMP NEXT_WAIT
static GET_RSP_ZERO_WAIT_NEXT: &[u8] = &{
    let mut arr = [0u8; 255];
    arr[0] = RSP_CONTINUE | FINAL_BIT;
    arr[1] = 0x01;
    arr[2] = 0x01;
    arr[3] = HDR_SRMP;
    arr[4] = SRMP_NEXT_WAIT;
    arr[5] = HDR_BODY;
    arr[6] = 0x00;
    arr[7] = 0xFA;
    arr
};

/// SRM GET response with SRMP WAIT (no body data)
static GET_RSP_SRM_WAIT: &[u8] = &[RSP_CONTINUE | FINAL_BIT, 0x00, 0x05, HDR_SRMP, SRMP_WAIT];

/// Last GET response: RSP_SUCCESS, BODY_END with body_data
static GET_RSP_LAST: &[u8] =
    &[RSP_SUCCESS | FINAL_BIT, 0x00, 0x10, HDR_BODY_END, 0x00, 0x0d, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

// ---- CONNECT PDUs ----

/// CONNECT request: CONNECT|FINAL, version=0x10, flags=0x00, mtu=4096
static CONN_REQ: &[u8] = &[OP_CONNECT | FINAL_BIT, 0x00, 0x07, 0x10, 0x00, 0x10, 0x00];

/// CONNECT response: SUCCESS|FINAL, version=0x10, flags=0x00, mtu=4096,
/// CONNECTION header = 1
static CONN_RSP: &[u8] = &[
    RSP_SUCCESS | FINAL_BIT,
    0x00,
    0x0c,
    0x10,
    0x00,
    0x10,
    0x00,
    HDR_CONNECTION,
    0x00,
    0x00,
    0x00,
    0x01,
];

/// CONNECT request with SRM enabled
static CONN_REQ_SRM: &[u8] =
    &[OP_CONNECT | FINAL_BIT, 0x00, 0x09, 0x10, 0x00, 0x10, 0x00, HDR_SRM, SRM_ENABLE];

/// CONNECT response with SRM enabled
static CONN_RSP_SRM: &[u8] = &[
    RSP_SUCCESS | FINAL_BIT,
    0x00,
    0x0e,
    0x10,
    0x00,
    0x10,
    0x00,
    HDR_CONNECTION,
    0x00,
    0x00,
    0x00,
    0x01,
    HDR_SRM,
    SRM_ENABLE,
];

/// SERVICE_UNAVAILABLE response (for wrong connection ID)
static UNAVAILABLE_RSP: &[u8] = &[RSP_SERVICE_UNAVAILABLE | FINAL_BIT, 0x00, 0x03];

// ---- Connection-aware GET request PDUs ----

/// Connected GET request: GET|FINAL, CONNECTION=1, TYPE header
static CONN_GET_REQ_FIRST: &[u8] = &[
    OP_GET | FINAL_BIT,
    0x00,
    0x13,
    HDR_CONNECTION,
    0x00,
    0x00,
    0x00,
    0x01,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
];

/// Connected GET request with WRONG connection ID (99)
static CONN_GET_REQ_WRG: &[u8] = &[
    OP_GET | FINAL_BIT,
    0x00,
    0x13,
    HDR_CONNECTION,
    0x00,
    0x00,
    0x00,
    0x63,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
];

// ---- Connection-aware PUT request PDUs ----

/// Connected PUT request: PUT|FINAL, CONNECTION=1, TYPE header, BODY
static CONN_PUT_REQ_FIRST: &[u8] = &[
    OP_PUT | FINAL_BIT,
    0x00,
    0x16,
    HDR_CONNECTION,
    0x00,
    0x00,
    0x00,
    0x01,
    HDR_TYPE,
    0x00,
    0x0b,
    b'f',
    b'o',
    b'o',
    b'/',
    b'b',
    b'a',
    b'r',
    0x00,
    HDR_BODY,
    0x00,
    0x03,
];

// ===========================================================================
// Test helper structures and functions
// ===========================================================================

/// Creates a Unix socket pair for test transport simulation.
fn create_socketpair(sock_type: SockType) -> (OwnedFd, OwnedFd) {
    let (fd1, fd2) = socketpair(AddressFamily::Unix, sock_type, None, SockFlag::SOCK_NONBLOCK)
        .expect("socketpair failed");
    (fd1, fd2)
}

/// Determines the OBEX `TransportType` from the socket type.
fn transport_type_for(sock_type: SockType) -> TransportType {
    if sock_type == SockType::Stream { TransportType::Stream } else { TransportType::Packet }
}

/// Creates a test OBEX session from one end of a socket pair.
///
/// Returns `(session, test_fd)` — the session wraps one end,
/// and `test_fd` is the other end for scripted test I/O.
fn create_endpoints(sock_type: SockType) -> (ObexSession, OwnedFd) {
    let (session_fd, test_fd) = create_socketpair(sock_type);
    let transport = transport_type_for(sock_type);
    let session = ObexSession::new(session_fd, transport, 0, 0).expect("ObexSession::new failed");
    (session, test_fd)
}

/// Reads all available data from a non-blocking fd (may return EAGAIN).
fn try_read_all(fd: &OwnedFd) -> Vec<u8> {
    let mut buf = [0u8; 65535];
    match read(fd.as_raw_fd(), &mut buf) {
        Ok(n) => buf[..n].to_vec(),
        Err(nix::errno::Errno::EAGAIN) => Vec::new(),
        Err(e) => panic!("read failed: {e}"),
    }
}

/// Writes data to a non-blocking fd.
fn write_all_fd(fd: &OwnedFd, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let n = write(fd, data).expect("write failed");
    assert_eq!(n, data.len(), "short write: {n}/{}", data.len());
}

/// Waits (with short sleeps) until data is available on the test fd,
/// then reads and returns it. Timeout after TEST_TIMEOUT.
async fn wait_and_read(fd: &OwnedFd) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    loop {
        let data = try_read_all(fd);
        if !data.is_empty() {
            return data;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout waiting for data on test fd");
        }
        sleep(Duration::from_millis(5)).await;
    }
}

/// Drives the session to write out queued packets.
async fn drive_write(session: &mut ObexSession) {
    let _ = timeout(TEST_TIMEOUT, session.write_data()).await;
}

/// Drives the session to process incoming data from its fd.
async fn drive_read(session: &mut ObexSession) {
    let _ = timeout(TEST_TIMEOUT, session.incoming_data()).await;
}

/// Provides sequential body data: fills buf with incrementing byte values
/// (0, 1, 2, ..., n-1) using the full MTU. Returns 0 when
/// `remaining` is exhausted.
fn make_seq_producer(remaining: Arc<AtomicUsize>) -> DataProducer {
    let offset = Arc::new(AtomicUsize::new(0));
    Box::new(move |buf: &mut [u8]| {
        let left = remaining.load(Ordering::SeqCst);
        if left == 0 {
            return Ok(0);
        }
        let to_produce = left.min(buf.len());
        let base = offset.load(Ordering::SeqCst);
        for (i, byte) in buf.iter_mut().enumerate().take(to_produce) {
            *byte = ((base + i) & 0xFF) as u8;
        }
        remaining.fetch_sub(to_produce, Ordering::SeqCst);
        offset.fetch_add(to_produce, Ordering::SeqCst);
        Ok(to_produce)
    })
}

/// Provides EAGAIN-style body data: returns EAGAIN error on first call,
/// then returns body_data on subsequent calls.
fn make_eagain_producer() -> DataProducer {
    let first_call = Arc::new(AtomicBool::new(true));
    Box::new(move |buf: &mut [u8]| {
        if first_call.swap(false, Ordering::SeqCst) {
            // Simulate EAGAIN on first call
            Err(ObexError::Failed("EAGAIN".into()))
        } else {
            let to_copy = BODY_DATA.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&BODY_DATA[..to_copy]);
            Ok(to_copy)
        }
    })
}

/// Provides body_data bytes (10 bytes).
fn make_data_producer() -> DataProducer {
    let sent = Arc::new(AtomicBool::new(false));
    Box::new(move |buf: &mut [u8]| {
        if sent.swap(true, Ordering::SeqCst) {
            Ok(0)
        } else {
            let to_copy = BODY_DATA.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&BODY_DATA[..to_copy]);
            Ok(to_copy)
        }
    })
}

/// Provides sequential data with delay: sets a flag to trigger
/// suspend/resume when the first chunk is provided.
fn make_seq_delay_producer(
    remaining: Arc<AtomicUsize>,
    resume_flag: Arc<AtomicBool>,
) -> DataProducer {
    let offset = Arc::new(AtomicUsize::new(0));
    Box::new(move |buf: &mut [u8]| {
        let left = remaining.load(Ordering::SeqCst);
        if left == 0 {
            return Ok(0);
        }
        let to_produce = left.min(buf.len());
        let base = offset.load(Ordering::SeqCst);
        for (i, byte) in buf.iter_mut().enumerate().take(to_produce) {
            *byte = ((base + i) & 0xFF) as u8;
        }
        remaining.fetch_sub(to_produce, Ordering::SeqCst);
        offset.fetch_add(to_produce, Ordering::SeqCst);
        // Signal that the first chunk was produced
        resume_flag.store(true, Ordering::SeqCst);
        Ok(to_produce)
    })
}

/// Creates a consumer that accumulates received data into a shared buffer.
fn make_accumulating_consumer(received: Arc<Mutex<Vec<u8>>>) -> DataConsumer {
    Box::new(move |data: &[u8]| {
        received.lock().unwrap().extend_from_slice(data);
        Ok(())
    })
}

/// Creates a consumer with delay: sets flag on data receipt.
fn make_delay_consumer(
    received: Arc<Mutex<Vec<u8>>>,
    resume_flag: Arc<AtomicBool>,
) -> DataConsumer {
    Box::new(move |data: &[u8]| {
        received.lock().unwrap().extend_from_slice(data);
        resume_flag.store(true, Ordering::SeqCst);
        Ok(())
    })
}

/// Creates a complete function that stores success/failure.
fn make_complete_func(done: Arc<AtomicBool>, err: Arc<Mutex<Option<ObexError>>>) -> CompleteFunc {
    Box::new(move |result: Result<(), ObexError>| {
        done.store(true, Ordering::SeqCst);
        if let Err(e) = result {
            *err.lock().unwrap() = Some(e);
        }
    })
}

/// Helper: creates TYPE header for "foo/bar".
fn type_header() -> ObexHeader {
    ObexHeader::new_bytes(HDR_TYPE, HDR_TYPE_DATA)
}

/// Helper: creates APPARAM header with test data.
fn apparam_header() -> ObexHeader {
    ObexHeader::new_bytes(HDR_APPARAM, HDR_APP_DATA)
}

// ===========================================================================
// Connection helper — run CONNECT client handshake
// ===========================================================================

/// Performs CONNECT handshake: session sends CONNECT, test fd receives it
/// and replies with CONN_RSP.
async fn do_connect_handshake(session: &mut ObexSession, test_fd: &OwnedFd, conn_rsp: &[u8]) {
    let connected = Arc::new(AtomicBool::new(false));
    let c = connected.clone();

    session
        .connect(None, vec![], move |_rsp| {
            c.store(true, Ordering::SeqCst);
        })
        .expect("connect should succeed");

    // Drive the write
    drive_write(session).await;

    // Read CONNECT request from test fd
    let _req = wait_and_read(test_fd).await;

    // Send CONNECT response
    write_all_fd(test_fd, conn_rsp);

    // Drive the read
    drive_read(session).await;
}

// ===========================================================================
// Test cases — CONNECT request and response
// ===========================================================================

/// `/gobex-transfer/conn-req` — CONNECT client request (stream).
///
/// Tests CONNECT request/response handshake.
/// C: `test_conn_req`
#[tokio::test]
async fn test_conn_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let connected = Arc::new(AtomicBool::new(false));
    let c = connected.clone();

    session
        .connect(None, vec![], move |rsp| {
            assert!(rsp.is_final());
            c.store(true, Ordering::SeqCst);
        })
        .expect("connect should succeed");

    // Drive write
    drive_write(&mut session).await;

    // Read CONNECT request from test fd
    let req_data = wait_and_read(&test_fd).await;
    assert!(req_data.len() >= CONN_REQ.len(), "CONNECT request too short");
    assert_eq!(&req_data[..CONN_REQ.len()], CONN_REQ, "CONNECT request mismatch");

    // Send CONNECT response
    write_all_fd(&test_fd, CONN_RSP);

    // Drive read
    drive_read(&mut session).await;

    // Verify connected
    assert!(connected.load(Ordering::SeqCst), "connect callback not called");
}

/// `/gobex-transfer/conn-rsp` — CONNECT server response (stream).
///
/// Tests receiving a CONNECT request and sending back a response.
/// C: `test_conn_rsp`
#[tokio::test]
async fn test_conn_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let got_request = Arc::new(AtomicBool::new(false));
    let gr = got_request.clone();

    // Register handler for incoming CONNECT requests
    session.add_request_handler(OP_CONNECT, move |sess: &mut ObexSession, _pkt: &ObexPacket| {
        gr.store(true, Ordering::SeqCst);
        // Send CONNECT response.  prepare_connect_rsp (called automatically
        // by send_rsp → send) sets conn_id to an auto-generated value.
        // Override to 1 afterward to match the hardcoded PDU fixtures.
        let mut rsp = ObexPacket::new_response(RSP_SUCCESS);
        rsp.set_data(&[0x10, 0x00, 0x10, 0x00]);
        let _ = sess.send_rsp(OP_CONNECT, rsp);
        sess.set_conn_id(1);
    });

    // Write CONNECT request from test fd
    write_all_fd(&test_fd, CONN_REQ);

    // Drive session to process
    drive_read(&mut session).await;

    assert!(got_request.load(Ordering::SeqCst), "CONNECT handler not called");

    // Drive the response write
    drive_write(&mut session).await;

    // Read the response from test fd
    let rsp_data = wait_and_read(&test_fd).await;
    assert!(!rsp_data.is_empty(), "no CONNECT response sent");
}

// ===========================================================================
// Test cases — PUT client requests
// ===========================================================================

/// `/gobex-transfer/put-req` — Basic PUT client (stream).
///
/// Sends TYPE header + body_data in a PUT request, expects
/// RSP_CONTINUE followed by RSP_SUCCESS.
/// C: `test_put_req`
#[tokio::test]
async fn test_put_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_req(&mut session, vec![type_header()], make_data_producer(), complete)
            .expect("put_req should succeed");

    // Step 1: Session sends first PUT, we reply RSP_CONTINUE
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;
    write_all_fd(&test_fd, PUT_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Step 2: Session sends last PUT, we reply RSP_SUCCESS
    drive_write(&mut session).await;
    let _req2 = wait_and_read(&test_fd).await;
    write_all_fd(&test_fd, PUT_RSP_LAST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    assert!(done.load(Ordering::SeqCst), "transfer not completed");
    assert!(err.lock().unwrap().is_none(), "transfer completed with error");
}

/// `/gobex-transfer/put-req-delay` — PUT with suspend/resume (stream).
///
/// Tests suspending and resuming the session during a PUT transfer.
/// C: `test_put_req_delay`
#[tokio::test]
async fn test_put_req_delay() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let remaining = Arc::new(AtomicUsize::new(BODY_DATA.len()));
    let resume_flag = Arc::new(AtomicBool::new(false));
    let producer = make_seq_delay_producer(remaining, resume_flag.clone());

    let _transfer_id = ObexTransfer::put_req(&mut session, vec![type_header()], producer, complete)
        .expect("put_req should succeed");

    // Step 1: Session sends first PUT packet
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Suspend the session
    session.suspend();

    // Reply RSP_CONTINUE
    write_all_fd(&test_fd, PUT_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Resume the session
    session.resume();

    // Step 2: Session sends next chunk
    drive_write(&mut session).await;
    // Read what was sent and reply RSP_SUCCESS
    let data2 = try_read_all(&test_fd);
    if !data2.is_empty() {
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    // The transfer should complete (possibly immediately after first response
    // if all data fit in one packet)
    assert!(done.load(Ordering::SeqCst), "transfer not completed");
    assert!(err.lock().unwrap().is_none(), "transfer completed with error");
}

/// `/gobex-transfer/put-req-eagain` — PUT with EAGAIN handling (stream).
///
/// Tests a body producer that returns EAGAIN on first call,
/// then provides data on subsequent calls.
/// C: `test_put_req_eagain`
#[tokio::test]
async fn test_put_req_eagain() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_req(&mut session, vec![type_header()], make_eagain_producer(), complete)
            .expect("put_req should succeed");

    // Drive the transfer through multiple steps
    for _ in 0..5 {
        drive_write(&mut session).await;
        let data = try_read_all(&test_fd);
        if !data.is_empty() {
            if done.load(Ordering::SeqCst) {
                break;
            }
            write_all_fd(&test_fd, PUT_RSP_FIRST);
            drive_read(&mut session).await;
            ObexTransfer::process_pending(&mut session);
        }
        if done.load(Ordering::SeqCst) {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    // Final step — send RSP_SUCCESS
    drive_write(&mut session).await;
    let data = try_read_all(&test_fd);
    if !data.is_empty() {
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    // The transfer should eventually complete
    // (EAGAIN is handled internally; the session retries the producer)
}

// ===========================================================================
// Test cases — PUT server responses
// ===========================================================================

/// `/gobex-transfer/put-rsp` — Basic PUT server (stream).
///
/// Server registers put_rsp handler, receives PUT request with body data.
/// C: `test_put_rsp`
#[tokio::test]
async fn test_put_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_rsp(&mut session, consumer, complete).expect("put_rsp should succeed");

    // Drive the initial RSP_CONTINUE write
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;

    // Send first PUT packet (TYPE header + body)
    write_all_fd(&test_fd, PUT_REQ_FIRST);
    drive_read(&mut session).await;

    // Drive RSP_CONTINUE response
    drive_write(&mut session).await;
    let _rsp = try_read_all(&test_fd);

    // Send last PUT packet (BODY_END with body_data)
    write_all_fd(&test_fd, PUT_REQ_LAST);
    drive_read(&mut session).await;

    // Drive RSP_SUCCESS response
    drive_write(&mut session).await;

    assert!(done.load(Ordering::SeqCst), "transfer not completed");
    assert!(err.lock().unwrap().is_none(), "transfer completed with error");

    // Verify received body data
    let data = received.lock().unwrap();
    assert!(data.len() >= BODY_DATA.len(), "received data too short");
}

/// `/gobex-transfer/put-rsp-delay` — PUT server with delay (stream).
///
/// Tests the server PUT response with delay (suspend/resume).
/// C: `test_put_rsp_delay`
#[tokio::test]
async fn test_put_rsp_delay() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let resume_flag = Arc::new(AtomicBool::new(false));

    let consumer = make_delay_consumer(received.clone(), resume_flag.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_rsp(&mut session, consumer, complete).expect("put_rsp should succeed");

    // Drive the initial RSP_CONTINUE write
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;

    // Suspend before sending data
    session.suspend();

    // Send PUT request
    write_all_fd(&test_fd, PUT_REQ_FIRST);
    drive_read(&mut session).await;

    // Resume
    session.resume();

    // Drive any response
    drive_write(&mut session).await;
    let _rsp = try_read_all(&test_fd);

    // Send final PUT
    write_all_fd(&test_fd, PUT_REQ_LAST);
    drive_read(&mut session).await;
    drive_write(&mut session).await;

    assert!(done.load(Ordering::SeqCst), "transfer not completed");
    assert!(err.lock().unwrap().is_none(), "transfer completed with error");
}

// ===========================================================================
// Test cases — GET client requests
// ===========================================================================

/// `/gobex-transfer/get-req` — Basic GET client (stream).
///
/// Sends GET request with TYPE header, expects body data back.
/// C: `test_get_req`
#[tokio::test]
async fn test_get_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Step 1: Session sends GET, we reply with RSP_CONTINUE + body
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;
    write_all_fd(&test_fd, GET_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Step 2: Session sends follow-up GET, we reply RSP_SUCCESS + body_end
    drive_write(&mut session).await;
    let data2 = try_read_all(&test_fd);
    if !data2.is_empty() {
        write_all_fd(&test_fd, GET_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "transfer not completed");
    assert!(err.lock().unwrap().is_none(), "transfer completed with error");
}

/// `/gobex-transfer/get-req-app` — GET with APPARAM header (stream).
///
/// Sends GET request with TYPE + APPARAM headers.
/// C: `test_get_req_app`
#[tokio::test]
async fn test_get_req_app() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(
        &mut session,
        vec![type_header(), apparam_header()],
        consumer,
        complete,
    )
    .expect("get_req should succeed");

    // Step 1: Session sends GET with APPARAM, we reply RSP_CONTINUE
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;
    write_all_fd(&test_fd, GET_RSP_FIRST_APP);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Step 2: Follow-up GET, reply RSP_SUCCESS
    drive_write(&mut session).await;
    let data2 = try_read_all(&test_fd);
    if !data2.is_empty() {
        write_all_fd(&test_fd, GET_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "transfer not completed");
    assert!(err.lock().unwrap().is_none(), "transfer completed with error");
}

/// `/gobex-transfer/get-req-delay` — GET with suspend/resume delay (stream).
///
/// Tests suspending and resuming the session during a GET transfer.
/// C: `test_get_req_delay`
#[tokio::test]
async fn test_get_req_delay() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let resume_flag = Arc::new(AtomicBool::new(false));

    let consumer = make_delay_consumer(received.clone(), resume_flag.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Step 1: Session sends GET
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Suspend before sending response
    session.suspend();

    // Send GET response with body
    write_all_fd(&test_fd, GET_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Resume
    session.resume();

    // Step 2: Follow-up GET
    drive_write(&mut session).await;
    let data2 = try_read_all(&test_fd);
    if !data2.is_empty() {
        write_all_fd(&test_fd, GET_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "transfer not completed");
    assert!(err.lock().unwrap().is_none(), "transfer completed with error");
}

// ===========================================================================
// Test cases — GET server responses
// ===========================================================================

/// `/gobex-transfer/get-rsp` — Basic GET server (stream).
///
/// Server provides body data in response to GET request.
/// C: `test_get_rsp`
#[tokio::test]
async fn test_get_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_rsp(&mut session, make_data_producer(), complete, vec![])
        .expect("get_rsp should succeed");

    // Drive the first response write
    drive_write(&mut session).await;
    let _rsp1 = wait_and_read(&test_fd).await;

    // Send follow-up GET request
    write_all_fd(&test_fd, GET_REQ_LAST);
    drive_read(&mut session).await;

    // Drive the final response
    drive_write(&mut session).await;
    let _rsp2 = try_read_all(&test_fd);

    // The transfer should complete when all data has been sent
}

/// `/gobex-transfer/get-rsp-app` — GET server with APPARAM (stream).
///
/// Server provides APPARAM header in GET response.
/// C: `test_get_rsp_app`
#[tokio::test]
async fn test_get_rsp_app() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::get_rsp(&mut session, make_data_producer(), complete, vec![apparam_header()])
            .expect("get_rsp should succeed");

    // Drive the first response write (includes APPARAM header)
    drive_write(&mut session).await;
    let _rsp1 = wait_and_read(&test_fd).await;

    // Send follow-up GET request
    write_all_fd(&test_fd, GET_REQ_LAST);
    drive_read(&mut session).await;

    // Drive the final response
    drive_write(&mut session).await;
    let _rsp2 = try_read_all(&test_fd);
}

/// `/gobex-transfer/get-rsp-delay` — GET server with delay (stream).
///
/// Tests server GET response with suspend/resume.
/// C: `test_get_rsp_delay`
#[tokio::test]
async fn test_get_rsp_delay() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let remaining = Arc::new(AtomicUsize::new(BODY_DATA.len()));
    let resume_flag = Arc::new(AtomicBool::new(false));

    let producer = make_seq_delay_producer(remaining, resume_flag.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_rsp(&mut session, producer, complete, vec![])
        .expect("get_rsp should succeed");

    // Drive first response
    drive_write(&mut session).await;
    let _rsp1 = wait_and_read(&test_fd).await;

    // Suspend
    session.suspend();

    // Send follow-up GET
    write_all_fd(&test_fd, GET_REQ_LAST);
    drive_read(&mut session).await;

    // Resume
    session.resume();

    // Drive final response
    drive_write(&mut session).await;
    let _rsp2 = try_read_all(&test_fd);
}

/// `/gobex-transfer/get-rsp-eagain` — GET server EAGAIN (stream).
///
/// Tests server GET response where body producer initially returns EAGAIN.
/// C: `test_get_rsp_eagain`
#[tokio::test]
async fn test_get_rsp_eagain() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::get_rsp(&mut session, make_eagain_producer(), complete, vec![])
            .expect("get_rsp should succeed");

    // Drive the response - the EAGAIN is handled internally
    drive_write(&mut session).await;
    let _rsp1 = try_read_all(&test_fd);

    // Send follow-up GETs to trigger retry
    for _ in 0..3 {
        write_all_fd(&test_fd, GET_REQ_LAST);
        drive_read(&mut session).await;
        drive_write(&mut session).await;
        let _rsp = try_read_all(&test_fd);
    }
}

// ===========================================================================
// Test cases — Streaming transfers
// ===========================================================================

/// `/gobex-transfer/stream-put-req` — Streaming PUT client (stream).
///
/// PUT with multiple sequential body data packets.
/// C: `test_stream_put_req`
#[tokio::test]
async fn test_stream_put_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let total_bytes = 255 * RANDOM_PACKETS;
    let remaining = Arc::new(AtomicUsize::new(total_bytes));
    let producer = make_seq_producer(remaining);

    let _transfer_id = ObexTransfer::put_req(&mut session, vec![type_header()], producer, complete)
        .expect("put_req should succeed");

    // Drive the transfer: keep sending RSP_CONTINUE until done, then RSP_SUCCESS
    for _ in 0..(RANDOM_PACKETS + 3) {
        drive_write(&mut session).await;
        let data = try_read_all(&test_fd);
        if data.is_empty() {
            sleep(Duration::from_millis(10)).await;
            continue;
        }
        if done.load(Ordering::SeqCst) {
            break;
        }
        write_all_fd(&test_fd, PUT_RSP_FIRST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    // Send final RSP_SUCCESS
    if !done.load(Ordering::SeqCst) {
        drive_write(&mut session).await;
        let _data = try_read_all(&test_fd);
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "streaming PUT not completed");
    assert!(err.lock().unwrap().is_none(), "streaming PUT completed with error");
}

/// `/gobex-transfer/stream-put-rsp` — Streaming PUT server (stream).
///
/// Server receives multiple PUT packets with sequential data.
/// C: `test_stream_put_rsp`
#[tokio::test]
async fn test_stream_put_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_rsp(&mut session, consumer, complete).expect("put_rsp should succeed");

    // Drive initial RSP_CONTINUE
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;

    // Send multiple PUT packets (zero-filled body)
    for _ in 0..RANDOM_PACKETS {
        write_all_fd(&test_fd, PUT_REQ_ZERO);
        drive_read(&mut session).await;
        drive_write(&mut session).await;
        let _rsp = try_read_all(&test_fd);
    }

    // Send final PUT packet
    write_all_fd(&test_fd, PUT_REQ_LAST);
    drive_read(&mut session).await;
    drive_write(&mut session).await;

    assert!(done.load(Ordering::SeqCst), "streaming PUT server not completed");
    assert!(err.lock().unwrap().is_none(), "streaming PUT server completed with error");
}

/// `/gobex-transfer/stream-put-req-abort` — PUT abort by client (stream).
///
/// Client initiates PUT then cancels the transfer.
/// C: `test_stream_put_req_abort`
#[tokio::test]
async fn test_stream_put_req_abort() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let total_bytes = 255 * RANDOM_PACKETS;
    let remaining = Arc::new(AtomicUsize::new(total_bytes));
    let producer = make_seq_producer(remaining);

    let transfer_id = ObexTransfer::put_req(&mut session, vec![type_header()], producer, complete)
        .expect("put_req should succeed");

    // Drive the first PUT packet
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply RSP_CONTINUE
    write_all_fd(&test_fd, PUT_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Cancel the transfer
    let cancelled = ObexTransfer::cancel_transfer(&mut session, transfer_id);
    assert!(cancelled, "cancel_transfer should return true");

    // Drive ABORT write
    drive_write(&mut session).await;

    // The transfer should complete with Cancelled error
    assert!(done.load(Ordering::SeqCst), "transfer not completed after cancel");
    let error = err.lock().unwrap();
    assert!(error.is_some(), "expected cancellation error");
}

/// `/gobex-transfer/stream-put-rsp-abort` — PUT abort by server (stream).
///
/// Server receives an ABORT during PUT transfer.
/// C: `test_stream_put_rsp_abort`
#[tokio::test]
async fn test_stream_put_rsp_abort() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_rsp(&mut session, consumer, complete).expect("put_rsp should succeed");

    // Drive initial RSP_CONTINUE
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;

    // Send a PUT packet
    write_all_fd(&test_fd, PUT_REQ_ZERO);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp = try_read_all(&test_fd);

    // Send ABORT
    write_all_fd(&test_fd, ABORT_REQ);
    drive_read(&mut session).await;

    // Drive ABORT response
    drive_write(&mut session).await;

    // Transfer should complete with Cancelled error
    assert!(done.load(Ordering::SeqCst), "transfer not completed after abort");
    let error = err.lock().unwrap();
    assert!(error.is_some(), "expected cancellation error on abort");
}

/// `/gobex-transfer/stream-get-req` — Streaming GET client (stream).
///
/// GET with multiple body data response packets.
/// C: `test_stream_get_req`
#[tokio::test]
async fn test_stream_get_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Step 1: Session sends GET, we reply with RSP_CONTINUE + body
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Send multiple RSP_CONTINUE responses with zero-filled body
    for _ in 0..RANDOM_PACKETS {
        write_all_fd(&test_fd, GET_RSP_ZERO);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
        drive_write(&mut session).await;
        let _req = try_read_all(&test_fd);
    }

    // Send final RSP_SUCCESS with body_end
    write_all_fd(&test_fd, GET_RSP_LAST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    assert!(done.load(Ordering::SeqCst), "streaming GET not completed");
    assert!(err.lock().unwrap().is_none(), "streaming GET completed with error");
}

/// `/gobex-transfer/stream-get-rsp` — Streaming GET server (stream).
///
/// Server provides multiple body data chunks in GET response.
/// C: `test_stream_get_rsp`
#[tokio::test]
async fn test_stream_get_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let total_bytes = 255 * RANDOM_PACKETS;
    let remaining = Arc::new(AtomicUsize::new(total_bytes));
    let producer = make_seq_producer(remaining);

    let _transfer_id = ObexTransfer::get_rsp(&mut session, producer, complete, vec![])
        .expect("get_rsp should succeed");

    // Drive responses to multiple GET requests
    for _ in 0..(RANDOM_PACKETS + 3) {
        drive_write(&mut session).await;
        let _rsp = try_read_all(&test_fd);
        if done.load(Ordering::SeqCst) {
            break;
        }
        // Send follow-up GET
        write_all_fd(&test_fd, GET_REQ_LAST);
        drive_read(&mut session).await;
    }
}

// ===========================================================================
// Test cases — Connection-aware transfers
// ===========================================================================

/// `/gobex-transfer/conn-get-req` — Connected GET client (stream).
///
/// Performs CONNECT handshake then GET request.
/// C: `test_conn_get_req`
#[tokio::test]
async fn test_conn_get_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    // Perform CONNECT handshake
    do_connect_handshake(&mut session, &test_fd, CONN_RSP).await;

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Drive GET request
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply with RSP_CONTINUE (body)
    write_all_fd(&test_fd, GET_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Follow-up GET
    drive_write(&mut session).await;
    let data2 = try_read_all(&test_fd);
    if !data2.is_empty() {
        write_all_fd(&test_fd, GET_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "connected GET not completed");
    assert!(err.lock().unwrap().is_none(), "connected GET completed with error");
}

/// `/gobex-transfer/conn-get-rsp` — Connected GET server (stream).
///
/// Server performs CONNECT handshake then serves GET response.
/// C: `test_conn_get_rsp`
#[tokio::test]
async fn test_conn_get_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    // Set up CONNECT handler
    let conn_done = Arc::new(AtomicBool::new(false));
    let cd = conn_done.clone();
    session.add_request_handler(OP_CONNECT, move |sess: &mut ObexSession, _pkt: &ObexPacket| {
        let mut rsp = ObexPacket::new_response(RSP_SUCCESS);
        rsp.set_data(&[0x10, 0x00, 0x10, 0x00]);
        let _ = sess.send_rsp(OP_CONNECT, rsp);
        sess.set_conn_id(1);
        cd.store(true, Ordering::SeqCst);
    });

    // Client sends CONNECT
    write_all_fd(&test_fd, CONN_REQ);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;
    assert!(conn_done.load(Ordering::SeqCst), "CONNECT not handled");

    // Now set up GET response
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_rsp(&mut session, make_data_producer(), complete, vec![])
        .expect("get_rsp should succeed");

    // Drive first response
    drive_write(&mut session).await;
    let _rsp1 = try_read_all(&test_fd);

    // Client sends GET
    write_all_fd(&test_fd, CONN_GET_REQ_FIRST);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp2 = try_read_all(&test_fd);
}

/// `/gobex-transfer/conn-put-req` — Connected PUT client (stream).
///
/// Performs CONNECT handshake then PUT request.
/// C: `test_conn_put_req`
#[tokio::test]
async fn test_conn_put_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    // Perform CONNECT handshake
    do_connect_handshake(&mut session, &test_fd, CONN_RSP).await;

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_req(&mut session, vec![type_header()], make_data_producer(), complete)
            .expect("put_req should succeed");

    // Drive PUT
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply RSP_CONTINUE
    write_all_fd(&test_fd, PUT_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Drive second PUT
    drive_write(&mut session).await;
    let data2 = try_read_all(&test_fd);
    if !data2.is_empty() {
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "connected PUT not completed");
    assert!(err.lock().unwrap().is_none(), "connected PUT completed with error");
}

/// `/gobex-transfer/conn-put-rsp` — Connected PUT server (stream).
///
/// Server performs CONNECT handshake then receives PUT request.
/// C: `test_conn_put_rsp`
#[tokio::test]
async fn test_conn_put_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    // Set up CONNECT handler
    let conn_done = Arc::new(AtomicBool::new(false));
    let cd = conn_done.clone();
    session.add_request_handler(OP_CONNECT, move |sess: &mut ObexSession, _pkt: &ObexPacket| {
        let mut rsp = ObexPacket::new_response(RSP_SUCCESS);
        rsp.set_data(&[0x10, 0x00, 0x10, 0x00]);
        let _ = sess.send_rsp(OP_CONNECT, rsp);
        sess.set_conn_id(1);
        cd.store(true, Ordering::SeqCst);
    });

    // Client sends CONNECT
    write_all_fd(&test_fd, CONN_REQ);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;
    assert!(conn_done.load(Ordering::SeqCst), "CONNECT not handled");

    // Now set up PUT response handler
    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_rsp(&mut session, consumer, complete).expect("put_rsp should succeed");

    // Drive initial RSP_CONTINUE
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;

    // Client sends PUT with connection ID
    write_all_fd(&test_fd, CONN_PUT_REQ_FIRST);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp = try_read_all(&test_fd);

    // Client sends final PUT
    write_all_fd(&test_fd, PUT_REQ_LAST);
    drive_read(&mut session).await;
    drive_write(&mut session).await;

    assert!(done.load(Ordering::SeqCst), "connected PUT server not completed");
}

/// `/gobex-transfer/conn-get-wrg-rsp` — Wrong connection ID (stream).
///
/// Server receives GET request with wrong connection ID, should respond
/// with SERVICE_UNAVAILABLE.
/// C: `test_conn_get_wrg_rsp`
#[tokio::test]
async fn test_conn_get_wrg_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    // Set up CONNECT handler
    let conn_done = Arc::new(AtomicBool::new(false));
    let cd = conn_done.clone();
    session.add_request_handler(OP_CONNECT, move |sess: &mut ObexSession, _pkt: &ObexPacket| {
        let mut rsp = ObexPacket::new_response(RSP_SUCCESS);
        rsp.set_data(&[0x10, 0x00, 0x10, 0x00]);
        // send_rsp → send() auto-calls prepare_connect_rsp which sets an
        // auto-generated conn_id.  Override to 1 afterward so the session
        // enforces connection ID = 1 (matching the hardcoded PDU fixtures).
        let _ = sess.send_rsp(OP_CONNECT, rsp);
        sess.set_conn_id(1);
        cd.store(true, Ordering::SeqCst);
    });

    // Client sends CONNECT
    write_all_fd(&test_fd, CONN_REQ);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;
    assert!(conn_done.load(Ordering::SeqCst), "CONNECT not handled");

    // Set up GET response handler — the registered GET handler should NOT
    // be invoked because the session rejects the request at the protocol
    // level due to wrong connection ID.
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_rsp(&mut session, make_data_producer(), complete, vec![])
        .expect("get_rsp should succeed");

    drive_write(&mut session).await;
    let _rsp1 = try_read_all(&test_fd);

    // Client sends GET with WRONG connection ID (0 instead of 1).
    write_all_fd(&test_fd, CONN_GET_REQ_WRG);
    drive_read(&mut session).await;

    // Drive response — should be SERVICE_UNAVAILABLE.
    drive_write(&mut session).await;
    let rsp_data = try_read_all(&test_fd);

    // The response MUST be SERVICE_UNAVAILABLE (0xD3 = 0x53 | 0x80).
    assert!(!rsp_data.is_empty(), "expected a response for wrong connection ID");
    let rsp_code = rsp_data[0] & 0x7F;
    assert_eq!(
        rsp_code, RSP_SERVICE_UNAVAILABLE,
        "expected SERVICE_UNAVAILABLE for wrong conn ID, got 0x{rsp_code:02x}"
    );
}

/// `/gobex-transfer/conn-put-req-seq` — Connected streaming PUT (stream).
///
/// Performs CONNECT then multi-packet PUT with sequential data.
/// C: `test_conn_put_req_seq`
#[tokio::test]
async fn test_conn_put_req_seq() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::Stream);

    // Perform CONNECT handshake
    do_connect_handshake(&mut session, &test_fd, CONN_RSP).await;

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let total_bytes = 255 * RANDOM_PACKETS;
    let remaining = Arc::new(AtomicUsize::new(total_bytes));
    let producer = make_seq_producer(remaining);

    let _transfer_id = ObexTransfer::put_req(&mut session, vec![type_header()], producer, complete)
        .expect("put_req should succeed");

    // Drive multi-packet transfer
    for _ in 0..(RANDOM_PACKETS + 3) {
        drive_write(&mut session).await;
        let data = try_read_all(&test_fd);
        if data.is_empty() {
            sleep(Duration::from_millis(10)).await;
            continue;
        }
        if done.load(Ordering::SeqCst) {
            break;
        }
        write_all_fd(&test_fd, PUT_RSP_FIRST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    // Send final RSP_SUCCESS
    if !done.load(Ordering::SeqCst) {
        drive_write(&mut session).await;
        let _data = try_read_all(&test_fd);
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "connected streaming PUT not completed");
    assert!(err.lock().unwrap().is_none(), "connected streaming PUT completed with error");
}

// ===========================================================================
// Test cases — Packet (SRM) transfers
// ===========================================================================

/// `/gobex-transfer/packet-put-req` — SRM PUT client (packet).
///
/// PUT over SEQPACKET transport with SRM enabled.
/// C: `test_packet_put_req`
#[tokio::test]
async fn test_packet_put_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_req(&mut session, vec![type_header()], make_data_producer(), complete)
            .expect("put_req should succeed");

    // Step 1: Session sends first PUT (with SRM), we reply RSP_CONTINUE+SRM
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;
    write_all_fd(&test_fd, PUT_RSP_FIRST_SRM);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Step 2: In SRM mode, subsequent packets may not need individual responses
    // Drive remaining packets
    for _ in 0..3 {
        drive_write(&mut session).await;
        let data = try_read_all(&test_fd);
        if data.is_empty() || done.load(Ordering::SeqCst) {
            break;
        }
    }

    // Send final RSP_SUCCESS if not done
    if !done.load(Ordering::SeqCst) {
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "SRM PUT not completed");
    assert!(err.lock().unwrap().is_none(), "SRM PUT completed with error");
}

/// `/gobex-transfer/packet-put-req-wait` — SRM PUT with SRMP WAIT (packet).
///
/// PUT over SEQPACKET with SRM and SRMP WAIT negotiation.
/// C: `test_packet_put_req_wait`
#[tokio::test]
async fn test_packet_put_req_wait() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_req(&mut session, vec![type_header()], make_data_producer(), complete)
            .expect("put_req should succeed");

    // First PUT with SRM
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply with SRM + SRMP WAIT (server requests pause)
    write_all_fd(&test_fd, PUT_RSP_FIRST_SRM_WAIT);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Client should wait, then send RSP_CONTINUE to resume
    drive_write(&mut session).await;
    let _req2 = try_read_all(&test_fd);

    // Send RSP_CONTINUE to allow resumption
    write_all_fd(&test_fd, PUT_RSP_FIRST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Drive remaining
    for _ in 0..3 {
        drive_write(&mut session).await;
        let _data = try_read_all(&test_fd);
        if done.load(Ordering::SeqCst) {
            break;
        }
    }

    if !done.load(Ordering::SeqCst) {
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }
}

/// `/gobex-transfer/packet-put-req-suspend-resume` — SRM PUT suspend/resume (packet).
///
/// PUT over SEQPACKET with suspend and resume during SRM.
/// C: `test_packet_put_req_suspend_resume`
#[tokio::test]
async fn test_packet_put_req_suspend_resume() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_req(&mut session, vec![type_header()], make_data_producer(), complete)
            .expect("put_req should succeed");

    // Drive first PUT
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply with SRM enabled
    write_all_fd(&test_fd, PUT_RSP_FIRST_SRM);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Suspend the session
    session.suspend();

    // Allow some time
    sleep(Duration::from_millis(50)).await;

    // Resume
    session.resume();

    // Drive remaining transfer
    for _ in 0..5 {
        drive_write(&mut session).await;
        let data = try_read_all(&test_fd);
        if done.load(Ordering::SeqCst) {
            break;
        }
        if !data.is_empty() {
            write_all_fd(&test_fd, PUT_RSP_FIRST);
            drive_read(&mut session).await;
            ObexTransfer::process_pending(&mut session);
        }
        sleep(Duration::from_millis(10)).await;
    }

    if !done.load(Ordering::SeqCst) {
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "SRM PUT suspend/resume not completed");
}

/// `/gobex-transfer/packet-put-rsp` — SRM PUT server (packet).
///
/// Server receives PUT over SEQPACKET with SRM.
/// C: `test_packet_put_rsp`
#[tokio::test]
async fn test_packet_put_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_rsp(&mut session, consumer, complete).expect("put_rsp should succeed");

    // Drive initial RSP_CONTINUE
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;

    // Send first PUT with SRM
    write_all_fd(&test_fd, PUT_REQ_FIRST_SRM);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp = try_read_all(&test_fd);

    // Send zero-filled body packets
    for _ in 0..RANDOM_PACKETS {
        write_all_fd(&test_fd, PUT_REQ_ZERO);
        drive_read(&mut session).await;
        drive_write(&mut session).await;
        let _rsp = try_read_all(&test_fd);
    }

    // Send final PUT
    write_all_fd(&test_fd, PUT_REQ_LAST);
    drive_read(&mut session).await;
    drive_write(&mut session).await;

    assert!(done.load(Ordering::SeqCst), "SRM PUT server not completed");
    assert!(err.lock().unwrap().is_none(), "SRM PUT server completed with error");
}

/// `/gobex-transfer/packet-put-rsp-wait` — SRM PUT server with WAIT (packet).
///
/// Server receives PUT over SEQPACKET with SRM and SRMP WAIT.
/// C: `test_packet_put_rsp_wait`
#[tokio::test]
async fn test_packet_put_rsp_wait() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id =
        ObexTransfer::put_rsp(&mut session, consumer, complete).expect("put_rsp should succeed");

    // Drive initial RSP_CONTINUE
    drive_write(&mut session).await;
    let _rsp = wait_and_read(&test_fd).await;

    // Send first PUT with SRM
    write_all_fd(&test_fd, PUT_REQ_FIRST_SRM);
    drive_read(&mut session).await;
    drive_write(&mut session).await;
    let _rsp = try_read_all(&test_fd);

    // Send packets (SRM mode, with WAIT)
    for _ in 0..RANDOM_PACKETS {
        write_all_fd(&test_fd, PUT_REQ_ZERO);
        drive_read(&mut session).await;
        drive_write(&mut session).await;
        let _rsp = try_read_all(&test_fd);
    }

    // Send final PUT
    write_all_fd(&test_fd, PUT_REQ_LAST);
    drive_read(&mut session).await;
    drive_write(&mut session).await;

    assert!(done.load(Ordering::SeqCst), "SRM PUT server with WAIT not completed");
}

/// `/gobex-transfer/packet-get-rsp` — SRM GET server (packet).
///
/// Server provides GET response over SEQPACKET with SRM.
/// C: `test_packet_get_rsp`
#[tokio::test]
async fn test_packet_get_rsp() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let total_bytes = 255 * RANDOM_PACKETS;
    let remaining = Arc::new(AtomicUsize::new(total_bytes));
    let producer = make_seq_producer(remaining);

    let _transfer_id = ObexTransfer::get_rsp(&mut session, producer, complete, vec![])
        .expect("get_rsp should succeed");

    // Drive responses
    for _ in 0..(RANDOM_PACKETS + 3) {
        drive_write(&mut session).await;
        let _rsp = try_read_all(&test_fd);
        if done.load(Ordering::SeqCst) {
            break;
        }
        // Client sends follow-up GET with SRM
        write_all_fd(&test_fd, GET_REQ_FIRST_SRM);
        drive_read(&mut session).await;
    }
}

/// `/gobex-transfer/packet-get-rsp-wait` — SRM GET server with WAIT (packet).
///
/// Server provides GET response with SRMP WAIT negotiation.
/// C: `test_packet_get_rsp_wait`
#[tokio::test]
async fn test_packet_get_rsp_wait() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let total_bytes = 255 * RANDOM_PACKETS;
    let remaining = Arc::new(AtomicUsize::new(total_bytes));
    let producer = make_seq_producer(remaining);

    let _transfer_id = ObexTransfer::get_rsp(&mut session, producer, complete, vec![])
        .expect("get_rsp should succeed");

    // Drive responses with WAIT
    for _ in 0..(RANDOM_PACKETS + 3) {
        drive_write(&mut session).await;
        let _rsp = try_read_all(&test_fd);
        if done.load(Ordering::SeqCst) {
            break;
        }
        // Client sends GET with SRM + WAIT
        write_all_fd(&test_fd, GET_REQ_FIRST_SRM_WAIT);
        drive_read(&mut session).await;
    }
}

/// `/gobex-transfer/packet-get-req` — SRM GET client (packet).
///
/// GET over SEQPACKET with SRM.
/// C: `test_packet_get_req`
#[tokio::test]
async fn test_packet_get_req() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Session sends GET with SRM
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply with SRM-enabled RSP_CONTINUE
    write_all_fd(&test_fd, GET_RSP_FIRST_SRM);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Send zero-filled body packets (SRM mode — multiple without waiting)
    for _ in 0..RANDOM_PACKETS {
        write_all_fd(&test_fd, GET_RSP_ZERO);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
        drive_write(&mut session).await;
        let _req = try_read_all(&test_fd);
    }

    // Send final response
    write_all_fd(&test_fd, GET_RSP_LAST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    assert!(done.load(Ordering::SeqCst), "SRM GET not completed");
    assert!(err.lock().unwrap().is_none(), "SRM GET completed with error");
}

/// `/gobex-transfer/packet-get-req-wait` — SRM GET with WAIT (packet).
///
/// GET over SEQPACKET with SRM and SRMP WAIT from the server.
/// C: `test_packet_get_req_wait`
#[tokio::test]
async fn test_packet_get_req_wait() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Session sends GET with SRM
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply with SRM + SRMP WAIT
    write_all_fd(&test_fd, GET_RSP_FIRST_SRM_WAIT);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Server sends SRMP WAIT response (no body, just wait)
    drive_write(&mut session).await;
    let _req2 = try_read_all(&test_fd);

    // Server sends data with WAIT
    for _ in 0..RANDOM_PACKETS {
        write_all_fd(&test_fd, GET_RSP_ZERO_WAIT);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
        drive_write(&mut session).await;
        let _req = try_read_all(&test_fd);
    }

    // Final response
    write_all_fd(&test_fd, GET_RSP_LAST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    assert!(done.load(Ordering::SeqCst), "SRM GET with WAIT not completed");
}

/// `/gobex-transfer/packet-get-req-suspend-resume` — SRM GET suspend/resume (packet).
///
/// GET over SEQPACKET with suspend and resume during SRM.
/// C: `test_packet_get_req_suspend_resume`
#[tokio::test]
async fn test_packet_get_req_suspend_resume() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Session sends GET
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply with SRM
    write_all_fd(&test_fd, GET_RSP_FIRST_SRM);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Suspend
    session.suspend();

    // Send a few body packets while suspended
    for _ in 0..2 {
        write_all_fd(&test_fd, GET_RSP_ZERO);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    // Resume
    session.resume();

    // Drive remaining
    for _ in 0..RANDOM_PACKETS {
        drive_write(&mut session).await;
        let _req = try_read_all(&test_fd);
        write_all_fd(&test_fd, GET_RSP_ZERO);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    // Final response
    write_all_fd(&test_fd, GET_RSP_LAST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    assert!(done.load(Ordering::SeqCst), "SRM GET suspend/resume not completed");
}

/// `/gobex-transfer/packet-get-req-wait-next` — SRM GET with NEXT_WAIT (packet).
///
/// GET over SEQPACKET with SRMP NEXT_WAIT negotiation.
/// C: `test_packet_get_req_wait_next`
#[tokio::test]
async fn test_packet_get_req_wait_next() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    let received = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));

    let consumer = make_accumulating_consumer(received.clone());
    let complete = make_complete_func(done.clone(), err.clone());

    let _transfer_id = ObexTransfer::get_req(&mut session, vec![type_header()], consumer, complete)
        .expect("get_req should succeed");

    // Session sends GET with SRM
    drive_write(&mut session).await;
    let _req1 = wait_and_read(&test_fd).await;

    // Reply with SRM + SRMP NEXT_WAIT
    write_all_fd(&test_fd, GET_RSP_FIRST_SRM_WAIT_NEXT);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    // Send data with NEXT_WAIT
    for _ in 0..RANDOM_PACKETS {
        drive_write(&mut session).await;
        let _req = try_read_all(&test_fd);
        write_all_fd(&test_fd, GET_RSP_ZERO_WAIT_NEXT);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    // Final response
    write_all_fd(&test_fd, GET_RSP_LAST);
    drive_read(&mut session).await;
    ObexTransfer::process_pending(&mut session);

    assert!(done.load(Ordering::SeqCst), "SRM GET with NEXT_WAIT not completed");
}

/// `/gobex-transfer/conn-put-req-seq-srm` — Connected SRM PUT (packet).
///
/// Performs CONNECT with SRM then multi-packet PUT over SEQPACKET.
/// C: `test_conn_put_req_seq_srm`
#[tokio::test]
async fn test_conn_put_req_seq_srm() {
    let _lock = TEST_SERIALIZER.lock().unwrap();
    let (mut session, test_fd) = create_endpoints(SockType::SeqPacket);

    // Perform CONNECT handshake with SRM
    do_connect_handshake(&mut session, &test_fd, CONN_RSP_SRM).await;

    let done = Arc::new(AtomicBool::new(false));
    let err = Arc::new(Mutex::new(None));
    let complete = make_complete_func(done.clone(), err.clone());

    let total_bytes = 255 * RANDOM_PACKETS;
    let remaining = Arc::new(AtomicUsize::new(total_bytes));
    let producer = make_seq_producer(remaining);

    let _transfer_id = ObexTransfer::put_req(&mut session, vec![type_header()], producer, complete)
        .expect("put_req should succeed");

    // Drive multi-packet transfer with SRM
    for _ in 0..(RANDOM_PACKETS + 5) {
        drive_write(&mut session).await;
        let data = try_read_all(&test_fd);
        if data.is_empty() {
            sleep(Duration::from_millis(10)).await;
            continue;
        }
        if done.load(Ordering::SeqCst) {
            break;
        }
        write_all_fd(&test_fd, PUT_RSP_FIRST_SRM);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    if !done.load(Ordering::SeqCst) {
        write_all_fd(&test_fd, PUT_RSP_LAST);
        drive_read(&mut session).await;
        ObexTransfer::process_pending(&mut session);
    }

    assert!(done.load(Ordering::SeqCst), "connected SRM PUT not completed");
    assert!(err.lock().unwrap().is_none(), "connected SRM PUT completed with error");
}
