// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_uhid.rs — Rust port of unit/test-uhid.c
//
// Comprehensive unit tests for `bluez_shared::device::uhid::BtUhid`,
// the UHID (User-space HID) device abstraction. Tests verify:
//
// - UHID_CREATE2 event formatting and minimal device creation
// - UHID_DESTROY event formatting
// - UHID_INPUT2 event formatting
// - Raw event send via BtUhid::send()
// - Callback registration and dispatch for GET_REPORT/SET_REPORT
// - Callback unregister_all
// - Input event queuing before UHID_START
// - MX Anywhere 3 mouse device creation with real HID descriptor
// - UhidEvent struct size and layout verification
// - UhidEventType::from_raw() and UhidDeviceType::from_icon() coverage
//
// Conversion patterns applied:
//
// | C (unit/test-uhid.c)                     | Rust (this file)                        |
// |------------------------------------------|-----------------------------------------|
// | `socketpair(AF_UNIX,SOCK_SEQPACKET,...)`  | `nix::sys::socket::socketpair()`        |
// | `bt_uhid_new(sv[0])`                      | `BtUhid::new(sv0)`                     |
// | `bt_uhid_unref(uhid)`                     | automatic `Drop`                        |
// | `bt_uhid_create(uhid, ...)`               | `uhid.create(...)`                      |
// | `bt_uhid_destroy(uhid, true)`             | `uhid.destroy(true)`                    |
// | `bt_uhid_send(uhid, &ev)`                 | `uhid.send(&ev)`                        |
// | `bt_uhid_input(uhid, 0, NULL, 0)`         | `uhid.input(0, &[])`                   |
// | `bt_uhid_register(uhid, type, cb, data)`  | `uhid.register(type, Box::new(cb))`     |
// | `bt_uhid_unregister_all(uhid)`            | `uhid.unregister_all()`                 |
// | `read(sv[1], buf, sizeof(uhid_event))`    | `nix::unistd::read(&sv1, &mut buf)`    |
// | `write(sv[1], pdu->data, pdu->size)`      | `nix::unistd::write(&sv1, bytes)`      |
// | `g_assert_cmpint(ev->type, ==, ...)`      | `assert_eq!(ev.event_type, ...)`        |
// | `memcmp(buf, pdu->data, pdu->size)`       | byte-slice comparison                   |
// | `UHID_CREATE` (legacy 0)                  | `UHID_CREATE2` (modern 11)              |
// | `UHID_INPUT` (legacy 6)                   | `UHID_INPUT2` (modern 12)               |
// | `UHID_OUTPUT` (legacy 4)                  | `UHID_SET_REPORT` (modern 13)           |
// | `UHID_FEATURE` (legacy 7)                 | `UHID_GET_REPORT` (modern 9)            |
// | `UHID_FEATURE_ANSWER` (legacy 8)          | `UHID_GET_REPORT_REPLY` (modern 10)     |
// | `BT_UHID_NONE`                            | `UhidDeviceType::None`                  |
// | `BT_UHID_MOUSE`                           | `UhidDeviceType::Mouse`                 |
// | `BDADDR_ANY`                              | `BDADDR_ANY`                            |

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bluez_shared::device::uhid::{
    BtUhid, UHID_CREATE2, UHID_DESTROY, UHID_EVENT_SIZE, UHID_GET_REPORT, UHID_GET_REPORT_REPLY,
    UHID_INPUT2, UHID_SET_REPORT, UHID_SET_REPORT_REPLY, UHID_START, UhidDeviceType, UhidEvent,
    UhidEventType,
};
use bluez_shared::sys::bluetooth::BDADDR_ANY;

use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, socketpair};
use nix::unistd::read;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a Unix `SOCK_SEQPACKET` socketpair for testing.
///
/// Returns `(uhid_fd, remote_fd)` where `uhid_fd` is passed to
/// [`BtUhid::new()`] and `remote_fd` is used for byte-level PDU
/// verification on the test side. This replaces the C test's
/// `socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)`.
fn create_test_socketpair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
        .expect("socketpair(AF_UNIX, SOCK_SEQPACKET) failed")
}

/// Read a full [`UhidEvent`] from a file descriptor.
///
/// `SOCK_SEQPACKET` preserves message boundaries, so a single `read()`
/// returns the entire 4380-byte event written by [`BtUhid::send()`].
fn read_uhid_event_from_fd(fd: &std::os::fd::OwnedFd) -> UhidEvent {
    let mut buf = [0u8; UHID_EVENT_SIZE];
    let n = read(fd.as_raw_fd(), &mut buf).expect("read from remote fd failed");
    assert_eq!(n, UHID_EVENT_SIZE, "short read: expected {UHID_EVENT_SIZE} got {n}");
    UhidEvent::from_bytes(&buf).expect("UhidEvent::from_bytes returned None")
}

/// Create a `BtUhid` instance with a socketpair for testing.
///
/// Returns `(uhid, remote_fd)` — `uhid` wraps `sv[0]`, `remote_fd` is
/// `sv[1]` for reading/writing test PDUs. The `BtUhid` has
/// `close_on_drop(true)` set so the fd is properly cleaned up.
fn create_test_uhid() -> (BtUhid, std::os::fd::OwnedFd) {
    let (sv0, sv1) = create_test_socketpair();
    let mut uhid = BtUhid::new(sv0);
    uhid.set_close_on_drop(true);
    (uhid, sv1)
}

/// Attempt a non-blocking read from a socket fd.
///
/// Uses `recv(MSG_DONTWAIT)` to check if data is available without
/// modifying the fd flags. Returns `Ok(n)` if data is available,
/// or `Err` with `EAGAIN`/`EWOULDBLOCK` if no data is pending.
fn try_read_nonblocking(fd: &std::os::fd::OwnedFd) -> nix::Result<usize> {
    let mut buf = [0u8; UHID_EVENT_SIZE];
    nix::sys::socket::recv(fd.as_raw_fd(), &mut buf, MsgFlags::MSG_DONTWAIT)
}

/// Build a UHID_START event for simulating kernel start notification.
///
/// After [`BtUhid::create()`] sends `UHID_CREATE2`, the kernel responds
/// with `UHID_START` to indicate the device is registered. This helper
/// constructs that event for injection via [`write_uhid_event_to_fd()`]
/// or direct [`BtUhid::process_event()`].
fn make_start_event() -> UhidEvent {
    let mut ev = UhidEvent::zeroed();
    ev.event_type = UHID_START;
    ev
}

// ============================================================================
// MX Anywhere 3 HID Report Descriptor (from C test)
// ============================================================================

/// HID Report Descriptor for the Logitech MX Anywhere 3 mouse.
///
/// Byte-identical to the descriptor in C `test-uhid.c` (lines 341–353),
/// extracted from the `UTIL_IOV_INIT(...)` initializer.
const MX_ANYWHERE_3_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xA1, 0x00, 0x95, 0x10, 0x75, 0x01,
    0x15, 0x00, 0x25, 0x01, 0x05, 0x09, 0x19, 0x01, 0x29, 0x10, 0x81, 0x02, 0x05, 0x01, 0x16, 0x01,
    0xF8, 0x26, 0xFF, 0x07, 0x75, 0x0C, 0x95, 0x02, 0x09, 0x30, 0x09, 0x31, 0x81, 0x06, 0x15, 0x81,
    0x25, 0x7F, 0x75, 0x08, 0x95, 0x01, 0x09, 0x38, 0x81, 0x06, 0x95, 0x01, 0x05, 0x0C, 0x0A, 0x38,
    0x02, 0x81, 0x06, 0xC0, 0xC0, 0x06, 0x43, 0xFF, 0x0A, 0x02, 0x02, 0xA1, 0x01, 0x85, 0x11, 0x75,
    0x08, 0x95, 0x13, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x09, 0x02, 0x81, 0x00, 0x09, 0x02, 0x91, 0x00,
    0xC0,
];

/// MX Anywhere 3 mouse device constants (from C `struct test_device`).
const MX_ANYWHERE_3_NAME: &str = "MX Anywhere 3";
const MX_ANYWHERE_3_VENDOR: u32 = 0x46D;
const MX_ANYWHERE_3_PRODUCT: u32 = 0xB025;
const MX_ANYWHERE_3_VERSION: u32 = 0x14;
const MX_ANYWHERE_3_COUNTRY: u32 = 0x00;

// ============================================================================
// Test: UhidEvent Struct Format Verification
// ============================================================================

/// Verify `UhidEvent` struct size matches the kernel ABI.
///
/// The kernel `struct uhid_event` is exactly 4380 bytes: 4-byte `__u32 type`
/// followed by a 4376-byte union. This test ensures the Rust packed
/// representation matches.
#[tokio::test]
async fn test_uhid_event_format() {
    // Verify overall event size matches kernel ABI.
    assert_eq!(
        std::mem::size_of::<UhidEvent>(),
        UHID_EVENT_SIZE,
        "UhidEvent size mismatch: expected {UHID_EVENT_SIZE}, got {}",
        std::mem::size_of::<UhidEvent>()
    );

    // Verify event_type is at offset 0 (packed struct).
    assert_eq!(std::mem::offset_of!(UhidEvent, event_type), 0, "event_type should be at offset 0");

    // Verify payload union starts at offset 4.
    assert_eq!(std::mem::offset_of!(UhidEvent, u), 4, "payload union should be at offset 4");

    // Verify payload size = UHID_EVENT_SIZE - sizeof(u32).
    let payload_size = UHID_EVENT_SIZE - std::mem::size_of::<u32>();
    let ev = UhidEvent::zeroed();
    assert_eq!(ev.u.len(), payload_size, "payload array length mismatch");

    // Verify zeroed event has all-zero bytes.
    // Copy event_type out of packed struct to avoid misaligned reference.
    let et = { ev.event_type };
    assert_eq!(et, 0);
    assert!(ev.u.iter().all(|&b| b == 0), "zeroed event should have all-zero payload");

    // Verify UhidEvent::from_bytes rejects short buffers.
    assert!(UhidEvent::from_bytes(&[0u8; 3]).is_none(), "from_bytes should reject < 4380 bytes");
    assert!(
        UhidEvent::from_bytes(&[0u8; UHID_EVENT_SIZE - 1]).is_none(),
        "from_bytes should reject UHID_EVENT_SIZE - 1 bytes"
    );

    // Verify round-trip: zeroed → as_bytes → from_bytes.
    let ev2 = UhidEvent::from_bytes(ev.as_bytes()).expect("round-trip from_bytes failed");
    let et2 = { ev2.event_type };
    assert_eq!(et2, 0);
    assert_eq!(ev2.u, ev.u);
}

// ============================================================================
// Test: /uhid/command/create → test_uhid_command_create
// ============================================================================

/// Create a minimal UHID device and verify the UHID_CREATE2 event.
///
/// Ported from C `/uhid/command/create` (test_client with ev_create):
/// - Creates a `BtUhid` via socketpair
/// - Calls `create()` with empty name, no addresses, zero IDs, no descriptor
/// - Reads the raw event from the remote fd
/// - Verifies event type is `UHID_CREATE2` (11)
/// - Verifies all `UhidCreate2Req` fields match expected values
#[tokio::test]
async fn test_uhid_command_create() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Call create with minimal parameters (matching C: "", NULL, NULL, 0s, NONE, NULL, 0).
    let result = uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[]);
    assert!(result.is_ok(), "bt_uhid_create failed: {:?}", result.err());

    // Verify the device is marked as created.
    assert!(uhid.created(), "device should be marked created after create()");

    // Read the UHID_CREATE2 event from the remote end of the socketpair.
    let ev = read_uhid_event_from_fd(&remote_fd);
    // Copy fields out of packed struct to avoid misaligned references.
    let et = { ev.event_type };
    assert_eq!(et, UHID_CREATE2, "expected UHID_CREATE2 ({UHID_CREATE2}), got {et}");

    // Verify typed payload fields via as_create2() accessor.
    let req = ev.as_create2();
    assert_eq!(req.name[0], 0, "name should be empty (NUL at index 0)");
    assert_eq!(req.phys[0], 0, "phys should be empty (no source address)");
    assert_eq!(req.uniq[0], 0, "uniq should be empty (no destination address)");
    let vendor = { req.vendor };
    let product = { req.product };
    let version = { req.version };
    let country = { req.country };
    let bus = { req.bus };
    let rd_size = { req.rd_size };
    assert_eq!(vendor, 0);
    assert_eq!(product, 0);
    assert_eq!(version, 0);
    assert_eq!(country, 0);
    assert_eq!(bus, 0x05, "bus should be BUS_BLUETOOTH (0x05)");
    assert_eq!(rd_size, 0, "rd_size should be 0 (no descriptor)");
}

// ============================================================================
// Test: /uhid/command/destroy → test_uhid_command_destroy
// ============================================================================

/// Create and then destroy a UHID device, verifying both events.
///
/// Ported from C `/uhid/command/destroy` (test_client with ev_destroy):
/// - Creates a device (sends UHID_CREATE2)
/// - Destroys with `force=true` (sends UHID_DESTROY)
/// - Verifies both events arrive on the remote fd
#[tokio::test]
async fn test_uhid_command_destroy() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Create the device first.
    uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[]).expect("create failed");

    // Read and discard the CREATE2 event.
    let ev_create = read_uhid_event_from_fd(&remote_fd);
    let et_create = { ev_create.event_type };
    assert_eq!(et_create, UHID_CREATE2);

    // Destroy the device with force=true.
    let result = uhid.destroy(true);
    assert!(result.is_ok(), "destroy failed: {:?}", result.err());

    // Read the DESTROY event.
    let ev_destroy = read_uhid_event_from_fd(&remote_fd);
    let et_destroy = { ev_destroy.event_type };
    assert_eq!(
        et_destroy, UHID_DESTROY,
        "expected UHID_DESTROY ({UHID_DESTROY}), got {et_destroy}"
    );

    // Verify the device is no longer marked as created.
    assert!(!uhid.created(), "device should not be marked created after destroy()");
}

// ============================================================================
// Test: /uhid/command/feature_answer → test_uhid_command_send
// ============================================================================

/// Send a raw UHID event via `BtUhid::send()` and verify receipt.
///
/// Ported from C `/uhid/command/feature_answer` (test_client with
/// ev_feature_answer). The C test uses `bt_uhid_send()` with a
/// UHID_FEATURE_ANSWER (legacy 8) event. In the modern Rust API,
/// the equivalent is UHID_GET_REPORT_REPLY (10).
///
/// This test verifies the raw send path independent of higher-level
/// methods like `create()` or `input()`.
#[tokio::test]
async fn test_uhid_command_send() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Create the device first (required for a valid fd path).
    uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[]).expect("create failed");
    let _ = read_uhid_event_from_fd(&remote_fd); // consume CREATE2

    // Build a GET_REPORT_REPLY event (replacing legacy UHID_FEATURE_ANSWER).
    let mut ev_reply = UhidEvent::zeroed();
    ev_reply.event_type = UHID_GET_REPORT_REPLY;

    // Send via the raw send API.
    let result = uhid.send(&ev_reply);
    assert!(result.is_ok(), "send failed: {:?}", result.err());

    // Read and verify the event on the remote end.
    let ev_received = read_uhid_event_from_fd(&remote_fd);
    let et_recv = { ev_received.event_type };
    assert_eq!(
        et_recv, UHID_GET_REPORT_REPLY,
        "expected UHID_GET_REPORT_REPLY ({UHID_GET_REPORT_REPLY}), got {et_recv}"
    );
}

// ============================================================================
// Test: /uhid/command/input → test_uhid_command_input
// ============================================================================

/// Send an HID input report via `BtUhid::input()` and verify the event.
///
/// Ported from C `/uhid/command/input` (test_client with ev_input).
/// The Rust API uses UHID_INPUT2 (12) instead of the legacy UHID_INPUT (6).
///
/// Note: `input()` queues events until UHID_START is received. This test
/// first simulates the start notification via `process_event()`, then
/// calls `input()` to verify the event is sent immediately.
#[tokio::test]
async fn test_uhid_command_input() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Create the device.
    uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[]).expect("create failed");
    let _ = read_uhid_event_from_fd(&remote_fd); // consume CREATE2

    // Simulate UHID_START from kernel to set started=true.
    let start_ev = make_start_event();
    uhid.process_event(&start_ev);
    assert!(uhid.started(), "device should be started after processing UHID_START");

    // Send input with number=0, empty data (matching C: bt_uhid_input(uhid, 0, NULL, 0)).
    let result = uhid.input(0, &[]);
    assert!(result.is_ok(), "input failed: {:?}", result.err());

    // Read and verify the INPUT2 event on the remote end.
    let ev_input = read_uhid_event_from_fd(&remote_fd);
    let et_input = { ev_input.event_type };
    assert_eq!(et_input, UHID_INPUT2, "expected UHID_INPUT2 ({UHID_INPUT2}), got {et_input}");

    // Verify the input payload has size 0 (empty data, number=0).
    let req = ev_input.as_input2();
    let req_size = { req.size };
    assert_eq!(req_size, 0, "input2 size should be 0 for empty input");
}

// ============================================================================
// Test: /uhid/event/output → test_uhid_event_set_report
// ============================================================================

/// Register a SET_REPORT callback and verify dispatch.
///
/// Ported from C `/uhid/event/output` (test_server with ev_output).
/// The C test registers a callback for UHID_OUTPUT (legacy 4). In the
/// modern Rust API, the equivalent kernel→userspace event is
/// UHID_SET_REPORT (13).
///
/// Flow:
/// 1. Register a callback for UHID_SET_REPORT
/// 2. Build a SET_REPORT event
/// 3. Dispatch via `process_event()`
/// 4. Verify the callback was invoked with the correct event type
#[tokio::test]
async fn test_uhid_event_set_report() {
    let (mut uhid, _remote_fd) = create_test_uhid();

    // Shared flag to verify callback invocation.
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);

    // Shared storage for the event type received by the callback.
    let received_type = Arc::new(AtomicU32::new(0));
    let received_type_clone = Arc::clone(&received_type);

    // Register callback for UHID_SET_REPORT (replaces C UHID_OUTPUT handler).
    let id = uhid.register(
        UHID_SET_REPORT,
        Box::new(move |ev: &UhidEvent| {
            called_clone.store(true, Ordering::SeqCst);
            received_type_clone.store(ev.event_type, Ordering::SeqCst);
        }),
    );
    assert!(id > 0, "register should return non-zero ID");

    // Build a SET_REPORT event (simulating kernel sending this to userspace).
    let mut ev_set_report = UhidEvent::zeroed();
    ev_set_report.event_type = UHID_SET_REPORT;

    // Dispatch to registered callbacks.
    uhid.process_event(&ev_set_report);

    // Verify callback was invoked.
    assert!(called.load(Ordering::SeqCst), "SET_REPORT callback should have been called");
    assert_eq!(
        received_type.load(Ordering::SeqCst),
        UHID_SET_REPORT,
        "callback should receive UHID_SET_REPORT event"
    );
}

// ============================================================================
// Test: /uhid/event/feature → test_uhid_event_get_report
// ============================================================================

/// Register a GET_REPORT callback and verify dispatch.
///
/// Ported from C `/uhid/event/feature` (test_server with ev_feature).
/// The C test registers a callback for UHID_FEATURE (legacy 7). In the
/// modern Rust API, the equivalent is UHID_GET_REPORT (9).
///
/// Flow:
/// 1. Register a callback for UHID_GET_REPORT
/// 2. Build a GET_REPORT event
/// 3. Dispatch via `process_event()`
/// 4. Verify the callback was invoked with the correct event type
#[tokio::test]
async fn test_uhid_event_get_report() {
    let (mut uhid, _remote_fd) = create_test_uhid();

    // Shared flag to verify callback invocation.
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);

    // Shared storage for the event type received by the callback.
    let received_type = Arc::new(AtomicU32::new(0));
    let received_type_clone = Arc::clone(&received_type);

    // Register callback for UHID_GET_REPORT (replaces C UHID_FEATURE handler).
    let id = uhid.register(
        UHID_GET_REPORT,
        Box::new(move |ev: &UhidEvent| {
            called_clone.store(true, Ordering::SeqCst);
            received_type_clone.store(ev.event_type, Ordering::SeqCst);
        }),
    );
    assert!(id > 0, "register should return non-zero ID");

    // Build a GET_REPORT event (simulating kernel sending this to userspace).
    let mut ev_get_report = UhidEvent::zeroed();
    ev_get_report.event_type = UHID_GET_REPORT;

    // Dispatch to registered callbacks.
    uhid.process_event(&ev_get_report);

    // Verify callback was invoked.
    assert!(called.load(Ordering::SeqCst), "GET_REPORT callback should have been called");
    assert_eq!(
        received_type.load(Ordering::SeqCst),
        UHID_GET_REPORT,
        "callback should receive UHID_GET_REPORT event"
    );
}

// ============================================================================
// Test: /uhid/device/mx_anywhere_3 → test_uhid_device_mx_anywhere_3
// ============================================================================

/// Create a virtual MX Anywhere 3 mouse device and verify all fields.
///
/// Ported from C `/uhid/device/mx_anywhere_3` (test_client with
/// mx_anywhere_3 test_device). Uses BDADDR_ANY for both source and
/// destination addresses. Verifies the UHID_CREATE2 event contains
/// the correct device name, vendor/product/version IDs, and the
/// full HID report descriptor.
#[tokio::test]
async fn test_uhid_device_mx_anywhere_3() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Create the device with MX Anywhere 3 parameters.
    let result = uhid.create(
        MX_ANYWHERE_3_NAME,
        Some(&BDADDR_ANY),
        Some(&BDADDR_ANY),
        MX_ANYWHERE_3_VENDOR,
        MX_ANYWHERE_3_PRODUCT,
        MX_ANYWHERE_3_VERSION,
        MX_ANYWHERE_3_COUNTRY,
        UhidDeviceType::Mouse,
        MX_ANYWHERE_3_DESCRIPTOR,
    );
    assert!(result.is_ok(), "create with MX Anywhere 3 failed: {:?}", result.err());

    // Read the CREATE2 event from the remote end.
    let ev = read_uhid_event_from_fd(&remote_fd);
    let et = { ev.event_type };
    assert_eq!(et, UHID_CREATE2);

    // Verify device name.
    let req = ev.as_create2();
    let name_len = MX_ANYWHERE_3_NAME.len();
    assert_eq!(&req.name[..name_len], MX_ANYWHERE_3_NAME.as_bytes(), "device name mismatch");
    assert_eq!(req.name[name_len], 0, "name should be NUL-terminated");

    // Verify phys field contains BDADDR_ANY formatted as "00:00:00:00:00:00".
    let bdaddr_str = b"00:00:00:00:00:00";
    assert_eq!(
        &req.phys[..bdaddr_str.len()],
        bdaddr_str.as_slice(),
        "phys should contain BDADDR_ANY string"
    );

    // Verify uniq field contains BDADDR_ANY.
    assert_eq!(
        &req.uniq[..bdaddr_str.len()],
        bdaddr_str.as_slice(),
        "uniq should contain BDADDR_ANY string"
    );

    // Copy packed struct fields to local variables to avoid misaligned references.
    let vendor = { req.vendor };
    let product = { req.product };
    let version = { req.version };
    let country = { req.country };
    let bus = { req.bus };
    let rd_size = { req.rd_size };
    assert_eq!(vendor, MX_ANYWHERE_3_VENDOR, "vendor ID mismatch");
    assert_eq!(product, MX_ANYWHERE_3_PRODUCT, "product ID mismatch");
    assert_eq!(version, MX_ANYWHERE_3_VERSION, "version mismatch");
    assert_eq!(country, MX_ANYWHERE_3_COUNTRY, "country mismatch");
    assert_eq!(bus, 0x05, "bus should be BUS_BLUETOOTH");

    // Verify report descriptor size and content.
    let desc_len = MX_ANYWHERE_3_DESCRIPTOR.len();
    assert_eq!(rd_size as usize, desc_len, "rd_size mismatch");
    assert_eq!(
        &req.rd_data[..desc_len],
        MX_ANYWHERE_3_DESCRIPTOR,
        "HID report descriptor content mismatch"
    );
}

// ============================================================================
// Test: Input Queuing Before UHID_START
// ============================================================================

/// Verify that `input()` queues events before `UHID_START` is received.
///
/// The kernel sends UHID_START after processing UHID_CREATE2. Until that
/// notification arrives, input events must be queued and NOT written to
/// the fd. After UHID_START, queued events are flushed.
///
/// This behavior matches C `bt_uhid_input()` lines 487–493.
#[tokio::test]
async fn test_uhid_input_queueing() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Create the device.
    uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[]).expect("create failed");
    let _ = read_uhid_event_from_fd(&remote_fd); // consume CREATE2

    // Device is NOT started yet — input should be queued.
    assert!(!uhid.started(), "device should not be started before UHID_START");

    // Queue several input events.
    uhid.input(0, &[0x01]).expect("queued input 1 failed");
    uhid.input(0, &[0x02]).expect("queued input 2 failed");
    uhid.input(0, &[0x03]).expect("queued input 3 failed");

    // Verify nothing was written to the remote fd by attempting a
    // non-blocking recv. MSG_DONTWAIT avoids modifying fd flags.
    let read_result = try_read_nonblocking(&remote_fd);
    assert!(read_result.is_err(), "no data should be available on remote fd before UHID_START");

    // Now simulate UHID_START — this should flush all queued inputs.
    let start_ev = make_start_event();
    uhid.process_event(&start_ev);
    assert!(uhid.started(), "device should be started after UHID_START");

    // Read the 3 flushed INPUT2 events.
    for i in 1..=3u8 {
        let ev = read_uhid_event_from_fd(&remote_fd);
        let et = { ev.event_type };
        assert_eq!(et, UHID_INPUT2, "flushed event {i} should be UHID_INPUT2");
        let req = ev.as_input2();
        let req_size = { req.size };
        assert_eq!(req_size, 1, "flushed input {i} data size should be 1");
        assert_eq!(req.data[0], i, "flushed input {i} data byte mismatch");
    }
}

// ============================================================================
// Test: Callback Unregister All
// ============================================================================

/// Verify `unregister_all()` removes all callbacks.
///
/// After calling `unregister_all()`, dispatching events should NOT invoke
/// any previously registered callbacks.
#[tokio::test]
async fn test_uhid_unregister_all() {
    let (mut uhid, _remote_fd) = create_test_uhid();

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);

    // Register a callback.
    let _id = uhid.register(
        UHID_SET_REPORT,
        Box::new(move |_ev: &UhidEvent| {
            called_clone.store(true, Ordering::SeqCst);
        }),
    );

    // Unregister all callbacks.
    uhid.unregister_all();

    // Build and dispatch a SET_REPORT event.
    let mut ev = UhidEvent::zeroed();
    ev.event_type = UHID_SET_REPORT;
    uhid.process_event(&ev);

    // Verify callback was NOT invoked.
    assert!(!called.load(Ordering::SeqCst), "callback should not be called after unregister_all()");
}

// ============================================================================
// Test: UhidEventType::from_raw Coverage
// ============================================================================

/// Verify `UhidEventType::from_raw()` correctly maps all known event types.
///
/// Tests all 9 recognized event type values and several unknown values.
#[tokio::test]
async fn test_uhid_event_type_from_raw() {
    // Known event types.
    assert_eq!(UhidEventType::from_raw(UHID_CREATE2), Some(UhidEventType::Create2));
    assert_eq!(UhidEventType::from_raw(UHID_DESTROY), Some(UhidEventType::Destroy));
    assert_eq!(UhidEventType::from_raw(UHID_START), Some(UhidEventType::Start));
    assert_eq!(UhidEventType::from_raw(UHID_INPUT2), Some(UhidEventType::Input2));
    assert_eq!(UhidEventType::from_raw(UHID_GET_REPORT), Some(UhidEventType::GetReport));
    assert_eq!(UhidEventType::from_raw(UHID_SET_REPORT), Some(UhidEventType::SetReport));
    assert_eq!(UhidEventType::from_raw(UHID_GET_REPORT_REPLY), Some(UhidEventType::GetReportReply));
    assert_eq!(UhidEventType::from_raw(UHID_SET_REPORT_REPLY), Some(UhidEventType::SetReportReply));

    // Verify Stop event type (value 3).
    assert_eq!(UhidEventType::from_raw(3), Some(UhidEventType::Stop));

    // Unknown/legacy event types should return None.
    assert_eq!(UhidEventType::from_raw(0), None, "legacy UHID_CREATE (0) should return None");
    assert_eq!(UhidEventType::from_raw(4), None, "legacy UHID_OUTPUT (4) should return None");
    assert_eq!(UhidEventType::from_raw(6), None, "legacy UHID_INPUT (6) should return None");
    assert_eq!(UhidEventType::from_raw(7), None, "legacy UHID_FEATURE (7) should return None");
    assert_eq!(
        UhidEventType::from_raw(8),
        None,
        "legacy UHID_FEATURE_ANSWER (8) should return None"
    );
    assert_eq!(UhidEventType::from_raw(100), None, "arbitrary unknown value should return None");
    assert_eq!(UhidEventType::from_raw(u32::MAX), None, "u32::MAX should return None");
}

// ============================================================================
// Test: UhidDeviceType::from_icon Coverage
// ============================================================================

/// Verify `UhidDeviceType::from_icon()` correctly maps icon strings.
///
/// Tests all 5 known icon strings and edge cases (None, unknown).
#[tokio::test]
async fn test_uhid_device_type_from_icon() {
    assert_eq!(UhidDeviceType::from_icon(Some("input-keyboard")), UhidDeviceType::Keyboard);
    assert_eq!(UhidDeviceType::from_icon(Some("input-mouse")), UhidDeviceType::Mouse);
    assert_eq!(UhidDeviceType::from_icon(Some("input-gaming")), UhidDeviceType::Gaming);
    assert_eq!(UhidDeviceType::from_icon(Some("input-tablet")), UhidDeviceType::Tablet);
    assert_eq!(UhidDeviceType::from_icon(None), UhidDeviceType::None);
    assert_eq!(
        UhidDeviceType::from_icon(Some("unknown-device")),
        UhidDeviceType::None,
        "unknown icon string should map to None"
    );
    assert_eq!(
        UhidDeviceType::from_icon(Some("")),
        UhidDeviceType::None,
        "empty icon string should map to None"
    );
}

// ============================================================================
// Test: Create Idempotency
// ============================================================================

/// Verify that calling `create()` twice does NOT send a second event.
///
/// The `BtUhid::create()` method is idempotent — if the device is already
/// created, it returns `Ok(())` without re-sending UHID_CREATE2.
#[tokio::test]
async fn test_uhid_create_idempotent() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // First create — should send UHID_CREATE2.
    uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[])
        .expect("first create failed");
    let ev1 = read_uhid_event_from_fd(&remote_fd);
    let et1 = { ev1.event_type };
    assert_eq!(et1, UHID_CREATE2);

    // Second create — should be idempotent (no event sent).
    uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[])
        .expect("second create should succeed");

    // Verify no additional event was written via non-blocking recv.
    let result = try_read_nonblocking(&remote_fd);
    assert!(result.is_err(), "no additional event should be written on second create()");
}

// ============================================================================
// Test: Destroy Without Create
// ============================================================================

/// Verify that `destroy()` on an uncreated device is a no-op.
///
/// If `create()` was never called, `destroy()` should return `Ok(())`
/// without writing anything to the fd.
#[tokio::test]
async fn test_uhid_destroy_without_create() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Destroy without prior create — should be no-op.
    let result = uhid.destroy(true);
    assert!(result.is_ok(), "destroy without create should succeed");

    // Verify nothing was written via non-blocking recv.
    let result = try_read_nonblocking(&remote_fd);
    assert!(result.is_err(), "no event should be written for destroy without create");
}

// ============================================================================
// Test: Input with Report Number
// ============================================================================

/// Verify `input()` correctly prepends a report number byte when non-zero.
///
/// When `number != 0`, the report number byte is prepended before the
/// data payload, and `size` includes both the number byte and the data.
#[tokio::test]
async fn test_uhid_input_with_report_number() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Create and start the device.
    uhid.create("", None, None, 0, 0, 0, 0, UhidDeviceType::None, &[]).expect("create failed");
    let _ = read_uhid_event_from_fd(&remote_fd); // consume CREATE2

    let start_ev = make_start_event();
    uhid.process_event(&start_ev);

    // Send input with report number 0x02 and 3 bytes of data.
    let data = [0xAA, 0xBB, 0xCC];
    uhid.input(0x02, &data).expect("input with report number failed");

    // Read and verify.
    let ev = read_uhid_event_from_fd(&remote_fd);
    let et = { ev.event_type };
    assert_eq!(et, UHID_INPUT2);

    let req = ev.as_input2();
    // Size = 1 (report number) + 3 (data) = 4.
    let req_size = { req.size };
    assert_eq!(req_size, 4, "input2 size should include report number + data");
    assert_eq!(req.data[0], 0x02, "first byte should be report number");
    assert_eq!(req.data[1], 0xAA);
    assert_eq!(req.data[2], 0xBB);
    assert_eq!(req.data[3], 0xCC);
}

// ============================================================================
// Test: Multiple Callback Registration
// ============================================================================

/// Verify multiple callbacks for different event types dispatch correctly.
///
/// Registers callbacks for both UHID_GET_REPORT and UHID_SET_REPORT,
/// then dispatches each event type and verifies only the matching
/// callback is invoked.
#[tokio::test]
async fn test_uhid_multiple_callbacks() {
    let (mut uhid, _remote_fd) = create_test_uhid();

    let get_report_called = Arc::new(AtomicBool::new(false));
    let get_report_called_clone = Arc::clone(&get_report_called);

    let set_report_called = Arc::new(AtomicBool::new(false));
    let set_report_called_clone = Arc::clone(&set_report_called);

    // Register GET_REPORT callback.
    uhid.register(
        UHID_GET_REPORT,
        Box::new(move |_ev: &UhidEvent| {
            get_report_called_clone.store(true, Ordering::SeqCst);
        }),
    );

    // Register SET_REPORT callback.
    uhid.register(
        UHID_SET_REPORT,
        Box::new(move |_ev: &UhidEvent| {
            set_report_called_clone.store(true, Ordering::SeqCst);
        }),
    );

    // Dispatch a GET_REPORT event — only get_report callback should fire.
    let mut ev = UhidEvent::zeroed();
    ev.event_type = UHID_GET_REPORT;
    uhid.process_event(&ev);

    assert!(
        get_report_called.load(Ordering::SeqCst),
        "GET_REPORT callback should have been called"
    );
    assert!(
        !set_report_called.load(Ordering::SeqCst),
        "SET_REPORT callback should NOT have been called for GET_REPORT event"
    );

    // Reset flags.
    get_report_called.store(false, Ordering::SeqCst);

    // Dispatch a SET_REPORT event — only set_report callback should fire.
    ev.event_type = UHID_SET_REPORT;
    uhid.process_event(&ev);

    assert!(
        !get_report_called.load(Ordering::SeqCst),
        "GET_REPORT callback should NOT have been called for SET_REPORT event"
    );
    assert!(
        set_report_called.load(Ordering::SeqCst),
        "SET_REPORT callback should have been called"
    );
}

// ============================================================================
// Test: Event Byte-Level Round-Trip
// ============================================================================

/// Verify that events written via `send()` are byte-identical when read.
///
/// Constructs a SET_REPORT_REPLY event with specific field values, sends
/// it through the socketpair, and verifies the raw bytes match exactly.
#[tokio::test]
async fn test_uhid_event_byte_roundtrip() {
    let (uhid, remote_fd) = create_test_uhid();

    // Build a SET_REPORT_REPLY event with specific values.
    let mut ev = UhidEvent::zeroed();
    ev.event_type = UHID_SET_REPORT_REPLY;
    {
        let rsp = ev.as_set_report_reply_mut();
        rsp.id = 42;
        rsp.err = 0;
    }

    // Send and read back.
    uhid.send(&ev).expect("send failed");
    let ev_received = read_uhid_event_from_fd(&remote_fd);

    // Verify byte-level identity.
    assert_eq!(
        ev.as_bytes(),
        ev_received.as_bytes(),
        "sent and received events should be byte-identical"
    );
}

// ============================================================================
// Test: Keyboard Device Destroy Behavior
// ============================================================================

/// Verify keyboard device type affects destroy behavior.
///
/// Keyboard devices (UhidDeviceType::Keyboard) are NOT destroyed on
/// non-forced disconnect to prevent keypress loss during reconnection.
/// Only `destroy(force=true)` actually destroys a keyboard device.
/// Non-keyboard devices are always force-destroyed.
#[tokio::test]
async fn test_uhid_keyboard_destroy_behavior() {
    let (mut uhid, remote_fd) = create_test_uhid();

    // Create a keyboard device.
    uhid.create(
        "Test Keyboard",
        None,
        None,
        0x1234,
        0x5678,
        0x01,
        0,
        UhidDeviceType::Keyboard,
        &[0x05, 0x01, 0x09, 0x06], // minimal keyboard descriptor stub
    )
    .expect("create keyboard failed");
    let _ = read_uhid_event_from_fd(&remote_fd); // consume CREATE2

    // Non-forced destroy on keyboard — should be no-op (device preserved).
    uhid.destroy(false).expect("non-forced destroy should succeed");
    assert!(uhid.created(), "keyboard should still be created after non-forced destroy");

    // Verify no DESTROY event was sent via non-blocking recv.
    let result = try_read_nonblocking(&remote_fd);
    assert!(result.is_err(), "no DESTROY event should be sent for non-forced keyboard destroy");

    // Forced destroy on keyboard — should actually destroy.
    uhid.destroy(true).expect("forced destroy should succeed");
    assert!(!uhid.created(), "keyboard should not be created after forced destroy");

    let ev = read_uhid_event_from_fd(&remote_fd);
    let et = { ev.event_type };
    assert_eq!(et, UHID_DESTROY, "forced destroy should send UHID_DESTROY");
}
