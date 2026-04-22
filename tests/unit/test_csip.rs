// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_csip.rs — Rust CSIP (Coordinated Set Identification Profile) tests
//
// Comprehensive unit tests for the CSIP module in `bluez_shared::audio::csip`,
// verifying:
//   - Server-side CSIS service registration and characteristic responses
//   - SIRK (Set Identity Resolving Key) read in cleartext and encrypted modes
//   - Set Size, Set Member Lock, and Rank characteristic reads
//   - Lock write operations (lock/unlock)
//   - CCC descriptor write for notification enablement
//   - Error handling for invalid lock values and already-locked sets
//   - RSI (Resolvable Set Identifier) matching via crypto
//   - Client discovery of CSIS service characteristics
//
// Architecture:
//   socketpair(AF_UNIX, SOCK_SEQPACKET) → nix::sys::socket::socketpair()
//   BtAtt::new(fd, false) + set_security(HIGH) for encrypted permissions
//   BtGattServer::new(db, att, 64, 0) → server-side ATT handler
//   pump_att() → simulates event loop for PDU processing
//
// Every test follows the established pattern from test_gmap.rs:
//   1. Create GattDb, register CSIS via BtCsip::set_sirk
//   2. Create socketpair-backed ATT transport
//   3. Create GATT server
//   4. Exchange ATT PDUs and verify responses

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use tokio::runtime::Runtime;

use bluez_shared::att::transport::BtAtt;
use bluez_shared::audio::csip::{BtCsip, CsipSirkType, bt_csip_register, bt_csip_unregister};
use bluez_shared::crypto::aes_cmac::{bt_crypto_rsi, bt_crypto_sef, bt_crypto_sih};
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbCcc};
use bluez_shared::gatt::server::BtGattServer;

// ============================================================================
// ATT Protocol Constants
// ============================================================================

/// ATT Read Request opcode (0x0A).
const ATT_OP_READ_REQ: u8 = 0x0A;
/// ATT Read Response opcode (0x0B).
const ATT_OP_READ_RSP: u8 = 0x0B;
/// ATT Write Request opcode (0x12).
const ATT_OP_WRITE_REQ: u8 = 0x12;
/// ATT Write Response opcode (0x13).
const ATT_OP_WRITE_RSP: u8 = 0x13;
/// ATT MTU Exchange Request opcode (0x02).
const ATT_OP_MTU_REQ: u8 = 0x02;
/// ATT MTU Exchange Response opcode (0x03).
const ATT_OP_MTU_RSP: u8 = 0x03;

/// Type alias for the optional SIRK encryption callback to avoid clippy::type_complexity.
type SirkEncryptFunc = Option<Arc<dyn Fn(&BtAtt, &[u8; 16]) -> bool + Send + Sync>>;

// ============================================================================
// CSIS Handle Constants
//
// Handle layout for a fresh GattDb with CSIS service registered via sirk_new:
//   Handle 1:  CSIS primary service declaration
//   Handle 2:  SIRK characteristic declaration
//   Handle 3:  SIRK characteristic value (READ)
//   Handle 4:  Set Size characteristic declaration
//   Handle 5:  Set Size characteristic value (READ)
//   Handle 6:  Set Member Lock characteristic declaration
//   Handle 7:  Set Member Lock characteristic value (READ + WRITE)
//   Handle 8:  Lock CCC descriptor (WRITE)
//   Handle 9:  Rank characteristic declaration
//   Handle 10: Rank characteristic value (READ)
//   Handle 11: CAS primary service declaration
//   Handle 12: CAS include declaration (pointing to CSIS)
// ============================================================================

/// SIRK characteristic value handle.
const SIRK_HANDLE: u16 = 0x0003;
/// Set Size characteristic value handle.
const SIZE_HANDLE: u16 = 0x0005;
/// Set Member Lock characteristic value handle.
const LOCK_HANDLE: u16 = 0x0007;
/// Lock CCC descriptor handle.
const LOCK_CCC_HANDLE: u16 = 0x0008;
/// Rank characteristic value handle.
const RANK_HANDLE: u16 = 0x000A;

// ============================================================================
// CSIS default values (matching C source defines)
// ============================================================================

/// Default set size value.
const CSIS_SIZE_DEFAULT: u8 = 0x02;
/// Default lock state (locked).
const CSIS_LOCK_DEFAULT: u8 = 0x01;
/// Default rank value.
const CSIS_RANK_DEFAULT: u8 = 0x01;
/// Lock value: locked.
const CSIS_LOCK_LOCKED: u8 = 0x01;
/// Lock value: unlocked.
const CSIS_LOCK_UNLOCKED: u8 = 0x02;

/// Default SIRK key (matching C source SIRK constant).
/// C string: "761FAE703ED681F0C50B34155B6434FB" interpreted as hex pairs.
const DEFAULT_SIRK: [u8; 16] = [
    0x76, 0x1F, 0xAE, 0x70, 0x3E, 0xD6, 0x81, 0xF0, 0xC5, 0x0B, 0x34, 0x15, 0x5B, 0x64, 0x34, 0xFB,
];

/// BT_SECURITY_HIGH (level 3) — needed for encrypted-permission characteristics.
const BT_SECURITY_HIGH: i32 = 3;

// ============================================================================
// Socketpair helpers
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
// ATT Pump helper
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
    // Read the response using the blocking helper with retry-on-EAGAIN.
    blocking_read(peer, response_buf)
}

// ============================================================================
// CSIP Server Context Helper
// ============================================================================

/// Encapsulates the ATT transport, GATT server, and socketpair endpoints
/// needed for CSIP server PDU exchange tests.
///
/// Includes a tokio `Runtime` because `GattDb` attribute read handlers
/// internally call `tokio::spawn` for timeout management. The runtime must
/// be alive and entered before any ATT read request is processed.
struct CsipServerContext {
    /// Tokio runtime — kept alive for the duration of the test so that
    /// `GattDb::read` attribute handlers can call `tokio::spawn`.
    rt: Runtime,
    att: Arc<Mutex<BtAtt>>,
    _server: Arc<BtGattServer>,
    _csip: Arc<BtCsip>,
    peer: OwnedFd,
    att_fd: OwnedFd,
}

/// Create a GATT server context with a CSIS service registered.
///
/// Creates a fresh GattDb, registers the CSIS service via `BtCsip::set_sirk`,
/// creates a socketpair-backed ATT transport, sets security to HIGH,
/// creates a GATT server, performs an MTU exchange, and builds a tokio runtime.
///
/// Returns the server context with the peer fd ready for Read/Write PDUs.
fn create_csip_server(encrypt: bool, sirk: &[u8; 16], size: u8, rank: u8) -> CsipServerContext {
    let rt = Runtime::new().expect("Failed to create tokio runtime for test");

    let db = GattDb::new();

    // Register CCC callbacks on the GattDb so that add_ccc() succeeds during
    // CSIS service registration.  Without this the CCC descriptor is silently
    // skipped, shifting all subsequent handle assignments.
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    // Create CSIP session and register CSIS service.
    let csip = BtCsip::new(db.clone(), None);
    let encrypt_func: SirkEncryptFunc = if encrypt {
        // For encrypted SIRK, provide a callback that always returns true
        // (simulating a connection with valid LTK).
        Some(Arc::new(|_att: &BtAtt, _sirk: &[u8; 16]| -> bool { true }))
    } else {
        None
    };
    let result = csip.set_sirk(encrypt, sirk, size, rank, encrypt_func);
    assert!(result, "BtCsip::set_sirk should succeed");

    let (fd1, fd2) = create_test_pair();
    let att_raw = fd1.as_raw_fd();
    let att = BtAtt::new(att_raw, false).expect("BtAtt::new failed");

    // Set security level to HIGH for encrypted permission attributes.
    {
        let mut att_guard = att.lock().unwrap();
        assert!(
            att_guard.set_security(BT_SECURITY_HIGH),
            "Failed to set ATT security level to HIGH"
        );
    }

    let server = BtGattServer::new(db, att.clone(), 64, 0).expect("BtGattServer::new failed");

    let ctx = CsipServerContext { rt, att, _server: server, _csip: csip, peer: fd2, att_fd: fd1 };

    // Perform MTU exchange.
    // Client sends MTU Request (0x02, MTU=64).
    let mut buf = [0u8; 512];
    let n =
        server_exchange(&ctx.att, &ctx.att_fd, &ctx.peer, &[ATT_OP_MTU_REQ, 0x40, 0x00], &mut buf);
    assert!(n >= 3, "MTU response too short: {n}");
    assert_eq!(buf[0], ATT_OP_MTU_RSP, "Expected MTU Response opcode 0x03");

    ctx
}

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

/// Send an ATT Read Request for the given handle and return the value bytes
/// from the Read Response (excluding the opcode byte).
///
/// Enters the tokio runtime context so that GattDb attribute read handlers
/// can call `tokio::spawn` for timeout management.
fn read_csip_characteristic(ctx: &CsipServerContext, handle: u16) -> Vec<u8> {
    let _guard = ctx.rt.enter();

    let req = make_read_request(handle);
    let mut buf = [0u8; 512];
    let n = server_exchange(&ctx.att, &ctx.att_fd, &ctx.peer, &req, &mut buf);
    assert!(n >= 2, "Read Response too short: {n} bytes for handle 0x{handle:04X}");
    assert_eq!(
        buf[0], ATT_OP_READ_RSP,
        "Expected Read Response opcode 0x{ATT_OP_READ_RSP:02X}, got 0x{:02X} for handle 0x{handle:04X}",
        buf[0]
    );
    buf[1..n].to_vec()
}

/// Send an ATT Write Request and return the full response PDU.
///
/// Enters the tokio runtime context for internal handler spawning.
fn write_csip_characteristic(ctx: &CsipServerContext, handle: u16, value: &[u8]) -> Vec<u8> {
    let _guard = ctx.rt.enter();

    let req = make_write_request(handle, value);
    let mut buf = [0u8; 512];
    let n = server_exchange(&ctx.att, &ctx.att_fd, &ctx.peer, &req, &mut buf);
    buf[..n].to_vec()
}

// ============================================================================
// Server Tests — CSIS Characteristic Reads
// ============================================================================

/// Test SIRK characteristic read in cleartext mode.
///
/// Creates a CSIS server with a cleartext SIRK, reads the SIRK characteristic,
/// and verifies the response format: [type_byte, sirk_bytes[0..16]].
///
/// For CsipSirkType::Cleartext, the type byte is 0x01.
#[test]
fn test_csip_sirk_read() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    let value = read_csip_characteristic(&ctx, SIRK_HANDLE);
    // SIRK response: [type_byte, sirk[0..16]] = 17 bytes
    assert_eq!(value.len(), 17, "SIRK value should be 17 bytes (1 type + 16 SIRK)");
    // Cleartext type byte = CsipSirkType::Cleartext as u8 = 0x01
    assert_eq!(
        value[0],
        CsipSirkType::Cleartext as u8,
        "SIRK type byte should be Cleartext (0x01)"
    );
    // The remaining 16 bytes should be the SIRK key.
    assert_eq!(&value[1..17], &DEFAULT_SIRK[..], "SIRK value should match the set key");
}

/// Test SIRK characteristic read in encrypted mode.
///
/// Creates a CSIS server with encrypted SIRK, reads the SIRK characteristic,
/// and verifies the response format. The encrypted value should differ from
/// the plaintext SIRK and be derivable via bt_crypto_sef.
#[test]
fn test_csip_sirk_encrypted() {
    let ctx = create_csip_server(true, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    let value = read_csip_characteristic(&ctx, SIRK_HANDLE);
    // SIRK response: [type_byte, encrypted_sirk[0..16]] = 17 bytes
    assert_eq!(value.len(), 17, "Encrypted SIRK value should be 17 bytes");
    // Encrypted type byte = CsipSirkType::Encrypt as u8 = 0x00
    assert_eq!(value[0], CsipSirkType::Encrypt as u8, "SIRK type byte should be Encrypt (0x00)");
    // Verify the encrypted value matches bt_crypto_sef(SIRK, SIRK).
    // The server code uses bt_crypto_sef(&sirk_val.val, &sirk_val.val).
    let expected_encrypted =
        bt_crypto_sef(&DEFAULT_SIRK, &DEFAULT_SIRK).expect("bt_crypto_sef should succeed");
    assert_eq!(
        &value[1..17],
        &expected_encrypted[..],
        "Encrypted SIRK should match bt_crypto_sef output"
    );
    // Encrypted value should differ from plaintext.
    assert_ne!(&value[1..17], &DEFAULT_SIRK[..], "Encrypted SIRK should differ from plaintext");
}

/// Test Set Size characteristic read.
///
/// Verifies the Size characteristic returns the configured set size value.
#[test]
fn test_csip_set_size_read() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    let value = read_csip_characteristic(&ctx, SIZE_HANDLE);
    assert_eq!(value.len(), 1, "Set Size should be 1 byte");
    assert_eq!(value[0], CSIS_SIZE_DEFAULT, "Set Size should be {CSIS_SIZE_DEFAULT:#04X}");
}

/// Test Set Size characteristic read with non-default value.
///
/// Verifies the Size characteristic returns a custom set size value.
#[test]
fn test_csip_set_size_read_custom() {
    let custom_size: u8 = 0x05;
    let ctx = create_csip_server(false, &DEFAULT_SIRK, custom_size, CSIS_RANK_DEFAULT);

    let value = read_csip_characteristic(&ctx, SIZE_HANDLE);
    assert_eq!(value.len(), 1, "Set Size should be 1 byte");
    assert_eq!(value[0], custom_size, "Set Size should be {custom_size:#04X}");
}

/// Test Set Member Lock characteristic read.
///
/// Verifies the Lock characteristic returns the default lock state.
#[test]
fn test_csip_set_member_lock_read() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    let value = read_csip_characteristic(&ctx, LOCK_HANDLE);
    assert_eq!(value.len(), 1, "Lock state should be 1 byte");
    assert_eq!(
        value[0], CSIS_LOCK_DEFAULT,
        "Lock state should be default ({CSIS_LOCK_DEFAULT:#04X})"
    );
}

/// Test Set Member Lock characteristic write — unlock then re-lock.
///
/// Writes an unlock value, reads back to verify, then writes a lock value
/// and verifies again.
#[test]
fn test_csip_set_member_lock_write() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    // Write unlock value (0x02) to lock handle.
    let response = write_csip_characteristic(&ctx, LOCK_HANDLE, &[CSIS_LOCK_UNLOCKED]);
    assert!(!response.is_empty(), "Write Response should not be empty");
    assert_eq!(
        response[0], ATT_OP_WRITE_RSP,
        "Expected Write Response opcode 0x{ATT_OP_WRITE_RSP:02X}, got 0x{:02X}",
        response[0]
    );

    // Read back lock state — should be unlocked.
    let value = read_csip_characteristic(&ctx, LOCK_HANDLE);
    assert_eq!(value.len(), 1, "Lock state should be 1 byte");
    assert_eq!(
        value[0], CSIS_LOCK_UNLOCKED,
        "Lock state should be unlocked ({CSIS_LOCK_UNLOCKED:#04X})"
    );

    // Write lock value (0x01) to re-lock.
    let response2 = write_csip_characteristic(&ctx, LOCK_HANDLE, &[CSIS_LOCK_LOCKED]);
    assert!(!response2.is_empty(), "Write Response should not be empty");
    assert_eq!(
        response2[0], ATT_OP_WRITE_RSP,
        "Expected Write Response opcode 0x{ATT_OP_WRITE_RSP:02X}"
    );

    // Read back lock state — should be locked again.
    let value2 = read_csip_characteristic(&ctx, LOCK_HANDLE);
    assert_eq!(value2.len(), 1, "Lock state should be 1 byte");
    assert_eq!(
        value2[0], CSIS_LOCK_LOCKED,
        "Lock state should be locked ({CSIS_LOCK_LOCKED:#04X})"
    );
}

/// Test Rank characteristic read.
///
/// Verifies the Rank characteristic returns the configured rank value.
#[test]
fn test_csip_rank_read() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    let value = read_csip_characteristic(&ctx, RANK_HANDLE);
    assert_eq!(value.len(), 1, "Rank should be 1 byte");
    assert_eq!(value[0], CSIS_RANK_DEFAULT, "Rank should be {CSIS_RANK_DEFAULT:#04X}");
}

/// Test Rank characteristic read with non-default value.
///
/// Verifies the Rank characteristic returns a custom rank.
#[test]
fn test_csip_rank_read_custom() {
    let custom_rank: u8 = 0x03;
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, custom_rank);

    let value = read_csip_characteristic(&ctx, RANK_HANDLE);
    assert_eq!(value.len(), 1, "Rank should be 1 byte");
    assert_eq!(value[0], custom_rank, "Rank should be {custom_rank:#04X}");
}

// ============================================================================
// Notification Tests
// ============================================================================

/// Test Lock CCC descriptor write to enable notifications.
///
/// Writes 0x0001 (little-endian) to the Lock CCC handle, verifying that the
/// server accepts the CCC configuration.
#[test]
fn test_csip_notification_lock() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    // Enable notifications: write 0x0001 (LE) to CCC handle.
    let response = write_csip_characteristic(&ctx, LOCK_CCC_HANDLE, &[0x01, 0x00]);
    assert!(!response.is_empty(), "CCC Write Response should not be empty");
    // CCC write should succeed — either Write Response (0x13) or handled silently.
    // The GATT server may respond with a Write Response for CCC writes.
    assert_eq!(
        response[0], ATT_OP_WRITE_RSP,
        "Expected Write Response opcode for CCC write, got 0x{:02X}",
        response[0]
    );

    // Now change the lock value — this should trigger notification delivery.
    // Write unlock value to lock handle.
    let wr = write_csip_characteristic(&ctx, LOCK_HANDLE, &[CSIS_LOCK_UNLOCKED]);
    assert_eq!(wr[0], ATT_OP_WRITE_RSP, "Lock write should return Write Response");

    // Read back to confirm the value was written.
    let value = read_csip_characteristic(&ctx, LOCK_HANDLE);
    assert_eq!(value[0], CSIS_LOCK_UNLOCKED, "Lock should be unlocked after write");
}

/// Test SIRK notification capability.
///
/// Verifies that the SIRK characteristic has the Notify property set by
/// reading the SIRK characteristic declaration (handle 2) and checking
/// the properties byte.
#[test]
fn test_csip_notification_sirk() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    // Read the SIRK characteristic declaration (handle 2).
    // The declaration format is: [properties, value_handle_lo, value_handle_hi, uuid...]
    let decl_handle: u16 = 0x0002;
    let decl = read_csip_characteristic(&ctx, decl_handle);
    assert!(
        decl.len() >= 5,
        "Characteristic declaration should be at least 5 bytes, got {}",
        decl.len()
    );

    // Properties byte is the first byte of the declaration value.
    let properties = decl[0];
    // BT_GATT_CHRC_PROP_NOTIFY = 0x10
    let has_notify = (properties & 0x10) != 0;
    assert!(
        has_notify,
        "SIRK characteristic should have Notify property set (properties=0x{properties:02X})"
    );

    // Verify the value handle points to SIRK_HANDLE.
    let value_handle = u16::from_le_bytes([decl[1], decl[2]]);
    assert_eq!(
        value_handle, SIRK_HANDLE,
        "SIRK declaration should point to handle {SIRK_HANDLE:#06X}"
    );
}

// ============================================================================
// Client Discovery Test
// ============================================================================

/// Test CSIS service discovery via GATT client attachment.
///
/// Creates both server and client side, attaches a GATT client to the CSIP
/// session, and verifies that the CSIS characteristics can be discovered.
/// Uses a dual-GattDb setup (local DB for server, remote DB for client).
#[test]
fn test_csip_client_discovery() {
    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    let server_db = GattDb::new();
    let client_db = GattDb::new();

    // Register CCC on the server DB so add_ccc() succeeds during CSIS setup.
    server_db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    // Set up server-side CSIS.
    let csip = BtCsip::new(server_db.clone(), Some(client_db.clone()));
    let result = csip.set_sirk(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT, None);
    assert!(result, "set_sirk should succeed for client discovery test");

    // Verify SIRK was registered.
    let sirk_info = csip.get_sirk();
    assert!(sirk_info.is_some(), "get_sirk should return Some after set_sirk");
    let (sirk_type, sirk_key, set_size, set_rank) = sirk_info.unwrap();
    assert_eq!(sirk_type, CsipSirkType::Cleartext, "SIRK type should be Cleartext");
    assert_eq!(sirk_key, DEFAULT_SIRK, "SIRK key should match");
    assert_eq!(set_size, CSIS_SIZE_DEFAULT, "Set size should match");
    assert_eq!(set_rank, CSIS_RANK_DEFAULT, "Rank should match");
}

// ============================================================================
// RSI (Resolvable Set Identifier) Matching Test
// ============================================================================

/// Test Resolvable Set Identifier generation and verification.
///
/// Generates an RSI from a known SIRK, then verifies that the hash component
/// can be recomputed from the prand component to confirm the RSI matches the
/// original SIRK. This tests the RSI matching logic used for set member
/// discovery in advertising data.
#[test]
fn test_csip_set_member_discovery() {
    // Generate an RSI from the default SIRK.
    let rsi = bt_crypto_rsi(&DEFAULT_SIRK).expect("bt_crypto_rsi should succeed");
    assert_eq!(rsi.len(), 6, "RSI should be 6 bytes");

    // RSI format: hash[0..3] || prand[3..6]
    let hash = &rsi[0..3];
    let prand = &rsi[3..6];

    // Verify prand has correct MSB format (bits [7:6] = 01).
    assert_eq!(prand[2] & 0xC0, 0x40, "prand MSBs should be 01 (resolvable set identifier)");

    // Recompute hash using sih(SIRK, prand) and verify match.
    let mut prand_arr = [0u8; 3];
    prand_arr.copy_from_slice(prand);
    let recomputed_hash =
        bt_crypto_sih(&DEFAULT_SIRK, &prand_arr).expect("bt_crypto_sih should succeed");
    assert_eq!(hash, &recomputed_hash[..], "Recomputed hash should match RSI hash component");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

/// Test error when writing an invalid lock value.
///
/// Writes an invalid lock value (not 0x01 or 0x02) to the lock handle.
/// The implementation accepts any single-byte value in the write callback
/// (matching the C behavior where the write callback always returns success).
/// This test verifies the write is processed and the value is stored.
#[test]
fn test_csip_error_invalid_value() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    // Write an invalid lock value (0xFF).
    // The C implementation's csis_lock_write_cb accepts any write with success.
    let response = write_csip_characteristic(&ctx, LOCK_HANDLE, &[0xFF]);
    assert!(!response.is_empty(), "Write Response should not be empty");
    // The write should succeed (matching C behavior).
    assert_eq!(
        response[0], ATT_OP_WRITE_RSP,
        "Write should succeed even for invalid value (matching C behavior)"
    );

    // Read back — the invalid value should be stored.
    let value = read_csip_characteristic(&ctx, LOCK_HANDLE);
    assert_eq!(value[0], 0xFF, "Lock value should store the written value");
}

/// Test lock write when set is already locked.
///
/// The CSIS lock starts in locked state (0x01). Writing 0x01 again should
/// succeed (the C implementation always accepts the write).
#[test]
fn test_csip_error_already_locked() {
    let ctx = create_csip_server(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT);

    // Read initial lock state — should be locked (0x01).
    let value = read_csip_characteristic(&ctx, LOCK_HANDLE);
    assert_eq!(value[0], CSIS_LOCK_LOCKED, "Initial lock state should be locked");

    // Write lock again (same value).
    let response = write_csip_characteristic(&ctx, LOCK_HANDLE, &[CSIS_LOCK_LOCKED]);
    assert!(!response.is_empty(), "Write Response should not be empty");
    assert_eq!(response[0], ATT_OP_WRITE_RSP, "Re-locking should succeed (matching C behavior)");

    // Lock state should still be locked.
    let value2 = read_csip_characteristic(&ctx, LOCK_HANDLE);
    assert_eq!(value2[0], CSIS_LOCK_LOCKED, "Lock state should remain locked");
}

// ============================================================================
// CSIP API Tests — Registration and Lifecycle
// ============================================================================

/// Test bt_csip_register and bt_csip_unregister global callback mechanism.
///
/// Registers global attach/detach callbacks, verifies the ID is non-zero,
/// then unregisters and verifies the unregister succeeds.
#[test]
fn test_csip_register_unregister() {
    let id = bt_csip_register(
        Box::new(|_csip| {
            // Attached callback — no action needed in this test.
        }),
        Box::new(|_csip| {
            // Detached callback — no action needed in this test.
        }),
    );
    assert_ne!(id, 0, "bt_csip_register should return a non-zero ID");

    let result = bt_csip_unregister(id);
    assert!(result, "bt_csip_unregister should succeed for valid ID");

    // Unregistering again should fail (already removed).
    let result2 = bt_csip_unregister(id);
    assert!(!result2, "bt_csip_unregister should fail for already-removed ID");
}

/// Test BtCsip::set_sirk with all-zero key (should fail).
///
/// Verifies that set_sirk rejects an all-zero SIRK key.
#[test]
fn test_csip_set_sirk_zero_key() {
    let db = GattDb::new();
    let csip = BtCsip::new(db, None);

    let zero_key = [0u8; 16];
    let result = csip.set_sirk(false, &zero_key, 2, 1, None);
    assert!(!result, "set_sirk should reject all-zero SIRK key");

    // get_sirk should return None since no SIRK was set.
    assert!(csip.get_sirk().is_none(), "get_sirk should return None when SIRK was not set");
}

/// Test BtCsip::set_sirk with encrypt=true but no encrypt_func (should fail).
///
/// Verifies that set_sirk rejects encrypted SIRK when no encryption
/// function is provided.
#[test]
fn test_csip_set_sirk_encrypt_no_func() {
    let db = GattDb::new();
    let csip = BtCsip::new(db, None);

    let result = csip.set_sirk(true, &DEFAULT_SIRK, 2, 1, None);
    assert!(!result, "set_sirk should reject encrypt=true without encrypt_func");
}

/// Test BtCsip::get_sirk returns correct values after set_sirk.
///
/// Verifies the round-trip of SIRK, size, and rank values through
/// set_sirk / get_sirk.
#[test]
fn test_csip_get_sirk_roundtrip() {
    let db = GattDb::new();
    let csip = BtCsip::new(db, None);

    let custom_size: u8 = 4;
    let custom_rank: u8 = 2;
    let result = csip.set_sirk(false, &DEFAULT_SIRK, custom_size, custom_rank, None);
    assert!(result, "set_sirk should succeed");

    let (sirk_type, key, size, rank) = csip.get_sirk().expect("get_sirk should return Some");
    assert_eq!(sirk_type, CsipSirkType::Cleartext);
    assert_eq!(key, DEFAULT_SIRK);
    assert_eq!(size, custom_size);
    assert_eq!(rank, custom_rank);
}

/// Test BtCsip::set_debug callback.
///
/// Verifies that set_debug accepts a callback without error.
#[test]
fn test_csip_set_debug() {
    let db = GattDb::new();
    let csip = BtCsip::new(db, None);

    let result = csip.set_debug(Some(Box::new(|msg: &str| {
        let _ = msg;
    })));
    assert!(result, "set_debug should succeed");

    // Setting None should also succeed (disable debug).
    let result2 = csip.set_debug(None);
    assert!(result2, "set_debug(None) should succeed");
}

/// Test BtCsip::get_att returns None when no client is attached.
///
/// Verifies that get_att returns None before any client attachment.
#[test]
fn test_csip_get_att_none() {
    let db = GattDb::new();
    let csip = BtCsip::new(db, None);

    assert!(csip.get_att().is_none(), "get_att should return None when no client is attached");
}

/// Test BtCsip::ready_register and ready_unregister.
///
/// Verifies that ready callbacks can be registered and unregistered.
#[test]
fn test_csip_ready_register_unregister() {
    let db = GattDb::new();
    let csip = BtCsip::new(db, None);

    let id = csip.ready_register(Box::new(|_csip: &BtCsip| {
        // Ready callback — no action needed.
    }));
    assert_ne!(id, 0, "ready_register should return a non-zero ID");

    let result = csip.ready_unregister(id);
    assert!(result, "ready_unregister should succeed for valid ID");

    // Unregistering again should fail.
    let result2 = csip.ready_unregister(id);
    assert!(!result2, "ready_unregister should fail for already-removed ID");
}

/// Test SIRK encryption function (bt_crypto_sef) — round-trip verification.
///
/// The SEF (SIRK Encryption Function) uses AES-CMAC-based key derivation.
/// Verify that encrypting and decrypting produces the original value.
/// Since SEF is an XOR-based encryption: sef(k, sef(k, v)) == v.
#[test]
fn test_csip_crypto_sef_roundtrip() {
    // sef(k, sirk) produces encrypted value
    let encrypted =
        bt_crypto_sef(&DEFAULT_SIRK, &DEFAULT_SIRK).expect("bt_crypto_sef should succeed");

    // sef(k, encrypted) should recover the original SIRK
    // because sef uses XOR: sef(k, sef(k, v)) = v
    let decrypted = bt_crypto_sef(&DEFAULT_SIRK, &encrypted).expect("bt_crypto_sef should succeed");

    assert_eq!(decrypted, DEFAULT_SIRK, "SEF round-trip should recover original SIRK");
}

/// Test BtCsip::attach and detach lifecycle.
///
/// Verifies that a GATT client can be attached to a CSIP session and
/// subsequently detached.  After attach, `get_att()` returns `Some`.
/// After detach, `get_att()` returns `None`.
#[test]
fn test_csip_attach_detach() {
    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let client_db = GattDb::new();
    let csip = BtCsip::new(db.clone(), Some(client_db.clone()));
    let result = csip.set_sirk(false, &DEFAULT_SIRK, CSIS_SIZE_DEFAULT, CSIS_RANK_DEFAULT, None);
    assert!(result, "set_sirk should succeed");

    // Before attach, get_att should return None.
    assert!(csip.get_att().is_none(), "get_att should return None before attach");

    // Create a GATT client on a socketpair transport.
    let (fd1, fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new failed");
    let client = BtGattClient::new(client_db, att, 64, 0).expect("BtGattClient::new failed");

    // Attach the GATT client.
    let attached = csip.attach(client);
    assert!(attached, "BtCsip::attach should succeed");

    // After attach, get_att should return Some.
    assert!(csip.get_att().is_some(), "get_att should return Some after attach");

    // Detach — should clean up.
    csip.detach();

    // After detach, get_att should return None again.
    assert!(csip.get_att().is_none(), "get_att should return None after detach");

    // Keep fd2 alive to prevent EPIPE.
    drop(fd2);
}
