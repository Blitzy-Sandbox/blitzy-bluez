// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_bass.rs — Rust BASS (Broadcast Audio Scan Service) tests
//
// Comprehensive unit tests for the BASS module in `bluez_shared::audio::bass`,
// verifying:
//   - Server-side BASS service registration and primary service discovery
//   - Broadcast Audio Scan Control Point characteristic discovery
//   - Broadcast Receive State characteristic discovery (2 instances + CCC)
//   - Ignore invalid Source_ID in Write Commands
//   - Add Source with invalid parameters (RFU PA_Sync, invalid addr_type)
//   - Opcode Not Supported error response
//   - Invalid length error responses for all opcodes
//   - Invalid Source_ID error responses for Set Broadcast_Code / Remove Source
//
// Architecture:
//   socketpair(AF_UNIX, SOCK_SEQPACKET) → nix::sys::socket::socketpair()
//   BtAtt::new(fd, false) for ATT transport
//   BtGattServer::new(db, att, 64, 0) → server-side ATT handler
//   pump_att() → simulates event loop for PDU processing
//
// Converted from unit/test-bass.c (8 active test cases):
//   3 SGGIT tests: SER/BV-01-C, CHA/BV-01-C, CHA/BV-02-C
//   5 SPE tests:   BI-01-C, BI-03-C, BI-04-C, BI-06-C, BI-07-C

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use tokio::runtime::{Handle, Runtime};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::BT_ATT_SECURITY_MEDIUM;
use bluez_shared::audio::bass::BtBass;
use bluez_shared::gatt::db::{GattDb, GattDbAttribute, GattDbCcc};
use bluez_shared::gatt::server::BtGattServer;
use bluez_shared::sys::bluetooth::BDADDR_ANY;
use bluez_shared::util::endian::get_le16;

// ============================================================================
// ATT Protocol Constants
// ============================================================================

/// ATT Error Response opcode (0x01).
const ATT_OP_ERROR_RSP: u8 = 0x01;
/// ATT MTU Exchange Request opcode (0x02).
const ATT_OP_MTU_REQ: u8 = 0x02;
/// ATT MTU Exchange Response opcode (0x03).
const ATT_OP_MTU_RSP: u8 = 0x03;
/// ATT Find Information Request opcode (0x04).
#[allow(dead_code)]
const ATT_OP_FIND_INFO_REQ: u8 = 0x04;
/// ATT Find Information Response opcode (0x05).
const ATT_OP_FIND_INFO_RSP: u8 = 0x05;
/// ATT Find By Type Value Request opcode (0x06).
#[allow(dead_code)]
const ATT_OP_FIND_BY_TYPE_REQ: u8 = 0x06;
/// ATT Find By Type Value Response opcode (0x07).
const ATT_OP_FIND_BY_TYPE_RSP: u8 = 0x07;
/// ATT Read By Type Request opcode (0x08).
const ATT_OP_READ_BY_TYPE_REQ: u8 = 0x08;
/// ATT Read By Type Response opcode (0x09).
const ATT_OP_READ_BY_TYPE_RSP: u8 = 0x09;
/// ATT Read Request opcode (0x0A).
#[allow(dead_code)]
const ATT_OP_READ_REQ: u8 = 0x0A;
/// ATT Read Response opcode (0x0B).
const ATT_OP_READ_RSP: u8 = 0x0B;
/// ATT Read By Group Type Request opcode (0x10).
const ATT_OP_READ_BY_GRP_TYPE_REQ: u8 = 0x10;
/// ATT Read By Group Type Response opcode (0x11).
const ATT_OP_READ_BY_GRP_TYPE_RSP: u8 = 0x11;
/// ATT Write Request opcode (0x12).
const ATT_OP_WRITE_REQ: u8 = 0x12;
/// ATT Write Response opcode (0x13).
const ATT_OP_WRITE_RSP: u8 = 0x13;
/// ATT Write Command opcode (0x52).
const ATT_OP_WRITE_CMD: u8 = 0x52;

// ATT error codes
/// ATT Error: Attribute Not Found (0x0A).
const ATT_ERROR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
/// ATT Error: Write Request Rejected (0xFC).
const ATT_ERROR_WRITE_REQUEST_REJECTED: u8 = 0xFC;
/// BASS Application Error: Opcode Not Supported (0x80).
const BASS_ERROR_OPCODE_NOT_SUPPORTED: u8 = 0x80;
/// BASS Application Error: Invalid Source ID (0x81).
const BASS_ERROR_INVALID_SOURCE_ID: u8 = 0x81;

// ============================================================================
// GATT Service/Characteristic UUIDs (16-bit, little-endian in ATT PDUs)
// ============================================================================

/// Primary Service Declaration UUID (0x2800) LE.
const PRIMARY_SERVICE_UUID_LE: [u8; 2] = [0x00, 0x28];
/// Characteristic Declaration UUID (0x2803) LE.
const CHARACTERISTIC_UUID_LE: [u8; 2] = [0x03, 0x28];
/// BASS UUID (0x184F) LE.
#[allow(dead_code)]
const BASS_UUID_LE: [u8; 2] = [0x4F, 0x18];

/// GATT client MTU used by all BASS tests.
const BASS_GATT_CLIENT_MTU: u16 = 64;

// ============================================================================
// BASS Handle Layout Constants
//
// Handle layout for a fresh GattDb with BASS service registered via
// BtBass::new():
//   Handle 0x0001: BASS primary service declaration
//   Handle 0x0002: Broadcast Receive State #1 char decl
//   Handle 0x0003: Broadcast Receive State #1 char value (Read+Notify)
//   Handle 0x0004: CCC descriptor for BRS #1
//   Handle 0x0005: Broadcast Receive State #2 char decl
//   Handle 0x0006: Broadcast Receive State #2 char value (Read+Notify)
//   Handle 0x0007: CCC descriptor for BRS #2
//   Handle 0x0008: Broadcast Audio Scan CP char decl
//   Handle 0x0009: Broadcast Audio Scan CP char value (Write+WriteNoRsp)
// ============================================================================

/// BASS service end handle.
const BASS_SERVICE_END: u16 = 0x000A;

/// Broadcast Audio Scan Control Point value handle.
const BASS_CP_HANDLE: u16 = 0x0009;

/// CCC descriptor handle for Broadcast Receive State #1.
const BASS_BRS1_CCC_HANDLE: u16 = 0x0004;

/// CCC descriptor handle for Broadcast Receive State #2.
const BASS_BRS2_CCC_HANDLE: u16 = 0x0007;

// ============================================================================
// CCC State Tracking
// ============================================================================

/// CCC state entry for tracking client characteristic configuration.
#[derive(Clone, Debug)]
struct CccState {
    /// Attribute handle for this CCC descriptor.
    handle: u16,
    /// CCC value (little-endian u16).
    value: u16,
}

// ============================================================================
// Socketpair Helpers
// ============================================================================

/// Create a Unix SOCK_SEQPACKET socketpair for ATT transport testing.
fn create_test_pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair creation failed")
}

/// Blocking read with retry on EAGAIN, with a 5-second timeout.
fn blocking_read(fd: &OwnedFd, buf: &mut [u8]) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match nix::unistd::read(fd.as_raw_fd(), buf) {
            Ok(n) => return n,
            Err(nix::errno::Errno::EAGAIN) => {
                if std::time::Instant::now() > deadline {
                    panic!("blocking_read: timed out");
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

/// Try to read from the peer fd with a short timeout. Returns None if no
/// response is available (EAGAIN after timeout).
fn try_read(fd: &OwnedFd, timeout_ms: u64) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 512];
    loop {
        match nix::unistd::read(fd.as_raw_fd(), &mut buf) {
            Ok(n) if n > 0 => return Some(buf[..n].to_vec()),
            Ok(_) => return None,
            Err(nix::errno::Errno::EAGAIN) => {
                if std::time::Instant::now() > deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("try_read: {e}"),
        }
    }
}

// ============================================================================
// ATT Pump Helper
// ============================================================================

/// Pump the ATT transport: read from the ATT fd, process the PDU through
/// BtAtt + BtGattServer, and flush the response writes.
///
/// This simulates the event loop that would normally drive the ATT layer.
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

/// Send a PDU to the server, pump ATT, and return full response as Vec.
fn server_exchange_vec(
    att: &Arc<Mutex<BtAtt>>,
    att_fd: &OwnedFd,
    peer: &OwnedFd,
    request: &[u8],
) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = server_exchange(att, att_fd, peer, request, &mut buf);
    buf[..n].to_vec()
}

/// Send a Write Command (no response expected). Pump ATT to process it.
fn server_write_cmd(att: &Arc<Mutex<BtAtt>>, att_fd: &OwnedFd, peer: &OwnedFd, cmd: &[u8]) {
    blocking_write(peer, cmd);
    pump_att(att, att_fd);
}

// ============================================================================
// BASS Server Context
// ============================================================================

/// Encapsulates the ATT transport, GATT server, BASS instance, and socketpair
/// endpoints needed for BASS server PDU exchange tests.
struct BassServerContext {
    /// Tokio runtime — kept alive for the duration of the test so that
    /// GattDb read attribute handlers can call tokio::spawn.
    _rt: Runtime,
    /// Tokio runtime handle — cloned from the runtime for entering the
    /// runtime context in helper functions.
    handle: Handle,
    /// Shared ATT transport reference.
    att: Arc<Mutex<BtAtt>>,
    /// GATT server reference — kept alive for lifetime management.
    _server: Arc<BtGattServer>,
    /// BASS instance — kept alive for lifetime management.
    _bass: Arc<BtBass>,
    /// Peer socket for sending/receiving PDUs.
    peer: OwnedFd,
    /// ATT socket endpoint (used by pump_att for reading).
    att_fd: OwnedFd,
    /// CCC states tracking (shared with CCC callbacks via Arc<Mutex>).
    /// Kept alive so the `Arc` ref-count is maintained for the closures.
    _ccc_states: Arc<Mutex<Vec<CccState>>>,
}

/// Create a BASS server context with BASS service registered.
///
/// Creates a fresh GattDb, registers CCC callbacks, creates a BtBass instance
/// (which registers the BASS service), sets the ATT transport, creates a GATT
/// server, and performs an MTU exchange.
fn create_bass_server() -> BassServerContext {
    let rt = Runtime::new().expect("Failed to create tokio runtime for test");
    let handle = rt.handle().clone();
    // Enter the runtime so that tokio::spawn (used inside GattDb::read for
    // timeout management) has an active reactor.
    let _guard = handle.enter();

    let db = GattDb::new();

    // CCC states shared between callbacks and test code.
    let ccc_states: Arc<Mutex<Vec<CccState>>> = Arc::new(Mutex::new(Vec::new()));

    // Register CCC callbacks matching the C test_server's behavior.
    let read_states = Arc::clone(&ccc_states);
    let write_states = Arc::clone(&ccc_states);
    let notify_states = Arc::clone(&ccc_states);

    db.ccc_register(GattDbCcc {
        read_func: Some(Arc::new(
            move |attrib: GattDbAttribute,
                  id: u32,
                  _offset: u16,
                  _opcode: u8,
                  _att: Option<Arc<Mutex<BtAtt>>>| {
                let handle = attrib.get_handle();
                let states = read_states.lock().unwrap();
                let ccc = states.iter().find(|c| c.handle == handle);
                match ccc {
                    Some(c) => {
                        let val_bytes = c.value.to_le_bytes();
                        attrib.read_result(id, 0, &val_bytes);
                    }
                    None => {
                        // No CCC state yet — return zero (disabled).
                        attrib.read_result(id, 0, &[0x00, 0x00]);
                    }
                }
            },
        )),
        write_func: Some(Arc::new(
            move |attrib: GattDbAttribute,
                  id: u32,
                  offset: u16,
                  value: &[u8],
                  _opcode: u8,
                  _att: Option<Arc<Mutex<BtAtt>>>| {
                // Validate length.
                if value.is_empty() || value.len() > 2 {
                    attrib.write_result(id, 0x0D_i32); // INVALID_ATTRIBUTE_VALUE_LEN
                    return;
                }

                // Validate offset.
                if offset > 2 {
                    attrib.write_result(id, 0x07_i32); // INVALID_OFFSET
                    return;
                }

                let val = if value.len() == 1 { u16::from(value[0]) } else { get_le16(value) };

                let handle = attrib.get_handle();
                let mut states = write_states.lock().unwrap();
                if let Some(ccc) = states.iter_mut().find(|c| c.handle == handle) {
                    ccc.value = val;
                } else {
                    states.push(CccState { handle, value: val });
                }

                attrib.write_result(id, 0);
            },
        )),
        notify_func: Some(Arc::new(
            move |attrib: GattDbAttribute,
                  ccc: GattDbAttribute,
                  _value: &[u8],
                  _att: Option<Arc<Mutex<BtAtt>>>| {
                let ccc_handle = ccc.get_handle();
                let states = notify_states.lock().unwrap();
                let ccc_state = states.iter().find(|c| c.handle == ccc_handle);
                if ccc_state.is_none() || (ccc_state.unwrap().value & 0x0001) == 0 {
                    return;
                }
                // Notification would be sent via bt_gatt_server_send_notification
                // in the C code. The server handles this internally in the Rust
                // implementation via the registered notify callback.
                let _ = attrib.get_handle();
            },
        )),
    });

    // Create BASS instance — this registers the BASS service in the GattDb.
    let db_arc = Arc::new(db.clone());
    let bass = BtBass::new(db_arc, None, &BDADDR_ANY);

    // Create socketpair for ATT transport.
    let (fd1, fd2) = create_test_pair();
    let att_raw = fd1.as_raw_fd();
    let att = BtAtt::new(att_raw, false).expect("BtAtt::new failed");

    // Set ATT security level to MEDIUM (matches C test: bt_att_set_security(att, BT_ATT_SECURITY_MEDIUM))
    {
        let mut att_guard = att.lock().unwrap();
        att_guard.set_security(BT_ATT_SECURITY_MEDIUM as i32);
    }

    // Set ATT transport on BASS (server-only mode, no client).
    bass.set_att(Arc::clone(&att));

    // Create GATT server.
    let server = BtGattServer::new(db, Arc::clone(&att), BASS_GATT_CLIENT_MTU, 0)
        .expect("BtGattServer::new failed");

    BassServerContext {
        _rt: rt,
        handle,
        att,
        _server: server,
        _bass: bass,
        peer: fd2,
        att_fd: fd1,
        _ccc_states: ccc_states,
    }
}

// ============================================================================
// PDU Construction Helpers
// ============================================================================

/// Build an ATT Read By Group Type Request PDU.
fn make_read_by_group_type(start: u16, end: u16, uuid: &[u8; 2]) -> Vec<u8> {
    vec![
        ATT_OP_READ_BY_GRP_TYPE_REQ,
        (start & 0xFF) as u8,
        (start >> 8) as u8,
        (end & 0xFF) as u8,
        (end >> 8) as u8,
        uuid[0],
        uuid[1],
    ]
}

/// Build an ATT Read By Type Request PDU.
fn make_read_by_type(start: u16, end: u16, uuid: &[u8; 2]) -> Vec<u8> {
    vec![
        ATT_OP_READ_BY_TYPE_REQ,
        (start & 0xFF) as u8,
        (start >> 8) as u8,
        (end & 0xFF) as u8,
        (end >> 8) as u8,
        uuid[0],
        uuid[1],
    ]
}

/// Build an ATT Find By Type Value Request PDU.
fn make_find_by_type_value(start: u16, end: u16, attr_type: &[u8; 2], value: &[u8]) -> Vec<u8> {
    let mut pdu = vec![
        ATT_OP_FIND_BY_TYPE_REQ,
        (start & 0xFF) as u8,
        (start >> 8) as u8,
        (end & 0xFF) as u8,
        (end >> 8) as u8,
        attr_type[0],
        attr_type[1],
    ];
    pdu.extend_from_slice(value);
    pdu
}

/// Build an ATT Find Information Request PDU.
fn make_find_info(start: u16, end: u16) -> Vec<u8> {
    vec![
        ATT_OP_FIND_INFO_REQ,
        (start & 0xFF) as u8,
        (start >> 8) as u8,
        (end & 0xFF) as u8,
        (end >> 8) as u8,
    ]
}

/// Build an ATT Read Request PDU.
fn make_read_request(handle: u16) -> Vec<u8> {
    vec![ATT_OP_READ_REQ, (handle & 0xFF) as u8, (handle >> 8) as u8]
}

/// Build an ATT Write Request PDU.
fn make_write_request(handle: u16, value: &[u8]) -> Vec<u8> {
    let mut pdu = vec![ATT_OP_WRITE_REQ, (handle & 0xFF) as u8, (handle >> 8) as u8];
    pdu.extend_from_slice(value);
    pdu
}

/// Build an ATT Write Command PDU.
fn make_write_command(handle: u16, value: &[u8]) -> Vec<u8> {
    let mut pdu = vec![ATT_OP_WRITE_CMD, (handle & 0xFF) as u8, (handle >> 8) as u8];
    pdu.extend_from_slice(value);
    pdu
}

/// Assert that a response is an ATT Error Response with the expected fields.
fn assert_error_response(rsp: &[u8], req_opcode: u8, handle: u16, error_code: u8, msg: &str) {
    assert!(rsp.len() >= 5, "{msg}: response too short ({} bytes)", rsp.len());
    assert_eq!(rsp[0], ATT_OP_ERROR_RSP, "{msg}: expected error response opcode 0x01");
    assert_eq!(rsp[1], req_opcode, "{msg}: wrong request opcode in error");
    let rsp_handle = u16::from_le_bytes([rsp[2], rsp[3]]);
    assert_eq!(rsp_handle, handle, "{msg}: wrong handle in error");
    assert_eq!(rsp[4], error_code, "{msg}: wrong error code");
}

// ============================================================================
// Common Discovery Sequences
// ============================================================================

/// Perform ATT MTU Exchange: send MTU request, verify MTU response.
fn do_mtu_exchange(ctx: &BassServerContext) {
    let _guard = ctx.handle.enter();
    // ATT: Exchange MTU Request (0x02) len 2 — Client RX MTU: 64
    let rsp = server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &[ATT_OP_MTU_REQ, 0x40, 0x00]);
    assert!(!rsp.is_empty(), "MTU response empty");
    assert_eq!(rsp[0], ATT_OP_MTU_RSP, "Expected MTU Response opcode 0x03");
}

/// Perform BASS Find By Type Value discovery:
/// Find BASS primary service (0x184F), then search past service end.
///
/// Returns the service end handle found in the first response.
fn do_bass_find_by_type_value(ctx: &BassServerContext) -> u16 {
    let _guard = ctx.handle.enter();
    // Find By Type Value Request: Primary Service (0x2800) = BASS (0x184F)
    // handle range 0x0001-0xFFFF
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_find_by_type_value(0x0001, 0xFFFF, &PRIMARY_SERVICE_UUID_LE, &BASS_UUID_LE),
    );
    assert!(!rsp1.is_empty(), "Find By Type Value response empty");
    assert_eq!(rsp1[0], ATT_OP_FIND_BY_TYPE_RSP, "Expected Find By Type Value Response");
    // Extract end handle from response (bytes [3..5] = end handle LE)
    assert!(rsp1.len() >= 5, "Find By Type Value response too short");
    let end_handle = u16::from_le_bytes([rsp1[3], rsp1[4]]);

    // Search past the service end
    let next_start = end_handle + 1;
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_find_by_type_value(next_start, 0xFFFF, &PRIMARY_SERVICE_UUID_LE, &BASS_UUID_LE),
    );
    assert_error_response(
        &rsp2,
        ATT_OP_FIND_BY_TYPE_REQ,
        next_start,
        ATT_ERROR_ATTRIBUTE_NOT_FOUND,
        "No more BASS services",
    );

    end_handle
}

/// Perform BASS characteristic discovery via Read By Type (0x2803).
fn do_bass_char_discovery(ctx: &BassServerContext) {
    let _guard = ctx.handle.enter();
    // Read By Type Request: Characteristic (0x2803) in BASS handle range
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_read_by_type(0x0001, 0x0009, &CHARACTERISTIC_UUID_LE),
    );
    assert!(!rsp1.is_empty(), "BASS char discovery response empty");
    assert_eq!(rsp1[0], ATT_OP_READ_BY_TYPE_RSP, "Expected Read By Type Response");

    // Continue search from last handle — should get Attribute Not Found
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_read_by_type(0x0009, 0x0009, &CHARACTERISTIC_UUID_LE),
    );
    assert_error_response(
        &rsp2,
        ATT_OP_READ_BY_TYPE_REQ,
        0x0009,
        ATT_ERROR_ATTRIBUTE_NOT_FOUND,
        "No more BASS characteristics",
    );
}

/// Perform CCC descriptor discovery via Find Information for both BRS handles.
fn do_bass_find_info(ctx: &BassServerContext) {
    let _guard = ctx.handle.enter();
    // Find Information for CCC of BRS #1 (handle 0x0004)
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_find_info(BASS_BRS1_CCC_HANDLE, BASS_BRS1_CCC_HANDLE),
    );
    assert!(!rsp1.is_empty(), "Find Info BRS1 CCC response empty");
    assert_eq!(rsp1[0], ATT_OP_FIND_INFO_RSP, "Expected Find Info Response for BRS1 CCC");

    // Find Information for CCC of BRS #2 (handle 0x0007)
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_find_info(BASS_BRS2_CCC_HANDLE, BASS_BRS2_CCC_HANDLE),
    );
    assert!(!rsp2.is_empty(), "Find Info BRS2 CCC response empty");
    assert_eq!(rsp2[0], ATT_OP_FIND_INFO_RSP, "Expected Find Info Response for BRS2 CCC");
}

/// Read CCC descriptors for both BRS characteristics (returns 0x0000 = disabled).
fn do_bass_read_char_desc(ctx: &BassServerContext) {
    let _guard = ctx.handle.enter();
    // Read CCC for BRS #1
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_read_request(BASS_BRS1_CCC_HANDLE),
    );
    assert!(!rsp1.is_empty(), "CCC read BRS1 empty");
    assert_eq!(rsp1[0], ATT_OP_READ_RSP, "Expected Read Response for BRS1 CCC");

    // Read CCC for BRS #2
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_read_request(BASS_BRS2_CCC_HANDLE),
    );
    assert!(!rsp2.is_empty(), "CCC read BRS2 empty");
    assert_eq!(rsp2[0], ATT_OP_READ_RSP, "Expected Read Response for BRS2 CCC");
}

/// Write CCC descriptors to enable notifications (0x0001) for both BRS.
fn do_bass_write_char_desc(ctx: &BassServerContext) {
    let _guard = ctx.handle.enter();
    // Write CCC for BRS #1 = 0x0001 (notifications enabled)
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(BASS_BRS1_CCC_HANDLE, &[0x01, 0x00]),
    );
    assert!(!rsp1.is_empty(), "CCC write BRS1 response empty");
    assert_eq!(rsp1[0], ATT_OP_WRITE_RSP, "Expected Write Response for BRS1 CCC");

    // Write CCC for BRS #2 = 0x0001 (notifications enabled)
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(BASS_BRS2_CCC_HANDLE, &[0x01, 0x00]),
    );
    assert!(!rsp2.is_empty(), "CCC write BRS2 response empty");
    assert_eq!(rsp2[0], ATT_OP_WRITE_RSP, "Expected Write Response for BRS2 CCC");
}

/// Read Broadcast Receive State characteristics (handles 0x0003, 0x0006).
/// Both should return empty (no source configured).
fn do_bass_read_bcast_recv_state(ctx: &BassServerContext) {
    let _guard = ctx.handle.enter();
    // Read BRS #1 value (handle 0x0003)
    let rsp1 = server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &make_read_request(0x0003));
    assert!(!rsp1.is_empty(), "BRS #1 read response empty");
    assert_eq!(rsp1[0], ATT_OP_READ_RSP, "Expected Read Response for BRS #1");

    // Read BRS #2 value (handle 0x0006)
    let rsp2 = server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &make_read_request(0x0006));
    assert!(!rsp2.is_empty(), "BRS #2 read response empty");
    assert_eq!(rsp2[0], ATT_OP_READ_RSP, "Expected Read Response for BRS #2");
}

/// Common preamble for SPE tests: MTU exchange, service discovery,
/// characteristic discovery, CCC descriptor discovery, CCC write (enable
/// notifications), and Broadcast Receive State reads.
fn do_spe_preamble(ctx: &BassServerContext) {
    do_mtu_exchange(ctx);
    do_bass_find_by_type_value(ctx);
    do_bass_char_discovery(ctx);
    do_bass_find_info(ctx);
    do_bass_write_char_desc(ctx);
    do_bass_read_bcast_recv_state(ctx);
}

// ============================================================================
// Test Cases — SGGIT (Service GGIT)
// ============================================================================

/// BASS/SR/SGGIT/SER/BV-01-C [Service GGIT - Broadcast Scan]
///
/// For each ATT_Read_By_Group_Type_Request, the IUT sends a correctly
/// formatted ATT_Read_By_Group_Type_Response reporting BASS to the
/// Lower Tester, or an ATT_Error_Response if there is no handle/UUID
/// pair matching the request.
///
/// For each ATT_Find_By_Type_Value_Request, the IUT sends one
/// ATT_Find_By_Type_Value_Response reporting BASS to the Lower Tester,
/// or an ATT_Error_Response when there are no more services matching
/// the request.
///
/// The IUT sends one ATT_Read_By_Type_Response to the Lower Tester for
/// each received ATT_Read_By_Type_Request, if it has characteristic
/// declarations within the handle range, or an ATT_Error_Response if
/// there are no further characteristic declarations within the
/// handle range of the request. The IUT reports all BASS characteristics.
#[test]
fn bass_sr_sggit_ser_bv_01_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // EXCHANGE_MTU
    do_mtu_exchange(&ctx);

    // Read By Group Type for Primary Service (0x2800) — discover BASS
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_read_by_group_type(0x0001, 0xFFFF, &PRIMARY_SERVICE_UUID_LE),
    );
    assert!(!rsp1.is_empty(), "Primary service response empty");
    assert_eq!(rsp1[0], ATT_OP_READ_BY_GRP_TYPE_RSP, "Expected Read By Group Type Response");

    // Continue search past BASS service end
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_read_by_group_type(BASS_SERVICE_END, 0xFFFF, &PRIMARY_SERVICE_UUID_LE),
    );
    assert_error_response(
        &rsp2,
        ATT_OP_READ_BY_GRP_TYPE_REQ,
        BASS_SERVICE_END,
        ATT_ERROR_ATTRIBUTE_NOT_FOUND,
        "No more primary services",
    );

    // BASS_FIND_BY_TYPE_VALUE
    do_bass_find_by_type_value(&ctx);

    // DISC_BASS_CHAR
    do_bass_char_discovery(&ctx);
}

/// BASS/SR/SGGIT/CHA/BV-01-C [Service GGIT - Broadcast Audio Scan Control Point]
///
/// The IUT sends one ATT_Read_By_Type_Response to the Lower Tester for
/// each received ATT_Read_By_Type_Request, if it has characteristic
/// declarations within the handle range, or an ATT_Error_Response if
/// there are no further characteristic declarations within the
/// handle range of the request. The IUT reports one instance of the
/// Broadcast Audio Scan Control Point characteristic.
#[test]
fn bass_sr_sggit_cha_bv_01_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // BASS_FIND_BY_TYPE_VALUE
    do_bass_find_by_type_value(&ctx);

    // DISC_BASS_CHAR
    do_bass_char_discovery(&ctx);

    // BASS_FIND_INFO
    do_bass_find_info(&ctx);
}

/// BASS/SR/SGGIT/CHA/BV-02-C [Service GGIT - Broadcast Receive State]
///
/// The IUT sends one ATT_Read_By_Type_Response to the Lower Tester for
/// each received ATT_Read_By_Type_Request, if it has characteristic
/// declarations within the handle range, or an ATT_Error_Response if
/// there are no further characteristic declarations within the
/// handle range of the request. The IUT reports two instances of the
/// Broadcast Receive State characteristic.
///
/// The IUT sends one ATT_Find_Information_Response to the Lower Tester
/// for each received ATT_Find_Information_Request, if it has
/// characteristic descriptors within the handle range, or an
/// ATT_Error_Response if there are no characteristic descriptors within
/// the handle range of the request. For each Broadcast Receive State
/// characteristic, the IUT reports one Client Characteristic
/// Configuration descriptor.
///
/// The IUT sends an ATT_Read_Response to the Lower Tester for each
/// ATT_Read_Request.
#[test]
fn bass_sr_sggit_cha_bv_02_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // DISC_BCAST_AUDIO_SCAN_CP = BASS_FIND_BY_TYPE_VALUE + DISC_BASS_CHAR + BASS_FIND_INFO
    do_bass_find_by_type_value(&ctx);
    do_bass_char_discovery(&ctx);
    do_bass_find_info(&ctx);

    // BASS_READ_CHAR_DESC
    do_bass_read_char_desc(&ctx);
}

// ============================================================================
// Test Cases — SPE (Special Procedures and Error Handling)
// ============================================================================

/// BASS/SR/SPE/BI-01-C [Ignore Invalid Source ID]
///
/// Verify that the BASS Server IUT does not respond to a control point
/// procedure call that uses an invalid Source_ID parameter.
///
/// The IUT does not send a notification of the Broadcast Receive State
/// characteristic.
#[test]
fn bass_sr_spe_bi_01_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // Common SPE preamble: MTU + discovery + CCC write + BRS read
    do_spe_preamble(&ctx);

    // Set Broadcast_Code with invalid Source_ID = 1 (Write Command — no response)
    // Opcode 0x04, Source_ID=1, Broadcast_Code=0x55542773705965346126556872453c69
    let set_bcode_cmd: Vec<u8> = make_write_command(
        BASS_CP_HANDLE,
        &[
            0x04, 0x01, 0x69, 0x3C, 0x45, 0x72, 0x68, 0x55, 0x26, 0x61, 0x34, 0x65, 0x59, 0x70,
            0x73, 0x27, 0x54, 0x55,
        ],
    );
    server_write_cmd(&ctx.att, &ctx.att_fd, &ctx.peer, &set_bcode_cmd);
    // No response expected — verify no notification arrives.
    let unexpected = try_read(&ctx.peer, 50);
    assert!(
        unexpected.is_none(),
        "No response/notification expected for Set Broadcast_Code with invalid Source_ID"
    );

    // Remove Source with invalid Source_ID = 1 (Write Command — no response)
    // Opcode 0x05, Source_ID=1
    let remove_cmd = make_write_command(BASS_CP_HANDLE, &[0x05, 0x01]);
    server_write_cmd(&ctx.att, &ctx.att_fd, &ctx.peer, &remove_cmd);
    // No response expected for Write Command.
    let unexpected2 = try_read(&ctx.peer, 50);
    assert!(
        unexpected2.is_none(),
        "No response/notification expected for Remove Source with invalid Source_ID"
    );
}

/// BASS/SR/SPE/BI-03-C [Add Source - Ignore Invalid Values]
///
/// Verify that the BASS Server IUT ignores Add Source control point
/// procedure calls that include an RFU or Invalid parameter.
///
/// The IUT does not send a notification of the Broadcast Receive State
/// characteristic.
#[test]
fn bass_sr_spe_bi_03_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // Common SPE preamble
    do_spe_preamble(&ctx);

    // Add Source #1: PA_Sync=0x06 (RFU), addr_type=0x00 (public)
    // Should be ignored — no notification.
    let add_src_1 = make_write_command(
        BASS_CP_HANDLE,
        &[
            0x02, 0x00, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, 0x00, 0x34, 0x12, 0x00, 0x06, 0x10,
            0x27, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    server_write_cmd(&ctx.att, &ctx.att_fd, &ctx.peer, &add_src_1);
    let unexpected1 = try_read(&ctx.peer, 50);
    assert!(unexpected1.is_none(), "No notification expected for Add Source with RFU PA_Sync=0x06");

    // Add Source #2: addr_type=0x05 (RFU), PA_Sync=0x02
    // Should be ignored — no notification.
    let add_src_2 = make_write_command(
        BASS_CP_HANDLE,
        &[
            0x02, 0x05, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, 0x00, 0x34, 0x12, 0x00, 0x02, 0x10,
            0x27, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    server_write_cmd(&ctx.att, &ctx.att_fd, &ctx.peer, &add_src_2);
    let unexpected2 = try_read(&ctx.peer, 50);
    assert!(
        unexpected2.is_none(),
        "No notification expected for Add Source with RFU addr_type=0x05"
    );

    // Add Source #3: addr_type=0x05 (RFU), SID=0x3F (invalid)
    // Should be ignored — no notification.
    let add_src_3 = make_write_command(
        BASS_CP_HANDLE,
        &[
            0x02, 0x05, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, 0x3F, 0x34, 0x12, 0x00, 0x02, 0x10,
            0x27, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    server_write_cmd(&ctx.att, &ctx.att_fd, &ctx.peer, &add_src_3);
    let unexpected3 = try_read(&ctx.peer, 50);
    assert!(unexpected3.is_none(), "No notification expected for Add Source with invalid SID=0x3F");

    // Add Source #4: valid params with BIS_Sync=0x00000001 for both subgroups
    // This one has valid params so it might succeed — still a write command.
    let add_src_4 = make_write_command(
        BASS_CP_HANDLE,
        &[
            0x02, 0x00, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, 0x00, 0x34, 0x12, 0x00, 0x02, 0x10,
            0x27, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    server_write_cmd(&ctx.att, &ctx.att_fd, &ctx.peer, &add_src_4);
    // Drain any potential notification (valid add source may generate one).
    let _ = try_read(&ctx.peer, 50);
}

/// BASS/SR/SPE/BI-04-C [Opcode Not Supported]
///
/// Verify that the BASS Server IUT returns an Opcode Not Supported error
/// response when the opcode written is not supported by the IUT or is
/// within a range that is reserved for future use being written to the
/// Broadcast Audio Scan Control Point.
///
/// The IUT sends an error response of OPCODE NOT SUPPORTED.
#[test]
fn bass_sr_spe_bi_04_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // Common SPE preamble
    do_spe_preamble(&ctx);

    // Write Request with opcode 0xFF (Reserved/unsupported)
    let rsp = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(BASS_CP_HANDLE, &[0xFF]),
    );
    assert_error_response(
        &rsp,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        BASS_ERROR_OPCODE_NOT_SUPPORTED,
        "Opcode 0xFF should return Opcode Not Supported",
    );
}

/// BASS/SR/SPE/BI-06-C [Invalid Length]
///
/// Verify that the BASS Server IUT rejects writing of an opcode with
/// an invalid length.
///
/// The IUT rejects the opcode with Write Request Rejected (0xFC).
#[test]
fn bass_sr_spe_bi_06_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // Common SPE preamble
    do_spe_preamble(&ctx);

    // 1. Remote Scan Stopped (opcode 0x00) with extra data → 0xFC
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(BASS_CP_HANDLE, &[0x00, 0x6D, 0xFE]),
    );
    assert_error_response(
        &rsp1,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        ATT_ERROR_WRITE_REQUEST_REJECTED,
        "Remote Scan Stopped with extra data",
    );

    // 2. Remote Scan Started (opcode 0x01) with extra data → 0xFC
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(BASS_CP_HANDLE, &[0x01, 0xC2, 0xA2]),
    );
    assert_error_response(
        &rsp2,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        ATT_ERROR_WRITE_REQUEST_REJECTED,
        "Remote Scan Started with extra data",
    );

    // 3. Add Source (opcode 0x02) with extra data after subgroups → 0xFC
    let rsp3 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(
            BASS_CP_HANDLE,
            &[
                0x02, 0x00, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, 0x00, 0x34, 0x12, 0x00, 0x02, 0x10,
                0x27, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        ),
    );
    assert_error_response(
        &rsp3,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        ATT_ERROR_WRITE_REQUEST_REJECTED,
        "Add Source with extra data",
    );

    // 4. Modify Source (opcode 0x03) with extra data → 0xFC
    let rsp4 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(
            BASS_CP_HANDLE,
            &[0x03, 0x00, 0x02, 0x10, 0x27, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00],
        ),
    );
    assert_error_response(
        &rsp4,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        ATT_ERROR_WRITE_REQUEST_REJECTED,
        "Modify Source with extra data",
    );

    // 5. Set Broadcast_Code (opcode 0x04) with extra data → 0xFC
    let rsp5 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(
            BASS_CP_HANDLE,
            &[
                0x04, 0x00, 0xB8, 0x03, 0xEA, 0xC6, 0xAF, 0xBB, 0x65, 0xA2, 0x5A, 0x41, 0xF1, 0x53,
                0x05, 0x68, 0x02, 0x01, 0x00, 0x00,
            ],
        ),
    );
    assert_error_response(
        &rsp5,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        ATT_ERROR_WRITE_REQUEST_REJECTED,
        "Set Broadcast_Code with extra data",
    );

    // 6. Remove Source (opcode 0x05) with extra data → 0xFC
    let rsp6 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(BASS_CP_HANDLE, &[0x05, 0x00, 0x8F, 0x13]),
    );
    assert_error_response(
        &rsp6,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        ATT_ERROR_WRITE_REQUEST_REJECTED,
        "Remove Source with extra data",
    );
}

/// BASS/SR/SPE/BI-07-C [Invalid Source ID]
///
/// Verify that the BASS Server IUT returns an error when a control
/// point procedure passing an invalid Source_ID parameter is called.
///
/// The IUT sends an ATT Error Response with the Error Code set to
/// Invalid Source_ID (0x81).
#[test]
fn bass_sr_spe_bi_07_c() {
    let ctx = create_bass_server();
    let _guard = ctx.handle.enter();

    // Common SPE preamble
    do_spe_preamble(&ctx);

    // Set Broadcast_Code with Source_ID=5 (invalid) via Write Request
    let rsp1 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(
            BASS_CP_HANDLE,
            &[
                0x04, 0x05, 0xB8, 0x03, 0xEA, 0xC6, 0xAF, 0xBB, 0x65, 0xA2, 0x5A, 0x41, 0xF1, 0x53,
                0x05, 0x68, 0x02, 0x01,
            ],
        ),
    );
    assert_error_response(
        &rsp1,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        BASS_ERROR_INVALID_SOURCE_ID,
        "Set Broadcast_Code with invalid Source_ID=5",
    );

    // Remove Source with Source_ID=5 (invalid) via Write Request
    let rsp2 = server_exchange_vec(
        &ctx.att,
        &ctx.att_fd,
        &ctx.peer,
        &make_write_request(BASS_CP_HANDLE, &[0x05, 0x05]),
    );
    assert_error_response(
        &rsp2,
        ATT_OP_WRITE_REQ,
        BASS_CP_HANDLE,
        BASS_ERROR_INVALID_SOURCE_ID,
        "Remove Source with invalid Source_ID=5",
    );
}
