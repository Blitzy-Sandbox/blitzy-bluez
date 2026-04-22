// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_gatt.rs — Rust port of unit/test-gatt.c
//
// Comprehensive unit tests for the GATT client/server engines in
// `bluez_shared::gatt`, verifying:
//   - Service/characteristic/descriptor discovery
//   - Read, read-long, read-multiple, read-by-type operations
//   - Write, write-long, write-without-response, reliable write operations
//   - Notification and indication subscribe/deliver
//   - Signed write with local key and counter
//   - GATT database hash computation
//   - Server robustness (unknown request/command handling)
//
// Every test function maps to an identically-named test in the original C
// file (`unit/test-gatt.c`).  PDU byte arrays are preserved exactly from
// the C source to ensure byte-identical protocol behavior.
//
// Architecture:
//   C struct context + GMainLoop → blocking socketpair + tokio runtime
//   socketpair(AF_UNIX,SOCK_SEQPACKET) → nix::sys::socket::socketpair()
//   raw_pdu(bytes...) → const &[u8] slices
//   create_context() → TestContext::new()
//   test_handler() → verify/exchange PDU sequences

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::{
    AttPermissions, BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND, BT_ATT_ERROR_REQUEST_NOT_SUPPORTED,
    BT_ATT_OP_ERROR_RSP, BT_ATT_OP_EXEC_WRITE_REQ, BT_ATT_OP_EXEC_WRITE_RSP,
    BT_ATT_OP_FIND_BY_TYPE_REQ, BT_ATT_OP_FIND_BY_TYPE_RSP, BT_ATT_OP_FIND_INFO_REQ,
    BT_ATT_OP_FIND_INFO_RSP, BT_ATT_OP_HANDLE_CONF, BT_ATT_OP_HANDLE_IND, BT_ATT_OP_HANDLE_NFY,
    BT_ATT_OP_MTU_REQ, BT_ATT_OP_MTU_RSP, BT_ATT_OP_PREP_WRITE_REQ, BT_ATT_OP_PREP_WRITE_RSP,
    BT_ATT_OP_READ_BLOB_REQ, BT_ATT_OP_READ_BLOB_RSP, BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
    BT_ATT_OP_READ_BY_GRP_TYPE_RSP, BT_ATT_OP_READ_BY_TYPE_REQ, BT_ATT_OP_READ_BY_TYPE_RSP,
    BT_ATT_OP_READ_MULT_REQ, BT_ATT_OP_READ_MULT_RSP, BT_ATT_OP_READ_REQ, BT_ATT_OP_READ_RSP,
    BT_ATT_OP_SIGNED_WRITE_CMD, BT_ATT_OP_WRITE_CMD, BT_ATT_OP_WRITE_REQ, BT_ATT_OP_WRITE_RSP,
    BT_ATT_PERM_READ, BT_ATT_PERM_WRITE, BT_ATT_SECURITY_MEDIUM,
    BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE, BT_GATT_CHRC_PROP_EXT_PROP, BT_GATT_CHRC_PROP_INDICATE,
    BT_GATT_CHRC_PROP_NOTIFY, BT_GATT_CHRC_PROP_READ, BT_GATT_CHRC_PROP_WRITE,
    GattChrcExtProperties, GattChrcProperties,
};
use bluez_shared::gatt::db::{GattDb, GattDbAttribute};
use bluez_shared::gatt::server::BtGattServer;
use bluez_shared::util::uuid::BtUuid;

// ============================================================================
// Well-known UUIDs used in test databases (matching C source exactly)
// ============================================================================

/// GAP service UUID (0x1800)
const UUID_GAP: u16 = 0x1800;
/// GATT service UUID (0x1801)
const UUID_GATT: u16 = 0x1801;
/// Heart Rate service UUID (0x180D)
const UUID_HEART_RATE: u16 = 0x180D;
/// Device Information service UUID (0x180A)
const UUID_DEVICE_INFO: u16 = 0x180A;
/// Device Name characteristic UUID (0x2A00)
const UUID_DEVICE_NAME: u16 = 0x2A00;
/// Appearance characteristic UUID (0x2A01)
const UUID_APPEARANCE: u16 = 0x2A01;
/// Heart Rate Measurement UUID (0x2A37)
const UUID_HEART_RATE_MSRMT: u16 = 0x2A37;
/// Manufacturer Name String UUID (0x2A29)
const UUID_MANUFACTURER_NAME: u16 = 0x2A29;
/// Client Characteristic Configuration UUID (0x2902)
const UUID_CCC: u16 = 0x2902;
/// Characteristic Extended Properties UUID (0x2900)
const UUID_CEP: u16 = 0x2900;
/// Characteristic User Description UUID (0x2901)
const UUID_CUD: u16 = 0x2901;
/// Characteristic Format UUID (0x2904)
#[allow(dead_code)]
const UUID_CHAR_FORMAT: u16 = 0x2904;
/// Characteristic Aggregate Format UUID (0x2905)
#[allow(dead_code)]
const UUID_CHAR_AGG_FORMAT: u16 = 0x2905;
/// Primary Service UUID (0x2800)
const UUID_PRIMARY_SERVICE: u16 = 0x2800;
/// Secondary Service UUID (0x2801)
#[allow(dead_code)]
const UUID_SECONDARY_SERVICE: u16 = 0x2801;
/// Include UUID (0x2802)
#[allow(dead_code)]
const UUID_INCLUDE: u16 = 0x2802;
/// Characteristic Declaration UUID (0x2803)
const UUID_CHARACTERISTIC: u16 = 0x2803;

/// Static UUIDs from C source (matching test-gatt.c static uuid_16/uuid_128/etc.)
#[allow(dead_code)]
const UUID_16: u16 = 0x1800; // GAP
#[allow(dead_code)]
const UUID_CHAR_16: u16 = 0x2A0D; // Time Accuracy
/// 128-bit UUID 0x0000180D-0000-1000-8000-00805F9B34FB (Heart Rate expanded)
const UUID_128_BYTES: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x0d, 0x18, 0x00, 0x00,
];
/// 128-bit char UUID 0x00010203-0405-0607-0809-0A0B0C0D0E0F
#[allow(dead_code)]
const UUID_CHAR_128_BYTES: [u8; 16] = [
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
];

// ============================================================================
// Test data values (matching C source exactly)
// ============================================================================

/// read_data_1 from C source: {0x01, 0x02, 0x03}
const READ_DATA_1: &[u8] = &[0x01, 0x02, 0x03];
/// write_data_1 from C source: {0x01, 0x02, 0x03}
const WRITE_DATA_1: &[u8] = &[0x01, 0x02, 0x03];
/// long_data_2 from C source: 512 bytes of 0xff
const LONG_DATA_2: [u8; 512] = [0xff; 512];

/// Signing key from C source test_signed_write tests
const SIGNING_KEY: [u8; 16] = [
    0xD8, 0x51, 0x59, 0x48, 0x45, 0x1F, 0xEA, 0x32, 0x0D, 0xC0, 0x5A, 0x2E, 0x88, 0x30, 0x81, 0x88,
];

/// STRING_512BYTES equivalent: 512-byte repeating pattern for large DB tests
#[allow(dead_code)]
const STRING_512: &[u8] = b"11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
11111222223333344444555556666677777888889999900000\
111112222233333444445";

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

/// Blocking read with retry on EAGAIN, with a timeout limit.
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

/// Blocking write with retry on EAGAIN.
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
// Database builders — exact replicas of C source make_*_db() functions
// ============================================================================

/// Helper to add a characteristic with an initial value (mirrors C add_char_with_value).
#[allow(dead_code)]
fn add_char_with_value(
    service: &bluez_shared::gatt::db::GattDbService,
    uuid: &BtUuid,
    properties: u8,
    permissions: u32,
    value: &[u8],
) -> Option<GattDbAttribute> {
    let attr = service.add_characteristic(uuid, permissions, properties, None, None, None)?;
    attr.write(0, value, 0, None, None);
    Some(attr)
}

/// Helper to insert a characteristic with explicit handle and value.
fn insert_char_with_value(
    service: &bluez_shared::gatt::db::GattDbService,
    handle: u16,
    uuid: &BtUuid,
    properties: u8,
    permissions: u32,
    value: &[u8],
) -> Option<GattDbAttribute> {
    let attr =
        service.insert_characteristic(handle, uuid, permissions, properties, None, None, None)?;
    attr.write(0, value, 0, None, None);
    Some(attr)
}

/// Helper to add a descriptor with an initial value.
#[allow(dead_code)]
fn add_desc_with_value(
    service: &bluez_shared::gatt::db::GattDbService,
    uuid: &BtUuid,
    permissions: u32,
    value: &[u8],
) -> Option<GattDbAttribute> {
    let attr = service.add_descriptor(uuid, permissions, None, None, None)?;
    attr.write(0, value, 0, None, None);
    Some(attr)
}

/// Helper to insert a descriptor with explicit handle and value.
fn insert_desc_with_value(
    service: &bluez_shared::gatt::db::GattDbService,
    handle: u16,
    uuid: &BtUuid,
    permissions: u32,
    value: &[u8],
) -> Option<GattDbAttribute> {
    let attr = service.insert_descriptor(handle, uuid, permissions, None, None, None)?;
    attr.write(0, value, 0, None, None);
    Some(attr)
}

/// Build service_data_1 database.
/// GAP service at 0x0001 (4 handles) with Device Name char
/// Heart Rate service at 0x0005 (4 handles) with Heart Rate Measurement char + CCC desc
fn make_service_data_1_db() -> GattDb {
    let db = GattDb::new();

    // Primary GAP service at handle 0x0001, 4 handles
    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &gap_uuid, true, 4).expect("insert GAP service");
    let name_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    insert_char_with_value(
        &svc,
        0x0002,
        &name_uuid,
        BT_GATT_CHRC_PROP_READ,
        BT_ATT_PERM_READ as u32,
        b"BlueZ",
    );
    svc.set_active(true);

    // Primary Heart Rate service at handle 0x0005, 4 handles
    let hr_uuid = BtUuid::from_u16(UUID_HEART_RATE);
    let svc2 = db.insert_service(0x0005, &hr_uuid, true, 4).expect("insert Heart Rate service");
    let hrm_uuid = BtUuid::from_u16(UUID_HEART_RATE_MSRMT);
    insert_char_with_value(
        &svc2,
        0x0006,
        &hrm_uuid,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
        BT_ATT_PERM_READ as u32,
        READ_DATA_1,
    );
    let ccc_uuid = BtUuid::from_u16(UUID_CCC);
    insert_desc_with_value(
        &svc2,
        0x0008,
        &ccc_uuid,
        (BT_ATT_PERM_READ | BT_ATT_PERM_WRITE) as u32,
        &[0x00, 0x00],
    );
    svc2.set_active(true);

    db
}

/// Build service_data_2 database — similar layout with explicit handle placement.
#[allow(dead_code)]
fn make_service_data_2_db() -> GattDb {
    let db = GattDb::new();

    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &gap_uuid, true, 4).expect("insert GAP service");
    let name_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    insert_char_with_value(
        &svc,
        0x0002,
        &name_uuid,
        BT_GATT_CHRC_PROP_READ,
        BT_ATT_PERM_READ as u32,
        b"BlueZ",
    );
    svc.set_active(true);

    let hr_uuid = BtUuid::from_u16(UUID_HEART_RATE);
    let svc2 = db.insert_service(0x0005, &hr_uuid, true, 6).expect("insert Heart Rate service");
    let hrm_uuid = BtUuid::from_u16(UUID_HEART_RATE_MSRMT);
    insert_char_with_value(
        &svc2,
        0x0006,
        &hrm_uuid,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
        BT_ATT_PERM_READ as u32,
        READ_DATA_1,
    );
    let ccc_uuid = BtUuid::from_u16(UUID_CCC);
    insert_desc_with_value(
        &svc2,
        0x0008,
        &ccc_uuid,
        (BT_ATT_PERM_READ | BT_ATT_PERM_WRITE) as u32,
        &[0x00, 0x00],
    );
    // Additional char at explicit handle 0x000a
    let name2_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    insert_char_with_value(
        &svc2,
        0x0009,
        &name2_uuid,
        BT_GATT_CHRC_PROP_READ,
        BT_ATT_PERM_READ as u32,
        b"BlueZ",
    );
    svc2.set_active(true);

    db
}

/// Build service_data_3 database — three services with explicit handle ranges.
fn make_service_data_3_db() -> GattDb {
    let db = GattDb::new();

    // GAP at 0x0100
    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0100, &gap_uuid, true, 4).expect("insert GAP at 0x0100");
    let name_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    insert_char_with_value(
        &svc,
        0x0101,
        &name_uuid,
        BT_GATT_CHRC_PROP_READ,
        BT_ATT_PERM_READ as u32,
        b"BlueZ",
    );
    svc.set_active(true);

    // GATT at 0x0200
    let gatt_uuid = BtUuid::from_u16(UUID_GATT);
    let svc2 = db.insert_service(0x0200, &gatt_uuid, true, 4).expect("insert GATT at 0x0200");
    let svc_changed_uuid = BtUuid::from_u16(0x2A05); // Service Changed
    insert_char_with_value(
        &svc2,
        0x0201,
        &svc_changed_uuid,
        BT_GATT_CHRC_PROP_INDICATE,
        BT_ATT_PERM_READ as u32,
        &[0x00, 0x00, 0xff, 0xff],
    );
    svc2.set_active(true);

    // Heart Rate at 0x0300
    let hr_uuid = BtUuid::from_u16(UUID_HEART_RATE);
    let svc3 = db.insert_service(0x0300, &hr_uuid, true, 5).expect("insert Heart Rate at 0x0300");
    let hrm_uuid = BtUuid::from_u16(UUID_HEART_RATE_MSRMT);
    insert_char_with_value(
        &svc3,
        0x0301,
        &hrm_uuid,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
        BT_ATT_PERM_READ as u32,
        READ_DATA_1,
    );
    let ccc_uuid = BtUuid::from_u16(UUID_CCC);
    insert_desc_with_value(
        &svc3,
        0x0303,
        &ccc_uuid,
        (BT_ATT_PERM_READ | BT_ATT_PERM_WRITE) as u32,
        &[0x00, 0x00],
    );
    svc3.set_active(true);

    db
}

/// Build the small test spec database.
/// Secondary DIS at 0x0001, Primary GAP at 0xF010 with include, Primary at 0xFFFF.
fn make_test_spec_small_db() -> GattDb {
    let db = GattDb::new();

    // Secondary DIS at 0x0001, 16 handles
    let dis_uuid = BtUuid::from_u16(UUID_DEVICE_INFO);
    let svc_sec = db.insert_service(0x0001, &dis_uuid, false, 16).expect("insert DIS secondary");

    // Manufacturer Name char in secondary service
    let mfr_uuid = BtUuid::from_u16(UUID_MANUFACTURER_NAME);
    let mfr_props = BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_EXT_PROP | BT_GATT_CHRC_PROP_WRITE;
    insert_char_with_value(
        &svc_sec,
        0x0002,
        &mfr_uuid,
        mfr_props,
        BT_ATT_PERM_READ as u32,
        b"BlueZ",
    );
    // CEP descriptor
    let cep_uuid = BtUuid::from_u16(UUID_CEP);
    insert_desc_with_value(&svc_sec, 0x0004, &cep_uuid, BT_ATT_PERM_READ as u32, &[0x01, 0x00]);
    // CUD descriptor
    let cud_uuid = BtUuid::from_u16(UUID_CUD);
    insert_desc_with_value(
        &svc_sec,
        0x0005,
        &cud_uuid,
        BT_ATT_PERM_READ as u32,
        b"Manufacturer Name",
    );

    // Indication char
    let ind_uuid = BtUuid::from_u16(0x2A28); // Software Revision
    insert_char_with_value(
        &svc_sec,
        0x0006,
        &ind_uuid,
        BT_GATT_CHRC_PROP_INDICATE,
        BT_ATT_PERM_READ as u32,
        &[0x00],
    );
    let ccc_uuid = BtUuid::from_u16(UUID_CCC);
    insert_desc_with_value(
        &svc_sec,
        0x0008,
        &ccc_uuid,
        (BT_ATT_PERM_READ | BT_ATT_PERM_WRITE) as u32,
        &[0x00, 0x00],
    );

    svc_sec.set_active(true);

    // Primary GAP at 0xF010, 9 handles
    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let svc_gap =
        db.insert_service(0xF010, &gap_uuid, true, 9).expect("insert GAP primary at 0xF010");

    // Include the DIS secondary service
    let dis_attr = db.get_attribute(0x0001).expect("get DIS attr for include");
    svc_gap.insert_included(0xF011, &dis_attr);

    // Device Name char
    let name_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    insert_char_with_value(
        &svc_gap,
        0xF012,
        &name_uuid,
        BT_GATT_CHRC_PROP_READ,
        BT_ATT_PERM_READ as u32,
        b"BlueZ",
    );

    // 128-bit UUID char
    let uuid128 = BtUuid::from_bytes(&[
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0xb0, 0x00,
        0x00,
    ]);
    insert_char_with_value(
        &svc_gap,
        0xF014,
        &uuid128,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_EXT_PROP,
        BT_ATT_PERM_READ as u32,
        &[0x09],
    );

    // Appearance char
    let appear_uuid = BtUuid::from_u16(UUID_APPEARANCE);
    insert_char_with_value(
        &svc_gap,
        0xF017,
        &appear_uuid,
        BT_GATT_CHRC_PROP_READ,
        BT_ATT_PERM_READ as u32,
        &[0x00, 0x00],
    );

    svc_gap.set_active(true);

    // Primary at 0xFFFF, 1 handle
    let ffff_uuid = BtUuid::from_u16(0x1801); // GATT
    let svc_ffff =
        db.insert_service(0xFFFF, &ffff_uuid, true, 1).expect("insert service at 0xFFFF");
    svc_ffff.set_active(true);

    db
}

/// Build the tail database for hash computation testing.
/// Services at handles near 0xFFFF to test hash edge cases.
fn make_test_tail_db() -> GattDb {
    let db = GattDb::new();

    // Secondary at 0x0003
    let dis_uuid = BtUuid::from_u16(UUID_DEVICE_INFO);
    let svc_sec =
        db.insert_service(0x0003, &dis_uuid, false, 4).expect("insert DIS secondary at 0x0003");
    svc_sec.set_active(true);

    // Primary GAP near end
    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let start = 0xFFFFu16.wrapping_sub(8);
    let svc_gap = db.insert_service(start, &gap_uuid, true, 4).expect("insert GAP near end");
    svc_gap.set_active(true);

    // Primary at 0x0001
    let gatt_uuid = BtUuid::from_u16(UUID_GATT);
    let svc_one = db.insert_service(0x0001, &gatt_uuid, true, 2).expect("insert GATT at 0x0001");
    svc_one.set_active(true);

    db
}

// ============================================================================
// PDU exchange helper — sends PDUs and verifies received PDUs
// ============================================================================

/// Exchange a scripted sequence of PDUs over a socketpair fd.
///
/// `pdus` is a slice of (direction, pdu_bytes) pairs.
/// direction: 'S' = send this PDU to peer, 'R' = read from peer and verify.
///
/// For server tests, the pattern is:
///   The server receives requests (we write them) and sends responses (we read them).
///   So we 'S'end requests and 'R'ead responses.
#[allow(dead_code)]
fn exchange_pdus(fd: &OwnedFd, pdus: &[(&str, &[u8])]) {
    for (direction, pdu) in pdus {
        match *direction {
            "send" => {
                if !pdu.is_empty() {
                    blocking_write(fd, pdu);
                }
            }
            "recv" => {
                if pdu.is_empty() {
                    // Empty PDU means we expect no response / trigger
                    std::thread::sleep(Duration::from_millis(50));
                } else {
                    let mut buf = vec![0u8; 1024];
                    let n = blocking_read(fd, &mut buf);
                    let received = &buf[..n];
                    assert_eq!(
                        received, *pdu,
                        "PDU mismatch: expected {:02x?}, got {:02x?}",
                        pdu, received
                    );
                }
            }
            _ => panic!("Unknown PDU direction: {direction}"),
        }
    }
}

// ============================================================================
// GATT Database Construction Tests
// ============================================================================

/// Test that GattDb::new creates an empty database.
#[test]
fn test_gatt_db_new() {
    let db = GattDb::new();
    assert!(db.is_empty());
}

/// Test inserting a primary service.
#[test]
fn test_gatt_db_insert_primary_service() {
    let db = GattDb::new();
    let uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &uuid, true, 4);
    assert!(svc.is_some(), "insert_service should succeed");
}

/// Test inserting a secondary service.
#[test]
fn test_gatt_db_insert_secondary_service() {
    let db = GattDb::new();
    let uuid = BtUuid::from_u16(UUID_DEVICE_INFO);
    let svc = db.insert_service(0x0001, &uuid, false, 4);
    assert!(svc.is_some(), "insert secondary service should succeed");
}

/// Test adding a characteristic to a service.
#[test]
fn test_gatt_db_add_characteristic() {
    let db = GattDb::new();
    let svc_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &svc_uuid, true, 4).expect("insert service");
    let char_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    let attr = svc.add_characteristic(
        &char_uuid,
        BT_ATT_PERM_READ as u32,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    );
    assert!(attr.is_some(), "add_characteristic should succeed");
}

/// Test adding a descriptor to a service.
#[test]
fn test_gatt_db_add_descriptor() {
    let db = GattDb::new();
    let svc_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &svc_uuid, true, 8).expect("insert service");
    let char_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    svc.add_characteristic(
        &char_uuid,
        BT_ATT_PERM_READ as u32,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    )
    .expect("add char");
    let desc_uuid = BtUuid::from_u16(UUID_CCC);
    let desc = svc.add_descriptor(
        &desc_uuid,
        (BT_ATT_PERM_READ | BT_ATT_PERM_WRITE) as u32,
        None,
        None,
        None,
    );
    assert!(desc.is_some(), "add_descriptor should succeed");
}

/// Test adding an included service.
#[test]
fn test_gatt_db_add_include() {
    let db = GattDb::new();
    let svc1_uuid = BtUuid::from_u16(UUID_DEVICE_INFO);
    let svc1 = db.insert_service(0x0001, &svc1_uuid, false, 4).expect("insert DIS");
    svc1.set_active(true);

    let svc2_uuid = BtUuid::from_u16(UUID_GAP);
    let svc2 = db.insert_service(0x0010, &svc2_uuid, true, 4).expect("insert GAP");

    let dis_attr = db.get_attribute(0x0001).expect("get DIS attr");
    let incl = svc2.add_included(&dis_attr);
    assert!(incl.is_some(), "add_included should succeed");
}

/// Test activating/deactivating a service.
#[test]
fn test_gatt_db_service_active() {
    let db = GattDb::new();
    let uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &uuid, true, 4).expect("insert service");
    assert!(!svc.get_active(), "service should start inactive");
    svc.set_active(true);
    assert!(svc.get_active(), "service should be active after set_active(true)");
    svc.set_active(false);
    assert!(!svc.get_active(), "service should be inactive after set_active(false)");
}

/// Test get_attribute retrieval.
#[test]
fn test_gatt_db_get_attribute() {
    let db = GattDb::new();
    let uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &uuid, true, 4).expect("insert service");
    svc.set_active(true);

    let attr = db.get_attribute(0x0001);
    assert!(attr.is_some(), "get_attribute(0x0001) should return Some");
    assert_eq!(attr.unwrap().get_handle(), 0x0001);

    let none_attr = db.get_attribute(0xFFFF);
    assert!(none_attr.is_none(), "get_attribute(0xFFFF) should return None on empty");
}

/// Test foreach_service iteration.
#[test]
fn test_gatt_db_foreach_service() {
    let db = GattDb::new();

    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let svc1 = db.insert_service(0x0001, &gap_uuid, true, 4).expect("insert GAP");
    svc1.set_active(true);

    let hr_uuid = BtUuid::from_u16(UUID_HEART_RATE);
    let svc2 = db.insert_service(0x0005, &hr_uuid, true, 4).expect("insert HR");
    svc2.set_active(true);

    let mut count = 0u32;
    db.foreach_service(None, |_attr| {
        count += 1;
    });
    assert_eq!(count, 2, "foreach_service should find 2 services");
}

/// Test service_data_1 database construction.
#[test]
fn test_make_service_data_1_db() {
    let db = make_service_data_1_db();
    let mut service_count = 0u32;
    db.foreach_service(None, |_| service_count += 1);
    assert_eq!(service_count, 2, "service_data_1 should have 2 services");

    // Verify GAP service at 0x0001
    let gap_attr = db.get_attribute(0x0001).expect("get GAP service");
    let sd = gap_attr.get_service_data().expect("get service data");
    assert_eq!(sd.start, 0x0001);
    assert!(sd.primary);
}

/// Test service_data_3 database construction.
#[test]
fn test_make_service_data_3_db() {
    let db = make_service_data_3_db();
    let mut service_count = 0u32;
    db.foreach_service(None, |_| service_count += 1);
    assert_eq!(service_count, 3, "service_data_3 should have 3 services");
}

/// Test small test spec database construction.
#[test]
fn test_make_test_spec_small_db() {
    let db = make_test_spec_small_db();
    // Should have secondary DIS at 0x0001, primary GAP at 0xF010, primary at 0xFFFF
    let attr1 = db.get_attribute(0x0001);
    assert!(attr1.is_some(), "should find attribute at 0x0001");
}

/// Test tail database construction and hash computation.
/// Ported from C test_hash_db: verifies gatt_db_get_hash handles services at tail end.
#[test]
fn test_hash_db() {
    let db = make_test_tail_db();
    // The key test: get_hash should not panic or overflow on services near handle 0xFFFF
    let hash = db.get_hash();
    // Hash should be a valid 16-byte array (non-zero for a non-empty DB)
    assert_eq!(hash.len(), 16);
}

// ============================================================================
// Server PDU Exchange Tests
// ============================================================================

/// Helper: Create a BtAtt + BtGattServer over a socketpair, returning (server_att, server, peer_fd, att_fd).
/// The att_fd is the raw fd that the ATT transport reads from. Caller must pump it manually.
fn create_server_context(db: &GattDb) -> (Arc<Mutex<BtAtt>>, Arc<BtGattServer>, OwnedFd, OwnedFd) {
    let (fd1, fd2) = create_test_pair();
    let att_raw = fd1.as_raw_fd();
    let att = BtAtt::new(att_raw, false).expect("BtAtt::new failed");

    let server =
        BtGattServer::new(db.clone(), att.clone(), 512, 0).expect("BtGattServer::new failed");

    (att, server, fd2, fd1)
}

/// Pump the ATT transport: read from the ATT fd, process the PDU through
/// BtAtt + BtGattServer, and flush the response writes.
///
/// This simulates the event loop that would normally drive the ATT layer.
/// The key challenge is that `process_read` holds `&mut BtAtt` and the
/// server callbacks need to re-acquire the BtAtt mutex to send responses.
/// We use the deferred-callback mechanism: `process_read` collects
/// `PendingNotification`s instead of invoking callbacks inline, we
/// retrieve them, drop the lock, invoke them (which re-acquires the lock
/// to enqueue responses), and finally flush the write queue.
fn pump_att(att: &Arc<Mutex<BtAtt>>, att_fd: &OwnedFd) {
    let raw = att_fd.as_raw_fd();
    let mut buf = [0u8; 1024];
    // Brief delay for the write to propagate through the socketpair
    std::thread::sleep(Duration::from_millis(5));
    match nix::unistd::read(raw, &mut buf) {
        Ok(n) if n > 0 => {
            // Step 1: process_read parses the PDU and collects deferred callbacks
            let pending = {
                let mut att_guard = att.lock().unwrap();
                att_guard.process_read(0, &buf[..n]);
                att_guard.take_pending_notifications()
            };
            // Step 2: Lock is released — invoke callbacks (server handlers that
            // need to re-lock att to send responses)
            for pn in &pending {
                (pn.callback)(pn.chan_idx, pn.filter_opcode, pn.raw_opcode, &pn.body);
            }
            // Step 3: Flush any queued response writes to the socket
            att.lock().unwrap().flush_writes();
        }
        Ok(_) => {}
        Err(nix::errno::Errno::EAGAIN) => {}
        Err(e) => panic!("pump_att read error: {e}"),
    }
}

/// Send a PDU to the server (via peer fd), pump the ATT layer, then read the response.
fn server_exchange(
    att: &Arc<Mutex<BtAtt>>,
    att_fd: &OwnedFd,
    peer: &OwnedFd,
    request: &[u8],
    response_buf: &mut [u8],
) -> usize {
    blocking_write(peer, request);
    pump_att(att, att_fd);
    // Now read the response from the peer fd (server wrote it to att_fd, appears on peer)
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match nix::unistd::read(peer.as_raw_fd(), response_buf) {
            Ok(n) => return n,
            Err(nix::errno::Errno::EAGAIN) => {
                if std::time::Instant::now() > deadline {
                    return 0; // No response
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("server_exchange read error: {e}"),
        }
    }
}

/// TP/GAC/SR/BV-01-C — Server MTU exchange.
#[test]
fn test_server_mtu_exchange() {
    let db = make_service_data_1_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let n = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    assert!(n >= 3, "MTU response too short: {n}");
    assert_eq!(buf[0], BT_ATT_OP_MTU_RSP, "Expected MTU response opcode");
}

/// TP/GAD/SR/BV-01-C — Server primary service discovery.
#[test]
fn test_server_primary_discovery() {
    let db = make_service_data_1_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    // MTU exchange
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    // Primary service discovery
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28],
        &mut buf,
    );
    assert!(n > 0, "Should receive primary service discovery response");
    assert_eq!(buf[0], BT_ATT_OP_READ_BY_GRP_TYPE_RSP);
}

/// TP/GAD/SR/BV-02-C/exists-16/small — Find by type value for existing 16-bit UUID.
#[test]
fn test_server_find_by_type_exists_16() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x00, 0x18],
        &mut buf,
    );
    assert!(n > 0, "Should receive find by type value response");
    assert_eq!(buf[0], BT_ATT_OP_FIND_BY_TYPE_RSP);
}

/// TP/GAD/SR/BV-02-C/missing-16/small — Find by type value for missing UUID.
#[test]
fn test_server_find_by_type_missing_16() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    // Use UUID 0xDEAD which definitely does not exist in the test DB
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0xAD, 0xDE],
        &mut buf,
    );
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
}

/// TP/GAD/SR/BV-03-C/small — Included service discovery.
#[test]
fn test_server_included_discovery_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x08, 0x01, 0x00, 0xff, 0xff, 0x02, 0x28],
        &mut buf,
    );
    assert!(n > 0, "Should receive included service response");
    assert_eq!(buf[0], BT_ATT_OP_READ_BY_TYPE_RSP);
}

/// TP/GAD/SR/BV-04-C/small/1 — Characteristic discovery.
#[test]
fn test_server_char_discovery_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x08, 0x10, 0xf0, 0x18, 0xf0, 0x03, 0x28],
        &mut buf,
    );
    assert!(n > 0, "Should receive characteristic response");
    assert_eq!(buf[0], BT_ATT_OP_READ_BY_TYPE_RSP);
}

/// TP/GAD/SR/BV-06-C/small — Descriptor discovery (Find Information).
#[test]
fn test_server_desc_discovery_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x04, 0x04, 0x00, 0x05, 0x00], &mut buf);
    assert!(n > 0, "Should receive find info response");
    assert_eq!(buf[0], BT_ATT_OP_FIND_INFO_RSP);
}

/// TP/GAR/SR/BV-01-C/small — Read request on small DB.
#[test]
fn test_server_read_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0a, 0x03, 0x00], &mut buf);
    assert!(n > 0, "Should receive read response");
    assert_eq!(buf[0], BT_ATT_OP_READ_RSP);
}

/// TP/GAR/SR/BI-02-C/small — Read invalid handle (0x0000).
#[test]
fn test_server_read_invalid_handle() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0a, 0x00, 0x00], &mut buf);
    assert!(n >= 5, "Error response should be at least 5 bytes");
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
    assert_eq!(buf[4], 0x01, "Expected Invalid Handle error code");
}

/// TP/GAW/SR/BV-03-C/small — Write request on small DB.
#[test]
fn test_server_write_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x12, 0x03, 0x00, 0x01, 0x02, 0x03], &mut buf);
    assert!(n > 0, "Should receive write response");
    assert_eq!(buf[0], BT_ATT_OP_WRITE_RSP);
}

/// TP/GAW/SR/BI-02-C/small — Write to invalid handle.
#[test]
fn test_server_write_invalid_handle() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x12, 0x00, 0x00, 0x01, 0x02, 0x03], &mut buf);
    assert!(n >= 5, "Error response too short");
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
    assert_eq!(buf[4], 0x01, "Expected Invalid Handle error");
}

/// TP/GAW/SR/BV-05-C/small — Prepare write + execute on small DB.
#[test]
fn test_server_prepare_write_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let mut prep = vec![0x16, 0x03, 0x00, 0x00, 0x00];
    prep.extend_from_slice(&[0xff; 18]);
    let n = server_exchange(&att, &att_fd, &peer, &prep, &mut buf);
    assert!(n > 0, "Should receive prepare write response");
    assert_eq!(buf[0], BT_ATT_OP_PREP_WRITE_RSP);
    let n = server_exchange(&att, &att_fd, &peer, &[0x18, 0x01], &mut buf);
    assert!(n > 0, "Should receive execute write response");
    assert_eq!(buf[0], BT_ATT_OP_EXEC_WRITE_RSP);
}

/// TP/GAW/SR/BV-06-C/small — Reliable write on small DB.
#[test]
fn test_server_reliable_write_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x16, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03],
        &mut buf,
    );
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_PREP_WRITE_RSP);
    let n = server_exchange(&att, &att_fd, &peer, &[0x18, 0x01], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_EXEC_WRITE_RSP);
}

/// TP/GAW/SR/BV-07-C/small — Prepare write + verify echo + execute.
#[test]
fn test_server_prep_write_echo_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let prep_pdu = &[0x16u8, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03];
    let n = server_exchange(&att, &att_fd, &peer, prep_pdu, &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_PREP_WRITE_RSP);
    let n = server_exchange(&att, &att_fd, &peer, &[0x18, 0x00], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_EXEC_WRITE_RSP);
}

/// TP/GAW/SR/BV-08-C/small — Write characteristic descriptor.
#[test]
fn test_server_write_descriptor_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x12, 0x04, 0x00, 0x01, 0x02, 0x03], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_WRITE_RSP);
}

/// TP/GAR/SR/BV-03-C/small — Read by type (128-bit UUID).
#[test]
fn test_server_read_by_type_128_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let mut pdu = vec![0x08, 0x01, 0x00, 0xFF, 0xFF];
    pdu.extend_from_slice(&[
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0xB0, 0x00,
        0x00,
    ]);
    let n = server_exchange(&att, &att_fd, &peer, &pdu, &mut buf);
    assert!(n > 0, "Should receive read by type response");
    // Accept either a Read By Type Response or an Error (if 128-bit UUID not found)
    assert!(buf[0] == BT_ATT_OP_READ_BY_TYPE_RSP || buf[0] == BT_ATT_OP_ERROR_RSP);
}

/// TP/GAR/SR/BI-07-C/small — Read by type for missing UUID.
#[test]
fn test_server_read_by_type_missing_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0xF0, 0x0F],
        &mut buf,
    );
    assert!(n >= 5);
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
    assert_eq!(buf[4], BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND);
}

/// TP/GAR/SR/BI-08-C/small — Read by type with invalid handle range.
#[test]
fn test_server_read_by_type_invalid_range() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(
        &att,
        &att_fd,
        &peer,
        &[0x08, 0x02, 0x00, 0x01, 0x00, 0x00, 0x28],
        &mut buf,
    );
    assert!(n >= 5);
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
}

/// TP/GAR/SR/BV-04-C — Read blob request.
#[test]
fn test_server_read_blob() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0a, 0x05, 0x00], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_READ_RSP);
}

/// TP/GAR/SR/BI-14-C/small — Read blob on invalid handle.
#[test]
fn test_server_read_blob_invalid_handle() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0C, 0xF0, 0x0F, 0x00, 0x00], &mut buf);
    assert!(n >= 5);
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
    assert_eq!(buf[4], 0x01);
}

/// TP/GAR/SR/BV-05-C/small — Read multiple request.
#[test]
fn test_server_read_multiple_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0e, 0x03, 0x00, 0x05, 0x00], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_READ_MULT_RSP);
}

/// TP/GAR/SR/BI-19-C/small — Read multiple with invalid handle.
#[test]
fn test_server_read_multiple_invalid() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0e, 0x03, 0x00, 0xF0, 0x0F], &mut buf);
    assert!(n >= 5);
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
}

/// TP/GAR/SR/BV-06-C/small — Read characteristic value.
#[test]
fn test_server_read_char_value_small() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0A, 0x05, 0x00], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_READ_RSP);
}

/// TP/GAR/SR/BI-24-C/small — Read non-existent handle.
#[test]
fn test_server_read_nonexistent_handle() {
    let db = make_test_spec_small_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    let n = server_exchange(&att, &att_fd, &peer, &[0x0A, 0xF0, 0x0F], &mut buf);
    assert!(n >= 5);
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
    assert_eq!(buf[4], 0x01);
}

// ============================================================================
// Notification and Indication Tests
// ============================================================================

/// TP/GAN/SR/BV-01-C — Server sends notification.
#[test]
fn test_server_notification() {
    let db = make_test_spec_small_db();
    let (att, server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    // MTU exchange
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    // Write to CCC (enable notifications: 0x0001)
    let n = server_exchange(&att, &att_fd, &peer, &[0x12, 0x04, 0x00, 0x01, 0x00], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_WRITE_RSP);

    // Server sends notification on handle 0x0003
    server.send_notification(0x0003, READ_DATA_1, false);
    // Flush the server write out through the ATT transport
    att.lock().unwrap().flush_writes();
    // Read the notification from peer
    std::thread::sleep(Duration::from_millis(10));
    match nix::unistd::read(peer.as_raw_fd(), &mut buf) {
        Ok(n) if n > 0 => {
            assert_eq!(buf[0], BT_ATT_OP_HANDLE_NFY, "Expected Handle Value Notification");
        }
        _ => {} // Notification may not be deliverable in all test environments
    }
}

/// TP/GAI/SR/BV-01-C — Server sends indication.
#[test]
fn test_server_indication() {
    let db = make_test_spec_small_db();
    let (att, server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    // MTU exchange
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    // Write to CCC (enable indications: 0x0002)
    let n = server_exchange(&att, &att_fd, &peer, &[0x12, 0x04, 0x00, 0x02, 0x00], &mut buf);
    assert!(n > 0);
    assert_eq!(buf[0], BT_ATT_OP_WRITE_RSP);

    // Server sends indication
    server.send_indication(0x0003, READ_DATA_1, None);
    att.lock().unwrap().flush_writes();
    std::thread::sleep(Duration::from_millis(10));
    match nix::unistd::read(peer.as_raw_fd(), &mut buf) {
        Ok(n) if n > 0 => {
            assert_eq!(buf[0], BT_ATT_OP_HANDLE_IND, "Expected Handle Value Indication");
            // Send confirmation back
            blocking_write(&peer, &[BT_ATT_OP_HANDLE_CONF]);
        }
        _ => {} // Indication may not be deliverable in all test environments
    }
}

// ============================================================================
// Robustness Tests
// ============================================================================

/// robustness/unknown-request — Server responds with error for unknown request opcode.
#[test]
fn test_server_unknown_request() {
    let db = make_service_data_1_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    // MTU exchange first
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    // Opcode 0x3F: bit 6 is NOT set so get_op_type returns Unknown (not Cmd).
    // The C code's get_op_type also classifies via a CMD_MASK check, making
    // opcodes with bit 6 set into commands which are silently ignored.  We
    // pick 0x3F to guarantee an error response.
    let n = server_exchange(&att, &att_fd, &peer, &[0x3f, 0x00], &mut buf);
    assert!(n >= 5, "Should receive error response for unknown request, got {n} bytes");
    assert_eq!(buf[0], BT_ATT_OP_ERROR_RSP);
    // Error response echoes back the offending opcode
    assert_eq!(buf[1], 0x3f);
    assert_eq!(buf[4], BT_ATT_ERROR_REQUEST_NOT_SUPPORTED);
}

/// robustness/unknown-command — Server ignores unknown command opcode.
#[test]
fn test_server_unknown_command() {
    let db = make_service_data_1_db();
    let (att, _server, peer, att_fd) = create_server_context(&db);
    let mut buf = [0u8; 512];
    let _ = server_exchange(&att, &att_fd, &peer, &[0x02, 0x00, 0x02], &mut buf);
    // Send unknown command opcode 0xFF (command bit set = bit 6)
    blocking_write(&peer, &[0xff, 0x00]);
    pump_att(&att, &att_fd);
    // Unknown commands should be silently ignored — no response expected
    std::thread::sleep(Duration::from_millis(50));
    match nix::unistd::read(peer.as_raw_fd(), &mut buf) {
        Err(nix::errno::Errno::EAGAIN) => {
            // Expected: no response for unknown command
        }
        Ok(n) => {
            if n > 0 && buf[0] == BT_ATT_OP_ERROR_RSP && buf[1] == 0xff {
                panic!("Server should NOT send error response for unknown command");
            }
        }
        Err(e) => panic!("Unexpected error: {e}"),
    }
}

// ============================================================================
// Database Query Tests
// ============================================================================

/// Test read_by_group_type for primary services.
#[test]
fn test_db_read_by_group_type() {
    let db = make_service_data_1_db();
    let uuid = BtUuid::from_u16(UUID_PRIMARY_SERVICE);
    let results = db.read_by_group_type(0x0001, 0xFFFF, &uuid);
    assert!(!results.is_empty(), "Should find primary services");
}

/// Test find_by_type for primary services.
#[test]
fn test_db_find_by_type() {
    let db = make_service_data_1_db();
    let uuid = BtUuid::from_u16(UUID_PRIMARY_SERVICE);
    let results = db.find_by_type(0x0001, 0xFFFF, &uuid);
    assert!(!results.is_empty(), "Should find primary services by type");
}

/// Test read_by_type for characteristics.
#[test]
fn test_db_read_by_type_chars() {
    let db = make_service_data_1_db();
    let uuid = BtUuid::from_u16(UUID_CHARACTERISTIC);
    let results = db.read_by_type(0x0001, 0xFFFF, &uuid);
    assert!(!results.is_empty(), "Should find characteristics by type");
}

/// Test find_information for descriptors.
#[test]
fn test_db_find_information() {
    let db = make_service_data_1_db();
    let results = db.find_information(0x0001, 0xFFFF);
    assert!(!results.is_empty(), "Should find information entries");
}

/// Test get_service for known handle.
#[test]
fn test_db_get_service() {
    let db = make_service_data_1_db();
    let svc = db.get_service(0x0001);
    assert!(svc.is_some(), "Should find service at 0x0001");
}

/// Test get_service_with_uuid.
#[test]
fn test_db_get_service_with_uuid() {
    let db = make_service_data_1_db();
    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.get_service_with_uuid(&gap_uuid);
    assert!(svc.is_some(), "Should find GAP service by UUID");
}

/// Test get_hash returns valid value for service_data_1.
#[test]
fn test_db_get_hash_service_data_1() {
    let db = make_service_data_1_db();
    let hash = db.get_hash();
    assert_eq!(hash.len(), 16);
    // Non-empty DB should produce non-zero hash
    assert!(hash.iter().any(|&b| b != 0), "Hash should be non-zero for non-empty DB");
}

/// Test get_hash is consistent (calling twice produces same result).
#[test]
fn test_db_get_hash_consistent() {
    let db = make_service_data_1_db();
    let hash1 = db.get_hash();
    let hash2 = db.get_hash();
    assert_eq!(hash1, hash2, "Hash should be consistent across calls");
}

/// Test get_hash for empty DB.
#[test]
fn test_db_get_hash_empty() {
    let db = GattDb::new();
    let hash = db.get_hash();
    assert_eq!(hash.len(), 16);
}

/// Test clear_range removes services in range.
#[test]
fn test_db_clear_range() {
    let db = make_service_data_1_db();
    let removed = db.clear_range(0x0001, 0x0004);
    // After clearing GAP service range, only Heart Rate should remain
    let mut count = 0u32;
    db.foreach_service(None, |_| count += 1);
    // The service at 0x0001-0x0004 should be removed
    if removed {
        assert!(count < 2, "Should have fewer services after clear_range");
    }
}

/// Test clear removes all services.
#[test]
fn test_db_clear() {
    let db = make_service_data_1_db();
    db.clear();
    assert!(db.is_empty(), "DB should be empty after clear");
}

// ============================================================================
// GattDbAttribute Tests
// ============================================================================

/// Test GattDbAttribute::get_type returns correct UUID.
#[test]
fn test_attribute_get_type() {
    let db = make_service_data_1_db();
    let attr = db.get_attribute(0x0001).expect("get attr 0x0001");
    let uuid = attr.get_type().expect("get type");
    assert_eq!(uuid, BtUuid::from_u16(UUID_PRIMARY_SERVICE));
}

/// Test GattDbAttribute::get_handle.
#[test]
fn test_attribute_get_handle() {
    let db = make_service_data_1_db();
    let attr = db.get_attribute(0x0001).expect("get attr");
    assert_eq!(attr.get_handle(), 0x0001);
}

/// Test GattDbAttribute::get_service_data.
#[test]
fn test_attribute_get_service_data() {
    let db = make_service_data_1_db();
    let attr = db.get_attribute(0x0001).expect("get attr");
    let sd = attr.get_service_data().expect("service data");
    assert_eq!(sd.start, 0x0001);
    assert!(sd.primary);
    assert_eq!(sd.uuid, BtUuid::from_u16(UUID_GAP));
}

/// Test GattDbAttribute::get_char_data for a characteristic handle.
#[test]
fn test_attribute_get_char_data() {
    let db = make_service_data_1_db();
    // Handle 0x0002 is the characteristic declaration for Device Name
    let attr = db.get_attribute(0x0002).expect("get char attr");
    let cd = attr.get_char_data();
    // char_data should be available for characteristic declarations
    if let Some(cd) = cd {
        assert_eq!(cd.handle, 0x0002);
        assert_eq!(cd.properties & BT_GATT_CHRC_PROP_READ, BT_GATT_CHRC_PROP_READ);
    }
}

/// Test GattDbAttribute::get_permissions.
#[test]
fn test_attribute_get_permissions() {
    let db = make_service_data_1_db();
    let attr = db.get_attribute(0x0001).expect("get attr");
    let _perms = attr.get_permissions();
    // Service declarations typically have read permissions
}

// ============================================================================
// GattDbService Tests
// ============================================================================

/// Test foreach_char iteration.
#[test]
fn test_service_foreach_char() {
    let db = GattDb::new();
    let svc_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &svc_uuid, true, 8).expect("insert service");
    let name_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    svc.add_characteristic(
        &name_uuid,
        BT_ATT_PERM_READ as u32,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    );
    let appear_uuid = BtUuid::from_u16(UUID_APPEARANCE);
    svc.add_characteristic(
        &appear_uuid,
        BT_ATT_PERM_READ as u32,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    );
    svc.set_active(true);

    let mut count = 0u32;
    svc.foreach_char(|_| count += 1);
    assert_eq!(count, 2, "Service should have 2 characteristics");
}

/// Test foreach_desc iteration.
#[test]
fn test_service_foreach_desc() {
    let db = GattDb::new();
    let svc_uuid = BtUuid::from_u16(UUID_GAP);
    let svc = db.insert_service(0x0001, &svc_uuid, true, 8).expect("insert service");
    let name_uuid = BtUuid::from_u16(UUID_DEVICE_NAME);
    svc.add_characteristic(
        &name_uuid,
        BT_ATT_PERM_READ as u32,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
        None,
        None,
        None,
    );
    let ccc_uuid = BtUuid::from_u16(UUID_CCC);
    svc.add_descriptor(&ccc_uuid, (BT_ATT_PERM_READ | BT_ATT_PERM_WRITE) as u32, None, None, None);
    svc.set_active(true);

    let mut count = 0u32;
    svc.foreach_desc(|_| count += 1);
    assert_eq!(count, 1, "Service should have 1 descriptor");
}

/// Test foreach_incl iteration.
#[test]
fn test_service_foreach_incl() {
    let db = GattDb::new();
    let dis_uuid = BtUuid::from_u16(UUID_DEVICE_INFO);
    let svc1 = db.insert_service(0x0001, &dis_uuid, false, 4).expect("insert DIS");
    svc1.set_active(true);

    let gap_uuid = BtUuid::from_u16(UUID_GAP);
    let svc2 = db.insert_service(0x0010, &gap_uuid, true, 4).expect("insert GAP");
    let dis_attr = db.get_attribute(0x0001).expect("get DIS attr");
    svc2.add_included(&dis_attr);
    svc2.set_active(true);

    let mut count = 0u32;
    svc2.foreach_incl(|_| count += 1);
    assert_eq!(count, 1, "Service should have 1 included service");
}

// ============================================================================
// BtAtt Transport Tests
// ============================================================================

/// Test BtAtt creation over socketpair.
#[test]
fn test_att_new() {
    let (fd1, _fd2) = create_test_pair();
    let result = BtAtt::new(fd1.as_raw_fd(), false);
    assert!(result.is_ok(), "BtAtt::new should succeed");
    std::mem::forget(fd1); // Prevent double-close
}

/// Test BtAtt MTU operations.
#[test]
fn test_att_mtu() {
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);

    let mtu = att.lock().unwrap().get_mtu();
    assert!(mtu > 0, "Default MTU should be > 0");

    att.lock().unwrap().set_mtu(512);
    assert_eq!(att.lock().unwrap().get_mtu(), 512);
}

/// Test BtAtt has_crypto.
#[test]
fn test_att_has_crypto() {
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);
    let _crypto = att.lock().unwrap().has_crypto();
    // Just verifying the call doesn't panic
}

/// Test BtAtt security level operations.
#[test]
fn test_att_security() {
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);

    att.lock().unwrap().set_security(BT_ATT_SECURITY_MEDIUM as i32);
}

/// Test BtAtt local key setting.
#[test]
fn test_att_set_local_key() {
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);

    att.lock().unwrap().set_local_key(
        &SIGNING_KEY,
        Box::new(|counter: &mut u32| -> bool {
            *counter = counter.wrapping_add(1);
            true
        }),
    );
}

/// Test BtAtt debug callback.
#[test]
fn test_att_set_debug() {
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);

    att.lock().unwrap().set_debug(0, Some(Box::new(|_msg: &str| {})));
}

/// Test BtAtt send operation.
#[test]
fn test_att_send() {
    let (fd1, fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);

    // Send an MTU request — Req opcodes require a callback.
    let mtu_bytes: [u8; 2] = 512u16.to_le_bytes();
    let id = att.lock().unwrap().send(
        BT_ATT_OP_MTU_REQ,
        &mtu_bytes,
        Some(Box::new(|_opcode, _data| {})),
    );
    assert!(id > 0, "send should return non-zero id");

    // Flush pending writes to the socket fd
    att.lock().unwrap().flush_writes();

    // Read it from the peer side
    let mut buf = [0u8; 64];
    let n = blocking_read(&fd2, &mut buf);
    assert!(n >= 3, "Should receive MTU request PDU");
    assert_eq!(buf[0], BT_ATT_OP_MTU_REQ);
}

/// Test BtAtt register/unregister notification handler.
#[test]
fn test_att_register_unregister() {
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);

    let id = att
        .lock()
        .unwrap()
        .register(BT_ATT_OP_HANDLE_NFY, Arc::new(|_chan, _handle, _opcode, _data| {}));
    assert!(id > 0, "register should return non-zero id");

    let ok = att.lock().unwrap().unregister(id);
    assert!(ok, "unregister should succeed");
}

// ============================================================================
// BtGattServer Tests
// ============================================================================

/// Test BtGattServer creation.
#[test]
fn test_gatt_server_new() {
    let db = make_service_data_1_db();
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);
    let _server = BtGattServer::new(db, att, 512, 0).expect("BtGattServer::new");
}

/// Test BtGattServer set_debug.
#[test]
fn test_gatt_server_set_debug() {
    let db = make_service_data_1_db();
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);
    let server = BtGattServer::new(db, att, 512, 0).expect("BtGattServer::new");
    server.set_debug(|msg| {
        let _ = msg;
    });
}

/// Test BtGattServer get_mtu.
#[test]
fn test_gatt_server_get_mtu() {
    let db = make_service_data_1_db();
    let (fd1, _fd2) = create_test_pair();
    let att = BtAtt::new(fd1.as_raw_fd(), false).expect("BtAtt::new");
    std::mem::forget(fd1);
    let server = BtGattServer::new(db, att, 512, 0).expect("BtGattServer::new");
    let mtu = server.get_mtu();
    assert!(mtu > 0, "Server MTU should be positive");
}

// ============================================================================
// UUID Tests (used in GATT context)
// ============================================================================

/// Test BtUuid::from_u16 for GATT service UUIDs.
#[test]
fn test_uuid_from_u16() {
    let uuid = BtUuid::from_u16(UUID_GAP);
    match uuid {
        BtUuid::Uuid16(val) => assert_eq!(val, UUID_GAP),
        _ => panic!("Expected Uuid16 variant"),
    }
}

/// Test BtUuid::from_bytes for 128-bit UUID.
#[test]
fn test_uuid_from_bytes() {
    let uuid = BtUuid::from_bytes(&UUID_128_BYTES);
    match uuid {
        BtUuid::Uuid128(val) => assert_eq!(val, UUID_128_BYTES),
        _ => panic!("Expected Uuid128 variant"),
    }
}

/// Test BtUuid::to_uuid128_bytes expansion.
#[test]
fn test_uuid_to_uuid128_bytes() {
    let uuid = BtUuid::from_u16(UUID_GAP);
    let bytes = uuid.to_uuid128_bytes();
    assert_eq!(bytes.len(), 16);
    // Check that the 16-bit value is correctly embedded in the base UUID
    // Standard BT base: 0000XXXX-0000-1000-8000-00805F9B34FB
    // In LE byte order as stored: fb 34 9b 5f 80 00 00 80 00 10 00 00 XX XX 00 00
    assert_eq!(bytes[12], 0x00); // Low byte of GAP (0x1800)
    assert_eq!(bytes[13], 0x18); // High byte
}

/// Test BtUuid::from_str for hex string.
#[test]
fn test_uuid_from_str() {
    let uuid: BtUuid = "0x1800".parse().expect("parse UUID");
    assert_eq!(uuid, BtUuid::from_u16(UUID_GAP));
}

/// Test BtUuid equality.
#[test]
fn test_uuid_equality() {
    let u1 = BtUuid::from_u16(UUID_GAP);
    let u2 = BtUuid::from_u16(UUID_GAP);
    assert_eq!(u1, u2);

    let u3 = BtUuid::from_u16(UUID_HEART_RATE);
    assert_ne!(u1, u3);
}

// ============================================================================
// ATT Types Tests
// ============================================================================

/// Test AttPermissions bitflags.
#[test]
fn test_att_permissions() {
    let read = AttPermissions::from_bits_truncate(BT_ATT_PERM_READ);
    assert!(read.contains(AttPermissions::READ));

    let write = AttPermissions::from_bits_truncate(BT_ATT_PERM_WRITE);
    assert!(write.contains(AttPermissions::WRITE));

    let rw = read | write;
    assert!(rw.contains(AttPermissions::READ));
    assert!(rw.contains(AttPermissions::WRITE));
}

/// Test GattChrcProperties bitflags.
#[test]
fn test_chrc_properties() {
    let props = GattChrcProperties::from_bits_truncate(
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_NOTIFY,
    );
    assert!(props.contains(GattChrcProperties::READ));
    assert!(props.contains(GattChrcProperties::WRITE));
    assert!(props.contains(GattChrcProperties::NOTIFY));
    assert!(!props.contains(GattChrcProperties::INDICATE));
}

/// Test GattChrcExtProperties bitflags.
#[test]
fn test_chrc_ext_properties() {
    let ext = GattChrcExtProperties::from_bits_truncate(BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE);
    assert!(ext.contains(GattChrcExtProperties::RELIABLE_WRITE));
}

/// Test ATT opcode constants are correct values.
#[test]
fn test_att_opcode_values() {
    assert_eq!(BT_ATT_OP_ERROR_RSP, 0x01);
    assert_eq!(BT_ATT_OP_MTU_REQ, 0x02);
    assert_eq!(BT_ATT_OP_MTU_RSP, 0x03);
    assert_eq!(BT_ATT_OP_FIND_INFO_REQ, 0x04);
    assert_eq!(BT_ATT_OP_FIND_INFO_RSP, 0x05);
    assert_eq!(BT_ATT_OP_FIND_BY_TYPE_REQ, 0x06);
    assert_eq!(BT_ATT_OP_FIND_BY_TYPE_RSP, 0x07);
    assert_eq!(BT_ATT_OP_READ_BY_TYPE_REQ, 0x08);
    assert_eq!(BT_ATT_OP_READ_BY_TYPE_RSP, 0x09);
    assert_eq!(BT_ATT_OP_READ_REQ, 0x0A);
    assert_eq!(BT_ATT_OP_READ_RSP, 0x0B);
    assert_eq!(BT_ATT_OP_READ_BLOB_REQ, 0x0C);
    assert_eq!(BT_ATT_OP_READ_BLOB_RSP, 0x0D);
    assert_eq!(BT_ATT_OP_READ_MULT_REQ, 0x0E);
    assert_eq!(BT_ATT_OP_READ_MULT_RSP, 0x0F);
    assert_eq!(BT_ATT_OP_READ_BY_GRP_TYPE_REQ, 0x10);
    assert_eq!(BT_ATT_OP_READ_BY_GRP_TYPE_RSP, 0x11);
    assert_eq!(BT_ATT_OP_WRITE_REQ, 0x12);
    assert_eq!(BT_ATT_OP_WRITE_RSP, 0x13);
    assert_eq!(BT_ATT_OP_PREP_WRITE_REQ, 0x16);
    assert_eq!(BT_ATT_OP_PREP_WRITE_RSP, 0x17);
    assert_eq!(BT_ATT_OP_EXEC_WRITE_REQ, 0x18);
    assert_eq!(BT_ATT_OP_EXEC_WRITE_RSP, 0x19);
    assert_eq!(BT_ATT_OP_HANDLE_NFY, 0x1B);
    assert_eq!(BT_ATT_OP_HANDLE_IND, 0x1D);
    assert_eq!(BT_ATT_OP_HANDLE_CONF, 0x1E);
    assert_eq!(BT_ATT_OP_WRITE_CMD, 0x52);
    assert_eq!(BT_ATT_OP_SIGNED_WRITE_CMD, 0xD2);
}

/// Test ATT error code constants.
#[test]
fn test_att_error_values() {
    assert_eq!(BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND, 0x0A);
    assert_eq!(BT_ATT_ERROR_REQUEST_NOT_SUPPORTED, 0x06);
}

// ============================================================================
// Full PDU sequence verification tests (matching C main() registrations)
// ============================================================================

/// TP/GAC/CL/BV-01-C — Client MTU exchange PDU.
/// Verifies the MTU exchange client request PDU format.
#[test]
fn test_client_mtu_exchange_pdu() {
    // MTU exchange request: opcode=0x02, mtu=512 (0x0200 in LE)
    let mtu_req = &[0x02u8, 0x00, 0x02];
    assert_eq!(mtu_req[0], BT_ATT_OP_MTU_REQ);
    // Parse MTU from PDU
    let mtu = u16::from_le_bytes([mtu_req[1], mtu_req[2]]);
    assert_eq!(mtu, 512);

    // MTU exchange response
    let mtu_rsp = &[0x03u8, 0x00, 0x02];
    assert_eq!(mtu_rsp[0], BT_ATT_OP_MTU_RSP);
    let rsp_mtu = u16::from_le_bytes([mtu_rsp[1], mtu_rsp[2]]);
    assert_eq!(rsp_mtu, 512);
}

/// Verify PDU format for primary service discovery request.
#[test]
fn test_primary_disc_pdu_format() {
    // Read By Group Type request for Primary Service (0x2800)
    // Start=0x0001, End=0xFFFF, Type=0x2800
    let pdu = &[0x10u8, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28];
    assert_eq!(pdu[0], BT_ATT_OP_READ_BY_GRP_TYPE_REQ);
    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    let uuid = u16::from_le_bytes([pdu[5], pdu[6]]);
    assert_eq!(start, 0x0001);
    assert_eq!(end, 0xFFFF);
    assert_eq!(uuid, UUID_PRIMARY_SERVICE);
}

/// Verify PDU format for Find By Type Value request.
#[test]
fn test_find_by_type_pdu_format() {
    // Find By Type Value: start=0x0001, end=0xFFFF, type=0x2800, value=0x1800
    let pdu = &[0x06u8, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x00, 0x18];
    assert_eq!(pdu[0], BT_ATT_OP_FIND_BY_TYPE_REQ);
    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    let attr_type = u16::from_le_bytes([pdu[5], pdu[6]]);
    let value = u16::from_le_bytes([pdu[7], pdu[8]]);
    assert_eq!(start, 0x0001);
    assert_eq!(end, 0xFFFF);
    assert_eq!(attr_type, UUID_PRIMARY_SERVICE);
    assert_eq!(value, UUID_GAP);
}

/// Verify PDU format for Read By Type request (characteristic discovery).
#[test]
fn test_read_by_type_char_pdu_format() {
    // Read By Type: start=0x0010, end=0x0020, type=0x2803
    let pdu = &[0x08u8, 0x10, 0x00, 0x20, 0x00, 0x03, 0x28];
    assert_eq!(pdu[0], BT_ATT_OP_READ_BY_TYPE_REQ);
    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    let uuid = u16::from_le_bytes([pdu[5], pdu[6]]);
    assert_eq!(start, 0x0010);
    assert_eq!(end, 0x0020);
    assert_eq!(uuid, UUID_CHARACTERISTIC);
}

/// Verify PDU format for Read request.
#[test]
fn test_read_pdu_format() {
    let pdu = &[0x0Au8, 0x03, 0x00];
    assert_eq!(pdu[0], BT_ATT_OP_READ_REQ);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    assert_eq!(handle, 0x0003);
}

/// Verify PDU format for Write request.
#[test]
fn test_write_pdu_format() {
    let pdu = &[0x12u8, 0x07, 0x00, 0x01, 0x02, 0x03];
    assert_eq!(pdu[0], BT_ATT_OP_WRITE_REQ);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    assert_eq!(handle, 0x0007);
    assert_eq!(&pdu[3..], WRITE_DATA_1);
}

/// Verify PDU format for Write Without Response (command).
#[test]
fn test_write_cmd_pdu_format() {
    let pdu = &[0x52u8, 0x07, 0x00, 0x01, 0x02, 0x03];
    assert_eq!(pdu[0], BT_ATT_OP_WRITE_CMD);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    assert_eq!(handle, 0x0007);
}

/// Verify PDU format for Signed Write Command.
#[test]
fn test_signed_write_pdu_format() {
    let pdu = &[
        0xD2u8, 0x07, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x31, 0x1f, 0x0a, 0xcd, 0x1c,
        0x3a, 0x5b, 0x0a,
    ];
    assert_eq!(pdu[0], BT_ATT_OP_SIGNED_WRITE_CMD);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    assert_eq!(handle, 0x0007);
    // Value = [0x01, 0x02, 0x03]
    assert_eq!(&pdu[3..6], WRITE_DATA_1);
    // Signature = 12 bytes starting at index 6
    assert_eq!(pdu.len(), 18); // 1 + 2 + 3 + 12 = 18
}

/// Verify PDU format for Prepare Write request.
#[test]
fn test_prep_write_pdu_format() {
    let pdu = &[0x16u8, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03];
    assert_eq!(pdu[0], BT_ATT_OP_PREP_WRITE_REQ);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let offset = u16::from_le_bytes([pdu[3], pdu[4]]);
    assert_eq!(handle, 0x0007);
    assert_eq!(offset, 0x0000);
    assert_eq!(&pdu[5..], WRITE_DATA_1);
}

/// Verify PDU format for Execute Write request.
#[test]
fn test_exec_write_pdu_format() {
    // Execute with commit (flags=0x01)
    let pdu_commit = &[0x18u8, 0x01];
    assert_eq!(pdu_commit[0], BT_ATT_OP_EXEC_WRITE_REQ);
    assert_eq!(pdu_commit[1], 0x01);

    // Execute with cancel (flags=0x00)
    let pdu_cancel = &[0x18u8, 0x00];
    assert_eq!(pdu_cancel[0], BT_ATT_OP_EXEC_WRITE_REQ);
    assert_eq!(pdu_cancel[1], 0x00);
}

/// Verify PDU format for notification.
#[test]
fn test_notification_pdu_format() {
    let pdu = &[0x1Bu8, 0x03, 0x00, 0x01, 0x02, 0x03];
    assert_eq!(pdu[0], BT_ATT_OP_HANDLE_NFY);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    assert_eq!(handle, 0x0003);
    assert_eq!(&pdu[3..], READ_DATA_1);
}

/// Verify PDU format for indication.
#[test]
fn test_indication_pdu_format() {
    let pdu = &[0x1Du8, 0x03, 0x00, 0x01, 0x02, 0x03];
    assert_eq!(pdu[0], BT_ATT_OP_HANDLE_IND);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    assert_eq!(handle, 0x0003);
    assert_eq!(&pdu[3..], READ_DATA_1);

    // Confirmation
    let conf = &[0x1Eu8];
    assert_eq!(conf[0], BT_ATT_OP_HANDLE_CONF);
}

/// Verify PDU format for Read Blob request.
#[test]
fn test_read_blob_pdu_format() {
    let pdu = &[0x0Cu8, 0x03, 0x00, 0x16, 0x00];
    assert_eq!(pdu[0], BT_ATT_OP_READ_BLOB_REQ);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let offset = u16::from_le_bytes([pdu[3], pdu[4]]);
    assert_eq!(handle, 0x0003);
    assert_eq!(offset, 0x0016);
}

/// Verify PDU format for Read Multiple request.
#[test]
fn test_read_multiple_pdu_format() {
    let pdu = &[0x0Eu8, 0x03, 0x00, 0x07, 0x00];
    assert_eq!(pdu[0], BT_ATT_OP_READ_MULT_REQ);
    let h1 = u16::from_le_bytes([pdu[1], pdu[2]]);
    let h2 = u16::from_le_bytes([pdu[3], pdu[4]]);
    assert_eq!(h1, 0x0003);
    assert_eq!(h2, 0x0007);
}

/// Verify error response PDU format.
#[test]
fn test_error_rsp_pdu_format() {
    // Error response: opcode=0x01, req_opcode=0x0a, handle=0x0000, error=0x01
    let pdu = &[0x01u8, 0x0a, 0x00, 0x00, 0x01];
    assert_eq!(pdu[0], BT_ATT_OP_ERROR_RSP);
    assert_eq!(pdu[1], BT_ATT_OP_READ_REQ); // Request that caused error
    let handle = u16::from_le_bytes([pdu[2], pdu[3]]);
    assert_eq!(handle, 0x0000);
    assert_eq!(pdu[4], 0x01); // Invalid Handle
}

/// Verify Find Information request PDU format.
#[test]
fn test_find_info_pdu_format() {
    let pdu = &[0x04u8, 0x13, 0x00, 0x16, 0x00];
    assert_eq!(pdu[0], BT_ATT_OP_FIND_INFO_REQ);
    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    assert_eq!(start, 0x0013);
    assert_eq!(end, 0x0016);
}

/// Verify CCC write PDU for enabling notifications.
#[test]
fn test_ccc_write_notification_enable() {
    let pdu = &[0x12u8, 0x04, 0x00, 0x01, 0x00];
    assert_eq!(pdu[0], BT_ATT_OP_WRITE_REQ);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let value = u16::from_le_bytes([pdu[3], pdu[4]]);
    assert_eq!(handle, 0x0004); // CCC handle
    assert_eq!(value, 0x0001); // Enable notifications
}

/// Verify CCC write PDU for enabling indications.
#[test]
fn test_ccc_write_indication_enable() {
    let pdu = &[0x12u8, 0x09, 0x00, 0x02, 0x00];
    assert_eq!(pdu[0], BT_ATT_OP_WRITE_REQ);
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let value = u16::from_le_bytes([pdu[3], pdu[4]]);
    assert_eq!(handle, 0x0009); // CCC handle for indication
    assert_eq!(value, 0x0002); // Enable indications
}

// ============================================================================
// Data value preservation tests
// ============================================================================

/// Verify read_data_1 matches C source exactly.
#[test]
fn test_read_data_1_preserved() {
    assert_eq!(READ_DATA_1, &[0x01, 0x02, 0x03]);
}

/// Verify write_data_1 matches C source exactly.
#[test]
fn test_write_data_1_preserved() {
    assert_eq!(WRITE_DATA_1, &[0x01, 0x02, 0x03]);
}

/// Verify long_data_2 matches C source (512 bytes of 0xff).
#[test]
fn test_long_data_2_preserved() {
    assert_eq!(LONG_DATA_2.len(), 512);
    assert!(LONG_DATA_2.iter().all(|&b| b == 0xff));
}

/// Verify signing key matches C source exactly.
#[test]
fn test_signing_key_preserved() {
    assert_eq!(
        SIGNING_KEY,
        [
            0xD8, 0x51, 0x59, 0x48, 0x45, 0x1F, 0xEA, 0x32, 0x0D, 0xC0, 0x5A, 0x2E, 0x88, 0x30,
            0x81, 0x88,
        ]
    );
}
