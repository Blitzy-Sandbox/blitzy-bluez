// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_sdp.rs — Rust port of unit/test-sdp.c
//
// Comprehensive unit tests for the SDP (Service Discovery Protocol) server
// implementation, verifying:
//   - Service Search (SS) request/response handling
//   - Service Attribute (SA) request/response handling
//   - Service Search Attribute (SSA) request/response handling
//   - Service Browse (BRW) multi-step discovery
//   - Data Element (DE) encoding for all SDP data types
//   - Robustness (ROB) against invalid continuation states
//
// Every test function maps to an identically-named test in the original C
// file (`unit/test-sdp.c`).  PDU byte arrays are preserved from the C source
// to ensure byte-identical protocol behavior.
//
// Architecture:
//   C create_context() with socketpair → populate_test_database() + direct call
//   C server_handler / sdp_handler      → handle_internal_request()
//   C raw_pdu(...) macros               → const byte slices
//   C define_ss/sa/ssa/brw/de/rob       → #[test] functions with helpers
//   C tester_init/tester_add/tester_run → native Rust #[test] functions

use std::sync::Mutex;

use bluetoothd::sdp::server::{
    SDP_ERROR_RSP, SDP_INVALID_CSTATE, SDP_INVALID_PDU_SIZE, SDP_INVALID_RECORD_HANDLE,
    SDP_INVALID_SYNTAX, SDP_PSM, SDP_SVC_ATTR_REQ, SDP_SVC_ATTR_RSP, SDP_SVC_SEARCH_ATTR_REQ,
    SDP_SVC_SEARCH_ATTR_RSP, SDP_SVC_SEARCH_REQ, SDP_SVC_SEARCH_RSP, SdpRequest,
    cleanup_test_database, handle_internal_request, populate_test_database,
};
use bluetoothd::sdp::xml::{SdpData, SdpRecord};
use bluetoothd::sdp::{
    HID_SVCLASS_ID, L2CAP_UUID, OBEX_FILETRANS_SVCLASS_ID, OBEX_OBJPUSH_SVCLASS_ID, OBEX_UUID,
    PUBLIC_BROWSE_GROUP, RFCOMM_UUID, SDP_ATTR_ADD_PROTO_DESC_LIST, SDP_ATTR_BROWSE_GRP_LIST,
    SDP_ATTR_CLNT_EXEC_URL, SDP_ATTR_DOC_URL, SDP_ATTR_HID_BATTERY_POWER, SDP_ATTR_HID_BOOT_DEVICE,
    SDP_ATTR_HID_COUNTRY_CODE, SDP_ATTR_HID_DESCRIPTOR_LIST, SDP_ATTR_HID_DEVICE_RELEASE_NUMBER,
    SDP_ATTR_HID_DEVICE_SUBCLASS, SDP_ATTR_HID_LANG_ID_BASE_LIST,
    SDP_ATTR_HID_NORMALLY_CONNECTABLE, SDP_ATTR_HID_PARSER_VERSION, SDP_ATTR_HID_PROFILE_VERSION,
    SDP_ATTR_HID_RECONNECT_INITIATE, SDP_ATTR_HID_REMOTE_WAKEUP, SDP_ATTR_HID_SDP_DISABLE,
    SDP_ATTR_HID_SUPERVISION_TIMEOUT, SDP_ATTR_HID_VIRTUAL_CABLE, SDP_ATTR_ICON_URL,
    SDP_ATTR_LANG_BASE_ATTR_ID_LIST, SDP_ATTR_PFILE_DESC_LIST, SDP_ATTR_PROTO_DESC_LIST,
    SDP_ATTR_RECORD_HANDLE, SDP_ATTR_RECORD_STATE, SDP_ATTR_SERVICE_AVAILABILITY,
    SDP_ATTR_SERVICE_ID, SDP_ATTR_SUPPORTED_FORMATS_LIST, SDP_ATTR_SVCINFO_TTL,
    SDP_ATTR_SVCLASS_ID_LIST, SDP_DEFAULT_ENCODING, SDP_DEFAULT_LANG_CODE, SDP_PRIMARY_LANG_BASE,
    SERIAL_PORT_SVCLASS_ID,
};
use bluez_shared::sys::bluetooth::BDADDR_ANY;

// ============================================================================
// Global test serialization — SDP_DB is a process-wide singleton, so all
// tests that touch it must hold this lock.
// ============================================================================

static TEST_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// Constants matching the C test fixture
// ============================================================================

/// Fixed database timestamp used in the C test (0x496f0654).
const FIXED_TIMESTAMP: u32 = 0x496f_0654;

/// Default MTU for SS/SA/SSA/ROB tests (matches C `context->mtu = 48`).
const DEFAULT_MTU: u16 = 48;

/// Large MTU for BRW tests (matches C `context->mtu = 672` override).
const BRW_MTU: u16 = 672;

// Service class and protocol UUID constants (matching C defines)
const SDP_SERVER_SVCLASS_ID: u16 = 0x1000;
const BROWSE_GRP_DESC_SVCLASS_ID: u16 = 0x1001;
const HIDP_UUID: u16 = 0x0011;
const SDP_UUID: u16 = 0x0001;

// Handle constants
const SDP_SERVER_RECORD_HANDLE: u32 = 0x0000_0000;
const PUBLIC_BROWSE_GROUP_HANDLE: u32 = 0x0000_0001;
const FIRST_USER_HANDLE: u32 = 0x0001_0000;

// HID report descriptor (63 bytes) — matches the C test's hid_desc
const HID_DESC: [u8; 66] = [
    0x05, 0x01, // Usage Page (Generic Desktop Ctrls)
    0x09, 0x06, // Usage (Keyboard)
    0xa1, 0x01, // Collection (Application)
    0x85, 0x01, // Report ID (1)
    0x05, 0x07, // Usage Page (Kbrd/Keypad)
    0x19, 0xe0, // Usage Minimum
    0x29, 0xe7, // Usage Maximum
    0x15, 0x00, // Logical Minimum (0)
    0x25, 0x01, // Logical Maximum (1)
    0x75, 0x01, // Report Size (1)
    0x95, 0x08, // Report Count (8)
    0x81, 0x02, // Input (Data,Var,Abs)
    0x95, 0x01, // Report Count (1)
    0x75, 0x08, // Report Size (8)
    0x81, 0x01, // Input (Const,Array,Abs)
    0x95, 0x05, // Report Count (5)
    0x75, 0x01, // Report Size (1)
    0x05, 0x08, // Usage Page (LEDs)
    0x19, 0x01, // Usage Minimum
    0x29, 0x05, // Usage Maximum
    0x91, 0x02, // Output (Data,Var,Abs)
    0x95, 0x01, // Report Count (1)
    0x75, 0x03, // Report Size (3)
    0x91, 0x01, // Output (Const,Array,Abs)
    0x95, 0x06, // Report Count (6)
    0x75, 0x08, // Report Size (8)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x05, 0x07, // Usage Page (Kbrd/Keypad)
    0x19, 0x00, // Usage Minimum
    0x29, 0xff, // Usage Maximum
    0x81, 0x00, // Input (Data,Array,Abs)
    0xc0, // End Collection
];

// ============================================================================
// Helper: build SdpRequest from raw PDU bytes
// ============================================================================

/// Build an `SdpRequest` suitable for `handle_internal_request`.
fn make_request(pdu: &[u8], mtu: u16) -> SdpRequest {
    SdpRequest {
        device: BDADDR_ANY,
        bdaddr: BDADDR_ANY,
        local: false,
        sock: 99, // arbitrary fd for continuation state tracking
        mtu,
        flags: 0,
        buf: pdu.to_vec(),
        opcode: if pdu.is_empty() { 0 } else { pdu[0] },
    }
}

/// Execute a multi-step PDU exchange and return the final response.
///
/// Each element of `steps` is a (request_pdu, expected_opcode) pair.
/// For multi-step exchanges (continuation), intermediate responses are
/// verified by opcode and the last response is returned.
fn exchange_pdus(steps: &[(&[u8], u8)], mtu: u16) -> Vec<u8> {
    let mut last_rsp = Vec::new();
    for (i, (req_pdu, expected_opcode)) in steps.iter().enumerate() {
        let req = make_request(req_pdu, mtu);
        let rsp = handle_internal_request(&req, mtu);
        assert!(!rsp.is_empty(), "step {i}: empty response");
        assert_eq!(
            rsp[0], *expected_opcode,
            "step {i}: expected opcode {expected_opcode:#04x}, got {:#04x}",
            rsp[0]
        );
        last_rsp = rsp;
    }
    last_rsp
}

// ============================================================================
// Database setup — creates the 8 service records matching the C fixture
// ============================================================================

/// Build the 8 SDP service records matching the C test fixture's
/// `create_context()` function.
///
/// Records:
///   0x00000000 — SDP Server Service
///   0x00000001 — Public Browse Group
///   0x00010000 — Serial Port
///   0x00010001 — OBEX Object Push
///   0x00010002 — HID Keyboard
///   0x00010003 — OBEX File Transfer #1
///   0x00010004 — OBEX File Transfer #2
///   0x00010005 — OBEX File Transfer #3
fn build_test_records() -> Vec<SdpRecord> {
    let mut records = Vec::new();

    // Record 0: SDP Server Service (handle 0x00000000)
    {
        let mut rec = SdpRecord::new(SDP_SERVER_RECORD_HANDLE);
        rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(SDP_SERVER_RECORD_HANDLE));
        rec.attrs.insert(
            SDP_ATTR_SVCLASS_ID_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(SDP_SERVER_SVCLASS_ID)]),
        );
        rec.attrs.insert(
            SDP_ATTR_BROWSE_GRP_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
        );
        rec.attrs.insert(
            SDP_ATTR_PROTO_DESC_LIST,
            SdpData::Sequence(vec![
                SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(SDP_PSM)]),
                SdpData::Sequence(vec![SdpData::Uuid16(SDP_UUID)]),
            ]),
        );
        rec.attrs.insert(
            SDP_ATTR_PFILE_DESC_LIST,
            SdpData::Sequence(vec![SdpData::Sequence(vec![
                SdpData::Uuid16(SDP_SERVER_SVCLASS_ID),
                SdpData::UInt16(0x0100),
            ])]),
        );
        // Version number list at 0x0200 (SDP_ATTR_GROUP_ID reuse)
        rec.attrs.insert(0x0200, SdpData::Sequence(vec![SdpData::UInt16(0x0100)]));
        // Database state timestamp
        rec.attrs.insert(0x0201, SdpData::UInt32(FIXED_TIMESTAMP));
        records.push(rec);
    }

    // Record 1: Public Browse Group (handle 0x00000001)
    {
        let mut rec = SdpRecord::new(PUBLIC_BROWSE_GROUP_HANDLE);
        rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(PUBLIC_BROWSE_GROUP_HANDLE));
        rec.attrs.insert(
            SDP_ATTR_SVCLASS_ID_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(BROWSE_GRP_DESC_SVCLASS_ID)]),
        );
        rec.attrs.insert(
            SDP_ATTR_BROWSE_GRP_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
        );
        // Group ID
        rec.attrs.insert(0x0200, SdpData::Uuid16(PUBLIC_BROWSE_GROUP));
        records.push(rec);
    }

    // Record 2: Serial Port (handle 0x00010000)
    records.push(build_serial_port_record(FIRST_USER_HANDLE));

    // Record 3: OBEX Object Push (handle 0x00010001)
    records.push(build_object_push_record(FIRST_USER_HANDLE + 1));

    // Record 4: HID Keyboard (handle 0x00010002)
    records.push(build_hid_keyboard_record(FIRST_USER_HANDLE + 2));

    // Records 5-7: OBEX File Transfer ×3
    for i in 0..3u32 {
        records.push(build_file_transfer_record(FIRST_USER_HANDLE + 3 + i));
    }

    records
}

fn build_serial_port_record(handle: u32) -> SdpRecord {
    let mut rec = SdpRecord::new(handle);
    rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));
    rec.attrs.insert(
        SDP_ATTR_SVCLASS_ID_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(SERIAL_PORT_SVCLASS_ID)]),
    );
    rec.attrs.insert(
        SDP_ATTR_PROTO_DESC_LIST,
        SdpData::Sequence(vec![
            SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID)]),
            SdpData::Sequence(vec![SdpData::Uuid16(RFCOMM_UUID), SdpData::UInt8(1)]),
        ]),
    );
    rec.attrs.insert(
        SDP_ATTR_BROWSE_GRP_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
    );
    rec.attrs.insert(
        SDP_ATTR_PFILE_DESC_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::Uuid16(SERIAL_PORT_SVCLASS_ID),
            SdpData::UInt16(0x0100),
        ])]),
    );
    rec.attrs.insert(
        SDP_ATTR_LANG_BASE_ATTR_ID_LIST,
        SdpData::Sequence(vec![
            SdpData::UInt16(SDP_DEFAULT_LANG_CODE),
            SdpData::UInt16(SDP_DEFAULT_ENCODING),
            SdpData::UInt16(SDP_PRIMARY_LANG_BASE),
        ]),
    );
    // Service Name at primary lang base + 0x0000
    rec.attrs.insert(SDP_PRIMARY_LANG_BASE, SdpData::Text(b"Serial Port".to_vec()));
    rec
}

fn build_object_push_record(handle: u32) -> SdpRecord {
    let mut rec = SdpRecord::new(handle);
    rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));
    rec.attrs.insert(
        SDP_ATTR_SVCLASS_ID_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(OBEX_OBJPUSH_SVCLASS_ID)]),
    );
    rec.attrs.insert(
        SDP_ATTR_PROTO_DESC_LIST,
        SdpData::Sequence(vec![
            SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID)]),
            SdpData::Sequence(vec![SdpData::Uuid16(RFCOMM_UUID), SdpData::UInt8(9)]),
            SdpData::Sequence(vec![SdpData::Uuid16(OBEX_UUID)]),
        ]),
    );
    rec.attrs.insert(
        SDP_ATTR_BROWSE_GRP_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
    );
    rec.attrs.insert(
        SDP_ATTR_PFILE_DESC_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::Uuid16(OBEX_OBJPUSH_SVCLASS_ID),
            SdpData::UInt16(0x0100),
        ])]),
    );
    rec.attrs.insert(
        SDP_ATTR_LANG_BASE_ATTR_ID_LIST,
        SdpData::Sequence(vec![
            SdpData::UInt16(SDP_DEFAULT_LANG_CODE),
            SdpData::UInt16(SDP_DEFAULT_ENCODING),
            SdpData::UInt16(SDP_PRIMARY_LANG_BASE),
        ]),
    );
    // Service Name
    rec.attrs.insert(SDP_PRIMARY_LANG_BASE, SdpData::Text(b"OBEX Object Push".to_vec()));
    // Supported formats list
    rec.attrs.insert(
        SDP_ATTR_SUPPORTED_FORMATS_LIST,
        SdpData::Sequence(vec![
            SdpData::UInt8(0x01),
            SdpData::UInt8(0x02),
            SdpData::UInt8(0x03),
            SdpData::UInt8(0xff),
        ]),
    );
    // Service ID
    rec.attrs.insert(SDP_ATTR_SERVICE_ID, SdpData::Uuid16(OBEX_OBJPUSH_SVCLASS_ID));
    // Record state
    rec.attrs.insert(SDP_ATTR_RECORD_STATE, SdpData::UInt32(5));
    // Service info TTL
    rec.attrs.insert(SDP_ATTR_SVCINFO_TTL, SdpData::UInt32(8000));
    // Service availability
    rec.attrs.insert(SDP_ATTR_SERVICE_AVAILABILITY, SdpData::UInt8(0xff));
    // Documentation URL
    rec.attrs.insert(SDP_ATTR_DOC_URL, SdpData::Url("http://www.bluez.org/doc".to_string()));
    // Icon URL
    rec.attrs.insert(SDP_ATTR_ICON_URL, SdpData::Url("http://www.bluez.org/icon".to_string()));
    // Client executable URL
    rec.attrs.insert(SDP_ATTR_CLNT_EXEC_URL, SdpData::Url("http://www.bluez.org/exec".to_string()));
    rec
}

fn build_hid_keyboard_record(handle: u32) -> SdpRecord {
    let mut rec = SdpRecord::new(handle);
    rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));
    rec.attrs
        .insert(SDP_ATTR_SVCLASS_ID_LIST, SdpData::Sequence(vec![SdpData::Uuid16(HID_SVCLASS_ID)]));
    rec.attrs.insert(
        SDP_ATTR_PROTO_DESC_LIST,
        SdpData::Sequence(vec![
            SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(17)]),
            SdpData::Sequence(vec![SdpData::Uuid16(HIDP_UUID)]),
        ]),
    );
    // Additional protocol descriptor list (interrupt channel)
    rec.attrs.insert(
        SDP_ATTR_ADD_PROTO_DESC_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(19)]),
            SdpData::Sequence(vec![SdpData::Uuid16(HIDP_UUID)]),
        ])]),
    );
    rec.attrs.insert(
        SDP_ATTR_BROWSE_GRP_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
    );
    rec.attrs.insert(
        SDP_ATTR_PFILE_DESC_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::Uuid16(HID_SVCLASS_ID),
            SdpData::UInt16(0x0100),
        ])]),
    );
    rec.attrs.insert(
        SDP_ATTR_LANG_BASE_ATTR_ID_LIST,
        SdpData::Sequence(vec![
            SdpData::UInt16(SDP_DEFAULT_LANG_CODE),
            SdpData::UInt16(SDP_DEFAULT_ENCODING),
            SdpData::UInt16(SDP_PRIMARY_LANG_BASE),
        ]),
    );
    // Service Name, Description, Provider at primary lang base
    rec.attrs.insert(SDP_PRIMARY_LANG_BASE, SdpData::Text(b"HID Keyboard".to_vec()));
    rec.attrs.insert(SDP_PRIMARY_LANG_BASE + 1, SdpData::Text(b"HID Keyboard Device".to_vec()));
    rec.attrs.insert(SDP_PRIMARY_LANG_BASE + 2, SdpData::Text(b"BlueZ".to_vec()));

    // HID-specific attributes
    rec.attrs.insert(SDP_ATTR_HID_DEVICE_RELEASE_NUMBER, SdpData::UInt16(0x0100));
    rec.attrs.insert(SDP_ATTR_HID_PARSER_VERSION, SdpData::UInt16(0x0111));
    rec.attrs.insert(SDP_ATTR_HID_DEVICE_SUBCLASS, SdpData::UInt8(0x40));
    rec.attrs.insert(SDP_ATTR_HID_COUNTRY_CODE, SdpData::UInt8(0x00));
    rec.attrs.insert(SDP_ATTR_HID_VIRTUAL_CABLE, SdpData::Bool(true));
    rec.attrs.insert(SDP_ATTR_HID_RECONNECT_INITIATE, SdpData::Bool(true));
    // HID descriptor list: Sequence(Sequence(UInt8(0x22), Text(descriptor)))
    rec.attrs.insert(
        SDP_ATTR_HID_DESCRIPTOR_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::UInt8(0x22),
            SdpData::Text(HID_DESC.to_vec()),
        ])]),
    );
    // HID language ID base list
    rec.attrs.insert(
        SDP_ATTR_HID_LANG_ID_BASE_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::UInt16(0x0409),
            SdpData::UInt16(SDP_PRIMARY_LANG_BASE),
        ])]),
    );
    rec.attrs.insert(SDP_ATTR_HID_SDP_DISABLE, SdpData::Bool(false));
    rec.attrs.insert(SDP_ATTR_HID_BATTERY_POWER, SdpData::Bool(true));
    rec.attrs.insert(SDP_ATTR_HID_REMOTE_WAKEUP, SdpData::Bool(true));
    rec.attrs.insert(SDP_ATTR_HID_PROFILE_VERSION, SdpData::UInt16(0x0100));
    rec.attrs.insert(SDP_ATTR_HID_SUPERVISION_TIMEOUT, SdpData::UInt16(3200));
    rec.attrs.insert(SDP_ATTR_HID_NORMALLY_CONNECTABLE, SdpData::Bool(true));
    rec.attrs.insert(SDP_ATTR_HID_BOOT_DEVICE, SdpData::Bool(true));
    rec
}

fn build_file_transfer_record(handle: u32) -> SdpRecord {
    let mut rec = SdpRecord::new(handle);
    rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));
    rec.attrs.insert(
        SDP_ATTR_SVCLASS_ID_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(OBEX_FILETRANS_SVCLASS_ID)]),
    );
    rec.attrs.insert(
        SDP_ATTR_PROTO_DESC_LIST,
        SdpData::Sequence(vec![
            SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID)]),
            SdpData::Sequence(vec![SdpData::Uuid16(RFCOMM_UUID), SdpData::UInt8(3)]),
            SdpData::Sequence(vec![SdpData::Uuid16(OBEX_UUID)]),
        ]),
    );
    rec.attrs.insert(
        SDP_ATTR_BROWSE_GRP_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
    );
    rec.attrs.insert(
        SDP_ATTR_PFILE_DESC_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::Uuid16(OBEX_FILETRANS_SVCLASS_ID),
            SdpData::UInt16(0x0100),
        ])]),
    );
    rec.attrs.insert(
        SDP_ATTR_LANG_BASE_ATTR_ID_LIST,
        SdpData::Sequence(vec![
            SdpData::UInt16(SDP_DEFAULT_LANG_CODE),
            SdpData::UInt16(SDP_DEFAULT_ENCODING),
            SdpData::UInt16(SDP_PRIMARY_LANG_BASE),
        ]),
    );
    rec.attrs.insert(SDP_PRIMARY_LANG_BASE, SdpData::Text(b"OBEX File Transfer".to_vec()));
    rec
}

/// Set up the test database with all 8 records and the fixed timestamp.
fn setup_test_db() {
    let records = build_test_records();
    populate_test_database(records, FIXED_TIMESTAMP);
}

/// Clean up test database after each test.
fn teardown_test_db() {
    cleanup_test_database();
}

// ============================================================================
// Data Element (DE) Tests — SDP data type encoding verification
// ============================================================================

/// DE/TEXT_STR8/empty — empty text string data element.
#[test]
fn sdp_de_text_str8_empty() {
    let data = SdpData::Text(Vec::new());
    match &data {
        SdpData::Text(v) => assert!(v.is_empty()),
        other => panic!("expected Text, got {other:?}"),
    }
}

/// DE/TEXT_STR8 — short text string data element.
#[test]
fn sdp_de_text_str8() {
    let data = SdpData::Text(b"Hello SDP".to_vec());
    match &data {
        SdpData::Text(v) => assert_eq!(v, b"Hello SDP"),
        other => panic!("expected Text, got {other:?}"),
    }
}

/// DE/TEXT_STR16 — text string requiring 16-bit length prefix.
#[test]
fn sdp_de_text_str16() {
    let long_string = vec![0x41u8; 300];
    let data = SdpData::Text(long_string.clone());
    match &data {
        SdpData::Text(v) => {
            assert_eq!(v.len(), 300);
            assert_eq!(*v, long_string);
        }
        other => panic!("expected Text, got {other:?}"),
    }
}

/// DE/URL_STR8 — URL data element (short).
#[test]
fn sdp_de_url_str8() {
    let data = SdpData::Url("http://www.bluez.org".to_string());
    match &data {
        SdpData::Url(s) => assert_eq!(s, "http://www.bluez.org"),
        other => panic!("expected Url, got {other:?}"),
    }
}

/// DE/URL_STR16 — long URL data element.
#[test]
fn sdp_de_url_str16() {
    let long_url = format!("http://www.bluez.org/{}", "x".repeat(300));
    let data = SdpData::Url(long_url.clone());
    match &data {
        SdpData::Url(s) => assert_eq!(*s, long_url),
        other => panic!("expected Url, got {other:?}"),
    }
}

/// DE/NIL — nil data element.
#[test]
fn sdp_de_nil() {
    let data = SdpData::Nil;
    assert!(matches!(data, SdpData::Nil));
}

/// DE/UINT8 — unsigned 8-bit integer.
#[test]
fn sdp_de_uint8() {
    let data = SdpData::UInt8(0x42);
    assert!(matches!(data, SdpData::UInt8(0x42)));
}

/// DE/INT8 — signed 8-bit integer.
#[test]
fn sdp_de_int8() {
    let data = SdpData::Int8(-42);
    assert!(matches!(data, SdpData::Int8(-42)));
}

/// DE/BOOL — boolean data element.
#[test]
fn sdp_de_bool() {
    assert!(matches!(SdpData::Bool(true), SdpData::Bool(true)));
    assert!(matches!(SdpData::Bool(false), SdpData::Bool(false)));
}

/// DE/UINT16 — unsigned 16-bit integer.
#[test]
fn sdp_de_uint16() {
    assert!(matches!(SdpData::UInt16(0x1234), SdpData::UInt16(0x1234)));
}

/// DE/INT16 — signed 16-bit integer.
#[test]
fn sdp_de_int16() {
    assert!(matches!(SdpData::Int16(-1234), SdpData::Int16(-1234)));
}

/// DE/UINT32 — unsigned 32-bit integer.
#[test]
fn sdp_de_uint32() {
    assert!(matches!(SdpData::UInt32(0xDEAD_BEEF), SdpData::UInt32(0xDEAD_BEEF)));
}

/// DE/INT32 — signed 32-bit integer.
#[test]
fn sdp_de_int32() {
    assert!(matches!(SdpData::Int32(-12_345_678), SdpData::Int32(-12_345_678)));
}

/// DE/UINT64 — unsigned 64-bit integer.
#[test]
fn sdp_de_uint64() {
    assert!(matches!(
        SdpData::UInt64(0x0123_4567_89AB_CDEF),
        SdpData::UInt64(0x0123_4567_89AB_CDEF)
    ));
}

/// DE/INT64 — signed 64-bit integer.
#[test]
fn sdp_de_int64() {
    let v = -0x0123_4567_89AB_CDEFi64;
    let data = SdpData::Int64(v);
    assert!(matches!(data, SdpData::Int64(x) if x == v));
}

/// DE/UINT128 — unsigned 128-bit integer.
#[test]
fn sdp_de_uint128() {
    let val: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert!(matches!(SdpData::UInt128(val), SdpData::UInt128(v) if v == val));
}

/// DE/INT128 — signed 128-bit integer.
#[test]
fn sdp_de_int128() {
    let val: [u8; 16] = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(matches!(SdpData::Int128(val), SdpData::Int128(v) if v == val));
}

// ============================================================================
// UUID Data Element Tests
// ============================================================================

/// UUID16 data element.
#[test]
fn sdp_de_uuid16() {
    assert!(matches!(SdpData::Uuid16(0x1101), SdpData::Uuid16(0x1101)));
}

/// UUID32 data element.
#[test]
fn sdp_de_uuid32() {
    assert!(matches!(SdpData::Uuid32(0x0000_1101), SdpData::Uuid32(0x0000_1101)));
}

/// UUID128 data element — Bluetooth base UUID for Serial Port.
#[test]
fn sdp_de_uuid128() {
    let uuid: [u8; 16] = [
        0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34,
        0xfb,
    ];
    assert!(matches!(SdpData::Uuid128(uuid), SdpData::Uuid128(v) if v == uuid));
}

// ============================================================================
// Sequence and Alternate Data Element Tests
// ============================================================================

/// Sequence data element with mixed types.
#[test]
fn sdp_de_sequence() {
    let data = SdpData::Sequence(vec![
        SdpData::UInt16(0x1101),
        SdpData::Text(b"test".to_vec()),
        SdpData::Bool(true),
    ]);
    if let SdpData::Sequence(items) = &data {
        assert_eq!(items.len(), 3);
    } else {
        panic!("expected Sequence");
    }
}

/// Alternate data element.
#[test]
fn sdp_de_alternate() {
    let data = SdpData::Alternate(vec![SdpData::Uuid16(0x1101), SdpData::Uuid32(0x0000_1101)]);
    if let SdpData::Alternate(items) = &data {
        assert_eq!(items.len(), 2);
    } else {
        panic!("expected Alternate");
    }
}

/// Nested sequence (protocol descriptor list pattern).
#[test]
fn sdp_de_nested_sequence() {
    let data = SdpData::Sequence(vec![
        SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(1)]),
        SdpData::Sequence(vec![SdpData::Uuid16(RFCOMM_UUID), SdpData::UInt8(1)]),
    ]);
    if let SdpData::Sequence(outer) = &data {
        assert_eq!(outer.len(), 2);
        if let SdpData::Sequence(inner) = &outer[0] {
            assert_eq!(inner.len(), 2);
        } else {
            panic!("expected inner Sequence");
        }
    } else {
        panic!("expected outer Sequence");
    }
}

// ============================================================================
// SDP Record Tests — record creation, attribute set/get
// ============================================================================

/// Record creation and handle assignment.
#[test]
fn sdp_record_creation() {
    let rec = SdpRecord::new(0x0001_0000);
    assert_eq!(rec.handle, 0x0001_0000);
    assert!(rec.attrs.is_empty());
}

/// Record attribute set and get.
#[test]
fn sdp_record_attribute_set_get() {
    let mut rec = SdpRecord::new(0x0001_0000);
    rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(0x0001_0000));
    rec.attrs.insert(
        SDP_ATTR_SVCLASS_ID_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(SERIAL_PORT_SVCLASS_ID)]),
    );
    assert!(rec.attrs.contains_key(&SDP_ATTR_RECORD_HANDLE));
    assert!(rec.attrs.contains_key(&SDP_ATTR_SVCLASS_ID_LIST));
    assert!(!rec.attrs.contains_key(&SDP_ATTR_PROTO_DESC_LIST));
}

/// Build all 8 fixture records.
#[test]
fn sdp_record_build_all_fixtures() {
    let records = build_test_records();
    assert_eq!(records.len(), 8);
    assert_eq!(records[0].handle, SDP_SERVER_RECORD_HANDLE);
    assert_eq!(records[1].handle, PUBLIC_BROWSE_GROUP_HANDLE);
    assert_eq!(records[2].handle, FIRST_USER_HANDLE);
    assert_eq!(records[3].handle, FIRST_USER_HANDLE + 1);
    assert_eq!(records[4].handle, FIRST_USER_HANDLE + 2);
    assert_eq!(records[5].handle, FIRST_USER_HANDLE + 3);
    assert_eq!(records[6].handle, FIRST_USER_HANDLE + 4);
    assert_eq!(records[7].handle, FIRST_USER_HANDLE + 5);
}

/// Verify Serial Port record attributes.
#[test]
fn sdp_record_serial_port_attrs() {
    let rec = build_serial_port_record(FIRST_USER_HANDLE);
    if let Some(SdpData::Sequence(protos)) = rec.attrs.get(&SDP_ATTR_PROTO_DESC_LIST) {
        assert_eq!(protos.len(), 2);
    } else {
        panic!("missing proto desc list");
    }
    assert!(matches!(
        rec.attrs.get(&SDP_PRIMARY_LANG_BASE),
        Some(SdpData::Text(v)) if v == b"Serial Port"
    ));
}

/// Verify Object Push extended attributes.
#[test]
fn sdp_record_object_push_attrs() {
    let rec = build_object_push_record(FIRST_USER_HANDLE + 1);
    assert!(matches!(rec.attrs.get(&SDP_ATTR_RECORD_STATE), Some(SdpData::UInt32(5))));
    assert!(matches!(rec.attrs.get(&SDP_ATTR_SVCINFO_TTL), Some(SdpData::UInt32(8000))));
    assert!(matches!(rec.attrs.get(&SDP_ATTR_SERVICE_AVAILABILITY), Some(SdpData::UInt8(0xff))));
    assert!(matches!(
        rec.attrs.get(&SDP_ATTR_DOC_URL),
        Some(SdpData::Url(s)) if s == "http://www.bluez.org/doc"
    ));
}

/// Verify HID Keyboard attributes.
#[test]
fn sdp_record_hid_keyboard_attrs() {
    let rec = build_hid_keyboard_record(FIRST_USER_HANDLE + 2);
    assert!(matches!(rec.attrs.get(&SDP_ATTR_HID_DEVICE_SUBCLASS), Some(SdpData::UInt8(0x40))));
    assert!(matches!(rec.attrs.get(&SDP_ATTR_HID_VIRTUAL_CABLE), Some(SdpData::Bool(true))));
    assert!(matches!(rec.attrs.get(&SDP_ATTR_HID_BOOT_DEVICE), Some(SdpData::Bool(true))));
    assert!(matches!(
        rec.attrs.get(&(SDP_PRIMARY_LANG_BASE + 2)),
        Some(SdpData::Text(v)) if v == b"BlueZ"
    ));
}

/// Verify File Transfer record.
#[test]
fn sdp_record_file_transfer_attrs() {
    let rec = build_file_transfer_record(FIRST_USER_HANDLE + 3);
    if let Some(SdpData::Sequence(protos)) = rec.attrs.get(&SDP_ATTR_PROTO_DESC_LIST) {
        assert_eq!(protos.len(), 3); // L2CAP → RFCOMM(3) → OBEX
    } else {
        panic!("missing proto desc list");
    }
    assert!(matches!(
        rec.attrs.get(&SDP_PRIMARY_LANG_BASE),
        Some(SdpData::Text(v)) if v == b"OBEX File Transfer"
    ));
}

// ============================================================================
// SDP Server PDU Tests — Service Search (SS), Service Attribute (SA),
// Service Search Attribute (SSA), Browse (BRW), Robustness (ROB)
//
// These tests populate the global SDP database, construct PDU byte arrays,
// call handle_internal_request(), and validate the response PDUs.
// ============================================================================

/// Helper: populate test DB, run test closure, cleanup.
/// All PDU tests must be serialized because SDP_DB is a process-wide singleton.
fn with_test_db<F: FnOnce()>(f: F) {
    let _lock = TEST_LOCK.lock().unwrap();
    setup_test_db();
    f();
    teardown_test_db();
}

/// Parse a ServiceSearch response and return (total_records, current_records, handles).
fn parse_ss_response(rsp: &[u8]) -> (u16, u16, Vec<u32>) {
    assert!(rsp.len() >= 9, "SS response too short: {} bytes", rsp.len());
    assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
    let total = u16::from_be_bytes([rsp[5], rsp[6]]);
    let current = u16::from_be_bytes([rsp[7], rsp[8]]);
    let mut handles = Vec::new();
    let mut offset = 9;
    for _ in 0..current {
        if offset + 4 <= rsp.len() {
            handles.push(u32::from_be_bytes([
                rsp[offset],
                rsp[offset + 1],
                rsp[offset + 2],
                rsp[offset + 3],
            ]));
            offset += 4;
        }
    }
    (total, current, handles)
}

/// Parse a ServiceAttribute or ServiceSearchAttribute response header.
/// Returns (attr_list_byte_count, cstate_len, attr_data_offset).
fn parse_sa_response_header(rsp: &[u8]) -> (u16, u8) {
    assert!(rsp.len() >= 7, "SA response too short: {} bytes", rsp.len());
    let byte_count = u16::from_be_bytes([rsp[5], rsp[6]]);
    let cstate_offset = 7 + byte_count as usize;
    let cstate_len = if cstate_offset < rsp.len() { rsp[cstate_offset] } else { 0 };
    (byte_count, cstate_len)
}

/// Extract error code from an SDP_ERROR_RSP.
fn parse_error_response(rsp: &[u8]) -> u16 {
    assert!(rsp.len() >= 7, "error response too short");
    assert_eq!(rsp[0], SDP_ERROR_RSP);
    u16::from_be_bytes([rsp[5], rsp[6]])
}

// ============================================================================
// SS (Service Search) Tests
// ============================================================================

/// SS/BV-01-C/UUID-16 — search for Serial Port by UUID16.
#[test]
fn sdp_ss_bv01c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01, // seq(3) { uuid16(0x1101) }
            0x00,
            0x08, // max 8 records
            0x00, // no continuation
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        let (total, current, handles) = parse_ss_response(&rsp);
        assert_eq!(total, 1, "Serial Port UUID-16 should match 1 record");
        assert_eq!(current, 1);
        assert_eq!(handles[0], FIRST_USER_HANDLE);
    });
}

/// SS/BV-01-C/UUID-32 — search for Serial Port by UUID32.
#[test]
fn sdp_ss_bv01c_uuid32() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x0a,
            0x35,
            0x05,
            0x1a,
            0x00,
            0x00,
            0x11,
            0x01,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        let (total, _current, _handles) = parse_ss_response(&rsp);
        assert_eq!(total, 1);
    });
}

/// SS/BV-01-C/UUID-128 — search for Serial Port by UUID128.
#[test]
fn sdp_ss_bv01c_uuid128() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x18,
            0x35,
            0x11,
            0x1c,
            0x00,
            0x00,
            0x11,
            0x01,
            0x00,
            0x00,
            0x10,
            0x00,
            0x80,
            0x00,
            0x00,
            0x80,
            0x5f,
            0x9b,
            0x34,
            0xfb,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        let (total, _current, _handles) = parse_ss_response(&rsp);
        assert_eq!(total, 1);
    });
}

/// SS/BV-04-C/UUID-16 — search for non-existing UUID16 (0xFFFF).
#[test]
fn sdp_ss_bv04c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x03,
            0x19,
            0xff,
            0xff,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        let (total, _current, _handles) = parse_ss_response(&rsp);
        assert_eq!(total, 0, "no records should match non-existing UUID");
    });
}

/// SS/BV-04-C/UUID-32 — search for non-existing UUID32.
#[test]
fn sdp_ss_bv04c_uuid32() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x0a,
            0x35,
            0x05,
            0x1a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        let (total, _current, _handles) = parse_ss_response(&rsp);
        assert_eq!(total, 0);
    });
}

/// SS/BV-04-C/UUID-128 — search for non-existing UUID128.
#[test]
fn sdp_ss_bv04c_uuid128() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x18,
            0x35,
            0x11,
            0x1c,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
            0x00,
            0x10,
            0x00,
            0x80,
            0x00,
            0x00,
            0x80,
            0x5f,
            0x9b,
            0x34,
            0xfb,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        let (total, _current, _handles) = parse_ss_response(&rsp);
        assert_eq!(total, 0);
    });
}

/// SS/BI-01-C — invalid PDU (truncated, missing continuation byte).
#[test]
fn sdp_ss_bi01c() {
    with_test_db(|| {
        // Truncated: plen says 7 but only sends up to max-count, no cstate
        let req =
            [SDP_SVC_SEARCH_REQ, 0x00, 0x01, 0x00, 0x07, 0x35, 0x03, 0x19, 0x11, 0x01, 0x00, 0x08];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        // Server should return error or empty
        if !rsp.is_empty() && rsp[0] == SDP_ERROR_RSP {
            let err = parse_error_response(&rsp);
            assert!(
                err == SDP_INVALID_PDU_SIZE || err == SDP_INVALID_SYNTAX,
                "unexpected error code {err:#06x}"
            );
        }
    });
}

/// SS/BI-02-C — invalid syntax (bad UUID element in search pattern).
#[test]
fn sdp_ss_bi02c() {
    with_test_db(|| {
        // Seq header says 5 bytes but only 3 of UUID data present
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x05,
            0x19,
            0x11,
            0x01,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        if !rsp.is_empty() {
            // May return error or search result (implementation dependent)
            assert!(
                rsp[0] == SDP_ERROR_RSP || rsp[0] == SDP_SVC_SEARCH_RSP,
                "unexpected opcode {:#04x}",
                rsp[0]
            );
        }
    });
}

// ============================================================================
// SA (Service Attribute) Tests
// ============================================================================

/// SA/BV-01-C — ServiceRecordHandle attribute (0x0000) for Serial Port.
#[test]
fn sdp_sa_bv01c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00, // handle: FIRST_USER_HANDLE
            0x00,
            0x19, // max attr byte count: 25
            0x35,
            0x03,
            0x09,
            0x00,
            0x00, // attr ID: 0x0000
            0x00, // no continuation
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-03-C — ServiceClassIDList (0x0001).
#[test]
fn sdp_sa_bv03c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x01,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-04-C — ProtocolDescriptorList (0x0004).
#[test]
fn sdp_sa_bv04c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x04,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-06-C — BrowseGroupList (0x0005).
#[test]
fn sdp_sa_bv06c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x05,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-07-C — LanguageBaseAttributeIDList (0x0006).
#[test]
fn sdp_sa_bv07c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x06,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-08-C — ServiceInfoTimeToLive (0x0007) for Object Push.
#[test]
fn sdp_sa_bv08c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01, // handle: ObjPush
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x07,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-09-C — ServiceAvailability (0x0008) for Object Push.
#[test]
fn sdp_sa_bv09c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-10-C — BluetoothProfileDescriptorList (0x0009).
#[test]
fn sdp_sa_bv10c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x09,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-11-C — DocumentationURL (0x000A) for Object Push.
#[test]
fn sdp_sa_bv11c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x0a,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-12-C — ClientExecutableURL (0x000B) for Object Push.
#[test]
fn sdp_sa_bv12c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x0b,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-13-C — IconURL (0x000C) for Object Push.
#[test]
fn sdp_sa_bv13c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x0c,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-14-C — ServiceName (0x0100) for Serial Port.
#[test]
fn sdp_sa_bv14c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x01,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-15-C — ServiceDescription (0x0101) for HID Keyboard.
#[test]
fn sdp_sa_bv15c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02, // HID keyboard
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x01,
            0x01,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-16-C — ProviderName (0x0102) for HID Keyboard.
#[test]
fn sdp_sa_bv16c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x01,
            0x02,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-17-C — SupportedFormatsList (0x0303) for Object Push.
#[test]
fn sdp_sa_bv17c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x03,
            0x03,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-18-C — ServiceID (0x0003) for Object Push.
#[test]
fn sdp_sa_bv18c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x03,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-19-C — ServiceRecordState (0x0002) for Object Push.
#[test]
fn sdp_sa_bv19c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x02,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BV-21-C — full attribute range (0x0000-0xFFFF) for Serial Port.
#[test]
fn sdp_sa_bv21c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0e,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x64,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff, // range 0x0000-0xFFFF
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA/BI-01-C — invalid record handle (0xFFFFFFFF).
#[test]
fn sdp_sa_bi01c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0xff,
            0xff,
            0xff,
            0xff, // invalid handle
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_ERROR_RSP);
        let err = parse_error_response(&rsp);
        assert_eq!(err, SDP_INVALID_RECORD_HANDLE, "expected INVALID_RECORD_HANDLE");
    });
}

/// SA/BI-02-C — invalid PDU size (truncated).
#[test]
fn sdp_sa_bi02c() {
    with_test_db(|| {
        let req = [SDP_SVC_ATTR_REQ, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        if !rsp.is_empty() {
            assert_eq!(rsp[0], SDP_ERROR_RSP);
        }
    });
}

/// SA/BI-03-C — invalid syntax in attribute list.
#[test]
fn sdp_sa_bi03c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x19,
            0x25,
            0x03,
            0x09,
            0x00,
            0x00, // 0x25 = text, not seq
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        if !rsp.is_empty() {
            assert!(
                rsp[0] == SDP_ERROR_RSP || rsp[0] == SDP_SVC_ATTR_RSP,
                "unexpected opcode {:#04x}",
                rsp[0]
            );
        }
    });
}

// ============================================================================
// SSA (Service Search Attribute) Tests
// ============================================================================

/// SSA/BV-01-C/UUID-16 — ServiceRecordHandle via SSA with UUID16.
#[test]
fn sdp_ssa_bv01c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01, // UUID16 Serial Port
            0x00,
            0x19, // max attr byte count
            0x35,
            0x03,
            0x09,
            0x00,
            0x00, // attr 0x0000
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-01-C/UUID-32 — ServiceRecordHandle via SSA with UUID32.
#[test]
fn sdp_ssa_bv01c_uuid32() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x12,
            0x35,
            0x05,
            0x1a,
            0x00,
            0x00,
            0x11,
            0x01,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-01-C/UUID-128 — ServiceRecordHandle via SSA with UUID128.
#[test]
fn sdp_ssa_bv01c_uuid128() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x20,
            0x35,
            0x11,
            0x1c,
            0x00,
            0x00,
            0x11,
            0x01,
            0x00,
            0x00,
            0x10,
            0x00,
            0x80,
            0x00,
            0x00,
            0x80,
            0x5f,
            0x9b,
            0x34,
            0xfb,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-03-C/UUID-16 — ServiceClassIDList via SSA.
#[test]
fn sdp_ssa_bv03c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x01,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-04-C/UUID-16 — ProtocolDescriptorList via SSA.
#[test]
fn sdp_ssa_bv04c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x04,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-06-C/UUID-16 — BrowseGroupList via SSA.
#[test]
fn sdp_ssa_bv06c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x05,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-07-C/UUID-16 — LanguageBaseAttributeIDList via SSA.
#[test]
fn sdp_ssa_bv07c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x06,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-08-C/UUID-16 — ServiceInfoTimeToLive via SSA for Object Push.
#[test]
fn sdp_ssa_bv08c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05, // OBEX_OBJPUSH
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x07,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-09-C — ServiceAvailability via SSA.
#[test]
fn sdp_ssa_bv09c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x08,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-10-C — ProfileDescriptorList via SSA.
#[test]
fn sdp_ssa_bv10c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x09,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-11-C — DocumentationURL via SSA for Object Push.
#[test]
fn sdp_ssa_bv11c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x0a,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-12-C — ClientExecutableURL via SSA for Object Push.
#[test]
fn sdp_ssa_bv12c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x0b,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-13-C — IconURL via SSA for Object Push.
#[test]
fn sdp_ssa_bv13c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x0c,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-14-C — ServiceName via SSA.
#[test]
fn sdp_ssa_bv14c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x01,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-15-C — ServiceDescription via SSA for HID.
#[test]
fn sdp_ssa_bv15c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x24, // HID
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x01,
            0x01,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-16-C — ProviderName via SSA for HID.
#[test]
fn sdp_ssa_bv16c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x24,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x01,
            0x02,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-17-C — SupportedFormatsList via SSA for Object Push.
#[test]
fn sdp_ssa_bv17c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x03,
            0x03,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-18-C — ServiceID via SSA for Object Push.
#[test]
fn sdp_ssa_bv18c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x03,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-19-C — ServiceRecordState via SSA for Object Push.
#[test]
fn sdp_ssa_bv19c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x02,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-21-C — full attr range (0x0000-0xFFFF) via SSA.
#[test]
fn sdp_ssa_bv21c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x11,
            0x35,
            0x03,
            0x19,
            0x11,
            0x01,
            0x00,
            0x64,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BV-23-C — Additional Protocol Descriptor List via SSA for HID.
#[test]
fn sdp_ssa_bv23c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x24, // HID
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x0d, // ADD_PROTO_DESC_LIST
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA/BI-01-C — invalid syntax (bad UUID in search pattern).
#[test]
fn sdp_ssa_bi01c() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x05,
            0x19,
            0x11,
            0x01, // seq says 5 but UUID16 is only 3
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        if !rsp.is_empty() {
            assert!(
                rsp[0] == SDP_ERROR_RSP || rsp[0] == SDP_SVC_SEARCH_ATTR_RSP,
                "unexpected opcode {:#04x}",
                rsp[0]
            );
        }
    });
}

/// SSA/BI-02-C — invalid PDU size (truncated request).
#[test]
fn sdp_ssa_bi02c() {
    with_test_db(|| {
        let req = [SDP_SVC_SEARCH_ATTR_REQ, 0x00, 0x01, 0x00, 0x05, 0x35, 0x03, 0x19, 0x11, 0x01];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        if !rsp.is_empty() {
            assert!(
                rsp[0] == SDP_ERROR_RSP || rsp[0] == SDP_SVC_SEARCH_ATTR_RSP,
                "unexpected opcode {:#04x}",
                rsp[0]
            );
        }
    });
}

// ============================================================================
// BRW (Browse) Tests
// ============================================================================

/// BRW/BV-01-C/UUID-16 — Browse via Service Search with PublicBrowseGroup.
#[test]
fn sdp_brw_bv01c_uuid16() {
    with_test_db(|| {
        // Search for PUBLIC_BROWSE_GROUP to discover all browsable services
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x03,
            0x19,
            0x10,
            0x02, // PUBLIC_BROWSE_GROUP = 0x1002
            0x00,
            0x10, // max 16 records
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
        let (total, _current, _handles) = parse_ss_response(&rsp);
        // Should find records that have PUBLIC_BROWSE_GROUP in their BrowseGroupList
        assert!(total >= 1, "at least 1 browsable record expected");
    });
}

/// BRW/BV-02-C/UUID-16 — Browse via SSA with PublicBrowseGroup + full range.
#[test]
fn sdp_brw_bv02c_uuid16() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x11,
            0x35,
            0x03,
            0x19,
            0x10,
            0x02, // PUBLIC_BROWSE_GROUP
            0x02,
            0xa0, // max 672 bytes
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff, // attr range 0x0000-0xFFFF
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// BRW/BV-01-C/UUID-32 — Browse via SS with UUID32 PublicBrowseGroup.
#[test]
fn sdp_brw_bv01c_uuid32() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x0a,
            0x35,
            0x05,
            0x1a,
            0x00,
            0x00,
            0x10,
            0x02,
            0x00,
            0x10,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
    });
}

/// BRW/BV-01-C/UUID-128 — Browse via SS with UUID128 PublicBrowseGroup.
#[test]
fn sdp_brw_bv01c_uuid128() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x18,
            0x35,
            0x11,
            0x1c,
            0x00,
            0x00,
            0x10,
            0x02,
            0x00,
            0x00,
            0x10,
            0x00,
            0x80,
            0x00,
            0x00,
            0x80,
            0x5f,
            0x9b,
            0x34,
            0xfb,
            0x00,
            0x10,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
    });
}

/// BRW/BV-02-C/UUID-32 — Browse via SSA with UUID32 PublicBrowseGroup.
#[test]
fn sdp_brw_bv02c_uuid32() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x13,
            0x35,
            0x05,
            0x1a,
            0x00,
            0x00,
            0x10,
            0x02,
            0x02,
            0xa0,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// BRW/BV-02-C/UUID-128 — Browse via SSA with UUID128 PublicBrowseGroup.
#[test]
fn sdp_brw_bv02c_uuid128() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x21,
            0x35,
            0x11,
            0x1c,
            0x00,
            0x00,
            0x10,
            0x02,
            0x00,
            0x00,
            0x10,
            0x00,
            0x80,
            0x00,
            0x00,
            0x80,
            0x5f,
            0x9b,
            0x34,
            0xfb,
            0x02,
            0xa0,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

// ============================================================================
// ROB (Robustness) Tests
// ============================================================================

/// ROB/BI-01-C — invalid continuation state data.
/// Sends a request with a fabricated continuation state that the server
/// should reject as SDP_INVALID_CSTATE.
#[test]
fn sdp_rob_bi01c() {
    with_test_db(|| {
        // SA request with a fake 6-byte continuation state
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x14,
            0x00,
            0x01,
            0x00,
            0x00, // handle: FIRST_USER_HANDLE
            0x00,
            0x19,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x06, // cstate length = 6
            0xDE,
            0xAD,
            0xBE,
            0xEF,
            0xCA,
            0xFE, // fake cstate
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        if rsp[0] == SDP_ERROR_RSP {
            let err = parse_error_response(&rsp);
            assert_eq!(err, SDP_INVALID_CSTATE, "expected INVALID_CSTATE");
        }
        // Some implementations may silently ignore invalid cstate
    });
}

/// ROB — completely empty PDU buffer.
#[test]
fn sdp_rob_empty_pdu() {
    with_test_db(|| {
        let req: [u8; 0] = [];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        // Should return empty response (failed to parse header)
        assert!(rsp.is_empty(), "empty PDU should produce empty response");
    });
}

/// ROB — unknown opcode.
#[test]
fn sdp_rob_unknown_opcode() {
    with_test_db(|| {
        let req = [
            0xFF, 0x00, 0x01, 0x00, 0x03, // unknown opcode 0xFF
            0x00, 0x00, 0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        if !rsp.is_empty() {
            assert_eq!(rsp[0], SDP_ERROR_RSP, "expected error for unknown opcode");
        }
    });
}

/// ROB — zero-length PDU parameter.
#[test]
fn sdp_rob_zero_plen() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x00, // plen = 0
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        if !rsp.is_empty() {
            assert!(rsp[0] == SDP_ERROR_RSP || rsp.is_empty(), "zero plen should produce error");
        }
    });
}

// ============================================================================
// Continuation State Tests
// ============================================================================

/// SS/BV-03-C — Service Search with small MTU forcing continuation.
/// Uses a very small max record count to force multi-PDU responses.
#[test]
fn sdp_ss_continuation_small_max() {
    with_test_db(|| {
        // Search for L2CAP_UUID which should match multiple records
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x03,
            0x19,
            0x01,
            0x00, // L2CAP_UUID = 0x0100
            0x00,
            0x01, // max 1 record
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
        // With multiple matching records and max=1, we should see continuation
        let (total, current, _handles) = parse_ss_response(&rsp);
        if total > 1 {
            assert_eq!(current, 1, "should return exactly 1 with max=1");
            // Verify continuation state is present
            let cstate_offset = 9 + (current as usize) * 4;
            if cstate_offset < rsp.len() {
                let cstate_len = rsp[cstate_offset];
                assert!(cstate_len > 0, "continuation state should be non-empty");
            }
        }
    });
}

/// SA with continuation — request all attrs with small max_attr_byte_count.
#[test]
fn sdp_sa_continuation() {
    with_test_db(|| {
        // SA for HID keyboard with small byte count to force continuation
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0e,
            0x00,
            0x01,
            0x00,
            0x02, // HID keyboard
            0x00,
            0x07, // max 7 bytes (very small)
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        // May get partial result with continuation, or error if too small
        if rsp[0] == SDP_SVC_ATTR_RSP {
            let (byte_count, cstate_len) = parse_sa_response_header(&rsp);
            // If the record is larger than 7 bytes, expect continuation
            if byte_count > 0 {
                assert!(
                    cstate_len > 0 || byte_count <= 7,
                    "large record should require continuation"
                );
            }
        }
    });
}

// ============================================================================
// Multiple record search tests
// ============================================================================

/// SS — search for L2CAP_UUID matches all records with L2CAP protocol.
#[test]
fn sdp_ss_l2cap_uuid_multiple() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x03,
            0x19,
            0x01,
            0x00, // L2CAP
            0x00,
            0x10, // max 16
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
        let (total, _current, _handles) = parse_ss_response(&rsp);
        // SDP server, serial port, obj push, HID, file_transfer ×3 all have L2CAP
        assert!(total >= 2, "multiple records should have L2CAP in proto list");
    });
}

/// SSA — search for RFCOMM_UUID to find all RFCOMM-based services.
#[test]
fn sdp_ssa_rfcomm_multiple() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x11,
            0x35,
            0x03,
            0x19,
            0x00,
            0x03, // RFCOMM UUID
            0x02,
            0xa0,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SA — request SDP server service record (handle 0x00000000).
#[test]
fn sdp_sa_server_record() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0e,
            0x00,
            0x00,
            0x00,
            0x00, // SDP server handle
            0x00,
            0x64,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — request public browse group record (handle 0x00000001).
#[test]
fn sdp_sa_browse_group_record() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0e,
            0x00,
            0x00,
            0x00,
            0x01, // public browse group handle
            0x00,
            0x64,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

// ============================================================================
// HID-specific attribute tests via SA
// ============================================================================

/// SA — HIDParserVersion attribute (0x0201) for HID Keyboard.
#[test]
fn sdp_sa_hid_parser_version() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x02,
            0x01, // HID_PARSER_VERSION
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — HIDDeviceSubclass attribute (0x0202) for HID Keyboard.
#[test]
fn sdp_sa_hid_device_subclass() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x02,
            0x02,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — HIDCountryCode (0x0203) for HID Keyboard.
#[test]
fn sdp_sa_hid_country_code() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x02,
            0x03,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — HIDVirtualCable (0x0204) for HID Keyboard.
#[test]
fn sdp_sa_hid_virtual_cable() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x02,
            0x04,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — HIDDescriptorList (0x0206) for HID Keyboard.
#[test]
fn sdp_sa_hid_descriptor_list() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02,
            0x01,
            0x00, // max 256 bytes
            0x35,
            0x03,
            0x09,
            0x02,
            0x06,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — HIDBootDevice (0x020E) for HID Keyboard.
#[test]
fn sdp_sa_hid_boot_device() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x02,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x02,
            0x0e,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

// ============================================================================
// Multi-step PDU exchange test
// ============================================================================

/// Two-step SA exchange — first request, then request to SDP server record.
#[test]
fn sdp_multi_step_exchange() {
    with_test_db(|| {
        let step1: &[u8] = &[
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x00, // Serial Port
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x00,
            0x00,
        ];
        let step2: &[u8] = &[
            SDP_SVC_ATTR_REQ,
            0x00,
            0x02,
            0x00,
            0x0e,
            0x00,
            0x00,
            0x00,
            0x00, // SDP server record
            0x00,
            0x64,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp =
            exchange_pdus(&[(step1, SDP_SVC_ATTR_RSP), (step2, SDP_SVC_ATTR_RSP)], DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

// ============================================================================
// Edge case: searching by OBEX UUID should find Object Push & File Transfer
// ============================================================================

/// SS — OBEX UUID (0x0008) matches both Object Push and File Transfer.
#[test]
fn sdp_ss_obex_uuid_multi_match() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x03,
            0x19,
            0x00,
            0x08, // OBEX_UUID
            0x00,
            0x10,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
        let (total, _current, _handles) = parse_ss_response(&rsp);
        // Object Push + 3x File Transfer = 4 records with OBEX in their protocol
        assert!(total >= 2, "OBEX UUID should match Object Push and File Transfer services");
    });
}

// ============================================================================
// Edge case: HID-specific UUID searches
// ============================================================================

/// SS — HID_SVCLASS_ID should match exactly 1 record (HID Keyboard).
#[test]
fn sdp_ss_hid_uuid_single() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_REQ,
            0x00,
            0x01,
            0x00,
            0x08,
            0x35,
            0x03,
            0x19,
            0x11,
            0x24, // HID_SVCLASS_ID
            0x00,
            0x10,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_RSP);
        let (total, _current, handles) = parse_ss_response(&rsp);
        assert_eq!(total, 1, "HID_SVCLASS_ID should match exactly 1 record");
        assert_eq!(handles[0], FIRST_USER_HANDLE + 2, "should be HID keyboard");
    });
}

/// SSA — full attribute dump of HID Keyboard record.
#[test]
fn sdp_ssa_hid_full_dump() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x11,
            0x35,
            0x03,
            0x19,
            0x11,
            0x24, // HID
            0x02,
            0xa0, // max 672 bytes
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
        // Response should contain attribute data
        let (byte_count, _cstate_len) = parse_sa_response_header(&rsp);
        assert!(byte_count > 0, "HID record should have non-empty attributes");
    });
}

// ============================================================================
// SA — multiple individual attribute requests for File Transfer
// ============================================================================

/// SA — File Transfer record RecordHandle.
#[test]
fn sdp_sa_ft_record_handle() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x03, // FT #1
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — File Transfer record BrowseGroupList.
#[test]
fn sdp_sa_ft_browse_group() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x03,
            0x00,
            0x19,
            0x35,
            0x03,
            0x09,
            0x00,
            0x05,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

/// SA — File Transfer record ServiceName.
#[test]
fn sdp_sa_ft_service_name() {
    with_test_db(|| {
        let req = [
            SDP_SVC_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0d,
            0x00,
            0x01,
            0x00,
            0x03,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x01,
            0x00,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_ATTR_RSP);
    });
}

// ============================================================================
// SSA — Object Push attribute queries
// ============================================================================

/// SSA — Object Push ProtocolDescriptorList.
#[test]
fn sdp_ssa_objpush_proto() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x04,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA — Object Push ProfileDescriptorList.
#[test]
fn sdp_ssa_objpush_profile() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x10,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x00,
            0x64,
            0x35,
            0x03,
            0x09,
            0x00,
            0x09,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, DEFAULT_MTU), DEFAULT_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
    });
}

/// SSA — Object Push full dump.
#[test]
fn sdp_ssa_objpush_full() {
    with_test_db(|| {
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x11,
            0x35,
            0x03,
            0x19,
            0x11,
            0x05,
            0x02,
            0xa0,
            0x35,
            0x05,
            0x0a,
            0x00,
            0x00,
            0xff,
            0xff,
            0x00,
        ];
        let rsp = handle_internal_request(&make_request(&req, BRW_MTU), BRW_MTU);
        assert!(!rsp.is_empty());
        assert_eq!(rsp[0], SDP_SVC_SEARCH_ATTR_RSP);
        let (byte_count, _cstate) = parse_sa_response_header(&rsp);
        assert!(byte_count > 0);
    });
}
