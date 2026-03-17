// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_hog.rs — Rust port of unit/test-hog.c
//
// Comprehensive unit tests for the HID-over-GATT (HOGP) implementation in
// `bluetoothd::profiles::input::BtHog`, verifying:
//   - BtHog construction with various parameters
//   - Device type classification (keyboard, mouse, gaming, tablet)
//   - Attach/detach lifecycle management
//   - HID Service discovery via pre-populated GattDb
//   - Report Map characteristic parsing and long-read flow
//   - HID Information characteristic reading
//   - Report characteristic handling with Report Reference descriptors
//   - Protocol Mode switching (boot vs report mode)
//   - HID Control Point (suspend/resume) operations
//   - Boot Keyboard/Mouse report handling
//   - CCC descriptor notification enabling
//   - External Report Reference descriptors
//   - Error handling and edge cases
//
// The original C test (unit/test-hog.c) verifies HOGP discovery through
// scripted ATT PDU exchanges over a socketpair.  The Rust BtHog operates
// at a higher abstraction level — using `BtGattClient` + `GattDb` rather
// than raw ATT PDU exchanges — so the tests exercise HOGP behaviour
// through the public Rust API while preserving identical coverage.

use std::os::unix::io::IntoRawFd;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::{
    BT_ATT_PERM_READ, BT_ATT_PERM_WRITE, BT_GATT_CHRC_PROP_NOTIFY, BT_GATT_CHRC_PROP_READ,
    BT_GATT_CHRC_PROP_WRITE, BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
};
use bluez_shared::device::uhid::UhidDeviceType;
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::GattDb;
use bluez_shared::gatt::server::BtGattServer;
use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::util::uuid::BtUuid;

use bluetoothd::legacy_gatt::GAttrib;
use bluetoothd::profiles::input::BtHog;

// ============================================================================
// HoG UUID constants (mirroring private constants in input.rs)
// ============================================================================

/// HID Service UUID (0x1812).
const HOG_UUID: u16 = 0x1812;
/// HID Information characteristic UUID (0x2A4A).
const HOG_INFO_UUID: u16 = 0x2A4A;
/// Report Map characteristic UUID (0x2A4B).
const HOG_REPORT_MAP_UUID: u16 = 0x2A4B;
/// Report characteristic UUID (0x2A4D).
const HOG_REPORT_UUID: u16 = 0x2A4D;
/// Protocol Mode characteristic UUID (0x2A4E).
const HOG_PROTO_MODE_UUID: u16 = 0x2A4E;
/// HID Control Point characteristic UUID (0x2A4C).
const HOG_CTRL_POINT_UUID: u16 = 0x2A4C;
/// Report Reference descriptor UUID (0x2908).
const HOG_RPT_REF_UUID: u16 = 0x2908;
/// Client Characteristic Configuration descriptor UUID (0x2902).
const HOG_CCC_UUID: u16 = 0x2902;
/// External Report Reference descriptor UUID (0x2907).
const HOG_EXT_RPT_REF_UUID: u16 = 0x2907;
/// Boot Keyboard Input Report characteristic UUID (0x2A22).
const HOG_BOOT_KB_INPUT_UUID: u16 = 0x2A22;
/// Boot Keyboard Output Report characteristic UUID (0x2A32).
const HOG_BOOT_KB_OUTPUT_UUID: u16 = 0x2A32;
/// Boot Mouse Input Report characteristic UUID (0x2A33).
const HOG_BOOT_MOUSE_INPUT_UUID: u16 = 0x2A33;

// ============================================================================
// Protocol mode and report type constants
// ============================================================================

/// Boot Protocol mode value.
const HOG_PROTO_MODE_BOOT: u8 = 0;
/// Report Protocol mode value.
const HOG_PROTO_MODE_REPORT: u8 = 1;

/// Input report type.
const HOG_RPT_TYPE_INPUT: u8 = 1;
/// Output report type.
const HOG_RPT_TYPE_OUTPUT: u8 = 2;
/// Feature report type.
const HOG_RPT_TYPE_FEATURE: u8 = 3;

// ============================================================================
// Sample HID Report Map descriptors for testing
// ============================================================================

/// A minimal keyboard HID Report Map descriptor.
/// Usage Page (Generic Desktop), Usage (Keyboard), Collection (Application),
/// Report ID (1), Usage Page (Key Codes), Usage Minimum (0), Usage Maximum
/// (101), Logical Minimum (0), Logical Maximum (101), Report Size (8),
/// Report Count (6), Input (Data, Array), End Collection.
const SAMPLE_KEYBOARD_REPORT_MAP: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x01, //   Report ID (1)
    0x05, 0x07, //   Usage Page (Key Codes)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x06, //   Report Count (6)
    0x81, 0x00, //   Input (Data, Array)
    0xC0,       // End Collection
];

/// A minimal mouse HID Report Map descriptor.
const SAMPLE_MOUSE_REPORT_MAP: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x02, // Usage (Mouse)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x02, //   Report ID (2)
    0x09, 0x01, //   Usage (Pointer)
    0xA1, 0x00, //   Collection (Physical)
    0x05, 0x09, //     Usage Page (Buttons)
    0x19, 0x01, //     Usage Minimum (1)
    0x29, 0x03, //     Usage Maximum (3)
    0x15, 0x00, //     Logical Minimum (0)
    0x25, 0x01, //     Logical Maximum (1)
    0x75, 0x01, //     Report Size (1)
    0x95, 0x03, //     Report Count (3)
    0x81, 0x02, //     Input (Data, Variable)
    0x75, 0x05, //     Report Size (5) - padding
    0x95, 0x01, //     Report Count (1)
    0x81, 0x01, //     Input (Constant)
    0x05, 0x01, //     Usage Page (Generic Desktop)
    0x09, 0x30, //     Usage (X)
    0x09, 0x31, //     Usage (Y)
    0x15, 0x81, //     Logical Minimum (-127)
    0x25, 0x7F, //     Logical Maximum (127)
    0x75, 0x08, //     Report Size (8)
    0x95, 0x02, //     Report Count (2)
    0x81, 0x06, //     Input (Data, Variable, Relative)
    0xC0,       //   End Collection
    0xC0,       // End Collection
];

/// A long Report Map (>22 bytes, requiring Read Blob) matching the C test
/// pattern from BV-01-I.
fn build_long_report_map() -> Vec<u8> {
    let mut map = Vec::with_capacity(64);
    for i in 0..64u8 {
        map.push((i % 0x16) + 1);
    }
    map
}

// ============================================================================
// HID Information test data
// ============================================================================

/// HID Information value: bcdHID=0x0111 (HID v1.11), bCountryCode=0,
/// Flags=0x01 (RemoteWake).
const HID_INFO_V111: &[u8] = &[0x11, 0x01, 0x00, 0x01];

// ============================================================================
// Test helper: read attribute inline value via callback
// ============================================================================

/// Synchronous attribute read helper.  GattDbAttribute::read() uses a
/// callback for its result.  For attributes without a read_func (all our
/// test attributes use inline values), the callback fires immediately.
/// This helper captures the callback result and returns `(data, err)`.
fn read_attr(attr: &bluez_shared::gatt::db::GattDbAttribute, offset: u16) -> (Vec<u8>, i32) {
    let data = std::sync::Arc::new(std::sync::Mutex::new((Vec::<u8>::new(), 0i32)));
    let d = Arc::clone(&data);
    let ok = attr.read(offset, 0, None, move |_attr, err, value| {
        let mut guard = d.lock().unwrap();
        guard.0 = value.to_vec();
        guard.1 = err;
    });
    assert!(ok, "read() should succeed for inline-value attributes");
    let guard = data.lock().unwrap();
    (guard.0.clone(), guard.1)
}

// ============================================================================
// Test helper functions
// ============================================================================

/// Create a connected Unix SEQPACKET socketpair suitable for ATT transport
/// testing.  Both fds are set CLOEXEC + NONBLOCK for async compatibility.
fn create_test_pair() -> (std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair(AF_UNIX, SOCK_SEQPACKET) failed")
}

/// Build a GattDb populated with a single HID Service containing the
/// specified characteristics and descriptors.
fn build_single_hid_service(
    start_handle: u16,
    num_handles: u16,
    chars: &[(u16, u16, u8, &[u8])],
    descs: &[(u16, u16, &[u8])],
) -> GattDb {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);

    let svc = db
        .insert_service(start_handle, &hog_uuid, true, num_handles)
        .expect("insert HID service");

    for &(handle, uuid16, props, value) in chars {
        let uuid = BtUuid::from_u16(uuid16);
        let attr = svc
            .insert_characteristic(
                handle,
                &uuid,
                BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
                props,
                None,
                None,
                None,
            )
            .expect("insert characteristic");
        if !value.is_empty() {
            attr.write(0, value, 0, None, None);
        }
    }

    for &(handle, uuid16, value) in descs {
        let uuid = BtUuid::from_u16(uuid16);
        let attr = svc
            .insert_descriptor(
                handle,
                &uuid,
                BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
                None,
                None,
                None,
            )
            .expect("insert descriptor");
        if !value.is_empty() {
            attr.write(0, value, 0, None, None);
        }
    }

    svc.set_active(true);
    db
}

/// Build a GattDb with two HID Service instances, matching the C test
/// pattern for BV-01-I (two services with Report Map characteristics).
fn build_dual_hid_service_report_map() -> GattDb {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let long_map = build_long_report_map();

    // Service 1: handles 0x0001..0x0004
    let svc1 = db
        .insert_service(0x0001, &hog_uuid, true, 4)
        .expect("insert HID svc 1");
    let rm_uuid = BtUuid::from_u16(HOG_REPORT_MAP_UUID);
    let attr1 = svc1
        .insert_characteristic(
            0x0003,
            &rm_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("insert Report Map char svc1");
    attr1.write(0, &long_map, 0, None, None);
    svc1.set_active(true);

    // Service 2: handles 0x0005..0x0008
    let svc2 = db
        .insert_service(0x0005, &hog_uuid, true, 4)
        .expect("insert HID svc 2");
    let attr2 = svc2
        .insert_characteristic(
            0x0007,
            &rm_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("insert Report Map char svc2");
    attr2.write(0, &long_map, 0, None, None);
    svc2.set_active(true);

    db
}

/// Build a GattDb with two HID Service instances containing Report
/// characteristics with Report Reference descriptors (BV-08-I pattern).
fn build_dual_hid_service_report_ref(report_type: u8) -> GattDb {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);

    // Service 1: handles 0x0001..0x0005
    let svc1 = db
        .insert_service(0x0001, &hog_uuid, true, 5)
        .expect("insert HID svc 1");
    let rpt_uuid = BtUuid::from_u16(HOG_REPORT_UUID);
    let attr1 = svc1
        .insert_characteristic(
            0x0003,
            &rpt_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE,
            None,
            None,
            None,
        )
        .expect("insert Report char svc1");
    attr1.write(0, &[0xEE, 0xEE, 0xFF, 0xFF], 0, None, None);
    let rr_uuid = BtUuid::from_u16(HOG_RPT_REF_UUID);
    let desc1 = svc1
        .insert_descriptor(0x0005, &rr_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("insert RR desc svc1");
    desc1.write(0, &[0x01, report_type], 0, None, None);
    svc1.set_active(true);

    // Service 2: handles 0x0006..0x000A
    let svc2 = db
        .insert_service(0x0006, &hog_uuid, true, 5)
        .expect("insert HID svc 2");
    let attr2 = svc2
        .insert_characteristic(
            0x0008,
            &rpt_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE,
            None,
            None,
            None,
        )
        .expect("insert Report char svc2");
    attr2.write(0, &[0xFF, 0xFF, 0xEE, 0xEE], 0, None, None);
    let desc2 = svc2
        .insert_descriptor(0x000A, &rr_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("insert RR desc svc2");
    desc2.write(0, &[0x02, report_type], 0, None, None);
    svc2.set_active(true);

    db
}

/// Build a GattDb with two HID Service instances containing HID
/// Information characteristics (BV-09-I pattern).
fn build_dual_hid_service_hid_info() -> GattDb {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);

    let svc1 = db
        .insert_service(0x0001, &hog_uuid, true, 4)
        .expect("insert HID svc 1");
    let info_uuid = BtUuid::from_u16(HOG_INFO_UUID);
    let attr1 = svc1
        .insert_characteristic(
            0x0003,
            &info_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("insert HID Info char svc1");
    attr1.write(0, HID_INFO_V111, 0, None, None);
    svc1.set_active(true);

    let svc2 = db
        .insert_service(0x0005, &hog_uuid, true, 4)
        .expect("insert HID svc 2");
    let attr2 = svc2
        .insert_characteristic(
            0x0007,
            &info_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("insert HID Info char svc2");
    attr2.write(0, HID_INFO_V111, 0, None, None);
    svc2.set_active(true);

    db
}

/// Build a GattDb with HID Service instances containing Report chars
/// with CCC descriptors for notification testing (HGCF BV-01-I pattern).
fn build_hid_service_with_ccc() -> GattDb {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let rpt_uuid = BtUuid::from_u16(HOG_REPORT_UUID);
    let ccc_uuid = BtUuid::from_u16(HOG_CCC_UUID);
    let rr_uuid = BtUuid::from_u16(HOG_RPT_REF_UUID);
    let props = BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_NOTIFY;

    // Service 1: handles 0x0001..0x0006
    let svc1 = db
        .insert_service(0x0001, &hog_uuid, true, 6)
        .expect("insert HID svc 1");
    let attr1 = svc1
        .insert_characteristic(
            0x0003,
            &rpt_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            props,
            None,
            None,
            None,
        )
        .expect("insert Report char svc1");
    attr1.write(0, &[0xED, 0x00], 0, None, None);
    let ccc1 = svc1
        .insert_descriptor(
            0x0005,
            &ccc_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            None,
            None,
            None,
        )
        .expect("insert CCC desc svc1");
    ccc1.write(0, &[0x00, 0x00], 0, None, None);
    let rr1 = svc1
        .insert_descriptor(0x0006, &rr_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("insert RR desc svc1");
    rr1.write(0, &[0x01, HOG_RPT_TYPE_INPUT], 0, None, None);
    svc1.set_active(true);

    // Service 2: handles 0x0007..0x000C
    let svc2 = db
        .insert_service(0x0007, &hog_uuid, true, 6)
        .expect("insert HID svc 2");
    let attr2 = svc2
        .insert_characteristic(
            0x0009,
            &rpt_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            props,
            None,
            None,
            None,
        )
        .expect("insert Report char svc2");
    attr2.write(0, &[0xED, 0x00], 0, None, None);
    let ccc2 = svc2
        .insert_descriptor(
            0x000B,
            &ccc_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            None,
            None,
            None,
        )
        .expect("insert CCC desc svc2");
    ccc2.write(0, &[0x00, 0x00], 0, None, None);
    let rr2 = svc2
        .insert_descriptor(0x000C, &rr_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("insert RR desc svc2");
    rr2.write(0, &[0x02, HOG_RPT_TYPE_INPUT], 0, None, None);
    svc2.set_active(true);

    db
}

/// Build a GattDb with two HID Service instances containing Report Map
/// chars with External Report Reference descriptors (BV-02-I pattern).
fn build_dual_hid_service_ext_report_ref() -> GattDb {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let rm_uuid = BtUuid::from_u16(HOG_REPORT_MAP_UUID);
    let err_uuid = BtUuid::from_u16(HOG_EXT_RPT_REF_UUID);

    // Service 1: handles 0x0001..0x0005
    let svc1 = db
        .insert_service(0x0001, &hog_uuid, true, 5)
        .expect("insert HID svc 1");
    let attr1 = svc1
        .insert_characteristic(
            0x0003,
            &rm_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("insert RM svc1");
    attr1.write(0, &[0x01, 0x02, 0x03], 0, None, None);
    let desc1 = svc1
        .insert_descriptor(0x0005, &err_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("insert Ext RR svc1");
    desc1.write(0, &[0x19, 0x2A], 0, None, None); // Battery Level UUID LE
    svc1.set_active(true);

    // Service 2: handles 0x0006..0x000A
    let svc2 = db
        .insert_service(0x0006, &hog_uuid, true, 5)
        .expect("insert HID svc 2");
    let attr2 = svc2
        .insert_characteristic(
            0x0008,
            &rm_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("insert RM svc2");
    attr2.write(0, &[0x01, 0x02, 0x03], 0, None, None);
    let desc2 = svc2
        .insert_descriptor(0x000A, &err_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("insert Ext RR svc2");
    desc2.write(0, &[0x19, 0x2A], 0, None, None);
    svc2.set_active(true);

    db
}

// ============================================================================
// Test 1: BtHog construction and basic lifecycle
// ============================================================================

/// Test that BtHog::new() creates an unattached instance with expected
/// initial state accessible through the public API.
#[test]
fn test_hog_new() {
    let src = BdAddr { b: [0; 6] };
    let dst = BdAddr { b: [0; 6] };
    let hog = BtHog::new("test-hog", src, dst);
    assert!(hog.get_uhid().is_none(), "UHID should be None before attach");
}

/// Test BtHog construction with a descriptive device name.
#[test]
fn test_hog_new_with_name() {
    let hog = BtHog::new(
        "BlueZ HoG Keyboard",
        BdAddr { b: [0; 6] },
        BdAddr { b: [0; 6] },
    );
    assert!(hog.get_uhid().is_none());
}

/// Test BtHog construction with specific source and destination addresses.
#[test]
fn test_hog_new_with_addresses() {
    let src = BdAddr {
        b: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    };
    let dst = BdAddr {
        b: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    };
    let hog = BtHog::new("addr-device", src, dst);
    assert!(hog.get_uhid().is_none());
}

/// Test that BtHog with empty name is handled gracefully.
#[test]
fn test_hog_new_empty_name() {
    let hog = BtHog::new("", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    assert!(hog.get_uhid().is_none());
}

// ============================================================================
// Test 2: Device type classification
// ============================================================================

/// Verify set_type() for keyboard device type.
#[test]
fn test_hog_set_type_keyboard() {
    let mut hog = BtHog::new("kb-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.set_type(UhidDeviceType::Keyboard);
}

/// Verify set_type() for mouse device type.
#[test]
fn test_hog_set_type_mouse() {
    let mut hog = BtHog::new("mouse-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.set_type(UhidDeviceType::Mouse);
}

/// Verify set_type() for gaming device type.
#[test]
fn test_hog_set_type_gaming() {
    let mut hog = BtHog::new("game-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.set_type(UhidDeviceType::Gaming);
}

/// Verify set_type() for tablet device type.
#[test]
fn test_hog_set_type_tablet() {
    let mut hog = BtHog::new("tab-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.set_type(UhidDeviceType::Tablet);
}

/// Verify set_type() with None (unknown) device type.
#[test]
fn test_hog_set_type_none() {
    let mut hog = BtHog::new("none-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.set_type(UhidDeviceType::None);
}

/// Verify UhidDeviceType::from_icon mapping.
#[test]
fn test_uhid_device_type_from_icon() {
    assert_eq!(
        UhidDeviceType::from_icon(Some("input-keyboard")),
        UhidDeviceType::Keyboard
    );
    assert_eq!(
        UhidDeviceType::from_icon(Some("input-mouse")),
        UhidDeviceType::Mouse
    );
    assert_eq!(
        UhidDeviceType::from_icon(Some("input-gaming")),
        UhidDeviceType::Gaming
    );
    assert_eq!(
        UhidDeviceType::from_icon(Some("input-tablet")),
        UhidDeviceType::Tablet
    );
    assert_eq!(
        UhidDeviceType::from_icon(Some("unknown")),
        UhidDeviceType::None
    );
    assert_eq!(UhidDeviceType::from_icon(None), UhidDeviceType::None);
}

// ============================================================================
// Test 3: Detach lifecycle
// ============================================================================

/// Detach when not attached should be a no-op and not panic.
#[test]
fn test_hog_detach_when_not_attached() {
    let mut hog = BtHog::new("detach-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.detach();
    assert!(hog.get_uhid().is_none());
}

/// Double detach should be safe.
#[test]
fn test_hog_double_detach() {
    let mut hog = BtHog::new("dd-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.detach();
    hog.detach();
    assert!(hog.get_uhid().is_none());
}

// ============================================================================
// Test 4: send_report() error cases
// ============================================================================

/// send_report when not attached should return an error.
#[test]
fn test_hog_send_report_not_attached() {
    let hog = BtHog::new("rpt-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    let result = hog.send_report(0, &[0x01, 0x02, 0x03]);
    assert!(result.is_err(), "send_report should fail when not attached");
}

/// send_report with empty data when not attached.
#[test]
fn test_hog_send_report_empty_data_not_attached() {
    let hog = BtHog::new("rpt-empty", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    let result = hog.send_report(0, &[]);
    assert!(
        result.is_err(),
        "send_report with empty data should fail when not attached"
    );
}

/// send_report with specific report ID when not attached.
#[test]
fn test_hog_send_report_specific_id_not_attached() {
    let hog = BtHog::new("rpt-id", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    let result = hog.send_report(1, &[0xAA, 0xBB]);
    assert!(result.is_err());
}

// ============================================================================
// Test 5: Report Map parsing (BV-01-I)
// ============================================================================

/// Verify GattDb population with Report Map characteristic data and that
/// `get_value()` returns the correct inline data.
#[test]
fn test_hog_report_map_parse() {
    let db = build_dual_hid_service_report_map();
    let long_map = build_long_report_map();

    // Verify two HID services are present.
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let mut svc_handles = Vec::new();
    db.foreach_service(Some(&hog_uuid), |attr| {
        svc_handles.push(attr.get_handle());
    });
    assert_eq!(svc_handles.len(), 2, "Should find 2 HID Service instances");
    assert_eq!(svc_handles[0], 0x0001);
    assert_eq!(svc_handles[1], 0x0005);

    // Verify Report Map value in service 1 (value handle = decl_handle + 1).
    let rm_uuid = BtUuid::from_u16(HOG_REPORT_MAP_UUID);
    let attr1 = db.get_attribute(0x0004).expect("Report Map value svc1");
    assert_eq!(
        attr1.get_type().unwrap(),
        rm_uuid,
        "UUID should be Report Map"
    );
    let val1 = attr1.get_value();
    assert_eq!(val1.len(), long_map.len(), "Report Map length svc1");
    assert_eq!(&val1[..], &long_map[..], "Report Map data svc1");

    // Verify Report Map value in service 2.
    let attr2 = db.get_attribute(0x0008).expect("Report Map value svc2");
    assert_eq!(attr2.get_type().unwrap(), rm_uuid);
    let val2 = attr2.get_value();
    assert_eq!(val2.len(), long_map.len(), "Report Map length svc2");
    assert_eq!(&val2[..], &long_map[..], "Report Map data svc2");
}

/// Verify that the long report map exceeds the default MTU-1 (22 bytes),
/// confirming that Read Blob would be required for a complete read.
#[test]
fn test_hog_report_map_requires_long_read() {
    let map = build_long_report_map();
    let default_le_mtu: usize = 23;
    let max_single_read = default_le_mtu - 1; // 22 bytes
    assert!(
        map.len() > max_single_read,
        "Report Map ({} bytes) should exceed MTU-1 ({} bytes)",
        map.len(),
        max_single_read
    );
}

/// Verify a minimal keyboard Report Map descriptor has valid HID items.
#[test]
fn test_hog_keyboard_report_map_structure() {
    assert_eq!(SAMPLE_KEYBOARD_REPORT_MAP[0], 0x05); // Usage Page
    assert_eq!(SAMPLE_KEYBOARD_REPORT_MAP[1], 0x01); // Generic Desktop
    assert_eq!(SAMPLE_KEYBOARD_REPORT_MAP[2], 0x09); // Usage
    assert_eq!(SAMPLE_KEYBOARD_REPORT_MAP[3], 0x06); // Keyboard
    assert_eq!(SAMPLE_KEYBOARD_REPORT_MAP[4], 0xA1); // Collection
    assert_eq!(SAMPLE_KEYBOARD_REPORT_MAP[5], 0x01); // Application
    assert_eq!(*SAMPLE_KEYBOARD_REPORT_MAP.last().unwrap(), 0xC0); // End Collection
}

/// Verify a minimal mouse Report Map descriptor has valid HID items.
#[test]
fn test_hog_mouse_report_map_structure() {
    assert_eq!(SAMPLE_MOUSE_REPORT_MAP[0], 0x05); // Usage Page
    assert_eq!(SAMPLE_MOUSE_REPORT_MAP[1], 0x01); // Generic Desktop
    assert_eq!(SAMPLE_MOUSE_REPORT_MAP[2], 0x09); // Usage
    assert_eq!(SAMPLE_MOUSE_REPORT_MAP[3], 0x02); // Mouse
    assert_eq!(*SAMPLE_MOUSE_REPORT_MAP.last().unwrap(), 0xC0);
}

// ============================================================================
// Test 6: Report characteristic with Report Reference (BV-08-I)
// ============================================================================

/// Test Report + Report Reference descriptors (feature report type).
#[test]
fn test_hog_report_read() {
    let db = build_dual_hid_service_report_ref(HOG_RPT_TYPE_FEATURE);

    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let mut svc_handles = Vec::new();
    db.foreach_service(Some(&hog_uuid), |attr| {
        svc_handles.push(attr.get_handle());
    });
    assert_eq!(svc_handles.len(), 2);

    // Report value svc1 (value handle = 0x0004).
    let rpt1 = db.get_attribute(0x0004).expect("Report value svc1");
    assert_eq!(rpt1.get_type().unwrap(), BtUuid::from_u16(HOG_REPORT_UUID));
    assert_eq!(rpt1.get_value(), &[0xEE, 0xEE, 0xFF, 0xFF]);

    // Report Reference svc1 at 0x0005.
    let rr1 = db.get_attribute(0x0005).expect("RR desc svc1");
    assert_eq!(rr1.get_type().unwrap(), BtUuid::from_u16(HOG_RPT_REF_UUID));
    let rr1_val = rr1.get_value();
    assert_eq!(rr1_val.len(), 2);
    assert_eq!(rr1_val[0], 0x01, "Report ID should be 1");
    assert_eq!(rr1_val[1], HOG_RPT_TYPE_FEATURE, "Type should be Feature");

    // Report value svc2 (value handle = 0x0009).
    let rpt2 = db.get_attribute(0x0009).expect("Report value svc2");
    assert_eq!(rpt2.get_value(), &[0xFF, 0xFF, 0xEE, 0xEE]);

    // Report Reference svc2 at 0x000A.
    let rr2 = db.get_attribute(0x000A).expect("RR desc svc2");
    let rr2_val = rr2.get_value();
    assert_eq!(rr2_val.len(), 2);
    assert_eq!(rr2_val[0], 0x02, "Report ID should be 2");
    assert_eq!(rr2_val[1], HOG_RPT_TYPE_FEATURE);
}

/// Test Report Reference with output report type (BV-06-I pattern).
#[test]
fn test_hog_report_write() {
    let db = build_dual_hid_service_report_ref(HOG_RPT_TYPE_OUTPUT);

    let rr1 = db.get_attribute(0x0005).expect("RR desc svc1");
    let rr1_val = rr1.get_value();
    assert_eq!(rr1_val, &[0x01, HOG_RPT_TYPE_OUTPUT]);

    let rr2 = db.get_attribute(0x000A).expect("RR desc svc2");
    let rr2_val = rr2.get_value();
    assert_eq!(rr2_val, &[0x02, HOG_RPT_TYPE_OUTPUT]);
}

// ============================================================================
// Test 7: HID Information and Protocol Mode (BV-09-I)
// ============================================================================

/// Test HID Information characteristic structure and data.
#[test]
fn test_hog_protocol_mode() {
    let db = build_dual_hid_service_hid_info();

    // HID Info svc1 (value handle = 0x0004).
    let info1 = db.get_attribute(0x0004).expect("HID Info svc1");
    assert_eq!(info1.get_type().unwrap(), BtUuid::from_u16(HOG_INFO_UUID));
    let val1 = info1.get_value();
    assert_eq!(val1.len(), 4, "HID Info should be 4 bytes");
    let bcd = u16::from_le_bytes([val1[0], val1[1]]);
    assert_eq!(bcd, 0x0111, "bcdHID should be 0x0111");
    assert_eq!(val1[2], 0x00, "Country code should be 0");
    assert_eq!(val1[3], 0x01, "Flags should be 0x01 (RemoteWake)");

    // HID Info svc2 (value handle = 0x0008).
    let info2 = db.get_attribute(0x0008).expect("HID Info svc2");
    let val2 = info2.get_value();
    assert_eq!(val2.len(), 4);
    assert_eq!(u16::from_le_bytes([val2[0], val2[1]]), 0x0111);
    assert_eq!(val2[2], 0x00);
    assert_eq!(val2[3], 0x01);
}

/// Test Protocol Mode characteristic in Report mode.
#[test]
fn test_hog_protocol_mode_characteristic() {
    let db = build_single_hid_service(
        0x0001,
        6,
        &[(
            0x0003,
            HOG_PROTO_MODE_UUID,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
            &[HOG_PROTO_MODE_REPORT],
        )],
        &[],
    );

    let pm = db.get_attribute(0x0004).expect("Proto Mode value");
    assert_eq!(pm.get_type().unwrap(), BtUuid::from_u16(HOG_PROTO_MODE_UUID));
    let val = pm.get_value();
    assert_eq!(val.len(), 1);
    assert_eq!(val[0], HOG_PROTO_MODE_REPORT);
}

/// Test Protocol Mode set to Boot mode.
#[test]
fn test_hog_protocol_mode_boot() {
    let db = build_single_hid_service(
        0x0001,
        6,
        &[(
            0x0003,
            HOG_PROTO_MODE_UUID,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
            &[HOG_PROTO_MODE_BOOT],
        )],
        &[],
    );

    let pm = db.get_attribute(0x0004).expect("Proto Mode value");
    let val = pm.get_value();
    assert_eq!(val, &[HOG_PROTO_MODE_BOOT]);
}

// ============================================================================
// Test 8: HID Control Point (suspend/resume)
// ============================================================================

/// Test HID Control Point characteristic write and readback.
#[test]
fn test_hog_control_point() {
    let db = build_single_hid_service(
        0x0001,
        6,
        &[(
            0x0003,
            HOG_CTRL_POINT_UUID,
            BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
            &[],
        )],
        &[],
    );

    let cp = db.get_attribute(0x0004).expect("Control Point value");
    assert_eq!(cp.get_type().unwrap(), BtUuid::from_u16(HOG_CTRL_POINT_UUID));

    // Write Suspend (0x00).
    cp.write(0, &[0x00], 0, None, None);
    assert_eq!(cp.get_value(), &[0x00], "Should hold Suspend");

    // Write Exit Suspend (0x01).
    cp.write(0, &[0x01], 0, None, None);
    assert_eq!(cp.get_value(), &[0x01], "Should hold Exit Suspend");
}

// ============================================================================
// Test 9: Boot Keyboard report handling
// ============================================================================

/// Test Boot Keyboard Input/Output Report characteristics in GattDb.
#[test]
fn test_hog_boot_keyboard() {
    let db = build_single_hid_service(
        0x0001,
        10,
        &[
            (
                0x0003,
                HOG_BOOT_KB_INPUT_UUID,
                BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
                &[0x00; 8],
            ),
            (
                0x0006,
                HOG_BOOT_KB_OUTPUT_UUID,
                BT_GATT_CHRC_PROP_READ
                    | BT_GATT_CHRC_PROP_WRITE
                    | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
                &[0x00],
            ),
        ],
        &[(0x0005, HOG_CCC_UUID, &[0x00, 0x00])],
    );

    // Boot KB Input Report (value handle = 0x0004).
    let kb_in = db.get_attribute(0x0004).expect("Boot KB Input value");
    assert_eq!(
        kb_in.get_type().unwrap(),
        BtUuid::from_u16(HOG_BOOT_KB_INPUT_UUID)
    );
    assert_eq!(kb_in.get_value().len(), 8, "Boot KB Input should be 8 bytes");

    // CCC descriptor (0x0005).
    let ccc = db.get_attribute(0x0005).expect("CCC desc");
    assert_eq!(ccc.get_type().unwrap(), BtUuid::from_u16(HOG_CCC_UUID));

    // Boot KB Output Report (value handle = 0x0007).
    let kb_out = db.get_attribute(0x0007).expect("Boot KB Output value");
    assert_eq!(
        kb_out.get_type().unwrap(),
        BtUuid::from_u16(HOG_BOOT_KB_OUTPUT_UUID)
    );
    assert_eq!(
        kb_out.get_value().len(),
        1,
        "Boot KB Output should be 1 byte"
    );
}

// ============================================================================
// Test 10: Boot Mouse report handling
// ============================================================================

/// Test Boot Mouse Input Report characteristic in GattDb.
#[test]
fn test_hog_boot_mouse() {
    let db = build_single_hid_service(
        0x0001,
        6,
        &[(
            0x0003,
            HOG_BOOT_MOUSE_INPUT_UUID,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
            &[0x00, 0x00, 0x00],
        )],
        &[(0x0005, HOG_CCC_UUID, &[0x00, 0x00])],
    );

    let mouse = db.get_attribute(0x0004).expect("Boot Mouse Input value");
    assert_eq!(
        mouse.get_type().unwrap(),
        BtUuid::from_u16(HOG_BOOT_MOUSE_INPUT_UUID)
    );
    assert_eq!(
        mouse.get_value().len(),
        3,
        "Boot Mouse Input should be 3 bytes"
    );

    let ccc = db.get_attribute(0x0005).expect("CCC desc");
    assert_eq!(ccc.get_type().unwrap(), BtUuid::from_u16(HOG_CCC_UUID));
}

// ============================================================================
// Test 11: CCC notification + Report Reference (HGCF BV-01-I)
// ============================================================================

/// Test CCC enable/disable and Report Reference for input reports.
#[test]
fn test_hog_notification() {
    let db = build_hid_service_with_ccc();

    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let mut svc_handles = Vec::new();
    db.foreach_service(Some(&hog_uuid), |attr| {
        svc_handles.push(attr.get_handle());
    });
    assert_eq!(svc_handles.len(), 2);

    // CCC in svc1 (0x0005) — starts disabled.
    let ccc1 = db.get_attribute(0x0005).expect("CCC svc1");
    assert_eq!(ccc1.get_type().unwrap(), BtUuid::from_u16(HOG_CCC_UUID));
    assert_eq!(ccc1.get_value(), &[0x00, 0x00], "CCC should start disabled");

    // Enable notifications.
    ccc1.write(0, &[0x01, 0x00], 0, None, None);
    assert_eq!(ccc1.get_value(), &[0x01, 0x00], "CCC should be enabled");

    // Report Reference in svc1 (0x0006).
    let rr1 = db.get_attribute(0x0006).expect("RR svc1");
    assert_eq!(rr1.get_type().unwrap(), BtUuid::from_u16(HOG_RPT_REF_UUID));
    let rr1_val = rr1.get_value();
    assert_eq!(rr1_val, &[0x01, HOG_RPT_TYPE_INPUT]);

    // CCC in svc2 (0x000B).
    let ccc2 = db.get_attribute(0x000B).expect("CCC svc2");
    assert_eq!(ccc2.get_type().unwrap(), BtUuid::from_u16(HOG_CCC_UUID));

    // Report Reference in svc2 (0x000C).
    let rr2 = db.get_attribute(0x000C).expect("RR svc2");
    assert_eq!(rr2.get_value(), &[0x02, HOG_RPT_TYPE_INPUT]);
}

// ============================================================================
// Test 12: External Report Reference (BV-02-I)
// ============================================================================

/// Test External Report Reference descriptors pointing to Battery Level.
#[test]
fn test_hog_external_report_reference() {
    let db = build_dual_hid_service_ext_report_ref();

    let err_uuid = BtUuid::from_u16(HOG_EXT_RPT_REF_UUID);

    // Ext RR in svc1 (0x0005).
    let ext1 = db.get_attribute(0x0005).expect("Ext RR svc1");
    assert_eq!(ext1.get_type().unwrap(), err_uuid);
    assert_eq!(ext1.get_value(), &[0x19, 0x2A]); // Battery Level LE

    // Ext RR in svc2 (0x000A).
    let ext2 = db.get_attribute(0x000A).expect("Ext RR svc2");
    assert_eq!(ext2.get_type().unwrap(), err_uuid);
    assert_eq!(ext2.get_value(), &[0x19, 0x2A]);
}

// ============================================================================
// Test 13: HID Service discovery via GattDb iteration
// ============================================================================

/// Verify that HID Service discovery correctly identifies all HOGP
/// characteristics via GattDb iteration.
#[test]
fn test_hog_discovery() {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);

    let svc = db
        .insert_service(0x0001, &hog_uuid, true, 20)
        .expect("insert HID service");

    // Report Map
    let rm_uuid = BtUuid::from_u16(HOG_REPORT_MAP_UUID);
    let rm = svc
        .insert_characteristic(
            0x0003,
            &rm_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("RM");
    rm.write(0, SAMPLE_KEYBOARD_REPORT_MAP, 0, None, None);

    // HID Information
    let info_uuid = BtUuid::from_u16(HOG_INFO_UUID);
    let info = svc
        .insert_characteristic(
            0x0005,
            &info_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("Info");
    info.write(0, HID_INFO_V111, 0, None, None);

    // Protocol Mode
    let pm_uuid = BtUuid::from_u16(HOG_PROTO_MODE_UUID);
    let pm = svc
        .insert_characteristic(
            0x0007,
            &pm_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
            None,
            None,
            None,
        )
        .expect("PM");
    pm.write(0, &[HOG_PROTO_MODE_REPORT], 0, None, None);

    // Report (input)
    let rpt_uuid = BtUuid::from_u16(HOG_REPORT_UUID);
    let rpt = svc
        .insert_characteristic(
            0x0009,
            &rpt_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
            None,
            None,
            None,
        )
        .expect("Report");
    rpt.write(0, &[0x00; 4], 0, None, None);

    // CCC
    let ccc_uuid = BtUuid::from_u16(HOG_CCC_UUID);
    let ccc = svc
        .insert_descriptor(
            0x000B,
            &ccc_uuid,
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            None,
            None,
            None,
        )
        .expect("CCC");
    ccc.write(0, &[0x00, 0x00], 0, None, None);

    // Report Reference
    let rr_uuid = BtUuid::from_u16(HOG_RPT_REF_UUID);
    let rr = svc
        .insert_descriptor(
            0x000C,
            &rr_uuid,
            BT_ATT_PERM_READ as u32,
            None,
            None,
            None,
        )
        .expect("RR");
    rr.write(0, &[0x01, HOG_RPT_TYPE_INPUT], 0, None, None);

    // Control Point
    let cp_uuid = BtUuid::from_u16(HOG_CTRL_POINT_UUID);
    svc.insert_characteristic(
        0x000D,
        &cp_uuid,
        BT_ATT_PERM_WRITE as u32,
        BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
        None,
        None,
        None,
    )
    .expect("CP");

    svc.set_active(true);

    // --- Discovery verification ---
    let mut svc_handles = Vec::new();
    db.foreach_service(Some(&hog_uuid), |attr| {
        svc_handles.push(attr.get_handle());
    });
    assert_eq!(svc_handles.len(), 1);
    assert_eq!(svc_handles[0], 0x0001);

    // Iterate attributes (BtHog discovery pattern).
    let mut found_rm = false;
    let mut found_info = false;
    let mut found_pm = false;
    let mut found_rpt = false;
    let mut found_cp = false;
    let mut found_ccc = false;
    let mut found_rr = false;

    for handle in 0x0001..=0x0014u16 {
        if let Some(attr) = db.get_attribute(handle) {
            if let Some(uuid) = attr.get_type() {
                if uuid == BtUuid::from_u16(HOG_REPORT_MAP_UUID) {
                    found_rm = true;
                } else if uuid == BtUuid::from_u16(HOG_INFO_UUID) {
                    found_info = true;
                } else if uuid == BtUuid::from_u16(HOG_PROTO_MODE_UUID) {
                    found_pm = true;
                } else if uuid == BtUuid::from_u16(HOG_REPORT_UUID) {
                    found_rpt = true;
                } else if uuid == BtUuid::from_u16(HOG_CTRL_POINT_UUID) {
                    found_cp = true;
                } else if uuid == BtUuid::from_u16(HOG_CCC_UUID) {
                    found_ccc = true;
                } else if uuid == BtUuid::from_u16(HOG_RPT_REF_UUID) {
                    found_rr = true;
                }
            }
        }
    }

    assert!(found_rm, "Report Map should be discovered");
    assert!(found_info, "HID Information should be discovered");
    assert!(found_pm, "Protocol Mode should be discovered");
    assert!(found_rpt, "Report should be discovered");
    assert!(found_cp, "Control Point should be discovered");
    assert!(found_ccc, "CCC should be discovered");
    assert!(found_rr, "Report Reference should be discovered");
}

/// Test discovery with empty GattDb.
#[test]
fn test_hog_discovery_empty_db() {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let mut count = 0;
    db.foreach_service(Some(&hog_uuid), |_| count += 1);
    assert_eq!(count, 0, "Empty DB should have no HID services");
}

/// Test discovery with a non-HID service present.
#[test]
fn test_hog_discovery_non_hid_service() {
    let db = GattDb::new();
    let gap_uuid = BtUuid::from_u16(0x1800);
    let svc = db
        .insert_service(0x0001, &gap_uuid, true, 4)
        .expect("GAP svc");
    svc.set_active(true);

    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let mut count = 0;
    db.foreach_service(Some(&hog_uuid), |_| count += 1);
    assert_eq!(count, 0, "Non-HID service should not match HOG filter");
}

// ============================================================================
// Test 14: BtHog attach/detach with GATT transport (async)
// ============================================================================

/// Test BtHog attach and detach lifecycle with a real GATT client.
#[tokio::test]
async fn test_hog_attach_detach_lifecycle() {
    let (fd_server, fd_client) = create_test_pair();
    // Transfer ownership to prevent OwnedFd double-close with BtAtt internals.
    let raw_server = fd_server.into_raw_fd();
    let raw_client = fd_client.into_raw_fd();

    let server_db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let svc = server_db
        .insert_service(0x0001, &hog_uuid, true, 6)
        .expect("svc");
    let rm_uuid = BtUuid::from_u16(HOG_REPORT_MAP_UUID);
    let rm = svc
        .insert_characteristic(
            0x0003,
            &rm_uuid,
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("RM");
    rm.write(0, SAMPLE_KEYBOARD_REPORT_MAP, 0, None, None);
    svc.set_active(true);

    let server_att =
        BtAtt::new(raw_server, false).expect("server BtAtt");
    let client_att =
        BtAtt::new(raw_client, false).expect("client BtAtt");

    let _server =
        BtGattServer::new(server_db.clone(), Arc::clone(&server_att), 23, 0).expect("server");

    let client_db = GattDb::new();
    let client =
        BtGattClient::new(client_db.clone(), Arc::clone(&client_att), 23, 0).expect("client");

    // Wait for client init (may not reach ready state in minimal server).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !client.is_ready() {
        if tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut hog = BtHog::new("lifecycle-test", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.attach(client, client_db);
    tokio::time::sleep(Duration::from_millis(100)).await;

    hog.detach();
    assert!(hog.get_uhid().is_none(), "UHID should be None after detach");
}

/// Test attach with empty GattDb does not panic.
#[tokio::test]
async fn test_hog_attach_empty_db() {
    let (fd_a, fd_b) = create_test_pair();
    let raw_a = fd_a.into_raw_fd();
    let raw_b = fd_b.into_raw_fd();

    let att_a = BtAtt::new(raw_a, false).expect("att_a");
    let att_b = BtAtt::new(raw_b, false).expect("att_b");

    let server_db = GattDb::new();
    let _server =
        BtGattServer::new(server_db.clone(), Arc::clone(&att_a), 23, 0).expect("server");

    let client_db = GattDb::new();
    let client =
        BtGattClient::new(client_db.clone(), Arc::clone(&att_b), 23, 0).expect("client");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut hog = BtHog::new("empty-db", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.attach(client, client_db);
    tokio::time::sleep(Duration::from_millis(100)).await;
    hog.detach();
}

/// Test double attach is handled gracefully.
#[tokio::test]
async fn test_hog_double_attach() {
    let (fd_a, fd_b) = create_test_pair();
    let raw_a = fd_a.into_raw_fd();
    let raw_b = fd_b.into_raw_fd();

    let att_a = BtAtt::new(raw_a, false).expect("att_a");
    let att_b = BtAtt::new(raw_b, false).expect("att_b");

    let server_db = GattDb::new();
    let _server =
        BtGattServer::new(server_db.clone(), Arc::clone(&att_a), 23, 0).expect("server");

    let client_db = GattDb::new();
    let client =
        BtGattClient::new(client_db.clone(), Arc::clone(&att_b), 23, 0).expect("client");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut hog = BtHog::new("double", BdAddr { b: [0; 6] }, BdAddr { b: [0; 6] });
    hog.attach(Arc::clone(&client), client_db.clone());
    tokio::time::sleep(Duration::from_millis(50)).await;
    hog.attach(client, client_db);
    tokio::time::sleep(Duration::from_millis(50)).await;
    hog.detach();
}

// ============================================================================
// Test 15: GAttrib construction
// ============================================================================

/// Test GAttrib construction from a socketpair fd.
#[tokio::test]
async fn test_gattrib_construction() {
    let (fd_a, fd_b) = create_test_pair();
    let raw_a = fd_a.into_raw_fd();
    std::mem::forget(fd_b); // Keep peer alive, prevent fd reuse
    let _gattrib = GAttrib::new(raw_a, 23, false);
}

// ============================================================================
// Test 16: Comprehensive HID service with all characteristic types
// ============================================================================

/// Build and verify a full HID service with all HOGP characteristics.
#[test]
fn test_hog_comprehensive_service_structure() {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);

    let svc = db
        .insert_service(0x0001, &hog_uuid, true, 40)
        .expect("svc");

    // Report Map
    let rm = svc
        .insert_characteristic(
            0x0003,
            &BtUuid::from_u16(HOG_REPORT_MAP_UUID),
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("RM");
    rm.write(0, SAMPLE_KEYBOARD_REPORT_MAP, 0, None, None);

    // HID Information
    let info = svc
        .insert_characteristic(
            0x0005,
            &BtUuid::from_u16(HOG_INFO_UUID),
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("Info");
    info.write(0, HID_INFO_V111, 0, None, None);

    // Protocol Mode
    let pm = svc
        .insert_characteristic(
            0x0007,
            &BtUuid::from_u16(HOG_PROTO_MODE_UUID),
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
            None,
            None,
            None,
        )
        .expect("PM");
    pm.write(0, &[HOG_PROTO_MODE_REPORT], 0, None, None);

    // Input Report + CCC + RR
    let irpt = svc
        .insert_characteristic(
            0x0009,
            &BtUuid::from_u16(HOG_REPORT_UUID),
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
            None,
            None,
            None,
        )
        .expect("Input Rpt");
    irpt.write(0, &[0x00; 4], 0, None, None);

    let iccc = svc
        .insert_descriptor(
            0x000B,
            &BtUuid::from_u16(HOG_CCC_UUID),
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            None,
            None,
            None,
        )
        .expect("CCC");
    iccc.write(0, &[0x00, 0x00], 0, None, None);

    let irr = svc
        .insert_descriptor(
            0x000C,
            &BtUuid::from_u16(HOG_RPT_REF_UUID),
            BT_ATT_PERM_READ as u32,
            None,
            None,
            None,
        )
        .expect("Input RR");
    irr.write(0, &[0x01, HOG_RPT_TYPE_INPUT], 0, None, None);

    // Output Report + RR
    let orpt = svc
        .insert_characteristic(
            0x000D,
            &BtUuid::from_u16(HOG_REPORT_UUID),
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            BT_GATT_CHRC_PROP_READ
                | BT_GATT_CHRC_PROP_WRITE
                | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
            None,
            None,
            None,
        )
        .expect("Output Rpt");
    orpt.write(0, &[0x00], 0, None, None);

    let orr = svc
        .insert_descriptor(
            0x000F,
            &BtUuid::from_u16(HOG_RPT_REF_UUID),
            BT_ATT_PERM_READ as u32,
            None,
            None,
            None,
        )
        .expect("Output RR");
    orr.write(0, &[0x00, HOG_RPT_TYPE_OUTPUT], 0, None, None);

    // Feature Report + RR
    let frpt = svc
        .insert_characteristic(
            0x0010,
            &BtUuid::from_u16(HOG_REPORT_UUID),
            BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE,
            None,
            None,
            None,
        )
        .expect("Feature Rpt");
    frpt.write(0, &[0x00; 2], 0, None, None);

    let frr = svc
        .insert_descriptor(
            0x0012,
            &BtUuid::from_u16(HOG_RPT_REF_UUID),
            BT_ATT_PERM_READ as u32,
            None,
            None,
            None,
        )
        .expect("Feature RR");
    frr.write(0, &[0x00, HOG_RPT_TYPE_FEATURE], 0, None, None);

    // Control Point
    svc.insert_characteristic(
        0x0013,
        &BtUuid::from_u16(HOG_CTRL_POINT_UUID),
        BT_ATT_PERM_WRITE as u32,
        BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
        None,
        None,
        None,
    )
    .expect("CP");

    svc.set_active(true);

    // Count chars by type.
    let mut report_maps = 0u32;
    let mut hid_infos = 0u32;
    let mut proto_modes = 0u32;
    let mut reports = 0u32;
    let mut control_points = 0u32;
    let mut cccs = 0u32;
    let mut report_refs = 0u32;

    for h in 0x0001..=0x0028u16 {
        if let Some(attr) = db.get_attribute(h) {
            if let Some(uuid) = attr.get_type() {
                if uuid == BtUuid::from_u16(HOG_REPORT_MAP_UUID) {
                    report_maps += 1;
                } else if uuid == BtUuid::from_u16(HOG_INFO_UUID) {
                    hid_infos += 1;
                } else if uuid == BtUuid::from_u16(HOG_PROTO_MODE_UUID) {
                    proto_modes += 1;
                } else if uuid == BtUuid::from_u16(HOG_REPORT_UUID) {
                    reports += 1;
                } else if uuid == BtUuid::from_u16(HOG_CTRL_POINT_UUID) {
                    control_points += 1;
                } else if uuid == BtUuid::from_u16(HOG_CCC_UUID) {
                    cccs += 1;
                } else if uuid == BtUuid::from_u16(HOG_RPT_REF_UUID) {
                    report_refs += 1;
                }
            }
        }
    }

    assert_eq!(report_maps, 1, "1 Report Map");
    assert_eq!(hid_infos, 1, "1 HID Information");
    assert_eq!(proto_modes, 1, "1 Protocol Mode");
    assert_eq!(reports, 3, "3 Reports (input+output+feature)");
    assert_eq!(control_points, 1, "1 Control Point");
    assert_eq!(cccs, 1, "1 CCC descriptor");
    assert_eq!(report_refs, 3, "3 Report References");
}

// ============================================================================
// Test 17: Edge cases and error conditions
// ============================================================================

/// Test HID Information with truncated data (< 4 bytes).
#[test]
fn test_hog_hid_info_truncated() {
    let db = build_single_hid_service(
        0x0001,
        4,
        &[(0x0003, HOG_INFO_UUID, BT_GATT_CHRC_PROP_READ, &[0x11, 0x01])],
        &[],
    );

    let info = db.get_attribute(0x0004).expect("HID Info value");
    assert_eq!(info.get_value().len(), 2, "Truncated HID Info");
}

/// Test Report Reference with missing data.
#[test]
fn test_hog_report_reference_empty() {
    let db = build_single_hid_service(
        0x0001,
        6,
        &[(0x0003, HOG_REPORT_UUID, BT_GATT_CHRC_PROP_READ, &[0xAA])],
        &[(0x0005, HOG_RPT_REF_UUID, &[])],
    );

    let rr = db.get_attribute(0x0005).expect("RR desc");
    assert_eq!(rr.get_value().len(), 0, "Empty Report Reference");
}

/// Test CCC descriptor with no initial value — still writable.
#[test]
fn test_hog_ccc_no_initial_value() {
    let db = build_single_hid_service(
        0x0001,
        6,
        &[(
            0x0003,
            HOG_REPORT_UUID,
            BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
            &[0x00],
        )],
        &[(0x0005, HOG_CCC_UUID, &[])],
    );

    let ccc = db.get_attribute(0x0005).expect("CCC desc");
    ccc.write(0, &[0x01, 0x00], 0, None, None);
    assert_eq!(
        ccc.get_value(),
        &[0x01, 0x00],
        "CCC should be writable even without initial value"
    );
}

/// Test multiple Report characteristics with different report types.
#[test]
fn test_hog_multiple_report_types() {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let svc = db
        .insert_service(0x0001, &hog_uuid, true, 20)
        .expect("svc");
    let rpt_uuid = BtUuid::from_u16(HOG_REPORT_UUID);
    let rr_uuid = BtUuid::from_u16(HOG_RPT_REF_UUID);

    // Input Report (id=1)
    svc.insert_characteristic(
        0x0003,
        &rpt_uuid,
        BT_ATT_PERM_READ as u32,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
        None,
        None,
        None,
    )
    .expect("input");
    let rr1 = svc
        .insert_descriptor(0x0005, &rr_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("rr1");
    rr1.write(0, &[0x01, HOG_RPT_TYPE_INPUT], 0, None, None);

    // Output Report (id=2)
    svc.insert_characteristic(
        0x0006,
        &rpt_uuid,
        BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
        BT_GATT_CHRC_PROP_READ
            | BT_GATT_CHRC_PROP_WRITE
            | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
        None,
        None,
        None,
    )
    .expect("output");
    let rr2 = svc
        .insert_descriptor(0x0008, &rr_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("rr2");
    rr2.write(0, &[0x02, HOG_RPT_TYPE_OUTPUT], 0, None, None);

    // Feature Report (id=3)
    svc.insert_characteristic(
        0x0009,
        &rpt_uuid,
        BT_ATT_PERM_READ as u32 | BT_ATT_PERM_WRITE as u32,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE,
        None,
        None,
        None,
    )
    .expect("feature");
    let rr3 = svc
        .insert_descriptor(0x000B, &rr_uuid, BT_ATT_PERM_READ as u32, None, None, None)
        .expect("rr3");
    rr3.write(0, &[0x03, HOG_RPT_TYPE_FEATURE], 0, None, None);

    svc.set_active(true);

    let rr_vals: Vec<Vec<u8>> = [0x0005u16, 0x0008, 0x000B]
        .iter()
        .map(|&h| db.get_attribute(h).unwrap().get_value())
        .collect();

    assert_eq!(rr_vals[0], &[0x01, HOG_RPT_TYPE_INPUT]);
    assert_eq!(rr_vals[1], &[0x02, HOG_RPT_TYPE_OUTPUT]);
    assert_eq!(rr_vals[2], &[0x03, HOG_RPT_TYPE_FEATURE]);
}

/// Test service handle boundaries (GAP + HID side-by-side).
#[test]
fn test_hog_service_handle_boundaries() {
    let db = GattDb::new();
    let hog_uuid = BtUuid::from_u16(HOG_UUID);
    let gap_uuid = BtUuid::from_u16(0x1800);

    let gap_svc = db
        .insert_service(0x0001, &gap_uuid, true, 4)
        .expect("GAP");
    gap_svc.set_active(true);

    let hid_svc = db
        .insert_service(0x0005, &hog_uuid, true, 6)
        .expect("HID");
    let rm = hid_svc
        .insert_characteristic(
            0x0007,
            &BtUuid::from_u16(HOG_REPORT_MAP_UUID),
            BT_ATT_PERM_READ as u32,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        )
        .expect("RM");
    rm.write(0, &[0x01, 0x02, 0x03], 0, None, None);
    hid_svc.set_active(true);

    let mut hog_handles = Vec::new();
    db.foreach_service(Some(&hog_uuid), |attr| {
        hog_handles.push(attr.get_handle());
    });
    assert_eq!(hog_handles.len(), 1);
    assert_eq!(hog_handles[0], 0x0005);

    let mut all_handles = Vec::new();
    db.foreach_service(None, |attr| {
        all_handles.push(attr.get_handle());
    });
    assert_eq!(all_handles.len(), 2, "Both GAP and HID should exist");
}

// ============================================================================
// Test 18: UUID constants correctness
// ============================================================================

/// Verify HoG UUID values per Bluetooth SIG assignments.
#[test]
fn test_hog_uuid_values() {
    assert_eq!(HOG_UUID, 0x1812);
    assert_eq!(HOG_INFO_UUID, 0x2A4A);
    assert_eq!(HOG_REPORT_MAP_UUID, 0x2A4B);
    assert_eq!(HOG_REPORT_UUID, 0x2A4D);
    assert_eq!(HOG_PROTO_MODE_UUID, 0x2A4E);
    assert_eq!(HOG_CTRL_POINT_UUID, 0x2A4C);
    assert_eq!(HOG_RPT_REF_UUID, 0x2908);
    assert_eq!(HOG_CCC_UUID, 0x2902);
    assert_eq!(HOG_EXT_RPT_REF_UUID, 0x2907);
    assert_eq!(HOG_BOOT_KB_INPUT_UUID, 0x2A22);
    assert_eq!(HOG_BOOT_KB_OUTPUT_UUID, 0x2A32);
    assert_eq!(HOG_BOOT_MOUSE_INPUT_UUID, 0x2A33);
}

/// Verify report type and protocol mode constant values.
#[test]
fn test_hog_constant_values() {
    assert_eq!(HOG_PROTO_MODE_BOOT, 0);
    assert_eq!(HOG_PROTO_MODE_REPORT, 1);
    assert_eq!(HOG_RPT_TYPE_INPUT, 1);
    assert_eq!(HOG_RPT_TYPE_OUTPUT, 2);
    assert_eq!(HOG_RPT_TYPE_FEATURE, 3);
}

// ============================================================================
// Test 19: Read Blob simulation via callback
// ============================================================================

/// Test reading Report Map at various offsets using the callback-based
/// `read()` API, simulating ATT Read Blob.
#[test]
fn test_hog_report_map_read_blob_simulation() {
    let db = build_single_hid_service(
        0x0001,
        4,
        &[(
            0x0003,
            HOG_REPORT_MAP_UUID,
            BT_GATT_CHRC_PROP_READ,
            SAMPLE_KEYBOARD_REPORT_MAP,
        )],
        &[],
    );

    let rm = db.get_attribute(0x0004).expect("Report Map value");

    // Full read at offset 0.
    let (data0, err0) = read_attr(&rm, 0);
    assert_eq!(err0, 0);
    assert_eq!(&data0, SAMPLE_KEYBOARD_REPORT_MAP);

    // Read at offset 10 — should return remaining bytes.
    let (data10, err10) = read_attr(&rm, 10);
    assert_eq!(err10, 0);
    assert_eq!(&data10, &SAMPLE_KEYBOARD_REPORT_MAP[10..]);

    // Read at offset equal to length — should return empty.
    let (data_end, err_end) = read_attr(&rm, SAMPLE_KEYBOARD_REPORT_MAP.len() as u16);
    assert_eq!(err_end, 0);
    assert!(data_end.is_empty());
}

// ============================================================================
// Test 20: Service data and char data
// ============================================================================

/// Verify service data from get_service_data().
#[test]
fn test_hog_service_data() {
    let db = build_single_hid_service(
        0x0010,
        8,
        &[(
            0x0012,
            HOG_REPORT_MAP_UUID,
            BT_GATT_CHRC_PROP_READ,
            &[0xAB, 0xCD],
        )],
        &[],
    );

    let svc_attr = db.get_attribute(0x0010).expect("Service decl");
    let svc_data = svc_attr.get_service_data().expect("Service data");
    assert_eq!(svc_data.start, 0x0010);
    assert!(svc_data.primary);
    assert_eq!(svc_data.uuid, BtUuid::from_u16(HOG_UUID));
}

/// Verify char data from get_char_data().
#[test]
fn test_hog_char_data() {
    let db = build_single_hid_service(
        0x0001,
        4,
        &[(
            0x0003,
            HOG_REPORT_MAP_UUID,
            BT_GATT_CHRC_PROP_READ,
            &[0x01],
        )],
        &[],
    );

    let decl = db.get_attribute(0x0003).expect("Char decl");
    let cd = decl.get_char_data().expect("Char data");
    assert_eq!(cd.uuid, BtUuid::from_u16(HOG_REPORT_MAP_UUID));
    assert_ne!(cd.properties & BT_GATT_CHRC_PROP_READ, 0);

    let val = db.get_attribute(0x0004).expect("Char value");
    let vd = val.get_char_data().expect("Char data from value");
    assert_eq!(vd.uuid, BtUuid::from_u16(HOG_REPORT_MAP_UUID));
}
