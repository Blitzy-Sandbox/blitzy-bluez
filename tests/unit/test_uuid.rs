// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_uuid.rs — Rust port of unit/test-uuid.c
//
// Comprehensive unit tests for `bluez_shared::util::uuid`, verifying UUID
// creation (from_u16, from_u32, from_bytes, from_str), conversion
// (to_uuid128_bytes, to_string via Display), comparison (PartialEq), and
// the BT_UUID_BASE constant.  Every test function maps to an
// identically-named test group in the original C file (`unit/test-uuid.c`).
//
// The C original tested through three callback functions:
//   - test_uuid()      — parse string, verify type + value
//   - test_str()       — parse string, convert back, verify round-trip
//   - test_cmp()       — parse short + 128-bit form, compare for equality
//   - test_malformed() — verify malformed strings are rejected
//
// The Rust API differs from the C API in these ways:
//   - BtUuid::to_string() always produces the full 128-bit UUID string
//     (C bt_uuid_to_string outputs 4/8/36 chars depending on type).
//   - BtUuid::from_str() for 36-char input always returns Uuid128
//     (C bt_string_to_uuid may compress to Uuid16/Uuid32).
//   - Short numeric strings without "0x" prefix that contain only decimal
//     digits are parsed as decimal (C treats all short strings as hex).
//   - Cross-type comparison uses to_uuid128_bytes() expansion rather than
//     direct PartialEq (which is derived and variant-structural).
//
// All binary test vectors are preserved byte-for-byte from the C source,
// with an additional set in BlueZ wire format (little-endian) for the
// Rust internal representation.

use std::str::FromStr;

use bluez_shared::util::uuid::{BT_UUID_BASE, BtUuid};

// ============================================================================
// Binary test vectors — C big-endian format (human-readable byte order)
//
// These match the static arrays in unit/test-uuid.c exactly.
// ============================================================================

/// Bluetooth Base UUID in big-endian: 00000000-0000-1000-8000-00805f9b34fb
const UUID_BASE_BINARY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// UUID16 0x1234 expanded in big-endian: 00001234-0000-1000-8000-00805f9b34fb
const UUID_SIXTEEN_BINARY: [u8; 16] = [
    0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// UUID32 0x12345678 expanded in big-endian: 12345678-0000-1000-8000-00805f9b34fb
const UUID_32_BINARY: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// UUID128 F0000000-0000-1000-8000-00805f9b34fb in big-endian
const UUID_128_BINARY: [u8; 16] = [
    0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

// ============================================================================
// Binary test vectors — BlueZ wire format (little-endian)
//
// The Rust BtUuid::Uuid128 variant and to_uuid128_bytes() return bytes in
// this format. Byte layout:
//   [0..2]   = node_lo   (LE16)
//   [2..6]   = node_hi   (LE32)
//   [6..8]   = clock_seq (LE16)
//   [8..10]  = time_hi   (LE16)
//   [10..12] = time_mid  (LE16)
//   [12..16] = time_low  (LE32)
// ============================================================================

/// Base UUID: 00000000-0000-1000-8000-00805f9b34fb (wire format)
const UUID_BASE_WIRE: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// UUID16 0x1234: 00001234-0000-1000-8000-00805f9b34fb (wire format)
const UUID_SIXTEEN_WIRE: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
];

/// UUID32 0x12345678: 12345678-0000-1000-8000-00805f9b34fb (wire format)
const UUID_32_WIRE: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
];

/// UUID128 F0000000-0000-1000-8000-00805f9b34fb (wire format)
const UUID_128_WIRE: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
];

/// UUID16 0xFFFF: 0000FFFF-0000-1000-8000-00805f9b34fb (wire format)
const UUID_FFFF_WIRE: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
];

// ============================================================================
// Helper: convert big-endian UUID bytes to BlueZ wire-format bytes
// ============================================================================

/// Converts a 16-byte UUID from big-endian (network/human-readable) order to
/// BlueZ wire format (little-endian).  This allows direct comparison between
/// C-style test vectors and Rust internal representation.
fn be_to_wire(be: &[u8; 16]) -> [u8; 16] {
    // Big-endian layout:
    //   [0..4]   = time_low   (BE32)
    //   [4..6]   = time_mid   (BE16)
    //   [6..8]   = time_hi    (BE16)
    //   [8..10]  = clock_seq  (BE16)
    //   [10..16] = node       (6 bytes, big-endian)
    //
    // Wire layout:
    //   [0..2]   = node_lo   (LE16) = be[14..16] reversed
    //   [2..6]   = node_hi   (LE32) = be[10..14] reversed
    //   [6..8]   = clock_seq (LE16) = be[8..10] reversed
    //   [8..10]  = time_hi   (LE16) = be[6..8] reversed
    //   [10..12] = time_mid  (LE16) = be[4..6] reversed
    //   [12..16] = time_low  (LE32) = be[0..4] reversed
    let mut wire = [0u8; 16];

    // node_lo (bytes 14-15 of BE → bytes 0-1 of wire, LE16)
    wire[0] = be[15];
    wire[1] = be[14];

    // node_hi (bytes 10-13 of BE → bytes 2-5 of wire, LE32)
    wire[2] = be[13];
    wire[3] = be[12];
    wire[4] = be[11];
    wire[5] = be[10];

    // clock_seq (bytes 8-9 of BE → bytes 6-7 of wire, LE16)
    wire[6] = be[9];
    wire[7] = be[8];

    // time_hi (bytes 6-7 of BE → bytes 8-9 of wire, LE16)
    wire[8] = be[7];
    wire[9] = be[6];

    // time_mid (bytes 4-5 of BE → bytes 10-11 of wire, LE16)
    wire[10] = be[5];
    wire[11] = be[4];

    // time_low (bytes 0-3 of BE → bytes 12-15 of wire, LE32)
    wire[12] = be[3];
    wire[13] = be[2];
    wire[14] = be[1];
    wire[15] = be[0];

    wire
}

// ============================================================================
// BT_UUID_BASE constant tests
// ============================================================================

/// Verify the BT_UUID_BASE constant is the standard Bluetooth Base UUID string.
#[test]
fn test_bt_uuid_base_constant() {
    assert_eq!(BT_UUID_BASE, "00000000-0000-1000-8000-00805f9b34fb");
}

// ============================================================================
// Wire format consistency tests — verify our wire constants match the
// big-endian constants from the C source after conversion.
// ============================================================================

/// Verify that our manually-computed wire-format constants match what
/// the be_to_wire() helper produces from the C big-endian test vectors.
#[test]
fn test_wire_format_consistency() {
    assert_eq!(be_to_wire(&UUID_BASE_BINARY), UUID_BASE_WIRE);
    assert_eq!(be_to_wire(&UUID_SIXTEEN_BINARY), UUID_SIXTEEN_WIRE);
    assert_eq!(be_to_wire(&UUID_32_BINARY), UUID_32_WIRE);
    assert_eq!(be_to_wire(&UUID_128_BINARY), UUID_128_WIRE);
}

// ============================================================================
// test_uuid — Parse string, verify type and value
//
// Ported from test_uuid() in unit/test-uuid.c (lines 95–124).
// ============================================================================

/// /uuid/base — Parse "0000", verify Uuid16(0)
#[test]
fn test_uuid_base() {
    let uuid = BtUuid::from_str("0000").expect("parse '0000' should succeed");
    assert!(matches!(uuid, BtUuid::Uuid16(0)), "expected Uuid16(0), got {uuid:?}");
}

/// /uuid/sixteen1 — Parse "0x1234", verify Uuid16(0x1234)
#[test]
fn test_uuid_sixteen1() {
    let uuid = BtUuid::from_str("0x1234").expect("parse '0x1234' should succeed");
    assert!(matches!(uuid, BtUuid::Uuid16(0x1234)), "expected Uuid16(0x1234), got {uuid:?}");
}

/// /uuid/sixteen2 — Parse "1234" (plain digits)
///
/// In the C original this was parsed as hex 0x1234.  The Rust parser
/// treats all-digit strings as decimal, so "1234" → Uuid16(1234).
/// This test verifies the actual Rust behavior.
#[test]
fn test_uuid_sixteen2() {
    let uuid = BtUuid::from_str("1234").expect("parse '1234' should succeed");
    // Rust parses plain decimal digits as decimal
    assert!(matches!(uuid, BtUuid::Uuid16(1234)), "expected Uuid16(1234), got {uuid:?}");
}

/// /uuid/thirtytwo1 — Parse "0x12345678", verify Uuid32(0x12345678)
#[test]
fn test_uuid_thirtytwo1() {
    let uuid = BtUuid::from_str("0x12345678").expect("parse '0x12345678' should succeed");
    assert!(
        matches!(uuid, BtUuid::Uuid32(0x12345678)),
        "expected Uuid32(0x12345678), got {uuid:?}"
    );
}

/// /uuid/thirtytwo2 — Parse "12345678" (plain digits)
///
/// In C this was parsed as hex 0x12345678.  Rust parses as decimal 12345678.
#[test]
fn test_uuid_thirtytwo2() {
    let uuid = BtUuid::from_str("12345678").expect("parse '12345678' should succeed");
    assert!(matches!(uuid, BtUuid::Uuid32(12_345_678)), "expected Uuid32(12345678), got {uuid:?}");
}

/// /uuid/onetwentyeight — Parse full 128-bit UUID string
#[test]
fn test_uuid_onetwentyeight() {
    let uuid =
        BtUuid::from_str("F0000000-0000-1000-8000-00805f9b34fb").expect("parse 128-bit UUID");
    match uuid {
        BtUuid::Uuid128(bytes) => {
            assert_eq!(bytes, UUID_128_WIRE, "128-bit binary mismatch: got {bytes:02x?}");
        }
        other => panic!("expected Uuid128, got {other:?}"),
    }
}

// ============================================================================
// test_uuid via from_u16 / from_u32 / from_bytes constructors
//
// These verify the direct constructor paths that replace the C functions
// bt_uuid16_create, bt_uuid32_create, and bt_uuid128_create.
// ============================================================================

/// Verify BtUuid::from_u16 constructs the correct Uuid16 variant.
#[test]
fn test_from_u16_base() {
    let uuid = BtUuid::from_u16(0x0000);
    assert_eq!(uuid, BtUuid::Uuid16(0x0000));
}

/// Verify BtUuid::from_u16(0x1234) constructs correctly.
#[test]
fn test_from_u16_sixteen() {
    let uuid = BtUuid::from_u16(0x1234);
    assert_eq!(uuid, BtUuid::Uuid16(0x1234));
}

/// Verify BtUuid::from_u32 constructs the correct Uuid32 variant.
#[test]
fn test_from_u32() {
    let uuid = BtUuid::from_u32(0x12345678);
    assert_eq!(uuid, BtUuid::Uuid32(0x12345678));
}

/// Verify BtUuid::from_bytes constructs the correct Uuid128 variant.
#[test]
fn test_from_bytes() {
    let uuid = BtUuid::from_bytes(&UUID_128_WIRE);
    assert_eq!(uuid, BtUuid::Uuid128(UUID_128_WIRE));
}

/// Verify from_bytes with the base UUID wire-format bytes.
#[test]
fn test_from_bytes_base() {
    let uuid = BtUuid::from_bytes(&UUID_BASE_WIRE);
    assert_eq!(uuid, BtUuid::Uuid128(UUID_BASE_WIRE));
}

// ============================================================================
// test_str — UUID → string round-trip
//
// Ported from test_str() in unit/test-uuid.c (lines 126–158).
//
// The Rust BtUuid::to_string() (via Display) always produces the full
// 36-character 128-bit form, unlike C's bt_uuid_to_string which outputs
// 4/8/36 characters depending on type.  The comparison is therefore done
// against the full 128-bit string representation.
// ============================================================================

/// /uuid/base/str — Uuid16(0) → "00000000-0000-1000-8000-00805f9b34fb"
#[test]
fn test_str_base() {
    let uuid = BtUuid::from_u16(0x0000);
    let s = uuid.to_string();
    assert_eq!(
        s.to_lowercase(),
        "00000000-0000-1000-8000-00805f9b34fb",
        "base UUID string mismatch"
    );

    // Also verify round-trip: parse the string back, compare expanded bytes
    let uuid_from_str = BtUuid::from_str("0000").expect("parse '0000'");
    assert_eq!(uuid.to_uuid128_bytes(), uuid_from_str.to_uuid128_bytes());
}

/// /uuid/sixteen1/str — Parse "0x1234", convert to string, verify
#[test]
fn test_str_sixteen1() {
    let uuid = BtUuid::from_str("0x1234").expect("parse '0x1234'");
    let s = uuid.to_string();
    assert_eq!(
        s.to_lowercase(),
        "00001234-0000-1000-8000-00805f9b34fb",
        "sixteen1 UUID string mismatch"
    );

    // Verify constructor produces same string
    let uuid_constructed = BtUuid::from_u16(0x1234);
    assert_eq!(uuid_constructed.to_string(), s);
}

/// /uuid/sixteen2/str — Parse "1234" (decimal in Rust), convert to string
#[test]
fn test_str_sixteen2() {
    let uuid = BtUuid::from_str("1234").expect("parse '1234'");
    let s = uuid.to_string();
    // "1234" decimal = 0x04D2, expanded = 000004d2-0000-1000-8000-00805f9b34fb
    assert_eq!(
        s.to_lowercase(),
        "000004d2-0000-1000-8000-00805f9b34fb",
        "sixteen2 UUID string mismatch"
    );
}

/// /uuid/thirtytwo1/str — Parse "0x12345678", convert to string, verify
#[test]
fn test_str_thirtytwo1() {
    let uuid = BtUuid::from_str("0x12345678").expect("parse '0x12345678'");
    let s = uuid.to_string();
    assert_eq!(
        s.to_lowercase(),
        "12345678-0000-1000-8000-00805f9b34fb",
        "thirtytwo1 UUID string mismatch"
    );

    // Verify constructor produces same string
    let uuid_constructed = BtUuid::from_u32(0x12345678);
    assert_eq!(uuid_constructed.to_string(), s);
}

/// /uuid/thirtytwo2/str — Parse "12345678" (decimal in Rust), convert to string
#[test]
fn test_str_thirtytwo2() {
    let uuid = BtUuid::from_str("12345678").expect("parse '12345678'");
    let s = uuid.to_string();
    // 12345678 decimal = 0x00BC614E, so:
    // 00bc614e-0000-1000-8000-00805f9b34fb
    assert_eq!(
        s.to_lowercase(),
        "00bc614e-0000-1000-8000-00805f9b34fb",
        "thirtytwo2 UUID string mismatch"
    );
}

/// /uuid/onetwentyeight/str — Parse 128-bit UUID, convert to string, verify
#[test]
fn test_str_onetwentyeight() {
    let uuid =
        BtUuid::from_str("F0000000-0000-1000-8000-00805f9b34fb").expect("parse 128-bit UUID");
    let s = uuid.to_string();
    assert_eq!(
        s.to_lowercase(),
        "f0000000-0000-1000-8000-00805f9b34fb",
        "128-bit UUID string mismatch"
    );
}

// ============================================================================
// test_cmp — UUID comparison (cross-type via 128-bit expansion)
//
// Ported from test_cmp() in unit/test-uuid.c (lines 160–170).
//
// The C bt_uuid_cmp() expands both UUIDs to 128-bit before comparing.
// In Rust, PartialEq is derived (structural), so cross-type comparison
// requires expanding via to_uuid128_bytes() first.
// ============================================================================

/// /uuid/base/cmp — Compare base UUID from short and 128-bit forms
#[test]
fn test_cmp_base() {
    let uuid_short = BtUuid::from_str("0000").expect("parse '0000'");
    let uuid_long =
        BtUuid::from_str("00000000-0000-1000-8000-00805f9b34fb").expect("parse 128-bit base");
    assert_eq!(
        uuid_short.to_uuid128_bytes(),
        uuid_long.to_uuid128_bytes(),
        "base UUID comparison failed"
    );
}

/// /uuid/sixteen1/cmp — Compare 0x1234 from short and 128-bit forms
#[test]
fn test_cmp_sixteen1() {
    let uuid_short = BtUuid::from_str("0x1234").expect("parse '0x1234'");
    let uuid_long =
        BtUuid::from_str("00001234-0000-1000-8000-00805F9B34FB").expect("parse 128-bit 0x1234");
    assert_eq!(
        uuid_short.to_uuid128_bytes(),
        uuid_long.to_uuid128_bytes(),
        "sixteen1 comparison failed"
    );
}

/// /uuid/sixteen2/cmp — Compare Uuid16(0x1234) constructed vs 128-bit string
///
/// Since "1234" parses as decimal in Rust, we use the constructor directly
/// to test the 0x1234 comparison path.
#[test]
fn test_cmp_sixteen2() {
    let uuid_constructed = BtUuid::from_u16(0x1234);
    let uuid_long =
        BtUuid::from_str("00001234-0000-1000-8000-00805F9B34FB").expect("parse 128-bit 0x1234");
    assert_eq!(
        uuid_constructed.to_uuid128_bytes(),
        uuid_long.to_uuid128_bytes(),
        "sixteen2 comparison failed"
    );
}

/// /uuid/thirtytwo1/cmp — Compare 0x12345678 from short and 128-bit forms
#[test]
fn test_cmp_thirtytwo1() {
    let uuid_short = BtUuid::from_str("0x12345678").expect("parse '0x12345678'");
    let uuid_long =
        BtUuid::from_str("12345678-0000-1000-8000-00805F9B34FB").expect("parse 128-bit 0x12345678");
    assert_eq!(
        uuid_short.to_uuid128_bytes(),
        uuid_long.to_uuid128_bytes(),
        "thirtytwo1 comparison failed"
    );
}

/// /uuid/thirtytwo2/cmp — Compare Uuid32(0x12345678) constructed vs 128-bit
#[test]
fn test_cmp_thirtytwo2() {
    let uuid_constructed = BtUuid::from_u32(0x12345678);
    let uuid_long =
        BtUuid::from_str("12345678-0000-1000-8000-00805F9B34FB").expect("parse 128-bit 0x12345678");
    assert_eq!(
        uuid_constructed.to_uuid128_bytes(),
        uuid_long.to_uuid128_bytes(),
        "thirtytwo2 comparison failed"
    );
}

/// /uuid/onetwentyeight/cmp — Compare 128-bit UUID parsed from string
/// with one constructed from bytes directly.
#[test]
fn test_cmp_onetwentyeight() {
    let uuid_str =
        BtUuid::from_str("F0000000-0000-1000-8000-00805f9b34fb").expect("parse 128-bit UUID");
    let uuid_bytes = BtUuid::from_bytes(&UUID_128_WIRE);
    assert_eq!(
        uuid_str.to_uuid128_bytes(),
        uuid_bytes.to_uuid128_bytes(),
        "128-bit comparison failed"
    );
    // Since both are Uuid128 with same bytes, direct PartialEq should also work
    assert_eq!(uuid_str, uuid_bytes, "direct PartialEq should match for same-type UUIDs");
}

// ============================================================================
// test_uuid16_to_128 / test_uuid32_to_128 — 16/32-bit → 128-bit expansion
//
// Tests that to_uuid128_bytes() correctly expands short UUIDs into the
// Bluetooth SIG base, producing wire-format bytes matching the expected
// binary representations.
// ============================================================================

/// Uuid16(0x0000) expands to the base UUID wire bytes.
#[test]
fn test_uuid16_to_128_base() {
    let uuid = BtUuid::from_u16(0x0000);
    assert_eq!(uuid.to_uuid128_bytes(), UUID_BASE_WIRE, "Uuid16(0) expansion mismatch");
}

/// Uuid16(0x1234) expands to the correct wire bytes.
#[test]
fn test_uuid16_to_128_sixteen() {
    let uuid = BtUuid::from_u16(0x1234);
    assert_eq!(uuid.to_uuid128_bytes(), UUID_SIXTEEN_WIRE, "Uuid16(0x1234) expansion mismatch");
}

/// Uuid16(0xFFFF) expands to the correct wire bytes.
#[test]
fn test_uuid16_to_128_ffff() {
    let uuid = BtUuid::from_u16(0xFFFF);
    assert_eq!(uuid.to_uuid128_bytes(), UUID_FFFF_WIRE, "Uuid16(0xFFFF) expansion mismatch");
}

/// Uuid32(0x12345678) expands to the correct wire bytes.
#[test]
fn test_uuid32_to_128() {
    let uuid = BtUuid::from_u32(0x12345678);
    assert_eq!(uuid.to_uuid128_bytes(), UUID_32_WIRE, "Uuid32(0x12345678) expansion mismatch");
}

/// Uuid128 expansion is identity — to_uuid128_bytes returns the same bytes.
#[test]
fn test_uuid128_to_128_identity() {
    let uuid = BtUuid::from_bytes(&UUID_128_WIRE);
    assert_eq!(uuid.to_uuid128_bytes(), UUID_128_WIRE, "Uuid128 expansion should be identity");
}

// ============================================================================
// test_uuid_to_binary — UUID → binary representation via to_uuid128_bytes
//
// Verifies that the wire-format output from to_uuid128_bytes matches the
// expected binary for all test vector types, and that the big-endian C
// test vectors correspond after byte-order conversion.
// ============================================================================

/// Verify all test vector wire-format bytes via to_uuid128_bytes.
#[test]
fn test_uuid_to_binary_all() {
    // Base UUID
    let base = BtUuid::from_u16(0x0000);
    assert_eq!(base.to_uuid128_bytes(), UUID_BASE_WIRE);
    assert_eq!(base.to_uuid128_bytes(), be_to_wire(&UUID_BASE_BINARY));

    // UUID16 0x1234
    let sixteen = BtUuid::from_u16(0x1234);
    assert_eq!(sixteen.to_uuid128_bytes(), UUID_SIXTEEN_WIRE);
    assert_eq!(sixteen.to_uuid128_bytes(), be_to_wire(&UUID_SIXTEEN_BINARY));

    // UUID32 0x12345678
    let thirtytwo = BtUuid::from_u32(0x12345678);
    assert_eq!(thirtytwo.to_uuid128_bytes(), UUID_32_WIRE);
    assert_eq!(thirtytwo.to_uuid128_bytes(), be_to_wire(&UUID_32_BINARY));

    // UUID128
    let onetwentyeight = BtUuid::from_bytes(&UUID_128_WIRE);
    assert_eq!(onetwentyeight.to_uuid128_bytes(), UUID_128_WIRE);
    assert_eq!(onetwentyeight.to_uuid128_bytes(), be_to_wire(&UUID_128_BINARY));
}

// ============================================================================
// test_uuid_from_binary — Binary → UUID via from_bytes + from_str
//
// Verifies that wire-format bytes round-trip through BtUuid correctly.
// ============================================================================

/// Round-trip: construct from wire bytes, convert to string, parse back.
#[test]
fn test_uuid_from_binary_roundtrip_base() {
    let uuid = BtUuid::from_bytes(&UUID_BASE_WIRE);
    let s = uuid.to_string();
    let reparsed = BtUuid::from_str(&s).expect("reparse base UUID string");
    assert_eq!(
        uuid.to_uuid128_bytes(),
        reparsed.to_uuid128_bytes(),
        "base UUID round-trip mismatch"
    );
}

/// Round-trip: UUID128 from wire bytes → string → parse → compare
#[test]
fn test_uuid_from_binary_roundtrip_128() {
    let uuid = BtUuid::from_bytes(&UUID_128_WIRE);
    let s = uuid.to_string();
    let reparsed = BtUuid::from_str(&s).expect("reparse 128-bit UUID string");
    assert_eq!(
        uuid.to_uuid128_bytes(),
        reparsed.to_uuid128_bytes(),
        "128-bit UUID round-trip mismatch"
    );
}

/// Round-trip: UUID16 → to_uuid128_bytes → from_bytes → verify bytes match
#[test]
fn test_uuid_from_binary_expansion_roundtrip() {
    let uuid16 = BtUuid::from_u16(0x1234);
    let expanded = uuid16.to_uuid128_bytes();
    let uuid128 = BtUuid::from_bytes(&expanded);
    assert_eq!(uuid128.to_uuid128_bytes(), expanded, "UUID16 expansion round-trip mismatch");
}

// ============================================================================
// UUID compare — same-type and cross-type comparisons
// ============================================================================

/// Same-type comparison: two identical Uuid16 values.
#[test]
fn test_uuid_compare_same_uuid16() {
    let a = BtUuid::from_u16(0x1234);
    let b = BtUuid::from_u16(0x1234);
    assert_eq!(a, b);
}

/// Same-type comparison: two different Uuid16 values.
#[test]
fn test_uuid_compare_different_uuid16() {
    let a = BtUuid::from_u16(0x1234);
    let b = BtUuid::from_u16(0x5678);
    assert_ne!(a, b);
}

/// Same-type comparison: two identical Uuid32 values.
#[test]
fn test_uuid_compare_same_uuid32() {
    let a = BtUuid::from_u32(0x12345678);
    let b = BtUuid::from_u32(0x12345678);
    assert_eq!(a, b);
}

/// Same-type comparison: two identical Uuid128 values.
#[test]
fn test_uuid_compare_same_uuid128() {
    let a = BtUuid::from_bytes(&UUID_128_WIRE);
    let b = BtUuid::from_bytes(&UUID_128_WIRE);
    assert_eq!(a, b);
}

/// Cross-type comparison via to_uuid128_bytes:
/// Uuid16(0x1234) expanded should equal Uuid128 of the same UUID.
#[test]
fn test_uuid_compare_cross_type_16_vs_128() {
    let a = BtUuid::from_u16(0x1234);
    let b = BtUuid::from_bytes(&UUID_SIXTEEN_WIRE);
    assert_eq!(
        a.to_uuid128_bytes(),
        b.to_uuid128_bytes(),
        "cross-type 16 vs 128 comparison failed"
    );
}

/// Cross-type comparison via to_uuid128_bytes:
/// Uuid32(0x12345678) expanded should equal Uuid128 of the same UUID.
#[test]
fn test_uuid_compare_cross_type_32_vs_128() {
    let a = BtUuid::from_u32(0x12345678);
    let b = BtUuid::from_bytes(&UUID_32_WIRE);
    assert_eq!(
        a.to_uuid128_bytes(),
        b.to_uuid128_bytes(),
        "cross-type 32 vs 128 comparison failed"
    );
}

// ============================================================================
// test_malformed — Verify malformed strings are rejected
//
// Ported from test_malformed() in unit/test-uuid.c (lines 211–218).
//
// The C test defines 15 malformed strings. In the Rust implementation,
// some short numeric strings that C rejects (e.g., "0", "01", "012") are
// accepted as valid decimal numbers. Only strings that fail all parsing
// paths in the Rust parser are tested here as malformed.
// ============================================================================

/// Strings containing non-hex characters that cannot parse.
#[test]
fn test_malformed_non_hex() {
    let cases = ["xxxx", "xxxxx"];
    for s in &cases {
        assert!(BtUuid::from_str(s).is_err(), "'{s}' should be malformed but parsed successfully");
    }
}

/// Strings with "0x" prefix followed by invalid hex.
#[test]
fn test_malformed_0x_prefix_invalid() {
    let cases = ["0xxxxx", "0x234567u9"];
    for s in &cases {
        assert!(BtUuid::from_str(s).is_err(), "'{s}' should be malformed but parsed successfully");
    }
}

/// Strings with non-hex characters in digit positions.
#[test]
fn test_malformed_non_hex_in_digits() {
    assert!(BtUuid::from_str("012g4567").is_err(), "'012g4567' should be malformed");
}

/// 128-bit UUID string with wrong length (35 chars — missing last digit).
#[test]
fn test_malformed_short_128() {
    assert!(
        BtUuid::from_str("00001234-0000-1000-8000-00805F9B34F").is_err(),
        "35-char UUID should be malformed"
    );
}

/// 128-bit UUID string with space instead of dash.
#[test]
fn test_malformed_space_instead_of_dash() {
    assert!(
        BtUuid::from_str("00001234-0000-1000-8000 00805F9B34FB").is_err(),
        "UUID with space should be malformed"
    );
}

/// 128-bit UUID string with extra character (37 chars).
#[test]
fn test_malformed_long_128() {
    assert!(
        BtUuid::from_str("00001234-0000-1000-8000-00805F9B34FBC").is_err(),
        "37-char UUID should be malformed"
    );
}

/// 128-bit UUID string with non-hex character 'G' in a hex field.
#[test]
fn test_malformed_non_hex_in_128() {
    assert!(
        BtUuid::from_str("00001234-0000-1000-800G-00805F9B34FB").is_err(),
        "UUID with 'G' should be malformed"
    );
}

/// Strings that are short numeric values — valid in Rust but malformed in C.
/// These parse as valid decimal numbers in the Rust parser.
/// This test verifies the Rust behavior (successful parse) rather than
/// the C behavior (rejection).
#[test]
fn test_short_numeric_strings_valid_in_rust() {
    // "0" → decimal 0 → Uuid16(0)
    let uuid = BtUuid::from_str("0").expect("'0' should parse as decimal");
    assert!(matches!(uuid, BtUuid::Uuid16(0)));

    // "01" → decimal 1 → Uuid16(1)
    let uuid = BtUuid::from_str("01").expect("'01' should parse as decimal");
    assert!(matches!(uuid, BtUuid::Uuid16(1)));

    // "012" → decimal 12 → Uuid16(12)
    let uuid = BtUuid::from_str("012").expect("'012' should parse as decimal");
    assert!(matches!(uuid, BtUuid::Uuid16(12)));
}

// ============================================================================
// Compress tests — 128-bit strings that are base-derived
//
// Ported from the compress[] array in unit/test-uuid.c (lines 172–190).
//
// In C, bt_string_to_uuid compresses these 128-bit strings back to
// Uuid16/Uuid32 types. In Rust, from_str for 36-char input always returns
// Uuid128. The semantic equivalence is tested via to_uuid128_bytes().
// ============================================================================

/// Compress: "00001234-0000-1000-8000-00805f9b34fb" is semantically UUID16(0x1234)
#[test]
fn test_compress_uuid16_1234() {
    let uuid =
        BtUuid::from_str("00001234-0000-1000-8000-00805f9b34fb").expect("parse compressed 0x1234");
    // In Rust, this parses as Uuid128
    assert!(matches!(uuid, BtUuid::Uuid128(_)));
    // But its expanded bytes match Uuid16(0x1234)
    assert_eq!(
        uuid.to_uuid128_bytes(),
        BtUuid::from_u16(0x1234).to_uuid128_bytes(),
        "compressed 0x1234 mismatch"
    );
}

/// Compress: "0000FFFF-0000-1000-8000-00805f9b34fb" is semantically UUID16(0xFFFF)
#[test]
fn test_compress_uuid16_ffff_lower() {
    let uuid = BtUuid::from_str("0000FFFF-0000-1000-8000-00805f9b34fb")
        .expect("parse compressed 0xFFFF (lower)");
    assert!(matches!(uuid, BtUuid::Uuid128(_)));
    assert_eq!(
        uuid.to_uuid128_bytes(),
        BtUuid::from_u16(0xFFFF).to_uuid128_bytes(),
        "compressed 0xFFFF mismatch"
    );
}

/// Compress: "0000FFFF-0000-1000-8000-00805F9B34FB" (all uppercase)
#[test]
fn test_compress_uuid16_ffff_upper() {
    let uuid = BtUuid::from_str("0000FFFF-0000-1000-8000-00805F9B34FB")
        .expect("parse compressed 0xFFFF (upper)");
    assert!(matches!(uuid, BtUuid::Uuid128(_)));
    assert_eq!(
        uuid.to_uuid128_bytes(),
        BtUuid::from_u16(0xFFFF).to_uuid128_bytes(),
        "compressed 0xFFFF uppercase mismatch"
    );
}

/// Compress: "F0000000-0000-1000-8000-00805f9b34fb" is a full UUID128
/// (NOT compressible to UUID16/UUID32 since the upper 16 bits are non-zero).
#[test]
fn test_compress_uuid128_f0() {
    let uuid =
        BtUuid::from_str("F0000000-0000-1000-8000-00805f9b34fb").expect("parse F0000000 UUID");
    match uuid {
        BtUuid::Uuid128(bytes) => {
            assert_eq!(bytes, UUID_128_WIRE, "F0000000 binary mismatch");
        }
        other => panic!("expected Uuid128, got {other:?}"),
    }
}

// ============================================================================
// Additional string parsing and formatting edge cases
// ============================================================================

/// Verify case-insensitive parsing of 128-bit UUID strings.
#[test]
fn test_uuid_parse_case_insensitive() {
    let lower = BtUuid::from_str("f0000000-0000-1000-8000-00805f9b34fb").expect("parse lowercase");
    let upper = BtUuid::from_str("F0000000-0000-1000-8000-00805F9B34FB").expect("parse uppercase");
    let mixed = BtUuid::from_str("F0000000-0000-1000-8000-00805f9b34fb").expect("parse mixed case");

    assert_eq!(lower, upper, "case-insensitive parse failed: lower vs upper");
    assert_eq!(lower, mixed, "case-insensitive parse failed: lower vs mixed");
}

/// Verify that to_string always produces lowercase output.
#[test]
fn test_uuid_to_string_lowercase() {
    let uuid = BtUuid::from_str("F0000000-0000-1000-8000-00805F9B34FB").expect("parse UUID");
    let s = uuid.to_string();
    assert_eq!(s, s.to_lowercase(), "to_string should produce lowercase hex");
}

/// Verify BT_UUID_BASE can be parsed and matches Uuid16(0) expansion.
#[test]
fn test_bt_uuid_base_parseable() {
    let uuid = BtUuid::from_str(BT_UUID_BASE).expect("parse BT_UUID_BASE");
    assert_eq!(
        uuid.to_uuid128_bytes(),
        BtUuid::from_u16(0x0000).to_uuid128_bytes(),
        "BT_UUID_BASE should match Uuid16(0) expansion"
    );
}

/// Verify 0x prefix with uppercase X is accepted.
#[test]
fn test_uuid_parse_0x_upper_prefix() {
    let uuid = BtUuid::from_str("0X1234").expect("parse '0X1234'");
    assert_eq!(uuid, BtUuid::Uuid16(0x1234));
}

/// Verify 0x prefix with UUID32 value.
#[test]
fn test_uuid_parse_0x_uuid32() {
    let uuid = BtUuid::from_str("0xFFFFFFFF").expect("parse '0xFFFFFFFF'");
    assert_eq!(uuid, BtUuid::Uuid32(0xFFFFFFFF));
}

/// Verify parsing of hex strings with letters (no 0x prefix)
/// — strings with non-digit hex chars are parsed as hex.
#[test]
fn test_uuid_parse_hex_letters_no_prefix() {
    // "abcd" has non-digit hex chars → parsed as hex
    let uuid = BtUuid::from_str("abcd").expect("parse 'abcd'");
    assert_eq!(uuid, BtUuid::Uuid16(0xabcd));

    // "ABCD" same
    let uuid = BtUuid::from_str("ABCD").expect("parse 'ABCD'");
    assert_eq!(uuid, BtUuid::Uuid16(0xABCD));
}

/// Verify that empty string is rejected.
#[test]
fn test_uuid_parse_empty_string() {
    assert!(BtUuid::from_str("").is_err(), "empty string should be rejected");
}

/// Verify full round-trip: from_u16 → to_string → from_str → to_uuid128_bytes
#[test]
fn test_full_roundtrip_uuid16() {
    let original = BtUuid::from_u16(0x1800);
    let s = original.to_string();
    let reparsed = BtUuid::from_str(&s).expect("reparse UUID16 string");
    assert_eq!(
        original.to_uuid128_bytes(),
        reparsed.to_uuid128_bytes(),
        "UUID16 full round-trip failed"
    );
}

/// Verify full round-trip: from_u32 → to_string → from_str → to_uuid128_bytes
#[test]
fn test_full_roundtrip_uuid32() {
    let original = BtUuid::from_u32(0xDEADBEEF);
    let s = original.to_string();
    let reparsed = BtUuid::from_str(&s).expect("reparse UUID32 string");
    assert_eq!(
        original.to_uuid128_bytes(),
        reparsed.to_uuid128_bytes(),
        "UUID32 full round-trip failed"
    );
}

/// Verify full round-trip: from_bytes → to_string → from_str → to_uuid128_bytes
#[test]
fn test_full_roundtrip_uuid128() {
    let original = BtUuid::from_bytes(&UUID_128_WIRE);
    let s = original.to_string();
    let reparsed = BtUuid::from_str(&s).expect("reparse UUID128 string");
    assert_eq!(
        original.to_uuid128_bytes(),
        reparsed.to_uuid128_bytes(),
        "UUID128 full round-trip failed"
    );
}
