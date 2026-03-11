// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_gobex_apparam.rs — Rust port of unit/test-gobex-apparam.c
//
// Comprehensive unit tests for `ObexApparam` — the OBEX Application Parameters
// TLV container from the `obexd` crate.  Every test function in the original C
// file (`unit/test-gobex-apparam.c`, 416 lines, 18 tests registered via
// `g_test_add_func`) is faithfully converted here as a Rust `#[test]` function,
// preserving identical test data byte arrays and assertion semantics.
//
// Additional tests beyond the C original cover PBAP-specific and MAP-specific
// application parameter tag IDs, empty-container edge cases, and maximum-length
// value handling.
//
// Conversion patterns applied:
//   g_obex_apparam_decode()         → ObexApparam::decode()
//   g_obex_apparam_encode()         → ObexApparam::encode()
//   g_obex_apparam_set_uint8()      → ObexApparam::set_u8()
//   g_obex_apparam_set_uint16()     → ObexApparam::set_u16()
//   g_obex_apparam_set_uint32()     → ObexApparam::set_u32()
//   g_obex_apparam_set_uint64()     → ObexApparam::set_u64()
//   g_obex_apparam_set_string()     → ObexApparam::set_string()
//   g_obex_apparam_set_bytes()      → ObexApparam::set_bytes()
//   g_obex_apparam_get_uint8()      → ObexApparam::get_u8()
//   g_obex_apparam_get_uint16()     → ObexApparam::get_u16()
//   g_obex_apparam_get_uint32()     → ObexApparam::get_u32()
//   g_obex_apparam_get_uint64()     → ObexApparam::get_u64()
//   g_obex_apparam_get_string()     → ObexApparam::get_string()
//   g_obex_apparam_get_bytes()      → ObexApparam::get_bytes()
//   g_obex_apparam_free()           → (Drop — automatic in Rust)

use obexd::obex::apparam::ObexApparam;

// ============================================================================
// Tag ID constants — identical to the C test file (lines 22–27)
// ============================================================================

const TAG_U8: u8 = 0x00;
const TAG_U16: u8 = 0x01;
const TAG_U32: u8 = 0x02;
const TAG_U64: u8 = 0x03;
const TAG_STRING: u8 = 0x04;
const TAG_BYTES: u8 = 0x05;

// ============================================================================
// TLV test data arrays — byte-identical to the C static arrays (lines 29–45)
// ============================================================================

/// Truncated TLV: tag byte only, no length byte.
/// C: `static uint8_t tag_nval_short[] = { TAG_U8 };`
const TAG_NVAL_SHORT: &[u8] = &[TAG_U8];

/// Truncated TLV: tag + length but no value bytes (length claims 1 byte).
/// C: `static uint8_t tag_nval_data[] = { TAG_U8, 0x01 };`
const TAG_NVAL_DATA: &[u8] = &[TAG_U8, 0x01];

/// Two-tag TLV where the second tag header is truncated (no length byte).
/// C: `static uint8_t tag_nval2_short[] = { TAG_U8, 0x01, 0x1, TAG_U16 };`
const TAG_NVAL2_SHORT: &[u8] = &[TAG_U8, 0x01, 0x01, TAG_U16];

/// Two-tag TLV where the second tag has a length but insufficient value bytes.
/// C: `static uint8_t tag_nval2_data[] = { TAG_U8, 0x01, 0x1, TAG_U16, 0x02 };`
const TAG_NVAL2_DATA: &[u8] = &[TAG_U8, 0x01, 0x01, TAG_U16, 0x02];

/// Single u8 tag: tag=0x00, length=1, value=0x01.
/// C: `static uint8_t tag_uint8[] = { TAG_U8, 0x01, 0x01 };`
const TAG_UINT8: &[u8] = &[TAG_U8, 0x01, 0x01];

/// Single u16 tag: tag=0x01, length=2, value=0x01,0x02 (big-endian 0x0102).
/// C: `static uint8_t tag_uint16[] = { TAG_U16, 0x02, 0x01, 0x02 };`
const TAG_UINT16: &[u8] = &[TAG_U16, 0x02, 0x01, 0x02];

/// Single u32 tag: tag=0x02, length=4, value=0x01020304 (big-endian).
/// C: `static uint8_t tag_uint32[] = { TAG_U32, 0x04, 0x01, 0x02, 0x03, 0x04 };`
const TAG_UINT32: &[u8] = &[TAG_U32, 0x04, 0x01, 0x02, 0x03, 0x04];

/// Single u64 tag: tag=0x03, length=8, value=0x0102030405060708 (big-endian).
/// C: `static uint8_t tag_uint64[] = { TAG_U64, 0x08, 0x01, 0x02, 0x03, 0x04,
///                                     0x05, 0x06, 0x07, 0x08 };`
const TAG_UINT64: &[u8] = &[TAG_U64, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

/// Single string tag: tag=0x04, length=4, value="ABC\0".
/// C: `static uint8_t tag_string[] = { TAG_STRING, 0x04, 'A', 'B', 'C', '\0' };`
const TAG_STRING_DATA: &[u8] = &[TAG_STRING, 0x04, b'A', b'B', b'C', 0x00];

/// Builds the 257-byte `tag_bytes` array matching the C definition:
///   `static uint8_t tag_bytes[257] = { TAG_BYTES, 0xFF };`
/// Element [0] = TAG_BYTES (0x05), [1] = 0xFF (length=255), [2..256] = 0x00.
fn make_tag_bytes() -> [u8; 257] {
    let mut arr = [0u8; 257];
    arr[0] = TAG_BYTES;
    arr[1] = 0xFF;
    arr
}

/// Multi-tag TLV: u8 + u16 + u32 + u64 + string, concatenated.
/// C: `static uint8_t tag_multi[] = { ... };` — 29 bytes total.
const TAG_MULTI: &[u8] = &[
    TAG_U8, 0x01, 0x01, TAG_U16, 0x02, 0x01, 0x02, TAG_U32, 0x04, 0x01, 0x02, 0x03, 0x04, TAG_U64,
    0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, TAG_STRING, 0x04, b'A', b'B', b'C', 0x00,
];

// ============================================================================
// Helper — parse_and_decode (C lines 48–63)
// ============================================================================

/// Decodes TLV `data`, re-encodes to a buffer, and asserts byte-for-byte
/// equality with the original input.  Returns the decoded `ObexApparam`.
///
/// This helper is valid only for single-tag TLV data because `ObexApparam`
/// uses a `HashMap` internally, so multi-tag encoding order is
/// non-deterministic.  All call sites in the C original use single-tag data.
///
/// Equivalent to the C `parse_and_decode()` function.
fn parse_and_decode(data: &[u8]) -> ObexApparam {
    let apparam = ObexApparam::decode(data).expect("decode should succeed");

    let mut encoded = vec![0u8; 1024];
    let len = apparam.encode(&mut encoded).expect("encode should succeed");

    assert_eq!(data, &encoded[..len], "round-trip encode produced different bytes");

    apparam
}

// ============================================================================
// Invalid TLV decode tests (C lines 65–103)
// ============================================================================

/// Ported from `test_apparam_nval_short` (C lines 65–73).
///
/// A single tag byte with no length byte should fail to decode.
#[test]
fn test_apparam_nval_short() {
    let result = ObexApparam::decode(TAG_NVAL_SHORT);
    assert!(result.is_err(), "decoding a truncated header (1 byte) must fail");
}

/// Ported from `test_apparam_nval_data` (C lines 75–83).
///
/// Tag + length claiming 1 byte, but no actual value bytes follow.
#[test]
fn test_apparam_nval_data() {
    let result = ObexApparam::decode(TAG_NVAL_DATA);
    assert!(result.is_err(), "decoding tag+len with no value bytes must fail");
}

/// Ported from `test_apparam_nval2_short` (C lines 85–93).
///
/// First tag is valid (u8=0x01), second tag has a tag byte but no length.
#[test]
fn test_apparam_nval2_short() {
    let result = ObexApparam::decode(TAG_NVAL2_SHORT);
    assert!(result.is_err(), "decoding with a truncated second tag header must fail");
}

/// Ported from `test_apparam_nval2_data` (C lines 95–103).
///
/// First tag is valid (u8=0x01), second tag has tag+length but insufficient
/// value bytes (needs 2, has 0).
#[test]
fn test_apparam_nval2_data() {
    let result = ObexApparam::decode(TAG_NVAL2_DATA);
    assert!(result.is_err(), "decoding with truncated second tag value must fail");
}

// ============================================================================
// Getter tests — decode from TLV and retrieve typed values (C lines 105–243)
// ============================================================================

/// Ported from `test_apparam_get_uint8` (C lines 105–119).
///
/// Decodes `TAG_UINT8`, verifies round-trip, then extracts the u8 value.
#[test]
fn test_apparam_get_uint8() {
    let apparam = parse_and_decode(TAG_UINT8);

    let data = apparam.get_u8(TAG_U8);
    assert_eq!(data, Some(0x01));
}

/// Ported from `test_apparam_get_uint16` (C lines 121–135).
///
/// Decodes `TAG_UINT16`, verifies round-trip, then extracts the u16 value
/// (big-endian 0x0102 from wire bytes [0x01, 0x02]).
#[test]
fn test_apparam_get_uint16() {
    let apparam = parse_and_decode(TAG_UINT16);

    let data = apparam.get_u16(TAG_U16);
    assert_eq!(data, Some(0x0102));
}

/// Ported from `test_apparam_get_uint32` (C lines 137–151).
///
/// Decodes `TAG_UINT32`, verifies round-trip, then extracts the u32 value
/// (big-endian 0x01020304).
#[test]
fn test_apparam_get_uint32() {
    let apparam = parse_and_decode(TAG_UINT32);

    let data = apparam.get_u32(TAG_U32);
    assert_eq!(data, Some(0x01020304));
}

/// Ported from `test_apparam_get_uint64` (C lines 153–167).
///
/// Decodes `TAG_UINT64`, verifies round-trip, then extracts the u64 value
/// (big-endian 0x0102030405060708).
#[test]
fn test_apparam_get_uint64() {
    let apparam = parse_and_decode(TAG_UINT64);

    let data = apparam.get_u64(TAG_U64);
    assert_eq!(data, Some(0x0102030405060708));
}

/// Ported from `test_apparam_get_string` (C lines 169–183).
///
/// Decodes `TAG_STRING_DATA` (TLV with "ABC\0"), verifies round-trip,
/// then extracts the string value (stripping the NUL terminator).
#[test]
fn test_apparam_get_string() {
    let apparam = parse_and_decode(TAG_STRING_DATA);

    let string = apparam.get_string(TAG_STRING);
    assert_eq!(string, Some("ABC".to_owned()));
}

/// Ported from `test_apparam_get_bytes` (C lines 185–200).
///
/// Decodes the 257-byte `tag_bytes` array (tag=0x05, length=255, 255 zero
/// bytes), verifies round-trip, then extracts the raw bytes and verifies
/// they match `tag_bytes[2..]`.
#[test]
fn test_apparam_get_bytes() {
    let tag_bytes = make_tag_bytes();
    let apparam = parse_and_decode(&tag_bytes);

    let data = apparam.get_bytes(TAG_BYTES);
    assert!(data.is_some(), "get_bytes should return Some for TAG_BYTES");

    let data = data.unwrap();
    assert_eq!(data.len(), 255, "bytes value length should be 255");
    assert_eq!(data, &tag_bytes[2..], "bytes value should match tag_bytes[2..]");
}

/// Ported from `test_apparam_get_multi` (C lines 202–244).
///
/// Decodes the multi-tag TLV array and extracts each typed value
/// independently.  Does NOT verify round-trip encoding because `HashMap`
/// ordering is non-deterministic for multiple tags.
#[test]
fn test_apparam_get_multi() {
    let apparam = ObexApparam::decode(TAG_MULTI).expect("multi-tag decode should succeed");

    // u8
    let data8 = apparam.get_u8(TAG_U8);
    assert_eq!(data8, Some(0x01));

    // u16
    let data16 = apparam.get_u16(TAG_U16);
    assert_eq!(data16, Some(0x0102));

    // u32
    let data32 = apparam.get_u32(TAG_U32);
    assert_eq!(data32, Some(0x01020304));

    // u64
    let data64 = apparam.get_u64(TAG_U64);
    assert_eq!(data64, Some(0x0102030405060708));

    // string
    let string = apparam.get_string(TAG_STRING);
    assert_eq!(string, Some("ABC".to_owned()));
}

// ============================================================================
// Setter tests — construct from scratch, encode, compare (C lines 246–368)
// ============================================================================

/// Ported from `test_apparam_set_uint8` (C lines 246–259).
///
/// Sets a u8 value, encodes to TLV, and verifies byte equality with
/// `TAG_UINT8`.
#[test]
fn test_apparam_set_uint8() {
    let mut apparam = ObexApparam::new();
    apparam.set_u8(TAG_U8, 0x01);

    let mut buf = [0u8; 1024];
    let len = apparam.encode(&mut buf).expect("encode should succeed");
    assert_eq!(&buf[..len], TAG_UINT8);
}

/// Ported from `test_apparam_set_uint16` (C lines 261–274).
///
/// Sets a u16 value, encodes to TLV, and verifies byte equality with
/// `TAG_UINT16`.
#[test]
fn test_apparam_set_uint16() {
    let mut apparam = ObexApparam::new();
    apparam.set_u16(TAG_U16, 0x0102);

    let mut buf = [0u8; 1024];
    let len = apparam.encode(&mut buf).expect("encode should succeed");
    assert_eq!(&buf[..len], TAG_UINT16);
}

/// Ported from `test_apparam_set_uint32` (C lines 276–289).
///
/// Sets a u32 value, encodes to TLV, and verifies byte equality with
/// `TAG_UINT32`.
#[test]
fn test_apparam_set_uint32() {
    let mut apparam = ObexApparam::new();
    apparam.set_u32(TAG_U32, 0x01020304);

    let mut buf = [0u8; 1024];
    let len = apparam.encode(&mut buf).expect("encode should succeed");
    assert_eq!(&buf[..len], TAG_UINT32);
}

/// Ported from `test_apparam_set_uint64` (C lines 291–304).
///
/// Sets a u64 value, encodes to TLV, and verifies byte equality with
/// `TAG_UINT64`.
#[test]
fn test_apparam_set_uint64() {
    let mut apparam = ObexApparam::new();
    apparam.set_u64(TAG_U64, 0x0102030405060708);

    let mut buf = [0u8; 1024];
    let len = apparam.encode(&mut buf).expect("encode should succeed");
    assert_eq!(&buf[..len], TAG_UINT64);
}

/// Ported from `test_apparam_set_string` (C lines 306–319).
///
/// Sets a string value "ABC", encodes to TLV, and verifies byte equality
/// with `TAG_STRING_DATA` (which includes the NUL terminator).
#[test]
fn test_apparam_set_string() {
    let mut apparam = ObexApparam::new();
    apparam.set_string(TAG_STRING, "ABC");

    let mut buf = [0u8; 1024];
    let len = apparam.encode(&mut buf).expect("encode should succeed");
    assert_eq!(&buf[..len], TAG_STRING_DATA);
}

/// Ported from `test_apparam_set_bytes` (C lines 321–334).
///
/// Sets 255 zero bytes, encodes to TLV, and verifies byte equality with
/// the 257-byte `tag_bytes` array.
#[test]
fn test_apparam_set_bytes() {
    let tag_bytes = make_tag_bytes();

    let mut apparam = ObexApparam::new();
    apparam.set_bytes(TAG_BYTES, &tag_bytes[2..]);

    let mut buf = [0u8; 1024];
    let len = apparam.encode(&mut buf).expect("encode should succeed");
    assert_eq!(&buf[..len], &tag_bytes[..]);
}

/// Ported from `test_apparam_set_multi` (C lines 336–368).
///
/// Sets all five typed values, encodes, and verifies the total encoded
/// length matches `TAG_MULTI.len()` (29 bytes).  Does NOT verify exact
/// byte ordering because `HashMap` iteration order is non-deterministic.
#[test]
fn test_apparam_set_multi() {
    let mut apparam = ObexApparam::new();
    apparam.set_u8(TAG_U8, 0x01);
    apparam.set_u16(TAG_U16, 0x0102);
    apparam.set_u32(TAG_U32, 0x01020304);
    apparam.set_u64(TAG_U64, 0x0102030405060708);
    apparam.set_string(TAG_STRING, "ABC");

    let mut buf = [0u8; 1024];
    let len = apparam.encode(&mut buf).expect("encode should succeed");
    assert_eq!(len, TAG_MULTI.len(), "multi-tag encoded length mismatch");
}

// ============================================================================
// Additional tests — beyond the C original
// ============================================================================

/// Empty container: decode of an empty byte slice produces an empty
/// `ObexApparam` with no tags.
#[test]
fn test_apparam_decode_empty() {
    let apparam = ObexApparam::decode(&[]).expect("empty decode should succeed");
    assert_eq!(apparam.encoded_len(), 0);
    assert_eq!(apparam.get_u8(0x00), None);
}

/// Empty container: encoding an empty `ObexApparam` should fail because the
/// C implementation returns `-ENOATTR` for empty containers.
#[test]
fn test_apparam_encode_empty_fails() {
    let apparam = ObexApparam::new();
    let mut buf = [0u8; 1024];
    let result = apparam.encode(&mut buf);
    assert!(result.is_err(), "encoding empty apparam should fail");
}

/// `encode_to_vec` convenience method round-trip for a single u8 tag.
#[test]
fn test_apparam_encode_to_vec_roundtrip() {
    let mut apparam = ObexApparam::new();
    apparam.set_u8(TAG_U8, 0xAB);

    let encoded = apparam.encode_to_vec().expect("encode_to_vec should succeed");
    assert_eq!(encoded, &[TAG_U8, 0x01, 0xAB]);

    let decoded = ObexApparam::decode(&encoded).expect("decode should succeed");
    assert_eq!(decoded.get_u8(TAG_U8), Some(0xAB));
}

/// `encoded_len` matches actual encoded output length for various types.
#[test]
fn test_apparam_encoded_len_accuracy() {
    let mut apparam = ObexApparam::new();
    apparam.set_u8(0x10, 1);
    // u8: 1 tag + 1 len + 1 val = 3
    assert_eq!(apparam.encoded_len(), 3);

    apparam.set_u16(0x11, 0x1234);
    // +u16: 1 + 1 + 2 = 4 → total 7
    assert_eq!(apparam.encoded_len(), 7);

    apparam.set_u32(0x12, 0x12345678);
    // +u32: 1 + 1 + 4 = 6 → total 13
    assert_eq!(apparam.encoded_len(), 13);

    apparam.set_u64(0x13, 0x123456789ABCDEF0);
    // +u64: 1 + 1 + 8 = 10 → total 23
    assert_eq!(apparam.encoded_len(), 23);
}

/// Buffer-too-small error when encoding to a buffer that is undersized.
#[test]
fn test_apparam_encode_buffer_too_small() {
    let mut apparam = ObexApparam::new();
    apparam.set_u32(TAG_U32, 0xDEADBEEF);

    // u32 tag needs 6 bytes (tag + len + 4 value bytes), provide only 4
    let mut small_buf = [0u8; 4];
    let result = apparam.encode(&mut small_buf);
    assert!(result.is_err(), "encoding to an undersized buffer should fail");
}

/// Getter returns `None` for a tag that was never set.
#[test]
fn test_apparam_get_missing_tag() {
    let mut apparam = ObexApparam::new();
    apparam.set_u8(0x10, 42);

    assert_eq!(apparam.get_u8(0x20), None, "missing u8 tag");
    assert_eq!(apparam.get_u16(0x20), None, "missing u16 tag");
    assert_eq!(apparam.get_u32(0x20), None, "missing u32 tag");
    assert_eq!(apparam.get_u64(0x20), None, "missing u64 tag");
    assert_eq!(apparam.get_string(0x20), None, "missing string tag");
    assert_eq!(apparam.get_bytes(0x20), None, "missing bytes tag");
}

/// Type-length mismatch: a u8 tag cannot be retrieved as u16/u32/u64
/// because the stored value has the wrong length.
#[test]
fn test_apparam_type_length_mismatch() {
    let mut apparam = ObexApparam::new();
    apparam.set_u8(0x10, 0xFF);

    // get_u8 should work
    assert_eq!(apparam.get_u8(0x10), Some(0xFF));

    // get_u16/u32/u64 should return None (length mismatch)
    assert_eq!(apparam.get_u16(0x10), None);
    assert_eq!(apparam.get_u32(0x10), None);
    assert_eq!(apparam.get_u64(0x10), None);
}

/// Multi-tag round-trip via `encode_to_vec` + `decode`: all values survive.
#[test]
fn test_apparam_multi_roundtrip() {
    let mut original = ObexApparam::new();
    original.set_u8(0x10, 0xAA);
    original.set_u16(0x11, 0xBBCC);
    original.set_u32(0x12, 0xDDEEFF00);
    original.set_string(0x13, "test");

    let encoded = original.encode_to_vec().expect("encode_to_vec should succeed");
    let decoded = ObexApparam::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.get_u8(0x10), Some(0xAA));
    assert_eq!(decoded.get_u16(0x11), Some(0xBBCC));
    assert_eq!(decoded.get_u32(0x12), Some(0xDDEEFF00));
    assert_eq!(decoded.get_string(0x13), Some("test".to_owned()));
}

// ============================================================================
// PBAP-specific application parameter tests
// ============================================================================

/// PBAP MaxListCount and ListStartOffset round-trip.
///
/// In the Bluetooth PBAP specification, application parameters use the same
/// TLV format with profile-specific tag IDs.  This test verifies that
/// `ObexApparam` correctly handles typical PBAP parameter values.
///
/// PBAP tag assignments (representative, not exhaustive):
///   MaxListCount:   tag 0x01, 2 bytes (u16)
///   ListStartOffset: tag 0x02, 2 bytes (u16)
///   Filter:         tag 0x03, 8 bytes (u64)
///   Format:         tag 0x04, 1 byte  (u8)
///   PhonebookSize:  tag 0x05, 2 bytes (u16)
///   NewMissedCalls: tag 0x06, 1 byte  (u8)
#[test]
fn test_apparam_pbap_parameters() {
    let mut apparam = ObexApparam::new();

    // MaxListCount = 500
    apparam.set_u16(0x01, 500);
    // ListStartOffset = 10
    apparam.set_u16(0x02, 10);
    // Filter = all fields enabled (0xFFFFFFFF_FFFFFFFF)
    apparam.set_u64(0x03, 0xFFFFFFFF_FFFFFFFF);
    // Format = vCard 3.0 (1)
    apparam.set_u8(0x04, 1);
    // PhonebookSize = 1000
    apparam.set_u16(0x05, 1000);
    // NewMissedCalls = 3
    apparam.set_u8(0x06, 3);

    let encoded = apparam.encode_to_vec().expect("PBAP encode should succeed");
    let decoded = ObexApparam::decode(&encoded).expect("PBAP decode should succeed");

    assert_eq!(decoded.get_u16(0x01), Some(500));
    assert_eq!(decoded.get_u16(0x02), Some(10));
    assert_eq!(decoded.get_u64(0x03), Some(0xFFFFFFFF_FFFFFFFF));
    assert_eq!(decoded.get_u8(0x04), Some(1));
    assert_eq!(decoded.get_u16(0x05), Some(1000));
    assert_eq!(decoded.get_u8(0x06), Some(3));
}

// ============================================================================
// MAP-specific application parameter tests
// ============================================================================

/// MAP (Message Access Profile) application parameter round-trip.
///
/// MAP uses the same TLV mechanism with profile-specific tag IDs:
///   MaxListCount:  tag 0x01, 2 bytes (u16)
///   ListStartOffset: tag 0x02, 2 bytes (u16)
///   SubjectLength: tag 0x05, 1 byte  (u8)
///   ParameterMask: tag 0x06, 4 bytes (u32)
///   FolderListSize: tag 0x11, 2 bytes (u16)
///   MessageListSize: tag 0x12, 2 bytes (u16)
#[test]
fn test_apparam_map_parameters() {
    let mut apparam = ObexApparam::new();

    // MaxListCount = 1024
    apparam.set_u16(0x01, 1024);
    // SubjectLength = 64
    apparam.set_u8(0x05, 64);
    // ParameterMask = 0x0000FFFF
    apparam.set_u32(0x06, 0x0000FFFF);
    // FolderListSize = 256
    apparam.set_u16(0x11, 256);

    let encoded = apparam.encode_to_vec().expect("MAP encode should succeed");
    let decoded = ObexApparam::decode(&encoded).expect("MAP decode should succeed");

    assert_eq!(decoded.get_u16(0x01), Some(1024));
    assert_eq!(decoded.get_u8(0x05), Some(64));
    assert_eq!(decoded.get_u32(0x06), Some(0x0000FFFF));
    assert_eq!(decoded.get_u16(0x11), Some(256));
}

/// MAP folder name as a string application parameter.
#[test]
fn test_apparam_map_folder_string() {
    let mut apparam = ObexApparam::new();
    apparam.set_string(0x20, "inbox");

    let encoded = apparam.encode_to_vec().expect("encode should succeed");
    let decoded = ObexApparam::decode(&encoded).expect("decode should succeed");

    assert_eq!(decoded.get_string(0x20), Some("inbox".to_owned()));
}

/// Maximum-length value: a 255-byte raw bytes payload (the maximum allowed
/// by the 1-byte length field in TLV format).
#[test]
fn test_apparam_max_length_bytes() {
    let payload: Vec<u8> = (0u8..=254).collect(); // 255 bytes: 0x00..0xFE
    assert_eq!(payload.len(), 255);

    let mut apparam = ObexApparam::new();
    apparam.set_bytes(0xAA, &payload);

    let encoded = apparam.encode_to_vec().expect("encode max-length should succeed");

    // Encoded: 1 (tag) + 1 (length) + 255 (value) = 257 bytes
    assert_eq!(encoded.len(), 257);

    let decoded = ObexApparam::decode(&encoded).expect("decode should succeed");
    let data = decoded.get_bytes(0xAA).expect("get_bytes should return Some");
    assert_eq!(data, &payload[..]);
}

/// Overwriting an existing tag replaces the value (last-write wins).
#[test]
fn test_apparam_overwrite_tag() {
    let mut apparam = ObexApparam::new();
    apparam.set_u8(0x10, 1);
    assert_eq!(apparam.get_u8(0x10), Some(1));

    // Overwrite with a new value
    apparam.set_u8(0x10, 99);
    assert_eq!(apparam.get_u8(0x10), Some(99));

    // Overwrite with a different type (u16) — the raw bytes change
    apparam.set_u16(0x10, 0x1234);
    assert_eq!(apparam.get_u16(0x10), Some(0x1234));
    // Previous u8 getter now returns None (length is 2, not 1)
    assert_eq!(apparam.get_u8(0x10), None);
}
