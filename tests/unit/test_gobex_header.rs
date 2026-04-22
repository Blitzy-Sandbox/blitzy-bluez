// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_gobex_header.rs
//
// Unit tests for OBEX header encoding and decoding — all four header types:
//   - Unicode (null-terminated UTF-16BE text)
//   - Byte sequence (raw bytes)
//   - 1-byte unsigned integer (u8)
//   - 4-byte unsigned integer (u32)
//
// Also tests application parameter headers, multi-header decode,
// and invalid / malformed header rejection.
//
// Rust conversion of unit/test-gobex-header.c (28 test functions) from
// BlueZ v5.86.  Every byte-array fixture is preserved exactly from the
// original C source.  No `unsafe`, zero warnings.

use obexd::obex::apparam::ObexApparam;
use obexd::obex::header::{
    HDR_ACTION, HDR_APPARAM, HDR_BODY, HDR_CONNECTION, HDR_NAME, HeaderError, ObexHeader,
};
use obexd::obex::session::ObexError;

// ---------------------------------------------------------------------------
// Byte-array fixtures — preserved exactly from the C unit test.
// ---------------------------------------------------------------------------

/// Connection ID header: HDR_CONNECTION (0xcb) + 4-byte value 0x01020304.
const HDR_CONNID: &[u8] = &[0xcb, 0x01, 0x02, 0x03, 0x04];

/// Name header with empty string: HDR_NAME (0x01) + length 3 (header-only).
const HDR_NAME_EMPTY: &[u8] = &[0x01, 0x00, 0x03];

/// Name header with ASCII string "foo" in UTF-16BE + null terminator.
const HDR_NAME_ASCII: &[u8] = &[0x01, 0x00, 0x0b, 0x00, b'f', 0x00, b'o', 0x00, b'o', 0x00, 0x00];

/// Name header with "åäö" (Latin-1 codepoints) in UTF-16BE + null terminator.
const HDR_NAME_UMLAUT: &[u8] = &[0x01, 0x00, 0x0b, 0x00, 0xe5, 0x00, 0xe4, 0x00, 0xf6, 0x00, 0x00];

/// Body header: HDR_BODY (0x48) + 4 data bytes [1, 2, 3, 4].
const HDR_BODY_DATA: &[u8] = &[0x48, 0x00, 0x07, 0x01, 0x02, 0x03, 0x04];

/// Action ID header: HDR_ACTION (0x94) + 1-byte value 0xab.
const HDR_ACTIONID: &[u8] = &[0x94, 0xab];

/// Invalid uint32 header — only 3 bytes, need 5 for a complete u32 header.
const HDR_UINT32_NVAL: &[u8] = &[0xcb, 0x01, 0x02];

/// Invalid unicode header — claimed length 0x1234 far exceeds buffer size.
const HDR_UNICODE_NVAL_SHORT: &[u8] = &[0x01, 0x12, 0x34, 0x00, b'a', 0x00, b'b', 0x00, 0x00];

/// Invalid unicode header — claimed length 1 is less than minimum 3.
const HDR_UNICODE_NVAL_DATA: &[u8] = &[0x01, 0x00, 0x01, 0x00, b'a', 0x00, b'b'];

/// Invalid bytes header — claimed length 0xabcd far exceeds buffer size.
const HDR_BYTES_NVAL_SHORT: &[u8] = &[0x48, 0xab, 0xcd, 0x01, 0x02, 0x03];

/// Invalid bytes header — only 2 bytes total, need at least 3 for byte-seq.
const HDR_BYTES_NVAL_DATA: &[u8] = &[0x48, 0xab];

/// Invalid bytes header — claimed length 0 is less than minimum 3.
const HDR_BYTES_NVAL_LEN: &[u8] = &[0x48, 0x00, 0x00];

/// Application parameters header: HDR_APPARAM (0x4c) with TLV tag 0,
/// u32 value 0x01020304.
const HDR_APPARAM_DATA: &[u8] = &[0x4c, 0x00, 0x09, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];

// ---------------------------------------------------------------------------
// Helper: convert HeaderError → ObexError for interface-contract compliance.
//
// The C test-gobex-header.c checks
//   g_assert_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR).
//
// In the Rust API, `ObexHeader::decode()` returns `HeaderError`, while the
// top-level OBEX error type is `ObexError`.  This helper bridges the two
// so that every invalid-decode test also verifies the ObexError mapping.
// ---------------------------------------------------------------------------

fn header_error_to_obex_error(err: HeaderError) -> ObexError {
    match err {
        HeaderError::ParseError(msg) => ObexError::ParseError(msg),
        HeaderError::BufferTooSmall { needed, available } => {
            ObexError::ParseError(format!("buffer too small: need {needed}, got {available}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: decode from raw bytes → re-encode → verify byte-identical output.
// Returns the decoded header for further value-level inspection.
// Mirrors the C `parse_and_encode()` helper exactly.
// ---------------------------------------------------------------------------

fn parse_and_encode(buf: &[u8]) -> ObexHeader {
    let (header, consumed) =
        ObexHeader::decode(buf).expect("decode should succeed for valid fixture");
    assert_eq!(consumed, buf.len(), "decode should consume entire buffer");

    let mut encoded = vec![0u8; 1024];
    let len = header.encode(&mut encoded).expect("encode should succeed for valid header");
    assert_eq!(len, consumed, "encoded length should match consumed bytes");
    assert_eq!(&encoded[..len], buf, "re-encoded bytes should match original");

    header
}

// ===========================================================================
// Category 1: Encode tests (7 tests)
//
// Create header via constructor → encode to buffer → compare against the
// known byte-array fixture.
// ===========================================================================

#[test]
fn test_header_name_empty() {
    let header = ObexHeader::new_unicode(HDR_NAME, "");
    let mut buf = vec![0u8; 256];
    let len = header.encode(&mut buf).expect("encode empty name");
    assert_eq!(&buf[..len], HDR_NAME_EMPTY);
}

#[test]
fn test_header_name_ascii() {
    let header = ObexHeader::new_unicode(HDR_NAME, "foo");
    let mut buf = vec![0u8; 256];
    let len = header.encode(&mut buf).expect("encode ascii name");
    assert_eq!(&buf[..len], HDR_NAME_ASCII);
}

#[test]
fn test_header_name_umlaut() {
    let header = ObexHeader::new_unicode(HDR_NAME, "åäö");
    let mut buf = vec![0u8; 256];
    let len = header.encode(&mut buf).expect("encode umlaut name");
    assert_eq!(&buf[..len], HDR_NAME_UMLAUT);
}

#[test]
fn test_header_bytes() {
    let header = ObexHeader::new_bytes(HDR_BODY, &[0x01, 0x02, 0x03, 0x04]);
    let mut buf = vec![0u8; 256];
    let len = header.encode(&mut buf).expect("encode body");
    assert_eq!(&buf[..len], HDR_BODY_DATA);
}

#[test]
fn test_header_apparam() {
    let mut apparam = ObexApparam::new();
    apparam.set_u32(0, 0x0102_0304);
    let header = ObexHeader::new_apparam(&apparam).expect("new_apparam should succeed");
    // Verify the constructed header carries the correct APPARAM header ID.
    assert_eq!(header.id(), HDR_APPARAM);
    let mut buf = vec![0u8; 256];
    let len = header.encode(&mut buf).expect("encode apparam");
    assert_eq!(&buf[..len], HDR_APPARAM_DATA);
}

#[test]
fn test_header_uint8() {
    let header = ObexHeader::new_u8(HDR_ACTION, 0xab);
    let mut buf = vec![0u8; 256];
    let len = header.encode(&mut buf).expect("encode actionid");
    assert_eq!(&buf[..len], HDR_ACTIONID);
}

#[test]
fn test_header_uint32() {
    let header = ObexHeader::new_u32(HDR_CONNECTION, 0x0102_0304);
    let mut buf = vec![0u8; 256];
    let len = header.encode(&mut buf).expect("encode connid");
    assert_eq!(&buf[..len], HDR_CONNID);
}

// ===========================================================================
// Category 2: Round-trip tests (7 tests)
//
// Decode from known bytes → re-encode → verify bytes match → extract the
// typed value and compare against the expected constant.
// Uses the `parse_and_encode()` helper that mirrors C `parse_and_encode()`.
// ===========================================================================

#[test]
fn test_header_encode_connid() {
    let header = parse_and_encode(HDR_CONNID);
    let val = header.as_u32().expect("should extract u32 value");
    assert_eq!(val, 0x0102_0304);
}

#[test]
fn test_header_encode_name_ascii() {
    let header = parse_and_encode(HDR_NAME_ASCII);
    let val = header.as_unicode().expect("should extract unicode string");
    assert_eq!(val, "foo");
}

#[test]
fn test_header_encode_name_umlaut() {
    let header = parse_and_encode(HDR_NAME_UMLAUT);
    let val = header.as_unicode().expect("should extract unicode string");
    assert_eq!(val, "åäö");
}

#[test]
fn test_header_encode_name_empty() {
    let header = parse_and_encode(HDR_NAME_EMPTY);
    let val = header.as_unicode().expect("should extract unicode string");
    assert_eq!(val, "");
}

#[test]
fn test_header_encode_body() {
    let header = parse_and_encode(HDR_BODY_DATA);
    let val = header.as_bytes().expect("should extract byte data");
    // The body data is the raw payload after the 3-byte header overhead.
    assert_eq!(val.len(), HDR_BODY_DATA.len() - 3);
    assert_eq!(val, &HDR_BODY_DATA[3..]);
}

#[test]
fn test_header_encode_apparam() {
    let header = parse_and_encode(HDR_APPARAM_DATA);
    let bytes = header.as_bytes().expect("should extract apparam bytes");
    let apparam = ObexApparam::decode(bytes).expect("should decode apparam TLV");
    let val = apparam.get_u32(0).expect("should get u32 tag 0");
    assert_eq!(val, 0x0102_0304);
}

#[test]
fn test_header_encode_actionid() {
    let header = parse_and_encode(HDR_ACTIONID);
    let val = header.as_u8().expect("should extract u8 value");
    assert_eq!(val, 0xab);
}

// ===========================================================================
// Category 3a: Valid decode tests (8 tests)
//
// Decode from known bytes and verify the consumed byte count plus header
// type validity.
// ===========================================================================

#[test]
fn test_decode_header_connid() {
    let (header, consumed) = ObexHeader::decode(HDR_CONNID).expect("decode connid");
    assert_eq!(consumed, HDR_CONNID.len());
    assert!(header.as_u32().is_some());
}

#[test]
fn test_decode_header_name_ascii() {
    let (header, consumed) = ObexHeader::decode(HDR_NAME_ASCII).expect("decode name ascii");
    assert_eq!(consumed, HDR_NAME_ASCII.len());
    assert!(header.as_unicode().is_some());
}

#[test]
fn test_decode_header_name_empty() {
    let (header, consumed) = ObexHeader::decode(HDR_NAME_EMPTY).expect("decode name empty");
    assert_eq!(consumed, HDR_NAME_EMPTY.len());
    assert!(header.as_unicode().is_some());
}

#[test]
fn test_decode_header_name_umlaut() {
    let (header, consumed) = ObexHeader::decode(HDR_NAME_UMLAUT).expect("decode name umlaut");
    assert_eq!(consumed, HDR_NAME_UMLAUT.len());
    assert!(header.as_unicode().is_some());
}

#[test]
fn test_decode_header_body() {
    let (header, consumed) = ObexHeader::decode(HDR_BODY_DATA).expect("decode body");
    assert_eq!(consumed, HDR_BODY_DATA.len());
    assert!(header.as_bytes().is_some());
}

/// Buffer contains hdr_body followed by an extra trailing byte 0xff.
/// Decode should consume only the header bytes, ignoring trailing data.
#[test]
fn test_decode_header_body_extdata() {
    let mut buf = Vec::from(HDR_BODY_DATA);
    buf.push(0xff);
    let (header, consumed) = ObexHeader::decode(&buf).expect("decode body with extra data");
    assert_eq!(consumed, HDR_BODY_DATA.len());
    assert!(header.as_bytes().is_some());
}

#[test]
fn test_decode_header_actionid() {
    let (header, consumed) = ObexHeader::decode(HDR_ACTIONID).expect("decode actionid");
    assert_eq!(consumed, HDR_ACTIONID.len());
    assert!(header.as_u8().is_some());
}

/// Two headers concatenated in one buffer: connid + name_ascii.
/// Verify that sequential decode calls each consume exactly one header.
#[test]
fn test_decode_header_multi() {
    let mut buf = Vec::from(HDR_CONNID);
    buf.extend_from_slice(HDR_NAME_ASCII);

    // First header: connection ID.
    let (header1, consumed1) = ObexHeader::decode(&buf).expect("decode first header in multi");
    assert_eq!(consumed1, HDR_CONNID.len());
    assert!(header1.as_u32().is_some());

    // Second header: name (ascii), from the remaining slice.
    let (header2, consumed2) =
        ObexHeader::decode(&buf[consumed1..]).expect("decode second header in multi");
    assert_eq!(consumed2, HDR_NAME_ASCII.len());
    assert!(header2.as_unicode().is_some());
}

// ===========================================================================
// Category 3b: Invalid decode tests (6 tests)
//
// Verify that malformed headers produce parse errors.
//
// The C tests assert:
//   g_assert_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR)
//
// In Rust, `ObexHeader::decode()` returns `Err(HeaderError::ParseError(…))`.
// Each test also verifies the mapping to `ObexError::ParseError` via the
// `header_error_to_obex_error` bridge, mirroring the C error-domain check.
// ===========================================================================

#[test]
fn test_decode_header_uint32_nval() {
    let result = ObexHeader::decode(HDR_UINT32_NVAL);
    assert!(result.is_err(), "should fail on truncated uint32 header");
    let err = result.unwrap_err();
    assert!(
        matches!(err, HeaderError::ParseError(_)),
        "expected HeaderError::ParseError, got: {err:?}"
    );
    let obex_err = header_error_to_obex_error(err);
    assert!(matches!(obex_err, ObexError::ParseError(_)));
}

#[test]
fn test_decode_header_unicode_nval_short() {
    let result = ObexHeader::decode(HDR_UNICODE_NVAL_SHORT);
    assert!(result.is_err(), "should fail: unicode length exceeds buffer");
    let err = result.unwrap_err();
    assert!(
        matches!(err, HeaderError::ParseError(_)),
        "expected HeaderError::ParseError, got: {err:?}"
    );
    let obex_err = header_error_to_obex_error(err);
    assert!(matches!(obex_err, ObexError::ParseError(_)));
}

#[test]
fn test_decode_header_unicode_nval_data() {
    let result = ObexHeader::decode(HDR_UNICODE_NVAL_DATA);
    assert!(result.is_err(), "should fail: unicode length < minimum");
    let err = result.unwrap_err();
    assert!(
        matches!(err, HeaderError::ParseError(_)),
        "expected HeaderError::ParseError, got: {err:?}"
    );
    let obex_err = header_error_to_obex_error(err);
    assert!(matches!(obex_err, ObexError::ParseError(_)));
}

#[test]
fn test_decode_header_bytes_nval_short() {
    let result = ObexHeader::decode(HDR_BYTES_NVAL_SHORT);
    assert!(result.is_err(), "should fail: bytes length exceeds buffer");
    let err = result.unwrap_err();
    assert!(
        matches!(err, HeaderError::ParseError(_)),
        "expected HeaderError::ParseError, got: {err:?}"
    );
    let obex_err = header_error_to_obex_error(err);
    assert!(matches!(obex_err, ObexError::ParseError(_)));
}

#[test]
fn test_decode_header_bytes_nval_data() {
    let result = ObexHeader::decode(HDR_BYTES_NVAL_DATA);
    assert!(result.is_err(), "should fail: bytes header too short");
    let err = result.unwrap_err();
    assert!(
        matches!(err, HeaderError::ParseError(_)),
        "expected HeaderError::ParseError, got: {err:?}"
    );
    let obex_err = header_error_to_obex_error(err);
    assert!(matches!(obex_err, ObexError::ParseError(_)));
}

#[test]
fn test_decode_header_bytes_nval_len() {
    let result = ObexHeader::decode(HDR_BYTES_NVAL_LEN);
    assert!(result.is_err(), "should fail: bytes length 0 < minimum 3");
    let err = result.unwrap_err();
    assert!(
        matches!(err, HeaderError::ParseError(_)),
        "expected HeaderError::ParseError, got: {err:?}"
    );
    let obex_err = header_error_to_obex_error(err);
    assert!(matches!(obex_err, ObexError::ParseError(_)));
}
