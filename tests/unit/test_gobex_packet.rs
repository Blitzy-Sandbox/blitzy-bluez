// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX packet test suite — Rust rewrite of unit/test-gobex-packet.c (248 lines)
// from BlueZ v5.86.
//
// Converts all 9 GLib test functions into Rust `#[test]` functions:
//   1. test_pkt           — Packet creation with FINAL bit
//   2. test_decode_pkt    — Minimal PUT packet decoding
//   3. test_decode_pkt_header — Decode PUT + ACTION header, verify u8 value
//   4. test_decode_connect — Decode CONNECT with header_offset=4, verify TARGET
//   5. test_decode_nval   — Invalid packet length triggers ParseError
//   6. test_decode_encode — Roundtrip decode→encode byte identity
//   7. test_encode_on_demand — Body producer fills [1,2,3,4], verify wire output
//   8. test_encode_on_demand_fail — Body producer error propagation
//   9. test_create_args   — Multi-header packet construction and encoding
//
// All wire byte arrays are preserved exactly from the C source to ensure
// byte-identical protocol behavior.

use obexd::obex::header::{
    HDR_ACTION, HDR_BODY, HDR_CONNECTION, HDR_INVALID, HDR_NAME, HDR_TARGET, HDR_TYPE, ObexHeader,
};
use obexd::obex::packet::{OP_CONNECT, OP_PUT, ObexPacket, PACKET_FINAL, PacketError};
use obexd::obex::session::ObexError;

// ---------------------------------------------------------------------------
// Test data arrays — wire bytes matching C static arrays exactly
// ---------------------------------------------------------------------------

/// CONNECT packet: opcode=CONNECT (0x00), length=12,
/// ConnectData=[0x10, 0x00, 0x10, 0x00], TARGET header with bytes [0xab, 0xcd].
///
/// C: `pkt_connect[] = { G_OBEX_OP_CONNECT, 0x00, 0x0c, 0x10, 0x00, 0x10, 0x00,
///                        G_OBEX_HDR_TARGET, 0x00, 0x05, 0xab, 0xcd }`
const PKT_CONNECT: &[u8] =
    &[OP_CONNECT, 0x00, 0x0c, 0x10, 0x00, 0x10, 0x00, HDR_TARGET, 0x00, 0x05, 0xab, 0xcd];

/// PUT packet with ACTION header value 0xab.
///
/// C: `pkt_put_action[] = { G_OBEX_OP_PUT, 0x00, 0x05, G_OBEX_HDR_ACTION, 0xab }`
const PKT_PUT_ACTION: &[u8] = &[OP_PUT, 0x00, 0x05, HDR_ACTION, 0xab];

/// PUT packet with BODY header containing [1, 2, 3, 4].
///
/// C: `pkt_put_body[] = { G_OBEX_OP_PUT, 0x00, 0x0a,
///                         G_OBEX_HDR_BODY, 0x00, 0x07, 1, 2, 3, 4 }`
const PKT_PUT_BODY: &[u8] = &[OP_PUT, 0x00, 0x0a, HDR_BODY, 0x00, 0x07, 1, 2, 3, 4];

/// Minimal PUT packet with no headers (3 bytes total).
///
/// C: `pkt_put[] = { G_OBEX_OP_PUT, 0x00, 0x03 }`
const PKT_PUT: &[u8] = &[OP_PUT, 0x00, 0x03];

/// PUT packet with invalid (oversized) length field — declared length 0xabcd
/// far exceeds the 4-byte buffer.  Decode must return ParseError.
///
/// C: `pkt_nval_len[] = { G_OBEX_OP_PUT, 0xab, 0xcd, 0x12 }`
const PKT_NVAL_LEN: &[u8] = &[OP_PUT, 0xab, 0xcd, 0x12];

/// PUT packet with 5 headers: CONNECTION (u32), TYPE (bytes), NAME (unicode),
/// ACTION (u8), BODY (bytes).  Total 50 bytes.
///
/// C: `pkt_put_long[] = { G_OBEX_OP_PUT, 0x00, 0x32, ... }`
const PKT_PUT_LONG: &[u8] = &[
    OP_PUT,
    0x00,
    0x32, // opcode + length (50)
    // HDR_CONNECTION (0xCB) — 4-byte value 0x01020304
    HDR_CONNECTION,
    0x01,
    0x02,
    0x03,
    0x04,
    // HDR_TYPE (0x42) — byte sequence "foo/bar\0" (length 0x0b = 11)
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
    // HDR_NAME (0x01) — Unicode (UTF-16BE) "file.txt" + null (length 0x15 = 21)
    HDR_NAME,
    0x00,
    0x15,
    0x00,
    b'f',
    0x00,
    b'i',
    0x00,
    b'l',
    0x00,
    b'e',
    0x00,
    b'.',
    0x00,
    b't',
    0x00,
    b'x',
    0x00,
    b't',
    0x00,
    0x00,
    // HDR_ACTION (0x94) — single byte 0xab
    HDR_ACTION,
    0xab,
    // HDR_BODY (0x48) — byte sequence [0x00, 0x01, 0x02, 0x03, 0x04] (length 0x08 = 8)
    HDR_BODY,
    0x00,
    0x08,
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
];

// ---------------------------------------------------------------------------
// Test functions — direct conversion of C GLib g_test_add_func entries
// ---------------------------------------------------------------------------

/// Verify basic packet creation with FINAL bit set.
///
/// C: `test_pkt` — `g_obex_packet_new(G_OBEX_OP_PUT, TRUE, G_OBEX_HDR_INVALID)`
#[test]
fn test_pkt() {
    let pkt = ObexPacket::new(OP_PUT);

    // ObexPacket::new defaults to final_bit = true.
    assert!(pkt.is_final(), "new packet must have FINAL bit set");

    // Verify opcode stored correctly.
    assert_eq!(pkt.opcode(), OP_PUT);

    // Schema conformance: reference PACKET_FINAL and HDR_INVALID constants.
    assert_eq!(PACKET_FINAL, 0x80);
    assert_eq!(HDR_INVALID, 0x00);
}

/// Decode a minimal 3-byte PUT packet successfully.
///
/// C: `test_decode_pkt` — `g_obex_packet_decode(pkt_put, sizeof(pkt_put), 0, ...)`
#[test]
fn test_decode_pkt() {
    let (pkt, consumed) = ObexPacket::decode(PKT_PUT, 0).expect("decode must succeed");

    assert_eq!(consumed, PKT_PUT.len(), "consumed must match buffer length");
    assert_eq!(pkt.opcode(), OP_PUT, "opcode must be PUT");
}

/// Decode a PUT packet with an ACTION header; verify header u8 value.
///
/// C: `test_decode_pkt_header` — decodes `pkt_put_action`, retrieves ACTION header,
///     asserts value == 0xab via `g_obex_header_get_uint8`.
#[test]
fn test_decode_pkt_header() {
    let (pkt, _consumed) = ObexPacket::decode(PKT_PUT_ACTION, 0).expect("decode must succeed");

    let header: &ObexHeader = pkt.get_header(HDR_ACTION).expect("ACTION header must be present");

    assert_eq!(header.as_u8(), Some(0xab), "ACTION header value must be 0xab");
}

/// Decode a CONNECT packet with `header_offset=4` (skipping 4-byte ConnectData);
/// verify TARGET header bytes `[0xab, 0xcd]`.
///
/// C: `test_decode_connect` — decodes `pkt_connect` with offset 4,
///     retrieves TARGET header, asserts bytes via `g_obex_header_get_bytes`.
#[test]
fn test_decode_connect() {
    let (pkt, _consumed) = ObexPacket::decode(PKT_CONNECT, 4).expect("decode must succeed");

    let header: &ObexHeader = pkt.get_header(HDR_TARGET).expect("TARGET header must be present");

    let bytes = header.as_bytes().expect("TARGET must be a bytes header");
    assert_eq!(bytes, &[0xab, 0xcd], "TARGET header bytes must match");
}

/// Attempt to decode a packet whose declared length (0xabcd = 43981) far exceeds
/// the 4-byte buffer — must return `PacketError::ParseError`.
///
/// C: `test_decode_nval` — asserts `g_assert_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR)`.
#[test]
fn test_decode_nval() {
    let result = ObexPacket::decode(PKT_NVAL_LEN, 0);

    assert!(result.is_err(), "decode of invalid packet must fail");

    match result.unwrap_err() {
        PacketError::ParseError(_msg) => { /* expected: declared length exceeds buffer */ }
        other => panic!("expected PacketError::ParseError, got: {other}"),
    }

    // Schema conformance: ObexError::ParseError maps to this error domain.
    // Verify the variant constructor is accessible.
    let _obex_err = ObexError::ParseError("maps to PacketError::ParseError".into());
}

/// Roundtrip test: decode `pkt_put_action`, re-encode, verify byte-identical output.
///
/// C: `test_decode_encode` (registered as "/gobex/test_encode_pkt") —
///     decodes, encodes into buffer, `assert_memequal(pkt_put_action, ...)`.
#[test]
fn test_decode_encode() {
    let (mut pkt, _consumed) = ObexPacket::decode(PKT_PUT_ACTION, 0).expect("decode must succeed");

    let mut buf = [0u8; 255];
    let len = pkt.encode(&mut buf).expect("encode must succeed");

    assert_eq!(&buf[..len], PKT_PUT_ACTION, "re-encoded bytes must be identical to source");
}

/// Create a PUT packet (not final), attach a body producer that writes [1,2,3,4],
/// encode, and verify the output matches `pkt_put_body`.
///
/// C: `test_encode_on_demand` — uses `get_body_data` callback writing `{1,2,3,4}`,
///     `assert_memequal(pkt_put_body, ...)`.
#[test]
fn test_encode_on_demand() {
    let mut pkt = ObexPacket::new(OP_PUT);
    pkt.set_final(false);

    pkt.set_body_producer(Box::new(|buf: &mut [u8]| -> Result<usize, PacketError> {
        let data: [u8; 4] = [1, 2, 3, 4];
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }));

    let mut buf = [0u8; 255];
    let len = pkt.encode(&mut buf).expect("encode must succeed");

    assert_eq!(&buf[..len], PKT_PUT_BODY, "on-demand body encoding must match expected wire bytes");
}

/// Create a PUT packet (not final), attach a body producer that returns an error,
/// verify that encode propagates the failure.
///
/// C: `test_encode_on_demand_fail` — uses `get_body_data_fail` returning `-EIO`,
///     asserts `len == -EIO`.
#[test]
fn test_encode_on_demand_fail() {
    let mut pkt = ObexPacket::new(OP_PUT);
    pkt.set_final(false);

    pkt.set_body_producer(Box::new(|_buf: &mut [u8]| -> Result<usize, PacketError> {
        Err(PacketError::ParseError("simulated I/O error".into()))
    }));

    let mut buf = [0u8; 255];
    let result = pkt.encode(&mut buf);

    assert!(result.is_err(), "encode must fail when body producer returns error");
}

/// Create a PUT packet (not final) with five headers added via convenience methods,
/// encode, and verify the output matches `pkt_put_long` (50 bytes).
///
/// C: `test_create_args` — constructs packet via varargs:
///     `G_OBEX_HDR_CONNECTION`, `G_OBEX_HDR_TYPE`, `G_OBEX_HDR_NAME`,
///     `G_OBEX_HDR_ACTION`, `G_OBEX_HDR_BODY` → `assert_memequal(pkt_put_long, ...)`.
#[test]
fn test_create_args() {
    let mut pkt = ObexPacket::new(OP_PUT);
    pkt.set_final(false);

    // Add headers in the same order as the C test (preserves wire byte order).
    pkt.add_uint32(HDR_CONNECTION, 0x0102_0304);
    pkt.add_bytes(HDR_TYPE, b"foo/bar\0");
    pkt.add_unicode(HDR_NAME, "file.txt");
    pkt.add_uint8(HDR_ACTION, 0xab);
    pkt.add_bytes(HDR_BODY, &[0x00, 0x01, 0x02, 0x03, 0x04]);

    let mut buf = [0u8; 255];
    let len = pkt.encode(&mut buf).expect("encode must succeed");

    assert_eq!(len, PKT_PUT_LONG.len(), "encoded length must match");
    assert_eq!(&buf[..len], PKT_PUT_LONG, "multi-header packet must match expected wire bytes");
}
