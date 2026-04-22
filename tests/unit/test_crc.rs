// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_crc.rs — CRC-24 unit tests for Bluetooth LE Link Layer
//
// Rust conversion of unit/test-crc.c from BlueZ v5.86. Tests CRC-24
// forward calculation (crc24_calculate), reverse/unwind (crc24_reverse),
// and 24-bit reversal (crc24_bit_reverse) using captured Bluetooth LE
// Link Layer packet test vectors.
//
// The C original registered 9 test cases ("/crc/1" through "/crc/9"),
// each exercising the same algorithm on a different captured LE packet.
// This Rust port preserves every packet byte array and expected result
// identically.
//
// Copyright (C) 2011  Intel Corporation

use bluez_shared::util::crc::{crc24_bit_reverse, crc24_calculate, crc24_reverse};

// -----------------------------------------------------------------------
//  Constants
// -----------------------------------------------------------------------

/// Default BLE advertising CRC initialization value (before bit-reversal).
///
/// The Bluetooth LE specification uses 0x555555 as the CRC init for
/// advertising channel PDUs. Packets 1-7 use this default; packets 8-9
/// use a connection-specific init value.
const DEFAULT_CRC_INIT_RAW: u32 = 0x55_5555;

/// Connection-specific CRC init value for test packets 8 and 9.
///
/// Extracted from the connection setup in packet 7: bytes at offset
/// 22..25 yield 0xbe, 0x1d, 0x16 in little-endian order = 0x161dbe.
const CONN_CRC_INIT_RAW: u32 = 0x16_1dbe;

// -----------------------------------------------------------------------
//  Test helper
// -----------------------------------------------------------------------

/// Verify CRC-24 forward calculation and reverse recovery for a packet.
///
/// Mirrors the C `test_crc()` function logic exactly:
///
/// 1. Bit-reverse the raw CRC init value to produce the CRC preset.
/// 2. Extract the expected CRC from the packet's last 3 bytes (LE 24-bit).
/// 3. Compute `crc24_calculate(preset, &packet[4..len-3])`.
/// 4. Assert the calculated CRC matches the expected CRC.
/// 5. Compute `crc24_reverse(expected_crc, &packet[4..len-3])`.
/// 6. Assert the recovered preset matches the bit-reversed init.
fn verify_crc_packet(packet: &[u8], raw_crc_init: u32) {
    let size = packet.len();
    assert!(size >= 7, "Packet too short for CRC-24 test: need >= 7 bytes, got {size}");

    // Bit-reverse the raw init to get the CRC preset used in calculation.
    let crc_init = crc24_bit_reverse(raw_crc_init);

    // Extract expected CRC from last 3 bytes (little-endian 24-bit).
    let crc_expected = u32::from(packet[size - 3])
        | (u32::from(packet[size - 2]) << 8)
        | (u32::from(packet[size - 1]) << 16);

    // PDU payload: skip 4-byte preamble+header, exclude 3-byte CRC trailer.
    let data = &packet[4..size - 3];

    // Forward CRC-24 calculation must match expected.
    let crc_calculated = crc24_calculate(crc_init, data);
    assert_eq!(
        crc_calculated, crc_expected,
        "Forward CRC mismatch: calculated 0x{crc_calculated:06x}, \
         expected 0x{crc_expected:06x}"
    );

    // Reverse CRC-24 must recover the original preset.
    let crc_reversed = crc24_reverse(crc_expected, data);
    assert_eq!(
        crc_reversed, crc_init,
        "Reverse CRC mismatch: recovered 0x{crc_reversed:06x}, \
         expected init 0x{crc_init:06x}"
    );
}

// -----------------------------------------------------------------------
//  Test vectors — captured Bluetooth LE Link Layer packets
//  (byte-identical to unit/test-crc.c packet_1 through packet_9)
// -----------------------------------------------------------------------

/// BLE advertising channel PDU #1.
const PACKET_1: [u8; 32] = [
    0xd6, 0xbe, 0x89, 0x8e, 0x00, 0x17, 0x7e, 0x01, 0x00, 0xd0, 0x22, 0x00, 0x02, 0x01, 0x06, 0x03,
    0x02, 0x0d, 0x18, 0x06, 0xff, 0x6b, 0x00, 0x03, 0x16, 0x52, 0x02, 0x0a, 0x00, 0xf4, 0x09, 0x92,
];

/// BLE advertising channel PDU #2.
const PACKET_2: [u8; 32] = [
    0xd6, 0xbe, 0x89, 0x8e, 0x00, 0x17, 0x7e, 0x01, 0x00, 0xd0, 0x22, 0x00, 0x02, 0x01, 0x06, 0x03,
    0x02, 0x0d, 0x18, 0x06, 0xff, 0x6b, 0x00, 0x03, 0x16, 0x54, 0x02, 0x0a, 0x00, 0x95, 0x5f, 0x14,
];

/// BLE advertising channel PDU #3.
const PACKET_3: [u8; 32] = [
    0xd6, 0xbe, 0x89, 0x8e, 0x00, 0x17, 0x7e, 0x01, 0x00, 0xd0, 0x22, 0x00, 0x02, 0x01, 0x06, 0x03,
    0x02, 0x0d, 0x18, 0x06, 0xff, 0x6b, 0x00, 0x03, 0x16, 0x55, 0x02, 0x0a, 0x00, 0x85, 0x66, 0x63,
];

/// BLE advertising channel PDU #4.
const PACKET_4: [u8; 32] = [
    0xd6, 0xbe, 0x89, 0x8e, 0x00, 0x17, 0x7e, 0x01, 0x00, 0xd0, 0x22, 0x00, 0x02, 0x01, 0x06, 0x03,
    0x02, 0x0d, 0x18, 0x06, 0xff, 0x6b, 0x00, 0x03, 0x16, 0x53, 0x02, 0x0a, 0x00, 0xe4, 0x30, 0xe5,
];

/// BLE data channel PDU #5.
const PACKET_5: [u8; 21] = [
    0xd6, 0xbe, 0x89, 0x8e, 0x03, 0x0c, 0x46, 0x1c, 0xda, 0x72, 0x02, 0x00, 0x7e, 0x01, 0x00, 0xd0,
    0x22, 0x00, 0x6e, 0xf4, 0x6f,
];

/// BLE advertising channel PDU #6.
const PACKET_6: [u8; 32] = [
    0xd6, 0xbe, 0x89, 0x8e, 0x04, 0x17, 0x7e, 0x01, 0x00, 0xd0, 0x22, 0x00, 0x10, 0x09, 0x50, 0x6f,
    0x6c, 0x61, 0x72, 0x20, 0x48, 0x37, 0x20, 0x30, 0x30, 0x30, 0x31, 0x37, 0x45, 0x0f, 0x8a, 0x65,
];

/// BLE data channel PDU #7 (connection-establishing, contains CRC init
/// for subsequent data channel packets 8 and 9).
const PACKET_7: [u8; 43] = [
    0xd6, 0xbe, 0x89, 0x8e, 0x05, 0x22, 0x46, 0x1c, 0xda, 0x72, 0x02, 0x00, 0x7e, 0x01, 0x00, 0xd0,
    0x22, 0x00, 0x96, 0x83, 0x9a, 0xaf, 0xbe, 0x1d, 0x16, 0x03, 0x05, 0x00, 0x36, 0x00, 0x00, 0x00,
    0x2a, 0x00, 0xff, 0xff, 0xff, 0xff, 0x1f, 0xa5, 0x77, 0x2d, 0x95,
];

/// BLE data channel PDU #8 (uses connection-specific CRC init 0x161dbe).
const PACKET_8: [u8; 9] = [0x96, 0x83, 0x9a, 0xaf, 0x01, 0x00, 0xc7, 0x15, 0x4d];

/// BLE data channel PDU #9 (uses connection-specific CRC init 0x161dbe).
const PACKET_9: [u8; 29] = [
    0x96, 0x83, 0x9a, 0xaf, 0x06, 0x14, 0x10, 0x00, 0x04, 0x00, 0x09, 0x07, 0x10, 0x00, 0x10, 0x11,
    0x00, 0x37, 0x2a, 0x13, 0x00, 0x02, 0x14, 0x00, 0x38, 0x2a, 0x73, 0x2a, 0xa3,
];

// -----------------------------------------------------------------------
//  CRC-24 packet validation tests (converted from C "/crc/N" test cases)
// -----------------------------------------------------------------------

/// C equivalent: tester_add("/crc/1", &crc_1, NULL, test_crc, NULL)
#[test]
fn crc_packet_1() {
    verify_crc_packet(&PACKET_1, DEFAULT_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/2", &crc_2, NULL, test_crc, NULL)
#[test]
fn crc_packet_2() {
    verify_crc_packet(&PACKET_2, DEFAULT_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/3", &crc_3, NULL, test_crc, NULL)
#[test]
fn crc_packet_3() {
    verify_crc_packet(&PACKET_3, DEFAULT_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/4", &crc_4, NULL, test_crc, NULL)
#[test]
fn crc_packet_4() {
    verify_crc_packet(&PACKET_4, DEFAULT_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/5", &crc_5, NULL, test_crc, NULL)
#[test]
fn crc_packet_5() {
    verify_crc_packet(&PACKET_5, DEFAULT_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/6", &crc_6, NULL, test_crc, NULL)
#[test]
fn crc_packet_6() {
    verify_crc_packet(&PACKET_6, DEFAULT_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/7", &crc_7, NULL, test_crc, NULL)
#[test]
fn crc_packet_7() {
    verify_crc_packet(&PACKET_7, DEFAULT_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/8", &crc_8, NULL, test_crc, NULL)
///
/// Uses connection-specific CRC init 0x161dbe (from packet_7 bytes
/// at offset 22..25: 0xbe, 0x1d, 0x16 in little-endian).
#[test]
fn crc_packet_8() {
    verify_crc_packet(&PACKET_8, CONN_CRC_INIT_RAW);
}

/// C equivalent: tester_add("/crc/9", &crc_9, NULL, test_crc, NULL)
///
/// Uses connection-specific CRC init 0x161dbe (from packet_7 bytes
/// at offset 22..25: 0xbe, 0x1d, 0x16 in little-endian).
#[test]
fn crc_packet_9() {
    verify_crc_packet(&PACKET_9, CONN_CRC_INIT_RAW);
}

// -----------------------------------------------------------------------
//  Additional coverage tests for CRC-24 functions
// -----------------------------------------------------------------------

/// Verify that bit-reversing the default BLE CRC init produces 0xAAAAAA.
///
/// 0x555555 = 0101_0101_0101_0101_0101_0101 in binary (24 bits).
/// Reversed = 1010_1010_1010_1010_1010_1010 = 0xAAAAAA.
#[test]
fn bit_reverse_default_init() {
    assert_eq!(crc24_bit_reverse(0x55_5555), 0xAA_AAAA);
}

/// Verify that bit-reversing is an involution (applying twice recovers
/// the original value) for all CRC init values used in these tests.
#[test]
fn bit_reverse_involution() {
    let values: [u32; 5] =
        [DEFAULT_CRC_INIT_RAW, CONN_CRC_INIT_RAW, 0x00_0001, 0x80_0000, 0xFF_FFFF];
    for val in values {
        assert_eq!(
            crc24_bit_reverse(crc24_bit_reverse(val)),
            val,
            "Involution failed for 0x{val:06x}"
        );
    }
}

/// Verify that crc24_calculate with empty data returns the preset unchanged.
#[test]
fn calculate_empty_data_returns_preset() {
    let preset = crc24_bit_reverse(DEFAULT_CRC_INIT_RAW);
    assert_eq!(crc24_calculate(preset, &[]), preset);
}

/// Verify that crc24_reverse with empty data returns the CRC unchanged.
#[test]
fn reverse_empty_data_returns_crc() {
    let crc: u32 = 0x12_3456;
    assert_eq!(crc24_reverse(crc, &[]), crc);
}
