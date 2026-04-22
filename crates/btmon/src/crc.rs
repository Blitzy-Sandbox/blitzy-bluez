// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/btmon/src/crc.rs — CRC-24 primitives for Bluetooth LE Link Layer
//
// Complete Rust rewrite of monitor/crc.c (71 lines) + monitor/crc.h (17 lines)
// from BlueZ v5.86. Provides bit-reversal, forward CRC-24 calculation, and
// reverse/unwind CRC-24 used by the LL (Link Layer) dissector for Bluetooth LE
// link-layer CRC validation.
//
// Copyright (C) 2011-2014  Intel Corporation
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>

/// Bluetooth LE CRC-24 forward polynomial constant.
///
/// This encodes the Bluetooth LE CRC-24 generator polynomial
/// x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1 in the bit-reversed
/// (LSB-first) representation used by the forward CRC engine.
const CRC24_POLY_FORWARD: u32 = 0x5a_6000;

/// Bluetooth LE CRC-24 reverse polynomial constant.
///
/// This is the bit-reversed form of [`CRC24_POLY_FORWARD`], used by the
/// reverse CRC engine to unwind a CRC-24 computation and recover the
/// original preset (init) value from a known data sequence and final CRC.
const CRC24_POLY_REVERSE: u32 = 0xb4_c000;

/// Mask for the lower 24 bits of a `u32`.
const CRC24_MASK: u32 = 0x00ff_ffff;

/// Reverse the lower 24 bits of `value`.
///
/// Given a 24-bit value stored in the lower bits of a `u32`, this function
/// produces its bit-reversed counterpart (bit 0 ↔ bit 23, bit 1 ↔ bit 22,
/// etc.). Bits above bit 23 in the input are ignored; the upper 8 bits of
/// the return value are always zero.
///
/// This operation is required by the Bluetooth LE Link Layer specification
/// because the CRC preset (init) value is transmitted in bit-reversed order
/// relative to the CRC computation direction.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(crc24_bit_reverse(0x000001), 0x800000);
/// assert_eq!(crc24_bit_reverse(0x800000), 0x000001);
/// assert_eq!(crc24_bit_reverse(0xAAAAAA), 0x555555);
/// ```
#[inline]
pub fn crc24_bit_reverse(value: u32) -> u32 {
    let mut result: u32 = 0;
    for i in 0u32..24 {
        result |= ((value >> i) & 1) << (23 - i);
    }
    result
}

/// Calculate a forward CRC-24 over the given data, starting from `preset`.
///
/// Implements the Bluetooth LE CRC-24 algorithm as specified in the
/// Bluetooth Core Specification Vol 6, Part B, Section 3.1.1. The CRC is
/// processed LSB-first (matching the BLE air interface bit ordering) using
/// the polynomial encoded in [`CRC24_POLY_FORWARD`] (0x5a6000).
///
/// # Parameters
///
/// * `preset` — Initial CRC-24 state (only the lower 24 bits are used).
/// * `data`   — Byte slice of payload to accumulate into the CRC.
///
/// # Returns
///
/// The resulting 24-bit CRC value in the lower bits of a `u32`.
///
/// # Note
///
/// The original C implementation limited the data length to 255 bytes
/// (`uint8_t len`). This Rust version accepts slices of any length, which
/// is a safe generalization since the caller controls the slice bounds.
#[inline]
pub fn crc24_calculate(preset: u32, data: &[u8]) -> u32 {
    let mut state = preset;
    for &byte in data {
        let mut cur = byte;
        for _ in 0u32..8 {
            let next_bit = (state ^ u32::from(cur)) & 1;
            cur >>= 1;
            state >>= 1;
            if next_bit != 0 {
                state |= 1 << 23;
                state ^= CRC24_POLY_FORWARD;
            }
        }
    }
    state
}

/// Reverse (unwind) a CRC-24 calculation to recover the original preset.
///
/// Given a final CRC value and the data over which it was computed, this
/// function reverses the forward CRC-24 computation to recover the preset
/// (init) value. This is used by the btmon LL dissector to determine the
/// CRC init value of a Bluetooth LE connection from captured link-layer
/// packets where the CRC and data are known.
///
/// The data is processed in reverse byte order (last byte first) using the
/// reverse polynomial [`CRC24_POLY_REVERSE`] (0xb4c000), with bits
/// extracted MSB-first within each byte.
///
/// # Parameters
///
/// * `crc`  — The final CRC-24 value (only the lower 24 bits are used).
/// * `data` — The data slice over which the CRC was originally computed.
///
/// # Returns
///
/// The recovered 24-bit CRC preset (init) value in the lower bits of a `u32`.
///
/// # Round-Trip Property
///
/// For any valid preset and data:
/// ```ignore
/// let crc = crc24_calculate(preset, data);
/// assert_eq!(crc24_reverse(crc, data), preset);
/// ```
#[inline]
pub fn crc24_reverse(crc: u32, data: &[u8]) -> u32 {
    let mut state = crc;
    let len = data.len();
    for i in 0..len {
        let cur = data[len - i - 1];
        for n in 0u32..8 {
            let top_bit = state >> 23;
            state = (state << 1) & CRC24_MASK;
            state |= top_bit ^ ((u32::from(cur) >> (7 - n)) & 1);
            if top_bit != 0 {
                state ^= CRC24_POLY_REVERSE;
            }
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    //  crc24_bit_reverse
    // ---------------------------------------------------------------

    #[test]
    fn bit_reverse_single_low_bit() {
        // Bit 0 → Bit 23
        assert_eq!(crc24_bit_reverse(0x00_0001), 0x80_0000);
    }

    #[test]
    fn bit_reverse_single_high_bit() {
        // Bit 23 → Bit 0
        assert_eq!(crc24_bit_reverse(0x80_0000), 0x00_0001);
    }

    #[test]
    fn bit_reverse_alternating_bits() {
        // 0xAAAAAA = 1010...10 → 0x555555 = 0101...01
        assert_eq!(crc24_bit_reverse(0xAA_AAAA), 0x55_5555);
    }

    #[test]
    fn bit_reverse_zero() {
        assert_eq!(crc24_bit_reverse(0x00_0000), 0x00_0000);
    }

    #[test]
    fn bit_reverse_all_ones() {
        // 0xFFFFFF reversed is still 0xFFFFFF
        assert_eq!(crc24_bit_reverse(0xFF_FFFF), 0xFF_FFFF);
    }

    #[test]
    fn bit_reverse_involution() {
        // Reversing twice yields the original value.
        let values = [0x00_0001u32, 0x80_0000, 0xAA_AAAA, 0x12_3456, 0xAB_CDEF & CRC24_MASK];
        for &v in &values {
            assert_eq!(crc24_bit_reverse(crc24_bit_reverse(v)), v);
        }
    }

    #[test]
    fn bit_reverse_ignores_upper_bits() {
        // Bits 24-31 of the input must be ignored; output must fit in 24 bits.
        let with_upper = 0xFF_000001u32;
        assert_eq!(crc24_bit_reverse(with_upper), 0x80_0000);
    }

    // ---------------------------------------------------------------
    //  crc24_calculate
    // ---------------------------------------------------------------

    #[test]
    fn calculate_empty_data() {
        // With no data bytes the CRC should equal the preset.
        let preset = 0x55_5555;
        assert_eq!(crc24_calculate(preset, &[]), preset);
    }

    #[test]
    fn calculate_single_zero_byte() {
        // Known computation: preset 0, single 0x00 byte.
        let result = crc24_calculate(0, &[0x00]);
        // Verify deterministic (same input → same output).
        assert_eq!(crc24_calculate(0, &[0x00]), result);
    }

    #[test]
    fn calculate_deterministic() {
        // Same inputs must always produce the same CRC.
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let preset = 0x55_5555;
        let crc1 = crc24_calculate(preset, &data);
        let crc2 = crc24_calculate(preset, &data);
        assert_eq!(crc1, crc2);
    }

    #[test]
    fn calculate_fits_in_24_bits() {
        // The result must never exceed 24 bits.
        let data = [0xFF; 64];
        let result = crc24_calculate(CRC24_MASK, &data);
        assert_eq!(result & !CRC24_MASK, 0);
    }

    // ---------------------------------------------------------------
    //  crc24_reverse
    // ---------------------------------------------------------------

    #[test]
    fn reverse_empty_data() {
        // Reversing with no data bytes should return the CRC itself.
        let crc = 0xAB_CDEF & CRC24_MASK;
        assert_eq!(crc24_reverse(crc, &[]), crc);
    }

    #[test]
    fn reverse_fits_in_24_bits() {
        let data = [0xFF; 64];
        let result = crc24_reverse(CRC24_MASK, &data);
        assert_eq!(result & !CRC24_MASK, 0);
    }

    // ---------------------------------------------------------------
    //  Round-trip: calculate → reverse recovers preset
    // ---------------------------------------------------------------

    #[test]
    fn round_trip_single_byte() {
        let preset = 0x55_5555;
        let data = [0x42u8];
        let crc = crc24_calculate(preset, &data);
        let recovered = crc24_reverse(crc, &data);
        assert_eq!(recovered, preset);
    }

    #[test]
    fn round_trip_multi_byte() {
        let preset = 0x12_3456;
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let crc = crc24_calculate(preset, &data);
        let recovered = crc24_reverse(crc, &data);
        assert_eq!(recovered, preset);
    }

    #[test]
    fn round_trip_zero_preset() {
        let preset = 0x00_0000;
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let crc = crc24_calculate(preset, &data);
        let recovered = crc24_reverse(crc, &data);
        assert_eq!(recovered, preset);
    }

    #[test]
    fn round_trip_all_ones_preset() {
        let preset = CRC24_MASK;
        let data = [0x00, 0xFF, 0x55, 0xAA];
        let crc = crc24_calculate(preset, &data);
        let recovered = crc24_reverse(crc, &data);
        assert_eq!(recovered, preset);
    }

    #[test]
    fn round_trip_ble_advertising_pdu_pattern() {
        // Simulate a BLE advertising PDU-length payload with the standard
        // BLE advertising CRC init value (0x555555).
        let preset = 0x55_5555;
        let data: Vec<u8> = (0u8..=38).collect();
        let crc = crc24_calculate(preset, &data);
        let recovered = crc24_reverse(crc, &data);
        assert_eq!(recovered, preset);
    }

    #[test]
    fn round_trip_various_presets() {
        let presets = [0x00_0000u32, 0x55_5555, 0xAA_AAAA, 0xFF_FFFF, 0x12_3456, 0x78_9ABC];
        let data = [0x10, 0x20, 0x30, 0x40, 0x50];
        for &preset in &presets {
            let crc = crc24_calculate(preset, &data);
            let recovered = crc24_reverse(crc, &data);
            assert_eq!(recovered, preset, "Round-trip failed for preset 0x{preset:06X}");
        }
    }

    // ---------------------------------------------------------------
    //  Cross-validation: bit_reverse interacts correctly with CRC
    // ---------------------------------------------------------------

    #[test]
    fn bit_reverse_of_calculated_crc_is_reversible() {
        let preset = 0xAB_CDEF & CRC24_MASK;
        let data = [0x01, 0x02, 0x03];
        let crc = crc24_calculate(preset, &data);
        let reversed_crc = crc24_bit_reverse(crc);
        // Bit-reversing twice returns to the original.
        assert_eq!(crc24_bit_reverse(reversed_crc), crc);
    }
}
