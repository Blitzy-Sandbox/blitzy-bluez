// SPDX-License-Identifier: GPL-2.0-or-later
//
// crates/bluez-shared/src/util/crc.rs — CRC-24 primitives for Bluetooth LE
//
// Provides bit-reversal, forward CRC-24 calculation, and reverse (unwind)
// CRC-24 used across the BlueZ stack for Bluetooth LE link-layer CRC
// validation.
//
// Ported from monitor/crc.c (BlueZ v5.86). The CRC-24 algorithm is
// specified in the Bluetooth Core Specification Vol 6, Part B, Section 3.1.1.
//
// Copyright (C) 2011-2014  Intel Corporation
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>

/// Bluetooth LE CRC-24 forward polynomial (LSB-first representation).
///
/// Encodes x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1.
const CRC24_POLY_FORWARD: u32 = 0x5a_6000;

/// Bluetooth LE CRC-24 reverse polynomial (bit-reversed form of forward).
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
/// the polynomial encoded in [`CRC24_POLY_FORWARD`].
///
/// # Parameters
///
/// * `preset` — Initial CRC-24 state (only the lower 24 bits are used).
/// * `data`   — Byte slice of payload to accumulate into the CRC.
///
/// # Returns
///
/// The resulting 24-bit CRC value in the lower bits of a `u32`.
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
/// reverse polynomial [`CRC24_POLY_REVERSE`], with bits extracted MSB-first
/// within each byte.
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

    #[test]
    fn bit_reverse_single_low_bit() {
        assert_eq!(crc24_bit_reverse(0x00_0001), 0x80_0000);
    }

    #[test]
    fn bit_reverse_single_high_bit() {
        assert_eq!(crc24_bit_reverse(0x80_0000), 0x00_0001);
    }

    #[test]
    fn bit_reverse_alternating() {
        assert_eq!(crc24_bit_reverse(0xAA_AAAA), 0x55_5555);
    }

    #[test]
    fn bit_reverse_zero() {
        assert_eq!(crc24_bit_reverse(0x00_0000), 0x00_0000);
    }

    #[test]
    fn bit_reverse_all_ones() {
        assert_eq!(crc24_bit_reverse(0xFF_FFFF), 0xFF_FFFF);
    }

    #[test]
    fn bit_reverse_involution() {
        let values = [0x00_0001u32, 0x80_0000, 0xAA_AAAA, 0x12_3456, 0xAB_CDEF & CRC24_MASK];
        for &v in &values {
            assert_eq!(crc24_bit_reverse(crc24_bit_reverse(v)), v);
        }
    }

    #[test]
    fn calculate_empty_data() {
        let preset = 0x55_5555;
        assert_eq!(crc24_calculate(preset, &[]), preset);
    }

    #[test]
    fn calculate_fits_in_24_bits() {
        let data = [0xFF; 64];
        let result = crc24_calculate(CRC24_MASK, &data);
        assert_eq!(result & !CRC24_MASK, 0);
    }

    #[test]
    fn reverse_empty_data() {
        let crc = 0x12_3456;
        assert_eq!(crc24_reverse(crc, &[]), crc);
    }

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
}
