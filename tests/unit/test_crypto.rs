// SPDX-License-Identifier: GPL-2.0-or-later
//
//  BlueZ - Bluetooth protocol stack for Linux
//
//  Copyright (C) 2011  Intel Corporation
//

//! Bluetooth AES-CMAC cryptographic unit tests.
//!
//! Converted from `unit/test-crypto.c` — tests the h6 link-key conversion
//! function, ATT signing/verification, GATT database hashing, SIRK
//! Encryption Function (SEF), and SIRK Hash Function (SIH) using known
//! test vectors from the Bluetooth Core Specification.
//!
//! All byte-level test vectors are preserved verbatim from the C original.
//! Each `#[test]` function corresponds to a `tester_add()` registration in
//! the C `main()` function.

use bluez_shared::crypto::aes_cmac::{
    CryptoError, bt_crypto_gatt_hash, bt_crypto_h6, bt_crypto_sef, bt_crypto_sign_att,
    bt_crypto_sih, bt_crypto_verify_att_sign,
};

// ============================================================================
// Shared Test Constants
// ============================================================================

/// Shared signing key for ATT signing test cases 1–4.
///
/// Corresponds to the file-scope `key[]` in test-crypto.c (line 74).
const ATT_SIGN_KEY: [u8; 16] = [
    0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab, 0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b,
];

/// Alternate signing key used by test case 5 and the verification tests.
///
/// Corresponds to `key_5[]` in test-crypto.c (line 151).
const ATT_SIGN_KEY_5: [u8; 16] = [
    0x50, 0x5E, 0x42, 0xDF, 0x96, 0x91, 0xEC, 0x72, 0xD3, 0x1F, 0xCD, 0xFB, 0xEB, 0x64, 0x1B, 0x61,
];

// ============================================================================
// Test: h6 — Link Key Conversion Function
// ============================================================================

/// Port of `/crypto/h6` from unit/test-crypto.c (lines 29–64).
///
/// Tests the h6 link-key conversion function with a known test vector:
///   h6(W, keyID) → 128-bit derived key
/// where W is a 128-bit input key and keyID is a 32-bit identifier.
#[test]
fn test_h6() {
    let w: [u8; 16] = [
        0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34, 0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34, 0x02,
        0xec,
    ];
    let m: [u8; 4] = [0x72, 0x62, 0x65, 0x6c];
    let expected: [u8; 16] = [
        0x99, 0x63, 0xb1, 0x80, 0xe2, 0xa9, 0xd3, 0xe8, 0x1c, 0xc9, 0x6d, 0xe7, 0x02, 0xe1, 0x9a,
        0x2d,
    ];

    let result = bt_crypto_h6(&w, &m).expect("bt_crypto_h6 should succeed");
    assert_eq!(result, expected, "h6 result mismatch");
}

// ============================================================================
// Test: ATT Signing (5 test cases)
// ============================================================================

/// Port of `/crypto/sign_att_1` from unit/test-crypto.c.
///
/// Empty payload (msg_len=0), sign counter=0, shared key.
/// Corresponds to `test_data_1` (lines 85–90).
#[test]
fn test_att_sign_1() {
    // msg_1 in C is {0x00} with msg_len=0 — effectively an empty payload.
    let expected: [u8; 12] =
        [0x00, 0x00, 0x00, 0x00, 0xb3, 0xa8, 0x59, 0x41, 0x27, 0xeb, 0xc2, 0xc0];

    let result = bt_crypto_sign_att(&ATT_SIGN_KEY, &[], 0)
        .expect("bt_crypto_sign_att should succeed for empty payload");
    assert_eq!(result, expected, "sign_att_1 result mismatch");
}

/// Port of `/crypto/sign_att_2` from unit/test-crypto.c.
///
/// 16-byte message (single AES block), sign counter=0, shared key.
/// Corresponds to `test_data_2` (lines 102–107).
#[test]
fn test_att_sign_2() {
    let msg: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let expected: [u8; 12] =
        [0x00, 0x00, 0x00, 0x00, 0x27, 0x39, 0x74, 0xf4, 0x39, 0x2a, 0x23, 0x2a];

    let result = bt_crypto_sign_att(&ATT_SIGN_KEY, &msg, 0)
        .expect("bt_crypto_sign_att should succeed for 16-byte payload");
    assert_eq!(result, expected, "sign_att_2 result mismatch");
}

/// Port of `/crypto/sign_att_3` from unit/test-crypto.c.
///
/// 40-byte message (multi-block), sign counter=0, shared key.
/// Corresponds to `test_data_3` (lines 120–125).
#[test]
fn test_att_sign_3() {
    let msg: [u8; 40] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    ];
    let expected: [u8; 12] =
        [0x00, 0x00, 0x00, 0x00, 0xb7, 0xca, 0x94, 0xab, 0x87, 0xc7, 0x82, 0x18];

    let result = bt_crypto_sign_att(&ATT_SIGN_KEY, &msg, 0)
        .expect("bt_crypto_sign_att should succeed for 40-byte payload");
    assert_eq!(result, expected, "sign_att_3 result mismatch");
}

/// Port of `/crypto/sign_att_4` from unit/test-crypto.c.
///
/// 64-byte message (four AES blocks), sign counter=0, shared key.
/// Corresponds to `test_data_4` (lines 140–145).
#[test]
fn test_att_sign_4() {
    let msg: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];
    let expected: [u8; 12] =
        [0x00, 0x00, 0x00, 0x00, 0x44, 0xe1, 0xe6, 0xce, 0x1d, 0xf5, 0x13, 0x68];

    let result = bt_crypto_sign_att(&ATT_SIGN_KEY, &msg, 0)
        .expect("bt_crypto_sign_att should succeed for 64-byte payload");
    assert_eq!(result, expected, "sign_att_4 result mismatch");
}

/// Port of `/crypto/sign_att_5` from unit/test-crypto.c.
///
/// 5-byte message, sign counter=1, alternate key (key_5).
/// Corresponds to `test_data_5` (lines 161–167).
#[test]
fn test_att_sign_5() {
    let msg: [u8; 5] = [0xd2, 0x12, 0x00, 0x13, 0x37];
    let expected: [u8; 12] =
        [0x01, 0x00, 0x00, 0x00, 0xF1, 0x87, 0x1E, 0x93, 0x3C, 0x90, 0x0F, 0xf2];

    let result = bt_crypto_sign_att(&ATT_SIGN_KEY_5, &msg, 1)
        .expect("bt_crypto_sign_att should succeed for 5-byte payload with cnt=1");
    assert_eq!(result, expected, "sign_att_5 result mismatch");
}

// ============================================================================
// Test: GATT Database Hash
// ============================================================================

/// Port of `/crypto/gatt_hash` from unit/test-crypto.c (lines 198–260).
///
/// Tests the GATT database hash function with a 7-element iovec representing
/// a sample GATT attribute database.  Six buffers are 16 bytes each; the
/// seventh (M6) is 15 bytes.  The expected hash is computed with AES-CMAC
/// using a zero key.
#[test]
fn test_gatt_hash() {
    // M0 — 16 bytes
    let m0: [u8; 16] = [
        0x01, 0x00, 0x00, 0x28, 0x00, 0x18, 0x02, 0x00, 0x03, 0x28, 0x0A, 0x03, 0x00, 0x00, 0x2A,
        0x04,
    ];
    // M1 — 16 bytes
    let m1: [u8; 16] = [
        0x00, 0x03, 0x28, 0x02, 0x05, 0x00, 0x01, 0x2A, 0x06, 0x00, 0x00, 0x28, 0x01, 0x18, 0x07,
        0x00,
    ];
    // M2 — 16 bytes
    let m2: [u8; 16] = [
        0x03, 0x28, 0x20, 0x08, 0x00, 0x05, 0x2A, 0x09, 0x00, 0x02, 0x29, 0x0A, 0x00, 0x03, 0x28,
        0x0A,
    ];
    // M3 — 16 bytes
    let m3: [u8; 16] = [
        0x0B, 0x00, 0x29, 0x2B, 0x0C, 0x00, 0x03, 0x28, 0x02, 0x0D, 0x00, 0x2A, 0x2B, 0x0E, 0x00,
        0x00,
    ];
    // M4 — 16 bytes
    let m4: [u8; 16] = [
        0x28, 0x08, 0x18, 0x0F, 0x00, 0x02, 0x28, 0x14, 0x00, 0x16, 0x00, 0x0F, 0x18, 0x10, 0x00,
        0x03,
    ];
    // M5 — 16 bytes
    let m5: [u8; 16] = [
        0x28, 0xA2, 0x11, 0x00, 0x18, 0x2A, 0x12, 0x00, 0x02, 0x29, 0x13, 0x00, 0x00, 0x29, 0x00,
        0x00,
    ];
    // M6 — 15 bytes (last buffer is one byte shorter)
    let m6: [u8; 15] =
        [0x14, 0x00, 0x01, 0x28, 0x0F, 0x18, 0x15, 0x00, 0x03, 0x28, 0x02, 0x16, 0x00, 0x19, 0x2A];

    let iov: &[&[u8]] = &[&m0, &m1, &m2, &m3, &m4, &m5, &m6];

    let expected: [u8; 16] = [
        0xF1, 0xCA, 0x2D, 0x48, 0xEC, 0xF5, 0x8B, 0xAC, 0x8A, 0x88, 0x30, 0xBB, 0xB9, 0xFB, 0xA9,
        0x90,
    ];

    let result = bt_crypto_gatt_hash(iov).expect("bt_crypto_gatt_hash should succeed");
    assert_eq!(result, expected, "gatt_hash result mismatch");
}

// ============================================================================
// Test: ATT Signature Verification (3 test cases)
// ============================================================================

/// Port of `/crypto/verify_sign_pass` from unit/test-crypto.c (lines 269–279).
///
/// Valid PDU consisting of the 5-byte message (msg_5) concatenated with its
/// 12-byte signature (t_msg_5).  Verification should return `Ok(true)`.
#[test]
fn test_verify_sign_success() {
    let pdu: [u8; 17] = [
        0xd2, 0x12, 0x00, 0x13, 0x37, 0x01, 0x00, 0x00, 0x00, 0xF1, 0x87, 0x1E, 0x93, 0x3C, 0x90,
        0x0F, 0xf2,
    ];

    let result = bt_crypto_verify_att_sign(&ATT_SIGN_KEY_5, &pdu)
        .expect("verify_att_sign should succeed for valid PDU");
    assert!(result, "verify_sign_pass: expected signature to match");
}

/// Port of `/crypto/verify_sign_bad_sign` from unit/test-crypto.c (lines 281–291).
///
/// Tampered PDU: the last byte of the signature is changed from `0xf2` to
/// `0xf1`.  Verification should return `Ok(false)`.
#[test]
fn test_verify_sign_tampered() {
    let pdu: [u8; 17] = [
        0xd2, 0x12, 0x00, 0x13, 0x37, 0x01, 0x00, 0x00, 0x00, 0xF1, 0x87, 0x1E, 0x93, 0x3C, 0x90,
        0x0F, 0xf1,
    ];

    let result = bt_crypto_verify_att_sign(&ATT_SIGN_KEY_5, &pdu)
        .expect("verify_att_sign should succeed for tampered PDU (returns Ok(false))");
    assert!(!result, "verify_sign_bad_sign: expected signature NOT to match");
}

/// Port of `/crypto/verify_sign_too_short` from unit/test-crypto.c (lines 293–302).
///
/// PDU consisting of only 5 bytes — shorter than the minimum `ATT_SIGN_LEN`
/// (12 bytes).  The C version returns `false` for undersized PDUs.  The Rust
/// implementation returns `Err(CryptoError::InvalidLength)` since no valid
/// 12-byte signature can be present.
#[test]
fn test_verify_sign_undersized() {
    let pdu: [u8; 5] = [0xd2, 0x12, 0x00, 0x13, 0x37];

    let result = bt_crypto_verify_att_sign(&ATT_SIGN_KEY_5, &pdu);
    assert!(
        matches!(result, Err(CryptoError::InvalidLength)),
        "verify_sign_too_short: expected Err(InvalidLength), got {result:?}"
    );
}

// ============================================================================
// Test: SIRK Encryption Function (SEF)
// ============================================================================

/// Port of `/crypto/sef` from unit/test-crypto.c (lines 314–350).
///
/// Tests the SIRK Encryption Function:
///   `sef(K, SIRK) = k1(K, s1("SIRKenc"), "csis") ⊕ SIRK`
/// with a known test vector.
#[test]
fn test_sef() {
    let sirk: [u8; 16] = [
        0xcd, 0xcc, 0x72, 0xdd, 0x86, 0x8c, 0xcd, 0xce, 0x22, 0xfd, 0xa1, 0x21, 0x09, 0x7d, 0x7d,
        0x45,
    ];
    let k: [u8; 16] = [
        0xd9, 0xce, 0xe5, 0x3c, 0x22, 0xc6, 0x1e, 0x06, 0x6f, 0x69, 0x48, 0xd4, 0x9b, 0x1b, 0x6e,
        0x67,
    ];
    let expected: [u8; 16] = [
        0x46, 0xd3, 0x5f, 0xf2, 0xd5, 0x62, 0x25, 0x7e, 0xa0, 0x24, 0x35, 0xe1, 0x35, 0x38, 0x0a,
        0x17,
    ];

    let result = bt_crypto_sef(&k, &sirk).expect("bt_crypto_sef should succeed");
    assert_eq!(result, expected, "sef result mismatch");
}

// ============================================================================
// Test: SIRK Hash Function (SIH)
// ============================================================================

/// Port of `/crypto/sih` from unit/test-crypto.c (lines 352–384).
///
/// Tests the SIRK Hash Function (identical to the address resolution
/// function `ah`):
///   `sih(k, r) = e(k, padding ∥ r) mod 2²⁴`
/// with a known test vector.
#[test]
fn test_sih() {
    let k: [u8; 16] = [
        0xcd, 0xcc, 0x72, 0xdd, 0x86, 0x8c, 0xcd, 0xce, 0x22, 0xfd, 0xa1, 0x21, 0x09, 0x7d, 0x7d,
        0x45,
    ];
    let r: [u8; 3] = [0x63, 0xf5, 0x69];
    let expected: [u8; 3] = [0xda, 0x48, 0x19];

    let result = bt_crypto_sih(&k, &r).expect("bt_crypto_sih should succeed");
    assert_eq!(result, expected, "sih result mismatch");
}
