// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Unit tests for Bluetooth library utility functions.
//
// Converted from `unit/test-lib.c` — tests various utility functions from
// `lib/bluetooth/` re-implemented in `bluez_shared::sys::bluetooth`.
//
// The original C test file tests:
//   - ntoh64 / hton64 byte-order conversions
//   - SDP access protocol, language attribute, profile descriptor, and
//     server version extraction (SDP functions are in the C-only libbluetooth
//     and not ported; equivalent protocol coverage lives in test_sdp.rs)
//
// This Rust test file covers all public utility functions exported by the
// `bluez_shared::sys::bluetooth` module, including:
//   - ntoh64 / hton64 (direct port from C)
//   - BdAddr/bdaddr_t address formatting (ba2str, Display)
//   - Address parsing (FromStr / str2ba equivalent)
//   - Address comparison (PartialEq / bacmp equivalent)
//   - Address format validation (bachk)
//   - Company ID to vendor name lookup (bt_compidtostr)
//   - HCI status code to errno mapping (bt_error)
//   - Well-known address constants (BDADDR_ANY, BDADDR_ALL, BDADDR_LOCAL)

use std::str::FromStr;

use bluez_shared::sys::bluetooth::{
    BDADDR_ALL, BDADDR_ANY, BDADDR_LOCAL, BdAddr, bachk, bdaddr_t, bt_compidtostr, bt_error,
    hton64, ntoh64,
};

// ===========================================================================
// ntoh64 / hton64 — Direct port from C test_ntoh64/test_hton64
// ===========================================================================

/// Direct conversion of C `test_ntoh64`:
///
/// ```c
/// static void test_ntoh64(const void *data)
/// {
///     uint64_t test = 0x123456789abcdef;
///     tester_test_passed();
/// }
/// ```
///
/// The C test simply calls `ntoh64(0x123456789abcdef)` and asserts the result
/// equals `be64toh(0x123456789abcdef)`.  In Rust, `ntoh64` is defined as
/// `u64::from_be(n)`, so we verify equivalence.
#[test]
fn test_ntoh64_basic() {
    let val: u64 = 0x0123_4567_89ab_cdef;
    // ntoh64 converts from network byte order (big-endian) to host order
    let expected = u64::from_be(val);
    assert_eq!(ntoh64(val), expected);
}

/// Direct conversion of C `test_hton64`:
///
/// ```c
/// static void test_hton64(const void *data)
/// {
///     uint64_t test = 0x123456789abcdef;
///     tester_test_passed();
/// }
/// ```
///
/// `hton64` converts from host byte order to network (big-endian).
#[test]
fn test_hton64_basic() {
    let val: u64 = 0x0123_4567_89ab_cdef;
    let expected = val.to_be();
    assert_eq!(hton64(val), expected);
}

/// Verify ntoh64 and hton64 are mutual inverses: converting to network
/// order then back to host order yields the original value.
#[test]
fn test_ntoh64_hton64_inverse() {
    let val: u64 = 0xDEAD_BEEF_CAFE_BABE;
    assert_eq!(ntoh64(hton64(val)), val);
    assert_eq!(hton64(ntoh64(val)), val);
}

/// Edge case: zero must be preserved through both conversions.
#[test]
fn test_ntoh64_zero() {
    assert_eq!(ntoh64(0), 0);
    assert_eq!(hton64(0), 0);
}

/// Edge case: u64::MAX must be preserved through both conversions.
#[test]
fn test_ntoh64_max() {
    assert_eq!(ntoh64(hton64(u64::MAX)), u64::MAX);
    assert_eq!(hton64(ntoh64(u64::MAX)), u64::MAX);
}

// ===========================================================================
// ba2str — Bluetooth Address to String Conversion
// ===========================================================================

/// Test ba2str on the all-zeros address.
///
/// Conversion rule: `bdaddr_t { b: [b0,b1,b2,b3,b4,b5] }` formats as
/// `"b5:b4:b3:b2:b1:b0"` — bytes are printed MSB-first (b[5] first).
#[test]
fn test_batostr_zeros() {
    let ba = bdaddr_t { b: [0x00; 6] };
    assert_eq!(ba.ba2str(), "00:00:00:00:00:00");
}

/// Test ba2str on the all-0xFF address.
#[test]
fn test_batostr_all_ff() {
    let ba = bdaddr_t { b: [0xFF; 6] };
    assert_eq!(ba.ba2str(), "FF:FF:FF:FF:FF:FF");
}

/// Test ba2str with a typical address, verifying byte ordering.
///
/// The bdaddr_t stores bytes in LSB-first order: b[0] is the least
/// significant octet. ba2str prints b[5]:b[4]:b[3]:b[2]:b[1]:b[0].
#[test]
fn test_batostr_sample() {
    let ba = bdaddr_t { b: [0x01, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA] };
    assert_eq!(ba.ba2str(), "AA:BB:CC:DD:EE:01");
}

/// Test that `fmt::Display` produces the same output as `ba2str`.
#[test]
fn test_batostr_display_trait() {
    let ba = bdaddr_t { b: [0x78, 0x56, 0x34, 0x12, 0x00, 0xAB] };
    let display_str = format!("{ba}");
    assert_eq!(display_str, "AB:00:12:34:56:78");
    assert_eq!(display_str, ba.ba2str());
}

/// Verify that ba2str output uses uppercase hex (matching C behavior).
#[test]
fn test_batostr_uppercase() {
    let ba = bdaddr_t { b: [0xab, 0xcd, 0xef, 0x12, 0x34, 0x56] };
    let s = ba.ba2str();
    // All hex digits must be uppercase
    assert_eq!(s, "56:34:12:EF:CD:AB");
    assert!(s.chars().all(|c| !c.is_ascii_lowercase()));
}

// ===========================================================================
// str2ba — String to Bluetooth Address Parsing (FromStr)
// ===========================================================================

/// Parse a valid uppercase address string.
#[test]
fn test_strtoba_valid_uppercase() {
    let ba = bdaddr_t::from_str("AA:BB:CC:DD:EE:FF").unwrap();
    // First pair "AA" → b[5], last pair "FF" → b[0]
    assert_eq!(ba.b, [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
}

/// Parse the all-zeros address string.
#[test]
fn test_strtoba_zeros() {
    let ba = bdaddr_t::from_str("00:00:00:00:00:00").unwrap();
    assert_eq!(ba.b, [0x00; 6]);
}

/// Parse the all-0xFF address string.
#[test]
fn test_strtoba_all_ff() {
    let ba = bdaddr_t::from_str("FF:FF:FF:FF:FF:FF").unwrap();
    assert_eq!(ba.b, [0xFF; 6]);
}

/// Parse a lowercase address string (both cases should work).
#[test]
fn test_strtoba_lowercase() {
    let ba = bdaddr_t::from_str("aa:bb:cc:dd:ee:ff").unwrap();
    assert_eq!(ba.b, [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
}

/// Parse a mixed-case address string.
#[test]
fn test_strtoba_mixed_case() {
    let ba = bdaddr_t::from_str("aA:Bb:cC:Dd:eE:fF").unwrap();
    assert_eq!(ba.b, [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
}

/// Invalid: no colons (too short after bachk).
#[test]
fn test_strtoba_invalid_no_colons() {
    assert!(bdaddr_t::from_str("AABBCCDDEEFF").is_err());
}

/// Invalid: non-hex characters.
#[test]
fn test_strtoba_invalid_hex_chars() {
    assert!(bdaddr_t::from_str("GG:HH:II:JJ:KK:LL").is_err());
}

/// Invalid: empty string.
#[test]
fn test_strtoba_invalid_empty() {
    assert!(bdaddr_t::from_str("").is_err());
}

/// Invalid: too many octets.
#[test]
fn test_strtoba_invalid_extra_octet() {
    assert!(bdaddr_t::from_str("00:11:22:33:44:55:66").is_err());
}

/// Invalid: too few octets.
#[test]
fn test_strtoba_invalid_short() {
    assert!(bdaddr_t::from_str("00:11:22:33:44").is_err());
}

// ===========================================================================
// bacmp — Bluetooth Address Comparison (PartialEq)
// ===========================================================================

/// Identical addresses must compare equal.
#[test]
fn test_ba_cmp_equal() {
    let ba1 = bdaddr_t { b: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] };
    let ba2 = bdaddr_t { b: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] };
    assert_eq!(ba1, ba2);
}

/// Reversed addresses must compare not-equal.
#[test]
fn test_ba_cmp_not_equal() {
    let ba1 = bdaddr_t { b: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] };
    let ba2 = bdaddr_t { b: [0x06, 0x05, 0x04, 0x03, 0x02, 0x01] };
    assert_ne!(ba1, ba2);
}

/// Addresses differing by a single byte must compare not-equal.
#[test]
fn test_ba_cmp_single_byte_diff() {
    let ba1 = bdaddr_t { b: [0x00; 6] };
    let mut ba2 = bdaddr_t { b: [0x00; 6] };
    ba2.b[3] = 0x01;
    assert_ne!(ba1, ba2);
}

/// Round-trip parse-then-compare: two addresses parsed from the same string
/// must be equal.
#[test]
fn test_ba_cmp_roundtrip() {
    let ba1 = bdaddr_t::from_str("AA:BB:CC:DD:EE:FF").unwrap();
    let ba2 = bdaddr_t::from_str("AA:BB:CC:DD:EE:FF").unwrap();
    assert_eq!(ba1, ba2);
}

/// Verify parsed constant addresses match the predefined constants.
#[test]
fn test_ba_cmp_with_constants() {
    let zero = bdaddr_t::from_str("00:00:00:00:00:00").unwrap();
    assert_eq!(zero, BDADDR_ANY);

    let all = bdaddr_t::from_str("FF:FF:FF:FF:FF:FF").unwrap();
    assert_eq!(all, BDADDR_ALL);

    let local = bdaddr_t::from_str("FF:FF:FF:00:00:00").unwrap();
    assert_eq!(local, BDADDR_LOCAL);
}

// ===========================================================================
// bt_compidtostr — Company ID to Vendor Name Lookup
// ===========================================================================

/// Company ID 0 is "Ericsson Technology Licensing" (first entry).
#[test]
fn test_bt_compid_ericsson() {
    assert_eq!(bt_compidtostr(0), "Ericsson Technology Licensing");
}

/// Company ID 1 is "Nokia Mobile Phones".
#[test]
fn test_bt_compid_nokia() {
    assert_eq!(bt_compidtostr(1), "Nokia Mobile Phones");
}

/// Company ID 2 is "Intel Corp.".
#[test]
fn test_bt_compid_intel() {
    assert_eq!(bt_compidtostr(2), "Intel Corp.");
}

/// Company ID 6 is "Microsoft".
#[test]
fn test_bt_compid_microsoft() {
    assert_eq!(bt_compidtostr(6), "Microsoft");
}

/// Company ID 13 is "Texas Instruments Inc.".
#[test]
fn test_bt_compid_ti() {
    assert_eq!(bt_compidtostr(13), "Texas Instruments Inc.");
}

/// Company ID 15 is "Broadcom Corporation".
#[test]
fn test_bt_compid_broadcom() {
    assert_eq!(bt_compidtostr(15), "Broadcom Corporation");
}

/// Company ID 29 is "Qualcomm".
#[test]
fn test_bt_compid_qualcomm() {
    assert_eq!(bt_compidtostr(29), "Qualcomm");
}

/// Company ID 76 is "Apple, Inc.".
#[test]
fn test_bt_compid_apple() {
    assert_eq!(bt_compidtostr(76), "Apple, Inc.");
}

/// Unknown (very large) company ID returns "not assigned".
#[test]
fn test_bt_compid_unknown_large() {
    assert_eq!(bt_compidtostr(99999), "not assigned");
}

/// Negative company ID returns "not assigned".
#[test]
fn test_bt_compid_negative() {
    assert_eq!(bt_compidtostr(-1), "not assigned");
}

// ===========================================================================
// bt_error — HCI Status Code to POSIX errno Mapping
// ===========================================================================

/// HCI Success (0x00) maps to errno 0.
#[test]
fn test_bt_error_success() {
    assert_eq!(bt_error(0x00), 0);
}

/// HCI Unknown Command (0x01) maps to EBADRQC (56).
#[test]
fn test_bt_error_unknown_command() {
    assert_eq!(bt_error(0x01), 56); // EBADRQC
}

/// HCI No Connection (0x02) maps to ENOTCONN (107).
#[test]
fn test_bt_error_no_connection() {
    assert_eq!(bt_error(0x02), 107); // ENOTCONN
}

/// HCI Hardware Failure (0x03) maps to EIO (5).
#[test]
fn test_bt_error_hardware_failure() {
    assert_eq!(bt_error(0x03), 5); // EIO
}

/// HCI Page Timeout (0x04) maps to EHOSTDOWN (112).
#[test]
fn test_bt_error_page_timeout() {
    assert_eq!(bt_error(0x04), 112); // EHOSTDOWN
}

/// HCI Authentication Failure (0x05) maps to EACCES (13).
#[test]
fn test_bt_error_auth_failure() {
    assert_eq!(bt_error(0x05), 13); // EACCES
}

/// HCI PIN or Key Missing (0x06) maps to EINVAL (22).
#[test]
fn test_bt_error_pin_missing() {
    assert_eq!(bt_error(0x06), 22); // EINVAL
}

/// HCI Memory Full (0x07) maps to ENOMEM (12).
#[test]
fn test_bt_error_memory_full() {
    assert_eq!(bt_error(0x07), 12); // ENOMEM
}

/// HCI Connection Timeout (0x08) maps to ETIMEDOUT (110).
#[test]
fn test_bt_error_conn_timeout() {
    assert_eq!(bt_error(0x08), 110); // ETIMEDOUT
}

/// HCI Max Connections (0x09) maps to EMLINK (31).
#[test]
fn test_bt_error_max_connections() {
    assert_eq!(bt_error(0x09), 31); // EMLINK
}

/// HCI Max SCO Connections (0x0a) maps to EMLINK (31).
#[test]
fn test_bt_error_max_sco_connections() {
    assert_eq!(bt_error(0x0a), 31); // EMLINK
}

/// HCI ACL Connection Exists (0x0b) maps to EALREADY (114).
#[test]
fn test_bt_error_acl_exists() {
    assert_eq!(bt_error(0x0b), 114); // EALREADY
}

/// HCI Command Disallowed (0x0c) maps to EBUSY (16).
#[test]
fn test_bt_error_command_disallowed() {
    assert_eq!(bt_error(0x0c), 16); // EBUSY
}

/// HCI Rejected Limited Resources (0x0d) maps to ECONNREFUSED (111).
#[test]
fn test_bt_error_rejected_resources() {
    assert_eq!(bt_error(0x0d), 111); // ECONNREFUSED
}

/// HCI Rejected Security (0x0e) maps to EACCES (13).
#[test]
fn test_bt_error_rejected_security() {
    assert_eq!(bt_error(0x0e), 13); // EACCES
}

/// HCI Unsupported Feature (0x11) maps to EOPNOTSUPP (95).
#[test]
fn test_bt_error_unsupported_feature() {
    assert_eq!(bt_error(0x11), 95); // EOPNOTSUPP
}

/// HCI OE User Ended Connection (0x13) maps to ECONNRESET (104).
#[test]
fn test_bt_error_user_ended() {
    assert_eq!(bt_error(0x13), 104); // ECONNRESET
}

/// HCI Connection Terminated (0x16) maps to ECONNABORTED (103).
#[test]
fn test_bt_error_conn_terminated() {
    assert_eq!(bt_error(0x16), 103); // ECONNABORTED
}

/// HCI Insufficient Security (0x2f) maps to EACCES (13).
#[test]
fn test_bt_error_insufficient_security() {
    assert_eq!(bt_error(0x2f), 13); // EACCES
}

/// Unrecognized HCI status code (0xFF) maps to ENOSYS (38).
#[test]
fn test_bt_error_unknown_code() {
    assert_eq!(bt_error(0xFF), 38); // ENOSYS
}

/// Another unrecognized code (0x80) also maps to ENOSYS.
#[test]
fn test_bt_error_unknown_code_mid() {
    assert_eq!(bt_error(0x80), 38); // ENOSYS
}

// ===========================================================================
// bachk — Bluetooth Address String Format Validation
// ===========================================================================

/// Valid uppercase address.
#[test]
fn test_bachk_valid_uppercase() {
    assert!(bachk("00:11:22:33:44:55"));
}

/// Valid all-0xFF address.
#[test]
fn test_bachk_valid_all_ff() {
    assert!(bachk("FF:FF:FF:FF:FF:FF"));
}

/// Valid lowercase address.
#[test]
fn test_bachk_valid_lowercase() {
    assert!(bachk("aa:bb:cc:dd:ee:ff"));
}

/// Valid mixed-case address.
#[test]
fn test_bachk_valid_mixed_case() {
    assert!(bachk("aA:bB:cC:dD:eE:fF"));
}

/// Valid all-zeros address.
#[test]
fn test_bachk_valid_all_zeros() {
    assert!(bachk("00:00:00:00:00:00"));
}

/// Invalid: too few octets (only 5).
#[test]
fn test_bachk_invalid_short() {
    assert!(!bachk("00:11:22:33:44"));
}

/// Invalid: no colons at all.
#[test]
fn test_bachk_invalid_no_colons() {
    assert!(!bachk("001122334455"));
}

/// Invalid: non-hex characters.
#[test]
fn test_bachk_invalid_bad_char() {
    assert!(!bachk("GG:HH:II:JJ:KK:LL"));
}

/// Invalid: empty string.
#[test]
fn test_bachk_invalid_empty() {
    assert!(!bachk(""));
}

/// Invalid: too many octets (7 pairs).
#[test]
fn test_bachk_invalid_extra() {
    assert!(!bachk("00:11:22:33:44:55:66"));
}

/// Invalid: dash separator instead of colon.
#[test]
fn test_bachk_invalid_dash_separator() {
    assert!(!bachk("00-11-22-33-44-55"));
}

/// Invalid: single character.
#[test]
fn test_bachk_invalid_single_char() {
    assert!(!bachk("A"));
}

/// Invalid: exactly 17 characters but with a non-hex digit.
#[test]
fn test_bachk_invalid_17_chars_bad_hex() {
    assert!(!bachk("0G:11:22:33:44:55"));
}

// ===========================================================================
// Well-Known Address Constants
// ===========================================================================

/// BDADDR_ANY is the all-zeros address.
#[test]
fn test_bdaddr_any_bytes() {
    assert_eq!(BDADDR_ANY.b, [0x00; 6]);
}

/// BDADDR_ANY formats as "00:00:00:00:00:00".
#[test]
fn test_bdaddr_any_str() {
    assert_eq!(BDADDR_ANY.ba2str(), "00:00:00:00:00:00");
}

/// BDADDR_ALL is the all-0xFF address.
#[test]
fn test_bdaddr_all_bytes() {
    assert_eq!(BDADDR_ALL.b, [0xFF; 6]);
}

/// BDADDR_ALL formats as "FF:FF:FF:FF:FF:FF".
#[test]
fn test_bdaddr_all_str() {
    assert_eq!(BDADDR_ALL.ba2str(), "FF:FF:FF:FF:FF:FF");
}

/// BDADDR_LOCAL is the local loopback address [0,0,0,0xFF,0xFF,0xFF].
#[test]
fn test_bdaddr_local_bytes() {
    assert_eq!(BDADDR_LOCAL.b, [0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF]);
}

/// BDADDR_LOCAL formats as "FF:FF:FF:00:00:00".
///
/// b[5]=0xFF, b[4]=0xFF, b[3]=0xFF, b[2]=0x00, b[1]=0x00, b[0]=0x00
#[test]
fn test_bdaddr_local_str() {
    assert_eq!(BDADDR_LOCAL.ba2str(), "FF:FF:FF:00:00:00");
}

/// BDADDR_ANY and BDADDR_ALL must not be equal.
#[test]
fn test_bdaddr_constants_not_equal() {
    assert_ne!(BDADDR_ANY, BDADDR_ALL);
    assert_ne!(BDADDR_ANY, BDADDR_LOCAL);
    assert_ne!(BDADDR_ALL, BDADDR_LOCAL);
}

// ===========================================================================
// BdAddr Type Alias — Verify Interchangeability
// ===========================================================================

/// BdAddr is a type alias for bdaddr_t — verify they are fully
/// interchangeable with no runtime distinction.
#[test]
fn test_bdaddr_type_alias() {
    let ba: BdAddr = bdaddr_t { b: [1, 2, 3, 4, 5, 6] };
    let _ba2: bdaddr_t = ba;
    // If this compiles, the type alias works correctly
    assert_eq!(ba.b, [1, 2, 3, 4, 5, 6]);
}

// ===========================================================================
// Round-Trip Tests
// ===========================================================================

/// Full round-trip: str → bdaddr_t → str must preserve the original string.
#[test]
fn test_roundtrip_str_ba_str() {
    let original = "AB:CD:EF:01:23:45";
    let ba = bdaddr_t::from_str(original).unwrap();
    assert_eq!(ba.ba2str(), original);
}

/// Round-trip with the all-zeros address.
#[test]
fn test_roundtrip_zeros() {
    let original = "00:00:00:00:00:00";
    let ba = bdaddr_t::from_str(original).unwrap();
    assert_eq!(ba.ba2str(), original);
}

/// Round-trip with the all-0xFF address.
#[test]
fn test_roundtrip_all_ff() {
    let original = "FF:FF:FF:FF:FF:FF";
    let ba = bdaddr_t::from_str(original).unwrap();
    assert_eq!(ba.ba2str(), original);
}

/// Round-trip with a real-world BT address (Samsung device example).
#[test]
fn test_roundtrip_realworld() {
    let original = "C0:D3:C0:FF:EE:11";
    let ba = bdaddr_t::from_str(original).unwrap();
    assert_eq!(ba.ba2str(), original);
}
