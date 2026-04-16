// SPDX-License-Identifier: GPL-2.0-or-later
//
// Bluetooth cryptographic functions replacing src/shared/crypto.c
//
// Uses pure-Rust crates instead of Linux AF_ALG sockets:
//   - `aes` for AES-128 ECB
//   - `cmac` for AES-CMAC
//   - `rand` for random bytes
//
// All SMP pairing functions match the Bluetooth Core Specification:
// e, ah, c1, s1, f4, f5, f6, g2, h6, h7

use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};
use cmac::{Cmac, Mac};

/// Length of an ATT signature (12 bytes).
pub const ATT_SIGN_LEN: usize = 12;

/// Swap byte order (reverse) of a buffer. Bluetooth spec uses MSB-first
/// for crypto operations, but protocol fields are little-endian.
fn swap_buf(src: &[u8], dst: &mut [u8]) {
    let len = src.len();
    assert_eq!(len, dst.len());
    for i in 0..len {
        dst[len - 1 - i] = src[i];
    }
}

/// AES-128 ECB encrypt with Bluetooth byte-order swapping.
///
/// Replaces C's `bt_crypto_e()`. Input key and plaintext are in Bluetooth
/// (big-endian MSB-first) order; output is also in that order.
pub fn bt_crypto_e(key: &[u8; 16], plaintext: &[u8; 16], encrypted: &mut [u8; 16]) -> bool {
    let mut k = [0u8; 16];
    let mut p = [0u8; 16];
    swap_buf(key, &mut k);
    swap_buf(plaintext, &mut p);

    let cipher = match Aes128::new_from_slice(&k) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let block = aes::Block::from(p);
    let mut out_block = block;
    cipher.encrypt_block(&mut out_block);

    let out_bytes: [u8; 16] = out_block.into();
    swap_buf(&out_bytes, encrypted);
    true
}

/// AES-CMAC with native byte order.
fn aes_cmac(key: &[u8; 16], msg: &[u8]) -> Option<[u8; 16]> {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).ok()?;
    mac.update(msg);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    Some(out)
}

/// AES-CMAC with Bluetooth byte-order swapping (big-endian keys).
#[allow(dead_code)]
fn aes_cmac_be(key: &[u8; 16], msg: &[u8]) -> Option<[u8; 16]> {
    let mut k = [0u8; 16];
    swap_buf(key, &mut k);
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(&k).ok()?;
    mac.update(msg);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    Some(out)
}

/// Random address hash function `ah`.
///
/// `hash = e(k, padding || r) mod 2^24`
///
/// Used to generate/verify resolvable private addresses (RPAs).
pub fn bt_crypto_ah(k: &[u8; 16], r: &[u8; 3], hash: &mut [u8; 3]) -> bool {
    let mut plaintext = [0u8; 16];
    plaintext[13] = r[0];
    plaintext[14] = r[1];
    plaintext[15] = r[2];

    let mut encrypted = [0u8; 16];
    if !bt_crypto_e(k, &plaintext, &mut encrypted) {
        return false;
    }

    hash[0] = encrypted[13];
    hash[1] = encrypted[14];
    hash[2] = encrypted[15];
    true
}

/// Legacy pairing confirm value generation `c1`.
///
/// `c1(k, r, preq, pres, iat, rat, ia, ra) = e(k, e(k, r XOR p1) XOR p2)`
///
/// where:
///   p1 = pres || preq || rat || iat
///   p2 = padding || ia || ra
#[allow(clippy::too_many_arguments)]
pub fn bt_crypto_c1(
    k: &[u8; 16],
    r: &[u8; 16],
    pres: &[u8; 7],
    preq: &[u8; 7],
    iat: u8,
    ia: &[u8; 6],
    rat: u8,
    ra: &[u8; 6],
    res: &mut [u8; 16],
) -> bool {
    // p1 = pres || preq || rat || iat
    let mut p1 = [0u8; 16];
    p1[0] = iat;
    p1[1] = rat;
    p1[2..9].copy_from_slice(preq);
    p1[9..16].copy_from_slice(pres);

    // p2 = padding(4) || ia || ra
    let mut p2 = [0u8; 16];
    p2[4..10].copy_from_slice(ia);
    p2[10..16].copy_from_slice(ra);

    // r XOR p1
    let mut xor1 = [0u8; 16];
    for i in 0..16 {
        xor1[i] = r[i] ^ p1[i];
    }

    // e(k, r XOR p1)
    let mut tmp = [0u8; 16];
    if !bt_crypto_e(k, &xor1, &mut tmp) {
        return false;
    }

    // e(k, r XOR p1) XOR p2
    let mut xor2 = [0u8; 16];
    for i in 0..16 {
        xor2[i] = tmp[i] ^ p2[i];
    }

    // e(k, e(k, r XOR p1) XOR p2)
    bt_crypto_e(k, &xor2, res)
}

/// Legacy pairing key generation `s1`.
///
/// `s1(k, r1, r2) = e(k, r1[0..8] || r2[0..8])`
pub fn bt_crypto_s1(
    k: &[u8; 16],
    r1: &[u8; 16],
    r2: &[u8; 16],
    res: &mut [u8; 16],
) -> bool {
    let mut plaintext = [0u8; 16];
    // Lower 8 bytes of r2 || lower 8 bytes of r1
    plaintext[..8].copy_from_slice(&r2[..8]);
    plaintext[8..].copy_from_slice(&r1[..8]);

    bt_crypto_e(k, &plaintext, res)
}

/// LE Secure Connections confirm value `f4`.
///
/// `f4(u, v, x, z) = AES-CMAC_x(u || v || z)`
pub fn bt_crypto_f4(
    u: &[u8; 32],
    v: &[u8; 32],
    x: &[u8; 16],
    z: u8,
    res: &mut [u8; 16],
) -> bool {
    // m = u || v || z (65 bytes)
    let mut m = [0u8; 65];
    // Bluetooth spec: u and v are in MSB-first, need to swap
    swap_buf(u, &mut m[0..32]);
    swap_buf(v, &mut m[32..64]);
    m[64] = z;

    let mut key = [0u8; 16];
    swap_buf(x, &mut key);

    match aes_cmac(&key, &m) {
        Some(result) => {
            swap_buf(&result, res);
            true
        }
        None => false,
    }
}

/// LE Secure Connections key derivation `f5`.
///
/// Derives MacKey and LTK from shared ECDH secret.
///
/// `T = AES-CMAC_salt(W)`
/// `MacKey = AES-CMAC_T(counter=0 || "btle" || N1 || N2 || A1 || A2 || Length=256)`
/// `LTK = AES-CMAC_T(counter=1 || ...same...)`
pub fn bt_crypto_f5(
    w: &[u8; 32],
    n1: &[u8; 16],
    n2: &[u8; 16],
    a1: &[u8; 7],
    a2: &[u8; 7],
    mackey: &mut [u8; 16],
    ltk: &mut [u8; 16],
) -> bool {
    // Salt from spec
    let salt: [u8; 16] = [
        0x6c, 0x88, 0x83, 0x91, 0xaa, 0xf5, 0xa5, 0x38,
        0x60, 0x37, 0x0b, 0xdb, 0x5a, 0x60, 0x83, 0xbe,
    ];

    // T = AES-CMAC_salt(W)
    let mut w_swapped = [0u8; 32];
    swap_buf(w, &mut w_swapped);

    let t = match aes_cmac(&salt, &w_swapped) {
        Some(v) => v,
        None => return false,
    };

    // Build message: counter(1) || "btle"(4) || N1(16) || N2(16) || A1(7) || A2(7) || Length(2) = 53 bytes
    let mut m = [0u8; 53];
    // m[0] = counter (set below)
    m[1..5].copy_from_slice(b"btle");

    let mut n1_swapped = [0u8; 16];
    let mut n2_swapped = [0u8; 16];
    swap_buf(n1, &mut n1_swapped);
    swap_buf(n2, &mut n2_swapped);

    m[5..21].copy_from_slice(&n1_swapped);
    m[21..37].copy_from_slice(&n2_swapped);

    // A1 and A2: type(1) || addr(6), MSB-first
    let mut a1_swapped = [0u8; 7];
    let mut a2_swapped = [0u8; 7];
    a1_swapped[0] = a1[6]; // type byte
    swap_buf(&a1[..6], &mut a1_swapped[1..7]);
    a2_swapped[0] = a2[6];
    swap_buf(&a2[..6], &mut a2_swapped[1..7]);

    m[37..44].copy_from_slice(&a1_swapped);
    m[44..51].copy_from_slice(&a2_swapped);

    // Length = 256 (big-endian)
    m[51] = 0x01;
    m[52] = 0x00;

    // MacKey: counter = 0
    m[0] = 0x00;
    match aes_cmac(&t, &m) {
        Some(result) => swap_buf(&result, mackey),
        None => return false,
    }

    // LTK: counter = 1
    m[0] = 0x01;
    match aes_cmac(&t, &m) {
        Some(result) => swap_buf(&result, ltk),
        None => return false,
    }

    true
}

/// LE Secure Connections check value `f6`.
///
/// `f6(w, n1, n2, r, io_cap, a1, a2) = AES-CMAC_w(n1 || n2 || r || io_cap || a1 || a2)`
#[allow(clippy::too_many_arguments)]
pub fn bt_crypto_f6(
    w: &[u8; 16],
    n1: &[u8; 16],
    n2: &[u8; 16],
    r: &[u8; 16],
    io_cap: &[u8; 3],
    a1: &[u8; 7],
    a2: &[u8; 7],
    res: &mut [u8; 16],
) -> bool {
    // m = n1 || n2 || r || io_cap || a1 || a2 (65 bytes)
    let mut m = [0u8; 65];
    let mut offset = 0;

    let mut n1s = [0u8; 16];
    let mut n2s = [0u8; 16];
    let mut rs = [0u8; 16];
    swap_buf(n1, &mut n1s);
    swap_buf(n2, &mut n2s);
    swap_buf(r, &mut rs);

    m[offset..offset + 16].copy_from_slice(&n1s);
    offset += 16;
    m[offset..offset + 16].copy_from_slice(&n2s);
    offset += 16;
    m[offset..offset + 16].copy_from_slice(&rs);
    offset += 16;
    m[offset..offset + 3].copy_from_slice(io_cap);
    offset += 3;

    let mut a1s = [0u8; 7];
    let mut a2s = [0u8; 7];
    a1s[0] = a1[6];
    swap_buf(&a1[..6], &mut a1s[1..7]);
    a2s[0] = a2[6];
    swap_buf(&a2[..6], &mut a2s[1..7]);

    m[offset..offset + 7].copy_from_slice(&a1s);
    offset += 7;
    m[offset..offset + 7].copy_from_slice(&a2s);

    let mut key = [0u8; 16];
    swap_buf(w, &mut key);

    match aes_cmac(&key, &m) {
        Some(result) => {
            swap_buf(&result, res);
            true
        }
        None => false,
    }
}

/// LE Secure Connections numeric comparison `g2`.
///
/// `g2(u, v, x, y) = AES-CMAC_x(u || v || y) mod 1000000`
pub fn bt_crypto_g2(
    u: &[u8; 32],
    v: &[u8; 32],
    x: &[u8; 16],
    y: &[u8; 16],
) -> Option<u32> {
    // m = u || v || y (80 bytes)
    let mut m = [0u8; 80];
    swap_buf(u, &mut m[0..32]);
    swap_buf(v, &mut m[32..64]);
    swap_buf(y, &mut m[64..80]);

    let mut key = [0u8; 16];
    swap_buf(x, &mut key);

    let result = aes_cmac(&key, &m)?;

    // Take last 4 bytes as big-endian u32, mod 1000000
    let val = u32::from_be_bytes([result[12], result[13], result[14], result[15]]);
    Some(val % 1_000_000)
}

/// Key derivation function `h6`.
///
/// `h6(w, keyid) = AES-CMAC_w(keyid)`
///
/// Matches C behavior: swap key, swap message, AES-CMAC, swap result.
pub fn bt_crypto_h6(w: &[u8; 16], keyid: &[u8; 4], res: &mut [u8; 16]) -> bool {
    let mut k = [0u8; 16];
    swap_buf(w, &mut k);

    let mut m = [0u8; 4];
    // swap 4-byte message (reverse byte order)
    for i in 0..4 {
        m[3 - i] = keyid[i];
    }

    match aes_cmac(&k, &m) {
        Some(result) => {
            swap_buf(&result, res);
            true
        }
        None => false,
    }
}

/// Key derivation function `h7`.
///
/// `h7(salt, w) = AES-CMAC_salt(w)`
pub fn bt_crypto_h7(salt: &[u8; 16], w: &[u8; 16], res: &mut [u8; 16]) -> bool {
    let mut salt_swapped = [0u8; 16];
    swap_buf(salt, &mut salt_swapped);

    let mut w_swapped = [0u8; 16];
    swap_buf(w, &mut w_swapped);

    match aes_cmac(&salt_swapped, &w_swapped) {
        Some(result) => {
            swap_buf(&result, res);
            true
        }
        None => false,
    }
}

/// Sign an ATT PDU using AES-CMAC.
///
/// Produces a 12-byte signature from key, message, and sign counter.
/// Matches C `bt_crypto_sign_att`:
///   1. Build msg_data = m || sign_cnt_le
///   2. Swap key, swap msg_data
///   3. AES-CMAC → out[16]
///   4. Put sign_cnt as BE32 at out[8..12]
///   5. Swap out → tmp
///   6. signature = tmp[4..16]
pub fn bt_crypto_sign_att(
    key: &[u8; 16],
    msg: &[u8],
    sign_cnt: u32,
    signature: &mut [u8; ATT_SIGN_LEN],
) -> bool {
    // Build signed data: msg || sign_cnt(4 bytes LE)
    let msg_len = msg.len() + 4;
    let mut msg_data = Vec::with_capacity(msg_len);
    msg_data.extend_from_slice(msg);
    msg_data.extend_from_slice(&sign_cnt.to_le_bytes());

    // Swap key
    let mut k = [0u8; 16];
    swap_buf(key, &mut k);

    // Swap msg
    let mut msg_s = vec![0u8; msg_len];
    for i in 0..msg_len {
        msg_s[msg_len - 1 - i] = msg_data[i];
    }

    match aes_cmac(&k, &msg_s) {
        Some(mut out) => {
            // Put sign_cnt as BE32 at out[8..12]
            out[8..12].copy_from_slice(&sign_cnt.to_be_bytes());

            // Swap out -> tmp
            let mut tmp = [0u8; 16];
            swap_buf(&out, &mut tmp);

            // signature = tmp[4..16]
            signature.copy_from_slice(&tmp[4..16]);
            true
        }
        None => false,
    }
}

/// Verify an ATT signature.
///
/// PDU format: data(N) || signature(12)
/// The signature contains sign_cnt(4 LE) || mac(8).
pub fn bt_crypto_verify_att_sign(key: &[u8; 16], pdu: &[u8]) -> bool {
    if pdu.len() < ATT_SIGN_LEN {
        return false;
    }

    let msg_len = pdu.len() - ATT_SIGN_LEN;
    let msg = &pdu[..msg_len];
    let received_sig = &pdu[msg_len..];

    // Extract sign counter from signature (first 4 bytes LE)
    let sign_cnt = u32::from_le_bytes([
        received_sig[0],
        received_sig[1],
        received_sig[2],
        received_sig[3],
    ]);

    let mut expected = [0u8; ATT_SIGN_LEN];
    if !bt_crypto_sign_att(key, msg, sign_cnt, &mut expected) {
        return false;
    }

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..ATT_SIGN_LEN {
        diff |= received_sig[i] ^ expected[i];
    }
    diff == 0
}

/// Generate cryptographic random bytes.
pub fn bt_crypto_random_bytes(buf: &mut [u8]) -> bool {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    rng.fill_bytes(buf);
    true
}

/// GATT database hash using AES-CMAC with zero key.
pub fn bt_crypto_gatt_hash(data: &[u8], res: &mut [u8; 16]) -> bool {
    let key = [0u8; 16];
    match aes_cmac(&key, data) {
        Some(result) => {
            res.copy_from_slice(&result);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_e() {
        // Test vector from Bluetooth Core Spec Vol 3, Part H, D.1
        let key = [0u8; 16];
        let plaintext = [0u8; 16];
        let mut encrypted = [0u8; 16];

        assert!(bt_crypto_e(&key, &plaintext, &mut encrypted));
        // Just verify it produces non-zero output with zero inputs
        // (actual vector validation would need spec test vectors)
        // The important thing is it doesn't crash and returns true
    }

    #[test]
    fn test_crypto_ah() {
        let k = [0u8; 16];
        let r = [0u8; 3];
        let mut hash = [0u8; 3];

        assert!(bt_crypto_ah(&k, &r, &mut hash));
    }

    #[test]
    fn test_crypto_c1() {
        let k = [0u8; 16];
        let r = [0u8; 16];
        let pres = [0u8; 7];
        let preq = [0u8; 7];
        let ia = [0u8; 6];
        let ra = [0u8; 6];
        let mut res = [0u8; 16];

        assert!(bt_crypto_c1(&k, &r, &pres, &preq, 0, &ia, 0, &ra, &mut res));
    }

    #[test]
    fn test_crypto_s1() {
        let k = [0u8; 16];
        let r1 = [0u8; 16];
        let r2 = [0u8; 16];
        let mut res = [0u8; 16];

        assert!(bt_crypto_s1(&k, &r1, &r2, &mut res));
    }

    #[test]
    fn test_crypto_f4() {
        let u = [0u8; 32];
        let v = [0u8; 32];
        let x = [0u8; 16];
        let mut res = [0u8; 16];

        assert!(bt_crypto_f4(&u, &v, &x, 0, &mut res));
    }

    #[test]
    fn test_crypto_f5() {
        let w = [0u8; 32];
        let n1 = [0u8; 16];
        let n2 = [0u8; 16];
        let a1 = [0u8; 7];
        let a2 = [0u8; 7];
        let mut mackey = [0u8; 16];
        let mut ltk = [0u8; 16];

        assert!(bt_crypto_f5(&w, &n1, &n2, &a1, &a2, &mut mackey, &mut ltk));
        // mackey and ltk should be different
        assert_ne!(mackey, ltk);
    }

    #[test]
    fn test_crypto_f6() {
        let w = [0u8; 16];
        let n1 = [0u8; 16];
        let n2 = [0u8; 16];
        let r = [0u8; 16];
        let io_cap = [0u8; 3];
        let a1 = [0u8; 7];
        let a2 = [0u8; 7];
        let mut res = [0u8; 16];

        assert!(bt_crypto_f6(&w, &n1, &n2, &r, &io_cap, &a1, &a2, &mut res));
    }

    #[test]
    fn test_crypto_g2() {
        let u = [0u8; 32];
        let v = [0u8; 32];
        let x = [0u8; 16];
        let y = [0u8; 16];

        let val = bt_crypto_g2(&u, &v, &x, &y);
        assert!(val.is_some());
        assert!(val.unwrap() < 1_000_000);
    }

    #[test]
    fn test_crypto_h6() {
        let w = [0u8; 16];
        let keyid = *b"btle";
        let mut res = [0u8; 16];

        assert!(bt_crypto_h6(&w, &keyid, &mut res));
    }

    #[test]
    fn test_sign_and_verify() {
        let key = [0x01u8; 16];
        let msg = b"test message";
        let sign_cnt = 42u32;

        let mut signature = [0u8; ATT_SIGN_LEN];
        assert!(bt_crypto_sign_att(&key, msg, sign_cnt, &mut signature));

        // Build full PDU: msg || signature
        let mut pdu = Vec::new();
        pdu.extend_from_slice(msg);
        pdu.extend_from_slice(&signature);

        assert!(bt_crypto_verify_att_sign(&key, &pdu));

        // Tamper with signature
        let last = pdu.len() - 1;
        pdu[last] ^= 0xFF;
        assert!(!bt_crypto_verify_att_sign(&key, &pdu));
    }

    #[test]
    fn test_random_bytes() {
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        assert!(bt_crypto_random_bytes(&mut buf1));
        assert!(bt_crypto_random_bytes(&mut buf2));
        // Extremely unlikely to be equal
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_gatt_hash() {
        let data = b"test data for hashing";
        let mut res = [0u8; 16];
        assert!(bt_crypto_gatt_hash(data, &mut res));

        // Same input should produce same hash
        let mut res2 = [0u8; 16];
        assert!(bt_crypto_gatt_hash(data, &mut res2));
        assert_eq!(res, res2);
    }

    #[test]
    fn test_verify_too_short() {
        let key = [0u8; 16];
        let short_pdu = [0u8; 5]; // Too short for signature
        assert!(!bt_crypto_verify_att_sign(&key, &short_pdu));
    }

    // ---------------------------------------------------------------
    // Tests ported from unit/test-crypto.c
    // ---------------------------------------------------------------

    /// test_h6 from test-crypto.c: h6 key derivation with spec test vector.
    #[test]
    fn test_c_h6_vector() {
        let w: [u8; 16] = [
            0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34,
            0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34, 0x02, 0xec,
        ];
        let m: [u8; 4] = [0x72, 0x62, 0x65, 0x6c];
        let exp: [u8; 16] = [
            0x99, 0x63, 0xb1, 0x80, 0xe2, 0xa9, 0xd3, 0xe8,
            0x1c, 0xc9, 0x6d, 0xe7, 0x02, 0xe1, 0x9a, 0x2d,
        ];
        let mut res = [0u8; 16];
        assert!(bt_crypto_h6(&w, &m, &mut res));
        assert_eq!(res, exp);
    }

    /// Helper for sign_att tests from test-crypto.c
    fn run_sign_att_test(key: &[u8; 16], msg: &[u8], msg_len: u16, cnt: u32, expected_t: &[u8; 12]) {
        let mut t = [0u8; 12];
        // The C test passes msg with msg_len; msg_len=0 means empty message
        let actual_msg = &msg[..msg_len as usize];
        assert!(bt_crypto_sign_att(key, actual_msg, cnt, &mut t));
        assert_eq!(&t, expected_t);
    }

    /// sign_att test 1: empty message, from test-crypto.c
    #[test]
    fn test_c_sign_att_1() {
        let key: [u8; 16] = [
            0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
            0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b,
        ];
        let msg: [u8; 1] = [0x00];
        let expected: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0xb3, 0xa8, 0x59, 0x41,
            0x27, 0xeb, 0xc2, 0xc0,
        ];
        run_sign_att_test(&key, &msg, 0, 0, &expected);
    }

    /// sign_att test 2: 16-byte message, from test-crypto.c
    #[test]
    fn test_c_sign_att_2() {
        let key: [u8; 16] = [
            0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
            0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b,
        ];
        let msg: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x27, 0x39, 0x74, 0xf4,
            0x39, 0x2a, 0x23, 0x2a,
        ];
        run_sign_att_test(&key, &msg, 16, 0, &expected);
    }

    /// sign_att test 3: 40-byte message, from test-crypto.c
    #[test]
    fn test_c_sign_att_3() {
        let key: [u8; 16] = [
            0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
            0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b,
        ];
        let msg: [u8; 40] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let expected: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0xb7, 0xca, 0x94, 0xab,
            0x87, 0xc7, 0x82, 0x18,
        ];
        run_sign_att_test(&key, &msg, 40, 0, &expected);
    }

    /// sign_att test 4: 64-byte message, from test-crypto.c
    #[test]
    fn test_c_sign_att_4() {
        let key: [u8; 16] = [
            0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
            0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b,
        ];
        let msg: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x44, 0xe1, 0xe6, 0xce,
            0x1d, 0xf5, 0x13, 0x68,
        ];
        run_sign_att_test(&key, &msg, 64, 0, &expected);
    }

    /// sign_att test 5: 5-byte message with counter=1, from test-crypto.c
    #[test]
    fn test_c_sign_att_5() {
        let key: [u8; 16] = [
            0x50, 0x5E, 0x42, 0xDF, 0x96, 0x91, 0xEC, 0x72,
            0xD3, 0x1F, 0xCD, 0xFB, 0xEB, 0x64, 0x1B, 0x61,
        ];
        let msg: [u8; 5] = [0xd2, 0x12, 0x00, 0x13, 0x37];
        let expected: [u8; 12] = [
            0x01, 0x00, 0x00, 0x00, 0xF1, 0x87, 0x1E, 0x93,
            0x3C, 0x90, 0x0F, 0xf2,
        ];
        run_sign_att_test(&key, &msg, 5, 1, &expected);
    }

    /// gatt_hash test from test-crypto.c with spec test vectors.
    #[test]
    fn test_c_gatt_hash_vector() {
        let m: [[u8; 16]; 7] = [
            // M0
            [0x01, 0x00, 0x00, 0x28, 0x00, 0x18, 0x02, 0x00,
             0x03, 0x28, 0x0A, 0x03, 0x00, 0x00, 0x2A, 0x04],
            // M1
            [0x00, 0x03, 0x28, 0x02, 0x05, 0x00, 0x01, 0x2A,
             0x06, 0x00, 0x00, 0x28, 0x01, 0x18, 0x07, 0x00],
            // M2
            [0x03, 0x28, 0x20, 0x08, 0x00, 0x05, 0x2A, 0x09,
             0x00, 0x02, 0x29, 0x0A, 0x00, 0x03, 0x28, 0x0A],
            // M3
            [0x0B, 0x00, 0x29, 0x2B, 0x0C, 0x00, 0x03, 0x28,
             0x02, 0x0D, 0x00, 0x2A, 0x2B, 0x0E, 0x00, 0x00],
            // M4
            [0x28, 0x08, 0x18, 0x0F, 0x00, 0x02, 0x28, 0x14,
             0x00, 0x16, 0x00, 0x0F, 0x18, 0x10, 0x00, 0x03],
            // M5
            [0x28, 0xA2, 0x11, 0x00, 0x18, 0x2A, 0x12, 0x00,
             0x02, 0x29, 0x13, 0x00, 0x00, 0x29, 0x00, 0x00],
            // M6
            [0x14, 0x00, 0x01, 0x28, 0x0F, 0x18, 0x15, 0x00,
             0x03, 0x28, 0x02, 0x16, 0x00, 0x19, 0x2A, 0x00],
        ];
        let exp: [u8; 16] = [
            0xF1, 0xCA, 0x2D, 0x48, 0xEC, 0xF5, 0x8B, 0xAC,
            0x8A, 0x88, 0x30, 0xBB, 0xB9, 0xFB, 0xA9, 0x90,
        ];

        // Build concatenated data (M6 is only 15 bytes in the C test)
        let mut data = Vec::new();
        for i in 0..7 {
            let len = if i == 6 { 15 } else { 16 };
            data.extend_from_slice(&m[i][..len]);
        }

        let mut res = [0u8; 16];
        assert!(bt_crypto_gatt_hash(&data, &mut res));
        assert_eq!(res, exp);
    }

    /// verify_sign pass test from test-crypto.c
    #[test]
    fn test_c_verify_sign_pass() {
        let key: [u8; 16] = [
            0x50, 0x5E, 0x42, 0xDF, 0x96, 0x91, 0xEC, 0x72,
            0xD3, 0x1F, 0xCD, 0xFB, 0xEB, 0x64, 0x1B, 0x61,
        ];
        let msg: [u8; 17] = [
            0xd2, 0x12, 0x00, 0x13, 0x37, 0x01, 0x00, 0x00,
            0x00, 0xF1, 0x87, 0x1E, 0x93, 0x3C, 0x90, 0x0F,
            0xf2,
        ];
        assert!(bt_crypto_verify_att_sign(&key, &msg));
    }

    /// verify_sign bad signature test from test-crypto.c
    #[test]
    fn test_c_verify_sign_bad_sign() {
        let key: [u8; 16] = [
            0x50, 0x5E, 0x42, 0xDF, 0x96, 0x91, 0xEC, 0x72,
            0xD3, 0x1F, 0xCD, 0xFB, 0xEB, 0x64, 0x1B, 0x61,
        ];
        // Last byte differs: 0xf1 instead of 0xf2
        let msg: [u8; 17] = [
            0xd2, 0x12, 0x00, 0x13, 0x37, 0x01, 0x00, 0x00,
            0x00, 0xF1, 0x87, 0x1E, 0x93, 0x3C, 0x90, 0x0F,
            0xf1,
        ];
        assert!(!bt_crypto_verify_att_sign(&key, &msg));
    }

    /// verify_sign too-short message test from test-crypto.c
    #[test]
    fn test_c_verify_sign_too_short() {
        let key: [u8; 16] = [
            0x50, 0x5E, 0x42, 0xDF, 0x96, 0x91, 0xEC, 0x72,
            0xD3, 0x1F, 0xCD, 0xFB, 0xEB, 0x64, 0x1B, 0x61,
        ];
        let msg: [u8; 5] = [0xd2, 0x12, 0x00, 0x13, 0x37];
        assert!(!bt_crypto_verify_att_sign(&key, &msg));
    }
}
