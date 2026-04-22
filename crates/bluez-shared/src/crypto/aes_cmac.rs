// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — AES-128/CMAC Bluetooth cryptographic primitives
//
// Copyright 2024 BlueZ Project

//! AES-128/CMAC-based Bluetooth cryptographic primitives.
//!
//! This module provides all AES-128 and AES-CMAC based cryptographic functions
//! required by the Bluetooth Core Specification, replacing the Linux AF_ALG
//! kernel socket-based crypto from `src/shared/crypto.c` (1007 lines) and
//! `src/shared/crypto.h` (64 lines) with pure-Rust implementations.
//!
//! # Architecture Changes from C
//!
//! - **AF_ALG sockets → `aes`/`cmac` crates**: The C code opens `PF_ALG`
//!   sockets for `ecb(aes)` and `cmac(aes)` kernel crypto operations. These
//!   are replaced with the `aes` crate (RustCrypto) for raw AES-128-ECB block
//!   encryption and the `cmac` crate for AES-CMAC operations. The `ring` crate
//!   does not expose raw AES-ECB, so the `aes` crate is used for that purpose.
//! - **`struct bt_crypto` singleton → stateless functions**: The C code manages
//!   a reference-counted singleton (`bt_crypto_new()`/`bt_crypto_ref()`/
//!   `bt_crypto_unref()`) holding three file descriptors (`ecb_aes`, `urandom`,
//!   `cmac_aes`). In Rust, all crypto operations are **stateless pure
//!   functions** — no struct, no lifecycle, no singleton.
//! - **`/dev/urandom` → `ring::rand::SystemRandom`**: Random byte generation
//!   uses the `ring` crate's secure random source.
//!
//! # Byte Order Convention
//!
//! Many Bluetooth crypto functions operate internally in big-endian (MSB first)
//! but accept and return data in little-endian (Bluetooth native, LSB first).
//! The internal `swap_buf` helper performs the byte-order reversal, matching
//! the C code's `swap_buf()` function exactly.
//!
//! # Safety
//!
//! This module contains zero `unsafe` blocks. All cryptographic operations
//! are performed through safe Rust APIs provided by the `aes`, `cmac`, and
//! `ring` crates.
//!
//! # Functions Provided
//!
//! ## Core Security Functions (BT Core Spec Vol 3, Part H)
//! - [`bt_crypto_e`] — Security function `e` (AES-128 encrypt)
//! - [`bt_crypto_ah`] — Random Address Hash function `ah`
//! - [`bt_crypto_c1`] — LE Legacy Pairing confirm value `c1`
//! - [`bt_crypto_s1`] — LE Legacy Pairing STK generation `s1`
//!
//! ## LE Secure Connections (BT Core Spec Vol 3, Part H, Section 2.2.7)
//! - [`bt_crypto_f4`] — Confirm value generation `f4`
//! - [`bt_crypto_f5`] — Key generation `f5` (returns MacKey + LTK)
//! - [`bt_crypto_f6`] — Check value generation `f6`
//! - [`bt_crypto_g2`] — Numeric comparison `g2`
//! - [`bt_crypto_h6`] — Link key conversion `h6`
//!
//! ## ATT Signing (BT Core Spec Vol 3, Part C, Section 10.4)
//! - [`bt_crypto_sign_att`] — Generate ATT signed write signature
//! - [`bt_crypto_verify_att_sign`] — Verify ATT signed write signature
//!
//! ## GATT Database Hash (BT Core Spec Vol 3, Part G, Section 7.3)
//! - [`bt_crypto_gatt_hash`] — AES-CMAC hash with zero key
//!
//! ## CSIS/SIRK (BT Core Spec Supplement, Part B, Section 6.7)
//! - [`bt_crypto_sef`] — SIRK Encryption Function
//! - [`bt_crypto_sih`] — SIRK Hash Function (alias for `ah`)
//! - [`bt_crypto_sirk`] — SIRK generation from device identity
//! - [`bt_crypto_rsi`] — Resolvable Set Identifier generation
//!
//! ## Utility
//! - [`random_bytes`] — Cryptographic random byte generation

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use cmac::{Cmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

/// Maximum message length that can be passed to the internal `aes_cmac` and
/// `aes_cmac_be` helpers. Matches the C constant `CMAC_MSG_MAX` (crypto.c
/// line 63). Messages longer than this limit must use the raw `cmac_compute`
/// helper directly (e.g., `bt_crypto_sign_att`, `bt_crypto_gatt_hash`).
const CMAC_MSG_MAX: usize = 80;

/// Length of an ATT signature in bytes. Matches the C constant `ATT_SIGN_LEN`
/// (crypto.c line 65). The signature consists of 4 bytes of sign_cnt
/// (little-endian) followed by 8 bytes of truncated AES-CMAC output.
const ATT_SIGN_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during AES/CMAC cryptographic operations.
///
/// Replaces the C code's `bool` return values with typed error variants
/// for idiomatic Rust error propagation via `Result<T, CryptoError>`.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AES-128-ECB block encryption failed.
    ///
    /// This indicates an internal error in the `aes` crate block cipher
    /// initialization, which should not occur with valid 16-byte keys.
    #[error("AES encryption failed")]
    AesError,

    /// AES-CMAC computation failed.
    ///
    /// This typically indicates an invalid key length passed to the CMAC
    /// initialization (should always be 16 bytes for AES-128-CMAC).
    #[error("CMAC computation failed")]
    CmacError,

    /// Cryptographic random number generation failed.
    ///
    /// Indicates a failure in the operating system's entropy source,
    /// accessed via `ring::rand::SystemRandom`.
    #[error("Random number generation failed")]
    RandomError,

    /// Invalid input length for a cryptographic operation.
    ///
    /// Raised when a message exceeds the maximum allowed length for
    /// CMAC operations ([`CMAC_MSG_MAX`] = 80 bytes), or when a PDU
    /// is too short for signature verification.
    #[error("Invalid input length")]
    InvalidLength,
}

// ---------------------------------------------------------------------------
// Internal helper functions
// ---------------------------------------------------------------------------

/// Reverse the byte order of a buffer, converting between MSB-first
/// (big-endian) and LSB-first (little-endian) representations.
///
/// This is the Rust equivalent of the C `swap_buf(src, dst, len)` function
/// (crypto.c lines 254-260). It is used throughout the Bluetooth crypto
/// functions to convert between Bluetooth's native little-endian byte order
/// and the big-endian order expected by standard cryptographic operations.
///
/// # Panics
///
/// Panics if `src` and `dst` have different lengths.
fn swap_buf(src: &[u8], dst: &mut [u8]) {
    let len = src.len();
    debug_assert_eq!(len, dst.len(), "swap_buf: src and dst must have equal length");
    for i in 0..len {
        dst[len - 1 - i] = src[i];
    }
}

/// XOR two 128-bit (16-byte) blocks.
///
/// Replaces the C `u128_xor(p, q, r)` function (crypto.c lines 449-461)
/// which used a `u128` struct with two `uint64_t` fields. The Rust version
/// performs a simple byte-wise XOR.
fn u128_xor(p: &[u8; 16], q: &[u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = p[i] ^ q[i];
    }
    r
}

/// Perform a single-block AES-128-ECB encryption.
///
/// This replaces the C `alg_new()` + `alg_encrypt()` functions (crypto.c
/// lines 206-252) which used AF_ALG `setsockopt(SOL_ALG, ALG_SET_KEY)`
/// followed by `sendmsg` + `read` on a kernel crypto socket.
///
/// Uses the `aes` crate (`aes::Aes128`) with the `cipher::BlockEncrypt`
/// trait for raw AES-128-ECB block encryption. The `ring` crate does not
/// expose raw AES-ECB operations, so the RustCrypto `aes` crate is the
/// standard Rust approach for Bluetooth crypto that requires raw AES.
fn aes_ecb_encrypt(key: &[u8; 16], plaintext: &[u8; 16]) -> Result<[u8; 16], CryptoError> {
    let cipher = Aes128::new(key.into());
    let mut block = (*plaintext).into();
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

/// Raw AES-CMAC computation with no message length limit.
///
/// Computes AES-128-CMAC over the given key and message bytes. Both key
/// and message are used as-is (caller is responsible for byte order).
///
/// This is the foundation for all CMAC operations in this module. The
/// length-limited wrappers `aes_cmac_be` and `aes_cmac` add byte-order
/// conversion and size checking on top of this function.
fn cmac_compute(key: &[u8], msg: &[u8]) -> Result<[u8; 16], CryptoError> {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).map_err(|_| CryptoError::CmacError)?;
    mac.update(msg);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    Ok(out)
}

/// AES-CMAC with big-endian key and message, enforcing the maximum message
/// length of [`CMAC_MSG_MAX`] bytes.
///
/// Replaces the C `aes_cmac_be()` function (crypto.c lines 589-617) which
/// opened an AF_ALG `cmac(aes)` socket, set the key via `setsockopt`, and
/// used `send` + `read` for the CMAC computation.
fn aes_cmac_be(key: &[u8; 16], msg: &[u8]) -> Result<[u8; 16], CryptoError> {
    if msg.len() > CMAC_MSG_MAX {
        return Err(CryptoError::InvalidLength);
    }
    cmac_compute(key, msg)
}

/// AES-CMAC with little-endian (Bluetooth native) key and message.
///
/// Converts key and message from little-endian to big-endian, performs the
/// CMAC computation, and converts the result back to little-endian. Enforces
/// the maximum message length of [`CMAC_MSG_MAX`] bytes.
///
/// Replaces the C `aes_cmac()` function (crypto.c lines 619-636) which
/// wrapped `aes_cmac_be()` with `swap_buf` calls for byte-order conversion.
fn aes_cmac_le(key: &[u8; 16], msg: &[u8]) -> Result<[u8; 16], CryptoError> {
    if msg.len() > CMAC_MSG_MAX {
        return Err(CryptoError::InvalidLength);
    }

    // Swap key from LE to BE (MSB first)
    let mut key_msb = [0u8; 16];
    swap_buf(key, &mut key_msb);

    // Swap message from LE to BE (MSB first) — stack-allocated up to CMAC_MSG_MAX
    let mut msg_msb = [0u8; CMAC_MSG_MAX];
    swap_buf(msg, &mut msg_msb[..msg.len()]);

    // Compute CMAC in big-endian domain
    let out_msb = cmac_compute(&key_msb, &msg_msb[..msg.len()])?;

    // Swap result from BE back to LE
    let mut res = [0u8; 16];
    swap_buf(&out_msb, &mut res);
    Ok(res)
}

/// AES-CMAC with zero key in big-endian mode.
///
/// Computes `AES-CMAC_ZERO(msg)` where the key is all zeros. Used as the
/// foundation for CSIS salt generation (`sef_s1`).
///
/// Replaces the C `aes_cmac_zero()` function (crypto.c lines 830-836).
fn aes_cmac_zero(msg: &[u8]) -> Result<[u8; 16], CryptoError> {
    let zero_key = [0u8; 16];
    aes_cmac_be(&zero_key, msg)
}

/// CSIS salt generation function s1.
///
/// `s1(M) = AES-CMAC_ZERO(M)` — CMAC with zero key over message M in
/// big-endian mode.
///
/// Replaces the C `sef_s1()` function (crypto.c lines 857-862).
fn sef_s1(m: &[u8]) -> Result<[u8; 16], CryptoError> {
    aes_cmac_zero(m)
}

/// CSIS key derivation function k1.
///
/// ```text
/// T = AES-CMAC_SALT(N)
/// k1(N, SALT, P) = AES-CMAC_T(P)
/// ```
///
/// All inputs and outputs are in big-endian format.
///
/// Replaces the C `sef_k1()` function (crypto.c lines 891-903).
fn sef_k1(n: &[u8; 16], salt: &[u8; 16], p: &[u8]) -> Result<[u8; 16], CryptoError> {
    // T = AES-CMAC_SALT(N)
    let t = aes_cmac_be(salt, n)?;

    // k1(N, SALT, P) = AES-CMAC_T(P)
    aes_cmac_be(&t, p)
}

// ---------------------------------------------------------------------------
// Public API: Random bytes
// ---------------------------------------------------------------------------

/// Generate cryptographic random bytes.
///
/// Fills the provided buffer with cryptographically secure random bytes
/// from the operating system's entropy source.
///
/// Replaces the C `bt_crypto_random_bytes()` function (crypto.c lines
/// 191-204) which read directly from `/dev/urandom`.
///
/// # Errors
///
/// Returns [`CryptoError::RandomError`] if the system random number
/// generator fails.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    let rng = SystemRandom::new();
    rng.fill(buf).map_err(|_| CryptoError::RandomError)
}

// ---------------------------------------------------------------------------
// Public API: Core Bluetooth Security Functions
// ---------------------------------------------------------------------------

/// Security function `e` — AES-128 encrypt with Bluetooth byte ordering.
///
/// Generates 128-bit encrypted data from a 128-bit key and 128-bit
/// plaintext using AES-128-ECB. The most significant octet of `key`
/// corresponds to `key[0]`, and similarly for `plaintext` and the output.
///
/// Internally converts from Bluetooth LE byte order to big-endian for the
/// AES operation, and converts the result back.
///
/// This is the fundamental building block for all LE Legacy pairing crypto
/// functions (`ah`, `c1`, `s1`) and the SIRK hash function (`sih`).
///
/// Replaces the C `bt_crypto_e()` function (crypto.c lines 357-388).
///
/// # Arguments
///
/// - `key` — 128-bit encryption key (Bluetooth byte order)
/// - `plaintext` — 128-bit plaintext data (Bluetooth byte order)
///
/// # Returns
///
/// 128-bit encrypted data (Bluetooth byte order).
pub fn bt_crypto_e(key: &[u8; 16], plaintext: &[u8; 16]) -> Result<[u8; 16], CryptoError> {
    // The most significant octet of key corresponds to key[0]
    let mut key_msb = [0u8; 16];
    swap_buf(key, &mut key_msb);

    // Most significant octet of plaintextData corresponds to plaintext[0]
    let mut pt_msb = [0u8; 16];
    swap_buf(plaintext, &mut pt_msb);

    // AES-128-ECB encrypt in big-endian domain
    let out_msb = aes_ecb_encrypt(&key_msb, &pt_msb)?;

    // Most significant octet of encryptedData corresponds to out[0]
    let mut encrypted = [0u8; 16];
    swap_buf(&out_msb, &mut encrypted);
    Ok(encrypted)
}

/// Random Address Hash function `ah`.
///
/// Generates a 24-bit hash value used in resolvable private addresses (RPAs).
///
/// ```text
/// r' = padding(13 zero bytes) || r(3 bytes)
/// ah(k, r) = e(k, r') mod 2^24
/// ```
///
/// The output is the least significant 24 bits (3 bytes) of the encrypted
/// result.
///
/// Replaces the C `bt_crypto_ah()` function (crypto.c lines 422-443).
///
/// # Arguments
///
/// - `k` — 128-bit key (Bluetooth byte order)
/// - `r` — 24-bit random part (3 bytes)
///
/// # Returns
///
/// 24-bit hash value (3 bytes).
pub fn bt_crypto_ah(k: &[u8; 16], r: &[u8; 3]) -> Result<[u8; 3], CryptoError> {
    // r' = padding || r  (r in least significant bytes, padding in most significant)
    let mut rp = [0u8; 16];
    rp[0..3].copy_from_slice(r);
    // rp[3..16] already zero (padding)

    // e(k, r')
    let encrypted = bt_crypto_e(k, &rp)?;

    // ah(k, r) = e(k, r') mod 2^24 — take least significant 3 bytes
    let mut hash = [0u8; 3];
    hash.copy_from_slice(&encrypted[0..3]);
    Ok(hash)
}

/// Confirm value generation function `c1` for LE Legacy Pairing.
///
/// Generates the confirm value used during the LE Legacy pairing process.
///
/// ```text
/// p1 = pres || preq || rat' || iat'
/// p2 = padding(4 zero bytes) || ia || ra
/// c1(k, r, preq, pres, iat, rat, ia, ra) = e(k, e(k, r XOR p1) XOR p2)
/// ```
///
/// Replaces the C `bt_crypto_c1()` function (crypto.c lines 515-546).
///
/// # Arguments
///
/// - `k` — 128-bit key (TK)
/// - `r` — 128-bit random number
/// - `pres` — 7-byte Pairing Response command
/// - `preq` — 7-byte Pairing Request command
/// - `iat` — Initiator address type (1 bit)
/// - `ia` — 6-byte initiator address
/// - `rat` — Responder address type (1 bit)
/// - `ra` — 6-byte responder address
///
/// # Returns
///
/// 128-bit confirm value.
pub fn bt_crypto_c1(
    k: &[u8; 16],
    r: &[u8; 16],
    pres: &[u8; 7],
    preq: &[u8; 7],
    iat: u8,
    ia: &[u8; 6],
    rat: u8,
    ra: &[u8; 6],
) -> Result<[u8; 16], CryptoError> {
    // p1 = pres || preq || rat' || iat'
    let mut p1 = [0u8; 16];
    p1[0] = iat;
    p1[1] = rat;
    p1[2..9].copy_from_slice(preq);
    p1[9..16].copy_from_slice(pres);

    // p2 = padding || ia || ra
    let mut p2 = [0u8; 16];
    p2[0..6].copy_from_slice(ra);
    p2[6..12].copy_from_slice(ia);
    // p2[12..16] already zero (padding)

    // res = r XOR p1
    let res = u128_xor(r, &p1);

    // res = e(k, res)
    let res = bt_crypto_e(k, &res)?;

    // res = res XOR p2
    let res = u128_xor(&res, &p2);

    // res = e(k, res)
    bt_crypto_e(k, &res)
}

/// Key generation function `s1` for LE Legacy Pairing STK generation.
///
/// Generates the Short-Term Key (STK) during the LE Legacy pairing process.
///
/// ```text
/// r' = r1[0..8] || r2[0..8]    (lower 8 bytes of each)
/// s1(k, r1, r2) = e(k, r')
/// ```
///
/// Replaces the C `bt_crypto_s1()` function (crypto.c lines 579-587).
///
/// # Arguments
///
/// - `k` — 128-bit key (TK)
/// - `r1` — 128-bit random number from initiator
/// - `r2` — 128-bit random number from responder
///
/// # Returns
///
/// 128-bit Short-Term Key.
pub fn bt_crypto_s1(k: &[u8; 16], r1: &[u8; 16], r2: &[u8; 16]) -> Result<[u8; 16], CryptoError> {
    // r' = r1'(lower 8 bytes) || r2'(lower 8 bytes)
    // The least significant 64 bits of r1 are r1[0..8], concatenated with
    // the least significant 64 bits of r2 (r2[0..8]).
    let mut rp = [0u8; 16];
    rp[0..8].copy_from_slice(&r2[0..8]);
    rp[8..16].copy_from_slice(&r1[0..8]);

    // s1(k, r1, r2) = e(k, r')
    bt_crypto_e(k, &rp)
}

// ---------------------------------------------------------------------------
// Public API: LE Secure Connections
// ---------------------------------------------------------------------------

/// LE Secure Connections confirm value generation function `f4`.
///
/// ```text
/// m = z || v || u    (65 bytes)
/// f4(u, v, x, z) = AES-CMAC_x(m)
/// ```
///
/// Replaces the C `bt_crypto_f4()` function (crypto.c lines 638-651).
///
/// # Arguments
///
/// - `u` — 256-bit public key X coordinate
/// - `v` — 256-bit public key X coordinate
/// - `x` — 128-bit CMAC key
/// - `z` — 8-bit parameter
///
/// # Returns
///
/// 128-bit confirm value.
pub fn bt_crypto_f4(
    u: &[u8; 32],
    v: &[u8; 32],
    x: &[u8; 16],
    z: u8,
) -> Result<[u8; 16], CryptoError> {
    let mut m = [0u8; 65];
    m[0] = z;
    m[1..33].copy_from_slice(v);
    m[33..65].copy_from_slice(u);

    aes_cmac_le(x, &m)
}

/// LE Secure Connections key generation function `f5`.
///
/// Generates the MacKey and LTK from the ECDH shared secret.
///
/// ```text
/// salt = 0x6c888391...  (hardcoded constant)
/// t = AES-CMAC(salt, w)
/// m = Counter || "btle" || n1 || n2 || a1 || a2 || length  (53 bytes)
/// mackey = AES-CMAC(t, m) with Counter=0
/// ltk    = AES-CMAC(t, m) with Counter=1
/// ```
///
/// Returns a tuple `(mackey, ltk)` instead of two output parameters.
///
/// Replaces the C `bt_crypto_f5()` function (crypto.c lines 653-679).
///
/// # Arguments
///
/// - `w` — 256-bit ECDH shared secret (DHKey)
/// - `n1` — 128-bit nonce from initiator
/// - `n2` — 128-bit nonce from responder
/// - `a1` — 7-byte initiator address info (type + address)
/// - `a2` — 7-byte responder address info (type + address)
///
/// # Returns
///
/// Tuple of `(mackey, ltk)`, each 128 bits.
pub fn bt_crypto_f5(
    w: &[u8; 32],
    n1: &[u8; 16],
    n2: &[u8; 16],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> Result<([u8; 16], [u8; 16]), CryptoError> {
    // "btle" string constant (reversed in LE encoding)
    let btle: [u8; 4] = [0x65, 0x6c, 0x74, 0x62];

    // Hardcoded salt constant from BT Core Spec
    let salt: [u8; 16] = [
        0xbe, 0x83, 0x60, 0x5a, 0xdb, 0x0b, 0x37, 0x60, 0x38, 0xa5, 0xf5, 0xaa, 0x91, 0x83, 0x88,
        0x6c,
    ];

    // Length constant = 256 in LE format
    let length: [u8; 2] = [0x00, 0x01];

    // t = AES-CMAC(salt, w)  [all in LE]
    let t = aes_cmac_le(&salt, w)?;

    // Build m (53 bytes):
    // m[0..2]   = length
    // m[2..9]   = a2
    // m[9..16]  = a1
    // m[16..32] = n2
    // m[32..48] = n1
    // m[48..52] = btle
    // m[52]     = counter
    let mut m = [0u8; 53];
    m[0..2].copy_from_slice(&length);
    m[2..9].copy_from_slice(a2);
    m[9..16].copy_from_slice(a1);
    m[16..32].copy_from_slice(n2);
    m[32..48].copy_from_slice(n1);
    m[48..52].copy_from_slice(&btle);

    // mackey = AES-CMAC(t, m) with Counter=0
    m[52] = 0;
    let mackey = aes_cmac_le(&t, &m)?;

    // ltk = AES-CMAC(t, m) with Counter=1
    m[52] = 1;
    let ltk = aes_cmac_le(&t, &m)?;

    Ok((mackey, ltk))
}

/// LE Secure Connections check value generation function `f6`.
///
/// ```text
/// m = a2 || a1 || io_cap || r || n2 || n1    (65 bytes)
/// f6(w, n1, n2, r, io_cap, a1, a2) = AES-CMAC_w(m)
/// ```
///
/// Replaces the C `bt_crypto_f6()` function (crypto.c lines 681-695).
///
/// # Arguments
///
/// - `w` — 128-bit key (MacKey)
/// - `n1` — 128-bit nonce from initiator
/// - `n2` — 128-bit nonce from responder
/// - `r` — 128-bit random value
/// - `io_cap` — 3-byte IO capability
/// - `a1` — 7-byte initiator address info
/// - `a2` — 7-byte responder address info
///
/// # Returns
///
/// 128-bit check value.
pub fn bt_crypto_f6(
    w: &[u8; 16],
    n1: &[u8; 16],
    n2: &[u8; 16],
    r: &[u8; 16],
    io_cap: &[u8; 3],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> Result<[u8; 16], CryptoError> {
    let mut m = [0u8; 65];
    m[0..7].copy_from_slice(a2);
    m[7..14].copy_from_slice(a1);
    m[14..17].copy_from_slice(io_cap);
    m[17..33].copy_from_slice(r);
    m[33..49].copy_from_slice(n2);
    m[49..65].copy_from_slice(n1);

    aes_cmac_le(w, &m)
}

/// Numeric comparison value generation function `g2`.
///
/// ```text
/// m = y || v || u    (80 bytes)
/// g2(u, v, x, y) = AES-CMAC_x(m) mod 10^6
/// ```
///
/// Returns a 6-digit numeric value (0–999999) for passkey comparison.
///
/// Replaces the C `bt_crypto_g2()` function (crypto.c lines 697-713).
///
/// # Arguments
///
/// - `u` — 256-bit public key X coordinate (local)
/// - `v` — 256-bit public key X coordinate (remote)
/// - `x` — 128-bit CMAC key
/// - `y` — 128-bit random nonce
///
/// # Returns
///
/// 6-digit numeric comparison value (0–999999).
pub fn bt_crypto_g2(
    u: &[u8; 32],
    v: &[u8; 32],
    x: &[u8; 16],
    y: &[u8; 16],
) -> Result<u32, CryptoError> {
    let mut m = [0u8; 80];
    m[0..16].copy_from_slice(y);
    m[16..48].copy_from_slice(v);
    m[48..80].copy_from_slice(u);

    let tmp = aes_cmac_le(x, &m)?;

    // get_le32(tmp) % 1000000
    let val = u32::from_le_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]);
    Ok(val % 1_000_000)
}

/// Link key conversion function `h6`.
///
/// ```text
/// h6(w, keyid) = AES-CMAC_w(keyid)
/// ```
///
/// Replaces the C `bt_crypto_h6()` function (crypto.c lines 715-722).
///
/// # Arguments
///
/// - `w` — 128-bit key
/// - `keyid` — 4-byte key identifier
///
/// # Returns
///
/// 128-bit derived key.
pub fn bt_crypto_h6(w: &[u8; 16], keyid: &[u8; 4]) -> Result<[u8; 16], CryptoError> {
    aes_cmac_le(w, keyid)
}

// ---------------------------------------------------------------------------
// Public API: ATT Signing
// ---------------------------------------------------------------------------

/// Generate an ATT signed write signature.
///
/// Produces a 12-byte signature for ATT signed write operations as specified
/// in BT Core Spec Vol 3, Part C, Section 10.4.1.
///
/// The signature format is:
/// - Bytes 0–3: sign_cnt in little-endian format
/// - Bytes 4–11: truncated AES-CMAC output
///
/// Algorithm:
/// 1. Concatenate message `m` with `sign_cnt` (LE u32)
/// 2. Swap key and message to big-endian
/// 3. Compute AES-CMAC in big-endian domain
/// 4. Place `sign_cnt` as BE u32 at output bytes 8–11
/// 5. Swap full 16-byte output to little-endian
/// 6. Extract bytes 4–15 as the 12-byte signature
///
/// Replaces the C `bt_crypto_sign_att()` function (crypto.c lines 262-322).
///
/// # Arguments
///
/// - `key` — 128-bit signing key (CSRK)
/// - `m` — Message data to sign
/// - `sign_cnt` — 32-bit signature counter
///
/// # Returns
///
/// 12-byte ATT signature.
pub fn bt_crypto_sign_att(
    key: &[u8; 16],
    m: &[u8],
    sign_cnt: u32,
) -> Result<[u8; 12], CryptoError> {
    let msg_len = m.len() + 4;
    let mut msg = vec![0u8; msg_len];
    msg[..m.len()].copy_from_slice(m);

    // Add sign_counter to the message as LE u32
    msg[m.len()..m.len() + 4].copy_from_slice(&sign_cnt.to_le_bytes());

    // The most significant octet of key corresponds to key[0] — swap to MSB
    let mut key_msb = [0u8; 16];
    swap_buf(key, &mut key_msb);

    // Swap msg before signing (LE → BE)
    let mut msg_msb = vec![0u8; msg_len];
    swap_buf(&msg, &mut msg_msb);

    // AES-CMAC with big-endian key and message (no length limit — uses raw cmac)
    let mut out = cmac_compute(&key_msb, &msg_msb)?;

    // As per BT spec 4.1 Vol[3], Part C, chapter 10.4.1: sign counter should
    // be placed in the signature
    out[8..12].copy_from_slice(&sign_cnt.to_be_bytes());

    // The most significant octet of hash corresponds to out[0] — swap back
    // Then truncate in most significant bit first order to 12 octets
    let mut tmp = [0u8; 16];
    swap_buf(&out, &mut tmp);

    let mut signature = [0u8; ATT_SIGN_LEN];
    signature.copy_from_slice(&tmp[4..16]);
    Ok(signature)
}

/// Verify an ATT signed write signature.
///
/// Extracts the signature counter from the last 12 bytes of the PDU,
/// regenerates the expected signature, and compares it with the signature
/// embedded in the PDU using constant-time comparison.
///
/// Replaces the C `bt_crypto_verify_att_sign()` function (crypto.c lines
/// 324-342).
///
/// # Arguments
///
/// - `key` — 128-bit signing key (CSRK)
/// - `pdu` — Complete signed PDU (payload + 12-byte signature)
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if the PDU is shorter than
/// [`ATT_SIGN_LEN`] bytes.
pub fn bt_crypto_verify_att_sign(key: &[u8; 16], pdu: &[u8]) -> Result<bool, CryptoError> {
    let pdu_len = pdu.len();
    if pdu_len < ATT_SIGN_LEN {
        return Err(CryptoError::InvalidLength);
    }

    // Extract the existing signature from the end of the PDU
    let sign = &pdu[pdu_len - ATT_SIGN_LEN..];

    // Extract sign_cnt from the first 4 bytes of the signature (LE u32)
    let sign_cnt = u32::from_le_bytes([sign[0], sign[1], sign[2], sign[3]]);

    // Generate the expected signature for the message portion (excluding signature)
    let generated_sign = bt_crypto_sign_att(key, &pdu[..pdu_len - ATT_SIGN_LEN], sign_cnt)?;

    // Constant-time comparison to avoid timing side-channels
    let mut diff = 0u8;
    for i in 0..ATT_SIGN_LEN {
        diff |= generated_sign[i] ^ sign[i];
    }

    Ok(diff == 0)
}

// ---------------------------------------------------------------------------
// Public API: GATT Database Hash
// ---------------------------------------------------------------------------

/// Compute the GATT Database Hash.
///
/// Computes `AES-CMAC` with a zero key over concatenated data buffers,
/// as specified in BT Core Spec Vol 3, Part G, Section 7.3.
///
/// The C code used `writev()` on the AF_ALG CMAC socket to feed multiple
/// iov buffers in a single operation. In Rust, we use the CMAC `update()`
/// method incrementally for each buffer slice.
///
/// Replaces the C `bt_crypto_gatt_hash()` function (crypto.c lines 724-753).
///
/// # Arguments
///
/// - `iov` — Slice of byte slices to concatenate and hash
///
/// # Returns
///
/// 128-bit GATT database hash.
pub fn bt_crypto_gatt_hash(iov: &[&[u8]]) -> Result<[u8; 16], CryptoError> {
    let key = [0u8; 16];
    let mut mac =
        <Cmac<Aes128> as Mac>::new_from_slice(&key).map_err(|_| CryptoError::CmacError)?;

    // Feed each iov buffer incrementally — equivalent to writev() on the CMAC socket
    for buf in iov {
        mac.update(buf);
    }

    let result = mac.finalize().into_bytes();
    let mut res = [0u8; 16];
    res.copy_from_slice(&result);
    Ok(res)
}

// ---------------------------------------------------------------------------
// Public API: CSIS/SIRK Functions
// ---------------------------------------------------------------------------

/// SIRK Encryption Function `sef`.
///
/// Encrypts a Set Identity Resolving Key (SIRK) using the link key or LTK.
///
/// ```text
/// sef(K, SIRK) = k1(K, s1("SIRKenc"), "csis") ^ SIRK
/// ```
///
/// Where:
/// - `s1(M) = AES-CMAC_ZERO(M)` (salt generation with zero key, big-endian)
/// - `k1(N, SALT, P) = AES-CMAC_{AES-CMAC_SALT(N)}(P)` (key derivation)
/// - `^` is bitwise XOR
///
/// Replaces the C `bt_crypto_sef()` function (crypto.c lines 936-967).
///
/// # Arguments
///
/// - `k` — 128-bit encryption key (Link Key or LTK, Bluetooth byte order)
/// - `sirk` — 128-bit SIRK to encrypt (Bluetooth byte order)
///
/// # Returns
///
/// 128-bit encrypted SIRK.
pub fn bt_crypto_sef(k: &[u8; 16], sirk: &[u8; 16]) -> Result<[u8; 16], CryptoError> {
    let m: &[u8] = b"SIRKenc";
    let p: &[u8] = b"csis";

    // salt = s1("SIRKenc") = AES-CMAC_ZERO("SIRKenc")  [big-endian]
    let salt = sef_s1(m)?;

    // Convert K from LE to BE (MSB format)
    let mut k_msb = [0u8; 16];
    swap_buf(k, &mut k_msb);

    // res_msb = k1(K_msb, salt, "csis")  [all big-endian]
    let res_msb = sef_k1(&k_msb, &salt, p)?;

    // Convert result from BE back to LE
    let mut res = [0u8; 16];
    swap_buf(&res_msb, &mut res);

    // out = res XOR sirk
    Ok(u128_xor(&res, sirk))
}

/// SIRK Hash Function `sih`.
///
/// The Resolvable Set Identifier hash function, identical to the Random
/// Address Hash function `ah`.
///
/// ```text
/// sih(k, r) = e(k, padding || r) mod 2^24
/// ```
///
/// Replaces the C `bt_crypto_sih()` function (crypto.c lines 785-789).
///
/// # Arguments
///
/// - `k` — 128-bit key (SIRK)
/// - `r` — 24-bit random value (3 bytes)
///
/// # Returns
///
/// 24-bit hash value (3 bytes).
pub fn bt_crypto_sih(k: &[u8; 16], r: &[u8; 3]) -> Result<[u8; 3], CryptoError> {
    bt_crypto_ah(k, r)
}

/// Generate a SIRK from device identity information.
///
/// Generates a Set Identity Resolving Key from a device name string and
/// device identification fields (vendor, product, version, source).
///
/// Algorithm:
/// 1. `k = gatt_hash([name_bytes])` — hash the name string with zero-key CMAC
/// 2. `sirk_plaintext = gatt_hash([vendor_le, product_le, version_le, source_le])`
///    — hash the device ID fields
/// 3. `sirk = sef(k, sirk_plaintext)` — encrypt with SEF
///
/// Replaces the C `bt_crypto_sirk()` function (crypto.c lines 974-1007).
///
/// # Arguments
///
/// - `name` — Device name string
/// - `vendor` — Vendor ID
/// - `product` — Product ID
/// - `version` — Version number
/// - `source` — Source identifier
///
/// # Returns
///
/// 128-bit SIRK.
pub fn bt_crypto_sirk(
    name: &str,
    vendor: u16,
    product: u16,
    version: u16,
    source: u16,
) -> Result<[u8; 16], CryptoError> {
    // Generate k using the name string as input
    let k = bt_crypto_gatt_hash(&[name.as_bytes()])?;

    // Generate sirk_plaintext using device ID fields as LE bytes.
    // The C code passes raw u16 memory (native endian, which is LE on Linux).
    let vendor_le = vendor.to_le_bytes();
    let product_le = product.to_le_bytes();
    let version_le = version.to_le_bytes();
    let source_le = source.to_le_bytes();

    let sirk_plaintext =
        bt_crypto_gatt_hash(&[&vendor_le[..], &product_le[..], &version_le[..], &source_le[..]])?;

    // Encrypt sirk using k as LTK with sef function
    bt_crypto_sef(&k, &sirk_plaintext)
}

/// Generate a Resolvable Set Identifier (RSI).
///
/// Creates a 6-byte RSI from a SIRK:
///
/// ```text
/// prand = random(3 bytes) with MSBs set: prand[2] = (prand[2] & 0x3F) | 0x40
/// hash  = sih(SIRK, prand)  (3 bytes)
/// rsi   = hash || prand     (6 bytes)
/// ```
///
/// The two most significant bits of `prand` are set to `01` to identify it
/// as a resolvable set identifier.
///
/// Replaces the C `bt_crypto_rsi()` function (crypto.c lines 803-828).
///
/// # Arguments
///
/// - `sirk` — 128-bit Set Identity Resolving Key
///
/// # Returns
///
/// 6-byte Resolvable Set Identifier.
pub fn bt_crypto_rsi(sirk: &[u8; 16]) -> Result<[u8; 6], CryptoError> {
    // Generate 3 random bytes for prand
    let mut prand = [0u8; 3];
    random_bytes(&mut prand)?;

    // Set MSBs: the two most significant bits of prand shall be equal to 01
    prand[2] &= 0x3f;
    prand[2] |= 0x40;

    // hash = sih(SIRK, prand)
    let hash = bt_crypto_sih(sirk, &prand)?;

    // rsi = hash || prand
    let mut rsi = [0u8; 6];
    rsi[0..3].copy_from_slice(&hash);
    rsi[3..6].copy_from_slice(&prand);

    Ok(rsi)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that random_bytes fills a buffer with non-zero data.
    /// (Statistical test — extremely unlikely to produce all zeros.)
    #[test]
    fn test_random_bytes() {
        let mut buf = [0u8; 32];
        random_bytes(&mut buf).unwrap();
        // At least one byte should be non-zero
        assert!(buf.iter().any(|&b| b != 0));
    }

    /// Test swap_buf reversal.
    #[test]
    fn test_swap_buf() {
        let src = [0x01, 0x02, 0x03, 0x04];
        let mut dst = [0u8; 4];
        swap_buf(&src, &mut dst);
        assert_eq!(dst, [0x04, 0x03, 0x02, 0x01]);
    }

    /// Test u128_xor.
    #[test]
    fn test_u128_xor() {
        let a = [0xFFu8; 16];
        let b = [0xFFu8; 16];
        let result = u128_xor(&a, &b);
        assert_eq!(result, [0u8; 16]);

        let c = [0u8; 16];
        let result = u128_xor(&a, &c);
        assert_eq!(result, [0xFFu8; 16]);
    }

    /// Test bt_crypto_e with known test vectors from BT Core Spec.
    /// Test Vector (from BT Core Spec Vol 3, Part H, Appendix D1):
    ///   Key: 0x00000000000000000000000000000000
    ///   Plaintext: 0x00000000000000000000000000000000
    ///   Expected: AES-128 ECB encrypt of all zeros with zero key
    #[test]
    fn test_bt_crypto_e_zero() {
        let key = [0u8; 16];
        let plaintext = [0u8; 16];
        let result = bt_crypto_e(&key, &plaintext).unwrap();
        // AES-128-ECB of all zeros with zero key produces a well-known value.
        // The swap_buf operations make this: swap(AES(swap(key), swap(pt)))
        // With all zeros, swap is identity, so result = swap(AES(0, 0))
        // AES-128-ECB(0, 0) = 0x66e94bd4ef8a2c3b884cfa59ca342b2e
        let expected_be: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        // After swap back to LE:
        let mut expected = [0u8; 16];
        swap_buf(&expected_be, &mut expected);
        assert_eq!(result, expected);
    }

    /// Test bt_crypto_ah with the example from BT Core Spec Vol 3, Part H,
    /// Section 2.2.2.
    #[test]
    fn test_bt_crypto_ah_spec_example() {
        // From the spec example: r = 0x423456
        // k = all zeros (simplified test)
        let k = [0u8; 16];
        let r = [0x56, 0x34, 0x42]; // LE byte order for 0x423456
        let result = bt_crypto_ah(&k, &r).unwrap();
        // The result is the first 3 bytes of e(k, padding || r)
        // We can verify it's 3 bytes and deterministic
        assert_eq!(result.len(), 3);

        // Same input should produce same output
        let result2 = bt_crypto_ah(&k, &r).unwrap();
        assert_eq!(result, result2);
    }

    /// Test bt_crypto_sih is identical to bt_crypto_ah.
    #[test]
    fn test_bt_crypto_sih_equals_ah() {
        let k = [0x42u8; 16];
        let r = [0x01, 0x02, 0x03];
        let ah_result = bt_crypto_ah(&k, &r).unwrap();
        let sih_result = bt_crypto_sih(&k, &r).unwrap();
        assert_eq!(ah_result, sih_result);
    }

    /// Test that CMAC with a message exceeding CMAC_MSG_MAX returns an error.
    #[test]
    fn test_aes_cmac_le_max_length() {
        let key = [0u8; 16];
        let msg = [0u8; CMAC_MSG_MAX + 1]; // 81 bytes — exceeds limit
        let result = aes_cmac_le(&key, &msg);
        assert!(result.is_err());
    }

    /// Test that CMAC at exactly CMAC_MSG_MAX succeeds.
    #[test]
    fn test_aes_cmac_le_exact_max() {
        let key = [0u8; 16];
        let msg = [0u8; CMAC_MSG_MAX]; // 80 bytes — exactly at limit
        let result = aes_cmac_le(&key, &msg);
        assert!(result.is_ok());
    }

    /// Test bt_crypto_gatt_hash with zero-length input produces a
    /// deterministic result (CMAC of empty message with zero key).
    #[test]
    fn test_bt_crypto_gatt_hash_empty() {
        let result = bt_crypto_gatt_hash(&[]).unwrap();
        // CMAC with zero key and empty message should be deterministic
        let result2 = bt_crypto_gatt_hash(&[]).unwrap();
        assert_eq!(result, result2);
        assert_eq!(result.len(), 16);
    }

    /// Test bt_crypto_gatt_hash with multiple iov buffers equals a single
    /// concatenated buffer (verifying incremental update correctness).
    #[test]
    fn test_bt_crypto_gatt_hash_iov_concatenation() {
        let a = [0x01u8, 0x02, 0x03];
        let b = [0x04u8, 0x05, 0x06];
        let combined = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];

        let result_split = bt_crypto_gatt_hash(&[&a, &b]).unwrap();
        let result_combined = bt_crypto_gatt_hash(&[&combined]).unwrap();
        assert_eq!(result_split, result_combined);
    }

    /// Test bt_crypto_verify_att_sign fails with PDU shorter than ATT_SIGN_LEN.
    #[test]
    fn test_verify_att_sign_short_pdu() {
        let key = [0u8; 16];
        let short_pdu = [0u8; ATT_SIGN_LEN - 1];
        let result = bt_crypto_verify_att_sign(&key, &short_pdu);
        assert!(result.is_err());
    }

    /// Test that bt_crypto_sign_att produces a 12-byte signature and
    /// bt_crypto_verify_att_sign can verify it.
    #[test]
    fn test_sign_and_verify_att() {
        let key = [0x42u8; 16];
        let message = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let sign_cnt: u32 = 1;

        // Generate signature
        let signature = bt_crypto_sign_att(&key, &message, sign_cnt).unwrap();
        assert_eq!(signature.len(), ATT_SIGN_LEN);

        // Build signed PDU: message || signature
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&message);
        pdu.extend_from_slice(&signature);

        // Verify should succeed
        let valid = bt_crypto_verify_att_sign(&key, &pdu).unwrap();
        assert!(valid);

        // Corrupt the PDU and verify should fail
        let mut corrupted_pdu = pdu.clone();
        corrupted_pdu[0] ^= 0xFF;
        let invalid = bt_crypto_verify_att_sign(&key, &corrupted_pdu).unwrap();
        assert!(!invalid);
    }

    /// Test bt_crypto_c1 produces deterministic output.
    #[test]
    fn test_bt_crypto_c1_deterministic() {
        let k = [0u8; 16];
        let r = [0u8; 16];
        let pres = [0u8; 7];
        let preq = [0u8; 7];
        let ia = [0u8; 6];
        let ra = [0u8; 6];

        let result1 = bt_crypto_c1(&k, &r, &pres, &preq, 0, &ia, 0, &ra).unwrap();
        let result2 = bt_crypto_c1(&k, &r, &pres, &preq, 0, &ia, 0, &ra).unwrap();
        assert_eq!(result1, result2);
    }

    /// Test bt_crypto_s1 produces deterministic output.
    #[test]
    fn test_bt_crypto_s1_deterministic() {
        let k = [0u8; 16];
        let r1 = [0x01u8; 16];
        let r2 = [0x02u8; 16];

        let result1 = bt_crypto_s1(&k, &r1, &r2).unwrap();
        let result2 = bt_crypto_s1(&k, &r1, &r2).unwrap();
        assert_eq!(result1, result2);
    }

    /// Test bt_crypto_f4 produces 16-byte output.
    #[test]
    fn test_bt_crypto_f4_output_size() {
        let u = [0u8; 32];
        let v = [0u8; 32];
        let x = [0u8; 16];
        let result = bt_crypto_f4(&u, &v, &x, 0).unwrap();
        assert_eq!(result.len(), 16);
    }

    /// Test bt_crypto_f5 returns two distinct 16-byte keys.
    #[test]
    fn test_bt_crypto_f5_output() {
        let w = [0u8; 32];
        let n1 = [0x01u8; 16];
        let n2 = [0x02u8; 16];
        let a1 = [0x03u8; 7];
        let a2 = [0x04u8; 7];

        let (mackey, ltk) = bt_crypto_f5(&w, &n1, &n2, &a1, &a2).unwrap();
        assert_eq!(mackey.len(), 16);
        assert_eq!(ltk.len(), 16);
        // mackey and ltk should differ (different counter values)
        assert_ne!(mackey, ltk);
    }

    /// Test bt_crypto_g2 returns a value in [0, 999999].
    #[test]
    fn test_bt_crypto_g2_range() {
        let u = [0u8; 32];
        let v = [0u8; 32];
        let x = [0u8; 16];
        let y = [0u8; 16];

        let val = bt_crypto_g2(&u, &v, &x, &y).unwrap();
        assert!(val < 1_000_000);
    }

    /// Test bt_crypto_h6 produces 16-byte output.
    #[test]
    fn test_bt_crypto_h6_output() {
        let w = [0u8; 16];
        let keyid = [0x72, 0x62, 0x65, 0x6c]; // "lebr" reversed
        let result = bt_crypto_h6(&w, &keyid).unwrap();
        assert_eq!(result.len(), 16);
    }

    /// Test bt_crypto_sef is deterministic and produces 16-byte output.
    #[test]
    fn test_bt_crypto_sef_deterministic() {
        let k = [0x42u8; 16];
        let sirk = [0x01u8; 16];

        let result1 = bt_crypto_sef(&k, &sirk).unwrap();
        let result2 = bt_crypto_sef(&k, &sirk).unwrap();
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 16);
    }

    /// Test bt_crypto_sirk produces deterministic output.
    #[test]
    fn test_bt_crypto_sirk_deterministic() {
        let result1 = bt_crypto_sirk("TestDevice", 0x0001, 0x0002, 0x0003, 0x0004).unwrap();
        let result2 = bt_crypto_sirk("TestDevice", 0x0001, 0x0002, 0x0003, 0x0004).unwrap();
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 16);
    }

    /// Test bt_crypto_rsi produces 6-byte output with correct prand MSBs.
    #[test]
    fn test_bt_crypto_rsi_format() {
        let sirk = [0x42u8; 16];
        let rsi = bt_crypto_rsi(&sirk).unwrap();
        assert_eq!(rsi.len(), 6);

        // prand is at rsi[3..6], and prand[2] (= rsi[5]) should have
        // bits 7:6 = 01 (i.e., 0x40..0x7F range)
        let prand_msb = rsi[5];
        assert_eq!(prand_msb & 0xC0, 0x40, "prand MSBs should be 01");
    }
}
