// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2024 BlueZ Project
//
// Mesh-specific cryptographic functions for the bluetooth-meshd daemon.
// Replaces mesh/crypto.c (1065 lines) and mesh/crypto.h (107 lines).
//
// Implements all mesh security KDFs (s1, k1–k4), AES-CMAC, AES-CCM
// encrypt/decrypt, network packet encode/decode, payload encrypt/decrypt,
// nonce builders, privacy obfuscation/clarification, FCS/CRC computation,
// and a runtime self-test.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as CipherKeyInit};
use cmac::{Cmac, Mac};
use tracing::debug;

use bluez_shared::crypto::aes_cmac::random_bytes;

// ---------------------------------------------------------------------------
// Protocol constants (from mesh/net.h and mesh/mesh-defs.h)
// Defined locally because the `net` module may not be available yet.
// ---------------------------------------------------------------------------

/// Bit 7 of the first transport byte indicates a control message.
const CTL: u8 = 0x80;

/// Mask for TTL field (bits 0-6).
const TTL_MASK: u8 = 0x7f;

/// 24-bit sequence number mask (kept for API compatibility; used by callers).
const _SEQ_MASK: u32 = 0x00FF_FFFF;

/// Application key aid value indicating a device key.
const APP_AID_DEV: u8 = 0x00;

/// Bit shift for the segmented flag in the transport header.
const SEG_HDR_SHIFT: u32 = 31;

/// Bit shift for key_aid / opcode in the transport header.
const KEY_HDR_SHIFT: u32 = 24;

/// Mask for key_aid + segmented flag.
const KEY_ID_MASK: u32 = 0x7f;

/// Mask for the opcode in control messages.
const OPCODE_MASK: u32 = 0x7f;

/// Bit shift for the SZMIC flag.
const SZMIC_HDR_SHIFT: u32 = 23;

/// Bit shift for SeqZero in segmented messages.
const SEQ_ZERO_HDR_SHIFT: u32 = 10;

/// Mask for SeqZero (13 bits).
const SEQ_ZERO_MASK: u32 = 0x1fff;

/// Mask for segment index fields (5 bits).
const SEG_MASK: u32 = 0x1f;

/// Bit shift for SegO (segment offset).
const SEGO_HDR_SHIFT: u32 = 5;

/// Bit shift for SegN (last segment number).
const SEGN_HDR_SHIFT: u32 = 0;

/// Relay bit position in the nonce (kept for API compatibility; used by callers).
const _RELAY: u8 = 0x80;

/// Bit shift for the relay flag in header word.
const RELAY_HDR_SHIFT: u32 = 23;

/// Network opcode: segment acknowledgment.
const NET_OP_SEG_ACKNOWLEDGE: u8 = 0x00;

/// Mask for the key AID (6 bits) used in non-control transport.
const KEY_AID_MASK: u8 = 0x3f;

// ---------------------------------------------------------------------------
// Address classification helpers
// ---------------------------------------------------------------------------

/// Returns true if the address is a unicast address (0x0001 – 0x7FFF).
#[inline]
fn is_unicast(addr: u16) -> bool {
    addr > 0 && addr < 0x8000
}

// ---------------------------------------------------------------------------
// PacketFields — parsed network PDU representation
// ---------------------------------------------------------------------------

/// Parsed representation of a mesh network PDU.
#[derive(Debug, Clone)]
pub struct PacketFields {
    pub ctl: bool,
    pub ttl: u8,
    pub seq: u32,
    pub src: u16,
    pub dst: u16,
    pub cookie: u8,
    pub opcode: u8,
    pub segmented: bool,
    pub key_aid: u8,
    pub szmic: bool,
    pub relay: bool,
    pub seq_zero: u16,
    pub seg_o: u8,
    pub seg_n: u8,
    pub payload: Vec<u8>,
    pub payload_len: usize,
}

// ---------------------------------------------------------------------------
// CRC table — reversed 8-bit polynomial 0x07
// Exact copy from mesh/crypto.c lines 945-985
// ---------------------------------------------------------------------------

#[rustfmt::skip]
static CRC_TABLE: [u8; 256] = [
    0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75,
    0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
    0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69,
    0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,
    0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d,
    0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
    0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51,
    0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,
    0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05,
    0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
    0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19,
    0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,
    0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d,
    0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
    0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21,
    0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,
    0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95,
    0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
    0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89,
    0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,
    0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad,
    0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
    0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1,
    0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,
    0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5,
    0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
    0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9,
    0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,
    0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd,
    0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
    0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1,
    0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf,
];

// ---------------------------------------------------------------------------
// AES-CCM expected test result for runtime self-test
// Exact copy from mesh/crypto.c lines 1017-1022
// ---------------------------------------------------------------------------

static CRYPTO_TEST_RESULT: [u8; 28] = [
    0x75, 0x03, 0x7e, 0xe2, 0x89, 0x81, 0xbe, 0x59, 0xbc, 0xe6, 0xdd, 0x23, 0x63, 0x5b, 0x16, 0x61,
    0xb7, 0x23, 0x92, 0xd4, 0x86, 0xee, 0x84, 0x29, 0x9a, 0x2a, 0xbf, 0x96,
];

// ===========================================================================
// Phase 1 — Low-Level Crypto Primitives
// ===========================================================================

/// Encrypt a single 16-byte block with AES-128 ECB.
/// Replaces the C `aes_ecb_one()` helper which uses `l_cipher_new(L_CIPHER_AES)`.
fn aes_ecb_one(key: &[u8; 16], input: &[u8; 16]) -> Option<[u8; 16]> {
    let cipher = Aes128::new(key.into());
    let mut block = aes::Block::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    let mut output = [0u8; 16];
    output.copy_from_slice(&block);
    Some(output)
}

/// Single-shot AES-CMAC computation.
/// Replaces the C `aes_cmac_one()` helper using `l_checksum_new_cmac_aes`.
fn aes_cmac_one(key: &[u8; 16], msg: &[u8], res: &mut [u8; 16]) -> bool {
    let Ok(mut mac) = <Cmac<Aes128> as Mac>::new_from_slice(key) else {
        return false;
    };
    Mac::update(&mut mac, msg);
    let result = Mac::finalize(mac).into_bytes();
    res.copy_from_slice(&result);
    true
}

/// Public AES-CMAC wrapper. Thin pass-through to `aes_cmac_one`.
pub fn mesh_crypto_aes_cmac(key: &[u8; 16], msg: &[u8], res: &mut [u8; 16]) -> bool {
    aes_cmac_one(key, msg, res)
}

// ===========================================================================
// AES-CCM Encrypt / Decrypt
// ===========================================================================

/// AES-CCM authenticated encryption.
///
/// # Arguments
/// * `nonce` — 13-byte nonce
/// * `key` — 16-byte AES key
/// * `aad` — optional associated data
/// * `msg` — plaintext
/// * `out_msg` — output buffer (must be `msg.len() + mic_size` bytes)
/// * `mic_size` — MIC length (4 or 8)
///
/// Returns `true` on success.
pub fn mesh_crypto_aes_ccm_encrypt(
    nonce: &[u8; 13],
    key: &[u8; 16],
    aad: Option<&[u8]>,
    msg: &[u8],
    out_msg: &mut [u8],
    mic_size: usize,
) -> bool {
    if out_msg.len() < msg.len() + mic_size {
        return false;
    }

    // Copy plaintext to output buffer for in-place encryption
    out_msg[..msg.len()].copy_from_slice(msg);

    let aad_bytes = aad.unwrap_or(&[]);

    match mic_size {
        4 => ccm_encrypt_inner::<ccm::consts::U4>(key, nonce, aad_bytes, out_msg, msg.len()),
        8 => ccm_encrypt_inner::<ccm::consts::U8>(key, nonce, aad_bytes, out_msg, msg.len()),
        _ => false,
    }
}

/// Generic CCM encryption helper parameterised on tag size.
fn ccm_encrypt_inner<TagSize>(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    buf: &mut [u8],
    pt_len: usize,
) -> bool
where
    TagSize: ccm::aead::generic_array::ArrayLength<u8> + ccm::TagSize,
{
    use ccm::aead::AeadInPlace;
    use ccm::aead::KeyInit as AeadKeyInit;
    use ccm::aead::generic_array::GenericArray;

    type AesCcm<T> = ccm::Ccm<Aes128, T, ccm::consts::U13>;

    let cipher = AesCcm::<TagSize>::new(GenericArray::from_slice(key));
    let nonce_ga = GenericArray::from_slice(nonce);

    match cipher.encrypt_in_place_detached(nonce_ga, aad, &mut buf[..pt_len]) {
        Ok(tag) => {
            buf[pt_len..pt_len + tag.len()].copy_from_slice(&tag);
            true
        }
        Err(_) => false,
    }
}

/// AES-CCM authenticated decryption.
///
/// # Arguments
/// * `nonce` — 13-byte nonce
/// * `key` — 16-byte AES key
/// * `aad` — optional associated data
/// * `enc_msg` — ciphertext including MIC at the end
/// * `out_msg` — output buffer for decrypted plaintext (`enc_msg.len() - mic_size` bytes)
/// * `out_mic` — buffer to receive extracted MIC
/// * `mic_size` — MIC length (4 or 8)
///
/// Returns `true` on success.
pub fn mesh_crypto_aes_ccm_decrypt(
    nonce: &[u8; 13],
    key: &[u8; 16],
    aad: Option<&[u8]>,
    enc_msg: &[u8],
    out_msg: &mut [u8],
    out_mic: &mut [u8],
    mic_size: usize,
) -> bool {
    if enc_msg.len() < mic_size {
        return false;
    }

    let ct_len = enc_msg.len() - mic_size;

    if out_msg.len() < ct_len || out_mic.len() < mic_size {
        return false;
    }

    // Extract MIC
    out_mic[..mic_size].copy_from_slice(&enc_msg[ct_len..ct_len + mic_size]);

    // Copy ciphertext to output
    out_msg[..ct_len].copy_from_slice(&enc_msg[..ct_len]);

    let aad_bytes = aad.unwrap_or(&[]);

    match mic_size {
        4 => ccm_decrypt_inner::<ccm::consts::U4>(
            key,
            nonce,
            aad_bytes,
            out_msg,
            ct_len,
            &out_mic[..mic_size],
        ),
        8 => ccm_decrypt_inner::<ccm::consts::U8>(
            key,
            nonce,
            aad_bytes,
            out_msg,
            ct_len,
            &out_mic[..mic_size],
        ),
        _ => false,
    }
}

/// Generic CCM decryption helper parameterised on tag size.
fn ccm_decrypt_inner<TagSize>(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    buf: &mut [u8],
    ct_len: usize,
    mic: &[u8],
) -> bool
where
    TagSize: ccm::aead::generic_array::ArrayLength<u8> + ccm::TagSize,
{
    use ccm::aead::AeadInPlace;
    use ccm::aead::KeyInit as AeadKeyInit;
    use ccm::aead::generic_array::GenericArray;

    type AesCcm<T> = ccm::Ccm<Aes128, T, ccm::consts::U13>;

    let cipher = AesCcm::<TagSize>::new(GenericArray::from_slice(key));
    let nonce_ga = GenericArray::from_slice(nonce);
    let tag = GenericArray::from_slice(mic);

    cipher.decrypt_in_place_detached(nonce_ga, aad, &mut buf[..ct_len], tag).is_ok()
}

// ===========================================================================
// Phase 2 — Mesh Key Derivation Functions (KDFs)
// ===========================================================================

/// s1 salt generation: AES-CMAC(zero_key, info).
/// Mesh Profile spec Section 3.8.2.4.
pub fn mesh_crypto_s1(info: &[u8]) -> Option<[u8; 16]> {
    let zero = [0u8; 16];
    let mut result = [0u8; 16];
    if !aes_cmac_one(&zero, info, &mut result) {
        return None;
    }
    Some(result)
}

/// k1 key derivation: T = CMAC(salt, ikm); OKM = CMAC(T, info).
/// Mesh Profile spec Section 3.8.2.5.
pub fn mesh_crypto_k1(ikm: &[u8; 16], salt: &[u8; 16], info: &[u8]) -> Option<[u8; 16]> {
    let mut t = [0u8; 16];
    if !aes_cmac_one(salt, ikm, &mut t) {
        return None;
    }
    let mut okm = [0u8; 16];
    if !aes_cmac_one(&t, info, &mut okm) {
        return None;
    }
    Some(okm)
}

/// k2 key derivation: derives (net_id, enc_key, priv_key) from a network key.
/// Mesh Profile spec Section 3.8.2.6.
///
/// Returns `(nid, encryption_key, privacy_key)` on success.
pub fn mesh_crypto_k2(n: &[u8; 16], p: &[u8]) -> Option<(u8, [u8; 16], [u8; 16])> {
    let salt = mesh_crypto_s1(b"smk2")?;

    // T = AES-CMAC(salt, N)
    let mut t = [0u8; 16];
    if !aes_cmac_one(&salt, n, &mut t) {
        return None;
    }

    // --- Round 1: T1 = CMAC(T, P || 0x01) ---
    let mut stage = Vec::with_capacity(16 + p.len() + 1);
    stage.extend_from_slice(p);
    stage.push(0x01);

    let mut t1 = [0u8; 16];
    if !aes_cmac_one(&t, &stage, &mut t1) {
        return None;
    }

    // --- Round 2: T2 = CMAC(T, T1 || P || 0x02) ---
    stage.clear();
    stage.extend_from_slice(&t1);
    stage.extend_from_slice(p);
    stage.push(0x02);

    let mut t2 = [0u8; 16];
    if !aes_cmac_one(&t, &stage, &mut t2) {
        return None;
    }

    // --- Round 3: T3 = CMAC(T, T2 || P || 0x03) ---
    stage.clear();
    stage.extend_from_slice(&t2);
    stage.extend_from_slice(p);
    stage.push(0x03);

    let mut t3 = [0u8; 16];
    if !aes_cmac_one(&t, &stage, &mut t3) {
        return None;
    }

    let nid = t1[15] & 0x7f;
    Some((nid, t2, t3))
}

/// k3 key derivation: derives an 8-byte network ID from a network key.
/// Mesh Profile spec Section 3.8.2.7.
pub fn mesh_crypto_k3(n: &[u8; 16]) -> Option<[u8; 8]> {
    let salt = mesh_crypto_s1(b"smk3")?;

    let mut t = [0u8; 16];
    if !aes_cmac_one(&salt, n, &mut t) {
        return None;
    }

    // info = "id64" || 0x01
    let info: &[u8] = &[b'i', b'd', b'6', b'4', 0x01];
    let mut result = [0u8; 16];
    if !aes_cmac_one(&t, info, &mut result) {
        return None;
    }

    let mut out = [0u8; 8];
    out.copy_from_slice(&result[8..16]);
    Some(out)
}

/// k4 key derivation: derives a 6-bit AID from an application key.
/// Mesh Profile spec Section 3.8.2.8.
pub fn mesh_crypto_k4(a: &[u8; 16]) -> Option<u8> {
    let salt = mesh_crypto_s1(b"smk4")?;

    let mut t = [0u8; 16];
    if !aes_cmac_one(&salt, a, &mut t) {
        return None;
    }

    // info = "id6" || 0x01
    let info: &[u8] = &[b'i', b'd', b'6', 0x01];
    let mut result = [0u8; 16];
    if !aes_cmac_one(&t, info, &mut result) {
        return None;
    }

    Some(result[15] & 0x3f)
}

/// Internal helper: crypto_128(N, s) = k1(N, s1(s), "id128" || 0x01).
/// Used by nkik, nkbk, nkpk.
fn crypto_128(n: &[u8; 16], s: &str) -> Option<[u8; 16]> {
    let salt = mesh_crypto_s1(s.as_bytes())?;
    let info: &[u8] = &[b'i', b'd', b'1', b'2', b'8', 0x01];
    mesh_crypto_k1(n, &salt, info)
}

/// Derive the identity key from a network key.
pub fn mesh_crypto_nkik(n: &[u8; 16]) -> Option<[u8; 16]> {
    crypto_128(n, "nkik")
}

/// Derive the beacon key from a network key.
pub fn mesh_crypto_nkbk(n: &[u8; 16]) -> Option<[u8; 16]> {
    crypto_128(n, "nkbk")
}

/// Derive the private beacon key from a network key.
pub fn mesh_crypto_nkpk(n: &[u8; 16]) -> Option<[u8; 16]> {
    crypto_128(n, "nkpk")
}

// ===========================================================================
// Identity, Beacon, and Provisioning Crypto
// ===========================================================================

/// Compute a mesh identity value from a network key and unicast address.
///
/// If the last 8 bytes of `id` are zero, random bytes are generated.
/// The first 8 bytes of `id` are filled with the encrypted identity.
pub fn mesh_crypto_identity(net_key: &[u8; 16], addr: u16, id: &mut [u8; 16]) -> bool {
    let Some(identity_key) = mesh_crypto_nkik(net_key) else {
        return false;
    };

    // If last 8 bytes are all zero, generate random bytes
    if id[8..16].iter().all(|&b| b == 0) && random_bytes(&mut id[8..16]).is_err() {
        return false;
    }

    // Build plaintext: 6 zero bytes || hash (id[8..16]) || addr big-endian
    let mut plaintext = [0u8; 16];
    plaintext[6..14].copy_from_slice(&id[8..16]);
    plaintext[14..16].copy_from_slice(&addr.to_be_bytes());

    let Some(encrypted) = aes_ecb_one(&identity_key, &plaintext) else {
        return false;
    };

    // Copy encrypted[8..16] to id[0..8]
    id[0..8].copy_from_slice(&encrypted[8..16]);
    true
}

/// Compute beacon CMAC authentication.
///
/// Returns the first 8 bytes of the CMAC as a big-endian u64.
pub fn mesh_crypto_beacon_cmac(
    encryption_key: &[u8; 16],
    network_id: &[u8; 8],
    iv_index: u32,
    kr: bool,
    iu: bool,
) -> Option<u64> {
    // Build 13-byte message: flags || network_id || iv_index_be32
    let mut msg = [0u8; 13];
    let mut flags: u8 = 0;
    if kr {
        flags |= 0x01;
    }
    if iu {
        flags |= 0x02;
    }
    msg[0] = flags;
    msg[1..9].copy_from_slice(network_id);
    msg[9..13].copy_from_slice(&iv_index.to_be_bytes());

    let mut cmac_result = [0u8; 16];
    if !aes_cmac_one(encryption_key, &msg, &mut cmac_result) {
        return None;
    }

    let val = u64::from_be_bytes([
        cmac_result[0],
        cmac_result[1],
        cmac_result[2],
        cmac_result[3],
        cmac_result[4],
        cmac_result[5],
        cmac_result[6],
        cmac_result[7],
    ]);

    Some(val)
}

/// Provisioning salt derivation.
/// prov_salt = AES-CMAC(zero, conf_salt || prov_rand || dev_rand)
pub fn mesh_crypto_prov_prov_salt(
    conf_salt: &[u8; 16],
    prov_rand: &[u8; 16],
    dev_rand: &[u8; 16],
) -> Option<[u8; 16]> {
    let zero = [0u8; 16];
    let mut msg = [0u8; 48];
    msg[0..16].copy_from_slice(conf_salt);
    msg[16..32].copy_from_slice(prov_rand);
    msg[32..48].copy_from_slice(dev_rand);

    let mut result = [0u8; 16];
    if !aes_cmac_one(&zero, &msg, &mut result) {
        return None;
    }
    Some(result)
}

/// Provisioning confirmation key.
/// T = AES-CMAC(salt, secret), conf_key = AES-CMAC(T, "prck")
pub fn mesh_crypto_prov_conf_key(secret: &[u8; 32], salt: &[u8; 16]) -> Option<[u8; 16]> {
    let mut t = [0u8; 16];
    if !aes_cmac_one(salt, secret, &mut t) {
        return None;
    }
    let mut conf_key = [0u8; 16];
    if !aes_cmac_one(&t, b"prck", &mut conf_key) {
        return None;
    }
    Some(conf_key)
}

/// Provisioning session key.
/// T = AES-CMAC(salt, secret), session_key = AES-CMAC(T, "prsk")
pub fn mesh_crypto_session_key(secret: &[u8; 32], salt: &[u8; 16]) -> Option<[u8; 16]> {
    let mut t = [0u8; 16];
    if !aes_cmac_one(salt, secret, &mut t) {
        return None;
    }
    let mut session_key = [0u8; 16];
    if !aes_cmac_one(&t, b"prsk", &mut session_key) {
        return None;
    }
    Some(session_key)
}

/// Provisioning nonce (13 bytes).
/// T = AES-CMAC(salt, secret), tmp = AES-CMAC(T, "prsn"), return tmp[3..16]
pub fn mesh_crypto_nonce(secret: &[u8; 32], salt: &[u8; 16]) -> Option<[u8; 13]> {
    let mut t = [0u8; 16];
    if !aes_cmac_one(salt, secret, &mut t) {
        return None;
    }
    let mut tmp = [0u8; 16];
    if !aes_cmac_one(&t, b"prsn", &mut tmp) {
        return None;
    }
    let mut nonce = [0u8; 13];
    nonce.copy_from_slice(&tmp[3..16]);
    Some(nonce)
}

/// Device key derivation.
/// T = AES-CMAC(salt, secret), device_key = AES-CMAC(T, "prdk")
pub fn mesh_crypto_device_key(secret: &[u8; 32], salt: &[u8; 16]) -> Option<[u8; 16]> {
    let mut t = [0u8; 16];
    if !aes_cmac_one(salt, secret, &mut t) {
        return None;
    }
    let mut device_key = [0u8; 16];
    if !aes_cmac_one(&t, b"prdk", &mut device_key) {
        return None;
    }
    Some(device_key)
}

/// Virtual address computation.
/// salt = s1("vtad"), tmp = AES-CMAC(salt, label),
/// addr = (be16(tmp[14..16]) & 0x3fff) | 0x8000
pub fn mesh_crypto_virtual_addr(virtual_label: &[u8; 16]) -> Option<u16> {
    let salt = mesh_crypto_s1(b"vtad")?;
    let mut tmp = [0u8; 16];
    if !aes_cmac_one(&salt, virtual_label, &mut tmp) {
        return None;
    }
    let raw = u16::from_be_bytes([tmp[14], tmp[15]]);
    Some((raw & 0x3fff) | 0x8000)
}

// ===========================================================================
// Nonce Builders
// ===========================================================================

/// Build a 13-byte network nonce (type 0x00).
fn mesh_crypto_network_nonce(ctl: bool, ttl: u8, seq: u32, src: u16, iv_index: u32) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = 0x00; // type = network
    let ctl_ttl = if ctl { CTL | (ttl & TTL_MASK) } else { ttl & TTL_MASK };
    nonce[1] = ctl_ttl;

    let seq_bytes = seq.to_be_bytes();
    nonce[2] = seq_bytes[1];
    nonce[3] = seq_bytes[2];
    nonce[4] = seq_bytes[3];

    let src_bytes = src.to_be_bytes();
    nonce[5] = src_bytes[0];
    nonce[6] = src_bytes[1];

    nonce[7] = 0x00;
    nonce[8] = 0x00;

    let iv_bytes = iv_index.to_be_bytes();
    nonce[9] = iv_bytes[0];
    nonce[10] = iv_bytes[1];
    nonce[11] = iv_bytes[2];
    nonce[12] = iv_bytes[3];

    nonce
}

/// Build a 13-byte application nonce (type 0x01).
fn mesh_crypto_application_nonce(
    seq: u32,
    src: u16,
    dst: u16,
    iv_index: u32,
    aszmic: bool,
) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = 0x01;
    nonce[1] = if aszmic { 0x80 } else { 0x00 };

    let seq_bytes = seq.to_be_bytes();
    nonce[2] = seq_bytes[1];
    nonce[3] = seq_bytes[2];
    nonce[4] = seq_bytes[3];

    let src_bytes = src.to_be_bytes();
    nonce[5] = src_bytes[0];
    nonce[6] = src_bytes[1];

    let dst_bytes = dst.to_be_bytes();
    nonce[7] = dst_bytes[0];
    nonce[8] = dst_bytes[1];

    let iv_bytes = iv_index.to_be_bytes();
    nonce[9] = iv_bytes[0];
    nonce[10] = iv_bytes[1];
    nonce[11] = iv_bytes[2];
    nonce[12] = iv_bytes[3];

    nonce
}

/// Build a 13-byte device nonce (type 0x02).
fn mesh_crypto_device_nonce(seq: u32, src: u16, dst: u16, iv_index: u32, aszmic: bool) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = 0x02;
    nonce[1] = if aszmic { 0x80 } else { 0x00 };

    let seq_bytes = seq.to_be_bytes();
    nonce[2] = seq_bytes[1];
    nonce[3] = seq_bytes[2];
    nonce[4] = seq_bytes[3];

    let src_bytes = src.to_be_bytes();
    nonce[5] = src_bytes[0];
    nonce[6] = src_bytes[1];

    let dst_bytes = dst.to_be_bytes();
    nonce[7] = dst_bytes[0];
    nonce[8] = dst_bytes[1];

    let iv_bytes = iv_index.to_be_bytes();
    nonce[9] = iv_bytes[0];
    nonce[10] = iv_bytes[1];
    nonce[11] = iv_bytes[2];
    nonce[12] = iv_bytes[3];

    nonce
}

/// Build a 13-byte proxy nonce (type 0x03).
fn mesh_crypto_proxy_nonce(seq: u32, src: u16, iv_index: u32) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = 0x03;
    nonce[1] = 0x00;

    let seq_bytes = seq.to_be_bytes();
    nonce[2] = seq_bytes[1];
    nonce[3] = seq_bytes[2];
    nonce[4] = seq_bytes[3];

    let src_bytes = src.to_be_bytes();
    nonce[5] = src_bytes[0];
    nonce[6] = src_bytes[1];

    nonce[7] = 0x00;
    nonce[8] = 0x00;

    let iv_bytes = iv_index.to_be_bytes();
    nonce[9] = iv_bytes[0];
    nonce[10] = iv_bytes[1];
    nonce[11] = iv_bytes[2];
    nonce[12] = iv_bytes[3];

    nonce
}

// ===========================================================================
// Privacy Functions
// ===========================================================================

/// Build a 16-byte privacy counter for PECB computation.
/// Layout: [0; 5] || iv_index_be32 || payload[0..7]
fn privacy_counter(iv_index: u32, payload: &[u8]) -> [u8; 16] {
    let mut counter = [0u8; 16];
    // First 5 bytes are zero
    counter[5..9].copy_from_slice(&iv_index.to_be_bytes());
    let copy_len = payload.len().min(7);
    counter[9..9 + copy_len].copy_from_slice(&payload[..copy_len]);
    counter
}

/// Compute the Privacy ECB (PECB) value: AES-ECB(privacy_key, privacy_counter).
fn pecb(privacy_key: &[u8; 16], iv_index: u32, payload: &[u8]) -> Option<[u8; 16]> {
    let counter = privacy_counter(iv_index, payload);
    aes_ecb_one(privacy_key, &counter)
}

/// Obfuscate the network header in a packet.
///
/// XORs packet[1..7] (the 6-byte network header: CTL/TTL, SEQ, SRC)
/// with PECB[0..6].
pub fn mesh_crypto_network_obfuscate(
    packet: &mut [u8],
    privacy_key: &[u8; 16],
    iv_index: u32,
    ctl: bool,
    ttl: u8,
    seq: u32,
    src: u16,
) -> bool {
    if packet.len() < 7 {
        return false;
    }

    // Build the 6-byte network header
    let mut net_hdr = [0u8; 6];
    net_hdr[0] = if ctl { CTL | (ttl & TTL_MASK) } else { ttl & TTL_MASK };
    let seq_bytes = seq.to_be_bytes();
    net_hdr[1] = seq_bytes[1];
    net_hdr[2] = seq_bytes[2];
    net_hdr[3] = seq_bytes[3];
    let src_bytes = src.to_be_bytes();
    net_hdr[4] = src_bytes[0];
    net_hdr[5] = src_bytes[1];

    // Compute PECB using the encrypted payload portion (starting at packet[7])
    let Some(pecb_val) = pecb(privacy_key, iv_index, &packet[7..]) else {
        return false;
    };

    // XOR net_hdr with PECB and write to packet[1..7]
    for i in 0..6 {
        packet[1 + i] = net_hdr[i] ^ pecb_val[i];
    }

    true
}

/// Clarify (de-obfuscate) the network header from a packet.
///
/// Returns `(ctl, ttl, seq, src)` on success.
pub fn mesh_crypto_network_clarify(
    packet: &mut [u8],
    privacy_key: &[u8; 16],
    iv_index: u32,
) -> Option<(bool, u8, u32, u16)> {
    if packet.len() < 7 {
        return None;
    }

    // Compute PECB using the encrypted payload portion (starting at packet[7])
    let pecb_val = pecb(privacy_key, iv_index, &packet[7..])?;

    // XOR packet[1..7] with PECB to reveal the network header
    for i in 0..6 {
        packet[1 + i] ^= pecb_val[i];
    }

    // Parse the clarified header
    let ctl = (packet[1] & CTL) != 0;
    let ttl = packet[1] & TTL_MASK;
    let seq = u32::from_be_bytes([0, packet[2], packet[3], packet[4]]);
    let src = u16::from_be_bytes([packet[5], packet[6]]);

    Some((ctl, ttl, seq, src))
}

// ===========================================================================
// Packet Build / Parse
// ===========================================================================

/// Parameters for building a mesh network PDU.
pub struct MeshPacketBuildParams<'a> {
    /// Control message flag.
    pub ctl: bool,
    /// Time-to-live (7 bits).
    pub ttl: u8,
    /// Sequence number (24-bit).
    pub seq: u32,
    /// Source address.
    pub src: u16,
    /// Destination address.
    pub dst: u16,
    /// Transport opcode (for control messages) or zero.
    pub opcode: u8,
    /// Whether the payload is segmented.
    pub segmented: bool,
    /// Application key AID (0 for device key).
    pub key_aid: u8,
    /// Size of MIC indicator.
    pub szmic: bool,
    /// Relay flag.
    pub relay: bool,
    /// Sequence zero (13 bits).
    pub seq_zero: u16,
    /// Segment offset.
    pub seg_o: u8,
    /// Last segment number.
    pub seg_n: u8,
    /// Upper transport payload bytes.
    pub payload: &'a [u8],
}

/// Build a raw mesh network PDU.
///
/// Returns `(packet_data, packet_length)` on success.
pub fn mesh_crypto_packet_build(params: &MeshPacketBuildParams<'_>) -> Option<(Vec<u8>, u8)> {
    let MeshPacketBuildParams {
        ctl,
        ttl,
        seq,
        src,
        dst,
        opcode,
        segmented,
        key_aid,
        szmic,
        relay,
        seq_zero,
        seg_o,
        seg_n,
        payload,
    } = *params;
    let mut packet = vec![0u8; 29 + payload.len()];

    packet[1] = if ctl { CTL | (ttl & TTL_MASK) } else { ttl & TTL_MASK };
    let seq_bytes = seq.to_be_bytes();
    packet[2] = seq_bytes[1];
    packet[3] = seq_bytes[2];
    packet[4] = seq_bytes[3];
    let src_bytes = src.to_be_bytes();
    packet[5] = src_bytes[0];
    packet[6] = src_bytes[1];
    let dst_bytes = dst.to_be_bytes();
    packet[7] = dst_bytes[0];
    packet[8] = dst_bytes[1];

    let hdr_len: usize;
    let mic_size: usize = if ctl { 8 } else { 4 };

    if ctl {
        if segmented {
            let mut hdr: u32 = 1u32 << SEG_HDR_SHIFT;
            hdr |= (opcode as u32 & OPCODE_MASK) << KEY_HDR_SHIFT;
            if szmic {
                hdr |= 1u32 << SZMIC_HDR_SHIFT;
            }
            if relay {
                hdr |= 1u32 << RELAY_HDR_SHIFT;
            }
            hdr |= (seq_zero as u32 & SEQ_ZERO_MASK) << SEQ_ZERO_HDR_SHIFT;
            hdr |= (seg_o as u32 & SEG_MASK) << SEGO_HDR_SHIFT;
            hdr |= (seg_n as u32 & SEG_MASK) << SEGN_HDR_SHIFT;
            let hdr_bytes = hdr.to_be_bytes();
            packet[9..13].copy_from_slice(&hdr_bytes);
            hdr_len = 4;
        } else {
            packet[9] = opcode & (OPCODE_MASK as u8);
            hdr_len = 1;
        }
    } else if segmented {
        let mut hdr: u32 = 1u32 << SEG_HDR_SHIFT;
        hdr |= (key_aid as u32 & KEY_ID_MASK) << KEY_HDR_SHIFT;
        if szmic {
            hdr |= 1u32 << SZMIC_HDR_SHIFT;
        }
        if relay {
            hdr |= 1u32 << RELAY_HDR_SHIFT;
        }
        hdr |= (seq_zero as u32 & SEQ_ZERO_MASK) << SEQ_ZERO_HDR_SHIFT;
        hdr |= (seg_o as u32 & SEG_MASK) << SEGO_HDR_SHIFT;
        hdr |= (seg_n as u32 & SEG_MASK) << SEGN_HDR_SHIFT;
        let hdr_bytes = hdr.to_be_bytes();
        packet[9..13].copy_from_slice(&hdr_bytes);
        hdr_len = 4;
    } else {
        packet[9] = key_aid & KEY_AID_MASK;
        hdr_len = 1;
    }

    let payload_offset = 9 + hdr_len;
    if payload_offset + payload.len() + mic_size > packet.len() {
        packet.resize(payload_offset + payload.len() + mic_size, 0);
    }
    packet[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    let total_len = payload_offset + payload.len() + mic_size;
    packet.truncate(total_len);

    Some((packet, total_len as u8))
}

/// Parse the network header portion (private helper).
fn network_header_parse(packet: &[u8]) -> Option<(bool, u8, u32, u16)> {
    if packet.len() < 7 {
        return None;
    }
    let ctl = (packet[1] & CTL) != 0;
    let ttl = packet[1] & TTL_MASK;
    let seq = u32::from_be_bytes([0, packet[2], packet[3], packet[4]]);
    let src = u16::from_be_bytes([packet[5], packet[6]]);
    Some((ctl, ttl, seq, src))
}

/// Parse a mesh network PDU into structured fields.
pub fn mesh_crypto_packet_parse(packet: &[u8]) -> Option<PacketFields> {
    if packet.len() < 14 {
        return None;
    }
    let (ctl, ttl, seq, src) = network_header_parse(packet)?;
    let dst = u16::from_be_bytes([packet[7], packet[8]]);
    let mic_size: usize = if ctl { 8 } else { 4 };
    let hdr32 = u32::from_be_bytes([packet[9], packet[10], packet[11], packet[12]]);
    let segmented = (hdr32 >> SEG_HDR_SHIFT) & 1 == 1;

    let mut fields = PacketFields {
        ctl,
        ttl,
        seq,
        src,
        dst,
        cookie: 0,
        opcode: 0,
        segmented,
        key_aid: 0,
        szmic: false,
        relay: false,
        seq_zero: 0,
        seg_o: 0,
        seg_n: 0,
        payload: Vec::new(),
        payload_len: 0,
    };

    if ctl {
        if segmented {
            fields.opcode = ((hdr32 >> KEY_HDR_SHIFT) & OPCODE_MASK) as u8;
            fields.szmic = ((hdr32 >> SZMIC_HDR_SHIFT) & 1) == 1;
            fields.relay = (hdr32 >> RELAY_HDR_SHIFT) & 1 == 1;
            fields.seq_zero = ((hdr32 >> SEQ_ZERO_HDR_SHIFT) & SEQ_ZERO_MASK) as u16;
            fields.seg_o = ((hdr32 >> SEGO_HDR_SHIFT) & SEG_MASK) as u8;
            fields.seg_n = ((hdr32 >> SEGN_HDR_SHIFT) & SEG_MASK) as u8;
            let pe = packet.len().saturating_sub(mic_size);
            if pe > 13 {
                fields.payload = packet[13..pe].to_vec();
                fields.payload_len = fields.payload.len();
            }
        } else {
            fields.opcode = packet[9] & (OPCODE_MASK as u8);
            if fields.opcode == NET_OP_SEG_ACKNOWLEDGE && packet.len() >= 14 {
                let ah = u32::from_be_bytes([packet[10], packet[11], packet[12], packet[13]]);
                fields.relay = (ah >> RELAY_HDR_SHIFT) & 1 == 1;
                fields.seq_zero = ((ah >> SEQ_ZERO_HDR_SHIFT) & SEQ_ZERO_MASK) as u16;
            }
            let pe = packet.len().saturating_sub(mic_size);
            if pe > 10 {
                fields.payload = packet[10..pe].to_vec();
                fields.payload_len = fields.payload.len();
            }
        }
    } else if segmented {
        fields.key_aid = ((hdr32 >> KEY_HDR_SHIFT) & KEY_ID_MASK) as u8;
        fields.szmic = ((hdr32 >> SZMIC_HDR_SHIFT) & 1) == 1;
        fields.relay = (hdr32 >> RELAY_HDR_SHIFT) & 1 == 1;
        fields.seq_zero = ((hdr32 >> SEQ_ZERO_HDR_SHIFT) & SEQ_ZERO_MASK) as u16;
        fields.seg_o = ((hdr32 >> SEGO_HDR_SHIFT) & SEG_MASK) as u8;
        fields.seg_n = ((hdr32 >> SEGN_HDR_SHIFT) & SEG_MASK) as u8;
        let pe = packet.len().saturating_sub(mic_size);
        if pe > 13 {
            fields.payload = packet[13..pe].to_vec();
            fields.payload_len = fields.payload.len();
        }
    } else {
        fields.key_aid = packet[9] & KEY_AID_MASK;
        let pe = packet.len().saturating_sub(mic_size);
        if pe > 10 {
            fields.payload = packet[10..pe].to_vec();
            fields.payload_len = fields.payload.len();
        }
    }
    Some(fields)
}

// ===========================================================================
// Payload Encrypt / Decrypt
// ===========================================================================

/// Parameters for mesh payload encryption.
pub struct MeshPayloadEncryptParams<'a> {
    /// Additional authenticated data.
    pub aad: Option<&'a [u8]>,
    /// Plaintext payload.
    pub payload: &'a [u8],
    /// Output buffer (must be large enough for payload + MIC).
    pub out: &'a mut [u8],
    /// Source address.
    pub src: u16,
    /// Destination address.
    pub dst: u16,
    /// Application key AID (0 for device key).
    pub key_aid: u8,
    /// Sequence number.
    pub seq: u32,
    /// IV index.
    pub iv_index: u32,
    /// Size of MIC indicator.
    pub aszmic: bool,
    /// Application or device key.
    pub app_key: &'a [u8; 16],
}

/// Encrypt a mesh application/device payload.
pub fn mesh_crypto_payload_encrypt(params: &mut MeshPayloadEncryptParams<'_>) -> bool {
    let aad = params.aad;
    let payload = params.payload;
    let src = params.src;
    let dst = params.dst;
    let key_aid = params.key_aid;
    let seq = params.seq;
    let iv_index = params.iv_index;
    let aszmic = params.aszmic;
    let app_key = params.app_key;
    let mic_size: usize = if aszmic { 8 } else { 4 };
    if params.out.len() < payload.len() + mic_size {
        return false;
    }
    let nonce = if key_aid == APP_AID_DEV {
        mesh_crypto_device_nonce(seq, src, dst, iv_index, aszmic)
    } else {
        mesh_crypto_application_nonce(seq, src, dst, iv_index, aszmic)
    };
    mesh_crypto_aes_ccm_encrypt(&nonce, app_key, aad, payload, params.out, mic_size)
}

/// Parameters for mesh payload decryption.
pub struct MeshPayloadDecryptParams<'a> {
    /// Additional authenticated data.
    pub aad: Option<&'a [u8]>,
    /// Ciphertext payload (including MIC).
    pub payload: &'a [u8],
    /// Size of MIC indicator.
    pub aszmic: bool,
    /// Source address.
    pub src: u16,
    /// Destination address.
    pub dst: u16,
    /// Application key AID (0 for device key).
    pub key_aid: u8,
    /// Sequence number.
    pub seq: u32,
    /// IV index.
    pub iv_index: u32,
    /// Output buffer for decrypted plaintext.
    pub out: &'a mut [u8],
    /// Application or device key.
    pub app_key: &'a [u8; 16],
}

/// Decrypt a mesh application/device payload.
pub fn mesh_crypto_payload_decrypt(params: &mut MeshPayloadDecryptParams<'_>) -> bool {
    let mic_size: usize = if params.aszmic { 8 } else { 4 };
    if params.payload.len() < mic_size {
        return false;
    }
    let pt_len = params.payload.len() - mic_size;
    if params.out.len() < pt_len {
        return false;
    }
    let nonce = if params.key_aid == APP_AID_DEV {
        mesh_crypto_device_nonce(params.seq, params.src, params.dst, params.iv_index, params.aszmic)
    } else {
        mesh_crypto_application_nonce(
            params.seq,
            params.src,
            params.dst,
            params.iv_index,
            params.aszmic,
        )
    };
    let mut mic_buf = [0u8; 8];
    mesh_crypto_aes_ccm_decrypt(
        &nonce,
        params.app_key,
        params.aad,
        params.payload,
        params.out,
        &mut mic_buf,
        mic_size,
    )
}

// ===========================================================================
// Packet Encrypt / Decrypt (Network Layer)
// ===========================================================================

/// Encrypt a network PDU (private helper).
fn mesh_crypto_packet_encrypt(
    packet: &mut [u8],
    packet_len: usize,
    iv_index: u32,
    enc_key: &[u8; 16],
    privacy_key: &[u8; 16],
    proxy: bool,
) -> bool {
    if packet_len < 14 {
        return false;
    }
    let Some((ctl, ttl, seq, src)) = network_header_parse(packet) else {
        return false;
    };
    let mic_size: usize = if ctl { 8 } else { 4 };
    let nonce = if ctl && proxy {
        mesh_crypto_proxy_nonce(seq, src, iv_index)
    } else {
        mesh_crypto_network_nonce(ctl, ttl, seq, src, iv_index)
    };

    let enc_start = 7;
    let pt_end = packet_len - mic_size;
    if pt_end <= enc_start {
        return false;
    }
    let pt_len = pt_end - enc_start;
    let plaintext: Vec<u8> = packet[enc_start..pt_end].to_vec();

    if !mesh_crypto_aes_ccm_encrypt(
        &nonce,
        enc_key,
        None,
        &plaintext,
        &mut packet[enc_start..enc_start + pt_len + mic_size],
        mic_size,
    ) {
        return false;
    }
    mesh_crypto_network_obfuscate(packet, privacy_key, iv_index, ctl, ttl, seq, src)
}

/// Decrypt a network PDU (private helper).
fn mesh_crypto_packet_decrypt(
    packet: &mut [u8],
    packet_len: usize,
    proxy: bool,
    iv_index: u32,
    enc_key: &[u8; 16],
    privacy_key: &[u8; 16],
) -> bool {
    if packet_len < 14 {
        return false;
    }
    let Some((ctl, _ttl, seq, src)) = mesh_crypto_network_clarify(packet, privacy_key, iv_index)
    else {
        return false;
    };
    if !is_unicast(src) {
        return false;
    }
    let ttl = packet[1] & TTL_MASK;
    let mic_size: usize = if ctl { 8 } else { 4 };
    let nonce = if ctl && proxy {
        mesh_crypto_proxy_nonce(seq, src, iv_index)
    } else {
        mesh_crypto_network_nonce(ctl, ttl, seq, src, iv_index)
    };

    let enc_start = 7;
    let enc_end = packet_len;
    if enc_end <= enc_start + mic_size {
        return false;
    }
    let encrypted: Vec<u8> = packet[enc_start..enc_end].to_vec();
    let ct_len = encrypted.len() - mic_size;
    let mut mic_buf = [0u8; 8];

    mesh_crypto_aes_ccm_decrypt(
        &nonce,
        enc_key,
        None,
        &encrypted,
        &mut packet[enc_start..enc_start + ct_len],
        &mut mic_buf,
        mic_size,
    )
}

/// Encode (encrypt + obfuscate) a mesh network packet.
pub fn mesh_crypto_packet_encode(
    packet: &mut [u8],
    iv_index: u32,
    enc_key: &[u8; 16],
    privacy_key: &[u8; 16],
) -> bool {
    let packet_len = packet.len();
    mesh_crypto_packet_encrypt(packet, packet_len, iv_index, enc_key, privacy_key, false)
}

/// Decode (clarify + decrypt) a mesh network packet.
pub fn mesh_crypto_packet_decode(
    packet: &[u8],
    proxy: bool,
    out: &mut [u8],
    iv_index: u32,
    enc_key: &[u8; 16],
    privacy_key: &[u8; 16],
) -> bool {
    let packet_len = packet.len();
    if packet_len < 14 || out.len() < packet_len {
        return false;
    }
    out[..packet_len].copy_from_slice(packet);
    mesh_crypto_packet_decrypt(out, packet_len, proxy, iv_index, enc_key, privacy_key)
}

// ===========================================================================
// Packet Label
// ===========================================================================

/// Set the IVI and NID fields in the first byte of a network packet.
pub fn mesh_crypto_packet_label(packet: &mut [u8], iv_index: u16, network_id: u8) -> bool {
    if packet.is_empty() {
        return false;
    }
    let ivi = ((iv_index & 0x0001) as u8) << 7;
    let nid = network_id & 0x7f;
    packet[0] = ivi | nid;
    true
}

// ===========================================================================
// FCS / CRC
// ===========================================================================

/// Compute the Frame Check Sequence (FCS) over a packet.
pub fn mesh_crypto_compute_fcs(packet: &[u8]) -> u8 {
    let mut fcs: u8 = 0xff;
    for &byte in packet {
        fcs = CRC_TABLE[(fcs ^ byte) as usize];
    }
    0xff_u8.wrapping_sub(fcs)
}

/// Verify the FCS of a packet.
pub fn mesh_crypto_check_fcs(packet: &[u8], received_fcs: u8) -> bool {
    let mut fcs: u8 = 0xff;
    for &byte in packet {
        fcs = CRC_TABLE[(fcs ^ byte) as usize];
    }
    fcs = CRC_TABLE[(fcs ^ received_fcs) as usize];
    fcs == 0xcf
}

// ===========================================================================
// Runtime Self-Test
// ===========================================================================

/// Runtime self-test that validates AES-CCM functionality.
pub fn mesh_crypto_check_avail() -> bool {
    debug!("Testing Crypto");

    let mut test_bytes = [0u8; 73];
    for (i, byte) in test_bytes.iter_mut().enumerate() {
        *byte = (0x60 + i) as u8;
    }

    let key: &[u8; 16] = test_bytes[0..16].try_into().unwrap();
    let aad: &[u8] = &test_bytes[16..32];
    let nonce: &[u8; 13] = test_bytes[32..45].try_into().unwrap();
    let data: &[u8] = &test_bytes[45..65];

    let mut output = [0u8; 28];
    if !mesh_crypto_aes_ccm_encrypt(nonce, key, Some(aad), data, &mut output, 8) {
        return false;
    }
    output == CRYPTO_TEST_RESULT
}
