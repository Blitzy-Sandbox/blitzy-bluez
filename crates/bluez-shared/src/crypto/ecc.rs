// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — P-256 Elliptic Curve Cryptography for LE Secure Connections
//
// Copyright 2024 BlueZ Project

//! P-256 Elliptic Curve Cryptography for Bluetooth LE Secure Connections.
//!
//! This module provides NIST P-256 (secp256r1) elliptic curve operations
//! required by the Bluetooth Core Specification for LE Secure Connections
//! pairing. It replaces the original hand-written software P-256
//! implementation from BlueZ's `src/shared/ecc.c` — approximately 800 lines
//! of big-number arithmetic (VLI operations: add, subtract, multiply, square,
//! modular inverse), modular arithmetic over the P-256 prime field, and
//! elliptic curve point operations (addition, doubling, scalar multiplication)
//! — with the audited [`p256`] crate from RustCrypto.
//!
//! The `p256` crate provides:
//!
//! - **Constant-time scalar operations** resistant to timing side-channels
//!   (replacing the C code's manual random-Z blinding in `ecc_point_mult`)
//! - **Hardware-accelerated point multiplication** where available
//! - **Validated P-256 curve operations** following NIST FIPS 186-4
//!
//! # Byte Order Convention
//!
//! The BlueZ Bluetooth stack uses **LSB-first (little-endian)** byte
//! representation for all ECC key material and shared secrets, matching the
//! Bluetooth Core Specification's byte ordering. Standard cryptographic
//! libraries (including `p256` and `ring`) use **MSB-first (big-endian)**
//! representation (SEC1 format for public keys).
//!
//! All public API functions in this module accept and return data in BlueZ's
//! LSB-first format. Internal conversion to/from standard SEC1/big-endian
//! format is performed transparently by the byte-order helper functions.
//!
//! - **Private key**: 32 bytes, LSB first (scalar value)
//! - **Public key**: 64 bytes = X (32 bytes LSB first) ‖ Y (32 bytes LSB first)
//! - **Shared secret**: 32 bytes, LSB first (ECDH x-coordinate)
//!
//! # Design Decision: `p256` crate over `ring` for ECC
//!
//! The `ring` crate's [`ring::agreement::EphemeralPrivateKey`] deliberately
//! does not expose raw private key bytes, as a deliberate security design
//! choice. However, the BlueZ HCI layer requires raw 32-byte private key
//! material for controller-side LE Secure Connections pairing operations
//! (the controller needs the raw scalar for its own ECDH computation).
//!
//! The `p256` crate from RustCrypto provides the same NIST P-256 curve
//! operations while supporting raw key material access through
//! [`p256::SecretKey::to_bytes()`] and [`p256::SecretKey::from_slice()`].
//! Random number generation still uses [`ring::rand::SystemRandom`] for
//! cryptographic random byte generation, replacing the C code's direct
//! `/dev/urandom` reads via `get_random_number()`.
//!
//! # Safety
//!
//! This module contains zero `unsafe` blocks. All cryptographic operations
//! are performed through safe Rust APIs provided by the `p256` and `ring`
//! crates.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

/// Maximum number of key generation attempts before reporting failure.
///
/// Mirrors the `MAX_TRIES` constant from `ecc.c` line 32. Each attempt
/// generates 32 random bytes and checks whether they form a valid P-256
/// scalar (non-zero and less than the curve order n). The probability of
/// 16 consecutive invalid scalars is astronomically low (~2^-2048 for the
/// zero check, and ~2^-128 for the range check since n ≈ 2^256) but this
/// provides a deterministic termination guarantee.
const MAX_TRIES: u32 = 16;

/// Errors that can occur during P-256 elliptic curve operations.
///
/// Replaces the C code's `bool` return values with typed error variants
/// for idiomatic Rust error propagation via `Result<T, EccError>`.
#[derive(Debug, Error)]
pub enum EccError {
    /// Key pair generation failed after [`MAX_TRIES`] retry attempts.
    ///
    /// This can occur if the cryptographic random number generator
    /// consistently produces values outside the valid scalar range [1, n-1],
    /// which is astronomically unlikely under normal operation.
    #[error("Key generation failed")]
    KeyGeneration,

    /// The provided public key does not represent a valid point on the
    /// P-256 curve.
    ///
    /// Validation checks (performed by `p256::PublicKey::from_sec1_bytes`):
    /// - Point is not the point at infinity
    /// - X and Y coordinates are in the range [0, p)
    /// - Point satisfies the curve equation y² = x³ + ax + b (mod p)
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// ECDH shared secret computation failed.
    ///
    /// This typically indicates an invalid private key scalar (zero or
    /// outside the valid range [1, n-1]), or the resulting point is the
    /// point at infinity.
    #[error("ECDH shared secret computation failed")]
    SharedSecret,

    /// Cryptographic random number generation failed.
    ///
    /// Indicates a failure in the operating system's entropy source,
    /// accessed via `ring::rand::SystemRandom`.
    #[error("Random number generation failed")]
    RandomError,
}

/// Reverse a 32-byte array to convert between LSB-first (BlueZ/Bluetooth)
/// and MSB-first (SEC1/standard crypto) byte representations.
///
/// This is the scalar equivalent of the C code's `ecc_bytes2native()` and
/// `ecc_native2bytes()` functions (ecc.c lines 802-840), which convert
/// between little-endian byte arrays and native `uint64_t[4]` words. Since
/// the `p256` crate works with big-endian byte arrays (SEC1 format), a
/// simple byte reversal achieves the same conversion.
fn reverse_bytes_32(input: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = input[31 - i];
    }
    output
}

/// Convert a BlueZ LSB-first public key (64 bytes) to SEC1 uncompressed
/// format (65 bytes).
///
/// BlueZ format: `X_LE[0..32] ‖ Y_LE[0..32]` (64 bytes, each coordinate
/// in little-endian byte order).
///
/// SEC1 uncompressed format: `0x04 ‖ X_BE[0..32] ‖ Y_BE[0..32]` (65 bytes,
/// with the uncompressed point marker byte and each coordinate in big-endian
/// byte order).
///
/// The conversion reverses each 32-byte coordinate independently and
/// prepends the `0x04` marker byte.
fn bluez_pubkey_to_sec1(bluez_pk: &[u8; 64]) -> [u8; 65] {
    let mut sec1 = [0u8; 65];
    // SEC1 uncompressed point format marker
    sec1[0] = 0x04;

    // Reverse X coordinate: BlueZ LE → SEC1 BE
    for i in 0..32 {
        sec1[1 + i] = bluez_pk[31 - i];
    }

    // Reverse Y coordinate: BlueZ LE → SEC1 BE
    for i in 0..32 {
        sec1[33 + i] = bluez_pk[63 - i];
    }

    sec1
}

/// Convert a SEC1 uncompressed public key (65 bytes) or encoded point to
/// BlueZ LSB-first format (64 bytes).
///
/// Input must be at least 65 bytes in SEC1 uncompressed format:
/// `0x04 ‖ X_BE[0..32] ‖ Y_BE[0..32]`.
///
/// Output is the BlueZ format: `X_LE[0..32] ‖ Y_LE[0..32]` (64 bytes).
///
/// Skips the `0x04` marker byte and reverses each 32-byte coordinate.
fn sec1_pubkey_to_bluez(sec1_pk: &[u8]) -> [u8; 64] {
    let mut bluez = [0u8; 64];

    // Reverse X coordinate: SEC1 BE sec1_pk[1..33] → BlueZ LE bluez[0..32]
    for i in 0..32 {
        bluez[i] = sec1_pk[32 - i];
    }

    // Reverse Y coordinate: SEC1 BE sec1_pk[33..65] → BlueZ LE bluez[32..64]
    for i in 0..32 {
        bluez[32 + i] = sec1_pk[64 - i];
    }

    bluez
}

/// Generate a new P-256 key pair for LE Secure Connections.
///
/// Returns a tuple `(public_key, private_key)` where both values use
/// BlueZ's LSB-first byte representation:
/// - `public_key`: 64 bytes = X (32 bytes LE) ‖ Y (32 bytes LE)
/// - `private_key`: 32 bytes LE scalar
///
/// # Algorithm
///
/// 1. Generate 32 cryptographically random bytes via `ring::rand::SystemRandom`
/// 2. Attempt to interpret them as a valid P-256 scalar (must be in [1, n-1])
/// 3. If invalid, retry (up to [`MAX_TRIES`] attempts)
/// 4. Derive the public key via scalar multiplication: `Q = d × G`
/// 5. Convert both keys to BlueZ LSB-first format
///
/// This replaces the C implementation at ecc.c lines 867-894 which used
/// `/dev/urandom` directly and the hand-written `ecc_point_mult` function.
///
/// # Errors
///
/// - [`EccError::RandomError`] if the system random number generator fails
/// - [`EccError::KeyGeneration`] if no valid scalar is found after
///   [`MAX_TRIES`] attempts (astronomically unlikely)
pub fn ecc_make_key() -> Result<([u8; 64], [u8; 32]), EccError> {
    let rng = SystemRandom::new();

    for _ in 0..MAX_TRIES {
        // Generate 32 random bytes to use as a candidate private key scalar.
        // These bytes are interpreted in big-endian order by the p256 crate.
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes).map_err(|_| EccError::RandomError)?;

        // Attempt to create a valid P-256 secret key from the random bytes.
        // from_slice validates that the scalar is non-zero and less than n.
        // This mirrors the C code's checks: vli_is_zero(priv) and
        // vli_cmp(curve_n, priv) != 1
        let secret_key = match p256::SecretKey::from_slice(&random_bytes) {
            Ok(sk) => sk,
            Err(_) => continue,
        };

        // Derive the public key: Q = d × G (base point multiplication)
        let public_key = secret_key.public_key();
        let encoded_point: p256::EncodedPoint = public_key.to_encoded_point(false);

        // Extract raw private key bytes (big-endian) and convert to BlueZ LE
        let private_key_msb = secret_key.to_bytes();
        let mut msb_arr = [0u8; 32];
        msb_arr.copy_from_slice(&private_key_msb);
        let private_key_bluez = reverse_bytes_32(&msb_arr);

        // Convert public key from SEC1 uncompressed to BlueZ LE format
        let public_key_bluez = sec1_pubkey_to_bluez(encoded_point.as_bytes());

        return Ok((public_key_bluez, private_key_bluez));
    }

    Err(EccError::KeyGeneration)
}

/// Derive a P-256 public key from a private key.
///
/// Given a 32-byte private key scalar in BlueZ LSB-first format, computes
/// the corresponding public key point `Q = d × G` and returns it as a
/// 64-byte BlueZ LSB-first public key.
///
/// This replaces the C implementation at ecc.c lines 842-865 which used
/// `ecc_bytes2native` for byte-order conversion and `ecc_point_mult` for
/// scalar multiplication with the P-256 generator point.
///
/// # Arguments
///
/// * `private_key` — 32-byte private key scalar in LSB-first format
///
/// # Returns
///
/// 64-byte public key in BlueZ LSB-first format: X (32 bytes LE) ‖ Y (32 bytes LE)
///
/// # Errors
///
/// - [`EccError::KeyGeneration`] if the private key is zero, out of range
///   [1, n-1], or produces the point at infinity
pub fn ecc_make_public_key(private_key: &[u8; 32]) -> Result<[u8; 64], EccError> {
    // Convert private key from BlueZ LSB-first to MSB-first (big-endian)
    // for the p256 crate. This mirrors ecc_bytes2native() from ecc.c.
    let msb_private = reverse_bytes_32(private_key);

    // Create a SecretKey from the big-endian scalar bytes.
    // This validates that the scalar is non-zero and in [1, n-1],
    // equivalent to the C code's vli_is_zero + vli_cmp checks.
    let secret_key =
        p256::SecretKey::from_slice(&msb_private).map_err(|_| EccError::KeyGeneration)?;

    // Derive public key: Q = d × G (base point scalar multiplication)
    let public_key = secret_key.public_key();
    let encoded_point: p256::EncodedPoint = public_key.to_encoded_point(false);

    // Convert from SEC1 uncompressed format to BlueZ LSB-first format.
    // This mirrors ecc_native2bytes() for pk.x and pk.y from ecc.c.
    Ok(sec1_pubkey_to_bluez(encoded_point.as_bytes()))
}

/// Validate that a public key represents a valid point on the P-256 curve.
///
/// Performs full point validation including:
/// - Point is not the point at infinity
/// - X and Y coordinates are in the valid range [0, p)
/// - Point satisfies the P-256 curve equation: y² ≡ x³ + ax + b (mod p)
///
/// This replaces the C implementation at ecc.c lines 896-904 which used
/// `ecc_bytes2native` for byte conversion and `ecc_valid_point` (lines
/// 775-800) for the mathematical validation checks.
///
/// # Arguments
///
/// * `public_key` — 64-byte public key in BlueZ LSB-first format
///
/// # Returns
///
/// `true` if the public key is a valid P-256 curve point, `false` otherwise.
pub fn ecc_valid_public_key(public_key: &[u8; 64]) -> bool {
    // Convert from BlueZ LSB-first format to SEC1 uncompressed format
    let sec1 = bluez_pubkey_to_sec1(public_key);

    // p256::PublicKey::from_sec1_bytes performs complete point validation:
    // checks that the point is not at infinity, coordinates are in range,
    // and the point lies on the curve. This is equivalent to the C code's
    // ecc_valid_point() function which checks ecc_point_is_zero,
    // vli_cmp(point->x, curve_p), vli_cmp(point->y, curve_p), and
    // verifies y² = x³ + ax + b mod p.
    p256::PublicKey::from_sec1_bytes(&sec1).is_ok()
}

/// Compute an ECDH shared secret from a peer's public key and our private key.
///
/// Performs P-256 Elliptic Curve Diffie-Hellman key agreement. The shared
/// secret is the x-coordinate of the resulting point: `S = (d × Q).x`,
/// where `d` is our private key scalar and `Q` is the peer's public key
/// point.
///
/// All inputs and the output use BlueZ's LSB-first byte representation.
///
/// This replaces the C implementation at ecc.c lines 906-930 which used
/// `ecc_bytes2native` for byte conversion, `ecc_valid_point` for public
/// key validation, and `ecc_point_mult` with a random blinding factor for
/// timing side-channel protection. The `p256` crate handles constant-time
/// operations internally.
///
/// # Arguments
///
/// * `public_key` — Peer's 64-byte public key in LSB-first format
/// * `private_key` — Our 32-byte private key scalar in LSB-first format
///
/// # Returns
///
/// 32-byte shared secret (ECDH x-coordinate) in LSB-first format.
///
/// # Errors
///
/// - [`EccError::InvalidPublicKey`] if the peer's public key is not on the curve
/// - [`EccError::SharedSecret`] if the private key is invalid or the
///   computation produces the point at infinity
pub fn ecdh_shared_secret(
    public_key: &[u8; 64],
    private_key: &[u8; 32],
) -> Result<[u8; 32], EccError> {
    // Validate peer public key and convert to SEC1 format.
    // This mirrors the C code's ecc_valid_point(&pk) check at line 920.
    let sec1 = bluez_pubkey_to_sec1(public_key);
    let peer_public =
        p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| EccError::InvalidPublicKey)?;

    // Convert our private key from BlueZ LSB-first to big-endian.
    // This mirrors ecc_bytes2native(private_key, priv) at line 923.
    let msb_private = reverse_bytes_32(private_key);
    let secret_key =
        p256::SecretKey::from_slice(&msb_private).map_err(|_| EccError::SharedSecret)?;

    // Compute ECDH: shared_point = d × Q
    // The p256 crate's diffie_hellman returns the x-coordinate of the
    // resulting point as the shared secret, in big-endian format.
    //
    // This replaces the C code's ecc_point_mult(&product, &pk, priv, rand, ...)
    // at line 925. The C code used a random blinding factor (rand) as the
    // initial Z coordinate for timing side-channel protection — the p256
    // crate provides constant-time operations natively, so no explicit
    // blinding is needed.
    let nz_scalar: p256::NonZeroScalar = secret_key.to_nonzero_scalar();
    let shared = p256::ecdh::diffie_hellman(nz_scalar, peer_public.as_affine());

    // Convert shared secret from big-endian to BlueZ LSB-first format.
    // This mirrors ecc_native2bytes(product.x, secret) at line 927.
    let secret_bytes = shared.raw_secret_bytes();
    let mut secret_msb = [0u8; 32];
    secret_msb.copy_from_slice(secret_bytes.as_slice());

    Ok(reverse_bytes_32(&secret_msb))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that reverse_bytes_32 correctly reverses a 32-byte array.
    #[test]
    fn test_reverse_bytes_32() {
        let input: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let reversed = reverse_bytes_32(&input);
        assert_eq!(reversed[0], 0x20);
        assert_eq!(reversed[31], 0x01);

        // Double reversal should return the original
        let double_reversed = reverse_bytes_32(&reversed);
        assert_eq!(double_reversed, input);
    }

    /// Verify that BlueZ → SEC1 → BlueZ public key round-trip is identity.
    #[test]
    fn test_pubkey_roundtrip() {
        // Create a known public key pattern in BlueZ format
        let mut bluez_pk = [0u8; 64];
        for (i, byte) in bluez_pk.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let sec1 = bluez_pubkey_to_sec1(&bluez_pk);
        assert_eq!(sec1[0], 0x04); // Uncompressed marker
        assert_eq!(sec1.len(), 65);

        let roundtrip = sec1_pubkey_to_bluez(&sec1);
        assert_eq!(roundtrip, bluez_pk);
    }

    /// Verify SEC1 conversion produces correct byte ordering for X coordinate.
    #[test]
    fn test_sec1_x_coordinate_ordering() {
        let mut bluez_pk = [0u8; 64];
        // Set X coordinate LSB-first: byte[0] = 0xFF (least significant)
        bluez_pk[0] = 0xFF;
        // byte[31] = 0x01 (most significant)
        bluez_pk[31] = 0x01;

        let sec1 = bluez_pubkey_to_sec1(&bluez_pk);
        // In SEC1, MSB comes first after the 0x04 marker
        assert_eq!(sec1[1], 0x01); // MSB of X
        assert_eq!(sec1[32], 0xFF); // LSB of X
    }

    /// Verify SEC1 conversion produces correct byte ordering for Y coordinate.
    #[test]
    fn test_sec1_y_coordinate_ordering() {
        let mut bluez_pk = [0u8; 64];
        // Set Y coordinate LSB-first: byte[32] = 0xAA (least significant)
        bluez_pk[32] = 0xAA;
        // byte[63] = 0xBB (most significant)
        bluez_pk[63] = 0xBB;

        let sec1 = bluez_pubkey_to_sec1(&bluez_pk);
        // In SEC1, MSB comes first
        assert_eq!(sec1[33], 0xBB); // MSB of Y
        assert_eq!(sec1[64], 0xAA); // LSB of Y
    }

    /// Verify that ecc_make_key generates a valid key pair.
    #[test]
    fn test_ecc_make_key() {
        let (public_key, private_key) = ecc_make_key().expect("Key generation should succeed");

        // Private key should not be all zeros
        assert_ne!(private_key, [0u8; 32]);

        // Public key should not be all zeros
        assert_ne!(public_key, [0u8; 64]);

        // Generated public key should be valid
        assert!(ecc_valid_public_key(&public_key));
    }

    /// Verify that ecc_make_public_key derives the correct public key
    /// from a generated private key, matching ecc_make_key output.
    #[test]
    fn test_ecc_make_public_key_consistency() {
        let (public_key, private_key) = ecc_make_key().expect("Key generation should succeed");

        let derived_public =
            ecc_make_public_key(&private_key).expect("Public key derivation should succeed");

        // The derived public key must match the one from ecc_make_key
        assert_eq!(derived_public, public_key);
    }

    /// Verify that ecc_make_public_key rejects an all-zero private key.
    #[test]
    fn test_ecc_make_public_key_rejects_zero() {
        let zero_key = [0u8; 32];
        assert!(ecc_make_public_key(&zero_key).is_err());
    }

    /// Verify that ecc_valid_public_key rejects invalid points.
    #[test]
    fn test_ecc_valid_public_key_rejects_invalid() {
        // All zeros is not a valid point (it's not on the curve)
        let zero_key = [0u8; 64];
        assert!(!ecc_valid_public_key(&zero_key));

        // Random bytes are extremely unlikely to be on the curve
        let mut garbage = [0u8; 64];
        for (i, byte) in garbage.iter_mut().enumerate() {
            *byte = (i * 37 + 13) as u8;
        }
        assert!(!ecc_valid_public_key(&garbage));
    }

    /// Verify that ecc_valid_public_key accepts a generated public key.
    #[test]
    fn test_ecc_valid_public_key_accepts_valid() {
        let (public_key, _) = ecc_make_key().expect("Key generation should succeed");
        assert!(ecc_valid_public_key(&public_key));
    }

    /// Verify ECDH shared secret computation produces consistent results.
    ///
    /// The fundamental ECDH property: if Alice has (pk_a, sk_a) and Bob has
    /// (pk_b, sk_b), then sk_a × pk_b == sk_b × pk_a (shared secret).
    #[test]
    fn test_ecdh_shared_secret_consistency() {
        // Generate two key pairs
        let (pk_a, sk_a) = ecc_make_key().expect("Key A generation should succeed");
        let (pk_b, sk_b) = ecc_make_key().expect("Key B generation should succeed");

        // Compute shared secrets from both sides
        let secret_ab = ecdh_shared_secret(&pk_b, &sk_a).expect("ECDH A→B should succeed");
        let secret_ba = ecdh_shared_secret(&pk_a, &sk_b).expect("ECDH B→A should succeed");

        // Both sides must derive the same shared secret
        assert_eq!(secret_ab, secret_ba);

        // Shared secret should not be all zeros
        assert_ne!(secret_ab, [0u8; 32]);
    }

    /// Verify that ecdh_shared_secret rejects an invalid public key.
    #[test]
    fn test_ecdh_rejects_invalid_public_key() {
        let (_, private_key) = ecc_make_key().expect("Key generation should succeed");

        let invalid_pk = [0u8; 64];
        let result = ecdh_shared_secret(&invalid_pk, &private_key);
        assert!(result.is_err());
    }

    /// Verify that ecdh_shared_secret rejects an all-zero private key.
    #[test]
    fn test_ecdh_rejects_zero_private_key() {
        let (public_key, _) = ecc_make_key().expect("Key generation should succeed");

        let zero_sk = [0u8; 32];
        let result = ecdh_shared_secret(&public_key, &zero_sk);
        assert!(result.is_err());
    }

    /// Verify byte-order conversion with the well-known P-256 generator point.
    ///
    /// The P-256 generator point G has known coordinates (from NIST FIPS 186-4):
    /// - Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    /// - Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    ///
    /// When the private key is 1, the public key equals G. Verify that the
    /// byte-order conversion produces the correct LSB-first representation.
    #[test]
    fn test_generator_point_derivation() {
        // Private key = 1 in LSB-first format (0x01 followed by 31 zero bytes)
        let mut private_key = [0u8; 32];
        private_key[0] = 0x01;

        let public_key =
            ecc_make_public_key(&private_key).expect("Generator point derivation should succeed");

        // Verify X coordinate (LSB-first): last byte should be 0x6B
        // (MSB of Gx = 0x6B17D1F2...)
        assert_eq!(public_key[31], 0x6B);
        // First byte should be 0x96 (LSB of Gx = ...D898C296)
        assert_eq!(public_key[0], 0x96);

        // Verify Y coordinate (LSB-first): last byte should be 0x4F
        // (MSB of Gy = 0x4FE342E2...)
        assert_eq!(public_key[63], 0x4F);
        // First byte should be 0xF5 (LSB of Gy = ...37BF51F5)
        assert_eq!(public_key[32], 0xF5);

        // This point must validate successfully
        assert!(ecc_valid_public_key(&public_key));
    }
}
