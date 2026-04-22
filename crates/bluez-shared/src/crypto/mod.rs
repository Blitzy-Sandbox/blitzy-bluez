// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth-specific cryptographic primitives
//
// Copyright 2024 BlueZ Project

//! Bluetooth-specific cryptographic primitives.
//!
//! This module provides the cryptographic building blocks required by the
//! Bluetooth Core Specification for LE pairing, Secure Connections key
//! exchange, ATT signing, GATT database hashing, and CSIS/SIRK operations.
//!
//! # Architecture
//!
//! The module replaces two C source files from BlueZ v5.86:
//!
//! - **`src/shared/crypto.c/h`** (1071 lines) — AES-128/CMAC-based
//!   cryptographic primitives for LE Legacy Pairing confirm/STK generation
//!   (`c1`, `s1`), LE Secure Connections confirm/key/check/compare values
//!   (`f4`, `f5`, `f6`, `g2`, `h6`), ATT signed writes, GATT database hash,
//!   and CSIS SIRK encryption/hashing/generation. The C implementation
//!   used Linux `AF_ALG` kernel crypto sockets (`ecb(aes)` and `cmac(aes)`)
//!   opened via `socket(PF_ALG, SOCK_SEQPACKET, 0)` with
//!   `setsockopt(SOL_ALG, ALG_SET_KEY)` and `sendmsg`/`read` for crypto
//!   operations. Random bytes came from `/dev/urandom` via a held file
//!   descriptor.
//!
//! - **`src/shared/ecc.c/h`** (~850 lines) — Hand-written P-256 elliptic
//!   curve implementation including big-number VLI arithmetic (add, subtract,
//!   multiply, square, modular inverse), modular field arithmetic over the
//!   P-256 prime, and elliptic curve point operations (addition, doubling,
//!   scalar multiplication with random-Z blinding for timing side-channel
//!   protection). Used for LE Secure Connections ECDH key exchange.
//!
//! # Rust Implementation
//!
//! - **AES/CMAC** operations (in [`aes_cmac`]) use the `aes` and `cmac`
//!   crates from RustCrypto for raw AES-128-ECB block encryption and
//!   AES-128-CMAC computation. The `ring` crate does not expose raw AES-ECB,
//!   which is required by several Bluetooth crypto functions (the security
//!   function `e` is defined as raw AES-128-ECB in the Bluetooth Core
//!   Specification Vol 3, Part H, Section 2.2.1).
//!
//! - **ECC** operations (in [`ecc`]) use the `p256` crate from RustCrypto,
//!   providing audited, constant-time P-256 scalar and point operations. The
//!   `ring` crate's `EphemeralPrivateKey` deliberately does not expose raw
//!   private key bytes as a security design choice. However, the BlueZ HCI
//!   layer requires raw 32-byte private key material for controller-side LE
//!   Secure Connections pairing operations.
//!
//! - **Random bytes** use `ring::rand::SystemRandom` for cryptographic
//!   random number generation, replacing direct `/dev/urandom` reads.
//!
//! # Design Decisions
//!
//! - **Stateless functions**: The C `struct bt_crypto` singleton with
//!   reference counting (`bt_crypto_new()`/`bt_crypto_ref()`/
//!   `bt_crypto_unref()`) and three held file descriptors (`ecb_aes`,
//!   `urandom`, `cmac_aes`) is eliminated entirely. All crypto functions
//!   are pure, stateless operations that create short-lived cipher contexts
//!   as needed. This removes the need for `Arc`-based sharing or any
//!   lifecycle management.
//!
//! - **Zero `unsafe`**: This entire module tree contains no `unsafe` blocks.
//!   All cryptographic operations are performed through safe Rust APIs
//!   provided by the `aes`, `cmac`, `p256`, and `ring` crates.
//!
//! - **Typed errors**: The C code's `bool` return values (success/failure
//!   with no diagnostic detail) are replaced with `Result<T, CryptoError>`
//!   and `Result<T, EccError>` for precise error propagation and idiomatic
//!   Rust error handling.
//!
//! # Sub-modules
//!
//! - [`aes_cmac`] — AES-128/CMAC Bluetooth crypto functions: [`bt_crypto_e`],
//!   [`bt_crypto_ah`], [`bt_crypto_c1`], [`bt_crypto_s1`], [`bt_crypto_f4`],
//!   [`bt_crypto_f5`], [`bt_crypto_f6`], [`bt_crypto_g2`], [`bt_crypto_h6`],
//!   [`bt_crypto_sign_att`], [`bt_crypto_verify_att_sign`],
//!   [`bt_crypto_gatt_hash`], [`bt_crypto_sef`], [`bt_crypto_sih`],
//!   [`bt_crypto_sirk`], [`bt_crypto_rsi`], [`random_bytes`]
//!
//! - [`ecc`] — P-256 ECC operations: [`ecc_make_key`],
//!   [`ecc_make_public_key`], [`ecc_valid_public_key`],
//!   [`ecdh_shared_secret`]
//!
//! [`bt_crypto_e`]: aes_cmac::bt_crypto_e
//! [`bt_crypto_ah`]: aes_cmac::bt_crypto_ah
//! [`bt_crypto_c1`]: aes_cmac::bt_crypto_c1
//! [`bt_crypto_s1`]: aes_cmac::bt_crypto_s1
//! [`bt_crypto_f4`]: aes_cmac::bt_crypto_f4
//! [`bt_crypto_f5`]: aes_cmac::bt_crypto_f5
//! [`bt_crypto_f6`]: aes_cmac::bt_crypto_f6
//! [`bt_crypto_g2`]: aes_cmac::bt_crypto_g2
//! [`bt_crypto_h6`]: aes_cmac::bt_crypto_h6
//! [`bt_crypto_sign_att`]: aes_cmac::bt_crypto_sign_att
//! [`bt_crypto_verify_att_sign`]: aes_cmac::bt_crypto_verify_att_sign
//! [`bt_crypto_gatt_hash`]: aes_cmac::bt_crypto_gatt_hash
//! [`bt_crypto_sef`]: aes_cmac::bt_crypto_sef
//! [`bt_crypto_sih`]: aes_cmac::bt_crypto_sih
//! [`bt_crypto_sirk`]: aes_cmac::bt_crypto_sirk
//! [`bt_crypto_rsi`]: aes_cmac::bt_crypto_rsi
//! [`random_bytes`]: aes_cmac::random_bytes
//! [`ecc_make_key`]: ecc::ecc_make_key
//! [`ecc_make_public_key`]: ecc::ecc_make_public_key
//! [`ecc_valid_public_key`]: ecc::ecc_valid_public_key
//! [`ecdh_shared_secret`]: ecc::ecdh_shared_secret

pub mod aes_cmac;
pub mod ecc;

// Re-export error types for convenient access from other crates.
// Consumers can use `bluez_shared::crypto::CryptoError` instead of the
// longer `bluez_shared::crypto::aes_cmac::CryptoError`.
pub use aes_cmac::CryptoError;
pub use ecc::EccError;
