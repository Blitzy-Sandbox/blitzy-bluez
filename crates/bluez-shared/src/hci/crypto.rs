// SPDX-License-Identifier: GPL-2.0-or-later
//! HCI-assisted LE cryptographic operations.
//!
//! Complete Rust rewrite of BlueZ `src/shared/hci-crypto.c` (159 lines) and
//! `src/shared/hci-crypto.h` (33 lines).  These functions use the HCI
//! **LE Encrypt** and **LE Rand** commands to perform controller-assisted
//! cryptographic operations required by the Bluetooth Security Manager
//! Protocol (SMP) and Resolvable Private Address (RPA) generation.
//!
//! # Architecture
//!
//! * **Async replaces callbacks** — The C `bt_hci_crypto_func_t` callback +
//!   `void *user_data` pattern is replaced by `async fn` returning `Result`.
//!   No `struct crypto_data` allocation is required.
//! * **No manual memory** — Stack variables and `Vec` replace `new0` / `free`.
//! * **Zero `unsafe`** — All unsafe FFI is confined to `crate::sys`.

use super::transport::{HciError, HciTransport};
use crate::sys::hci::{
    OCF_LE_ENCRYPT, OCF_LE_RAND, OGF_LE_CTL, le_encrypt_cp, le_encrypt_rp, le_rand_rp, opcode,
};
use zerocopy::{FromBytes, IntoBytes};

// ===========================================================================
// Error Type
// ===========================================================================

/// Errors produced by HCI-assisted cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum HciCryptoError {
    /// The HCI command completed with a non-zero status byte from the
    /// controller.
    #[error("HCI crypto command failed with status 0x{status:02x}")]
    CommandFailed {
        /// HCI error status code returned by the controller.
        status: u8,
    },

    /// The `size` parameter passed to the internal `le_encrypt` helper was
    /// outside the valid range `1..=16`.
    #[error("invalid encryption result size (must be 1..=16)")]
    InvalidSize,

    /// The underlying HCI transport layer returned an error.
    #[error("HCI transport error: {0}")]
    TransportError(#[from] HciError),
}

// ===========================================================================
// Internal Helper — le_encrypt
// ===========================================================================

/// Send an **LE Encrypt** HCI command and return the first `size` bytes of
/// the encrypted result.
///
/// This replaces the C `le_encrypt()` function (`hci-crypto.c` lines 42–67)
/// and the associated `le_encrypt_callback` (lines 28–40).  The async/await
/// model eliminates the intermediate `struct crypto_data` callback wrapper.
///
/// # Parameters
///
/// * `hci`       — HCI transport to send the command through.
/// * `size`      — Number of result bytes to return (1..=16).  Corresponds to
///   the C `crypto_data.size` truncation field.
/// * `key`       — 128-bit AES key.
/// * `plaintext` — 128-bit plaintext block.
///
/// # Errors
///
/// * [`HciCryptoError::InvalidSize`] if `size` is 0 or greater than 16.
/// * [`HciCryptoError::CommandFailed`] if the controller returns non-zero status.
/// * [`HciCryptoError::TransportError`] if the HCI transport fails.
async fn le_encrypt(
    hci: &HciTransport,
    size: u8,
    key: &[u8; 16],
    plaintext: &[u8; 16],
) -> Result<Vec<u8>, HciCryptoError> {
    // Validate size range.
    // Matches C: `if (!callback || !size || size > 16) return false;`
    if size == 0 || size > 16 {
        return Err(HciCryptoError::InvalidSize);
    }

    // Construct the LE Encrypt command parameter struct.
    let cmd = le_encrypt_cp { key: *key, plaintext: *plaintext };

    // Send BT_HCI_CMD_LE_ENCRYPT = opcode(OGF_LE_CTL, OCF_LE_ENCRYPT).
    let cmd_opcode = opcode(OGF_LE_CTL, OCF_LE_ENCRYPT);
    let response = hci.send_command(cmd_opcode, cmd.as_bytes()).await?;

    // Parse the response as le_encrypt_rp { status: u8, data: [u8; 16] }.
    // Guard against a truncated response from the controller.
    let expected_len = core::mem::size_of::<le_encrypt_rp>();
    if response.data.len() < expected_len {
        return Err(HciCryptoError::CommandFailed { status: 0xFF });
    }
    let rsp = le_encrypt_rp::read_from_bytes(&response.data[..expected_len])
        .map_err(|_| HciCryptoError::CommandFailed { status: 0xFF })?;

    // Check HCI status.
    // Matches C: `if (rsp->status) { data->callback(NULL, 0, ...); return; }`
    if rsp.status != 0 {
        return Err(HciCryptoError::CommandFailed { status: rsp.status });
    }

    // Return the first `size` bytes of the encrypted data.
    Ok(rsp.data[..size as usize].to_vec())
}

// ===========================================================================
// Public API Functions
// ===========================================================================

/// Generate a pseudo-random number suitable for use as a Resolvable Private
/// Address (RPA) random part.
///
/// Replaces `bt_hci_crypto_prand()` (`hci-crypto.c` lines 88–107) and
/// `prand_callback` (lines 69–86).
///
/// The returned 3-byte value has the two MSBs of the third byte set to `01`,
/// identifying it as a resolvable private address random part per the
/// Bluetooth Core Specification (Vol 6, Part B, § 1.3.2.2).
///
/// # Byte extraction from the 64-bit random number
///
/// ```text
/// prand[0] = (number & 0xff0000) >> 16   // byte 2 of LE u64
/// prand[1] = (number & 0x00ff00) >> 8    // byte 1 of LE u64
/// prand[2] = (number & 0x00003f) | 0x40  // byte 0, upper 2 bits = 01
/// ```
///
/// # Errors
///
/// * [`HciCryptoError::CommandFailed`] if the controller returns non-zero status.
/// * [`HciCryptoError::TransportError`] if the HCI transport fails.
pub async fn crypto_prand(hci: &HciTransport) -> Result<[u8; 3], HciCryptoError> {
    // Send BT_HCI_CMD_LE_RAND with no parameters.
    let cmd_opcode = opcode(OGF_LE_CTL, OCF_LE_RAND);
    let response = hci.send_command(cmd_opcode, &[]).await?;

    // Parse response as le_rand_rp { status: u8, random: u64 }.
    // Guard against a truncated response.
    let expected_len = core::mem::size_of::<le_rand_rp>();
    if response.data.len() < expected_len {
        return Err(HciCryptoError::CommandFailed { status: 0xFF });
    }
    let rsp = le_rand_rp::read_from_bytes(&response.data[..expected_len])
        .map_err(|_| HciCryptoError::CommandFailed { status: 0xFF })?;

    // Check HCI status.
    if rsp.status != 0 {
        return Err(HciCryptoError::CommandFailed { status: rsp.status });
    }

    // Extract 3 bytes from the random number and set the RPA type bits.
    // Matches C code exactly (hci-crypto.c lines 81–83):
    //   prand[0] = (rsp->number & 0xff0000) >> 16;
    //   prand[1] = (rsp->number & 0x00ff00) >> 8;
    //   prand[2] = (rsp->number & 0x00003f) | 0x40;
    let number = rsp.random;
    let prand: [u8; 3] = [
        ((number & 0x00ff_0000) >> 16) as u8,
        ((number & 0x0000_ff00) >> 8) as u8,
        ((number & 0x0000_003f) | 0x40) as u8,
    ];

    Ok(prand)
}

/// Perform AES-128 encryption via the HCI controller (full 16-byte result).
///
/// Replaces `bt_hci_crypto_e()` (`hci-crypto.c` lines 109–114).
/// This is the core `e()` function from the Bluetooth specification:
/// `e(key, plaintext) = AES-128(key, plaintext)`.
///
/// # Parameters
///
/// * `hci`       — HCI transport.
/// * `key`       — 128-bit AES key.
/// * `plaintext` — 128-bit plaintext block.
///
/// # Returns
///
/// The 128-bit (16-byte) encrypted result.
///
/// # Errors
///
/// * [`HciCryptoError::CommandFailed`] if the controller returns non-zero status.
/// * [`HciCryptoError::TransportError`] if the HCI transport fails.
pub async fn crypto_e(
    hci: &HciTransport,
    key: &[u8; 16],
    plaintext: &[u8; 16],
) -> Result<[u8; 16], HciCryptoError> {
    let result = le_encrypt(hci, 16, key, plaintext).await?;
    // le_encrypt with size=16 guarantees exactly 16 bytes on success.
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&result);
    Ok(arr)
}

/// Bluetooth diversification function **d1**.
///
/// Replaces `bt_hci_crypto_d1()` (`hci-crypto.c` lines 116–131).
///
/// Computes `d1(k, d, r) = e(k, d')` where `d'` is a 16-byte block
/// constructed as:
///
/// ```text
/// dp[0]     = d & 0xff      (d low byte, little-endian)
/// dp[1]     = d >> 8         (d high byte)
/// dp[2]     = r & 0xff       (r low byte, little-endian)
/// dp[3]     = r >> 8         (r high byte)
/// dp[4..16] = 0x00           (12 zero padding bytes)
/// ```
///
/// # Parameters
///
/// * `hci` — HCI transport.
/// * `k`   — 128-bit diversification key.
/// * `d`   — 16-bit diversifier.
/// * `r`   — 16-bit random value.
///
/// # Returns
///
/// The 128-bit (16-byte) diversified result.
///
/// # Errors
///
/// * [`HciCryptoError::CommandFailed`] if the controller returns non-zero status.
/// * [`HciCryptoError::TransportError`] if the HCI transport fails.
pub async fn crypto_d1(
    hci: &HciTransport,
    k: &[u8; 16],
    d: u16,
    r: u16,
) -> Result<[u8; 16], HciCryptoError> {
    // Construct d' = padding || r || d  (hci-crypto.c lines 120–127).
    let mut dp = [0u8; 16];
    dp[0] = (d & 0xff) as u8;
    dp[1] = (d >> 8) as u8;
    dp[2] = (r & 0xff) as u8;
    dp[3] = (r >> 8) as u8;
    // dp[4..16] already zeroed by the [0u8; 16] initializer.

    // d1(k, d, r) = e(k, d')
    let result = le_encrypt(hci, 16, k, &dp).await?;
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&result);
    Ok(arr)
}

/// Bluetooth diversification function **dm**.
///
/// Replaces `bt_hci_crypto_dm()` (`hci-crypto.c` lines 133–145).
///
/// Computes `dm(k, r) = e(k, r') mod 2^64` where `r'` is a 16-byte block:
///
/// ```text
/// rp[0..8]  = r             (8 bytes copied)
/// rp[8..16] = 0x00          (8 zero padding bytes)
/// ```
///
/// The result is truncated to 8 bytes (`size=8` passed to `le_encrypt`).
///
/// # Parameters
///
/// * `hci` — HCI transport.
/// * `k`   — 128-bit key.
/// * `r`   — 8-byte random value.
///
/// # Returns
///
/// The 8-byte diversified result.
///
/// # Errors
///
/// * [`HciCryptoError::CommandFailed`] if the controller returns non-zero status.
/// * [`HciCryptoError::TransportError`] if the HCI transport fails.
pub async fn crypto_dm(
    hci: &HciTransport,
    k: &[u8; 16],
    r: &[u8; 8],
) -> Result<[u8; 8], HciCryptoError> {
    // Construct r' = padding || r  (hci-crypto.c lines 137–141).
    let mut rp = [0u8; 16];
    rp[..8].copy_from_slice(r);
    // rp[8..16] already zeroed.

    // dm(k, r) = e(k, r') mod 2^64 — truncated to 8 bytes by le_encrypt(size=8).
    let result = le_encrypt(hci, 8, k, &rp).await?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&result);
    Ok(arr)
}

/// Bluetooth address hash function **ah**.
///
/// Replaces `bt_hci_crypto_ah()` (`hci-crypto.c` lines 147–159).
///
/// Computes `ah(k, r) = e(k, r') mod 2^24` where `r'` is a 16-byte block:
///
/// ```text
/// rp[0..3]  = r             (3 bytes copied)
/// rp[3..16] = 0x00          (13 zero padding bytes)
/// ```
///
/// The result is truncated to 3 bytes (`size=3` passed to `le_encrypt`),
/// producing the 24-bit hash value used for Resolvable Private Address
/// resolution (Bluetooth Core Spec Vol 3, Part H, § 2.2.2).
///
/// # Parameters
///
/// * `hci` — HCI transport.
/// * `k`   — 128-bit Identity Resolving Key (IRK).
/// * `r`   — 3-byte random part of the Resolvable Private Address.
///
/// # Returns
///
/// The 3-byte address hash value.
///
/// # Errors
///
/// * [`HciCryptoError::CommandFailed`] if the controller returns non-zero status.
/// * [`HciCryptoError::TransportError`] if the HCI transport fails.
pub async fn crypto_ah(
    hci: &HciTransport,
    k: &[u8; 16],
    r: &[u8; 3],
) -> Result<[u8; 3], HciCryptoError> {
    // Construct r' = padding || r  (hci-crypto.c lines 151–155).
    let mut rp = [0u8; 16];
    rp[..3].copy_from_slice(r);
    // rp[3..16] already zeroed.

    // ah(k, r) = e(k, r') mod 2^24 — truncated to 3 bytes by le_encrypt(size=3).
    let result = le_encrypt(hci, 3, k, &rp).await?;
    let mut arr = [0u8; 3];
    arr.copy_from_slice(&result);
    Ok(arr)
}
