// SPDX-License-Identifier: GPL-2.0-or-later
//! HCI (Host Controller Interface) transport and cryptographic operations.
//!
//! This module provides async HCI socket communication with Bluetooth
//! controllers and HCI-assisted LE cryptographic functions.  It replaces the
//! C implementation files `src/shared/hci.c` / `src/shared/hci.h` and
//! `src/shared/hci-crypto.c` / `src/shared/hci-crypto.h` from the BlueZ
//! v5.86 codebase.
//!
//! # Sub-modules
//!
//! * [`transport`] — Async HCI socket transport with command queuing and
//!   response correlation.  The opaque ref-counted `struct bt_hci` from C is
//!   replaced by [`HciTransport`], which uses `Arc`-based shared ownership,
//!   `tokio::io::unix::AsyncFd` for non-blocking I/O, and
//!   `tokio::sync::oneshot` / `tokio::sync::mpsc` channels for delivering
//!   command responses and event notifications respectively.
//!
//! * [`crypto`] — Controller-assisted LE cryptographic functions operating
//!   through the HCI **LE Encrypt** and **LE Rand** commands.  Provides
//!   [`crypto_prand`] (random address generation), [`crypto_e`] (AES-128
//!   encrypt), [`crypto_d1`] / [`crypto_dm`] (key diversification), and
//!   [`crypto_ah`] (address hash) — the same five primitives declared in
//!   `hci-crypto.h`.
//!
//! # Migration from C
//!
//! All `callback_t fn + void *user_data` patterns from the C API have been
//! replaced with `async fn` returning `Result`.  The `bt_hci_callback_func_t`
//! and `bt_hci_crypto_func_t` callback typedefs, along with the intermediate
//! `struct crypto_data` wrapper, are no longer needed.
//!
//! Reference counting (`bt_hci_ref` / `bt_hci_unref`) is replaced by Rust's
//! `Arc<HciTransport>` shared ownership model with automatic cleanup via
//! `Drop`.
//!
//! # Safety
//!
//! This module contains zero `unsafe` blocks.  All kernel socket operations
//! and HCI channel I/O are performed through the `nix` crate's safe wrappers
//! and `tokio::io::unix::AsyncFd`, with the raw `AF_BLUETOOTH` socket
//! creation confined to the `crate::sys` FFI boundary module.

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// Async HCI socket transport — command queuing, response correlation, and
/// event dispatch over raw HCI channels.
pub mod transport;

/// HCI-assisted LE cryptographic functions — AES-128 encrypt, random number
/// generation, and key diversification via controller commands.
pub mod crypto;

// ---------------------------------------------------------------------------
// Convenience re-exports
// ---------------------------------------------------------------------------

// Transport types: re-exported so callers can write
// `bluez_shared::hci::HciTransport` instead of
// `bluez_shared::hci::transport::HciTransport`.
pub use transport::HciError;
pub use transport::HciEvent;
pub use transport::HciResponse;
pub use transport::HciTransport;

// Crypto types and functions: re-exported for ergonomic access via
// `bluez_shared::hci::crypto_prand(...)` etc.
pub use crypto::HciCryptoError;
pub use crypto::{crypto_ah, crypto_d1, crypto_dm, crypto_e, crypto_prand};
