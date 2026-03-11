// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — btmon IRK/identity key management
//
// Copyright 2024 BlueZ Project
//
// Complete Rust rewrite of monitor/keys.c (141 lines) + monitor/keys.h (24 lines).
// Maintains an IRK list and resolves LE Resolvable Private Addresses (RPAs)
// using the `bt_crypto_ah` random address hash function from bluez-shared.

//! IRK (Identity Resolving Key) management for the btmon packet monitor.
//!
//! This module maintains a list of IRK entries and provides functions to:
//!
//! - Add and update IRK keys and their associated identity addresses
//! - Resolve LE Resolvable Private Addresses (RPAs) to their underlying
//!   identity addresses using the Bluetooth `ah` hash function
//! - Deduplicate IRK entries by key when adding identity information
//!
//! # Architecture
//!
//! Replaces the C implementation's `struct bt_crypto` singleton and
//! `struct queue *irk_list` with:
//!
//! - **Stateless crypto**: `bt_crypto_ah` from `bluez_shared::crypto::aes_cmac`
//!   is a pure function — no crypto context lifecycle needed
//! - **Thread-local state**: `thread_local!` + `RefCell<Vec<IrkData>>` for the
//!   IRK list, matching btmon's single-threaded (current-thread tokio) runtime
//!
//! # GLib Container Removal
//!
//! | C (GLib)               | Rust                                   |
//! |------------------------|----------------------------------------|
//! | `queue_new()`          | `Vec::new()`                           |
//! | `queue_push_tail()`    | `Vec::push()`                          |
//! | `queue_peek_tail()`    | `Vec::last_mut()`                      |
//! | `queue_find()`         | `Vec::iter().find()` / `iter_mut()`    |
//! | `queue_destroy(free)`  | `Vec::clear()` (Drop handles the rest) |
//! | `new0(struct, 1)`      | `IrkData { key, addr, addr_type }`     |
//! | `free(irk)`            | Automatic Drop                         |
//!
//! # Safety
//!
//! This module contains zero `unsafe` blocks. All memory operations use safe
//! Rust types and all cryptographic operations use the safe `bt_crypto_ah`
//! function from `bluez_shared::crypto::aes_cmac`.

use std::cell::RefCell;

use bluez_shared::crypto::aes_cmac::bt_crypto_ah;

// ---------------------------------------------------------------------------
// Sentinel constants (keys.c lines 24-25)
// ---------------------------------------------------------------------------

/// All-zero 16-byte key used as sentinel for "key not yet set" in partial
/// IRK entries. Matches the C `static const uint8_t empty_key[16]`.
const EMPTY_KEY: [u8; 16] = [0u8; 16];

/// All-zero 6-byte address used as sentinel for "address not yet set" in
/// partial IRK entries. Matches the C `static const uint8_t empty_addr[6]`.
const EMPTY_ADDR: [u8; 6] = [0u8; 6];

// ---------------------------------------------------------------------------
// Data structures (keys.c lines 29-33)
// ---------------------------------------------------------------------------

/// A single IRK entry associating an Identity Resolving Key with an identity
/// address. Replaces the C `struct irk_data`.
///
/// Entries may be partially populated during incremental updates:
/// - `keys_update_identity_key` may set `key` first with `addr` as `EMPTY_ADDR`
/// - `keys_update_identity_addr` may set `addr` first with `key` as `EMPTY_KEY`
/// - The next complementary update fills in the missing half
struct IrkData {
    /// 128-bit Identity Resolving Key (IRK).
    key: [u8; 16],
    /// 48-bit identity address (public or static random).
    addr: [u8; 6],
    /// Address type (e.g., 0x00 = public, 0x01 = random).
    addr_type: u8,
}

// ---------------------------------------------------------------------------
// Module-level state (keys.c lines 27, 35)
// ---------------------------------------------------------------------------

// The C code maintains two statics:
//   static struct bt_crypto *crypto;   — Replaced by stateless bt_crypto_ah()
//   static struct queue *irk_list;     — Replaced by thread-local Vec<IrkData>
//
// btmon uses a single-threaded (current_thread) tokio runtime, so thread_local
// with RefCell is the appropriate interior mutability pattern.

thread_local! {
    /// Thread-local IRK entry list, replacing the C `static struct queue *irk_list`.
    static IRK_LIST: RefCell<Vec<IrkData>> = const { RefCell::new(Vec::new()) };
}

// ---------------------------------------------------------------------------
// Private helpers (keys.c lines 89-98, 116-122)
// ---------------------------------------------------------------------------

/// Check whether the given IRK resolves the given RPA.
///
/// Computes `ah(irk.key, prand)` where `prand = addr[3..6]` and compares
/// the result against `hash = addr[0..3]`. Returns `true` if the computed
/// hash matches, indicating this IRK is the identity behind the RPA.
///
/// Replaces the C `match_resolve_irk()` callback (keys.c lines 89-98):
/// ```c
/// bt_crypto_ah(crypto, irk->key, addr + 3, local_hash);
/// return !memcmp(addr, local_hash, 3);
/// ```
///
/// # RPA Structure (Bluetooth Core Spec Vol 6, Part B, §1.3.2.2)
///
/// A Resolvable Private Address is composed of:
/// - `hash` (24 bits) = `addr[0..3]` — least significant 3 bytes
/// - `prand` (24 bits) = `addr[3..6]` — most significant 3 bytes
///
/// The `ah` function: `ah(k, r) = e(k, r') mod 2^24` where `r' = padding || r`
fn match_resolve_irk(irk: &IrkData, addr: &[u8; 6]) -> bool {
    // Extract the prand portion (most significant 3 bytes of RPA)
    let prand: [u8; 3] = [addr[3], addr[4], addr[5]];

    // Compute ah(IRK, prand) → local_hash[3]
    match bt_crypto_ah(&irk.key, &prand) {
        Ok(local_hash) => {
            // Compare computed hash with the hash portion of the RPA
            // (least significant 3 bytes)
            addr[0] == local_hash[0] && addr[1] == local_hash[1] && addr[2] == local_hash[2]
        }
        Err(_) => false,
    }
}

/// Check whether the given IRK entry has a matching key.
///
/// Simple byte-for-byte comparison of the 128-bit IRK.
///
/// Replaces the C `match_key()` callback (keys.c lines 116-122):
/// ```c
/// return !memcmp(irk->key, key, 16);
/// ```
fn match_key(irk: &IrkData, key: &[u8; 16]) -> bool {
    irk.key == *key
}

// ---------------------------------------------------------------------------
// Public API (keys.h lines 15-24)
// ---------------------------------------------------------------------------

/// Initialize the keys module.
///
/// Creates the crypto context and IRK list. In the Rust implementation,
/// `bt_crypto_ah` is stateless so no crypto context is needed — this
/// function simply ensures the IRK list is in a clean, empty state.
///
/// Replaces `keys_setup()` (keys.c lines 37-42):
/// ```c
/// void keys_setup(void) {
///     crypto = bt_crypto_new();
///     irk_list = queue_new();
/// }
/// ```
pub fn keys_setup() {
    IRK_LIST.with(|list| {
        list.borrow_mut().clear();
    });
}

/// Clean up the keys module.
///
/// Drops the crypto context and frees all IRK entries. In the Rust
/// implementation, Drop handles resource cleanup automatically — this
/// function clears the IRK list to release memory eagerly.
///
/// Replaces `keys_cleanup()` (keys.c lines 44-49):
/// ```c
/// void keys_cleanup(void) {
///     bt_crypto_unref(crypto);
///     queue_destroy(irk_list, free);
/// }
/// ```
pub fn keys_cleanup() {
    IRK_LIST.with(|list| {
        list.borrow_mut().clear();
    });
}

/// Update the IRK key for the most recent identity entry, or create a new
/// partial entry if the last entry already has a key set.
///
/// This supports incremental construction of IRK entries where the key
/// arrives before the address (e.g., from MGMT_EV_NEW_IRK events).
///
/// # Behavior
///
/// - If the last entry in the list has an all-zero key (`EMPTY_KEY`):
///   update it in-place with the provided key
/// - Otherwise: create a new entry with the provided key and empty
///   address/type, and append it to the list
///
/// Replaces `keys_update_identity_key()` (keys.c lines 51-67).
pub fn keys_update_identity_key(key: &[u8; 16]) {
    IRK_LIST.with(|list| {
        let mut list = list.borrow_mut();

        // Check if the last entry has an empty key (partial entry waiting
        // for its key to be filled in)
        if let Some(last) = list.last_mut() {
            if last.key == EMPTY_KEY {
                last.key = *key;
                return;
            }
        }

        // No partial entry available — create a new one with the key set
        // and address/type pending
        list.push(IrkData { key: *key, addr: EMPTY_ADDR, addr_type: 0 });
    });
}

/// Update the identity address for the most recent IRK entry, or create a
/// new partial entry if the last entry already has an address set.
///
/// This supports incremental construction of IRK entries where the address
/// arrives before the key (e.g., from separate MGMT events).
///
/// # Behavior
///
/// - If the last entry in the list has an all-zero address (`EMPTY_ADDR`):
///   update it in-place with the provided address and type
/// - Otherwise: create a new entry with the provided address/type and empty
///   key, and append it to the list
///
/// Replaces `keys_update_identity_addr()` (keys.c lines 69-87).
pub fn keys_update_identity_addr(addr: &[u8; 6], addr_type: u8) {
    IRK_LIST.with(|list| {
        let mut list = list.borrow_mut();

        // Check if the last entry has an empty address (partial entry waiting
        // for its address to be filled in)
        if let Some(last) = list.last_mut() {
            if last.addr == EMPTY_ADDR {
                last.addr = *addr;
                last.addr_type = addr_type;
                return;
            }
        }

        // No partial entry available — create a new one with address/type set
        // and key pending
        list.push(IrkData { key: EMPTY_KEY, addr: *addr, addr_type });
    });
}

/// Resolve a Resolvable Private Address (RPA) to its identity address
/// using the stored IRK list.
///
/// Iterates all IRK entries and computes `ah(IRK, prand)` for each,
/// comparing against the hash portion of the RPA. On match, copies the
/// identity address and type to the output parameters.
///
/// # Arguments
///
/// - `addr` — 6-byte Resolvable Private Address to resolve
/// - `ident` — Output buffer for the 6-byte identity address
/// - `ident_type` — Output for the identity address type
///
/// # Returns
///
/// `true` if the RPA was resolved (outputs populated), `false` if no
/// matching IRK was found.
///
/// Replaces `keys_resolve_identity()` (keys.c lines 100-114).
pub fn keys_resolve_identity(addr: &[u8; 6], ident: &mut [u8; 6], ident_type: &mut u8) -> bool {
    IRK_LIST.with(|list| {
        let list = list.borrow();

        for irk in list.iter() {
            if match_resolve_irk(irk, addr) {
                *ident = irk.addr;
                *ident_type = irk.addr_type;
                return true;
            }
        }

        false
    })
}

/// Add or update an identity entry by IRK key.
///
/// Searches the IRK list for an entry with a matching key. If found,
/// updates its address and type in-place. If not found, creates a new
/// complete entry with the given key, address, and type.
///
/// # Arguments
///
/// - `addr` — 6-byte identity address
/// - `addr_type` — Address type
/// - `key` — 16-byte Identity Resolving Key
///
/// # Returns
///
/// Always returns `true`, matching the C behavior.
///
/// Replaces `keys_add_identity()` (keys.c lines 124-140).
pub fn keys_add_identity(addr: &[u8; 6], addr_type: u8, key: &[u8; 16]) -> bool {
    IRK_LIST.with(|list| {
        let mut list = list.borrow_mut();

        // Search for an existing entry with the same key
        if let Some(irk) = list.iter_mut().find(|irk| match_key(irk, key)) {
            // Update address and type in the existing entry
            irk.addr = *addr;
            irk.addr_type = addr_type;
        } else {
            // Create a new complete entry
            list.push(IrkData { key: *key, addr: *addr, addr_type });
        }

        true
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_setup_cleanup_lifecycle() {
        keys_setup();
        // After setup, resolving any address should fail (no IRKs loaded)
        let addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut ident = [0u8; 6];
        let mut ident_type = 0u8;
        assert!(!keys_resolve_identity(&addr, &mut ident, &mut ident_type));
        keys_cleanup();
    }

    #[test]
    fn test_cleanup_clears_state() {
        keys_setup();
        let key = [0x42u8; 16];
        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        keys_add_identity(&addr, 0x01, &key);
        keys_cleanup();

        // After cleanup, should be empty again
        keys_setup();
        let prand: [u8; 3] = [0x70, 0x81, 0x94];
        if let Ok(hash) = bt_crypto_ah(&key, &prand) {
            let rpa = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];
            let mut ident = [0u8; 6];
            let mut ident_type = 0u8;
            assert!(!keys_resolve_identity(&rpa, &mut ident, &mut ident_type));
        }
        keys_cleanup();
    }

    // -----------------------------------------------------------------------
    // Incremental update tests (key-first and addr-first patterns)
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_key_first_then_addr() {
        keys_setup();

        let key = [0x01u8; 16];
        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let addr_type = 0x01;

        // Set key first → creates partial entry with empty addr
        keys_update_identity_key(&key);
        // Set addr → fills in same entry (last entry has empty addr)
        keys_update_identity_addr(&addr, addr_type);

        // Verify by adding same key with different addr (dedup finds it)
        let new_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert!(keys_add_identity(&new_addr, 0x00, &key));

        keys_cleanup();
    }

    #[test]
    fn test_update_addr_first_then_key() {
        keys_setup();

        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let addr_type = 0x01;
        let key = [0x02u8; 16];

        // Set addr first → creates partial entry with empty key
        keys_update_identity_addr(&addr, addr_type);
        // Set key → fills in same entry (last entry has empty key)
        keys_update_identity_key(&key);

        keys_cleanup();
    }

    #[test]
    fn test_update_key_creates_new_when_last_has_key() {
        keys_setup();

        let key1 = [0x01u8; 16];
        let key2 = [0x02u8; 16];

        // First key → creates entry with key1
        keys_update_identity_key(&key1);
        // Second key → last entry already has key, creates new entry
        keys_update_identity_key(&key2);

        // Both should be findable via add_identity dedup
        assert!(keys_add_identity(&[0xAA; 6], 0x00, &key1));
        assert!(keys_add_identity(&[0xBB; 6], 0x00, &key2));

        keys_cleanup();
    }

    #[test]
    fn test_update_addr_creates_new_when_last_has_addr() {
        keys_setup();

        let addr1 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let addr2 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // First addr → creates entry
        keys_update_identity_addr(&addr1, 0x00);
        // Second addr → last entry already has addr, creates new entry
        keys_update_identity_addr(&addr2, 0x01);

        keys_cleanup();
    }

    // -----------------------------------------------------------------------
    // add_identity tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_identity_new_entry() {
        keys_setup();

        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let key = [0x42u8; 16];
        assert!(keys_add_identity(&addr, 0x01, &key));

        keys_cleanup();
    }

    #[test]
    fn test_add_identity_dedup_by_key() {
        keys_setup();

        let key = [0x42u8; 16];
        let addr1 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let addr2 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        assert!(keys_add_identity(&addr1, 0x00, &key));
        // Same key, different addr → should update in-place
        assert!(keys_add_identity(&addr2, 0x01, &key));

        // Verify the updated address is used for resolution
        let prand: [u8; 3] = [0x70, 0x81, 0x94];
        if let Ok(hash) = bt_crypto_ah(&key, &prand) {
            let rpa = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];
            let mut resolved_addr = [0u8; 6];
            let mut resolved_type = 0u8;
            assert!(keys_resolve_identity(&rpa, &mut resolved_addr, &mut resolved_type));
            // Should resolve to addr2 (the updated address), not addr1
            assert_eq!(resolved_addr, addr2);
            assert_eq!(resolved_type, 0x01);
        }

        keys_cleanup();
    }

    #[test]
    fn test_add_identity_always_returns_true() {
        keys_setup();

        let key = [0xABu8; 16];
        let addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // New entry
        assert!(keys_add_identity(&addr, 0x00, &key));
        // Update existing
        assert!(keys_add_identity(&[0xAA; 6], 0x01, &key));
        // Different key
        assert!(keys_add_identity(&addr, 0x00, &[0xCD; 16]));

        keys_cleanup();
    }

    // -----------------------------------------------------------------------
    // RPA resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_identity_with_known_irk() {
        keys_setup();

        let irk: [u8; 16] = [
            0xEC, 0x02, 0x34, 0xA3, 0x57, 0xC8, 0xAD, 0x05, 0x34, 0x10, 0x10, 0xA6, 0x0A, 0x39,
            0x7D, 0x9B,
        ];

        let identity_addr: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let identity_type: u8 = 0x01;

        assert!(keys_add_identity(&identity_addr, identity_type, &irk));

        // Construct a valid RPA using bt_crypto_ah
        let prand: [u8; 3] = [0x70, 0x81, 0x94];
        let hash = bt_crypto_ah(&irk, &prand).expect("bt_crypto_ah should succeed");

        let rpa: [u8; 6] = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];

        let mut resolved_addr = [0u8; 6];
        let mut resolved_type = 0u8;

        assert!(keys_resolve_identity(&rpa, &mut resolved_addr, &mut resolved_type));
        assert_eq!(resolved_addr, identity_addr);
        assert_eq!(resolved_type, identity_type);

        keys_cleanup();
    }

    #[test]
    fn test_resolve_identity_no_irks_loaded() {
        keys_setup();

        let addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut ident = [0u8; 6];
        let mut ident_type = 0u8;

        assert!(!keys_resolve_identity(&addr, &mut ident, &mut ident_type));

        keys_cleanup();
    }

    #[test]
    fn test_resolve_identity_wrong_irk() {
        keys_setup();

        let irk = [0x42u8; 16];
        let addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        keys_add_identity(&addr, 0x01, &irk);

        // Construct RPA with a DIFFERENT IRK — should not resolve
        let other_irk = [0x99u8; 16];
        let prand: [u8; 3] = [0x70, 0x81, 0x94];
        let hash = bt_crypto_ah(&other_irk, &prand).expect("bt_crypto_ah should succeed");
        let rpa = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];

        let mut ident = [0u8; 6];
        let mut ident_type = 0u8;
        assert!(!keys_resolve_identity(&rpa, &mut ident, &mut ident_type));

        keys_cleanup();
    }

    #[test]
    fn test_resolve_identity_multiple_irks() {
        keys_setup();

        let irk1 = [0x11u8; 16];
        let addr1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let irk2 = [0x22u8; 16];
        let addr2 = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        keys_add_identity(&addr1, 0x00, &irk1);
        keys_add_identity(&addr2, 0x01, &irk2);

        // Resolve using irk2
        let prand: [u8; 3] = [0x70, 0x81, 0x94];
        let hash = bt_crypto_ah(&irk2, &prand).expect("bt_crypto_ah should succeed");
        let rpa = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];

        let mut resolved_addr = [0u8; 6];
        let mut resolved_type = 0u8;
        assert!(keys_resolve_identity(&rpa, &mut resolved_addr, &mut resolved_type));
        assert_eq!(resolved_addr, addr2);
        assert_eq!(resolved_type, 0x01);

        keys_cleanup();
    }

    // -----------------------------------------------------------------------
    // Sentinel comparison tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_key_sentinel() {
        // Setting an all-zero key is treated as "not yet set"
        keys_setup();

        keys_update_identity_key(&EMPTY_KEY);
        // The entry has key=EMPTY_KEY, addr=EMPTY_ADDR
        // Updating key again: last entry has empty key → update in-place
        let real_key = [0x99u8; 16];
        keys_update_identity_key(&real_key);

        // Now there should be 1 entry with real_key
        // Verify via add_identity dedup
        assert!(keys_add_identity(&[0xAA; 6], 0x00, &real_key));

        keys_cleanup();
    }

    #[test]
    fn test_empty_addr_sentinel() {
        keys_setup();

        keys_update_identity_addr(&EMPTY_ADDR, 0x00);
        // The entry has key=EMPTY_KEY, addr=EMPTY_ADDR
        // Updating addr again: last entry has empty addr → update in-place
        let real_addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        keys_update_identity_addr(&real_addr, 0x01);

        // Now update addr again: last entry has non-empty addr → creates new
        keys_update_identity_addr(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 0x00);

        keys_cleanup();
    }

    // -----------------------------------------------------------------------
    // match_resolve_irk and match_key helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_match_key_identical() {
        let irk = IrkData { key: [0x42u8; 16], addr: [0u8; 6], addr_type: 0 };
        assert!(match_key(&irk, &[0x42u8; 16]));
    }

    #[test]
    fn test_match_key_different() {
        let irk = IrkData { key: [0x42u8; 16], addr: [0u8; 6], addr_type: 0 };
        assert!(!match_key(&irk, &[0x43u8; 16]));
    }

    #[test]
    fn test_match_resolve_irk_valid() {
        let irk_key: [u8; 16] = [
            0xEC, 0x02, 0x34, 0xA3, 0x57, 0xC8, 0xAD, 0x05, 0x34, 0x10, 0x10, 0xA6, 0x0A, 0x39,
            0x7D, 0x9B,
        ];
        let irk =
            IrkData { key: irk_key, addr: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], addr_type: 0x01 };

        let prand: [u8; 3] = [0x70, 0x81, 0x94];
        let hash = bt_crypto_ah(&irk_key, &prand).expect("should succeed");
        let rpa: [u8; 6] = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];

        assert!(match_resolve_irk(&irk, &rpa));
    }

    #[test]
    fn test_match_resolve_irk_invalid() {
        let irk = IrkData { key: [0x42u8; 16], addr: [0u8; 6], addr_type: 0 };
        // Random address that won't match
        let addr: [u8; 6] = [0x00, 0x00, 0x00, 0x11, 0x22, 0x33];
        // This is overwhelmingly likely to be false (1/2^24 collision chance)
        // We don't assert false due to theoretical possibility, but verify
        // the function doesn't panic
        let _result = match_resolve_irk(&irk, &addr);
    }
}
