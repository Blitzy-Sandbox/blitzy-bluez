// SPDX-License-Identifier: GPL-2.0-or-later
//
// Identity key management replacing monitor/keys.c
//
// Manages identity resolving keys (IRKs) for resolving random
// private addresses to their identity addresses.

use std::sync::Mutex;

static KEYS: Mutex<KeyStore> = Mutex::new(KeyStore::new());

struct KeyEntry {
    addr: [u8; 6],
    addr_type: u8,
    irk: [u8; 16],
}

struct KeyStore {
    entries: Vec<KeyEntry>,
    local_irk: Option<[u8; 16]>,
    local_addr: Option<([u8; 6], u8)>,
}

impl KeyStore {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
            local_irk: None,
            local_addr: None,
        }
    }
}

/// Initialize the key store.
pub fn keys_setup() {
    let mut store = KEYS.lock().unwrap();
    store.entries.clear();
    store.local_irk = None;
    store.local_addr = None;
}

/// Clean up the key store.
pub fn keys_cleanup() {
    keys_setup();
}

/// Update the local identity resolving key.
pub fn keys_update_identity_key(key: &[u8; 16]) {
    let mut store = KEYS.lock().unwrap();
    store.local_irk = Some(*key);
}

/// Update the local identity address.
pub fn keys_update_identity_addr(addr: &[u8; 6], addr_type: u8) {
    let mut store = KEYS.lock().unwrap();
    store.local_addr = Some((*addr, addr_type));
}

/// Add a peer identity (address + IRK).
pub fn keys_add_identity(addr: &[u8; 6], addr_type: u8, key: &[u8; 16]) -> bool {
    let mut store = KEYS.lock().unwrap();

    // Check for duplicates
    if store
        .entries
        .iter()
        .any(|e| e.addr == *addr && e.addr_type == addr_type)
    {
        return false;
    }

    store.entries.push(KeyEntry {
        addr: *addr,
        addr_type,
        irk: *key,
    });
    true
}

/// Try to resolve a random address to an identity address.
///
/// Returns (identity_addr, identity_addr_type) if resolved.
pub fn keys_resolve_identity(addr: &[u8; 6]) -> Option<([u8; 6], u8)> {
    let store = KEYS.lock().unwrap();

    // Try to resolve using stored IRKs
    // A resolvable private address has bits [47:46] = 01
    if addr[5] & 0xC0 != 0x40 {
        return None; // Not a resolvable private address
    }

    let prand = [addr[3], addr[4], addr[5]];

    for entry in &store.entries {
        if verify_irk(&entry.irk, &prand, addr) {
            return Some((entry.addr, entry.addr_type));
        }
    }

    None
}

/// Verify an IRK against a random address.
fn verify_irk(irk: &[u8; 16], prand: &[u8; 3], addr: &[u8; 6]) -> bool {
    // Use bt_crypto_ah to verify: ah(IRK, prand) == hash
    let hash = [addr[0], addr[1], addr[2]];
    if let Some(computed) = compute_ah(irk, prand) {
        computed == hash
    } else {
        false
    }
}

/// Compute ah(k, r) = e(k, r') mod 2^24
fn compute_ah(irk: &[u8; 16], prand: &[u8; 3]) -> Option<[u8; 3]> {
    let mut res = [0u8; 3];
    if bluez_shared::crypto::bt_crypto_ah(irk, prand, &mut res) {
        Some(res)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_setup_cleanup() {
        keys_setup();
        keys_cleanup();
    }

    #[test]
    fn test_keys_add_identity() {
        keys_setup();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let key = [0xAA; 16];
        assert!(keys_add_identity(&addr, 0x01, &key));
        assert!(!keys_add_identity(&addr, 0x01, &key)); // duplicate
        keys_cleanup();
    }

    #[test]
    fn test_keys_update_local() {
        keys_setup();
        let key = [0xBB; 16];
        let addr = [0x01; 6];
        keys_update_identity_key(&key);
        keys_update_identity_addr(&addr, 0x00);
        keys_cleanup();
    }

    #[test]
    fn test_keys_resolve_non_rpa() {
        keys_setup();
        // Not a resolvable private address (bits [47:46] != 01)
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x00];
        assert!(keys_resolve_identity(&addr).is_none());
        keys_cleanup();
    }
}
