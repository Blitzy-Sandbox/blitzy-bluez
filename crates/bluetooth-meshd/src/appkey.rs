// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
// Copyright (C) 2017-2019 Intel Corporation. All rights reserved.
//
// Complete Rust rewrite of `mesh/appkey.c` (~452 lines) and `mesh/appkey.h`
// from BlueZ v5.86.
//
// Manages Application Keys bound to Network Keys within the Bluetooth Mesh
// stack, including Key Refresh phase behaviour and index-list packing for
// configuration model responses (AppKey List message).

//! Application key management for the Bluetooth Mesh daemon.
//!
//! This module provides:
//!
//! - [`MeshAppKey`] — the per-key state structure (index, bound net key,
//!   current key material + AID, new key material + AID during Key Refresh).
//! - Lifecycle functions: [`appkey_key_init`], [`appkey_key_free`],
//!   [`appkey_finalize`].
//! - Access helpers: [`appkey_get_key`], [`appkey_get_key_idx`],
//!   [`appkey_have_key`], [`appkey_net_idx`].
//! - Management operations: [`appkey_key_add`], [`appkey_key_update`],
//!   [`appkey_key_delete`], [`appkey_delete_bound_keys`].
//! - List packing: [`appkey_list`] for the Config AppKey List response.
//!
//! All ELL `l_queue` operations are replaced with `Vec<MeshAppKey>` stored
//! on [`MeshNet`](crate::net::MeshNet). AID derivation delegates to
//! [`mesh_crypto_k4`](crate::crypto::mesh_crypto_k4).

use tracing::warn;

use crate::crypto::mesh_crypto_k4;
use crate::mesh::{
    APP_AID_INVALID, KEY_AID_SHIFT, KEY_ID_AKF, KEY_REFRESH_PHASE_ONE, KEY_REFRESH_PHASE_TWO,
    MAX_KEY_IDX, MESH_STATUS_CANNOT_UPDATE, MESH_STATUS_IDX_ALREADY_STORED,
    MESH_STATUS_INSUFF_RESOURCES, MESH_STATUS_INVALID_APPKEY, MESH_STATUS_INVALID_BINDING,
    MESH_STATUS_INVALID_NETKEY, MESH_STATUS_STORAGE_FAIL, MESH_STATUS_SUCCESS, NET_IDX_INVALID,
};
use crate::net::MeshNet;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum number of application keys that can be stored per node.
///
/// Corresponds to `#define MAX_APP_KEYS 32` in `mesh/appkey.h`.
pub const MAX_APP_KEYS: usize = 32;

// ===========================================================================
// Core Structure
// ===========================================================================

/// Application key state — replaces C `struct mesh_app_key`.
///
/// Each application key is bound to exactly one network key and carries
/// both the current key material and (during Key Refresh) the new key
/// material. The 6-bit Application Identifier (AID) is pre-computed from
/// each key via the k4 key derivation function.
#[derive(Debug, Clone)]
pub struct MeshAppKey {
    /// Application key index (0–4095).
    pub app_idx: u16,
    /// Bound network key index (0–4095).
    pub net_idx: u16,
    /// Current 128-bit key material.
    pub key: [u8; 16],
    /// New 128-bit key material during Key Refresh (zeroed when not in use).
    pub new_key: [u8; 16],
    /// AID derived from [`key`](MeshAppKey::key) via k4.
    pub key_aid: u8,
    /// AID derived from [`new_key`](MeshAppKey::new_key) via k4, or
    /// [`APP_AID_INVALID`] when no new key is present.
    pub new_key_aid: u8,
}

impl MeshAppKey {
    /// Create a new application key with default (zeroed) fields.
    ///
    /// The `new_key_aid` is initialised to [`APP_AID_INVALID`] to indicate
    /// that no new key is present (matching `app_key_new()` in the C code).
    fn new() -> Self {
        Self {
            app_idx: 0,
            net_idx: 0,
            key: [0u8; 16],
            new_key: [0u8; 16],
            key_aid: 0,
            new_key_aid: APP_AID_INVALID,
        }
    }
}

// ===========================================================================
// Internal Helpers
// ===========================================================================

/// Derive the AID from `key_value` and store it (with the key material)
/// into either the current or new slot of `key`.
///
/// Replaces the C `set_key()` static helper. The AID byte is computed as
/// `KEY_ID_AKF | (k4(key_value) << KEY_AID_SHIFT)` which sets the AKF
/// (Application Key Flag) bit and embeds the 6-bit identifier.
///
/// Returns `true` on success, `false` if the k4 derivation fails.
fn set_key(key: &mut MeshAppKey, key_value: &[u8; 16], is_new: bool) -> bool {
    let Some(aid) = mesh_crypto_k4(key_value) else {
        return false;
    };

    let full_aid = KEY_ID_AKF | (aid << KEY_AID_SHIFT);

    if is_new {
        key.new_key_aid = full_aid;
        key.new_key = *key_value;
    } else {
        key.key_aid = full_aid;
        key.key = *key_value;
    }

    true
}

// ===========================================================================
// Lifecycle Functions
// ===========================================================================

/// Initialise an application key and append it to the network's key list.
///
/// This is the load-time initialiser used when restoring persisted keys from
/// the JSON configuration. It creates a new [`MeshAppKey`], derives AIDs,
/// and pushes it onto the network's app-key vector.
///
/// Replaces C `appkey_key_init()`.
///
/// # Arguments
/// * `net` — Mutable reference to the mesh network layer.
/// * `net_idx` — Bound network key index (must already exist in `net`).
/// * `app_idx` — Application key index.
/// * `key_value` — 16-byte current key material.
/// * `new_key_value` — Optional 16-byte new key (during Key Refresh).
///
/// # Returns
/// `true` if the key was successfully initialised and appended; `false` on
/// validation failure or if the k4 derivation fails.
pub fn appkey_key_init(
    net: &mut MeshNet,
    net_idx: u16,
    app_idx: u16,
    key_value: &[u8; 16],
    new_key_value: Option<&[u8; 16]>,
) -> bool {
    // Validate key index bounds (12-bit maximum).
    if net_idx > MAX_KEY_IDX || app_idx > MAX_KEY_IDX {
        return false;
    }

    // The bound network key must already exist.
    if !net.have_key(net_idx) {
        return false;
    }

    let mut key = MeshAppKey::new();
    key.net_idx = net_idx;
    key.app_idx = app_idx;

    // Derive AID and store the current key material.
    if !set_key(&mut key, key_value, false) {
        return false;
    }

    // If a new key is provided (Key Refresh in progress), derive its AID too.
    if let Some(new_val) = new_key_value {
        if !set_key(&mut key, new_val, true) {
            return false;
        }
    }

    net.get_app_keys_mut().push(key);
    true
}

/// Release an application key.
///
/// In Rust the [`MeshAppKey`] is dropped automatically when it goes out of
/// scope, so this function is a no-op provided for API symmetry with the
/// C `appkey_key_free()`.
pub fn appkey_key_free(_key: MeshAppKey) {
    // Rust ownership semantics handle deallocation. No manual free required.
}

/// Finalise Key Refresh for all application keys bound to `net_idx`.
///
/// For each bound key that has a valid new AID (i.e. `new_key_aid !=
/// APP_AID_INVALID`), promotes the new key to the current slot:
///   - `key_aid` ← `new_key_aid`
///   - `key` ← `new_key`
///   - `new_key_aid` ← `APP_AID_INVALID`
///
/// Replaces C `appkey_finalize()` which iterates via `l_queue_foreach`.
pub fn appkey_finalize(net: &mut MeshNet, net_idx: u16) {
    for key in net.get_app_keys_mut() {
        if key.net_idx != net_idx {
            continue;
        }

        if key.new_key_aid == APP_AID_INVALID {
            continue;
        }

        // Promote new key → current key.
        key.key_aid = key.new_key_aid;
        key.new_key_aid = APP_AID_INVALID;
        key.key = key.new_key;
    }
}

// ===========================================================================
// Key Access Functions
// ===========================================================================

/// Retrieve the active key material and AID for the given app key index.
///
/// During Key Refresh Phase Two the *new* key is returned; in all other
/// phases the *current* key is returned. Returns `None` if:
/// - the key index is not found,
/// - the bound network key no longer exists, or
/// - Phase Two is active but no new key has been provisioned.
///
/// Replaces C `appkey_get_key()`.
pub fn appkey_get_key(net: &MeshNet, app_idx: u16) -> Option<(&[u8; 16], u8)> {
    let app_key = net.get_app_keys().iter().find(|k| k.app_idx == app_idx)?;

    // Verify the bound network key still exists.
    if !net.have_key(app_key.net_idx) {
        return None;
    }

    let phase = net.key_refresh_phase_get(app_key.net_idx);

    if phase != KEY_REFRESH_PHASE_TWO {
        // Normal operation or Phase One — use current key.
        return Some((&app_key.key, app_key.key_aid));
    }

    // Phase Two — use new key if available.
    if app_key.new_key_aid == APP_AID_INVALID {
        return None;
    }

    Some((&app_key.new_key, app_key.new_key_aid))
}

/// Retrieve both old and new key material from an app key reference.
///
/// Returns a 4-tuple `(key, key_aid, new_key, new_key_aid)` providing
/// references to both the current and new key slots. The caller can inspect
/// `new_key_aid == APP_AID_INVALID` to determine if a new key is present.
///
/// Replaces C `appkey_get_key_idx()` which used output pointer parameters.
pub fn appkey_get_key_idx(app_key: &MeshAppKey) -> (Option<&[u8; 16]>, u8, Option<&[u8; 16]>, u8) {
    (Some(&app_key.key), app_key.key_aid, Some(&app_key.new_key), app_key.new_key_aid)
}

/// Check whether an application key with the given index exists.
///
/// Replaces C `appkey_have_key()`.
pub fn appkey_have_key(net: &MeshNet, app_idx: u16) -> bool {
    net.get_app_keys().iter().any(|k| k.app_idx == app_idx)
}

/// Return the network key index to which the given app key is bound.
///
/// Returns [`NET_IDX_INVALID`] if the app key index is not found.
///
/// Replaces C `appkey_net_idx()`.
pub fn appkey_net_idx(net: &MeshNet, app_idx: u16) -> u16 {
    net.get_app_keys()
        .iter()
        .find(|k| k.app_idx == app_idx)
        .map(|k| k.net_idx)
        .unwrap_or(NET_IDX_INVALID)
}

// ===========================================================================
// Key Management Operations
// ===========================================================================

/// Add a new application key.
///
/// Validates the request against the Mesh Profile spec rules:
/// - If `app_idx` already exists with a different `net_idx` →
///   `MESH_STATUS_INVALID_NETKEY`.
/// - If `app_idx` already exists with the same key material →
///   `MESH_STATUS_SUCCESS` (idempotent).
/// - If `app_idx` already exists with different key material →
///   `MESH_STATUS_IDX_ALREADY_STORED`.
/// - If the bound `net_idx` does not exist → `MESH_STATUS_INVALID_NETKEY`.
/// - If the maximum key count is reached → `MESH_STATUS_INSUFF_RESOURCES`.
///
/// On success the key is persisted via [`MeshConfig::app_key_add`] and
/// appended to the network's app-key vector.
///
/// Replaces C `appkey_key_add()`.
pub fn appkey_key_add(net: &mut MeshNet, net_idx: u16, app_idx: u16, new_key: &[u8; 16]) -> i32 {
    // Check for an existing key with the same app_idx.
    if let Some(existing) = net.get_app_keys().iter().find(|k| k.app_idx == app_idx) {
        if existing.net_idx != net_idx {
            return i32::from(MESH_STATUS_INVALID_NETKEY);
        } else if new_key == &existing.key {
            return i32::from(MESH_STATUS_SUCCESS);
        } else {
            return i32::from(MESH_STATUS_IDX_ALREADY_STORED);
        }
    }

    // The bound network key must exist.
    if !net.have_key(net_idx) {
        return i32::from(MESH_STATUS_INVALID_NETKEY);
    }

    // Enforce maximum key count.
    if net.get_app_keys().len() >= MAX_APP_KEYS {
        return i32::from(MESH_STATUS_INSUFF_RESOURCES);
    }

    // Create and initialise the new key entry.
    let mut key = MeshAppKey::new();
    if !set_key(&mut key, new_key, false) {
        return i32::from(MESH_STATUS_INSUFF_RESOURCES);
    }

    // Persist to configuration storage.
    let config = net.get_config().cloned();
    if let Some(cfg_arc) = config {
        if let Ok(mut cfg_guard) = cfg_arc.lock() {
            if cfg_guard.app_key_add(net_idx, app_idx, new_key).is_err() {
                return i32::from(MESH_STATUS_STORAGE_FAIL);
            }
        } else {
            return i32::from(MESH_STATUS_STORAGE_FAIL);
        }
    }

    key.net_idx = net_idx;
    key.app_idx = app_idx;
    net.get_app_keys_mut().push(key);

    i32::from(MESH_STATUS_SUCCESS)
}

/// Update an existing application key during Key Refresh Phase One.
///
/// Validates that:
/// - The app key exists and is bound to `net_idx`.
/// - Key Refresh Phase One is active for the bound network key.
/// - The new key material differs from the previously-set new key (or
///   returns success if identical for idempotence).
///
/// On success the new key + AID are stored and persisted via
/// [`MeshConfig::app_key_update`].
///
/// Replaces C `appkey_key_update()`.
pub fn appkey_key_update(net: &mut MeshNet, net_idx: u16, app_idx: u16, new_key: &[u8; 16]) -> i32 {
    // Validate the bound network key exists.
    if !net.have_key(net_idx) {
        return i32::from(MESH_STATUS_INVALID_NETKEY);
    }

    // Find the existing app key.
    let key_pos = match net.get_app_keys().iter().position(|k| k.app_idx == app_idx) {
        Some(pos) => pos,
        None => return i32::from(MESH_STATUS_INVALID_APPKEY),
    };

    // Verify binding.
    if net.get_app_keys()[key_pos].net_idx != net_idx {
        return i32::from(MESH_STATUS_INVALID_BINDING);
    }

    // Key Refresh must be in Phase One to accept updates.
    let phase = net.key_refresh_phase_get(net_idx);
    if phase != KEY_REFRESH_PHASE_ONE {
        return i32::from(MESH_STATUS_CANNOT_UPDATE);
    }

    // Idempotence: if the new key material is already stored, succeed silently.
    if new_key == &net.get_app_keys()[key_pos].new_key {
        return i32::from(MESH_STATUS_SUCCESS);
    }

    // Derive AID and store the new key material.
    {
        let keys = net.get_app_keys_mut();
        if !set_key(&mut keys[key_pos], new_key, true) {
            return i32::from(MESH_STATUS_INSUFF_RESOURCES);
        }
    }

    // Persist the update.
    let config = net.get_config().cloned();
    if let Some(cfg_arc) = config {
        if let Ok(mut cfg_guard) = cfg_arc.lock() {
            if cfg_guard.app_key_update(net_idx, app_idx, new_key).is_err() {
                return i32::from(MESH_STATUS_STORAGE_FAIL);
            }
        } else {
            return i32::from(MESH_STATUS_STORAGE_FAIL);
        }
    }

    i32::from(MESH_STATUS_SUCCESS)
}

/// Delete an application key.
///
/// Per the Mesh spec, deleting a non-existent key returns success. If the
/// key exists but is bound to a different `net_idx`, returns
/// `MESH_STATUS_INVALID_NETKEY`.
///
/// On success the key is removed from the network's vector and the deletion
/// is persisted via [`MeshConfig::app_key_del`].
///
/// Replaces C `appkey_key_delete()`.
pub fn appkey_key_delete(net: &mut MeshNet, net_idx: u16, app_idx: u16) -> i32 {
    // Find the key position.
    let key_pos = match net.get_app_keys().iter().position(|k| k.app_idx == app_idx) {
        Some(pos) => pos,
        // Per spec: deleting a non-existent key is not an error.
        None => return i32::from(MESH_STATUS_SUCCESS),
    };

    // Verify binding matches.
    if net.get_app_keys()[key_pos].net_idx != net_idx {
        return i32::from(MESH_STATUS_INVALID_NETKEY);
    }

    // Remove the key from the vector.
    let _removed = net.get_app_keys_mut().remove(key_pos);

    // Persist the deletion.
    let config = net.get_config().cloned();
    if let Some(cfg_arc) = config {
        if let Ok(mut cfg_guard) = cfg_arc.lock() {
            if cfg_guard.app_key_del(net_idx, app_idx).is_err() {
                return i32::from(MESH_STATUS_STORAGE_FAIL);
            }
        } else {
            return i32::from(MESH_STATUS_STORAGE_FAIL);
        }
    }

    i32::from(MESH_STATUS_SUCCESS)
}

/// Delete all application keys bound to the given network key index.
///
/// Iterates the key list, removes every key whose `net_idx` matches, and
/// persists each deletion. This is called when a network key is deleted to
/// cascade the removal.
///
/// Replaces C `appkey_delete_bound_keys()` which used `l_queue_remove_if`
/// in a loop.
pub fn appkey_delete_bound_keys(net: &mut MeshNet, net_idx: u16) {
    // Collect indices of keys to remove (to avoid borrowing conflicts).
    let to_remove: Vec<u16> =
        net.get_app_keys().iter().filter(|k| k.net_idx == net_idx).map(|k| k.app_idx).collect();

    if to_remove.is_empty() {
        return;
    }

    // Persist each deletion.
    let config = net.get_config().cloned();
    if let Some(cfg_arc) = config {
        if let Ok(mut cfg_guard) = cfg_arc.lock() {
            for &app_idx in &to_remove {
                let _ = cfg_guard.app_key_del(net_idx, app_idx);
            }
        }
    }

    // Remove all matching keys from the vector.
    net.get_app_keys_mut().retain(|k| k.net_idx != net_idx);
}

// ===========================================================================
// Key Listing
// ===========================================================================

/// Pack application key indices bound to `net_idx` into `buf` for a Config
/// AppKey List response.
///
/// The Mesh Profile specification encodes key indices in a packed 12-bit
/// format:
/// - Pairs of indices are packed into 3 bytes (24 bits): the first index
///   occupies bits [23:12] and the second index bits [11:0], stored in
///   little-endian byte order.
/// - A trailing single index (odd count) is packed into 2 bytes (16 bits)
///   in little-endian order.
///
/// Returns `(status, packed_size)` where `status` is the mesh status code
/// and `packed_size` is the number of bytes written to `buf`.
///
/// Replaces C `appkey_list()`.
pub fn appkey_list(net: &MeshNet, net_idx: u16, buf: &mut [u8]) -> (u8, u16) {
    if !net.have_key(net_idx) {
        return (MESH_STATUS_INVALID_NETKEY, 0);
    }

    let app_keys = net.get_app_keys();
    if app_keys.is_empty() {
        return (MESH_STATUS_SUCCESS, 0);
    }

    let buf_size = buf.len() as u16;
    let mut idx_pair: u32 = 0;
    let mut i: usize = 0;
    let mut datalen: u16 = 0;

    for key in app_keys {
        if key.net_idx != net_idx {
            continue;
        }

        if (i & 1) == 0 {
            // First index of a pair — stash it.
            idx_pair = u32::from(key.app_idx);
        } else {
            // Second index — pack the pair into 3 bytes LE.
            idx_pair = (idx_pair << 12) + u32::from(key.app_idx);

            // Check buffer capacity before writing.
            if datalen + 3 > buf_size {
                warn!("Appkey list too large");
                return (MESH_STATUS_SUCCESS, datalen);
            }

            let le_bytes = idx_pair.to_le_bytes();
            buf[datalen as usize] = le_bytes[0];
            buf[(datalen + 1) as usize] = le_bytes[1];
            buf[(datalen + 2) as usize] = le_bytes[2];
            datalen += 3;
        }
        i += 1;
    }

    // Process the last app key if there is an odd count.
    if (i & 1) == 1 && (datalen + 2) <= buf_size {
        let le_bytes = (idx_pair as u16).to_le_bytes();
        buf[datalen as usize] = le_bytes[0];
        buf[(datalen + 1) as usize] = le_bytes[1];
        datalen += 2;
    }

    (MESH_STATUS_SUCCESS, datalen)
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{
        MESH_STATUS_CANNOT_UPDATE, MESH_STATUS_IDX_ALREADY_STORED, MESH_STATUS_INSUFF_RESOURCES,
        MESH_STATUS_INVALID_APPKEY, MESH_STATUS_INVALID_BINDING, MESH_STATUS_INVALID_NETKEY,
        MESH_STATUS_SUCCESS, NET_IDX_INVALID,
    };

    // All tests use `#[tokio::test]` because `MeshNet::add_key()` internally
    // calls `net_key_beacon_enable()` which schedules a tokio timer, requiring
    // a reactor to be present.

    /// Helper: create a MeshNet with a single subnet at the given net_idx.
    fn make_net_with_subnet(net_idx: u16) -> MeshNet {
        let mut net = MeshNet::new();
        let key = [0x11u8; 16];
        let status = net.add_key(net_idx, &key);
        assert_eq!(status, MESH_STATUS_SUCCESS, "add_key should succeed");
        net
    }

    // =====================================================================
    // Constants
    // =====================================================================

    #[tokio::test]
    async fn test_max_app_keys_constant() {
        assert_eq!(MAX_APP_KEYS, 32);
    }

    // =====================================================================
    // MeshAppKey struct
    // =====================================================================

    #[tokio::test]
    async fn test_mesh_app_key_fields() {
        let key = MeshAppKey {
            app_idx: 0x100,
            net_idx: 0x200,
            key: [0xAA; 16],
            new_key: [0xBB; 16],
            key_aid: 0x42,
            new_key_aid: 0x43,
        };
        assert_eq!(key.app_idx, 0x100);
        assert_eq!(key.net_idx, 0x200);
        assert_eq!(key.key, [0xAA; 16]);
        assert_eq!(key.new_key, [0xBB; 16]);
        assert_eq!(key.key_aid, 0x42);
        assert_eq!(key.new_key_aid, 0x43);
    }

    #[tokio::test]
    async fn test_appkey_key_free_is_noop() {
        let key = MeshAppKey {
            app_idx: 1,
            net_idx: 0,
            key: [0u8; 16],
            new_key: [0u8; 16],
            key_aid: 0,
            new_key_aid: APP_AID_INVALID,
        };
        appkey_key_free(key); // Should not panic
    }

    // =====================================================================
    // appkey_key_init
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_key_init_success() {
        let mut net = make_net_with_subnet(0);
        let app_key = [0x22u8; 16];
        assert!(appkey_key_init(&mut net, 0, 0, &app_key, None));
        assert!(appkey_have_key(&net, 0));
    }

    #[tokio::test]
    async fn test_appkey_key_init_with_new_key() {
        let mut net = make_net_with_subnet(0);
        let app_key = [0x22u8; 16];
        let new_key = [0x33u8; 16];
        assert!(appkey_key_init(&mut net, 0, 1, &app_key, Some(&new_key)));
        assert!(appkey_have_key(&net, 1));

        let entry = &net.get_app_keys()[0];
        assert_eq!(entry.key, app_key);
        assert_eq!(entry.new_key, new_key);
        assert_ne!(entry.new_key_aid, APP_AID_INVALID);
    }

    #[tokio::test]
    async fn test_appkey_key_init_invalid_net_idx() {
        let mut net = make_net_with_subnet(0);
        let app_key = [0x22u8; 16];
        assert!(!appkey_key_init(&mut net, 99, 0, &app_key, None));
    }

    #[tokio::test]
    async fn test_appkey_key_init_out_of_range_idx() {
        let mut net = make_net_with_subnet(0);
        let app_key = [0x22u8; 16];
        assert!(!appkey_key_init(&mut net, 0, 0x1000, &app_key, None));
        assert!(!appkey_key_init(&mut net, 0x1000, 0, &app_key, None));
    }

    // =====================================================================
    // appkey_key_add
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_key_add_success() {
        let mut net = make_net_with_subnet(0);
        let key = [0x44u8; 16];
        let status = appkey_key_add(&mut net, 0, 5, &key);
        assert_eq!(status, i32::from(MESH_STATUS_SUCCESS));
        assert!(appkey_have_key(&net, 5));
    }

    #[tokio::test]
    async fn test_appkey_key_add_idempotent() {
        let mut net = make_net_with_subnet(0);
        let key = [0x44u8; 16];
        assert_eq!(appkey_key_add(&mut net, 0, 5, &key), i32::from(MESH_STATUS_SUCCESS));
        assert_eq!(appkey_key_add(&mut net, 0, 5, &key), i32::from(MESH_STATUS_SUCCESS));
        assert_eq!(net.get_app_keys().len(), 1);
    }

    #[tokio::test]
    async fn test_appkey_key_add_different_key_same_idx() {
        let mut net = make_net_with_subnet(0);
        let key1 = [0x44u8; 16];
        let key2 = [0x55u8; 16];
        assert_eq!(appkey_key_add(&mut net, 0, 5, &key1), i32::from(MESH_STATUS_SUCCESS));
        assert_eq!(
            appkey_key_add(&mut net, 0, 5, &key2),
            i32::from(MESH_STATUS_IDX_ALREADY_STORED)
        );
    }

    #[tokio::test]
    async fn test_appkey_key_add_invalid_netkey() {
        let mut net = make_net_with_subnet(0);
        let key = [0x44u8; 16];
        assert_eq!(appkey_key_add(&mut net, 99, 5, &key), i32::from(MESH_STATUS_INVALID_NETKEY));
    }

    #[tokio::test]
    async fn test_appkey_key_add_wrong_netkey_binding() {
        let mut net = make_net_with_subnet(0);
        let key2 = [0x99u8; 16];
        net.add_key(1, &key2);
        let app_key = [0x44u8; 16];
        assert_eq!(appkey_key_add(&mut net, 0, 5, &app_key), i32::from(MESH_STATUS_SUCCESS));
        assert_eq!(appkey_key_add(&mut net, 1, 5, &app_key), i32::from(MESH_STATUS_INVALID_NETKEY));
    }

    #[tokio::test]
    async fn test_appkey_key_add_max_keys() {
        let mut net = make_net_with_subnet(0);
        for i in 0..MAX_APP_KEYS {
            let mut key = [0u8; 16];
            key[0] = (i & 0xff) as u8;
            key[1] = ((i >> 8) & 0xff) as u8;
            let status = appkey_key_add(&mut net, 0, i as u16, &key);
            assert_eq!(status, i32::from(MESH_STATUS_SUCCESS), "add key {i} should succeed");
        }
        let extra = [0xFFu8; 16];
        assert_eq!(
            appkey_key_add(&mut net, 0, MAX_APP_KEYS as u16, &extra),
            i32::from(MESH_STATUS_INSUFF_RESOURCES)
        );
    }

    // =====================================================================
    // appkey_get_key / appkey_get_key_idx
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_get_key() {
        let mut net = make_net_with_subnet(0);
        let key_val = [0x55u8; 16];
        appkey_key_add(&mut net, 0, 10, &key_val);
        let result = appkey_get_key(&net, 10);
        assert!(result.is_some());
        let (k, aid) = result.unwrap();
        assert_eq!(*k, key_val);
        assert_ne!(aid, APP_AID_INVALID);
        assert_ne!(aid & KEY_ID_AKF, 0);
    }

    #[tokio::test]
    async fn test_appkey_get_key_nonexistent() {
        let net = make_net_with_subnet(0);
        assert!(appkey_get_key(&net, 999).is_none());
    }

    #[tokio::test]
    async fn test_appkey_get_key_idx() {
        let mut net = make_net_with_subnet(0);
        let key_val = [0x66u8; 16];
        appkey_key_add(&mut net, 0, 20, &key_val);
        let entry = &net.get_app_keys()[0];
        let (key, aid, new_key, new_aid) = appkey_get_key_idx(entry);
        assert!(key.is_some());
        assert_eq!(*key.unwrap(), key_val);
        assert_ne!(aid, APP_AID_INVALID);
        assert_eq!(new_aid, APP_AID_INVALID);
        assert!(new_key.is_some());
    }

    // =====================================================================
    // appkey_have_key / appkey_net_idx
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_have_key() {
        let mut net = make_net_with_subnet(0);
        assert!(!appkey_have_key(&net, 0));
        appkey_key_add(&mut net, 0, 0, &[0x77u8; 16]);
        assert!(appkey_have_key(&net, 0));
    }

    #[tokio::test]
    async fn test_appkey_net_idx() {
        let mut net = make_net_with_subnet(0);
        assert_eq!(appkey_net_idx(&net, 0), NET_IDX_INVALID);
        appkey_key_add(&mut net, 0, 0, &[0x88u8; 16]);
        assert_eq!(appkey_net_idx(&net, 0), 0);
    }

    // =====================================================================
    // appkey_key_delete
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_key_delete_success() {
        let mut net = make_net_with_subnet(0);
        appkey_key_add(&mut net, 0, 5, &[0xAAu8; 16]);
        assert!(appkey_have_key(&net, 5));
        let status = appkey_key_delete(&mut net, 0, 5);
        assert_eq!(status, i32::from(MESH_STATUS_SUCCESS));
        assert!(!appkey_have_key(&net, 5));
    }

    #[tokio::test]
    async fn test_appkey_key_delete_nonexistent() {
        let mut net = make_net_with_subnet(0);
        assert_eq!(appkey_key_delete(&mut net, 0, 999), i32::from(MESH_STATUS_SUCCESS));
    }

    #[tokio::test]
    async fn test_appkey_key_delete_wrong_netkey() {
        let mut net = make_net_with_subnet(0);
        let key2 = [0x99u8; 16];
        net.add_key(1, &key2);
        appkey_key_add(&mut net, 0, 5, &[0xBBu8; 16]);
        assert_eq!(appkey_key_delete(&mut net, 1, 5), i32::from(MESH_STATUS_INVALID_NETKEY));
        assert!(appkey_have_key(&net, 5));
    }

    // =====================================================================
    // appkey_delete_bound_keys
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_delete_bound_keys() {
        let mut net = make_net_with_subnet(0);
        let key2 = [0x99u8; 16];
        net.add_key(1, &key2);
        appkey_key_add(&mut net, 0, 10, &[0xA0u8; 16]);
        appkey_key_add(&mut net, 0, 11, &[0xA1u8; 16]);
        appkey_key_add(&mut net, 1, 20, &[0xB0u8; 16]);

        assert_eq!(net.get_app_keys().len(), 3);
        appkey_delete_bound_keys(&mut net, 0);
        assert_eq!(net.get_app_keys().len(), 1);
        assert!(!appkey_have_key(&net, 10));
        assert!(!appkey_have_key(&net, 11));
        assert!(appkey_have_key(&net, 20));
    }

    // =====================================================================
    // appkey_key_update
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_key_update_no_phase_one() {
        let mut net = make_net_with_subnet(0);
        appkey_key_add(&mut net, 0, 5, &[0xCCu8; 16]);
        let new_key = [0xDDu8; 16];
        assert_eq!(
            appkey_key_update(&mut net, 0, 5, &new_key),
            i32::from(MESH_STATUS_CANNOT_UPDATE)
        );
    }

    #[tokio::test]
    async fn test_appkey_key_update_nonexistent() {
        let mut net = make_net_with_subnet(0);
        assert_eq!(
            appkey_key_update(&mut net, 0, 999, &[0xEEu8; 16]),
            i32::from(MESH_STATUS_INVALID_APPKEY)
        );
    }

    #[tokio::test]
    async fn test_appkey_key_update_invalid_netkey() {
        let mut net = make_net_with_subnet(0);
        assert_eq!(
            appkey_key_update(&mut net, 99, 5, &[0xEEu8; 16]),
            i32::from(MESH_STATUS_INVALID_NETKEY)
        );
    }

    #[tokio::test]
    async fn test_appkey_key_update_wrong_binding() {
        let mut net = make_net_with_subnet(0);
        let key2 = [0x99u8; 16];
        net.add_key(1, &key2);
        appkey_key_add(&mut net, 0, 5, &[0xCCu8; 16]);
        assert_eq!(
            appkey_key_update(&mut net, 1, 5, &[0xDDu8; 16]),
            i32::from(MESH_STATUS_INVALID_BINDING)
        );
    }

    // =====================================================================
    // appkey_finalize
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_finalize_promotes_new_key() {
        let mut net = make_net_with_subnet(0);
        let current_key = [0x11u8; 16];
        let new_key = [0x22u8; 16];
        assert!(appkey_key_init(&mut net, 0, 5, &current_key, Some(&new_key)));

        let entry_before = net.get_app_keys()[0].clone();
        assert_ne!(entry_before.new_key_aid, APP_AID_INVALID);

        appkey_finalize(&mut net, 0);

        let entry_after = &net.get_app_keys()[0];
        assert_eq!(entry_after.key, new_key);
        assert_eq!(entry_after.key_aid, entry_before.new_key_aid);
        assert_eq!(entry_after.new_key_aid, APP_AID_INVALID);
    }

    #[tokio::test]
    async fn test_appkey_finalize_no_new_key_is_noop() {
        let mut net = make_net_with_subnet(0);
        let current_key = [0x11u8; 16];
        assert!(appkey_key_init(&mut net, 0, 5, &current_key, None));

        let entry_before = net.get_app_keys()[0].clone();
        assert_eq!(entry_before.new_key_aid, APP_AID_INVALID);

        appkey_finalize(&mut net, 0);

        let entry_after = &net.get_app_keys()[0];
        assert_eq!(entry_after.key, current_key);
        assert_eq!(entry_after.key_aid, entry_before.key_aid);
    }

    // =====================================================================
    // appkey_list — index packing
    // =====================================================================

    #[tokio::test]
    async fn test_appkey_list_empty() {
        let net = make_net_with_subnet(0);
        let mut buf = [0u8; 64];
        let (status, size) = appkey_list(&net, 0, &mut buf);
        assert_eq!(status, MESH_STATUS_SUCCESS);
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_appkey_list_invalid_netkey() {
        let net = make_net_with_subnet(0);
        let mut buf = [0u8; 64];
        let (status, _) = appkey_list(&net, 99, &mut buf);
        assert_eq!(status, MESH_STATUS_INVALID_NETKEY);
    }

    #[tokio::test]
    async fn test_appkey_list_single_key() {
        let mut net = make_net_with_subnet(0);
        appkey_key_add(&mut net, 0, 0x123, &[0xAAu8; 16]);
        let mut buf = [0u8; 64];
        let (status, size) = appkey_list(&net, 0, &mut buf);
        assert_eq!(status, MESH_STATUS_SUCCESS);
        assert_eq!(size, 2);
        let packed = u16::from_le_bytes([buf[0], buf[1]]);
        assert_eq!(packed, 0x123);
    }

    #[tokio::test]
    async fn test_appkey_list_two_keys() {
        let mut net = make_net_with_subnet(0);
        appkey_key_add(&mut net, 0, 0x001, &[0xA1u8; 16]);
        appkey_key_add(&mut net, 0, 0x002, &[0xA2u8; 16]);
        let mut buf = [0u8; 64];
        let (status, size) = appkey_list(&net, 0, &mut buf);
        assert_eq!(status, MESH_STATUS_SUCCESS);
        assert_eq!(size, 3);
        let packed_val = u32::from_le_bytes([buf[0], buf[1], buf[2], 0]);
        assert_eq!(packed_val, 0x1002);
    }

    #[tokio::test]
    async fn test_appkey_list_three_keys() {
        let mut net = make_net_with_subnet(0);
        appkey_key_add(&mut net, 0, 0x010, &[0xB1u8; 16]);
        appkey_key_add(&mut net, 0, 0x020, &[0xB2u8; 16]);
        appkey_key_add(&mut net, 0, 0x030, &[0xB3u8; 16]);
        let mut buf = [0u8; 64];
        let (status, size) = appkey_list(&net, 0, &mut buf);
        assert_eq!(status, MESH_STATUS_SUCCESS);
        assert_eq!(size, 5);
        let pair = u32::from_le_bytes([buf[0], buf[1], buf[2], 0]);
        assert_eq!(pair, 0x10020);
        let trailing = u16::from_le_bytes([buf[3], buf[4]]);
        assert_eq!(trailing, 0x030);
    }

    #[tokio::test]
    async fn test_appkey_list_only_matching_netkey() {
        let mut net = make_net_with_subnet(0);
        let key2 = [0x99u8; 16];
        net.add_key(1, &key2);
        appkey_key_add(&mut net, 0, 0x100, &[0xC1u8; 16]);
        appkey_key_add(&mut net, 1, 0x200, &[0xC2u8; 16]);
        appkey_key_add(&mut net, 0, 0x101, &[0xC3u8; 16]);

        let mut buf = [0u8; 64];
        let (status, size) = appkey_list(&net, 0, &mut buf);
        assert_eq!(status, MESH_STATUS_SUCCESS);
        assert_eq!(size, 3);

        let (status2, size2) = appkey_list(&net, 1, &mut buf);
        assert_eq!(status2, MESH_STATUS_SUCCESS);
        assert_eq!(size2, 2);
        let packed = u16::from_le_bytes([buf[0], buf[1]]);
        assert_eq!(packed, 0x200);
    }

    // =====================================================================
    // AID derivation correctness
    // =====================================================================

    #[tokio::test]
    async fn test_aid_has_akf_bit_set() {
        let mut net = make_net_with_subnet(0);
        let key_val = [0xDDu8; 16];
        appkey_key_add(&mut net, 0, 7, &key_val);
        let entry = &net.get_app_keys()[0];
        assert_ne!(entry.key_aid & KEY_ID_AKF, 0);
        assert!(entry.key_aid <= 0x7f);
    }

    #[tokio::test]
    async fn test_aid_consistency() {
        let mut net = make_net_with_subnet(0);
        let key_val = [0xEEu8; 16];
        appkey_key_init(&mut net, 0, 1, &key_val, None);
        appkey_key_init(&mut net, 0, 2, &key_val, None);
        let aid1 = net.get_app_keys()[0].key_aid;
        let aid2 = net.get_app_keys()[1].key_aid;
        assert_eq!(aid1, aid2);
    }
}
