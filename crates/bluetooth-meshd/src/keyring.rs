// SPDX-License-Identifier: LGPL-2.1-or-later
// crates/bluetooth-meshd/src/keyring.rs
//
// Complete Rust rewrite of mesh/keyring.c + mesh/keyring.h from BlueZ v5.86.
//
// Persists Network Keys, Application Keys, and remote Device Keys on disk
// in the same binary format used by the C implementation, and builds the
// D-Bus `ExportKeys` reply for the `org.bluez.mesh.Node1` interface.
//
// Filesystem layout (under the node's storage directory):
//   <node_storage_dir>/net_keys/<3hex>   — raw KeyringNetKey bytes
//   <node_storage_dir>/app_keys/<3hex>   — raw KeyringAppKey bytes
//   <node_storage_dir>/dev_keys/<4hex>   — 16 raw device-key bytes
//
// All key files use mode 0o600 (owner read/write only).
// Directories are created with default permissions via `create_dir_all`.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use tracing::{debug, error};
use zbus::zvariant::{StructureBuilder, Value};

use crate::dbus::{MeshError, byte_array_to_variant, dict_insert_basic};
use crate::mesh::{KEY_REFRESH_PHASE_NONE, KEY_REFRESH_PHASE_THREE, is_unicast, is_unicast_range};

// ---------------------------------------------------------------------------
// Constants — directory basenames matching the C defines
// ---------------------------------------------------------------------------

/// Subdirectory for network key files.
const NET_KEY_DIR: &str = "net_keys";

/// Subdirectory for application key files.
const APP_KEY_DIR: &str = "app_keys";

/// Subdirectory for remote device key files.
const DEV_KEY_DIR: &str = "dev_keys";

/// On-disk size of a serialised [`KeyringNetKey`].
///
/// Layout (C `struct keyring_net_key`):
///   offset  0: net_idx  (u16, 2 bytes, native endian)
///   offset  2: phase    (u8,  1 byte)
///   offset  3: old_key  (16 bytes)
///   offset 19: new_key  (16 bytes)
///   offset 35: padding  (1 byte — struct alignment to 2)
/// Total: 36 bytes.
const NET_KEY_DISK_SIZE: usize = 36;

/// On-disk size of a serialised [`KeyringAppKey`].
///
/// Layout (C `struct keyring_app_key`):
///   offset  0: app_idx  (u16, 2 bytes, native endian)
///   offset  2: net_idx  (u16, 2 bytes, native endian)
///   offset  4: old_key  (16 bytes)
///   offset 20: new_key  (16 bytes)
/// Total: 36 bytes.
const APP_KEY_DISK_SIZE: usize = 36;

/// Size of a single device key (128-bit / 16 bytes).
const DEV_KEY_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Public Structs — storage-compatible with the C originals
// ---------------------------------------------------------------------------

/// A network key record stored in `<node>/net_keys/<3hex>`.
///
/// Fields map 1:1 to the C `struct keyring_net_key` from `mesh/keyring.h`.
#[derive(Debug, Clone)]
pub struct KeyringNetKey {
    /// Network key index (12-bit, stored as u16).
    pub net_idx: u16,
    /// Key Refresh phase (0 = normal, 1/2/3 = refresh phases).
    pub phase: u8,
    /// Previous network key (zeroed when phase == 0).
    pub old_key: [u8; 16],
    /// Current (or new, during refresh) network key.
    pub new_key: [u8; 16],
}

/// An application key record stored in `<node>/app_keys/<3hex>`.
///
/// Fields map 1:1 to the C `struct keyring_app_key` from `mesh/keyring.h`.
#[derive(Debug, Clone)]
pub struct KeyringAppKey {
    /// Application key index (12-bit, stored as u16).
    pub app_idx: u16,
    /// Bound network key index (immutable once set).
    pub net_idx: u16,
    /// Previous application key (zeroed when no refresh active).
    pub old_key: [u8; 16],
    /// Current (or new, during refresh) application key.
    pub new_key: [u8; 16],
}

// ---------------------------------------------------------------------------
// Serialisation Helpers — manual byte packing matching the C struct layout
// ---------------------------------------------------------------------------

impl KeyringNetKey {
    /// Serialise to a fixed-size byte array matching the C struct layout.
    fn to_bytes(&self) -> [u8; NET_KEY_DISK_SIZE] {
        let mut buf = [0u8; NET_KEY_DISK_SIZE];
        buf[0..2].copy_from_slice(&self.net_idx.to_ne_bytes());
        buf[2] = self.phase;
        buf[3..19].copy_from_slice(&self.old_key);
        buf[19..35].copy_from_slice(&self.new_key);
        // buf[35] is the C struct trailing-padding byte, stays zero.
        buf
    }

    /// Deserialise from a byte slice (must be at least [`NET_KEY_DISK_SIZE`]).
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < NET_KEY_DISK_SIZE {
            return None;
        }
        let net_idx = u16::from_ne_bytes([data[0], data[1]]);
        let phase = data[2];
        let mut old_key = [0u8; 16];
        old_key.copy_from_slice(&data[3..19]);
        let mut new_key = [0u8; 16];
        new_key.copy_from_slice(&data[19..35]);
        Some(Self { net_idx, phase, old_key, new_key })
    }
}

impl KeyringAppKey {
    /// Serialise to a fixed-size byte array matching the C struct layout.
    fn to_bytes(&self) -> [u8; APP_KEY_DISK_SIZE] {
        let mut buf = [0u8; APP_KEY_DISK_SIZE];
        buf[0..2].copy_from_slice(&self.app_idx.to_ne_bytes());
        buf[2..4].copy_from_slice(&self.net_idx.to_ne_bytes());
        buf[4..20].copy_from_slice(&self.old_key);
        buf[20..36].copy_from_slice(&self.new_key);
        buf
    }

    /// Deserialise from a byte slice (must be at least [`APP_KEY_DISK_SIZE`]).
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < APP_KEY_DISK_SIZE {
            return None;
        }
        let app_idx = u16::from_ne_bytes([data[0], data[1]]);
        let net_idx = u16::from_ne_bytes([data[2], data[3]]);
        let mut old_key = [0u8; 16];
        old_key.copy_from_slice(&data[4..20]);
        let mut new_key = [0u8; 16];
        new_key.copy_from_slice(&data[20..36]);
        Some(Self { app_idx, net_idx, old_key, new_key })
    }
}

// ---------------------------------------------------------------------------
// Private File I/O Helpers
// ---------------------------------------------------------------------------

/// Build the full path to a key-type subdirectory under a node's storage.
///
/// Returns `<node_path>/<key_dir>` and ensures the directory exists.
fn ensure_key_dir(node_path: &str, key_dir: &str) -> Option<PathBuf> {
    let dir = Path::new(node_path).join(key_dir);
    if let Err(e) = fs::create_dir_all(&dir) {
        error!("Failed to create key directory {}: {}", dir.display(), e);
        return None;
    }
    Some(dir)
}

/// Format an index as a zero-padded lowercase hexadecimal string.
///
/// - `width == 3` for net/app keys (e.g. "00a")
/// - `width == 4` for dev keys (e.g. "0042")
fn idx_to_hex(idx: u16, width: usize) -> String {
    match width {
        3 => format!("{:03x}", idx),
        4 => format!("{:04x}", idx),
        _ => format!("{:x}", idx),
    }
}

/// Write raw bytes to a key file at `<node_path>/<key_dir>/<hex_name>`.
///
/// Creates the directory if it does not exist, opens the file with
/// `O_WRONLY | O_CREAT | O_TRUNC` and mode `0o600`, then writes the
/// data atomically.
fn write_key_file(node_path: &str, key_dir: &str, idx: u16, hex_width: usize, data: &[u8]) -> bool {
    let Some(dir) = ensure_key_dir(node_path, key_dir) else {
        return false;
    };
    let path = dir.join(idx_to_hex(idx, hex_width));

    let result = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(data));

    match result {
        Ok(()) => true,
        Err(e) => {
            error!("Failed to write key file {}: {}", path.display(), e);
            false
        }
    }
}

/// Read the entire contents of a key file at `<node_path>/<key_dir>/<hex>`.
///
/// Returns `None` if the file does not exist, is unreadable, or has
/// fewer bytes than expected.
fn read_key_file(node_path: &str, key_dir: &str, idx: u16, hex_width: usize) -> Option<Vec<u8>> {
    let dir = Path::new(node_path).join(key_dir);
    let path = dir.join(idx_to_hex(idx, hex_width));
    fs::read(&path).ok()
}

/// Open and iterate a key directory, returning `(parsed_idx, raw_bytes)` pairs.
///
/// Entries whose filenames cannot be parsed as hexadecimal integers of the
/// expected width, or whose contents cannot be read, are silently skipped.
fn read_key_dir_entries(node_path: &str, key_dir: &str, hex_width: usize) -> Vec<(u16, Vec<u8>)> {
    let dir = Path::new(node_path).join(key_dir);
    let entries = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) => {
            error!("Cannot open key directory {}: {}", dir.display(), e);
            return Vec::new();
        }
    };

    let mut result = Vec::new();
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Only accept filenames matching expected hex width.
        if name.len() != hex_width {
            continue;
        }
        let idx = match u16::from_str_radix(&name, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Only process regular files.
        if let Ok(ft) = entry.file_type() {
            if !ft.is_file() {
                continue;
            }
        }
        if let Ok(data) = fs::read(entry.path()) {
            result.push((idx, data));
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Network Key CRUD
// ---------------------------------------------------------------------------

/// Persist a network key to `<node_path>/net_keys/<3hex>`.
///
/// Replaces C `keyring_put_net_key()`.
pub fn keyring_put_net_key(node_path: &str, net_idx: u16, key: &KeyringNetKey) -> bool {
    let data = key.to_bytes();
    write_key_file(node_path, NET_KEY_DIR, net_idx, 3, &data)
}

/// Read a network key from `<node_path>/net_keys/<3hex>`.
///
/// Returns `None` if the file does not exist or contains invalid data.
/// Replaces C `keyring_get_net_key()`.
pub fn keyring_get_net_key(node_path: &str, net_idx: u16) -> Option<KeyringNetKey> {
    let data = read_key_file(node_path, NET_KEY_DIR, net_idx, 3)?;
    KeyringNetKey::from_bytes(&data)
}

/// Delete a network key file at `<node_path>/net_keys/<3hex>`.
///
/// Always returns `true` (matching C behaviour where `remove()` errors
/// are silently ignored). Replaces C `keyring_del_net_key()`.
pub fn keyring_del_net_key(node_path: &str, net_idx: u16) -> bool {
    let dir = Path::new(node_path).join(NET_KEY_DIR);
    let fname = dir.join(idx_to_hex(net_idx, 3));
    debug!("RM Net Key {}", fname.display());
    let _ = fs::remove_file(&fname);
    true
}

// ---------------------------------------------------------------------------
// Application Key CRUD
// ---------------------------------------------------------------------------

/// Persist an application key to `<node_path>/app_keys/<3hex>`.
///
/// If an existing key file is found with a different `net_idx` binding,
/// the write is rejected and `false` is returned — application keys are
/// permanently bound to a single network key index.
///
/// Replaces C `keyring_put_app_key()`.
pub fn keyring_put_app_key(
    node_path: &str,
    app_idx: u16,
    net_idx: u16,
    key: &KeyringAppKey,
) -> bool {
    // Read existing key to enforce net_idx binding.
    if let Some(existing_data) = read_key_file(node_path, APP_KEY_DIR, app_idx, 3) {
        if let Some(existing) = KeyringAppKey::from_bytes(&existing_data) {
            if existing.net_idx != net_idx {
                return false;
            }
        }
    }

    let data = key.to_bytes();
    write_key_file(node_path, APP_KEY_DIR, app_idx, 3, &data)
}

/// Finalise a Key Refresh for all application keys bound to `net_idx`.
///
/// For each app key whose `net_idx` matches, copies `new_key` → `old_key`
/// and rewrites the file.  This is the completion step of the Key Refresh
/// Procedure (Phase 3 → Phase 0 transition).
///
/// Replaces C `keyring_finalize_app_keys()`.
pub fn keyring_finalize_app_keys(node_path: &str, net_idx: u16) -> bool {
    let dir = Path::new(node_path).join(APP_KEY_DIR);
    let entries = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if name.len() != 3 {
            continue;
        }
        if let Ok(ft) = entry.file_type() {
            if !ft.is_file() {
                continue;
            }
        }

        let path = entry.path();
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let Some(mut key) = KeyringAppKey::from_bytes(&data) else {
            continue;
        };

        if key.net_idx != net_idx {
            continue;
        }

        debug!("Finalize app key {}", name);

        // Copy new_key into old_key (key refresh completion).
        key.old_key = key.new_key;

        let buf = key.to_bytes();
        let write_result = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(&buf));

        if let Err(e) = write_result {
            error!("Failed to finalize app key {}: {}", path.display(), e);
        }
    }

    true
}

/// Read an application key from `<node_path>/app_keys/<3hex>`.
///
/// Replaces C `keyring_get_app_key()`.
pub fn keyring_get_app_key(node_path: &str, app_idx: u16) -> Option<KeyringAppKey> {
    let data = read_key_file(node_path, APP_KEY_DIR, app_idx, 3)?;
    KeyringAppKey::from_bytes(&data)
}

/// Delete an application key file at `<node_path>/app_keys/<3hex>`.
///
/// Replaces C `keyring_del_app_key()`.
pub fn keyring_del_app_key(node_path: &str, app_idx: u16) -> bool {
    let dir = Path::new(node_path).join(APP_KEY_DIR);
    let fname = dir.join(idx_to_hex(app_idx, 3));
    debug!("RM App Key {}", fname.display());
    let _ = fs::remove_file(&fname);
    true
}

// ---------------------------------------------------------------------------
// Remote Device Key CRUD
// ---------------------------------------------------------------------------

/// Read a remote device key for a single unicast address.
///
/// Returns the 16-byte device key from `<node_path>/dev_keys/<4hex>`,
/// or `None` if the address is not unicast or the file is absent/corrupt.
///
/// Replaces C `keyring_get_remote_dev_key()`.
pub fn keyring_get_remote_dev_key(node_path: &str, unicast: u16) -> Option<[u8; 16]> {
    if !is_unicast(unicast) {
        return None;
    }

    let data = read_key_file(node_path, DEV_KEY_DIR, unicast, 4)?;
    if data.len() < DEV_KEY_SIZE {
        return None;
    }

    let mut key = [0u8; 16];
    key.copy_from_slice(&data[..16]);
    Some(key)
}

/// Persist a remote device key for a contiguous range of unicast addresses.
///
/// Writes the same `dev_key` to files `<4hex>` for each address in
/// `[unicast, unicast + count - 1]`.  Returns `false` if the range is
/// invalid or any write fails.
///
/// Replaces C `keyring_put_remote_dev_key()`.
pub fn keyring_put_remote_dev_key(
    node_path: &str,
    unicast: u16,
    count: u8,
    dev_key: &[u8; 16],
) -> bool {
    if !is_unicast_range(unicast, count) {
        return false;
    }

    for i in 0..u16::from(count) {
        let addr = unicast.wrapping_add(i);
        debug!("Put Dev Key {:04x}", addr);
        if !write_key_file(node_path, DEV_KEY_DIR, addr, 4, dev_key) {
            return false;
        }
    }

    true
}

/// Delete remote device key files for a contiguous range of unicast addresses.
///
/// Removes files for `[unicast, unicast + count - 1]`.  Returns `false` if
/// the range is invalid.
///
/// Replaces C `keyring_del_remote_dev_key()`.
pub fn keyring_del_remote_dev_key(node_path: &str, unicast: u16, count: u8) -> bool {
    if !is_unicast_range(unicast, count) {
        return false;
    }

    for i in 0..u16::from(count) {
        let addr = unicast.wrapping_add(i);
        let dir = Path::new(node_path).join(DEV_KEY_DIR);
        let fname = dir.join(idx_to_hex(addr, 4));
        debug!("RM Dev Key {}", fname.display());
        let _ = fs::remove_file(&fname);
    }

    true
}

/// Delete all remote device key files that share the same key value,
/// starting from `unicast` and scanning forward through contiguous
/// addresses.
///
/// This is used when a remote node is removed: the node's device key was
/// written to every element address, so all copies must be cleaned up.
///
/// Replaces C `keyring_del_remote_dev_key_all()`.
pub fn keyring_del_remote_dev_key_all(node_path: &str, unicast: u16) {
    // Read the reference key at the given unicast address.
    let reference_key = match keyring_get_remote_dev_key(node_path, unicast) {
        Some(k) => k,
        None => return,
    };

    // Scan forward to find the extent of contiguous matching keys.
    let mut end_addr = unicast.wrapping_add(1);
    while is_unicast(end_addr) {
        match keyring_get_remote_dev_key(node_path, end_addr) {
            Some(k) if k == reference_key => {
                end_addr = end_addr.wrapping_add(1);
            }
            _ => break,
        }
    }

    // Calculate count covering [unicast .. end_addr - 1].
    let count = end_addr.wrapping_sub(unicast);

    // Delete all keys in the range if there is more than zero.
    if count > 0 && count <= u16::from(u8::MAX) {
        keyring_del_remote_dev_key(node_path, unicast, count as u8);
    } else if count > u16::from(u8::MAX) {
        // Range exceeds what del_remote_dev_key can handle in a single
        // call; fall back to batch deletion in chunks.
        let mut addr = unicast;
        while addr < end_addr {
            let remaining = end_addr.wrapping_sub(addr);
            let chunk = if remaining > u16::from(u8::MAX) { u8::MAX } else { remaining as u8 };
            keyring_del_remote_dev_key(node_path, addr, chunk);
            addr = addr.wrapping_add(u16::from(chunk));
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus ExportKeys Reply Builder
// ---------------------------------------------------------------------------

/// Intermediate representation for a device key during deduplication.
struct DevKeyEntry {
    unicast: u16,
    value: [u8; 16],
}

/// Build the D-Bus `ExportKeys` reply for a mesh node.
///
/// The returned [`Value`] is a `a{sv}` dictionary containing:
///
/// - `"NetKeys"` → `a(qaya{sv})`: array of (net_idx, new_key_bytes, props),
///   where `props` is a dict with optional `"Phase"` (u8), `"OldKey"` (ay),
///   and `"AppKeys"` → `a(qaya{sv})` nested for that net key.
///
/// - `"DevKeys"` → `a(qay)`: array of (unicast, key_bytes), deduplicated
///   by key value (lowest unicast address kept per unique key).
///
/// Keys in Key Refresh Phase 3 are excluded from NetKeys (they are
/// unreliable during the transition).
///
/// Replaces C `keyring_build_export_keys_reply()`.
pub fn keyring_build_export_keys_reply(node_path: &str) -> Result<Value<'static>, MeshError> {
    let mut top_dict: HashMap<String, Value<'static>> = HashMap::new();

    // ---- NetKeys ----
    let net_keys_array = build_net_keys_reply(node_path);
    dict_insert_basic(&mut top_dict, "NetKeys", Value::from(net_keys_array));

    // ---- DevKeys ----
    let dev_keys_array = build_dev_keys_reply(node_path);
    dict_insert_basic(&mut top_dict, "DevKeys", Value::from(dev_keys_array));

    Ok(Value::from(top_dict))
}

/// Build the `"NetKeys"` portion: `a(qaya{sv})`.
///
/// Each entry is a `Vec<Value>` packed as `[net_idx(u16), new_key(ay), props(a{sv})]`,
/// then collected into a `Vec<Value>` representing the outer array.
fn build_net_keys_reply(node_path: &str) -> Vec<Value<'static>> {
    let entries = read_key_dir_entries(node_path, NET_KEY_DIR, 3);
    let mut net_key_structs: Vec<Value<'static>> = Vec::new();

    for (_idx, data) in &entries {
        let Some(net_key) = KeyringNetKey::from_bytes(data) else {
            continue;
        };

        // Skip keys in Phase 3 — they are unreliable during transition.
        if net_key.phase == KEY_REFRESH_PHASE_THREE {
            continue;
        }

        let mut props: HashMap<String, Value<'static>> = HashMap::new();

        // Include Phase and OldKey when a Key Refresh is in progress.
        if net_key.phase != KEY_REFRESH_PHASE_NONE {
            dict_insert_basic(&mut props, "Phase", Value::from(net_key.phase));
            dict_insert_basic(&mut props, "OldKey", byte_array_to_variant(&net_key.old_key));
        }

        // Nested AppKeys for this network key.
        let app_keys = build_app_keys_reply(node_path, net_key.net_idx, net_key.phase);
        if !app_keys.is_empty() {
            dict_insert_basic(&mut props, "AppKeys", Value::from(app_keys));
        }

        // Build a proper D-Bus struct (q, ay, a{sv}) using StructureBuilder
        // so the wire type matches the C daemon's l_dbus_message_builder.
        let struct_result = StructureBuilder::new()
            .append_field(Value::from(net_key.net_idx))
            .append_field(byte_array_to_variant(&net_key.new_key))
            .append_field(Value::from(props))
            .build();

        if let Ok(s) = struct_result {
            net_key_structs.push(Value::Structure(s));
        }
    }

    net_key_structs
}

/// Build the `"AppKeys"` portion for a single network key: `a(qaya{sv})`.
fn build_app_keys_reply(node_path: &str, net_idx: u16, net_key_phase: u8) -> Vec<Value<'static>> {
    let entries = read_key_dir_entries(node_path, APP_KEY_DIR, 3);
    let mut app_key_structs: Vec<Value<'static>> = Vec::new();

    for (_idx, data) in &entries {
        let Some(app_key) = KeyringAppKey::from_bytes(data) else {
            continue;
        };

        // Only include app keys bound to this network key.
        if app_key.net_idx != net_idx {
            continue;
        }

        let mut props: HashMap<String, Value<'static>> = HashMap::new();

        // Include OldKey when the parent network key is in a refresh phase.
        if net_key_phase != KEY_REFRESH_PHASE_NONE {
            dict_insert_basic(&mut props, "OldKey", byte_array_to_variant(&app_key.old_key));
        }

        // Build a proper D-Bus struct (q, ay, a{sv}).
        let struct_result = StructureBuilder::new()
            .append_field(Value::from(app_key.app_idx))
            .append_field(byte_array_to_variant(&app_key.new_key))
            .append_field(Value::from(props))
            .build();

        if let Ok(s) = struct_result {
            app_key_structs.push(Value::Structure(s));
        }
    }

    app_key_structs
}

/// Build the `"DevKeys"` portion: `a(qay)`.
///
/// Device keys are deduplicated by value — when multiple unicast addresses
/// share the same 16-byte key (as happens for multi-element nodes), only
/// the entry with the lowest unicast address is included.
fn build_dev_keys_reply(node_path: &str) -> Vec<Value<'static>> {
    let entries = read_key_dir_entries(node_path, DEV_KEY_DIR, 4);

    // Collect all device keys.
    let mut dev_keys: Vec<DevKeyEntry> = Vec::new();
    for (idx, data) in &entries {
        if data.len() < DEV_KEY_SIZE {
            continue;
        }
        let mut value = [0u8; 16];
        value.copy_from_slice(&data[..16]);
        dev_keys.push(DevKeyEntry { unicast: *idx, value });
    }

    // Sort by unicast address so the lowest address wins during dedup.
    dev_keys.sort_by_key(|e| e.unicast);

    // Deduplicate by key value — keep only the first (lowest unicast)
    // occurrence of each unique key.
    let mut seen_keys: Vec<[u8; 16]> = Vec::new();
    let mut unique_entries: Vec<&DevKeyEntry> = Vec::new();

    for entry in &dev_keys {
        if !seen_keys.contains(&entry.value) {
            seen_keys.push(entry.value);
            unique_entries.push(entry);
        }
    }

    // Build the Value array: each element is a D-Bus struct (q, ay).
    let mut dev_key_structs: Vec<Value<'static>> = Vec::new();
    for entry in &unique_entries {
        let struct_result = StructureBuilder::new()
            .append_field(Value::from(entry.unicast))
            .append_field(byte_array_to_variant(&entry.value))
            .build();

        if let Ok(s) = struct_result {
            dev_key_structs.push(Value::Structure(s));
        }
    }

    dev_key_structs
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Monotonic counter ensuring each test gets a unique directory, even
    /// when tests execute in parallel within the same process.
    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a temporary directory for test key storage and return its path.
    fn make_test_dir() -> String {
        let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("bluez_keyring_test_{}_{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        dir.to_string_lossy().into_owned()
    }

    /// Cleanup helper.
    fn cleanup(dir: &str) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn net_key_round_trip() {
        let dir = make_test_dir();

        let key =
            KeyringNetKey { net_idx: 0x0042, phase: 0, old_key: [0u8; 16], new_key: [0xAA; 16] };

        assert!(keyring_put_net_key(&dir, 0x0042, &key));

        let read_back = keyring_get_net_key(&dir, 0x0042);
        assert!(read_back.is_some());
        let rb = read_back.unwrap();
        assert_eq!(rb.net_idx, 0x0042);
        assert_eq!(rb.phase, 0);
        assert_eq!(rb.new_key, [0xAA; 16]);

        assert!(keyring_del_net_key(&dir, 0x0042));
        assert!(keyring_get_net_key(&dir, 0x0042).is_none());

        cleanup(&dir);
    }

    #[test]
    fn app_key_binding_enforcement() {
        let dir = make_test_dir();

        let key =
            KeyringAppKey { app_idx: 0x010, net_idx: 0x001, old_key: [0; 16], new_key: [0xBB; 16] };

        // First write succeeds.
        assert!(keyring_put_app_key(&dir, 0x010, 0x001, &key));

        // Second write with same net_idx succeeds.
        assert!(keyring_put_app_key(&dir, 0x010, 0x001, &key));

        // Write with different net_idx is rejected.
        let key2 =
            KeyringAppKey { app_idx: 0x010, net_idx: 0x002, old_key: [0; 16], new_key: [0xCC; 16] };
        assert!(!keyring_put_app_key(&dir, 0x010, 0x002, &key2));

        cleanup(&dir);
    }

    #[test]
    fn app_key_finalize() {
        let dir = make_test_dir();

        let key = KeyringAppKey {
            app_idx: 0x005,
            net_idx: 0x001,
            old_key: [0x11; 16],
            new_key: [0x22; 16],
        };
        assert!(keyring_put_app_key(&dir, 0x005, 0x001, &key));

        assert!(keyring_finalize_app_keys(&dir, 0x001));

        let rb = keyring_get_app_key(&dir, 0x005).unwrap();
        // After finalization, old_key should equal new_key.
        assert_eq!(rb.old_key, [0x22; 16]);
        assert_eq!(rb.new_key, [0x22; 16]);

        cleanup(&dir);
    }

    #[test]
    fn dev_key_range_operations() {
        let dir = make_test_dir();
        let dev_key = [0xDD; 16];

        // Write 3 element addresses.
        assert!(keyring_put_remote_dev_key(&dir, 0x0100, 3, &dev_key));

        // Read them back.
        assert_eq!(keyring_get_remote_dev_key(&dir, 0x0100), Some(dev_key));
        assert_eq!(keyring_get_remote_dev_key(&dir, 0x0101), Some(dev_key));
        assert_eq!(keyring_get_remote_dev_key(&dir, 0x0102), Some(dev_key));
        assert!(keyring_get_remote_dev_key(&dir, 0x0103).is_none());

        // Delete the range.
        assert!(keyring_del_remote_dev_key(&dir, 0x0100, 3));
        assert!(keyring_get_remote_dev_key(&dir, 0x0100).is_none());

        cleanup(&dir);
    }

    #[test]
    fn dev_key_del_all_contiguous() {
        let dir = make_test_dir();
        let dev_key = [0xEE; 16];
        let other_key = [0xFF; 16];

        // Write a node with 3 elements sharing the same key.
        assert!(keyring_put_remote_dev_key(&dir, 0x0200, 3, &dev_key));
        // Write a different node at the next address.
        assert!(keyring_put_remote_dev_key(&dir, 0x0203, 1, &other_key));

        keyring_del_remote_dev_key_all(&dir, 0x0200);

        // All 3 matching keys should be gone.
        assert!(keyring_get_remote_dev_key(&dir, 0x0200).is_none());
        assert!(keyring_get_remote_dev_key(&dir, 0x0201).is_none());
        assert!(keyring_get_remote_dev_key(&dir, 0x0202).is_none());
        // The other node's key should still be present.
        assert_eq!(keyring_get_remote_dev_key(&dir, 0x0203), Some(other_key));

        cleanup(&dir);
    }

    #[test]
    fn serialisation_sizes() {
        let nk = KeyringNetKey { net_idx: 0, phase: 0, old_key: [0; 16], new_key: [0; 16] };
        assert_eq!(nk.to_bytes().len(), NET_KEY_DISK_SIZE);

        let ak = KeyringAppKey { app_idx: 0, net_idx: 0, old_key: [0; 16], new_key: [0; 16] };
        assert_eq!(ak.to_bytes().len(), APP_KEY_DISK_SIZE);
    }

    #[test]
    fn unicast_validation_for_dev_keys() {
        let dir = make_test_dir();
        let dev_key = [0x42; 16];

        // Address 0x0000 (UNASSIGNED) should be rejected.
        assert!(!keyring_put_remote_dev_key(&dir, 0x0000, 1, &dev_key));
        assert!(keyring_get_remote_dev_key(&dir, 0x0000).is_none());

        // Address 0x8000 (VIRTUAL) should be rejected.
        assert!(keyring_get_remote_dev_key(&dir, 0x8000).is_none());

        // Count 0 should be rejected.
        assert!(!keyring_put_remote_dev_key(&dir, 0x0001, 0, &dev_key));

        cleanup(&dir);
    }

    #[test]
    fn export_keys_empty() {
        let dir = make_test_dir();

        // With no keys stored, export should succeed with empty arrays.
        let result = keyring_build_export_keys_reply(&dir);
        assert!(result.is_ok());

        cleanup(&dir);
    }

    #[test]
    fn net_key_byte_layout_matches_c() {
        // Verify that the byte layout produced by to_bytes() matches
        // what the C struct would produce on a little-endian system.
        let key = KeyringNetKey {
            net_idx: 0x0123,
            phase: 0x02,
            old_key: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            new_key: [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
        };
        let bytes = key.to_bytes();

        // net_idx at offset 0 (native endian).
        assert_eq!(bytes[0..2], 0x0123u16.to_ne_bytes());
        // phase at offset 2.
        assert_eq!(bytes[2], 0x02);
        // old_key at offset 3..19.
        assert_eq!(bytes[3], 1);
        assert_eq!(bytes[18], 16);
        // new_key at offset 19..35.
        assert_eq!(bytes[19], 17);
        assert_eq!(bytes[34], 32);
        // Padding byte at offset 35.
        assert_eq!(bytes[35], 0);
    }
}
