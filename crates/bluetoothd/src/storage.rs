// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
// Copyright (C) 2006-2010  Nokia Corporation
//
// Persistent storage for adapter and device state — Rust rewrite of
// `src/storage.c`, `src/storage.h`, `src/textfile.c`, and `src/textfile.h`.
//
// CRITICAL: The storage format is byte-identical to the C implementation to
// preserve existing Bluetooth pairings and device data across the daemon
// replacement.  All file paths, section names, key names, and value formats
// match the original C code character-for-character.
//
// ## Module organisation
//
// 1. **Textfile helpers** — Key-value flat files (`key value\n` per line)
//    with `flock()` concurrency control, replacing `textfile.c`.
// 2. **Storage API** — Adapter config readers (`read_discoverable_timeout`,
//    `read_local_name`, etc.) and SDP record parsing, replacing `storage.c`.
// 3. **INI-based device info** — Device info, adapter settings, and device
//    cache persistence via `rust-ini`, replacing `GKeyFile` usage.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;

use ini::Ini;
use nix::fcntl::{Flock, FlockArg};
use thiserror::Error;
use tracing::{debug, error, warn};

use bluez_shared::sys::bluetooth::bdaddr_t;

/// Re-exported type alias for convenience; identical to [`bdaddr_t`].
pub use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::sys::hci::HCI_MAX_NAME_LENGTH;
use bluez_shared::util::uuid::BtUuid;

use crate::log::{btd_debug, btd_error, btd_warn};
use crate::sdp::{SDP_ATTR_SVCLASS_ID_LIST, SdpData, SdpRecord};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Storage subsystem error.
///
/// Covers all failure modes for persistent storage operations: file I/O,
/// format parsing, missing entries, and file-lock contention.
#[derive(Debug, Error)]
pub enum StorageError {
    /// File I/O failure (open, read, write, create_dir, ftruncate, fdatasync).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Malformed data encountered during parsing (invalid hex in SDP records,
    /// bad key-value format, corrupt INI section).
    #[error("parse error: {0}")]
    ParseError(String),

    /// Requested key, file, or entry does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// File locking (`flock`) failed — another process holds an incompatible
    /// lock, or the kernel rejected the operation.
    #[error("lock error: {0}")]
    LockError(String),
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default persistent storage directory.
///
/// Matches the C build-time `STORAGEDIR` define which defaults to
/// `/var/lib/bluetooth` (set in `configure.ac`).
pub const STORAGEDIR: &str = "/var/lib/bluetooth";

/// Adapter index constant used for storage-related log messages that are not
/// tied to a specific adapter.
const LOG_INDEX_NONE: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Storage path prefix (cached, equivalent to C static local in
// create_filename)
// ---------------------------------------------------------------------------

/// Cached storage path prefix, initialised once from `STATE_DIRECTORY` env
/// var (systemd service mode) or falling back to [`STORAGEDIR`].
static STORAGE_PREFIX: OnceLock<String> = OnceLock::new();

/// Return the storage prefix string.
///
/// - If the `STATE_DIRECTORY` environment variable is set (systemd service
///   mode), the first colon-delimited path component is used.
/// - Otherwise, [`STORAGEDIR`] (`/var/lib/bluetooth`) is used.
///
/// The result is cached for the lifetime of the process.
fn get_storage_prefix() -> &'static str {
    STORAGE_PREFIX.get_or_init(|| {
        if let Ok(state_dir) = std::env::var("STATE_DIRECTORY") {
            // systemd may pass multiple paths separated by colons —
            // use only the first component.
            if let Some(idx) = state_dir.find(':') {
                state_dir[..idx].to_owned()
            } else {
                state_dir
            }
        } else {
            STORAGEDIR.to_owned()
        }
    })
}

// ---------------------------------------------------------------------------
// Path helpers (from textfile.h / textfile.c)
// ---------------------------------------------------------------------------

/// Build a full storage path by concatenating the storage prefix with the
/// given `suffix`.
///
/// Equivalent to C `create_filename(buf, size, fmt, ...)` where the
/// variadic format has already been resolved into `suffix`.
///
/// The `suffix` typically starts with `"/"` (e.g. `"/XX:XX:.../config"`).
///
/// # Examples
///
/// ```ignore
/// let p = create_filename("/00:11:22:33:44:55/config");
/// // → "/var/lib/bluetooth/00:11:22:33:44:55/config"
/// ```
pub fn create_filename(suffix: &str) -> PathBuf {
    let prefix = get_storage_prefix();
    let mut path = String::with_capacity(prefix.len() + suffix.len());
    path.push_str(prefix);
    path.push_str(suffix);
    debug!("create_filename: {}", path);
    PathBuf::from(path)
}

/// Create all intermediate directories for `filename` and then create (or
/// open) the file itself with the given POSIX `mode` permission bits.
///
/// Equivalent to C `create_file(filename, mode)`.
pub fn create_file(filename: &Path, mode: u32) -> Result<(), StorageError> {
    // Ensure parent directories exist (equivalent to create_dirs()).
    if let Some(parent) = filename.parent() {
        fs::create_dir_all(parent)?;
    }

    // Create-or-open the file with the requested permission mode.
    let file =
        OpenOptions::new().read(true).write(true).create(true).truncate(false).open(filename)?;

    // Apply the requested permission bits.
    let perms = fs::Permissions::from_mode(mode);
    file.set_permissions(perms)?;

    debug!("create_file: {} mode {:o}", filename.display(), mode);
    Ok(())
}

/// Build a storage path of the form `<prefix>/<address>/<name>`.
///
/// Equivalent to C `create_name(buf, size, address, name)`.
///
/// # Examples
///
/// ```ignore
/// let p = create_name("00:11:22:33:44:55", "config");
/// // → "/var/lib/bluetooth/00:11:22:33:44:55/config"
/// ```
pub fn create_name(address: &str, name: &str) -> PathBuf {
    create_filename(&format!("/{address}/{name}"))
}

// ---------------------------------------------------------------------------
// Textfile helpers (from textfile.c / textfile.h)
//
// File format: one `key value\n` pair per line, space-separated.
// Concurrent access is protected by POSIX advisory file locks (`flock`).
// ---------------------------------------------------------------------------

/// Internal: write (put or delete) a key in a textfile, with exclusive
/// locking.  When `value` is `Some`, the key line is created or updated.
/// When `value` is `None`, the key line is removed.
fn write_key_internal(pathname: &Path, key: &str, value: Option<&str>) -> Result<(), StorageError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(pathname)
        .map_err(|e| {
            error!("textfile open for write failed: {}: {e}", pathname.display());
            StorageError::IoError(e)
        })?;

    let mut locked = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, e)| {
        error!("exclusive flock failed: {}: {e}", pathname.display());
        StorageError::LockError(format!("exclusive lock on {}: {e}", pathname.display()))
    })?;

    let mut content = String::new();
    locked.read_to_string(&mut content).map_err(|e| {
        error!("textfile read failed: {}: {e}", pathname.display());
        StorageError::IoError(e)
    })?;

    let key_prefix = format!("{key} ");
    let mut new_content = String::with_capacity(content.len() + 64);
    let mut found = false;
    let mut changed = false;

    for line in content.lines() {
        if line.starts_with(&key_prefix) {
            found = true;
            if let Some(val) = value {
                // Check if value is already identical — skip rewrite if so.
                let existing = &line[key.len() + 1..];
                if existing == val {
                    new_content.push_str(line);
                    new_content.push('\n');
                } else {
                    new_content.push_str(key);
                    new_content.push(' ');
                    new_content.push_str(val);
                    new_content.push('\n');
                    changed = true;
                }
            } else {
                // Deletion — skip this line.
                changed = true;
            }
        } else if !line.is_empty() {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if !found {
        if let Some(val) = value {
            new_content.push_str(key);
            new_content.push(' ');
            new_content.push_str(val);
            new_content.push('\n');
            changed = true;
        }
    }

    // Only rewrite the file if the content actually changed.
    if changed {
        locked.seek(SeekFrom::Start(0))?;
        locked.set_len(0)?;
        locked.write_all(new_content.as_bytes())?;
    }

    locked.sync_data()?;
    Ok(())
}

/// Write or update a key-value entry in a textfile.
///
/// If the key already exists with the same value, the file is not rewritten
/// (optimisation to reduce disk writes).
///
/// Equivalent to C `textfile_put(pathname, key, value)`.
pub fn textfile_put(pathname: &Path, key: &str, value: &str) -> Result<(), StorageError> {
    write_key_internal(pathname, key, Some(value))
}

/// Delete a key from a textfile.
///
/// If the key does not exist, this is a no-op (no error).
///
/// Equivalent to C `textfile_del(pathname, key)`.
pub fn textfile_del(pathname: &Path, key: &str) -> Result<(), StorageError> {
    write_key_internal(pathname, key, None)
}

/// Read a single key's value from a textfile, with shared locking.
///
/// Returns `None` if the file cannot be opened, the lock cannot be acquired,
/// or the key is not present.  This mirrors the C `textfile_get()` which
/// returns `NULL` for all error/not-found conditions.
///
/// Equivalent to C `textfile_get(pathname, key)`.
pub fn textfile_get(pathname: &Path, key: &str) -> Option<String> {
    let file = match File::open(pathname) {
        Ok(f) => f,
        Err(e) => {
            debug!("textfile_get: cannot open {}: {e}", pathname.display());
            return None;
        }
    };

    let mut locked = match Flock::lock(file, FlockArg::LockShared) {
        Ok(l) => l,
        Err((_, e)) => {
            warn!("textfile_get: shared lock failed on {}: {e}", pathname.display());
            return None;
        }
    };

    let mut content = String::new();
    if locked.read_to_string(&mut content).is_err() {
        return None;
    }

    let key_prefix = format!("{key} ");

    for line in content.lines() {
        if line.starts_with(&key_prefix) {
            let value = &line[key.len() + 1..];
            return Some(value.to_owned());
        }
    }

    None
}

/// Iterate over all key-value entries in a textfile, calling `func` for
/// each.
///
/// The file is opened read-only with a shared lock held for the duration of
/// the iteration.
///
/// Equivalent to C `textfile_foreach(pathname, func, data)`.
pub fn textfile_foreach<F>(pathname: &Path, mut func: F) -> Result<(), StorageError>
where
    F: FnMut(&str, &str),
{
    let file = File::open(pathname).map_err(|e| {
        debug!("textfile_foreach: cannot open {}: {e}", pathname.display());
        StorageError::IoError(e)
    })?;

    let mut locked = Flock::lock(file, FlockArg::LockShared).map_err(|(_, e)| {
        warn!("textfile_foreach: shared lock failed on {}: {e}", pathname.display());
        StorageError::LockError(format!("shared lock on {}: {e}", pathname.display()))
    })?;

    let mut content = String::new();
    locked.read_to_string(&mut content)?;

    for line in content.lines() {
        if let Some(idx) = line.find(' ') {
            let key = &line[..idx];
            let value = &line[idx + 1..];
            if !key.is_empty() {
                func(key, value);
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Adapter configuration readers (from storage.c)
// ---------------------------------------------------------------------------

/// Read the discoverable timeout from the adapter's legacy config textfile.
///
/// Reads the `discovto` key from `<prefix>/<src>/config`.
///
/// Equivalent to C `read_discoverable_timeout(src, &timeout)`.
pub fn read_discoverable_timeout(src: &str) -> Result<i32, StorageError> {
    let filename = create_name(src, "config");
    let val_str = textfile_get(&filename, "discovto").ok_or_else(|| {
        debug!("read_discoverable_timeout: key 'discovto' not found for {src}");
        StorageError::NotFound("discovto".into())
    })?;

    val_str.trim().parse::<i32>().map_err(|e| {
        warn!("read_discoverable_timeout: parse failed for '{val_str}': {e}");
        StorageError::ParseError(format!("invalid discovto value '{val_str}': {e}"))
    })
}

/// Read the pairable timeout from the adapter's legacy config textfile.
///
/// Reads the `pairto` key from `<prefix>/<src>/config`.
///
/// Equivalent to C `read_pairable_timeout(src, &timeout)`.
pub fn read_pairable_timeout(src: &str) -> Result<i32, StorageError> {
    let filename = create_name(src, "config");
    let val_str = textfile_get(&filename, "pairto").ok_or_else(|| {
        debug!("read_pairable_timeout: key 'pairto' not found for {src}");
        StorageError::NotFound("pairto".into())
    })?;

    val_str.trim().parse::<i32>().map_err(|e| {
        warn!("read_pairable_timeout: parse failed for '{val_str}': {e}");
        StorageError::ParseError(format!("invalid pairto value '{val_str}': {e}"))
    })
}

/// Read the power-on mode from the adapter's legacy config textfile.
///
/// Reads the `onmode` key from `<prefix>/<src>/config`.
///
/// Equivalent to C `read_on_mode(src, mode, length)`.
pub fn read_on_mode(src: &str) -> Result<String, StorageError> {
    let filename = create_name(src, "config");
    let val_str = textfile_get(&filename, "onmode").ok_or_else(|| {
        debug!("read_on_mode: key 'onmode' not found for {src}");
        StorageError::NotFound("onmode".into())
    })?;

    Ok(val_str)
}

/// Read the local adapter name from the adapter's legacy config textfile.
///
/// Reads the `name` key from `<prefix>/<addr>/config` where `<addr>` is the
/// colon-separated BD address string obtained from `bdaddr.ba2str()`.
///
/// The returned name is truncated to [`HCI_MAX_NAME_LENGTH`] bytes, matching
/// the C implementation.
///
/// Equivalent to C `read_local_name(bdaddr, name)`.
pub fn read_local_name(bdaddr: &bdaddr_t) -> Result<String, StorageError> {
    let addr = bdaddr.ba2str();
    let filename = create_filename(&format!("/{addr}/config"));
    btd_debug(LOG_INDEX_NONE, &format!("read_local_name: path={}", filename.display()));

    let val_str = textfile_get(&filename, "name").ok_or_else(|| {
        btd_warn(LOG_INDEX_NONE, &format!("read_local_name: key 'name' not found for {addr}"));
        StorageError::NotFound("name".into())
    })?;

    // Truncate to HCI_MAX_NAME_LENGTH (248 bytes), matching C behaviour.
    let truncated = if val_str.len() > HCI_MAX_NAME_LENGTH {
        val_str[..HCI_MAX_NAME_LENGTH].to_owned()
    } else {
        val_str
    };

    Ok(truncated)
}

// ---------------------------------------------------------------------------
// SDP binary PDU parsing helpers
// ---------------------------------------------------------------------------

/// Decode a hex-encoded byte string into raw bytes.
///
/// The input must have an even number of hex characters.  Each pair of
/// characters is decoded as one byte (e.g. `"0A"` → `0x0A`).
fn hex_decode(hex: &str) -> Result<Vec<u8>, StorageError> {
    if hex.len() % 2 != 0 {
        return Err(StorageError::ParseError(format!(
            "odd-length hex string ({} chars)",
            hex.len()
        )));
    }
    let mut result = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| {
            StorageError::ParseError(format!("invalid hex at position {i}: '{}'", &hex[i..i + 2]))
        })?;
        result.push(byte);
    }
    Ok(result)
}

/// Ensure `data` has at least `need` bytes, returning a parse error
/// otherwise.
fn check_sdp_len(data: &[u8], need: usize) -> Result<(), StorageError> {
    if data.len() < need {
        Err(StorageError::ParseError(format!(
            "SDP data truncated: need {need} bytes, have {}",
            data.len()
        )))
    } else {
        Ok(())
    }
}

/// Read the variable-length size prefix for SDP container / string types.
///
/// Returns `(data_length, header_bytes_consumed)`.
fn sdp_var_length(data: &[u8], size_idx: u8) -> Result<(usize, usize), StorageError> {
    match size_idx {
        5 => {
            check_sdp_len(data, 2)?;
            Ok((data[1] as usize, 2))
        }
        6 => {
            check_sdp_len(data, 3)?;
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            Ok((len, 3))
        }
        7 => {
            check_sdp_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            Ok((len, 5))
        }
        _ => Err(StorageError::ParseError(format!(
            "invalid SDP variable-length size index: {size_idx}"
        ))),
    }
}

/// Fixed-size data lengths for SDP integer / UUID types, indexed by the
/// 3-bit size descriptor.
const SDP_FIXED_SIZES: [usize; 5] = [1, 2, 4, 8, 16];

/// Parse a single SDP data element from the byte slice.
///
/// Returns `(parsed_element, total_bytes_consumed)`.
fn parse_sdp_element(data: &[u8]) -> Result<(SdpData, usize), StorageError> {
    check_sdp_len(data, 1)?;
    let desc = data[0];
    let type_id = (desc >> 3) & 0x1f;
    let size_idx = desc & 0x07;

    match type_id {
        // ----- Nil (type 0) -----
        0 => Ok((SdpData::Nil, 1)),

        // ----- Unsigned Integer (type 1) -----
        1 => {
            if size_idx as usize >= SDP_FIXED_SIZES.len() {
                return Err(StorageError::ParseError(format!("bad UInt size_idx {size_idx}")));
            }
            let sz = SDP_FIXED_SIZES[size_idx as usize];
            check_sdp_len(data, 1 + sz)?;
            let d = &data[1..];
            let elem = match sz {
                1 => SdpData::UInt8(d[0]),
                2 => SdpData::UInt16(u16::from_be_bytes([d[0], d[1]])),
                4 => SdpData::UInt32(u32::from_be_bytes(d[..4].try_into().unwrap())),
                8 => SdpData::UInt64(u64::from_be_bytes(d[..8].try_into().unwrap())),
                16 => {
                    let mut v = [0u8; 16];
                    v.copy_from_slice(&d[..16]);
                    SdpData::UInt128(v)
                }
                _ => unreachable!(),
            };
            Ok((elem, 1 + sz))
        }

        // ----- Signed Integer (type 2) -----
        2 => {
            if size_idx as usize >= SDP_FIXED_SIZES.len() {
                return Err(StorageError::ParseError(format!("bad SInt size_idx {size_idx}")));
            }
            let sz = SDP_FIXED_SIZES[size_idx as usize];
            check_sdp_len(data, 1 + sz)?;
            let d = &data[1..];
            let elem = match sz {
                1 => SdpData::Int8(d[0] as i8),
                2 => SdpData::Int16(i16::from_be_bytes([d[0], d[1]])),
                4 => SdpData::Int32(i32::from_be_bytes(d[..4].try_into().unwrap())),
                8 => SdpData::Int64(i64::from_be_bytes(d[..8].try_into().unwrap())),
                16 => {
                    let mut v = [0u8; 16];
                    v.copy_from_slice(&d[..16]);
                    SdpData::Int128(v)
                }
                _ => unreachable!(),
            };
            Ok((elem, 1 + sz))
        }

        // ----- UUID (type 3) -----
        3 => {
            let sz = match size_idx {
                1 => 2,
                2 => 4,
                4 => 16,
                _ => {
                    return Err(StorageError::ParseError(format!("bad UUID size_idx {size_idx}")));
                }
            };
            check_sdp_len(data, 1 + sz)?;
            let d = &data[1..];
            let elem = match sz {
                2 => SdpData::Uuid16(u16::from_be_bytes([d[0], d[1]])),
                4 => SdpData::Uuid32(u32::from_be_bytes(d[..4].try_into().unwrap())),
                16 => {
                    let mut v = [0u8; 16];
                    v.copy_from_slice(&d[..16]);
                    SdpData::Uuid128(v)
                }
                _ => unreachable!(),
            };
            Ok((elem, 1 + sz))
        }

        // ----- Text String (type 4) -----
        4 => {
            let (data_len, hdr) = sdp_var_length(data, size_idx)?;
            check_sdp_len(data, hdr + data_len)?;
            let bytes = data[hdr..hdr + data_len].to_vec();
            Ok((SdpData::Text(bytes), hdr + data_len))
        }

        // ----- Boolean (type 5) -----
        5 => {
            check_sdp_len(data, 2)?;
            Ok((SdpData::Bool(data[1] != 0), 2))
        }

        // ----- Data Element Sequence (type 6) -----
        6 => {
            let (data_len, hdr) = sdp_var_length(data, size_idx)?;
            check_sdp_len(data, hdr + data_len)?;
            let mut items = Vec::new();
            let mut pos = 0;
            let seq_data = &data[hdr..hdr + data_len];
            while pos < data_len {
                let (elem, consumed) = parse_sdp_element(&seq_data[pos..])?;
                items.push(elem);
                pos += consumed;
            }
            Ok((SdpData::Sequence(items), hdr + data_len))
        }

        // ----- Data Element Alternative (type 7) -----
        7 => {
            let (data_len, hdr) = sdp_var_length(data, size_idx)?;
            check_sdp_len(data, hdr + data_len)?;
            let mut items = Vec::new();
            let mut pos = 0;
            let alt_data = &data[hdr..hdr + data_len];
            while pos < data_len {
                let (elem, consumed) = parse_sdp_element(&alt_data[pos..])?;
                items.push(elem);
                pos += consumed;
            }
            Ok((SdpData::Alternate(items), hdr + data_len))
        }

        // ----- URL (type 8) -----
        8 => {
            let (data_len, hdr) = sdp_var_length(data, size_idx)?;
            check_sdp_len(data, hdr + data_len)?;
            let url_str = String::from_utf8_lossy(&data[hdr..hdr + data_len]).into_owned();
            Ok((SdpData::Url(url_str), hdr + data_len))
        }

        _ => Err(StorageError::ParseError(format!("unknown SDP data element type {type_id}"))),
    }
}

/// Parse a raw SDP PDU byte sequence into an [`SdpRecord`].
///
/// The PDU is expected to be a Data Element Sequence whose children
/// alternate between UInt16 attribute IDs and their corresponding data
/// element values.
fn parse_sdp_record(data: &[u8]) -> Result<SdpRecord, StorageError> {
    if data.is_empty() {
        return Err(StorageError::ParseError("empty SDP PDU".into()));
    }

    let (element, _consumed) = parse_sdp_element(data)?;

    // The outer element must be a Sequence of (attr_id, value) pairs.
    let items = match element {
        SdpData::Sequence(items) => items,
        _ => {
            return Err(StorageError::ParseError("SDP record top-level is not a sequence".into()));
        }
    };

    let mut attrs = BTreeMap::new();
    let mut iter = items.into_iter();

    while let Some(id_elem) = iter.next() {
        let attr_id = match id_elem {
            SdpData::UInt16(id) => id,
            _ => {
                // Malformed: attribute ID should be UInt16. Skip pair.
                let _ = iter.next();
                continue;
            }
        };
        if let Some(value) = iter.next() {
            attrs.insert(attr_id, value);
        }
    }

    // Extract service record handle from attribute 0x0000 if present.
    let handle = attrs
        .get(&0x0000)
        .and_then(|v| match v {
            SdpData::UInt32(h) => Some(*h),
            _ => None,
        })
        .unwrap_or(0);

    Ok(SdpRecord { handle, attrs })
}

// ---------------------------------------------------------------------------
// SDP record helpers (from storage.c)
// ---------------------------------------------------------------------------

/// Parse a hex-encoded SDP service record PDU into an [`SdpRecord`].
///
/// The input is a string of hex character pairs (e.g. `"350311"...`),
/// which is decoded into raw bytes and then parsed as an SDP data element
/// sequence.
///
/// Equivalent to C `record_from_string(str)`.
pub fn record_from_string(hex_str: &str) -> Result<SdpRecord, StorageError> {
    if hex_str.is_empty() {
        return Err(StorageError::ParseError("empty SDP hex string".into()));
    }

    let bytes = hex_decode(hex_str)?;
    parse_sdp_record(&bytes)
}

/// Search a list of SDP records for one whose first service class UUID
/// matches `uuid_str` (case-insensitive comparison).
///
/// The service class UUIDs are extracted from the
/// [`SDP_ATTR_SVCLASS_ID_LIST`] (0x0001) attribute, which is expected to
/// be a Sequence of UUID data elements.
///
/// Equivalent to C `find_record_in_list(recs, uuid)`.
pub fn find_record_in_list<'a>(records: &'a [SdpRecord], uuid_str: &str) -> Option<&'a SdpRecord> {
    // Attempt to parse the target UUID for byte-level comparison.
    let target_uuid = BtUuid::from_str(uuid_str).ok();
    let target_bytes = target_uuid.as_ref().map(|u| u.to_uuid128_bytes());

    for rec in records {
        // Look up the ServiceClassIDList attribute.
        let svc_list = match rec.attrs.get(&SDP_ATTR_SVCLASS_ID_LIST) {
            Some(SdpData::Sequence(seq)) => seq,
            _ => continue,
        };

        // Extract the first UUID from the list.
        let first_uuid = match svc_list.first() {
            Some(SdpData::Uuid16(v)) => BtUuid::from_u16(*v),
            Some(SdpData::Uuid32(v)) => BtUuid::from_u32(*v),
            Some(SdpData::Uuid128(v)) => BtUuid::from_bytes(v),
            _ => continue,
        };

        // Try byte-level comparison first (most accurate).
        if let Some(ref t_bytes) = target_bytes {
            if first_uuid.to_uuid128_bytes() == *t_bytes {
                return Some(rec);
            }
        }

        // Fall back to case-insensitive string comparison.
        let svc_str = first_uuid.to_string();
        if svc_str.eq_ignore_ascii_case(uuid_str) {
            return Some(rec);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// INI-based persistence helpers
// ---------------------------------------------------------------------------

/// Internal: write an [`Ini`] configuration to a file, creating parent
/// directories as needed.
fn write_ini_file(path: &Path, ini: &Ini) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    ini.write_to_file(path).map_err(|e| {
        btd_error(LOG_INDEX_NONE, &format!("failed to write INI file {}: {e}", path.display()));
        StorageError::IoError(std::io::Error::other(e.to_string()))
    })?;

    debug!("wrote INI file: {}", path.display());
    Ok(())
}

/// Internal: load an [`Ini`] configuration from a file.
fn read_ini_file(path: &Path) -> Result<Ini, StorageError> {
    Ini::load_from_file(path).map_err(|e| {
        debug!("failed to load INI file {}: {e}", path.display());
        match e {
            ini::Error::Io(io_err) => StorageError::IoError(io_err),
            ini::Error::Parse(p) => {
                StorageError::ParseError(format!("INI parse error in {}: {p}", path.display()))
            }
        }
    })
}

/// Internal helper: read a value from an [`Ini`] object, checking both a
/// named section and the general (header-less) section.
#[allow(dead_code)]
fn ini_get_value(ini: &Ini, section: Option<&str>, key: &str) -> Option<String> {
    if let Some(sect_name) = section {
        if let Some(sect) = ini.section(Some(sect_name)) {
            if let Some(val) = sect.get(key) {
                return Some(val.to_owned());
            }
        }
    }

    // Also check the general (unnamed) section as a fallback.
    let general = ini.general_section();
    general.get(key).map(|v| v.to_owned())
}

// ---------------------------------------------------------------------------
// Device info persistence
// ---------------------------------------------------------------------------

/// Store device information to an INI file.
///
/// The file is written at the given `path` (typically the output of
/// [`device_info_path`]).  The INI object should contain sections such as
/// `[General]`, `[DeviceID]`, `[LinkKey]`, `[LongTermKey]`, etc.
///
/// All section names, key names, and value formats are byte-identical to
/// the C `GKeyFile`-based implementation.
pub fn store_device_info(path: &Path, info: &Ini) -> Result<(), StorageError> {
    debug!("store_device_info: {}", path.display());
    write_ini_file(path, info)
}

/// Load device information from an INI file.
///
/// Returns the parsed [`Ini`] object with all sections and key-value
/// pairs.  Callers access individual sections (e.g. `[General]`,
/// `[LinkKey]`) via [`Ini::section`].
pub fn load_device_info(path: &Path) -> Result<Ini, StorageError> {
    debug!("load_device_info: {}", path.display());
    read_ini_file(path)
}

// ---------------------------------------------------------------------------
// Adapter settings persistence
// ---------------------------------------------------------------------------

/// Store adapter settings to an INI file.
///
/// The file is written at the given `path` (typically the output of
/// [`adapter_settings_path`]).  The INI object should contain a
/// `[General]` section with keys such as `Discoverable`, `Pairable`,
/// `Alias`, `Class`.
pub fn store_adapter_settings(path: &Path, settings: &Ini) -> Result<(), StorageError> {
    debug!("store_adapter_settings: {}", path.display());
    write_ini_file(path, settings)
}

/// Load adapter settings from an INI file.
pub fn load_adapter_settings(path: &Path) -> Result<Ini, StorageError> {
    debug!("load_adapter_settings: {}", path.display());
    read_ini_file(path)
}

// ---------------------------------------------------------------------------
// Device cache persistence
// ---------------------------------------------------------------------------

/// Store a device discovery cache to an INI file.
///
/// The cache file (typically at `<prefix>/<adapter>/cache/<device>`)
/// stores discovered service and attribute data in INI format.
pub fn store_device_cache(path: &Path, cache: &Ini) -> Result<(), StorageError> {
    debug!("store_device_cache: {}", path.display());
    write_ini_file(path, cache)
}

/// Load a device discovery cache from an INI file.
pub fn load_device_cache(path: &Path) -> Result<Ini, StorageError> {
    debug!("load_device_cache: {}", path.display());
    read_ini_file(path)
}

// ---------------------------------------------------------------------------
// Path builders
// ---------------------------------------------------------------------------

/// Build the path to a device's info file.
///
/// Format: `<prefix>/<adapter>/<device>/info`
///
/// This is the primary persistent storage file for paired/bonded device
/// state, containing sections like `[General]`, `[LinkKey]`, etc.
pub fn device_info_path(adapter: &str, device: &str) -> PathBuf {
    create_filename(&format!("/{adapter}/{device}/info"))
}

/// Build the path to an adapter's settings file.
///
/// Format: `<prefix>/<addr>/settings`
///
/// Contains the `[General]` section with adapter properties
/// (Discoverable, Pairable, Alias, Class).
pub fn adapter_settings_path(addr: &str) -> PathBuf {
    create_filename(&format!("/{addr}/settings"))
}

/// Build the path to a device's cache file.
///
/// Format: `<prefix>/<adapter>/cache/<device>`
///
/// Stores discovered service/attribute data for faster reconnection.
pub fn device_cache_path(adapter: &str, device: &str) -> PathBuf {
    create_filename(&format!("/{adapter}/cache/{device}"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Monotonic counter ensuring each test gets a unique directory.
    static TEST_DIR_CTR: AtomicU64 = AtomicU64::new(0);

    /// Helper: create a per-test temporary directory.
    fn temp_dir() -> PathBuf {
        let id = TEST_DIR_CTR.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("bluez_storage_test_{}_{}", std::process::id(), id));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_hex_decode_valid() {
        let bytes = hex_decode("0A1bFF00").unwrap();
        assert_eq!(bytes, vec![0x0A, 0x1B, 0xFF, 0x00]);
    }

    #[test]
    fn test_hex_decode_empty() {
        let bytes = hex_decode("").unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert!(hex_decode("ABC").is_err());
    }

    #[test]
    fn test_hex_decode_invalid_chars() {
        assert!(hex_decode("ZZZZ").is_err());
    }

    #[test]
    fn test_textfile_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("test_kv.txt");

        textfile_put(&path, "mykey", "myvalue").unwrap();
        assert_eq!(textfile_get(&path, "mykey"), Some("myvalue".to_owned()));

        textfile_put(&path, "mykey", "newvalue").unwrap();
        assert_eq!(textfile_get(&path, "mykey"), Some("newvalue".to_owned()));

        textfile_put(&path, "other", "data").unwrap();
        assert_eq!(textfile_get(&path, "other"), Some("data".to_owned()));
        assert_eq!(textfile_get(&path, "mykey"), Some("newvalue".to_owned()));

        textfile_del(&path, "mykey").unwrap();
        assert_eq!(textfile_get(&path, "mykey"), None);
        assert_eq!(textfile_get(&path, "other"), Some("data".to_owned()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_textfile_foreach_iteration() {
        let dir = temp_dir();
        let path = dir.join("test_foreach.txt");

        textfile_put(&path, "a", "1").unwrap();
        textfile_put(&path, "b", "2").unwrap();
        textfile_put(&path, "c", "3").unwrap();

        let mut entries = Vec::new();
        textfile_foreach(&path, |k, v| {
            entries.push((k.to_owned(), v.to_owned()));
        })
        .unwrap();

        assert_eq!(entries.len(), 3);
        assert!(entries.contains(&("a".to_owned(), "1".to_owned())));
        assert!(entries.contains(&("b".to_owned(), "2".to_owned())));
        assert!(entries.contains(&("c".to_owned(), "3".to_owned())));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_textfile_get_nonexistent_file() {
        assert_eq!(textfile_get(Path::new("/tmp/nonexistent_bluez_test_file"), "key"), None);
    }

    #[test]
    fn test_textfile_get_nonexistent_key() {
        let dir = temp_dir();
        let path = dir.join("test_missing_key.txt");
        textfile_put(&path, "exists", "yes").unwrap();
        assert_eq!(textfile_get(&path, "missing"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_textfile_put_no_change_optimization() {
        let dir = temp_dir();
        let path = dir.join("test_nochange.txt");

        textfile_put(&path, "k", "v").unwrap();
        let content1 = fs::read_to_string(&path).unwrap();

        textfile_put(&path, "k", "v").unwrap();
        let content2 = fs::read_to_string(&path).unwrap();

        assert_eq!(content1, content2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_create_filename_default_prefix() {
        let path = create_filename("/00:11:22:33:44:55/config");
        let path_str = path.to_string_lossy();
        assert!(path_str.ends_with("/00:11:22:33:44:55/config"));
    }

    #[test]
    fn test_create_name() {
        let path = create_name("AA:BB:CC:DD:EE:FF", "config");
        let path_str = path.to_string_lossy();
        assert!(path_str.ends_with("/AA:BB:CC:DD:EE:FF/config"));
    }

    #[test]
    fn test_create_file_and_dirs() {
        let dir = temp_dir();
        let path = dir.join("sub1/sub2/testfile.txt");
        create_file(&path, 0o644).unwrap();
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_device_info_path() {
        let path = device_info_path("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF");
        let s = path.to_string_lossy();
        assert!(s.ends_with("/00:11:22:33:44:55/AA:BB:CC:DD:EE:FF/info"));
    }

    #[test]
    fn test_adapter_settings_path() {
        let path = adapter_settings_path("00:11:22:33:44:55");
        let s = path.to_string_lossy();
        assert!(s.ends_with("/00:11:22:33:44:55/settings"));
    }

    #[test]
    fn test_device_cache_path() {
        let path = device_cache_path("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF");
        let s = path.to_string_lossy();
        assert!(s.ends_with("/00:11:22:33:44:55/cache/AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_ini_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("test_device_info.ini");

        let mut ini = Ini::new();
        ini.with_section(Some("General"))
            .set("Name", "TestDevice")
            .set("Alias", "MyDevice")
            .set("Class", "0x000104")
            .set("Trusted", "true")
            .set("Blocked", "false");
        ini.with_section(Some("LinkKey"))
            .set("Key", "AABBCCDD11223344AABBCCDD11223344")
            .set("Type", "4")
            .set("PINLength", "0");

        store_device_info(&path, &ini).unwrap();
        let loaded = load_device_info(&path).unwrap();

        let general = loaded.section(Some("General")).unwrap();
        assert_eq!(general.get("Name"), Some("TestDevice"));
        assert_eq!(general.get("Alias"), Some("MyDevice"));
        assert_eq!(general.get("Trusted"), Some("true"));

        let linkkey = loaded.section(Some("LinkKey")).unwrap();
        assert_eq!(linkkey.get("Type"), Some("4"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_adapter_settings_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("test_adapter_settings.ini");

        let mut ini = Ini::new();
        ini.with_section(Some("General"))
            .set("Discoverable", "true")
            .set("Pairable", "true")
            .set("Alias", "MyAdapter")
            .set("Class", "0x000000");

        store_adapter_settings(&path, &ini).unwrap();
        let loaded = load_adapter_settings(&path).unwrap();

        let val = ini_get_value(&loaded, Some("General"), "Discoverable");
        assert_eq!(val.as_deref(), Some("true"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_device_cache_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("test_device_cache.ini");

        let mut ini = Ini::new();
        ini.with_section(Some("ServiceRecords")).set("0x00010000", "35031101");

        store_device_cache(&path, &ini).unwrap();
        let loaded = load_device_cache(&path).unwrap();

        let sr = loaded.section(Some("ServiceRecords")).unwrap();
        assert_eq!(sr.get("0x00010000"), Some("35031101"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sdp_parse_simple_sequence() {
        // Sequence { UInt16(0x0000), UInt32(0x00010000) }
        // 0x35 = type 6(Seq), size_idx 5(1-byte len)
        // 0x08 = 8 bytes of content
        // 0x09 = type 1(UInt), size_idx 1(2-byte) → UInt16
        // 0x00,0x00 = attr_id 0x0000
        // 0x0A = type 1(UInt), size_idx 2(4-byte) → UInt32
        // 0x00,0x01,0x00,0x00 = value 0x00010000
        let pdu: Vec<u8> = vec![
            0x35, 0x08, // Sequence, length=8
            0x09, 0x00, 0x00, // UInt16 attr_id = 0x0000
            0x0A, 0x00, 0x01, 0x00, 0x00, // UInt32 value = 0x00010000
        ];

        let record = parse_sdp_record(&pdu).unwrap();
        assert_eq!(record.handle, 0x00010000);
        assert_eq!(record.attrs.len(), 1);
        assert_eq!(record.attrs[&0x0000], SdpData::UInt32(0x00010000));
    }

    #[test]
    fn test_record_from_string() {
        // Same PDU as above: Seq(8){ UInt16(0), UInt32(0x10000) }
        let hex = "35080900000a00010000";
        let record = record_from_string(hex).unwrap();
        assert_eq!(record.handle, 0x00010000);
    }

    #[test]
    fn test_find_record_in_list() {
        let mut attrs = BTreeMap::new();
        attrs.insert(0x0000, SdpData::UInt32(0x00010001));
        attrs.insert(SDP_ATTR_SVCLASS_ID_LIST, SdpData::Sequence(vec![SdpData::Uuid16(0x1101)]));
        let rec = SdpRecord { handle: 0x00010001, attrs };

        let records = vec![rec];

        let found = find_record_in_list(&records, "00001101-0000-1000-8000-00805f9b34fb");
        assert!(found.is_some());
        assert_eq!(found.unwrap().handle, 0x00010001);

        let not_found = find_record_in_list(&records, "00001102-0000-1000-8000-00805f9b34fb");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_storage_error_display() {
        let e = StorageError::NotFound("test".into());
        assert_eq!(e.to_string(), "not found: test");

        let e = StorageError::LockError("flock busy".into());
        assert_eq!(e.to_string(), "lock error: flock busy");

        let e = StorageError::ParseError("bad hex".into());
        assert_eq!(e.to_string(), "parse error: bad hex");
    }

    #[test]
    fn test_ini_get_value_general_section() {
        let mut ini = Ini::new();
        ini.with_section(None::<String>).set("RootKey", "rootval");
        ini.with_section(Some("Named")).set("A", "B");

        assert_eq!(ini_get_value(&ini, None, "RootKey").as_deref(), Some("rootval"));
        assert_eq!(ini_get_value(&ini, Some("Named"), "A").as_deref(), Some("B"));
        assert_eq!(ini_get_value(&ini, Some("Named"), "Missing"), None);
    }
}
