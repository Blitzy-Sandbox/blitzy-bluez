// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
//
// Unit tests for the textfile key-value storage helpers.  Converted from
// `unit/test-textfile.c` — exercises `textfile_put`, `textfile_get`,
// `textfile_del`, and `textfile_foreach` from `bluetoothd::storage`.
//
// Each test creates an isolated temporary directory via `tempfile::TempDir`
// for parallel-safe, RAII-cleaned test execution — replacing the C test's
// hardcoded `/tmp/textfile` path.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use bluetoothd::storage::{textfile_del, textfile_foreach, textfile_get, textfile_put};
use nix::unistd::{SysconfVar, sysconf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test helper functions
// ---------------------------------------------------------------------------

/// Build the textfile path inside a temporary directory.
fn test_path(dir: &TempDir) -> PathBuf {
    dir.path().join("textfile")
}

/// Create an empty textfile at `path` (equivalent to C `util_create_empty`).
///
/// The file is created with default permissions, then truncated to zero
/// length — mirroring the C `creat(path, 0644); ftruncate(fd, 0);` pattern.
fn util_create_empty(path: &Path) {
    let file = File::create(path).expect("failed to create empty textfile");
    file.set_len(0).expect("failed to truncate textfile to zero length");
}

/// Create a textfile filled with null bytes of exactly the system page size
/// (equivalent to C `util_create_pagesize`).
///
/// Writes the data in 512-byte chunks, mirroring the C implementation that
/// uses `memset(value, 0, 512); write(fd, value, 512)` in a loop.
fn util_create_pagesize(path: &Path) {
    let page_size = sysconf(SysconfVar::PAGE_SIZE)
        .expect("sysconf(PAGE_SIZE) failed")
        .expect("PAGE_SIZE not available") as usize;

    let mut file = File::create(path).expect("failed to create pagesize textfile");
    file.set_len(0).expect("failed to truncate textfile to zero length");

    let chunk = [0u8; 512];
    let num_chunks = page_size / chunk.len();
    for _ in 0..num_chunks {
        file.write_all(&chunk).expect("failed to write null-byte chunk");
    }
}

/// Iterate all entries in a textfile via `textfile_foreach` and verify each
/// entry's value length matches the hex ID extracted from the key.
///
/// Equivalent to C `check_entry` callback:
/// - Key format is `"00:00:00:00:00:XX"` (17 chars).
/// - The hex digit(s) at `key[16..]` determine the expected value length.
/// - Special case: if the extracted ID equals 1, the expected length is
///   `max` (because key `01` was overwritten with a `max`-length value).
fn check_entries_via_foreach(path: &Path, max: usize) {
    textfile_foreach(path, |key, value| {
        assert_eq!(key.len(), 17, "check_entry: key '{key}' length {} != 17", key.len());

        // Extract hex ID from the last character(s) of the key.
        // Mirrors C: `strtol(key + 16, NULL, 16)`.
        let hex_suffix = &key[16..];
        let id = usize::from_str_radix(hex_suffix, 16)
            .unwrap_or_else(|e| panic!("failed to parse hex from key suffix '{hex_suffix}': {e}"));

        let expected_len = if id == 1 { max } else { id };
        assert_eq!(
            value.len(),
            expected_len,
            "check_entry: value length mismatch for key '{key}': \
             got {}, expected {expected_len}",
            value.len()
        );
    })
    .expect("textfile_foreach failed during check_entries");
}

// ===========================================================================
// Tests converted from C `unit/test-textfile.c`
// ===========================================================================

// ---------------------------------------------------------------------------
// /textfile/pagesize — reading from a file filled with null bytes
// ---------------------------------------------------------------------------

/// Converted from C `test_pagesize`.
///
/// Verifies that `textfile_get` returns `None` when the file is filled
/// entirely with null bytes — no valid `key value\n` lines exist in such
/// a file.
#[test]
fn test_textfile_pagesize() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    // Verify the system page size meets the minimum assumed by the C test.
    let page_size = sysconf(SysconfVar::PAGE_SIZE)
        .expect("sysconf(PAGE_SIZE) failed")
        .expect("PAGE_SIZE not available");
    assert!(page_size >= 4096, "system page size ({page_size}) is less than 4096");

    util_create_pagesize(&path);

    // A key lookup in a file full of null bytes must return None.
    let result = textfile_get(&path, "11:11:11:11:11:11");
    assert!(result.is_none(), "expected None for key in null-byte file, got: {result:?}");
}

// ---------------------------------------------------------------------------
// /textfile/delete — deletion from empty file, put/get cycle
// ---------------------------------------------------------------------------

/// Converted from C `test_delete`.
///
/// Verifies that:
/// 1. Deleting a non-existent key from an empty file succeeds (no-op).
/// 2. Putting a key with an empty value and then reading it back succeeds.
#[test]
fn test_textfile_del() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    util_create_empty(&path);

    // Deleting from an empty file is a no-op — must succeed.
    textfile_del(&path, "00:00:00:00:00:00").expect("textfile_del on empty file should succeed");

    // Put an empty-string value (mirrors C: memset(value, 0, 512) yielding
    // an empty C string).
    textfile_put(&path, "00:00:00:00:00:00", "").expect("textfile_put with empty value failed");

    // Retrieve the key and verify it was stored.
    let result = textfile_get(&path, "00:00:00:00:00:00");
    assert!(result.is_some(), "expected Some after put with empty value, got None");
}

// ---------------------------------------------------------------------------
// /textfile/overwrite — put, overwrite, delete, verify-gone cycle
// ---------------------------------------------------------------------------

/// Converted from C `test_overwrite`.
///
/// Verifies that:
/// 1. A key can be stored with an empty value.
/// 2. The value can be overwritten with a non-empty string.
/// 3. Multiple identical puts are idempotent (no error, no data change).
/// 4. The key can be deleted and subsequent get returns `None`.
#[test]
fn test_textfile_overwrite() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    util_create_empty(&path);

    let key = "00:00:00:00:00:00";

    // Initial put with empty value.
    textfile_put(&path, key, "").expect("put empty value failed");

    // Overwrite with "Test".
    textfile_put(&path, key, "Test").expect("overwrite with 'Test' failed");

    // Idempotent overwrites — value unchanged, no error.
    textfile_put(&path, key, "Test").expect("idempotent overwrite (1) failed");
    textfile_put(&path, key, "Test").expect("idempotent overwrite (2) failed");

    // Delete the key.
    textfile_del(&path, key).expect("delete after overwrite failed");

    // Verify the key is gone.
    let result = textfile_get(&path, key);
    assert!(result.is_none(), "expected None after delete, got: {result:?}");
}

// ---------------------------------------------------------------------------
// /textfile/multiple — multi-key lifecycle with foreach verification
// ---------------------------------------------------------------------------

/// Converted from C `test_multiple` with `check_entry` callback.
///
/// Exercises the full lifecycle of 10 keys: put with 'x'-filled values of
/// increasing length, overwrite specific keys with 'y' and 'z' values,
/// selective deletion, and iteration via `textfile_foreach` to verify
/// remaining entries.
#[test]
fn test_textfile_multiple() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);
    let max: usize = 10;

    util_create_empty(&path);

    // --- Phase 1: Put 10 keys (01..0A) with 'x'-filled values -----------
    // Key i gets value 'x' repeated i times.
    for i in 1..=max {
        let key = format!("00:00:00:00:00:{i:02X}");
        let value: String = "x".repeat(i);

        textfile_put(&path, &key, &value).unwrap_or_else(|e| panic!("put key {key} failed: {e}"));

        let result = textfile_get(&path, &key);
        assert_eq!(result.as_deref(), Some(value.as_str()), "get after initial put for key {key}");
    }

    // --- Phase 2: Overwrite key 0A (max) with 'y' * max ------------------
    {
        let key = format!("00:00:00:00:00:{max:02X}");
        let value: String = "y".repeat(max);

        textfile_put(&path, &key, &value)
            .unwrap_or_else(|e| panic!("overwrite key {key} with 'y' failed: {e}"));

        let result = textfile_get(&path, &key);
        assert_eq!(
            result.as_deref(),
            Some(value.as_str()),
            "get after 'y' overwrite for key {key}"
        );
    }

    // --- Phase 3: Overwrite key 01 with 'z' * max -------------------------
    {
        let key = format!("00:00:00:00:00:{:02X}", 1);
        let value: String = "z".repeat(max);

        textfile_put(&path, &key, &value)
            .unwrap_or_else(|e| panic!("overwrite key {key} with 'z' failed: {e}"));

        let result = textfile_get(&path, &key);
        assert_eq!(
            result.as_deref(),
            Some(value.as_str()),
            "get after 'z' overwrite for key {key}"
        );
    }

    // --- Phase 4: Verify all 10 keys have expected value lengths ----------
    // Key 01 was overwritten to length `max`; all others retain length = i.
    for i in 1..=max {
        let key = format!("00:00:00:00:00:{i:02X}");
        let val = textfile_get(&path, &key)
            .unwrap_or_else(|| panic!("expected Some for key {key} in Phase 4"));

        let expected_len = if i == 1 { max } else { i };
        assert_eq!(
            val.len(),
            expected_len,
            "Phase 4: value length for key {key}: got {}, expected {expected_len}",
            val.len()
        );
    }

    // --- Phase 5: Delete keys 02 and 07 (max - 3) ------------------------
    {
        let key02 = format!("00:00:00:00:00:{:02X}", 2);
        textfile_del(&path, &key02).expect("delete key 02 failed");

        let key07 = format!("00:00:00:00:00:{:02X}", max - 3);
        textfile_del(&path, &key07).expect("delete key 07 failed");
    }

    // --- Phase 6: Foreach check — 8 remaining keys -----------------------
    check_entries_via_foreach(&path, max);

    // --- Phase 7: Delete keys 01 and 0A (max) ----------------------------
    {
        let key01 = format!("00:00:00:00:00:{:02X}", 1);
        textfile_del(&path, &key01).expect("delete key 01 failed");

        let key0a = format!("00:00:00:00:00:{max:02X}");
        textfile_del(&path, &key0a).expect("delete key 0A failed");
    }

    // --- Phase 8: Delete non-existent key 0B (max + 1) — no-op ----------
    {
        let key0b = format!("00:00:00:00:00:{:02X}", max + 1);
        textfile_del(&path, &key0b).expect("delete non-existent key 0B should succeed");
    }

    // --- Phase 9: Foreach check — 6 remaining keys -----------------------
    check_entries_via_foreach(&path, max);
}

// ===========================================================================
// Additional test cases (schema-requested, extending C original coverage)
// ===========================================================================

// ---------------------------------------------------------------------------
// test_textfile_put — basic put operation
// ---------------------------------------------------------------------------

/// Verifies that `textfile_put` creates the file if it does not exist and
/// stores the key-value pair correctly.  Also verifies multiple keys can
/// be written to the same file.
#[test]
fn test_textfile_put() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    // Put into a non-existent file — textfile_put creates it.
    textfile_put(&path, "AA:BB:CC:DD:EE:FF", "some_value")
        .expect("textfile_put to new file failed");

    // Verify the file was created.
    assert!(path.exists(), "textfile should exist after first put");

    // Verify the value is retrievable.
    let result = textfile_get(&path, "AA:BB:CC:DD:EE:FF");
    assert_eq!(result.as_deref(), Some("some_value"), "get should return value written by put");

    // Put a second key into the same file.
    textfile_put(&path, "11:22:33:44:55:66", "another_value")
        .expect("textfile_put second key failed");

    let result2 = textfile_get(&path, "11:22:33:44:55:66");
    assert_eq!(result2.as_deref(), Some("another_value"), "get should return second value");

    // First key still accessible.
    let result1 = textfile_get(&path, "AA:BB:CC:DD:EE:FF");
    assert_eq!(
        result1.as_deref(),
        Some("some_value"),
        "first key should still be accessible after second put"
    );
}

// ---------------------------------------------------------------------------
// test_textfile_get — basic get operation
// ---------------------------------------------------------------------------

/// Verifies that `textfile_get` returns the correct value for an existing
/// key and `None` for a key that does not exist in the file.
#[test]
fn test_textfile_get() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    textfile_put(&path, "AA:BB:CC:DD:EE:FF", "hello_world").expect("textfile_put failed");

    // Retrieve the key — should return the value.
    let result = textfile_get(&path, "AA:BB:CC:DD:EE:FF");
    assert_eq!(result.as_deref(), Some("hello_world"), "get should return the put value");

    // Retrieve a non-existent key — should return None.
    let missing = textfile_get(&path, "00:00:00:00:00:00");
    assert!(missing.is_none(), "get for non-existent key should return None");
}

// ---------------------------------------------------------------------------
// test_textfile_foreach — iteration over all entries
// ---------------------------------------------------------------------------

/// Verifies that `textfile_foreach` visits every key-value pair in the file
/// and passes the correct key and value to the callback closure.
#[test]
fn test_textfile_foreach() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    // Write several entries.
    textfile_put(&path, "key1", "val1").expect("put key1 failed");
    textfile_put(&path, "key2", "val2").expect("put key2 failed");
    textfile_put(&path, "key3", "val3").expect("put key3 failed");

    // Iterate and collect results.
    let mut entries: Vec<(String, String)> = Vec::new();
    textfile_foreach(&path, |key, value| {
        entries.push((key.to_owned(), value.to_owned()));
    })
    .expect("textfile_foreach failed");

    assert_eq!(entries.len(), 3, "foreach should visit exactly 3 entries");

    // Verify all entries are present (order matches insertion order since
    // textfile_put appends new keys).
    assert!(
        entries.iter().any(|(k, v)| k == "key1" && v == "val1"),
        "key1/val1 not found in foreach results"
    );
    assert!(
        entries.iter().any(|(k, v)| k == "key2" && v == "val2"),
        "key2/val2 not found in foreach results"
    );
    assert!(
        entries.iter().any(|(k, v)| k == "key3" && v == "val3"),
        "key3/val3 not found in foreach results"
    );
}

// ---------------------------------------------------------------------------
// test_textfile_empty — operations on an empty file
// ---------------------------------------------------------------------------

/// Verifies correct behaviour when operating on a freshly-created empty
/// file: get returns `None`, foreach visits zero entries, and delete
/// succeeds as a no-op.
#[test]
fn test_textfile_empty() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    util_create_empty(&path);

    // Get from empty file returns None.
    let result = textfile_get(&path, "00:00:00:00:00:00");
    assert!(result.is_none(), "get from empty file should return None");

    // Foreach on empty file iterates zero entries.
    let mut count = 0usize;
    textfile_foreach(&path, |_key, _value| {
        count += 1;
    })
    .expect("textfile_foreach on empty file should succeed");
    assert_eq!(count, 0, "foreach on empty file should visit 0 entries");

    // Delete from empty file succeeds (no-op).
    textfile_del(&path, "00:00:00:00:00:00").expect("textfile_del on empty file should succeed");
}

// ---------------------------------------------------------------------------
// test_textfile_missing — operations on a non-existent file
// ---------------------------------------------------------------------------

/// Verifies correct behaviour when the textfile does not exist:
/// - `textfile_get` returns `None` (file cannot be opened for reading).
/// - `textfile_foreach` returns an error (file cannot be opened).
#[test]
fn test_textfile_missing() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    // File does not exist — no util_create_empty() call.
    assert!(!path.exists(), "test file should not exist initially");

    // Get from non-existent file returns None (mirrors C textfile_get
    // returning NULL on open() failure).
    let result = textfile_get(&path, "00:00:00:00:00:00");
    assert!(result.is_none(), "get from non-existent file should return None");

    // Foreach on non-existent file returns an error (cannot open for read).
    let foreach_result = textfile_foreach(&path, |_key, _value| {});
    assert!(foreach_result.is_err(), "foreach on non-existent file should return Err");
}

// ---------------------------------------------------------------------------
// test_textfile_format — verify exact on-disk file format
// ---------------------------------------------------------------------------

/// Verifies the exact on-disk file format: each entry is stored as
/// `key value\n` (single space separator, LF terminated).  This format
/// must be byte-identical to the C implementation to preserve existing
/// Bluetooth pairings and device data (AAP §0.7.10).
#[test]
fn test_textfile_format() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = test_path(&dir);

    textfile_put(&path, "AA:BB:CC:DD:EE:FF", "value1").expect("put key1 failed");
    textfile_put(&path, "11:22:33:44:55:66", "value2").expect("put key2 failed");

    // Read the raw file content and verify the exact format.
    let content = fs::read_to_string(&path).expect("failed to read textfile");

    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2, "file should contain exactly 2 lines");

    // Each line must be "key value" with a single space separator.
    assert_eq!(lines[0], "AA:BB:CC:DD:EE:FF value1");
    assert_eq!(lines[1], "11:22:33:44:55:66 value2");

    // The file must end with a newline character (each line is LF-terminated).
    assert!(content.ends_with('\n'), "file content should end with newline");

    // Verify total byte count: each line is "key value\n".
    // Line 1: "AA:BB:CC:DD:EE:FF value1\n" = 17 + 1 + 6 + 1 = 25 bytes
    // Line 2: "11:22:33:44:55:66 value2\n" = 17 + 1 + 6 + 1 = 25 bytes
    assert_eq!(content.len(), 50, "total file size should be 50 bytes");
}
