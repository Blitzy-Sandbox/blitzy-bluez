// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluetooth-meshd/src/util.rs
//
// Utility functions for the bluetooth-meshd daemon: debug packet
// dumps, monotonic timestamps, hex conversions, recursive directory
// creation / deletion, and a portable basename helper.
//
// Replaces mesh/util.c (173 lines) and mesh/util.h (24 lines) from
// the BlueZ v5.86 C codebase with idiomatic Rust equivalents.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::time::{ClockId, clock_gettime};
use tracing::{debug, error};

// ── Constants ───────────────────────────────────────────────────

/// Lowercase hex digit lookup table matching the C `hexdigits[]`
/// array used by `hex2str()` / `hex2str_buf()`.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

// ── Debug State ─────────────────────────────────────────────────

/// Global debug-enabled flag controlling `print_packet` output.
///
/// Set once during startup via [`enable_debug`].  Relaxed ordering
/// is sufficient because the flag is a simple boolean toggle that
/// is written once and then only read.
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable debug output for [`print_packet`].
///
/// In the original C code this additionally called
/// `l_debug_enable("*")`.  In Rust the tracing-subscriber handles
/// log-level filtering at the subscriber layer; this function only
/// sets the internal flag so that [`print_packet`] will produce
/// output.
pub fn enable_debug() {
    DEBUG_ENABLED.store(true, Ordering::Relaxed);
}

// ── Packet Debug Printing ───────────────────────────────────────

/// Print a labelled hex dump of `data` via [`tracing::debug!`].
///
/// Output format matches the C implementation exactly:
///
/// ```text
/// {secs % 100000:05}.{millis:03} {label}: {hex_string}
/// ```
///
/// Returns immediately if debugging has not been enabled via
/// [`enable_debug`].  An empty `data` slice produces the label
/// followed by the literal string `"empty"`.
pub fn print_packet(label: &str, data: &[u8]) {
    if !DEBUG_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    // Wall-clock time matching C's gettimeofday(&pkt_time, NULL).
    let (secs, millis) = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let s = dur.as_secs() % 100_000;
            let ms = dur.subsec_millis();
            (s, ms)
        }
        Err(_) => (0u64, 0u32),
    };

    if data.is_empty() {
        debug!("{:05}.{:03} {}: empty", secs, millis, label);
    } else {
        let hex_string = hex2str(data);
        debug!("{:05}.{:03} {}: {}", secs, millis, label, hex_string);
    }
}

// ── Timestamp ───────────────────────────────────────────────────

/// Return the current monotonic clock time in whole seconds.
///
/// Behavioural clone of the C version which calls
/// `clock_gettime(CLOCK_MONOTONIC, &ts)` and returns `ts.tv_sec`
/// cast to `uint32_t`.  Uses the safe `nix` wrapper (requires the
/// `"time"` Cargo feature on the `nix` crate).
pub fn get_timestamp_secs() -> u32 {
    match clock_gettime(ClockId::CLOCK_MONOTONIC) {
        Ok(ts) => ts.tv_sec() as u32,
        Err(_) => 0,
    }
}

// ── Hex Conversions ─────────────────────────────────────────────

/// Decode a single hex nibble character to its 4-bit value.
///
/// Accepts `0`–`9`, `a`–`f`, `A`–`F`.  Returns `None` for any
/// byte that is not a valid hex digit.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a hex string into a byte slice, returning `true` on
/// success.
///
/// `hex_str` must contain at least `out.len() * 2` valid hex
/// characters.  Each consecutive pair of characters is decoded
/// into one output byte.  Returns `false` if the input is too
/// short or contains invalid hex digits.
///
/// Replaces C `str2hex(str, in_len, out, out_len)` which uses
/// `sscanf("%02hhx", …)` per byte pair.
pub fn str2hex(hex_str: &str, out: &mut [u8]) -> bool {
    let bytes = hex_str.as_bytes();
    if bytes.len() < out.len() * 2 {
        return false;
    }
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = match hex_nibble(bytes[i * 2]) {
            Some(v) => v,
            None => return false,
        };
        let lo = match hex_nibble(bytes[i * 2 + 1]) {
            Some(v) => v,
            None => return false,
        };
        *slot = (hi << 4) | lo;
    }
    true
}

/// Convert a byte slice to a lowercase hex `String`.
///
/// Idiomatic Rust API returning an owned `String`.  Replaces the
/// C `l_util_hexstring()` helper and the manual `hexdigits[]`
/// table loop.
pub fn hex2str(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        s.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        s.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Convert a byte slice to a lowercase hex string inside a
/// caller-provided byte buffer.
///
/// Writes `data.len() * 2` hex characters into `out` followed by
/// a NUL terminator (for C-compatible consumers).  Returns the
/// number of **input** bytes converted, or `0` if `out` is too
/// small to hold the result plus terminator.
///
/// Replaces C `hex2str(in, in_len, out, out_len)`.
pub fn hex2str_buf(data: &[u8], out: &mut [u8]) -> usize {
    // +1 for the NUL terminator.
    let needed = data.len() * 2 + 1;
    if out.len() < needed {
        return 0;
    }
    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = HEX_DIGITS[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX_DIGITS[(byte & 0x0f) as usize];
    }
    out[data.len() * 2] = 0; // NUL terminator
    data.len()
}

// ── Directory Operations ────────────────────────────────────────

/// Recursively create all path components of `dir_name`.
///
/// If `dir_name` already exists as a regular file the function
/// returns `0` immediately without error — matching the C
/// implementation which performs a `stat()` check after the mkdir
/// walk and treats a regular-file hit as success.
///
/// Returns `0` on success, `1` on failure (matching the C return
/// convention).
///
/// Replaces the C `create_dir()` which manually splits the path
/// on `/` and calls `mkdir(dir, 0755)` for each component.
/// `std::fs::create_dir_all` provides equivalent semantics.
pub fn create_dir(dir_name: &str) -> i32 {
    // If the path already exists as a regular file, the C code
    // returns 0 after its mkdir loop.  Mirror that here.
    match std::fs::metadata(dir_name) {
        Ok(meta) if meta.is_file() => return 0,
        Ok(_) => return 0, // Already exists as a directory.
        Err(_) => {}
    }

    if let Err(e) = std::fs::create_dir_all(dir_name) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            error!("Failed to create dir({}): {}", dir_name, e);
            return 1;
        }
    }
    0
}

/// Recursively remove `path` (file **or** directory tree).
///
/// Replaces the C `del_path()` which uses `nftw()` with
/// `FTW_DEPTH | FTW_PHYS` and a callback that calls `remove()`
/// for files and `rmdir()` for directories.
///
/// `std::fs::remove_dir_all` performs identical depth-first
/// removal for directories.  For plain files
/// `std::fs::remove_file` is used instead.
///
/// Errors other than "not found" are logged but otherwise ignored
/// to match the original C behaviour where `nftw` errors are
/// silently discarded.
pub fn del_path(path: &str) {
    let p = Path::new(path);
    let result = if p.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) };
    if let Err(e) = result {
        if e.kind() != std::io::ErrorKind::NotFound {
            error!("Failed to delete {}: {}", path, e);
        }
    }
}

// ── Basename ────────────────────────────────────────────────────

/// Return the component after the last `/`, or the full string if
/// no `/` is present.
///
/// Replaces the C `mesh_basename()` fallback used when
/// `HAVE_DECL_BASENAME` is not available.  Matches the exact C
/// logic: `strrchr(path, '/')` and returning `p + 1`.
///
/// Note: `std::path::Path::file_name()` offers similar
/// functionality, but this implementation preserves byte-identical
/// semantics with the C version (e.g. trailing `/` returns `""`).
pub fn mesh_basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(pos) => &path[pos + 1..],
        None => path,
    }
}

// ── Unit Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── hex2str ─────────────────────────────────────────────────

    #[test]
    fn hex2str_basic_bytes() {
        assert_eq!(hex2str(&[0xab, 0xcd, 0xef]), "abcdef");
    }

    #[test]
    fn hex2str_boundary_values() {
        assert_eq!(hex2str(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn hex2str_empty_input() {
        assert_eq!(hex2str(&[]), "");
    }

    #[test]
    fn hex2str_all_nibbles() {
        let input: Vec<u8> = (0..=15).collect();
        let expected = "000102030405060708090a0b0c0d0e0f";
        assert_eq!(hex2str(&input), expected);
    }

    // ── str2hex ─────────────────────────────────────────────────

    #[test]
    fn str2hex_lowercase() {
        let mut buf = [0u8; 3];
        assert!(str2hex("abcdef", &mut buf));
        assert_eq!(buf, [0xab, 0xcd, 0xef]);
    }

    #[test]
    fn str2hex_uppercase() {
        let mut buf = [0u8; 2];
        assert!(str2hex("AABB", &mut buf));
        assert_eq!(buf, [0xaa, 0xbb]);
    }

    #[test]
    fn str2hex_mixed_case() {
        let mut buf = [0u8; 2];
        assert!(str2hex("aAbB", &mut buf));
        assert_eq!(buf, [0xaa, 0xbb]);
    }

    #[test]
    fn str2hex_too_short_input() {
        let mut buf = [0u8; 3];
        // 4 hex chars < 6 needed for 3 bytes
        assert!(!str2hex("aabb", &mut buf));
    }

    #[test]
    fn str2hex_invalid_chars() {
        let mut buf = [0u8; 2];
        assert!(!str2hex("zzzz", &mut buf));
    }

    #[test]
    fn str2hex_empty_output() {
        let mut buf = [0u8; 0];
        // Empty output is trivially satisfied.
        assert!(str2hex("", &mut buf));
    }

    #[test]
    fn str2hex_extra_input_ignored() {
        let mut buf = [0u8; 1];
        // "aabbcc" has 6 chars, we only need 2 for 1 byte.
        assert!(str2hex("aabbcc", &mut buf));
        assert_eq!(buf, [0xaa]);
    }

    // ── hex2str_buf ─────────────────────────────────────────────

    #[test]
    fn hex2str_buf_basic() {
        let mut buf = [0u8; 7]; // 3 bytes * 2 + NUL
        let count = hex2str_buf(&[0xab, 0xcd, 0xef], &mut buf);
        assert_eq!(count, 3);
        assert_eq!(&buf[..6], b"abcdef");
        assert_eq!(buf[6], 0); // NUL terminator
    }

    #[test]
    fn hex2str_buf_too_small() {
        let mut buf = [0u8; 2]; // too small for 1 byte (need 3)
        let count = hex2str_buf(&[0xab], &mut buf);
        assert_eq!(count, 0);
    }

    #[test]
    fn hex2str_buf_empty_data() {
        let mut buf = [0xffu8; 2];
        let count = hex2str_buf(&[], &mut buf);
        assert_eq!(count, 0);
        assert_eq!(buf[0], 0); // NUL written at position 0
    }

    #[test]
    fn hex2str_buf_exact_fit() {
        let mut buf = [0xffu8; 3]; // exactly 1 byte * 2 + NUL
        let count = hex2str_buf(&[0xfe], &mut buf);
        assert_eq!(count, 1);
        assert_eq!(&buf[..2], b"fe");
        assert_eq!(buf[2], 0);
    }

    // ── roundtrip ───────────────────────────────────────────────

    #[test]
    fn roundtrip_hex_conversion() {
        let original = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex_string = hex2str(&original);
        assert_eq!(hex_string, "0123456789abcdef");
        let mut recovered = [0u8; 8];
        assert!(str2hex(&hex_string, &mut recovered));
        assert_eq!(original, recovered);
    }

    // ── mesh_basename ───────────────────────────────────────────

    #[test]
    fn mesh_basename_with_slash() {
        assert_eq!(mesh_basename("/foo/bar/baz"), "baz");
    }

    #[test]
    fn mesh_basename_no_slash() {
        assert_eq!(mesh_basename("filename"), "filename");
    }

    #[test]
    fn mesh_basename_trailing_slash() {
        assert_eq!(mesh_basename("/foo/bar/"), "");
    }

    #[test]
    fn mesh_basename_root() {
        assert_eq!(mesh_basename("/"), "");
    }

    #[test]
    fn mesh_basename_single_component() {
        assert_eq!(mesh_basename("/file"), "file");
    }

    #[test]
    fn mesh_basename_empty_string() {
        assert_eq!(mesh_basename(""), "");
    }

    // ── get_timestamp_secs ──────────────────────────────────────

    #[test]
    fn get_timestamp_secs_nonzero() {
        // CLOCK_MONOTONIC should always return a positive value on
        // a running Linux system (time since boot).
        assert!(get_timestamp_secs() > 0);
    }

    #[test]
    fn get_timestamp_secs_monotonic() {
        let t1 = get_timestamp_secs();
        let t2 = get_timestamp_secs();
        // Monotonic guarantee: t2 >= t1 (may be equal within same
        // second).
        assert!(t2 >= t1);
    }

    // ── enable_debug + print_packet ─────────────────────────────

    #[test]
    fn enable_debug_sets_flag() {
        // Reset to known state (other tests may have enabled it).
        DEBUG_ENABLED.store(false, Ordering::Relaxed);
        assert!(!DEBUG_ENABLED.load(Ordering::Relaxed));
        enable_debug();
        assert!(DEBUG_ENABLED.load(Ordering::Relaxed));
    }

    #[test]
    fn print_packet_does_not_panic_when_disabled() {
        DEBUG_ENABLED.store(false, Ordering::Relaxed);
        // Should return immediately without side effects.
        print_packet("test", &[0x01, 0x02, 0x03]);
        print_packet("test", &[]);
    }

    #[test]
    fn print_packet_does_not_panic_when_enabled() {
        DEBUG_ENABLED.store(true, Ordering::Relaxed);
        // Even without a tracing subscriber, debug! should not
        // panic.
        print_packet("test-label", &[0xde, 0xad, 0xbe, 0xef]);
        print_packet("empty-test", &[]);
    }

    // ── create_dir + del_path ───────────────────────────────────

    #[test]
    fn create_and_delete_temp_dir() {
        let dir = "/tmp/blitzy_mesh_util_test_dir/sub1/sub2";
        // Ensure it doesn't already exist.
        let _ = std::fs::remove_dir_all("/tmp/blitzy_mesh_util_test_dir");

        assert_eq!(create_dir(dir), 0);
        assert!(Path::new(dir).is_dir());

        // Deleting the whole tree.
        del_path("/tmp/blitzy_mesh_util_test_dir");
        assert!(!Path::new("/tmp/blitzy_mesh_util_test_dir").exists());
    }

    #[test]
    fn create_dir_already_exists() {
        let dir = "/tmp/blitzy_mesh_util_test_existing";
        let _ = std::fs::create_dir_all(dir);
        // Should return 0 even if it already exists.
        assert_eq!(create_dir(dir), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn del_path_nonexistent() {
        // Deleting something that doesn't exist should not panic
        // or error.
        del_path("/tmp/blitzy_mesh_util_nonexistent_12345");
    }

    #[test]
    fn del_path_single_file() {
        let path = "/tmp/blitzy_mesh_util_test_file.txt";
        std::fs::write(path, "test content").expect("write test file");
        assert!(Path::new(path).exists());
        del_path(path);
        assert!(!Path::new(path).exists());
    }
}
