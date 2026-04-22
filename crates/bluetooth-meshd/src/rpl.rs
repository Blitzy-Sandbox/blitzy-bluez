// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Replay Protection List (RPL) persistence module for bluetooth-meshd.
 *
 * Replaces mesh/rpl.c (301 lines) and mesh/rpl.h (23 lines) from BlueZ v5.86.
 *
 * The RPL ensures replay attacks are rejected by persisting per-source
 * sequence-number high-water-marks on disk, organized in directories
 * keyed by IV index:
 *
 *   {node_path}/rpl/{iv_index:08x}/{src:04x}
 *
 * Each file contains exactly 6 ASCII hex characters representing the
 * sequence number. On IV index rotation, stale entries are pruned so
 * only the current and previous IV index directories are retained.
 */

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use tracing::error;

use crate::util::del_path;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Subdirectory name appended to the node storage path for RPL data.
const RPL_DIR: &str = "rpl";

/// Maximum valid sequence number (24-bit, from mesh network layer).
const SEQ_MASK: u32 = 0x00FF_FFFF;

// ---------------------------------------------------------------------------
// Address validation helpers (from mesh-defs.h IS_UNICAST macro)
// ---------------------------------------------------------------------------

/// Check whether `addr` is a unicast address (0x0001..=0x7FFF).
///
/// Equivalent to the C macro `IS_UNICAST(a)` defined in `mesh/mesh-defs.h`:
///   `((a) >= 0x0001 && (a) <= 0x7fff)`
#[inline]
fn is_unicast(addr: u16) -> bool {
    (0x0001..=0x7FFF).contains(&addr)
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Replay Protection List entry — mirrors C `struct mesh_rpl`.
///
/// Stores the highest observed sequence number from a given source
/// address at a specific IV index. Used to reject replayed messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRpl {
    /// IV index under which this entry was recorded.
    pub iv_index: u32,
    /// Highest observed sequence number from `src`.
    pub seq: u32,
    /// Source unicast address.
    pub src: u16,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Persist an RPL entry for `src` at the given `iv_index` with `seq`.
///
/// Creates `{node_path}/rpl/{iv_index:08x}/{src:04x}` containing 6 hex
/// digits of `seq`. Also removes the corresponding entry from the
/// previous IV index directory (`iv_index - 1`), if present.
///
/// Returns `true` on success.
///
/// Replaces C `rpl_put_entry(struct mesh_node *node, uint16_t src,
///                            uint32_t iv_index, uint32_t seq)`.
pub fn rpl_put_entry(node_path: &str, src: u16, iv_index: u32, seq: u32) -> bool {
    if !is_unicast(src) {
        return false;
    }

    // Build IV-index directory: {node_path}/rpl/{iv_index:08x}
    let iv_dir = PathBuf::from(node_path).join(RPL_DIR).join(format!("{iv_index:08x}"));

    if let Err(e) = fs::create_dir_all(&iv_dir) {
        error!("Failed to create RPL dir {}: {}", iv_dir.display(), e);
        return false;
    }

    // Write sequence number as 6-char hex string
    let file_path = iv_dir.join(format!("{src:04x}"));
    let seq_str = format!("{seq:06x}");

    match fs::File::create(&file_path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(seq_str.as_bytes()) {
                error!("Failed to write RPL entry {}: {}", file_path.display(), e);
                return false;
            }
        }
        Err(e) => {
            error!("Failed to create RPL file {}: {}", file_path.display(), e);
            return false;
        }
    }

    // Remove previous IV index entry for this source (iv_index - 1).
    // Wrapping subtraction handles iv_index == 0 gracefully — the
    // resulting path simply won't exist.
    let prev_iv = iv_index.wrapping_sub(1);
    let prev_file = PathBuf::from(node_path)
        .join(RPL_DIR)
        .join(format!("{prev_iv:08x}"))
        .join(format!("{src:04x}"));

    if let Err(e) = fs::remove_file(&prev_file) {
        // NotFound is expected — the entry may not exist in the
        // previous IV index directory.
        if e.kind() != std::io::ErrorKind::NotFound {
            error!("Failed to remove old RPL entry {}: {}", prev_file.display(), e);
        }
    }

    true
}

/// Delete RPL entries for `src` across all IV index directories.
///
/// Iterates every IV-index subdirectory under `{node_path}/rpl` and
/// removes the file named `{src:04x}`.
///
/// Replaces C `rpl_del_entry(struct mesh_node *node, uint16_t src)`.
pub fn rpl_del_entry(node_path: &str, src: u16) {
    if !is_unicast(src) {
        return;
    }

    let rpl_dir = PathBuf::from(node_path).join(RPL_DIR);

    let entries = match fs::read_dir(&rpl_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let src_name = format!("{src:04x}");

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let file_path = path.join(&src_name);
        if let Err(e) = fs::remove_file(&file_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                error!("Failed to remove RPL entry {}: {}", file_path.display(), e);
            }
        }
    }
}

/// Load the full RPL from disk into `rpl_list`.
///
/// Reads all `{node_path}/rpl/{iv_index:08x}/{src:04x}` files,
/// populating (or updating) entries in `rpl_list`. When two entries
/// share the same `src`, the one with the higher `iv_index` wins.
///
/// Returns `true` on success, `false` if the RPL directory cannot be
/// opened.
///
/// Replaces C `rpl_get_list(struct mesh_node *node,
///                           struct l_queue *rpl_list)`.
pub fn rpl_get_list(node_path: &str, rpl_list: &mut Vec<MeshRpl>) -> bool {
    let rpl_dir = PathBuf::from(node_path).join(RPL_DIR);

    let entries = match fs::read_dir(&rpl_dir) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to open RPL dir {}: {}", rpl_dir.display(), e);
            return false;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        get_entries(&path, rpl_list);
    }

    true
}

/// Prune stale IV-index directories, keeping only `cur` and `cur - 1`.
///
/// Iterates subdirectories under `{node_path}/rpl`. Any directory
/// whose name is malformed (not exactly 8 hex chars) or whose
/// parsed IV index value is neither `cur` nor `cur - 1` is
/// recursively deleted via `del_path`.
///
/// Replaces C `rpl_update(struct mesh_node *node, uint32_t cur)`.
pub fn rpl_update(node_path: &str, cur: u32) {
    let rpl_dir = PathBuf::from(node_path).join(RPL_DIR);

    // Ensure the RPL directory exists.
    if let Err(e) = fs::create_dir_all(&rpl_dir) {
        error!("Failed to create RPL dir {}: {}", rpl_dir.display(), e);
        return;
    }

    let entries = match fs::read_dir(&rpl_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let prev = cur.wrapping_sub(1);

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => {
                // Non-UTF-8 directory name — malformed, remove it.
                del_path(&path.to_string_lossy());
                continue;
            }
        };

        // Valid IV-index directory names are exactly 8 hex characters.
        if name.len() != 8 {
            del_path(&path.to_string_lossy());
            continue;
        }

        match u32::from_str_radix(&name, 16) {
            Ok(val) if val == cur || val == prev => {
                // Keep current and previous IV index directories.
            }
            _ => {
                // Stale or malformed — prune.
                del_path(&path.to_string_lossy());
            }
        }
    }
}

/// Create the RPL directory `{node_path}/rpl` if it does not exist.
///
/// Returns `true` on success.
///
/// Replaces C `rpl_init(const char *node_path)`.
pub fn rpl_init(node_path: &str) -> bool {
    let rpl_dir = PathBuf::from(node_path).join(RPL_DIR);

    if let Err(e) = fs::create_dir_all(&rpl_dir) {
        error!("Failed to create RPL dir {}: {}", rpl_dir.display(), e);
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Parse all RPL entry files within a single IV-index directory.
///
/// Each file is named `{src:04x}` and contains a 6-char hex sequence
/// number. Entries are merged into `rpl_list` — if an entry for the
/// same `src` already exists and the new `iv_index` is higher, the
/// existing entry is updated.
///
/// Replaces C static `get_entries(const char *iv_path,
///                                 struct l_queue *rpl_list)`.
fn get_entries(iv_path: &std::path::Path, rpl_list: &mut Vec<MeshRpl>) {
    // Extract IV index from the directory name.
    let dir_name = match iv_path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return,
    };

    let iv_index = match u32::from_str_radix(dir_name, 16) {
        Ok(v) => v,
        Err(_) => return,
    };

    let entries = match fs::read_dir(iv_path) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to read RPL IV dir {}: {}", iv_path.display(), e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let file_name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Parse source address from filename (4-char hex).
        let src = match u16::from_str_radix(&file_name, 16) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Read the 6-char hex sequence number.
        let seq = match read_seq_from_file(&path) {
            Some(s) => s,
            None => continue,
        };

        // Check for an existing entry with the same source.
        if let Some(existing) = rpl_list.iter_mut().find(|r| r.src == src) {
            // Update if the new IV index is strictly higher.
            if iv_index > existing.iv_index {
                existing.iv_index = iv_index;
                existing.seq = seq;
            }
        } else {
            // Add a new entry only if it passes validation.
            if seq <= SEQ_MASK && is_unicast(src) {
                rpl_list.push(MeshRpl { iv_index, seq, src });
            }
        }
    }
}

/// Read and parse a 6-char hex sequence number from an RPL entry file.
///
/// Returns `None` on any I/O or parse error.
fn read_seq_from_file(path: &std::path::Path) -> Option<u32> {
    let mut f = fs::File::open(path).ok()?;
    let mut buf = String::with_capacity(8);
    f.read_to_string(&mut buf).ok()?;
    let trimmed = buf.trim();
    u32::from_str_radix(trimmed, 16).ok()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Monotonic counter for unique temp directory names.
    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Create a unique temporary directory and return its path.
    /// The directory is created under `std::env::temp_dir()`.
    fn make_temp_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("rpl_test_{pid}_{id}"));
        let _ = fs::remove_dir_all(&dir); // clean up leftover from previous runs
        fs::create_dir_all(&dir).expect("Failed to create temp dir");
        dir
    }

    /// Remove temp directory after test.
    fn cleanup(dir: &PathBuf) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_is_unicast() {
        assert!(!is_unicast(0x0000));
        assert!(is_unicast(0x0001));
        assert!(is_unicast(0x7FFF));
        assert!(!is_unicast(0x8000));
        assert!(!is_unicast(0xFFFF));
    }

    #[test]
    fn test_rpl_init_creates_directory() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();

        assert!(rpl_init(node_path));
        assert!(tmp.join(RPL_DIR).is_dir());
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_put_entry_and_read() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();

        assert!(rpl_init(node_path));
        assert!(rpl_put_entry(node_path, 0x0001, 0x1234, 0x00ABCD));

        let file_path = tmp.join("rpl/00001234/0001");
        assert!(file_path.is_file());

        let contents = fs::read_to_string(&file_path).unwrap();
        assert_eq!(contents, "00abcd");
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_put_entry_removes_previous_iv() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();
        assert!(rpl_init(node_path));

        assert!(rpl_put_entry(node_path, 0x0001, 5, 10));
        let prev_file = tmp.join("rpl/00000005/0001");
        assert!(prev_file.is_file());

        assert!(rpl_put_entry(node_path, 0x0001, 6, 20));
        let new_file = tmp.join("rpl/00000006/0001");
        assert!(new_file.is_file());
        assert!(!prev_file.is_file());
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_put_entry_rejects_non_unicast() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();
        assert!(rpl_init(node_path));

        assert!(!rpl_put_entry(node_path, 0x0000, 1, 1));
        assert!(!rpl_put_entry(node_path, 0x8000, 1, 1));
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_del_entry() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();
        assert!(rpl_init(node_path));

        assert!(rpl_put_entry(node_path, 0x0001, 10, 100));
        assert!(rpl_put_entry(node_path, 0x0001, 11, 200));
        assert!(rpl_put_entry(node_path, 0x0002, 11, 300));

        rpl_del_entry(node_path, 0x0001);

        let f1 = tmp.join("rpl/0000000b/0001");
        assert!(!f1.exists());
        let f2 = tmp.join("rpl/0000000b/0002");
        assert!(f2.is_file());
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_get_list() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();
        assert!(rpl_init(node_path));

        assert!(rpl_put_entry(node_path, 0x0001, 5, 100));
        assert!(rpl_put_entry(node_path, 0x0002, 5, 200));
        assert!(rpl_put_entry(node_path, 0x0001, 6, 150));

        let mut list = Vec::new();
        assert!(rpl_get_list(node_path, &mut list));

        let entry1 = list.iter().find(|r| r.src == 0x0001).unwrap();
        assert_eq!(entry1.iv_index, 6);
        assert_eq!(entry1.seq, 150);

        let entry2 = list.iter().find(|r| r.src == 0x0002).unwrap();
        assert_eq!(entry2.iv_index, 5);
        assert_eq!(entry2.seq, 200);
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_get_list_dedup_keeps_higher_iv() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();
        assert!(rpl_init(node_path));

        // Manually create entries at two IV indices for the same src.
        let iv5_dir = tmp.join("rpl/00000005");
        fs::create_dir_all(&iv5_dir).unwrap();
        fs::write(iv5_dir.join("0001"), "000064").unwrap(); // seq=100

        let iv7_dir = tmp.join("rpl/00000007");
        fs::create_dir_all(&iv7_dir).unwrap();
        fs::write(iv7_dir.join("0001"), "0000c8").unwrap(); // seq=200

        let mut list = Vec::new();
        assert!(rpl_get_list(node_path, &mut list));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].iv_index, 7);
        assert_eq!(list[0].seq, 200);
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_update_prunes_stale() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();
        assert!(rpl_init(node_path));

        for iv in [3u32, 4, 5] {
            let dir = tmp.join(format!("rpl/{iv:08x}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("0001"), "000001").unwrap();
        }

        rpl_update(node_path, 5);

        assert!(tmp.join("rpl/00000005").is_dir());
        assert!(tmp.join("rpl/00000004").is_dir());
        assert!(!tmp.join("rpl/00000003").exists());
        cleanup(&tmp);
    }

    #[test]
    fn test_rpl_update_removes_malformed_dirs() {
        let tmp = make_temp_dir();
        let node_path = tmp.to_str().unwrap();
        assert!(rpl_init(node_path));

        let good_dir = tmp.join("rpl/0000000a");
        fs::create_dir_all(&good_dir).unwrap();
        let bad_dir = tmp.join("rpl/bad");
        fs::create_dir_all(&bad_dir).unwrap();

        rpl_update(node_path, 0x0A);

        assert!(good_dir.is_dir());
        assert!(!bad_dir.exists());
        cleanup(&tmp);
    }
}
