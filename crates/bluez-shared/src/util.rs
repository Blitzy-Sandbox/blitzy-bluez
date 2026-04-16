// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite
//
// Utility functions corresponding to src/shared/util.h / util.c.
// Many C utilities (endian helpers, memory allocation) are unnecessary in Rust.
// This module provides the remaining functionality: hex dump, string helpers,
// iov helpers, and LTV parsing.

use std::fmt::Write;

/// Format a byte buffer as a hex dump with directional prefix.
///
/// Corresponds to `util_hexdump()`. The `dir` character is typically
/// `'<'` for incoming or `'>'` for outgoing data.
///
/// Each line shows up to 16 bytes in hex, prefixed with the direction character.
pub fn hexdump(dir: char, buf: &[u8]) -> String {
    let mut output = String::new();
    for chunk in buf.chunks(16) {
        write!(output, "{} ", dir).unwrap();
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                output.push(' ');
            }
            write!(output, "{:02x} ", byte).unwrap();
        }
        output.push('\n');
    }
    output
}

/// Format bytes as a simple hex string (no separators).
pub fn hex_str(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len() * 2);
    for byte in buf {
        write!(s, "{:02x}", byte).unwrap();
    }
    s
}

/// Parse a hex string into bytes. Returns None on invalid input.
pub fn from_hex_str(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Replace all characters in `delimiters` within `s` with `replacement`.
/// Corresponds to `strdelimit()`.
pub fn str_delimit(s: &mut String, delimiters: &str, replacement: char) {
    let replaced: String = s
        .chars()
        .map(|c| if delimiters.contains(c) { replacement } else { c })
        .collect();
    *s = replaced;
}

/// Check if `s` ends with `suffix`. Corresponds to `strsuffix()`.
/// (Rust has `str::ends_with()` natively, but we provide this for API compat.)
pub fn str_suffix(s: &str, suffix: &str) -> bool {
    s.ends_with(suffix)
}

/// Strip leading and trailing whitespace. Corresponds to `strstrip()`.
/// (Rust has `str::trim()` natively.)
pub fn str_strip(s: &str) -> &str {
    s.trim()
}

/// Count the number of complete UTF-8 characters in the first `len` bytes.
/// Corresponds to `strnlenutf8()`.
pub fn str_n_len_utf8(s: &str, len: usize) -> usize {
    let bytes = s.as_bytes();
    let limit = len.min(bytes.len());
    // Find a valid UTF-8 boundary at or before limit
    let valid_str = match std::str::from_utf8(&bytes[..limit]) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
    };
    valid_str.chars().count()
}

/// Check if a byte slice is valid UTF-8. Corresponds to `strisutf8()`.
pub fn is_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

/// A growable byte buffer with push/pull cursor semantics.
///
/// Replaces the C `struct iovec` + `util_iov_push*` / `util_iov_pull*` pattern.
/// In C, an iovec has `iov_base` (pointer) and `iov_len` (length) that are
/// manipulated manually. In Rust, we use a `Vec<u8>` for push operations
/// and track a read cursor for pull operations.
#[derive(Debug, Clone, Default)]
pub struct IovBuf {
    data: Vec<u8>,
    read_pos: usize,
}

impl IovBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
            read_pos: 0,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            read_pos: 0,
        }
    }

    /// Total bytes written.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Bytes remaining to be read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.read_pos
    }

    /// Get the full buffer contents.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the unread portion of the buffer.
    pub fn unread(&self) -> &[u8] {
        &self.data[self.read_pos..]
    }

    // ---- Push operations (append to buffer) ----

    /// Append raw bytes. Corresponds to `util_iov_push_mem()`.
    pub fn push_mem(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Append a u8. Corresponds to `util_iov_push_u8()`.
    pub fn push_u8(&mut self, val: u8) {
        self.data.push(val);
    }

    /// Append a u16 in little-endian. Corresponds to `util_iov_push_le16()`.
    pub fn push_le16(&mut self, val: u16) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a u16 in big-endian. Corresponds to `util_iov_push_be16()`.
    pub fn push_be16(&mut self, val: u16) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a u24 in little-endian (3 bytes). Corresponds to `util_iov_push_le24()`.
    pub fn push_le24(&mut self, val: u32) {
        let bytes = val.to_le_bytes();
        self.data.extend_from_slice(&bytes[..3]);
    }

    /// Append a u24 in big-endian (3 bytes). Corresponds to `util_iov_push_be24()`.
    pub fn push_be24(&mut self, val: u32) {
        let bytes = val.to_be_bytes();
        self.data.extend_from_slice(&bytes[1..4]);
    }

    /// Append a u32 in little-endian. Corresponds to `util_iov_push_le32()`.
    pub fn push_le32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a u32 in big-endian. Corresponds to `util_iov_push_be32()`.
    pub fn push_be32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a u64 in little-endian. Corresponds to `util_iov_push_le64()`.
    pub fn push_le64(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a u64 in big-endian. Corresponds to `util_iov_push_be64()`.
    pub fn push_be64(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    // ---- Pull operations (read from cursor) ----

    /// Pull `len` bytes from the read cursor. Returns None if insufficient data.
    /// Corresponds to `util_iov_pull_mem()`.
    pub fn pull_mem(&mut self, len: usize) -> Option<&[u8]> {
        if self.remaining() < len {
            return None;
        }
        let start = self.read_pos;
        self.read_pos += len;
        Some(&self.data[start..start + len])
    }

    /// Pull a u8. Corresponds to `util_iov_pull_u8()`.
    pub fn pull_u8(&mut self) -> Option<u8> {
        let bytes = self.pull_mem(1)?;
        Some(bytes[0])
    }

    /// Pull a u16 in little-endian. Corresponds to `util_iov_pull_le16()`.
    pub fn pull_le16(&mut self) -> Option<u16> {
        let bytes = self.pull_mem(2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Pull a u16 in big-endian. Corresponds to `util_iov_pull_be16()`.
    pub fn pull_be16(&mut self) -> Option<u16> {
        let bytes = self.pull_mem(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Pull a u24 in little-endian (returns u32). Corresponds to `util_iov_pull_le24()`.
    pub fn pull_le24(&mut self) -> Option<u32> {
        let bytes = self.pull_mem(3)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]))
    }

    /// Pull a u24 in big-endian (returns u32). Corresponds to `util_iov_pull_be24()`.
    pub fn pull_be24(&mut self) -> Option<u32> {
        let bytes = self.pull_mem(3)?;
        Some(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    /// Pull a u32 in little-endian. Corresponds to `util_iov_pull_le32()`.
    pub fn pull_le32(&mut self) -> Option<u32> {
        let bytes = self.pull_mem(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Pull a u32 in big-endian. Corresponds to `util_iov_pull_be32()`.
    pub fn pull_be32(&mut self) -> Option<u32> {
        let bytes = self.pull_mem(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Pull a u64 in little-endian. Corresponds to `util_iov_pull_le64()`.
    pub fn pull_le64(&mut self) -> Option<u64> {
        let bytes = self.pull_mem(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Some(u64::from_le_bytes(arr))
    }

    /// Pull a u64 in big-endian. Corresponds to `util_iov_pull_be64()`.
    pub fn pull_be64(&mut self) -> Option<u64> {
        let bytes = self.pull_mem(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Some(u64::from_be_bytes(arr))
    }
}

/// LTV (Length-Type-Value) iterator over a byte slice.
///
/// Corresponds to `util_ltv_foreach()`. Iterates over entries where each
/// entry is: [length] [type] [value...], with length including the type byte.
pub struct LtvIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> LtvIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

/// A single LTV entry: length (including type byte), type, and value.
#[derive(Debug, Clone)]
pub struct LtvEntry<'a> {
    pub entry_type: u8,
    pub value: &'a [u8],
}

impl<'a> Iterator for LtvIter<'a> {
    type Item = LtvEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }

        let len = self.data[self.pos] as usize;
        if len == 0 {
            return None;
        }

        // length byte includes the type byte, so value length is len - 1
        if self.pos + 1 + len > self.data.len() {
            return None;
        }

        let entry_type = self.data[self.pos + 1];
        let value = &self.data[self.pos + 2..self.pos + 1 + len];
        self.pos += 1 + len;

        Some(LtvEntry { entry_type, value })
    }
}

/// Push an LTV entry onto an IovBuf. Corresponds to `util_ltv_push()`.
pub fn ltv_push(buf: &mut IovBuf, entry_type: u8, value: &[u8]) {
    let len = (value.len() + 1) as u8; // +1 for the type byte
    buf.push_u8(len);
    buf.push_u8(entry_type);
    buf.push_mem(value);
}

/// UID bitmap allocator. Corresponds to `util_get_uid()` / `util_clear_uid()`.
///
/// Allocates IDs from a bitmap, returning the lowest available ID (1-based).
pub fn get_uid(bitmap: &mut u64, max: u8) -> Option<u8> {
    for i in 0..max {
        if *bitmap & (1u64 << i) == 0 {
            *bitmap |= 1u64 << i;
            return Some(i + 1);
        }
    }
    None
}

/// Clear a previously allocated UID. ID is 1-based.
pub fn clear_uid(bitmap: &mut u64, id: u8) {
    if id > 0 {
        *bitmap &= !(1u64 << (id - 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let output = hexdump('>', &data);
        assert!(output.contains("> 01 02 03 04"));
    }

    #[test]
    fn test_hexdump_multiline() {
        let data: Vec<u8> = (0..20).collect();
        let output = hexdump('<', &data);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_hex_str() {
        assert_eq!(hex_str(&[0xAB, 0xCD, 0xEF]), "abcdef");
        assert_eq!(hex_str(&[]), "");
    }

    #[test]
    fn test_from_hex_str() {
        assert_eq!(from_hex_str("abcdef"), Some(vec![0xAB, 0xCD, 0xEF]));
        assert_eq!(from_hex_str("ABCDEF"), Some(vec![0xAB, 0xCD, 0xEF]));
        assert_eq!(from_hex_str(""), Some(vec![]));
        assert_eq!(from_hex_str("abc"), None); // odd length
        assert_eq!(from_hex_str("zz"), None); // invalid hex
    }

    #[test]
    fn test_str_delimit() {
        let mut s = "hello-world_test".to_string();
        str_delimit(&mut s, "-_", '.');
        assert_eq!(s, "hello.world.test");
    }

    #[test]
    fn test_str_suffix() {
        assert!(str_suffix("hello.txt", ".txt"));
        assert!(!str_suffix("hello.txt", ".rs"));
    }

    #[test]
    fn test_str_strip() {
        assert_eq!(str_strip("  hello  "), "hello");
        assert_eq!(str_strip("hello"), "hello");
    }

    #[test]
    fn test_str_n_len_utf8() {
        assert_eq!(str_n_len_utf8("hello", 5), 5);
        assert_eq!(str_n_len_utf8("hello", 3), 3);
        assert_eq!(str_n_len_utf8("héllo", 2), 1); // 'é' is 2 bytes, only first byte is within limit
    }

    #[test]
    fn test_is_utf8() {
        assert!(is_utf8(b"hello"));
        assert!(is_utf8("héllo".as_bytes()));
        assert!(!is_utf8(&[0xFF, 0xFE]));
    }

    #[test]
    fn test_iov_buf_push_pull() {
        let mut buf = IovBuf::new();
        buf.push_u8(0x42);
        buf.push_le16(0x1234);
        buf.push_be16(0x5678);
        buf.push_le32(0xDEADBEEF);
        buf.push_be32(0xCAFEBABE);
        buf.push_le64(0x0102030405060708);

        assert_eq!(buf.len(), 1 + 2 + 2 + 4 + 4 + 8);

        let mut reader = IovBuf::from_slice(buf.as_slice());
        assert_eq!(reader.pull_u8(), Some(0x42));
        assert_eq!(reader.pull_le16(), Some(0x1234));
        assert_eq!(reader.pull_be16(), Some(0x5678));
        assert_eq!(reader.pull_le32(), Some(0xDEADBEEF));
        assert_eq!(reader.pull_be32(), Some(0xCAFEBABE));
        assert_eq!(reader.pull_le64(), Some(0x0102030405060708));
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn test_iov_buf_pull_insufficient() {
        let mut buf = IovBuf::from_slice(&[0x01]);
        assert_eq!(buf.pull_u8(), Some(0x01));
        assert_eq!(buf.pull_u8(), None);
        assert_eq!(buf.pull_le16(), None);
    }

    #[test]
    fn test_iov_buf_le24_be24() {
        let mut buf = IovBuf::new();
        buf.push_le24(0x123456);
        buf.push_be24(0x789ABC);

        let mut reader = IovBuf::from_slice(buf.as_slice());
        assert_eq!(reader.pull_le24(), Some(0x123456));
        assert_eq!(reader.pull_be24(), Some(0x789ABC));
    }

    #[test]
    fn test_iov_buf_mem() {
        let mut buf = IovBuf::new();
        buf.push_mem(&[0x01, 0x02, 0x03]);

        let mut reader = IovBuf::from_slice(buf.as_slice());
        let mem = reader.pull_mem(3).unwrap();
        assert_eq!(mem, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_ltv_iter() {
        // Build LTV data: [len=3, type=0x01, val=0xAA, 0xBB], [len=2, type=0x02, val=0xCC]
        let data = [0x03, 0x01, 0xAA, 0xBB, 0x02, 0x02, 0xCC];
        let entries: Vec<LtvEntry> = LtvIter::new(&data).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_type, 0x01);
        assert_eq!(entries[0].value, &[0xAA, 0xBB]);
        assert_eq!(entries[1].entry_type, 0x02);
        assert_eq!(entries[1].value, &[0xCC]);
    }

    #[test]
    fn test_ltv_push() {
        let mut buf = IovBuf::new();
        ltv_push(&mut buf, 0x01, &[0xAA, 0xBB]);
        assert_eq!(buf.as_slice(), &[0x03, 0x01, 0xAA, 0xBB]);
    }

    #[test]
    fn test_ltv_iter_empty() {
        let entries: Vec<LtvEntry> = LtvIter::new(&[]).collect();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_ltv_iter_zero_length_terminates() {
        let data = [0x02, 0x01, 0xAA, 0x00, 0x02, 0x03, 0xBB];
        let entries: Vec<LtvEntry> = LtvIter::new(&data).collect();
        assert_eq!(entries.len(), 1); // stops at zero-length entry
    }

    #[test]
    fn test_uid_allocator() {
        let mut bitmap: u64 = 0;
        assert_eq!(get_uid(&mut bitmap, 8), Some(1));
        assert_eq!(get_uid(&mut bitmap, 8), Some(2));
        assert_eq!(get_uid(&mut bitmap, 8), Some(3));

        clear_uid(&mut bitmap, 2);
        assert_eq!(get_uid(&mut bitmap, 8), Some(2)); // reuses freed ID

        // Fill all 8
        for _ in 0..5 {
            get_uid(&mut bitmap, 8);
        }
        assert_eq!(get_uid(&mut bitmap, 8), None); // full
    }

    #[test]
    fn test_iov_buf_be64() {
        let mut buf = IovBuf::new();
        buf.push_be64(0x0102030405060708);
        let mut reader = IovBuf::from_slice(buf.as_slice());
        assert_eq!(reader.pull_be64(), Some(0x0102030405060708));
    }

    // ---------------------------------------------------------------
    // Tests ported from unit/test-lib.c
    // ---------------------------------------------------------------

    /// test_ntoh64 from test-lib.c: verify big-endian u64 byte order.
    ///
    /// In Rust, u64::from_be() is the equivalent of ntoh64/be64toh.
    #[test]
    fn test_c_ntoh64() {
        let test_val: u64 = 0x0123456789abcdef;
        // ntoh64 = be64toh = from_be
        let result = u64::from_be(test_val);
        let expected = u64::from_be_bytes(test_val.to_ne_bytes());
        assert_eq!(result, expected);
    }

    /// test_hton64 from test-lib.c: verify host-to-big-endian u64.
    ///
    /// In Rust, u64::to_be() is the equivalent of hton64/htobe64.
    #[test]
    fn test_c_hton64() {
        let test_val: u64 = 0x0123456789abcdef;
        // hton64 = htobe64 = to_be
        let result = test_val.to_be();
        let expected = u64::from_ne_bytes(test_val.to_be_bytes());
        assert_eq!(result, expected);
    }

    /// Verify that to_be/from_be are inverses.
    #[test]
    fn test_c_ntoh_hton_roundtrip() {
        let test_val: u64 = 0x0123456789abcdef;
        assert_eq!(u64::from_be(test_val.to_be()), test_val);
    }
}
