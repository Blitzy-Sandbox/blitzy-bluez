//! Endianness conversion, unaligned byte access, IoBuf read/write buffer,
//! LTV (Length-Type-Value) helpers, hex dump, and general utility functions.
//!
//! This module is the lowest-level foundation used by virtually every other
//! module in the BlueZ stack. It replaces the C implementation in
//! `src/shared/util.c` and `src/shared/util.h`.

use std::fmt;
use std::io::Read;

// =============================================================================
// Endian conversion functions (const fn)
// =============================================================================

/// Convert a little-endian `u16` value to native (CPU) byte order.
#[inline]
pub const fn le16_to_cpu(val: u16) -> u16 {
    u16::from_le(val)
}

/// Convert a little-endian `u32` value to native (CPU) byte order.
#[inline]
pub const fn le32_to_cpu(val: u32) -> u32 {
    u32::from_le(val)
}

/// Convert a little-endian `u64` value to native (CPU) byte order.
#[inline]
pub const fn le64_to_cpu(val: u64) -> u64 {
    u64::from_le(val)
}

/// Convert a native (CPU) `u16` value to little-endian byte order.
#[inline]
pub const fn cpu_to_le16(val: u16) -> u16 {
    val.to_le()
}

/// Convert a native (CPU) `u32` value to little-endian byte order.
#[inline]
pub const fn cpu_to_le32(val: u32) -> u32 {
    val.to_le()
}

/// Convert a native (CPU) `u64` value to little-endian byte order.
#[inline]
pub const fn cpu_to_le64(val: u64) -> u64 {
    val.to_le()
}

/// Convert a big-endian `u16` value to native (CPU) byte order.
#[inline]
pub const fn be16_to_cpu(val: u16) -> u16 {
    u16::from_be(val)
}

/// Convert a big-endian `u32` value to native (CPU) byte order.
#[inline]
pub const fn be32_to_cpu(val: u32) -> u32 {
    u32::from_be(val)
}

/// Convert a big-endian `u64` value to native (CPU) byte order.
#[inline]
pub const fn be64_to_cpu(val: u64) -> u64 {
    u64::from_be(val)
}

/// Convert a native (CPU) `u16` value to big-endian byte order.
#[inline]
pub const fn cpu_to_be16(val: u16) -> u16 {
    val.to_be()
}

/// Convert a native (CPU) `u32` value to big-endian byte order.
#[inline]
pub const fn cpu_to_be32(val: u32) -> u32 {
    val.to_be()
}

/// Convert a native (CPU) `u64` value to big-endian byte order.
#[inline]
pub const fn cpu_to_be64(val: u64) -> u64 {
    val.to_be()
}

// =============================================================================
// Unaligned byte access — get (read) functions
// =============================================================================

/// Read a single unsigned byte from a byte slice.
#[inline]
pub fn get_u8(data: &[u8]) -> u8 {
    data[0]
}

/// Read a single signed byte from a byte slice.
#[inline]
pub fn get_s8(data: &[u8]) -> i8 {
    data[0] as i8
}

/// Read a little-endian `u16` from an unaligned byte slice.
#[inline]
pub fn get_le16(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

/// Read a big-endian `u16` from an unaligned byte slice.
#[inline]
pub fn get_be16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

/// Read a little-endian 24-bit value from an unaligned byte slice as `u32`.
///
/// Reads 3 bytes: the first two as a little-endian `u16`, and the third byte
/// shifted left by 16 bits.
#[inline]
pub fn get_le24(data: &[u8]) -> u32 {
    u32::from(data[2]) << 16 | u32::from(get_le16(data))
}

/// Read a big-endian 24-bit value from an unaligned byte slice as `u32`.
///
/// Reads 3 bytes: the first byte shifted left by 16 bits, and the next two
/// as a big-endian `u16`.
#[inline]
pub fn get_be24(data: &[u8]) -> u32 {
    u32::from(data[0]) << 16 | u32::from(get_be16(&data[1..]))
}

/// Read a little-endian `u32` from an unaligned byte slice.
#[inline]
pub fn get_le32(data: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[..4]);
    u32::from_le_bytes(buf)
}

/// Read a big-endian `u32` from an unaligned byte slice.
#[inline]
pub fn get_be32(data: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[..4]);
    u32::from_be_bytes(buf)
}

/// Read a little-endian `u64` from an unaligned byte slice.
#[inline]
pub fn get_le64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[..8]);
    u64::from_le_bytes(buf)
}

/// Read a big-endian `u64` from an unaligned byte slice.
#[inline]
pub fn get_be64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[..8]);
    u64::from_be_bytes(buf)
}

// =============================================================================
// Unaligned byte access — put (write) functions
// =============================================================================

/// Write a single unsigned byte to a mutable byte slice.
#[inline]
pub fn put_u8(val: u8, dst: &mut [u8]) {
    dst[0] = val;
}

/// Write a little-endian `u16` to an unaligned mutable byte slice.
#[inline]
pub fn put_le16(val: u16, dst: &mut [u8]) {
    dst[..2].copy_from_slice(&val.to_le_bytes());
}

/// Write a big-endian `u16` to an unaligned mutable byte slice.
#[inline]
pub fn put_be16(val: u16, dst: &mut [u8]) {
    dst[..2].copy_from_slice(&val.to_be_bytes());
}

/// Write a little-endian 24-bit value (from `u32`) to an unaligned mutable
/// byte slice. Writes the low 16 bits as little-endian, then the third byte.
#[inline]
pub fn put_le24(val: u32, dst: &mut [u8]) {
    put_le16(val as u16, dst);
    dst[2] = (val >> 16) as u8;
}

/// Write a big-endian 24-bit value (from `u32`) to an unaligned mutable
/// byte slice. Writes the high byte first, then the low 16 bits as big-endian.
#[inline]
pub fn put_be24(val: u32, dst: &mut [u8]) {
    dst[0] = (val >> 16) as u8;
    put_be16(val as u16, &mut dst[1..]);
}

/// Write a little-endian `u32` to an unaligned mutable byte slice.
#[inline]
pub fn put_le32(val: u32, dst: &mut [u8]) {
    dst[..4].copy_from_slice(&val.to_le_bytes());
}

/// Write a big-endian `u32` to an unaligned mutable byte slice.
#[inline]
pub fn put_be32(val: u32, dst: &mut [u8]) {
    dst[..4].copy_from_slice(&val.to_be_bytes());
}

/// Write a little-endian `u64` to an unaligned mutable byte slice.
#[inline]
pub fn put_le64(val: u64, dst: &mut [u8]) {
    dst[..8].copy_from_slice(&val.to_le_bytes());
}

/// Write a big-endian `u64` to an unaligned mutable byte slice.
#[inline]
pub fn put_be64(val: u64, dst: &mut [u8]) {
    dst[..8].copy_from_slice(&val.to_be_bytes());
}

// =============================================================================
// IoBuf — Resizable byte buffer with read cursor
// =============================================================================

/// A resizable byte buffer with a read cursor, replacing C's `struct iovec`
/// used throughout BlueZ as a combined read/write protocol buffer.
///
/// `IoBuf` supports two modes of operation:
/// - **Write mode**: append data using `push_*` methods (data grows at the end)
/// - **Read mode**: consume data using `pull_*` methods (cursor advances forward)
///
/// The read cursor (`offset`) is independent of the write position, allowing
/// data to be written and then read back sequentially.
pub struct IoBuf {
    data: Vec<u8>,
    offset: usize,
}

impl IoBuf {
    // ---- Constructors ----

    /// Create a new empty `IoBuf`.
    pub fn new() -> Self {
        IoBuf { data: Vec::new(), offset: 0 }
    }

    /// Create a new `IoBuf` with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        IoBuf { data: Vec::with_capacity(capacity), offset: 0 }
    }

    /// Create a new `IoBuf` from existing data for parsing.
    ///
    /// The read cursor starts at position 0, ready to pull data.
    pub fn from_bytes(data: &[u8]) -> Self {
        IoBuf { data: data.to_vec(), offset: 0 }
    }

    // ---- Pull (read) operations ----

    /// Pull `len` raw bytes from the buffer, advancing the read cursor.
    ///
    /// Returns `None` if fewer than `len` bytes remain.
    /// Replaces `util_iov_pull_mem`.
    pub fn pull_mem(&mut self, len: usize) -> Option<&[u8]> {
        if self.remaining() < len {
            return None;
        }
        let start = self.offset;
        self.offset += len;
        Some(&self.data[start..start + len])
    }

    /// Pull a single `u8` from the buffer.
    ///
    /// Returns `None` if no bytes remain.
    pub fn pull_u8(&mut self) -> Option<u8> {
        if self.remaining() < 1 {
            return None;
        }
        let val = self.data[self.offset];
        self.offset += 1;
        Some(val)
    }

    /// Pull a little-endian `u16` from the buffer.
    pub fn pull_le16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let val = get_le16(&self.data[self.offset..]);
        self.offset += 2;
        Some(val)
    }

    /// Pull a little-endian `u32` from the buffer.
    pub fn pull_le32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let val = get_le32(&self.data[self.offset..]);
        self.offset += 4;
        Some(val)
    }

    /// Pull a little-endian `u64` from the buffer.
    pub fn pull_le64(&mut self) -> Option<u64> {
        if self.remaining() < 8 {
            return None;
        }
        let val = get_le64(&self.data[self.offset..]);
        self.offset += 8;
        Some(val)
    }

    /// Pull a big-endian `u16` from the buffer.
    pub fn pull_be16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let val = get_be16(&self.data[self.offset..]);
        self.offset += 2;
        Some(val)
    }

    /// Pull a big-endian `u32` from the buffer.
    pub fn pull_be32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let val = get_be32(&self.data[self.offset..]);
        self.offset += 4;
        Some(val)
    }

    /// Pull a big-endian `u64` from the buffer.
    pub fn pull_be64(&mut self) -> Option<u64> {
        if self.remaining() < 8 {
            return None;
        }
        let val = get_be64(&self.data[self.offset..]);
        self.offset += 8;
        Some(val)
    }

    /// Pull a little-endian 24-bit value from the buffer as `u32`.
    pub fn pull_le24(&mut self) -> Option<u32> {
        if self.remaining() < 3 {
            return None;
        }
        let val = get_le24(&self.data[self.offset..]);
        self.offset += 3;
        Some(val)
    }

    /// Pull a big-endian 24-bit value from the buffer as `u32`.
    pub fn pull_be24(&mut self) -> Option<u32> {
        if self.remaining() < 3 {
            return None;
        }
        let val = get_be24(&self.data[self.offset..]);
        self.offset += 3;
        Some(val)
    }

    /// Pull a little-endian boolean value from the buffer.
    ///
    /// Reads a single byte; nonzero is `true`, zero is `false`.
    /// Replaces `util_iov_pull_le_bv`.
    pub fn pull_le_bool(&mut self) -> Option<bool> {
        self.pull_u8().map(|v| v != 0)
    }

    /// Advance the read cursor by `len` bytes without reading data.
    ///
    /// Returns `true` if the skip succeeded, `false` if insufficient data.
    /// Replaces `util_iov_pull`.
    pub fn pull(&mut self, len: usize) -> bool {
        if self.remaining() < len {
            return false;
        }
        self.offset += len;
        true
    }

    // ---- Push (write) operations ----

    /// Append raw bytes to the end of the buffer.
    ///
    /// Replaces `util_iov_push_mem`.
    pub fn push_mem(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Append a single `u8` to the buffer.
    pub fn push_u8(&mut self, val: u8) {
        self.data.push(val);
    }

    /// Append a little-endian `u16` to the buffer.
    pub fn push_le16(&mut self, val: u16) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a little-endian `u32` to the buffer.
    pub fn push_le32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a little-endian `u64` to the buffer.
    pub fn push_le64(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian `u16` to the buffer.
    pub fn push_be16(&mut self, val: u16) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a big-endian `u32` to the buffer.
    pub fn push_be32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a big-endian `u64` to the buffer.
    pub fn push_be64(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian 24-bit value (from `u32`) to the buffer.
    pub fn push_le24(&mut self, val: u32) {
        self.data.extend_from_slice(&(val as u16).to_le_bytes());
        self.data.push((val >> 16) as u8);
    }

    /// Append a big-endian 24-bit value (from `u32`) to the buffer.
    pub fn push_be24(&mut self, val: u32) {
        self.data.push((val >> 16) as u8);
        self.data.extend_from_slice(&(val as u16).to_be_bytes());
    }

    // ---- Utility methods ----

    /// Append data to the buffer. Alias for [`push_mem`](IoBuf::push_mem).
    ///
    /// Replaces `util_iov_append`.
    pub fn append(&mut self, data: &[u8]) {
        self.push_mem(data);
    }

    /// Replace the buffer contents with a copy of `src`, up to `len` bytes.
    ///
    /// Resets the read cursor to position 0.
    /// Replaces `util_iov_memcpy`.
    pub fn memcpy_from(&mut self, src: &[u8], len: usize) {
        let actual_len = len.min(src.len());
        self.data.clear();
        self.data.extend_from_slice(&src[..actual_len]);
        self.offset = 0;
    }

    /// Return the total number of bytes in the buffer.
    ///
    /// This is the full data length, not the remaining unread bytes.
    /// Replaces `util_iov_len`.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the buffer contains no data at all.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the number of unread bytes remaining after the read cursor.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Return a view of the entire buffer contents.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return a view of the unread bytes from the current read cursor onward.
    pub fn remaining_bytes(&self) -> &[u8] {
        &self.data[self.offset..]
    }
}

// =============================================================================
// IoBuf trait implementations
// =============================================================================

impl Default for IoBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for IoBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoBuf")
            .field("len", &self.data.len())
            .field("offset", &self.offset)
            .field("remaining", &self.remaining())
            .finish()
    }
}

impl From<Vec<u8>> for IoBuf {
    fn from(data: Vec<u8>) -> Self {
        IoBuf { data, offset: 0 }
    }
}

impl From<&[u8]> for IoBuf {
    fn from(data: &[u8]) -> Self {
        IoBuf::from_bytes(data)
    }
}

// =============================================================================
// LTV (Length-Type-Value) helpers
// =============================================================================

/// Append an LTV (Length-Type-Value) record to an [IoBuf].
///
/// The length byte encodes data.len() + 1 (includes the type byte but not
/// the length byte itself), followed by the type byte, then the data payload.
/// This matches the BlueZ LTV convention used in advertising data, codec
/// capabilities, and other TLV-encoded structures.
pub fn ltv_push(output: &mut IoBuf, ltv_type: u8, data: &[u8]) {
    let length = (data.len() + 1) as u8;
    output.push_u8(length);
    output.push_u8(ltv_type);
    output.push_mem(data);
}

/// Iterate over LTV (Length-Type-Value) records in a byte slice.
///
/// For each record the callback receives (type_byte, data_slice).
/// If the callback returns false, iteration stops and this function returns
/// false. Returns true when all records have been processed successfully.
///
/// Records with a length byte of zero are skipped. Iteration stops if the
/// remaining data is insufficient for the advertised length.
pub fn ltv_foreach(data: &[u8], mut callback: impl FnMut(u8, &[u8]) -> bool) -> bool {
    let mut offset = 0;

    while offset < data.len() {
        let length = data[offset] as usize;
        offset += 1;

        if length == 0 {
            continue;
        }

        if offset + length > data.len() {
            break;
        }

        let ltv_type = data[offset];
        let ltv_data = &data[offset + 1..offset + length];
        offset += length;

        if !callback(ltv_type, ltv_data) {
            return false;
        }
    }

    true
}

// =============================================================================
// Debug and hex dump utilities
// =============================================================================

/// Dispatch a debug message string through a callback.
///
/// This is a thin Rust wrapper around the BlueZ util_debug pattern.
/// In idiomatic Rust code prefer the tracing crate macros instead.
pub fn util_debug(callback: &mut dyn FnMut(&str), message: &str) {
    if message.is_empty() {
        return;
    }
    callback(message);
}

/// Produce a hex dump of data in 16-byte-per-line format, invoking
/// callback with each formatted line.
///
/// The output format matches the original BlueZ util_hexdump layout:
/// The first line uses prefix as the direction indicator. Subsequent
/// (continuation) lines are padded with spaces to the same width.
pub fn hexdump(prefix: &str, data: &[u8], mut callback: impl FnMut(&str)) {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    if data.is_empty() {
        return;
    }

    let prefix_len = prefix.len();
    let mut is_first_line = true;

    for chunk_start in (0..data.len()).step_by(16) {
        let chunk_end = chunk_start.saturating_add(16).min(data.len());
        let chunk = &data[chunk_start..chunk_end];
        let chunk_len = chunk.len();

        let mut line = String::with_capacity(prefix_len + 1 + 48 + 1 + 16);

        if is_first_line {
            line.push_str(prefix);
            is_first_line = false;
        } else {
            for _ in 0..prefix_len {
                line.push(' ');
            }
        }

        line.push(' ');

        // Hex column: print each byte as two hex digits, pad missing bytes
        for byte in chunk.iter().take(16) {
            line.push(HEX_DIGITS[(*byte >> 4) as usize] as char);
            line.push(HEX_DIGITS[(*byte & 0x0f) as usize] as char);
            line.push(' ');
        }
        for _ in chunk_len..16 {
            line.push_str("   ");
        }

        line.push(' ');

        // ASCII column: printable characters or '.'
        for byte in chunk.iter().take(16) {
            if (0x20..=0x7E).contains(byte) {
                line.push(*byte as char);
            } else {
                line.push('.');
            }
        }
        for _ in chunk_len..16 {
            line.push(' ');
        }

        callback(&line);
    }
}

// =============================================================================
// Bitfield and system utilities
// =============================================================================

/// Check whether a 64-bit bitfield has even parity.
///
/// Returns true if the number of set bits is even (even parity).
pub fn bitfield_has_parity(val: u64) -> bool {
    val.count_ones() % 2 == 0
}

/// Fill buf with cryptographically-secure random bytes.
///
/// Uses /dev/urandom as the entropy source.
/// Replaces util_getrandom.
pub fn getrandom(buf: &mut [u8]) -> Result<(), std::io::Error> {
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(buf)
}

// =============================================================================
// String utilities
// =============================================================================

/// Replace every occurrence of any character in delimiters with
/// replacement in the given string.
///
/// Replaces util_strdelimit.
pub fn strdelimit(string: &str, delimiters: &str, replacement: char) -> String {
    string.chars().map(|c| if delimiters.contains(c) { replacement } else { c }).collect()
}

/// Check whether string ends with suffix.
///
/// Replaces util_strsuffix.
pub fn strsuffix(string: &str, suffix: &str) -> bool {
    string.ends_with(suffix)
}

/// Strip leading and trailing ASCII whitespace from a string.
///
/// Replaces util_strstrip.
pub fn strstrip(string: &str) -> &str {
    string.trim()
}

/// Count the number of UTF-8 characters whose start byte falls within
/// the first max_bytes bytes of string.
///
/// This counts UTF-8 start bytes (non-continuation bytes), which corresponds
/// to the number of complete or partial Unicode code points beginning within
/// the byte range. Replaces util_strnlenutf8.
pub fn strnlen_utf8(string: &str, max_bytes: usize) -> usize {
    let bytes = string.as_bytes();
    let limit = max_bytes.min(bytes.len());
    let mut count = 0usize;

    for byte in &bytes[..limit] {
        if (byte & 0xC0) != 0x80 {
            count += 1;
        }
    }

    count
}

/// Check whether a byte slice is valid UTF-8.
///
/// Replaces util_strisutf8.
pub fn stris_utf8(string: &[u8]) -> bool {
    std::str::from_utf8(string).is_ok()
}

/// Convert a byte slice to a UTF-8 String, replacing invalid sequences
/// with the Unicode replacement character (U+FFFD).
///
/// Replaces util_strtoutf8.
pub fn str_to_utf8(string: &[u8]) -> String {
    String::from_utf8_lossy(string).into_owned()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_le16_roundtrip() {
        let val: u16 = 0x1234;
        assert_eq!(le16_to_cpu(cpu_to_le16(val)), val);
    }

    #[test]
    fn test_be16_roundtrip() {
        let val: u16 = 0x1234;
        assert_eq!(be16_to_cpu(cpu_to_be16(val)), val);
    }

    #[test]
    fn test_le32_roundtrip() {
        let val: u32 = 0x1234_5678;
        assert_eq!(le32_to_cpu(cpu_to_le32(val)), val);
    }

    #[test]
    fn test_be32_roundtrip() {
        let val: u32 = 0x1234_5678;
        assert_eq!(be32_to_cpu(cpu_to_be32(val)), val);
    }

    #[test]
    fn test_le64_roundtrip() {
        let val: u64 = 0x0123_4567_89AB_CDEF;
        assert_eq!(le64_to_cpu(cpu_to_le64(val)), val);
    }

    #[test]
    fn test_be64_roundtrip() {
        let val: u64 = 0x0123_4567_89AB_CDEF;
        assert_eq!(be64_to_cpu(cpu_to_be64(val)), val);
    }

    #[test]
    fn test_get_le16() {
        assert_eq!(get_le16(&[0x01, 0x02]), 0x0201);
    }

    #[test]
    fn test_get_be16() {
        assert_eq!(get_be16(&[0x01, 0x02]), 0x0102);
    }

    #[test]
    fn test_put_le32_bytes() {
        let mut buf = [0u8; 4];
        put_le32(0x0102_0304, &mut buf);
        assert_eq!(buf, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_put_be32_bytes() {
        let mut buf = [0u8; 4];
        put_be32(0x0102_0304, &mut buf);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_get_le24() {
        assert_eq!(get_le24(&[0x56, 0x34, 0x12]), 0x0012_3456);
    }

    #[test]
    fn test_get_be24() {
        assert_eq!(get_be24(&[0x12, 0x34, 0x56]), 0x0012_3456);
    }

    #[test]
    fn test_put_le24() {
        let mut buf = [0u8; 3];
        put_le24(0x0012_3456, &mut buf);
        assert_eq!(buf, [0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_put_be24() {
        let mut buf = [0u8; 3];
        put_be24(0x0012_3456, &mut buf);
        assert_eq!(buf, [0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_get_s8() {
        assert_eq!(get_s8(&[0xFF]), -1i8);
        assert_eq!(get_s8(&[0x7F]), 127i8);
    }

    #[test]
    fn test_get_put_u8() {
        let mut buf = [0u8; 1];
        put_u8(0xAB, &mut buf);
        assert_eq!(get_u8(&buf), 0xAB);
    }

    #[test]
    fn test_get_put_le64() {
        let val: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut buf = [0u8; 8];
        put_le64(val, &mut buf);
        assert_eq!(get_le64(&buf), val);
    }

    #[test]
    fn test_get_put_be64() {
        let val: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut buf = [0u8; 8];
        put_be64(val, &mut buf);
        assert_eq!(get_be64(&buf), val);
    }

    #[test]
    fn test_iobuf_push_pull_le16() {
        let mut buf = IoBuf::new();
        buf.push_le16(0x1234);
        assert_eq!(buf.len(), 2);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_le16(), Some(0x1234));
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn test_iobuf_push_pull_be32() {
        let mut buf = IoBuf::new();
        buf.push_be32(0xDEAD_BEEF);
        assert_eq!(buf.len(), 4);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_be32(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn test_iobuf_pull_insufficient_data() {
        let mut buf = IoBuf::from_bytes(&[0x01]);
        assert_eq!(buf.pull_le16(), None);
        assert_eq!(buf.pull_le32(), None);
        assert_eq!(buf.pull_le64(), None);
        assert_eq!(buf.pull_be16(), None);
        assert_eq!(buf.pull_be32(), None);
        assert_eq!(buf.pull_be64(), None);
        assert_eq!(buf.pull_u8(), Some(0x01));
        assert_eq!(buf.pull_u8(), None);
    }

    #[test]
    fn test_iobuf_pull_le_bool() {
        let mut buf = IoBuf::from_bytes(&[0x00, 0x01, 0xFF]);
        assert_eq!(buf.pull_le_bool(), Some(false));
        assert_eq!(buf.pull_le_bool(), Some(true));
        assert_eq!(buf.pull_le_bool(), Some(true));
        assert_eq!(buf.pull_le_bool(), None);
    }

    #[test]
    fn test_iobuf_pull_skip() {
        let mut buf = IoBuf::from_bytes(&[0x01, 0x02, 0x03, 0x04]);
        assert!(buf.pull(2));
        assert_eq!(buf.remaining(), 2);
        assert_eq!(buf.pull_u8(), Some(0x03));
        assert!(!buf.pull(5));
    }

    #[test]
    fn test_iobuf_push_24bit() {
        let mut buf = IoBuf::new();
        buf.push_le24(0x0012_3456);
        buf.push_be24(0x0078_9ABC);
        assert_eq!(buf.len(), 6);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_le24(), Some(0x0012_3456));
        assert_eq!(reader.pull_be24(), Some(0x0078_9ABC));
    }

    #[test]
    fn test_iobuf_append_alias() {
        let mut buf = IoBuf::new();
        buf.append(&[1, 2, 3]);
        assert_eq!(buf.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_iobuf_memcpy_from() {
        let mut buf = IoBuf::from_bytes(&[0xFF; 10]);
        buf.memcpy_from(&[0x01, 0x02, 0x03], 3);
        assert_eq!(buf.as_bytes(), &[0x01, 0x02, 0x03]);
        assert_eq!(buf.remaining(), 3);
    }

    #[test]
    fn test_iobuf_remaining_bytes() {
        let mut buf = IoBuf::from_bytes(&[0x01, 0x02, 0x03, 0x04]);
        let _ = buf.pull(2);
        assert_eq!(buf.remaining_bytes(), &[0x03, 0x04]);
    }

    #[test]
    fn test_iobuf_with_capacity() {
        let buf = IoBuf::with_capacity(1024);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_iobuf_default() {
        let buf: IoBuf = Default::default();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_iobuf_from_vec() {
        let data = vec![0x0A, 0x0B, 0x0C];
        let buf = IoBuf::from(data);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_bytes(), &[0x0A, 0x0B, 0x0C]);
    }

    #[test]
    fn test_iobuf_from_slice() {
        let data: &[u8] = &[0x0D, 0x0E, 0x0F];
        let buf = IoBuf::from(data);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_bytes(), &[0x0D, 0x0E, 0x0F]);
    }

    #[test]
    fn test_iobuf_debug() {
        let buf = IoBuf::from_bytes(&[1, 2, 3]);
        let debug_str = format!("{buf:?}");
        assert!(debug_str.contains("IoBuf"));
        assert!(debug_str.contains("len"));
    }

    #[test]
    fn test_iobuf_push_pull_le64() {
        let mut buf = IoBuf::new();
        buf.push_le64(0xDEAD_BEEF_CAFE_BABE);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_le64(), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn test_iobuf_push_pull_be64() {
        let mut buf = IoBuf::new();
        buf.push_be64(0xDEAD_BEEF_CAFE_BABE);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_be64(), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn test_iobuf_push_pull_be16() {
        let mut buf = IoBuf::new();
        buf.push_be16(0xABCD);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_be16(), Some(0xABCD));
    }

    #[test]
    fn test_iobuf_push_pull_le32() {
        let mut buf = IoBuf::new();
        buf.push_le32(0x1234_5678);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_le32(), Some(0x1234_5678));
    }

    #[test]
    fn test_iobuf_push_pull_u8() {
        let mut buf = IoBuf::new();
        buf.push_u8(0xAB);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        assert_eq!(reader.pull_u8(), Some(0xAB));
    }

    #[test]
    fn test_iobuf_push_mem_pull_mem() {
        let mut buf = IoBuf::new();
        buf.push_mem(&[1, 2, 3, 4]);
        assert_eq!(buf.len(), 4);
        let mut reader = IoBuf::from_bytes(buf.as_bytes());
        let first_two = reader.pull_mem(2).unwrap().to_vec();
        assert_eq!(first_two, vec![1, 2]);
        let next_two = reader.pull_mem(2).unwrap().to_vec();
        assert_eq!(next_two, vec![3, 4]);
        assert_eq!(reader.pull_mem(1), None);
    }

    #[test]
    fn test_iobuf_is_empty() {
        let buf = IoBuf::new();
        assert!(buf.is_empty());
        let buf2 = IoBuf::from_bytes(&[1]);
        assert!(!buf2.is_empty());
    }

    #[test]
    fn test_iobuf_memcpy_from_truncated() {
        let mut buf = IoBuf::new();
        buf.memcpy_from(&[1, 2], 10);
        assert_eq!(buf.as_bytes(), &[1, 2]);
    }

    #[test]
    fn test_ltv_roundtrip() {
        let mut output = IoBuf::new();
        ltv_push(&mut output, 0x01, &[0xAA, 0xBB]);
        ltv_push(&mut output, 0x02, &[0xCC]);
        let mut records = Vec::new();
        let result = ltv_foreach(output.as_bytes(), |t, d| {
            records.push((t, d.to_vec()));
            true
        });
        assert!(result);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], (0x01, vec![0xAA, 0xBB]));
        assert_eq!(records[1], (0x02, vec![0xCC]));
    }

    #[test]
    fn test_ltv_foreach_early_stop() {
        let mut output = IoBuf::new();
        ltv_push(&mut output, 0x01, &[0xAA]);
        ltv_push(&mut output, 0x02, &[0xBB]);
        let mut count = 0;
        let result = ltv_foreach(output.as_bytes(), |_t, _d| {
            count += 1;
            false
        });
        assert!(!result);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_ltv_foreach_empty() {
        let result = ltv_foreach(&[], |_t, _d| true);
        assert!(result);
    }

    #[test]
    fn test_ltv_foreach_zero_length_skip() {
        let data = [0x00, 0x02, 0x01, 0xAA];
        let mut records = Vec::new();
        ltv_foreach(&data, |t, d| {
            records.push((t, d.to_vec()));
            true
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], (0x01, vec![0xAA]));
    }

    #[test]
    fn test_ltv_foreach_truncated() {
        let data = [0x05, 0x01, 0xAA];
        let mut records = Vec::new();
        ltv_foreach(&data, |t, d| {
            records.push((t, d.to_vec()));
            true
        });
        assert!(records.is_empty());
    }

    #[test]
    fn test_hexdump_basic() {
        let data = [0x41u8, 0x42, 0x43];
        let mut lines = Vec::new();
        hexdump(">", &data, |line| lines.push(line.to_owned()));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("> "));
        assert!(lines[0].contains("41 42 43"));
        assert!(lines[0].contains("ABC"));
    }

    #[test]
    fn test_hexdump_empty() {
        let mut lines = Vec::new();
        hexdump(">", &[], |line| lines.push(line.to_owned()));
        assert!(lines.is_empty());
    }

    #[test]
    fn test_hexdump_multiline() {
        let data: Vec<u8> = (0..32).collect();
        let mut lines = Vec::new();
        hexdump(">", &data, |line| lines.push(line.to_owned()));
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("> "));
        assert!(lines[1].starts_with("  "));
    }

    #[test]
    fn test_hexdump_non_printable() {
        let data = [0x00u8, 0x1F, 0x7F, 0xFF];
        let mut lines = Vec::new();
        hexdump(">", &data, |line| lines.push(line.to_owned()));
        assert!(lines[0].contains("...."));
    }

    #[test]
    fn test_bitfield_parity() {
        assert!(bitfield_has_parity(0));
        assert!(!bitfield_has_parity(1));
        assert!(bitfield_has_parity(3));
        assert!(!bitfield_has_parity(7));
        assert!(bitfield_has_parity(0xFF));
    }

    #[test]
    fn test_getrandom() {
        let mut buf = [0u8; 32];
        let result = getrandom(&mut buf);
        assert!(result.is_ok());
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_strdelimit() {
        assert_eq!(strdelimit("a.b-c", ".-", '_'), "a_b_c");
        assert_eq!(strdelimit("hello", "xyz", '_'), "hello");
        assert_eq!(strdelimit("", ".", '_'), "");
    }

    #[test]
    fn test_strsuffix() {
        assert!(strsuffix("hello.txt", ".txt"));
        assert!(!strsuffix("hello.txt", ".csv"));
        assert!(strsuffix("hello", ""));
        assert!(!strsuffix("", "x"));
    }

    #[test]
    fn test_strstrip() {
        assert_eq!(strstrip("  hello  "), "hello");
        assert_eq!(strstrip("hello"), "hello");
        assert_eq!(strstrip("  "), "");
        assert_eq!(strstrip("\t\nhello\n\t"), "hello");
    }

    #[test]
    fn test_strnlen_utf8() {
        assert_eq!(strnlen_utf8("hello", 5), 5);
        assert_eq!(strnlen_utf8("hello", 3), 3);
        assert_eq!(strnlen_utf8("\u{00e9}", 2), 1);
        assert_eq!(strnlen_utf8("\u{00e9}", 1), 1);
        assert_eq!(strnlen_utf8("\u{20ac}", 3), 1);
        assert_eq!(strnlen_utf8("\u{20ac}", 1), 1);
    }

    #[test]
    fn test_stris_utf8() {
        assert!(stris_utf8(b"hello"));
        assert!(stris_utf8("caf\u{00e9}".as_bytes()));
        assert!(!stris_utf8(&[0xFF, 0xFE]));
        assert!(stris_utf8(&[]));
    }

    #[test]
    fn test_str_to_utf8() {
        assert_eq!(str_to_utf8(b"hello"), "hello");
        assert_eq!(str_to_utf8("caf\u{00e9}".as_bytes()), "caf\u{00e9}");
        let result = str_to_utf8(&[0xFF, 0xFE]);
        assert!(result.contains('\u{FFFD}'));
    }

    #[test]
    fn test_util_debug() {
        let mut called = false;
        let mut cb = |msg: &str| {
            assert_eq!(msg, "test message");
            called = true;
        };
        util_debug(&mut cb, "test message");
        assert!(called);
    }

    #[test]
    fn test_util_debug_empty() {
        let mut cb = |_msg: &str| {
            panic!("should not be called for empty message");
        };
        util_debug(&mut cb, "");
    }
}
