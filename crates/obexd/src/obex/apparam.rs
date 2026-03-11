// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX Application Parameters — TLV-encoded parameter container.
//
// Rust rewrite of gobex/gobex-apparam.c (355 lines) and gobex/gobex-apparam.h
// (47 lines) from BlueZ v5.86.
//
// This module implements the OBEX Application Parameters TLV format used in
// OBEX headers such as AUTHCHAL, AUTHRESP, and profile-specific application
// parameters (PBAP, MAP, etc.).
//
// Wire format per tag: [u8 tag_id] [u8 value_length] [value_bytes...]
// - Tag IDs are 1 byte (0–255)
// - Value length is 1 byte (0–255), so the maximum value payload is 255 bytes
// - Integer values are stored in network byte order (big-endian)

use std::collections::HashMap;
use std::fmt;

/// Maximum value length for a single TLV tag (limited by the 1-byte length field).
const MAX_TAG_VALUE_LEN: usize = u8::MAX as usize;

/// Minimum size of a single TLV entry on the wire (1-byte tag + 1-byte length).
const TLV_HEADER_LEN: usize = 2;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by OBEX application parameter encoding/decoding operations.
///
/// This is a self-contained error type for the `apparam` module. Other OBEX
/// subsystem modules may wrap or convert this into their own error enums
/// (e.g. `ObexError::ParseError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApparamError {
    /// The supplied TLV data is truncated or otherwise malformed.
    ParseError(String),
    /// An encoding operation received invalid arguments (e.g. empty container,
    /// buffer too small).
    InvalidArgs(String),
}

impl fmt::Display for ApparamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApparamError::ParseError(msg) => write!(f, "apparam parse error: {msg}"),
            ApparamError::InvalidArgs(msg) => write!(f, "apparam invalid args: {msg}"),
        }
    }
}

impl std::error::Error for ApparamError {}

// ---------------------------------------------------------------------------
// ObexApparam
// ---------------------------------------------------------------------------

/// OBEX Application Parameters — TLV-encoded parameter container.
///
/// Used in OBEX headers (`AUTHCHAL`, `AUTHRESP`, `APPARAM`) for carrying
/// profile-specific data.  Internally stores tags in a [`HashMap`] mapping
/// tag IDs (`u8`) to raw value bytes.  Integer values are kept in network
/// byte order (big-endian) in storage, matching the C implementation exactly.
///
/// # Wire Format
///
/// Each tag is encoded as:
///
/// ```text
/// [u8 tag_id] [u8 value_length] [value_bytes ...]
/// ```
///
/// The container is simply a concatenation of zero or more such tags.
///
/// # Example
///
/// ```ignore
/// let mut ap = ObexApparam::new();
/// ap.set_u16(0x01, 1024);
/// ap.set_string(0x02, "hello");
/// let encoded = ap.encode_to_vec().unwrap();
/// let decoded = ObexApparam::decode(&encoded).unwrap();
/// assert_eq!(decoded.get_u16(0x01), Some(1024));
/// assert_eq!(decoded.get_string(0x02), Some("hello".to_owned()));
/// ```
#[derive(Debug, Clone, Default)]
pub struct ObexApparam {
    /// Tag ID → raw value bytes (integers stored in network byte order).
    params: HashMap<u8, Vec<u8>>,
}

impl ObexApparam {
    // -------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------

    /// Creates a new, empty application parameter container.
    ///
    /// Equivalent to the C `g_obex_apparam_new()`.
    #[must_use]
    pub fn new() -> Self {
        Self { params: HashMap::new() }
    }

    // -------------------------------------------------------------------
    // Typed setters
    // -------------------------------------------------------------------

    /// Stores a `u8` value for the given tag ID.
    ///
    /// Equivalent to C `g_obex_apparam_set_uint8`.
    pub fn set_u8(&mut self, id: u8, val: u8) -> &mut Self {
        self.params.insert(id, vec![val]);
        self
    }

    /// Stores a `u16` value in network byte order for the given tag ID.
    ///
    /// Equivalent to C `g_obex_apparam_set_uint16` (uses `g_htons`).
    pub fn set_u16(&mut self, id: u8, val: u16) -> &mut Self {
        self.params.insert(id, val.to_be_bytes().to_vec());
        self
    }

    /// Stores a `u32` value in network byte order for the given tag ID.
    ///
    /// Equivalent to C `g_obex_apparam_set_uint32` (uses `g_htonl`).
    pub fn set_u32(&mut self, id: u8, val: u32) -> &mut Self {
        self.params.insert(id, val.to_be_bytes().to_vec());
        self
    }

    /// Stores a `u64` value in network byte order for the given tag ID.
    ///
    /// Equivalent to C `g_obex_apparam_set_uint64` (uses `GUINT64_TO_BE`).
    pub fn set_u64(&mut self, id: u8, val: u64) -> &mut Self {
        self.params.insert(id, val.to_be_bytes().to_vec());
        self
    }

    /// Stores a string value for the given tag ID.
    ///
    /// The string is stored **including a NUL terminator**, matching the C
    /// `g_obex_apparam_set_string` behaviour.  If the string (plus NUL)
    /// exceeds 255 bytes it is silently truncated to 254 bytes of content
    /// plus a NUL, matching `MIN(strlen(val) + 1, G_MAXUINT8)`.
    pub fn set_string(&mut self, id: u8, val: &str) -> &mut Self {
        let raw = val.as_bytes();
        // Total length including NUL terminator, capped at MAX_TAG_VALUE_LEN.
        let total_len = (raw.len() + 1).min(MAX_TAG_VALUE_LEN);
        let content_len = total_len - 1; // bytes of string content before NUL

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&raw[..content_len]);
        buf.push(0); // NUL terminator
        self.params.insert(id, buf);
        self
    }

    /// Stores raw bytes for the given tag ID.
    ///
    /// If `val` exceeds 255 bytes it is silently truncated, matching the C
    /// behaviour that caps at `G_MAXUINT8`.
    pub fn set_bytes(&mut self, id: u8, val: &[u8]) -> &mut Self {
        let len = val.len().min(MAX_TAG_VALUE_LEN);
        self.params.insert(id, val[..len].to_vec());
        self
    }

    // -------------------------------------------------------------------
    // Typed getters
    // -------------------------------------------------------------------

    /// Retrieves a `u8` value for the given tag ID.
    ///
    /// Returns `None` if the tag is absent or if the stored length is not
    /// exactly 1 byte.  Equivalent to C `g_obex_apparam_get_uint8`.
    #[must_use]
    pub fn get_u8(&self, id: u8) -> Option<u8> {
        let data = self.params.get(&id)?;
        if data.len() != 1 {
            return None;
        }
        Some(data[0])
    }

    /// Retrieves a `u16` value (converted from network byte order) for the
    /// given tag ID.
    ///
    /// Returns `None` if the tag is absent or if the stored length is not
    /// exactly 2 bytes.  Equivalent to C `g_obex_apparam_get_uint16`
    /// (uses `g_ntohs`).
    #[must_use]
    pub fn get_u16(&self, id: u8) -> Option<u16> {
        let data = self.params.get(&id)?;
        if data.len() < 2 {
            return None;
        }
        let bytes: [u8; 2] = [data[0], data[1]];
        Some(u16::from_be_bytes(bytes))
    }

    /// Retrieves a `u32` value (converted from network byte order) for the
    /// given tag ID.
    ///
    /// Returns `None` if the tag is absent or if the stored length is less
    /// than 4 bytes.  Equivalent to C `g_obex_apparam_get_uint32`
    /// (uses `g_ntohl`).
    #[must_use]
    pub fn get_u32(&self, id: u8) -> Option<u32> {
        let data = self.params.get(&id)?;
        if data.len() < 4 {
            return None;
        }
        let bytes: [u8; 4] = data[..4].try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    /// Retrieves a `u64` value (converted from network byte order) for the
    /// given tag ID.
    ///
    /// Returns `None` if the tag is absent or if the stored length is less
    /// than 8 bytes.  Equivalent to C `g_obex_apparam_get_uint64`
    /// (uses `GUINT64_FROM_BE`).
    #[must_use]
    pub fn get_u64(&self, id: u8) -> Option<u64> {
        let data = self.params.get(&id)?;
        if data.len() < 8 {
            return None;
        }
        let bytes: [u8; 8] = data[..8].try_into().ok()?;
        Some(u64::from_be_bytes(bytes))
    }

    /// Retrieves a string value for the given tag ID.
    ///
    /// The stored data is expected to include a NUL terminator (as written
    /// by [`set_string`](Self::set_string)).  The returned [`String`]
    /// strips any trailing NUL bytes, matching the C `g_strndup` behaviour
    /// in `g_obex_apparam_get_string`.
    ///
    /// Returns `None` if the tag is absent or if the bytes are not valid
    /// UTF-8.
    #[must_use]
    pub fn get_string(&self, id: u8) -> Option<String> {
        let data = self.params.get(&id)?;
        // Strip trailing NUL bytes (there should be exactly one, but be robust).
        let trimmed = match data.iter().position(|&b| b == 0) {
            Some(pos) => &data[..pos],
            None => data.as_slice(),
        };
        std::str::from_utf8(trimmed).ok().map(String::from)
    }

    /// Retrieves raw bytes for the given tag ID.
    ///
    /// Returns `None` if the tag is absent.  Equivalent to C
    /// `g_obex_apparam_get_bytes`.
    #[must_use]
    pub fn get_bytes(&self, id: u8) -> Option<&[u8]> {
        self.params.get(&id).map(Vec::as_slice)
    }

    // -------------------------------------------------------------------
    // Decode / Encode
    // -------------------------------------------------------------------

    /// Decodes an application parameter container from a TLV byte stream.
    ///
    /// The byte stream must be a well-formed sequence of `[tag_id, length,
    /// value…]` triplets.  **All** input bytes must be consumed exactly;
    /// leftover bytes at the end are treated as an error (matching the C
    /// `g_obex_apparam_decode` behaviour where `count != size → NULL`).
    ///
    /// # Errors
    ///
    /// Returns [`ApparamError::ParseError`] if the data is truncated or
    /// contains trailing garbage.
    pub fn decode(data: &[u8]) -> Result<Self, ApparamError> {
        // C requires size >= 2 for the first tag, but an empty slice is
        // technically a valid zero-tag container (the C check is for the
        // first tag inside the loop).  We mirror the C behaviour: if
        // `data.len() < 2` and data is not empty, it's an error.
        if data.is_empty() {
            return Ok(Self::new());
        }

        if data.len() < TLV_HEADER_LEN {
            return Err(ApparamError::ParseError(
                "truncated TLV header: data shorter than 2 bytes".into(),
            ));
        }

        let mut apparam = Self::new();
        let mut offset: usize = 0;

        while offset < data.len() {
            // Need at least 2 bytes for the tag header.
            let remaining = data.len() - offset;
            if remaining < TLV_HEADER_LEN {
                return Err(ApparamError::ParseError(format!(
                    "truncated TLV header at offset {offset}: {remaining} byte(s) remaining"
                )));
            }

            let tag_id = data[offset];
            let tag_len = data[offset + 1] as usize;
            offset += TLV_HEADER_LEN;

            // Validate that the full value fits in the remaining data.
            let value_remaining = data.len() - offset;
            if value_remaining < tag_len {
                return Err(ApparamError::ParseError(format!(
                    "truncated TLV value for tag 0x{tag_id:02x} at offset {}: \
                     expected {tag_len} bytes, only {value_remaining} available",
                    offset - TLV_HEADER_LEN,
                )));
            }

            let value = data[offset..offset + tag_len].to_vec();
            apparam.params.insert(tag_id, value);
            offset += tag_len;
        }

        // The C implementation requires exact consumption:
        //   if (count != size) { g_obex_apparam_free(apparam); return NULL; }
        // Our loop exits only when `offset == data.len()`, so if we reached
        // this point without error the data has been fully consumed.
        debug_assert_eq!(offset, data.len());

        Ok(apparam)
    }

    /// Encodes the application parameters into a caller-supplied buffer.
    ///
    /// Returns the total number of bytes written on success.
    ///
    /// # Errors
    ///
    /// * [`ApparamError::InvalidArgs`] with `"empty apparam"` if the
    ///   container has no tags (mirrors the C `-ENOATTR` return).
    /// * [`ApparamError::InvalidArgs`] with `"buffer too small"` if `buf`
    ///   cannot hold the entire encoded representation.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ApparamError> {
        if self.params.is_empty() {
            return Err(ApparamError::InvalidArgs("empty apparam".into()));
        }

        let needed = self.encoded_len();
        if buf.len() < needed {
            return Err(ApparamError::InvalidArgs(format!(
                "buffer too small: need {needed} bytes, got {}",
                buf.len()
            )));
        }

        let mut offset: usize = 0;
        for (&id, value) in &self.params {
            buf[offset] = id;
            // The value length always fits in a u8 because set_* methods cap
            // at MAX_TAG_VALUE_LEN (255).
            buf[offset + 1] = value.len() as u8;
            buf[offset + TLV_HEADER_LEN..offset + TLV_HEADER_LEN + value.len()]
                .copy_from_slice(value);
            offset += TLV_HEADER_LEN + value.len();
        }

        Ok(offset)
    }

    /// Returns the total number of bytes needed to encode all tags without
    /// actually performing the encoding.
    ///
    /// Useful for pre-allocating an encode buffer.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.params.values().map(|v| TLV_HEADER_LEN + v.len()).sum()
    }

    /// Convenience method: encodes the container into a newly allocated
    /// [`Vec<u8>`].
    ///
    /// # Errors
    ///
    /// Returns [`ApparamError::InvalidArgs`] if the container is empty.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, ApparamError> {
        if self.params.is_empty() {
            return Err(ApparamError::InvalidArgs("empty apparam".into()));
        }

        let len = self.encoded_len();
        let mut buf = vec![0u8; len];
        let written = self.encode(&mut buf)?;
        debug_assert_eq!(written, len);
        Ok(buf)
    }

    // -------------------------------------------------------------------
    // Utility methods
    // -------------------------------------------------------------------

    /// Returns `true` if the container has no tags.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Returns the number of tags stored in the container.
    #[must_use]
    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// Returns `true` if a tag with the given ID is present.
    #[must_use]
    pub fn contains(&self, id: u8) -> bool {
        self.params.contains_key(&id)
    }

    /// Removes the tag with the given ID, returning its raw value bytes if
    /// it was present.
    pub fn remove(&mut self, id: u8) -> Option<Vec<u8>> {
        self.params.remove(&id)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- new / is_empty / len ------------------------------------------

    #[test]
    fn test_new_is_empty() {
        let ap = ObexApparam::new();
        assert!(ap.is_empty());
        assert_eq!(ap.len(), 0);
        assert_eq!(ap.encoded_len(), 0);
    }

    // -- set / get u8 ---------------------------------------------------

    #[test]
    fn test_set_get_u8() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 42);
        assert!(!ap.is_empty());
        assert_eq!(ap.len(), 1);
        assert_eq!(ap.get_u8(0x01), Some(42));
        // Missing tag returns None.
        assert_eq!(ap.get_u8(0x02), None);
    }

    // -- set / get u16 --------------------------------------------------

    #[test]
    fn test_set_get_u16() {
        let mut ap = ObexApparam::new();
        ap.set_u16(0x10, 0x1234);
        assert_eq!(ap.get_u16(0x10), Some(0x1234));
        // Verify network byte order in raw storage.
        let raw = ap.get_bytes(0x10).unwrap();
        assert_eq!(raw, &[0x12, 0x34]);
    }

    // -- set / get u32 --------------------------------------------------

    #[test]
    fn test_set_get_u32() {
        let mut ap = ObexApparam::new();
        ap.set_u32(0x20, 0xDEAD_BEEF);
        assert_eq!(ap.get_u32(0x20), Some(0xDEAD_BEEF));
        let raw = ap.get_bytes(0x20).unwrap();
        assert_eq!(raw, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // -- set / get u64 --------------------------------------------------

    #[test]
    fn test_set_get_u64() {
        let mut ap = ObexApparam::new();
        ap.set_u64(0x30, 0x0102_0304_0506_0708);
        assert_eq!(ap.get_u64(0x30), Some(0x0102_0304_0506_0708));
        let raw = ap.get_bytes(0x30).unwrap();
        assert_eq!(raw, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    // -- set / get string -----------------------------------------------

    #[test]
    fn test_set_get_string_basic() {
        let mut ap = ObexApparam::new();
        ap.set_string(0x40, "hello");
        assert_eq!(ap.get_string(0x40), Some("hello".to_owned()));
        // Raw storage includes NUL terminator.
        let raw = ap.get_bytes(0x40).unwrap();
        assert_eq!(raw, b"hello\0");
    }

    #[test]
    fn test_set_get_string_empty() {
        let mut ap = ObexApparam::new();
        ap.set_string(0x41, "");
        assert_eq!(ap.get_string(0x41), Some(String::new()));
        let raw = ap.get_bytes(0x41).unwrap();
        assert_eq!(raw, b"\0");
    }

    #[test]
    fn test_set_string_truncation() {
        // A string whose bytes + NUL exceed 255 should be truncated.
        let long = "A".repeat(300);
        let mut ap = ObexApparam::new();
        ap.set_string(0x42, &long);
        let raw = ap.get_bytes(0x42).unwrap();
        // Total stored length must not exceed MAX_TAG_VALUE_LEN (255).
        assert_eq!(raw.len(), 255);
        // Last byte must be NUL.
        assert_eq!(*raw.last().unwrap(), 0);
        // Content is 254 'A's + NUL.
        assert!(raw[..254].iter().all(|&b| b == b'A'));
    }

    // -- set / get bytes ------------------------------------------------

    #[test]
    fn test_set_get_bytes() {
        let mut ap = ObexApparam::new();
        let data = [0xCA, 0xFE, 0xBA, 0xBE];
        ap.set_bytes(0x50, &data);
        assert_eq!(ap.get_bytes(0x50), Some(data.as_slice()));
    }

    #[test]
    fn test_set_bytes_truncation() {
        let long = vec![0xAB; 300];
        let mut ap = ObexApparam::new();
        ap.set_bytes(0x51, &long);
        assert_eq!(ap.get_bytes(0x51).unwrap().len(), 255);
    }

    // -- contains / remove ----------------------------------------------

    #[test]
    fn test_contains_and_remove() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 1);
        assert!(ap.contains(0x01));
        assert!(!ap.contains(0x02));

        let removed = ap.remove(0x01);
        assert_eq!(removed, Some(vec![1]));
        assert!(!ap.contains(0x01));
        assert!(ap.is_empty());

        // Removing non-existent tag returns None.
        assert_eq!(ap.remove(0xFF), None);
    }

    // -- encode / decode round-trip -------------------------------------

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 0x42);
        ap.set_u16(0x02, 1024);
        ap.set_u32(0x03, 0xAABB_CCDD);
        ap.set_u64(0x04, 0x1122_3344_5566_7788);
        ap.set_string(0x05, "test");
        ap.set_bytes(0x06, &[1, 2, 3]);

        let encoded = ap.encode_to_vec().unwrap();
        let decoded = ObexApparam::decode(&encoded).unwrap();

        assert_eq!(decoded.get_u8(0x01), Some(0x42));
        assert_eq!(decoded.get_u16(0x02), Some(1024));
        assert_eq!(decoded.get_u32(0x03), Some(0xAABB_CCDD));
        assert_eq!(decoded.get_u64(0x04), Some(0x1122_3344_5566_7788));
        assert_eq!(decoded.get_string(0x05), Some("test".to_owned()));
        assert_eq!(decoded.get_bytes(0x06), Some([1u8, 2, 3].as_slice()));
    }

    #[test]
    fn test_encode_to_buf() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0xAA, 0xFF);

        // Encoded: [0xAA, 0x01, 0xFF] = 3 bytes.
        assert_eq!(ap.encoded_len(), 3);

        let mut buf = [0u8; 16];
        let written = ap.encode(&mut buf).unwrap();
        assert_eq!(written, 3);
        // The encoded bytes contain: tag=0xAA, len=1, val=0xFF.
        // Since there's only one tag we can check directly.
        assert_eq!(buf[..3], [0xAA, 0x01, 0xFF]);
    }

    #[test]
    fn test_encode_empty_error() {
        let ap = ObexApparam::new();
        let result = ap.encode_to_vec();
        assert!(result.is_err());
        match result.unwrap_err() {
            ApparamError::InvalidArgs(msg) => assert!(msg.contains("empty")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_encode_buffer_too_small() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 42);
        let mut tiny = [0u8; 1]; // needs 3
        let result = ap.encode(&mut tiny);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApparamError::InvalidArgs(msg) => assert!(msg.contains("buffer too small")),
            other => panic!("unexpected error: {other}"),
        }
    }

    // -- decode edge cases ----------------------------------------------

    #[test]
    fn test_decode_empty_data() {
        let ap = ObexApparam::decode(&[]).unwrap();
        assert!(ap.is_empty());
    }

    #[test]
    fn test_decode_truncated_header() {
        // Only 1 byte — not enough for a TLV header.
        let result = ObexApparam::decode(&[0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_truncated_value() {
        // Header says 4 bytes of value, but only 2 are present.
        let result = ObexApparam::decode(&[0x01, 0x04, 0xAA, 0xBB]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_trailing_garbage() {
        // Valid tag (id=0x01, len=1, val=0x42) followed by a single stray byte.
        let result = ObexApparam::decode(&[0x01, 0x01, 0x42, 0xFF]);
        // The stray byte (0xFF) can't form a valid TLV header alone, so the
        // next iteration will see remaining=1 < 2 and error.
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_zero_length_tag() {
        // A tag with length 0 is valid.
        let ap = ObexApparam::decode(&[0x99, 0x00]).unwrap();
        assert!(ap.contains(0x99));
        assert_eq!(ap.get_bytes(0x99), Some([].as_slice()));
    }

    #[test]
    fn test_decode_multiple_tags() {
        // Two tags back-to-back:
        //   tag 0x0A, len 2, val 0x00 0x0A  (u16 = 10)
        //   tag 0x0B, len 1, val 0x05        (u8 = 5)
        let data = [0x0A, 0x02, 0x00, 0x0A, 0x0B, 0x01, 0x05];
        let ap = ObexApparam::decode(&data).unwrap();
        assert_eq!(ap.len(), 2);
        assert_eq!(ap.get_u16(0x0A), Some(10));
        assert_eq!(ap.get_u8(0x0B), Some(5));
    }

    // -- Wire-compatibility with C implementation ----------------------

    #[test]
    fn test_wire_compat_u16_network_order() {
        // C stores u16 0x0400 (1024) as [0x04, 0x00] via g_htons.
        let mut ap = ObexApparam::new();
        ap.set_u16(0x01, 1024);
        let encoded = ap.encode_to_vec().unwrap();
        // Expected: [tag=0x01, len=0x02, 0x04, 0x00].
        assert_eq!(encoded, [0x01, 0x02, 0x04, 0x00]);
    }

    #[test]
    fn test_wire_compat_u32_network_order() {
        // C stores u32 1 as [0x00, 0x00, 0x00, 0x01] via g_htonl.
        let mut ap = ObexApparam::new();
        ap.set_u32(0x02, 1);
        let encoded = ap.encode_to_vec().unwrap();
        assert_eq!(encoded, [0x02, 0x04, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_wire_compat_u64_network_order() {
        let mut ap = ObexApparam::new();
        ap.set_u64(0x03, 1);
        let encoded = ap.encode_to_vec().unwrap();
        assert_eq!(encoded, [0x03, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_wire_compat_string_with_nul() {
        // C stores "hi" as [b'h', b'i', 0x00] — 3 bytes.
        let mut ap = ObexApparam::new();
        ap.set_string(0x04, "hi");
        let encoded = ap.encode_to_vec().unwrap();
        assert_eq!(encoded, [0x04, 0x03, b'h', b'i', 0x00]);
    }

    // -- getter length validation --------------------------------------

    #[test]
    fn test_get_u8_wrong_length() {
        let mut ap = ObexApparam::new();
        // Store 2 bytes for a tag, then try to get_u8 — should fail.
        ap.set_u16(0x01, 0x1234);
        assert_eq!(ap.get_u8(0x01), None);
    }

    #[test]
    fn test_get_u16_too_short() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 42);
        assert_eq!(ap.get_u16(0x01), None);
    }

    #[test]
    fn test_get_u32_too_short() {
        let mut ap = ObexApparam::new();
        ap.set_u16(0x01, 1);
        assert_eq!(ap.get_u32(0x01), None);
    }

    #[test]
    fn test_get_u64_too_short() {
        let mut ap = ObexApparam::new();
        ap.set_u32(0x01, 1);
        assert_eq!(ap.get_u64(0x01), None);
    }

    // -- chaining -------------------------------------------------------

    #[test]
    fn test_setter_chaining() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 1)
            .set_u16(0x02, 2)
            .set_u32(0x03, 3)
            .set_u64(0x04, 4)
            .set_string(0x05, "x")
            .set_bytes(0x06, &[0xAB]);

        assert_eq!(ap.len(), 6);
        assert_eq!(ap.get_u8(0x01), Some(1));
        assert_eq!(ap.get_u16(0x02), Some(2));
        assert_eq!(ap.get_u32(0x03), Some(3));
        assert_eq!(ap.get_u64(0x04), Some(4));
        assert_eq!(ap.get_string(0x05), Some("x".to_owned()));
        assert_eq!(ap.get_bytes(0x06), Some([0xAB].as_slice()));
    }

    // -- tag overwrite --------------------------------------------------

    #[test]
    fn test_overwrite_tag() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 10);
        assert_eq!(ap.get_u8(0x01), Some(10));

        ap.set_u8(0x01, 20);
        assert_eq!(ap.get_u8(0x01), Some(20));
        assert_eq!(ap.len(), 1); // still one tag
    }

    // -- encoded_len matches encode -------------------------------------

    #[test]
    fn test_encoded_len_matches_encode() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 1);
        ap.set_u16(0x02, 2);
        ap.set_string(0x03, "abc");
        ap.set_bytes(0x04, &[0; 10]);

        let predicted = ap.encoded_len();
        let encoded = ap.encode_to_vec().unwrap();
        assert_eq!(predicted, encoded.len());
    }

    // -- decode then re-encode produces same data ----------------------

    #[test]
    fn test_decode_reencode_identity() {
        // Build a known byte sequence with two tags in a specific order.
        // Because HashMap iteration order is arbitrary, re-encoding may
        // produce tags in a different order. However, decoding the
        // re-encoded data must yield the same logical content.
        let original = [
            0x01, 0x02, 0x00, 0x0A, // tag 0x01, u16 = 10
            0x02, 0x01, 0xFF, // tag 0x02, u8 = 255
        ];
        let decoded = ObexApparam::decode(&original).unwrap();
        let reencoded = decoded.encode_to_vec().unwrap();
        let redecoded = ObexApparam::decode(&reencoded).unwrap();

        assert_eq!(redecoded.get_u16(0x01), Some(10));
        assert_eq!(redecoded.get_u8(0x02), Some(255));
    }

    // -- get_string with data lacking NUL ------------------------------

    #[test]
    fn test_get_string_no_nul() {
        let mut ap = ObexApparam::new();
        // Manually insert bytes without NUL — get_string should still work.
        ap.params.insert(0x99, b"abc".to_vec());
        assert_eq!(ap.get_string(0x99), Some("abc".to_owned()));
    }

    // -- Default trait --------------------------------------------------

    #[test]
    fn test_default() {
        let ap = ObexApparam::default();
        assert!(ap.is_empty());
    }
}
