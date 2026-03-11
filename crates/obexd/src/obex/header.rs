// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX header handling — encoding, decoding, and header ID constants.
//
// Rust rewrite of gobex/gobex-header.c (568 lines) and gobex/gobex-header.h
// (90 lines) from BlueZ v5.86.
//
// OBEX headers carry metadata alongside the packet payload.  Each header is
// identified by a single-byte ID whose top two bits encode the value type:
//
//   Bits 7-6  |  Type          |  Wire encoding
//   ----------|----------------|--------------------------------------
//   0b00      |  Unicode       |  1-byte ID + 2-byte BE length + UTF-16BE data (null-terminated)
//   0b01      |  Byte sequence |  1-byte ID + 2-byte BE length + raw bytes
//   0b10      |  u8            |  1-byte ID + 1-byte value
//   0b11      |  u32           |  1-byte ID + 4-byte BE value
//
// Wire format and constant values are byte-identical to the C implementation
// for interoperability.

use super::apparam::ObexApparam;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by OBEX header encoding/decoding operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// The supplied header data is truncated or malformed.
    ParseError(String),
    /// The supplied buffer is too small to hold the encoded header.
    BufferTooSmall {
        /// Number of bytes required.
        needed: usize,
        /// Number of bytes available in the buffer.
        available: usize,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::ParseError(msg) => write!(f, "header parse error: {msg}"),
            HeaderError::BufferTooSmall { needed, available } => {
                write!(f, "header buffer too small: need {needed} bytes, got {available}")
            }
        }
    }
}

impl std::error::Error for HeaderError {}

// ---------------------------------------------------------------------------
// Encoding type mask constants
// ---------------------------------------------------------------------------

/// Bitmask for extracting the encoding type from a header ID byte.
pub const HDR_ENC_MASK: u8 = 0xC0;
/// Unicode string encoding (null-terminated UTF-16BE with 2-byte length prefix).
pub const HDR_ENC_UNICODE: u8 = 0x00;
/// Byte sequence encoding (2-byte length prefix).
pub const HDR_ENC_BYTES: u8 = 0x40;
/// Single `u8` value encoding.
pub const HDR_ENC_UINT8: u8 = 0x80;
/// 4-byte big-endian `u32` value encoding.
pub const HDR_ENC_UINT32: u8 = 0xC0;

// ---------------------------------------------------------------------------
// Header ID constants — values match gobex/gobex-header.h exactly
// ---------------------------------------------------------------------------

/// Not a real header (sentinel value).
pub const HDR_INVALID: u8 = 0x00;

// Unicode headers (encoding bits = 0b00)
/// Object Name (Unicode).
pub const HDR_NAME: u8 = 0x01;
/// Description (Unicode).
pub const HDR_DESCRIPTION: u8 = 0x05;
/// Destination Name for COPY/MOVE (Unicode).
pub const HDR_DESTNAME: u8 = 0x15;

// Byte sequence headers (encoding bits = 0b01)
/// Object Type — ASCII MIME string (Bytes).
pub const HDR_TYPE: u8 = 0x42;
/// ISO 8601 time (Bytes).
pub const HDR_TIME: u8 = 0x44;
/// Target UUID (Bytes).
pub const HDR_TARGET: u8 = 0x46;
/// HTTP headers (Bytes).
pub const HDR_HTTP: u8 = 0x47;
/// Object Body chunk (Bytes).
pub const HDR_BODY: u8 = 0x48;
/// End of Object Body (Bytes).
pub const HDR_BODY_END: u8 = 0x49;
/// Who — identifies OBEX application (Bytes).
pub const HDR_WHO: u8 = 0x4a;
/// Application Parameters — TLV encoded (Bytes).
pub const HDR_APPARAM: u8 = 0x4c;
/// Authentication Challenge (Bytes).
pub const HDR_AUTHCHAL: u8 = 0x4d;
/// Authentication Response (Bytes).
pub const HDR_AUTHRESP: u8 = 0x4e;
/// WAN UUID (Bytes).
pub const HDR_WANUUID: u8 = 0x50;
/// Object Class (Bytes).
pub const HDR_OBJECTCLASS: u8 = 0x51;
/// Session Parameters (Bytes).
pub const HDR_SESSIONPARAM: u8 = 0x52;

// u8 headers (encoding bits = 0b10)
/// Session Sequence number (u8).
pub const HDR_SESSIONSEQ: u8 = 0x93;
/// Action ID (u8).
pub const HDR_ACTION: u8 = 0x94;
/// Single Response Mode (u8).
pub const HDR_SRM: u8 = 0x97;
/// SRM Parameters (u8).
pub const HDR_SRMP: u8 = 0x98;

// u32 headers (encoding bits = 0b11)
/// Count (u32).
pub const HDR_COUNT: u8 = 0xc0;
/// Object Length (u32).
pub const HDR_LENGTH: u8 = 0xc3;
/// Connection ID (u32).
pub const HDR_CONNECTION: u8 = 0xcb;
/// Creator ID (u32).
pub const HDR_CREATOR: u8 = 0xcf;
/// Permissions (u32).
pub const HDR_PERMISSIONS: u8 = 0xd6;

// ---------------------------------------------------------------------------
// Action header values
// ---------------------------------------------------------------------------

/// Action: Copy object.
pub const ACTION_COPY: u8 = 0x00;
/// Action: Move/rename object.
pub const ACTION_MOVE: u8 = 0x01;
/// Action: Set permissions.
pub const ACTION_SETPERM: u8 = 0x02;

// ---------------------------------------------------------------------------
// SRM header values
// ---------------------------------------------------------------------------

/// SRM: Disabled.
pub const SRM_DISABLE: u8 = 0x00;
/// SRM: Enabled.
pub const SRM_ENABLE: u8 = 0x01;
/// SRM: Indicate (supported).
pub const SRM_INDICATE: u8 = 0x02;

// ---------------------------------------------------------------------------
// SRMP header values
// ---------------------------------------------------------------------------

/// SRMP: Proceed to next operation.
pub const SRMP_NEXT: u8 = 0x00;
/// SRMP: Wait before proceeding.
pub const SRMP_WAIT: u8 = 0x01;
/// SRMP: Next, then wait.
pub const SRMP_NEXT_WAIT: u8 = 0x02;

// ---------------------------------------------------------------------------
// Free helper functions (operate on header ID values)
// ---------------------------------------------------------------------------

/// Returns the encoding type of a header ID (the top 2 bits).
///
/// Equivalent to the C `G_OBEX_HDR_ENC(id)` macro.
#[inline]
#[must_use]
pub fn encoding_type(id: u8) -> u8 {
    id & HDR_ENC_MASK
}

/// Returns `true` if the header ID indicates a Unicode-encoded header.
#[inline]
#[must_use]
pub fn is_unicode(id: u8) -> bool {
    encoding_type(id) == HDR_ENC_UNICODE
}

/// Returns `true` if the header ID indicates a byte-sequence-encoded header.
#[inline]
#[must_use]
pub fn is_bytes(id: u8) -> bool {
    encoding_type(id) == HDR_ENC_BYTES
}

// ---------------------------------------------------------------------------
// UTF-16BE conversion helpers (private)
// ---------------------------------------------------------------------------

/// Converts a UTF-8 string to a null-terminated UTF-16BE byte sequence.
///
/// OBEX requires Unicode headers to carry UTF-16 data in big-endian byte
/// order, terminated by a two-byte null (`0x00, 0x00`).
///
/// Replaces the C `utf8_to_utf16` helper which calls `g_utf8_to_utf16`
/// followed by a host-to-network byte-swap loop.
fn utf8_to_utf16be(s: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(s.len() * 2 + 2);
    for unit in s.encode_utf16() {
        let [hi, lo] = unit.to_be_bytes();
        buf.push(hi);
        buf.push(lo);
    }
    // Null terminator (two zero bytes).
    buf.push(0x00);
    buf.push(0x00);
    buf
}

/// Converts a UTF-16BE byte slice (potentially null-terminated) to a UTF-8
/// [`String`].
///
/// The input `data` must have even length.  A trailing null code unit
/// (`0x0000`) is stripped if present, matching the C `utf16_to_utf8` helper
/// which calls `g_utf16_to_utf8` on the non-null portion.
fn utf16be_to_utf8(data: &[u8]) -> Result<String, HeaderError> {
    if data.len() % 2 != 0 {
        return Err(HeaderError::ParseError("UTF-16BE data has odd byte count".into()));
    }
    if data.is_empty() {
        return Ok(String::new());
    }

    // Parse big-endian u16 code units.
    let mut units: Vec<u16> = Vec::with_capacity(data.len() / 2);
    for chunk in data.chunks_exact(2) {
        units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    // Strip trailing null terminator if present.
    if let Some(&last) = units.last() {
        if last == 0 {
            units.pop();
        }
    }

    String::from_utf16(&units)
        .map_err(|e| HeaderError::ParseError(format!("UTF-16 to UTF-8 conversion failed: {e}")))
}

/// Returns the number of bytes that a UTF-8 string occupies when encoded as
/// null-terminated UTF-16BE (the value-only portion, excluding the header ID
/// and length prefix).
///
/// For an empty string the result is 0 (matching the C special case where
/// `hlen == 3`).
fn utf16be_value_byte_len(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    let code_units: usize = s.encode_utf16().count();
    // Each code unit is 2 bytes, plus a 2-byte null terminator.
    (code_units + 1) * 2
}

// ---------------------------------------------------------------------------
// ObexHeader enum
// ---------------------------------------------------------------------------

/// An OBEX protocol header, carrying one of four typed values.
///
/// Replaces the C `struct _GObexHeader` which used a union for the value.
/// In Rust, the enum provides type safety: each variant stores its own typed
/// payload, and the header ID is carried alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObexHeader {
    /// Unicode header: UTF-16BE on the wire, UTF-8 in memory.
    Unicode {
        /// Header ID byte (top 2 bits == `HDR_ENC_UNICODE`).
        id: u8,
        /// The string value, stored as UTF-8.
        value: String,
    },
    /// Byte-sequence header.
    Bytes {
        /// Header ID byte (top 2 bits == `HDR_ENC_BYTES`).
        id: u8,
        /// The raw byte data.
        data: Vec<u8>,
    },
    /// Single-byte header.
    U8 {
        /// Header ID byte (top 2 bits == `HDR_ENC_UINT8`).
        id: u8,
        /// The u8 value.
        value: u8,
    },
    /// 32-bit unsigned integer header (big-endian on wire).
    U32 {
        /// Header ID byte (top 2 bits == `HDR_ENC_UINT32`).
        id: u8,
        /// The u32 value (host byte order in memory).
        value: u32,
    },
}

impl ObexHeader {
    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Returns the header ID byte.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u8 {
        match self {
            ObexHeader::Unicode { id, .. }
            | ObexHeader::Bytes { id, .. }
            | ObexHeader::U8 { id, .. }
            | ObexHeader::U32 { id, .. } => *id,
        }
    }

    /// Returns the total encoded length of this header on the wire (ID byte +
    /// length prefix + value bytes).
    ///
    /// - Unicode: `3 + utf16be_value_byte_len` (or 3 for empty string)
    /// - Bytes: `3 + data.len()`
    /// - U8: `2`
    /// - U32: `5`
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            ObexHeader::Unicode { value, .. } => {
                let vlen = utf16be_value_byte_len(value);
                if vlen == 0 { 3 } else { 3 + vlen }
            }
            ObexHeader::Bytes { data, .. } => 3 + data.len(),
            ObexHeader::U8 { .. } => 2,
            ObexHeader::U32 { .. } => 5,
        }
    }

    /// Returns the string value if this is a Unicode header, or `None`.
    #[must_use]
    pub fn as_unicode(&self) -> Option<&str> {
        match self {
            ObexHeader::Unicode { value, .. } => Some(value.as_str()),
            _ => None,
        }
    }

    /// Returns the byte data if this is a Bytes header, or `None`.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ObexHeader::Bytes { data, .. } => Some(data.as_slice()),
            _ => None,
        }
    }

    /// Returns the u8 value if this is a U8 header, or `None`.
    #[must_use]
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            ObexHeader::U8 { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Returns the u32 value if this is a U32 header, or `None`.
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            ObexHeader::U32 { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Returns the encoding type of this header's ID (the top 2 bits).
    #[inline]
    #[must_use]
    pub fn encoding_type(&self) -> u8 {
        encoding_type(self.id())
    }

    /// Returns `true` if this header carries a Unicode string value.
    #[inline]
    #[must_use]
    pub fn is_unicode(&self) -> bool {
        matches!(self, ObexHeader::Unicode { .. })
    }

    /// Returns `true` if this header carries a byte-sequence value.
    #[inline]
    #[must_use]
    pub fn is_bytes(&self) -> bool {
        matches!(self, ObexHeader::Bytes { .. })
    }

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Creates a new Unicode header from a UTF-8 string.
    ///
    /// # Panics
    ///
    /// Debug-asserts that the top 2 bits of `id` equal `HDR_ENC_UNICODE`.
    #[must_use]
    pub fn new_unicode(id: u8, value: &str) -> Self {
        debug_assert_eq!(
            encoding_type(id),
            HDR_ENC_UNICODE,
            "new_unicode called with non-Unicode header ID 0x{id:02x}"
        );
        ObexHeader::Unicode { id, value: value.to_owned() }
    }

    /// Creates a new byte-sequence header.
    ///
    /// # Panics
    ///
    /// Debug-asserts that the top 2 bits of `id` equal `HDR_ENC_BYTES`.
    #[must_use]
    pub fn new_bytes(id: u8, data: &[u8]) -> Self {
        debug_assert_eq!(
            encoding_type(id),
            HDR_ENC_BYTES,
            "new_bytes called with non-Bytes header ID 0x{id:02x}"
        );
        ObexHeader::Bytes { id, data: data.to_vec() }
    }

    /// Creates a new single-byte header.
    ///
    /// # Panics
    ///
    /// Debug-asserts that the top 2 bits of `id` equal `HDR_ENC_UINT8`.
    #[must_use]
    pub fn new_u8(id: u8, value: u8) -> Self {
        debug_assert_eq!(
            encoding_type(id),
            HDR_ENC_UINT8,
            "new_u8 called with non-U8 header ID 0x{id:02x}"
        );
        ObexHeader::U8 { id, value }
    }

    /// Creates a new 32-bit unsigned integer header.
    ///
    /// # Panics
    ///
    /// Debug-asserts that the top 2 bits of `id` equal `HDR_ENC_UINT32`.
    #[must_use]
    pub fn new_u32(id: u8, value: u32) -> Self {
        debug_assert_eq!(
            encoding_type(id),
            HDR_ENC_UINT32,
            "new_u32 called with non-U32 header ID 0x{id:02x}"
        );
        ObexHeader::U32 { id, value }
    }

    /// Creates a new Application Parameters header (`HDR_APPARAM`) by encoding
    /// the given [`ObexApparam`] container into a byte-sequence header.
    ///
    /// Returns `None` if encoding the apparam fails (e.g. the container is
    /// empty).  Matches the C `g_obex_header_new_apparam` which returns `NULL`
    /// on encode failure.
    ///
    /// Uses [`ObexApparam::encoded_len`] to pre-allocate the exact buffer size,
    /// and [`ObexApparam::encode`] to serialise the TLV data into the buffer.
    /// The convenience method [`ObexApparam::encode_to_vec`] is available for
    /// callers who prefer a single-call allocation path.
    #[must_use]
    pub fn new_apparam(apparam: &ObexApparam) -> Option<Self> {
        // Compute the exact buffer size required for the apparam TLV payload.
        let len = apparam.encoded_len();
        if len == 0 {
            return None;
        }

        // Allocate a buffer of exactly the right size and encode into it.
        let mut data = vec![0u8; len];
        let written = apparam.encode(&mut data).ok()?;
        data.truncate(written);

        // Verify consistency: encode_to_vec should produce the same result.
        debug_assert_eq!(apparam.encode_to_vec().ok().as_deref(), Some(data.as_slice()));

        Some(ObexHeader::Bytes { id: HDR_APPARAM, data })
    }

    // -----------------------------------------------------------------------
    // Encode
    // -----------------------------------------------------------------------

    /// Encodes this header into `buf`, returning the number of bytes written.
    ///
    /// The output is wire-compatible with the C `g_obex_header_encode`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::BufferTooSmall`] if `buf` cannot hold the
    /// encoded header.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, HeaderError> {
        let hlen = self.encoded_len();
        if buf.len() < hlen {
            return Err(HeaderError::BufferTooSmall { needed: hlen, available: buf.len() });
        }

        match self {
            ObexHeader::Unicode { id, value } => {
                buf[0] = *id;
                if value.is_empty() {
                    // Empty string: write id + length=3 (just the header overhead).
                    let wire_len: u16 = 3;
                    buf[1..3].copy_from_slice(&wire_len.to_be_bytes());
                    Ok(3)
                } else {
                    let utf16_data = utf8_to_utf16be(value);
                    let wire_len = 3u16.wrapping_add(utf16_data.len() as u16);
                    buf[1..3].copy_from_slice(&wire_len.to_be_bytes());
                    buf[3..3 + utf16_data.len()].copy_from_slice(&utf16_data);
                    Ok(wire_len as usize)
                }
            }
            ObexHeader::Bytes { id, data } => {
                buf[0] = *id;
                let wire_len = 3u16.wrapping_add(data.len() as u16);
                buf[1..3].copy_from_slice(&wire_len.to_be_bytes());
                buf[3..3 + data.len()].copy_from_slice(data);
                Ok(wire_len as usize)
            }
            ObexHeader::U8 { id, value } => {
                buf[0] = *id;
                buf[1] = *value;
                Ok(2)
            }
            ObexHeader::U32 { id, value } => {
                buf[0] = *id;
                buf[1..5].copy_from_slice(&value.to_be_bytes());
                Ok(5)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Decode
    // -----------------------------------------------------------------------

    /// Decodes a single OBEX header from the front of `buf`.
    ///
    /// Returns `(header, consumed_bytes)` on success.  The caller should
    /// advance the buffer by `consumed_bytes` before decoding the next header.
    ///
    /// The output is wire-compatible with the C `g_obex_header_decode`.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::ParseError`] if the buffer is too short or
    /// contains malformed data.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), HeaderError> {
        if buf.len() < 2 {
            return Err(HeaderError::ParseError("too short header in packet".into()));
        }

        let id = buf[0];
        let enc = encoding_type(id);

        match enc {
            HDR_ENC_UNICODE => {
                if buf.len() < 3 {
                    return Err(HeaderError::ParseError(format!(
                        "not enough data for unicode header (0x{id:02x})"
                    )));
                }
                let hdr_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;

                if hdr_len == 3 {
                    // Empty string.
                    return Ok((ObexHeader::Unicode { id, value: String::new() }, 3));
                }

                if hdr_len > buf.len() || hdr_len < 5 {
                    return Err(HeaderError::ParseError(format!(
                        "invalid unicode header (0x{id:02x}) length ({hdr_len})"
                    )));
                }

                // Data between the 3-byte header overhead and the end of the
                // header contains UTF-16BE code units.  The last 2 bytes are
                // typically the null terminator; utf16be_to_utf8 strips it.
                let utf16_data = &buf[3..hdr_len];
                let value = utf16be_to_utf8(utf16_data)?;

                Ok((ObexHeader::Unicode { id, value }, hdr_len))
            }

            HDR_ENC_BYTES => {
                if buf.len() < 3 {
                    return Err(HeaderError::ParseError("too short byte array header".into()));
                }
                let hdr_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;

                if hdr_len > buf.len() {
                    return Err(HeaderError::ParseError("too long byte array header".into()));
                }
                if hdr_len < 3 {
                    return Err(HeaderError::ParseError("too small byte array length".into()));
                }

                let data = buf[3..hdr_len].to_vec();
                Ok((ObexHeader::Bytes { id, data }, hdr_len))
            }

            HDR_ENC_UINT8 => {
                // Already validated buf.len() >= 2 above.
                let value = buf[1];
                Ok((ObexHeader::U8 { id, value }, 2))
            }

            HDR_ENC_UINT32 => {
                if buf.len() < 5 {
                    return Err(HeaderError::ParseError("too short uint32 header".into()));
                }
                let value = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                Ok((ObexHeader::U32 { id, value }, 5))
            }

            _ => {
                // All four encoding patterns are covered (0x00, 0x40, 0x80,
                // 0xC0), so this branch is unreachable for valid 2-bit masks.
                Err(HeaderError::ParseError(format!(
                    "unknown encoding type 0x{enc:02x} for header 0x{id:02x}"
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Header list builder
// ---------------------------------------------------------------------------

/// Builds a header list from an iterator of [`ObexHeader`] values.
///
/// This is the Rust equivalent of the C `g_obex_header_create_list` variadic
/// function.  In idiomatic Rust, callers can simply use
/// `vec![header1, header2, ...]` directly; this helper is provided for API
/// parity.
#[must_use]
pub fn create_list(headers: impl IntoIterator<Item = ObexHeader>) -> Vec<ObexHeader> {
    headers.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Encoding type helpers -------------------------------------------

    #[test]
    fn test_encoding_type_mask() {
        assert_eq!(encoding_type(HDR_NAME), HDR_ENC_UNICODE);
        assert_eq!(encoding_type(HDR_TYPE), HDR_ENC_BYTES);
        assert_eq!(encoding_type(HDR_ACTION), HDR_ENC_UINT8);
        assert_eq!(encoding_type(HDR_CONNECTION), HDR_ENC_UINT32);
    }

    #[test]
    fn test_is_unicode_and_is_bytes() {
        assert!(is_unicode(HDR_NAME));
        assert!(is_unicode(HDR_DESCRIPTION));
        assert!(!is_unicode(HDR_TYPE));

        assert!(is_bytes(HDR_TYPE));
        assert!(is_bytes(HDR_BODY));
        assert!(!is_bytes(HDR_NAME));
    }

    // -- Constant values --------------------------------------------------

    #[test]
    fn test_header_id_constants() {
        assert_eq!(HDR_INVALID, 0x00);
        assert_eq!(HDR_NAME, 0x01);
        assert_eq!(HDR_DESCRIPTION, 0x05);
        assert_eq!(HDR_DESTNAME, 0x15);
        assert_eq!(HDR_TYPE, 0x42);
        assert_eq!(HDR_TIME, 0x44);
        assert_eq!(HDR_TARGET, 0x46);
        assert_eq!(HDR_HTTP, 0x47);
        assert_eq!(HDR_BODY, 0x48);
        assert_eq!(HDR_BODY_END, 0x49);
        assert_eq!(HDR_WHO, 0x4a);
        assert_eq!(HDR_APPARAM, 0x4c);
        assert_eq!(HDR_AUTHCHAL, 0x4d);
        assert_eq!(HDR_AUTHRESP, 0x4e);
        assert_eq!(HDR_WANUUID, 0x50);
        assert_eq!(HDR_OBJECTCLASS, 0x51);
        assert_eq!(HDR_SESSIONPARAM, 0x52);
        assert_eq!(HDR_SESSIONSEQ, 0x93);
        assert_eq!(HDR_ACTION, 0x94);
        assert_eq!(HDR_SRM, 0x97);
        assert_eq!(HDR_SRMP, 0x98);
        assert_eq!(HDR_COUNT, 0xc0);
        assert_eq!(HDR_LENGTH, 0xc3);
        assert_eq!(HDR_CONNECTION, 0xcb);
        assert_eq!(HDR_CREATOR, 0xcf);
        assert_eq!(HDR_PERMISSIONS, 0xd6);
    }

    #[test]
    fn test_action_srm_srmp_constants() {
        assert_eq!(ACTION_COPY, 0x00);
        assert_eq!(ACTION_MOVE, 0x01);
        assert_eq!(ACTION_SETPERM, 0x02);
        assert_eq!(SRM_DISABLE, 0x00);
        assert_eq!(SRM_ENABLE, 0x01);
        assert_eq!(SRM_INDICATE, 0x02);
        assert_eq!(SRMP_NEXT, 0x00);
        assert_eq!(SRMP_WAIT, 0x01);
        assert_eq!(SRMP_NEXT_WAIT, 0x02);
    }

    // -- UTF-16BE conversion -----------------------------------------------

    #[test]
    fn test_utf8_to_utf16be_hello() {
        let result = utf8_to_utf16be("Hello");
        // 'H'=0x0048 'e'=0x0065 'l'=0x006C 'l'=0x006C 'o'=0x006F + null
        let expected = [
            0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00,
            0x00, // null terminator
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_utf16be_to_utf8_hello() {
        let data = [0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00];
        let result = utf16be_to_utf8(&data).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_utf16be_roundtrip() {
        let original = "Bluetooth™";
        let encoded = utf8_to_utf16be(original);
        let decoded = utf16be_to_utf8(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_utf16be_to_utf8_empty() {
        let result = utf16be_to_utf8(&[]).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_utf16be_to_utf8_just_null() {
        let result = utf16be_to_utf8(&[0x00, 0x00]).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_utf16be_to_utf8_odd_length() {
        let result = utf16be_to_utf8(&[0x00]);
        assert!(result.is_err());
    }

    // -- ObexHeader accessors ---------------------------------------------

    #[test]
    fn test_header_id() {
        let hdr = ObexHeader::new_unicode(HDR_NAME, "test");
        assert_eq!(hdr.id(), HDR_NAME);

        let hdr = ObexHeader::new_bytes(HDR_BODY, &[1, 2, 3]);
        assert_eq!(hdr.id(), HDR_BODY);

        let hdr = ObexHeader::new_u8(HDR_SRM, SRM_ENABLE);
        assert_eq!(hdr.id(), HDR_SRM);

        let hdr = ObexHeader::new_u32(HDR_CONNECTION, 42);
        assert_eq!(hdr.id(), HDR_CONNECTION);
    }

    #[test]
    fn test_as_accessors() {
        let hdr = ObexHeader::new_unicode(HDR_NAME, "file.txt");
        assert_eq!(hdr.as_unicode(), Some("file.txt"));
        assert_eq!(hdr.as_bytes(), None);
        assert_eq!(hdr.as_u8(), None);
        assert_eq!(hdr.as_u32(), None);

        let hdr = ObexHeader::new_bytes(HDR_BODY, &[0xAB, 0xCD]);
        assert_eq!(hdr.as_bytes(), Some([0xAB, 0xCD].as_slice()));
        assert_eq!(hdr.as_unicode(), None);

        let hdr = ObexHeader::new_u8(HDR_ACTION, ACTION_COPY);
        assert_eq!(hdr.as_u8(), Some(ACTION_COPY));
        assert_eq!(hdr.as_u32(), None);

        let hdr = ObexHeader::new_u32(HDR_LENGTH, 0x1234);
        assert_eq!(hdr.as_u32(), Some(0x1234));
        assert_eq!(hdr.as_u8(), None);
    }

    // -- encoded_len -------------------------------------------------------

    #[test]
    fn test_encoded_len_unicode_empty() {
        let hdr = ObexHeader::new_unicode(HDR_NAME, "");
        assert_eq!(hdr.encoded_len(), 3);
    }

    #[test]
    fn test_encoded_len_unicode_hello() {
        // "Hello" = 5 UTF-16 code units → (5+1)*2 = 12 bytes → 3 + 12 = 15
        let hdr = ObexHeader::new_unicode(HDR_NAME, "Hello");
        assert_eq!(hdr.encoded_len(), 15);
    }

    #[test]
    fn test_encoded_len_bytes() {
        let hdr = ObexHeader::new_bytes(HDR_BODY, &[0; 10]);
        assert_eq!(hdr.encoded_len(), 13); // 3 + 10
    }

    #[test]
    fn test_encoded_len_u8() {
        let hdr = ObexHeader::new_u8(HDR_SRM, SRM_ENABLE);
        assert_eq!(hdr.encoded_len(), 2);
    }

    #[test]
    fn test_encoded_len_u32() {
        let hdr = ObexHeader::new_u32(HDR_CONNECTION, 1);
        assert_eq!(hdr.encoded_len(), 5);
    }

    // -- Encode / Decode round-trip ----------------------------------------

    #[test]
    fn test_encode_decode_unicode() {
        let original = ObexHeader::new_unicode(HDR_NAME, "test.txt");
        let mut buf = [0u8; 256];
        let written = original.encode(&mut buf).unwrap();
        assert_eq!(written, original.encoded_len());

        let (decoded, consumed) = ObexHeader::decode(&buf[..written]).unwrap();
        assert_eq!(consumed, written);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_unicode_empty() {
        let original = ObexHeader::new_unicode(HDR_NAME, "");
        let mut buf = [0u8; 16];
        let written = original.encode(&mut buf).unwrap();
        assert_eq!(written, 3);
        assert_eq!(buf[0], HDR_NAME);
        assert_eq!(u16::from_be_bytes([buf[1], buf[2]]), 3);

        let (decoded, consumed) = ObexHeader::decode(&buf[..written]).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(decoded.as_unicode(), Some(""));
    }

    #[test]
    fn test_encode_unicode_wire_format() {
        // "Hi" = 0x0048, 0x0069 in UTF-16BE + null terminator
        let hdr = ObexHeader::new_unicode(HDR_NAME, "Hi");
        let mut buf = [0u8; 32];
        let written = hdr.encode(&mut buf).unwrap();

        // id=0x01, length = 3 + 6 = 9, data = 00 48 00 69 00 00
        assert_eq!(written, 9);
        assert_eq!(buf[0], 0x01); // id
        assert_eq!(buf[1..3], [0x00, 0x09]); // length = 9
        assert_eq!(buf[3..9], [0x00, 0x48, 0x00, 0x69, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_decode_bytes() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let original = ObexHeader::new_bytes(HDR_BODY, &payload);
        let mut buf = [0u8; 32];
        let written = original.encode(&mut buf).unwrap();
        assert_eq!(written, 7); // 3 + 4

        let (decoded, consumed) = ObexHeader::decode(&buf[..written]).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_u8() {
        let original = ObexHeader::new_u8(HDR_SRM, SRM_ENABLE);
        let mut buf = [0u8; 8];
        let written = original.encode(&mut buf).unwrap();
        assert_eq!(written, 2);
        assert_eq!(buf[0], HDR_SRM);
        assert_eq!(buf[1], SRM_ENABLE);

        let (decoded, consumed) = ObexHeader::decode(&buf[..written]).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_u32() {
        let original = ObexHeader::new_u32(HDR_CONNECTION, 0xDEADBEEF);
        let mut buf = [0u8; 8];
        let written = original.encode(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert_eq!(buf[0], HDR_CONNECTION);
        assert_eq!(buf[1..5], [0xDE, 0xAD, 0xBE, 0xEF]);

        let (decoded, consumed) = ObexHeader::decode(&buf[..written]).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_buffer_too_small() {
        let hdr = ObexHeader::new_u32(HDR_LENGTH, 42);
        let mut buf = [0u8; 3]; // needs 5
        let result = hdr.encode(&mut buf);
        assert!(result.is_err());
    }

    // -- Decode error cases ------------------------------------------------

    #[test]
    fn test_decode_too_short() {
        let result = ObexHeader::decode(&[0x97]); // only 1 byte
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_u32_too_short() {
        let result = ObexHeader::decode(&[HDR_CONNECTION, 0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_bytes_length_exceeds_buffer() {
        // Header says length=100 but only 5 bytes total available.
        let buf = [HDR_BODY, 0x00, 0x64, 0x00, 0x00];
        let result = ObexHeader::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_bytes_length_too_small() {
        // Header says length=2, which is < 3 minimum.
        let buf = [HDR_BODY, 0x00, 0x02];
        let result = ObexHeader::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_unicode_invalid_length() {
        // Unicode header with length=4 is invalid (< 5 for non-empty).
        let buf = [HDR_NAME, 0x00, 0x04, 0x00];
        let result = ObexHeader::decode(&buf);
        assert!(result.is_err());
    }

    // -- new_apparam -------------------------------------------------------

    #[test]
    fn test_new_apparam_with_data() {
        let mut ap = ObexApparam::new();
        ap.set_u8(0x01, 42);
        let hdr = ObexHeader::new_apparam(&ap);
        assert!(hdr.is_some());
        let hdr = hdr.unwrap();
        assert_eq!(hdr.id(), HDR_APPARAM);
        assert!(hdr.as_bytes().is_some());
        // The encoded apparam should be: [tag=0x01, len=1, val=42]
        assert_eq!(hdr.as_bytes().unwrap(), &[0x01, 0x01, 42]);
    }

    #[test]
    fn test_new_apparam_empty_returns_none() {
        let ap = ObexApparam::new();
        let hdr = ObexHeader::new_apparam(&ap);
        assert!(hdr.is_none());
    }

    // -- Instance encoding_type / is_unicode / is_bytes --------------------

    #[test]
    fn test_instance_encoding_helpers() {
        let hdr = ObexHeader::new_unicode(HDR_NAME, "x");
        assert_eq!(hdr.encoding_type(), HDR_ENC_UNICODE);
        assert!(hdr.is_unicode());
        assert!(!hdr.is_bytes());

        let hdr = ObexHeader::new_bytes(HDR_BODY, &[]);
        assert_eq!(hdr.encoding_type(), HDR_ENC_BYTES);
        assert!(hdr.is_bytes());
        assert!(!hdr.is_unicode());
    }

    // -- create_list -------------------------------------------------------

    #[test]
    fn test_create_list() {
        let list = create_list([
            ObexHeader::new_unicode(HDR_NAME, "test"),
            ObexHeader::new_u8(HDR_SRM, SRM_ENABLE),
            ObexHeader::new_u32(HDR_CONNECTION, 1),
        ]);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].id(), HDR_NAME);
        assert_eq!(list[1].id(), HDR_SRM);
        assert_eq!(list[2].id(), HDR_CONNECTION);
    }

    // -- Multiple headers sequential decode ---------------------------------

    #[test]
    fn test_sequential_decode() {
        let h1 = ObexHeader::new_u8(HDR_SRM, SRM_ENABLE);
        let h2 = ObexHeader::new_u32(HDR_CONNECTION, 7);
        let h3 = ObexHeader::new_unicode(HDR_NAME, "AB");

        let mut buf = [0u8; 128];
        let mut offset = 0;
        offset += h1.encode(&mut buf[offset..]).unwrap();
        offset += h2.encode(&mut buf[offset..]).unwrap();
        offset += h3.encode(&mut buf[offset..]).unwrap();

        let mut pos = 0;
        let (d1, c1) = ObexHeader::decode(&buf[pos..offset]).unwrap();
        pos += c1;
        let (d2, c2) = ObexHeader::decode(&buf[pos..offset]).unwrap();
        pos += c2;
        let (d3, c3) = ObexHeader::decode(&buf[pos..offset]).unwrap();
        pos += c3;

        assert_eq!(pos, offset);
        assert_eq!(d1, h1);
        assert_eq!(d2, h2);
        assert_eq!(d3, h3);
    }
}
