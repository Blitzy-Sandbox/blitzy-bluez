// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX packet encoding/decoding — Rust rewrite of gobex/gobex-packet.c (456 lines)
// and gobex/gobex-packet.h (99 lines) from BlueZ v5.86.
//
// Implements the OBEX packet wire format:
//   [opcode | FINAL_BIT] [u16 big-endian packet-length] [pre-header data] [headers...]
//
// with optional body data producer support for streaming large objects.
//
// Wire format and constant values are byte-identical to the C implementation
// for interoperability.

use super::header::{HDR_BODY, HDR_BODY_END, HeaderError, ObexHeader};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from OBEX packet encode/decode operations.
#[derive(Debug)]
pub enum PacketError {
    /// Malformed packet data encountered during decode.
    ParseError(String),
    /// Output buffer is too small for encoding the packet.
    BufferTooSmall(String),
    /// An error propagated from an OBEX header encode/decode operation.
    Header(HeaderError),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "OBEX parse error: {msg}"),
            Self::BufferTooSmall(msg) => write!(f, "buffer too small: {msg}"),
            Self::Header(e) => write!(f, "header error: {e}"),
        }
    }
}

impl std::error::Error for PacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HeaderError> for PacketError {
    fn from(e: HeaderError) -> Self {
        Self::Header(e)
    }
}

// ---------------------------------------------------------------------------
// Request opcode constants  (low 7 bits; FINAL bit = 0x80 is handled separately)
// Matches C definitions: G_OBEX_OP_CONNECT … G_OBEX_OP_ABORT
// ---------------------------------------------------------------------------

/// OBEX CONNECT request opcode.
pub const OP_CONNECT: u8 = 0x00;
/// OBEX DISCONNECT request opcode.
pub const OP_DISCONNECT: u8 = 0x01;
/// OBEX PUT request opcode.
pub const OP_PUT: u8 = 0x02;
/// OBEX GET request opcode.
pub const OP_GET: u8 = 0x03;
/// OBEX SETPATH request opcode.
pub const OP_SETPATH: u8 = 0x05;
/// OBEX ACTION request opcode.
pub const OP_ACTION: u8 = 0x06;
/// OBEX SESSION request opcode.
pub const OP_SESSION: u8 = 0x07;
/// OBEX ABORT request opcode.
pub const OP_ABORT: u8 = 0x7f;

/// OBEX FINAL bit — OR'd with the opcode in the first byte on the wire.
pub const PACKET_FINAL: u8 = 0x80;

// ---------------------------------------------------------------------------
// Response code constants  (38 values matching C `G_OBEX_RSP_*`)
// ---------------------------------------------------------------------------

/// Continue — more data expected.
pub const RSP_CONTINUE: u8 = 0x10;
/// Success — operation completed.
pub const RSP_SUCCESS: u8 = 0x20;
/// Created.
pub const RSP_CREATED: u8 = 0x21;
/// Accepted.
pub const RSP_ACCEPTED: u8 = 0x22;
/// Non-Authoritative Information.
pub const RSP_NON_AUTHORITATIVE: u8 = 0x23;
/// No Content.
pub const RSP_NO_CONTENT: u8 = 0x24;
/// Reset Content.
pub const RSP_RESET_CONTENT: u8 = 0x25;
/// Partial Content.
pub const RSP_PARTIAL_CONTENT: u8 = 0x26;
/// Multiple Choices.
pub const RSP_MULTIPLE_CHOICES: u8 = 0x30;
/// Moved Permanently.
pub const RSP_MOVED_PERMANENTLY: u8 = 0x31;
/// Moved Temporarily.
pub const RSP_MOVED_TEMPORARILY: u8 = 0x32;
/// See Other.
pub const RSP_SEE_OTHER: u8 = 0x33;
/// Not Modified.
pub const RSP_NOT_MODIFIED: u8 = 0x34;
/// Use Proxy.
pub const RSP_USE_PROXY: u8 = 0x35;
/// Bad Request.
pub const RSP_BAD_REQUEST: u8 = 0x40;
/// Unauthorized.
pub const RSP_UNAUTHORIZED: u8 = 0x41;
/// Payment Required.
pub const RSP_PAYMENT_REQUIRED: u8 = 0x42;
/// Forbidden.
pub const RSP_FORBIDDEN: u8 = 0x43;
/// Not Found.
pub const RSP_NOT_FOUND: u8 = 0x44;
/// Method Not Allowed.
pub const RSP_METHOD_NOT_ALLOWED: u8 = 0x45;
/// Not Acceptable.
pub const RSP_NOT_ACCEPTABLE: u8 = 0x46;
/// Proxy Authentication Required.
pub const RSP_PROXY_AUTH_REQUIRED: u8 = 0x47;
/// Request Timeout.
pub const RSP_REQUEST_TIME_OUT: u8 = 0x48;
/// Conflict.
pub const RSP_CONFLICT: u8 = 0x49;
/// Gone.
pub const RSP_GONE: u8 = 0x4a;
/// Length Required.
pub const RSP_LENGTH_REQUIRED: u8 = 0x4b;
/// Precondition Failed.
pub const RSP_PRECONDITION_FAILED: u8 = 0x4c;
/// Requested Entity Too Large.
pub const RSP_REQ_ENTITY_TOO_LARGE: u8 = 0x4d;
/// Requested URL Too Large.
pub const RSP_REQ_URL_TOO_LARGE: u8 = 0x4e;
/// Unsupported Media Type.
pub const RSP_UNSUPPORTED_MEDIA_TYPE: u8 = 0x4f;
/// Internal Server Error.
pub const RSP_INTERNAL_SERVER_ERROR: u8 = 0x50;
/// Not Implemented.
pub const RSP_NOT_IMPLEMENTED: u8 = 0x51;
/// Bad Gateway.
pub const RSP_BAD_GATEWAY: u8 = 0x52;
/// Service Unavailable.
pub const RSP_SERVICE_UNAVAILABLE: u8 = 0x53;
/// Gateway Timeout.
pub const RSP_GATEWAY_TIMEOUT: u8 = 0x54;
/// HTTP Version Not Supported.
pub const RSP_HTTP_VERSION_NOT_SUPPORTED: u8 = 0x55;
/// Database Full.
pub const RSP_DATABASE_FULL: u8 = 0x60;
/// Database Locked.
pub const RSP_DATABASE_LOCKED: u8 = 0x61;

// ---------------------------------------------------------------------------
// ObexPacket
// ---------------------------------------------------------------------------

/// Type alias for the body data producer closure.
///
/// The closure receives a mutable byte slice and writes body data into it,
/// returning the number of bytes produced.  Returning `Ok(0)` signals
/// end-of-body.
type BodyProducer = Box<dyn FnMut(&mut [u8]) -> Result<usize, PacketError> + Send>;

/// An OBEX protocol packet containing opcode, optional pre-header data,
/// an ordered list of headers, and an optional body data producer.
///
/// Wire format: `[opcode | FINAL_BIT] [u16-BE packet-length] [data] [headers…]`
///
/// Replaces the C `struct _GObexPacket`:
/// - `GSList *headers`            → `Vec<ObexHeader>`
/// - `union data { buf; buf_ref}` → `Vec<u8>` (always owned)
/// - `GObexDataProducer`          → `Box<dyn FnMut>` closure
pub struct ObexPacket {
    /// Request opcode or response code (stored **without** the FINAL bit).
    opcode: u8,
    /// Whether the FINAL bit should be set on the wire.
    final_bit: bool,
    /// Pre-header data region (e.g., 4-byte ConnectData, 2-byte SetpathData).
    data: Vec<u8>,
    /// Ordered list of OBEX headers.
    headers: Vec<ObexHeader>,
    /// Accumulated encoded byte-length of all headers in `headers`.
    hlen: usize,
    /// Optional body data producer invoked during [`encode`](Self::encode).
    body_producer: Option<BodyProducer>,
}

// `body_producer` is not `Debug`, so derive is impossible; provide a manual impl.
impl std::fmt::Debug for ObexPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObexPacket")
            .field("opcode", &self.opcode)
            .field("final_bit", &self.final_bit)
            .field("data_len", &self.data.len())
            .field("num_headers", &self.headers.len())
            .field("hlen", &self.hlen)
            .field("has_body_producer", &self.body_producer.is_some())
            .finish()
    }
}

impl ObexPacket {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new OBEX packet with the given opcode.
    ///
    /// Defaults: `final_bit = true`, no headers, no pre-header data, no body
    /// producer.  Matches the C `g_obex_packet_new(opcode, G_OBEX_HDR_INVALID)`
    /// constructor where `final_bit` defaults to `TRUE`.
    pub fn new(opcode: u8) -> Self {
        Self {
            opcode,
            final_bit: true,
            data: Vec::new(),
            headers: Vec::new(),
            hlen: 0,
            body_producer: None,
        }
    }

    /// Create a new OBEX response packet.
    ///
    /// Convenience wrapper identical to [`new`](Self::new) — documents that the
    /// opcode value is a response code (e.g., [`RSP_SUCCESS`]).  Response
    /// packets always have `final_bit = true`.
    pub fn new_response(rsp: u8) -> Self {
        Self::new(rsp)
    }

    // -----------------------------------------------------------------------
    // Opcode / operation accessors
    // -----------------------------------------------------------------------

    /// Returns the raw opcode (without the FINAL bit).
    pub fn opcode(&self) -> u8 {
        self.opcode
    }

    /// Returns whether the FINAL bit is set.
    pub fn is_final(&self) -> bool {
        self.final_bit
    }

    /// Sets or clears the FINAL bit.
    pub fn set_final(&mut self, final_bit: bool) {
        self.final_bit = final_bit;
    }

    /// Returns the operation code with the FINAL bit masked out (`opcode & 0x7f`).
    ///
    /// In practice identical to [`opcode`](Self::opcode) because the opcode is
    /// stored without the FINAL bit, but provided for API parity with the C
    /// `g_obex_packet_get_operation` function.
    pub fn operation(&self) -> u8 {
        self.opcode & 0x7f
    }

    // -----------------------------------------------------------------------
    // Pre-header data region
    // -----------------------------------------------------------------------

    /// Set the pre-header data region (copy semantics).
    ///
    /// Used for CONNECT (4-byte ConnectData: version + flags + MTU) and SETPATH
    /// (2-byte SetpathData: flags + constants).  Replaces
    /// `g_obex_packet_set_data` with always-owned Rust `Vec<u8>`.
    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }

    /// Returns a reference to the pre-header data region.
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    // -----------------------------------------------------------------------
    // Header operations
    // -----------------------------------------------------------------------

    /// Append a header to the end of the header list.
    ///
    /// Matches C `g_obex_packet_add_header`.
    pub fn add_header(&mut self, header: ObexHeader) {
        self.hlen += header.encoded_len();
        self.headers.push(header);
    }

    /// Insert a header at the **front** of the header list.
    ///
    /// Matches C `g_obex_packet_prepend_header`.
    pub fn prepend_header(&mut self, header: ObexHeader) {
        self.hlen += header.encoded_len();
        self.headers.insert(0, header);
    }

    /// Find the first header with the given ID, or `None`.
    ///
    /// Matches C `g_obex_packet_get_header` which iterates the `GSList` and
    /// returns the first match.
    pub fn get_header(&self, id: u8) -> Option<&ObexHeader> {
        self.headers.iter().find(|h| h.id() == id)
    }

    /// Find the body header — checks `HDR_BODY` (0x48) first, then
    /// `HDR_BODY_END` (0x49).
    ///
    /// Matches the C `g_obex_packet_get_body` which checks BODY before
    /// BODY\_END.
    pub fn get_body(&self) -> Option<&ObexHeader> {
        self.get_header(HDR_BODY).or_else(|| self.get_header(HDR_BODY_END))
    }

    /// Returns a slice of all headers in insertion order.
    pub fn headers(&self) -> &[ObexHeader] {
        &self.headers
    }

    // -----------------------------------------------------------------------
    // Convenience header adders
    // -----------------------------------------------------------------------

    /// Add a Unicode (UTF-16BE on wire) header.
    ///
    /// Equivalent to `g_obex_packet_add_unicode(pkt, id, str)`.
    pub fn add_unicode(&mut self, id: u8, value: &str) {
        self.add_header(ObexHeader::new_unicode(id, value));
    }

    /// Add a byte-sequence header.
    ///
    /// Equivalent to `g_obex_packet_add_bytes(pkt, id, data, len)`.
    pub fn add_bytes(&mut self, id: u8, data: &[u8]) {
        self.add_header(ObexHeader::new_bytes(id, data));
    }

    /// Add a single-byte (U8) header.
    ///
    /// Equivalent to `g_obex_packet_add_uint8(pkt, id, val)`.
    pub fn add_uint8(&mut self, id: u8, value: u8) {
        self.add_header(ObexHeader::new_u8(id, value));
    }

    /// Add a 32-bit unsigned integer header.
    ///
    /// Equivalent to `g_obex_packet_add_uint32(pkt, id, val)`.
    pub fn add_uint32(&mut self, id: u8, value: u32) {
        self.add_header(ObexHeader::new_u32(id, value));
    }

    // -----------------------------------------------------------------------
    // Body producer
    // -----------------------------------------------------------------------

    /// Set the body data producer callback.
    ///
    /// The producer is invoked during [`encode`](Self::encode) to fill the
    /// remaining buffer space with body data.  It receives a mutable byte
    /// slice and returns the number of bytes written:
    ///
    /// - `Ok(n)` where `n > 0` → body data produced, encoded as `HDR_BODY`.
    /// - `Ok(0)` → end of body, encoded as `HDR_BODY_END`.  If the packet's
    ///   opcode is [`RSP_CONTINUE`], it is automatically switched to
    ///   [`RSP_SUCCESS`].
    ///
    /// Replaces `g_obex_packet_add_body(pkt, func, user_data)`.
    pub fn set_body_producer(&mut self, producer: BodyProducer) {
        self.body_producer = Some(producer);
    }

    // -----------------------------------------------------------------------
    // Encode  (from g_obex_packet_encode + get_body helper)
    // -----------------------------------------------------------------------

    /// Encode this packet into `buf` and return the total bytes written.
    ///
    /// Wire format produced:
    /// ```text
    /// [opcode | FINAL] [u16-BE length] [pre-header data] [headers…] [body?]
    /// ```
    ///
    /// # Side effect
    ///
    /// If a body producer is present and returns `Ok(0)` while the current
    /// opcode is [`RSP_CONTINUE`], the opcode is mutated in-place to
    /// [`RSP_SUCCESS`] (matching the C `g_obex_packet_encode` behaviour).
    ///
    /// # Errors
    ///
    /// Returns [`PacketError::BufferTooSmall`] when `buf` cannot hold the
    /// packet, or propagates any error from header encoding or the body
    /// producer.
    pub fn encode(&mut self, buf: &mut [u8]) -> Result<usize, PacketError> {
        // Minimum required: 3 (opcode + u16 length) + pre-header data + headers.
        let min_size = 3usize.saturating_add(self.data.len()).saturating_add(self.hlen);
        if min_size > buf.len() {
            return Err(PacketError::BufferTooSmall(format!(
                "need at least {min_size} bytes, have {}",
                buf.len()
            )));
        }

        // Byte 0 is written at the end (opcode may change during body producer).
        // Bytes 1-2 reserved for u16 BE packet length (also written at the end).

        // Write pre-header data starting at byte 3.
        if !self.data.is_empty() {
            buf[3..3 + self.data.len()].copy_from_slice(&self.data);
        }

        let mut count: usize = 3 + self.data.len();

        // Encode all headers sequentially (preserving insertion order).
        for header in &self.headers {
            let written = header.encode(&mut buf[count..])?;
            count += written;
        }

        // Body producer — fills remaining buffer space with body data wrapped
        // in an HDR_BODY or HDR_BODY_END header.
        if let Some(producer) = self.body_producer.as_mut() {
            let remaining = buf.len().saturating_sub(count);
            if remaining < 3 {
                return Err(PacketError::BufferTooSmall(
                    "no space for body header overhead".into(),
                ));
            }

            // Producer writes into the space *after* the 3-byte body header.
            let produced = producer(&mut buf[count + 3..count + remaining])?;

            // Choose header ID and handle end-of-body opcode switch.
            if produced > 0 {
                buf[count] = HDR_BODY;
            } else {
                buf[count] = HDR_BODY_END;
                // CRITICAL: when the body is complete and the current opcode is
                // RSP_CONTINUE, switch to RSP_SUCCESS (matching C behaviour in
                // g_obex_packet_encode).
                if self.opcode == RSP_CONTINUE {
                    self.opcode = RSP_SUCCESS;
                }
            }

            // Write the body header's u16 BE length (header_id + length + data).
            let body_header_total = produced + 3;
            let len_be = (body_header_total as u16).to_be_bytes();
            buf[count + 1] = len_be[0];
            buf[count + 2] = len_be[1];

            count += body_header_total;
        }

        // Guard against impossibly large packets.
        if count > u16::MAX as usize {
            return Err(PacketError::BufferTooSmall(
                "encoded packet exceeds maximum OBEX length (65535)".into(),
            ));
        }

        // Write final opcode byte (potentially updated by body producer) with
        // FINAL bit.
        buf[0] = self.opcode | if self.final_bit { PACKET_FINAL } else { 0 };

        // Write u16 BE packet length to bytes 1-2.
        let pkt_len_be = (count as u16).to_be_bytes();
        buf[1] = pkt_len_be[0];
        buf[2] = pkt_len_be[1];

        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Decode  (from g_obex_packet_decode + parse_headers)
    // -----------------------------------------------------------------------

    /// Decode an OBEX packet from `buf`.
    ///
    /// `header_offset` specifies the size of the pre-header data region:
    /// - **4** for CONNECT (ConnectData: version + flags + MTU)
    /// - **2** for SETPATH (SetpathData: flags + constants)
    /// - **0** for all other operations
    ///
    /// Returns `(packet, consumed_bytes)` on success.  `consumed_bytes` equals
    /// the `u16` packet-length field on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError::ParseError`] when the buffer is too short,
    /// incomplete, or contains malformed header data.
    pub fn decode(buf: &[u8], header_offset: usize) -> Result<(Self, usize), PacketError> {
        // 1. Validate minimum buffer length.
        let min_len = 3 + header_offset;
        if buf.len() < min_len {
            return Err(PacketError::ParseError(format!(
                "packet too short: need at least {min_len} bytes, have {}",
                buf.len()
            )));
        }

        // 2. Read opcode byte — extract base opcode and FINAL bit.
        let raw_opcode = buf[0];
        let opcode = raw_opcode & !PACKET_FINAL;
        let final_bit = (raw_opcode & PACKET_FINAL) != 0;

        // 3. Read u16 BE packet length from bytes 1-2.
        let packet_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;

        // 4. Validate packet length fits within buffer.
        if packet_len > buf.len() {
            return Err(PacketError::ParseError(format!(
                "incomplete packet: declared length {packet_len}, buffer has {} bytes",
                buf.len()
            )));
        }

        // 5. Ensure the packet is large enough for header_offset.
        if packet_len < min_len {
            return Err(PacketError::ParseError(format!(
                "packet length {packet_len} too small for header offset {header_offset}"
            )));
        }

        // 6. Build the packet.
        let mut pkt = Self::new(opcode);
        pkt.final_bit = final_bit;

        // 7. Copy pre-header data (e.g., ConnectData, SetpathData).
        if header_offset > 0 {
            pkt.data = buf[3..3 + header_offset].to_vec();
        }

        // 8. Parse headers from the remaining bytes within the declared length.
        let header_start = 3 + header_offset;
        let mut offset = header_start;
        while offset < packet_len {
            let remaining = &buf[offset..packet_len];
            if remaining.is_empty() {
                break;
            }
            match ObexHeader::decode(remaining) {
                Ok((header, consumed)) => {
                    if consumed == 0 {
                        // Safety: prevent infinite loop on zero-length decode.
                        break;
                    }
                    pkt.hlen += consumed;
                    pkt.headers.push(header);
                    offset += consumed;
                }
                Err(_) => {
                    // Stop parsing on header decode error — matches C
                    // `parse_headers` which breaks on NULL header return.
                    break;
                }
            }
        }

        Ok((pkt, packet_len))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Constant verification --

    #[test]
    fn opcode_constants_match_c() {
        assert_eq!(OP_CONNECT, 0x00);
        assert_eq!(OP_DISCONNECT, 0x01);
        assert_eq!(OP_PUT, 0x02);
        assert_eq!(OP_GET, 0x03);
        assert_eq!(OP_SETPATH, 0x05);
        assert_eq!(OP_ACTION, 0x06);
        assert_eq!(OP_SESSION, 0x07);
        assert_eq!(OP_ABORT, 0x7f);
        assert_eq!(PACKET_FINAL, 0x80);
    }

    #[test]
    fn response_constants_match_c() {
        assert_eq!(RSP_CONTINUE, 0x10);
        assert_eq!(RSP_SUCCESS, 0x20);
        assert_eq!(RSP_CREATED, 0x21);
        assert_eq!(RSP_ACCEPTED, 0x22);
        assert_eq!(RSP_NON_AUTHORITATIVE, 0x23);
        assert_eq!(RSP_NO_CONTENT, 0x24);
        assert_eq!(RSP_RESET_CONTENT, 0x25);
        assert_eq!(RSP_PARTIAL_CONTENT, 0x26);
        assert_eq!(RSP_MULTIPLE_CHOICES, 0x30);
        assert_eq!(RSP_MOVED_PERMANENTLY, 0x31);
        assert_eq!(RSP_MOVED_TEMPORARILY, 0x32);
        assert_eq!(RSP_SEE_OTHER, 0x33);
        assert_eq!(RSP_NOT_MODIFIED, 0x34);
        assert_eq!(RSP_USE_PROXY, 0x35);
        assert_eq!(RSP_BAD_REQUEST, 0x40);
        assert_eq!(RSP_UNAUTHORIZED, 0x41);
        assert_eq!(RSP_PAYMENT_REQUIRED, 0x42);
        assert_eq!(RSP_FORBIDDEN, 0x43);
        assert_eq!(RSP_NOT_FOUND, 0x44);
        assert_eq!(RSP_METHOD_NOT_ALLOWED, 0x45);
        assert_eq!(RSP_NOT_ACCEPTABLE, 0x46);
        assert_eq!(RSP_PROXY_AUTH_REQUIRED, 0x47);
        assert_eq!(RSP_REQUEST_TIME_OUT, 0x48);
        assert_eq!(RSP_CONFLICT, 0x49);
        assert_eq!(RSP_GONE, 0x4a);
        assert_eq!(RSP_LENGTH_REQUIRED, 0x4b);
        assert_eq!(RSP_PRECONDITION_FAILED, 0x4c);
        assert_eq!(RSP_REQ_ENTITY_TOO_LARGE, 0x4d);
        assert_eq!(RSP_REQ_URL_TOO_LARGE, 0x4e);
        assert_eq!(RSP_UNSUPPORTED_MEDIA_TYPE, 0x4f);
        assert_eq!(RSP_INTERNAL_SERVER_ERROR, 0x50);
        assert_eq!(RSP_NOT_IMPLEMENTED, 0x51);
        assert_eq!(RSP_BAD_GATEWAY, 0x52);
        assert_eq!(RSP_SERVICE_UNAVAILABLE, 0x53);
        assert_eq!(RSP_GATEWAY_TIMEOUT, 0x54);
        assert_eq!(RSP_HTTP_VERSION_NOT_SUPPORTED, 0x55);
        assert_eq!(RSP_DATABASE_FULL, 0x60);
        assert_eq!(RSP_DATABASE_LOCKED, 0x61);
    }

    // -- Constructor / accessor tests --

    #[test]
    fn new_packet_defaults() {
        let pkt = ObexPacket::new(OP_GET);
        assert_eq!(pkt.opcode(), OP_GET);
        assert!(pkt.is_final());
        assert!(pkt.get_data().is_empty());
        assert!(pkt.headers().is_empty());
        assert_eq!(pkt.operation(), OP_GET & 0x7f);
    }

    #[test]
    fn new_response_defaults() {
        let pkt = ObexPacket::new_response(RSP_SUCCESS);
        assert_eq!(pkt.opcode(), RSP_SUCCESS);
        assert!(pkt.is_final());
    }

    #[test]
    fn set_final_flag() {
        let mut pkt = ObexPacket::new(OP_PUT);
        assert!(pkt.is_final());
        pkt.set_final(false);
        assert!(!pkt.is_final());
        pkt.set_final(true);
        assert!(pkt.is_final());
    }

    #[test]
    fn data_region() {
        let mut pkt = ObexPacket::new(OP_CONNECT);
        assert!(pkt.get_data().is_empty());
        pkt.set_data(&[0x10, 0x00, 0x10, 0x00]);
        assert_eq!(pkt.get_data(), &[0x10, 0x00, 0x10, 0x00]);
    }

    // -- Header operation tests --

    #[test]
    fn add_and_get_header() {
        let mut pkt = ObexPacket::new(OP_PUT);
        pkt.add_uint32(super::super::header::HDR_CONNECTION, 1);
        pkt.add_unicode(super::super::header::HDR_NAME, "test.txt");
        assert_eq!(pkt.headers().len(), 2);
        assert!(pkt.get_header(super::super::header::HDR_CONNECTION).is_some());
        assert!(pkt.get_header(super::super::header::HDR_NAME).is_some());
        assert!(pkt.get_header(0xFF).is_none());
    }

    #[test]
    fn prepend_header() {
        let mut pkt = ObexPacket::new(OP_PUT);
        pkt.add_uint8(super::super::header::HDR_SRM, 0x01);
        pkt.prepend_header(ObexHeader::new_u32(super::super::header::HDR_CONNECTION, 5));
        assert_eq!(pkt.headers()[0].id(), super::super::header::HDR_CONNECTION);
        assert_eq!(pkt.headers()[1].id(), super::super::header::HDR_SRM);
    }

    #[test]
    fn get_body_checks_body_then_body_end() {
        let mut pkt = ObexPacket::new(OP_PUT);
        // No body headers yet.
        assert!(pkt.get_body().is_none());

        // Add HDR_BODY_END only.
        pkt.add_bytes(HDR_BODY_END, b"end");
        assert_eq!(pkt.get_body().unwrap().id(), HDR_BODY_END);

        // Now also add HDR_BODY — it should be returned first.
        pkt.add_bytes(HDR_BODY, b"body");
        assert_eq!(pkt.get_body().unwrap().id(), HDR_BODY);
    }

    // -- Encode / decode round-trip tests --

    #[test]
    fn encode_minimal_packet() {
        let mut pkt = ObexPacket::new(OP_DISCONNECT);
        let mut buf = [0u8; 64];
        let len = pkt.encode(&mut buf).unwrap();

        // Minimal: opcode|FINAL (1) + length (2) = 3 bytes.
        assert_eq!(len, 3);
        assert_eq!(buf[0], OP_DISCONNECT | PACKET_FINAL);
        assert_eq!(u16::from_be_bytes([buf[1], buf[2]]), 3);
    }

    #[test]
    fn encode_with_data_region() {
        let mut pkt = ObexPacket::new(OP_CONNECT);
        pkt.set_data(&[0x10, 0x00, 0xFF, 0xFE]); // ConnectData
        let mut buf = [0u8; 64];
        let len = pkt.encode(&mut buf).unwrap();

        assert_eq!(len, 7); // 3 + 4 data bytes
        assert_eq!(buf[0], OP_CONNECT | PACKET_FINAL);
        assert_eq!(u16::from_be_bytes([buf[1], buf[2]]), 7);
        assert_eq!(&buf[3..7], &[0x10, 0x00, 0xFF, 0xFE]);
    }

    #[test]
    fn encode_with_u8_header() {
        let mut pkt = ObexPacket::new(OP_GET);
        pkt.add_uint8(super::super::header::HDR_SRM, 0x01);
        let mut buf = [0u8; 64];
        let len = pkt.encode(&mut buf).unwrap();

        // 3 (overhead) + 2 (U8 header) = 5.
        assert_eq!(len, 5);
        assert_eq!(buf[3], super::super::header::HDR_SRM);
        assert_eq!(buf[4], 0x01);
    }

    #[test]
    fn encode_buffer_too_small() {
        let mut pkt = ObexPacket::new(OP_GET);
        pkt.add_uint32(super::super::header::HDR_CONNECTION, 42);
        let mut buf = [0u8; 4]; // too small for 3 + 5 = 8 bytes
        let result = pkt.encode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_minimal_packet() {
        // Hand-craft a 3-byte DISCONNECT|FINAL packet.
        let buf = [OP_DISCONNECT | PACKET_FINAL, 0x00, 0x03];
        let (pkt, consumed) = ObexPacket::decode(&buf, 0).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(pkt.opcode(), OP_DISCONNECT);
        assert!(pkt.is_final());
        assert!(pkt.headers().is_empty());
        assert!(pkt.get_data().is_empty());
    }

    #[test]
    fn decode_with_data_region() {
        // CONNECT|FINAL, length=7, 4 bytes ConnectData.
        let buf = [OP_CONNECT | PACKET_FINAL, 0x00, 0x07, 0x10, 0x00, 0xFF, 0xFE];
        let (pkt, consumed) = ObexPacket::decode(&buf, 4).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(pkt.opcode(), OP_CONNECT);
        assert!(pkt.is_final());
        assert_eq!(pkt.get_data(), &[0x10, 0x00, 0xFF, 0xFE]);
    }

    #[test]
    fn decode_too_short() {
        let buf = [0x80, 0x00]; // only 2 bytes
        assert!(ObexPacket::decode(&buf, 0).is_err());
    }

    #[test]
    fn decode_incomplete_packet() {
        // Packet declares length=10 but buffer only has 5 bytes.
        let buf = [0x80, 0x00, 0x0A, 0x00, 0x00];
        assert!(ObexPacket::decode(&buf, 0).is_err());
    }

    #[test]
    fn encode_decode_round_trip() {
        let mut pkt = ObexPacket::new(OP_PUT);
        pkt.set_data(&[0xAA, 0xBB]);
        pkt.add_uint32(super::super::header::HDR_CONNECTION, 7);
        pkt.add_uint8(super::super::header::HDR_SRM, 0x01);

        let mut buf = [0u8; 128];
        let len = pkt.encode(&mut buf).unwrap();

        let (decoded, consumed) = ObexPacket::decode(&buf[..len], 2).unwrap();
        assert_eq!(consumed, len);
        assert_eq!(decoded.opcode(), OP_PUT);
        assert!(decoded.is_final());
        assert_eq!(decoded.get_data(), &[0xAA, 0xBB]);
        assert_eq!(decoded.headers().len(), 2);
        assert_eq!(
            decoded.get_header(super::super::header::HDR_CONNECTION).unwrap().as_u32(),
            Some(7)
        );
        assert_eq!(decoded.get_header(super::super::header::HDR_SRM).unwrap().as_u8(), Some(0x01));
    }

    #[test]
    fn encode_without_final_bit() {
        let mut pkt = ObexPacket::new(OP_PUT);
        pkt.set_final(false);
        let mut buf = [0u8; 64];
        let len = pkt.encode(&mut buf).unwrap();
        assert_eq!(len, 3);
        // Opcode byte should NOT have FINAL bit set.
        assert_eq!(buf[0], OP_PUT);
    }

    #[test]
    fn decode_without_final_bit() {
        let buf = [OP_GET, 0x00, 0x03]; // no FINAL bit
        let (pkt, _) = ObexPacket::decode(&buf, 0).unwrap();
        assert_eq!(pkt.opcode(), OP_GET);
        assert!(!pkt.is_final());
    }

    #[test]
    fn body_producer_with_data() {
        let mut pkt = ObexPacket::new_response(RSP_CONTINUE);
        pkt.set_body_producer(Box::new(|buf: &mut [u8]| {
            let data = b"Hello";
            buf[..data.len()].copy_from_slice(data);
            Ok(data.len())
        }));
        let mut buf = [0u8; 128];
        let len = pkt.encode(&mut buf).unwrap();

        // opcode should remain RSP_CONTINUE (producer returned >0).
        assert_eq!(pkt.opcode(), RSP_CONTINUE);
        // buf[0] should be RSP_CONTINUE | FINAL
        assert_eq!(buf[0], RSP_CONTINUE | PACKET_FINAL);

        // Verify body header at offset 3: HDR_BODY, u16 length, data
        assert_eq!(buf[3], HDR_BODY);
        let body_hdr_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        assert_eq!(body_hdr_len, 5 + 3); // "Hello" + 3
        assert_eq!(&buf[6..6 + 5], b"Hello");
        assert_eq!(len, 3 + body_hdr_len);
    }

    #[test]
    fn body_producer_end_of_body_switches_continue_to_success() {
        let mut pkt = ObexPacket::new_response(RSP_CONTINUE);
        pkt.set_body_producer(Box::new(|_buf: &mut [u8]| {
            Ok(0) // no more data → end of body
        }));
        let mut buf = [0u8; 128];
        let len = pkt.encode(&mut buf).unwrap();

        // Opcode should have switched to RSP_SUCCESS.
        assert_eq!(pkt.opcode(), RSP_SUCCESS);
        assert_eq!(buf[0], RSP_SUCCESS | PACKET_FINAL);

        // Body header should be HDR_BODY_END with length 3 (empty body).
        assert_eq!(buf[3], HDR_BODY_END);
        let body_hdr_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        assert_eq!(body_hdr_len, 3);
        assert_eq!(len, 3 + 3);
    }

    #[test]
    fn body_producer_end_no_switch_for_non_continue() {
        let mut pkt = ObexPacket::new_response(RSP_NOT_FOUND);
        pkt.set_body_producer(Box::new(|_buf: &mut [u8]| Ok(0)));
        let mut buf = [0u8; 128];
        let _ = pkt.encode(&mut buf).unwrap();
        // Opcode should remain RSP_NOT_FOUND — switch only applies to RSP_CONTINUE.
        assert_eq!(pkt.opcode(), RSP_NOT_FOUND);
    }

    #[test]
    fn debug_impl() {
        let pkt = ObexPacket::new(OP_GET);
        let dbg = format!("{pkt:?}");
        assert!(dbg.contains("ObexPacket"));
        assert!(dbg.contains("opcode"));
    }

    #[test]
    fn packet_error_display() {
        let e = PacketError::ParseError("bad data".into());
        assert!(e.to_string().contains("bad data"));
        let e = PacketError::BufferTooSmall("too small".into());
        assert!(e.to_string().contains("too small"));
    }
}
