// SPDX-License-Identifier: GPL-2.0-or-later
//! OBEX protocol implementation — replaces gobex/ C library.
//!
//! Implements OBEX packet encoding/decoding, header types, opcodes, and
//! response codes per the IrDA OBEX specification.

/// OBEX operation opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObexOpcode {
    Connect = 0x80,
    Disconnect = 0x81,
    Put = 0x02,
    Get = 0x03,
    SetPath = 0x85,
    Action = 0x06,
    Session = 0x87,
    Abort = 0xFF,
}

impl ObexOpcode {
    /// Parse an opcode byte (ignoring the final bit).
    pub fn from_byte(byte: u8) -> Option<Self> {
        // The final bit is 0x80 on some opcodes; mask it for matching
        let masked = byte & 0x7F;
        match byte {
            0x80 => Some(Self::Connect),
            0x81 => Some(Self::Disconnect),
            0x85 => Some(Self::SetPath),
            0x87 => Some(Self::Session),
            0xFF => Some(Self::Abort),
            _ => match masked {
                0x02 => Some(Self::Put),
                0x03 => Some(Self::Get),
                0x06 => Some(Self::Action),
                _ => None,
            },
        }
    }
}

/// OBEX response codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObexResponseCode {
    Continue = 0x10,
    Success = 0x20,
    Created = 0x21,
    BadRequest = 0x40,
    Unauthorized = 0x41,
    Forbidden = 0x43,
    NotFound = 0x44,
    NotAcceptable = 0x46,
    Conflict = 0x49,
    InternalServerError = 0x50,
    NotImplemented = 0x51,
    ServiceUnavailable = 0x53,
}

impl ObexResponseCode {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x10 => Some(Self::Continue),
            0x20 => Some(Self::Success),
            0x21 => Some(Self::Created),
            0x40 => Some(Self::BadRequest),
            0x41 => Some(Self::Unauthorized),
            0x43 => Some(Self::Forbidden),
            0x44 => Some(Self::NotFound),
            0x46 => Some(Self::NotAcceptable),
            0x49 => Some(Self::Conflict),
            0x50 => Some(Self::InternalServerError),
            0x51 => Some(Self::NotImplemented),
            0x53 => Some(Self::ServiceUnavailable),
            _ => None,
        }
    }
}

/// OBEX header identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderId {
    Count = 0xC0,
    Name = 0x01,
    Type = 0x42,
    Length = 0xC3,
    TimeIso = 0x44,
    Time4Byte = 0xC4,
    Description = 0x05,
    Target = 0x46,
    Http = 0x47,
    Body = 0x48,
    EndOfBody = 0x49,
    Who = 0x4A,
    ConnectionId = 0xCB,
    AppParameters = 0x4C,
    AuthChallenge = 0x4D,
    AuthResponse = 0x4E,
    ObjectClass = 0x4F,
    SingleResponseMode = 0x97,
    SingleResponseModeParameter = 0x98,
    ActionId = 0x94,
    DestName = 0x15,
    Permissions = 0xD6,
    SessionParameters = 0x52,
    SessionSequenceNumber = 0x93,
}

impl HeaderId {
    /// Returns the encoding type based on the two high bits of the header ID.
    /// 0b00 = Unicode text (2-byte length prefix)
    /// 0b01 = Byte sequence (2-byte length prefix)
    /// 0b10 = 1-byte value
    /// 0b11 = 4-byte value
    pub fn encoding_type(self) -> HeaderEncoding {
        match (self as u8) >> 6 {
            0b00 => HeaderEncoding::Unicode,
            0b01 => HeaderEncoding::ByteSeq,
            0b10 => HeaderEncoding::Byte1,
            0b11 => HeaderEncoding::Byte4,
            _ => unreachable!(),
        }
    }
}

/// Header data encoding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderEncoding {
    /// Null-terminated Unicode text, with 2-byte length prefix.
    Unicode,
    /// Byte sequence, with 2-byte length prefix.
    ByteSeq,
    /// Single-byte value.
    Byte1,
    /// 4-byte value.
    Byte4,
}

/// An OBEX header with its ID and data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObexHeader {
    pub id: HeaderId,
    pub data: Vec<u8>,
}

impl ObexHeader {
    pub fn new(id: HeaderId, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    /// Encode this header into bytes appended to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.id as u8);
        match self.id.encoding_type() {
            HeaderEncoding::Unicode | HeaderEncoding::ByteSeq => {
                let len = 3u16 + self.data.len() as u16;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&self.data);
            }
            HeaderEncoding::Byte1 => {
                if let Some(&b) = self.data.first() {
                    buf.push(b);
                } else {
                    buf.push(0);
                }
            }
            HeaderEncoding::Byte4 => {
                let mut val = [0u8; 4];
                let copy_len = self.data.len().min(4);
                val[4 - copy_len..].copy_from_slice(&self.data[..copy_len]);
                buf.extend_from_slice(&val);
            }
        }
    }

    /// Decode one header from the byte slice, returning the header and bytes consumed.
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }

        let id_byte = data[0];
        let encoding = match id_byte >> 6 {
            0b00 => HeaderEncoding::Unicode,
            0b01 => HeaderEncoding::ByteSeq,
            0b10 => HeaderEncoding::Byte1,
            0b11 => HeaderEncoding::Byte4,
            _ => return None,
        };

        match encoding {
            HeaderEncoding::Unicode | HeaderEncoding::ByteSeq => {
                if data.len() < 3 {
                    return None;
                }
                let len = u16::from_be_bytes([data[1], data[2]]) as usize;
                if data.len() < len || len < 3 {
                    return None;
                }
                let header_data = data[3..len].to_vec();
                // We store the raw id byte — callers can try to interpret it
                Some((
                    ObexHeader {
                        id: raw_header_id(id_byte)?,
                        data: header_data,
                    },
                    len,
                ))
            }
            HeaderEncoding::Byte1 => {
                if data.len() < 2 {
                    return None;
                }
                Some((
                    ObexHeader {
                        id: raw_header_id(id_byte)?,
                        data: vec![data[1]],
                    },
                    2,
                ))
            }
            HeaderEncoding::Byte4 => {
                if data.len() < 5 {
                    return None;
                }
                Some((
                    ObexHeader {
                        id: raw_header_id(id_byte)?,
                        data: data[1..5].to_vec(),
                    },
                    5,
                ))
            }
        }
    }
}

/// Try to convert a raw byte to a known HeaderId.
fn raw_header_id(byte: u8) -> Option<HeaderId> {
    match byte {
        0xC0 => Some(HeaderId::Count),
        0x01 => Some(HeaderId::Name),
        0x42 => Some(HeaderId::Type),
        0xC3 => Some(HeaderId::Length),
        0x44 => Some(HeaderId::TimeIso),
        0xC4 => Some(HeaderId::Time4Byte),
        0x05 => Some(HeaderId::Description),
        0x46 => Some(HeaderId::Target),
        0x47 => Some(HeaderId::Http),
        0x48 => Some(HeaderId::Body),
        0x49 => Some(HeaderId::EndOfBody),
        0x4A => Some(HeaderId::Who),
        0xCB => Some(HeaderId::ConnectionId),
        0x4C => Some(HeaderId::AppParameters),
        0x4D => Some(HeaderId::AuthChallenge),
        0x4E => Some(HeaderId::AuthResponse),
        0x4F => Some(HeaderId::ObjectClass),
        0x97 => Some(HeaderId::SingleResponseMode),
        0x98 => Some(HeaderId::SingleResponseModeParameter),
        0x94 => Some(HeaderId::ActionId),
        0x15 => Some(HeaderId::DestName),
        0xD6 => Some(HeaderId::Permissions),
        0x52 => Some(HeaderId::SessionParameters),
        0x93 => Some(HeaderId::SessionSequenceNumber),
        _ => None,
    }
}

/// An OBEX packet consisting of an opcode, final bit, and headers.
#[derive(Debug, Clone, PartialEq)]
pub struct ObexPacket {
    pub opcode: u8,
    pub final_bit: bool,
    pub headers: Vec<ObexHeader>,
}

impl ObexPacket {
    pub fn new(opcode: ObexOpcode, final_bit: bool) -> Self {
        Self {
            opcode: opcode as u8,
            final_bit,
            headers: Vec::new(),
        }
    }

    pub fn add_header(&mut self, header: ObexHeader) {
        self.headers.push(header);
    }

    /// Encode the packet into a byte vector.
    /// Format: opcode(1) | length(2) | headers...
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let opcode = if self.final_bit {
            self.opcode | 0x80
        } else {
            self.opcode & 0x7F
        };
        buf.push(opcode);
        // Reserve space for length (filled in later)
        buf.push(0);
        buf.push(0);

        for header in &self.headers {
            header.encode(&mut buf);
        }

        let len = buf.len() as u16;
        buf[1..3].copy_from_slice(&len.to_be_bytes());
        buf
    }

    /// Decode a packet from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }

        let opcode_byte = data[0];
        let final_bit = (opcode_byte & 0x80) != 0;
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;

        if data.len() < len {
            return None;
        }

        let mut headers = Vec::new();
        let mut offset = 3;
        while offset < len {
            match ObexHeader::decode(&data[offset..len]) {
                Some((header, consumed)) => {
                    headers.push(header);
                    offset += consumed;
                }
                None => break,
            }
        }

        Some(Self {
            opcode: opcode_byte,
            final_bit,
            headers,
        })
    }
}

/// Errors that can occur during OBEX session operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObexError {
    /// I/O error (transport-level).
    IoError(String),
    /// Received data does not form a valid OBEX packet.
    InvalidPacket,
    /// An OBEX header could not be decoded.
    InvalidHeader,
    /// The session has been disconnected.
    Disconnected,
    /// Operation timed out.
    Timeout,
}

impl std::fmt::Display for ObexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
            Self::InvalidPacket => write!(f, "invalid OBEX packet"),
            Self::InvalidHeader => write!(f, "invalid OBEX header"),
            Self::Disconnected => write!(f, "session disconnected"),
            Self::Timeout => write!(f, "operation timed out"),
        }
    }
}

impl std::error::Error for ObexError {}

/// An OBEX session managing state for a single connection.
pub struct ObexSession {
    /// Maximum packet size negotiated during connect.
    pub max_packet_size: u16,
    /// Connection ID if established.
    pub connection_id: Option<u32>,
    /// Whether the session is connected.
    pub connected: bool,
    /// Internal transport buffer for receiving data.
    rx_buf: Vec<u8>,
    /// Internal transport buffer holding data to be sent.
    tx_buf: Vec<u8>,
}

impl ObexSession {
    pub fn new() -> Self {
        Self {
            max_packet_size: 4096,
            connection_id: None,
            connected: false,
            rx_buf: Vec::new(),
            tx_buf: Vec::new(),
        }
    }

    /// Initiate a connect request (stub).
    pub fn connect(&mut self) -> ObexPacket {
        self.connected = true;
        ObexPacket::new(ObexOpcode::Connect, true)
    }

    /// Create a disconnect packet (stub).
    pub fn disconnect(&mut self) -> ObexPacket {
        self.connected = false;
        self.connection_id = None;
        ObexPacket::new(ObexOpcode::Disconnect, true)
    }

    /// Send a packet (stub — returns encoded bytes).
    pub fn send(&self, packet: &ObexPacket) -> Vec<u8> {
        packet.encode()
    }

    /// Receive and decode a packet from bytes (stub).
    pub fn receive(&self, data: &[u8]) -> Option<ObexPacket> {
        ObexPacket::decode(data)
    }

    /// Serialize a packet and write it to the transport buffer.
    ///
    /// The encoded packet is validated (minimum 3 bytes, length field matches)
    /// and appended to the internal transmit buffer.
    pub fn send_packet(&mut self, packet: &ObexPacket) -> Result<(), ObexError> {
        if !self.connected {
            return Err(ObexError::Disconnected);
        }

        let encoded = packet.encode();
        if encoded.len() < 3 {
            return Err(ObexError::InvalidPacket);
        }

        let declared_len = u16::from_be_bytes([encoded[1], encoded[2]]) as usize;
        if declared_len != encoded.len() {
            return Err(ObexError::InvalidPacket);
        }

        if encoded.len() > self.max_packet_size as usize {
            return Err(ObexError::InvalidPacket);
        }

        self.tx_buf.extend_from_slice(&encoded);
        Ok(())
    }

    /// Read a complete OBEX packet from the receive buffer.
    ///
    /// Callers should first push incoming transport data via [`push_rx_data`].
    /// The method validates the 3-byte header (opcode + 2-byte length), ensures
    /// the buffer holds enough bytes, then parses and returns the packet.
    pub fn receive_packet(&mut self) -> Result<ObexPacket, ObexError> {
        if !self.connected {
            return Err(ObexError::Disconnected);
        }

        if self.rx_buf.len() < 3 {
            return Err(ObexError::InvalidPacket);
        }

        let declared_len =
            u16::from_be_bytes([self.rx_buf[1], self.rx_buf[2]]) as usize;

        if declared_len < 3 {
            // Corrupt length — discard these bytes.
            self.rx_buf.drain(..3.min(self.rx_buf.len()));
            return Err(ObexError::InvalidPacket);
        }

        if self.rx_buf.len() < declared_len {
            // Not enough data yet.
            return Err(ObexError::InvalidPacket);
        }

        let pkt_data: Vec<u8> = self.rx_buf.drain(..declared_len).collect();
        ObexPacket::decode(&pkt_data).ok_or(ObexError::InvalidHeader)
    }

    /// Append raw bytes received from the transport to the receive buffer.
    pub fn push_rx_data(&mut self, data: &[u8]) {
        self.rx_buf.extend_from_slice(data);
    }

    /// Drain the transmit buffer, returning all pending bytes.
    pub fn take_tx_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.tx_buf)
    }

    /// Handle a multi-packet (Continue) response sequence.
    ///
    /// Collects body data across multiple Continue responses until a final
    /// response is received. Returns the combined body and the final response code byte.
    pub fn collect_continue_responses(&mut self) -> Result<(Vec<u8>, u8), ObexError> {
        if !self.connected {
            return Err(ObexError::Disconnected);
        }

        let mut body = Vec::new();

        loop {
            let pkt = self.receive_packet()?;

            // Collect Body / EndOfBody header data.
            for hdr in &pkt.headers {
                if hdr.id == HeaderId::Body || hdr.id == HeaderId::EndOfBody {
                    body.extend_from_slice(&hdr.data);
                }
            }

            let response_code = pkt.opcode & 0x7F;

            // Continue (0x10 masked to 0x10) — keep going.
            if response_code == ObexResponseCode::Continue as u8 {
                continue;
            }

            // Any other response code is the final response.
            return Ok((body, pkt.opcode));
        }
    }
}

impl Default for ObexSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Opcode parsing (from test-gobex.c) ----

    #[test]
    fn opcode_from_byte() {
        assert_eq!(ObexOpcode::from_byte(0x80), Some(ObexOpcode::Connect));
        assert_eq!(ObexOpcode::from_byte(0x81), Some(ObexOpcode::Disconnect));
        assert_eq!(ObexOpcode::from_byte(0x02), Some(ObexOpcode::Put));
        assert_eq!(ObexOpcode::from_byte(0x82), Some(ObexOpcode::Put));
        assert_eq!(ObexOpcode::from_byte(0xFF), Some(ObexOpcode::Abort));
        assert_eq!(ObexOpcode::from_byte(0x10), None);
    }

    #[test]
    fn opcode_get_with_final() {
        assert_eq!(ObexOpcode::from_byte(0x03), Some(ObexOpcode::Get));
        assert_eq!(ObexOpcode::from_byte(0x83), Some(ObexOpcode::Get));
    }

    #[test]
    fn opcode_setpath() {
        assert_eq!(ObexOpcode::from_byte(0x85), Some(ObexOpcode::SetPath));
    }

    #[test]
    fn opcode_action() {
        assert_eq!(ObexOpcode::from_byte(0x06), Some(ObexOpcode::Action));
    }

    // ---- Response code parsing (from test-gobex.c) ----

    #[test]
    fn response_code_round_trip() {
        assert_eq!(
            ObexResponseCode::from_byte(0x20),
            Some(ObexResponseCode::Success)
        );
        assert_eq!(
            ObexResponseCode::from_byte(0x44),
            Some(ObexResponseCode::NotFound)
        );
        assert_eq!(ObexResponseCode::from_byte(0x99), None);
    }

    #[test]
    fn response_code_continue() {
        assert_eq!(
            ObexResponseCode::from_byte(0x10),
            Some(ObexResponseCode::Continue)
        );
    }

    #[test]
    fn response_code_unauthorized() {
        assert_eq!(
            ObexResponseCode::from_byte(0x41),
            Some(ObexResponseCode::Unauthorized)
        );
    }

    // ---- Header encoding type (from test-gobex-header.c) ----

    #[test]
    fn header_encoding_types() {
        // Name (0x01) -> Unicode (high bits 0b00)
        assert_eq!(HeaderId::Name.encoding_type(), HeaderEncoding::Unicode);
        // Body (0x48) -> ByteSeq (high bits 0b01)
        assert_eq!(HeaderId::Body.encoding_type(), HeaderEncoding::ByteSeq);
        // ActionId (0x94) -> Byte1 (high bits 0b10)
        assert_eq!(HeaderId::ActionId.encoding_type(), HeaderEncoding::Byte1);
        // ConnectionId (0xCB) -> Byte4 (high bits 0b11)
        assert_eq!(
            HeaderId::ConnectionId.encoding_type(),
            HeaderEncoding::Byte4
        );
        // Count (0xC0) -> Byte4
        assert_eq!(HeaderId::Count.encoding_type(), HeaderEncoding::Byte4);
        // Length (0xC3) -> Byte4
        assert_eq!(HeaderId::Length.encoding_type(), HeaderEncoding::Byte4);
    }

    // ---- Header encode ConnectionId (from test-gobex-header.c: hdr_connid) ----

    #[test]
    fn header_encode_connection_id() {
        // C test: hdr_connid = { G_OBEX_HDR_CONNECTION, 1, 2, 3, 4 }
        let header = ObexHeader::new(HeaderId::ConnectionId, vec![0x01, 0x02, 0x03, 0x04]);
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf, vec![0xCB, 0x01, 0x02, 0x03, 0x04]);
    }

    // ---- Header decode ConnectionId ----

    #[test]
    fn header_decode_connection_id() {
        let data = [0xCB, 0x01, 0x02, 0x03, 0x04];
        let (header, consumed) = ObexHeader::decode(&data).unwrap();
        assert_eq!(header.id, HeaderId::ConnectionId);
        assert_eq!(header.data, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(consumed, 5);
    }

    // ---- Header encode Body (from test-gobex-header.c: hdr_body) ----

    #[test]
    fn header_encode_body() {
        // C test: hdr_body = { G_OBEX_HDR_BODY, 0x00, 0x07, 1, 2, 3, 4 }
        let header = ObexHeader::new(HeaderId::Body, vec![1, 2, 3, 4]);
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf, vec![0x48, 0x00, 0x07, 1, 2, 3, 4]);
    }

    // ---- Header decode Body ----

    #[test]
    fn header_decode_body() {
        let data = [0x48, 0x00, 0x07, 1, 2, 3, 4];
        let (header, consumed) = ObexHeader::decode(&data).unwrap();
        assert_eq!(header.id, HeaderId::Body);
        assert_eq!(header.data, vec![1, 2, 3, 4]);
        assert_eq!(consumed, 7);
    }

    // ---- Header encode ActionId byte (from test-gobex-header.c: hdr_actionid) ----

    #[test]
    fn header_encode_action_id() {
        // C test: hdr_actionid = { G_OBEX_HDR_ACTION, 0xab }
        let header = ObexHeader::new(HeaderId::ActionId, vec![0xab]);
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf, vec![0x94, 0xab]);
    }

    // ---- Header decode ActionId ----

    #[test]
    fn header_decode_action_id() {
        let data = [0x94, 0xab];
        let (header, consumed) = ObexHeader::decode(&data).unwrap();
        assert_eq!(header.id, HeaderId::ActionId);
        assert_eq!(header.data, vec![0xab]);
        assert_eq!(consumed, 2);
    }

    // ---- Header encode Name (from test-gobex-header.c: hdr_name_empty) ----

    #[test]
    fn header_encode_name_empty() {
        // C test: hdr_name_empty = { G_OBEX_HDR_NAME, 0x00, 0x03 }
        let header = ObexHeader::new(HeaderId::Name, vec![]);
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf, vec![0x01, 0x00, 0x03]);
    }

    // ---- Header decode invalid: too short for uint32 ----

    #[test]
    fn header_decode_uint32_too_short() {
        // C test: hdr_uint32_nval = { G_OBEX_HDR_CONNECTION, 1, 2 } (only 3 bytes, need 5)
        let data = [0xCB, 0x01, 0x02];
        assert!(ObexHeader::decode(&data).is_none());
    }

    // ---- Header decode invalid: byte sequence with bad length ----

    #[test]
    fn header_decode_bytes_nval_len() {
        // C test: hdr_bytes_nval_len = { G_OBEX_HDR_BODY, 0x00, 0x00 }
        // Length 0 is < 3 minimum
        let data = [0x48, 0x00, 0x00];
        assert!(ObexHeader::decode(&data).is_none());
    }

    // ---- Packet encode/decode round-trip (from test-gobex.c) ----

    #[test]
    fn packet_encode_decode_round_trip() {
        let mut pkt = ObexPacket::new(ObexOpcode::Put, true);
        pkt.add_header(ObexHeader::new(HeaderId::Name, b"hello".to_vec()));
        pkt.add_header(ObexHeader::new(
            HeaderId::SingleResponseMode,
            vec![0x01],
        ));

        let encoded = pkt.encode();
        let decoded = ObexPacket::decode(&encoded).expect("decode failed");

        assert!(decoded.final_bit);
        assert_eq!(decoded.headers.len(), 2);
        assert_eq!(decoded.headers[0].id, HeaderId::Name);
        assert_eq!(decoded.headers[0].data, b"hello");
        assert_eq!(decoded.headers[1].id, HeaderId::SingleResponseMode);
        assert_eq!(decoded.headers[1].data, vec![0x01]);
    }

    // ---- Connect request packet (from test-gobex.c: pkt_connect_req) ----

    #[test]
    fn packet_connect_request_structure() {
        let pkt = ObexPacket::new(ObexOpcode::Connect, true);
        let encoded = pkt.encode();
        // Connect with final bit = 0x80 | 0x80 = 0x80 (Connect is already 0x80)
        assert_eq!(encoded[0], 0x80);
        // Minimum 3 bytes header
        let len = u16::from_be_bytes([encoded[1], encoded[2]]);
        assert_eq!(len as usize, encoded.len());
    }

    // ---- Disconnect request packet ----

    #[test]
    fn packet_disconnect_request() {
        let pkt = ObexPacket::new(ObexOpcode::Disconnect, true);
        let encoded = pkt.encode();
        assert_eq!(encoded[0], 0x81);
        assert_eq!(encoded.len(), 3);
    }

    // ---- Decode too-short packet ----

    #[test]
    fn packet_decode_too_short() {
        // From test-gobex.c: pkt_nval_short_rsp = { 0x10 | FINAL_BIT, 0x12 }
        let data = [0x90, 0x12];
        assert!(ObexPacket::decode(&data).is_none());
    }

    // ---- Session connect/disconnect ----

    #[test]
    fn session_connect_disconnect() {
        let mut session = ObexSession::new();
        assert!(!session.connected);

        let connect_pkt = session.connect();
        assert!(session.connected);
        let bytes = session.send(&connect_pkt);
        assert!(bytes.len() >= 3);

        let _disconnect_pkt = session.disconnect();
        assert!(!session.connected);
        assert!(session.connection_id.is_none());
    }

    // ---- Packet with Body header (from test-gobex.c: pkt_put_body) ----

    #[test]
    fn packet_put_with_body() {
        let mut pkt = ObexPacket::new(ObexOpcode::Put, false);
        pkt.add_header(ObexHeader::new(HeaderId::Body, vec![1, 2, 3, 4]));
        let encoded = pkt.encode();

        // Put without final = 0x02
        assert_eq!(encoded[0], 0x02);

        let decoded = ObexPacket::decode(&encoded).unwrap();
        assert!(!decoded.final_bit);
        assert_eq!(decoded.headers.len(), 1);
        assert_eq!(decoded.headers[0].id, HeaderId::Body);
        assert_eq!(decoded.headers[0].data, vec![1, 2, 3, 4]);
    }

    // ---- AppParameters header encode/decode (from test-gobex-header.c) ----

    #[test]
    fn header_apparam_encode_decode() {
        let param_data = vec![0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        let header = ObexHeader::new(HeaderId::AppParameters, param_data.clone());
        let mut buf = Vec::new();
        header.encode(&mut buf);

        // Expected: 0x4C, len_hi, len_lo, data...
        assert_eq!(buf[0], 0x4C);
        let len = u16::from_be_bytes([buf[1], buf[2]]);
        assert_eq!(len as usize, 3 + param_data.len());

        let (decoded, _) = ObexHeader::decode(&buf).unwrap();
        assert_eq!(decoded.id, HeaderId::AppParameters);
        assert_eq!(decoded.data, param_data);
    }

    // ---- ObexError display ----

    #[test]
    fn obex_error_display() {
        assert_eq!(
            ObexError::Disconnected.to_string(),
            "session disconnected"
        );
        assert_eq!(
            ObexError::IoError("broken pipe".into()).to_string(),
            "I/O error: broken pipe"
        );
        assert_eq!(ObexError::Timeout.to_string(), "operation timed out");
    }

    // ---- Session send_packet / receive_packet ----

    #[test]
    fn session_send_receive_packet() {
        let mut session = ObexSession::new();
        session.connected = true;

        // Build a Put packet with a Body header
        let mut pkt = ObexPacket::new(ObexOpcode::Put, true);
        pkt.add_header(ObexHeader::new(HeaderId::Body, vec![0xAA, 0xBB]));

        // Send it
        session.send_packet(&pkt).unwrap();

        // The tx buffer should now contain the encoded packet
        let tx = session.take_tx_data();
        assert!(tx.len() >= 3);

        // Feed the bytes into the rx side and receive
        session.push_rx_data(&tx);
        let received = session.receive_packet().unwrap();
        assert!(received.final_bit);
        assert_eq!(received.headers.len(), 1);
        assert_eq!(received.headers[0].id, HeaderId::Body);
        assert_eq!(received.headers[0].data, vec![0xAA, 0xBB]);
    }

    // ---- Session send_packet when disconnected ----

    #[test]
    fn session_send_when_disconnected() {
        let mut session = ObexSession::new();
        assert!(!session.connected);

        let pkt = ObexPacket::new(ObexOpcode::Get, true);
        assert_eq!(session.send_packet(&pkt), Err(ObexError::Disconnected));
    }

    // ---- Session receive_packet with incomplete data ----

    #[test]
    fn session_receive_incomplete() {
        let mut session = ObexSession::new();
        session.connected = true;

        // Only 2 bytes — not enough for a packet header
        session.push_rx_data(&[0x80, 0x00]);
        assert_eq!(session.receive_packet(), Err(ObexError::InvalidPacket));
    }

    // ---- Session collect_continue_responses ----

    #[test]
    fn session_collect_continue_responses() {
        let mut session = ObexSession::new();
        session.connected = true;

        // First packet: Continue response with Body
        let mut pkt1 = ObexPacket {
            opcode: ObexResponseCode::Continue as u8 | 0x80,
            final_bit: true,
            headers: vec![ObexHeader::new(HeaderId::Body, vec![1, 2, 3])],
        };
        let _ = &mut pkt1; // suppress unused warning
        let enc1 = pkt1.encode();

        // Second packet: Success response with EndOfBody
        let pkt2 = ObexPacket {
            opcode: ObexResponseCode::Success as u8 | 0x80,
            final_bit: true,
            headers: vec![ObexHeader::new(HeaderId::EndOfBody, vec![4, 5])],
        };
        let enc2 = pkt2.encode();

        // Feed both packets
        session.push_rx_data(&enc1);
        session.push_rx_data(&enc2);

        let (body, final_code) = session.collect_continue_responses().unwrap();
        assert_eq!(body, vec![1, 2, 3, 4, 5]);
        // Final code should be Success with final bit
        assert_eq!(final_code & 0x7F, ObexResponseCode::Success as u8);
    }
}
