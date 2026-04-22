// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Legacy ATT PDU Encode/Decode Helpers
//
// Copyright 2024 BlueZ Project
//
// Rust rewrite of `attrib/att.c` (1239 lines) + `attrib/att.h` (187 lines).
// Provides the legacy ATT PDU marshaling/unmarshaling layer used by the legacy
// GATT procedures in `gatt.rs` and the GAttrib transport in `gattrib.rs`.
//
// This module defines ATT opcode constants, error codes, PDU size limits,
// encoder/decoder functions for all ATT operations, the `AttDataList` container,
// signed write support, and diagnostic error-to-string mapping.

use bluez_shared::crypto::aes_cmac::bt_crypto_sign_att;
use bluez_shared::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// ATT Opcode Constants
// ---------------------------------------------------------------------------

/// Error response opcode.
pub const ATT_OP_ERROR: u8 = 0x01;
/// Exchange MTU request opcode.
pub const ATT_OP_MTU_REQ: u8 = 0x02;
/// Exchange MTU response opcode.
pub const ATT_OP_MTU_RESP: u8 = 0x03;
/// Find Information request opcode.
pub const ATT_OP_FIND_INFO_REQ: u8 = 0x04;
/// Find Information response opcode.
pub const ATT_OP_FIND_INFO_RESP: u8 = 0x05;
/// Find By Type Value request opcode.
pub const ATT_OP_FIND_BY_TYPE_REQ: u8 = 0x06;
/// Find By Type Value response opcode.
pub const ATT_OP_FIND_BY_TYPE_RESP: u8 = 0x07;
/// Read By Type request opcode.
pub const ATT_OP_READ_BY_TYPE_REQ: u8 = 0x08;
/// Read By Type response opcode.
pub const ATT_OP_READ_BY_TYPE_RESP: u8 = 0x09;
/// Read request opcode.
pub const ATT_OP_READ_REQ: u8 = 0x0A;
/// Read response opcode.
pub const ATT_OP_READ_RESP: u8 = 0x0B;
/// Read Blob request opcode.
pub const ATT_OP_READ_BLOB_REQ: u8 = 0x0C;
/// Read Blob response opcode.
pub const ATT_OP_READ_BLOB_RESP: u8 = 0x0D;
/// Read Multiple request opcode.
pub const ATT_OP_READ_MULTI_REQ: u8 = 0x0E;
/// Read Multiple response opcode.
pub const ATT_OP_READ_MULTI_RESP: u8 = 0x0F;
/// Read By Group Type request opcode.
pub const ATT_OP_READ_BY_GROUP_REQ: u8 = 0x10;
/// Read By Group Type response opcode.
pub const ATT_OP_READ_BY_GROUP_RESP: u8 = 0x11;
/// Write request opcode.
pub const ATT_OP_WRITE_REQ: u8 = 0x12;
/// Write response opcode.
pub const ATT_OP_WRITE_RESP: u8 = 0x13;
/// Write command opcode (no response).
pub const ATT_OP_WRITE_CMD: u8 = 0x52;
/// Prepare Write request opcode.
pub const ATT_OP_PREP_WRITE_REQ: u8 = 0x16;
/// Prepare Write response opcode.
pub const ATT_OP_PREP_WRITE_RESP: u8 = 0x17;
/// Execute Write request opcode.
pub const ATT_OP_EXEC_WRITE_REQ: u8 = 0x18;
/// Execute Write response opcode.
pub const ATT_OP_EXEC_WRITE_RESP: u8 = 0x19;
/// Handle Value Notification opcode.
pub const ATT_OP_HANDLE_NOTIFY: u8 = 0x1B;
/// Handle Value Indication opcode.
pub const ATT_OP_HANDLE_IND: u8 = 0x1D;
/// Handle Value Confirmation opcode.
pub const ATT_OP_HANDLE_CNF: u8 = 0x1E;
/// Signed Write Command opcode.
pub const ATT_OP_SIGNED_WRITE_CMD: u8 = 0xD2;

// ---------------------------------------------------------------------------
// ATT Error Codes
// ---------------------------------------------------------------------------

/// The attribute handle given was not valid on this server.
pub const ATT_ECODE_INVALID_HANDLE: u8 = 0x01;
/// The attribute cannot be read.
pub const ATT_ECODE_READ_NOT_PERM: u8 = 0x02;
/// The attribute cannot be written.
pub const ATT_ECODE_WRITE_NOT_PERM: u8 = 0x03;
/// The attribute PDU was invalid.
pub const ATT_ECODE_INVALID_PDU: u8 = 0x04;
/// The attribute requires authentication before it can be read or written.
pub const ATT_ECODE_AUTHENTICATION: u8 = 0x05;
/// Attribute server does not support the request received.
pub const ATT_ECODE_REQ_NOT_SUPP: u8 = 0x06;
/// Offset specified was past the end of the attribute.
pub const ATT_ECODE_INVALID_OFFSET: u8 = 0x07;
/// The attribute requires authorization before it can be read or written.
pub const ATT_ECODE_AUTHORIZATION: u8 = 0x08;
/// Too many prepare writes have been queued.
pub const ATT_ECODE_PREP_QUEUE_FULL: u8 = 0x09;
/// No attribute found within the given attribute handle range.
pub const ATT_ECODE_ATTR_NOT_FOUND: u8 = 0x0A;
/// The attribute cannot be read or written using the Read Blob Request.
pub const ATT_ECODE_ATTR_NOT_LONG: u8 = 0x0B;
/// The Encryption Key Size used for encrypting this link is insufficient.
pub const ATT_ECODE_INSUFF_ENCR_KEY_SIZE: u8 = 0x0C;
/// The attribute value length is invalid for the operation.
pub const ATT_ECODE_INVALID_VALUE_LEN: u8 = 0x0D;
/// The attribute request has encountered an unlikely error condition.
pub const ATT_ECODE_UNLIKELY: u8 = 0x0E;
/// The attribute requires encryption before it can be read or written.
pub const ATT_ECODE_INSUFF_ENC: u8 = 0x0F;
/// The attribute type is not a supported grouping attribute.
pub const ATT_ECODE_UNSUPP_GRP_TYPE: u8 = 0x10;
/// Insufficient resources to complete the request.
pub const ATT_ECODE_INSUFF_RESOURCES: u8 = 0x11;
/// Application error: I/O.
pub const ATT_ECODE_IO: u8 = 0x80;
/// Application error: timeout.
pub const ATT_ECODE_TIMEOUT: u8 = 0x81;
/// Application error: operation aborted.
pub const ATT_ECODE_ABORTED: u8 = 0x82;

// ---------------------------------------------------------------------------
// Size Constants
// ---------------------------------------------------------------------------

/// Length of the CMAC signature appended to Signed Write Command PDUs.
pub const ATT_SIGNATURE_LEN: usize = 12;
/// Maximum attribute value length.
pub const ATT_MAX_VALUE_LEN: usize = 512;
/// Default BR/EDR L2CAP MTU for ATT.
pub const ATT_DEFAULT_L2CAP_MTU: u16 = 48;
/// Default LE L2CAP MTU for ATT.
pub const ATT_DEFAULT_LE_MTU: u16 = 23;

// ---------------------------------------------------------------------------
// Execute Write Flags
// ---------------------------------------------------------------------------

/// Cancel all prepared writes.
pub const ATT_CANCEL_ALL_PREP_WRITES: u8 = 0x00;
/// Write all prepared writes.
pub const ATT_WRITE_ALL_PREP_WRITES: u8 = 0x01;

// ---------------------------------------------------------------------------
// Find Information Response Formats
// ---------------------------------------------------------------------------

/// Format for 16-bit UUIDs in Find Information Response.
pub const ATT_FIND_INFO_RESP_FMT_16BIT: u8 = 0x01;
/// Format for 128-bit UUIDs in Find Information Response.
pub const ATT_FIND_INFO_RESP_FMT_128BIT: u8 = 0x02;

// ---------------------------------------------------------------------------
// Internal UUID type constants matching C BT_UUID16/BT_UUID128 enum values
// ---------------------------------------------------------------------------

/// C enum value for BT_UUID16 (from bluetooth/uuid.h).
const BT_UUID16_TYPE: u8 = 16;
/// C enum value for BT_UUID128 (from bluetooth/uuid.h).
const BT_UUID128_TYPE: u8 = 128;

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// Container for uniform-length attribute data entries.
///
/// Replaces the C `struct att_data_list` which used a pointer array with
/// contiguous data allocation. Each entry has the same byte length. Rust's
/// `Vec<Vec<u8>>` provides automatic memory management.
#[derive(Debug, Clone)]
pub struct AttDataList {
    /// Byte vectors for each entry (all the same length).
    entries: Vec<Vec<u8>>,
    /// Uniform byte length of each entry.
    entry_len: u16,
}

impl AttDataList {
    /// Creates a new `AttDataList` with `num` zero-initialized entries, each
    /// of `len` bytes.
    ///
    /// Matches the behavior of C `att_data_list_alloc()`, including the
    /// constraint that `len` must fit in a `u8` (max 255). Returns an empty
    /// list if `len > 255` to match the C `NULL` return.
    pub fn new(num: u16, len: u16) -> Self {
        if len > u16::from(u8::MAX) {
            return AttDataList { entries: Vec::new(), entry_len: 0 };
        }
        let entries = (0..num).map(|_| vec![0u8; len as usize]).collect();
        AttDataList { entries, entry_len: len }
    }

    /// Returns the number of entries in the list.
    pub fn num(&self) -> u16 {
        self.entries.len() as u16
    }

    /// Returns the uniform byte length of each entry.
    pub fn len(&self) -> u16 {
        self.entry_len
    }

    /// Returns true if the list has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a read-only reference to the entry at `index`, or `None` if
    /// out of bounds.
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.entries.get(index).map(|v| v.as_slice())
    }

    /// Returns a mutable reference to the entry at `index`, or `None` if
    /// out of bounds.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        self.entries.get_mut(index).map(|v| v.as_mut_slice())
    }
}

/// Attribute handle range used in Find By Type Value and other operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttRange {
    /// Start handle of the range (inclusive).
    pub start: u16,
    /// End handle of the range (inclusive).
    pub end: u16,
}

/// Decoded Find By Type Value Request fields.
#[derive(Debug, Clone)]
pub struct FindByTypeReq {
    /// Starting handle for the search range.
    pub start: u16,
    /// Ending handle for the search range.
    pub end: u16,
    /// 16-bit UUID to find.
    pub uuid: BtUuid,
    /// Attribute value to match.
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Diagnostic Functions
// ---------------------------------------------------------------------------

/// Returns a human-readable description of an ATT error code.
///
/// Maps all standard ATT error codes (0x01-0x11) and application-defined
/// codes (0x80-0x82) to descriptive strings. Unknown codes map to
/// "Unexpected error code".
pub fn att_ecode2str(status: u8) -> &'static str {
    match status {
        ATT_ECODE_INVALID_HANDLE => "Invalid handle",
        ATT_ECODE_READ_NOT_PERM => "Attribute can't be read",
        ATT_ECODE_WRITE_NOT_PERM => "Attribute can't be written",
        ATT_ECODE_INVALID_PDU => "Attribute PDU was invalid",
        ATT_ECODE_AUTHENTICATION => "Attribute requires authentication before read/write",
        ATT_ECODE_REQ_NOT_SUPP => "Server doesn't support the request received",
        ATT_ECODE_INVALID_OFFSET => "Offset past the end of the attribute",
        ATT_ECODE_AUTHORIZATION => "Attribute requires authorization before read/write",
        ATT_ECODE_PREP_QUEUE_FULL => "Too many prepare writes have been queued",
        ATT_ECODE_ATTR_NOT_FOUND => "No attribute found within the given range",
        ATT_ECODE_ATTR_NOT_LONG => "Attribute can't be read/written using Read Blob Req",
        ATT_ECODE_INSUFF_ENCR_KEY_SIZE => "Encryption Key Size is insufficient",
        ATT_ECODE_INVALID_VALUE_LEN => "Attribute value length is invalid",
        ATT_ECODE_UNLIKELY => "Request attribute has encountered an unlikely error",
        ATT_ECODE_INSUFF_ENC => "Encryption required before read/write",
        ATT_ECODE_UNSUPP_GRP_TYPE => "Attribute type is not a supported grouping attribute",
        ATT_ECODE_INSUFF_RESOURCES => "Insufficient Resources to complete the request",
        ATT_ECODE_IO => "Internal application error: I/O",
        ATT_ECODE_TIMEOUT => "A timeout occurred",
        ATT_ECODE_ABORTED => "The operation was aborted",
        _ => "Unexpected error code",
    }
}

// ---------------------------------------------------------------------------
// Internal UUID Helper Functions
// ---------------------------------------------------------------------------

/// Writes a UUID to a byte buffer in little-endian wire format.
///
/// For UUID16: writes 2 bytes LE, returns 2.
/// For UUID32: expands to UUID128 and writes 16 bytes, returns 16.
/// For UUID128: copies 16 bytes (already in BlueZ LE wire format), returns 16.
fn put_uuid_le(uuid: &BtUuid, dst: &mut [u8]) -> usize {
    match uuid {
        BtUuid::Uuid16(val) => {
            dst[..2].copy_from_slice(&val.to_le_bytes());
            2
        }
        BtUuid::Uuid32(_) => {
            let bytes = uuid.to_uuid128_bytes();
            dst[..16].copy_from_slice(&bytes);
            16
        }
        BtUuid::Uuid128(bytes) => {
            dst[..16].copy_from_slice(bytes);
            16
        }
    }
}

/// Reads a UUID from little-endian wire bytes.
///
/// `uuid_type` selects the size: `BT_UUID16_TYPE` (16) reads 2 bytes,
/// otherwise reads 16 bytes as UUID128.
fn get_uuid(uuid_type: u8, raw: &[u8]) -> BtUuid {
    if uuid_type == BT_UUID16_TYPE {
        let val = u16::from_le_bytes([raw[0], raw[1]]);
        BtUuid::from_u16(val)
    } else {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&raw[..16]);
        BtUuid::from_bytes(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Encoder Functions — Requests
// ---------------------------------------------------------------------------

/// Encodes an Exchange MTU Request PDU.
///
/// Format: opcode(1) + client_rx_mtu(2) = 3 bytes.
/// Returns the encoded length (3), or 0 on error.
pub fn enc_mtu_req(mtu: u16, pdu: &mut [u8]) -> usize {
    if pdu.len() < 3 {
        return 0;
    }
    pdu[0] = ATT_OP_MTU_REQ;
    pdu[1..3].copy_from_slice(&mtu.to_le_bytes());
    3
}

/// Encodes a Find Information Request PDU.
///
/// Format: opcode(1) + start_handle(2) + end_handle(2) = 5 bytes.
pub fn enc_find_info_req(start: u16, end: u16, pdu: &mut [u8]) -> usize {
    if pdu.len() < 5 {
        return 0;
    }
    pdu[0] = ATT_OP_FIND_INFO_REQ;
    pdu[1..3].copy_from_slice(&start.to_le_bytes());
    pdu[3..5].copy_from_slice(&end.to_le_bytes());
    5
}

/// Encodes a Find By Type Value Request PDU.
///
/// Format: opcode(1) + start(2) + end(2) + uuid16(2) + value(vlen).
/// Only UUID16 is accepted; other UUID types return 0.
pub fn enc_find_by_type_req(
    start: u16,
    end: u16,
    uuid: &BtUuid,
    value: &[u8],
    pdu: &mut [u8],
) -> usize {
    let min_len: usize = 7; // opcode(1) + start(2) + end(2) + uuid16(2)

    // Find By Type Value only supports UUID16
    let uuid_val = match uuid {
        BtUuid::Uuid16(v) => *v,
        _ => return 0,
    };

    if pdu.len() < min_len {
        return 0;
    }

    // Clamp value length to available space
    let vlen = value.len().min(pdu.len() - min_len);

    pdu[0] = ATT_OP_FIND_BY_TYPE_REQ;
    pdu[1..3].copy_from_slice(&start.to_le_bytes());
    pdu[3..5].copy_from_slice(&end.to_le_bytes());
    pdu[5..7].copy_from_slice(&uuid_val.to_le_bytes());

    if vlen > 0 {
        pdu[7..7 + vlen].copy_from_slice(&value[..vlen]);
    }

    min_len + vlen
}

/// Encodes a Read By Type Request PDU.
///
/// Format: opcode(1) + start(2) + end(2) + uuid(2 or 16).
/// Only UUID16 and UUID128 are accepted.
pub fn enc_read_by_type_req(start: u16, end: u16, uuid: &BtUuid, pdu: &mut [u8]) -> usize {
    let uuid_len: usize = match uuid {
        BtUuid::Uuid16(_) => 2,
        BtUuid::Uuid128(_) => 16,
        _ => return 0,
    };

    let total = 5 + uuid_len;
    if pdu.len() < total {
        return 0;
    }

    pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
    pdu[1..3].copy_from_slice(&start.to_le_bytes());
    pdu[3..5].copy_from_slice(&end.to_le_bytes());
    put_uuid_le(uuid, &mut pdu[5..]);
    total
}

/// Encodes a Read Request PDU.
///
/// Format: opcode(1) + handle(2) = 3 bytes.
pub fn enc_read_req(handle: u16, pdu: &mut [u8]) -> usize {
    if pdu.len() < 3 {
        return 0;
    }
    pdu[0] = ATT_OP_READ_REQ;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());
    3
}

/// Encodes a Read Blob Request PDU.
///
/// Format: opcode(1) + handle(2) + offset(2) = 5 bytes.
pub fn enc_read_blob_req(handle: u16, offset: u16, pdu: &mut [u8]) -> usize {
    if pdu.len() < 5 {
        return 0;
    }
    pdu[0] = ATT_OP_READ_BLOB_REQ;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());
    pdu[3..5].copy_from_slice(&offset.to_le_bytes());
    5
}

/// Encodes a Read By Group Type Request PDU.
///
/// Format: opcode(1) + start(2) + end(2) + uuid(2 or 16).
/// Only UUID16 and UUID128 are accepted.
pub fn enc_read_by_grp_req(start: u16, end: u16, uuid: &BtUuid, pdu: &mut [u8]) -> usize {
    let uuid_len: usize = match uuid {
        BtUuid::Uuid16(_) => 2,
        BtUuid::Uuid128(_) => 16,
        _ => return 0,
    };

    let total = 5 + uuid_len;
    if pdu.len() < total {
        return 0;
    }

    pdu[0] = ATT_OP_READ_BY_GROUP_REQ;
    pdu[1..3].copy_from_slice(&start.to_le_bytes());
    pdu[3..5].copy_from_slice(&end.to_le_bytes());
    put_uuid_le(uuid, &mut pdu[5..]);
    total
}

/// Encodes a Write Request PDU.
///
/// Format: opcode(1) + handle(2) + value(vlen).
pub fn enc_write_req(handle: u16, value: &[u8], pdu: &mut [u8]) -> usize {
    let min_len: usize = 3; // opcode(1) + handle(2)

    if pdu.len() < min_len {
        return 0;
    }

    let vlen = value.len().min(pdu.len() - min_len);

    pdu[0] = ATT_OP_WRITE_REQ;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());

    if vlen > 0 {
        pdu[3..3 + vlen].copy_from_slice(&value[..vlen]);
        return min_len + vlen;
    }

    min_len
}

/// Encodes a Write Command PDU (no response expected).
///
/// Format: opcode(1) + handle(2) + value(vlen).
pub fn enc_write_cmd(handle: u16, value: &[u8], pdu: &mut [u8]) -> usize {
    let min_len: usize = 3; // opcode(1) + handle(2)

    if pdu.len() < min_len {
        return 0;
    }

    let vlen = value.len().min(pdu.len() - min_len);

    pdu[0] = ATT_OP_WRITE_CMD;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());

    if vlen > 0 {
        pdu[3..3 + vlen].copy_from_slice(&value[..vlen]);
        return min_len + vlen;
    }

    min_len
}

/// Encodes a Signed Write Command PDU with CMAC signature.
///
/// Format: opcode(1) + handle(2) + value(vlen) + signature(12).
/// The CMAC signature is computed over opcode + handle + value using the
/// provided CSRK and sign counter.
pub fn enc_signed_write_cmd(
    handle: u16,
    value: &[u8],
    csrk: &[u8; 16],
    sign_cnt: u32,
    pdu: &mut [u8],
) -> usize {
    let hdr_len: usize = 3; // opcode(1) + handle(2)
    let min_len: usize = hdr_len + ATT_SIGNATURE_LEN;

    if pdu.len() < min_len {
        return 0;
    }

    let vlen = value.len().min(pdu.len() - min_len);

    pdu[0] = ATT_OP_SIGNED_WRITE_CMD;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());

    if vlen > 0 {
        pdu[hdr_len..hdr_len + vlen].copy_from_slice(&value[..vlen]);
    }

    // Compute CMAC signature over the PDU data (opcode + handle + value)
    let msg_end = hdr_len + vlen;
    let sig_result = bt_crypto_sign_att(csrk, &pdu[..msg_end], sign_cnt);

    match sig_result {
        Ok(sig) => {
            pdu[msg_end..msg_end + ATT_SIGNATURE_LEN].copy_from_slice(&sig);
            min_len + vlen
        }
        Err(_) => 0,
    }
}

/// Encodes a Prepare Write Request PDU.
///
/// Format: opcode(1) + handle(2) + offset(2) + value(vlen).
pub fn enc_prep_write_req(handle: u16, offset: u16, value: &[u8], pdu: &mut [u8]) -> usize {
    let min_len: usize = 5; // opcode(1) + handle(2) + offset(2)

    if pdu.len() < min_len {
        return 0;
    }

    let vlen = value.len().min(pdu.len() - min_len);

    pdu[0] = ATT_OP_PREP_WRITE_REQ;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());
    pdu[3..5].copy_from_slice(&offset.to_le_bytes());

    if vlen > 0 {
        pdu[5..5 + vlen].copy_from_slice(&value[..vlen]);
        return min_len + vlen;
    }

    min_len
}

/// Encodes an Execute Write Request PDU.
///
/// Format: opcode(1) + flags(1) = 2 bytes.
/// Flags must be 0 (cancel) or 1 (write). Returns 0 for invalid flags.
pub fn enc_exec_write_req(flags: u8, pdu: &mut [u8]) -> usize {
    if pdu.len() < 2 {
        return 0;
    }

    if flags > 1 {
        return 0;
    }

    pdu[0] = ATT_OP_EXEC_WRITE_REQ;
    pdu[1] = flags;
    2
}

/// Encodes a Read Multiple Request PDU.
///
/// Format: opcode(1) + handles(2 * num_handles).
pub fn enc_read_multi_req(handles: &[u16], pdu: &mut [u8]) -> usize {
    if handles.is_empty() {
        return 0;
    }

    let total = 1 + handles.len() * 2;
    if pdu.len() < total {
        return 0;
    }

    pdu[0] = ATT_OP_READ_MULTI_REQ;
    let mut offset = 1;
    for &h in handles {
        pdu[offset..offset + 2].copy_from_slice(&h.to_le_bytes());
        offset += 2;
    }

    total
}

// ---------------------------------------------------------------------------
// Encoder Functions — Responses
// ---------------------------------------------------------------------------

/// Encodes an Exchange MTU Response PDU.
///
/// Format: opcode(1) + server_rx_mtu(2) = 3 bytes.
pub fn enc_mtu_resp(mtu: u16, pdu: &mut [u8]) -> usize {
    if pdu.len() < 3 {
        return 0;
    }
    pdu[0] = ATT_OP_MTU_RESP;
    pdu[1..3].copy_from_slice(&mtu.to_le_bytes());
    3
}

/// Encodes a Find Information Response PDU.
///
/// Format: opcode(1) + format(1) + data_list(entry_len * num).
/// The `format` byte indicates UUID16 (0x01) or UUID128 (0x02).
pub fn enc_find_info_resp(format: u8, list: &AttDataList, pdu: &mut [u8]) -> usize {
    if list.is_empty() {
        return 0;
    }

    let entry_len = list.len() as usize;
    // Need at least header (2 bytes) + one entry
    if pdu.len() < 2 + entry_len {
        return 0;
    }

    pdu[0] = ATT_OP_FIND_INFO_RESP;
    pdu[1] = format;

    let mut offset: usize = 2;
    for i in 0..list.num() as usize {
        if offset + entry_len > pdu.len() {
            break;
        }
        if let Some(data) = list.get(i) {
            pdu[offset..offset + entry_len].copy_from_slice(data);
            offset += entry_len;
        }
    }

    offset
}

/// Encodes a Find By Type Value Response PDU.
///
/// Format: opcode(1) + handle_pairs(4 * num).
/// Each entry in the `AttDataList` should be 4 bytes (start_handle + end_handle).
pub fn enc_find_by_type_resp(list: &AttDataList, pdu: &mut [u8]) -> usize {
    if pdu.is_empty() {
        return 0;
    }

    pdu[0] = ATT_OP_FIND_BY_TYPE_RESP;
    let mut offset: usize = 1;

    for i in 0..list.num() as usize {
        if offset + 4 > pdu.len() {
            break;
        }
        if let Some(data) = list.get(i) {
            let copy_len = data.len().min(4);
            pdu[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
            offset += 4;
        }
    }

    offset
}

/// Encodes a Read By Type Response PDU.
///
/// Format: opcode(1) + length(1) + data_list(entry_len * num).
pub fn enc_read_by_type_resp(list: &AttDataList, pdu: &mut [u8]) -> usize {
    if list.is_empty() {
        return 0;
    }
    if pdu.len() < 2 {
        return 0;
    }

    let entry_len = (list.len() as usize).min(pdu.len() - 2);

    pdu[0] = ATT_OP_READ_BY_TYPE_RESP;
    pdu[1] = entry_len as u8;

    let mut offset: usize = 2;
    for i in 0..list.num() as usize {
        if offset + entry_len > pdu.len() {
            break;
        }
        if let Some(data) = list.get(i) {
            pdu[offset..offset + entry_len].copy_from_slice(&data[..entry_len]);
            offset += entry_len;
        }
    }

    offset
}

/// Encodes a Read Response PDU.
///
/// Format: opcode(1) + value(vlen).
/// Value is truncated if it exceeds the available PDU space.
pub fn enc_read_resp(value: &[u8], pdu: &mut [u8]) -> usize {
    if pdu.is_empty() {
        return 0;
    }

    let vlen = value.len().min(pdu.len() - 1);
    pdu[0] = ATT_OP_READ_RESP;
    pdu[1..1 + vlen].copy_from_slice(&value[..vlen]);
    vlen + 1
}

/// Encodes a Read Blob Response PDU.
///
/// Format: opcode(1) + partial_value(from offset to end or PDU limit).
/// The `offset` indicates where within the full `value` to start copying.
pub fn enc_read_blob_resp(value: &[u8], offset: u16, pdu: &mut [u8]) -> usize {
    if pdu.is_empty() {
        return 0;
    }

    let off = offset as usize;
    if off >= value.len() {
        pdu[0] = ATT_OP_READ_BLOB_RESP;
        return 1;
    }

    let remaining = value.len() - off;
    let vlen = remaining.min(pdu.len() - 1);
    pdu[0] = ATT_OP_READ_BLOB_RESP;
    pdu[1..1 + vlen].copy_from_slice(&value[off..off + vlen]);
    vlen + 1
}

/// Encodes a Read By Group Type Response PDU.
///
/// Format: opcode(1) + length(1) + data_list(entry_len * num).
pub fn enc_read_by_grp_resp(list: &AttDataList, pdu: &mut [u8]) -> usize {
    if list.is_empty() {
        return 0;
    }
    if pdu.len() < 2 {
        return 0;
    }

    let entry_len = list.len() as usize;
    if pdu.len() < entry_len + 2 {
        return 0;
    }

    pdu[0] = ATT_OP_READ_BY_GROUP_RESP;
    pdu[1] = entry_len as u8;

    let mut offset: usize = 2;
    for i in 0..list.num() as usize {
        if offset + entry_len > pdu.len() {
            break;
        }
        if let Some(data) = list.get(i) {
            pdu[offset..offset + entry_len].copy_from_slice(data);
            offset += entry_len;
        }
    }

    offset
}

/// Encodes a Write Response PDU.
///
/// Format: opcode(1) = 1 byte.
pub fn enc_write_resp(pdu: &mut [u8]) -> usize {
    if pdu.is_empty() {
        return 0;
    }
    pdu[0] = ATT_OP_WRITE_RESP;
    1
}

/// Encodes a Prepare Write Response PDU.
///
/// Format: opcode(1) + handle(2) + offset(2) + value(vlen).
pub fn enc_prep_write_resp(handle: u16, offset: u16, value: &[u8], pdu: &mut [u8]) -> usize {
    let min_len: usize = 5; // opcode(1) + handle(2) + offset(2)

    if pdu.len() < min_len {
        return 0;
    }

    let vlen = value.len().min(pdu.len() - min_len);

    pdu[0] = ATT_OP_PREP_WRITE_RESP;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());
    pdu[3..5].copy_from_slice(&offset.to_le_bytes());

    if vlen > 0 {
        pdu[5..5 + vlen].copy_from_slice(&value[..vlen]);
        return min_len + vlen;
    }

    min_len
}

/// Encodes an Execute Write Response PDU.
///
/// Format: opcode(1) = 1 byte.
pub fn enc_exec_write_resp(pdu: &mut [u8]) -> usize {
    if pdu.is_empty() {
        return 0;
    }
    pdu[0] = ATT_OP_EXEC_WRITE_RESP;
    1
}

/// Encodes an Error Response PDU.
///
/// Format: opcode(1) + req_opcode(1) + handle(2) + error_code(1) = 5 bytes.
pub fn enc_error_resp(opcode: u8, handle: u16, status: u8, pdu: &mut [u8]) -> usize {
    if pdu.len() < 5 {
        return 0;
    }
    pdu[0] = ATT_OP_ERROR;
    pdu[1] = opcode;
    pdu[2..4].copy_from_slice(&handle.to_le_bytes());
    pdu[4] = status;
    5
}

/// Encodes a Handle Value Notification PDU.
///
/// Format: opcode(1) + handle(2) + value(vlen).
pub fn enc_notification(handle: u16, value: &[u8], pdu: &mut [u8]) -> usize {
    let min_len: usize = 3; // opcode(1) + handle(2)
    let total = min_len + value.len();

    if pdu.len() < total {
        return 0;
    }

    pdu[0] = ATT_OP_HANDLE_NOTIFY;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());
    pdu[3..3 + value.len()].copy_from_slice(value);
    total
}

/// Encodes a Handle Value Indication PDU.
///
/// Format: opcode(1) + handle(2) + value(vlen).
pub fn enc_indication(handle: u16, value: &[u8], pdu: &mut [u8]) -> usize {
    let min_len: usize = 3; // opcode(1) + handle(2)
    let total = min_len + value.len();

    if pdu.len() < total {
        return 0;
    }

    pdu[0] = ATT_OP_HANDLE_IND;
    pdu[1..3].copy_from_slice(&handle.to_le_bytes());
    pdu[3..3 + value.len()].copy_from_slice(value);
    total
}

/// Encodes a Handle Value Confirmation PDU.
///
/// Format: opcode(1) = 1 byte.
pub fn enc_confirmation(pdu: &mut [u8]) -> usize {
    if pdu.is_empty() {
        return 0;
    }
    pdu[0] = ATT_OP_HANDLE_CNF;
    1
}

// ---------------------------------------------------------------------------
// Decoder Functions — Requests
// ---------------------------------------------------------------------------

/// Decodes an Exchange MTU Request PDU. Returns the client MTU.
pub fn dec_mtu_req(pdu: &[u8]) -> Option<u16> {
    if pdu.len() < 3 {
        return None;
    }
    if pdu[0] != ATT_OP_MTU_REQ {
        return None;
    }
    Some(u16::from_le_bytes([pdu[1], pdu[2]]))
}

/// Decodes a Find Information Request PDU.
/// Returns `(start_handle, end_handle)`.
pub fn dec_find_info_req(pdu: &[u8]) -> Option<(u16, u16)> {
    if pdu.len() < 5 {
        return None;
    }
    if pdu[0] != ATT_OP_FIND_INFO_REQ {
        return None;
    }
    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    Some((start, end))
}

/// Decodes a Find By Type Value Request PDU.
/// Returns a `FindByTypeReq` containing start, end, UUID16, and value.
pub fn dec_find_by_type_req(pdu: &[u8]) -> Option<FindByTypeReq> {
    if pdu.len() < 7 {
        return None;
    }
    if pdu[0] != ATT_OP_FIND_BY_TYPE_REQ {
        return None;
    }

    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    let uuid_val = u16::from_le_bytes([pdu[5], pdu[6]]);
    let uuid = BtUuid::from_u16(uuid_val);

    let value = if pdu.len() > 7 { pdu[7..].to_vec() } else { Vec::new() };

    Some(FindByTypeReq { start, end, uuid, value })
}

/// Decodes a Read By Type Request PDU.
/// Returns `(start_handle, end_handle, uuid)`.
pub fn dec_read_by_type_req(pdu: &[u8]) -> Option<(u16, u16, BtUuid)> {
    // Minimum: opcode(1) + start(2) + end(2) + uuid16(2) = 7
    let min_len: usize = 5; // opcode + start + end
    if pdu.len() < min_len + 2 {
        return None;
    }
    if pdu[0] != ATT_OP_READ_BY_TYPE_REQ {
        return None;
    }

    let uuid_type = if pdu.len() == min_len + 2 {
        BT_UUID16_TYPE
    } else if pdu.len() == min_len + 16 {
        BT_UUID128_TYPE
    } else {
        return None;
    };

    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    let uuid = get_uuid(uuid_type, &pdu[5..]);

    Some((start, end, uuid))
}

/// Decodes a Read Request PDU. Returns the attribute handle.
pub fn dec_read_req(pdu: &[u8]) -> Option<u16> {
    if pdu.len() < 3 {
        return None;
    }
    if pdu[0] != ATT_OP_READ_REQ {
        return None;
    }
    Some(u16::from_le_bytes([pdu[1], pdu[2]]))
}

/// Decodes a Read Blob Request PDU.
/// Returns `(handle, offset)`.
pub fn dec_read_blob_req(pdu: &[u8]) -> Option<(u16, u16)> {
    if pdu.len() < 5 {
        return None;
    }
    if pdu[0] != ATT_OP_READ_BLOB_REQ {
        return None;
    }
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let offset = u16::from_le_bytes([pdu[3], pdu[4]]);
    Some((handle, offset))
}

/// Decodes a Read By Group Type Request PDU.
/// Returns `(start_handle, end_handle, uuid)`.
pub fn dec_read_by_grp_req(pdu: &[u8]) -> Option<(u16, u16, BtUuid)> {
    let min_len: usize = 5; // opcode + start + end
    if pdu.len() < min_len + 2 {
        return None;
    }
    if pdu[0] != ATT_OP_READ_BY_GROUP_REQ {
        return None;
    }

    let uuid_type = if pdu.len() == min_len + 2 {
        BT_UUID16_TYPE
    } else if pdu.len() == min_len + 16 {
        BT_UUID128_TYPE
    } else {
        return None;
    };

    let start = u16::from_le_bytes([pdu[1], pdu[2]]);
    let end = u16::from_le_bytes([pdu[3], pdu[4]]);
    let uuid = get_uuid(uuid_type, &pdu[5..]);

    Some((start, end, uuid))
}

/// Decodes a Write Request PDU.
/// Returns `(handle, value)`.
pub fn dec_write_req(pdu: &[u8]) -> Option<(u16, Vec<u8>)> {
    let min_len: usize = 3; // opcode(1) + handle(2)
    if pdu.len() < min_len {
        return None;
    }
    if pdu[0] != ATT_OP_WRITE_REQ {
        return None;
    }
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let value = pdu[min_len..].to_vec();
    Some((handle, value))
}

/// Decodes a Write Command PDU.
/// Returns `(handle, value)`.
pub fn dec_write_cmd(pdu: &[u8]) -> Option<(u16, Vec<u8>)> {
    let min_len: usize = 3; // opcode(1) + handle(2)
    if pdu.len() < min_len {
        return None;
    }
    if pdu[0] != ATT_OP_WRITE_CMD {
        return None;
    }
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let value = pdu[min_len..].to_vec();
    Some((handle, value))
}

/// Decodes a Prepare Write Request PDU.
/// Returns `(handle, offset, value)`.
pub fn dec_prep_write_req(pdu: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
    let min_len: usize = 5; // opcode(1) + handle(2) + offset(2)
    if pdu.len() < min_len {
        return None;
    }
    if pdu[0] != ATT_OP_PREP_WRITE_REQ {
        return None;
    }
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let offset = u16::from_le_bytes([pdu[3], pdu[4]]);
    let value = pdu[min_len..].to_vec();
    Some((handle, offset, value))
}

/// Decodes an Execute Write Request PDU. Returns the flags byte.
pub fn dec_exec_write_req(pdu: &[u8]) -> Option<u8> {
    if pdu.len() < 2 {
        return None;
    }
    if pdu[0] != ATT_OP_EXEC_WRITE_REQ {
        return None;
    }
    Some(pdu[1])
}

// ---------------------------------------------------------------------------
// Decoder Functions — Responses
// ---------------------------------------------------------------------------

/// Decodes an Exchange MTU Response PDU. Returns the server MTU.
pub fn dec_mtu_resp(pdu: &[u8]) -> Option<u16> {
    if pdu.len() < 3 {
        return None;
    }
    if pdu[0] != ATT_OP_MTU_RESP {
        return None;
    }
    Some(u16::from_le_bytes([pdu[1], pdu[2]]))
}

/// Decodes a Find Information Response PDU.
/// Returns `(format, data_list)` where format is 0x01 (UUID16) or 0x02 (UUID128).
pub fn dec_find_info_resp(pdu: &[u8]) -> Option<(u8, AttDataList)> {
    if pdu.len() < 6 {
        return None;
    }
    if pdu[0] != ATT_OP_FIND_INFO_RESP {
        return None;
    }

    let format = pdu[1];

    // Entry size: handle(2) + uuid_size
    // For format 0x01 (UUID16): 2 + 2 = 4
    // For format 0x02 (UUID128): 2 + 16 = 18
    let entry_len: usize = match format {
        ATT_FIND_INFO_RESP_FMT_16BIT => 4,
        ATT_FIND_INFO_RESP_FMT_128BIT => 18,
        _ => return None,
    };

    let data_len = pdu.len() - 2;
    if data_len % entry_len != 0 {
        return None;
    }
    let num = data_len / entry_len;
    if num == 0 {
        return None;
    }

    let mut list = AttDataList::new(num as u16, entry_len as u16);
    let mut ptr = 2;
    for i in 0..num {
        if let Some(entry) = list.get_mut(i) {
            entry.copy_from_slice(&pdu[ptr..ptr + entry_len]);
        }
        ptr += entry_len;
    }

    Some((format, list))
}

/// Decodes a Find By Type Value Response PDU.
/// Returns an `AttDataList` with 4-byte entries (start_handle + end_handle).
pub fn dec_find_by_type_resp(pdu: &[u8]) -> Option<AttDataList> {
    // Minimum: opcode(1) + one handle pair (4)
    if pdu.len() < 5 {
        return None;
    }
    if pdu[0] != ATT_OP_FIND_BY_TYPE_RESP {
        return None;
    }

    let data_len = pdu.len() - 1;
    // Reject incomplete handle pairs
    if data_len % 4 != 0 {
        return None;
    }

    let num = data_len / 4;
    let mut list = AttDataList::new(num as u16, 4);

    let mut ptr = 1;
    for i in 0..num {
        if let Some(entry) = list.get_mut(i) {
            entry.copy_from_slice(&pdu[ptr..ptr + 4]);
        }
        ptr += 4;
    }

    Some(list)
}

/// Decodes a Read By Type Response PDU.
/// Returns an `AttDataList` where each entry is `length` bytes.
pub fn dec_read_by_type_resp(pdu: &[u8]) -> Option<AttDataList> {
    // Minimum: opcode(1) + length(1) + at least one entry of 3+ bytes
    if pdu.len() < 5 {
        return None;
    }
    if pdu[0] != ATT_OP_READ_BY_TYPE_RESP {
        return None;
    }

    let entry_len = pdu[1] as usize;
    // Minimum entry: handle(2) + value(1) = 3
    if entry_len < 3 {
        return None;
    }

    let data_len = pdu.len() - 2;
    // Reject incomplete entries
    if data_len % entry_len != 0 {
        return None;
    }

    let num = data_len / entry_len;
    let mut list = AttDataList::new(num as u16, entry_len as u16);

    let mut ptr = 2;
    for i in 0..num {
        if let Some(entry) = list.get_mut(i) {
            entry.copy_from_slice(&pdu[ptr..ptr + entry_len]);
        }
        ptr += entry_len;
    }

    Some(list)
}

/// Decodes a Read Response PDU. Copies value bytes into `value_buf`.
/// Returns the number of value bytes copied.
pub fn dec_read_resp(pdu: &[u8], value_buf: &mut [u8]) -> Option<usize> {
    if pdu.is_empty() {
        return None;
    }
    if pdu[0] != ATT_OP_READ_RESP {
        return None;
    }

    let vlen = pdu.len() - 1;
    if value_buf.len() < vlen {
        return None;
    }

    value_buf[..vlen].copy_from_slice(&pdu[1..]);
    Some(vlen)
}

/// Decodes a Read By Group Type Response PDU.
/// Returns an `AttDataList` where each entry is `length` bytes.
pub fn dec_read_by_grp_resp(pdu: &[u8]) -> Option<AttDataList> {
    // Minimum: opcode(1) + length(1) + at least one entry of 5+ bytes
    if pdu.len() < 7 {
        return None;
    }
    if pdu[0] != ATT_OP_READ_BY_GROUP_RESP {
        return None;
    }

    let entry_len = pdu[1] as usize;
    // Minimum entry: start_handle(2) + end_handle(2) + value(1) = 5
    if entry_len < 5 {
        return None;
    }

    let data_len = pdu.len() - 2;
    // Reject incomplete entries
    if data_len % entry_len != 0 {
        return None;
    }

    let num = data_len / entry_len;
    let mut list = AttDataList::new(num as u16, entry_len as u16);

    let mut ptr = 2;
    for i in 0..num {
        if let Some(entry) = list.get_mut(i) {
            entry.copy_from_slice(&pdu[ptr..ptr + entry_len]);
        }
        ptr += entry_len;
    }

    Some(list)
}

/// Decodes a Write Response PDU. Returns `Some(())` if valid.
pub fn dec_write_resp(pdu: &[u8]) -> Option<()> {
    if pdu.is_empty() {
        return None;
    }
    if pdu[0] != ATT_OP_WRITE_RESP {
        return None;
    }
    Some(())
}

/// Decodes a Prepare Write Response PDU.
/// Returns `(handle, offset, value)`.
pub fn dec_prep_write_resp(pdu: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
    let min_len: usize = 5; // opcode(1) + handle(2) + offset(2)
    if pdu.len() < min_len {
        return None;
    }
    if pdu[0] != ATT_OP_PREP_WRITE_RESP {
        return None;
    }
    let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
    let offset = u16::from_le_bytes([pdu[3], pdu[4]]);
    let value = pdu[min_len..].to_vec();
    Some((handle, offset, value))
}

/// Decodes an Execute Write Response PDU. Returns `Some(())` if valid.
pub fn dec_exec_write_resp(pdu: &[u8]) -> Option<()> {
    if pdu.is_empty() {
        return None;
    }
    if pdu[0] != ATT_OP_EXEC_WRITE_RESP {
        return None;
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_att_ecode2str_known_codes() {
        assert_eq!(att_ecode2str(0x01), "Invalid handle");
        assert_eq!(att_ecode2str(0x02), "Attribute can't be read");
        assert_eq!(att_ecode2str(0x06), "Server doesn't support the request received");
        assert_eq!(att_ecode2str(0x0A), "No attribute found within the given range");
        assert_eq!(att_ecode2str(0x11), "Insufficient Resources to complete the request");
        assert_eq!(att_ecode2str(0x80), "Internal application error: I/O");
        assert_eq!(att_ecode2str(0x81), "A timeout occurred");
        assert_eq!(att_ecode2str(0x82), "The operation was aborted");
    }

    #[test]
    fn test_att_ecode2str_unknown() {
        assert_eq!(att_ecode2str(0xFF), "Unexpected error code");
        assert_eq!(att_ecode2str(0x00), "Unexpected error code");
    }

    #[test]
    fn test_att_data_list_basic() {
        let list = AttDataList::new(3, 4);
        assert_eq!(list.num(), 3);
        assert_eq!(list.len(), 4);
        assert!(!list.is_empty());
        assert_eq!(list.get(0), Some([0u8, 0, 0, 0].as_slice()));
        assert!(list.get(3).is_none());
    }

    #[test]
    fn test_att_data_list_mutate() {
        let mut list = AttDataList::new(2, 4);
        if let Some(entry) = list.get_mut(0) {
            entry[0] = 0x01;
            entry[1] = 0x02;
        }
        assert_eq!(list.get(0).unwrap()[0], 0x01);
        assert_eq!(list.get(0).unwrap()[1], 0x02);
    }

    #[test]
    fn test_att_data_list_overflow_len() {
        let list = AttDataList::new(1, 256);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_enc_dec_mtu_req() {
        let mut pdu = [0u8; 64];
        let len = enc_mtu_req(512, &mut pdu);
        assert_eq!(len, 3);
        assert_eq!(pdu[0], ATT_OP_MTU_REQ);

        let mtu = dec_mtu_req(&pdu[..len]).unwrap();
        assert_eq!(mtu, 512);
    }

    #[test]
    fn test_enc_dec_mtu_resp() {
        let mut pdu = [0u8; 64];
        let len = enc_mtu_resp(256, &mut pdu);
        assert_eq!(len, 3);

        let mtu = dec_mtu_resp(&pdu[..len]).unwrap();
        assert_eq!(mtu, 256);
    }

    #[test]
    fn test_enc_dec_find_info_req() {
        let mut pdu = [0u8; 64];
        let len = enc_find_info_req(0x0001, 0xFFFF, &mut pdu);
        assert_eq!(len, 5);

        let (start, end) = dec_find_info_req(&pdu[..len]).unwrap();
        assert_eq!(start, 0x0001);
        assert_eq!(end, 0xFFFF);
    }

    #[test]
    fn test_enc_dec_read_by_type_req_uuid16() {
        let uuid = BtUuid::from_u16(0x2803);
        let mut pdu = [0u8; 64];
        let len = enc_read_by_type_req(1, 0xFFFF, &uuid, &mut pdu);
        assert_eq!(len, 7);

        let (start, end, decoded_uuid) = dec_read_by_type_req(&pdu[..len]).unwrap();
        assert_eq!(start, 1);
        assert_eq!(end, 0xFFFF);
        assert_eq!(decoded_uuid, uuid);
    }

    #[test]
    fn test_enc_dec_read_by_type_req_uuid128() {
        let bytes: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let uuid = BtUuid::from_bytes(&bytes);
        let mut pdu = [0u8; 64];
        let len = enc_read_by_type_req(1, 100, &uuid, &mut pdu);
        assert_eq!(len, 21);

        let (start, end, decoded_uuid) = dec_read_by_type_req(&pdu[..len]).unwrap();
        assert_eq!(start, 1);
        assert_eq!(end, 100);
        assert_eq!(decoded_uuid, uuid);
    }

    #[test]
    fn test_enc_dec_read_req() {
        let mut pdu = [0u8; 64];
        let len = enc_read_req(0x0042, &mut pdu);
        assert_eq!(len, 3);

        let handle = dec_read_req(&pdu[..len]).unwrap();
        assert_eq!(handle, 0x0042);
    }

    #[test]
    fn test_enc_dec_read_blob_req() {
        let mut pdu = [0u8; 64];
        let len = enc_read_blob_req(0x0010, 0x0020, &mut pdu);
        assert_eq!(len, 5);

        let (handle, offset) = dec_read_blob_req(&pdu[..len]).unwrap();
        assert_eq!(handle, 0x0010);
        assert_eq!(offset, 0x0020);
    }

    #[test]
    fn test_enc_dec_write_req() {
        let value = [0x01, 0x02, 0x03];
        let mut pdu = [0u8; 64];
        let len = enc_write_req(0x0042, &value, &mut pdu);
        assert_eq!(len, 6);

        let (handle, dec_value) = dec_write_req(&pdu[..len]).unwrap();
        assert_eq!(handle, 0x0042);
        assert_eq!(dec_value, value);
    }

    #[test]
    fn test_enc_dec_write_cmd() {
        let value = [0xAA, 0xBB];
        let mut pdu = [0u8; 64];
        let len = enc_write_cmd(0x0001, &value, &mut pdu);
        assert_eq!(len, 5);

        let (handle, dec_value) = dec_write_cmd(&pdu[..len]).unwrap();
        assert_eq!(handle, 0x0001);
        assert_eq!(dec_value, value);
    }

    #[test]
    fn test_enc_dec_exec_write_req() {
        let mut pdu = [0u8; 64];
        let len = enc_exec_write_req(ATT_WRITE_ALL_PREP_WRITES, &mut pdu);
        assert_eq!(len, 2);

        let flags = dec_exec_write_req(&pdu[..len]).unwrap();
        assert_eq!(flags, ATT_WRITE_ALL_PREP_WRITES);
    }

    #[test]
    fn test_enc_exec_write_req_invalid_flags() {
        let mut pdu = [0u8; 64];
        let len = enc_exec_write_req(2, &mut pdu);
        assert_eq!(len, 0);
    }

    #[test]
    fn test_enc_dec_prep_write_req() {
        let value = [0x01, 0x02, 0x03, 0x04];
        let mut pdu = [0u8; 64];
        let len = enc_prep_write_req(0x0042, 0x0010, &value, &mut pdu);
        assert_eq!(len, 9);

        let (handle, offset, dec_value) = dec_prep_write_req(&pdu[..len]).unwrap();
        assert_eq!(handle, 0x0042);
        assert_eq!(offset, 0x0010);
        assert_eq!(dec_value, value);
    }

    #[test]
    fn test_enc_dec_write_resp() {
        let mut pdu = [0u8; 64];
        let len = enc_write_resp(&mut pdu);
        assert_eq!(len, 1);

        assert!(dec_write_resp(&pdu[..len]).is_some());
    }

    #[test]
    fn test_enc_dec_exec_write_resp() {
        let mut pdu = [0u8; 64];
        let len = enc_exec_write_resp(&mut pdu);
        assert_eq!(len, 1);

        assert!(dec_exec_write_resp(&pdu[..len]).is_some());
    }

    #[test]
    fn test_enc_dec_error_resp() {
        let mut pdu = [0u8; 64];
        let len = enc_error_resp(ATT_OP_READ_REQ, 0x0042, ATT_ECODE_ATTR_NOT_FOUND, &mut pdu);
        assert_eq!(len, 5);
        assert_eq!(pdu[0], ATT_OP_ERROR);
        assert_eq!(pdu[1], ATT_OP_READ_REQ);
        assert_eq!(pdu[4], ATT_ECODE_ATTR_NOT_FOUND);
    }

    #[test]
    fn test_enc_dec_confirmation() {
        let mut pdu = [0u8; 64];
        let len = enc_confirmation(&mut pdu);
        assert_eq!(len, 1);
        assert_eq!(pdu[0], ATT_OP_HANDLE_CNF);
    }

    #[test]
    fn test_enc_dec_read_by_grp_req_uuid16() {
        let uuid = BtUuid::from_u16(0x2800);
        let mut pdu = [0u8; 64];
        let len = enc_read_by_grp_req(0x0001, 0xFFFF, &uuid, &mut pdu);
        assert_eq!(len, 7);

        let (start, end, decoded) = dec_read_by_grp_req(&pdu[..len]).unwrap();
        assert_eq!(start, 0x0001);
        assert_eq!(end, 0xFFFF);
        assert_eq!(decoded, uuid);
    }

    #[test]
    fn test_enc_dec_find_by_type_req() {
        let uuid = BtUuid::from_u16(0x2800);
        let value = [0x01, 0x18];
        let mut pdu = [0u8; 64];
        let len = enc_find_by_type_req(0x0001, 0xFFFF, &uuid, &value, &mut pdu);
        assert_eq!(len, 9);

        let req = dec_find_by_type_req(&pdu[..len]).unwrap();
        assert_eq!(req.start, 0x0001);
        assert_eq!(req.end, 0xFFFF);
        assert_eq!(req.uuid, uuid);
        assert_eq!(req.value, value);
    }

    #[test]
    fn test_enc_dec_read_multi_req() {
        let handles = [0x0001u16, 0x0003, 0x0005];
        let mut pdu = [0u8; 64];
        let len = enc_read_multi_req(&handles, &mut pdu);
        assert_eq!(len, 7);
        assert_eq!(pdu[0], ATT_OP_READ_MULTI_REQ);

        // Verify handle values in PDU
        assert_eq!(u16::from_le_bytes([pdu[1], pdu[2]]), 0x0001);
        assert_eq!(u16::from_le_bytes([pdu[3], pdu[4]]), 0x0003);
        assert_eq!(u16::from_le_bytes([pdu[5], pdu[6]]), 0x0005);
    }

    #[test]
    fn test_enc_dec_notification() {
        let value = [0x01, 0x02, 0x03];
        let mut pdu = [0u8; 64];
        let len = enc_notification(0x0042, &value, &mut pdu);
        assert_eq!(len, 6);
        assert_eq!(pdu[0], ATT_OP_HANDLE_NOTIFY);
    }

    #[test]
    fn test_enc_dec_indication() {
        let value = [0x01, 0x02, 0x03];
        let mut pdu = [0u8; 64];
        let len = enc_indication(0x0042, &value, &mut pdu);
        assert_eq!(len, 6);
        assert_eq!(pdu[0], ATT_OP_HANDLE_IND);
    }

    #[test]
    fn test_enc_dec_read_resp() {
        let value = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut pdu = [0u8; 64];
        let len = enc_read_resp(&value, &mut pdu);
        assert_eq!(len, 5);

        let mut buf = [0u8; 64];
        let vlen = dec_read_resp(&pdu[..len], &mut buf).unwrap();
        assert_eq!(vlen, 4);
        assert_eq!(&buf[..vlen], &value);
    }

    #[test]
    fn test_enc_dec_read_by_type_resp() {
        let mut list = AttDataList::new(2, 5);
        if let Some(e) = list.get_mut(0) {
            e.copy_from_slice(&[0x01, 0x00, 0xAA, 0xBB, 0xCC]);
        }
        if let Some(e) = list.get_mut(1) {
            e.copy_from_slice(&[0x02, 0x00, 0xDD, 0xEE, 0xFF]);
        }

        let mut pdu = [0u8; 64];
        let len = enc_read_by_type_resp(&list, &mut pdu);
        assert_eq!(len, 12);

        let dec_list = dec_read_by_type_resp(&pdu[..len]).unwrap();
        assert_eq!(dec_list.num(), 2);
        assert_eq!(dec_list.len(), 5);
        assert_eq!(dec_list.get(0).unwrap(), &[0x01, 0x00, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_enc_dec_read_by_grp_resp() {
        let mut list = AttDataList::new(1, 6);
        if let Some(e) = list.get_mut(0) {
            e.copy_from_slice(&[0x01, 0x00, 0x03, 0x00, 0x00, 0x28]);
        }

        let mut pdu = [0u8; 64];
        let len = enc_read_by_grp_resp(&list, &mut pdu);
        assert_eq!(len, 8);

        let dec_list = dec_read_by_grp_resp(&pdu[..len]).unwrap();
        assert_eq!(dec_list.num(), 1);
        assert_eq!(dec_list.len(), 6);
    }

    #[test]
    fn test_enc_dec_find_info_resp_uuid16() {
        let mut list = AttDataList::new(2, 4);
        if let Some(e) = list.get_mut(0) {
            e.copy_from_slice(&[0x01, 0x00, 0x00, 0x28]);
        }
        if let Some(e) = list.get_mut(1) {
            e.copy_from_slice(&[0x02, 0x00, 0x03, 0x28]);
        }

        let mut pdu = [0u8; 64];
        let len = enc_find_info_resp(ATT_FIND_INFO_RESP_FMT_16BIT, &list, &mut pdu);
        assert_eq!(len, 10);

        let (format, dec_list) = dec_find_info_resp(&pdu[..len]).unwrap();
        assert_eq!(format, ATT_FIND_INFO_RESP_FMT_16BIT);
        assert_eq!(dec_list.num(), 2);
        assert_eq!(dec_list.len(), 4);
    }

    #[test]
    fn test_enc_dec_find_by_type_resp() {
        let mut list = AttDataList::new(2, 4);
        if let Some(e) = list.get_mut(0) {
            e[0..2].copy_from_slice(&0x0001u16.to_le_bytes());
            e[2..4].copy_from_slice(&0x0003u16.to_le_bytes());
        }
        if let Some(e) = list.get_mut(1) {
            e[0..2].copy_from_slice(&0x0010u16.to_le_bytes());
            e[2..4].copy_from_slice(&0x0015u16.to_le_bytes());
        }

        let mut pdu = [0u8; 64];
        let len = enc_find_by_type_resp(&list, &mut pdu);
        assert_eq!(len, 9);

        let dec_list = dec_find_by_type_resp(&pdu[..len]).unwrap();
        assert_eq!(dec_list.num(), 2);
        assert_eq!(dec_list.len(), 4);
    }

    #[test]
    fn test_enc_dec_prep_write_resp() {
        let value = [0x01, 0x02, 0x03];
        let mut pdu = [0u8; 64];
        let len = enc_prep_write_resp(0x0042, 0x0010, &value, &mut pdu);
        assert_eq!(len, 8);

        let (handle, offset, dec_value) = dec_prep_write_resp(&pdu[..len]).unwrap();
        assert_eq!(handle, 0x0042);
        assert_eq!(offset, 0x0010);
        assert_eq!(dec_value, value);
    }

    #[test]
    fn test_enc_read_blob_resp() {
        let value = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut pdu = [0u8; 64];
        let len = enc_read_blob_resp(&value, 2, &mut pdu);
        assert_eq!(len, 4); // opcode(1) + remaining 3 bytes
        assert_eq!(pdu[0], ATT_OP_READ_BLOB_RESP);
        assert_eq!(&pdu[1..4], &[0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_decoder_rejects_wrong_opcode() {
        let pdu = [ATT_OP_MTU_RESP, 0x00, 0x01];
        assert!(dec_mtu_req(&pdu).is_none());

        let pdu = [ATT_OP_MTU_REQ, 0x00, 0x01];
        assert!(dec_mtu_resp(&pdu).is_none());

        let pdu = [0xFF];
        assert!(dec_write_resp(&pdu).is_none());
        assert!(dec_exec_write_resp(&pdu).is_none());
    }

    #[test]
    fn test_decoder_rejects_short_pdu() {
        assert!(dec_mtu_req(&[ATT_OP_MTU_REQ, 0x00]).is_none());
        assert!(dec_find_info_req(&[ATT_OP_FIND_INFO_REQ, 0x00, 0x00, 0x00]).is_none());
        assert!(dec_read_req(&[ATT_OP_READ_REQ, 0x00]).is_none());
        assert!(dec_read_blob_req(&[ATT_OP_READ_BLOB_REQ, 0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_encoder_rejects_small_buffer() {
        let mut pdu = [0u8; 2];
        assert_eq!(enc_mtu_req(512, &mut pdu), 0);
        assert_eq!(enc_find_info_req(1, 2, &mut pdu), 0);
        assert_eq!(enc_read_req(1, &mut pdu), 0);
    }

    #[test]
    fn test_att_range() {
        let range = AttRange { start: 1, end: 10 };
        let range2 = range;
        assert_eq!(range, range2);
        assert_eq!(range.start, 1);
        assert_eq!(range.end, 10);
    }

    #[test]
    fn test_opcode_constants() {
        assert_eq!(ATT_OP_ERROR, 0x01);
        assert_eq!(ATT_OP_MTU_REQ, 0x02);
        assert_eq!(ATT_OP_MTU_RESP, 0x03);
        assert_eq!(ATT_OP_FIND_INFO_REQ, 0x04);
        assert_eq!(ATT_OP_FIND_INFO_RESP, 0x05);
        assert_eq!(ATT_OP_FIND_BY_TYPE_REQ, 0x06);
        assert_eq!(ATT_OP_FIND_BY_TYPE_RESP, 0x07);
        assert_eq!(ATT_OP_READ_BY_TYPE_REQ, 0x08);
        assert_eq!(ATT_OP_READ_BY_TYPE_RESP, 0x09);
        assert_eq!(ATT_OP_READ_REQ, 0x0A);
        assert_eq!(ATT_OP_READ_RESP, 0x0B);
        assert_eq!(ATT_OP_READ_BLOB_REQ, 0x0C);
        assert_eq!(ATT_OP_READ_BLOB_RESP, 0x0D);
        assert_eq!(ATT_OP_READ_MULTI_REQ, 0x0E);
        assert_eq!(ATT_OP_READ_MULTI_RESP, 0x0F);
        assert_eq!(ATT_OP_READ_BY_GROUP_REQ, 0x10);
        assert_eq!(ATT_OP_READ_BY_GROUP_RESP, 0x11);
        assert_eq!(ATT_OP_WRITE_REQ, 0x12);
        assert_eq!(ATT_OP_WRITE_RESP, 0x13);
        assert_eq!(ATT_OP_WRITE_CMD, 0x52);
        assert_eq!(ATT_OP_PREP_WRITE_REQ, 0x16);
        assert_eq!(ATT_OP_PREP_WRITE_RESP, 0x17);
        assert_eq!(ATT_OP_EXEC_WRITE_REQ, 0x18);
        assert_eq!(ATT_OP_EXEC_WRITE_RESP, 0x19);
        assert_eq!(ATT_OP_HANDLE_NOTIFY, 0x1B);
        assert_eq!(ATT_OP_HANDLE_IND, 0x1D);
        assert_eq!(ATT_OP_HANDLE_CNF, 0x1E);
        assert_eq!(ATT_OP_SIGNED_WRITE_CMD, 0xD2);
    }

    #[test]
    fn test_error_code_constants() {
        assert_eq!(ATT_ECODE_INVALID_HANDLE, 0x01);
        assert_eq!(ATT_ECODE_READ_NOT_PERM, 0x02);
        assert_eq!(ATT_ECODE_WRITE_NOT_PERM, 0x03);
        assert_eq!(ATT_ECODE_INVALID_PDU, 0x04);
        assert_eq!(ATT_ECODE_AUTHENTICATION, 0x05);
        assert_eq!(ATT_ECODE_REQ_NOT_SUPP, 0x06);
        assert_eq!(ATT_ECODE_INVALID_OFFSET, 0x07);
        assert_eq!(ATT_ECODE_AUTHORIZATION, 0x08);
        assert_eq!(ATT_ECODE_PREP_QUEUE_FULL, 0x09);
        assert_eq!(ATT_ECODE_ATTR_NOT_FOUND, 0x0A);
        assert_eq!(ATT_ECODE_ATTR_NOT_LONG, 0x0B);
        assert_eq!(ATT_ECODE_INSUFF_ENCR_KEY_SIZE, 0x0C);
        assert_eq!(ATT_ECODE_INVALID_VALUE_LEN, 0x0D);
        assert_eq!(ATT_ECODE_UNLIKELY, 0x0E);
        assert_eq!(ATT_ECODE_INSUFF_ENC, 0x0F);
        assert_eq!(ATT_ECODE_UNSUPP_GRP_TYPE, 0x10);
        assert_eq!(ATT_ECODE_INSUFF_RESOURCES, 0x11);
        assert_eq!(ATT_ECODE_IO, 0x80);
        assert_eq!(ATT_ECODE_TIMEOUT, 0x81);
        assert_eq!(ATT_ECODE_ABORTED, 0x82);
    }

    #[test]
    fn test_size_constants() {
        assert_eq!(ATT_SIGNATURE_LEN, 12);
        assert_eq!(ATT_MAX_VALUE_LEN, 512);
        assert_eq!(ATT_DEFAULT_L2CAP_MTU, 48);
        assert_eq!(ATT_DEFAULT_LE_MTU, 23);
    }
}
