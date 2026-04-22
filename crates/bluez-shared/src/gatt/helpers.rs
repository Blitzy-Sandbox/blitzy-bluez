//! GATT Discovery Utilities
//!
//! Port of `src/shared/gatt-helpers.c` and `gatt-helpers.h` providing
//! ATT-backed discovery procedures and result iterators for GATT
//! service, characteristic, and descriptor discovery operations.
//!
//! All discovery operations are async and use paginated ATT requests
//! to discover services, characteristics, descriptors, and included
//! services over a BLE connection.

use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::att::transport::{AttResponseCallback, BtAtt};
use crate::att::types;
use crate::util::endian;
use crate::util::uuid::BtUuid;

// ─── GATT Service Type UUID Constants ───────────────────────────────

/// Primary Service Declaration UUID (0x2800).
const GATT_PRIM_SVC_UUID: u16 = 0x2800;

/// Secondary Service Declaration UUID (0x2801).
const GATT_SND_SVC_UUID: u16 = 0x2801;

/// Include Declaration UUID (0x2802).
const GATT_INCLUDE_UUID: u16 = 0x2802;

/// Characteristic Declaration UUID (0x2803).
const GATT_CHARAC_UUID: u16 = 0x2803;

// ─── Error Type ─────────────────────────────────────────────────────

/// Errors that can occur during GATT discovery operations.
#[derive(Debug, Error)]
pub enum GattError {
    /// ATT protocol error with the specific error code.
    #[error("ATT error: 0x{0:02x}")]
    AttError(u8),

    /// Received an invalid or malformed ATT PDU.
    #[error("Invalid PDU received")]
    InvalidPdu,

    /// The operation timed out waiting for a response.
    #[error("Operation timed out")]
    Timeout,

    /// An error occurred on the underlying ATT transport.
    #[error("Transport error: {0}")]
    TransportError(String),
}

// ─── Entry Types (Iterator Results) ─────────────────────────────────

/// A discovered GATT service entry.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    /// Start handle of the service attribute group.
    pub start_handle: u16,
    /// End handle of the service attribute group.
    pub end_handle: u16,
    /// Service UUID. For `FIND_BY_TYPE_RSP` results this is a zero UUID
    /// since the UUID was already known from the request filter.
    pub uuid: BtUuid,
}

/// A discovered GATT characteristic entry.
#[derive(Debug, Clone)]
pub struct CharEntry {
    /// Handle of the characteristic declaration attribute.
    pub start_handle: u16,
    /// End handle of the characteristic (next start − 1 or service end).
    pub end_handle: u16,
    /// Handle of the characteristic value attribute.
    pub value_handle: u16,
    /// Characteristic properties bitmask.
    pub properties: u8,
    /// Characteristic UUID.
    pub uuid: BtUuid,
}

/// A discovered GATT descriptor entry.
#[derive(Debug, Clone)]
pub struct DescEntry {
    /// Handle of the descriptor attribute.
    pub handle: u16,
    /// Descriptor UUID.
    pub uuid: BtUuid,
}

/// A discovered included service entry.
#[derive(Debug, Clone)]
pub struct InclEntry {
    /// Handle of the include declaration attribute.
    pub handle: u16,
    /// Start handle of the included service.
    pub start_handle: u16,
    /// End handle of the included service.
    pub end_handle: u16,
    /// UUID of the included service.  `None` when UUID128 resolution
    /// was not possible (e.g. the `READ_RSP` was missing or malformed).
    pub uuid: Option<BtUuid>,
}

/// A generic Read By Type result entry.
pub struct ReadByTypeEntry<'a> {
    /// Attribute handle.
    pub handle: u16,
    /// Attribute value data (borrowed from the result buffer).
    pub value: &'a [u8],
}

// ─── Result Storage ─────────────────────────────────────────────────

/// An individual ATT response PDU chunk within a discovery result.
#[derive(Debug, Clone)]
struct GattResultChunk {
    /// ATT response opcode (e.g. `READ_BY_GRP_TYPE_RSP`).
    opcode: u8,
    /// Raw entry data (entries only, opcode-specific headers stripped).
    pdu: Vec<u8>,
    /// Size of each individual entry within the PDU.
    data_len: u16,
}

/// Accumulated result of a GATT discovery operation.
///
/// Contains one or more PDU chunks collected during paginated discovery.
/// Iterate over results using [`BtGattIter`].
#[derive(Debug, Clone)]
pub struct BtGattResult {
    /// Collected response PDU chunks.
    chunks: Vec<GattResultChunk>,
    /// End handle of the discovery range, used for characteristic
    /// end-handle calculation in the iterator.
    discovery_end: u16,
}

impl BtGattResult {
    /// Create a new empty result with the given discovery end handle.
    fn new(discovery_end: u16) -> Self {
        Self { chunks: Vec::new(), discovery_end }
    }

    /// Append a new PDU chunk to this result.
    fn append(&mut self, opcode: u8, pdu: &[u8], data_len: u16) {
        self.chunks.push(GattResultChunk { opcode, pdu: pdu.to_vec(), data_len });
    }

    /// Count the total number of entries across all chunks.
    fn element_count(&self) -> usize {
        self.chunks
            .iter()
            .filter(|c| c.data_len > 0)
            .map(|c| c.pdu.len() / c.data_len as usize)
            .sum()
    }

    /// Returns the number of service entries in this result.
    pub fn service_count(&self) -> usize {
        self.element_count()
    }

    /// Returns the number of characteristic entries in this result.
    pub fn characteristic_count(&self) -> usize {
        self.element_count()
    }

    /// Returns the number of descriptor entries in this result.
    pub fn descriptor_count(&self) -> usize {
        self.element_count()
    }

    /// Returns the number of included service entries in this result.
    pub fn included_count(&self) -> usize {
        self.element_count()
    }
}

// ─── Iterator ───────────────────────────────────────────────────────

/// Iterator over GATT discovery results.
///
/// Provides methods to iterate over services, characteristics,
/// descriptors, included services, and generic Read By Type results.
pub struct BtGattIter<'a> {
    /// Reference to the result being iterated.
    result: &'a BtGattResult,
    /// Index of the current chunk in the result.
    chunk_idx: usize,
    /// Byte offset within the current chunk's PDU data.
    pos: usize,
}

impl<'a> BtGattIter<'a> {
    /// Create a new iterator positioned at the start of the result.
    pub fn init(result: &'a BtGattResult) -> Self {
        Self { result, chunk_idx: 0, pos: 0 }
    }

    /// Get a reference to the current chunk, if any remain.
    fn current_chunk(&self) -> Option<&'a GattResultChunk> {
        self.result.chunks.get(self.chunk_idx)
    }

    /// Advance to the next chunk, resetting the byte position.
    fn advance_chunk(&mut self) {
        self.chunk_idx += 1;
        self.pos = 0;
    }

    /// Advance the byte position within the current chunk.
    /// If the position reaches or exceeds the chunk's PDU length,
    /// automatically advances to the next chunk.
    fn advance_pos(&mut self, bytes: usize) {
        self.pos += bytes;
        if let Some(chunk) = self.result.chunks.get(self.chunk_idx) {
            if self.pos >= chunk.pdu.len() {
                self.advance_chunk();
            }
        }
    }

    /// Peek at the start handle of the next characteristic entry to
    /// calculate the current characteristic's end handle.
    fn peek_next_char_start(&self, current_data_len: usize) -> Option<u16> {
        let chunk = self.current_chunk()?;
        let next_pos = self.pos + current_data_len;

        if next_pos + 2 <= chunk.pdu.len() {
            // Next entry exists within the same chunk.
            Some(endian::get_le16(&chunk.pdu[next_pos..next_pos + 2]))
        } else {
            // Look at the first entry of the next chunk.
            let next_chunk = self.result.chunks.get(self.chunk_idx + 1)?;
            if next_chunk.opcode == types::BT_ATT_OP_READ_BY_TYPE_RSP && next_chunk.pdu.len() >= 2 {
                Some(endian::get_le16(&next_chunk.pdu[0..2]))
            } else {
                None
            }
        }
    }

    /// Iterate to the next service entry.
    ///
    /// Handles both `READ_BY_GRP_TYPE_RSP` (opcode 0x11) and
    /// `FIND_BY_TYPE_RSP` (opcode 0x07) response chunks.
    pub fn next_service(&mut self) -> Option<ServiceEntry> {
        let chunk = self.current_chunk()?;

        match chunk.opcode {
            types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP => {
                let data_len = chunk.data_len as usize;
                if data_len < 4 || self.pos + data_len > chunk.pdu.len() {
                    return None;
                }
                let pdu = &chunk.pdu[self.pos..];
                let start_handle = endian::get_le16(&pdu[0..2]);
                let end_handle = endian::get_le16(&pdu[2..4]);
                let uuid = parse_uuid_from_pdu(&pdu[4..data_len]);

                self.advance_pos(data_len);
                Some(ServiceEntry { start_handle, end_handle, uuid })
            }
            types::BT_ATT_OP_FIND_BY_TYPE_RSP => {
                if self.pos + 4 > chunk.pdu.len() {
                    return None;
                }
                let pdu = &chunk.pdu[self.pos..];
                let start_handle = endian::get_le16(&pdu[0..2]);
                let end_handle = endian::get_le16(&pdu[2..4]);

                self.advance_pos(4);
                // FIND_BY_TYPE_RSP does not include UUID — the caller
                // already knows it from the request filter.
                Some(ServiceEntry { start_handle, end_handle, uuid: BtUuid::Uuid128([0u8; 16]) })
            }
            _ => None,
        }
    }

    /// Iterate to the next characteristic entry.
    ///
    /// Handles `READ_BY_TYPE_RSP` (opcode 0x09) with `data_len` 7
    /// (UUID16) or 21 (UUID128).  Calculates `end_handle` by peeking
    /// at the next entry or falling back to the discovery range end.
    pub fn next_characteristic(&mut self) -> Option<CharEntry> {
        let chunk = self.current_chunk()?;
        if chunk.opcode != types::BT_ATT_OP_READ_BY_TYPE_RSP {
            return None;
        }
        let data_len = chunk.data_len as usize;
        // Minimum: handle(2) + properties(1) + value_handle(2) + UUID16(2)
        if data_len < 7 || self.pos + data_len > chunk.pdu.len() {
            return None;
        }
        let pdu = &chunk.pdu[self.pos..];
        let start_handle = endian::get_le16(&pdu[0..2]);
        let properties = endian::get_u8(&pdu[2..3]);
        let value_handle = endian::get_le16(&pdu[3..5]);
        let uuid = parse_uuid_from_pdu(&pdu[5..data_len]);

        // Calculate end_handle: next characteristic's start - 1, or
        // the discovery range end if this is the last characteristic.
        let end_handle = self
            .peek_next_char_start(data_len)
            .map_or(self.result.discovery_end, |next_start| next_start.saturating_sub(1));

        self.advance_pos(data_len);
        Some(CharEntry { start_handle, end_handle, value_handle, properties, uuid })
    }

    /// Iterate to the next descriptor entry.
    ///
    /// Handles `FIND_INFO_RSP` (opcode 0x05).  Entry size depends on
    /// `data_len`: 4 bytes for UUID16 (format 0x01) or 18 bytes for
    /// UUID128 (format 0x02).
    pub fn next_descriptor(&mut self) -> Option<DescEntry> {
        let chunk = self.current_chunk()?;
        if chunk.opcode != types::BT_ATT_OP_FIND_INFO_RSP {
            return None;
        }
        let data_len = chunk.data_len as usize;
        if data_len < 4 || self.pos + data_len > chunk.pdu.len() {
            return None;
        }
        let pdu = &chunk.pdu[self.pos..];
        let handle = endian::get_le16(&pdu[0..2]);
        let uuid = parse_uuid_from_pdu(&pdu[2..data_len]);

        self.advance_pos(data_len);
        Some(DescEntry { handle, uuid })
    }

    /// Iterate to the next included service entry.
    ///
    /// Handles `READ_BY_TYPE_RSP` (opcode 0x09) with `data_len` 8
    /// (inline UUID16) or 6 (UUID128 resolved via chained `READ_RSP`).
    pub fn next_included_service(&mut self) -> Option<InclEntry> {
        let chunk = self.current_chunk()?;
        if chunk.opcode != types::BT_ATT_OP_READ_BY_TYPE_RSP {
            return None;
        }
        let data_len = chunk.data_len as usize;
        if self.pos + data_len > chunk.pdu.len() {
            return None;
        }
        let pdu = &chunk.pdu[self.pos..];

        match data_len {
            8 => {
                // Inline UUID16: handle(2)+start(2)+end(2)+UUID16(2)
                let handle = endian::get_le16(&pdu[0..2]);
                let start_handle = endian::get_le16(&pdu[2..4]);
                let end_handle = endian::get_le16(&pdu[4..6]);
                let uuid = parse_uuid_from_pdu(&pdu[6..8]);

                self.advance_pos(8);
                Some(InclEntry { handle, start_handle, end_handle, uuid: Some(uuid) })
            }
            6 => {
                // No inline UUID: handle(2)+start(2)+end(2)
                let handle = endian::get_le16(&pdu[0..2]);
                let start_handle = endian::get_le16(&pdu[2..4]);
                let end_handle = endian::get_le16(&pdu[4..6]);

                self.advance_pos(6);

                // The next chunk should be a READ_RSP with the UUID.
                let uuid = self.current_chunk().and_then(|c| {
                    if c.opcode == types::BT_ATT_OP_READ_RSP {
                        Some(parse_uuid_from_pdu(&c.pdu))
                    } else {
                        None
                    }
                });

                // Advance past the READ_RSP chunk if it was consumed.
                if uuid.is_some() {
                    self.advance_chunk();
                }

                Some(InclEntry { handle, start_handle, end_handle, uuid })
            }
            _ => None,
        }
    }

    /// Iterate to the next generic Read By Type entry.
    ///
    /// Returns the attribute handle and raw value bytes.
    pub fn next_read_by_type(&mut self) -> Option<ReadByTypeEntry<'a>> {
        let chunk = self.current_chunk()?;
        if chunk.opcode != types::BT_ATT_OP_READ_BY_TYPE_RSP {
            return None;
        }
        let data_len = chunk.data_len as usize;
        // Minimum: handle(2) + at least one value byte
        if data_len < 3 || self.pos + data_len > chunk.pdu.len() {
            return None;
        }
        let pdu = &chunk.pdu[self.pos..];
        let handle = endian::get_le16(&pdu[0..2]);
        let value = &pdu[2..data_len];

        self.advance_pos(data_len);
        Some(ReadByTypeEntry { handle, value })
    }
}

// ─── Request Management ─────────────────────────────────────────────

/// Handle for a completed GATT discovery operation.
///
/// Provides access to the accumulated results and metadata about the
/// discovery range.  In async mode `cancel()` cancels any residual ATT
/// operation associated with the last pagination step.
pub struct BtGattRequest {
    /// Reference to the ATT transport.
    att: Arc<Mutex<BtAtt>>,
    /// Last ATT operation identifier (may already be completed).
    att_id: u32,
    /// Accumulated discovery results.
    result: BtGattResult,
    /// Start handle of the discovery range.
    start: u16,
    /// End handle of the discovery range.
    end: u16,
}

impl BtGattRequest {
    /// Cancel any pending ATT operation associated with this request.
    ///
    /// After an async discovery completes the ATT operation is already
    /// finished and this is a defensive no-op.  It is still useful if a
    /// discovery is aborted mid-flight through task cancellation.
    pub fn cancel(&self) {
        if self.att_id != 0 {
            if let Ok(mut guard) = self.att.lock() {
                guard.cancel(self.att_id);
            }
        }
    }

    /// Borrow the accumulated discovery result.
    pub fn result(&self) -> &BtGattResult {
        &self.result
    }

    /// Get the start handle of the discovery range.
    pub fn start_handle(&self) -> u16 {
        self.start
    }

    /// Get the end handle of the discovery range.
    pub fn end_handle(&self) -> u16 {
        self.end
    }
}

// ─── Internal Helpers ───────────────────────────────────────────────

/// Parse a UUID from raw little-endian wire-format PDU bytes.
///
/// Supports 2-byte (UUID16) and 16-byte (UUID128) formats.
fn parse_uuid_from_pdu(data: &[u8]) -> BtUuid {
    match data.len() {
        2 => BtUuid::from_u16(endian::get_le16(data)),
        16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(data);
            BtUuid::Uuid128(bytes)
        }
        _ => {
            tracing::warn!("Unexpected UUID length {} bytes", data.len());
            BtUuid::Uuid128([0u8; 16])
        }
    }
}

/// Convert a [`BtUuid`] to its little-endian wire-format bytes.
fn uuid_to_le_bytes(uuid: &BtUuid) -> Vec<u8> {
    match uuid {
        BtUuid::Uuid16(val) => val.to_le_bytes().to_vec(),
        BtUuid::Uuid32(val) => val.to_le_bytes().to_vec(),
        BtUuid::Uuid128(bytes) => bytes.to_vec(),
    }
}

/// Parse an ATT Error Response PDU and extract the error code.
///
/// PDU layout: `request_opcode(1) + handle_le(2) + error_code(1)`.
fn parse_error_rsp(pdu: &[u8]) -> Result<u8, GattError> {
    if pdu.len() < 4 {
        return Err(GattError::InvalidPdu);
    }
    // Log the failed request opcode when a known variant exists.
    let req_opcode = pdu[0];
    if let Ok(op) = types::AttOpcode::try_from(req_opcode) {
        tracing::debug!("ATT error response for {:?}", op);
    }
    Ok(pdu[3])
}

/// Send an ATT request and asynchronously await the response.
///
/// Uses a `tokio::sync::oneshot` channel to bridge the callback-based
/// [`BtAtt::send()`] API to an async interface.  Returns the response
/// opcode, a *copy* of the response PDU data, and the ATT operation id.
async fn send_att_request(
    att: &Arc<Mutex<BtAtt>>,
    opcode: u8,
    pdu: &[u8],
) -> Result<(u8, Vec<u8>, u32), GattError> {
    let (tx, rx) = tokio::sync::oneshot::channel::<(u8, Vec<u8>)>();

    let callback: AttResponseCallback = Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
        let _ = tx.send((rsp_opcode, rsp_pdu.to_vec()));
    }));

    let id = {
        let mut guard =
            att.lock().map_err(|_| GattError::TransportError("ATT mutex poisoned".into()))?;
        guard.send(opcode, pdu, callback)
    };

    if id == 0 {
        return Err(GattError::TransportError("Failed to send ATT request".into()));
    }

    let (rsp_op, rsp_data) = rx.await.map_err(|_| GattError::Timeout)?;
    Ok((rsp_op, rsp_data, id))
}

/// Check whether an ATT error code represents `ATTRIBUTE_NOT_FOUND`,
/// using the typed [`types::AttError`] enum for validation.
fn is_attribute_not_found(ecode: u8) -> bool {
    ecode == types::BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND
}

// ─── Discovery Operations ───────────────────────────────────────────

/// Exchange ATT MTU with the remote device.
///
/// Sends an Exchange MTU Request and returns the negotiated MTU value
/// (minimum of client and server MTU, at least
/// [`types::BT_ATT_DEFAULT_LE_MTU`]).  Updates the ATT transport's MTU.
pub async fn exchange_mtu(att: &Arc<Mutex<BtAtt>>, client_mtu: u16) -> Result<u16, GattError> {
    // Read the current MTU for diagnostic logging.
    let current_mtu = {
        let guard =
            att.lock().map_err(|_| GattError::TransportError("ATT mutex poisoned".into()))?;
        guard.get_mtu()
    };
    tracing::debug!("Exchange MTU: current={}, requesting={}", current_mtu, client_mtu,);

    let mut pdu = [0u8; 2];
    endian::put_le16(client_mtu, &mut pdu);

    let (rsp_opcode, rsp_pdu, _id) = send_att_request(att, types::BT_ATT_OP_MTU_REQ, &pdu).await?;

    if rsp_opcode == types::BT_ATT_OP_ERROR_RSP {
        let ecode = parse_error_rsp(&rsp_pdu)?;
        return Err(GattError::AttError(ecode));
    }

    if rsp_opcode != types::BT_ATT_OP_MTU_RSP || rsp_pdu.len() < 2 {
        return Err(GattError::InvalidPdu);
    }

    let server_mtu = endian::get_le16(&rsp_pdu[0..2]);
    let negotiated = core::cmp::min(client_mtu, server_mtu);
    let final_mtu = core::cmp::max(negotiated, types::BT_ATT_DEFAULT_LE_MTU);

    // Update ATT transport with the negotiated MTU.
    {
        let mut guard =
            att.lock().map_err(|_| GattError::TransportError("ATT mutex poisoned".into()))?;
        guard.set_mtu(final_mtu);
    }

    tracing::debug!(
        "MTU exchanged: client={}, server={}, final={}",
        client_mtu,
        server_mtu,
        final_mtu,
    );

    Ok(final_mtu)
}

/// Discover all primary services, optionally filtered by UUID.
///
/// If `uuid` is `None` a `READ_BY_GRP_TYPE_REQ` is sent for
/// `GATT_PRIM_SVC_UUID`.  If `uuid` is `Some(...)` a
/// `FIND_BY_TYPE_REQ` is used to filter by the exact service UUID on
/// the server side.  Results are paginated until `0xFFFF` is reached or
/// the server returns `ATTRIBUTE_NOT_FOUND`.
pub async fn discover_all_primary_services(
    att: &Arc<Mutex<BtAtt>>,
    uuid: Option<&BtUuid>,
) -> Result<BtGattRequest, GattError> {
    discover_primary_services(att, uuid, 0x0001, 0xFFFF).await
}

/// Discover primary services within a bounded handle range.
///
/// When `uuid` is `None`, uses `READ_BY_GRP_TYPE_REQ` with
/// `GATT_PRIM_SVC_UUID` (0x2800).  When `uuid` is `Some(...)`, uses
/// `FIND_BY_TYPE_REQ` with the UUID value for server-side filtering.
pub async fn discover_primary_services(
    att: &Arc<Mutex<BtAtt>>,
    uuid: Option<&BtUuid>,
    start: u16,
    end: u16,
) -> Result<BtGattRequest, GattError> {
    if start == 0 || start > end {
        return Err(GattError::InvalidPdu);
    }

    tracing::debug!(
        "Discover primary services: start=0x{:04X}, end=0x{:04X}, uuid={:?}",
        start,
        end,
        uuid,
    );

    let mut result = BtGattResult::new(end);
    let mut current_start = start;
    let mut last_att_id: u32;

    loop {
        let (rsp_opcode, rsp_pdu, att_id) = if let Some(filter_uuid) = uuid {
            // FIND_BY_TYPE_REQ: start(2) + end(2) + attr_type(2) + value(2 or 16)
            let uuid_bytes = uuid_to_le_bytes(filter_uuid);
            let pdu_len = 6 + uuid_bytes.len();
            let mut pdu = vec![0u8; pdu_len];
            endian::put_le16(current_start, &mut pdu[0..2]);
            endian::put_le16(end, &mut pdu[2..4]);
            // GATT_PRIM_SVC_UUID as the attribute type being searched
            endian::put_le16(GATT_PRIM_SVC_UUID, &mut pdu[4..6]);
            pdu[6..pdu_len].copy_from_slice(&uuid_bytes);

            send_att_request(att, types::BT_ATT_OP_FIND_BY_TYPE_REQ, &pdu).await?
        } else {
            // READ_BY_GRP_TYPE_REQ: start(2) + end(2) + UUID16(2)
            let mut pdu = [0u8; 6];
            endian::put_le16(current_start, &mut pdu[0..2]);
            endian::put_le16(end, &mut pdu[2..4]);
            endian::put_le16(GATT_PRIM_SVC_UUID, &mut pdu[4..6]);

            send_att_request(att, types::BT_ATT_OP_READ_BY_GRP_TYPE_REQ, &pdu).await?
        };

        last_att_id = att_id;

        // Handle error response
        if rsp_opcode == types::BT_ATT_OP_ERROR_RSP {
            let ecode = parse_error_rsp(&rsp_pdu)?;
            if is_attribute_not_found(ecode) && !result.chunks.is_empty() {
                // Successful termination: no more attributes to find.
                break;
            }
            return Err(GattError::AttError(ecode));
        }

        if uuid.is_some() {
            // FIND_BY_TYPE_RSP: entries of 4 bytes each (start_handle + end_handle)
            if rsp_opcode != types::BT_ATT_OP_FIND_BY_TYPE_RSP {
                return Err(GattError::InvalidPdu);
            }
            if rsp_pdu.is_empty() || rsp_pdu.len() % 4 != 0 {
                return Err(GattError::InvalidPdu);
            }
            let last_end = endian::get_le16(&rsp_pdu[rsp_pdu.len() - 2..rsp_pdu.len()]);
            result.append(rsp_opcode, &rsp_pdu, 4);

            if last_end >= end || last_end == 0xFFFF {
                break;
            }
            current_start = last_end.saturating_add(1);
        } else {
            // READ_BY_GRP_TYPE_RSP: data_len(1) + entries
            if rsp_opcode != types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP {
                return Err(GattError::InvalidPdu);
            }
            if rsp_pdu.is_empty() {
                return Err(GattError::InvalidPdu);
            }
            let data_len = rsp_pdu[0] as usize;
            if data_len < 4 {
                return Err(GattError::InvalidPdu);
            }
            let body = &rsp_pdu[1..];
            if body.is_empty() || body.len() % data_len != 0 {
                return Err(GattError::InvalidPdu);
            }
            // Last entry's end_handle for pagination
            let last_end =
                endian::get_le16(&body[body.len() - data_len + 2..body.len() - data_len + 4]);
            result.append(rsp_opcode, body, data_len as u16);

            if last_end >= end || last_end == 0xFFFF {
                break;
            }
            current_start = last_end.saturating_add(1);
        }

        if current_start > end {
            break;
        }
    }

    tracing::debug!("Primary service discovery complete: {} chunk(s)", result.chunks.len(),);

    Ok(BtGattRequest { att: Arc::clone(att), att_id: last_att_id, result, start, end })
}

/// Discover secondary services within a bounded handle range.
///
/// Uses `READ_BY_GRP_TYPE_REQ` with `GATT_SND_SVC_UUID` (0x2801).
/// Optionally filters results by `uuid` client-side (the ATT protocol
/// does not support server-side filtering for secondary services).
pub async fn discover_secondary_services(
    att: &Arc<Mutex<BtAtt>>,
    uuid: Option<&BtUuid>,
    start: u16,
    end: u16,
) -> Result<BtGattRequest, GattError> {
    if start == 0 || start > end {
        return Err(GattError::InvalidPdu);
    }

    tracing::debug!("Discover secondary services: start=0x{:04X}, end=0x{:04X}", start, end,);

    let mut result = BtGattResult::new(end);
    let mut current_start = start;
    let mut last_att_id: u32;

    loop {
        // READ_BY_GRP_TYPE_REQ: start(2) + end(2) + UUID16(2)
        let mut pdu = [0u8; 6];
        endian::put_le16(current_start, &mut pdu[0..2]);
        endian::put_le16(end, &mut pdu[2..4]);
        endian::put_le16(GATT_SND_SVC_UUID, &mut pdu[4..6]);

        let (rsp_opcode, rsp_pdu, att_id) =
            send_att_request(att, types::BT_ATT_OP_READ_BY_GRP_TYPE_REQ, &pdu).await?;

        last_att_id = att_id;

        if rsp_opcode == types::BT_ATT_OP_ERROR_RSP {
            let ecode = parse_error_rsp(&rsp_pdu)?;
            if is_attribute_not_found(ecode) && !result.chunks.is_empty() {
                break;
            }
            return Err(GattError::AttError(ecode));
        }

        if rsp_opcode != types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP {
            return Err(GattError::InvalidPdu);
        }
        if rsp_pdu.is_empty() {
            return Err(GattError::InvalidPdu);
        }

        let data_len = rsp_pdu[0] as usize;
        if data_len < 4 {
            return Err(GattError::InvalidPdu);
        }
        let body = &rsp_pdu[1..];
        if body.is_empty() || body.len() % data_len != 0 {
            return Err(GattError::InvalidPdu);
        }

        let last_end =
            endian::get_le16(&body[body.len() - data_len + 2..body.len() - data_len + 4]);

        // Client-side UUID filter: only append entries that match.
        if let Some(filter_uuid) = uuid {
            let filter_bytes = filter_uuid.to_uuid128_bytes();
            for chunk_start in (0..body.len()).step_by(data_len) {
                let entry = &body[chunk_start..chunk_start + data_len];
                let entry_uuid = parse_uuid_from_pdu(&entry[4..]);
                let entry_bytes = entry_uuid.to_uuid128_bytes();
                if entry_bytes == filter_bytes {
                    result.append(rsp_opcode, entry, data_len as u16);
                }
            }
        } else {
            result.append(rsp_opcode, body, data_len as u16);
        }

        if last_end >= end || last_end == 0xFFFF {
            break;
        }
        current_start = last_end.saturating_add(1);
        if current_start > end {
            break;
        }
    }

    tracing::debug!("Secondary service discovery complete: {} chunk(s)", result.chunks.len(),);

    Ok(BtGattRequest { att: Arc::clone(att), att_id: last_att_id, result, start, end })
}

/// Discover included services within a bounded handle range.
///
/// Uses `READ_BY_TYPE_REQ` with `GATT_INCLUDE_UUID` (0x2802).  When
/// the server returns 6-byte entries (UUID128 included service), a
/// secondary `READ_REQ` is issued for each entry to resolve the full
/// 128-bit UUID.  The resolved UUID is stored in a separate
/// `READ_RSP` chunk immediately following the entry chunk.
pub async fn discover_included_services(
    att: &Arc<Mutex<BtAtt>>,
    start: u16,
    end: u16,
) -> Result<BtGattRequest, GattError> {
    if start == 0 || start > end {
        return Err(GattError::InvalidPdu);
    }

    tracing::debug!("Discover included services: start=0x{:04X}, end=0x{:04X}", start, end,);

    let mut result = BtGattResult::new(end);
    let mut current_start = start;
    let mut last_att_id: u32;

    loop {
        // READ_BY_TYPE_REQ: start(2) + end(2) + UUID16(2)
        let mut pdu = [0u8; 6];
        endian::put_le16(current_start, &mut pdu[0..2]);
        endian::put_le16(end, &mut pdu[2..4]);
        endian::put_le16(GATT_INCLUDE_UUID, &mut pdu[4..6]);

        let (rsp_opcode, rsp_pdu, att_id) =
            send_att_request(att, types::BT_ATT_OP_READ_BY_TYPE_REQ, &pdu).await?;

        last_att_id = att_id;

        if rsp_opcode == types::BT_ATT_OP_ERROR_RSP {
            let ecode = parse_error_rsp(&rsp_pdu)?;
            if is_attribute_not_found(ecode) && !result.chunks.is_empty() {
                break;
            }
            return Err(GattError::AttError(ecode));
        }

        if rsp_opcode != types::BT_ATT_OP_READ_BY_TYPE_RSP {
            return Err(GattError::InvalidPdu);
        }
        if rsp_pdu.is_empty() {
            return Err(GattError::InvalidPdu);
        }

        let data_len = rsp_pdu[0] as usize;
        let body = &rsp_pdu[1..];
        if body.is_empty() || body.len() % data_len != 0 {
            return Err(GattError::InvalidPdu);
        }

        let entry_count = body.len() / data_len;
        let last_handle =
            endian::get_le16(&body[(entry_count - 1) * data_len..(entry_count - 1) * data_len + 2]);

        if data_len == 6 {
            // UUID128: need READ_REQ for each entry to resolve UUID.
            for i in 0..entry_count {
                let offset = i * data_len;
                let entry = &body[offset..offset + data_len];
                // Store one entry per chunk so the iterator can
                // alternate between READ_BY_TYPE_RSP and READ_RSP.
                result.append(rsp_opcode, entry, data_len as u16);

                // READ_REQ to resolve the included service UUID.
                let incl_start = endian::get_le16(&entry[2..4]);
                let mut read_pdu = [0u8; 2];
                endian::put_le16(incl_start, &mut read_pdu);

                let (read_rsp_op, read_rsp_data, read_att_id) =
                    send_att_request(att, types::BT_ATT_OP_READ_REQ, &read_pdu).await?;
                last_att_id = read_att_id;

                if read_rsp_op == types::BT_ATT_OP_ERROR_RSP {
                    let ecode = parse_error_rsp(&read_rsp_data)?;
                    return Err(GattError::AttError(ecode));
                }
                if read_rsp_op != types::BT_ATT_OP_READ_RSP {
                    return Err(GattError::InvalidPdu);
                }
                // Store the READ_RSP UUID data as a separate chunk.
                result.append(
                    read_rsp_op,
                    &read_rsp_data,
                    0, // data_len is unused for READ_RSP chunks
                );
            }
        } else if data_len == 8 {
            // UUID16 inline — store directly.
            result.append(rsp_opcode, body, data_len as u16);
        } else {
            return Err(GattError::InvalidPdu);
        }

        if last_handle >= end || last_handle == 0xFFFF {
            break;
        }
        current_start = last_handle.saturating_add(1);
        if current_start > end {
            break;
        }
    }

    tracing::debug!("Included service discovery complete: {} chunk(s)", result.chunks.len(),);

    Ok(BtGattRequest { att: Arc::clone(att), att_id: last_att_id, result, start, end })
}

/// Discover characteristics within a bounded handle range.
///
/// Uses `READ_BY_TYPE_REQ` with `GATT_CHARAC_UUID` (0x2803).
/// Paginated by incrementing start to `last_value_handle + 1`.
pub async fn discover_characteristics(
    att: &Arc<Mutex<BtAtt>>,
    start: u16,
    end: u16,
) -> Result<BtGattRequest, GattError> {
    if start == 0 || start > end {
        return Err(GattError::InvalidPdu);
    }

    tracing::debug!("Discover characteristics: start=0x{:04X}, end=0x{:04X}", start, end,);

    let mut result = BtGattResult::new(end);
    let mut current_start = start;
    let mut last_att_id: u32;

    loop {
        // READ_BY_TYPE_REQ: start(2) + end(2) + UUID16(2)
        let mut pdu = [0u8; 6];
        endian::put_le16(current_start, &mut pdu[0..2]);
        endian::put_le16(end, &mut pdu[2..4]);
        endian::put_le16(GATT_CHARAC_UUID, &mut pdu[4..6]);

        let (rsp_opcode, rsp_pdu, att_id) =
            send_att_request(att, types::BT_ATT_OP_READ_BY_TYPE_REQ, &pdu).await?;

        last_att_id = att_id;

        if rsp_opcode == types::BT_ATT_OP_ERROR_RSP {
            let ecode = parse_error_rsp(&rsp_pdu)?;
            if is_attribute_not_found(ecode) && !result.chunks.is_empty() {
                break;
            }
            return Err(GattError::AttError(ecode));
        }

        if rsp_opcode != types::BT_ATT_OP_READ_BY_TYPE_RSP {
            return Err(GattError::InvalidPdu);
        }
        if rsp_pdu.is_empty() {
            return Err(GattError::InvalidPdu);
        }

        let data_len = rsp_pdu[0] as usize;
        // data_len must be 7 (UUID16) or 21 (UUID128)
        if data_len != 7 && data_len != 21 {
            return Err(GattError::InvalidPdu);
        }
        let body = &rsp_pdu[1..];
        if body.is_empty() || body.len() % data_len != 0 {
            return Err(GattError::InvalidPdu);
        }

        let entry_count = body.len() / data_len;
        // Pagination: advance past the last value_handle.
        // value_handle is at offset 3 within each entry (after handle(2) + props(1)).
        let last_entry = &body[(entry_count - 1) * data_len..];
        let last_value_handle = endian::get_le16(&last_entry[3..5]);

        result.append(rsp_opcode, body, data_len as u16);

        if last_value_handle >= end || last_value_handle == 0xFFFF {
            break;
        }
        current_start = last_value_handle.saturating_add(1);
        if current_start > end {
            break;
        }
    }

    tracing::debug!("Characteristic discovery complete: {} chunk(s)", result.chunks.len(),);

    Ok(BtGattRequest { att: Arc::clone(att), att_id: last_att_id, result, start, end })
}

/// Discover descriptors within a bounded handle range.
///
/// Uses `FIND_INFO_REQ` between start and end handles.
/// Returns handle+UUID pairs.  Paginated by incrementing start to
/// `last_handle + 1`.
pub async fn discover_descriptors(
    att: &Arc<Mutex<BtAtt>>,
    start: u16,
    end: u16,
) -> Result<BtGattRequest, GattError> {
    if start == 0 || start > end {
        return Err(GattError::InvalidPdu);
    }

    tracing::debug!("Discover descriptors: start=0x{:04X}, end=0x{:04X}", start, end,);

    let mut result = BtGattResult::new(end);
    let mut current_start = start;
    let mut last_att_id: u32;

    loop {
        // FIND_INFO_REQ: start(2) + end(2)
        let mut pdu = [0u8; 4];
        endian::put_le16(current_start, &mut pdu[0..2]);
        endian::put_le16(end, &mut pdu[2..4]);

        let (rsp_opcode, rsp_pdu, att_id) =
            send_att_request(att, types::BT_ATT_OP_FIND_INFO_REQ, &pdu).await?;

        last_att_id = att_id;

        if rsp_opcode == types::BT_ATT_OP_ERROR_RSP {
            let ecode = parse_error_rsp(&rsp_pdu)?;
            if is_attribute_not_found(ecode) && !result.chunks.is_empty() {
                break;
            }
            return Err(GattError::AttError(ecode));
        }

        if rsp_opcode != types::BT_ATT_OP_FIND_INFO_RSP {
            return Err(GattError::InvalidPdu);
        }
        // FIND_INFO_RSP: format(1) + entries
        if rsp_pdu.is_empty() {
            return Err(GattError::InvalidPdu);
        }

        let format = rsp_pdu[0];
        let entry_len: usize = match format {
            0x01 => 4,  // handle(2) + UUID16(2)
            0x02 => 18, // handle(2) + UUID128(16)
            _ => return Err(GattError::InvalidPdu),
        };

        let body = &rsp_pdu[1..];
        if body.is_empty() || body.len() % entry_len != 0 {
            return Err(GattError::InvalidPdu);
        }

        let entry_count = body.len() / entry_len;
        let last_handle = endian::get_le16(
            &body[(entry_count - 1) * entry_len..(entry_count - 1) * entry_len + 2],
        );

        result.append(rsp_opcode, body, entry_len as u16);

        if last_handle >= end || last_handle == 0xFFFF {
            break;
        }
        current_start = last_handle.saturating_add(1);
        if current_start > end {
            break;
        }
    }

    tracing::debug!("Descriptor discovery complete: {} chunk(s)", result.chunks.len(),);

    Ok(BtGattRequest { att: Arc::clone(att), att_id: last_att_id, result, start, end })
}

/// Read attribute values by type within a bounded handle range.
///
/// Uses `READ_BY_TYPE_REQ` with the given `uuid`.  This is a generic
/// read procedure used for reading Database Hash, Server Supported
/// Features, and other GATT metadata.  Paginated until
/// `ATTRIBUTE_NOT_FOUND` or the end handle is reached.
pub async fn read_by_type(
    att: &Arc<Mutex<BtAtt>>,
    start: u16,
    end: u16,
    uuid: &BtUuid,
) -> Result<BtGattRequest, GattError> {
    if start == 0 || start > end {
        return Err(GattError::InvalidPdu);
    }

    tracing::debug!("Read by type: start=0x{:04X}, end=0x{:04X}, uuid={:?}", start, end, uuid,);

    let uuid_bytes = uuid_to_le_bytes(uuid);
    let mut result = BtGattResult::new(end);
    let mut current_start = start;
    let mut last_att_id: u32;

    loop {
        // READ_BY_TYPE_REQ: start(2) + end(2) + UUID(2 or 16)
        let pdu_len = 4 + uuid_bytes.len();
        let mut pdu = vec![0u8; pdu_len];
        endian::put_le16(current_start, &mut pdu[0..2]);
        endian::put_le16(end, &mut pdu[2..4]);
        pdu[4..pdu_len].copy_from_slice(&uuid_bytes);

        let (rsp_opcode, rsp_pdu, att_id) =
            send_att_request(att, types::BT_ATT_OP_READ_BY_TYPE_REQ, &pdu).await?;

        last_att_id = att_id;

        if rsp_opcode == types::BT_ATT_OP_ERROR_RSP {
            let ecode = parse_error_rsp(&rsp_pdu)?;
            if is_attribute_not_found(ecode) && !result.chunks.is_empty() {
                break;
            }
            return Err(GattError::AttError(ecode));
        }

        if rsp_opcode != types::BT_ATT_OP_READ_BY_TYPE_RSP {
            return Err(GattError::InvalidPdu);
        }
        if rsp_pdu.is_empty() {
            return Err(GattError::InvalidPdu);
        }

        let data_len = rsp_pdu[0] as usize;
        if data_len < 3 {
            return Err(GattError::InvalidPdu);
        }
        let body = &rsp_pdu[1..];
        if body.is_empty() || body.len() % data_len != 0 {
            return Err(GattError::InvalidPdu);
        }

        let entry_count = body.len() / data_len;
        let last_handle =
            endian::get_le16(&body[(entry_count - 1) * data_len..(entry_count - 1) * data_len + 2]);

        result.append(rsp_opcode, body, data_len as u16);

        if last_handle >= end || last_handle == 0xFFFF {
            break;
        }
        current_start = last_handle.saturating_add(1);
        if current_start > end {
            break;
        }
    }

    tracing::debug!("Read by type complete: {} chunk(s)", result.chunks.len(),);

    Ok(BtGattRequest { att: Arc::clone(att), att_id: last_att_id, result, start, end })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::att::types;
    use crate::util::uuid::BtUuid;

    #[test]
    fn test_empty_result_counts() {
        let result = BtGattResult::new(0xFFFF);
        assert_eq!(result.service_count(), 0);
        assert_eq!(result.characteristic_count(), 0);
        assert_eq!(result.descriptor_count(), 0);
        assert_eq!(result.included_count(), 0);
    }

    #[test]
    fn test_iter_on_empty_result() {
        let result = BtGattResult::new(0xFFFF);
        let mut iter = BtGattIter::init(&result);
        assert!(iter.next_service().is_none());
        assert!(iter.next_characteristic().is_none());
        assert!(iter.next_descriptor().is_none());
        assert!(iter.next_included_service().is_none());
        assert!(iter.next_read_by_type().is_none());
    }

    #[test]
    fn test_next_service_read_by_grp_type_uuid16() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.extend_from_slice(&0x0005u16.to_le_bytes());
        body.extend_from_slice(&0x1800u16.to_le_bytes());
        body.extend_from_slice(&0x0006u16.to_le_bytes());
        body.extend_from_slice(&0x0009u16.to_le_bytes());
        body.extend_from_slice(&0x1801u16.to_le_bytes());

        result.append(types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP, &body, 6);
        assert_eq!(result.service_count(), 2);

        let mut iter = BtGattIter::init(&result);

        let svc1 = iter.next_service().unwrap();
        assert_eq!(svc1.start_handle, 0x0001);
        assert_eq!(svc1.end_handle, 0x0005);
        assert!(matches!(svc1.uuid, BtUuid::Uuid16(0x1800)));

        let svc2 = iter.next_service().unwrap();
        assert_eq!(svc2.start_handle, 0x0006);
        assert_eq!(svc2.end_handle, 0x0009);
        assert!(matches!(svc2.uuid, BtUuid::Uuid16(0x1801)));

        assert!(iter.next_service().is_none());
    }

    #[test]
    fn test_next_service_read_by_grp_type_uuid128() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x000Au16.to_le_bytes());
        body.extend_from_slice(&0x000Fu16.to_le_bytes());
        let uuid128: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        body.extend_from_slice(&uuid128);

        result.append(types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP, &body, 20);

        let mut iter = BtGattIter::init(&result);
        let svc = iter.next_service().unwrap();
        assert_eq!(svc.start_handle, 0x000A);
        assert_eq!(svc.end_handle, 0x000F);
        assert!(matches!(svc.uuid, BtUuid::Uuid128(b) if b == uuid128));
        assert!(iter.next_service().is_none());
    }

    #[test]
    fn test_next_service_find_by_type() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.extend_from_slice(&0x0005u16.to_le_bytes());

        result.append(types::BT_ATT_OP_FIND_BY_TYPE_RSP, &body, 4);

        let mut iter = BtGattIter::init(&result);
        let svc = iter.next_service().unwrap();
        assert_eq!(svc.start_handle, 0x0001);
        assert_eq!(svc.end_handle, 0x0005);
        let zeros = [0u8; 16];
        assert!(matches!(svc.uuid, BtUuid::Uuid128(b) if b == zeros));
    }

    #[test]
    fn test_next_characteristic_uuid16() {
        let mut result = BtGattResult::new(0x0020);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0002u16.to_le_bytes());
        body.push(0x02);
        body.extend_from_slice(&0x0003u16.to_le_bytes());
        body.extend_from_slice(&0x2A00u16.to_le_bytes());
        body.extend_from_slice(&0x0004u16.to_le_bytes());
        body.push(0x0A);
        body.extend_from_slice(&0x0005u16.to_le_bytes());
        body.extend_from_slice(&0x2A01u16.to_le_bytes());

        result.append(types::BT_ATT_OP_READ_BY_TYPE_RSP, &body, 7);

        let mut iter = BtGattIter::init(&result);

        let ch1 = iter.next_characteristic().unwrap();
        assert_eq!(ch1.start_handle, 0x0002);
        assert_eq!(ch1.properties, 0x02);
        assert_eq!(ch1.value_handle, 0x0003);
        assert!(matches!(ch1.uuid, BtUuid::Uuid16(0x2A00)));
        assert_eq!(ch1.end_handle, 0x0003);

        let ch2 = iter.next_characteristic().unwrap();
        assert_eq!(ch2.start_handle, 0x0004);
        assert_eq!(ch2.value_handle, 0x0005);
        assert_eq!(ch2.end_handle, 0x0020);

        assert!(iter.next_characteristic().is_none());
    }

    #[test]
    fn test_next_descriptor_uuid16() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0004u16.to_le_bytes());
        body.extend_from_slice(&0x2902u16.to_le_bytes());
        body.extend_from_slice(&0x0005u16.to_le_bytes());
        body.extend_from_slice(&0x2901u16.to_le_bytes());

        result.append(types::BT_ATT_OP_FIND_INFO_RSP, &body, 4);

        let mut iter = BtGattIter::init(&result);
        let d1 = iter.next_descriptor().unwrap();
        assert_eq!(d1.handle, 0x0004);
        assert!(matches!(d1.uuid, BtUuid::Uuid16(0x2902)));

        let d2 = iter.next_descriptor().unwrap();
        assert_eq!(d2.handle, 0x0005);
        assert!(matches!(d2.uuid, BtUuid::Uuid16(0x2901)));

        assert!(iter.next_descriptor().is_none());
    }

    #[test]
    fn test_next_descriptor_uuid128() {
        let mut result = BtGattResult::new(0xFFFF);
        let uuid128: [u8; 16] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x01,
        ];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0010u16.to_le_bytes());
        body.extend_from_slice(&uuid128);

        result.append(types::BT_ATT_OP_FIND_INFO_RSP, &body, 18);

        let mut iter = BtGattIter::init(&result);
        let d = iter.next_descriptor().unwrap();
        assert_eq!(d.handle, 0x0010);
        assert!(matches!(d.uuid, BtUuid::Uuid128(b) if b == uuid128));
    }

    #[test]
    fn test_next_included_service_uuid16_inline() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0003u16.to_le_bytes());
        body.extend_from_slice(&0x0010u16.to_le_bytes());
        body.extend_from_slice(&0x001Fu16.to_le_bytes());
        body.extend_from_slice(&0x1800u16.to_le_bytes());

        result.append(types::BT_ATT_OP_READ_BY_TYPE_RSP, &body, 8);

        let mut iter = BtGattIter::init(&result);
        let incl = iter.next_included_service().unwrap();
        assert_eq!(incl.handle, 0x0003);
        assert_eq!(incl.start_handle, 0x0010);
        assert_eq!(incl.end_handle, 0x001F);
        assert!(incl.uuid.is_some());
        assert!(matches!(incl.uuid.unwrap(), BtUuid::Uuid16(0x1800)));
    }

    #[test]
    fn test_next_included_service_uuid128_chained_read() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut entry = Vec::new();
        entry.extend_from_slice(&0x0005u16.to_le_bytes());
        entry.extend_from_slice(&0x0020u16.to_le_bytes());
        entry.extend_from_slice(&0x002Fu16.to_le_bytes());
        result.append(types::BT_ATT_OP_READ_BY_TYPE_RSP, &entry, 6);

        let uuid128: [u8; 16] = [0xAA; 16];
        result.append(types::BT_ATT_OP_READ_RSP, &uuid128, 0);

        let mut iter = BtGattIter::init(&result);
        let incl = iter.next_included_service().unwrap();
        assert_eq!(incl.handle, 0x0005);
        assert_eq!(incl.start_handle, 0x0020);
        assert_eq!(incl.end_handle, 0x002F);
        assert!(incl.uuid.is_some());
        assert!(matches!(incl.uuid.unwrap(), BtUuid::Uuid128(b) if b == [0xAA; 16]));
    }

    #[test]
    fn test_next_read_by_type() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        result.append(types::BT_ATT_OP_READ_BY_TYPE_RSP, &body, 5);

        let mut iter = BtGattIter::init(&result);
        let entry = iter.next_read_by_type().unwrap();
        assert_eq!(entry.handle, 0x0001);
        assert_eq!(entry.value, &[0xAA, 0xBB, 0xCC]);
        assert!(iter.next_read_by_type().is_none());
    }

    #[test]
    fn test_multi_chunk_service_iteration() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body1 = Vec::new();
        body1.extend_from_slice(&0x0001u16.to_le_bytes());
        body1.extend_from_slice(&0x0005u16.to_le_bytes());
        body1.extend_from_slice(&0x1800u16.to_le_bytes());
        result.append(types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP, &body1, 6);

        let mut body2 = Vec::new();
        body2.extend_from_slice(&0x0006u16.to_le_bytes());
        body2.extend_from_slice(&0x000Au16.to_le_bytes());
        body2.extend_from_slice(&0x1801u16.to_le_bytes());
        result.append(types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP, &body2, 6);

        assert_eq!(result.service_count(), 2);

        let mut iter = BtGattIter::init(&result);
        let s1 = iter.next_service().unwrap();
        assert_eq!(s1.start_handle, 0x0001);
        let s2 = iter.next_service().unwrap();
        assert_eq!(s2.start_handle, 0x0006);
        assert!(iter.next_service().is_none());
    }

    #[test]
    fn test_gatt_error_display() {
        let err = GattError::AttError(0x0A);
        let display = format!("{err}");
        assert!(!display.is_empty());

        let err2 = GattError::InvalidPdu;
        assert!(!format!("{err2}").is_empty());

        let err3 = GattError::Timeout;
        assert!(!format!("{err3}").is_empty());

        let err4 = GattError::TransportError("test".into());
        assert!(format!("{err4}").contains("test"));
    }

    #[test]
    fn test_service_count_multiple_entries() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        for i in 0u16..3 {
            body.extend_from_slice(&(i * 10 + 1).to_le_bytes());
            body.extend_from_slice(&(i * 10 + 9).to_le_bytes());
            body.extend_from_slice(&(0x1800 + i).to_le_bytes());
        }
        result.append(types::BT_ATT_OP_READ_BY_GRP_TYPE_RSP, &body, 6);
        assert_eq!(result.service_count(), 3);
    }

    #[test]
    fn test_characteristic_count() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0002u16.to_le_bytes());
        body.push(0x02);
        body.extend_from_slice(&0x0003u16.to_le_bytes());
        body.extend_from_slice(&0x2A00u16.to_le_bytes());
        body.extend_from_slice(&0x0004u16.to_le_bytes());
        body.push(0x0A);
        body.extend_from_slice(&0x0005u16.to_le_bytes());
        body.extend_from_slice(&0x2A01u16.to_le_bytes());

        result.append(types::BT_ATT_OP_READ_BY_TYPE_RSP, &body, 7);
        assert_eq!(result.characteristic_count(), 2);
    }

    #[test]
    fn test_descriptor_count() {
        let mut result = BtGattResult::new(0xFFFF);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0004u16.to_le_bytes());
        body.extend_from_slice(&0x2902u16.to_le_bytes());
        body.extend_from_slice(&0x0005u16.to_le_bytes());
        body.extend_from_slice(&0x2901u16.to_le_bytes());

        result.append(types::BT_ATT_OP_FIND_INFO_RSP, &body, 4);
        assert_eq!(result.descriptor_count(), 2);
    }
}
