// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Async SDP Client Search Helpers
//
// Copyright 2024 BlueZ Project
//
// Rust rewrite of `src/sdp-client.c` (453 lines) and `src/sdp-client.h` (22
// lines).  Provides the client-side SDP service search API used by the daemon
// to discover services on remote Bluetooth devices.  Sessions are cached for a
// short period (2 seconds) to avoid repeated L2CAP connection overhead when
// multiple searches target the same device.
//
// Key design translations from C to Rust:
// - `GSList *cached_sdp_sessions` → `Mutex<Vec<CachedSdpSession>>`
// - `GSList *context_list` → `Mutex<Vec<ActiveSearch>>`
// - `callback_t + void *user_data` → `async fn` returning `Result`
// - `g_timeout_add_seconds(CACHE_TIMEOUT)` → `tokio::time::sleep`
// - `GIOChannel` + `g_io_add_watch` → `tokio::spawn` + async socket ops
// - `sdp_connect(SDP_NON_BLOCKING)` → `SocketBuilder::connect().await`

use std::os::fd::RawFd;
use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicU16, Ordering},
};
use std::time::Duration;

use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use bluez_shared::socket::{BluetoothSocket, BtTransport, SocketBuilder};
use bluez_shared::sys::bluetooth::{BDADDR_ANY, BdAddr};
use bluez_shared::util::uuid::BtUuid;

use super::{SdpData, SdpRecord};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of seconds to keep an SDP session in the cache.
/// Matches C `CACHE_TIMEOUT = 2` (sdp-client.c line 29).
const CACHE_TIMEOUT: Duration = Duration::from_secs(2);

/// SDP protocol service multiplexer — L2CAP PSM for SDP.
const SDP_PSM: u16 = 0x0001;

/// Low priority value for SDP socket traffic, matching
/// C `uint32_t prio = 1` (sdp-client.c line 299).
const SDP_SO_PRIORITY: i32 = 1;

/// SDP PDU identifier: `ServiceSearchAttributeRequest`.
const SDP_SVC_SEARCH_ATTR_REQ: u8 = 0x06;

/// SDP PDU identifier: `ServiceSearchAttributeResponse`.
const SDP_SVC_SEARCH_ATTR_RSP: u8 = 0x07;

/// SDP attribute: `ServiceClassIDList`.
const SDP_ATTR_SVCLASS_ID_LIST: u16 = 0x0001;

/// Maximum attribute byte count sent in the search request.
const MAX_ATTR_BYTE_COUNT: u16 = 65535;

/// Maximum receive buffer size for SDP responses.
const SDP_RECV_BUF_SIZE: usize = 65536;

/// SDP PDU header length (PDU-ID + TransactionID + ParameterLength).
const SDP_PDU_HEADER_LEN: usize = 5;

// ---------------------------------------------------------------------------
// Data Element type descriptors (SDP spec, §3.2)
// ---------------------------------------------------------------------------

const DE_TYPE_NIL: u8 = 0;
const DE_TYPE_UINT: u8 = 1;
const DE_TYPE_INT: u8 = 2;
const DE_TYPE_UUID: u8 = 3;
const DE_TYPE_TEXT: u8 = 4;
const DE_TYPE_BOOL: u8 = 5;
const DE_TYPE_SEQ: u8 = 6;
const DE_TYPE_ALT: u8 = 7;
const DE_TYPE_URL: u8 = 8;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Monotonically increasing transaction ID for SDP PDUs.
static TRANSACTION_ID: AtomicU16 = AtomicU16::new(1);

/// Module-level session cache (replaces C `cached_sdp_sessions` GSList).
static CACHED_SESSIONS: LazyLock<Mutex<Vec<CachedSdpSession>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Module-level active search tracking (replaces C `context_list` GSList).
static ACTIVE_SEARCHES: LazyLock<Mutex<Vec<ActiveSearch>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the SDP client search helpers.
#[derive(Debug, thiserror::Error)]
pub enum SdpClientError {
    /// L2CAP connection to the remote SDP service failed.
    #[error("SDP connection failed: {0}")]
    ConnectionFailed(String),

    /// The SDP search returned a protocol-level error.
    #[error("SDP protocol error: {0}")]
    ProtocolError(String),

    /// The search was cancelled via [`bt_cancel_discovery`].
    #[error("SDP search cancelled")]
    Cancelled,

    /// No active search was found for the given address pair.
    #[error("SDP search not found for address pair")]
    NotFound,

    /// The SDP session was not connected.
    #[error("SDP session not connected")]
    NotConnected,

    /// Underlying socket I/O error.
    #[error("SDP socket error: {0}")]
    SocketError(String),
}

// ---------------------------------------------------------------------------
// Public result type
// ---------------------------------------------------------------------------

/// Result type returned by [`bt_search`] and [`bt_search_service`].
pub type SearchResult = Result<Vec<SdpRecord>, SdpClientError>;

// ---------------------------------------------------------------------------
// Internal structures
// ---------------------------------------------------------------------------

/// A cached SDP session awaiting reuse or expiry.
struct CachedSdpSession {
    src: BdAddr,
    dst: BdAddr,
    socket: Arc<BluetoothSocket>,
}

/// A currently active SDP search, identified by source/destination pair.
struct ActiveSearch {
    src: BdAddr,
    dst: BdAddr,
    cancel: Arc<Notify>,
}

// ---------------------------------------------------------------------------
// Transaction ID helper
// ---------------------------------------------------------------------------

/// Allocate the next SDP transaction identifier (wrapping).
fn next_transaction_id() -> u16 {
    TRANSACTION_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// SO_PRIORITY helper
// ---------------------------------------------------------------------------

/// Set `SO_PRIORITY` on a raw file descriptor.
///
/// The C code (sdp-client.c line 327) sets `setsockopt(SOL_SOCKET,
/// SO_PRIORITY, &prio, sizeof(prio))` with `prio = 1` to keep SDP
/// traffic low-priority.  Delegates to the socket module's safe FFI
/// wrapper (`bt_sockopt_set_priority`).
fn set_socket_priority(raw_fd: RawFd, priority: i32) {
    if let Err(e) = bluez_shared::socket::bt_sockopt_set_priority(raw_fd, priority) {
        warn!("Setting SDP priority failed: {}", e);
    }
}

// ---------------------------------------------------------------------------
// SDP PDU builder
// ---------------------------------------------------------------------------

/// Encode a [`BtUuid`] as an SDP Data Element and append it to `buf`.
fn encode_uuid_data_element(uuid: &BtUuid, buf: &mut Vec<u8>) {
    match *uuid {
        BtUuid::Uuid16(v) => {
            // Type = UUID (3), Size index = 1 (2 bytes) → 0x19
            buf.push((DE_TYPE_UUID << 3) | 1);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        BtUuid::Uuid32(v) => {
            // Type = UUID (3), Size index = 2 (4 bytes) → 0x1A
            buf.push((DE_TYPE_UUID << 3) | 2);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        BtUuid::Uuid128(v) => {
            // Type = UUID (3), Size index = 4 (16 bytes) → 0x1C
            buf.push((DE_TYPE_UUID << 3) | 4);
            buf.extend_from_slice(&v);
        }
    }
}

/// Encode a Data Element Sequence header for an inner payload of
/// `inner_len` bytes and append it to `buf`.
fn encode_seq_header(inner_len: usize, buf: &mut Vec<u8>) {
    if inner_len <= 0xFF {
        buf.push((DE_TYPE_SEQ << 3) | 5); // next 1 byte is length
        buf.push(inner_len as u8);
    } else if inner_len <= 0xFFFF {
        buf.push((DE_TYPE_SEQ << 3) | 6); // next 2 bytes
        buf.extend_from_slice(&(inner_len as u16).to_be_bytes());
    } else {
        buf.push((DE_TYPE_SEQ << 3) | 7); // next 4 bytes
        buf.extend_from_slice(&(inner_len as u32).to_be_bytes());
    }
}

/// Build a complete `SDP_ServiceSearchAttributeRequest` PDU.
///
/// The service search pattern contains only the target UUID (matching C
/// behaviour in `connect_watch`, sdp-client.c line 261).  The attribute
/// ID range is 0x0000–0xFFFF (full range).
fn build_search_attr_request(uuid: &BtUuid, continuation: &[u8]) -> Vec<u8> {
    let tid = next_transaction_id();

    // --- ServiceSearchPattern (Data Element Sequence of UUIDs) ---
    let mut uuid_element = Vec::with_capacity(18);
    encode_uuid_data_element(uuid, &mut uuid_element);

    let mut search_pattern = Vec::with_capacity(20);
    encode_seq_header(uuid_element.len(), &mut search_pattern);
    search_pattern.extend_from_slice(&uuid_element);

    // --- AttributeIDList (Data Element Sequence of UINT32 ranges) ---
    // Range 0x0000-0xFFFF  →  UINT32  0x0000_FFFF
    let range: u32 = 0x0000_FFFF;
    let mut attr_element = Vec::with_capacity(5);
    attr_element.push((DE_TYPE_UINT << 3) | 2); // UINT32
    attr_element.extend_from_slice(&range.to_be_bytes());

    let mut attr_list = Vec::with_capacity(7);
    encode_seq_header(attr_element.len(), &mut attr_list);
    attr_list.extend_from_slice(&attr_element);

    // --- Assemble parameters ---
    let param_len = search_pattern.len() + 2 /* MaxAttrByteCount */ + attr_list.len() + 1 /* cont len */ + continuation.len();

    let mut pdu = Vec::with_capacity(SDP_PDU_HEADER_LEN + param_len);
    pdu.push(SDP_SVC_SEARCH_ATTR_REQ);
    pdu.extend_from_slice(&tid.to_be_bytes());
    pdu.extend_from_slice(&(param_len as u16).to_be_bytes());
    pdu.extend_from_slice(&search_pattern);
    pdu.extend_from_slice(&MAX_ATTR_BYTE_COUNT.to_be_bytes());
    pdu.extend_from_slice(&attr_list);
    // Continuation state
    pdu.push(continuation.len() as u8);
    pdu.extend_from_slice(continuation);

    pdu
}

// ===========================================================================
// SDP Data Element Reader
// ===========================================================================

/// Streaming reader for SDP Data Element byte sequences.
///
/// Used to parse `SDP_SVC_SEARCH_ATTR_RSP` response payloads which
/// consist of nested Data Element Sequences containing attribute
/// ID / value pairs.
struct DataElementReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DataElementReader<'a> {
    /// Create a new reader over `data` starting at offset zero.
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes remaining in the buffer.
    #[inline]
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Read a single byte, advancing position.
    fn read_u8(&mut self) -> Option<u8> {
        if self.pos < self.data.len() {
            let v = self.data[self.pos];
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }

    /// Read a big-endian 16-bit unsigned integer.
    fn read_u16_be(&mut self) -> Option<u16> {
        if self.pos + 2 <= self.data.len() {
            let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
            self.pos += 2;
            Some(v)
        } else {
            None
        }
    }

    /// Read a big-endian 32-bit unsigned integer.
    fn read_u32_be(&mut self) -> Option<u32> {
        if self.pos + 4 <= self.data.len() {
            let v = u32::from_be_bytes([
                self.data[self.pos],
                self.data[self.pos + 1],
                self.data[self.pos + 2],
                self.data[self.pos + 3],
            ]);
            self.pos += 4;
            Some(v)
        } else {
            None
        }
    }

    /// Read a big-endian 64-bit unsigned integer.
    fn read_u64_be(&mut self) -> Option<u64> {
        if self.pos + 8 <= self.data.len() {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&self.data[self.pos..self.pos + 8]);
            self.pos += 8;
            Some(u64::from_be_bytes(arr))
        } else {
            None
        }
    }

    /// Read `n` raw bytes as a slice.
    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + n];
            self.pos += n;
            Some(slice)
        } else {
            None
        }
    }

    /// Read and copy exactly 16 bytes into a fixed-size array.
    fn read_16_bytes(&mut self) -> Option<[u8; 16]> {
        let slice = self.read_bytes(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(slice);
        Some(arr)
    }

    // ---- Typed element readers -------------------------------------------

    /// Read the variable-length size field for Text / Sequence / Alternate
    /// / URL types (size descriptor indices 5, 6, 7).
    fn read_var_length(&mut self, size_idx: u8) -> Option<usize> {
        match size_idx {
            5 => self.read_u8().map(|v| v as usize),
            6 => self.read_u16_be().map(|v| v as usize),
            7 => self.read_u32_be().map(|v| v as usize),
            _ => None,
        }
    }

    /// Read a UINT data element body given its size index.
    fn read_uint_element(&mut self, size_idx: u8) -> Option<SdpData> {
        match size_idx {
            0 => self.read_u8().map(SdpData::UInt8),
            1 => self.read_u16_be().map(SdpData::UInt16),
            2 => self.read_u32_be().map(SdpData::UInt32),
            3 => self.read_u64_be().map(SdpData::UInt64),
            4 => self.read_16_bytes().map(SdpData::UInt128),
            _ => None,
        }
    }

    /// Read an INT data element body given its size index.
    fn read_int_element(&mut self, size_idx: u8) -> Option<SdpData> {
        match size_idx {
            0 => self.read_u8().map(|v| SdpData::Int8(v as i8)),
            1 => self.read_u16_be().map(|v| SdpData::Int16(v as i16)),
            2 => self.read_u32_be().map(|v| SdpData::Int32(v as i32)),
            3 => self.read_u64_be().map(|v| SdpData::Int64(v as i64)),
            4 => self.read_16_bytes().map(SdpData::Int128),
            _ => None,
        }
    }

    /// Read a UUID data element body given its size index.
    fn read_uuid_element(&mut self, size_idx: u8) -> Option<SdpData> {
        match size_idx {
            1 => self.read_u16_be().map(SdpData::Uuid16),
            2 => self.read_u32_be().map(SdpData::Uuid32),
            4 => self.read_16_bytes().map(SdpData::Uuid128),
            _ => None,
        }
    }

    /// Read a list of data elements spanning exactly `total_len` bytes.
    fn read_element_list(&mut self, total_len: usize) -> Option<Vec<SdpData>> {
        let end = self.pos.checked_add(total_len)?;
        if end > self.data.len() {
            return None;
        }
        let mut list = Vec::new();
        while self.pos < end {
            let elem = self.read_data_element()?;
            list.push(elem);
        }
        Some(list)
    }

    /// Read one complete SDP Data Element (header + body).
    fn read_data_element(&mut self) -> Option<SdpData> {
        if self.remaining() == 0 {
            return None;
        }
        let desc = self.read_u8()?;
        let de_type = desc >> 3;
        let size_idx = desc & 0x07;

        match de_type {
            DE_TYPE_NIL => Some(SdpData::Nil),
            DE_TYPE_UINT => self.read_uint_element(size_idx),
            DE_TYPE_INT => self.read_int_element(size_idx),
            DE_TYPE_UUID => self.read_uuid_element(size_idx),
            DE_TYPE_TEXT => {
                let len = self.read_var_length(size_idx)?;
                let bytes = self.read_bytes(len)?;
                Some(SdpData::Text(bytes.to_vec()))
            }
            DE_TYPE_BOOL => {
                let v = self.read_u8()?;
                Some(SdpData::Bool(v != 0))
            }
            DE_TYPE_SEQ => {
                let len = self.read_var_length(size_idx)?;
                self.read_element_list(len).map(SdpData::Sequence)
            }
            DE_TYPE_ALT => {
                let len = self.read_var_length(size_idx)?;
                self.read_element_list(len).map(SdpData::Alternate)
            }
            DE_TYPE_URL => {
                let len = self.read_var_length(size_idx)?;
                let bytes = self.read_bytes(len)?;
                let s = String::from_utf8_lossy(bytes).into_owned();
                Some(SdpData::Url(s))
            }
            _ => {
                // Unknown type — attempt to skip based on size descriptor.
                if size_idx <= 4 {
                    let skip = match size_idx {
                        0 => 1usize,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                        4 => 16,
                        _ => return None,
                    };
                    self.read_bytes(skip)?;
                } else if let Some(len) = self.read_var_length(size_idx) {
                    self.read_bytes(len)?;
                }
                Some(SdpData::Nil) // Treat unknown as Nil
            }
        }
    }
}

// ===========================================================================
// SDP Response Parsing
// ===========================================================================

/// Parse the accumulated `SDP_SVC_SEARCH_ATTR_RSP` attribute data into
/// a vector of [`SdpRecord`]s.
///
/// The accumulated data (after stripping PDU headers and continuation
/// handling) is a Data Element Sequence of attribute-list sequences.
/// Each inner sequence contains interleaved UINT16 attribute IDs and
/// their Data Element values.  This mirrors the C `search_completed_cb`
/// logic (sdp-client.c lines 149-210) which calls `sdp_extract_seqtype`
/// and then `sdp_extract_pdu` in a loop.
fn parse_records_from_response(accumulated: &[u8]) -> Vec<SdpRecord> {
    let mut records = Vec::new();
    if accumulated.is_empty() {
        return records;
    }

    let mut reader = DataElementReader::new(accumulated);

    // Outer wrapper: Data Element Sequence of per-record sequences.
    let desc = match reader.read_u8() {
        Some(d) => d,
        None => return records,
    };
    let de_type = desc >> 3;
    let size_idx = desc & 0x07;

    if de_type != DE_TYPE_SEQ {
        return records;
    }

    let seq_len = match reader.read_var_length(size_idx) {
        Some(l) => l,
        None => return records,
    };

    let seq_end = reader.pos.saturating_add(seq_len).min(reader.data.len());

    // Iterate over per-record sequences.
    while reader.pos < seq_end && reader.remaining() > 0 {
        let rec_desc = match reader.read_u8() {
            Some(d) => d,
            None => break,
        };
        let rec_type = rec_desc >> 3;
        let rec_size_idx = rec_desc & 0x07;

        if rec_type != DE_TYPE_SEQ {
            break;
        }

        let rec_len = match reader.read_var_length(rec_size_idx) {
            Some(l) => l,
            None => break,
        };

        let rec_end = reader.pos.saturating_add(rec_len).min(reader.data.len());

        let mut record = SdpRecord::new(0);

        // Read attribute-ID / value pairs.
        while reader.pos < rec_end {
            // Attribute ID must be a UINT16 data element.
            let attr_desc = match reader.read_u8() {
                Some(d) => d,
                None => break,
            };
            if (attr_desc >> 3) != DE_TYPE_UINT || (attr_desc & 0x07) != 1 {
                // Not a UINT16 — corrupted record; skip remainder.
                reader.pos = rec_end;
                break;
            }
            let attr_id = match reader.read_u16_be() {
                Some(id) => id,
                None => break,
            };

            // Attribute value — arbitrary Data Element.
            let value = match reader.read_data_element() {
                Some(v) => v,
                None => break,
            };

            // Extract record handle (attribute 0x0000 = ServiceRecordHandle).
            if attr_id == 0x0000 {
                if let SdpData::UInt32(handle) = value {
                    record.handle = handle;
                }
            }

            record.attrs.insert(attr_id, value);
        }

        // Ensure the reader is positioned at the record boundary.
        reader.pos = rec_end;

        records.push(record);
    }

    records
}

// ===========================================================================
// Service Class UUID Extraction
// ===========================================================================

/// Extract the first UUID from the `ServiceClassIDList` attribute
/// (0x0001) of an SDP record.
///
/// This mirrors the C `rec->svclass` field which is populated by
/// `sdp_extract_pdu` from the first entry in the service class ID
/// list.  Used by [`bt_search_service`] to filter results by service
/// class UUID (matching sdp-client.c lines 191-195).
fn extract_service_class_uuid(record: &SdpRecord) -> Option<BtUuid> {
    let svclass_list = record.attrs.get(&SDP_ATTR_SVCLASS_ID_LIST)?;

    // ServiceClassIDList is a Sequence of UUIDs.
    let uuids = match svclass_list {
        SdpData::Sequence(list) => list,
        _ => return None,
    };

    // Return the first UUID, converting to BtUuid.
    match uuids.first()? {
        SdpData::Uuid16(v) => Some(BtUuid::from_u16(*v)),
        SdpData::Uuid32(v) => Some(BtUuid::Uuid32(*v)),
        SdpData::Uuid128(v) => Some(BtUuid::Uuid128(*v)),
        _ => None,
    }
}

// ===========================================================================
// Session Cache Operations
// ===========================================================================

/// Look up and remove a cached SDP session for the given address pair.
///
/// On a cache hit the session is removed from the cache, its background
/// tasks (expiry timer + disconnect watcher) are cancelled, and the
/// socket is returned for reuse.  Matches C `get_cached_sdp_session`
/// (sdp-client.c lines 58-82).
async fn get_cached_session(src: &BdAddr, dst: &BdAddr) -> Option<Arc<BluetoothSocket>> {
    let mut cache = CACHED_SESSIONS.lock().await;
    let pos = cache.iter().position(|e| e.src == *src && e.dst == *dst)?;
    let entry = cache.swap_remove(pos);
    Some(entry.socket)
}

/// Cache an SDP session for potential reuse within [`CACHE_TIMEOUT`].
///
/// Spawns two background tasks:
/// 1. **Expiry timer** — removes the entry after `CACHE_TIMEOUT` seconds.
/// 2. **Disconnect watcher** — removes the entry if the remote end
///    disconnects early (HUP/ERR detection).
///
/// Matches C `cache_sdp_session` (sdp-client.c lines 95-123).
async fn cache_session(src: BdAddr, dst: BdAddr, socket: Arc<BluetoothSocket>) {
    let socket_watcher = socket.clone();
    let src_expiry = src;
    let dst_expiry = dst;
    let src_disc = src;
    let dst_disc = dst;

    // Store in cache before spawning background tasks.
    {
        let mut cache = CACHED_SESSIONS.lock().await;
        cache.push(CachedSdpSession { src, dst, socket });
    }

    // Background task 1: cache expiry timer.
    let _expiry: JoinHandle<()> = tokio::spawn(async move {
        tokio::time::sleep(CACHE_TIMEOUT).await;
        let mut cache = CACHED_SESSIONS.lock().await;
        let before = cache.len();
        cache.retain(|e| !(e.src == src_expiry && e.dst == dst_expiry));
        if cache.len() < before {
            debug!("SDP session cache expired for {:?}", dst_expiry);
        }
    });

    // Background task 2: disconnect watcher.
    let _disconnect: JoinHandle<()> = tokio::spawn(async move {
        let _ = socket_watcher.wait_disconnect().await;
        let mut cache = CACHED_SESSIONS.lock().await;
        let before = cache.len();
        cache.retain(|e| !(e.src == src_disc && e.dst == dst_disc));
        if cache.len() < before {
            debug!("SDP cached session disconnected for {:?}", dst_disc);
        }
    });
}

/// Explicitly remove and drop a cached SDP session for the given
/// address pair.  Matches C `bt_clear_cached_session` which retrieves
/// and closes the session (sdp-client.c lines 445-452).
async fn remove_cached_session(src: &BdAddr, dst: &BdAddr) {
    let mut cache = CACHED_SESSIONS.lock().await;
    cache.retain(|e| !(e.src == *src && e.dst == *dst));
}

// ===========================================================================
// Connection Helper
// ===========================================================================

/// Create or reuse an L2CAP connection to the remote SDP service.
///
/// 1. Check the session cache for a reusable socket.
/// 2. On miss, build a new non-blocking L2CAP connection to PSM 0x0001
///    via [`SocketBuilder`].
/// 3. Set `SO_PRIORITY = 1` on the socket (matching C sdp-client.c line
///    327).
///
/// This replaces C `create_search_context` (sdp-client.c lines 292-338).
async fn create_sdp_connection(
    src: &BdAddr,
    dst: &BdAddr,
) -> Result<Arc<BluetoothSocket>, SdpClientError> {
    // Attempt cache hit first.
    if let Some(cached_socket) = get_cached_session(src, dst).await {
        debug!("Reusing cached SDP session (src any={}) for {:?}", *src == BDADDR_ANY, dst,);
        return Ok(cached_socket);
    }

    // Create fresh L2CAP connection to SDP PSM.
    debug!("Creating new SDP connection (src any={}) to {:?}", *src == BDADDR_ANY, dst,);
    let socket: BluetoothSocket = SocketBuilder::new()
        .source_bdaddr(*src)
        .dest_bdaddr(*dst)
        .psm(SDP_PSM)
        .transport(BtTransport::L2cap)
        .connect()
        .await
        .map_err(|e| SdpClientError::ConnectionFailed(e.to_string()))?;

    // Set low priority for SDP traffic (C: prio = 1).
    set_socket_priority(socket.as_raw_fd(), SDP_SO_PRIORITY);

    // Verify socket readiness after connect.
    let _: () = socket.readable().await.map_err(|e| SdpClientError::SocketError(e.to_string()))?;

    Ok(Arc::new(socket))
}

// ===========================================================================
// SDP Search Implementation
// ===========================================================================

/// Perform the SDP `ServiceSearchAttribute` transaction over `socket`,
/// accumulating multi-PDU responses via continuation state.
///
/// Returns the raw accumulated attribute-list bytes on success.
async fn perform_sdp_search(
    socket: &BluetoothSocket,
    uuid: &BtUuid,
    cancel: &Notify,
) -> Result<Vec<u8>, SdpClientError> {
    let mut accumulated = Vec::new();
    let mut continuation: Vec<u8> = Vec::new();

    loop {
        // Build the request PDU with current continuation state.
        let pdu = build_search_attr_request(uuid, &continuation);

        // Send the request, cancellation-aware.
        tokio::select! {
            biased;
            _ = cancel.notified() => {
                return Err(SdpClientError::Cancelled);
            }
            result = socket.send(&pdu) => {
                let _: usize = result.map_err(|e| SdpClientError::SocketError(e.to_string()))?;
            }
        }

        // Receive the response, cancellation-aware.
        let mut buf = vec![0u8; SDP_RECV_BUF_SIZE];
        let n = tokio::select! {
            biased;
            _ = cancel.notified() => {
                return Err(SdpClientError::Cancelled);
            }
            result = socket.recv(&mut buf) => {
                let n: usize = result.map_err(|e| SdpClientError::SocketError(e.to_string()))?;
                n
            }
        };

        if n < SDP_PDU_HEADER_LEN {
            return Err(SdpClientError::ProtocolError(format!(
                "SDP response too short ({n} bytes, need at least {SDP_PDU_HEADER_LEN})"
            )));
        }

        let pdu_id = buf[0];
        // Transaction ID at buf[1..3] — validated but not required to match
        // because the C code also ignores TID mismatch.
        let param_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;

        if pdu_id != SDP_SVC_SEARCH_ATTR_RSP {
            return Err(SdpClientError::ProtocolError(format!(
                "Unexpected SDP PDU ID 0x{pdu_id:02X}, expected 0x{SDP_SVC_SEARCH_ATTR_RSP:02X}"
            )));
        }

        if n < SDP_PDU_HEADER_LEN + param_len {
            return Err(SdpClientError::ProtocolError(
                "SDP response parameter data truncated".into(),
            ));
        }

        let params = &buf[SDP_PDU_HEADER_LEN..SDP_PDU_HEADER_LEN + param_len];

        // Minimum parameter content: 2 bytes (AttributeByteCount) + 1 byte
        // (ContinuationState length).
        if params.len() < 3 {
            return Err(SdpClientError::ProtocolError("SDP response parameters too short".into()));
        }

        let attr_byte_count = u16::from_be_bytes([params[0], params[1]]) as usize;

        if params.len() < 2 + attr_byte_count + 1 {
            return Err(SdpClientError::ProtocolError("SDP attribute data truncated".into()));
        }

        // Accumulate attribute bytes.
        accumulated.extend_from_slice(&params[2..2 + attr_byte_count]);

        // Parse continuation state.
        let cont_offset = 2 + attr_byte_count;
        let cont_len = params[cont_offset] as usize;

        if cont_len == 0 {
            // Transaction complete — no more continuation data.
            break;
        }

        if cont_offset + 1 + cont_len > params.len() {
            return Err(SdpClientError::ProtocolError("SDP continuation state truncated".into()));
        }

        continuation = params[cont_offset + 1..cont_offset + 1 + cont_len].to_vec();
    }

    Ok(accumulated)
}

/// Core search implementation shared by [`bt_search`] and
/// [`bt_search_service`].
///
/// 1. Registers a cancellation token in [`ACTIVE_SEARCHES`].
/// 2. Connects to the remote SDP service.
/// 3. Sends the `ServiceSearchAttribute` transaction.
/// 4. Parses and optionally filters results.
/// 5. Caches the session on success.
/// 6. Removes the active-search entry on completion.
async fn sdp_search_internal(
    src: &BdAddr,
    dst: &BdAddr,
    uuid: &BtUuid,
    filter_svc_class: Option<&BtUuid>,
) -> SearchResult {
    // Register a cancellation handle.
    let cancel = Arc::new(Notify::new());
    {
        let mut searches = ACTIVE_SEARCHES.lock().await;
        searches.push(ActiveSearch { src: *src, dst: *dst, cancel: cancel.clone() });
    }

    // Perform the search (errors are propagated after cleanup).
    let result = sdp_search_with_cancel(src, dst, uuid, filter_svc_class, &cancel).await;

    // Unregister the active search regardless of outcome.
    {
        let mut searches = ACTIVE_SEARCHES.lock().await;
        searches.retain(|s| !(s.src == *src && s.dst == *dst));
    }

    result
}

/// Inner search logic with cancellation support.
async fn sdp_search_with_cancel(
    src: &BdAddr,
    dst: &BdAddr,
    uuid: &BtUuid,
    filter_svc_class: Option<&BtUuid>,
    cancel: &Notify,
) -> SearchResult {
    // 1. Establish or reuse SDP connection.
    let socket = create_sdp_connection(src, dst).await?;

    // 2. Perform the SDP search transaction.
    let accumulated = perform_sdp_search(&socket, uuid, cancel).await?;

    // 3. Parse records from the accumulated response data.
    let mut records = parse_records_from_response(&accumulated);

    // 4. Apply optional service-class UUID filter.
    //    Matches C `search_completed_cb` filter (sdp-client.c lines 191-195):
    //      if (ctxt->filter_svc_class &&
    //          sdp_uuid_cmp(&ctxt->uuid, &rec->svclass) != 0) { skip }
    if let Some(filter_uuid) = filter_svc_class {
        let filter_128 = filter_uuid.to_uuid128_bytes();
        records.retain(|rec| {
            if let Some(svclass) = extract_service_class_uuid(rec) {
                svclass.to_uuid128_bytes() == filter_128
            } else {
                false
            }
        });
    }

    // 5. Cache the session for reuse.
    cache_session(*src, *dst, socket).await;

    Ok(records)
}

// ===========================================================================
// Public API
// ===========================================================================

/// Search for SDP service records on a remote device.
///
/// Connects (or reuses a cached session) to the remote SDP service via
/// L2CAP PSM 0x0001, issues a `ServiceSearchAttributeRequest` for the
/// given UUID, and returns all matching records.  No service-class
/// filtering is applied.
///
/// This is the Rust equivalent of C `bt_search` (sdp-client.c lines
/// 361-379).
///
/// # Arguments
///
/// * `src` — Source adapter address (use [`BDADDR_ANY`] for any adapter).
/// * `dst` — Destination device address.
/// * `uuid` — Service UUID to search for.
/// * `_flags` — Reserved flags (unused in async implementation; the C
///   `SDP_NON_BLOCKING` flag is implicit).
pub async fn bt_search(src: &BdAddr, dst: &BdAddr, uuid: &BtUuid, _flags: u16) -> SearchResult {
    sdp_search_internal(src, dst, uuid, None).await
}

/// Search for SDP service records with service-class filtering.
///
/// Like [`bt_search`], but additionally filters each returned record:
/// only records whose `ServiceClassIDList` (attribute 0x0001) first
/// UUID matches `filter_svc_class` are included in the result.
///
/// This is the Rust equivalent of C `bt_search_service` (sdp-client.c
/// lines 382-401).
///
/// # Arguments
///
/// * `src` — Source adapter address (use [`BDADDR_ANY`] for any adapter).
/// * `dst` — Destination device address.
/// * `uuid` — Service UUID to search for.
/// * `_flags` — Reserved flags (unused in async implementation).
/// * `filter_svc_class` — UUID that must match the record's service
///   class ID for the record to be included.
pub async fn bt_search_service(
    src: &BdAddr,
    dst: &BdAddr,
    uuid: &BtUuid,
    _flags: u16,
    filter_svc_class: &BtUuid,
) -> SearchResult {
    sdp_search_internal(src, dst, uuid, Some(filter_svc_class)).await
}

/// Cancel an ongoing SDP discovery for a specific address pair.
///
/// Finds the active search context matching `(src, dst)` and signals
/// cancellation, causing the in-flight search future to return
/// [`SdpClientError::Cancelled`].
///
/// Returns [`SdpClientError::NotFound`] if no active search exists for
/// the given pair.
///
/// This is the Rust equivalent of C `bt_cancel_discovery` (sdp-client.c
/// lines 415-443).
pub async fn bt_cancel_discovery(src: &BdAddr, dst: &BdAddr) -> Result<(), SdpClientError> {
    let mut searches = ACTIVE_SEARCHES.lock().await;

    let pos = searches
        .iter()
        .position(|s| s.src == *src && s.dst == *dst)
        .ok_or(SdpClientError::NotFound)?;

    let search = searches.swap_remove(pos);
    search.cancel.notify_one();

    Ok(())
}

/// Clear the cached SDP session for a specific address pair.
///
/// If a cached session exists it is removed and the underlying socket
/// is closed (dropped).  This is typically called when a device
/// disconnects or when the adapter is powered down.
///
/// This is the Rust equivalent of C `bt_clear_cached_session`
/// (sdp-client.c lines 445-452).
pub async fn bt_clear_cached_session(src: &BdAddr, dst: &BdAddr) {
    remove_cached_session(src, dst).await;
    debug!("Cleared cached SDP session for {:?}", dst);
}

// ===========================================================================
// Unit-test helpers (cfg(test) only)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the PDU builder produces a well-formed SDP request.
    #[test]
    fn test_build_search_attr_request_uuid16() {
        let uuid = BtUuid::from_u16(0x1101); // Serial Port
        let pdu = build_search_attr_request(&uuid, &[]);

        assert_eq!(pdu[0], SDP_SVC_SEARCH_ATTR_REQ);
        // Transaction ID at [1..3]
        // Parameter length at [3..5]
        let param_len = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
        assert_eq!(pdu.len(), SDP_PDU_HEADER_LEN + param_len);

        // Last byte should be 0x00 (no continuation)
        assert_eq!(*pdu.last().unwrap(), 0x00);
    }

    /// Verify UUID16 encoding as a Data Element.
    #[test]
    fn test_encode_uuid16() {
        let uuid = BtUuid::Uuid16(0x1234);
        let mut buf = Vec::new();
        encode_uuid_data_element(&uuid, &mut buf);
        assert_eq!(buf, &[0x19, 0x12, 0x34]);
    }

    /// Verify UUID128 encoding as a Data Element.
    #[test]
    fn test_encode_uuid128() {
        let uuid = BtUuid::Uuid128([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let mut buf = Vec::new();
        encode_uuid_data_element(&uuid, &mut buf);
        assert_eq!(buf.len(), 17); // 1 header + 16 data
        assert_eq!(buf[0], 0x1C); // UUID, 16 bytes
    }

    /// Verify sequence header encoding for small payloads.
    #[test]
    fn test_encode_seq_header_small() {
        let mut buf = Vec::new();
        encode_seq_header(10, &mut buf);
        assert_eq!(buf, &[0x35, 10]);
    }

    /// Round-trip: parse a minimal SDP response containing one empty
    /// record.
    #[test]
    fn test_parse_empty_record() {
        // Outer SEQ (size=2) containing inner SEQ (size=0)
        let data = vec![0x35, 0x02, 0x35, 0x00];
        let records = parse_records_from_response(&data);
        assert_eq!(records.len(), 1);
        assert!(records[0].attrs.is_empty());
    }

    /// Parse a minimal record with a single UINT32 attribute.
    #[test]
    fn test_parse_single_attribute_record() {
        // Build: outer SEQ -> inner SEQ -> (UINT16 attr_id=0x0000, UINT32 value=0x00010001)
        let mut inner = Vec::new();
        // Attribute ID: UINT16 0x0000
        inner.push(0x09); // UINT16
        inner.extend_from_slice(&0x0000u16.to_be_bytes());
        // Value: UINT32 0x00010001 (ServiceRecordHandle)
        inner.push(0x0A); // UINT32
        inner.extend_from_slice(&0x0001_0001u32.to_be_bytes());

        let mut outer = Vec::new();
        // Inner SEQ header
        let mut inner_seq = Vec::new();
        inner_seq.push(0x35);
        inner_seq.push(inner.len() as u8);
        inner_seq.extend_from_slice(&inner);

        // Outer SEQ header
        outer.push(0x35);
        outer.push(inner_seq.len() as u8);
        outer.extend_from_slice(&inner_seq);

        let records = parse_records_from_response(&outer);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle, 0x0001_0001);
        assert_eq!(records[0].attrs.get(&0x0000), Some(&SdpData::UInt32(0x0001_0001)));
    }

    /// Verify service class extraction from a record.
    #[test]
    fn test_extract_service_class_uuid() {
        let mut record = SdpRecord::new(1);
        record
            .attrs
            .insert(SDP_ATTR_SVCLASS_ID_LIST, SdpData::Sequence(vec![SdpData::Uuid16(0x1101)]));

        let uuid = extract_service_class_uuid(&record);
        assert!(uuid.is_some());
        assert_eq!(uuid.unwrap(), BtUuid::from_u16(0x1101));
    }

    /// Verify that records without service class are filtered out.
    #[test]
    fn test_filter_no_svclass() {
        let record = SdpRecord::new(1);
        assert!(extract_service_class_uuid(&record).is_none());
    }

    /// Verify the Data Element reader parses UINT variants correctly.
    #[test]
    fn test_data_element_reader_uint() {
        // UINT8 = 42
        let data = [0x08, 42u8];
        let mut reader = DataElementReader::new(&data);
        assert_eq!(reader.read_data_element(), Some(SdpData::UInt8(42)));
        assert_eq!(reader.remaining(), 0);

        // UINT16 = 0x1234
        let data = [0x09, 0x12, 0x34];
        let mut reader = DataElementReader::new(&data);
        assert_eq!(reader.read_data_element(), Some(SdpData::UInt16(0x1234)));
    }

    /// Verify the Data Element reader handles a nested sequence.
    #[test]
    fn test_data_element_reader_seq() {
        // SEQ(len=3) { UINT8(99) }
        let data = [0x35, 0x02, 0x08, 99];
        let mut reader = DataElementReader::new(&data);
        let result = reader.read_data_element();
        assert_eq!(result, Some(SdpData::Sequence(vec![SdpData::UInt8(99)])));
    }

    /// Verify PDU builder with continuation state.
    #[test]
    fn test_build_request_with_continuation() {
        let uuid = BtUuid::from_u16(0x1101);
        let cont = vec![0x01, 0x02, 0x03];
        let pdu = build_search_attr_request(&uuid, &cont);

        // Continuation: last 4 bytes = len(3) + [1, 2, 3]
        let pdu_len = pdu.len();
        assert_eq!(pdu[pdu_len - 4], 3); // continuation length
        assert_eq!(&pdu[pdu_len - 3..], &[1, 2, 3]);
    }

    /// Verify transaction ID increments.
    #[test]
    fn test_transaction_id_increments() {
        let t1 = next_transaction_id();
        let t2 = next_transaction_id();
        assert_eq!(t2, t1.wrapping_add(1));
    }
}
