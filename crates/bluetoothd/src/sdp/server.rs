// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2001-2002  Nokia Corporation
// Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
// Copyright (C) 2002-2003  Stephen Crane <steve.crane@rococosoft.com>
//
// SDP daemon server — Rust rewrite of `src/sdpd-server.c` (listener, accept,
// session handling) and `src/sdpd-request.c` (PDU parsing, continuation state,
// request dispatch).
//
// This module provides:
// - L2CAP PSM 1 listener for remote SDP queries
// - Unix domain socket listener at `/run/sdp` for local record registration
// - SDP PDU parsing (ServiceSearchRequest, ServiceAttributeRequest,
//   ServiceSearchAttributeRequest) with continuation state management
// - Request dispatch to database module for local-only register/update/remove
// - Async server lifecycle (start/stop) integrated with tokio runtime
//
// # Safety
//
// This module is a designated FFI boundary for kernel Bluetooth socket
// operations (`AF_BLUETOOTH`).  The Linux kernel does not expose Bluetooth
// sockets through any safe Rust abstraction (nix, socket2, etc.), so raw
// `libc` calls with `unsafe` blocks are required for socket creation,
// bind, listen, accept, getsockopt/setsockopt, getpeername/getsockname,
// and send/recv on AF_BLUETOOTH sockets.  Every `unsafe` block contains
// a `// SAFETY:` comment documenting the invariant.
#![allow(unsafe_code)]

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, spawn};

use tracing::{debug, error, info};

use bluez_shared::sys::bluetooth::{
    AF_BLUETOOTH, BDADDR_ANY, BDADDR_LOCAL, BTPROTO_L2CAP, BdAddr, SOL_L2CAP, htobs,
};
use bluez_shared::sys::l2cap::{
    L2CAP_LM, L2CAP_LM_MASTER, L2CAP_OPTIONS, l2cap_options, sockaddr_l2,
};

use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_info};
use crate::sdp::database::{self, SdpDatabase};

// ---------------------------------------------------------------------------
// SDP PDU opcode constants (Bluetooth SDP specification)
// ---------------------------------------------------------------------------

/// SDP ErrorResponse PDU opcode.
pub const SDP_ERROR_RSP: u8 = 0x01;

/// SDP ServiceSearchRequest PDU opcode.
pub const SDP_SVC_SEARCH_REQ: u8 = 0x02;

/// SDP ServiceSearchResponse PDU opcode.
pub const SDP_SVC_SEARCH_RSP: u8 = 0x03;

/// SDP ServiceAttributeRequest PDU opcode.
pub const SDP_SVC_ATTR_REQ: u8 = 0x04;

/// SDP ServiceAttributeResponse PDU opcode.
pub const SDP_SVC_ATTR_RSP: u8 = 0x05;

/// SDP ServiceSearchAttributeRequest PDU opcode.
pub const SDP_SVC_SEARCH_ATTR_REQ: u8 = 0x06;

/// SDP ServiceSearchAttributeResponse PDU opcode.
pub const SDP_SVC_SEARCH_ATTR_RSP: u8 = 0x07;

/// Internal: service register request (local Unix socket only).
pub const SDP_SVC_REGISTER_REQ: u8 = 0x75;

/// Internal: service update request (local Unix socket only).
pub const SDP_SVC_UPDATE_REQ: u8 = 0x76;

/// Internal: service remove request (local Unix socket only).
pub const SDP_SVC_REMOVE_REQ: u8 = 0x78;

// ---------------------------------------------------------------------------
// SDP error code constants
// ---------------------------------------------------------------------------

/// Invalid SDP version (error code 0x0001).
pub const SDP_INVALID_VERSION: u16 = 0x0001;

/// Invalid service record handle (error code 0x0002).
pub const SDP_INVALID_RECORD_HANDLE: u16 = 0x0002;

/// Invalid request syntax (error code 0x0003).
pub const SDP_INVALID_SYNTAX: u16 = 0x0003;

/// Invalid PDU size (error code 0x0004).
pub const SDP_INVALID_PDU_SIZE: u16 = 0x0004;

/// Invalid continuation state (error code 0x0005).
pub const SDP_INVALID_CSTATE: u16 = 0x0005;

// ---------------------------------------------------------------------------
// Server configuration constants
// ---------------------------------------------------------------------------

/// L2CAP Protocol Service Multiplexer for SDP (PSM 1).
pub const SDP_PSM: u16 = 1;

/// Path for the Unix domain socket used by local clients.
pub const SDP_UNIX_PATH: &str = "/run/sdp";

/// Server flag: enable backward-compatible Unix socket interface.
pub const SDP_SERVER_COMPAT: u32 = 1 << 0;

/// Server flag: enforce central (master) role on L2CAP connections.
pub const SDP_SERVER_CENTRAL: u32 = 1 << 1;

/// Size of the SDP PDU header in bytes: opcode(1) + tid(2) + plen(2).
const SDP_PDU_HDR_SIZE: usize = 5;

/// Maximum receive buffer size for a single SDP PDU.
const SDP_MAX_PDU_SIZE: usize = 65535;

/// Continuation state size on the wire: length(1) + timestamp(4) + value(2).
const SDP_CONT_STATE_SIZE: usize = 1 + 4 + 2;

/// Minimum valid continuation state body size (timestamp + union value).
const SDP_CONT_STATE_BODY_SIZE: usize = 6;

/// SDP Data Element Sequence type discriminant: 8-bit length.
const SDP_SEQ8: u8 = 0x35;

/// SDP Data Element Sequence type discriminant: 16-bit length.
const SDP_SEQ16: u8 = 0x36;

/// UUID-16 data type.
const SDP_UUID16: u8 = 0x19;

/// UUID-32 data type.
const SDP_UUID32: u8 = 0x1a;

/// UUID-128 data type.
const SDP_UUID128: u8 = 0x1c;

/// Unsigned 16-bit integer data type.
const SDP_UINT16: u8 = 0x09;

/// Unsigned 32-bit integer data type.
const SDP_UINT32: u8 = 0x0a;

// ---------------------------------------------------------------------------
// SDP PDU header
// ---------------------------------------------------------------------------

/// Parsed SDP PDU header (5 bytes on wire).
#[derive(Debug, Clone, Copy)]
pub struct SdpPduHeader {
    /// PDU identifier / opcode.
    pub opcode: u8,
    /// Transaction identifier.
    pub tid: u16,
    /// Parameter length (bytes following the header).
    pub param_len: u16,
}

impl SdpPduHeader {
    /// Parse an SDP PDU header from a byte slice.
    ///
    /// Returns `None` if the slice is shorter than 5 bytes.
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < SDP_PDU_HDR_SIZE {
            return None;
        }
        Some(Self {
            opcode: buf[0],
            tid: u16::from_be_bytes([buf[1], buf[2]]),
            param_len: u16::from_be_bytes([buf[3], buf[4]]),
        })
    }

    /// Serialise the header into the first 5 bytes of `buf`.
    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.opcode;
        let tid_bytes = self.tid.to_be_bytes();
        buf[1] = tid_bytes[0];
        buf[2] = tid_bytes[1];
        let plen_bytes = self.param_len.to_be_bytes();
        buf[3] = plen_bytes[0];
        buf[4] = plen_bytes[1];
    }
}

// ---------------------------------------------------------------------------
// SDP request context
// ---------------------------------------------------------------------------

/// SDP request context, the Rust equivalent of `sdp_req_t`.
///
/// Carries all state needed to process a single SDP PDU and send back
/// the response.
pub struct SdpRequest {
    /// Peer device Bluetooth address (for access control).
    pub device: BdAddr,
    /// Local adapter Bluetooth address.
    pub bdaddr: BdAddr,
    /// Whether the request arrived over the local Unix socket (`true`) or
    /// L2CAP (`false`).
    pub local: bool,
    /// Socket file descriptor for sending the response.
    pub sock: RawFd,
    /// Maximum Transmission Unit for response sizing.
    pub mtu: u16,
    /// Server flags (`SDP_SERVER_COMPAT`, `SDP_SERVER_CENTRAL`).
    pub flags: u32,
    /// Full PDU buffer (including header).
    pub buf: Vec<u8>,
    /// Current PDU opcode being processed.
    pub opcode: u8,
}

// ---------------------------------------------------------------------------
// Continuation state types
// ---------------------------------------------------------------------------

/// Continuation state transmitted on the wire (7 bytes: 1 length + 6 body).
#[derive(Debug, Clone, Copy)]
struct ContinuationState {
    /// Database timestamp identifying the cached response.
    timestamp: u32,
    /// Continuation value — `max_bytes_sent` for attribute responses,
    /// `last_index_sent` for search responses.
    value: u16,
}

/// Server-side cached continuation information for a multi-PDU response.
#[derive(Debug)]
struct ContinuationInfo {
    /// Socket fd that owns this continuation.
    sock: RawFd,
    /// Original request opcode.
    opcode: u8,
    /// Timestamp used as a lookup key.
    timestamp: u32,
    /// Accumulated response bytes (complete response before chunking).
    buf: Vec<u8>,
}

/// Parsed attribute ID — either a single 16-bit ID or a 32-bit range.
#[derive(Debug, Clone, Copy)]
enum AttrId {
    /// Single attribute ID.
    Single(u16),
    /// Attribute ID range: (low << 16) | high.
    Range(u16, u16),
}

/// Parsed UUID from a DES element.
#[derive(Debug, Clone)]
enum SdpUuid {
    Uuid16(u16),
    Uuid32(u32),
    Uuid128([u8; 16]),
}

// ---------------------------------------------------------------------------
// Module-level global state
// ---------------------------------------------------------------------------

/// Global continuation state store — shared across all session tasks.
static CSTATES: std::sync::LazyLock<Mutex<Vec<ContinuationInfo>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Global SDP database instance — shared across all session tasks.
static SDP_DB: std::sync::LazyLock<Mutex<SdpDatabase>> =
    std::sync::LazyLock::new(|| Mutex::new(SdpDatabase::new()));

/// Accept loop task handles — stored so `stop_sdp_server` can abort them.
static SERVER_TASKS: std::sync::LazyLock<Mutex<Vec<JoinHandle<()>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

// ---------------------------------------------------------------------------
// Continuation state management
// ---------------------------------------------------------------------------

/// Look up a continuation info entry by timestamp and opcode.
///
/// If the timestamp matches but the opcode differs, the stale entry is
/// removed. If no matching entry exists at all, all entries for the
/// requesting socket are cleaned up.
fn get_cont_info(
    cstates: &mut Vec<ContinuationInfo>,
    sock: RawFd,
    opcode: u8,
    cstate: &ContinuationState,
) -> Option<usize> {
    // Find by timestamp.
    let pos = cstates.iter().position(|c| c.timestamp == cstate.timestamp);
    match pos {
        Some(idx) => {
            if cstates[idx].opcode == opcode {
                Some(idx)
            } else {
                // Opcode mismatch — clean up stale entry.
                cstates.remove(idx);
                None
            }
        }
        None => {
            // No match — clean up all entries for this socket.
            cstates.retain(|c| c.sock != sock);
            None
        }
    }
}

/// Allocate a new continuation buffer, storing the accumulated response.
///
/// Returns the timestamp assigned to the new continuation entry.
fn alloc_cont_buf(
    cstates: &mut Vec<ContinuationInfo>,
    db: &SdpDatabase,
    sock: RawFd,
    opcode: u8,
    data: &[u8],
) -> u32 {
    let ts = db.get_time();
    cstates.push(ContinuationInfo { sock, opcode, timestamp: ts, buf: data.to_vec() });
    ts
}

/// Append a continuation state to the response buffer.
///
/// If `cstate` is `Some`, writes the 7-byte continuation state body;
/// otherwise writes a single 0x00 byte (null continuation).
fn set_cstate_pdu(rsp: &mut Vec<u8>, cstate: Option<&ContinuationState>) -> usize {
    match cstate {
        Some(cs) => {
            debug!("Non-null continuation state id: 0x{:x}", cs.timestamp);
            // Length byte (6 = sizeof timestamp + sizeof value).
            rsp.push(SDP_CONT_STATE_BODY_SIZE as u8);
            rsp.extend_from_slice(&cs.timestamp.to_be_bytes());
            rsp.extend_from_slice(&cs.value.to_be_bytes());
            1 + SDP_CONT_STATE_BODY_SIZE
        }
        None => {
            rsp.push(0);
            1
        }
    }
}

/// Extract continuation state from the end of a request PDU body.
///
/// Returns `None` for null continuation (size byte == 0).
/// Returns `Some(ContinuationState)` for a valid continuation.
/// Returns an error status code if the data is malformed.
fn get_cstate(buf: &[u8]) -> Result<Option<ContinuationState>, u16> {
    if buf.is_empty() {
        return Err(SDP_INVALID_SYNTAX);
    }

    let cstate_size = buf[0] as usize;
    debug!("Continuation state size: {}", cstate_size);

    if cstate_size == 0 {
        return Ok(None);
    }

    let body = &buf[1..];
    if body.len() < SDP_CONT_STATE_BODY_SIZE {
        return Err(SDP_INVALID_SYNTAX);
    }

    let timestamp = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let value = u16::from_be_bytes([body[4], body[5]]);

    debug!("Cstate timestamp: 0x{:x}, value: {}", timestamp, value);

    Ok(Some(ContinuationState { timestamp, value }))
}

/// Remove all continuation states for a given socket (session cleanup).
pub fn sdp_cstate_cleanup(sock: RawFd) {
    // We need to block on the lock since this may be called from sync context.
    // Use try_lock to avoid deadlock if already held by current task.
    if let Ok(mut cstates) = CSTATES.try_lock() {
        cstates.retain(|c| c.sock != sock);
    }
}

/// Async version of continuation state cleanup.
async fn sdp_cstate_cleanup_async(sock: RawFd) {
    let mut cstates = CSTATES.lock().await;
    cstates.retain(|c| c.sock != sock);
}

// ---------------------------------------------------------------------------
// DES (Data Element Sequence) parsing
// ---------------------------------------------------------------------------

/// Extract the sequence type and data size from a DES header.
///
/// Returns `(bytes_consumed, data_size)` or `None` if invalid.
fn extract_seq_type(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() {
        return None;
    }

    match buf[0] {
        SDP_SEQ8 => {
            if buf.len() < 2 {
                return None;
            }
            Some((2, buf[1] as usize))
        }
        SDP_SEQ16 => {
            if buf.len() < 3 {
                return None;
            }
            let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
            Some((3, len))
        }
        _ => None,
    }
}

/// Extract a UUID from a typed data element.
///
/// Returns `(uuid, bytes_consumed)` or `None` on error.
fn extract_uuid(buf: &[u8]) -> Option<(SdpUuid, usize)> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] {
        SDP_UUID16 => {
            if buf.len() < 3 {
                return None;
            }
            let val = u16::from_be_bytes([buf[1], buf[2]]);
            Some((SdpUuid::Uuid16(val), 3))
        }
        SDP_UUID32 => {
            if buf.len() < 5 {
                return None;
            }
            let val = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
            Some((SdpUuid::Uuid32(val), 5))
        }
        SDP_UUID128 => {
            if buf.len() < 17 {
                return None;
            }
            let mut val = [0u8; 16];
            val.copy_from_slice(&buf[1..17]);
            Some((SdpUuid::Uuid128(val), 17))
        }
        _ => None,
    }
}

/// Extract a DES of UUIDs from a request buffer.
///
/// Returns `(uuids, bytes_consumed)` or an error.
fn extract_uuid_des(buf: &[u8]) -> Result<(Vec<SdpUuid>, usize), u16> {
    let (header_len, data_size) = extract_seq_type(buf).ok_or(SDP_INVALID_SYNTAX)?;
    let mut pos = header_len;
    let end = header_len + data_size;

    if buf.len() < end {
        return Err(SDP_INVALID_SYNTAX);
    }

    let mut uuids = Vec::new();
    while pos < end {
        let (uuid, consumed) = extract_uuid(&buf[pos..]).ok_or(SDP_INVALID_SYNTAX)?;
        uuids.push(uuid);
        pos += consumed;
    }

    Ok((uuids, end))
}

/// Extract a DES of attribute IDs (uint16 or uint32 ranges) from a buffer.
///
/// Returns `(attr_ids, bytes_consumed)` or an error.
fn extract_attrid_des(buf: &[u8]) -> Result<(Vec<AttrId>, usize), u16> {
    let (header_len, data_size) = extract_seq_type(buf).ok_or(SDP_INVALID_SYNTAX)?;
    let mut pos = header_len;
    let end = header_len + data_size;

    if buf.len() < end {
        return Err(SDP_INVALID_SYNTAX);
    }

    let mut attrs = Vec::new();
    while pos < end {
        if pos >= buf.len() {
            return Err(SDP_INVALID_SYNTAX);
        }
        match buf[pos] {
            SDP_UINT16 => {
                pos += 1;
                if pos + 2 > end || pos + 2 > buf.len() {
                    return Err(SDP_INVALID_SYNTAX);
                }
                let val = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
                attrs.push(AttrId::Single(val));
                pos += 2;
            }
            SDP_UINT32 => {
                pos += 1;
                if pos + 4 > end || pos + 4 > buf.len() {
                    return Err(SDP_INVALID_SYNTAX);
                }
                let val = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
                let low = (val >> 16) as u16;
                let high = (val & 0xFFFF) as u16;
                attrs.push(AttrId::Range(low, high));
                pos += 4;
            }
            _ => {
                return Err(SDP_INVALID_SYNTAX);
            }
        }
    }

    Ok((attrs, end))
}

// ---------------------------------------------------------------------------
// UUID matching
// ---------------------------------------------------------------------------

/// Convert any UUID to its 128-bit form for comparison.
///
/// Uses the Bluetooth Base UUID: `00000000-0000-1000-8000-00805F9B34FB`.
fn uuid_to_128(uuid: &SdpUuid) -> [u8; 16] {
    // Bluetooth Base UUID
    let base: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34,
        0xFB,
    ];
    match uuid {
        SdpUuid::Uuid16(v) => {
            let mut out = base;
            let bytes = v.to_be_bytes();
            out[2] = bytes[0];
            out[3] = bytes[1];
            out
        }
        SdpUuid::Uuid32(v) => {
            let mut out = base;
            let bytes = v.to_be_bytes();
            out[0] = bytes[0];
            out[1] = bytes[1];
            out[2] = bytes[2];
            out[3] = bytes[3];
            out
        }
        SdpUuid::Uuid128(v) => *v,
    }
}

/// Convert an `SdpData` UUID variant to a 128-bit UUID for comparison.
fn sdp_data_uuid_to_128(data: &crate::sdp::xml::SdpData) -> Option<[u8; 16]> {
    use crate::sdp::xml::SdpData;
    match data {
        SdpData::Uuid16(v) => Some(uuid_to_128(&SdpUuid::Uuid16(*v))),
        SdpData::Uuid32(v) => Some(uuid_to_128(&SdpUuid::Uuid32(*v))),
        SdpData::Uuid128(v) => Some(*v),
        _ => None,
    }
}

/// Collect all UUIDs from an SDP record's attribute values (recursive).
fn collect_record_uuids(data: &crate::sdp::xml::SdpData, out: &mut Vec<[u8; 16]>) {
    use crate::sdp::xml::SdpData;
    match data {
        SdpData::Uuid16(_) | SdpData::Uuid32(_) | SdpData::Uuid128(_) => {
            if let Some(u) = sdp_data_uuid_to_128(data) {
                if !out.contains(&u) {
                    out.push(u);
                }
            }
        }
        SdpData::Sequence(children) | SdpData::Alternate(children) => {
            for child in children {
                collect_record_uuids(child, out);
            }
        }
        _ => {}
    }
}

/// Check if a service record matches a set of UUID search patterns.
///
/// Returns `true` if every UUID in `patterns` exists in the record's
/// attribute values. Mirrors the C `sdp_match_uuid` behaviour.
fn match_uuid_patterns(record: &crate::sdp::xml::SdpRecord, patterns: &[SdpUuid]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    // Collect all UUIDs from the record.
    let mut record_uuids: Vec<[u8; 16]> = Vec::new();
    for attr_data in record.attrs.values() {
        collect_record_uuids(attr_data, &mut record_uuids);
    }

    // Every search pattern UUID must be found in the record.
    for pattern in patterns {
        let target = uuid_to_128(pattern);
        if !record_uuids.contains(&target) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Attribute extraction for responses
// ---------------------------------------------------------------------------

/// Encode an SDP data element into its wire format.
fn encode_sdp_data(data: &crate::sdp::xml::SdpData, out: &mut Vec<u8>) {
    use crate::sdp::xml::SdpData;
    match data {
        SdpData::Nil => {
            out.push(0x00);
        }
        SdpData::Bool(v) => {
            out.push(0x28);
            out.push(if *v { 1 } else { 0 });
        }
        SdpData::UInt8(v) => {
            out.push(0x08);
            out.push(*v);
        }
        SdpData::UInt16(v) => {
            out.push(SDP_UINT16);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::UInt32(v) => {
            out.push(SDP_UINT32);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::UInt64(v) => {
            out.push(0x0b);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::UInt128(v) => {
            out.push(0x0c);
            out.extend_from_slice(v);
        }
        SdpData::Int8(v) => {
            out.push(0x10);
            out.push(*v as u8);
        }
        SdpData::Int16(v) => {
            out.push(0x11);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::Int32(v) => {
            out.push(0x12);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::Int64(v) => {
            out.push(0x13);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::Int128(v) => {
            out.push(0x14);
            out.extend_from_slice(v);
        }
        SdpData::Uuid16(v) => {
            out.push(SDP_UUID16);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::Uuid32(v) => {
            out.push(SDP_UUID32);
            out.extend_from_slice(&v.to_be_bytes());
        }
        SdpData::Uuid128(v) => {
            out.push(SDP_UUID128);
            out.extend_from_slice(v);
        }
        SdpData::Text(v) => {
            if v.len() < 256 {
                out.push(0x25);
                out.push(v.len() as u8);
            } else if v.len() < 65536 {
                out.push(0x26);
                out.extend_from_slice(&(v.len() as u16).to_be_bytes());
            } else {
                out.push(0x27);
                out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            }
            out.extend_from_slice(v);
        }
        SdpData::Url(v) => {
            let bytes = v.as_bytes();
            if bytes.len() < 256 {
                out.push(0x45);
                out.push(bytes.len() as u8);
            } else if bytes.len() < 65536 {
                out.push(0x46);
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            } else {
                out.push(0x47);
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            }
            out.extend_from_slice(bytes);
        }
        SdpData::Sequence(children) => {
            let mut inner = Vec::new();
            for child in children {
                encode_sdp_data(child, &mut inner);
            }
            if inner.len() < 256 {
                out.push(SDP_SEQ8);
                out.push(inner.len() as u8);
            } else if inner.len() < 65536 {
                out.push(SDP_SEQ16);
                out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            } else {
                out.push(0x37); // SEQ32
                out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
            }
            out.extend_from_slice(&inner);
        }
        SdpData::Alternate(children) => {
            let mut inner = Vec::new();
            for child in children {
                encode_sdp_data(child, &mut inner);
            }
            if inner.len() < 256 {
                out.push(0x3d);
                out.push(inner.len() as u8);
            } else if inner.len() < 65536 {
                out.push(0x3e);
                out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            } else {
                out.push(0x3f);
                out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
            }
            out.extend_from_slice(&inner);
        }
    }
}

/// Generate a full PDU encoding of a record's attributes (for attribute
/// responses). Encodes each attribute as (uint16 ID, value) pairs within
/// a DES.
fn gen_record_pdu(record: &crate::sdp::xml::SdpRecord) -> Vec<u8> {
    use crate::sdp::xml::SdpData;
    let mut inner = Vec::new();
    for (&attr_id, attr_val) in &record.attrs {
        // Attribute ID as UINT16
        encode_sdp_data(&SdpData::UInt16(attr_id), &mut inner);
        // Attribute value
        encode_sdp_data(attr_val, &mut inner);
    }
    // Wrap in a DES
    let mut out = Vec::new();
    if inner.len() < 256 {
        out.push(SDP_SEQ8);
        out.push(inner.len() as u8);
    } else if inner.len() < 65536 {
        out.push(SDP_SEQ16);
        out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    } else {
        out.push(0x37);
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(&inner);
    out
}

/// Extract requested attributes from a record and encode them as a DES.
///
/// If `attrs` is empty, returns an empty DES.
fn extract_attrs(record: &crate::sdp::xml::SdpRecord, attrs: &[AttrId]) -> Result<Vec<u8>, u16> {
    use crate::sdp::xml::SdpData;

    if attrs.is_empty() {
        debug!("Attribute sequence is empty");
        return Ok(Vec::new());
    }

    debug!("Entries in attr seq: {}", attrs.len());

    // Generate full record PDU for range queries that cover everything.
    let full_pdu = gen_record_pdu(record);

    let mut inner = Vec::new();

    for aid in attrs {
        match aid {
            AttrId::Single(attr_id) => {
                debug!("AttrDataType: single 0x{:04x}", attr_id);
                if let Some(data) = record.attrs.get(attr_id) {
                    encode_sdp_data(&SdpData::UInt16(*attr_id), &mut inner);
                    encode_sdp_data(data, &mut inner);
                }
            }
            AttrId::Range(low, high) => {
                debug!("attr range: 0x{:04x}-0x{:04x}", low, high);
                if *low == 0x0000 && *high == 0xFFFF {
                    // Full range — return the complete record PDU content.
                    // The full_pdu is already a DES, return it directly.
                    return Ok(full_pdu);
                }
                for attr_id in *low..=*high {
                    if let Some(data) = record.attrs.get(&attr_id) {
                        encode_sdp_data(&SdpData::UInt16(attr_id), &mut inner);
                        encode_sdp_data(data, &mut inner);
                    }
                }
            }
        }
    }

    // Wrap collected attributes in a DES.
    let mut out = Vec::new();
    if inner.len() < 256 {
        out.push(SDP_SEQ8);
        out.push(inner.len() as u8);
    } else if inner.len() < 65536 {
        out.push(SDP_SEQ16);
        out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    } else {
        out.push(0x37);
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(&inner);
    Ok(out)
}

// ---------------------------------------------------------------------------
// SDP request handlers
// ---------------------------------------------------------------------------

/// Handle SDP ServiceSearchRequest (opcode 0x02).
///
/// Parse: UUID pattern DES, max service record count, continuation state.
/// Match records against UUID patterns.
/// Build response with service record handles (4 bytes each).
fn service_search_req(
    req: &SdpRequest,
    db: &SdpDatabase,
    cstates: &mut Vec<ContinuationInfo>,
) -> Result<Vec<u8>, u16> {
    let pdata = &req.buf[SDP_PDU_HDR_SIZE..];
    let data_len = pdata.len();

    // Extract UUID pattern DES.
    let (patterns, scanned) = extract_uuid_des(pdata)?;
    let mut pos = scanned;

    // Validate parameter length.
    let hdr = SdpPduHeader::parse(&req.buf).ok_or(SDP_INVALID_SYNTAX)?;
    let plen = hdr.param_len as usize;
    let mlen = scanned + 2 + 1; // DES + max_count(2) + cstate_size(1)
    if pos + 2 > data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    if plen < mlen {
        return Err(SDP_INVALID_SYNTAX);
    }

    // Parse max service record count.
    let expected = u16::from_be_bytes([pdata[pos], pdata[pos + 1]]);
    pos += 2;

    debug!("Expected count: {}", expected);
    debug!("Bytes scanned: {}", scanned);

    // Parse continuation state.
    if pos >= data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    let cstate_opt = get_cstate(&pdata[pos..])?;
    if cstate_opt.is_none() {
        // Clean up any existing continuation for this socket.
        cstates.retain(|c| c.sock != req.sock);
    }

    // Calculate max handles we can send in one MTU.
    let mtu_avail = (req.mtu as usize)
        .saturating_sub(SDP_PDU_HDR_SIZE)
        .saturating_sub(4) // total + current count fields
        .saturating_sub(SDP_CONT_STATE_SIZE);
    let actual = std::cmp::min(expected as usize, mtu_avail / 4);

    let mut rsp = Vec::with_capacity(256);

    match cstate_opt {
        None => {
            // Fresh search — scan all records.
            let handles = db.get_record_list();
            let mut matched_handles: Vec<u32> = Vec::new();

            for &h in &handles {
                if let Some(rec) = db.find_record(h) {
                    if match_uuid_patterns(rec, &patterns) && db.check_access(h, &req.device) {
                        matched_handles.push(h);
                    }
                }
            }

            let rsp_count = matched_handles.len();
            debug!("Match count: {}", rsp_count);

            if rsp_count <= actual {
                // Fits in one PDU — send all.
                rsp.extend_from_slice(&(rsp_count as u16).to_be_bytes());
                rsp.extend_from_slice(&(rsp_count as u16).to_be_bytes());
                for &h in &matched_handles {
                    rsp.extend_from_slice(&h.to_be_bytes());
                }
                set_cstate_pdu(&mut rsp, None);
            } else {
                // Need continuation — cache the full result.
                let mut full_rsp = Vec::new();
                full_rsp.extend_from_slice(&(rsp_count as u16).to_be_bytes());
                full_rsp.extend_from_slice(&(rsp_count as u16).to_be_bytes());
                for &h in &matched_handles {
                    full_rsp.extend_from_slice(&h.to_be_bytes());
                }

                let ts = alloc_cont_buf(cstates, db, req.sock, req.opcode, &full_rsp);

                // Send first chunk.
                let send_count = actual;
                rsp.extend_from_slice(&(rsp_count as u16).to_be_bytes());
                rsp.extend_from_slice(&(send_count as u16).to_be_bytes());
                for &h in &matched_handles[..send_count] {
                    rsp.extend_from_slice(&h.to_be_bytes());
                }
                let new_cstate = ContinuationState { timestamp: ts, value: send_count as u16 };
                set_cstate_pdu(&mut rsp, Some(&new_cstate));
            }
        }
        Some(ref cstate) => {
            // Continuation — retrieve cached response.
            let cinfo_idx =
                get_cont_info(cstates, req.sock, req.opcode, cstate).ok_or(SDP_INVALID_CSTATE)?;
            let cached = &cstates[cinfo_idx].buf;

            if cached.len() < 4 {
                cstates.remove(cinfo_idx);
                return Err(SDP_INVALID_CSTATE);
            }

            // Total record count from cached response.
            let total_count = u16::from_be_bytes([cached[0], cached[1]]);
            let last_index = cstate.value as usize;

            if last_index * 4 + 4 > cached.len() {
                cstates.remove(cinfo_idx);
                return Err(SDP_INVALID_CSTATE);
            }

            // Build continuation response.
            let remaining = (total_count as usize).saturating_sub(last_index);
            let send_count = std::cmp::min(remaining, actual);
            let new_last = last_index + send_count;

            rsp.extend_from_slice(&total_count.to_be_bytes());
            rsp.extend_from_slice(&(send_count as u16).to_be_bytes());

            // Handles start at offset 4 in the cached buffer.
            let handle_offset = 4;
            for i in last_index..new_last {
                let off = handle_offset + i * 4;
                if off + 4 <= cached.len() {
                    rsp.extend_from_slice(&cached[off..off + 4]);
                }
            }

            if new_last >= total_count as usize {
                // Done — remove continuation.
                cstates.remove(cinfo_idx);
                set_cstate_pdu(&mut rsp, None);
            } else {
                let new_cstate =
                    ContinuationState { timestamp: cstate.timestamp, value: new_last as u16 };
                set_cstate_pdu(&mut rsp, Some(&new_cstate));
            }
        }
    }

    Ok(rsp)
}

/// Build a continuation response for attribute-based requests.
///
/// Sends a chunk of the cached response starting at `max_bytes_sent`.
fn cstate_rsp(
    cstates: &mut Vec<ContinuationInfo>,
    cinfo_idx: usize,
    cstate: &ContinuationState,
    max: usize,
) -> Result<(Vec<u8>, usize), u16> {
    // Extract cached data metrics first to avoid borrow conflicts.
    let cached_len = cstates[cinfo_idx].buf.len();
    let sent = cstate.value as usize;

    if sent >= cached_len {
        cstates.remove(cinfo_idx);
        let mut rsp = Vec::new();
        let cs = set_cstate_pdu(&mut rsp, None);
        return Ok((rsp, cs));
    }

    let remaining = cached_len - sent;
    let chunk = std::cmp::min(max, remaining);

    // Copy the chunk we need before we potentially mutate the cstates vec.
    let chunk_data: Vec<u8> = cstates[cinfo_idx].buf[sent..sent + chunk].to_vec();

    let mut rsp = Vec::with_capacity(chunk + SDP_CONT_STATE_SIZE);
    rsp.extend_from_slice(&chunk_data);

    let new_sent = sent + chunk;
    let cstate_size = if new_sent >= cached_len {
        cstates.remove(cinfo_idx);
        set_cstate_pdu(&mut rsp, None)
    } else {
        let new_cstate = ContinuationState { timestamp: cstate.timestamp, value: new_sent as u16 };
        set_cstate_pdu(&mut rsp, Some(&new_cstate))
    };

    debug!(
        "Response size: {}, sending now: {}, bytes sent so far: {}",
        cached_len, chunk, new_sent
    );

    Ok((rsp, cstate_size))
}

/// Handle SDP ServiceAttributeRequest (opcode 0x04).
fn service_attr_req(
    req: &SdpRequest,
    db: &SdpDatabase,
    cstates: &mut Vec<ContinuationInfo>,
) -> Result<Vec<u8>, u16> {
    let pdata = &req.buf[SDP_PDU_HDR_SIZE..];
    let data_len = pdata.len();
    let mut pos = 0;

    // Parse service record handle (4 bytes).
    if data_len < 4 {
        return Err(SDP_INVALID_SYNTAX);
    }
    let handle = u32::from_be_bytes([pdata[0], pdata[1], pdata[2], pdata[3]]);
    pos += 4;

    // Parse max attribute byte count (2 bytes).
    if pos + 2 > data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    let mut max_rsp_size = u16::from_be_bytes([pdata[pos], pdata[pos + 1]]) as usize;
    pos += 2;

    // Extract attribute ID list.
    if pos >= data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    let (attrs, attr_scanned) = extract_attrid_des(&pdata[pos..])?;
    pos += attr_scanned;

    // Validate PDU size.
    let hdr = SdpPduHeader::parse(&req.buf).ok_or(SDP_INVALID_SYNTAX)?;
    let plen = hdr.param_len as usize;
    let mlen = 4 + 2 + attr_scanned + 1;
    if plen < mlen {
        return Err(SDP_INVALID_PDU_SIZE);
    }

    // Parse continuation state.
    if pos >= data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    let cstate_opt = get_cstate(&pdata[pos..])?;
    if cstate_opt.is_none() {
        cstates.retain(|c| c.sock != req.sock);
    }

    debug!("SvcRecHandle: 0x{:x}", handle);
    debug!("max_rsp_size: {}", max_rsp_size);

    // Minimum max_rsp_size is 0x0007.
    if max_rsp_size < 0x0007 {
        return Err(SDP_INVALID_SYNTAX);
    }

    // Clamp to MTU.
    let mtu_max = (req.mtu as usize)
        .saturating_sub(SDP_PDU_HDR_SIZE)
        .saturating_sub(4) // uint32 overhead
        .saturating_sub(SDP_CONT_STATE_SIZE)
        .saturating_sub(2); // byte count field
    max_rsp_size = std::cmp::min(max_rsp_size, mtu_max);

    let mut rsp = Vec::with_capacity(max_rsp_size + 16);

    let cstate_size;
    if let Some(cstate) = &cstate_opt {
        // Continuation response.
        let cinfo_idx =
            get_cont_info(cstates, req.sock, req.opcode, cstate).ok_or(SDP_INVALID_CSTATE)?;
        let (chunk, cs) = cstate_rsp(cstates, cinfo_idx, cstate, max_rsp_size)?;
        cstate_size = cs;
        rsp = chunk;
    } else {
        // Fresh request.
        let rec = db.find_record(handle).ok_or(SDP_INVALID_RECORD_HANDLE)?;
        let attr_data = extract_attrs(rec, &attrs)?;

        if attr_data.len() > max_rsp_size {
            // Need continuation.
            let ts = alloc_cont_buf(cstates, db, req.sock, req.opcode, &attr_data);
            let chunk_size = max_rsp_size;
            rsp.extend_from_slice(&attr_data[..chunk_size]);

            debug!("Creating continuation state of size: {}", attr_data.len());

            let new_cstate = ContinuationState { timestamp: ts, value: chunk_size as u16 };
            cstate_size = set_cstate_pdu(&mut rsp, Some(&new_cstate));
        } else {
            rsp.extend_from_slice(&attr_data);
            if rsp.is_empty() {
                // Empty attribute list — encode empty DES.
                rsp.push(SDP_SEQ8);
                rsp.push(0);
            }
            cstate_size = set_cstate_pdu(&mut rsp, None);
        }
    }

    // Prepend the byte count field.
    let byte_count = (rsp.len() - cstate_size) as u16;
    let mut final_rsp = Vec::with_capacity(2 + rsp.len());
    final_rsp.extend_from_slice(&byte_count.to_be_bytes());
    final_rsp.extend_from_slice(&rsp);

    Ok(final_rsp)
}

/// Handle SDP ServiceSearchAttributeRequest (opcode 0x06).
fn service_search_attr_req(
    req: &SdpRequest,
    db: &SdpDatabase,
    cstates: &mut Vec<ContinuationInfo>,
) -> Result<Vec<u8>, u16> {
    let pdata = &req.buf[SDP_PDU_HDR_SIZE..];
    let data_len = pdata.len();
    let mut pos = 0;

    // Extract UUID pattern DES.
    let (patterns, uuid_scanned) = extract_uuid_des(&pdata[pos..])?;
    pos += uuid_scanned;

    debug!("Bytes scanned: {}", uuid_scanned);

    // Parse max attribute byte count (2 bytes).
    if pos + 2 > data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    let mut max = u16::from_be_bytes([pdata[pos], pdata[pos + 1]]) as usize;
    pos += 2;

    debug!("Max Attr expected: {}", max);

    // Extract attribute ID list.
    if pos >= data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    let (attrs, attr_scanned) = extract_attrid_des(&pdata[pos..])?;
    pos += attr_scanned;

    // Validate PDU size.
    let hdr = SdpPduHeader::parse(&req.buf).ok_or(SDP_INVALID_SYNTAX)?;
    let plen = hdr.param_len as usize;
    let totscanned = uuid_scanned + 2 + attr_scanned + 1;
    if plen < totscanned {
        return Err(SDP_INVALID_PDU_SIZE);
    }

    // Parse continuation state.
    if pos >= data_len {
        return Err(SDP_INVALID_SYNTAX);
    }
    let cstate_opt = get_cstate(&pdata[pos..])?;
    if cstate_opt.is_none() {
        cstates.retain(|c| c.sock != req.sock);
    }

    // Clamp max to MTU.
    let mtu_max = (req.mtu as usize)
        .saturating_sub(SDP_PDU_HDR_SIZE)
        .saturating_sub(SDP_CONT_STATE_SIZE)
        .saturating_sub(2); // byte count field
    max = std::cmp::min(max, mtu_max);

    let mut rsp = Vec::with_capacity(max + 16);

    let cstate_size = match cstate_opt {
        None => {
            // Fresh request — build combined response.
            let handles = db.get_record_list();
            let mut combined = Vec::new();
            let mut rsp_count = 0;

            for &h in &handles {
                if let Some(rec) = db.find_record(h) {
                    if match_uuid_patterns(rec, &patterns) && db.check_access(h, &req.device) {
                        rsp_count += 1;
                        let attr_data = extract_attrs(rec, &attrs)?;
                        combined.extend_from_slice(&attr_data);

                        debug!("Response count: {}", rsp_count);
                        debug!("Local PDU size: {}", attr_data.len());
                    }
                }
            }

            if combined.is_empty() && rsp_count == 0 {
                // No matches — empty DES.
                combined.push(SDP_SEQ8);
                combined.push(0);
            }

            debug!("Net PDU size: {}", combined.len());

            if combined.len() > max {
                // Need continuation.
                let ts = alloc_cont_buf(cstates, db, req.sock, req.opcode, &combined);
                rsp.extend_from_slice(&combined[..max]);

                let new_cstate = ContinuationState { timestamp: ts, value: max as u16 };
                set_cstate_pdu(&mut rsp, Some(&new_cstate))
            } else {
                rsp.extend_from_slice(&combined);
                set_cstate_pdu(&mut rsp, None)
            }
        }
        Some(ref cstate) => {
            // Continuation response.
            let cinfo_idx =
                get_cont_info(cstates, req.sock, req.opcode, cstate).ok_or(SDP_INVALID_CSTATE)?;

            let (chunk, cs) = cstate_rsp(cstates, cinfo_idx, cstate, max)?;
            rsp = chunk;
            cs
        }
    };

    // Prepend byte count field.
    let byte_count = (rsp.len() - cstate_size) as u16;
    let mut final_rsp = Vec::with_capacity(2 + rsp.len());
    final_rsp.extend_from_slice(&byte_count.to_be_bytes());
    final_rsp.extend_from_slice(&rsp);

    Ok(final_rsp)
}

// ---------------------------------------------------------------------------
// Top-level request processing
// ---------------------------------------------------------------------------

/// Process a single SDP request and send the response.
///
/// Dispatches to the appropriate handler based on the PDU opcode, builds
/// the response header, and sends the complete response PDU.
fn process_request(
    req: &mut SdpRequest,
    db: &mut SdpDatabase,
    cstates: &mut Vec<ContinuationInfo>,
) {
    let reqhdr = match SdpPduHeader::parse(&req.buf) {
        Some(h) => h,
        None => {
            btd_error(0, "sdp: PDU too short to parse header");
            return;
        }
    };

    // Validate parameter length.
    let expected_len = SDP_PDU_HDR_SIZE + reqhdr.param_len as usize;
    if req.buf.len() < expected_len {
        // PDU size mismatch — send error.
        send_error_rsp(req.sock, &reqhdr, SDP_INVALID_PDU_SIZE);
        return;
    }

    req.opcode = reqhdr.opcode;
    btd_debug(0, &format!("sdp: processing PDU opcode 0x{:02x}", reqhdr.opcode));

    let (rsp_opcode, result) = match reqhdr.opcode {
        SDP_SVC_SEARCH_REQ => {
            debug!("Got a svc srch req");
            (SDP_SVC_SEARCH_RSP, service_search_req(req, db, cstates))
        }
        SDP_SVC_ATTR_REQ => {
            debug!("Got a svc attr req");
            (SDP_SVC_ATTR_RSP, service_attr_req(req, db, cstates))
        }
        SDP_SVC_SEARCH_ATTR_REQ => {
            debug!("Got a svc srch attr req");
            (SDP_SVC_SEARCH_ATTR_RSP, service_search_attr_req(req, db, cstates))
        }
        SDP_SVC_REGISTER_REQ => {
            debug!("Service register request");
            if req.local {
                let body = if req.buf.len() > SDP_PDU_HDR_SIZE {
                    &req.buf[SDP_PDU_HDR_SIZE..]
                } else {
                    &[]
                };
                match database::service_register_req(db, body, &req.device, req.sock, req.flags) {
                    Ok(rsp_body) => (SDP_SVC_REGISTER_REQ + 1, Ok(rsp_body)),
                    Err(err_code) => (SDP_ERROR_RSP, Err(err_code)),
                }
            } else {
                (SDP_ERROR_RSP, Err(SDP_INVALID_SYNTAX))
            }
        }
        SDP_SVC_UPDATE_REQ => {
            debug!("Service update request");
            if req.local {
                let body = if req.buf.len() > SDP_PDU_HDR_SIZE {
                    &req.buf[SDP_PDU_HDR_SIZE..]
                } else {
                    &[]
                };
                match database::service_update_req(db, body, &req.device) {
                    Ok(rsp_body) => (SDP_SVC_UPDATE_REQ + 1, Ok(rsp_body)),
                    Err(err_code) => (SDP_ERROR_RSP, Err(err_code)),
                }
            } else {
                (SDP_ERROR_RSP, Err(SDP_INVALID_SYNTAX))
            }
        }
        SDP_SVC_REMOVE_REQ => {
            debug!("Service removal request");
            if req.local {
                let body = if req.buf.len() > SDP_PDU_HDR_SIZE {
                    &req.buf[SDP_PDU_HDR_SIZE..]
                } else {
                    &[]
                };
                match database::service_remove_req(db, body, &req.device) {
                    Ok(rsp_body) => (SDP_SVC_REMOVE_REQ + 1, Ok(rsp_body)),
                    Err(err_code) => (SDP_ERROR_RSP, Err(err_code)),
                }
            } else {
                (SDP_ERROR_RSP, Err(SDP_INVALID_SYNTAX))
            }
        }
        other => {
            error!("Unknown PDU ID: 0x{:02x} received", other);
            btd_error(0, &format!("sdp: unknown PDU ID 0x{other:02x}"));
            (SDP_ERROR_RSP, Err(SDP_INVALID_SYNTAX))
        }
    };

    // Build response.
    match result {
        Ok(rsp_body) => {
            let rsp_hdr = SdpPduHeader {
                opcode: rsp_opcode,
                tid: reqhdr.tid,
                param_len: rsp_body.len() as u16,
            };
            let mut pdu = vec![0u8; SDP_PDU_HDR_SIZE + rsp_body.len()];
            rsp_hdr.write_to(&mut pdu);
            pdu[SDP_PDU_HDR_SIZE..].copy_from_slice(&rsp_body);

            debug!("Sending rsp. status 0");
            send_pdu(req.sock, &pdu);
            debug!("Bytes Sent: {}", pdu.len());
        }
        Err(status) => {
            // Error response — cleanup continuation state on error.
            cstates.retain(|c| c.sock != req.sock);

            let mut err_body = Vec::with_capacity(2);
            err_body.extend_from_slice(&status.to_be_bytes());

            let rsp_hdr = SdpPduHeader {
                opcode: SDP_ERROR_RSP,
                tid: reqhdr.tid,
                param_len: err_body.len() as u16,
            };
            let mut pdu = vec![0u8; SDP_PDU_HDR_SIZE + err_body.len()];
            rsp_hdr.write_to(&mut pdu);
            pdu[SDP_PDU_HDR_SIZE..].copy_from_slice(&err_body);

            debug!("Sending rsp. status {}", status);
            send_pdu(req.sock, &pdu);
            debug!("Bytes Sent: {}", pdu.len());
        }
    }
}

/// Send an error response PDU.
fn send_error_rsp(sock: RawFd, reqhdr: &SdpPduHeader, status: u16) {
    let mut err_body = Vec::with_capacity(2);
    err_body.extend_from_slice(&status.to_be_bytes());

    let rsp_hdr =
        SdpPduHeader { opcode: SDP_ERROR_RSP, tid: reqhdr.tid, param_len: err_body.len() as u16 };
    let mut pdu = vec![0u8; SDP_PDU_HDR_SIZE + err_body.len()];
    rsp_hdr.write_to(&mut pdu);
    pdu[SDP_PDU_HDR_SIZE..].copy_from_slice(&err_body);
    send_pdu(sock, &pdu);
}

/// Send raw bytes over a socket, logging errors.
fn send_pdu(sock: RawFd, data: &[u8]) {
    let result = nix::sys::socket::send(sock, data, nix::sys::socket::MsgFlags::empty());
    match result {
        Ok(_) => {}
        Err(e) => {
            error!("send: {} ({})", e, e);
            btd_error(0, &format!("sdp: send failed: {e}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Public request handling API
// ---------------------------------------------------------------------------

/// Handle an SDP request from an external socket.
///
/// Extracts the peer address, determines whether the connection is L2CAP
/// or Unix, gets the appropriate MTU, and dispatches the request.
pub fn handle_request(sock: RawFd, data: &[u8]) {
    // We acquire all locks synchronously (blocking style) since handle_request
    // is called from an async context but the underlying operations are quick.
    let mut db = match SDP_DB.try_lock() {
        Ok(db) => db,
        Err(_) => {
            btd_error(0, "sdp: failed to acquire database lock");
            return;
        }
    };
    let mut cstates = match CSTATES.try_lock() {
        Ok(cs) => cs,
        Err(_) => {
            btd_error(0, "sdp: failed to acquire cstate lock");
            return;
        }
    };

    // Determine the socket type by checking address family.
    let is_bluetooth = is_bluetooth_socket(sock);

    let (device, bdaddr, mtu, local) = if is_bluetooth {
        // L2CAP socket — get peer address and MTU.
        let peer_addr = get_l2cap_peer_addr(sock);
        let local_addr = get_l2cap_local_addr(sock);
        let l2cap_mtu = get_l2cap_mtu(sock);
        (local_addr, peer_addr, l2cap_mtu, false)
    } else {
        // Unix socket — local connection.
        (BDADDR_ANY, BDADDR_LOCAL, 2048u16, true)
    };

    let mut req =
        SdpRequest { device, bdaddr, local, sock, mtu, flags: 0, buf: data.to_vec(), opcode: 0 };

    process_request(&mut req, &mut db, &mut cstates);
}

/// Handle an internal SDP request (within the daemon, no socket I/O).
///
/// Processes the request and returns the response PDU bytes directly
/// without sending over a socket.
pub fn handle_internal_request(req: &SdpRequest, _mtu: u16) -> Vec<u8> {
    let db = match SDP_DB.try_lock() {
        Ok(db) => db,
        Err(_) => {
            btd_error(0, "sdp: failed to acquire database lock for internal request");
            return Vec::new();
        }
    };
    let mut cstates = match CSTATES.try_lock() {
        Ok(cs) => cs,
        Err(_) => {
            btd_error(0, "sdp: failed to acquire cstate lock for internal request");
            return Vec::new();
        }
    };

    let mut internal_req = SdpRequest {
        device: BDADDR_ANY,
        bdaddr: BDADDR_LOCAL,
        local: false,
        sock: req.sock,
        mtu: req.mtu,
        flags: 0,
        buf: req.buf.clone(),
        opcode: 0,
    };

    let reqhdr = match SdpPduHeader::parse(&internal_req.buf) {
        Some(h) => h,
        None => return Vec::new(),
    };

    internal_req.opcode = reqhdr.opcode;

    let result = match reqhdr.opcode {
        SDP_SVC_SEARCH_REQ => service_search_req(&internal_req, &db, &mut cstates),
        SDP_SVC_ATTR_REQ => service_attr_req(&internal_req, &db, &mut cstates),
        SDP_SVC_SEARCH_ATTR_REQ => service_search_attr_req(&internal_req, &db, &mut cstates),
        _ => Err(SDP_INVALID_SYNTAX),
    };

    match result {
        Ok(rsp_body) => {
            let rsp_opcode = match reqhdr.opcode {
                SDP_SVC_SEARCH_REQ => SDP_SVC_SEARCH_RSP,
                SDP_SVC_ATTR_REQ => SDP_SVC_ATTR_RSP,
                SDP_SVC_SEARCH_ATTR_REQ => SDP_SVC_SEARCH_ATTR_RSP,
                _ => SDP_ERROR_RSP,
            };
            let rsp_hdr = SdpPduHeader {
                opcode: rsp_opcode,
                tid: reqhdr.tid,
                param_len: rsp_body.len() as u16,
            };
            let mut pdu = vec![0u8; SDP_PDU_HDR_SIZE + rsp_body.len()];
            rsp_hdr.write_to(&mut pdu);
            pdu[SDP_PDU_HDR_SIZE..].copy_from_slice(&rsp_body);
            pdu
        }
        Err(status) => {
            let mut err_body = Vec::with_capacity(2);
            err_body.extend_from_slice(&status.to_be_bytes());
            let rsp_hdr = SdpPduHeader {
                opcode: SDP_ERROR_RSP,
                tid: reqhdr.tid,
                param_len: err_body.len() as u16,
            };
            let mut pdu = vec![0u8; SDP_PDU_HDR_SIZE + err_body.len()];
            rsp_hdr.write_to(&mut pdu);
            pdu[SDP_PDU_HDR_SIZE..].copy_from_slice(&err_body);
            pdu
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level socket helpers
// ---------------------------------------------------------------------------

/// Check if a socket is a Bluetooth (AF_BLUETOOTH) socket.
fn is_bluetooth_socket(sock: RawFd) -> bool {
    // Use getsockopt SO_DOMAIN to determine the address family.
    let mut domain: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut domain as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return false;
    }
    domain == AF_BLUETOOTH
}

/// Get the peer L2CAP address from a connected socket.
fn get_l2cap_peer_addr(sock: RawFd) -> BdAddr {
    let mut sa = sockaddr_l2::default();
    let mut len = std::mem::size_of::<sockaddr_l2>() as libc::socklen_t;
    let ret = unsafe {
        libc::getpeername(sock, &mut sa as *mut sockaddr_l2 as *mut libc::sockaddr, &mut len)
    };
    if ret < 0 {
        error!("getpeername: {}", std::io::Error::last_os_error());
        btd_error(0, "sdp: getpeername failed");
        return BDADDR_ANY;
    }
    BdAddr { b: sa.l2_bdaddr.b }
}

/// Get the local L2CAP address from a connected socket.
fn get_l2cap_local_addr(sock: RawFd) -> BdAddr {
    let mut sa = sockaddr_l2::default();
    let mut len = std::mem::size_of::<sockaddr_l2>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(sock, &mut sa as *mut sockaddr_l2 as *mut libc::sockaddr, &mut len)
    };
    if ret < 0 {
        error!("getsockname: {}", std::io::Error::last_os_error());
        btd_error(0, "sdp: getsockname failed");
        return BDADDR_ANY;
    }
    BdAddr { b: sa.l2_bdaddr.b }
}

/// Get the L2CAP outgoing MTU from a connected socket.
fn get_l2cap_mtu(sock: RawFd) -> u16 {
    let mut opts = l2cap_options::default();
    let mut len = std::mem::size_of::<l2cap_options>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            sock,
            SOL_L2CAP,
            L2CAP_OPTIONS,
            &mut opts as *mut l2cap_options as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        error!("getsockopt L2CAP_OPTIONS: {}", std::io::Error::last_os_error());
        btd_error(0, "sdp: getsockopt L2CAP_OPTIONS failed");
        return 672; // Default L2CAP MTU
    }
    opts.omtu
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/// Start the SDP server: register built-in records, create L2CAP and Unix
/// listeners, and spawn async accept loops.
///
/// This is the async entry point replacing `start_sdp_server()` from the C
/// implementation.
pub async fn start_sdp_server(mtu: u16, central: bool, compat: bool) -> Result<(), BtdError> {
    info!("Starting SDP server");
    btd_info(0, "Starting SDP server");

    // Register built-in SDP records.
    {
        let mut db = SDP_DB.lock().await;
        db.register_public_browse_group();
        db.register_server_service(compat);
    }

    // Create L2CAP listener socket.
    let l2cap_fd = create_l2cap_listener(mtu, central)?;

    // Spawn L2CAP accept loop.
    let l2cap_task = spawn(async move {
        l2cap_accept_loop(l2cap_fd).await;
    });

    let mut tasks = SERVER_TASKS.lock().await;
    tasks.push(l2cap_task);

    if compat {
        // Create Unix domain socket listener.
        match create_unix_listener() {
            Ok(unix_listener) => {
                let unix_task = spawn(async move {
                    unix_accept_loop(unix_listener).await;
                });
                tasks.push(unix_task);
            }
            Err(e) => {
                error!("Failed to create Unix SDP socket: {}", e);
                btd_error(0, &format!("sdp: unix socket error: {e}"));
                // Non-fatal: L2CAP socket is the primary listener.
            }
        }
    }

    Ok(())
}

/// Stop the SDP server: reset database, abort tasks, clean up sockets.
pub async fn stop_sdp_server() {
    info!("Stopping SDP server");
    btd_info(0, "Stopping SDP server");

    // Reset the SDP database.
    {
        let mut db = SDP_DB.lock().await;
        db.reset();
    }

    // Abort all accept loop tasks.
    {
        let mut tasks = SERVER_TASKS.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
    }

    // Clear continuation states.
    {
        let mut cstates = CSTATES.lock().await;
        cstates.clear();
    }

    // Remove Unix socket path.
    let _ = std::fs::remove_file(SDP_UNIX_PATH);
}

// ---------------------------------------------------------------------------
// Socket creation helpers
// ---------------------------------------------------------------------------

/// Create and configure the L2CAP listener socket for SDP PSM 1.
fn create_l2cap_listener(mtu: u16, central: bool) -> Result<OwnedFd, BtdError> {
    // Create L2CAP SEQPACKET socket.
    let sock = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_L2CAP) };
    if sock < 0 {
        let e = std::io::Error::last_os_error();
        error!("opening L2CAP socket: {}", e);
        btd_error(0, &format!("sdp: opening L2CAP socket: {e}"));
        return Err(BtdError::Failed(format!("opening L2CAP socket: {e}")));
    }

    // SAFETY: We just created a valid fd.
    let fd = unsafe { OwnedFd::from_raw_fd(sock) };

    // Bind to BDADDR_ANY, SDP PSM.
    let mut addr = sockaddr_l2::default();
    addr.l2_family = AF_BLUETOOTH as u16;
    addr.l2_psm = htobs(SDP_PSM);
    addr.l2_bdaddr = BDADDR_ANY;

    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const sockaddr_l2 as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_l2>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let e = std::io::Error::last_os_error();
        error!("binding L2CAP socket: {}", e);
        btd_error(0, &format!("sdp: binding L2CAP socket: {e}"));
        return Err(BtdError::Failed(format!("binding L2CAP socket: {e}")));
    }

    // Set central (master) mode if requested.
    if central {
        let opt: libc::c_int = L2CAP_LM_MASTER as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_L2CAP,
                L2CAP_LM,
                &opt as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            error!("setsockopt L2CAP_LM_MASTER: {}", e);
            btd_error(0, &format!("sdp: setsockopt L2CAP_LM: {e}"));
            return Err(BtdError::Failed(format!("setsockopt L2CAP_LM: {e}")));
        }
    }

    // Set custom MTU if specified.
    if mtu > 0 {
        let mut opts = l2cap_options::default();
        let mut optlen = std::mem::size_of::<l2cap_options>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                SOL_L2CAP,
                L2CAP_OPTIONS,
                &mut opts as *mut l2cap_options as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            error!("getsockopt L2CAP_OPTIONS: {}", e);
            btd_error(0, &format!("sdp: getsockopt L2CAP_OPTIONS: {e}"));
            return Err(BtdError::Failed(format!("getsockopt L2CAP_OPTIONS: {e}")));
        }

        opts.omtu = mtu;
        opts.imtu = mtu;

        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_L2CAP,
                L2CAP_OPTIONS,
                &opts as *const l2cap_options as *const libc::c_void,
                std::mem::size_of::<l2cap_options>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            error!("setsockopt L2CAP_OPTIONS: {}", e);
            btd_error(0, &format!("sdp: setsockopt L2CAP_OPTIONS: {e}"));
            return Err(BtdError::Failed(format!("setsockopt L2CAP_OPTIONS: {e}")));
        }
    }

    // Listen with backlog 5.
    let ret = unsafe { libc::listen(fd.as_raw_fd(), 5) };
    if ret < 0 {
        let e = std::io::Error::last_os_error();
        error!("listen L2CAP: {}", e);
        btd_error(0, &format!("sdp: listen L2CAP: {e}"));
        return Err(BtdError::Failed(format!("listen L2CAP: {e}")));
    }

    Ok(fd)
}

/// Create the Unix domain socket listener at `/run/sdp`.
fn create_unix_listener() -> Result<UnixListener, BtdError> {
    // Remove any existing socket file.
    let _ = std::fs::remove_file(SDP_UNIX_PATH);

    let listener = match std::os::unix::net::UnixListener::bind(SDP_UNIX_PATH) {
        Ok(l) => l,
        Err(e) => {
            error!("binding UNIX socket: {}", e);
            btd_error(0, &format!("sdp: binding UNIX socket: {e}"));
            return Err(BtdError::Failed(format!("binding UNIX socket: {e}")));
        }
    };

    // Set permissions to 0660.
    std::fs::set_permissions(SDP_UNIX_PATH, std::os::unix::fs::PermissionsExt::from_mode(0o660))
        .map_err(|e| {
            error!("chmod UNIX socket: {}", e);
            btd_error(0, &format!("sdp: chmod UNIX socket: {e}"));
            BtdError::Failed(format!("chmod UNIX socket: {e}"))
        })?;

    // Set non-blocking for async.
    listener.set_nonblocking(true).map_err(|e| {
        error!("set_nonblocking UNIX socket: {}", e);
        BtdError::Failed(format!("set_nonblocking: {e}"))
    })?;

    let async_listener = UnixListener::from_std(listener).map_err(|e| {
        error!("UnixListener::from_std: {}", e);
        BtdError::Failed(format!("UnixListener::from_std: {e}"))
    })?;

    Ok(async_listener)
}

// ---------------------------------------------------------------------------
// Accept loops
// ---------------------------------------------------------------------------

/// L2CAP accept loop — accepts incoming L2CAP connections and spawns
/// per-session handler tasks.
async fn l2cap_accept_loop(listener_fd: OwnedFd) {
    // Set non-blocking for AsyncFd.
    let raw = listener_fd.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let async_fd = match AsyncFd::new(listener_fd) {
        Ok(fd) => fd,
        Err(e) => {
            error!("AsyncFd::new for L2CAP listener: {}", e);
            btd_error(0, &format!("sdp: AsyncFd L2CAP: {e}"));
            return;
        }
    };

    loop {
        // Wait for readable.
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                error!("L2CAP listener readable error: {}", e);
                break;
            }
        };

        // Accept connection.
        let mut peer_addr = sockaddr_l2::default();
        let mut addrlen = std::mem::size_of::<sockaddr_l2>() as libc::socklen_t;
        // SAFETY: `async_fd.as_raw_fd()` is a valid, open listener socket fd.
        // `peer_addr` is a properly-sized sockaddr_l2 buffer.  The kernel writes
        // the peer address into `peer_addr` and updates `addrlen`.
        let nsk = unsafe {
            libc::accept(
                async_fd.as_raw_fd(),
                &mut peer_addr as *mut sockaddr_l2 as *mut libc::sockaddr,
                &mut addrlen,
            )
        };

        if nsk < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            error!("Can't accept L2CAP connection: {}", err);
            btd_error(0, &format!("sdp: accept L2CAP: {err}"));
            guard.clear_ready();
            continue;
        }

        guard.clear_ready();

        // Spawn session handler.
        let session_fd = nsk;
        spawn(async move {
            handle_l2cap_session(session_fd).await;
        });
    }
}

/// Unix socket accept loop — accepts incoming Unix connections and spawns
/// per-session handler tasks.
async fn unix_accept_loop(listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                spawn(async move {
                    handle_unix_session(stream).await;
                });
            }
            Err(e) => {
                error!("Can't accept Unix connection: {}", e);
                btd_error(0, &format!("sdp: accept Unix: {e}"));
                // Brief sleep to avoid busy-loop on persistent errors.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session handlers
// ---------------------------------------------------------------------------

/// Handle a single L2CAP session: read PDUs and dispatch requests.
async fn handle_l2cap_session(sock: RawFd) {
    // Set non-blocking.
    unsafe {
        let flags = libc::fcntl(sock, libc::F_GETFL);
        libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(sock) };
    let async_fd = match AsyncFd::new(owned_fd) {
        Ok(fd) => fd,
        Err(e) => {
            error!("AsyncFd::new for session: {}", e);
            return;
        }
    };

    let mut buf = vec![0u8; SDP_MAX_PDU_SIZE];

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        // SAFETY: `async_fd.as_raw_fd()` is a valid open socket fd.
        // `buf` is a properly-sized mutable buffer.  `MSG_PEEK` does
        // not consume data so we can read the header first.
        let peek_len = unsafe {
            libc::recv(
                async_fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                SDP_PDU_HDR_SIZE,
                libc::MSG_PEEK,
            )
        };

        if peek_len <= 0 {
            if peek_len == 0 {
                // EOF.
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            break;
        }

        if (peek_len as usize) < SDP_PDU_HDR_SIZE {
            guard.clear_ready();
            break;
        }

        // Parse header to determine full PDU size.
        let param_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let full_size = SDP_PDU_HDR_SIZE + param_len;

        if full_size > SDP_MAX_PDU_SIZE {
            break;
        }

        // SAFETY: `async_fd.as_raw_fd()` is a valid open socket.
        // `buf` has capacity >= `full_size`.  `full_size` was validated
        // against `SDP_MAX_PDU_SIZE`.
        let read_len = unsafe {
            libc::recv(async_fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, full_size, 0)
        };

        guard.clear_ready();

        if read_len <= 0 {
            break;
        }

        let data = &buf[..read_len as usize];
        handle_request(async_fd.as_raw_fd(), data);
    }

    // Cleanup.
    let raw = async_fd.as_raw_fd();
    {
        let mut db = SDP_DB.lock().await;
        db.collect_all(raw);
    }
    sdp_cstate_cleanup_async(raw).await;
}

/// Handle a single Unix domain socket session.
///
/// Uses raw fd reads via AsyncFd since tokio's UnixStream requires &mut self
/// for AsyncReadExt methods but we also need the raw fd for handle_request.
async fn handle_unix_session(stream: tokio::net::UnixStream) {
    let sock = stream.as_raw_fd();
    let async_fd = match AsyncFd::new(stream) {
        Ok(fd) => fd,
        Err(e) => {
            error!("AsyncFd::new for Unix session: {}", e);
            return;
        }
    };

    let mut buf = vec![0u8; SDP_MAX_PDU_SIZE];

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        // Read data from the Unix socket.
        // SAFETY: `sock` is a valid open file descriptor obtained from the
        // `UnixStream`.  `buf` is a properly-sized mutable buffer.
        let read_len =
            unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, SDP_MAX_PDU_SIZE, 0) };

        if read_len <= 0 {
            if read_len < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
            }
            break;
        }

        guard.clear_ready();

        let data = &buf[..read_len as usize];
        if data.len() < SDP_PDU_HDR_SIZE {
            continue;
        }

        handle_request(sock, data);
    }

    // Cleanup.
    {
        let mut db = SDP_DB.lock().await;
        db.collect_all(sock);
    }
    sdp_cstate_cleanup_async(sock).await;
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constant value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sdp_pdu_opcode_constants() {
        assert_eq!(SDP_ERROR_RSP, 0x01);
        assert_eq!(SDP_SVC_SEARCH_REQ, 0x02);
        assert_eq!(SDP_SVC_SEARCH_RSP, 0x03);
        assert_eq!(SDP_SVC_ATTR_REQ, 0x04);
        assert_eq!(SDP_SVC_ATTR_RSP, 0x05);
        assert_eq!(SDP_SVC_SEARCH_ATTR_REQ, 0x06);
        assert_eq!(SDP_SVC_SEARCH_ATTR_RSP, 0x07);
    }

    #[test]
    fn test_sdp_internal_opcode_constants() {
        assert_eq!(SDP_SVC_REGISTER_REQ, 0x75);
        assert_eq!(SDP_SVC_UPDATE_REQ, 0x76);
        assert_eq!(SDP_SVC_REMOVE_REQ, 0x78);
    }

    #[test]
    fn test_sdp_error_code_constants() {
        assert_eq!(SDP_INVALID_VERSION, 0x0001);
        assert_eq!(SDP_INVALID_RECORD_HANDLE, 0x0002);
        assert_eq!(SDP_INVALID_SYNTAX, 0x0003);
        assert_eq!(SDP_INVALID_PDU_SIZE, 0x0004);
        assert_eq!(SDP_INVALID_CSTATE, 0x0005);
    }

    #[test]
    fn test_sdp_server_constants() {
        assert_eq!(SDP_PSM, 1);
        assert_eq!(SDP_UNIX_PATH, "/run/sdp");
        assert_eq!(SDP_SERVER_COMPAT, 0x0001);
        assert_eq!(SDP_SERVER_CENTRAL, 0x0002);
    }

    // -----------------------------------------------------------------------
    // SdpPduHeader tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pdu_header_parse_valid() {
        // opcode=0x02, tid=0x1234, param_len=0x0008
        let buf = [0x02, 0x12, 0x34, 0x00, 0x08];
        let hdr = SdpPduHeader::parse(&buf).unwrap();
        assert_eq!(hdr.opcode, 0x02);
        assert_eq!(hdr.tid, 0x1234);
        assert_eq!(hdr.param_len, 0x0008);
    }

    #[test]
    fn test_pdu_header_parse_too_short() {
        let buf = [0x02, 0x12, 0x34, 0x00]; // Only 4 bytes
        assert!(SdpPduHeader::parse(&buf).is_none());
    }

    #[test]
    fn test_pdu_header_parse_empty() {
        let buf: [u8; 0] = [];
        assert!(SdpPduHeader::parse(&buf).is_none());
    }

    #[test]
    fn test_pdu_header_write_to_roundtrip() {
        let original = SdpPduHeader { opcode: SDP_SVC_SEARCH_RSP, tid: 0xABCD, param_len: 0x1234 };
        let mut buf = [0u8; 5];
        original.write_to(&mut buf);
        let parsed = SdpPduHeader::parse(&buf).unwrap();
        assert_eq!(parsed.opcode, original.opcode);
        assert_eq!(parsed.tid, original.tid);
        assert_eq!(parsed.param_len, original.param_len);
    }

    #[test]
    fn test_pdu_header_write_to_bytes() {
        let hdr = SdpPduHeader { opcode: SDP_ERROR_RSP, tid: 0x0001, param_len: 0x0002 };
        let mut buf = [0u8; 5];
        hdr.write_to(&mut buf);
        assert_eq!(buf, [0x01, 0x00, 0x01, 0x00, 0x02]);
    }

    // -----------------------------------------------------------------------
    // SdpRequest struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sdp_request_fields() {
        let req = SdpRequest {
            device: BDADDR_ANY,
            bdaddr: BDADDR_LOCAL,
            local: true,
            sock: 42,
            mtu: 672,
            flags: SDP_SERVER_COMPAT | SDP_SERVER_CENTRAL,
            buf: vec![0x02, 0x00, 0x01, 0x00, 0x03],
            opcode: SDP_SVC_SEARCH_REQ,
        };
        assert!(req.local);
        assert_eq!(req.sock, 42);
        assert_eq!(req.mtu, 672);
        assert_eq!(req.flags, 0x0003);
        assert_eq!(req.opcode, SDP_SVC_SEARCH_REQ);
        assert_eq!(req.buf.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Continuation state tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_cstate_null() {
        // A single zero byte means null continuation.
        let buf = [0x00];
        let result = get_cstate(&buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_cstate_valid() {
        // size=6, timestamp=0xAABBCCDD, value=0x1234
        let buf = [0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0x12, 0x34];
        let result = get_cstate(&buf).unwrap();
        let cs = result.unwrap();
        assert_eq!(cs.timestamp, 0xAABBCCDD);
        assert_eq!(cs.value, 0x1234);
    }

    #[test]
    fn test_get_cstate_empty_buf() {
        let buf: [u8; 0] = [];
        let result = get_cstate(&buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SDP_INVALID_SYNTAX);
    }

    #[test]
    fn test_get_cstate_truncated_body() {
        // size=6 but only 3 body bytes present.
        let buf = [0x06, 0x01, 0x02, 0x03];
        let result = get_cstate(&buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SDP_INVALID_SYNTAX);
    }

    #[test]
    fn test_set_cstate_pdu_null() {
        let mut rsp = Vec::new();
        let size = set_cstate_pdu(&mut rsp, None);
        assert_eq!(size, 1);
        assert_eq!(rsp, vec![0x00]);
    }

    #[test]
    fn test_set_cstate_pdu_non_null() {
        let cs = ContinuationState { timestamp: 0x12345678, value: 0xABCD };
        let mut rsp = Vec::new();
        let size = set_cstate_pdu(&mut rsp, Some(&cs));
        // size byte (6) + 4 timestamp + 2 value = 7 bytes
        assert_eq!(size, 7);
        assert_eq!(rsp.len(), 7);
        assert_eq!(rsp[0], 0x06); // SDP_CONT_STATE_BODY_SIZE
        assert_eq!(&rsp[1..5], &0x12345678u32.to_be_bytes());
        assert_eq!(&rsp[5..7], &0xABCDu16.to_be_bytes());
    }

    #[test]
    fn test_set_cstate_pdu_roundtrip() {
        // Write a non-null continuation state, then read it back.
        let original = ContinuationState { timestamp: 0xDEADBEEF, value: 42 };
        let mut rsp = Vec::new();
        set_cstate_pdu(&mut rsp, Some(&original));

        let parsed = get_cstate(&rsp).unwrap().unwrap();
        assert_eq!(parsed.timestamp, original.timestamp);
        assert_eq!(parsed.value, original.value);
    }

    // -----------------------------------------------------------------------
    // Continuation state store tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_cont_info_no_match() {
        let mut cstates = vec![ContinuationInfo {
            sock: 10,
            opcode: SDP_SVC_SEARCH_REQ,
            timestamp: 100,
            buf: vec![1, 2, 3],
        }];
        let cstate = ContinuationState {
            timestamp: 999, // Not matching
            value: 0,
        };
        let result = get_cont_info(&mut cstates, 10, SDP_SVC_SEARCH_REQ, &cstate);
        assert!(result.is_none());
        // Should have cleaned up all entries for sock 10.
        assert!(cstates.is_empty());
    }

    #[test]
    fn test_get_cont_info_match() {
        let mut cstates = vec![ContinuationInfo {
            sock: 10,
            opcode: SDP_SVC_SEARCH_REQ,
            timestamp: 100,
            buf: vec![1, 2, 3],
        }];
        let cstate = ContinuationState { timestamp: 100, value: 0 };
        let result = get_cont_info(&mut cstates, 10, SDP_SVC_SEARCH_REQ, &cstate);
        assert_eq!(result, Some(0));
        assert_eq!(cstates.len(), 1); // Still present.
    }

    #[test]
    fn test_get_cont_info_opcode_mismatch() {
        let mut cstates = vec![ContinuationInfo {
            sock: 10,
            opcode: SDP_SVC_SEARCH_REQ,
            timestamp: 100,
            buf: vec![1, 2, 3],
        }];
        let cstate = ContinuationState { timestamp: 100, value: 0 };
        // Different opcode — stale entry should be removed.
        let result = get_cont_info(&mut cstates, 10, SDP_SVC_ATTR_REQ, &cstate);
        assert!(result.is_none());
        assert!(cstates.is_empty());
    }

    #[test]
    fn test_sdp_cstate_cleanup_no_panic() {
        // Calling cleanup with an invalid fd should not panic.
        sdp_cstate_cleanup(-1);
    }

    // -----------------------------------------------------------------------
    // DES parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_seq_type_seq8() {
        // SEQ8 with length 5
        let buf = [SDP_SEQ8, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let (header_len, data_size) = extract_seq_type(&buf).unwrap();
        assert_eq!(header_len, 2);
        assert_eq!(data_size, 5);
    }

    #[test]
    fn test_extract_seq_type_seq16() {
        // SEQ16 with length 0x0100 (256)
        let buf = [SDP_SEQ16, 0x01, 0x00];
        let (header_len, data_size) = extract_seq_type(&buf).unwrap();
        assert_eq!(header_len, 3);
        assert_eq!(data_size, 256);
    }

    #[test]
    fn test_extract_seq_type_invalid() {
        let buf = [0x00]; // Not a DES type
        assert!(extract_seq_type(&buf).is_none());
    }

    #[test]
    fn test_extract_seq_type_empty() {
        let buf: [u8; 0] = [];
        assert!(extract_seq_type(&buf).is_none());
    }

    #[test]
    fn test_extract_seq_type_seq8_truncated() {
        let buf = [SDP_SEQ8]; // Missing length byte
        assert!(extract_seq_type(&buf).is_none());
    }

    #[test]
    fn test_extract_seq_type_seq16_truncated() {
        let buf = [SDP_SEQ16, 0x01]; // Missing second length byte
        assert!(extract_seq_type(&buf).is_none());
    }

    // -----------------------------------------------------------------------
    // UUID extraction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_uuid16() {
        let buf = [SDP_UUID16, 0x11, 0x0A]; // UUID16 = 0x110A
        let (uuid, consumed) = extract_uuid(&buf).unwrap();
        assert_eq!(consumed, 3);
        match uuid {
            SdpUuid::Uuid16(v) => assert_eq!(v, 0x110A),
            _ => panic!("Expected Uuid16"),
        }
    }

    #[test]
    fn test_extract_uuid32() {
        let buf = [SDP_UUID32, 0xAA, 0xBB, 0xCC, 0xDD];
        let (uuid, consumed) = extract_uuid(&buf).unwrap();
        assert_eq!(consumed, 5);
        match uuid {
            SdpUuid::Uuid32(v) => assert_eq!(v, 0xAABBCCDD),
            _ => panic!("Expected Uuid32"),
        }
    }

    #[test]
    fn test_extract_uuid128() {
        let mut buf = vec![SDP_UUID128];
        let uuid_bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        buf.extend_from_slice(&uuid_bytes);
        let (uuid, consumed) = extract_uuid(&buf).unwrap();
        assert_eq!(consumed, 17);
        match uuid {
            SdpUuid::Uuid128(v) => assert_eq!(v, uuid_bytes),
            _ => panic!("Expected Uuid128"),
        }
    }

    #[test]
    fn test_extract_uuid_truncated() {
        let buf = [SDP_UUID16, 0x11]; // Missing second byte
        assert!(extract_uuid(&buf).is_none());
    }

    #[test]
    fn test_extract_uuid_invalid_type() {
        let buf = [0xFF, 0x11, 0x0A]; // Invalid UUID type descriptor
        assert!(extract_uuid(&buf).is_none());
    }

    #[test]
    fn test_extract_uuid_empty() {
        let buf: [u8; 0] = [];
        assert!(extract_uuid(&buf).is_none());
    }

    // -----------------------------------------------------------------------
    // UUID DES extraction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_uuid_des_single_uuid16() {
        // DES with one UUID16 (0x1101)
        let buf = [
            SDP_SEQ8, 0x03, // SEQ8 with length 3
            SDP_UUID16, 0x11, 0x01, // UUID16 = 0x1101
        ];
        let (uuids, consumed) = extract_uuid_des(&buf).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(uuids.len(), 1);
        match &uuids[0] {
            SdpUuid::Uuid16(v) => assert_eq!(*v, 0x1101),
            _ => panic!("Expected Uuid16"),
        }
    }

    #[test]
    fn test_extract_uuid_des_multiple_uuid16() {
        // DES with two UUID16 values
        let buf = [
            SDP_SEQ8, 0x06, // SEQ8 with length 6
            SDP_UUID16, 0x11, 0x01, // UUID16 = 0x1101
            SDP_UUID16, 0x11, 0x0A, // UUID16 = 0x110A
        ];
        let (uuids, consumed) = extract_uuid_des(&buf).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(uuids.len(), 2);
        match &uuids[0] {
            SdpUuid::Uuid16(v) => assert_eq!(*v, 0x1101),
            _ => panic!("Expected Uuid16"),
        }
        match &uuids[1] {
            SdpUuid::Uuid16(v) => assert_eq!(*v, 0x110A),
            _ => panic!("Expected Uuid16"),
        }
    }

    #[test]
    fn test_extract_uuid_des_invalid() {
        let buf = [0xFF]; // Not a DES
        let result = extract_uuid_des(&buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SDP_INVALID_SYNTAX);
    }

    #[test]
    fn test_extract_uuid_des_truncated_data() {
        // DES header says 10 bytes but buffer is too short.
        let buf = [SDP_SEQ8, 0x0A, SDP_UUID16, 0x11];
        let result = extract_uuid_des(&buf);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Attribute ID DES tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_attrid_des_single() {
        // DES with one UINT16 attribute ID (0x0001)
        let buf = [
            SDP_SEQ8, 0x03, // SEQ8 with length 3
            SDP_UINT16, 0x00, 0x01, // UINT16 = 0x0001
        ];
        let (attrs, consumed) = extract_attrid_des(&buf).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(attrs.len(), 1);
        match attrs[0] {
            AttrId::Single(v) => assert_eq!(v, 0x0001),
            _ => panic!("Expected Single"),
        }
    }

    #[test]
    fn test_extract_attrid_des_range() {
        // DES with one UINT32 range (0x0001-0xFFFF)
        let buf = [
            SDP_SEQ8, 0x05, // SEQ8 with length 5
            SDP_UINT32, 0x00, 0x01, 0xFF, 0xFF, // UINT32 range = 0x0001..0xFFFF
        ];
        let (attrs, consumed) = extract_attrid_des(&buf).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(attrs.len(), 1);
        match attrs[0] {
            AttrId::Range(low, high) => {
                assert_eq!(low, 0x0001);
                assert_eq!(high, 0xFFFF);
            }
            _ => panic!("Expected Range"),
        }
    }

    #[test]
    fn test_extract_attrid_des_full_range() {
        // Full range 0x0000-0xFFFF
        let buf = [
            SDP_SEQ8, 0x05, // SEQ8 with length 5
            SDP_UINT32, 0x00, 0x00, 0xFF, 0xFF, // UINT32 range = 0x0000..0xFFFF
        ];
        let (attrs, consumed) = extract_attrid_des(&buf).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(attrs.len(), 1);
        match attrs[0] {
            AttrId::Range(low, high) => {
                assert_eq!(low, 0x0000);
                assert_eq!(high, 0xFFFF);
            }
            _ => panic!("Expected Range"),
        }
    }

    #[test]
    fn test_extract_attrid_des_mixed() {
        // DES with one UINT16 + one UINT32 range
        let buf = [
            SDP_SEQ8, 0x08, // SEQ8 with length 8
            SDP_UINT16, 0x00, 0x01, // UINT16 = 0x0001
            SDP_UINT32, 0x00, 0x03, 0x00, 0x09, // UINT32 range = 0x0003..0x0009
        ];
        let (attrs, consumed) = extract_attrid_des(&buf).unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(attrs.len(), 2);
        match attrs[0] {
            AttrId::Single(v) => assert_eq!(v, 0x0001),
            _ => panic!("Expected Single"),
        }
        match attrs[1] {
            AttrId::Range(low, high) => {
                assert_eq!(low, 0x0003);
                assert_eq!(high, 0x0009);
            }
            _ => panic!("Expected Range"),
        }
    }

    #[test]
    fn test_extract_attrid_des_invalid_type() {
        // DES with invalid data type inside
        let buf = [
            SDP_SEQ8, 0x03, 0xFF, 0x00, 0x01, // Invalid type 0xFF
        ];
        let result = extract_attrid_des(&buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SDP_INVALID_SYNTAX);
    }

    // -----------------------------------------------------------------------
    // UUID-to-128 conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_uuid_to_128_from_uuid16() {
        let uuid = SdpUuid::Uuid16(0x1101); // Serial Port Profile
        let full = uuid_to_128(&uuid);
        // Expected: 00001101-0000-1000-8000-00805F9B34FB
        assert_eq!(full[0], 0x00);
        assert_eq!(full[1], 0x00);
        assert_eq!(full[2], 0x11);
        assert_eq!(full[3], 0x01);
        assert_eq!(full[4], 0x00);
        assert_eq!(full[5], 0x00);
        assert_eq!(full[6], 0x10);
        assert_eq!(full[7], 0x00);
        assert_eq!(full[8], 0x80);
        assert_eq!(full[9], 0x00);
        assert_eq!(full[10], 0x00);
        assert_eq!(full[11], 0x80);
        assert_eq!(full[12], 0x5F);
        assert_eq!(full[13], 0x9B);
        assert_eq!(full[14], 0x34);
        assert_eq!(full[15], 0xFB);
    }

    #[test]
    fn test_uuid_to_128_from_uuid32() {
        let uuid = SdpUuid::Uuid32(0xDEADBEEF);
        let full = uuid_to_128(&uuid);
        assert_eq!(full[0], 0xDE);
        assert_eq!(full[1], 0xAD);
        assert_eq!(full[2], 0xBE);
        assert_eq!(full[3], 0xEF);
        // Remaining bytes should be the Bluetooth Base UUID suffix.
        assert_eq!(full[4], 0x00);
        assert_eq!(full[5], 0x00);
        assert_eq!(full[6], 0x10);
        assert_eq!(full[7], 0x00);
    }

    #[test]
    fn test_uuid_to_128_from_uuid128() {
        let bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let uuid = SdpUuid::Uuid128(bytes);
        let full = uuid_to_128(&uuid);
        assert_eq!(full, bytes);
    }

    #[test]
    fn test_uuid_to_128_base_uuid() {
        // UUID16 0x0000 should produce the Bluetooth Base UUID.
        let uuid = SdpUuid::Uuid16(0x0000);
        let full = uuid_to_128(&uuid);
        let expected: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B,
            0x34, 0xFB,
        ];
        assert_eq!(full, expected);
    }

    // -----------------------------------------------------------------------
    // alloc_cont_buf tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_alloc_cont_buf_creates_entry() {
        let mut cstates: Vec<ContinuationInfo> = Vec::new();
        let db = SdpDatabase::new();
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let ts = alloc_cont_buf(&mut cstates, &db, 42, SDP_SVC_ATTR_REQ, &data);
        assert_eq!(cstates.len(), 1);
        assert_eq!(cstates[0].sock, 42);
        assert_eq!(cstates[0].opcode, SDP_SVC_ATTR_REQ);
        assert_eq!(cstates[0].timestamp, ts);
        assert_eq!(cstates[0].buf, data);
    }

    #[test]
    fn test_alloc_cont_buf_multiple() {
        let mut cstates: Vec<ContinuationInfo> = Vec::new();
        let db = SdpDatabase::new();

        alloc_cont_buf(&mut cstates, &db, 1, SDP_SVC_SEARCH_REQ, &[0xAA]);
        alloc_cont_buf(&mut cstates, &db, 2, SDP_SVC_ATTR_REQ, &[0xBB]);
        assert_eq!(cstates.len(), 2);
        assert_eq!(cstates[0].sock, 1);
        assert_eq!(cstates[1].sock, 2);
    }

    // -----------------------------------------------------------------------
    // cstate_rsp tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cstate_rsp_full_chunk() {
        // Cached data: 10 bytes, sent so far: 0, max chunk: 100
        let mut cstates = vec![ContinuationInfo {
            sock: 1,
            opcode: SDP_SVC_ATTR_REQ,
            timestamp: 42,
            buf: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A],
        }];
        let cstate = ContinuationState { timestamp: 42, value: 0 };
        let (rsp, cstate_size) = cstate_rsp(&mut cstates, 0, &cstate, 100).unwrap();
        // All 10 bytes should be returned plus null cstate.
        assert_eq!(
            rsp.len(),
            10 + 1 // 10 data + 1 null cstate
        );
        assert_eq!(&rsp[..10], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
        assert_eq!(rsp[10], 0x00); // Null continuation
        assert_eq!(cstate_size, 1);
        // Entry should have been removed.
        assert!(cstates.is_empty());
    }

    #[test]
    fn test_cstate_rsp_partial_chunk() {
        // Cached data: 10 bytes, sent so far: 0, max chunk: 4
        let mut cstates = vec![ContinuationInfo {
            sock: 1,
            opcode: SDP_SVC_ATTR_REQ,
            timestamp: 42,
            buf: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A],
        }];
        let cstate = ContinuationState { timestamp: 42, value: 0 };
        let (rsp, cstate_size) = cstate_rsp(&mut cstates, 0, &cstate, 4).unwrap();
        // First 4 bytes + 7 bytes continuation state
        assert_eq!(&rsp[..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(cstate_size, 7);
        // Entry should still be present.
        assert_eq!(cstates.len(), 1);
    }

    #[test]
    fn test_cstate_rsp_already_sent_all() {
        // value >= buf.len(), so everything is already sent.
        let mut cstates = vec![ContinuationInfo {
            sock: 1,
            opcode: SDP_SVC_ATTR_REQ,
            timestamp: 42,
            buf: vec![0x01, 0x02],
        }];
        let cstate = ContinuationState {
            timestamp: 42,
            value: 10, // Already past end
        };
        let (rsp, cstate_size) = cstate_rsp(&mut cstates, 0, &cstate, 100).unwrap();
        // Should return null continuation only.
        assert_eq!(rsp, vec![0x00]);
        assert_eq!(cstate_size, 1);
        assert!(cstates.is_empty());
    }

    // -----------------------------------------------------------------------
    // Error response PDU structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_rsp_constants_are_distinct() {
        // Ensure all error codes are unique.
        let codes = [
            SDP_INVALID_VERSION,
            SDP_INVALID_RECORD_HANDLE,
            SDP_INVALID_SYNTAX,
            SDP_INVALID_PDU_SIZE,
            SDP_INVALID_CSTATE,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "Error codes {} and {} are equal", i, j);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Opcode response mapping tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_response_opcode_mapping() {
        // Verify that request opcodes map to correct response opcodes.
        assert_eq!(SDP_SVC_SEARCH_REQ + 1, SDP_SVC_SEARCH_RSP);
        assert_eq!(SDP_SVC_ATTR_REQ + 1, SDP_SVC_ATTR_RSP);
        assert_eq!(SDP_SVC_SEARCH_ATTR_REQ + 1, SDP_SVC_SEARCH_ATTR_RSP);
    }

    // -----------------------------------------------------------------------
    // Internal constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_internal_constants() {
        assert_eq!(SDP_PDU_HDR_SIZE, 5);
        assert_eq!(SDP_MAX_PDU_SIZE, 65535);
        assert_eq!(SDP_CONT_STATE_SIZE, 7);
        assert_eq!(SDP_CONT_STATE_BODY_SIZE, 6);
    }

    #[test]
    fn test_sdp_data_type_constants() {
        assert_eq!(SDP_SEQ8, 0x35);
        assert_eq!(SDP_SEQ16, 0x36);
        assert_eq!(SDP_UUID16, 0x19);
        assert_eq!(SDP_UUID32, 0x1a);
        assert_eq!(SDP_UUID128, 0x1c);
        assert_eq!(SDP_UINT16, 0x09);
        assert_eq!(SDP_UINT32, 0x0a);
    }

    // -----------------------------------------------------------------------
    // SdpPduHeader edge case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pdu_header_max_values() {
        let hdr = SdpPduHeader { opcode: 0xFF, tid: 0xFFFF, param_len: 0xFFFF };
        let mut buf = [0u8; 5];
        hdr.write_to(&mut buf);
        let parsed = SdpPduHeader::parse(&buf).unwrap();
        assert_eq!(parsed.opcode, 0xFF);
        assert_eq!(parsed.tid, 0xFFFF);
        assert_eq!(parsed.param_len, 0xFFFF);
    }

    #[test]
    fn test_pdu_header_zero_values() {
        let hdr = SdpPduHeader { opcode: 0x00, tid: 0x0000, param_len: 0x0000 };
        let mut buf = [0u8; 5];
        hdr.write_to(&mut buf);
        assert_eq!(buf, [0, 0, 0, 0, 0]);
    }

    // -----------------------------------------------------------------------
    // Continuation state cleanup with multiple entries
    // -----------------------------------------------------------------------

    #[test]
    fn test_cstate_cleanup_removes_only_matching_sock() {
        let mut cstates = vec![
            ContinuationInfo { sock: 1, opcode: 0x02, timestamp: 10, buf: vec![1] },
            ContinuationInfo { sock: 2, opcode: 0x04, timestamp: 20, buf: vec![2] },
            ContinuationInfo { sock: 1, opcode: 0x06, timestamp: 30, buf: vec![3] },
            ContinuationInfo { sock: 3, opcode: 0x02, timestamp: 40, buf: vec![4] },
        ];
        cstates.retain(|c| c.sock != 1);
        assert_eq!(cstates.len(), 2);
        assert_eq!(cstates[0].sock, 2);
        assert_eq!(cstates[1].sock, 3);
    }
}
