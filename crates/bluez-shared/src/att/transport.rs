// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
//! ATT (Attribute Protocol) transport layer.
//!
//! Complete Rust rewrite of `src/shared/att.c` and `src/shared/att.h`.
//! This module implements the core ATT transport for all GATT operations,
//! replacing the opaque ref-counted `struct bt_att` / `struct bt_att_chan`
//! with idiomatic Rust types using `Arc`, async I/O, and channels.
//!
//! # Architecture
//!
//! - [`BtAtt`] is the main transport handle, shared via `Arc<Mutex<…>>`.
//! - [`BtAttChan`] represents a single ATT bearer (BR/EDR, LE, EATT, or
//!   local loopback).
//! - All callback+user\_data pairs are replaced with boxed Rust closures.
//! - The GLib / ELL mainloop is replaced with `tokio` async I/O
//!   (`AsyncFd`, spawned tasks, `tokio::time`).
//! - GLib containers (`queue`, `GList`) are replaced with `Vec` /
//!   `VecDeque`.
//! - Reference counting (`bt_att_ref` / `bt_att_unref`) is replaced with
//!   `Arc`.

use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::mem;
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::{Arc, Mutex};

use tokio::task::JoinHandle;

use super::types::{
    AttError, AttOpcode, AttPermissions, AttSecurityLevel, BT_ATT_ALL_REQUESTS, BT_ATT_BREDR,
    BT_ATT_CID, BT_ATT_DEFAULT_LE_MTU, BT_ATT_EATT, BT_ATT_EATT_PSM, BT_ATT_ERROR_AUTHENTICATION,
    BT_ATT_ERROR_DB_OUT_OF_SYNC, BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION,
    BT_ATT_ERROR_INSUFFICIENT_RESOURCES, BT_ATT_ERROR_INVALID_HANDLE,
    BT_ATT_ERROR_REQUEST_NOT_SUPPORTED, BT_ATT_ERROR_UNLIKELY, BT_ATT_LE, BT_ATT_LOCAL,
    BT_ATT_MAX_LE_MTU, BT_ATT_MAX_VALUE_LEN, BT_ATT_OP_ERROR_RSP, BT_ATT_OP_EXEC_WRITE_REQ,
    BT_ATT_OP_EXEC_WRITE_RSP, BT_ATT_OP_FIND_BY_TYPE_REQ, BT_ATT_OP_FIND_BY_TYPE_RSP,
    BT_ATT_OP_FIND_INFO_REQ, BT_ATT_OP_FIND_INFO_RSP, BT_ATT_OP_HANDLE_CONF, BT_ATT_OP_HANDLE_IND,
    BT_ATT_OP_HANDLE_NFY, BT_ATT_OP_HANDLE_NFY_MULT, BT_ATT_OP_MTU_REQ, BT_ATT_OP_MTU_RSP,
    BT_ATT_OP_PREP_WRITE_REQ, BT_ATT_OP_PREP_WRITE_RSP, BT_ATT_OP_READ_BLOB_REQ,
    BT_ATT_OP_READ_BLOB_RSP, BT_ATT_OP_READ_BY_GRP_TYPE_REQ, BT_ATT_OP_READ_BY_GRP_TYPE_RSP,
    BT_ATT_OP_READ_BY_TYPE_REQ, BT_ATT_OP_READ_BY_TYPE_RSP, BT_ATT_OP_READ_MULT_REQ,
    BT_ATT_OP_READ_MULT_RSP, BT_ATT_OP_READ_MULT_VL_REQ, BT_ATT_OP_READ_MULT_VL_RSP,
    BT_ATT_OP_READ_REQ, BT_ATT_OP_READ_RSP, BT_ATT_OP_SIGNED_WRITE_CMD, BT_ATT_OP_WRITE_CMD,
    BT_ATT_OP_WRITE_REQ, BT_ATT_OP_WRITE_RSP, BT_ATT_PSM, BT_ERROR_ALREADY_IN_PROGRESS,
    BT_ERROR_OUT_OF_RANGE, BtAttPduErrorRsp,
};

use crate::crypto::aes_cmac::{bt_crypto_sign_att, bt_crypto_verify_att_sign};
use crate::sys::bluetooth::{
    AF_BLUETOOTH, BDADDR_BREDR, BT_SECURITY, BT_SECURITY_FIPS, BT_SECURITY_HIGH, BT_SECURITY_LOW,
    BT_SECURITY_MEDIUM, BT_SECURITY_SDP, BT_SNDMTU, BTPROTO_L2CAP, SOL_BLUETOOTH, SOL_L2CAP,
    bt_security,
};
use crate::sys::l2cap::{L2CAP_OPTIONS, l2cap_options, sockaddr_l2};

// ---------------------------------------------------------------------------
// Type aliases for complex callback signatures
// ---------------------------------------------------------------------------

/// One-shot callback invoked when an ATT response/confirmation arrives.
/// Parameters: `(response_opcode, response_body)`.
pub type AttResponseCallback = Option<Box<dyn FnOnce(u8, &[u8]) + Send>>;

/// Persistent handler for incoming ATT PDUs.
/// Parameters: `(channel_idx, filter_opcode, raw_opcode, pdu_body)`.
pub type AttNotifyCallback = Box<dyn Fn(usize, u16, u8, &[u8]) + Send + Sync>;

/// DB-out-of-sync notification callback.
/// Parameters: `(opcode, pdu, operation_id)`.
pub type AttDbSyncCallback = Option<Box<dyn Fn(u8, &[u8], u32) + Send + Sync>>;

// ---------------------------------------------------------------------------
// Internal constants (from att.c lines 29-35)
// ---------------------------------------------------------------------------

/// Minimum ATT PDU length — just the opcode byte.
const ATT_MIN_PDU_LEN: usize = 1;

/// Bit mask: if set in the opcode, the PDU is a command (no response expected).
const ATT_OP_CMD_MASK: u8 = 0x40;

/// Bit mask: if set in the opcode, the PDU carries a CMAC signature.
const ATT_OP_SIGNED_MASK: u8 = 0x80;

/// Transaction timeout in milliseconds (30 seconds per BT spec).
/// Used by callers to configure per-operation timeouts.
pub const ATT_TIMEOUT_INTERVAL: u64 = 30_000;

/// Length of the ATT authentication signature appended to signed writes.
const BT_ATT_SIGNATURE_LEN: usize = 12;

// Debug verbosity levels (from att.h)
/// Standard debug messages.
pub const BT_ATT_DEBUG: u8 = 0x00;
/// Verbose debug messages.
pub const BT_ATT_DEBUG_VERBOSE: u8 = 0x01;
/// Hex-dump every PDU.
pub const BT_ATT_DEBUG_HEXDUMP: u8 = 0x02;

// ---------------------------------------------------------------------------
// AttOpType — classifies an ATT opcode (from att.c lines 103-162)
// ---------------------------------------------------------------------------

/// Classification of an ATT opcode into request/response/command/etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttOpType {
    /// Request — expects a matching response.
    Req,
    /// Response — matches a prior request.
    Rsp,
    /// Command — no response expected.
    Cmd,
    /// Indication — expects a confirmation.
    Ind,
    /// Notification — no confirmation expected.
    Nfy,
    /// Confirmation — matches a prior indication.
    Conf,
    /// Unrecognised opcode.
    Unknown,
}

/// Map an ATT opcode to its operation type.
///
/// Mirrors the C `att_opcode_type_table` (att.c lines 113-147) with a
/// fallback: if bit 6 (CMD mask) is set the opcode is treated as a command;
/// otherwise it is unknown.
pub fn get_op_type(opcode: u8) -> AttOpType {
    match opcode {
        BT_ATT_OP_ERROR_RSP => AttOpType::Rsp,
        BT_ATT_OP_MTU_REQ => AttOpType::Req,
        BT_ATT_OP_MTU_RSP => AttOpType::Rsp,
        BT_ATT_OP_FIND_INFO_REQ => AttOpType::Req,
        BT_ATT_OP_FIND_INFO_RSP => AttOpType::Rsp,
        BT_ATT_OP_FIND_BY_TYPE_REQ => AttOpType::Req,
        BT_ATT_OP_FIND_BY_TYPE_RSP => AttOpType::Rsp,
        BT_ATT_OP_READ_BY_TYPE_REQ => AttOpType::Req,
        BT_ATT_OP_READ_BY_TYPE_RSP => AttOpType::Rsp,
        BT_ATT_OP_READ_REQ => AttOpType::Req,
        BT_ATT_OP_READ_RSP => AttOpType::Rsp,
        BT_ATT_OP_READ_BLOB_REQ => AttOpType::Req,
        BT_ATT_OP_READ_BLOB_RSP => AttOpType::Rsp,
        BT_ATT_OP_READ_MULT_REQ => AttOpType::Req,
        BT_ATT_OP_READ_MULT_RSP => AttOpType::Rsp,
        BT_ATT_OP_READ_BY_GRP_TYPE_REQ => AttOpType::Req,
        BT_ATT_OP_READ_BY_GRP_TYPE_RSP => AttOpType::Rsp,
        BT_ATT_OP_WRITE_REQ => AttOpType::Req,
        BT_ATT_OP_WRITE_RSP => AttOpType::Rsp,
        BT_ATT_OP_WRITE_CMD => AttOpType::Cmd,
        BT_ATT_OP_SIGNED_WRITE_CMD => AttOpType::Cmd,
        BT_ATT_OP_PREP_WRITE_REQ => AttOpType::Req,
        BT_ATT_OP_PREP_WRITE_RSP => AttOpType::Rsp,
        BT_ATT_OP_EXEC_WRITE_REQ => AttOpType::Req,
        BT_ATT_OP_EXEC_WRITE_RSP => AttOpType::Rsp,
        BT_ATT_OP_HANDLE_NFY => AttOpType::Nfy,
        BT_ATT_OP_HANDLE_IND => AttOpType::Ind,
        BT_ATT_OP_HANDLE_CONF => AttOpType::Conf,
        BT_ATT_OP_READ_MULT_VL_REQ => AttOpType::Req,
        BT_ATT_OP_READ_MULT_VL_RSP => AttOpType::Rsp,
        BT_ATT_OP_HANDLE_NFY_MULT => AttOpType::Nfy,
        _ => {
            if opcode & ATT_OP_CMD_MASK != 0 {
                AttOpType::Cmd
            } else {
                AttOpType::Unknown
            }
        }
    }
}

/// Map a response opcode back to its corresponding request opcode.
///
/// Mirrors the C `att_req_rsp_mapping_table` (att.c lines 164-180).
/// Returns `None` if the opcode is not a recognised response.
pub fn get_req_opcode(rsp_opcode: u8) -> Option<u8> {
    match rsp_opcode {
        BT_ATT_OP_ERROR_RSP => Some(0), // generic — see handle_error_rsp
        BT_ATT_OP_MTU_RSP => Some(BT_ATT_OP_MTU_REQ),
        BT_ATT_OP_FIND_INFO_RSP => Some(BT_ATT_OP_FIND_INFO_REQ),
        BT_ATT_OP_FIND_BY_TYPE_RSP => Some(BT_ATT_OP_FIND_BY_TYPE_REQ),
        BT_ATT_OP_READ_BY_TYPE_RSP => Some(BT_ATT_OP_READ_BY_TYPE_REQ),
        BT_ATT_OP_READ_RSP => Some(BT_ATT_OP_READ_REQ),
        BT_ATT_OP_READ_BLOB_RSP => Some(BT_ATT_OP_READ_BLOB_REQ),
        BT_ATT_OP_READ_MULT_RSP => Some(BT_ATT_OP_READ_MULT_REQ),
        BT_ATT_OP_READ_BY_GRP_TYPE_RSP => Some(BT_ATT_OP_READ_BY_GRP_TYPE_REQ),
        BT_ATT_OP_WRITE_RSP => Some(BT_ATT_OP_WRITE_REQ),
        BT_ATT_OP_PREP_WRITE_RSP => Some(BT_ATT_OP_PREP_WRITE_REQ),
        BT_ATT_OP_EXEC_WRITE_RSP => Some(BT_ATT_OP_EXEC_WRITE_REQ),
        BT_ATT_OP_READ_MULT_VL_RSP => Some(BT_ATT_OP_READ_MULT_VL_REQ),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Internal helper structs
// ---------------------------------------------------------------------------

/// Signing key material and counter generator.
struct SignInfo {
    /// 128-bit signing key (CSRK).
    key: [u8; 16],
    /// Callback returning the next sign counter value.  Returns `true` on
    /// success (writing the counter into the provided `&mut u32`).
    counter: Box<dyn Fn(&mut u32) -> bool + Send + Sync>,
}

/// A queued ATT send operation (replaces C `struct att_send_op`).
struct AttSendOp {
    /// Unique operation identifier.
    id: u32,
    /// Handle to the spawned timeout task (aborted on completion/cancel).
    timeout_handle: Option<JoinHandle<()>>,
    /// Classification of the PDU opcode.
    op_type: AttOpType,
    /// Raw opcode byte (first byte of `pdu`).
    opcode: u8,
    /// Complete PDU: `[opcode] + [payload] + [optional signature]`.
    pdu: Vec<u8>,
    /// Whether a security-retry has been requested for this operation.
    retry: bool,
    /// One-shot callback invoked when the response/confirmation arrives.
    callback: AttResponseCallback,
}

impl Drop for AttSendOp {
    fn drop(&mut self) {
        // Abort the timeout task if it is still running.
        if let Some(handle) = self.timeout_handle.take() {
            handle.abort();
        }
    }
}

/// Registered notification/indication handler (replaces C `struct att_notify`).
struct AttNotify {
    /// Registration identifier.
    id: u32,
    /// Opcode filter (`BT_ATT_ALL_REQUESTS` matches all REQ+CMD opcodes).
    opcode: u16,
    /// Callback: `(channel_idx, opcode_u16, raw_opcode_u8, pdu_body)`.
    callback: AttNotifyCallback,
}

/// Registered disconnect handler (replaces C `struct att_disconn`).
struct AttDisconn {
    id: u32,
    /// Set to `true` during the disconnect walk to defer removal.
    removed: bool,
    /// Callback receiving the disconnect error code.
    callback: Box<dyn Fn(i32) + Send + Sync>,
}

/// Registered MTU-exchange handler (replaces C `struct att_exchange`).
struct AttExchange {
    id: u32,
    /// Set to `true` during notification walk to defer removal.
    removed: bool,
    /// Callback receiving the new MTU.
    callback: Box<dyn Fn(u16) + Send + Sync>,
}

// ---------------------------------------------------------------------------
// Low-level socket helpers (FFI boundary — safe wrappers around libc calls)
// ---------------------------------------------------------------------------

/// Query a raw integer socket option.
///
/// # Safety justification
///
/// Calls `libc::getsockopt` on a valid open file descriptor with a
/// properly-sized `c_int` output buffer.  The caller guarantees `fd` is a
/// valid, open socket descriptor.
#[allow(unsafe_code)]
fn getsockopt_int(fd: RawFd, level: libc::c_int, optname: libc::c_int) -> io::Result<i32> {
    let mut val: libc::c_int = 0;
    let mut len: libc::socklen_t = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a valid open socket descriptor; `val` is a properly
    // aligned c_int buffer with `len` set to its size.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            &mut val as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(val)
}

/// Set a raw integer socket option.
#[allow(unsafe_code)]
pub fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    let len: libc::socklen_t = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a valid open socket; `val` points to a single c_int.
    let ret = unsafe {
        libc::setsockopt(fd, level, optname, &val as *const libc::c_int as *const libc::c_void, len)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Get the `bt_security` structure for a Bluetooth socket.
#[allow(unsafe_code)]
fn getsockopt_bt_security(fd: RawFd) -> io::Result<bt_security> {
    let mut sec = bt_security { level: 0, key_size: 0 };
    let mut len: libc::socklen_t = mem::size_of::<bt_security>() as libc::socklen_t;
    // SAFETY: fd is a valid Bluetooth socket; sec is properly sized.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_BLUETOOTH,
            BT_SECURITY,
            &mut sec as *mut bt_security as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sec)
}

/// Set the `bt_security` structure on a Bluetooth socket.
#[allow(unsafe_code)]
fn setsockopt_bt_security(fd: RawFd, sec: &bt_security) -> io::Result<()> {
    let len: libc::socklen_t = mem::size_of::<bt_security>() as libc::socklen_t;
    // SAFETY: fd is a valid Bluetooth socket; sec is properly sized.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_BLUETOOTH,
            BT_SECURITY,
            sec as *const bt_security as *const libc::c_void,
            len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Get the L2CAP options (for MTU query) on a Bluetooth socket.
#[allow(unsafe_code)]
fn getsockopt_l2cap_options(fd: RawFd) -> io::Result<l2cap_options> {
    // SAFETY: zero-init is valid for this packed C struct (all-zero = default).
    let mut opts: l2cap_options = {
        #[allow(unsafe_code)]
        // SAFETY: l2cap_options is a repr(C) struct with no validity invariants.
        unsafe {
            mem::zeroed()
        }
    };
    let mut len: libc::socklen_t = mem::size_of::<l2cap_options>() as libc::socklen_t;
    // SAFETY: fd is a valid L2CAP socket; opts is properly sized.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_L2CAP,
            L2CAP_OPTIONS,
            &mut opts as *mut l2cap_options as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(opts)
}

/// Retrieve the local socket address as `sockaddr_l2`.
#[allow(unsafe_code)]
fn getsockname_l2(fd: RawFd) -> io::Result<sockaddr_l2> {
    // SAFETY: zero-init is valid for this packed C struct (all-zero = default).
    let mut addr: sockaddr_l2 = {
        #[allow(unsafe_code)]
        // SAFETY: sockaddr_l2 is a repr(C) struct with no validity invariants.
        unsafe {
            mem::zeroed()
        }
    };
    let mut len: libc::socklen_t = mem::size_of::<sockaddr_l2>() as libc::socklen_t;
    // SAFETY: fd is a valid L2CAP socket; addr is properly sized.
    let ret = unsafe {
        libc::getsockname(fd, &mut addr as *mut sockaddr_l2 as *mut libc::sockaddr, &mut len)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(addr)
}

// ---------------------------------------------------------------------------
// Higher-level socket helpers (att.c lines 1151-1235)
// ---------------------------------------------------------------------------

/// Check whether `fd` is an L2CAP-based Bluetooth socket.
///
/// Mirrors `is_io_l2cap_based` (att.c lines 1151-1174).
fn is_io_l2cap_based(fd: RawFd) -> bool {
    let domain = match getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_DOMAIN) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if domain != AF_BLUETOOTH {
        return false;
    }
    let proto = match getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL) {
        Ok(v) => v,
        Err(_) => return false,
    };
    proto == BTPROTO_L2CAP
}

/// Query the outgoing MTU of a Bluetooth socket.
///
/// Tries `L2CAP_OPTIONS.omtu` first, falls back to `BT_SNDMTU`.
/// Returns 0 on failure (mirrors `io_get_mtu` att.c lines 1203-1216).
fn io_get_mtu(fd: RawFd) -> u16 {
    if let Ok(opts) = getsockopt_l2cap_options(fd) {
        if opts.omtu > 0 {
            return opts.omtu;
        }
    }
    // Fallback: BT_SNDMTU (SOL_BLUETOOTH level).
    match getsockopt_int(fd, SOL_BLUETOOTH, BT_SNDMTU) {
        Ok(v) if v > 0 => v as u16,
        _ => 0,
    }
}

/// Determine the ATT channel type for a socket fd.
///
/// Mirrors `io_get_type` (att.c lines 1218-1235):
/// - Not L2CAP → `BT_ATT_LOCAL`
/// - L2CAP + `BDADDR_BREDR` address type → `BT_ATT_BREDR`
/// - Otherwise → `BT_ATT_LE`
fn io_get_type(fd: RawFd) -> u8 {
    if !is_io_l2cap_based(fd) {
        return BT_ATT_LOCAL;
    }
    match getsockname_l2(fd) {
        Ok(addr) if addr.l2_bdaddr_type == BDADDR_BREDR => BT_ATT_BREDR,
        _ => BT_ATT_LE,
    }
}

/// Map an errno value (or positive ATT error code) to an ATT error byte.
///
/// Mirrors `att_ecode_from_error` (att.c lines 1963-1989).
pub fn att_ecode_from_error(err: i32) -> u8 {
    if err > 0 && err < 255 {
        // Positive values in 1..254 are pass-through ATT error codes.
        return err as u8;
    }
    // Negative errno values — map to ATT error codes.
    match -err {
        libc::ENOENT => BT_ATT_ERROR_INVALID_HANDLE,
        libc::ENOMEM => BT_ATT_ERROR_INSUFFICIENT_RESOURCES,
        libc::EALREADY => BT_ERROR_ALREADY_IN_PROGRESS,
        libc::EOVERFLOW => BT_ERROR_OUT_OF_RANGE,
        _ => BT_ATT_ERROR_UNLIKELY,
    }
}

/// Build a complete ATT PDU (opcode + payload + optional signature).
///
/// Mirrors the PDU construction in `encode_pdu` (att.c lines 333-373).
/// Returns `None` if the resulting PDU exceeds the channel MTU.
fn encode_pdu(
    opcode: u8,
    payload: &[u8],
    mtu: u16,
    local_sign: &Option<SignInfo>,
    has_crypto: bool,
) -> Option<Vec<u8>> {
    // Payload cannot exceed the maximum attribute value length.
    if payload.len() > BT_ATT_MAX_VALUE_LEN as usize {
        return None;
    }

    let signed = opcode & ATT_OP_SIGNED_MASK != 0;
    let sig_len = if signed { BT_ATT_SIGNATURE_LEN } else { 0 };
    let total = 1 + payload.len() + sig_len;

    if total > mtu as usize {
        return None;
    }

    let mut pdu = Vec::with_capacity(total);
    pdu.push(opcode);
    pdu.extend_from_slice(payload);

    if signed {
        let sign_info = local_sign.as_ref()?;
        if !has_crypto {
            return None;
        }
        let mut sign_cnt: u32 = 0;
        if !(sign_info.counter)(&mut sign_cnt) {
            return None;
        }
        match bt_crypto_sign_att(&sign_info.key, &pdu, sign_cnt) {
            Ok(signature) => pdu.extend_from_slice(&signature),
            Err(_) => return None,
        }
    }

    Some(pdu)
}

/// Check whether `opcode` matches the filter in an `AttNotify` entry.
///
/// `BT_ATT_ALL_REQUESTS` (0x00) matches all request and command opcodes.
/// Otherwise an exact match on the opcode byte is required.
fn opcode_match(filter: u16, opcode: u8) -> bool {
    if filter == BT_ATT_ALL_REQUESTS as u16 {
        let t = get_op_type(opcode);
        return t == AttOpType::Req || t == AttOpType::Cmd;
    }
    filter == opcode as u16
}

// ---------------------------------------------------------------------------
// BtAttChan — single ATT bearer
// ---------------------------------------------------------------------------

/// A single ATT bearer channel.
///
/// Replaces the C `struct bt_att_chan` (att.c lines 39-57).
pub struct BtAttChan {
    /// Raw socket file descriptor.
    fd: RawFd,
    /// Channel type: `BT_ATT_BREDR`, `BT_ATT_LE`, `BT_ATT_EATT`, or
    /// `BT_ATT_LOCAL`.
    chan_type: u8,
    /// Security level (only meaningful for `BT_ATT_LOCAL`).
    sec_level: i32,
    /// Channel-local send queue.
    queue: VecDeque<AttSendOp>,
    /// Currently pending request (awaiting response).
    pending_req: Option<AttSendOp>,
    /// Currently pending indication (awaiting confirmation).
    pending_ind: Option<AttSendOp>,
    /// Pending DB-sync operation (after `DB_OUT_OF_SYNC` error).
    pending_db_sync: Option<AttSendOp>,
    /// Whether a write handler is currently armed.
    writer_active: bool,
    /// Whether there is an un-responded incoming request on this channel.
    in_req: bool,
    /// Read buffer (sized to the channel MTU).
    buf: Vec<u8>,
    /// Negotiated MTU for this channel.
    pub mtu: u16,
}

impl BtAttChan {
    /// Create a new ATT channel wrapping a raw socket fd.
    ///
    /// Determines initial MTU from the socket type and allocates the read
    /// buffer accordingly.  Mirrors `bt_att_chan_new` (att.c lines 1237-1284).
    pub fn new(fd: RawFd, chan_type: u8) -> Result<Self, io::Error> {
        let mtu = match chan_type {
            BT_ATT_LOCAL => BT_ATT_DEFAULT_LE_MTU,
            _ => {
                let m = io_get_mtu(fd);
                if m < BT_ATT_DEFAULT_LE_MTU { BT_ATT_DEFAULT_LE_MTU } else { m }
            }
        };

        Ok(Self {
            fd,
            chan_type,
            sec_level: BT_SECURITY_SDP as i32,
            queue: VecDeque::new(),
            pending_req: None,
            pending_ind: None,
            pending_db_sync: None,
            writer_active: false,
            in_req: false,
            buf: vec![0u8; mtu as usize],
            mtu,
        })
    }

    /// Enqueue an ATT PDU for direct transmission on this channel.
    ///
    /// Constructs an internal send operation and pushes it into the channel's
    /// local queue.  Returns the assigned operation id (0 on encoding failure).
    ///
    /// Mirrors `bt_att_chan_send` (att.c lines 1772-1797).
    pub fn send(
        &mut self,
        opcode: u8,
        pdu: &[u8],
        callback: AttResponseCallback,
        next_id: &mut u32,
    ) -> u32 {
        let op_type = get_op_type(opcode);
        let mut encoded = Vec::with_capacity(1 + pdu.len());
        encoded.push(opcode);
        encoded.extend_from_slice(pdu);

        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        if *next_id == 0 {
            *next_id = 1;
        }

        let op = AttSendOp {
            id,
            timeout_handle: None,
            op_type,
            opcode,
            pdu: encoded,
            retry: false,
            callback,
        };
        self.queue.push_back(op);
        id
    }

    /// Cancel a pending or queued operation by id.
    ///
    /// Returns `true` if the operation was found and removed.
    /// Mirrors `bt_att_chan_cancel` (att.c lines 1807-1832).
    pub fn cancel(&mut self, id: u32) -> bool {
        // Check pending_db_sync.
        if let Some(ref op) = self.pending_db_sync {
            if op.id == id {
                self.pending_db_sync.take();
                return true;
            }
        }
        // Check pending_req.
        if let Some(ref op) = self.pending_req {
            if op.id == id {
                self.pending_req.take();
                return true;
            }
        }
        // Check pending_ind.
        if let Some(ref op) = self.pending_ind {
            if op.id == id {
                self.pending_ind.take();
                return true;
            }
        }
        // Check channel-local queue.
        if let Some(pos) = self.queue.iter().position(|o| o.id == id) {
            self.queue.remove(pos);
            return true;
        }
        false
    }

    /// Send an ATT Error Response PDU on this channel.
    ///
    /// Constructs a `BtAttPduErrorRsp` from the given request opcode, handle,
    /// and error code, then writes it to the socket.
    /// Mirrors `bt_att_chan_send_error_rsp` (att.c lines 1991-2009).
    pub fn send_error_rsp(&self, request_opcode: u8, handle: u16, ecode: u8) {
        let err_rsp = BtAttPduErrorRsp { opcode: request_opcode, handle, ecode };
        let mut pdu = Vec::with_capacity(5);
        pdu.push(BT_ATT_OP_ERROR_RSP);
        pdu.push(err_rsp.opcode);
        pdu.extend_from_slice(&err_rsp.handle.to_le_bytes());
        pdu.push(err_rsp.ecode);
        let _ = write_to_fd(self.fd, &pdu);
    }

    /// Write raw bytes to the channel socket.
    fn write_pdu(&self, data: &[u8]) -> io::Result<usize> {
        write_to_fd(self.fd, data)
    }

    /// Get the security level of this channel.
    fn get_security(&self) -> io::Result<(i32, u8)> {
        if self.chan_type == BT_ATT_LOCAL {
            return Ok((self.sec_level, 0));
        }
        let sec = getsockopt_bt_security(self.fd)?;
        Ok((sec.level as i32, sec.key_size))
    }

    /// Set the security level on this channel.
    fn set_security(&self, level: i32) -> io::Result<()> {
        let sec = bt_security { level: level as u8, key_size: 0 };
        setsockopt_bt_security(self.fd, &sec)
    }

    /// Returns true if there is queued or pending work on this channel.
    fn has_work(&self) -> bool {
        !self.queue.is_empty() || self.pending_req.is_some() || self.pending_ind.is_some()
    }
}

/// Write raw bytes to a file descriptor using `writev` (scatter-gather).
///
/// This replaces the C `bt_att_chan_write` which used `io_send` with iovecs.
#[allow(unsafe_code)]
fn write_to_fd(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    let iov = [IoSlice::new(data)];
    // SAFETY: The caller guarantees `fd` is a valid, open file descriptor.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    nix::sys::uio::writev(borrowed, &iov).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Read from a file descriptor into a buffer.
pub fn read_from_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    nix::unistd::read(fd, buf).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

// ---------------------------------------------------------------------------
// BtAtt — main ATT transport
// ---------------------------------------------------------------------------

/// Core ATT transport handle.
///
/// Replaces the C `struct bt_att` (att.c lines 59-95).
/// Shared ownership is achieved via `Arc<Mutex<BtAtt>>` — callers clone the
/// `Arc` instead of calling `bt_att_ref()`.
pub struct BtAtt {
    /// Whether to close the underlying FDs when the transport is dropped.
    close_on_drop: bool,
    /// Attached ATT bearer channels.  The *last* element (tail) is always
    /// the "original" channel; EATT channels are pushed to the front.
    chans: Vec<BtAttChan>,
    /// Encryption key size (set externally, e.g. by pairing).
    enc_size: u8,
    /// Largest MTU across all channels.
    mtu: u16,
    /// Registered opcode notification handlers.
    notify_list: Vec<AttNotify>,
    /// Registered disconnect handlers.
    disconn_list: Vec<AttDisconn>,
    /// Registered MTU-exchange handlers.
    exchange_list: Vec<AttExchange>,
    /// Monotonically increasing send-operation ID.
    next_send_id: u32,
    /// Monotonically increasing registration ID.
    next_reg_id: u32,
    /// Shared request queue (drained round-robin across channels).
    req_queue: VecDeque<AttSendOp>,
    /// Shared indication queue.
    ind_queue: VecDeque<AttSendOp>,
    /// Shared write (command/notification/response) queue.
    write_queue: VecDeque<AttSendOp>,
    /// Whether a disconnect sequence is in progress.
    in_disc: bool,
    /// Callback invoked when an ATT transaction times out.
    timeout_callback: Option<Box<dyn Fn(u32, u8) + Send + Sync>>,
    /// Callback invoked when the remote sends `DB_OUT_OF_SYNC`.
    db_sync_callback: AttDbSyncCallback,
    /// Current debug verbosity level.
    debug_level: u8,
    /// Debug logging callback.
    debug_callback: Option<Box<dyn Fn(&str) + Send + Sync>>,
    /// Whether the crypto subsystem is available (for signing).
    has_crypto_support: bool,
    /// Local signing key material.
    local_sign: Option<SignInfo>,
    /// Remote signing key material (for verifying incoming signed writes).
    remote_sign: Option<SignInfo>,
}

impl BtAtt {
    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// Create a new ATT transport over the given socket fd.
    ///
    /// Detects the channel type (BR/EDR, LE, or local loopback) from the
    /// socket, creates the initial channel, and optionally initialises
    /// the signing crypto subsystem.
    ///
    /// `ext_signed` — if `true`, the caller provides signing externally and
    /// the internal crypto engine is not initialised.
    ///
    /// Mirrors `bt_att_new` (att.c lines 1302-1329).
    pub fn new(fd: RawFd, ext_signed: bool) -> Result<Arc<Mutex<Self>>, io::Error> {
        let chan_type = io_get_type(fd);
        let chan = BtAttChan::new(fd, chan_type)?;
        let mtu = chan.mtu;

        let att = Self {
            close_on_drop: false,
            chans: vec![chan],
            enc_size: 0,
            mtu,
            notify_list: Vec::new(),
            disconn_list: Vec::new(),
            exchange_list: Vec::new(),
            next_send_id: 1,
            next_reg_id: 1,
            req_queue: VecDeque::new(),
            ind_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            in_disc: false,
            timeout_callback: None,
            db_sync_callback: None,
            debug_level: BT_ATT_DEBUG,
            debug_callback: None,
            has_crypto_support: !ext_signed,
            local_sign: None,
            remote_sign: None,
        };

        Ok(Arc::new(Mutex::new(att)))
    }

    // -----------------------------------------------------------------------
    // Channel management
    // -----------------------------------------------------------------------

    /// Attach an additional EATT channel fd to this transport.
    ///
    /// EATT channels are inserted at the head of the channel list for
    /// priority (att.c line 1289).
    ///
    /// Mirrors `bt_att_attach_fd` (att.c lines 1375-1389).
    pub fn attach_fd(&mut self, fd: RawFd) -> Result<(), io::Error> {
        let chan = BtAttChan::new(fd, BT_ATT_EATT)?;
        // If the new channel's MTU is larger, update the transport MTU.
        if chan.mtu > self.mtu {
            self.mtu = chan.mtu;
        }
        // Push to head (index 0) for priority — EATT channels are preferred.
        self.chans.insert(0, chan);
        Ok(())
    }

    /// Return the raw fd of the "original" (tail) channel.
    ///
    /// Mirrors `bt_att_get_fd` (att.c lines 1391-1404).
    pub fn get_fd(&self) -> Result<RawFd, io::Error> {
        self.chans
            .last()
            .map(|c| c.fd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no channels"))
    }

    /// Return the number of attached channels.
    ///
    /// Mirrors `bt_att_get_channels` (att.c lines 1406-1412).
    pub fn get_channels(&self) -> usize {
        self.chans.len()
    }

    // -----------------------------------------------------------------------
    // MTU management
    // -----------------------------------------------------------------------

    /// Return the largest MTU across all channels.
    ///
    /// Mirrors `bt_att_get_mtu` (att.c lines 1432-1438).
    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }

    /// Set the MTU on the original (tail) channel and, if it is the new
    /// maximum, update the transport MTU and fire exchange callbacks.
    ///
    /// Returns `false` if `mtu < BT_ATT_DEFAULT_LE_MTU` or there are no
    /// channels.
    ///
    /// Mirrors `bt_att_set_mtu` (att.c lines 1452-1484).
    pub fn set_mtu(&mut self, mtu: u16) -> bool {
        if mtu < BT_ATT_DEFAULT_LE_MTU {
            return false;
        }
        let tail_idx = match self.chans.len().checked_sub(1) {
            Some(i) => i,
            None => return false,
        };
        let chan = &mut self.chans[tail_idx];
        chan.mtu = mtu;
        chan.buf.resize(mtu as usize, 0);

        if mtu > self.mtu {
            self.mtu = mtu;
            // Notify exchange listeners.
            for ex in &self.exchange_list {
                if !ex.removed {
                    (ex.callback)(mtu);
                }
            }
        }
        true
    }

    /// Return the link type of the original (tail) channel.
    ///
    /// Mirrors `bt_att_get_link_type` (att.c lines 1486-1498).
    pub fn get_link_type(&self) -> u8 {
        self.chans.last().map_or(BT_ATT_LOCAL, |c| c.chan_type)
    }

    // -----------------------------------------------------------------------
    // Send operations
    // -----------------------------------------------------------------------

    /// Enqueue an ATT PDU for transmission and return a non-zero operation
    /// id on success (0 on failure).
    ///
    /// Mirrors `bt_att_send` (att.c lines 1644-1700).
    pub fn send(&mut self, opcode: u8, pdu: &[u8], callback: AttResponseCallback) -> u32 {
        let op_type = get_op_type(opcode);

        // Validate callback rules: REQ/IND require callback, CMD/NFY/RSP must
        // not have one.
        match op_type {
            AttOpType::Req | AttOpType::Ind => {
                if callback.is_none() {
                    return 0;
                }
            }
            AttOpType::Rsp | AttOpType::Cmd | AttOpType::Nfy | AttOpType::Conf => {
                if callback.is_some() {
                    return 0;
                }
            }
            AttOpType::Unknown => return 0,
        }

        let encoded =
            match encode_pdu(opcode, pdu, self.mtu, &self.local_sign, self.has_crypto_support) {
                Some(p) => p,
                None => return 0,
            };

        let id = self.next_send_id;
        self.next_send_id = self.next_send_id.wrapping_add(1);
        if self.next_send_id == 0 {
            self.next_send_id = 1;
        }

        let op = AttSendOp {
            id,
            timeout_handle: None,
            op_type,
            opcode,
            pdu: encoded,
            retry: false,
            callback,
        };

        // Route to the appropriate queue.
        match op_type {
            AttOpType::Req => {
                // MTU_REQ always goes to the original (tail) channel's own
                // queue (att.c line 1667).
                if opcode == BT_ATT_OP_MTU_REQ {
                    if let Some(tail) = self.chans.last_mut() {
                        tail.queue.push_back(op);
                    }
                } else {
                    self.req_queue.push_back(op);
                }
            }
            AttOpType::Ind => {
                self.ind_queue.push_back(op);
            }
            _ => {
                // CMD, NFY, RSP, CONF → write queue.
                self.write_queue.push_back(op);
            }
        }

        id
    }

    /// Re-submit a previously pending request (e.g. after a security upgrade
    /// or DB-out-of-sync resolution).
    ///
    /// Mirrors `bt_att_resend` (att.c lines 1703-1770).
    pub fn resend(
        &mut self,
        id: u32,
        opcode: u8,
        pdu: &[u8],
        callback: AttResponseCallback,
    ) -> Result<(), i32> {
        let op_type = get_op_type(opcode);
        if op_type != AttOpType::Req {
            return Err(-libc::EINVAL);
        }

        // Find the existing operation in pending_req or pending_db_sync.
        let mut found_op: Option<AttSendOp> = None;
        for chan in &mut self.chans {
            if let Some(ref p) = chan.pending_req {
                if p.id == id {
                    found_op = chan.pending_req.take();
                    break;
                }
            }
            if let Some(ref p) = chan.pending_db_sync {
                if p.id == id {
                    found_op = chan.pending_db_sync.take();
                    break;
                }
            }
        }

        let mut op = found_op.ok_or(-libc::ENOENT)?;

        // Re-encode the PDU.
        let encoded = encode_pdu(opcode, pdu, self.mtu, &self.local_sign, self.has_crypto_support)
            .ok_or(-libc::EINVAL)?;

        op.opcode = opcode;
        op.pdu = encoded;
        op.op_type = op_type;
        op.callback = callback;

        // Continuation operations (READ_BLOB, PREP_WRITE, EXEC_WRITE) go to
        // the head of the queue for immediate re-send; others go to the tail.
        let is_continuation = matches!(
            opcode,
            BT_ATT_OP_READ_BLOB_REQ | BT_ATT_OP_PREP_WRITE_REQ | BT_ATT_OP_EXEC_WRITE_REQ
        );

        if is_continuation {
            self.req_queue.push_front(op);
        } else {
            self.req_queue.push_back(op);
        }

        Ok(())
    }

    /// Cancel a single pending or queued operation by id.
    ///
    /// Mirrors `bt_att_cancel` (att.c lines 1885-1929).
    pub fn cancel(&mut self, id: u32) -> bool {
        // Check pending_db_sync on each channel first (att.c line 1899).
        for chan in &mut self.chans {
            if let Some(ref op) = chan.pending_db_sync {
                if op.id == id {
                    chan.pending_db_sync.take();
                    return true;
                }
            }
        }

        // Check per-channel pending_req/ind and queues.
        for chan in &mut self.chans {
            if chan.cancel(id) {
                return true;
            }
        }

        // During disconnect, check shared queues with disc_cancel logic.
        if self.in_disc {
            return self.disc_cancel(id);
        }

        // Check shared queues.
        if let Some(pos) = self.req_queue.iter().position(|o| o.id == id) {
            self.req_queue.remove(pos);
            return true;
        }
        if let Some(pos) = self.ind_queue.iter().position(|o| o.id == id) {
            self.ind_queue.remove(pos);
            return true;
        }
        if let Some(pos) = self.write_queue.iter().position(|o| o.id == id) {
            self.write_queue.remove(pos);
            return true;
        }
        false
    }

    /// Cancel all pending and queued operations.
    ///
    /// Mirrors `bt_att_cancel_all` (att.c lines 1932-1961).
    pub fn cancel_all(&mut self) -> bool {
        self.req_queue.clear();
        self.ind_queue.clear();
        self.write_queue.clear();

        for chan in &mut self.chans {
            chan.queue.clear();
            // Disarm pending operations (invoke callbacks with empty data).
            if let Some(mut op) = chan.pending_req.take() {
                if let Some(cb) = op.callback.take() {
                    cb(0, &[]);
                }
            }
            if let Some(mut op) = chan.pending_ind.take() {
                if let Some(cb) = op.callback.take() {
                    cb(0, &[]);
                }
            }
            if let Some(op) = chan.pending_db_sync.take() {
                drop(op);
            }
        }
        true
    }

    // -----------------------------------------------------------------------
    // Notification / callback registration
    // -----------------------------------------------------------------------

    /// Register a handler for incoming ATT PDUs matching `opcode`.
    ///
    /// Use `BT_ATT_ALL_REQUESTS` (0x00) to match all requests and commands.
    /// Returns a non-zero registration id.
    ///
    /// Mirrors `bt_att_register` (att.c lines 2012-2038).
    pub fn register(&mut self, opcode: u8, callback: AttNotifyCallback) -> u32 {
        let id = self.next_reg_id;
        self.next_reg_id = self.next_reg_id.wrapping_add(1);
        if self.next_reg_id == 0 {
            self.next_reg_id = 1;
        }

        self.notify_list.push(AttNotify { id, opcode: opcode as u16, callback });

        id
    }

    /// Unregister a previously registered opcode handler.
    ///
    /// Mirrors `bt_att_unregister` (att.c lines 2041-2055).
    pub fn unregister(&mut self, id: u32) -> bool {
        if let Some(pos) = self.notify_list.iter().position(|n| n.id == id) {
            self.notify_list.remove(pos);
            return true;
        }
        false
    }

    /// Register a disconnect handler.  Returns a non-zero id.
    ///
    /// Mirrors `bt_att_register_disconnect` (att.c lines 1534-1560).
    pub fn register_disconnect(&mut self, callback: Box<dyn Fn(i32) + Send + Sync>) -> u32 {
        let id = self.next_reg_id;
        self.next_reg_id = self.next_reg_id.wrapping_add(1);
        if self.next_reg_id == 0 {
            self.next_reg_id = 1;
        }

        self.disconn_list.push(AttDisconn { id, removed: false, callback });

        id
    }

    /// Unregister a disconnect handler.
    ///
    /// During an active disconnect sequence the entry is marked `removed`
    /// instead of being immediately deleted.
    ///
    /// Mirrors `bt_att_unregister_disconnect` (att.c lines 1562-1587).
    pub fn unregister_disconnect(&mut self, id: u32) -> bool {
        if let Some(pos) = self.disconn_list.iter().position(|d| d.id == id) {
            if self.chans.is_empty() {
                // During disconnect — mark removed, don't actually delete.
                self.disconn_list[pos].removed = true;
            } else {
                self.disconn_list.remove(pos);
            }
            return true;
        }
        false
    }

    /// Register an MTU-exchange callback.  Returns a non-zero id.
    ///
    /// Mirrors `bt_att_register_exchange` (att.c lines 1589-1615).
    pub fn register_exchange(&mut self, callback: Box<dyn Fn(u16) + Send + Sync>) -> u32 {
        let id = self.next_reg_id;
        self.next_reg_id = self.next_reg_id.wrapping_add(1);
        if self.next_reg_id == 0 {
            self.next_reg_id = 1;
        }

        self.exchange_list.push(AttExchange { id, removed: false, callback });

        id
    }

    /// Unregister an MTU-exchange callback.
    ///
    /// Mirrors `bt_att_unregister_exchange` (att.c lines 1617-1642).
    pub fn unregister_exchange(&mut self, id: u32) -> bool {
        if let Some(pos) = self.exchange_list.iter().position(|e| e.id == id) {
            self.exchange_list.remove(pos);
            return true;
        }
        false
    }

    /// Unregister all notification handlers.
    ///
    /// Mirrors `bt_att_unregister_all` (att.c lines 2057-2067).
    pub fn unregister_all(&mut self) -> bool {
        self.notify_list.clear();
        true
    }

    // -----------------------------------------------------------------------
    // Security management
    // -----------------------------------------------------------------------

    /// Get the security level and encryption key size for the transport.
    ///
    /// Queries the original (tail) channel.  For `BT_ATT_LOCAL` channels the
    /// stored `sec_level` is returned.
    ///
    /// Mirrors `bt_att_get_security` (att.c lines 2069-2089).
    pub fn get_security(&self, enc_size: &mut u8) -> Result<i32, io::Error> {
        let chan = self
            .chans
            .last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no channels"))?;

        let (level, ks) = chan.get_security()?;
        *enc_size = if self.enc_size > 0 { self.enc_size } else { ks };
        Ok(level)
    }

    /// Set the security level on the original (tail) channel.
    ///
    /// Validates that `level` is in the range `BT_SECURITY_SDP..=BT_SECURITY_HIGH`.
    ///
    /// Mirrors `bt_att_set_security` (att.c lines 2091-2104).
    pub fn set_security(&mut self, level: i32) -> bool {
        if level < BT_SECURITY_SDP as i32 || level > BT_SECURITY_HIGH as i32 {
            return false;
        }
        let chan = match self.chans.last() {
            Some(c) => c,
            None => return false,
        };
        if chan.chan_type == BT_ATT_LOCAL {
            // For local channels, just record the level.
            if let Some(c) = self.chans.last_mut() {
                c.sec_level = level;
            }
            return true;
        }
        chan.set_security(level).is_ok()
    }

    /// Set the encryption key size (externally determined, e.g. by pairing).
    ///
    /// Mirrors `bt_att_set_enc_key_size` (att.c lines 2106-2112).
    pub fn set_enc_key_size(&mut self, enc_size: u8) {
        self.enc_size = enc_size;
    }

    // -----------------------------------------------------------------------
    // Signing keys
    // -----------------------------------------------------------------------

    /// Set the local signing key (CSRK) and counter callback.
    ///
    /// Mirrors `bt_att_set_local_key` (att.c lines 2127-2133).
    pub fn set_local_key(
        &mut self,
        key: &[u8; 16],
        counter: Box<dyn Fn(&mut u32) -> bool + Send + Sync>,
    ) -> bool {
        self.local_sign = Some(SignInfo { key: *key, counter });
        true
    }

    /// Set the remote signing key (CSRK) and counter callback.
    ///
    /// Mirrors `bt_att_set_remote_key` (att.c lines 2135-2143).
    pub fn set_remote_key(
        &mut self,
        key: &[u8; 16],
        counter: Box<dyn Fn(&mut u32) -> bool + Send + Sync>,
    ) -> bool {
        self.remote_sign = Some(SignInfo { key: *key, counter });
        true
    }

    /// Check whether the signing crypto subsystem is available.
    ///
    /// Mirrors `bt_att_has_crypto` (att.c lines 2145-2151).
    pub fn has_crypto(&self) -> bool {
        self.has_crypto_support
    }

    /// Set or clear the retry flag on a pending operation.
    ///
    /// **Note:** The C code at att.c line 2174 stores `!retry`, so the
    /// semantics are inverted: passing `true` here actually clears the
    /// retry flag, and `false` sets it.
    ///
    /// Mirrors `bt_att_set_retry` (att.c lines 2153-2177).
    pub fn set_retry(&mut self, id: u32, retry: bool) -> bool {
        for chan in &mut self.chans {
            if let Some(ref mut op) = chan.pending_req {
                if op.id == id {
                    op.retry = !retry; // Inverted per C code
                    return true;
                }
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Debug configuration
    // -----------------------------------------------------------------------

    /// Set the debug verbosity level and callback.
    ///
    /// Mirrors `bt_att_set_debug` (att.c lines 1414-1430).
    pub fn set_debug(
        &mut self,
        level: u8,
        callback: Option<Box<dyn Fn(&str) + Send + Sync>>,
    ) -> bool {
        self.debug_level = level;
        self.debug_callback = callback;
        true
    }

    // -----------------------------------------------------------------------
    // Timeout and DB-sync callbacks
    // -----------------------------------------------------------------------

    /// Set the ATT transaction timeout callback.
    ///
    /// Mirrors `bt_att_set_timeout_cb` (att.c lines 1500-1515).
    pub fn set_timeout_cb(&mut self, callback: Box<dyn Fn(u32, u8) + Send + Sync>) -> bool {
        self.timeout_callback = Some(callback);
        true
    }

    /// Set the DB-out-of-sync callback.
    ///
    /// Mirrors `bt_att_set_db_sync_cb` (att.c lines 1517-1532).
    pub fn set_db_sync_cb(&mut self, callback: Box<dyn Fn(u8, &[u8], u32) + Send + Sync>) -> bool {
        self.db_sync_callback = Some(callback);
        true
    }

    // -----------------------------------------------------------------------
    // Close-on-drop
    // -----------------------------------------------------------------------

    /// Control whether the underlying socket FDs are closed when this
    /// transport (or all `Arc` references to it) is dropped.
    ///
    /// Mirrors `bt_att_set_close_on_unref` (att.c lines 1355-1373).
    pub fn set_close_on_drop(&mut self, do_close: bool) -> bool {
        self.close_on_drop = do_close;
        true
    }

    // -----------------------------------------------------------------------
    // Internal: write scheduling
    // -----------------------------------------------------------------------

    /// Pick the next operation to send on `chan` (channel at `chan_idx`).
    ///
    /// Priority order (att.c `pick_next_send_op` lines 421-462):
    /// 1. Channel-local queue
    /// 2. Shared write queue (if PDU fits the channel MTU)
    /// 3. Shared request queue (if no pending_req; skip MTU_REQ on EATT)
    /// 4. Shared indication queue (if no pending_ind)
    fn pick_next_send_op(&mut self, chan_idx: usize) -> Option<AttSendOp> {
        let chan = &self.chans[chan_idx];
        let chan_mtu = chan.mtu as usize;
        let chan_type = chan.chan_type;
        let has_pending_req = chan.pending_req.is_some();
        let has_pending_ind = chan.pending_ind.is_some();

        // 1. Channel-local queue.
        {
            let chan = &mut self.chans[chan_idx];
            if let Some(op) = chan.queue.pop_front() {
                return Some(op);
            }
        }

        // 2. Shared write queue (CMD/NFY/RSP/CONF) — only if fits MTU.
        if let Some(pos) = self.write_queue.iter().position(|op| op.pdu.len() <= chan_mtu) {
            return self.write_queue.remove(pos);
        }

        // 3. Shared request queue — only if no pending_req.
        if !has_pending_req {
            let pos = self.req_queue.iter().position(|op| {
                // Skip MTU_REQ on EATT channels.
                if chan_type == BT_ATT_EATT && op.opcode == BT_ATT_OP_MTU_REQ {
                    return false;
                }
                true
            });
            if let Some(p) = pos {
                return self.req_queue.remove(p);
            }
        }

        // 4. Shared indication queue — only if no pending_ind.
        if !has_pending_ind {
            if let Some(op) = self.ind_queue.pop_front() {
                return Some(op);
            }
        }

        None
    }

    /// Attempt to write the next queued operation on channel `chan_idx`.
    ///
    /// Mirrors `can_write_data` (att.c lines 549-599).
    fn try_write_chan(&mut self, chan_idx: usize) -> bool {
        let op = match self.pick_next_send_op(chan_idx) {
            Some(o) => o,
            None => return false,
        };

        let write_ok = {
            let chan = &self.chans[chan_idx];
            chan.write_pdu(&op.pdu).is_ok()
        };

        if !write_ok {
            // Write failed — discard the operation.
            return false;
        }

        let op_type = op.op_type;
        let _opcode = op.opcode;

        match op_type {
            AttOpType::Req => {
                // Store as pending; start 30s timeout.
                let chan = &mut self.chans[chan_idx];
                chan.pending_req = Some(op);
                // Timeout handling is done externally via the async I/O loop;
                // here we record that the operation is pending.
            }
            AttOpType::Ind => {
                let chan = &mut self.chans[chan_idx];
                chan.pending_ind = Some(op);
            }
            AttOpType::Rsp => {
                // Clear the in_req flag for this channel.
                let chan = &mut self.chans[chan_idx];
                chan.in_req = false;
                // Response sent — op is consumed.
                drop(op);
            }
            _ => {
                // CMD, NFY, CONF — consumed after send.
                drop(op);
            }
        }

        true
    }

    /// Wake up the writer on all channels — attempt to drain queued operations.
    fn wakeup_writer(&mut self) {
        for i in 0..self.chans.len() {
            self.wakeup_chan_writer(i);
        }
    }

    /// Wake up the writer on a specific channel.
    ///
    /// Mirrors `wakeup_chan_writer` (att.c lines 601-623).
    fn wakeup_chan_writer(&mut self, chan_idx: usize) {
        if chan_idx >= self.chans.len() {
            return;
        }
        // Only write if the channel or shared queues have work.
        let chan = &self.chans[chan_idx];
        let has_work = chan.has_work()
            || !self.write_queue.is_empty()
            || !self.req_queue.is_empty()
            || !self.ind_queue.is_empty();

        if !has_work {
            return;
        }

        self.chans[chan_idx].writer_active = true;
        while self.try_write_chan(chan_idx) {
            // Keep writing until the queue is drained or write blocks.
        }
        if chan_idx < self.chans.len() {
            self.chans[chan_idx].writer_active = false;
        }
    }

    // -----------------------------------------------------------------------
    // Internal: read/response processing
    // -----------------------------------------------------------------------

    /// Process an incoming ATT PDU on channel `chan_idx`.
    ///
    /// Dispatches by opcode type to the appropriate handler.
    /// Mirrors `can_read_data` (att.c lines 1077-1149).
    fn handle_pdu(&mut self, chan_idx: usize, pdu: &[u8]) {
        if pdu.len() < ATT_MIN_PDU_LEN {
            return;
        }
        let opcode = pdu[0];
        let body = &pdu[1..];

        match get_op_type(opcode) {
            AttOpType::Rsp => {
                self.handle_rsp(chan_idx, opcode, body);
            }
            AttOpType::Conf => {
                self.handle_conf(chan_idx);
            }
            AttOpType::Req => {
                {
                    let chan = &self.chans[chan_idx];
                    if chan.in_req {
                        // Protocol violation: overlapping requests on the
                        // same channel — shutdown.
                        return;
                    }
                }
                self.chans[chan_idx].in_req = true;
                self.handle_notify(chan_idx, opcode, body);
            }
            AttOpType::Cmd | AttOpType::Nfy | AttOpType::Ind | AttOpType::Unknown => {
                self.handle_notify(chan_idx, opcode, body);
            }
        }
    }

    /// Handle an incoming response PDU.
    ///
    /// Matches the response to the pending request on the channel and invokes
    /// its callback.  Error responses receive special handling (security
    /// upgrade, DB-out-of-sync).
    ///
    /// Mirrors `handle_rsp` (att.c lines 859-919).
    fn handle_rsp(&mut self, chan_idx: usize, opcode: u8, body: &[u8]) {
        let pending = self.chans[chan_idx].pending_req.take();
        let mut op = match pending {
            Some(o) => o,
            None => return, // No pending request — discard.
        };

        if opcode == BT_ATT_OP_ERROR_RSP {
            self.handle_error_rsp(chan_idx, &mut op, body);
            // handle_error_rsp may re-queue the op if retrying.
            return;
        }

        // Verify the response matches the expected request opcode.
        if let Some(expected_req) = get_req_opcode(opcode) {
            if expected_req != op.opcode && expected_req != 0 {
                // Mismatch — discard.
                return;
            }
        }

        // Invoke the callback.
        if let Some(cb) = op.callback.take() {
            cb(opcode, body);
        }

        // Wake up writer to send next queued operation.
        self.wakeup_chan_writer(chan_idx);
    }

    /// Handle an ATT Error Response.
    ///
    /// Implements security upgrade retry and DB-out-of-sync handling.
    ///
    /// Mirrors `handle_error_rsp` (att.c lines 793-857).
    fn handle_error_rsp(&mut self, chan_idx: usize, op: &mut AttSendOp, body: &[u8]) {
        if body.len() < 4 {
            // Malformed error response — invoke callback with generic error.
            if let Some(cb) = op.callback.take() {
                cb(BT_ATT_OP_ERROR_RSP, body);
            }
            return;
        }

        let _req_opcode = body[0];
        let _handle = u16::from_le_bytes([body[1], body[2]]);
        let ecode = body[3];

        // DB_OUT_OF_SYNC: move op to pending_db_sync and notify.
        if ecode == BT_ATT_ERROR_DB_OUT_OF_SYNC {
            // Remove timeout.
            if let Some(h) = op.timeout_handle.take() {
                h.abort();
            }
            // Invoke db_sync_callback if registered.
            if let Some(ref sync_cb) = self.db_sync_callback {
                sync_cb(op.opcode, &op.pdu, op.id);
            }
            // Transfer to pending_db_sync.
            let stolen_op = AttSendOp {
                id: op.id,
                timeout_handle: None,
                op_type: op.op_type,
                opcode: op.opcode,
                pdu: std::mem::take(&mut op.pdu),
                retry: op.retry,
                callback: op.callback.take(),
            };
            self.chans[chan_idx].pending_db_sync = Some(stolen_op);
            return;
        }

        // Security retry: attempt to upgrade security level if appropriate.
        if !op.retry && self.try_security_upgrade(chan_idx, op, ecode) {
            // Remove timeout; the op is re-queued for retry.
            if let Some(h) = op.timeout_handle.take() {
                h.abort();
            }
            op.retry = true;
            let retry_op = AttSendOp {
                id: op.id,
                timeout_handle: None,
                op_type: op.op_type,
                opcode: op.opcode,
                pdu: std::mem::take(&mut op.pdu),
                retry: true,
                callback: op.callback.take(),
            };
            // Push to head of channel queue for immediate retry.
            self.chans[chan_idx].queue.push_front(retry_op);
            self.wakeup_chan_writer(chan_idx);
            return;
        }

        // No retry — invoke the callback with the error.
        if let Some(cb) = op.callback.take() {
            cb(BT_ATT_OP_ERROR_RSP, body);
        }
        self.wakeup_chan_writer(chan_idx);
    }

    /// Attempt a security upgrade based on an ATT error code.
    ///
    /// Mirrors `change_security` (att.c lines 765-791):
    /// - `INSUFFICIENT_ENCRYPTION` + sec < MEDIUM → upgrade to MEDIUM
    /// - `AUTHENTICATION` → step through MEDIUM → HIGH → FIPS
    fn try_security_upgrade(&self, _chan_idx: usize, _op: &AttSendOp, ecode: u8) -> bool {
        let chan = match self.chans.last() {
            Some(c) => c,
            None => return false,
        };

        let (current_level, _) = match chan.get_security() {
            Ok(v) => v,
            Err(_) => return false,
        };

        let new_level = match ecode {
            BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION => {
                if current_level < BT_SECURITY_MEDIUM as i32 {
                    Some(BT_SECURITY_MEDIUM as i32)
                } else {
                    None
                }
            }
            BT_ATT_ERROR_AUTHENTICATION => {
                if current_level < BT_SECURITY_MEDIUM as i32 {
                    Some(BT_SECURITY_MEDIUM as i32)
                } else if current_level < BT_SECURITY_HIGH as i32 {
                    Some(BT_SECURITY_HIGH as i32)
                } else if current_level < BT_SECURITY_FIPS as i32 {
                    Some(BT_SECURITY_FIPS as i32)
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(level) = new_level { chan.set_security(level).is_ok() } else { false }
    }

    /// Handle an incoming confirmation PDU (response to an indication).
    ///
    /// Mirrors `handle_conf` (att.c lines 921-944).
    fn handle_conf(&mut self, chan_idx: usize) {
        let pending = self.chans[chan_idx].pending_ind.take();
        if let Some(mut op) = pending {
            if let Some(cb) = op.callback.take() {
                cb(BT_ATT_OP_HANDLE_CONF, &[]);
            }
        }
        self.wakeup_chan_writer(chan_idx);
    }

    /// Dispatch an incoming PDU to registered notification handlers.
    ///
    /// Handles signed write verification, BR/EDR MTU_REQ rejection, and
    /// "not supported" for unhandled non-command opcodes.
    ///
    /// Mirrors `handle_notify` (att.c lines 1010-1075).
    fn handle_notify(&mut self, chan_idx: usize, opcode: u8, body: &[u8]) {
        let chan_type = self.chans[chan_idx].chan_type;

        // BR/EDR and EATT: reject MTU_REQ with "not supported".
        if opcode == BT_ATT_OP_MTU_REQ && (chan_type == BT_ATT_BREDR || chan_type == BT_ATT_EATT) {
            let handle: u16 = 0;
            self.chans[chan_idx].send_error_rsp(opcode, handle, BT_ATT_ERROR_REQUEST_NOT_SUPPORTED);
            return;
        }

        // Handle signed writes: verify signature if opcode has SIGNED_MASK.
        let verified_body = if opcode & ATT_OP_SIGNED_MASK != 0 {
            if let Some(ref remote_sign) = self.remote_sign {
                // Build full PDU (opcode + body) for verification.
                let mut full_pdu = Vec::with_capacity(1 + body.len());
                full_pdu.push(opcode);
                full_pdu.extend_from_slice(body);
                match bt_crypto_verify_att_sign(&remote_sign.key, &full_pdu) {
                    Ok(true) => {
                        // Strip the 12-byte signature from the body.
                        if body.len() >= BT_ATT_SIGNATURE_LEN {
                            &body[..body.len() - BT_ATT_SIGNATURE_LEN]
                        } else {
                            return; // Malformed signed PDU.
                        }
                    }
                    _ => return, // Signature verification failed.
                }
            } else {
                return; // No remote signing key configured.
            }
        } else {
            body
        };

        // Dispatch to registered handlers.
        let mut handled = false;
        for notify in &self.notify_list {
            if opcode_match(notify.opcode, opcode) {
                (notify.callback)(chan_idx, notify.opcode, opcode, verified_body);
                handled = true;
            }
        }

        // If no handler matched a non-CMD opcode, send "Not Supported".
        if !handled {
            let op_type = get_op_type(opcode);
            if op_type != AttOpType::Cmd && op_type != AttOpType::Nfy {
                self.chans[chan_idx].send_error_rsp(opcode, 0, BT_ATT_ERROR_REQUEST_NOT_SUPPORTED);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: disconnect handling
    // -----------------------------------------------------------------------

    /// Handle channel disconnect (HUP/ERR on the socket).
    ///
    /// Mirrors `disconnect_cb` (att.c lines 663-721).
    fn handle_disconnect(&mut self, chan_idx: usize, err: i32) {
        // Remove the channel.
        if chan_idx < self.chans.len() {
            self.chans.remove(chan_idx);
        }

        // If channels remain, just notify pending ops on the removed channel.
        if !self.chans.is_empty() {
            return;
        }

        // No channels left — full disconnect.
        self.in_disc = true;

        // Drain all shared queues, invoking callbacks with the error.
        self.drain_queue_with_error(&mut VecDeque::new(), err);
        let mut rq = std::mem::take(&mut self.req_queue);
        self.drain_queue_with_error(&mut rq, err);
        let mut iq = std::mem::take(&mut self.ind_queue);
        self.drain_queue_with_error(&mut iq, err);
        let mut wq = std::mem::take(&mut self.write_queue);
        self.drain_queue_with_error(&mut wq, err);

        // Notify disconnect handlers.
        for d in &self.disconn_list {
            if !d.removed {
                (d.callback)(err);
            }
        }

        // Clean up removed entries.
        self.disconn_list.retain(|d| !d.removed);
        self.in_disc = false;
    }

    /// Drain a send-op queue, invoking each operation's callback with an
    /// error indication.
    fn drain_queue_with_error(&self, queue: &mut VecDeque<AttSendOp>, _err: i32) {
        while let Some(mut op) = queue.pop_front() {
            if let Some(cb) = op.callback.take() {
                cb(BT_ATT_OP_ERROR_RSP, &[]);
            }
        }
    }

    /// Cancel during disconnect — looks in shared queues.
    fn disc_cancel(&mut self, id: u32) -> bool {
        if let Some(pos) = self.req_queue.iter().position(|o| o.id == id) {
            self.req_queue.remove(pos);
            return true;
        }
        if let Some(pos) = self.ind_queue.iter().position(|o| o.id == id) {
            self.ind_queue.remove(pos);
            return true;
        }
        if let Some(pos) = self.write_queue.iter().position(|o| o.id == id) {
            self.write_queue.remove(pos);
            return true;
        }
        false
    }

    // -----------------------------------------------------------------------
    // Public: process incoming data (called from async read loop)
    // -----------------------------------------------------------------------

    /// Process raw bytes read from channel `chan_idx`.
    ///
    /// This is the main entry point called by the external async I/O loop
    /// when data is available on a channel's socket.
    pub fn process_read(&mut self, chan_idx: usize, data: &[u8]) {
        self.handle_pdu(chan_idx, data);
    }

    /// Notify the transport that a channel has disconnected.
    ///
    /// Called by the external async I/O loop when HUP/ERR is detected.
    pub fn process_disconnect(&mut self, chan_idx: usize, err: i32) {
        self.handle_disconnect(chan_idx, err);
    }

    /// Attempt to write queued operations on all channels.
    ///
    /// Called by the external async I/O loop when a channel becomes writable.
    pub fn flush_writes(&mut self) {
        self.wakeup_writer();
    }

    /// Attempt to write queued operations on a specific channel.
    pub fn flush_chan_writes(&mut self, chan_idx: usize) {
        if chan_idx < self.chans.len() {
            self.wakeup_chan_writer(chan_idx);
        }
    }
}

impl Drop for BtAtt {
    fn drop(&mut self) {
        if self.close_on_drop {
            for chan in &self.chans {
                let _ = nix::unistd::close(chan.fd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public utility helpers
// ---------------------------------------------------------------------------

/// Convert a raw opcode byte to the typed [`AttOpcode`] enum.
///
/// Returns `None` if the byte is not a recognized ATT opcode value.
pub fn opcode_to_att_opcode(opcode: u8) -> Option<AttOpcode> {
    AttOpcode::try_from(opcode).ok()
}

/// Convert a raw ATT error code byte to the typed [`AttError`] enum.
///
/// Returns `None` if the byte is not a standard (0x01..=0x13) ATT error.
pub fn ecode_to_att_error(ecode: u8) -> Option<AttError> {
    AttError::try_from(ecode).ok()
}

/// Convert an [`AttSecurityLevel`] to the corresponding kernel
/// `BT_SECURITY_*` level used in `setsockopt`.
///
/// The mapping is: Auto → SDP (0), Low → LOW (1), Medium → MEDIUM (2),
/// High → HIGH (3), Fips → FIPS (4).
pub fn security_level_to_kernel(level: AttSecurityLevel) -> i32 {
    match level {
        AttSecurityLevel::Auto => BT_SECURITY_SDP as i32,
        AttSecurityLevel::Low => BT_SECURITY_LOW as i32,
        AttSecurityLevel::Medium => BT_SECURITY_MEDIUM as i32,
        AttSecurityLevel::High => BT_SECURITY_HIGH as i32,
        AttSecurityLevel::Fips => BT_SECURITY_FIPS as i32,
    }
}

/// Determine the minimum [`AttSecurityLevel`] required by the given
/// permission mask.
///
/// - Secure permissions → `High`
/// - Authentication permissions → `Medium`
/// - Encryption permissions → `Low`
/// - Otherwise → `Auto` (no requirement)
pub fn security_for_permissions(perms: AttPermissions) -> AttSecurityLevel {
    if perms.intersects(AttPermissions::SECURE) {
        AttSecurityLevel::High
    } else if perms.intersects(AttPermissions::AUTHEN) {
        AttSecurityLevel::Medium
    } else if perms.intersects(AttPermissions::ENCRYPT) {
        AttSecurityLevel::Low
    } else {
        AttSecurityLevel::Auto
    }
}

/// Return the valid MTU range for ATT: `(min, max)`.
///
/// The minimum is [`BT_ATT_DEFAULT_LE_MTU`] (23 bytes) and the maximum
/// is [`BT_ATT_MAX_LE_MTU`] (517 bytes).
pub fn mtu_range() -> (u16, u16) {
    (BT_ATT_DEFAULT_LE_MTU, BT_ATT_MAX_LE_MTU)
}

/// The fixed L2CAP CID for the ATT bearer (CID 4).
pub const ATT_FIXED_CID: u16 = BT_ATT_CID;

/// The fixed L2CAP PSM for ATT (PSM 0x001F = 31).
pub const ATT_FIXED_PSM: u16 = BT_ATT_PSM;

/// The L2CAP PSM for Enhanced ATT bearers (EATT, PSM 0x0027 = 39).
pub const EATT_FIXED_PSM: u16 = BT_ATT_EATT_PSM;
