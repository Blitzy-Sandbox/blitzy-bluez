// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2011-2014  Intel Corporation
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
//
// l2cap.rs — L2CAP dissector: central routing hub for btmon protocol dissectors.

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::{print_field, print_indent, print_text};

// ============================================================================
// L2capFrame — Core Frame Cursor Struct
// ============================================================================

/// Core frame cursor struct used by ALL btmon dissectors.
#[derive(Clone)]
pub struct L2capFrame {
    pub index: u16,
    pub in_: bool,
    pub handle: u16,
    pub ident: u8,
    pub cid: u16,
    pub psm: u16,
    pub chan: u16,
    pub mode: u8,
    pub seq_num: u8,
    pub data: Vec<u8>,
    pub pos: usize,
    pub size: u16,
}

impl L2capFrame {
    /// Create a new L2capFrame wrapping data with the given logical size.
    pub fn new(data: Vec<u8>, size: u16) -> Self {
        Self {
            index: 0,
            in_: false,
            handle: 0,
            ident: 0,
            cid: 0,
            psm: 0,
            chan: u16::MAX,
            mode: 0,
            seq_num: 0,
            data,
            pos: 0,
            size,
        }
    }

    /// Return a slice of the remaining un-consumed data from current position.
    pub fn remaining_data(&self) -> &[u8] {
        let end = self.pos.saturating_add(self.size as usize).min(self.data.len());
        &self.data[self.pos..end]
    }

    /// Advance cursor by `offset` bytes without reading.
    pub fn pull(&mut self, offset: usize) -> bool {
        if (self.size as usize) < offset {
            return false;
        }
        self.pos += offset;
        self.size -= offset as u16;
        true
    }

    /// Read one byte, advancing the cursor.
    pub fn get_u8(&mut self) -> Option<u8> {
        if (self.size as usize) < 1 {
            return None;
        }
        let v = self.data[self.pos];
        self.pos += 1;
        self.size -= 1;
        Some(v)
    }

    /// Read a little-endian u16, advancing the cursor.
    pub fn get_le16(&mut self) -> Option<u16> {
        if (self.size as usize) < 2 {
            return None;
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        self.size -= 2;
        Some(v)
    }

    /// Read a big-endian u16, advancing the cursor.
    pub fn get_be16(&mut self) -> Option<u16> {
        if (self.size as usize) < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        self.size -= 2;
        Some(v)
    }

    /// Read 3 bytes as little-endian u32, advancing 3 bytes.
    pub fn get_le24(&mut self) -> Option<u32> {
        if (self.size as usize) < 3 {
            return None;
        }
        let v = u32::from(self.data[self.pos])
            | (u32::from(self.data[self.pos + 1]) << 8)
            | (u32::from(self.data[self.pos + 2]) << 16);
        self.pos += 3;
        self.size -= 3;
        Some(v)
    }

    /// Read 3 bytes as big-endian u32, advancing 3 bytes.
    pub fn get_be24(&mut self) -> Option<u32> {
        if (self.size as usize) < 3 {
            return None;
        }
        let v = (u32::from(self.data[self.pos]) << 16)
            | (u32::from(self.data[self.pos + 1]) << 8)
            | u32::from(self.data[self.pos + 2]);
        self.pos += 3;
        self.size -= 3;
        Some(v)
    }

    /// Read a little-endian u32, advancing the cursor.
    pub fn get_le32(&mut self) -> Option<u32> {
        if (self.size as usize) < 4 {
            return None;
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        self.size -= 4;
        Some(v)
    }

    /// Read a big-endian u32, advancing the cursor.
    pub fn get_be32(&mut self) -> Option<u32> {
        if (self.size as usize) < 4 {
            return None;
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        self.size -= 4;
        Some(v)
    }

    /// Read a little-endian u64, advancing the cursor.
    pub fn get_le64(&mut self) -> Option<u64> {
        if (self.size as usize) < 8 {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        self.size -= 8;
        Some(u64::from_le_bytes(b))
    }

    /// Read a big-endian u64, advancing the cursor.
    pub fn get_be64(&mut self) -> Option<u64> {
        if (self.size as usize) < 8 {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        self.size -= 8;
        Some(u64::from_be_bytes(b))
    }

    /// Read big-endian u128 (16 bytes).
    /// NOTE: The C code (l2cap.h) reads both halves from frame->data without
    /// offset between them, producing an intentional duplication. We replicate
    /// that behavioral clone.
    pub fn get_be128(&mut self) -> Option<u128> {
        if (self.size as usize) < 16 {
            return None;
        }
        let mut hi = [0u8; 8];
        hi.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&self.data[self.pos + 8..self.pos + 16]);
        let v = (u128::from(u64::from_be_bytes(hi)) << 64) | u128::from(u64::from_be_bytes(lo));
        self.pos += 16;
        self.size -= 16;
        Some(v)
    }

    /// Clone frame with a truncated size.
    pub fn clone_size(&self, len: usize) -> L2capFrame {
        let mut f = self.clone();
        f.size = len as u16;
        f
    }

    // Print helpers — read, format, print, return true on success.

    pub fn print_u8(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_u8() {
            print_field!("{}: 0x{:02x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_le16(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_le16() {
            print_field!("{}: 0x{:04x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_be16(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_be16() {
            print_field!("{}: 0x{:04x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_le24(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_le24() {
            print_field!("{}: 0x{:06x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_be24(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_be24() {
            print_field!("{}: 0x{:06x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_le32(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_le32() {
            print_field!("{}: 0x{:08x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_be32(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_be32() {
            print_field!("{}: 0x{:08x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_le64(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_le64() {
            print_field!("{}: 0x{:016x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_be64(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_be64() {
            print_field!("{}: 0x{:016x}", label, v);
            true
        } else {
            false
        }
    }

    pub fn print_be128(&mut self, label: &str) -> bool {
        if let Some(v) = self.get_be128() {
            print_field!("{}: 0x{:032x}", label, v);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

const L2CAP_MODE_BASIC: u8 = 0x00;
const L2CAP_MODE_RETRANS: u8 = 0x01;
const L2CAP_MODE_FLOWCTL: u8 = 0x02;
const L2CAP_MODE_ERTM: u8 = 0x03;
const L2CAP_MODE_STREAMING: u8 = 0x04;
const L2CAP_MODE_LE_FLOWCTL: u8 = 0x80;
const L2CAP_MODE_ECRED: u8 = 0x81;

// Standard control field bitmasks
const L2CAP_CTRL_FRAME_TYPE: u16 = 0x0001;
const L2CAP_CTRL_SUPERVISE_MASK: u16 = 0x000c;
const L2CAP_CTRL_SUPER_SHIFT: u32 = 2;
const L2CAP_CTRL_POLL: u16 = 0x0010;
const L2CAP_CTRL_FINAL: u16 = 0x0080;
const L2CAP_CTRL_TXSEQ_MASK: u16 = 0x007e;
const L2CAP_CTRL_TXSEQ_SHIFT: u32 = 1;
const L2CAP_CTRL_REQSEQ_MASK: u16 = 0x3f00;
const L2CAP_CTRL_REQSEQ_SHIFT: u32 = 8;
const L2CAP_CTRL_SAR_MASK: u16 = 0xc000;
const L2CAP_CTRL_SAR_SHIFT: u32 = 14;

// Extended control field bitmasks
const L2CAP_EXT_CTRL_FRAME_TYPE: u32 = 0x0000_0001;
const L2CAP_EXT_CTRL_SUPERVISE_MASK: u32 = 0x0003_0000;
const L2CAP_EXT_CTRL_SUPER_SHIFT: u32 = 16;
const L2CAP_EXT_CTRL_POLL: u32 = 0x0004_0000;
const L2CAP_EXT_CTRL_FINAL: u32 = 0x0000_0002;
const L2CAP_EXT_CTRL_TXSEQ_MASK: u32 = 0x0000_fffc;
const L2CAP_EXT_CTRL_TXSEQ_SHIFT: u32 = 2;
const L2CAP_EXT_CTRL_REQSEQ_MASK: u32 = 0xfffc_0000;
const L2CAP_EXT_CTRL_REQSEQ_SHIFT: u32 = 18;
const L2CAP_EXT_CTRL_SAR_MASK: u32 = 0x0003_0000;
const L2CAP_EXT_CTRL_SAR_SHIFT: u32 = 16;

const L2CAP_SAR_START: u8 = 0x01;

const L2CAP_CID_SIGNALING: u16 = 0x0001;
const L2CAP_CID_CONNLESS: u16 = 0x0002;
const L2CAP_CID_AMP: u16 = 0x0003;
const L2CAP_CID_ATT: u16 = 0x0004;
const L2CAP_CID_LE_SIGNALING: u16 = 0x0005;
const L2CAP_CID_SMP: u16 = 0x0006;
const L2CAP_CID_SMP_BREDR: u16 = 0x0007;

const MAX_CHAN: usize = 64;
const MAX_INDEX: usize = 16;

// ============================================================================
// Internal Structs
// ============================================================================

#[derive(Clone, Default)]
struct PacketLatency {
    count: u32,
    total: u64,
    min: u64,
    max: u64,
}

#[derive(Clone, Default)]
struct ChanData {
    index: u16,
    handle: u16,
    scid: u16,
    dcid: u16,
    psm: u16,
    _ctrlid: u16,
    mode: u8,
    ext_ctrl: u8,
    seq_num: u8,
    sdu: u16,
    tx_l: PacketLatency,
}

#[derive(Clone, Default)]
struct IndexData {
    frag_buf: Option<Vec<u8>>,
    frag_pos: usize,
    frag_len: usize,
    frag_cid: u16,
}

#[derive(Clone)]
struct FrameQueueEntry {
    frame: L2capFrame,
}

// ============================================================================
// Thread-local state
// ============================================================================

thread_local! {
    static CHAN_LIST: RefCell<Vec<ChanData>> =
        const { RefCell::new(Vec::new()) };
    static INDEX_LIST: RefCell<Vec<[IndexData; 2]>> =
        const { RefCell::new(Vec::new()) };
    static FRAME_QUEUE: RefCell<VecDeque<FrameQueueEntry>> =
        const { RefCell::new(VecDeque::new()) };
    static SEQ_NUM_MAP: RefCell<Vec<(u16, u16, u8)>> =
        const { RefCell::new(Vec::new()) };
}

// ============================================================================
// Lazy Initialization
// ============================================================================

/// Access CHAN_LIST with mutable borrow, ensuring it's initialized.
fn with_chan_list_mut<R>(f: impl FnOnce(&mut Vec<ChanData>) -> R) -> R {
    CHAN_LIST.with(|cl| {
        let mut list = cl.borrow_mut();
        if list.is_empty() {
            list.resize_with(MAX_CHAN, ChanData::default);
        }
        f(&mut list)
    })
}

/// Access CHAN_LIST with immutable borrow, ensuring it's initialized.
fn with_chan_list<R>(f: impl FnOnce(&Vec<ChanData>) -> R) -> R {
    CHAN_LIST.with(|cl| {
        let mut list = cl.borrow_mut();
        if list.is_empty() {
            list.resize_with(MAX_CHAN, ChanData::default);
        }
        f(&list)
    })
}

/// Access INDEX_LIST with mutable borrow, ensuring it's initialized.
fn with_index_list_mut<R>(f: impl FnOnce(&mut Vec<[IndexData; 2]>) -> R) -> R {
    INDEX_LIST.with(|il| {
        let mut list = il.borrow_mut();
        if list.is_empty() {
            list.resize_with(MAX_INDEX, || [IndexData::default(), IndexData::default()]);
        }
        f(&mut list)
    })
}

/// Access INDEX_LIST with immutable borrow, ensuring it's initialized.
/// Retained for API completeness even though currently unused.
fn _with_index_list<R>(f: impl FnOnce(&Vec<[IndexData; 2]>) -> R) -> R {
    INDEX_LIST.with(|il| {
        let mut list = il.borrow_mut();
        if list.is_empty() {
            list.resize_with(MAX_INDEX, || [IndexData::default(), IndexData::default()]);
        }
        f(&list)
    })
}

// ============================================================================
// Channel Management
// ============================================================================

fn assign_scid(index: u16, handle: u16, scid: u16, psm: u16, ctrlid: u16, mode: u8) {
    with_chan_list_mut(|list| {
        for e in list.iter_mut() {
            if e.scid == 0 && e.dcid == 0 {
                *e = ChanData {
                    index,
                    handle,
                    scid,
                    psm,
                    _ctrlid: ctrlid,
                    mode,
                    seq_num: get_next_seq_num(handle, psm),
                    ..ChanData::default()
                };
                return;
            }
        }
    });
}

fn release_scid(index: u16, handle: u16, scid: u16) {
    with_chan_list_mut(|list| {
        for e in list.iter_mut() {
            if e.index == index && e.handle == handle && e.scid == scid {
                *e = ChanData::default();
                return;
            }
        }
    });
}

fn assign_dcid(index: u16, handle: u16, dcid: u16, scid: u16) {
    with_chan_list_mut(|list| {
        for e in list.iter_mut() {
            if e.index == index && e.handle == handle && e.scid == scid {
                e.dcid = dcid;
                return;
            }
        }
    });
}

fn assign_mode(index: u16, handle: u16, mode: u8, dcid: u16) {
    with_chan_list_mut(|list| {
        for e in list.iter_mut() {
            if e.index == index && e.handle == handle && (e.scid == dcid || e.dcid == dcid) {
                e.mode = mode;
                return;
            }
        }
    });
}

fn assign_ext_ctrl(index: u16, handle: u16, ext_ctrl: u8, dcid: u16) {
    with_chan_list_mut(|list| {
        for e in list.iter_mut() {
            if e.index == index && e.handle == handle && (e.scid == dcid || e.dcid == dcid) {
                e.ext_ctrl = ext_ctrl;
                return;
            }
        }
    });
}

fn get_chan_data_index(index: u16, handle: u16, cid: u16) -> Option<usize> {
    with_chan_list(|list| {
        for (i, e) in list.iter().enumerate() {
            if e.index == index && e.handle == handle && (e.scid == cid || e.dcid == cid) {
                return Some(i);
            }
        }
        None
    })
}

fn get_psm(index: u16, handle: u16, cid: u16) -> u16 {
    with_chan_list(|list| {
        list.iter()
            .find(|e| e.index == index && e.handle == handle && (e.scid == cid || e.dcid == cid))
            .map_or(0, |e| e.psm)
    })
}

fn get_mode(index: u16, handle: u16, cid: u16) -> u8 {
    with_chan_list(|list| {
        list.iter()
            .find(|e| e.index == index && e.handle == handle && (e.scid == cid || e.dcid == cid))
            .map_or(0, |e| e.mode)
    })
}

fn get_seq_num(index: u16, handle: u16, cid: u16) -> u8 {
    with_chan_list(|list| {
        list.iter()
            .find(|e| e.index == index && e.handle == handle && (e.scid == cid || e.dcid == cid))
            .map_or(0, |e| e.seq_num)
    })
}

fn get_ext_ctrl(index: u16, handle: u16, cid: u16) -> u8 {
    with_chan_list(|list| {
        list.iter()
            .find(|e| e.index == index && e.handle == handle && (e.scid == cid || e.dcid == cid))
            .map_or(0, |e| e.ext_ctrl)
    })
}

fn get_next_seq_num(handle: u16, psm: u16) -> u8 {
    SEQ_NUM_MAP.with(|m| {
        let mut map = m.borrow_mut();
        for e in map.iter_mut() {
            if e.0 == handle && e.1 == psm {
                e.2 = e.2.wrapping_add(1);
                return e.2;
            }
        }
        map.push((handle, psm, 0));
        0
    })
}

fn clear_fragment_buffer(index: u16, in_: bool) {
    if (index as usize) >= MAX_INDEX {
        return;
    }
    with_index_list_mut(|list| {
        list[index as usize][usize::from(in_)] = IndexData::default();
    });
}

// ============================================================================
// String Helpers
// ============================================================================

fn sar2str(sar: u8) -> &'static str {
    match sar {
        0x00 => "Unsegmented",
        0x01 => "Start",
        0x02 => "End",
        0x03 => "Continuation",
        _ => "Bad SAR",
    }
}

fn supervisory2str(sup: u8) -> &'static str {
    match sup {
        0x00 => "RR (Receiver Ready)",
        0x01 => "REJ (Reject)",
        0x02 => "RNR (Receiver Not Ready)",
        0x03 => "SREJ (Selective Reject)",
        _ => "Bad Supervisory",
    }
}

fn mode2str(mode: u8) -> &'static str {
    match mode {
        L2CAP_MODE_BASIC => "Basic",
        L2CAP_MODE_RETRANS => "Retransmission",
        L2CAP_MODE_FLOWCTL => "Flow Control",
        L2CAP_MODE_ERTM => "Enhanced Retransmission",
        L2CAP_MODE_STREAMING => "Streaming",
        L2CAP_MODE_LE_FLOWCTL => "LE Flow Control",
        L2CAP_MODE_ECRED => "Enhanced Credit",
        _ => "Unknown",
    }
}

fn psm2str(psm: u16) -> &'static str {
    match psm {
        0x0001 => "SDP",
        0x0003 => "RFCOMM",
        0x0005 => "TCS-BIN",
        0x0007 => "TCS-BIN-CORDLESS",
        0x000f => "BNEP",
        0x0011 => "HID Control",
        0x0013 => "HID Interrupt",
        0x0015 => "UPnP",
        0x0017 => "AVCTP Control",
        0x0019 => "AVDTP",
        0x001b => "AVCTP Browsing",
        0x001d => "UDI C-Plane",
        0x001f => "ATT",
        0x0021 => "3DSP",
        0x0023 => "LE PSM IPSP",
        0x0025 => "OTS",
        0x0027 => "EATT",
        _ => "",
    }
}

// ============================================================================
// Print Helpers
// ============================================================================

fn print_psm(psm: u16) {
    let n = psm2str(psm);
    if n.is_empty() {
        print_field!("PSM: {} (0x{:04x})", psm, psm);
    } else {
        print_field!("PSM: {} (0x{:04x})", n, psm);
    }
}

fn print_cid(label: &str, cid: u16) {
    print_field!("{} CID: {}", label, cid);
}

fn print_reject_reason(reason: u16) {
    let s = match reason {
        0x0000 => "Command not understood",
        0x0001 => "Signaling MTU exceeded",
        0x0002 => "Invalid CID in request",
        _ => "Reserved",
    };
    print_field!("Reason: {} (0x{:04x})", s, reason);
}

fn print_conn_result(result: u16) {
    let s = match result {
        0x0000 => "Connection successful",
        0x0001 => "Connection pending",
        0x0002 => "Connection refused - PSM not supported",
        0x0003 => "Connection refused - security block",
        0x0004 => "Connection refused - no resources available",
        0x0006 => "Connection refused - invalid Source CID",
        0x0007 => "Connection refused - Source CID already allocated",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

fn print_le_conn_result(result: u16) {
    let s = match result {
        0x0000 => "Connection successful",
        0x0002 => "Connection refused - PSM not supported",
        0x0004 => "Connection refused - no resources",
        0x0005 => "Connection refused - insufficient authentication",
        0x0006 => "Connection refused - insufficient authorization",
        0x0007 => "Connection refused - insufficient encryption key size",
        0x0008 => "Connection refused - insufficient encryption",
        0x0009 => "Connection refused - invalid Source CID",
        0x000a => "Connection refused - Source CID already allocated",
        0x000b => "Connection refused - unacceptable parameters",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

fn print_create_chan_result(result: u16) {
    let s = match result {
        0x0000 => "Connection successful",
        0x0001 => "Connection pending",
        0x0002 => "Connection refused - PSM not supported",
        0x0003 => "Connection refused - security block",
        0x0004 => "Connection refused - no resources available",
        0x0005 => "Connection refused - Controller ID not supported",
        0x0006 => "Connection refused - invalid Source CID",
        0x0007 => "Connection refused - Source CID already allocated",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

fn print_conn_status(status: u16) {
    let s = match status {
        0x0000 => "No further information available",
        0x0001 => "Authentication pending",
        0x0002 => "Authorization pending",
        _ => "Reserved",
    };
    print_field!("Status: {} (0x{:04x})", s, status);
}

fn print_config_flags(flags: u16) {
    if (flags & 0x0001) != 0 {
        print_field!("Flags: 0x{:04x} (continuation)", flags);
    } else {
        print_field!("Flags: 0x{:04x}", flags);
    }
}

fn print_config_result(result: u16) {
    let s = match result {
        0x0000 => "Success",
        0x0001 => "Failure - unacceptable parameters",
        0x0002 => "Failure - rejected",
        0x0003 => "Failure - unknown options",
        0x0004 => "Pending",
        0x0005 => "Failure - flow spec rejected",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

fn print_config_options(frame: &mut L2capFrame, is_rsp: bool) {
    while frame.size >= 2 {
        let Some(opt_type) = frame.get_u8() else { return };
        let Some(opt_len) = frame.get_u8() else { return };
        let hint = (opt_type & 0x80) != 0;
        let rtype = opt_type & 0x7f;
        match rtype {
            0x01 => {
                if opt_len >= 2 {
                    if let Some(mtu) = frame.get_le16() {
                        print_field!("MTU: {}", mtu);
                    }
                } else {
                    frame.pull(opt_len as usize);
                }
            }
            0x02 => {
                if opt_len >= 2 {
                    if let Some(to) = frame.get_le16() {
                        print_field!("Flush Timeout: {}", to);
                    }
                } else {
                    frame.pull(opt_len as usize);
                }
            }
            0x03 => {
                if opt_len >= 22 {
                    let _f = frame.get_u8();
                    if let (Some(st), Some(tr), Some(tb), Some(pb), Some(lat), Some(dv)) = (
                        frame.get_u8(),
                        frame.get_le32(),
                        frame.get_le32(),
                        frame.get_le32(),
                        frame.get_le32(),
                        frame.get_le32(),
                    ) {
                        let sn = match st {
                            0 => "No Traffic",
                            1 => "Best Effort",
                            2 => "Guaranteed",
                            _ => "Reserved",
                        };
                        print_field!("QoS: {} (0x{:02x})", sn, st);
                        print_field!("  Token Rate: {}", tr);
                        print_field!("  Token Bucket Size: {}", tb);
                        print_field!("  Peak Bandwidth: {}", pb);
                        print_field!("  Latency: {}", lat);
                        print_field!("  Delay Variation: {}", dv);
                    }
                } else {
                    frame.pull(opt_len as usize);
                }
            }
            0x04 => {
                if opt_len >= 9 {
                    if let (Some(md), Some(tw), Some(mt), Some(rto), Some(mto), Some(mp)) = (
                        frame.get_u8(),
                        frame.get_u8(),
                        frame.get_u8(),
                        frame.get_le16(),
                        frame.get_le16(),
                        frame.get_le16(),
                    ) {
                        print_field!("Mode: {} (0x{:02x})", mode2str(md), md);
                        print_field!("  TX Window Size: {}", tw);
                        print_field!("  Max Transmit: {}", mt);
                        print_field!("  Retransmission Timeout: {}", rto);
                        print_field!("  Monitor Timeout: {}", mto);
                        print_field!("  Maximum PDU Size: {}", mp);
                        if is_rsp {
                            assign_mode(frame.index, frame.handle, md, frame.cid);
                        }
                    }
                } else {
                    frame.pull(opt_len as usize);
                }
            }
            0x05 => {
                if opt_len >= 1 {
                    if let Some(ft) = frame.get_u8() {
                        let sn = if ft == 0 { "No FCS" } else { "16-bit FCS" };
                        print_field!("FCS: {} (0x{:02x})", sn, ft);
                    }
                } else {
                    frame.pull(opt_len as usize);
                }
            }
            0x06 => {
                if opt_len >= 16 {
                    if let (Some(id), Some(st), Some(ss), Some(si), Some(al), Some(ft)) = (
                        frame.get_u8(),
                        frame.get_u8(),
                        frame.get_le16(),
                        frame.get_le32(),
                        frame.get_le32(),
                        frame.get_le32(),
                    ) {
                        let sn = match st {
                            0 => "No Traffic",
                            1 => "Best Effort",
                            2 => "Guaranteed",
                            _ => "Reserved",
                        };
                        print_field!("Extended Flow Spec: {} (0x{:02x})", sn, st);
                        print_field!("  Identifier: 0x{:02x}", id);
                        print_field!("  Max SDU Size: {}", ss);
                        print_field!("  SDU Inter-arrival Time: {}", si);
                        print_field!("  Access Latency: {}", al);
                        print_field!("  Flush Timeout: {}", ft);
                    }
                } else {
                    frame.pull(opt_len as usize);
                }
            }
            0x07 => {
                if opt_len >= 2 {
                    if let Some(ew) = frame.get_le16() {
                        print_field!("Extended Window Size: {}", ew);
                        if is_rsp {
                            assign_ext_ctrl(frame.index, frame.handle, 1, frame.cid);
                        }
                    }
                } else {
                    frame.pull(opt_len as usize);
                }
            }
            _ => {
                if hint {
                    print_field!("  Unknown option: 0x{:02x} (hint)", rtype);
                } else {
                    print_field!("  Unknown option: 0x{:02x}", rtype);
                }
                frame.pull(opt_len as usize);
            }
        }
    }
}

fn print_info_type(it: u16) {
    let s = match it {
        0x0001 => "Connectionless MTU",
        0x0002 => "Extended features supported",
        0x0003 => "Fixed channels supported",
        _ => "Reserved",
    };
    print_field!("Type: {} (0x{:04x})", s, it);
}

fn print_info_result(result: u16) {
    let s = match result {
        0x0000 => "Success",
        0x0001 => "Not supported",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

fn print_features(features: u32) {
    use crate::display::BitfieldData;
    let table: &[BitfieldData] = &[
        BitfieldData { bit: 0x0001, str_val: "Flow control mode" },
        BitfieldData { bit: 0x0002, str_val: "Retransmission mode" },
        BitfieldData { bit: 0x0004, str_val: "Bi-directional QoS" },
        BitfieldData { bit: 0x0008, str_val: "Enhanced Retransmission Mode" },
        BitfieldData { bit: 0x0010, str_val: "Streaming Mode" },
        BitfieldData { bit: 0x0020, str_val: "FCS Option" },
        BitfieldData { bit: 0x0040, str_val: "Extended Flow Specification for BR/EDR" },
        BitfieldData { bit: 0x0080, str_val: "Fixed Channels" },
        BitfieldData { bit: 0x0100, str_val: "Extended Window Size" },
        BitfieldData { bit: 0x0200, str_val: "Unicast Connectionless Data Reception" },
        BitfieldData { bit: 0x0400, str_val: "Enhanced Credit Based Flow Control Mode" },
    ];
    print_field!("Features: 0x{:08x}", features);
    crate::display::print_bitfield(10, u64::from(features), table);
}

fn print_channels(channels: u64) {
    use crate::display::BitfieldData;
    let table: &[BitfieldData] = &[
        BitfieldData { bit: 0x0002, str_val: "L2CAP Signaling (BR/EDR)" },
        BitfieldData { bit: 0x0004, str_val: "Connectionless reception" },
        BitfieldData { bit: 0x0008, str_val: "AMP Manager Protocol" },
        BitfieldData { bit: 0x0010, str_val: "Attribute Protocol" },
        BitfieldData { bit: 0x0020, str_val: "L2CAP Signaling (LE)" },
        BitfieldData { bit: 0x0040, str_val: "Security Manager Protocol" },
        BitfieldData { bit: 0x0080, str_val: "Security Manager (BR/EDR)" },
        BitfieldData { bit: 0x0100, str_val: "AMP Test Manager" },
    ];
    print_field!("Channels: 0x{:016x}", channels);
    crate::display::print_bitfield(10, channels, table);
}

fn print_move_result(result: u16) {
    let s = match result {
        0x0000 => "Move success",
        0x0001 => "Move pending",
        0x0002 => "Move refused - Controller ID not supported",
        0x0003 => "Move refused - same Controller ID",
        0x0004 => "Move refused - Configuration not supported",
        0x0005 => "Move refused - Move Channel collision",
        0x0006 => "Move refused - Channel not allowed to be moved",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

fn print_move_cfm_result(result: u16) {
    let s = match result {
        0x0000 => "Move confirmed - success",
        0x0001 => "Move confirmed - refused",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

fn print_conn_param_result(result: u16) {
    let s = match result {
        0x0000 => "Connection Parameters accepted",
        0x0001 => "Connection Parameters rejected",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:04x})", s, result);
}

// ============================================================================
// Control Field Parsing
// ============================================================================

fn l2cap_ctrl_ext_parse(frame: &L2capFrame, ctrl: u32) {
    if (ctrl & L2CAP_EXT_CTRL_FRAME_TYPE) != 0 {
        let sup = ((ctrl & L2CAP_EXT_CTRL_SUPERVISE_MASK) >> L2CAP_EXT_CTRL_SUPER_SHIFT) as u8;
        let p = u32::from((ctrl & L2CAP_EXT_CTRL_POLL) != 0);
        let f = u32::from((ctrl & L2CAP_EXT_CTRL_FINAL) != 0);
        let rq = (ctrl & L2CAP_EXT_CTRL_REQSEQ_MASK) >> L2CAP_EXT_CTRL_REQSEQ_SHIFT;
        print_field!("Frame Type: Supervisory (S-frame)");
        print_field!("Supervisory: {} (0x{:02x})", supervisory2str(sup), sup);
        print_field!("P-bit: {}", p);
        print_field!("F-bit: {}", f);
        print_field!("ReqSeq: {}", rq);
    } else {
        let tx = (ctrl & L2CAP_EXT_CTRL_TXSEQ_MASK) >> L2CAP_EXT_CTRL_TXSEQ_SHIFT;
        let f = u32::from((ctrl & L2CAP_EXT_CTRL_FINAL) != 0);
        let rq = (ctrl & L2CAP_EXT_CTRL_REQSEQ_MASK) >> L2CAP_EXT_CTRL_REQSEQ_SHIFT;
        let sar = ((ctrl & L2CAP_EXT_CTRL_SAR_MASK) >> L2CAP_EXT_CTRL_SAR_SHIFT) as u8;
        print_field!("Frame Type: Information (I-frame)");
        print_field!("TxSeq: {}", tx);
        print_field!("F-bit: {}", f);
        print_field!("ReqSeq: {}", rq);
        print_field!("SAR: {} (0x{:02x})", sar2str(sar), sar);
        if sar == L2CAP_SAR_START {
            let d = frame.remaining_data();
            if d.len() >= 2 {
                let sdu = u16::from_le_bytes([d[0], d[1]]);
                print_field!("SDU Length: {}", sdu);
            }
        }
    }
}

fn l2cap_ctrl_parse(frame: &L2capFrame, ctrl: u16) {
    if (ctrl & L2CAP_CTRL_FRAME_TYPE) != 0 {
        let sup = ((ctrl & L2CAP_CTRL_SUPERVISE_MASK) >> L2CAP_CTRL_SUPER_SHIFT) as u8;
        let p = u16::from((ctrl & L2CAP_CTRL_POLL) != 0);
        let f = u16::from((ctrl & L2CAP_CTRL_FINAL) != 0);
        let rq = (ctrl & L2CAP_CTRL_REQSEQ_MASK) >> L2CAP_CTRL_REQSEQ_SHIFT;
        print_field!("Frame Type: Supervisory (S-frame)");
        print_field!("Supervisory: {} (0x{:02x})", supervisory2str(sup), sup);
        print_field!("P-bit: {}", p);
        print_field!("F-bit: {}", f);
        print_field!("ReqSeq: {}", rq);
    } else {
        let tx = (ctrl & L2CAP_CTRL_TXSEQ_MASK) >> L2CAP_CTRL_TXSEQ_SHIFT;
        let f = u16::from((ctrl & L2CAP_CTRL_FINAL) != 0);
        let rq = (ctrl & L2CAP_CTRL_REQSEQ_MASK) >> L2CAP_CTRL_REQSEQ_SHIFT;
        let sar = ((ctrl & L2CAP_CTRL_SAR_MASK) >> L2CAP_CTRL_SAR_SHIFT) as u8;
        print_field!("Frame Type: Information (I-frame)");
        print_field!("TxSeq: {}", tx);
        print_field!("F-bit: {}", f);
        print_field!("ReqSeq: {}", rq);
        print_field!("SAR: {} (0x{:02x})", sar2str(sar), sar);
        if sar == L2CAP_SAR_START {
            let d = frame.remaining_data();
            if d.len() >= 2 {
                let sdu = u16::from_le_bytes([d[0], d[1]]);
                print_field!("SDU Length: {}", sdu);
            }
        }
    }
}

// ============================================================================
// BR/EDR Signaling Command Handlers
// ============================================================================

struct SigOpcode {
    code: u8,
    name: &'static str,
    handler: fn(&mut L2capFrame),
}

static BREDR_SIG_TABLE: &[SigOpcode] = &[
    SigOpcode { code: 0x01, name: "Command Reject", handler: sig_cmd_reject },
    SigOpcode { code: 0x02, name: "Connection Request", handler: sig_conn_req },
    SigOpcode { code: 0x03, name: "Connection Response", handler: sig_conn_rsp },
    SigOpcode { code: 0x04, name: "Configure Request", handler: sig_config_req },
    SigOpcode { code: 0x05, name: "Configure Response", handler: sig_config_rsp },
    SigOpcode { code: 0x06, name: "Disconnection Request", handler: sig_disconn_req },
    SigOpcode { code: 0x07, name: "Disconnection Response", handler: sig_disconn_rsp },
    SigOpcode { code: 0x08, name: "Echo Request", handler: sig_echo },
    SigOpcode { code: 0x09, name: "Echo Response", handler: sig_echo },
    SigOpcode { code: 0x0a, name: "Information Request", handler: sig_info_req },
    SigOpcode { code: 0x0b, name: "Information Response", handler: sig_info_rsp },
    SigOpcode { code: 0x0c, name: "Create Channel Request", handler: sig_create_chan_req },
    SigOpcode { code: 0x0d, name: "Create Channel Response", handler: sig_create_chan_rsp },
    SigOpcode { code: 0x0e, name: "Move Channel Request", handler: sig_move_chan_req },
    SigOpcode { code: 0x0f, name: "Move Channel Response", handler: sig_move_chan_rsp },
    SigOpcode { code: 0x10, name: "Move Channel Confirmation", handler: sig_move_chan_cfm },
    SigOpcode {
        code: 0x11,
        name: "Move Channel Confirmation Response",
        handler: sig_move_chan_cfm_rsp,
    },
    SigOpcode {
        code: 0x17,
        name: "Enhanced Credit Connection Request",
        handler: sig_ecred_conn_req,
    },
    SigOpcode {
        code: 0x18,
        name: "Enhanced Credit Connection Response",
        handler: sig_ecred_conn_rsp,
    },
    SigOpcode {
        code: 0x19,
        name: "Enhanced Credit Reconfigure Request",
        handler: sig_ecred_reconf_req,
    },
    SigOpcode {
        code: 0x1a,
        name: "Enhanced Credit Reconfigure Response",
        handler: sig_ecred_reconf_rsp,
    },
];

static LE_SIG_TABLE: &[SigOpcode] = &[
    SigOpcode { code: 0x01, name: "Command Reject", handler: sig_cmd_reject },
    SigOpcode { code: 0x06, name: "Disconnection Request", handler: sig_disconn_req },
    SigOpcode { code: 0x07, name: "Disconnection Response", handler: sig_disconn_rsp },
    SigOpcode {
        code: 0x12,
        name: "Connection Parameter Update Request",
        handler: sig_conn_param_req,
    },
    SigOpcode {
        code: 0x13,
        name: "Connection Parameter Update Response",
        handler: sig_conn_param_rsp,
    },
    SigOpcode { code: 0x14, name: "LE Connection Request", handler: sig_le_conn_req },
    SigOpcode { code: 0x15, name: "LE Connection Response", handler: sig_le_conn_rsp },
    SigOpcode { code: 0x16, name: "LE Flow Control Credit", handler: sig_le_flowctl_creds },
    SigOpcode {
        code: 0x17,
        name: "Enhanced Credit Connection Request",
        handler: sig_ecred_conn_req,
    },
    SigOpcode {
        code: 0x18,
        name: "Enhanced Credit Connection Response",
        handler: sig_ecred_conn_rsp,
    },
    SigOpcode {
        code: 0x19,
        name: "Enhanced Credit Reconfigure Request",
        handler: sig_ecred_reconf_req,
    },
    SigOpcode {
        code: 0x1a,
        name: "Enhanced Credit Reconfigure Response",
        handler: sig_ecred_reconf_rsp,
    },
];

fn sig_cmd_reject(frame: &mut L2capFrame) {
    let Some(reason) = frame.get_le16() else { return };
    print_reject_reason(reason);
    if reason == 0x0002 && frame.size >= 4 {
        if let (Some(s), Some(d)) = (frame.get_le16(), frame.get_le16()) {
            print_cid("Source", s);
            print_cid("Destination", d);
        }
    } else if reason == 0x0001 && frame.size >= 2 {
        if let Some(mtu) = frame.get_le16() {
            print_field!("MTU: {}", mtu);
        }
    }
}

fn sig_conn_req(frame: &mut L2capFrame) {
    let (Some(psm), Some(scid)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_psm(psm);
    print_cid("Source", scid);
    assign_scid(frame.index, frame.handle, scid, psm, 0, L2CAP_MODE_BASIC);
}

fn sig_conn_rsp(frame: &mut L2capFrame) {
    let (Some(dcid), Some(scid), Some(result), Some(status)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_cid("Destination", dcid);
    print_cid("Source", scid);
    print_conn_result(result);
    print_conn_status(status);
    if result == 0x0000 {
        assign_dcid(frame.index, frame.handle, dcid, scid);
    }
}

fn sig_config_req(frame: &mut L2capFrame) {
    let (Some(dcid), Some(flags)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_cid("Destination", dcid);
    print_config_flags(flags);
    print_config_options(frame, false);
}

fn sig_config_rsp(frame: &mut L2capFrame) {
    let (Some(scid), Some(flags), Some(result)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_cid("Source", scid);
    print_config_flags(flags);
    print_config_result(result);
    print_config_options(frame, true);
}

fn sig_disconn_req(frame: &mut L2capFrame) {
    let (Some(dcid), Some(scid)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_cid("Destination", dcid);
    print_cid("Source", scid);
}

fn sig_disconn_rsp(frame: &mut L2capFrame) {
    let (Some(dcid), Some(scid)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_cid("Destination", dcid);
    print_cid("Source", scid);
    release_scid(frame.index, frame.handle, scid);
}

fn sig_echo(frame: &mut L2capFrame) {
    if frame.size > 0 {
        crate::display::print_hex_field("Data", frame.remaining_data());
    }
}

fn sig_info_req(frame: &mut L2capFrame) {
    let Some(it) = frame.get_le16() else { return };
    print_info_type(it);
}

fn sig_info_rsp(frame: &mut L2capFrame) {
    let (Some(it), Some(result)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_info_type(it);
    print_info_result(result);
    if result != 0x0000 {
        return;
    }
    match it {
        0x0001 => {
            if let Some(mtu) = frame.get_le16() {
                print_field!("MTU: {}", mtu);
            }
        }
        0x0002 => {
            if let Some(f) = frame.get_le32() {
                print_features(f);
            }
        }
        0x0003 => {
            if let Some(c) = frame.get_le64() {
                print_channels(c);
            }
        }
        _ => {}
    }
}

fn sig_create_chan_req(frame: &mut L2capFrame) {
    let (Some(psm), Some(scid), Some(ci)) = (frame.get_le16(), frame.get_le16(), frame.get_u8())
    else {
        return;
    };
    print_psm(psm);
    print_cid("Source", scid);
    print_field!("Controller ID: {}", ci);
    assign_scid(frame.index, frame.handle, scid, psm, u16::from(ci), L2CAP_MODE_BASIC);
}

fn sig_create_chan_rsp(frame: &mut L2capFrame) {
    let (Some(dcid), Some(scid), Some(result), Some(status)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_cid("Destination", dcid);
    print_cid("Source", scid);
    print_create_chan_result(result);
    print_conn_status(status);
    if result == 0x0000 {
        assign_dcid(frame.index, frame.handle, dcid, scid);
    }
}

fn sig_move_chan_req(frame: &mut L2capFrame) {
    let (Some(icid), Some(ci)) = (frame.get_le16(), frame.get_u8()) else { return };
    print_cid("Initiator", icid);
    print_field!("Controller ID: {}", ci);
}

fn sig_move_chan_rsp(frame: &mut L2capFrame) {
    let (Some(icid), Some(result)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_cid("Initiator", icid);
    print_move_result(result);
}

fn sig_move_chan_cfm(frame: &mut L2capFrame) {
    let (Some(icid), Some(result)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_cid("Initiator", icid);
    print_move_cfm_result(result);
}

fn sig_move_chan_cfm_rsp(frame: &mut L2capFrame) {
    let Some(icid) = frame.get_le16() else { return };
    print_cid("Initiator", icid);
}

fn sig_conn_param_req(frame: &mut L2capFrame) {
    let (Some(mn), Some(mx), Some(lat), Some(to)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_field!("Min interval: {}", mn);
    print_field!("Max interval: {}", mx);
    print_field!("Peripheral latency: {}", lat);
    print_field!("Timeout multiplier: {}", to);
}

fn sig_conn_param_rsp(frame: &mut L2capFrame) {
    let Some(result) = frame.get_le16() else { return };
    print_conn_param_result(result);
}

fn sig_le_conn_req(frame: &mut L2capFrame) {
    let (Some(psm), Some(scid), Some(mtu), Some(mps), Some(credits)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_psm(psm);
    print_cid("Source", scid);
    print_field!("MTU: {}", mtu);
    print_field!("MPS: {}", mps);
    print_field!("Credits: {}", credits);
    assign_scid(frame.index, frame.handle, scid, psm, 0, L2CAP_MODE_LE_FLOWCTL);
}

fn sig_le_conn_rsp(frame: &mut L2capFrame) {
    let (Some(dcid), Some(mtu), Some(mps), Some(credits), Some(result)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_cid("Destination", dcid);
    print_field!("MTU: {}", mtu);
    print_field!("MPS: {}", mps);
    print_field!("Credits: {}", credits);
    print_le_conn_result(result);
}

fn sig_le_flowctl_creds(frame: &mut L2capFrame) {
    let (Some(cid), Some(credits)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_cid("CID", cid);
    print_field!("Credits: {}", credits);
}

fn sig_ecred_conn_req(frame: &mut L2capFrame) {
    let (Some(psm), Some(mtu), Some(mps), Some(credits)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_psm(psm);
    print_field!("MTU: {}", mtu);
    print_field!("MPS: {}", mps);
    print_field!("Credits: {}", credits);
    while frame.size >= 2 {
        let Some(scid) = frame.get_le16() else { break };
        print_cid("Source", scid);
        assign_scid(frame.index, frame.handle, scid, psm, 0, L2CAP_MODE_ECRED);
    }
}

fn sig_ecred_conn_rsp(frame: &mut L2capFrame) {
    let (Some(mtu), Some(mps), Some(credits), Some(result)) =
        (frame.get_le16(), frame.get_le16(), frame.get_le16(), frame.get_le16())
    else {
        return;
    };
    print_field!("MTU: {}", mtu);
    print_field!("MPS: {}", mps);
    print_field!("Credits: {}", credits);
    print_le_conn_result(result);
    while frame.size >= 2 {
        let Some(dcid) = frame.get_le16() else { break };
        print_cid("Destination", dcid);
    }
}

fn sig_ecred_reconf_req(frame: &mut L2capFrame) {
    let (Some(mtu), Some(mps)) = (frame.get_le16(), frame.get_le16()) else { return };
    print_field!("MTU: {}", mtu);
    print_field!("MPS: {}", mps);
    while frame.size >= 2 {
        let Some(scid) = frame.get_le16() else { break };
        print_cid("Source", scid);
    }
}

fn sig_ecred_reconf_rsp(frame: &mut L2capFrame) {
    let Some(result) = frame.get_le16() else { return };
    print_field!("Result: 0x{:04x}", result);
}

// ============================================================================
// Signaling Dispatch
// ============================================================================

fn bredr_sig_packet(index: u16, in_: bool, handle: u16, cid: u16, data: &[u8], size: u16) {
    let mut off: usize = 0;
    let len = size as usize;
    while off + 4 <= len {
        let code = data[off];
        let ident = data[off + 1];
        let slen = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
        off += 4;
        let color = if in_ { crate::display::COLOR_MAGENTA } else { crate::display::COLOR_BLUE };
        let entry = BREDR_SIG_TABLE.iter().find(|e| e.code == code);
        if let Some(e) = entry {
            print_indent!(
                6,
                color,
                "L2CAP: ",
                e.name,
                crate::display::COLOR_OFF,
                " (0x{:02x}) ident {} len {}",
                code,
                ident,
                slen
            );
        } else {
            print_indent!(
                6,
                crate::display::COLOR_WHITE_BG,
                "L2CAP: ",
                "Unknown",
                crate::display::COLOR_OFF,
                " (0x{:02x}) ident {} len {}",
                code,
                ident,
                slen
            );
        }
        let pend = (off + slen).min(len);
        let payload = &data[off..pend];
        let mut frame = L2capFrame::new(payload.to_vec(), payload.len() as u16);
        frame.index = index;
        frame.in_ = in_;
        frame.handle = handle;
        frame.ident = ident;
        frame.cid = cid;
        if let Some(e) = entry {
            (e.handler)(&mut frame);
        }
        off = pend;
    }
}

fn le_sig_packet(index: u16, in_: bool, handle: u16, cid: u16, data: &[u8], size: u16) {
    if (size as usize) < 4 {
        print_text!(crate::display::COLOR_ERROR, "  Malformed LE Signaling packet");
        return;
    }
    let code = data[0];
    let ident = data[1];
    let slen = u16::from_le_bytes([data[2], data[3]]) as usize;
    let color = if in_ { crate::display::COLOR_MAGENTA } else { crate::display::COLOR_BLUE };
    let entry = LE_SIG_TABLE.iter().find(|e| e.code == code);
    if let Some(e) = entry {
        print_indent!(
            6,
            color,
            "LE L2CAP: ",
            e.name,
            crate::display::COLOR_OFF,
            " (0x{:02x}) ident {} len {}",
            code,
            ident,
            slen
        );
    } else {
        print_indent!(
            6,
            crate::display::COLOR_WHITE_BG,
            "LE L2CAP: ",
            "Unknown",
            crate::display::COLOR_OFF,
            " (0x{:02x}) ident {} len {}",
            code,
            ident,
            slen
        );
    }
    let pend = (4 + slen).min(size as usize);
    let payload = &data[4..pend];
    let mut frame = L2capFrame::new(payload.to_vec(), payload.len() as u16);
    frame.index = index;
    frame.in_ = in_;
    frame.handle = handle;
    frame.ident = ident;
    frame.cid = cid;
    if let Some(e) = entry {
        (e.handler)(&mut frame);
    }
}

// ============================================================================
// SMP Packet Handler
// ============================================================================

struct SmpOpcode {
    code: u8,
    name: &'static str,
    handler: fn(&mut L2capFrame),
}

static SMP_TABLE: &[SmpOpcode] = &[
    SmpOpcode { code: 0x01, name: "Pairing Request", handler: smp_pairing },
    SmpOpcode { code: 0x02, name: "Pairing Response", handler: smp_pairing },
    SmpOpcode { code: 0x03, name: "Pairing Confirm", handler: smp_confirm },
    SmpOpcode { code: 0x04, name: "Pairing Random", handler: smp_random },
    SmpOpcode { code: 0x05, name: "Pairing Failed", handler: smp_failed },
    SmpOpcode { code: 0x06, name: "Encryption Information", handler: smp_encrypt },
    SmpOpcode { code: 0x07, name: "Central Identification", handler: smp_central_id },
    SmpOpcode { code: 0x08, name: "Identity Information", handler: smp_ident_info },
    SmpOpcode { code: 0x09, name: "Identity Address Information", handler: smp_ident_addr },
    SmpOpcode { code: 0x0a, name: "Signing Information", handler: smp_signing },
    SmpOpcode { code: 0x0b, name: "Security Request", handler: smp_security_req },
    SmpOpcode { code: 0x0c, name: "Pairing Public Key", handler: smp_public_key },
    SmpOpcode { code: 0x0d, name: "Pairing DHKey Check", handler: smp_dhkey_check },
    SmpOpcode { code: 0x0e, name: "Pairing Keypress Notification", handler: smp_keypress },
];

fn print_smp_auth_req(auth: u8) {
    let bonding = if (auth & 0x03) != 0 { "Bonding" } else { "No Bonding" };
    let mitm = if (auth & 0x04) != 0 { ", MITM" } else { "" };
    let sc = if (auth & 0x08) != 0 { ", Secure Connections" } else { "" };
    let kp = if (auth & 0x10) != 0 { ", Keypress" } else { "" };
    let ct = if (auth & 0x20) != 0 { ", CT2" } else { "" };
    print_field!("Auth Req: {}{}{}{}{} (0x{:02x})", bonding, mitm, sc, kp, ct, auth);
}

fn print_smp_key_dist(label: &str, dist: u8) {
    let enc = if (dist & 0x01) != 0 { "EncKey " } else { "" };
    let id = if (dist & 0x02) != 0 { "IdKey " } else { "" };
    let sign = if (dist & 0x04) != 0 { "Sign " } else { "" };
    let link = if (dist & 0x08) != 0 { "LinkKey " } else { "" };
    print_field!("{}: {}{}{}{} (0x{:02x})", label, enc, id, sign, link, dist);
}

fn smp_pairing(frame: &mut L2capFrame) {
    let (Some(io), Some(oob), Some(auth), Some(ks), Some(ik), Some(rk)) = (
        frame.get_u8(),
        frame.get_u8(),
        frame.get_u8(),
        frame.get_u8(),
        frame.get_u8(),
        frame.get_u8(),
    ) else {
        return;
    };
    let io_str = match io {
        0 => "DisplayOnly",
        1 => "DisplayYesNo",
        2 => "KeyboardOnly",
        3 => "NoInputNoOutput",
        4 => "KeyboardDisplay",
        _ => "Reserved",
    };
    let oob_str = match oob {
        0 => "Authentication data not present",
        1 => "Authentication data from remote device present",
        _ => "Reserved",
    };
    print_field!("IO Capability: {} (0x{:02x})", io_str, io);
    print_field!("OOB Data: {} (0x{:02x})", oob_str, oob);
    print_smp_auth_req(auth);
    print_field!("Max Encryption Key Size: {}", ks);
    print_smp_key_dist("Initiator Key Distribution", ik);
    print_smp_key_dist("Responder Key Distribution", rk);
}

fn smp_confirm(frame: &mut L2capFrame) {
    if frame.size >= 16 {
        let d = frame.remaining_data()[..16].to_vec();
        crate::display::print_hex_field("Confirm Value", &d);
        frame.pull(16);
    }
}

fn smp_random(frame: &mut L2capFrame) {
    if frame.size >= 16 {
        let d = frame.remaining_data()[..16].to_vec();
        crate::display::print_hex_field("Random Value", &d);
        frame.pull(16);
    }
}

fn smp_failed(frame: &mut L2capFrame) {
    let Some(r) = frame.get_u8() else { return };
    let s = match r {
        0x01 => "Passkey Entry Failed",
        0x02 => "OOB Not Available",
        0x03 => "Authentication Requirements",
        0x04 => "Confirm Value Failed",
        0x05 => "Pairing Not Supported",
        0x06 => "Encryption Key Size",
        0x07 => "Command Not Supported",
        0x08 => "Unspecified Reason",
        0x09 => "Repeated Attempts",
        0x0a => "Invalid Parameters",
        0x0b => "DHKey Check Failed",
        0x0c => "Numeric Comparison Failed",
        0x0d => "BR/EDR pairing in progress",
        0x0e => "Cross-transport Key Derivation/Generation not allowed",
        _ => "Reserved",
    };
    print_field!("Reason: {} (0x{:02x})", s, r);
}

fn smp_encrypt(frame: &mut L2capFrame) {
    if frame.size >= 16 {
        let d = frame.remaining_data()[..16].to_vec();
        crate::display::print_hex_field("Long Term Key", &d);
        frame.pull(16);
    }
}

fn smp_central_id(frame: &mut L2capFrame) {
    let (Some(ediv), Some(rand)) = (frame.get_le16(), frame.get_le64()) else { return };
    print_field!("EDIV: 0x{:04x}", ediv);
    print_field!("Rand: 0x{:016x}", rand);
}

fn smp_ident_info(frame: &mut L2capFrame) {
    if frame.size >= 16 {
        let d = frame.remaining_data()[..16].to_vec();
        crate::display::print_hex_field("Identity Resolving Key", &d);
        let mut key = [0u8; 16];
        key.copy_from_slice(&d);
        crate::keys::keys_update_identity_key(&key);
        frame.pull(16);
    }
}

fn smp_ident_addr(frame: &mut L2capFrame) {
    let Some(at) = frame.get_u8() else { return };
    let ts = if at == 0 { "Public" } else { "Random" };
    print_field!("Address Type: {} (0x{:02x})", ts, at);
    if frame.size >= 6 {
        let d = frame.remaining_data();
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&d[..6]);
        print_field!(
            "Address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            addr[5],
            addr[4],
            addr[3],
            addr[2],
            addr[1],
            addr[0]
        );
        crate::keys::keys_update_identity_addr(&addr, at);
        frame.pull(6);
    }
}

fn smp_signing(frame: &mut L2capFrame) {
    if frame.size >= 16 {
        let d = frame.remaining_data()[..16].to_vec();
        crate::display::print_hex_field("Signature Key", &d);
        frame.pull(16);
    }
}

fn smp_security_req(frame: &mut L2capFrame) {
    let Some(auth) = frame.get_u8() else { return };
    print_smp_auth_req(auth);
}

fn smp_public_key(frame: &mut L2capFrame) {
    if frame.size >= 64 {
        let d = frame.remaining_data();
        crate::display::print_hex_field("Public Key X", &d[..32]);
        crate::display::print_hex_field("Public Key Y", &d[32..64]);
        frame.pull(64);
    }
}

fn smp_dhkey_check(frame: &mut L2capFrame) {
    if frame.size >= 16 {
        let d = frame.remaining_data()[..16].to_vec();
        crate::display::print_hex_field("DHKey Check", &d);
        frame.pull(16);
    }
}

fn smp_keypress(frame: &mut L2capFrame) {
    let Some(nt) = frame.get_u8() else { return };
    let s = match nt {
        0 => "Passkey entry started",
        1 => "Passkey digit entered",
        2 => "Passkey digit erased",
        3 => "Passkey cleared",
        4 => "Passkey entry completed",
        _ => "Reserved",
    };
    print_field!("Notification Type: {} (0x{:02x})", s, nt);
}

fn smp_packet(index: u16, in_: bool, handle: u16, cid: u16, data: &[u8], size: u16) {
    if (size as usize) < 1 {
        print_text!(crate::display::COLOR_ERROR, "  Malformed SMP packet");
        return;
    }
    let code = data[0];
    let color = if in_ { crate::display::COLOR_MAGENTA } else { crate::display::COLOR_BLUE };
    let pfx = if cid == L2CAP_CID_SMP_BREDR { "BR/EDR SMP: " } else { "SMP: " };
    let entry = SMP_TABLE.iter().find(|e| e.code == code);
    if let Some(e) = entry {
        print_indent!(
            6,
            color,
            pfx,
            e.name,
            crate::display::COLOR_OFF,
            " (0x{:02x}) len {}",
            code,
            size.saturating_sub(1)
        );
    } else {
        print_indent!(
            6,
            crate::display::COLOR_WHITE_BG,
            pfx,
            "Unknown",
            crate::display::COLOR_OFF,
            " (0x{:02x}) len {}",
            code,
            size.saturating_sub(1)
        );
    }
    let payload = &data[1..size as usize];
    let mut frame = L2capFrame::new(payload.to_vec(), payload.len() as u16);
    frame.index = index;
    frame.in_ = in_;
    frame.handle = handle;
    frame.cid = cid;
    if let Some(e) = entry {
        (e.handler)(&mut frame);
    }
}

// ============================================================================
// Connectionless and AMP Handlers
// ============================================================================

fn connless_packet(_index: u16, in_: bool, _handle: u16, _cid: u16, data: &[u8], size: u16) {
    if (size as usize) < 2 {
        print_text!(crate::display::COLOR_ERROR, "  Malformed Connectionless packet");
        return;
    }
    let psm = u16::from_le_bytes([data[0], data[1]]);
    let color = if in_ { crate::display::COLOR_MAGENTA } else { crate::display::COLOR_BLUE };
    print_indent!(
        6,
        color,
        "L2CAP: ",
        "Connectionless",
        crate::display::COLOR_OFF,
        " len {}",
        size
    );
    print_psm(psm);
    if size > 2 {
        crate::display::print_hex_field("Payload", &data[2..size as usize]);
    }
}

fn amp_packet(_index: u16, in_: bool, _handle: u16, _cid: u16, data: &[u8], size: u16) {
    if (size as usize) < 4 {
        print_text!(crate::display::COLOR_ERROR, "  Malformed AMP packet");
        return;
    }
    let code = data[0];
    let ident = data[1];
    let alen = u16::from_le_bytes([data[2], data[3]]);
    let color = if in_ { crate::display::COLOR_MAGENTA } else { crate::display::COLOR_BLUE };
    let amp_names: &[(u8, &str)] = &[
        (0x01, "Command Reject"),
        (0x02, "Discover Request"),
        (0x03, "Discover Response"),
        (0x04, "Change Notify"),
        (0x05, "Change Response"),
        (0x06, "Get Info Request"),
        (0x07, "Get Info Response"),
        (0x08, "Get Assoc Request"),
        (0x09, "Get Assoc Response"),
        (0x0a, "Create Physical Link Request"),
        (0x0b, "Create Physical Link Response"),
        (0x0c, "Disconnect Physical Link Request"),
        (0x0d, "Disconnect Physical Link Response"),
    ];
    let name = amp_names.iter().find(|n| n.0 == code).map_or("Unknown", |n| n.1);
    if name != "Unknown" {
        print_indent!(
            6,
            color,
            "AMP: ",
            name,
            crate::display::COLOR_OFF,
            " (0x{:02x}) ident {} len {}",
            code,
            ident,
            alen
        );
    } else {
        print_indent!(
            6,
            crate::display::COLOR_WHITE_BG,
            "AMP: ",
            name,
            crate::display::COLOR_OFF,
            " (0x{:02x}) ident {} len {}",
            code,
            ident,
            alen
        );
    }
    let pe = (4 + alen as usize).min(size as usize);
    let payload = &data[4..pe];
    let mut frame = L2capFrame::new(payload.to_vec(), payload.len() as u16);
    frame.in_ = in_;
    match code {
        0x01 => {
            if let Some(r) = frame.get_le16() {
                print_field!("Reason: 0x{:04x}", r);
            }
        }
        0x02 | 0x03 => {
            if let (Some(mtu), Some(mask)) = (frame.get_le16(), frame.get_le16()) {
                print_field!("MTU/MPS: {}", mtu);
                print_field!("Controller list mask: 0x{:04x}", mask);
                while frame.size >= 3 {
                    if let (Some(ci), Some(ct), Some(cs)) =
                        (frame.get_u8(), frame.get_u8(), frame.get_u8())
                    {
                        print_field!("  Controller: id {} type {} status {}", ci, ct, cs);
                    } else {
                        break;
                    }
                }
            }
        }
        0x06 | 0x08 => {
            if let Some(ci) = frame.get_u8() {
                print_field!("Controller ID: {}", ci);
            }
        }
        0x07 => {
            if let (Some(ci), Some(st)) = (frame.get_u8(), frame.get_u8()) {
                print_field!("Controller ID: {}", ci);
                print_field!("Status: 0x{:02x}", st);
                if let Some(tb) = frame.get_le32() {
                    print_field!("Total Bandwidth: {}", tb);
                }
                if let Some(mb) = frame.get_le32() {
                    print_field!("Max Guaranteed Bandwidth: {}", mb);
                }
                if let Some(ml) = frame.get_le32() {
                    print_field!("Min Latency: {}", ml);
                }
                if let Some(pc) = frame.get_le16() {
                    print_field!("PAL Capabilities: 0x{:04x}", pc);
                }
                if let Some(mp) = frame.get_le16() {
                    print_field!("Max Assoc Length: {}", mp);
                }
            }
        }
        0x09 => {
            if let (Some(ci), Some(st)) = (frame.get_u8(), frame.get_u8()) {
                print_field!("Controller ID: {}", ci);
                print_field!("Status: 0x{:02x}", st);
                if frame.size > 0 {
                    crate::display::print_hex_field("Assoc Data", frame.remaining_data());
                }
            }
        }
        _ => {
            if frame.size > 0 {
                crate::display::print_hex_field("Data", frame.remaining_data());
            }
        }
    }
}

// ============================================================================
// Central Dispatch — l2cap_frame
// ============================================================================

pub fn l2cap_frame(index: u16, in_: bool, handle: u16, cid: u16, psm: u16, data: &[u8], size: u16) {
    match cid {
        L2CAP_CID_SIGNALING => {
            bredr_sig_packet(index, in_, handle, cid, data, size);
            return;
        }
        L2CAP_CID_CONNLESS => {
            connless_packet(index, in_, handle, cid, data, size);
            return;
        }
        L2CAP_CID_AMP => {
            amp_packet(index, in_, handle, cid, data, size);
            return;
        }
        L2CAP_CID_ATT => {
            super::att::att_packet(index, in_, handle, cid, data, size);
            return;
        }
        L2CAP_CID_LE_SIGNALING => {
            le_sig_packet(index, in_, handle, cid, data, size);
            return;
        }
        L2CAP_CID_SMP | L2CAP_CID_SMP_BREDR => {
            smp_packet(index, in_, handle, cid, data, size);
            return;
        }
        _ => {}
    }

    // Dynamic CID handling
    let mut frame = L2capFrame::new(data.to_vec(), size);
    l2cap_frame_init(&mut frame, index, in_, handle, 0, cid, psm, data, size);

    match frame.mode {
        L2CAP_MODE_LE_FLOWCTL | L2CAP_MODE_ECRED => {
            let ci = get_chan_data_index(index, handle, cid);
            let sdu = with_chan_list(|list| ci.map(|i| list[i].sdu).unwrap_or(0));
            if sdu == 0 {
                let Some(sl) = frame.get_le16() else { return };
                print_field!("SDU Length: {}", sl);
                with_chan_list_mut(|list| {
                    if let Some(i) = ci {
                        list[i].sdu = sl.saturating_sub(frame.size);
                    }
                });
            } else {
                with_chan_list_mut(|list| {
                    if let Some(i) = ci {
                        list[i].sdu = sdu.saturating_sub(frame.size);
                    }
                });
            }
        }
        L2CAP_MODE_ERTM | L2CAP_MODE_STREAMING => {
            let ext = get_ext_ctrl(index, handle, cid);
            if ext != 0 {
                let Some(c) = frame.get_le32() else { return };
                l2cap_ctrl_ext_parse(&frame, c);
            } else {
                let Some(c) = frame.get_le16() else { return };
                l2cap_ctrl_parse(&frame, c);
            }
        }
        _ => {}
    }

    // PSM dispatch to sibling dissectors
    match frame.psm {
        0x0001 => super::sdp::sdp_packet(&frame),
        0x0003 => super::rfcomm::rfcomm_packet(&frame),
        0x000f => super::bnep::bnep_packet(&frame),
        0x001f => {
            super::att::att_packet(
                frame.index,
                frame.in_,
                frame.handle,
                frame.cid,
                frame.remaining_data(),
                frame.size,
            );
        }
        0x0027 => {
            // EATT: skip 2-byte SDU length before ATT payload
            if frame.get_le16().is_some() {
                super::att::att_packet(
                    frame.index,
                    frame.in_,
                    frame.handle,
                    frame.cid,
                    frame.remaining_data(),
                    frame.size,
                );
            }
        }
        0x0017 | 0x001b => super::avctp::avctp_packet(&frame),
        _ => {
            if frame.size > 0 {
                crate::display::print_hex_field("L2CAP PDU", frame.remaining_data());
            }
        }
    }
}

// ============================================================================
// Frame Queue for Latency
// ============================================================================

fn l2cap_queue_frame(frame: &L2capFrame) {
    FRAME_QUEUE.with(|fq| {
        fq.borrow_mut().push_back(FrameQueueEntry { frame: frame.clone() });
    });
}

/// Initialize an L2capFrame with channel context from the state tables.
pub fn l2cap_frame_init(
    frame: &mut L2capFrame,
    index: u16,
    in_: bool,
    handle: u16,
    ident: u8,
    cid: u16,
    psm: u16,
    _data: &[u8],
    _size: u16,
) {
    frame.index = index;
    frame.in_ = in_;
    frame.handle = handle;
    frame.ident = ident;
    frame.cid = cid;
    frame.psm = if psm != 0 { psm } else { get_psm(index, handle, cid) };
    frame.chan = get_chan_data_index(index, handle, cid).map_or(u16::MAX, |i| i as u16);
    frame.mode = get_mode(index, handle, cid);
    frame.seq_num = get_seq_num(index, handle, cid);
    if !in_ {
        l2cap_queue_frame(frame);
    }
}

/// Dequeue a frame from the latency tracking queue and print channel latency.
pub fn l2cap_dequeue_frame(delta_us: u64, conn: &str) {
    let entry = FRAME_QUEUE.with(|fq| fq.borrow_mut().pop_front());
    if let Some(e) = entry {
        if e.frame.chan != u16::MAX {
            with_chan_list_mut(|list| {
                let idx = e.frame.chan as usize;
                if idx < list.len() {
                    let lat = &mut list[idx].tx_l;
                    lat.count += 1;
                    lat.total += delta_us;
                    if lat.count == 1 || delta_us < lat.min {
                        lat.min = delta_us;
                    }
                    if delta_us > lat.max {
                        lat.max = delta_us;
                    }
                    let avg = if lat.count > 0 { lat.total / u64::from(lat.count) } else { 0 };
                    print_indent!(
                        6,
                        crate::display::COLOR_CYAN,
                        "Channel:",
                        "",
                        crate::display::COLOR_OFF,
                        " {} [{} {}] {}.{:03} ms (min {}.{:03} avg {}.{:03} max {}.{:03})",
                        conn,
                        psm2str(e.frame.psm),
                        e.frame.seq_num,
                        delta_us / 1000,
                        delta_us % 1000,
                        lat.min / 1000,
                        lat.min % 1000,
                        avg / 1000,
                        avg % 1000,
                        lat.max / 1000,
                        lat.max % 1000
                    );
                }
            });
        }
    }
}

// ============================================================================
// l2cap_packet — Fragment Reassembly Entry Point
// ============================================================================

/// Main entry point: receives raw ACL data, performs L2CAP fragment reassembly,
/// then dispatches complete frames via `l2cap_frame`.
pub fn l2cap_packet(index: u16, in_: bool, handle: u16, flags: u8, data: &[u8], size: u16) {
    let len = size as usize;
    match flags {
        0x00 | 0x02 => {
            // Start of non-auto-flushable / Start of auto-flushable
            if len < 4 {
                print_text!(
                    crate::display::COLOR_ERROR,
                    "  Malformed L2CAP start frame (too short: {})",
                    len
                );
                return;
            }
            let l2len = u16::from_le_bytes([data[0], data[1]]) as usize;
            let cid = u16::from_le_bytes([data[2], data[3]]);
            if l2len + 4 <= len {
                // Complete frame
                clear_fragment_buffer(index, in_);
                let payload = &data[4..4 + l2len];
                l2cap_frame(index, in_, handle, cid, 0, payload, l2len as u16);
            } else if (index as usize) < MAX_INDEX {
                // Fragment: start buffering
                with_index_list_mut(|list| {
                    let dir = usize::from(in_);
                    let id = &mut list[index as usize][dir];
                    let total = l2len + 4;
                    let mut buf = vec![0u8; total];
                    let cl = len.min(total);
                    buf[..cl].copy_from_slice(&data[..cl]);
                    id.frag_buf = Some(buf);
                    id.frag_pos = cl;
                    id.frag_len = total;
                    id.frag_cid = cid;
                });
            }
        }
        0x01 => {
            // Continuation fragment
            if (index as usize) >= MAX_INDEX {
                return;
            }
            let (complete, cid, buf) = with_index_list_mut(|list| {
                let dir = usize::from(in_);
                let id = &mut list[index as usize][dir];
                if id.frag_buf.is_none() {
                    return (false, 0u16, Vec::new());
                }
                let fb = id.frag_buf.as_mut().unwrap();
                let rem = id.frag_len.saturating_sub(id.frag_pos);
                let cl = len.min(rem);
                fb[id.frag_pos..id.frag_pos + cl].copy_from_slice(&data[..cl]);
                id.frag_pos += cl;
                if id.frag_pos >= id.frag_len {
                    let rc = id.frag_cid;
                    let rb = fb.clone();
                    *id = IndexData::default();
                    (true, rc, rb)
                } else {
                    (false, 0, Vec::new())
                }
            });
            if complete && buf.len() >= 4 {
                let l2len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
                let end = (4 + l2len).min(buf.len());
                let payload = &buf[4..end];
                l2cap_frame(index, in_, handle, cid, 0, payload, payload.len() as u16);
            }
        }
        0x03 => {
            // Complete L2CAP PDU (auto-flushable)
            if len < 4 {
                print_text!(
                    crate::display::COLOR_ERROR,
                    "  Malformed L2CAP complete frame (too short: {})",
                    len
                );
                return;
            }
            let l2len = u16::from_le_bytes([data[0], data[1]]) as usize;
            let cid = u16::from_le_bytes([data[2], data[3]]);
            if l2len + 4 > len {
                print_text!(
                    crate::display::COLOR_ERROR,
                    "  L2CAP length {} exceeds available data {}",
                    l2len + 4,
                    len
                );
                return;
            }
            clear_fragment_buffer(index, in_);
            let payload = &data[4..4 + l2len];
            l2cap_frame(index, in_, handle, cid, 0, payload, l2len as u16);
        }
        _ => {
            print_text!(crate::display::COLOR_ERROR, "  Unknown ACL flags: 0x{:02x}", flags);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(bytes: &[u8]) -> L2capFrame {
        L2capFrame {
            index: 0,
            in_: false,
            handle: 0x0040,
            ident: 0,
            cid: 0x0040,
            psm: 0,
            chan: u16::MAX,
            mode: 0,
            seq_num: 0,
            data: bytes.to_vec(),
            pos: 0,
            size: bytes.len() as u16,
        }
    }

    #[test]
    fn test_get_u8() {
        let mut frame = make_frame(&[0xAB, 0xCD]);
        assert_eq!(frame.get_u8(), Some(0xAB));
        assert_eq!(frame.pos, 1);
        assert_eq!(frame.size, 1);
        assert_eq!(frame.get_u8(), Some(0xCD));
        assert_eq!(frame.get_u8(), None);
    }

    #[test]
    fn test_get_le16() {
        let mut frame = make_frame(&[0x34, 0x12]);
        assert_eq!(frame.get_le16(), Some(0x1234));
        assert_eq!(frame.pos, 2);
        assert_eq!(frame.size, 0);
        assert_eq!(frame.get_le16(), None);
    }

    #[test]
    fn test_get_be16() {
        let mut frame = make_frame(&[0x12, 0x34]);
        assert_eq!(frame.get_be16(), Some(0x1234));
    }

    #[test]
    fn test_get_le32() {
        let mut frame = make_frame(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(frame.get_le32(), Some(0x12345678));
    }

    #[test]
    fn test_get_be32() {
        let mut frame = make_frame(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(frame.get_be32(), Some(0x12345678));
    }

    #[test]
    fn test_get_le64() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(frame.get_le64(), Some(0x0807060504030201));
    }

    #[test]
    fn test_get_be64() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(frame.get_be64(), Some(0x0102030405060708));
    }

    #[test]
    fn test_get_le24() {
        let mut frame = make_frame(&[0x56, 0x34, 0x12]);
        assert_eq!(frame.get_le24(), Some(0x123456));
    }

    #[test]
    fn test_get_be24() {
        let mut frame = make_frame(&[0x12, 0x34, 0x56]);
        assert_eq!(frame.get_be24(), Some(0x123456));
    }

    #[test]
    fn test_pull() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03, 0x04]);
        assert!(frame.pull(2));
        assert_eq!(frame.pos, 2);
        assert_eq!(frame.size, 2);
        assert!(frame.pull(2));
        assert_eq!(frame.size, 0);
        assert!(!frame.pull(1));
    }

    #[test]
    fn test_remaining_data() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03]);
        assert_eq!(frame.remaining_data(), &[0x01, 0x02, 0x03]);
        frame.pull(1);
        assert_eq!(frame.remaining_data(), &[0x02, 0x03]);
    }

    #[test]
    fn test_clone_size() {
        let frame = make_frame(&[0x01, 0x02, 0x03, 0x04]);
        let sub = frame.clone_size(2);
        assert_eq!(sub.size, 2);
        assert_eq!(sub.data.len(), frame.data.len());
        assert_eq!(sub.pos, frame.pos);
    }

    #[test]
    fn test_clone_frame() {
        let frame = make_frame(&[0xAA, 0xBB]);
        let cloned = frame.clone();
        assert_eq!(cloned.data, frame.data);
        assert_eq!(cloned.pos, frame.pos);
        assert_eq!(cloned.size, frame.size);
        assert_eq!(cloned.handle, frame.handle);
    }

    #[test]
    fn test_get_be128() {
        let mut frame = make_frame(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]);
        assert_eq!(frame.get_be128(), Some(0x00112233445566778899AABBCCDDEEFF));
    }

    #[test]
    fn test_boundary_underflow() {
        let mut frame = make_frame(&[0x01]);
        assert_eq!(frame.get_le16(), None);
        assert_eq!(frame.pos, 0);
        assert_eq!(frame.size, 1);
    }

    #[test]
    fn test_empty_frame() {
        let mut frame = make_frame(&[]);
        assert_eq!(frame.get_u8(), None);
        assert!(!frame.pull(1));
    }

    #[test]
    fn test_new_constructor() {
        let data = vec![0xDE, 0xAD];
        let frame = L2capFrame::new(data.clone(), 2);
        assert_eq!(frame.data, data);
        assert_eq!(frame.size, 2);
        assert_eq!(frame.pos, 0);
        assert_eq!(frame.index, 0);
        assert_eq!(frame.chan, u16::MAX);
    }

    #[test]
    fn test_mode_str_helpers() {
        assert_eq!(mode2str(L2CAP_MODE_BASIC), "Basic");
        assert_eq!(mode2str(L2CAP_MODE_RETRANS), "Retransmission");
        assert_eq!(mode2str(L2CAP_MODE_FLOWCTL), "Flow Control");
        assert_eq!(mode2str(L2CAP_MODE_ERTM), "Enhanced Retransmission");
        assert_eq!(mode2str(L2CAP_MODE_STREAMING), "Streaming");
        assert_eq!(mode2str(L2CAP_MODE_LE_FLOWCTL), "LE Flow Control");
        assert_eq!(mode2str(L2CAP_MODE_ECRED), "Enhanced Credit");
        assert_eq!(mode2str(0xFF), "Unknown");
    }

    #[test]
    fn test_sar_str() {
        assert_eq!(sar2str(0x00), "Unsegmented");
        assert_eq!(sar2str(0x01), "Start");
        assert_eq!(sar2str(0x02), "End");
        assert_eq!(sar2str(0x03), "Continuation");
        assert_eq!(sar2str(0xFF), "Bad SAR");
    }

    #[test]
    fn test_supervisory_str() {
        assert_eq!(supervisory2str(0x00), "RR (Receiver Ready)");
        assert_eq!(supervisory2str(0x01), "REJ (Reject)");
        assert_eq!(supervisory2str(0x02), "RNR (Receiver Not Ready)");
        assert_eq!(supervisory2str(0x03), "SREJ (Selective Reject)");
        assert_eq!(supervisory2str(0xFF), "Bad Supervisory");
    }

    #[test]
    fn test_psm2str_known() {
        assert_eq!(psm2str(0x0001), "SDP");
        assert_eq!(psm2str(0x0003), "RFCOMM");
        assert_eq!(psm2str(0x000f), "BNEP");
        assert_eq!(psm2str(0x0017), "AVCTP Control");
        assert_eq!(psm2str(0x001b), "AVCTP Browsing");
        assert_eq!(psm2str(0x0019), "AVDTP");
        assert_eq!(psm2str(0x001f), "ATT");
        assert_eq!(psm2str(0x0027), "EATT");
        assert_eq!(psm2str(0x9999), "");
    }

    #[test]
    fn test_l2cap_frame_init_basic() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut frame = L2capFrame::new(data.clone(), 4);
        l2cap_frame_init(&mut frame, 0, false, 0x0040, 1, 0x0040, 0x0001, &data, 4);
        assert_eq!(frame.index, 0);
        assert!(!frame.in_);
        assert_eq!(frame.handle, 0x0040);
        assert_eq!(frame.ident, 1);
        assert_eq!(frame.cid, 0x0040);
        assert_eq!(frame.psm, 0x0001);
    }
}
