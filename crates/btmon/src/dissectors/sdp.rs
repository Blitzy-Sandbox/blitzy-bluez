// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/btmon/src/dissectors/sdp.rs — SDP (Service Discovery Protocol) dissector
//
// Complete Rust rewrite of monitor/sdp.c (772 lines) + monitor/sdp.h (12 lines).
// Decodes SDP PDUs (Error, Search, Attribute, ServiceSearchAttribute
// requests/responses), recursive data element parsing (nil, uint, int, uuid,
// text, bool, sequence, alternative, URL), continuation state reassembly,
// and attribute ID to name mapping.

use std::cell::RefCell;
use std::fmt::Write;

use crate::display::{
    COLOR_BLUE, COLOR_ERROR, COLOR_MAGENTA, COLOR_OFF, COLOR_WHITE_BG, print_hexdump,
};
// Re-import #[macro_export] macros from crate root — these are defined in
// display.rs but exported at the crate level by the Rust macro_export rules.
use crate::{print_field, print_indent, print_text};

use bluez_shared::util::uuid::{bt_uuid16_to_str, bt_uuid32_to_str};

// ============================================================================
// Local L2capFrame definition (mirrors l2cap.rs export contract).
// Defined locally per D4 rules since l2cap.rs is not in depends_on_files.
// ============================================================================

/// L2CAP frame cursor struct used by all dissectors.
///
/// This is a local definition matching the API contract that will be
/// exported by `crates/btmon/src/dissectors/l2cap.rs`.  When that module
/// is created it will be the canonical source; until then, this local
/// definition enables independent compilation.
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
    /// The full payload buffer.
    data: Vec<u8>,
    /// Current read position within `data`.
    pos: usize,
    /// Remaining bytes available for reading from the current position.
    pub size: u16,
}

impl L2capFrame {
    /// Read one byte from the frame, advancing the cursor.
    pub fn get_u8(&mut self) -> Option<u8> {
        if (self.size as usize) < 1 {
            return None;
        }
        let val = self.data[self.pos];
        self.pos += 1;
        self.size -= 1;
        Some(val)
    }

    /// Read a big-endian u16 from the frame, advancing the cursor.
    pub fn get_be16(&mut self) -> Option<u16> {
        if (self.size as usize) < 2 {
            return None;
        }
        let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        self.size -= 2;
        Some(val)
    }

    /// Advance the cursor by `offset` bytes without reading.
    pub fn pull(&mut self, offset: usize) -> bool {
        if (self.size as usize) < offset {
            return false;
        }
        self.pos += offset;
        self.size -= offset as u16;
        true
    }

    /// Return a slice of the remaining un-consumed data.
    pub fn remaining_data(&self) -> &[u8] {
        let end = self.pos + self.size as usize;
        &self.data[self.pos..end]
    }
}

// ============================================================================
// SDP PDU Type Constants (from bt.h / sdp.c lines 703-711)
// ============================================================================

const SDP_ERROR_RSP: u8 = 0x01;
const SDP_SERVICE_SEARCH_REQ: u8 = 0x02;
const SDP_SERVICE_SEARCH_RSP: u8 = 0x03;
const SDP_SERVICE_ATTR_REQ: u8 = 0x04;
const SDP_SERVICE_ATTR_RSP: u8 = 0x05;
const SDP_SERVICE_SEARCH_ATTR_REQ: u8 = 0x06;
const SDP_SERVICE_SEARCH_ATTR_RSP: u8 = 0x07;

// ============================================================================
// Data Element Type Table (from sdp.c lines 149-168)
// ============================================================================

/// Information about one data element type from the SDP specification.
struct TypeData {
    value: u8,
    /// Allowed size descriptor indices (0xff sentinel terminated).
    sizes: &'static [u8],
    recurse: bool,
    name: &'static str,
    /// Whether this type has a value print handler.
    has_print: bool,
}

const TYPE_TABLE: &[TypeData] = &[
    TypeData { value: 0, sizes: &[0, 0xff], recurse: false, name: "Nil", has_print: false },
    TypeData {
        value: 1,
        sizes: &[0, 1, 2, 3, 4, 0xff],
        recurse: false,
        name: "Unsigned Integer",
        has_print: true,
    },
    TypeData {
        value: 2,
        sizes: &[0, 1, 2, 3, 4, 0xff],
        recurse: false,
        name: "Signed Integer",
        has_print: true,
    },
    TypeData { value: 3, sizes: &[1, 2, 4, 0xff], recurse: false, name: "UUID", has_print: true },
    TypeData { value: 4, sizes: &[5, 6, 7, 0xff], recurse: false, name: "String", has_print: true },
    TypeData { value: 5, sizes: &[0, 0xff], recurse: false, name: "Boolean", has_print: true },
    TypeData {
        value: 6,
        sizes: &[5, 6, 7, 0xff],
        recurse: true,
        name: "Sequence",
        has_print: false,
    },
    TypeData {
        value: 7,
        sizes: &[5, 6, 7, 0xff],
        recurse: true,
        name: "Alternative",
        has_print: false,
    },
    TypeData { value: 8, sizes: &[5, 6, 7, 0xff], recurse: false, name: "URL", has_print: true },
];

// ============================================================================
// Size Descriptor Table (from sdp.c lines 170-184)
// ============================================================================

/// Size descriptor entry: fixed sizes (bits=0, size=N) or
/// variable sizes (bits=8/16/32, size=0 → length prefix of bits/8 bytes).
struct SizeData {
    bits: u8,
    size: u8,
}

const SIZE_TABLE: &[SizeData] = &[
    SizeData { bits: 0, size: 1 },  // index 0 → 1 byte
    SizeData { bits: 0, size: 2 },  // index 1 → 2 bytes
    SizeData { bits: 0, size: 4 },  // index 2 → 4 bytes
    SizeData { bits: 0, size: 8 },  // index 3 → 8 bytes
    SizeData { bits: 0, size: 16 }, // index 4 → 16 bytes
    SizeData { bits: 8, size: 0 },  // index 5 → 1-byte length prefix
    SizeData { bits: 16, size: 0 }, // index 6 → 2-byte length prefix
    SizeData { bits: 32, size: 0 }, // index 7 → 4-byte length prefix
];

// ============================================================================
// TID and Continuation State Tracking (from sdp.c lines 33-74, 415-424)
// ============================================================================

const MAX_TID: usize = 16;
const MAX_CONT_SIZE: usize = 17;
const MAX_CONT: usize = 8;

/// Per-transaction-ID tracking state for SDP continuation reassembly.
struct TidData {
    inuse: bool,
    tid: u16,
    channel: u16,
    cont: Vec<u8>,
}

impl TidData {
    fn new() -> Self {
        TidData { inuse: false, tid: 0, channel: 0, cont: vec![0u8; MAX_CONT_SIZE] }
    }
}

/// Accumulated continuation data for reassembly across PDUs.
struct ContData {
    channel: u16,
    cont: Vec<u8>,
    data: Vec<u8>,
    size: u32,
}

impl ContData {
    fn new() -> Self {
        ContData { channel: 0, cont: vec![0u8; MAX_CONT_SIZE], data: Vec::new(), size: 0 }
    }
}

thread_local! {
    /// Per-transaction ID state array (MAX_TID=16 entries).
    static TID_LIST: RefCell<Vec<TidData>> = RefCell::new(
        (0..MAX_TID).map(|_| TidData::new()).collect()
    );

    /// Continuation data buffer array (MAX_CONT=8 entries).
    static CONT_LIST: RefCell<Vec<ContData>> = RefCell::new(
        (0..MAX_CONT).map(|_| ContData::new()).collect()
    );
}

// ============================================================================
// Attribute ID Table (from sdp.c lines 325-343)
// ============================================================================

/// Well-known SDP attribute IDs and their human-readable names.
const ATTRIBUTE_TABLE: &[(u16, &str)] = &[
    (0x0000, "Service Record Handle"),
    (0x0001, "Service Class ID List"),
    (0x0002, "Service Record State"),
    (0x0003, "Service ID"),
    (0x0004, "Protocol Descriptor List"),
    (0x0005, "Browse Group List"),
    (0x0006, "Language Base Attribute ID List"),
    (0x0007, "Service Info Time To Live"),
    (0x0008, "Service Availability"),
    (0x0009, "Bluetooth Profile Descriptor List"),
    (0x000a, "Documentation URL"),
    (0x000b, "Client Executable URL"),
    (0x000c, "Icon URL"),
    (0x000d, "Additional Protocol Descriptor List"),
];

/// Look up a well-known SDP attribute ID; returns "Unknown" for unmapped IDs.
fn get_attr_id_str(attr_id: u16) -> &'static str {
    for &(id, name) in ATTRIBUTE_TABLE {
        if id == attr_id {
            return name;
        }
    }
    "Unknown"
}

// ============================================================================
// Error Code Mapping (from sdp.c lines 523-538)
// ============================================================================

/// Map an SDP error code to its human-readable name.
fn error_str(code: u16) -> &'static str {
    match code {
        0x0001 => "Invalid Version",
        0x0002 => "Invalid Record Handle",
        0x0003 => "Invalid Syntax",
        0x0004 => "Invalid PDU Size",
        0x0005 => "Invalid Continuation State",
        _ => "Unknown",
    }
}

// ============================================================================
// Byte-Level Helpers for Raw Slice Access (from src/shared/util.h)
// ============================================================================

/// Read a big-endian u16 from a byte slice.
fn be16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

/// Read a big-endian u32 from a byte slice.
fn be32(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

/// Read a big-endian u64 from a byte slice.
fn be64(data: &[u8]) -> u64 {
    u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]])
}

/// Check if a size descriptor index is valid for the given type.
/// Mirrors C `valid_size()` from sdp.c line 187.
fn valid_size(size_index: u8, sizes: &[u8]) -> bool {
    for &s in sizes {
        if s == 0xff {
            break;
        }
        if s == size_index {
            return true;
        }
    }
    false
}

/// Get the number of extra bits (length prefix size in bits) for a size
/// descriptor index. Returns 0 for fixed-size entries.
/// Mirrors C `get_bits()` from sdp.c line 199.
fn get_bits(descriptor: u8) -> u8 {
    let idx = (descriptor & 0x07) as usize;
    if idx < SIZE_TABLE.len() { SIZE_TABLE[idx].bits } else { 0 }
}

/// Get the data payload size from a data element's leading bytes.
/// For fixed-size descriptors, returns the fixed size.
/// For variable-size descriptors, reads the length prefix from data.
/// Mirrors C `get_size()` from sdp.c line 211.
fn get_size(data: &[u8]) -> u32 {
    let idx = (data[0] & 0x07) as usize;
    if idx >= SIZE_TABLE.len() {
        return 0;
    }
    let entry = &SIZE_TABLE[idx];
    match entry.bits {
        0 => {
            // Fixed size; but Nil type (descriptor 0x00) has size 0
            if (data[0] & 0xf8) == 0 { 0 } else { entry.size as u32 }
        }
        8 => {
            if data.len() < 2 {
                0
            } else {
                data[1] as u32
            }
        }
        16 => {
            if data.len() < 3 {
                0
            } else {
                be16(&data[1..]) as u32
            }
        }
        32 => {
            if data.len() < 5 {
                0
            } else {
                be32(&data[1..])
            }
        }
        _ => 0,
    }
}

/// Get the total byte count consumed by a variable-length data element
/// (descriptor byte + length prefix bytes + payload).
/// Only valid for size indices 5, 6, 7. Returns 0 for fixed-size indices.
/// Mirrors C `get_bytes()` from sdp.c line 311.
fn get_bytes(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    match data[0] & 0x07 {
        5 => {
            if data.len() < 2 {
                0
            } else {
                2 + data[1] as u32
            }
        }
        6 => {
            if data.len() < 3 {
                0
            } else {
                3 + be16(&data[1..]) as u32
            }
        }
        7 => {
            if data.len() < 5 {
                0
            } else {
                5 + be32(&data[1..])
            }
        }
        _ => 0,
    }
}

// ============================================================================
// Data Element Print Functions (from sdp.c lines 76-147)
// ============================================================================

/// Print an unsigned integer data element value.
/// Mirrors C `print_uint()` from sdp.c line 76.
fn print_uint(indent: u8, data: &[u8], size: u32) {
    match size {
        1 => {
            print_field!("{:>width$}0x{:02x}", ' ', data[0], width = indent as usize);
        }
        2 => {
            print_field!("{:>width$}0x{:04x}", ' ', be16(data), width = indent as usize);
        }
        4 => {
            print_field!("{:>width$}0x{:08x}", ' ', be32(data), width = indent as usize);
        }
        8 => {
            print_field!("{:>width$}0x{:016x}", ' ', be64(data), width = indent as usize);
        }
        _ => {
            print_hexdump(&data[..size as usize]);
        }
    }
}

/// Print a signed integer data element value.
/// Mirrors C `print_sint()` from sdp.c line 97 — simply hexdumps the data.
fn print_sint(_indent: u8, data: &[u8], size: u32) {
    print_hexdump(&data[..size as usize]);
}

/// Print a UUID data element value (2, 4, or 16 bytes).
/// Mirrors C `print_uuid()` from sdp.c line 102.
fn print_uuid(indent: u8, data: &[u8], size: u32) {
    match size {
        2 => {
            let uuid16 = be16(data);
            print_field!(
                "{:>width$}{} (0x{:04x})",
                ' ',
                bt_uuid16_to_str(uuid16),
                uuid16,
                width = indent as usize
            );
        }
        4 => {
            let uuid32 = be32(data);
            print_field!(
                "{:>width$}{} (0x{:08x})",
                ' ',
                bt_uuid32_to_str(uuid32),
                uuid32,
                width = indent as usize
            );
        }
        16 => {
            // 128-bit UUID: display full string, then check for Bluetooth Base UUID
            let p0 = be32(data);
            let p1 = be16(&data[4..]);
            let p2 = be16(&data[6..]);
            let p3 = be16(&data[8..]);
            let p4 = be16(&data[10..]);
            let p5 = be32(&data[12..]);

            // Build the UUID string matching C format:
            // %8.8x-%4.4x-%4.4x-%4.4x-%4.4x%8.4x
            // The last part uses %8.4x (min 4 digits, field width 8)
            let last_hex = format!("{:04x}", p5);
            let mut uuid_str = String::with_capacity(40);
            let _ = write!(
                uuid_str,
                "{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:>8}",
                p0, p1, p2, p3, p4, last_hex
            );

            print_field!("{:>width$}{}", ' ', uuid_str, width = indent as usize);

            // Check if this is a Bluetooth Base UUID and resolve the name
            if p1 == 0x0000 && p2 == 0x1000 && p3 == 0x8000 && p4 == 0x0080 && p5 == 0x5F9B_34FB {
                print_field!("{:>width$}{}", ' ', bt_uuid32_to_str(p0), width = indent as usize);
            }
        }
        _ => {
            print_hexdump(&data[..size as usize]);
        }
    }
}

/// Print a text string data element value.
/// Mirrors C `print_string()` from sdp.c line 134.
fn print_string(indent: u8, data: &[u8], size: u32) {
    let len = size as usize;
    let text = String::from_utf8_lossy(&data[..len]);
    print_field!("{:>width$}{} [len {}]", ' ', text, size, width = indent as usize);
}

/// Print a boolean data element value.
/// Mirrors C `print_boolean()` from sdp.c line 144.
fn print_boolean(indent: u8, data: &[u8], _size: u32) {
    let val = if data[0] != 0 { "true" } else { "false" };
    print_field!("{:>width$}{}", ' ', val, width = indent as usize);
}

/// Dispatch to the appropriate type-specific print function.
fn type_print(type_index: usize, indent: u8, data: &[u8], size: u32) {
    match type_index {
        1 => print_uint(indent, data, size),
        2 => print_sint(indent, data, size),
        3 => print_uuid(indent, data, size),
        4 => print_string(indent, data, size),
        5 => print_boolean(indent, data, size),
        8 => print_string(indent, data, size), // URL uses same printer as String
        _ => {}
    }
}

// ============================================================================
// Recursive Data Element Decoder (from sdp.c lines 238-309)
// ============================================================================

/// Callback type for custom element printing within sequences.
/// Parameters: (position, indent, de_type, data_payload_slice).
type PrintFunc = fn(u32, u8, u8, &[u8]);

/// Recursively decode and print SDP data elements from a raw byte buffer.
///
/// * `start_pos` — Position index of the first element (for print_func callbacks).
/// * `indent` — Current indentation level (in characters beyond the base 8).
/// * `buf` — Raw byte buffer containing one or more data elements.
/// * `print_func` — Optional callback for custom element rendering.
///
/// Mirrors C `decode_data_elements()` from sdp.c line 238.
fn decode_data_elements(start_pos: u32, indent: u8, buf: &[u8], print_func: Option<PrintFunc>) {
    let total = buf.len();
    if total == 0 {
        return;
    }

    let mut offset: usize = 0;
    let mut position = start_pos;

    while offset < total {
        let remaining = total - offset;
        let data = &buf[offset..];

        // Get extra bits count (length prefix size in bits)
        let extrabits = get_bits(data[0]) as u32;
        let extra_bytes = (extrabits / 8) as usize;

        if remaining < 1 + extra_bytes {
            print_text!(COLOR_ERROR, "data element descriptor too short");
            print_hexdump(&data[..remaining]);
            return;
        }

        // Get the data payload length
        let datalen = get_size(data);

        if remaining < 1 + extra_bytes + datalen as usize {
            print_text!(COLOR_ERROR, "data element size too short");
            print_hexdump(&data[..remaining]);
            return;
        }

        // Total element length: descriptor(1) + length_prefix(extra_bytes) + datalen
        let elemlen = 1 + extra_bytes + datalen as usize;

        // Look up the type
        let type_val = (data[0] >> 3) as usize;
        let size_index = data[0] & 0x07;
        let payload_start = 1 + extra_bytes;
        let payload_end = payload_start + datalen as usize;
        let payload = &data[payload_start..payload_end];

        let mut found = false;

        for entry in TYPE_TABLE {
            if entry.value as usize != type_val {
                continue;
            }

            // If a custom print function is provided, call it with the payload
            if let Some(pf) = print_func {
                pf(position, indent, entry.value, payload);
                found = true;
                break;
            }

            // Default printing: show type descriptor line
            print_field!(
                "{:>width$}{} ({}) with {} byte{} [{} extra bits] len {}",
                ' ',
                entry.name,
                type_val,
                datalen,
                if datalen == 1 { "" } else { "s" },
                extrabits,
                elemlen,
                width = indent as usize
            );

            // Validate size descriptor for this type
            if !valid_size(size_index, entry.sizes) {
                print_text!(COLOR_ERROR, "invalid data element size");
                print_hexdump(payload);
                found = true;
                break;
            }

            // Recursive types (Sequence, Alternative) descend into children
            if entry.recurse {
                decode_data_elements(0, indent + 2, payload, print_func);
            } else if entry.has_print {
                type_print(entry.value as usize, indent + 2, payload, datalen);
            }

            found = true;
            break;
        }

        if !found {
            print_text!(COLOR_ERROR, "unknown data element type {}", type_val);
            print_hexdump(&data[..remaining]);
            return;
        }

        if elemlen > remaining {
            print_text!(COLOR_ERROR, "invalid data element size");
            return;
        }

        offset += elemlen;
        position += 1;
    }
}

// ============================================================================
// Attribute Print Callbacks (from sdp.c lines 346-390)
// ============================================================================

/// Print callback for attribute ID/value pairs within an attribute list.
/// Even positions (0, 2, 4, ...) are attribute IDs; odd positions are values.
/// Mirrors C `print_attr()` from sdp.c line 346.
fn print_attr(position: u32, indent: u8, de_type: u8, data: &[u8]) {
    if (position % 2) == 0 {
        // Even position: attribute ID
        let id = if data.len() >= 2 { be16(data) } else { 0 };
        let name = get_attr_id_str(id);
        print_field!(
            "{:>width$}Attribute: {} (0x{:04x}) [len {}]",
            ' ',
            name,
            id,
            data.len(),
            width = indent as usize
        );
    } else {
        // Odd position: attribute value — dispatch by type
        for entry in TYPE_TABLE {
            if entry.value != de_type {
                continue;
            }
            if entry.recurse {
                decode_data_elements(0, indent + 2, data, None);
            } else if entry.has_print {
                type_print(entry.value as usize, indent + 2, data, data.len() as u32);
            }
            break;
        }
    }
}

/// Print callback for an attribute list (a sequence of attribute ID/value pairs).
/// Mirrors C `print_attr_list()` from sdp.c line 377.
fn print_attr_list(position: u32, indent: u8, _de_type: u8, data: &[u8]) {
    print_field!(
        "{:>width$}Attribute list: [len {}] {{position {}}}",
        ' ',
        data.len(),
        position,
        width = indent as usize
    );
    decode_data_elements(0, indent + 2, data, Some(print_attr));
}

/// Print callback for nested attribute lists (ServiceSearchAttribute response).
/// Mirrors C `print_attr_lists()` from sdp.c line 386.
fn print_attr_lists(_position: u32, indent: u8, _de_type: u8, data: &[u8]) {
    decode_data_elements(0, indent, data, Some(print_attr_list));
}

// ============================================================================
// Continuation State Handling (from sdp.c lines 392-498)
// ============================================================================

/// Print SDP continuation state bytes.
/// Mirrors C `print_continuation()` from sdp.c line 392.
fn print_continuation(data: &[u8], size: usize) {
    if size == 0 {
        print_text!(COLOR_ERROR, "missing continuation state");
        return;
    }

    let clen = data[0] as usize;

    if clen != size - 1 {
        print_text!(COLOR_ERROR, "invalid continuation state");
        print_hexdump(&data[..size]);
        return;
    }

    print_field!("Continuation state: {}", clen);
    if clen > 0 {
        print_hexdump(&data[1..1 + clen]);
    }
}

/// Store continuation state in TID data, then print it.
/// Mirrors C `store_continuation()` from sdp.c line 404.
fn store_continuation(tid_idx: Option<usize>, data: &[u8], size: usize) {
    if size > MAX_CONT_SIZE {
        print_text!(COLOR_ERROR, "invalid continuation size");
        return;
    }

    if let Some(idx) = tid_idx {
        TID_LIST.with(|list| {
            let mut list = list.borrow_mut();
            let tid = &mut list[idx];
            let copy_len = size.min(tid.cont.len());
            tid.cont[..copy_len].copy_from_slice(&data[..copy_len]);
        });
    }

    print_continuation(data, size);
}

/// Handle continuation reassembly for attribute/search-attribute responses.
/// Accumulates partial response data across multiple PDUs and decodes the
/// complete result once the final (empty) continuation state is received.
/// Mirrors C `handle_continuation()` from sdp.c line 426.
fn handle_continuation(tid_idx: usize, nested: bool, bytes: u16, data: &[u8], size: usize) {
    let bytes_usize = bytes as usize;

    if bytes_usize + 1 > size {
        print_text!(COLOR_ERROR, "missing continuation state");
        return;
    }

    // Read the TID's previous continuation state
    let prev_cont_zero = TID_LIST.with(|list| list.borrow()[tid_idx].cont[0]);

    // Fresh exchange (no previous continuation) and final (no new continuation)
    if prev_cont_zero == 0x00 && data[bytes_usize] == 0x00 {
        // Complete in a single PDU — decode directly
        let pf: PrintFunc = if nested { print_attr_lists } else { print_attr_list };
        decode_data_elements(0, 2, &data[..bytes_usize], Some(pf));
        print_continuation(&data[bytes_usize..], size - bytes_usize);
        return;
    }

    // Look for existing continuation data entry or find a free slot
    let channel = TID_LIST.with(|list| list.borrow()[tid_idx].channel);
    let tid_cont = TID_LIST.with(|list| list.borrow()[tid_idx].cont.clone());

    let slot = CONT_LIST.with(|clist| {
        let clist = clist.borrow();
        let mut free_slot: Option<usize> = None;
        let mut match_slot: Option<usize> = None;

        for i in 0..MAX_CONT {
            if clist[i].cont[0] == 0x00 {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            if clist[i].channel != channel {
                continue;
            }
            if clist[i].cont[0] != tid_cont[0] {
                continue;
            }
            let clen = tid_cont[0] as usize;
            if clen > 0 && clist[i].cont[1..1 + clen] == tid_cont[1..1 + clen] {
                match_slot = Some(i);
                break;
            }
        }

        match_slot.or(free_slot)
    });

    print_continuation(&data[bytes_usize..], size - bytes_usize);

    let n = match slot {
        Some(n) => n,
        None => return,
    };

    // Accumulate data into the continuation buffer
    CONT_LIST.with(|clist| {
        let mut clist = clist.borrow_mut();
        let entry = &mut clist[n];

        entry.channel = channel;

        // Append the new attribute bytes
        if bytes_usize > 0 {
            entry.data.extend_from_slice(&data[..bytes_usize]);
            entry.size += bytes as u32;
        }

        // Check if this is the final fragment (continuation length == 0)
        if data[bytes_usize] == 0x00 {
            let combined_size = entry.size;
            let combined_data = entry.data.clone();

            print_field!("Combined attribute bytes: {}", combined_size);

            let pf: PrintFunc = if nested { print_attr_lists } else { print_attr_list };
            decode_data_elements(0, 2, &combined_data[..combined_size as usize], Some(pf));

            entry.data.clear();
            entry.size = 0;
            entry.cont[0] = 0;
        } else {
            // More fragments expected — store new continuation state
            let clen = data[bytes_usize] as usize;
            if bytes_usize + 1 + clen <= size {
                let cont_data = &data[bytes_usize..bytes_usize + 1 + clen];
                let copy_len = cont_data.len().min(entry.cont.len());
                entry.cont[..copy_len].copy_from_slice(&cont_data[..copy_len]);
            }
        }
    });
}

// ============================================================================
// TID Management (from sdp.c lines 45-74)
// ============================================================================

/// Find an existing TID entry or allocate a new one.
/// Returns the index into TID_LIST, or None if full.
/// Mirrors C `get_tid()` from sdp.c line 45.
fn get_tid(tid: u16, channel: u16) -> Option<usize> {
    TID_LIST.with(|list| {
        let mut list = list.borrow_mut();
        let mut free_slot: Option<usize> = None;

        for i in 0..MAX_TID {
            if !list[i].inuse {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }
            if list[i].tid == tid && list[i].channel == channel {
                return Some(i);
            }
        }

        if let Some(n) = free_slot {
            list[n].inuse = true;
            list[n].tid = tid;
            list[n].channel = channel;
            Some(n)
        } else {
            None
        }
    })
}

/// Clear a TID entry, marking it available for reuse.
/// Mirrors C `clear_tid()` from sdp.c line 70.
fn clear_tid(tid_idx: Option<usize>) {
    if let Some(idx) = tid_idx {
        TID_LIST.with(|list| {
            list.borrow_mut()[idx].inuse = false;
        });
    }
}

// ============================================================================
// Common Response Parser (from sdp.c lines 500-521)
// ============================================================================

/// Parse the common header of attribute/search-attribute response PDUs.
/// Reads the 2-byte attribute byte count, validates it, and returns it.
/// Returns 0 on error.
/// Mirrors C `common_rsp()` from sdp.c line 500.
fn common_rsp(data: &[u8], size: usize) -> u16 {
    if size < 2 {
        print_text!(COLOR_ERROR, "invalid size");
        print_hexdump(&data[..size]);
        return 0;
    }

    let bytes = be16(data);
    print_field!("Attribute bytes: {}", bytes);

    if bytes as usize > size - 2 {
        print_text!(COLOR_ERROR, "invalid attribute size");
        print_hexdump(&data[2..size]);
        return 0;
    }

    bytes
}

// ============================================================================
// SDP PDU Handlers (from sdp.c lines 541-695)
// ============================================================================

/// Handle SDP Error Response (PDU 0x01).
/// Mirrors C `error_rsp()` from sdp.c line 541.
fn error_rsp(data: &[u8], size: usize, tid_idx: Option<usize>) {
    clear_tid(tid_idx);

    if size < 2 {
        print_text!(COLOR_ERROR, "invalid size");
        print_hexdump(&data[..size]);
        return;
    }

    let error = be16(data);
    print_field!("Error code: {} (0x{:04x})", error_str(error), error);
}

/// Handle SDP Service Search Request (PDU 0x02).
/// Mirrors C `service_req()` from sdp.c line 558.
fn service_req(data: &[u8], size: usize, _tid_idx: Option<usize>) {
    let search_bytes = get_bytes(data) as usize;
    print_field!("Search pattern: [len {}]", search_bytes);

    if search_bytes + 2 > size {
        print_text!(COLOR_ERROR, "invalid search list length");
        print_hexdump(&data[..size]);
        return;
    }

    decode_data_elements(0, 2, &data[..search_bytes], None);

    print_field!("Max record count: {}", be16(&data[search_bytes..]));

    print_continuation(&data[search_bytes + 2..], size - search_bytes - 2);
}

/// Handle SDP Service Search Response (PDU 0x03).
/// Mirrors C `service_rsp()` from sdp.c line 580.
fn service_rsp(data: &[u8], size: usize, tid_idx: Option<usize>) {
    clear_tid(tid_idx);

    if size < 4 {
        print_text!(COLOR_ERROR, "invalid size");
        print_hexdump(&data[..size]);
        return;
    }

    let count = be16(&data[2..]) as usize;
    if count * 4 > size {
        print_text!(COLOR_ERROR, "invalid record count");
        return;
    }

    print_field!("Total record count: {}", be16(data));
    print_field!("Current record count: {}", count);

    for i in 0..count {
        print_field!("Record handle: 0x{:04x}", be32(&data[4 + (i * 4)..]));
    }

    print_continuation(&data[4 + (count * 4)..], size - 4 - (count * 4));
}

/// Handle SDP Service Attribute Request (PDU 0x04).
/// Mirrors C `attr_req()` from sdp.c line 610.
fn attr_req(data: &[u8], size: usize, tid_idx: Option<usize>) {
    if size < 6 {
        print_text!(COLOR_ERROR, "invalid size");
        print_hexdump(&data[..size]);
        return;
    }

    print_field!("Record handle: 0x{:04x}", be32(data));
    print_field!("Max attribute bytes: {}", be16(&data[4..]));

    let attr_bytes = get_bytes(&data[6..]) as usize;
    print_field!("Attribute list: [len {}]", attr_bytes);

    if attr_bytes + 6 > size {
        print_text!(COLOR_ERROR, "invalid attribute list length");
        print_hexdump(&data[..size]);
        return;
    }

    decode_data_elements(0, 2, &data[6..6 + attr_bytes], None);

    store_continuation(tid_idx, &data[6 + attr_bytes..], size - 6 - attr_bytes);
}

/// Handle SDP Service Attribute Response (PDU 0x05).
/// Mirrors C `attr_rsp()` from sdp.c line 638.
fn attr_rsp(data: &[u8], size: usize, tid_idx: Option<usize>) {
    let bytes = common_rsp(data, size);

    if let Some(idx) = tid_idx {
        handle_continuation(idx, false, bytes, &data[2..], size - 2);
    }

    clear_tid(tid_idx);
}

/// Handle SDP Service Search Attribute Request (PDU 0x06).
/// Mirrors C `search_attr_req()` from sdp.c line 650.
fn search_attr_req(data: &[u8], size: usize, tid_idx: Option<usize>) {
    let search_bytes = get_bytes(data) as usize;
    print_field!("Search pattern: [len {}]", search_bytes);

    if search_bytes + 2 > size {
        print_text!(COLOR_ERROR, "invalid search list length");
        print_hexdump(&data[..size]);
        return;
    }

    decode_data_elements(0, 2, &data[..search_bytes], None);

    print_field!("Max record count: {}", be16(&data[search_bytes..]));

    let rem_offset = search_bytes + 2;
    let attr_bytes = get_bytes(&data[rem_offset..]) as usize;
    print_field!("Attribute list: [len {}]", attr_bytes);

    if search_bytes + attr_bytes > size {
        print_text!(COLOR_ERROR, "invalid attribute list length");
        return;
    }

    decode_data_elements(0, 2, &data[rem_offset..rem_offset + attr_bytes], None);

    store_continuation(tid_idx, &data[rem_offset + attr_bytes..], size - rem_offset - attr_bytes);
}

/// Handle SDP Service Search Attribute Response (PDU 0x07).
/// Mirrors C `search_attr_rsp()` from sdp.c line 685.
fn search_attr_rsp(data: &[u8], size: usize, tid_idx: Option<usize>) {
    let bytes = common_rsp(data, size);

    if let Some(idx) = tid_idx {
        handle_continuation(idx, true, bytes, &data[2..], size - 2);
    }

    clear_tid(tid_idx);
}

// ============================================================================
// PDU Dispatch Table (from sdp.c lines 697-711)
// ============================================================================

/// SDP PDU dispatch entry: maps PDU ID to name and handler function.
struct SdpData {
    pdu: u8,
    name: &'static str,
    handler: fn(&[u8], usize, Option<usize>),
}

const SDP_TABLE: &[SdpData] = &[
    SdpData { pdu: SDP_ERROR_RSP, name: "Error Response", handler: error_rsp },
    SdpData { pdu: SDP_SERVICE_SEARCH_REQ, name: "Service Search Request", handler: service_req },
    SdpData { pdu: SDP_SERVICE_SEARCH_RSP, name: "Service Search Response", handler: service_rsp },
    SdpData { pdu: SDP_SERVICE_ATTR_REQ, name: "Service Attribute Request", handler: attr_req },
    SdpData { pdu: SDP_SERVICE_ATTR_RSP, name: "Service Attribute Response", handler: attr_rsp },
    SdpData {
        pdu: SDP_SERVICE_SEARCH_ATTR_REQ,
        name: "Service Search Attribute Request",
        handler: search_attr_req,
    },
    SdpData {
        pdu: SDP_SERVICE_SEARCH_ATTR_RSP,
        name: "Service Search Attribute Response",
        handler: search_attr_rsp,
    },
];

// ============================================================================
// Public Entry Point (from sdp.c lines 714-772)
// ============================================================================

/// Decode and display an SDP PDU from the given L2CAP frame.
///
/// Reads the 5-byte SDP header (PDU ID, Transaction ID, Parameter Length),
/// validates the frame, looks up the PDU handler in the dispatch table, and
/// invokes it. This is the sole public API of the SDP dissector module.
///
/// Mirrors C `sdp_packet()` from sdp.c line 714.
pub fn sdp_packet(frame: &L2capFrame) {
    let mut f = frame.clone();

    // Read SDP header: PDU ID (1 byte) + Transaction ID (2 bytes BE) +
    // Parameter Length (2 bytes BE)
    let pdu = match f.get_u8() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "frame too short");
            print_hexdump(frame.remaining_data());
            return;
        }
    };
    let tid = match f.get_be16() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "frame too short");
            print_hexdump(frame.remaining_data());
            return;
        }
    };
    let plen = match f.get_be16() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "frame too short");
            print_hexdump(frame.remaining_data());
            return;
        }
    };

    // Validate parameter length matches remaining frame size
    if f.size != plen {
        print_text!(COLOR_ERROR, "invalid frame size");
        print_hexdump(f.remaining_data());
        return;
    }

    // Look up PDU in dispatch table
    let mut sdp_data: Option<&SdpData> = None;
    for entry in SDP_TABLE {
        if entry.pdu == pdu {
            sdp_data = Some(entry);
            break;
        }
    }

    // Determine display color and name
    let (pdu_color, pdu_str) = if let Some(sd) = sdp_data {
        let color = if frame.in_ { COLOR_MAGENTA } else { COLOR_BLUE };
        (color, sd.name)
    } else {
        (COLOR_WHITE_BG, "Unknown")
    };

    // Print the SDP PDU header line
    print_indent!(
        6,
        pdu_color,
        "SDP: ",
        pdu_str,
        COLOR_OFF,
        " (0x{:02x}) tid {} len {}",
        pdu,
        tid,
        plen
    );

    // Get TID tracking entry
    let tid_info = get_tid(tid, frame.chan);

    // Dispatch to handler or hexdump for unknown PDUs
    if sdp_data.is_none() || tid_info.is_none() {
        print_hexdump(f.remaining_data());
        return;
    }

    let sd = sdp_data.unwrap();
    let payload = f.remaining_data();
    (sd.handler)(payload, payload.len(), tid_info);
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build an L2capFrame from raw data bytes.
    fn make_frame(data: &[u8]) -> L2capFrame {
        let size = data.len() as u16;
        L2capFrame {
            index: 0,
            in_: false,
            handle: 0,
            ident: 0,
            cid: 0,
            psm: 1,
            chan: 0,
            mode: 0,
            seq_num: 0,
            data: data.to_vec(),
            pos: 0,
            size,
        }
    }

    // ---- L2capFrame cursor tests ----

    #[test]
    fn test_frame_get_u8() {
        let mut frame = make_frame(&[0xAB, 0xCD]);
        assert_eq!(frame.get_u8(), Some(0xAB));
        assert_eq!(frame.size, 1);
        assert_eq!(frame.get_u8(), Some(0xCD));
        assert_eq!(frame.size, 0);
        assert_eq!(frame.get_u8(), None);
    }

    #[test]
    fn test_frame_get_be16() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03]);
        assert_eq!(frame.get_be16(), Some(0x0102));
        assert_eq!(frame.size, 1);
        assert_eq!(frame.get_be16(), None);
    }

    #[test]
    fn test_frame_pull() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03, 0x04]);
        assert!(frame.pull(2));
        assert_eq!(frame.size, 2);
        assert_eq!(frame.remaining_data(), &[0x03, 0x04]);
        assert!(!frame.pull(3));
    }

    #[test]
    fn test_frame_remaining_data() {
        let frame = make_frame(&[0x10, 0x20, 0x30]);
        assert_eq!(frame.remaining_data(), &[0x10, 0x20, 0x30]);
    }

    // ---- Byte helper tests ----

    #[test]
    fn test_be16() {
        assert_eq!(be16(&[0x01, 0x02]), 0x0102);
        assert_eq!(be16(&[0xFF, 0x00]), 0xFF00);
    }

    #[test]
    fn test_be32() {
        assert_eq!(be32(&[0x01, 0x02, 0x03, 0x04]), 0x01020304);
    }

    #[test]
    fn test_be64() {
        assert_eq!(be64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]), 0x0102030405060708);
    }

    // ---- Size descriptor tests ----

    #[test]
    fn test_valid_size() {
        // UINT sizes: 0, 1, 2, 3, 4
        assert!(valid_size(0, TYPE_TABLE[1].sizes));
        assert!(valid_size(4, TYPE_TABLE[1].sizes));
        assert!(!valid_size(5, TYPE_TABLE[1].sizes));
        // SEQ sizes: 5, 6, 7
        assert!(valid_size(5, TYPE_TABLE[6].sizes));
        assert!(!valid_size(0, TYPE_TABLE[6].sizes));
    }

    #[test]
    fn test_get_bits() {
        assert_eq!(get_bits(0x00), 0); // index 0 → fixed
        assert_eq!(get_bits(0x05), 8); // index 5 → 8 bits prefix
        assert_eq!(get_bits(0x06), 16); // index 6 → 16 bits prefix
        assert_eq!(get_bits(0x07), 32); // index 7 → 32 bits prefix
    }

    #[test]
    fn test_get_size_fixed() {
        // UINT8 (type=1, size_index=0 → 1 byte)
        assert_eq!(get_size(&[0x08]), 1);
        // UINT16 (type=1, size_index=1 → 2 bytes)
        assert_eq!(get_size(&[0x09]), 2);
        // UINT32 (type=1, size_index=2 → 4 bytes)
        assert_eq!(get_size(&[0x0A]), 4);
        // Nil type (0x00 → size 0)
        assert_eq!(get_size(&[0x00]), 0);
    }

    #[test]
    fn test_get_size_variable() {
        // SEQ with 1-byte prefix: type=6, size_index=5 → data[1] is length
        assert_eq!(get_size(&[0x35, 0x0A]), 10);
        // SEQ with 2-byte prefix: type=6, size_index=6 → BE16 from data[1..3]
        assert_eq!(get_size(&[0x36, 0x00, 0x10]), 16);
    }

    #[test]
    fn test_get_bytes() {
        // size_index=5: 2 + data[1]
        assert_eq!(get_bytes(&[0x35, 0x03]), 5);
        // size_index=6: 3 + BE16(data[1..3])
        assert_eq!(get_bytes(&[0x36, 0x00, 0x10]), 19);
    }

    // ---- Attribute name tests ----

    #[test]
    fn test_get_attr_id_str() {
        assert_eq!(get_attr_id_str(0x0000), "Service Record Handle");
        assert_eq!(get_attr_id_str(0x0004), "Protocol Descriptor List");
        assert_eq!(get_attr_id_str(0x0009), "Bluetooth Profile Descriptor List");
        assert_eq!(get_attr_id_str(0x000d), "Additional Protocol Descriptor List");
        assert_eq!(get_attr_id_str(0xFFFF), "Unknown");
    }

    // ---- Error code tests ----

    #[test]
    fn test_error_str() {
        assert_eq!(error_str(0x0001), "Invalid Version");
        assert_eq!(error_str(0x0003), "Invalid Syntax");
        assert_eq!(error_str(0x0005), "Invalid Continuation State");
        assert_eq!(error_str(0x0000), "Unknown");
        assert_eq!(error_str(0xFFFF), "Unknown");
    }

    // ---- SDP PDU smoke tests ----

    #[test]
    fn test_sdp_packet_error_rsp() {
        let data: Vec<u8> = vec![
            0x01, // PDU ID: Error Response
            0x00, 0x01, // TID: 1
            0x00, 0x02, // plen: 2
            0x00, 0x03, // Error: Invalid Syntax
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame); // must not panic
    }

    #[test]
    fn test_sdp_packet_service_search_rsp() {
        let data: Vec<u8> = vec![
            0x03, // PDU ID: Service Search Response
            0x00, 0x02, // TID: 2
            0x00, 0x09, // plen: 9
            0x00, 0x01, // Total: 1
            0x00, 0x01, // Current: 1
            0x00, 0x01, 0x00, 0x01, // Handle
            0x00, // Continuation: none
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    #[test]
    fn test_sdp_packet_unknown_pdu() {
        let data: Vec<u8> = vec![
            0xFF, // Unknown PDU
            0x00, 0x01, 0x00, 0x02, 0xDE, 0xAD,
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    #[test]
    fn test_sdp_packet_short_frame() {
        let data: Vec<u8> = vec![0x01, 0x00];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    #[test]
    fn test_sdp_service_attr_rsp() {
        let data: Vec<u8> = vec![
            0x05, // PDU: Service Attribute Response
            0x00, 0x03, // TID: 3
            0x00, 0x0D, // plen: 13
            0x00, 0x0A, // Attribute bytes: 10
            0x35, 0x08, // SEQ, len=8
            0x09, 0x00, 0x00, // UINT16 attr 0x0000
            0x0A, 0x00, 0x01, 0x00, 0x01, // UINT32
            0x00, // Continuation: none
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    #[test]
    fn test_sdp_search_attr_req() {
        let data: Vec<u8> = vec![
            0x06, // PDU: Service Search Attribute Request
            0x00, 0x04, // TID: 4
            0x00, 0x0F, // plen: 15
            0x35, 0x03, 0x19, 0x01, 0x00, // Search: SEQ[UUID16(0x0100)]
            0x01, 0x00, // Max attr bytes: 256
            0x35, 0x03, 0x09, 0x00, 0x00, // Attr list: SEQ[UINT16(0x0000)]
            0x00, // Continuation: none
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    #[test]
    fn test_sdp_service_search_req() {
        let data: Vec<u8> = vec![
            0x02, // PDU: Service Search Request
            0x00, 0x05, // TID: 5
            0x00, 0x08, // plen: 8
            0x35, 0x03, 0x19, 0x01, 0x00, // Search: SEQ[UUID16(0x0100)]
            0x00, 0x10, // Max record count: 16
            0x00, // Continuation: none
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    #[test]
    fn test_sdp_service_attr_req() {
        let data: Vec<u8> = vec![
            0x04, // PDU: Service Attribute Request
            0x00, 0x06, // TID: 6
            0x00, 0x0C, // plen: 12
            0x00, 0x01, 0x00, 0x01, // Record handle: 0x00010001
            0x01, 0x00, // Max attr bytes: 256
            0x35, 0x03, 0x09, 0x00, 0x00, // Attr list: SEQ[UINT16(0)]
            0x00, // Continuation: none
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    #[test]
    fn test_sdp_search_attr_rsp() {
        let data: Vec<u8> = vec![
            0x07, // PDU: Service Search Attribute Response
            0x00, 0x07, // TID: 7
            0x00, 0x0D, // plen: 13
            0x00, 0x0A, // Attribute bytes: 10
            0x35, 0x08, // SEQ outer, len=8
            0x35, 0x06, // SEQ inner, len=6 (one attr list)
            0x09, 0x00, 0x01, // UINT16 attr 0x0001
            0x19, 0x01, 0x00, // UUID16 0x0100
            0x00, // Continuation: none
        ];
        let frame = make_frame(&data);
        sdp_packet(&frame);
    }

    // ---- Data element decoder tests ----

    #[test]
    fn test_decode_nil() {
        let data = [0x00u8]; // Nil type
        decode_data_elements(0, 2, &data, None); // must not panic
    }

    #[test]
    fn test_decode_uint8() {
        let data = [0x08u8, 0xAB]; // UINT8 = 0xAB
        decode_data_elements(0, 2, &data, None);
    }

    #[test]
    fn test_decode_uuid16() {
        let data = [0x19u8, 0x01, 0x00]; // UUID16 = 0x0100
        decode_data_elements(0, 2, &data, None);
    }

    #[test]
    fn test_decode_bool_true() {
        let data = [0x28u8, 0x01]; // BOOL = true
        decode_data_elements(0, 2, &data, None);
    }

    #[test]
    fn test_decode_sequence() {
        // SEQ containing a single UINT8
        let data = [0x35u8, 0x02, 0x08, 0x42];
        decode_data_elements(0, 2, &data, None);
    }

    #[test]
    fn test_decode_nested_sequence() {
        // SEQ containing a SEQ containing a UINT16
        let data = [
            0x35, 0x05, // outer SEQ, len=5
            0x35, 0x03, // inner SEQ, len=3
            0x09, 0x00, 0x01, // UINT16 = 0x0001
        ];
        decode_data_elements(0, 2, &data, None);
    }

    #[test]
    fn test_decode_text() {
        // TEXT with 1-byte length prefix: "Hello"
        let data = [0x25, 0x05, b'H', b'e', b'l', b'l', b'o'];
        decode_data_elements(0, 2, &data, None);
    }

    #[test]
    fn test_decode_url() {
        // URL with 1-byte length prefix: "http"
        let data = [0x45, 0x04, b'h', b't', b't', b'p'];
        decode_data_elements(0, 2, &data, None);
    }

    #[test]
    fn test_decode_uuid128() {
        // UUID128: 16 bytes
        let data = [
            0x1C, // UUID, size=4 → 16 bytes
            0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B,
            0x34, 0xFB,
        ];
        decode_data_elements(0, 2, &data, None);
    }
}
