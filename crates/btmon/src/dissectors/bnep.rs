// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014 Intel Corporation
 * Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
 *
 * bnep.rs — BNEP (Bluetooth Network Encapsulation Protocol) dissector.
 *
 * Complete Rust rewrite of monitor/bnep.c (470 lines) + monitor/bnep.h
 * (12 lines) from BlueZ v5.86.  Decodes BNEP control messages (Setup
 * Connection Request/Response, Filter Net Type Set/Response, Filter Multi
 * Addr Set/Response), extension headers, and compressed/general ethernet
 * frame type identification.
 */

use crate::display::{
    COLOR_BLUE, COLOR_ERROR, COLOR_MAGENTA, COLOR_OFF, COLOR_WHITE_BG, print_hexdump,
};
// Re-import #[macro_export] macros from crate root — these are defined in
// display.rs but exported at the crate level by the Rust macro_export rules.
use crate::{print_field, print_indent, print_text};

use bluez_shared::util::uuid::bt_uuid32_to_str;

// ============================================================================
// Now uses the canonical L2capFrame from l2cap.rs.
// ============================================================================

pub use super::l2cap::L2capFrame;

// ============================================================================
// BNEP Packet Type Constants (from bnep.c / bt.h)
// ============================================================================

/// General Ethernet — full 6-byte dst + 6-byte src + 2-byte EtherType header.
const BNEP_GENERAL_ETHERNET: u8 = 0x00;

/// Control — carries BNEP control messages.
const BNEP_CONTROL: u8 = 0x01;

/// Compressed Ethernet — only 2-byte EtherType (addresses omitted).
const BNEP_COMPRESSED_ETHERNET: u8 = 0x02;

/// Compressed Ethernet Source Only — 6-byte src + 2-byte EtherType.
const BNEP_COMPRESSED_ETHERNET_SRC_ONLY: u8 = 0x03;

/// Compressed Ethernet Destination Only — 6-byte dst + 2-byte EtherType.
const BNEP_COMPRESSED_ETHERNET_DST_ONLY: u8 = 0x04;

// ============================================================================
// BNEP Control Type Constants
// ============================================================================

/// Control Command Not Understood response.
const BNEP_CONTROL_CMD_NOT_UNDERSTOOD: u8 = 0x00;

/// Setup Connection Request.
const BNEP_SETUP_CONN_REQ: u8 = 0x01;

/// Setup Connection Response.
const BNEP_SETUP_CONN_RSP: u8 = 0x02;

/// Filter Net Type Set request.
const BNEP_FILTER_NET_TYPE_SET: u8 = 0x03;

/// Filter Net Type Response.
const BNEP_FILTER_NET_TYPE_RSP: u8 = 0x04;

/// Filter Multi Address Set request.
const BNEP_FILTER_MULTI_ADDR_SET: u8 = 0x05;

/// Filter Multi Address Response.
const BNEP_FILTER_MULTI_ADDR_RSP: u8 = 0x06;

// ============================================================================
// BNEP Extension Type Constants
// ============================================================================

/// Extension header containing a BNEP control message.
const BNEP_EXTENSION_CONTROL: u8 = 0x00;

// ============================================================================
// Bit Manipulation Helpers (from bnep.c lines 35-36)
// ============================================================================

/// Extract the BNEP packet type from the type/extension byte (lower 7 bits).
fn get_pkt_type(type_byte: u8) -> u8 {
    type_byte & 0x7f
}

/// Extract the extension flag from the type/extension byte (bit 7).
fn get_extension(type_byte: u8) -> bool {
    (type_byte & 0x80) != 0
}

// ============================================================================
// BNEP Frame Context
// ============================================================================

/// Internal BNEP frame state used during dissection.
struct BnepFrame {
    /// BNEP packet type (lower 7 bits of the type byte).
    type_: u8,
    /// Whether extension headers follow (bit 7 of the type byte).
    extension: bool,
    /// The underlying L2CAP frame cursor for byte consumption.
    l2cap_frame: L2capFrame,
}

// ============================================================================
// String Lookup Helpers
// ============================================================================

/// BNEP packet type name/function dispatch table entry.
struct BnepData {
    type_val: u8,
    name: &'static str,
    handler: Option<fn(&mut BnepFrame, u8) -> bool>,
}

/// BNEP control type name/function dispatch table entry.
struct BnepControlData {
    type_val: u8,
    name: &'static str,
    handler: Option<fn(&mut BnepFrame, u8) -> bool>,
}

/// BNEP packet type dispatch table — maps type values to names and handlers.
/// Mirrors the C `bnep_table[]` from bnep.c lines 393–400.
static BNEP_TABLE: &[BnepData] = &[
    BnepData {
        type_val: BNEP_GENERAL_ETHERNET,
        name: "General Ethernet",
        handler: Some(bnep_general),
    },
    BnepData { type_val: BNEP_CONTROL, name: "Control", handler: Some(bnep_control_handler) },
    BnepData {
        type_val: BNEP_COMPRESSED_ETHERNET,
        name: "Compressed Ethernet",
        handler: Some(bnep_compressed),
    },
    BnepData {
        type_val: BNEP_COMPRESSED_ETHERNET_SRC_ONLY,
        name: "Compressed Ethernet SrcOnly",
        handler: Some(bnep_src_only),
    },
    BnepData {
        type_val: BNEP_COMPRESSED_ETHERNET_DST_ONLY,
        name: "Compressed Ethernet DestOnly",
        handler: Some(bnep_dst_only),
    },
];

/// BNEP control type dispatch table — maps control type values to names and
/// handlers.  Mirrors the C `bnep_control_table[]` from bnep.c lines 244–252.
static BNEP_CONTROL_TABLE: &[BnepControlData] = &[
    BnepControlData {
        type_val: BNEP_CONTROL_CMD_NOT_UNDERSTOOD,
        name: "Command Not Understood",
        handler: Some(cmd_nt_understood),
    },
    BnepControlData {
        type_val: BNEP_SETUP_CONN_REQ,
        name: "Setup Conn Req",
        handler: Some(setup_conn_req),
    },
    BnepControlData {
        type_val: BNEP_SETUP_CONN_RSP,
        name: "Setup Conn Rsp",
        handler: Some(print_rsp_msg),
    },
    BnepControlData {
        type_val: BNEP_FILTER_NET_TYPE_SET,
        name: "Filter NetType Set",
        handler: Some(filter_nettype_req),
    },
    BnepControlData {
        type_val: BNEP_FILTER_NET_TYPE_RSP,
        name: "Filter NetType Rsp",
        handler: Some(print_rsp_msg),
    },
    BnepControlData {
        type_val: BNEP_FILTER_MULTI_ADDR_SET,
        name: "Filter MultAddr Set",
        handler: Some(filter_multaddr_req),
    },
    BnepControlData {
        type_val: BNEP_FILTER_MULTI_ADDR_RSP,
        name: "Filter MultAddr Rsp",
        handler: Some(print_rsp_msg),
    },
];

/// Map a setup/filter response value to a human-readable string.
/// Mirrors the C `value2str()` from bnep.c lines 154–170.
fn value2str(value: u16) -> &'static str {
    match value {
        0x00 => "Operation Successful",
        0x01 => "Operation Failed - Invalid Dst Srv UUID",
        0x02 => "Operation Failed - Invalid Src Srv UUID",
        0x03 => "Operation Failed - Invalid Srv UUID size",
        0x04 => "Operation Failed - Conn not allowed",
        _ => "Unknown",
    }
}

// ============================================================================
// MAC Address Reader
// ============================================================================

/// Read a 6-byte MAC address from the frame, format as "xx:xx:xx:xx:xx:xx".
/// Returns `None` if the frame is too short.
fn get_macaddr(frame: &mut L2capFrame) -> Option<String> {
    let mut addr = [0u8; 6];
    for byte in &mut addr {
        *byte = frame.get_u8()?;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    ))
}

// ============================================================================
// Packet Type Handlers
// ============================================================================

/// Decode a BNEP General Ethernet frame: 6-byte dst + 6-byte src + 2-byte
/// EtherType.  Mirrors C `bnep_general()` from bnep.c lines 67–89.
fn bnep_general(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let dest_addr = match get_macaddr(&mut bnep_frame.l2cap_frame) {
        Some(a) => a,
        None => return false,
    };

    let src_addr = match get_macaddr(&mut bnep_frame.l2cap_frame) {
        Some(a) => a,
        None => return false,
    };

    let proto = match bnep_frame.l2cap_frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_field!(
        "{:>width$}dst {} src {} [proto 0x{:04x}] ",
        ' ',
        dest_addr,
        src_addr,
        proto,
        width = indent as usize
    );

    true
}

/// Decode a BNEP Compressed Ethernet frame: 2-byte EtherType only.
/// Mirrors C `bnep_compressed()` from bnep.c lines 294–306.
fn bnep_compressed(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let proto = match bnep_frame.l2cap_frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{:>width$}[proto 0x{:04x}] ", ' ', proto, width = indent as usize);

    true
}

/// Decode a BNEP Compressed Ethernet Source Only frame: 6-byte src + 2-byte
/// EtherType.  Mirrors C `bnep_src_only()` from bnep.c lines 308–327.
fn bnep_src_only(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let src_addr = match get_macaddr(&mut bnep_frame.l2cap_frame) {
        Some(a) => a,
        None => return false,
    };

    let proto = match bnep_frame.l2cap_frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_field!(
        "{:>width$}src {} [proto 0x{:04x}] ",
        ' ',
        src_addr,
        proto,
        width = indent as usize
    );

    true
}

/// Decode a BNEP Compressed Ethernet Destination Only frame: 6-byte dst +
/// 2-byte EtherType.  Mirrors C `bnep_dst_only()` from bnep.c lines 329–348.
fn bnep_dst_only(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let dest_addr = match get_macaddr(&mut bnep_frame.l2cap_frame) {
        Some(a) => a,
        None => return false,
    };

    let proto = match bnep_frame.l2cap_frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_field!(
        "{:>width$}dst {} [proto 0x{:04x}] ",
        ' ',
        dest_addr,
        proto,
        width = indent as usize
    );

    true
}

/// Wrapper handler for BNEP_CONTROL type in the packet type table.
/// Dispatches to `bnep_control` with hdr_len = -1 (full remaining data).
/// Mirrors C `bnep_control` being used in `bnep_table[1]` entry.
fn bnep_control_handler(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    bnep_control(bnep_frame, indent, None)
}

// ============================================================================
// Control Message Decoders
// ============================================================================

/// Decode a BNEP control message.
///
/// Reads 1-byte control type, looks up the handler, prints the control
/// name and dispatches to the specific control message decoder.
/// The `hdr_len` parameter limits how many bytes the control message body
/// occupies (used when decoding control extensions); `None` means unlimited.
///
/// Mirrors C `bnep_control()` from bnep.c lines 255–292.
fn bnep_control(bnep_frame: &mut BnepFrame, indent: u8, hdr_len: Option<u8>) -> bool {
    let frame = &mut bnep_frame.l2cap_frame;

    let ctype = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    // Look up the control type in the dispatch table
    let ctrl_data = BNEP_CONTROL_TABLE.iter().find(|entry| entry.type_val == ctype);

    let type_str = match ctrl_data {
        Some(data) => data.name,
        None => "Unknown control type",
    };

    print_field!("{:>width$}{} (0x{:02x}) ", ' ', type_str, ctype, width = indent as usize);

    // If no handler registered, hexdump the remaining body
    let has_handler = ctrl_data.is_some_and(|d| d.handler.is_some());
    if !has_handler {
        if let Some(len) = hdr_len {
            // hdr_len includes the control type byte already consumed,
            // so the body is (hdr_len - 1) bytes.
            let body_len = if len > 0 { (len - 1) as usize } else { 0 };
            let remaining = bnep_frame.l2cap_frame.remaining_data();
            let dump_len = body_len.min(remaining.len());
            print_hexdump(&remaining[..dump_len]);
            bnep_frame.l2cap_frame.pull(dump_len);
        }
        return true;
    }

    // Dispatch to the specific control message handler
    let handler = ctrl_data.unwrap().handler.unwrap();
    handler(bnep_frame, indent + 2)
}

/// Decode "Command Not Understood" control message: 1-byte unknown type.
/// Mirrors C `cmd_nt_understood()` from bnep.c lines 91–102.
fn cmd_nt_understood(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let frame = &mut bnep_frame.l2cap_frame;

    let ptype = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{:>width$}Type: 0x{:02x} ", ' ', ptype, width = indent as usize);

    true
}

/// Decode "Setup Connection Request" control message: 1-byte UUID size,
/// then dst + src UUIDs of that size (2/4/16 bytes each).
/// Mirrors C `setup_conn_req()` from bnep.c lines 104–152.
fn setup_conn_req(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let frame = &mut bnep_frame.l2cap_frame;

    let uuid_size = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{:>width$}Size: 0x{:02x} ", ' ', uuid_size, width = indent as usize);

    let (dst_uuid, src_uuid) = match uuid_size {
        2 => {
            let d = u32::from(match frame.get_be16() {
                Some(v) => v,
                None => return false,
            });
            let s = u32::from(match frame.get_be16() {
                Some(v) => v,
                None => return false,
            });
            (d, s)
        }
        4 => {
            let d = match frame.get_be32() {
                Some(v) => v,
                None => return false,
            };
            let s = match frame.get_be32() {
                Some(v) => v,
                None => return false,
            };
            (d, s)
        }
        16 => {
            // Read first 4 bytes of 16-byte UUID as the significant portion,
            // then skip the remaining 12 bytes.
            let d = match frame.get_be32() {
                Some(v) => v,
                None => return false,
            };
            if !frame.pull(12) {
                return false;
            }

            let s = match frame.get_be32() {
                Some(v) => v,
                None => return false,
            };
            if !frame.pull(12) {
                return false;
            }
            (d, s)
        }
        _ => {
            // Unknown UUID size — skip (uuid_size * 2) bytes for both UUIDs.
            let skip_bytes = (uuid_size as usize) * 2;
            if !frame.pull(skip_bytes) {
                return false;
            }
            return true;
        }
    };

    print_field!(
        "{:>width$}Dst: 0x{:x}({})",
        ' ',
        dst_uuid,
        bt_uuid32_to_str(dst_uuid),
        width = indent as usize
    );
    print_field!(
        "{:>width$}Src: 0x{:x}({})",
        ' ',
        src_uuid,
        bt_uuid32_to_str(src_uuid),
        width = indent as usize
    );

    true
}

/// Decode a response message: 2-byte response code.
/// Mirrors C `print_rsp_msg()` from bnep.c lines 172–184.
fn print_rsp_msg(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let frame = &mut bnep_frame.l2cap_frame;

    let rsp_msg = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_field!(
        "{:>width$}Rsp msg: {}(0x{:04x}) ",
        ' ',
        value2str(rsp_msg),
        rsp_msg,
        width = indent as usize
    );

    true
}

/// Decode "Filter Net Type Set" control message: 2-byte list length,
/// then (start_range, end_range) pairs of EtherType u16 values.
/// Mirrors C `filter_nettype_req()` from bnep.c lines 186–210.
fn filter_nettype_req(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let frame = &mut bnep_frame.l2cap_frame;

    let length = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{:>width$}Length: 0x{:04x}", ' ', length, width = indent as usize);

    // Each filter pair is 4 bytes: 2-byte start + 2-byte end
    let count = length / 4;
    for _ in 0..count {
        let start_range = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };

        let end_range = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };

        print_field!(
            "{:>width$}0x{:04x} - 0x{:04x}",
            ' ',
            start_range,
            end_range,
            width = indent as usize
        );
    }

    true
}

/// Decode "Filter Multi Address Set" control message: 2-byte list length,
/// then (start_addr, end_addr) pairs of 6-byte MAC addresses.
/// Mirrors C `filter_multaddr_req()` from bnep.c lines 212–236.
fn filter_multaddr_req(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let length = match bnep_frame.l2cap_frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{:>width$}Length: 0x{:04x}", ' ', length, width = indent as usize);

    // Each filter pair is 12 bytes: 6-byte start MAC + 6-byte end MAC
    let count = length / 12;
    for _ in 0..count {
        let start_addr = match get_macaddr(&mut bnep_frame.l2cap_frame) {
            Some(a) => a,
            None => return false,
        };

        let end_addr = match get_macaddr(&mut bnep_frame.l2cap_frame) {
            Some(a) => a,
            None => return false,
        };

        print_field!("{:>width$}{} - {}", ' ', start_addr, end_addr, width = indent as usize);
    }

    true
}

// ============================================================================
// Extension Header Decoder
// ============================================================================

/// Decode a BNEP extension header chain.
///
/// Each extension header has:
///   - 1 byte: type (lower 7 bits) + has_more_extensions (bit 7)
///   - 1 byte: body length
///   - N bytes: extension body
///
/// Recursively processes chained extensions via the has_more_extensions flag.
/// Mirrors C `bnep_eval_extension()` from bnep.c lines 350–385.
fn bnep_eval_extension(bnep_frame: &mut BnepFrame, indent: u8) -> bool {
    let frame = &mut bnep_frame.l2cap_frame;

    let type_byte = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    let length = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    let has_extension = get_extension(type_byte);
    let ext_type = get_pkt_type(type_byte);

    match ext_type {
        BNEP_EXTENSION_CONTROL => {
            print_field!(
                "{:>width$}Ext Control(0x{:02x}|{}) len 0x{:02x}",
                ' ',
                ext_type,
                if has_extension { "1" } else { "0" },
                length,
                width = indent as usize
            );
            if !bnep_control(bnep_frame, indent + 2, Some(length)) {
                return false;
            }
        }
        _ => {
            print_field!(
                "{:>width$}Ext Unknown(0x{:02x}|{}) len 0x{:02x}",
                ' ',
                ext_type,
                if has_extension { "1" } else { "0" },
                length,
                width = indent as usize
            );
            let remaining = bnep_frame.l2cap_frame.remaining_data();
            let dump_len = (length as usize).min(remaining.len());
            print_hexdump(&remaining[..dump_len]);
            bnep_frame.l2cap_frame.pull(dump_len);
        }
    }

    // Process next extension if the has_more flag is set
    if has_extension && !bnep_eval_extension(bnep_frame, indent) {
        return false;
    }

    true
}

// ============================================================================
// Main Frame Decoder
// ============================================================================

/// Decode a complete BNEP frame.
///
/// Reads the type/extension byte, dispatches to the appropriate packet
/// type handler, processes extension headers if present, and hexdumps
/// remaining payload data.
///
/// Mirrors C `bnep_packet()` body from bnep.c lines 402–470.
fn bnep_frame(frame: &L2capFrame) {
    let indent: u8 = 1;

    // Clone the L2CAP frame for local consumption
    let mut bnep = BnepFrame { type_: 0, extension: false, l2cap_frame: frame.clone() };

    let l2cap_frame = &mut bnep.l2cap_frame;

    // Read the type/extension byte
    let type_byte = match l2cap_frame.get_u8() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "frame too short");
            print_hexdump(frame.remaining_data());
            return;
        }
    };

    bnep.extension = get_extension(type_byte);
    bnep.type_ = get_pkt_type(type_byte);

    // Look up the packet type in the dispatch table
    let bnep_data = BNEP_TABLE.iter().find(|entry| entry.type_val == bnep.type_);

    // Determine color and type name string
    let (pdu_color, pdu_str) = match bnep_data {
        Some(data) => {
            let color = if data.handler.is_some() {
                if frame.in_ { COLOR_MAGENTA } else { COLOR_BLUE }
            } else {
                COLOR_WHITE_BG
            };
            (color, data.name)
        }
        None => (COLOR_WHITE_BG, "Unknown packet type"),
    };

    // Print the BNEP header line with directional color
    print_indent!(
        6,
        pdu_color,
        "BNEP: ",
        pdu_str,
        COLOR_OFF,
        " (0x{:02x}|{})",
        bnep.type_,
        if bnep.extension { "1" } else { "0" }
    );

    // If no handler registered or unknown type, hexdump and return
    let has_handler = bnep_data.is_some_and(|d| d.handler.is_some());
    if !has_handler {
        print_hexdump(bnep.l2cap_frame.remaining_data());
        return;
    }

    // Dispatch to the packet type handler
    let handler = bnep_data.unwrap().handler.unwrap();
    if !handler(&mut bnep, indent) {
        print_text!(COLOR_ERROR, "frame too short");
        print_hexdump(frame.remaining_data());
        return;
    }

    // Process extension headers if the extension flag is set
    if bnep.extension && !bnep_eval_extension(&mut bnep, indent + 2) {
        print_text!(COLOR_ERROR, "frame too short");
        print_hexdump(frame.remaining_data());
        return;
    }

    // Control packets have no payload data after control message body
    if bnep.type_ == BNEP_CONTROL {
        return;
    }

    // Hexdump remaining payload bytes (network layer data)
    let remaining = bnep.l2cap_frame.remaining_data();
    if !remaining.is_empty() {
        print_hexdump(remaining);
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Decode and display a BNEP packet from an L2CAP frame.
///
/// This is the sole public entry point for the BNEP dissector, called from
/// the L2CAP dissector when the PSM is 0x000f (BNEP).
///
/// Mirrors C `void bnep_packet(const struct l2cap_frame *frame)` from
/// bnep.h line 12.
pub fn bnep_packet(frame: &L2capFrame) {
    bnep_frame(frame);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create an L2capFrame from a byte slice with given direction.
    fn make_frame(data: &[u8], in_: bool) -> L2capFrame {
        L2capFrame {
            index: 0,
            in_,
            handle: 0,
            ident: 0,
            cid: 0x000f,
            psm: 0x000f,
            chan: 0,
            mode: 0,
            seq_num: 0,
            data: data.to_vec(),
            pos: 0,
            size: data.len() as u16,
        }
    }

    #[test]
    fn test_get_pkt_type() {
        assert_eq!(get_pkt_type(0x00), 0x00);
        assert_eq!(get_pkt_type(0x01), 0x01);
        assert_eq!(get_pkt_type(0x82), 0x02); // extension flag set
        assert_eq!(get_pkt_type(0x83), 0x03);
        assert_eq!(get_pkt_type(0x04), 0x04);
        assert_eq!(get_pkt_type(0xff), 0x7f);
    }

    #[test]
    fn test_get_extension() {
        assert!(!get_extension(0x00));
        assert!(!get_extension(0x01));
        assert!(get_extension(0x80));
        assert!(get_extension(0x82));
        assert!(get_extension(0xff));
    }

    #[test]
    fn test_get_macaddr() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut frame = make_frame(&data, true);
        let addr = get_macaddr(&mut frame).unwrap();
        assert_eq!(addr, "01:02:03:04:05:06");
        assert_eq!(frame.size, 0);
    }

    #[test]
    fn test_get_macaddr_too_short() {
        let data = [0x01, 0x02, 0x03];
        let mut frame = make_frame(&data, true);
        assert!(get_macaddr(&mut frame).is_none());
    }

    #[test]
    fn test_value2str() {
        assert_eq!(value2str(0x0000), "Operation Successful");
        assert_eq!(value2str(0x0001), "Operation Failed - Invalid Dst Srv UUID");
        assert_eq!(value2str(0x0002), "Operation Failed - Invalid Src Srv UUID");
        assert_eq!(value2str(0x0003), "Operation Failed - Invalid Srv UUID size");
        assert_eq!(value2str(0x0004), "Operation Failed - Conn not allowed");
        assert_eq!(value2str(0xffff), "Unknown");
    }

    #[test]
    fn test_bnep_control_packet_decode() {
        // BNEP Control type (0x01), control type = Setup Conn Rsp (0x02),
        // response = 0x0000 (success)
        let data = [0x01, 0x02, 0x00, 0x00];
        let frame = make_frame(&data, true);
        // Should not panic — exercises the decode path
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_general_ethernet_decode() {
        // BNEP General Ethernet (0x00):
        // dst MAC: 01:02:03:04:05:06
        // src MAC: 0a:0b:0c:0d:0e:0f
        // EtherType: 0x0800 (IPv4)
        let data = [
            0x00, // type = General Ethernet, no extension
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // src MAC
            0x08, 0x00, // EtherType = IPv4
        ];
        let frame = make_frame(&data, false);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_compressed_ethernet_decode() {
        // BNEP Compressed Ethernet (0x02): EtherType only
        let data = [0x02, 0x08, 0x00]; // type=0x02, proto=0x0800
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_src_only_decode() {
        // BNEP Compressed Ethernet SrcOnly (0x03):
        // src MAC: aa:bb:cc:dd:ee:ff
        // EtherType: 0x86dd (IPv6)
        let data = [
            0x03, // type
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src MAC
            0x86, 0xdd, // EtherType = IPv6
        ];
        let frame = make_frame(&data, false);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_dst_only_decode() {
        // BNEP Compressed Ethernet DestOnly (0x04):
        // dst MAC: 11:22:33:44:55:66
        // EtherType: 0x0806 (ARP)
        let data = [
            0x04, // type
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // dst MAC
            0x08, 0x06, // EtherType = ARP
        ];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_setup_conn_req_uuid2() {
        // BNEP Control, Setup Conn Req with 2-byte UUIDs
        // type=0x01 (control), ctrl_type=0x01 (setup req),
        // uuid_size=0x02, dst=0x1116 (NAP), src=0x1115 (PANU)
        let data = [0x01, 0x01, 0x02, 0x11, 0x16, 0x11, 0x15];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_setup_conn_req_uuid4() {
        // Setup Conn Req with 4-byte UUIDs
        let data = [
            0x01, 0x01, 0x04, // control, setup conn req, uuid size=4
            0x00, 0x00, 0x11, 0x16, // dst UUID
            0x00, 0x00, 0x11, 0x15, // src UUID
        ];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_setup_conn_req_uuid16() {
        // Setup Conn Req with 16-byte UUIDs
        let mut data = vec![0x01, 0x01, 16]; // control, setup conn req, uuid size=16
        // dst UUID: 16 bytes (first 4 are the significant portion)
        data.extend_from_slice(&[0x00, 0x00, 0x11, 0x16]);
        data.extend_from_slice(&[0x00; 12]); // remaining 12 bytes
        // src UUID: 16 bytes
        data.extend_from_slice(&[0x00, 0x00, 0x11, 0x15]);
        data.extend_from_slice(&[0x00; 12]); // remaining 12 bytes
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_filter_nettype_set() {
        // Filter NetType Set: length=8 (2 pairs of 4 bytes)
        let data = [
            0x01, 0x03, // control, Filter NetType Set
            0x00, 0x08, // length = 8
            0x08, 0x00, // start range = 0x0800
            0x08, 0x00, // end range = 0x0800
            0x86, 0xdd, // start range = 0x86DD
            0x86, 0xdd, // end range = 0x86DD
        ];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_filter_multaddr_set() {
        // Filter MultAddr Set: length=12 (1 pair of 12 bytes)
        let data = [
            0x01, 0x05, // control, Filter MultAddr Set
            0x00, 0x0c, // length = 12
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // start addr
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // end addr
        ];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_extension_header() {
        // General Ethernet with an extension header:
        // type byte = 0x80 (General Ethernet + extension bit set)
        let data = [
            0x80, // type = General Ethernet (0x00) | extension (0x80)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // src MAC
            0x08, 0x00, // EtherType
            // Extension header: type=0x00 (control, no more extensions), len=3
            0x00, 0x03, // ext type=Control (no extension flag), length=3
            // Extension body: control type = Setup Conn Rsp (0x02), rsp = 0x0000
            0x02, 0x00, 0x00,
        ];
        let frame = make_frame(&data, false);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_frame_too_short() {
        // Empty frame — should print "frame too short"
        let data: [u8; 0] = [];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_unknown_type() {
        // Unknown packet type (0x7f)
        let data = [0x7f, 0xde, 0xad, 0xbe, 0xef];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_cmd_not_understood() {
        // Control: Command Not Understood (0x00), unknown type byte = 0x42
        let data = [0x01, 0x00, 0x42];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_filter_nettype_rsp() {
        // Filter NetType Rsp: response = 0x0000 (success)
        let data = [0x01, 0x04, 0x00, 0x00];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_filter_multaddr_rsp() {
        // Filter MultAddr Rsp: response = 0x0001 (not allowed)
        let data = [0x01, 0x06, 0x00, 0x01];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_bnep_chained_extensions() {
        // Compressed Ethernet with two chained extension headers
        let data = [
            0x82, // type = Compressed Ethernet (0x02) | extension (0x80)
            0x08, 0x00, // EtherType
            // First extension: type=0x80 (Control + more extensions), len=3
            0x80, 0x03, // ext type=0x00 (control) + extension flag, length=3
            0x02, 0x00, 0x00, // Setup Conn Rsp, success
            // Second extension: type=0x00 (Control, no more extensions), len=3
            0x00, 0x03, // ext type=0x00 (control), no extension, length=3
            0x02, 0x00, 0x00, // Setup Conn Rsp, success
        ];
        let frame = make_frame(&data, true);
        bnep_packet(&frame);
    }

    #[test]
    fn test_l2cap_frame_get_u8() {
        let data = [0x42, 0xff];
        let mut frame = make_frame(&data, true);
        assert_eq!(frame.get_u8(), Some(0x42));
        assert_eq!(frame.get_u8(), Some(0xff));
        assert_eq!(frame.get_u8(), None);
    }

    #[test]
    fn test_l2cap_frame_get_be16() {
        let data = [0x12, 0x34];
        let mut frame = make_frame(&data, true);
        assert_eq!(frame.get_be16(), Some(0x1234));
        assert_eq!(frame.get_be16(), None);
    }

    #[test]
    fn test_l2cap_frame_get_be32() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut frame = make_frame(&data, true);
        assert_eq!(frame.get_be32(), Some(0x12345678));
        assert_eq!(frame.get_be32(), None);
    }

    #[test]
    fn test_l2cap_frame_pull() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut frame = make_frame(&data, true);
        assert!(frame.pull(2));
        assert_eq!(frame.size, 2);
        assert_eq!(frame.get_u8(), Some(0x03));
        assert!(!frame.pull(5)); // not enough data
    }

    #[test]
    fn test_l2cap_frame_remaining_data() {
        let data = [0x01, 0x02, 0x03];
        let mut frame = make_frame(&data, true);
        frame.get_u8();
        assert_eq!(frame.remaining_data(), &[0x02, 0x03]);
    }
}
