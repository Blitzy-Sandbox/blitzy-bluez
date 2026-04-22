// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014 Intel Corporation
 * Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
 *
 * rfcomm.rs — RFCOMM protocol dissector.
 *
 * Complete Rust rewrite of monitor/rfcomm.c (508 lines) + monitor/rfcomm.h
 * (67 lines) from BlueZ v5.86.  Decodes RFCOMM frames (SABM, UA, DM, DISC,
 * UIH, UI), MCC (Multiplexer Control Command) messages for PN, MSC, RPN,
 * RLS, NSC, Test, FCon, FCoff, and address/control/length field parsing
 * with EA bit handling.
 */

use crate::display::{
    COLOR_BLUE, COLOR_ERROR, COLOR_MAGENTA, COLOR_OFF, COLOR_WHITE_BG, print_hexdump,
};
// Re-import #[macro_export] macros from crate root — these are defined in
// display.rs but exported at the crate level by the Rust macro_export rules.
use crate::{print_field, print_indent, print_text};

// ============================================================================
// Local L2capFrame definition (mirrors l2cap.rs export contract).
// Now uses the canonical L2capFrame from l2cap.rs.
// ============================================================================

pub use super::l2cap::L2capFrame;

// ============================================================================
// RFCOMM Frame Type Constants (from rfcomm.h lines 13-17)
// ============================================================================

const RFCOMM_SABM: u8 = 0x2f;
const RFCOMM_DISC: u8 = 0x43;
const RFCOMM_UA: u8 = 0x63;
const RFCOMM_DM: u8 = 0x0f;
const RFCOMM_UIH: u8 = 0xef;

// ============================================================================
// Address/Control Field Helpers (from rfcomm.h lines 19-24)
// ============================================================================

/// Extract the frame type from the control byte (strips P/F bit).
fn rfcomm_get_type(control: u8) -> u8 {
    control & 0xef
}

/// Extract DLCI from the address byte.
fn rfcomm_get_dlci(address: u8) -> u8 {
    (address & 0xfc) >> 2
}

/// Extract the channel number from the address byte.
fn rfcomm_get_channel(address: u8) -> u8 {
    (address & 0xf8) >> 3
}

/// Extract direction bit from the address byte.
fn rfcomm_get_dir(address: u8) -> u8 {
    (address & 0x04) >> 2
}

/// Test the Extended Address (EA) bit — true if EA=1 (last octet).
fn rfcomm_test_ea(length: u8) -> bool {
    (length & 0x01) != 0
}

// ============================================================================
// MCC Type Constants (from rfcomm.h lines 43-55)
// ============================================================================

const RFCOMM_TEST: u8 = 0x08;
const RFCOMM_FCON: u8 = 0x28;
const RFCOMM_FCOFF: u8 = 0x18;
const RFCOMM_MSC: u8 = 0x38;
const RFCOMM_RPN: u8 = 0x24;
const RFCOMM_RLS: u8 = 0x14;
const RFCOMM_PN: u8 = 0x20;
const RFCOMM_NSC: u8 = 0x04;

/// Test the C/R bit in MCC type byte.
fn rfcomm_test_cr(type_: u8) -> bool {
    (type_ & 0x02) != 0
}

/// Extract the MCC command type field from the MCC type byte.
fn rfcomm_get_mcc_type(type_: u8) -> u8 {
    (type_ & 0xfc) >> 2
}

// ============================================================================
// Additional Extraction Helpers (from rfcomm.c macros)
// ============================================================================

/// C/R to string: 0 → "RSP", 1 → "CMD" (from cr_str[] array).
fn cr_to_str(cr: bool) -> &'static str {
    if cr { "CMD" } else { "RSP" }
}

/// Extract 7-bit length from a single length byte (EA=1).
fn get_len8(length: u8) -> u16 {
    u16::from((length & 0xfe) >> 1)
}

/// Extract 15-bit length from a two-byte length field.
fn get_len16(length: u16) -> u16 {
    (length & 0xfffe) >> 1
}

/// Extract P/F (Poll/Final) bit from the control byte.
fn get_pf(control: u8) -> u8 {
    (control >> 4) & 0x1
}

/// Extract C/R bit from the address byte.
fn get_cr(address: u8) -> u8 {
    (address & 0x02) >> 1
}

// ============================================================================
// Frame Type → String Lookup (from rfcomm.c rfcomm_table[])
// ============================================================================

/// Convert an RFCOMM frame type code to its human-readable name.
fn rfcomm_type_to_str(type_: u8) -> &'static str {
    match type_ {
        RFCOMM_SABM => "Set Async Balance Mode (SABM)",
        RFCOMM_UA => "Unnumbered Ack (UA)",
        RFCOMM_DM => "Disconnect Mode (DM)",
        RFCOMM_DISC => "Disconnect (DISC)",
        RFCOMM_UIH => "Unnumbered Info with Header Check (UIH)",
        _ => "Unknown",
    }
}

// ============================================================================
// MCC Type → String Lookup (from rfcomm.c mcc_table[])
// ============================================================================

/// Convert an MCC command type to its human-readable name.
fn mcc_type_to_str(type_: u8) -> &'static str {
    match type_ {
        RFCOMM_TEST => "Test Command",
        RFCOMM_FCON => "Flow Control On Command",
        RFCOMM_FCOFF => "Flow Control Off Command",
        RFCOMM_MSC => "Modem Status Command",
        RFCOMM_RPN => "Remote Port Negotiation Command",
        RFCOMM_RLS => "Remote Line Status",
        RFCOMM_PN => "DLC Parameter Negotiation",
        RFCOMM_NSC => "Non Supported Command",
        _ => "Unknown",
    }
}

// ============================================================================
// Local Frame Structures
//
// These mirror the local structs in rfcomm.c, parsed out of the byte
// stream rather than using packed C structs.
// ============================================================================

/// Parsed RFCOMM header (address + control + length + FCS + optional credits).
struct RfcommLocalHdr {
    address: u8,
    control: u8,
    length: u16,
    fcs: u8,
    credits: u8,
}

/// Parsed MCC header — only the length is retained because the type byte
/// is consumed and dispatched directly in `mcc_frame`.
struct RfcommLocalMcc {
    length: u16,
}

/// Parsed MSC data (dlci + v24_sig).
struct RfcommLocalMsc {
    dlci: u8,
    v24_sig: u8,
}

/// Parsed PN parameters.
struct RfcommPnParams {
    dlci: u8,
    flow_ctrl: u8,
    priority: u8,
    ack_timer: u8,
    frame_size: u16,
    max_retrans: u8,
    credits: u8,
}

/// Parsed RPN parameters — dlci is printed before the struct is built so
/// only the port-negotiation fields are stored here.
struct RfcommRpnParams {
    bit_rate: u8,
    parity: u8,
    io: u8,
    xon: u8,
    xoff: u8,
    pm: u16,
}

/// Parsed RLS data.
struct RfcommRlsData {
    dlci: u8,
    error: u8,
}

/// Parsed NSC data.
struct RfcommNscData {
    cmd_type: u8,
}

/// Local representation combining header + MCC + remaining frame data.
struct RfcommFrame {
    hdr: RfcommLocalHdr,
    mcc: RfcommLocalMcc,
    frame: L2capFrame,
}

// ============================================================================
// MCC Decoders (from rfcomm.c lines ~120-350)
// ============================================================================

/// Decode and print MCC Test command data.
fn mcc_test(rfcomm: &mut RfcommFrame) {
    let mcc_len = rfcomm.mcc.length as usize;
    if mcc_len == 0 {
        return;
    }
    let avail = rfcomm.frame.size as usize;
    let to_dump = if mcc_len <= avail { mcc_len } else { avail };
    let data = &rfcomm.frame.remaining_data()[..to_dump];
    print_hexdump(data);
    rfcomm.frame.pull(to_dump);
}

/// Decode and print MSC (Modem Status Command) data.
fn mcc_msc(rfcomm: &mut RfcommFrame) {
    let mcc_len = rfcomm.mcc.length as usize;
    if mcc_len < 2 {
        return;
    }

    let dlci_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let v24_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    let msc = RfcommLocalMsc { dlci: (dlci_byte & 0xfc) >> 2, v24_sig: v24_byte };

    print_field!("DLCI: {} (0x{:02x})", msc.dlci, msc.dlci);

    let fc = (msc.v24_sig & 0x02) >> 1;
    let rtc = (msc.v24_sig & 0x04) >> 2;
    let rtr = (msc.v24_sig & 0x08) >> 3;
    let ic = (msc.v24_sig & 0x40) >> 6;
    let dv = (msc.v24_sig & 0x80) >> 7;

    print_field!("V.24 Signal: FC={} RTC={} RTR={} IC={} DV={}", fc, rtc, rtr, ic, dv);

    // Remaining bytes after the 2-byte MSC minimum may contain break signal.
    // C code has a TODO and just hexdumps the remainder.
    let remaining_msc = mcc_len.saturating_sub(2);
    if remaining_msc > 0 {
        let avail = rfcomm.frame.size as usize;
        let to_dump = if remaining_msc <= avail { remaining_msc } else { avail };
        let data = &rfcomm.frame.remaining_data()[..to_dump];
        print_hexdump(data);
        rfcomm.frame.pull(to_dump);
    }
}

/// Decode and print RPN (Remote Port Negotiation) parameters.
fn mcc_rpn(rfcomm: &mut RfcommFrame) {
    let mcc_len = rfcomm.mcc.length as usize;

    // RPN can be short (1 byte for DLCI-only query) or full (8 bytes)
    if mcc_len < 1 {
        return;
    }

    let dlci_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    let dlci = (dlci_byte & 0xfc) >> 2;
    print_field!("DLCI: {} (0x{:02x})", dlci, dlci);

    // Short RPN (1 byte) — just the DLCI query
    if mcc_len < 8 {
        return;
    }

    // Full RPN — read remaining 7 bytes
    let bit_rate = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let parity_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let io_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let xon = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let xoff = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let pm = match rfcomm.frame.get_le16() {
        Some(v) => v,
        None => return,
    };

    let rpn = RfcommRpnParams { bit_rate, parity: parity_byte, io: io_byte, xon, xoff, pm };

    let baud_str = match rpn.bit_rate {
        0 => "2400",
        1 => "4800",
        2 => "7200",
        3 => "9600",
        4 => "19200",
        5 => "38400",
        6 => "57600",
        7 => "115200",
        8 => "230400",
        _ => "Reserved",
    };
    print_field!("Baud Rate: {}", baud_str);

    let db = rpn.parity & 0x03;
    let sb = (rpn.parity & 0x04) >> 2;
    let parity_bit = (rpn.parity & 0x08) >> 3;
    let ptype = (rpn.parity & 0x30) >> 4;

    let db_str = match db {
        0 => "5 bit",
        2 => "6 bit",
        1 => "7 bit",
        3 => "8 bit",
        _ => "Unknown",
    };
    print_field!("Data Bits: {}", db_str);

    let sb_str = match sb {
        0 => "1",
        1 => "1.5",
        _ => "Unknown",
    };
    print_field!("Stop Bit: {}", sb_str);

    let parity_str = if parity_bit == 0 { "No" } else { "Yes" };
    print_field!("Parity: {}", parity_str);

    let ptype_str = match ptype {
        0 => "Odd",
        1 => "Even",
        2 => "Mark",
        3 => "Space",
        _ => "Unknown",
    };
    print_field!("Parity Type: {}", ptype_str);

    let xin = rpn.io & 0x01;
    let xout = (rpn.io & 0x02) >> 1;
    let rtri = (rpn.io & 0x04) >> 2;
    let rtro = (rpn.io & 0x08) >> 3;
    let rtci = (rpn.io & 0x10) >> 4;
    let rtco = (rpn.io & 0x20) >> 5;

    print_field!(
        "Flow Ctrl: XON/XOFF input={} output={} RTR input={} output={} RTC input={} output={}",
        xin,
        xout,
        rtri,
        rtro,
        rtci,
        rtco
    );

    print_field!("XON Char: 0x{:02x}", rpn.xon);
    print_field!("XOFF Char: 0x{:02x}", rpn.xoff);
    print_field!("Parameter Mask: 0x{:04x}", rpn.pm);
}

/// Decode and print RLS (Remote Line Status) data.
fn mcc_rls(rfcomm: &mut RfcommFrame) {
    let mcc_len = rfcomm.mcc.length as usize;
    if mcc_len < 2 {
        return;
    }

    let dlci_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let error_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    let rls = RfcommRlsData { dlci: (dlci_byte & 0xfc) >> 2, error: error_byte & 0x0f };

    print_field!("DLCI: {} (0x{:02x})", rls.dlci, rls.dlci);

    let overrun = (rls.error & 0x08) >> 3;
    let parity = (rls.error & 0x04) >> 2;
    let framing = (rls.error & 0x02) >> 1;

    print_field!("Error: Overrun={} Parity={} Framing={}", overrun, parity, framing);
}

/// Decode and print PN (DLC Parameter Negotiation) data.
fn mcc_pn(rfcomm: &mut RfcommFrame) {
    let mcc_len = rfcomm.mcc.length as usize;
    if mcc_len < 8 {
        return;
    }

    let dlci_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let flow_ctrl_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let priority_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let ack_timer = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let frame_size = match rfcomm.frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    let max_retrans = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let credits = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    let pn = RfcommPnParams {
        dlci: dlci_byte & 0x3f,
        flow_ctrl: flow_ctrl_byte,
        priority: priority_byte & 0x3f,
        ack_timer,
        frame_size,
        max_retrans,
        credits,
    };

    let frm_type = pn.flow_ctrl & 0x0f;
    let crt_flow = (pn.flow_ctrl & 0xf0) >> 4;

    print_field!("DLCI: {} (0x{:02x})", pn.dlci, pn.dlci);
    print_field!("Frame Type: 0x{:02x}", frm_type);
    print_field!("Credit Flow: 0x{:02x}", crt_flow);
    print_field!("Priority: {} (0x{:02x})", pn.priority, pn.priority);
    print_field!("Ack Timer: {}", pn.ack_timer);
    print_field!("Frame Size: {}", pn.frame_size);
    print_field!("Max Retrans: {}", pn.max_retrans);
    print_field!("Credits: {}", pn.credits);
}

/// Decode and print NSC (Non Supported Command) data.
fn mcc_nsc(rfcomm: &mut RfcommFrame) {
    let mcc_len = rfcomm.mcc.length as usize;
    if mcc_len < 1 {
        return;
    }

    let cmd_type_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    let nsc = RfcommNscData { cmd_type: cmd_type_byte };

    print_field!("Cmd Type: 0x{:02x}", nsc.cmd_type);
}

// ============================================================================
// MCC Frame Decoder (from rfcomm.c lines ~370-420)
// ============================================================================

/// Decode and dispatch MCC (Multiplexer Control Command) frames on DLCI 0.
fn mcc_frame(rfcomm: &mut RfcommFrame) {
    // Read MCC type byte
    let type_byte = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    // Read MCC length (EA-aware: 1 or 2 bytes)
    let first_len = match rfcomm.frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    let mcc_length = if rfcomm_test_ea(first_len) {
        get_len8(first_len)
    } else {
        let second_len = match rfcomm.frame.get_u8() {
            Some(v) => v,
            None => return,
        };
        get_len16(u16::from(first_len) | (u16::from(second_len) << 8))
    };

    let mcc_type = rfcomm_get_mcc_type(type_byte);
    let cr = rfcomm_test_cr(type_byte);

    rfcomm.mcc = RfcommLocalMcc { length: mcc_length };

    let mcc_str = mcc_type_to_str(mcc_type);
    let cr_str_val = cr_to_str(cr);

    print_field!("MCC Message type: {} {} (0x{:02x})", mcc_str, cr_str_val, mcc_type);
    print_field!("Length: {}", mcc_length);

    // Dispatch to specific MCC handler
    match mcc_type {
        RFCOMM_PN => mcc_pn(rfcomm),
        RFCOMM_MSC => mcc_msc(rfcomm),
        RFCOMM_RPN => mcc_rpn(rfcomm),
        RFCOMM_RLS => mcc_rls(rfcomm),
        RFCOMM_NSC => mcc_nsc(rfcomm),
        RFCOMM_TEST => mcc_test(rfcomm),
        RFCOMM_FCON => {
            // Flow Control On — no additional data to decode
        }
        RFCOMM_FCOFF => {
            // Flow Control Off — no additional data to decode
        }
        _ => {
            // Unknown MCC type — hexdump payload
            let dump_len = mcc_length as usize;
            let avail = rfcomm.frame.size as usize;
            let to_dump = if dump_len <= avail { dump_len } else { avail };
            if to_dump > 0 {
                let data = &rfcomm.frame.remaining_data()[..to_dump];
                print_hexdump(data);
                rfcomm.frame.pull(to_dump);
            }
        }
    }
}

// ============================================================================
// UIH Frame Decoder (from rfcomm.c lines ~420-445)
// ============================================================================

/// Decode UIH (Unnumbered Information with Header check) frame payload.
fn uih_frame(rfcomm: &mut RfcommFrame) {
    let channel = rfcomm_get_channel(rfcomm.hdr.address);

    if channel == 0 {
        // DLCI 0 is the multiplexer control channel
        mcc_frame(rfcomm);
    } else {
        // Data channel
        let pf = get_pf(rfcomm.hdr.control);

        if pf != 0 {
            // Credit-based flow control: next byte is the credit count
            let credits_byte = match rfcomm.frame.get_u8() {
                Some(v) => v,
                None => return,
            };
            rfcomm.hdr.credits = credits_byte;
            print_field!("Credits: {}", rfcomm.hdr.credits);
        }

        // Hexdump the remaining UIH data payload
        let remaining = rfcomm.frame.size as usize;
        if remaining > 0 {
            let data = rfcomm.frame.remaining_data();
            print_hexdump(data);
        }
    }
}

// ============================================================================
// RFCOMM Header Printing (from rfcomm.c print_rfcomm_hdr)
// ============================================================================

/// Print the decoded RFCOMM header fields.
fn print_rfcomm_hdr(rfcomm: &RfcommFrame) {
    let address = rfcomm.hdr.address;
    let control = rfcomm.hdr.control;

    let cr = get_cr(address);
    let dlci = rfcomm_get_dlci(address);
    let channel = rfcomm_get_channel(address);
    let dir = rfcomm_get_dir(address);
    let pf = get_pf(control);

    let dir_str = if dir != 0 { "1" } else { "0" };

    print_field!("Address: 0x{:02x} cr {} dlci 0x{:02x}", address, cr, dlci);
    print_field!("Control: 0x{:02x} poll/final {}", control, pf);
    print_field!("Length: {}", rfcomm.hdr.length);
    print_field!("FCS: 0x{:02x}", rfcomm.hdr.fcs);

    // Suppress unused variable warnings via explicit naming
    let _ = channel;
    let _ = dir_str;
}

// ============================================================================
// Main Frame Decoder (from rfcomm.c rfcomm_frame / rfcomm_packet)
// ============================================================================

/// Decode and print a complete RFCOMM frame from the given L2CAP frame.
fn rfcomm_frame(frame: &mut L2capFrame) {
    // We need at least 4 bytes: address(1) + control(1) + length(1+) + FCS(1)
    if (frame.size as usize) < 4 {
        print_text!(COLOR_ERROR, "Frame too short");
        print_hexdump(frame.remaining_data());
        return;
    }

    // Read address byte
    let address = match frame.get_u8() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "Frame too short");
            return;
        }
    };

    // Read control byte
    let control = match frame.get_u8() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "Frame too short");
            return;
        }
    };

    // Read length field — EA-aware (1 or 2 bytes)
    let first_len = match frame.get_u8() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "Frame too short");
            return;
        }
    };

    let length = if rfcomm_test_ea(first_len) {
        get_len8(first_len)
    } else {
        let second_len = match frame.get_u8() {
            Some(v) => v,
            None => {
                print_text!(COLOR_ERROR, "Frame too short");
                return;
            }
        };
        get_len16(u16::from(first_len) | (u16::from(second_len) << 8))
    };

    // FCS is the last byte in the original L2CAP frame data
    // In the C code, fcs is read at data offset (hdr_length + payload_length)
    // We need to peek at the last byte of the remaining data after header parsing.
    //
    // Strategy: data currently points after header bytes. The remaining data is
    // length bytes of payload + 1 byte FCS. We read the FCS from the end.
    let fcs = if (frame.size as usize) > length as usize {
        // FCS is after the payload
        let fcs_offset = frame.pos + length as usize;
        if fcs_offset < frame.data.len() { frame.data[fcs_offset] } else { 0x00 }
    } else {
        0x00
    };

    let frame_type = rfcomm_get_type(control);
    let type_str = rfcomm_type_to_str(frame_type);
    let dlci = rfcomm_get_dlci(address);
    let channel = rfcomm_get_channel(address);
    let dir = rfcomm_get_dir(address);
    let pf = get_pf(control);

    // Select color based on direction for known types, WHITE_BG for unknown
    let known = type_str != "Unknown";
    let pdu_color = if !known {
        COLOR_WHITE_BG
    } else if frame.in_ {
        COLOR_MAGENTA
    } else {
        COLOR_BLUE
    };

    // If the frame type is unknown, print header in warning color then hexdump
    if !known {
        print_indent!(
            6,
            pdu_color,
            "RFCOMM",
            "",
            COLOR_OFF,
            ": {} DLCI {} ch {} dir {} pf {}",
            type_str,
            dlci,
            channel,
            if dir != 0 { "1" } else { "0" },
            pf
        );
        print_hexdump(frame.remaining_data());
        return;
    }

    let dir_str = if dir != 0 { "1" } else { "0" };

    // Print the RFCOMM header line (from rfcomm.c: indent with type, dlci, channel, dir, pf)
    print_indent!(
        6,
        pdu_color,
        "RFCOMM",
        "",
        COLOR_OFF,
        ": {} DLCI {} ch {} dir {} pf {}",
        type_str,
        dlci,
        channel,
        dir_str,
        pf
    );

    // Build local frame representation
    let mut rfcomm = RfcommFrame {
        hdr: RfcommLocalHdr { address, control, length, fcs, credits: 0 },
        mcc: RfcommLocalMcc { length: 0 },
        frame: frame.clone(),
    };

    // Print decoded header fields
    print_rfcomm_hdr(&rfcomm);

    // For UIH frames, decode payload (MCC or data)
    if frame_type == RFCOMM_UIH {
        uih_frame(&mut rfcomm);
    }
    // SABM, UA, DM, DISC frames have no payload beyond FCS
}

// ============================================================================
// Public Entry Point (from rfcomm.h, called by l2cap.rs)
// ============================================================================

/// Decode an RFCOMM frame from the given L2CAP frame.
///
/// This is the public entry point called from `l2cap.rs` when a dynamic
/// channel with PSM 0x0003 is detected.  It clones the L2CAP frame to
/// create a local cursor, then dispatches to the frame decoder.
pub fn rfcomm_packet(frame: &L2capFrame) {
    let mut l2cap_frame = frame.clone();
    rfcomm_frame(&mut l2cap_frame);
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an L2capFrame from raw data bytes for testing.
    fn make_frame(data: &[u8], incoming: bool) -> L2capFrame {
        L2capFrame {
            index: 0,
            in_: incoming,
            handle: 0,
            ident: 0,
            cid: 0x0040,
            psm: 0x0003,
            chan: 0,
            mode: 0,
            seq_num: 0,
            data: data.to_vec(),
            pos: 0,
            size: data.len() as u16,
        }
    }

    #[test]
    fn test_rfcomm_get_type() {
        assert_eq!(rfcomm_get_type(0x2f), RFCOMM_SABM);
        assert_eq!(rfcomm_get_type(0x3f), RFCOMM_SABM); // with P/F bit set
        assert_eq!(rfcomm_get_type(0x63), RFCOMM_UA);
        assert_eq!(rfcomm_get_type(0x73), RFCOMM_UA); // with P/F bit set
        assert_eq!(rfcomm_get_type(0x0f), RFCOMM_DM);
        assert_eq!(rfcomm_get_type(0x43), RFCOMM_DISC);
        assert_eq!(rfcomm_get_type(0xef), RFCOMM_UIH);
        assert_eq!(rfcomm_get_type(0xff), RFCOMM_UIH); // with P/F bit set
    }

    #[test]
    fn test_rfcomm_get_dlci() {
        assert_eq!(rfcomm_get_dlci(0x00), 0);
        assert_eq!(rfcomm_get_dlci(0x04), 1);
        assert_eq!(rfcomm_get_dlci(0x08), 2);
        assert_eq!(rfcomm_get_dlci(0xfc), 63);
    }

    #[test]
    fn test_rfcomm_get_channel() {
        assert_eq!(rfcomm_get_channel(0x00), 0);
        assert_eq!(rfcomm_get_channel(0x08), 1);
        assert_eq!(rfcomm_get_channel(0x10), 2);
        assert_eq!(rfcomm_get_channel(0xf8), 31);
    }

    #[test]
    fn test_rfcomm_get_dir() {
        assert_eq!(rfcomm_get_dir(0x00), 0);
        assert_eq!(rfcomm_get_dir(0x04), 1);
        assert_eq!(rfcomm_get_dir(0x08), 0);
    }

    #[test]
    fn test_rfcomm_test_ea() {
        assert!(rfcomm_test_ea(0x01));
        assert!(rfcomm_test_ea(0x03));
        assert!(!rfcomm_test_ea(0x00));
        assert!(!rfcomm_test_ea(0x02));
    }

    #[test]
    fn test_get_len8() {
        assert_eq!(get_len8(0x01), 0); // EA=1, length=0
        assert_eq!(get_len8(0x03), 1); // EA=1, length=1
        assert_eq!(get_len8(0xff), 127); // EA=1, length=127
    }

    #[test]
    fn test_get_len16() {
        assert_eq!(get_len16(0x0000), 0);
        assert_eq!(get_len16(0x0002), 1);
        assert_eq!(get_len16(0xfffe), 32767);
    }

    #[test]
    fn test_get_pf() {
        assert_eq!(get_pf(0x00), 0);
        assert_eq!(get_pf(0x10), 1);
        assert_eq!(get_pf(0xef), 0); // UIH no PF
        assert_eq!(get_pf(0xff), 1); // UIH with PF
    }

    #[test]
    fn test_rfcomm_type_to_str() {
        assert_eq!(rfcomm_type_to_str(RFCOMM_SABM), "Set Async Balance Mode (SABM)");
        assert_eq!(rfcomm_type_to_str(RFCOMM_UA), "Unnumbered Ack (UA)");
        assert_eq!(rfcomm_type_to_str(RFCOMM_DM), "Disconnect Mode (DM)");
        assert_eq!(rfcomm_type_to_str(RFCOMM_DISC), "Disconnect (DISC)");
        assert_eq!(rfcomm_type_to_str(RFCOMM_UIH), "Unnumbered Info with Header Check (UIH)");
        assert_eq!(rfcomm_type_to_str(0x00), "Unknown");
    }

    #[test]
    fn test_mcc_type_to_str() {
        assert_eq!(mcc_type_to_str(RFCOMM_TEST), "Test Command");
        assert_eq!(mcc_type_to_str(RFCOMM_FCON), "Flow Control On Command");
        assert_eq!(mcc_type_to_str(RFCOMM_FCOFF), "Flow Control Off Command");
        assert_eq!(mcc_type_to_str(RFCOMM_MSC), "Modem Status Command");
        assert_eq!(mcc_type_to_str(RFCOMM_RPN), "Remote Port Negotiation Command");
        assert_eq!(mcc_type_to_str(RFCOMM_RLS), "Remote Line Status");
        assert_eq!(mcc_type_to_str(RFCOMM_PN), "DLC Parameter Negotiation");
        assert_eq!(mcc_type_to_str(RFCOMM_NSC), "Non Supported Command");
        assert_eq!(mcc_type_to_str(0xff), "Unknown");
    }

    #[test]
    fn test_rfcomm_mcc_field_extraction() {
        // CR bit test
        assert!(rfcomm_test_cr(0x02));
        assert!(!rfcomm_test_cr(0x00));
        assert!(rfcomm_test_cr(0x03));

        // MCC type extraction
        assert_eq!(rfcomm_get_mcc_type(0x20), RFCOMM_TEST);
        assert_eq!(rfcomm_get_mcc_type(0x80), RFCOMM_PN);
        assert_eq!(rfcomm_get_mcc_type(0xe0), RFCOMM_MSC);
    }

    #[test]
    fn test_cr_to_str() {
        assert_eq!(cr_to_str(true), "CMD");
        assert_eq!(cr_to_str(false), "RSP");
    }

    #[test]
    fn test_l2cap_frame_get_u8() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03], true);
        assert_eq!(frame.get_u8(), Some(0x01));
        assert_eq!(frame.size, 2);
        assert_eq!(frame.get_u8(), Some(0x02));
        assert_eq!(frame.size, 1);
        assert_eq!(frame.get_u8(), Some(0x03));
        assert_eq!(frame.size, 0);
        assert_eq!(frame.get_u8(), None);
    }

    #[test]
    fn test_l2cap_frame_get_le16() {
        let mut frame = make_frame(&[0x34, 0x12, 0x78, 0x56], true);
        assert_eq!(frame.get_le16(), Some(0x1234));
        assert_eq!(frame.get_le16(), Some(0x5678));
        assert_eq!(frame.get_le16(), None);
    }

    #[test]
    fn test_l2cap_frame_pull() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03, 0x04], true);
        assert!(frame.pull(2));
        assert_eq!(frame.size, 2);
        assert_eq!(frame.remaining_data(), &[0x03, 0x04]);
        assert!(frame.pull(2));
        assert_eq!(frame.size, 0);
        assert!(!frame.pull(1));
    }

    #[test]
    fn test_l2cap_frame_remaining_data() {
        let frame = make_frame(&[0x01, 0x02, 0x03], true);
        assert_eq!(frame.remaining_data(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_rfcomm_packet_too_short() {
        // Frame with only 3 bytes (needs at least 4)
        let frame = make_frame(&[0x03, 0x2f, 0x01], true);
        rfcomm_packet(&frame);
        // Should print "Frame too short" — no panic
    }

    #[test]
    fn test_rfcomm_packet_sabm() {
        // SABM frame: address=0x03, control=0x3f (SABM|PF), length=0x01(EA, len=0), FCS=0x1c
        let frame = make_frame(&[0x03, 0x3f, 0x01, 0x1c], true);
        rfcomm_packet(&frame);
        // Should decode SABM frame without panic
    }

    #[test]
    fn test_rfcomm_packet_ua() {
        // UA frame: address=0x03, control=0x73 (UA|PF), length=0x01(EA, len=0), FCS=0xd7
        let frame = make_frame(&[0x03, 0x73, 0x01, 0xd7], true);
        rfcomm_packet(&frame);
        // Should decode UA frame without panic
    }

    #[test]
    fn test_rfcomm_packet_disc() {
        // DISC frame: address=0x03, control=0x53 (DISC|PF), length=0x01(EA, len=0), FCS=0xfd
        let frame = make_frame(&[0x03, 0x53, 0x01, 0xfd], true);
        rfcomm_packet(&frame);
        // Should decode DISC frame without panic
    }

    #[test]
    fn test_rfcomm_packet_dm() {
        // DM frame: address=0x03, control=0x1f (DM|PF), length=0x01(EA, len=0), FCS=0x5c
        let frame = make_frame(&[0x03, 0x1f, 0x01, 0x5c], true);
        rfcomm_packet(&frame);
        // Should decode DM frame without panic
    }

    #[test]
    fn test_rfcomm_packet_uih_mcc_pn() {
        // UIH on DLCI 0 with MCC PN: address=0x01(DLCI=0, CR=0), control=0xef(UIH),
        // length=0x11(EA, len=8+2=10 bytes MCC overhead)
        // MCC: type=0x83(PN|CR), len=0x11(EA, len=8)
        // PN: dlci=0x01, flow_ctrl=0xe0, priority=0x07, ack_timer=0x00,
        //     frame_size=0x40,0x01 (320 LE), max_retrans=0x00, credits=0x07
        // FCS=0xaa
        let data: Vec<u8> = vec![
            0x01, 0xef, 0x15, // address, control, length(EA, len=10)
            0x83, 0x11, // MCC type=PN|CR, length(EA, len=8)
            0x01, 0xe0, 0x07, 0x00, 0x40, 0x01, 0x00, 0x07, // PN params
            0xaa, // FCS
        ];
        let frame = make_frame(&data, true);
        rfcomm_packet(&frame);
        // Should decode PN parameters without panic
    }

    #[test]
    fn test_rfcomm_packet_uih_data_with_credits() {
        // UIH on DLCI > 0 with PF (credits): address=0x09(DLCI=2, channel=1, dir=0),
        // control=0xff(UIH|PF), length=0x05(EA, len=2), credits=0x0a,
        // data=0xde,0xad, FCS=0xbb
        let data: Vec<u8> = vec![
            0x09, 0xff, 0x05, // address(DLCI=2), control(UIH|PF), length(EA, len=2)
            0x0a, 0xde, 0xad, // credits=10, data bytes
            0xbb, // FCS
        ];
        let frame = make_frame(&data, false);
        rfcomm_packet(&frame);
        // Should decode credits + hexdump data without panic
    }

    #[test]
    fn test_rfcomm_packet_unknown_type() {
        // Unknown frame type: control=0x01 -> type = 0x01 & 0xef = 0x01 (unknown)
        let frame = make_frame(&[0x03, 0x01, 0x01, 0x00], true);
        rfcomm_packet(&frame);
        // Should hexdump without crash
    }

    #[test]
    fn test_rfcomm_packet_two_byte_length() {
        // UIH with 2-byte length field: address=0x01, control=0xef,
        // first_len=0x00 (EA=0, meaning 2-byte), second_len=0x02 (total 15-bit len=1)
        // + 1 byte payload + FCS
        let data: Vec<u8> = vec![
            0x01, 0xef, 0x02, 0x00, // address, control, length(2-byte, len=1)
            0x41, // 1 byte payload
            0xcc, // FCS
        ];
        let frame = make_frame(&data, true);
        rfcomm_packet(&frame);
        // Should handle 2-byte length correctly without panic
    }
}
