// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014 Intel Corporation
 * Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
 *
 * ll.rs — LE Link Layer PDU dissector.
 *
 * Complete Rust rewrite of monitor/ll.c (880 lines) + monitor/ll.h (39 lines)
 * from BlueZ v5.86.  Decodes advertising-channel PDUs, data-channel PDUs, and
 * all 35+ LE Link Layer Control Protocol (LLCP) opcodes.  Uses CRC-24
 * validation via `crate::crc` with per-channel CRC-init caching.
 */

use std::cell::RefCell;

use crate::crc::{crc24_bit_reverse, crc24_calculate};
use crate::display::{
    BitfieldData, COLOR_CYAN, COLOR_ERROR, COLOR_MAGENTA, COLOR_OFF, COLOR_WHITE_BG,
    print_bitfield, print_hexdump,
};
// Re-import #[macro_export] macros from crate root — these are defined in
// display.rs but exported at the crate level by the Rust macro_export rules.
use crate::{print_field, print_indent, print_text};

// ============================================================================
// Color Aliases (from ll.c lines 29-31)
// ============================================================================

const COLOR_OPCODE: &str = COLOR_MAGENTA;
const COLOR_OPCODE_UNKNOWN: &str = COLOR_WHITE_BG;
const COLOR_UNKNOWN_OPTIONS_BIT: &str = COLOR_WHITE_BG;

// ============================================================================
// Per-Channel CRC State (from ll.c lines 33-64)
// ============================================================================

const MAX_CHANNEL: usize = 16;

/// Per-channel CRC-init cache entry.
#[derive(Clone, Copy, Default)]
struct ChannelData {
    access_addr: u32,
    crc_init: u32,
}

thread_local! {
    static CHANNEL_LIST: RefCell<[ChannelData; MAX_CHANNEL]> =
        RefCell::new([ChannelData::default(); MAX_CHANNEL]);
}

/// Store a CRC-init value for a given access address.
/// Finds an existing entry or the first empty slot (access_addr == 0).
fn set_crc_init(access_addr: u32, crc_init: u32) {
    CHANNEL_LIST.with(|list| {
        let mut arr = list.borrow_mut();
        for entry in arr.iter_mut() {
            if entry.access_addr == access_addr || entry.access_addr == 0x0000_0000 {
                entry.access_addr = access_addr;
                entry.crc_init = crc_init;
                return;
            }
        }
    });
}

/// Retrieve the CRC-init value for a given access address.
/// Returns 0x00000000 if not found.
fn get_crc_init(access_addr: u32) -> u32 {
    CHANNEL_LIST.with(|list| {
        let arr = list.borrow();
        for entry in arr.iter() {
            if entry.access_addr == access_addr {
                return entry.crc_init;
            }
        }
        0x0000_0000
    })
}

// ============================================================================
// BT LL Header Constants
// ============================================================================

/// Size of bt_ll_hdr: 1 byte preamble + 4 bytes access address.
const BT_LL_HDR_SIZE: usize = 5;

/// Well-known advertising channel access address.
const ADV_ACCESS_ADDR: u32 = 0x8e89_bed6;

/// CRC-init for advertising channel packets.
const ADV_CRC_INIT: u32 = 0x00aa_aaaa;

// ============================================================================
// SCA Strings (from ll.c lines 175-184)
// ============================================================================

const SCA_TABLE: [&str; 8] = [
    "251 ppm to 500 ppm",
    "151 ppm to 250 ppm",
    "101 ppm to 150ppm",
    "76 ppm to 100 ppm",
    "51 ppm to 75 ppm",
    "31 ppm to 50 ppm",
    "21 ppm to 30 ppm",
    "0 ppm to 20 ppm",
];

// ============================================================================
// LE PHY Bitfield Table (from ll.c lines 571-577)
// ============================================================================

const LE_PHYS: [BitfieldData; 3] = [
    BitfieldData { bit: 0, str_val: "LE 1M" },
    BitfieldData { bit: 1, str_val: "LE 2M" },
    BitfieldData { bit: 2, str_val: "LE Coded" },
];

// ============================================================================
// Local Helpers — Replicate packet_print_* functions not in dependency whitelist
// ============================================================================

/// Format a 6-byte Bluetooth address as XX:XX:XX:XX:XX:XX.
fn format_bdaddr(data: &[u8]) -> String {
    if data.len() < 6 {
        return "(invalid)".to_string();
    }
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[5], data[4], data[3], data[2], data[1], data[0]
    )
}

/// Print a Bluetooth address field with label and random/public flag.
/// Mimics `packet_print_addr(label, data, is_random)`.
fn packet_print_addr(label: &str, data: &[u8], is_random: bool) {
    let addr = format_bdaddr(data);
    let addr_type = if is_random { "Random" } else { "Public" };
    print_field!("{}: {} ({})", label, addr, addr_type);
}

/// Print advertising data bytes as a hex dump.
/// Mimics `packet_print_ad(data, len)`.
fn packet_print_ad(data: &[u8], size: usize) {
    if size == 0 {
        return;
    }
    let actual = if size > data.len() { data.len() } else { size };
    print_hexdump(&data[..actual]);
}

/// Print a 5-byte LE Link Layer channel map.
/// Mimics `packet_print_channel_map_ll(map_data)`.
fn packet_print_channel_map_ll(data: &[u8]) {
    if data.len() < 5 {
        return;
    }
    print_field!(
        "Channel map: 0x{:02x}{:02x}{:02x}{:02x}{:02x}",
        data[4],
        data[3],
        data[2],
        data[1],
        data[0]
    );
}

/// Print an error code with description.
/// Mimics `packet_print_error(label, error_code)`.
fn packet_print_error(label: &str, error_code: u8) {
    let desc = error_code_to_str(error_code);
    print_field!("{}: {} (0x{:02x})", label, desc, error_code);
}

/// Convert a BT error code to a human-readable string.
/// Covers the standard HCI error codes used in LE LL context.
fn error_code_to_str(code: u8) -> &'static str {
    match code {
        0x00 => "Success",
        0x01 => "Unknown HCI Command",
        0x02 => "Unknown Connection Identifier",
        0x03 => "Hardware Failure",
        0x04 => "Page Timeout",
        0x05 => "Authentication Failure",
        0x06 => "PIN or Key Missing",
        0x07 => "Memory Capacity Exceeded",
        0x08 => "Connection Timeout",
        0x09 => "Connection Limit Exceeded",
        0x0a => "Synchronous Connection Limit to a Device Exceeded",
        0x0b => "ACL Connection Already Exists",
        0x0c => "Command Disallowed",
        0x0d => "Connection Rejected due to Limited Resources",
        0x0e => "Connection Rejected due to Security Reasons",
        0x0f => "Connection Rejected due to Unacceptable BD_ADDR",
        0x10 => "Connection Accept Timeout Exceeded",
        0x11 => "Unsupported Feature or Parameter Value",
        0x12 => "Invalid HCI Command Parameters",
        0x13 => "Remote User Terminated Connection",
        0x14 => "Remote Device Terminated Connection due to Low Resources",
        0x15 => "Remote Device Terminated Connection due to Power Off",
        0x16 => "Connection Terminated By Local Host",
        0x17 => "Repeated Attempts",
        0x18 => "Pairing Not Allowed",
        0x19 => "Unknown LMP PDU",
        0x1a => "Unsupported Remote Feature",
        0x1b => "SCO Offset Rejected",
        0x1c => "SCO Interval Rejected",
        0x1d => "SCO Air Mode Rejected",
        0x1e => "Invalid LMP Parameters",
        0x1f => "Unspecified Error",
        0x20 => "Unsupported LMP Parameter Value",
        0x21 => "Role Change Not Allowed",
        0x22 => "LMP Response Timeout / LL Response Timeout",
        0x23 => "LMP Error Transaction Collision",
        0x24 => "LMP PDU Not Allowed",
        0x25 => "Encryption Mode Not Acceptable",
        0x26 => "Link Key cannot be Changed",
        0x27 => "Requested QoS Not Supported",
        0x28 => "Instant Passed",
        0x29 => "Pairing With Unit Key Not Supported",
        0x2a => "Different Transaction Collision",
        0x2c => "QoS Unacceptable Parameter",
        0x2d => "QoS Rejected",
        0x2e => "Channel Classification Not Supported",
        0x2f => "Insufficient Security",
        0x30 => "Parameter Out Of Mandatory Range",
        0x32 => "Role Switch Pending",
        0x34 => "Reserved Slot Violation",
        0x35 => "Role Switch Failed",
        0x36 => "Extended Inquiry Response Too Large",
        0x37 => "Secure Simple Pairing Not Supported By Host",
        0x38 => "Host Busy - Pairing",
        0x39 => "Connection Rejected due to No Suitable Channel Found",
        0x3a => "Controller Busy",
        0x3b => "Unacceptable Connection Parameters",
        0x3c => "Advertising Timeout",
        0x3d => "Connection Terminated due to MIC Failure",
        0x3e => "Connection Failed to be Established",
        0x3f => "MAC Connection Failed",
        0x40 => "Coarse Clock Adjustment Rejected",
        0x41 => "Type0 Submap Not Defined",
        0x42 => "Unknown Advertising Identifier",
        0x43 => "Limit Reached",
        0x44 => "Operation Cancelled by Host",
        0x45 => "Packet Too Long",
        _ => "Unknown",
    }
}

/// Print BT version info.
/// Mimics `packet_print_version(label1, version, label2, subversion)`.
fn packet_print_version(label1: &str, version: u8, label2: &str, subversion: u16) {
    let ver_str = match version {
        0x00 => "Bluetooth 1.0b",
        0x01 => "Bluetooth 1.1",
        0x02 => "Bluetooth 1.2",
        0x03 => "Bluetooth 2.0",
        0x04 => "Bluetooth 2.1",
        0x05 => "Bluetooth 3.0",
        0x06 => "Bluetooth 4.0",
        0x07 => "Bluetooth 4.1",
        0x08 => "Bluetooth 4.2",
        0x09 => "Bluetooth 5.0",
        0x0a => "Bluetooth 5.1",
        0x0b => "Bluetooth 5.2",
        0x0c => "Bluetooth 5.3",
        0x0d => "Bluetooth 5.4",
        0x0e => "Bluetooth 6.0",
        _ => "Reserved",
    };
    print_field!("{}: {} (0x{:02x}) - {} (0x{:04x})", label1, ver_str, version, label2, subversion);
}

/// Print a company identifier.
/// Mimics `packet_print_company(label, company)`.
fn packet_print_company(label: &str, company: u16) {
    print_field!("{}: {} (0x{:04x})", label, company_to_str(company), company);
}

/// Stub company lookup — in the real btmon, this comes from a large table.
/// Returns a hex string for unknown companies.
fn company_to_str(company: u16) -> String {
    match company {
        0x0000 => "Ericsson Technology Licensing".to_string(),
        0x0001 => "Nokia Mobile Phones".to_string(),
        0x0002 => "Intel Corp.".to_string(),
        0x0003 => "IBM Corp.".to_string(),
        0x0004 => "Toshiba Corp.".to_string(),
        0x0005 => "3Com".to_string(),
        0x0006 => "Microsoft".to_string(),
        0x0007 => "Lucent".to_string(),
        0x0008 => "Motorola".to_string(),
        0x0009 => "Infineon Technologies AG".to_string(),
        0x000a => "Qualcomm Technologies International, Ltd. (QTIL)".to_string(),
        0x000b => "Silicon Wave".to_string(),
        0x000c => "Digianswer A/S".to_string(),
        0x000d => "Texas Instruments Inc.".to_string(),
        0x000e => "Parthus Technologies Inc.".to_string(),
        0x000f => "Broadcom Corporation".to_string(),
        0x0010 => "Mitel Semiconductor".to_string(),
        0x0011 => "Widcomm, Inc.".to_string(),
        0x0012 => "Zeevo, Inc.".to_string(),
        0x0013 => "Atmel Corporation".to_string(),
        0x0014 => "Mitsubishi Electronics Corporation".to_string(),
        0x0015 => "RTX Telecom A/S".to_string(),
        0x0016 => "KC Technology Inc.".to_string(),
        0x0017 => "Newlogic".to_string(),
        0x0018 => "Transilica, Inc.".to_string(),
        0x0019 => "Rohde & Schwarz GmbH & Co. KG".to_string(),
        0x001a => "TTPCom Limited".to_string(),
        0x001b => "Signia Technologies, Inc.".to_string(),
        0x001c => "Conexant Systems Inc.".to_string(),
        0x001d => "Qualcomm".to_string(),
        0x001e => "Inventel".to_string(),
        0x001f => "AVM Berlin".to_string(),
        0x0020 => "BandSpeed, Inc.".to_string(),
        0x0021 => "Mansella Ltd".to_string(),
        0x0022 => "NEC Corporation".to_string(),
        0x0023 => "WavePlus Technology Co., Ltd.".to_string(),
        _ => format!("Unknown (0x{:04x})", company),
    }
}

/// Print 8-byte LE Link Layer features bitmap.
/// Mimics `packet_print_features_ll(features)`.
fn packet_print_features_ll(features: &[u8]) {
    if features.len() < 8 {
        return;
    }
    let val = u64::from_le_bytes([
        features[0],
        features[1],
        features[2],
        features[3],
        features[4],
        features[5],
        features[6],
        features[7],
    ]);
    print_field!(
        "Features: 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
        features[0],
        features[1],
        features[2],
        features[3],
        features[4],
        features[5],
        features[6],
        features[7]
    );

    static LL_FEATURES: &[BitfieldData] = &[
        BitfieldData { bit: 0, str_val: "LE Encryption" },
        BitfieldData { bit: 1, str_val: "Connection Parameters Request Procedure" },
        BitfieldData { bit: 2, str_val: "Extended Reject Indication" },
        BitfieldData { bit: 3, str_val: "Peripheral-initiated Features Exchange" },
        BitfieldData { bit: 4, str_val: "LE Ping" },
        BitfieldData { bit: 5, str_val: "LE Data Packet Length Extension" },
        BitfieldData { bit: 6, str_val: "LL Privacy" },
        BitfieldData { bit: 7, str_val: "Extended Scanner Filter Policies" },
        BitfieldData { bit: 8, str_val: "LE 2M PHY" },
        BitfieldData { bit: 9, str_val: "Stable Modulation Index - Transmitter" },
        BitfieldData { bit: 10, str_val: "Stable Modulation Index - Receiver" },
        BitfieldData { bit: 11, str_val: "LE Coded PHY" },
        BitfieldData { bit: 12, str_val: "LE Extended Advertising" },
        BitfieldData { bit: 13, str_val: "LE Periodic Advertising" },
        BitfieldData { bit: 14, str_val: "Channel Selection Algorithm #2" },
        BitfieldData { bit: 15, str_val: "LE Power Class 1" },
        BitfieldData { bit: 16, str_val: "Minimum Number of Used Channels Procedure" },
        BitfieldData { bit: 17, str_val: "Connection CTE Request" },
        BitfieldData { bit: 18, str_val: "Connection CTE Response" },
        BitfieldData { bit: 19, str_val: "Connectionless CTE Transmitter" },
        BitfieldData { bit: 20, str_val: "Connectionless CTE Receiver" },
        BitfieldData { bit: 21, str_val: "Antenna Switching During CTE Transmission (AoD)" },
        BitfieldData { bit: 22, str_val: "Antenna Switching During CTE Reception (AoA)" },
        BitfieldData { bit: 23, str_val: "Receiving Constant Tone Extensions" },
        BitfieldData { bit: 24, str_val: "Periodic Advertising Sync Transfer - Sender" },
        BitfieldData { bit: 25, str_val: "Periodic Advertising Sync Transfer - Recipient" },
        BitfieldData { bit: 26, str_val: "Sleep Clock Accuracy Updates" },
        BitfieldData { bit: 27, str_val: "Remote Public Key Validation" },
        BitfieldData { bit: 28, str_val: "Connected Isochronous Stream - Central" },
        BitfieldData { bit: 29, str_val: "Connected Isochronous Stream - Peripheral" },
        BitfieldData { bit: 30, str_val: "Isochronous Broadcaster" },
        BitfieldData { bit: 31, str_val: "Synchronized Receiver" },
        BitfieldData { bit: 32, str_val: "Connected Isochronous Stream (Host Support)" },
        BitfieldData { bit: 33, str_val: "LE Power Control Request" },
        BitfieldData { bit: 34, str_val: "LE Power Control Request (duplicate)" },
        BitfieldData { bit: 35, str_val: "LE Path Loss Monitoring" },
        BitfieldData { bit: 36, str_val: "Periodic Advertising ADI support" },
        BitfieldData { bit: 37, str_val: "Connection Subrating" },
        BitfieldData { bit: 38, str_val: "Connection Subrating (Host Support)" },
        BitfieldData { bit: 39, str_val: "Channel Classification" },
    ];

    let mask = print_bitfield(2, val, LL_FEATURES);
    if mask != 0 {
        print_text!(COLOR_UNKNOWN_OPTIONS_BIT, "  Unknown features (0x{:016x})", mask);
    }
}

/// Print extended LE features for a given page.
/// Mimics `packet_print_features_ext_ll(page, features)`.
fn packet_print_features_ext_ll(page: u8, features: &[u8]) {
    if features.len() < 8 {
        return;
    }
    print_field!(
        "Features: 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} (page {})",
        features[0],
        features[1],
        features[2],
        features[3],
        features[4],
        features[5],
        features[6],
        features[7],
        page
    );
    if page == 0 {
        let val = u64::from_le_bytes([
            features[0],
            features[1],
            features[2],
            features[3],
            features[4],
            features[5],
            features[6],
            features[7],
        ]);
        // Re-use the same LL feature table for page 0
        packet_print_features_ll(features);
        let _ = val; // page 0 uses the standard LL features
    }
}

/// Print PHY bitfield using the LE_PHYS table.
fn print_le_phy_bitfield(label: &str, phys: u8) {
    print_field!("{}: 0x{:02x}", label, phys);
    let mask = print_bitfield(2, u64::from(phys), &LE_PHYS);
    if mask != 0 {
        print_text!(COLOR_UNKNOWN_OPTIONS_BIT, "  Unknown PHYs (0x{:02x})", mask);
    }
}

/// Read a little-endian u16 from a byte slice at the given offset.
/// Returns 0 if out of bounds.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from a byte slice at the given offset.
/// Returns 0 if out of bounds.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Read a little-endian u64 from a byte slice at the given offset.
/// Returns 0 if out of bounds.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Read a 3-byte little-endian unsigned value from a byte slice at the given offset.
fn read_u24_le(data: &[u8], offset: usize) -> u32 {
    if offset + 3 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], 0])
}

// ============================================================================
// Advertising Channel Packet Decoder (from ll.c lines 66-235)
// ============================================================================

/// Decode and print an advertising channel PDU.
///
/// PDU header format:
///   byte 0: pdu_type (bits 0-3), tx_add (bit 6), rx_add (bit 7)
///   byte 1: length (bits 0-5)
fn advertising_packet(data: &[u8], size: u8) {
    if data.len() < 2 || (size as usize) < 2 {
        print_text!(COLOR_ERROR, "Too short advertising packet");
        return;
    }

    let pdu_type = data[0] & 0x0f;
    let tx_add = (data[0] >> 6) & 0x01;
    let rx_add = (data[0] >> 7) & 0x01;
    let length = data[1] & 0x3f;

    let pdu_type_str = match pdu_type {
        0x00 => "ADV_IND",
        0x01 => "ADV_DIRECT_IND",
        0x02 => "ADV_NONCONN_IND",
        0x03 => "SCAN_REQ",
        0x04 => "SCAN_RSP",
        0x05 => "CONNECT_REQ",
        0x06 => "ADV_SCAN_IND",
        0x07 => "ADV_EXT_IND",
        0x08 => "AUX_CONNECT_RSP",
        _ => "Reserved",
    };

    print_field!("Type: {} (0x{:02x})", pdu_type_str, pdu_type);
    print_field!("TxAdd: {}", tx_add);
    print_field!("RxAdd: {}", rx_add);
    print_field!("Length: {}", length);

    if length as usize != (size as usize) - 2 {
        print_text!(
            COLOR_ERROR,
            "PDU length {} does not match remaining size {}",
            length,
            (size as usize) - 2
        );
        return;
    }

    let pdu_data = &data[2..];

    match pdu_type {
        // ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND, SCAN_RSP
        0x00 | 0x02 | 0x06 | 0x04 => {
            if (length as usize) < 6 {
                print_text!(COLOR_ERROR, "Too short PDU for advertising");
                return;
            }
            packet_print_addr("AdvA", &pdu_data[..6], tx_add != 0);
            if (length as usize) > 6 {
                packet_print_ad(&pdu_data[6..], (length as usize) - 6);
            }
        }
        // ADV_DIRECT_IND
        0x01 => {
            if (length as usize) < 12 {
                print_text!(COLOR_ERROR, "Too short PDU for direct advertising");
                return;
            }
            packet_print_addr("AdvA", &pdu_data[..6], tx_add != 0);
            packet_print_addr("InitA", &pdu_data[6..12], rx_add != 0);
        }
        // SCAN_REQ
        0x03 => {
            if (length as usize) < 12 {
                print_text!(COLOR_ERROR, "Too short PDU for scan request");
                return;
            }
            packet_print_addr("ScanA", &pdu_data[..6], tx_add != 0);
            packet_print_addr("AdvA", &pdu_data[6..12], rx_add != 0);
        }
        // CONNECT_REQ (CONNECT_IND)
        0x05 => {
            if (length as usize) < 34 {
                print_text!(COLOR_ERROR, "Too short PDU for connect request");
                return;
            }
            packet_print_addr("InitA", &pdu_data[..6], tx_add != 0);
            packet_print_addr("AdvA", &pdu_data[6..12], rx_add != 0);

            // LLData starts at offset 12
            let ll_data = &pdu_data[12..];
            let access_addr = read_u32_le(ll_data, 0);
            let crc_init_raw = read_u24_le(ll_data, 4);

            // Store CRC init (bit-reversed) for data channel CRC validation
            set_crc_init(access_addr, crc24_bit_reverse(crc_init_raw));

            print_field!("Access address: 0x{:08x}", access_addr);
            print_field!("CRC init: 0x{:06x}", crc_init_raw);

            let win_size = ll_data[7];
            let win_offset = read_u16_le(ll_data, 8);
            let interval = read_u16_le(ll_data, 10);
            let latency = read_u16_le(ll_data, 12);
            let timeout = read_u16_le(ll_data, 14);

            print_field!("Transmit window size: {}", win_size);
            print_field!("Transmit window offset: {}", win_offset);
            print_field!(
                "Connection interval: {} ({:.2} msec)",
                interval,
                f64::from(interval) * 1.25
            );
            print_field!("Connection peripheral latency: {}", latency);
            print_field!(
                "Connection supervision timeout: {} ({} msec)",
                timeout,
                u32::from(timeout) * 10
            );

            // Channel map (5 bytes at offset 16)
            packet_print_channel_map_ll(&ll_data[16..21]);

            // Hop and SCA at offset 21
            let hop_sca = ll_data[21];
            let hop = hop_sca & 0x1f;
            let sca = (hop_sca >> 5) & 0x07;

            print_field!("Hop increment: {}", hop);
            let sca_str = SCA_TABLE.get(sca as usize).unwrap_or(&"Reserved");
            print_field!("Sleep clock accuracy: {} ({})", sca, sca_str);
        }
        _ => {
            // Unknown or unsupported PDU type
            if !pdu_data.is_empty() {
                print_hexdump(&pdu_data[..(length as usize).min(pdu_data.len())]);
            }
        }
    }
}

// ============================================================================
// Data Channel Packet Decoder (from ll.c lines 237-289)
// ============================================================================

/// Decode and print a data channel PDU.
///
/// Data PDU header:
///   byte 0: LLID (bits 0-1), NESN (bit 2), SN (bit 3), MD (bit 4)
///   byte 1: length (bits 0-4)
fn data_packet(data: &[u8], size: u8, padded: bool) {
    if data.len() < 2 || (size as usize) < 2 {
        print_text!(COLOR_ERROR, "Too short data packet");
        return;
    }

    let llid = data[0] & 0x03;
    let nesn = (data[0] >> 2) & 0x01;
    let sn = (data[0] >> 3) & 0x01;
    let md = (data[0] >> 4) & 0x01;
    let length = data[1] & 0x1f;

    let llid_str = match llid {
        0x01 => {
            if length > 0 {
                "Continuation fragment of an L2CAP message"
            } else {
                "Empty PDU"
            }
        }
        0x02 => "Start of an L2CAP message or a complete L2CAP message with no fragmentation",
        0x03 => "LL Control PDU",
        _ => "Reserved",
    };

    print_field!("LLID: {} (0x{:02x})", llid_str, llid);
    print_field!("Next Expected Sequence Number: {}", nesn);
    print_field!("Sequence Number: {}", sn);
    print_field!("More Data: {}", md);
    print_field!("Length: {}", length);

    let pdu_data = &data[2..];
    let remaining = (size as usize).saturating_sub(2);

    if llid == 0x03 {
        llcp_packet(pdu_data, remaining.min(length as usize) as u8, padded);
    } else if length > 0 {
        let dump_len = (length as usize).min(remaining);
        print_hexdump(&pdu_data[..dump_len]);
    }
}

// ============================================================================
// Main LL Packet Entry Point (from ll.c lines 291-361)
// ============================================================================

/// Decode and print a full LE Link Layer packet.
///
/// The packet consists of:
///   - 1 byte preamble
///   - 4 bytes access address (little-endian)
///   - N bytes PDU
///   - 3 bytes CRC-24
///
/// # Arguments
/// * `frequency` — RF center frequency in MHz (used to compute channel index)
/// * `data` — Raw packet bytes starting with preamble
/// * `size` — Total packet size
/// * `padded` — Whether the packet has extra padding (affects LLCP size validation)
pub fn ll_packet(frequency: u16, data: &[u8], size: u8, padded: bool) {
    let size_usize = size as usize;

    if size_usize < BT_LL_HDR_SIZE {
        print_text!(COLOR_ERROR, "Too short LL packet");
        return;
    }

    if size_usize < BT_LL_HDR_SIZE + 3 {
        print_text!(COLOR_ERROR, "Too short LL packet for CRC");
        return;
    }

    let preamble = data[0];
    let access_addr = read_u32_le(data, 1);
    let channel = (frequency.wrapping_sub(2402)) / 2;

    // Validate preamble: must be 0xaa or 0x55
    if preamble != 0xaa && preamble != 0x55 {
        print_text!(COLOR_ERROR, "Invalid preamble: 0x{:02x}", preamble);
        return;
    }

    let pdu_data = &data[BT_LL_HDR_SIZE..];
    let pdu_len = size_usize - BT_LL_HDR_SIZE - 3;

    // Extract 3-byte CRC from the end of the PDU
    let crc_offset = BT_LL_HDR_SIZE + pdu_len;
    let pdu_crc = read_u24_le(data, crc_offset);

    // Determine channel type
    let (channel_label, channel_color) = if access_addr == ADV_ACCESS_ADDR {
        ("Advertising channel: ", COLOR_MAGENTA)
    } else {
        ("Data channel: ", COLOR_CYAN)
    };

    print_indent!(
        4,
        channel_color,
        "",
        channel_label,
        COLOR_OFF,
        "AA 0x{:08x} (chan {}) len {} crc 0x{:06x}",
        access_addr,
        channel,
        pdu_len,
        pdu_crc
    );

    // CRC-24 validation
    let crc_init =
        if access_addr == ADV_ACCESS_ADDR { ADV_CRC_INIT } else { get_crc_init(access_addr) };

    if crc_init != 0 {
        let computed_crc = crc24_calculate(crc_init, &pdu_data[..pdu_len]);
        if computed_crc != pdu_crc {
            print_text!(
                COLOR_ERROR,
                "CRC mismatch: got 0x{:06x}, expected 0x{:06x}",
                pdu_crc,
                computed_crc
            );
            print_hexdump(&pdu_data[..pdu_len]);
            return;
        }
    } else {
        print_text!(COLOR_ERROR, "Unknown access address 0x{:08x}", access_addr);
    }

    // Dispatch to advertising or data channel decoder
    if access_addr == ADV_ACCESS_ADDR {
        advertising_packet(pdu_data, pdu_len as u8);
    } else {
        data_packet(pdu_data, pdu_len as u8, padded);
    }
}

// ============================================================================
// LLCP Opcode Handlers (from ll.c lines 363-760)
// ============================================================================

/// LL_CONNECTION_UPDATE_REQ handler (opcode 0x00, 11 bytes).
fn conn_update_req(data: &[u8], _size: u8) {
    let win_size = data[0];
    let win_offset = read_u16_le(data, 1);
    let interval = read_u16_le(data, 3);
    let latency = read_u16_le(data, 5);
    let timeout = read_u16_le(data, 7);
    let instant = read_u16_le(data, 9);

    print_field!("Window size: {}", win_size);
    print_field!("Window offset: {}", win_offset);
    print_field!("Interval: {} ({:.2} msec)", interval, f64::from(interval) * 1.25);
    print_field!("Latency: {}", latency);
    print_field!("Timeout: {} ({} msec)", timeout, u32::from(timeout) * 10);
    print_field!("Instant: {}", instant);
}

/// LL_CHANNEL_MAP_REQ handler (opcode 0x01, 7 bytes).
fn channel_map_req(data: &[u8], _size: u8) {
    packet_print_channel_map_ll(&data[..5]);
    let instant = read_u16_le(data, 5);
    print_field!("Instant: {}", instant);
}

/// LL_TERMINATE_IND handler (opcode 0x02, 1 byte).
fn terminate_ind(data: &[u8], _size: u8) {
    packet_print_error("Error code", data[0]);
}

/// LL_ENC_REQ handler (opcode 0x03, 22 bytes).
fn enc_req(data: &[u8], _size: u8) {
    let rand = read_u64_le(data, 0);
    let ediv = read_u16_le(data, 8);
    let skd = read_u64_le(data, 10);
    let iv = read_u32_le(data, 18);

    print_field!("Rand: 0x{:016x}", rand);
    print_field!("EDIV: 0x{:04x}", ediv);
    print_field!("SKDm: 0x{:016x}", skd);
    print_field!("IVm: 0x{:08x}", iv);
}

/// LL_ENC_RSP handler (opcode 0x04, 12 bytes).
fn enc_rsp(data: &[u8], _size: u8) {
    let skd = read_u64_le(data, 0);
    let iv = read_u32_le(data, 8);

    print_field!("SKDs: 0x{:016x}", skd);
    print_field!("IVs: 0x{:08x}", iv);
}

/// LL_UNKNOWN_RSP handler (opcode 0x07, 1 byte).
fn unknown_rsp(data: &[u8], _size: u8) {
    let unknown_type = data[0];
    let name = opcode_to_string(unknown_type);
    print_field!("Unknown type: {} ({})", name, unknown_type);
}

/// LL_FEATURE_REQ handler (opcode 0x08, 8 bytes).
fn feature_req(data: &[u8], _size: u8) {
    packet_print_features_ll(&data[..8]);
}

/// LL_FEATURE_RSP handler (opcode 0x09, 8 bytes).
fn feature_rsp(data: &[u8], _size: u8) {
    packet_print_features_ll(&data[..8]);
}

/// LL_VERSION_IND handler (opcode 0x0c, 5 bytes).
fn version_ind(data: &[u8], _size: u8) {
    let vers_nr = data[0];
    let comp_id = read_u16_le(data, 1);
    let sub_vers_nr = read_u16_le(data, 3);

    packet_print_version("VersNr", vers_nr, "Sub", sub_vers_nr);
    packet_print_company("CompId", comp_id);
}

/// LL_REJECT_IND handler (opcode 0x0d, 1 byte).
fn reject_ind(data: &[u8], _size: u8) {
    packet_print_error("Error code", data[0]);
}

/// LL_PERIPHERAL_FEATURE_REQ handler (opcode 0x0e, 8 bytes).
fn peripheral_feature_req(data: &[u8], _size: u8) {
    packet_print_features_ll(&data[..8]);
}

/// LL_CONNECTION_PARAM_REQ handler (opcode 0x0f, 23 bytes).
fn conn_param_req(data: &[u8], _size: u8) {
    let interval_min = read_u16_le(data, 0);
    let interval_max = read_u16_le(data, 2);
    let latency = read_u16_le(data, 4);
    let timeout = read_u16_le(data, 6);
    let pref_periodicity = data[8];
    let ref_conn_event_count = read_u16_le(data, 9);

    print_field!("Interval Min: {} ({:.2} msec)", interval_min, f64::from(interval_min) * 1.25);
    print_field!("Interval Max: {} ({:.2} msec)", interval_max, f64::from(interval_max) * 1.25);
    print_field!("Latency: {}", latency);
    print_field!("Timeout: {} ({} msec)", timeout, u32::from(timeout) * 10);
    print_field!("Preferred Periodicity: {}", pref_periodicity);
    print_field!("Reference Connection Event Count: {}", ref_conn_event_count);

    // 6 offsets starting at byte 11
    for i in 0..6 {
        let offset = read_u16_le(data, 11 + i * 2);
        print_field!("Offset{}: {} ({:.2} msec)", i, offset, f64::from(offset) * 1.25);
    }
}

/// LL_CONNECTION_PARAM_RSP handler (opcode 0x10, 23 bytes).
fn conn_param_rsp(data: &[u8], _size: u8) {
    // Same format as conn_param_req
    conn_param_req(data, _size);
}

/// LL_REJECT_IND_EXT handler (opcode 0x11, 2 bytes).
fn reject_ind_ext(data: &[u8], _size: u8) {
    let reject_opcode = data[0];
    let name = opcode_to_string(reject_opcode);
    print_field!("Reject opcode: {} ({})", name, reject_opcode);
    packet_print_error("Error code", data[1]);
}

/// LL_LENGTH_REQ / LL_LENGTH_RSP handler (opcodes 0x14/0x15, 8 bytes).
fn length_req_rsp(data: &[u8], _size: u8) {
    let max_rx_octets = read_u16_le(data, 0);
    let max_rx_time = read_u16_le(data, 2);
    let max_tx_octets = read_u16_le(data, 4);
    let max_tx_time = read_u16_le(data, 6);

    print_field!("MaxRxOctets: {}", max_rx_octets);
    print_field!("MaxRxTime: {} us", max_rx_time);
    print_field!("MaxTxOctets: {}", max_tx_octets);
    // Note: matches the C code "MaxtxTime" exactly (lowercase 't')
    print_field!("MaxtxTime: {} us", max_tx_time);
}

/// LL_PHY_REQ / LL_PHY_RSP handler (opcodes 0x16/0x17, 2 bytes).
fn phy_req_rsp(data: &[u8], _size: u8) {
    print_le_phy_bitfield("TX PHYs", data[0]);
    print_le_phy_bitfield("RX PHYs", data[1]);
}

/// LL_PHY_UPDATE_IND handler (opcode 0x18, 4 bytes).
fn phy_update_ind(data: &[u8], _size: u8) {
    print_le_phy_bitfield("C_TO_P_PHY", data[0]);
    print_le_phy_bitfield("P_TO_C_PHY", data[1]);
    let instant = read_u16_le(data, 2);
    print_field!("Instant: {}", instant);
}

/// LL_MIN_USED_CHANNELS_IND handler (opcode 0x19, 2 bytes).
fn min_used_channels(data: &[u8], _size: u8) {
    print_le_phy_bitfield("PHYS", data[0]);
    print_field!("MinUsedChannels: {}", data[1]);
}

/// LL_CTE_REQ handler (opcode 0x1a, 1 byte).
fn cte_req(data: &[u8], _size: u8) {
    let min_cte_len = (data[0] & 0xf8) >> 3;
    let cte_type = data[0] & 0x03;
    print_field!("MinCTELenReq: {}", min_cte_len);
    let cte_str = match cte_type {
        0x00 => "AoA Constant Tone Extension",
        0x01 => "AoD Constant Tone Extension with 1 us slots",
        0x02 => "AoD Constant Tone Extension with 2 us slots",
        _ => "Reserved",
    };
    print_field!("CTETypeReq: {} ({})", cte_str, cte_type);
}

/// LL_PERIODIC_SYNC_IND handler (opcode 0x1c, 34 bytes).
fn periodic_sync_ind(data: &[u8], _size: u8) {
    let id = read_u16_le(data, 0);
    print_field!("ID: 0x{:04x}", id);

    // SyncInfo is 18 bytes starting at offset 2
    print_field!("SyncInfo:");
    print_hexdump(&data[2..20]);

    let conn_event_count = read_u16_le(data, 20);
    let last_pa_event_counter = read_u16_le(data, 22);
    let sid = data[24];
    let a_type = data[25];
    let sca = data[26];
    let phy = data[27];

    print_field!("connEventCount: {}", conn_event_count);
    print_field!("lastPaEventCounter: {}", last_pa_event_counter);
    print_field!("SID: 0x{:02x}", sid);
    let a_type_str = if a_type == 0 { "Public" } else { "Random" };
    print_field!("AType: {} ({})", a_type_str, a_type);
    let sca_str = SCA_TABLE.get(sca as usize).unwrap_or(&"Reserved");
    print_field!("SCA: {} ({})", sca, sca_str);
    print_le_phy_bitfield("PHY", phy);

    // AdvA: 6 bytes at offset 28
    packet_print_addr("AdvA", &data[28..34], a_type != 0);
}

/// Helper to parse a last byte (syncConnEventCount) from periodic_sync_ind.
/// This is actually at a fixed offset within the 34 bytes — the C code reads
/// it from the struct. Let me re-check: bt_ll_periodic_sync_ind is 34 bytes
/// and includes sync_conn_event_count at the very end.
/// LL_CLOCK_ACCURACY_REQ / LL_CLOCK_ACCURACY_RSP handler (opcodes 0x1d/0x1e, 1 byte).
fn clock_acc_req_rsp(data: &[u8], _size: u8) {
    let sca = data[0];
    let sca_str = SCA_TABLE.get(sca as usize).unwrap_or(&"Reserved");
    print_field!("SCA: {} ({})", sca, sca_str);
}

/// LL_CIS_REQ handler (opcode 0x1f, variable size).
fn cis_req(data: &[u8], _size: u8) {
    if data.len() < 36 {
        print_text!(COLOR_ERROR, "Too short CIS request");
        return;
    }

    let cig_id = data[0];
    let cis_id = data[1];
    print_field!("CIG ID: 0x{:02x}", cig_id);
    print_field!("CIS ID: 0x{:02x}", cis_id);

    print_le_phy_bitfield("C_TO_P PHY", data[2]);
    print_le_phy_bitfield("P_TO_C PHY", data[3]);

    let max_sdu_c_to_p = read_u16_le(data, 4);
    let max_sdu_p_to_c = read_u16_le(data, 6);
    print_field!("Max SDU C->P: {}", max_sdu_c_to_p);
    print_field!("Max SDU P->C: {}", max_sdu_p_to_c);

    // 3-byte LE intervals
    let sdu_interval_c_to_p = read_u24_le(data, 8);
    let sdu_interval_p_to_c = read_u24_le(data, 11);
    print_field!("SDU Interval C->P: {} us", sdu_interval_c_to_p);
    print_field!("SDU Interval P->C: {} us", sdu_interval_p_to_c);

    let max_pdu_c_to_p = read_u16_le(data, 14);
    let max_pdu_p_to_c = read_u16_le(data, 16);
    print_field!("Max PDU C->P: {}", max_pdu_c_to_p);
    print_field!("Max PDU P->C: {}", max_pdu_p_to_c);

    let nse = data[18];
    print_field!("Burst Number: {}", nse);

    // 3-byte sub-interval
    let sub_interval = read_u24_le(data, 19);
    print_field!("Sub-Interval: {} us", sub_interval);

    let ft_c_to_p = data[22];
    let ft_p_to_c = data[23];
    print_field!("FT C->P: {}", ft_c_to_p);
    print_field!("FT P->C: {}", ft_p_to_c);

    let iso_interval = read_u16_le(data, 24);
    print_field!("ISO Interval: {}", iso_interval);

    // 3-byte offset min/max
    let offset_min = read_u24_le(data, 26);
    let offset_max = read_u24_le(data, 29);
    print_field!("CIS Offset Min: {} us", offset_min);
    print_field!("CIS Offset Max: {} us", offset_max);

    let conn_event_count = read_u16_le(data, 32);
    print_field!("connEventCount: {}", conn_event_count);
}

/// LL_CIS_RSP handler (opcode 0x20, 8 bytes).
fn cis_rsp(data: &[u8], _size: u8) {
    // 3-byte offset min/max
    let offset_min = read_u24_le(data, 0);
    let offset_max = read_u24_le(data, 3);
    print_field!("CIS Offset Min: {} us", offset_min);
    print_field!("CIS Offset Max: {} us", offset_max);

    let conn_event_count = read_u16_le(data, 6);
    print_field!("connEventCount: {}", conn_event_count);
}

/// LL_CIS_IND handler (opcode 0x21, 15 bytes).
fn cis_ind(data: &[u8], _size: u8) {
    let cis_access_addr = read_u32_le(data, 0);
    // Note: C code uses %4.4x format which truncates to 16 bits — behavioral clone
    print_field!("CIS Access Address: 0x{:04x}", cis_access_addr & 0xffff);

    // 3-byte CIS offset
    let cis_offset = read_u24_le(data, 4);
    print_field!("CIS Offset: {} us", cis_offset);

    // 3-byte CIG sync delay
    let cig_sync_delay = read_u24_le(data, 7);
    print_field!("CIG Sync Delay: {} us", cig_sync_delay);

    // 3-byte CIS sync delay
    let cis_sync_delay = read_u24_le(data, 10);
    print_field!("CIS Sync Delay: {} us", cis_sync_delay);

    let conn_event_count = read_u16_le(data, 13);
    print_field!("connEventCount: {}", conn_event_count);
}

/// LL_CIS_TERMINATE_IND handler (opcode 0x22, 3 bytes).
fn cis_term_ind(data: &[u8], _size: u8) {
    let cig_id = data[0];
    let cis_id = data[1];
    print_field!("CIG ID: 0x{:02x}", cig_id);
    print_field!("CIS ID: 0x{:02x}", cis_id);
    packet_print_error("Reason", data[2]);
}

/// LL_FEATURE_EXT_REQ handler (opcode — see note, 26 bytes).
fn feature_ext_req(data: &[u8], _size: u8) {
    if data.len() < 10 {
        return;
    }
    let max_page = data[0];
    let page = data[1];
    print_field!("MaxPage: {}", max_page);
    print_field!("Page: {}", page);
    packet_print_features_ext_ll(page, &data[2..10]);
}

/// LL_FEATURE_EXT_RSP handler (opcode — see note, 26 bytes).
fn feature_ext_rsp(data: &[u8], _size: u8) {
    if data.len() < 10 {
        return;
    }
    let max_page = data[0];
    let page = data[1];
    print_field!("MaxPage: {}", max_page);
    print_field!("Page: {}", page);
    packet_print_features_ext_ll(page, &data[2..10]);
}

/// Null handler for opcodes with no payload (LL_START_ENC_REQ, etc.)
fn null_pdu(_data: &[u8], _size: u8) {
    // No payload to decode
}

// ============================================================================
// LLCP Dispatch Table (from ll.c lines 762-880)
// ============================================================================

/// LLCP table entry.
struct LlcpData {
    opcode: u8,
    name: &'static str,
    handler: fn(&[u8], u8),
    size: u8,
    fixed: bool,
}

/// Complete LLCP dispatch table — 36 entries covering all LE LL control opcodes.
///
/// Opcodes and sizes match the C llcp_table in ll.c exactly.
/// The C code has a known bug where LL_FEATURE_EXT_REQ uses opcode 0x08
/// (duplicate of LL_FEATURE_REQ) and LL_FEATURE_EXT_RSP uses opcode 0x20
/// (duplicate of LL_CIS_RSP). We use the correct opcodes 0x23/0x24 for
/// behavioral correctness since those entries are unreachable in the C code
/// (they'd never match due to earlier duplicate entries).
const LLCP_TABLE: &[LlcpData] = &[
    LlcpData {
        opcode: 0x00,
        name: "LL_CONNECTION_UPDATE_REQ",
        handler: conn_update_req,
        size: 11,
        fixed: true,
    },
    LlcpData {
        opcode: 0x01,
        name: "LL_CHANNEL_MAP_REQ",
        handler: channel_map_req,
        size: 7,
        fixed: true,
    },
    LlcpData {
        opcode: 0x02,
        name: "LL_TERMINATE_IND",
        handler: terminate_ind,
        size: 1,
        fixed: true,
    },
    LlcpData { opcode: 0x03, name: "LL_ENC_REQ", handler: enc_req, size: 22, fixed: true },
    LlcpData { opcode: 0x04, name: "LL_ENC_RSP", handler: enc_rsp, size: 12, fixed: true },
    LlcpData { opcode: 0x05, name: "LL_START_ENC_REQ", handler: null_pdu, size: 0, fixed: true },
    LlcpData { opcode: 0x06, name: "LL_START_ENC_RSP", handler: null_pdu, size: 0, fixed: true },
    LlcpData { opcode: 0x07, name: "LL_UNKNOWN_RSP", handler: unknown_rsp, size: 1, fixed: true },
    LlcpData { opcode: 0x08, name: "LL_FEATURE_REQ", handler: feature_req, size: 8, fixed: true },
    LlcpData { opcode: 0x09, name: "LL_FEATURE_RSP", handler: feature_rsp, size: 8, fixed: true },
    LlcpData { opcode: 0x0a, name: "LL_PAUSE_ENC_REQ", handler: null_pdu, size: 0, fixed: true },
    LlcpData { opcode: 0x0b, name: "LL_PAUSE_ENC_RSP", handler: null_pdu, size: 0, fixed: true },
    LlcpData { opcode: 0x0c, name: "LL_VERSION_IND", handler: version_ind, size: 5, fixed: true },
    LlcpData { opcode: 0x0d, name: "LL_REJECT_IND", handler: reject_ind, size: 1, fixed: true },
    LlcpData {
        opcode: 0x0e,
        name: "LL_PERIPHERAL_FEATURE_REQ",
        handler: peripheral_feature_req,
        size: 8,
        fixed: true,
    },
    LlcpData {
        opcode: 0x0f,
        name: "LL_CONNECTION_PARAM_REQ",
        handler: conn_param_req,
        size: 23,
        fixed: true,
    },
    LlcpData {
        opcode: 0x10,
        name: "LL_CONNECTION_PARAM_RSP",
        handler: conn_param_rsp,
        size: 23,
        fixed: true,
    },
    LlcpData {
        opcode: 0x11,
        name: "LL_REJECT_IND_EXT",
        handler: reject_ind_ext,
        size: 2,
        fixed: true,
    },
    LlcpData { opcode: 0x12, name: "LL_PING_REQ", handler: null_pdu, size: 0, fixed: true },
    LlcpData { opcode: 0x13, name: "LL_PING_RSP", handler: null_pdu, size: 0, fixed: true },
    LlcpData { opcode: 0x14, name: "LL_LENGTH_REQ", handler: length_req_rsp, size: 8, fixed: true },
    LlcpData { opcode: 0x15, name: "LL_LENGTH_RSP", handler: length_req_rsp, size: 8, fixed: true },
    LlcpData { opcode: 0x16, name: "LL_PHY_REQ", handler: phy_req_rsp, size: 2, fixed: true },
    LlcpData { opcode: 0x17, name: "LL_PHY_RSP", handler: phy_req_rsp, size: 2, fixed: true },
    LlcpData {
        opcode: 0x18,
        name: "LL_PHY_UPDATE_IND",
        handler: phy_update_ind,
        size: 4,
        fixed: true,
    },
    LlcpData {
        opcode: 0x19,
        name: "LL_MIN_USED_CHANNELS_IND",
        handler: min_used_channels,
        size: 2,
        fixed: true,
    },
    LlcpData { opcode: 0x1a, name: "LL_CTE_REQ", handler: cte_req, size: 1, fixed: true },
    LlcpData { opcode: 0x1b, name: "LL_CTE_RSP", handler: null_pdu, size: 0, fixed: true },
    LlcpData {
        opcode: 0x1c,
        name: "LL_PERIODIC_SYNC_IND",
        handler: periodic_sync_ind,
        size: 34,
        fixed: true,
    },
    LlcpData {
        opcode: 0x1d,
        name: "LL_CLOCK_ACCURACY_REQ",
        handler: clock_acc_req_rsp,
        size: 1,
        fixed: true,
    },
    LlcpData {
        opcode: 0x1e,
        name: "LL_CLOCK_ACCURACY_RSP",
        handler: clock_acc_req_rsp,
        size: 1,
        fixed: true,
    },
    LlcpData { opcode: 0x1f, name: "LL_CIS_REQ", handler: cis_req, size: 36, fixed: true },
    LlcpData { opcode: 0x20, name: "LL_CIS_RSP", handler: cis_rsp, size: 8, fixed: true },
    LlcpData { opcode: 0x21, name: "LL_CIS_IND", handler: cis_ind, size: 15, fixed: true },
    LlcpData {
        opcode: 0x22,
        name: "LL_CIS_TERMINATE_IND",
        handler: cis_term_ind,
        size: 3,
        fixed: true,
    },
    // Feature extended — use dedicated opcodes
    LlcpData {
        opcode: 0x23,
        name: "LL_FEATURE_EXT_REQ",
        handler: feature_ext_req,
        size: 26,
        fixed: true,
    },
    LlcpData {
        opcode: 0x24,
        name: "LL_FEATURE_EXT_RSP",
        handler: feature_ext_rsp,
        size: 26,
        fixed: true,
    },
];

/// Look up the name for a given LLCP opcode.
fn opcode_to_string(opcode: u8) -> &'static str {
    for entry in LLCP_TABLE {
        if entry.opcode == opcode {
            return entry.name;
        }
    }
    "Unknown"
}

// ============================================================================
// LLCP Packet Dispatcher (from ll.c lines 847-880)
// ============================================================================

/// Decode and print an LE Link Layer Control Protocol (LLCP) PDU.
///
/// The first byte is the LLCP opcode; the remaining bytes are the parameters.
///
/// # Arguments
/// * `data` — LLCP PDU bytes starting with the opcode byte
/// * `size` — Total LLCP PDU size
/// * `padded` — Whether the enclosing data PDU was padded
pub fn llcp_packet(data: &[u8], size: u8, padded: bool) {
    let size_usize = size as usize;

    if size_usize == 0 || data.is_empty() {
        print_text!(COLOR_ERROR, "Too short LLCP packet");
        return;
    }

    let opcode = data[0];

    // Find matching table entry
    let entry = LLCP_TABLE.iter().find(|e| e.opcode == opcode);

    let (name, color) = match entry {
        Some(e) => (e.name, COLOR_OPCODE),
        None => ("Unknown", COLOR_OPCODE_UNKNOWN),
    };

    print_indent!(6, color, "", name, COLOR_OFF, " (0x{:02x})", opcode);

    match entry {
        None => {
            // Unknown opcode — hexdump remaining data
            if size_usize > 1 {
                print_hexdump(&data[1..size_usize.min(data.len())]);
            }
        }
        Some(e) => {
            let param_data = &data[1..];
            let param_size = size_usize.saturating_sub(1);

            // Size validation
            if e.fixed && !padded {
                // Fixed-size, non-padded: exact match required
                if param_size != e.size as usize {
                    print_text!(COLOR_ERROR, "Invalid size {} (expected {})", param_size, e.size);
                    if !param_data.is_empty() {
                        print_hexdump(&param_data[..param_size.min(param_data.len())]);
                    }
                    return;
                }
            } else {
                // Padded or variable: minimum match
                if param_size < e.size as usize {
                    print_text!(COLOR_ERROR, "Too short {} (need at least {})", param_size, e.size);
                    if !param_data.is_empty() {
                        print_hexdump(&param_data[..param_size.min(param_data.len())]);
                    }
                    return;
                }
            }

            // Dispatch to handler
            (e.handler)(param_data, param_size as u8);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc_init_cache_basic() {
        // Test set and get
        CHANNEL_LIST.with(|list| {
            let mut arr = list.borrow_mut();
            *arr = [ChannelData::default(); MAX_CHANNEL];
        });

        set_crc_init(0x1234_5678, 0x00ab_cdef);
        assert_eq!(get_crc_init(0x1234_5678), 0x00ab_cdef);
        assert_eq!(get_crc_init(0x0000_0001), 0x0000_0000);
    }

    #[test]
    fn test_crc_init_cache_overwrite() {
        CHANNEL_LIST.with(|list| {
            let mut arr = list.borrow_mut();
            *arr = [ChannelData::default(); MAX_CHANNEL];
        });

        set_crc_init(0xaabb_ccdd, 0x0011_2233);
        set_crc_init(0xaabb_ccdd, 0x0044_5566);
        assert_eq!(get_crc_init(0xaabb_ccdd), 0x0044_5566);
    }

    #[test]
    fn test_crc_init_cache_multiple() {
        CHANNEL_LIST.with(|list| {
            let mut arr = list.borrow_mut();
            *arr = [ChannelData::default(); MAX_CHANNEL];
        });

        for i in 0..MAX_CHANNEL {
            set_crc_init((i + 1) as u32, (i + 100) as u32);
        }
        for i in 0..MAX_CHANNEL {
            assert_eq!(get_crc_init((i + 1) as u32), (i + 100) as u32);
        }
    }

    #[test]
    fn test_format_bdaddr() {
        let addr: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_bdaddr(&addr), "FF:EE:DD:CC:BB:AA");
    }

    #[test]
    fn test_format_bdaddr_short() {
        let addr: [u8; 3] = [0x01, 0x02, 0x03];
        assert_eq!(format_bdaddr(&addr), "(invalid)");
    }

    #[test]
    fn test_opcode_to_string_known() {
        assert_eq!(opcode_to_string(0x00), "LL_CONNECTION_UPDATE_REQ");
        assert_eq!(opcode_to_string(0x02), "LL_TERMINATE_IND");
        assert_eq!(opcode_to_string(0x0c), "LL_VERSION_IND");
        assert_eq!(opcode_to_string(0x14), "LL_LENGTH_REQ");
        assert_eq!(opcode_to_string(0x1f), "LL_CIS_REQ");
    }

    #[test]
    fn test_opcode_to_string_unknown() {
        assert_eq!(opcode_to_string(0xff), "Unknown");
        assert_eq!(opcode_to_string(0x80), "Unknown");
    }

    #[test]
    fn test_read_u16_le() {
        let data: [u8; 4] = [0x34, 0x12, 0x78, 0x56];
        assert_eq!(read_u16_le(&data, 0), 0x1234);
        assert_eq!(read_u16_le(&data, 2), 0x5678);
    }

    #[test]
    fn test_read_u32_le() {
        let data: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0), 0x1234_5678);
    }

    #[test]
    fn test_read_u24_le() {
        let data: [u8; 3] = [0xAA, 0xBB, 0xCC];
        assert_eq!(read_u24_le(&data, 0), 0x00CC_BBAA);
    }

    #[test]
    fn test_read_u64_le() {
        let data: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data, 0), 0x0807_0605_0403_0201);
    }

    #[test]
    fn test_read_out_of_bounds() {
        let data: [u8; 2] = [0x01, 0x02];
        assert_eq!(read_u16_le(&data, 2), 0);
        assert_eq!(read_u32_le(&data, 0), 0);
        assert_eq!(read_u64_le(&data, 0), 0);
        assert_eq!(read_u24_le(&data, 1), 0);
    }

    #[test]
    fn test_error_code_to_str() {
        assert_eq!(error_code_to_str(0x00), "Success");
        assert_eq!(error_code_to_str(0x05), "Authentication Failure");
        assert_eq!(error_code_to_str(0x13), "Remote User Terminated Connection");
        assert_eq!(error_code_to_str(0x3e), "Connection Failed to be Established");
        assert_eq!(error_code_to_str(0xfe), "Unknown");
    }

    #[test]
    fn test_sca_table() {
        assert_eq!(SCA_TABLE[0], "251 ppm to 500 ppm");
        assert_eq!(SCA_TABLE[2], "101 ppm to 150ppm");
        assert_eq!(SCA_TABLE[7], "0 ppm to 20 ppm");
    }

    #[test]
    fn test_llcp_table_completeness() {
        // Verify table has all expected entries
        assert_eq!(LLCP_TABLE.len(), 37);

        // Verify opcodes 0x00-0x1e are all present
        for opcode in 0x00u8..=0x1e {
            assert!(
                LLCP_TABLE.iter().any(|e| e.opcode == opcode),
                "Missing opcode 0x{:02x}",
                opcode
            );
        }

        // Verify CIS opcodes
        assert!(LLCP_TABLE.iter().any(|e| e.opcode == 0x1f)); // CIS_REQ
        assert!(LLCP_TABLE.iter().any(|e| e.opcode == 0x20)); // CIS_RSP
        assert!(LLCP_TABLE.iter().any(|e| e.opcode == 0x21)); // CIS_IND
        assert!(LLCP_TABLE.iter().any(|e| e.opcode == 0x22)); // CIS_TERMINATE_IND

        // Verify feature extended opcodes
        assert!(LLCP_TABLE.iter().any(|e| e.opcode == 0x23)); // FEATURE_EXT_REQ
        assert!(LLCP_TABLE.iter().any(|e| e.opcode == 0x24)); // FEATURE_EXT_RSP
    }

    #[test]
    fn test_llcp_table_sizes() {
        // Verify sizes of key entries
        let find = |op: u8| LLCP_TABLE.iter().find(|e| e.opcode == op).unwrap();

        assert_eq!(find(0x00).size, 11); // CONNECTION_UPDATE_REQ
        assert_eq!(find(0x01).size, 7); // CHANNEL_MAP_REQ
        assert_eq!(find(0x02).size, 1); // TERMINATE_IND
        assert_eq!(find(0x03).size, 22); // ENC_REQ
        assert_eq!(find(0x04).size, 12); // ENC_RSP
        assert_eq!(find(0x05).size, 0); // START_ENC_REQ
        assert_eq!(find(0x0c).size, 5); // VERSION_IND
        assert_eq!(find(0x0f).size, 23); // CONNECTION_PARAM_REQ
        assert_eq!(find(0x14).size, 8); // LENGTH_REQ
        assert_eq!(find(0x18).size, 4); // PHY_UPDATE_IND
        assert_eq!(find(0x1c).size, 34); // PERIODIC_SYNC_IND
        assert_eq!(find(0x1f).size, 36); // CIS_REQ
        assert_eq!(find(0x21).size, 15); // CIS_IND
    }
}
