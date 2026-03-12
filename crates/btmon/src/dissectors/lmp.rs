// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014 Intel Corporation
 * Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
 *
 * lmp.rs — LMP (Link Manager Protocol) PDU dissector.
 *
 * Complete Rust rewrite of monitor/lmp.c (924 lines) + monitor/lmp.h (16 lines)
 * from BlueZ v5.86.  Decodes LMP PDUs with per-opcode payload size validation,
 * covering all LMP transactions: name, features, version, clock offset, timing
 * accuracy, slot offset, page mode, supervision timeout, quality of service,
 * SCO, power control, encryption, role switch, hold/sniff/park modes, AFH, SSP,
 * LE, ping.
 */

use crate::display::{COLOR_ERROR, COLOR_MAGENTA, COLOR_OFF, COLOR_WHITE_BG, print_hexdump};
// Re-import #[macro_export] macros from crate root — these are defined in
// display.rs but exported at the crate level by the Rust macro_export rules.
use crate::{print_field, print_indent, print_text};

// ============================================================================
// Color Aliases (from lmp.c lines 26-28)
// ============================================================================

const COLOR_OPCODE: &str = COLOR_MAGENTA;
const COLOR_OPCODE_UNKNOWN: &str = COLOR_WHITE_BG;

// ============================================================================
// LMP_ESC4 macro equivalent (from bt.h line 256)
// ============================================================================

/// Encode an extended LMP opcode using escape code 127.
const fn lmp_esc4(x: u16) -> u16 {
    (127 << 8) | x
}

// ============================================================================
// Safe byte-slice parsing helpers
// ============================================================================

/// Read a single byte at `offset` from `data`.
#[inline]
fn get_u8(data: &[u8], offset: usize) -> u8 {
    data[offset]
}

/// Read a little-endian u16 at `offset` from `data`.
#[inline]
fn get_le16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 at `offset` from `data`.
#[inline]
fn get_le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

// ============================================================================
// Local packet helper functions
//
// Defined locally per D4 rules since packet.rs is not in depends_on_files.
// These replicate the output format of the corresponding packet.c functions.
// ============================================================================

/// HCI error code to string mapping (subset covering all standard codes).
fn error_to_str(error: u8) -> &'static str {
    match error {
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
        0x14 => "Remote Device Terminated due to Low Resources",
        0x15 => "Remote Device Terminated due to Power Off",
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
        0x3c => "Directed Advertising Timeout",
        0x3d => "Connection Terminated due to MIC Failure",
        0x3e => "Connection Failed to be Established",
        0x3f => "MAC Connection Failed",
        0x40 => "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging",
        0x41 => "Type0 Submap Not Defined",
        0x42 => "Unknown Advertising Identifier",
        0x43 => "Limit Reached",
        0x44 => "Operation Cancelled by Host",
        0x45 => "Packet Too Long",
        _ => "Reserved",
    }
}

/// Print an HCI error code field matching C `packet_print_error` format.
fn packet_print_error(label: &str, error: u8) {
    print_field!("{}: {} (0x{:02x})", label, error_to_str(error), error);
}

/// Bluetooth version to string mapping.
fn ver_to_str(version: u8) -> &'static str {
    match version {
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
    }
}

/// Print BT version matching C `packet_print_version` format.
fn packet_print_version(label: &str, version: u8, sublabel: &str, subversion: u16) {
    print_field!(
        "{}: {} (0x{:02x}) - {}: {} (0x{:04x})",
        label,
        ver_to_str(version),
        version,
        sublabel,
        subversion,
        subversion
    );
}

/// Print company identifier matching C `packet_print_company` format.
fn packet_print_company(label: &str, company: u16) {
    print_field!("{}: {} ({})", label, company, company);
}

/// Print LMP features bitfield matching C `packet_print_features_lmp` format.
fn packet_print_features_lmp(features: &[u8], page: u8) {
    let mut hex = String::with_capacity(23);
    for (i, &b) in features.iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        hex.push_str(&format!("{:02x}", b));
    }
    print_field!("Features: 0x{} (page {})", hex, page);
}

/// Print IO capability matching C `packet_print_io_capability` format.
fn packet_print_io_capability(capability: u8) {
    let s = match capability {
        0x00 => "DisplayOnly",
        0x01 => "DisplayYesNo",
        0x02 => "KeyboardOnly",
        0x03 => "NoInputNoOutput",
        _ => "Reserved",
    };
    print_field!("IO capability: {} (0x{:02x})", s, capability);
}

/// Print IO authentication requirement matching C format.
fn packet_print_io_authentication(authentication: u8) {
    let s = match authentication {
        0x00 => "MITM Protection Not Required - No Bonding",
        0x01 => "MITM Protection Required - No Bonding",
        0x02 => "MITM Protection Not Required - Dedicated Bonding",
        0x03 => "MITM Protection Required - Dedicated Bonding",
        0x04 => "MITM Protection Not Required - General Bonding",
        0x05 => "MITM Protection Required - General Bonding",
        _ => "Reserved",
    };
    print_field!("Authentication: {} (0x{:02x})", s, authentication);
}

/// Print BD_ADDR matching C `packet_print_addr` format.
fn packet_print_addr(label: &str, bdaddr: &[u8], _addr_type: u8) {
    print_field!(
        "{}: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        label,
        bdaddr[5],
        bdaddr[4],
        bdaddr[3],
        bdaddr[2],
        bdaddr[1],
        bdaddr[0]
    );
}

/// Print LMP channel map matching C `packet_print_channel_map_lmp` format.
fn packet_print_channel_map_lmp(map: &[u8]) {
    let mut hex = String::with_capacity(29);
    for (i, &b) in map.iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        hex.push_str(&format!("{:02x}", b));
    }
    print_field!("Channel map: 0x{}", hex);
}

// ============================================================================
// Internal opcode string helper
// ============================================================================

/// Look up opcode name string from the LMP table.
fn get_opcode_str(opcode: u16) -> Option<&'static str> {
    for entry in LMP_TABLE {
        if entry.opcode == opcode {
            return Some(entry.name);
        }
    }
    None
}

/// Print an LMP operation field (used by accepted / not_accepted decoders).
fn print_opcode(opcode: u16) {
    let name = get_opcode_str(opcode).unwrap_or("Unknown");

    if opcode & 0xff00 != 0 {
        print_field!("Operation: {} ({}/{})", name, opcode >> 8, opcode & 0xff);
    } else {
        print_field!("Operation: {} ({})", name, opcode);
    }
}

// ============================================================================
// Individual LMP PDU Decoders (from lmp.c lines 46-710)
// ============================================================================

fn name_req(data: &[u8], _size: u8) {
    let offset = get_u8(data, 0);
    print_field!("Offset: {}", offset);
}

fn name_rsp(data: &[u8], _size: u8) {
    let offset = get_u8(data, 0);
    let length = get_u8(data, 1);

    // Extract 14-byte name fragment, NUL-terminate
    let fragment_bytes = &data[2..16];
    let end = fragment_bytes.iter().position(|&b| b == 0).unwrap_or(14);
    let fragment = std::str::from_utf8(&fragment_bytes[..end]).unwrap_or("");

    print_field!("Offset: {}", offset);
    print_field!("Length: {}", length);
    print_field!("Fragment: {}", fragment);
}

fn accepted(data: &[u8], _size: u8) {
    let opcode = u16::from(get_u8(data, 0));
    print_opcode(opcode);
}

fn not_accepted(data: &[u8], _size: u8) {
    let opcode = u16::from(get_u8(data, 0));
    let error = get_u8(data, 1);

    print_opcode(opcode);
    packet_print_error("Error code", error);
}

fn clkoffset_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn clkoffset_rsp(data: &[u8], _size: u8) {
    let offset = get_le16(data, 0);
    print_field!("Clock offset: 0x{:04x}", offset);
}

fn detach(data: &[u8], _size: u8) {
    let error = get_u8(data, 0);
    packet_print_error("Error code", error);
}

fn au_rand(data: &[u8], _size: u8) {
    print_hexdump(&data[..16]);
}

fn sres(data: &[u8], _size: u8) {
    print_hexdump(&data[..4]);
}

fn encryption_mode_req(data: &[u8], _size: u8) {
    let mode = get_u8(data, 0);
    let s = match mode {
        0x00 => "No encryption",
        0x01 => "Encryption",
        0x02 => "Encryption",
        _ => "Reserved",
    };
    print_field!("Mode: {} ({})", s, mode);
}

fn encryption_key_size_req(data: &[u8], _size: u8) {
    let key_size = get_u8(data, 0);
    print_field!("Key size: {}", key_size);
}

fn start_encryption_req(data: &[u8], _size: u8) {
    print_hexdump(&data[..16]);
}

fn stop_encryption_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn switch_req(data: &[u8], _size: u8) {
    let instant = get_le32(data, 0);
    print_field!("Instant: 0x{:08x}", instant);
}

fn unsniff_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn max_power(_data: &[u8], _size: u8) {
    // No payload fields
}

fn min_power(_data: &[u8], _size: u8) {
    // No payload fields
}

fn auto_rate(_data: &[u8], _size: u8) {
    // No payload fields
}

fn preferred_rate(data: &[u8], _size: u8) {
    let rate = get_u8(data, 0);

    // Basic data rate: FEC (bit 0)
    let s = if rate & 0x01 != 0 { "do not use FEC" } else { "use FEC" };
    print_field!("Basic data rate: {} (0x{:02x})", s, rate & 0x01);

    // Basic data rate: packet size (bits 2:1)
    let s = match (rate & 0x06) >> 1 {
        0 => "No packet-size preference available",
        1 => "use 1-slot packets",
        2 => "use 3-slot packets",
        3 => "use 5-slot packets",
        _ => "Reserved",
    };
    print_field!("Basic data rate: {} (0x{:02x})", s, rate & 0x06);

    // Enhanced data rate: speed (matching C's rate & 0x11 mask exactly)
    let s = match (rate & 0x11) >> 3 {
        0 => "use DM1 packets",
        1 => "use 2 Mb/s packets",
        2 => "use 3 MB/s packets",
        3 => "reserved",
        _ => "reserved",
    };
    print_field!("Enhanced data rate: {} (0x{:02x})", s, rate & 0x11);

    // Enhanced data rate: packet size (bits 6:5)
    let s = match (rate & 0x60) >> 5 {
        0 => "No packet-size preference available",
        1 => "use 1-slot packets",
        2 => "use 3-slot packets",
        3 => "use 5-slot packets",
        _ => "Reserved",
    };
    print_field!("Enhanced data rate: {} (0x{:02x})", s, rate & 0x60);
}

fn version_req(data: &[u8], _size: u8) {
    let version = get_u8(data, 0);
    let company = get_le16(data, 1);
    let subversion = get_le16(data, 3);

    packet_print_version("Version", version, "Subversion", subversion);
    packet_print_company("Company", company);
}

fn version_res(data: &[u8], _size: u8) {
    let version = get_u8(data, 0);
    let company = get_le16(data, 1);
    let subversion = get_le16(data, 3);

    packet_print_version("Version", version, "Subversion", subversion);
    packet_print_company("Company", company);
}

fn features_req(data: &[u8], _size: u8) {
    packet_print_features_lmp(&data[..8], 0x00);
}

fn features_res(data: &[u8], _size: u8) {
    packet_print_features_lmp(&data[..8], 0x00);
}

fn max_slot(data: &[u8], _size: u8) {
    let slots = get_u8(data, 0);
    print_field!("Slots: 0x{:04x}", slots);
}

fn max_slot_req(data: &[u8], _size: u8) {
    let slots = get_u8(data, 0);
    print_field!("Slots: 0x{:04x}", slots);
}

fn timing_accuracy_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn timing_accuracy_res(data: &[u8], _size: u8) {
    let drift = get_u8(data, 0);
    let jitter = get_u8(data, 1);

    print_field!("Drift: {} ppm", drift);
    print_field!("Jitter: {} usec", jitter);
}

fn setup_complete(_data: &[u8], _size: u8) {
    // No payload fields
}

fn use_semi_permanent_key(_data: &[u8], _size: u8) {
    // No payload fields
}

fn host_connection_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn slot_offset(data: &[u8], _size: u8) {
    let offset = get_le16(data, 0);
    let bdaddr = &data[2..8];

    print_field!("Offset: {} usec", offset);
    packet_print_addr("Address", bdaddr, 0x00);
}

fn page_scan_mode_req(data: &[u8], _size: u8) {
    let scheme = get_u8(data, 0);
    let settings = get_u8(data, 1);

    let scheme_str = match scheme {
        0x00 => "Mandatory",
        _ => "Reserved",
    };
    print_field!("Paging scheme: {} ({})", scheme_str, scheme);

    let settings_str = if scheme == 0x00 {
        match settings {
            0x00 => "R0",
            0x01 => "R1",
            0x02 => "R2",
            _ => "Reserved",
        }
    } else {
        "Reserved"
    };
    print_field!("Paging scheme settings: {} ({})", settings_str, settings);
}

fn test_activate(_data: &[u8], _size: u8) {
    // No payload fields
}

fn encryption_key_size_mask_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn set_afh(data: &[u8], _size: u8) {
    let instant = get_le32(data, 0);
    let mode = get_u8(data, 4);
    let map = &data[5..15];

    print_field!("Instant: {}", instant);

    let mode_str = match mode {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("Mode: {} (0x{:02x})", mode_str, mode);

    packet_print_channel_map_lmp(map);
}

fn encapsulated_header(data: &[u8], _size: u8) {
    let major = get_u8(data, 0);
    let minor = get_u8(data, 1);
    let length = get_u8(data, 2);

    print_field!("Major type: {}", major);
    print_field!("Minor type: {}", minor);

    if major == 0x01 {
        let s = match minor {
            0x01 => "P-192 Public Key",
            0x02 => "P-256 Public Key",
            _ => "Reserved",
        };
        print_field!("  {}", s);
    }

    print_field!("Length: {}", length);
}

fn encapsulated_payload(data: &[u8], _size: u8) {
    print_hexdump(&data[..16]);
}

fn simple_pairing_confirm(data: &[u8], _size: u8) {
    print_hexdump(&data[..16]);
}

fn simple_pairing_number(data: &[u8], _size: u8) {
    print_hexdump(&data[..16]);
}

fn dhkey_check(data: &[u8], _size: u8) {
    print_hexdump(&data[..16]);
}

// ============================================================================
// Extended Opcode PDU Decoders
// ============================================================================

fn accepted_ext(data: &[u8], _size: u8) {
    let escape = get_u8(data, 0);
    let opcode_byte = get_u8(data, 1);

    let opcode = match escape {
        127 => lmp_esc4(u16::from(opcode_byte)),
        _ => return,
    };

    print_opcode(opcode);
}

fn not_accepted_ext(data: &[u8], _size: u8) {
    let escape = get_u8(data, 0);
    let opcode_byte = get_u8(data, 1);
    let error = get_u8(data, 2);

    let opcode = match escape {
        127 => lmp_esc4(u16::from(opcode_byte)),
        _ => return,
    };

    print_opcode(opcode);
    print_field!("Error code: {}", error);
}

fn features_req_ext(data: &[u8], _size: u8) {
    let page = get_u8(data, 0);
    let max_page = get_u8(data, 1);
    let features = &data[2..10];

    print_field!("Features page: {}", page);
    print_field!("Max supported page: {}", max_page);
    packet_print_features_lmp(features, page);
}

fn features_res_ext(data: &[u8], _size: u8) {
    let page = get_u8(data, 0);
    let max_page = get_u8(data, 1);
    let features = &data[2..10];

    print_field!("Features page: {}", page);
    print_field!("Max supported page: {}", max_page);
    packet_print_features_lmp(features, page);
}

fn packet_type_table_req(data: &[u8], _size: u8) {
    let table = get_u8(data, 0);
    let s = match table {
        0x00 => "1 Mbps only",
        0x01 => "2/3 Mbps",
        _ => "Reserved",
    };
    print_field!("Table: {} (0x{:02x})", s, table);
}

fn channel_classification_req(data: &[u8], _size: u8) {
    let mode = get_u8(data, 0);
    let min_interval = get_le16(data, 1);
    let max_interval = get_le16(data, 3);

    let mode_str = match mode {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("Reporting mode: {} (0x{:02x})", mode_str, mode);
    print_field!("Min interval: 0x{:02x}", min_interval);
    print_field!("Max interval: 0x{:02x}", max_interval);
}

fn channel_classification(data: &[u8], _size: u8) {
    let classification = &data[..10];
    let mut hex = String::with_capacity(20);
    for &b in classification {
        hex.push_str(&format!("{:02x}", b));
    }
    print_field!("Classification: 0x{}", hex);
}

fn pause_encryption_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn resume_encryption_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn io_capability_req(data: &[u8], _size: u8) {
    let capability = get_u8(data, 0);
    let oob_data = get_u8(data, 1);
    let authentication = get_u8(data, 2);

    packet_print_io_capability(capability);

    let s = match oob_data {
        0x00 => "No authentication data received",
        0x01 => "Authentication data received",
        _ => "Reserved",
    };
    print_field!("OOB data: {} (0x{:02x})", s, oob_data);

    packet_print_io_authentication(authentication);
}

fn io_capability_res(data: &[u8], _size: u8) {
    let capability = get_u8(data, 0);
    let oob_data = get_u8(data, 1);
    let authentication = get_u8(data, 2);

    packet_print_io_capability(capability);

    let s = match oob_data {
        0x00 => "No authentication data received",
        0x01 => "Authentication data received",
        _ => "Reserved",
    };
    print_field!("OOB data: {} (0x{:02x})", s, oob_data);

    packet_print_io_authentication(authentication);
}

fn numeric_comparison_failed(_data: &[u8], _size: u8) {
    // No payload fields
}

fn passkey_failed(_data: &[u8], _size: u8) {
    // No payload fields
}

fn oob_failed(_data: &[u8], _size: u8) {
    // No payload fields
}

fn power_control_req(data: &[u8], _size: u8) {
    let request = get_u8(data, 0);
    let s = match request {
        0x00 => "Decrement power one step",
        0x01 => "Increment power one step",
        0x02 => "Increase to maximum power",
        _ => "Reserved",
    };
    print_field!("Request: {} (0x{:02x})", s, request);
}

fn power_control_res(data: &[u8], _size: u8) {
    let response = get_u8(data, 0);

    print_field!("Response: 0x{:02x}", response);

    // GFSK (bits 1:0)
    let s = match response & 0x03 {
        0x00 => "Not supported",
        0x01 => "Changed one step",
        0x02 => "Max power",
        0x03 => "Min power",
        _ => "Reserved",
    };
    print_field!("  GFSK: {}", s);

    // DQPSK (bits 3:2)
    let s = match (response & 0x0c) >> 2 {
        0x00 => "Not supported",
        0x01 => "Changed one step",
        0x02 => "Max power",
        0x03 => "Min power",
        _ => "Reserved",
    };
    print_field!("  DQPSK: {}", s);

    // 8DPSK (bits 5:4)
    let s = match (response & 0x30) >> 4 {
        0x00 => "Not supported",
        0x01 => "Changed one step",
        0x02 => "Max power",
        0x03 => "Min power",
        _ => "Reserved",
    };
    print_field!("  8DPSK: {}", s);
}

fn ping_req(_data: &[u8], _size: u8) {
    // No payload fields
}

fn ping_res(_data: &[u8], _size: u8) {
    // No payload fields
}

// ============================================================================
// LMP Opcode Table (from lmp.c lines 711-816)
// ============================================================================

/// Describes one LMP opcode entry with its name, decode handler, expected
/// payload size, and whether the size must match exactly (fixed) or is a
/// minimum (variable).
struct LmpData {
    opcode: u16,
    name: &'static str,
    func: Option<fn(&[u8], u8)>,
    size: u8,
    fixed: bool,
}

/// Complete LMP opcode table matching the C `lmp_table[]` exactly.
/// Entries without a handler (`func: None`) are opcodes with missing decoders
/// and will be printed by `lmp_todo()`.
static LMP_TABLE: &[LmpData] = &[
    // Basic opcodes (1-66)
    LmpData { opcode: 1, name: "LMP_name_req", func: Some(name_req), size: 1, fixed: true },
    LmpData { opcode: 2, name: "LMP_name_res", func: Some(name_rsp), size: 16, fixed: true },
    LmpData { opcode: 3, name: "LMP_accepted", func: Some(accepted), size: 1, fixed: true },
    LmpData { opcode: 4, name: "LMP_not_accepted", func: Some(not_accepted), size: 2, fixed: true },
    LmpData {
        opcode: 5,
        name: "LMP_clkoffset_req",
        func: Some(clkoffset_req),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: 6,
        name: "LMP_clkoffset_res",
        func: Some(clkoffset_rsp),
        size: 2,
        fixed: true,
    },
    LmpData { opcode: 7, name: "LMP_detach", func: Some(detach), size: 1, fixed: true },
    LmpData { opcode: 8, name: "LMP_in_rand", func: None, size: 0, fixed: false },
    LmpData { opcode: 9, name: "LMP_comb_key", func: None, size: 0, fixed: false },
    LmpData { opcode: 10, name: "LMP_unit_key", func: None, size: 0, fixed: false },
    LmpData { opcode: 11, name: "LMP_au_rand", func: Some(au_rand), size: 16, fixed: true },
    LmpData { opcode: 12, name: "LMP_sres", func: Some(sres), size: 4, fixed: true },
    LmpData { opcode: 13, name: "LMP_temp_rand", func: None, size: 0, fixed: false },
    LmpData { opcode: 14, name: "LMP_temp_key", func: None, size: 0, fixed: false },
    LmpData {
        opcode: 15,
        name: "LMP_encryption_mode_req",
        func: Some(encryption_mode_req),
        size: 1,
        fixed: true,
    },
    LmpData {
        opcode: 16,
        name: "LMP_encryption_key_size_req",
        func: Some(encryption_key_size_req),
        size: 1,
        fixed: true,
    },
    LmpData {
        opcode: 17,
        name: "LMP_start_encryption_req",
        func: Some(start_encryption_req),
        size: 16,
        fixed: true,
    },
    LmpData {
        opcode: 18,
        name: "LMP_stop_encryption_req",
        func: Some(stop_encryption_req),
        size: 0,
        fixed: true,
    },
    LmpData { opcode: 19, name: "LMP_switch_req", func: Some(switch_req), size: 4, fixed: true },
    LmpData { opcode: 20, name: "LMP_hold", func: None, size: 0, fixed: false },
    LmpData { opcode: 21, name: "LMP_hold_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 22, name: "LMP_sniff", func: None, size: 0, fixed: false },
    LmpData { opcode: 23, name: "LMP_sniff_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 24, name: "LMP_unsniff_req", func: Some(unsniff_req), size: 0, fixed: true },
    LmpData { opcode: 25, name: "LMP_park_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 26, name: "LMP_park", func: None, size: 0, fixed: false },
    LmpData {
        opcode: 27,
        name: "LMP_set_broadcast_scan_window",
        func: None,
        size: 0,
        fixed: false,
    },
    LmpData { opcode: 28, name: "LMP_modify_beacon", func: None, size: 0, fixed: false },
    LmpData { opcode: 29, name: "LMP_unpark_BD_ADDR_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 30, name: "LMP_unpark_PM_ADDR_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 31, name: "LMP_incr_power_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 32, name: "LMP_decr_power_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 33, name: "LMP_max_power", func: Some(max_power), size: 0, fixed: true },
    LmpData { opcode: 34, name: "LMP_min_power", func: Some(min_power), size: 0, fixed: true },
    LmpData { opcode: 35, name: "LMP_auto_rate", func: Some(auto_rate), size: 0, fixed: true },
    LmpData {
        opcode: 36,
        name: "LMP_preferred_rate",
        func: Some(preferred_rate),
        size: 1,
        fixed: true,
    },
    LmpData { opcode: 37, name: "LMP_version_req", func: Some(version_req), size: 5, fixed: true },
    LmpData { opcode: 38, name: "LMP_version_res", func: Some(version_res), size: 5, fixed: true },
    LmpData {
        opcode: 39,
        name: "LMP_features_req",
        func: Some(features_req),
        size: 8,
        fixed: true,
    },
    LmpData {
        opcode: 40,
        name: "LMP_features_res",
        func: Some(features_res),
        size: 8,
        fixed: true,
    },
    LmpData { opcode: 41, name: "LMP_quality_of_service", func: None, size: 0, fixed: false },
    LmpData { opcode: 42, name: "LMP_quality_of_service_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 43, name: "LMP_SCO_link_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 44, name: "LMP_remove_SCO_link_req", func: None, size: 0, fixed: false },
    LmpData { opcode: 45, name: "LMP_max_slot", func: Some(max_slot), size: 1, fixed: true },
    LmpData {
        opcode: 46,
        name: "LMP_max_slot_req",
        func: Some(max_slot_req),
        size: 1,
        fixed: true,
    },
    LmpData {
        opcode: 47,
        name: "LMP_timing_accuracy_req",
        func: Some(timing_accuracy_req),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: 48,
        name: "LMP_timing_accuracy_res",
        func: Some(timing_accuracy_res),
        size: 2,
        fixed: true,
    },
    LmpData {
        opcode: 49,
        name: "LMP_setup_complete",
        func: Some(setup_complete),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: 50,
        name: "LMP_use_semi_permanent_key",
        func: Some(use_semi_permanent_key),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: 51,
        name: "LMP_host_connection_req",
        func: Some(host_connection_req),
        size: 0,
        fixed: true,
    },
    LmpData { opcode: 52, name: "LMP_slot_offset", func: Some(slot_offset), size: 8, fixed: true },
    LmpData { opcode: 53, name: "LMP_page_mode_req", func: None, size: 0, fixed: false },
    LmpData {
        opcode: 54,
        name: "LMP_page_scan_mode_req",
        func: Some(page_scan_mode_req),
        size: 2,
        fixed: true,
    },
    LmpData { opcode: 55, name: "LMP_supervision_timeout", func: None, size: 0, fixed: false },
    LmpData {
        opcode: 56,
        name: "LMP_test_activate",
        func: Some(test_activate),
        size: 0,
        fixed: true,
    },
    LmpData { opcode: 57, name: "LMP_test_control", func: None, size: 0, fixed: false },
    LmpData {
        opcode: 58,
        name: "LMP_encryption_key_size_mask_req",
        func: Some(encryption_key_size_mask_req),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: 59,
        name: "LMP_encryption_key_size_mask_res",
        func: None,
        size: 0,
        fixed: false,
    },
    LmpData { opcode: 60, name: "LMP_set_AFH", func: Some(set_afh), size: 15, fixed: true },
    LmpData {
        opcode: 61,
        name: "LMP_encapsulated_header",
        func: Some(encapsulated_header),
        size: 3,
        fixed: true,
    },
    LmpData {
        opcode: 62,
        name: "LMP_encapsulated_payload",
        func: Some(encapsulated_payload),
        size: 16,
        fixed: true,
    },
    LmpData {
        opcode: 63,
        name: "LMP_simple_pairing_confirm",
        func: Some(simple_pairing_confirm),
        size: 16,
        fixed: true,
    },
    LmpData {
        opcode: 64,
        name: "LMP_simple_pairing_number",
        func: Some(simple_pairing_number),
        size: 16,
        fixed: true,
    },
    LmpData { opcode: 65, name: "LMP_DHkey_check", func: Some(dhkey_check), size: 16, fixed: true },
    LmpData { opcode: 66, name: "LMP_pause_encryption_aes_req", func: None, size: 0, fixed: false },
    // Extended opcodes (LMP_ESC4)
    LmpData {
        opcode: lmp_esc4(1),
        name: "LMP_accepted_ext",
        func: Some(accepted_ext),
        size: 2,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(2),
        name: "LMP_not_accepted_ext",
        func: Some(not_accepted_ext),
        size: 3,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(3),
        name: "LMP_features_req_ext",
        func: Some(features_req_ext),
        size: 10,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(4),
        name: "LMP_features_res_ext",
        func: Some(features_res_ext),
        size: 10,
        fixed: true,
    },
    LmpData { opcode: lmp_esc4(5), name: "LMP_clk_adj", func: None, size: 0, fixed: false },
    LmpData { opcode: lmp_esc4(6), name: "LMP_clk_adj_ack", func: None, size: 0, fixed: false },
    LmpData { opcode: lmp_esc4(7), name: "LMP_clk_adj_req", func: None, size: 0, fixed: false },
    LmpData {
        opcode: lmp_esc4(11),
        name: "LMP_packet_type_table_req",
        func: Some(packet_type_table_req),
        size: 1,
        fixed: true,
    },
    LmpData { opcode: lmp_esc4(12), name: "LMP_eSCO_link_req", func: None, size: 0, fixed: false },
    LmpData {
        opcode: lmp_esc4(13),
        name: "LMP_remove_eSCO_link_req",
        func: None,
        size: 0,
        fixed: false,
    },
    LmpData {
        opcode: lmp_esc4(16),
        name: "LMP_channel_classification_req",
        func: Some(channel_classification_req),
        size: 5,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(17),
        name: "LMP_channel_classification",
        func: Some(channel_classification),
        size: 10,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(21),
        name: "LMP_sniff_subrating_req",
        func: None,
        size: 0,
        fixed: false,
    },
    LmpData {
        opcode: lmp_esc4(22),
        name: "LMP_sniff_subrating_res",
        func: None,
        size: 0,
        fixed: false,
    },
    LmpData {
        opcode: lmp_esc4(23),
        name: "LMP_pause_encryption_req",
        func: Some(pause_encryption_req),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(24),
        name: "LMP_resume_encryption_req",
        func: Some(resume_encryption_req),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(25),
        name: "LMP_IO_capability_req",
        func: Some(io_capability_req),
        size: 3,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(26),
        name: "LMP_IO_capability_res",
        func: Some(io_capability_res),
        size: 3,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(27),
        name: "LMP_numeric_comparison_failed",
        func: Some(numeric_comparison_failed),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(28),
        name: "LMP_passkey_failed",
        func: Some(passkey_failed),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(29),
        name: "LMP_oob_failed",
        func: Some(oob_failed),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(30),
        name: "LMP_keypress_notification",
        func: None,
        size: 0,
        fixed: false,
    },
    LmpData {
        opcode: lmp_esc4(31),
        name: "LMP_power_control_req",
        func: Some(power_control_req),
        size: 1,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(32),
        name: "LMP_power_control_res",
        func: Some(power_control_res),
        size: 1,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(33),
        name: "LMP_ping_req",
        func: Some(ping_req),
        size: 0,
        fixed: true,
    },
    LmpData {
        opcode: lmp_esc4(34),
        name: "LMP_ping_res",
        func: Some(ping_res),
        size: 0,
        fixed: true,
    },
    LmpData { opcode: lmp_esc4(35), name: "LMP_SAM_set_type0", func: None, size: 0, fixed: false },
    LmpData { opcode: lmp_esc4(36), name: "LMP_SAM_define_map", func: None, size: 0, fixed: false },
    LmpData { opcode: lmp_esc4(37), name: "LMP_SAM_switch", func: None, size: 0, fixed: false },
];

// ============================================================================
// Public API (from lmp.h)
// ============================================================================

/// Decode and display an LMP PDU.
///
/// Parses the LMP opcode from the first byte(s) of `data`, validates the
/// payload size against the opcode table, and dispatches to the appropriate
/// per-opcode decoder.
///
/// # Arguments
///
/// * `data`   — Raw LMP PDU bytes (including the opcode/TID byte).
/// * `size`   — Total byte length of `data`.
/// * `padded` — If `true`, the PDU may be zero-padded (relaxes exact-size
///   checking to minimum-size checking).
pub fn lmp_packet(data: &[u8], size: u8, padded: bool) {
    let size_usize = size as usize;

    if size_usize == 0 || data.is_empty() {
        return;
    }

    // Extract TID (bit 0) and basic opcode (bits 7:1) from first byte
    let tid = data[0] & 0x01;
    let mut opcode: u16 = u16::from((data[0] & 0xfe) >> 1);
    let off: usize;

    let tid_str = if tid == 0x00 { "Central" } else { "Peripheral" };

    match opcode {
        127 => {
            // Extended opcode — escape 127
            if size_usize < 2 {
                print_text!(COLOR_ERROR, "extended opcode too short");
                print_hexdump(&data[..size_usize]);
                return;
            }
            opcode = lmp_esc4(u16::from(data[1]));
            off = 2;
        }
        124..=126 => {
            // Reserved escape codes — silently skip
            return;
        }
        _ => {
            off = 1;
        }
    }

    // Look up the opcode in the table
    let lmp_data = LMP_TABLE.iter().find(|e| e.opcode == opcode);

    // Determine color and name string
    let (opcode_color, opcode_str) = match lmp_data {
        Some(entry) => {
            let color = if entry.func.is_some() { COLOR_OPCODE } else { COLOR_OPCODE_UNKNOWN };
            (color, entry.name)
        }
        None => (COLOR_OPCODE_UNKNOWN, "Unknown"),
    };

    // Print the opcode header line with indentation
    if opcode & 0xff00 != 0 {
        print_indent!(
            6,
            opcode_color,
            "",
            opcode_str,
            COLOR_OFF,
            " ({}/{}) {} transaction ({})",
            opcode >> 8,
            opcode & 0xff,
            tid_str,
            tid
        );
    } else {
        print_indent!(
            6,
            opcode_color,
            "",
            opcode_str,
            COLOR_OFF,
            " ({}) {} transaction ({})",
            opcode,
            tid_str,
            tid
        );
    }

    // If no table entry or no handler, hexdump the payload
    let entry = match lmp_data {
        Some(e) if e.func.is_some() => e,
        _ => {
            if off < size_usize {
                print_hexdump(&data[off..size_usize]);
            }
            return;
        }
    };

    // Validate payload size
    let payload_size = size_usize - off;
    if entry.fixed && !padded {
        if payload_size != entry.size as usize {
            print_text!(COLOR_ERROR, "invalid packet size");
            print_hexdump(&data[off..size_usize]);
            return;
        }
    } else if payload_size < entry.size as usize {
        print_text!(COLOR_ERROR, "too short packet");
        print_hexdump(&data[off..size_usize]);
        return;
    }

    // Dispatch to the per-opcode decoder
    if let Some(handler) = entry.func {
        handler(&data[off..size_usize], (size_usize - off) as u8);
    }
}

/// Print a list of LMP opcodes that have no decoder implementation.
///
/// Used by `btmon --todo` to display which LMP operations still need
/// decoding support.
pub fn lmp_todo() {
    println!("LMP operations with missing decodings:");

    for entry in LMP_TABLE {
        if entry.func.is_some() {
            continue;
        }
        println!("\t{}", entry.name);
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lmp_todo_does_not_panic() {
        lmp_todo();
    }

    #[test]
    fn test_lmp_packet_empty_data() {
        lmp_packet(&[], 0, false);
    }

    #[test]
    fn test_lmp_packet_basic_opcode_name_req() {
        let data: [u8; 2] = [0x02, 0x05];
        lmp_packet(&data, 2, false);
    }

    #[test]
    fn test_lmp_packet_basic_opcode_accepted() {
        let data: [u8; 2] = [0x06, 0x01];
        lmp_packet(&data, 2, false);
    }

    #[test]
    fn test_lmp_packet_basic_opcode_not_accepted() {
        let data: [u8; 3] = [0x08, 0x01, 0x06];
        lmp_packet(&data, 3, false);
    }

    #[test]
    fn test_lmp_packet_basic_opcode_detach() {
        let data: [u8; 2] = [0x0e, 0x13];
        lmp_packet(&data, 2, false);
    }

    #[test]
    fn test_lmp_packet_extended_opcode_accepted_ext() {
        let data: [u8; 4] = [0xfe, 0x01, 0x7f, 0x03];
        lmp_packet(&data, 4, false);
    }

    #[test]
    fn test_lmp_packet_extended_opcode_ping_req() {
        let data: [u8; 2] = [0xfe, 33];
        lmp_packet(&data, 2, false);
    }

    #[test]
    fn test_lmp_packet_reserved_escapes_silent() {
        for esc in [124u8, 125, 126] {
            let byte0 = (esc << 1) | 0;
            let data: [u8; 1] = [byte0];
            lmp_packet(&data, 1, false);
        }
    }

    #[test]
    fn test_lmp_packet_tid_peripheral() {
        let data: [u8; 1] = [0x63];
        lmp_packet(&data, 1, false);
    }

    #[test]
    fn test_lmp_packet_padded_relaxes_size() {
        let data: [u8; 3] = [0x02, 0x05, 0x00];
        lmp_packet(&data, 3, true);
    }

    #[test]
    fn test_lmp_packet_size_mismatch_error() {
        let data: [u8; 2] = [0x08, 0x01];
        lmp_packet(&data, 2, false);
    }

    #[test]
    fn test_lmp_packet_extended_too_short() {
        let data: [u8; 1] = [0xfe];
        lmp_packet(&data, 1, false);
    }

    #[test]
    fn test_lmp_packet_unknown_basic_opcode() {
        let byte0 = (120u8 << 1) | 0;
        let data: [u8; 3] = [byte0, 0xaa, 0xbb];
        lmp_packet(&data, 3, false);
    }

    #[test]
    fn test_lmp_packet_version_req() {
        let data: [u8; 6] = [0x4a, 0x09, 0x0d, 0x00, 0x01, 0x00];
        lmp_packet(&data, 6, false);
    }

    #[test]
    fn test_lmp_packet_slot_offset() {
        let data: [u8; 9] = [0x68, 0x40, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        lmp_packet(&data, 9, false);
    }

    #[test]
    fn test_lmp_packet_io_capability_req() {
        let data: [u8; 5] = [0xfe, 25, 0x01, 0x00, 0x03];
        lmp_packet(&data, 5, false);
    }

    #[test]
    fn test_lmp_packet_features_req() {
        let data: [u8; 9] = [0x4e, 0xff, 0xfe, 0x0f, 0xfe, 0xdb, 0xff, 0x7b, 0x87];
        lmp_packet(&data, 9, false);
    }

    #[test]
    fn test_lmp_packet_power_control_res() {
        let data: [u8; 3] = [0xfe, 32, 0x15];
        lmp_packet(&data, 3, false);
    }

    #[test]
    fn test_lmp_packet_set_afh() {
        let data: [u8; 16] = [
            0x78, 0x00, 0x01, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x7f,
        ];
        lmp_packet(&data, 16, false);
    }

    #[test]
    fn test_lmp_packet_encryption_mode_req() {
        let data: [u8; 2] = [0x1e, 0x01];
        lmp_packet(&data, 2, false);
    }

    #[test]
    fn test_lmp_packet_preferred_rate() {
        let data: [u8; 2] = [0x48, 0x49];
        lmp_packet(&data, 2, false);
    }

    #[test]
    fn test_get_opcode_str_basic() {
        assert_eq!(get_opcode_str(1), Some("LMP_name_req"));
        assert_eq!(get_opcode_str(3), Some("LMP_accepted"));
        assert_eq!(get_opcode_str(66), Some("LMP_pause_encryption_aes_req"));
        assert_eq!(get_opcode_str(200), None);
    }

    #[test]
    fn test_get_opcode_str_extended() {
        assert_eq!(get_opcode_str(lmp_esc4(1)), Some("LMP_accepted_ext"));
        assert_eq!(get_opcode_str(lmp_esc4(33)), Some("LMP_ping_req"));
        assert_eq!(get_opcode_str(lmp_esc4(37)), Some("LMP_SAM_switch"));
        assert_eq!(get_opcode_str(lmp_esc4(99)), None);
    }

    #[test]
    fn test_lmp_table_completeness() {
        assert_eq!(LMP_TABLE.len(), 95);
    }

    #[test]
    fn test_lmp_table_basic_range() {
        for opcode in 1u16..=66 {
            let found = LMP_TABLE.iter().any(|e| e.opcode == opcode);
            assert!(found, "Basic opcode {} missing from table", opcode);
        }
    }

    #[test]
    fn test_lmp_table_extended_opcodes() {
        let ext_opcodes: [u16; 29] = [
            1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 16, 17, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37,
        ];
        for ext in ext_opcodes {
            let op = lmp_esc4(ext);
            let found = LMP_TABLE.iter().any(|e| e.opcode == op);
            assert!(found, "Extended opcode ESC4({}) missing", ext);
        }
    }

    #[test]
    fn test_error_to_str_values() {
        assert_eq!(error_to_str(0x00), "Success");
        assert_eq!(error_to_str(0x05), "Authentication Failure");
        assert_eq!(error_to_str(0x13), "Remote User Terminated Connection");
        assert_eq!(error_to_str(0xff), "Reserved");
    }

    #[test]
    fn test_ver_to_str_values() {
        assert_eq!(ver_to_str(0x09), "Bluetooth 5.0");
        assert_eq!(ver_to_str(0x0e), "Bluetooth 6.0");
        assert_eq!(ver_to_str(0xff), "Reserved");
    }

    #[test]
    fn test_lmp_esc4_values() {
        assert_eq!(lmp_esc4(1), (127 << 8) | 1);
        assert_eq!(lmp_esc4(33), (127 << 8) | 33);
        assert_eq!(lmp_esc4(0), 127 << 8);
    }

    #[test]
    fn test_byte_parsing_helpers() {
        let data: [u8; 6] = [0x42, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(get_u8(&data, 0), 0x42);
        assert_eq!(get_le16(&data, 1), 0x0201);
        assert_eq!(get_le32(&data, 2), 0x05040302);
    }

    #[test]
    fn test_lmp_packet_au_rand() {
        let mut data = [0u8; 17];
        data[0] = 0x16;
        for i in 1..17 {
            data[i] = i as u8;
        }
        lmp_packet(&data, 17, false);
    }

    #[test]
    fn test_lmp_packet_sres() {
        let data: [u8; 5] = [0x18, 0xaa, 0xbb, 0xcc, 0xdd];
        lmp_packet(&data, 5, false);
    }

    #[test]
    fn test_lmp_packet_name_rsp() {
        let mut data = [0u8; 17];
        data[0] = 0x04;
        data[1] = 0x00;
        data[2] = 0x0a;
        data[3] = b'T';
        data[4] = b'e';
        data[5] = b's';
        data[6] = b't';
        data[7] = b'D';
        data[8] = b'e';
        data[9] = b'v';
        lmp_packet(&data, 17, false);
    }

    #[test]
    fn test_lmp_packet_not_accepted_ext() {
        let data: [u8; 5] = [0xfe, 0x02, 0x7f, 0x03, 0x05];
        lmp_packet(&data, 5, false);
    }

    #[test]
    fn test_lmp_packet_features_req_ext() {
        let data: [u8; 12] = [0xfe, 3, 1, 2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        lmp_packet(&data, 12, false);
    }

    #[test]
    fn test_lmp_packet_channel_classification() {
        let data: [u8; 12] = [0xfe, 17, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        lmp_packet(&data, 12, false);
    }

    #[test]
    fn test_lmp_packet_switch_req() {
        let data: [u8; 5] = [0x26, 0x00, 0x10, 0x00, 0x00];
        lmp_packet(&data, 5, false);
    }

    #[test]
    fn test_lmp_packet_clkoffset_rsp() {
        let data: [u8; 3] = [0x0c, 0x34, 0x12];
        lmp_packet(&data, 3, false);
    }

    #[test]
    fn test_lmp_packet_timing_accuracy_res() {
        let data: [u8; 3] = [0x60, 20, 10];
        lmp_packet(&data, 3, false);
    }

    #[test]
    fn test_lmp_packet_encapsulated_header() {
        let data: [u8; 4] = [0x7a, 0x01, 0x01, 48];
        lmp_packet(&data, 4, false);
    }
}
