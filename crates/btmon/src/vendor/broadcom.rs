// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014 Intel Corporation
 * Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
 *
 * broadcom.rs — Broadcom vendor HCI command/event decoder for btmon.
 *
 * Complete Rust rewrite of monitor/broadcom.c (730 lines) +
 * monitor/broadcom.h (19 lines) from BlueZ v5.86.
 * Decodes Broadcom-specific vendor HCI commands and events with
 * byte-identical output to the C original.
 */

use super::{VendorEvt, VendorOcf};
use crate::display::{self, COLOR_WHITE_BG};
use crate::{print_field, print_text};
use bluez_shared::util::endian::{get_be32, get_le16, get_le32, get_s8, get_u8};

// ============================================================================
// Color alias (from broadcom.c line 28)
// ============================================================================

const COLOR_UNKNOWN_FEATURE_BIT: &str = COLOR_WHITE_BG;

// ============================================================================
// HCI error status strings (matching packet_print_error / error2str)
// ============================================================================

/// Map an HCI status/error code to its human-readable name, matching the
/// C `error_to_str()` table from `packet.c`.
fn error_to_str(status: u8) -> &'static str {
    match status {
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
        0x1a => "Unsupported Remote Feature / Unsupported LMP Feature",
        0x1b => "SCO Offset Rejected",
        0x1c => "SCO Interval Rejected",
        0x1d => "SCO Air Mode Rejected",
        0x1e => "Invalid LMP Parameters / Invalid LL Parameters",
        0x1f => "Unspecified Error",
        0x20 => "Unsupported LMP Parameter Value / Unsupported LL Parameter Value",
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
        0x2b => "Reserved",
        0x2c => "QoS Unacceptable Parameter",
        0x2d => "QoS Rejected",
        0x2e => "Channel Classification Not Supported",
        0x2f => "Insufficient Security",
        0x30 => "Parameter Out Of Manadatory Range",
        0x31 => "Reserved",
        0x32 => "Role Switch Pending",
        0x33 => "Reserved",
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
        0x40 => "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging",
        0x41 => "Type0 Submap Not Defined",
        0x42 => "Unknown Advertising Identifier",
        0x43 => "Limit Reached",
        0x44 => "Operation Cancelled by Host",
        0x45 => "Packet Too Long",
        _ => "Unknown",
    }
}

// ============================================================================
// Print helpers (lines 30-221 in broadcom.c)
// ============================================================================

/// Print HCI status field: `"Status: <description> (0xNN)"`.
fn print_status(status: u8) {
    print_field!("Status: {} (0x{:02x})", error_to_str(status), status);
}

/// Print connection handle field: `"Handle: N"`.
fn print_handle(handle: u16) {
    print_field!("Handle: {}", handle);
}

/// Print RSSI value: `"RSSI: N dBm"`.
fn print_rssi(rssi: i8) {
    print_field!("RSSI: {} dBm", rssi);
}

/// Print BD_ADDR in standard format with address type label.
fn print_addr(label: &str, data: &[u8], _addr_type: u8) {
    if data.len() < 6 {
        return;
    }
    print_field!(
        "{}: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        label,
        data[5],
        data[4],
        data[3],
        data[2],
        data[1],
        data[0]
    );
}

/// Print SCO routing mode.
fn print_sco_routing(routing: u8) {
    let s = match routing {
        0x00 => "PCM",
        0x01 => "Transport",
        0x02 => "Codec",
        0x03 => "I2S",
        _ => "Reserved",
    };
    print_field!("SCO routing: {} (0x{:02x})", s, routing);
}

/// Print PCM interface rate.
fn print_pcm_interface_rate(rate: u8) {
    let s = match rate {
        0x00 => "128 KBps",
        0x01 => "256 KBps",
        0x02 => "512 KBps",
        0x03 => "1024 KBps",
        0x04 => "2048 KBps",
        _ => "Reserved",
    };
    print_field!("PCM interface rate: {} (0x{:02x})", s, rate);
}

/// Print frame type.
fn print_frame_type(frame_type: u8) {
    let s = match frame_type {
        0x00 => "Short",
        0x01 => "Long",
        _ => "Reserved",
    };
    print_field!("Frame type: {} (0x{:02x})", s, frame_type);
}

/// Print sync mode.
fn print_sync_mode(mode: u8) {
    let s = match mode {
        0x00 => "Peripheral",
        0x01 => "Central",
        _ => "Reserved",
    };
    print_field!("Sync mode: {} (0x{:02x})", s, mode);
}

/// Print clock mode.
fn print_clock_mode(mode: u8) {
    let s = match mode {
        0x00 => "Peripheral",
        0x01 => "Central",
        _ => "Reserved",
    };
    print_field!("Clock mode: {} (0x{:02x})", s, mode);
}

/// Print sleep mode.
fn print_sleep_mode(mode: u8) {
    let s = match mode {
        0x00 => "No sleep mode",
        0x01 => "UART",
        0x02 => "UART with messaging",
        0x03 => "USB",
        0x04 => "H4IBSS",
        0x05 => "USB with Host wake",
        0x06 => "SDIO",
        0x07 => "UART CS-N",
        0x08 => "SPI",
        0x09 => "H5",
        0x0a => "H4DS",
        0x0c => "UART with BREAK",
        _ => "Reserved",
    };
    print_field!("Sleep mode: {} (0x{:02x})", s, mode);
}

/// Print UART clock setting.
fn print_clock_setting(clock: u8) {
    let s = match clock {
        0x01 => "48 Mhz",
        0x02 => "24 Mhz",
        _ => "Reserved",
    };
    print_field!("UART clock: {} (0x{:02x})", s, clock);
}

// ============================================================================
// Command/Response decoder functions (lines 223-568 in broadcom.c)
// ============================================================================

/// Null command — no parameters to decode.
fn null_cmd(_index: u16, _data: &[u8]) {}

/// Status-only response decoder.
fn status_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    print_status(status);
}

/// Write BD ADDR command: 6-byte Bluetooth address.
fn write_bd_addr_cmd(_index: u16, data: &[u8]) {
    print_addr("Address", data, 0x00);
}

/// Update UART Baud Rate command: encoded rate (LE16) + explicit rate (LE32).
fn update_uart_baud_rate_cmd(_index: u16, data: &[u8]) {
    let enc_rate = get_le16(data);
    let exp_rate = get_le32(&data[2..]);

    if enc_rate == 0x0000 {
        print_field!("Encoded baud rate: Not used (0x0000)");
    } else {
        print_field!("Encoded baud rate: 0x{:04x}", enc_rate);
    }

    print_field!("Explicit baud rate: {} Mbps", exp_rate);
}

/// Write SCO PCM Interface Parameters command: 5 bytes.
fn write_sco_pcm_int_param_cmd(_index: u16, data: &[u8]) {
    let routing = get_u8(data);
    let rate = get_u8(&data[1..]);
    let frame_type = get_u8(&data[2..]);
    let sync_mode = get_u8(&data[3..]);
    let clock_mode = get_u8(&data[4..]);

    print_sco_routing(routing);
    print_pcm_interface_rate(rate);
    print_frame_type(frame_type);
    print_sync_mode(sync_mode);
    print_clock_mode(clock_mode);
}

/// Read SCO PCM Interface Parameters response: status + 5 fields.
fn read_sco_pcm_int_param_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    let routing = get_u8(&data[1..]);
    let rate = get_u8(&data[2..]);
    let frame_type = get_u8(&data[3..]);
    let sync_mode = get_u8(&data[4..]);
    let clock_mode = get_u8(&data[5..]);

    print_status(status);
    print_sco_routing(routing);
    print_pcm_interface_rate(rate);
    print_frame_type(frame_type);
    print_sync_mode(sync_mode);
    print_clock_mode(clock_mode);
}

/// Set Sleepmode Parameters command: mode byte + remaining hexdump.
fn set_sleepmode_param_cmd(_index: u16, data: &[u8]) {
    let mode = get_u8(data);
    print_sleep_mode(mode);
    display::print_hexdump(&data[1..]);
}

/// Read Sleepmode Parameters response: status + mode + remaining hexdump.
fn read_sleepmode_param_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    let mode = get_u8(&data[1..]);

    print_status(status);
    print_sleep_mode(mode);
    display::print_hexdump(&data[2..]);
}

/// Enable Radio command: mode byte.
fn enable_radio_cmd(_index: u16, data: &[u8]) {
    let mode = get_u8(data);
    let s = match mode {
        0x00 => "Disable the radio",
        0x01 => "Enable the radio",
        _ => "Reserved",
    };
    print_field!("Mode: {} (0x{:02x})", s, mode);
}

/// Enable USB HID Emulation command: enable byte.
fn enable_usb_hid_emulation_cmd(_index: u16, data: &[u8]) {
    let enable = get_u8(data);
    let s = match enable {
        0x00 => "Bluetooth mode",
        0x01 => "HID Mode",
        _ => "Reserved",
    };
    print_field!("Enable: {} (0x{:02x})", s, enable);
}

/// Read UART Clock Setting response: status + clock byte.
fn read_uart_clock_setting_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    let clock = get_u8(&data[1..]);

    print_status(status);
    print_clock_setting(clock);
}

/// Write UART Clock Setting command: clock byte.
fn write_uart_clock_setting_cmd(_index: u16, data: &[u8]) {
    let clock = get_u8(data);
    print_clock_setting(clock);
}

/// Read Raw RSSI command: LE16 connection handle.
fn read_raw_rssi_cmd(_index: u16, data: &[u8]) {
    let handle = get_le16(data);
    print_handle(handle);
}

/// Read Raw RSSI response: status + LE16 handle + i8 RSSI.
fn read_raw_rssi_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    let handle = get_le16(&data[1..]);
    let rssi = get_s8(&data[3..]);

    print_status(status);
    print_handle(handle);
    print_rssi(rssi);
}

/// Write RAM command: LE32 address + remaining hexdump.
fn write_ram_cmd(_index: u16, data: &[u8]) {
    let addr = get_le32(data);
    print_field!("Address: 0x{:08x}", addr);
    display::print_hexdump(&data[4..]);
}

/// Read RAM command: LE32 address + u8 length.
fn read_ram_cmd(_index: u16, data: &[u8]) {
    let addr = get_le32(data);
    let length = get_u8(&data[4..]);

    print_field!("Address: 0x{:08x}", addr);
    print_field!("Length: {}", length);
}

/// Read RAM response: status + remaining hexdump.
fn read_ram_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    print_status(status);
    display::print_hexdump(&data[1..]);
}

/// Launch RAM command: LE32 address.
fn launch_ram_cmd(_index: u16, data: &[u8]) {
    let addr = get_le32(data);
    print_field!("Address: 0x{:08x}", addr);
}

/// Read VID PID response: status + LE16 VID + LE16 PID.
fn read_vid_pid_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    let vid = get_le16(&data[1..]);
    let pid = get_le16(&data[3..]);

    print_status(status);
    print_field!("Product: {:04x}:{:04x}", vid, pid);
}

/// Write High Priority Connection command: LE16 handle + priority byte.
fn write_high_priority_connection_cmd(_index: u16, data: &[u8]) {
    let handle = get_le16(data);
    let priority = get_u8(&data[2..]);

    print_handle(handle);

    let s = match priority {
        0x00 => "Low",
        0x01 => "High",
        _ => "Reserved",
    };
    print_field!("Priority: {} (0x{:02x})", s, priority);
}

// ============================================================================
// Broadcom features table (lines 455-491 in broadcom.c)
// ============================================================================

/// Broadcom-specific feature bit entry.
struct FeatureEntry {
    bit: u8,
    name: &'static str,
}

/// Broadcom controller feature bits.
static FEATURES_TABLE: &[FeatureEntry] = &[
    FeatureEntry { bit: 0, name: "Multi-AV transport bandwidth reducer" },
    FeatureEntry { bit: 1, name: "WBS SBC" },
    FeatureEntry { bit: 2, name: "FW LC-PLC" },
    FeatureEntry { bit: 3, name: "FM SBC internal stack" },
];

/// Print 8-byte Broadcom feature array as hex and named bits.
fn print_features(features_array: &[u8]) {
    let mut features: u64 = 0;
    let mut hex_str = String::new();

    for (i, &byte) in features_array.iter().enumerate().take(8) {
        hex_str.push_str(&format!(" 0x{:02x}", byte));
        features |= (byte as u64) << (i * 8);
    }

    print_field!("Features:{}", hex_str);

    let mut mask = features;

    for entry in FEATURES_TABLE {
        if features & (1u64 << entry.bit) != 0 {
            print_field!("  {}", entry.name);
            mask &= !(1u64 << entry.bit);
        }
    }

    if mask != 0 {
        print_text!(COLOR_UNKNOWN_FEATURE_BIT, "  Unknown features (0x{:016x})", mask);
    }
}

/// Read Controller Features response: status + 8-byte features.
fn read_controller_features_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    print_status(status);
    print_features(&data[1..]);
}

/// Read Verbose Config Version Info response.
fn read_verbose_version_info_rsp(_index: u16, data: &[u8]) {
    let status = get_u8(data);
    let chip_id = get_u8(&data[1..]);
    let target_id = get_u8(&data[2..]);
    let build_base = get_le16(&data[3..]);
    let build_num = get_le16(&data[5..]);

    print_status(status);
    print_field!("Chip ID: {} (0x{:02x})", chip_id, chip_id);

    let s = match target_id {
        254 => "Invalid",
        255 => "Undefined",
        _ => "Reserved",
    };

    print_field!("Build target: {} ({})", s, target_id);
    print_field!("Build baseline: {} (0x{:04x})", build_base, build_base);
    print_field!("Build number: {} (0x{:04x})", build_num, build_num);
}

/// Enable WBS command: mode byte + LE16 codec.
fn enable_wbs_cmd(_index: u16, data: &[u8]) {
    let mode = get_u8(data);
    let codec = get_le16(&data[1..]);

    let mode_str = match mode {
        0x00 => "Disable WBS",
        0x01 => "Enable WBS",
        _ => "Reserved",
    };

    print_field!("Mode: {} (0x{:02x})", mode_str, mode);

    let codec_str = match codec {
        0x0000 => "None",
        0x0001 => "CVSD",
        0x0002 => "mSBC",
        _ => "Reserved",
    };

    print_field!("Codec: {} (0x{:04x})", codec_str, codec);
}

// ============================================================================
// Vendor OCF Table (lines 570-633 in broadcom.c)
// ============================================================================

/// Complete Broadcom vendor OCF descriptor table — 21 entries matching the
/// C `vendor_ocf_table[]` exactly (names, sizes, fixed flags).
static VENDOR_OCF_TABLE: &[VendorOcf] = &[
    VendorOcf {
        ocf: 0x001,
        name: "Write BD ADDR",
        cmd_func: write_bd_addr_cmd,
        cmd_size: 6,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x018,
        name: "Update UART Baud Rate",
        cmd_func: update_uart_baud_rate_cmd,
        cmd_size: 6,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x01c,
        name: "Write SCO PCM Int Param",
        cmd_func: write_sco_pcm_int_param_cmd,
        cmd_size: 5,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x01d,
        name: "Read SCO PCM Int Param",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: read_sco_pcm_int_param_rsp,
        rsp_size: 6,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x027,
        name: "Set Sleepmode Param",
        cmd_func: set_sleepmode_param_cmd,
        cmd_size: 12,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x028,
        name: "Read Sleepmode Param",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: read_sleepmode_param_rsp,
        rsp_size: 13,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x02e,
        name: "Download Minidriver",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x034,
        name: "Enable Radio",
        cmd_func: enable_radio_cmd,
        cmd_size: 1,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x03b,
        name: "Enable USB HID Emulation",
        cmd_func: enable_usb_hid_emulation_cmd,
        cmd_size: 1,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x044,
        name: "Read UART Clock Setting",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: read_uart_clock_setting_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x045,
        name: "Write UART Clock Setting",
        cmd_func: write_uart_clock_setting_cmd,
        cmd_size: 1,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x048,
        name: "Read Raw RSSI",
        cmd_func: read_raw_rssi_cmd,
        cmd_size: 2,
        cmd_fixed: true,
        rsp_func: read_raw_rssi_rsp,
        rsp_size: 4,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x04c,
        name: "Write RAM",
        cmd_func: write_ram_cmd,
        cmd_size: 4,
        cmd_fixed: false,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x04d,
        name: "Read RAM",
        cmd_func: read_ram_cmd,
        cmd_size: 5,
        cmd_fixed: true,
        rsp_func: read_ram_rsp,
        rsp_size: 1,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x04e,
        name: "Launch RAM",
        cmd_func: launch_ram_cmd,
        cmd_size: 4,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x05a,
        name: "Read VID PID",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: read_vid_pid_rsp,
        rsp_size: 5,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x057,
        name: "Write High Priority Connection",
        cmd_func: write_high_priority_connection_cmd,
        cmd_size: 3,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x06d,
        name: "Write I2SPCM Interface Param",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x06e,
        name: "Read Controller Features",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: read_controller_features_rsp,
        rsp_size: 9,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x079,
        name: "Read Verbose Config Version Info",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: read_verbose_version_info_rsp,
        rsp_size: 7,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x07e,
        name: "Enable WBS",
        cmd_func: enable_wbs_cmd,
        cmd_size: 3,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
];

// ============================================================================
// Public OCF lookup
// ============================================================================

/// Look up a Broadcom vendor OCF descriptor by opcode.
///
/// Returns `Some(&VendorOcf)` if the OCF is recognized, `None` otherwise.
/// Uses linear search matching the C `broadcom_vendor_ocf()` implementation.
pub fn broadcom_vendor_ocf(ocf: u16) -> Option<&'static VendorOcf> {
    VENDOR_OCF_TABLE.iter().find(|entry| entry.ocf == ocf)
}

// ============================================================================
// LM Diagnostic decoder (lines 647-707 in broadcom.c)
// ============================================================================

/// Decode a 63-byte Broadcom LM diagnostic event.
///
/// Handles 4 diagnostic types: LMP sent (0x00), LMP receive (0x01),
/// LL sent (0x80), LL receive (0x81), and unknown types.
/// For LMP types, delegates to `lmp_packet`; for LL types, delegates
/// to `llcp_packet`.
///
/// If the data is not exactly 63 bytes, hexdumps the raw data.
///
/// This function is public because it is called from outside the vendor
/// module (from packet.rs or similar dispatch code).
pub fn broadcom_lm_diag(data: &[u8]) {
    if data.len() != 63 {
        display::print_hexdump(data);
        return;
    }

    let diag_type = get_u8(data);
    let clock = get_be32(&data[1..]);

    let type_str = match diag_type {
        0x00 => "LMP sent",
        0x01 => "LMP receive",
        0x80 => "LL sent",
        0x81 => "LL receive",
        _ => "Unknown",
    };

    print_field!("Type: {} ({})", type_str, diag_type);
    print_field!("Clock: 0x{:08x}", clock);

    match diag_type {
        0x00 => {
            // LMP sent: 4-byte partial address at data[5..9], 1 byte hexdump,
            // then LMP PDU at data[10..]
            let addr = &data[5..];
            print_field!(
                "Address: --:--:{:02X}:{:02X}:{:02X}:{:02X}",
                addr[0],
                addr[1],
                addr[2],
                addr[3]
            );
            display::print_hexdump(&data[9..10]);
            crate::dissectors::lmp::lmp_packet(&data[10..], (data.len() - 10) as u8, true);
        }
        0x01 => {
            // LMP receive: 4-byte partial address at data[5..9], 4 bytes hexdump,
            // then LMP PDU at data[13..]
            let addr = &data[5..];
            print_field!(
                "Address: --:--:{:02X}:{:02X}:{:02X}:{:02X}",
                addr[0],
                addr[1],
                addr[2],
                addr[3]
            );
            display::print_hexdump(&data[9..13]);
            crate::dissectors::lmp::lmp_packet(&data[13..], (data.len() - 13) as u8, true);
        }
        0x80 | 0x81 => {
            // LL sent/receive: 7 bytes hexdump at data[5..12],
            // then LLCP PDU at data[12..]
            display::print_hexdump(&data[5..12]);
            crate::dissectors::ll::llcp_packet(&data[12..], (data.len() - 12) as u8, true);
        }
        _ => {
            // Unknown type: hexdump from data[9..]
            display::print_hexdump(&data[9..]);
        }
    }
}

// ============================================================================
// Vendor Event Table (lines 709-718 in broadcom.c)
// ============================================================================

/// LM Diag event wrapper — forwards to `broadcom_lm_diag`.
fn lm_diag_evt(_index: u16, data: &[u8]) {
    broadcom_lm_diag(data);
}

/// Broadcom vendor event descriptor table — 1 entry matching the
/// C `vendor_evt_table[]` exactly.
static VENDOR_EVT_TABLE: &[VendorEvt] = &[VendorEvt {
    evt: 0xb4,
    name: "LM Diag",
    evt_func: lm_diag_evt,
    evt_size: 64,
    evt_fixed: true,
}];

// ============================================================================
// Public EVT lookup
// ============================================================================

/// Look up a Broadcom vendor event descriptor by event code.
///
/// Returns `Some(&VendorEvt)` if the event code is recognized, `None` otherwise.
/// Uses linear search matching the C `broadcom_vendor_evt()` implementation.
pub fn broadcom_vendor_evt(evt: u8) -> Option<&'static VendorEvt> {
    VENDOR_EVT_TABLE.iter().find(|entry| entry.evt == evt)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocf_write_bd_addr() {
        let e = broadcom_vendor_ocf(0x001).expect("OCF 0x001 should exist");
        assert_eq!(e.name, "Write BD ADDR");
        assert_eq!(e.ocf, 0x001);
        assert_eq!(e.cmd_size, 6);
        assert!(e.cmd_fixed);
        assert_eq!(e.rsp_size, 1);
        assert!(e.rsp_fixed);
    }

    #[test]
    fn test_ocf_update_uart_baud_rate() {
        let e = broadcom_vendor_ocf(0x018).expect("OCF 0x018 should exist");
        assert_eq!(e.name, "Update UART Baud Rate");
        assert_eq!(e.cmd_size, 6);
        assert!(e.cmd_fixed);
    }

    #[test]
    fn test_ocf_download_minidriver() {
        let e = broadcom_vendor_ocf(0x02e).expect("OCF 0x02e should exist");
        assert_eq!(e.name, "Download Minidriver");
        assert_eq!(e.cmd_size, 0);
        assert!(e.cmd_fixed);
        assert_eq!(e.rsp_size, 1);
        assert!(e.rsp_fixed);
    }

    #[test]
    fn test_ocf_write_ram() {
        let e = broadcom_vendor_ocf(0x04c).expect("OCF 0x04c should exist");
        assert_eq!(e.name, "Write RAM");
        assert_eq!(e.cmd_size, 4);
        assert!(!e.cmd_fixed);
        assert_eq!(e.rsp_size, 1);
        assert!(e.rsp_fixed);
    }

    #[test]
    fn test_ocf_read_ram() {
        let e = broadcom_vendor_ocf(0x04d).expect("OCF 0x04d should exist");
        assert_eq!(e.name, "Read RAM");
        assert_eq!(e.cmd_size, 5);
        assert!(e.cmd_fixed);
        assert!(!e.rsp_fixed);
    }

    #[test]
    fn test_ocf_launch_ram() {
        let e = broadcom_vendor_ocf(0x04e).expect("OCF 0x04e should exist");
        assert_eq!(e.name, "Launch RAM");
        assert_eq!(e.cmd_size, 4);
        assert!(e.cmd_fixed);
    }

    #[test]
    fn test_ocf_read_vid_pid() {
        let e = broadcom_vendor_ocf(0x05a).expect("OCF 0x05a should exist");
        assert_eq!(e.name, "Read VID PID");
        assert_eq!(e.cmd_size, 0);
        assert_eq!(e.rsp_size, 5);
        assert!(e.rsp_fixed);
    }

    #[test]
    fn test_ocf_enable_wbs() {
        let e = broadcom_vendor_ocf(0x07e).expect("OCF 0x07e should exist");
        assert_eq!(e.name, "Enable WBS");
        assert_eq!(e.cmd_size, 3);
        assert!(e.cmd_fixed);
    }

    #[test]
    fn test_ocf_write_i2spcm() {
        let e = broadcom_vendor_ocf(0x06d).expect("OCF 0x06d should exist");
        assert_eq!(e.name, "Write I2SPCM Interface Param");
        // C code has zero-initialized struct → both sizes 0, fixed false
        assert_eq!(e.cmd_size, 0);
        assert!(!e.cmd_fixed);
        assert_eq!(e.rsp_size, 0);
        assert!(!e.rsp_fixed);
    }

    #[test]
    fn test_ocf_nonexistent() {
        assert!(broadcom_vendor_ocf(0xFFF).is_none());
        assert!(broadcom_vendor_ocf(0x000).is_none());
        assert!(broadcom_vendor_ocf(0x002).is_none());
    }

    #[test]
    fn test_all_21_ocf_entries_exist() {
        // Actual OCF values from the C vendor_ocf_table[]
        let expected: &[u16] = &[
            0x001, 0x018, 0x01c, 0x01d, 0x027, 0x028, 0x02e, 0x034, 0x03b, 0x044, 0x045, 0x048,
            0x04c, 0x04d, 0x04e, 0x05a, 0x057, 0x06d, 0x06e, 0x079, 0x07e,
        ];
        assert_eq!(expected.len(), 21);
        for &ocf in expected {
            assert!(broadcom_vendor_ocf(ocf).is_some(), "OCF 0x{ocf:03x} missing");
        }
    }

    #[test]
    fn test_evt_lm_diag() {
        let e = broadcom_vendor_evt(0xb4).expect("EVT 0xb4 should exist");
        assert_eq!(e.name, "LM Diag");
        assert_eq!(e.evt, 0xb4);
        assert_eq!(e.evt_size, 64);
        assert!(e.evt_fixed);
    }

    #[test]
    fn test_evt_nonexistent() {
        assert!(broadcom_vendor_evt(0x00).is_none());
        assert!(broadcom_vendor_evt(0xFF).is_none());
        assert!(broadcom_vendor_evt(0xb3).is_none());
    }

    #[test]
    fn test_lm_diag_short_data() {
        broadcom_lm_diag(&[0u8; 10]);
    }

    #[test]
    fn test_lm_diag_lmp_sent() {
        let mut data = vec![0u8; 63];
        data[0] = 0x00;
        broadcom_lm_diag(&data);
    }

    #[test]
    fn test_lm_diag_lmp_receive() {
        let mut data = vec![0u8; 63];
        data[0] = 0x01;
        broadcom_lm_diag(&data);
    }

    #[test]
    fn test_lm_diag_ll_sent() {
        let mut data = vec![0u8; 63];
        data[0] = 0x80;
        broadcom_lm_diag(&data);
    }

    #[test]
    fn test_lm_diag_ll_receive() {
        let mut data = vec![0u8; 63];
        data[0] = 0x81;
        broadcom_lm_diag(&data);
    }

    #[test]
    fn test_lm_diag_unknown_type() {
        let mut data = vec![0u8; 63];
        data[0] = 0xFF;
        broadcom_lm_diag(&data);
    }

    #[test]
    fn test_status_rsp_no_panic() {
        let e = broadcom_vendor_ocf(0x001).unwrap();
        (e.rsp_func)(0, &[0x00]);
    }

    #[test]
    fn test_write_bd_addr_cmd_no_panic() {
        let e = broadcom_vendor_ocf(0x001).unwrap();
        (e.cmd_func)(0, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_update_uart_baud_rate_cmd_no_panic() {
        let e = broadcom_vendor_ocf(0x018).unwrap();
        (e.cmd_func)(0, &[0x00, 0x00, 0x00, 0xC2, 0x01, 0x00]);
    }

    #[test]
    fn test_write_sco_pcm_int_param_cmd_no_panic() {
        let e = broadcom_vendor_ocf(0x01c).unwrap();
        (e.cmd_func)(0, &[0x00, 0x01, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_enable_wbs_cmd_no_panic() {
        let e = broadcom_vendor_ocf(0x07e).unwrap();
        (e.cmd_func)(0, &[0x01, 0x02, 0x00]);
    }

    #[test]
    fn test_read_verbose_version_info_rsp_no_panic() {
        let e = broadcom_vendor_ocf(0x079).unwrap();
        (e.rsp_func)(0, &[0x00, 0x42, 0x03, 0x01, 0x00, 0x02, 0x00]);
    }

    #[test]
    fn test_read_controller_features_rsp_no_panic() {
        let e = broadcom_vendor_ocf(0x06e).unwrap();
        let data = [0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        (e.rsp_func)(0, &data);
    }

    #[test]
    fn test_enable_radio_cmd_no_panic() {
        let e = broadcom_vendor_ocf(0x034).unwrap();
        (e.cmd_func)(0, &[0x01]);
    }

    #[test]
    fn test_set_sleepmode_param_cmd_no_panic() {
        let e = broadcom_vendor_ocf(0x027).unwrap();
        let data = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        (e.cmd_func)(0, &data);
    }

    #[test]
    fn test_write_ram_cmd_no_panic() {
        let e = broadcom_vendor_ocf(0x04c).unwrap();
        let data = [0x00, 0x10, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        (e.cmd_func)(0, &data);
    }

    #[test]
    fn test_read_raw_rssi_no_panic() {
        let e = broadcom_vendor_ocf(0x048).unwrap();
        (e.cmd_func)(0, &[0x01, 0x00]);
        (e.rsp_func)(0, &[0x00, 0x01, 0x00, 0xE0_u8]);
    }

    #[test]
    fn test_error_to_str_known_codes() {
        assert_eq!(error_to_str(0x00), "Success");
        assert_eq!(error_to_str(0x01), "Unknown HCI Command");
        assert_eq!(error_to_str(0x05), "Authentication Failure");
        assert_eq!(error_to_str(0x09), "Connection Limit Exceeded");
        assert_eq!(error_to_str(0x0b), "ACL Connection Already Exists");
        assert_eq!(error_to_str(0x0c), "Command Disallowed");
        assert_eq!(error_to_str(0x12), "Invalid HCI Command Parameters");
        assert_eq!(error_to_str(0x45), "Packet Too Long");
    }

    #[test]
    fn test_error_to_str_unknown_code() {
        assert_eq!(error_to_str(0xFE), "Unknown");
    }
}
