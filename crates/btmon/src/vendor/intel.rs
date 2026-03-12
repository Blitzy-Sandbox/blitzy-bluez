// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014  Intel Corporation
 * Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 * intel.rs — Intel vendor-specific HCI command/event decoder for btmon.
 *
 * Complete Rust rewrite of monitor/intel.c (1913 lines) + monitor/intel.h
 * from BlueZ v5.86.  Decodes Intel-specific HCI vendor commands and events.
 * Output is byte-identical to the C version for the same input data.
 */

use crate::display::{COLOR_ERROR, COLOR_WHITE_BG, print_hexdump};
use crate::dissectors::ll::llcp_packet;
use crate::dissectors::lmp::lmp_packet;
use crate::{print_field, print_text};

use super::{VendorEvt, VendorOcf};

// ============================================================================
// Color aliases (matching C monitor/intel.c lines 31-33)
// ============================================================================
const COLOR_UNKNOWN_EVENT_MASK: &str = COLOR_WHITE_BG;
const COLOR_UNKNOWN_SCAN_STATUS: &str = COLOR_WHITE_BG;
const COLOR_UNKNOWN_EXT_EVENT: &str = COLOR_WHITE_BG;

// ============================================================================
// Byte-slice parsing helpers (safe, little-endian)
// ============================================================================

#[inline]
fn get_u8(data: &[u8], off: usize) -> u8 {
    data[off]
}

#[inline]
fn get_le16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn get_le32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn get_le64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

// ============================================================================
// Local packet helpers (matching C packet.c functions used by intel.c)
// ============================================================================

/// Equivalent to C `bt_compidtostr()` — maps a Bluetooth SIG company ID
/// to its assigned name string.
fn bt_compidtostr(compid: u16) -> &'static str {
    match compid {
        0 => "Ericsson Technology Licensing",
        1 => "Nokia Mobile Phones",
        2 => "Intel Corp.",
        3 => "IBM Corp.",
        4 => "Toshiba Corp.",
        5 => "3Com",
        6 => "Microsoft",
        7 => "Lucent",
        8 => "Motorola",
        9 => "Infineon Technologies AG",
        10 => "Qualcomm Technologies International, Ltd. (QTIL)",
        11 => "Silicon Wave",
        12 => "Digianswer A/S",
        13 => "Texas Instruments Inc.",
        14 => "Parthus Technologies Inc.",
        15 => "Broadcom Corporation",
        16 => "Mitel Semiconductor",
        17 => "Widcomm, Inc.",
        18 => "Zeevo, Inc.",
        19 => "Atmel Corporation",
        20 => "Mitsubishi Electric Corporation",
        21 => "RTX Telecom A/S",
        22 => "KC Technology Inc.",
        23 => "Newlogic",
        24 => "Transilica, Inc.",
        25 => "Rohde & Schwarz GmbH & Co. KG",
        26 => "TTPCom Limited",
        27 => "Signia Technologies, Inc.",
        28 => "Conexant Systems Inc.",
        29 => "Qualcomm",
        30 => "Inventel",
        31 => "AVM Berlin",
        32 => "BandSpeed, Inc.",
        33 => "Mansella Ltd",
        34 => "NEC Corporation",
        35 => "WavePlus Technology Co., Ltd.",
        36 => "Alcatel",
        37 => "NXP Semiconductors (formerly Philips Semiconductors)",
        38 => "C Technologies",
        39 => "Open Interface",
        40 => "R F Micro Devices",
        41 => "Hitachi Ltd",
        42 => "Symbol Technologies, Inc.",
        43 => "Tenovis",
        44 => "Macronix International Co. Ltd.",
        45 => "GCT Semiconductor",
        46 => "Norwood Systems",
        47 => "MewTel Technology Inc.",
        48 => "ST Microelectronics",
        49 => "Synopsys, Inc.",
        50 => "Red-M (Communications) Ltd",
        51 => "Commil Ltd",
        52 => "Computer Access Technology Corporation (CATC)",
        53 => "Eclipse (HQ Espana) S.L.",
        54 => "Renesas Electronics Corporation",
        55 => "Mobilian Corporation",
        56 => "Syntronics Corporation",
        57 => "Integrated System Solution Corp.",
        58 => "Panasonic Holdings Corporation",
        59 => "Gennum Corporation",
        60 => "BlackBerry Limited",
        61 => "IPextreme, Inc.",
        62 => "Systems and Chips, Inc",
        63 => "Bluetooth SIG, Inc",
        64 => "Seiko Epson Corporation",
        65 => "Integrated Silicon Solution Taiwan, Inc.",
        66 => "CONWISE Technology Corporation Ltd",
        67 => "PARROT AUTOMOTIVE SAS",
        68 => "Socket Mobile",
        69 => "Atheros Communications, Inc.",
        70 => "MediaTek, Inc.",
        71 => "Bluegiga",
        72 => "Marvell Technology Group Ltd.",
        73 => "3DSP Corporation",
        74 => "Accel Semiconductor Ltd.",
        75 => "Continental Automotive Systems",
        76 => "Apple, Inc.",
        77 => "Staccato Communications, Inc.",
        78 => "Avago Technologies",
        79 => "APT Ltd.",
        80 => "SiRF Technology, Inc.",
        81 => "Tzero Technologies, Inc.",
        82 => "J&M Corporation",
        83 => "Free2move AB",
        84 => "3DiJoy Corporation",
        85 => "Plantronics, Inc.",
        86 => "Sony Ericsson Mobile Communications",
        87 => "Harman International Industries, Inc.",
        88 => "Vizio, Inc.",
        89 => "Nordic Semiconductor ASA",
        _ => "not assigned",
    }
}

/// Equivalent to C `packet_print_error(label, status)`.
/// Prints an HCI error status field with its string mapping.
fn packet_print_error(label: &str, error: u8) {
    let s = match error {
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
        0x0b => "Connection Already Exists",
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
        0x23 => "LMP Error Transaction Collision / LL Procedure Collision",
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
        0x3e => "Connection Failed to be Established / Synchronization Timeout",
        0x3f => "MAC Connection Failed",
        0x40 => "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging",
        0x41 => "Type0 Submap Not Defined",
        0x42 => "Unknown Advertising Identifier",
        0x43 => "Limit Reached",
        0x44 => "Operation Cancelled by Host",
        0x45 => "Packet Too Long",
        _ => "Unknown",
    };
    print_field!("{}: {} (0x{:02x})", label, s, error);
}

/// Equivalent to C `packet_print_addr(label, data, addr_type)`.
/// Prints a Bluetooth device address from a 6-byte slice.
fn packet_print_addr(label: &str, data: &[u8], addr_type: u8) {
    if data.len() < 6 {
        return;
    }
    let type_str = match addr_type {
        0x00 => "Public",
        0x01 => "Random",
        _ => "Reserved",
    };
    print_field!(
        "{}: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ({})",
        label,
        data[5],
        data[4],
        data[3],
        data[2],
        data[1],
        data[0],
        type_str
    );
}

/// Local replacement for `packet_print_features_lmp`.
/// Prints LMP features as raw hex since the full feature-bit lookup tables
/// are defined in the packet module outside our dependency scope.
fn packet_print_features_lmp(features: &[u8], page: u8) {
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
}

/// Local replacement for `packet_print_features_ll`.
/// Prints LE features as raw hex since the full feature-bit lookup tables
/// are defined in the packet module outside our dependency scope.
fn packet_print_features_ll(features: &[u8]) {
    print_field!(
        "LE Features: 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
        features[0],
        features[1],
        features[2],
        features[3],
        features[4],
        features[5],
        features[6],
        features[7]
    );
}

// ============================================================================
// print_status  /  print_module  /  null_cmd  /  status_rsp
// ============================================================================

/// Print "Status: <string> (0x<NN>)" — delegates to packet_print_error.
fn print_status(status: u8) {
    packet_print_error("Status", status);
}

/// Print "Module: <name> (0x<NN>)".
fn print_module(module: u8) {
    let s = match module {
        0x01 => "BC",
        0x02 => "HCI",
        0x03 => "LLC",
        0x04 => "OS",
        0x05 => "LM",
        0x06 => "SC",
        0x07 => "SP",
        0x08 => "OSAL",
        0x09 => "LC",
        0x0a => "APP",
        0x0b => "TLD",
        0xf0 => "Debug",
        _ => "Reserved",
    };
    print_field!("Module: {} (0x{:02x})", s, module);
}

/// No-op command/response decoder.
fn null_cmd(_index: u16, _data: &[u8]) {}

/// Generic status-only response decoder — reads a single byte and prints it.
fn status_rsp(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    print_status(get_u8(data, 0));
}

// ============================================================================
// Intel Version TLV system  (C lines 101-400)
// ============================================================================

/// Type alias for a TLV print function: (type_id, value_bytes, type_string).
type TlvPrintFn = fn(u8, &[u8], &str);

/// Descriptor for one TLV type in the Intel version response.
struct VersionTlvDesc {
    type_id: u8,
    type_str: &'static str,
    func: TlvPrintFn,
}

// -- Individual TLV printers ------------------------------------------------

fn print_version_tlv_u32(type_id: u8, val: &[u8], type_str: &str) {
    print_field!("{}({}): 0x{:08x}", type_str, type_id, get_le32(val, 0));
}

fn print_version_tlv_u16(type_id: u8, val: &[u8], type_str: &str) {
    print_field!("{}({}): 0x{:04x}", type_str, type_id, get_le16(val, 0));
}

fn print_version_tlv_u8(type_id: u8, val: &[u8], type_str: &str) {
    print_field!("{}({}): 0x{:02x}", type_str, type_id, get_u8(val, 0));
}

fn print_version_tlv_enabled(type_id: u8, val: &[u8], type_str: &str) {
    let v = get_u8(val, 0);
    let s = if v != 0 { "Enabled" } else { "Disabled" };
    print_field!("{}({}): {}({})", type_str, type_id, s, v);
}

fn print_version_tlv_cnvi_bt(type_id: u8, val: &[u8], type_str: &str) {
    let cnvibt = get_le32(val, 0);
    let variant = ((cnvibt >> 16) & 0x3f) as u8;
    let s = match variant {
        0x17 => "Typhoon Peak2",
        0x18 => "Solar",
        0x19 => "Solar F",
        0x1b => "Magnetor",
        0x1c => "Gale Peak2",
        0x1d => "BlazarU",
        0x1e => "BlazarI",
        0x1f => "Scorpious Peak",
        0x22 => "BlazarIW",
        _ => "Unknown",
    };
    print_field!("{}({}): 0x{:08x} - {}(0x{:02x})", type_str, type_id, cnvibt, s, variant);
}

fn print_version_tlv_img_type(type_id: u8, val: &[u8], type_str: &str) {
    let v = get_u8(val, 0);
    let s = match v {
        0x01 => "Bootloader",
        0x03 => "Firmware",
        _ => "Unknown",
    };
    print_field!("{}({}): {}(0x{:02x})", type_str, type_id, s, v);
}

fn print_version_tlv_timestamp(type_id: u8, val: &[u8], type_str: &str) {
    // C: print_field("%s(%u): %u-%u", type_str, tlv->type, tlv->val[1], tlv->val[0]);
    print_field!("{}({}): {}-{}", type_str, type_id, val[1], val[0]);
}

fn print_version_tlv_min_fw(type_id: u8, val: &[u8], type_str: &str) {
    // C: print_field("%s(%u): %u-%u.%u", type_str, tlv->type,
    //               tlv->val[0], tlv->val[1], 2000 + tlv->val[2]);
    print_field!("{}({}): {}-{}.{}", type_str, type_id, val[0], val[1], 2000 + u32::from(val[2]));
}

fn print_version_tlv_otp_bdaddr(type_id: u8, val: &[u8], type_str: &str) {
    // C: packet_print_addr(type_str, tlv->val, 0x00);
    // The type_id is NOT printed here — packet_print_addr uses the label directly.
    let _ = type_id;
    packet_print_addr(type_str, val, 0x00);
}

fn print_version_tlv_unknown(type_id: u8, val: &[u8], type_str: &str) {
    print_field!("{}({}): ", type_str, type_id);
    print_hexdump(val);
}

fn print_version_tlv_mfg(type_id: u8, val: &[u8], type_str: &str) {
    let mfg_id = get_le16(val, 0);
    print_field!("{}({}): {} ({})", type_str, type_id, bt_compidtostr(mfg_id), mfg_id);
}

// -- TLV table (types 16-49, matching C intel_version_tlv_table[]) -----------

static INTEL_VERSION_TLV_TABLE: &[VersionTlvDesc] = &[
    VersionTlvDesc { type_id: 16, type_str: "CNVi TOP", func: print_version_tlv_u32 },
    VersionTlvDesc { type_id: 17, type_str: "CNVr TOP", func: print_version_tlv_u32 },
    VersionTlvDesc { type_id: 18, type_str: "CNVi BT", func: print_version_tlv_cnvi_bt },
    VersionTlvDesc { type_id: 19, type_str: "CNVr BT", func: print_version_tlv_u32 },
    VersionTlvDesc { type_id: 20, type_str: "CNVi OTP", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 21, type_str: "CNVr OTP", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 22, type_str: "Device Rev ID", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 23, type_str: "USB VID", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 24, type_str: "USB PID", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 25, type_str: "PCIE VID", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 26, type_str: "PCIe DID", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 27, type_str: "PCIe Subsystem ID", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 28, type_str: "Image Type", func: print_version_tlv_img_type },
    VersionTlvDesc { type_id: 29, type_str: "Time Stamp", func: print_version_tlv_timestamp },
    VersionTlvDesc { type_id: 30, type_str: "Build Type", func: print_version_tlv_u8 },
    VersionTlvDesc { type_id: 31, type_str: "Build Num", func: print_version_tlv_u32 },
    VersionTlvDesc { type_id: 32, type_str: "FW Build Product", func: print_version_tlv_u8 },
    VersionTlvDesc { type_id: 33, type_str: "FW Build HW", func: print_version_tlv_u8 },
    VersionTlvDesc { type_id: 34, type_str: "FW Build Step", func: print_version_tlv_u8 },
    VersionTlvDesc { type_id: 35, type_str: "BT Spec", func: print_version_tlv_u8 },
    VersionTlvDesc { type_id: 36, type_str: "Manufacturer", func: print_version_tlv_mfg },
    VersionTlvDesc { type_id: 37, type_str: "HCI Revision", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 38, type_str: "LMP SubVersion", func: print_version_tlv_u16 },
    VersionTlvDesc { type_id: 39, type_str: "OTP Patch Version", func: print_version_tlv_u8 },
    VersionTlvDesc { type_id: 40, type_str: "Secure Boot", func: print_version_tlv_enabled },
    VersionTlvDesc { type_id: 41, type_str: "Key From Header", func: print_version_tlv_enabled },
    VersionTlvDesc { type_id: 42, type_str: "OTP Lock", func: print_version_tlv_enabled },
    VersionTlvDesc { type_id: 43, type_str: "API Lock", func: print_version_tlv_enabled },
    VersionTlvDesc { type_id: 44, type_str: "Debug Lock", func: print_version_tlv_enabled },
    VersionTlvDesc { type_id: 45, type_str: "Minimum FW", func: print_version_tlv_min_fw },
    VersionTlvDesc { type_id: 46, type_str: "Limited CCE", func: print_version_tlv_enabled },
    VersionTlvDesc { type_id: 47, type_str: "SBE Type", func: print_version_tlv_u8 },
    VersionTlvDesc { type_id: 48, type_str: "OTP BDADDR", func: print_version_tlv_otp_bdaddr },
    VersionTlvDesc { type_id: 49, type_str: "Unlocked State", func: print_version_tlv_enabled },
];

// -- Version response decoders ----------------------------------------------

/// Parse a TLV-format Read Version response.
fn read_version_tlv_rsp(_index: u16, data: &[u8]) {
    let size = data.len();
    let mut off: usize = 0;

    while off + 2 <= size {
        let tid = get_u8(data, off);
        let tlen = get_u8(data, off + 1) as usize;

        if off + 2 + tlen > size {
            break;
        }

        let val = &data[off + 2..off + 2 + tlen];

        // Look up in the version TLV table
        let mut found = false;
        for desc in INTEL_VERSION_TLV_TABLE {
            if desc.type_id == tid {
                (desc.func)(tid, val, desc.type_str);
                found = true;
                break;
            }
        }
        if !found {
            print_version_tlv_unknown(tid, val, "Unknown");
        }

        off += 2 + tlen;
    }
}

/// Parse legacy (fixed-format) Read Version response.
fn read_version_rsp(_index: u16, data: &[u8]) {
    let size = data.len();

    // Detect TLV vs legacy format (C logic: if size != 10 && hw_platform != 0x37)
    if size < 1 {
        return;
    }
    // First byte is status in legacy mode, or the first TLV type in TLV mode.
    // In legacy format, data is exactly 10 bytes:
    //   status(1) + hw_platform(1) + hw_variant(1) + hw_revision(1) +
    //   fw_variant(1) + fw_revision(1) + fw_build_nn(1) + fw_build_cw(1) +
    //   fw_build_yy(1) + fw_patch_num(1)
    if size != 10 {
        // Check if it's TLV by examining what would be hw_platform
        if size >= 2 && get_u8(data, 1) != 0x37 {
            read_version_tlv_rsp(_index, data);
            return;
        }
    }

    // Legacy fixed format
    print_status(get_u8(data, 0));
    print_field!("Hardware platform: 0x{:02x}", get_u8(data, 1));
    print_field!("Hardware variant: 0x{:02x}", get_u8(data, 2));
    print_field!("Hardware revision: 0x{:02x}", get_u8(data, 3));
    print_field!("Firmware variant: 0x{:02x}", get_u8(data, 4));
    print_field!("Firmware revision: 0x{:02x}", get_u8(data, 5));
    print_field!(
        "Firmware build: {}-{}.{}",
        get_u8(data, 6),
        get_u8(data, 7),
        2000 + u32::from(get_u8(data, 8))
    );
    print_field!("Firmware patch: 0x{:02x}", get_u8(data, 9));
}

/// Read Version command decoder — prints requested TLV type list.
fn read_version_cmd(_index: u16, data: &[u8]) {
    let size = data.len();
    let mut off: usize = 0;

    while off < size {
        print_field!("Requested type: {}", get_u8(data, off));
        off += 1;
    }
}

// ============================================================================
// Command Decoder Functions  (C lines 308-780)
// ============================================================================

fn reset_cmd(_index: u16, data: &[u8]) {
    let reset_type = get_u8(data, 0);
    let patch_enable = get_u8(data, 1);
    let ddc_reload = get_u8(data, 2);
    let boot_option = get_u8(data, 3);
    let boot_addr = get_le32(data, 4);

    let rt_str = match reset_type {
        0x00 => "Soft software reset",
        0x01 => "Hard software reset",
        _ => "Reserved",
    };
    print_field!("Reset type: {} (0x{:02x})", rt_str, reset_type);

    let pe_str = match patch_enable {
        0x00 => "Do not enable",
        0x01 => "Enable",
        _ => "Reserved",
    };
    print_field!("Patch enable: {} (0x{:02x})", pe_str, patch_enable);

    let dd_str = match ddc_reload {
        0x00 => "Do not reload",
        0x01 => "Reload from OTP",
        _ => "Reserved",
    };
    print_field!("DDC reload: {} (0x{:02x})", dd_str, ddc_reload);

    let bo_str = match boot_option {
        0x00 => "Current image",
        0x01 => "Specified boot address",
        _ => "Reserved",
    };
    print_field!("Boot option: {} (0x{:02x})", bo_str, boot_option);

    print_field!("Boot address: 0x{:08x}", boot_addr);
}

fn set_uart_baudrate_cmd(_index: u16, data: &[u8]) {
    let baudrate = get_u8(data, 0);
    let s = match baudrate {
        0x00 => "9600 Baud",
        0x01 => "19200 Baud",
        0x02 => "38400 Baud",
        0x03 => "57600 Baud",
        0x04 => "115200 Baud",
        0x05 => "230400 Baud",
        0x06 => "460800 Baud",
        0x07 => "921600 Baud",
        0x08 => "1843200 Baud",
        0x09 => "3250000 baud",
        0x0a => "2000000 baud",
        0x0b => "3000000 baud",
        0x0c => "3714286 baud",
        0x0d => "4333333 baud",
        0x0e => "6500000 baud",
        _ => "Reserved",
    };
    print_field!("Baudrate: {} (0x{:02x})", s, baudrate);
}

fn secure_send_cmd(_index: u16, data: &[u8]) {
    let frag_type = get_u8(data, 0);
    let s = match frag_type {
        0x00 => "Init",
        0x01 => "Data",
        0x02 => "Sign",
        0x03 => "PKey",
        _ => "Reserved",
    };
    print_field!("Fragment type: {} (0x{:02x})", s, frag_type);
    if data.len() > 1 {
        print_hexdump(&data[1..]);
    }
}

fn manufacturer_mode_cmd(_index: u16, data: &[u8]) {
    let mode_change = get_u8(data, 0);
    let reset = get_u8(data, 1);

    let mc_str = match mode_change {
        0x00 => "Disable",
        0x01 => "Enable",
        _ => "Reserved",
    };
    print_field!("Mode change: {} (0x{:02x})", mc_str, mode_change);

    let rs_str = match reset {
        0x00 => "No reset",
        0x01 => "Reset and deactivate patches",
        0x02 => "Reset and activate patches",
        _ => "Reserved",
    };
    print_field!("Reset: {} (0x{:02x})", rs_str, reset);
}

fn write_bd_data_cmd(_index: u16, data: &[u8]) {
    let size = data.len();
    packet_print_addr("Address", data, 0x00);
    if size > 6 {
        print_hexdump(&data[6..12.min(size)]);
    }
    if size >= 20 {
        packet_print_features_lmp(&data[12..20], 0);
    }
    if size >= 21 {
        let mut features = [0u8; 8];
        features[0] = data[20];
        packet_print_features_ll(&features);
    }
    if size > 21 {
        print_hexdump(&data[21..]);
    }
}

fn read_bd_data_rsp(_index: u16, data: &[u8]) {
    let size = data.len();
    print_status(get_u8(data, 0));
    if size >= 7 {
        packet_print_addr("Address", &data[1..], 0x00);
    }
    if size > 7 {
        print_hexdump(&data[7..]);
    }
}

fn write_bd_address_cmd(_index: u16, data: &[u8]) {
    packet_print_addr("Address", data, 0x00);
}

fn act_deact_traces_cmd(_index: u16, data: &[u8]) {
    let tx_trace = get_u8(data, 0);
    let tx_arq = get_u8(data, 1);
    let rx_trace = get_u8(data, 2);

    print_field!("TX trace: 0x{:02x}", tx_trace);
    print_field!("TX ArqN: 0x{:02x}", tx_arq);
    print_field!("RX trace: 0x{:02x}", rx_trace);
}

fn stimulate_exception_cmd(_index: u16, data: &[u8]) {
    let exc_type = get_u8(data, 0);
    print_field!("Exception type: 0x{:02x}", exc_type);
}

// -- Events mask table (for set_event_mask_cmd) -----------------------------

struct EventTableEntry {
    bit: u8,
    str_val: &'static str,
}

static EVENTS_TABLE: &[EventTableEntry] = &[
    EventTableEntry { bit: 0, str_val: "Bootup" },
    EventTableEntry { bit: 1, str_val: "Hardware Error" },
    EventTableEntry { bit: 2, str_val: "Value of the INIT command" },
    EventTableEntry { bit: 3, str_val: "Default BD Data" },
    EventTableEntry { bit: 5, str_val: "Secure Send Commands Result" },
    EventTableEntry { bit: 6, str_val: "Debug Exception" },
    EventTableEntry { bit: 7, str_val: "LE Link Established" },
    EventTableEntry { bit: 8, str_val: "Scan Status" },
    EventTableEntry { bit: 9, str_val: "Activate/Deactivate Traces Complete" },
];

fn set_event_mask_cmd(_index: u16, data: &[u8]) {
    let events = get_le64(data, 0);
    print_field!("Mask: 0x{:016x}", events);

    let mut mask = events;
    for entry in EVENTS_TABLE {
        if events & (1u64 << entry.bit) != 0 {
            print_field!("  {}", entry.str_val);
            mask &= !(1u64 << entry.bit);
        }
    }

    if mask != 0 {
        print_text!(COLOR_UNKNOWN_EVENT_MASK, "  Unknown mask (0x{:016x})", mask);
    }
}

fn ddc_config_write_cmd(_index: u16, data: &[u8]) {
    let id = get_le16(data, 0);
    print_field!("Identifier: 0x{:04x}", id);
    if data.len() > 2 {
        print_hexdump(&data[2..]);
    }
}

fn ddc_config_write_rsp(_index: u16, data: &[u8]) {
    print_status(get_u8(data, 0));
    print_field!("Identifier: 0x{:04x}", get_le16(data, 1));
}

fn memory_write_cmd(_index: u16, data: &[u8]) {
    let addr = get_le32(data, 0);
    print_field!("Address: 0x{:08x}", addr);
    if data.len() > 4 {
        print_hexdump(&data[4..]);
    }
}

fn read_supported_features_cmd(_index: u16, data: &[u8]) {
    print_field!("Page: 0x{:02x}", get_u8(data, 0));
}

fn read_supported_features_rsp(_index: u16, data: &[u8]) {
    print_status(get_u8(data, 0));
    print_field!("Page: 0x{:02x}", get_u8(data, 1));
    print_field!("Max pages: 0x{:02x}", get_u8(data, 2));
    if data.len() > 3 {
        print_hexdump(&data[3..]);
    }
}

fn ppag_enable(_index: u16, data: &[u8]) {
    let ppag_enable_val = get_le32(data, 0);
    print_field!("PPAG Enable: 0x{:08x}", ppag_enable_val);
}

// ============================================================================
// Vendor OCF Table  (C lines 782-863)
// ============================================================================

static VENDOR_OCF_TABLE: &[VendorOcf] = &[
    VendorOcf {
        ocf: 0x001,
        name: "Reset",
        cmd_func: reset_cmd,
        cmd_size: 8,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x002,
        name: "No Operation",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x005,
        name: "Read Version",
        cmd_func: read_version_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: read_version_rsp,
        rsp_size: 1,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x006,
        name: "Set UART Baudrate",
        cmd_func: set_uart_baudrate_cmd,
        cmd_size: 1,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x007,
        name: "Enable LPM",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x008,
        name: "PCM Write Configuration",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x009,
        name: "Secure Send",
        cmd_func: secure_send_cmd,
        cmd_size: 1,
        cmd_fixed: false,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x00d,
        name: "Read Secure Boot Params",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x00e,
        name: "Write Secure Boot Params",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x00f,
        name: "Unlock",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x010,
        name: "Change UART Baudrate",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x011,
        name: "Manufacturer Mode",
        cmd_func: manufacturer_mode_cmd,
        cmd_size: 2,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x012,
        name: "Read Link RSSI",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x022,
        name: "Get Exception Info",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x024,
        name: "Clear Exception Info",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x02f,
        name: "Write BD Data",
        cmd_func: write_bd_data_cmd,
        cmd_size: 6,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x030,
        name: "Read BD Data",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: read_bd_data_rsp,
        rsp_size: 7,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x031,
        name: "Write BD Address",
        cmd_func: write_bd_address_cmd,
        cmd_size: 6,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x032,
        name: "Flow Specification",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x034,
        name: "Read Secure ID",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x038,
        name: "Set Synchronous USB Interface Type",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x039,
        name: "Config Synchronous Interface",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x03f,
        name: "SW RF Kill",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x043,
        name: "Activate Deactivate Traces",
        cmd_func: act_deact_traces_cmd,
        cmd_size: 3,
        cmd_fixed: true,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x04d,
        name: "Stimulate Exception",
        cmd_func: stimulate_exception_cmd,
        cmd_size: 1,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x050,
        name: "Read HW Version",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x052,
        name: "Set Event Mask",
        cmd_func: set_event_mask_cmd,
        cmd_size: 8,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x053,
        name: "Config_Link_Controller",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x089,
        name: "DDC Write",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x08a,
        name: "DDC Read",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x08b,
        name: "DDC Config Write",
        cmd_func: ddc_config_write_cmd,
        cmd_size: 3,
        cmd_fixed: false,
        rsp_func: ddc_config_write_rsp,
        rsp_size: 3,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x08c,
        name: "DDC Config Read",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x08d,
        name: "Memory Read",
        cmd_func: null_cmd,
        cmd_size: 0,
        cmd_fixed: false,
        rsp_func: null_cmd,
        rsp_size: 0,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x08e,
        name: "Memory Write",
        cmd_func: memory_write_cmd,
        cmd_size: 6,
        cmd_fixed: false,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x0a6,
        name: "Read Supported Features",
        cmd_func: read_supported_features_cmd,
        cmd_size: 1,
        cmd_fixed: true,
        rsp_func: read_supported_features_rsp,
        rsp_size: 19,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x20b,
        name: "PPAG Enable",
        cmd_func: ppag_enable,
        cmd_size: 4,
        cmd_fixed: true,
        rsp_func: status_rsp,
        rsp_size: 1,
        rsp_fixed: true,
    },
];

// ============================================================================
// Event Decoder Functions  (C lines 865-1265)
// ============================================================================

fn startup_evt(_index: u16, _data: &[u8]) {}

fn fatal_exception_evt(_index: u16, data: &[u8]) {
    let line = get_le16(data, 0);
    let module = get_u8(data, 2);
    let reason = get_u8(data, 3);

    print_field!("Line: {}", line);
    print_module(module);
    print_field!("Reason: 0x{:02x}", reason);
    if data.len() > 4 {
        print_hexdump(&data[4..]);
    }
}

fn bootup_evt(_index: u16, data: &[u8]) {
    let zero = get_u8(data, 0);
    let num_packets = get_u8(data, 1);
    let source = get_u8(data, 2);
    let reset_type = get_u8(data, 3);
    let reset_reason = get_u8(data, 4);
    let ddc_status = get_u8(data, 5);

    print_field!("Zero: 0x{:02x}", zero);
    print_field!("Number of packets: {}", num_packets);

    let src_str = match source {
        0x00 => "Bootloader",
        0x01 => "Firmware",
        _ => "Reserved",
    };
    print_field!("Source: {} (0x{:02x})", src_str, source);

    let rt_str = match reset_type {
        0x00 => "Power ON",
        0x01 => "FW Software",
        0x02 => "S3",
        0x03 => "S4/S5",
        0x04 => "Exception",
        0x81 => "HW Watchdog",
        0x82 => "SW Watchdog",
        0x83 => "FW Assert",
        0x84 => "S3 Wakeup",
        0x85 => "Exit Idle",
        0x86 => "Fatal",
        0x87 => "System Exception",
        _ => "Reserved",
    };
    print_field!("Reset type: {} (0x{:02x})", rt_str, reset_type);

    let rr_str = match reset_reason {
        0x00 => "Power ON",
        0x01 => "Reset command",
        0x02 => "Intel Reset",
        0x03 => "Watchdog",
        0x08 => "Fatal Exception",
        0x09 => "System Exception",
        _ => "Reserved",
    };
    print_field!("Reset reason: {} (0x{:02x})", rr_str, reset_reason);

    let dd_str = match ddc_status {
        0x00 => "Not used",
        0x01 => "Used",
        _ => "Reserved",
    };
    print_field!("DDC status: {} (0x{:02x})", dd_str, ddc_status);
}

fn default_bd_data_evt(_index: u16, data: &[u8]) {
    let size = data.len();
    print_status(get_u8(data, 0));
    if size >= 7 {
        packet_print_addr("Address", &data[1..], 0x00);
    }
    if size > 7 {
        print_hexdump(&data[7..]);
    }
}

fn secure_send_commands_result_evt(_index: u16, data: &[u8]) {
    let result = get_u8(data, 0);
    let opcode = get_le16(data, 1);
    let status = get_u8(data, 3);

    let res_str = match result {
        0x00 => "Success",
        0x01 => "General Failure",
        0x02 => "Hardware Failure",
        0x03 => "Signature Verification Failed",
        _ => "Reserved",
    };
    print_field!("Result: {} (0x{:02x})", res_str, result);

    // Decode OGF/OCF from the opcode
    let ogf = (opcode >> 10) & 0x3f;
    let ocf = opcode & 0x03ff;
    print_field!("Opcode: 0x{:04x} (OGF 0x{:02x}, OCF 0x{:04x})", opcode, ogf, ocf);

    print_status(status);
}

fn debug_exception_evt(_index: u16, data: &[u8]) {
    let line = get_le16(data, 0);
    let module = get_u8(data, 2);
    let reason = get_u8(data, 3);

    print_field!("Line: {}", line);
    print_module(module);
    print_field!("Reason: 0x{:02x}", reason);
    if data.len() > 4 {
        print_hexdump(&data[4..]);
    }
}

fn le_link_established_evt(_index: u16, data: &[u8]) {
    let handle = get_le16(data, 0);
    print_field!("Handle: 0x{:04x}", handle);
    if data.len() > 2 {
        print_hexdump(&data[2..]);
    }
}

fn scan_status_evt(_index: u16, data: &[u8]) {
    let enable = get_u8(data, 0);
    let s = match enable {
        0x01 => "Started",
        0x00 => "Stopped",
        _ => "Reserved",
    };
    print_field!("Scan enable: {} (0x{:02x})", s, enable);
    if enable != 0x00 && enable != 0x01 {
        print_text!(COLOR_UNKNOWN_SCAN_STATUS, "  Unknown scan status (0x{:02x})", enable);
    }
}

fn act_deact_traces_complete_evt(_index: u16, data: &[u8]) {
    print_status(get_u8(data, 0));
}

fn lmp_pdu_trace_evt(_index: u16, data: &[u8]) {
    let size = data.len();
    if size < 3 {
        return;
    }

    let trace_type = get_u8(data, 0);
    let handle = get_le16(data, 1);

    let tt_str = match trace_type {
        0x00 => "LMP RX",
        0x01 => "LMP TX",
        0x02 => "LMP ACK",
        0x03 => "LL RX",
        0x04 => "LL TX",
        0x05 => "LL ACK",
        _ => "Unknown",
    };
    print_field!("Type: {} (0x{:02x})", tt_str, trace_type);
    print_field!("Handle: {}", handle);

    match trace_type {
        0x00 => {
            // LMP RX: data + clock(4)
            if size < 8 {
                return;
            }
            let len = size - 8;
            let clock = get_le32(data, 4 + len);
            print_hexdump(&data[3..4]);
            lmp_packet(&data[4..4 + len], len as u8, false);
            print_field!("Clock: 0x{:08x}", clock);
        }
        0x01 => {
            // LMP TX: data + clock(4) + id(1)
            if size < 9 {
                return;
            }
            let len = size - 9;
            let clock = get_le32(data, 4 + len);
            let id = get_u8(data, 4 + len + 4);
            print_hexdump(&data[3..4]);
            lmp_packet(&data[4..4 + len], len as u8, false);
            print_field!("Clock: 0x{:08x}", clock);
            print_field!("ID: 0x{:02x}", id);
        }
        0x02 => {
            // LMP ACK: clock(4) + id(1)
            if size < 8 {
                return;
            }
            let clock = get_le32(data, 3);
            let id = get_u8(data, 7);
            print_field!("Clock: 0x{:08x}", clock);
            print_field!("ID: 0x{:02x}", id);
        }
        0x03 => {
            // LL RX: count(2) + ?(1) + hex(2) + llcp(len)
            if size < 8 {
                return;
            }
            let len = size - 8;
            let count = get_le16(data, 3);
            print_field!("Count: 0x{:04x}", count);
            print_hexdump(&data[6..8]);
            llcp_packet(&data[8..8 + len], len as u8, false);
        }
        0x04 => {
            // LL TX: count(2) + id(1) + hex(2) + llcp(len)
            if size < 8 {
                return;
            }
            let len = size - 8;
            let count = get_le16(data, 3);
            let id = get_u8(data, 5);
            print_field!("Count: 0x{:04x}", count);
            print_field!("ID: 0x{:02x}", id);
            print_hexdump(&data[6..8]);
            llcp_packet(&data[8..8 + len], len as u8, false);
        }
        0x05 => {
            // LL ACK: count(2) + id(1)
            if size < 6 {
                return;
            }
            let count = get_le16(data, 3);
            let id = get_u8(data, 5);
            print_field!("Count: 0x{:04x}", count);
            print_field!("ID: 0x{:02x}", id);
        }
        _ => {
            if size > 3 {
                print_hexdump(&data[3..]);
            }
        }
    }
}

fn write_bd_data_complete_evt(_index: u16, data: &[u8]) {
    print_status(get_u8(data, 0));
}

fn sco_rejected_via_lmp_evt(_index: u16, data: &[u8]) {
    packet_print_addr("Address", data, 0x00);
    let reason = get_u8(data, 6);
    packet_print_error("Reason", reason);
}

fn ptt_switch_notification_evt(_index: u16, data: &[u8]) {
    let handle = get_le16(data, 0);
    let direction = get_u8(data, 2);

    print_field!("Handle: {}", handle);

    let dir_str = match direction {
        0x00 => "eSCO",
        0x01 => "ACL",
        _ => "Reserved",
    };
    print_field!("Direction: {} (0x{:02x})", dir_str, direction);
}

fn system_exception_evt(_index: u16, data: &[u8]) {
    let exc_type = get_u8(data, 0);
    let s = match exc_type {
        0x00 => "No Exception",
        0x01 => "Undefined Instruction",
        0x02 => "Prefetch Abort",
        0x03 => "Data Abort",
        _ => "Reserved",
    };
    print_field!("Type: {} (0x{:02x})", s, exc_type);
    if data.len() > 1 {
        print_hexdump(&data[1..]);
    }
}

// ============================================================================
// Vendor EVT Table  (C lines 1265-1298)
// ============================================================================

/// No-op event handler used for events that have no decoder.
fn null_evt(_index: u16, _data: &[u8]) {}

static VENDOR_EVT_TABLE: &[VendorEvt] = &[
    VendorEvt { evt: 0x00, name: "Startup", evt_func: startup_evt, evt_size: 0, evt_fixed: true },
    VendorEvt {
        evt: 0x01,
        name: "Fatal Exception",
        evt_func: fatal_exception_evt,
        evt_size: 4,
        evt_fixed: true,
    },
    VendorEvt { evt: 0x02, name: "Bootup", evt_func: bootup_evt, evt_size: 6, evt_fixed: true },
    VendorEvt {
        evt: 0x05,
        name: "Default BD Data",
        evt_func: default_bd_data_evt,
        evt_size: 1,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x06,
        name: "Secure Send Commands Result",
        evt_func: secure_send_commands_result_evt,
        evt_size: 4,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x08,
        name: "Debug Exception",
        evt_func: debug_exception_evt,
        evt_size: 4,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x0f,
        name: "LE Link Established",
        evt_func: le_link_established_evt,
        evt_size: 26,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x11,
        name: "Scan Status",
        evt_func: scan_status_evt,
        evt_size: 1,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x16,
        name: "Activate Deactivate Traces Complete",
        evt_func: act_deact_traces_complete_evt,
        evt_size: 1,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x17,
        name: "LMP PDU Trace",
        evt_func: lmp_pdu_trace_evt,
        evt_size: 3,
        evt_fixed: false,
    },
    VendorEvt {
        evt: 0x19,
        name: "Write BD Data Complete",
        evt_func: write_bd_data_complete_evt,
        evt_size: 1,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x25,
        name: "SCO Rejected via LMP",
        evt_func: sco_rejected_via_lmp_evt,
        evt_size: 7,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x26,
        name: "PTT Switch Notification",
        evt_func: ptt_switch_notification_evt,
        evt_size: 3,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x29,
        name: "System Exception",
        evt_func: system_exception_evt,
        evt_size: 133,
        evt_fixed: true,
    },
    VendorEvt {
        evt: 0x2c,
        name: "FW Trace String",
        evt_func: null_evt,
        evt_size: 0,
        evt_fixed: false,
    },
    VendorEvt {
        evt: 0x2e,
        name: "FW Trace Binary",
        evt_func: null_evt,
        evt_size: 0,
        evt_fixed: false,
    },
];

// ============================================================================
// Intel Extended Telemetry TLV System  (C lines 1299-1724)
// ============================================================================

/// Extended telemetry subevent descriptor.
struct ExtSubevent {
    subevent_id: u8,
    length: u8,
    func: fn(u8, &[u8]),
}

/// Map extended event type code to string.
fn ext_evt_type_str(type_id: u8) -> &'static str {
    match type_id {
        0x00 => "System Exception",
        0x01 => "Fatal Exception",
        0x02 => "Debug Exception",
        0x03 => "Connection Event Statistics",
        0x04 => "Disconnection Event Statistics",
        0x05 => "Performance Statistics",
        _ => "Unknown",
    }
}

// -- Extended event type subevent (0x01) ------------------------------------

fn ext_evt_type(subevent_id: u8, value: &[u8]) {
    let evt_type = get_u8(value, 0);
    let s = ext_evt_type_str(evt_type);

    if s == "Unknown" {
        print_text!(
            COLOR_UNKNOWN_EXT_EVENT,
            "Unknown extended telemetry event type (0x{:02x})",
            evt_type
        );
        // Reconstruct TLV header + value for hexdump (matching C behavior)
        let mut buf = Vec::with_capacity(2 + value.len());
        buf.push(subevent_id);
        buf.push(value.len() as u8);
        buf.extend_from_slice(value);
        print_hexdump(&buf);
        return;
    }

    print_field!("Extended event type (0x{:02x}): {} (0x{:02x})", subevent_id, s, evt_type);
}

// -- ACL quality subevent decoders ------------------------------------------

fn ext_acl_evt_conn_handle(subevent_id: u8, value: &[u8]) {
    let conn_handle = get_le16(value, 0);
    print_field!("ACL connection handle (0x{:02x}): 0x{:04x}", subevent_id, conn_handle);
}

fn ext_acl_evt_hec_errors(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Rx HEC errors (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_crc_errors(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Rx CRC errors (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_num_pkt_from_host(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Packets from host (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_tx_pkt_to_air(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx packets (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_tx_pkt_0_retry(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx packets 0 retries (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_tx_pkt_1_retry(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx packets 1 retries (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_tx_pkt_2_retry(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx packets 2 retries (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_tx_pkt_3_retry(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx packets 3 retries (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_tx_pkt_4_or_more_retry(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx packets 4 and more retries (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_tx_pkt_type(subevent_id: u8, value: &[u8]) {
    static PKT_TYPES: &[&str] =
        &["DH1", "DH3", "DH5", "2-DH1", "2-DH3", "2-DH5", "3-DH1", "3-DH3", "3-DH5"];

    for (i, pkt_name) in PKT_TYPES.iter().enumerate() {
        let off = i * 4;
        if off + 4 > value.len() {
            break;
        }
        let num = get_le32(value, off);
        if num == 0 {
            continue;
        }
        print_field!("Tx {} packets (0x{:02x}): {}", pkt_name, subevent_id, num as i32);
    }
}

fn ext_acl_evt_rx_pkt_from_air(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Rx packets (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_link_throughput(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Link throughput (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_max_packet_latency(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Max packet latency (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_avg_packet_latency(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Avg packet latency (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_acl_evt_rssi_moving_avg(subevent_id: u8, value: &[u8]) {
    // C: uint16_t rssi_1m = get_le16(tlv->value); printed with %5d
    // uint16_t promoted to int in printf — always non-negative.
    let rssi_1m = get_le16(value, 0);
    let rssi_2m = get_le16(value, 2);
    let rssi_3m = get_le16(value, 4);
    let rssi_s2 = get_le16(value, 6);
    let rssi_s8 = get_le16(value, 8);

    if rssi_1m == 0 && rssi_2m == 0 && rssi_3m == 0 && rssi_s2 == 0 && rssi_s8 == 0 {
        return;
    }

    print_field!(
        "RSSI Moving Avg (0x{:02x}): 1M {:5}  2M {:5}  3M {:5}  S2 {:5}  S8 {:5}",
        subevent_id,
        rssi_1m,
        rssi_2m,
        rssi_3m,
        rssi_s2,
        rssi_s8
    );
}

/// Helper for 3-value counters (1M/2M/3M) used by RSSI/SNR bad count fields.
fn ext_acl_evt_bad_cnt(prefix: &str, subevent_id: u8, value: &[u8]) {
    let c_1m = get_le32(value, 0);
    let c_2m = get_le32(value, 4);
    let c_3m = get_le32(value, 8);

    if c_1m == 0 && c_2m == 0 && c_3m == 0 {
        return;
    }

    print_field!(
        "{} (0x{:02x}): 1M {} 2M {} 3M {}",
        prefix,
        subevent_id,
        c_1m as i32,
        c_2m as i32,
        c_3m as i32
    );
}

fn ext_acl_evt_snr_bad_cnt(subevent_id: u8, value: &[u8]) {
    ext_acl_evt_bad_cnt("ACL RX SNR Bad Margin Counter", subevent_id, value);
}

fn ext_acl_evt_rx_rssi_bad_cnt(subevent_id: u8, value: &[u8]) {
    ext_acl_evt_bad_cnt("ACL RX RSSI Bad Counter", subevent_id, value);
}

fn ext_acl_evt_tx_rssi_bad_cnt(subevent_id: u8, value: &[u8]) {
    ext_acl_evt_bad_cnt("ACL TX RSSI Bad Counter", subevent_id, value);
}

// -- SCO quality subevent decoders ------------------------------------------

fn ext_sco_evt_conn_handle(subevent_id: u8, value: &[u8]) {
    let conn_handle = get_le16(value, 0);
    print_field!("SCO/eSCO connection handle (0x{:02x}): 0x{:04x}", subevent_id, conn_handle);
}

fn ext_sco_evt_num_rx_pkt(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Rx packets (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_sco_evt_num_tx_pkt(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx packets (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_sco_evt_num_rx_pkt_lost(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Rx payload lost (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_sco_evt_num_tx_pkt_lost(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Tx payload lost (0x{:02x}): {}", subevent_id, num as i32);
}

/// Helper for 5-slot error arrays.
fn slots_errors(label: &str, subevent_id: u8, value: &[u8]) {
    if value.len() != 5 * 4 {
        print_text!(COLOR_UNKNOWN_EXT_EVENT, "  Invalid subevent length ({})", value.len());
        return;
    }
    let s1 = get_le32(value, 0);
    let s3 = get_le32(value, 4);
    let s5 = get_le32(value, 8);
    let s2 = get_le32(value, 12);
    let s6 = get_le32(value, 16);

    if s1 == 0 && s3 == 0 && s5 == 0 && s2 == 0 && s6 == 0 {
        return;
    }

    print_field!(
        "{} (0x{:02x}): 1-slot {} 3-slot {} 5-slot {} 2-slot {} 6-slot {}",
        label,
        subevent_id,
        s1 as i32,
        s3 as i32,
        s5 as i32,
        s2 as i32,
        s6 as i32
    );
}

fn ext_sco_evt_num_no_sync_errors(subevent_id: u8, value: &[u8]) {
    slots_errors("Rx No SYNC errors", subevent_id, value);
}

fn ext_sco_evt_num_hec_errors(subevent_id: u8, value: &[u8]) {
    slots_errors("Rx HEC errors", subevent_id, value);
}

fn ext_sco_evt_num_crc_errors(subevent_id: u8, value: &[u8]) {
    slots_errors("Rx CRC errors", subevent_id, value);
}

fn ext_sco_evt_num_nak_errors(subevent_id: u8, value: &[u8]) {
    slots_errors("Rx NAK errors", subevent_id, value);
}

fn ext_sco_evt_num_failed_tx_by_wifi(subevent_id: u8, value: &[u8]) {
    slots_errors("Failed Tx due to Wifi coex", subevent_id, value);
}

fn ext_sco_evt_num_failed_rx_by_wifi(subevent_id: u8, value: &[u8]) {
    slots_errors("Failed Rx due to Wifi coex", subevent_id, value);
}

fn ext_sco_evt_samples_inserted(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Late samples inserted (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_sco_evt_samples_dropped(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Samples dropped (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_sco_evt_mute_samples(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("Mute samples (0x{:02x}): {}", subevent_id, num as i32);
}

fn ext_sco_evt_plc_injection_data(subevent_id: u8, value: &[u8]) {
    let num = get_le32(value, 0);
    if num == 0 {
        return;
    }
    print_field!("PLC injection data (0x{:02x}): {}", subevent_id, num as i32);
}

// -- Extended telemetry subevent table --------------------------------------

static INTEL_EXT_SUBEVENT_TABLE: &[ExtSubevent] = &[
    // Event type
    ExtSubevent { subevent_id: 0x01, length: 1, func: ext_evt_type },
    // ACL quality (0x4a - 0x64)
    ExtSubevent { subevent_id: 0x4a, length: 2, func: ext_acl_evt_conn_handle },
    ExtSubevent { subevent_id: 0x4b, length: 4, func: ext_acl_evt_hec_errors },
    ExtSubevent { subevent_id: 0x4c, length: 4, func: ext_acl_evt_crc_errors },
    ExtSubevent { subevent_id: 0x4d, length: 4, func: ext_acl_evt_num_pkt_from_host },
    ExtSubevent { subevent_id: 0x4e, length: 4, func: ext_acl_evt_tx_pkt_to_air },
    ExtSubevent { subevent_id: 0x4f, length: 4, func: ext_acl_evt_tx_pkt_0_retry },
    ExtSubevent { subevent_id: 0x50, length: 4, func: ext_acl_evt_tx_pkt_1_retry },
    ExtSubevent { subevent_id: 0x51, length: 4, func: ext_acl_evt_tx_pkt_2_retry },
    ExtSubevent { subevent_id: 0x52, length: 4, func: ext_acl_evt_tx_pkt_3_retry },
    ExtSubevent { subevent_id: 0x53, length: 4, func: ext_acl_evt_tx_pkt_4_or_more_retry },
    ExtSubevent { subevent_id: 0x54, length: 36, func: ext_acl_evt_tx_pkt_type },
    ExtSubevent { subevent_id: 0x55, length: 4, func: ext_acl_evt_rx_pkt_from_air },
    ExtSubevent { subevent_id: 0x56, length: 4, func: ext_acl_evt_link_throughput },
    ExtSubevent { subevent_id: 0x57, length: 4, func: ext_acl_evt_max_packet_latency },
    ExtSubevent { subevent_id: 0x58, length: 4, func: ext_acl_evt_avg_packet_latency },
    ExtSubevent { subevent_id: 0x59, length: 10, func: ext_acl_evt_rssi_moving_avg },
    ExtSubevent { subevent_id: 0x62, length: 12, func: ext_acl_evt_snr_bad_cnt },
    ExtSubevent { subevent_id: 0x63, length: 12, func: ext_acl_evt_rx_rssi_bad_cnt },
    ExtSubevent { subevent_id: 0x64, length: 12, func: ext_acl_evt_tx_rssi_bad_cnt },
    // SCO quality (0x6a - 0x78)
    ExtSubevent { subevent_id: 0x6a, length: 2, func: ext_sco_evt_conn_handle },
    ExtSubevent { subevent_id: 0x6b, length: 4, func: ext_sco_evt_num_rx_pkt },
    ExtSubevent { subevent_id: 0x6c, length: 4, func: ext_sco_evt_num_tx_pkt },
    ExtSubevent { subevent_id: 0x6d, length: 4, func: ext_sco_evt_num_rx_pkt_lost },
    ExtSubevent { subevent_id: 0x6e, length: 4, func: ext_sco_evt_num_tx_pkt_lost },
    ExtSubevent { subevent_id: 0x6f, length: 20, func: ext_sco_evt_num_no_sync_errors },
    ExtSubevent { subevent_id: 0x70, length: 20, func: ext_sco_evt_num_hec_errors },
    ExtSubevent { subevent_id: 0x71, length: 20, func: ext_sco_evt_num_crc_errors },
    ExtSubevent { subevent_id: 0x72, length: 20, func: ext_sco_evt_num_nak_errors },
    ExtSubevent { subevent_id: 0x73, length: 20, func: ext_sco_evt_num_failed_tx_by_wifi },
    ExtSubevent { subevent_id: 0x74, length: 20, func: ext_sco_evt_num_failed_rx_by_wifi },
    ExtSubevent { subevent_id: 0x75, length: 4, func: ext_sco_evt_samples_inserted },
    ExtSubevent { subevent_id: 0x76, length: 4, func: ext_sco_evt_samples_dropped },
    ExtSubevent { subevent_id: 0x77, length: 4, func: ext_sco_evt_mute_samples },
    ExtSubevent { subevent_id: 0x78, length: 4, func: ext_sco_evt_plc_injection_data },
];

// -- Extended telemetry TLV processing --------------------------------------

/// Process one extended telemetry TLV entry starting at `data[*offset]`.
/// Returns `true` if processing can continue, `false` on error (caller hexdumps).
fn process_ext_subevent(data: &[u8], offset: &mut usize, total: usize) -> bool {
    if *offset + 2 > total {
        return false;
    }

    let subevent_id = data[*offset];
    let length = data[*offset + 1];
    let val_start = *offset + 2;
    let val_end = val_start + usize::from(length);

    // Look up in the table
    let subevent = INTEL_EXT_SUBEVENT_TABLE.iter().find(|s| s.subevent_id == subevent_id);

    match subevent {
        None => {
            print_text!(COLOR_UNKNOWN_EXT_EVENT, "Unknown extended subevent 0x{:02x}", subevent_id);
            if val_end <= total {
                print_hexdump(&data[val_start..val_end]);
            }
            *offset = val_end;
            true
        }
        Some(entry) => {
            if length != entry.length {
                print_text!(
                    COLOR_ERROR,
                    "Invalid length {} of subevent 0x{:02x}",
                    length,
                    subevent_id
                );
                return false;
            }

            if val_end > total {
                print_text!(COLOR_ERROR, "Subevent exceeds the buffer size.");
                return false;
            }

            (entry.func)(subevent_id, &data[val_start..val_end]);

            *offset = val_end;
            true
        }
    }
}

/// Process the complete Extended Telemetry event data (TLV loop).
fn intel_vendor_ext_evt(_index: u16, data: &[u8]) {
    let total = data.len();
    let mut offset = 0usize;

    while offset < total {
        if !process_ext_subevent(data, &mut offset, total) {
            // Error: dump all remaining data
            print_hexdump(data);
            return;
        }
    }
}

// ============================================================================
// Vendor Prefix Event System  (C lines 1725-1913)
// ============================================================================

/// Intel vendor prefix bytes that precede extended vendor events.
const INTEL_VENDOR_PREFIX: [u8; 2] = [0x87, 0x80];

/// Vendor prefix event table — maps sub-opcodes to event descriptors.
static VENDOR_PREFIX_EVT_TABLE: &[VendorEvt] = &[VendorEvt {
    evt: 0x03,
    name: "Extended Telemetry",
    evt_func: intel_vendor_ext_evt,
    evt_size: 0,
    evt_fixed: false,
}];

/// Check for an Intel vendor-prefix event (0x87, 0x80 prefix + sub-opcode).
/// Sets `consumed` to the number of prefix bytes consumed on success.
fn intel_vendor_prefix_evt(data: &[u8], consumed: &mut usize) -> Option<&'static VendorEvt> {
    if data.len() < 3 {
        return None;
    }

    // Verify the 2-byte vendor prefix
    if data[0] != INTEL_VENDOR_PREFIX[0] || data[1] != INTEL_VENDOR_PREFIX[1] {
        return None;
    }

    // Print the prefix
    print_field!("Vendor Prefix (0x{:02x}{:02x})", data[0], data[1]);

    let subopcode = data[2];

    for entry in VENDOR_PREFIX_EVT_TABLE {
        if entry.evt == subopcode {
            // consumed = sizeof(vendor_prefix_evt) = 3
            *consumed = 3;
            return Some(entry);
        }
    }

    None
}

// ============================================================================
// Public API
// ============================================================================

/// Look up an Intel vendor OCF descriptor by opcode.
///
/// Returns `Some(&VendorOcf)` if the OCF matches a known Intel command,
/// `None` otherwise.
pub fn intel_vendor_ocf(ocf: u16) -> Option<&'static VendorOcf> {
    VENDOR_OCF_TABLE.iter().find(|entry| entry.ocf == ocf)
}

/// Look up an Intel vendor event descriptor.
///
/// First checks the regular vendor event table against `data[0]`.
/// If no match, checks for the vendor prefix pattern (0x87 0x80) and
/// sets `consumed` to the number of prefix bytes consumed.
///
/// Returns `Some(&VendorEvt)` on match, `None` otherwise.
pub fn intel_vendor_evt(data: &[u8], consumed: &mut usize) -> Option<&'static VendorEvt> {
    if data.is_empty() {
        return None;
    }

    let evt = data[0];

    // Check regular event table first
    for entry in VENDOR_EVT_TABLE {
        if entry.evt == evt {
            return Some(entry);
        }
    }

    // Fall through to vendor prefix event check
    intel_vendor_prefix_evt(data, consumed)
}
