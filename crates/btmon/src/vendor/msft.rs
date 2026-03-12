//! Microsoft vendor HCI extension decoder for btmon.
//!
//! Complete C-to-Rust rewrite of `monitor/msft.c` (316 lines) + `monitor/msft.h`
//! (189 lines). Decodes MSFT HCI vendor commands, responses, and events.
//! Output MUST be byte-identical to the C version for the same input data.
//!
//! The MSFT extension uses a single OCF (0x000, "Extension") that internally
//! dispatches via the first data byte (subcommand code) to a 7-entry command
//! table covering: Read Supported Features, Monitor RSSI, Cancel Monitor RSSI,
//! LE Monitor Advertisement, LE Cancel Monitor Advertisement, LE Set
//! Advertisement Filter Enable, and Read Absolute RSSI.

use std::fmt::Write as FmtWrite;

use super::{VendorEvt, VendorOcf};
use crate::display::{COLOR_ERROR, COLOR_HCI_COMMAND, COLOR_HCI_COMMAND_UNKNOWN, COLOR_OFF};
use crate::{print_field, print_indent, print_text};
use bluez_shared::util::endian::{get_le16, get_le32, get_s8, get_u8};
use bluez_shared::util::uuid::{bt_uuid16_to_str, bt_uuid32_to_str, bt_uuidstr_to_str};

// ============================================================================
// Internal Command Table Entry
// ============================================================================

/// Dispatch table entry for MSFT subcommands. Maps a subcommand code to its
/// human-readable name and command/response handler functions with minimum
/// data size requirements.
struct CmdTableEntry {
    subcmd: u8,
    name: &'static str,
    cmd_func: fn(u16, &[u8]),
    cmd_size: usize,
    rsp_func: fn(u16, &[u8]),
    rsp_size: usize,
}

// ============================================================================
// No-op Handler Functions
// ============================================================================

/// Empty command handler for subcommands with no command parameters to decode.
fn null_cmd(_index: u16, _data: &[u8]) {}

/// Empty response handler for subcommands with no response fields to decode.
fn null_rsp(_index: u16, _data: &[u8]) {}

// ============================================================================
// Command / Response Decoders
// ============================================================================

/// Decode Read Supported Features response (subcmd 0x00).
///
/// Wire layout: status(u8) + subcmd(u8) + features(8 bytes) +
///              evt_prefix_len(u8) + evt_prefix(variable)
fn read_supported_features_rsp(_index: u16, data: &[u8]) {
    // Features at offset 2 (after status + subcmd), 8 bytes
    if data.len() >= 10 {
        crate::packet::print_features_msft(&data[2..10]);
    }

    if data.len() >= 11 {
        let evt_prefix_len = get_u8(&data[10..]) as usize;
        print_field!("Event prefix length: {}", evt_prefix_len);

        if evt_prefix_len > 0 && data.len() >= 11 + evt_prefix_len {
            crate::packet::hexdump(&data[11..11 + evt_prefix_len]);
            crate::packet::set_msft_evt_prefix(&data[11..11 + evt_prefix_len]);
        }
    }
}

/// Decode Monitor RSSI command (subcmd 0x01).
///
/// Wire layout: subcmd(u8) + handle(LE16) + rssi_threshold_high(i8) +
///              rssi_threshold_low(i8) + rssi_threshold_low_time_interval(u8) +
///              rssi_sampling_period(u8)
fn monitor_rssi_cmd(_index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }

    let handle = get_le16(&data[1..]);
    let rssi_high = get_s8(&data[3..]);
    let rssi_low = get_s8(&data[4..]);
    let interval = get_u8(&data[5..]);
    let sampling = get_u8(&data[6..]);

    print_field!("Handle: {}", handle);
    crate::packet::print_rssi("RSSI threshold high", rssi_high);
    crate::packet::print_rssi("RSSI threshold low", rssi_low);
    print_field!("RSSI threshold low time interval: {} sec (0x{:02x})", interval, interval);
    print_field!("RSSI sampling period: {} msec (0x{:02x})", u32::from(sampling) * 100, sampling);
}

/// Decode Cancel Monitor RSSI command (subcmd 0x02).
///
/// Wire layout: subcmd(u8) + handle(LE16)
fn cancel_monitor_rssi_cmd(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let handle = get_le16(&data[1..]);
    print_field!("Handle: {}", handle);
}

/// Decode LE Monitor Advertisement command (subcmd 0x03).
///
/// Wire layout: subcmd(u8) + rssi_threshold_high(i8) + rssi_threshold_low(i8) +
///              rssi_threshold_low_interval(u8) + rssi_sampling_period(u8) +
///              condition_type(u8) + condition_data(variable)
///
/// Condition types:
///   0x01 — Pattern: num_patterns(u8) + per pattern: length(u8) + ad_type(u8) +
///          start_byte(u8) + pattern(length bytes)
///   0x02 — UUID: uuid_type(u8) + uuid_value(2/4/16 bytes depending on type)
///   0x03 — IRK: 16 bytes of Identity Resolving Key
///   0x04 — Address: addr_type(u8) + bdaddr(6 bytes)
fn le_monitor_advertisement_cmd(_index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }

    let rssi_high = get_s8(&data[1..]);
    let rssi_low = get_s8(&data[2..]);
    let interval = get_u8(&data[3..]);
    let sampling = get_u8(&data[4..]);
    let condition_type = get_u8(&data[5..]);

    crate::packet::print_rssi("RSSI threshold high", rssi_high);
    crate::packet::print_rssi("RSSI threshold low", rssi_low);
    print_field!("RSSI threshold low time interval: {} sec (0x{:02x})", interval, interval);
    print_field!("RSSI sampling period: {} msec (0x{:02x})", u32::from(sampling) * 100, sampling);
    print_field!("Condition type: {}", condition_type);

    // Condition-specific data starts at offset 6
    let cond_data = &data[6..];

    match condition_type {
        // Pattern condition
        0x01 => {
            decode_pattern_condition(cond_data);
        }
        // UUID condition
        0x02 => {
            decode_uuid_condition(cond_data);
        }
        // IRK condition — 16 bytes
        0x03 => {
            decode_irk_condition(cond_data);
        }
        // Address condition — addr_type(u8) + bdaddr(6)
        0x04 => {
            decode_address_condition(cond_data);
        }
        // Unknown condition type
        _ => {
            crate::packet::hexdump(cond_data);
        }
    }
}

/// Decode a pattern-type condition (type 0x01) from LE Monitor Advertisement.
///
/// Wire layout: num_patterns(u8) + for each pattern: length(u8) + ad_type(u8) +
///              start_byte(u8) + pattern_data(length bytes)
fn decode_pattern_condition(cond_data: &[u8]) {
    if cond_data.is_empty() {
        return;
    }
    let num_patterns = get_u8(cond_data);
    print_field!("Number of patterns: {}", num_patterns);

    let mut offset: usize = 1; // past num_patterns byte
    for _ in 0..num_patterns {
        if offset >= cond_data.len() {
            break;
        }
        let length = get_u8(&cond_data[offset..]) as usize;
        if offset + 1 >= cond_data.len() {
            break;
        }
        let ad_type = get_u8(&cond_data[offset + 1..]);
        if offset + 2 >= cond_data.len() {
            break;
        }
        let start_byte = get_u8(&cond_data[offset + 2..]);

        print_field!("AD type: {}", ad_type);
        print_field!("Start byte: {}", start_byte);
        print_field!("Pattern:");

        let pat_start = offset + 3;
        let pat_end = pat_start + length;
        if pat_end <= cond_data.len() {
            crate::packet::hexdump(&cond_data[pat_start..pat_end]);
        }
        // Advance: 3 bytes header (length, ad_type, start_byte) + pattern data
        offset = pat_end;
    }
}

/// Decode a UUID-type condition (type 0x02) from LE Monitor Advertisement.
///
/// Wire layout: uuid_type(u8) + uuid_value(variable):
///   uuid_type 0x01 → UUID16 (2 bytes LE)
///   uuid_type 0x02 → UUID32 (4 bytes LE)
///   uuid_type 0x03 → UUID128 (16 bytes LE)
fn decode_uuid_condition(cond_data: &[u8]) {
    if cond_data.is_empty() {
        return;
    }
    let uuid_type = get_u8(cond_data);
    print_field!("UUID type: {}", uuid_type);

    let value = &cond_data[1..];

    match uuid_type {
        // UUID16
        0x01 => {
            if value.len() < 2 {
                return;
            }
            let val = get_le16(value);
            let uuid_str = format!("{:04x}", val);
            let name = bt_uuid16_to_str(val);
            print_field!("UUID: {} ({})", uuid_str, name);
        }
        // UUID32
        0x02 => {
            if value.len() < 4 {
                return;
            }
            let val = get_le32(value);
            let uuid_str = format!("{:08x}", val);
            let name = bt_uuid32_to_str(val);
            print_field!("UUID: {} ({})", uuid_str, name);
        }
        // UUID128 — 16 bytes in BlueZ LE wire format
        0x03 => {
            if value.len() < 16 {
                return;
            }
            let uuid_str = format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:08x}{:04x}",
                get_le32(&value[12..]),
                get_le16(&value[10..]),
                get_le16(&value[8..]),
                get_le16(&value[6..]),
                get_le32(&value[2..]),
                get_le16(value)
            );
            let name = bt_uuidstr_to_str(&uuid_str).unwrap_or("Unknown");
            print_field!("UUID: {} ({})", uuid_str, name);
        }
        // Unknown UUID type — hexdump raw data
        _ => {
            crate::packet::hexdump(cond_data);
        }
    }
}

/// Decode an IRK-type condition (type 0x03) from LE Monitor Advertisement.
///
/// Wire layout: 16 bytes of Identity Resolving Key. Formatted as 32-char hex
/// string with each pair of bytes printed in swapped order (matching the C
/// implementation which reads through a declared irk[8] struct using indices
/// up to 15, producing pair-swapped hex output).
fn decode_irk_condition(cond_data: &[u8]) {
    if cond_data.len() < 16 {
        crate::packet::hexdump(cond_data);
        return;
    }
    let mut irk_str = String::with_capacity(32);
    for i in 0..8 {
        // Each pair: the higher-indexed byte first, then the lower-indexed byte
        // Matches C: sprintf(str + (i*4), "%2.2x%2.2x", irk[i*2+1], irk[i*2])
        let _ = write!(irk_str, "{:02x}{:02x}", cond_data[i * 2 + 1], cond_data[i * 2]);
    }
    print_field!("IRK: {}", irk_str);
}

/// Decode an address-type condition (type 0x04) from LE Monitor Advertisement.
///
/// Wire layout: addr_type(u8) + bdaddr(6 bytes)
fn decode_address_condition(cond_data: &[u8]) {
    if cond_data.len() < 7 {
        crate::packet::hexdump(cond_data);
        return;
    }
    let addr_type = get_u8(cond_data);
    let addr_str = match addr_type {
        0x00 => "Public",
        0x01 => "Random",
        _ => "Reserved",
    };
    print_field!("Address type: {} (0x{:02x})", addr_str, addr_type);
    crate::packet::print_addr("", &cond_data[1..7], addr_type);
}

/// Decode LE Monitor Advertisement response (subcmd 0x03).
///
/// Wire layout: status(u8) + subcmd(u8) + monitor_handle(u8)
fn le_monitor_advertisement_rsp(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let monitor_handle = get_u8(&data[2..]);
    print_field!("Monitor handle: {}", monitor_handle);
}

/// Decode LE Cancel Monitor Advertisement command (subcmd 0x04).
///
/// Wire layout: subcmd(u8) + monitor_handle(u8)
fn le_cancel_monitor_adv_cmd(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let monitor_handle = get_u8(&data[1..]);
    print_field!("Monitor handle: {}", monitor_handle);
}

/// Decode LE Set Advertisement Filter Enable command (subcmd 0x05).
///
/// Wire layout: subcmd(u8) + enable(u8)
///   enable: 0x00 = "Current allow list", 0x01 = "All filter conditions"
fn set_adv_filter_enable_cmd(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let enable = get_u8(&data[1..]);
    let enable_str = match enable {
        0x00 => "Current allow list",
        0x01 => "All filter conditions",
        _ => "Reserved",
    };
    print_field!("Enable: {} (0x{:02x})", enable_str, enable);
}

// ============================================================================
// Subcommand Dispatch Table
// ============================================================================

/// MSFT subcommand dispatch table. Seven entries mapping subcommand codes
/// (0x00–0x06) to their names and decoder functions with minimum size
/// requirements. Matches the C `cmd_table[]` exactly.
static CMD_TABLE: [CmdTableEntry; 7] = [
    CmdTableEntry {
        subcmd: 0x00,
        name: "Read Supported Features",
        cmd_func: null_cmd,
        cmd_size: 0,
        rsp_func: read_supported_features_rsp,
        rsp_size: 12,
    },
    CmdTableEntry {
        subcmd: 0x01,
        name: "Monitor RSSI",
        cmd_func: monitor_rssi_cmd,
        cmd_size: 7,
        rsp_func: null_rsp,
        rsp_size: 0,
    },
    CmdTableEntry {
        subcmd: 0x02,
        name: "Cancel Monitor RSSI",
        cmd_func: cancel_monitor_rssi_cmd,
        cmd_size: 3,
        rsp_func: null_rsp,
        rsp_size: 0,
    },
    CmdTableEntry {
        subcmd: 0x03,
        name: "LE Monitor Advertisement",
        cmd_func: le_monitor_advertisement_cmd,
        cmd_size: 6,
        rsp_func: le_monitor_advertisement_rsp,
        rsp_size: 3,
    },
    CmdTableEntry {
        subcmd: 0x04,
        name: "LE Cancel Monitor Advertisement",
        cmd_func: le_cancel_monitor_adv_cmd,
        cmd_size: 2,
        rsp_func: null_rsp,
        rsp_size: 0,
    },
    CmdTableEntry {
        subcmd: 0x05,
        name: "LE Set Advertisement Filter Enable",
        cmd_func: set_adv_filter_enable_cmd,
        cmd_size: 2,
        rsp_func: null_rsp,
        rsp_size: 0,
    },
    CmdTableEntry {
        subcmd: 0x06,
        name: "Read Absolute RSSI",
        cmd_func: null_cmd,
        cmd_size: 0,
        rsp_func: null_rsp,
        rsp_size: 0,
    },
];

// ============================================================================
// MSFT Command / Response Dispatch
// ============================================================================

/// Top-level MSFT vendor command dispatcher. Reads the subcommand byte at
/// offset 0, looks it up in [`CMD_TABLE`], prints the subcommand name with
/// color formatting, validates minimum size, and calls the appropriate handler.
/// Full data (including the subcmd byte) is passed to the handler.
fn msft_cmd(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let subcmd = get_u8(data);

    // Look up subcommand in dispatch table
    let entry = CMD_TABLE.iter().find(|e| e.subcmd == subcmd);

    let (subcmd_color, subcmd_str) = match entry {
        Some(e) => (COLOR_HCI_COMMAND, e.name),
        None => (COLOR_HCI_COMMAND_UNKNOWN, "Unknown"),
    };

    print_indent!(
        6,
        subcmd_color,
        "",
        "MSFT sub-command: ",
        COLOR_OFF,
        "{} (0x{:02x})",
        subcmd_str,
        subcmd
    );

    let entry = match entry {
        Some(e) => e,
        None => {
            crate::packet::hexdump(data);
            return;
        }
    };

    if entry.cmd_size > 0 && data.len() < entry.cmd_size {
        print_text!(COLOR_ERROR, "invalid size ({} < {})", data.len(), entry.cmd_size);
        crate::packet::hexdump(data);
        return;
    }

    (entry.cmd_func)(_index, data);
}

/// Top-level MSFT vendor response dispatcher. Reads the status byte at
/// offset 0 (printing it via [`crate::packet::print_error`]), then reads the
/// subcommand byte at offset 1, looks it up in [`CMD_TABLE`], prints the
/// subcommand name, validates minimum size, and calls the response handler.
/// Full data (including status and subcmd bytes) is passed to the handler.
fn msft_rsp(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let status = get_u8(data);
    crate::packet::print_error("Status", status);

    if data.len() < 2 {
        crate::packet::hexdump(data);
        return;
    }

    let subcmd = get_u8(&data[1..]);

    // Look up subcommand in dispatch table
    let entry = CMD_TABLE.iter().find(|e| e.subcmd == subcmd);

    let (subcmd_color, subcmd_str) = match entry {
        Some(e) => (COLOR_HCI_COMMAND, e.name),
        None => (COLOR_HCI_COMMAND_UNKNOWN, "Unknown"),
    };

    print_indent!(
        6,
        subcmd_color,
        "",
        "MSFT sub-command: ",
        COLOR_OFF,
        "{} (0x{:02x})",
        subcmd_str,
        subcmd
    );

    let entry = match entry {
        Some(e) => e,
        None => {
            crate::packet::hexdump(data);
            return;
        }
    };

    if entry.rsp_size > 0 && data.len() < entry.rsp_size {
        print_text!(COLOR_ERROR, "invalid size ({} < {})", data.len(), entry.rsp_size);
        crate::packet::hexdump(data);
        return;
    }

    (entry.rsp_func)(_index, data);
}

// ============================================================================
// Vendor OCF Entry and Public API
// ============================================================================

/// Single MSFT vendor OCF descriptor. The MSFT extension uses OCF 0x000
/// ("Extension") with internal subcommand dispatch, unlike Intel and Broadcom
/// which have per-OCF table entries. Minimum command size is 1 (the subcmd
/// byte), minimum response size is 2 (status + subcmd).
static VENDOR_OCF_ENTRY: VendorOcf = VendorOcf {
    ocf: 0x000,
    name: "Extension",
    cmd_func: msft_cmd,
    cmd_size: 1,
    cmd_fixed: false,
    rsp_func: msft_rsp,
    rsp_size: 2,
    rsp_fixed: false,
};

/// Returns the single MSFT vendor OCF descriptor.
///
/// Unlike Intel and Broadcom which return per-OCF entries from tables, MSFT
/// uses a single OCF that internally dispatches to 7 subcommands.
pub fn msft_vendor_ocf() -> Option<&'static VendorOcf> {
    Some(&VENDOR_OCF_ENTRY)
}

// ============================================================================
// Vendor Event Entry and Public API
// ============================================================================

/// MSFT vendor event handler — hexdumps the entire event payload.
/// Detailed event decoding is deferred until the event prefix has been
/// registered via [`crate::packet::set_msft_evt_prefix`].
fn msft_evt(_index: u16, data: &[u8]) {
    crate::packet::hexdump(data);
}

/// Single MSFT vendor event descriptor. Event code 0x00 ("Extension"),
/// minimum size 1 byte, variable length.
static VENDOR_EVT_ENTRY: VendorEvt =
    VendorEvt { evt: 0x00, name: "Extension", evt_func: msft_evt, evt_size: 1, evt_fixed: false };

/// Returns the single MSFT vendor event descriptor.
pub fn msft_vendor_evt() -> Option<&'static VendorEvt> {
    Some(&VENDOR_EVT_ENTRY)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_ocf_returns_some() {
        let ocf = msft_vendor_ocf();
        assert!(ocf.is_some(), "msft_vendor_ocf must return Some");
    }

    #[test]
    fn test_vendor_ocf_fields() {
        let ocf = msft_vendor_ocf().unwrap();
        assert_eq!(ocf.ocf, 0x000);
        assert_eq!(ocf.name, "Extension");
        assert_eq!(ocf.cmd_size, 1);
        assert!(!ocf.cmd_fixed);
        assert_eq!(ocf.rsp_size, 2);
        assert!(!ocf.rsp_fixed);
    }

    #[test]
    fn test_vendor_evt_returns_some() {
        let evt = msft_vendor_evt();
        assert!(evt.is_some(), "msft_vendor_evt must return Some");
    }

    #[test]
    fn test_vendor_evt_fields() {
        let evt = msft_vendor_evt().unwrap();
        assert_eq!(evt.evt, 0x00);
        assert_eq!(evt.name, "Extension");
        assert_eq!(evt.evt_size, 1);
        assert!(!evt.evt_fixed);
    }

    #[test]
    fn test_vendor_ocf_stable_reference() {
        let ocf1 = msft_vendor_ocf().unwrap() as *const VendorOcf;
        let ocf2 = msft_vendor_ocf().unwrap() as *const VendorOcf;
        assert_eq!(ocf1, ocf2, "Should return same static reference");
    }

    #[test]
    fn test_vendor_evt_stable_reference() {
        let evt1 = msft_vendor_evt().unwrap() as *const VendorEvt;
        let evt2 = msft_vendor_evt().unwrap() as *const VendorEvt;
        assert_eq!(evt1, evt2, "Should return same static reference");
    }

    #[test]
    fn test_cmd_handler_empty_data() {
        // Empty data should not panic
        msft_cmd(0, &[]);
    }

    #[test]
    fn test_cmd_handler_valid_subcmd_read_features() {
        // Subcmd 0x00 "Read Supported Features" — null_cmd does nothing
        msft_cmd(0, &[0x00]);
    }

    #[test]
    fn test_cmd_handler_unknown_subcmd() {
        // Unknown subcmd 0xFF — hexdumps data, does not panic
        msft_cmd(0, &[0xFF, 0x01, 0x02]);
    }

    #[test]
    fn test_rsp_handler_empty_data() {
        msft_rsp(0, &[]);
    }

    #[test]
    fn test_rsp_handler_valid_subcmd() {
        // Status=0x00 Success, subcmd=0x00 Read Supported Features
        // 12 bytes minimum: status(1)+subcmd(1)+features(8)+prefix_len(1)+prefix(1)
        let mut data = vec![0x00u8, 0x00];
        data.extend_from_slice(&[0x00; 8]); // features
        data.push(0x01); // evt_prefix_len
        data.push(0xAB); // evt_prefix byte
        msft_rsp(0, &data);
    }

    #[test]
    fn test_rsp_handler_unknown_subcmd() {
        msft_rsp(0, &[0x00, 0xFF, 0x01, 0x02]);
    }

    #[test]
    fn test_evt_handler() {
        msft_evt(0, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_cmd_monitor_rssi() {
        // subcmd(1)+handle(2)+rssi_h(1)+rssi_l(1)+interval(1)+sampling(1)
        let data: [u8; 7] = [0x01, 0x01, 0x00, 0xE2, 0xCE, 0x05, 0x0A];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_cancel_monitor_rssi() {
        let data: [u8; 3] = [0x02, 0x01, 0x00];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_monitor_adv_pattern() {
        let data = vec![
            0x03, 0xE2, 0xCE, 0x05, 0x0A, // subcmd + rssi fields
            0x01, // condition_type = Pattern
            0x01, // num_patterns = 1
            0x02, // length = 2
            0x09, // ad_type
            0x00, // start_byte
            0x41, 0x42, // pattern
        ];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_monitor_adv_uuid16() {
        let data = vec![0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x02, 0x01, 0x0D, 0x18];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_monitor_adv_uuid32() {
        let data = vec![0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x02, 0x02, 0x0D, 0x18, 0x00, 0x00];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_monitor_adv_uuid128() {
        let mut data = vec![0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x02, 0x03];
        data.extend_from_slice(&[0x00; 16]);
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_monitor_adv_irk() {
        let mut data = vec![0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x03];
        data.extend_from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ]);
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_monitor_adv_address() {
        let data =
            vec![0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_monitor_adv_unknown_condition() {
        let data = vec![
            0x03, 0xE2, 0xCE, 0x05, 0x0A, 0xFF, 0xAA, 0xBB, // unknown condition type
        ];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_cancel_monitor_adv() {
        let data: [u8; 2] = [0x04, 0x05];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_cmd_le_set_adv_filter_enable() {
        msft_cmd(0, &[0x05, 0x00]); // Current allow list
        msft_cmd(0, &[0x05, 0x01]); // All filter conditions
        msft_cmd(0, &[0x05, 0xFF]); // Reserved
    }

    #[test]
    fn test_cmd_read_abs_rssi() {
        msft_cmd(0, &[0x06]);
    }

    #[test]
    fn test_rsp_le_monitor_adv() {
        let data: [u8; 3] = [0x00, 0x03, 0x07];
        msft_rsp(0, &data);
    }

    #[test]
    fn test_cmd_size_too_small() {
        // Subcmd 0x01 Monitor RSSI requires 7 bytes, send only 3
        msft_cmd(0, &[0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_rsp_size_too_small() {
        // Subcmd 0x00 rsp requires 12 bytes, send only 5
        let data = [0x00, 0x00, 0x00, 0x00, 0x00];
        msft_rsp(0, &data);
    }

    #[test]
    fn test_cmd_table_has_seven_entries() {
        assert_eq!(CMD_TABLE.len(), 7);
    }

    #[test]
    fn test_cmd_table_subcmd_ordering() {
        for (i, entry) in CMD_TABLE.iter().enumerate() {
            assert_eq!(entry.subcmd, i as u8, "CMD_TABLE[{}] should have subcmd 0x{:02x}", i, i);
        }
    }

    #[test]
    fn test_cmd_table_names() {
        let expected = [
            "Read Supported Features",
            "Monitor RSSI",
            "Cancel Monitor RSSI",
            "LE Monitor Advertisement",
            "LE Cancel Monitor Advertisement",
            "LE Set Advertisement Filter Enable",
            "Read Absolute RSSI",
        ];
        for (entry, name) in CMD_TABLE.iter().zip(expected.iter()) {
            assert_eq!(entry.name, *name);
        }
    }

    #[test]
    fn test_irk_formatting() {
        // Test the IRK condition with known bytes
        let mut data = vec![0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x03];
        // 16 IRK bytes: pairs will be swapped
        data.extend_from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        // This should print IRK: 0100030205040706090a0b0c0d0e0f0e
        // Actually: pairs (0,1),(2,3),(4,5),(6,7),(8,9),(a,b),(c,d),(e,f)
        // swap: 01 00, 03 02, 05 04, 07 06, 09 08, 0b 0a, 0d 0c, 0f 0e
        msft_cmd(0, &data);
    }

    #[test]
    fn test_address_condition_random() {
        let data = vec![
            0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x04, 0x01, // addr_type = Random
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_address_condition_reserved() {
        let data = vec![
            0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x04, 0x02, // addr_type = Reserved
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_uuid_unknown_type() {
        let data = vec![
            0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x02, 0xFF, // unknown uuid type
            0x01, 0x02, 0x03,
        ];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_multiple_patterns() {
        let data = vec![
            0x03, 0xE2, 0xCE, 0x05, 0x0A, 0x01, // condition = Pattern
            0x02, // num_patterns = 2
            // pattern 1: length=1, ad_type=0x09, start=0, data=0x41
            0x01, 0x09, 0x00, 0x41,
            // pattern 2: length=2, ad_type=0xFF, start=1, data=0xBB 0xCC
            0x02, 0xFF, 0x01, 0xBB, 0xCC,
        ];
        msft_cmd(0, &data);
    }

    #[test]
    fn test_rsp_single_byte_data() {
        // Only status byte, no subcmd — should print error and hexdump
        msft_rsp(0, &[0x05]);
    }
}
