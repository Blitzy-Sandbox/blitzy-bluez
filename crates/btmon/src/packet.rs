//! Packet decoding and display utilities for btmon.
//!
//! Stub — full implementation will be provided by the assigned agent.
//! Provides the functions called by vendor decoders and protocol dissectors
//! for formatted output of HCI packet data.

use crate::print_field;

/// Hexdump raw byte data to the terminal in standard btmon format.
pub fn hexdump(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    // Stub: print hex bytes in 16-byte rows with ASCII sidebar
    let mut offset = 0usize;
    while offset < data.len() {
        let end = std::cmp::min(offset + 16, data.len());
        let chunk = &data[offset..end];
        print!("        ");
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                print!(" ");
            }
            print!(" {:02x}", byte);
        }
        // Pad remaining
        for i in chunk.len()..16 {
            if i == 8 {
                print!(" ");
            }
            print!("   ");
        }
        print!("  ");
        for byte in chunk {
            let ch = if (0x20..=0x7e).contains(byte) { *byte as char } else { '.' };
            print!("{}", ch);
        }
        println!();
        offset += 16;
    }
}

/// Print a formatted HCI error/status field.
///
/// Displays the label, status code in hex, and human-readable status name.
pub fn print_error(label: &str, error: u8) {
    let status_str = match error {
        0x00 => "Success",
        0x01 => "Unknown HCI Command",
        0x02 => "Unknown Connection Identifier",
        0x03 => "Hardware Failure",
        0x04 => "Page Timeout",
        0x05 => "Authentication Failure",
        0x06 => "PIN or Key Missing",
        0x07 => "Memory Capacity Exceeded",
        0x08 => "Connection Timeout",
        _ => "Unknown",
    };
    print_field!("{}: {} (0x{:02x})", label, status_str, error);
}

/// Print a formatted Bluetooth address.
///
/// Displays the label (if non-empty) and the BD_ADDR in standard
/// XX:XX:XX:XX:XX:XX format, along with the address type.
pub fn print_addr(label: &str, data: &[u8], addr_type: u8) {
    if data.len() < 6 {
        return;
    }
    let addr_str = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[5], data[4], data[3], data[2], data[1], data[0]
    );
    let type_str = match addr_type {
        0x00 => "Public",
        0x01 => "Random",
        _ => "Reserved",
    };
    if label.is_empty() {
        print_field!("Address: {} ({})", addr_str, type_str);
    } else {
        print_field!("{}: {} ({})", label, addr_str, type_str);
    }
}

/// Print a formatted RSSI value with label.
pub fn print_rssi(label: &str, rssi: i8) {
    print_field!("{}: {} dBm", label, rssi);
}

/// Print MSFT vendor-specific feature flags.
///
/// Decodes and displays the 8-byte MSFT features bitmask.
pub fn print_features_msft(features: &[u8]) {
    if features.len() < 8 {
        return;
    }
    // Stub: hexdump the features for now
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
}

/// Store the MSFT vendor event prefix for subsequent event routing.
///
/// After the MSFT Read Supported Features response is parsed, this function
/// is called with the event prefix bytes. The prefix is used to identify
/// MSFT vendor events in subsequent HCI event packets.
pub fn set_msft_evt_prefix(_prefix: &[u8]) {
    // Stub: store prefix for vendor event routing
    // Full implementation will save to a global or per-index state
}
