// SPDX-License-Identifier: GPL-2.0-or-later
//
// Microsoft vendor extension decoders replacing monitor/msft.c

use crate::display;

// MSFT sub-opcodes
pub const MSFT_OP_READ_SUPPORTED_FEATURES: u8 = 0x00;
pub const MSFT_OP_MONITOR_RSSI: u8 = 0x01;
pub const MSFT_OP_CANCEL_MONITOR_RSSI: u8 = 0x02;
pub const MSFT_OP_LE_MONITOR_ADV: u8 = 0x03;
pub const MSFT_OP_CANCEL_LE_MONITOR_ADV: u8 = 0x04;
pub const MSFT_OP_LE_SET_ADV_FILTER_ENABLE: u8 = 0x05;
pub const MSFT_OP_READ_ABS_RSSI: u8 = 0x06;

/// Decode an MSFT vendor command.
pub fn decode_msft_cmd(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let sub_opcode = data[0];
    let name = match sub_opcode {
        MSFT_OP_READ_SUPPORTED_FEATURES => "Read Supported Features",
        MSFT_OP_MONITOR_RSSI => "Monitor RSSI",
        MSFT_OP_CANCEL_MONITOR_RSSI => "Cancel Monitor RSSI",
        MSFT_OP_LE_MONITOR_ADV => "LE Monitor Advertisement",
        MSFT_OP_CANCEL_LE_MONITOR_ADV => "Cancel LE Monitor Advertisement",
        MSFT_OP_LE_SET_ADV_FILTER_ENABLE => "LE Set Advertisement Filter Enable",
        MSFT_OP_READ_ABS_RSSI => "Read Absolute RSSI",
        _ => "Unknown",
    };
    display::print_field(&format!("MSFT Sub-opcode: {} (0x{:02x})", name, sub_opcode));
}

/// Decode an MSFT vendor event.
pub fn decode_msft_evt(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    decode_msft_cmd(data); // Same sub-opcode structure
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msft_decode() {
        // Just verify no panic
        decode_msft_cmd(&[MSFT_OP_READ_SUPPORTED_FEATURES]);
        decode_msft_cmd(&[]);
        decode_msft_evt(&[MSFT_OP_LE_MONITOR_ADV]);
    }
}
