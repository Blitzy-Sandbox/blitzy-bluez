// SPDX-License-Identifier: GPL-2.0-or-later
//
// SDP (Service Discovery Protocol) decoder
//
// Decodes SDP PDUs carried over L2CAP PSM 0x0001 (dynamic CIDs).
// Handles all SDP PDU types including data element sequence parsing.

use crate::display;

// SDP PDU IDs
const SDP_ERROR_RSP: u8 = 0x01;
const SDP_SERVICE_SEARCH_REQ: u8 = 0x02;
const SDP_SERVICE_SEARCH_RSP: u8 = 0x03;
const SDP_SERVICE_ATTR_REQ: u8 = 0x04;
const SDP_SERVICE_ATTR_RSP: u8 = 0x05;
const SDP_SERVICE_SEARCH_ATTR_REQ: u8 = 0x06;
const SDP_SERVICE_SEARCH_ATTR_RSP: u8 = 0x07;

fn be_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn pdu_id_to_str(pdu_id: u8) -> &'static str {
    match pdu_id {
        SDP_ERROR_RSP => "Error Response",
        SDP_SERVICE_SEARCH_REQ => "Service Search Request",
        SDP_SERVICE_SEARCH_RSP => "Service Search Response",
        SDP_SERVICE_ATTR_REQ => "Service Attribute Request",
        SDP_SERVICE_ATTR_RSP => "Service Attribute Response",
        SDP_SERVICE_SEARCH_ATTR_REQ => "Service Search Attribute Request",
        SDP_SERVICE_SEARCH_ATTR_RSP => "Service Search Attribute Response",
        _ => "Unknown",
    }
}

fn error_code_to_str(code: u16) -> &'static str {
    match code {
        0x0001 => "Invalid/unsupported SDP version",
        0x0002 => "Invalid Service Record Handle",
        0x0003 => "Invalid request syntax",
        0x0004 => "Invalid PDU Size",
        0x0005 => "Invalid Continuation State",
        0x0006 => "Insufficient Resources to satisfy Request",
        _ => "Unknown",
    }
}

// Data Element type descriptors
fn data_element_type_str(type_id: u8) -> &'static str {
    match type_id {
        0 => "Nil",
        1 => "Unsigned Integer",
        2 => "Signed Integer",
        3 => "UUID",
        4 => "Text String",
        5 => "Boolean",
        6 => "Data Element Sequence",
        7 => "Data Element Alternative",
        8 => "URL",
        _ => "Unknown",
    }
}

/// Decode a data element and return the number of bytes consumed.
/// `indent` controls nesting depth for display.
fn decode_data_element(data: &[u8], indent: usize) -> usize {
    if data.is_empty() {
        return 0;
    }

    let header = data[0];
    let type_id = (header >> 3) & 0x1f;
    let size_desc = header & 0x07;

    let pad = "  ".repeat(indent);

    // Determine the size of the data portion
    let (data_size, header_size) = match size_desc {
        0 => {
            if type_id == 0 { (0usize, 1usize) } else { (1, 1) }
        }
        1 => (2, 1),
        2 => (4, 1),
        3 => (8, 1),
        4 => (16, 1),
        5 => {
            if data.len() < 2 { return data.len(); }
            (data[1] as usize, 2)
        }
        6 => {
            if data.len() < 3 { return data.len(); }
            (be_u16(data, 1) as usize, 3)
        }
        7 => {
            if data.len() < 5 { return data.len(); }
            (be_u32(data, 1) as usize, 5)
        }
        _ => return data.len(),
    };

    let total = header_size + data_size;
    if data.len() < total {
        display::print_field(&format!("{}Data Element: truncated (need {} have {})", pad, total, data.len()));
        return data.len();
    }

    let value_data = &data[header_size..total];

    match type_id {
        0 => {
            display::print_field(&format!("{}Nil", pad));
        }
        1 => {
            // Unsigned Integer
            let val = match data_size {
                1 => format!("0x{:02x}", value_data[0]),
                2 => format!("0x{:04x}", be_u16(value_data, 0)),
                4 => format!("0x{:08x}", be_u32(value_data, 0)),
                _ => {
                    let hex: String = value_data.iter().map(|b| format!("{:02x}", b)).collect();
                    format!("0x{}", hex)
                }
            };
            display::print_field(&format!("{}Unsigned Integer: {}", pad, val));
        }
        2 => {
            // Signed Integer
            let val = match data_size {
                1 => format!("{}", value_data[0] as i8),
                2 => format!("{}", i16::from_be_bytes([value_data[0], value_data[1]])),
                4 => format!("{}", i32::from_be_bytes([value_data[0], value_data[1], value_data[2], value_data[3]])),
                _ => {
                    let hex: String = value_data.iter().map(|b| format!("{:02x}", b)).collect();
                    hex
                }
            };
            display::print_field(&format!("{}Signed Integer: {}", pad, val));
        }
        3 => {
            // UUID
            match data_size {
                2 => {
                    let uuid = be_u16(value_data, 0);
                    display::print_field(&format!("{}UUID: 0x{:04x}", pad, uuid));
                }
                4 => {
                    let uuid = be_u32(value_data, 0);
                    display::print_field(&format!("{}UUID: 0x{:08x}", pad, uuid));
                }
                16 => {
                    display::print_field(&format!(
                        "{}UUID: {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        pad,
                        value_data[0], value_data[1], value_data[2], value_data[3],
                        value_data[4], value_data[5],
                        value_data[6], value_data[7],
                        value_data[8], value_data[9],
                        value_data[10], value_data[11], value_data[12], value_data[13], value_data[14], value_data[15],
                    ));
                }
                _ => {
                    display::print_field(&format!("{}UUID: (invalid size {})", pad, data_size));
                }
            }
        }
        4 => {
            // Text String
            let text = String::from_utf8_lossy(value_data);
            display::print_field(&format!("{}Text: \"{}\"", pad, text));
        }
        5 => {
            // Boolean
            if !value_data.is_empty() {
                display::print_field(&format!("{}Boolean: {}", pad, value_data[0] != 0));
            }
        }
        6 | 7 => {
            // Data Element Sequence / Alternative
            let type_name = data_element_type_str(type_id);
            display::print_field(&format!("{}{} (len {})", pad, type_name, data_size));
            let mut offset = 0;
            while offset < value_data.len() {
                let consumed = decode_data_element(&value_data[offset..], indent + 1);
                if consumed == 0 {
                    break;
                }
                offset += consumed;
            }
        }
        8 => {
            // URL
            let url = String::from_utf8_lossy(value_data);
            display::print_field(&format!("{}URL: \"{}\"", pad, url));
        }
        _ => {
            display::print_field(&format!("{}{} (type {}, size {})", pad, data_element_type_str(type_id), type_id, data_size));
            if !value_data.is_empty() {
                display::print_hexdump(value_data);
            }
        }
    }

    total
}

/// Decode an SDP PDU.
pub fn decode_sdp(data: &[u8]) {
    if data.len() < 5 {
        if !data.is_empty() {
            display::print_field("SDP: packet too short");
            display::print_hexdump(data);
        }
        return;
    }

    let pdu_id = data[0];
    let transaction_id = be_u16(data, 1);
    let param_len = be_u16(data, 3) as usize;
    let name = pdu_id_to_str(pdu_id);

    display::print_field(&format!("SDP: {} (0x{:02x}) tid 0x{:04x} len {}", name, pdu_id, transaction_id, param_len));

    if data.len() < 5 + param_len {
        display::print_field("SDP: parameter data truncated");
        return;
    }

    let params = &data[5..5 + param_len];

    match pdu_id {
        SDP_ERROR_RSP => {
            if params.len() >= 2 {
                let error_code = be_u16(params, 0);
                display::print_field(&format!("  Error code: {} (0x{:04x})", error_code_to_str(error_code), error_code));
                if params.len() > 2 {
                    display::print_field("  Error info:");
                    display::print_hexdump(&params[2..]);
                }
            }
        }
        SDP_SERVICE_SEARCH_REQ => {
            // ServiceSearchPattern (data element sequence) + MaxServiceRecordCount + ContinuationState
            let consumed = decode_data_element(params, 1);
            let rest = &params[consumed..];
            if rest.len() >= 2 {
                let max_count = be_u16(rest, 0);
                display::print_field(&format!("  Max service record count: {}", max_count));
                if rest.len() > 2 {
                    decode_continuation_state(&rest[2..]);
                }
            }
        }
        SDP_SERVICE_SEARCH_RSP => {
            if params.len() >= 4 {
                let total_count = be_u16(params, 0);
                let current_count = be_u16(params, 2);
                display::print_field(&format!("  Total service record count: {}", total_count));
                display::print_field(&format!("  Current service record count: {}", current_count));
                let mut offset = 4;
                for i in 0..current_count as usize {
                    if offset + 4 <= params.len() {
                        let handle = be_u32(params, offset);
                        display::print_field(&format!("  Service record handle[{}]: 0x{:08x}", i, handle));
                        offset += 4;
                    }
                }
                if offset < params.len() {
                    decode_continuation_state(&params[offset..]);
                }
            }
        }
        SDP_SERVICE_ATTR_REQ => {
            if params.len() >= 6 {
                let handle = be_u32(params, 0);
                let max_bytes = be_u16(params, 4);
                display::print_field(&format!("  Service record handle: 0x{:08x}", handle));
                display::print_field(&format!("  Max attribute byte count: {}", max_bytes));
                if params.len() > 6 {
                    display::print_field("  Attribute ID list:");
                    let consumed = decode_data_element(&params[6..], 2);
                    let rest_offset = 6 + consumed;
                    if rest_offset < params.len() {
                        decode_continuation_state(&params[rest_offset..]);
                    }
                }
            }
        }
        SDP_SERVICE_ATTR_RSP => {
            if params.len() >= 2 {
                let byte_count = be_u16(params, 0);
                display::print_field(&format!("  Attribute list byte count: {}", byte_count));
                if params.len() > 2 {
                    let attr_end = (2 + byte_count as usize).min(params.len());
                    display::print_field("  Attribute list:");
                    let attr_data = &params[2..attr_end];
                    let mut offset = 0;
                    while offset < attr_data.len() {
                        let consumed = decode_data_element(&attr_data[offset..], 2);
                        if consumed == 0 {
                            break;
                        }
                        offset += consumed;
                    }
                    if attr_end < params.len() {
                        decode_continuation_state(&params[attr_end..]);
                    }
                }
            }
        }
        SDP_SERVICE_SEARCH_ATTR_REQ => {
            // ServiceSearchPattern + MaxAttributeByteCount + AttributeIDList + ContinuationState
            let consumed = decode_data_element(params, 1);
            let rest = &params[consumed..];
            if rest.len() >= 2 {
                let max_bytes = be_u16(rest, 0);
                display::print_field(&format!("  Max attribute byte count: {}", max_bytes));
                if rest.len() > 2 {
                    display::print_field("  Attribute ID list:");
                    let consumed2 = decode_data_element(&rest[2..], 2);
                    let rest2_offset = 2 + consumed2;
                    if rest2_offset < rest.len() {
                        decode_continuation_state(&rest[rest2_offset..]);
                    }
                }
            }
        }
        SDP_SERVICE_SEARCH_ATTR_RSP => {
            if params.len() >= 2 {
                let byte_count = be_u16(params, 0);
                display::print_field(&format!("  Attribute list byte count: {}", byte_count));
                if params.len() > 2 {
                    let attr_end = (2 + byte_count as usize).min(params.len());
                    display::print_field("  Attribute list:");
                    let attr_data = &params[2..attr_end];
                    let mut offset = 0;
                    while offset < attr_data.len() {
                        let consumed = decode_data_element(&attr_data[offset..], 2);
                        if consumed == 0 {
                            break;
                        }
                        offset += consumed;
                    }
                    if attr_end < params.len() {
                        decode_continuation_state(&params[attr_end..]);
                    }
                }
            }
        }
        _ => {
            if !params.is_empty() {
                display::print_hexdump(params);
            }
        }
    }
}

fn decode_continuation_state(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let cont_len = data[0] as usize;
    display::print_field(&format!("  Continuation state length: {}", cont_len));
    if cont_len > 0 && data.len() > 1 {
        let end = (1 + cont_len).min(data.len());
        display::print_hex_field("  Continuation state", &data[1..end]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdu_id_to_str() {
        assert_eq!(pdu_id_to_str(SDP_ERROR_RSP), "Error Response");
        assert_eq!(pdu_id_to_str(SDP_SERVICE_SEARCH_REQ), "Service Search Request");
        assert_eq!(pdu_id_to_str(SDP_SERVICE_SEARCH_ATTR_RSP), "Service Search Attribute Response");
        assert_eq!(pdu_id_to_str(0xFF), "Unknown");
    }

    #[test]
    fn test_decode_sdp_error_rsp() {
        // PDU=0x01, TID=0x0001, Len=2, ErrorCode=0x0002 (Invalid Service Record Handle)
        let data = [0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02];
        decode_sdp(&data);
    }

    #[test]
    fn test_decode_sdp_service_search_req() {
        // Service Search Request with UUID 0x1101 (Serial Port)
        // PDU=0x02, TID=0x0001, Len=8
        // DataElementSeq(3 bytes): UUID-16 = 0x1101
        // MaxServiceRecordCount = 10
        // ContinuationState = 0 (no continuation)
        let data = [
            0x02, // PDU ID
            0x00, 0x01, // Transaction ID
            0x00, 0x08, // Param length = 8
            // Data element sequence: type=6(seq), size_desc=5(next byte = length)
            0x35, 0x03, // Sequence, length 3
            0x19, 0x11, 0x01, // UUID-16: 0x1101
            0x00, 0x0A, // Max service record count = 10
            0x00, // Continuation state length = 0
        ];
        decode_sdp(&data);
    }

    #[test]
    fn test_decode_sdp_service_search_rsp() {
        // Service Search Response with 1 handle
        let data = [
            0x03, // PDU ID
            0x00, 0x01, // Transaction ID
            0x00, 0x09, // Param length = 9
            0x00, 0x01, // Total count = 1
            0x00, 0x01, // Current count = 1
            0x00, 0x01, 0x00, 0x00, // Handle = 0x00010000
            0x00, // Continuation state length = 0
        ];
        decode_sdp(&data);
    }

    #[test]
    fn test_decode_data_element_uuid16() {
        // UUID-16: type=3, size_desc=1(2 bytes) => header = (3<<3)|1 = 0x19
        let data = [0x19, 0x11, 0x01]; // UUID 0x1101
        let consumed = decode_data_element(&data, 0);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_decode_data_element_uint32() {
        // Unsigned Integer, 4 bytes: type=1, size_desc=2 => header = (1<<3)|2 = 0x0A
        let data = [0x0A, 0x00, 0x01, 0x00, 0x00];
        let consumed = decode_data_element(&data, 0);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_decode_data_element_text() {
        // Text String, length in next byte: type=4, size_desc=5 => header = (4<<3)|5 = 0x25
        let data = [0x25, 0x05, b'H', b'e', b'l', b'l', b'o'];
        let consumed = decode_data_element(&data, 0);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_decode_data_element_sequence() {
        // Sequence containing a UUID-16
        // Sequence: type=6, size_desc=5 => header = (6<<3)|5 = 0x35
        let data = [0x35, 0x03, 0x19, 0x11, 0x01];
        let consumed = decode_data_element(&data, 0);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_decode_data_element_bool() {
        // Boolean: type=5, size_desc=0(1 byte) => header = (5<<3)|0 = 0x28
        let data = [0x28, 0x01];
        let consumed = decode_data_element(&data, 0);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_data_element_nil() {
        // Nil: type=0, size_desc=0 => header = 0x00
        let data = [0x00];
        let consumed = decode_data_element(&data, 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_sdp_empty() {
        decode_sdp(&[]);
        decode_sdp(&[0x01]); // too short
    }

    #[test]
    fn test_decode_sdp_service_search_attr_req() {
        // Simplified Service Search Attribute Request
        let data = [
            0x06, // PDU ID
            0x00, 0x02, // Transaction ID
            0x00, 0x0F, // Param length
            // Service search pattern: seq(UUID 0x0100)
            0x35, 0x03, 0x19, 0x01, 0x00,
            // Max attribute byte count
            0x04, 0x00,
            // Attribute ID list: seq(range 0x0000-0xFFFF)
            0x35, 0x05,
            0x0A, 0x00, 0x00, 0xFF, 0xFF,
            // Continuation state
            0x00,
        ];
        decode_sdp(&data);
    }

    #[test]
    fn test_error_code_to_str() {
        assert_eq!(error_code_to_str(0x0001), "Invalid/unsupported SDP version");
        assert_eq!(error_code_to_str(0x0006), "Insufficient Resources to satisfy Request");
        assert_eq!(error_code_to_str(0xFFFF), "Unknown");
    }
}
