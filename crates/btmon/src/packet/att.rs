// SPDX-License-Identifier: GPL-2.0-or-later
//
// ATT protocol decoder replacing monitor/att.c (5,446 LOC)
//
// Decodes Attribute Protocol (ATT) PDUs carried over L2CAP CID 0x0004.
// Each opcode is decoded with its parameters displayed in human-readable form.

use crate::display;

// ATT opcodes
const ATT_OP_ERROR_RSP: u8 = 0x01;
const ATT_OP_MTU_REQ: u8 = 0x02;
const ATT_OP_MTU_RSP: u8 = 0x03;
const ATT_OP_FIND_INFO_REQ: u8 = 0x04;
const ATT_OP_FIND_INFO_RSP: u8 = 0x05;
const ATT_OP_FIND_BY_TYPE_REQ: u8 = 0x06;
const ATT_OP_FIND_BY_TYPE_RSP: u8 = 0x07;
const ATT_OP_READ_BY_TYPE_REQ: u8 = 0x08;
const ATT_OP_READ_BY_TYPE_RSP: u8 = 0x09;
const ATT_OP_READ_REQ: u8 = 0x0a;
const ATT_OP_READ_RSP: u8 = 0x0b;
const ATT_OP_READ_BLOB_REQ: u8 = 0x0c;
const ATT_OP_READ_BLOB_RSP: u8 = 0x0d;
const ATT_OP_READ_MULTI_REQ: u8 = 0x0e;
const ATT_OP_READ_MULTI_RSP: u8 = 0x0f;
const ATT_OP_READ_BY_GRP_TYPE_REQ: u8 = 0x10;
const ATT_OP_READ_BY_GRP_TYPE_RSP: u8 = 0x11;
const ATT_OP_WRITE_REQ: u8 = 0x12;
const ATT_OP_WRITE_RSP: u8 = 0x13;
const ATT_OP_PREP_WRITE_REQ: u8 = 0x16;
const ATT_OP_PREP_WRITE_RSP: u8 = 0x17;
const ATT_OP_EXEC_WRITE_REQ: u8 = 0x18;
const ATT_OP_EXEC_WRITE_RSP: u8 = 0x19;
const ATT_OP_HANDLE_NOTIFY: u8 = 0x1b;
const ATT_OP_HANDLE_IND: u8 = 0x1d;
const ATT_OP_HANDLE_CONF: u8 = 0x1e;
const ATT_OP_READ_MULTI_VAR_REQ: u8 = 0x20;
const ATT_OP_READ_MULTI_VAR_RSP: u8 = 0x21;
const ATT_OP_MULTI_NOTIFY: u8 = 0x23;
const ATT_OP_WRITE_CMD: u8 = 0x52;
const ATT_OP_SIGNED_WRITE_CMD: u8 = 0xd2;

fn att_opcode_to_str(opcode: u8) -> &'static str {
    match opcode {
        ATT_OP_ERROR_RSP => "Error Response",
        ATT_OP_MTU_REQ => "Exchange MTU Request",
        ATT_OP_MTU_RSP => "Exchange MTU Response",
        ATT_OP_FIND_INFO_REQ => "Find Information Request",
        ATT_OP_FIND_INFO_RSP => "Find Information Response",
        ATT_OP_FIND_BY_TYPE_REQ => "Find By Type Value Request",
        ATT_OP_FIND_BY_TYPE_RSP => "Find By Type Value Response",
        ATT_OP_READ_BY_TYPE_REQ => "Read By Type Request",
        ATT_OP_READ_BY_TYPE_RSP => "Read By Type Response",
        ATT_OP_READ_REQ => "Read Request",
        ATT_OP_READ_RSP => "Read Response",
        ATT_OP_READ_BLOB_REQ => "Read Blob Request",
        ATT_OP_READ_BLOB_RSP => "Read Blob Response",
        ATT_OP_READ_MULTI_REQ => "Read Multiple Request",
        ATT_OP_READ_MULTI_RSP => "Read Multiple Response",
        ATT_OP_READ_BY_GRP_TYPE_REQ => "Read By Group Type Request",
        ATT_OP_READ_BY_GRP_TYPE_RSP => "Read By Group Type Response",
        ATT_OP_WRITE_REQ => "Write Request",
        ATT_OP_WRITE_RSP => "Write Response",
        ATT_OP_PREP_WRITE_REQ => "Prepare Write Request",
        ATT_OP_PREP_WRITE_RSP => "Prepare Write Response",
        ATT_OP_EXEC_WRITE_REQ => "Execute Write Request",
        ATT_OP_EXEC_WRITE_RSP => "Execute Write Response",
        ATT_OP_HANDLE_NOTIFY => "Handle Value Notification",
        ATT_OP_HANDLE_IND => "Handle Value Indication",
        ATT_OP_HANDLE_CONF => "Handle Value Confirmation",
        ATT_OP_READ_MULTI_VAR_REQ => "Read Multiple Variable Length Request",
        ATT_OP_READ_MULTI_VAR_RSP => "Read Multiple Variable Length Response",
        ATT_OP_MULTI_NOTIFY => "Multiple Handle Value Notification",
        ATT_OP_WRITE_CMD => "Write Command",
        ATT_OP_SIGNED_WRITE_CMD => "Signed Write Command",
        _ => "Unknown",
    }
}

fn error_to_str(error: u8) -> &'static str {
    match error {
        0x01 => "Invalid Handle",
        0x02 => "Read Not Permitted",
        0x03 => "Write Not Permitted",
        0x04 => "Invalid PDU",
        0x05 => "Insufficient Authentication",
        0x06 => "Request Not Supported",
        0x07 => "Invalid Offset",
        0x08 => "Insufficient Authorization",
        0x09 => "Prepare Queue Full",
        0x0a => "Attribute Not Found",
        0x0b => "Attribute Not Long",
        0x0c => "Insufficient Encryption Key Size",
        0x0d => "Invalid Attribute Value Length",
        0x0e => "Unlikely Error",
        0x0f => "Insufficient Encryption",
        0x10 => "Unsupported Group Type",
        0x11 => "Insufficient Resources",
        0x12 => "Value Not Allowed",
        _ => "Unknown",
    }
}

fn print_uuid(label: &str, data: &[u8]) {
    match data.len() {
        2 => {
            let uuid = u16::from_le_bytes([data[0], data[1]]);
            display::print_field(&format!("{}: 0x{:04x}", label, uuid));
        }
        16 => {
            display::print_field(&format!(
                "{}: {:08x}-{:04x}-{:04x}-{:04x}-{:08x}{:04x}",
                label,
                u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
                u16::from_le_bytes([data[10], data[11]]),
                u16::from_le_bytes([data[8], data[9]]),
                u16::from_le_bytes([data[6], data[7]]),
                u32::from_le_bytes([data[2], data[3], data[4], data[5]]),
                u16::from_le_bytes([data[0], data[1]]),
            ));
        }
        _ => {
            display::print_hexdump(data);
        }
    }
}

fn print_handle_range(label: &str, data: &[u8]) {
    if data.len() >= 4 {
        let start = u16::from_le_bytes([data[0], data[1]]);
        let end = u16::from_le_bytes([data[2], data[3]]);
        display::print_field(&format!("{}: 0x{:04x}-0x{:04x}", label, start, end));
    }
}

/// Decode an ATT PDU.
pub fn decode_att(_index: u16, _incoming: bool, _handle: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let opcode = data[0];
    let name = att_opcode_to_str(opcode);

    display::print_field(&format!("ATT: {} (0x{:02x}) len {}", name, opcode, data.len() - 1));

    let params = &data[1..];

    match opcode {
        ATT_OP_ERROR_RSP => {
            if params.len() >= 4 {
                let req_opcode = params[0];
                let att_handle = u16::from_le_bytes([params[1], params[2]]);
                let error = params[3];
                display::print_field(&format!(
                    "  Request Opcode: {} (0x{:02x})",
                    att_opcode_to_str(req_opcode), req_opcode
                ));
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                display::print_field(&format!(
                    "  Error: {} (0x{:02x})",
                    error_to_str(error), error
                ));
            }
        }
        ATT_OP_MTU_REQ | ATT_OP_MTU_RSP => {
            if params.len() >= 2 {
                let mtu = u16::from_le_bytes([params[0], params[1]]);
                display::print_field(&format!("  Client/Server RX MTU: {}", mtu));
            }
        }
        ATT_OP_FIND_INFO_REQ => {
            if params.len() >= 4 {
                print_handle_range("  Handle range", params);
            }
        }
        ATT_OP_FIND_INFO_RSP => {
            if params.is_empty() {
                return;
            }
            let format = params[0];
            let uuid_len: usize = if format == 1 { 2 } else { 16 };
            let entry_len = 2 + uuid_len;
            display::print_field(&format!(
                "  Format: {} ({})",
                if format == 1 { "UUID-16" } else { "UUID-128" },
                format
            ));
            let mut offset = 1;
            while offset + entry_len <= params.len() {
                let att_handle = u16::from_le_bytes([params[offset], params[offset + 1]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                print_uuid("    UUID", &params[offset + 2..offset + 2 + uuid_len]);
                offset += entry_len;
            }
        }
        ATT_OP_FIND_BY_TYPE_REQ => {
            if params.len() >= 6 {
                print_handle_range("  Handle range", params);
                let att_type = u16::from_le_bytes([params[4], params[5]]);
                display::print_field(&format!("  Attribute type: 0x{:04x}", att_type));
                if params.len() > 6 {
                    display::print_field("  Value:");
                    display::print_hexdump(&params[6..]);
                }
            }
        }
        ATT_OP_FIND_BY_TYPE_RSP => {
            let mut offset = 0;
            while offset + 4 <= params.len() {
                let found_handle = u16::from_le_bytes([params[offset], params[offset + 1]]);
                let group_end = u16::from_le_bytes([params[offset + 2], params[offset + 3]]);
                display::print_field(&format!(
                    "  Handle: 0x{:04x} Group End: 0x{:04x}",
                    found_handle, group_end
                ));
                offset += 4;
            }
        }
        ATT_OP_READ_BY_TYPE_REQ | ATT_OP_READ_BY_GRP_TYPE_REQ => {
            if params.len() >= 4 {
                print_handle_range("  Handle range", params);
                if params.len() > 4 {
                    print_uuid("  Attribute type", &params[4..]);
                }
            }
        }
        ATT_OP_READ_BY_TYPE_RSP | ATT_OP_READ_BY_GRP_TYPE_RSP => {
            if params.is_empty() {
                return;
            }
            let entry_len = params[0] as usize;
            display::print_field(&format!("  Attribute data length: {}", entry_len));
            let mut offset = 1;
            while offset + entry_len <= params.len() {
                let att_handle = u16::from_le_bytes([params[offset], params[offset + 1]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                if entry_len > 2 {
                    display::print_hexdump(&params[offset + 2..offset + entry_len]);
                }
                offset += entry_len;
            }
        }
        ATT_OP_READ_REQ => {
            if params.len() >= 2 {
                let att_handle = u16::from_le_bytes([params[0], params[1]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
            }
        }
        ATT_OP_READ_RSP | ATT_OP_READ_BLOB_RSP => {
            if !params.is_empty() {
                display::print_hexdump(params);
            }
        }
        ATT_OP_READ_BLOB_REQ => {
            if params.len() >= 4 {
                let att_handle = u16::from_le_bytes([params[0], params[1]]);
                let offset_val = u16::from_le_bytes([params[2], params[3]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                display::print_field(&format!("  Offset: {}", offset_val));
            }
        }
        ATT_OP_READ_MULTI_REQ | ATT_OP_READ_MULTI_VAR_REQ => {
            let mut offset = 0;
            while offset + 2 <= params.len() {
                let att_handle = u16::from_le_bytes([params[offset], params[offset + 1]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                offset += 2;
            }
        }
        ATT_OP_READ_MULTI_RSP | ATT_OP_READ_MULTI_VAR_RSP => {
            if !params.is_empty() {
                display::print_hexdump(params);
            }
        }
        ATT_OP_WRITE_REQ | ATT_OP_WRITE_CMD => {
            if params.len() >= 2 {
                let att_handle = u16::from_le_bytes([params[0], params[1]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                if params.len() > 2 {
                    display::print_hexdump(&params[2..]);
                }
            }
        }
        ATT_OP_WRITE_RSP | ATT_OP_EXEC_WRITE_RSP | ATT_OP_HANDLE_CONF => {
            // No parameters
        }
        ATT_OP_PREP_WRITE_REQ | ATT_OP_PREP_WRITE_RSP => {
            if params.len() >= 4 {
                let att_handle = u16::from_le_bytes([params[0], params[1]]);
                let offset_val = u16::from_le_bytes([params[2], params[3]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                display::print_field(&format!("  Offset: {}", offset_val));
                if params.len() > 4 {
                    display::print_hexdump(&params[4..]);
                }
            }
        }
        ATT_OP_EXEC_WRITE_REQ => {
            if !params.is_empty() {
                let flags = params[0];
                display::print_field(&format!(
                    "  Flags: {} (0x{:02x})",
                    if flags == 0 { "Cancel" } else { "Write" },
                    flags
                ));
            }
        }
        ATT_OP_HANDLE_NOTIFY | ATT_OP_HANDLE_IND => {
            if params.len() >= 2 {
                let att_handle = u16::from_le_bytes([params[0], params[1]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                if params.len() > 2 {
                    display::print_hexdump(&params[2..]);
                }
            }
        }
        ATT_OP_MULTI_NOTIFY => {
            let mut offset = 0;
            while offset + 4 <= params.len() {
                let att_handle = u16::from_le_bytes([params[offset], params[offset + 1]]);
                let val_len = u16::from_le_bytes([params[offset + 2], params[offset + 3]]) as usize;
                display::print_field(&format!("  Handle: 0x{:04x} Length: {}", att_handle, val_len));
                offset += 4;
                let end = (offset + val_len).min(params.len());
                if end > offset {
                    display::print_hexdump(&params[offset..end]);
                }
                offset = end;
            }
        }
        ATT_OP_SIGNED_WRITE_CMD => {
            if params.len() >= 2 {
                let att_handle = u16::from_le_bytes([params[0], params[1]]);
                display::print_field(&format!("  Handle: 0x{:04x}", att_handle));
                // Last 12 bytes are signature (if present)
                if params.len() > 14 {
                    display::print_hexdump(&params[2..params.len() - 12]);
                    display::print_field("  Signature:");
                    display::print_hexdump(&params[params.len() - 12..]);
                } else if params.len() > 2 {
                    display::print_hexdump(&params[2..]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_att_opcode_to_str() {
        assert_eq!(att_opcode_to_str(ATT_OP_MTU_REQ), "Exchange MTU Request");
        assert_eq!(att_opcode_to_str(ATT_OP_ERROR_RSP), "Error Response");
        assert_eq!(att_opcode_to_str(0xFF), "Unknown");
    }

    #[test]
    fn test_error_to_str() {
        assert_eq!(error_to_str(0x01), "Invalid Handle");
        assert_eq!(error_to_str(0x06), "Request Not Supported");
        assert_eq!(error_to_str(0xFF), "Unknown");
    }

    #[test]
    fn test_decode_att_mtu_req() {
        // MTU Request: opcode=0x02, MTU=256
        let data = [0x02, 0x00, 0x01];
        decode_att(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_att_error_rsp() {
        // Error Response: opcode=0x01, req_opcode=0x0a, handle=0x0001, error=0x0a
        let data = [0x01, 0x0a, 0x01, 0x00, 0x0a];
        decode_att(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_att_read_req() {
        // Read Request: opcode=0x0a, handle=0x0003
        let data = [0x0a, 0x03, 0x00];
        decode_att(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_att_write_cmd() {
        // Write Command: opcode=0x52, handle=0x0004, value=[0x01]
        let data = [0x52, 0x04, 0x00, 0x01];
        decode_att(0, false, 0x0040, &data);
    }

    #[test]
    fn test_decode_att_notification() {
        // Handle Value Notification: opcode=0x1b, handle=0x0005, value=[0xAA, 0xBB]
        let data = [0x1b, 0x05, 0x00, 0xAA, 0xBB];
        decode_att(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_att_empty() {
        decode_att(0, true, 0x0040, &[]);
    }

    #[test]
    fn test_decode_att_find_info_req() {
        // Find Information Request: opcode=0x04, start=0x0001, end=0xFFFF
        let data = [0x04, 0x01, 0x00, 0xFF, 0xFF];
        decode_att(0, false, 0x0040, &data);
    }
}
