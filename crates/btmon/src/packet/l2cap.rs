// SPDX-License-Identifier: GPL-2.0-or-later
//
// L2CAP frame decoder replacing monitor/l2cap.c
//
// Parses L2CAP headers and dispatches to higher-level protocol decoders
// (ATT, SMP, SDP, etc.) based on the Channel ID (CID).

use crate::display;
use super::att;
use super::smp;

// Well-known CIDs
const L2CAP_CID_SIGNALING: u16 = 0x0001;
const L2CAP_CID_CONNECTIONLESS: u16 = 0x0002;
const L2CAP_CID_ATT: u16 = 0x0004;
const L2CAP_CID_LE_SIGNALING: u16 = 0x0005;
const L2CAP_CID_SMP: u16 = 0x0006;
const L2CAP_CID_SMP_BREDR: u16 = 0x0007;

// L2CAP signaling opcodes
const L2CAP_CMD_REJECT: u8 = 0x01;
const L2CAP_CONN_REQ: u8 = 0x02;
const L2CAP_CONN_RSP: u8 = 0x03;
const L2CAP_CONF_REQ: u8 = 0x04;
const L2CAP_CONF_RSP: u8 = 0x05;
const L2CAP_DISCONN_REQ: u8 = 0x06;
const L2CAP_DISCONN_RSP: u8 = 0x07;
const L2CAP_ECHO_REQ: u8 = 0x08;
const L2CAP_ECHO_RSP: u8 = 0x09;
const L2CAP_INFO_REQ: u8 = 0x0a;
const L2CAP_INFO_RSP: u8 = 0x0b;
const L2CAP_CONN_PARAM_UPDATE_REQ: u8 = 0x12;
const L2CAP_CONN_PARAM_UPDATE_RSP: u8 = 0x13;
const L2CAP_LE_CREDIT_CONN_REQ: u8 = 0x14;
const L2CAP_LE_CREDIT_CONN_RSP: u8 = 0x15;
const L2CAP_LE_FLOW_CONTROL_CREDIT: u8 = 0x16;
const L2CAP_ECRED_CONN_REQ: u8 = 0x17;
const L2CAP_ECRED_CONN_RSP: u8 = 0x18;
const L2CAP_ECRED_RECONF_REQ: u8 = 0x19;
const L2CAP_ECRED_RECONF_RSP: u8 = 0x1a;

fn le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// L2CAP frame context for protocol decoders.
pub struct L2capFrame<'a> {
    pub index: u16,
    pub incoming: bool,
    pub handle: u16,
    pub cid: u16,
    pub data: &'a [u8],
}

/// PSM to protocol name mapping.
fn psm_to_str(psm: u16) -> &'static str {
    match psm {
        0x0001 => "SDP",
        0x0003 => "RFCOMM",
        0x000f => "BNEP",
        0x0011 => "HID-Control",
        0x0013 => "HID-Interrupt",
        0x0017 => "AVCTP-Control",
        0x001b => "AVDTP",
        0x001f => "AVCTP-Browsing",
        0x0025 => "ATT",
        0x0027 => "LE Audio",
        _ => "Unknown",
    }
}

/// Decode an L2CAP packet from ACL data.
pub fn decode_l2cap(index: u16, incoming: bool, handle: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let l2cap_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let cid = u16::from_le_bytes([data[2], data[3]]);

    display::print_field(&format!(
        "L2CAP: len {} cid 0x{:04x} [{}]",
        l2cap_len,
        cid,
        cid_to_str(cid),
    ));

    if data.len() < 4 + l2cap_len {
        display::print_text(display::COLOR_RED, "L2CAP: packet too short");
        return;
    }

    let payload = &data[4..4 + l2cap_len];

    match cid {
        L2CAP_CID_SIGNALING => decode_signaling(payload),
        L2CAP_CID_LE_SIGNALING => decode_le_signaling(payload),
        L2CAP_CID_ATT => att::decode_att(index, incoming, handle, payload),
        L2CAP_CID_SMP | L2CAP_CID_SMP_BREDR => smp::decode_smp(payload),
        L2CAP_CID_CONNECTIONLESS => {
            display::print_field("Connectionless data:");
            display::print_hexdump(payload);
        }
        _ => {
            // Dynamic CID -- could be RFCOMM, SDP, AVDTP, etc.
            display::print_field(&format!("Dynamic CID 0x{:04x}:", cid));
            display::print_hexdump(payload);
        }
    }
}

fn cid_to_str(cid: u16) -> &'static str {
    match cid {
        L2CAP_CID_SIGNALING => "Signaling",
        L2CAP_CID_CONNECTIONLESS => "Connectionless",
        L2CAP_CID_ATT => "ATT",
        L2CAP_CID_LE_SIGNALING => "LE Signaling",
        L2CAP_CID_SMP => "SMP",
        L2CAP_CID_SMP_BREDR => "SMP BR/EDR",
        _ => "Dynamic",
    }
}

fn info_type_str(info_type: u16) -> &'static str {
    match info_type {
        0x0001 => "Connectionless MTU",
        0x0002 => "Extended Features Supported",
        0x0003 => "Fixed Channels Supported",
        _ => "Unknown",
    }
}

fn decode_extended_features(mask: u32) {
    if mask & 0x0001 != 0 { display::print_field("    Flow Control Mode"); }
    if mask & 0x0002 != 0 { display::print_field("    Retransmission Mode"); }
    if mask & 0x0004 != 0 { display::print_field("    Bi-directional QoS"); }
    if mask & 0x0008 != 0 { display::print_field("    Enhanced Retransmission Mode"); }
    if mask & 0x0010 != 0 { display::print_field("    Streaming Mode"); }
    if mask & 0x0020 != 0 { display::print_field("    FCS Option"); }
    if mask & 0x0040 != 0 { display::print_field("    Extended Flow Specification"); }
    if mask & 0x0080 != 0 { display::print_field("    Fixed Channels"); }
    if mask & 0x0100 != 0 { display::print_field("    Extended Window Size"); }
    if mask & 0x0200 != 0 { display::print_field("    Unicast Connectionless Data Reception"); }
    if mask & 0x0400 != 0 { display::print_field("    Enhanced Credit Based Flow Control Mode"); }
}

fn conn_result_str(result: u16) -> &'static str {
    match result {
        0x0000 => "Connection successful",
        0x0001 => "Connection pending",
        0x0002 => "Connection refused - PSM not supported",
        0x0003 => "Connection refused - security block",
        0x0004 => "Connection refused - no resources available",
        0x0006 => "Connection refused - invalid Source CID",
        0x0007 => "Connection refused - Source CID already allocated",
        _ => "Unknown",
    }
}

fn le_credit_conn_result_str(result: u16) -> &'static str {
    match result {
        0x0000 => "Connection successful",
        0x0002 => "Connection refused - PSM not supported",
        0x0004 => "Connection refused - no resources",
        0x0005 => "Connection refused - insufficient authentication",
        0x0006 => "Connection refused - insufficient authorization",
        0x0007 => "Connection refused - insufficient encryption key size",
        0x0008 => "Connection refused - insufficient encryption",
        0x0009 => "Connection refused - invalid Source CID",
        0x000a => "Connection refused - Source CID already allocated",
        0x000b => "Connection refused - unacceptable parameters",
        _ => "Unknown",
    }
}

fn decode_signaling(data: &[u8]) {
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let code = data[offset];
        let ident = data[offset + 1];
        let length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        let name = signaling_code_to_str(code);
        display::print_field(&format!(
            "L2CAP Signaling: {} (0x{:02x}) ident {} len {}",
            name, code, ident, length
        ));

        let payload_end = (offset + 4 + length).min(data.len());
        let payload = &data[offset + 4..payload_end];

        decode_signaling_payload(code, payload);

        offset += 4 + length;
    }
}

fn decode_signaling_payload(code: u8, payload: &[u8]) {
    match code {
        L2CAP_CONN_REQ => {
            if payload.len() >= 4 {
                let psm = le_u16(payload, 0);
                let scid = le_u16(payload, 2);
                display::print_field(&format!("  PSM: {} (0x{:04x})", psm_to_str(psm), psm));
                display::print_field(&format!("  Source CID: 0x{:04x}", scid));
            }
        }
        L2CAP_CONN_RSP => {
            if payload.len() >= 8 {
                let dcid = le_u16(payload, 0);
                let scid = le_u16(payload, 2);
                let result = le_u16(payload, 4);
                let status = le_u16(payload, 6);
                display::print_field(&format!("  Destination CID: 0x{:04x}", dcid));
                display::print_field(&format!("  Source CID: 0x{:04x}", scid));
                display::print_field(&format!("  Result: {} (0x{:04x})", conn_result_str(result), result));
                display::print_field(&format!("  Status: 0x{:04x}", status));
            }
        }
        L2CAP_CONF_REQ => {
            if payload.len() >= 4 {
                let dcid = le_u16(payload, 0);
                let flags = le_u16(payload, 2);
                display::print_field(&format!("  Destination CID: 0x{:04x}", dcid));
                display::print_field(&format!("  Flags: 0x{:04x}", flags));
                if payload.len() > 4 {
                    display::print_field("  Configuration options:");
                    display::print_hexdump(&payload[4..]);
                }
            }
        }
        L2CAP_CONF_RSP => {
            if payload.len() >= 6 {
                let scid = le_u16(payload, 0);
                let flags = le_u16(payload, 2);
                let result = le_u16(payload, 4);
                display::print_field(&format!("  Source CID: 0x{:04x}", scid));
                display::print_field(&format!("  Flags: 0x{:04x}", flags));
                display::print_field(&format!("  Result: 0x{:04x}", result));
                if payload.len() > 6 {
                    display::print_field("  Configuration options:");
                    display::print_hexdump(&payload[6..]);
                }
            }
        }
        L2CAP_DISCONN_REQ => {
            if payload.len() >= 4 {
                let dcid = le_u16(payload, 0);
                let scid = le_u16(payload, 2);
                display::print_field(&format!("  Destination CID: 0x{:04x}", dcid));
                display::print_field(&format!("  Source CID: 0x{:04x}", scid));
            }
        }
        L2CAP_DISCONN_RSP => {
            if payload.len() >= 4 {
                let dcid = le_u16(payload, 0);
                let scid = le_u16(payload, 2);
                display::print_field(&format!("  Destination CID: 0x{:04x}", dcid));
                display::print_field(&format!("  Source CID: 0x{:04x}", scid));
            }
        }
        L2CAP_INFO_REQ => {
            if payload.len() >= 2 {
                let info_type = le_u16(payload, 0);
                display::print_field(&format!("  Info type: {} (0x{:04x})", info_type_str(info_type), info_type));
            }
        }
        L2CAP_INFO_RSP => {
            if payload.len() >= 4 {
                let info_type = le_u16(payload, 0);
                let result = le_u16(payload, 2);
                display::print_field(&format!("  Info type: {} (0x{:04x})", info_type_str(info_type), info_type));
                display::print_field(&format!("  Result: {} (0x{:04x})", if result == 0 { "Success" } else { "Not supported" }, result));
                if result == 0 && payload.len() > 4 {
                    match info_type {
                        0x0001 => {
                            // Connectionless MTU
                            if payload.len() >= 6 {
                                let mtu = le_u16(payload, 4);
                                display::print_field(&format!("  Connectionless MTU: {}", mtu));
                            }
                        }
                        0x0002 => {
                            // Extended Features
                            if payload.len() >= 8 {
                                let mask = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                                display::print_field(&format!("  Extended features: 0x{:08x}", mask));
                                decode_extended_features(mask);
                            }
                        }
                        0x0003 => {
                            // Fixed Channels
                            if payload.len() >= 12 {
                                display::print_hex_field("  Fixed channels", &payload[4..12]);
                            }
                        }
                        _ => {
                            display::print_hexdump(&payload[4..]);
                        }
                    }
                }
            }
        }
        L2CAP_LE_CREDIT_CONN_REQ => {
            if payload.len() >= 10 {
                let psm = le_u16(payload, 0);
                let scid = le_u16(payload, 2);
                let mtu = le_u16(payload, 4);
                let mps = le_u16(payload, 6);
                let credits = le_u16(payload, 8);
                display::print_field(&format!("  PSM: {} (0x{:04x})", psm_to_str(psm), psm));
                display::print_field(&format!("  Source CID: 0x{:04x}", scid));
                display::print_field(&format!("  MTU: {}", mtu));
                display::print_field(&format!("  MPS: {}", mps));
                display::print_field(&format!("  Initial Credits: {}", credits));
            }
        }
        L2CAP_LE_CREDIT_CONN_RSP => {
            if payload.len() >= 10 {
                let dcid = le_u16(payload, 0);
                let mtu = le_u16(payload, 2);
                let mps = le_u16(payload, 4);
                let credits = le_u16(payload, 6);
                let result = le_u16(payload, 8);
                display::print_field(&format!("  Destination CID: 0x{:04x}", dcid));
                display::print_field(&format!("  MTU: {}", mtu));
                display::print_field(&format!("  MPS: {}", mps));
                display::print_field(&format!("  Initial Credits: {}", credits));
                display::print_field(&format!("  Result: {} (0x{:04x})", le_credit_conn_result_str(result), result));
            }
        }
        L2CAP_LE_FLOW_CONTROL_CREDIT => {
            if payload.len() >= 4 {
                let cid = le_u16(payload, 0);
                let credits = le_u16(payload, 2);
                display::print_field(&format!("  CID: 0x{:04x}", cid));
                display::print_field(&format!("  Credits: {}", credits));
            }
        }
        L2CAP_ECRED_CONN_REQ => {
            if payload.len() >= 8 {
                let psm = le_u16(payload, 0);
                let mtu = le_u16(payload, 2);
                let mps = le_u16(payload, 4);
                let credits = le_u16(payload, 6);
                display::print_field(&format!("  PSM: {} (0x{:04x})", psm_to_str(psm), psm));
                display::print_field(&format!("  MTU: {}", mtu));
                display::print_field(&format!("  MPS: {}", mps));
                display::print_field(&format!("  Initial Credits: {}", credits));
                // Source CID list follows
                let mut off = 8;
                while off + 2 <= payload.len() {
                    let scid = le_u16(payload, off);
                    display::print_field(&format!("  Source CID: 0x{:04x}", scid));
                    off += 2;
                }
            }
        }
        L2CAP_ECRED_CONN_RSP => {
            if payload.len() >= 8 {
                let mtu = le_u16(payload, 0);
                let mps = le_u16(payload, 2);
                let credits = le_u16(payload, 4);
                let result = le_u16(payload, 6);
                display::print_field(&format!("  MTU: {}", mtu));
                display::print_field(&format!("  MPS: {}", mps));
                display::print_field(&format!("  Initial Credits: {}", credits));
                display::print_field(&format!("  Result: {} (0x{:04x})", le_credit_conn_result_str(result), result));
                // Destination CID list follows
                let mut off = 8;
                while off + 2 <= payload.len() {
                    let dcid = le_u16(payload, off);
                    display::print_field(&format!("  Destination CID: 0x{:04x}", dcid));
                    off += 2;
                }
            }
        }
        L2CAP_ECRED_RECONF_REQ => {
            if payload.len() >= 4 {
                let mtu = le_u16(payload, 0);
                let mps = le_u16(payload, 2);
                display::print_field(&format!("  MTU: {}", mtu));
                display::print_field(&format!("  MPS: {}", mps));
                // Destination CID list follows
                let mut off = 4;
                while off + 2 <= payload.len() {
                    let dcid = le_u16(payload, off);
                    display::print_field(&format!("  Destination CID: 0x{:04x}", dcid));
                    off += 2;
                }
            }
        }
        L2CAP_ECRED_RECONF_RSP => {
            if payload.len() >= 2 {
                let result = le_u16(payload, 0);
                let result_str = match result {
                    0x0000 => "Success",
                    0x0001 => "Reduction not allowed",
                    0x0002 => "Invalid MTU",
                    0x0003 => "Invalid MPS",
                    0x0004 => "Invalid CIDs",
                    _ => "Unknown",
                };
                display::print_field(&format!("  Result: {} (0x{:04x})", result_str, result));
            }
        }
        L2CAP_CONN_PARAM_UPDATE_REQ => {
            if payload.len() >= 8 {
                let interval_min = le_u16(payload, 0);
                let interval_max = le_u16(payload, 2);
                let latency = le_u16(payload, 4);
                let timeout = le_u16(payload, 6);
                display::print_field(&format!("  Min interval: {} ({:.2} ms)", interval_min, interval_min as f64 * 1.25));
                display::print_field(&format!("  Max interval: {} ({:.2} ms)", interval_max, interval_max as f64 * 1.25));
                display::print_field(&format!("  Peripheral latency: {}", latency));
                display::print_field(&format!("  Supervision timeout: {} ({} ms)", timeout, timeout as u32 * 10));
            }
        }
        L2CAP_CONN_PARAM_UPDATE_RSP => {
            if payload.len() >= 2 {
                let result = le_u16(payload, 0);
                display::print_field(&format!("  Result: {} (0x{:04x})", if result == 0 { "Accepted" } else { "Rejected" }, result));
            }
        }
        L2CAP_CMD_REJECT => {
            if payload.len() >= 2 {
                let reason = le_u16(payload, 0);
                let reason_str = match reason {
                    0x0000 => "Command not understood",
                    0x0001 => "Signaling MTU exceeded",
                    0x0002 => "Invalid CID in request",
                    _ => "Unknown",
                };
                display::print_field(&format!("  Reason: {} (0x{:04x})", reason_str, reason));
                if payload.len() > 2 {
                    display::print_hexdump(&payload[2..]);
                }
            }
        }
        _ => {
            if !payload.is_empty() {
                display::print_hexdump(payload);
            }
        }
    }
}

fn decode_le_signaling(data: &[u8]) {
    // Same structure as BR/EDR signaling but with different allowed commands
    decode_signaling(data);
}

fn signaling_code_to_str(code: u8) -> &'static str {
    match code {
        L2CAP_CMD_REJECT => "Command Reject",
        L2CAP_CONN_REQ => "Connection Request",
        L2CAP_CONN_RSP => "Connection Response",
        L2CAP_CONF_REQ => "Configuration Request",
        L2CAP_CONF_RSP => "Configuration Response",
        L2CAP_DISCONN_REQ => "Disconnection Request",
        L2CAP_DISCONN_RSP => "Disconnection Response",
        L2CAP_ECHO_REQ => "Echo Request",
        L2CAP_ECHO_RSP => "Echo Response",
        L2CAP_INFO_REQ => "Information Request",
        L2CAP_INFO_RSP => "Information Response",
        L2CAP_CONN_PARAM_UPDATE_REQ => "Connection Parameter Update Request",
        L2CAP_CONN_PARAM_UPDATE_RSP => "Connection Parameter Update Response",
        L2CAP_LE_CREDIT_CONN_REQ => "LE Credit Based Connection Request",
        L2CAP_LE_CREDIT_CONN_RSP => "LE Credit Based Connection Response",
        L2CAP_LE_FLOW_CONTROL_CREDIT => "LE Flow Control Credit",
        L2CAP_ECRED_CONN_REQ => "Enhanced Credit Based Connection Request",
        L2CAP_ECRED_CONN_RSP => "Enhanced Credit Based Connection Response",
        L2CAP_ECRED_RECONF_REQ => "Enhanced Credit Based Reconfigure Request",
        L2CAP_ECRED_RECONF_RSP => "Enhanced Credit Based Reconfigure Response",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_to_str() {
        assert_eq!(cid_to_str(L2CAP_CID_ATT), "ATT");
        assert_eq!(cid_to_str(L2CAP_CID_SMP), "SMP");
        assert_eq!(cid_to_str(0x0040), "Dynamic");
    }

    #[test]
    fn test_signaling_code_to_str() {
        assert_eq!(signaling_code_to_str(L2CAP_CONN_REQ), "Connection Request");
        assert_eq!(signaling_code_to_str(L2CAP_LE_CREDIT_CONN_REQ), "LE Credit Based Connection Request");
        assert_eq!(signaling_code_to_str(L2CAP_ECRED_CONN_REQ), "Enhanced Credit Based Connection Request");
        assert_eq!(signaling_code_to_str(0xFF), "Unknown");
    }

    #[test]
    fn test_decode_l2cap_att() {
        // L2CAP header: len=3, CID=0x0004 (ATT)
        // ATT payload: Exchange MTU Request (0x02), MTU=256
        let data = [0x03, 0x00, 0x04, 0x00, 0x02, 0x00, 0x01];
        decode_l2cap(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_l2cap_signaling() {
        // Connection Request: code=0x02, ident=1, len=4, PSM=0x0001, SCID=0x0040
        let data = [0x08, 0x00, 0x01, 0x00,
                     0x02, 0x01, 0x04, 0x00, 0x01, 0x00, 0x40, 0x00];
        decode_l2cap(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_smp_via_l2cap() {
        // L2CAP header: len=7, CID=0x0006 (SMP), SMP Pairing Request
        let data = [0x07, 0x00, 0x06, 0x00, 0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07];
        decode_l2cap(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_l2cap_short() {
        decode_l2cap(0, true, 0x0040, &[0x00, 0x00]);
        decode_l2cap(0, true, 0x0040, &[]);
    }

    #[test]
    fn test_decode_l2cap_le_credit_conn_req() {
        // LE Credit Based Connection Request: code=0x14, ident=1, len=10
        // PSM=0x0025 (ATT), SCID=0x0040, MTU=256, MPS=256, Credits=10
        let l2cap_payload = [
            0x14, 0x01, 0x0a, 0x00,
            0x25, 0x00, 0x40, 0x00, 0x00, 0x01, 0x00, 0x01, 0x0a, 0x00,
        ];
        let mut data = vec![
            (l2cap_payload.len() as u8), 0x00, // L2CAP length
            0x05, 0x00, // CID = LE Signaling
        ];
        data.extend_from_slice(&l2cap_payload);
        decode_l2cap(0, true, 0x0040, &data);
    }

    #[test]
    fn test_decode_l2cap_le_credit_conn_rsp() {
        // LE Credit Based Connection Response: code=0x15, ident=1, len=10
        let l2cap_payload = [
            0x15, 0x01, 0x0a, 0x00,
            0x40, 0x00, // DCID
            0x00, 0x01, // MTU
            0x00, 0x01, // MPS
            0x0a, 0x00, // Credits
            0x00, 0x00, // Result: success
        ];
        decode_signaling(&l2cap_payload);
    }

    #[test]
    fn test_decode_l2cap_le_flow_control_credit() {
        let payload = [
            0x16, 0x01, 0x04, 0x00,
            0x40, 0x00, // CID
            0x05, 0x00, // Credits
        ];
        decode_signaling(&payload);
    }

    #[test]
    fn test_decode_l2cap_ecred_conn_req() {
        let payload = [
            0x17, 0x01, 0x0c, 0x00,
            0x25, 0x00, // PSM
            0x00, 0x02, // MTU
            0x00, 0x01, // MPS
            0x0a, 0x00, // Credits
            0x40, 0x00, // SCID 1
            0x41, 0x00, // SCID 2
        ];
        decode_signaling(&payload);
    }

    #[test]
    fn test_decode_l2cap_ecred_conn_rsp() {
        let payload = [
            0x18, 0x01, 0x0c, 0x00,
            0x00, 0x02, // MTU
            0x00, 0x01, // MPS
            0x0a, 0x00, // Credits
            0x00, 0x00, // Result
            0x40, 0x00, // DCID 1
            0x41, 0x00, // DCID 2
        ];
        decode_signaling(&payload);
    }

    #[test]
    fn test_decode_l2cap_ecred_reconf() {
        let req_payload = [
            0x19, 0x01, 0x06, 0x00,
            0x00, 0x02, // MTU
            0x00, 0x01, // MPS
            0x40, 0x00, // DCID
        ];
        decode_signaling(&req_payload);

        let rsp_payload = [
            0x1a, 0x01, 0x02, 0x00,
            0x00, 0x00, // Result: success
        ];
        decode_signaling(&rsp_payload);
    }

    #[test]
    fn test_decode_info_rsp_extended_features() {
        // Info Response with Extended Features
        let payload = [
            0x0b, 0x01, 0x08, 0x00,
            0x02, 0x00, // Info type: Extended Features Supported
            0x00, 0x00, // Result: Success
            0xA8, 0x04, 0x00, 0x00, // Mask
        ];
        decode_signaling(&payload);
    }

    #[test]
    fn test_psm_to_str() {
        assert_eq!(psm_to_str(0x0001), "SDP");
        assert_eq!(psm_to_str(0x0003), "RFCOMM");
        assert_eq!(psm_to_str(0x9999), "Unknown");
    }
}
