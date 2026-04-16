// SPDX-License-Identifier: GPL-2.0-or-later
//
// SMP (Security Manager Protocol) decoder
//
// Decodes SMP PDUs carried over L2CAP CID 0x0006 (LE) or 0x0007 (BR/EDR).

use crate::display;

// SMP opcodes
const SMP_PAIRING_REQUEST: u8 = 0x01;
const SMP_PAIRING_RESPONSE: u8 = 0x02;
const SMP_PAIRING_CONFIRM: u8 = 0x03;
const SMP_PAIRING_RANDOM: u8 = 0x04;
const SMP_PAIRING_FAILED: u8 = 0x05;
const SMP_ENCRYPT_INFO: u8 = 0x06;
const SMP_CENTRAL_IDENT: u8 = 0x07;
const SMP_IDENT_INFO: u8 = 0x08;
const SMP_IDENT_ADDR_INFO: u8 = 0x09;
const SMP_SIGNING_INFO: u8 = 0x0a;
const SMP_SECURITY_REQUEST: u8 = 0x0b;
const SMP_PAIRING_PUBLIC_KEY: u8 = 0x0c;
const SMP_PAIRING_DHKEY_CHECK: u8 = 0x0d;
const SMP_PAIRING_KEYPRESS: u8 = 0x0e;

fn smp_opcode_to_str(opcode: u8) -> &'static str {
    match opcode {
        SMP_PAIRING_REQUEST => "Pairing Request",
        SMP_PAIRING_RESPONSE => "Pairing Response",
        SMP_PAIRING_CONFIRM => "Pairing Confirm",
        SMP_PAIRING_RANDOM => "Pairing Random",
        SMP_PAIRING_FAILED => "Pairing Failed",
        SMP_ENCRYPT_INFO => "Encryption Information",
        SMP_CENTRAL_IDENT => "Central Identification",
        SMP_IDENT_INFO => "Identity Information",
        SMP_IDENT_ADDR_INFO => "Identity Address Information",
        SMP_SIGNING_INFO => "Signing Information",
        SMP_SECURITY_REQUEST => "Security Request",
        SMP_PAIRING_PUBLIC_KEY => "Pairing Public Key",
        SMP_PAIRING_DHKEY_CHECK => "Pairing DHKey Check",
        SMP_PAIRING_KEYPRESS => "Pairing Keypress Notification",
        _ => "Unknown",
    }
}

fn io_capability_str(cap: u8) -> &'static str {
    match cap {
        0x00 => "DisplayOnly",
        0x01 => "DisplayYesNo",
        0x02 => "KeyboardOnly",
        0x03 => "NoInputNoOutput",
        0x04 => "KeyboardDisplay",
        _ => "Unknown",
    }
}

fn oob_data_flag_str(flag: u8) -> &'static str {
    match flag {
        0x00 => "OOB Authentication data not present",
        0x01 => "OOB Authentication data from remote device present",
        _ => "Unknown",
    }
}

fn decode_auth_req(auth_req: u8) {
    display::print_field(&format!("  AuthReq: 0x{:02x}", auth_req));
    if auth_req & 0x01 != 0 { display::print_field("    Bonding"); }
    if auth_req & 0x04 != 0 { display::print_field("    MITM"); }
    if auth_req & 0x08 != 0 { display::print_field("    Secure Connections"); }
    if auth_req & 0x10 != 0 { display::print_field("    Keypress Notifications"); }
    if auth_req & 0x20 != 0 { display::print_field("    CT2"); }
}

fn decode_key_dist(label: &str, flags: u8) {
    display::print_field(&format!("  {} Key Distribution: 0x{:02x}", label, flags));
    if flags & 0x01 != 0 { display::print_field(&format!("    {} EncKey (LTK)", label)); }
    if flags & 0x02 != 0 { display::print_field(&format!("    {} IdKey (IRK)", label)); }
    if flags & 0x04 != 0 { display::print_field(&format!("    {} Sign (CSRK)", label)); }
    if flags & 0x08 != 0 { display::print_field(&format!("    {} LinkKey", label)); }
}

fn pairing_failed_reason_str(reason: u8) -> &'static str {
    match reason {
        0x01 => "Passkey Entry Failed",
        0x02 => "OOB Not Available",
        0x03 => "Authentication Requirements",
        0x04 => "Confirm Value Failed",
        0x05 => "Pairing Not Supported",
        0x06 => "Encryption Key Size",
        0x07 => "Command Not Supported",
        0x08 => "Unspecified Reason",
        0x09 => "Repeated Attempts",
        0x0a => "Invalid Parameters",
        0x0b => "DHKey Check Failed",
        0x0c => "Numeric Comparison Failed",
        0x0d => "BR/EDR pairing in progress",
        0x0e => "Cross-transport Key Derivation/Generation not allowed",
        0x0f => "Key Rejected",
        _ => "Unknown",
    }
}

fn keypress_type_str(t: u8) -> &'static str {
    match t {
        0x00 => "Passkey entry started",
        0x01 => "Passkey digit entered",
        0x02 => "Passkey digit erased",
        0x03 => "Passkey cleared",
        0x04 => "Passkey entry completed",
        _ => "Unknown",
    }
}

/// Decode an SMP PDU.
pub fn decode_smp(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let opcode = data[0];
    let name = smp_opcode_to_str(opcode);
    display::print_field(&format!("SMP: {} (0x{:02x})", name, opcode));

    let params = &data[1..];

    match opcode {
        SMP_PAIRING_REQUEST | SMP_PAIRING_RESPONSE => {
            if params.len() >= 6 {
                display::print_field(&format!("  IO Capability: {} (0x{:02x})", io_capability_str(params[0]), params[0]));
                display::print_field(&format!("  OOB data flag: {} (0x{:02x})", oob_data_flag_str(params[1]), params[1]));
                decode_auth_req(params[2]);
                display::print_field(&format!("  Max encryption key size: {}", params[3]));
                decode_key_dist("Initiator", params[4]);
                decode_key_dist("Responder", params[5]);
            }
        }
        SMP_PAIRING_CONFIRM => {
            if params.len() >= 16 {
                display::print_hex_field("  Confirm value", &params[0..16]);
            }
        }
        SMP_PAIRING_RANDOM => {
            if params.len() >= 16 {
                display::print_hex_field("  Random value", &params[0..16]);
            }
        }
        SMP_PAIRING_FAILED => {
            if !params.is_empty() {
                display::print_field(&format!("  Reason: {} (0x{:02x})", pairing_failed_reason_str(params[0]), params[0]));
            }
        }
        SMP_ENCRYPT_INFO => {
            if params.len() >= 16 {
                display::print_hex_field("  Long Term Key", &params[0..16]);
            }
        }
        SMP_CENTRAL_IDENT => {
            if params.len() >= 10 {
                let ediv = u16::from_le_bytes([params[0], params[1]]);
                display::print_field(&format!("  EDIV: 0x{:04x}", ediv));
                display::print_hex_field("  Rand", &params[2..10]);
            }
        }
        SMP_IDENT_INFO => {
            if params.len() >= 16 {
                display::print_hex_field("  Identity Resolving Key", &params[0..16]);
            }
        }
        SMP_IDENT_ADDR_INFO => {
            if params.len() >= 7 {
                let addr_type = params[0];
                let addr_type_str = if addr_type == 0 { "Public" } else { "Random" };
                display::print_field(&format!("  Address type: {} (0x{:02x})", addr_type_str, addr_type));
                if let Ok(addr) = <[u8; 6]>::try_from(&params[1..7]) {
                    display::print_addr("  Address", &addr, addr_type);
                }
            }
        }
        SMP_SIGNING_INFO => {
            if params.len() >= 16 {
                display::print_hex_field("  Signature Key", &params[0..16]);
            }
        }
        SMP_SECURITY_REQUEST => {
            if !params.is_empty() {
                decode_auth_req(params[0]);
            }
        }
        SMP_PAIRING_PUBLIC_KEY => {
            if params.len() >= 64 {
                display::print_hex_field("  Public Key X", &params[0..32]);
                display::print_hex_field("  Public Key Y", &params[32..64]);
            }
        }
        SMP_PAIRING_DHKEY_CHECK => {
            if params.len() >= 16 {
                display::print_hex_field("  DHKey Check", &params[0..16]);
            }
        }
        SMP_PAIRING_KEYPRESS => {
            if !params.is_empty() {
                display::print_field(&format!("  Notification type: {} (0x{:02x})", keypress_type_str(params[0]), params[0]));
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
    fn test_smp_opcode_to_str() {
        assert_eq!(smp_opcode_to_str(0x01), "Pairing Request");
        assert_eq!(smp_opcode_to_str(0x0c), "Pairing Public Key");
        assert_eq!(smp_opcode_to_str(0xFF), "Unknown");
    }

    #[test]
    fn test_decode_smp_pairing_request() {
        // Pairing Request: IO=DisplayYesNo, OOB=No, AuthReq=0x0D (bonding+MITM+SC),
        // MaxKeySize=16, InitKeyDist=0x07, RespKeyDist=0x07
        let data = [0x01, 0x01, 0x00, 0x0D, 0x10, 0x07, 0x07];
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_pairing_response() {
        let data = [0x02, 0x03, 0x00, 0x09, 0x10, 0x03, 0x03];
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_pairing_confirm() {
        let mut data = vec![0x03];
        data.extend_from_slice(&[0xAA; 16]);
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_pairing_random() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0xBB; 16]);
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_pairing_failed() {
        // Failed: Authentication Requirements
        let data = [0x05, 0x03];
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_encrypt_info() {
        let mut data = vec![0x06];
        data.extend_from_slice(&[0xCC; 16]);
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_central_ident() {
        let data = [0x07, 0x34, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_ident_addr_info() {
        let data = [0x09, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_security_request() {
        let data = [0x0b, 0x0D];
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_public_key() {
        let mut data = vec![0x0c];
        data.extend_from_slice(&[0xDD; 64]);
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_dhkey_check() {
        let mut data = vec![0x0d];
        data.extend_from_slice(&[0xEE; 16]);
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_keypress() {
        let data = [0x0e, 0x01]; // Passkey digit entered
        decode_smp(&data);
    }

    #[test]
    fn test_decode_smp_empty() {
        decode_smp(&[]);
    }

    #[test]
    fn test_pairing_failed_reason_str() {
        assert_eq!(pairing_failed_reason_str(0x01), "Passkey Entry Failed");
        assert_eq!(pairing_failed_reason_str(0x0b), "DHKey Check Failed");
        assert_eq!(pairing_failed_reason_str(0xFF), "Unknown");
    }
}
