// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2015  Andrzej Kaczmarek <andrzej.kaczmarek@codecoup.pl>
//
// avdtp.rs — AVDTP signaling dissector.
//
// Complete Rust rewrite of monitor/avdtp.c (772 lines) + monitor/avdtp.h.
// Decodes AVDTP signaling messages (Discover, Get Capabilities,
// Set Configuration, Open, Start, Close, Suspend, Abort,
// Security Control, Get All Capabilities, Delay Report).
// Parses service capability elements (Media Transport, Reporting,
// Recovery, Content Protection, Header Compression, Multiplexing,
// Media Codec, Delay Reporting). Invokes A2DP codec decoders for
// media codec capabilities via `super::a2dp`.

use super::l2cap::L2capFrame;
use crate::packet;
use crate::{print_field, print_indent, print_text};

// ============================================================================
// Constants — Message Types (avdtp.c lines 31-34)
// ============================================================================

const AVDTP_MSG_TYPE_COMMAND: u8 = 0x00;
// General Reject (0x01) is protocol-defined but implicitly handled by default
// arms in signal-specific handlers, matching the C behavior.
const AVDTP_MSG_TYPE_RESPONSE_ACCEPT: u8 = 0x02;
const AVDTP_MSG_TYPE_RESPONSE_REJECT: u8 = 0x03;

// ============================================================================
// Constants — Signal Identifiers (avdtp.c lines 37-49)
// ============================================================================

const AVDTP_DISCOVER: u8 = 0x01;
const AVDTP_GET_CAPABILITIES: u8 = 0x02;
const AVDTP_SET_CONFIGURATION: u8 = 0x03;
const AVDTP_GET_CONFIGURATION: u8 = 0x04;
const AVDTP_RECONFIGURE: u8 = 0x05;
const AVDTP_OPEN: u8 = 0x06;
const AVDTP_START: u8 = 0x07;
const AVDTP_CLOSE: u8 = 0x08;
const AVDTP_SUSPEND: u8 = 0x09;
const AVDTP_ABORT: u8 = 0x0a;
const AVDTP_SECURITY_CONTROL: u8 = 0x0b;
const AVDTP_GET_ALL_CAPABILITIES: u8 = 0x0c;
const AVDTP_DELAYREPORT: u8 = 0x0d;

// ============================================================================
// Constants — Service Categories (avdtp.c lines 52-59)
// ============================================================================

const AVDTP_MEDIA_TRANSPORT: u8 = 0x01;
const AVDTP_REPORTING: u8 = 0x02;
const AVDTP_RECOVERY: u8 = 0x03;
const AVDTP_CONTENT_PROTECTION: u8 = 0x04;
const AVDTP_HEADER_COMPRESSION: u8 = 0x05;
const AVDTP_MULTIPLEXING: u8 = 0x06;
const AVDTP_MEDIA_CODEC: u8 = 0x07;
const AVDTP_DELAY_REPORTING: u8 = 0x08;

// ============================================================================
// AVDTP Frame — Internal wrapper (avdtp.c lines 61-65)
// ============================================================================

/// Internal frame wrapper that carries AVDTP header state alongside the
/// L2CAP frame cursor.
struct AvdtpFrame {
    /// Raw AVDTP header byte (msg type, packet type, transaction label).
    hdr: u8,
    /// Currently parsed signal identifier.
    sig_id: u8,
    /// Underlying L2CAP frame cursor for safe byte consumption.
    l2cap_frame: L2capFrame,
}

// ============================================================================
// Helper: configuration signal ID check (avdtp.c lines 67-72)
// ============================================================================

/// Returns true if `sig_id` is a configuration-related signal identifier.
/// Used to select between a2dp_codec_cfg (configuration) and a2dp_codec_cap
/// (capability) decoding.
fn is_configuration_sig_id(sig_id: u8) -> bool {
    sig_id == AVDTP_SET_CONFIGURATION
        || sig_id == AVDTP_GET_CONFIGURATION
        || sig_id == AVDTP_RECONFIGURE
}

// ============================================================================
// String Lookups (avdtp.c lines 74-232)
// ============================================================================

/// Map message type value to human-readable string.
fn msgtype2str(msgtype: u8) -> &'static str {
    match msgtype {
        0 => "Command",
        1 => "General Reject",
        2 => "Response Accept",
        3 => "Response Reject",
        _ => "",
    }
}

/// Map signal identifier to human-readable string.
fn sigid2str(sigid: u8) -> &'static str {
    match sigid {
        AVDTP_DISCOVER => "Discover",
        AVDTP_GET_CAPABILITIES => "Get Capabilities",
        AVDTP_SET_CONFIGURATION => "Set Configuration",
        AVDTP_GET_CONFIGURATION => "Get Configuration",
        AVDTP_RECONFIGURE => "Reconfigure",
        AVDTP_OPEN => "Open",
        AVDTP_START => "Start",
        AVDTP_CLOSE => "Close",
        AVDTP_SUSPEND => "Suspend",
        AVDTP_ABORT => "Abort",
        AVDTP_SECURITY_CONTROL => "Security Control",
        AVDTP_GET_ALL_CAPABILITIES => "Get All Capabilities",
        AVDTP_DELAYREPORT => "Delay Report",
        _ => "Reserved",
    }
}

/// Map AVDTP error code to human-readable string.
fn error2str(error: u8) -> &'static str {
    match error {
        0x01 => "BAD_HEADER_FORMAT",
        0x11 => "BAD_LENGTH",
        0x12 => "BAD_ACP_SEID",
        0x13 => "SEP_IN_USE",
        0x14 => "SEP_NOT_IN_USER",
        0x17 => "BAD_SERV_CATEGORY",
        0x18 => "BAD_PAYLOAD_FORMAT",
        0x19 => "NOT_SUPPORTED_COMMAND",
        0x1a => "INVALID_CAPABILITIES",
        0x22 => "BAD_RECOVERY_TYPE",
        0x23 => "BAD_MEDIA_TRANSPORT_FORMAT",
        0x25 => "BAD_RECOVERY_FORMAT",
        0x26 => "BAD_ROHC_FORMAT",
        0x27 => "BAD_CP_FORMAT",
        0x28 => "BAD_MULTIPLEXING_FORMAT",
        0x29 => "UNSUPPORTED_CONFIGURATION",
        0x31 => "BAD_STATE",
        _ => "Unknown",
    }
}

/// Map media type value to human-readable string.
fn mediatype2str(media_type: u8) -> &'static str {
    match media_type {
        0x00 => "Audio",
        0x01 => "Video",
        0x02 => "Multimedia",
        _ => "Reserved",
    }
}

/// Map media codec value to human-readable string.
fn mediacodec2str(codec: u8) -> &'static str {
    match codec {
        0x00 => "SBC",
        0x01 => "MPEG-1,2 Audio",
        0x02 => "MPEG-2,4 AAC",
        0x04 => "ATRAC Family",
        0xff => "Non-A2DP",
        _ => "Reserved",
    }
}

/// Map content protection type to human-readable string.
fn cptype2str(cp: u16) -> &'static str {
    match cp {
        0x0001 => "DTCP",
        0x0002 => "SCMS-T",
        _ => "Reserved",
    }
}

/// Map service category to human-readable string.
fn servicecat2str(service_cat: u8) -> &'static str {
    match service_cat {
        AVDTP_MEDIA_TRANSPORT => "Media Transport",
        AVDTP_REPORTING => "Reporting",
        AVDTP_RECOVERY => "Recovery",
        AVDTP_CONTENT_PROTECTION => "Content Protection",
        AVDTP_HEADER_COMPRESSION => "Header Compression",
        AVDTP_MULTIPLEXING => "Multiplexing",
        AVDTP_MEDIA_CODEC => "Media Codec",
        AVDTP_DELAY_REPORTING => "Delay Reporting",
        _ => "Reserved",
    }
}

// ============================================================================
// Service Capability Decoders (avdtp.c lines 234-337)
// ============================================================================

/// Parse and print a common error code for reject responses.
fn avdtp_reject_common(avdtp_frame: &mut AvdtpFrame) -> bool {
    let frame = &mut avdtp_frame.l2cap_frame;
    let Some(error) = frame.get_u8() else {
        return false;
    };

    print_field!("Error code: {} (0x{:02x})", error2str(error), error);

    true
}

/// Parse and print a Content Protection service capability.
fn service_content_protection(avdtp_frame: &mut AvdtpFrame, mut losc: u8) -> bool {
    let frame = &mut avdtp_frame.l2cap_frame;

    if losc < 2 {
        return false;
    }

    let Some(cp_type) = frame.get_le16() else {
        return false;
    };

    losc -= 2;

    print_field!(
        "{:>width$}Content Protection Type: {} (0x{:04x})",
        ' ',
        cptype2str(cp_type),
        cp_type,
        width = 2
    );

    // Hexdump protection-specific information if present.
    if losc > 0 {
        packet::hexdump(&frame.remaining_data()[..losc as usize]);
        frame.pull(losc as usize);
    }

    true
}

/// Parse and print a Media Codec service capability.
fn service_media_codec(avdtp_frame: &mut AvdtpFrame, mut losc: u8) -> bool {
    let frame = &mut avdtp_frame.l2cap_frame;

    if losc < 2 {
        return false;
    }

    let Some(media_type_raw) = frame.get_u8() else {
        return false;
    };
    let Some(codec) = frame.get_u8() else {
        return false;
    };

    losc -= 2;

    let media_type = media_type_raw >> 4;

    print_field!(
        "{:>width$}Media Type: {} (0x{:02x})",
        ' ',
        mediatype2str(media_type),
        media_type,
        width = 2
    );

    print_field!(
        "{:>width$}Media Codec: {} (0x{:02x})",
        ' ',
        mediacodec2str(codec),
        codec,
        width = 2
    );

    if is_configuration_sig_id(avdtp_frame.sig_id) {
        super::a2dp::a2dp_codec_cfg(codec, losc, &mut avdtp_frame.l2cap_frame)
    } else {
        super::a2dp::a2dp_codec_cap(codec, losc, &mut avdtp_frame.l2cap_frame)
    }
}

/// Decode a sequence of service capabilities (Category + LOSC + data).
fn decode_capabilities(avdtp_frame: &mut AvdtpFrame) -> bool {
    loop {
        let frame = &mut avdtp_frame.l2cap_frame;
        let Some(service_cat) = frame.get_u8() else {
            break;
        };

        print_field!("Service Category: {} (0x{:02x})", servicecat2str(service_cat), service_cat);

        let Some(losc) = avdtp_frame.l2cap_frame.get_u8() else {
            return false;
        };

        if (avdtp_frame.l2cap_frame.size as u8) < losc {
            return false;
        }

        match service_cat {
            AVDTP_CONTENT_PROTECTION => {
                if !service_content_protection(avdtp_frame, losc) {
                    return false;
                }
            }
            AVDTP_MEDIA_CODEC => {
                if !service_media_codec(avdtp_frame, losc) {
                    return false;
                }
            }
            AVDTP_MEDIA_TRANSPORT
            | AVDTP_REPORTING
            | AVDTP_RECOVERY
            | AVDTP_HEADER_COMPRESSION
            | AVDTP_MULTIPLEXING
            | AVDTP_DELAY_REPORTING => {
                if losc > 0 {
                    packet::hexdump(&avdtp_frame.l2cap_frame.remaining_data()[..losc as usize]);
                    avdtp_frame.l2cap_frame.pull(losc as usize);
                }
            }
            _ => {
                if losc > 0 {
                    packet::hexdump(&avdtp_frame.l2cap_frame.remaining_data()[..losc as usize]);
                    avdtp_frame.l2cap_frame.pull(losc as usize);
                }
            }
        }
    }

    true
}

// ============================================================================
// Signal ID Handlers (avdtp.c lines 339-666)
// ============================================================================

/// Discover — command has no payload, accept lists SEIDs, reject is common.
fn avdtp_discover(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => true,
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => {
            let frame = &mut avdtp_frame.l2cap_frame;
            while let Some(seid) = frame.get_u8() {
                print_field!("ACP SEID: {}", seid >> 2);

                let Some(info) = frame.get_u8() else {
                    return false;
                };

                print_field!(
                    "{:>width$}Media Type: {} (0x{:02x})",
                    ' ',
                    mediatype2str(info >> 4),
                    info >> 4,
                    width = 2
                );
                print_field!(
                    "{:>width$}SEP Type: {} (0x{:02x})",
                    ' ',
                    if info & 0x08 != 0 { "SNK" } else { "SRC" },
                    (info >> 3) & 0x01,
                    width = 2
                );
                print_field!(
                    "{:>width$}In use: {}",
                    ' ',
                    if seid & 0x02 != 0 { "Yes" } else { "No" },
                    width = 2
                );
            }
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_REJECT => avdtp_reject_common(avdtp_frame),
        _ => false,
    }
}

/// Get Capabilities / Get All Capabilities.
fn avdtp_get_capabilities(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => decode_capabilities(avdtp_frame),
        AVDTP_MSG_TYPE_RESPONSE_REJECT => avdtp_reject_common(avdtp_frame),
        _ => false,
    }
}

/// Set Configuration.
fn avdtp_set_configuration(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(acp_seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", acp_seid >> 2);

            let Some(int_seid) = frame.get_u8() else {
                return false;
            };
            print_field!("INT SEID: {}", int_seid >> 2);

            decode_capabilities(avdtp_frame)
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        AVDTP_MSG_TYPE_RESPONSE_REJECT => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(service_cat) = frame.get_u8() else {
                return false;
            };
            print_field!(
                "Service Category: {} (0x{:02x})",
                servicecat2str(service_cat),
                service_cat
            );
            avdtp_reject_common(avdtp_frame)
        }
        _ => false,
    }
}

/// Get Configuration.
fn avdtp_get_configuration(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => decode_capabilities(avdtp_frame),
        AVDTP_MSG_TYPE_RESPONSE_REJECT => avdtp_reject_common(avdtp_frame),
        _ => false,
    }
}

/// Reconfigure.
fn avdtp_reconfigure(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            decode_capabilities(avdtp_frame)
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        AVDTP_MSG_TYPE_RESPONSE_REJECT => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(service_cat) = frame.get_u8() else {
                return false;
            };
            print_field!(
                "Service Category: {} (0x{:02x})",
                servicecat2str(service_cat),
                service_cat
            );
            avdtp_reject_common(avdtp_frame)
        }
        _ => false,
    }
}

/// Open — SEID on command, empty on accept, reject common.
fn avdtp_open(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        AVDTP_MSG_TYPE_RESPONSE_REJECT => avdtp_reject_common(avdtp_frame),
        _ => false,
    }
}

/// Start — first SEID + remaining SEIDs on command, empty accept, SEID + error on reject.
fn avdtp_start(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);

            while let Some(seid) = frame.get_u8() {
                print_field!("ACP SEID: {}", seid >> 2);
            }
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        AVDTP_MSG_TYPE_RESPONSE_REJECT => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            avdtp_reject_common(avdtp_frame)
        }
        _ => false,
    }
}

/// Close — same structure as Open.
fn avdtp_close(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        AVDTP_MSG_TYPE_RESPONSE_REJECT => avdtp_reject_common(avdtp_frame),
        _ => false,
    }
}

/// Suspend — same structure as Start.
fn avdtp_suspend(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);

            while let Some(seid) = frame.get_u8() {
                print_field!("ACP SEID: {}", seid >> 2);
            }
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        AVDTP_MSG_TYPE_RESPONSE_REJECT => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            avdtp_reject_common(avdtp_frame)
        }
        _ => false,
    }
}

/// Abort — SEID on command, empty on accept (no reject case).
fn avdtp_abort(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        _ => false,
    }
}

/// Security Control — SEID + data on command, data on accept, reject common.
fn avdtp_security_control(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);
            packet::hexdump(frame.remaining_data());
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => {
            let frame = &mut avdtp_frame.l2cap_frame;
            packet::hexdump(frame.remaining_data());
            true
        }
        AVDTP_MSG_TYPE_RESPONSE_REJECT => avdtp_reject_common(avdtp_frame),
        _ => false,
    }
}

/// Delay Report — SEID + delay on command, empty accept, reject common.
fn avdtp_delayreport(avdtp_frame: &mut AvdtpFrame) -> bool {
    let msg_type = avdtp_frame.hdr & 0x03;

    match msg_type {
        AVDTP_MSG_TYPE_COMMAND => {
            let frame = &mut avdtp_frame.l2cap_frame;
            let Some(seid) = frame.get_u8() else {
                return false;
            };
            print_field!("ACP SEID: {}", seid >> 2);

            let Some(delay) = frame.get_be16() else {
                return false;
            };
            print_field!("Delay: {}.{}ms", delay / 10, delay % 10);

            true
        }
        AVDTP_MSG_TYPE_RESPONSE_ACCEPT => true,
        AVDTP_MSG_TYPE_RESPONSE_REJECT => avdtp_reject_common(avdtp_frame),
        _ => false,
    }
}

// ============================================================================
// Signaling Packet Parser (avdtp.c lines 668-749)
// ============================================================================

/// Parse an AVDTP signaling packet from the L2CAP frame.
fn avdtp_signalling_packet(avdtp_frame: &mut AvdtpFrame) -> bool {
    let frame = &mut avdtp_frame.l2cap_frame;

    let pdu_color =
        if frame.in_ { crate::display::COLOR_MAGENTA } else { crate::display::COLOR_BLUE };

    let Some(hdr) = frame.get_u8() else {
        return false;
    };

    avdtp_frame.hdr = hdr;

    // Continue Packet (0x08) or End Packet (0x0c) — fragmented.
    if (hdr & 0x0c) == 0x08 || (hdr & 0x0c) == 0x0c {
        // Fragmentation reassembly not supported — hexdump only (mirrors C behavior).
        packet::hexdump(avdtp_frame.l2cap_frame.remaining_data());
        return true;
    }

    // Start Packet (0x04) — read NOSP byte.
    let mut nosp: u8 = 0;
    if (hdr & 0x0c) == 0x04 {
        let Some(n) = avdtp_frame.l2cap_frame.get_u8() else {
            return false;
        };
        nosp = n;
    }

    let Some(raw_sig_id) = avdtp_frame.l2cap_frame.get_u8() else {
        return false;
    };

    let sig_id = raw_sig_id & 0x3f;
    avdtp_frame.sig_id = sig_id;

    print_indent!(
        6,
        pdu_color,
        "AVDTP: ",
        sigid2str(sig_id),
        crate::display::COLOR_OFF,
        " (0x{:02x}) {} (0x{:02x}) type 0x{:02x} label {} nosp {}",
        sig_id,
        msgtype2str(hdr & 0x03),
        hdr & 0x03,
        hdr & 0x0c,
        hdr >> 4,
        nosp
    );

    // Start Packet: fragmentation not fully handled.
    if (hdr & 0x0c) == 0x04 {
        packet::hexdump(avdtp_frame.l2cap_frame.remaining_data());
        return true;
    }

    match sig_id {
        AVDTP_DISCOVER => avdtp_discover(avdtp_frame),
        AVDTP_GET_CAPABILITIES | AVDTP_GET_ALL_CAPABILITIES => avdtp_get_capabilities(avdtp_frame),
        AVDTP_SET_CONFIGURATION => avdtp_set_configuration(avdtp_frame),
        AVDTP_GET_CONFIGURATION => avdtp_get_configuration(avdtp_frame),
        AVDTP_RECONFIGURE => avdtp_reconfigure(avdtp_frame),
        AVDTP_OPEN => avdtp_open(avdtp_frame),
        AVDTP_START => avdtp_start(avdtp_frame),
        AVDTP_CLOSE => avdtp_close(avdtp_frame),
        AVDTP_SUSPEND => avdtp_suspend(avdtp_frame),
        AVDTP_ABORT => avdtp_abort(avdtp_frame),
        AVDTP_SECURITY_CONTROL => avdtp_security_control(avdtp_frame),
        AVDTP_DELAYREPORT => avdtp_delayreport(avdtp_frame),
        _ => {
            packet::hexdump(avdtp_frame.l2cap_frame.remaining_data());
            true
        }
    }
}

// ============================================================================
// Public API (avdtp.c lines 751-772, avdtp.h)
// ============================================================================

/// Decode an AVDTP packet from an L2CAP frame.
///
/// If `seq_num == 1` the frame is a signaling packet; otherwise it is a media
/// stream packet (hexdumped only when the A2DP_STREAM filter is active).
pub fn avdtp_packet(frame: &L2capFrame) {
    let mut avdtp_frame = AvdtpFrame { hdr: 0, sig_id: 0, l2cap_frame: frame.clone() };

    match frame.seq_num {
        1 => {
            let ret = avdtp_signalling_packet(&mut avdtp_frame);
            if !ret {
                print_text!(crate::display::COLOR_ERROR, "PDU malformed");
                packet::hexdump(frame.remaining_data());
            }
        }
        _ => {
            if packet::has_filter(packet::PacketFilter::SHOW_A2DP_STREAM) {
                packet::hexdump(frame.remaining_data());
            }
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msgtype2str() {
        assert_eq!(msgtype2str(0), "Command");
        assert_eq!(msgtype2str(1), "General Reject");
        assert_eq!(msgtype2str(2), "Response Accept");
        assert_eq!(msgtype2str(3), "Response Reject");
        assert_eq!(msgtype2str(4), "");
    }

    #[test]
    fn test_sigid2str() {
        assert_eq!(sigid2str(AVDTP_DISCOVER), "Discover");
        assert_eq!(sigid2str(AVDTP_GET_CAPABILITIES), "Get Capabilities");
        assert_eq!(sigid2str(AVDTP_SET_CONFIGURATION), "Set Configuration");
        assert_eq!(sigid2str(AVDTP_GET_CONFIGURATION), "Get Configuration");
        assert_eq!(sigid2str(AVDTP_RECONFIGURE), "Reconfigure");
        assert_eq!(sigid2str(AVDTP_OPEN), "Open");
        assert_eq!(sigid2str(AVDTP_START), "Start");
        assert_eq!(sigid2str(AVDTP_CLOSE), "Close");
        assert_eq!(sigid2str(AVDTP_SUSPEND), "Suspend");
        assert_eq!(sigid2str(AVDTP_ABORT), "Abort");
        assert_eq!(sigid2str(AVDTP_SECURITY_CONTROL), "Security Control");
        assert_eq!(sigid2str(AVDTP_GET_ALL_CAPABILITIES), "Get All Capabilities");
        assert_eq!(sigid2str(AVDTP_DELAYREPORT), "Delay Report");
        assert_eq!(sigid2str(0x00), "Reserved");
        assert_eq!(sigid2str(0xff), "Reserved");
    }

    #[test]
    fn test_error2str() {
        assert_eq!(error2str(0x01), "BAD_HEADER_FORMAT");
        assert_eq!(error2str(0x11), "BAD_LENGTH");
        assert_eq!(error2str(0x12), "BAD_ACP_SEID");
        assert_eq!(error2str(0x13), "SEP_IN_USE");
        assert_eq!(error2str(0x14), "SEP_NOT_IN_USER");
        assert_eq!(error2str(0x17), "BAD_SERV_CATEGORY");
        assert_eq!(error2str(0x18), "BAD_PAYLOAD_FORMAT");
        assert_eq!(error2str(0x19), "NOT_SUPPORTED_COMMAND");
        assert_eq!(error2str(0x1a), "INVALID_CAPABILITIES");
        assert_eq!(error2str(0x22), "BAD_RECOVERY_TYPE");
        assert_eq!(error2str(0x23), "BAD_MEDIA_TRANSPORT_FORMAT");
        assert_eq!(error2str(0x25), "BAD_RECOVERY_FORMAT");
        assert_eq!(error2str(0x26), "BAD_ROHC_FORMAT");
        assert_eq!(error2str(0x27), "BAD_CP_FORMAT");
        assert_eq!(error2str(0x28), "BAD_MULTIPLEXING_FORMAT");
        assert_eq!(error2str(0x29), "UNSUPPORTED_CONFIGURATION");
        assert_eq!(error2str(0x31), "BAD_STATE");
        assert_eq!(error2str(0x00), "Unknown");
    }

    #[test]
    fn test_mediatype2str() {
        assert_eq!(mediatype2str(0x00), "Audio");
        assert_eq!(mediatype2str(0x01), "Video");
        assert_eq!(mediatype2str(0x02), "Multimedia");
        assert_eq!(mediatype2str(0x03), "Reserved");
    }

    #[test]
    fn test_mediacodec2str() {
        assert_eq!(mediacodec2str(0x00), "SBC");
        assert_eq!(mediacodec2str(0x01), "MPEG-1,2 Audio");
        assert_eq!(mediacodec2str(0x02), "MPEG-2,4 AAC");
        assert_eq!(mediacodec2str(0x04), "ATRAC Family");
        assert_eq!(mediacodec2str(0xff), "Non-A2DP");
        assert_eq!(mediacodec2str(0x03), "Reserved");
    }

    #[test]
    fn test_cptype2str() {
        assert_eq!(cptype2str(0x0001), "DTCP");
        assert_eq!(cptype2str(0x0002), "SCMS-T");
        assert_eq!(cptype2str(0x0003), "Reserved");
    }

    #[test]
    fn test_servicecat2str() {
        assert_eq!(servicecat2str(AVDTP_MEDIA_TRANSPORT), "Media Transport");
        assert_eq!(servicecat2str(AVDTP_REPORTING), "Reporting");
        assert_eq!(servicecat2str(AVDTP_RECOVERY), "Recovery");
        assert_eq!(servicecat2str(AVDTP_CONTENT_PROTECTION), "Content Protection");
        assert_eq!(servicecat2str(AVDTP_HEADER_COMPRESSION), "Header Compression");
        assert_eq!(servicecat2str(AVDTP_MULTIPLEXING), "Multiplexing");
        assert_eq!(servicecat2str(AVDTP_MEDIA_CODEC), "Media Codec");
        assert_eq!(servicecat2str(AVDTP_DELAY_REPORTING), "Delay Reporting");
        assert_eq!(servicecat2str(0x00), "Reserved");
    }

    #[test]
    fn test_is_configuration_sig_id() {
        assert!(is_configuration_sig_id(AVDTP_SET_CONFIGURATION));
        assert!(is_configuration_sig_id(AVDTP_GET_CONFIGURATION));
        assert!(is_configuration_sig_id(AVDTP_RECONFIGURE));
        assert!(!is_configuration_sig_id(AVDTP_DISCOVER));
        assert!(!is_configuration_sig_id(AVDTP_OPEN));
        assert!(!is_configuration_sig_id(AVDTP_GET_CAPABILITIES));
    }

    #[test]
    fn test_avdtp_discover_command() {
        // Discover command: hdr=0x00 (command, single, label 0), sig_id=0x01
        let data = vec![0x00, 0x01];
        let l2cap_frame = L2capFrame::new(data.clone(), data.len() as u16);
        let mut af = AvdtpFrame { hdr: 0, sig_id: 0, l2cap_frame };
        // Parse signalling packet — should succeed
        let result = avdtp_signalling_packet(&mut af);
        assert!(result);
    }

    #[test]
    fn test_avdtp_discover_accept() {
        // Discover accept: hdr=0x02 (response accept, single, label 0), sig_id=0x01
        // Then 2 bytes per SEP entry: seid=0x04 (SEID 1), info=0x08 (Audio, SNK)
        let data = vec![0x02, 0x01, 0x04, 0x08];
        let l2cap_frame = L2capFrame::new(data.clone(), data.len() as u16);
        let mut af = AvdtpFrame { hdr: 0, sig_id: 0, l2cap_frame };
        let result = avdtp_signalling_packet(&mut af);
        assert!(result);
    }

    #[test]
    fn test_avdtp_delayreport_command() {
        // Delay Report command: hdr=0x00, sig_id=0x0d, SEID=0x04, delay=0x0064 (10.0ms)
        let data = vec![0x00, 0x0d, 0x04, 0x00, 0x64];
        let l2cap_frame = L2capFrame::new(data.clone(), data.len() as u16);
        let mut af = AvdtpFrame { hdr: 0, sig_id: 0, l2cap_frame };
        let result = avdtp_signalling_packet(&mut af);
        assert!(result);
    }

    #[test]
    fn test_avdtp_packet_media_stream_no_filter() {
        // seq_num != 1 means media stream; without filter set, should be silent.
        let data = vec![0x80, 0x60, 0x01, 0x02];
        let mut l2cap_frame = L2capFrame::new(data.clone(), data.len() as u16);
        l2cap_frame.seq_num = 2;
        avdtp_packet(&l2cap_frame);
    }

    #[test]
    fn test_avdtp_abort_command() {
        // Abort command: hdr=0x00, sig_id=0x0a, SEID=0x04
        let data = vec![0x00, 0x0a, 0x04];
        let l2cap_frame = L2capFrame::new(data.clone(), data.len() as u16);
        let mut af = AvdtpFrame { hdr: 0, sig_id: 0, l2cap_frame };
        let result = avdtp_signalling_packet(&mut af);
        assert!(result);
    }

    #[test]
    fn test_avdtp_abort_accept() {
        // Abort accept: hdr=0x02, sig_id=0x0a
        let data = vec![0x02, 0x0a];
        let l2cap_frame = L2capFrame::new(data.clone(), data.len() as u16);
        let mut af = AvdtpFrame { hdr: 0, sig_id: 0, l2cap_frame };
        let result = avdtp_signalling_packet(&mut af);
        assert!(result);
    }

    #[test]
    fn test_avdtp_continuation_packet() {
        // Continuation packet: packet type 0x08
        let data = vec![0x08, 0x01, 0x02, 0x03];
        let l2cap_frame = L2capFrame::new(data.clone(), data.len() as u16);
        let mut af = AvdtpFrame { hdr: 0, sig_id: 0, l2cap_frame };
        let result = avdtp_signalling_packet(&mut af);
        assert!(result);
    }
}
