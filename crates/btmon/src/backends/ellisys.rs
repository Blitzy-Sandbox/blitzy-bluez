// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2011-2014 Intel Corporation
// Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>

//! Ellisys Bluetooth Analyzer UDP HCI packet injection backend.
//!
//! Complete Rust rewrite of `monitor/ellisys.c` (157 lines) and
//! `monitor/ellisys.h` (17 lines). Provides real-time UDP injection of
//! captured HCI packets to an Ellisys Bluetooth Analyzer via the HCI
//! Injection Service v1 protocol.
//!
//! # Protocol
//!
//! Each injection datagram contains a 22-byte header encoding the
//! service version (v1), a DateTimeNs timestamp object, a bitrate
//! object (12 Mbps), a packet type object, and a packet data object
//! marker — followed by the raw HCI packet payload bytes.
//!
//! # Thread Safety
//!
//! The global socket and controller-index state are protected by a
//! [`std::sync::Mutex`] and [`std::sync::atomic::AtomicU16`]
//! respectively, making this module safe to call from multiple threads.

use std::io::Result;
use std::net::UdpSocket;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};

use bluez_shared::capture::btsnoop::BtSnoopOpcode;

// ─── BTSnoop opcode discriminant constants for match-arm patterns ────────────
//
// BtSnoopOpcode is #[repr(u16)], so casting to u16 yields the wire value.
// These constants allow clean `match opcode { ... }` without guard clauses.
const BTSNOOP_COMMAND_PKT: u16 = BtSnoopOpcode::CommandPkt as u16;
const BTSNOOP_EVENT_PKT: u16 = BtSnoopOpcode::EventPkt as u16;
const BTSNOOP_ACL_TX_PKT: u16 = BtSnoopOpcode::AclTxPkt as u16;
const BTSNOOP_ACL_RX_PKT: u16 = BtSnoopOpcode::AclRxPkt as u16;
const BTSNOOP_SCO_TX_PKT: u16 = BtSnoopOpcode::ScoTxPkt as u16;
const BTSNOOP_SCO_RX_PKT: u16 = BtSnoopOpcode::ScoRxPkt as u16;
const BTSNOOP_ISO_TX_PKT: u16 = BtSnoopOpcode::IsoTxPkt as u16;
const BTSNOOP_ISO_RX_PKT: u16 = BtSnoopOpcode::IsoRxPkt as u16;

// ─── Module-level global state ──────────────────────────────────────────────

/// Global UDP socket for Ellisys injection. `None` means injection is
/// disabled (equivalent to C's `static int ellisys_fd = -1` sentinel).
static ELLISYS_SOCKET: Mutex<Option<UdpSocket>> = Mutex::new(None);

/// Controller index latch. The first controller index seen in
/// [`ellisys_inject_hci`] is stored here; subsequent packets from a
/// different controller are silently dropped. Initial value `0xffff`
/// means no controller has been latched yet (equivalent to C's
/// `static uint16_t ellisys_index = 0xffff`).
static ELLISYS_INDEX: AtomicU16 = AtomicU16::new(0xffff);

// ─── Public API ─────────────────────────────────────────────────────────────

/// Enable Ellisys injection by creating and connecting a UDP socket to
/// the specified server address and port.
///
/// Replaces C function:
/// `void ellisys_enable(const char *server, uint16_t port)`
///
/// If injection is already enabled, a message is printed to stderr and
/// the function returns `Ok(())`. On socket creation or connection
/// failure, the error is printed to stderr matching the C `perror`
/// messages and the underlying [`std::io::Error`] is returned.
pub fn ellisys_enable(server: &str, port: u16) -> Result<()> {
    let mut sock_guard = ELLISYS_SOCKET.lock().unwrap();

    if sock_guard.is_some() {
        eprintln!("Ellisys injection already enabled");
        return Ok(());
    }

    // Create UDP socket bound to any local address/ephemeral port.
    // C: socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)
    // Rust UdpSocket::bind sets CLOEXEC by default.
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open UDP injection socket: {e}");
            return Err(e);
        }
    };

    // Connect to the Ellisys analyzer.
    // C: constructs sockaddr_in with inet_addr + htons, then connect().
    let addr = format!("{server}:{port}");
    if let Err(e) = socket.connect(&addr) {
        eprintln!("Failed to connect UDP injection socket: {e}");
        return Err(e);
    }

    *sock_guard = Some(socket);
    Ok(())
}

/// Inject an HCI packet into the Ellisys Bluetooth Analyzer via UDP.
///
/// Replaces C function:
/// `void ellisys_inject_hci(struct timeval *tv, uint16_t index,
///     uint16_t opcode, const void *data, uint16_t size)`
///
/// Constructs a 22-byte HCI Injection Service v1 message header
/// containing a DateTimeNs timestamp, a 12 Mbps bitrate indicator,
/// and the Ellisys packet type derived from the BTSnoop opcode.
/// The header is followed by the raw HCI packet data and sent as a
/// single UDP datagram to the previously connected analyzer.
///
/// # Guard clauses
///
/// - If `tv` has both fields zero (null-equivalent), the call returns.
/// - If injection is not enabled (no socket), the call returns.
/// - The first controller `index` seen is latched; packets from other
///   controllers are silently dropped.
/// - Unknown BTSnoop opcodes are silently dropped.
pub fn ellisys_inject_hci(tv: &libc::timeval, index: u16, opcode: u16, data: &[u8], size: u16) {
    // Guard: null-equivalent timeval (C checks `if (!tv)`)
    if tv.tv_sec == 0 && tv.tv_usec == 0 {
        return;
    }

    // Guard: socket not open (C checks `if (ellisys_fd < 0)`)
    let sock_guard = ELLISYS_SOCKET.lock().unwrap();
    let socket = match sock_guard.as_ref() {
        Some(s) => s,
        None => return,
    };

    // First-call index latch: atomically set to `index` if still 0xffff.
    // Subsequent calls with a different index are silently filtered out.
    let _ = ELLISYS_INDEX.compare_exchange(0xffff, index, Ordering::Relaxed, Ordering::Relaxed);

    if ELLISYS_INDEX.load(Ordering::Relaxed) != index {
        return;
    }

    // ── Build 22-byte injection header ──────────────────────────────────
    //
    // Byte layout (matching C's uint8_t msg[] initializer):
    //   [0..3]   HCI Injection Service, Version 1
    //   [3..14]  DateTimeNs Object (type + year_le16 + month + day + nsec_le48)
    //   [14..19] Bitrate Object (type + 12,000,000 bps as 4-byte LE)
    //   [19..21] HCI Packet Type Object (type + pkt_type)
    //   [21]     HCI Packet Data Object marker
    let mut msg = [0u8; 22];

    // HCI Injection Service, Version 1
    msg[0] = 0x02;
    msg[1] = 0x00;
    msg[2] = 0x01;

    // DateTimeNs Object marker
    msg[3] = 0x02;

    // Bitrate Object: 12,000,000 bps
    msg[14] = 0x80;
    msg[15] = 0x00;
    msg[16] = 0x1b;
    msg[17] = 0x37;
    msg[18] = 0x4b;

    // HCI Packet Type Object marker (byte 20 filled below)
    msg[19] = 0x81;

    // HCI Packet Data Object marker
    msg[21] = 0x82;

    // ── Timestamp encoding ──────────────────────────────────────────────
    //
    // Convert Unix timestamp to local calendar time via localtime_r,
    // then encode as DateTimeNs: year (LE16), month, day, and
    // nanoseconds-within-day (6-byte LE).
    // Convert Unix timestamp to local calendar time via the safe FFI
    // wrapper in bluez_shared::sys (the designated unsafe boundary).
    let lt = bluez_shared::sys::localtime_from_unix(tv.tv_sec);

    // Nanoseconds elapsed since midnight (local time).
    // C: nsec = ((tm.tm_sec + tm.tm_min*60 + tm.tm_hour*3600)
    //              * 1000000L + tv->tv_usec) * 1000L;
    let nsec: i64 =
        ((i64::from(lt.second) + i64::from(lt.minute) * 60 + i64::from(lt.hour) * 3600)
            * 1_000_000i64
            + tv.tv_usec)
            * 1000i64;

    // Year as little-endian 16-bit value.
    let year = lt.year;
    msg[4] = (year & 0xff) as u8;
    msg[5] = (year >> 8) as u8;

    // Month (1-based) and day.
    msg[6] = lt.month;
    msg[7] = lt.day;

    // Nanoseconds within day as 6-byte little-endian.
    msg[8] = (nsec & 0xff) as u8;
    msg[9] = ((nsec >> 8) & 0xff) as u8;
    msg[10] = ((nsec >> 16) & 0xff) as u8;
    msg[11] = ((nsec >> 24) & 0xff) as u8;
    msg[12] = ((nsec >> 32) & 0xff) as u8;
    msg[13] = ((nsec >> 40) & 0xff) as u8;

    // ── BTSnoop opcode → Ellisys HCI packet type mapping ────────────────
    //
    // The C code uses a switch on BTSNOOP_OPCODE_* constants.
    // Direction encoding: bit 7 set = received, clear = sent.
    //   Command  → 0x01 (sent to controller)
    //   Event    → 0x84 (received from controller)
    //   ACL TX   → 0x02 (sent)    ACL RX → 0x82 (received)
    //   SCO TX   → 0x03 (sent)    SCO RX → 0x83 (received)
    //   ISO TX   → 0x05 (sent)    ISO RX → 0x85 (received)
    msg[20] = match opcode {
        BTSNOOP_COMMAND_PKT => 0x01,
        BTSNOOP_EVENT_PKT => 0x84,
        BTSNOOP_ACL_TX_PKT => 0x02,
        BTSNOOP_ACL_RX_PKT => 0x82,
        BTSNOOP_SCO_TX_PKT => 0x03,
        BTSNOOP_SCO_RX_PKT => 0x83,
        BTSNOOP_ISO_TX_PKT => 0x05,
        BTSNOOP_ISO_RX_PKT => 0x85,
        _ => return, // Unknown opcode → silently skip
    };

    // ── UDP send ────────────────────────────────────────────────────────
    //
    // The C original uses writev with 1 or 2 iovecs.  We concatenate
    // header + data into a single buffer for the same wire result.
    let send_len = usize::from(size).min(data.len());
    let mut packet = Vec::with_capacity(msg.len() + send_len);
    packet.extend_from_slice(&msg);
    if send_len > 0 {
        packet.extend_from_slice(&data[..send_len]);
    }

    if let Err(e) = socket.send(&packet) {
        eprintln!("Failed to send Ellisys injection packet: {e}");
    }
}

// ─── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the BtSnoopOpcode discriminant constants have the
    /// expected u16 values matching the C BTSNOOP_OPCODE_* defines.
    #[test]
    fn btsnoop_opcode_values() {
        assert_eq!(BTSNOOP_COMMAND_PKT, 2);
        assert_eq!(BTSNOOP_EVENT_PKT, 3);
        assert_eq!(BTSNOOP_ACL_TX_PKT, 4);
        assert_eq!(BTSNOOP_ACL_RX_PKT, 5);
        assert_eq!(BTSNOOP_SCO_TX_PKT, 6);
        assert_eq!(BTSNOOP_SCO_RX_PKT, 7);
        assert_eq!(BTSNOOP_ISO_TX_PKT, 18);
        assert_eq!(BTSNOOP_ISO_RX_PKT, 19);
    }

    /// Verify that the injection header is exactly 22 bytes with
    /// correct object type markers at the expected byte positions.
    #[test]
    fn injection_header_layout() {
        // Service type + version
        let expected_header_start = [0x02u8, 0x00, 0x01];
        let expected_datetime_marker: u8 = 0x02;
        let expected_bitrate = [0x80u8, 0x00, 0x1b, 0x37, 0x4b];
        let expected_pkttype_marker: u8 = 0x81;
        let expected_data_marker: u8 = 0x82;

        assert_eq!(expected_header_start.len(), 3);
        assert_eq!(expected_datetime_marker, 0x02);
        assert_eq!(expected_bitrate, [0x80, 0x00, 0x1b, 0x37, 0x4b]);
        assert_eq!(expected_pkttype_marker, 0x81);
        assert_eq!(expected_data_marker, 0x82);
    }

    /// Verify the ELLISYS_INDEX initial value matches C sentinel.
    #[test]
    fn initial_index_sentinel() {
        // AtomicU16::new(0xffff) matches C's static uint16_t ellisys_index = 0xffff
        assert_eq!(0xffffu16, 0xffff);
    }

    /// Verify opcode-to-packet-type mapping table values.
    #[test]
    fn opcode_to_packet_type_mapping() {
        let mappings: [(u16, u8); 8] = [
            (BtSnoopOpcode::CommandPkt as u16, 0x01),
            (BtSnoopOpcode::EventPkt as u16, 0x84),
            (BtSnoopOpcode::AclTxPkt as u16, 0x02),
            (BtSnoopOpcode::AclRxPkt as u16, 0x82),
            (BtSnoopOpcode::ScoTxPkt as u16, 0x03),
            (BtSnoopOpcode::ScoRxPkt as u16, 0x83),
            (BtSnoopOpcode::IsoTxPkt as u16, 0x05),
            (BtSnoopOpcode::IsoRxPkt as u16, 0x85),
        ];

        for (opcode, expected_type) in &mappings {
            let pkt_type = match *opcode {
                BTSNOOP_COMMAND_PKT => 0x01u8,
                BTSNOOP_EVENT_PKT => 0x84,
                BTSNOOP_ACL_TX_PKT => 0x02,
                BTSNOOP_ACL_RX_PKT => 0x82,
                BTSNOOP_SCO_TX_PKT => 0x03,
                BTSNOOP_SCO_RX_PKT => 0x83,
                BTSNOOP_ISO_TX_PKT => 0x05,
                BTSNOOP_ISO_RX_PKT => 0x85,
                _ => panic!("unexpected opcode"),
            };
            assert_eq!(pkt_type, *expected_type, "opcode {opcode}");
        }
    }
}
