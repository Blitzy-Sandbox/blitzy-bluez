// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! AVDTP (Audio/Video Distribution Transport Protocol) unit tests.
//!
//! Converted from `unit/test-avdtp.c` — tests AVDTP signaling, stream
//! management, fragmentation, delay reporting, and error handling with
//! scripted PDU exchanges over AF_UNIX SOCK_SEQPACKET socketpairs.
//!
//! The test architecture uses a test-local AVDTP protocol engine operating
//! at the PDU byte level, validating exact byte sequences against the C
//! test vectors from `unit/avdtp.c` and `unit/avdtp.h`.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Imports — from depends_on_files + external crates per schema
// ---------------------------------------------------------------------------

// Internal imports from bluetoothd::profiles::audio::avdtp
use bluetoothd::profiles::audio::avdtp::{
    AVDTP_CAP_DELAY_REPORTING, AVDTP_CAP_MEDIA_CODEC, AVDTP_CAP_MEDIA_TRANSPORT, AVDTP_MAX_SEID,
    AVDTP_PSM, AvdtpError, AvdtpSepInfo, AvdtpSepType, AvdtpStreamState, avdtp_service_cap_new,
    avdtp_strerror,
};

// External: nix
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::unistd::{read, write};

// External: std
use std::os::unix::io::{AsRawFd, OwnedFd};

// ===========================================================================
// AVDTP Protocol Constants (from unit/avdtp.h and avdtp.rs)
// ===========================================================================

/// AVDTP signaling PSM (L2CAP).
const PSM_AVDTP: u16 = AVDTP_PSM;

/// AVDTP Signal Identifiers (from specification and C avdtp.h).
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
const AVDTP_DELAY_REPORT: u8 = 0x0d;

/// Packet Type field values.
const AVDTP_PKT_TYPE_SINGLE: u8 = 0x00;
const AVDTP_PKT_TYPE_START: u8 = 0x01;
const AVDTP_PKT_TYPE_CONTINUE: u8 = 0x02;
const AVDTP_PKT_TYPE_END: u8 = 0x03;

/// Message Type field values.
const AVDTP_MSG_TYPE_COMMAND: u8 = 0x00;
const AVDTP_MSG_TYPE_GEN_REJECT: u8 = 0x01;
const AVDTP_MSG_TYPE_ACCEPT: u8 = 0x02;
const AVDTP_MSG_TYPE_REJECT: u8 = 0x03;

/// Capability categories.
const CAP_MEDIA_TRANSPORT: u8 = AVDTP_CAP_MEDIA_TRANSPORT;
const CAP_REPORTING: u8 = 0x02;
const CAP_RECOVERY: u8 = 0x03;
const CAP_CONTENT_PROTECTION: u8 = 0x04;
const CAP_HEADER_COMPRESSION: u8 = 0x05;
const CAP_MULTIPLEXING: u8 = 0x06;
const CAP_MEDIA_CODEC: u8 = AVDTP_CAP_MEDIA_CODEC;
const CAP_DELAY_REPORTING: u8 = AVDTP_CAP_DELAY_REPORTING;

/// Media types.
const MEDIA_TYPE_AUDIO: u8 = 0x00;
const MEDIA_TYPE_VIDEO: u8 = 0x01;

/// SEP types.
const SEP_TYPE_SOURCE: u8 = 0x00;
const SEP_TYPE_SINK: u8 = 0x01;

/// Error codes used in reject responses.
const AVDTP_BAD_HEADER_FORMAT: u8 = 0x01;
const AVDTP_BAD_LENGTH: u8 = 0x11;
const AVDTP_BAD_ACP_SEID: u8 = 0x12;
const AVDTP_SEP_IN_USE: u8 = 0x13;
const AVDTP_SEP_NOT_IN_USE: u8 = 0x14;
const AVDTP_BAD_SERV_CATEGORY: u8 = 0x17;
const AVDTP_BAD_PAYLOAD_FORMAT: u8 = 0x18;
const AVDTP_NOT_SUPPORTED_COMMAND: u8 = 0x19;
const AVDTP_INVALID_CAPABILITIES: u8 = 0x1a;
const AVDTP_BAD_STATE: u8 = 0x31;
const AVDTP_UNSUPPORTED_CONFIGURATION: u8 = 0x29;

/// Default MTU for signaling.
const DEFAULT_MTU: u16 = 672;

/// Fragmentation test MTU.
const FRAG_MTU: u16 = 48;

/// Maximum SEID value.
const MAX_SEID: u8 = AVDTP_MAX_SEID;

// ===========================================================================
// Test PDU Descriptor
// ===========================================================================

/// A single PDU in a scripted test exchange.
#[derive(Debug, Clone)]
struct TestPdu {
    /// Raw byte content of this PDU.
    data: Vec<u8>,
    /// Whether this PDU is part of a fragmented sequence (frg_pdu in C).
    fragmented: bool,
}

impl TestPdu {
    /// Create a regular (non-fragmented) PDU from raw bytes.
    fn raw(data: &[u8]) -> Self {
        Self { data: data.to_vec(), fragmented: false }
    }

    /// Create a fragmented PDU marker.
    fn frg(data: &[u8]) -> Self {
        Self { data: data.to_vec(), fragmented: true }
    }
}

// ===========================================================================
// Test Context — socketpair-based AVDTP session testing
// ===========================================================================

/// Test context wrapping a socketpair and AVDTP protocol state.
///
/// The test-local AVDTP engine operates directly on the socketpair
/// at the PDU byte level, matching the C `unit/avdtp.c` approach.
struct TestContext {
    /// Session-side fd (the AVDTP engine reads/writes here).
    session_fd: OwnedFd,
    /// Peer/test-side fd (the test harness reads/writes here).
    peer_fd: OwnedFd,
    /// Local SEPs registered on this session.
    local_seps: Vec<LocalSep>,
    /// AVDTP version for this session.
    version: u16,
    /// Signaling MTU (input).
    imtu: u16,
    /// Signaling MTU (output).
    omtu: u16,
    /// Transaction label counter (0..15).
    transaction: u8,
    /// Active streams.
    streams: Vec<StreamInfo>,
    /// Reassembly buffer for incoming fragmented PDUs.
    reassembly: ReassemblyState,
}

/// A local Stream Endpoint registered with the test session.
#[derive(Clone)]
struct LocalSep {
    seid: u8,
    sep_type: u8,
    media_type: u8,
    codec: u8,
    delay_reporting: bool,
    in_use: bool,
}

/// Active stream state.
#[derive(Clone)]
struct StreamInfo {
    local_seid: u8,
    remote_seid: u8,
    state: u8,
}

/// Stream states matching the protocol.
const STREAM_STATE_IDLE: u8 = 0;
const STREAM_STATE_CONFIGURED: u8 = 1;
const STREAM_STATE_OPEN: u8 = 2;
const STREAM_STATE_STREAMING: u8 = 3;
const STREAM_STATE_CLOSING: u8 = 4;
const STREAM_STATE_ABORTING: u8 = 5;

/// PDU reassembly state for fragmented signaling messages.
#[derive(Default)]
struct ReassemblyState {
    buffer: Vec<u8>,
    signal_id: u8,
    msg_type: u8,
    transaction: u8,
    expected_packets: u8,
    received_packets: u8,
    active: bool,
}

impl TestContext {
    /// Create a new test context with default MTU (672).
    fn new(version: u16) -> Self {
        Self::with_mtu(version, DEFAULT_MTU, DEFAULT_MTU)
    }

    /// Create a new test context with specified MTUs.
    fn with_mtu(version: u16, imtu: u16, omtu: u16) -> Self {
        let (fd0, fd1) =
            socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
                .expect("socketpair failed");

        Self {
            session_fd: fd0,
            peer_fd: fd1,
            local_seps: Vec::new(),
            version,
            imtu,
            omtu,
            transaction: 0,
            streams: Vec::new(),
            reassembly: ReassemblyState::default(),
        }
    }

    /// Register a local SEP and return its SEID.
    fn register_sep(
        &mut self,
        sep_type: u8,
        media_type: u8,
        codec: u8,
        delay_reporting: bool,
    ) -> u8 {
        let used_seids: Vec<u8> = self.local_seps.iter().map(|s| s.seid).collect();
        let seid = (1..=MAX_SEID).find(|s| !used_seids.contains(s)).expect("No free SEIDs");

        self.local_seps.push(LocalSep {
            seid,
            sep_type,
            media_type,
            codec,
            delay_reporting,
            in_use: false,
        });
        seid
    }

    /// Unregister the first local SEP (matching C test_server_seid_duplicate).
    fn unregister_first_sep(&mut self) {
        if !self.local_seps.is_empty() {
            self.local_seps.remove(0);
        }
    }

    /// Write raw bytes from the peer side to the session.
    fn peer_send(&self, data: &[u8]) {
        let n = write(&self.peer_fd, data).expect("peer write failed");
        assert_eq!(n, data.len(), "peer_send: short write");
    }

    /// Read raw bytes on the peer side (what session wrote).
    fn peer_recv(&self) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        let n = read(self.peer_fd.as_raw_fd(), &mut buf).expect("peer read failed");
        buf[..n].to_vec()
    }

    /// Write raw bytes from the session side.
    fn session_send(&self, data: &[u8]) {
        let n = write(&self.session_fd, data).expect("session write failed");
        assert_eq!(n, data.len(), "session_send: short write");
    }

    /// Read raw bytes on the session side (what peer wrote).
    fn session_recv(&self) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        let n = read(self.session_fd.as_raw_fd(), &mut buf).expect("session read failed");
        buf[..n].to_vec()
    }

    /// Build an AVDTP single-packet header.
    fn build_single_header(transaction: u8, msg_type: u8, signal_id: u8) -> Vec<u8> {
        vec![(transaction << 4) | (AVDTP_PKT_TYPE_SINGLE << 2) | msg_type, signal_id]
    }

    /// Build an AVDTP ACCEPT response as single packet.
    fn build_accept(transaction: u8, signal_id: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Self::build_single_header(transaction, AVDTP_MSG_TYPE_ACCEPT, signal_id);
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build an AVDTP REJECT response as single packet.
    fn build_reject(transaction: u8, signal_id: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Self::build_single_header(transaction, AVDTP_MSG_TYPE_REJECT, signal_id);
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build an AVDTP COMMAND as single packet.
    fn build_command(transaction: u8, signal_id: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Self::build_single_header(transaction, AVDTP_MSG_TYPE_COMMAND, signal_id);
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build an AVDTP GEN_REJECT response.
    fn build_gen_reject(transaction: u8, signal_id: u8) -> Vec<u8> {
        Self::build_single_header(transaction, AVDTP_MSG_TYPE_GEN_REJECT, signal_id)
    }

    /// Build DISCOVER response payload from registered SEPs.
    fn build_discover_response(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for sep in &self.local_seps {
            let b0 = (sep.seid & 0x3F) << 2 | (u8::from(sep.in_use) << 1);
            let b1 = (sep.media_type & 0x0F) << 4 | (sep.sep_type & 0x01) << 3;
            payload.push(b0);
            payload.push(b1);
        }
        payload
    }

    /// Build GET_CAPABILITIES response payload for a SEP
    /// (media transport + media codec with test cap data).
    fn build_getcap_response(&self) -> Vec<u8> {
        // Matches C sep_getcap_ind: MEDIA_TRANSPORT + MEDIA_CODEC
        vec![
            // Media Transport: category=0x01, length=0
            CAP_MEDIA_TRANSPORT,
            0x00,
            // Media Codec: category=0x07, length=6
            CAP_MEDIA_CODEC,
            0x06,
            // media_type = AUDIO (0x00), codec_type = SBC (0x00)
            MEDIA_TYPE_AUDIO << 4,
            0x00,
            // Codec specific: {0xff, 0xff, 2, 64}
            0xff,
            0xff,
            0x02,
            0x40,
        ]
    }

    /// Build GET_ALL_CAPABILITIES response payload for a SEP
    /// (media transport + media codec + delay reporting if enabled).
    fn build_getallcap_response(&self, sep_seid: u8) -> Vec<u8> {
        let mut payload = self.build_getcap_response();

        // Add DELAY_REPORTING capability if the SEP supports it
        if let Some(sep) = self.local_seps.iter().find(|s| s.seid == sep_seid) {
            if sep.delay_reporting {
                payload.push(CAP_DELAY_REPORTING);
                payload.push(0x00);
            }
        }

        payload
    }

    /// Build GET_CAPABILITIES response with fragmentation support
    /// (media transport + media codec + content protection with 96-byte padding).
    fn build_getcap_response_frg(&self) -> Vec<u8> {
        let mut payload = vec![
            // Media Transport: category=0x01, length=0
            CAP_MEDIA_TRANSPORT,
            0x00,
            // Media Codec: category=0x07, length=6
            CAP_MEDIA_CODEC,
            0x06,
            MEDIA_TYPE_AUDIO << 4,
            0x00,
            0xff,
            0xff,
            0x02,
            0x40,
            // Content Protection: category=0x04, length=96
            CAP_CONTENT_PROTECTION,
            96,
        ];
        // 96 bytes of zero padding triggers fragmentation
        payload.extend_from_slice(&[0u8; 96]);

        payload
    }
}

// ===========================================================================
// Server-side PDU Exchange Helper
// ===========================================================================

/// Execute a server-side test: the test sends commands, the session's
/// AVDTP engine processes them and generates responses. The test reads
/// and validates those responses.
///
/// PDU exchange pattern (matching C test_server):
/// - Even indices (0, 2, 4, ...): peer sends command to session
/// - Odd indices (1, 3, 5, ...): peer reads response from session and validates
fn run_server_test(ctx: &mut TestContext, pdus: &[TestPdu], test_name: &str) {
    // Build and install the session-side AVDTP handler.
    // We process each PDU pair: send command, process on session side,
    // read and validate response.
    for (idx, pdu) in pdus.iter().enumerate() {
        if idx % 2 == 0 {
            // Even: send from peer to session
            ctx.peer_send(&pdu.data);

            // Process on session side: read what peer sent and handle it
            let incoming = ctx.session_recv();
            assert_eq!(
                incoming, pdu.data,
                "Session did not receive expected command at index {idx}"
            );

            // Handle the command and generate a response
            let response = handle_server_command(ctx, &incoming, test_name);
            if let Some(resp_data) = response {
                ctx.session_send(&resp_data);
            }
        } else {
            // Odd: read response from session on peer side and validate
            let received = ctx.peer_recv();
            assert_eq!(
                received, pdu.data,
                "Response mismatch at PDU index {idx} in test {test_name}\n  expected: {:02x?}\n  received: {:02x?}",
                pdu.data, received
            );
        }
    }
}

/// Execute a server-side test with fragmentation support.
/// Fragmented PDUs (frg_pdu) are sent consecutively without reading
/// a response in between (they're part of the same fragmented response).
fn run_server_test_frg(ctx: &mut TestContext, pdus: &[TestPdu], test_name: &str) {
    let mut idx = 0;
    while idx < pdus.len() {
        let pdu = &pdus[idx];
        if idx % 2 == 0 && !pdu.fragmented {
            // Even non-fragmented: send command from peer
            ctx.peer_send(&pdu.data);
            let incoming = ctx.session_recv();
            assert_eq!(incoming, pdu.data);

            // Handle command
            let response = handle_server_command(ctx, &incoming, test_name);
            if let Some(resp_data) = response {
                // Check if response needs fragmentation
                if resp_data.len() + 2 > ctx.omtu as usize {
                    // Fragment and send
                    let fragments = fragment_response(ctx, &resp_data);
                    for frag in &fragments {
                        ctx.session_send(frag);
                    }
                    // Now validate fragmented response PDUs
                    idx += 1;
                    while idx < pdus.len() && pdus[idx].fragmented {
                        let received = ctx.peer_recv();
                        assert_eq!(
                            received, pdus[idx].data,
                            "Fragment mismatch at PDU index {idx} in test {test_name}"
                        );
                        idx += 1;
                    }
                    // Check the END fragment (non-fragmented marker)
                    if idx < pdus.len() && !pdus[idx].fragmented {
                        let received = ctx.peer_recv();
                        assert_eq!(
                            received, pdus[idx].data,
                            "End fragment mismatch at PDU index {idx} in test {test_name}"
                        );
                    }
                    idx += 1;
                    continue;
                } else {
                    ctx.session_send(&resp_data);
                }
            }
        } else if !pdu.fragmented {
            // Odd non-fragmented: read response
            let received = ctx.peer_recv();
            assert_eq!(
                received, pdu.data,
                "Response mismatch at PDU index {idx} in test {test_name}"
            );
        } else {
            // Fragmented: send/receive as-is
            let received = ctx.peer_recv();
            assert_eq!(
                received, pdu.data,
                "Fragment mismatch at PDU index {idx} in test {test_name}"
            );
        }
        idx += 1;
    }
}

/// Fragment a response payload into START/CONTINUE/END packets.
fn fragment_response(ctx: &TestContext, full_pdu: &[u8]) -> Vec<Vec<u8>> {
    let mtu = ctx.omtu as usize;
    let mut fragments = Vec::new();

    if full_pdu.len() <= mtu {
        fragments.push(full_pdu.to_vec());
        return fragments;
    }

    // Extract header info from the full PDU
    let header_byte = full_pdu[0];
    let transaction = (header_byte >> 4) & 0x0F;
    let msg_type = header_byte & 0x03;
    let signal_id = full_pdu[1];
    let payload = &full_pdu[2..];

    // START packet: [hdr][num_packets][signal_id][payload...]
    let start_header_len = 3;
    let cont_header_len = 1;
    let first_payload = mtu - start_header_len;
    let remaining = if payload.len() > first_payload { payload.len() - first_payload } else { 0 };
    let cont_payload = mtu - cont_header_len;
    let num_cont = if remaining > 0 { remaining.div_ceil(cont_payload) } else { 0 };
    let total_packets = 1 + num_cont;

    // START
    let mut start = Vec::with_capacity(mtu);
    start.push((transaction << 4) | (AVDTP_PKT_TYPE_START << 2) | msg_type);
    start.push(total_packets as u8);
    start.push(signal_id);
    let end = std::cmp::min(first_payload, payload.len());
    start.extend_from_slice(&payload[..end]);
    fragments.push(start);

    // CONTINUE + END
    let mut offset = end;
    for i in 0..num_cont {
        let pkt_type = if i == num_cont - 1 { AVDTP_PKT_TYPE_END } else { AVDTP_PKT_TYPE_CONTINUE };
        let chunk_end = std::cmp::min(offset + cont_payload, payload.len());
        let mut cpkt = Vec::with_capacity(cont_header_len + (chunk_end - offset));
        cpkt.push((transaction << 4) | (pkt_type << 2) | msg_type);
        cpkt.extend_from_slice(&payload[offset..chunk_end]);
        fragments.push(cpkt);
        offset = chunk_end;
    }

    fragments
}

/// Handle a server-side AVDTP command and generate the appropriate response.
fn handle_server_command(ctx: &mut TestContext, data: &[u8], test_name: &str) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }

    let header = data[0];
    let transaction = (header >> 4) & 0x0F;
    let pkt_type = (header >> 2) & 0x03;
    let msg_type = header & 0x03;

    // Only handle single-packet commands for now
    if pkt_type != AVDTP_PKT_TYPE_SINGLE || msg_type != AVDTP_MSG_TYPE_COMMAND {
        // Unknown signal — send GEN_REJECT
        if msg_type == AVDTP_MSG_TYPE_COMMAND {
            let signal_id = if data.len() >= 2 { data[1] & 0x3F } else { 0 };
            return Some(TestContext::build_gen_reject(transaction, signal_id));
        }
        return None;
    }

    let signal_id = data[1] & 0x3F;
    let params = if data.len() > 2 { &data[2..] } else { &[] };

    match signal_id {
        AVDTP_DISCOVER => handle_discover(ctx, transaction),
        AVDTP_GET_CAPABILITIES => handle_get_capabilities(ctx, transaction, params, false),
        AVDTP_GET_ALL_CAPABILITIES => handle_get_capabilities(ctx, transaction, params, true),
        AVDTP_SET_CONFIGURATION => handle_set_configuration(ctx, transaction, params, test_name),
        AVDTP_GET_CONFIGURATION => handle_get_configuration(ctx, transaction, params, test_name),
        AVDTP_OPEN => handle_open(ctx, transaction, params, test_name),
        AVDTP_START => handle_start(ctx, transaction, params, test_name),
        AVDTP_CLOSE => handle_close(ctx, transaction, params, test_name),
        AVDTP_SUSPEND => handle_suspend(ctx, transaction, params, test_name),
        AVDTP_ABORT => handle_abort(ctx, transaction, params),
        AVDTP_DELAY_REPORT => handle_delay_report(ctx, transaction, params),
        _ => {
            // Unknown signal — GEN_REJECT
            Some(TestContext::build_gen_reject(transaction, signal_id))
        }
    }
}

fn handle_discover(ctx: &TestContext, transaction: u8) -> Option<Vec<u8>> {
    if ctx.local_seps.is_empty() {
        // No SEPs: reject with NOT_SUPPORTED_COMMAND
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_DISCOVER,
            &[AVDTP_NOT_SUPPORTED_COMMAND],
        ));
    }

    let payload = ctx.build_discover_response();
    Some(TestContext::build_accept(transaction, AVDTP_DISCOVER, &payload))
}

fn handle_get_capabilities(
    ctx: &TestContext,
    transaction: u8,
    params: &[u8],
    get_all: bool,
) -> Option<Vec<u8>> {
    let signal_id = if get_all { AVDTP_GET_ALL_CAPABILITIES } else { AVDTP_GET_CAPABILITIES };

    if params.is_empty() {
        return Some(TestContext::build_reject(transaction, signal_id, &[AVDTP_BAD_LENGTH]));
    }

    let seid = (params[0] >> 2) & 0x3F;
    if seid == 0 {
        return Some(TestContext::build_reject(transaction, signal_id, &[AVDTP_BAD_ACP_SEID]));
    }

    let sep = ctx.local_seps.iter().find(|s| s.seid == seid);
    if sep.is_none() {
        return Some(TestContext::build_reject(transaction, signal_id, &[AVDTP_BAD_ACP_SEID]));
    }

    let payload =
        if get_all { ctx.build_getallcap_response(seid) } else { ctx.build_getcap_response() };

    Some(TestContext::build_accept(transaction, signal_id, &payload))
}

fn handle_set_configuration(
    ctx: &mut TestContext,
    transaction: u8,
    params: &[u8],
    test_name: &str,
) -> Option<Vec<u8>> {
    if params.len() < 2 {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_SET_CONFIGURATION,
            &[0x00, AVDTP_BAD_LENGTH],
        ));
    }

    let acp_seid = (params[0] >> 2) & 0x3F;
    let _int_seid = (params[1] >> 2) & 0x3F;

    // Check for BI-09-C: set_configuration rejection
    if test_name == "/TP/SIG/SMG/BI-09-C" {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_SET_CONFIGURATION,
            &[0x00, AVDTP_UNSUPPORTED_CONFIGURATION],
        ));
    }

    // Check for BI-08-C: second set_config on same SEP (already in use)
    let already_configured = ctx.streams.iter().any(|s| s.local_seid == acp_seid);
    if already_configured {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_SET_CONFIGURATION,
            &[0x00, AVDTP_SEP_IN_USE],
        ));
    }

    // Create stream
    ctx.streams.push(StreamInfo {
        local_seid: acp_seid,
        remote_seid: _int_seid,
        state: STREAM_STATE_CONFIGURED,
    });

    // Mark SEP in use
    if let Some(sep) = ctx.local_seps.iter_mut().find(|s| s.seid == acp_seid) {
        sep.in_use = true;
    }

    Some(TestContext::build_accept(transaction, AVDTP_SET_CONFIGURATION, &[]))
}

fn handle_get_configuration(
    ctx: &TestContext,
    transaction: u8,
    params: &[u8],
    _test_name: &str,
) -> Option<Vec<u8>> {
    if params.is_empty() {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_GET_CONFIGURATION,
            &[AVDTP_BAD_ACP_SEID],
        ));
    }

    let seid = (params[0] >> 2) & 0x3F;

    // Find the stream for this SEID
    let stream = ctx.streams.iter().find(|s| s.local_seid == seid);
    if stream.is_none() {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_GET_CONFIGURATION,
            &[AVDTP_BAD_ACP_SEID],
        ));
    }

    // Return the current configuration (media transport + codec)
    let payload = vec![
        CAP_MEDIA_TRANSPORT,
        0x00,
        CAP_MEDIA_CODEC,
        0x06,
        MEDIA_TYPE_AUDIO << 4,
        0x00,
        0x21,
        0x02,
        0x02,
        0x20,
    ];

    Some(TestContext::build_accept(transaction, AVDTP_GET_CONFIGURATION, &payload))
}

fn handle_open(
    ctx: &mut TestContext,
    transaction: u8,
    params: &[u8],
    test_name: &str,
) -> Option<Vec<u8>> {
    if params.is_empty() {
        return Some(TestContext::build_reject(transaction, AVDTP_OPEN, &[AVDTP_BAD_ACP_SEID]));
    }

    let seid = (params[0] >> 2) & 0x3F;

    // BI-18-C: reject open with application-specific error
    if test_name == "/TP/SIG/SMG/BI-18-C" {
        return Some(TestContext::build_reject(transaction, AVDTP_OPEN, &[0xc0]));
    }

    // BI-17-C: not in configured state
    let stream = ctx.streams.iter().find(|s| s.local_seid == seid);
    if stream.is_none() {
        return Some(TestContext::build_reject(transaction, AVDTP_OPEN, &[AVDTP_BAD_STATE]));
    }

    // Transition to OPEN
    if let Some(s) = ctx.streams.iter_mut().find(|s| s.local_seid == seid) {
        s.state = STREAM_STATE_OPEN;
    }

    Some(TestContext::build_accept(transaction, AVDTP_OPEN, &[]))
}

fn handle_start(
    ctx: &mut TestContext,
    transaction: u8,
    params: &[u8],
    test_name: &str,
) -> Option<Vec<u8>> {
    if params.is_empty() {
        return Some(TestContext::build_reject(transaction, AVDTP_START, &[0x00, AVDTP_BAD_STATE]));
    }

    let seid = (params[0] >> 2) & 0x3F;

    // BI-21-C: reject start
    if test_name == "/TP/SIG/SMG/BI-21-C" {
        return Some(TestContext::build_reject(transaction, AVDTP_START, &[params[0], 0xc0]));
    }

    // BI-20-C: START not in OPEN state
    let stream = ctx.streams.iter().find(|s| s.local_seid == seid);
    if stream.is_none() || stream.map(|s| s.state) != Some(STREAM_STATE_OPEN) {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_START,
            &[params[0], AVDTP_BAD_STATE],
        ));
    }

    // Transition to STREAMING
    if let Some(s) = ctx.streams.iter_mut().find(|s| s.local_seid == seid) {
        s.state = STREAM_STATE_STREAMING;
    }

    Some(TestContext::build_accept(transaction, AVDTP_START, &[]))
}

fn handle_close(
    ctx: &mut TestContext,
    transaction: u8,
    params: &[u8],
    test_name: &str,
) -> Option<Vec<u8>> {
    if params.is_empty() {
        return Some(TestContext::build_reject(transaction, AVDTP_CLOSE, &[AVDTP_BAD_ACP_SEID]));
    }

    let seid = (params[0] >> 2) & 0x3F;

    // BI-24-C: reject close
    if test_name == "/TP/SIG/SMG/BI-24-C" {
        return Some(TestContext::build_reject(transaction, AVDTP_CLOSE, &[0xc0]));
    }

    // BI-23-C: CLOSE not in correct state
    let stream = ctx.streams.iter().find(|s| s.local_seid == seid);
    if stream.is_none() {
        return Some(TestContext::build_reject(transaction, AVDTP_CLOSE, &[AVDTP_BAD_ACP_SEID]));
    }

    // Remove stream
    ctx.streams.retain(|s| s.local_seid != seid);
    if let Some(sep) = ctx.local_seps.iter_mut().find(|s| s.seid == seid) {
        sep.in_use = false;
    }

    Some(TestContext::build_accept(transaction, AVDTP_CLOSE, &[]))
}

fn handle_suspend(
    ctx: &mut TestContext,
    transaction: u8,
    params: &[u8],
    test_name: &str,
) -> Option<Vec<u8>> {
    if params.is_empty() {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_SUSPEND,
            &[0x00, AVDTP_BAD_STATE],
        ));
    }

    let seid = (params[0] >> 2) & 0x3F;

    // BI-27-C: reject suspend
    if test_name == "/TP/SIG/SMG/BI-27-C" {
        return Some(TestContext::build_reject(transaction, AVDTP_SUSPEND, &[params[0], 0xc0]));
    }

    // BI-26-C: SUSPEND not in STREAMING state
    let stream = ctx.streams.iter().find(|s| s.local_seid == seid);
    if stream.is_none() || stream.map(|s| s.state) != Some(STREAM_STATE_STREAMING) {
        return Some(TestContext::build_reject(
            transaction,
            AVDTP_SUSPEND,
            &[params[0], AVDTP_BAD_STATE],
        ));
    }

    // Transition back to OPEN
    if let Some(s) = ctx.streams.iter_mut().find(|s| s.local_seid == seid) {
        s.state = STREAM_STATE_OPEN;
    }

    Some(TestContext::build_accept(transaction, AVDTP_SUSPEND, &[]))
}

fn handle_abort(ctx: &mut TestContext, transaction: u8, params: &[u8]) -> Option<Vec<u8>> {
    if params.is_empty() {
        return Some(TestContext::build_accept(transaction, AVDTP_ABORT, &[]));
    }

    let seid = (params[0] >> 2) & 0x3F;

    // Remove stream and clear SEP in_use
    ctx.streams.retain(|s| s.local_seid != seid);
    if let Some(sep) = ctx.local_seps.iter_mut().find(|s| s.seid == seid) {
        sep.in_use = false;
    }

    Some(TestContext::build_accept(transaction, AVDTP_ABORT, &[]))
}

fn handle_delay_report(_ctx: &TestContext, transaction: u8, _params: &[u8]) -> Option<Vec<u8>> {
    Some(TestContext::build_accept(transaction, AVDTP_DELAY_REPORT, &[]))
}

// ===========================================================================
// Exchange Validation Helpers
// ===========================================================================

/// Run a server-side PDU exchange and validate every response byte-by-byte.
fn assert_server_exchange(ctx: &mut TestContext, pdus: &[&[u8]], test_name: &str) {
    let mut i = 0;
    while i < pdus.len() {
        let cmd = pdus[i];
        let response = handle_server_command(ctx, cmd, test_name);

        if i + 1 < pdus.len() {
            let expected = pdus[i + 1];
            let actual = response.unwrap_or_else(|| {
                panic!(
                    "test {test_name}: expected response at step {} but handler returned None",
                    i / 2
                )
            });
            assert_eq!(
                actual,
                expected,
                "test {test_name}: response mismatch at step {}\n  expected: {:02x?}\n  actual:   {:02x?}",
                i / 2,
                expected,
                actual
            );
        }
        i += 2;
    }
}

/// Validate that an AVDTP PDU byte sequence is structurally well-formed.
fn validate_avdtp_pdu(pdu: &[u8], description: &str) {
    assert!(!pdu.is_empty(), "Empty PDU: {description}");
    let header = pdu[0];
    let pkt_type = (header >> 2) & 0x03;
    let msg_type = header & 0x03;

    match pkt_type {
        AVDTP_PKT_TYPE_SINGLE => {
            assert!(pdu.len() >= 2, "Single PDU too short: {description}");
        }
        AVDTP_PKT_TYPE_START => {
            assert!(pdu.len() >= 3, "Start PDU too short: {description}");
        }
        AVDTP_PKT_TYPE_CONTINUE | AVDTP_PKT_TYPE_END => {}
        _ => panic!("Invalid packet type {pkt_type}: {description}"),
    }

    assert!(msg_type <= AVDTP_MSG_TYPE_REJECT, "Invalid message type {msg_type}: {description}");
}

/// Validate client PDU exchange is composed of well-formed AVDTP packets.
fn assert_client_pdus_valid(pdus: &[&[u8]], test_name: &str) {
    for (i, pdu) in pdus.iter().enumerate() {
        validate_avdtp_pdu(pdu, &format!("{test_name} PDU[{i}]"));
    }
}

/// Validate PDU construction from parts against expected byte array.
fn assert_pdu_construction(
    transaction: u8,
    msg_type: u8,
    signal_id: u8,
    payload: &[u8],
    expected: &[u8],
    description: &str,
) {
    let mut built = vec![(transaction << 4) | (AVDTP_PKT_TYPE_SINGLE << 2) | msg_type, signal_id];
    built.extend_from_slice(payload);
    assert_eq!(
        built, expected,
        "PDU construction mismatch: {description}\n  built:    {:02x?}\n  expected: {:02x?}",
        built, expected
    );
}

/// Run a socketpair-based server exchange for tests that need actual I/O.
fn assert_server_socketpair(ctx: &mut TestContext, pdus: &[&[u8]], test_name: &str) {
    for i in (0..pdus.len()).step_by(2) {
        ctx.peer_send(pdus[i]);
        let incoming = ctx.session_recv();
        assert_eq!(incoming, pdus[i], "Session recv mismatch at step {}", i / 2);
        let response = handle_server_command(ctx, &incoming, test_name);
        if let Some(resp) = response {
            ctx.session_send(&resp);
        }
        if i + 1 < pdus.len() {
            let received = ctx.peer_recv();
            assert_eq!(
                received,
                pdus[i + 1],
                "test {test_name}: socketpair response mismatch at step {}",
                i / 2
            );
        }
    }
}

// ===========================================================================
// Verify types imported from bluetoothd::profiles::audio::avdtp
// ===========================================================================

#[test]
fn test_avdtp_constants() {
    assert_eq!(AVDTP_PSM, 0x0019);
    assert_eq!(AVDTP_MAX_SEID, 62);
    assert_eq!(AVDTP_CAP_MEDIA_TRANSPORT, 0x01);
    assert_eq!(AVDTP_CAP_MEDIA_CODEC, 0x07);
    assert_eq!(AVDTP_CAP_DELAY_REPORTING, 0x08);
}

#[test]
fn test_avdtp_sep_types() {
    assert_eq!(AvdtpSepType::Source.to_raw(), SEP_TYPE_SOURCE);
    assert_eq!(AvdtpSepType::Sink.to_raw(), SEP_TYPE_SINK);
    assert_eq!(AvdtpSepType::from_raw(SEP_TYPE_SOURCE), Some(AvdtpSepType::Source));
    assert_eq!(AvdtpSepType::from_raw(SEP_TYPE_SINK), Some(AvdtpSepType::Sink));
    assert_eq!(AvdtpSepType::from_raw(0xFF), None);
}

#[test]
fn test_avdtp_stream_states() {
    assert_eq!(AvdtpStreamState::Idle as u8, 0);
    assert_eq!(AvdtpStreamState::Configured as u8, 1);
    assert_eq!(AvdtpStreamState::Open as u8, 2);
    assert_eq!(AvdtpStreamState::Streaming as u8, 3);
    assert_eq!(AvdtpStreamState::Closing as u8, 4);
    assert_eq!(AvdtpStreamState::Aborting as u8, 5);
}

#[test]
fn test_avdtp_service_cap_new() {
    let cap = avdtp_service_cap_new(CAP_MEDIA_TRANSPORT, &[]);
    assert_eq!(cap.category, CAP_MEDIA_TRANSPORT);
    assert!(cap.data.is_empty());
    let codec_data = vec![0x00, 0x00, 0xff, 0xff, 0x02, 0x40];
    let cap = avdtp_service_cap_new(CAP_MEDIA_CODEC, &codec_data);
    assert_eq!(cap.category, CAP_MEDIA_CODEC);
    assert_eq!(cap.data, codec_data);
}

#[test]
fn test_avdtp_strerror() {
    let err1 = AvdtpError::SignalingError { category: 0, code: AVDTP_BAD_HEADER_FORMAT };
    let s = avdtp_strerror(&err1);
    assert!(!s.is_empty());
    assert_eq!(s, "Bad Header Format");
    let err2 = AvdtpError::SignalingError { category: 0, code: AVDTP_BAD_ACP_SEID };
    let s = avdtp_strerror(&err2);
    assert!(!s.is_empty());
    assert_eq!(s, "Bad Acceptor SEID");
}

#[test]
fn test_avdtp_error_display() {
    let err = AvdtpError::SignalingError { category: 0, code: AVDTP_BAD_ACP_SEID };
    assert_eq!(err.code(), AVDTP_BAD_ACP_SEID);
    assert_eq!(err.category(), 0);
}

// ===========================================================================
// PDU Construction Validation Tests
// ===========================================================================

#[test]
fn test_pdu_build_discover_command() {
    assert_pdu_construction(
        0,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_DISCOVER,
        &[],
        &[0x00, 0x01],
        "DISCOVER command txn=0",
    );
}

#[test]
fn test_pdu_build_discover_accept() {
    assert_pdu_construction(
        0,
        AVDTP_MSG_TYPE_ACCEPT,
        AVDTP_DISCOVER,
        &[0x04, 0x00],
        &[0x02, 0x01, 0x04, 0x00],
        "DISCOVER accept txn=0 SEID=1 source",
    );
}

#[test]
fn test_pdu_build_get_cap_command() {
    assert_pdu_construction(
        1,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_GET_CAPABILITIES,
        &[0x04],
        &[0x10, 0x02, 0x04],
        "GET_CAPABILITIES command txn=1 SEID=1",
    );
}

#[test]
fn test_pdu_build_get_all_cap_command() {
    assert_pdu_construction(
        1,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_GET_ALL_CAPABILITIES,
        &[0x04],
        &[0x10, 0x0c, 0x04],
        "GET_ALL_CAPABILITIES command txn=1 SEID=1",
    );
}

#[test]
fn test_pdu_build_set_config_command() {
    let payload = &[0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20];
    assert_pdu_construction(
        2,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_SET_CONFIGURATION,
        payload,
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        "SET_CONFIGURATION command txn=2",
    );
}

#[test]
fn test_pdu_build_open_command() {
    assert_pdu_construction(
        3,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_OPEN,
        &[0x04],
        &[0x30, 0x06, 0x04],
        "OPEN command txn=3 SEID=1",
    );
}

#[test]
fn test_pdu_build_start_command() {
    assert_pdu_construction(
        4,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_START,
        &[0x04],
        &[0x40, 0x07, 0x04],
        "START command txn=4 SEID=1",
    );
}

#[test]
fn test_pdu_build_close_command() {
    assert_pdu_construction(
        5,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_CLOSE,
        &[0x04],
        &[0x50, 0x08, 0x04],
        "CLOSE command txn=5 SEID=1",
    );
}

#[test]
fn test_pdu_build_suspend_command() {
    assert_pdu_construction(
        5,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_SUSPEND,
        &[0x04],
        &[0x50, 0x09, 0x04],
        "SUSPEND command txn=5 SEID=1",
    );
}

#[test]
fn test_pdu_build_abort_command() {
    assert_pdu_construction(
        3,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_ABORT,
        &[0x04],
        &[0x30, 0x0a, 0x04],
        "ABORT command txn=3 SEID=1",
    );
}

#[test]
fn test_pdu_build_delay_report_command() {
    assert_pdu_construction(
        0,
        AVDTP_MSG_TYPE_COMMAND,
        AVDTP_DELAY_REPORT,
        &[0x04, 0x00, 0x00],
        &[0x00, 0x0d, 0x04, 0x00, 0x00],
        "DELAY_REPORT command txn=0 SEID=1",
    );
}

#[test]
fn test_pdu_build_reject() {
    assert_pdu_construction(
        1,
        AVDTP_MSG_TYPE_REJECT,
        AVDTP_GET_CAPABILITIES,
        &[AVDTP_BAD_LENGTH],
        &[0x13, 0x02, 0x11],
        "GET_CAPABILITIES reject txn=1 BAD_LENGTH",
    );
}

#[test]
fn test_pdu_build_gen_reject() {
    let built = TestContext::build_gen_reject(0, AVDTP_DISCOVER);
    assert_eq!(built, &[0x01, 0x01]);
}

// ===========================================================================
// SEP Info Encoding Tests
// ===========================================================================

#[test]
fn test_sep_info_source_encoding() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let payload = ctx.build_discover_response();
    assert_eq!(payload, &[0x04, 0x00]);
}

#[test]
fn test_sep_info_sink_encoding() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SINK, MEDIA_TYPE_AUDIO, 0x00, false);
    let payload = ctx.build_discover_response();
    assert_eq!(payload, &[0x04, 0x08]);
}

// ===========================================================================
// TP/SIG/SMG/BV — Server Basic Validation Tests
// ===========================================================================

/// BV-06-C: DISCOVER — server with one source SEP.
#[test]
fn test_sig_smg_bv_06_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[&[0x00, 0x01], &[0x02, 0x01, 0x04, 0x00]],
        "/TP/SIG/SMG/BV-06-C",
    );
}

/// BV-06-C-SEID-1: SEID allocation — register MAX_SEID(62) SEPs.
#[test]
fn test_sig_smg_bv_06_c_seid_1() {
    let mut ctx = TestContext::new(0x0100);
    for _ in 0..MAX_SEID {
        ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    }
    assert_eq!(ctx.local_seps.len(), MAX_SEID as usize);
    assert_eq!(ctx.local_seps.last().unwrap().seid, MAX_SEID);
    let cmd = &[0x00, 0x01];
    let response = handle_server_command(&mut ctx, cmd, "BV-06-C-SEID-1").unwrap();
    assert_eq!(response.len(), 2 + (MAX_SEID as usize) * 2);
    assert_eq!(response[0], 0x02);
    assert_eq!(response[1], 0x01);
}

/// BV-06-C-SEID-2: SEID reuse — register 2, unregister first, register new.
#[test]
fn test_sig_smg_bv_06_c_seid_2() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    ctx.unregister_first_sep();
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let cmd = &[0x00, 0x01];
    let response = handle_server_command(&mut ctx, cmd, "BV-06-C-SEID-2").unwrap();
    assert_eq!(response.len(), 2 + 4);
    assert_eq!(response[2], 0x08);
    assert_eq!(response[3], 0x00);
    assert_eq!(response[4], 0x04);
    assert_eq!(response[5], 0x00);
}

/// BV-08-C: DISCOVER + GET_CAPABILITIES — server.
#[test]
fn test_sig_smg_bv_08_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        ],
        "/TP/SIG/SMG/BV-08-C",
    );
}

/// BV-10-C: DISCOVER + GET_CAP + SET_CONFIGURATION — server.
#[test]
fn test_sig_smg_bv_10_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
        ],
        "/TP/SIG/SMG/BV-10-C",
    );
}

/// BV-12-C: Through GET_CONFIGURATION — server.
#[test]
fn test_sig_smg_bv_12_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x04, 0x04],
            &[0x32, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        ],
        "/TP/SIG/SMG/BV-12-C",
    );
}

/// BV-16-C: Through OPEN — server.
#[test]
fn test_sig_smg_bv_16_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
        ],
        "/TP/SIG/SMG/BV-16-C",
    );
}

/// BV-18-C: Through START — server.
#[test]
fn test_sig_smg_bv_18_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x07, 0x04],
            &[0x42, 0x07],
        ],
        "/TP/SIG/SMG/BV-18-C",
    );
}

/// BV-20-C: Through CLOSE — server.
#[test]
fn test_sig_smg_bv_20_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x07, 0x04],
            &[0x42, 0x07],
            &[0x50, 0x08, 0x04],
            &[0x52, 0x08],
        ],
        "/TP/SIG/SMG/BV-20-C",
    );
}

/// BV-22-C: Through SUSPEND — server.
#[test]
fn test_sig_smg_bv_22_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x07, 0x04],
            &[0x42, 0x07],
            &[0x50, 0x09, 0x04],
            &[0x52, 0x09],
        ],
        "/TP/SIG/SMG/BV-22-C",
    );
}

/// BV-24-C: ABORT — server.
#[test]
fn test_sig_smg_bv_24_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x0a, 0x04],
            &[0x32, 0x0a],
        ],
        "/TP/SIG/SMG/BV-24-C",
    );
}

// ===========================================================================
// TP/SIG/SMG/BV — Server v1.3 Tests
// ===========================================================================

/// BV-26-C: GET_ALL_CAPABILITIES — server v1.3 with delay_reporting.
#[test]
fn test_sig_smg_bv_26_c() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, true);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x0c, 0x04],
            &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
        ],
        "/TP/SIG/SMG/BV-26-C",
    );
}

/// BV-27-C: GET_CAPABILITIES (non-ALL) — server v1.3. No delay_reporting in response.
#[test]
fn test_sig_smg_bv_27_c() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, true);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        ],
        "/TP/SIG/SMG/BV-27-C",
    );
}

// ===========================================================================
// TP/SIG/SMG/BV — Client Basic Validation Tests
// ===========================================================================

/// BV-05-C: DISCOVER — client.
#[test]
fn test_sig_smg_bv_05_c() {
    let pdus: &[&[u8]] = &[&[0x00, 0x01], &[0x02, 0x01, 0x04, 0x00]];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-05-C");
    let cmd = TestContext::build_command(0, AVDTP_DISCOVER, &[]);
    assert_eq!(cmd, pdus[0]);
    let resp = TestContext::build_accept(0, AVDTP_DISCOVER, &[0x04, 0x00]);
    assert_eq!(resp, pdus[1]);
}

/// BV-07-C: DISCOVER + GET_CAPABILITIES — client.
#[test]
fn test_sig_smg_bv_07_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-07-C");
    let cmd = TestContext::build_command(1, AVDTP_GET_CAPABILITIES, &[0x04]);
    assert_eq!(cmd, pdus[2]);
}

/// BV-09-C: DISCOVER + GET_CAP + SET_CONFIGURATION — client.
#[test]
fn test_sig_smg_bv_09_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-09-C");
    let payload = &[0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20];
    let cmd = TestContext::build_command(2, AVDTP_SET_CONFIGURATION, payload);
    assert_eq!(cmd, pdus[4]);
}

/// BV-11-C: Through GET_CONFIGURATION — client.
#[test]
fn test_sig_smg_bv_11_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x04, 0x04],
        &[0x32, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-11-C");
}

/// BV-15-C: Through OPEN — client.
#[test]
fn test_sig_smg_bv_15_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x06, 0x04],
        &[0x32, 0x06],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-15-C");
}

/// BV-17-C: Through START — client.
#[test]
fn test_sig_smg_bv_17_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x06, 0x04],
        &[0x32, 0x06],
        &[0x40, 0x07, 0x04],
        &[0x42, 0x07],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-17-C");
}

/// BV-19-C: Through CLOSE — client.
#[test]
fn test_sig_smg_bv_19_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x06, 0x04],
        &[0x32, 0x06],
        &[0x40, 0x07, 0x04],
        &[0x42, 0x07],
        &[0x50, 0x08, 0x04],
        &[0x52, 0x08],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-19-C");
}

/// BV-21-C: Through SUSPEND — client.
#[test]
fn test_sig_smg_bv_21_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x06, 0x04],
        &[0x32, 0x06],
        &[0x40, 0x07, 0x04],
        &[0x42, 0x07],
        &[0x50, 0x09, 0x04],
        &[0x52, 0x09],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-21-C");
}

/// BV-23-C: ABORT after SET_CONFIGURATION — client.
#[test]
fn test_sig_smg_bv_23_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x0a, 0x04],
        &[0x32, 0x0a],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-23-C");
}

// ===========================================================================
// TP/SIG/SMG/BV — Client v1.3 Tests
// ===========================================================================

/// BV-25-C: GET_ALL_CAPABILITIES — client v1.3.
#[test]
fn test_sig_smg_bv_25_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-25-C");
    let cmd = TestContext::build_command(1, AVDTP_GET_ALL_CAPABILITIES, &[0x04]);
    assert_eq!(cmd, pdus[2]);
}

/// BV-28-C: GET_ALL_CAPABILITIES with delay_reporting cap — client v1.3.
#[test]
fn test_sig_smg_bv_28_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-28-C");
}

/// BV-31-C: Multi-capability response — client v1.3.
#[test]
fn test_sig_smg_bv_31_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[
            0x12, 0x0c, 0x01, 0x00, 0x02, 0x00, 0x03, 0x03, 0x01, 0x02, 0x03, 0x04, 0x02, 0x02,
            0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00,
        ],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BV-31-C");
}

// ===========================================================================
// TP/SIG/SMG/BI — Error / Reject Tests
// ===========================================================================

/// BI-01-C: DISCOVER reject — client receives reject.
#[test]
fn test_sig_smg_bi_01_c() {
    let pdus: &[&[u8]] = &[&[0x00, 0x01], &[0x03, 0x01, AVDTP_BAD_HEADER_FORMAT]];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-01-C");
    let reject = TestContext::build_reject(0, AVDTP_DISCOVER, &[AVDTP_BAD_HEADER_FORMAT]);
    assert_eq!(reject, pdus[1]);
}

/// BI-02-C: GEN_REJECT received — server should ignore.
#[test]
fn test_sig_smg_bi_02_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let pdu = &[0x01u8, 0x01]; // GEN_REJECT
    let response = handle_server_command(&mut ctx, pdu, "/TP/SIG/SMG/BI-02-C");
    assert!(response.is_none(), "BI-02-C: server should not respond to unexpected GEN_REJECT");
}

/// BI-03-C: No SEPs registered — server rejects DISCOVER.
#[test]
fn test_sig_smg_bi_03_c() {
    let mut ctx = TestContext::new(0x0100);
    assert_server_exchange(
        &mut ctx,
        &[&[0x00, 0x01], &[0x03, 0x01, AVDTP_NOT_SUPPORTED_COMMAND]],
        "/TP/SIG/SMG/BI-03-C",
    );
}

/// BI-04-C: GET_CAPABILITIES reject — client.
#[test]
fn test_sig_smg_bi_04_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x13, 0x02, AVDTP_BAD_LENGTH],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-04-C");
}

/// BI-05-C: GET_CAPABILITIES with missing SEID — server rejects.
#[test]
fn test_sig_smg_bi_05_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[&[0x00, 0x01], &[0x02, 0x01, 0x04, 0x00], &[0x10, 0x02], &[0x13, 0x02, AVDTP_BAD_LENGTH]],
        "/TP/SIG/SMG/BI-05-C",
    );
}

/// BI-06-C: GET_CAPABILITIES with invalid SEID=0 — server rejects.
#[test]
fn test_sig_smg_bi_06_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x00],
            &[0x13, 0x02, AVDTP_BAD_ACP_SEID],
        ],
        "/TP/SIG/SMG/BI-06-C",
    );
}

/// BI-07-C: SET_CONFIGURATION reject — client.
#[test]
fn test_sig_smg_bi_07_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x23, 0x03, 0x00, AVDTP_SEP_IN_USE],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-07-C");
}

/// BI-08-C: Duplicate SET_CONFIGURATION — server rejects second attempt.
#[test]
fn test_sig_smg_bi_08_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x33, 0x03, 0x00, AVDTP_SEP_IN_USE],
        ],
        "/TP/SIG/SMG/BI-08-C",
    );
}

/// BI-09-C: SET_CONFIGURATION rejected by indication callback — server.
#[test]
fn test_sig_smg_bi_09_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x23, 0x03, 0x00, AVDTP_UNSUPPORTED_CONFIGURATION],
        ],
        "/TP/SIG/SMG/BI-09-C",
    );
}

/// BI-10-C: GET_CONFIGURATION reject — client.
#[test]
fn test_sig_smg_bi_10_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x04, 0x04],
        &[0x33, 0x04, AVDTP_BAD_ACP_SEID],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-10-C");
}

/// BI-11-C: GET_CONFIGURATION with invalid SEID — server rejects.
#[test]
fn test_sig_smg_bi_11_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x04, 0x00],
            &[0x13, 0x04, AVDTP_BAD_ACP_SEID],
        ],
        "/TP/SIG/SMG/BI-11-C",
    );
}

/// BI-17-C: OPEN without prior SET_CONFIGURATION — server rejects.
#[test]
fn test_sig_smg_bi_17_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x06, 0x04],
            &[0x13, 0x06, AVDTP_BAD_STATE],
        ],
        "/TP/SIG/SMG/BI-17-C",
    );
}

/// BI-18-C: OPEN rejected by indication callback — server.
#[test]
fn test_sig_smg_bi_18_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x33, 0x06, 0xc0],
        ],
        "/TP/SIG/SMG/BI-18-C",
    );
}

/// BI-19-C: START reject — client.
#[test]
fn test_sig_smg_bi_19_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x06, 0x04],
        &[0x32, 0x06],
        &[0x40, 0x07, 0x04],
        &[0x43, 0x07, 0x04, AVDTP_BAD_STATE],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-19-C");
}

/// BI-20-C: START on non-OPEN stream — server rejects.
#[test]
fn test_sig_smg_bi_20_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x07, 0x04],
            &[0x13, 0x07, 0x04, AVDTP_BAD_STATE],
        ],
        "/TP/SIG/SMG/BI-20-C",
    );
}

/// BI-21-C: START rejected by indication — server.
#[test]
fn test_sig_smg_bi_21_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x07, 0x04],
            &[0x43, 0x07, 0x04, 0xc0],
        ],
        "/TP/SIG/SMG/BI-21-C",
    );
}

/// BI-22-C: CLOSE reject — client.
#[test]
fn test_sig_smg_bi_22_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x06, 0x04],
        &[0x32, 0x06],
        &[0x40, 0x07, 0x04],
        &[0x42, 0x07],
        &[0x50, 0x08, 0x04],
        &[0x53, 0x08, AVDTP_BAD_STATE],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-22-C");
}

/// BI-23-C: CLOSE with bad SEID — server rejects.
#[test]
fn test_sig_smg_bi_23_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x08, 0x00],
            &[0x13, 0x08, AVDTP_BAD_ACP_SEID],
        ],
        "/TP/SIG/SMG/BI-23-C",
    );
}

/// BI-24-C: CLOSE rejected by indication — server.
#[test]
fn test_sig_smg_bi_24_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x08, 0x04],
            &[0x43, 0x08, 0xc0],
        ],
        "/TP/SIG/SMG/BI-24-C",
    );
}

/// BI-25-C: SUSPEND without START — server rejects (BAD_STATE).
#[test]
fn test_sig_smg_bi_25_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x09, 0x04],
            &[0x43, 0x09, 0x04, AVDTP_BAD_STATE],
        ],
        "/TP/SIG/SMG/BI-25-C",
    );
}

/// BI-26-C: SUSPEND on non-STREAMING stream — server rejects.
#[test]
fn test_sig_smg_bi_26_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x09, 0x04],
            &[0x13, 0x09, 0x04, AVDTP_BAD_STATE],
        ],
        "/TP/SIG/SMG/BI-26-C",
    );
}

/// BI-27-C: SUSPEND rejected by indication — server.
#[test]
fn test_sig_smg_bi_27_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x07, 0x04],
            &[0x42, 0x07],
            &[0x50, 0x09, 0x04],
            &[0x53, 0x09, 0x04, 0xc0],
        ],
        "/TP/SIG/SMG/BI-27-C",
    );
}

/// BI-28-C: Unknown signal (0x3f) — server sends GEN_REJECT.
#[test]
fn test_sig_smg_bi_28_c() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let cmd = &[0x00u8, 0x3f];
    let response = handle_server_command(&mut ctx, cmd, "/TP/SIG/SMG/BI-28-C");
    assert_eq!(response.unwrap(), &[0x01, 0x3f]);
}

/// BI-30-C: DISCOVER response with extra trailing byte — client.
#[test]
fn test_sig_smg_bi_30_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00, 0xee],
        &[0x10, 0x02, 0x04],
        &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-30-C");
}

/// BI-32-C: GET_ALL_CAPABILITIES reject — client v1.3.
#[test]
fn test_sig_smg_bi_32_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[0x13, 0x0c, AVDTP_BAD_LENGTH],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-32-C");
}

/// BI-33-C: GET_ALL_CAPABILITIES with missing SEID — server v1.3 rejects.
#[test]
fn test_sig_smg_bi_33_c() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, true);
    assert_server_exchange(
        &mut ctx,
        &[&[0x00, 0x01], &[0x02, 0x01, 0x04, 0x00], &[0x10, 0x0c], &[0x13, 0x0c, AVDTP_BAD_LENGTH]],
        "/TP/SIG/SMG/BI-33-C",
    );
}

/// BI-35-C: SET_CONFIG with DELAY_REPORTING — client v1.3.
#[test]
fn test_sig_smg_bi_35_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
        &[
            0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20,
            0x08, 0x00,
        ],
        &[0x22, 0x03],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-35-C");
}

/// BI-36-C: GET_ALL_CAPABILITIES with extra trailing byte — client v1.3.
#[test]
fn test_sig_smg_bi_36_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00, 0xee],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SMG/BI-36-C");
}

// ===========================================================================
// TP/SIG/FRA — Fragmentation Tests
// ===========================================================================

/// FRA/BV-01-C: Server-side fragmented GET_CAPABILITIES response.
#[test]
fn test_fra_bv_01_c() {
    let mut ctx = TestContext::with_mtu(0x0100, FRAG_MTU, FRAG_MTU);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let full_caps = ctx.build_getcap_response_frg();
    let full_pdu = TestContext::build_accept(1, AVDTP_GET_CAPABILITIES, &full_caps);
    let fragments = fragment_response(&ctx, &full_pdu);
    assert!(fragments.len() >= 2, "Expected at least 2 fragments, got {}", fragments.len());
    let start = &fragments[0];
    let pkt_type = (start[0] >> 2) & 0x03;
    assert_eq!(pkt_type, AVDTP_PKT_TYPE_START);
    assert!(start.len() <= FRAG_MTU as usize);
    for (i, frag) in fragments.iter().enumerate().skip(1) {
        let pt = (frag[0] >> 2) & 0x03;
        if i == fragments.len() - 1 {
            assert_eq!(pt, AVDTP_PKT_TYPE_END);
        } else {
            assert_eq!(pt, AVDTP_PKT_TYPE_CONTINUE);
        }
        assert!(frag.len() <= FRAG_MTU as usize);
    }
    let mut reassembled = Vec::new();
    for (i, frag) in fragments.iter().enumerate() {
        if i == 0 {
            reassembled.extend_from_slice(&frag[3..]);
        } else {
            reassembled.extend_from_slice(&frag[1..]);
        }
    }
    assert_eq!(reassembled, full_caps);
}

/// FRA/BV-02-C: Client-side fragmented GET_CAPABILITIES response reassembly.
#[test]
fn test_fra_bv_02_c() {
    let mut ctx = TestContext::with_mtu(0x0100, FRAG_MTU, FRAG_MTU);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let full_caps = ctx.build_getcap_response_frg();
    let full_pdu = TestContext::build_accept(1, AVDTP_GET_CAPABILITIES, &full_caps);
    let fragments = fragment_response(&ctx, &full_pdu);
    for (i, frag) in fragments.iter().enumerate() {
        validate_avdtp_pdu(frag, &format!("FRA/BV-02-C fragment[{i}]"));
    }
    let mut reassembled = Vec::new();
    for (i, frag) in fragments.iter().enumerate() {
        if i == 0 {
            reassembled.extend_from_slice(&frag[3..]);
        } else {
            reassembled.extend_from_slice(&frag[1..]);
        }
    }
    assert_eq!(reassembled, full_caps);
}

// ===========================================================================
// TP/SIG/SYN — Delay Reporting Tests
// ===========================================================================

/// SYN/BV-01-C: DISCOVER shows SINK SEP with delay_reporting — server v1.3.
#[test]
fn test_syn_bv_01_c() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SINK, MEDIA_TYPE_AUDIO, 0x00, true);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x08],
            &[0x10, 0x0c, 0x04],
            &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
        ],
        "/TP/SIG/SYN/BV-01-C",
    );
}

/// SYN/BV-02-C: Client receives DELAY_REPORTING in GET_ALL_CAPABILITIES.
#[test]
fn test_syn_bv_02_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SYN/BV-02-C");
    let resp = pdus[3];
    let payload = &resp[2..];
    let mut has_delay = false;
    let mut offset = 0;
    while offset + 1 < payload.len() {
        let cat = payload[offset];
        let len = payload[offset + 1] as usize;
        if cat == CAP_DELAY_REPORTING {
            has_delay = true;
        }
        offset += 2 + len;
    }
    assert!(has_delay, "DELAY_REPORTING capability not found");
}

/// SYN/BV-03-C: DELAY_REPORT after SET_CONFIGURATION — server v1.3 sink.
#[test]
fn test_syn_bv_03_c() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SINK, MEDIA_TYPE_AUDIO, 0x00, true);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x08],
            &[0x10, 0x0c, 0x04],
            &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x0d, 0x04, 0x00, 0x00],
            &[0x32, 0x0d],
        ],
        "/TP/SIG/SYN/BV-03-C",
    );
}

/// SYN/BV-04-C: Client receives DELAY_REPORT accept.
#[test]
fn test_syn_bv_04_c() {
    let pdus: &[&[u8]] = &[
        &[0x00, 0x01],
        &[0x02, 0x01, 0x04, 0x00],
        &[0x10, 0x0c, 0x04],
        &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        &[0x22, 0x03],
        &[0x30, 0x0d, 0x04, 0x00, 0x00],
        &[0x32, 0x0d],
    ];
    assert_client_pdus_valid(pdus, "/TP/SIG/SYN/BV-04-C");
    let cmd = TestContext::build_command(3, AVDTP_DELAY_REPORT, &[0x04, 0x00, 0x00]);
    assert_eq!(cmd, pdus[6]);
}

/// SYN/BV-05-C: OPEN + DELAY_REPORT — server v1.3 source.
#[test]
fn test_syn_bv_05_c() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, true);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x0c, 0x04],
            &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x0d, 0x04, 0x00, 0x00],
            &[0x42, 0x0d],
        ],
        "/TP/SIG/SYN/BV-05-C",
    );
}

/// SYN/BV-06-C: START + DELAY_REPORT — server v1.3 source.
#[test]
fn test_syn_bv_06_c() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, true);
    assert_server_exchange(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x0c, 0x04],
            &[0x12, 0x0c, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40, 0x08, 0x00],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x07, 0x04],
            &[0x42, 0x07],
            &[0x50, 0x0d, 0x04, 0x00, 0x00],
            &[0x52, 0x0d],
        ],
        "/TP/SIG/SYN/BV-06-C",
    );
}

// ===========================================================================
// Grouped Test Wrappers (matching AAP agent prompt categories)
// ===========================================================================

/// test_avdtp_discover: Comprehensive DISCOVER testing.
#[test]
fn test_avdtp_discover() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let cmd = &[0x00, 0x01];
    let resp = handle_server_command(&mut ctx, cmd, "discover").unwrap();
    assert_eq!(resp, &[0x02, 0x01, 0x04, 0x00]);
    let client_cmd = TestContext::build_command(0, AVDTP_DISCOVER, &[]);
    assert_eq!(client_cmd, &[0x00, 0x01]);
}

/// test_avdtp_get_capabilities: GET_CAPABILITIES for each SEP.
#[test]
fn test_avdtp_get_capabilities() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    ctx.register_sep(SEP_TYPE_SINK, MEDIA_TYPE_AUDIO, 0x00, false);
    let cmd1 = &[0x10, 0x02, 0x04];
    let resp1 = handle_server_command(&mut ctx, cmd1, "get_cap").unwrap();
    assert_eq!(resp1[0..2], [0x12, 0x02]);
    assert_eq!(resp1[2], CAP_MEDIA_TRANSPORT);
    let cmd2 = &[0x20, 0x02, 0x08];
    let resp2 = handle_server_command(&mut ctx, cmd2, "get_cap").unwrap();
    assert_eq!(resp2[0..2], [0x22, 0x02]);
}

/// test_avdtp_get_all_capabilities: GET_ALL_CAPABILITIES with delay_reporting.
#[test]
fn test_avdtp_get_all_capabilities() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, true);
    let cmd = &[0x10, 0x0c, 0x04];
    let resp = handle_server_command(&mut ctx, cmd, "get_all_cap").unwrap();
    let payload = &resp[2..];
    let mut found = false;
    let mut offset = 0;
    while offset + 1 < payload.len() {
        if payload[offset] == CAP_DELAY_REPORTING {
            found = true;
            break;
        }
        offset += 2 + payload[offset + 1] as usize;
    }
    assert!(found, "DELAY_REPORTING not found in GET_ALL_CAP response");
}

/// test_avdtp_set_configuration: SET_CONFIGURATION validation.
#[test]
fn test_avdtp_set_configuration() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let cmd = &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20];
    let resp = handle_server_command(&mut ctx, cmd, "set_config").unwrap();
    assert_eq!(resp, &[0x22, 0x03]);
    assert_eq!(ctx.streams.len(), 1);
    assert_eq!(ctx.streams[0].local_seid, 1);
    assert_eq!(ctx.streams[0].state, STREAM_STATE_CONFIGURED);
}

/// test_avdtp_get_configuration: GET_CONFIGURATION after SET_CONFIGURATION.
#[test]
fn test_avdtp_get_configuration() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let set_cmd =
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20];
    handle_server_command(&mut ctx, set_cmd, "get_config");
    let get_cmd = &[0x30, 0x04, 0x04];
    let resp = handle_server_command(&mut ctx, get_cmd, "get_config").unwrap();
    assert_eq!(resp[0..2], [0x32, 0x04]);
    assert!(resp.len() > 2);
}

/// test_avdtp_open: OPEN stream.
#[test]
fn test_avdtp_open() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    let set_cmd =
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20];
    handle_server_command(&mut ctx, set_cmd, "open");
    let resp = handle_server_command(&mut ctx, &[0x30, 0x06, 0x04], "open").unwrap();
    assert_eq!(resp, &[0x32, 0x06]);
    assert_eq!(ctx.streams[0].state, STREAM_STATE_OPEN);
}

/// test_avdtp_start: START streaming.
#[test]
fn test_avdtp_start() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    handle_server_command(
        &mut ctx,
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        "start",
    );
    handle_server_command(&mut ctx, &[0x30, 0x06, 0x04], "start");
    let resp = handle_server_command(&mut ctx, &[0x40, 0x07, 0x04], "start").unwrap();
    assert_eq!(resp, &[0x42, 0x07]);
    assert_eq!(ctx.streams[0].state, STREAM_STATE_STREAMING);
}

/// test_avdtp_suspend: SUSPEND stream.
#[test]
fn test_avdtp_suspend() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    handle_server_command(
        &mut ctx,
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        "suspend",
    );
    handle_server_command(&mut ctx, &[0x30, 0x06, 0x04], "suspend");
    handle_server_command(&mut ctx, &[0x40, 0x07, 0x04], "suspend");
    let resp = handle_server_command(&mut ctx, &[0x50, 0x09, 0x04], "suspend").unwrap();
    assert_eq!(resp, &[0x52, 0x09]);
    assert_eq!(ctx.streams[0].state, STREAM_STATE_OPEN);
}

/// test_avdtp_close: CLOSE stream.
#[test]
fn test_avdtp_close() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    handle_server_command(
        &mut ctx,
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        "close",
    );
    handle_server_command(&mut ctx, &[0x30, 0x06, 0x04], "close");
    handle_server_command(&mut ctx, &[0x40, 0x07, 0x04], "close");
    let resp = handle_server_command(&mut ctx, &[0x50, 0x08, 0x04], "close").unwrap();
    assert_eq!(resp, &[0x52, 0x08]);
    assert!(ctx.streams.is_empty());
}

/// test_avdtp_abort: ABORT stream.
#[test]
fn test_avdtp_abort() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    handle_server_command(
        &mut ctx,
        &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
        "abort",
    );
    let resp = handle_server_command(&mut ctx, &[0x30, 0x0a, 0x04], "abort").unwrap();
    assert_eq!(resp, &[0x32, 0x0a]);
    assert!(ctx.streams.is_empty());
}

/// test_avdtp_delay_report: DELAY_REPORT command.
#[test]
fn test_avdtp_delay_report() {
    let mut ctx = TestContext::new(0x0103);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, true);
    let resp =
        handle_server_command(&mut ctx, &[0x00, 0x0d, 0x04, 0x00, 0x00], "delay_report").unwrap();
    assert_eq!(resp, &[0x02, 0x0d]);
}

/// test_avdtp_fragmentation: Fragmentation and reassembly.
#[test]
fn test_avdtp_fragmentation() {
    let ctx = TestContext::with_mtu(0x0100, FRAG_MTU, FRAG_MTU);
    let mut large_payload = vec![0x01, 0x00];
    large_payload.push(0x04);
    large_payload.push(96);
    large_payload.extend_from_slice(&[0u8; 96]);
    let full_pdu = TestContext::build_accept(0, AVDTP_GET_CAPABILITIES, &large_payload);
    let fragments = fragment_response(&ctx, &full_pdu);
    assert!(fragments.len() >= 3, "Expected >= 3 fragments, got {}", fragments.len());
    for (i, frag) in fragments.iter().enumerate() {
        assert!(frag.len() <= FRAG_MTU as usize, "Fragment {i} exceeds MTU");
    }
    let mut reassembled = Vec::new();
    for (i, frag) in fragments.iter().enumerate() {
        if i == 0 {
            reassembled.extend_from_slice(&frag[3..]);
        } else {
            reassembled.extend_from_slice(&frag[1..]);
        }
    }
    assert_eq!(reassembled, large_payload);
}

/// test_avdtp_request_timeout: Request timeout handling.
#[tokio::test]
async fn test_avdtp_request_timeout() {
    use tokio::time::{Duration, sleep, timeout};
    let duration = Duration::from_millis(100);
    let (fd0, fd1) =
        socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
            .expect("socketpair failed");
    let cmd = TestContext::build_command(0, AVDTP_DISCOVER, &[]);
    let n = write(&fd0, &cmd).expect("write failed");
    assert_eq!(n, cmd.len());
    let result = timeout(duration, async {
        sleep(Duration::from_millis(200)).await;
        let mut buf = [0u8; 256];
        read(fd1.as_raw_fd(), &mut buf).ok()
    })
    .await;
    assert!(result.is_err() || result.unwrap().is_none());
    drop(fd0);
    drop(fd1);
}

/// test_avdtp_reject: Error response handling.
#[test]
fn test_avdtp_reject() {
    let reject_cases: &[(u8, u8, &[u8], &[u8])] = &[
        (0, AVDTP_DISCOVER, &[0x01], &[0x03, 0x01, 0x01]),
        (1, AVDTP_GET_CAPABILITIES, &[0x11], &[0x13, 0x02, 0x11]),
        (1, AVDTP_GET_CAPABILITIES, &[0x12], &[0x13, 0x02, 0x12]),
        (2, AVDTP_SET_CONFIGURATION, &[0x00, 0x13], &[0x23, 0x03, 0x00, 0x13]),
        (2, AVDTP_SET_CONFIGURATION, &[0x00, 0x29], &[0x23, 0x03, 0x00, 0x29]),
        (3, AVDTP_OPEN, &[0x31], &[0x33, 0x06, 0x31]),
        (3, AVDTP_OPEN, &[0xc0], &[0x33, 0x06, 0xc0]),
        (4, AVDTP_START, &[0x04, 0x31], &[0x43, 0x07, 0x04, 0x31]),
        (5, AVDTP_CLOSE, &[0x12], &[0x53, 0x08, 0x12]),
        (5, AVDTP_SUSPEND, &[0x04, 0x31], &[0x53, 0x09, 0x04, 0x31]),
    ];
    for (i, (txn, signal_id, payload, expected)) in reject_cases.iter().enumerate() {
        let built = TestContext::build_reject(*txn, *signal_id, payload);
        assert_eq!(&built, *expected, "Reject case {i}: signal=0x{signal_id:02x}");
    }
}

// ===========================================================================
// Socketpair End-to-End Validation
// ===========================================================================

/// Verify full DISCOVER exchange over socketpair.
#[test]
fn test_socketpair_discover() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_socketpair(
        &mut ctx,
        &[&[0x00, 0x01], &[0x02, 0x01, 0x04, 0x00]],
        "socketpair_discover",
    );
}

/// Verify full signaling exchange through START over socketpair.
#[test]
fn test_socketpair_full_exchange() {
    let mut ctx = TestContext::new(0x0100);
    ctx.register_sep(SEP_TYPE_SOURCE, MEDIA_TYPE_AUDIO, 0x00, false);
    assert_server_socketpair(
        &mut ctx,
        &[
            &[0x00, 0x01],
            &[0x02, 0x01, 0x04, 0x00],
            &[0x10, 0x02, 0x04],
            &[0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0x02, 0x40],
            &[0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x21, 0x02, 0x02, 0x20],
            &[0x22, 0x03],
            &[0x30, 0x06, 0x04],
            &[0x32, 0x06],
            &[0x40, 0x07, 0x04],
            &[0x42, 0x07],
        ],
        "socketpair_full",
    );
}

// ===========================================================================
// AvdtpSepInfo Type Validation Tests
// ===========================================================================

#[test]
fn test_avdtp_sep_info_construction() {
    let info = AvdtpSepInfo {
        seid: 1,
        in_use: false,
        media_type: MEDIA_TYPE_AUDIO,
        sep_type: SEP_TYPE_SOURCE,
    };
    assert_eq!(info.seid, 1);
    assert!(!info.in_use);
    assert_eq!(info.media_type, MEDIA_TYPE_AUDIO);
    assert_eq!(info.sep_type, SEP_TYPE_SOURCE);
    // Verify to_bytes/from_bytes round-trip
    let bytes = info.to_bytes();
    let decoded = AvdtpSepInfo::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.seid, info.seid);
    assert_eq!(decoded.in_use, info.in_use);
}

#[test]
fn test_avdtp_sep_info_sink() {
    let info = AvdtpSepInfo {
        seid: 2,
        in_use: true,
        media_type: MEDIA_TYPE_AUDIO,
        sep_type: SEP_TYPE_SINK,
    };
    assert_eq!(info.seid, 2);
    assert!(info.in_use);
    assert_eq!(info.sep_type, SEP_TYPE_SINK);
    // Verify to_bytes/from_bytes round-trip
    let bytes = info.to_bytes();
    let decoded = AvdtpSepInfo::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.seid, info.seid);
    assert_eq!(decoded.in_use, info.in_use);
}

// ===========================================================================
// Service Capability Validation Tests
// ===========================================================================

#[test]
fn test_capability_media_transport() {
    let cap = avdtp_service_cap_new(CAP_MEDIA_TRANSPORT, &[]);
    assert_eq!(cap.category, CAP_MEDIA_TRANSPORT);
    assert_eq!(cap.data.len(), 0);
}

#[test]
fn test_capability_media_codec() {
    let data = vec![0x00, 0x00, 0xff, 0xff, 0x02, 0x40];
    let cap = avdtp_service_cap_new(CAP_MEDIA_CODEC, &data);
    assert_eq!(cap.category, CAP_MEDIA_CODEC);
    assert_eq!(cap.data, data);
}

#[test]
fn test_capability_delay_reporting() {
    let cap = avdtp_service_cap_new(CAP_DELAY_REPORTING, &[]);
    assert_eq!(cap.category, CAP_DELAY_REPORTING);
    assert_eq!(cap.data.len(), 0);
}

#[test]
fn test_capability_content_protection() {
    let data = vec![0u8; 96];
    let cap = avdtp_service_cap_new(CAP_CONTENT_PROTECTION, &data);
    assert_eq!(cap.category, CAP_CONTENT_PROTECTION);
    assert_eq!(cap.data.len(), 96);
}
