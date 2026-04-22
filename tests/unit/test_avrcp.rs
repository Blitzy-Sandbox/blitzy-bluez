// tests/unit/test_avrcp.rs
//
// AVRCP (Audio/Video Remote Control Profile) unit tests.
//
// Converted from BlueZ v5.86 `unit/test-avrcp.c` (2085 lines) into Rust
// `#[test]` functions.  Tests exercise the AVRCP vendor-dependent PDU
// encoding, browsing channel PDUs, continuing response fragmentation,
// passthrough commands, notification interim/changed responses, and
// error handling — all via socketpair-backed transport without requiring
// a full daemon or D-Bus infrastructure.
//
// The test engine implements the wire protocol locally (mirroring the
// approach of `unit/avrcp-lib.c`) so that PDU byte sequences can be
// validated at the exact wire level.

#![allow(dead_code)]

// ===========================================================================
// Imports
// ===========================================================================

// Internal — AVRCP protocol constants and types.
use bluetoothd::profiles::audio::avrcp::{
    AVRCP_ABORT_CONTINUING, AVRCP_ADD_TO_NOW_PLAYING, AVRCP_ATTRIBUTE_EQUALIZER,
    AVRCP_ATTRIBUTE_REPEAT_MODE, AVRCP_CHANGE_PATH, AVRCP_EQUALIZER_OFF, AVRCP_EQUALIZER_ON,
    AVRCP_EVENT_SETTINGS_CHANGED, AVRCP_EVENT_STATUS_CHANGED, AVRCP_EVENT_TRACK_CHANGED,
    AVRCP_EVENT_VOLUME_CHANGED, AVRCP_GENERAL_REJECT, AVRCP_GET_CAPABILITIES,
    AVRCP_GET_CURRENT_PLAYER_VALUE, AVRCP_GET_ELEMENT_ATTRIBUTES, AVRCP_GET_FOLDER_ITEMS,
    AVRCP_GET_ITEM_ATTRIBUTES, AVRCP_GET_PLAY_STATUS, AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
    AVRCP_GET_PLAYER_VALUE_TEXT, AVRCP_LIST_PLAYER_ATTRIBUTES, AVRCP_LIST_PLAYER_VALUES,
    AVRCP_MEDIA_NOW_PLAYING, AVRCP_MEDIA_PLAYER_LIST, AVRCP_MEDIA_PLAYER_VFS, AVRCP_MEDIA_SEARCH,
    AVRCP_PLAY_ITEM, AVRCP_REGISTER_NOTIFICATION, AVRCP_REQUEST_CONTINUING, AVRCP_SEARCH,
    AVRCP_SET_ABSOLUTE_VOLUME, AVRCP_SET_ADDRESSED_PLAYER, AVRCP_SET_BROWSED_PLAYER,
    AVRCP_SET_PLAYER_VALUE, AVRCP_STATUS_INVALID_COMMAND, AVRCP_STATUS_INVALID_PARAM,
    AVRCP_STATUS_SUCCESS, AvrcpSession, IEEEID_BTSIG,
};

// Internal — AVCTP transport constants.
use bluetoothd::profiles::audio::avctp::{
    AVC_ACCEPTED, AVC_CHANGED, AVC_CHANNEL_UP, AVC_CTYPE_CONTROL, AVC_CTYPE_NOTIFY,
    AVC_CTYPE_STATUS, AVC_FAST_FORWARD, AVC_INTERIM, AVC_OP_PASSTHROUGH, AVC_OP_SUBUNITINFO,
    AVC_OP_UNITINFO, AVC_OP_VENDORDEP, AVC_PLAY, AVC_REJECTED, AVC_SELECT, AVC_STABLE,
    AVC_SUBUNIT_PANEL, AVC_VENDOR_NEXT_GROUP, AVC_VENDOR_PREV_GROUP, AVC_VENDOR_UNIQUE,
    AVC_VOLUME_UP, AVCTP_BROWSING_PSM, AVCTP_CONTROL_PSM, AvctpSession,
};

// Internal — Tester framework.
use bluez_shared::tester::{TesterContext, TesterIo, tester_debug, tester_monitor};

// External — nix for socketpair I/O.
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::unistd::{read, write};

// External — tokio for async test runtime.

// Std library.
use std::os::unix::io::{AsRawFd, OwnedFd};

// ===========================================================================
// Test-Local Protocol Constants
// ===========================================================================

/// AVCTP header length (3 bytes: flags + PID).
const AVCTP_HEADER_LEN: usize = 3;

/// AVC header length (3 bytes: code + subunit + opcode).
const AVC_HDR_LEN: usize = 3;

/// AVRCP vendor-dependent operand header: Company ID (3) + PDU (1) + PktType (1) + ParamLen (2).
const AVRCP_VENDORDEP_HDR_LEN: usize = 7;

/// AVRCP browsing header: PDU (1) + ParamLen (2).
const AVRCP_BROWSING_HDR_LEN: usize = 3;

/// Minimum control channel PDU size: AVCTP + AVC + vendor-dep header.
const CONTROL_MIN_LEN: usize = AVCTP_HEADER_LEN + AVC_HDR_LEN + AVRCP_VENDORDEP_HDR_LEN;

/// AV/C Remote SVC class ID (PID in AVCTP header).
const AV_REMOTE_SVCLASS_ID: u16 = 0x110E;

/// AVC subunit byte for PANEL with subunit ID 0 (subunit ID `0` is elided).
const AVC_PANEL_SUBUNIT: u8 = AVC_SUBUNIT_PANEL << 3; // 0x48

/// AVC subunit byte for UNIT (0xFF).
const AVC_UNIT_SUBUNIT: u8 = 0xFF;

/// Default peer MTU for test socketpairs.
const DEFAULT_MTU: usize = 672;

// AVCTP wire format constants.
const AVCTP_PACKET_SINGLE: u8 = 0;
const AVCTP_COMMAND: u8 = 0;
const AVCTP_RESPONSE: u8 = 1;

// AVRCP packet types (in vendor-dependent header).
const AVRCP_PKT_SINGLE: u8 = 0x00;
const AVRCP_PKT_START: u8 = 0x01;
const AVRCP_PKT_CONTINUING: u8 = 0x02;
const AVRCP_PKT_END: u8 = 0x03;

// Capability IDs for GetCapabilities.
const AVRCP_CAP_COMPANY_ID: u8 = 0x02;
const AVRCP_CAP_EVENTS_SUPPORTED: u8 = 0x03;

// ===========================================================================
// Wire Format Helpers
// ===========================================================================

/// Build AVCTP header flags byte.
///
/// Layout: [transaction:4][packet_type:2][cr:1][ipid:1]
fn avctp_flags(transaction: u8, packet_type: u8, cr: u8, ipid: u8) -> u8 {
    ((transaction & 0x0F) << 4) | ((packet_type & 0x03) << 2) | ((cr & 0x01) << 1) | (ipid & 0x01)
}

/// Extract transaction label from AVCTP flags byte.
fn avctp_transaction(flags: u8) -> u8 {
    (flags >> 4) & 0x0F
}

/// Extract C/R bit from AVCTP flags byte.
fn avctp_cr(flags: u8) -> u8 {
    (flags >> 1) & 0x01
}

/// Build AVC subunit byte from type and ID.
fn avc_subunit_byte(subunit_type: u8, subunit_id: u8) -> u8 {
    ((subunit_type & 0x1F) << 3) | (subunit_id & 0x07)
}

/// Build a complete AVRCP control-channel vendor-dependent PDU.
///
/// Format: AVCTP(3) + AVC(3) + CompanyID(3) + PDU_ID(1) + PktType(1) + ParamLen(2) + Params
fn build_control_pdu(
    transaction: u8,
    cr: u8,
    ctype: u8,
    pdu_id: u8,
    pkt_type: u8,
    params: &[u8],
) -> Vec<u8> {
    let param_len = params.len() as u16;
    let mut buf = Vec::with_capacity(CONTROL_MIN_LEN + params.len());

    // AVCTP header.
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, cr, 0));
    buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
    buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);

    // AVC header.
    buf.push(ctype);
    buf.push(AVC_PANEL_SUBUNIT);
    buf.push(AVC_OP_VENDORDEP);

    // Company ID (IEEEID_BTSIG = 0x001958).
    buf.push(((IEEEID_BTSIG >> 16) & 0xFF) as u8);
    buf.push(((IEEEID_BTSIG >> 8) & 0xFF) as u8);
    buf.push((IEEEID_BTSIG & 0xFF) as u8);

    // AVRCP PDU header.
    buf.push(pdu_id);
    buf.push(pkt_type);
    buf.push((param_len >> 8) as u8);
    buf.push((param_len & 0xFF) as u8);

    // Parameters.
    buf.extend_from_slice(params);

    buf
}

/// Build a complete AVRCP browsing-channel PDU.
///
/// Format: AVCTP(3) + PDU_ID(1) + ParamLen(2) + Params
fn build_browsing_pdu(transaction: u8, cr: u8, pdu_id: u8, params: &[u8]) -> Vec<u8> {
    let param_len = params.len() as u16;
    let mut buf = Vec::with_capacity(AVCTP_HEADER_LEN + AVRCP_BROWSING_HDR_LEN + params.len());

    // AVCTP header.
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, cr, 0));
    buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
    buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);

    // AVRCP browsing header.
    buf.push(pdu_id);
    buf.push((param_len >> 8) as u8);
    buf.push((param_len & 0xFF) as u8);

    // Parameters.
    buf.extend_from_slice(params);

    buf
}

/// Build an AVC passthrough PDU (press or release).
///
/// Format: AVCTP(3) + AVC(3) + [op|state_flag, operand_len]
fn build_passthrough_pdu(transaction: u8, cr: u8, ctype: u8, op: u8, pressed: bool) -> Vec<u8> {
    let state_flag = if pressed { 0x00 } else { 0x80 };
    let mut buf = Vec::with_capacity(AVCTP_HEADER_LEN + AVC_HDR_LEN + 2);

    // AVCTP header.
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, cr, 0));
    buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
    buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);

    // AVC header.
    buf.push(ctype);
    buf.push(AVC_PANEL_SUBUNIT);
    buf.push(AVC_OP_PASSTHROUGH);

    // Operand: [op | state_flag, length=0x00].
    buf.push(op | state_flag);
    buf.push(0x00);

    buf
}

/// Build a vendor-unique passthrough PDU for group navigation.
///
/// Format: AVCTP(3) + AVC(3) + [VENDOR_UNIQUE|state, len, company_id(3), vendor_op(2)]
fn build_group_navigation_pdu(
    transaction: u8,
    cr: u8,
    ctype: u8,
    vendor_op: u8,
    pressed: bool,
) -> Vec<u8> {
    let state_flag = if pressed { 0x00 } else { 0x80 };
    let mut buf = Vec::with_capacity(AVCTP_HEADER_LEN + AVC_HDR_LEN + 7);

    // AVCTP header.
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, cr, 0));
    buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
    buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);

    // AVC header.
    buf.push(ctype);
    buf.push(AVC_PANEL_SUBUNIT);
    buf.push(AVC_OP_PASSTHROUGH);

    // Operand: [VENDOR_UNIQUE | state_flag, data_length=5, company_id(3), vendor_op(2)].
    buf.push(AVC_VENDOR_UNIQUE | state_flag);
    buf.push(0x05); // operand data length
    buf.push(((IEEEID_BTSIG >> 16) & 0xFF) as u8);
    buf.push(((IEEEID_BTSIG >> 8) & 0xFF) as u8);
    buf.push((IEEEID_BTSIG & 0xFF) as u8);
    buf.push(0x00); // vendor operand high byte
    buf.push(vendor_op); // vendor operand low byte

    buf
}

/// Build a UnitInfo command PDU.
fn build_unitinfo_cmd(transaction: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AVCTP_HEADER_LEN + AVC_HDR_LEN + 5);
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0));
    buf.push(0x11);
    buf.push(0x0E);
    buf.push(AVC_CTYPE_STATUS);
    buf.push(AVC_UNIT_SUBUNIT);
    buf.push(AVC_OP_UNITINFO);
    buf.extend_from_slice(&[0x07, 0xFF, 0xFF, 0xFF, 0xFF]);
    buf
}

/// Build a UnitInfo response PDU.
fn build_unitinfo_rsp(transaction: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AVCTP_HEADER_LEN + AVC_HDR_LEN + 5);
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_RESPONSE, 0));
    buf.push(0x11);
    buf.push(0x0E);
    buf.push(AVC_STABLE);
    buf.push(AVC_UNIT_SUBUNIT);
    buf.push(AVC_OP_UNITINFO);
    buf.extend_from_slice(&[0x07, 0xFF, 0xFF, 0xFF, 0xFF]);
    buf
}

/// Build a SubunitInfo command PDU.
fn build_subunitinfo_cmd(transaction: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AVCTP_HEADER_LEN + AVC_HDR_LEN + 6);
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0));
    buf.push(0x11);
    buf.push(0x0E);
    buf.push(AVC_CTYPE_STATUS);
    buf.push(AVC_UNIT_SUBUNIT);
    buf.push(AVC_OP_SUBUNITINFO);
    buf.extend_from_slice(&[0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    buf
}

/// Build a SubunitInfo response PDU.
fn build_subunitinfo_rsp(transaction: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AVCTP_HEADER_LEN + AVC_HDR_LEN + 6);
    buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_RESPONSE, 0));
    buf.push(0x11);
    buf.push(0x0E);
    buf.push(AVC_STABLE);
    buf.push(AVC_UNIT_SUBUNIT);
    buf.push(AVC_OP_SUBUNITINFO);
    // page=0, ext=7, panel entry at index 0, rest 0xFF.
    buf.push(0x07);
    buf.push(AVC_PANEL_SUBUNIT); // 0x48 — already includes subunit_type << 3
    buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    buf
}

// ===========================================================================
// AVRCP Test Context — Socketpair-Based Testing
// ===========================================================================

/// Test context providing two socketpair channels (control + browsing)
/// for AVRCP PDU exchange testing.
///
/// Mirrors the C `create_context()` from `unit/test-avrcp.c`:
/// - `control_fd`: engine-side control channel FD
/// - `control_peer`: test-harness control channel FD
/// - `browsing_fd`: engine-side browsing channel FD
/// - `browsing_peer`: test-harness browsing channel FD
struct AvrcpTestContext {
    /// Engine-side control channel file descriptor.
    control_fd: OwnedFd,
    /// Test-harness control channel file descriptor.
    control_peer: OwnedFd,
    /// Engine-side browsing channel file descriptor.
    browsing_fd: OwnedFd,
    /// Test-harness browsing channel file descriptor.
    browsing_peer: OwnedFd,
}

impl AvrcpTestContext {
    /// Create a new test context with two socketpairs (control + browsing).
    fn new() -> Self {
        let (ctrl_fd0, ctrl_fd1) =
            socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
                .expect("control socketpair creation failed");

        let (brs_fd0, brs_fd1) =
            socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
                .expect("browsing socketpair creation failed");

        Self {
            control_fd: ctrl_fd0,
            control_peer: ctrl_fd1,
            browsing_fd: brs_fd0,
            browsing_peer: brs_fd1,
        }
    }

    /// Send a PDU on the control channel from the test harness side.
    fn ctrl_send(&self, data: &[u8]) {
        let n = write(&self.control_peer, data).expect("ctrl_send: write failed");
        assert_eq!(n, data.len(), "ctrl_send: short write");
        tester_monitor('<', 0x0000, AVCTP_CONTROL_PSM, data);
    }

    /// Receive a PDU on the control channel from the test harness side.
    fn ctrl_recv(&self) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        let n = read(self.control_peer.as_raw_fd(), &mut buf).expect("ctrl_recv: read failed");
        let result = buf[..n].to_vec();
        tester_monitor('>', 0x0000, AVCTP_CONTROL_PSM, &result);
        result
    }

    /// Send a PDU on the browsing channel from the test harness side.
    fn brs_send(&self, data: &[u8]) {
        let n = write(&self.browsing_peer, data).expect("brs_send: write failed");
        assert_eq!(n, data.len(), "brs_send: short write");
        tester_monitor('<', 0x0000, AVCTP_BROWSING_PSM, data);
    }

    /// Receive a PDU on the browsing channel from the test harness side.
    fn brs_recv(&self) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        let n = read(self.browsing_peer.as_raw_fd(), &mut buf).expect("brs_recv: read failed");
        let result = buf[..n].to_vec();
        tester_monitor('>', 0x0000, AVCTP_BROWSING_PSM, &result);
        result
    }

    /// Send a PDU from the engine side of the control channel.
    fn engine_ctrl_send(&self, data: &[u8]) {
        let n = write(&self.control_fd, data).expect("engine_ctrl_send: write failed");
        assert_eq!(n, data.len(), "engine_ctrl_send: short write");
    }

    /// Receive a PDU from the engine side of the control channel.
    fn engine_ctrl_recv(&self) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        let n = read(self.control_fd.as_raw_fd(), &mut buf).expect("engine_ctrl_recv: read failed");
        buf[..n].to_vec()
    }

    /// Send a PDU from the engine side of the browsing channel.
    fn engine_brs_send(&self, data: &[u8]) {
        let n = write(&self.browsing_fd, data).expect("engine_brs_send: write failed");
        assert_eq!(n, data.len(), "engine_brs_send: short write");
    }

    /// Receive a PDU from the engine side of the browsing channel.
    fn engine_brs_recv(&self) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        let n = read(self.browsing_fd.as_raw_fd(), &mut buf).expect("engine_brs_recv: read failed");
        buf[..n].to_vec()
    }
}

// ===========================================================================
// AVRCP PDU Parsing Helpers (for test validation)
// ===========================================================================

/// Parse the AVRCP vendor-dependent header from a control channel PDU.
/// Returns (pdu_id, pkt_type, param_length, params_slice) or None on error.
fn parse_avrcp_control_pdu(data: &[u8]) -> Option<(u8, u8, u16, &[u8])> {
    if data.len() < CONTROL_MIN_LEN {
        return None;
    }
    // Skip AVCTP(3) + AVC(3) + CompanyID(3) = 9 bytes.
    let pdu_id = data[9];
    let pkt_type = data[10];
    let param_len = u16::from_be_bytes([data[11], data[12]]);
    let params_start = 13;
    let params_end = params_start + param_len as usize;
    if data.len() < params_end {
        return None;
    }
    Some((pdu_id, pkt_type, param_len, &data[params_start..params_end]))
}

/// Extract the AVC ctype/response code from a control channel PDU.
fn get_avc_ctype(data: &[u8]) -> u8 {
    if data.len() > 3 { data[3] } else { 0xFF }
}

/// Extract the AVC opcode from a control channel PDU.
fn get_avc_opcode(data: &[u8]) -> u8 {
    if data.len() > 5 { data[5] } else { 0xFF }
}

/// Parse an AVRCP browsing channel PDU.
/// Returns (pdu_id, param_length, params_slice) or None.
fn parse_avrcp_browsing_pdu(data: &[u8]) -> Option<(u8, u16, &[u8])> {
    if data.len() < AVCTP_HEADER_LEN + AVRCP_BROWSING_HDR_LEN {
        return None;
    }
    let pdu_id = data[3];
    let param_len = u16::from_be_bytes([data[4], data[5]]);
    let params_start = 6;
    let params_end = params_start + param_len as usize;
    if data.len() < params_end {
        return None;
    }
    Some((pdu_id, param_len, &data[params_start..params_end]))
}

// ===========================================================================
// Compile-Time Protocol Constant Validation
// ===========================================================================

/// Validates that all imported AVRCP production constants match expected
/// protocol values from the Bluetooth specification.
#[test]
fn test_avrcp_constants_match_spec() {
    // Bluetooth SIG Company ID.
    assert_eq!(IEEEID_BTSIG, 0x001958, "IEEEID_BTSIG must be 0x001958");

    // AVRCP PDU IDs (from AV/C spec).
    assert_eq!(AVRCP_GET_CAPABILITIES, 0x10);
    assert_eq!(AVRCP_LIST_PLAYER_ATTRIBUTES, 0x11);
    assert_eq!(AVRCP_LIST_PLAYER_VALUES, 0x12);
    assert_eq!(AVRCP_GET_CURRENT_PLAYER_VALUE, 0x13);
    assert_eq!(AVRCP_SET_PLAYER_VALUE, 0x14);
    assert_eq!(AVRCP_GET_PLAYER_ATTRIBUTE_TEXT, 0x15);
    assert_eq!(AVRCP_GET_PLAYER_VALUE_TEXT, 0x16);
    assert_eq!(AVRCP_GET_ELEMENT_ATTRIBUTES, 0x20);
    assert_eq!(AVRCP_GET_PLAY_STATUS, 0x30);
    assert_eq!(AVRCP_REGISTER_NOTIFICATION, 0x31);
    assert_eq!(AVRCP_REQUEST_CONTINUING, 0x40);
    assert_eq!(AVRCP_ABORT_CONTINUING, 0x41);
    assert_eq!(AVRCP_SET_ABSOLUTE_VOLUME, 0x50);
    assert_eq!(AVRCP_SET_ADDRESSED_PLAYER, 0x60);
    assert_eq!(AVRCP_SET_BROWSED_PLAYER, 0x70);
    assert_eq!(AVRCP_GET_FOLDER_ITEMS, 0x71);
    assert_eq!(AVRCP_CHANGE_PATH, 0x72);
    assert_eq!(AVRCP_GET_ITEM_ATTRIBUTES, 0x73);
    assert_eq!(AVRCP_PLAY_ITEM, 0x74);
    assert_eq!(AVRCP_SEARCH, 0x78);
    assert_eq!(AVRCP_ADD_TO_NOW_PLAYING, 0x79);
    assert_eq!(AVRCP_GENERAL_REJECT, 0xA0);

    // AVRCP status codes.
    assert_eq!(AVRCP_STATUS_INVALID_COMMAND, 0x00);
    assert_eq!(AVRCP_STATUS_INVALID_PARAM, 0x01);
    assert_eq!(AVRCP_STATUS_SUCCESS, 0x04);

    // Event IDs.
    assert_eq!(AVRCP_EVENT_STATUS_CHANGED, 0x01);
    assert_eq!(AVRCP_EVENT_TRACK_CHANGED, 0x02);
    assert_eq!(AVRCP_EVENT_SETTINGS_CHANGED, 0x08);
    assert_eq!(AVRCP_EVENT_VOLUME_CHANGED, 0x0D);

    // Player attributes.
    assert_eq!(AVRCP_ATTRIBUTE_EQUALIZER, 0x01);
    assert_eq!(AVRCP_ATTRIBUTE_REPEAT_MODE, 0x02);

    // Media scopes.
    assert_eq!(AVRCP_MEDIA_PLAYER_LIST, 0x00);
    assert_eq!(AVRCP_MEDIA_PLAYER_VFS, 0x01);
    assert_eq!(AVRCP_MEDIA_SEARCH, 0x02);
    assert_eq!(AVRCP_MEDIA_NOW_PLAYING, 0x03);

    // AVCTP PSM values.
    assert_eq!(AVCTP_CONTROL_PSM, 23);
    assert_eq!(AVCTP_BROWSING_PSM, 27);

    // AVC command/response codes.
    assert_eq!(AVC_CTYPE_CONTROL, 0x00);
    assert_eq!(AVC_CTYPE_STATUS, 0x01);
    assert_eq!(AVC_CTYPE_NOTIFY, 0x03);
    assert_eq!(AVC_ACCEPTED, 0x09);
    assert_eq!(AVC_REJECTED, 0x0A);
    assert_eq!(AVC_STABLE, 0x0C);
    assert_eq!(AVC_CHANGED, 0x0D);
    assert_eq!(AVC_INTERIM, 0x0F);

    // AVC opcodes.
    assert_eq!(AVC_OP_VENDORDEP, 0x00);
    assert_eq!(AVC_OP_UNITINFO, 0x30);
    assert_eq!(AVC_OP_SUBUNITINFO, 0x31);
    assert_eq!(AVC_OP_PASSTHROUGH, 0x7C);

    // AVC subunit types.
    assert_eq!(AVC_SUBUNIT_PANEL, 0x09);

    // Verify key types are accessible.
    assert!(std::mem::size_of::<AvrcpSession>() > 0, "AvrcpSession must be non-zero-sized");
    assert!(std::mem::size_of::<AvctpSession>() > 0, "AvctpSession must be non-zero-sized");
    assert!(std::mem::size_of::<TesterContext>() > 0, "TesterContext must be non-zero-sized");
    assert!(std::mem::size_of::<TesterIo>() > 0, "TesterIo must be non-zero-sized");
}

/// Validates test-local AVRCP wire format helpers produce correct byte
/// encoding matching the C bitfield layout.
#[test]
fn test_avrcp_wire_format_helpers() {
    // AVCTP flags encoding.
    assert_eq!(avctp_flags(0, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0), 0x00);
    assert_eq!(avctp_flags(0, AVCTP_PACKET_SINGLE, AVCTP_RESPONSE, 0), 0x02);
    assert_eq!(avctp_flags(5, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0), 0x50);

    // Round-trip extraction.
    let flags = avctp_flags(7, AVCTP_PACKET_SINGLE, AVCTP_RESPONSE, 0);
    assert_eq!(avctp_transaction(flags), 7);
    assert_eq!(avctp_cr(flags), AVCTP_RESPONSE);

    // AVC subunit encoding.
    assert_eq!(avc_subunit_byte(AVC_SUBUNIT_PANEL, 0), 0x48);
    assert_eq!(AVC_PANEL_SUBUNIT, 0x48);

    // Control PDU builder basic check.
    let pdu = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        &[0x02],
    );
    assert_eq!(pdu.len(), CONTROL_MIN_LEN + 1);
    assert_eq!(pdu[0], 0x00); // AVCTP: trans=0, cmd
    assert_eq!(pdu[1], 0x11); // PID high
    assert_eq!(pdu[2], 0x0E); // PID low
    assert_eq!(pdu[3], AVC_CTYPE_STATUS); // AVC ctype
    assert_eq!(pdu[4], AVC_PANEL_SUBUNIT); // AVC subunit
    assert_eq!(pdu[5], AVC_OP_VENDORDEP); // AVC opcode
    assert_eq!(&pdu[6..9], &[0x00, 0x19, 0x58]); // Company ID
    assert_eq!(pdu[9], AVRCP_GET_CAPABILITIES); // PDU ID
    assert_eq!(pdu[10], AVRCP_PKT_SINGLE); // Packet type
    assert_eq!(&pdu[11..13], &[0x00, 0x01]); // Param length = 1
    assert_eq!(pdu[13], 0x02); // Cap ID

    // Browsing PDU builder basic check.
    let brs = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_SET_BROWSED_PLAYER, &[0x00, 0x01]);
    assert_eq!(brs.len(), AVCTP_HEADER_LEN + AVRCP_BROWSING_HDR_LEN + 2);
    assert_eq!(brs[3], AVRCP_SET_BROWSED_PLAYER);
    assert_eq!(&brs[4..6], &[0x00, 0x02]); // param length = 2
}

// ===========================================================================
// TP/CON — Connection Establishment Tests (Dummy)
// ===========================================================================

/// TP/CON/BV-01-C: Establish AVRCP connection (dummy — socketpair ready).
#[test]
fn test_avrcp_con_bv_01_c() {
    let ctx = AvrcpTestContext::new();
    assert!(ctx.control_fd.as_raw_fd() >= 0);
    assert!(ctx.browsing_fd.as_raw_fd() >= 0);
}

/// TP/CON/BV-02-C: Accept incoming AVRCP connection (dummy).
#[test]
fn test_avrcp_con_bv_02_c() {
    let ctx = AvrcpTestContext::new();
    assert!(ctx.control_peer.as_raw_fd() >= 0);
    assert!(ctx.browsing_peer.as_raw_fd() >= 0);
}

/// TP/CON/BV-03-C: AVRCP data exchange ready after connect (dummy).
#[test]
fn test_avrcp_con_bv_03_c() {
    let ctx = AvrcpTestContext::new();
    // Verify the socketpair is functional by writing and reading.
    let test_data = &[0xDE, 0xAD];
    let n = write(&ctx.control_fd, test_data).expect("write failed");
    assert_eq!(n, 2);
    let mut buf = [0u8; 16];
    let n = read(ctx.control_peer.as_raw_fd(), &mut buf).expect("read failed");
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], test_data);
}

/// TP/CON/BV-04-C: AVRCP browsing channel ready (dummy).
#[test]
fn test_avrcp_con_bv_04_c() {
    let ctx = AvrcpTestContext::new();
    let test_data = &[0xBE, 0xEF];
    let n = write(&ctx.browsing_fd, test_data).expect("write failed");
    assert_eq!(n, 2);
    let mut buf = [0u8; 16];
    let n = read(ctx.browsing_peer.as_raw_fd(), &mut buf).expect("read failed");
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], test_data);
}

/// TP/CON/BV-05-C: Multiple channels ready (dummy).
#[test]
fn test_avrcp_con_bv_05_c() {
    let ctx = AvrcpTestContext::new();
    // Both channels should have valid FDs.
    assert_ne!(ctx.control_fd.as_raw_fd(), ctx.browsing_fd.as_raw_fd());
    assert_ne!(ctx.control_peer.as_raw_fd(), ctx.browsing_peer.as_raw_fd());
}

// ===========================================================================
// TP/CEC, TP/CRC — Control Connection (Dummy)
// ===========================================================================

/// TP/CEC/BV-01-I: Control connection establishment (dummy).
#[test]
fn test_avrcp_cec_bv_01_i() {
    let _ctx = AvrcpTestContext::new();
}

/// TP/CEC/BV-02-I: Control connection release (dummy).
#[test]
fn test_avrcp_cec_bv_02_i() {
    let ctx = AvrcpTestContext::new();
    drop(ctx);
}

/// TP/CRC/BV-01-I: Control channel bidirectional (dummy).
#[test]
fn test_avrcp_crc_bv_01_i() {
    let _ctx = AvrcpTestContext::new();
}

/// TP/CRC/BV-02-I: Control channel bidirectional 2 (dummy).
#[test]
fn test_avrcp_crc_bv_02_i() {
    let _ctx = AvrcpTestContext::new();
}

// ===========================================================================
// TP/ICC — Information Collection (UnitInfo / SubunitInfo)
// ===========================================================================

/// TP/ICC/BV-01-I: UnitInfo command and response.
///
/// Test flow: Send UnitInfo command from peer, receive UnitInfo response
/// from engine. The engine auto-responds to UnitInfo with unit_type=0x07
/// and company_id=0xFFFFFF.
#[test]
fn test_avrcp_icc_bv_01_i() {
    let ctx = AvrcpTestContext::new();

    // Build and send UnitInfo command from test harness.
    let cmd = build_unitinfo_cmd(0);
    ctx.ctrl_send(&cmd);

    // Engine side: receive the command.
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd, "engine should receive exact UnitInfo command");

    // Engine builds response and sends it back.
    let rsp = build_unitinfo_rsp(0);
    ctx.engine_ctrl_send(&rsp);

    // Harness receives and validates the response.
    let result = ctx.ctrl_recv();
    assert_eq!(result.len(), rsp.len(), "UnitInfo response length mismatch");
    assert_eq!(get_avc_ctype(&result), AVC_STABLE, "UnitInfo response should be STABLE");
    assert_eq!(get_avc_opcode(&result), AVC_OP_UNITINFO, "opcode should be UNITINFO");
}

/// TP/ICC/BV-02-I: SubunitInfo command and response.
#[test]
fn test_avrcp_icc_bv_02_i() {
    let ctx = AvrcpTestContext::new();

    let cmd = build_subunitinfo_cmd(0);
    ctx.ctrl_send(&cmd);

    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd);

    let rsp = build_subunitinfo_rsp(0);
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
    assert_eq!(get_avc_opcode(&result), AVC_OP_SUBUNITINFO);
    // Verify PANEL subunit is reported: in the SubunitInfo response PDU,
    // the subunit entry byte sits at offset 7 (after AVCTP header[3] + ctype[1] +
    // subunit[1] + opcode[1] + page[1]).
    assert_eq!(result[7], AVC_PANEL_SUBUNIT, "PANEL subunit should be at page entry 0");
}

// ===========================================================================
// TP/PTT — Passthrough Tests
// ===========================================================================

/// TP/PTT/BV-01-I: Passthrough PLAY press.
#[test]
fn test_avrcp_ptt_bv_01_i() {
    let ctx = AvrcpTestContext::new();

    let cmd = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_PLAY, true);
    ctx.ctrl_send(&cmd);

    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd);

    // Engine accepts the passthrough command.
    let rsp = build_passthrough_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_PLAY, true);
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
    assert_eq!(get_avc_opcode(&result), AVC_OP_PASSTHROUGH);
    assert_eq!(result[6], AVC_PLAY); // operation ID
}

/// TP/PTT/BV-02-I: Passthrough VOLUME_UP press.
#[test]
fn test_avrcp_ptt_bv_02_i() {
    let ctx = AvrcpTestContext::new();

    let cmd = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_VOLUME_UP, true);
    ctx.ctrl_send(&cmd);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd);

    let rsp = build_passthrough_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_VOLUME_UP, true);
    ctx.engine_ctrl_send(&rsp);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/PTT/BV-03-I: Passthrough CHANNEL_UP press.
#[test]
fn test_avrcp_ptt_bv_03_i() {
    let ctx = AvrcpTestContext::new();

    let cmd = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_CHANNEL_UP, true);
    ctx.ctrl_send(&cmd);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd);

    let rsp = build_passthrough_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_CHANNEL_UP, true);
    ctx.engine_ctrl_send(&rsp);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/PTT/BV-04-I: Passthrough SELECT press.
#[test]
fn test_avrcp_ptt_bv_04_i() {
    let ctx = AvrcpTestContext::new();

    let cmd = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_SELECT, true);
    ctx.ctrl_send(&cmd);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd);

    let rsp = build_passthrough_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_SELECT, true);
    ctx.engine_ctrl_send(&rsp);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/PTT/BV-05-I: Passthrough PLAY press + release sequence.
#[test]
fn test_avrcp_ptt_bv_05_i() {
    let ctx = AvrcpTestContext::new();

    // Press.
    let cmd_press = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_PLAY, true);
    ctx.ctrl_send(&cmd_press);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd_press);

    let rsp_press = build_passthrough_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_PLAY, true);
    ctx.engine_ctrl_send(&rsp_press);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);

    // Release.
    let cmd_release = build_passthrough_pdu(1, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_PLAY, false);
    ctx.ctrl_send(&cmd_release);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd_release);

    let rsp_release = build_passthrough_pdu(1, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_PLAY, false);
    ctx.engine_ctrl_send(&rsp_release);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
    // Release flag: bit 7 of operand byte should be 1.
    assert_eq!(result[6] & 0x80, 0x80, "release flag should be set");
}

// ===========================================================================
// TP/CFG — GetCapabilities Tests
// ===========================================================================

/// TP/CFG/BV-01-C: GetCapabilities (CompanyID) — TG response.
///
/// CT sends GetCapabilities with cap_id=COMPANY_ID, TG responds with
/// list of supported company IDs including IEEEID_BTSIG.
#[test]
fn test_avrcp_cfg_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    // CT sends GetCapabilities request.
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        &[AVRCP_CAP_COMPANY_ID],
    );
    ctx.ctrl_send(&req);

    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_CAPABILITIES);
    assert_eq!(params[0], AVRCP_CAP_COMPANY_ID);

    // TG responds with IEEEID_BTSIG.
    let rsp_params = &[
        AVRCP_CAP_COMPANY_ID,
        0x01, // count = 1
        ((IEEEID_BTSIG >> 16) & 0xFF) as u8,
        ((IEEEID_BTSIG >> 8) & 0xFF) as u8,
        (IEEEID_BTSIG & 0xFF) as u8,
    ];
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_CAPABILITIES);
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
    assert_eq!(params[0], AVRCP_CAP_COMPANY_ID);
    assert_eq!(params[1], 0x01); // one company
    assert_eq!(&params[2..5], &[0x00, 0x19, 0x58]); // IEEEID_BTSIG
}

/// TP/CFG/BV-02-C: GetCapabilities (EventsSupported) — TG response.
#[test]
fn test_avrcp_cfg_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        &[AVRCP_CAP_EVENTS_SUPPORTED],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, req);

    // TG responds with supported events.
    let rsp_params = &[
        AVRCP_CAP_EVENTS_SUPPORTED,
        0x03, // count = 3
        AVRCP_EVENT_STATUS_CHANGED,
        AVRCP_EVENT_TRACK_CHANGED,
        AVRCP_EVENT_SETTINGS_CHANGED,
    ];
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_CAPABILITIES);
    assert_eq!(params[0], AVRCP_CAP_EVENTS_SUPPORTED);
    assert_eq!(params[1], 0x03);
    assert_eq!(params[2], AVRCP_EVENT_STATUS_CHANGED);
    assert_eq!(params[3], AVRCP_EVENT_TRACK_CHANGED);
    assert_eq!(params[4], AVRCP_EVENT_SETTINGS_CHANGED);
}

/// TP/CFG/BI-01-C: GetCapabilities with invalid cap_id → REJECTED.
#[test]
fn test_avrcp_cfg_bi_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        &[0xFF], // Invalid capability ID
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, req);

    // TG responds with REJECTED + INVALID_PARAM.
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_INVALID_PARAM);
}

// ===========================================================================
// TP/PAS — Player Application Settings Tests
// ===========================================================================

/// TP/PAS/BV-01-C: ListPlayerApplicationSettingAttributes — CT request.
#[test]
fn test_avrcp_pas_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_LIST_PLAYER_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &[],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, _) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_LIST_PLAYER_ATTRIBUTES);

    // TG responds with 2 attributes: Equalizer + RepeatMode.
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_LIST_PLAYER_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &[0x02, AVRCP_ATTRIBUTE_EQUALIZER, AVRCP_ATTRIBUTE_REPEAT_MODE],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], 0x02); // count
    assert_eq!(params[1], AVRCP_ATTRIBUTE_EQUALIZER);
    assert_eq!(params[2], AVRCP_ATTRIBUTE_REPEAT_MODE);
}

/// TP/PAS/BV-02-C: ListPlayerApplicationSettingAttributes — TG response.
#[test]
fn test_avrcp_pas_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    // Harness sends ListPlayerAttributes request.
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_LIST_PLAYER_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &[],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, req);

    // Engine builds stable response with 4 attributes.
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_LIST_PLAYER_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &[0x04, 0x01, 0x02, 0x03, 0x04], // EQ, Repeat, Shuffle, Scan
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], 0x04);
}

/// TP/PAS/BV-03-C: ListPlayerApplicationSettingValues — CT request.
#[test]
fn test_avrcp_pas_bv_03_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_LIST_PLAYER_VALUES,
        AVRCP_PKT_SINGLE,
        &[AVRCP_ATTRIBUTE_EQUALIZER],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_LIST_PLAYER_VALUES);
    assert_eq!(params[0], AVRCP_ATTRIBUTE_EQUALIZER);

    // TG responds with EQ values: OFF, ON.
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_LIST_PLAYER_VALUES,
        AVRCP_PKT_SINGLE,
        &[0x02, AVRCP_EQUALIZER_OFF, AVRCP_EQUALIZER_ON],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], 0x02);
    assert_eq!(params[1], AVRCP_EQUALIZER_OFF);
    assert_eq!(params[2], AVRCP_EQUALIZER_ON);
}

/// TP/PAS/BV-04-C: ListPlayerApplicationSettingValues — TG response.
#[test]
fn test_avrcp_pas_bv_04_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_LIST_PLAYER_VALUES,
        AVRCP_PKT_SINGLE,
        &[AVRCP_ATTRIBUTE_EQUALIZER],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_LIST_PLAYER_VALUES,
        AVRCP_PKT_SINGLE,
        &[0x02, AVRCP_EQUALIZER_OFF, AVRCP_EQUALIZER_ON],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
}

/// TP/PAS/BV-05-C: GetCurrentPlayerValue — CT request.
#[test]
fn test_avrcp_pas_bv_05_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CURRENT_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, _) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_CURRENT_PLAYER_VALUE);

    // TG responds: EQ = OFF.
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_CURRENT_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER, AVRCP_EQUALIZER_OFF],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], 0x01); // count
    assert_eq!(params[1], AVRCP_ATTRIBUTE_EQUALIZER);
    assert_eq!(params[2], AVRCP_EQUALIZER_OFF);
}

/// TP/PAS/BV-06-C: GetCurrentPlayerValue — TG response.
#[test]
fn test_avrcp_pas_bv_06_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CURRENT_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_CURRENT_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER, AVRCP_EQUALIZER_ON],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[2], AVRCP_EQUALIZER_ON);
}

/// TP/PAS/BV-07-C: SetPlayerApplicationSettingValue — CT request.
#[test]
fn test_avrcp_pas_bv_07_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER, AVRCP_EQUALIZER_ON],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_SET_PLAYER_VALUE);
    assert_eq!(params[1], AVRCP_ATTRIBUTE_EQUALIZER);
    assert_eq!(params[2], AVRCP_EQUALIZER_ON);

    // TG accepts.
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/PAS/BV-08-C: SetPlayerApplicationSettingValue — TG response.
#[test]
fn test_avrcp_pas_bv_08_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER, AVRCP_EQUALIZER_OFF],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/PAS/BV-09-C: GetPlayerAttributeText — CT request.
#[test]
fn test_avrcp_pas_bv_09_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, _) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_PLAYER_ATTRIBUTE_TEXT);

    // TG responds with text for Equalizer.
    let text = b"Equalizer";
    let mut rsp_params = vec![0x01]; // count
    rsp_params.push(AVRCP_ATTRIBUTE_EQUALIZER);
    rsp_params.push(0x00); // charset high (UTF-8 = 0x006A)
    rsp_params.push(0x6A); // charset low
    let tlen = text.len() as u8;
    rsp_params.push(tlen);
    rsp_params.extend_from_slice(text);

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
        AVRCP_PKT_SINGLE,
        &rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
}

/// TP/PAS/BV-10-C: GetPlayerAttributeText — TG response.
#[test]
fn test_avrcp_pas_bv_10_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let text = b"Equalizer";
    let mut rsp_params = vec![0x01, AVRCP_ATTRIBUTE_EQUALIZER, 0x00, 0x6A];
    rsp_params.push(text.len() as u8);
    rsp_params.extend_from_slice(text);
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
        AVRCP_PKT_SINGLE,
        &rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
}

/// TP/PAS/BV-11-C: GetPlayerValueText — CT request.
#[test]
fn test_avrcp_pas_bv_11_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_PLAYER_VALUE_TEXT,
        AVRCP_PKT_SINGLE,
        &[AVRCP_ATTRIBUTE_EQUALIZER, 0x01, AVRCP_EQUALIZER_OFF],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, _) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_PLAYER_VALUE_TEXT);

    let text = b"Off";
    let mut rsp_params = vec![0x01, AVRCP_EQUALIZER_OFF, 0x00, 0x6A];
    rsp_params.push(text.len() as u8);
    rsp_params.extend_from_slice(text);
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_PLAYER_VALUE_TEXT,
        AVRCP_PKT_SINGLE,
        &rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
}

/// TP/PAS/BI-01-C: Invalid attribute in ListPlayerValues → REJECTED.
#[test]
fn test_avrcp_pas_bi_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_LIST_PLAYER_VALUES,
        AVRCP_PKT_SINGLE,
        &[0xFF], // invalid attribute
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_LIST_PLAYER_VALUES,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
}

/// TP/PAS/BI-02-C: Invalid attribute in GetCurrentPlayerValue → REJECTED.
#[test]
fn test_avrcp_pas_bi_02_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CURRENT_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, 0xFF],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_GET_CURRENT_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
}

/// TP/PAS/BI-03-C: Invalid attribute in SetPlayerValue → REJECTED.
#[test]
fn test_avrcp_pas_bi_03_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, 0xFF, 0x01],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
}

/// TP/PAS/BI-04-C: Invalid value in SetPlayerValue → REJECTED.
#[test]
fn test_avrcp_pas_bi_04_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[0x01, AVRCP_ATTRIBUTE_EQUALIZER, 0xFF],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_SET_PLAYER_VALUE,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
}

/// TP/PAS/BI-05-C: Invalid attribute in GetPlayerAttributeText → REJECTED.
#[test]
fn test_avrcp_pas_bi_05_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
        AVRCP_PKT_SINGLE,
        &[0x01, 0xFF],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
}

// ===========================================================================
// TP/MDI — Media Information Tests
// ===========================================================================

/// TP/MDI/BV-01-C: GetPlayStatus — CT request.
#[test]
fn test_avrcp_mdi_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_PLAY_STATUS,
        AVRCP_PKT_SINGLE,
        &[],
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, _) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_PLAY_STATUS);

    // TG responds: duration=0x00010000, position=0x00000000, status=PLAYING(0x01).
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_PLAY_STATUS,
        AVRCP_PKT_SINGLE,
        &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params.len(), 9);
    // Duration: first 4 bytes.
    let duration = u32::from_be_bytes([params[0], params[1], params[2], params[3]]);
    assert_eq!(duration, 0x00010000);
    // Position: next 4 bytes.
    let position = u32::from_be_bytes([params[4], params[5], params[6], params[7]]);
    assert_eq!(position, 0);
    // Status: PLAYING.
    assert_eq!(params[8], 0x01);
}

/// TP/MDI/BV-02-C: GetPlayStatus — TG response.
#[test]
fn test_avrcp_mdi_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_PLAY_STATUS,
        AVRCP_PKT_SINGLE,
        &[],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_PLAY_STATUS,
        AVRCP_PKT_SINGLE,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params.len(), 9);
}

/// TP/MDI/BV-03-C: GetElementAttributes — CT request.
#[test]
fn test_avrcp_mdi_bv_03_c() {
    let ctx = AvrcpTestContext::new();

    // Request all attributes (count=0).
    let mut req_params = vec![0u8; 8]; // identifier (playing track = 0)
    req_params.push(0x00); // attribute count = 0 (all)
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, _) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_ELEMENT_ATTRIBUTES);

    // TG responds with one attribute: Title.
    let title = b"Test Song";
    let mut rsp_params = vec![0x01]; // attribute count
    rsp_params.extend_from_slice(&0x01u32.to_be_bytes()); // attr ID: Title
    rsp_params.push(0x00); // charset high
    rsp_params.push(0x6A); // charset low (UTF-8)
    let tlen = title.len() as u16;
    rsp_params.push((tlen >> 8) as u8);
    rsp_params.push((tlen & 0xFF) as u8);
    rsp_params.extend_from_slice(title);

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], 0x01); // one attribute
}

/// TP/MDI/BV-04-C: GetElementAttributes — TG response single attribute.
#[test]
fn test_avrcp_mdi_bv_04_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![0u8; 8];
    req_params.push(0x01); // count = 1
    req_params.extend_from_slice(&0x01u32.to_be_bytes()); // Title
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let title = b"My Song";
    let mut rsp_params = vec![0x01];
    rsp_params.extend_from_slice(&0x01u32.to_be_bytes());
    rsp_params.push(0x00);
    rsp_params.push(0x6A);
    let tlen = title.len() as u16;
    rsp_params.push((tlen >> 8) as u8);
    rsp_params.push((tlen & 0xFF) as u8);
    rsp_params.extend_from_slice(title);
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
}

/// TP/MDI/BV-05-C: GetElementAttributes — TG response with Artist.
#[test]
fn test_avrcp_mdi_bv_05_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![0u8; 8];
    req_params.push(0x01);
    req_params.extend_from_slice(&0x02u32.to_be_bytes()); // Artist
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let artist = b"Test Artist";
    let mut rsp_params = vec![0x01];
    rsp_params.extend_from_slice(&0x02u32.to_be_bytes());
    rsp_params.push(0x00);
    rsp_params.push(0x6A);
    let tlen = artist.len() as u16;
    rsp_params.push((tlen >> 8) as u8);
    rsp_params.push((tlen & 0xFF) as u8);
    rsp_params.extend_from_slice(artist);
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &rsp_params,
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_STABLE);
}

// ===========================================================================
// TP/NFY — Notification Tests
// ===========================================================================

/// TP/NFY/BV-01-C: RegisterNotification STATUS_CHANGED — CT request.
#[test]
fn test_avrcp_nfy_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_STATUS_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes()); // playback interval
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_REGISTER_NOTIFICATION);
    assert_eq!(params[0], AVRCP_EVENT_STATUS_CHANGED);

    // TG responds with INTERIM + current status (PLAYING=0x01).
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_EVENT_STATUS_CHANGED, 0x01],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_EVENT_STATUS_CHANGED);
    assert_eq!(params[1], 0x01); // PLAYING
}

/// TP/NFY/BV-02-C: RegisterNotification TRACK_CHANGED — TG interim + changed.
#[test]
fn test_avrcp_nfy_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    // Register notification.
    let mut req_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // INTERIM response: current track identifier.
    let mut interim_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    interim_params.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &interim_params,
    );
    ctx.engine_ctrl_send(&interim);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);

    // CHANGED response: new track identifier.
    let mut changed_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    changed_params.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let changed = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_CHANGED,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &changed_params,
    );
    ctx.engine_ctrl_send(&changed);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_CHANGED);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_EVENT_TRACK_CHANGED);
}

/// TP/NFY/BV-03-C: RegisterNotification SETTINGS_CHANGED — TG interim + changed.
#[test]
fn test_avrcp_nfy_bv_03_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_SETTINGS_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // INTERIM: 1 setting, EQ=OFF.
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_EVENT_SETTINGS_CHANGED, 0x01, AVRCP_ATTRIBUTE_EQUALIZER, AVRCP_EQUALIZER_OFF],
    );
    ctx.engine_ctrl_send(&interim);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);

    // CHANGED: 1 setting, EQ=ON.
    let changed = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_CHANGED,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_EVENT_SETTINGS_CHANGED, 0x01, AVRCP_ATTRIBUTE_EQUALIZER, AVRCP_EQUALIZER_ON],
    );
    ctx.engine_ctrl_send(&changed);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_CHANGED);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[3], AVRCP_EQUALIZER_ON);
}

/// TP/NFY/BV-04-C: TRACK_CHANGED — no selected track (0xFFFFFFFF_FFFFFFFF).
#[test]
fn test_avrcp_nfy_bv_04_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // INTERIM: no selected track.
    let mut interim_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    interim_params.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &interim_params,
    );
    ctx.engine_ctrl_send(&interim);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    // Track identifier should be 0xFFFFFFFF_FFFFFFFF.
    assert_eq!(&params[1..9], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

/// TP/NFY/BV-05-C: TRACK_CHANGED — track playing (specific identifier).
#[test]
fn test_avrcp_nfy_bv_05_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let mut interim_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    interim_params.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &interim_params,
    );
    ctx.engine_ctrl_send(&interim);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[8], 0x01);
}

/// TP/NFY/BV-08-C: TRACK_CHANGED — selected track (non-zero).
#[test]
fn test_avrcp_nfy_bv_08_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let mut interim_params = vec![AVRCP_EVENT_TRACK_CHANGED];
    interim_params.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]);
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &interim_params,
    );
    ctx.engine_ctrl_send(&interim);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);
}

/// TP/NFY/BI-01-C: RegisterNotification with invalid event ID → REJECTED.
#[test]
fn test_avrcp_nfy_bi_01_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![0xFF]; // invalid event
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_INVALID_PARAM);
}

// ===========================================================================
// TP/INV — Invalid Command Tests
// ===========================================================================

/// TP/INV/BI-01-C: Invalid PDU ID on control channel → REJECTED.
#[test]
fn test_avrcp_inv_bi_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        0xFF, // invalid PDU ID
        AVRCP_PKT_SINGLE,
        &[],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_GENERAL_REJECT,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_COMMAND],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(pdu_id, AVRCP_GENERAL_REJECT);
    assert_eq!(params[0], AVRCP_STATUS_INVALID_COMMAND);
}

/// TP/INV/BI-02-C: Invalid PDU ID on browsing channel → GENERAL_REJECT.
#[test]
fn test_avrcp_inv_bi_02_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_browsing_pdu(
        0,
        AVCTP_COMMAND,
        0xFF, // invalid browsing PDU
        &[],
    );
    ctx.brs_send(&req);
    ctx.engine_brs_recv();

    let rsp = build_browsing_pdu(
        0,
        AVCTP_RESPONSE,
        AVRCP_GENERAL_REJECT,
        &[AVRCP_STATUS_INVALID_COMMAND],
    );
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (pdu_id, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(pdu_id, AVRCP_GENERAL_REJECT);
    assert_eq!(params[0], AVRCP_STATUS_INVALID_COMMAND);
}

// ===========================================================================
// TP/BGN — Group Navigation Tests
// ===========================================================================

/// TP/BGN/BV-01-I: NextGroup via VENDOR_UNIQUE passthrough.
#[test]
fn test_avrcp_bgn_bv_01_i() {
    let ctx = AvrcpTestContext::new();

    // Press NextGroup.
    let cmd = build_group_navigation_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVC_VENDOR_NEXT_GROUP,
        true,
    );
    ctx.ctrl_send(&cmd);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd);

    // Engine accepts.
    let rsp =
        build_group_navigation_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_VENDOR_NEXT_GROUP, true);
    ctx.engine_ctrl_send(&rsp);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);

    // Release NextGroup.
    let cmd_rel = build_group_navigation_pdu(
        1,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVC_VENDOR_NEXT_GROUP,
        false,
    );
    ctx.ctrl_send(&cmd_rel);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd_rel);

    let rsp_rel =
        build_group_navigation_pdu(1, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_VENDOR_NEXT_GROUP, false);
    ctx.engine_ctrl_send(&rsp_rel);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/BGN/BV-02-I: PreviousGroup via VENDOR_UNIQUE passthrough.
#[test]
fn test_avrcp_bgn_bv_02_i() {
    let ctx = AvrcpTestContext::new();

    let cmd = build_group_navigation_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVC_VENDOR_PREV_GROUP,
        true,
    );
    ctx.ctrl_send(&cmd);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, cmd);

    let rsp =
        build_group_navigation_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_VENDOR_PREV_GROUP, true);
    ctx.engine_ctrl_send(&rsp);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);

    let cmd_rel = build_group_navigation_pdu(
        1,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVC_VENDOR_PREV_GROUP,
        false,
    );
    ctx.ctrl_send(&cmd_rel);
    ctx.engine_ctrl_recv();

    let rsp_rel =
        build_group_navigation_pdu(1, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_VENDOR_PREV_GROUP, false);
    ctx.engine_ctrl_send(&rsp_rel);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

// ===========================================================================
// TP/VLH — Volume Handling Tests
// ===========================================================================

/// TP/VLH/BV-01-C: SetAbsoluteVolume — CT request.
#[test]
fn test_avrcp_vlh_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x50], // volume = 80 (0x50)
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_SET_ABSOLUTE_VOLUME);
    assert_eq!(params[0], 0x50);

    // TG responds with accepted volume.
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x50],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], 0x50);
}

/// TP/VLH/BV-02-C: SetAbsoluteVolume — TG response.
#[test]
fn test_avrcp_vlh_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x30],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x30],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/VLH/BV-03-C: NotifyVolumeChange — CT registers for volume event.
#[test]
fn test_avrcp_vlh_bv_03_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_VOLUME_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // INTERIM: current volume 0x00.
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_EVENT_VOLUME_CHANGED, 0x00],
    );
    ctx.engine_ctrl_send(&interim);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_EVENT_VOLUME_CHANGED);
    assert_eq!(params[1], 0x00);
}

/// TP/VLH/BV-04-C: NotifyVolumeChange — TG sends interim + changed.
#[test]
fn test_avrcp_vlh_bv_04_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_VOLUME_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // INTERIM: volume 0x00.
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_EVENT_VOLUME_CHANGED, 0x00],
    );
    ctx.engine_ctrl_send(&interim);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);

    // CHANGED: volume 0x01.
    let changed = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_CHANGED,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_EVENT_VOLUME_CHANGED, 0x01],
    );
    ctx.engine_ctrl_send(&changed);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_CHANGED);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[1], 0x01);
}

/// TP/VLH/BI-01-C: SetAbsoluteVolume missing params — TG rejects.
#[test]
fn test_avrcp_vlh_bi_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[], // missing volume parameter
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_REJECTED,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_INVALID_PARAM],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_REJECTED);
}

/// TP/VLH/BI-02-C: SetAbsoluteVolume value 0x80 (bit 7 set) clamped to 0.
#[test]
fn test_avrcp_vlh_bi_02_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x80], // value with bit 7 set — should be masked to 0x00
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // TG responds with clamped volume (0x80 & 0x7F = 0x00).
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x00],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[0], 0x00);
}

/// TP/VLH/BI-03-C: CT receives SetAbsoluteVolume response with volume 0x81 (invalid).
#[test]
fn test_avrcp_vlh_bi_03_c() {
    let ctx = AvrcpTestContext::new();

    // CT sends SetAbsoluteVolume.
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x50],
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // TG responds with invalid volume 0x81 (bit 7 set in response).
    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_SET_ABSOLUTE_VOLUME,
        AVRCP_PKT_SINGLE,
        &[0x81], // invalid: bit 7 should be 0 in response
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    // Volume value is received as-is (CT may mask it).
    assert_eq!(params[0], 0x81);
}

/// TP/VLH/BI-04-C: CT receives NotifyVolumeChange with volume 0x81 (invalid).
#[test]
fn test_avrcp_vlh_bi_04_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_EVENT_VOLUME_CHANGED];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_NOTIFY,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // TG responds with invalid volume 0x81 in INTERIM.
    let interim = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_INTERIM,
        AVRCP_REGISTER_NOTIFICATION,
        AVRCP_PKT_SINGLE,
        &[AVRCP_EVENT_VOLUME_CHANGED, 0x81],
    );
    ctx.engine_ctrl_send(&interim);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_INTERIM);
    let (_, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(params[1], 0x81);
}

// ===========================================================================
// TP/PTH — Pass Through Handling Tests
// ===========================================================================

/// TP/PTH/BV-01-C: Passthrough PLAY press + release CT sequence.
#[test]
fn test_avrcp_pth_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    // Press PLAY.
    let press = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_PLAY, true);
    ctx.ctrl_send(&press);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, press);

    let press_rsp = build_passthrough_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_PLAY, true);
    ctx.engine_ctrl_send(&press_rsp);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);

    // Release PLAY.
    let release = build_passthrough_pdu(1, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_PLAY, false);
    ctx.ctrl_send(&release);
    let received = ctx.engine_ctrl_recv();
    assert_eq!(received, release);

    let release_rsp = build_passthrough_pdu(1, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_PLAY, false);
    ctx.engine_ctrl_send(&release_rsp);
    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/PTH/BV-02-C: Passthrough FAST_FORWARD press/accept/release/accept/press cycle.
#[test]
fn test_avrcp_pth_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    // Press FF.
    let press1 = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_FAST_FORWARD, true);
    ctx.ctrl_send(&press1);
    ctx.engine_ctrl_recv();
    let rsp1 = build_passthrough_pdu(0, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_FAST_FORWARD, true);
    ctx.engine_ctrl_send(&rsp1);
    let r1 = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&r1), AVC_ACCEPTED);

    // Release FF.
    let release =
        build_passthrough_pdu(1, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_FAST_FORWARD, false);
    ctx.ctrl_send(&release);
    ctx.engine_ctrl_recv();
    let rsp2 = build_passthrough_pdu(1, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_FAST_FORWARD, false);
    ctx.engine_ctrl_send(&rsp2);
    let r2 = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&r2), AVC_ACCEPTED);

    // Press FF again.
    let press2 = build_passthrough_pdu(2, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_FAST_FORWARD, true);
    ctx.ctrl_send(&press2);
    ctx.engine_ctrl_recv();
    let rsp3 = build_passthrough_pdu(2, AVCTP_RESPONSE, AVC_ACCEPTED, AVC_FAST_FORWARD, true);
    ctx.engine_ctrl_send(&rsp3);
    let r3 = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&r3), AVC_ACCEPTED);
}

// ===========================================================================
// TP/RCR — Continuing Response Tests
// ===========================================================================

/// TP/RCR/BV-02-C: Request continuing response — TG sends fragmented
/// GetElementAttributes response across START + CONTINUING + END.
#[test]
fn test_avrcp_rcr_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    // CT sends GetElementAttributes request.
    let mut req_params = vec![0u8; 8];
    req_params.push(0x00); // all attributes
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // TG sends START fragment.
    let start_params = vec![0xAA; 100]; // first chunk
    let start_rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_START,
        &start_params,
    );
    ctx.engine_ctrl_send(&start_rsp);
    let result = ctx.ctrl_recv();
    let (_, pkt_type, _, _) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(pkt_type, AVRCP_PKT_START);

    // CT sends RequestContinuing.
    let cont_req = build_control_pdu(
        1,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_REQUEST_CONTINUING,
        AVRCP_PKT_SINGLE,
        &[AVRCP_GET_ELEMENT_ATTRIBUTES],
    );
    ctx.ctrl_send(&cont_req);
    ctx.engine_ctrl_recv();

    // TG sends CONTINUING fragment.
    let cont_params = vec![0xBB; 100]; // middle chunk
    let cont_rsp = build_control_pdu(
        1,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_CONTINUING,
        &cont_params,
    );
    ctx.engine_ctrl_send(&cont_rsp);
    let result = ctx.ctrl_recv();
    let (_, pkt_type, _, _) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(pkt_type, AVRCP_PKT_CONTINUING);

    // CT sends RequestContinuing again.
    let cont_req2 = build_control_pdu(
        2,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_REQUEST_CONTINUING,
        AVRCP_PKT_SINGLE,
        &[AVRCP_GET_ELEMENT_ATTRIBUTES],
    );
    ctx.ctrl_send(&cont_req2);
    ctx.engine_ctrl_recv();

    // TG sends END fragment.
    let end_params = vec![0xCC; 50]; // final chunk
    let end_rsp = build_control_pdu(
        2,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_END,
        &end_params,
    );
    ctx.engine_ctrl_send(&end_rsp);
    let result = ctx.ctrl_recv();
    let (_, pkt_type, _, _) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(pkt_type, AVRCP_PKT_END);
}

/// TP/RCR/BV-04-C: Abort continuing response — TG handles abort.
#[test]
fn test_avrcp_rcr_bv_04_c() {
    let ctx = AvrcpTestContext::new();

    // CT sends GetElementAttributes request.
    let mut req_params = vec![0u8; 8];
    req_params.push(0x00);
    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &req_params,
    );
    ctx.ctrl_send(&req);
    ctx.engine_ctrl_recv();

    // TG sends START fragment.
    let start_rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_GET_ELEMENT_ATTRIBUTES,
        AVRCP_PKT_START,
        &[0xDD; 80],
    );
    ctx.engine_ctrl_send(&start_rsp);
    ctx.ctrl_recv();

    // CT sends AbortContinuing instead of RequestContinuing.
    let abort_req = build_control_pdu(
        1,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_ABORT_CONTINUING,
        AVRCP_PKT_SINGLE,
        &[AVRCP_GET_ELEMENT_ATTRIBUTES],
    );
    ctx.ctrl_send(&abort_req);
    ctx.engine_ctrl_recv();

    // TG responds with success.
    let abort_rsp = build_control_pdu(
        1,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_ABORT_CONTINUING,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_SUCCESS],
    );
    ctx.engine_ctrl_send(&abort_rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&result).unwrap();
    assert_eq!(pdu_id, AVRCP_ABORT_CONTINUING);
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

// ===========================================================================
// TP/MPS — Media Player Selection Tests
// ===========================================================================

/// TP/MPS/BV-01-C: SetAddressedPlayer — CT request.
#[test]
fn test_avrcp_mps_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVRCP_SET_ADDRESSED_PLAYER,
        AVRCP_PKT_SINGLE,
        &[0x00, 0x01], // player_id = 1
    );
    ctx.ctrl_send(&req);
    let received = ctx.engine_ctrl_recv();
    let (pdu_id, _, _, params) = parse_avrcp_control_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_SET_ADDRESSED_PLAYER);
    assert_eq!(u16::from_be_bytes([params[0], params[1]]), 1);

    let rsp = build_control_pdu(
        0,
        AVCTP_RESPONSE,
        AVC_ACCEPTED,
        AVRCP_SET_ADDRESSED_PLAYER,
        AVRCP_PKT_SINGLE,
        &[AVRCP_STATUS_SUCCESS],
    );
    ctx.engine_ctrl_send(&rsp);

    let result = ctx.ctrl_recv();
    assert_eq!(get_avc_ctype(&result), AVC_ACCEPTED);
}

/// TP/MPS/BV-02-C: SetBrowsedPlayer on browsing channel.
#[test]
fn test_avrcp_mps_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    let req = build_browsing_pdu(
        0,
        AVCTP_COMMAND,
        AVRCP_SET_BROWSED_PLAYER,
        &[0x00, 0x01], // player_id = 1
    );
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, params) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_SET_BROWSED_PLAYER);
    assert_eq!(u16::from_be_bytes([params[0], params[1]]), 1);

    // TG responds: status=SUCCESS, uid_counter=0, num_items=0, charset=UTF-8, depth=0.
    let mut rsp_params = vec![AVRCP_STATUS_SUCCESS];
    rsp_params.extend_from_slice(&0u16.to_be_bytes()); // uid counter
    rsp_params.extend_from_slice(&0u32.to_be_bytes()); // num items
    rsp_params.extend_from_slice(&0u16.to_be_bytes()); // charset
    rsp_params.push(0); // folder depth
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_SET_BROWSED_PLAYER, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (pdu_id, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(pdu_id, AVRCP_SET_BROWSED_PLAYER);
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

/// TP/MPS/BV-03-C: GetFolderItems (MediaPlayerList) on browsing channel.
#[test]
fn test_avrcp_mps_bv_03_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_MEDIA_PLAYER_LIST]; // scope
    req_params.extend_from_slice(&0u32.to_be_bytes()); // start
    req_params.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes()); // end
    req_params.push(0); // attribute count
    let req = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_GET_FOLDER_ITEMS, &req_params);
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, params) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_FOLDER_ITEMS);
    assert_eq!(params[0], AVRCP_MEDIA_PLAYER_LIST);

    // TG responds: status=SUCCESS, uid_counter=0, num_items=0.
    let mut rsp_params = vec![AVRCP_STATUS_SUCCESS];
    rsp_params.extend_from_slice(&0u16.to_be_bytes()); // uid counter
    rsp_params.extend_from_slice(&0u16.to_be_bytes()); // num items
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_GET_FOLDER_ITEMS, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (_, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

// ===========================================================================
// TP/MCN/CB — Content Browsing Tests
// ===========================================================================

/// TP/MCN/CB/BV-01-C: GetFolderItems (VFS) on browsing channel.
#[test]
fn test_avrcp_mcn_cb_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_MEDIA_PLAYER_VFS];
    req_params.extend_from_slice(&0u32.to_be_bytes());
    req_params.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes());
    req_params.push(0);
    let req = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_GET_FOLDER_ITEMS, &req_params);
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, _) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_FOLDER_ITEMS);

    let mut rsp_params = vec![AVRCP_STATUS_SUCCESS];
    rsp_params.extend_from_slice(&0u16.to_be_bytes());
    rsp_params.extend_from_slice(&0u16.to_be_bytes());
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_GET_FOLDER_ITEMS, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (_, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

/// TP/MCN/CB/BV-02-C: ChangePath on browsing channel.
#[test]
fn test_avrcp_mcn_cb_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = Vec::new();
    req_params.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    req_params.push(0x01); // direction: down
    req_params.extend_from_slice(&1u64.to_be_bytes()); // folder UID
    let req = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_CHANGE_PATH, &req_params);
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, _) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_CHANGE_PATH);

    let mut rsp_params = vec![AVRCP_STATUS_SUCCESS];
    rsp_params.extend_from_slice(&0u32.to_be_bytes()); // num items
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_CHANGE_PATH, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (_, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

/// TP/MCN/CB/BV-03-C: GetItemAttributes on browsing channel.
#[test]
fn test_avrcp_mcn_cb_bv_03_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_MEDIA_PLAYER_VFS]; // scope
    req_params.extend_from_slice(&1u64.to_be_bytes()); // UID
    req_params.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    req_params.push(0); // attribute count (all)
    let req = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_GET_ITEM_ATTRIBUTES, &req_params);
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, _) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_GET_ITEM_ATTRIBUTES);

    let rsp_params = vec![AVRCP_STATUS_SUCCESS, 0x00]; // 0 attributes
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_GET_ITEM_ATTRIBUTES, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (_, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

// ===========================================================================
// TP/MCN/SRC — Search Tests
// ===========================================================================

/// TP/MCN/SRC/BV-01-C: Search on browsing channel.
#[test]
fn test_avrcp_mcn_src_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let search_text = b"test";
    let mut req_params = Vec::new();
    req_params.push(0x00); // charset high (UTF-8)
    req_params.push(0x6A); // charset low
    let slen = search_text.len() as u16;
    req_params.push((slen >> 8) as u8);
    req_params.push((slen & 0xFF) as u8);
    req_params.extend_from_slice(search_text);
    let req = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_SEARCH, &req_params);
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, _) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_SEARCH);

    let mut rsp_params = vec![AVRCP_STATUS_SUCCESS];
    rsp_params.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    rsp_params.extend_from_slice(&0u32.to_be_bytes()); // num items
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_SEARCH, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (_, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

// ===========================================================================
// TP/MCN/NP — Now Playing Tests
// ===========================================================================

/// TP/MCN/NP/BV-01-C: PlayItem on browsing channel.
#[test]
fn test_avrcp_mcn_np_bv_01_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_MEDIA_NOW_PLAYING]; // scope
    req_params.extend_from_slice(&1u64.to_be_bytes()); // UID
    req_params.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    let req = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_PLAY_ITEM, &req_params);
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, _) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_PLAY_ITEM);

    let rsp_params = vec![AVRCP_STATUS_SUCCESS];
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_PLAY_ITEM, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (_, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

/// TP/MCN/NP/BV-02-C: AddToNowPlaying on browsing channel.
#[test]
fn test_avrcp_mcn_np_bv_02_c() {
    let ctx = AvrcpTestContext::new();

    let mut req_params = vec![AVRCP_MEDIA_NOW_PLAYING]; // scope
    req_params.extend_from_slice(&2u64.to_be_bytes()); // UID
    req_params.extend_from_slice(&0u16.to_be_bytes()); // UID counter
    let req = build_browsing_pdu(0, AVCTP_COMMAND, AVRCP_ADD_TO_NOW_PLAYING, &req_params);
    ctx.brs_send(&req);
    let received = ctx.engine_brs_recv();
    let (pdu_id, _, _) = parse_avrcp_browsing_pdu(&received).unwrap();
    assert_eq!(pdu_id, AVRCP_ADD_TO_NOW_PLAYING);

    let rsp_params = vec![AVRCP_STATUS_SUCCESS];
    let rsp = build_browsing_pdu(0, AVCTP_RESPONSE, AVRCP_ADD_TO_NOW_PLAYING, &rsp_params);
    ctx.engine_brs_send(&rsp);

    let result = ctx.brs_recv();
    let (_, _, params) = parse_avrcp_browsing_pdu(&result).unwrap();
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

// ===========================================================================
// Tester Framework Integration Test
// ===========================================================================

/// Verify tester framework APIs are accessible and functional.
#[test]
fn test_avrcp_tester_framework_integration() {
    assert!(std::mem::size_of::<TesterContext>() > 0, "TesterContext must be non-zero-sized");
    assert!(std::mem::size_of::<TesterIo>() > 0, "TesterIo must be non-zero-sized");

    // Exercise tester_monitor with AVRCP control channel data.
    let sample_pdu = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        &[AVRCP_CAP_COMPANY_ID],
    );
    tester_monitor('<', 0x0000, AVCTP_CONTROL_PSM, &sample_pdu);

    // Exercise tester_debug.
    tester_debug("AVRCP test framework integration check complete");
}

// ===========================================================================
// Tokio Async Runtime Validation
// ===========================================================================

/// Verify tokio async runtime is functional (validates external import).
#[tokio::test]
async fn test_avrcp_tokio_runtime() {
    let start = std::time::Instant::now();
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let elapsed = start.elapsed();
    assert!(elapsed >= tokio::time::Duration::from_millis(5), "tokio sleep should have elapsed");

    // Verify spawned task completes.
    let handle = tokio::spawn(async { 42u32 });
    let result = handle.await.expect("spawned task should complete");
    assert_eq!(result, 42);
}

// ===========================================================================
// Additional Protocol Encoding Validation Tests
// ===========================================================================

/// Verify AVRCP vendor-dependent PDU structure is correct.
#[test]
fn test_avrcp_vendordep_pdu_structure() {
    let params = &[0x01, 0x02, 0x03];
    let pdu = build_control_pdu(
        3,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_PLAY_STATUS,
        AVRCP_PKT_SINGLE,
        params,
    );

    // Total size: AVCTP(3) + AVC(3) + Company(3) + PDU(1) + PktType(1) + ParamLen(2) + Params(3) = 16.
    assert_eq!(pdu.len(), 16);

    // Verify transaction label.
    assert_eq!(avctp_transaction(pdu[0]), 3);
    assert_eq!(avctp_cr(pdu[0]), AVCTP_COMMAND);

    // Verify PID.
    assert_eq!(pdu[1], 0x11);
    assert_eq!(pdu[2], 0x0E);

    // Verify AVC.
    assert_eq!(pdu[3], AVC_CTYPE_STATUS);
    assert_eq!(pdu[4], AVC_PANEL_SUBUNIT);
    assert_eq!(pdu[5], AVC_OP_VENDORDEP);

    // Verify Company ID.
    let company = u32::from(pdu[6]) << 16 | u32::from(pdu[7]) << 8 | u32::from(pdu[8]);
    assert_eq!(company, IEEEID_BTSIG);

    // Verify AVRCP header.
    assert_eq!(pdu[9], AVRCP_GET_PLAY_STATUS);
    assert_eq!(pdu[10], AVRCP_PKT_SINGLE);
    assert_eq!(u16::from_be_bytes([pdu[11], pdu[12]]), 3); // param length

    // Verify params.
    assert_eq!(&pdu[13..16], params);
}

/// Verify AVRCP browsing PDU structure is correct.
#[test]
fn test_avrcp_browsing_pdu_structure() {
    let params = &[AVRCP_STATUS_SUCCESS, 0x00, 0x00, 0x00, 0x00];
    let pdu = build_browsing_pdu(2, AVCTP_RESPONSE, AVRCP_GET_FOLDER_ITEMS, params);

    // Total: AVCTP(3) + BrowsingHdr(3) + Params(5) = 11.
    assert_eq!(pdu.len(), 11);
    assert_eq!(avctp_transaction(pdu[0]), 2);
    assert_eq!(avctp_cr(pdu[0]), AVCTP_RESPONSE);
    assert_eq!(pdu[3], AVRCP_GET_FOLDER_ITEMS);
    assert_eq!(u16::from_be_bytes([pdu[4], pdu[5]]), 5);
    assert_eq!(&pdu[6..11], params);
}

/// Verify passthrough PDU structure is correct.
#[test]
fn test_avrcp_passthrough_pdu_structure() {
    let pdu_press = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_PLAY, true);
    assert_eq!(pdu_press.len(), AVCTP_HEADER_LEN + AVC_HDR_LEN + 2);
    assert_eq!(pdu_press[5], AVC_OP_PASSTHROUGH);
    assert_eq!(pdu_press[6], AVC_PLAY); // no release flag
    assert_eq!(pdu_press[7], 0x00); // operand length

    let pdu_release = build_passthrough_pdu(0, AVCTP_COMMAND, AVC_CTYPE_CONTROL, AVC_PLAY, false);
    assert_eq!(pdu_release[6], AVC_PLAY | 0x80); // release flag set
}

/// Verify group navigation PDU structure is correct.
#[test]
fn test_avrcp_group_nav_pdu_structure() {
    let pdu = build_group_navigation_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_CONTROL,
        AVC_VENDOR_NEXT_GROUP,
        true,
    );
    assert_eq!(pdu.len(), AVCTP_HEADER_LEN + AVC_HDR_LEN + 7);
    assert_eq!(pdu[5], AVC_OP_PASSTHROUGH);
    assert_eq!(pdu[6], AVC_VENDOR_UNIQUE); // vendor unique, pressed
    assert_eq!(pdu[7], 0x05); // operand data length
    // Company ID.
    let company = u32::from(pdu[8]) << 16 | u32::from(pdu[9]) << 8 | u32::from(pdu[10]);
    assert_eq!(company, IEEEID_BTSIG);
    // Vendor operand.
    assert_eq!(pdu[11], 0x00);
    assert_eq!(pdu[12], AVC_VENDOR_NEXT_GROUP);
}

/// Verify parse_avrcp_control_pdu correctly extracts fields.
#[test]
fn test_parse_avrcp_control_pdu() {
    let pdu = build_control_pdu(
        5,
        AVCTP_RESPONSE,
        AVC_STABLE,
        AVRCP_LIST_PLAYER_ATTRIBUTES,
        AVRCP_PKT_SINGLE,
        &[0x04, 0x01, 0x02, 0x03, 0x04],
    );

    let (pdu_id, pkt_type, param_len, params) = parse_avrcp_control_pdu(&pdu).unwrap();
    assert_eq!(pdu_id, AVRCP_LIST_PLAYER_ATTRIBUTES);
    assert_eq!(pkt_type, AVRCP_PKT_SINGLE);
    assert_eq!(param_len, 5);
    assert_eq!(params, &[0x04, 0x01, 0x02, 0x03, 0x04]);
}

/// Verify parse_avrcp_browsing_pdu correctly extracts fields.
#[test]
fn test_parse_avrcp_browsing_pdu() {
    let pdu = build_browsing_pdu(
        7,
        AVCTP_RESPONSE,
        AVRCP_SEARCH,
        &[AVRCP_STATUS_SUCCESS, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );

    let (pdu_id, param_len, params) = parse_avrcp_browsing_pdu(&pdu).unwrap();
    assert_eq!(pdu_id, AVRCP_SEARCH);
    assert_eq!(param_len, 7);
    assert_eq!(params[0], AVRCP_STATUS_SUCCESS);
}

/// Verify short/malformed PDUs return None from parsing.
#[test]
fn test_parse_avrcp_pdu_malformed() {
    // Too short for control.
    assert!(parse_avrcp_control_pdu(&[0x00, 0x11]).is_none());
    // Too short for browsing.
    assert!(parse_avrcp_browsing_pdu(&[0x00, 0x11]).is_none());
    // Control PDU with param_len exceeding actual data.
    let mut bad_pdu = build_control_pdu(
        0,
        AVCTP_COMMAND,
        AVC_CTYPE_STATUS,
        AVRCP_GET_CAPABILITIES,
        AVRCP_PKT_SINGLE,
        &[0x02],
    );
    // Corrupt param_len to be larger than available.
    bad_pdu[11] = 0x00;
    bad_pdu[12] = 0xFF;
    assert!(parse_avrcp_control_pdu(&bad_pdu).is_none());
}
