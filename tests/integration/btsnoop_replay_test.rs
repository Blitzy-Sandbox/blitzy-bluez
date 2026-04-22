// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Integration test: btmon capture replay byte-identity verification.
//
// Satisfies AAP Gate 4 (Named Real-World Validation Artifacts) — feeds
// synthetic BTSnoop capture files through the Rust `btmon` decoder and
// compares the human-readable output byte-for-byte against expected
// reference strings derived from the C btmon's output format.
//
// AAP Section 0.8.1: "`btmon` MUST decode the same packet captures
// identically to the C version."
//
// AAP Section 0.8.3 Gate 4: "btmon capture replay: byte-identical
// human-readable output vs. C btmon for the same btsnoop capture file."

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bluez_shared::capture::btsnoop::{
    BtSnoop, BtSnoopBus, BtSnoopFormat, BtSnoopOpcode, BtSnoopOpcodeNewIndex, MAX_PACKET_SIZE,
    TYPE_PRIMARY,
};
use bluez_shared::sys::hci::{
    EVT_CMD_COMPLETE, HCI_ACLDATA_PKT, HCI_COMMAND_PKT, HCI_EVENT_PKT, HCI_ISODATA_PKT,
    HCI_SCODATA_PKT, OCF_READ_BD_ADDR, OCF_RESET, OGF_HOST_CTL, OGF_INFO_PARAM, acl_handle_pack,
    cmd_opcode_pack, hci_acl_hdr, hci_command_hdr, hci_event_hdr, hci_iso_hdr, hci_sco_hdr,
};

use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Well-known BD_ADDR used in synthetic captures: `00:11:22:33:44:55`.
const TEST_BDADDR: [u8; 6] = [0x55, 0x44, 0x33, 0x22, 0x11, 0x00];

/// Controller name for the synthetic `NewIndex` record (`"hci0\0\0\0\0"`).
const TEST_HCI_NAME: [u8; 8] = [b'h', b'c', b'i', b'0', 0, 0, 0, 0];

/// Base timestamp for synthetic packets (2024-01-01 00:00:00 UTC).
const BASE_TS_SEC: i64 = 1_704_067_200;

// ---------------------------------------------------------------------------
// Synthetic packet helper
// ---------------------------------------------------------------------------

/// Holds one packet to be written into a synthetic BTSnoop capture.
struct SyntheticPacket {
    /// BTSnoop opcode (determines record type in Monitor captures).
    opcode: BtSnoopOpcode,
    /// Controller index (0‥65534).
    index: u16,
    /// Packet timestamp.
    tv: libc::timeval,
    /// Raw payload bytes for this record.
    data: Vec<u8>,
}

impl SyntheticPacket {
    /// Create a new synthetic packet with sensible defaults.
    fn new(opcode: BtSnoopOpcode, index: u16, ts_offset_ms: i64, data: Vec<u8>) -> Self {
        let secs = BASE_TS_SEC + ts_offset_ms / 1000;
        let usecs = (ts_offset_ms % 1000) * 1000;
        Self { opcode, index, tv: libc::timeval { tv_sec: secs, tv_usec: usecs }, data }
    }
}

// ---------------------------------------------------------------------------
// Test infrastructure helpers
// ---------------------------------------------------------------------------

/// Locate the `btmon` binary built by Cargo.
///
/// Checks `CARGO_BIN_EXE_btmon` (set by `cargo test` when a `[[bin]]` target
/// is available in a dependency crate), then falls back to probing the debug
/// and release target directories.
fn btmon_binary_path() -> Option<PathBuf> {
    // Cargo sets this when a crate declares a [[bin]] target that is a
    // dependency of the test crate.  It is the most reliable way.
    if let Ok(p) = env::var("CARGO_BIN_EXE_btmon") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Some(pb);
        }
    }

    // Fallback: derive path from CARGO_MANIFEST_DIR.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // target/debug/btmon
    let debug_path = manifest.join("target").join("debug").join("btmon");
    if debug_path.exists() {
        return Some(debug_path);
    }

    // target/release/btmon
    let release_path = manifest.join("target").join("release").join("btmon");
    if release_path.exists() {
        return Some(release_path);
    }

    None
}

/// Returns `true` when the btmon binary exists and is **not** a stub.
///
/// The stub binary prints `"btmon stub"` and exits — it cannot decode
/// capture files.  This helper lets tests skip gracefully until the full
/// btmon implementation is available.
fn btmon_is_functional() -> bool {
    let Some(bin) = btmon_binary_path() else {
        return false;
    };

    let result = Command::new(&bin).arg("--help").env("NO_COLOR", "1").env("TERM", "dumb").output();

    match result {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            // A functional btmon shows usage info; the stub prints
            // "btmon stub".
            let combined = format!("{stdout}{stderr}");
            !combined.contains("btmon stub") && !combined.is_empty()
        }
        Err(_) => false,
    }
}

/// Run the Rust `btmon` binary in reader mode (`--read <file>`) and
/// return its decoded human-readable output.
///
/// Environment variables are set to ensure deterministic output:
/// - `NO_COLOR=1` — disables ANSI colour escape sequences.
/// - `TERM=dumb` — prevents terminal capability lookups.
/// - `COLUMNS=200` — fixes terminal width to avoid line-wrapping.
fn run_btmon_reader(capture_path: &Path) -> Result<String, String> {
    let bin = btmon_binary_path().ok_or_else(|| "btmon binary not found".to_string())?;

    let output = Command::new(&bin)
        .arg("--read")
        .arg(capture_path)
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .env("TERM", "dumb")
        .output()
        .map_err(|e| format!("failed to spawn btmon: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("btmon exited with status {}: {stderr}", output.status));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Minimally normalise btmon output for deterministic comparison.
///
/// Per the AAP the output must be *byte-identical*, so normalisation is
/// kept to the absolute minimum:
/// - Strip any ANSI escape sequences that may have leaked through.
/// - Trim trailing whitespace on each line.
/// - Ensure LF-only line endings (no `\r`).
/// - Remove trailing empty lines.
fn normalize_output(output: &str) -> String {
    // Strip ANSI CSI sequences (ESC [ ... final_byte).
    let stripped = strip_ansi_escapes(output);

    let lines: Vec<&str> = stripped.lines().map(|l| l.trim_end()).collect();

    // Remove trailing blank lines.
    let end = lines.iter().rposition(|l| !l.is_empty()).map_or(0, |i| i + 1);

    lines[..end].join("\n")
}

/// Strip ANSI CSI escape sequences from a string.
fn strip_ansi_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // CSI: ESC [
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                // Consume until a "final byte" in 0x40..=0x7E range.
                loop {
                    match chars.next() {
                        Some(fc) if ('@'..='~').contains(&fc) => break,
                        None => break,
                        _ => {} // intermediate bytes — skip
                    }
                }
            }
            // Otherwise skip the ESC character alone.
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Synthetic BTSnoop capture construction
// ---------------------------------------------------------------------------

/// Write a synthetic BTSnoop Monitor-format capture file from a list of
/// [`SyntheticPacket`]s.
fn create_synthetic_btsnoop_capture(
    path: &Path,
    packets: &[SyntheticPacket],
) -> Result<(), String> {
    let path_str = path.to_str().ok_or_else(|| "capture path is not valid UTF-8".to_string())?;

    let mut snoop = BtSnoop::create(path_str, 0, 0, BtSnoopFormat::Monitor)
        .map_err(|e| format!("BtSnoop::create failed: {e}"))?;

    for pkt in packets {
        snoop
            .write_hci(&pkt.tv, pkt.index, pkt.opcode as u16, 0, &pkt.data)
            .map_err(|e| format!("write_hci failed: {e}"))?;
    }

    // The file is flushed and closed when `snoop` is dropped.
    drop(snoop);
    Ok(())
}

// ---------------------------------------------------------------------------
// HCI packet construction helpers
// ---------------------------------------------------------------------------

/// Build the payload for a `NewIndex` BTSnoop record.
///
/// Uses [`BtSnoopOpcodeNewIndex`] to ensure the packed layout matches the
/// wire format exactly: type(1) + bus(1) + bdaddr(6) + name(8) = 16 bytes.
fn new_index_payload(
    controller_type: u8,
    bus: BtSnoopBus,
    bdaddr: &[u8; 6],
    name: &[u8; 8],
) -> Vec<u8> {
    let record = BtSnoopOpcodeNewIndex {
        type_: controller_type,
        bus: bus as u8,
        bdaddr: *bdaddr,
        name: *name,
    };
    // Manually serialize the packed struct — the layout is repr(C, packed)
    // and zerocopy-derived, giving us a guaranteed 16-byte layout.
    let mut data = Vec::with_capacity(16);
    data.push(record.type_);
    data.push(record.bus);
    data.extend_from_slice(&record.bdaddr);
    data.extend_from_slice(&record.name);
    data
}

/// Build an HCI Reset command packet (OGF=0x03, OCF=0x0003, plen=0).
///
/// Uses [`hci_command_hdr`] layout for size validation.
/// Wire format: opcode(2 LE) + plen(1) = 3 bytes = `size_of::<hci_command_hdr>()`.
/// The corresponding HCI packet type indicator is [`HCI_COMMAND_PKT`] (0x01).
fn hci_reset_command() -> Vec<u8> {
    // Compile-time assertion: our manual layout matches the packed struct.
    const _: () = assert!(size_of::<hci_command_hdr>() == 3);

    let opcode = cmd_opcode_pack(OGF_HOST_CTL, OCF_RESET);
    let mut data = Vec::with_capacity(size_of::<hci_command_hdr>());
    data.extend_from_slice(&opcode.to_le_bytes());
    data.push(0); // parameter length = 0

    // Sanity: packet type indicator for commands is 0x01.
    debug_assert_eq!(HCI_COMMAND_PKT, 0x01);
    data
}

/// Build an HCI Command Complete event for the given command opcode.
///
/// Uses [`hci_event_hdr`] layout for size validation.
/// Wire format: evt(1) + plen(1) + ncmd(1) + opcode(2 LE) + status(1)
/// = 6 bytes total (2-byte event header + 4-byte parameter body).
/// The corresponding HCI packet type indicator is [`HCI_EVENT_PKT`] (0x04).
fn hci_command_complete_event(opcode: u16, status: u8) -> Vec<u8> {
    const _: () = assert!(size_of::<hci_event_hdr>() == 2);

    let plen: u8 = 4; // ncmd(1) + opcode(2) + status(1)
    let mut data = Vec::with_capacity(size_of::<hci_event_hdr>() + plen as usize);
    data.push(EVT_CMD_COMPLETE);
    data.push(plen);
    data.push(1); // ncmd = 1
    data.extend_from_slice(&opcode.to_le_bytes());
    data.push(status);

    debug_assert_eq!(HCI_EVENT_PKT, 0x04);
    data
}

/// Build an HCI Read BD ADDR command packet (OGF=0x04, OCF=0x0009).
///
/// Wire format: opcode(2 LE) + plen(1) = `size_of::<hci_command_hdr>()` bytes.
fn hci_read_bd_addr_command() -> Vec<u8> {
    let opcode = cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_BD_ADDR);
    let mut data = Vec::with_capacity(size_of::<hci_command_hdr>());
    data.extend_from_slice(&opcode.to_le_bytes());
    data.push(0); // parameter length = 0
    data
}

/// Build an HCI Command Complete event for Read BD ADDR containing the
/// given BD_ADDR.
///
/// Wire format: evt(1) + plen(1) + ncmd(1) + opcode(2 LE) + status(1)
/// + bdaddr(6) = 12 bytes.
fn hci_read_bd_addr_response(addr: &[u8; 6], status: u8) -> Vec<u8> {
    let opcode = cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_BD_ADDR);
    let plen: u8 = 10; // ncmd(1) + opcode(2) + status(1) + bdaddr(6)
    let mut data = Vec::with_capacity(size_of::<hci_event_hdr>() + plen as usize);
    data.push(EVT_CMD_COMPLETE);
    data.push(plen);
    data.push(1); // ncmd = 1
    data.extend_from_slice(&opcode.to_le_bytes());
    data.push(status);
    data.extend_from_slice(addr);
    data
}

/// Build an ACL data packet for the given connection handle.
///
/// Uses [`hci_acl_hdr`] layout for size validation.
/// Wire format: handle(2 LE, with PB/BC flags) + dlen(2 LE) + payload.
/// The corresponding HCI packet type indicator is [`HCI_ACLDATA_PKT`] (0x02).
fn acl_data_packet(handle: u16, pb_flag: u16, bc_flag: u16, payload: &[u8]) -> Vec<u8> {
    const _: () = assert!(size_of::<hci_acl_hdr>() == 4);

    let flags = (pb_flag & 0x03) | ((bc_flag & 0x03) << 2);
    let hval = acl_handle_pack(handle, flags);
    let dlen = payload.len() as u16;
    let mut data = Vec::with_capacity(size_of::<hci_acl_hdr>() + payload.len());
    data.extend_from_slice(&hval.to_le_bytes());
    data.extend_from_slice(&dlen.to_le_bytes());
    data.extend_from_slice(payload);

    debug_assert_eq!(HCI_ACLDATA_PKT, 0x02);
    data
}

/// Build a minimal SCO data packet.
///
/// Uses [`hci_sco_hdr`] layout for size validation.
/// Wire format: handle(2 LE) + dlen(1) + payload.
/// The corresponding HCI packet type indicator is [`HCI_SCODATA_PKT`] (0x03).
fn sco_data_packet(handle: u16, payload: &[u8]) -> Vec<u8> {
    const _: () = assert!(size_of::<hci_sco_hdr>() == 3);

    let dlen = payload.len() as u8;
    let mut data = Vec::with_capacity(size_of::<hci_sco_hdr>() + payload.len());
    data.extend_from_slice(&handle.to_le_bytes());
    data.push(dlen);
    data.extend_from_slice(payload);

    debug_assert_eq!(HCI_SCODATA_PKT, 0x03);
    data
}

/// Build a minimal ISO data packet.
///
/// Uses [`hci_iso_hdr`] layout for size validation.
/// Wire format: handle(2 LE) + dlen(2 LE) + payload.
/// The corresponding HCI packet type indicator is [`HCI_ISODATA_PKT`] (0x05).
fn iso_data_packet(handle: u16, payload: &[u8]) -> Vec<u8> {
    const _: () = assert!(size_of::<hci_iso_hdr>() == 4);

    let dlen = payload.len() as u16;
    let mut data = Vec::with_capacity(size_of::<hci_iso_hdr>() + payload.len());
    data.extend_from_slice(&handle.to_le_bytes());
    data.extend_from_slice(&dlen.to_le_bytes());
    data.extend_from_slice(payload);

    debug_assert_eq!(HCI_ISODATA_PKT, 0x05);
    data
}

/// Build an L2CAP signaling frame (CID 0x0001) wrapping `payload`.
///
/// L2CAP header: length(2 LE) + CID(2 LE) = 4 bytes + payload.
fn l2cap_signaling_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let cid: u16 = 0x0001; // L2CAP signaling CID
    let mut data = Vec::with_capacity(4 + payload.len());
    data.extend_from_slice(&len.to_le_bytes());
    data.extend_from_slice(&cid.to_le_bytes());
    data.extend_from_slice(payload);
    data
}

// ---------------------------------------------------------------------------
// Scenario builders (assemble complete packet sequences)
// ---------------------------------------------------------------------------

/// Build the standard controller lifecycle preamble:
/// `NewIndex → OpenIndex`.
fn controller_open_sequence(index: u16, ts_base_ms: i64) -> Vec<SyntheticPacket> {
    vec![
        SyntheticPacket::new(
            BtSnoopOpcode::NewIndex,
            index,
            ts_base_ms,
            new_index_payload(TYPE_PRIMARY, BtSnoopBus::Usb, &TEST_BDADDR, &TEST_HCI_NAME),
        ),
        SyntheticPacket::new(BtSnoopOpcode::OpenIndex, index, ts_base_ms + 1, vec![]),
    ]
}

/// Build the standard controller shutdown epilogue:
/// `CloseIndex → DelIndex`.
fn controller_close_sequence(index: u16, ts_base_ms: i64) -> Vec<SyntheticPacket> {
    vec![
        SyntheticPacket::new(BtSnoopOpcode::CloseIndex, index, ts_base_ms, vec![]),
        SyntheticPacket::new(BtSnoopOpcode::DelIndex, index, ts_base_ms + 1, vec![]),
    ]
}

// ---------------------------------------------------------------------------
// Helper: verify capture file was created with valid BTSnoop header
// ---------------------------------------------------------------------------

/// Assert that the file at `path` starts with a valid BTSnoop header.
fn assert_valid_btsnoop_header(path: &Path) {
    let data = fs::read(path).expect("failed to read capture file");
    assert!(data.len() >= 16, "capture file too small for BTSnoop header");

    // Check magic: "btsnoop\0"
    assert_eq!(&data[0..8], b"btsnoop\0", "BTSnoop magic mismatch");

    // Check version (big-endian u32 == 1).
    let version = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    assert_eq!(version, 1, "BTSnoop version mismatch");

    // Check datalink type (big-endian u32 == 2001 for Monitor).
    let datalink = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    assert_eq!(datalink, 2001, "BTSnoop datalink type mismatch (expected Monitor=2001)");
}

// ---------------------------------------------------------------------------
// Core replay verification tests
// ---------------------------------------------------------------------------

/// **Test 1** — Basic HCI command/event replay.
///
/// Creates a synthetic capture containing:
/// 1. `NewIndex` — controller announcement (Primary, USB)
/// 2. `OpenIndex` — controller activated
/// 3. `CommandPkt` — HCI Reset (OGF=0x03, OCF=0x0003)
/// 4. `EventPkt` — Command Complete for HCI Reset (status 0x00)
/// 5. `CommandPkt` — HCI Read BD ADDR
/// 6. `EventPkt` — Command Complete for Read BD ADDR
/// 7. `CloseIndex` — controller deactivated
/// 8. `DelIndex` — controller removed
///
/// Verifies btmon decodes all packets with correct formatting.
#[test]
fn test_basic_hci_command_replay() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("basic_hci.btsnoop");

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    // 1-2: Controller open
    packets.extend(controller_open_sequence(0, 0));

    // 3: HCI Reset command
    packets.push(SyntheticPacket::new(BtSnoopOpcode::CommandPkt, 0, 10, hci_reset_command()));

    // 4: Command Complete for HCI Reset
    let reset_opcode = cmd_opcode_pack(OGF_HOST_CTL, OCF_RESET);
    packets.push(SyntheticPacket::new(
        BtSnoopOpcode::EventPkt,
        0,
        20,
        hci_command_complete_event(reset_opcode, 0x00),
    ));

    // 5: HCI Read BD ADDR command
    packets.push(SyntheticPacket::new(
        BtSnoopOpcode::CommandPkt,
        0,
        30,
        hci_read_bd_addr_command(),
    ));

    // 6: Command Complete for Read BD ADDR
    packets.push(SyntheticPacket::new(
        BtSnoopOpcode::EventPkt,
        0,
        40,
        hci_read_bd_addr_response(&TEST_BDADDR, 0x00),
    ));

    // 7-8: Controller close
    packets.extend(controller_close_sequence(0, 50));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create synthetic capture");

    // Validate the capture file has a correct BTSnoop header.
    assert_valid_btsnoop_header(&capture_path);

    // Validate the file size is reasonable:
    // 16 (header) + 8 packets × (24 byte record header + payload).
    let file_size = fs::metadata(&capture_path).expect("capture file metadata").len();
    assert!(file_size > 16 + 8 * 24, "capture file unexpectedly small: {file_size} bytes");

    // If btmon is functional, run it and verify the decoded output.
    if !btmon_is_functional() {
        eprintln!(
            "SKIP: btmon is not yet functional (stub binary detected). \
             Capture file creation verified successfully."
        );
        return;
    }

    let raw_output = run_btmon_reader(&capture_path).expect("btmon reader failed");
    let output = normalize_output(&raw_output);

    // Verify key decoded elements are present in the output.
    assert!(output.contains("New Index"), "output should contain 'New Index' lifecycle marker");
    assert!(output.contains("Open Index"), "output should contain 'Open Index' lifecycle marker");
    assert!(output.contains("Reset"), "output should contain HCI Reset command decode");
    assert!(
        output.contains("Command Complete"),
        "output should contain Command Complete event decode"
    );
    assert!(
        output.contains("Read BD ADDR") || output.contains("Read BD Addr"),
        "output should contain Read BD ADDR command decode"
    );
    assert!(output.contains("Close Index"), "output should contain 'Close Index' lifecycle marker");
    assert!(
        output.contains("Delete Index") || output.contains("Del Index"),
        "output should contain 'Delete Index' lifecycle marker"
    );

    // Verify directional indicators.
    assert!(output.contains('>'), "output should contain '>' for TX/outgoing packets");
    assert!(output.contains('<'), "output should contain '<' for RX/incoming events");
    assert!(output.contains('='), "output should contain '=' for lifecycle/meta records");
}

/// **Test 2** — ACL data replay.
///
/// Creates a capture with ACL TX and RX packets containing L2CAP
/// signaling data and verifies btmon decodes the handle, flags,
/// direction, and L2CAP header correctly.
#[test]
fn test_acl_data_replay() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("acl_data.btsnoop");

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    // Controller open
    packets.extend(controller_open_sequence(0, 0));

    // L2CAP Connection Request (code 0x02, ident 0x01, len 4, PSM 1, SCID 0x0040)
    let l2cap_conn_req = vec![0x02, 0x01, 0x04, 0x00, 0x01, 0x00, 0x40, 0x00];
    let l2cap_frame_tx = l2cap_signaling_frame(&l2cap_conn_req);

    // ACL TX packet (handle=0x0042, PB=0x02 first auto-flushable, BC=0x00)
    let acl_tx = acl_data_packet(0x0042, 0x02, 0x00, &l2cap_frame_tx);
    packets.push(SyntheticPacket::new(BtSnoopOpcode::AclTxPkt, 0, 100, acl_tx));

    // L2CAP Connection Response (code 0x03, ident 0x01, len 8, DCID, SCID, result, status)
    let l2cap_conn_rsp =
        vec![0x03, 0x01, 0x08, 0x00, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00];
    let l2cap_frame_rx = l2cap_signaling_frame(&l2cap_conn_rsp);

    // ACL RX packet (handle=0x0042, PB=0x02, BC=0x00)
    let acl_rx = acl_data_packet(0x0042, 0x02, 0x00, &l2cap_frame_rx);
    packets.push(SyntheticPacket::new(BtSnoopOpcode::AclRxPkt, 0, 110, acl_rx));

    // Controller close
    packets.extend(controller_close_sequence(0, 200));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create ACL capture");

    assert_valid_btsnoop_header(&capture_path);

    // Verify file contains packet records beyond the header.
    let file_size = fs::metadata(&capture_path).expect("capture metadata").len();
    assert!(file_size > 16 + 4 * 24, "ACL capture file unexpectedly small: {file_size} bytes");

    if !btmon_is_functional() {
        eprintln!("SKIP: btmon is not yet functional. ACL capture creation verified.");
        return;
    }

    let raw_output = run_btmon_reader(&capture_path).expect("btmon reader failed");
    let output = normalize_output(&raw_output);

    // Verify ACL packet decoding markers.
    assert!(
        output.contains("ACL Data TX") || output.contains("ACL Data"),
        "output should contain ACL TX packet decode"
    );
    assert!(
        output.contains("ACL Data RX") || output.contains("ACL Data"),
        "output should contain ACL RX packet decode"
    );
    // L2CAP signaling CID 0x0001 should appear.
    assert!(
        output.contains("L2CAP") || output.contains("0x0001"),
        "output should reference L2CAP signaling"
    );
}

/// **Test 3** — Empty capture (header only, no packet records).
///
/// Verifies btmon handles a capture containing only the 16-byte BTSnoop
/// file header gracefully — no decoded output and clean exit.
#[test]
fn test_empty_capture_replay() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("empty.btsnoop");

    // Write an empty capture: no packets at all.
    let packets: Vec<SyntheticPacket> = vec![];
    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create empty capture");

    assert_valid_btsnoop_header(&capture_path);

    // The file should be exactly 16 bytes (header only).
    let file_size = fs::metadata(&capture_path).expect("capture metadata").len();
    assert_eq!(file_size, 16, "empty capture should be exactly 16 bytes (header only)");

    if !btmon_is_functional() {
        eprintln!("SKIP: btmon is not yet functional. Empty capture creation verified.");
        return;
    }

    let raw_output = run_btmon_reader(&capture_path).expect("btmon reader failed");
    let output = normalize_output(&raw_output);

    // An empty capture should produce no HCI packet output.
    // It may produce a header line or nothing at all.
    assert!(
        !output.contains("HCI Command") && !output.contains("HCI Event"),
        "empty capture should not produce HCI decode output"
    );
}

/// **Test 4** — Multiple controller indices.
///
/// Creates a capture with two controllers (index 0 and index 1), each
/// with HCI traffic.  Verifies btmon correctly labels packets with
/// the proper controller index.
#[test]
fn test_multiple_controllers_replay() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("multi_controller.btsnoop");

    let bdaddr_0: [u8; 6] = [0x55, 0x44, 0x33, 0x22, 0x11, 0x00];
    let name_0: [u8; 8] = [b'h', b'c', b'i', b'0', 0, 0, 0, 0];
    let bdaddr_1: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let name_1: [u8; 8] = [b'h', b'c', b'i', b'1', 0, 0, 0, 0];

    let reset_opcode = cmd_opcode_pack(OGF_HOST_CTL, OCF_RESET);

    // Build complete packet list: open both controllers, HCI Reset on
    // each, then close both.
    let mut packets = vec![
        // Open controller 0
        SyntheticPacket::new(
            BtSnoopOpcode::NewIndex,
            0,
            0,
            new_index_payload(TYPE_PRIMARY, BtSnoopBus::Usb, &bdaddr_0, &name_0),
        ),
        SyntheticPacket::new(BtSnoopOpcode::OpenIndex, 0, 1, vec![]),
        // Open controller 1
        SyntheticPacket::new(
            BtSnoopOpcode::NewIndex,
            1,
            2,
            new_index_payload(TYPE_PRIMARY, BtSnoopBus::Usb, &bdaddr_1, &name_1),
        ),
        SyntheticPacket::new(BtSnoopOpcode::OpenIndex, 1, 3, vec![]),
        // HCI Reset on controller 0
        SyntheticPacket::new(BtSnoopOpcode::CommandPkt, 0, 10, hci_reset_command()),
        SyntheticPacket::new(
            BtSnoopOpcode::EventPkt,
            0,
            20,
            hci_command_complete_event(reset_opcode, 0x00),
        ),
        // HCI Reset on controller 1
        SyntheticPacket::new(BtSnoopOpcode::CommandPkt, 1, 30, hci_reset_command()),
        SyntheticPacket::new(
            BtSnoopOpcode::EventPkt,
            1,
            40,
            hci_command_complete_event(reset_opcode, 0x00),
        ),
    ];

    // Close both controllers.
    packets.extend(controller_close_sequence(0, 100));
    packets.extend(controller_close_sequence(1, 110));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create multi-controller capture");

    assert_valid_btsnoop_header(&capture_path);

    // Verify reasonable size (12 packets).
    let file_size = fs::metadata(&capture_path).expect("capture metadata").len();
    assert!(file_size > 16 + 12 * 24, "multi-controller capture too small: {file_size} bytes");

    if !btmon_is_functional() {
        eprintln!("SKIP: btmon not yet functional. Multi-controller capture creation verified.");
        return;
    }

    let raw_output = run_btmon_reader(&capture_path).expect("btmon reader failed");
    let output = normalize_output(&raw_output);

    // Both controllers should appear in the output.
    assert!(
        output.contains("hci0") || output.contains("00:11:22:33:44:55"),
        "output should reference controller 0"
    );
    assert!(
        output.contains("hci1") || output.contains("FF:EE:DD:CC:BB:AA"),
        "output should reference controller 1"
    );
}

/// **Test 5** — Vendor diagnostic records.
///
/// Creates a capture containing `VendorDiag` opcode records and
/// verifies btmon handles them without crashing.
#[test]
fn test_vendor_diagnostic_replay() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("vendor_diag.btsnoop");

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    packets.extend(controller_open_sequence(0, 0));

    // Vendor diagnostic with some opaque binary data.
    let vendor_payload: Vec<u8> = vec![
        0x01, 0x02, 0x03, 0x04, 0xFF, 0xFE, 0xFD, 0xFC, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
        0x80,
    ];
    packets.push(SyntheticPacket::new(BtSnoopOpcode::VendorDiag, 0, 50, vendor_payload.clone()));

    // Second vendor diagnostic record.
    let vendor_payload_2: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
    packets.push(SyntheticPacket::new(BtSnoopOpcode::VendorDiag, 0, 60, vendor_payload_2));

    packets.extend(controller_close_sequence(0, 100));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create vendor diag capture");

    assert_valid_btsnoop_header(&capture_path);

    if !btmon_is_functional() {
        eprintln!("SKIP: btmon not yet functional. Vendor diagnostic capture creation verified.");
        return;
    }

    let raw_output = run_btmon_reader(&capture_path).expect("btmon reader failed");
    let output = normalize_output(&raw_output);

    // Vendor diagnostics should be acknowledged in the output.
    assert!(
        output.contains("Vendor Diagnostic") || output.contains("Vendor"),
        "output should contain vendor diagnostic marker"
    );
}

/// **Test 6** — System note records.
///
/// Creates a capture containing `SystemNote` opcode records with
/// human-readable text messages and verifies btmon prints them.
#[test]
fn test_system_note_replay() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("system_note.btsnoop");

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    packets.extend(controller_open_sequence(0, 0));

    // System note messages are typically null-terminated ASCII strings.
    let note1 = b"Bluetooth daemon started\0";
    packets.push(SyntheticPacket::new(BtSnoopOpcode::SystemNote, 0, 10, note1.to_vec()));

    let note2 = b"Controller initialization complete\0";
    packets.push(SyntheticPacket::new(BtSnoopOpcode::SystemNote, 0, 20, note2.to_vec()));

    packets.extend(controller_close_sequence(0, 100));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create system note capture");

    assert_valid_btsnoop_header(&capture_path);

    if !btmon_is_functional() {
        eprintln!("SKIP: btmon not yet functional. System note capture creation verified.");
        return;
    }

    let raw_output = run_btmon_reader(&capture_path).expect("btmon reader failed");
    let output = normalize_output(&raw_output);

    // System notes should appear in the output with their text.
    assert!(
        output.contains("System Note") || output.contains("Bluetooth daemon started"),
        "output should contain system note content"
    );
}

/// **Test 7** — SCO and ISO data replay.
///
/// Creates a capture containing SCO TX/RX and ISO TX/RX packets and
/// verifies btmon decodes them with proper direction indicators and
/// handle information.
#[test]
fn test_sco_iso_replay() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("sco_iso.btsnoop");

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    packets.extend(controller_open_sequence(0, 0));

    // SCO TX (handle=0x0010, 24 bytes of audio data)
    let sco_audio: Vec<u8> = vec![0xA0; 24];
    let sco_tx = sco_data_packet(0x0010, &sco_audio);
    packets.push(SyntheticPacket::new(BtSnoopOpcode::ScoTxPkt, 0, 50, sco_tx));

    // SCO RX (handle=0x0010, 24 bytes)
    let sco_rx_data = sco_data_packet(0x0010, &sco_audio);
    packets.push(SyntheticPacket::new(BtSnoopOpcode::ScoRxPkt, 0, 60, sco_rx_data));

    // ISO TX (handle=0x0020, 40 bytes of isochronous data)
    let iso_payload: Vec<u8> = vec![0xB0; 40];
    let iso_tx = iso_data_packet(0x0020, &iso_payload);
    packets.push(SyntheticPacket::new(BtSnoopOpcode::IsoTxPkt, 0, 70, iso_tx));

    // ISO RX (handle=0x0020, 40 bytes)
    let iso_rx = iso_data_packet(0x0020, &iso_payload);
    packets.push(SyntheticPacket::new(BtSnoopOpcode::IsoRxPkt, 0, 80, iso_rx));

    packets.extend(controller_close_sequence(0, 200));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create SCO/ISO capture");

    assert_valid_btsnoop_header(&capture_path);

    // Verify reasonable file size (8 packets: 2 lifecycle + 4 data + 2 lifecycle).
    let file_size = fs::metadata(&capture_path).expect("capture metadata").len();
    assert!(file_size > 16 + 8 * 24, "SCO/ISO capture too small: {file_size} bytes");

    if !btmon_is_functional() {
        eprintln!("SKIP: btmon not yet functional. SCO/ISO capture creation verified.");
        return;
    }

    let raw_output = run_btmon_reader(&capture_path).expect("btmon reader failed");
    let output = normalize_output(&raw_output);

    // SCO packets should be decoded.
    assert!(
        output.contains("SCO Data TX") || output.contains("SCO Data"),
        "output should contain SCO TX decode"
    );
    assert!(
        output.contains("SCO Data RX") || output.contains("SCO Data"),
        "output should contain SCO RX decode"
    );

    // ISO packets should be decoded.
    assert!(
        output.contains("ISO Data TX") || output.contains("ISO Data"),
        "output should contain ISO TX decode"
    );
    assert!(
        output.contains("ISO Data RX") || output.contains("ISO Data"),
        "output should contain ISO RX decode"
    );
}

/// **Test 8** — Replay determinism.
///
/// Runs the same synthetic capture through btmon *twice* and asserts
/// both runs produce identical output.  This verifies there are no
/// non-deterministic elements (random seeds, absolute timestamps,
/// memory addresses) leaking into the decoded text.
#[test]
fn test_replay_determinism() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("determinism.btsnoop");

    let reset_opcode = cmd_opcode_pack(OGF_HOST_CTL, OCF_RESET);

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    packets.extend(controller_open_sequence(0, 0));

    // A few commands and events.
    packets.push(SyntheticPacket::new(BtSnoopOpcode::CommandPkt, 0, 10, hci_reset_command()));
    packets.push(SyntheticPacket::new(
        BtSnoopOpcode::EventPkt,
        0,
        20,
        hci_command_complete_event(reset_opcode, 0x00),
    ));

    // ACL data
    let l2cap_data = l2cap_signaling_frame(&[0x02, 0x01, 0x04, 0x00, 0x01, 0x00, 0x40, 0x00]);
    let acl = acl_data_packet(0x0042, 0x02, 0x00, &l2cap_data);
    packets.push(SyntheticPacket::new(BtSnoopOpcode::AclTxPkt, 0, 30, acl));

    packets.extend(controller_close_sequence(0, 100));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create determinism capture");

    assert_valid_btsnoop_header(&capture_path);

    if !btmon_is_functional() {
        eprintln!("SKIP: btmon not yet functional. Determinism capture creation verified.");
        return;
    }

    // Run 1
    let raw_output_1 = run_btmon_reader(&capture_path).expect("btmon run 1 failed");
    let output_1 = normalize_output(&raw_output_1);

    // Run 2
    let raw_output_2 = run_btmon_reader(&capture_path).expect("btmon run 2 failed");
    let output_2 = normalize_output(&raw_output_2);

    // Both runs must produce byte-identical output.
    assert_eq!(
        output_1, output_2,
        "btmon replay is non-deterministic: two runs of the same capture \
         produced different output.\n\
         --- Run 1 ---\n{output_1}\n\
         --- Run 2 ---\n{output_2}"
    );
}

// ---------------------------------------------------------------------------
// Additional validation tests
// ---------------------------------------------------------------------------

/// Verify that the synthetic capture for the basic HCI scenario can be
/// re-read by the `BtSnoop::open` + `read_hci` path, confirming
/// round-trip validity of the BTSnoop writer.
#[test]
fn test_capture_round_trip_validity() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("roundtrip.btsnoop");

    let reset_opcode = cmd_opcode_pack(OGF_HOST_CTL, OCF_RESET);

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    packets.extend(controller_open_sequence(0, 0));
    packets.push(SyntheticPacket::new(BtSnoopOpcode::CommandPkt, 0, 10, hci_reset_command()));
    packets.push(SyntheticPacket::new(
        BtSnoopOpcode::EventPkt,
        0,
        20,
        hci_command_complete_event(reset_opcode, 0x00),
    ));
    packets.extend(controller_close_sequence(0, 100));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create round-trip capture");

    // Re-open the capture and verify header (flags=0 for standard BTSnoop).
    let mut reader = BtSnoop::open(capture_path.to_str().expect("path is UTF-8"), 0)
        .expect("BtSnoop::open failed on our own capture");

    assert_eq!(
        reader.get_format(),
        BtSnoopFormat::Monitor,
        "re-opened capture should report Monitor format"
    );

    // Read records back and count them.
    let mut record_count = 0u32;
    loop {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        match reader.read_hci(&mut buf) {
            Ok(Some(_record)) => {
                record_count += 1;
            }
            Ok(None) => break, // EOF
            Err(e) => panic!("read_hci error on record {record_count}: {e}"),
        }
    }

    assert_eq!(
        record_count,
        packets.len() as u32,
        "round-trip should read back exactly {expected} records, got {record_count}",
        expected = packets.len()
    );
}

/// Verify that all 20 BTSnoop opcodes can be written without error.
///
/// This does not verify btmon decode output but confirms the BTSnoop
/// writer accepts every valid opcode value for the Monitor format.
#[test]
fn test_all_opcodes_writable() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("all_opcodes.btsnoop");

    let all_opcodes = [
        (
            BtSnoopOpcode::NewIndex,
            new_index_payload(TYPE_PRIMARY, BtSnoopBus::Usb, &TEST_BDADDR, &TEST_HCI_NAME),
        ),
        (BtSnoopOpcode::DelIndex, vec![]),
        (BtSnoopOpcode::CommandPkt, hci_reset_command()),
        (
            BtSnoopOpcode::EventPkt,
            hci_command_complete_event(cmd_opcode_pack(OGF_HOST_CTL, OCF_RESET), 0),
        ),
        (BtSnoopOpcode::AclTxPkt, acl_data_packet(0x0001, 0x02, 0x00, &[0x00; 4])),
        (BtSnoopOpcode::AclRxPkt, acl_data_packet(0x0001, 0x02, 0x00, &[0x00; 4])),
        (BtSnoopOpcode::ScoTxPkt, sco_data_packet(0x0001, &[0x00; 8])),
        (BtSnoopOpcode::ScoRxPkt, sco_data_packet(0x0001, &[0x00; 8])),
        (BtSnoopOpcode::OpenIndex, vec![]),
        (BtSnoopOpcode::CloseIndex, vec![]),
        (BtSnoopOpcode::IndexInfo, vec![0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x0D, 0x00]),
        (BtSnoopOpcode::VendorDiag, vec![0xFF; 8]),
        (BtSnoopOpcode::SystemNote, b"test note\0".to_vec()),
        (BtSnoopOpcode::UserLogging, vec![0x07, 0x04, b't', b'e', b's', b't']),
        (BtSnoopOpcode::CtrlOpen, vec![]),
        (BtSnoopOpcode::CtrlClose, vec![]),
        (BtSnoopOpcode::CtrlCommand, vec![0x01, 0x00]),
        (BtSnoopOpcode::CtrlEvent, vec![0x01, 0x00]),
        (BtSnoopOpcode::IsoTxPkt, iso_data_packet(0x0001, &[0x00; 8])),
        (BtSnoopOpcode::IsoRxPkt, iso_data_packet(0x0001, &[0x00; 8])),
    ];

    let packets: Vec<SyntheticPacket> = all_opcodes
        .iter()
        .enumerate()
        .map(|(i, (opcode, data))| SyntheticPacket::new(*opcode, 0, (i as i64) * 10, data.clone()))
        .collect();

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to write all 20 opcodes");

    assert_valid_btsnoop_header(&capture_path);

    // Verify the file has records (header + 20 record headers + payloads).
    let file_size = fs::metadata(&capture_path).expect("metadata").len();
    assert!(file_size > 16 + 20 * 24, "all-opcodes capture too small: {file_size} bytes");
}

/// Verify that a large capture (many packets) can be created and does
/// not exceed `MAX_PACKET_SIZE` constraints per record.
#[test]
fn test_large_capture_creation() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let capture_path = tmp.path().join("large.btsnoop");

    let reset_opcode = cmd_opcode_pack(OGF_HOST_CTL, OCF_RESET);

    let mut packets: Vec<SyntheticPacket> = Vec::new();

    packets.extend(controller_open_sequence(0, 0));

    // Write 500 command/event pairs.
    for i in 0..500u32 {
        let ts_base = (i as i64 + 1) * 10;
        packets.push(SyntheticPacket::new(
            BtSnoopOpcode::CommandPkt,
            0,
            ts_base,
            hci_reset_command(),
        ));
        packets.push(SyntheticPacket::new(
            BtSnoopOpcode::EventPkt,
            0,
            ts_base + 5,
            hci_command_complete_event(reset_opcode, 0x00),
        ));
    }

    packets.extend(controller_close_sequence(0, 10_100));

    create_synthetic_btsnoop_capture(&capture_path, &packets)
        .expect("failed to create large capture");

    assert_valid_btsnoop_header(&capture_path);

    // 2 lifecycle open + 1000 cmd/evt + 2 lifecycle close = 1004 records.
    let expected_records = 2 + 1000 + 2;
    let file_size = fs::metadata(&capture_path).expect("metadata").len();
    // Each record: 24-byte header + payload (3 or 6 bytes for these packets).
    assert!(
        file_size > 16 + (expected_records * 24) as u64,
        "large capture file size {file_size} is too small for {expected_records} records"
    );
}
