// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2011-2014 Intel Corporation
// Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
//
// analyze.rs — Offline btsnoop trace analyzer.
//
// Complete Rust rewrite of monitor/analyze.c (1190 lines) + monitor/analyze.h
// from BlueZ v5.86. Post-processes btsnoop capture files: builds per-controller
// / per-connection / per-L2CAP-channel models, computes throughput/latency
// statistics, and renders histograms via gnuplot.

use std::collections::VecDeque;
use std::io::Write;
use std::mem::size_of;
use std::process::{Command, Stdio};

use zerocopy::FromBytes;

use bluez_shared::capture::btsnoop::{
    BTSNOOP_FLAG_PKLG_SUPPORT, BtSnoop, BtSnoopFormat, BtSnoopOpcode, BtSnoopOpcodeIndexInfo,
    BtSnoopOpcodeNewIndex, HciRecord, MAX_PACKET_SIZE,
};
use bluez_shared::sys::bluetooth::{bdaddr_t, bt_compidtostr, bt_get_le16};
use bluez_shared::sys::hci::{
    ACL_LINK, ESCO_LINK, EVT_CMD_COMPLETE, EVT_CONN_COMPLETE, EVT_DISCONN_COMPLETE,
    EVT_LE_CONN_COMPLETE, EVT_LE_META_EVENT, EVT_NUM_COMP_PKTS, OCF_READ_BD_ADDR, OGF_INFO_PARAM,
    SCO_LINK, acl_handle, cmd_opcode_pack, evt_cmd_complete, evt_conn_complete,
    evt_disconn_complete, hci_acl_hdr, hci_event_hdr, hci_iso_hdr, read_bd_addr_rp,
};
use bluez_shared::sys::l2cap::{
    L2CAP_CONN_REQ, L2CAP_CONN_RSP, l2cap_cmd_hdr, l2cap_conn_req, l2cap_conn_rsp, l2cap_hdr,
};

use crate::packet::{BtmonConn, PacketLatency, packet_latency_add, print_addr};
use crate::{print_field, print_text};

// ============================================================================
// HCI sub-event codes not yet available in bluez_shared::sys::hci
// ============================================================================

/// Synchronous Connection Complete event code (0x2c).
const EVT_SYNC_CONN_COMPLETE: u8 = 0x2c;

/// LE Enhanced Connection Complete sub-event code.
const EVT_LE_ENHANCED_CONN_COMPLETE: u8 = 0x0a;

/// LE CIS Established sub-event code.
const EVT_LE_CIS_ESTABLISHED: u8 = 0x19;

/// LE CIS Request sub-event code.
const EVT_LE_CIS_REQ: u8 = 0x1a;

/// LE BIG Complete sub-event code.
const EVT_LE_BIG_COMPLETE: u8 = 0x1b;

/// LE BIG Sync Established sub-event code.
/// Note: typo preserved from C source (ESTABILISHED → matches BlueZ naming).
const EVT_LE_BIG_SYNC_ESTABILISHED: u8 = 0x1d;

// ============================================================================
// Packed event structures not yet in bluez_shared::sys::hci
//
// These replicate the C `struct bt_hci_evt_*` layouts for safe byte parsing.
// ============================================================================

/// Synchronous Connection Complete event parameters.
#[derive(Debug, Clone, Copy, FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C, packed)]
struct EvtSyncConnComplete {
    status: u8,
    handle: u16,
    bdaddr: [u8; 6],
    link_type: u8,
    tx_interval: u8,
    retrans_window: u8,
    rx_pkt_len: u16,
    tx_pkt_len: u16,
    air_mode: u8,
}

/// LE Connection Complete event parameters.
#[derive(Debug, Clone, Copy, FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C, packed)]
struct EvtLeConnComplete {
    status: u8,
    handle: u16,
    role: u8,
    peer_addr_type: u8,
    peer_addr: [u8; 6],
    interval: u16,
    latency: u16,
    supv_timeout: u16,
    clock_accuracy: u8,
}

/// LE Enhanced Connection Complete event parameters.
#[derive(Debug, Clone, Copy, FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C, packed)]
struct EvtLeEnhConnComplete {
    status: u8,
    handle: u16,
    role: u8,
    peer_addr_type: u8,
    peer_addr: [u8; 6],
    local_rpa: [u8; 6],
    peer_rpa: [u8; 6],
    interval: u16,
    latency: u16,
    supv_timeout: u16,
    clock_accuracy: u8,
}

/// LE CIS Established event parameters.
#[derive(Debug, Clone, Copy, FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C, packed)]
struct EvtLeCisEstablished {
    status: u8,
    conn_handle: u16,
    cig_sync_delay: [u8; 3],
    cis_sync_delay: [u8; 3],
    m_latency: [u8; 3],
    s_latency: [u8; 3],
    m_phy: u8,
    s_phy: u8,
    nse: u8,
    m_bn: u8,
    s_bn: u8,
    m_ft: u8,
    s_ft: u8,
    m_max_pdu: u16,
    s_max_pdu: u16,
    iso_interval: u16,
}

/// LE CIS Request event parameters.
#[derive(Debug, Clone, Copy, FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C, packed)]
struct EvtLeCisReq {
    acl_handle: u16,
    cis_handle: u16,
    cig_id: u8,
    cis_id: u8,
}

/// LE BIG Complete event parameters (fixed header, variable handle list).
#[derive(Debug, Clone, Copy, FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C, packed)]
struct EvtLeBigComplete {
    status: u8,
    big_handle: u8,
    big_sync_delay: [u8; 3],
    transport_latency: [u8; 3],
    phy: u8,
    nse: u8,
    bn: u8,
    pto: u8,
    irc: u8,
    max_pdu: u16,
    iso_interval: u16,
    num_bis: u8,
}

/// LE BIG Sync Established event parameters (fixed header, variable handle list).
#[derive(Debug, Clone, Copy, FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C, packed)]
struct EvtLeBigSyncEstablished {
    status: u8,
    big_handle: u8,
    transport_latency: [u8; 3],
    nse: u8,
    bn: u8,
    pto: u8,
    irc: u8,
    max_pdu: u16,
    iso_interval: u16,
    num_bis: u8,
}

// ============================================================================
// TV_MSEC helper — convert timeval to milliseconds (i64)
// ============================================================================

/// Convert a `libc::timeval` to total milliseconds.
#[inline]
fn tv_msec(tv: &libc::timeval) -> i64 {
    tv.tv_sec * 1000 + tv.tv_usec / 1000
}

/// Check if a timeval is set (non-zero).
#[inline]
fn timerisset(tv: &libc::timeval) -> bool {
    tv.tv_sec != 0 || tv.tv_usec != 0
}

/// Compute `result = a - b` for timeval values.
#[inline]
fn timersub(a: &libc::timeval, b: &libc::timeval, result: &mut libc::timeval) {
    result.tv_sec = a.tv_sec - b.tv_sec;
    result.tv_usec = a.tv_usec - b.tv_usec;
    if result.tv_usec < 0 {
        result.tv_sec -= 1;
        result.tv_usec += 1_000_000;
    }
}

// ============================================================================
// Data Model Structures
// ============================================================================

/// Histogram entry for latency distribution plotting.
struct PlotEntry {
    /// Millisecond bucket.
    x_msec: i64,
    /// Occurrence count.
    y_count: usize,
}

/// TX queue entry — records the timestamp when a packet was sent, along with
/// an optional L2CAP channel index for per-channel statistics.
struct HciConnTx {
    tv: libc::timeval,
    chan_idx: Option<usize>,
}

/// Per-direction packet statistics.
struct HciStats {
    /// Total bytes transferred.
    bytes: usize,
    /// Total packets counted.
    num: usize,
    /// Number of completed packets (for TX: from Num Completed Packets event).
    num_comp: usize,
    /// Latency accumulator.
    latency: PacketLatency,
    /// Histogram data for latency distribution.
    plot: Vec<PlotEntry>,
    /// Minimum packet size observed.
    min: u16,
    /// Maximum packet size observed.
    max: u16,
}

impl HciStats {
    fn new() -> Self {
        Self {
            bytes: 0,
            num: 0,
            num_comp: 0,
            latency: PacketLatency::default(),
            plot: Vec::new(),
            min: 0,
            max: 0,
        }
    }
}

/// L2CAP channel tracking within a connection.
struct L2capChan {
    /// Channel ID.
    cid: u16,
    /// Protocol/Service Multiplexer.
    psm: u16,
    /// True if this is an outbound (TX) channel.
    out: bool,
    /// Timestamp of last received packet on this channel.
    last_rx: libc::timeval,
    /// RX statistics for this channel.
    rx: HciStats,
    /// TX statistics for this channel.
    tx: HciStats,
}

impl L2capChan {
    fn new(cid: u16, out: bool) -> Self {
        Self {
            cid,
            psm: 0,
            out,
            last_rx: libc::timeval { tv_sec: 0, tv_usec: 0 },
            rx: HciStats::new(),
            tx: HciStats::new(),
        }
    }
}

/// Per-connection state in the analysis model.
struct HciConn {
    /// Connection handle.
    handle: u16,
    /// Parent connection handle (for CIS linked to ACL).
    link: u16,
    /// Connection type (using BtmonConn discriminant values).
    type_: u8,
    /// Remote BD_ADDR.
    bdaddr: bdaddr_t,
    /// Remote BD_ADDR type.
    bdaddr_type: u8,
    /// Whether the connection setup event was observed.
    setup_seen: bool,
    /// Whether the disconnection event was observed.
    terminated: bool,
    /// Disconnect reason code.
    disconnect_reason: u8,
    /// Frame number at which connection was established.
    frame_connected: usize,
    /// Frame number at which connection was terminated.
    frame_disconnected: usize,
    /// Queue of pending TX timestamps for latency calculation.
    tx_queue: VecDeque<HciConnTx>,
    /// Timestamp of last received packet.
    last_rx: libc::timeval,
    /// L2CAP channels observed on this connection.
    chan_list: Vec<L2capChan>,
    /// RX packet statistics.
    rx: HciStats,
    /// TX packet statistics.
    tx: HciStats,
}

impl HciConn {
    fn new(handle: u16, type_: u8) -> Self {
        Self {
            handle,
            link: 0,
            type_,
            bdaddr: bdaddr_t { b: [0u8; 6] },
            bdaddr_type: 0,
            setup_seen: false,
            terminated: false,
            disconnect_reason: 0,
            frame_connected: 0,
            frame_disconnected: 0,
            tx_queue: VecDeque::new(),
            last_rx: libc::timeval { tv_sec: 0, tv_usec: 0 },
            chan_list: Vec::new(),
            rx: HciStats::new(),
            tx: HciStats::new(),
        }
    }
}

/// Per-controller device state in the analysis model.
struct HciDev {
    /// Controller index.
    index: u16,
    /// Controller type (0x00 = BR/EDR, 0x01 = AMP).
    type_: u8,
    /// Controller BD_ADDR.
    bdaddr: bdaddr_t,
    /// Total HCI packet count.
    num_hci: usize,
    /// HCI command count.
    num_cmd: usize,
    /// HCI event count.
    num_evt: usize,
    /// ACL packet count.
    num_acl: usize,
    /// SCO packet count.
    num_sco: usize,
    /// ISO packet count.
    num_iso: usize,
    /// Vendor diagnostic count.
    vendor_diag: usize,
    /// System note count.
    system_note: usize,
    /// User log count.
    user_log: usize,
    /// Control message count.
    ctrl_msg: usize,
    /// Unknown opcode count.
    unknown: usize,
    /// Manufacturer identifier (0xffff = unknown).
    manufacturer: u16,
    /// List of connections on this controller.
    conn_list: Vec<HciConn>,
}

impl HciDev {
    fn new(index: u16) -> Self {
        Self {
            index,
            type_: 0,
            bdaddr: bdaddr_t { b: [0u8; 6] },
            num_hci: 0,
            num_cmd: 0,
            num_evt: 0,
            num_acl: 0,
            num_sco: 0,
            num_iso: 0,
            vendor_diag: 0,
            system_note: 0,
            user_log: 0,
            ctrl_msg: 0,
            unknown: 0,
            manufacturer: 0xffff,
            conn_list: Vec::new(),
        }
    }
}

// ============================================================================
// Gnuplot Histogram Rendering
// ============================================================================

/// Draw a latency histogram via gnuplot using ASCII "dumb" terminal mode.
///
/// Spawns gnuplot as a child process, pipes data via stdin, and prints
/// the resulting ASCII art to stdout. If gnuplot is not installed, this
/// function silently does nothing (matching C popen behavior).
fn plot_draw(plot: &[PlotEntry], title: &str) {
    if plot.len() < 2 {
        return;
    }

    let mut child = match Command::new("gnuplot")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    if let Some(ref mut stdin) = child.stdin {
        let _ = writeln!(stdin, "$data << EOD");
        for entry in plot {
            let _ = writeln!(stdin, "{} {}", entry.x_msec, entry.y_count);
        }
        let _ = writeln!(stdin, "EOD");
        let _ = writeln!(stdin, "set terminal dumb enhanced ansi");
        let _ = writeln!(stdin, "set xlabel 'Latency (ms)'");
        let _ = writeln!(stdin, "set tics out nomirror");
        let _ = writeln!(stdin, "set log y");
        let _ = writeln!(stdin, "set yrange [0.5:*]");
        let _ = writeln!(stdin, "plot $data using 1:2 t '{}' w impulses", title);
        let _ = stdin.flush();
    }

    // Drop stdin to signal EOF, then wait for the child
    drop(child.stdin.take());
    let _ = child.wait();
}

// ============================================================================
// Statistics Output
// ============================================================================

/// Print RX/TX statistics block for a connection or channel.
fn print_stats(stats: &HciStats, label: &str) {
    if stats.num == 0 {
        return;
    }

    print_field!("{} packets: {}/{}", label, stats.num, stats.num_comp);
    print_field!(
        "{} Latency: {}-{} msec (~{} msec)",
        label,
        tv_msec(&stats.latency.min),
        tv_msec(&stats.latency.max),
        tv_msec(&stats.latency.med)
    );
    print_field!(
        "{} size: {}-{} octets (~{} octets)",
        label,
        stats.min,
        stats.max,
        stats.bytes.checked_div(stats.num).unwrap_or(0)
    );

    let total_ms = tv_msec(&stats.latency.total);
    if total_ms > 0 {
        print_field!("{} speed: ~{} Kb/s", label, stats.bytes as i64 * 8 / total_ms);
    }

    plot_draw(&stats.plot, label);
}

// ============================================================================
// L2CAP Channel Management
// ============================================================================

/// Look up an L2CAP channel by CID and direction, creating it if not found.
fn chan_lookup(conn: &mut HciConn, cid: u16, out: bool) -> usize {
    for (i, chan) in conn.chan_list.iter().enumerate() {
        if chan.cid == cid && chan.out == out {
            return i;
        }
    }
    let chan = L2capChan::new(cid, out);
    conn.chan_list.push(chan);
    conn.chan_list.len() - 1
}

// ============================================================================
// L2CAP Channel Destroy (summary output)
// ============================================================================

/// Print summary for a single L2CAP channel.
fn chan_destroy(chan: &L2capChan) {
    if chan.rx.num == 0 && chan.tx.num == 0 {
        return;
    }

    println!("  Found {} L2CAP channel with CID {}", if chan.out { "TX" } else { "RX" }, chan.cid);
    if chan.psm != 0 {
        print_field!("PSM {}", chan.psm);
    }

    print_stats(&chan.rx, "RX");
    print_stats(&chan.tx, "TX");
}

// ============================================================================
// Connection Destroy (summary output)
// ============================================================================

/// Print summary for a single HCI connection and all its L2CAP channels.
fn conn_destroy(conn: &HciConn) {
    let str_type = match conn.type_ {
        x if x == BtmonConn::Acl as u8 => "BR-ACL",
        x if x == BtmonConn::Le as u8 => "BR-SCO",
        x if x == BtmonConn::Sco as u8 => "BR-ESCO",
        x if x == BtmonConn::Esco as u8 => "LE-ACL",
        x if x == BtmonConn::Cis as u8 => "LE-CIS",
        x if x == BtmonConn::Bis as u8 => "LE-BIS",
        _ => "unknown",
    };

    println!("  Found {} connection with handle {}", str_type, conn.handle);
    print_addr("Address", &conn.bdaddr.b, conn.bdaddr_type);
    if !conn.setup_seen {
        print_field!("Connection setup missing");
    }
    print_stats(&conn.rx, "RX");
    print_stats(&conn.tx, "TX");

    if conn.setup_seen {
        print_field!("Connected: #{}", conn.frame_connected);
        if conn.terminated {
            print_field!("Disconnected: #{}", conn.frame_disconnected);
            print_field!("Disconnect Reason: 0x{:02x}", conn.disconnect_reason);
        }
    }

    for chan in &conn.chan_list {
        chan_destroy(chan);
    }
}

// ============================================================================
// Connection Management
// ============================================================================

/// Find a non-terminated connection by handle, or return None.
fn conn_lookup(dev: &HciDev, handle: u16) -> Option<usize> {
    dev.conn_list.iter().position(|c| c.handle == handle && !c.terminated)
}

/// Find a non-terminated connection whose `link` field matches the given handle.
fn link_lookup(dev: &HciDev, handle: u16) -> Option<usize> {
    dev.conn_list.iter().position(|c| c.link == handle && !c.terminated)
}

/// Look up a connection by handle and type, creating a new one if not found
/// or if the type doesn't match. Matches the C `conn_lookup_type` behavior.
fn conn_lookup_type(dev: &mut HciDev, handle: u16, type_: u8) -> usize {
    // Search for an existing non-terminated connection with matching handle
    if let Some(idx) = dev.conn_list.iter().position(|c| c.handle == handle && !c.terminated) {
        if type_ == 0 || dev.conn_list[idx].type_ == type_ {
            return idx;
        }
    }
    // Allocate a new connection
    let conn = HciConn::new(handle, type_);
    dev.conn_list.push(conn);
    dev.conn_list.len() - 1
}

// ============================================================================
// Device Management
// ============================================================================

/// Look up a device by index, creating one if not found. Returns mutable
/// reference index into the dev_list.
fn dev_lookup(dev_list: &mut Vec<HciDev>, index: u16) -> usize {
    if let Some(pos) = dev_list.iter().position(|d| d.index == index) {
        return pos;
    }
    let dev = HciDev::new(index);
    dev_list.push(dev);
    dev_list.len() - 1
}

/// Print the summary for a single HCI device and all its connections.
fn dev_destroy(dev: &HciDev) {
    let str_type = match dev.type_ {
        0x00 => "BR/EDR",
        0x01 => "AMP",
        _ => "unknown",
    };

    println!("Found {} controller with index {}", str_type, dev.index);
    print!(
        "  BD_ADDR {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        dev.bdaddr.b[5],
        dev.bdaddr.b[4],
        dev.bdaddr.b[3],
        dev.bdaddr.b[2],
        dev.bdaddr.b[1],
        dev.bdaddr.b[0]
    );
    if dev.manufacturer != 0xffff {
        print!(" ({})", bt_compidtostr(dev.manufacturer as i32));
    }
    println!();

    println!("  {} commands", dev.num_cmd);
    println!("  {} events", dev.num_evt);
    println!("  {} ACL packets", dev.num_acl);
    println!("  {} SCO packets", dev.num_sco);
    println!("  {} ISO packets", dev.num_iso);
    println!("  {} vendor diagnostics", dev.vendor_diag);
    println!("  {} system notes", dev.system_note);
    println!("  {} user logs", dev.user_log);
    println!("  {} control messages ", dev.ctrl_msg);
    println!("  {} unknown opcodes", dev.unknown);

    for conn in &dev.conn_list {
        conn_destroy(conn);
    }
    println!();
}

// ============================================================================
// Plot / Histogram Data Accumulation
// ============================================================================

/// Add a latency sample to the plot histogram.
///
/// Uses LRU ordering: if a bucket with matching millisecond value exists,
/// it is removed, incremented, and pushed to the head. Otherwise a new
/// entry is appended to the tail.
fn plot_add(plot: &mut Vec<PlotEntry>, latency: &libc::timeval, count: usize) {
    let msec = tv_msec(latency);

    // LRU search: find and remove existing bucket
    if let Some(pos) = plot.iter().position(|p| p.x_msec == msec) {
        let mut entry = plot.remove(pos);
        entry.y_count += count;
        plot.insert(0, entry);
        return;
    }

    // New bucket
    plot.push(PlotEntry { x_msec: msec, y_count: count });
}

// ============================================================================
// Packet Statistics Accumulation
// ============================================================================

/// Update packet statistics with a new packet of the given size.
fn stats_add(stats: &mut HciStats, size: u16) {
    stats.num += 1;
    stats.bytes += size as usize;

    if stats.min == 0 || size < stats.min {
        stats.min = size;
    }
    if stats.max == 0 || size > stats.max {
        stats.max = size;
    }
}

// ============================================================================
// TX/RX Packet Tracking
// ============================================================================

/// Record a TX packet: enqueue timestamp and update TX stats.
fn conn_pkt_tx(conn: &mut HciConn, tv: &libc::timeval, size: u16, chan_idx: Option<usize>) {
    let last_tx = HciConnTx { tv: *tv, chan_idx };
    conn.tx_queue.push_back(last_tx);

    stats_add(&mut conn.tx, size);

    if let Some(idx) = chan_idx {
        if let Some(chan) = conn.chan_list.get_mut(idx) {
            stats_add(&mut chan.tx, size);
        }
    }
}

/// Record an RX packet: update inter-arrival latency and RX stats.
fn conn_pkt_rx(conn: &mut HciConn, tv: &libc::timeval, size: u16, chan_idx: Option<usize>) {
    let mut res = libc::timeval { tv_sec: 0, tv_usec: 0 };

    if timerisset(&conn.last_rx) {
        timersub(tv, &conn.last_rx, &mut res);
        packet_latency_add(&mut conn.rx.latency, &res);
        plot_add(&mut conn.rx.plot, &res, 1);
    }

    conn.last_rx = *tv;

    stats_add(&mut conn.rx, size);
    conn.rx.num_comp += 1;

    if let Some(idx) = chan_idx {
        if let Some(chan) = conn.chan_list.get_mut(idx) {
            let mut chan_res = libc::timeval { tv_sec: 0, tv_usec: 0 };
            if timerisset(&chan.last_rx) {
                timersub(tv, &chan.last_rx, &mut chan_res);
                packet_latency_add(&mut chan.rx.latency, &chan_res);
                plot_add(&mut chan.rx.plot, &chan_res, 1);
            }
            chan.last_rx = *tv;
            stats_add(&mut chan.rx, size);
            chan.rx.num_comp += 1;
        }
    }
}

// ============================================================================
// L2CAP Signaling Parser
// ============================================================================

/// Parse L2CAP signaling commands to track PSM assignment to channels.
fn l2cap_sig(conn: &mut HciConn, out: bool, data: &[u8]) {
    if data.len() < size_of::<l2cap_cmd_hdr>() {
        return;
    }

    let hdr = match l2cap_cmd_hdr::read_from_bytes(&data[..size_of::<l2cap_cmd_hdr>()]) {
        Ok(h) => h,
        Err(_) => return,
    };

    match hdr.code {
        L2CAP_CONN_REQ => {
            if data.len() < size_of::<l2cap_cmd_hdr>() + size_of::<l2cap_conn_req>() {
                return;
            }
            let offset = size_of::<l2cap_cmd_hdr>();
            let req = match l2cap_conn_req::read_from_bytes(
                &data[offset..offset + size_of::<l2cap_conn_req>()],
            ) {
                Ok(r) => r,
                Err(_) => return,
            };
            let psm = u16::from_le(req.psm);
            let scid = u16::from_le(req.scid);
            let idx = chan_lookup(conn, scid, out);
            conn.chan_list[idx].psm = psm;
        }
        L2CAP_CONN_RSP => {
            if data.len() < size_of::<l2cap_cmd_hdr>() + size_of::<l2cap_conn_rsp>() {
                return;
            }
            let offset = size_of::<l2cap_cmd_hdr>();
            let rsp = match l2cap_conn_rsp::read_from_bytes(
                &data[offset..offset + size_of::<l2cap_conn_rsp>()],
            ) {
                Ok(r) => r,
                Err(_) => return,
            };
            let dcid = u16::from_le(rsp.dcid);
            let scid = u16::from_le(rsp.scid);

            // Look up the original channel (from the request) to get the PSM
            let psm = {
                let idx = chan_lookup(conn, scid, !out);
                conn.chan_list[idx].psm
            };
            // Assign PSM to the response channel
            let idx = chan_lookup(conn, dcid, out);
            conn.chan_list[idx].psm = psm;
        }
        _ => {}
    }
}

// ============================================================================
// BTSnoop Record Handlers
// ============================================================================

/// Handle NEW_INDEX opcode: add a new device.
fn new_index(dev_list: &mut Vec<HciDev>, index: u16, data: &[u8]) {
    if data.len() < size_of::<BtSnoopOpcodeNewIndex>() {
        return;
    }

    let ni =
        match BtSnoopOpcodeNewIndex::read_from_bytes(&data[..size_of::<BtSnoopOpcodeNewIndex>()]) {
            Ok(n) => n,
            Err(_) => return,
        };

    let mut dev = HciDev::new(index);
    dev.type_ = ni.type_;
    dev.bdaddr.b.copy_from_slice(&ni.bdaddr);
    dev_list.push(dev);
}

/// Handle DEL_INDEX opcode: remove device and print summary.
fn del_index(dev_list: &mut Vec<HciDev>, index: u16) {
    if let Some(pos) = dev_list.iter().position(|d| d.index == index) {
        let dev = dev_list.remove(pos);
        dev_destroy(&dev);
    } else {
        eprintln!("Remove for an unexisting device");
    }
}

/// Handle COMMAND_PKT opcode: increment command counter.
fn command_pkt(dev_list: &mut Vec<HciDev>, index: u16) {
    let idx = dev_lookup(dev_list, index);
    dev_list[idx].num_hci += 1;
    dev_list[idx].num_cmd += 1;
}

// ============================================================================
// HCI Event Handlers
// ============================================================================

/// Handle Connection Complete event.
fn handle_evt_conn_complete(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<evt_conn_complete>() {
        return;
    }
    let evt = match evt_conn_complete::read_from_bytes(&data[..size_of::<evt_conn_complete>()]) {
        Ok(e) => e,
        Err(_) => return,
    };

    if evt.status != 0 {
        return;
    }

    let handle = u16::from_le(evt.handle);
    let conn_idx = conn_lookup_type(dev, handle, BtmonConn::Acl as u8);
    dev.conn_list[conn_idx].bdaddr = evt.bdaddr;
    dev.conn_list[conn_idx].frame_connected = frame;
    dev.conn_list[conn_idx].setup_seen = true;
}

/// Handle Disconnect Complete event.
fn handle_evt_disconnect_complete(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<evt_disconn_complete>() {
        return;
    }
    let evt =
        match evt_disconn_complete::read_from_bytes(&data[..size_of::<evt_disconn_complete>()]) {
            Ok(e) => e,
            Err(_) => return,
        };

    if evt.status != 0 {
        return;
    }

    let handle = u16::from_le(evt.handle);
    if let Some(conn_idx) = conn_lookup(dev, handle) {
        dev.conn_list[conn_idx].frame_disconnected = frame;
        dev.conn_list[conn_idx].disconnect_reason = evt.reason;
        dev.conn_list[conn_idx].terminated = true;
    }
}

/// Handle READ_BD_ADDR response.
fn rsp_read_bd_addr(dev: &mut HciDev, data: &[u8]) {
    if data.len() < size_of::<read_bd_addr_rp>() {
        return;
    }
    let rsp = match read_bd_addr_rp::read_from_bytes(&data[..size_of::<read_bd_addr_rp>()]) {
        Ok(r) => r,
        Err(_) => return,
    };

    if rsp.status != 0 {
        return;
    }

    dev.bdaddr = rsp.bdaddr;
}

/// Handle Command Complete event — dispatch by opcode.
fn handle_evt_cmd_complete(dev: &mut HciDev, data: &[u8]) {
    if data.len() < size_of::<evt_cmd_complete>() {
        return;
    }
    let evt = match evt_cmd_complete::read_from_bytes(&data[..size_of::<evt_cmd_complete>()]) {
        Ok(e) => e,
        Err(_) => return,
    };

    let opcode = u16::from_le(evt.opcode);
    let remaining = &data[size_of::<evt_cmd_complete>()..];

    let read_bd_addr_opcode = cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_BD_ADDR);
    if opcode == read_bd_addr_opcode {
        rsp_read_bd_addr(dev, remaining);
    }
}

/// Handle Number of Completed Packets event.
fn handle_evt_num_completed_packets(dev: &mut HciDev, tv: &libc::timeval, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let num_handles = data[0] as usize;
    let mut offset: usize = 1;

    for _ in 0..num_handles {
        if offset + 4 > data.len() {
            break;
        }

        let handle = bt_get_le16(&data[offset..]);
        let count = bt_get_le16(&data[offset + 2..]);
        offset += 4;

        let conn_idx = match conn_lookup(dev, handle) {
            Some(idx) => idx,
            None => continue,
        };

        dev.conn_list[conn_idx].tx.num_comp += count as usize;

        for _ in 0..count {
            if let Some(last_tx) = dev.conn_list[conn_idx].tx_queue.pop_front() {
                let mut res = libc::timeval { tv_sec: 0, tv_usec: 0 };
                timersub(tv, &last_tx.tv, &mut res);

                packet_latency_add(&mut dev.conn_list[conn_idx].tx.latency, &res);
                plot_add(&mut dev.conn_list[conn_idx].tx.plot, &res, 1);

                if let Some(chan_idx) = last_tx.chan_idx {
                    if let Some(chan) = dev.conn_list[conn_idx].chan_list.get_mut(chan_idx) {
                        chan.tx.num_comp += count as usize;
                        packet_latency_add(&mut chan.tx.latency, &res);
                        plot_add(&mut chan.tx.plot, &res, 1);
                    }
                }
            }
        }
    }
}

/// Handle Synchronous Connection Complete event.
fn handle_evt_sync_conn_complete(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<EvtSyncConnComplete>() {
        return;
    }
    let evt = match EvtSyncConnComplete::read_from_bytes(&data[..size_of::<EvtSyncConnComplete>()])
    {
        Ok(e) => e,
        Err(_) => return,
    };

    if evt.status != 0 {
        return;
    }

    let handle = u16::from_le(evt.handle);
    // Map HCI link_type values to BtmonConn types.
    // SCO_LINK=0x00 -> Sco, ACL_LINK=0x01 -> Acl, ESCO_LINK=0x02 -> Esco
    let conn_type = match evt.link_type {
        SCO_LINK => BtmonConn::Sco as u8,
        ACL_LINK => BtmonConn::Acl as u8,
        ESCO_LINK => BtmonConn::Esco as u8,
        other => other,
    };
    let conn_idx = conn_lookup_type(dev, handle, conn_type);
    dev.conn_list[conn_idx].bdaddr.b.copy_from_slice(&evt.bdaddr);
    dev.conn_list[conn_idx].frame_connected = frame;
    dev.conn_list[conn_idx].setup_seen = true;
}

// ============================================================================
// LE Meta Event Handlers
// ============================================================================

/// Handle LE Connection Complete sub-event.
fn handle_evt_le_conn_complete(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<EvtLeConnComplete>() {
        return;
    }
    let evt = match EvtLeConnComplete::read_from_bytes(&data[..size_of::<EvtLeConnComplete>()]) {
        Ok(e) => e,
        Err(_) => return,
    };

    if evt.status != 0 {
        return;
    }

    let handle = u16::from_le(evt.handle);
    let conn_idx = conn_lookup_type(dev, handle, BtmonConn::Le as u8);
    dev.conn_list[conn_idx].bdaddr.b.copy_from_slice(&evt.peer_addr);
    dev.conn_list[conn_idx].bdaddr_type = evt.peer_addr_type;
    dev.conn_list[conn_idx].frame_connected = frame;
    dev.conn_list[conn_idx].setup_seen = true;
}

/// Handle LE Enhanced Connection Complete sub-event.
fn handle_evt_le_enh_conn_complete(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<EvtLeEnhConnComplete>() {
        return;
    }
    let evt =
        match EvtLeEnhConnComplete::read_from_bytes(&data[..size_of::<EvtLeEnhConnComplete>()]) {
            Ok(e) => e,
            Err(_) => return,
        };

    if evt.status != 0 {
        return;
    }

    let handle = u16::from_le(evt.handle);
    let conn_idx = conn_lookup_type(dev, handle, BtmonConn::Le as u8);
    dev.conn_list[conn_idx].bdaddr.b.copy_from_slice(&evt.peer_addr);
    dev.conn_list[conn_idx].bdaddr_type = evt.peer_addr_type;
    dev.conn_list[conn_idx].frame_connected = frame;
    dev.conn_list[conn_idx].setup_seen = true;
}

/// Handle LE CIS Established sub-event.
fn handle_evt_le_cis_established(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<EvtLeCisEstablished>() {
        return;
    }
    let evt = match EvtLeCisEstablished::read_from_bytes(&data[..size_of::<EvtLeCisEstablished>()])
    {
        Ok(e) => e,
        Err(_) => return,
    };

    if evt.status != 0 {
        return;
    }

    let conn_handle = u16::from_le(evt.conn_handle);
    let conn_idx = conn_lookup_type(dev, conn_handle, BtmonConn::Cis as u8);
    dev.conn_list[conn_idx].frame_connected = frame;
    dev.conn_list[conn_idx].setup_seen = true;

    // Copy bdaddr from the parent ACL connection
    let handle = dev.conn_list[conn_idx].handle;
    if let Some(link_idx) = link_lookup(dev, handle) {
        let bdaddr = dev.conn_list[link_idx].bdaddr;
        dev.conn_list[conn_idx].bdaddr = bdaddr;
    }
}

/// Handle LE CIS Request sub-event.
fn handle_evt_le_cis_req(dev: &mut HciDev, data: &[u8]) {
    if data.len() < size_of::<EvtLeCisReq>() {
        return;
    }
    let evt = match EvtLeCisReq::read_from_bytes(&data[..size_of::<EvtLeCisReq>()]) {
        Ok(e) => e,
        Err(_) => return,
    };

    let acl_handle_val = u16::from_le(evt.acl_handle);
    let cis_handle = u16::from_le(evt.cis_handle);

    if let Some(conn_idx) = conn_lookup(dev, acl_handle_val) {
        dev.conn_list[conn_idx].link = cis_handle;
    }
}

/// Handle LE BIG Complete sub-event.
fn handle_evt_le_big_complete(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<EvtLeBigComplete>() {
        return;
    }
    let evt = match EvtLeBigComplete::read_from_bytes(&data[..size_of::<EvtLeBigComplete>()]) {
        Ok(e) => e,
        Err(_) => return,
    };

    if evt.status != 0 {
        return;
    }

    let hdr_size = size_of::<EvtLeBigComplete>();
    let mut offset = hdr_size;

    for _ in 0..evt.num_bis {
        if offset + 2 > data.len() {
            return;
        }
        let handle = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let conn_idx = conn_lookup_type(dev, handle, BtmonConn::Bis as u8);
        dev.conn_list[conn_idx].setup_seen = true;
        dev.conn_list[conn_idx].frame_connected = frame;
    }
}

/// Handle LE BIG Sync Established sub-event.
fn handle_evt_le_big_sync_established(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.len() < size_of::<EvtLeBigSyncEstablished>() {
        return;
    }
    let evt = match EvtLeBigSyncEstablished::read_from_bytes(
        &data[..size_of::<EvtLeBigSyncEstablished>()],
    ) {
        Ok(e) => e,
        Err(_) => return,
    };

    if evt.status != 0 {
        return;
    }

    let hdr_size = size_of::<EvtLeBigSyncEstablished>();
    let mut offset = hdr_size;

    for _ in 0..evt.num_bis {
        if offset + 2 > data.len() {
            return;
        }
        let handle = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let conn_idx = conn_lookup_type(dev, handle, BtmonConn::Bis as u8);
        dev.conn_list[conn_idx].setup_seen = true;
        dev.conn_list[conn_idx].frame_connected = frame;
    }
}

/// Dispatch LE meta event to appropriate sub-event handler.
fn handle_evt_le_meta_event(dev: &mut HciDev, frame: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let subevt = data[0];
    let remaining = &data[1..];

    match subevt {
        EVT_LE_CONN_COMPLETE => {
            handle_evt_le_conn_complete(dev, frame, remaining);
        }
        EVT_LE_ENHANCED_CONN_COMPLETE => {
            handle_evt_le_enh_conn_complete(dev, frame, remaining);
        }
        EVT_LE_CIS_ESTABLISHED => {
            handle_evt_le_cis_established(dev, frame, remaining);
        }
        EVT_LE_CIS_REQ => {
            handle_evt_le_cis_req(dev, remaining);
        }
        EVT_LE_BIG_COMPLETE => {
            handle_evt_le_big_complete(dev, frame, remaining);
        }
        EVT_LE_BIG_SYNC_ESTABILISHED => {
            handle_evt_le_big_sync_established(dev, frame, remaining);
        }
        _ => {}
    }
}

// ============================================================================
// Event Packet Dispatcher
// ============================================================================

/// Process an HCI event packet.
fn event_pkt(
    dev_list: &mut Vec<HciDev>,
    tv: &libc::timeval,
    index: u16,
    frame: usize,
    data: &[u8],
) {
    if data.len() < size_of::<hci_event_hdr>() {
        return;
    }

    let hdr = match hci_event_hdr::read_from_bytes(&data[..size_of::<hci_event_hdr>()]) {
        Ok(h) => h,
        Err(_) => return,
    };

    let remaining = &data[size_of::<hci_event_hdr>()..];

    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].num_hci += 1;
    dev_list[dev_idx].num_evt += 1;

    match hdr.evt {
        EVT_CONN_COMPLETE => {
            handle_evt_conn_complete(&mut dev_list[dev_idx], frame, remaining);
        }
        EVT_DISCONN_COMPLETE => {
            handle_evt_disconnect_complete(&mut dev_list[dev_idx], frame, remaining);
        }
        EVT_CMD_COMPLETE => {
            handle_evt_cmd_complete(&mut dev_list[dev_idx], remaining);
        }
        EVT_NUM_COMP_PKTS => {
            handle_evt_num_completed_packets(&mut dev_list[dev_idx], tv, remaining);
        }
        EVT_SYNC_CONN_COMPLETE => {
            handle_evt_sync_conn_complete(&mut dev_list[dev_idx], frame, remaining);
        }
        EVT_LE_META_EVENT => {
            handle_evt_le_meta_event(&mut dev_list[dev_idx], frame, remaining);
        }
        _ => {}
    }
}

// ============================================================================
// ACL Packet Handler
// ============================================================================

/// Process an ACL data packet (TX or RX).
fn acl_pkt(dev_list: &mut Vec<HciDev>, tv: &libc::timeval, index: u16, out: bool, data: &[u8]) {
    if data.len() < size_of::<hci_acl_hdr>() {
        return;
    }

    let hdr = match hci_acl_hdr::read_from_bytes(&data[..size_of::<hci_acl_hdr>()]) {
        Ok(h) => h,
        Err(_) => return,
    };

    let payload = &data[size_of::<hci_acl_hdr>()..];
    let payload_size = data.len() - size_of::<hci_acl_hdr>();

    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].num_hci += 1;
    dev_list[dev_idx].num_acl += 1;

    let raw_handle = u16::from_le(hdr.handle);
    let handle = acl_handle(raw_handle);
    let pb_flag = raw_handle >> 12;

    let conn_idx = conn_lookup_type(&mut dev_list[dev_idx], handle, 0x00);

    let mut chan_idx: Option<usize> = None;

    // First or start packet — parse L2CAP header
    if matches!(pb_flag, 0x00 | 0x02) && payload.len() >= size_of::<l2cap_hdr>() {
        let cid = bt_get_le16(&payload[2..]);
        chan_idx = Some(chan_lookup(&mut dev_list[dev_idx].conn_list[conn_idx], cid, out));

        if cid == 1 && payload.len() > 4 {
            // L2CAP signaling channel — parse signaling commands
            l2cap_sig(&mut dev_list[dev_idx].conn_list[conn_idx], out, &payload[4..]);
        }
    }

    if out {
        conn_pkt_tx(&mut dev_list[dev_idx].conn_list[conn_idx], tv, payload_size as u16, chan_idx);
    } else {
        conn_pkt_rx(&mut dev_list[dev_idx].conn_list[conn_idx], tv, payload_size as u16, chan_idx);
    }
}

// ============================================================================
// SCO Packet Handler
// ============================================================================

/// Process an SCO data packet (TX or RX).
fn sco_pkt(dev_list: &mut Vec<HciDev>, tv: &libc::timeval, index: u16, out: bool, data: &[u8]) {
    if data.len() < size_of::<hci_acl_hdr>() {
        return;
    }

    let hdr = match hci_acl_hdr::read_from_bytes(&data[..size_of::<hci_acl_hdr>()]) {
        Ok(h) => h,
        Err(_) => return,
    };

    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].num_hci += 1;
    dev_list[dev_idx].num_sco += 1;

    let handle = u16::from_le(hdr.handle) & 0x0fff;

    // Try SCO first, then eSCO
    let conn_idx = if let Some(idx) = dev_list[dev_idx]
        .conn_list
        .iter()
        .position(|c| c.handle == handle && !c.terminated && c.type_ == BtmonConn::Sco as u8)
    {
        idx
    } else if let Some(idx) = dev_list[dev_idx]
        .conn_list
        .iter()
        .position(|c| c.handle == handle && !c.terminated && c.type_ == BtmonConn::Esco as u8)
    {
        idx
    } else {
        let conn = HciConn::new(handle, BtmonConn::Sco as u8);
        dev_list[dev_idx].conn_list.push(conn);
        dev_list[dev_idx].conn_list.len() - 1
    };

    let payload_size = data.len().saturating_sub(size_of::<hci_acl_hdr>()) as u16;

    if out {
        conn_pkt_tx(&mut dev_list[dev_idx].conn_list[conn_idx], tv, payload_size, None);
    } else {
        conn_pkt_rx(&mut dev_list[dev_idx].conn_list[conn_idx], tv, payload_size, None);
    }
}

// ============================================================================
// ISO Packet Handler
// ============================================================================

/// Process an ISO data packet (TX or RX).
fn iso_pkt(dev_list: &mut Vec<HciDev>, tv: &libc::timeval, index: u16, out: bool, data: &[u8]) {
    if data.len() < size_of::<hci_iso_hdr>() {
        return;
    }

    let hdr = match hci_iso_hdr::read_from_bytes(&data[..size_of::<hci_iso_hdr>()]) {
        Ok(h) => h,
        Err(_) => return,
    };

    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].num_hci += 1;
    dev_list[dev_idx].num_iso += 1;

    let handle = u16::from_le(hdr.handle) & 0x0fff;

    // Try CIS first, then BIS
    let conn_idx = if let Some(idx) = dev_list[dev_idx]
        .conn_list
        .iter()
        .position(|c| c.handle == handle && !c.terminated && c.type_ == BtmonConn::Cis as u8)
    {
        idx
    } else if let Some(idx) = dev_list[dev_idx]
        .conn_list
        .iter()
        .position(|c| c.handle == handle && !c.terminated && c.type_ == BtmonConn::Bis as u8)
    {
        idx
    } else {
        let conn = HciConn::new(handle, BtmonConn::Cis as u8);
        dev_list[dev_idx].conn_list.push(conn);
        dev_list[dev_idx].conn_list.len() - 1
    };

    let payload_size = data.len().saturating_sub(size_of::<hci_iso_hdr>()) as u16;

    if out {
        conn_pkt_tx(&mut dev_list[dev_idx].conn_list[conn_idx], tv, payload_size, None);
    } else {
        conn_pkt_rx(&mut dev_list[dev_idx].conn_list[conn_idx], tv, payload_size, None);
    }
}

// ============================================================================
// Counter-Only Handlers
// ============================================================================

/// Handle INDEX_INFO opcode: update manufacturer field.
fn info_index(dev_list: &mut Vec<HciDev>, index: u16, data: &[u8]) {
    if data.len() < size_of::<BtSnoopOpcodeIndexInfo>() {
        return;
    }
    let hdr =
        match BtSnoopOpcodeIndexInfo::read_from_bytes(&data[..size_of::<BtSnoopOpcodeIndexInfo>()])
        {
            Ok(h) => h,
            Err(_) => return,
        };

    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].manufacturer = hdr.manufacturer;
}

/// Handle VENDOR_DIAG opcode: increment counter.
fn vendor_diag(dev_list: &mut Vec<HciDev>, index: u16) {
    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].vendor_diag += 1;
}

/// Handle SYSTEM_NOTE opcode: increment counter.
fn system_note_handler(dev_list: &mut Vec<HciDev>, index: u16) {
    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].system_note += 1;
}

/// Handle USER_LOGGING opcode: increment counter.
fn user_log(dev_list: &mut Vec<HciDev>, index: u16) {
    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].user_log += 1;
}

/// Handle control messages (CTRL_OPEN, CTRL_CLOSE, CTRL_COMMAND, CTRL_EVENT).
fn ctrl_msg(dev_list: &mut Vec<HciDev>, index: u16) {
    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].ctrl_msg += 1;
}

/// Handle unknown opcodes: increment counter.
fn unknown_opcode(dev_list: &mut Vec<HciDev>, index: u16) {
    let dev_idx = dev_lookup(dev_list, index);
    dev_list[dev_idx].unknown += 1;
}

// ============================================================================
// Public API
// ============================================================================

/// Analyze a btsnoop trace file and print a comprehensive summary report.
///
/// Opens the btsnoop file at `path`, iterates all HCI records, builds
/// per-controller/per-connection/per-channel statistics models, and
/// prints a hierarchical summary including packet counts, latency
/// distributions, throughput calculations, and optional gnuplot histograms.
///
/// This function is the Rust equivalent of C `analyze_trace()` from
/// `monitor/analyze.c`.
pub fn analyze_trace(path: &str) {
    let mut btsnoop_file = match BtSnoop::open(path, BTSNOOP_FLAG_PKLG_SUPPORT) {
        Ok(f) => f,
        Err(_) => return,
    };

    let format = btsnoop_file.get_format();

    match format {
        BtSnoopFormat::Hci | BtSnoopFormat::Uart | BtSnoopFormat::Monitor => {}
        _ => {
            eprintln!("Unsupported packet format");
            return;
        }
    }

    let mut dev_list: Vec<HciDev> = Vec::new();
    let mut num_packets: usize = 0;
    let mut num_frames: usize = 0;
    let mut buf = vec![0u8; MAX_PACKET_SIZE];

    loop {
        let record: HciRecord = match btsnoop_file.read_hci(&mut buf) {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(_) => break,
        };

        let pktlen = record.size as usize;
        let data = &buf[..pktlen.min(buf.len())];

        match record.opcode {
            x if x == BtSnoopOpcode::NewIndex as u16 => {
                new_index(&mut dev_list, record.index, data);
            }
            x if x == BtSnoopOpcode::DelIndex as u16 => {
                del_index(&mut dev_list, record.index);
            }
            x if x == BtSnoopOpcode::CommandPkt as u16 => {
                num_frames += 1;
                command_pkt(&mut dev_list, record.index);
            }
            x if x == BtSnoopOpcode::EventPkt as u16 => {
                num_frames += 1;
                event_pkt(&mut dev_list, &record.tv, record.index, num_frames, data);
            }
            x if x == BtSnoopOpcode::AclTxPkt as u16 => {
                num_frames += 1;
                acl_pkt(&mut dev_list, &record.tv, record.index, true, data);
            }
            x if x == BtSnoopOpcode::AclRxPkt as u16 => {
                num_frames += 1;
                acl_pkt(&mut dev_list, &record.tv, record.index, false, data);
            }
            x if x == BtSnoopOpcode::ScoTxPkt as u16 => {
                num_frames += 1;
                sco_pkt(&mut dev_list, &record.tv, record.index, true, data);
            }
            x if x == BtSnoopOpcode::ScoRxPkt as u16 => {
                num_frames += 1;
                sco_pkt(&mut dev_list, &record.tv, record.index, false, data);
            }
            x if x == BtSnoopOpcode::OpenIndex as u16 || x == BtSnoopOpcode::CloseIndex as u16 => {
                // No action needed for open/close index
            }
            x if x == BtSnoopOpcode::IndexInfo as u16 => {
                info_index(&mut dev_list, record.index, data);
            }
            x if x == BtSnoopOpcode::VendorDiag as u16 => {
                vendor_diag(&mut dev_list, record.index);
            }
            x if x == BtSnoopOpcode::SystemNote as u16 => {
                system_note_handler(&mut dev_list, record.index);
            }
            x if x == BtSnoopOpcode::UserLogging as u16 => {
                user_log(&mut dev_list, record.index);
            }
            x if x == BtSnoopOpcode::CtrlOpen as u16
                || x == BtSnoopOpcode::CtrlClose as u16
                || x == BtSnoopOpcode::CtrlCommand as u16
                || x == BtSnoopOpcode::CtrlEvent as u16 =>
            {
                ctrl_msg(&mut dev_list, record.index);
            }
            x if x == BtSnoopOpcode::IsoTxPkt as u16 => {
                num_frames += 1;
                iso_pkt(&mut dev_list, &record.tv, record.index, true, data);
            }
            x if x == BtSnoopOpcode::IsoRxPkt as u16 => {
                num_frames += 1;
                iso_pkt(&mut dev_list, &record.tv, record.index, false, data);
            }
            _ => {
                unknown_opcode(&mut dev_list, record.index);
            }
        }

        num_packets += 1;
    }

    print_text!(crate::display::COLOR_HIGHLIGHT, "Trace contains {} packets", num_packets);
    println!();

    for dev in &dev_list {
        dev_destroy(dev);
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_trace_nonexistent_file() {
        // Should not panic — returns silently on open failure
        analyze_trace("/nonexistent/file.btsnoop");
    }

    #[test]
    fn test_analyze_trace_empty_path() {
        // Should not panic — returns silently on open failure
        analyze_trace("");
    }

    #[test]
    fn test_analyze_trace_exported() {
        // Verify the function pointer type matches expected signature
        let _fn_ptr: fn(&str) = analyze_trace;
    }

    #[test]
    fn test_tv_msec_zero() {
        let tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        assert_eq!(tv_msec(&tv), 0);
    }

    #[test]
    fn test_tv_msec_one_second() {
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        assert_eq!(tv_msec(&tv), 1000);
    }

    #[test]
    fn test_tv_msec_mixed() {
        let tv = libc::timeval { tv_sec: 2, tv_usec: 500_000 };
        assert_eq!(tv_msec(&tv), 2500);
    }

    #[test]
    fn test_timerisset_zero() {
        let tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        assert!(!timerisset(&tv));
    }

    #[test]
    fn test_timerisset_set() {
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        assert!(timerisset(&tv));
    }

    #[test]
    fn test_timersub_basic() {
        let a = libc::timeval { tv_sec: 5, tv_usec: 500_000 };
        let b = libc::timeval { tv_sec: 3, tv_usec: 200_000 };
        let mut result = libc::timeval { tv_sec: 0, tv_usec: 0 };
        timersub(&a, &b, &mut result);
        assert_eq!(result.tv_sec, 2);
        assert_eq!(result.tv_usec, 300_000);
    }

    #[test]
    fn test_timersub_borrow() {
        let a = libc::timeval { tv_sec: 5, tv_usec: 100_000 };
        let b = libc::timeval { tv_sec: 3, tv_usec: 400_000 };
        let mut result = libc::timeval { tv_sec: 0, tv_usec: 0 };
        timersub(&a, &b, &mut result);
        assert_eq!(result.tv_sec, 1);
        assert_eq!(result.tv_usec, 700_000);
    }

    #[test]
    fn test_hci_dev_new() {
        let dev = HciDev::new(42);
        assert_eq!(dev.index, 42);
        assert_eq!(dev.type_, 0);
        assert_eq!(dev.manufacturer, 0xffff);
        assert!(dev.conn_list.is_empty());
        assert_eq!(dev.num_hci, 0);
    }

    #[test]
    fn test_hci_conn_new() {
        let conn = HciConn::new(0x0040, BtmonConn::Acl as u8);
        assert_eq!(conn.handle, 0x0040);
        assert_eq!(conn.type_, BtmonConn::Acl as u8);
        assert!(!conn.setup_seen);
        assert!(!conn.terminated);
        assert!(conn.tx_queue.is_empty());
        assert!(conn.chan_list.is_empty());
    }

    #[test]
    fn test_hci_stats_new() {
        let stats = HciStats::new();
        assert_eq!(stats.num, 0);
        assert_eq!(stats.bytes, 0);
        assert_eq!(stats.num_comp, 0);
        assert_eq!(stats.min, 0);
        assert_eq!(stats.max, 0);
    }

    #[test]
    fn test_stats_add() {
        let mut stats = HciStats::new();
        stats_add(&mut stats, 100);
        assert_eq!(stats.num, 1);
        assert_eq!(stats.bytes, 100);
        assert_eq!(stats.min, 100);
        assert_eq!(stats.max, 100);

        stats_add(&mut stats, 50);
        assert_eq!(stats.num, 2);
        assert_eq!(stats.bytes, 150);
        assert_eq!(stats.min, 50);
        assert_eq!(stats.max, 100);

        stats_add(&mut stats, 200);
        assert_eq!(stats.num, 3);
        assert_eq!(stats.bytes, 350);
        assert_eq!(stats.min, 50);
        assert_eq!(stats.max, 200);
    }

    #[test]
    fn test_dev_lookup_creates_new() {
        let mut dev_list: Vec<HciDev> = Vec::new();
        let idx = dev_lookup(&mut dev_list, 0);
        assert_eq!(idx, 0);
        assert_eq!(dev_list.len(), 1);
        assert_eq!(dev_list[0].index, 0);
    }

    #[test]
    fn test_dev_lookup_finds_existing() {
        let mut dev_list: Vec<HciDev> = Vec::new();
        dev_lookup(&mut dev_list, 0);
        dev_lookup(&mut dev_list, 1);
        let idx = dev_lookup(&mut dev_list, 0);
        assert_eq!(idx, 0);
        assert_eq!(dev_list.len(), 2);
    }

    #[test]
    fn test_conn_lookup_type_creates_new() {
        let mut dev = HciDev::new(0);
        let idx = conn_lookup_type(&mut dev, 0x0040, BtmonConn::Acl as u8);
        assert_eq!(idx, 0);
        assert_eq!(dev.conn_list.len(), 1);
        assert_eq!(dev.conn_list[0].handle, 0x0040);
    }

    #[test]
    fn test_conn_lookup_type_finds_existing() {
        let mut dev = HciDev::new(0);
        conn_lookup_type(&mut dev, 0x0040, BtmonConn::Acl as u8);
        let idx = conn_lookup_type(&mut dev, 0x0040, BtmonConn::Acl as u8);
        assert_eq!(idx, 0);
        assert_eq!(dev.conn_list.len(), 1);
    }

    #[test]
    fn test_conn_lookup_type_mismatched_type_creates_new() {
        let mut dev = HciDev::new(0);
        conn_lookup_type(&mut dev, 0x0040, BtmonConn::Acl as u8);
        let idx = conn_lookup_type(&mut dev, 0x0040, BtmonConn::Le as u8);
        assert_eq!(idx, 1);
        assert_eq!(dev.conn_list.len(), 2);
    }

    #[test]
    fn test_conn_pkt_tx_enqueues() {
        let mut conn = HciConn::new(0x0040, BtmonConn::Acl as u8);
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        conn_pkt_tx(&mut conn, &tv, 100, None);
        assert_eq!(conn.tx_queue.len(), 1);
        assert_eq!(conn.tx.num, 1);
        assert_eq!(conn.tx.bytes, 100);
    }

    #[test]
    fn test_conn_pkt_rx_updates_stats() {
        let mut conn = HciConn::new(0x0040, BtmonConn::Acl as u8);
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        conn_pkt_rx(&mut conn, &tv, 200, None);
        assert_eq!(conn.rx.num, 1);
        assert_eq!(conn.rx.bytes, 200);
        assert_eq!(conn.rx.num_comp, 1);
    }

    #[test]
    fn test_plot_add_new_bucket() {
        let mut plot: Vec<PlotEntry> = Vec::new();
        let tv = libc::timeval { tv_sec: 0, tv_usec: 5_000 };
        plot_add(&mut plot, &tv, 1);
        assert_eq!(plot.len(), 1);
        assert_eq!(plot[0].x_msec, 5);
        assert_eq!(plot[0].y_count, 1);
    }

    #[test]
    fn test_plot_add_existing_bucket() {
        let mut plot: Vec<PlotEntry> = Vec::new();
        let tv = libc::timeval { tv_sec: 0, tv_usec: 5_000 };
        plot_add(&mut plot, &tv, 1);
        plot_add(&mut plot, &tv, 2);
        assert_eq!(plot.len(), 1);
        assert_eq!(plot[0].y_count, 3);
    }

    #[test]
    fn test_l2cap_chan_lookup_creates_new() {
        let mut conn = HciConn::new(0x0040, BtmonConn::Acl as u8);
        let idx = chan_lookup(&mut conn, 0x0040, true);
        assert_eq!(idx, 0);
        assert_eq!(conn.chan_list.len(), 1);
        assert_eq!(conn.chan_list[0].cid, 0x0040);
        assert!(conn.chan_list[0].out);
    }

    #[test]
    fn test_l2cap_chan_lookup_finds_existing() {
        let mut conn = HciConn::new(0x0040, BtmonConn::Acl as u8);
        chan_lookup(&mut conn, 0x0040, true);
        let idx = chan_lookup(&mut conn, 0x0040, true);
        assert_eq!(idx, 0);
        assert_eq!(conn.chan_list.len(), 1);
    }

    #[test]
    fn test_conn_lookup_finds_active() {
        let mut dev = HciDev::new(0);
        conn_lookup_type(&mut dev, 0x0040, BtmonConn::Acl as u8);
        let result = conn_lookup(&dev, 0x0040);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_conn_lookup_ignores_terminated() {
        let mut dev = HciDev::new(0);
        conn_lookup_type(&mut dev, 0x0040, BtmonConn::Acl as u8);
        dev.conn_list[0].terminated = true;
        let result = conn_lookup(&dev, 0x0040);
        assert!(result.is_none());
    }
}
