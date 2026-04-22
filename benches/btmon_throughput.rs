// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 Intel Corporation. All rights reserved.

//! btmon packet decode throughput benchmark for Gate 3 validation.
//!
//! Validates AAP Section 0.8.3 Gate 3 threshold: **btmon decode throughput
//! ≥ 0.9× C original**. Measured values are required — assumed parity is
//! not acceptable (AAP Section 0.8.4).
//!
//! # Measurement Methodology
//!
//! The benchmark measures packets decoded per second for a synthetic btsnoop
//! capture containing a representative mix of HCI command, event, ACL, and
//! control packets. This mirrors the hot path in the C `control_reader()`
//! function (monitor/control.c lines 1531-1595):
//!
//! ```text
//! while (1) {
//!     btsnoop_read_hci(file, &tv, &index, &opcode, buf, &pktlen);
//!     packet_monitor(&tv, NULL, index, opcode, buf, pktlen);
//! }
//! ```
//!
//! The Rust equivalent reads packets via [`BtSnoop::read_hci`] and dispatches
//! them through [`btmon::packet::packet_monitor`] for HCI command/event/ACL/
//! SCO/ISO decoding and human-readable output.
//!
//! # Benchmark Functions
//!
//! - **`bench_btmon_decode_throughput`** — Full decode pipeline throughput
//!   (btsnoop read → packet_monitor dispatch) across a mixed packet capture.
//! - **`bench_btmon_decode_per_protocol`** — Parameterised benchmarks per
//!   protocol type (HCI command/event, ACL data, control messages).
//! - **`bench_btsnoop_read_throughput`** — Raw btsnoop file I/O performance,
//!   isolating capture format parsing from protocol decoding.
//!
//! # References
//!
//! - AAP Section 0.8.3 Gate 3 — Performance Baseline Comparison
//! - AAP Section 0.8.4 — Measured values required
//! - C source: `monitor/control.c:control_reader()` (lines 1531-1595)
//! - C source: `monitor/packet.c:packet_monitor()`
//! - C source: `src/shared/btsnoop.c:btsnoop_read_hci()`

use std::fs::{self, File};
use std::io::Write;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use zerocopy::IntoBytes;

use bluez_shared::capture::btsnoop::{
    BtSnoop, BtSnoopFormat, BtSnoopOpcode, BtSnoopOpcodeIndexInfo, BtSnoopOpcodeNewIndex,
    HciRecord, MAX_PACKET_SIZE,
};
use btmon::packet::{self, PacketFilter};

// ---------------------------------------------------------------------------
// Synthetic btsnoop capture data generation
// ---------------------------------------------------------------------------

/// Number of packets per protocol type in the mixed capture.
const PACKETS_PER_TYPE: usize = 500;

/// Build a minimal but realistic HCI Command packet payload.
///
/// Layout: 3-byte HCI command header (opcode LE + param_len) followed by
/// `extra_len` bytes of zero-padded parameters.
fn build_hci_command(ogf: u16, ocf: u16, extra_len: usize) -> Vec<u8> {
    let opcode = (ogf << 10) | ocf;
    let param_len = extra_len as u8;
    let mut pkt = Vec::with_capacity(3 + extra_len);
    // Use Write::write_all for constructing the HCI command header bytes
    pkt.write_all(&opcode.to_le_bytes()).expect("Vec write infallible");
    pkt.write_all(&[param_len]).expect("Vec write infallible");
    pkt.resize(3 + extra_len, 0x00);
    pkt
}

/// Build a minimal HCI Event packet payload.
///
/// Layout: 2-byte event header (event code + param_len) followed by
/// `extra_len` bytes of zero-padded parameters.
fn build_hci_event(event_code: u8, extra_len: usize) -> Vec<u8> {
    let param_len = extra_len as u8;
    let mut pkt = Vec::with_capacity(2 + extra_len);
    pkt.push(event_code);
    pkt.push(param_len);
    pkt.resize(2 + extra_len, 0x00);
    pkt
}

/// Build a minimal ACL data packet payload.
///
/// Layout: 4-byte ACL header (handle+flags LE, data_len LE) followed by
/// `payload_len` bytes of zero-padded data.
fn build_acl_data(handle: u16, payload_len: usize) -> Vec<u8> {
    let handle_flags = handle & 0x0FFF; // PB=0, BC=0
    let data_len = payload_len as u16;
    let mut pkt = Vec::with_capacity(4 + payload_len);
    pkt.extend_from_slice(&handle_flags.to_le_bytes());
    pkt.extend_from_slice(&data_len.to_le_bytes());
    pkt.resize(4 + payload_len, 0xAB);
    pkt
}

/// Temporary file path for benchmark btsnoop captures.
fn temp_btsnoop_path(suffix: &str) -> String {
    format!("/tmp/bluez_bench_btsnoop_{suffix}.btsnoop")
}

/// Generate a synthetic btsnoop capture file at the given path containing a
/// representative mix of HCI packet types suitable for throughput measurement.
///
/// The capture contains:
/// - 1 × NewIndex packet (controller announcement)
/// - 1 × IndexInfo packet (controller metadata)
/// - `PACKETS_PER_TYPE` × HCI Command packets (mixed OGFs, 4-32 byte payloads)
/// - `PACKETS_PER_TYPE` × HCI Event packets (mixed codes, 10-50 byte payloads)
/// - `PACKETS_PER_TYPE` × ACL TX packets (200-600 byte payloads)
/// - `PACKETS_PER_TYPE` × ACL RX packets (100-400 byte payloads)
///
/// Returns the total number of packets written (including headers).
fn generate_mixed_capture(path: &str) -> u64 {
    let mut snoop = BtSnoop::create(path, 0, 0, BtSnoopFormat::Monitor)
        .expect("BtSnoop::create for benchmark capture");

    let tv = libc::timeval { tv_sec: 1_700_000_000, tv_usec: 0 };

    // Write NewIndex packet — announces controller hci0
    let new_idx = BtSnoopOpcodeNewIndex {
        type_: 0, // Primary
        bus: 1,   // USB
        bdaddr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        name: *b"hci0\0\0\0\0",
    };
    snoop
        .write_hci(&tv, 0, BtSnoopOpcode::NewIndex as u16, 0, new_idx.as_bytes())
        .expect("write NewIndex");

    // Write IndexInfo packet
    let idx_info = BtSnoopOpcodeIndexInfo {
        bdaddr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        manufacturer: 2u16.to_le(), // Intel
    };
    snoop
        .write_hci(&tv, 0, BtSnoopOpcode::IndexInfo as u16, 0, idx_info.as_bytes())
        .expect("write IndexInfo");

    let mut count: u64 = 2;

    // HCI Command packets — variety of OGFs and parameter sizes
    for i in 0..PACKETS_PER_TYPE {
        let ogf = ((i % 8) + 1) as u16; // OGFs 1-8
        let ocf = (i % 64) as u16;
        let extra = 4 + (i % 29); // 4-32 bytes
        let pkt = build_hci_command(ogf, ocf, extra);
        let pkt_tv = libc::timeval {
            tv_sec: tv.tv_sec + (i as i64) / 1000,
            tv_usec: ((i as i64) % 1000) * 1000,
        };
        snoop
            .write_hci(&pkt_tv, 0, BtSnoopOpcode::CommandPkt as u16, 0, &pkt)
            .expect("write HCI Command");
        count += 1;
    }

    // HCI Event packets — variety of event codes and sizes
    for i in 0..PACKETS_PER_TYPE {
        let evt_code = ((i % 62) + 1) as u8; // event codes 1-62
        let extra = 10 + (i % 41); // 10-50 bytes
        let pkt = build_hci_event(evt_code, extra);
        let pkt_tv = libc::timeval {
            tv_sec: tv.tv_sec + (PACKETS_PER_TYPE as i64 + i as i64) / 1000,
            tv_usec: ((PACKETS_PER_TYPE as i64 + i as i64) % 1000) * 1000,
        };
        snoop
            .write_hci(&pkt_tv, 0, BtSnoopOpcode::EventPkt as u16, 0, &pkt)
            .expect("write HCI Event");
        count += 1;
    }

    // ACL TX packets — larger payloads representing host→controller data
    for i in 0..PACKETS_PER_TYPE {
        let handle = ((i % 8) + 1) as u16;
        let payload = 200 + (i % 401); // 200-600 bytes
        let pkt = build_acl_data(handle, payload);
        let pkt_tv = libc::timeval {
            tv_sec: tv.tv_sec + (2 * PACKETS_PER_TYPE as i64 + i as i64) / 1000,
            tv_usec: ((2 * PACKETS_PER_TYPE as i64 + i as i64) % 1000) * 1000,
        };
        snoop.write_hci(&pkt_tv, 0, BtSnoopOpcode::AclTxPkt as u16, 0, &pkt).expect("write ACL TX");
        count += 1;
    }

    // ACL RX packets — controller→host data
    for i in 0..PACKETS_PER_TYPE {
        let handle = ((i % 8) + 1) as u16;
        let payload = 100 + (i % 301); // 100-400 bytes
        let pkt = build_acl_data(handle, payload);
        let pkt_tv = libc::timeval {
            tv_sec: tv.tv_sec + (3 * PACKETS_PER_TYPE as i64 + i as i64) / 1000,
            tv_usec: ((3 * PACKETS_PER_TYPE as i64 + i as i64) % 1000) * 1000,
        };
        snoop.write_hci(&pkt_tv, 0, BtSnoopOpcode::AclRxPkt as u16, 0, &pkt).expect("write ACL RX");
        count += 1;
    }

    count
}

/// Generate a protocol-specific btsnoop capture containing only packets of
/// a single opcode type. Returns the number of packets written.
fn generate_protocol_capture(path: &str, opcode: BtSnoopOpcode, count: usize) -> u64 {
    let mut snoop = BtSnoop::create(path, 0, 0, BtSnoopFormat::Monitor)
        .expect("BtSnoop::create for protocol capture");

    let base_tv = libc::timeval { tv_sec: 1_700_000_000, tv_usec: 0 };

    // Always start with a NewIndex so packet_monitor can initialise state
    let new_idx = BtSnoopOpcodeNewIndex {
        type_: 0,
        bus: 1,
        bdaddr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        name: *b"hci0\0\0\0\0",
    };
    snoop
        .write_hci(&base_tv, 0, BtSnoopOpcode::NewIndex as u16, 0, new_idx.as_bytes())
        .expect("write NewIndex header");

    let mut total: u64 = 1;

    for i in 0..count {
        let pkt_tv = libc::timeval {
            tv_sec: base_tv.tv_sec + (i as i64) / 1000,
            tv_usec: ((i as i64) % 1000) * 1000,
        };

        let pkt_data = match opcode {
            BtSnoopOpcode::CommandPkt => {
                let ogf = ((i % 8) + 1) as u16;
                let ocf = (i % 64) as u16;
                build_hci_command(ogf, ocf, 8 + (i % 25))
            }
            BtSnoopOpcode::EventPkt => {
                let evt = ((i % 62) + 1) as u8;
                build_hci_event(evt, 10 + (i % 41))
            }
            BtSnoopOpcode::AclTxPkt | BtSnoopOpcode::AclRxPkt => {
                let handle = ((i % 8) + 1) as u16;
                build_acl_data(handle, 200 + (i % 401))
            }
            _ => vec![0u8; 16], // Minimal payload for other opcodes
        };

        snoop.write_hci(&pkt_tv, 0, opcode as u16, 0, &pkt_data).expect("write protocol packet");
        total += 1;
    }

    total
}

// ---------------------------------------------------------------------------
// Benchmark: full decode throughput (mixed packet capture)
// ---------------------------------------------------------------------------

/// Benchmark the full btmon decode pipeline: btsnoop read → packet_monitor.
///
/// This mirrors the C `control_reader()` hot path (monitor/control.c lines
/// 1563-1573): reading each packet from a btsnoop capture and dispatching it
/// through `packet_monitor()` for decoding.
///
/// Throughput is reported as packets decoded per second.
fn bench_btmon_decode_throughput(c: &mut Criterion) {
    let path = temp_btsnoop_path("mixed");
    let packet_count = generate_mixed_capture(&path);

    let mut group = c.benchmark_group("btmon_throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.throughput(Throughput::Elements(packet_count));

    group.bench_function("decode_mixed", |b| {
        b.iter(|| {
            // Reset filter state before each iteration
            packet::set_filter(PacketFilter::SHOW_INDEX);

            let mut snoop = BtSnoop::open(&path, 0).expect("open benchmark capture");
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let mut decoded = 0u64;

            loop {
                let result: Result<Option<HciRecord>, _> = snoop.read_hci(&mut buf);
                match result {
                    Ok(Some(record)) => {
                        // Skip sentinel opcodes exactly as C does
                        // (control.c:1570-1571)
                        if record.opcode == 0xffff {
                            continue;
                        }

                        // Dispatch through the packet decode pipeline —
                        // the hot path
                        packet::packet_monitor(
                            &record.tv,
                            None,
                            record.index,
                            record.opcode,
                            &buf[..record.size as usize],
                            record.size as usize,
                        );
                        decoded += 1;
                    }
                    Ok(None) | Err(_) => break,
                }
            }

            black_box(decoded)
        });
    });

    group.finish();

    // Cleanup temporary file
    let _ = fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Benchmark: per-protocol decode throughput
// ---------------------------------------------------------------------------

/// Parameterised benchmark measuring decode throughput per protocol type.
///
/// Creates separate benchmarks for HCI command, HCI event, and ACL data
/// packets to validate that individual protocol dissectors maintain throughput
/// parity with the C original.
fn bench_btmon_decode_per_protocol(c: &mut Criterion) {
    let protocols: Vec<(&str, BtSnoopOpcode)> = vec![
        ("hci_command", BtSnoopOpcode::CommandPkt),
        ("hci_event", BtSnoopOpcode::EventPkt),
        ("acl_tx", BtSnoopOpcode::AclTxPkt),
        ("acl_rx", BtSnoopOpcode::AclRxPkt),
    ];

    let packets_per_proto: usize = 2000;

    let mut group = c.benchmark_group("btmon_per_protocol");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    // Construct a synthetic peer credential to exercise the `Option<&ucred>`
    // code path in `packet_monitor`, matching the `SCM_CREDENTIALS` ancillary
    // data that the real btmon receives from control sockets.
    let cred = libc::ucred { pid: std::process::id() as i32, uid: 0, gid: 0 };

    for (name, opcode) in &protocols {
        let path = temp_btsnoop_path(name);
        let pkt_count = generate_protocol_capture(&path, *opcode, packets_per_proto);

        group.throughput(Throughput::Elements(pkt_count));

        group.bench_with_input(BenchmarkId::new("decode", *name), opcode, |b, _opcode| {
            b.iter(|| {
                packet::set_filter(PacketFilter::SHOW_INDEX);

                let mut snoop = BtSnoop::open(&path, 0).expect("open protocol capture");
                let mut buf = vec![0u8; MAX_PACKET_SIZE];
                let mut decoded = 0u64;

                while let Ok(Some(record)) = snoop.read_hci(&mut buf) {
                    if record.opcode == 0xffff {
                        continue;
                    }

                    packet::packet_monitor(
                        &record.tv,
                        Some(&cred),
                        record.index,
                        record.opcode,
                        &buf[..record.size as usize],
                        record.size as usize,
                    );
                    decoded += 1;
                }

                black_box(decoded)
            });
        });
    }

    group.finish();

    // Cleanup temporary files
    for (name, _) in &protocols {
        let path = temp_btsnoop_path(name);
        let _ = fs::remove_file(&path);
    }
}

// ---------------------------------------------------------------------------
// Benchmark: raw btsnoop read throughput (I/O only, no decode)
// ---------------------------------------------------------------------------

/// Benchmark raw btsnoop file I/O performance, isolating capture format
/// parsing from protocol decoding.
///
/// This measures only the [`BtSnoop::read_hci`] path (corresponding to C
/// `btsnoop_read_hci()` in `src/shared/btsnoop.c`) without dispatching
/// packets through the decode pipeline.
fn bench_btsnoop_read_throughput(c: &mut Criterion) {
    let path = temp_btsnoop_path("read_only");
    let packet_count = generate_mixed_capture(&path);

    // Use File::open() to measure the btsnoop capture file size for
    // byte-throughput reporting, isolating I/O parsing from protocol decode.
    let file_size = File::open(&path)
        .expect("open btsnoop for metadata")
        .metadata()
        .expect("btsnoop file metadata")
        .len();

    let mut group = c.benchmark_group("btsnoop_read");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    // Report byte throughput — meaningful for I/O-focused benchmarks since
    // it shows raw capture parsing bandwidth (bytes/sec).
    group.throughput(Throughput::Bytes(file_size));

    group.bench_function("read_hci_bytes", |b| {
        b.iter(|| {
            let mut snoop = BtSnoop::open(&path, 0).expect("open read benchmark capture");
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let mut total_bytes = 0u64;
            let mut total_packets = 0u64;

            while let Ok(Some(record)) = snoop.read_hci(&mut buf) {
                total_bytes += record.size as u64;
                total_packets += 1;
            }

            black_box((total_packets, total_bytes))
        });
    });

    // Also report element (packet) throughput for comparison
    group.throughput(Throughput::Elements(packet_count));

    group.bench_function("read_hci_packets", |b| {
        b.iter(|| {
            let mut snoop = BtSnoop::open(&path, 0).expect("open read benchmark capture");
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let mut total_packets = 0u64;

            while let Ok(Some(record)) = snoop.read_hci(&mut buf) {
                total_packets += record.size as u64;
            }

            black_box(total_packets)
        });
    });

    group.finish();

    // Cleanup temporary file
    let _ = fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Criterion registration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_btmon_decode_throughput,
    bench_btmon_decode_per_protocol,
    bench_btsnoop_read_throughput
);
criterion_main!(benches);
