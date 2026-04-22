// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors

//! MGMT Command Round-Trip Latency Benchmark
//!
//! Criterion benchmark measuring MGMT command round-trip latency for
//! Gate 3 validation (AAP Section 0.8.3).  The threshold is:
//! **MGMT round-trip latency ≤ 1.1× C original.**
//!
//! Measured values are required per AAP 0.8.4 — "assumed parity is not
//! acceptable."
//!
//! # Measurement Methodology
//!
//! Each benchmark iteration measures the time from command serialisation
//! through socket write, socket read, response parsing, and oneshot-channel
//! delivery — the complete hot path of the MGMT protocol client.
//!
//! # Reference C Code
//!
//! The C implementation being replaced:
//! - `src/shared/mgmt.c` — `struct mgmt` (lines 33–53): request queue,
//!   reply queue, pending list, notify list, raw socket I/O.
//! - `src/shared/mgmt.c` — `struct mgmt_request` (lines 55–69): per-command
//!   state including opcode, index, callback, and user data.
//! - `src/shared/mgmt.c` — `mgmt_send()` (lines 831–838): queue command,
//!   arm writer.
//! - `src/shared/mgmt.c` — `mgmt_send_timeout()` (lines 799–829): command
//!   submission with deadline.
//! - `src/shared/mgmt.c` — `can_read_data()` (lines 374–431): response
//!   dispatch — `MGMT_EV_CMD_COMPLETE` / `CMD_STATUS` routing + event
//!   notify.
//! - `src/shared/mgmt.c` — `mgmt_register()` (line 965): event
//!   subscription.
//!
//! # Rust Equivalents
//!
//! - [`MgmtSocket`] — async MGMT client with `send_command()` returning
//!   typed [`MgmtResponse`] via oneshot channel (AAP Section 0.7.6).
//! - [`MgmtSocket::subscribe()`] — event subscription returning
//!   `mpsc::Receiver<MgmtEvent>`.
//!
//! # Benchmark Design
//!
//! Benchmarks use a Unix-domain socketpair to create a connected pair of
//! file descriptors.  One end feeds [`MgmtSocket`]; a mock responder
//! thread reads commands from the other end and writes back CMD_COMPLETE
//! responses with appropriate return parameters.  This avoids requiring
//! `/dev/vhci` kernel support for CI-friendly CPU-bound benchmarks.
//!
//! The [`setup_mgmt_with_emulator()`] function provides an alternative
//! integration-level setup using a real VHCI-backed [`HciEmulator`].
//!
//! # AAP References
//!
//! - Section 0.8.3 Gate 3: Performance Baseline Comparison
//! - Section 0.8.4: Measured values required

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use tokio::runtime::Runtime;

use bluez_emulator::BtDevType;
use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_emulator::vhci::Vhci;
use bluez_shared::mgmt::client::{MgmtError, MgmtEvent, MgmtResponse, MgmtSocket};
use bluez_shared::sys::mgmt::{
    MGMT_EV_CMD_COMPLETE, MGMT_EV_INDEX_ADDED, MGMT_HDR_SIZE, MGMT_INDEX_NONE,
    MGMT_OP_READ_COMMANDS, MGMT_OP_READ_INFO, MGMT_OP_READ_VERSION, MGMT_STATUS_SUCCESS,
    mgmt_ev_cmd_complete, mgmt_hdr, mgmt_rp_read_info, mgmt_rp_read_version,
};

// ---------------------------------------------------------------------------
// Compile-time type compatibility assertions
// ---------------------------------------------------------------------------

/// Verify that the MGMT header is exactly 6 bytes (opcode + index + length).
const _MGMT_HDR_SIZE_CHECK: () = assert!(MGMT_HDR_SIZE == 6);

/// Verify [`mgmt_hdr`] struct size matches [`MGMT_HDR_SIZE`].
const _MGMT_HDR_STRUCT_SIZE: () = assert!(std::mem::size_of::<mgmt_hdr>() == MGMT_HDR_SIZE);

/// Verify [`mgmt_ev_cmd_complete`] is 3 bytes (opcode u16 + status u8).
const _CMD_COMPLETE_SIZE: () = assert!(std::mem::size_of::<mgmt_ev_cmd_complete>() == 3);

/// Compile-time size capture for [`mgmt_rp_read_version`] — 3 bytes.
const _READ_VERSION_RP_SIZE: usize = std::mem::size_of::<mgmt_rp_read_version>();

/// Compile-time size capture for [`mgmt_rp_read_info`] — ~280 bytes.
const _READ_INFO_RP_SIZE: usize = std::mem::size_of::<mgmt_rp_read_info>();

/// Verify [`MgmtResponse`] is importable and sized.
const _MGMT_RESPONSE_SIZE: usize = std::mem::size_of::<MgmtResponse>();

/// Verify [`MgmtEvent`] is importable and sized.
const _MGMT_EVENT_SIZE: usize = std::mem::size_of::<MgmtEvent>();

/// Verify [`MgmtError`] is importable and sized.
const _MGMT_ERROR_SIZE: usize = std::mem::size_of::<MgmtError>();

// ---------------------------------------------------------------------------
// Mock MGMT kernel responder
// ---------------------------------------------------------------------------

/// Build a MGMT `CMD_COMPLETE` response packet for the given command opcode.
///
/// Wire format (matching `lib/bluetooth/mgmt.h`):
/// ```text
/// [mgmt_hdr: event=0x0001, index, len=3+rp_len]
/// [mgmt_ev_cmd_complete: opcode, status=SUCCESS]
/// [return_params: rp_len bytes]
/// ```
fn build_cmd_complete(opcode: u16, index: u16, return_params: &[u8]) -> Vec<u8> {
    let ev_data_len: u16 = 3 + return_params.len() as u16;
    let mut buf = Vec::with_capacity(MGMT_HDR_SIZE + ev_data_len as usize);

    // mgmt_hdr: event code, controller index, payload length
    buf.extend_from_slice(&MGMT_EV_CMD_COMPLETE.to_le_bytes());
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&ev_data_len.to_le_bytes());

    // mgmt_ev_cmd_complete: original command opcode + status
    buf.extend_from_slice(&opcode.to_le_bytes());
    buf.push(MGMT_STATUS_SUCCESS);

    // Return parameters specific to the command
    buf.extend_from_slice(return_params);

    buf
}

/// Build return parameters for `MGMT_OP_READ_VERSION` (opcode 0x0001).
///
/// Returns a 3-byte payload: `{ version: u8, revision: u16_le }`.
fn build_read_version_rp() -> Vec<u8> {
    let mut rp = Vec::with_capacity(_READ_VERSION_RP_SIZE);
    rp.push(1); // MGMT interface version
    rp.extend_from_slice(&23u16.to_le_bytes()); // revision
    rp
}

/// Build return parameters for `MGMT_OP_READ_INFO` (opcode 0x0004).
///
/// Returns a payload matching [`mgmt_rp_read_info`] (~280 bytes).
fn build_read_info_rp() -> Vec<u8> {
    let mut rp = vec![0u8; _READ_INFO_RP_SIZE];
    // address: 6 bytes at offset 0 — synthetic BD_ADDR
    rp[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    // bluetooth_version: u8 at offset 6
    rp[6] = 0x09; // BT 5.0
    // manufacturer: u16_le at offset 7
    rp[7..9].copy_from_slice(&0x000Au16.to_le_bytes());
    // supported_settings: u32_le at offset 9
    rp[9..13].copy_from_slice(&0x003F_FFFFu32.to_le_bytes());
    // current_settings: u32_le at offset 13
    rp[13..17].copy_from_slice(&0x0000_0001u32.to_le_bytes());
    // dev_class[3], name[249], short_name[11] — zeroed
    rp
}

/// Build return parameters for `MGMT_OP_READ_COMMANDS` (opcode 0x0002).
///
/// Returns a 4-byte payload: `{ num_commands: u16_le, num_events: u16_le }`.
fn build_read_commands_rp() -> Vec<u8> {
    let mut rp = Vec::with_capacity(4);
    rp.extend_from_slice(&0u16.to_le_bytes()); // num_commands
    rp.extend_from_slice(&0u16.to_le_bytes()); // num_events
    rp
}

/// Build a MGMT event notification packet.
///
/// Wire format:
/// ```text
/// [mgmt_hdr: event=event_code, index, len=data.len()]
/// [event_data]
/// ```
fn build_event_packet(event_code: u16, index: u16, data: &[u8]) -> Vec<u8> {
    let data_len = data.len() as u16;
    let mut buf = Vec::with_capacity(MGMT_HDR_SIZE + data.len());
    buf.extend_from_slice(&event_code.to_le_bytes());
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&data_len.to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Spawn a mock MGMT kernel responder thread.
///
/// The thread reads MGMT command packets from `mock_fd`, parses the opcode,
/// and writes back a `CMD_COMPLETE` response with appropriate return
/// parameters.  The thread exits when the peer socket is closed (read
/// returns 0 or an error).
fn spawn_mock_responder(mock_fd: OwnedFd) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut file = std::fs::File::from(mock_fd);
        let mut buf = [0u8; 4096];

        loop {
            // The mock fd is non-blocking (SOCK_NONBLOCK set at socketpair
            // creation).  Handle WouldBlock by yielding and retrying — data
            // arrives within microseconds in benchmark scenarios because the
            // writer_loop sends the command before the responder reads.
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                    continue;
                }
                Err(_) => break,
            };

            if n < MGMT_HDR_SIZE {
                continue;
            }

            // Parse request header: opcode (u16_le) at offset 0, index at offset 2
            let opcode = u16::from_le_bytes([buf[0], buf[1]]);
            let index = u16::from_le_bytes([buf[2], buf[3]]);

            // Build return parameters based on the command opcode
            let rp = match opcode {
                MGMT_OP_READ_VERSION => build_read_version_rp(),
                MGMT_OP_READ_INFO => build_read_info_rp(),
                MGMT_OP_READ_COMMANDS => build_read_commands_rp(),
                _ => Vec::new(),
            };

            let response = build_cmd_complete(opcode, index, &rp);
            // SEQPACKET writes are atomic — retry on WouldBlock (buffer full).
            loop {
                match file.write_all(&response) {
                    Ok(()) => break,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(_) => return,
                }
            }
        }
    })
}

/// Create a connected [`MgmtSocket`] pair using a Unix-domain socketpair.
///
/// Returns `(MgmtSocket, mock_fd)` where `mock_fd` is the simulated
/// kernel-side end of the connection.  The [`MgmtSocket`] end is wrapped
/// in an `AsyncFd` for async I/O via tokio.
///
/// Uses `SOCK_SEQPACKET` to preserve message boundaries, matching the
/// datagram semantics of the real `HCI_CHANNEL_CONTROL` MGMT socket.
fn create_mgmt_socketpair() -> (MgmtSocket, OwnedFd) {
    // Create both fds as non-blocking (SOCK_NONBLOCK) so that the mgmt fd
    // works correctly with tokio::io::unix::AsyncFd.  AsyncFd requires the
    // underlying fd to be O_NONBLOCK — without it, the reader_loop's
    // guard.try_io(|fd| nix::unistd::read(..)) issues a blocking read that
    // never returns WouldBlock, stalling the tokio runtime thread and causing
    // an indefinite hang in send_command().
    //
    // Both fds receive SOCK_NONBLOCK; the mock responder thread handles
    // WouldBlock via yield_now() spin-wait (see spawn_mock_responder).
    let (fd_mgmt, fd_mock) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair creation failed");

    let mgmt = MgmtSocket::new(fd_mgmt).expect("MgmtSocket creation failed");
    (mgmt, fd_mock)
}

// ---------------------------------------------------------------------------
// Public API — Real emulator fixture
// ---------------------------------------------------------------------------

/// Create a [`MgmtSocket`] connected to a real VHCI-backed [`HciEmulator`].
///
/// This function requires `/dev/vhci` kernel support and creates a virtual
/// Bluetooth controller for integration-level benchmarks that need
/// realistic MGMT command handling.
///
/// Mirrors the C test setup from `tools/mgmt-tester.c`
/// (`tester_setup_complete`) where the emulator is created, then a MGMT
/// socket is opened via the standard `HCI_CHANNEL_CONTROL` path.
///
/// # Errors
///
/// Returns an error if:
/// - `/dev/vhci` is not available (missing kernel module)
/// - The HCI emulator fails to initialise
/// - The MGMT socket cannot be opened
pub fn setup_mgmt_with_emulator() -> Result<(MgmtSocket, HciEmulator), Box<dyn std::error::Error>> {
    // Probe VHCI kernel device availability before creating the full
    // emulator stack.  This provides a clear error message when /dev/vhci
    // is missing rather than a cryptic ioctl failure down the line.
    let vhci_probe = Vhci::open(BtDevType::BrEdrLe);
    if let Err(ref e) = vhci_probe {
        return Err(format!("VHCI device unavailable: {e}").into());
    }
    // Release the probed device; HciEmulator::new() creates its own.
    drop(vhci_probe);

    let emu = HciEmulator::new(EmulatorType::BrEdrLe)?;
    let mgmt = MgmtSocket::new_default()?;
    Ok((mgmt, emu))
}

// ---------------------------------------------------------------------------
// Benchmark: MGMT_OP_READ_VERSION round-trip latency
// ---------------------------------------------------------------------------

/// Measure the round-trip latency of `MGMT_OP_READ_VERSION` (opcode 0x0001).
///
/// This is the simplest MGMT command: zero-length parameters, 3-byte
/// response.  It isolates the core overhead of command serialisation,
/// socket I/O, response parsing, and oneshot-channel delivery.
fn bench_mgmt_read_version_latency(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime creation failed");
    let (mgmt, mock_fd) = rt.block_on(async { create_mgmt_socketpair() });
    let _responder = spawn_mock_responder(mock_fd);

    c.bench_function("mgmt_read_version_latency", |b| {
        b.iter(|| {
            rt.block_on(async {
                let resp = mgmt
                    .send_command(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, &[])
                    .await
                    .expect("read_version send_command failed");
                black_box(resp);
            });
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: MGMT_OP_READ_INFO round-trip latency
// ---------------------------------------------------------------------------

/// Measure the round-trip latency of `MGMT_OP_READ_INFO` (opcode 0x0004).
///
/// This exercises a larger response payload (~280 bytes), testing the
/// deserialisation path more thoroughly.  `READ_INFO` is one of the most
/// frequently used MGMT commands during adapter initialisation
/// (`adapter.c`).
fn bench_mgmt_read_info_latency(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime creation failed");
    let (mgmt, mock_fd) = rt.block_on(async { create_mgmt_socketpair() });
    let _responder = spawn_mock_responder(mock_fd);

    c.bench_function("mgmt_read_info_latency", |b| {
        b.iter(|| {
            rt.block_on(async {
                let resp = mgmt
                    .send_command(MGMT_OP_READ_INFO, 0, &[])
                    .await
                    .expect("read_info send_command failed");
                black_box(resp);
            });
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: MGMT command queue throughput
// ---------------------------------------------------------------------------

/// Measure the throughput of sending multiple MGMT commands in rapid
/// succession.
///
/// Tests the request-queue and pending-list management paths:
/// - C reference: `mgmt->request_queue` (mgmt.c line 39)
/// - C reference: `mgmt->pending_list` (mgmt.c line 40)
///
/// Commands are sent sequentially within each iteration to measure
/// the sustained command pipeline throughput.  The batch sizes (10, 50,
/// 100) exercise both small-queue and large-queue performance.
fn bench_mgmt_command_queue_throughput(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime creation failed");
    let (mgmt, mock_fd) = rt.block_on(async { create_mgmt_socketpair() });
    let _responder = spawn_mock_responder(mock_fd);

    let mut group = c.benchmark_group("mgmt_command_queue_throughput");
    for &batch_size in &[10u32, 50, 100] {
        group.bench_with_input(BenchmarkId::new("batch", batch_size), &batch_size, |b, &size| {
            b.iter(|| {
                rt.block_on(async {
                    for _ in 0..size {
                        let resp = mgmt
                            .send_command(MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, &[])
                            .await
                            .expect("batch send_command failed");
                        black_box(resp);
                    }
                });
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: MGMT event notification dispatch latency
// ---------------------------------------------------------------------------

/// Measure the latency of MGMT event notification dispatch.
///
/// Exercises the event subscription and delivery pipeline:
/// - C reference: `mgmt_register()` (mgmt.c line 965)
/// - C reference: `mgmt->notify_list` processing in `process_notify()`
///   (mgmt.c lines 355–372)
///
/// Each iteration injects a `MGMT_EV_INDEX_ADDED` event into the mock
/// socket end and measures the time until the subscriber receives it
/// via the `mpsc::Receiver<MgmtEvent>` channel.
fn bench_mgmt_event_notification(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime creation failed");
    let (mgmt, mock_fd) = rt.block_on(async { create_mgmt_socketpair() });

    // Subscribe to INDEX_ADDED events (event code 0x0004).
    // This mirrors the C `mgmt_register(mgmt, MGMT_EV_INDEX_ADDED, ...)`.
    let (_sub_id, mut rx) =
        rt.block_on(async { mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await });

    // Convert mock_fd to File for direct event injection from the
    // benchmark thread (no separate responder needed for events).
    let mut mock_file = std::fs::File::from(mock_fd);

    // Pre-build the event packet: INDEX_ADDED with controller index 0,
    // no payload.  This is the minimal MGMT event (header only).
    let event_packet = build_event_packet(MGMT_EV_INDEX_ADDED, 0, &[]);

    c.bench_function("mgmt_event_notification", |b| {
        b.iter(|| {
            // Inject event into the socket buffer (blocking write, typically
            // completes immediately for small packets).
            mock_file.write_all(&event_packet).expect("event injection write failed");

            // Drive the tokio runtime to process the event and deliver it
            // through the subscriber channel.
            rt.block_on(async {
                let evt = rx.recv().await.expect("event recv failed");
                black_box(evt);
            });
        });
    });

    // Keep mgmt alive until benchmark completes to avoid closing the
    // socket prematurely.  The drop here is explicit for clarity.
    drop(mgmt);
}

// ---------------------------------------------------------------------------
// Criterion benchmark group registration
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(3))
        .sample_size(200);
    targets = bench_mgmt_read_version_latency,
              bench_mgmt_read_info_latency,
              bench_mgmt_command_queue_throughput,
              bench_mgmt_event_notification
}
criterion_main!(benches);
