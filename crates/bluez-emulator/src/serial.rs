// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluez-emulator/src/serial.rs — PTY-backed H:4 HCI transport
//
// Complete Rust rewrite of emulator/serial.c (236 lines) and
// emulator/serial.h (24 lines).  Creates a pseudo-terminal (PTY),
// prints the slave path to stdout, and forwards HCI command packets
// between the PTY and a BtDev virtual controller.  Supports
// reconnect-on-hangup behaviour: when the slave side disconnects, a
// new PTY is transparently created.

use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::Arc;

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::pty::{PtyMaster, grantpt, posix_openpt, ptsname_r, unlockpt};
use nix::sys::uio::writev;
use nix::unistd::read;
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::task::{JoinHandle, spawn};

use crate::btdev::{BtDev, BtDevError, BtDevType};
use bluez_shared::sys::hci::{HCI_COMMAND_HDR_SIZE, HCI_COMMAND_PKT};

// ---------------------------------------------------------------------------
// SerialType — controller type for the serial PTY emulator
// ---------------------------------------------------------------------------

/// Controller type for the serial PTY emulator.
///
/// Maps directly to `enum serial_type` in `emulator/serial.h`.
/// Each variant selects the corresponding [`BtDevType`] when creating
/// the virtual controller backing the PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialType {
    /// Dual-mode Bluetooth BR/EDR + LE controller.
    BrEdrLe,
    /// Classic Bluetooth BR/EDR-only controller.
    BrEdr,
    /// Bluetooth Low Energy only controller.
    Le,
    /// AMP (Alternate MAC/PHY) controller.
    Amp,
}

impl From<SerialType> for BtDevType {
    fn from(st: SerialType) -> Self {
        match st {
            SerialType::BrEdrLe => BtDevType::BrEdrLe,
            SerialType::BrEdr => BtDevType::BrEdr,
            SerialType::Le => BtDevType::Le,
            SerialType::Amp => BtDevType::Amp,
        }
    }
}

// ---------------------------------------------------------------------------
// SerialError — error type for serial PTY operations
// ---------------------------------------------------------------------------

/// Errors originating from serial PTY operations.
#[derive(Debug, Error)]
pub enum SerialError {
    /// PTY system call failure (posix_openpt / grantpt / unlockpt / ptsname_r).
    #[error("PTY operation failed: {0}")]
    Pty(#[from] nix::Error),

    /// I/O error during fd cloning or AsyncFd registration.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Virtual controller creation failed.
    #[error("BtDev creation failed: {0}")]
    BtDev(#[from] BtDevError),
}

// ---------------------------------------------------------------------------
// Serial — the public entry-point
// ---------------------------------------------------------------------------

/// PTY-backed H:4 transport for HCI emulation.
///
/// Opens a pseudo-terminal, prints the slave path for external tools
/// (e.g. `hciattach`), and forwards HCI command packets between the PTY
/// and a [`BtDev`] virtual controller.  On slave-side hangup the PTY is
/// transparently re-created (reconnect-on-hangup), matching the
/// behaviour of the C `emulator/serial.c`.
///
/// # Lifecycle
///
/// ```text
/// Serial::open(serial_type)
///   └── create_pty_resources()
///   └── tokio::spawn(serial_reconnect_loop)
///
/// Serial::close()  (or Drop)
///   └── JoinHandle::abort()
/// ```
pub struct Serial {
    /// Controller type used for BtDev creation on (re-)connect.
    _serial_type: SerialType,
    /// Fixed emulator ID (0x42, matching C `emulator/serial.c` line 221).
    _id: u16,
    /// Handle to the background read/reconnect task.
    join_handle: Option<JoinHandle<()>>,
}

impl Serial {
    /// Fixed emulator ID matching C code (`emulator/serial.c` line 221).
    const DEFAULT_ID: u16 = 0x42;

    /// Open a serial PTY emulator of the given controller type.
    ///
    /// Creates a pseudo-terminal, prints the slave path to stdout,
    /// initialises a [`BtDev`] virtual controller, and spawns a
    /// background task that reads H:4 command packets from the PTY and
    /// delivers them to the controller.  If the slave side hangs up, a
    /// new PTY is transparently created (reconnect-on-hangup).
    ///
    /// Returns an error if the initial PTY creation or `BtDev` setup
    /// fails.  Must be called within a tokio runtime context.
    pub fn open(serial_type: SerialType) -> Result<Self, SerialError> {
        let id = Self::DEFAULT_ID;

        // Validate that PTY creation works synchronously before spawning
        // the background task (matches C `serial_open` which returns NULL
        // on initial `open_pty` failure).
        let (async_fd, btdev, write_fd_anchor, path) = create_pty_resources(serial_type, id)?;
        println!("Pseudo terminal at {path}");

        // Spawn the read-loop with automatic reconnect-on-hangup.
        let handle =
            spawn(serial_reconnect_loop(async_fd, btdev, write_fd_anchor, serial_type, id));

        Ok(Self { _serial_type: serial_type, _id: id, join_handle: Some(handle) })
    }

    /// Close the serial PTY emulator.
    ///
    /// Aborts the background read task, which causes all owned resources
    /// (PTY file descriptor, [`BtDev`], write-fd `Arc`) to be dropped.
    pub fn close(&mut self) {
        if let Some(handle) = self.join_handle.take() {
            handle.abort();
        }
    }
}

impl Drop for Serial {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// PTY resource creation
// ---------------------------------------------------------------------------

/// Bundle of resources produced by [`create_pty_resources`].
///
/// Returned as a tuple to avoid an extra struct:
/// `(AsyncFd<PtyMaster>, BtDev, Arc<OwnedFd>, slave_path)`.
///
/// * `AsyncFd<PtyMaster>` — the master PTY wrapped for async reads.
/// * `BtDev` — the virtual controller, with its send handler already
///   wired to write back into the master PTY via `writev`.
/// * `Arc<OwnedFd>` — the duplicated master fd kept alive so the send
///   handler closure's captured `Arc` clone remains valid.
/// * `String` — slave PTY path (e.g. `/dev/pts/5`).
type PtyResources = (AsyncFd<PtyMaster>, BtDev, Arc<OwnedFd>, String);

/// Create a new PTY with a `BtDev` and `AsyncFd` ready for the read loop.
///
/// The returned `Arc<OwnedFd>` (write-fd anchor) **must** be kept alive
/// for as long as the `BtDev` is in use — its clone is captured inside
/// the send-handler closure.
fn create_pty_resources(serial_type: SerialType, id: u16) -> Result<PtyResources, SerialError> {
    // Open master PTY.  O_NONBLOCK is required for tokio `AsyncFd`
    // compatibility (the C code uses a blocking fd with epoll, but
    // tokio's reactor requires non-blocking descriptors).
    let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_NONBLOCK)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let path = ptsname_r(&master)?;

    // Create a virtual controller with the appropriate type.
    let dev_type = BtDevType::from(serial_type);
    let mut btdev = BtDev::new(dev_type, id)?;

    // Safely duplicate the master fd for the write handler.
    // `BorrowedFd::try_clone_to_owned` calls `fcntl(F_DUPFD_CLOEXEC)`
    // internally — zero `unsafe` needed.
    let write_fd = Arc::new(master.as_fd().try_clone_to_owned()?);
    let write_fd_for_handler = Arc::clone(&write_fd);

    // Set the BtDev send handler: scatter-gather write via `writev`.
    // Matches `serial_write_callback` (emulator/serial.c lines 64-73).
    // Errors are silently ignored, matching the C code:
    //   `if (written < 0) return;`
    btdev.set_send_handler(Some(Box::new(move |iov: &[IoSlice<'_>]| {
        let _ = writev(write_fd_for_handler.as_fd(), iov);
    })));

    // Wrap the master PTY in `AsyncFd` for the async read loop.
    let async_fd = AsyncFd::new(master)?;

    Ok((async_fd, btdev, write_fd, path))
}

// ---------------------------------------------------------------------------
// Reconnect loop
// ---------------------------------------------------------------------------

/// Background task: drives the read loop and handles reconnect-on-hangup.
///
/// When the slave side disconnects (HUP / EOF), the current PTY, BtDev
/// and write-fd are dropped and a fresh set is created, matching the C
/// reconnection logic in `serial_read_callback` (lines 83-86).
async fn serial_reconnect_loop(
    mut async_fd: AsyncFd<PtyMaster>,
    mut btdev: BtDev,
    mut write_fd_anchor: Arc<OwnedFd>,
    serial_type: SerialType,
    id: u16,
) {
    loop {
        let should_reconnect = serial_read_loop(&async_fd, &mut btdev).await;

        if !should_reconnect {
            break;
        }

        // Create a fresh PTY (old resources are dropped on reassignment
        // in the correct order: BtDev first, then AsyncFd, then the
        // write-fd anchor).
        match create_pty_resources(serial_type, id) {
            Ok((new_fd, new_btdev, new_write_fd, path)) => {
                btdev = new_btdev;
                async_fd = new_fd;
                write_fd_anchor = new_write_fd;
                println!("Pseudo terminal at {path}");
            }
            Err(e) => {
                eprintln!("serial PTY reconnect error: {e}");
                break;
            }
        }
    }

    // Ensure resources are dropped in the right order even on normal exit.
    drop(btdev);
    drop(async_fd);
    drop(write_fd_anchor);
}

// ---------------------------------------------------------------------------
// H:4 reassembly
// ---------------------------------------------------------------------------

/// Result of feeding a single byte to the [`H4Reassembler`].
enum FeedResult {
    /// Byte consumed; more data needed.
    Continue,
    /// A complete H:4 packet is ready for delivery to `BtDev`.
    Complete(Vec<u8>),
    /// Unknown packet type encountered — discard the rest of the read
    /// buffer (matching C `printf("packet error\n"); return true;`).
    PacketError,
}

/// H:4 packet reassembly state machine.
///
/// Supports **only** `HCI_COMMAND_PKT` (0x01) packets, matching the C
/// implementation (serial.c lines 104-123).  Unknown packet types
/// produce a "packet error" message and cause the remainder of the
/// current read buffer to be discarded.
///
/// The reassembly proceeds in two stages:
///
/// 1. **Header stage** (`header_parsed == false`): accumulate the
///    type byte (1) plus the 3-byte `hci_command_hdr` (total 4 bytes).
///    Once complete, extract `plen` and compute the final packet length.
///
/// 2. **Payload stage** (`header_parsed == true`): accumulate the
///    remaining `plen` payload bytes.  Once complete, the full packet
///    (type + header + payload) is returned.
struct H4Reassembler {
    /// Accumulated packet data (`None` = idle / waiting for type byte).
    data: Option<Vec<u8>>,
    /// Total number of bytes expected for the current packet.
    expect: usize,
    /// Whether the HCI command header has already been fully parsed.
    header_parsed: bool,
}

impl H4Reassembler {
    /// Create a new reassembler in the idle state.
    fn new() -> Self {
        Self { data: None, expect: 0, header_parsed: false }
    }

    /// Reset the reassembler to the idle state after a complete packet
    /// or on error.
    fn reset(&mut self) {
        self.data = None;
        self.expect = 0;
        self.header_parsed = false;
    }

    /// Feed one byte into the reassembler.
    ///
    /// * [`FeedResult::Complete`] — full H:4 packet ready for
    ///   `btdev.receive_h4()`.
    /// * [`FeedResult::Continue`] — more bytes needed.
    /// * [`FeedResult::PacketError`] — unknown packet type; caller
    ///   should discard the rest of the current read buffer.
    fn feed_byte(&mut self, byte: u8) -> FeedResult {
        if self.data.is_none() {
            // Waiting for the H:4 packet type byte.
            if byte == HCI_COMMAND_PKT {
                // HCI Command: type(1) + hci_command_hdr(3) = 4 bytes min.
                let initial_expect = 1 + HCI_COMMAND_HDR_SIZE;
                self.data = Some(Vec::with_capacity(initial_expect));
                self.expect = initial_expect;
                self.header_parsed = false;
            } else {
                // Unknown packet type — matches C behaviour:
                //   printf("packet error\n"); return true;
                println!("packet error");
                return FeedResult::PacketError;
            }
        }

        // Accumulate the byte.
        let data = self.data.as_mut().expect("data initialised above or in a prior call");
        data.push(byte);

        // Still waiting for more bytes?
        if data.len() < self.expect {
            return FeedResult::Continue;
        }

        if !self.header_parsed {
            // We have accumulated: type(1) + opcode(2) + plen(1) = 4 bytes.
            // Extract plen to compute the full packet length.
            //
            //   hci_command_hdr layout (3 bytes, packed):
            //     offset 0: opcode   (u16, 2 bytes)
            //     offset 2: plen     (u8,  1 byte)
            //
            // In the reassembly buffer:
            //   data[0] = H:4 type byte
            //   data[1] = opcode low byte
            //   data[2] = opcode high byte
            //   data[3] = plen
            let plen = data[3];
            self.expect = 1 + HCI_COMMAND_HDR_SIZE + plen as usize;
            self.header_parsed = true;

            // If there are still payload bytes outstanding, keep going.
            if data.len() < self.expect {
                return FeedResult::Continue;
            }
            // plen == 0 → packet is already complete; fall through.
        }

        // Full packet assembled — extract and reset.
        let complete = self.data.take().expect("data was Some");
        self.reset();
        FeedResult::Complete(complete)
    }
}

// ---------------------------------------------------------------------------
// Async read loop
// ---------------------------------------------------------------------------

/// Async read loop: reads from the PTY via `AsyncFd`, reassembles H:4
/// packets, and delivers complete packets to the `BtDev`.
///
/// Returns `true` if the slave side hung up (caller should reconnect)
/// or `false` on a fatal read error (caller should stop).
async fn serial_read_loop(async_fd: &AsyncFd<PtyMaster>, btdev: &mut BtDev) -> bool {
    let mut reassembler = H4Reassembler::new();
    let mut buf = [0u8; 4096];

    loop {
        // Wait for the PTY to become readable.
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => return false,
        };

        // Attempt a non-blocking read within the readiness guard.
        match guard.try_io(|inner| {
            match read(inner.as_raw_fd(), &mut buf) {
                Ok(0) => {
                    // EOF / HUP — signal reconnect.
                    Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "PTY hangup"))
                }
                Ok(n) => Ok(n),
                Err(Errno::EAGAIN) => {
                    // Not actually ready — let tokio re-arm.
                    // Note: EWOULDBLOCK == EAGAIN on Linux.
                    Err(std::io::ErrorKind::WouldBlock.into())
                }
                Err(Errno::EINTR) => {
                    // Interrupted by signal — treat as would-block to
                    // retry after the next readiness notification.
                    Err(std::io::ErrorKind::WouldBlock.into())
                }
                Err(e) => Err(std::io::Error::from(e)),
            }
        }) {
            Ok(Ok(n)) => {
                // Process received bytes through the H:4 reassembler.
                for &byte in &buf[..n] {
                    match reassembler.feed_byte(byte) {
                        FeedResult::Continue => {}
                        FeedResult::Complete(packet) => {
                            btdev.receive_h4(&packet);
                        }
                        FeedResult::PacketError => {
                            // Discard the remaining bytes in this read
                            // buffer (matching C: `return true;` from
                            // the callback keeps the fd registered but
                            // discards the current buffer).
                            break;
                        }
                    }
                }
            }
            Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                // HUP — request reconnect.
                return true;
            }
            Ok(Err(_)) => {
                // Fatal read error — stop.
                return false;
            }
            Err(_would_block) => {
                // Spurious readiness or EINTR — loop and re-poll.
                continue;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_type_conversion_br_edr_le() {
        assert_eq!(BtDevType::from(SerialType::BrEdrLe), BtDevType::BrEdrLe);
    }

    #[test]
    fn serial_type_conversion_br_edr() {
        assert_eq!(BtDevType::from(SerialType::BrEdr), BtDevType::BrEdr);
    }

    #[test]
    fn serial_type_conversion_le() {
        assert_eq!(BtDevType::from(SerialType::Le), BtDevType::Le);
    }

    #[test]
    fn serial_type_conversion_amp() {
        assert_eq!(BtDevType::from(SerialType::Amp), BtDevType::Amp);
    }

    #[test]
    fn reassembler_starts_idle() {
        let r = H4Reassembler::new();
        assert!(r.data.is_none());
        assert_eq!(r.expect, 0);
        assert!(!r.header_parsed);
    }

    #[test]
    fn reassembler_rejects_unknown_type() {
        let mut r = H4Reassembler::new();
        // Type 0xFF is not HCI_COMMAND_PKT (0x01).
        assert!(matches!(r.feed_byte(0xFF), FeedResult::PacketError));
        // State should remain idle.
        assert!(r.data.is_none());
    }

    #[test]
    fn reassembler_complete_command_no_payload() {
        let mut r = H4Reassembler::new();
        // H:4 type byte (0x01 = HCI Command)
        assert!(matches!(r.feed_byte(0x01), FeedResult::Continue));
        // opcode low byte
        assert!(matches!(r.feed_byte(0x03), FeedResult::Continue));
        // opcode high byte
        assert!(matches!(r.feed_byte(0x0C), FeedResult::Continue));
        // plen = 0 → no payload → packet complete immediately
        match r.feed_byte(0x00) {
            FeedResult::Complete(pkt) => {
                assert_eq!(pkt, vec![0x01, 0x03, 0x0C, 0x00]);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        // Reassembler back to idle.
        assert!(r.data.is_none());
    }

    #[test]
    fn reassembler_complete_command_with_payload() {
        let mut r = H4Reassembler::new();
        // Type
        assert!(matches!(r.feed_byte(0x01), FeedResult::Continue));
        // opcode = 0x0C03 (Reset)
        assert!(matches!(r.feed_byte(0x03), FeedResult::Continue));
        assert!(matches!(r.feed_byte(0x0C), FeedResult::Continue));
        // plen = 2
        assert!(matches!(r.feed_byte(0x02), FeedResult::Continue));
        // payload byte 1
        assert!(matches!(r.feed_byte(0xAA), FeedResult::Continue));
        // payload byte 2 → complete
        match r.feed_byte(0xBB) {
            FeedResult::Complete(pkt) => {
                assert_eq!(pkt, vec![0x01, 0x03, 0x0C, 0x02, 0xAA, 0xBB]);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn reassembler_multiple_packets_in_sequence() {
        let mut r = H4Reassembler::new();

        // Packet 1: type=0x01, opcode=0x0001, plen=0 → complete at 4th byte.
        let pkt1 = [0x01u8, 0x01, 0x00, 0x00];
        for (i, &b) in pkt1.iter().enumerate() {
            let result = r.feed_byte(b);
            if i == pkt1.len() - 1 {
                assert!(
                    matches!(result, FeedResult::Complete(_)),
                    "pkt1 byte {i}: expected Complete"
                );
            } else {
                assert!(matches!(result, FeedResult::Continue), "pkt1 byte {i}: expected Continue");
            }
        }

        // Packet 2: type=0x01, opcode=0x0002, plen=1, payload=0xFF
        // → complete at 5th byte.
        let pkt2 = [0x01u8, 0x02, 0x00, 0x01, 0xFF];
        for (i, &b) in pkt2.iter().enumerate() {
            let result = r.feed_byte(b);
            if i == pkt2.len() - 1 {
                assert!(
                    matches!(result, FeedResult::Complete(_)),
                    "pkt2 byte {i}: expected Complete"
                );
            } else {
                assert!(matches!(result, FeedResult::Continue), "pkt2 byte {i}: expected Continue");
            }
        }
    }

    /// Verify the debug representation doesn't panic.
    #[test]
    fn serial_type_debug() {
        let variants = [SerialType::BrEdrLe, SerialType::BrEdr, SerialType::Le, SerialType::Amp];
        for v in &variants {
            let _ = format!("{v:?}");
        }
    }

    /// Verify SerialType equality/inequality.
    #[test]
    fn serial_type_eq() {
        assert_eq!(SerialType::BrEdrLe, SerialType::BrEdrLe);
        assert_ne!(SerialType::BrEdrLe, SerialType::Le);
    }

    /// Verify SerialType is Copy.
    #[test]
    fn serial_type_is_copy() {
        let a = SerialType::Le;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    /// Verify SerialError variants format correctly.
    #[test]
    fn serial_error_display() {
        let err = SerialError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        let msg = format!("{err}");
        assert!(msg.contains("I/O error"));

        let err2 = SerialError::Pty(nix::Error::EACCES);
        let msg2 = format!("{err2}");
        assert!(msg2.contains("PTY operation failed"));
    }

    impl std::fmt::Debug for FeedResult {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Continue => write!(f, "Continue"),
                Self::Complete(v) => write!(f, "Complete({v:?})"),
                Self::PacketError => write!(f, "PacketError"),
            }
        }
    }
}
