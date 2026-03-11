// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluez-emulator/src/phy.rs — Simulated PHY layer for BlueZ HCI emulator
//
// Complete Rust rewrite of emulator/phy.c (297 lines) and emulator/phy.h (59 lines).
// Implements a UDP broadcast "PHY bus" on port 45023 with header framing,
// self-echo suppression via random 64-bit instance IDs, and callback
// registration for received packets.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, SockaddrIn, bind, setsockopt, socket, sockopt,
};
use tokio::net::UdpSocket;
use tokio::task::{self, JoinHandle};

// ── Constants ───────────────────────────────────────────────────────────────

/// PHY bus UDP port matching `BT_PHY_PORT` in the C source (phy.c line 31).
const BT_PHY_PORT: u16 = 45023;

/// Null/announcement packet type. Sent on PHY construction to announce
/// the new instance to other participants on the PHY bus.
pub const BT_PHY_PKT_NULL: u16 = 0x0000;

/// Advertising packet type, carrying `BtPhyPktAdv` metadata followed by
/// advertising data and scan response data.
pub const BT_PHY_PKT_ADV: u16 = 0x0001;

/// Connection request packet type, carrying `BtPhyPktConn` metadata
/// with link parameters for establishing a simulated connection.
pub const BT_PHY_PKT_CONN: u16 = 0x0002;

/// Size of the PHY wire-format header in bytes.
const BT_PHY_HDR_SIZE: usize = 16;

/// Maximum payload size for received packets, matching the C buffer
/// (phy.c line 74: `unsigned char buf[4096]`).
const MAX_PAYLOAD_SIZE: usize = 4096;

// ── PHY Header ──────────────────────────────────────────────────────────────

/// PHY protocol header (16 bytes on the wire).
///
/// Replaces `struct bt_phy_hdr` from phy.c lines 42-47. Fields are stored
/// in host byte order within this struct; conversion to/from the
/// little-endian wire format is performed by the internal serialization
/// helpers used in send and receive paths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BtPhyHdr {
    /// PHY instance ID used for self-echo suppression. Each `BtPhy`
    /// instance generates a unique random ID at construction time;
    /// received packets whose header ID matches the local ID are
    /// silently discarded.
    pub id: u64,
    /// Header flags (currently reserved — always zero).
    pub flags: u32,
    /// Packet type discriminator (`BT_PHY_PKT_NULL`, `BT_PHY_PKT_ADV`,
    /// or `BT_PHY_PKT_CONN`).
    pub type_: u16,
    /// Payload length in bytes (not including this header).
    pub len: u16,
}

impl BtPhyHdr {
    /// Serialize this header to a 16-byte little-endian wire
    /// representation matching the C `struct bt_phy_hdr` layout.
    fn to_bytes(self) -> [u8; BT_PHY_HDR_SIZE] {
        let mut buf = [0u8; BT_PHY_HDR_SIZE];
        buf[0..8].copy_from_slice(&self.id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.flags.to_le_bytes());
        buf[12..14].copy_from_slice(&self.type_.to_le_bytes());
        buf[14..16].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    /// Deserialize a header from at least 16 bytes of little-endian wire
    /// data. Returns `None` if the slice is shorter than 16 bytes.
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < BT_PHY_HDR_SIZE {
            return None;
        }
        Some(Self {
            id: u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            flags: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            type_: u16::from_le_bytes([data[12], data[13]]),
            len: u16::from_le_bytes([data[14], data[15]]),
        })
    }
}

// ── Advertising Packet Metadata ─────────────────────────────────────────────

/// Advertising packet metadata sent as the payload of a
/// `BT_PHY_PKT_ADV` datagram.
///
/// Replaces `struct bt_phy_pkt_adv` from phy.h lines 38-47.
/// All fields are single bytes or byte arrays, so no endianness
/// conversion is required.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BtPhyPktAdv {
    /// Advertising channel index (37, 38, or 39).
    pub chan_idx: u8,
    /// PDU type (e.g. `ADV_IND`, `ADV_DIRECT_IND`).
    pub pdu_type: u8,
    /// Transmitter address type (public or random).
    pub tx_addr_type: u8,
    /// 6-byte transmitter Bluetooth address.
    pub tx_addr: [u8; 6],
    /// Receiver address type (public or random).
    pub rx_addr_type: u8,
    /// 6-byte receiver Bluetooth address.
    pub rx_addr: [u8; 6],
    /// Length of the advertising data following this struct.
    pub adv_data_len: u8,
    /// Length of the scan response data following the advertising data.
    pub scan_rsp_len: u8,
}

// ── Connection Packet Metadata ──────────────────────────────────────────────

/// Connection request packet metadata sent as the payload of a
/// `BT_PHY_PKT_CONN` datagram.
///
/// Replaces `struct bt_phy_pkt_conn` from phy.h lines 49-59.
/// All fields are single bytes or byte arrays, so no endianness
/// conversion is required.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BtPhyPktConn {
    /// Channel index for the connection.
    pub chan_idx: u8,
    /// Link type (ACL, SCO, LE, etc.).
    pub link_type: u8,
    /// Transmitter address type (public or random).
    pub tx_addr_type: u8,
    /// 6-byte transmitter Bluetooth address.
    pub tx_addr: [u8; 6],
    /// Receiver address type (public or random).
    pub rx_addr_type: u8,
    /// 6-byte receiver Bluetooth address.
    pub rx_addr: [u8; 6],
    /// 8-byte LMP/LE feature mask.
    pub features: [u8; 8],
    /// Connection identifier.
    pub id: u8,
}

// ── Callback Type ───────────────────────────────────────────────────────────

/// Thread-safe PHY packet callback, replacing `bt_phy_callback_func_t`.
///
/// Wrapped in `Arc` so the receive task can clone it cheaply and release
/// the mutex before invocation, preventing deadlocks.
///
/// Parameters: `(packet_type, payload_data)`.
type PhyCallback = Arc<dyn Fn(u16, &[u8]) + Send + Sync>;

// ── BtPhy ───────────────────────────────────────────────────────────────────

/// Simulated Bluetooth PHY layer using UDP broadcast on port 45023.
///
/// Replaces `struct bt_phy` from phy.c lines 33-40. Callers obtain an
/// `Arc<BtPhy>` from [`BtPhy::new`], which replaces the C manual
/// reference counting (`bt_phy_ref`/`bt_phy_unref`) with Rust's
/// `Arc`-based automatic reference counting.
///
/// # Lifecycle
///
/// 1. [`BtPhy::new`] creates RX and TX sockets, generates a random
///    instance ID, spawns an async receive task, and sends a
///    `BT_PHY_PKT_NULL` announcement.
/// 2. [`BtPhy::register`] sets the callback for incoming packets.
/// 3. [`BtPhy::send`] and [`BtPhy::send_vector`] emit packets to
///    all participants on the PHY bus via UDP broadcast.
/// 4. Dropping the last `Arc<BtPhy>` aborts the receive task and
///    closes both sockets.
pub struct BtPhy {
    /// Transmit UDP socket with `SO_BROADCAST` enabled.
    tx_socket: UdpSocket,
    /// Random 64-bit instance ID for self-echo suppression.
    id: u64,
    /// Registered callback invoked for every received non-self packet.
    /// Protected by a `Mutex` so it can be set via `register()` (which
    /// takes `&self`) while the receive task reads it concurrently.
    callback: Arc<Mutex<Option<PhyCallback>>>,
    /// Handle for the spawned async RX read-loop task.
    read_task: Option<JoinHandle<()>>,
}

impl BtPhy {
    /// Create a new PHY instance, start receiving packets, and send
    /// an initial null announcement.
    ///
    /// Replaces `bt_phy_new()` (phy.c lines 152-188).
    ///
    /// Must be called from within a Tokio runtime context (the async
    /// receive task is spawned via `tokio::task::spawn`).
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if socket creation, option setting, binding,
    /// or random ID generation fails.
    pub fn new() -> Result<Arc<Self>, io::Error> {
        let rx_socket = create_rx_socket()?;
        let tx_socket = create_tx_socket()?;
        let id = generate_random_id()?;

        let callback: Arc<Mutex<Option<PhyCallback>>> = Arc::new(Mutex::new(None));

        // Spawn the async RX loop with cloned references.
        let cb_clone = Arc::clone(&callback);
        let read_task = task::spawn(phy_rx_loop(rx_socket, id, cb_clone));

        let phy = Arc::new(Self { tx_socket, id, callback, read_task: Some(read_task) });

        // Announce our presence on the PHY bus (matching phy.c line 185).
        phy.send(BT_PHY_PKT_NULL, &[]);

        Ok(phy)
    }

    /// Send a single-buffer packet on the PHY bus.
    ///
    /// Replaces `bt_phy_send` (phy.c lines 216-220). Convenience
    /// wrapper around [`send_vector`](BtPhy::send_vector) with a
    /// single data segment.
    pub fn send(&self, pkt_type: u16, data: &[u8]) -> bool {
        self.send_vector(pkt_type, data, &[], &[])
    }

    /// Send a scatter-gather packet with up to three data segments.
    ///
    /// Replaces `bt_phy_send_vector` (phy.c lines 222-285). Builds a
    /// `BtPhyHdr` (with the local instance ID, zero flags, the given
    /// packet type, and the combined payload length) followed by the
    /// concatenation of `data1`, `data2`, and `data3`. The complete
    /// datagram is sent via non-blocking `try_send_to` to the UDP
    /// broadcast address `255.255.255.255:45023`, mirroring the C
    /// `sendmsg` with `MSG_DONTWAIT`.
    ///
    /// Returns `true` on success, `false` on any send error (matching
    /// the C return convention at phy.c lines 280-284).
    pub fn send_vector(&self, pkt_type: u16, data1: &[u8], data2: &[u8], data3: &[u8]) -> bool {
        let payload_len = data1.len() + data2.len() + data3.len();

        // Payload length must fit in the 16-bit header field.
        let Ok(payload_len_u16) = u16::try_from(payload_len) else {
            return false;
        };

        // Build the PHY header in little-endian wire format.
        let hdr = BtPhyHdr { id: self.id, flags: 0, type_: pkt_type, len: payload_len_u16 };
        let hdr_bytes = hdr.to_bytes();

        // Assemble the complete datagram: [header | data1 | data2 | data3].
        let total_len = BT_PHY_HDR_SIZE + payload_len;
        let mut buf = vec![0u8; total_len];
        buf[..BT_PHY_HDR_SIZE].copy_from_slice(&hdr_bytes);

        let mut offset = BT_PHY_HDR_SIZE;
        for segment in [data1, data2, data3] {
            if !segment.is_empty() {
                buf[offset..offset + segment.len()].copy_from_slice(segment);
                offset += segment.len();
            }
        }

        // Broadcast destination matching the C code:
        //   addr.sin_addr.s_addr = INADDR_BROADCAST
        //   addr.sin_port = htons(BT_PHY_PORT)
        let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, BT_PHY_PORT));

        // Non-blocking send (MSG_DONTWAIT equivalent).
        self.tx_socket.try_send_to(&buf, dest).is_ok()
    }

    /// Register a callback for received packets.
    ///
    /// Replaces `bt_phy_register` (phy.c lines 287-297). The callback
    /// receives `(packet_type, payload)` for every non-self packet
    /// arriving on the PHY bus. Only one callback may be registered
    /// at a time; subsequent calls replace the previous callback.
    ///
    /// Returns `true` on success, `false` if the internal mutex is
    /// poisoned (which should never happen under normal operation).
    pub fn register(&self, callback: impl Fn(u16, &[u8]) + Send + Sync + 'static) -> bool {
        match self.callback.lock() {
            Ok(mut guard) => {
                *guard = Some(Arc::new(callback));
                true
            }
            Err(_) => false,
        }
    }
}

impl Drop for BtPhy {
    /// Clean up the PHY instance on drop.
    ///
    /// Replaces the teardown logic in `bt_phy_unref` (phy.c lines
    /// 200-214). Aborts the RX read-loop task (equivalent to
    /// `mainloop_remove_fd`); both UDP sockets are closed
    /// automatically when the `UdpSocket` values are dropped.
    fn drop(&mut self) {
        if let Some(handle) = self.read_task.take() {
            handle.abort();
        }
    }
}

// ── Socket Creation Helpers ─────────────────────────────────────────────────

/// Create the RX UDP socket bound to `INADDR_BROADCAST:45023` with
/// `SO_REUSEADDR`, matching `create_rx_socket` (phy.c lines 109-134).
///
/// The socket is created via `nix` POSIX APIs to set `SO_REUSEADDR`
/// before the `bind` call (which the standard library API does not
/// expose), then converted to a non-blocking `tokio::net::UdpSocket`.
fn create_rx_socket() -> Result<UdpSocket, io::Error> {
    // PF_INET + SOCK_DGRAM + SOCK_CLOEXEC, no explicit protocol.
    let fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)
        .map_err(nix_to_io)?;

    // SO_REUSEADDR allows multiple emulator instances to coexist.
    setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(nix_to_io)?;

    // Bind to 255.255.255.255:45023 to receive broadcast datagrams.
    let addr = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::BROADCAST, BT_PHY_PORT));
    bind(fd.as_raw_fd(), &addr).map_err(nix_to_io)?;

    // Convert OwnedFd → std::net::UdpSocket → tokio::net::UdpSocket.
    let std_socket: std::net::UdpSocket = std::net::UdpSocket::from(fd);
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
}

/// Create the TX UDP socket with `SO_BROADCAST` enabled, matching
/// `create_tx_socket` (phy.c lines 136-150).
///
/// No bind is performed — the destination address is specified per
/// datagram in [`BtPhy::send_vector`].
fn create_tx_socket() -> Result<UdpSocket, io::Error> {
    let fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)
        .map_err(nix_to_io)?;

    // SO_BROADCAST enables sending to the broadcast address.
    setsockopt(&fd, sockopt::Broadcast, &true).map_err(nix_to_io)?;

    let std_socket: std::net::UdpSocket = std::net::UdpSocket::from(fd);
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
}

// ── Random ID Generator ─────────────────────────────────────────────────────

/// Generate a cryptographically random 64-bit instance ID by reading
/// from `/dev/urandom`.
///
/// Mirrors the C `get_random_bytes` function (phy.c lines 49-66) with
/// the `util_getrandom` fallback. On modern Linux, `/dev/urandom` is
/// always available and non-blocking, so a fallback path is unnecessary.
fn generate_random_id() -> Result<u64, io::Error> {
    use std::io::Read;
    let mut buf = [0u8; 8];
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(&mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

// ── Async RX Read Loop ─────────────────────────────────────────────────────

/// Async receive loop that reads packets from the PHY bus RX socket.
///
/// Replaces `phy_rx_callback` (phy.c lines 68-107). Runs as a
/// `tokio::task::spawn`-ed task. For each received datagram:
///
/// 1. Validates that the datagram is at least 16 bytes (header size).
/// 2. Parses the little-endian `BtPhyHdr`.
/// 3. **Self-echo suppression:** discards packets whose header `id`
///    matches the local `self_id` (phy.c lines 98-99).
/// 4. Validates that `(datagram_len - header_size) == hdr.len`
///    (phy.c lines 101-102).
/// 5. Invokes the registered callback with `(pkt_type, payload)`
///    (phy.c lines 104-106).
///
/// The loop breaks on any receive error (equivalent to the
/// `EPOLLERR | EPOLLHUP` check at phy.c line 77).
async fn phy_rx_loop(
    rx_socket: UdpSocket,
    self_id: u64,
    callback: Arc<Mutex<Option<PhyCallback>>>,
) {
    let mut buf = [0u8; BT_PHY_HDR_SIZE + MAX_PAYLOAD_SIZE];

    loop {
        // Await the next datagram (replaces recvmsg with MSG_DONTWAIT
        // inside the mainloop EPOLLIN callback).
        let len = match rx_socket.recv_from(&mut buf).await {
            Ok((len, _addr)) => len,
            // Any receive error terminates the loop, matching the
            // EPOLLERR/EPOLLHUP handling at phy.c lines 77-80.
            Err(_) => break,
        };

        // Need at least a full header (phy.c line 95-96).
        if len < BT_PHY_HDR_SIZE {
            continue;
        }

        // Parse the little-endian wire header.
        let Some(hdr) = BtPhyHdr::from_bytes(&buf[..BT_PHY_HDR_SIZE]) else {
            continue;
        };

        // Self-echo suppression: skip our own packets (phy.c lines 98-99).
        if hdr.id == self_id {
            continue;
        }

        // Validate that the declared payload length matches the actual
        // received data minus the header (phy.c lines 101-102).
        let payload_len = hdr.len as usize;
        if len - BT_PHY_HDR_SIZE != payload_len {
            continue;
        }

        // Clone the callback Arc out of the mutex so we release the
        // lock before invoking the callback, preventing potential
        // deadlocks if the callback re-enters BtPhy methods.
        let cb_opt: Option<PhyCallback> = callback.lock().ok().and_then(|guard| guard.clone());

        if let Some(cb) = cb_opt {
            cb(hdr.type_, &buf[BT_PHY_HDR_SIZE..BT_PHY_HDR_SIZE + payload_len]);
        }
    }
}

// ── Utility ─────────────────────────────────────────────────────────────────

/// Convert a `nix::errno::Errno` to a standard `io::Error`, preserving
/// the original OS error number for diagnostic purposes.
fn nix_to_io(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bt_phy_hdr_size() {
        // Verify the header serializes to exactly 16 bytes.
        let hdr = BtPhyHdr::default();
        assert_eq!(hdr.to_bytes().len(), 16);
    }

    #[test]
    fn test_bt_phy_hdr_round_trip() {
        let original = BtPhyHdr {
            id: 0xDEAD_BEEF_CAFE_BABE,
            flags: 0x1234_5678,
            type_: BT_PHY_PKT_ADV,
            len: 42,
        };
        let bytes = original.to_bytes();
        let restored = BtPhyHdr::from_bytes(&bytes).expect("round-trip parse failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn test_bt_phy_hdr_from_short_slice() {
        // Slices shorter than 16 bytes must return None.
        assert!(BtPhyHdr::from_bytes(&[0u8; 15]).is_none());
        assert!(BtPhyHdr::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_bt_phy_hdr_little_endian_wire_format() {
        let hdr =
            BtPhyHdr { id: 0x0102_0304_0506_0708, flags: 0x090A_0B0C, type_: 0x0D0E, len: 0x0F10 };
        let bytes = hdr.to_bytes();
        // id: LE bytes  0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[7], 0x01);
        // flags: LE bytes 0x0C, 0x0B, 0x0A, 0x09
        assert_eq!(bytes[8], 0x0C);
        assert_eq!(bytes[11], 0x09);
        // type: LE bytes 0x0E, 0x0D
        assert_eq!(bytes[12], 0x0E);
        assert_eq!(bytes[13], 0x0D);
        // len: LE bytes 0x10, 0x0F
        assert_eq!(bytes[14], 0x10);
        assert_eq!(bytes[15], 0x0F);
    }

    #[test]
    fn test_constants() {
        assert_eq!(BT_PHY_PKT_NULL, 0x0000);
        assert_eq!(BT_PHY_PKT_ADV, 0x0001);
        assert_eq!(BT_PHY_PKT_CONN, 0x0002);
    }

    #[test]
    fn test_bt_phy_pkt_adv_default() {
        let pkt = BtPhyPktAdv::default();
        assert_eq!(pkt.chan_idx, 0);
        assert_eq!(pkt.pdu_type, 0);
        assert_eq!(pkt.tx_addr, [0u8; 6]);
        assert_eq!(pkt.rx_addr, [0u8; 6]);
        assert_eq!(pkt.adv_data_len, 0);
        assert_eq!(pkt.scan_rsp_len, 0);
    }

    #[test]
    fn test_bt_phy_pkt_conn_default() {
        let pkt = BtPhyPktConn::default();
        assert_eq!(pkt.chan_idx, 0);
        assert_eq!(pkt.link_type, 0);
        assert_eq!(pkt.tx_addr, [0u8; 6]);
        assert_eq!(pkt.rx_addr, [0u8; 6]);
        assert_eq!(pkt.features, [0u8; 8]);
        assert_eq!(pkt.id, 0);
    }

    #[test]
    fn test_generate_random_id_is_nonzero_with_high_probability() {
        // Generating two IDs should almost certainly give different values.
        let id1 = generate_random_id().expect("random id gen failed");
        let id2 = generate_random_id().expect("random id gen failed");
        // Both zero is astronomically unlikely (probability 2^-128).
        assert!(id1 != 0 || id2 != 0);
    }
}
