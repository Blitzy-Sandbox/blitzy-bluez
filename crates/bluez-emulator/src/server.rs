// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluez-emulator/src/server.rs — Socket server transport
//
// Complete Rust rewrite of emulator/server.c (395 lines) and
// emulator/server.h (26 lines).  Exposes emulated HCI controllers
// to external H:4 transport clients over UNIX-domain sockets or
// loopback TCP, creating a virtual controller (`BtDev`) per accepted
// connection.
//
// The C implementation uses an epoll mainloop for accept / read / write.
// This Rust version uses tokio for async socket I/O with:
//   - A spawned accept-loop task per server instance.
//   - A spawned read-loop task per accepted client.
//   - Non-blocking scatter-gather writes via `nix::sys::socket::sendmsg`
//     with `MSG_DONTWAIT`, matching the original `client_write_callback`.
//
// Key transformation rules applied:
//   mainloop_add_fd  → tokio::spawn
//   mainloop_remove_fd → JoinHandle::abort / task return
//   recv(MSG_DONTWAIT) → stream.read().await
//   sendmsg(MSG_DONTWAIT) → nix::sys::socket::sendmsg
//   malloc/free → Rust ownership (Box, Vec, OwnedFd)
//   close(fd) → Drop of stream / listener / OwnedFd

use std::io::IoSlice;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{MsgFlags, SockaddrStorage, sendmsg};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinHandle;

use crate::btdev::{BtDev, BtDevType};
use bluez_shared::sys::hci::{
    HCI_ACL_HDR_SIZE, HCI_ACLDATA_PKT, HCI_COMMAND_HDR_SIZE, HCI_COMMAND_PKT, HCI_ISO_HDR_SIZE,
    HCI_ISODATA_PKT,
};

// ===========================================================================
// ServerType enum  (replaces `enum server_type` from server.h)
// ===========================================================================

/// Type of emulated server, determining which virtual controller is
/// created for each accepted client connection.
///
/// Matches the C `enum server_type` exactly:
///   `SERVER_TYPE_BREDRLE`, `_BREDR`, `_LE`, `_AMP`, `_MONITOR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    /// BR/EDR + LE dual-mode controller (maps to `BtDevType::BrEdrLe52`).
    BrEdrLe,
    /// BR/EDR-only controller.
    BrEdr,
    /// LE-only controller.
    Le,
    /// AMP controller.
    Amp,
    /// Packet monitor — no virtual controller is created per client.
    Monitor,
}

impl ServerType {
    /// Convert to the corresponding [`BtDevType`], or `None` for `Monitor`.
    ///
    /// Matches the C mapping in `server_accept_callback`:
    ///   `SERVER_TYPE_BREDRLE → BTDEV_TYPE_BREDRLE52`
    ///   `SERVER_TYPE_BREDR   → BTDEV_TYPE_BREDR`
    ///   `SERVER_TYPE_LE      → BTDEV_TYPE_LE`
    ///   `SERVER_TYPE_AMP     → BTDEV_TYPE_AMP`
    ///   `SERVER_TYPE_MONITOR → (no btdev)`
    fn to_btdev_type(self) -> Option<BtDevType> {
        match self {
            Self::BrEdrLe => Some(BtDevType::BrEdrLe52),
            Self::BrEdr => Some(BtDevType::BrEdr),
            Self::Le => Some(BtDevType::Le),
            Self::Amp => Some(BtDevType::Amp),
            Self::Monitor => None,
        }
    }
}

// ===========================================================================
// ServerError
// ===========================================================================

/// Errors that can occur during server operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Socket binding, listening, or accept failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to create virtual controller for a client.
    #[error("BtDev creation failed: {0}")]
    BtDev(#[from] crate::btdev::BtDevError),
}

// ===========================================================================
// Server struct  (replaces `struct server` from server.c)
// ===========================================================================

/// H:4 transport server that accepts external clients over UNIX-domain
/// sockets or loopback TCP and creates a virtual HCI controller per
/// connection.
///
/// Each accepted client receives its own [`BtDev`] instance.  Incoming
/// H:4 packets are reassembled and forwarded to the controller via
/// [`BtDev::receive_h4`].  Outgoing packets (HCI events, ACL data) are
/// written back to the client through the send handler.
///
/// # Lifecycle
///
/// - `open_unix` / `open_tcp` — bind, listen, spawn accept-loop.
/// - `close` — abort the accept-loop (also invoked on `Drop`).
/// - Already-connected clients live until their connections close.
pub struct Server {
    /// Server type determines which controller type is created per client.
    server_type: ServerType,
    /// Controller ID base passed to `BtDev::new`.
    /// `0x42` for UNIX sockets, `0x43` for TCP — matching C exactly.
    id: u16,
    /// Handle to the spawned accept-loop task, `None` after `close()`.
    accept_handle: Option<JoinHandle<()>>,
}

impl Server {
    // -------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------

    /// Open a UNIX-domain socket server at the given filesystem path.
    ///
    /// The path is unlinked first (equivalent to C `unlink(path)`).
    /// The server binds, listens, and spawns an accept-loop task.
    /// Controller ID is set to `0x42` (matching C).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Io`] if the socket cannot be bound.
    pub async fn open_unix(server_type: ServerType, path: &str) -> Result<Self, ServerError> {
        // Remove any stale socket file (C: unlink(path)).
        let _ = std::fs::remove_file(path);

        let listener = UnixListener::bind(path)?;
        tracing::debug!("UNIX server listening on {}", path);

        let id: u16 = 0x42;
        let handle = tokio::task::spawn(accept_loop_unix(listener, server_type, id));

        Ok(Self { server_type, id, accept_handle: Some(handle) })
    }

    /// Open a TCP loopback server on the given port.
    ///
    /// The server binds to `127.0.0.1` with `SO_REUSEADDR` (set by
    /// tokio's `TcpListener::bind`) and spawns an accept-loop task.
    /// Controller ID is set to `0x43` (matching C).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Io`] if the socket cannot be bound.
    pub async fn open_tcp(server_type: ServerType, port: u16) -> Result<Self, ServerError> {
        // tokio's TcpListener::bind sets SO_REUSEADDR by default.
        // Binding to "127.0.0.1" matches C: inet_addr("127.0.0.1").
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        tracing::debug!("TCP server listening on 127.0.0.1:{}", port);

        let id: u16 = 0x43;
        let handle = tokio::task::spawn(accept_loop_tcp(listener, server_type, id));

        Ok(Self { server_type, id, accept_handle: Some(handle) })
    }

    // -------------------------------------------------------------------
    // Destructor
    // -------------------------------------------------------------------

    /// Stop accepting new connections.
    ///
    /// Aborts the accept-loop task and drops the listener socket.
    /// Already-connected clients continue running until their sockets
    /// close or encounter errors.
    ///
    /// Matches C `server_close` which calls `mainloop_remove_fd(server->fd)`.
    pub fn close(&mut self) {
        if let Some(handle) = self.accept_handle.take() {
            handle.abort();
            tracing::debug!("Server closed (type={:?}, id=0x{:04x})", self.server_type, self.id,);
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close();
    }
}

// ===========================================================================
// Accept loops  (replaces `server_accept_callback` in server.c)
// ===========================================================================

/// Accept loop for UNIX-domain socket connections.
///
/// Runs indefinitely until the task is aborted by [`Server::close`].
/// For each accepted connection it clones the underlying file descriptor
/// (one copy for async reads, one for the synchronous send handler) and
/// spawns a per-client read task.
async fn accept_loop_unix(listener: UnixListener, server_type: ServerType, id: u16) {
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("Failed to accept UNIX connection: {}", e);
                continue;
            }
        };

        tracing::debug!("Accepted UNIX client connection");

        // Convert to std for cloning (dup), then back to tokio.
        let std_stream = match stream.into_std() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to convert UNIX stream to std: {}", e);
                continue;
            }
        };

        let write_clone = match std_stream.try_clone() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to clone UNIX stream fd: {}", e);
                continue;
            }
        };

        let tokio_stream = match tokio::net::UnixStream::from_std(std_stream) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to re-register UNIX stream with tokio: {}", e);
                continue;
            }
        };

        // Convert the cloned std stream to an OwnedFd for the send handler.
        let write_fd: OwnedFd = write_clone.into();
        spawn_client(tokio_stream, write_fd, server_type, id);
    }
}

/// Accept loop for TCP loopback connections.
///
/// Runs indefinitely until the task is aborted by [`Server::close`].
async fn accept_loop_tcp(listener: TcpListener, server_type: ServerType, id: u16) {
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("Failed to accept TCP connection: {}", e);
                continue;
            }
        };

        tracing::debug!("Accepted TCP client connection from {}", addr);

        let std_stream = match stream.into_std() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to convert TCP stream to std: {}", e);
                continue;
            }
        };

        let write_clone = match std_stream.try_clone() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to clone TCP stream fd: {}", e);
                continue;
            }
        };

        let tokio_stream = match tokio::net::TcpStream::from_std(std_stream) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to re-register TCP stream with tokio: {}", e);
                continue;
            }
        };

        let write_fd: OwnedFd = write_clone.into();
        spawn_client(tokio_stream, write_fd, server_type, id);
    }
}

// ===========================================================================
// Client setup and lifecycle
// ===========================================================================

/// Create a virtual controller (unless Monitor) and spawn the client
/// read-loop task.
///
/// `write_fd` is a dup'd file descriptor of the accepted connection,
/// moved into the `BtDev` send handler for non-blocking writes.
fn spawn_client<S>(stream: S, write_fd: OwnedFd, server_type: ServerType, id: u16)
where
    S: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let btdev = if let Some(dev_type) = server_type.to_btdev_type() {
        // Create the virtual controller for this client.
        let mut dev = match BtDev::new(dev_type, id) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Failed to create BtDev({:?}): {}", dev_type, e);
                return;
            }
        };

        // Install the send handler.  This closure is called synchronously
        // from within `BtDev::receive_h4` whenever the controller has an
        // outgoing H:4 packet (event, ACL, SCO, ISO).  We use the dup'd
        // file descriptor with `sendmsg(MSG_DONTWAIT)` to write the
        // scatter-gather iovecs directly, matching the C
        // `client_write_callback` behaviour.
        dev.set_send_handler(Some(make_send_handler(write_fd)));
        Some(dev)
    } else {
        // Monitor type: no virtual controller.  The read loop will
        // accept connections and silently discard all received data.
        drop(write_fd);
        None
    };

    // Spawn the per-client async read task.
    tokio::task::spawn(client_read_loop(stream, btdev));
}

/// Build the send-handler closure that writes H:4 response packets to
/// the client socket using non-blocking scatter-gather I/O.
///
/// Replaces C `client_write_callback` (lines 74-89 of server.c).
fn make_send_handler(write_fd: OwnedFd) -> Box<dyn Fn(&[IoSlice<'_>]) + Send + Sync> {
    Box::new(move |iovs: &[IoSlice<'_>]| {
        // `sendmsg` with `MSG_DONTWAIT` on the dup'd fd performs a
        // non-blocking scatter-gather write.  If the kernel buffer is
        // full the write is silently dropped, matching the C code which
        // ignores the return value of `sendmsg`.
        let _ = sendmsg::<SockaddrStorage>(
            write_fd.as_raw_fd(),
            iovs,
            &[],
            MsgFlags::MSG_DONTWAIT,
            None,
        );
    })
}

// ===========================================================================
// Client read loop — H:4 packet reassembly
// (replaces `client_read_callback`, lines 91-178 of server.c)
// ===========================================================================

/// Async read loop for a single client connection.
///
/// Reads raw bytes from the transport, reassembles them into complete
/// H:4 packets using [`H4Reassembler`], and forwards each complete
/// packet to the virtual controller via [`BtDev::receive_h4`].
///
/// The task terminates on EOF, read error, or hangup.  When it returns
/// the `BtDev` is dropped, which releases the global device slot.
async fn client_read_loop<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    mut btdev: Option<BtDev>,
) {
    let mut buf = [0u8; 4096];
    let mut reassembler = H4Reassembler::new();

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                // EOF — remote closed the connection.
                tracing::trace!("Client disconnected (EOF)");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("Client read error: {}", e);
                break;
            }
        };

        // For Monitor servers btdev is None — silently discard data.
        if let Some(ref mut dev) = btdev {
            reassembler.feed(&buf[..n], dev);
        }
    }

    // Dropping `btdev` calls `BtDev::drop` which frees the global slot.
    tracing::trace!("Client task exiting, btdev dropped");
}

// ===========================================================================
// H:4 packet reassembler
// ===========================================================================

/// Incremental H:4 (UART transport) packet reassembler.
///
/// H:4 framing prepends a one-byte packet-type indicator to HCI packets:
///   - `0x01` — HCI Command  (header: 3 bytes — opcode + plen)
///   - `0x02` — HCI ACL Data (header: 4 bytes — handle + dlen)
///   - `0x05` — HCI ISO Data (header: 4 bytes — handle + dlen)
///
/// The reassembler accumulates bytes across partial reads until a
/// complete packet is formed, then delivers it to the caller.
struct H4Reassembler {
    /// Accumulated bytes for the current (incomplete) packet.
    pkt_buf: Vec<u8>,
    /// Total expected packet length (type + header + payload).
    /// Zero while the header has not yet been fully received.
    pkt_total: usize,
}

impl H4Reassembler {
    /// Create a new reassembler with no pending state.
    fn new() -> Self {
        Self { pkt_buf: Vec::with_capacity(4096), pkt_total: 0 }
    }

    /// Feed a chunk of raw bytes into the reassembler.
    ///
    /// For each complete H:4 packet found, `btdev.receive_h4()` is called
    /// immediately.  Partial packets are buffered internally until the
    /// next `feed` call supplies the remaining bytes.
    fn feed(&mut self, data: &[u8], btdev: &mut BtDev) {
        let mut pos = 0;

        while pos < data.len() {
            if self.pkt_buf.is_empty() && self.pkt_total == 0 {
                // -------------------------------------------------------
                // Starting a brand-new packet.
                // -------------------------------------------------------
                let pkt_type = data[pos];
                let hdr_size = match Self::header_size_for_type(pkt_type) {
                    Some(s) => s,
                    None => {
                        tracing::warn!(
                            "Unknown H:4 packet type 0x{:02x}, discarding rest of buffer",
                            pkt_type,
                        );
                        return;
                    }
                };

                let avail = data.len() - pos;

                if avail < hdr_size {
                    // Not enough data to parse the header — stash what
                    // we have and wait for the next read.
                    self.pkt_buf.extend_from_slice(&data[pos..]);
                    return;
                }

                // Full header available — compute total packet length.
                let payload_len = Self::payload_length(pkt_type, &data[pos + 1..pos + hdr_size]);
                let total = hdr_size + payload_len;

                if avail >= total {
                    // Complete packet available in this chunk.
                    btdev.receive_h4(&data[pos..pos + total]);
                    pos += total;
                } else {
                    // Partial body — stash and wait.
                    self.pkt_buf.extend_from_slice(&data[pos..]);
                    self.pkt_total = total;
                    return;
                }
            } else {
                // -------------------------------------------------------
                // Continuing a previously started packet.
                // -------------------------------------------------------

                if self.pkt_total == 0 {
                    // Header not yet complete — fill it.
                    let pkt_type = self.pkt_buf[0];
                    let hdr_size = match Self::header_size_for_type(pkt_type) {
                        Some(s) => s,
                        None => {
                            self.pkt_buf.clear();
                            return;
                        }
                    };

                    let need = hdr_size.saturating_sub(self.pkt_buf.len());
                    let avail = data.len() - pos;
                    let take = need.min(avail);
                    self.pkt_buf.extend_from_slice(&data[pos..pos + take]);
                    pos += take;

                    if self.pkt_buf.len() < hdr_size {
                        // Still waiting for more header bytes.
                        return;
                    }

                    // Header complete — parse the payload length.
                    let payload_len = Self::payload_length(pkt_type, &self.pkt_buf[1..hdr_size]);
                    self.pkt_total = hdr_size + payload_len;
                }

                // Accumulate body bytes.
                let need = self.pkt_total.saturating_sub(self.pkt_buf.len());
                let avail = data.len() - pos;
                let take = need.min(avail);
                self.pkt_buf.extend_from_slice(&data[pos..pos + take]);
                pos += take;

                if self.pkt_buf.len() == self.pkt_total {
                    // Complete packet — deliver it.
                    btdev.receive_h4(&self.pkt_buf);
                    self.pkt_buf.clear();
                    self.pkt_total = 0;
                }
            }
        }
    }

    /// Return the full header size (type-byte + HCI header) for a given
    /// H:4 packet type, or `None` for unknown types.
    fn header_size_for_type(pkt_type: u8) -> Option<usize> {
        match pkt_type {
            HCI_COMMAND_PKT => Some(1 + HCI_COMMAND_HDR_SIZE),
            HCI_ACLDATA_PKT => Some(1 + HCI_ACL_HDR_SIZE),
            HCI_ISODATA_PKT => Some(1 + HCI_ISO_HDR_SIZE),
            _ => None,
        }
    }

    /// Parse the payload length from the HCI header bytes (excluding the
    /// type byte).
    ///
    /// Layout per packet type:
    ///   Command : `[opcode_lo, opcode_hi, plen]`       → payload = plen
    ///   ACL     : `[handle_lo, handle_hi, dlen_lo, dlen_hi]` → payload = dlen
    ///   ISO     : `[handle_lo, handle_hi, dlen_lo, dlen_hi]` → payload = dlen
    fn payload_length(pkt_type: u8, header: &[u8]) -> usize {
        match pkt_type {
            HCI_COMMAND_PKT => {
                // hci_command_hdr: opcode(2) + plen(1).
                // `plen` is at byte offset 2 within the header.
                header[2] as usize
            }
            HCI_ACLDATA_PKT => {
                // hci_acl_hdr: handle(2) + dlen(2).
                // `dlen` is at byte offsets 2..4, little-endian.
                u16::from_le_bytes([header[2], header[3]]) as usize
            }
            HCI_ISODATA_PKT => {
                // hci_iso_hdr: handle(2) + dlen(2).
                // `dlen` is at byte offsets 2..4, little-endian.
                u16::from_le_bytes([header[2], header[3]]) as usize
            }
            _ => 0,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ServerType mapping tests
    // -----------------------------------------------------------------------

    #[test]
    fn server_type_to_btdev_bredrle() {
        assert_eq!(ServerType::BrEdrLe.to_btdev_type(), Some(BtDevType::BrEdrLe52),);
    }

    #[test]
    fn server_type_to_btdev_bredr() {
        assert_eq!(ServerType::BrEdr.to_btdev_type(), Some(BtDevType::BrEdr));
    }

    #[test]
    fn server_type_to_btdev_le() {
        assert_eq!(ServerType::Le.to_btdev_type(), Some(BtDevType::Le));
    }

    #[test]
    fn server_type_to_btdev_amp() {
        assert_eq!(ServerType::Amp.to_btdev_type(), Some(BtDevType::Amp));
    }

    #[test]
    fn server_type_to_btdev_monitor() {
        assert_eq!(ServerType::Monitor.to_btdev_type(), None);
    }

    // -----------------------------------------------------------------------
    // H:4 reassembler tests
    // -----------------------------------------------------------------------

    #[test]
    fn header_size_for_command() {
        assert_eq!(
            H4Reassembler::header_size_for_type(HCI_COMMAND_PKT),
            Some(1 + HCI_COMMAND_HDR_SIZE),
        );
    }

    #[test]
    fn header_size_for_acl() {
        assert_eq!(
            H4Reassembler::header_size_for_type(HCI_ACLDATA_PKT),
            Some(1 + HCI_ACL_HDR_SIZE),
        );
    }

    #[test]
    fn header_size_for_iso() {
        assert_eq!(
            H4Reassembler::header_size_for_type(HCI_ISODATA_PKT),
            Some(1 + HCI_ISO_HDR_SIZE),
        );
    }

    #[test]
    fn header_size_unknown() {
        assert_eq!(H4Reassembler::header_size_for_type(0xFF), None);
    }

    #[test]
    fn payload_length_command() {
        // Command header: opcode_lo, opcode_hi, plen=10
        let hdr = [0x00, 0x00, 10];
        assert_eq!(H4Reassembler::payload_length(HCI_COMMAND_PKT, &hdr), 10);
    }

    #[test]
    fn payload_length_acl() {
        // ACL header: handle_lo, handle_hi, dlen_lo=0x20, dlen_hi=0x00 → 32
        let hdr = [0x01, 0x00, 0x20, 0x00];
        assert_eq!(H4Reassembler::payload_length(HCI_ACLDATA_PKT, &hdr), 32);
    }

    #[test]
    fn payload_length_iso() {
        // ISO header: handle_lo, handle_hi, dlen_lo=0x00, dlen_hi=0x01 → 256
        let hdr = [0x01, 0x00, 0x00, 0x01];
        assert_eq!(H4Reassembler::payload_length(HCI_ISODATA_PKT, &hdr), 256);
    }
}
