// SPDX-License-Identifier: GPL-2.0-or-later
//
// Async HCI transport replacing src/shared/hci.c
//
// Implements the HCI command/response pattern with credit-based flow control.
// C's callback pattern is replaced by:
//   - send() returns oneshot::Receiver<HciResponse>
//   - Event registration via subscribe()
//   - Internal task handles I/O, credit management, and dispatch

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

use crate::hci::events::{BT_HCI_EVT_CMD_COMPLETE, BT_HCI_EVT_CMD_STATUS};

/// H4 packet type indicators.
pub const BT_H4_CMD_PKT: u8 = 0x01;
pub const BT_H4_ACL_PKT: u8 = 0x02;
pub const BT_H4_SCO_PKT: u8 = 0x03;
pub const BT_H4_EVT_PKT: u8 = 0x04;
pub const BT_H4_ISO_PKT: u8 = 0x05;

/// Response from an HCI command.
#[derive(Debug, Clone)]
pub struct HciResponse {
    /// Response parameters (after status byte for CMD_COMPLETE).
    pub data: Vec<u8>,
}

/// An HCI event.
#[derive(Debug, Clone)]
pub struct HciEvent {
    /// Event code.
    pub event: u8,
    /// Event parameters.
    pub data: Vec<u8>,
}

/// Internal command to be sent.
struct HciCommand {
    opcode: u16,
    data: Vec<u8>,
    response_tx: oneshot::Sender<io::Result<HciResponse>>,
}

/// Internal data packet to be sent.
struct HciDataPacket {
    pkt_type: u8,
    data: Vec<u8>,
}

/// Async HCI transport.
///
/// Replaces C's `struct bt_hci`. Communicates with an HCI controller
/// via user-channel or raw socket.
pub struct HciTransport {
    inner: Arc<HciTransportInner>,
}

struct HciTransportInner {
    cmd_tx: mpsc::UnboundedSender<HciCommand>,
    data_tx: mpsc::UnboundedSender<HciDataPacket>,
    event_tx: mpsc::UnboundedSender<HciEventSubscription>,
    next_sub_id: AtomicU32,
    shutdown: Notify,
}

struct HciEventSubscription {
    _id: u32,
    event: Option<u8>,
    tx: mpsc::UnboundedSender<HciEvent>,
}

/// Handle for receiving HCI events. Drop to unsubscribe.
pub struct HciEventReceiver {
    pub rx: mpsc::UnboundedReceiver<HciEvent>,
    _id: u32,
}

impl HciTransport {
    /// Create an HCI transport from an existing non-blocking fd.
    ///
    /// Set `is_stream` to true for stream-based transports (UART),
    /// false for packet-based (user-channel, raw).
    pub fn new(fd: std::os::unix::io::OwnedFd, _is_stream: bool) -> io::Result<Self> {
        let async_fd = Arc::new(AsyncFd::new(fd)?);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let shutdown = Notify::new();

        let inner = Arc::new(HciTransportInner {
            cmd_tx,
            data_tx,
            event_tx,
            next_sub_id: AtomicU32::new(1),
            shutdown,
        });

        let async_fd_clone = async_fd.clone();
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            hci_io_task(async_fd_clone, cmd_rx, data_rx, event_rx, &inner_clone.shutdown).await;
        });

        Ok(Self { inner })
    }

    /// Send an HCI command and wait for the response.
    pub async fn send(
        &self,
        opcode: u16,
        data: &[u8],
    ) -> io::Result<HciResponse> {
        let (response_tx, response_rx) = oneshot::channel();

        let cmd = HciCommand {
            opcode,
            data: data.to_vec(),
            response_tx,
        };

        self.inner
            .cmd_tx
            .send(cmd)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "transport shut down"))?;

        response_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "response channel closed"))?
    }

    /// Send a data packet (ACL, SCO, or ISO).
    pub fn send_data(&self, pkt_type: u8, data: &[u8]) -> io::Result<()> {
        let pkt = HciDataPacket {
            pkt_type,
            data: data.to_vec(),
        };

        self.inner
            .data_tx
            .send(pkt)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "transport shut down"))
    }

    /// Subscribe to HCI events.
    ///
    /// - `event`: Filter by event code, or `None` for all events.
    pub fn subscribe(&self, event: Option<u8>) -> io::Result<HciEventReceiver> {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.inner.next_sub_id.fetch_add(1, Ordering::Relaxed);

        let sub = HciEventSubscription { _id: id, event, tx };

        self.inner
            .event_tx
            .send(sub)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "transport shut down"))?;

        Ok(HciEventReceiver { rx, _id: id })
    }

    /// Shut down the transport.
    pub fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
    }
}

/// Write a complete HCI packet to the socket.
async fn write_packet(
    fd: &AsyncFd<std::os::unix::io::OwnedFd>,
    packet: &[u8],
) -> io::Result<()> {
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| {
            let raw = std::os::unix::io::AsRawFd::as_raw_fd(inner.get_ref());
            let ret = unsafe {
                libc::send(
                    raw,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                )
            };
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// The internal I/O task for HCI transport.
async fn hci_io_task(
    fd: Arc<AsyncFd<std::os::unix::io::OwnedFd>>,
    mut cmd_rx: mpsc::UnboundedReceiver<HciCommand>,
    mut data_rx: mpsc::UnboundedReceiver<HciDataPacket>,
    mut event_sub_rx: mpsc::UnboundedReceiver<HciEventSubscription>,
    shutdown: &Notify,
) {
    // Pending commands awaiting response, keyed by opcode
    #[allow(clippy::type_complexity)]
    let pending: Arc<Mutex<VecDeque<(u16, oneshot::Sender<io::Result<HciResponse>>)>>> =
        Arc::new(Mutex::new(VecDeque::new()));
    let subscribers: Arc<Mutex<Vec<HciEventSubscription>>> = Arc::new(Mutex::new(Vec::new()));

    // Command credit counter (starts at 1 per spec)
    let mut num_cmds: u8 = 1;
    // Commands waiting for credits
    let mut cmd_queue: VecDeque<HciCommand> = VecDeque::new();

    let mut buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            // Handle outgoing commands
            Some(cmd) = cmd_rx.recv() => {
                cmd_queue.push_back(cmd);

                // Try to send queued commands if we have credits
                while num_cmds > 0 {
                    if let Some(cmd) = cmd_queue.pop_front() {
                        // Build HCI command packet: type(1) + opcode(2) + plen(1) + data
                        let mut packet = Vec::with_capacity(4 + cmd.data.len());
                        packet.push(BT_H4_CMD_PKT);
                        packet.extend_from_slice(&cmd.opcode.to_le_bytes());
                        packet.push(cmd.data.len() as u8);
                        packet.extend_from_slice(&cmd.data);

                        if let Err(e) = write_packet(&fd, &packet).await {
                            let _ = cmd.response_tx.send(Err(e));
                            continue;
                        }

                        num_cmds -= 1;
                        pending.lock().await.push_back((cmd.opcode, cmd.response_tx));
                    } else {
                        break;
                    }
                }
            }

            // Handle outgoing data packets
            Some(pkt) = data_rx.recv() => {
                let mut packet = Vec::with_capacity(1 + pkt.data.len());
                packet.push(pkt.pkt_type);
                packet.extend_from_slice(&pkt.data);
                let _ = write_packet(&fd, &packet).await;
            }

            // Handle new event subscriptions
            Some(sub) = event_sub_rx.recv() => {
                subscribers.lock().await.push(sub);
            }

            // Handle incoming data from socket
            result = fd.readable() => {
                if let Ok(mut guard) = result {
                    match guard.try_io(|inner| {
                        let raw = std::os::unix::io::AsRawFd::as_raw_fd(inner.get_ref());
                        let ret = unsafe {
                            libc::recv(
                                raw,
                                buf.as_mut_ptr() as *mut libc::c_void,
                                buf.len(),
                                0,
                            )
                        };
                        if ret < 0 {
                            Err(io::Error::last_os_error())
                        } else {
                            Ok(ret as usize)
                        }
                    }) {
                        Ok(Ok(n)) if n >= 3 => {
                            // Packet format: type(1) + event_hdr(evt(1) + plen(1)) + params
                            let pkt_type = buf[0];
                            if pkt_type == BT_H4_EVT_PKT && n >= 3 {
                                let evt_code = buf[1];
                                let plen = buf[2] as usize;
                                let params = if n >= 3 + plen {
                                    &buf[3..3 + plen]
                                } else {
                                    &buf[3..n]
                                };

                                match evt_code {
                                    BT_HCI_EVT_CMD_COMPLETE => {
                                        // ncmd(1) + opcode(2) + return_params
                                        if params.len() >= 3 {
                                            let ncmd = params[0];
                                            let opcode = u16::from_le_bytes([params[1], params[2]]);
                                            let data = params[3..].to_vec();

                                            num_cmds = ncmd;

                                            // Match to pending command
                                            let mut p = pending.lock().await;
                                            if let Some(pos) = p.iter().position(|(op, _)| *op == opcode) {
                                                let (_, tx) = p.remove(pos).unwrap();
                                                let _ = tx.send(Ok(HciResponse { data }));
                                            }
                                        }
                                    }
                                    BT_HCI_EVT_CMD_STATUS => {
                                        // status(1) + ncmd(1) + opcode(2)
                                        if params.len() >= 4 {
                                            let _status = params[0];
                                            let ncmd = params[1];
                                            let opcode = u16::from_le_bytes([params[2], params[3]]);

                                            num_cmds = ncmd;

                                            let mut p = pending.lock().await;
                                            if let Some(pos) = p.iter().position(|(op, _)| *op == opcode) {
                                                let (_, tx) = p.remove(pos).unwrap();
                                                let _ = tx.send(Ok(HciResponse { data: params.to_vec() }));
                                            }
                                        }
                                    }
                                    _ => {}
                                }

                                // Dispatch to event subscribers
                                let subs = subscribers.lock().await;
                                let evt = HciEvent {
                                    event: evt_code,
                                    data: params.to_vec(),
                                };
                                subs.iter()
                                    .filter(|s| s.event.is_none_or(|e| e == evt_code))
                                    .for_each(|s| {
                                        let _ = s.tx.send(evt.clone());
                                    });

                                // Try to send queued commands with new credits
                                while num_cmds > 0 {
                                    if let Some(cmd) = cmd_queue.pop_front() {
                                        let mut packet = Vec::with_capacity(4 + cmd.data.len());
                                        packet.push(BT_H4_CMD_PKT);
                                        packet.extend_from_slice(&cmd.opcode.to_le_bytes());
                                        packet.push(cmd.data.len() as u8);
                                        packet.extend_from_slice(&cmd.data);

                                        if let Err(e) = write_packet(&fd, &packet).await {
                                            let _ = cmd.response_tx.send(Err(e));
                                            continue;
                                        }

                                        num_cmds -= 1;
                                        pending.lock().await.push_back((cmd.opcode, cmd.response_tx));
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(Ok(_)) => {} // Too short
                        Ok(Err(e)) => {
                            tracing::error!("hci recv error: {}", e);
                        }
                        Err(_would_block) => {}
                    }
                }
            }

            // Shutdown
            _ = shutdown.notified() => {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hci_response_debug() {
        let resp = HciResponse {
            data: vec![0x00, 0x01],
        };
        let _ = format!("{:?}", resp);
    }

    #[test]
    fn test_hci_event_clone() {
        let evt = HciEvent {
            event: 0x0E,
            data: vec![1, 2, 3],
        };
        let evt2 = evt.clone();
        assert_eq!(evt.event, evt2.event);
    }

    #[test]
    fn test_packet_type_constants() {
        assert_eq!(BT_H4_CMD_PKT, 0x01);
        assert_eq!(BT_H4_ACL_PKT, 0x02);
        assert_eq!(BT_H4_EVT_PKT, 0x04);
        assert_eq!(BT_H4_ISO_PKT, 0x05);
    }
}
