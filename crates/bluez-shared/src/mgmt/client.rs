// SPDX-License-Identifier: GPL-2.0-or-later
//
// Async management client replacing src/shared/mgmt.c
//
// C's callback pattern is replaced by:
//   - send() returns oneshot::Receiver<MgmtResponse> for the response
//   - Event subscription via broadcast-style channels
//   - Internal task serializes commands and dispatches responses/events

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

use crate::mgmt::defs::{MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS, MGMT_HDR_SIZE};

/// Response from a management command.
#[derive(Debug, Clone)]
pub struct MgmtResponse {
    /// MGMT_STATUS_* value.
    pub status: u8,
    /// Response parameters (may be empty).
    pub data: Vec<u8>,
}

/// An event received from the management interface.
#[derive(Debug, Clone)]
pub struct MgmtEvent {
    /// Event opcode (MGMT_EV_*).
    pub event: u16,
    /// Controller index (0xFFFF for non-controller events).
    pub index: u16,
    /// Event parameters.
    pub data: Vec<u8>,
}

/// Internal command to send to the writer task.
struct SendCommand {
    opcode: u16,
    index: u16,
    data: Vec<u8>,
    response_tx: oneshot::Sender<io::Result<MgmtResponse>>,
}

/// Async management client.
///
/// Replaces C's `struct bt_mgmt`. Communicates with the BlueZ kernel management
/// interface over an HCI control socket.
///
/// ```ignore
/// let client = MgmtClient::open()?;
/// let version = client.send(MGMT_OP_READ_VERSION, 0xFFFF, &[]).await?;
/// ```
pub struct MgmtClient {
    inner: Arc<MgmtClientInner>,
}

struct MgmtClientInner {
    cmd_tx: mpsc::UnboundedSender<SendCommand>,
    event_tx: mpsc::UnboundedSender<EventSubscription>,
    next_sub_id: AtomicU32,
    shutdown: Notify,
}

struct EventSubscription {
    _id: u32,
    event: Option<u16>,
    index: Option<u16>,
    tx: mpsc::UnboundedSender<MgmtEvent>,
}

/// Handle for receiving events. Drop to unsubscribe.
pub struct EventReceiver {
    pub rx: mpsc::UnboundedReceiver<MgmtEvent>,
    _id: u32,
}

impl MgmtClient {
    /// Create a management client from an existing non-blocking file descriptor.
    ///
    /// The fd should be an HCI control socket (BTPROTO_HCI, HCI_CHANNEL_CONTROL).
    /// The client spawns an internal task to handle I/O.
    pub fn new(fd: std::os::unix::io::OwnedFd) -> io::Result<Self> {
        let async_fd = Arc::new(AsyncFd::new(fd)?);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let shutdown = Notify::new();

        let inner = Arc::new(MgmtClientInner {
            cmd_tx,
            event_tx,
            next_sub_id: AtomicU32::new(1),
            shutdown,
        });

        // Spawn the I/O task
        let async_fd_clone = async_fd.clone();
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            mgmt_io_task(async_fd_clone, cmd_rx, event_rx, &inner_clone.shutdown).await;
        });

        Ok(Self { inner })
    }

    /// Send a management command and wait for the response.
    pub async fn send(
        &self,
        opcode: u16,
        index: u16,
        data: &[u8],
    ) -> io::Result<MgmtResponse> {
        let (response_tx, response_rx) = oneshot::channel();

        let cmd = SendCommand {
            opcode,
            index,
            data: data.to_vec(),
            response_tx,
        };

        self.inner
            .cmd_tx
            .send(cmd)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client shut down"))?;

        response_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "response channel closed"))?
    }

    /// Subscribe to management events.
    ///
    /// - `event`: Filter by event type, or `None` for all events.
    /// - `index`: Filter by controller index, or `None` for all controllers.
    pub fn subscribe(
        &self,
        event: Option<u16>,
        index: Option<u16>,
    ) -> io::Result<EventReceiver> {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.inner.next_sub_id.fetch_add(1, Ordering::Relaxed);

        let sub = EventSubscription {
            _id: id,
            event,
            index,
            tx,
        };

        self.inner
            .event_tx
            .send(sub)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client shut down"))?;

        Ok(EventReceiver { rx, _id: id })
    }

    /// Shut down the client, closing the I/O task.
    pub fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
    }
}

/// The internal I/O task that reads/writes on the management socket.
async fn mgmt_io_task(
    fd: Arc<AsyncFd<std::os::unix::io::OwnedFd>>,
    mut cmd_rx: mpsc::UnboundedReceiver<SendCommand>,
    mut event_sub_rx: mpsc::UnboundedReceiver<EventSubscription>,
    shutdown: &Notify,
) {
    #[allow(clippy::type_complexity)]
    let pending: Arc<Mutex<HashMap<(u16, u16), Vec<oneshot::Sender<io::Result<MgmtResponse>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let subscribers: Arc<Mutex<Vec<EventSubscription>>> = Arc::new(Mutex::new(Vec::new()));
    let mut buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            // Handle incoming commands to send
            Some(cmd) = cmd_rx.recv() => {
                // Build MGMT packet: header + data
                let total_len = MGMT_HDR_SIZE + cmd.data.len();
                let mut packet = Vec::with_capacity(total_len);
                packet.extend_from_slice(&cmd.opcode.to_le_bytes());
                packet.extend_from_slice(&cmd.index.to_le_bytes());
                packet.extend_from_slice(&(cmd.data.len() as u16).to_le_bytes());
                packet.extend_from_slice(&cmd.data);

                // Register pending response
                {
                    let mut p = pending.lock().await;
                    p.entry((cmd.opcode, cmd.index))
                        .or_default()
                        .push(cmd.response_tx);
                }

                // Write to socket
                loop {
                    let mut guard = match fd.writable().await {
                        Ok(g) => g,
                        Err(e) => {
                            // Can't recover; pending senders will get dropped
                            tracing::error!("mgmt writable error: {}", e);
                            break;
                        }
                    };
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
                            Ok(ret as usize)
                        }
                    }) {
                        Ok(Ok(_)) => break,
                        Ok(Err(e)) => {
                            tracing::error!("mgmt send error: {}", e);
                            break;
                        }
                        Err(_would_block) => continue,
                    }
                }
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
                        Ok(Ok(n)) if n >= MGMT_HDR_SIZE => {
                            let event = u16::from_le_bytes([buf[0], buf[1]]);
                            let index = u16::from_le_bytes([buf[2], buf[3]]);
                            let _plen = u16::from_le_bytes([buf[4], buf[5]]) as usize;
                            let params = &buf[MGMT_HDR_SIZE..n];

                            match event {
                                MGMT_EV_CMD_COMPLETE => {
                                    if params.len() >= 3 {
                                        let opcode = u16::from_le_bytes([params[0], params[1]]);
                                        let status = params[2];
                                        let data = params[3..].to_vec();

                                        let mut p = pending.lock().await;
                                        if let Some(senders) = p.get_mut(&(opcode, index)) {
                                            if let Some(tx) = senders.pop() {
                                                let _ = tx.send(Ok(MgmtResponse { status, data }));
                                            }
                                            if senders.is_empty() {
                                                p.remove(&(opcode, index));
                                            }
                                        }
                                    }
                                }
                                MGMT_EV_CMD_STATUS => {
                                    if params.len() >= 3 {
                                        let opcode = u16::from_le_bytes([params[0], params[1]]);
                                        let status = params[2];

                                        let mut p = pending.lock().await;
                                        if let Some(senders) = p.get_mut(&(opcode, index)) {
                                            if let Some(tx) = senders.pop() {
                                                let _ = tx.send(Ok(MgmtResponse {
                                                    status,
                                                    data: Vec::new(),
                                                }));
                                            }
                                            if senders.is_empty() {
                                                p.remove(&(opcode, index));
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    // Dispatch to event subscribers
                                    let subs = subscribers.lock().await;
                                    let evt = MgmtEvent {
                                        event,
                                        index,
                                        data: params.to_vec(),
                                    };
                                    subs.iter()
                                        .filter(|s| {
                                            s.event.is_none_or(|e| e == event)
                                                && s.index.is_none_or(|i| i == index)
                                        })
                                        .for_each(|s| {
                                            let _ = s.tx.send(evt.clone());
                                        });
                                }
                            }
                        }
                        Ok(Ok(_)) => {} // Too short, ignore
                        Ok(Err(e)) => {
                            tracing::error!("mgmt recv error: {}", e);
                        }
                        Err(_would_block) => {}
                    }
                }
            }

            // Shutdown signal
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
    fn test_mgmt_response_debug() {
        let resp = MgmtResponse {
            status: 0,
            data: vec![1, 2, 3],
        };
        let _ = format!("{:?}", resp);
    }

    #[test]
    fn test_mgmt_event_clone() {
        let evt = MgmtEvent {
            event: 0x0001,
            index: 0xFFFF,
            data: vec![1, 2, 3],
        };
        let evt2 = evt.clone();
        assert_eq!(evt.event, evt2.event);
        assert_eq!(evt.data, evt2.data);
    }
}
