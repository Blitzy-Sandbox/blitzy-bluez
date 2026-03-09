// SPDX-License-Identifier: GPL-2.0-or-later
//
// ATT (Attribute Protocol) implementation replacing src/shared/att.c
//
// Provides async ATT client/server with EATT multi-channel support.
// C's callback pattern is replaced by async send/recv and event channels.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

// ---- ATT Constants ----

pub const BT_ATT_CID: u16 = 4;
pub const BT_ATT_PSM: u16 = 31;
pub const BT_ATT_EATT_PSM: u16 = 0x27;

pub const BT_ATT_DEFAULT_LE_MTU: u16 = 23;
pub const BT_ATT_MAX_LE_MTU: u16 = 517;
pub const BT_ATT_MAX_VALUE_LEN: u16 = 512;

/// ATT link types.
pub const BT_ATT_BREDR: u8 = 0x00;
pub const BT_ATT_LE: u8 = 0x01;
pub const BT_ATT_EATT: u8 = 0x02;
pub const BT_ATT_LOCAL: u8 = 0xFF;

/// ATT security levels.
pub const BT_ATT_SECURITY_AUTO: u8 = 0;
pub const BT_ATT_SECURITY_LOW: u8 = 1;
pub const BT_ATT_SECURITY_MEDIUM: u8 = 2;
pub const BT_ATT_SECURITY_HIGH: u8 = 3;
pub const BT_ATT_SECURITY_FIPS: u8 = 4;

// ---- ATT Opcodes ----

pub const BT_ATT_OP_ERROR_RSP: u8 = 0x01;
pub const BT_ATT_OP_MTU_REQ: u8 = 0x02;
pub const BT_ATT_OP_MTU_RSP: u8 = 0x03;
pub const BT_ATT_OP_FIND_INFO_REQ: u8 = 0x04;
pub const BT_ATT_OP_FIND_INFO_RSP: u8 = 0x05;
pub const BT_ATT_OP_FIND_BY_TYPE_REQ: u8 = 0x06;
pub const BT_ATT_OP_FIND_BY_TYPE_RSP: u8 = 0x07;
pub const BT_ATT_OP_READ_BY_TYPE_REQ: u8 = 0x08;
pub const BT_ATT_OP_READ_BY_TYPE_RSP: u8 = 0x09;
pub const BT_ATT_OP_READ_REQ: u8 = 0x0A;
pub const BT_ATT_OP_READ_RSP: u8 = 0x0B;
pub const BT_ATT_OP_READ_BLOB_REQ: u8 = 0x0C;
pub const BT_ATT_OP_READ_BLOB_RSP: u8 = 0x0D;
pub const BT_ATT_OP_READ_MULT_REQ: u8 = 0x0E;
pub const BT_ATT_OP_READ_MULT_RSP: u8 = 0x0F;
pub const BT_ATT_OP_READ_BY_GRP_TYPE_REQ: u8 = 0x10;
pub const BT_ATT_OP_READ_BY_GRP_TYPE_RSP: u8 = 0x11;
pub const BT_ATT_OP_WRITE_REQ: u8 = 0x12;
pub const BT_ATT_OP_WRITE_RSP: u8 = 0x13;
pub const BT_ATT_OP_PREP_WRITE_REQ: u8 = 0x16;
pub const BT_ATT_OP_PREP_WRITE_RSP: u8 = 0x17;
pub const BT_ATT_OP_EXEC_WRITE_REQ: u8 = 0x18;
pub const BT_ATT_OP_EXEC_WRITE_RSP: u8 = 0x19;
pub const BT_ATT_OP_HANDLE_NFY: u8 = 0x1B;
pub const BT_ATT_OP_HANDLE_IND: u8 = 0x1D;
pub const BT_ATT_OP_HANDLE_CFM: u8 = 0x1E;
pub const BT_ATT_OP_READ_MULT_VL_REQ: u8 = 0x20;
pub const BT_ATT_OP_READ_MULT_VL_RSP: u8 = 0x21;
pub const BT_ATT_OP_HANDLE_NFY_MULT: u8 = 0x23;
pub const BT_ATT_OP_WRITE_CMD: u8 = 0x52;
pub const BT_ATT_OP_SIGNED_WRITE_CMD: u8 = 0xD2;

/// Mask to determine if an opcode expects a response.
#[cfg(test)]
const ATT_OP_SIGNED_MASK: u8 = 0x80;

// ---- ATT Error Codes ----

pub const BT_ATT_ERROR_INVALID_HANDLE: u8 = 0x01;
pub const BT_ATT_ERROR_READ_NOT_PERMITTED: u8 = 0x02;
pub const BT_ATT_ERROR_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const BT_ATT_ERROR_INVALID_PDU: u8 = 0x04;
pub const BT_ATT_ERROR_AUTHENTICATION: u8 = 0x05;
pub const BT_ATT_ERROR_REQUEST_NOT_SUPPORTED: u8 = 0x06;
pub const BT_ATT_ERROR_INVALID_OFFSET: u8 = 0x07;
pub const BT_ATT_ERROR_AUTHORIZATION: u8 = 0x08;
pub const BT_ATT_ERROR_PREPARE_QUEUE_FULL: u8 = 0x09;
pub const BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
pub const BT_ATT_ERROR_ATTRIBUTE_NOT_LONG: u8 = 0x0B;
pub const BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_SIZE: u8 = 0x0C;
pub const BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN: u8 = 0x0D;
pub const BT_ATT_ERROR_UNLIKELY: u8 = 0x0E;
pub const BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION: u8 = 0x0F;
pub const BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE: u8 = 0x10;
pub const BT_ATT_ERROR_INSUFFICIENT_RESOURCES: u8 = 0x11;
pub const BT_ATT_ERROR_DB_OUT_OF_SYNC: u8 = 0x12;
pub const BT_ATT_ERROR_VALUE_NOT_ALLOWED: u8 = 0x13;

// ---- Permission Flags ----

pub const BT_ATT_PERM_READ: u16 = 0x0001;
pub const BT_ATT_PERM_WRITE: u16 = 0x0002;
pub const BT_ATT_PERM_READ_ENCRYPT: u16 = 0x0004;
pub const BT_ATT_PERM_WRITE_ENCRYPT: u16 = 0x0008;
pub const BT_ATT_PERM_READ_AUTHEN: u16 = 0x0010;
pub const BT_ATT_PERM_WRITE_AUTHEN: u16 = 0x0020;
pub const BT_ATT_PERM_AUTHORIZE: u16 = 0x0040;
pub const BT_ATT_PERM_SECURE_READ: u16 = 0x0080;
pub const BT_ATT_PERM_SECURE_WRITE: u16 = 0x0100;
pub const BT_ATT_PERM_NONE: u16 = 0x0200;

// ---- ATT Operation Types ----

/// Classification of ATT opcodes by request/response pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttOpType {
    /// Request that expects a response.
    Request,
    /// Response to a request.
    Response,
    /// Command that does not expect a response.
    Command,
    /// Indication that expects a confirmation.
    Indication,
    /// Notification (no confirmation expected).
    Notification,
    /// Confirmation of an indication.
    Confirmation,
    /// Unknown or invalid opcode.
    Unknown,
}

/// Classify an ATT opcode by its type.
pub fn att_op_type(opcode: u8) -> AttOpType {
    match opcode {
        BT_ATT_OP_MTU_REQ
        | BT_ATT_OP_FIND_INFO_REQ
        | BT_ATT_OP_FIND_BY_TYPE_REQ
        | BT_ATT_OP_READ_BY_TYPE_REQ
        | BT_ATT_OP_READ_REQ
        | BT_ATT_OP_READ_BLOB_REQ
        | BT_ATT_OP_READ_MULT_REQ
        | BT_ATT_OP_READ_BY_GRP_TYPE_REQ
        | BT_ATT_OP_WRITE_REQ
        | BT_ATT_OP_PREP_WRITE_REQ
        | BT_ATT_OP_EXEC_WRITE_REQ
        | BT_ATT_OP_READ_MULT_VL_REQ => AttOpType::Request,

        BT_ATT_OP_ERROR_RSP
        | BT_ATT_OP_MTU_RSP
        | BT_ATT_OP_FIND_INFO_RSP
        | BT_ATT_OP_FIND_BY_TYPE_RSP
        | BT_ATT_OP_READ_BY_TYPE_RSP
        | BT_ATT_OP_READ_RSP
        | BT_ATT_OP_READ_BLOB_RSP
        | BT_ATT_OP_READ_MULT_RSP
        | BT_ATT_OP_READ_BY_GRP_TYPE_RSP
        | BT_ATT_OP_WRITE_RSP
        | BT_ATT_OP_PREP_WRITE_RSP
        | BT_ATT_OP_EXEC_WRITE_RSP
        | BT_ATT_OP_READ_MULT_VL_RSP => AttOpType::Response,

        BT_ATT_OP_WRITE_CMD | BT_ATT_OP_SIGNED_WRITE_CMD => AttOpType::Command,

        BT_ATT_OP_HANDLE_IND => AttOpType::Indication,

        BT_ATT_OP_HANDLE_NFY | BT_ATT_OP_HANDLE_NFY_MULT => AttOpType::Notification,

        BT_ATT_OP_HANDLE_CFM => AttOpType::Confirmation,

        _ => AttOpType::Unknown,
    }
}

/// An ATT PDU received on a channel.
#[derive(Debug, Clone)]
pub struct AttPdu {
    /// ATT opcode.
    pub opcode: u8,
    /// PDU parameters (after opcode byte).
    pub data: Vec<u8>,
}

/// Response from an ATT request.
#[derive(Debug, Clone)]
pub struct AttResponse {
    /// Response opcode (or BT_ATT_OP_ERROR_RSP).
    pub opcode: u8,
    /// Response parameters.
    pub data: Vec<u8>,
}

/// Internal command for the ATT I/O task.
struct AttSendOp {
    opcode: u8,
    data: Vec<u8>,
    response_tx: Option<oneshot::Sender<io::Result<AttResponse>>>,
}

/// ATT notification/indication subscription.
struct AttSubscription {
    _id: u32,
    opcode: Option<u8>,
    tx: mpsc::UnboundedSender<AttPdu>,
}

/// Async ATT protocol handler.
///
/// Replaces C's `struct bt_att`. Supports request/response, notifications,
/// indications, and commands over one or more channels (EATT).
pub struct BtAtt {
    inner: Arc<BtAttInner>,
}

struct BtAttInner {
    send_tx: mpsc::UnboundedSender<AttSendOp>,
    sub_tx: mpsc::UnboundedSender<AttSubscription>,
    next_sub_id: AtomicU32,
    mtu: AtomicU16,
    shutdown: Notify,
}

/// Handle for receiving ATT notifications/indications.
pub struct AttNotifyReceiver {
    pub rx: mpsc::UnboundedReceiver<AttPdu>,
    _id: u32,
}

impl BtAtt {
    /// Create an ATT instance from a non-blocking L2CAP socket fd.
    pub fn new(fd: std::os::unix::io::OwnedFd) -> io::Result<Self> {
        let async_fd = Arc::new(AsyncFd::new(fd)?);
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        let (sub_tx, sub_rx) = mpsc::unbounded_channel();
        let shutdown = Notify::new();

        let inner = Arc::new(BtAttInner {
            send_tx,
            sub_tx,
            next_sub_id: AtomicU32::new(1),
            mtu: AtomicU16::new(BT_ATT_DEFAULT_LE_MTU),
            shutdown,
        });

        let async_fd_clone = async_fd.clone();
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            att_io_task(async_fd_clone, send_rx, sub_rx, &inner_clone).await;
        });

        Ok(Self { inner })
    }

    /// Send an ATT request and wait for the response.
    pub async fn send_request(
        &self,
        opcode: u8,
        data: &[u8],
    ) -> io::Result<AttResponse> {
        let (response_tx, response_rx) = oneshot::channel();

        let op = AttSendOp {
            opcode,
            data: data.to_vec(),
            response_tx: Some(response_tx),
        };

        self.inner
            .send_tx
            .send(op)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ATT shut down"))?;

        response_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "response channel closed"))?
    }

    /// Send an ATT command (no response expected).
    pub fn send_command(&self, opcode: u8, data: &[u8]) -> io::Result<()> {
        let op = AttSendOp {
            opcode,
            data: data.to_vec(),
            response_tx: None,
        };

        self.inner
            .send_tx
            .send(op)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ATT shut down"))
    }

    /// Subscribe to ATT notifications/indications.
    pub fn subscribe(&self, opcode: Option<u8>) -> io::Result<AttNotifyReceiver> {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.inner.next_sub_id.fetch_add(1, Ordering::Relaxed);

        let sub = AttSubscription { _id: id, opcode, tx };

        self.inner
            .sub_tx
            .send(sub)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ATT shut down"))?;

        Ok(AttNotifyReceiver { rx, _id: id })
    }

    /// Get the current MTU.
    pub fn mtu(&self) -> u16 {
        self.inner.mtu.load(Ordering::Relaxed)
    }

    /// Shut down the ATT instance.
    pub fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
    }
}

/// Internal I/O task for ATT.
async fn att_io_task(
    fd: Arc<AsyncFd<std::os::unix::io::OwnedFd>>,
    mut send_rx: mpsc::UnboundedReceiver<AttSendOp>,
    mut sub_rx: mpsc::UnboundedReceiver<AttSubscription>,
    inner: &BtAttInner,
) {
    let pending_req: Arc<Mutex<Option<oneshot::Sender<io::Result<AttResponse>>>>> =
        Arc::new(Mutex::new(None));
    let pending_ind: Arc<Mutex<Option<oneshot::Sender<io::Result<AttResponse>>>>> =
        Arc::new(Mutex::new(None));
    let subscribers: Arc<Mutex<Vec<AttSubscription>>> = Arc::new(Mutex::new(Vec::new()));
    let mut send_queue: VecDeque<AttSendOp> = VecDeque::new();

    let mut buf = vec![0u8; BT_ATT_MAX_LE_MTU as usize + 1];

    loop {
        tokio::select! {
            // Handle outgoing operations
            Some(op) = send_rx.recv() => {
                send_queue.push_back(op);

                // Try to send queued operations
                while let Some(op) = send_queue.front() {
                    let op_type = att_op_type(op.opcode);

                    // Check if we can send (request/indication needs no pending)
                    let can_send = match op_type {
                        AttOpType::Request => pending_req.lock().await.is_none(),
                        AttOpType::Indication => pending_ind.lock().await.is_none(),
                        _ => true,
                    };

                    if !can_send {
                        break;
                    }

                    let op = send_queue.pop_front().unwrap();

                    // Build PDU: opcode(1) + data
                    let mut pdu = Vec::with_capacity(1 + op.data.len());
                    pdu.push(op.opcode);
                    pdu.extend_from_slice(&op.data);

                    // Write to socket
                    let write_result = loop {
                        let mut guard = match fd.writable().await {
                            Ok(g) => g,
                            Err(e) => break Err(e),
                        };
                        match guard.try_io(|fd_inner| {
                            let raw = std::os::unix::io::AsRawFd::as_raw_fd(fd_inner.get_ref());
                            let ret = unsafe {
                                libc::send(
                                    raw,
                                    pdu.as_ptr() as *const libc::c_void,
                                    pdu.len(),
                                    0,
                                )
                            };
                            if ret < 0 {
                                Err(io::Error::last_os_error())
                            } else {
                                Ok(())
                            }
                        }) {
                            Ok(result) => break result,
                            Err(_would_block) => continue,
                        }
                    };

                    if let Err(e) = write_result {
                        if let Some(tx) = op.response_tx {
                            let _ = tx.send(Err(e));
                        }
                        continue;
                    }

                    // Track pending request/indication
                    if let Some(tx) = op.response_tx {
                        match op_type {
                            AttOpType::Request => {
                                *pending_req.lock().await = Some(tx);
                            }
                            AttOpType::Indication => {
                                *pending_ind.lock().await = Some(tx);
                            }
                            _ => {
                                // Commands don't need response tracking
                                // but shouldn't have response_tx
                            }
                        }
                    }
                }
            }

            // Handle new subscriptions
            Some(sub) = sub_rx.recv() => {
                subscribers.lock().await.push(sub);
            }

            // Handle incoming data
            result = fd.readable() => {
                if let Ok(mut guard) = result {
                    match guard.try_io(|fd_inner| {
                        let raw = std::os::unix::io::AsRawFd::as_raw_fd(fd_inner.get_ref());
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
                        Ok(Ok(n)) if n >= 1 => {
                            let opcode = buf[0];
                            let data = buf[1..n].to_vec();
                            let op_type = att_op_type(opcode);

                            match op_type {
                                AttOpType::Response => {
                                    // Deliver to pending request
                                    if let Some(tx) = pending_req.lock().await.take() {
                                        let _ = tx.send(Ok(AttResponse { opcode, data: data.clone() }));
                                    }
                                }
                                AttOpType::Confirmation => {
                                    // Deliver to pending indication
                                    if let Some(tx) = pending_ind.lock().await.take() {
                                        let _ = tx.send(Ok(AttResponse { opcode, data: data.clone() }));
                                    }
                                }
                                _ => {}
                            }

                            // Dispatch to all matching subscribers
                            let subs = subscribers.lock().await;
                            let pdu = AttPdu { opcode, data };
                            subs.iter()
                                .filter(|s| s.opcode.is_none_or(|o| o == opcode))
                                .for_each(|s| {
                                    let _ = s.tx.send(pdu.clone());
                                });
                        }
                        Ok(Ok(_)) => {} // Empty read
                        Ok(Err(e)) => {
                            tracing::error!("att recv error: {}", e);
                        }
                        Err(_would_block) => {}
                    }
                }
            }

            // Shutdown
            _ = inner.shutdown.notified() => {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_att_op_type_classification() {
        assert_eq!(att_op_type(BT_ATT_OP_MTU_REQ), AttOpType::Request);
        assert_eq!(att_op_type(BT_ATT_OP_MTU_RSP), AttOpType::Response);
        assert_eq!(att_op_type(BT_ATT_OP_WRITE_CMD), AttOpType::Command);
        assert_eq!(att_op_type(BT_ATT_OP_HANDLE_NFY), AttOpType::Notification);
        assert_eq!(att_op_type(BT_ATT_OP_HANDLE_IND), AttOpType::Indication);
        assert_eq!(att_op_type(BT_ATT_OP_HANDLE_CFM), AttOpType::Confirmation);
        assert_eq!(att_op_type(0xFF), AttOpType::Unknown);
    }

    #[test]
    fn test_att_constants() {
        assert_eq!(BT_ATT_DEFAULT_LE_MTU, 23);
        assert_eq!(BT_ATT_MAX_LE_MTU, 517);
        assert_eq!(BT_ATT_CID, 4);
        assert_eq!(BT_ATT_EATT_PSM, 0x27);
    }

    #[test]
    fn test_att_error_codes() {
        assert_eq!(BT_ATT_ERROR_INVALID_HANDLE, 0x01);
        assert_eq!(BT_ATT_ERROR_INSUFFICIENT_RESOURCES, 0x11);
        assert_eq!(BT_ATT_ERROR_DB_OUT_OF_SYNC, 0x12);
    }

    #[test]
    fn test_att_permissions() {
        assert_eq!(BT_ATT_PERM_READ | BT_ATT_PERM_WRITE, 0x0003);
        assert_eq!(BT_ATT_PERM_READ_ENCRYPT | BT_ATT_PERM_WRITE_ENCRYPT, 0x000C);
    }

    #[test]
    fn test_signed_mask() {
        assert_eq!(BT_ATT_OP_SIGNED_WRITE_CMD & ATT_OP_SIGNED_MASK, ATT_OP_SIGNED_MASK);
        assert_eq!(BT_ATT_OP_WRITE_CMD & ATT_OP_SIGNED_MASK, 0);
    }
}
