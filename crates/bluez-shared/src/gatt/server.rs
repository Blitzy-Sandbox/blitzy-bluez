// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT server replacing src/shared/gatt-server.c
//
// Handles incoming ATT requests by looking up attributes in a GattDb and
// responding. Registers handlers for all standard ATT request opcodes.
//
// C's callback-based ATT handler registration is replaced by an async task
// that processes incoming PDUs from the ATT layer.

use std::io;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use tokio::sync::{Mutex, Notify};

use crate::att::{
    AttPdu, BtAtt, BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND, BT_ATT_ERROR_INVALID_HANDLE,
    BT_ATT_ERROR_INVALID_OFFSET, BT_ATT_ERROR_INVALID_PDU,
    BT_ATT_ERROR_PREPARE_QUEUE_FULL, BT_ATT_ERROR_READ_NOT_PERMITTED,
    BT_ATT_ERROR_WRITE_NOT_PERMITTED, BT_ATT_OP_ERROR_RSP, BT_ATT_OP_EXEC_WRITE_REQ,
    BT_ATT_OP_EXEC_WRITE_RSP, BT_ATT_OP_FIND_BY_TYPE_REQ, BT_ATT_OP_FIND_BY_TYPE_RSP,
    BT_ATT_OP_FIND_INFO_REQ, BT_ATT_OP_FIND_INFO_RSP,
    BT_ATT_OP_HANDLE_IND, BT_ATT_OP_HANDLE_NFY, BT_ATT_OP_MTU_REQ, BT_ATT_OP_MTU_RSP,
    BT_ATT_OP_PREP_WRITE_REQ, BT_ATT_OP_PREP_WRITE_RSP, BT_ATT_OP_READ_BLOB_REQ,
    BT_ATT_OP_READ_BLOB_RSP, BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
    BT_ATT_OP_READ_BY_GRP_TYPE_RSP, BT_ATT_OP_READ_BY_TYPE_REQ,
    BT_ATT_OP_READ_BY_TYPE_RSP, BT_ATT_OP_READ_REQ, BT_ATT_OP_READ_RSP,
    BT_ATT_OP_WRITE_CMD, BT_ATT_OP_WRITE_REQ, BT_ATT_OP_WRITE_RSP,
    BT_ATT_PERM_READ, BT_ATT_PERM_WRITE,
};
use crate::uuid::Uuid;

use super::db::GattDb;

/// Default maximum prepare write queue length.
const DEFAULT_MAX_PREP_QUEUE_LEN: usize = 30;

/// Prepared write entry.
#[derive(Debug, Clone)]
struct PrepWrite {
    handle: u16,
    offset: u16,
    value: Vec<u8>,
}

/// GATT server.
///
/// Replaces C's `struct bt_gatt_server`. Handles incoming ATT requests
/// by looking up attributes in the GATT database.
///
/// ```ignore
/// let server = GattServer::new(att, db, 23);
/// ```
pub struct GattServer {
    inner: Arc<GattServerInner>,
}

struct GattServerInner {
    att: Arc<BtAtt>,
    db: GattDb,
    mtu: AtomicU16,
    prep_queue: Mutex<Vec<PrepWrite>>,
    max_prep_queue_len: usize,
    shutdown: Notify,
}

impl GattServer {
    /// Create a new GATT server.
    ///
    /// Spawns an internal task that handles incoming ATT requests.
    pub fn new(att: Arc<BtAtt>, db: GattDb, mtu: u16) -> Self {
        let inner = Arc::new(GattServerInner {
            att,
            db,
            mtu: AtomicU16::new(mtu),
            prep_queue: Mutex::new(Vec::new()),
            max_prep_queue_len: DEFAULT_MAX_PREP_QUEUE_LEN,
            shutdown: Notify::new(),
        });

        // Spawn the request handler task
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            server_task(inner_clone).await;
        });

        Self { inner }
    }

    /// Get the current MTU.
    pub fn mtu(&self) -> u16 {
        self.inner.mtu.load(Ordering::Relaxed)
    }

    /// Set the MTU.
    pub fn set_mtu(&self, mtu: u16) {
        self.inner.mtu.store(mtu, Ordering::Relaxed);
    }

    /// Send a notification to the client.
    pub fn send_notification(
        &self,
        handle: u16,
        value: &[u8],
    ) -> Result<(), io::Error> {
        let mut pdu = Vec::with_capacity(2 + value.len());
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(value);

        self.inner.att.send_command(BT_ATT_OP_HANDLE_NFY, &pdu)
    }

    /// Send an indication to the client (waits for confirmation).
    pub async fn send_indication(
        &self,
        handle: u16,
        value: &[u8],
    ) -> Result<(), io::Error> {
        let mut pdu = Vec::with_capacity(2 + value.len());
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(value);

        self.inner.att.send_request(BT_ATT_OP_HANDLE_IND, &pdu).await?;
        Ok(())
    }

    /// Get a reference to the ATT transport.
    pub fn att(&self) -> &Arc<BtAtt> {
        &self.inner.att
    }

    /// Get a reference to the GATT database.
    pub fn db(&self) -> &GattDb {
        &self.inner.db
    }

    /// Shut down the server.
    pub fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
    }
}

impl Clone for GattServer {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Internal task that handles incoming ATT requests.
async fn server_task(inner: Arc<GattServerInner>) {
    // Subscribe to all incoming PDUs (None = all opcodes)
    let mut all_rx = match inner.att.subscribe(None) {
        Ok(r) => r,
        Err(_) => return,
    };

    loop {
        tokio::select! {
            Some(pdu) = all_rx.rx.recv() => {
                handle_request(&inner, &pdu).await;
            }
            _ = inner.shutdown.notified() => {
                break;
            }
            else => break,
        }
    }
}

/// Route an incoming ATT PDU to the appropriate handler.
async fn handle_request(inner: &GattServerInner, pdu: &AttPdu) {
    match pdu.opcode {
        BT_ATT_OP_MTU_REQ => handle_mtu_req(inner, &pdu.data).await,
        BT_ATT_OP_READ_BY_GRP_TYPE_REQ => handle_read_by_grp_type(inner, &pdu.data).await,
        BT_ATT_OP_READ_BY_TYPE_REQ => handle_read_by_type(inner, &pdu.data).await,
        BT_ATT_OP_FIND_INFO_REQ => handle_find_info(inner, &pdu.data).await,
        BT_ATT_OP_FIND_BY_TYPE_REQ => handle_find_by_type(inner, &pdu.data).await,
        BT_ATT_OP_READ_REQ => handle_read(inner, &pdu.data).await,
        BT_ATT_OP_READ_BLOB_REQ => handle_read_blob(inner, &pdu.data).await,
        BT_ATT_OP_WRITE_REQ => handle_write(inner, &pdu.data, true).await,
        BT_ATT_OP_WRITE_CMD => handle_write(inner, &pdu.data, false).await,
        BT_ATT_OP_PREP_WRITE_REQ => handle_prep_write(inner, &pdu.data).await,
        BT_ATT_OP_EXEC_WRITE_REQ => handle_exec_write(inner, &pdu.data).await,
        _ => {} // Ignore unknown opcodes
    }
}

/// Build an ATT error response.
fn error_rsp(req_opcode: u8, handle: u16, error: u8) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(4);
    pdu.push(req_opcode);
    pdu.extend_from_slice(&handle.to_le_bytes());
    pdu.push(error);
    pdu
}

/// Handle Exchange MTU Request.
async fn handle_mtu_req(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 2 {
        let _ = inner
            .att
            .send_command(BT_ATT_OP_ERROR_RSP, &error_rsp(BT_ATT_OP_MTU_REQ, 0, BT_ATT_ERROR_INVALID_PDU));
        return;
    }

    let client_mtu = u16::from_le_bytes([data[0], data[1]]);
    let server_mtu = inner.mtu.load(Ordering::Relaxed);
    let agreed_mtu = client_mtu.min(server_mtu).max(23);
    inner.mtu.store(agreed_mtu, Ordering::Relaxed);

    let mut rsp = Vec::with_capacity(2);
    rsp.extend_from_slice(&server_mtu.to_le_bytes());
    let _ = inner.att.send_command(BT_ATT_OP_MTU_RSP, &rsp);
}

/// Handle Read By Group Type Request.
async fn handle_read_by_grp_type(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 6 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_BY_GRP_TYPE_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let start = u16::from_le_bytes([data[0], data[1]]);
    let end = u16::from_le_bytes([data[2], data[3]]);
    let uuid = parse_uuid_from_pdu(&data[4..]);

    if start == 0 || start > end {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_BY_GRP_TYPE_REQ, start, BT_ATT_ERROR_INVALID_HANDLE),
        );
        return;
    }

    let results = inner.db.read_by_group_type(start, end, uuid).await;

    if results.is_empty() {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(
                BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
                start,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            ),
        );
        return;
    }

    // Build response: item_len(1) + items (handle(2) + end_handle(2) + uuid(2 or 16))
    let first_uuid_len = match results[0].2 {
        Uuid::Uuid16(_) => 2,
        Uuid::Uuid32(_) => 4,
        Uuid::Uuid128(_) => 16,
    };
    let item_len = 4 + first_uuid_len;
    let mtu = inner.mtu.load(Ordering::Relaxed) as usize;

    let mut rsp = Vec::with_capacity(mtu);
    rsp.push(item_len as u8);

    for (svc_start, svc_end, svc_uuid) in &results {
        if rsp.len() + item_len > mtu {
            break;
        }
        rsp.extend_from_slice(&svc_start.to_le_bytes());
        rsp.extend_from_slice(&svc_end.to_le_bytes());
        append_uuid_le(&mut rsp, svc_uuid);
    }

    let _ = inner
        .att
        .send_command(BT_ATT_OP_READ_BY_GRP_TYPE_RSP, &rsp);
}

/// Handle Read By Type Request.
async fn handle_read_by_type(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 6 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_BY_TYPE_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let start = u16::from_le_bytes([data[0], data[1]]);
    let end = u16::from_le_bytes([data[2], data[3]]);
    let uuid = parse_uuid_from_pdu(&data[4..]);

    if start == 0 || start > end {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_BY_TYPE_REQ, start, BT_ATT_ERROR_INVALID_HANDLE),
        );
        return;
    }

    let results = inner.db.read_by_type(start, end, uuid).await;

    if results.is_empty() {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(
                BT_ATT_OP_READ_BY_TYPE_REQ,
                start,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            ),
        );
        return;
    }

    // All items must have the same length
    let first_len = results[0].1.len();
    let item_len = 2 + first_len;
    let mtu = inner.mtu.load(Ordering::Relaxed) as usize;

    let mut rsp = Vec::with_capacity(mtu);
    rsp.push(item_len as u8);

    for (handle, value) in &results {
        if value.len() != first_len {
            break; // Different length, stop here
        }
        if rsp.len() + item_len > mtu {
            break;
        }
        rsp.extend_from_slice(&handle.to_le_bytes());
        rsp.extend_from_slice(value);
    }

    let _ = inner
        .att
        .send_command(BT_ATT_OP_READ_BY_TYPE_RSP, &rsp);
}

/// Handle Find Information Request.
async fn handle_find_info(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 4 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_FIND_INFO_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let start = u16::from_le_bytes([data[0], data[1]]);
    let end = u16::from_le_bytes([data[2], data[3]]);

    if start == 0 || start > end {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_FIND_INFO_REQ, start, BT_ATT_ERROR_INVALID_HANDLE),
        );
        return;
    }

    let results = inner.db.find_information(start, end).await;

    if results.is_empty() {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(
                BT_ATT_OP_FIND_INFO_REQ,
                start,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            ),
        );
        return;
    }

    // Determine format based on first UUID
    let (format, uuid_len) = match results[0].1 {
        Uuid::Uuid16(_) => (0x01u8, 2usize),
        _ => (0x02, 16),
    };

    let item_len = 2 + uuid_len;
    let mtu = inner.mtu.load(Ordering::Relaxed) as usize;

    let mut rsp = Vec::with_capacity(mtu);
    rsp.push(format);

    for (handle, uuid) in &results {
        // All items must have the same UUID format
        let this_uuid_len = match uuid {
            Uuid::Uuid16(_) => 2,
            _ => 16,
        };
        if this_uuid_len != uuid_len {
            break;
        }
        if rsp.len() + item_len > mtu {
            break;
        }
        rsp.extend_from_slice(&handle.to_le_bytes());
        append_uuid_le(&mut rsp, uuid);
    }

    let _ = inner.att.send_command(BT_ATT_OP_FIND_INFO_RSP, &rsp);
}

/// Handle Find By Type Value Request.
async fn handle_find_by_type(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 6 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_FIND_BY_TYPE_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let start = u16::from_le_bytes([data[0], data[1]]);
    let end = u16::from_le_bytes([data[2], data[3]]);
    let uuid = Uuid::from_u16(u16::from_le_bytes([data[4], data[5]]));
    let value = &data[6..];

    let results = inner.db.find_by_type_value(start, end, uuid, value).await;

    if results.is_empty() {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(
                BT_ATT_OP_FIND_BY_TYPE_REQ,
                start,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            ),
        );
        return;
    }

    let mut rsp = Vec::new();
    for (found_start, found_end) in &results {
        rsp.extend_from_slice(&found_start.to_le_bytes());
        rsp.extend_from_slice(&found_end.to_le_bytes());
    }

    let _ = inner
        .att
        .send_command(BT_ATT_OP_FIND_BY_TYPE_RSP, &rsp);
}

/// Handle Read Request.
async fn handle_read(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 2 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let handle = u16::from_le_bytes([data[0], data[1]]);

    // Check permissions
    let attr = match inner.db.get_attribute(handle).await {
        Some(a) => a,
        None => {
            let _ = inner.att.send_command(
                BT_ATT_OP_ERROR_RSP,
                &error_rsp(BT_ATT_OP_READ_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE),
            );
            return;
        }
    };

    if attr.permissions != 0 && (attr.permissions as u16 & BT_ATT_PERM_READ) == 0 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_REQ, handle, BT_ATT_ERROR_READ_NOT_PERMITTED),
        );
        return;
    }

    let value = inner.db.attribute_read(handle, 0).await.unwrap_or_default();

    // Truncate to MTU-1
    let mtu = inner.mtu.load(Ordering::Relaxed) as usize;
    let max_len = mtu.saturating_sub(1);
    let rsp_value = if value.len() > max_len {
        &value[..max_len]
    } else {
        &value
    };

    let _ = inner.att.send_command(BT_ATT_OP_READ_RSP, rsp_value);
}

/// Handle Read Blob Request.
async fn handle_read_blob(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 4 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_BLOB_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let handle = u16::from_le_bytes([data[0], data[1]]);
    let offset = u16::from_le_bytes([data[2], data[3]]);

    let attr = match inner.db.get_attribute(handle).await {
        Some(a) => a,
        None => {
            let _ = inner.att.send_command(
                BT_ATT_OP_ERROR_RSP,
                &error_rsp(BT_ATT_OP_READ_BLOB_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE),
            );
            return;
        }
    };

    if attr.permissions != 0 && (attr.permissions as u16 & BT_ATT_PERM_READ) == 0 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_BLOB_REQ, handle, BT_ATT_ERROR_READ_NOT_PERMITTED),
        );
        return;
    }

    if offset as usize > attr.value.len() {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_READ_BLOB_REQ, handle, BT_ATT_ERROR_INVALID_OFFSET),
        );
        return;
    }

    let value = &attr.value[offset as usize..];
    let mtu = inner.mtu.load(Ordering::Relaxed) as usize;
    let max_len = mtu.saturating_sub(1);
    let rsp_value = if value.len() > max_len {
        &value[..max_len]
    } else {
        value
    };

    let _ = inner.att.send_command(BT_ATT_OP_READ_BLOB_RSP, rsp_value);
}

/// Handle Write Request / Write Command.
async fn handle_write(inner: &GattServerInner, data: &[u8], needs_response: bool) {
    let req_opcode = if needs_response {
        BT_ATT_OP_WRITE_REQ
    } else {
        BT_ATT_OP_WRITE_CMD
    };

    if data.len() < 2 {
        if needs_response {
            let _ = inner.att.send_command(
                BT_ATT_OP_ERROR_RSP,
                &error_rsp(req_opcode, 0, BT_ATT_ERROR_INVALID_PDU),
            );
        }
        return;
    }

    let handle = u16::from_le_bytes([data[0], data[1]]);
    let value = &data[2..];

    let attr = match inner.db.get_attribute(handle).await {
        Some(a) => a,
        None => {
            if needs_response {
                let _ = inner.att.send_command(
                    BT_ATT_OP_ERROR_RSP,
                    &error_rsp(req_opcode, handle, BT_ATT_ERROR_INVALID_HANDLE),
                );
            }
            return;
        }
    };

    if attr.permissions != 0 && (attr.permissions as u16 & BT_ATT_PERM_WRITE) == 0 {
        if needs_response {
            let _ = inner.att.send_command(
                BT_ATT_OP_ERROR_RSP,
                &error_rsp(req_opcode, handle, BT_ATT_ERROR_WRITE_NOT_PERMITTED),
            );
        }
        return;
    }

    inner.db.attribute_write(handle, 0, value).await;

    if needs_response {
        let _ = inner.att.send_command(BT_ATT_OP_WRITE_RSP, &[]);
    }
}

/// Handle Prepare Write Request.
async fn handle_prep_write(inner: &GattServerInner, data: &[u8]) {
    if data.len() < 4 {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_PREP_WRITE_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let handle = u16::from_le_bytes([data[0], data[1]]);
    let offset = u16::from_le_bytes([data[2], data[3]]);
    let value = data[4..].to_vec();

    // Check handle exists
    if inner.db.get_attribute(handle).await.is_none() {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_PREP_WRITE_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE),
        );
        return;
    }

    let mut queue = inner.prep_queue.lock().await;
    if queue.len() >= inner.max_prep_queue_len {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_PREP_WRITE_REQ, handle, BT_ATT_ERROR_PREPARE_QUEUE_FULL),
        );
        return;
    }

    queue.push(PrepWrite {
        handle,
        offset,
        value: value.clone(),
    });

    // Response echoes the request
    let _ = inner.att.send_command(BT_ATT_OP_PREP_WRITE_RSP, data);
}

/// Handle Execute Write Request.
async fn handle_exec_write(inner: &GattServerInner, data: &[u8]) {
    if data.is_empty() {
        let _ = inner.att.send_command(
            BT_ATT_OP_ERROR_RSP,
            &error_rsp(BT_ATT_OP_EXEC_WRITE_REQ, 0, BT_ATT_ERROR_INVALID_PDU),
        );
        return;
    }

    let flags = data[0];
    let mut queue = inner.prep_queue.lock().await;

    if flags == 0x01 {
        // Execute all prepared writes
        let writes: Vec<PrepWrite> = queue.drain(..).collect();
        drop(queue);

        for pw in writes {
            inner.db.attribute_write(pw.handle, pw.offset, &pw.value).await;
        }
    } else {
        // Cancel all prepared writes
        queue.clear();
    }

    let _ = inner.att.send_command(BT_ATT_OP_EXEC_WRITE_RSP, &[]);
}

/// Parse a UUID from an ATT PDU (2 or 16 bytes, little-endian).
fn parse_uuid_from_pdu(data: &[u8]) -> Uuid {
    match data.len() {
        2 => Uuid::from_u16(u16::from_le_bytes([data[0], data[1]])),
        4 => Uuid::from_u32(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        n if n >= 16 => {
            let mut be = [0u8; 16];
            be.copy_from_slice(&data[..16]);
            be.reverse();
            Uuid::from_u128_bytes(be)
        }
        _ => Uuid::from_u16(0),
    }
}

/// Append a UUID in little-endian format to a buffer.
fn append_uuid_le(buf: &mut Vec<u8>, uuid: &Uuid) {
    match uuid {
        Uuid::Uuid16(v) => buf.extend_from_slice(&v.to_le_bytes()),
        Uuid::Uuid32(v) => buf.extend_from_slice(&v.to_le_bytes()),
        Uuid::Uuid128(bytes) => {
            let mut le = *bytes;
            le.reverse();
            buf.extend_from_slice(&le);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt::GATT_PRIM_SVC_UUID;

    #[test]
    fn test_parse_uuid_from_pdu_16() {
        let uuid = parse_uuid_from_pdu(&[0x00, 0x28]);
        assert_eq!(uuid, Uuid::from_u16(GATT_PRIM_SVC_UUID));
    }

    #[test]
    fn test_parse_uuid_from_pdu_128() {
        let le_bytes = [
            0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x28,
            0x00, 0x00,
        ];
        let uuid = parse_uuid_from_pdu(&le_bytes);
        let expected = Uuid::from_u16(GATT_PRIM_SVC_UUID).to_uuid128();
        assert_eq!(uuid.to_uuid128(), expected);
    }

    #[test]
    fn test_error_rsp() {
        let rsp = error_rsp(BT_ATT_OP_READ_REQ, 0x0003, BT_ATT_ERROR_INVALID_HANDLE);
        assert_eq!(rsp.len(), 4);
        assert_eq!(rsp[0], BT_ATT_OP_READ_REQ);
        assert_eq!(u16::from_le_bytes([rsp[1], rsp[2]]), 0x0003);
        assert_eq!(rsp[3], BT_ATT_ERROR_INVALID_HANDLE);
    }

    #[test]
    fn test_append_uuid_le_16() {
        let mut buf = Vec::new();
        append_uuid_le(&mut buf, &Uuid::from_u16(0x2800));
        assert_eq!(buf, vec![0x00, 0x28]);
    }

    #[test]
    fn test_prep_write_clone() {
        let pw = PrepWrite {
            handle: 5,
            offset: 0,
            value: vec![1, 2, 3],
        };
        let pw2 = pw.clone();
        assert_eq!(pw.handle, pw2.handle);
        assert_eq!(pw.value, pw2.value);
    }
}
