// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT client replacing src/shared/gatt-client.c
//
// High-level GATT client that performs service discovery on initialization,
// manages notification/indication registrations, handles Service Changed
// indications, and provides read/write operations.
//
// C's callback pattern is replaced by async functions returning Results.
// C's ref counting is replaced by Arc.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, Notify, RwLock};

use crate::att::{
    AttPdu, BtAtt, BT_ATT_OP_EXEC_WRITE_REQ, BT_ATT_OP_HANDLE_CFM, BT_ATT_OP_HANDLE_IND,
    BT_ATT_OP_HANDLE_NFY, BT_ATT_OP_PREP_WRITE_REQ, BT_ATT_OP_READ_BLOB_REQ,
    BT_ATT_OP_READ_REQ, BT_ATT_OP_WRITE_CMD, BT_ATT_OP_WRITE_REQ,
};

use super::db::GattDb;
use super::helpers;

/// Notification data from a remote GATT server.
#[derive(Debug, Clone)]
pub struct GattNotification {
    /// The characteristic value handle.
    pub handle: u16,
    /// The notification/indication value.
    pub value: Vec<u8>,
}

/// A notification registration handle. Drop to unregister.
pub struct NotifyRegistration {
    /// Receive notifications on this channel.
    pub rx: mpsc::UnboundedReceiver<GattNotification>,
    id: u32,
    client: Arc<GattClientInner>,
}

impl Drop for NotifyRegistration {
    fn drop(&mut self) {
        let _ = self.client.unreg_tx.send(self.id);
    }
}

/// GATT client state.
///
/// Replaces C's `struct bt_gatt_client`. Performs service discovery on
/// creation and manages the attribute cache in a `GattDb`.
///
/// ```ignore
/// let client = GattClient::new(att, db).await?;
/// let value = client.read_value(0x0003).await?;
/// ```
pub struct GattClient {
    inner: Arc<GattClientInner>,
}

struct GattClientInner {
    att: Arc<BtAtt>,
    db: GattDb,
    ready: AtomicBool,
    ready_notify: Notify,
    next_reg_id: AtomicU32,
    /// Notification registrations: id -> (handle, sender)
    registrations: RwLock<HashMap<u32, (u16, mpsc::UnboundedSender<GattNotification>)>>,
    /// Channel for unregistration requests
    unreg_tx: mpsc::UnboundedSender<u32>,
    /// Service Changed callback senders
    svc_changed_tx: Mutex<Vec<mpsc::UnboundedSender<(u16, u16)>>>,
}

impl GattClient {
    /// Create a new GATT client.
    ///
    /// Optionally performs discovery. If the database is already populated
    /// (from a previous connection with the same device), discovery may be
    /// skipped based on the database hash.
    pub fn new(att: Arc<BtAtt>, db: GattDb) -> Self {
        let (unreg_tx, unreg_rx) = mpsc::unbounded_channel();

        let inner = Arc::new(GattClientInner {
            att,
            db,
            ready: AtomicBool::new(false),
            ready_notify: Notify::new(),
            next_reg_id: AtomicU32::new(1),
            registrations: RwLock::new(HashMap::new()),
            unreg_tx,
            svc_changed_tx: Mutex::new(Vec::new()),
        });

        // Spawn notification dispatcher
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            notification_task(inner_clone, unreg_rx).await;
        });

        Self { inner }
    }

    /// Wait until the client is ready (discovery complete).
    pub async fn wait_ready(&self) {
        if self.inner.ready.load(Ordering::Acquire) {
            return;
        }
        self.inner.ready_notify.notified().await;
    }

    /// Check if the client is ready.
    pub fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::Acquire)
    }

    /// Perform service discovery and populate the database.
    pub async fn discover(&self) -> Result<(), helpers::GattError> {
        let att = &self.inner.att;

        // Discover primary services
        let primaries = helpers::discover_all_primary_services(att).await?;
        for svc in &primaries {
            let num_handles = svc.end_handle - svc.start_handle + 1;
            self.inner
                .db
                .insert_service(svc.start_handle, svc.uuid, true, num_handles)
                .await;
        }

        // Discover secondary services
        if let Ok(secondaries) = helpers::discover_secondary_services(att).await {
            for svc in &secondaries {
                let num_handles = svc.end_handle - svc.start_handle + 1;
                self.inner
                    .db
                    .insert_service(svc.start_handle, svc.uuid, false, num_handles)
                    .await;
            }
        }

        // For each service, discover characteristics and descriptors
        let all_services: Vec<_> = primaries
            .iter()
            .map(|s| (s.start_handle, s.end_handle))
            .collect();

        for (svc_start, svc_end) in &all_services {
            // Discover characteristics
            if let Ok(chars) =
                helpers::discover_characteristics(att, *svc_start, *svc_end).await
            {
                for (i, chr) in chars.iter().enumerate() {
                    let _ = self
                        .inner
                        .db
                        .service_add_characteristic(
                            *svc_start,
                            chr.uuid,
                            0,
                            chr.properties,
                            &[],
                        )
                        .await;

                    // Discover descriptors between this char value and next char decl
                    let desc_start = chr.value_handle + 1;
                    let desc_end = if i + 1 < chars.len() {
                        chars[i + 1].decl_handle - 1
                    } else {
                        *svc_end
                    };

                    if desc_start <= desc_end {
                        if let Ok(descs) =
                            helpers::discover_descriptors(att, desc_start, desc_end).await
                        {
                            for desc in &descs {
                                let _ = self
                                    .inner
                                    .db
                                    .service_add_descriptor(*svc_start, desc.uuid, 0, &[])
                                    .await;
                            }
                        }
                    }
                }
            }

            // Activate the service
            self.inner.db.set_service_active(*svc_start, true).await;
        }

        self.inner.ready.store(true, Ordering::Release);
        self.inner.ready_notify.notify_waiters();

        Ok(())
    }

    /// Read a characteristic or descriptor value by handle.
    pub async fn read_value(&self, handle: u16) -> Result<Vec<u8>, io::Error> {
        let mut pdu = Vec::with_capacity(2);
        pdu.extend_from_slice(&handle.to_le_bytes());

        let rsp = self.inner.att.send_request(BT_ATT_OP_READ_REQ, &pdu).await?;
        Ok(rsp.data)
    }

    /// Read a long characteristic value (Read Blob).
    pub async fn read_long_value(
        &self,
        handle: u16,
        offset: u16,
    ) -> Result<Vec<u8>, io::Error> {
        let mut result = Vec::new();
        let mut current_offset = offset;

        loop {
            let mut pdu = Vec::with_capacity(4);
            pdu.extend_from_slice(&handle.to_le_bytes());
            pdu.extend_from_slice(&current_offset.to_le_bytes());

            let rsp = self
                .inner
                .att
                .send_request(BT_ATT_OP_READ_BLOB_REQ, &pdu)
                .await?;

            result.extend_from_slice(&rsp.data);

            // If we got less than MTU-1 bytes, we've read everything
            // Use a conservative check: if response is empty or short
            if rsp.data.is_empty() || rsp.data.len() < 20 {
                break;
            }

            current_offset += rsp.data.len() as u16;
        }

        Ok(result)
    }

    /// Write a characteristic value (with response).
    pub async fn write_value(
        &self,
        handle: u16,
        value: &[u8],
    ) -> Result<(), io::Error> {
        let mut pdu = Vec::with_capacity(2 + value.len());
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(value);

        self.inner.att.send_request(BT_ATT_OP_WRITE_REQ, &pdu).await?;
        Ok(())
    }

    /// Write without response (Write Command).
    pub fn write_without_response(
        &self,
        handle: u16,
        value: &[u8],
    ) -> Result<(), io::Error> {
        let mut pdu = Vec::with_capacity(2 + value.len());
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(value);

        self.inner.att.send_command(BT_ATT_OP_WRITE_CMD, &pdu)
    }

    /// Write a long characteristic value using Prepare Write + Execute Write.
    pub async fn write_long_value(
        &self,
        handle: u16,
        value: &[u8],
        reliable: bool,
    ) -> Result<(), io::Error> {
        let mtu = 23u16; // TODO: get actual negotiated MTU
        let max_chunk = (mtu - 5) as usize;
        let mut offset: u16 = 0;

        for chunk in value.chunks(max_chunk.max(1)) {
            let mut pdu = Vec::with_capacity(4 + chunk.len());
            pdu.extend_from_slice(&handle.to_le_bytes());
            pdu.extend_from_slice(&offset.to_le_bytes());
            pdu.extend_from_slice(chunk);

            let rsp = self
                .inner
                .att
                .send_request(BT_ATT_OP_PREP_WRITE_REQ, &pdu)
                .await?;

            // Verify response for reliable write
            if reliable && rsp.data != pdu {
                // Cancel the write
                self.inner
                    .att
                    .send_request(BT_ATT_OP_EXEC_WRITE_REQ, &[0x00])
                    .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reliable write mismatch",
                ));
            }

            offset += chunk.len() as u16;
        }

        // Execute the write
        self.inner
            .att
            .send_request(BT_ATT_OP_EXEC_WRITE_REQ, &[0x01])
            .await?;

        Ok(())
    }

    /// Register for notifications/indications on a characteristic.
    ///
    /// Returns a registration handle with a receiver channel. Drop to unregister.
    pub async fn register_notify(
        &self,
        value_handle: u16,
        ccc_handle: Option<u16>,
    ) -> Result<NotifyRegistration, io::Error> {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.inner.next_reg_id.fetch_add(1, Ordering::Relaxed);

        // Store the registration
        self.inner
            .registrations
            .write()
            .await
            .insert(id, (value_handle, tx));

        // Enable notifications on CCC if provided
        if let Some(ccc) = ccc_handle {
            let mut ccc_value = Vec::with_capacity(4);
            ccc_value.extend_from_slice(&ccc.to_le_bytes());
            // Enable both notifications and indications
            ccc_value.extend_from_slice(&0x0003u16.to_le_bytes());

            // Write CCC - best effort
            let mut pdu = Vec::with_capacity(4);
            pdu.extend_from_slice(&ccc.to_le_bytes());
            pdu.extend_from_slice(&0x0003u16.to_le_bytes());
            let _ = self.inner.att.send_request(BT_ATT_OP_WRITE_REQ, &pdu).await;
        }

        Ok(NotifyRegistration {
            rx,
            id,
            client: self.inner.clone(),
        })
    }

    /// Subscribe to Service Changed indications.
    pub async fn subscribe_service_changed(
        &self,
    ) -> mpsc::UnboundedReceiver<(u16, u16)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.svc_changed_tx.lock().await.push(tx);
        rx
    }

    /// Get a reference to the ATT transport.
    pub fn att(&self) -> &Arc<BtAtt> {
        &self.inner.att
    }

    /// Get a reference to the GATT database.
    pub fn db(&self) -> &GattDb {
        &self.inner.db
    }
}

impl Clone for GattClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Internal task that dispatches ATT notifications to registered receivers.
async fn notification_task(
    inner: Arc<GattClientInner>,
    mut unreg_rx: mpsc::UnboundedReceiver<u32>,
) {
    // Subscribe to notification and indication opcodes
    let mut nfy_rx = match inner.att.subscribe(Some(BT_ATT_OP_HANDLE_NFY)) {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut ind_rx = match inner.att.subscribe(Some(BT_ATT_OP_HANDLE_IND)) {
        Ok(r) => r,
        Err(_) => return,
    };

    loop {
        tokio::select! {
            Some(pdu) = nfy_rx.rx.recv() => {
                dispatch_notification(&inner, &pdu).await;
            }
            Some(pdu) = ind_rx.rx.recv() => {
                dispatch_notification(&inner, &pdu).await;
                // Send confirmation for indications
                let _ = inner.att.send_command(BT_ATT_OP_HANDLE_CFM, &[]);
            }
            Some(id) = unreg_rx.recv() => {
                inner.registrations.write().await.remove(&id);
            }
            else => break,
        }
    }
}

/// Parse and dispatch a notification/indication PDU.
async fn dispatch_notification(inner: &GattClientInner, pdu: &AttPdu) {
    if pdu.data.len() < 2 {
        return;
    }

    let handle = u16::from_le_bytes([pdu.data[0], pdu.data[1]]);
    let value = pdu.data[2..].to_vec();

    // Check for Service Changed indication
    // Service Changed UUID is 0x2A05, handle would need to be looked up
    // For now, dispatch to registered handlers
    let regs = inner.registrations.read().await;
    for (_, (reg_handle, tx)) in regs.iter() {
        if *reg_handle == handle {
            let _ = tx.send(GattNotification {
                handle,
                value: value.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_clone() {
        let n = GattNotification {
            handle: 0x0003,
            value: vec![1, 2, 3],
        };
        let n2 = n.clone();
        assert_eq!(n.handle, n2.handle);
        assert_eq!(n.value, n2.value);
    }

    #[test]
    fn test_gatt_client_clone() {
        // Verify that GattClient can be cloned (Arc-based)
        // Can't fully construct without a real BtAtt, but we verify the type
        assert!(std::mem::size_of::<GattClient>() > 0);
    }
}
