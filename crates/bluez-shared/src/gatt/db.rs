// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT attribute database replacing src/shared/gatt-db.c
//
// The database stores services, characteristics, descriptors, and included
// services using handle-based addressing. Used by both client (cache) and
// server (local attributes).
//
// C's ref counting is replaced by Arc. C's callback-based read/write is
// replaced by async channels and trait objects.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::uuid::Uuid;

use super::{
    GATT_CHARAC_UUID, GATT_CLIENT_CHARAC_CFG_UUID, GATT_INCLUDE_UUID, GATT_PRIM_SVC_UUID,
    GATT_SND_SVC_UUID,
};

/// Maximum length of a characteristic declaration value.
/// 1 byte properties + 2 bytes value handle + up to 16 bytes UUID128.
const MAX_CHAR_DECL_VALUE_LEN: usize = 19;

/// Maximum length of an included service declaration value.
/// 2 bytes start handle + 2 bytes end handle + optional 2 bytes UUID16.
const _MAX_INCLUDED_VALUE_LEN: usize = 6;

// ---- Public types ----

/// A GATT attribute with its metadata and optional value.
#[derive(Debug, Clone)]
pub struct GattAttribute {
    /// Attribute handle.
    pub handle: u16,
    /// Attribute type UUID.
    pub uuid: Uuid,
    /// Permissions for this attribute.
    pub permissions: u32,
    /// Stored value (for declarations and static attributes).
    pub value: Vec<u8>,
}

/// A GATT service containing its attributes.
#[derive(Debug, Clone)]
pub struct GattService {
    /// Whether this service is a primary service.
    pub primary: bool,
    /// Service UUID.
    pub uuid: Uuid,
    /// Whether the service is active (visible to queries).
    pub active: bool,
    /// Whether the service has been claimed by an upper layer.
    pub claimed: bool,
    /// Start handle (first attribute).
    pub start_handle: u16,
    /// End handle (last attribute in the service's handle range).
    pub end_handle: u16,
    /// All attributes in this service, keyed by handle.
    pub attributes: BTreeMap<u16, GattAttribute>,
}

/// Notification type for database changes.
#[derive(Debug, Clone)]
pub enum GattDbNotify {
    /// A service was added and activated.
    ServiceAdded(u16, u16),
    /// A service was removed (start_handle, end_handle).
    ServiceRemoved(u16, u16),
}

/// Callback ID for observer registration.
pub type NotifyId = u32;

/// The GATT attribute database.
///
/// Thread-safe via `Arc<RwLock<...>>`. Replaces C's `struct gatt_db`.
///
/// ```ignore
/// let db = GattDb::new();
/// let svc_handle = db.add_service(Uuid::from_u16(0x180F), true, 4).await;
/// ```
pub struct GattDb {
    inner: Arc<RwLock<GattDbInner>>,
    next_notify_id: AtomicU32,
}

struct GattDbInner {
    /// Services ordered by start handle.
    services: BTreeMap<u16, GattService>,
    /// Last allocated handle.
    last_handle: u16,
    /// Observer callbacks.
    observers: Vec<(u32, tokio::sync::mpsc::UnboundedSender<GattDbNotify>)>,
    /// Cached database hash (GATT 5.0+).
    hash: Option<[u8; 16]>,
}

impl Clone for GattDb {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            next_notify_id: AtomicU32::new(0),
        }
    }
}

impl GattDb {
    /// Create a new empty GATT database.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(GattDbInner {
                services: BTreeMap::new(),
                last_handle: 0,
                observers: Vec::new(),
                hash: None,
            })),
            next_notify_id: AtomicU32::new(1),
        }
    }

    /// Register for database change notifications.
    /// Returns a (NotifyId, Receiver) pair. Drop the receiver to unsubscribe.
    pub async fn register(
        &self,
    ) -> (
        NotifyId,
        tokio::sync::mpsc::UnboundedReceiver<GattDbNotify>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let id = self.next_notify_id.fetch_add(1, Ordering::Relaxed);
        self.inner.write().await.observers.push((id, tx));
        (id, rx)
    }

    /// Unregister a database change observer.
    pub async fn unregister(&self, id: NotifyId) {
        let mut inner = self.inner.write().await;
        inner.observers.retain(|(obs_id, _)| *obs_id != id);
    }

    /// Add a service with auto-allocated handles.
    ///
    /// Returns the start handle of the new service, or None if out of handles.
    pub async fn add_service(
        &self,
        uuid: Uuid,
        primary: bool,
        num_handles: u16,
    ) -> Option<u16> {
        let mut inner = self.inner.write().await;
        let start = inner.last_handle.checked_add(1)?;
        let end = start.checked_add(num_handles.saturating_sub(1))?;

        let svc = create_service(&uuid, primary, start, end);
        inner.services.insert(start, svc);
        inner.last_handle = end;
        inner.hash = None;

        Some(start)
    }

    /// Insert a service at a specific handle range.
    ///
    /// Returns the start handle, or None if the range overlaps.
    pub async fn insert_service(
        &self,
        start_handle: u16,
        uuid: Uuid,
        primary: bool,
        num_handles: u16,
    ) -> Option<u16> {
        if start_handle == 0 || num_handles == 0 {
            return None;
        }

        let end_handle = start_handle.checked_add(num_handles - 1)?;
        let mut inner = self.inner.write().await;

        // Check for overlapping services
        for (_, svc) in inner.services.iter() {
            if start_handle <= svc.end_handle && end_handle >= svc.start_handle {
                return None;
            }
        }

        let svc = create_service(&uuid, primary, start_handle, end_handle);
        inner.services.insert(start_handle, svc);

        if end_handle > inner.last_handle {
            inner.last_handle = end_handle;
        }
        inner.hash = None;

        Some(start_handle)
    }

    /// Remove a service by its start handle.
    pub async fn remove_service(&self, start_handle: u16) -> bool {
        let mut inner = self.inner.write().await;
        if let Some(svc) = inner.services.remove(&start_handle) {
            let start = svc.start_handle;
            let end = svc.end_handle;
            inner.hash = None;
            notify_observers(&inner.observers, GattDbNotify::ServiceRemoved(start, end));
            true
        } else {
            false
        }
    }

    /// Remove all services.
    pub async fn clear(&self) {
        let mut inner = self.inner.write().await;
        let handles: Vec<(u16, u16)> = inner
            .services
            .values()
            .map(|s| (s.start_handle, s.end_handle))
            .collect();

        inner.services.clear();
        inner.last_handle = 0;
        inner.hash = None;

        for (start, end) in handles {
            notify_observers(&inner.observers, GattDbNotify::ServiceRemoved(start, end));
        }
    }

    /// Remove services whose handles fall within a range.
    pub async fn clear_range(&self, start: u16, end: u16) {
        let mut inner = self.inner.write().await;
        let to_remove: Vec<u16> = inner
            .services
            .iter()
            .filter(|(_, svc)| svc.start_handle >= start && svc.end_handle <= end)
            .map(|(&h, _)| h)
            .collect();

        for h in to_remove {
            if let Some(svc) = inner.services.remove(&h) {
                inner.hash = None;
                notify_observers(
                    &inner.observers,
                    GattDbNotify::ServiceRemoved(svc.start_handle, svc.end_handle),
                );
            }
        }
    }

    /// Set a service as active (visible to queries).
    pub async fn set_service_active(&self, start_handle: u16, active: bool) {
        let mut inner = self.inner.write().await;
        if let Some(svc) = inner.services.get_mut(&start_handle) {
            let was_active = svc.active;
            svc.active = active;
            let start = svc.start_handle;
            let end = svc.end_handle;
            let _ = svc;

            if active && !was_active {
                inner.hash = None;
                notify_observers(&inner.observers, GattDbNotify::ServiceAdded(start, end));
            } else if !active && was_active {
                inner.hash = None;
            }
        }
    }

    /// Check if a service is active.
    pub async fn is_service_active(&self, start_handle: u16) -> bool {
        let inner = self.inner.read().await;
        inner
            .services
            .get(&start_handle)
            .is_some_and(|s| s.active)
    }

    /// Set/get claimed state of a service.
    pub async fn set_service_claimed(&self, start_handle: u16, claimed: bool) {
        let mut inner = self.inner.write().await;
        if let Some(svc) = inner.services.get_mut(&start_handle) {
            svc.claimed = claimed;
        }
    }

    pub async fn is_service_claimed(&self, start_handle: u16) -> bool {
        let inner = self.inner.read().await;
        inner
            .services
            .get(&start_handle)
            .is_some_and(|s| s.claimed)
    }

    /// Add a characteristic to a service.
    ///
    /// Returns the value handle (declaration handle + 1), or None on failure.
    pub async fn service_add_characteristic(
        &self,
        svc_handle: u16,
        uuid: Uuid,
        permissions: u32,
        properties: u8,
        value: &[u8],
    ) -> Option<u16> {
        let mut inner = self.inner.write().await;
        let svc = inner.services.get_mut(&svc_handle)?;

        // Need 2 handles: declaration + value
        let decl_handle = next_free_handle(svc)?;
        let value_handle = decl_handle.checked_add(1)?;
        if value_handle > svc.end_handle {
            return None;
        }

        // Build characteristic declaration value
        let uuid_bytes = uuid.to_uuid128();
        let uuid_len = match uuid {
            Uuid::Uuid16(_) => 2,
            Uuid::Uuid32(_) => 4,
            Uuid::Uuid128(_) => 16,
        };

        let mut decl_value = Vec::with_capacity(MAX_CHAR_DECL_VALUE_LEN);
        decl_value.push(properties);
        decl_value.extend_from_slice(&value_handle.to_le_bytes());

        match uuid {
            Uuid::Uuid16(v) => decl_value.extend_from_slice(&v.to_le_bytes()),
            Uuid::Uuid32(v) => decl_value.extend_from_slice(&v.to_le_bytes()),
            Uuid::Uuid128(_) => {
                // LE byte order for 128-bit
                let mut le = uuid_bytes;
                le.reverse();
                decl_value.extend_from_slice(&le[..uuid_len]);
            }
        }

        // Insert declaration attribute
        svc.attributes.insert(
            decl_handle,
            GattAttribute {
                handle: decl_handle,
                uuid: Uuid::from_u16(GATT_CHARAC_UUID),
                permissions: 0, // Declaration is always readable
                value: decl_value,
            },
        );

        // Insert value attribute
        svc.attributes.insert(
            value_handle,
            GattAttribute {
                handle: value_handle,
                uuid,
                permissions,
                value: value.to_vec(),
            },
        );

        inner.hash = None;
        Some(value_handle)
    }

    /// Add a descriptor to a service.
    ///
    /// Returns the descriptor handle, or None on failure.
    pub async fn service_add_descriptor(
        &self,
        svc_handle: u16,
        uuid: Uuid,
        permissions: u32,
        value: &[u8],
    ) -> Option<u16> {
        let mut inner = self.inner.write().await;
        let svc = inner.services.get_mut(&svc_handle)?;

        let handle = next_free_handle(svc)?;

        svc.attributes.insert(
            handle,
            GattAttribute {
                handle,
                uuid,
                permissions,
                value: value.to_vec(),
            },
        );

        inner.hash = None;
        Some(handle)
    }

    /// Add a CCC (Client Characteristic Configuration) descriptor.
    pub async fn service_add_ccc(
        &self,
        svc_handle: u16,
        permissions: u32,
    ) -> Option<u16> {
        self.service_add_descriptor(
            svc_handle,
            Uuid::from_u16(GATT_CLIENT_CHARAC_CFG_UUID),
            permissions,
            &[0x00, 0x00], // Default: notifications/indications disabled
        )
        .await
    }

    /// Add an included service declaration.
    pub async fn service_add_included(
        &self,
        svc_handle: u16,
        included_svc_handle: u16,
    ) -> Option<u16> {
        let inner_read = self.inner.read().await;
        let included = inner_read.services.get(&included_svc_handle)?;
        let incl_start = included.start_handle;
        let incl_end = included.end_handle;
        let incl_uuid = included.uuid;
        drop(inner_read);

        let mut inner = self.inner.write().await;
        let svc = inner.services.get_mut(&svc_handle)?;
        let handle = next_free_handle(svc)?;

        // Build included service value: start_handle(2) + end_handle(2) + optional UUID16(2)
        let mut value = Vec::with_capacity(6);
        value.extend_from_slice(&incl_start.to_le_bytes());
        value.extend_from_slice(&incl_end.to_le_bytes());
        if let Uuid::Uuid16(u16_val) = incl_uuid {
            value.extend_from_slice(&u16_val.to_le_bytes());
        }

        svc.attributes.insert(
            handle,
            GattAttribute {
                handle,
                uuid: Uuid::from_u16(GATT_INCLUDE_UUID),
                permissions: 0,
                value,
            },
        );

        inner.hash = None;
        Some(handle)
    }

    /// Get an attribute by handle.
    pub async fn get_attribute(&self, handle: u16) -> Option<GattAttribute> {
        let inner = self.inner.read().await;
        for svc in inner.services.values() {
            if handle >= svc.start_handle && handle <= svc.end_handle {
                return svc.attributes.get(&handle).cloned();
            }
        }
        None
    }

    /// Get the service containing a given handle.
    pub async fn get_service(&self, handle: u16) -> Option<GattService> {
        let inner = self.inner.read().await;
        for svc in inner.services.values() {
            if handle >= svc.start_handle && handle <= svc.end_handle {
                return Some(svc.clone());
            }
        }
        None
    }

    /// Get service handles (start, end) for a service containing the given handle.
    pub async fn get_service_handles(&self, handle: u16) -> Option<(u16, u16)> {
        let inner = self.inner.read().await;
        for svc in inner.services.values() {
            if handle >= svc.start_handle && handle <= svc.end_handle {
                return Some((svc.start_handle, svc.end_handle));
            }
        }
        None
    }

    /// Read By Group Type: find all services of a given type in a handle range.
    ///
    /// Returns (start_handle, end_handle, service_uuid) tuples.
    pub async fn read_by_group_type(
        &self,
        start: u16,
        end: u16,
        uuid: Uuid,
    ) -> Vec<(u16, u16, Uuid)> {
        let inner = self.inner.read().await;
        let is_primary = uuid.eq_as_uuid128(&Uuid::from_u16(GATT_PRIM_SVC_UUID));
        let is_secondary = uuid.eq_as_uuid128(&Uuid::from_u16(GATT_SND_SVC_UUID));

        if !is_primary && !is_secondary {
            return Vec::new();
        }

        inner
            .services
            .values()
            .filter(|svc| {
                svc.active
                    && svc.start_handle >= start
                    && svc.start_handle <= end
                    && svc.primary == is_primary
            })
            .map(|svc| (svc.start_handle, svc.end_handle, svc.uuid))
            .collect()
    }

    /// Find By Type Value: find services matching a type and value.
    pub async fn find_by_type_value(
        &self,
        start: u16,
        end: u16,
        uuid: Uuid,
        value: &[u8],
    ) -> Vec<(u16, u16)> {
        let inner = self.inner.read().await;

        inner
            .services
            .values()
            .filter(|svc| {
                if !svc.active || svc.start_handle < start || svc.start_handle > end {
                    return false;
                }
                // Check service declaration attribute
                if let Some(attr) = svc.attributes.get(&svc.start_handle) {
                    attr.uuid.eq_as_uuid128(&uuid) && attr.value == value
                } else {
                    false
                }
            })
            .map(|svc| (svc.start_handle, svc.end_handle))
            .collect()
    }

    /// Read By Type: find all attributes of a given type in a handle range.
    ///
    /// Returns (handle, value) pairs.
    pub async fn read_by_type(
        &self,
        start: u16,
        end: u16,
        uuid: Uuid,
    ) -> Vec<(u16, Vec<u8>)> {
        let inner = self.inner.read().await;
        let mut results = Vec::new();

        for svc in inner.services.values() {
            if !svc.active || svc.end_handle < start || svc.start_handle > end {
                continue;
            }
            for attr in svc.attributes.values() {
                if attr.handle >= start
                    && attr.handle <= end
                    && attr.uuid.eq_as_uuid128(&uuid)
                {
                    results.push((attr.handle, attr.value.clone()));
                }
            }
        }

        results.sort_by_key(|(h, _)| *h);
        results
    }

    /// Find Information: get (handle, uuid) pairs in a handle range.
    pub async fn find_information(
        &self,
        start: u16,
        end: u16,
    ) -> Vec<(u16, Uuid)> {
        let inner = self.inner.read().await;
        let mut results = Vec::new();

        for svc in inner.services.values() {
            if !svc.active || svc.end_handle < start || svc.start_handle > end {
                continue;
            }
            for attr in svc.attributes.values() {
                if attr.handle >= start && attr.handle <= end {
                    results.push((attr.handle, attr.uuid));
                }
            }
        }

        results.sort_by_key(|(h, _)| *h);
        results
    }

    /// Iterate over all active services, calling the provided function.
    pub async fn foreach_service<F>(&self, mut f: F)
    where
        F: FnMut(&GattService),
    {
        let inner = self.inner.read().await;
        for svc in inner.services.values() {
            if svc.active {
                f(svc);
            }
        }
    }

    /// Iterate over active services in a handle range.
    pub async fn foreach_service_in_range<F>(&self, start: u16, end: u16, mut f: F)
    where
        F: FnMut(&GattService),
    {
        let inner = self.inner.read().await;
        for svc in inner.services.values() {
            if svc.active && svc.start_handle >= start && svc.end_handle <= end {
                f(svc);
            }
        }
    }

    /// Get all characteristics in a service.
    ///
    /// Returns (decl_handle, value_handle, properties, uuid) tuples.
    pub async fn service_get_characteristics(
        &self,
        svc_handle: u16,
    ) -> Vec<(u16, u16, u8, Uuid)> {
        let inner = self.inner.read().await;
        let svc = match inner.services.get(&svc_handle) {
            Some(s) => s,
            None => return Vec::new(),
        };

        let charac_uuid = Uuid::from_u16(GATT_CHARAC_UUID);
        let mut chars = Vec::new();

        for attr in svc.attributes.values() {
            if attr.uuid.eq_as_uuid128(&charac_uuid) && attr.value.len() >= 3 {
                let properties = attr.value[0];
                let value_handle = u16::from_le_bytes([attr.value[1], attr.value[2]]);
                let char_uuid = parse_uuid_from_decl(&attr.value[3..]);
                chars.push((attr.handle, value_handle, properties, char_uuid));
            }
        }

        chars
    }

    /// Get all descriptors for a characteristic (between value_handle+1 and next char decl or service end).
    pub async fn service_get_descriptors(
        &self,
        svc_handle: u16,
        value_handle: u16,
    ) -> Vec<(u16, Uuid)> {
        let inner = self.inner.read().await;
        let svc = match inner.services.get(&svc_handle) {
            Some(s) => s,
            None => return Vec::new(),
        };

        let charac_uuid = Uuid::from_u16(GATT_CHARAC_UUID);
        let start = value_handle + 1;

        // Find end of this characteristic's descriptors (next char decl or service end)
        let desc_end = svc
            .attributes
            .iter()
            .filter(|(&h, attr)| h > value_handle && attr.uuid.eq_as_uuid128(&charac_uuid))
            .map(|(&h, _)| h - 1)
            .next()
            .unwrap_or(svc.end_handle);

        svc.attributes
            .iter()
            .filter(|(&h, _)| h >= start && h <= desc_end)
            .map(|(_, attr)| (attr.handle, attr.uuid))
            .collect()
    }

    /// Read an attribute's stored value.
    pub async fn attribute_read(&self, handle: u16, offset: u16) -> Option<Vec<u8>> {
        let attr = self.get_attribute(handle).await?;
        let offset = offset as usize;
        if offset > attr.value.len() {
            return Some(Vec::new());
        }
        Some(attr.value[offset..].to_vec())
    }

    /// Write to an attribute's stored value.
    pub async fn attribute_write(&self, handle: u16, offset: u16, value: &[u8]) -> bool {
        let mut inner = self.inner.write().await;
        for svc in inner.services.values_mut() {
            if let Some(attr) = svc.attributes.get_mut(&handle) {
                let offset = offset as usize;
                if offset > attr.value.len() {
                    return false;
                }
                let needed = offset + value.len();
                if needed > attr.value.len() {
                    attr.value.resize(needed, 0);
                }
                attr.value[offset..offset + value.len()].copy_from_slice(value);
                inner.hash = None;
                return true;
            }
        }
        false
    }

    /// Check if the database is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.services.is_empty()
    }

    /// Get the number of services.
    pub async fn service_count(&self) -> usize {
        self.inner.read().await.services.len()
    }

    /// Get the cached hash, if any.
    pub async fn get_hash(&self) -> Option<[u8; 16]> {
        self.inner.read().await.hash
    }

    /// Set the database hash.
    pub async fn set_hash(&self, hash: [u8; 16]) {
        self.inner.write().await.hash = Some(hash);
    }

    /// Compute and cache the database hash using AES-CMAC.
    ///
    /// The hash covers all active service, characteristic, and descriptor
    /// declarations in handle order, per GATT 5.0+ spec.
    pub async fn compute_hash(&self) -> Option<[u8; 16]> {
        let inner = self.inner.read().await;
        let mut data = Vec::new();

        // Collect all attributes from active services in handle order
        let mut all_attrs: Vec<&GattAttribute> = Vec::new();
        for svc in inner.services.values() {
            if !svc.active {
                continue;
            }
            for attr in svc.attributes.values() {
                all_attrs.push(attr);
            }
        }
        all_attrs.sort_by_key(|a| a.handle);

        // Build the hash input: for each attribute, handle(2) + uuid(2/16) + value
        for attr in &all_attrs {
            data.extend_from_slice(&attr.handle.to_le_bytes());
            // UUID in LE format
            match attr.uuid {
                Uuid::Uuid16(v) => data.extend_from_slice(&v.to_le_bytes()),
                Uuid::Uuid32(v) => data.extend_from_slice(&v.to_le_bytes()),
                Uuid::Uuid128(bytes) => {
                    let mut le = bytes;
                    le.reverse();
                    data.extend_from_slice(&le);
                }
            }
            data.extend_from_slice(&attr.value);
        }

        let mut hash = [0u8; 16];
        if crate::crypto::bt_crypto_gatt_hash(&data, &mut hash) {
            drop(inner);
            self.inner.write().await.hash = Some(hash);
            Some(hash)
        } else {
            None
        }
    }
}

impl Default for GattDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Internal helpers ----

/// Create a service with its service declaration attribute.
fn create_service(uuid: &Uuid, primary: bool, start: u16, end: u16) -> GattService {
    let svc_type = if primary {
        GATT_PRIM_SVC_UUID
    } else {
        GATT_SND_SVC_UUID
    };

    // Service declaration value is the service UUID in LE
    let value = match uuid {
        Uuid::Uuid16(v) => v.to_le_bytes().to_vec(),
        Uuid::Uuid32(v) => v.to_le_bytes().to_vec(),
        Uuid::Uuid128(bytes) => {
            let mut le = *bytes;
            le.reverse();
            le.to_vec()
        }
    };

    let mut attributes = BTreeMap::new();
    attributes.insert(
        start,
        GattAttribute {
            handle: start,
            uuid: Uuid::from_u16(svc_type),
            permissions: 0,
            value,
        },
    );

    GattService {
        primary,
        uuid: *uuid,
        active: false,
        claimed: false,
        start_handle: start,
        end_handle: end,
        attributes,
    }
}

/// Find the next free handle within a service.
fn next_free_handle(svc: &GattService) -> Option<u16> {
    if svc.attributes.is_empty() {
        return Some(svc.start_handle);
    }

    // The next handle is one past the highest used handle
    let max_used = *svc.attributes.keys().last()?;
    let next = max_used + 1;
    if next <= svc.end_handle {
        Some(next)
    } else {
        None
    }
}

/// Parse a UUID from characteristic declaration value bytes.
fn parse_uuid_from_decl(bytes: &[u8]) -> Uuid {
    match bytes.len() {
        2 => Uuid::from_u16(u16::from_le_bytes([bytes[0], bytes[1]])),
        4 => Uuid::from_u32(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        16 => {
            let mut be = [0u8; 16];
            be.copy_from_slice(bytes);
            be.reverse(); // LE to BE
            Uuid::from_u128_bytes(be)
        }
        _ => Uuid::from_u16(0),
    }
}

/// Send a notification to all observers.
fn notify_observers(
    observers: &[(u32, tokio::sync::mpsc::UnboundedSender<GattDbNotify>)],
    notify: GattDbNotify,
) {
    observers.iter().for_each(|(_, tx)| {
        let _ = tx.send(notify.clone());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_new_db_is_empty() {
        rt().block_on(async {
            let db = GattDb::new();
            assert!(db.is_empty().await);
            assert_eq!(db.service_count().await, 0);
        });
    }

    #[test]
    fn test_add_service() {
        rt().block_on(async {
            let db = GattDb::new();
            let handle = db
                .add_service(Uuid::from_u16(0x180F), true, 4)
                .await
                .unwrap();
            assert_eq!(handle, 1);
            assert_eq!(db.service_count().await, 1);

            // Service starts inactive
            assert!(!db.is_service_active(handle).await);

            db.set_service_active(handle, true).await;
            assert!(db.is_service_active(handle).await);
        });
    }

    #[test]
    fn test_add_characteristic() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db
                .add_service(Uuid::from_u16(0x180F), true, 6)
                .await
                .unwrap();

            let val_handle = db
                .service_add_characteristic(
                    svc,
                    Uuid::from_u16(0x2A19), // Battery Level
                    0x01,                    // permissions
                    0x02,                    // properties: Read
                    &[100],                  // 100% battery
                )
                .await
                .unwrap();

            // Declaration at handle 2, value at handle 3
            assert_eq!(val_handle, 3);

            // Read the value
            let value = db.attribute_read(val_handle, 0).await.unwrap();
            assert_eq!(value, vec![100]);
        });
    }

    #[test]
    fn test_add_descriptor() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db
                .add_service(Uuid::from_u16(0x180F), true, 6)
                .await
                .unwrap();

            let _val_handle = db
                .service_add_characteristic(
                    svc,
                    Uuid::from_u16(0x2A19),
                    0x01,
                    0x12, // Read + Notify
                    &[100],
                )
                .await
                .unwrap();

            let ccc = db.service_add_ccc(svc, 0x03).await.unwrap();
            assert_eq!(ccc, 4);

            // CCC default value is 0x0000
            let value = db.attribute_read(ccc, 0).await.unwrap();
            assert_eq!(value, vec![0x00, 0x00]);
        });
    }

    #[test]
    fn test_read_by_group_type() {
        rt().block_on(async {
            let db = GattDb::new();

            let svc1 = db
                .add_service(Uuid::from_u16(0x180F), true, 4)
                .await
                .unwrap();
            db.set_service_active(svc1, true).await;

            let svc2 = db
                .add_service(Uuid::from_u16(0x180A), true, 4)
                .await
                .unwrap();
            db.set_service_active(svc2, true).await;

            let results = db
                .read_by_group_type(0x0001, 0xFFFF, Uuid::from_u16(GATT_PRIM_SVC_UUID))
                .await;
            assert_eq!(results.len(), 2);
            assert_eq!(results[0].2, Uuid::from_u16(0x180F));
            assert_eq!(results[1].2, Uuid::from_u16(0x180A));
        });
    }

    #[test]
    fn test_find_information() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db
                .add_service(Uuid::from_u16(0x180F), true, 6)
                .await
                .unwrap();
            db.set_service_active(svc, true).await;

            let _val = db
                .service_add_characteristic(svc, Uuid::from_u16(0x2A19), 0x01, 0x02, &[100])
                .await
                .unwrap();

            let info = db.find_information(1, 0xFFFF).await;
            // Should have: service decl (1), char decl (2), char value (3)
            assert_eq!(info.len(), 3);
            assert_eq!(info[0].0, 1); // service decl handle
            assert_eq!(info[1].0, 2); // char decl handle
            assert_eq!(info[2].0, 3); // char value handle
        });
    }

    #[test]
    fn test_remove_service() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db
                .add_service(Uuid::from_u16(0x180F), true, 4)
                .await
                .unwrap();
            assert_eq!(db.service_count().await, 1);

            assert!(db.remove_service(svc).await);
            assert_eq!(db.service_count().await, 0);

            // Removing nonexistent service returns false
            assert!(!db.remove_service(svc).await);
        });
    }

    #[test]
    fn test_insert_service() {
        rt().block_on(async {
            let db = GattDb::new();

            // Insert at specific handle
            let handle = db
                .insert_service(10, Uuid::from_u16(0x180F), true, 5)
                .await
                .unwrap();
            assert_eq!(handle, 10);

            // Overlapping insert should fail
            assert!(db
                .insert_service(12, Uuid::from_u16(0x180A), true, 3)
                .await
                .is_none());

            // Non-overlapping should succeed
            let h2 = db
                .insert_service(1, Uuid::from_u16(0x180A), true, 5)
                .await
                .unwrap();
            assert_eq!(h2, 1);
        });
    }

    #[test]
    fn test_attribute_write() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db
                .add_service(Uuid::from_u16(0x180F), true, 4)
                .await
                .unwrap();

            let val = db
                .service_add_characteristic(svc, Uuid::from_u16(0x2A19), 0x03, 0x0A, &[50])
                .await
                .unwrap();

            // Write new value
            assert!(db.attribute_write(val, 0, &[75]).await);
            let read_val = db.attribute_read(val, 0).await.unwrap();
            assert_eq!(read_val, vec![75]);
        });
    }

    #[test]
    fn test_service_get_characteristics() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db
                .add_service(Uuid::from_u16(0x180F), true, 10)
                .await
                .unwrap();

            db.service_add_characteristic(svc, Uuid::from_u16(0x2A19), 0x01, 0x02, &[100])
                .await
                .unwrap();
            db.service_add_characteristic(svc, Uuid::from_u16(0x2A1A), 0x01, 0x02, &[50])
                .await
                .unwrap();

            let chars = db.service_get_characteristics(svc).await;
            assert_eq!(chars.len(), 2);
            assert_eq!(chars[0].3, Uuid::from_u16(0x2A19));
            assert_eq!(chars[1].3, Uuid::from_u16(0x2A1A));
        });
    }

    #[test]
    fn test_notify_observer() {
        rt().block_on(async {
            let db = GattDb::new();
            let (_id, mut rx) = db.register().await;

            let svc = db
                .add_service(Uuid::from_u16(0x180F), true, 4)
                .await
                .unwrap();

            // Activate triggers notification
            db.set_service_active(svc, true).await;

            match rx.try_recv() {
                Ok(GattDbNotify::ServiceAdded(1, 4)) => {}
                other => panic!("expected ServiceAdded(1,4), got {:?}", other),
            }

            // Remove triggers notification
            db.remove_service(svc).await;

            match rx.try_recv() {
                Ok(GattDbNotify::ServiceRemoved(1, 4)) => {}
                other => panic!("expected ServiceRemoved(1,4), got {:?}", other),
            }
        });
    }

    #[test]
    fn test_clear() {
        rt().block_on(async {
            let db = GattDb::new();
            db.add_service(Uuid::from_u16(0x180F), true, 4).await;
            db.add_service(Uuid::from_u16(0x180A), true, 4).await;
            assert_eq!(db.service_count().await, 2);

            db.clear().await;
            assert!(db.is_empty().await);
        });
    }

    #[test]
    fn test_default_trait() {
        let db = GattDb::default();
        assert!(std::mem::size_of_val(&db) > 0);
    }

    #[test]
    fn test_parse_uuid_from_decl_16() {
        let uuid = parse_uuid_from_decl(&[0x19, 0x2A]);
        assert_eq!(uuid, Uuid::from_u16(0x2A19));
    }

    // -----------------------------------------------------------------------
    // Ported from unit/test-gatt.c — GATT database operations
    // -----------------------------------------------------------------------

    // Port of test-gatt.c: add service with specific UUID and verify handle range
    #[test]
    fn test_gatt_db_add_service_gap() {
        rt().block_on(async {
            let db = GattDb::new();
            // GAP service (0x1800) with 4 handles
            let h = db.add_service(Uuid::from_u16(0x1800), true, 4).await.unwrap();
            assert_eq!(h, 1);
            let svc = db.get_service(1).await.unwrap();
            assert_eq!(svc.start_handle, 1);
            assert_eq!(svc.end_handle, 4);
            assert!(svc.primary);
            assert_eq!(svc.uuid, Uuid::from_u16(0x1800));
        });
    }

    // Port of test-gatt.c: add two primary services and discover them
    #[test]
    fn test_gatt_db_two_primary_services_discovery() {
        rt().block_on(async {
            let db = GattDb::new();

            // Service 1: GAP (0x1801)
            let svc1 = db.add_service(Uuid::from_u16(0x1801), true, 4).await.unwrap();
            db.set_service_active(svc1, true).await;

            // Service 2: Heart Rate (0x180D)
            let svc2 = db.add_service(Uuid::from_u16(0x180D), true, 6).await.unwrap();
            db.set_service_active(svc2, true).await;

            let results = db
                .read_by_group_type(0x0001, 0xFFFF, Uuid::from_u16(GATT_PRIM_SVC_UUID))
                .await;
            assert_eq!(results.len(), 2);
            assert_eq!(results[0].0, 1); // start handle of first service
            assert_eq!(results[0].1, 4); // end handle
            assert_eq!(results[0].2, Uuid::from_u16(0x1801));
            assert_eq!(results[1].0, 5); // start of second
            assert_eq!(results[1].1, 10);
            assert_eq!(results[1].2, Uuid::from_u16(0x180D));
        });
    }

    // Port of test-gatt.c: secondary service discovery
    #[test]
    fn test_gatt_db_secondary_service() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x180A), false, 4).await.unwrap();
            db.set_service_active(svc, true).await;

            // Primary query should return nothing
            let primary = db
                .read_by_group_type(0x0001, 0xFFFF, Uuid::from_u16(GATT_PRIM_SVC_UUID))
                .await;
            assert!(primary.is_empty());

            // Secondary query should find it
            let secondary = db
                .read_by_group_type(0x0001, 0xFFFF, Uuid::from_u16(GATT_SND_SVC_UUID))
                .await;
            assert_eq!(secondary.len(), 1);
            assert_eq!(secondary[0].2, Uuid::from_u16(0x180A));
        });
    }

    // Port of test-gatt.c: add characteristic and read by type
    #[test]
    fn test_gatt_db_characteristic_read_by_type() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x1800), true, 8).await.unwrap();
            db.set_service_active(svc, true).await;

            // Device Name characteristic (0x2A00)
            let val_handle = db
                .service_add_characteristic(
                    svc,
                    Uuid::from_u16(0x2A00),
                    0x01, // read permission
                    0x02, // read property
                    b"TestDevice",
                )
                .await
                .unwrap();

            // Read by type for characteristic declarations (0x2803)
            let chars = db
                .read_by_type(1, 8, Uuid::from_u16(GATT_CHARAC_UUID))
                .await;
            assert_eq!(chars.len(), 1);
            // Char decl value: properties(1) + value_handle(2) + uuid(2)
            let decl_val = &chars[0].1;
            assert_eq!(decl_val[0], 0x02); // properties = Read
            let vhandle = u16::from_le_bytes([decl_val[1], decl_val[2]]);
            assert_eq!(vhandle, val_handle);

            // Read the actual characteristic value
            let value = db.attribute_read(val_handle, 0).await.unwrap();
            assert_eq!(value, b"TestDevice");
        });
    }

    // Port of test-gatt.c: add multiple characteristics to a service
    #[test]
    fn test_gatt_db_multiple_characteristics() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x1800), true, 12).await.unwrap();

            // Device Name (0x2A00)
            let vh1 = db
                .service_add_characteristic(svc, Uuid::from_u16(0x2A00), 0x01, 0x02, b"Name")
                .await
                .unwrap();
            assert_eq!(vh1, 3);

            // Appearance (0x2A01)
            let vh2 = db
                .service_add_characteristic(svc, Uuid::from_u16(0x2A01), 0x01, 0x02, &[0x00, 0x00])
                .await
                .unwrap();
            assert_eq!(vh2, 5);

            // Manufacturer Name (0x2A29)
            let vh3 = db
                .service_add_characteristic(svc, Uuid::from_u16(0x2A29), 0x01, 0x0A, b"Mfr")
                .await
                .unwrap();
            assert_eq!(vh3, 7);

            let chars = db.service_get_characteristics(svc).await;
            assert_eq!(chars.len(), 3);
            assert_eq!(chars[0].3, Uuid::from_u16(0x2A00));
            assert_eq!(chars[1].3, Uuid::from_u16(0x2A01));
            assert_eq!(chars[2].3, Uuid::from_u16(0x2A29));
        });
    }

    // Port of test-gatt.c: add descriptor and find information
    #[test]
    fn test_gatt_db_descriptor_find_info() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x180F), true, 8).await.unwrap();
            db.set_service_active(svc, true).await;

            let _vh = db
                .service_add_characteristic(
                    svc,
                    Uuid::from_u16(0x2A19),
                    0x01,
                    0x12, // Read + Notify
                    &[100],
                )
                .await
                .unwrap();

            // Add CCC descriptor (0x2902)
            let ccc = db.service_add_ccc(svc, 0x03).await.unwrap();
            assert_eq!(ccc, 4);

            // Find information in descriptor range
            let info = db.find_information(4, 4).await;
            assert_eq!(info.len(), 1);
            assert_eq!(info[0].0, 4);
            assert_eq!(info[0].1, Uuid::from_u16(GATT_CLIENT_CHARAC_CFG_UUID));
        });
    }

    // Port of test-gatt.c: attribute write at offset
    #[test]
    fn test_gatt_db_write_at_offset() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x180F), true, 4).await.unwrap();

            let vh = db
                .service_add_characteristic(svc, Uuid::from_u16(0x2A19), 0x03, 0x0A, &[0, 0, 0, 0])
                .await
                .unwrap();

            // Write at offset 2
            assert!(db.attribute_write(vh, 2, &[0xAB, 0xCD]).await);
            let value = db.attribute_read(vh, 0).await.unwrap();
            assert_eq!(value, vec![0, 0, 0xAB, 0xCD]);

            // Read at offset 2
            let partial = db.attribute_read(vh, 2).await.unwrap();
            assert_eq!(partial, vec![0xAB, 0xCD]);
        });
    }

    // Port of test-gatt.c: clear range removes only services in that range
    #[test]
    fn test_gatt_db_clear_range() {
        rt().block_on(async {
            let db = GattDb::new();
            let s1 = db.add_service(Uuid::from_u16(0x1800), true, 4).await.unwrap();
            let s2 = db.add_service(Uuid::from_u16(0x1801), true, 4).await.unwrap();
            let s3 = db.add_service(Uuid::from_u16(0x180F), true, 4).await.unwrap();
            assert_eq!(db.service_count().await, 3);

            // Clear only the middle service (handles 5-8)
            db.clear_range(s2, s2 + 3).await;
            assert_eq!(db.service_count().await, 2);

            // First and third still exist
            assert!(db.get_service(s1).await.is_some());
            assert!(db.get_service(s3).await.is_some());
            assert!(db.get_service(s2).await.is_none());
        });
    }

    // Port of test-gatt.c: service claimed state
    #[test]
    fn test_gatt_db_service_claimed() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x1800), true, 4).await.unwrap();

            assert!(!db.is_service_claimed(svc).await);
            db.set_service_claimed(svc, true).await;
            assert!(db.is_service_claimed(svc).await);
            db.set_service_claimed(svc, false).await;
            assert!(!db.is_service_claimed(svc).await);
        });
    }

    // Port of test-gatt.c: find_by_type_value for service UUID matching
    #[test]
    fn test_gatt_db_find_by_type_value() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x180F), true, 4).await.unwrap();
            db.set_service_active(svc, true).await;

            // Search for primary service (0x2800) with value = UUID16 LE bytes for 0x180F
            let uuid_bytes = 0x180Fu16.to_le_bytes().to_vec();
            let results = db
                .find_by_type_value(0x0001, 0xFFFF, Uuid::from_u16(GATT_PRIM_SVC_UUID), &uuid_bytes)
                .await;
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].0, svc);
        });
    }

    // Port of test-gatt.c: included service declaration
    #[test]
    fn test_gatt_db_included_service() {
        rt().block_on(async {
            let db = GattDb::new();

            // Create included service first
            let incl_svc = db.add_service(Uuid::from_u16(0x180A), true, 4).await.unwrap();
            db.set_service_active(incl_svc, true).await;

            // Create main service with room for include declaration
            let main_svc = db.add_service(Uuid::from_u16(0x1800), true, 6).await.unwrap();

            // Add included service reference
            let incl_handle = db.service_add_included(main_svc, incl_svc).await.unwrap();
            assert_eq!(incl_handle, 6); // next handle after service decl at 5

            // Read the included service declaration value
            let attr = db.get_attribute(incl_handle).await.unwrap();
            assert_eq!(attr.uuid, Uuid::from_u16(GATT_INCLUDE_UUID));
            // Value: start_handle(2) + end_handle(2) + UUID16(2)
            assert_eq!(attr.value.len(), 6);
            let inc_start = u16::from_le_bytes([attr.value[0], attr.value[1]]);
            let inc_end = u16::from_le_bytes([attr.value[2], attr.value[3]]);
            let inc_uuid = u16::from_le_bytes([attr.value[4], attr.value[5]]);
            assert_eq!(inc_start, 1);
            assert_eq!(inc_end, 4);
            assert_eq!(inc_uuid, 0x180A);
        });
    }

    // Port of test-gatt.c: service_get_descriptors
    #[test]
    fn test_gatt_db_get_descriptors() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x180F), true, 10).await.unwrap();

            let vh = db
                .service_add_characteristic(
                    svc,
                    Uuid::from_u16(0x2A19),
                    0x01,
                    0x12,
                    &[100],
                )
                .await
                .unwrap();

            // Add CCC descriptor
            let ccc = db.service_add_ccc(svc, 0x03).await.unwrap();

            // Add custom descriptor (0x2900 - Char Extended Properties)
            let desc = db
                .service_add_descriptor(svc, Uuid::from_u16(0x2900), 0x01, &[0x01, 0x00])
                .await
                .unwrap();

            let descs = db.service_get_descriptors(svc, vh).await;
            assert_eq!(descs.len(), 2);
            assert_eq!(descs[0].0, ccc);
            assert_eq!(descs[1].0, desc);
        });
    }

    // Port of test-gatt.c: 128-bit UUID service
    #[test]
    fn test_gatt_db_uuid128_service() {
        rt().block_on(async {
            let db = GattDb::new();
            let uuid = Uuid::from_u128_bytes([
                0x00, 0x00, 0x18, 0x0D, 0x00, 0x00, 0x10, 0x00,
                0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
            ]);
            let svc = db.add_service(uuid, true, 4).await.unwrap();
            db.set_service_active(svc, true).await;

            let service = db.get_service(svc).await.unwrap();
            assert_eq!(service.uuid, uuid);
        });
    }

    // Port of test-gatt.c: service handle range query
    #[test]
    fn test_gatt_db_get_service_handles() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x180F), true, 6).await.unwrap();
            db.service_add_characteristic(svc, Uuid::from_u16(0x2A19), 0, 0x02, &[0])
                .await;

            let (start, end) = db.get_service_handles(3).await.unwrap();
            assert_eq!(start, 1);
            assert_eq!(end, 6);

            // Handle outside any service
            assert!(db.get_service_handles(100).await.is_none());
        });
    }

    // Port of test-gatt.c: inactive service not visible in queries
    #[test]
    fn test_gatt_db_inactive_service_not_queryable() {
        rt().block_on(async {
            let db = GattDb::new();
            let svc = db.add_service(Uuid::from_u16(0x180F), true, 4).await.unwrap();
            // Don't activate it

            let results = db
                .read_by_group_type(0x0001, 0xFFFF, Uuid::from_u16(GATT_PRIM_SVC_UUID))
                .await;
            assert!(results.is_empty());

            // Activate and verify it shows up
            db.set_service_active(svc, true).await;
            let results = db
                .read_by_group_type(0x0001, 0xFFFF, Uuid::from_u16(GATT_PRIM_SVC_UUID))
                .await;
            assert_eq!(results.len(), 1);
        });
    }

    // Port of test-gatt.c: handle range limited discovery
    #[test]
    fn test_gatt_db_read_by_group_type_range() {
        rt().block_on(async {
            let db = GattDb::new();

            let s1 = db.add_service(Uuid::from_u16(0x1800), true, 4).await.unwrap();
            db.set_service_active(s1, true).await;

            let s2 = db.add_service(Uuid::from_u16(0x180F), true, 4).await.unwrap();
            db.set_service_active(s2, true).await;

            // Only query second half of handle space
            let results = db
                .read_by_group_type(5, 0xFFFF, Uuid::from_u16(GATT_PRIM_SVC_UUID))
                .await;
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].2, Uuid::from_u16(0x180F));
        });
    }

    // Port of test-gatt.c: parse_uuid_from_decl with 4-byte UUID
    #[test]
    fn test_parse_uuid_from_decl_32() {
        let uuid = parse_uuid_from_decl(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(uuid, Uuid::from_u32(0x04030201));
    }

    // Port of test-gatt.c: parse_uuid_from_decl with 16-byte UUID
    #[test]
    fn test_parse_uuid_from_decl_128() {
        let le_bytes = [
            0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80,
            0x00, 0x10, 0x00, 0x00, 0x0F, 0x18, 0x00, 0x00,
        ];
        let uuid = parse_uuid_from_decl(&le_bytes);
        let expected = Uuid::from_u16(0x180F).to_uuid128();
        assert_eq!(uuid.to_uuid128(), expected);
    }

    // Port of test-gatt.c: overflow protection for handle allocation
    #[test]
    fn test_gatt_db_handle_overflow() {
        rt().block_on(async {
            let db = GattDb::new();
            // Insert at high handle range
            let h = db.insert_service(0xFFFC, Uuid::from_u16(0x1800), true, 4).await.unwrap();
            assert_eq!(h, 0xFFFC);

            // Trying to add_service should fail (no room after 0xFFFF)
            assert!(db.add_service(Uuid::from_u16(0x1801), true, 1).await.is_none());
        });
    }
}
