// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * In-memory GATT database.
 *
 * Port of `src/shared/gatt-db.c` + `gatt-db.h` — models services,
 * characteristics, descriptors, and includes with CCC handling, DB hash
 * computation, async read/write with timeouts, permissions, and change
 * tracking.
 */

use std::any::Any;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, warn};

use crate::att::transport::BtAtt;
use crate::att::types::{AttPermissions, GattChrcExtProperties, GattChrcProperties};
use crate::crypto::aes_cmac::{CryptoError, bt_crypto_gatt_hash};
use crate::util::endian::{get_le16, put_le16};
use crate::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Timeout for pending attribute read/write operations (5 seconds).
const ATTRIBUTE_TIMEOUT: Duration = Duration::from_millis(5000);

/// Debounce interval for DB hash recomputation (100 ms).
const HASH_UPDATE_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum length of a characteristic declaration value:
/// 1 (properties) + 2 (value_handle LE16) + 16 (UUID-128) = 19 bytes.
const MAX_CHAR_DECL_VALUE_LEN: usize = 19;

/// Maximum length of an include declaration value:
/// 2 (start handle) + 2 (end handle) + 2 (optional UUID-16) = 6 bytes.
const MAX_INCLUDED_VALUE_LEN: usize = 6;

// Well-known 16-bit GATT UUIDs
const PRIMARY_SERVICE_UUID: u16 = 0x2800;
const SECONDARY_SERVICE_UUID: u16 = 0x2801;
const INCLUDED_SERVICE_UUID: u16 = 0x2802;
const CHARACTERISTIC_UUID: u16 = 0x2803;
const CCC_UUID: u16 = 0x2902;
const CEP_UUID: u16 = 0x2900;
const CAF_UUID: u16 = 0x2B29;

/// Negated Linux ETIMEDOUT errno value used for attribute read/write timeout.
const ETIMEDOUT: i32 = -110;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during GATT database operations.
#[derive(Debug, Error)]
pub enum GattDbError {
    /// The specified attribute handle does not exist.
    #[error("invalid attribute handle 0x{0:04x}")]
    InvalidHandle(u16),

    /// Could not allocate resources (e.g., handle space exhausted).
    #[error("insufficient resources to allocate service")]
    InsufficientResources,

    /// A pending attribute operation timed out.
    #[error("attribute operation timed out")]
    AttributeTimeout,

    /// Hash computation failed.
    #[error("hash computation failed: {0}")]
    HashComputationFailed(#[from] CryptoError),

    /// The requested service handle range overlaps an existing service.
    #[error("service handle range overlaps existing service")]
    ServiceOverlap,
}

// ---------------------------------------------------------------------------
// Callback type aliases (stored, long-lived)
// ---------------------------------------------------------------------------

/// Attribute read handler — called when an attribute read is initiated.
///
/// Parameters: `(attribute, request_id, offset, opcode, att_transport)`.
type ReadFn = Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// Attribute write handler — called when an attribute write is initiated.
///
/// Parameters: `(attribute, request_id, offset, value, opcode, att_transport)`.
type WriteFn =
    Arc<dyn Fn(GattDbAttribute, u32, u16, &[u8], u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// CCC notification handler — called when an attribute with a CCC descriptor
/// needs to notify.
///
/// Parameters: `(value_attribute, ccc_attribute, value, att_transport)`.
type NotifyFn =
    Arc<dyn Fn(GattDbAttribute, GattDbAttribute, &[u8], Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// Authorization callback — checked before read/write operations.
///
/// Returns `true` to allow, `false` to deny.
type AuthorizeFn =
    Arc<dyn Fn(GattDbAttribute, u8, Option<Arc<Mutex<BtAtt>>>) -> bool + Send + Sync>;

/// Service added/removed notification callback.
type ServiceCb = Arc<dyn Fn(GattDbAttribute) + Send + Sync>;

/// Attribute removal notification callback.
type AttrRemoveCb = Arc<dyn Fn(GattDbAttribute) + Send + Sync>;

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

/// Service data returned by [`GattDbAttribute::get_service_data`].
#[derive(Debug, Clone)]
pub struct ServiceData {
    /// Start handle of the service.
    pub start: u16,
    /// End handle of the service.
    pub end: u16,
    /// `true` for primary service, `false` for secondary.
    pub primary: bool,
    /// Service UUID.
    pub uuid: BtUuid,
}

/// Characteristic data returned by [`GattDbAttribute::get_char_data`].
#[derive(Debug, Clone)]
pub struct CharData {
    /// Handle of the characteristic declaration.
    pub handle: u16,
    /// Handle of the characteristic value attribute.
    pub value_handle: u16,
    /// Characteristic properties byte.
    pub properties: u8,
    /// Extended properties (from CEP descriptor), 0 if absent.
    pub ext_prop: u16,
    /// Characteristic UUID.
    pub uuid: BtUuid,
}

/// Include data returned by [`GattDbAttribute::get_incl_data`].
#[derive(Debug, Clone)]
pub struct InclData {
    /// Handle of the include declaration.
    pub handle: u16,
    /// Start handle of the included service.
    pub start_handle: u16,
    /// End handle of the included service.
    pub end_handle: u16,
}

/// CCC (Client Characteristic Configuration) callback set.
///
/// Register with [`GattDb::ccc_register`] before adding CCC descriptors.
pub struct GattDbCcc {
    /// Read callback for CCC descriptor (may be `None` for default response).
    pub read_func: Option<ReadFn>,
    /// Write callback for CCC descriptor (may be `None` for default response).
    pub write_func: Option<WriteFn>,
    /// Notification callback for characteristic values with CCC.
    pub notify_func: Option<NotifyFn>,
}

// ---------------------------------------------------------------------------
// Internal structures
// ---------------------------------------------------------------------------

/// Internal representation of a single GATT attribute.
struct AttributeInternal {
    handle: u16,
    uuid: BtUuid,
    permissions: u32,
    /// Inline value data (for attributes without `read_func`/`write_func`).
    value: Vec<u8>,
    /// Current/fixed value length. 0 means variable (grows on write).
    value_len: u16,
    read_func: Option<ReadFn>,
    write_func: Option<WriteFn>,
    /// CCC notification function (set on value attribute when CCC is added).
    notify_func: Option<NotifyFn>,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
    /// Auto-incrementing ID counter for pending reads.
    read_id: u32,
    /// Auto-incrementing ID counter for pending writes.
    write_id: u32,
    pending_reads: Vec<PendingRead>,
    pending_writes: Vec<PendingWrite>,
    /// Auto-incrementing ID counter for attribute removal notifications.
    next_notify_id: u32,
    /// Registered removal notification callbacks.
    notify_list: Vec<AttrNotifyEntry>,
}

/// Internal representation of a GATT service (group of attributes).
struct ServiceInternal {
    /// Whether the service is visible to clients.
    active: bool,
    /// Whether the service has been claimed by a profile handler.
    claimed: bool,
    /// Total number of handles allocated for this service.
    num_handles: u16,
    /// Attributes within the service. Index 0 is the service declaration.
    attributes: Vec<AttributeInternal>,
}

/// A pending asynchronous attribute read.
struct PendingRead {
    id: u32,
    timeout_handle: Option<JoinHandle<()>>,
    func: Box<dyn FnOnce(GattDbAttribute, i32, &[u8]) + Send>,
}

/// A pending asynchronous attribute write.
struct PendingWrite {
    id: u32,
    timeout_handle: Option<JoinHandle<()>>,
    func: Box<dyn FnOnce(GattDbAttribute, i32) + Send>,
}

/// DB-level change notification registration.
struct DbNotifyEntry {
    id: u32,
    service_added: Option<ServiceCb>,
    service_removed: Option<ServiceCb>,
}

/// Per-attribute removal notification registration.
struct AttrNotifyEntry {
    id: u32,
    func: AttrRemoveCb,
}

/// Shared inner state of the GATT database, protected by a [`Mutex`].
struct GattDbInner {
    /// Cached 16-byte AES-CMAC database hash.
    hash: [u8; 16],
    /// Handle of the debounce timer for hash recomputation.
    hash_timer: Option<JoinHandle<()>>,
    /// Highest allocated attribute handle.
    last_handle: u16,
    /// All services, sorted by start handle.
    services: Vec<ServiceInternal>,
    /// DB-level change notification registrations.
    notify_list: Vec<DbNotifyEntry>,
    /// Next ID for DB-level change notifications.
    next_notify_id: u32,
    /// CCC descriptor callback set.
    ccc: Option<GattDbCcc>,
    /// Authorization callback checked before read/write.
    authorize: Option<AuthorizeFn>,
}

// ---------------------------------------------------------------------------
// Helper functions (lock-free, operate on borrowed inner)
// ---------------------------------------------------------------------------

/// Find (service_index, attribute_index) for a given handle.
fn find_attr(inner: &GattDbInner, handle: u16) -> Option<(usize, usize)> {
    for (si, svc) in inner.services.iter().enumerate() {
        if svc.attributes.is_empty() {
            continue;
        }
        let start = svc.attributes[0].handle;
        let end = start.saturating_add(svc.num_handles.saturating_sub(1));
        if handle >= start && handle <= end {
            for (ai, attr) in svc.attributes.iter().enumerate() {
                if attr.handle == handle {
                    return Some((si, ai));
                }
            }
            return None;
        }
    }
    None
}

/// Find the service index whose declaration matches `handle`.
fn find_service_idx(inner: &GattDbInner, handle: u16) -> Option<usize> {
    inner
        .services
        .iter()
        .position(|svc| !svc.attributes.is_empty() && svc.attributes[0].handle == handle)
}

/// Return the end handle of a service (start + num_handles - 1).
fn service_end_handle(svc: &ServiceInternal) -> u16 {
    if svc.attributes.is_empty() {
        return 0;
    }
    svc.attributes[0].handle.saturating_add(svc.num_handles.saturating_sub(1))
}

/// Create a new blank attribute for a service at the given handle.
fn new_attribute(handle: u16, uuid: &BtUuid, permissions: u32) -> AttributeInternal {
    AttributeInternal {
        handle,
        uuid: uuid.clone(),
        permissions,
        value: Vec::new(),
        value_len: 0,
        read_func: None,
        write_func: None,
        notify_func: None,
        user_data: None,
        read_id: 0,
        write_id: 0,
        pending_reads: Vec::new(),
        pending_writes: Vec::new(),
        next_notify_id: 0,
        notify_list: Vec::new(),
    }
}

/// Check whether a UUID is a 16-bit type matching `val`.
fn is_uuid16(uuid: &BtUuid, val: u16) -> bool {
    match uuid {
        BtUuid::Uuid16(v) => *v == val,
        _ => false,
    }
}

/// Check whether a UUID matches a service declaration type.
fn is_service_uuid(uuid: &BtUuid) -> bool {
    is_uuid16(uuid, PRIMARY_SERVICE_UUID) || is_uuid16(uuid, SECONDARY_SERVICE_UUID)
}

/// Encode a UUID for inclusion in declaration values (LE byte order).
/// Returns the number of bytes written.
fn uuid_to_le_bytes(uuid: &BtUuid, buf: &mut [u8]) -> usize {
    match uuid {
        BtUuid::Uuid16(v) => {
            if buf.len() >= 2 {
                put_le16(*v, &mut buf[..2]);
            }
            2
        }
        BtUuid::Uuid32(v) => {
            let bytes = BtUuid::Uuid32(*v).to_uuid128_bytes();
            let len = bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&bytes[..len]);
            16
        }
        BtUuid::Uuid128(bytes) => {
            let len = bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&bytes[..len]);
            16
        }
    }
}

/// Decode a UUID from LE bytes in a declaration value.
fn uuid_from_le_bytes(data: &[u8]) -> Option<BtUuid> {
    match data.len() {
        2 => Some(BtUuid::Uuid16(get_le16(data))),
        16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(data);
            Some(BtUuid::Uuid128(bytes))
        }
        _ => None,
    }
}

/// Fire attribute-removal callbacks for all attributes in a service.
fn notify_service_attributes_removed(db: &Arc<Mutex<GattDbInner>>, svc: &ServiceInternal) {
    for attr_int in &svc.attributes {
        let cbs: Vec<AttrRemoveCb> =
            attr_int.notify_list.iter().map(|e| Arc::clone(&e.func)).collect();
        for cb in cbs {
            cb(GattDbAttribute { inner: Arc::clone(db), handle: attr_int.handle });
        }
    }
}

/// Compute the DB hash synchronously, updating inner.hash.
fn compute_hash_locked(db: &Arc<Mutex<GattDbInner>>) {
    let mut inner = db.lock().unwrap();
    // Clear the timer handle so we know the computation is done.
    inner.hash_timer = None;

    // Build scatter-gather list of all hash-eligible attribute data.
    let mut iov: Vec<Vec<u8>> = Vec::new();
    for svc in &inner.services {
        if !svc.active {
            continue;
        }
        for attr in &svc.attributes {
            // Skip hash-ineligible types: CCC (0x2902), CAF (0x2B29)
            if is_uuid16(&attr.uuid, CCC_UUID) || is_uuid16(&attr.uuid, CAF_UUID) {
                continue;
            }
            let mut entry = Vec::new();
            // Handle (2 bytes LE)
            let mut h_buf = [0u8; 2];
            put_le16(attr.handle, &mut h_buf);
            entry.extend_from_slice(&h_buf);
            // UUID in LE format
            let mut u_buf = [0u8; 16];
            let u_len = uuid_to_le_bytes(&attr.uuid, &mut u_buf);
            entry.extend_from_slice(&u_buf[..u_len]);
            // Value for declaration types (service decl, char decl, include, ext prop)
            if is_service_uuid(&attr.uuid)
                || is_uuid16(&attr.uuid, CHARACTERISTIC_UUID)
                || is_uuid16(&attr.uuid, INCLUDED_SERVICE_UUID)
                || is_uuid16(&attr.uuid, CEP_UUID)
            {
                entry.extend_from_slice(&attr.value);
            }
            iov.push(entry);
        }
    }

    let refs: Vec<&[u8]> = iov.iter().map(|v| v.as_slice()).collect();
    match bt_crypto_gatt_hash(&refs) {
        Ok(hash) => {
            inner.hash = hash;
            debug!("DB hash updated: {:02x?}", hash);
        }
        Err(e) => {
            error!("DB hash computation failed: {}", e);
        }
    }
}

// ===========================================================================
// GattDb — the in-memory GATT database
// ===========================================================================

/// In-memory GATT database.
///
/// Thread-safe via interior mutability (`Arc<Mutex<…>>`). Cloning a `GattDb`
/// creates a new shared reference (equivalent to `gatt_db_ref` in C).
#[derive(Clone)]
pub struct GattDb {
    inner: Arc<Mutex<GattDbInner>>,
}

impl GattDb {
    // ----- Lifecycle -----

    /// Create a new, empty GATT database.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(GattDbInner {
                hash: [0u8; 16],
                hash_timer: None,
                last_handle: 0,
                services: Vec::new(),
                notify_list: Vec::new(),
                next_notify_id: 0,
                ccc: None,
                authorize: None,
            })),
        }
    }

    /// Returns `true` if `self` and `other` refer to the same underlying database
    /// (i.e., they are clones sharing the same `Arc` allocation).
    pub fn ptr_eq(&self, other: &GattDb) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Returns `true` if the database contains no services.
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.services.is_empty()
    }

    /// Returns a copy of the current 16-byte database hash.
    pub fn get_hash(&self) -> [u8; 16] {
        let inner = self.inner.lock().unwrap();
        inner.hash
    }

    /// Schedule an asynchronous database hash recomputation.
    ///
    /// The actual computation is debounced by [`HASH_UPDATE_TIMEOUT`]
    /// (100 ms) — repeated calls within the interval reset the timer.
    pub fn hash_update(&self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(handle) = inner.hash_timer.take() {
            handle.abort();
        }
        let db_arc = Arc::clone(&self.inner);
        let handle = tokio::spawn(async move {
            tokio::time::sleep(HASH_UPDATE_TIMEOUT).await;
            compute_hash_locked(&db_arc);
        });
        inner.hash_timer = Some(handle);
    }

    // ----- DB-level notification registration -----

    /// Register callbacks for service addition and removal events.
    ///
    /// Returns a registration ID that can be passed to
    /// [`unregister`](Self::unregister).
    pub fn register(
        &self,
        service_added: Option<impl Fn(GattDbAttribute) + Send + Sync + 'static>,
        service_removed: Option<impl Fn(GattDbAttribute) + Send + Sync + 'static>,
    ) -> u32 {
        let mut inner = self.inner.lock().unwrap();
        inner.next_notify_id += 1;
        let id = inner.next_notify_id;
        inner.notify_list.push(DbNotifyEntry {
            id,
            service_added: service_added.map(|f| Arc::new(f) as ServiceCb),
            service_removed: service_removed.map(|f| Arc::new(f) as ServiceCb),
        });
        id
    }

    /// Remove a DB-level notification registration.
    pub fn unregister(&self, id: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let pos = inner.notify_list.iter().position(|e| e.id == id);
        match pos {
            Some(idx) => {
                inner.notify_list.remove(idx);
                true
            }
            None => false,
        }
    }

    // ----- Authorization & CCC -----

    /// Set the authorization callback checked before attribute reads/writes.
    pub fn set_authorize(
        &self,
        callback: impl Fn(GattDbAttribute, u8, Option<Arc<Mutex<BtAtt>>>) -> bool
        + Send
        + Sync
        + 'static,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.authorize = Some(Arc::new(callback));
    }

    /// Register the CCC callback set. Must be called before
    /// [`GattDbService::add_ccc`].
    pub fn ccc_register(&self, ccc: GattDbCcc) {
        let mut inner = self.inner.lock().unwrap();
        inner.ccc = Some(ccc);
    }

    // ----- Service management -----

    /// Add a new service at the next available handle.
    pub fn add_service(
        &self,
        uuid: &BtUuid,
        primary: bool,
        num_handles: u16,
    ) -> Option<GattDbService> {
        if num_handles < 1 {
            return None;
        }
        let (start, notify_cbs) = {
            let mut inner = self.inner.lock().unwrap();
            let start = inner.last_handle.checked_add(1)?;
            let end = start.checked_add(num_handles.checked_sub(1)?)?;
            // checked_add on u16 returns None on overflow, so `end` is valid.
            let svc_uuid = if primary {
                BtUuid::from_u16(PRIMARY_SERVICE_UUID)
            } else {
                BtUuid::from_u16(SECONDARY_SERVICE_UUID)
            };
            let mut svc_attr = new_attribute(start, &svc_uuid, 0);
            let mut uuid_buf = [0u8; 16];
            let uuid_len = uuid_to_le_bytes(uuid, &mut uuid_buf);
            svc_attr.value = uuid_buf[..uuid_len].to_vec();
            svc_attr.value_len = uuid_len as u16;

            let service = ServiceInternal {
                active: false,
                claimed: false,
                num_handles,
                attributes: vec![svc_attr],
            };
            inner.last_handle = end;
            let pos = inner
                .services
                .iter()
                .position(|s| !s.attributes.is_empty() && s.attributes[0].handle > start)
                .unwrap_or(inner.services.len());
            inner.services.insert(pos, service);
            debug!("service added: handle=0x{:04x}..0x{:04x} primary={}", start, end, primary);
            let cbs: Vec<ServiceCb> =
                inner.notify_list.iter().filter_map(|e| e.service_added.clone()).collect();
            (start, cbs)
        };
        // Fire service-added notifications outside the lock.
        for cb in &notify_cbs {
            cb(GattDbAttribute { inner: Arc::clone(&self.inner), handle: start });
        }
        Some(GattDbService { inner: Arc::clone(&self.inner), handle: start })
    }

    /// Insert a service at a specific handle.
    pub fn insert_service(
        &self,
        handle: u16,
        uuid: &BtUuid,
        primary: bool,
        num_handles: u16,
    ) -> Option<GattDbService> {
        if num_handles < 1 || handle == 0 {
            return None;
        }
        let end = handle.checked_add(num_handles.checked_sub(1)?)?;
        let notify_cbs = {
            let mut inner = self.inner.lock().unwrap();
            // Check overlap with existing services.
            for svc in &inner.services {
                if svc.attributes.is_empty() {
                    continue;
                }
                let s_start = svc.attributes[0].handle;
                let s_end = service_end_handle(svc);
                if handle <= s_end && end >= s_start {
                    if handle == s_start && num_handles == svc.num_handles {
                        return Some(GattDbService {
                            inner: Arc::clone(&self.inner),
                            handle: s_start,
                        });
                    }
                    warn!("service overlap at 0x{:04x}..0x{:04x}", handle, end);
                    return None;
                }
            }
            let svc_uuid = if primary {
                BtUuid::from_u16(PRIMARY_SERVICE_UUID)
            } else {
                BtUuid::from_u16(SECONDARY_SERVICE_UUID)
            };
            let mut svc_attr = new_attribute(handle, &svc_uuid, 0);
            let mut uuid_buf = [0u8; 16];
            let uuid_len = uuid_to_le_bytes(uuid, &mut uuid_buf);
            svc_attr.value = uuid_buf[..uuid_len].to_vec();
            svc_attr.value_len = uuid_len as u16;

            let service = ServiceInternal {
                active: false,
                claimed: false,
                num_handles,
                attributes: vec![svc_attr],
            };
            if end > inner.last_handle {
                inner.last_handle = end;
            }
            let pos = inner
                .services
                .iter()
                .position(|s| !s.attributes.is_empty() && s.attributes[0].handle > handle)
                .unwrap_or(inner.services.len());
            inner.services.insert(pos, service);
            debug!("service inserted: handle=0x{:04x}..0x{:04x}", handle, end);
            let cbs: Vec<ServiceCb> =
                inner.notify_list.iter().filter_map(|e| e.service_added.clone()).collect();
            cbs
        };
        for cb in &notify_cbs {
            cb(GattDbAttribute { inner: Arc::clone(&self.inner), handle });
        }
        Some(GattDbService { inner: Arc::clone(&self.inner), handle })
    }

    /// Remove a service identified by its declaration attribute handle.
    pub fn remove_service(&self, attrib: &GattDbAttribute) -> bool {
        let (removed_svc, notify_cbs) = {
            let mut inner = self.inner.lock().unwrap();
            let idx = match find_service_idx(&inner, attrib.handle) {
                Some(i) => i,
                None => return false,
            };
            let svc = inner.services.remove(idx);
            debug!("service removed: handle=0x{:04x}", attrib.handle);
            let cbs: Vec<ServiceCb> =
                inner.notify_list.iter().filter_map(|e| e.service_removed.clone()).collect();
            (svc, cbs)
        };
        notify_service_attributes_removed(&self.inner, &removed_svc);
        for cb in &notify_cbs {
            cb(GattDbAttribute { inner: Arc::clone(&self.inner), handle: attrib.handle });
        }
        true
    }

    /// Remove all services from the database.
    pub fn clear(&self) -> bool {
        let (removed_services, notify_cbs) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.services.is_empty() {
                return true;
            }
            let svcs = std::mem::take(&mut inner.services);
            let cbs: Vec<ServiceCb> =
                inner.notify_list.iter().filter_map(|e| e.service_removed.clone()).collect();
            inner.last_handle = 0;
            (svcs, cbs)
        };
        for svc in &removed_services {
            notify_service_attributes_removed(&self.inner, svc);
            if let Some(decl) = svc.attributes.first() {
                for cb in &notify_cbs {
                    cb(GattDbAttribute { inner: Arc::clone(&self.inner), handle: decl.handle });
                }
            }
        }
        true
    }

    /// Remove all services whose start handle falls within the given range.
    pub fn clear_range(&self, start_handle: u16, end_handle: u16) -> bool {
        let (removed, notify_cbs) = {
            let mut inner = self.inner.lock().unwrap();
            let mut removed = Vec::new();
            let mut kept = Vec::new();
            for svc in std::mem::take(&mut inner.services) {
                if svc.attributes.is_empty() {
                    kept.push(svc);
                    continue;
                }
                let s = svc.attributes[0].handle;
                if s >= start_handle && s <= end_handle {
                    removed.push(svc);
                } else {
                    kept.push(svc);
                }
            }
            inner.services = kept;
            let cbs: Vec<ServiceCb> =
                inner.notify_list.iter().filter_map(|e| e.service_removed.clone()).collect();
            (removed, cbs)
        };
        for svc in &removed {
            notify_service_attributes_removed(&self.inner, svc);
            if let Some(decl) = svc.attributes.first() {
                for cb in &notify_cbs {
                    cb(GattDbAttribute { inner: Arc::clone(&self.inner), handle: decl.handle });
                }
            }
        }
        true
    }

    // ----- Discovery -----

    /// Discover services by group type (primary/secondary) in a handle range.
    ///
    /// Returns service declaration attributes whose type matches
    /// `type_uuid` (typically 0x2800 or 0x2801).
    pub fn read_by_group_type(
        &self,
        start: u16,
        end: u16,
        type_uuid: &BtUuid,
    ) -> Vec<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let mut result = Vec::new();
        for svc in &inner.services {
            if !svc.active || svc.attributes.is_empty() {
                continue;
            }
            let decl = &svc.attributes[0];
            if decl.handle < start || decl.handle > end {
                continue;
            }
            if decl.uuid == *type_uuid {
                result
                    .push(GattDbAttribute { inner: Arc::clone(&self.inner), handle: decl.handle });
            }
        }
        result
    }

    /// Find services by type UUID in a handle range.
    pub fn find_by_type(&self, start: u16, end: u16, type_uuid: &BtUuid) -> Vec<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let mut result = Vec::new();
        for svc in &inner.services {
            if !svc.active || svc.attributes.is_empty() {
                continue;
            }
            let decl = &svc.attributes[0];
            if decl.handle < start || decl.handle > end {
                continue;
            }
            if decl.uuid == *type_uuid {
                result
                    .push(GattDbAttribute { inner: Arc::clone(&self.inner), handle: decl.handle });
            }
        }
        result
    }

    /// Find services by type UUID and service UUID value.
    pub fn find_by_type_value(
        &self,
        start: u16,
        end: u16,
        type_uuid: &BtUuid,
        value: &[u8],
    ) -> Vec<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let mut result = Vec::new();
        for svc in &inner.services {
            if !svc.active || svc.attributes.is_empty() {
                continue;
            }
            let decl = &svc.attributes[0];
            if decl.handle < start || decl.handle > end {
                continue;
            }
            if decl.uuid == *type_uuid && decl.value == value {
                result
                    .push(GattDbAttribute { inner: Arc::clone(&self.inner), handle: decl.handle });
            }
        }
        result
    }

    /// Read attributes by type UUID within a handle range.
    ///
    /// Iterates across all active services and returns attributes whose
    /// UUID matches `type_uuid`.
    pub fn read_by_type(&self, start: u16, end: u16, type_uuid: &BtUuid) -> Vec<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let mut result = Vec::new();
        for svc in &inner.services {
            if !svc.active {
                continue;
            }
            for attr in &svc.attributes {
                if attr.handle < start || attr.handle > end {
                    continue;
                }
                if attr.uuid == *type_uuid {
                    result.push(GattDbAttribute {
                        inner: Arc::clone(&self.inner),
                        handle: attr.handle,
                    });
                }
            }
        }
        result
    }

    /// Return all attributes in a handle range (Find Information).
    pub fn find_information(&self, start_handle: u16, end_handle: u16) -> Vec<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let mut result = Vec::new();
        for svc in &inner.services {
            if !svc.active {
                continue;
            }
            for attr in &svc.attributes {
                if attr.handle < start_handle || attr.handle > end_handle {
                    continue;
                }
                result
                    .push(GattDbAttribute { inner: Arc::clone(&self.inner), handle: attr.handle });
            }
        }
        result
    }

    /// Look up a single attribute by its handle.
    pub fn get_attribute(&self, handle: u16) -> Option<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        find_attr(&inner, handle)
            .map(|_| GattDbAttribute { inner: Arc::clone(&self.inner), handle })
    }

    /// Look up the service declaration attribute for a given handle.
    ///
    /// If `handle` falls within a service's handle range, returns the
    /// service declaration (first attribute).
    pub fn get_service(&self, handle: u16) -> Option<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        for svc in &inner.services {
            if svc.attributes.is_empty() {
                continue;
            }
            let s = svc.attributes[0].handle;
            let e = service_end_handle(svc);
            if handle >= s && handle <= e {
                return Some(GattDbAttribute { inner: Arc::clone(&self.inner), handle: s });
            }
        }
        None
    }

    /// Find the first service whose declaration value matches `uuid`.
    pub fn get_service_with_uuid(&self, uuid: &BtUuid) -> Option<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let mut uuid_buf = [0u8; 16];
        let uuid_len = uuid_to_le_bytes(uuid, &mut uuid_buf);
        let target = &uuid_buf[..uuid_len];
        for svc in &inner.services {
            if svc.attributes.is_empty() {
                continue;
            }
            let decl = &svc.attributes[0];
            if decl.value == target {
                return Some(GattDbAttribute {
                    inner: Arc::clone(&self.inner),
                    handle: decl.handle,
                });
            }
        }
        None
    }

    // ----- Iteration -----

    /// Iterate over all services, optionally filtered by service UUID.
    pub fn foreach_service(&self, uuid: Option<&BtUuid>, mut func: impl FnMut(GattDbAttribute)) {
        self.foreach_service_in_range(uuid, &mut func, 0x0001, 0xFFFF);
    }

    /// Iterate over services in a handle range, optionally filtered by UUID.
    pub fn foreach_service_in_range(
        &self,
        uuid: Option<&BtUuid>,
        func: &mut dyn FnMut(GattDbAttribute),
        start_handle: u16,
        end_handle: u16,
    ) {
        let handles: Vec<u16> = {
            let inner = self.inner.lock().unwrap();
            let mut result = Vec::new();
            let uuid_bytes = uuid.map(|u| {
                let mut buf = [0u8; 16];
                let len = uuid_to_le_bytes(u, &mut buf);
                buf[..len].to_vec()
            });
            for svc in &inner.services {
                if svc.attributes.is_empty() {
                    continue;
                }
                let decl = &svc.attributes[0];
                if decl.handle < start_handle || decl.handle > end_handle {
                    continue;
                }
                if let Some(ref target) = uuid_bytes {
                    if decl.value != *target {
                        continue;
                    }
                }
                result.push(decl.handle);
            }
            result
        };
        for h in handles {
            func(GattDbAttribute { inner: Arc::clone(&self.inner), handle: h });
        }
    }

    /// Iterate over individual attributes in a handle range, optionally
    /// filtered by attribute type UUID.
    pub fn foreach_in_range(
        &self,
        uuid: Option<&BtUuid>,
        mut func: impl FnMut(GattDbAttribute),
        start_handle: u16,
        end_handle: u16,
    ) {
        let handles: Vec<u16> = {
            let inner = self.inner.lock().unwrap();
            let mut result = Vec::new();
            for svc in &inner.services {
                for attr in &svc.attributes {
                    if attr.handle < start_handle || attr.handle > end_handle {
                        continue;
                    }
                    if let Some(u) = uuid {
                        if attr.uuid != *u {
                            continue;
                        }
                    }
                    result.push(attr.handle);
                }
            }
            result
        };
        for h in handles {
            func(GattDbAttribute { inner: Arc::clone(&self.inner), handle: h });
        }
    }
}

impl Default for GattDb {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// GattDbService — handle to a service within the database
// ===========================================================================

/// Handle to a GATT service within the database.
///
/// Created by [`GattDb::add_service`] or [`GattDb::insert_service`].
/// Cloning is cheap (shared reference).
#[derive(Clone)]
pub struct GattDbService {
    inner: Arc<Mutex<GattDbInner>>,
    /// Handle of the service declaration attribute.
    handle: u16,
}

impl GattDbService {
    // ----- Characteristic management -----

    /// Add a characteristic at the next available handle within this service.
    ///
    /// Creates two attributes: declaration and value. Returns the value
    /// attribute handle.
    pub fn add_characteristic(
        &self,
        uuid: &BtUuid,
        permissions: u32,
        properties: u8,
        read_func: Option<ReadFn>,
        write_func: Option<WriteFn>,
        user_data: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Option<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let si = find_service_idx(&inner, self.handle)?;
        let svc = &inner.services[si];
        let attr_count = svc.attributes.len() as u16;
        // Need 2 handles: declaration + value
        if attr_count + 2 > svc.num_handles {
            return None;
        }
        let decl_handle = svc.attributes[0].handle + attr_count;
        let value_handle = decl_handle + 1;
        drop(inner);
        self.insert_characteristic_inner(
            decl_handle,
            value_handle,
            uuid,
            permissions,
            properties,
            read_func,
            write_func,
            user_data,
        )
    }

    /// Insert a characteristic at specific handles.
    pub fn insert_characteristic(
        &self,
        handle: u16,
        uuid: &BtUuid,
        permissions: u32,
        properties: u8,
        read_func: Option<ReadFn>,
        write_func: Option<WriteFn>,
        user_data: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Option<GattDbAttribute> {
        let value_handle = handle.checked_add(1)?;
        self.insert_characteristic_inner(
            handle,
            value_handle,
            uuid,
            permissions,
            properties,
            read_func,
            write_func,
            user_data,
        )
    }

    fn insert_characteristic_inner(
        &self,
        decl_handle: u16,
        value_handle: u16,
        uuid: &BtUuid,
        permissions: u32,
        properties: u8,
        read_func: Option<ReadFn>,
        write_func: Option<WriteFn>,
        user_data: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Option<GattDbAttribute> {
        let mut inner = self.inner.lock().unwrap();
        let si = find_service_idx(&inner, self.handle)?;

        // Build declaration value: [properties(1) + value_handle_le16(2) + uuid(2 or 16)]
        let char_decl_uuid = BtUuid::from_u16(CHARACTERISTIC_UUID);
        let mut decl_value = Vec::with_capacity(MAX_CHAR_DECL_VALUE_LEN);
        decl_value.push(properties);
        let mut vh_buf = [0u8; 2];
        put_le16(value_handle, &mut vh_buf);
        decl_value.extend_from_slice(&vh_buf);
        let mut uuid_buf = [0u8; 16];
        let uuid_len = uuid_to_le_bytes(uuid, &mut uuid_buf);
        decl_value.extend_from_slice(&uuid_buf[..uuid_len]);

        let mut decl_attr = new_attribute(decl_handle, &char_decl_uuid, 0);
        decl_attr.value_len = decl_value.len() as u16;
        decl_attr.value = decl_value;

        let mut val_attr = new_attribute(value_handle, uuid, permissions);
        val_attr.read_func = read_func;
        val_attr.write_func = write_func;
        val_attr.user_data = user_data;

        // Find insertion index (sorted by handle)
        let svc = &mut inner.services[si];
        let idx = svc
            .attributes
            .iter()
            .position(|a| a.handle > decl_handle)
            .unwrap_or(svc.attributes.len());
        svc.attributes.insert(idx, decl_attr);
        svc.attributes.insert(idx + 1, val_attr);

        Some(GattDbAttribute { inner: Arc::clone(&self.inner), handle: value_handle })
    }

    // ----- Descriptor management -----

    /// Add a descriptor at the next available handle.
    pub fn add_descriptor(
        &self,
        uuid: &BtUuid,
        permissions: u32,
        read_func: Option<ReadFn>,
        write_func: Option<WriteFn>,
        user_data: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Option<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let si = find_service_idx(&inner, self.handle)?;
        let svc = &inner.services[si];
        let attr_count = svc.attributes.len() as u16;
        if attr_count + 1 > svc.num_handles {
            return None;
        }
        let desc_handle = svc.attributes[0].handle + attr_count;
        drop(inner);
        self.insert_descriptor(desc_handle, uuid, permissions, read_func, write_func, user_data)
    }

    /// Insert a descriptor at a specific handle.
    pub fn insert_descriptor(
        &self,
        handle: u16,
        uuid: &BtUuid,
        permissions: u32,
        read_func: Option<ReadFn>,
        write_func: Option<WriteFn>,
        user_data: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Option<GattDbAttribute> {
        let mut inner = self.inner.lock().unwrap();
        let si = find_service_idx(&inner, self.handle)?;
        let svc = &mut inner.services[si];

        let mut attr = new_attribute(handle, uuid, permissions);
        attr.read_func = read_func;
        attr.write_func = write_func;
        attr.user_data = user_data;

        let idx =
            svc.attributes.iter().position(|a| a.handle > handle).unwrap_or(svc.attributes.len());
        svc.attributes.insert(idx, attr);

        Some(GattDbAttribute { inner: Arc::clone(&self.inner), handle })
    }

    // ----- Include management -----

    /// Add an included-service declaration at the next available handle.
    pub fn add_included(&self, include: &GattDbAttribute) -> Option<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let si = find_service_idx(&inner, self.handle)?;
        let svc = &inner.services[si];
        let attr_count = svc.attributes.len() as u16;
        if attr_count + 1 > svc.num_handles {
            return None;
        }
        let incl_handle = svc.attributes[0].handle + attr_count;
        drop(inner);
        self.insert_included(incl_handle, include)
    }

    /// Insert an included-service declaration at a specific handle.
    pub fn insert_included(
        &self,
        handle: u16,
        include: &GattDbAttribute,
    ) -> Option<GattDbAttribute> {
        let mut inner = self.inner.lock().unwrap();
        let si = find_service_idx(&inner, self.handle)?;

        // Get included service's start/end handles and UUID.
        let incl_si = find_service_idx(&inner, include.handle)?;
        let incl_svc = &inner.services[incl_si];
        let incl_start = incl_svc.attributes[0].handle;
        let incl_end = service_end_handle(incl_svc);
        let incl_svc_uuid_bytes = incl_svc.attributes[0].value.clone();

        let incl_uuid = BtUuid::from_u16(INCLUDED_SERVICE_UUID);
        let mut attr = new_attribute(handle, &incl_uuid, 0);

        // Value: [start_handle_le16 + end_handle_le16 + optional uuid16_le16]
        let mut val = Vec::with_capacity(MAX_INCLUDED_VALUE_LEN);
        let mut buf = [0u8; 2];
        put_le16(incl_start, &mut buf);
        val.extend_from_slice(&buf);
        put_le16(incl_end, &mut buf);
        val.extend_from_slice(&buf);
        // Include UUID16 only if the included service's UUID is 16-bit.
        if incl_svc_uuid_bytes.len() == 2 {
            val.extend_from_slice(&incl_svc_uuid_bytes);
        }
        attr.value_len = val.len() as u16;
        attr.value = val;

        let svc = &mut inner.services[si];
        let idx =
            svc.attributes.iter().position(|a| a.handle > handle).unwrap_or(svc.attributes.len());
        svc.attributes.insert(idx, attr);

        Some(GattDbAttribute { inner: Arc::clone(&self.inner), handle })
    }

    // ----- CCC -----

    /// Add a CCC (Client Characteristic Configuration) descriptor for the
    /// most recently added characteristic.
    pub fn add_ccc(&self, permissions: u32) -> Option<GattDbAttribute> {
        let mut inner = self.inner.lock().unwrap();
        let si = find_service_idx(&inner, self.handle)?;

        // CCC callbacks must be registered on the DB first.
        let ccc_ref = inner.ccc.as_ref()?;
        let ccc_read = ccc_ref.read_func.clone();
        let ccc_write = ccc_ref.write_func.clone();
        let ccc_notify = ccc_ref.notify_func.clone();

        let svc = &inner.services[si];
        let attr_count = svc.attributes.len() as u16;
        if attr_count + 1 > svc.num_handles {
            return None;
        }
        let ccc_handle = svc.attributes[0].handle + attr_count;

        // Find the last characteristic's value attribute by walking backward.
        let mut value_attr_idx: Option<usize> = None;
        for ai in (0..svc.attributes.len()).rev() {
            let a = &svc.attributes[ai];
            if is_uuid16(&a.uuid, CHARACTERISTIC_UUID) {
                // Found a char declaration; value attr is at ai+1.
                if ai + 1 < svc.attributes.len() {
                    value_attr_idx = Some(ai + 1);
                }
                break;
            }
        }

        let svc = &mut inner.services[si];

        let ccc_uuid = BtUuid::from_u16(CCC_UUID);
        let ccc_perms = (AttPermissions::READ.bits() as u32)
            | (AttPermissions::WRITE.bits() as u32)
            | permissions;
        let mut ccc_attr = new_attribute(ccc_handle, &ccc_uuid, ccc_perms);
        ccc_attr.value_len = 2; // Fixed 2-byte CCC value.

        // Set up read/write callbacks that delegate to the registered CCC handlers.
        if let Some(rf) = ccc_read {
            ccc_attr.read_func = Some(rf);
        } else {
            // Default CCC read: respond with empty value.
            ccc_attr.read_func = Some(Arc::new(
                move |attr: GattDbAttribute,
                      id: u32,
                      _offset: u16,
                      _opcode: u8,
                      _att: Option<Arc<Mutex<BtAtt>>>| {
                    attr.read_result(id, 0, &[]);
                },
            ));
        }
        if let Some(wf) = ccc_write {
            ccc_attr.write_func = Some(wf);
        } else {
            // Default CCC write: respond with success.
            ccc_attr.write_func = Some(Arc::new(
                move |attr: GattDbAttribute,
                      id: u32,
                      _offset: u16,
                      _value: &[u8],
                      _opcode: u8,
                      _att: Option<Arc<Mutex<BtAtt>>>| {
                    attr.write_result(id, 0);
                },
            ));
        }

        // Set notify_func on the value attribute.
        if let Some(vai) = value_attr_idx {
            if let Some(nf) = ccc_notify {
                svc.attributes[vai].notify_func = Some(nf);
            }
        }

        let idx = svc
            .attributes
            .iter()
            .position(|a| a.handle > ccc_handle)
            .unwrap_or(svc.attributes.len());
        svc.attributes.insert(idx, ccc_attr);

        Some(GattDbAttribute { inner: Arc::clone(&self.inner), handle: ccc_handle })
    }

    // ----- Service state -----

    /// Set whether the service is active (visible to discovery).
    pub fn set_active(&self, active: bool) -> bool {
        let (changed, notify_cbs) = {
            let mut inner = self.inner.lock().unwrap();
            let si = match find_service_idx(&inner, self.handle) {
                Some(i) => i,
                None => return false,
            };
            let was_active = inner.services[si].active;
            inner.services[si].active = active;
            if active == was_active {
                return true;
            }
            let cbs: Vec<ServiceCb> = if active {
                inner.notify_list.iter().filter_map(|e| e.service_added.clone()).collect()
            } else {
                inner.notify_list.iter().filter_map(|e| e.service_removed.clone()).collect()
            };
            (true, cbs)
        };
        for cb in &notify_cbs {
            cb(GattDbAttribute { inner: Arc::clone(&self.inner), handle: self.handle });
        }
        changed
    }

    /// Returns `true` if the service is active.
    pub fn get_active(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        find_service_idx(&inner, self.handle).map(|si| inner.services[si].active).unwrap_or(false)
    }

    /// Set whether the service has been claimed by a profile handler.
    pub fn set_claimed(&self, claimed: bool) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match find_service_idx(&inner, self.handle) {
            Some(si) => {
                inner.services[si].claimed = claimed;
                true
            }
            None => false,
        }
    }

    /// Returns `true` if the service has been claimed.
    pub fn get_claimed(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        find_service_idx(&inner, self.handle).map(|si| inner.services[si].claimed).unwrap_or(false)
    }

    // ----- Per-service iteration -----

    /// Iterate attributes within this service, optionally filtered by UUID.
    pub fn foreach(&self, uuid: Option<&BtUuid>, mut func: impl FnMut(GattDbAttribute)) {
        let handles: Vec<u16> = {
            let inner = self.inner.lock().unwrap();
            match find_service_idx(&inner, self.handle) {
                Some(si) => inner.services[si]
                    .attributes
                    .iter()
                    .filter(|a| uuid.is_none_or(|u| a.uuid == *u))
                    .map(|a| a.handle)
                    .collect(),
                None => Vec::new(),
            }
        };
        for h in handles {
            func(GattDbAttribute { inner: Arc::clone(&self.inner), handle: h });
        }
    }

    /// Iterate characteristic declaration attributes within this service.
    pub fn foreach_char(&self, func: impl FnMut(GattDbAttribute)) {
        let char_uuid = BtUuid::from_u16(CHARACTERISTIC_UUID);
        self.foreach(Some(&char_uuid), func);
    }

    /// Iterate descriptor attributes following the last characteristic.
    ///
    /// Descriptors are all attributes between the characteristic value
    /// attribute and the next characteristic declaration (or end of service).
    pub fn foreach_desc(&self, mut func: impl FnMut(GattDbAttribute)) {
        let handles: Vec<u16> = {
            let inner = self.inner.lock().unwrap();
            let si = match find_service_idx(&inner, self.handle) {
                Some(i) => i,
                None => return,
            };
            let svc = &inner.services[si];
            let mut result = Vec::new();
            // Find descriptors: walk from end, find last char decl,
            // then collect attributes between value and next char/end.
            let attrs = &svc.attributes;
            let mut i = 0;
            while i < attrs.len() {
                if is_uuid16(&attrs[i].uuid, CHARACTERISTIC_UUID) {
                    // Skip declaration and value attributes (i, i+1).
                    i += 2;
                    // Collect descriptors until next char decl or end.
                    while i < attrs.len()
                        && !is_uuid16(&attrs[i].uuid, CHARACTERISTIC_UUID)
                        && !is_service_uuid(&attrs[i].uuid)
                    {
                        result.push(attrs[i].handle);
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            result
        };
        for h in handles {
            func(GattDbAttribute { inner: Arc::clone(&self.inner), handle: h });
        }
    }

    /// Iterate included-service declaration attributes.
    pub fn foreach_incl(&self, func: impl FnMut(GattDbAttribute)) {
        let incl_uuid = BtUuid::from_u16(INCLUDED_SERVICE_UUID);
        self.foreach(Some(&incl_uuid), func);
    }

    /// Returns a [`GattDbAttribute`] handle for this service's declaration.
    pub fn as_attribute(&self) -> GattDbAttribute {
        GattDbAttribute { inner: Arc::clone(&self.inner), handle: self.handle }
    }
}

// ===========================================================================
// GattDbAttribute — handle to a single attribute
// ===========================================================================

/// Handle to a single GATT attribute within the database.
///
/// This is a lightweight, cheaply cloneable handle. The underlying
/// attribute data is owned by the [`GattDb`] inner state.
#[derive(Clone)]
pub struct GattDbAttribute {
    inner: Arc<Mutex<GattDbInner>>,
    handle: u16,
}

impl GattDbAttribute {
    // ----- Accessors -----

    /// Return the attribute's type UUID.
    pub fn get_type(&self) -> Option<BtUuid> {
        let inner = self.inner.lock().unwrap();
        let (si, ai) = find_attr(&inner, self.handle)?;
        Some(inner.services[si].attributes[ai].uuid.clone())
    }

    /// Return the attribute handle.
    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    /// Return a [`GattDbService`] handle for the service this attribute
    /// belongs to.
    pub fn get_service(&self) -> Option<GattDbService> {
        let inner = self.inner.lock().unwrap();
        let (si, _) = find_attr(&inner, self.handle)?;
        let svc = &inner.services[si];
        if svc.attributes.is_empty() {
            return None;
        }
        Some(GattDbService { inner: Arc::clone(&self.inner), handle: svc.attributes[0].handle })
    }

    /// Return the UUID of the service this attribute belongs to.
    pub fn get_service_uuid(&self) -> Option<BtUuid> {
        let inner = self.inner.lock().unwrap();
        let (si, _) = find_attr(&inner, self.handle)?;
        let svc = &inner.services[si];
        if svc.attributes.is_empty() {
            return None;
        }
        uuid_from_le_bytes(&svc.attributes[0].value)
    }

    /// Return `(start_handle, end_handle)` of the containing service.
    pub fn get_service_handles(&self) -> Option<(u16, u16)> {
        let inner = self.inner.lock().unwrap();
        let (si, _) = find_attr(&inner, self.handle)?;
        let svc = &inner.services[si];
        if svc.attributes.is_empty() {
            return None;
        }
        let start = svc.attributes[0].handle;
        let end = service_end_handle(svc);
        Some((start, end))
    }

    /// Return full service data if this attribute is a service declaration.
    pub fn get_service_data(&self) -> Option<ServiceData> {
        let inner = self.inner.lock().unwrap();
        let (si, ai) = find_attr(&inner, self.handle)?;
        let svc = &inner.services[si];
        let attr = &svc.attributes[ai];
        // Must be a service declaration.
        if !is_service_uuid(&attr.uuid) {
            return None;
        }
        let start = svc.attributes[0].handle;
        let end = service_end_handle(svc);
        let primary = is_uuid16(&attr.uuid, PRIMARY_SERVICE_UUID);
        let uuid = uuid_from_le_bytes(&attr.value)?;
        Some(ServiceData { start, end, primary, uuid })
    }

    /// Return characteristic data for this attribute.
    ///
    /// Accepts either the characteristic declaration or value attribute.
    pub fn get_char_data(&self) -> Option<CharData> {
        let inner = self.inner.lock().unwrap();
        let (si, ai) = find_attr(&inner, self.handle)?;
        let svc = &inner.services[si];
        let attr = &svc.attributes[ai];

        // Determine which attribute is the declaration.
        let decl_idx = if is_uuid16(&attr.uuid, CHARACTERISTIC_UUID) {
            ai
        } else if ai > 0 && is_uuid16(&svc.attributes[ai - 1].uuid, CHARACTERISTIC_UUID) {
            ai - 1
        } else {
            return None;
        };

        let decl = &svc.attributes[decl_idx];
        if decl.value.len() < 5 {
            return None; // Minimum: 1(props) + 2(handle) + 2(uuid16)
        }
        let raw_props = decl.value[0];
        // Validate properties through the typed bitflags representation.
        let _typed_props = GattChrcProperties::from_bits_truncate(raw_props);
        let value_handle = get_le16(&decl.value[1..3]);
        let uuid = uuid_from_le_bytes(&decl.value[3..])?;

        // Search for extended properties descriptor.
        let ext_prop_raw = get_char_extended_prop(svc, decl_idx);
        // Validate extended properties through the typed bitflags representation.
        let _typed_ext = GattChrcExtProperties::from_bits_truncate(ext_prop_raw as u8);

        Some(CharData {
            handle: decl.handle,
            value_handle,
            properties: raw_props,
            ext_prop: ext_prop_raw,
            uuid,
        })
    }

    /// Return include data for this attribute (must be an include declaration).
    pub fn get_incl_data(&self) -> Option<InclData> {
        let inner = self.inner.lock().unwrap();
        let (si, ai) = find_attr(&inner, self.handle)?;
        let attr = &inner.services[si].attributes[ai];
        if !is_uuid16(&attr.uuid, INCLUDED_SERVICE_UUID) {
            return None;
        }
        if attr.value.len() < 4 {
            return None;
        }
        let start_handle = get_le16(&attr.value[0..2]);
        let end_handle = get_le16(&attr.value[2..4]);
        Some(InclData { handle: attr.handle, start_handle, end_handle })
    }

    /// Return the attribute's permission mask.
    pub fn get_permissions(&self) -> u32 {
        let inner = self.inner.lock().unwrap();
        find_attr(&inner, self.handle)
            .map(|(si, ai)| inner.services[si].attributes[ai].permissions)
            .unwrap_or(0)
    }

    /// Return a copy of the attribute's inline value bytes.
    ///
    /// Returns an empty vector if the attribute has no stored value or the
    /// handle is invalid.
    pub fn get_value(&self) -> Vec<u8> {
        let inner = self.inner.lock().unwrap();
        match find_attr(&inner, self.handle) {
            Some((si, ai)) => inner.services[si].attributes[ai].value.clone(),
            None => Vec::new(),
        }
    }

    // ----- Async Read -----

    /// Initiate an attribute read operation.
    ///
    /// If the attribute has a `read_func`, an authorization check is performed
    /// first, then the read handler is invoked asynchronously. The `func`
    /// callback is called when the result is ready (via [`read_result`]) or on
    /// timeout.
    ///
    /// If no `read_func` is set, the inline value is returned immediately.
    pub fn read(
        &self,
        offset: u16,
        opcode: u8,
        att: Option<Arc<Mutex<BtAtt>>>,
        func: impl FnOnce(GattDbAttribute, i32, &[u8]) + Send + 'static,
    ) -> bool {
        // Phase 1: extract state under lock.
        let extract = {
            let inner = self.inner.lock().unwrap();
            let (si, ai) = match find_attr(&inner, self.handle) {
                Some(x) => x,
                None => return false,
            };
            let attr_int = &inner.services[si].attributes[ai];
            if attr_int.value_len > 0 && offset > attr_int.value_len {
                return false;
            }
            if attr_int.read_func.is_some() {
                ReadExtract::HasFunc {
                    read_func: attr_int.read_func.clone().unwrap(),
                    authorize: inner.authorize.clone(),
                }
            } else {
                let ofs = offset as usize;
                let value = if ofs >= attr_int.value.len() {
                    Vec::new()
                } else {
                    attr_int.value[ofs..].to_vec()
                };
                ReadExtract::Inline(value)
            }
        };

        match extract {
            ReadExtract::Inline(value) => {
                func(self.clone(), 0, &value);
                true
            }
            ReadExtract::HasFunc { read_func, authorize } => {
                // Phase 2: authorize outside lock.
                if let Some(auth_fn) = authorize {
                    if !auth_fn(self.clone(), opcode, att.clone()) {
                        func(self.clone(), 0x08, &[]); // AUTHORIZATION error
                        return true;
                    }
                }
                // Phase 3: create pending read under lock.
                let id = {
                    let mut inner = self.inner.lock().unwrap();
                    let (si, ai) = match find_attr(&inner, self.handle) {
                        Some(x) => x,
                        None => return false,
                    };
                    let attr_int = &mut inner.services[si].attributes[ai];
                    attr_int.read_id += 1;
                    let id = attr_int.read_id;
                    let db_clone = Arc::clone(&self.inner);
                    let h = self.handle;
                    let timeout = tokio::spawn(async move {
                        tokio::time::sleep(ATTRIBUTE_TIMEOUT).await;
                        let pending = {
                            let mut inner = db_clone.lock().unwrap();
                            match find_attr(&inner, h) {
                                Some((si2, ai2)) => {
                                    let a = &mut inner.services[si2].attributes[ai2];
                                    let pos = a.pending_reads.iter().position(|p| p.id == id);
                                    pos.map(|idx| a.pending_reads.remove(idx))
                                }
                                None => None,
                            }
                        };
                        if let Some(p) = pending {
                            error!("attribute read timed out: handle=0x{:04x}", h);
                            (p.func)(
                                GattDbAttribute { inner: db_clone, handle: h },
                                ETIMEDOUT,
                                &[],
                            );
                        }
                    });
                    attr_int.pending_reads.push(PendingRead {
                        id,
                        timeout_handle: Some(timeout),
                        func: Box::new(func),
                    });
                    id
                };
                // Phase 4: call read_func outside lock.
                read_func(self.clone(), id, offset, opcode, att);
                true
            }
        }
    }

    /// Complete a pending read operation.
    ///
    /// `id` is the request ID passed to the `read_func` callback.
    pub fn read_result(&self, id: u32, err: i32, value: &[u8]) -> bool {
        let pending = {
            let mut inner = self.inner.lock().unwrap();
            match find_attr(&inner, self.handle) {
                Some((si, ai)) => {
                    let attr_int = &mut inner.services[si].attributes[ai];
                    let pos = attr_int.pending_reads.iter().position(|p| p.id == id);
                    pos.map(|idx| attr_int.pending_reads.remove(idx))
                }
                None => None,
            }
        };
        match pending {
            Some(mut p) => {
                if let Some(handle) = p.timeout_handle.take() {
                    handle.abort();
                }
                (p.func)(self.clone(), err, value);
                true
            }
            None => false,
        }
    }

    // ----- Async Write -----

    /// Initiate an attribute write operation.
    pub fn write(
        &self,
        offset: u16,
        value: &[u8],
        opcode: u8,
        att: Option<Arc<Mutex<BtAtt>>>,
        func: Option<Box<dyn FnOnce(GattDbAttribute, i32) + Send + 'static>>,
    ) -> bool {
        // Phase 1: extract state under lock.
        let extract = {
            let inner = self.inner.lock().unwrap();
            let (si, ai) = match find_attr(&inner, self.handle) {
                Some(x) => x,
                None => return false,
            };
            let attr_int = &inner.services[si].attributes[ai];
            if attr_int.write_func.is_some() {
                // Check boundaries for fixed-length attributes.
                if attr_int.value_len > 0 {
                    if offset > attr_int.value_len {
                        if let Some(f) = func {
                            f(self.clone(), 0x07); // INVALID_OFFSET
                        }
                        return true;
                    }
                    if (offset as usize) + value.len() > attr_int.value_len as usize {
                        if let Some(f) = func {
                            f(self.clone(), 0x0D); // INVALID_ATTRIBUTE_VALUE_LEN
                        }
                        return true;
                    }
                }
                WriteExtract::HasFunc {
                    write_func: attr_int.write_func.clone().unwrap(),
                    authorize: inner.authorize.clone(),
                }
            } else {
                WriteExtract::Inline
            }
        };

        match extract {
            WriteExtract::Inline => {
                // Inline write: store value directly.
                if !value.is_empty() {
                    let mut inner = self.inner.lock().unwrap();
                    if let Some((si, ai)) = find_attr(&inner, self.handle) {
                        let attr_int = &mut inner.services[si].attributes[ai];
                        let new_end = (offset as usize) + value.len();
                        if attr_int.value.len() < new_end || attr_int.value_len == 0 {
                            attr_int.value.resize(new_end, 0);
                            attr_int.value_len = new_end as u16;
                        }
                        attr_int.value[offset as usize..offset as usize + value.len()]
                            .copy_from_slice(value);
                    }
                }
                if let Some(f) = func {
                    f(self.clone(), 0);
                }
                true
            }
            WriteExtract::HasFunc { write_func, authorize } => {
                // Phase 2: authorize outside lock.
                if let Some(auth_fn) = authorize {
                    if !auth_fn(self.clone(), opcode, att.clone()) {
                        if let Some(f) = func {
                            f(self.clone(), 0x08); // AUTHORIZATION
                        }
                        return true;
                    }
                }
                // Phase 3: create pending write under lock.
                let id = {
                    let mut inner = self.inner.lock().unwrap();
                    let (si, ai) = match find_attr(&inner, self.handle) {
                        Some(x) => x,
                        None => return false,
                    };
                    let attr_int = &mut inner.services[si].attributes[ai];
                    attr_int.write_id += 1;
                    let id = attr_int.write_id;

                    if let Some(f) = func {
                        let db_clone = Arc::clone(&self.inner);
                        let h = self.handle;
                        let timeout = tokio::spawn(async move {
                            tokio::time::sleep(ATTRIBUTE_TIMEOUT).await;
                            let pending = {
                                let mut inner = db_clone.lock().unwrap();
                                match find_attr(&inner, h) {
                                    Some((si2, ai2)) => {
                                        let a = &mut inner.services[si2].attributes[ai2];
                                        let pos = a.pending_writes.iter().position(|p| p.id == id);
                                        pos.map(|idx| a.pending_writes.remove(idx))
                                    }
                                    None => None,
                                }
                            };
                            if let Some(p) = pending {
                                error!("attribute write timed out: handle=0x{:04x}", h);
                                (p.func)(GattDbAttribute { inner: db_clone, handle: h }, ETIMEDOUT);
                            }
                        });
                        attr_int.pending_writes.push(PendingWrite {
                            id,
                            timeout_handle: Some(timeout),
                            func: Box::new(f),
                        });
                    }
                    id
                };
                // Phase 4: call write_func outside lock.
                write_func(self.clone(), id, offset, value, opcode, att);
                true
            }
        }
    }

    /// Complete a pending write operation.
    pub fn write_result(&self, id: u32, err: i32) -> bool {
        let pending = {
            let mut inner = self.inner.lock().unwrap();
            match find_attr(&inner, self.handle) {
                Some((si, ai)) => {
                    let attr_int = &mut inner.services[si].attributes[ai];
                    let pos = attr_int.pending_writes.iter().position(|p| p.id == id);
                    pos.map(|idx| attr_int.pending_writes.remove(idx))
                }
                None => None,
            }
        };
        match pending {
            Some(mut p) => {
                if let Some(handle) = p.timeout_handle.take() {
                    handle.abort();
                }
                (p.func)(self.clone(), err);
                true
            }
            None => false,
        }
    }

    /// Set a fixed value length for this attribute. If this attribute is a
    /// characteristic declaration, adjusts the value attribute instead.
    pub fn set_fixed_length(&self, len: u16) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let (si, ai) = match find_attr(&inner, self.handle) {
            Some(x) => x,
            None => return false,
        };
        // If this is a char declaration, target the value attribute.
        let target_ai = if is_uuid16(&inner.services[si].attributes[ai].uuid, CHARACTERISTIC_UUID) {
            if ai + 1 < inner.services[si].attributes.len() {
                ai + 1
            } else {
                return false;
            }
        } else {
            ai
        };
        inner.services[si].attributes[target_ai].value_len = len;
        true
    }

    // ----- CCC and Notification -----

    /// Find the CCC descriptor for this attribute's characteristic.
    pub fn get_ccc(&self) -> Option<GattDbAttribute> {
        let inner = self.inner.lock().unwrap();
        let (si, ai) = find_attr(&inner, self.handle)?;
        let svc = &inner.services[si];

        // First get the value attribute.
        let val_idx = get_value_attr_index(svc, ai)?;

        // Search descriptors after the value attribute for CCC.
        let ccc_uuid_val = CCC_UUID;
        for idx in (val_idx + 1)..svc.attributes.len() {
            let a = &svc.attributes[idx];
            // Stop at next characteristic declaration or service declaration.
            if is_uuid16(&a.uuid, CHARACTERISTIC_UUID) || is_service_uuid(&a.uuid) {
                break;
            }
            if is_uuid16(&a.uuid, ccc_uuid_val) {
                return Some(GattDbAttribute { inner: Arc::clone(&self.inner), handle: a.handle });
            }
        }
        None
    }

    /// Notify through the CCC descriptor.
    ///
    /// Finds the value attribute, then the CCC descriptor, and invokes the
    /// CCC notify callback.
    pub fn notify(&self, value: &[u8], att: Option<Arc<Mutex<BtAtt>>>) -> bool {
        let (notify_fn, value_handle, ccc_handle) = {
            let inner = self.inner.lock().unwrap();
            let (si, ai) = match find_attr(&inner, self.handle) {
                Some(x) => x,
                None => return false,
            };
            let svc = &inner.services[si];

            // Get the value attribute index.
            let val_idx = match get_value_attr_index(svc, ai) {
                Some(i) => i,
                None => return false,
            };
            let val_handle = svc.attributes[val_idx].handle;
            let nf = svc.attributes[val_idx].notify_func.clone();
            if nf.is_none() {
                return false;
            }

            // Find CCC descriptor.
            let mut ccc_h = None;
            for idx in (val_idx + 1)..svc.attributes.len() {
                let a = &svc.attributes[idx];
                if is_uuid16(&a.uuid, CHARACTERISTIC_UUID) || is_service_uuid(&a.uuid) {
                    break;
                }
                if is_uuid16(&a.uuid, CCC_UUID) {
                    ccc_h = Some(a.handle);
                    break;
                }
            }
            match ccc_h {
                Some(ch) => (nf.unwrap(), val_handle, ch),
                None => return false,
            }
        };

        let val_attr = GattDbAttribute { inner: Arc::clone(&self.inner), handle: value_handle };
        let ccc_attr = GattDbAttribute { inner: Arc::clone(&self.inner), handle: ccc_handle };
        notify_fn(val_attr, ccc_attr, value, att);
        true
    }

    // ----- Lifecycle -----

    /// Reset the attribute's inline value to empty.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some((si, ai)) = find_attr(&inner, self.handle) {
            let attr = &mut inner.services[si].attributes[ai];
            attr.value.clear();
            attr.value_len = 0;
        }
    }

    /// Return the user data associated with this attribute.
    pub fn get_user_data(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        let inner = self.inner.lock().unwrap();
        let (si, ai) = find_attr(&inner, self.handle)?;
        inner.services[si].attributes[ai].user_data.clone()
    }

    /// Register a callback to be invoked when this attribute is removed.
    ///
    /// Returns a registration ID for [`unregister`](Self::unregister).
    pub fn register(&self, removed: impl Fn(GattDbAttribute) + Send + Sync + 'static) -> u32 {
        let mut inner = self.inner.lock().unwrap();
        let (si, ai) = match find_attr(&inner, self.handle) {
            Some(x) => x,
            None => return 0,
        };
        let attr = &mut inner.services[si].attributes[ai];
        attr.next_notify_id += 1;
        let id = attr.next_notify_id;
        attr.notify_list.push(AttrNotifyEntry { id, func: Arc::new(removed) });
        id
    }

    /// Remove an attribute removal notification registration.
    pub fn unregister(&self, id: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let (si, ai) = match find_attr(&inner, self.handle) {
            Some(x) => x,
            None => return false,
        };
        let attr = &mut inner.services[si].attributes[ai];
        let pos = attr.notify_list.iter().position(|e| e.id == id);
        match pos {
            Some(idx) => {
                attr.notify_list.remove(idx);
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Private helper enums for read/write extraction
// ---------------------------------------------------------------------------

enum ReadExtract {
    Inline(Vec<u8>),
    HasFunc { read_func: ReadFn, authorize: Option<AuthorizeFn> },
}

enum WriteExtract {
    Inline,
    HasFunc { write_func: WriteFn, authorize: Option<AuthorizeFn> },
}

/// Get the index of the "value attribute" within a service, given an
/// attribute index (which may be a char declaration, value, or descriptor).
fn get_value_attr_index(svc: &ServiceInternal, ai: usize) -> Option<usize> {
    let attr = &svc.attributes[ai];
    if is_uuid16(&attr.uuid, CHARACTERISTIC_UUID) {
        // Declaration → value at next index.
        if ai + 1 < svc.attributes.len() {
            return Some(ai + 1);
        }
        return None;
    }
    if ai > 0 && is_uuid16(&svc.attributes[ai - 1].uuid, CHARACTERISTIC_UUID) {
        return Some(ai);
    }
    // Walk backwards to find the char declaration.
    for idx in (0..ai).rev() {
        if is_uuid16(&svc.attributes[idx].uuid, CHARACTERISTIC_UUID) {
            if idx + 1 < svc.attributes.len() {
                return Some(idx + 1);
            }
            return None;
        }
    }
    None
}

/// Search descriptors after a characteristic declaration for the
/// Characteristic Extended Properties descriptor (0x2900).
fn get_char_extended_prop(svc: &ServiceInternal, decl_idx: usize) -> u16 {
    // Start after the value attribute (decl_idx + 2).
    let start = decl_idx + 2;
    for idx in start..svc.attributes.len() {
        let a = &svc.attributes[idx];
        if is_uuid16(&a.uuid, CHARACTERISTIC_UUID) || is_service_uuid(&a.uuid) {
            break;
        }
        if is_uuid16(&a.uuid, CEP_UUID) && a.value.len() >= 2 {
            return get_le16(&a.value[0..2]);
        }
    }
    0
}
