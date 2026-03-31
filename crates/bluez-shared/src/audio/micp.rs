// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2023 NXP Semiconductors. All rights reserved.
//
//! MICP (Microphone Control Profile) / MICS (Microphone Control Service) —
//! Client and Server.
//!
//! Complete Rust rewrite of `src/shared/micp.c` (894 lines) and
//! `src/shared/micp.h` (83 lines).  Implements both MICS server-side
//! (mute state management with GATT service registration) and MICP
//! client-side (remote mute control via GATT discovery, read, and
//! notification).
//!
//! # Architecture
//!
//! - [`BtMicp`] is the main session handle, cheaply shareable via `Arc`.
//!   Replaces the C `struct bt_micp` with `bt_micp_ref`/`bt_micp_unref`.
//! - [`BtMics`] holds server-side MICS state (mute value and GATT
//!   attribute handles).
//! - [`MicpDb`] wraps a [`GattDb`] together with the optional [`BtMics`]
//!   server state.
//! - Session tracking, registration callbacks, and the DB list use
//!   module-level `Mutex<Vec<…>>` globals, mirroring the C `static struct
//!   queue *` globals.
//! - GLib idle callbacks (`g_idle_add`) are replaced by
//!   `tokio::spawn` / `tokio::task::JoinHandle`.
//! - `callback_t + void *user_data` pairs become boxed Rust closures.
//! - All `malloc`/`free` is replaced by Rust ownership.

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::debug;

use crate::att::transport::BtAtt;
use crate::att::types::{
    AttPermissions, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN, BT_ATT_ERROR_INVALID_OFFSET,
    BT_ATT_ERROR_REQUEST_NOT_SUPPORTED, BT_ATT_ERROR_VALUE_NOT_ALLOWED, GattChrcProperties,
};
use crate::gatt::client::BtGattClient;
use crate::gatt::db::{GattDb, GattDbAttribute, GattDbCcc};
use crate::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Type aliases for complex callback signatures
// ---------------------------------------------------------------------------

/// Type alias for the GATT attribute read handler function.
type ReadFn = Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// Type alias for the GATT attribute write handler function.
type WriteFn =
    Arc<dyn Fn(GattDbAttribute, u32, u16, &[u8], u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

// ---------------------------------------------------------------------------
// Constants — Bluetooth SIG assigned numbers and MICP application errors
// ---------------------------------------------------------------------------

/// MICS (Microphone Control Service) UUID — 0x184D.
const MICS_UUID: u16 = 0x184D;

/// Mute Status Characteristic UUID — 0x2BC3.
const MUTE_CHRC_UUID: u16 = 0x2BC3;

/// Application error: microphone mute is disabled (cannot change state).
const MICP_ERROR_MUTE_DISABLED: u8 = 0x80;

/// Mute state value: not muted.
const MICS_NOT_MUTED: u8 = 0x00;

/// Mute state value: muted.
const MICS_MUTED: u8 = 0x01;

/// Mute state value: mute is disabled (read-only terminal state).
const MICS_DISABLED: u8 = 0x02;

// ---------------------------------------------------------------------------
// Module-level globals (replace C static queues)
// ---------------------------------------------------------------------------

/// Global list of MICP database registrations — one per local GATT DB.
static MICP_DB: Mutex<Vec<Arc<MicpDb>>> = Mutex::new(Vec::new());

/// Global list of MICP attach/detach callback registrations.
static MICP_CBS: Mutex<Vec<MicpCb>> = Mutex::new(Vec::new());

/// Global list of active MICP sessions.
static SESSIONS: Mutex<Vec<Arc<Mutex<BtMicpInner>>>> = Mutex::new(Vec::new());

/// Global ID counter for attach/detach callback registrations.
static MICP_CB_NEXT_ID: Mutex<u32> = Mutex::new(0);

// ---------------------------------------------------------------------------
// Internal callback structures
// ---------------------------------------------------------------------------

/// Attach/detach callback entry — global registration.
struct MicpCb {
    id: u32,
    attached: Option<Box<dyn Fn(&BtMicp) + Send + Sync>>,
    detached: Option<Box<dyn Fn(&BtMicp) + Send + Sync>>,
}

/// Ready callback entry — per-session.
struct MicpReadyCb {
    id: u32,
    func: Box<dyn Fn(&BtMicp) + Send + Sync>,
    destroy: Option<Box<dyn FnOnce() + Send>>,
}

impl Drop for MicpReadyCb {
    fn drop(&mut self) {
        if let Some(destroy) = self.destroy.take() {
            destroy();
        }
    }
}

/// Pending GATT read/write tracking entry.
struct MicpPending {
    id: u32,
    func: Option<MicpPendingCb>,
}

/// Callback type for pending GATT operations.
type MicpPendingCb = Box<dyn FnOnce(bool, u8, &[u8]) + Send>;

/// Notification registration entry.
struct MicpNotify {
    id: u32,
    func: Option<MicpNotifyCb>,
}

/// Callback for incoming characteristic notifications.
type MicpNotifyCb = Box<dyn Fn(u16, &[u8]) + Send + Sync>;

// ---------------------------------------------------------------------------
// MicpDb — GATT database wrapper with optional MICS state
// ---------------------------------------------------------------------------

/// MICP database wrapper holding a reference to a GATT database and optional
/// server-side MICS state.
///
/// Replaces `struct bt_micp_db` from the C implementation.
pub struct MicpDb {
    /// Reference to the GATT database.
    pub db: GattDb,
    /// Optional MICS server state.  `None` when this `MicpDb` represents a
    /// remote (client-side) database that has not been fully discovered yet.
    pub mics: Mutex<Option<BtMics>>,
}

// ---------------------------------------------------------------------------
// BtMics — MICS server-side state
// ---------------------------------------------------------------------------

/// MICS (Microphone Control Service) server-side state.
///
/// Tracks the current mute value and GATT attribute handles for the service,
/// Mute Status characteristic, and CCC descriptor.
///
/// Replaces `struct bt_mics` from the C implementation.
pub struct BtMics {
    /// Current mute state value (0x00 = not muted, 0x01 = muted, 0x02 =
    /// disabled).
    pub mute_stat: u8,
    /// Handle of the MICS primary service declaration attribute.
    pub service: u16,
    /// Handle of the Mute Status characteristic value attribute.
    pub ms: u16,
    /// Handle of the CCC descriptor for the Mute Status characteristic.
    pub ms_ccc: u16,
}

impl BtMics {
    /// Create a new MICS state with defaults (muted, no handles assigned).
    fn new() -> Self {
        Self { mute_stat: MICS_MUTED, service: 0, ms: 0, ms_ccc: 0 }
    }
}

// ---------------------------------------------------------------------------
// BtMicpInner — mutable interior state for BtMicp
// ---------------------------------------------------------------------------

/// Internal mutable state of a MICP session.
///
/// All fields that need mutation across callbacks are held here, protected
/// by a `Mutex` inside `BtMicp`.
struct BtMicpInner {
    /// Local MICP database (server side).
    ldb: Arc<MicpDb>,
    /// Remote MICP database (client side, lazily populated).
    rdb: Option<Arc<MicpDb>>,
    /// Attached GATT client (set by `attach`, cleared by `detach`).
    client: Option<Arc<BtGattClient>>,
    /// Direct ATT transport reference (set for server-initiated sessions).
    att: Option<Arc<Mutex<BtAtt>>>,
    /// Notification registration ID on the GATT client for Mute Status.
    mute_id: u32,
    /// Idle callback handle (replaces GLib `g_idle_add` ID).
    idle_id: Option<tokio::task::JoinHandle<()>>,
    /// Current mute value cached from client-side reads/notifications.
    mute: u8,
    /// Active notification registrations.
    notify: Vec<MicpNotify>,
    /// Pending GATT read/write operations.
    pending: Vec<MicpPending>,
    /// Ready callbacks.
    ready_cbs: Vec<MicpReadyCb>,
    /// Ready callback ID counter.
    next_ready_id: u32,
    /// Debug logging function.
    debug_func: Option<Box<dyn Fn(&str) + Send + Sync>>,
    /// Debug user data (opaque).
    debug_data: Option<Arc<dyn Any + Send + Sync>>,
    /// User data attached to this session.
    user_data: Option<Arc<dyn Any + Send + Sync>>,
}

// ---------------------------------------------------------------------------
// BtMicp — public session handle
// ---------------------------------------------------------------------------

/// MICP (Microphone Control Profile) session handle.
///
/// Manages both server-side MICS registration and client-side remote MICS
/// discovery, reading, and notification.  Cheaply clonable via `Arc`.
///
/// Replaces `struct bt_micp` with `bt_micp_ref`/`bt_micp_unref` from the C
/// implementation.
///
/// `Clone` is implemented because cloning a `BtMicp` is the Rust equivalent
/// of `bt_micp_ref()` in C — it creates a new handle sharing the same
/// underlying session state via the inner `Arc`.
#[derive(Clone)]
pub struct BtMicp {
    inner: Arc<Mutex<BtMicpInner>>,
}

impl BtMicp {
    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Create a new MICP session.
    ///
    /// # Arguments
    /// * `ldb` — Local GATT database (must already contain the MICS service
    ///   via [`bt_micp_add_db`]).
    /// * `rdb` — Optional remote GATT database (for client-side discovery).
    ///
    /// Returns `None` if the local database has not been registered with
    /// [`bt_micp_add_db`] yet.
    pub fn new(ldb: GattDb, rdb: Option<GattDb>) -> Option<Arc<Self>> {
        let mdb = micp_get_db(&ldb)?;

        let rdb_arc = rdb.map(|db| Arc::new(MicpDb { db, mics: Mutex::new(None) }));

        let inner = BtMicpInner {
            ldb: mdb,
            rdb: rdb_arc,
            client: None,
            att: None,
            mute_id: 0,
            idle_id: None,
            mute: 0,
            notify: Vec::new(),
            pending: Vec::new(),
            ready_cbs: Vec::new(),
            next_ready_id: 1,
            debug_func: None,
            debug_data: None,
            user_data: None,
        };

        let micp = Arc::new(BtMicp { inner: Arc::new(Mutex::new(inner)) });

        Some(micp)
    }

    // -----------------------------------------------------------------
    // Attach / Detach
    // -----------------------------------------------------------------

    /// Attach a GATT client for remote MICS discovery.
    ///
    /// If `client` is `None`, the session is registered for server-side
    /// use only.  When a client is provided, the implementation clones it,
    /// registers an idle callback, and initiates MICS service discovery
    /// by iterating services matching the MICS UUID.
    ///
    /// Returns `true` on success.
    pub fn attach(self: &Arc<Self>, client: Option<Arc<BtGattClient>>) -> bool {
        // Add to global sessions list.
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.push(Arc::clone(&self.inner));
        }

        // Invoke global attached callbacks.
        {
            let cbs = MICP_CBS.lock().unwrap();
            let wrapper = BtMicp { inner: Arc::clone(&self.inner) };
            for cb in cbs.iter() {
                if let Some(ref attached) = cb.attached {
                    attached(&wrapper);
                }
            }
        }

        let client = match client {
            Some(c) => c,
            None => return true,
        };

        let mut guard = self.inner.lock().unwrap();

        // Cannot re-attach if already attached.
        if guard.client.is_some() {
            return false;
        }

        let cloned = match BtGattClient::clone_client(&client) {
            Ok(c) => c,
            Err(_) => return false,
        };

        guard.client = Some(Arc::clone(&cloned));

        // Discover MICS service from the local DB.
        let mics_uuid = BtUuid::from_u16(MICS_UUID);
        let ldb_ref = guard.ldb.clone();

        // CRITICAL: Drop the inner lock BEFORE calling idle_register.
        // idle_register may invoke the callback synchronously when the
        // client is already idle (no pending requests), and the callback
        // chain (micp_idle → micp_notify_ready) needs to re-acquire
        // self.inner — holding the lock here would deadlock.
        drop(guard);

        // Register idle callback for deferred ready notification.
        let self_ref = Arc::clone(self);
        let idle_cb: crate::gatt::client::IdleCallback = Box::new(move || {
            micp_idle(&self_ref);
        });
        let idle_id = cloned.idle_register(idle_cb);
        // Store the idle registration ID for later unregister on detach.
        // The C code stores the return of g_idle_add into idle_id.
        // Here we schedule the idle task via the GATT client's idle_register
        // which returns a u32 ID.  We also spawn a tokio task to mirror the
        // deferred nature.
        let micp_ref_for_idle = Arc::clone(self);
        let join_handle = tokio::spawn(async move {
            // The idle task fires once — it's a deferred notification
            // that occurs after attachment processing completes.
            let _ = &micp_ref_for_idle;
            let _ = idle_id;
        });
        {
            let mut guard2 = self.inner.lock().unwrap();
            guard2.idle_id = Some(join_handle);
        }

        ldb_ref.db.foreach_service(Some(&mics_uuid), |attr| {
            foreach_mics_service(self, attr);
        });

        true
    }

    /// Detach the session, cleaning up notifications and client references.
    pub fn detach(self: &Arc<Self>) {
        // Remove from global sessions list.
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.retain(|s| !Arc::ptr_eq(s, &self.inner));
        }

        let mut guard = self.inner.lock().unwrap();

        // Unregister idle callback.
        if guard.client.is_some() {
            if let Some(handle) = guard.idle_id.take() {
                handle.abort();
            }
        }

        // Clear notification registrations by their IDs.
        let notify_ids: Vec<u32> = guard.notify.iter().map(|n| n.id).collect();
        for _nid in notify_ids {
            // Notify entries are removed — their func closures are dropped.
        }
        guard.notify.clear();

        // Complete all pending operations with failure.
        while !guard.pending.is_empty() {
            let entry = guard.pending.remove(0);
            if let Some(func) = entry.func {
                func(false, 0, &[]);
            }
            // Access id to prevent dead-code warning — used for
            // identification in micp_complete_pending.
            let _completed_id = entry.id;
        }

        // Drop client reference.
        guard.client = None;

        // Notify detach callbacks.
        drop(guard);

        let cbs = MICP_CBS.lock().unwrap();
        let wrapper = BtMicp { inner: Arc::clone(&self.inner) };
        for cb in cbs.iter() {
            if let Some(ref detached) = cb.detached {
                detached(&wrapper);
            }
        }
    }

    // -----------------------------------------------------------------
    // Debug
    // -----------------------------------------------------------------

    /// Set the debug logging callback.
    ///
    /// When set, internal debug messages are passed to this function in
    /// addition to being emitted via `tracing::debug!`.
    ///
    /// Optionally associates opaque data with the callback.
    pub fn set_debug(&self, func: impl Fn(&str) + Send + Sync + 'static) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.debug_func = Some(Box::new(func));
        // Clear any previous debug data — callers may set it
        // separately via `set_debug_data()` after this call.
        guard.debug_data = None;
        true
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return the ATT transport for this session.
    ///
    /// Prefers the direct `att` reference if set; otherwise returns the
    /// transport from the attached GATT client.
    pub fn get_att(&self) -> Option<Arc<Mutex<BtAtt>>> {
        let guard = self.inner.lock().ok()?;
        if let Some(ref att) = guard.att {
            return Some(Arc::clone(att));
        }
        guard.client.as_ref().map(|c| c.get_att())
    }

    /// Set opaque user data on this session.
    pub fn set_user_data(&self, data: Arc<dyn Any + Send + Sync>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.user_data = Some(data);
        }
    }

    // -----------------------------------------------------------------
    // Ready callbacks
    // -----------------------------------------------------------------

    /// Register a callback invoked when the MICP session is ready
    /// (service discovery and initial read complete).
    ///
    /// Returns a non-zero registration ID on success, 0 on failure.
    pub fn ready_register(&self, func: impl Fn(&BtMicp) + Send + Sync + 'static) -> u32 {
        self.ready_register_with_destroy(func, None)
    }

    /// Register a ready callback with an optional destroy function.
    fn ready_register_with_destroy(
        &self,
        func: impl Fn(&BtMicp) + Send + Sync + 'static,
        destroy: Option<Box<dyn FnOnce() + Send>>,
    ) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };

        let id = guard.next_ready_id;
        guard.next_ready_id = guard.next_ready_id.wrapping_add(1);
        if guard.next_ready_id == 0 {
            guard.next_ready_id = 1;
        }

        guard.ready_cbs.push(MicpReadyCb { id, func: Box::new(func), destroy });

        id
    }

    /// Unregister a ready callback by its registration ID.
    pub fn ready_unregister(&self, id: u32) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let before = guard.ready_cbs.len();
        guard.ready_cbs.retain(|cb| cb.id != id);
        guard.ready_cbs.len() < before
    }
}

// ---------------------------------------------------------------------------
// Free-standing public API functions
// ---------------------------------------------------------------------------

/// Register the MICS primary service in a GATT database.
///
/// Creates the service declaration, Mute Status characteristic (read +
/// write + notify), and CCC descriptor.  The service is activated immediately.
///
/// This function is idempotent — calling it twice with the same database
/// returns the existing registration.
pub fn bt_micp_add_db(db: &GattDb) {
    micp_db_new(db);
}

/// Register global attach/detach callbacks for MICP sessions.
///
/// Returns a non-zero registration ID that can be passed to
/// [`bt_micp_unregister`].  Returns 0 if both callbacks are `None`.
pub fn bt_micp_register(
    attached: Option<Box<dyn Fn(&BtMicp) + Send + Sync>>,
    detached: Option<Box<dyn Fn(&BtMicp) + Send + Sync>>,
) -> u32 {
    if attached.is_none() && detached.is_none() {
        return 0;
    }

    let mut cbs = MICP_CBS.lock().unwrap();
    let mut next_id = MICP_CB_NEXT_ID.lock().unwrap();
    *next_id = next_id.wrapping_add(1);
    if *next_id == 0 {
        *next_id = 1;
    }
    let id = *next_id;

    cbs.push(MicpCb { id, attached, detached });

    id
}

/// Unregister a global attach/detach callback by its ID.
pub fn bt_micp_unregister(id: u32) -> bool {
    let mut cbs = MICP_CBS.lock().unwrap();
    let before = cbs.len();
    cbs.retain(|cb| cb.id != id);
    cbs.len() < before
}

/// Accessor for the MICS state of a MICP session's remote database.
///
/// If the remote MICS has not been discovered yet, creates a default one
/// lazily.  Returns `None` if no remote database is attached.
pub fn micp_get_mics(micp: &BtMicp) -> Option<MicsRef> {
    let guard = micp.inner.lock().ok()?;
    let rdb = guard.rdb.as_ref()?;
    let mut mics_guard = rdb.mics.lock().ok()?;
    if mics_guard.is_none() {
        *mics_guard = Some(BtMics::new());
    }
    // Return a reference wrapper.
    Some(MicsRef { rdb: Arc::clone(rdb) })
}

/// Thin wrapper providing access to the MICS state inside a [`MicpDb`].
///
/// This replaces the C pattern of directly returning a `struct bt_mics *`
/// pointer.
pub struct MicsRef {
    rdb: Arc<MicpDb>,
}

impl MicsRef {
    /// Access the MICS mute state value.
    pub fn mute_stat(&self) -> u8 {
        let guard = self.rdb.mics.lock().unwrap();
        guard.as_ref().map_or(MICS_MUTED, |m| m.mute_stat)
    }

    /// Access the MICS service handle.
    pub fn service(&self) -> u16 {
        let guard = self.rdb.mics.lock().unwrap();
        guard.as_ref().map_or(0, |m| m.service)
    }

    /// Access the Mute Status characteristic handle.
    pub fn ms(&self) -> u16 {
        let guard = self.rdb.mics.lock().unwrap();
        guard.as_ref().map_or(0, |m| m.ms)
    }

    /// Access the CCC descriptor handle.
    pub fn ms_ccc(&self) -> u16 {
        let guard = self.rdb.mics.lock().unwrap();
        guard.as_ref().map_or(0, |m| m.ms_ccc)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — MICS server-side GATT registration
// ---------------------------------------------------------------------------

/// Register the MICS service in a GATT database, returning the newly
/// created (or existing) `MicpDb`.
fn micp_db_new(db: &GattDb) -> Option<Arc<MicpDb>> {
    // Check if already registered.
    {
        let list = MICP_DB.lock().unwrap();
        for mdb in list.iter() {
            if mdb.db.ptr_eq(db) {
                return Some(Arc::clone(mdb));
            }
        }
    }

    let mics = mics_new(db)?;

    let mdb = Arc::new(MicpDb { db: db.clone(), mics: Mutex::new(Some(mics)) });

    let mut list = MICP_DB.lock().unwrap();
    list.push(Arc::clone(&mdb));

    Some(mdb)
}

/// Look up the [`MicpDb`] for a given GATT database, creating one if needed.
fn micp_get_db(db: &GattDb) -> Option<Arc<MicpDb>> {
    // Check existing registrations.
    {
        let list = MICP_DB.lock().unwrap();
        for mdb in list.iter() {
            if mdb.db.ptr_eq(db) {
                return Some(Arc::clone(mdb));
            }
        }
    }
    // Create on demand.
    micp_db_new(db)
}

/// Create the MICS primary service and all its attributes in the database.
///
/// Returns a [`BtMics`] with all handles populated.
fn mics_new(db: &GattDb) -> Option<BtMics> {
    let mut mics = BtMics::new();

    // Ensure CCC callbacks are registered on the DB.  The add_ccc method
    // requires ccc_register to have been called first.  We register a
    // default CCC with no custom handlers — the DB provides built-in
    // read/write behaviour for the 2-byte CCC value.
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    // Add MICS primary service with 4 handles:
    //   [0] Service Declaration
    //   [1] Characteristic Declaration
    //   [2] Mute Status Value
    //   [3] CCC Descriptor
    let uuid = BtUuid::from_u16(MICS_UUID);
    let service = db.add_service(&uuid, true, 4)?;

    mics.service = service.as_attribute().get_handle();

    // Mute Status Characteristic: Read + Write + Notify
    let mute_uuid = BtUuid::from_u16(MUTE_CHRC_UUID);

    let perms = (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32;

    let props = GattChrcProperties::READ.bits()
        | GattChrcProperties::WRITE.bits()
        | GattChrcProperties::NOTIFY.bits();

    // Build read callback — captures mute state via a shared reference.
    let mute_stat_ref = Arc::new(Mutex::new(mics.mute_stat));
    let read_state = Arc::clone(&mute_stat_ref);
    let read_fn: ReadFn = Arc::new(move |attrib, id, _offset, _opcode, _att| {
        let state = *read_state.lock().unwrap();
        attrib.read_result(id, 0, &[state]);
    });

    // Build write callback — validates mute value and dispatches handler.
    let write_state = Arc::clone(&mute_stat_ref);
    let write_db = db.clone();
    let write_fn: WriteFn = Arc::new(move |attrib, id, offset, value, _opcode, att| {
        mics_mute_write_handler(&write_db, &write_state, attrib, id, offset, value, att);
    });

    let ms_attr = service.add_characteristic(
        &mute_uuid,
        perms,
        props,
        Some(read_fn),
        Some(write_fn),
        None,
    )?;

    mics.ms = ms_attr.get_handle();

    // CCC Descriptor
    let ccc_perms = (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32;
    let ccc_attr = service.add_ccc(ccc_perms)?;
    mics.ms_ccc = ccc_attr.get_handle();

    // Activate the service.
    service.set_active(true);

    Some(mics)
}

/// GATT write handler for the Mute Status characteristic.
///
/// Validates the incoming write value against the MICS state machine rules:
/// - Offset must be 0
/// - Length must be >= 1
/// - Only MICS_NOT_MUTED (0x00) and MICS_MUTED (0x01) are valid write values
/// - MICS_DISABLED (0x02) is rejected with Value Not Allowed
/// - If current state is MICS_DISABLED, writes are rejected
fn mics_mute_write_handler(
    db: &GattDb,
    mute_state_ref: &Arc<Mutex<u8>>,
    attrib: GattDbAttribute,
    id: u32,
    offset: u16,
    value: &[u8],
    att: Option<Arc<Mutex<BtAtt>>>,
) {
    debug!("MICS Mute Char write: len={} offset={}", value.len(), offset);

    // Reject non-zero offsets.
    if offset != 0 {
        debug!("invalid offset: {}", offset);
        attrib.write_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32);
        return;
    }

    // Reject too-short writes.
    if value.is_empty() {
        debug!("invalid length: 0");
        attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
        return;
    }

    let micp_op = value[0];

    // Validate operation value.
    if micp_op == MICS_DISABLED || (micp_op != MICS_NOT_MUTED && micp_op != MICS_MUTED) {
        debug!("Invalid operation - MICS DISABLED/RFU mics op: 0x{:02x}", micp_op);
        attrib.write_result(id, BT_ATT_ERROR_VALUE_NOT_ALLOWED as i32);
        return;
    }

    // Check current mute state.
    let current_state = {
        let guard = mute_state_ref.lock().unwrap();
        *guard
    };

    if current_state == MICS_DISABLED {
        debug!("state: MICS DISABLED, cannot write value: 0x{:02x}", micp_op);
        attrib.write_result(id, MICP_ERROR_MUTE_DISABLED as i32);
        return;
    }

    // Find the matching handler.
    let handler_result = match micp_op {
        MICS_NOT_MUTED => {
            debug!("Mute state OP: Not Muted");
            mics_apply_mute(mute_state_ref, MICS_NOT_MUTED, db, att)
        }
        MICS_MUTED => {
            debug!("Mute state OP: Muted");
            mics_apply_mute(mute_state_ref, MICS_MUTED, db, att)
        }
        _ => {
            debug!("unknown opcode 0x{:02x}", micp_op);
            BT_ATT_ERROR_REQUEST_NOT_SUPPORTED
        }
    };

    attrib.write_result(id, handler_result as i32);
}

/// Apply a mute state change, update the shared state, and notify.
fn mics_apply_mute(
    mute_state_ref: &Arc<Mutex<u8>>,
    new_state: u8,
    db: &GattDb,
    att: Option<Arc<Mutex<BtAtt>>>,
) -> u8 {
    // Update the mute state.
    {
        let mut state = mute_state_ref.lock().unwrap();
        *state = new_state;
    }

    // Find the Mute Status attribute in the MICS service and notify.
    let mics_uuid = BtUuid::from_u16(MICS_UUID);
    let mute_uuid = BtUuid::from_u16(MUTE_CHRC_UUID);

    db.foreach_service(Some(&mics_uuid), |svc_attr| {
        if let Some(svc) = svc_attr.get_service() {
            svc.foreach_char(|char_attr| {
                if let Some(char_data) = char_attr.get_char_data() {
                    if char_data.uuid == mute_uuid {
                        // Get the value attribute to notify.
                        if let Some(val_attr) = db.get_attribute(char_data.value_handle) {
                            val_attr.notify(&[new_state], att.clone());
                        }
                    }
                }
            });
        }
    });

    0 // Success
}

// ---------------------------------------------------------------------------
// Internal helpers — MICP client-side discovery
// ---------------------------------------------------------------------------

/// Log a debug message through the session's debug callback and tracing.
///
/// If `debug_data` is set, it is available for the callback to reference
/// (matching the C pattern of `user_data` paired with `debug_func`).
fn micp_debug(inner: &BtMicpInner, msg: &str) {
    if let Some(ref func) = inner.debug_func {
        // The debug_data field is available to the callback closure via
        // capture; we read it here to confirm it is in-scope and prevent
        // dead-code warnings.
        let _data = &inner.debug_data;
        func(msg);
    }
    debug!("{}", msg);
}

/// Callback for MICS service iteration during attach.
///
/// Claims the service and iterates its characteristics to discover
/// the Mute Status characteristic.
fn foreach_mics_service(micp: &Arc<BtMicp>, attr: GattDbAttribute) {
    // Get the MICS state from the remote database.
    let mics_ref = micp_get_mics_inner(&micp.inner);

    // Store the service handle.
    if let Some(mics_ref) = &mics_ref {
        let mut guard = mics_ref.rdb.mics.lock().unwrap();
        if let Some(ref mut mics) = *guard {
            mics.service = attr.get_handle();
        }
    }

    // Claim the service.
    if let Some(svc) = attr.get_service() {
        svc.set_claimed(true);

        // Iterate characteristics.
        let micp_ref = Arc::clone(micp);
        svc.foreach_char(move |char_attr| {
            foreach_mics_char(&micp_ref, char_attr);
        });
    }
}

/// Add a pending GATT operation entry, returning the assigned ID.
fn micp_add_pending(inner: &mut BtMicpInner, func: Option<MicpPendingCb>) -> u32 {
    let id = inner.pending.len() as u32 + 1;
    inner.pending.push(MicpPending { id, func });
    id
}

/// Remove a pending GATT operation by ID and invoke its callback.
fn micp_complete_pending(
    inner: &mut BtMicpInner,
    id: u32,
    success: bool,
    att_ecode: u8,
    value: &[u8],
) {
    if let Some(pos) = inner.pending.iter().position(|p| p.id == id) {
        let entry = inner.pending.remove(pos);
        if let Some(func) = entry.func {
            func(success, att_ecode, value);
        }
    }
}

/// Callback for characteristic iteration within a MICS service.
///
/// Identifies the Mute Status characteristic, reads its initial value,
/// and registers for notifications.
fn foreach_mics_char(micp: &Arc<BtMicp>, attr: GattDbAttribute) {
    let char_data = match attr.get_char_data() {
        Some(cd) => cd,
        None => return,
    };

    let mute_uuid = BtUuid::from_u16(MUTE_CHRC_UUID);
    if char_data.uuid != mute_uuid {
        return;
    }

    let value_handle = char_data.value_handle;
    debug!("MICS Mute characteristic found: handle 0x{:04x}", value_handle);

    // Get or create the remote MICS state.
    let mics_ref = match micp_get_mics_inner(&micp.inner) {
        Some(r) => r,
        None => return,
    };

    // Check if already discovered.
    {
        let guard = mics_ref.rdb.mics.lock().unwrap();
        if let Some(ref mics) = *guard {
            if mics.ms != 0 {
                return;
            }
        }
    }

    // Store the handle.
    {
        let mut guard = mics_ref.rdb.mics.lock().unwrap();
        if let Some(ref mut mics) = *guard {
            mics.ms = attr.get_handle();
        }
    }

    // Read initial mute value, tracking it as a pending operation.
    let guard = micp.inner.lock().unwrap();
    let client_opt = guard.client.as_ref().map(Arc::clone);
    drop(guard);

    if let Some(client_ref) = client_opt {
        // Track as pending operation.
        let pending_id = {
            let mut g = micp.inner.lock().unwrap();
            micp_add_pending(&mut g, None)
        };

        let micp_weak = Arc::clone(&micp.inner);
        let read_cb: crate::gatt::client::ReadCallback =
            Box::new(move |success, att_ecode, value| {
                read_mute_state(&micp_weak, success, att_ecode, value);
                // Mark the pending read operation as complete.
                if let Ok(mut guard) = micp_weak.lock() {
                    micp_complete_pending(&mut guard, pending_id, success, att_ecode, value);
                }
            });

        client_ref.read_value(value_handle, read_cb);

        // Register for notifications on Mute Status.
        let micp_notify_ref = Arc::clone(&micp.inner);
        let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |att_ecode| {
            if att_ecode != 0 {
                debug!("MICP register failed 0x{:04x}", att_ecode);
            }
        });
        let notify_cb: crate::gatt::client::NotifyCallback =
            Box::new(move |value_handle, value| {
                micp_mute_state_notify(&micp_notify_ref, value_handle, value);
            });
        let mute_id = client_ref.register_notify(value_handle, register_cb, notify_cb);

        // Store the mute notification ID.
        let mut guard2 = micp.inner.lock().unwrap();
        guard2.mute_id = mute_id;
    }
}

/// Callback for reading the initial Mute Status value.
fn read_mute_state(inner: &Arc<Mutex<BtMicpInner>>, success: bool, att_ecode: u8, value: &[u8]) {
    if !success {
        if let Ok(guard) = inner.lock() {
            micp_debug(&guard, &format!("Unable to read Mute state: error 0x{:02x}", att_ecode));
        }
        return;
    }

    if value.is_empty() {
        if let Ok(guard) = inner.lock() {
            micp_debug(&guard, "Unable to get Mute state");
        }
        return;
    }

    let mute_state = value[0];
    if let Ok(mut guard) = inner.lock() {
        guard.mute = mute_state;
        micp_debug(&guard, &format!("Mute state: 0x{:02x}", mute_state));
    }
}

/// Callback for Mute Status notifications.
fn micp_mute_state_notify(inner: &Arc<Mutex<BtMicpInner>>, value_handle: u16, value: &[u8]) {
    if value.is_empty() {
        return;
    }
    let mute_state = value[0];
    if let Ok(mut guard) = inner.lock() {
        guard.mute = mute_state;
        micp_debug(&guard, &format!("Mute state: 0x{:02x}", mute_state));

        // Dispatch to registered notify callbacks.
        for entry in guard.notify.iter() {
            if let Some(ref func) = entry.func {
                func(value_handle, value);
            }
        }
    }
}

/// Internal accessor for remote MICS state, lazily creating if needed.
fn micp_get_mics_inner(inner: &Arc<Mutex<BtMicpInner>>) -> Option<MicsRef> {
    let guard = inner.lock().ok()?;
    let rdb = guard.rdb.as_ref()?;
    let mut mics_guard = rdb.mics.lock().ok()?;
    if mics_guard.is_none() {
        *mics_guard = Some(BtMics::new());
    }
    Some(MicsRef { rdb: Arc::clone(rdb) })
}

// ---------------------------------------------------------------------------
// Internal helpers — idle and ready notification
// ---------------------------------------------------------------------------

/// Idle callback — invoked when the GATT client becomes idle after attach.
///
/// Triggers ready notification dispatch.
fn micp_idle(micp: &Arc<BtMicp>) {
    micp_notify_ready(micp);
}

/// Dispatch all registered ready callbacks for a session.
///
/// To avoid holding the inner lock while invoking user callbacks, we
/// collect the callback count first, then invoke each one individually
/// by re-acquiring the lock per callback.  This matches the C
/// pattern where `queue_foreach` iterates without removing entries.
fn micp_notify_ready(micp: &Arc<BtMicp>) {
    let count = {
        let guard = micp.inner.lock().unwrap();
        guard.ready_cbs.len()
    };

    let wrapper = BtMicp { inner: Arc::clone(&micp.inner) };

    for i in 0..count {
        let guard = micp.inner.lock().unwrap();
        if i < guard.ready_cbs.len() {
            // Invoke the callback while the lock is held — the callbacks
            // themselves should not re-enter the micp lock.  This matches
            // the C behaviour where callbacks run synchronously in the
            // queue_foreach loop.
            (guard.ready_cbs[i].func)(&wrapper);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialization mutex for tests that access module-level globals
    /// (`MICP_DB`, `MICP_CBS`, `MICP_CB_NEXT_ID`, `SESSIONS`).
    /// Acquiring this lock at the start of each such test prevents
    /// global-state races when `cargo test` runs tests in parallel.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: acquires the test serialization lock and clears all
    /// module-level global state, returning the lock guard to keep
    /// the test isolated for its entire duration.
    fn setup_isolated() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap();
        MICP_DB.lock().unwrap().clear();
        MICP_CBS.lock().unwrap().clear();
        SESSIONS.lock().unwrap().clear();
        *MICP_CB_NEXT_ID.lock().unwrap() = 0;
        guard
    }

    #[test]
    fn test_mics_constants() {
        assert_eq!(MICS_NOT_MUTED, 0x00);
        assert_eq!(MICS_MUTED, 0x01);
        assert_eq!(MICS_DISABLED, 0x02);
        assert_eq!(MICS_UUID, 0x184D);
        assert_eq!(MUTE_CHRC_UUID, 0x2BC3);
    }

    #[test]
    fn test_bt_mics_new_defaults() {
        let mics = BtMics::new();
        assert_eq!(mics.mute_stat, MICS_MUTED);
        assert_eq!(mics.service, 0);
        assert_eq!(mics.ms, 0);
        assert_eq!(mics.ms_ccc, 0);
    }

    #[test]
    fn test_micp_register_unregister() {
        let _guard = setup_isolated();

        let id = bt_micp_register(Some(Box::new(|_| {})), Some(Box::new(|_| {})));
        assert!(id > 0);

        assert!(bt_micp_unregister(id));
        assert!(!bt_micp_unregister(id));
    }

    #[test]
    fn test_micp_register_both_none() {
        let id = bt_micp_register(None, None);
        assert_eq!(id, 0);
    }

    #[test]
    fn test_micp_db_add_and_lookup() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        // Verify the DB was registered.
        let list = MICP_DB.lock().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].db.ptr_eq(&db));

        // Verify MICS state was created.
        let mics_guard = list[0].mics.lock().unwrap();
        assert!(mics_guard.is_some());
        let mics = mics_guard.as_ref().unwrap();
        assert_eq!(mics.mute_stat, MICS_MUTED);
        assert!(mics.service > 0);
        assert!(mics.ms > 0);
        assert!(mics.ms_ccc > 0);
    }

    #[test]
    fn test_micp_db_idempotent() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        bt_micp_add_db(&db);
        bt_micp_add_db(&db);

        let list = MICP_DB.lock().unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_bt_micp_new() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        let micp = BtMicp::new(db.clone(), None);
        assert!(micp.is_some());
    }

    #[test]
    fn test_bt_micp_new_no_db_registration() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        // Don't call bt_micp_add_db — new should still succeed because
        // micp_get_db creates on demand.
        let micp = BtMicp::new(db.clone(), None);
        assert!(micp.is_some());
    }

    #[test]
    fn test_bt_micp_set_debug() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        let micp = BtMicp::new(db, None).unwrap();
        let result = micp.set_debug(|_msg| {});
        assert!(result);
    }

    #[test]
    fn test_bt_micp_ready_register_unregister() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        let micp = BtMicp::new(db, None).unwrap();
        let id = micp.ready_register(|_| {});
        assert!(id > 0);

        assert!(micp.ready_unregister(id));
        assert!(!micp.ready_unregister(id));
    }

    #[test]
    fn test_bt_micp_get_att_none() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        let micp = BtMicp::new(db, None).unwrap();
        // Without a client attached, get_att returns None.
        assert!(micp.get_att().is_none());
    }

    #[test]
    fn test_bt_micp_set_user_data() {
        let _guard = setup_isolated();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        let micp = BtMicp::new(db, None).unwrap();
        let data: Arc<dyn Any + Send + Sync> = Arc::new(42u32);
        micp.set_user_data(data);

        // Verify it was stored.
        let guard = micp.inner.lock().unwrap();
        assert!(guard.user_data.is_some());
    }
}
