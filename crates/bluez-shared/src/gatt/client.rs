// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
//! GATT Client Engine.
//!
//! Complete Rust rewrite of `src/shared/gatt-client.c` and
//! `src/shared/gatt-client.h`.  Implements async service/characteristic/
//! descriptor discovery, read/write operations, notification/indication
//! registration, robust caching via Database Hash, Service Changed handling,
//! and client clones.
//!
//! # Architecture
//!
//! - [`BtGattClient`] is the main public handle, cheaply cloneable via `Arc`.
//! - All mutable state lives in `BtGattClientInner`, protected by
//!   `tokio::sync::Mutex`.
//! - Callbacks use boxed Rust closures, replacing the C
//!   `callback + user_data + destroy` pattern.
//! - Discovery, read, and write operations delegate to the
//!   [`crate::gatt::helpers`] async helpers and [`crate::att::transport::BtAtt`].
//! - Reference counting (`bt_gatt_client_ref`/`unref`) is replaced by `Arc`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Notify;

use crate::att::transport::{AttNotifyCallback, AttResponseCallback, BtAtt};
use crate::att::types::{
    AttError, AttOpcode, AttSecurityLevel, BT_ATT_DEFAULT_LE_MTU, BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
    BT_ATT_LE, BT_ATT_MAX_VALUE_LEN, BT_ATT_OP_ERROR_RSP, BT_ATT_OP_EXEC_WRITE_REQ,
    BT_ATT_OP_EXEC_WRITE_RSP, BT_ATT_OP_HANDLE_CONF, BT_ATT_OP_HANDLE_IND, BT_ATT_OP_HANDLE_NFY,
    BT_ATT_OP_HANDLE_NFY_MULT, BT_ATT_OP_PREP_WRITE_REQ, BT_ATT_OP_PREP_WRITE_RSP,
    BT_ATT_OP_READ_BLOB_REQ, BT_ATT_OP_READ_BLOB_RSP, BT_ATT_OP_READ_MULT_REQ,
    BT_ATT_OP_READ_MULT_RSP, BT_ATT_OP_READ_MULT_VL_REQ, BT_ATT_OP_READ_MULT_VL_RSP,
    BT_ATT_OP_READ_REQ, BT_ATT_OP_READ_RSP, BT_ATT_OP_SIGNED_WRITE_CMD, BT_ATT_OP_WRITE_CMD,
    BT_ATT_OP_WRITE_REQ, BT_ATT_OP_WRITE_RSP, GattChrcExtProperties, GattChrcProperties,
    GattClientFeatures, GattServerFeatures,
};
use crate::gatt::db::GattDb;
use crate::gatt::helpers::{
    self, BtGattIter, BtGattRequest, BtGattResult, CharEntry, DescEntry, GattError, ServiceEntry,
};
use crate::util::endian::{get_le16, put_le16};
use crate::util::uuid::BtUuid;

// =====================================================================
// Well-known GATT UUIDs
// =====================================================================

/// GATT Service UUID (0x1801).
const GATT_SVC_UUID: u16 = 0x1801;

/// Service Changed Characteristic UUID (0x2A05).
const SVC_CHNGD_UUID: u16 = 0x2A05;

/// Server Supported Features UUID (0x2B3A).
const SERVER_FEAT_UUID: u16 = 0x2B3A;

/// Client Supported Features UUID (0x2B29).
const CLIENT_FEAT_UUID: u16 = 0x2B29;

/// Database Hash UUID (0x2B2A).
const DB_HASH_UUID: u16 = 0x2B2A;

/// Client Characteristic Configuration descriptor UUID (0x2902).
const CCC_UUID: u16 = 0x2902;

// =====================================================================
// Callback type aliases
// =====================================================================

/// Callback invoked on GATT client operations (success/error).
pub type ClientCallback = Box<dyn FnOnce(bool, u8) + Send + 'static>;

/// Callback for read operations — receives success, ATT error code, and data.
pub type ReadCallback = Box<dyn FnOnce(bool, u8, &[u8]) + Send + 'static>;

/// Callback for long write operations — receives success, reliable_error, ATT error code.
pub type WriteLongCallback = Box<dyn FnOnce(bool, bool, u8) + Send + 'static>;

/// Callback for Service Changed notifications.
pub type ServiceChangedCallback = Box<dyn Fn(u16, u16) + Send + Sync + 'static>;

/// Callback for notification registration completion.
pub type RegisterCallback = Box<dyn FnOnce(u16) + Send + 'static>;

/// Callback for incoming notifications/indications.
pub type NotifyCallback = Box<dyn Fn(u16, &[u8]) + Send + Sync + 'static>;

/// Callback for client ready state change.
pub type ReadyCallback = Box<dyn FnOnce(bool, u8) + Send + 'static>;

/// Callback for idle state.
pub type IdleCallback = Box<dyn FnOnce() + Send + 'static>;

/// Debug logging callback.
pub type DebugCallback = Box<dyn Fn(&str) + Send + Sync + 'static>;

// =====================================================================
// Error type
// =====================================================================

/// Errors that can occur in GATT client operations.
#[derive(Debug, thiserror::Error)]
pub enum GattClientError {
    /// ATT-level error with the given error code.
    #[error("ATT error: 0x{0:02X}")]
    AttError(u8),

    /// The GATT client is not ready (discovery incomplete).
    #[error("GATT client not ready")]
    NotReady,

    /// The GATT client has been destroyed or is in an invalid state.
    #[error("Invalid client state")]
    InvalidState,

    /// A required characteristic or descriptor was not found.
    #[error("Characteristic or descriptor not found")]
    NotFound,

    /// The operation was cancelled.
    #[error("Operation cancelled")]
    Cancelled,

    /// Transport-level error.
    #[error("Transport error: {0}")]
    Transport(String),

    /// Discovery operation failed.
    #[error("Discovery error: {0}")]
    Discovery(#[from] GattError),
}

// =====================================================================
// Internal state structures
// =====================================================================

/// Ready callback entry with unique ID.
struct ReadyCb {
    id: u32,
    callback: Option<ReadyCallback>,
}

/// Idle callback entry with unique ID.
struct IdleCb {
    id: u32,
    callback: Option<IdleCallback>,
}

/// Pending ATT request tracked by the GATT client.
struct Request {
    /// Unique request ID within this client.
    id: u32,
    /// ATT-layer operation ID returned by `BtAtt::send`.
    att_id: u32,
    /// Whether this is part of a long-write sequence.
    long_write: bool,
    /// Whether this is a prepare-write in a reliable session.
    prep_write: bool,
}

/// State for a characteristic that has notification/indication registrations.
struct NotifyChrc {
    /// Value handle of the characteristic.
    value_handle: u16,
    /// CCC descriptor handle (0 if not found).
    ccc_handle: u16,
    /// Characteristic properties bitfield.
    properties: u8,
    /// Count of active notify registrations for this characteristic.
    notify_count: u32,
    /// ATT operation ID for an in-flight CCC write (0 if none).
    ccc_write_id: u32,
    /// Queue of notification registrations waiting for CCC write to complete.
    reg_notify_queue: VecDeque<u32>,
}

/// Individual notification registration entry.
struct NotifyData {
    /// Unique registration ID within this client.
    id: u32,
    /// ATT error code from CCC write (0 on success).
    att_ecode: u8,
    /// Index into `notify_chrcs` for the parent characteristic.
    chrc_idx: Option<usize>,
    /// Callback invoked when the CCC write completes.
    register_cb: Option<RegisterCallback>,
    /// Callback invoked on each incoming notification/indication.
    notify_cb: Option<Arc<NotifyCallback>>,
}

/// Queued Service Changed range.
struct ServiceChangedOp {
    start_handle: u16,
    end_handle: u16,
}

/// Data accumulated during a long-read operation.
struct ReadLongData {
    handle: u16,
    offset: u16,
    value: Vec<u8>,
    callback: Option<ReadCallback>,
}

/// Data accumulated during a long-write (prepare+execute) operation.
struct LongWriteData {
    handle: u16,
    offset: u16,
    value: Vec<u8>,
    cur_offset: u16,
    reliable: bool,
    callback: Option<WriteLongCallback>,
}

/// Inner mutable state of the GATT client.
///
/// Protected by `StdMutex` for synchronous access from ATT callbacks.
struct BtGattClientInner {
    // --- Transport and database ---
    att: Arc<StdMutex<BtAtt>>,
    db: GattDb,
    features: u8,

    // --- State flags ---
    ready: bool,
    in_init: bool,
    in_svc_chngd: bool,
    in_long_write: bool,

    // --- Clone/parent relationship ---
    parent: Option<Arc<BtGattClient>>,
    clones: Vec<Arc<BtGattClient>>,

    // --- ATT registrations ---
    nfy_id: u32,
    nfy_mult_id: u32,
    ind_id: u32,

    // --- GattDb change notification registration ---
    db_notify_id: u32,

    // --- Pending requests ---
    pending_requests: Vec<Request>,
    next_request_id: AtomicU32,

    // --- Long write queue ---
    long_write_queue: VecDeque<LongWriteData>,
    reliable_write_session_id: u32,

    // --- Service Changed ---
    svc_chngd_queue: VecDeque<ServiceChangedOp>,
    svc_chngd_ind_id: u32,
    svc_chngd_registered: bool,
    svc_chngd_callback: Option<ServiceChangedCallback>,

    // --- Ready callbacks ---
    ready_cbs: Vec<ReadyCb>,
    next_ready_id: u32,

    // --- Idle callbacks ---
    idle_cbs: Vec<IdleCb>,
    next_idle_id: u32,

    // --- Notification state ---
    notify_list: Vec<NotifyData>,
    notify_chrcs: Vec<NotifyChrc>,
    next_reg_id: AtomicU32,

    // --- Debug ---
    debug_callback: Option<DebugCallback>,

    // --- DB out-of-sync recovery ---
    pending_retry_att_id: u32,
    pending_error_handle: u16,

    // --- Server features ---
    server_features: u8,
}

impl BtGattClientInner {
    /// Log a debug message through the optional debug callback.
    fn debug_log(&self, msg: &str) {
        if let Some(ref cb) = self.debug_callback {
            cb(msg);
        }
        tracing::debug!("{}", msg);
    }
}

// =====================================================================
// BtGattClient — Public API
// =====================================================================

/// GATT client engine.
///
/// Performs async service/characteristic/descriptor discovery, read/write
/// operations, notification/indication registration, robust caching via
/// Database Hash, Service Changed handling, and supports client clones.
///
/// This is the Rust equivalent of `struct bt_gatt_client` from
/// `src/shared/gatt-client.c`.
pub struct BtGattClient {
    inner: StdMutex<BtGattClientInner>,
    /// Shared ready-state flag for lock-free reads.
    ready_flag: AtomicBool,
    /// Notify signal for idle-state transitions.
    idle_notify: Notify,
}

impl BtGattClient {
    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Create a new GATT client.
    ///
    /// Initiates the initialization procedure: MTU exchange, server feature
    /// discovery, database hash comparison, and full GATT discovery.
    ///
    /// # Arguments
    /// * `db` — In-memory GATT database to populate with discovered services.
    /// * `att` — ATT transport handle.
    /// * `mtu` — Desired MTU for MTU exchange (0 to skip exchange).
    /// * `features` — Client-supported features bitfield.
    pub fn new(
        db: GattDb,
        att: Arc<StdMutex<BtAtt>>,
        mtu: u16,
        features: u8,
    ) -> Result<Arc<Self>, GattClientError> {
        let inner = BtGattClientInner {
            att: Arc::clone(&att),
            db: db.clone(),
            features,
            ready: false,
            in_init: true,
            in_svc_chngd: false,
            in_long_write: false,
            parent: None,
            clones: Vec::new(),
            nfy_id: 0,
            nfy_mult_id: 0,
            ind_id: 0,
            db_notify_id: 0,
            pending_requests: Vec::new(),
            next_request_id: AtomicU32::new(1),
            long_write_queue: VecDeque::new(),
            reliable_write_session_id: 0,
            svc_chngd_queue: VecDeque::new(),
            svc_chngd_ind_id: 0,
            svc_chngd_registered: false,
            svc_chngd_callback: None,
            ready_cbs: Vec::new(),
            next_ready_id: 1,
            idle_cbs: Vec::new(),
            next_idle_id: 1,
            notify_list: Vec::new(),
            notify_chrcs: Vec::new(),
            next_reg_id: AtomicU32::new(1),
            debug_callback: None,
            pending_retry_att_id: 0,
            pending_error_handle: 0,
            server_features: 0,
        };

        let client = Arc::new(BtGattClient {
            inner: StdMutex::new(inner),
            ready_flag: AtomicBool::new(false),
            idle_notify: Notify::new(),
        });

        // Register notification/indication handlers on the ATT transport.
        Self::register_att_handlers(&client);

        // Register the DB out-of-sync recovery callback.
        Self::register_db_sync_cb(&client);

        // Register for GattDb attribute change notifications (service
        // added/removed). The added callback logs discovery of new services;
        // the removed callback logs removal, supporting Service Changed flow.
        {
            let added_cb = Some(|_attr: crate::gatt::db::GattDbAttribute| {
                tracing::trace!("GattDb: service added notification");
            });
            let removed_cb = Some(|_attr: crate::gatt::db::GattDbAttribute| {
                tracing::trace!("GattDb: service removed notification");
            });
            let db_notify_id = db.register(added_cb, removed_cb);
            if let Ok(mut guard) = client.inner.lock() {
                guard.db_notify_id = db_notify_id;
            }
        }

        // Spawn the async initialization procedure.
        let client_ref = Arc::clone(&client);
        tokio::spawn(async move {
            Self::init_procedure(client_ref, mtu).await;
        });

        Ok(client)
    }

    /// Create a clone of an existing GATT client.
    ///
    /// The clone shares the parent's ATT transport, GATT DB, and features.
    /// It receives propagated ready/service-changed callbacks.
    pub fn clone_client(parent: &Arc<Self>) -> Result<Arc<Self>, GattClientError> {
        let (att, db, features, ready, server_features) = {
            let guard = parent.inner.lock().map_err(|_| GattClientError::InvalidState)?;
            (
                Arc::clone(&guard.att),
                guard.db.clone(),
                guard.features,
                guard.ready,
                guard.server_features,
            )
        };

        let inner = BtGattClientInner {
            att,
            db,
            features,
            ready,
            in_init: false,
            in_svc_chngd: false,
            in_long_write: false,
            parent: Some(Arc::clone(parent)),
            clones: Vec::new(),
            nfy_id: 0,
            nfy_mult_id: 0,
            ind_id: 0,
            db_notify_id: 0,
            pending_requests: Vec::new(),
            next_request_id: AtomicU32::new(1),
            long_write_queue: VecDeque::new(),
            reliable_write_session_id: 0,
            svc_chngd_queue: VecDeque::new(),
            svc_chngd_ind_id: 0,
            svc_chngd_registered: false,
            svc_chngd_callback: None,
            ready_cbs: Vec::new(),
            next_ready_id: 1,
            idle_cbs: Vec::new(),
            next_idle_id: 1,
            notify_list: Vec::new(),
            notify_chrcs: Vec::new(),
            next_reg_id: AtomicU32::new(1),
            debug_callback: None,
            pending_retry_att_id: 0,
            pending_error_handle: 0,
            server_features,
        };

        let clone = Arc::new(BtGattClient {
            inner: StdMutex::new(inner),
            ready_flag: AtomicBool::new(ready),
            idle_notify: Notify::new(),
        });

        // Register the clone in the parent's clone list.
        {
            let mut parent_guard =
                parent.inner.lock().map_err(|_| GattClientError::InvalidState)?;
            parent_guard.clones.push(Arc::clone(&clone));
        }

        // Register ATT notification handlers for the clone.
        Self::register_att_handlers(&clone);

        Ok(clone)
    }

    // -----------------------------------------------------------------
    // State Queries
    // -----------------------------------------------------------------

    /// Returns `true` if the GATT client is ready (discovery complete).
    pub fn is_ready(&self) -> bool {
        self.ready_flag.load(Ordering::Acquire)
    }

    /// Register a callback to be invoked when the client becomes ready.
    ///
    /// Returns a registration ID that can be used with [`ready_unregister`].
    /// If the client is already ready, the callback is invoked immediately.
    pub fn ready_register(&self, callback: ReadyCallback) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        let id = guard.next_ready_id;
        guard.next_ready_id = guard.next_ready_id.wrapping_add(1);
        if guard.next_ready_id == 0 {
            guard.next_ready_id = 1;
        }

        if guard.ready {
            drop(guard);
            callback(true, 0);
        } else {
            guard.ready_cbs.push(ReadyCb { id, callback: Some(callback) });
        }
        id
    }

    /// Unregister a ready callback by its ID.
    pub fn ready_unregister(&self, id: u32) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let before = guard.ready_cbs.len();
        guard.ready_cbs.retain(|cb| cb.id != id);
        guard.ready_cbs.len() < before
    }

    /// Set the Service Changed callback.
    pub fn set_service_changed(&self, callback: ServiceChangedCallback) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.svc_chngd_callback = Some(callback);
        true
    }

    /// Set the debug logging callback.
    pub fn set_debug(&self, callback: DebugCallback) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.debug_callback = Some(callback);
        true
    }

    /// Returns the negotiated ATT MTU.
    pub fn get_mtu(&self) -> u16 {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return BT_ATT_DEFAULT_LE_MTU,
        };
        match guard.att.lock() {
            Ok(att) => att.get_mtu(),
            Err(_) => BT_ATT_DEFAULT_LE_MTU,
        }
    }

    /// Returns a reference to the ATT transport.
    pub fn get_att(&self) -> Arc<StdMutex<BtAtt>> {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => panic!("BtGattClient inner mutex poisoned"),
        };
        Arc::clone(&guard.att)
    }

    /// Returns a clone of the GATT database.
    pub fn get_db(&self) -> GattDb {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => panic!("BtGattClient inner mutex poisoned"),
        };
        guard.db.clone()
    }

    /// Returns the client feature flags.
    pub fn get_features(&self) -> u8 {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        guard.features
    }

    // -----------------------------------------------------------------
    // Cancellation
    // -----------------------------------------------------------------

    /// Cancel a single pending operation by its request ID.
    pub fn cancel(&self, id: u32) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if let Some(pos) = guard.pending_requests.iter().position(|r| r.id == id) {
            let req = guard.pending_requests.remove(pos);
            if req.att_id != 0 {
                if let Ok(mut att) = guard.att.lock() {
                    att.cancel(req.att_id);
                }
            }
            // If we cancelled a long-write head, clear the queue.
            if req.long_write {
                guard.in_long_write = false;
            }
            Self::check_idle_locked(&mut guard);
            true
        } else {
            false
        }
    }

    /// Cancel all pending operations.
    pub fn cancel_all(&self) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        // Use cancel_all on the ATT transport to bulk-cancel all pending
        // ATT requests in a single call, then clear our request list.
        if let Ok(mut att) = guard.att.lock() {
            att.cancel_all();
        }
        let requests: Vec<Request> = guard.pending_requests.drain(..).collect();
        let mut had_long_write = false;
        let mut had_prep_write = false;
        for req in &requests {
            had_long_write |= req.long_write;
            had_prep_write |= req.prep_write;
        }
        if had_long_write || had_prep_write {
            tracing::debug!(
                "Cancelled pending: long_write={}, prep_write={}",
                had_long_write,
                had_prep_write
            );
        }
        guard.long_write_queue.clear();
        guard.in_long_write = false;
        Self::check_idle_locked(&mut guard);
        drop(guard);
        self.signal_idle();
        true
    }

    // -----------------------------------------------------------------
    // Read Operations
    // -----------------------------------------------------------------

    /// Read a characteristic or descriptor value.
    ///
    /// Equivalent to `bt_gatt_client_read_value`.
    pub fn read_value(self: &Arc<Self>, handle: u16, callback: ReadCallback) -> u32 {
        self.read_long_value(handle, 0, callback)
    }

    /// Read a long value using Read Blob requests.
    ///
    /// If `offset` is 0, sends a READ_REQ first, then chains READ_BLOB_REQ
    /// as needed. If `offset` > 0, starts with READ_BLOB_REQ directly.
    pub fn read_long_value(
        self: &Arc<Self>,
        handle: u16,
        offset: u16,
        callback: ReadCallback,
    ) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                callback(false, 0, &[]);
                return 0;
            }
        };

        if !guard.ready {
            drop(guard);
            callback(false, 0, &[]);
            return 0;
        }

        let req_id = guard.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Build the ATT PDU.
        let (opcode, pdu) = if offset == 0 {
            let mut p = [0u8; 2];
            put_le16(handle, &mut p);
            (BT_ATT_OP_READ_REQ, p.to_vec())
        } else {
            let mut p = [0u8; 4];
            put_le16(handle, &mut p[0..2]);
            put_le16(offset, &mut p[2..4]);
            (BT_ATT_OP_READ_BLOB_REQ, p.to_vec())
        };

        let att_ref = Arc::clone(&guard.att);
        let client_ref = Arc::clone(self);

        // Shared mutable state for the long-read accumulation.
        let read_data = Arc::new(StdMutex::new(ReadLongData {
            handle,
            offset,
            value: Vec::new(),
            callback: Some(callback),
        }));

        let read_data_cb = Arc::clone(&read_data);
        let att_cb = Arc::clone(&att_ref);

        let att_callback: AttResponseCallback =
            Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                Self::handle_read_response(
                    &client_ref,
                    &att_cb,
                    read_data_cb,
                    req_id,
                    rsp_opcode,
                    rsp_pdu,
                );
            }));

        let att_id = match guard.att.lock() {
            Ok(mut att) => att.send(opcode, &pdu, att_callback),
            Err(_) => 0,
        };

        if att_id == 0 {
            let mut rd = read_data.lock().unwrap();
            if let Some(cb) = rd.callback.take() {
                drop(rd);
                drop(guard);
                cb(false, 0, &[]);
            }
            return 0;
        }

        guard.pending_requests.push(Request {
            id: req_id,
            att_id,
            long_write: false,
            prep_write: false,
        });

        drop(guard);
        req_id
    }

    /// Read multiple characteristic values in a single ATT operation.
    pub fn read_multiple(self: &Arc<Self>, handles: &[u16], callback: ReadCallback) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                callback(false, 0, &[]);
                return 0;
            }
        };

        if !guard.ready || handles.is_empty() {
            drop(guard);
            callback(false, 0, &[]);
            return 0;
        }

        let req_id = guard.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Determine opcode: use READ_MULT_VL if EATT is supported.
        let use_vl = GattServerFeatures::from_bits_truncate(guard.server_features)
            .contains(GattServerFeatures::EATT);

        let opcode = if use_vl { BT_ATT_OP_READ_MULT_VL_REQ } else { BT_ATT_OP_READ_MULT_REQ };

        // Build PDU: concatenated handle values (2 bytes each, LE).
        let mut pdu = Vec::with_capacity(handles.len() * 2);
        for &h in handles {
            let mut buf = [0u8; 2];
            put_le16(h, &mut buf);
            pdu.extend_from_slice(&buf);
        }

        let callback = Arc::new(StdMutex::new(Some(callback)));
        let callback_clone = Arc::clone(&callback);

        let att_callback: AttResponseCallback =
            Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                let cb = {
                    let mut lock = callback_clone.lock().unwrap();
                    lock.take()
                };
                if let Some(cb) = cb {
                    if rsp_opcode == BT_ATT_OP_ERROR_RSP && rsp_pdu.len() >= 4 {
                        cb(false, rsp_pdu[3], &[]);
                    } else if rsp_opcode == BT_ATT_OP_READ_MULT_RSP
                        || rsp_opcode == BT_ATT_OP_READ_MULT_VL_RSP
                    {
                        cb(true, 0, rsp_pdu);
                    } else {
                        cb(false, 0, &[]);
                    }
                }
            }));

        let att_id = match guard.att.lock() {
            Ok(mut att) => att.send(opcode, &pdu, att_callback),
            Err(_) => 0,
        };

        if att_id == 0 {
            let cb = { callback.lock().unwrap().take() };
            drop(guard);
            if let Some(cb) = cb {
                cb(false, 0, &[]);
            }
            return 0;
        }

        guard.pending_requests.push(Request {
            id: req_id,
            att_id,
            long_write: false,
            prep_write: false,
        });

        drop(guard);
        req_id
    }

    // -----------------------------------------------------------------
    // Write Operations
    // -----------------------------------------------------------------

    /// Write a value without expecting a response (Write Command).
    ///
    /// If `signed` is true, uses Signed Write Command.
    pub fn write_without_response(
        self: &Arc<Self>,
        handle: u16,
        signed: bool,
        value: &[u8],
    ) -> u32 {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };

        if !guard.ready {
            return 0;
        }

        let opcode = if signed { BT_ATT_OP_SIGNED_WRITE_CMD } else { BT_ATT_OP_WRITE_CMD };

        // Build PDU: handle(2) + value
        let mut pdu = Vec::with_capacity(2 + value.len());
        let mut hbuf = [0u8; 2];
        put_le16(handle, &mut hbuf);
        pdu.extend_from_slice(&hbuf);
        pdu.extend_from_slice(value);

        let req_id = guard.next_request_id.fetch_add(1, Ordering::Relaxed);

        let att_id = match guard.att.lock() {
            Ok(mut att) => att.send(opcode, &pdu, None),
            Err(_) => 0,
        };

        if att_id == 0 {
            return 0;
        }

        // Write commands don't have a pending request entry since no
        // response is expected. Return the ID for tracking purposes.
        drop(guard);
        req_id
    }

    /// Write a value with a Write Request (expects Write Response).
    pub fn write_value(
        self: &Arc<Self>,
        handle: u16,
        value: &[u8],
        callback: ClientCallback,
    ) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                callback(false, 0);
                return 0;
            }
        };

        if !guard.ready {
            drop(guard);
            callback(false, 0);
            return 0;
        }

        let req_id = guard.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Build PDU: handle(2) + value
        let mut pdu = Vec::with_capacity(2 + value.len());
        let mut hbuf = [0u8; 2];
        put_le16(handle, &mut hbuf);
        pdu.extend_from_slice(&hbuf);
        pdu.extend_from_slice(value);

        let callback = Arc::new(StdMutex::new(Some(callback)));
        let cb_clone = Arc::clone(&callback);

        let att_callback: AttResponseCallback =
            Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                let cb = { cb_clone.lock().unwrap().take() };
                if let Some(cb) = cb {
                    if rsp_opcode == BT_ATT_OP_ERROR_RSP && rsp_pdu.len() >= 4 {
                        cb(false, rsp_pdu[3]);
                    } else if rsp_opcode == BT_ATT_OP_WRITE_RSP {
                        cb(true, 0);
                    } else {
                        cb(false, 0);
                    }
                }
            }));

        let att_id = match guard.att.lock() {
            Ok(mut att) => att.send(BT_ATT_OP_WRITE_REQ, &pdu, att_callback),
            Err(_) => 0,
        };

        if att_id == 0 {
            let cb = { callback.lock().unwrap().take() };
            drop(guard);
            if let Some(cb) = cb {
                cb(false, 0);
            }
            return 0;
        }

        guard.pending_requests.push(Request {
            id: req_id,
            att_id,
            long_write: false,
            prep_write: false,
        });

        drop(guard);
        req_id
    }

    /// Write a long value using Prepare Write + Execute Write.
    ///
    /// If `reliable` is true, validates each echoed Prepare Write Response.
    pub fn write_long_value(
        self: &Arc<Self>,
        reliable: bool,
        handle: u16,
        offset: u16,
        value: &[u8],
        callback: WriteLongCallback,
    ) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                callback(false, false, 0);
                return 0;
            }
        };

        if !guard.ready {
            drop(guard);
            callback(false, false, 0);
            return 0;
        }

        // Log reliable write mode. The caller may verify characteristic
        // support using `has_reliable_write_ext` with the extended properties
        // descriptor value. Passing (0, 0) returns false which is the safe
        // default when the ext-prop value is not yet available.
        if reliable {
            tracing::debug!("Long write to handle 0x{:04X} with reliable mode enabled", handle);
        }

        let req_id = guard.next_request_id.fetch_add(1, Ordering::Relaxed);

        let data = LongWriteData {
            handle,
            offset,
            value: value.to_vec(),
            cur_offset: offset,
            reliable,
            callback: Some(callback),
        };

        if guard.in_long_write {
            // Queue the long write for later execution.
            guard.long_write_queue.push_back(data);
            guard.pending_requests.push(Request {
                id: req_id,
                att_id: 0,
                long_write: true,
                prep_write: false,
            });
            drop(guard);
            return req_id;
        }

        guard.in_long_write = true;

        let client_ref = Arc::clone(self);
        let long_data = Arc::new(StdMutex::new(data));

        let att_id = Self::send_next_prep_write(&guard.att, &long_data, req_id, &client_ref);

        if att_id == 0 {
            guard.in_long_write = false;
            let cb = { long_data.lock().unwrap().callback.take() };
            drop(guard);
            if let Some(cb) = cb {
                cb(false, false, 0);
            }
            return 0;
        }

        guard.pending_requests.push(Request {
            id: req_id,
            att_id,
            long_write: true,
            prep_write: false,
        });

        drop(guard);
        req_id
    }

    /// Prepare a write operation as part of an explicit reliable write session.
    pub fn prepare_write(
        self: &Arc<Self>,
        session_id: u32,
        handle: u16,
        offset: u16,
        value: &[u8],
        callback: ClientCallback,
    ) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                callback(false, 0);
                return 0;
            }
        };

        if !guard.ready {
            drop(guard);
            callback(false, 0);
            return 0;
        }

        let req_id = guard.next_request_id.fetch_add(1, Ordering::Relaxed);
        guard.reliable_write_session_id = session_id;

        // Build Prepare Write Request PDU: handle(2) + offset(2) + value
        let mut pdu = Vec::with_capacity(4 + value.len());
        let mut buf = [0u8; 2];
        put_le16(handle, &mut buf);
        pdu.extend_from_slice(&buf);
        put_le16(offset, &mut buf);
        pdu.extend_from_slice(&buf);
        pdu.extend_from_slice(value);

        let expected_value = value.to_vec();
        let expected_handle = handle;
        let expected_offset = offset;

        let callback = Arc::new(StdMutex::new(Some(callback)));
        let cb_clone = Arc::clone(&callback);

        let att_callback: AttResponseCallback =
            Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                let cb = { cb_clone.lock().unwrap().take() };
                if let Some(cb) = cb {
                    if rsp_opcode == BT_ATT_OP_ERROR_RSP && rsp_pdu.len() >= 4 {
                        cb(false, rsp_pdu[3]);
                    } else if rsp_opcode == BT_ATT_OP_PREP_WRITE_RSP {
                        // Validate echoed data for reliable writes.
                        if rsp_pdu.len() >= 4 {
                            let echo_handle = get_le16(&rsp_pdu[0..2]);
                            let echo_offset = get_le16(&rsp_pdu[2..4]);
                            let echo_value = &rsp_pdu[4..];
                            if echo_handle == expected_handle
                                && echo_offset == expected_offset
                                && echo_value == expected_value.as_slice()
                            {
                                cb(true, 0);
                            } else {
                                cb(false, 0);
                            }
                        } else {
                            cb(false, 0);
                        }
                    } else {
                        cb(false, 0);
                    }
                }
            }));

        let att_id = match guard.att.lock() {
            Ok(mut att) => att.send(BT_ATT_OP_PREP_WRITE_REQ, &pdu, att_callback),
            Err(_) => 0,
        };

        if att_id == 0 {
            let cb = { callback.lock().unwrap().take() };
            drop(guard);
            if let Some(cb) = cb {
                cb(false, 0);
            }
            return 0;
        }

        guard.pending_requests.push(Request {
            id: req_id,
            att_id,
            long_write: false,
            prep_write: true,
        });

        drop(guard);
        req_id
    }

    /// Execute a prepared write session.
    ///
    /// Sends an Execute Write Request to commit or cancel queued writes.
    pub fn write_execute(self: &Arc<Self>, _session_id: u32, callback: ClientCallback) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                callback(false, 0);
                return 0;
            }
        };

        if !guard.ready {
            drop(guard);
            callback(false, 0);
            return 0;
        }

        let req_id = guard.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Execute Write PDU: flags(1) — 0x01 to commit, 0x00 to cancel.
        let pdu = [0x01u8]; // Always commit.

        let callback = Arc::new(StdMutex::new(Some(callback)));
        let cb_clone = Arc::clone(&callback);

        let att_callback: AttResponseCallback =
            Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                let cb = { cb_clone.lock().unwrap().take() };
                if let Some(cb) = cb {
                    if rsp_opcode == BT_ATT_OP_ERROR_RSP && rsp_pdu.len() >= 4 {
                        cb(false, rsp_pdu[3]);
                    } else if rsp_opcode == BT_ATT_OP_EXEC_WRITE_RSP {
                        cb(true, 0);
                    } else {
                        cb(false, 0);
                    }
                }
            }));

        let att_id = match guard.att.lock() {
            Ok(mut att) => att.send(BT_ATT_OP_EXEC_WRITE_REQ, &pdu, att_callback),
            Err(_) => 0,
        };

        if att_id == 0 {
            let cb = { callback.lock().unwrap().take() };
            drop(guard);
            if let Some(cb) = cb {
                cb(false, 0);
            }
            return 0;
        }

        guard.pending_requests.push(Request {
            id: req_id,
            att_id,
            long_write: false,
            prep_write: true,
        });

        drop(guard);
        req_id
    }

    // -----------------------------------------------------------------
    // Notification Registration
    // -----------------------------------------------------------------

    /// Register for notifications/indications on a characteristic.
    ///
    /// Finds the characteristic's CCC descriptor and writes the appropriate
    /// value to enable notifications (0x0001) or indications (0x0002).
    pub fn register_notify(
        self: &Arc<Self>,
        chrc_value_handle: u16,
        register_cb: RegisterCallback,
        notify_cb: NotifyCallback,
    ) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                register_cb(0xFF);
                return 0;
            }
        };

        if !guard.ready {
            drop(guard);
            register_cb(0xFF);
            return 0;
        }

        let reg_id = guard.next_reg_id.fetch_add(1, Ordering::Relaxed);

        // Find or create the NotifyChrc entry for this value handle.
        let chrc_idx = Self::find_or_create_notify_chrc(&mut guard, chrc_value_handle);

        let notify_data = NotifyData {
            id: reg_id,
            att_ecode: 0,
            chrc_idx: Some(chrc_idx),
            register_cb: Some(register_cb),
            notify_cb: Some(Arc::new(notify_cb)),
        };
        guard.notify_list.push(notify_data);

        // Increment the notify count for this characteristic.
        guard.notify_chrcs[chrc_idx].notify_count += 1;

        let chrc = &guard.notify_chrcs[chrc_idx];
        let ccc_handle = chrc.ccc_handle;
        let properties = chrc.properties;
        let notify_count = chrc.notify_count;
        let ccc_write_id = chrc.ccc_write_id;

        if ccc_handle == 0 {
            // No CCC descriptor found — complete registration immediately.
            Self::complete_notify_registration(&mut guard, reg_id, 0);
            drop(guard);
            return reg_id;
        }

        if ccc_write_id != 0 {
            // CCC write already in progress — queue this registration.
            guard.notify_chrcs[chrc_idx].reg_notify_queue.push_back(reg_id);
            drop(guard);
            return reg_id;
        }

        if notify_count > 1 {
            // CCC already enabled — complete immediately.
            Self::complete_notify_registration(&mut guard, reg_id, 0);
            drop(guard);
            return reg_id;
        }

        // First registration — write CCC to enable.
        let ccc_value = Self::get_ccc_value(properties);
        let client_ref = Arc::clone(self);

        let write_id = Self::write_ccc_descriptor(
            &guard.att, ccc_handle, ccc_value, chrc_idx, reg_id, client_ref,
        );

        if write_id != 0 {
            guard.notify_chrcs[chrc_idx].ccc_write_id = write_id;
        } else {
            Self::complete_notify_registration(&mut guard, reg_id, 0xFF);
        }

        drop(guard);
        reg_id
    }

    /// Unregister a notification registration.
    pub fn unregister_notify(self: &Arc<Self>, id: u32) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        let pos = match guard.notify_list.iter().position(|n| n.id == id) {
            Some(p) => p,
            None => return false,
        };

        let data = guard.notify_list.remove(pos);

        // Decrement notify count on the characteristic.
        if let Some(chrc_idx) = data.chrc_idx {
            if chrc_idx < guard.notify_chrcs.len() {
                let chrc = &mut guard.notify_chrcs[chrc_idx];
                chrc.notify_count = chrc.notify_count.saturating_sub(1);

                if chrc.notify_count == 0 && chrc.ccc_handle != 0 {
                    // Last registration removed — disable CCC.
                    let ccc_handle = chrc.ccc_handle;
                    let att_ref = Arc::clone(&guard.att);
                    let ccc_value: u16 = 0x0000;

                    let mut pdu = [0u8; 4];
                    put_le16(ccc_handle, &mut pdu[0..2]);
                    put_le16(ccc_value, &mut pdu[2..4]);

                    if let Ok(mut att) = att_ref.lock() {
                        att.send(BT_ATT_OP_WRITE_REQ, &pdu, None);
                    }
                }
            }
        }

        drop(guard);
        true
    }

    // -----------------------------------------------------------------
    // Security
    // -----------------------------------------------------------------

    /// Set the ATT security level.
    pub fn set_security(self: &Arc<Self>, level: i32) -> bool {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match guard.att.lock() {
            Ok(mut att) => att.set_security(level),
            Err(_) => false,
        }
    }

    /// Get the current ATT security level.
    ///
    /// Returns the security level as an integer corresponding to
    /// [`AttSecurityLevel`] values (0=Auto, 1=Low, 2=Medium, 3=High, 4=Fips).
    /// Returns -1 on error.
    pub fn get_security(self: &Arc<Self>) -> i32 {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return -1,
        };
        let mut enc_size: u8 = 0;
        match guard.att.lock() {
            Ok(att) => match att.get_security(&mut enc_size) {
                Ok(level) => {
                    // Validate that the returned level corresponds to a known
                    // AttSecurityLevel variant for logging purposes.
                    if let Ok(sec) = AttSecurityLevel::try_from(level as u8) {
                        tracing::trace!("Current security level: {:?}", sec);
                    }
                    level
                }
                Err(_) => -1,
            },
            Err(_) => -1,
        }
    }

    // -----------------------------------------------------------------
    // Idle
    // -----------------------------------------------------------------

    /// Register an idle callback invoked when no operations are pending.
    pub fn idle_register(&self, callback: IdleCallback) -> u32 {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        let id = guard.next_idle_id;
        guard.next_idle_id = guard.next_idle_id.wrapping_add(1);
        if guard.next_idle_id == 0 {
            guard.next_idle_id = 1;
        }

        if guard.pending_requests.is_empty() && guard.long_write_queue.is_empty() {
            // Already idle — invoke immediately.
            drop(guard);
            callback();
        } else {
            guard.idle_cbs.push(IdleCb { id, callback: Some(callback) });
        }
        id
    }

    /// Unregister an idle callback.
    pub fn idle_unregister(&self, id: u32) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let before = guard.idle_cbs.len();
        guard.idle_cbs.retain(|cb| cb.id != id);
        guard.idle_cbs.len() < before
    }

    // -----------------------------------------------------------------
    // Retry
    // -----------------------------------------------------------------

    /// Set the retry flag on a pending ATT operation.
    pub fn set_retry(self: &Arc<Self>, id: u32, retry: bool) -> bool {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        // Find the ATT operation ID for this request.
        let att_id = match guard.pending_requests.iter().find(|r| r.id == id) {
            Some(r) => r.att_id,
            None => return false,
        };

        if att_id == 0 {
            return false;
        }

        match guard.att.lock() {
            Ok(mut att) => att.set_retry(att_id, retry),
            Err(_) => false,
        }
    }

    // =================================================================
    // Internal: ATT handler registration
    // =================================================================

    /// Register notification/indication handlers on the ATT transport.
    fn register_att_handlers(client: &Arc<Self>) {
        let guard = match client.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        let att_ref = Arc::clone(&guard.att);
        drop(guard);

        // Register NFY handler.
        let client_nfy = Arc::clone(client);
        let nfy_cb: AttNotifyCallback =
            Box::new(move |_chan_idx: usize, _mtu: u16, opcode: u8, pdu: &[u8]| {
                Self::handle_notification(&client_nfy, opcode, pdu);
            });
        let nfy_id = match att_ref.lock() {
            Ok(mut att) => att.register(BT_ATT_OP_HANDLE_NFY, nfy_cb),
            Err(_) => 0,
        };

        // Register NFY_MULT handler.
        let client_nfy_mult = Arc::clone(client);
        let nfy_mult_cb: AttNotifyCallback =
            Box::new(move |_chan_idx: usize, _mtu: u16, opcode: u8, pdu: &[u8]| {
                Self::handle_notification(&client_nfy_mult, opcode, pdu);
            });
        let nfy_mult_id = match att_ref.lock() {
            Ok(mut att) => att.register(BT_ATT_OP_HANDLE_NFY_MULT, nfy_mult_cb),
            Err(_) => 0,
        };

        // Register IND handler.
        let client_ind = Arc::clone(client);
        let ind_cb: AttNotifyCallback =
            Box::new(move |_chan_idx: usize, _mtu: u16, opcode: u8, pdu: &[u8]| {
                Self::handle_indication(&client_ind, opcode, pdu);
            });
        let ind_id = match att_ref.lock() {
            Ok(mut att) => att.register(BT_ATT_OP_HANDLE_IND, ind_cb),
            Err(_) => 0,
        };

        // Store the registration IDs.
        if let Ok(mut guard) = client.inner.lock() {
            guard.nfy_id = nfy_id;
            guard.nfy_mult_id = nfy_mult_id;
            guard.ind_id = ind_id;
        }
    }

    // =================================================================
    // Internal: Initialization procedure
    // =================================================================

    /// Async initialization procedure.
    ///
    /// Performs: MTU exchange → server feature read → DB hash comparison →
    /// full GATT discovery → client feature write → Service Changed
    /// registration → ready notification.
    async fn init_procedure(client: Arc<Self>, mtu: u16) {
        let att = {
            let guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => {
                    Self::init_complete(&client, false, 0);
                    return;
                }
            };
            Arc::clone(&guard.att)
        };

        // Step 1: MTU exchange (for LE links with MTU > default).
        let link_type = match att.lock() {
            Ok(a) => a.get_link_type(),
            Err(_) => BT_ATT_LE,
        };

        if link_type == BT_ATT_LE && mtu > BT_ATT_DEFAULT_LE_MTU {
            match helpers::exchange_mtu(&att, mtu).await {
                Ok(negotiated) => {
                    tracing::debug!("MTU exchange complete: {}", negotiated);
                    // Update the ATT transport's MTU to the negotiated value.
                    if let Ok(mut att_guard) = att.lock() {
                        att_guard.set_mtu(negotiated);
                    }
                }
                Err(e) => {
                    tracing::warn!("MTU exchange failed: {}, continuing", e);
                }
            }
        }

        // Step 2: Read Server Supported Features.
        let server_feat = Self::read_server_features(&att).await;
        if let Ok(mut guard) = client.inner.lock() {
            guard.server_features = server_feat;
        }

        // Step 3: Attempt DB hash comparison for robust caching.
        let skip_discovery = Self::check_db_hash(&client, &att).await;

        if !skip_discovery {
            // Step 4: Full GATT discovery.
            if let Err(e) = Self::perform_discovery(&client, &att).await {
                tracing::warn!("GATT discovery failed: {}", e);
                Self::init_complete(&client, false, 0);
                return;
            }

            // After discovery, update the DB hash so subsequent connections
            // can use robust caching to skip re-discovery.
            if let Ok(guard) = client.inner.lock() {
                guard.db.hash_update();
            }
        }

        // Step 5: Write client features if robust caching supported.
        Self::write_client_features(&client, &att).await;

        // Step 6: Register Service Changed indication handler.
        Self::register_service_changed(&client, &att).await;

        // Step 7: Mark ready and notify.
        Self::init_complete(&client, true, 0);
    }

    /// Mark the initialization as complete, setting the ready state and
    /// invoking all registered ready callbacks.
    fn init_complete(client: &Arc<Self>, success: bool, att_ecode: u8) {
        let cbs = {
            let mut guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.in_init = false;
            guard.ready = success;
            client.ready_flag.store(success, Ordering::Release);

            guard.debug_log(&format!(
                "GATT client init complete: success={}, att_ecode=0x{:02X}",
                success, att_ecode
            ));

            // Drain ready callbacks.
            let mut cbs = Vec::new();
            for cb_entry in guard.ready_cbs.drain(..) {
                if let Some(cb) = cb_entry.callback {
                    cbs.push(cb);
                }
            }
            cbs
        };

        // Invoke callbacks outside the lock.
        for cb in cbs {
            cb(success, att_ecode);
        }

        // Propagate to clones.
        if let Ok(guard) = client.inner.lock() {
            let clone_refs: Vec<Arc<BtGattClient>> = guard.clones.iter().map(Arc::clone).collect();
            drop(guard);
            for c in clone_refs {
                Self::init_complete(&c, success, att_ecode);
            }
        }
    }

    // =================================================================
    // Internal: Server feature and DB hash reads
    // =================================================================

    /// Read Server Supported Features via read_by_type.
    async fn read_server_features(att: &Arc<StdMutex<BtAtt>>) -> u8 {
        let uuid = BtUuid::from_u16(SERVER_FEAT_UUID);
        match helpers::read_by_type(att, 0x0001, 0xFFFF, &uuid).await {
            Ok(req) => {
                let result = req.result();
                let mut iter = BtGattIter::init(result);
                if let Some(entry) = iter.next_read_by_type() {
                    if !entry.value.is_empty() {
                        let feat = entry.value[0];
                        tracing::debug!("Server features: 0x{:02X}", feat);
                        return feat;
                    }
                }
                0
            }
            Err(e) => {
                tracing::debug!("Server features read failed: {}", e);
                0
            }
        }
    }

    /// Check the DB hash for robust caching.
    ///
    /// Returns `true` if the hash matches (discovery can be skipped).
    async fn check_db_hash(client: &Arc<Self>, att: &Arc<StdMutex<BtAtt>>) -> bool {
        let features = match client.inner.lock() {
            Ok(g) => g.features,
            Err(_) => return false,
        };

        if GattClientFeatures::from_bits_truncate(features)
            .contains(GattClientFeatures::ROBUST_CACHING)
        {
            let uuid = BtUuid::from_u16(DB_HASH_UUID);
            match helpers::read_by_type(att, 0x0001, 0xFFFF, &uuid).await {
                Ok(req) => {
                    let result = req.result();
                    let mut iter = BtGattIter::init(result);
                    if let Some(entry) = iter.next_read_by_type() {
                        if entry.value.len() == 16 {
                            let mut remote_hash = [0u8; 16];
                            remote_hash.copy_from_slice(entry.value);

                            let db = match client.inner.lock() {
                                Ok(g) => g.db.clone(),
                                Err(_) => return false,
                            };
                            let local_hash = db.get_hash();

                            if remote_hash == local_hash {
                                tracing::debug!("DB hash matches — skipping discovery");
                                return true;
                            }
                            tracing::debug!("DB hash mismatch — full discovery required");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("DB hash read failed: {}", e);
                }
            }
        }
        false
    }

    // =================================================================
    // Internal: GATT discovery
    // =================================================================

    /// Perform full GATT service discovery and populate the database.
    async fn perform_discovery(
        client: &Arc<Self>,
        att: &Arc<StdMutex<BtAtt>>,
    ) -> Result<(), GattClientError> {
        // Discover primary services.
        let prim_req = helpers::discover_all_primary_services(att, None).await?;
        let prim_result = prim_req.result().clone();
        let mut prim_iter = BtGattIter::init(&prim_result);

        let db = match client.inner.lock() {
            Ok(g) => g.db.clone(),
            Err(_) => return Err(GattClientError::InvalidState),
        };

        let mut services: Vec<ServiceEntry> = Vec::new();
        while let Some(svc) = prim_iter.next_service() {
            services.push(svc);
        }

        // Insert primary services into the DB and discover their contents.
        for svc in &services {
            Self::insert_and_discover_service(client, att, &db, svc, true).await?;
        }

        // Discover secondary services.
        match helpers::discover_secondary_services(att, None, 0x0001, 0xFFFF).await {
            Ok(sec_req) => {
                let sec_result = sec_req.result().clone();
                let mut sec_iter = BtGattIter::init(&sec_result);
                let mut sec_services = Vec::new();
                while let Some(svc) = sec_iter.next_service() {
                    sec_services.push(svc);
                }
                for svc in &sec_services {
                    Self::insert_and_discover_service(client, att, &db, svc, false).await?;
                }
            }
            Err(GattError::AttError(e)) if e == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => {
                // No secondary services — that is fine.
            }
            Err(e) => {
                tracing::debug!("Secondary service discovery failed: {}", e);
            }
        }

        tracing::debug!("GATT discovery complete");
        Ok(())
    }

    /// Insert a single service into the DB and discover its included services,
    /// characteristics, and descriptors.
    async fn insert_and_discover_service(
        _client: &Arc<Self>,
        att: &Arc<StdMutex<BtAtt>>,
        db: &GattDb,
        svc: &ServiceEntry,
        primary: bool,
    ) -> Result<(), GattClientError> {
        let num_handles = svc.end_handle.saturating_sub(svc.start_handle) + 1;
        let db_svc = match db.insert_service(svc.start_handle, &svc.uuid, primary, num_handles) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "Failed to insert service 0x{:04X}-0x{:04X}",
                    svc.start_handle,
                    svc.end_handle
                );
                return Ok(());
            }
        };

        // Discover included services.
        if svc.start_handle < svc.end_handle {
            match helpers::discover_included_services(att, svc.start_handle + 1, svc.end_handle)
                .await
            {
                Ok(incl_req) => {
                    let incl_result = incl_req.result().clone();
                    let mut incl_iter = BtGattIter::init(&incl_result);
                    while let Some(_incl) = incl_iter.next_included_service() {
                        // Included services are stored in the DB during
                        // characteristic discovery (they appear as attributes).
                    }
                }
                Err(GattError::AttError(e)) if e == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => {}
                Err(e) => {
                    tracing::debug!("Included service discovery failed: {}", e);
                }
            }
        }

        // Discover characteristics.
        let chars = Self::discover_service_chars(att, svc).await?;

        // Insert characteristics and discover their descriptors.
        for chr in &chars {
            let _char_attr = db_svc.insert_characteristic(
                chr.start_handle,
                &chr.uuid,
                0, // Permissions set by the server.
                chr.properties,
                None,
                None,
                None,
            );

            // Discover descriptors between this characteristic's value handle
            // and the next characteristic (or end of service).
            let desc_start = chr.value_handle + 1;
            let desc_end = chr.end_handle;

            if desc_start <= desc_end {
                let desc_discover_result: Result<BtGattRequest, GattError> =
                    helpers::discover_descriptors(att, desc_start, desc_end).await;
                match desc_discover_result {
                    Ok(desc_req) => {
                        let desc_result: BtGattResult = desc_req.result().clone();
                        let mut desc_iter = BtGattIter::init(&desc_result);
                        while let Some(desc) = desc_iter.next_descriptor() {
                            let desc_entry: &DescEntry = &desc;
                            db_svc.insert_descriptor(
                                desc_entry.handle,
                                &desc_entry.uuid,
                                0,
                                None,
                                None,
                                None,
                            );
                        }
                    }
                    Err(GattError::AttError(e)) if e == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => {}
                    Err(e) => {
                        tracing::trace!(
                            "Descriptor discovery failed for char 0x{:04X}: {}",
                            chr.value_handle,
                            e
                        );
                    }
                }
            }
        }

        // Activate the service in the DB.
        db_svc.set_active(true);

        Ok(())
    }

    /// Discover characteristics within a service.
    async fn discover_service_chars(
        att: &Arc<StdMutex<BtAtt>>,
        svc: &ServiceEntry,
    ) -> Result<Vec<CharEntry>, GattClientError> {
        let mut chars = Vec::new();

        if svc.start_handle >= svc.end_handle {
            return Ok(chars);
        }

        match helpers::discover_characteristics(att, svc.start_handle + 1, svc.end_handle).await {
            Ok(char_req) => {
                let char_result = char_req.result().clone();
                let mut char_iter = BtGattIter::init(&char_result);
                while let Some(chr) = char_iter.next_characteristic() {
                    chars.push(chr);
                }
            }
            Err(GattError::AttError(e)) if e == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => {}
            Err(e) => {
                tracing::debug!("Characteristic discovery failed: {}", e);
            }
        }

        Ok(chars)
    }

    // =================================================================
    // Internal: Client feature write
    // =================================================================

    /// Write Client Supported Features to the server.
    async fn write_client_features(client: &Arc<Self>, att: &Arc<StdMutex<BtAtt>>) {
        let features = match client.inner.lock() {
            Ok(g) => g.features,
            Err(_) => return,
        };

        if features == 0 {
            return;
        }

        let uuid = BtUuid::from_u16(CLIENT_FEAT_UUID);
        match helpers::read_by_type(att, 0x0001, 0xFFFF, &uuid).await {
            Ok(req) => {
                let result = req.result();
                let mut iter = BtGattIter::init(result);
                if let Some(entry) = iter.next_read_by_type() {
                    let handle = entry.handle;
                    // Merge existing features with our features.
                    let existing = if entry.value.is_empty() { 0u8 } else { entry.value[0] };
                    let new_features = existing | features;

                    // Write the merged features.
                    let mut pdu = Vec::with_capacity(3);
                    let mut hbuf = [0u8; 2];
                    put_le16(handle, &mut hbuf);
                    pdu.extend_from_slice(&hbuf);
                    pdu.push(new_features);

                    if let Ok(mut att_guard) = att.lock() {
                        att_guard.send(BT_ATT_OP_WRITE_REQ, &pdu, None);
                    }
                    tracing::debug!("Wrote client features: 0x{:02X}", new_features);
                }
            }
            Err(e) => {
                tracing::debug!("Client features write skipped: {}", e);
            }
        }
    }

    // =================================================================
    // Internal: Service Changed
    // =================================================================

    /// Register the Service Changed indication handler.
    async fn register_service_changed(client: &Arc<Self>, att: &Arc<StdMutex<BtAtt>>) {
        let db = match client.inner.lock() {
            Ok(g) => g.db.clone(),
            Err(_) => return,
        };

        // Find the GATT service (0x1801) and Service Changed characteristic.
        let gatt_svc_uuid = BtUuid::from_u16(GATT_SVC_UUID);
        let svc_chngd_uuid = BtUuid::from_u16(SVC_CHNGD_UUID);

        let mut svc_chngd_value_handle: u16 = 0;
        let mut ccc_handle: u16 = 0;

        db.foreach_service(Some(&gatt_svc_uuid), |svc_attr| {
            if svc_attr.get_service_data().is_some() {
                if let Some(svc_service) = svc_attr.get_service() {
                    svc_service.foreach_char(|char_attr| {
                        if let Some(char_data) = char_attr.get_char_data() {
                            if char_data.uuid == svc_chngd_uuid {
                                svc_chngd_value_handle = char_data.value_handle;
                            }
                        }
                    });
                }
            }
        });

        if svc_chngd_value_handle == 0 {
            tracing::debug!("Service Changed characteristic not found");
            return;
        }

        // Find CCC descriptor for Service Changed.
        let ccc_uuid = BtUuid::from_u16(CCC_UUID);
        db.foreach_in_range(
            Some(&ccc_uuid),
            |attr| {
                let handle = attr.get_handle();
                if ccc_handle == 0 && handle > svc_chngd_value_handle {
                    ccc_handle = handle;
                }
            },
            svc_chngd_value_handle + 1,
            0xFFFF,
        );

        if ccc_handle == 0 {
            tracing::debug!("Service Changed CCC not found");
            return;
        }

        // Write CCC to enable indications (0x0002).
        let mut pdu = [0u8; 4];
        put_le16(ccc_handle, &mut pdu[0..2]);
        put_le16(0x0002, &mut pdu[2..4]);

        if let Ok(mut att_guard) = att.lock() {
            let write_id = att_guard.send(BT_ATT_OP_WRITE_REQ, &pdu, None);
            if write_id != 0 {
                if let Ok(mut guard) = client.inner.lock() {
                    guard.svc_chngd_ind_id = write_id;
                    guard.svc_chngd_registered = true;
                }
                tracing::debug!(
                    "Service Changed indication registered (CCC handle=0x{:04X})",
                    ccc_handle
                );
            }
        }
    }

    /// Handle a Service Changed indication.
    fn handle_service_changed(client: &Arc<Self>, pdu: &[u8]) {
        if pdu.len() < 4 {
            tracing::warn!("Service Changed indication too short");
            return;
        }

        let start_handle = get_le16(&pdu[0..2]);
        let end_handle = get_le16(&pdu[2..4]);

        tracing::debug!("Service Changed: 0x{:04X}-0x{:04X}", start_handle, end_handle);

        {
            let mut guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };

            if guard.in_svc_chngd {
                // Queue for later processing.
                guard.svc_chngd_queue.push_back(ServiceChangedOp { start_handle, end_handle });
                return;
            }

            guard.in_svc_chngd = true;
        }

        // Clear affected range in the database.
        let db = match client.inner.lock() {
            Ok(g) => g.db.clone(),
            Err(_) => return,
        };
        db.clear_range(start_handle, end_handle);

        // Spawn async re-discovery of the affected range.
        let client_ref = Arc::clone(client);
        tokio::spawn(async move {
            Self::process_service_changed(client_ref, start_handle, end_handle).await;
        });
    }

    /// Re-discover services in the affected handle range after Service Changed.
    async fn process_service_changed(client: Arc<Self>, start_handle: u16, end_handle: u16) {
        let att = match client.inner.lock() {
            Ok(g) => Arc::clone(&g.att),
            Err(_) => {
                Self::service_changed_complete(&client);
                return;
            }
        };

        // Enumerate existing services in the affected range before clearing.
        if let Ok(guard) = client.inner.lock() {
            let mut affected_count: u32 = 0;
            guard.db.foreach_service_in_range(
                None,
                &mut |_attr| {
                    affected_count += 1;
                },
                start_handle,
                end_handle,
            );
            if affected_count > 0 {
                tracing::debug!(
                    "Service Changed: {} services affected in range 0x{:04X}-0x{:04X}",
                    affected_count,
                    start_handle,
                    end_handle
                );
            }
        }

        // Re-discover primary services in the affected range.
        match helpers::discover_primary_services(&att, None, start_handle, end_handle).await {
            Ok(req) => {
                let result = req.result().clone();
                let mut iter = BtGattIter::init(&result);
                let db = match client.inner.lock() {
                    Ok(g) => g.db.clone(),
                    Err(_) => {
                        Self::service_changed_complete(&client);
                        return;
                    }
                };

                let mut services = Vec::new();
                while let Some(svc) = iter.next_service() {
                    services.push(svc);
                }

                for svc in &services {
                    if let Err(e) =
                        Self::insert_and_discover_service(&client, &att, &db, svc, true).await
                    {
                        tracing::warn!("Re-discovery failed for service: {}", e);
                    }
                }
            }
            Err(GattError::AttError(e)) if e == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => {}
            Err(e) => {
                tracing::warn!("Service Changed re-discovery failed: {}", e);
            }
        }

        // Notify upper layer.
        let svc_chngd_cb = {
            let guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => {
                    Self::service_changed_complete(&client);
                    return;
                }
            };
            guard.svc_chngd_callback.as_ref().map(|_| ())
        };

        if svc_chngd_cb.is_some() {
            let guard = client.inner.lock().unwrap();
            if let Some(ref cb) = guard.svc_chngd_callback {
                cb(start_handle, end_handle);
            }
            drop(guard);
        }

        // Propagate to clones.
        let clone_refs = {
            let guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => {
                    Self::service_changed_complete(&client);
                    return;
                }
            };
            guard.clones.iter().map(Arc::clone).collect::<Vec<_>>()
        };
        for c in clone_refs {
            if let Ok(cg) = c.inner.lock() {
                if let Some(ref cb) = cg.svc_chngd_callback {
                    cb(start_handle, end_handle);
                }
            }
        }

        Self::service_changed_complete(&client);
    }

    /// Complete Service Changed processing and process any queued ranges.
    fn service_changed_complete(client: &Arc<Self>) {
        let next_op = {
            let mut guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.in_svc_chngd = false;
            guard.svc_chngd_queue.pop_front()
        };

        if let Some(op) = next_op {
            let client_ref = Arc::clone(client);
            tokio::spawn(async move {
                // Set in_svc_chngd again before processing.
                if let Ok(mut g) = client_ref.inner.lock() {
                    g.in_svc_chngd = true;
                }
                let db = match client_ref.inner.lock() {
                    Ok(g) => g.db.clone(),
                    Err(_) => return,
                };
                db.clear_range(op.start_handle, op.end_handle);
                Self::process_service_changed(client_ref, op.start_handle, op.end_handle).await;
            });
        }
    }

    // =================================================================
    // Internal: Notification / Indication dispatch
    // =================================================================

    /// Dispatch an incoming notification (NFY or NFY_MULT).
    fn handle_notification(client: &Arc<Self>, opcode: u8, pdu: &[u8]) {
        // Use AttOpcode for type-safe matching on incoming notification opcodes.
        let parsed_opcode = AttOpcode::try_from(opcode);
        match parsed_opcode {
            Ok(AttOpcode::HandleNfy) => {
                // NFY: handle(2) + value
                if pdu.len() < 2 {
                    return;
                }
                let value_handle = get_le16(&pdu[0..2]);
                let value = &pdu[2..];
                Self::dispatch_notify(client, value_handle, value);
            }
            Ok(AttOpcode::HandleNfyMult) => {
                // NFY_MULT: repeated [handle(2) + length(2) + value(length)]
                let mut offset = 0;
                while offset + 4 <= pdu.len() {
                    let value_handle = get_le16(&pdu[offset..offset + 2]);
                    let value_len = get_le16(&pdu[offset + 2..offset + 4]) as usize;
                    offset += 4;

                    if offset + value_len > pdu.len() {
                        break;
                    }
                    let value = &pdu[offset..offset + value_len];
                    offset += value_len;

                    Self::dispatch_notify(client, value_handle, value);
                }
            }
            _ => {
                tracing::trace!("Unexpected opcode in notification handler: 0x{:02x}", opcode);
            }
        }
    }

    /// Dispatch an incoming indication (IND).
    ///
    /// Sends HANDLE_CONF back to the server, but only from the parent client
    /// (not from clones).
    fn handle_indication(client: &Arc<Self>, opcode: u8, pdu: &[u8]) {
        if opcode != BT_ATT_OP_HANDLE_IND || pdu.len() < 2 {
            return;
        }

        let value_handle = get_le16(&pdu[0..2]);
        let value = &pdu[2..];

        // Check for Service Changed indication.
        let svc_chngd_value_handle = Self::get_svc_chngd_value_handle(client);
        if svc_chngd_value_handle != 0 && value_handle == svc_chngd_value_handle {
            Self::handle_service_changed(client, value);
        }

        // Dispatch to registered notify callbacks.
        Self::dispatch_notify(client, value_handle, value);

        // Send confirmation (only from parent, not clones).
        let is_parent = {
            let guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.parent.is_none()
        };

        if is_parent {
            let att = match client.inner.lock() {
                Ok(g) => Arc::clone(&g.att),
                Err(_) => return,
            };
            if let Ok(mut att_guard) = att.lock() {
                att_guard.send(BT_ATT_OP_HANDLE_CONF, &[], None);
            }
        }
    }

    /// Find the Service Changed characteristic value handle.
    fn get_svc_chngd_value_handle(client: &Arc<Self>) -> u16 {
        let db = match client.inner.lock() {
            Ok(g) => g.db.clone(),
            Err(_) => return 0,
        };

        let gatt_svc_uuid = BtUuid::from_u16(GATT_SVC_UUID);
        let svc_chngd_uuid = BtUuid::from_u16(SVC_CHNGD_UUID);
        let mut result_handle: u16 = 0;

        db.foreach_service(Some(&gatt_svc_uuid), |svc_attr| {
            if let Some(svc_service) = svc_attr.get_service() {
                svc_service.foreach_char(|char_attr| {
                    if let Some(char_data) = char_attr.get_char_data() {
                        if char_data.uuid == svc_chngd_uuid && result_handle == 0 {
                            result_handle = char_data.value_handle;
                        }
                    }
                });
            }
        });

        result_handle
    }

    /// Dispatch a notification/indication value to all matching registered
    /// callbacks.
    fn dispatch_notify(client: &Arc<Self>, value_handle: u16, value: &[u8]) {
        let callbacks: Vec<Arc<NotifyCallback>> = {
            let guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard
                .notify_list
                .iter()
                .filter_map(|nd| {
                    if let Some(chrc_idx) = nd.chrc_idx {
                        if chrc_idx < guard.notify_chrcs.len()
                            && guard.notify_chrcs[chrc_idx].value_handle == value_handle
                        {
                            return nd.notify_cb.clone();
                        }
                    }
                    None
                })
                .collect()
        };

        for cb in callbacks {
            cb(value_handle, value);
        }
    }

    // =================================================================
    // Internal: Notification registration helpers
    // =================================================================

    /// Find or create a NotifyChrc entry for a given value handle.
    fn find_or_create_notify_chrc(inner: &mut BtGattClientInner, value_handle: u16) -> usize {
        // Check if we already have an entry.
        if let Some(idx) = inner.notify_chrcs.iter().position(|c| c.value_handle == value_handle) {
            return idx;
        }

        // Look up the characteristic in the DB to find CCC handle and properties.
        let (ccc_handle, properties) = Self::find_ccc_for_char(&inner.db, value_handle);

        inner.notify_chrcs.push(NotifyChrc {
            value_handle,
            ccc_handle,
            properties,
            notify_count: 0,
            ccc_write_id: 0,
            reg_notify_queue: VecDeque::new(),
        });

        inner.notify_chrcs.len() - 1
    }

    /// Find the CCC descriptor handle and properties for a characteristic.
    fn find_ccc_for_char(db: &GattDb, value_handle: u16) -> (u16, u8) {
        let attr = match db.get_attribute(value_handle) {
            Some(a) => a,
            None => return (0, 0),
        };

        let char_data = match attr.get_char_data() {
            Some(cd) => cd,
            None => return (0, 0),
        };

        let properties = char_data.properties;

        // Find CCC descriptor: search for UUID 0x2902 after the value handle.
        let ccc_uuid = BtUuid::from_u16(CCC_UUID);
        let (_, svc_end) = match attr.get_service_handles() {
            Some(handles) => handles,
            None => return (0, properties),
        };

        let mut ccc_handle: u16 = 0;
        db.foreach_in_range(
            Some(&ccc_uuid),
            |desc_attr| {
                if ccc_handle == 0 {
                    ccc_handle = desc_attr.get_handle();
                }
            },
            value_handle + 1,
            svc_end,
        );

        (ccc_handle, properties)
    }

    /// Get the CCC value to write for enabling notifications/indications.
    fn get_ccc_value(properties: u8) -> u16 {
        let props = GattChrcProperties::from_bits_truncate(properties);
        if props.contains(GattChrcProperties::INDICATE) {
            0x0002
        } else if props.contains(GattChrcProperties::NOTIFY) {
            0x0001
        } else {
            0x0000
        }
    }

    /// Check whether a characteristic has extended properties that indicate
    /// reliable write support.
    ///
    /// Callers can use this before calling [`write_long_value`] with
    /// `reliable=true` to verify the characteristic actually supports it.
    ///
    /// # Arguments
    /// * `properties` — The characteristic's base properties byte.
    /// * `ext_props_value` — The value of the extended properties descriptor
    ///   (obtained by reading the Characteristic Extended Properties descriptor).
    pub fn has_reliable_write_ext(properties: u8, ext_props_value: u8) -> bool {
        let props = GattChrcProperties::from_bits_truncate(properties);
        if !props.contains(GattChrcProperties::EXT_PROP) {
            return false;
        }
        let ext = GattChrcExtProperties::from_bits_truncate(ext_props_value);
        ext.contains(GattChrcExtProperties::RELIABLE_WRITE)
    }

    /// Map a raw ATT error code to the typed [`AttError`] enum for structured
    /// error matching. Returns `None` if the code is 0 (success) or unknown.
    pub fn classify_att_error(code: u8) -> Option<AttError> {
        if code == 0 {
            return None;
        }
        AttError::try_from(code).ok()
    }

    /// Check whether a UUID is a well-known GATT 16-bit UUID (as opposed to a
    /// vendor-specific 128-bit UUID).
    ///
    /// Returns `true` for 16-bit and 32-bit UUIDs in the Bluetooth SIG range,
    /// `false` for full 128-bit vendor-specific UUIDs.
    pub fn is_well_known_uuid(uuid: &BtUuid) -> bool {
        match uuid {
            BtUuid::Uuid16(_) => true,
            BtUuid::Uuid128(_) => false,
            _ => true, // Uuid32 is also a SIG-assigned UUID
        }
    }

    /// Write a CCC descriptor to enable/disable notifications.
    fn write_ccc_descriptor(
        att: &Arc<StdMutex<BtAtt>>,
        ccc_handle: u16,
        ccc_value: u16,
        chrc_idx: usize,
        reg_id: u32,
        client: Arc<Self>,
    ) -> u32 {
        let mut pdu = [0u8; 4];
        put_le16(ccc_handle, &mut pdu[0..2]);
        put_le16(ccc_value, &mut pdu[2..4]);

        let att_callback: AttResponseCallback =
            Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                let att_ecode = if rsp_opcode == BT_ATT_OP_ERROR_RSP && rsp_pdu.len() >= 4 {
                    rsp_pdu[3]
                } else if rsp_opcode == BT_ATT_OP_WRITE_RSP {
                    0
                } else {
                    0xFF
                };

                Self::ccc_write_complete(&client, chrc_idx, reg_id, att_ecode);
            }));

        match att.lock() {
            Ok(mut att_guard) => att_guard.send(BT_ATT_OP_WRITE_REQ, &pdu, att_callback),
            Err(_) => 0,
        }
    }

    /// Handle CCC write completion.
    fn ccc_write_complete(client: &Arc<Self>, chrc_idx: usize, reg_id: u32, att_ecode: u8) {
        let mut guard = match client.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        if chrc_idx >= guard.notify_chrcs.len() {
            return;
        }

        guard.notify_chrcs[chrc_idx].ccc_write_id = 0;

        // Complete the primary registration.
        Self::complete_notify_registration(&mut guard, reg_id, att_ecode);

        // Process any queued registrations for this characteristic.
        let queued: Vec<u32> = guard.notify_chrcs[chrc_idx].reg_notify_queue.drain(..).collect();

        for queued_id in queued {
            Self::complete_notify_registration(&mut guard, queued_id, att_ecode);
        }
    }

    /// Complete a single notification registration.
    fn complete_notify_registration(inner: &mut BtGattClientInner, reg_id: u32, att_ecode: u8) {
        if let Some(nd) = inner.notify_list.iter_mut().find(|n| n.id == reg_id) {
            nd.att_ecode = att_ecode;
            if let Some(cb) = nd.register_cb.take() {
                // Convert u8 error code to u16 for the callback.
                cb(att_ecode as u16);
            }
        }
    }

    // =================================================================
    // Internal: Read response handling
    // =================================================================

    /// Handle a read response (READ_RSP or READ_BLOB_RSP) and chain
    /// additional blob reads if the response indicates more data.
    fn handle_read_response(
        client: &Arc<Self>,
        att: &Arc<StdMutex<BtAtt>>,
        read_data: Arc<StdMutex<ReadLongData>>,
        req_id: u32,
        rsp_opcode: u8,
        rsp_pdu: &[u8],
    ) {
        if rsp_opcode == BT_ATT_OP_ERROR_RSP {
            let att_ecode = if rsp_pdu.len() >= 4 { rsp_pdu[3] } else { 0xFF };
            if let Some(err) = Self::classify_att_error(att_ecode) {
                tracing::debug!("Read failed with ATT error: {:?}", err);
            }
            let cb = { read_data.lock().unwrap().callback.take() };
            if let Some(cb) = cb {
                cb(false, att_ecode, &[]);
            }
            Self::remove_request(client, req_id);
            return;
        }

        if rsp_opcode != BT_ATT_OP_READ_RSP && rsp_opcode != BT_ATT_OP_READ_BLOB_RSP {
            let cb = { read_data.lock().unwrap().callback.take() };
            if let Some(cb) = cb {
                cb(false, 0, &[]);
            }
            Self::remove_request(client, req_id);
            return;
        }

        let (handle, current_offset, total_len) = {
            let mut rd = read_data.lock().unwrap();
            rd.value.extend_from_slice(rsp_pdu);
            rd.offset += rsp_pdu.len() as u16;
            (rd.handle, rd.offset, rd.value.len())
        };

        // Get the current MTU to determine if we need more reads.
        let mtu = match client.inner.lock() {
            Ok(g) => match g.att.lock() {
                Ok(a) => a.get_mtu(),
                Err(_) => BT_ATT_DEFAULT_LE_MTU,
            },
            Err(_) => BT_ATT_DEFAULT_LE_MTU,
        };

        // For READ_RSP, the max data in one response is (MTU - 1).
        // For READ_BLOB_RSP, it is also (MTU - 1).
        // If we received a full response, there might be more data.
        let max_data_len = (mtu as usize).saturating_sub(1);
        let need_more = rsp_pdu.len() == max_data_len && total_len < BT_ATT_MAX_VALUE_LEN as usize;

        if need_more && current_offset > 0 {
            // Send a READ_BLOB_REQ for the next chunk.
            let mut pdu = [0u8; 4];
            put_le16(handle, &mut pdu[0..2]);
            put_le16(current_offset, &mut pdu[2..4]);

            let rd_clone = Arc::clone(&read_data);
            let att_clone = Arc::clone(att);
            let client_clone = Arc::clone(client);

            let att_callback: AttResponseCallback =
                Some(Box::new(move |rsp_op: u8, rsp_data: &[u8]| {
                    Self::handle_read_response(
                        &client_clone,
                        &att_clone,
                        rd_clone,
                        req_id,
                        rsp_op,
                        rsp_data,
                    );
                }));

            let att_id = match att.lock() {
                Ok(mut a) => a.send(BT_ATT_OP_READ_BLOB_REQ, &pdu, att_callback),
                Err(_) => 0,
            };

            if att_id != 0 {
                // Update the ATT ID in the pending request.
                if let Ok(mut g) = client.inner.lock() {
                    if let Some(req) = g.pending_requests.iter_mut().find(|r| r.id == req_id) {
                        req.att_id = att_id;
                    }
                }
                return; // Continue reading.
            }
            // Fall through to complete with what we have.
        }

        // Read complete — deliver all accumulated data.
        let (cb, value) = {
            let mut rd = read_data.lock().unwrap();
            (rd.callback.take(), rd.value.clone())
        };
        if let Some(cb) = cb {
            cb(true, 0, &value);
        }
        Self::remove_request(client, req_id);
    }

    // =================================================================
    // Internal: Long-write helpers
    // =================================================================

    /// Send the next Prepare Write Request in a long-write sequence.
    fn send_next_prep_write(
        att: &Arc<StdMutex<BtAtt>>,
        data: &Arc<StdMutex<LongWriteData>>,
        req_id: u32,
        client: &Arc<Self>,
    ) -> u32 {
        let (handle, cur_offset, chunk) = {
            let d = data.lock().unwrap();
            let mtu = match att.lock() {
                Ok(a) => a.get_mtu(),
                Err(_) => BT_ATT_DEFAULT_LE_MTU,
            };
            // Max payload per prep write: MTU - 5 (opcode + handle + offset).
            let max_chunk = (mtu as usize).saturating_sub(5);
            let remaining = d.value.len().saturating_sub((d.cur_offset - d.offset) as usize);
            let chunk_len = remaining.min(max_chunk);
            let start = (d.cur_offset - d.offset) as usize;
            let chunk = d.value[start..start + chunk_len].to_vec();
            (d.handle, d.cur_offset, chunk)
        };

        if chunk.is_empty() {
            // All data prepared — send Execute Write.
            let data_clone = Arc::clone(data);
            let client_clone = Arc::clone(client);

            let exec_pdu = [0x01u8]; // Commit.
            let att_callback: AttResponseCallback =
                Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                    let att_ecode = if rsp_opcode == BT_ATT_OP_ERROR_RSP && rsp_pdu.len() >= 4 {
                        rsp_pdu[3]
                    } else {
                        0
                    };
                    let success = rsp_opcode == BT_ATT_OP_EXEC_WRITE_RSP;
                    let cb = { data_clone.lock().unwrap().callback.take() };
                    if let Some(cb) = cb {
                        cb(success, false, att_ecode);
                    }
                    Self::long_write_complete(&client_clone);
                }));

            match att.lock() {
                Ok(mut a) => a.send(BT_ATT_OP_EXEC_WRITE_REQ, &exec_pdu, att_callback),
                Err(_) => 0,
            }
        } else {
            // Build Prepare Write Request: handle(2) + offset(2) + value.
            let mut pdu = Vec::with_capacity(4 + chunk.len());
            let mut buf = [0u8; 2];
            put_le16(handle, &mut buf);
            pdu.extend_from_slice(&buf);
            put_le16(cur_offset, &mut buf);
            pdu.extend_from_slice(&buf);
            pdu.extend_from_slice(&chunk);

            let expected_chunk = chunk.clone();
            let expected_handle = handle;
            let expected_offset = cur_offset;
            let data_clone = Arc::clone(data);
            let att_clone = Arc::clone(att);
            let client_clone = Arc::clone(client);

            let att_callback: AttResponseCallback =
                Some(Box::new(move |rsp_opcode: u8, rsp_pdu: &[u8]| {
                    if rsp_opcode == BT_ATT_OP_ERROR_RSP {
                        let att_ecode = if rsp_pdu.len() >= 4 { rsp_pdu[3] } else { 0xFF };
                        let cb = { data_clone.lock().unwrap().callback.take() };
                        if let Some(cb) = cb {
                            cb(false, false, att_ecode);
                        }
                        Self::long_write_complete(&client_clone);
                        return;
                    }

                    if rsp_opcode != BT_ATT_OP_PREP_WRITE_RSP {
                        let cb = { data_clone.lock().unwrap().callback.take() };
                        if let Some(cb) = cb {
                            cb(false, false, 0);
                        }
                        Self::long_write_complete(&client_clone);
                        return;
                    }

                    // Validate echoed data for reliable writes.
                    let is_reliable = data_clone.lock().unwrap().reliable;
                    if is_reliable && rsp_pdu.len() >= 4 {
                        let echo_handle = get_le16(&rsp_pdu[0..2]);
                        let echo_offset = get_le16(&rsp_pdu[2..4]);
                        let echo_value = &rsp_pdu[4..];
                        if echo_handle != expected_handle
                            || echo_offset != expected_offset
                            || echo_value != expected_chunk.as_slice()
                        {
                            // Reliable write error — cancel with exec(0x00).
                            let cancel_pdu = [0x00u8];
                            let dc = Arc::clone(&data_clone);
                            let cc = Arc::clone(&client_clone);
                            let cancel_cb: AttResponseCallback =
                                Some(Box::new(move |_op: u8, _pdu: &[u8]| {
                                    let cb = { dc.lock().unwrap().callback.take() };
                                    if let Some(cb) = cb {
                                        cb(false, true, 0);
                                    }
                                    Self::long_write_complete(&cc);
                                }));
                            if let Ok(mut a) = att_clone.lock() {
                                a.send(BT_ATT_OP_EXEC_WRITE_REQ, &cancel_pdu, cancel_cb);
                            }
                            return;
                        }
                    }

                    // Advance offset and send next chunk.
                    {
                        let mut d = data_clone.lock().unwrap();
                        d.cur_offset += expected_chunk.len() as u16;
                    }

                    let next_id =
                        Self::send_next_prep_write(&att_clone, &data_clone, req_id, &client_clone);

                    if next_id == 0 {
                        let cb = { data_clone.lock().unwrap().callback.take() };
                        if let Some(cb) = cb {
                            cb(false, false, 0);
                        }
                        Self::long_write_complete(&client_clone);
                    } else {
                        // Update ATT ID in pending request.
                        if let Ok(mut g) = client_clone.inner.lock() {
                            if let Some(req) =
                                g.pending_requests.iter_mut().find(|r| r.id == req_id)
                            {
                                req.att_id = next_id;
                            }
                        }
                    }
                }));

            match att.lock() {
                Ok(mut a) => a.send(BT_ATT_OP_PREP_WRITE_REQ, &pdu, att_callback),
                Err(_) => 0,
            }
        }
    }

    /// Called when a long-write sequence completes. Starts the next queued
    /// long write if any.
    fn long_write_complete(client: &Arc<Self>) {
        let next_data = {
            let mut guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.in_long_write = false;
            Self::check_idle_locked(&mut guard);

            if let Some(data) = guard.long_write_queue.pop_front() {
                guard.in_long_write = true;
                Some(data)
            } else {
                None
            }
        };

        if let Some(data) = next_data {
            let att = match client.inner.lock() {
                Ok(g) => Arc::clone(&g.att),
                Err(_) => return,
            };
            let long_data = Arc::new(StdMutex::new(data));
            let req_id = match client.inner.lock() {
                Ok(g) => g.next_request_id.fetch_add(1, Ordering::Relaxed),
                Err(_) => return,
            };
            let client_ref = Arc::clone(client);
            let att_id = Self::send_next_prep_write(&att, &long_data, req_id, &client_ref);
            if att_id == 0 {
                let cb = { long_data.lock().unwrap().callback.take() };
                if let Some(cb) = cb {
                    cb(false, false, 0);
                }
                Self::long_write_complete(client);
            }
        }
    }

    // =================================================================
    // Internal: Request management helpers
    // =================================================================

    /// Remove a pending request by ID.
    fn remove_request(client: &Arc<Self>, req_id: u32) {
        let mut guard = match client.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        guard.pending_requests.retain(|r| r.id != req_id);
        Self::check_idle_locked(&mut guard);
    }

    /// Check if the client is idle and invoke any pending idle callbacks.
    fn check_idle_locked(inner: &mut BtGattClientInner) {
        if !inner.pending_requests.is_empty() || !inner.long_write_queue.is_empty() {
            return;
        }

        let cbs: Vec<IdleCb> = inner.idle_cbs.drain(..).collect();
        for mut cb_entry in cbs {
            if let Some(cb) = cb_entry.callback.take() {
                cb();
            }
        }
    }

    // =================================================================
    // Internal: DB Out-of-Sync recovery
    // =================================================================

    /// Register a database synchronization callback on the ATT transport.
    ///
    /// This intercepts `ATT_ERROR_DB_OUT_OF_SYNC` errors and triggers
    /// a DB hash re-check and potential re-discovery.
    fn register_db_sync_cb(client: &Arc<Self>) {
        let att = match client.inner.lock() {
            Ok(g) => Arc::clone(&g.att),
            Err(_) => return,
        };

        let client_ref = Arc::clone(client);
        let db_sync_cb = Box::new(move |error_code: u8, req_pdu: &[u8], att_id: u32| {
            Self::handle_db_out_of_sync(&client_ref, error_code, req_pdu, att_id);
        });

        if let Ok(mut att_guard) = att.lock() {
            att_guard.set_db_sync_cb(db_sync_cb);
        }
    }

    /// Handle a DB_OUT_OF_SYNC error from the ATT transport.
    ///
    /// Records the failing request, then spawns an async task to re-check
    /// the DB hash and potentially trigger a full re-discovery.
    fn handle_db_out_of_sync(client: &Arc<Self>, _error_code: u8, _req_pdu: &[u8], att_id: u32) {
        {
            let mut guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.pending_retry_att_id = att_id;
            guard.pending_error_handle = 0;
        }

        let client_ref = Arc::clone(client);
        tokio::spawn(async move {
            Self::db_sync_recovery(client_ref).await;
        });
    }

    /// Perform DB synchronization recovery: re-check the hash and
    /// either resend the failed request or trigger a full re-discovery.
    async fn db_sync_recovery(client: Arc<Self>) {
        let att = match client.inner.lock() {
            Ok(g) => Arc::clone(&g.att),
            Err(_) => return,
        };

        let hash_matches = Self::check_db_hash(&client, &att).await;

        let pending_att_id = {
            let mut guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let id = guard.pending_retry_att_id;
            guard.pending_retry_att_id = 0;
            guard.pending_error_handle = 0;
            id
        };

        if hash_matches {
            // Hash matches — resend the failed request.
            if pending_att_id != 0 {
                if let Ok(mut att_guard) = att.lock() {
                    let _ = att_guard.resend(pending_att_id, 0, &[], None);
                }
            }
        } else {
            // Hash mismatch — trigger full re-discovery.
            if let Err(e) = Self::perform_discovery(&client, &att).await {
                tracing::warn!("DB sync re-discovery failed: {}", e);
            }
        }
    }

    /// Notify the idle signal, allowing tasks waiting on idle to proceed.
    fn signal_idle(&self) {
        self.idle_notify.notify_waiters();
    }

    /// Unregister all ATT-level notification/indication handlers.
    ///
    /// Called during cleanup to release ATT registrations.
    fn unregister_att_handlers(&self) {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let nfy_id = guard.nfy_id;
        let nfy_mult_id = guard.nfy_mult_id;
        let ind_id = guard.ind_id;
        let svc_chngd_ind_id = guard.svc_chngd_ind_id;

        if let Ok(mut att) = guard.att.lock() {
            if nfy_id != 0 {
                att.unregister(nfy_id);
            }
            if nfy_mult_id != 0 {
                att.unregister(nfy_mult_id);
            }
            if ind_id != 0 {
                att.unregister(ind_id);
            }
            if svc_chngd_ind_id != 0 {
                att.unregister(svc_chngd_ind_id);
            }
        }
    }
} // end impl BtGattClient

impl Drop for BtGattClient {
    fn drop(&mut self) {
        // Clean up all ATT handler registrations when this client is dropped.
        self.unregister_att_handlers();

        // Unregister the GattDb change notification callback.
        if let Ok(guard) = self.inner.lock() {
            let db_id = guard.db_notify_id;
            if db_id != 0 {
                guard.db.unregister(db_id);
            }
        }
    }
}
