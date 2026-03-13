// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2022 Intel Corporation. All rights reserved.
//
//! Call Control Profile (CCP) / Generic Telephone Bearer Service (GTBS).
//!
//! Complete Rust rewrite of `src/shared/ccp.c` (1226 lines) and
//! `src/shared/ccp.h` (45 lines). This module implements the CCP scaffold
//! for telephone call control — bearer info access, call state notifications.
//!
//! # Architecture
//!
//! - [`BtCcp`] is the main CCP client instance, shared via `Arc`.
//! - [`CcpDb`] wraps a [`GattDb`] reference alongside a [`BtCcs`] service
//!   record for GTBS registration.
//! - [`CcpEventCallback`] is a trait replacing the C
//!   `struct bt_ccp_event_callback` for receiving call state notifications.
//! - Reference counting (`bt_ccp_ref`/`bt_ccp_unref`) is replaced by `Arc`.
//! - Callback + `void *user_data` patterns are replaced by trait objects
//!   and closures.
//! - GLib containers (`struct queue`) are replaced by `Vec` and
//!   [`Queue`](crate::util::queue::Queue).

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::debug;

use crate::att::transport::BtAtt;
use crate::att::types::{AttPermissions, BT_ATT_ERROR_INSUFFICIENT_RESOURCES, GattChrcProperties};
use crate::gatt::client::{BtGattClient, NotifyCallback, ReadCallback, RegisterCallback};
use crate::gatt::db::{GattDb, GattDbAttribute};
use crate::util::queue::Queue;
use crate::util::uuid::BtUuid;

// =====================================================================
// GTBS / TBS Assigned UUID16 Values
// =====================================================================

/// Generic Telephone Bearer Service UUID (0x184C).
const GTBS_UUID: u16 = 0x184C;

/// Bearer Provider Name characteristic UUID (0x2BB3).
const BEARER_PROVIDER_NAME_CHRC_UUID: u16 = 0x2BB3;

/// Bearer UCI characteristic UUID (0x2BB4).
const BEARER_UCI_CHRC_UUID: u16 = 0x2BB4;

/// Bearer Technology characteristic UUID (0x2BB5).
const BEARER_TECH_CHRC_UUID: u16 = 0x2BB5;

/// Bearer URI Schemes Supported List characteristic UUID (0x2BB6).
const BEARER_URI_SCHEME_CHRC_UUID: u16 = 0x2BB6;

/// Bearer Signal Strength characteristic UUID (0x2BB7).
const BEARER_SIGNAL_STR_CHRC_UUID: u16 = 0x2BB7;

/// Bearer Signal Strength Reporting Interval characteristic UUID (0x2BB8).
const BEARER_SIGNAL_INTRVL_CHRC_UUID: u16 = 0x2BB8;

/// Bearer List Current Calls characteristic UUID (0x2BB9).
const CURR_CALL_LIST_CHRC_UUID: u16 = 0x2BB9;

/// Content Control ID characteristic UUID (0x2BBA).
const BEARER_CCID_CHRC_UUID: u16 = 0x2BBA;

/// Status Flags characteristic UUID (0x2BBB).
const CALL_STATUS_FLAG_CHRC_UUID: u16 = 0x2BBB;

/// Incoming Call Target Bearer URI characteristic UUID (0x2BBC).
const INCOM_CALL_TARGET_URI_CHRC_UUID: u16 = 0x2BBC;

/// Call State characteristic UUID (0x2BBD).
const CALL_STATE_CHRC_UUID: u16 = 0x2BBD;

/// Call Control Point characteristic UUID (0x2BBE).
const CALL_CTRL_POINT_CHRC_UUID: u16 = 0x2BBE;

/// Call Control Point Optional Opcodes characteristic UUID (0x2BBF).
const CALL_CTRL_POINT_OPT_OPCODE_CHRC_UUID: u16 = 0x2BBF;

/// Termination Reason characteristic UUID (0x2BC0).
const TERMINATION_REASON_CHRC_UUID: u16 = 0x2BC0;

/// Incoming Call characteristic UUID (0x2BC1).
const INCOMING_CALL_CHRC_UUID: u16 = 0x2BC1;

/// Call Friendly Name characteristic UUID (0x2BC2).
const CALL_FRIENDLY_NAME_CHRC_UUID: u16 = 0x2BC2;

// =====================================================================
// Module-level CCP database registry
// =====================================================================

/// Global registry of CCP database instances.
///
/// Replaces the static `struct queue *ccp_db` in ccp.c.
static CCP_DB_REGISTRY: Mutex<Option<Queue<CcpDb>>> = Mutex::new(None);

/// Ensure the global CCP DB registry is initialized.
fn ensure_ccp_db_registry<F, R>(f: F) -> R
where
    F: FnOnce(&mut Queue<CcpDb>) -> R,
{
    let mut guard = CCP_DB_REGISTRY.lock().unwrap();
    let queue = guard.get_or_insert_with(Queue::new);
    f(queue)
}

// =====================================================================
// CcpEventCallback — trait replacing bt_ccp_event_callback
// =====================================================================

/// Event callback trait for CCP notifications.
///
/// Replaces the C `struct bt_ccp_event_callback` with its `call_state`
/// function pointer.
pub trait CcpEventCallback: Send + Sync {
    /// Called when a call state change notification is received.
    ///
    /// # Arguments
    /// * `ccp` — The CCP instance that received the notification.
    /// * `value` — Raw call state data bytes from the GATT notification.
    fn call_state(&self, ccp: &BtCcp, value: &[u8]);
}

// =====================================================================
// CcpSessionInfo — session info placeholder
// =====================================================================

/// CCP session information placeholder.
///
/// Replaces `struct bt_ccp_session_info` from ccp.h.
/// This is a scaffold structure for future session tracking.
#[derive(Default)]
pub struct CcpSessionInfo {
    _private: (),
}

impl CcpSessionInfo {
    /// Create a new session info instance.
    pub fn new() -> Self {
        Self::default()
    }
}

// =====================================================================
// BtCcs — internal GATT service record for GTBS
// =====================================================================

/// Internal representation of the GTBS service attributes.
///
/// Replaces `struct bt_ccs` from ccp.c (lines 83-112).
/// Stores handles to all GTBS characteristic and CCC descriptor attributes.
pub struct BtCcs {
    /// Parent CcpDb reference (back-pointer for server-side context).
    _mdb_present: bool,
    /// GTBS service declaration attribute.
    service: Option<GattDbAttribute>,
    /// Bearer Provider Name characteristic.
    bearer_name: Option<GattDbAttribute>,
    /// Bearer Provider Name CCC descriptor.
    bearer_name_ccc: Option<GattDbAttribute>,
    /// Bearer UCI characteristic.
    bearer_uci: Option<GattDbAttribute>,
    /// Bearer Technology characteristic.
    bearer_technology: Option<GattDbAttribute>,
    /// Bearer Technology CCC descriptor.
    bearer_technology_ccc: Option<GattDbAttribute>,
    /// Bearer URI Schemes Supported List characteristic.
    bearer_uri_schemes_list: Option<GattDbAttribute>,
    /// Bearer Signal Strength characteristic.
    signal_strength: Option<GattDbAttribute>,
    /// Bearer Signal Strength CCC descriptor.
    signal_strength_ccc: Option<GattDbAttribute>,
    /// Bearer Signal Strength Reporting Interval characteristic.
    signal_reporting_intrvl: Option<GattDbAttribute>,
    /// Bearer List Current Calls characteristic.
    current_call_list: Option<GattDbAttribute>,
    /// Current Call List CCC descriptor.
    current_call_list_ccc: Option<GattDbAttribute>,
    /// Content Control ID characteristic.
    ccid: Option<GattDbAttribute>,
    /// Status Flags characteristic.
    status_flag: Option<GattDbAttribute>,
    /// Status Flags CCC descriptor.
    status_flag_ccc: Option<GattDbAttribute>,
    /// Incoming Call Target Bearer URI characteristic.
    target_bearer_uri: Option<GattDbAttribute>,
    /// Call State characteristic.
    call_state: Option<GattDbAttribute>,
    /// Call State CCC descriptor.
    call_state_ccc: Option<GattDbAttribute>,
    /// Call Control Point characteristic.
    call_ctrl_point: Option<GattDbAttribute>,
    /// Call Control Point CCC descriptor (stored for completeness; used by
    /// future CCC write logic when the full CCP server is wired up).
    _call_ctrl_point_ccc: Option<GattDbAttribute>,
    /// Call Control Point Optional Opcodes characteristic.
    call_ctrl_opt_opcode: Option<GattDbAttribute>,
    /// Termination Reason characteristic.
    termination_reason: Option<GattDbAttribute>,
    /// Termination Reason CCC descriptor (stored for completeness; used by
    /// future CCC write logic when the full CCP server is wired up).
    _termination_reason_ccc: Option<GattDbAttribute>,
    /// Incoming Call characteristic.
    incoming_call: Option<GattDbAttribute>,
    /// Incoming Call CCC descriptor.
    incoming_call_ccc: Option<GattDbAttribute>,
    /// Call Friendly Name characteristic.
    friendly_name: Option<GattDbAttribute>,
    /// Call Friendly Name CCC descriptor.
    friendly_name_ccc: Option<GattDbAttribute>,
}

impl BtCcs {
    /// Create a new empty CCS record with all attributes set to `None`.
    fn new() -> Self {
        Self {
            _mdb_present: false,
            service: None,
            bearer_name: None,
            bearer_name_ccc: None,
            bearer_uci: None,
            bearer_technology: None,
            bearer_technology_ccc: None,
            bearer_uri_schemes_list: None,
            signal_strength: None,
            signal_strength_ccc: None,
            signal_reporting_intrvl: None,
            current_call_list: None,
            current_call_list_ccc: None,
            ccid: None,
            status_flag: None,
            status_flag_ccc: None,
            target_bearer_uri: None,
            call_state: None,
            call_state_ccc: None,
            call_ctrl_point: None,
            _call_ctrl_point_ccc: None,
            call_ctrl_opt_opcode: None,
            termination_reason: None,
            _termination_reason_ccc: None,
            incoming_call: None,
            incoming_call_ccc: None,
            friendly_name: None,
            friendly_name_ccc: None,
        }
    }
}

// =====================================================================
// CcpDb — GATT database wrapper for CCP
// =====================================================================

/// CCP database wrapper binding a [`GattDb`] to a GTBS service record.
///
/// Replaces `struct bt_ccp_db` from ccp.c (lines 34-37).
pub struct CcpDb {
    /// The underlying GATT database reference.
    pub db: GattDb,
    /// The GTBS service record, if registered.
    pub ccs: Option<BtCcs>,
}

impl CcpDb {
    /// Create a new CcpDb wrapping the given GATT database.
    fn new(db: GattDb) -> Self {
        Self { db, ccs: None }
    }

    /// Check if this CcpDb wraps the same GATT database.
    fn matches_db(&self, other: &GattDb) -> bool {
        self.db.ptr_eq(other)
    }
}

// =====================================================================
// BtCcpPending — pending GATT operation tracker
// =====================================================================

/// Tracks a pending GATT read operation for CCP.
///
/// Replaces `struct bt_ccp_pending` from ccp.c (lines 39-44).
struct BtCcpPending {
    /// GATT client operation ID (tracked for cancellation support).
    _id: u32,
}

// =====================================================================
// BtCcp — main CCP client instance
// =====================================================================

/// Inner mutable state of the CCP client.
struct BtCcpInner {
    /// GATT client handle for remote operations.
    client: Option<Arc<BtGattClient>>,
    /// Local GATT database wrapper (retained for lifetime management; the
    /// local DB owns the GTBS service registration).
    _ldb: Arc<Mutex<CcpDb>>,
    /// Remote GATT database wrapper.
    rdb: Option<Arc<Mutex<CcpDb>>>,

    // Notification registration IDs for each characteristic.
    bearer_name_id: u32,
    bearer_uci_id: u32,
    bearer_technology_id: u32,
    bearer_uri_schemes_list_id: u32,
    signal_strength_id: u32,
    signal_reporting_intrvl_id: u32,
    current_call_list_id: u32,
    ccid_id: u32,
    status_flag_id: u32,
    target_bearer_uri_id: u32,
    call_state_id: u32,
    call_control_pt_id: u32,
    call_control_opt_opcode_id: u32,
    termination_reason_id: u32,
    incoming_call_id: u32,
    friendly_name_id: u32,

    /// Event callback trait object.
    event_cbs: Option<Arc<dyn CcpEventCallback>>,
    /// Pending GATT operations.
    pending: Vec<BtCcpPending>,

    /// Debug logging function.
    debug_func: Option<Box<dyn Fn(&str) + Send + Sync>>,
    /// User data (type-erased).
    user_data: Option<Arc<dyn Any + Send + Sync>>,
}

/// CCP (Call Control Profile) client instance.
///
/// Replaces the opaque `struct bt_ccp` from ccp.h/ccp.c.
/// Shared via `Arc` (replacing `bt_ccp_ref`/`bt_ccp_unref`).
///
/// # Lifecycle
///
/// 1. Create with [`BtCcp::new`], passing local and optional remote GATT databases.
/// 2. Configure with [`set_event_callbacks`](BtCcp::set_event_callbacks),
///    [`set_debug`](BtCcp::set_debug), [`set_user_data`](BtCcp::set_user_data).
/// 3. Attach a GATT client with [`attach`](BtCcp::attach) to discover GTBS
///    services and subscribe to notifications.
/// 4. Detach with [`detach`](BtCcp::detach) when done.
pub struct BtCcp {
    inner: Mutex<BtCcpInner>,
}

impl BtCcp {
    // -----------------------------------------------------------------
    // Debug helper
    // -----------------------------------------------------------------

    /// Log a debug message through the configured debug callback and tracing.
    fn ccp_debug(inner: &BtCcpInner, msg: &str) {
        if let Some(ref func) = inner.debug_func {
            func(msg);
        }
        debug!("{}", msg);
    }

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Create a new CCP client instance.
    ///
    /// Replaces `bt_ccp_new()` (ccp.c lines 1164-1192).
    ///
    /// # Arguments
    /// * `ldb` — Local GATT database.
    /// * `rdb` — Optional remote GATT database.
    ///
    /// # Returns
    /// An `Arc<BtCcp>` on success, or `None` if `ldb` is invalid.
    pub fn new(ldb: GattDb, rdb: Option<GattDb>) -> Option<Arc<Self>> {
        // Get or create the CcpDb wrapper for the local database.
        let mdb = ccp_get_db(&ldb)?;

        // Create the remote database wrapper if provided.
        let rdb_wrapped = rdb.map(|db| {
            let ccp_db = CcpDb::new(db);
            Arc::new(Mutex::new(ccp_db))
        });

        let inner = BtCcpInner {
            client: None,
            _ldb: mdb,
            rdb: rdb_wrapped,
            bearer_name_id: 0,
            bearer_uci_id: 0,
            bearer_technology_id: 0,
            bearer_uri_schemes_list_id: 0,
            signal_strength_id: 0,
            signal_reporting_intrvl_id: 0,
            current_call_list_id: 0,
            ccid_id: 0,
            status_flag_id: 0,
            target_bearer_uri_id: 0,
            call_state_id: 0,
            call_control_pt_id: 0,
            call_control_opt_opcode_id: 0,
            termination_reason_id: 0,
            incoming_call_id: 0,
            friendly_name_id: 0,
            event_cbs: None,
            pending: Vec::new(),
            debug_func: None,
            user_data: None,
        };

        let ccp = Arc::new(BtCcp { inner: Mutex::new(inner) });

        Some(ccp)
    }

    // -----------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------

    /// Set event callbacks for CCP notifications.
    ///
    /// Replaces `bt_ccp_set_event_callbacks()` (ccp.c lines 1107-1121).
    pub fn set_event_callbacks(&self, cbs: Arc<dyn CcpEventCallback>) {
        let mut inner = self.inner.lock().unwrap();
        inner.event_cbs = Some(cbs);
    }

    /// Set the debug logging function.
    ///
    /// Replaces `bt_ccp_set_debug()` (ccp.c lines 201-216).
    ///
    /// # Returns
    /// `true` on success.
    pub fn set_debug(&self, func: impl Fn(&str) + Send + Sync + 'static) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.debug_func = Some(Box::new(func));
        true
    }

    /// Set opaque user data.
    ///
    /// Replaces `bt_ccp_set_user_data()` (ccp.c lines 183-191).
    pub fn set_user_data(&self, data: Arc<dyn Any + Send + Sync>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.user_data = Some(data);
        true
    }

    /// Get the previously set user data.
    ///
    /// Replaces `bt_ccp_get_user_data()` (ccp.c lines 193-199).
    pub fn get_user_data(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        let inner = self.inner.lock().unwrap();
        inner.user_data.clone()
    }

    // -----------------------------------------------------------------
    // Attach / Detach
    // -----------------------------------------------------------------

    /// Attach a GATT client and begin TBS/GTBS discovery.
    ///
    /// Replaces `bt_ccp_attach()` (ccp.c lines 1199-1218).
    ///
    /// If the remote database already has CCS characteristic handles
    /// cached, attaches directly to the call state characteristic.
    /// Otherwise, discovers the GTBS service by UUID and iterates its
    /// characteristics.
    ///
    /// # Returns
    /// `true` on success.
    pub fn attach(self: &Arc<Self>, client: Arc<BtGattClient>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        Self::ccp_debug(&inner, &format!("ccp attach {:p}", Arc::as_ptr(self)));

        // Clone the GATT client (replaces bt_gatt_client_clone).
        let cloned = match BtGattClient::clone_client(&client) {
            Ok(c) => c,
            Err(_) => return false,
        };
        inner.client = Some(cloned);

        // Check if we have a remote database with existing CCS data.
        let has_ccs = if let Some(ref rdb) = inner.rdb {
            let rdb_guard = rdb.lock().unwrap();
            rdb_guard.ccs.as_ref().and_then(|ccs| ccs.call_state.as_ref()).is_some()
        } else {
            false
        };

        if has_ccs {
            // CCS already discovered — attach call state directly.
            drop(inner);
            self.call_state_attach();
            return true;
        }

        // Discover GTBS service from the remote database.
        let rdb_db = {
            let rdb = match inner.rdb {
                Some(ref rdb) => rdb,
                None => return true,
            };
            let rdb_guard = rdb.lock().unwrap();
            rdb_guard.db.clone()
        };

        let gtbs_uuid = BtUuid::from_u16(GTBS_UUID);
        let self_ref = Arc::clone(self);

        drop(inner);

        rdb_db.foreach_service(Some(&gtbs_uuid), move |attr| {
            Self::foreach_ccs_service(&self_ref, attr);
        });

        true
    }

    /// Detach the GATT client.
    ///
    /// Replaces `bt_ccp_detach()` (ccp.c lines 1220-1226).
    pub fn detach(&self) {
        let mut inner = self.inner.lock().unwrap();
        Self::ccp_debug(&inner, "ccp detach");
        inner.client = None;
    }

    // -----------------------------------------------------------------
    // Service discovery (client-side)
    // -----------------------------------------------------------------

    /// Handle GTBS service discovery: set the service attribute and
    /// iterate its characteristics.
    ///
    /// Replaces `foreach_ccs_service()` (ccp.c lines 1123-1132).
    fn foreach_ccs_service(ccp: &Arc<BtCcp>, attr: GattDbAttribute) {
        // Get or create the CCS record in the remote database.
        {
            let inner = ccp.inner.lock().unwrap();
            if let Some(ref rdb) = inner.rdb {
                let mut rdb_guard = rdb.lock().unwrap();
                let ccs = rdb_guard.ccs.get_or_insert_with(BtCcs::new);
                ccs.service = Some(attr.clone());
                ccs._mdb_present = true;
            }
        }

        // Get the service handle and iterate its characteristics.
        if let Some(svc) = attr.get_service() {
            let ccp_ref = Arc::clone(ccp);
            svc.foreach_char(move |char_attr| {
                Self::foreach_ccs_char(&ccp_ref, char_attr);
            });
        }
    }

    /// Handle individual characteristic discovery within GTBS.
    ///
    /// Replaces `foreach_ccs_char()` (ccp.c lines 986-1105).
    /// Matches characteristic UUIDs and initiates read + notification
    /// registration for each recognized characteristic.
    fn foreach_ccs_char(ccp: &Arc<BtCcp>, attr: GattDbAttribute) {
        let char_data = match attr.get_char_data() {
            Some(cd) => cd,
            None => return,
        };

        let value_handle = char_data.value_handle;
        let uuid = char_data.uuid;

        // Get the CCS record, bail if already discovered (call_state is set).
        {
            let inner = ccp.inner.lock().unwrap();
            if let Some(ref rdb) = inner.rdb {
                let rdb_guard = rdb.lock().unwrap();
                if let Some(ref ccs) = rdb_guard.ccs {
                    if ccs.call_state.is_some() {
                        return;
                    }
                }
            }
        }

        // Match the characteristic UUID against known CCP UUIDs.
        if let BtUuid::Uuid16(uuid16) = uuid {
            match uuid16 {
                x if x == BEARER_PROVIDER_NAME_CHRC_UUID => {
                    debug!("Found Bearer Name, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.bearer_name, attr);
                    ccp.name_attach();
                }
                x if x == BEARER_UCI_CHRC_UUID => {
                    debug!("Found Bearer UCI, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.bearer_uci, attr);
                    ccp.uci_attach();
                }
                x if x == BEARER_TECH_CHRC_UUID => {
                    debug!("Found Bearer Technology, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.bearer_technology, attr);
                    ccp.technology_attach();
                }
                x if x == BEARER_SIGNAL_STR_CHRC_UUID => {
                    debug!("Found Signal Strength, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.signal_strength, attr);
                    ccp.strength_attach();
                }
                x if x == BEARER_SIGNAL_INTRVL_CHRC_UUID => {
                    debug!("Found Signal Interval, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.signal_reporting_intrvl, attr);
                    ccp.signal_intrvl_attach();
                }
                x if x == CALL_STATUS_FLAG_CHRC_UUID => {
                    debug!("Found Status Flag, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.status_flag, attr);
                    ccp.status_attach();
                }
                x if x == BEARER_URI_SCHEME_CHRC_UUID => {
                    debug!("Found URI Scheme, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.bearer_uri_schemes_list, attr);
                    ccp.uri_list_attach();
                }
                x if x == CURR_CALL_LIST_CHRC_UUID => {
                    debug!("Found Call List, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.current_call_list, attr);
                    ccp.call_list_attach();
                }
                x if x == BEARER_CCID_CHRC_UUID => {
                    debug!("Found CCID, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.ccid, attr);
                    ccp.ccid_attach();
                }
                x if x == INCOM_CALL_TARGET_URI_CHRC_UUID => {
                    debug!("Found Bearer URI, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.target_bearer_uri, attr);
                    ccp.tar_uri_attach();
                }
                x if x == CALL_STATE_CHRC_UUID => {
                    debug!("Found Call State, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.call_state, attr);
                    // Note: In the C code, CALL_STATE_CHRC_UUID is used for the
                    // call_ctrl_point registration during ccs_new, but during
                    // foreach_ccs_char it corresponds to the call state.
                    // However, the C code's foreach_ccs_char doesn't have an
                    // explicit entry for CALL_STATE_CHRC_UUID - it uses it for
                    // the call_ctrl_point field. Let's follow the exact C mapping.
                }
                x if x == CALL_CTRL_POINT_CHRC_UUID => {
                    debug!("Found Control Point, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.call_ctrl_point, attr);
                    ccp.ctrl_point_attach();
                }
                x if x == CALL_CTRL_POINT_OPT_OPCODE_CHRC_UUID => {
                    debug!("Found Control opcode, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.call_ctrl_opt_opcode, attr);
                    ccp.ctrl_opcode_attach();
                }
                x if x == TERMINATION_REASON_CHRC_UUID => {
                    debug!("Found Termination Reason, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.termination_reason, attr);
                    ccp.term_reason_attach();
                }
                x if x == INCOMING_CALL_CHRC_UUID => {
                    debug!("Found Incoming Call, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.incoming_call, attr);
                    ccp.incom_call_attach();
                }
                x if x == CALL_FRIENDLY_NAME_CHRC_UUID => {
                    debug!("Found Friendly Name, handle 0x{:04x}", value_handle);
                    Self::set_ccs_char(ccp, |ccs| &mut ccs.friendly_name, attr);
                    ccp.friendly_name_attach();
                }
                _ => {
                    debug!("Unknown CCP characteristic UUID 0x{:04x}", uuid16);
                }
            }
        }
    }

    /// Helper to set a CCS characteristic attribute in the remote database.
    fn set_ccs_char<F>(ccp: &Arc<BtCcp>, accessor: F, attr: GattDbAttribute)
    where
        F: FnOnce(&mut BtCcs) -> &mut Option<GattDbAttribute>,
    {
        let inner = ccp.inner.lock().unwrap();
        if let Some(ref rdb) = inner.rdb {
            let mut rdb_guard = rdb.lock().unwrap();
            let ccs = rdb_guard.ccs.get_or_insert_with(BtCcs::new);
            let field = accessor(ccs);
            *field = Some(attr);
        }
    }

    // -----------------------------------------------------------------
    // Characteristic attach helpers (read + register notify)
    // -----------------------------------------------------------------

    /// Read a characteristic value and track the pending operation.
    ///
    /// Replaces `ccp_read_value()` (ccp.c lines 465-486).
    fn ccp_read_value(&self, value_handle: u16) {
        let inner = self.inner.lock().unwrap();
        let client = match inner.client {
            Some(ref c) => Arc::clone(c),
            None => return,
        };
        drop(inner);

        let callback: ReadCallback = Box::new(move |success, att_ecode, value| {
            if !success {
                debug!("CCP: Unable to read call state: error 0x{:02x}", att_ecode);
                return;
            }
            debug!("CCP: Read complete, handle 0x{:04x}, {} bytes", value_handle, value.len());
        });

        let id = client.read_value(value_handle, callback);
        if id == 0 {
            let inner = self.inner.lock().unwrap();
            Self::ccp_debug(&inner, "Unable to send Read request");
            return;
        }

        let mut inner = self.inner.lock().unwrap();
        inner.pending.push(BtCcpPending { _id: id });
    }

    /// Generic notification register callback (non-mandatory characteristics).
    ///
    /// Replaces `ccp_cb_register()` (ccp.c lines 502-510).
    fn make_generic_register_cb(label: &'static str) -> RegisterCallback {
        Box::new(move |att_ecode| {
            if att_ecode != 0 {
                debug!("CCP {} notification registration failed: 0x{:04x}", label, att_ecode);
            }
        })
    }

    /// Generic notification callback (non-mandatory characteristics).
    ///
    /// Replaces `ccp_cb_notify()` (ccp.c lines 512-516).
    fn make_generic_notify_cb(label: &'static str) -> NotifyCallback {
        Box::new(move |_value_handle, _value| {
            debug!("CCP {} notification received", label);
        })
    }

    /// Helper to get the value handle from a CCS characteristic, reading
    /// from the remote database.
    fn get_ccs_value_handle<F>(&self, accessor: F) -> Option<u16>
    where
        F: FnOnce(&BtCcs) -> &Option<GattDbAttribute>,
    {
        let inner = self.inner.lock().unwrap();
        let rdb = inner.rdb.as_ref()?;
        let rdb_guard = rdb.lock().unwrap();
        let ccs = rdb_guard.ccs.as_ref()?;
        let attr = accessor(ccs).as_ref()?;
        let char_data = attr.get_char_data()?;
        Some(char_data.value_handle)
    }

    /// Attach to Bearer Provider Name characteristic.
    ///
    /// Replaces `bt_ccp_name_attach()` (ccp.c lines 720-740).
    fn name_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.bearer_name) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("bearer_name"),
                Self::make_generic_notify_cb("bearer_name"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.bearer_name_id = id;
        }
    }

    /// Attach to Bearer UCI characteristic.
    ///
    /// Replaces `bt_ccp_uci_attach()` (ccp.c lines 785-804).
    fn uci_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.bearer_uci) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("bearer_uci"),
                Self::make_generic_notify_cb("bearer_uci"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.bearer_uci_id = id;
        }
    }

    /// Attach to Bearer Technology characteristic.
    ///
    /// Replaces `bt_ccp_technology_attach()` (ccp.c lines 806-824).
    fn technology_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.bearer_technology) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("bearer_technology"),
                Self::make_generic_notify_cb("bearer_technology"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.bearer_technology_id = id;
        }
    }

    /// Attach to Signal Strength characteristic.
    ///
    /// Replaces `bt_ccp_strength_attach()` (ccp.c lines 826-844).
    fn strength_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.signal_strength) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("signal_strength"),
                Self::make_generic_notify_cb("signal_strength"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.signal_strength_id = id;
        }
    }

    /// Attach to Signal Strength Reporting Interval characteristic.
    ///
    /// Replaces `bt_ccp_signal_intrvl_attach()` (ccp.c lines 946-964).
    fn signal_intrvl_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.signal_reporting_intrvl) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("signal_reporting_interval"),
                Self::make_generic_notify_cb("signal_reporting_interval"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.signal_reporting_intrvl_id = id;
        }
    }

    /// Attach to Status Flags characteristic.
    ///
    /// Replaces `bt_ccp_status_attach()` (ccp.c lines 763-783).
    fn status_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.status_flag) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("status_flag"),
                Self::make_generic_notify_cb("status_flag"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.status_flag_id = id;
        }
    }

    /// Attach to URI Schemes List characteristic.
    ///
    /// Replaces `bt_ccp_uri_list_attach()` (ccp.c lines 966-984).
    fn uri_list_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.bearer_uri_schemes_list) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("bearer_uri_schemes"),
                Self::make_generic_notify_cb("bearer_uri_schemes"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.bearer_uri_schemes_list_id = id;
        }
    }

    /// Attach to Current Call List characteristic.
    ///
    /// Replaces `bt_ccp_call_list_attach()` (ccp.c lines 698-718).
    fn call_list_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.current_call_list) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("current_call_list"),
                Self::make_generic_notify_cb("current_call_list"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.current_call_list_id = id;
        }
    }

    /// Attach to CCID characteristic.
    ///
    /// Replaces `bt_ccp_ccid_attach()` (ccp.c lines 846-863).
    fn ccid_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.ccid) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("ccid"),
                Self::make_generic_notify_cb("ccid"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.ccid_id = id;
        }
    }

    /// Attach to Target Bearer URI characteristic.
    ///
    /// Replaces `bt_ccp_tar_uri_attach()` (ccp.c lines 865-884).
    fn tar_uri_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.target_bearer_uri) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("target_bearer_uri"),
                Self::make_generic_notify_cb("target_bearer_uri"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.target_bearer_uri_id = id;
        }
    }

    /// Attach to Call State characteristic.
    ///
    /// Replaces `bt_ccp_call_state_attach()` (ccp.c lines 676-696).
    fn call_state_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.call_state) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("call_state"),
                Self::make_generic_notify_cb("call_state"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.call_state_id = id;
        }
    }

    /// Attach to Call Control Point characteristic.
    ///
    /// Replaces `bt_ccp_ctrl_point_attach()` (ccp.c lines 886-904).
    fn ctrl_point_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.call_ctrl_point) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("call_control_point"),
                Self::make_generic_notify_cb("call_control_point"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.call_control_pt_id = id;
        }
    }

    /// Attach to Call Control Point Optional Opcodes characteristic.
    ///
    /// Replaces `bt_ccp_ctrl_opcode_attach()` (ccp.c lines 906-924).
    fn ctrl_opcode_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.call_ctrl_opt_opcode) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("call_control_opt_opcode"),
                Self::make_generic_notify_cb("call_control_opt_opcode"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.call_control_opt_opcode_id = id;
        }
    }

    /// Attach to Termination Reason characteristic.
    ///
    /// Replaces `bt_ccp_term_reason_attach()` (ccp.c lines 742-761).
    fn term_reason_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.termination_reason) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("termination_reason"),
                Self::make_generic_notify_cb("termination_reason"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.termination_reason_id = id;
        }
    }

    /// Attach to Incoming Call characteristic.
    ///
    /// Replaces `bt_ccp_incom_call_attach()` (ccp.c lines 654-674).
    fn incom_call_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.incoming_call) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("incoming_call"),
                Self::make_generic_notify_cb("incoming_call"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.incoming_call_id = id;
        }
    }

    /// Attach to Call Friendly Name characteristic.
    ///
    /// Replaces `bt_ccp_friendly_name_attach()` (ccp.c lines 926-944).
    fn friendly_name_attach(&self) {
        let value_handle = match self.get_ccs_value_handle(|ccs| &ccs.friendly_name) {
            Some(h) => h,
            None => return,
        };

        self.ccp_read_value(value_handle);

        let inner = self.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            let id = client.register_notify(
                value_handle,
                Self::make_generic_register_cb("friendly_name"),
                Self::make_generic_notify_cb("friendly_name"),
            );
            drop(inner);
            let mut inner = self.inner.lock().unwrap();
            inner.friendly_name_id = id;
        }
    }
}

// =====================================================================
// GTBS Service Registration (Server-side)
// =====================================================================

/// Create a new GTBS service in the given GATT database.
///
/// Replaces `ccs_new()` (ccp.c lines 242-430).
/// Registers the GTBS primary service with all 15 CCP characteristics
/// and their CCC descriptors.
fn ccs_new(db: &GattDb) -> Option<BtCcs> {
    let mut ccs = BtCcs::new();

    // Register GTBS primary service with 42 handles (matching C).
    let gtbs_uuid = BtUuid::from_u16(GTBS_UUID);
    let service = db.add_service(&gtbs_uuid, true, 42)?;

    // --- Bearer Provider Name (Read + Notify) ---
    let uuid = BtUuid::from_u16(BEARER_PROVIDER_NAME_CHRC_UUID);
    ccs.bearer_name = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );
    ccs.bearer_name_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // --- Bearer UCI (Read) ---
    let uuid = BtUuid::from_u16(BEARER_UCI_CHRC_UUID);
    ccs.bearer_uci = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );

    // --- Bearer Technology (Read + Notify) ---
    let uuid = BtUuid::from_u16(BEARER_TECH_CHRC_UUID);
    ccs.bearer_technology = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );
    ccs.bearer_technology_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // --- Bearer URI Schemes (Read) ---
    let uuid = BtUuid::from_u16(BEARER_URI_SCHEME_CHRC_UUID);
    ccs.bearer_uri_schemes_list = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );

    // --- Signal Strength (Read + Notify) ---
    let uuid = BtUuid::from_u16(BEARER_SIGNAL_STR_CHRC_UUID);
    ccs.signal_strength = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );
    ccs.signal_strength_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // --- Signal Strength Reporting Interval (Read + Write + Write Without Resp) ---
    let uuid = BtUuid::from_u16(BEARER_SIGNAL_INTRVL_CHRC_UUID);
    ccs.signal_reporting_intrvl = service.add_characteristic(
        &uuid,
        (AttPermissions::READ | AttPermissions::WRITE).bits() as u32,
        (GattChrcProperties::READ
            | GattChrcProperties::WRITE
            | GattChrcProperties::WRITE_WITHOUT_RESP)
            .bits(),
        Some(Arc::new(ccs_call_state_read)),
        Some(Arc::new(ccs_call_state_write)),
        None,
    );

    // --- Current Call List (Read + Notify) ---
    let uuid = BtUuid::from_u16(CURR_CALL_LIST_CHRC_UUID);
    ccs.current_call_list = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );
    ccs.current_call_list_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // --- Content Control ID (Read) ---
    let uuid = BtUuid::from_u16(BEARER_CCID_CHRC_UUID);
    ccs.ccid = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );

    // --- Status Flags (Read + Notify) ---
    let uuid = BtUuid::from_u16(CALL_STATUS_FLAG_CHRC_UUID);
    ccs.status_flag = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );
    ccs.status_flag_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // --- Incoming Call Target Bearer URI (Read) ---
    let uuid = BtUuid::from_u16(INCOM_CALL_TARGET_URI_CHRC_UUID);
    ccs.target_bearer_uri = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );

    // --- Call State (Read + Notify) ---
    // Note: In the C code (ccp.c line 363), CALL_STATE_CHRC_UUID is used
    // for what is stored in call_ctrl_point, but semantically this is the
    // Call State characteristic registration. We follow the C layout exactly.
    let uuid = BtUuid::from_u16(CALL_STATE_CHRC_UUID);
    ccs.call_state = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );
    ccs.call_state_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // --- Call Control Point (Write + Write Without Resp + Notify) ---
    let uuid = BtUuid::from_u16(CALL_CTRL_POINT_CHRC_UUID);
    ccs.call_ctrl_point = service.add_characteristic(
        &uuid,
        AttPermissions::WRITE.bits() as u32,
        (GattChrcProperties::WRITE
            | GattChrcProperties::WRITE_WITHOUT_RESP
            | GattChrcProperties::NOTIFY)
            .bits(),
        None,
        Some(Arc::new(ccs_call_state_write)),
        None,
    );

    // --- Call Control Point Optional Opcodes (Read) ---
    let uuid = BtUuid::from_u16(CALL_CTRL_POINT_OPT_OPCODE_CHRC_UUID);
    ccs.call_ctrl_opt_opcode = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );

    // --- Termination Reason (Read + Notify) ---
    let uuid = BtUuid::from_u16(TERMINATION_REASON_CHRC_UUID);
    ccs.termination_reason = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );

    // --- Incoming Call (Notify only) ---
    let uuid = BtUuid::from_u16(INCOMING_CALL_CHRC_UUID);
    ccs.incoming_call = service.add_characteristic(
        &uuid,
        AttPermissions::NONE.bits() as u32,
        GattChrcProperties::NOTIFY.bits(),
        None,
        None,
        None,
    );
    ccs.incoming_call_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // --- Call Friendly Name (Read + Notify) ---
    let uuid = BtUuid::from_u16(CALL_FRIENDLY_NAME_CHRC_UUID);
    ccs.friendly_name = service.add_characteristic(
        &uuid,
        AttPermissions::READ.bits() as u32,
        (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits(),
        Some(Arc::new(ccs_call_state_read)),
        None,
        None,
    );
    ccs.friendly_name_ccc =
        service.add_ccc((AttPermissions::READ | AttPermissions::WRITE).bits() as u32);

    // Service starts inactive (matching C: gatt_db_service_set_active(false)).
    service.set_active(false);

    ccs.service = Some(service.as_attribute());
    Some(ccs)
}

/// GTBS characteristic read handler.
///
/// Replaces `ccs_call_state_read()` (ccp.c lines 218-230).
/// Returns a zero-initialized call state value.
fn ccs_call_state_read(
    attrib: GattDbAttribute,
    id: u32,
    _offset: u16,
    _opcode: u8,
    _att: Option<Arc<Mutex<BtAtt>>>,
) {
    let call_state: i32 = 0;
    let data = call_state.to_le_bytes();
    attrib.read_result(id, 0, &data);
}

/// GTBS characteristic write handler.
///
/// Replaces `ccs_call_state_write()` (ccp.c lines 232-240).
/// Returns BT_ATT_ERROR_INSUFFICIENT_RESOURCES for all writes.
fn ccs_call_state_write(
    attrib: GattDbAttribute,
    id: u32,
    _offset: u16,
    _value: &[u8],
    _opcode: u8,
    _att: Option<Arc<Mutex<BtAtt>>>,
) {
    attrib.write_result(id, BT_ATT_ERROR_INSUFFICIENT_RESOURCES as i32);
}

// =====================================================================
// CcpDb management functions
// =====================================================================

/// Create a new CcpDb entry, register GTBS, and add to the global registry.
///
/// Replaces `ccp_db_new()` (ccp.c lines 1134-1151).
fn ccp_db_new(db: &GattDb) -> Option<Arc<Mutex<CcpDb>>> {
    let mut mdb = CcpDb::new(db.clone());
    mdb.ccs = ccs_new(db);

    let arc = Arc::new(Mutex::new(mdb));
    let arc_clone = Arc::clone(&arc);

    ensure_ccp_db_registry(|queue| {
        // Store a separate CcpDb entry in the registry for lookup.
        let registry_entry = CcpDb::new(db.clone());
        queue.push_tail(registry_entry);
    });

    Some(arc_clone)
}

/// Get or create a CcpDb for the given GATT database.
///
/// Replaces `ccp_get_db()` (ccp.c lines 1153-1162).
fn ccp_get_db(db: &GattDb) -> Option<Arc<Mutex<CcpDb>>> {
    // Check if we already have a CcpDb for this database in the registry.
    let found = ensure_ccp_db_registry(|queue| queue.find(|entry| entry.matches_db(db)).is_some());

    if found {
        // Database is already registered; create a wrapper for the caller.
        let mdb = CcpDb::new(db.clone());
        return Some(Arc::new(Mutex::new(mdb)));
    }

    ccp_db_new(db)
}

// =====================================================================
// Public registration function
// =====================================================================

/// Register the GTBS service in the given GATT database.
///
/// Replaces `bt_ccp_register()` (ccp.c lines 1194-1197).
/// This function registers the GTBS service and all its characteristics.
pub fn bt_ccp_register(db: &GattDb) {
    let _ = ccp_db_new(db);
}
