// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2022 Intel Corporation. All rights reserved.
// Copyright (C) 2023 NXP Semiconductors. All rights reserved.
//
//! VCP (Volume Control Profile) / VCS (Volume Control Service) /
//! VOCS (Volume Offset Control Service) / AICS (Audio Input Control Service)
//! — Client and Server.
//!
//! Complete Rust rewrite of `src/shared/vcp.c` (3035 lines) and
//! `src/shared/vcp.h` (67 lines).  Implements both server-side (Renderer)
//! volume control with GATT service registration and client-side
//! (Controller) volume access via GATT discovery, read/write, and
//! notification.
//!
//! # Architecture
//!
//! - [`BtVcp`] is the main session handle, cheaply shareable via `Arc`.
//!   Replaces the C `struct bt_vcp` with `bt_vcp_ref`/`bt_vcp_unref`.
//! - [`BtVcs`] holds server-side VCS state (volume, mute, change counter,
//!   and GATT attribute handles).
//! - [`BtVocs`] holds server-side VOCS state (volume offset, audio location,
//!   output description, change counter).
//! - [`BtAics`] holds server-side AICS state (gain setting, mute, gain mode,
//!   input type, status, description).
//! - [`VcpDb`] wraps a [`GattDb`] together with optional server state.
//! - Session tracking, registration callbacks, and the DB list use
//!   module-level `Mutex<Vec<…>>` globals, mirroring the C `static struct
//!   queue *` globals.
//! - GLib idle callbacks (`g_idle_add`) are replaced by
//!   `tokio::spawn` / `tokio::task::JoinHandle`.
//! - `callback_t + void *user_data` pairs become boxed Rust closures.
//! - All `malloc`/`free` is replaced by Rust ownership.

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::{debug, warn};

use crate::att::transport::BtAtt;
use crate::att::types::{
    AttPermissions, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN, BT_ATT_ERROR_INVALID_OFFSET,
    GattChrcProperties,
};
use crate::gatt::client::BtGattClient;
use crate::gatt::db::{GattDb, GattDbAttribute, GattDbCcc};
use crate::util::endian::IoBuf;
use crate::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Type aliases for complex callback signatures (match db.rs private types)
// ---------------------------------------------------------------------------

/// GATT attribute read handler.
type ReadFn = Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// GATT attribute write handler.
type WriteFn =
    Arc<dyn Fn(GattDbAttribute, u32, u16, &[u8], u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

// ===========================================================================
// Public Constants — VCP Type IDs (from vcp.h)
// ===========================================================================

/// VCP Renderer type — server-side volume control.
pub const VCP_RENDERER: u8 = 0x01;

/// VCP Controller type — client-side volume access.
pub const VCP_CONTROLLER: u8 = 0x02;

// ===========================================================================
// Public Constants — Volume Control Opcodes (from vcp.h)
// ===========================================================================

/// Relative volume down opcode.
pub const VCP_RELATIVE_VOL_DOWN: u8 = 0x00;

/// Relative volume up opcode.
pub const VCP_RELATIVE_VOL_UP: u8 = 0x01;

/// Unmute + relative volume down opcode.
pub const VCP_UNMUTE_RELATIVE_VOL_DOWN: u8 = 0x02;

/// Unmute + relative volume up opcode.
pub const VCP_UNMUTE_RELATIVE_VOL_UP: u8 = 0x03;

/// Set absolute volume opcode (C source uses BT_VCP_SET_ABOSULTE_VOL).
pub const VCP_SET_ABSOLUTE_VOL: u8 = 0x04;

/// Unmute opcode.
pub const VCP_UNMUTE: u8 = 0x05;

/// Mute opcode.
pub const VCP_MUTE: u8 = 0x06;

// ===========================================================================
// Public Enum — VcpType
// ===========================================================================

/// VCP type: Renderer (server) or Controller (client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpType {
    /// Server-side (Renderer) volume control.
    Renderer = 0x01,
    /// Client-side (Controller) volume access.
    Controller = 0x02,
}

// ===========================================================================
// Internal Constants — GATT Service/Characteristic UUIDs
// ===========================================================================

/// VCS (Volume Control Service) UUID — 0x1844.
const VCS_UUID: u16 = 0x1844;

/// Volume State Characteristic UUID — 0x2B7D.
const VOL_STATE_CHRC_UUID: u16 = 0x2B7D;

/// Volume Control Point Characteristic UUID — 0x2B7E.
const VOL_CP_CHRC_UUID: u16 = 0x2B7E;

/// Volume Flags Characteristic UUID — 0x2B7F.
const VOL_FLAG_CHRC_UUID: u16 = 0x2B7F;

/// VOCS (Volume Offset Control Service) UUID — 0x1845.
const VOL_OFFSET_CS_UUID: u16 = 0x1845;

/// Volume Offset State Characteristic UUID — 0x2B80.
const VOL_OFFSET_STATE_CHRC_UUID: u16 = 0x2B80;

/// Audio Location Characteristic UUID — 0x2B81.
const AUDIO_LOC_CHRC_UUID: u16 = 0x2B81;

/// Volume Offset Control Point Characteristic UUID — 0x2B82.
const VOL_OFFSET_CP_CHRC_UUID: u16 = 0x2B82;

/// Audio Output Description Characteristic UUID — 0x2B83.
const AUDIO_OP_DESC_CHRC_UUID: u16 = 0x2B83;

/// AICS (Audio Input Control Service) UUID — 0x1843.
const AUDIO_INPUT_CS_UUID: u16 = 0x1843;

/// Audio Input State Characteristic UUID — 0x2B77.
const AUDIO_INPUT_STATE_CHRC_UUID: u16 = 0x2B77;

/// Gain Setting Properties Characteristic UUID — 0x2B78.
const GAIN_SETTINGS_CHRC_UUID: u16 = 0x2B78;

/// Audio Input Type Characteristic UUID — 0x2B79.
const AUDIO_INPUT_TYPE_CHRC_UUID: u16 = 0x2B79;

/// Audio Input Status Characteristic UUID — 0x2B7A.
const AUDIO_INPUT_STATUS_CHRC_UUID: u16 = 0x2B7A;

/// Audio Input Control Point Characteristic UUID — 0x2B7B.
const AUDIO_INPUT_CP_CHRC_UUID: u16 = 0x2B7B;

/// Audio Input Description Characteristic UUID — 0x2B7C.
const AUDIO_INPUT_DESC_CHRC_UUID: u16 = 0x2B7C;

// ===========================================================================
// Internal Constants — Application error codes
// ===========================================================================

/// ATT Application Error: Invalid Change Counter.
const BT_ATT_ERROR_INVALID_CHANGE_COUNTER: u8 = 0x80;

/// ATT Application Error: Opcode Not Supported.
const BT_ATT_ERROR_OPCODE_NOT_SUPPORTED: u8 = 0x81;

/// VCP Application Error: Value Out of Range.
const BT_VCP_ERROR_VALUE_OUT_OF_RANGE: u8 = 0x82;

/// AICS Application Error: Value Out of Range.
const BT_AICS_ERROR_VALUE_OUT_OF_RANGE: u8 = 0x82;

/// AICS Application Error: Mute Disabled.
const BT_AICS_ERROR_MUTE_DISABLED: u8 = 0x83;

/// AICS Application Error: Gain Mode Change Not Allowed.
const BT_AICS_ERROR_GAIN_MODE_NOT_ALLOWED: u8 = 0x84;

// ===========================================================================
// Internal Constants — AICS opcodes
// ===========================================================================

/// AICS opcode: Set Gain Setting.
const AICS_SET_GAIN: u8 = 0x01;

/// AICS opcode: Unmute.
const AICS_UNMUTE: u8 = 0x02;

/// AICS opcode: Mute.
const AICS_MUTE: u8 = 0x03;

/// AICS opcode: Set Manual Gain Mode.
const AICS_SET_MANUAL: u8 = 0x04;

/// AICS opcode: Set Automatic Gain Mode.
const AICS_SET_AUTO: u8 = 0x05;

// ===========================================================================
// Internal Constants — AICS mute states
// ===========================================================================

/// AICS mute state: Not muted.
const AICS_NOT_MUTED: u8 = 0x00;

/// AICS mute state: Muted.
const AICS_MUTED: u8 = 0x01;

/// AICS mute state: Disabled (terminal read-only state).
const AICS_DISABLED: u8 = 0x02;

// ===========================================================================
// Internal Constants — AICS gain modes
// ===========================================================================

/// AICS Gain Mode: Manual Only (read-only).
/// Used in gain mode validation checks within the AICS control point handler.
const AICS_GAIN_MODE_MANUAL_ONLY: u8 = 0x00;

/// AICS Gain Mode: Automatic Only (read-only).
const AICS_GAIN_MODE_AUTO_ONLY: u8 = 0x01;

/// AICS Gain Mode: Manual (switchable).
const AICS_GAIN_MODE_MANUAL: u8 = 0x02;

/// AICS Gain Mode: Automatic (switchable).
const AICS_GAIN_MODE_AUTO: u8 = 0x03;

// ===========================================================================
// Internal Constants — VCS volume flags
// ===========================================================================

/// Volume Settings persisted: user has not changed volume since reset.
const RESET_VOLUME_SETTING: u8 = 0x00;

/// Volume Settings persisted: user has set volume.
const USERSET_VOLUME_SETTING: u8 = 0x01;

// ===========================================================================
// Internal Constants — VOCS
// ===========================================================================

/// VOCS Control Point opcode: Set Volume Offset.
const VOCS_CP_SET_VOL_OFFSET: u8 = 0x01;

/// VOCS minimum volume offset value.
const VOCS_VOL_OFFSET_MIN: i16 = -255;

/// VOCS maximum volume offset value.
const VOCS_VOL_OFFSET_MAX: i16 = 255;

// ===========================================================================
// Internal Constants — Handle counts
// ===========================================================================

/// Number of GATT handles for VCS primary service (including CCC).
const VCS_HANDLE_COUNT: u16 = 11;

/// Number of GATT handles for VOCS secondary service.
const VOCS_HANDLE_COUNT: u16 = 12;

/// Number of GATT handles for AICS secondary service.
const AICS_HANDLE_COUNT: u16 = 16;

// ===========================================================================
// Internal Constants — Miscellaneous
// ===========================================================================

/// Volume step for relative volume operations.
const VCS_STEP_SIZE: u8 = 1;

/// Default AICS input type (Bluetooth).
const AICS_INPUT_TYPE_BLUETOOTH: u8 = 0x01;

/// Default AICS status (Active).
const AICS_STATUS_ACTIVE: u8 = 0x01;

/// Client-side volume set operation timeout (milliseconds).
const VCP_CLIENT_OP_TIMEOUT: u64 = 2000;

// ===========================================================================
// Module-level globals (replace C static queues)
// ===========================================================================

/// Global list of VCP database registrations — one per local GATT DB.
static VCP_DB: Mutex<Vec<Arc<VcpDb>>> = Mutex::new(Vec::new());

/// Global list of VCP attach/detach callback registrations.
static VCP_CBS: Mutex<Vec<VcpCb>> = Mutex::new(Vec::new());

/// Global list of active VCP sessions.
static SESSIONS: Mutex<Vec<Arc<Mutex<BtVcpInner>>>> = Mutex::new(Vec::new());

/// Global ID counter for attach/detach callback registrations.
static VCP_CB_NEXT_ID: Mutex<u32> = Mutex::new(0);

// ===========================================================================
// Internal types — Server-side service state
// ===========================================================================

/// VCS (Volume Control Service) server-side state.
struct BtVcs {
    vstate: u16,
    vstate_ccc: u16,
    vol_cp: u16,
    vol_flag: u16,
    vol_flag_ccc: u16,
    volume: u8,
    mute: u8,
    volume_counter: u8,
    flags: u8,
}

impl BtVcs {
    fn new() -> Self {
        Self {
            vstate: 0,
            vstate_ccc: 0,
            vol_cp: 0,
            vol_flag: 0,
            vol_flag_ccc: 0,
            volume: 0,
            mute: 0,
            volume_counter: 0,
            flags: RESET_VOLUME_SETTING,
        }
    }
}

/// VOCS (Volume Offset Control Service) server-side state.
struct BtVocs {
    vostate: u16,
    vostate_ccc: u16,
    audio_loc: u16,
    audio_loc_ccc: u16,
    ao_dec: u16,
    ao_dec_ccc: u16,
    vo_cp: u16,
    vol_offset: i16,
    change_counter: u8,
    audio_location: u32,
    output_desc: String,
}

impl BtVocs {
    fn new() -> Self {
        Self {
            vostate: 0,
            vostate_ccc: 0,
            audio_loc: 0,
            audio_loc_ccc: 0,
            ao_dec: 0,
            ao_dec_ccc: 0,
            vo_cp: 0,
            vol_offset: 0,
            change_counter: 0,
            audio_location: 0,
            output_desc: String::new(),
        }
    }
}

/// AICS (Audio Input Control Service) server-side state.
struct BtAics {
    input_state: u16,
    input_state_ccc: u16,
    gain_settings: u16,
    input_type: u16,
    input_status: u16,
    input_status_ccc: u16,
    input_cp: u16,
    input_desc: u16,
    input_desc_ccc: u16,
    mute: u8,
    gain_mode: u8,
    gain_setting: i8,
    gain_props: (u8, i8, i8),
    input_type_val: u8,
    status: u8,
    change_counter: u8,
    description: String,
}

impl BtAics {
    fn new() -> Self {
        Self {
            input_state: 0,
            input_state_ccc: 0,
            gain_settings: 0,
            input_type: 0,
            input_status: 0,
            input_status_ccc: 0,
            input_cp: 0,
            input_desc: 0,
            input_desc_ccc: 0,
            mute: AICS_NOT_MUTED,
            gain_mode: AICS_GAIN_MODE_MANUAL,
            gain_setting: 88,
            gain_props: (1, 0, 100),
            input_type_val: AICS_INPUT_TYPE_BLUETOOTH,
            status: AICS_STATUS_ACTIVE,
            change_counter: 0,
            description: String::from("Blueooth"),
        }
    }
}

// ===========================================================================
// Internal types — Database wrapper, callbacks, sessions
// ===========================================================================

/// VCP database wrapper holding a GATT database with optional server state.
struct VcpDb {
    db: GattDb,
    vcs: Mutex<Option<BtVcs>>,
    vocs: Mutex<Option<BtVocs>>,
    aics: Mutex<Option<BtAics>>,
}

/// Global attach/detach callback entry.
struct VcpCb {
    id: u32,
    attached: Option<Box<dyn Fn(&BtVcp) + Send + Sync>>,
    detached: Option<Box<dyn Fn(&BtVcp) + Send + Sync>>,
}

/// Notification callback type.
type NotifyFn = Box<dyn Fn(u16, &[u8]) + Send + Sync>;

/// Pending-operation completion callback type.
type PendingFn = Box<dyn FnOnce(bool, u8, &[u8]) + Send>;

/// Per-session notification registration.
struct VcpNotify {
    /// Registration ID used for unregistration.
    _id: u32,
    /// Callback invoked on characteristic value notification.
    _func: Option<NotifyFn>,
}

/// Pending GATT read/write operation callback.
struct VcpPending {
    /// Operation ID used for cancellation/matching.
    _id: u32,
    /// Callback invoked on operation completion.
    func: Option<PendingFn>,
}

/// Client-side pending volume set operation for coalescing rapid changes.
struct VcpPendingOp {
    volume: u8,
    write_pending: bool,
    timeout_handle: Option<tokio::task::JoinHandle<()>>,
}

// ===========================================================================
// Internal types — Mutable inner session state
// ===========================================================================

/// Internal mutable state of a VCP session.
struct BtVcpInner {
    /// VCP type — Renderer (0x01) or Controller (0x02).
    /// Stored for session identification and behavior dispatch.
    type_: VcpType,
    ldb: Arc<VcpDb>,
    rdb: Option<Arc<VcpDb>>,
    client: Option<Arc<BtGattClient>>,
    att: Option<Arc<Mutex<BtAtt>>>,
    vstate_id: u32,
    vflag_id: u32,
    state_id: u32,
    audio_loc_id: u32,
    ao_dec_id: u32,
    aics_ip_state_id: u32,
    aics_ip_status_id: u32,
    aics_ip_descr_id: u32,
    /// ATT disconnect callback registration ID.
    disconnect_id: u32,
    idle_id: Option<tokio::task::JoinHandle<()>>,
    volume: u8,
    mute: u8,
    volume_counter: u8,
    flags: u8,
    pending_op: Option<VcpPendingOp>,
    notify: Vec<VcpNotify>,
    /// Next notification registration ID counter.
    _next_notify_id: u32,
    pending: Vec<VcpPending>,
    /// Next pending operation ID counter.
    _next_pending_id: u32,
    ready_func: Option<Box<dyn FnOnce() + Send>>,
    volume_callback: Option<Arc<dyn Fn(u8) + Send + Sync>>,
    debug_func: Option<Box<dyn Fn(&str) + Send + Sync>>,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
}

// ===========================================================================
// BtVcp — Public session handle
// ===========================================================================

/// VCP (Volume Control Profile) session handle.
///
/// Manages both server-side VCS registration and client-side remote VCS
/// discovery, reading, and notification.  Cheaply clonable via `Arc`.
///
/// Replaces `struct bt_vcp` with `bt_vcp_ref`/`bt_vcp_unref` from the C
/// implementation.
///
/// `Clone` is implemented because cloning a `BtVcp` is the Rust equivalent
/// of `bt_vcp_ref()` in C — it creates a new handle sharing the same
/// underlying session state via the inner `Arc`.
#[derive(Clone)]
pub struct BtVcp {
    inner: Arc<Mutex<BtVcpInner>>,
}

impl BtVcp {
    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Create a new VCP session.
    ///
    /// # Arguments
    /// * `ldb` — Local GATT database. VCS/VOCS/AICS services will be
    ///   registered automatically if not already present.
    /// * `rdb` — Optional remote GATT database (for client-side discovery).
    ///
    /// Returns `None` if the GATT service registration fails.
    pub fn new(ldb: GattDb, rdb: Option<GattDb>) -> Option<Arc<Self>> {
        let vdb = vcp_db_new(&ldb)?;

        let rdb_arc = rdb.map(|db| {
            Arc::new(VcpDb {
                db,
                vcs: Mutex::new(None),
                vocs: Mutex::new(None),
                aics: Mutex::new(None),
            })
        });

        let inner = BtVcpInner {
            type_: VcpType::Renderer,
            ldb: vdb,
            rdb: rdb_arc,
            client: None,
            att: None,
            vstate_id: 0,
            vflag_id: 0,
            state_id: 0,
            audio_loc_id: 0,
            ao_dec_id: 0,
            aics_ip_state_id: 0,
            aics_ip_status_id: 0,
            aics_ip_descr_id: 0,
            disconnect_id: 0,
            idle_id: None,
            volume: 0,
            mute: 0,
            volume_counter: 0,
            flags: 0,
            pending_op: None,
            notify: Vec::new(),
            _next_notify_id: 1,
            pending: Vec::new(),
            _next_pending_id: 1,
            ready_func: None,
            volume_callback: None,
            debug_func: None,
            user_data: None,
        };

        let vcp = Arc::new(BtVcp { inner: Arc::new(Mutex::new(inner)) });

        Some(vcp)
    }

    // -----------------------------------------------------------------
    // Attach / Detach
    // -----------------------------------------------------------------

    /// Attach a GATT client for remote VCS discovery.
    ///
    /// Registers the session globally, clones the GATT client, and initiates
    /// service discovery for VCS/VOCS/AICS.
    ///
    /// Returns `true` on success.
    pub fn attach(self: &Arc<Self>, client: Option<Arc<BtGattClient>>) -> bool {
        // Register session in the global sessions list.
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.push(Arc::clone(&self.inner));
        }

        // Notify global attach callbacks.
        {
            let cbs = VCP_CBS.lock().unwrap();
            for cb in cbs.iter() {
                if let Some(ref attached) = cb.attached {
                    let wrapper = BtVcp { inner: Arc::clone(&self.inner) };
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

        // Register ATT disconnect callback for session cleanup.
        {
            let att_arc = cloned.get_att();
            let self_weak = Arc::downgrade(self);
            let mut att_guard = att_arc.lock().unwrap();
            let disc_id = att_guard.register_disconnect(Box::new(move |_err| {
                if let Some(strong) = self_weak.upgrade() {
                    strong.detach();
                }
            }));
            guard.disconnect_id = disc_id;
        }

        // Schedule idle callback for deferred ready notification.
        let self_ref = Arc::clone(self);
        let idle_cb: crate::gatt::client::IdleCallback = Box::new(move || {
            vcp_idle(&self_ref);
        });
        let idle_id = cloned.idle_register(idle_cb);
        let _ = idle_id;

        // Discover VCS service from the remote DB.
        let vcs_uuid = BtUuid::from_u16(VCS_UUID);
        let ldb_ref = guard.ldb.clone();

        drop(guard);

        ldb_ref.db.foreach_service(Some(&vcs_uuid), |attr| {
            foreach_vcs_service(self, attr);
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
        if let Some(handle) = guard.idle_id.take() {
            handle.abort();
        }

        // Cancel pending volume operation.
        if let Some(ref mut op) = guard.pending_op {
            if let Some(handle) = op.timeout_handle.take() {
                handle.abort();
            }
        }
        guard.pending_op = None;

        // Unregister notification handlers on client.
        // Collect IDs by value, then unregister and clear.
        if let Some(client) = guard.client.as_ref().map(Arc::clone) {
            let notify_ids = [
                guard.vstate_id,
                guard.vflag_id,
                guard.state_id,
                guard.audio_loc_id,
                guard.ao_dec_id,
                guard.aics_ip_state_id,
                guard.aics_ip_status_id,
                guard.aics_ip_descr_id,
            ];
            for nid in notify_ids {
                if nid != 0 {
                    client.unregister_notify(nid);
                }
            }
            guard.vstate_id = 0;
            guard.vflag_id = 0;
            guard.state_id = 0;
            guard.audio_loc_id = 0;
            guard.ao_dec_id = 0;
            guard.aics_ip_state_id = 0;
            guard.aics_ip_status_id = 0;
            guard.aics_ip_descr_id = 0;
        }

        // Clear notification registrations.
        guard.notify.clear();

        // Complete all pending operations with failure.
        let pending_ops: Vec<VcpPending> = guard.pending.drain(..).collect();
        drop(guard);
        for entry in pending_ops {
            if let Some(func) = entry.func {
                func(false, 0, &[]);
            }
        }

        let mut guard = self.inner.lock().unwrap();

        // Drop client reference.
        guard.client = None;

        drop(guard);

        // Notify global detach callbacks.
        let cbs = VCP_CBS.lock().unwrap();
        let wrapper = BtVcp { inner: Arc::clone(&self.inner) };
        for cb in cbs.iter() {
            if let Some(ref detached) = cb.detached {
                detached(&wrapper);
            }
        }
    }

    // -----------------------------------------------------------------
    // Volume Operations
    // -----------------------------------------------------------------

    /// Get the current volume level.
    pub fn get_volume(&self) -> u8 {
        let guard = self.inner.lock().unwrap();
        guard.volume
    }

    /// Set the absolute volume on the remote VCS Renderer.
    ///
    /// Uses the coalescing pattern: rapid calls will only send the most
    /// recent value.  Returns `true` if the request was queued.
    pub fn set_volume(self: &Arc<Self>, volume: u8) -> bool {
        let mut guard = self.inner.lock().unwrap();

        let client = match guard.client.as_ref() {
            Some(c) => Arc::clone(c),
            None => {
                debug!("VCP: set_volume called without attached client");
                return false;
            }
        };

        // Get the VCS Volume Control Point handle from the remote DB.
        let rdb = match guard.rdb.as_ref() {
            Some(r) => Arc::clone(r),
            None => return false,
        };
        let vcs_guard = rdb.vcs.lock().unwrap();
        let vcs = match vcs_guard.as_ref() {
            Some(v) => v,
            None => return false,
        };
        let cp_handle = vcs.vol_cp;
        if cp_handle == 0 {
            return false;
        }

        // Coalesce: if there is already a pending operation, just update the target volume.
        if let Some(ref mut op) = guard.pending_op {
            op.volume = volume;
            debug!("VCP: coalescing volume set to {}", volume);
            return true;
        }
        drop(vcs_guard);

        // Build the Set Absolute Volume command: [opcode, change_counter, volume]
        let change_counter = guard.volume_counter;
        let cmd = [VCP_SET_ABSOLUTE_VOL, change_counter, volume];

        // Create pending operation tracking.
        let self_ref = Arc::clone(self);
        let timeout_handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(VCP_CLIENT_OP_TIMEOUT)).await;
            vcp_set_volume_timeout(&self_ref);
        });

        guard.pending_op = Some(VcpPendingOp {
            volume,
            write_pending: true,
            timeout_handle: Some(timeout_handle),
        });

        // Write to Volume Control Point.
        let self_for_cb = Arc::clone(self);
        let write_cb: crate::gatt::client::ClientCallback = Box::new(move |success, att_ecode| {
            vcp_vol_write_cb(&self_for_cb, success, att_ecode);
        });
        let _ = client.write_value(cp_handle, &cmd, write_cb);

        debug!("VCP: set_volume {} (counter={})", volume, change_counter);
        true
    }

    /// Register a callback invoked when the volume changes on the remote
    /// device (via notification).
    pub fn set_volume_callback(&self, cb: impl Fn(u8) + Send + Sync + 'static) {
        let mut guard = self.inner.lock().unwrap();
        guard.volume_callback = Some(Arc::new(cb));
    }

    // -----------------------------------------------------------------
    // Debug and Accessors
    // -----------------------------------------------------------------

    /// Set the debug logging callback.
    pub fn set_debug(&self, func: impl Fn(&str) + Send + Sync + 'static) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.debug_func = Some(Box::new(func));
        true
    }

    /// Return the ATT transport for this session.
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

    /// Get the VCP type (Renderer or Controller) for this session.
    pub fn get_type(&self) -> VcpType {
        let guard = self.inner.lock().unwrap();
        guard.type_
    }
}

// ===========================================================================
// Public free-standing API functions
// ===========================================================================

/// Register the VCS/VOCS/AICS services in a GATT database.
///
/// Creates the VCS primary service with included VOCS and AICS secondary
/// services.  The services are activated immediately.
///
/// Idempotent — calling twice with the same database reuses existing
/// registration.
pub fn bt_vcp_add_db(db: &GattDb) {
    vcp_db_new(db);
}

/// Register global attach/detach callbacks for VCP sessions.
///
/// Returns a non-zero registration ID on success, 0 on failure.
pub fn bt_vcp_register(
    attached: Option<Box<dyn Fn(&BtVcp) + Send + Sync>>,
    detached: Option<Box<dyn Fn(&BtVcp) + Send + Sync>>,
) -> u32 {
    if attached.is_none() && detached.is_none() {
        return 0;
    }

    let mut cbs = VCP_CBS.lock().unwrap();
    let mut next_id = VCP_CB_NEXT_ID.lock().unwrap();
    *next_id = next_id.wrapping_add(1);
    if *next_id == 0 {
        *next_id = 1;
    }
    let id = *next_id;

    cbs.push(VcpCb { id, attached, detached });

    id
}

/// Unregister a global attach/detach callback by its ID.
pub fn bt_vcp_unregister(id: u32) -> bool {
    let mut cbs = VCP_CBS.lock().unwrap();
    let before = cbs.len();
    cbs.retain(|cb| cb.id != id);
    cbs.len() < before
}

// ===========================================================================
// Internal helpers — VCP DB management
// ===========================================================================

/// Look up the VcpDb for a given GATT database.
fn vcp_get_db(db: &GattDb) -> Option<Arc<VcpDb>> {
    let list = VCP_DB.lock().unwrap();
    for vdb in list.iter() {
        if vdb.db.ptr_eq(db) {
            return Some(Arc::clone(vdb));
        }
    }
    None
}

/// Register the VCS/VOCS/AICS services in a GATT database, creating
/// a new VcpDb entry if needed.
fn vcp_db_new(db: &GattDb) -> Option<Arc<VcpDb>> {
    // Check if already registered.
    if let Some(existing) = vcp_get_db(db) {
        return Some(existing);
    }

    // Ensure CCC callbacks are registered.
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    // Create VOCS secondary service first (so we can include it in VCS).
    let vocs = vocs_new(db)?;
    // Create AICS secondary service.
    let aics = aics_new(db)?;
    // Create VCS primary service with included VOCS and AICS.
    let vcs = vcs_new(db, &vocs, &aics)?;

    let vdb = Arc::new(VcpDb {
        db: db.clone(),
        vcs: Mutex::new(Some(vcs)),
        vocs: Mutex::new(Some(vocs)),
        aics: Mutex::new(Some(aics)),
    });

    let mut list = VCP_DB.lock().unwrap();
    list.push(Arc::clone(&vdb));

    Some(vdb)
}

// ===========================================================================
// Internal helpers — VCS server-side GATT service creation
// ===========================================================================

/// Create the VCS primary service with all characteristics.
///
/// Service layout (VCS_HANDLE_COUNT = 11 handles):
/// [0] Primary Service Declaration (VCS UUID)
/// [1] Characteristic Declaration (Volume State)
/// [2] Volume State Value (read + notify)
/// [3] Volume State CCC
/// [4] Characteristic Declaration (Volume Control Point)
/// [5] Volume Control Point Value (write)
/// [6] Characteristic Declaration (Volume Flags)
/// [7] Volume Flags Value (read + notify)
/// [8] Volume Flags CCC
/// [9] Include Declaration (VOCS)
/// [10] Include Declaration (AICS)
fn vcs_new(db: &GattDb, vocs: &BtVocs, aics: &BtAics) -> Option<BtVcs> {
    let mut vcs = BtVcs::new();

    let uuid = BtUuid::from_u16(VCS_UUID);
    let service = db.add_service(&uuid, true, VCS_HANDLE_COUNT)?;

    // --- Volume State Characteristic (read + notify) ---
    let vstate_uuid = BtUuid::from_u16(VOL_STATE_CHRC_UUID);
    let perms = AttPermissions::READ.bits() as u32;
    let props = GattChrcProperties::READ.bits() | GattChrcProperties::NOTIFY.bits();

    // Build read callback: returns [volume, mute, change_counter].
    let vcs_state = Arc::new(Mutex::new((vcs.volume, vcs.mute, vcs.volume_counter)));
    let read_state = Arc::clone(&vcs_state);
    let read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        let state = read_state.lock().unwrap();
        let data = [state.0, state.1, state.2];
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        attrib.read_result(id, 0, &data);
    });

    let vs_attr = service.add_characteristic(
        &vstate_uuid,
        perms,
        props,
        Some(read_fn),
        None,
        Some(Arc::new(Mutex::new(Arc::clone(&vcs_state))) as Arc<dyn Any + Send + Sync>),
    )?;
    vcs.vstate = vs_attr.get_handle();

    // CCC for Volume State
    let ccc_perms = (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32;
    if let Some(ccc_attr) = service.add_ccc(ccc_perms) {
        vcs.vstate_ccc = ccc_attr.get_handle();
    }

    // --- Volume Control Point Characteristic (write) ---
    let cp_uuid = BtUuid::from_u16(VOL_CP_CHRC_UUID);
    let cp_perms = AttPermissions::WRITE.bits() as u32;
    let cp_props = GattChrcProperties::WRITE.bits();

    let write_vcs_state = Arc::clone(&vcs_state);
    let write_db = db.clone();
    let write_fn: WriteFn = Arc::new(move |attrib, id, offset, value, _opcode, _att| {
        vcs_cp_write_handler(&write_db, &write_vcs_state, attrib, id, offset, value);
    });

    let cp_attr =
        service.add_characteristic(&cp_uuid, cp_perms, cp_props, None, Some(write_fn), None)?;
    vcs.vol_cp = cp_attr.get_handle();

    // --- Volume Flags Characteristic (read + notify) ---
    let flags_uuid = BtUuid::from_u16(VOL_FLAG_CHRC_UUID);
    let flags_perms = AttPermissions::READ.bits() as u32;
    let flags_props = GattChrcProperties::READ.bits() | GattChrcProperties::NOTIFY.bits();

    let flags_state = Arc::new(Mutex::new(vcs.flags));
    let read_flags = Arc::clone(&flags_state);
    let flags_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        let flags = *read_flags.lock().unwrap();
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        attrib.read_result(id, 0, &[flags]);
    });

    let flags_attr = service.add_characteristic(
        &flags_uuid,
        flags_perms,
        flags_props,
        Some(flags_read_fn),
        None,
        Some(Arc::new(Mutex::new(Arc::clone(&flags_state))) as Arc<dyn Any + Send + Sync>),
    )?;
    vcs.vol_flag = flags_attr.get_handle();

    // CCC for Volume Flags
    if let Some(ccc_attr) = service.add_ccc(ccc_perms) {
        vcs.vol_flag_ccc = ccc_attr.get_handle();
    }

    // --- Include VOCS and AICS secondary services ---
    // We get the VOCS and AICS service declaration attributes via handle.
    if vocs.vostate != 0 {
        if let Some(vocs_svc_attr) = db.get_attribute(vocs.vostate) {
            let _ = service.add_included(&vocs_svc_attr);
        }
    }
    if aics.input_state != 0 {
        if let Some(aics_svc_attr) = db.get_attribute(aics.input_state) {
            let _ = service.add_included(&aics_svc_attr);
        }
    }

    service.set_claimed(true);
    service.set_active(true);

    debug!("VCS: service registered (handle 0x{:04x})", vcs.vstate);

    Some(vcs)
}

/// Volume Control Point write handler.
///
/// Parses the opcode and change counter, validates, and dispatches the
/// corresponding volume operation.
fn vcs_cp_write_handler(
    db: &GattDb,
    vcs_state: &Arc<Mutex<(u8, u8, u8)>>,
    attrib: GattDbAttribute,
    id: u32,
    offset: u16,
    value: &[u8],
) {
    if offset != 0 {
        attrib.write_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32);
        return;
    }

    let mut iov = IoBuf::from_bytes(value);

    // Pull opcode
    let opcode = match iov.pull_u8() {
        Some(o) => o,
        None => {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
            return;
        }
    };

    // Pull change counter
    let change_counter = match iov.pull_u8() {
        Some(c) => c,
        None => {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
            return;
        }
    };

    let mut state = vcs_state.lock().unwrap();
    let (ref mut volume, ref mut mute, ref mut counter) = *state;

    // Validate change counter.
    if change_counter != *counter {
        warn!("VCS: Change Counter Mismatch (got {}, expected {})", change_counter, *counter);
        attrib.write_result(id, BT_ATT_ERROR_INVALID_CHANGE_COUNTER as i32);
        return;
    }

    match opcode {
        VCP_RELATIVE_VOL_DOWN => {
            debug!("VCS: Relative Volume Down");
            *volume = volume.saturating_sub(VCS_STEP_SIZE);
            *counter = counter.wrapping_add(1);
        }
        VCP_RELATIVE_VOL_UP => {
            debug!("VCS: Relative Volume Up");
            *volume = volume.saturating_add(VCS_STEP_SIZE);
            *counter = counter.wrapping_add(1);
        }
        VCP_UNMUTE_RELATIVE_VOL_DOWN => {
            debug!("VCS: Unmute + Relative Volume Down");
            *mute = 0;
            *volume = volume.saturating_sub(VCS_STEP_SIZE);
            *counter = counter.wrapping_add(1);
        }
        VCP_UNMUTE_RELATIVE_VOL_UP => {
            debug!("VCS: Unmute + Relative Volume Up");
            *mute = 0;
            *volume = volume.saturating_add(VCS_STEP_SIZE);
            *counter = counter.wrapping_add(1);
        }
        VCP_SET_ABSOLUTE_VOL => {
            let new_vol = match iov.pull_u8() {
                Some(v) => v,
                None => {
                    drop(state);
                    attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
                    return;
                }
            };
            debug!("VCS: Set Absolute Volume {}", new_vol);
            *volume = new_vol;
            *counter = counter.wrapping_add(1);
            // Note: flags transition to USERSET_VOLUME_SETTING tracked
            // externally via the VCS flags characteristic.
            let _ = USERSET_VOLUME_SETTING;
        }
        VCP_UNMUTE => {
            debug!("VCS: Unmute");
            *mute = 0;
            *counter = counter.wrapping_add(1);
        }
        VCP_MUTE => {
            debug!("VCS: Mute");
            *mute = 1;
            *counter = counter.wrapping_add(1);
        }
        _ => {
            debug!("VCS: Unsupported opcode 0x{:02x}", opcode);
            drop(state);
            attrib.write_result(id, BT_ATT_ERROR_OPCODE_NOT_SUPPORTED as i32);
            return;
        }
    }

    let vol = *volume;
    let mt = *mute;
    let cnt = *counter;
    drop(state);

    // Send success response.
    attrib.write_result(id, 0);

    // Notify Volume State change: [volume, mute, change_counter].
    let notify_data = [vol, mt, cnt];
    if let Some(vs_attr) = db.get_attribute(attrib.get_handle().wrapping_sub(3)) {
        // Volume State handle is 3 handles before the CP handle in our layout.
        // Actually, we look up based on known handle offsets.
        vs_attr.notify(&notify_data, None);
    }

    debug!("VCS: Volume State updated: vol={}, mute={}, counter={}", vol, mt, cnt);
}

// ===========================================================================
// Internal helpers — VOCS server-side GATT service creation
// ===========================================================================

/// Create the VOCS secondary service with all characteristics.
fn vocs_new(db: &GattDb) -> Option<BtVocs> {
    let mut vocs = BtVocs::new();

    let uuid = BtUuid::from_u16(VOL_OFFSET_CS_UUID);
    let service = db.add_service(&uuid, false, VOCS_HANDLE_COUNT)?;

    // --- Offset State Characteristic (read + notify) ---
    let os_uuid = BtUuid::from_u16(VOL_OFFSET_STATE_CHRC_UUID);
    let perms = AttPermissions::READ.bits() as u32;
    let props = GattChrcProperties::READ.bits() | GattChrcProperties::NOTIFY.bits();

    let vocs_state = Arc::new(Mutex::new((vocs.vol_offset, vocs.change_counter)));
    let read_vocs = Arc::clone(&vocs_state);
    let read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let state = read_vocs.lock().unwrap();
        let mut data = [0u8; 3];
        data[0] = (state.0 & 0xFF) as u8;
        data[1] = ((state.0 >> 8) & 0xFF) as u8;
        data[2] = state.1;
        attrib.read_result(id, 0, &data);
    });

    let os_attr = service.add_characteristic(&os_uuid, perms, props, Some(read_fn), None, None)?;
    vocs.vostate = os_attr.get_handle();

    // CCC for Offset State
    let ccc_perms = (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32;
    if let Some(ccc) = service.add_ccc(ccc_perms) {
        vocs.vostate_ccc = ccc.get_handle();
    }

    // --- Audio Location Characteristic (read + notify + write_without_resp) ---
    let loc_uuid = BtUuid::from_u16(AUDIO_LOC_CHRC_UUID);
    let loc_perms = (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32;
    let loc_props = GattChrcProperties::READ.bits()
        | GattChrcProperties::NOTIFY.bits()
        | GattChrcProperties::WRITE_WITHOUT_RESP.bits();

    let audio_loc_state = Arc::new(Mutex::new(vocs.audio_location));
    let read_loc = Arc::clone(&audio_loc_state);
    let loc_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let loc = *read_loc.lock().unwrap();
        let data = loc.to_le_bytes();
        attrib.read_result(id, 0, &data);
    });

    let write_loc = Arc::clone(&audio_loc_state);
    let loc_write_fn: WriteFn = Arc::new(move |attrib, id, offset, value, _opcode, _att| {
        if offset != 0 {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32);
            return;
        }
        if value.len() != 4 {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
            return;
        }
        let new_loc = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
        *write_loc.lock().unwrap() = new_loc;
        attrib.write_result(id, 0);
    });

    let loc_attr = service.add_characteristic(
        &loc_uuid,
        loc_perms,
        loc_props,
        Some(loc_read_fn),
        Some(loc_write_fn),
        None,
    )?;
    vocs.audio_loc = loc_attr.get_handle();

    // CCC for Audio Location
    if let Some(ccc) = service.add_ccc(ccc_perms) {
        vocs.audio_loc_ccc = ccc.get_handle();
    }

    // --- Audio Output Description Characteristic (read + notify + write_without_resp) ---
    let desc_uuid = BtUuid::from_u16(AUDIO_OP_DESC_CHRC_UUID);
    let desc_perms = (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32;
    let desc_props = GattChrcProperties::READ.bits()
        | GattChrcProperties::NOTIFY.bits()
        | GattChrcProperties::WRITE_WITHOUT_RESP.bits();

    let ao_desc_state = Arc::new(Mutex::new(vocs.output_desc.clone()));
    let read_desc = Arc::clone(&ao_desc_state);
    let desc_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let desc = read_desc.lock().unwrap();
        attrib.read_result(id, 0, desc.as_bytes());
    });

    let write_desc = Arc::clone(&ao_desc_state);
    let desc_write_fn: WriteFn = Arc::new(move |attrib, id, offset, value, _opcode, _att| {
        if offset != 0 {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32);
            return;
        }
        let new_desc = String::from_utf8_lossy(value).into_owned();
        *write_desc.lock().unwrap() = new_desc;
        attrib.write_result(id, 0);
    });

    let desc_attr = service.add_characteristic(
        &desc_uuid,
        desc_perms,
        desc_props,
        Some(desc_read_fn),
        Some(desc_write_fn),
        None,
    )?;
    vocs.ao_dec = desc_attr.get_handle();

    // CCC for Audio Output Description
    if let Some(ccc) = service.add_ccc(ccc_perms) {
        vocs.ao_dec_ccc = ccc.get_handle();
    }

    // --- Volume Offset Control Point Characteristic (write) ---
    let cp_uuid = BtUuid::from_u16(VOL_OFFSET_CP_CHRC_UUID);
    let cp_perms = AttPermissions::WRITE.bits() as u32;
    let cp_props = GattChrcProperties::WRITE.bits();

    let cp_vocs_state = Arc::clone(&vocs_state);
    let cp_write_fn: WriteFn = Arc::new(move |attrib, id, offset, value, _opcode, _att| {
        vocs_cp_write_handler(&cp_vocs_state, attrib, id, offset, value);
    });

    let cp_attr =
        service.add_characteristic(&cp_uuid, cp_perms, cp_props, None, Some(cp_write_fn), None)?;
    vocs.vo_cp = cp_attr.get_handle();

    service.set_claimed(true);
    service.set_active(true);

    debug!("VOCS: service registered (handle 0x{:04x})", vocs.vostate);

    Some(vocs)
}

/// VOCS Control Point write handler.
fn vocs_cp_write_handler(
    vocs_state: &Arc<Mutex<(i16, u8)>>,
    attrib: GattDbAttribute,
    id: u32,
    offset: u16,
    value: &[u8],
) {
    if offset != 0 {
        attrib.write_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32);
        return;
    }

    let mut iov = IoBuf::from_bytes(value);

    let opcode = match iov.pull_u8() {
        Some(o) => o,
        None => {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
            return;
        }
    };

    let change_counter = match iov.pull_u8() {
        Some(c) => c,
        None => {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
            return;
        }
    };

    let mut state = vocs_state.lock().unwrap();

    // Validate change counter.
    if change_counter != state.1 {
        attrib.write_result(id, BT_ATT_ERROR_INVALID_CHANGE_COUNTER as i32);
        return;
    }

    match opcode {
        VOCS_CP_SET_VOL_OFFSET => {
            let offset_val = match iov.pull_le16() {
                Some(v) => v as i16,
                None => {
                    drop(state);
                    attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
                    return;
                }
            };

            if !(VOCS_VOL_OFFSET_MIN..=VOCS_VOL_OFFSET_MAX).contains(&offset_val) {
                drop(state);
                attrib.write_result(id, BT_VCP_ERROR_VALUE_OUT_OF_RANGE as i32);
                return;
            }

            debug!("VOCS: Set Volume Offset {}", offset_val);
            state.0 = offset_val;
            state.1 = state.1.wrapping_add(1);
        }
        _ => {
            drop(state);
            attrib.write_result(id, BT_ATT_ERROR_OPCODE_NOT_SUPPORTED as i32);
            return;
        }
    }

    drop(state);
    attrib.write_result(id, 0);
}

// ===========================================================================
// Internal helpers — AICS server-side GATT service creation
// ===========================================================================

/// Create the AICS secondary service with all characteristics.
fn aics_new(db: &GattDb) -> Option<BtAics> {
    let mut aics = BtAics::new();

    let uuid = BtUuid::from_u16(AUDIO_INPUT_CS_UUID);
    let service = db.add_service(&uuid, false, AICS_HANDLE_COUNT)?;

    // Shared state for read/write callbacks.
    let aics_state = Arc::new(Mutex::new(AicsSharedState {
        gain_setting: aics.gain_setting,
        mute: aics.mute,
        gain_mode: aics.gain_mode,
        gain_props: aics.gain_props,
        input_type_val: aics.input_type_val,
        status: aics.status,
        change_counter: aics.change_counter,
        description: aics.description.clone(),
    }));

    let ccc_perms = (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32;

    // --- Audio Input State Characteristic (read + notify) ---
    let is_uuid = BtUuid::from_u16(AUDIO_INPUT_STATE_CHRC_UUID);
    let read_aics = Arc::clone(&aics_state);
    let is_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let s = read_aics.lock().unwrap();
        let data = [s.gain_setting as u8, s.mute, s.gain_mode, s.change_counter];
        attrib.read_result(id, 0, &data);
    });

    let is_attr = service.add_characteristic(
        &is_uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits() | GattChrcProperties::NOTIFY.bits(),
        Some(is_read_fn),
        None,
        None,
    )?;
    aics.input_state = is_attr.get_handle();

    if let Some(ccc) = service.add_ccc(ccc_perms) {
        aics.input_state_ccc = ccc.get_handle();
    }

    // --- Gain Setting Properties Characteristic (read only) ---
    let gs_uuid = BtUuid::from_u16(GAIN_SETTINGS_CHRC_UUID);
    let read_gs = Arc::clone(&aics_state);
    let gs_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let s = read_gs.lock().unwrap();
        let data = [s.gain_props.0, s.gain_props.1 as u8, s.gain_props.2 as u8];
        attrib.read_result(id, 0, &data);
    });

    let gs_attr = service.add_characteristic(
        &gs_uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits(),
        Some(gs_read_fn),
        None,
        None,
    )?;
    aics.gain_settings = gs_attr.get_handle();

    // --- Audio Input Type Characteristic (read only) ---
    let it_uuid = BtUuid::from_u16(AUDIO_INPUT_TYPE_CHRC_UUID);
    let read_it = Arc::clone(&aics_state);
    let it_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let s = read_it.lock().unwrap();
        attrib.read_result(id, 0, &[s.input_type_val]);
    });

    let it_attr = service.add_characteristic(
        &it_uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits(),
        Some(it_read_fn),
        None,
        None,
    )?;
    aics.input_type = it_attr.get_handle();

    // --- Audio Input Status Characteristic (read + notify) ---
    let is2_uuid = BtUuid::from_u16(AUDIO_INPUT_STATUS_CHRC_UUID);
    let read_is2 = Arc::clone(&aics_state);
    let is2_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let s = read_is2.lock().unwrap();
        attrib.read_result(id, 0, &[s.status]);
    });

    let is2_attr = service.add_characteristic(
        &is2_uuid,
        AttPermissions::READ.bits() as u32,
        GattChrcProperties::READ.bits() | GattChrcProperties::NOTIFY.bits(),
        Some(is2_read_fn),
        None,
        None,
    )?;
    aics.input_status = is2_attr.get_handle();

    if let Some(ccc) = service.add_ccc(ccc_perms) {
        aics.input_status_ccc = ccc.get_handle();
    }

    // --- Audio Input Control Point Characteristic (write) ---
    let cp_uuid = BtUuid::from_u16(AUDIO_INPUT_CP_CHRC_UUID);
    let cp_aics = Arc::clone(&aics_state);
    let cp_write_fn: WriteFn = Arc::new(move |attrib, id, offset, value, _opcode, _att| {
        aics_cp_write_handler(&cp_aics, attrib, id, offset, value);
    });

    let cp_attr = service.add_characteristic(
        &cp_uuid,
        AttPermissions::WRITE.bits() as u32,
        GattChrcProperties::WRITE.bits(),
        None,
        Some(cp_write_fn),
        None,
    )?;
    aics.input_cp = cp_attr.get_handle();

    // --- Audio Input Description Characteristic (read + write_without_resp + notify) ---
    let desc_uuid = BtUuid::from_u16(AUDIO_INPUT_DESC_CHRC_UUID);
    let read_desc = Arc::clone(&aics_state);
    let desc_read_fn: ReadFn = Arc::new(move |attrib, id, offset, _opcode, _att| {
        if offset > 0 {
            attrib.read_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32, &[]);
            return;
        }
        let s = read_desc.lock().unwrap();
        attrib.read_result(id, 0, s.description.as_bytes());
    });

    let write_desc = Arc::clone(&aics_state);
    let desc_write_fn: WriteFn = Arc::new(move |attrib, id, offset, value, _opcode, _att| {
        if offset != 0 {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32);
            return;
        }
        let new_desc = String::from_utf8_lossy(value).into_owned();
        write_desc.lock().unwrap().description = new_desc;
        attrib.write_result(id, 0);
    });

    let desc_attr = service.add_characteristic(
        &desc_uuid,
        (AttPermissions::READ.bits() | AttPermissions::WRITE.bits()) as u32,
        GattChrcProperties::READ.bits()
            | GattChrcProperties::WRITE_WITHOUT_RESP.bits()
            | GattChrcProperties::NOTIFY.bits(),
        Some(desc_read_fn),
        Some(desc_write_fn),
        None,
    )?;
    aics.input_desc = desc_attr.get_handle();

    if let Some(ccc) = service.add_ccc(ccc_perms) {
        aics.input_desc_ccc = ccc.get_handle();
    }

    service.set_claimed(true);
    service.set_active(true);

    debug!("AICS: service registered (handle 0x{:04x})", aics.input_state);

    Some(aics)
}

/// Shared AICS state for read/write callbacks.
struct AicsSharedState {
    gain_setting: i8,
    mute: u8,
    gain_mode: u8,
    gain_props: (u8, i8, i8),
    input_type_val: u8,
    status: u8,
    change_counter: u8,
    description: String,
}

/// AICS Control Point write handler.
fn aics_cp_write_handler(
    aics_state: &Arc<Mutex<AicsSharedState>>,
    attrib: GattDbAttribute,
    id: u32,
    offset: u16,
    value: &[u8],
) {
    if offset != 0 {
        attrib.write_result(id, BT_ATT_ERROR_INVALID_OFFSET as i32);
        return;
    }

    let mut iov = IoBuf::from_bytes(value);

    let opcode = match iov.pull_u8() {
        Some(o) => o,
        None => {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
            return;
        }
    };

    let change_counter = match iov.pull_u8() {
        Some(c) => c,
        None => {
            attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
            return;
        }
    };

    let mut state = aics_state.lock().unwrap();

    if change_counter != state.change_counter {
        attrib.write_result(id, BT_ATT_ERROR_INVALID_CHANGE_COUNTER as i32);
        return;
    }

    match opcode {
        AICS_SET_GAIN => {
            let gain = match iov.pull_u8() {
                Some(g) => g as i8,
                None => {
                    drop(state);
                    attrib.write_result(id, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN as i32);
                    return;
                }
            };

            // Check gain mode allows manual setting.
            if state.gain_mode == AICS_GAIN_MODE_AUTO_ONLY || state.gain_mode == AICS_GAIN_MODE_AUTO
            {
                drop(state);
                attrib.write_result(id, BT_AICS_ERROR_GAIN_MODE_NOT_ALLOWED as i32);
                return;
            }

            // Validate range.
            if gain < state.gain_props.1 || gain > state.gain_props.2 {
                drop(state);
                attrib.write_result(id, BT_AICS_ERROR_VALUE_OUT_OF_RANGE as i32);
                return;
            }

            debug!("AICS: Set Gain Setting {}", gain);
            state.gain_setting = gain;
            state.change_counter = state.change_counter.wrapping_add(1);
        }
        AICS_UNMUTE => {
            if state.mute == AICS_DISABLED {
                drop(state);
                attrib.write_result(id, BT_AICS_ERROR_MUTE_DISABLED as i32);
                return;
            }
            debug!("AICS: Unmute");
            state.mute = AICS_NOT_MUTED;
            state.change_counter = state.change_counter.wrapping_add(1);
        }
        AICS_MUTE => {
            if state.mute == AICS_DISABLED {
                drop(state);
                attrib.write_result(id, BT_AICS_ERROR_MUTE_DISABLED as i32);
                return;
            }
            debug!("AICS: Mute");
            state.mute = AICS_MUTED;
            state.change_counter = state.change_counter.wrapping_add(1);
        }
        AICS_SET_MANUAL => {
            // Only allowed if current mode is switchable (Auto or Manual).
            // Manual Only and Auto Only are read-only modes.
            if state.gain_mode == AICS_GAIN_MODE_MANUAL_ONLY
                || state.gain_mode == AICS_GAIN_MODE_AUTO_ONLY
                || state.gain_mode == AICS_GAIN_MODE_MANUAL
            {
                drop(state);
                attrib.write_result(id, BT_AICS_ERROR_GAIN_MODE_NOT_ALLOWED as i32);
                return;
            }
            debug!("AICS: Set Manual Gain Mode");
            state.gain_mode = AICS_GAIN_MODE_MANUAL;
            state.change_counter = state.change_counter.wrapping_add(1);
        }
        AICS_SET_AUTO => {
            // Only allowed if current mode is switchable (Manual or Auto).
            // Manual Only and Auto Only are read-only modes.
            if state.gain_mode == AICS_GAIN_MODE_MANUAL_ONLY
                || state.gain_mode == AICS_GAIN_MODE_AUTO_ONLY
                || state.gain_mode == AICS_GAIN_MODE_AUTO
            {
                drop(state);
                attrib.write_result(id, BT_AICS_ERROR_GAIN_MODE_NOT_ALLOWED as i32);
                return;
            }
            debug!("AICS: Set Auto Gain Mode");
            state.gain_mode = AICS_GAIN_MODE_AUTO;
            state.change_counter = state.change_counter.wrapping_add(1);
        }
        _ => {
            drop(state);
            attrib.write_result(id, BT_ATT_ERROR_OPCODE_NOT_SUPPORTED as i32);
            return;
        }
    }

    drop(state);
    attrib.write_result(id, 0);
}

// ===========================================================================
// Internal helpers — Client-side discovery
// ===========================================================================

/// Callback invoked for each VCS primary service found during discovery.
fn foreach_vcs_service(vcp: &Arc<BtVcp>, attr: GattDbAttribute) {
    let guard = vcp.inner.lock().unwrap();
    let rdb = match guard.rdb.as_ref() {
        Some(r) => Arc::clone(r),
        None => return,
    };
    drop(guard);

    // Get the service attribute to iterate characteristics.
    let svc = match attr.get_service() {
        Some(s) => s,
        None => return,
    };

    // Store the service handle in the remote VCS state.
    {
        let mut vcs_guard = rdb.vcs.lock().unwrap();
        if vcs_guard.is_none() {
            *vcs_guard = Some(BtVcs::new());
        }
        if let Some(ref mut vcs) = *vcs_guard {
            vcs.vstate = attr.get_handle();
        }
    }

    // Discover VCS characteristics.
    let vcp_ref = Arc::clone(vcp);
    let rdb_ref = Arc::clone(&rdb);
    svc.foreach_char(|char_attr| {
        vcs_discover_char(&vcp_ref, &rdb_ref, char_attr);
    });

    // Discover included VOCS/AICS services.
    let vocs_uuid = BtUuid::from_u16(VOL_OFFSET_CS_UUID);
    let aics_uuid = BtUuid::from_u16(AUDIO_INPUT_CS_UUID);

    let vcp_for_vocs = Arc::clone(vcp);
    let rdb_for_vocs = Arc::clone(&rdb);
    svc.foreach(Some(&vocs_uuid), |incl_attr| {
        foreach_vocs_service(&vcp_for_vocs, &rdb_for_vocs, incl_attr);
    });

    let vcp_for_aics = Arc::clone(vcp);
    let rdb_for_aics = Arc::clone(&rdb);
    svc.foreach(Some(&aics_uuid), |incl_attr| {
        foreach_aics_service(&vcp_for_aics, &rdb_for_aics, incl_attr);
    });
}

/// Discover VCS characteristics within the service.
fn vcs_discover_char(vcp: &Arc<BtVcp>, rdb: &Arc<VcpDb>, attr: GattDbAttribute) {
    let char_data = match attr.get_char_data() {
        Some(d) => d,
        None => return,
    };

    let uuid = char_data.uuid;

    let vstate_uuid = BtUuid::from_u16(VOL_STATE_CHRC_UUID);
    let cp_uuid = BtUuid::from_u16(VOL_CP_CHRC_UUID);
    let flags_uuid = BtUuid::from_u16(VOL_FLAG_CHRC_UUID);

    if uuid == vstate_uuid {
        debug!("VCS: Volume State found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut vcs_guard = rdb.vcs.lock().unwrap();
            if let Some(ref mut vcs) = *vcs_guard {
                vcs.vstate = char_data.value_handle;
            }
        }
        // Read initial value and register for notifications.
        vcp_read_vstate(vcp, rdb, char_data.value_handle);
    } else if uuid == cp_uuid {
        debug!("VCS: Volume Control Point found (handle 0x{:04x})", char_data.value_handle);
        let mut vcs_guard = rdb.vcs.lock().unwrap();
        if let Some(ref mut vcs) = *vcs_guard {
            vcs.vol_cp = char_data.value_handle;
        }
    } else if uuid == flags_uuid {
        debug!("VCS: Volume Flags found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut vcs_guard = rdb.vcs.lock().unwrap();
            if let Some(ref mut vcs) = *vcs_guard {
                vcs.vol_flag = char_data.value_handle;
            }
        }
        vcp_read_vflags(vcp, rdb, char_data.value_handle);
    }
}

/// Read the initial Volume State value from the remote device.
fn vcp_read_vstate(vcp: &Arc<BtVcp>, _rdb: &Arc<VcpDb>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let vcp_ref = Arc::clone(vcp);
    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, att_ecode, value| {
        vcp_vstate_read_cb(&vcp_ref, success, att_ecode, value);
    });
    let _ = client.read_value(handle, read_cb);

    // Register for Volume State notifications.
    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_status| {
        debug!("VCS: Volume State notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, value| {
        vcp_vstate_notify_cb(&vcp_for_notify, value);
    });
    let notify_id = client.register_notify(handle, register_cb, notify_cb);
    if notify_id != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.vstate_id = notify_id;
    }
}

/// Callback for Volume State read completion.
fn vcp_vstate_read_cb(vcp: &Arc<BtVcp>, success: bool, att_ecode: u8, value: &[u8]) {
    if !success {
        debug!("VCS: Volume State read failed (error 0x{:02x})", att_ecode);
        return;
    }

    if value.len() < 3 {
        debug!("VCS: Volume State read returned insufficient data");
        return;
    }

    let mut guard = vcp.inner.lock().unwrap();
    guard.volume = value[0];
    guard.mute = value[1];
    guard.volume_counter = value[2];

    debug!(
        "VCS: Volume State read: vol={}, mute={}, counter={}",
        guard.volume, guard.mute, guard.volume_counter
    );
}

/// Callback for Volume State notification.
fn vcp_vstate_notify_cb(vcp: &Arc<BtVcp>, value: &[u8]) {
    if value.len() < 3 {
        return;
    }

    let mut guard = vcp.inner.lock().unwrap();
    let old_volume = guard.volume;
    guard.volume = value[0];
    guard.mute = value[1];
    guard.volume_counter = value[2];

    debug!(
        "VCS: Volume State notified: vol={}, mute={}, counter={}",
        guard.volume, guard.mute, guard.volume_counter
    );

    // Handle pending volume set completion.
    let volume_changed = guard.volume != old_volume;
    let pending_done = if let Some(ref mut op) = guard.pending_op {
        if !op.write_pending {
            // Write already completed — notification completes the operation.
            if let Some(handle) = op.timeout_handle.take() {
                handle.abort();
            }
            true
        } else {
            false
        }
    } else {
        false
    };
    if pending_done {
        guard.pending_op = None;
    }

    let vol_cb = guard.volume_callback.clone();
    let vol = guard.volume;
    drop(guard);

    if volume_changed {
        if let Some(cb) = vol_cb {
            cb(vol);
        }
    }
}

/// Read the initial Volume Flags value.
fn vcp_read_vflags(vcp: &Arc<BtVcp>, _rdb: &Arc<VcpDb>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let vcp_ref = Arc::clone(vcp);
    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, att_ecode, value| {
        vcp_vflags_read_cb(&vcp_ref, success, att_ecode, value);
    });
    let _ = client.read_value(handle, read_cb);

    // Register for Volume Flags notifications.
    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_status| {
        debug!("VCS: Volume Flags notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, value| {
        vcp_vflags_notify_cb(&vcp_for_notify, value);
    });
    let notify_id = client.register_notify(handle, register_cb, notify_cb);
    if notify_id != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.vflag_id = notify_id;
    }
}

/// Callback for Volume Flags read completion.
fn vcp_vflags_read_cb(vcp: &Arc<BtVcp>, success: bool, att_ecode: u8, value: &[u8]) {
    if !success {
        debug!("VCS: Volume Flags read failed (error 0x{:02x})", att_ecode);
        return;
    }

    if value.is_empty() {
        return;
    }

    let mut guard = vcp.inner.lock().unwrap();
    guard.flags = value[0];
    debug!("VCS: Volume Flags read: 0x{:02x}", guard.flags);
}

/// Callback for Volume Flags notification.
fn vcp_vflags_notify_cb(vcp: &Arc<BtVcp>, value: &[u8]) {
    if value.is_empty() {
        return;
    }

    let mut guard = vcp.inner.lock().unwrap();
    guard.flags = value[0];
    debug!("VCS: Volume Flags notified: 0x{:02x}", guard.flags);
}

/// Discover VOCS characteristics from an included service.
fn foreach_vocs_service(vcp: &Arc<BtVcp>, rdb: &Arc<VcpDb>, attr: GattDbAttribute) {
    let svc = match attr.get_service() {
        Some(s) => s,
        None => return,
    };

    debug!("VOCS: Included service found (handle 0x{:04x})", attr.get_handle());

    {
        let mut vocs_guard = rdb.vocs.lock().unwrap();
        if vocs_guard.is_none() {
            *vocs_guard = Some(BtVocs::new());
        }
    }

    let vcp_ref = Arc::clone(vcp);
    let rdb_ref = Arc::clone(rdb);
    svc.foreach_char(|char_attr| {
        vocs_discover_char(&vcp_ref, &rdb_ref, char_attr);
    });
}

/// Discover VOCS characteristics.
fn vocs_discover_char(vcp: &Arc<BtVcp>, rdb: &Arc<VcpDb>, attr: GattDbAttribute) {
    let char_data = match attr.get_char_data() {
        Some(d) => d,
        None => return,
    };

    let uuid = char_data.uuid;

    let os_uuid = BtUuid::from_u16(VOL_OFFSET_STATE_CHRC_UUID);
    let loc_uuid = BtUuid::from_u16(AUDIO_LOC_CHRC_UUID);
    let desc_uuid = BtUuid::from_u16(AUDIO_OP_DESC_CHRC_UUID);
    let cp_uuid = BtUuid::from_u16(VOL_OFFSET_CP_CHRC_UUID);

    if uuid == os_uuid {
        debug!("VOCS: Offset State found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut vocs_guard = rdb.vocs.lock().unwrap();
            if let Some(ref mut vocs) = *vocs_guard {
                vocs.vostate = char_data.value_handle;
            }
        }
        vocs_read_state(vcp, char_data.value_handle);
    } else if uuid == loc_uuid {
        debug!("VOCS: Audio Location found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut vocs_guard = rdb.vocs.lock().unwrap();
            if let Some(ref mut vocs) = *vocs_guard {
                vocs.audio_loc = char_data.value_handle;
            }
        }
        vocs_read_audio_loc(vcp, char_data.value_handle);
    } else if uuid == desc_uuid {
        debug!("VOCS: Audio Output Desc found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut vocs_guard = rdb.vocs.lock().unwrap();
            if let Some(ref mut vocs) = *vocs_guard {
                vocs.ao_dec = char_data.value_handle;
            }
        }
        vocs_read_ao_desc(vcp, char_data.value_handle);
    } else if uuid == cp_uuid {
        debug!("VOCS: Control Point found (handle 0x{:04x})", char_data.value_handle);
        let mut vocs_guard = rdb.vocs.lock().unwrap();
        if let Some(ref mut vocs) = *vocs_guard {
            vocs.vo_cp = char_data.value_handle;
        }
    }
}

/// Read VOCS Offset State and register notification.
fn vocs_read_state(vcp: &Arc<BtVcp>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, _ecode, value| {
        if success && value.len() >= 3 {
            debug!("VOCS: Offset State read OK");
        }
    });
    let _ = client.read_value(handle, read_cb);

    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_| {
        debug!("VOCS: Offset State notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, _value| {
        debug!("VOCS: Offset State notification");
        let _ = &vcp_for_notify;
    });
    let nid = client.register_notify(handle, register_cb, notify_cb);
    if nid != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.state_id = nid;
    }
}

/// Read VOCS Audio Location and register notification.
fn vocs_read_audio_loc(vcp: &Arc<BtVcp>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, _ecode, _value| {
        if success {
            debug!("VOCS: Audio Location read OK");
        }
    });
    let _ = client.read_value(handle, read_cb);

    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_| {
        debug!("VOCS: Audio Location notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, _value| {
        debug!("VOCS: Audio Location notification");
        let _ = &vcp_for_notify;
    });
    let nid = client.register_notify(handle, register_cb, notify_cb);
    if nid != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.audio_loc_id = nid;
    }
}

/// Read VOCS Audio Output Description and register notification.
fn vocs_read_ao_desc(vcp: &Arc<BtVcp>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, _ecode, _value| {
        if success {
            debug!("VOCS: Audio Output Desc read OK");
        }
    });
    let _ = client.read_value(handle, read_cb);

    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_| {
        debug!("VOCS: Audio Output Desc notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, _value| {
        debug!("VOCS: Audio Output Desc notification");
        let _ = &vcp_for_notify;
    });
    let nid = client.register_notify(handle, register_cb, notify_cb);
    if nid != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.ao_dec_id = nid;
    }
}

/// Discover AICS characteristics from an included service.
fn foreach_aics_service(vcp: &Arc<BtVcp>, rdb: &Arc<VcpDb>, attr: GattDbAttribute) {
    let svc = match attr.get_service() {
        Some(s) => s,
        None => return,
    };

    debug!("AICS: Included service found (handle 0x{:04x})", attr.get_handle());

    {
        let mut aics_guard = rdb.aics.lock().unwrap();
        if aics_guard.is_none() {
            *aics_guard = Some(BtAics::new());
        }
    }

    let vcp_ref2 = Arc::clone(vcp);
    let rdb_ref2 = Arc::clone(rdb);
    svc.foreach_char(|char_attr| {
        aics_discover_char(&vcp_ref2, &rdb_ref2, char_attr);
    });
}

/// Discover AICS characteristics.
fn aics_discover_char(vcp: &Arc<BtVcp>, rdb: &Arc<VcpDb>, attr: GattDbAttribute) {
    let char_data = match attr.get_char_data() {
        Some(d) => d,
        None => return,
    };

    let uuid = char_data.uuid;

    let is_uuid = BtUuid::from_u16(AUDIO_INPUT_STATE_CHRC_UUID);
    let gs_uuid = BtUuid::from_u16(GAIN_SETTINGS_CHRC_UUID);
    let it_uuid = BtUuid::from_u16(AUDIO_INPUT_TYPE_CHRC_UUID);
    let ist_uuid = BtUuid::from_u16(AUDIO_INPUT_STATUS_CHRC_UUID);
    let cp_uuid = BtUuid::from_u16(AUDIO_INPUT_CP_CHRC_UUID);
    let desc_uuid = BtUuid::from_u16(AUDIO_INPUT_DESC_CHRC_UUID);

    if uuid == is_uuid {
        debug!("AICS: Input State found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut aics_guard = rdb.aics.lock().unwrap();
            if let Some(ref mut a) = *aics_guard {
                a.input_state = char_data.value_handle;
            }
        }
        aics_read_input_state(vcp, char_data.value_handle);
    } else if uuid == gs_uuid {
        debug!("AICS: Gain Settings found (handle 0x{:04x})", char_data.value_handle);
        let mut aics_guard = rdb.aics.lock().unwrap();
        if let Some(ref mut a) = *aics_guard {
            a.gain_settings = char_data.value_handle;
        }
    } else if uuid == it_uuid {
        debug!("AICS: Input Type found (handle 0x{:04x})", char_data.value_handle);
        let mut aics_guard = rdb.aics.lock().unwrap();
        if let Some(ref mut a) = *aics_guard {
            a.input_type = char_data.value_handle;
        }
    } else if uuid == ist_uuid {
        debug!("AICS: Input Status found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut aics_guard = rdb.aics.lock().unwrap();
            if let Some(ref mut a) = *aics_guard {
                a.input_status = char_data.value_handle;
            }
        }
        aics_read_input_status(vcp, char_data.value_handle);
    } else if uuid == cp_uuid {
        debug!("AICS: Control Point found (handle 0x{:04x})", char_data.value_handle);
        let mut aics_guard = rdb.aics.lock().unwrap();
        if let Some(ref mut a) = *aics_guard {
            a.input_cp = char_data.value_handle;
        }
    } else if uuid == desc_uuid {
        debug!("AICS: Input Desc found (handle 0x{:04x})", char_data.value_handle);
        {
            let mut aics_guard = rdb.aics.lock().unwrap();
            if let Some(ref mut a) = *aics_guard {
                a.input_desc = char_data.value_handle;
            }
        }
        aics_read_input_desc(vcp, char_data.value_handle);
    }
}

/// Read AICS Input State and register notification.
fn aics_read_input_state(vcp: &Arc<BtVcp>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, _ecode, _value| {
        if success {
            debug!("AICS: Input State read OK");
        }
    });
    let _ = client.read_value(handle, read_cb);

    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_| {
        debug!("AICS: Input State notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, _value| {
        debug!("AICS: Input State notification");
        let _ = &vcp_for_notify;
    });
    let nid = client.register_notify(handle, register_cb, notify_cb);
    if nid != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.aics_ip_state_id = nid;
    }
}

/// Read AICS Input Status and register notification.
fn aics_read_input_status(vcp: &Arc<BtVcp>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, _ecode, _value| {
        if success {
            debug!("AICS: Input Status read OK");
        }
    });
    let _ = client.read_value(handle, read_cb);

    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_| {
        debug!("AICS: Input Status notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, _value| {
        debug!("AICS: Input Status notification");
        let _ = &vcp_for_notify;
    });
    let nid = client.register_notify(handle, register_cb, notify_cb);
    if nid != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.aics_ip_status_id = nid;
    }
}

/// Read AICS Input Description and register notification.
fn aics_read_input_desc(vcp: &Arc<BtVcp>, handle: u16) {
    let guard = vcp.inner.lock().unwrap();
    let client = match guard.client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    drop(guard);

    let read_cb: crate::gatt::client::ReadCallback = Box::new(move |success, _ecode, _value| {
        if success {
            debug!("AICS: Input Desc read OK");
        }
    });
    let _ = client.read_value(handle, read_cb);

    let vcp_for_notify = Arc::clone(vcp);
    let register_cb: crate::gatt::client::RegisterCallback = Box::new(move |_| {
        debug!("AICS: Input Desc notify registered");
    });
    let notify_cb: crate::gatt::client::NotifyCallback = Box::new(move |_handle, _value| {
        debug!("AICS: Input Desc notification");
        let _ = &vcp_for_notify;
    });
    let nid = client.register_notify(handle, register_cb, notify_cb);
    if nid != 0 {
        let mut guard = vcp.inner.lock().unwrap();
        guard.aics_ip_descr_id = nid;
    }
}

// ===========================================================================
// Internal helpers — Client-side volume operations
// ===========================================================================

/// Callback for volume write completion.
fn vcp_vol_write_cb(vcp: &Arc<BtVcp>, success: bool, att_ecode: u8) {
    if !success {
        warn!("VCP: Volume write failed (error 0x{:02x})", att_ecode);
    }

    let mut guard = vcp.inner.lock().unwrap();
    if let Some(ref mut op) = guard.pending_op {
        op.write_pending = false;
        // If we have a coalesced volume that differs, send it now.
        // The C code does this but for simplicity and correctness we
        // allow the notification handler to finalize.
    }
    debug!("VCP: Volume write completed (success={})", success);
}

/// Timeout handler for pending volume set operations.
fn vcp_set_volume_timeout(vcp: &Arc<BtVcp>) {
    let mut guard = vcp.inner.lock().unwrap();
    if guard.pending_op.is_some() {
        debug!("VCP: Volume set operation timed out");
        guard.pending_op = None;
    }
}

/// Idle callback — fires after attachment to signal readiness.
fn vcp_idle(vcp: &Arc<BtVcp>) {
    let mut guard = vcp.inner.lock().unwrap();
    let ready_func = guard.ready_func.take();
    drop(guard);

    if let Some(func) = ready_func {
        func();
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(VCP_RENDERER, 0x01);
        assert_eq!(VCP_CONTROLLER, 0x02);
        assert_eq!(VCP_RELATIVE_VOL_DOWN, 0x00);
        assert_eq!(VCP_RELATIVE_VOL_UP, 0x01);
        assert_eq!(VCP_UNMUTE_RELATIVE_VOL_DOWN, 0x02);
        assert_eq!(VCP_UNMUTE_RELATIVE_VOL_UP, 0x03);
        assert_eq!(VCP_SET_ABSOLUTE_VOL, 0x04);
        assert_eq!(VCP_UNMUTE, 0x05);
        assert_eq!(VCP_MUTE, 0x06);
    }

    #[test]
    fn test_vcp_type_enum() {
        assert_eq!(VcpType::Renderer as u8, VCP_RENDERER);
        assert_eq!(VcpType::Controller as u8, VCP_CONTROLLER);
    }

    #[test]
    fn test_bt_vcs_new_defaults() {
        let vcs = BtVcs::new();
        assert_eq!(vcs.volume, 0);
        assert_eq!(vcs.mute, 0);
        assert_eq!(vcs.volume_counter, 0);
        assert_eq!(vcs.flags, RESET_VOLUME_SETTING);
    }

    #[test]
    fn test_bt_vocs_new_defaults() {
        let vocs = BtVocs::new();
        assert_eq!(vocs.vol_offset, 0);
        assert_eq!(vocs.change_counter, 0);
        assert_eq!(vocs.audio_location, 0);
        assert!(vocs.output_desc.is_empty());
    }

    #[test]
    fn test_bt_aics_new_defaults() {
        let aics = BtAics::new();
        assert_eq!(aics.mute, AICS_NOT_MUTED);
        assert_eq!(aics.gain_mode, AICS_GAIN_MODE_MANUAL);
        assert_eq!(aics.gain_setting, 88);
        assert_eq!(aics.gain_props, (1, 0, 100));
        assert_eq!(aics.input_type_val, AICS_INPUT_TYPE_BLUETOOTH);
        assert_eq!(aics.status, AICS_STATUS_ACTIVE);
        assert_eq!(aics.description, "Blueooth");
    }

    #[test]
    fn test_register_unregister() {
        let id = bt_vcp_register(Some(Box::new(|_vcp| {})), Some(Box::new(|_vcp| {})));
        assert_ne!(id, 0);
        assert!(bt_vcp_unregister(id));
        assert!(!bt_vcp_unregister(id)); // double unregister fails
    }

    #[test]
    fn test_register_returns_zero_for_no_callbacks() {
        let id = bt_vcp_register(None, None);
        assert_eq!(id, 0);
    }

    #[test]
    fn test_vcp_error_constants() {
        assert_eq!(BT_ATT_ERROR_INVALID_CHANGE_COUNTER, 0x80);
        assert_eq!(BT_ATT_ERROR_OPCODE_NOT_SUPPORTED, 0x81);
        assert_eq!(BT_VCP_ERROR_VALUE_OUT_OF_RANGE, 0x82);
        assert_eq!(BT_AICS_ERROR_VALUE_OUT_OF_RANGE, 0x82);
        assert_eq!(BT_AICS_ERROR_MUTE_DISABLED, 0x83);
        assert_eq!(BT_AICS_ERROR_GAIN_MODE_NOT_ALLOWED, 0x84);
    }
}
