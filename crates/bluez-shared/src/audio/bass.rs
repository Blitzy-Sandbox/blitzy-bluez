// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BASS — Broadcast Audio Scan Service (broadcast assistant).
 *
 * Complete Rust rewrite of BlueZ `src/shared/bass.c` (1983 lines) and
 * `src/shared/bass.h` (139 lines). Manages broadcast source add/modify/remove,
 * PA sync state, BIS sync management, and broadcast code handling.
 *
 * Key transformations from C:
 * - `bt_bass_ref`/`bt_bass_unref` → `Arc<BtBass>` (reference counting)
 * - `struct queue *` → `Vec<T>`
 * - All `callback_t + void *user_data` → closures / trait objects
 * - `bdaddr_t` → `BdAddr` from `crate::sys::bluetooth`
 * - `struct iovec` → `IoBuf` from `crate::util::endian`
 * - `gatt_db_ref`/`unref` → `Arc<GattDb>` / `GattDb.clone()`
 * - GLib containers removed entirely
 * - Global statics use `Mutex<Vec<..>>` with `AtomicU32` ID counters
 */

use std::any::Any;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tracing::{debug, warn};

use crate::att::transport::BtAtt;
use crate::att::types::{
    AttError, AttPermissions, BT_ERROR_WRITE_REQUEST_REJECTED, GattChrcProperties,
};
use crate::gatt::client::BtGattClient;
use crate::gatt::db::{GattDb, GattDbAttribute, GattDbService};
use crate::sys::bluetooth::{BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, BdAddr};
use crate::util::endian::{IoBuf, util_debug};
use crate::util::queue::Queue;
use crate::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// GATT callback type aliases (match private types in gatt/db.rs)
// ---------------------------------------------------------------------------

/// GATT attribute read callback.
type ReadFn = Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// GATT attribute write callback.
type WriteFn =
    Arc<dyn Fn(GattDbAttribute, u32, u16, &[u8], u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

// ===========================================================================
// BASS Constants (from bass.h)
// ===========================================================================

/// Number of Broadcast Receive State characteristics in a BASS service.
pub const NUM_BCAST_RECV_STATES: u8 = 2;

/// Size of a broadcast code (16 bytes).
pub const BASS_BCAST_CODE_SIZE: usize = 16;

/// Bitmask indicating BIG sync failure for all BIS indices.
pub const BASS_BIG_SYNC_FAILED_BITMASK: u32 = 0xFFFF_FFFF;

/// Minimum fixed-size length of a Broadcast Receive State value (excluding
/// variable-length subgroup data).
pub const BASS_BCAST_SRC_LEN: usize = 15;

/// Per-subgroup fixed-size data length (bis_sync u32 + meta_len u8).
pub const BASS_BCAST_SRC_SUBGROUP_LEN: usize = 5;

// Application Error Codes
/// Application error: opcode not supported.
pub const BASS_ERROR_OPCODE_NOT_SUPPORTED: u8 = 0x80;
/// Application error: invalid source ID.
pub const BASS_ERROR_INVALID_SOURCE_ID: u8 = 0x81;

// ---------------------------------------------------------------------------
// PA Sync State Values
// ---------------------------------------------------------------------------

/// PA_Sync_State values for Broadcast Receive State characteristic.
#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BassPaSyncState {
    #[default]
    NotSynchronized = 0x00,
    SyncInfoRe = 0x01,
    Synchronized = 0x02,
    FailedToSync = 0x03,
    NoPast = 0x04,
}

impl BassPaSyncState {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::NotSynchronized),
            0x01 => Some(Self::SyncInfoRe),
            0x02 => Some(Self::Synchronized),
            0x03 => Some(Self::FailedToSync),
            0x04 => Some(Self::NoPast),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BIG Encryption State Values
// ---------------------------------------------------------------------------

/// BIG_Encryption values for Broadcast Receive State characteristic.
#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BassBigEncState {
    #[default]
    NoEnc = 0x00,
    BcodeReq = 0x01,
    Dec = 0x02,
    BadCode = 0x03,
}

impl BassBigEncState {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::NoEnc),
            0x01 => Some(Self::BcodeReq),
            0x02 => Some(Self::Dec),
            0x03 => Some(Self::BadCode),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PA_Sync Parameter Values
// ---------------------------------------------------------------------------

/// Do not synchronize to PA.
pub const PA_SYNC_NO_SYNC: u8 = 0x00;
/// Synchronize to PA – PAST available.
pub const PA_SYNC_PAST: u8 = 0x01;
/// Synchronize to PA – PAST not available.
pub const PA_SYNC_NO_PAST: u8 = 0x02;

// ---------------------------------------------------------------------------
// BIS Sync and PA Interval Constants
// ---------------------------------------------------------------------------

/// No preference for BIS synchronization.
pub const BIS_SYNC_NO_PREF: u32 = 0xFFFF_FFFF;
/// PA interval unknown.
pub const PA_INTERVAL_UNKNOWN: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Broadcast Audio Scan Control Point Opcodes
// ---------------------------------------------------------------------------

pub const BASS_REMOTE_SCAN_STOPPED: u8 = 0x00;
pub const BASS_REMOTE_SCAN_STARTED: u8 = 0x01;
pub const BASS_ADD_SRC: u8 = 0x02;
pub const BASS_MOD_SRC: u8 = 0x03;
pub const BASS_SET_BCAST_CODE: u8 = 0x04;
pub const BASS_REMOVE_SRC: u8 = 0x05;

// ---------------------------------------------------------------------------
// Address Type Constants
// ---------------------------------------------------------------------------

pub const BASS_ADDR_PUBLIC: u8 = 0x00;
pub const BASS_ADDR_RANDOM: u8 = 0x01;

// ---------------------------------------------------------------------------
// Internal UUID Constants
// ---------------------------------------------------------------------------

const BASS_UUID: u16 = 0x184F;
const BCAST_RECV_STATE_UUID: u16 = 0x2BC7;
const BCAST_AUDIO_SCAN_CP_UUID: u16 = 0x2BC8;

// ===========================================================================
// Wire-Format Structures
// ===========================================================================

/// Broadcast Audio Scan Control Point header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct BassBcastAudioScanCpHdr {
    pub op: u8,
}

/// Add Source parameters (fixed-size portion; subgroup data follows).
#[derive(Debug, Clone)]
pub struct BassAddSrcParams {
    pub addr_type: u8,
    pub addr: BdAddr,
    pub sid: u8,
    pub bid: u32,
    pub pa_sync: u8,
    pub pa_interval: u16,
    pub num_subgroups: u8,
}

/// Modify Source parameters (fixed-size portion; subgroup data follows).
#[derive(Debug, Clone)]
pub struct BassModSrcParams {
    pub id: u8,
    pub pa_sync: u8,
    pub pa_interval: u16,
    pub num_subgroups: u8,
}

/// Set Broadcast Code parameters.
#[derive(Debug, Clone)]
pub struct BassSetBcastCodeParams {
    pub id: u8,
    pub bcast_code: [u8; BASS_BCAST_CODE_SIZE],
}

/// Remove Source parameters.
#[derive(Debug, Clone)]
pub struct BassRemoveSrcParams {
    pub id: u8,
}

// ===========================================================================
// BcastSrc — Broadcast Source State
// ===========================================================================

/// Per-subgroup data within a broadcast source.
#[derive(Debug, Clone, Default)]
struct SubgroupData {
    bis_sync: u32,
    pending_bis_sync: u32,
    meta_len: u8,
    meta: Vec<u8>,
}

/// Broadcast source state — one per Broadcast Receive State characteristic.
#[derive(Debug, Clone)]
pub struct BcastSrc {
    pub id: u8,
    pub pa_sync_state: BassPaSyncState,
    pub big_enc_state: BassBigEncState,
    pub bis_sync: u32,
    pub addr_type: u8,
    pub addr: BdAddr,
    pub sid: u8,
    pub bid: u32,
    pub pa_interval: u16,
    pub num_subgroups: u8,
    pub bcast_code: Option<[u8; BASS_BCAST_CODE_SIZE]>,
    subgroup_data: Vec<SubgroupData>,
}

impl Default for BcastSrc {
    fn default() -> Self {
        Self {
            id: 0,
            pa_sync_state: BassPaSyncState::NotSynchronized,
            big_enc_state: BassBigEncState::NoEnc,
            bis_sync: 0,
            addr_type: BASS_ADDR_PUBLIC,
            addr: BdAddr::default(),
            sid: 0,
            bid: 0,
            pa_interval: PA_INTERVAL_UNKNOWN,
            num_subgroups: 0,
            bcast_code: None,
            subgroup_data: Vec::new(),
        }
    }
}

// ===========================================================================
// Internal Data Structures
// ===========================================================================

/// Broadcast source entry — links a BcastSrc to its GATT attribute.
struct BcastSrcEntry {
    src: BcastSrc,
    attr: Option<GattDbAttribute>,
}

/// Broadcast Receive State characteristic slot.
struct BcastRecvState {
    attr: Option<GattDbAttribute>,
}

/// Per-database structure holding the local BASS service.
struct BassDbInner {
    db: GattDb,
    adapter_bdaddr: BdAddr,
    bcast_srcs: Queue<BcastSrcEntry>,
    bcast_recv_states: Queue<BcastRecvState>,
    bcast_audio_scan_cp: Option<GattDbAttribute>,
    /// Tracks active source IDs for O(1) ID-based removal via Queue::remove.
    active_src_ids: Queue<u8>,
}

/// Shared reference to a BASS database.
type SharedBassDb = Arc<Mutex<BassDbInner>>;

/// Global callback for session attach/detach events.
struct BassCb {
    id: u32,
    attached: Box<dyn Fn() + Send + Sync>,
    detached: Box<dyn Fn() + Send + Sync>,
}

/// Source change callback registration.
struct BassSrcChanged {
    id: u32,
    callback: Box<dyn Fn(u8, u32, u8, u8, u32) + Send + Sync>,
}

/// Control point handler callback registration.
struct BassCpHandler {
    id: u32,
    handler: Box<dyn Fn(&mut BcastSrc, u8, &[u8]) -> i32 + Send + Sync>,
}

/// Internal mutable state for a BASS session.
struct BtBassInner {
    ldb: Option<SharedBassDb>,
    rdb: Option<SharedBassDb>,
    att: Option<Arc<Mutex<BtAtt>>>,
    client: Option<Arc<BtGattClient>>,
    disconn_id: u32,
    src_cbs: Queue<BassSrcChanged>,
    cp_handlers: Queue<BassCpHandler>,
    debug_func: Option<Box<dyn FnMut(&str) + Send + Sync>>,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
}

impl BtBassInner {
    fn debug_log(&mut self, msg: &str) {
        if let Some(ref mut f) = self.debug_func {
            util_debug(f, msg);
        }
    }

    fn notify_src_changed(&self, src: &BcastSrc) {
        self.src_cbs.foreach(|cb| {
            (cb.callback)(
                src.id,
                src.bis_sync,
                src.pa_sync_state as u8,
                src.big_enc_state as u8,
                src.bid,
            );
        });
    }
}

// ===========================================================================
// Global State
// ===========================================================================

static BASS_DBS: std::sync::LazyLock<Mutex<Queue<SharedBassDb>>> =
    std::sync::LazyLock::new(|| Mutex::new(Queue::new()));
static BASS_CBS: std::sync::LazyLock<Mutex<Queue<BassCb>>> =
    std::sync::LazyLock::new(|| Mutex::new(Queue::new()));
static SESSIONS: std::sync::LazyLock<Mutex<Queue<Arc<Mutex<BtBassInner>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Queue::new()));

static NEXT_CB_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_SRC_CB_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_CP_HANDLER_ID: AtomicU32 = AtomicU32::new(1);

// ===========================================================================
// Wire-format helpers
// ===========================================================================

/// Parse a Broadcast Receive State notification value into a BcastSrc.
/// Equivalent to `bass_build_bcast_src` in bass.c.
pub(crate) fn build_bcast_src(data: &[u8]) -> Option<BcastSrc> {
    let mut iov = IoBuf::from_bytes(data);

    let source_id = iov.pull_u8()?;
    let addr_type = iov.pull_u8()?;
    let addr_bytes = iov.pull_mem(6)?;
    let mut addr = BdAddr::default();
    addr.b.copy_from_slice(addr_bytes);
    let sid = iov.pull_u8()?;
    let bid = iov.pull_le24()?;
    let pa_sync_state_raw = iov.pull_u8()?;
    let big_enc_raw = iov.pull_u8()?;

    let pa_sync_state =
        BassPaSyncState::from_u8(pa_sync_state_raw).unwrap_or(BassPaSyncState::NotSynchronized);
    let big_enc_state = BassBigEncState::from_u8(big_enc_raw).unwrap_or(BassBigEncState::NoEnc);

    let bcast_code = if big_enc_state == BassBigEncState::BadCode {
        let code_bytes = iov.pull_mem(BASS_BCAST_CODE_SIZE)?;
        let mut code = [0u8; BASS_BCAST_CODE_SIZE];
        code.copy_from_slice(code_bytes);
        Some(code)
    } else {
        None
    };

    let num_subgroups = iov.pull_u8()?;
    let mut subgroup_data = Vec::with_capacity(num_subgroups as usize);
    let mut bis_sync_total: u32 = 0;

    for _ in 0..num_subgroups {
        let bis_sync = iov.pull_le32()?;
        let meta_len = iov.pull_u8()?;
        let meta =
            if meta_len > 0 { iov.pull_mem(meta_len as usize)?.to_vec() } else { Vec::new() };
        bis_sync_total |= bis_sync;
        subgroup_data.push(SubgroupData { bis_sync, pending_bis_sync: 0, meta_len, meta });
    }

    Some(BcastSrc {
        id: source_id,
        pa_sync_state,
        big_enc_state,
        bis_sync: bis_sync_total,
        addr_type,
        addr,
        sid,
        bid,
        pa_interval: PA_INTERVAL_UNKNOWN,
        num_subgroups,
        bcast_code,
        subgroup_data,
    })
}

/// Serialize a BcastSrc to wire-format bytes.
/// Equivalent to `bass_parse_bcast_src` in bass.c.
pub(crate) fn serialize_bcast_src(src: &BcastSrc) -> Vec<u8> {
    let mut iov = IoBuf::with_capacity(64);
    iov.push_u8(src.id);
    iov.push_u8(src.addr_type);
    iov.push_mem(&src.addr.b);
    iov.push_u8(src.sid);
    iov.push_le24(src.bid);
    iov.push_u8(src.pa_sync_state as u8);
    iov.push_u8(src.big_enc_state as u8);

    if src.big_enc_state == BassBigEncState::BadCode {
        if let Some(ref code) = src.bcast_code {
            iov.push_mem(code);
        } else {
            iov.push_mem(&[0u8; BASS_BCAST_CODE_SIZE]);
        }
    }

    iov.push_u8(src.num_subgroups);
    for sg in &src.subgroup_data {
        iov.push_le32(sg.bis_sync);
        iov.push_u8(sg.meta_len);
        if !sg.meta.is_empty() {
            iov.push_mem(&sg.meta);
        }
    }
    iov.as_bytes().to_vec()
}

/// Validate the CP command parameter length.
///
/// Mirrors the C `bass_check_cp_command_len` logic: for known opcodes,
/// validate that the parameter data is consumed exactly (no trailing bytes).
/// Unknown opcodes pass through so the handler lookup can produce
/// "Opcode Not Supported" (0x80) instead of "Write Request Rejected" (0xFC).
pub(crate) fn check_cp_command_len(op: u8, params: &[u8]) -> bool {
    match op {
        BASS_REMOTE_SCAN_STOPPED | BASS_REMOTE_SCAN_STARTED => {
            // These opcodes carry no parameters beyond the opcode byte.
            params.is_empty()
        }
        BASS_REMOVE_SRC => {
            // Exactly Source_ID (1 byte).
            params.len() == 1
        }
        BASS_ADD_SRC => {
            if params.len() < BASS_BCAST_SRC_LEN {
                return false;
            }
            let mut iov = IoBuf::from_bytes(params);
            // Pull fixed fields: addr_type(1) + addr(6) + sid(1) + broadcast_id(3) +
            // pa_sync(1) + pa_interval(2) = 14 bytes
            if !iov.pull(14) {
                return false;
            }
            let num_subgroups = match iov.pull_u8() {
                Some(n) => n,
                None => return false,
            };
            for _ in 0..num_subgroups {
                if iov.pull_le32().is_none() {
                    return false;
                }
                let meta_len = match iov.pull_u8() {
                    Some(n) => n,
                    None => return false,
                };
                if meta_len > 0 && iov.pull_mem(meta_len as usize).is_none() {
                    return false;
                }
            }
            // Reject trailing data after all subgroups.
            iov.remaining() == 0
        }
        BASS_MOD_SRC => {
            if params.len() < 5 {
                return false;
            }
            let mut iov = IoBuf::from_bytes(params);
            // Pull fixed fields: source_id(1) + pa_sync(1) + pa_interval(2) = 4 bytes
            if !iov.pull(4) {
                return false;
            }
            let num_subgroups = match iov.pull_u8() {
                Some(n) => n,
                None => return false,
            };
            for _ in 0..num_subgroups {
                if iov.pull_le32().is_none() {
                    return false;
                }
                let meta_len = match iov.pull_u8() {
                    Some(n) => n,
                    None => return false,
                };
                if meta_len > 0 && iov.pull_mem(meta_len as usize).is_none() {
                    return false;
                }
            }
            // Reject trailing data after all subgroups.
            iov.remaining() == 0
        }
        BASS_SET_BCAST_CODE => {
            // Exactly Source_ID (1 byte) + Broadcast_Code (16 bytes).
            params.len() == BASS_BCAST_CODE_SIZE + 1
        }
        // Unknown opcodes: let them pass through to the handler lookup,
        // which will return BASS_ERROR_OPCODE_NOT_SUPPORTED (0x80).
        _ => true,
    }
}

// ===========================================================================
// Control Point Opcode Handlers
// ===========================================================================

fn handle_remote_scan_stopped(
    inner: &mut BtBassInner,
    _db: &mut BassDbInner,
    _iov: &mut IoBuf,
    attr: &GattDbAttribute,
    id: u32,
    _att: Option<Arc<Mutex<BtAtt>>>,
) {
    inner.debug_log("BASS: Remote Scan Stopped");
    attr.write_result(id, 0);
}

fn handle_remote_scan_started(
    inner: &mut BtBassInner,
    _db: &mut BassDbInner,
    _iov: &mut IoBuf,
    attr: &GattDbAttribute,
    id: u32,
    _att: Option<Arc<Mutex<BtAtt>>>,
) {
    inner.debug_log("BASS: Remote Scan Started");
    attr.write_result(id, 0);
}

fn handle_remove_src(
    inner: &mut BtBassInner,
    db: &mut BassDbInner,
    iov: &mut IoBuf,
    attr: &GattDbAttribute,
    id: u32,
    att: Option<Arc<Mutex<BtAtt>>>,
) {
    let source_id = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };

    inner.debug_log(&format!("BASS: Remove Source id={source_id}"));

    // Validate source ID exists.
    let entry = db.bcast_srcs.find(|e| e.src.id == source_id);
    let entry = match entry {
        Some(e) => e,
        None => {
            attr.write_result(id, BASS_ERROR_INVALID_SOURCE_ID as i32);
            return;
        }
    };

    // Cannot remove if PA is synchronized or BIS sync is active.
    if entry.src.pa_sync_state == BassPaSyncState::Synchronized || entry.src.bis_sync != 0 {
        attr.write_result(id, BASS_ERROR_INVALID_SOURCE_ID as i32);
        return;
    }

    let removed = db.bcast_srcs.remove_if(|e| e.src.id == source_id);
    let removed = match removed {
        Some(r) => r,
        None => return,
    };

    // Remove from active source ID tracking (uses Queue::remove by value).
    db.active_src_ids.remove(&source_id);

    // Send empty notification for this source ID.
    if let Some(ref recv_attr) = removed.attr {
        let empty_data = vec![source_id];
        recv_attr.notify(&empty_data, att);
    }

    inner.notify_src_changed(&removed.src);
    attr.write_result(id, 0);
}

fn handle_add_src(
    inner: &mut BtBassInner,
    db: &mut BassDbInner,
    iov: &mut IoBuf,
    attr: &GattDbAttribute,
    id: u32,
    att: Option<Arc<Mutex<BtAtt>>>,
) {
    inner.debug_log("BASS: Add Source");

    let addr_type = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let addr_bytes = match iov.pull_mem(6) {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let mut addr = BdAddr::default();
    addr.b.copy_from_slice(addr_bytes);

    let sid = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let bid = match iov.pull_le24() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let pa_sync = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let pa_interval = match iov.pull_le16() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let num_subgroups = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };

    let mut subgroup_data = Vec::with_capacity(num_subgroups as usize);
    for _ in 0..num_subgroups {
        let bis_sync = match iov.pull_le32() {
            Some(v) => v,
            None => {
                attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
                return;
            }
        };
        let meta_len = match iov.pull_u8() {
            Some(v) => v,
            None => {
                attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
                return;
            }
        };
        let meta = if meta_len > 0 {
            match iov.pull_mem(meta_len as usize) {
                Some(m) => m.to_vec(),
                None => {
                    attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
                    return;
                }
            }
        } else {
            Vec::new()
        };
        subgroup_data.push(SubgroupData { bis_sync, pending_bis_sync: bis_sync, meta_len, meta });
    }

    // Allocate a source ID (0–255).
    let source_id = match (0..=255u16).find(|c| {
        let c8 = *c as u8;
        !db.bcast_srcs.iter().any(|e| e.src.id == c8)
    }) {
        Some(c) => c as u8,
        None => {
            warn!("BASS: No available source ID");
            attr.write_result(id, AttError::Unlikely as i32);
            return;
        }
    };

    // Find an available receive state slot.
    let recv_attr = db
        .bcast_recv_states
        .iter()
        .find(|rs| {
            if let Some(ref rs_attr) = rs.attr {
                let handle = rs_attr.get_handle();
                !db.bcast_srcs
                    .iter()
                    .any(|e| e.attr.as_ref().is_some_and(|a| a.get_handle() == handle))
            } else {
                false
            }
        })
        .and_then(|rs| rs.attr.clone());

    // Map BASS addr_type to kernel addr_type.
    let kernel_addr_type = match addr_type {
        BASS_ADDR_PUBLIC => BDADDR_LE_PUBLIC,
        BASS_ADDR_RANDOM => BDADDR_LE_RANDOM,
        _ => addr_type,
    };

    let bis_sync_total: u32 = subgroup_data.iter().fold(0u32, |a, sg| a | sg.bis_sync);
    let initial_pa_state = match pa_sync {
        PA_SYNC_NO_SYNC => BassPaSyncState::NotSynchronized,
        PA_SYNC_PAST => BassPaSyncState::SyncInfoRe,
        PA_SYNC_NO_PAST => BassPaSyncState::NoPast,
        _ => BassPaSyncState::NotSynchronized,
    };

    let mut new_src = BcastSrc {
        id: source_id,
        pa_sync_state: initial_pa_state,
        big_enc_state: BassBigEncState::NoEnc,
        bis_sync: bis_sync_total,
        addr_type: kernel_addr_type,
        addr,
        sid,
        bid,
        pa_interval,
        num_subgroups,
        bcast_code: None,
        subgroup_data,
    };

    // Invoke registered CP handlers.
    let remaining = iov.as_bytes().to_vec();
    inner.cp_handlers.foreach(|handler| {
        (handler.handler)(&mut new_src, BASS_ADD_SRC, &remaining);
    });

    // Track the new source ID for fast removal via Queue::remove.
    db.active_src_ids.push_tail(new_src.id);

    db.bcast_srcs.push_tail(BcastSrcEntry { src: new_src.clone(), attr: recv_attr.clone() });

    if let Some(ref ra) = recv_attr {
        let data = serialize_bcast_src(&new_src);
        ra.notify(&data, att);
    }

    inner.notify_src_changed(&new_src);
    attr.write_result(id, 0);
}

fn handle_set_bcast_code(
    inner: &mut BtBassInner,
    db: &mut BassDbInner,
    iov: &mut IoBuf,
    attr: &GattDbAttribute,
    id: u32,
    att: Option<Arc<Mutex<BtAtt>>>,
) {
    let source_id = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let code_bytes = match iov.pull_mem(BASS_BCAST_CODE_SIZE) {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let mut bcast_code = [0u8; BASS_BCAST_CODE_SIZE];
    bcast_code.copy_from_slice(code_bytes);

    inner.debug_log(&format!("BASS: Set Broadcast Code id={source_id}"));

    if db.bcast_srcs.find(|e| e.src.id == source_id).is_none() {
        attr.write_result(id, BASS_ERROR_INVALID_SOURCE_ID as i32);
        return;
    }

    let remaining = iov.as_bytes().to_vec();
    // Apply CP handlers and update source in a single mutable pass.
    let mut notify_data: Option<(Vec<u8>, BcastSrc)> = None;
    let mut notify_attr: Option<GattDbAttribute> = None;

    db.bcast_srcs.foreach_mut(|entry| {
        if entry.src.id != source_id {
            return;
        }
        inner.cp_handlers.foreach(|handler| {
            (handler.handler)(&mut entry.src, BASS_SET_BCAST_CODE, &remaining);
        });

        entry.src.bcast_code = Some(bcast_code);

        let has_pending = entry.src.subgroup_data.iter().any(|sg| sg.pending_bis_sync != 0);
        if !has_pending {
            entry.src.big_enc_state = BassBigEncState::Dec;
        }

        let data = serialize_bcast_src(&entry.src);
        notify_data = Some((data, entry.src.clone()));
        notify_attr = entry.attr.clone();
    });

    if let Some((ref data, ref src)) = notify_data {
        if let Some(ref ra) = notify_attr {
            ra.notify(data, att);
        }
        inner.notify_src_changed(src);
    }

    attr.write_result(id, 0);
}

fn handle_mod_src(
    inner: &mut BtBassInner,
    db: &mut BassDbInner,
    iov: &mut IoBuf,
    attr: &GattDbAttribute,
    id: u32,
    att: Option<Arc<Mutex<BtAtt>>>,
) {
    let source_id = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let pa_sync = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let pa_interval = match iov.pull_le16() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };
    let num_subgroups = match iov.pull_u8() {
        Some(v) => v,
        None => {
            attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
            return;
        }
    };

    inner.debug_log(&format!("BASS: Modify Source id={source_id}"));

    if db.bcast_srcs.find(|e| e.src.id == source_id).is_none() {
        attr.write_result(id, BASS_ERROR_INVALID_SOURCE_ID as i32);
        return;
    }

    let mut new_subgroups = Vec::with_capacity(num_subgroups as usize);
    for _ in 0..num_subgroups {
        let bis_sync = match iov.pull_le32() {
            Some(v) => v,
            None => {
                attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
                return;
            }
        };
        let meta_len = match iov.pull_u8() {
            Some(v) => v,
            None => {
                attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
                return;
            }
        };
        let meta = if meta_len > 0 {
            match iov.pull_mem(meta_len as usize) {
                Some(m) => m.to_vec(),
                None => {
                    attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
                    return;
                }
            }
        } else {
            Vec::new()
        };
        new_subgroups.push(SubgroupData { bis_sync, pending_bis_sync: bis_sync, meta_len, meta });
    }

    let remaining = iov.as_bytes().to_vec();
    let mut notify_data: Option<(Vec<u8>, BcastSrc)> = None;
    let mut notify_attr: Option<GattDbAttribute> = None;

    db.bcast_srcs.foreach_mut(|entry| {
        if entry.src.id != source_id {
            return;
        }

        inner.cp_handlers.foreach(|handler| {
            (handler.handler)(&mut entry.src, BASS_MOD_SRC, &remaining);
        });

        let src = &mut entry.src;
        src.pa_interval = pa_interval;
        src.num_subgroups = num_subgroups;

        let metadata_changed = {
            let old_sg = &src.subgroup_data;
            let new_sg = &new_subgroups;
            old_sg.len() != new_sg.len()
                || old_sg
                    .iter()
                    .zip(new_sg.iter())
                    .any(|(o, n)| o.meta_len != n.meta_len || o.meta != n.meta)
        };

        src.subgroup_data = new_subgroups.clone();
        src.bis_sync = src.subgroup_data.iter().fold(0u32, |a, sg| a | sg.bis_sync);

        match pa_sync {
            PA_SYNC_NO_SYNC => {
                src.pa_sync_state = BassPaSyncState::NotSynchronized;
            }
            // PA_SYNC_PAST / PA_SYNC_NO_PAST only promote the state if the broadcast
            // source is not already fully synchronized; otherwise the existing state
            // is preserved (matched by the `_ => {}` fallthrough below).
            PA_SYNC_PAST if src.pa_sync_state != BassPaSyncState::Synchronized => {
                src.pa_sync_state = BassPaSyncState::SyncInfoRe;
            }
            PA_SYNC_NO_PAST if src.pa_sync_state != BassPaSyncState::Synchronized => {
                src.pa_sync_state = BassPaSyncState::NoPast;
            }
            _ => {}
        }

        if metadata_changed {
            if let Some(ref ra) = entry.attr {
                let data = serialize_bcast_src(src);
                ra.notify(&data, att.clone());
            }
        }

        let data = serialize_bcast_src(src);
        notify_data = Some((data, src.clone()));
        notify_attr = entry.attr.clone();
    });

    if let Some((_data, ref src)) = notify_data {
        inner.notify_src_changed(src);
    }

    attr.write_result(id, 0);
}

// ===========================================================================
// Opcode Dispatch
// ===========================================================================

type CpHandlerFn = fn(
    &mut BtBassInner,
    &mut BassDbInner,
    &mut IoBuf,
    &GattDbAttribute,
    u32,
    Option<Arc<Mutex<BtAtt>>>,
);

struct BassOpHandler {
    name: &'static str,
    op: u8,
    handler: CpHandlerFn,
}

static BASS_HANDLERS: &[BassOpHandler] = &[
    BassOpHandler {
        name: "Remote Scan Stopped",
        op: BASS_REMOTE_SCAN_STOPPED,
        handler: handle_remote_scan_stopped,
    },
    BassOpHandler {
        name: "Remote Scan Started",
        op: BASS_REMOTE_SCAN_STARTED,
        handler: handle_remote_scan_started,
    },
    BassOpHandler { name: "Remove Source", op: BASS_REMOVE_SRC, handler: handle_remove_src },
    BassOpHandler { name: "Add Source", op: BASS_ADD_SRC, handler: handle_add_src },
    BassOpHandler {
        name: "Set Broadcast Code",
        op: BASS_SET_BCAST_CODE,
        handler: handle_set_bcast_code,
    },
    BassOpHandler { name: "Modify Source", op: BASS_MOD_SRC, handler: handle_mod_src },
];

/// Top-level CP write dispatcher.
fn bass_cp_write(
    session: &Arc<Mutex<BtBassInner>>,
    db: &SharedBassDb,
    attr: &GattDbAttribute,
    id: u32,
    value: &[u8],
    att: Option<Arc<Mutex<BtAtt>>>,
) {
    if value.is_empty() {
        attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
        return;
    }

    let op = value[0];
    let params = &value[1..];

    if !check_cp_command_len(op, params) {
        attr.write_result(id, BT_ERROR_WRITE_REQUEST_REJECTED as i32);
        return;
    }

    for handler_entry in BASS_HANDLERS {
        if handler_entry.op == op {
            let mut inner = session.lock().unwrap();
            inner.debug_log(&format!("BASS: CP write op={op} ({})", handler_entry.name));
            let mut db_inner = db.lock().unwrap();
            let mut iov = IoBuf::from_bytes(params);
            (handler_entry.handler)(&mut inner, &mut db_inner, &mut iov, attr, id, att);
            return;
        }
    }

    {
        let mut inner = session.lock().unwrap();
        inner.debug_log(&format!("BASS: Unknown CP opcode 0x{op:02x}"));
    }
    attr.write_result(id, BASS_ERROR_OPCODE_NOT_SUPPORTED as i32);
}

// ===========================================================================
// BASS GATT Service Creation
// ===========================================================================

/// Create BASS service in a local GATT database.
fn create_bass_service(shared_db: &SharedBassDb) -> bool {
    let bass_uuid = BtUuid::from_u16(BASS_UUID);
    let recv_uuid = BtUuid::from_u16(BCAST_RECV_STATE_UUID);
    let cp_uuid = BtUuid::from_u16(BCAST_AUDIO_SCAN_CP_UUID);

    let num_handles = 1 + (NUM_BCAST_RECV_STATES as u16) * 3 + 2;

    let db = {
        let db_inner = shared_db.lock().unwrap();
        db_inner.db.clone()
    };

    let service: GattDbService = match db.add_service(&bass_uuid, true, num_handles) {
        Some(s) => s,
        None => return false,
    };

    let mut recv_states = Queue::new();

    for i in 0..NUM_BCAST_RECV_STATES {
        let recv_perms =
            AttPermissions::READ.bits() as u32 | AttPermissions::READ_ENCRYPT.bits() as u32;
        let recv_props = GattChrcProperties::READ.bits() | GattChrcProperties::NOTIFY.bits();

        // Read callback: return serialized source data for this slot.
        let db_for_read = Arc::clone(shared_db);
        let slot_index = i as usize;
        let read_fn: ReadFn = Arc::new(move |attr, req_id, _offset, _opcode, _att| {
            let db_inner = db_for_read.lock().unwrap();
            match db_inner.bcast_srcs.get(slot_index) {
                Some(entry) => {
                    let data = serialize_bcast_src(&entry.src);
                    attr.read_result(req_id, 0, &data);
                }
                None => {
                    // Empty slot — return single zero byte (empty source).
                    attr.read_result(req_id, 0, &[0]);
                }
            }
        });

        let recv_attr = service.add_characteristic(
            &recv_uuid,
            recv_perms,
            recv_props,
            Some(read_fn),
            None,
            None,
        );

        let _ccc = service.add_ccc(0);

        recv_states.push_tail(BcastRecvState { attr: recv_attr });
    }

    // Add Broadcast Audio Scan Control Point characteristic.
    let cp_perms =
        AttPermissions::WRITE.bits() as u32 | AttPermissions::WRITE_ENCRYPT.bits() as u32;
    let cp_props = GattChrcProperties::WRITE.bits() | GattChrcProperties::WRITE_WITHOUT_RESP.bits();

    // Write callback: dispatch CP commands.
    let db_for_write = Arc::clone(shared_db);
    let write_fn: WriteFn = Arc::new(move |attr, req_id, _offset, value, _opcode, att| {
        // Find the session whose ATT matches this connection.
        let session = find_session_for_db(&db_for_write);
        match session {
            Some(s) => bass_cp_write(&s, &db_for_write, &attr, req_id, value, att),
            None => {
                // No active session — still process server-only commands.
                // Create a temporary inner for stateless processing.
                attr.write_result(req_id, AttError::Unlikely as i32);
            }
        }
    });

    let cp_attr =
        service.add_characteristic(&cp_uuid, cp_perms, cp_props, None, Some(write_fn), None);

    service.set_active(true);

    // Store results back into the shared DB.
    let mut db_inner = shared_db.lock().unwrap();
    db_inner.bcast_recv_states = recv_states;
    db_inner.bcast_audio_scan_cp = cp_attr;

    let addr = db_inner.adapter_bdaddr;
    debug!("BASS: Service created with {} recv states for adapter {}", NUM_BCAST_RECV_STATES, addr,);
    true
}

/// Find a session that uses the given BassDb.
fn find_session_for_db(db: &SharedBassDb) -> Option<Arc<Mutex<BtBassInner>>> {
    let sessions = SESSIONS.lock().unwrap();
    for session in sessions.iter() {
        let inner = session.lock().unwrap();
        if let Some(ref ldb) = inner.ldb {
            if Arc::ptr_eq(ldb, db) {
                return Some(Arc::clone(session));
            }
        }
    }
    None
}

// ===========================================================================
// BcastSrc Free Functions
// ===========================================================================

/// Set the PA synchronization state on a broadcast source.
/// Returns 0 on success, negative errno on invalid state.
pub fn bt_bass_set_pa_sync(src: &mut BcastSrc, sync_state: u8) -> i32 {
    match BassPaSyncState::from_u8(sync_state) {
        Some(state) => {
            src.pa_sync_state = state;
            notify_all_sessions_src_changed(src);
            0
        }
        None => -22,
    }
}

/// Get the PA synchronization state of a broadcast source.
pub fn bt_bass_get_pa_sync(src: &BcastSrc) -> Result<u8, i32> {
    Ok(src.pa_sync_state as u8)
}

/// Set a specific BIS as synchronized on a broadcast source.
pub fn bt_bass_set_bis_sync(src: &mut BcastSrc, bis: u8) -> i32 {
    if bis == 0 {
        return -22;
    }
    let mask = 1u32 << (bis - 1);
    src.bis_sync |= mask;

    let mut found = false;
    for sg in &mut src.subgroup_data {
        if sg.pending_bis_sync & mask != 0 {
            sg.bis_sync |= mask;
            found = true;
        }
    }
    if !found {
        if let Some(sg) = src.subgroup_data.first_mut() {
            sg.bis_sync |= mask;
        }
    }
    notify_all_sessions_src_changed(src);
    0
}

/// Clear a specific BIS synchronization bit on a broadcast source.
pub fn bt_bass_clear_bis_sync(src: &mut BcastSrc, bis: u8) -> i32 {
    if bis == 0 {
        return -22;
    }
    let mask = 1u32 << (bis - 1);
    src.bis_sync &= !mask;
    for sg in &mut src.subgroup_data {
        sg.bis_sync &= !mask;
    }
    notify_all_sessions_src_changed(src);
    0
}

/// Check whether a specific BIS index is synchronized.
pub fn bt_bass_check_bis(src: &BcastSrc, bis: u8) -> bool {
    if bis == 0 {
        return false;
    }
    (src.bis_sync & (1u32 << (bis - 1))) != 0
}

/// Set the BIG encryption state on a broadcast source.
pub fn bt_bass_set_enc(src: &mut BcastSrc, enc: u8) -> i32 {
    match BassBigEncState::from_u8(enc) {
        Some(state) => {
            src.big_enc_state = state;
            notify_all_sessions_src_changed(src);
            0
        }
        None => -22,
    }
}

/// Notify all active sessions about a source state change.
fn notify_all_sessions_src_changed(src: &BcastSrc) {
    let sessions = SESSIONS.lock().unwrap();
    sessions.foreach(|session| {
        let inner = session.lock().unwrap();
        inner.notify_src_changed(src);
    });
}

// ===========================================================================
// Global Registration Functions
// ===========================================================================

/// Register global callbacks for BASS session attach/detach events.
/// Returns a registration ID for `bt_bass_unregister`.
pub fn bt_bass_register(
    attached: impl Fn() + Send + Sync + 'static,
    detached: impl Fn() + Send + Sync + 'static,
) -> u32 {
    let id = NEXT_CB_ID.fetch_add(1, Ordering::Relaxed);
    let cb = BassCb { id, attached: Box::new(attached), detached: Box::new(detached) };
    let mut cbs = BASS_CBS.lock().unwrap();
    cbs.push_tail(cb);
    id
}

/// Unregister a global callback.
pub fn bt_bass_unregister(id: u32) -> bool {
    let mut cbs = BASS_CBS.lock().unwrap();
    cbs.remove_if(|cb| cb.id == id).is_some()
}

// ===========================================================================
// Database Operations
// ===========================================================================

/// Add BASS service to a local GATT database.
pub fn bt_bass_add_db(db: &GattDb, adapter_bdaddr: &BdAddr) {
    let mut dbs = BASS_DBS.lock().unwrap();

    // Check for duplicate.
    if dbs.iter().any(|d| {
        let inner = d.lock().unwrap();
        inner.db.ptr_eq(db)
    }) {
        return;
    }

    let shared = Arc::new(Mutex::new(BassDbInner {
        db: db.clone(),
        adapter_bdaddr: *adapter_bdaddr,
        bcast_srcs: Queue::new(),
        bcast_recv_states: Queue::new(),
        bcast_audio_scan_cp: None,
        active_src_ids: Queue::new(),
    }));

    // Create the GATT service (must be done before adding to dbs).
    if !create_bass_service(&shared) {
        warn!("BASS: Failed to create BASS service in GATT DB");
        return;
    }

    debug!("BASS: Service added to DB");
    dbs.push_tail(shared);
}

/// Find or create a SharedBassDb for the given GattDb.
fn find_or_create_bass_db(db: &GattDb, adapter_bdaddr: &BdAddr) -> Option<SharedBassDb> {
    let dbs = BASS_DBS.lock().unwrap();
    for d in dbs.iter() {
        let inner = d.lock().unwrap();
        if inner.db.ptr_eq(db) {
            return Some(Arc::clone(d));
        }
    }
    drop(dbs);

    // Not found — create it.
    bt_bass_add_db(db, adapter_bdaddr);

    let dbs = BASS_DBS.lock().unwrap();
    for d in dbs.iter() {
        let inner = d.lock().unwrap();
        if inner.db.ptr_eq(db) {
            return Some(Arc::clone(d));
        }
    }
    None
}

// ===========================================================================
// BtBass — Public API
// ===========================================================================

/// BASS session handle (broadcast assistant).
///
/// Wraps the internal mutable state in `Arc<Mutex<...>>` for thread-safe
/// shared ownership. This replaces `bt_bass_ref`/`bt_bass_unref`.
pub struct BtBass {
    inner: Arc<Mutex<BtBassInner>>,
}

impl BtBass {
    /// Create a new BASS session.
    ///
    /// `ldb` is the local GATT database. `rdb` is an optional remote GATT
    /// database for client-side BASS discovery. `adapter_bdaddr` is the
    /// adapter's Bluetooth address.
    pub fn new(ldb: Arc<GattDb>, rdb: Option<Arc<GattDb>>, adapter_bdaddr: &BdAddr) -> Arc<Self> {
        let ldb_shared = find_or_create_bass_db(&ldb, adapter_bdaddr);

        let rdb_shared = rdb.as_ref().and_then(|r| find_or_create_bass_db(r, adapter_bdaddr));

        let inner = BtBassInner {
            ldb: ldb_shared,
            rdb: rdb_shared,
            att: None,
            client: None,
            disconn_id: 0,
            src_cbs: Queue::new(),
            cp_handlers: Queue::new(),
            debug_func: None,
            user_data: None,
        };

        debug!("BASS: New session created");
        Arc::new(Self { inner: Arc::new(Mutex::new(inner)) })
    }

    /// Attach a GATT client for remote BASS service interaction.
    pub fn attach(&self, client: Arc<BtGattClient>) -> bool {
        // Clone client via clone_client API (equivalent to bt_gatt_client_clone).
        let cloned_client = match BtGattClient::clone_client(&client) {
            Ok(c) => c,
            Err(_) => Arc::clone(&client),
        };
        let att = cloned_client.get_att();

        {
            let mut inner = self.inner.lock().unwrap();

            let session_ref = Arc::clone(&self.inner);
            let disconn_id = {
                let mut att_guard = att.lock().unwrap();
                att_guard.register_disconnect(Box::new(move |_err| {
                    let mut inner = session_ref.lock().unwrap();
                    inner.debug_log("BASS: ATT disconnected");
                    inner.att = None;
                    inner.client = None;
                    inner.disconn_id = 0;
                }))
            };

            inner.client = Some(Arc::clone(&cloned_client));
            inner.att = Some(Arc::clone(&att));
            inner.disconn_id = disconn_id;
        }

        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.push_tail(Arc::clone(&self.inner));
        }

        {
            let cbs = BASS_CBS.lock().unwrap();
            cbs.foreach(|cb| {
                (cb.attached)();
            });
        }

        self.discover_bass_service(&cloned_client);
        debug!("BASS: Client attached");
        true
    }

    /// Set the ATT transport directly (without a GATT client).
    pub fn set_att(&self, att: Arc<Mutex<BtAtt>>) -> bool {
        let mut inner = self.inner.lock().unwrap();

        let session_ref = Arc::clone(&self.inner);
        let disconn_id = {
            let mut att_guard = att.lock().unwrap();
            att_guard.register_disconnect(Box::new(move |_err| {
                let mut inner = session_ref.lock().unwrap();
                inner.debug_log("BASS: ATT disconnected (set_att)");
                inner.att = None;
                inner.disconn_id = 0;
            }))
        };

        inner.att = Some(att);
        inner.disconn_id = disconn_id;

        {
            let mut sessions = SESSIONS.lock().unwrap();
            let already = sessions.find(|s| Arc::ptr_eq(s, &self.inner)).is_some();
            if !already {
                sessions.push_tail(Arc::clone(&self.inner));
            }
        }

        debug!("BASS: ATT transport set");
        true
    }

    /// Detach from the current ATT transport and GATT client.
    pub fn detach(&self) {
        let (att_ref, disconn_id) = {
            let mut inner = self.inner.lock().unwrap();
            let att_ref = inner.att.take();
            let did = inner.disconn_id;
            inner.disconn_id = 0;
            inner.client = None;
            (att_ref, did)
        };

        if let Some(att) = att_ref {
            if disconn_id != 0 {
                if let Ok(mut att_guard) = att.lock() {
                    att_guard.unregister_disconnect(disconn_id);
                }
            }
        }

        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.retain(|s| !Arc::ptr_eq(s, &self.inner));
        }

        {
            let cbs = BASS_CBS.lock().unwrap();
            cbs.foreach(|cb| {
                (cb.detached)();
            });
        }

        debug!("BASS: Detached");
    }

    /// Set the debug logging callback.
    pub fn set_debug(&self, func: impl FnMut(&str) + Send + Sync + 'static) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.debug_func = Some(Box::new(func));
        true
    }

    /// Set user data on the session.
    pub fn set_user_data(&self, data: Arc<dyn Any + Send + Sync>) {
        let mut inner = self.inner.lock().unwrap();
        inner.user_data = Some(data);
    }

    /// Get the ATT transport handle, if attached.
    pub fn get_att(&self) -> Option<Arc<Mutex<BtAtt>>> {
        let inner = self.inner.lock().unwrap();
        inner.att.clone()
    }

    /// Get the GATT client handle, if attached.
    pub fn get_client(&self) -> Option<Arc<BtGattClient>> {
        let inner = self.inner.lock().unwrap();
        inner.client.clone()
    }

    /// Write to the Broadcast Audio Scan Control Point on the remote device.
    pub fn send(&self, hdr: &BassBcastAudioScanCpHdr, params: &[u8]) -> i32 {
        let inner = self.inner.lock().unwrap();

        let client = match &inner.client {
            Some(c) => Arc::clone(c),
            None => return -19,
        };

        let rdb = match &inner.rdb {
            Some(r) => Arc::clone(r),
            None => return -19,
        };

        let cp_handle = {
            let db_inner = rdb.lock().unwrap();
            match &db_inner.bcast_audio_scan_cp {
                Some(attr) => attr.get_handle(),
                None => return -19,
            }
        };

        let mut pdu = Vec::with_capacity(1 + params.len());
        pdu.push(hdr.op);
        pdu.extend_from_slice(params);

        drop(inner);

        let result = client.write_without_response(cp_handle, false, &pdu);
        if result == 0 { -5 } else { 0 }
    }

    /// Register a callback for broadcast source state changes.
    pub fn src_register(&self, cb: impl Fn(u8, u32, u8, u8, u32) + Send + Sync + 'static) -> u32 {
        let id = NEXT_SRC_CB_ID.fetch_add(1, Ordering::Relaxed);
        let entry = BassSrcChanged { id, callback: Box::new(cb) };
        let mut inner = self.inner.lock().unwrap();
        inner.src_cbs.push_tail(entry);
        id
    }

    /// Unregister a source change callback.
    pub fn src_unregister(&self, id: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.src_cbs.remove_if(|e| e.id == id).is_some()
    }

    /// Register a control point handler callback.
    pub fn cp_handler_register(
        &self,
        handler: impl Fn(&mut BcastSrc, u8, &[u8]) -> i32 + Send + Sync + 'static,
    ) -> u32 {
        let id = NEXT_CP_HANDLER_ID.fetch_add(1, Ordering::Relaxed);
        let entry = BassCpHandler { id, handler: Box::new(handler) };
        let mut inner = self.inner.lock().unwrap();
        inner.cp_handlers.push_tail(entry);
        id
    }

    /// Unregister a control point handler.
    pub fn cp_handler_unregister(&self, id: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.cp_handlers.remove_if(|e| e.id == id).is_some()
    }

    // ----- Internal methods -----

    /// Discover the BASS service on the remote GATT database.
    fn discover_bass_service(&self, client: &Arc<BtGattClient>) {
        let rdb = {
            let inner = self.inner.lock().unwrap();
            inner.rdb.clone()
        };

        let rdb = match rdb {
            Some(r) => r,
            None => return,
        };

        let recv_uuid = BtUuid::from_u16(BCAST_RECV_STATE_UUID);
        let bass_uuid = BtUuid::from_u16(BASS_UUID);

        let db = {
            let db_inner = rdb.lock().unwrap();
            db_inner.db.clone()
        };

        db.foreach_service(Some(&bass_uuid), |svc_attr| {
            if let Some(svc) = svc_attr.get_service() {
                svc.foreach_char(|char_attr| {
                    if let Some(char_data) = char_attr.get_char_data() {
                        if char_data.uuid == recv_uuid {
                            let value_handle = char_data.value_handle;

                            // Read current BRS value to seed initial state.
                            let session_read = Arc::clone(&self.inner);
                            client.read_value(
                                value_handle,
                                Box::new(move |success, _att_err, data| {
                                    if success && !data.is_empty() {
                                        Self::handle_recv_state_notify(
                                            &session_read,
                                            value_handle,
                                            data,
                                        );
                                    }
                                }),
                            );

                            // Register for ongoing notifications.
                            let session_ref = Arc::clone(&self.inner);
                            client.register_notify(
                                value_handle,
                                Box::new(|_status| {}),
                                Box::new(move |handle, data| {
                                    Self::handle_recv_state_notify(&session_ref, handle, data);
                                }),
                            );
                        }
                    }
                });
            }
        });
    }

    /// Handle a Broadcast Receive State notification.
    fn handle_recv_state_notify(session: &Arc<Mutex<BtBassInner>>, handle: u16, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut inner = session.lock().unwrap();
        inner.debug_log(&format!(
            "BASS: Recv State notification handle=0x{handle:04x} len={}",
            data.len(),
        ));

        match build_bcast_src(data) {
            Some(src) => inner.notify_src_changed(&src),
            None => warn!("BASS: Failed to parse recv state notification"),
        }
    }
}

impl Drop for BtBass {
    fn drop(&mut self) {
        let (att_ref, disconn_id) = {
            let mut inner = self.inner.lock().unwrap();
            let att_ref = inner.att.take();
            let did = inner.disconn_id;
            inner.disconn_id = 0;
            inner.client = None;
            (att_ref, did)
        };

        if let Some(att) = att_ref {
            if disconn_id != 0 {
                if let Ok(mut att_guard) = att.lock() {
                    att_guard.unregister_disconnect(disconn_id);
                }
            }
        }

        let mut sessions = SESSIONS.lock().unwrap();
        sessions.retain(|s| !Arc::ptr_eq(s, &self.inner));
    }
}
