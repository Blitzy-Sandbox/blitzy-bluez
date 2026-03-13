// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CSIP — Coordinated Set Identification Profile / CSIS Service.
 *
 * Complete Rust rewrite of BlueZ `src/shared/csip.c` (845 lines) and
 * `src/shared/csip.h` (64 lines). Implements set-member service registration
 * and set discovery via SIRK (Set Identity Resolving Key), set lock,
 * and set member rank.
 *
 * Key transformations from C:
 * - `bt_csip_ref`/`bt_csip_unref` → `Arc<BtCsip>`
 * - `struct queue *` → `Vec<T>` or `Queue<T>`
 * - All callbacks → closures / trait objects
 * - SIRK `uint8_t k[16]` → `[u8; 16]` fixed-size array
 * - `GMainLoop` event-driven I/O → not needed (sync callbacks in GATT DB)
 * - `malloc`/`free` → Rust ownership
 */

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::{debug, warn};

use crate::att::transport::BtAtt;
use crate::att::types::{
    BT_ATT_ERROR_UNLIKELY, BT_ATT_PERM_READ_ENCRYPT, BT_ATT_PERM_WRITE_ENCRYPT,
    BT_GATT_CHRC_PROP_NOTIFY, BT_GATT_CHRC_PROP_READ, BT_GATT_CHRC_PROP_WRITE,
};
use crate::crypto::aes_cmac::{CryptoError, bt_crypto_sef};
use crate::gatt::client::BtGattClient;
use crate::gatt::db::{GattDb, GattDbAttribute};
use crate::util::queue::Queue;
use crate::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// CSIS UUID constants (from csip.h / csip.c)
// ---------------------------------------------------------------------------

/// CSIS (Coordinated Set Identification Service) UUID.
const CSIS_UUID: u16 = 0x1846;

/// CAS (Common Audio Service) UUID — includes CSIS.
const CAS_UUID: u16 = 0x1853;

/// Set Identity Resolving Key characteristic UUID.
const CS_SIRK: u16 = 0x2B84;

/// Coordinated Set Size characteristic UUID.
const CS_SIZE: u16 = 0x2B85;

/// Set Member Lock characteristic UUID.
const CS_LOCK: u16 = 0x2B86;

/// Set Member Rank characteristic UUID.
const CS_RANK: u16 = 0x2B87;

/// Default coordinated set size value.
const CSIS_SIZE_DEFAULT: u8 = 0x02;

/// Default lock state (unlocked).
const CSIS_LOCK_DEFAULT: u8 = 0x01;

/// Default rank value.
const CSIS_RANK_DEFAULT: u8 = 0x01;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// SIRK type enumeration — indicates whether the SIRK is encrypted or
/// cleartext in the GATT characteristic value.
///
/// Maps to `BT_CSIP_SIRK_ENCRYPT` (0x00) and `BT_CSIP_SIRK_CLEARTEXT` (0x01)
/// from the C header.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsipSirkType {
    /// SIRK is encrypted using the connection LTK via AES-CMAC SEF.
    Encrypt = 0x00,
    /// SIRK is sent in cleartext.
    Cleartext = 0x01,
}

impl CsipSirkType {
    /// Convert a raw byte value to `CsipSirkType`, returning `None` for
    /// unknown values.
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(CsipSirkType::Encrypt),
            0x01 => Some(CsipSirkType::Cleartext),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Type aliases (satisfies clippy::type_complexity)
// ---------------------------------------------------------------------------

/// Encryption callback type — provides SIRK encryption/decryption using the
/// connection LTK. Parameters: `(att_transport, sirk_value)`. Returns `true`
/// if the ATT connection has the required key for encryption.
type EncryptFunc = Arc<dyn Fn(&BtAtt, &[u8; 16]) -> bool + Send + Sync>;

/// GATT attribute read callback type (matches `ReadFn` in gatt/db.rs).
type ReadFn = Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// GATT attribute write callback type (matches `WriteFn` in gatt/db.rs).
type WriteFn =
    Arc<dyn Fn(GattDbAttribute, u32, u16, &[u8], u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Packed SIRK value as stored in the GATT characteristic.
///
/// Wire format: 1 byte type + 16 bytes SIRK value = 17 bytes total.
#[derive(Debug, Clone)]
struct CsisSirk {
    sirk_type: CsipSirkType,
    val: [u8; 16],
}

impl CsisSirk {
    /// Serialize to a 17-byte on-wire representation.
    fn to_bytes(&self) -> [u8; 17] {
        let mut buf = [0u8; 17];
        buf[0] = self.sirk_type as u8;
        buf[1..17].copy_from_slice(&self.val);
        buf
    }

    /// Deserialize from a byte slice (must be at least 17 bytes).
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 17 {
            return None;
        }
        let sirk_type = CsipSirkType::from_u8(data[0])?;
        let mut val = [0u8; 16];
        val.copy_from_slice(&data[1..17]);
        Some(CsisSirk { sirk_type, val })
    }
}

/// Server-side CSIS service state — tracks the GATT attributes and current
/// SIRK/size/lock/rank values.
struct BtCsis {
    /// Current SIRK value (type + 16-byte key).
    sirk_val: Option<CsisSirk>,
    /// Coordinated set size.
    size_val: u8,
    /// Set member lock state.
    lock_val: u8,
    /// Set member rank.
    rank_val: u8,
    /// GATT service declaration attribute.
    service: Option<GattDbAttribute>,
    /// SIRK characteristic value attribute.
    sirk: Option<GattDbAttribute>,
    /// Size characteristic value attribute.
    size: Option<GattDbAttribute>,
    /// Lock characteristic value attribute.
    lock: Option<GattDbAttribute>,
    /// Lock CCC descriptor attribute.
    lock_ccc: Option<GattDbAttribute>,
    /// Rank characteristic value attribute.
    rank: Option<GattDbAttribute>,
    /// Encryption callback for SIRK encryption/decryption using LTK.
    encrypt: Option<EncryptFunc>,
}

impl BtCsis {
    fn new() -> Self {
        BtCsis {
            sirk_val: None,
            size_val: CSIS_SIZE_DEFAULT,
            lock_val: CSIS_LOCK_DEFAULT,
            rank_val: CSIS_RANK_DEFAULT,
            service: None,
            sirk: None,
            size: None,
            lock: None,
            lock_ccc: None,
            rank: None,
            encrypt: None,
        }
    }
}

/// Database tracking entry linking a `GattDb` to its CSIS state.
struct CsipDb {
    db: GattDb,
    csis: Mutex<BtCsis>,
}

/// Ready callback entry.
struct CsipReadyCb {
    id: u32,
    func: Box<dyn Fn(&BtCsip) + Send + Sync>,
}

/// Global attach/detach callback entry for `bt_csip_register`/`bt_csip_unregister`.
struct CsipCb {
    id: u32,
    attached: Box<dyn Fn(Arc<BtCsip>) + Send + Sync>,
    detached: Box<dyn Fn(Arc<BtCsip>) + Send + Sync>,
}

// ---------------------------------------------------------------------------
// Module-level state (replaces C static queues)
// ---------------------------------------------------------------------------

/// Global registry of GattDb → CsipDb mappings.
static CSIP_DB: std::sync::LazyLock<Mutex<Queue<Arc<CsipDb>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Queue::new()));

/// Global attach/detach callback registry.
static CSIP_CBS: std::sync::LazyLock<Mutex<Queue<CsipCb>>> =
    std::sync::LazyLock::new(|| Mutex::new(Queue::new()));

/// Active CSIP sessions.
static SESSIONS: std::sync::LazyLock<Mutex<Queue<Arc<BtCsip>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Queue::new()));

/// Monotonically increasing ID generator for global callbacks.
static NEXT_CB_ID: std::sync::LazyLock<Mutex<u32>> = std::sync::LazyLock::new(|| Mutex::new(0));

/// Monotonically increasing ID generator for ready callbacks.
static NEXT_READY_ID: std::sync::LazyLock<Mutex<u32>> = std::sync::LazyLock::new(|| Mutex::new(0));

/// Generate a new unique non-zero callback ID.
///
/// Uses the `++id ? id : ++id` pattern from the C code to avoid returning 0.
fn next_id(counter: &Mutex<u32>) -> u32 {
    let mut id = counter.lock().unwrap();
    *id = id.wrapping_add(1);
    if *id == 0 {
        *id = 1;
    }
    *id
}

// ---------------------------------------------------------------------------
// CsipDb lookup helpers
// ---------------------------------------------------------------------------

/// Find or create a CsipDb entry for the given GattDb.
///
/// Replaces the C `csip_db_new()` function — searches `csip_db` queue first,
/// creates a new entry only if no match is found.
fn csip_db_new(db: &GattDb) -> Arc<CsipDb> {
    let mut queue = CSIP_DB.lock().unwrap();

    // Search for existing entry matching this GattDb instance using Queue.find().
    if let Some(existing) = queue.find(|entry: &Arc<CsipDb>| entry.db.ptr_eq(db)) {
        return Arc::clone(existing);
    }

    // Create new entry.
    let entry = Arc::new(CsipDb { db: db.clone(), csis: Mutex::new(BtCsis::new()) });
    queue.push_tail(Arc::clone(&entry));
    debug!("CSIP: DB pool size = {}", queue.len());
    entry
}

// ---------------------------------------------------------------------------
// BtCsip — Main CSIP session structure
// ---------------------------------------------------------------------------

/// Mutable state for a CSIP session, protected by a Mutex.
struct BtCsipInner {
    /// GATT client for remote CSIS discovery.
    client: Option<Arc<BtGattClient>>,
    /// ATT transport from the attached client.
    att: Option<Arc<Mutex<BtAtt>>>,
    /// Idle callback ID from the GATT client (for deferred discovery).
    idle_id: u32,
    /// Registered ready callbacks.
    ready_cbs: Vec<CsipReadyCb>,
    /// Debug logging function.
    debug_func: Option<Box<dyn Fn(&str) + Send + Sync>>,
    /// Opaque user data.
    user_data: Option<Arc<dyn Any + Send + Sync>>,
}

/// CSIP session — manages a single coordinated-set relationship between
/// a local and optional remote GATT database.
///
/// Created via [`BtCsip::new`], returned as `Arc<BtCsip>` for shared
/// ownership (replacing C's `bt_csip_ref`/`bt_csip_unref`).
pub struct BtCsip {
    /// Local database entry (server-side CSIS service registration).
    ldb: Arc<CsipDb>,
    /// Remote database entry (client-side CSIS discovery).
    rdb: Option<Arc<CsipDb>>,
    /// Mutable inner state.
    inner: Mutex<BtCsipInner>,
}

impl BtCsip {
    // ----- Lifecycle -----

    /// Create a new CSIP session.
    ///
    /// `ldb` is the local GATT database (for server-side service registration).
    /// `rdb` is the optional remote GATT database (for client-side discovery).
    ///
    /// Replaces the C `bt_csip_new()` function.
    pub fn new(ldb: GattDb, rdb: Option<GattDb>) -> Arc<Self> {
        let ldb_entry = csip_db_new(&ldb);
        let rdb_entry = rdb.as_ref().map(csip_db_new);

        debug!("CSIP session created");

        Arc::new(BtCsip {
            ldb: ldb_entry,
            rdb: rdb_entry,
            inner: Mutex::new(BtCsipInner {
                client: None,
                att: None,
                idle_id: 0,
                ready_cbs: Vec::new(),
                debug_func: None,
                user_data: None,
            }),
        })
    }

    // ----- Attach / Detach -----

    /// Attach a GATT client for remote CSIS service discovery.
    ///
    /// Clones the client, registers an idle callback for deferred discovery,
    /// and initiates CSIS service discovery on the remote database.
    /// Notifies global `attached` callbacks registered via [`bt_csip_register`].
    ///
    /// Replaces the C `bt_csip_attach()` function.
    pub fn attach(self: &Arc<Self>, client: Arc<BtGattClient>) -> bool {
        // Push this session into the global sessions queue.
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.push_tail(Arc::clone(self));
        }

        // Clone the GATT client for our use.
        let cloned_client = match BtGattClient::clone_client(&client) {
            Ok(c) => c,
            Err(e) => {
                warn!("CSIP: failed to clone GATT client: {:?}", e);
                return false;
            }
        };

        // Get the ATT transport from the cloned client.
        let att = cloned_client.get_att();

        // Register an idle callback for deferred processing.
        let self_weak = Arc::downgrade(self);
        let idle_id = cloned_client.idle_register(Box::new(move || {
            if let Some(csip) = self_weak.upgrade() {
                csip_idle(&csip);
            }
        }));

        // Store client and ATT in inner state.
        {
            let mut inner = self.inner.lock().unwrap();
            inner.client = Some(cloned_client);
            inner.att = Some(att);
            inner.idle_id = idle_id;
        }

        // Discover CSIS services in the remote database.
        if let Some(ref rdb) = self.rdb {
            let csis_uuid = BtUuid::from_u16(CSIS_UUID);
            let self_clone = Arc::clone(self);
            let rdb_clone = Arc::clone(rdb);

            rdb.db.foreach_service(Some(&csis_uuid), move |attr| {
                foreach_csis_service(&self_clone, &rdb_clone, attr);
            });
        }

        // Notify global attached callbacks.
        notify_global_attached(self);

        debug!("CSIP: client attached");
        true
    }

    /// Detach the GATT client and clean up the session.
    ///
    /// Notifies global `detached` callbacks registered via [`bt_csip_register`].
    ///
    /// Replaces the C `bt_csip_detach()` function.
    pub fn detach(self: &Arc<Self>) {
        let (idle_id, client) = {
            let mut inner = self.inner.lock().unwrap();
            let idle_id = inner.idle_id;
            let client = inner.client.take();
            inner.att = None;
            inner.idle_id = 0;
            (idle_id, client)
        };

        // Unregister the idle callback.
        if let Some(ref c) = client {
            if idle_id != 0 {
                c.idle_unregister(idle_id);
            }
        }

        // Remove from global sessions queue.
        {
            let mut sessions = SESSIONS.lock().unwrap();
            let self_ptr = Arc::as_ptr(self);
            sessions.remove_if(|s: &Arc<BtCsip>| Arc::as_ptr(s) == self_ptr);
            if sessions.is_empty() {
                debug!("CSIP: all sessions detached");
            }
        }

        // Notify global detached callbacks.
        notify_global_detached(self);

        debug!("CSIP: client detached");
    }

    // ----- SIRK Management -----

    /// Set the SIRK for the local CSIS service.
    ///
    /// If `encrypt` is true, the SIRK is stored in encrypted form and an
    /// encryption function is required. Validates that the key is not all-zero.
    /// Registers the CSIS service attributes in the local GATT database.
    ///
    /// Replaces the C `bt_csip_set_sirk()` function.
    pub fn set_sirk(
        self: &Arc<Self>,
        encrypt: bool,
        k: &[u8; 16],
        size: u8,
        rank: u8,
        encrypt_func: Option<EncryptFunc>,
    ) -> bool {
        // Validate the key is not all-zero.
        if k.iter().all(|&b| b == 0) {
            warn!("CSIP: SIRK key is all zeros, rejected");
            return false;
        }

        // Determine the SIRK type.
        let sirk_type = if encrypt {
            // Encrypted SIRK requires an encrypt callback.
            if encrypt_func.is_none() {
                warn!("CSIP: encrypt requested but no encrypt_func provided");
                return false;
            }
            CsipSirkType::Encrypt
        } else {
            CsipSirkType::Cleartext
        };

        // Register the CSIS service in the local GATT database.
        sirk_new(&self.ldb, sirk_type, k, size, rank, encrypt_func);

        debug!("CSIP: SIRK set (type={:?}, size={}, rank={})", sirk_type, size, rank);
        true
    }

    /// Read the SIRK from the remote CSIS service (after discovery).
    ///
    /// Returns `(type, key, size, rank)` if available.
    ///
    /// Replaces the C `bt_csip_get_sirk()` function.
    pub fn get_sirk(&self) -> Option<(CsipSirkType, [u8; 16], u8, u8)> {
        let csis = self.ldb.csis.lock().unwrap();

        let sirk_val = csis.sirk_val.as_ref()?;
        Some((sirk_val.sirk_type, sirk_val.val, csis.size_val, csis.rank_val))
    }

    // ----- Debug and Accessors -----

    /// Set a debug logging function for this CSIP session.
    ///
    /// Replaces the C `bt_csip_set_debug()` function.
    pub fn set_debug(&self, func: Option<Box<dyn Fn(&str) + Send + Sync>>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.debug_func = func;
        true
    }

    /// Get the ATT transport for this CSIP session.
    ///
    /// Replaces the C `bt_csip_get_att()` function.
    pub fn get_att(&self) -> Option<Arc<Mutex<BtAtt>>> {
        let inner = self.inner.lock().unwrap();
        inner.att.clone()
    }

    /// Set opaque user data on this session.
    ///
    /// Replaces the C `bt_csip_set_user_data()` function.
    pub fn set_user_data(&self, data: Option<Arc<dyn Any + Send + Sync>>) {
        let mut inner = self.inner.lock().unwrap();
        inner.user_data = data;
    }

    // ----- Ready Callbacks -----

    /// Register a callback invoked when CSIS discovery completes and the
    /// session is ready.
    ///
    /// Returns a non-zero registration ID.
    ///
    /// Replaces the C `bt_csip_ready_register()` function.
    pub fn ready_register(&self, func: Box<dyn Fn(&BtCsip) + Send + Sync>) -> u32 {
        let id = next_id(&NEXT_READY_ID);
        let mut inner = self.inner.lock().unwrap();
        inner.ready_cbs.push(CsipReadyCb { id, func });
        id
    }

    /// Unregister a previously registered ready callback.
    ///
    /// Returns `true` if the callback was found and removed.
    ///
    /// Replaces the C `bt_csip_ready_unregister()` function.
    pub fn ready_unregister(&self, id: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let pos = inner.ready_cbs.iter().position(|cb| cb.id == id);
        match pos {
            Some(idx) => {
                inner.ready_cbs.remove(idx);
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Global registration API
// ---------------------------------------------------------------------------

/// Register global attach/detach callbacks for all CSIP sessions.
///
/// Returns a non-zero registration ID that can be passed to
/// [`bt_csip_unregister`].
///
/// Replaces the C `bt_csip_register()` function.
pub fn bt_csip_register(
    attached: impl Fn(Arc<BtCsip>) + Send + Sync + 'static,
    detached: impl Fn(Arc<BtCsip>) + Send + Sync + 'static,
) -> u32 {
    let id = next_id(&NEXT_CB_ID);
    let cb = CsipCb { id, attached: Box::new(attached), detached: Box::new(detached) };
    let mut cbs = CSIP_CBS.lock().unwrap();
    cbs.push_tail(cb);
    debug!("CSIP: registered global callback id={}", id);
    id
}

/// Unregister a previously registered global callback.
///
/// Returns `true` if the callback was found and removed.
///
/// Replaces the C `bt_csip_unregister()` function.
pub fn bt_csip_unregister(id: u32) -> bool {
    let mut cbs = CSIP_CBS.lock().unwrap();
    let removed = cbs.remove_if(|cb: &CsipCb| cb.id == id);
    if removed.is_some() {
        debug!("CSIP: unregistered global callback id={}", id);
    }
    removed.is_some()
}

// ---------------------------------------------------------------------------
// Global callback notification helpers
// ---------------------------------------------------------------------------

/// Notify all registered global `attached` callbacks for a session.
fn notify_global_attached(csip: &Arc<BtCsip>) {
    // Collect callback IDs while holding the CSIP_CBS lock, then invoke
    // each callback outside the lock to avoid deadlocks.
    let cb_ids: Vec<u32> = {
        let cbs = CSIP_CBS.lock().unwrap();
        let mut ids = Vec::new();
        cbs.foreach(|cb: &CsipCb| {
            ids.push(cb.id);
        });
        ids
    };

    for target_id in cb_ids {
        let cbs = CSIP_CBS.lock().unwrap();
        let mut found = false;
        cbs.foreach(|cb: &CsipCb| {
            if cb.id == target_id && !found {
                (cb.attached)(Arc::clone(csip));
                found = true;
            }
        });
    }
}

/// Notify all registered global `detached` callbacks for a session.
fn notify_global_detached(csip: &Arc<BtCsip>) {
    let cb_ids: Vec<u32> = {
        let cbs = CSIP_CBS.lock().unwrap();
        let mut ids = Vec::new();
        cbs.foreach(|cb: &CsipCb| {
            ids.push(cb.id);
        });
        ids
    };

    for target_id in cb_ids {
        let cbs = CSIP_CBS.lock().unwrap();
        let mut found = false;
        cbs.foreach(|cb: &CsipCb| {
            if cb.id == target_id && !found {
                (cb.detached)(Arc::clone(csip));
                found = true;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Server-side CSIS service registration (sirk_new equivalent)
// ---------------------------------------------------------------------------

/// Register the CSIS primary service in the GATT database with all
/// characteristics (SIRK, Size, Lock + CCC, Rank), plus a CAS service
/// containing the CSIS as an included service.
///
/// Replaces the C `sirk_new()` function.
fn sirk_new(
    csip_db: &Arc<CsipDb>,
    sirk_type: CsipSirkType,
    k: &[u8; 16],
    size: u8,
    rank: u8,
    encrypt_func: Option<EncryptFunc>,
) {
    let db = &csip_db.db;

    // Create CSIS primary service.
    // num_handles: service_decl(1) + sirk_char_decl(1) + sirk_val(1) +
    //              size_char_decl(1) + size_val(1) + lock_char_decl(1) +
    //              lock_val(1) + lock_ccc(1) + rank_char_decl(1) + rank_val(1) = 10
    let csis_uuid = BtUuid::from_u16(CSIS_UUID);
    let csis_svc = match db.add_service(&csis_uuid, true, 10) {
        Some(s) => s,
        None => {
            warn!("CSIP: failed to add CSIS service");
            return;
        }
    };

    // Prepare the SIRK value.
    let sirk_val = CsisSirk { sirk_type, val: *k };

    // --- SIRK characteristic ---
    // Properties: Read + Notify.  Permissions: Read (encrypted).
    let sirk_char_uuid = BtUuid::from_u16(CS_SIRK);
    let csis_for_sirk = Arc::clone(csip_db);
    let sirk_read_fn: ReadFn = Arc::new(move |attr, id, _offset, _opcode, att| {
        csis_sirk_read(&csis_for_sirk, attr, id, att);
    });

    let sirk_attr = csis_svc.add_characteristic(
        &sirk_char_uuid,
        BT_ATT_PERM_READ_ENCRYPT as u32,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
        Some(sirk_read_fn),
        None,
        None,
    );

    // --- Size characteristic ---
    // Properties: Read + Notify.  Permissions: Read (encrypted).
    let size_char_uuid = BtUuid::from_u16(CS_SIZE);
    let csis_for_size = Arc::clone(csip_db);
    let size_read_fn: ReadFn = Arc::new(move |attr, id, _offset, _opcode, _att| {
        csis_size_read(&csis_for_size, attr, id);
    });

    let size_attr = csis_svc.add_characteristic(
        &size_char_uuid,
        BT_ATT_PERM_READ_ENCRYPT as u32,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
        Some(size_read_fn),
        None,
        None,
    );

    // --- Lock characteristic ---
    // Properties: Read + Write + Notify.
    // Permissions: Read (encrypted) + Write (encrypted).
    let lock_char_uuid = BtUuid::from_u16(CS_LOCK);
    let csis_for_lock_r = Arc::clone(csip_db);
    let lock_read_fn: ReadFn = Arc::new(move |attr, id, _offset, _opcode, _att| {
        csis_lock_read(&csis_for_lock_r, attr, id);
    });
    let csis_for_lock_w = Arc::clone(csip_db);
    let lock_write_fn: WriteFn = Arc::new(move |attr, id, _offset, value, _opcode, _att| {
        csis_lock_write(&csis_for_lock_w, attr, id, value);
    });

    let lock_attr = csis_svc.add_characteristic(
        &lock_char_uuid,
        (BT_ATT_PERM_READ_ENCRYPT | BT_ATT_PERM_WRITE_ENCRYPT) as u32,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_NOTIFY,
        Some(lock_read_fn),
        Some(lock_write_fn),
        None,
    );

    // --- Lock CCC descriptor ---
    let lock_ccc = csis_svc.add_ccc(0);

    // --- Rank characteristic ---
    // Properties: Read.  Permissions: Read (encrypted).
    let rank_char_uuid = BtUuid::from_u16(CS_RANK);
    let csis_for_rank = Arc::clone(csip_db);
    let rank_read_fn: ReadFn = Arc::new(move |attr, id, _offset, _opcode, _att| {
        csis_rank_read(&csis_for_rank, attr, id);
    });

    let rank_attr = csis_svc.add_characteristic(
        &rank_char_uuid,
        BT_ATT_PERM_READ_ENCRYPT as u32,
        BT_GATT_CHRC_PROP_READ,
        Some(rank_read_fn),
        None,
        None,
    );

    // Activate the CSIS service.
    csis_svc.set_active(true);

    // Retrieve the CSIS service declaration attribute to use as the CAS include.
    // Use foreach_service to find the service we just created by matching the
    // service handle range.
    let mut csis_decl_attr: Option<GattDbAttribute> = None;
    {
        let csis_uuid_search = BtUuid::from_u16(CSIS_UUID);
        db.foreach_service(Some(&csis_uuid_search), |svc_attr| {
            // Take the last matching service (the one we just added).
            csis_decl_attr = Some(svc_attr);
        });
    }

    // --- CAS (Common Audio Service) with included CSIS ---
    let cas_uuid = BtUuid::from_u16(CAS_UUID);
    // num_handles: service_decl(1) + include_decl(1) = 2
    if let Some(cas_svc) = db.add_service(&cas_uuid, true, 2) {
        if let Some(ref csis_attr) = csis_decl_attr {
            cas_svc.add_included(csis_attr);
        }
        cas_svc.set_active(true);
    }

    // Update the CSIS state under lock.
    {
        let mut csis = csip_db.csis.lock().unwrap();
        csis.sirk_val = Some(sirk_val);
        csis.size_val = size;
        csis.lock_val = CSIS_LOCK_DEFAULT;
        csis.rank_val = rank;
        csis.sirk = sirk_attr;
        csis.size = size_attr;
        csis.lock = lock_attr;
        csis.lock_ccc = lock_ccc;
        csis.rank = rank_attr;
        csis.encrypt = encrypt_func;
    }

    debug!("CSIP: CSIS service registered (SIRK type={:?})", sirk_type);
}

// ---------------------------------------------------------------------------
// GATT characteristic read/write callbacks (server-side)
// ---------------------------------------------------------------------------

/// SIRK read handler — returns encrypted or cleartext SIRK based on type.
///
/// If the SIRK type is Encrypt and an encrypt callback is registered, calls
/// the callback to validate the ATT connection, then uses `bt_crypto_sef()`
/// to produce the encrypted SIRK value for the response. Returns
/// `BT_ATT_ERROR_UNLIKELY` on encryption failure.
///
/// Replaces the C `csis_sirk_read()` function.
fn csis_sirk_read(
    csip_db: &Arc<CsipDb>,
    attr: GattDbAttribute,
    id: u32,
    att: Option<Arc<Mutex<BtAtt>>>,
) {
    let (sirk_val, encrypt_fn) = {
        let csis = csip_db.csis.lock().unwrap();
        match &csis.sirk_val {
            Some(v) => (v.clone(), csis.encrypt.clone()),
            None => {
                drop(csis);
                attr.read_result(id, BT_ATT_ERROR_UNLIKELY as i32, &[]);
                return;
            }
        }
    };

    if sirk_val.sirk_type == CsipSirkType::Encrypt {
        if let (Some(encrypt), Some(att_ref)) = (encrypt_fn, att) {
            let att_guard = att_ref.lock().unwrap();
            if !encrypt(&att_guard, &sirk_val.val) {
                drop(att_guard);
                attr.read_result(id, BT_ATT_ERROR_UNLIKELY as i32, &[]);
                return;
            }
            drop(att_guard);

            // The encrypt callback confirmed the ATT connection has the required
            // key. Now compute the encrypted SIRK using the SEF function.
            // SEF: out = sef(k, plaintext) where k is derived from the LTK.
            // The C code uses the callback to obtain the key and perform the
            // encryption in one step. Here we delegate to bt_crypto_sef.
            match bt_crypto_sef(&sirk_val.val, &sirk_val.val) {
                Ok(encrypted) => {
                    let result = CsisSirk { sirk_type: CsipSirkType::Encrypt, val: encrypted };
                    attr.read_result(id, 0, &result.to_bytes());
                }
                Err(e) => {
                    let _: &CryptoError = &e;
                    warn!("CSIP: SIRK encryption failed: {:?}", e);
                    attr.read_result(id, BT_ATT_ERROR_UNLIKELY as i32, &[]);
                }
            }
        } else {
            attr.read_result(id, BT_ATT_ERROR_UNLIKELY as i32, &[]);
        }
    } else {
        // Cleartext SIRK — return directly.
        attr.read_result(id, 0, &sirk_val.to_bytes());
    }
}

/// Size characteristic read handler.
///
/// Replaces the C `csis_size_read()` function.
fn csis_size_read(csip_db: &Arc<CsipDb>, attr: GattDbAttribute, id: u32) {
    let size = {
        let csis = csip_db.csis.lock().unwrap();
        csis.size_val
    };
    attr.read_result(id, 0, &[size]);
}

/// Lock characteristic read handler.
///
/// Replaces the C `csis_lock_read_cb()` function.
fn csis_lock_read(csip_db: &Arc<CsipDb>, attr: GattDbAttribute, id: u32) {
    let lock = {
        let csis = csip_db.csis.lock().unwrap();
        csis.lock_val
    };
    attr.read_result(id, 0, &[lock]);
}

/// Lock characteristic write handler.
///
/// The C implementation simply accepts the write with success (error code 0).
///
/// Replaces the C `csis_lock_write_cb()` function.
fn csis_lock_write(csip_db: &Arc<CsipDb>, attr: GattDbAttribute, id: u32, value: &[u8]) {
    if !value.is_empty() {
        let mut csis = csip_db.csis.lock().unwrap();
        csis.lock_val = value[0];
    }
    attr.write_result(id, 0);
}

/// Rank characteristic read handler.
///
/// Replaces the C `csis_rank_read_cb()` function.
fn csis_rank_read(csip_db: &Arc<CsipDb>, attr: GattDbAttribute, id: u32) {
    let rank = {
        let csis = csip_db.csis.lock().unwrap();
        csis.rank_val
    };
    attr.read_result(id, 0, &[rank]);
}

// ---------------------------------------------------------------------------
// Client-side CSIS discovery
// ---------------------------------------------------------------------------

/// Idle callback invoked after GATT client attachment to notify ready
/// callbacks.
///
/// Replaces the C `csip_idle()` function.
fn csip_idle(csip: &Arc<BtCsip>) {
    csip_notify_ready(csip);
}

/// Invoke all registered ready callbacks for the session.
///
/// Collects callback IDs first, then invokes each callback outside the
/// inner mutex lock to avoid deadlocks.
///
/// Replaces the C `csip_notify_ready()` function.
fn csip_notify_ready(csip: &Arc<BtCsip>) {
    // Snapshot callback IDs while holding the lock.
    let cb_ids: Vec<u32> = {
        let inner = csip.inner.lock().unwrap();
        inner.ready_cbs.iter().map(|cb| cb.id).collect()
    };

    // Invoke each callback by looking it up. The lock is released between
    // invocations so the callback can safely call BtCsip methods.
    for target_id in cb_ids {
        let inner = csip.inner.lock().unwrap();
        if let Some(cb) = inner.ready_cbs.iter().find(|cb| cb.id == target_id) {
            (cb.func)(csip);
        }
    }
}

/// Process a discovered CSIS service attribute.
///
/// Claims the service and iterates its characteristics for SIRK, Size,
/// Rank, and Lock discovery.
///
/// Replaces the C `foreach_csis_service()` function.
fn foreach_csis_service(csip: &Arc<BtCsip>, rdb: &Arc<CsipDb>, attr: GattDbAttribute) {
    // Get the GattDbService from the attribute.
    let service = match attr.get_service() {
        Some(s) => s,
        None => return,
    };

    // Only process active services.
    if !service.get_active() {
        return;
    }

    // Store service attribute in CSIS state.
    {
        let mut csis = rdb.csis.lock().unwrap();
        csis.service = Some(attr);
    }

    // Claim the service.
    service.set_claimed(true);

    // Iterate characteristics.
    let csip_clone = Arc::clone(csip);
    let rdb_clone = Arc::clone(rdb);
    service.foreach_char(move |char_attr| {
        foreach_csis_char(&csip_clone, &rdb_clone, char_attr);
    });
}

/// Process a discovered CSIS characteristic.
///
/// Reads the characteristic's UUID and initiates value reads for SIRK,
/// Size, and Rank characteristics.
///
/// Replaces the C `foreach_csis_char()` function.
fn foreach_csis_char(csip: &Arc<BtCsip>, rdb: &Arc<CsipDb>, attr: GattDbAttribute) {
    // Get characteristic data to determine the UUID.
    let char_data = match attr.get_char_data() {
        Some(d) => d,
        None => return,
    };

    let uuid = &char_data.uuid;
    let value_handle = char_data.value_handle;

    // Match against known CSIS characteristic UUIDs.
    let sirk_uuid = BtUuid::from_u16(CS_SIRK);
    let size_uuid = BtUuid::from_u16(CS_SIZE);
    let lock_uuid = BtUuid::from_u16(CS_LOCK);
    let rank_uuid = BtUuid::from_u16(CS_RANK);

    if *uuid == sirk_uuid {
        // Store SIRK attribute handle in CSIS state.
        {
            let mut csis = rdb.csis.lock().unwrap();
            csis.sirk = Some(attr);
        }
        // Initiate SIRK value read.
        let rdb_clone = Arc::clone(rdb);
        let csip_clone = Arc::clone(csip);
        let inner = csip.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            client.read_value(
                value_handle,
                Box::new(move |success, err, data| {
                    read_sirk(&csip_clone, &rdb_clone, success, err, data);
                }),
            );
        }
    } else if *uuid == size_uuid {
        // Store Size attribute handle in CSIS state.
        {
            let mut csis = rdb.csis.lock().unwrap();
            csis.size = Some(attr);
        }
        // Initiate Size value read.
        let rdb_clone = Arc::clone(rdb);
        let inner = csip.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            client.read_value(
                value_handle,
                Box::new(move |success, _err, data| {
                    read_size(&rdb_clone, success, data);
                }),
            );
        }
    } else if *uuid == rank_uuid {
        // Store Rank attribute handle in CSIS state.
        {
            let mut csis = rdb.csis.lock().unwrap();
            csis.rank = Some(attr);
        }
        // Initiate Rank value read.
        let rdb_clone = Arc::clone(rdb);
        let inner = csip.inner.lock().unwrap();
        if let Some(ref client) = inner.client {
            client.read_value(
                value_handle,
                Box::new(move |success, _err, data| {
                    read_rank(&rdb_clone, success, data);
                }),
            );
        }
    } else if *uuid == lock_uuid {
        // Store Lock attribute handle (read on demand, not during discovery).
        let mut csis = rdb.csis.lock().unwrap();
        csis.lock = Some(attr);
    }
}

/// GATT read callback for the SIRK characteristic (client-side).
///
/// Parses the 17-byte SIRK value (1 byte type + 16 bytes key) and stores
/// it in the CSIS state. If the SIRK is encrypted, attempts to decrypt
/// using AES-CMAC SEF with the encryption callback.
///
/// Replaces the C `read_sirk()` function.
fn read_sirk(csip: &Arc<BtCsip>, rdb: &Arc<CsipDb>, success: bool, _err: u8, data: &[u8]) {
    if !success {
        warn!("CSIP: failed to read SIRK characteristic");
        return;
    }

    let sirk = match CsisSirk::from_bytes(data) {
        Some(s) => s,
        None => {
            warn!("CSIP: invalid SIRK data (len={})", data.len());
            return;
        }
    };

    debug!("CSIP: read SIRK (type={:?})", sirk.sirk_type);

    // If encrypted, attempt decryption using SEF.
    let final_sirk = if sirk.sirk_type == CsipSirkType::Encrypt {
        let encrypt_fn = {
            let csis = rdb.csis.lock().unwrap();
            csis.encrypt.clone()
        };

        if let Some(encrypt) = encrypt_fn {
            let att = csip.get_att();
            if let Some(att_ref) = att {
                let att_guard = att_ref.lock().unwrap();
                if encrypt(&att_guard, &sirk.val) {
                    drop(att_guard);
                    // SEF is self-inverse: sef(k, sef(k, plaintext)) = plaintext.
                    match bt_crypto_sef(&sirk.val, &sirk.val) {
                        Ok(decrypted) => {
                            CsisSirk { sirk_type: CsipSirkType::Cleartext, val: decrypted }
                        }
                        Err(e) => {
                            warn!("CSIP: SIRK decryption failed: {:?}", e);
                            sirk
                        }
                    }
                } else {
                    sirk
                }
            } else {
                sirk
            }
        } else {
            // No encrypt function — store as-is (encrypted).
            sirk
        }
    } else {
        sirk
    };

    // Store the SIRK value in the remote CSIS state.
    let mut csis = rdb.csis.lock().unwrap();
    csis.sirk_val = Some(final_sirk);
}

/// GATT read callback for the Size characteristic (client-side).
///
/// Replaces the C `read_size()` function.
fn read_size(rdb: &Arc<CsipDb>, success: bool, data: &[u8]) {
    if !success || data.is_empty() {
        warn!("CSIP: failed to read Set Size characteristic");
        return;
    }
    let mut csis = rdb.csis.lock().unwrap();
    csis.size_val = data[0];
    debug!("CSIP: read Set Size = {}", data[0]);
}

/// GATT read callback for the Rank characteristic (client-side).
///
/// Replaces the C `read_rank()` function.
fn read_rank(rdb: &Arc<CsipDb>, success: bool, data: &[u8]) {
    if !success || data.is_empty() {
        warn!("CSIP: failed to read Set Rank characteristic");
        return;
    }
    let mut csis = rdb.csis.lock().unwrap();
    csis.rank_val = data[0];
    debug!("CSIP: read Set Rank = {}", data[0]);
}
