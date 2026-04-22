// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
//! Gaming Audio Profile (GMAP) / Gaming Audio Service (GMAS).
//!
//! Implements the GMAS GATT service (server-side registration) and GMAS
//! client-side discovery.  Rust equivalent of `src/shared/gmap.c` and
//! `src/shared/gmap.h` from BlueZ v5.86.
//!
//! The module exposes role and per-role feature bitflags, a `BtGmap` struct
//! that manages GMAS sessions (both server and client modes), and a global
//! session registry keyed by ATT transport identity.

use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use bitflags::bitflags;
use tracing::{debug, warn};

use crate::att::transport::BtAtt;
use crate::att::types::{AttPermissions, GattChrcProperties};
use crate::gatt::client::BtGattClient;
use crate::gatt::db::{GattDb, GattDbAttribute, GattDbService};
use crate::util::uuid::BtUuid;

// =====================================================================
// GMAS Service and Characteristic UUIDs (Bluetooth SIG Assigned Numbers)
// =====================================================================

/// GMAS (Gaming Audio Service) primary service UUID.
const GMAS_UUID: u16 = 0x1858;

/// GMAP Role characteristic UUID.
const GMAP_ROLE_CHRC_UUID: u16 = 0x2C00;

/// UGG (Unicast Game Gateway) Feature characteristic UUID.
const GMAP_UGG_CHRC_UUID: u16 = 0x2C01;

/// UGT (Unicast Game Terminal) Feature characteristic UUID.
const GMAP_UGT_CHRC_UUID: u16 = 0x2C02;

/// BGS (Broadcast Game Sender) Feature characteristic UUID.
const GMAP_BGS_CHRC_UUID: u16 = 0x2C03;

/// BGR (Broadcast Game Receiver) Feature characteristic UUID.
const GMAP_BGR_CHRC_UUID: u16 = 0x2C04;

// =====================================================================
// Handle allocation: 5 characteristics × 2 (decl + value) + 1 (service)
// =====================================================================
const GMAS_NUM_HANDLES: u16 = 11;

// =====================================================================
// Local type alias matching db.rs ReadFn (private there, reproduced here
// so clippy does not flag type_complexity in update_chrcs_locked).
// =====================================================================
type GmapReadFn =
    Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

// =====================================================================
// Masks for valid bits
// =====================================================================
const ROLE_MASK: u8 = 0x0F;
const UGG_FEAT_MASK: u8 = 0x07;
const UGT_FEAT_MASK: u8 = 0x7F;
const BGS_FEAT_MASK: u8 = 0x01;
const BGR_FEAT_MASK: u8 = 0x03;

// =====================================================================
// Role and Feature Bitflags
// =====================================================================

bitflags! {
    /// GMAP Role bitmask indicating which gaming audio roles are supported.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GmapRole: u8 {
        /// Unicast Game Gateway.
        const UGG = 0x01;
        /// Unicast Game Terminal.
        const UGT = 0x02;
        /// Broadcast Game Sender.
        const BGS = 0x04;
        /// Broadcast Game Receiver.
        const BGR = 0x08;
    }
}

bitflags! {
    /// UGG (Unicast Game Gateway) feature bitmask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GmapUggFeatures: u8 {
        /// UGG Multiplex.
        const MULTIPLEX = 0x01;
        /// UGG 96 kbps Source.
        const KBPS_96   = 0x02;
        /// UGG Multisink.
        const MULTISINK = 0x04;
    }
}

bitflags! {
    /// UGT (Unicast Game Terminal) feature bitmask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GmapUgtFeatures: u8 {
        /// UGT Source.
        const SOURCE          = 0x01;
        /// UGT 80 kbps Source.
        const KBPS_80_SOURCE  = 0x02;
        /// UGT Sink.
        const SINK            = 0x04;
        /// UGT 64 kbps Sink.
        const KBPS_64_SINK    = 0x08;
        /// UGT Multiplex.
        const MULTIPLEX       = 0x10;
        /// UGT Multisink.
        const MULTISINK       = 0x20;
        /// UGT Multisource.
        const MULTISOURCE     = 0x40;
    }
}

bitflags! {
    /// BGS (Broadcast Game Sender) feature bitmask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GmapBgsFeatures: u8 {
        /// BGS 96 kbps.
        const KBPS_96 = 0x01;
    }
}

bitflags! {
    /// BGR (Broadcast Game Receiver) feature bitmask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GmapBgrFeatures: u8 {
        /// BGR Multisink.
        const MULTISINK = 0x01;
        /// BGR Multiplex.
        const MULTIPLEX = 0x02;
    }
}

// =====================================================================
// Display implementations
// =====================================================================

impl fmt::Display for GmapRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(GmapRole::UGG) {
            parts.push("UGG");
        }
        if self.contains(GmapRole::UGT) {
            parts.push("UGT");
        }
        if self.contains(GmapRole::BGS) {
            parts.push("BGS");
        }
        if self.contains(GmapRole::BGR) {
            parts.push("BGR");
        }
        if parts.is_empty() { write!(f, "(none)") } else { write!(f, "{}", parts.join(", ")) }
    }
}

impl fmt::Display for GmapUggFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(GmapUggFeatures::MULTIPLEX) {
            parts.push("UGG Multiplex");
        }
        if self.contains(GmapUggFeatures::KBPS_96) {
            parts.push("UGG 96 kbps Source");
        }
        if self.contains(GmapUggFeatures::MULTISINK) {
            parts.push("UGG Multisink");
        }
        if parts.is_empty() { write!(f, "(none)") } else { write!(f, "{}", parts.join(", ")) }
    }
}

impl fmt::Display for GmapUgtFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(GmapUgtFeatures::SOURCE) {
            parts.push("UGT Source");
        }
        if self.contains(GmapUgtFeatures::KBPS_80_SOURCE) {
            parts.push("UGT 80 kbps Source");
        }
        if self.contains(GmapUgtFeatures::SINK) {
            parts.push("UGT Sink");
        }
        if self.contains(GmapUgtFeatures::KBPS_64_SINK) {
            parts.push("UGT 64 kbps Sink");
        }
        if self.contains(GmapUgtFeatures::MULTIPLEX) {
            parts.push("UGT Multiplex");
        }
        if self.contains(GmapUgtFeatures::MULTISINK) {
            parts.push("UGT Multisink");
        }
        if self.contains(GmapUgtFeatures::MULTISOURCE) {
            parts.push("UGT Multisource");
        }
        if parts.is_empty() { write!(f, "(none)") } else { write!(f, "{}", parts.join(", ")) }
    }
}

impl fmt::Display for GmapBgsFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(GmapBgsFeatures::KBPS_96) {
            write!(f, "BGS 96 kbps")
        } else {
            write!(f, "(none)")
        }
    }
}

impl fmt::Display for GmapBgrFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(GmapBgrFeatures::MULTISINK) {
            parts.push("BGR Multisink");
        }
        if self.contains(GmapBgrFeatures::MULTIPLEX) {
            parts.push("BGR Multiplex");
        }
        if parts.is_empty() { write!(f, "(none)") } else { write!(f, "{}", parts.join(", ")) }
    }
}

// =====================================================================
// Global session registry
// =====================================================================

/// Global list of active GMAP sessions (both server and client).
static INSTANCES: Mutex<Vec<Arc<BtGmap>>> = Mutex::new(Vec::new());

// =====================================================================
// Internal state
// =====================================================================

/// Internal mutable state of a GMAP session.
struct BtGmapInner {
    // ---- Server-side DB and service ----
    /// Local GATT database where the GMAS service is registered (server mode).
    ldb: Option<GattDb>,
    /// Server-side GMAS service handle (for characteristic management).
    service: Option<GattDbService>,
    /// Atomic value backing the GMAP Role characteristic read handler.
    role_value: Arc<AtomicU8>,
    /// Atomic value backing the UGG Feature characteristic read handler.
    ugg_value: Arc<AtomicU8>,
    /// Atomic value backing the UGT Feature characteristic read handler.
    ugt_value: Arc<AtomicU8>,
    /// Atomic value backing the BGS Feature characteristic read handler.
    bgs_value: Arc<AtomicU8>,
    /// Atomic value backing the BGR Feature characteristic read handler.
    bgr_value: Arc<AtomicU8>,
    /// Whether the Role characteristic has been added to the service.
    role_attr_created: bool,
    /// Whether the UGG Feature characteristic has been added to the service.
    ugg_attr_created: bool,
    /// Whether the UGT Feature characteristic has been added to the service.
    ugt_attr_created: bool,
    /// Whether the BGS Feature characteristic has been added to the service.
    bgs_attr_created: bool,
    /// Whether the BGR Feature characteristic has been added to the service.
    bgr_attr_created: bool,

    // ---- Client-side state ----
    /// GATT client for remote GMAS discovery.
    client: Option<Arc<BtGattClient>>,
    /// Remote GATT database kept alive for session lifetime (from client discovery).
    _rdb: Option<GattDb>,
    /// ATT transport handle used as session lookup key.
    att: Option<Arc<Mutex<BtAtt>>>,
    /// Idle callback registration ID on the GATT client.
    idle_id: u32,

    // ---- Shared role and feature state ----
    /// Current GMAP role(s).
    role: GmapRole,
    /// Current UGG feature flags.
    ugg_features: GmapUggFeatures,
    /// Current UGT feature flags.
    ugt_features: GmapUgtFeatures,
    /// Current BGS feature flags.
    bgs_features: GmapBgsFeatures,
    /// Current BGR feature flags.
    bgr_features: GmapBgrFeatures,

    // ---- Debug ----
    /// Optional debug logging callback.
    debug_func: Option<Box<dyn Fn(&str) + Send + Sync>>,
}

impl BtGmapInner {
    /// Log a debug message through the optional debug callback and tracing.
    fn debug_log(&self, msg: &str) {
        if let Some(ref func) = self.debug_func {
            func(msg);
        }
        debug!("{}", msg);
    }
}

// =====================================================================
// BtGmap — GMAP session (server or client)
// =====================================================================

/// Gaming Audio Profile session.
///
/// Manages a GMAS (Gaming Audio Service) instance that can operate in:
/// - **Server mode**: registers the GMAS service in a local GATT database
///   with role and per-role feature characteristics.
/// - **Client mode**: discovers a remote GMAS service via a GATT client and
///   reads the advertised role and feature values.
///
/// Sessions are tracked in a global registry and can be looked up by their
/// ATT transport handle via [`BtGmap::find`].
pub struct BtGmap {
    inner: Mutex<BtGmapInner>,
}

impl BtGmap {
    // -----------------------------------------------------------------
    // Session management (associated functions)
    // -----------------------------------------------------------------

    /// Attach to a remote GMAS service via a GATT client.
    ///
    /// Clones the GATT client, discovers the GMAS service in the remote
    /// database, reads the GMAP Role characteristic and all per-role feature
    /// characteristics that are present.  Returns the session handle.
    ///
    /// Equivalent to C `bt_gmap_attach`.
    pub fn attach(ldb: GattDb, client: Arc<BtGattClient>) -> Option<Arc<BtGmap>> {
        let cloned = BtGattClient::clone_client(&client).ok()?;
        let rdb = cloned.get_db();
        let att = cloned.get_att();

        let role_value = Arc::new(AtomicU8::new(0));
        let ugg_value = Arc::new(AtomicU8::new(0));
        let ugt_value = Arc::new(AtomicU8::new(0));
        let bgs_value = Arc::new(AtomicU8::new(0));
        let bgr_value = Arc::new(AtomicU8::new(0));

        let gmap = Arc::new(BtGmap {
            inner: Mutex::new(BtGmapInner {
                ldb: Some(ldb),
                service: None,
                role_value,
                ugg_value,
                ugt_value,
                bgs_value,
                bgr_value,
                role_attr_created: false,
                ugg_attr_created: false,
                ugt_attr_created: false,
                bgs_attr_created: false,
                bgr_attr_created: false,
                client: Some(Arc::clone(&cloned)),
                _rdb: Some(rdb.clone()),
                att: Some(att),
                idle_id: 0,
                role: GmapRole::empty(),
                ugg_features: GmapUggFeatures::empty(),
                ugt_features: GmapUgtFeatures::empty(),
                bgs_features: GmapBgsFeatures::empty(),
                bgr_features: GmapBgrFeatures::empty(),
                debug_func: None,
            }),
        });

        // Discover GMAS service in the remote GATT database.
        Self::discover_gmas(&gmap, &cloned, &rdb);

        // Register an idle callback so we are notified when all outstanding
        // read operations have completed.
        let gmap_idle_ref = Arc::clone(&gmap);
        let idle_id = cloned.idle_register(Box::new(move || {
            let inner = gmap_idle_ref.inner.lock().unwrap();
            inner.debug_log("GMAP discovery idle — ready");
        }));

        {
            let mut inner = gmap.inner.lock().unwrap();
            inner.idle_id = idle_id;
        }

        // Register in the global session list.
        {
            let mut instances = INSTANCES.lock().unwrap();
            instances.push(Arc::clone(&gmap));
        }

        debug!("GMAP attached");
        Some(gmap)
    }

    /// Find an existing GMAP session by its ATT transport handle.
    ///
    /// Searches the global session registry for a session whose ATT
    /// transport is pointer-identical to `att`.
    ///
    /// Equivalent to C `bt_gmap_find`.
    pub fn find(att: &Arc<Mutex<BtAtt>>) -> Option<Arc<BtGmap>> {
        let instances = INSTANCES.lock().unwrap();
        for gmap in instances.iter() {
            let inner = gmap.inner.lock().unwrap();
            if let Some(ref stored_att) = inner.att {
                if Arc::ptr_eq(stored_att, att) {
                    return Some(Arc::clone(gmap));
                }
            }
        }
        None
    }

    /// Find an existing GMAP session by its local GATT database.
    ///
    /// Searches the global session registry for a session whose local
    /// GATT database is pointer-identical to `db`.  This is the
    /// database-based counterpart of [`BtGmap::find`] and mirrors the
    /// pattern used by [`BtTmap::find`] for local service lookup.
    ///
    /// Typically used during endpoint registration to update the local
    /// GMAS service characteristics with aggregated role and feature
    /// values computed from all registered media endpoints.
    pub fn find_by_db(db: &GattDb) -> Option<Arc<BtGmap>> {
        let instances = INSTANCES.lock().unwrap();
        for gmap in instances.iter() {
            let inner = gmap.inner.lock().unwrap();
            if let Some(ref ldb) = inner.ldb {
                if ldb.ptr_eq(db) {
                    return Some(Arc::clone(gmap));
                }
            }
        }
        None
    }

    /// Register the GMAS service in a local GATT database (server-side).
    ///
    /// Creates a new GMAP session with the specified role and per-role
    /// feature values, registers the corresponding characteristics in the
    /// GATT database, and adds the session to the global registry.
    ///
    /// Returns `true` on success.
    ///
    /// Equivalent to C `bt_gmap_add_db`.
    pub fn add_db(
        ldb: GattDb,
        role: GmapRole,
        ugg: GmapUggFeatures,
        ugt: GmapUgtFeatures,
        bgs: GmapBgsFeatures,
        bgr: GmapBgrFeatures,
    ) -> bool {
        let masked_role = GmapRole::from_bits_truncate(role.bits() & ROLE_MASK);
        if masked_role.is_empty() {
            warn!("GMAP add_db called with empty role");
            return false;
        }

        let role_val = Arc::new(AtomicU8::new(masked_role.bits()));
        let ugg_val = Arc::new(AtomicU8::new(ugg.bits() & UGG_FEAT_MASK));
        let ugt_val = Arc::new(AtomicU8::new(ugt.bits() & UGT_FEAT_MASK));
        let bgs_val = Arc::new(AtomicU8::new(bgs.bits() & BGS_FEAT_MASK));
        let bgr_val = Arc::new(AtomicU8::new(bgr.bits() & BGR_FEAT_MASK));

        let gmap = Arc::new(BtGmap {
            inner: Mutex::new(BtGmapInner {
                ldb: Some(ldb),
                service: None,
                role_value: role_val,
                ugg_value: ugg_val,
                ugt_value: ugt_val,
                bgs_value: bgs_val,
                bgr_value: bgr_val,
                role_attr_created: false,
                ugg_attr_created: false,
                ugt_attr_created: false,
                bgs_attr_created: false,
                bgr_attr_created: false,
                client: None,
                _rdb: None,
                att: None,
                idle_id: 0,
                role: masked_role,
                ugg_features: GmapUggFeatures::from_bits_truncate(ugg.bits() & UGG_FEAT_MASK),
                ugt_features: GmapUgtFeatures::from_bits_truncate(ugt.bits() & UGT_FEAT_MASK),
                bgs_features: GmapBgsFeatures::from_bits_truncate(bgs.bits() & BGS_FEAT_MASK),
                bgr_features: GmapBgrFeatures::from_bits_truncate(bgr.bits() & BGR_FEAT_MASK),
                debug_func: None,
            }),
        });

        // Register the GMAS service in the local GATT database.
        {
            let mut inner = gmap.inner.lock().unwrap();
            Self::init_service_locked(&mut inner);
        }

        // Add to global session list.
        {
            let mut instances = INSTANCES.lock().unwrap();
            instances.push(Arc::clone(&gmap));
        }

        debug!("GMAP service registered: role={}", masked_role);
        true
    }

    // -----------------------------------------------------------------
    // Role and feature accessors
    // -----------------------------------------------------------------

    /// Returns the current GMAP role bitmask.
    pub fn get_role(&self) -> GmapRole {
        let inner = self.inner.lock().unwrap();
        inner.role
    }

    /// Update the GMAP role bitmask.
    ///
    /// If roles with existing feature characteristics are being removed, the
    /// entire GMAS service is reinitialized (GATT does not support removing
    /// individual characteristics).  Otherwise only new characteristics are
    /// added.
    pub fn set_role(&self, role: GmapRole) {
        let mut inner = self.inner.lock().unwrap();
        let new_role = GmapRole::from_bits_truncate(role.bits() & ROLE_MASK);

        if inner.role == new_role {
            return;
        }

        // Determine if any roles with existing feature attrs are removed.
        let removed = inner.role.difference(new_role);
        let need_reinit = Self::has_existing_feat_attrs_locked(&inner, removed);

        inner.role = new_role;
        inner.role_value.store(new_role.bits(), Ordering::Relaxed);

        if need_reinit {
            // Must rebuild the entire service since we cannot remove
            // individual characteristics from a GATT service.
            Self::init_service_locked(&mut inner);
        } else {
            Self::update_chrcs_locked(&mut inner);
        }

        // Activate or deactivate based on whether any role is set.
        if let Some(ref svc) = inner.service {
            svc.set_active(!new_role.is_empty());
        }
    }

    /// Returns the current UGG feature flags.
    pub fn get_ugg_features(&self) -> GmapUggFeatures {
        let inner = self.inner.lock().unwrap();
        inner.ugg_features
    }

    /// Update the UGG feature flags.
    pub fn set_ugg_features(&self, features: GmapUggFeatures) {
        let mut inner = self.inner.lock().unwrap();
        let masked = GmapUggFeatures::from_bits_truncate(features.bits() & UGG_FEAT_MASK);
        inner.ugg_features = masked;
        inner.ugg_value.store(masked.bits(), Ordering::Relaxed);
    }

    /// Returns the current UGT feature flags.
    pub fn get_ugt_features(&self) -> GmapUgtFeatures {
        let inner = self.inner.lock().unwrap();
        inner.ugt_features
    }

    /// Update the UGT feature flags.
    pub fn set_ugt_features(&self, features: GmapUgtFeatures) {
        let mut inner = self.inner.lock().unwrap();
        let masked = GmapUgtFeatures::from_bits_truncate(features.bits() & UGT_FEAT_MASK);
        inner.ugt_features = masked;
        inner.ugt_value.store(masked.bits(), Ordering::Relaxed);
    }

    /// Returns the current BGS feature flags.
    pub fn get_bgs_features(&self) -> GmapBgsFeatures {
        let inner = self.inner.lock().unwrap();
        inner.bgs_features
    }

    /// Update the BGS feature flags.
    pub fn set_bgs_features(&self, features: GmapBgsFeatures) {
        let mut inner = self.inner.lock().unwrap();
        let masked = GmapBgsFeatures::from_bits_truncate(features.bits() & BGS_FEAT_MASK);
        inner.bgs_features = masked;
        inner.bgs_value.store(masked.bits(), Ordering::Relaxed);
    }

    /// Returns the current BGR feature flags.
    pub fn get_bgr_features(&self) -> GmapBgrFeatures {
        let inner = self.inner.lock().unwrap();
        inner.bgr_features
    }

    /// Update the BGR feature flags.
    pub fn set_bgr_features(&self, features: GmapBgrFeatures) {
        let mut inner = self.inner.lock().unwrap();
        let masked = GmapBgrFeatures::from_bits_truncate(features.bits() & BGR_FEAT_MASK);
        inner.bgr_features = masked;
        inner.bgr_value.store(masked.bits(), Ordering::Relaxed);
    }

    /// Set the debug logging callback.
    pub fn set_debug(&self, func: Option<Box<dyn Fn(&str) + Send + Sync>>) {
        let mut inner = self.inner.lock().unwrap();
        inner.debug_func = func;
    }

    // -----------------------------------------------------------------
    // Server-side helpers (operate on locked inner)
    // -----------------------------------------------------------------

    /// Initialize (or reinitialize) the GMAS GATT service.
    ///
    /// Removes any existing service, creates a new GMAS primary service
    /// with room for up to 5 characteristics, adds the appropriate
    /// characteristics based on the current role, and activates the
    /// service if at least one role bit is set.
    fn init_service_locked(inner: &mut BtGmapInner) {
        let ldb = match inner.ldb {
            Some(ref db) => db.clone(),
            None => return,
        };

        // Remove existing service if present.
        if let Some(ref svc) = inner.service {
            ldb.remove_service(&svc.as_attribute());
        }
        inner.service = None;
        inner.role_attr_created = false;
        inner.ugg_attr_created = false;
        inner.ugt_attr_created = false;
        inner.bgs_attr_created = false;
        inner.bgr_attr_created = false;

        // Allocate a new GMAS primary service.
        let gmas_uuid = BtUuid::from_u16(GMAS_UUID);
        let svc = match ldb.add_service(&gmas_uuid, true, GMAS_NUM_HANDLES) {
            Some(s) => s,
            None => {
                warn!("Failed to add GMAS service to GATT DB");
                return;
            }
        };
        inner.service = Some(svc);

        // Add characteristics for the current role.
        Self::update_chrcs_locked(inner);

        // Activate the service if at least one role is set.
        if let Some(ref svc) = inner.service {
            svc.set_active(!inner.role.is_empty());
        }
    }

    /// Add any missing characteristics to the existing GMAS service based
    /// on the current role flags.
    ///
    /// - The GMAP Role characteristic is always added.
    /// - Per-role feature characteristics are added only when the
    ///   corresponding role bit is set.
    /// - Characteristics that already exist are not duplicated.
    fn update_chrcs_locked(inner: &mut BtGmapInner) {
        let svc = match inner.service {
            Some(ref s) => s.clone(),
            None => return,
        };

        let perms = AttPermissions::READ.bits() as u32;
        let props = GattChrcProperties::READ.bits();

        // Helper: (should_add, already_created, uuid, atomic_value)
        let entries: [(bool, bool, u16, Arc<AtomicU8>); 5] = [
            (
                true, // Role characteristic is always added
                inner.role_attr_created,
                GMAP_ROLE_CHRC_UUID,
                Arc::clone(&inner.role_value),
            ),
            (
                inner.role.contains(GmapRole::UGG),
                inner.ugg_attr_created,
                GMAP_UGG_CHRC_UUID,
                Arc::clone(&inner.ugg_value),
            ),
            (
                inner.role.contains(GmapRole::UGT),
                inner.ugt_attr_created,
                GMAP_UGT_CHRC_UUID,
                Arc::clone(&inner.ugt_value),
            ),
            (
                inner.role.contains(GmapRole::BGS),
                inner.bgs_attr_created,
                GMAP_BGS_CHRC_UUID,
                Arc::clone(&inner.bgs_value),
            ),
            (
                inner.role.contains(GmapRole::BGR),
                inner.bgr_attr_created,
                GMAP_BGR_CHRC_UUID,
                Arc::clone(&inner.bgr_value),
            ),
        ];

        for (idx, (should_add, created, uuid_val, atomic_ref)) in entries.into_iter().enumerate() {
            if !should_add || created {
                continue;
            }

            let uuid = BtUuid::from_u16(uuid_val);
            let val_ref = atomic_ref;

            // Build the read callback returning the current atomic value.
            let read_fn: GmapReadFn = Arc::new(move |attr, id, _offset, _opcode, _att| {
                let v = val_ref.load(Ordering::Relaxed);
                attr.read_result(id, 0, &[v]);
            });

            if let Some(attr) =
                svc.add_characteristic(&uuid, perms, props, Some(read_fn), None, None)
            {
                attr.set_fixed_length(1);
                match idx {
                    0 => inner.role_attr_created = true,
                    1 => inner.ugg_attr_created = true,
                    2 => inner.ugt_attr_created = true,
                    3 => inner.bgs_attr_created = true,
                    4 => inner.bgr_attr_created = true,
                    _ => {}
                }
            }
        }
    }

    /// Check whether any roles in `roles` have existing feature
    /// characteristics in the current service.
    fn has_existing_feat_attrs_locked(inner: &BtGmapInner, roles: GmapRole) -> bool {
        (roles.contains(GmapRole::UGG) && inner.ugg_attr_created)
            || (roles.contains(GmapRole::UGT) && inner.ugt_attr_created)
            || (roles.contains(GmapRole::BGS) && inner.bgs_attr_created)
            || (roles.contains(GmapRole::BGR) && inner.bgr_attr_created)
    }

    // -----------------------------------------------------------------
    // Client-side discovery
    // -----------------------------------------------------------------

    /// Discover the GMAS service in a remote GATT database and read its
    /// role and per-role feature characteristics.
    fn discover_gmas(gmap: &Arc<BtGmap>, client: &Arc<BtGattClient>, rdb: &GattDb) {
        let gmas_uuid = BtUuid::from_u16(GMAS_UUID);

        // Collect service declaration handles first to avoid borrow issues.
        let mut service_handles: Vec<u16> = Vec::new();
        rdb.foreach_service(Some(&gmas_uuid), |attr| {
            service_handles.push(attr.get_handle());
        });

        for handle in &service_handles {
            let attr = match rdb.get_attribute(*handle) {
                Some(a) => a,
                None => continue,
            };
            let svc = match attr.get_service() {
                Some(s) => s,
                None => continue,
            };

            // Claim the service for GMAP.
            svc.set_claimed(true);

            // Iterate characteristics within this service.
            let gmap_chars = Arc::clone(gmap);
            let client_chars = Arc::clone(client);
            svc.foreach_char(|char_attr| {
                Self::process_remote_char(&gmap_chars, &client_chars, &char_attr);
            });
        }
    }

    /// Process a single characteristic discovered in a remote GMAS service.
    /// Reads the value via the GATT client and updates session state.
    fn process_remote_char(
        gmap: &Arc<BtGmap>,
        client: &Arc<BtGattClient>,
        char_attr: &GattDbAttribute,
    ) {
        let char_data = match char_attr.get_char_data() {
            Some(cd) => cd,
            None => return,
        };

        let value_handle = char_data.value_handle;
        let uuid = char_data.uuid;

        let role_uuid = BtUuid::from_u16(GMAP_ROLE_CHRC_UUID);
        let ugg_uuid = BtUuid::from_u16(GMAP_UGG_CHRC_UUID);
        let ugt_uuid = BtUuid::from_u16(GMAP_UGT_CHRC_UUID);
        let bgs_uuid = BtUuid::from_u16(GMAP_BGS_CHRC_UUID);
        let bgr_uuid = BtUuid::from_u16(GMAP_BGR_CHRC_UUID);

        let gmap_ref = Arc::clone(gmap);

        if uuid == role_uuid {
            debug!("Reading GMAP Role (handle=0x{:04x})", value_handle);
            client.read_value(
                value_handle,
                Box::new(move |success, _ecode, value| {
                    Self::handle_role_read(&gmap_ref, success, value);
                }),
            );
        } else if uuid == ugg_uuid {
            debug!("Reading UGG Features (handle=0x{:04x})", value_handle);
            client.read_value(
                value_handle,
                Box::new(move |success, _ecode, value| {
                    Self::handle_ugg_read(&gmap_ref, success, value);
                }),
            );
        } else if uuid == ugt_uuid {
            debug!("Reading UGT Features (handle=0x{:04x})", value_handle);
            client.read_value(
                value_handle,
                Box::new(move |success, _ecode, value| {
                    Self::handle_ugt_read(&gmap_ref, success, value);
                }),
            );
        } else if uuid == bgs_uuid {
            debug!("Reading BGS Features (handle=0x{:04x})", value_handle);
            client.read_value(
                value_handle,
                Box::new(move |success, _ecode, value| {
                    Self::handle_bgs_read(&gmap_ref, success, value);
                }),
            );
        } else if uuid == bgr_uuid {
            debug!("Reading BGR Features (handle=0x{:04x})", value_handle);
            client.read_value(
                value_handle,
                Box::new(move |success, _ecode, value| {
                    Self::handle_bgr_read(&gmap_ref, success, value);
                }),
            );
        }
    }

    // ----- Read result handlers -----

    fn handle_role_read(gmap: &Arc<BtGmap>, success: bool, value: &[u8]) {
        if !success || value.is_empty() {
            warn!("Failed to read GMAP Role");
            return;
        }
        let role = GmapRole::from_bits_truncate(value[0] & ROLE_MASK);
        let mut inner = gmap.inner.lock().unwrap();
        inner.role = role;
        inner.debug_log(&format!("GMAP Role: {}", role));
    }

    fn handle_ugg_read(gmap: &Arc<BtGmap>, success: bool, value: &[u8]) {
        if !success || value.is_empty() {
            warn!("Failed to read UGG Features");
            return;
        }
        let feats = GmapUggFeatures::from_bits_truncate(value[0] & UGG_FEAT_MASK);
        let mut inner = gmap.inner.lock().unwrap();
        inner.ugg_features = feats;
        inner.debug_log(&format!("UGG Features: {}", feats));
    }

    fn handle_ugt_read(gmap: &Arc<BtGmap>, success: bool, value: &[u8]) {
        if !success || value.is_empty() {
            warn!("Failed to read UGT Features");
            return;
        }
        let feats = GmapUgtFeatures::from_bits_truncate(value[0] & UGT_FEAT_MASK);
        let mut inner = gmap.inner.lock().unwrap();
        inner.ugt_features = feats;
        inner.debug_log(&format!("UGT Features: {}", feats));
    }

    fn handle_bgs_read(gmap: &Arc<BtGmap>, success: bool, value: &[u8]) {
        if !success || value.is_empty() {
            warn!("Failed to read BGS Features");
            return;
        }
        let feats = GmapBgsFeatures::from_bits_truncate(value[0] & BGS_FEAT_MASK);
        let mut inner = gmap.inner.lock().unwrap();
        inner.bgs_features = feats;
        inner.debug_log(&format!("BGS Features: {}", feats));
    }

    fn handle_bgr_read(gmap: &Arc<BtGmap>, success: bool, value: &[u8]) {
        if !success || value.is_empty() {
            warn!("Failed to read BGR Features");
            return;
        }
        let feats = GmapBgrFeatures::from_bits_truncate(value[0] & BGR_FEAT_MASK);
        let mut inner = gmap.inner.lock().unwrap();
        inner.bgr_features = feats;
        inner.debug_log(&format!("BGR Features: {}", feats));
    }
}

impl Drop for BtGmap {
    fn drop(&mut self) {
        // Unregister the idle callback if active.
        let inner = self.inner.get_mut().unwrap();
        if inner.idle_id != 0 {
            if let Some(ref client) = inner.client {
                client.idle_unregister(inner.idle_id);
            }
            inner.idle_id = 0;
        }
        // Note: removal from the global INSTANCES list is NOT done here to
        // avoid a re-entrant deadlock (std::sync::Mutex is not reentrant).
        // Callers must invoke BtGmap::detach() before dropping the last Arc.
    }
}

impl BtGmap {
    /// Remove this session from the global registry.
    ///
    /// Must be called before dropping the last `Arc<BtGmap>` reference to
    /// prevent the session from lingering in the global list.  This is safe
    /// to call multiple times.
    pub fn detach(self: &Arc<Self>) {
        if let Ok(mut instances) = INSTANCES.lock() {
            let self_ptr = Arc::as_ptr(self);
            instances.retain(|arc| !std::ptr::eq(Arc::as_ptr(arc), self_ptr));
        }
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmap_role_bitflags() {
        let role = GmapRole::UGG | GmapRole::BGS;
        assert!(role.contains(GmapRole::UGG));
        assert!(!role.contains(GmapRole::UGT));
        assert!(role.contains(GmapRole::BGS));
        assert!(!role.contains(GmapRole::BGR));
        assert_eq!(role.bits(), 0x05);
    }

    #[test]
    fn test_gmap_role_display() {
        let role = GmapRole::UGG | GmapRole::UGT | GmapRole::BGS | GmapRole::BGR;
        let s = format!("{}", role);
        assert_eq!(s, "UGG, UGT, BGS, BGR");
    }

    #[test]
    fn test_gmap_role_display_empty() {
        let role = GmapRole::empty();
        assert_eq!(format!("{}", role), "(none)");
    }

    #[test]
    fn test_ugg_features_bitflags() {
        let f = GmapUggFeatures::MULTIPLEX | GmapUggFeatures::KBPS_96;
        assert!(f.contains(GmapUggFeatures::MULTIPLEX));
        assert!(f.contains(GmapUggFeatures::KBPS_96));
        assert!(!f.contains(GmapUggFeatures::MULTISINK));
        assert_eq!(f.bits(), 0x03);
    }

    #[test]
    fn test_ugg_features_display() {
        let f = GmapUggFeatures::all();
        let s = format!("{}", f);
        assert_eq!(s, "UGG Multiplex, UGG 96 kbps Source, UGG Multisink");
    }

    #[test]
    fn test_ugt_features_bitflags() {
        let f = GmapUgtFeatures::SOURCE | GmapUgtFeatures::SINK | GmapUgtFeatures::MULTISOURCE;
        assert_eq!(f.bits(), 0x45);
        assert!(f.contains(GmapUgtFeatures::SOURCE));
        assert!(f.contains(GmapUgtFeatures::SINK));
        assert!(f.contains(GmapUgtFeatures::MULTISOURCE));
        assert!(!f.contains(GmapUgtFeatures::MULTIPLEX));
    }

    #[test]
    fn test_ugt_features_display() {
        let f = GmapUgtFeatures::SOURCE | GmapUgtFeatures::SINK;
        let s = format!("{}", f);
        assert_eq!(s, "UGT Source, UGT Sink");
    }

    #[test]
    fn test_bgs_features_bitflags() {
        let f = GmapBgsFeatures::KBPS_96;
        assert_eq!(f.bits(), 0x01);
    }

    #[test]
    fn test_bgs_features_display() {
        assert_eq!(format!("{}", GmapBgsFeatures::KBPS_96), "BGS 96 kbps");
        assert_eq!(format!("{}", GmapBgsFeatures::empty()), "(none)");
    }

    #[test]
    fn test_bgr_features_bitflags() {
        let f = GmapBgrFeatures::MULTISINK | GmapBgrFeatures::MULTIPLEX;
        assert_eq!(f.bits(), 0x03);
    }

    #[test]
    fn test_bgr_features_display() {
        let f = GmapBgrFeatures::MULTISINK | GmapBgrFeatures::MULTIPLEX;
        assert_eq!(format!("{}", f), "BGR Multisink, BGR Multiplex");
    }

    #[test]
    fn test_role_mask() {
        // ROLE_MASK is already u8 (0x0F), so `0xFF &` is a no-op: this test
        // simply verifies `from_bits_truncate(ROLE_MASK)` yields every role bit.
        let role = GmapRole::from_bits_truncate(ROLE_MASK);
        assert_eq!(role, GmapRole::UGG | GmapRole::UGT | GmapRole::BGS | GmapRole::BGR);
    }

    #[test]
    fn test_ugg_feat_mask() {
        // UGG_FEAT_MASK is u8 (0x07); `from_bits_truncate` of the mask must
        // yield every UGG feature flag.
        let f = GmapUggFeatures::from_bits_truncate(UGG_FEAT_MASK);
        assert_eq!(f, GmapUggFeatures::all());
    }

    #[test]
    fn test_ugt_feat_mask() {
        // UGT_FEAT_MASK is u8 (0x7F); `from_bits_truncate` of the mask must
        // yield every UGT feature flag.
        let f = GmapUgtFeatures::from_bits_truncate(UGT_FEAT_MASK);
        assert_eq!(f, GmapUgtFeatures::all());
    }

    #[test]
    fn test_has_existing_feat_attrs() {
        let inner = BtGmapInner {
            ldb: None,
            service: None,
            role_value: Arc::new(AtomicU8::new(0)),
            ugg_value: Arc::new(AtomicU8::new(0)),
            ugt_value: Arc::new(AtomicU8::new(0)),
            bgs_value: Arc::new(AtomicU8::new(0)),
            bgr_value: Arc::new(AtomicU8::new(0)),
            role_attr_created: true,
            ugg_attr_created: true,
            ugt_attr_created: false,
            bgs_attr_created: false,
            bgr_attr_created: false,
            client: None,
            _rdb: None,
            att: None,
            idle_id: 0,
            role: GmapRole::UGG,
            ugg_features: GmapUggFeatures::empty(),
            ugt_features: GmapUgtFeatures::empty(),
            bgs_features: GmapBgsFeatures::empty(),
            bgr_features: GmapBgrFeatures::empty(),
            debug_func: None,
        };
        assert!(BtGmap::has_existing_feat_attrs_locked(&inner, GmapRole::UGG));
        assert!(!BtGmap::has_existing_feat_attrs_locked(&inner, GmapRole::UGT));
        assert!(!BtGmap::has_existing_feat_attrs_locked(&inner, GmapRole::BGS));
    }

    #[test]
    fn test_add_db_server_side() {
        let db = GattDb::new();
        let result = BtGmap::add_db(
            db,
            GmapRole::UGG | GmapRole::UGT,
            GmapUggFeatures::MULTIPLEX,
            GmapUgtFeatures::SOURCE,
            GmapBgsFeatures::empty(),
            GmapBgrFeatures::empty(),
        );
        assert!(result);

        // Drain sessions from INSTANCES *while holding the lock* so no
        // Drop runs inside the critical section, then release the lock
        // and let the drained Arcs drop outside.
        let drained: Vec<Arc<BtGmap>> = {
            let mut instances = INSTANCES.lock().unwrap();
            instances.drain(..).collect()
        };
        drop(drained);
    }

    #[test]
    fn test_add_db_empty_role_fails() {
        let db = GattDb::new();
        let result = BtGmap::add_db(
            db,
            GmapRole::empty(),
            GmapUggFeatures::empty(),
            GmapUgtFeatures::empty(),
            GmapBgsFeatures::empty(),
            GmapBgrFeatures::empty(),
        );
        assert!(!result);
    }

    #[test]
    fn test_find_by_db_returns_matching_instance() {
        // Create a GattDb and clone it before handing to add_db (Clone
        // shares the same inner Arc, so ptr_eq will hold).
        let db = GattDb::new();
        let db_clone = db.clone();

        let ok = BtGmap::add_db(
            db,
            GmapRole::UGG,
            GmapUggFeatures::MULTIPLEX,
            GmapUgtFeatures::empty(),
            GmapBgsFeatures::empty(),
            GmapBgrFeatures::empty(),
        );
        assert!(ok);

        // find_by_db should locate the instance we just registered.
        let found = BtGmap::find_by_db(&db_clone);
        assert!(found.is_some(), "find_by_db must locate the instance registered via add_db");

        let gmap = found.unwrap();
        assert_eq!(gmap.get_role(), GmapRole::UGG);

        // Cleanup: drain INSTANCES to avoid leaking into other tests.
        let drained: Vec<Arc<BtGmap>> = {
            let mut instances = INSTANCES.lock().unwrap();
            instances.drain(..).collect()
        };
        drop(drained);
    }

    #[test]
    fn test_find_by_db_returns_none_for_different_db() {
        // Register a GMAP instance with one database.
        let db1 = GattDb::new();
        let ok = BtGmap::add_db(
            db1,
            GmapRole::UGT,
            GmapUggFeatures::empty(),
            GmapUgtFeatures::SOURCE,
            GmapBgsFeatures::empty(),
            GmapBgrFeatures::empty(),
        );
        assert!(ok);

        // Search using a completely different GattDb — should not match.
        let db2 = GattDb::new();
        let found = BtGmap::find_by_db(&db2);
        assert!(found.is_none(), "find_by_db must return None for a non-matching database");

        // Cleanup.
        let drained: Vec<Arc<BtGmap>> = {
            let mut instances = INSTANCES.lock().unwrap();
            instances.drain(..).collect()
        };
        drop(drained);
    }

    #[test]
    fn test_find_by_db_returns_none_when_empty() {
        // Ensure INSTANCES is empty before the check.
        {
            let mut instances = INSTANCES.lock().unwrap();
            instances.drain(..);
        }

        let db = GattDb::new();
        let found = BtGmap::find_by_db(&db);
        assert!(found.is_none(), "find_by_db must return None when no instances are registered");
    }
}
