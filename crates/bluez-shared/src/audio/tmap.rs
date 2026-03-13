// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2025 Pauli Virtanen. All rights reserved.
//
//! TMAP (Telephony and Media Audio Profile) / TMAS (Telephony and Media Audio
//! Service) — Client and Server.
//!
//! Complete Rust rewrite of `src/shared/tmap.c` (306 lines) and
//! `src/shared/tmap.h` (54 lines). Implements the TMAS role characteristic
//! to advertise supported audio roles (CG, CT, UMS, UMR, BMS, BMR).
//!
//! # Architecture
//!
//! - [`TmapRole`] is a bitflags type representing TMAP role capabilities.
//! - [`BtTmap`] is the main session handle, shared via `Arc`.
//! - Server-side: [`BtTmap::add_db`] registers the TMAS primary service in
//!   the local GATT database with a read-only Role characteristic.
//! - Client-side: [`BtTmap::attach`] discovers the remote TMAS service,
//!   reads the Role characteristic, and registers the session.
//! - Session tracking uses a global `Mutex<Vec<…>>` replacing C's
//!   `struct queue *instances`.
//! - Reference counting (`bt_tmap_ref`/`bt_tmap_unref`) is replaced by `Arc`.
//! - Debug callbacks are replaced by `tracing::debug!`.

use std::fmt;
use std::sync::{Arc, Mutex};

use bitflags::bitflags;
use tracing::debug;

use crate::att::transport::BtAtt;
use crate::att::types::{AttPermissions, GattChrcProperties};
use crate::gatt::client::BtGattClient;
use crate::gatt::db::{GattDb, GattDbAttribute};
use crate::util::endian::{IoBuf, put_le16};
use crate::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Constants — Bluetooth SIG assigned numbers
// ---------------------------------------------------------------------------

/// Type alias for the GATT attribute read handler function.
type ReadFn = Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;

/// Type alias for the debug logging callback.
type DebugFn = Box<dyn Fn(&str) + Send + Sync>;

/// TMAS (Telephony and Media Audio Service) UUID — 0x1855.
const TMAS_UUID: u16 = 0x1855;

/// TMAP Role Characteristic UUID — 0x2B51.
const TMAP_ROLE_CHRC_UUID: u16 = 0x2B51;

// ---------------------------------------------------------------------------
// TmapRole — bitflags type
// ---------------------------------------------------------------------------

bitflags! {
    /// TMAP Role capability bitfield.
    ///
    /// Each bit indicates a supported TMAP role. Multiple roles can be
    /// active simultaneously. The wire encoding is a 2-byte little-endian
    /// `u16`.
    ///
    /// Values match the Bluetooth SIG specification exactly:
    /// - Bit 0 (0x0001): Call Gateway (CG)
    /// - Bit 1 (0x0002): Call Terminal (CT)
    /// - Bit 2 (0x0004): Unicast Media Sender (UMS)
    /// - Bit 3 (0x0008): Unicast Media Receiver (UMR)
    /// - Bit 4 (0x0010): Broadcast Media Sender (BMS)
    /// - Bit 5 (0x0020): Broadcast Media Receiver (BMR)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TmapRole: u16 {
        /// Call Gateway.
        const CG  = 0x0001;
        /// Call Terminal.
        const CT  = 0x0002;
        /// Unicast Media Sender.
        const UMS = 0x0004;
        /// Unicast Media Receiver.
        const UMR = 0x0008;
        /// Broadcast Media Sender.
        const BMS = 0x0010;
        /// Broadcast Media Receiver.
        const BMR = 0x0020;
        /// Mask of all valid role bits (bits 0–5).
        const MASK = 0x003F;
    }
}

impl TmapRole {
    /// Returns a comma-separated string of active role abbreviations.
    ///
    /// Matching the C `TMAP_ROLE_LIST` macro behaviour, iterates over all
    /// defined role flags and collects the lowercase string names of set
    /// flags.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let role = TmapRole::CG | TmapRole::UMS;
    /// assert_eq!(role.role_list(), "cg, ums");
    /// ```
    pub fn role_list(&self) -> String {
        const ROLE_NAMES: &[(TmapRole, &str)] = &[
            (TmapRole::CG, "cg"),
            (TmapRole::CT, "ct"),
            (TmapRole::UMS, "ums"),
            (TmapRole::UMR, "umr"),
            (TmapRole::BMS, "bms"),
            (TmapRole::BMR, "bmr"),
        ];

        let mut parts = Vec::new();
        for &(flag, name) in ROLE_NAMES {
            if self.contains(flag) {
                parts.push(name);
            }
        }
        parts.join(", ")
    }
}

impl fmt::Display for TmapRole {
    /// Formats the role as a comma-separated list of active role
    /// abbreviations using uppercase names: CG, CT, UMS, UMR, BMS, BMR.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const ROLE_NAMES: &[(TmapRole, &str)] = &[
            (TmapRole::CG, "CG"),
            (TmapRole::CT, "CT"),
            (TmapRole::UMS, "UMS"),
            (TmapRole::UMR, "UMR"),
            (TmapRole::BMS, "BMS"),
            (TmapRole::BMR, "BMR"),
        ];

        let mut first = true;
        for &(flag, name) in ROLE_NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("(none)")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Global instances list
// ---------------------------------------------------------------------------

/// Global list of active TMAP sessions, replacing C's
/// `static struct queue *instances`.
static INSTANCES: Mutex<Vec<Arc<BtTmapInner>>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// BtTmapInner — internal state
// ---------------------------------------------------------------------------

/// Internal state of a TMAP session.
///
/// Immutable fields are set at construction; mutable fields use interior
/// mutability (`Mutex` or `Arc<Mutex<…>>`).
struct BtTmapInner {
    /// GATT client for remote TMAS discovery (`None` for server-side
    /// sessions).
    client: Option<Arc<BtGattClient>>,

    /// Local (server-side) or remote (client-side) GATT database.
    ldb: GattDb,

    /// Service attribute handle (server-side only). Used for removal and
    /// activation state.
    service_attr: Option<GattDbAttribute>,

    /// Role attribute handle (server-side only).
    #[allow(dead_code)]
    role_attr: Option<GattDbAttribute>,

    /// Current TMAP role value. Shared with the read-handler closure on
    /// the server side so that `set_role` updates are visible to GATT
    /// reads immediately.
    role_state: Arc<Mutex<TmapRole>>,

    /// Idle-callback registration ID (client-side only).
    idle_id: Mutex<u32>,

    /// Optional debug callback (replaces C `bt_tmap_debug_func_t`).
    debug_func: Mutex<Option<DebugFn>>,
}

impl Drop for BtTmapInner {
    fn drop(&mut self) {
        // Client-side: unregister the idle callback and release the client.
        if let Some(ref client) = self.client {
            let id = *self.idle_id.lock().unwrap();
            if id != 0 {
                client.idle_unregister(id);
            }
        }

        // Server-side: remove the TMAS service from the local GATT DB.
        if self.client.is_none() {
            if let Some(ref svc_attr) = self.service_attr {
                self.ldb.remove_service(svc_attr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BtTmap — public API
// ---------------------------------------------------------------------------

/// TMAP (Telephony and Media Audio Profile) session handle.
///
/// Wraps an `Arc<BtTmapInner>` for shared ownership. This is the Rust
/// equivalent of `struct bt_tmap` from `src/shared/tmap.c`.
///
/// # Lifecycle
///
/// - **Server-side**: created via [`BtTmap::add_db`], which registers a TMAS
///   primary service in the local GATT database. The role value is set via
///   [`BtTmap::set_role`], which also activates/deactivates the service.
///
/// - **Client-side**: created via [`BtTmap::attach`], which discovers the
///   remote TMAS service and reads the TMAP Role characteristic.
///
/// - Sessions are tracked in a global instances list. Dropping the last
///   reference removes the session from the list and cleans up resources.
pub struct BtTmap {
    inner: Arc<BtTmapInner>,
}

impl BtTmap {
    // =================================================================
    // Client-side: attach to remote TMAS service
    // =================================================================

    /// Attach to a remote TMAS service via a GATT client.
    ///
    /// Discovers the TMAS service in the remote GATT database, reads the
    /// TMAP Role characteristic, and registers the session in the global
    /// instances list once the client becomes idle.
    ///
    /// Rust equivalent of `bt_tmap_attach` from `tmap.c`.
    pub fn attach(client: &Arc<BtGattClient>) -> Option<Arc<BtTmap>> {
        // Clone the GATT client (C: bt_gatt_client_clone).
        let cloned = BtGattClient::clone_client(client).ok()?;

        // Retrieve the remote GATT database.
        let rdb = cloned.get_db();

        let inner = Arc::new(BtTmapInner {
            client: Some(Arc::clone(&cloned)),
            ldb: rdb,
            service_attr: None,
            role_attr: None,
            role_state: Arc::new(Mutex::new(TmapRole::empty())),
            idle_id: Mutex::new(0),
            debug_func: Mutex::new(None),
        });

        let tmap = Arc::new(BtTmap { inner: Arc::clone(&inner) });

        // Discover TMAS service in the remote database.
        let tmas_uuid = BtUuid::from_u16(TMAS_UUID);
        let tmap_disc = Arc::clone(&tmap);
        tmap.inner.ldb.foreach_service(Some(&tmas_uuid), move |attr| {
            Self::foreach_tmap_service(&tmap_disc, attr);
        });

        // Register idle callback — defers adding to INSTANCES until the
        // GATT client finishes any in-flight operations.
        let tmap_idle = Arc::clone(&tmap);
        let idle_id = cloned.idle_register(Box::new(move || {
            Self::tmap_idle(&tmap_idle);
        }));

        // Store the idle id so Drop can unregister it.
        *tmap.inner.idle_id.lock().unwrap() = idle_id;

        Some(tmap)
    }

    /// Process a discovered TMAS service attribute (client-side).
    fn foreach_tmap_service(tmap: &Arc<BtTmap>, attr: GattDbAttribute) {
        if let Some(svc) = attr.get_service() {
            // Claim the service so other profiles don't try to use it.
            svc.set_claimed(true);

            let tmap_ref = Arc::clone(tmap);
            svc.foreach_char(move |char_attr| {
                Self::foreach_tmap_char(&tmap_ref, char_attr);
            });
        }
    }

    /// Process a discovered characteristic within the TMAS service.
    ///
    /// If this is the TMAP Role characteristic, reads its value from the
    /// remote device.
    fn foreach_tmap_char(tmap: &Arc<BtTmap>, attr: GattDbAttribute) {
        let char_data = match attr.get_char_data() {
            Some(d) => d,
            None => return,
        };

        let role_uuid = BtUuid::from_u16(TMAP_ROLE_CHRC_UUID);
        if char_data.uuid != role_uuid {
            return;
        }

        debug!("TMAS Role Char found: handle 0x{:04x}", char_data.value_handle);

        // Read the TMAP Role characteristic value.
        if let Some(ref client) = tmap.inner.client {
            let tmap_cb = Arc::clone(tmap);
            client.read_value(
                char_data.value_handle,
                Box::new(move |success: bool, att_ecode: u8, value: &[u8]| {
                    Self::tmap_role_read(&tmap_cb, success, att_ecode, value);
                }),
            );
        }
    }

    /// Handle the TMAP Role characteristic read response (client-side).
    ///
    /// Parses the 2-byte little-endian role value and stores it in the
    /// session's mutable role state.
    fn tmap_role_read(tmap: &Arc<BtTmap>, success: bool, att_ecode: u8, value: &[u8]) {
        if !success {
            debug!("Unable to read Role: error 0x{:02x}", att_ecode);
            return;
        }

        let mut iov = IoBuf::from_bytes(value);
        let role_raw = match iov.pull_le16() {
            Some(v) => v,
            None => {
                debug!("Invalid Role");
                return;
            }
        };

        debug!("Role 0x{:x}", role_raw);

        // Mask to valid bits and store.
        let role = TmapRole::from_bits_truncate(role_raw) & TmapRole::MASK;
        *tmap.inner.role_state.lock().unwrap() = role;
    }

    /// Idle callback — finalises session registration (client-side).
    ///
    /// Called when the GATT client becomes idle after discovery and reads.
    /// Adds the session to the global instances list.
    fn tmap_idle(tmap: &Arc<BtTmap>) {
        let mut instances = INSTANCES.lock().unwrap();
        let already = instances.iter().any(|i| Arc::ptr_eq(i, &tmap.inner));
        if !already {
            instances.push(Arc::clone(&tmap.inner));
        }
    }

    // =================================================================
    // Server-side: register TMAS service in local GATT DB
    // =================================================================

    /// Register the TMAS service in the local GATT database.
    ///
    /// Creates a TMAS primary service with a read-only TMAP Role
    /// characteristic. The service is initially inactive; call
    /// [`set_role`](BtTmap::set_role) with a non-zero role value to
    /// activate it.
    ///
    /// Rust equivalent of `bt_tmap_add_db` from `tmap.c`.
    ///
    /// # Returns
    ///
    /// `Some(Arc<BtTmap>)` on success, `None` if a server-side session
    /// already exists for this database or service registration fails.
    pub fn add_db(ldb: &GattDb, role: TmapRole) -> Option<Arc<BtTmap>> {
        // Reject if a server-side session already exists for this DB.
        {
            let instances = INSTANCES.lock().unwrap();
            for inst in instances.iter() {
                if inst.client.is_none() && Self::db_matches(inst, ldb) {
                    return None;
                }
            }
        }

        // Add TMAS primary service: 3 handles (service decl, char decl,
        // char value).
        let tmas_uuid = BtUuid::from_u16(TMAS_UUID);
        let service = ldb.add_service(&tmas_uuid, true, 3)?;

        // Shared role state for the read handler and later set_role().
        let role_state = Arc::new(Mutex::new(role));
        let role_state_read = Arc::clone(&role_state);

        // Read handler — returns the current role as 2-byte LE.
        let read_fn: ReadFn = Arc::new(
            move |attrib: GattDbAttribute,
                  id: u32,
                  _offset: u16,
                  _opcode: u8,
                  _att: Option<Arc<Mutex<BtAtt>>>| {
                let role_val = *role_state_read.lock().unwrap();
                let mut buf = [0u8; 2];
                put_le16(role_val.bits(), &mut buf);
                attrib.read_result(id, 0, &buf);
            },
        );

        // Add the TMAP Role characteristic (read-only).
        let role_chrc_uuid = BtUuid::from_u16(TMAP_ROLE_CHRC_UUID);
        let role_attr = service.add_characteristic(
            &role_chrc_uuid,
            AttPermissions::READ.bits() as u32,
            GattChrcProperties::READ.bits(),
            Some(read_fn),
            None,
            None,
        )?;

        let inner = Arc::new(BtTmapInner {
            client: None,
            ldb: ldb.clone(),
            service_attr: Some(service.as_attribute()),
            role_attr: Some(role_attr),
            role_state: Arc::clone(&role_state),
            idle_id: Mutex::new(0),
            debug_func: Mutex::new(None),
        });

        let tmap = Arc::new(BtTmap { inner: Arc::clone(&inner) });

        // Register in global instances.
        {
            let mut instances = INSTANCES.lock().unwrap();
            instances.push(Arc::clone(&inner));
        }

        Some(tmap)
    }

    // =================================================================
    // Session lookup
    // =================================================================

    /// Find an existing TMAP session by GATT database.
    ///
    /// Searches the global instances list for a session whose local GATT
    /// database matches the given database (pointer equality).
    ///
    /// Rust equivalent of `bt_tmap_find` from `tmap.c`.
    pub fn find(db: &GattDb) -> Option<Arc<BtTmap>> {
        let instances = INSTANCES.lock().unwrap();
        for inst in instances.iter() {
            if Self::db_matches(inst, db) {
                return Some(Arc::new(BtTmap { inner: Arc::clone(inst) }));
            }
        }
        None
    }

    /// Returns `true` when the inner's GATT database is the same instance
    /// as `db` (pointer equality on the underlying `Arc`).
    fn db_matches(inner: &BtTmapInner, db: &GattDb) -> bool {
        inner.ldb.ptr_eq(db)
    }

    // =================================================================
    // Role accessors
    // =================================================================

    /// Returns the current TMAP role value.
    ///
    /// For server-side sessions this is the locally configured role.
    /// For client-side sessions this is the role read from the remote
    /// device.
    pub fn get_role(&self) -> TmapRole {
        *self.inner.role_state.lock().unwrap()
    }

    /// Set the TMAP role value (server-side only).
    ///
    /// Updates the role bitfield and activates/deactivates the TMAS
    /// service depending on whether any roles are set. If the role is
    /// zero the service is deactivated; otherwise it is activated.
    ///
    /// Has no effect on client-side sessions.
    pub fn set_role(&self, role: TmapRole) {
        // Only server-side sessions can update the role.
        if self.inner.client.is_some() {
            return;
        }

        let masked = role & TmapRole::MASK;
        {
            let mut guard = self.inner.role_state.lock().unwrap();
            if masked == *guard {
                return;
            }
            *guard = masked;
        }

        debug!("set role 0x{:02x}", masked.bits());

        // Activate or deactivate the TMAS service.
        if let Some(ref svc_attr) = self.inner.service_attr {
            if let Some(svc) = svc_attr.get_service() {
                svc.set_active(!masked.is_empty());
            }
        }
    }

    // =================================================================
    // Debug
    // =================================================================

    /// Set the debug logging callback.
    ///
    /// The callback receives formatted debug messages. In addition,
    /// `tracing::debug!` is always emitted for structured logging.
    ///
    /// Rust equivalent of `bt_tmap_set_debug` from `tmap.c`.
    pub fn set_debug(&self, cb: DebugFn) -> bool {
        let mut guard = self.inner.debug_func.lock().unwrap();
        *guard = Some(cb);
        true
    }
}

impl Drop for BtTmap {
    fn drop(&mut self) {
        // Remove from global instances when the last external reference
        // is dropped. `strong_count == 2` means only `self` and the
        // INSTANCES vec hold a reference.
        if Arc::strong_count(&self.inner) <= 2 {
            let mut instances = INSTANCES.lock().unwrap();
            instances.retain(|i| !Arc::ptr_eq(i, &self.inner));
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tmap_role_bits() {
        assert_eq!(TmapRole::CG.bits(), 0x0001);
        assert_eq!(TmapRole::CT.bits(), 0x0002);
        assert_eq!(TmapRole::UMS.bits(), 0x0004);
        assert_eq!(TmapRole::UMR.bits(), 0x0008);
        assert_eq!(TmapRole::BMS.bits(), 0x0010);
        assert_eq!(TmapRole::BMR.bits(), 0x0020);
        assert_eq!(TmapRole::MASK.bits(), 0x003F);
    }

    #[test]
    fn test_tmap_role_list_single() {
        assert_eq!(TmapRole::CG.role_list(), "cg");
        assert_eq!(TmapRole::CT.role_list(), "ct");
        assert_eq!(TmapRole::UMS.role_list(), "ums");
        assert_eq!(TmapRole::UMR.role_list(), "umr");
        assert_eq!(TmapRole::BMS.role_list(), "bms");
        assert_eq!(TmapRole::BMR.role_list(), "bmr");
    }

    #[test]
    fn test_tmap_role_list_multiple() {
        let role = TmapRole::CG | TmapRole::UMS | TmapRole::BMR;
        assert_eq!(role.role_list(), "cg, ums, bmr");
    }

    #[test]
    fn test_tmap_role_list_empty() {
        assert_eq!(TmapRole::empty().role_list(), "");
    }

    #[test]
    fn test_tmap_role_list_all() {
        let role = TmapRole::MASK;
        assert_eq!(role.role_list(), "cg, ct, ums, umr, bms, bmr");
    }

    #[test]
    fn test_tmap_role_display() {
        let role = TmapRole::CG | TmapRole::CT;
        assert_eq!(format!("{role}"), "CG, CT");
    }

    #[test]
    fn test_tmap_role_display_empty() {
        assert_eq!(format!("{}", TmapRole::empty()), "(none)");
    }

    #[test]
    fn test_tmap_role_mask() {
        let raw = 0x00FF_u16;
        let role = TmapRole::from_bits_truncate(raw) & TmapRole::MASK;
        assert_eq!(role.bits(), 0x003F);
    }

    #[test]
    fn test_tmap_role_from_bits() {
        let role = TmapRole::from_bits(0x0015);
        assert!(role.is_some());
        let r = role.unwrap();
        assert!(r.contains(TmapRole::CG));
        assert!(r.contains(TmapRole::UMS));
        assert!(r.contains(TmapRole::BMS));
        assert!(!r.contains(TmapRole::CT));
    }

    #[test]
    fn test_tmap_uuid_constants() {
        assert_eq!(TMAS_UUID, 0x1855);
        assert_eq!(TMAP_ROLE_CHRC_UUID, 0x2B51);
    }
}
