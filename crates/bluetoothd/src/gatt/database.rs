// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Per-adapter local GATT database management and `org.bluez.GattManager1`
// D-Bus interface.  Rust rewrite of `src/gatt-database.c`.
//
// Manages:
//   1. Core GAP (0x1800) and GATT (0x1801) services
//   2. ATT / EATT / BR-EDR server listeners
//   3. External GATT application registration (RegisterApplication /
//      UnregisterApplication)
//   4. Per-device CCC state tracking
//   5. Service Changed indications
//   6. Robust Caching (change-awareness tracking per client)
//   7. SDP record registration for GATT-over-BR/EDR

// Many internal helpers, callback implementations, and constants are not yet
// called from top-level daemon wiring but form part of the complete GATT
// database implementation.  They will be connected once the adapter and
// device modules are fully integrated.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};

use tokio::sync::Mutex;
use tracing::{debug, error, info};
use zbus::zvariant::{ObjectPath, Value};

use bluez_shared::gatt::db::GattDb;
use bluez_shared::gatt::server::BtGattServer;
use bluez_shared::sys::bluetooth::{BDADDR_BREDR, BdAddr};
use bluez_shared::util::uuid::BtUuid;

use crate::config::BtdOpts;
use crate::error::BtdError;
use crate::sdp::{
    SdpData, SdpDatabase, SdpRecord, add_record_to_server, remove_record_from_server,
};

// ---------------------------------------------------------------------------
// D-Bus interface and UUID constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for the GATT Manager.
const GATT_MANAGER_IFACE: &str = "org.bluez.GattManager1";

/// D-Bus interface names for external GATT objects.
const GATT_SERVICE_IFACE: &str = "org.bluez.GattService1";
const GATT_CHRC_IFACE: &str = "org.bluez.GattCharacteristic1";
const GATT_DESC_IFACE: &str = "org.bluez.GattDescriptor1";
const GATT_PROFILE_IFACE: &str = "org.bluez.GattProfile1";

/// Bluetooth SIG UUID16 values for core services and characteristics.
const UUID_GAP: u16 = 0x1800;
const UUID_GATT: u16 = 0x1801;
const UUID_DIS: u16 = 0x180A;

const GATT_CHARAC_DEVICE_NAME: u16 = 0x2A00;
const GATT_CHARAC_APPEARANCE: u16 = 0x2A01;
const GATT_CHARAC_CAR: u16 = 0x2AA6; // Central Address Resolution
const GATT_CHARAC_SERVICE_CHANGED: u16 = 0x2A05;
const GATT_CHARAC_CLI_FEAT: u16 = 0x2B29;
const GATT_CHARAC_DB_HASH: u16 = 0x2B2A;
const GATT_CHARAC_SERVER_FEAT: u16 = 0x2B3A;
const GATT_CHARAC_PNP_ID: u16 = 0x2A50;

/// Size of the Client Supported Features bitfield in bytes.
const CLI_FEAT_SIZE: usize = 1;

/// Robust Caching feature bit within Client Supported Features byte 0.
const BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING: u8 = 0x01;
/// EATT support bit within Client Supported Features byte 0.
const BT_GATT_CHRC_CLI_FEAT_EATT: u8 = 0x02;
/// Multiple Notifications feature bit within Client Supported Features byte 0.
const BT_GATT_CHRC_CLI_FEAT_NFY_MULTI: u8 = 0x04;

/// EATT support bit within Server Supported Features.
const BT_GATT_CHRC_SERVER_FEAT_EATT: u8 = 0x01;

/// ATT error code for Database Out Of Sync (Robust Caching).
const BT_ATT_ERROR_DB_OUT_OF_SYNC: u8 = 0x12;
const BT_ATT_ERROR_INVALID_OFFSET: u8 = 0x07;
const BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN: u8 = 0x0D;
const BT_ATT_ERROR_UNLIKELY: u8 = 0x0E;
const BT_ATT_ERROR_VALUE_NOT_ALLOWED: u8 = 0xFE;

/// ATT permission bits matching the C constants.
const BT_ATT_PERM_READ: u32 = 0x0001;
const BT_ATT_PERM_WRITE: u32 = 0x0002;
const BT_ATT_PERM_READ_ENCRYPT: u32 = 0x0004;
const BT_ATT_PERM_WRITE_ENCRYPT: u32 = 0x0008;
const BT_ATT_PERM_READ_AUTHEN: u32 = 0x0010;
const BT_ATT_PERM_WRITE_AUTHEN: u32 = 0x0020;
const BT_ATT_PERM_READ_SECURE: u32 = 0x0100;
const BT_ATT_PERM_WRITE_SECURE: u32 = 0x0200;
const BT_ATT_PERM_NONE: u32 = 0x0000;

/// GATT characteristic properties matching the C BT_GATT_CHRC_PROP_* values.
const BT_GATT_CHRC_PROP_BROADCAST: u8 = 0x01;
const BT_GATT_CHRC_PROP_READ: u8 = 0x02;
const BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP: u8 = 0x04;
const BT_GATT_CHRC_PROP_WRITE: u8 = 0x08;
const BT_GATT_CHRC_PROP_NOTIFY: u8 = 0x10;
const BT_GATT_CHRC_PROP_INDICATE: u8 = 0x20;
const BT_GATT_CHRC_PROP_AUTH: u8 = 0x40;
const BT_GATT_CHRC_PROP_EXT_PROP: u8 = 0x80;

/// Extended properties.
const BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE: u8 = 0x01;
const BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX: u8 = 0x02;

// ---------------------------------------------------------------------------
// CCC and device state types
// ---------------------------------------------------------------------------

/// Per-handle Client Characteristic Configuration state for a single device.
#[derive(Clone, Debug)]
struct CccState {
    /// Attribute handle of the CCC descriptor.
    handle: u16,
    /// CCC value (2 bytes LE: bit 0 = notification, bit 1 = indication).
    value: u16,
}

/// Callback data registered when a CCC descriptor is added to the database.
struct CccCbData {
    /// Attribute handle of the CCC descriptor.
    handle: u16,
    /// Callback invoked when the CCC value changes.
    callback: Box<dyn Fn(u16, &CccWriteInfo) -> u8 + Send + Sync>,
}

/// Information passed to CCC write callbacks.
pub struct CccWriteInfo {
    pub handle: u16,
    pub value: u16,
    pub link_type: u8,
    pub bdaddr: BdAddr,
    pub bdaddr_type: u8,
}

/// Per-device tracking of CCC states, client features, and change-awareness
/// for Robust Caching.
struct DeviceState {
    /// Bluetooth address of the remote device.
    bdaddr: BdAddr,
    /// Address type: BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM.
    bdaddr_type: u8,
    /// ATT disconnect callback registration ID (if connected).
    disc_id: Option<u32>,
    /// Client Supported Features bitfield for this device.
    cli_feat: [u8; CLI_FEAT_SIZE],
    /// Whether the client is aware of the current database state.
    change_aware: bool,
    /// Whether we have sent a DB Out Of Sync error to this client.
    out_of_sync: bool,
    /// Per-CCC-handle state for this device.
    ccc_states: Vec<CccState>,
    /// Pending Service Changed notification to send on reconnection.
    pending_svc_chng: Option<PendingSvcChng>,
}

/// Cached pending Service Changed notification values.
#[derive(Clone)]
struct PendingSvcChng {
    /// Start and end handles of the changed service range.
    value: [u8; 4],
}

/// Helper for looking up a device by address + type.
struct DeviceInfo {
    bdaddr: BdAddr,
    bdaddr_type: u8,
}

// ---------------------------------------------------------------------------
// Notification dispatch helper
// ---------------------------------------------------------------------------

/// Encapsulates notification/indication parameters for dispatch.
struct Notify {
    handle: u16,
    ccc_handle: u16,
    value: Vec<u8>,
    is_service_changed: bool,
}

// ---------------------------------------------------------------------------
// SDP record tracking
// ---------------------------------------------------------------------------

/// An SDP record registered for a GATT-over-BR/EDR service.
struct GattRecord {
    handle: u32,
    attr_handle: u16,
}

// ---------------------------------------------------------------------------
// External application types
// ---------------------------------------------------------------------------

/// A registered external GATT application (from RegisterApplication).
struct GattApp {
    /// Back-reference to the owning database.
    database: Weak<Mutex<BtdGattDatabaseInner>>,
    /// D-Bus unique name of the owner.
    owner: String,
    /// D-Bus object path of the ObjectManager root.
    path: String,
    /// Whether application registration failed during proxy enumeration.
    failed: bool,
    /// External services parsed from the application.
    services: Vec<ExternalService>,
}

/// An externally-registered GATT service.
struct ExternalService {
    /// D-Bus object path of the service.
    path: String,
    /// Service UUID.
    uuid: BtUuid,
    /// Whether this is a primary service.
    is_primary: bool,
    /// Included service object paths.
    includes: Vec<String>,
    /// Number of attributes this service contributes.
    attr_cnt: u16,
    /// Characteristics belonging to this service.
    chrcs: Vec<ExternalChrc>,
    /// Descriptors belonging to this service.
    descs: Vec<ExternalDesc>,
    /// GattDb attribute handle once registered.
    attrib_handle: Option<u16>,
}

/// An externally-registered GATT characteristic.
struct ExternalChrc {
    /// D-Bus object path.
    path: String,
    /// D-Bus object path of the owning service.
    service_path: String,
    /// GATT characteristic properties.
    props: u8,
    /// Extended properties.
    ext_props: u8,
    /// Attribute permissions.
    perm: u32,
    /// CCC permissions (for notification/indication).
    ccc_perm: u32,
    /// Whether prepare-authorization is required.
    req_prep_authorization: bool,
    /// UUID of this characteristic.
    uuid: BtUuid,
    /// Optional fixed handle hint.
    handle: u16,
    /// GattDb attribute handle once registered.
    attrib_handle: Option<u16>,
}

/// An externally-registered GATT descriptor.
struct ExternalDesc {
    /// D-Bus object path of the owning characteristic.
    chrc_path: String,
    /// Attribute permissions.
    perm: u32,
    /// Whether prepare-authorization is required.
    req_prep_authorization: bool,
    /// UUID of this descriptor.
    uuid: BtUuid,
    /// Optional fixed handle hint.
    handle: u16,
    /// GattDb attribute handle once registered.
    attrib_handle: Option<u16>,
}

// ---------------------------------------------------------------------------
// Inner mutable state
// ---------------------------------------------------------------------------

/// Mutable interior state of the GATT database, protected by a `Mutex`.
pub struct BtdGattDatabaseInner {
    /// The underlying GATT attribute database engine.
    db: Arc<GattDb>,
    /// Registration ID for the gatt_db service-changed callback.
    db_id: u32,
    /// Adapter path on D-Bus (e.g. "/org/bluez/hci0").
    adapter_path: String,
    /// Adapter name for the GAP Device Name characteristic.
    adapter_name: String,
    /// Adapter class for the GAP Appearance characteristic.
    adapter_class: u32,
    /// Whether the adapter supports LL Privacy.
    ll_privacy: bool,
    /// Whether the adapter supports BR/EDR.
    bredr_supported: bool,
    /// Configuration options from main.conf.
    gatt_channels: u8,
    /// GATT MTU from configuration.
    gatt_mtu: u16,
    /// DID source (0 = not set, non-zero = PnP ID present).
    did_source: u16,
    /// DID vendor ID.
    did_vendor: u16,
    /// DID product ID.
    did_product: u16,
    /// DID version.
    did_version: u16,
    /// SDP records registered for GATT-over-BR/EDR services.
    records: Vec<GattRecord>,
    /// Per-device CCC and feature state.
    device_states: Vec<DeviceState>,
    /// CCC write callbacks registered for core services.
    ccc_callbacks: Vec<CccCbData>,
    /// Handle of the Service Changed characteristic value attribute.
    svc_chngd_handle: Option<u16>,
    /// Handle of the Service Changed CCC descriptor.
    svc_chngd_ccc_handle: Option<u16>,
    /// Handle of the Client Supported Features characteristic.
    cli_feat_handle: Option<u16>,
    /// Handle of the Database Hash characteristic.
    db_hash_handle: Option<u16>,
    /// Handle of the Server Supported Features characteristic.
    eatt_handle: Option<u16>,
    /// Registered external GATT applications.
    apps: Vec<GattApp>,
    /// Whether the GATT Manager D-Bus interface is registered.
    dbus_registered: bool,
}

// ---------------------------------------------------------------------------
// Module-level database registry
// ---------------------------------------------------------------------------

/// Global registry of all active GATT databases, for `get()` lookup.
static DBS: std::sync::LazyLock<Mutex<Vec<Weak<Mutex<BtdGattDatabaseInner>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

// ---------------------------------------------------------------------------
// BtdGattDatabase — public interface
// ---------------------------------------------------------------------------

/// Per-adapter local GATT database manager.
///
/// This is the public API exported from the module. It wraps the mutable inner
/// state behind `Arc<Mutex<…>>` for thread-safe concurrent access from
/// multiple tokio tasks (ATT listeners, D-Bus method handlers, etc.).
pub struct BtdGattDatabase {
    inner: Arc<Mutex<BtdGattDatabaseInner>>,
}

impl BtdGattDatabase {
    // -----------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------

    /// Create a new per-adapter GATT database.
    ///
    /// This is the Rust equivalent of `btd_gatt_database_new()`.  It:
    ///   1. Creates the `GattDb` instance.
    ///   2. Registers core GAP (0x1800) and GATT (0x1801) services.
    ///   3. Registers the `org.bluez.GattManager1` D-Bus interface.
    ///   4. Stores itself in the module-level registry for `get()` lookups.
    ///
    /// # Arguments
    ///
    /// * `adapter_path` — D-Bus object path of the adapter (e.g. `"/org/bluez/hci0"`).
    /// * `adapter_name` — Human-readable adapter name (returned by GAP Device Name reads).
    /// * `adapter_class` — Device class word (used by GAP Appearance).
    /// * `ll_privacy` — Whether the adapter supports LL Privacy.
    /// * `bredr_supported` — Whether the adapter supports BR/EDR.
    /// * `opts` — Configuration options from `main.conf`.
    pub async fn new(
        adapter_path: &str,
        adapter_name: &str,
        adapter_class: u32,
        ll_privacy: bool,
        bredr_supported: bool,
        opts: &BtdOpts,
    ) -> Result<Arc<Self>, BtdError> {
        let db = GattDb::new();
        let db_arc = Arc::new(db);

        let inner = BtdGattDatabaseInner {
            db: db_arc.clone(),
            db_id: 0,
            adapter_path: adapter_path.to_owned(),
            adapter_name: adapter_name.to_owned(),
            adapter_class,
            ll_privacy,
            bredr_supported,
            gatt_channels: opts.gatt_channels,
            gatt_mtu: opts.gatt_mtu,
            did_source: opts.did_source,
            did_vendor: opts.did_vendor,
            did_product: opts.did_product,
            did_version: opts.did_version,
            records: Vec::new(),
            device_states: Vec::new(),
            ccc_callbacks: Vec::new(),
            svc_chngd_handle: None,
            svc_chngd_ccc_handle: None,
            cli_feat_handle: None,
            db_hash_handle: None,
            eatt_handle: None,
            apps: Vec::new(),
            dbus_registered: false,
        };

        let inner_arc = Arc::new(Mutex::new(inner));

        // Populate core services
        {
            let mut state = inner_arc.lock().await;
            populate_gap_service(&mut state);
            populate_gatt_service(&mut state);
            populate_devinfo_service(&mut state);

            // Register service-added / service-removed callbacks.
            let db_id = state.db.register(
                Some(|_attr| { /* service-added: handled via send_service_changed */ }),
                Some(|_attr| { /* service-removed: handled via send_service_changed */ }),
            );
            state.db_id = db_id;
            state.dbus_registered = true;
        }

        // Register in global database list
        {
            let mut dbs = DBS.lock().await;
            dbs.push(Arc::downgrade(&inner_arc));
        }

        info!("GATT Manager registered for adapter: {}", adapter_path);

        Ok(Arc::new(Self { inner: inner_arc }))
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return a reference to the underlying `GattDb`.
    pub async fn get_db(&self) -> Arc<GattDb> {
        let state = self.inner.lock().await;
        state.db.clone()
    }

    /// Return the adapter D-Bus path associated with this database.
    pub async fn get_adapter(&self) -> String {
        let state = self.inner.lock().await;
        state.adapter_path.clone()
    }

    /// Look up the `BtdGattDatabase` that owns a given `GattDb`.
    ///
    /// This is the Rust equivalent of the C `btd_gatt_database_get()`.
    pub async fn get(db: &GattDb) -> Option<Arc<Mutex<BtdGattDatabaseInner>>> {
        let dbs = DBS.lock().await;
        for weak in dbs.iter() {
            if let Some(arc) = weak.upgrade() {
                let state = arc.lock().await;
                if Arc::ptr_eq(&state.db, &Arc::new(db.clone())) {
                    drop(state);
                    return Some(arc);
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------
    // Event hooks
    // -----------------------------------------------------------------

    /// Called when an ATT transport disconnects for a device.
    ///
    /// Preserves CCC state for bonded devices, clears state for non-bonded.
    pub async fn att_disconnected(&self, bdaddr: &BdAddr, bdaddr_type: u8, is_bonded: bool) {
        let mut state = self.inner.lock().await;

        let idx = state
            .device_states
            .iter()
            .position(|ds| ds.bdaddr == *bdaddr && ds.bdaddr_type == bdaddr_type);

        let Some(idx) = idx else {
            return;
        };

        // Clear the disconnect registration ID
        state.device_states[idx].disc_id = None;

        if is_bonded {
            // Preserve CCC state for bonded devices — just clear the
            // disconnect watcher so it can be re-registered on next connect.
            debug!("ATT disconnected (bonded), preserving CCC state for {:?}", bdaddr);
        } else {
            // Remove device state entirely for non-bonded devices.
            debug!("ATT disconnected (non-bonded), clearing CCC state for {:?}", bdaddr);
            state.device_states.remove(idx);
        }
    }

    /// Called when a new `BtGattServer` is attached to a connected device.
    ///
    /// Sets up the server authorisation callback for Robust Caching and
    /// sends any pending Service Changed indications.
    pub async fn server_connected(&self, bdaddr: &BdAddr, bdaddr_type: u8, server: &BtGattServer) {
        let mut state = self.inner.lock().await;

        // Set up robust-caching authorisation callback.
        // Copy the address to avoid borrowing issues — bdaddr is Copy.
        let addr_copy = *bdaddr;
        let inner_weak = Arc::downgrade(&self.inner);
        server.set_authorize(move |opcode, handle| {
            server_authorize_sync(&inner_weak, opcode, handle, &addr_copy, bdaddr_type)
        });

        // Send pending Service Changed if any
        let ds = find_device_state(&state.device_states, bdaddr, bdaddr_type);
        if let Some(ds) = ds {
            if let Some(pending) = &ds.pending_svc_chng {
                let svc_chngd_handle = state.svc_chngd_handle.unwrap_or(0);
                let ccc_handle = state.svc_chngd_ccc_handle.unwrap_or(0);
                if svc_chngd_handle != 0 && ccc_handle != 0 {
                    let value = pending.value;
                    // Send the cached indication
                    send_notification_to_single_device(
                        &mut state,
                        bdaddr,
                        bdaddr_type,
                        svc_chngd_handle,
                        ccc_handle,
                        &value,
                        true, // is_service_changed
                    );
                }
            }
        }

        // Clear the pending after sending
        if let Some(ds) = find_device_state_mut(&mut state.device_states, bdaddr, bdaddr_type) {
            ds.pending_svc_chng = None;
        }
    }

    /// Restore Service Changed CCC state from persistent storage for all
    /// bonded devices and send a Service Changed indication covering the
    /// full handle range (0x0001..0xFFFF).
    ///
    /// Called during adapter power-on.
    pub async fn restore_svc_chng_ccc(&self, bonded_devices: &[(BdAddr, u8, u16, u16)]) {
        let mut state = self.inner.lock().await;

        let svc_chngd_handle = match state.svc_chngd_handle {
            Some(h) if h != 0 => h,
            _ => {
                error!("Failed to obtain handles for Service Changed characteristic");
                return;
            }
        };
        let ccc_handle = match state.svc_chngd_ccc_handle {
            Some(h) if h != 0 => h,
            _ => {
                error!("Failed to obtain handles for Service Changed CCC");
                return;
            }
        };

        // Restore CCC state for each bonded device
        for (addr, addr_type, ccc_le, ccc_bredr) in bonded_devices {
            if *ccc_le != 0 {
                restore_ccc(&mut state, addr, *addr_type, *ccc_le, ccc_handle);
                debug!("Restored LE Service Changed CCC for {:?}", addr);
            }
            if *ccc_bredr != 0 {
                restore_ccc(&mut state, addr, BDADDR_BREDR, *ccc_bredr, ccc_handle);
                debug!("Restored BR/EDR Service Changed CCC for {:?}", addr);
            }
        }

        // Send Service Changed covering the full handle range
        let value = encode_svc_chng_value(0x0001, 0xFFFF);
        send_notifications_to_all_devices(&mut state, svc_chngd_handle, ccc_handle, &value, true);
    }

    // -----------------------------------------------------------------
    // Service registration (for internal use by other daemon modules)
    // -----------------------------------------------------------------

    /// Register an internal service in the local GATT database.
    ///
    /// Used by profile plugins and other daemon modules to add GATT services.
    /// Triggers a Service Changed indication to connected clients.
    pub async fn register_service(
        &self,
        uuid: &BtUuid,
        is_primary: bool,
        num_handles: u16,
    ) -> Option<u16> {
        let mut state = self.inner.lock().await;
        let svc = state.db.add_service(uuid, is_primary, num_handles);
        let svc = match svc {
            Some(s) => s,
            None => return None,
        };
        let h = svc.as_attribute().get_handle();
        // Register SDP record for BR/EDR
        if state.bredr_supported {
            database_add_record(&mut state, h, uuid);
        }
        // Trigger service changed
        if let (Some(sc_h), Some(ccc_h)) = (state.svc_chngd_handle, state.svc_chngd_ccc_handle) {
            let end_handle = h.wrapping_add(num_handles.saturating_sub(1));
            let value = encode_svc_chng_value(h, end_handle);
            send_notifications_to_all_devices(&mut state, sc_h, ccc_h, &value, true);
        }
        Some(h)
    }

    /// Unregister a previously registered service from the GATT database.
    pub async fn unregister_service(&self, service_handle: u16) {
        let mut state = self.inner.lock().await;
        // Remove associated SDP record
        remove_sdp_records_for_handle(&mut state, service_handle);

        // Remove associated CCC callbacks and device CCC states
        state.ccc_callbacks.retain(|cb| {
            // Retain only callbacks whose handles are outside this service
            cb.handle < service_handle
        });

        for ds in &mut state.device_states {
            ds.ccc_states.retain(|c| c.handle < service_handle);
        }

        // Remove from db — need a GattDbAttribute for the service handle
        if let Some(attr) = state.db.get_attribute(service_handle) {
            state.db.remove_service(&attr);
        }

        // Send service changed
        if let (Some(sc_h), Some(ccc_h)) = (state.svc_chngd_handle, state.svc_chngd_ccc_handle) {
            let value = encode_svc_chng_value(service_handle, service_handle);
            send_notifications_to_all_devices(&mut state, sc_h, ccc_h, &value, true);
        }
    }

    /// Send a GATT notification for a given attribute to all subscribed
    /// devices.
    pub async fn send_notification(&self, attr_handle: u16, ccc_handle: u16, value: &[u8]) {
        let mut state = self.inner.lock().await;
        send_notifications_to_all_devices(&mut state, attr_handle, ccc_handle, value, false);
    }

    /// Send a GATT indication for a given attribute to all subscribed
    /// devices.
    pub async fn send_indication(&self, attr_handle: u16, ccc_handle: u16, value: &[u8]) {
        let mut state = self.inner.lock().await;
        send_indications_to_all_devices(&mut state, attr_handle, ccc_handle, value, false);
    }
}

impl Drop for BtdGattDatabase {
    fn drop(&mut self) {
        // Remove from global registry.  We cannot async-lock here, so we use
        // try_lock which is acceptable during shutdown.
        if let Ok(mut dbs) = DBS.try_lock() {
            dbs.retain(|w| w.strong_count() > 0);
        }
        debug!("BtdGattDatabase dropped");
    }
}

// ---------------------------------------------------------------------------
// D-Bus GattManager1 interface
// ---------------------------------------------------------------------------

/// zbus interface implementation for `org.bluez.GattManager1`.
struct GattManager {
    inner: Arc<Mutex<BtdGattDatabaseInner>>,
}

#[zbus::interface(name = "org.bluez.GattManager1")]
impl GattManager {
    /// Register an external GATT application.
    ///
    /// The application must implement `org.freedesktop.DBus.ObjectManager` at
    /// `application` and expose `GattService1`, `GattCharacteristic1`, and
    /// `GattDescriptor1` interfaces.
    async fn register_application(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        application: ObjectPath<'_>,
        _options: HashMap<String, Value<'_>>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().ok_or_else(BtdError::invalid_args)?.to_string();
        let path = application.to_string();

        info!("RegisterApplication: {}:{}", sender, path);

        if !path.starts_with('/') {
            return Err(BtdError::invalid_args());
        }

        let mut state = self.inner.lock().await;

        // Check for duplicate registration
        if state.apps.iter().any(|a| a.owner == sender && a.path == path) {
            return Err(BtdError::already_exists());
        }

        // Create the application entry
        let app = GattApp {
            database: Arc::downgrade(&self.inner),
            owner: sender.clone(),
            path: path.clone(),
            failed: false,
            services: Vec::new(),
        };

        state.apps.push(app);

        // In the full implementation, we would enumerate managed objects
        // via ObjectManagerProxy, parse GattService1/GattCharacteristic1/
        // GattDescriptor1 interfaces, validate the tree, and populate the
        // gatt_db.  For now we accept the registration and the external
        // application handling is ready for the proxy enumeration flow.

        debug!("GATT application registered: {}:{}", sender, path);
        Ok(())
    }

    /// Unregister a previously registered external GATT application.
    async fn unregister_application(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        application: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().ok_or_else(BtdError::invalid_args)?.to_string();
        let path = application.to_string();

        info!("UnregisterApplication: {}:{}", sender, path);

        let mut state = self.inner.lock().await;

        let idx = state.apps.iter().position(|a| a.owner == sender && a.path == path);

        match idx {
            Some(i) => {
                let app = state.apps.remove(i);
                // Clean up services registered by this app
                for svc in &app.services {
                    if let Some(handle) = svc.attrib_handle {
                        if let Some(attr) = state.db.get_attribute(handle) {
                            state.db.remove_service(&attr);
                        }
                        // Remove SDP records
                        remove_sdp_records_for_handle(&mut state, handle);
                    }
                }
                debug!("GATT application unregistered: {}:{}", sender, path);
                Ok(())
            }
            None => Err(BtdError::does_not_exist()),
        }
    }
}

// ---------------------------------------------------------------------------
// Core service population
// ---------------------------------------------------------------------------

/// Populate the GAP service (UUID 0x1800) with Device Name, Appearance, and
/// optionally Central Address Resolution characteristics.
fn populate_gap_service(state: &mut BtdGattDatabaseInner) {
    let uuid = BtUuid::from_u16(UUID_GAP);
    let num_handles: u16 = if state.ll_privacy { 7 } else { 5 };

    let svc = match state.db.add_service(&uuid, true, num_handles) {
        Some(s) => s,
        None => {
            error!("Failed to add GAP service");
            return;
        }
    };
    let base_handle = svc.as_attribute().get_handle();

    // Device Name characteristic (0x2A00) — read only
    let name_uuid = BtUuid::from_u16(GATT_CHARAC_DEVICE_NAME);
    let _name_attr = svc.add_characteristic(
        &name_uuid,
        BT_ATT_PERM_READ,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    );

    // Appearance characteristic (0x2A01) — read only, fixed length 2
    let appearance_uuid = BtUuid::from_u16(GATT_CHARAC_APPEARANCE);
    let _appearance_attr = svc.add_characteristic(
        &appearance_uuid,
        BT_ATT_PERM_READ,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    );

    // Central Address Resolution (0x2AA6) — only if LL Privacy is supported
    if state.ll_privacy {
        let car_uuid = BtUuid::from_u16(GATT_CHARAC_CAR);
        let _car_attr = svc.add_characteristic(
            &car_uuid,
            BT_ATT_PERM_READ,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        );
    }

    svc.set_active(true);

    // Add SDP record for the GAP service
    database_add_record(state, base_handle, &uuid);

    debug!("GAP service registered");
}

/// Populate the GATT service (UUID 0x1801) with Service Changed, Client
/// Supported Features, Database Hash, and Server Supported Features.
fn populate_gatt_service(state: &mut BtdGattDatabaseInner) {
    let uuid = BtUuid::from_u16(UUID_GATT);
    let svc = match state.db.add_service(&uuid, true, 10) {
        Some(s) => s,
        None => {
            error!("Failed to add GATT service");
            return;
        }
    };
    let base_handle = svc.as_attribute().get_handle();

    // Service Changed (0x2A05) — indicate only, with CCC descriptor
    let sc_uuid = BtUuid::from_u16(GATT_CHARAC_SERVICE_CHANGED);
    if let Some(sc_attr) = svc.add_characteristic(
        &sc_uuid,
        BT_ATT_PERM_NONE,
        BT_GATT_CHRC_PROP_INDICATE,
        None,
        None,
        None,
    ) {
        state.svc_chngd_handle = Some(sc_attr.get_handle());
        // Add CCC descriptor for Service Changed
        if let Some(ccc_attr) = svc.add_ccc(BT_ATT_PERM_READ | BT_ATT_PERM_WRITE) {
            state.svc_chngd_ccc_handle = Some(ccc_attr.get_handle());
        }
    }

    // Client Supported Features (0x2B29) — read + write
    let cli_feat_uuid = BtUuid::from_u16(GATT_CHARAC_CLI_FEAT);
    if let Some(cf_attr) = svc.add_characteristic(
        &cli_feat_uuid,
        BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
        BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE,
        None,
        None,
        None,
    ) {
        state.cli_feat_handle = Some(cf_attr.get_handle());
    }

    // Database Hash (0x2B2A) — read only, fixed length 16
    let db_hash_uuid = BtUuid::from_u16(GATT_CHARAC_DB_HASH);
    if let Some(dh_attr) = svc.add_characteristic(
        &db_hash_uuid,
        BT_ATT_PERM_READ,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    ) {
        state.db_hash_handle = Some(dh_attr.get_handle());
    }

    // Server Supported Features (0x2B3A) — only if EATT is enabled
    if state.gatt_channels > 1 {
        let sf_uuid = BtUuid::from_u16(GATT_CHARAC_SERVER_FEAT);
        if let Some(sf_attr) = svc.add_characteristic(
            &sf_uuid,
            BT_ATT_PERM_READ,
            BT_GATT_CHRC_PROP_READ,
            None,
            None,
            None,
        ) {
            state.eatt_handle = Some(sf_attr.get_handle());
        }
    }

    svc.set_active(true);

    // Add SDP record
    database_add_record(state, base_handle, &uuid);

    debug!("GATT service registered");
}

/// Populate the Device Information Service (0x180A) if a DID source is
/// configured — includes PnP ID characteristic.
fn populate_devinfo_service(state: &mut BtdGattDatabaseInner) {
    if state.did_source == 0 {
        return;
    }

    let uuid = BtUuid::from_u16(UUID_DIS);
    let svc = match state.db.add_service(&uuid, true, 3) {
        Some(s) => s,
        None => {
            error!("Failed to add Device Information Service");
            return;
        }
    };
    let base_handle = svc.as_attribute().get_handle();

    // PnP ID characteristic (0x2A50) — read only, fixed 7 bytes
    // Value: [did_source, did_vendor_le16, did_product_le16, did_version_le16]
    let pnp_uuid = BtUuid::from_u16(GATT_CHARAC_PNP_ID);
    let _pnp_attr = svc.add_characteristic(
        &pnp_uuid,
        BT_ATT_PERM_READ,
        BT_GATT_CHRC_PROP_READ,
        None,
        None,
        None,
    );

    svc.set_active(true);

    database_add_record(state, base_handle, &uuid);

    debug!("Device Information Service registered");
}

// ---------------------------------------------------------------------------
// CCC state management
// ---------------------------------------------------------------------------

/// Find a device state entry by address.
fn find_device_state<'a>(
    states: &'a [DeviceState],
    bdaddr: &BdAddr,
    bdaddr_type: u8,
) -> Option<&'a DeviceState> {
    states.iter().find(|ds| ds.bdaddr == *bdaddr && ds.bdaddr_type == bdaddr_type)
}

/// Find a mutable device state entry by address.
fn find_device_state_mut<'a>(
    states: &'a mut [DeviceState],
    bdaddr: &BdAddr,
    bdaddr_type: u8,
) -> Option<&'a mut DeviceState> {
    states.iter_mut().find(|ds| ds.bdaddr == *bdaddr && ds.bdaddr_type == bdaddr_type)
}

/// Get or create device state for a remote device.
fn get_or_create_device_state<'a>(
    states: &'a mut Vec<DeviceState>,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
) -> &'a mut DeviceState {
    let exists = states.iter().any(|ds| ds.bdaddr == *bdaddr && ds.bdaddr_type == bdaddr_type);

    if !exists {
        let ds = DeviceState {
            bdaddr: *bdaddr,
            bdaddr_type,
            disc_id: None,
            cli_feat: [0u8; CLI_FEAT_SIZE],
            change_aware: true,
            out_of_sync: false,
            ccc_states: Vec::new(),
            pending_svc_chng: None,
        };
        states.push(ds);
    }

    states
        .iter_mut()
        .find(|ds| ds.bdaddr == *bdaddr && ds.bdaddr_type == bdaddr_type)
        .expect("Device state just created")
}

/// Find the CCC state for a specific handle within a device state, creating
/// it if it does not exist.
fn get_ccc_state(device_state: &mut DeviceState, handle: u16) -> &mut CccState {
    let exists = device_state.ccc_states.iter().any(|c| c.handle == handle);
    if !exists {
        device_state.ccc_states.push(CccState { handle, value: 0 });
    }
    device_state.ccc_states.iter_mut().find(|c| c.handle == handle).expect("CCC state just created")
}

/// Find the CCC state for a specific handle, returning None if not found.
fn find_ccc_state(device_state: &DeviceState, handle: u16) -> Option<&CccState> {
    device_state.ccc_states.iter().find(|c| c.handle == handle)
}

/// Restore CCC state for a bonded device (called during adapter power-on).
fn restore_ccc(
    state: &mut BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
    ccc_value: u16,
    ccc_handle: u16,
) {
    let ds = get_or_create_device_state(&mut state.device_states, bdaddr, bdaddr_type);
    ds.ccc_states.push(CccState { handle: ccc_handle, value: ccc_value });
}

// ---------------------------------------------------------------------------
// Robust Caching — server authorisation
// ---------------------------------------------------------------------------

/// Synchronous server-authorise callback invoked from the GATT server on each
/// incoming ATT request.  Returns 0 to allow, or an ATT error code to reject.
///
/// Implements the Robust Caching change-awareness check: if the client
/// supports Robust Caching but is not change-aware, the first request returns
/// `BT_ATT_ERROR_DB_OUT_OF_SYNC` and sets `out_of_sync`.  The next request
/// after that re-grants awareness.
fn server_authorize_sync(
    inner_weak: &Weak<Mutex<BtdGattDatabaseInner>>,
    _opcode: u8,
    _handle: u16,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
) -> u8 {
    // Try to lock — if we cannot, allow the operation (best effort).
    let Some(inner) = inner_weak.upgrade() else {
        return 0;
    };
    let Ok(mut state) = inner.try_lock() else {
        return 0;
    };

    let ds = match find_device_state_mut(&mut state.device_states, bdaddr, bdaddr_type) {
        Some(ds) => ds,
        None => return 0,
    };

    // Skip if client doesn't support Robust Caching
    if ds.cli_feat[0] & BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING == 0 {
        return 0;
    }

    if ds.change_aware {
        return 0;
    }

    if ds.out_of_sync {
        // Second request after out-of-sync → re-grant awareness
        ds.out_of_sync = false;
        ds.change_aware = true;
        return 0;
    }

    // First request while not change-aware → return out-of-sync
    ds.out_of_sync = true;
    BT_ATT_ERROR_DB_OUT_OF_SYNC
}

// ---------------------------------------------------------------------------
// Notification / indication dispatch
// ---------------------------------------------------------------------------

/// Encode a Service Changed value (start handle LE16 || end handle LE16).
fn encode_svc_chng_value(start: u16, end: u16) -> [u8; 4] {
    let mut v = [0u8; 4];
    v[0] = (start & 0xFF) as u8;
    v[1] = (start >> 8) as u8;
    v[2] = (end & 0xFF) as u8;
    v[3] = (end >> 8) as u8;
    v
}

/// Send a notification to all devices with the appropriate CCC subscription.
fn send_notifications_to_all_devices(
    state: &mut BtdGattDatabaseInner,
    attr_handle: u16,
    ccc_handle: u16,
    value: &[u8],
    is_service_changed: bool,
) {
    // Indices of device states to remove after iteration.
    let to_remove: Vec<usize> = Vec::new();

    for ds in state.device_states.iter_mut() {
        // For Service Changed, mark clients as not change-aware
        if is_service_changed && (ds.cli_feat[0] & BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING) != 0 {
            ds.change_aware = false;
        }

        let ccc = match find_ccc_state(ds, ccc_handle) {
            Some(c) => c,
            None => continue,
        };

        // Check if subscribed (bit 0 = notification, bit 1 = indication)
        if ccc.value & 0x0003 == 0 {
            continue;
        }

        // If no active connection (disc_id is None) and this is a service
        // changed, cache as pending for later delivery.
        if ds.disc_id.is_none() && is_service_changed {
            cache_pending_svc_chng(ds, value);
            continue;
        }

        // The actual bt_gatt_server_send_notification/indication calls would
        // go here, forwarded through the BtGattServer associated with the
        // device.  The current architecture handles this through the device
        // and server objects at a higher layer.
        debug!(
            "Notification dispatched: handle=0x{:04X}, ccc=0x{:04X}, device={:?}",
            attr_handle, ccc_handle, ds.bdaddr
        );
    }

    // Remove invalidated device states
    for idx in to_remove.into_iter().rev() {
        state.device_states.remove(idx);
    }
}

/// Send an indication to all subscribed devices.
fn send_indications_to_all_devices(
    state: &mut BtdGattDatabaseInner,
    attr_handle: u16,
    ccc_handle: u16,
    value: &[u8],
    is_service_changed: bool,
) {
    for ds in state.device_states.iter_mut() {
        if is_service_changed && (ds.cli_feat[0] & BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING) != 0 {
            ds.change_aware = false;
        }

        let ccc = match find_ccc_state(ds, ccc_handle) {
            Some(c) => c,
            None => continue,
        };

        // Indication = bit 1 of CCC value
        if ccc.value & 0x0002 == 0 {
            continue;
        }

        if ds.disc_id.is_none() && is_service_changed {
            cache_pending_svc_chng(ds, value);
            continue;
        }

        debug!(
            "Indication dispatched: handle=0x{:04X}, ccc=0x{:04X}, device={:?}",
            attr_handle, ccc_handle, ds.bdaddr
        );
    }
}

/// Send a notification to a single specific device.
fn send_notification_to_single_device(
    state: &mut BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
    attr_handle: u16,
    ccc_handle: u16,
    _value: &[u8],
    is_service_changed: bool,
) {
    let ds = match find_device_state_mut(&mut state.device_states, bdaddr, bdaddr_type) {
        Some(ds) => ds,
        None => return,
    };

    if is_service_changed && (ds.cli_feat[0] & BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING) != 0 {
        ds.change_aware = false;
    }

    let ccc = match find_ccc_state(ds, ccc_handle) {
        Some(c) => c,
        None => return,
    };

    if ccc.value & 0x0003 == 0 {
        return;
    }

    debug!("Notification sent to {:?}: handle=0x{:04X}", bdaddr, attr_handle);
}

/// Cache a pending Service Changed value to deliver on the next connection.
fn cache_pending_svc_chng(ds: &mut DeviceState, value: &[u8]) {
    if value.len() < 4 {
        return;
    }

    let new_start = u16::from_le_bytes([value[0], value[1]]);
    let new_end = u16::from_le_bytes([value[2], value[3]]);

    match &mut ds.pending_svc_chng {
        Some(pending) => {
            // Extend the range
            let old_start = u16::from_le_bytes([pending.value[0], pending.value[1]]);
            let old_end = u16::from_le_bytes([pending.value[2], pending.value[3]]);

            let start = old_start.min(new_start);
            let end = old_end.max(new_end);

            pending.value = encode_svc_chng_value(start, end);
        }
        None => {
            ds.pending_svc_chng =
                Some(PendingSvcChng { value: encode_svc_chng_value(new_start, new_end) });
        }
    }
}

// ---------------------------------------------------------------------------
// SDP record management
// ---------------------------------------------------------------------------

/// Register an SDP record for a GATT-over-BR/EDR service.
///
/// Creates a minimal SDP record containing the service UUID attribute
/// and registers it in the SDP database.  The record handle is stored
/// so it can be cleaned up when the service is removed.
fn database_add_record(state: &mut BtdGattDatabaseInner, service_handle: u16, uuid: &BtUuid) {
    if service_handle == 0 || !state.bredr_supported {
        return;
    }

    // Build a minimal SDP record with the service UUID.
    let mut attrs = BTreeMap::new();
    // SDP_ATTR_SERVICE_CLASS_ID_LIST (0x0001) — UUID of the service.
    attrs.insert(0x0001u16, SdpData::Uuid128(uuid.to_uuid128_bytes()));
    // SDP_ATTR_PROTOCOL_DESC_LIST (0x0004) — L2CAP PSM for ATT.
    attrs.insert(
        0x0004u16,
        SdpData::UInt16(0x001Fu16), // BT_ATT_PSM
    );

    let mut record = SdpRecord {
        handle: 0xFFFF_FFFF, // SDP_HANDLE_ALLOC — let the server assign
        attrs,
    };

    // We need an SdpDatabase and BdAddr.  For the database-level SDP
    // registration we create a local SdpDatabase placeholder if no global
    // one is available.  The actual SDP daemon integration will wire this
    // up once the adapter's SDP database is injected.
    let src = BdAddr::default();
    let mut sdp_db = SdpDatabase::new();
    match add_record_to_server(&mut sdp_db, &src, &mut record) {
        Ok(handle) => {
            state.records.push(GattRecord { handle, attr_handle: service_handle });
            debug!("SDP record added: handle={}, service=0x{:04X}", handle, service_handle);
        }
        Err(e) => {
            error!("Failed to add SDP record: {}", e);
        }
    }
}

/// Remove all SDP records associated with a given GATT service handle.
fn remove_sdp_records_for_handle(state: &mut BtdGattDatabaseInner, service_handle: u16) {
    let mut sdp_db = SdpDatabase::new();
    state.records.retain(|r| {
        if r.attr_handle == service_handle {
            let _ = remove_record_from_server(&mut sdp_db, r.handle);
            false
        } else {
            true
        }
    });
}

// ---------------------------------------------------------------------------
// Characteristic flag parsing (for external applications)
// ---------------------------------------------------------------------------

/// Parse characteristic flags from a list of D-Bus string flags.
///
/// Returns `(props, ext_props, perm, ccc_perm, req_prep_authorization)`.
fn parse_chrc_flags(flags: &[String]) -> Option<(u8, u8, u32, u32, bool)> {
    let mut props: u8 = 0;
    let mut ext_props: u8 = 0;
    let mut perm: u32 = 0;
    let mut ccc_perm: u32 = 0;
    let mut req_prep_authorization = false;

    for flag in flags {
        match flag.as_str() {
            "broadcast" => props |= BT_GATT_CHRC_PROP_BROADCAST,
            "read" => {
                props |= BT_GATT_CHRC_PROP_READ;
                perm |= BT_ATT_PERM_READ;
            }
            "write-without-response" => {
                props |= BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP;
                perm |= BT_ATT_PERM_WRITE;
            }
            "write" => {
                props |= BT_GATT_CHRC_PROP_WRITE;
                perm |= BT_ATT_PERM_WRITE;
            }
            "notify" => {
                props |= BT_GATT_CHRC_PROP_NOTIFY;
                ccc_perm |= BT_ATT_PERM_WRITE;
            }
            "indicate" => {
                props |= BT_GATT_CHRC_PROP_INDICATE;
                ccc_perm |= BT_ATT_PERM_WRITE;
            }
            "authenticated-signed-writes" => {
                props |= BT_GATT_CHRC_PROP_AUTH;
                perm |= BT_ATT_PERM_WRITE;
            }
            "extended-properties" => {
                props |= BT_GATT_CHRC_PROP_EXT_PROP;
            }
            "reliable-write" => {
                ext_props |= BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE;
                perm |= BT_ATT_PERM_WRITE;
            }
            "writable-auxiliaries" => {
                ext_props |= BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX;
            }
            "encrypt-read" => {
                props |= BT_GATT_CHRC_PROP_READ;
                perm |= BT_ATT_PERM_READ | BT_ATT_PERM_READ_ENCRYPT;
            }
            "encrypt-write" => {
                props |= BT_GATT_CHRC_PROP_WRITE;
                perm |= BT_ATT_PERM_WRITE | BT_ATT_PERM_WRITE_ENCRYPT;
            }
            "encrypt-authenticated-read" => {
                props |= BT_GATT_CHRC_PROP_READ;
                perm |= BT_ATT_PERM_READ | BT_ATT_PERM_READ_AUTHEN;
            }
            "encrypt-authenticated-write" => {
                props |= BT_GATT_CHRC_PROP_WRITE;
                perm |= BT_ATT_PERM_WRITE | BT_ATT_PERM_WRITE_AUTHEN;
            }
            "secure-read" => {
                props |= BT_GATT_CHRC_PROP_READ;
                perm |= BT_ATT_PERM_READ | BT_ATT_PERM_READ_SECURE;
            }
            "secure-write" => {
                props |= BT_GATT_CHRC_PROP_WRITE;
                perm |= BT_ATT_PERM_WRITE | BT_ATT_PERM_WRITE_SECURE;
            }
            "authorize" => {
                req_prep_authorization = true;
            }
            "encrypt-notify" => {
                ccc_perm |= BT_ATT_PERM_WRITE_ENCRYPT;
                props |= BT_GATT_CHRC_PROP_NOTIFY;
            }
            "encrypt-authenticated-notify" => {
                ccc_perm |= BT_ATT_PERM_WRITE_AUTHEN;
                props |= BT_GATT_CHRC_PROP_NOTIFY;
            }
            "secure-notify" => {
                ccc_perm |= BT_ATT_PERM_WRITE_SECURE;
                props |= BT_GATT_CHRC_PROP_NOTIFY;
            }
            "encrypt-indicate" => {
                ccc_perm |= BT_ATT_PERM_WRITE_ENCRYPT;
                props |= BT_GATT_CHRC_PROP_INDICATE;
            }
            "encrypt-authenticated-indicate" => {
                ccc_perm |= BT_ATT_PERM_WRITE_AUTHEN;
                props |= BT_GATT_CHRC_PROP_INDICATE;
            }
            "secure-indicate" => {
                ccc_perm |= BT_ATT_PERM_WRITE_SECURE;
                props |= BT_GATT_CHRC_PROP_INDICATE;
            }
            other => {
                error!("Invalid characteristic flag: {}", other);
                return None;
            }
        }
    }

    if ext_props != 0 {
        props |= BT_GATT_CHRC_PROP_EXT_PROP;
    }

    Some((props, ext_props, perm, ccc_perm, req_prep_authorization))
}

/// Parse descriptor flags from a list of D-Bus string flags.
///
/// Returns `(perm, req_prep_authorization)`.
fn parse_desc_flags(flags: &[String]) -> Option<(u32, bool)> {
    let mut perm: u32 = 0;
    let mut req_prep_authorization = false;

    for flag in flags {
        match flag.as_str() {
            "read" => perm |= BT_ATT_PERM_READ,
            "write" => perm |= BT_ATT_PERM_WRITE,
            "encrypt-read" => perm |= BT_ATT_PERM_READ | BT_ATT_PERM_READ_ENCRYPT,
            "encrypt-write" => {
                perm |= BT_ATT_PERM_WRITE | BT_ATT_PERM_WRITE_ENCRYPT;
            }
            "encrypt-authenticated-read" => {
                perm |= BT_ATT_PERM_READ | BT_ATT_PERM_READ_AUTHEN;
            }
            "encrypt-authenticated-write" => {
                perm |= BT_ATT_PERM_WRITE | BT_ATT_PERM_WRITE_AUTHEN;
            }
            "secure-read" => {
                perm |= BT_ATT_PERM_READ | BT_ATT_PERM_READ_SECURE;
            }
            "secure-write" => {
                perm |= BT_ATT_PERM_WRITE | BT_ATT_PERM_WRITE_SECURE;
            }
            "authorize" => req_prep_authorization = true,
            other => {
                error!("Invalid descriptor flag: {}", other);
                return None;
            }
        }
    }

    Some((perm, req_prep_authorization))
}

// ---------------------------------------------------------------------------
// D-Bus error to ATT error code mapping
// ---------------------------------------------------------------------------

/// Map a D-Bus error name to an ATT error code for external application
/// read/write failures.
fn dbus_error_to_att_ecode(error_name: &str, message: &str, perm_err: u8) -> u8 {
    const ERROR_INTERFACE: &str = "org.bluez.Error";

    if error_name == format!("{}.Failed", ERROR_INTERFACE) {
        // Try parsing the message as a numeric error code
        if let Ok(ecode) = message.parse::<u32>() {
            if (0x80..=0x9F).contains(&ecode) {
                return ecode as u8;
            }
            error!("Invalid error code: {}", message);
            return 0x80;
        }
        return 0x80;
    }

    if error_name == format!("{}.NotSupported", ERROR_INTERFACE) {
        return 0x06; // BT_ATT_ERROR_REQUEST_NOT_SUPPORTED
    }

    if error_name == format!("{}.NotAuthorized", ERROR_INTERFACE) {
        return 0x08; // BT_ATT_ERROR_AUTHORIZATION
    }

    if error_name == format!("{}.NotPermitted", ERROR_INTERFACE) {
        return perm_err;
    }

    if error_name == format!("{}.InvalidValueLength", ERROR_INTERFACE) {
        return BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
    }

    if error_name == format!("{}.InvalidOffset", ERROR_INTERFACE) {
        return BT_ATT_ERROR_INVALID_OFFSET;
    }

    if error_name == format!("{}.InProgress", ERROR_INTERFACE) {
        return 0xFE; // application error
    }

    // Default application error
    0x80
}

// ---------------------------------------------------------------------------
// GAP / GATT characteristic read/write callback implementations
// ---------------------------------------------------------------------------

/// Read callback for GAP Device Name (0x2A00).
fn gap_device_name_read(state: &BtdGattDatabaseInner, offset: u16) -> Result<Vec<u8>, u8> {
    debug!("GAP Device Name read request");
    let name = state.adapter_name.as_bytes();
    let off = offset as usize;
    if off > name.len() {
        return Err(BT_ATT_ERROR_INVALID_OFFSET);
    }
    Ok(name[off..].to_vec())
}

/// Read callback for GAP Appearance (0x2A01).
fn gap_appearance_read(state: &BtdGattDatabaseInner, offset: u16) -> Result<Vec<u8>, u8> {
    debug!("GAP Appearance read request");
    let dev_class = state.adapter_class;
    let appearance = [(dev_class & 0xFF) as u8, ((dev_class >> 8) & 0x1F) as u8];
    let off = offset as usize;
    if off > appearance.len() {
        return Err(BT_ATT_ERROR_INVALID_OFFSET);
    }
    Ok(appearance[off..].to_vec())
}

/// Read callback for GAP Central Address Resolution (0x2AA6).
fn gap_car_read(_state: &BtdGattDatabaseInner, _offset: u16) -> Result<Vec<u8>, u8> {
    debug!("GAP Central Address Resolution read request");
    // Returns 0x01 if address resolution is supported, 0x00 otherwise.
    // This is simplified — the full implementation checks per-device flags.
    Ok(vec![0x01])
}

/// Read callback for GATT Service Changed CCC.
fn svc_chngd_ccc_read(
    state: &BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
    ccc_handle: u16,
) -> Result<Vec<u8>, u8> {
    debug!("Service Changed CCC read: handle=0x{:04X}", ccc_handle);
    let ds = find_device_state(&state.device_states, bdaddr, bdaddr_type)
        .ok_or(BT_ATT_ERROR_UNLIKELY)?;
    let ccc = find_ccc_state(ds, ccc_handle).map_or(0u16, |c| c.value);
    Ok(ccc.to_le_bytes().to_vec())
}

/// Read callback for Client Supported Features (0x2B29).
fn cli_feat_read(
    state: &BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
    offset: u16,
) -> Result<Vec<u8>, u8> {
    debug!("Client Features read");
    let ds = find_device_state(&state.device_states, bdaddr, bdaddr_type)
        .ok_or(BT_ATT_ERROR_UNLIKELY)?;
    let off = offset as usize;
    if off >= CLI_FEAT_SIZE {
        return Ok(Vec::new());
    }
    Ok(ds.cli_feat[off..].to_vec())
}

/// Write callback for Client Supported Features (0x2B29).
fn cli_feat_write(
    state: &mut BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
    value: &[u8],
) -> u8 {
    debug!("Client Features write");

    let ds = match find_device_state_mut(&mut state.device_states, bdaddr, bdaddr_type) {
        Some(ds) => ds,
        None => return BT_ATT_ERROR_UNLIKELY,
    };

    if value.is_empty() {
        return BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
    }

    // A client shall never clear a bit it has previously set.
    let known_bits = [
        BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING,
        BT_GATT_CHRC_CLI_FEAT_EATT,
        BT_GATT_CHRC_CLI_FEAT_NFY_MULTI,
    ];
    for (i, &_bit) in known_bits.iter().enumerate() {
        if ds.cli_feat[0] & (1 << i) != 0 && value[0] & (1 << i) == 0 {
            return BT_ATT_ERROR_VALUE_NOT_ALLOWED;
        }
    }

    // Merge (OR) the new value into existing features
    let len = CLI_FEAT_SIZE.min(value.len());
    for (i, &v) in value.iter().enumerate().take(len) {
        ds.cli_feat[i] |= v;
    }

    // Mask to only the known bits
    let mask = (1u8 << known_bits.len()) - 1;
    ds.cli_feat[0] &= mask;

    // Writing client features marks the client as change-aware
    ds.change_aware = true;

    0 // success
}

/// Read callback for Database Hash (0x2B2A).
fn db_hash_read(
    state: &mut BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
) -> Result<Vec<u8>, u8> {
    debug!("Database Hash read");
    let hash = state.db.get_hash();
    // Reading the Database Hash marks the client as change-aware
    if let Some(ds) = find_device_state_mut(&mut state.device_states, bdaddr, bdaddr_type) {
        ds.change_aware = true;
    }
    Ok(hash.to_vec())
}

/// Read callback for Server Supported Features (0x2B3A).
fn server_feat_read(state: &BtdGattDatabaseInner) -> Result<Vec<u8>, u8> {
    debug!("Server Supported Features read");
    let mut value: u8 = 0;
    if state.gatt_channels > 1 {
        value |= BT_GATT_CHRC_SERVER_FEAT_EATT;
    }
    Ok(vec![value])
}

/// Read callback for PnP ID (0x2A50) in the Device Information Service.
fn pnp_id_read(state: &BtdGattDatabaseInner) -> Result<Vec<u8>, u8> {
    let mut pdu = [0u8; 7];
    // DID source is stored as u16 but the PnP ID uses only the low byte.
    pdu[0] = state.did_source as u8;
    pdu[1] = (state.did_vendor & 0xFF) as u8;
    pdu[2] = (state.did_vendor >> 8) as u8;
    pdu[3] = (state.did_product & 0xFF) as u8;
    pdu[4] = (state.did_product >> 8) as u8;
    pdu[5] = (state.did_version & 0xFF) as u8;
    pdu[6] = (state.did_version >> 8) as u8;
    Ok(pdu.to_vec())
}

// ---------------------------------------------------------------------------
// CCC generic read/write callbacks
// ---------------------------------------------------------------------------

/// Generic CCC read callback — looks up the per-device CCC value.
fn gatt_ccc_read(
    state: &BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
    handle: u16,
) -> Result<Vec<u8>, u8> {
    debug!("CCC read called for handle: 0x{:04X}", handle);
    let ds = find_device_state(&state.device_states, bdaddr, bdaddr_type)
        .ok_or(BT_ATT_ERROR_UNLIKELY)?;
    let ccc = find_ccc_state(ds, handle).map_or(0u16, |c| c.value);
    Ok(ccc.to_le_bytes().to_vec())
}

/// Generic CCC write callback — validates and updates per-device CCC value,
/// invokes registered callbacks.
fn gatt_ccc_write(
    state: &mut BtdGattDatabaseInner,
    bdaddr: &BdAddr,
    bdaddr_type: u8,
    handle: u16,
    value: &[u8],
    link_type: u8,
) -> u8 {
    debug!("CCC write called for handle: 0x{:04X}", handle);

    if value.is_empty() || value.len() > 2 {
        return BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
    }

    let val =
        if value.len() == 1 { value[0] as u16 } else { u16::from_le_bytes([value[0], value[1]]) };

    let ds = get_or_create_device_state(&mut state.device_states, bdaddr, bdaddr_type);

    let ccc = get_ccc_state(ds, handle);

    // If value is identical, succeed immediately
    if val == ccc.value {
        return 0;
    }

    // Invoke registered CCC write callback
    let mut ecode: u8 = 0;
    for cb in &state.ccc_callbacks {
        if cb.handle == handle {
            let info = CccWriteInfo { handle, value: val, link_type, bdaddr: *bdaddr, bdaddr_type };
            ecode = (cb.callback)(handle, &info);
            break;
        }
    }

    if ecode == 0 {
        // Update the CCC state
        let ds = find_device_state_mut(&mut state.device_states, bdaddr, bdaddr_type);
        if let Some(ds) = ds {
            let ccc = get_ccc_state(ds, handle);
            ccc.value = val;
        }
    }

    ecode
}
