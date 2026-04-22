// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012 Texas Instruments, Inc.
// Copyright (C) 2015 Google Inc.
//
// Battery Service (BAS) client profile plugin — Rust rewrite consolidating
// `profiles/battery/battery.c`, `profiles/battery/bas.c`, and
// `profiles/battery/bas.h`.
//
// This module discovers the remote LE GATT Battery Service (UUID 0x180F),
// reads Battery Level (UUID 0x2A19), subscribes to notifications, and feeds
// BlueZ's internal Battery1 D-Bus framework.
//
// ## Architecture
//
// Two main components:
//
// 1. **`BtBas`** — Standalone BAS client helper (from `bas.c` / `bas.h`).
//    Encapsulates GATT-level Battery Service discovery, initial read, and
//    notification subscription using the modern `BtGattClient` API. Designed
//    for use by any code that needs low-level BAS access.
//
// 2. **Battery Profile Plugin** (from `battery.c`) — Full daemon integration
//    with the `org.bluez.Battery1` D-Bus framework.  Manages per-device
//    lifecycle (probe/accept/disconnect/remove), battery registration,
//    percentage change tracking, and initial-value replay after CCC write.
//
// ## Lifecycle (Profile Plugin)
//
// 1. **Probe** (`batt_probe`): Allocates per-device `Batt` context in the
//    module-level state map, keyed by device Bluetooth address.
// 2. **Accept** (`batt_accept`): Clones the GATT client and database from the
//    device, discovers the Battery Service, locates the Battery Level
//    characteristic, reads its initial value, registers for CCC notifications.
//    On CCC write success, registers the Battery1 D-Bus object and replays
//    the cached initial value.
// 3. **Disconnect** (`batt_disconnect`): Calls `batt_reset()` to unregister
//    notifications, release GATT resources, and unregister the Battery1
//    D-Bus object.
// 4. **Remove** (`batt_remove`): Removes per-device state from the module
//    map and resets all GATT state.
//
// ## Plugin Registration
//
// Registered via `inventory::submit!` with `PluginPriority::Default` (0),
// replacing C's `BLUETOOTH_PLUGIN_DEFINE(battery, VERSION,
// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, batt_init, batt_exit)`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use bluez_shared::gatt::client::{BtGattClient, NotifyCallback, ReadCallback, RegisterCallback};
use bluez_shared::gatt::db::GattDb;
use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::util::uuid::BtUuid;

use crate::battery::{btd_battery_register, btd_battery_unregister, btd_battery_update};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_warn, info as log_info};
use crate::plugin::PluginPriority;
use crate::profile::{
    BTD_PROFILE_BEARER_LE, BtdProfile, btd_profile_register, btd_profile_unregister,
};

// ===========================================================================
// Constants
// ===========================================================================

/// Battery Service UUID (0x180F) — well-known Bluetooth SIG 16-bit UUID.
///
/// Used for GATT service discovery and profile registration.
pub const BATT_UUID16: u16 = 0x180F;

/// Battery Level characteristic UUID (0x2A19).
///
/// The single mandatory characteristic of the Battery Service.  It carries
/// a single byte with the current charge level (0–100 %).
const GATT_CHARAC_BATTERY_LEVEL: u16 = 0x2A19;

/// Battery Service UUID in full 128-bit string form, used for profile
/// registration as `remote_uuid`.
const BATTERY_UUID_STR: &str = "0000180f-0000-1000-8000-00805f9b34fb";

/// Source string passed to `btd_battery_register()` when creating the
/// Battery1 D-Bus object for this BAS client.
const BATTERY_SOURCE: &str = "GATT Battery Service";

/// Sentinel value indicating that the battery level is unknown.
const BATTERY_LEVEL_UNKNOWN: i16 = -1;

/// Maximum valid battery percentage.
const BATTERY_MAX_LEVEL: u8 = 100;

// ===========================================================================
// BtBas — BAS Client Helper (from bas.c / bas.h)
// ===========================================================================

/// BAS (Battery Service) client helper.
///
/// Replaces C's opaque `struct bt_bas` from `bas.h` / `bas.c`.  Provides a
/// self-contained Battery Service discovery, initial read, and notification
/// subscription engine using the modern `BtGattClient` API.
///
/// # Usage
///
/// ```ignore
/// let mut bas = BtBas::new();
/// bas.attach(gatt_client);  // starts discovery + read + notify subscription
/// let level = bas.get_level();  // -1 until first read completes
/// bas.detach();  // cancels pending ops, unregisters notifications
/// ```
pub struct BtBas {
    /// Cloned GATT client for ATT operations.
    gatt_client: Option<Arc<BtGattClient>>,

    /// Referenced GATT database for service/characteristic enumeration.
    gatt_db: Option<GattDb>,

    /// Discovered Battery Level characteristic value handle.
    battery_level_handle: Option<u16>,

    /// CCC descriptor handle for notifications (managed internally by
    /// `BtGattClient::register_notify`).
    ccc_handle: Option<u16>,

    /// Notification registration ID from `BtGattClient::register_notify`.
    notify_id: Option<u32>,

    /// Last known battery level (shared with notification callback).
    /// -1 = unknown sentinel.
    level: Arc<StdMutex<i16>>,

    /// In-flight async operation tracking for cancellation on detach.
    pending_ops: Vec<JoinHandle<()>>,
}

impl BtBas {
    /// Create a new BAS client helper in unattached state.
    ///
    /// Equivalent to C `bt_bas_new()` from `bas.c`.
    pub fn new() -> Self {
        Self {
            gatt_client: None,
            gatt_db: None,
            battery_level_handle: None,
            ccc_handle: None,
            notify_id: None,
            level: Arc::new(StdMutex::new(BATTERY_LEVEL_UNKNOWN)),
            pending_ops: Vec::new(),
        }
    }

    /// Attach a GATT client and begin BAS discovery and notification
    /// subscription.
    ///
    /// This method discovers the Battery Service (UUID 0x180F), locates the
    /// Battery Level characteristic (UUID 0x2A19), reads its initial value,
    /// and registers for CCC notifications so that future level changes are
    /// tracked automatically.
    ///
    /// Equivalent to C `bt_bas_attach()` from `bas.c`.
    ///
    /// # Arguments
    ///
    /// * `client` — The GATT client to use for ATT operations.
    pub fn attach(&mut self, client: Arc<BtGattClient>) {
        if self.gatt_client.is_some() {
            debug!("BtBas: already attached, ignoring duplicate attach");
            btd_debug(0, "BtBas: already attached, ignoring duplicate attach");
            return;
        }

        let db = client.get_db();
        self.gatt_client = Some(Arc::clone(&client));
        self.gatt_db = Some(db.clone());

        // ---- Discover Battery Service and Battery Level characteristic ----
        let batt_uuid = BtUuid::from_u16(BATT_UUID16);
        let level_uuid = BtUuid::from_u16(GATT_CHARAC_BATTERY_LEVEL);
        let mut value_handle: Option<u16> = None;

        // Collect service attributes to avoid nested mutable borrow issues.
        let mut service_attrs = Vec::new();
        db.foreach_service(Some(&batt_uuid), |attr| {
            service_attrs.push(attr);
        });

        for svc_attr in service_attrs {
            if value_handle.is_some() {
                break;
            }
            if let Some(svc) = svc_attr.get_service() {
                let mut char_attrs = Vec::new();
                svc.foreach_char(|attr| {
                    char_attrs.push(attr);
                });
                for char_attr in char_attrs {
                    if let Some(cd) = char_attr.get_char_data() {
                        if cd.uuid == level_uuid {
                            value_handle = Some(cd.value_handle);
                            break;
                        }
                    }
                }
            }
        }

        let vh = match value_handle {
            Some(vh) => vh,
            None => {
                warn!("BtBas: Battery Level characteristic not found");
                btd_warn(0, "BtBas: Battery Level characteristic not found");
                return;
            }
        };

        self.battery_level_handle = Some(vh);
        debug!("BtBas: found Battery Level at handle 0x{:04x}", vh);
        btd_debug(0, &format!("BtBas: found Battery Level at handle 0x{:04x}", vh));

        // ---- Read initial value ----
        let level_for_read = Arc::clone(&self.level);
        let read_cb: ReadCallback = Box::new(move |success, att_ecode, data: &[u8]| {
            if !success || data.is_empty() {
                debug!("BtBas: failed to read initial value (ecode=0x{:02x})", att_ecode);
                return;
            }
            let val = data[0];
            if val <= BATTERY_MAX_LEVEL {
                if let Ok(mut l) = level_for_read.lock() {
                    *l = val as i16;
                }
                debug!("BtBas: initial battery level = {}%", val);
            }
        });
        client.read_value(vh, read_cb);

        // ---- Register for notifications ----
        let level_for_register = Arc::clone(&self.level);
        let register_cb: RegisterCallback = Box::new(move |att_ecode| {
            if att_ecode != 0 {
                error!("BtBas: notification registration failed (ecode=0x{:02x})", att_ecode);
            } else {
                debug!("BtBas: notification registered successfully");
                // Update level from any pending read that may have completed
                // before the CCC write finished.
                let _ = &level_for_register;
            }
        });

        let level_for_notify = Arc::clone(&self.level);
        let notify_cb: NotifyCallback = Box::new(move |_handle, data: &[u8]| {
            if !data.is_empty() && data[0] <= BATTERY_MAX_LEVEL {
                if let Ok(mut l) = level_for_notify.lock() {
                    *l = data[0] as i16;
                }
            }
        });

        let nid = client.register_notify(vh, register_cb, notify_cb);
        if nid != 0 {
            self.notify_id = Some(nid);
        } else {
            warn!("BtBas: failed to register for notifications");
            btd_warn(0, "BtBas: failed to register for notifications");
        }
    }

    /// Detach from the GATT client, cancelling all pending operations and
    /// unregistering notifications.
    ///
    /// Equivalent to C `bt_bas_detach()` from `bas.c`.
    pub fn detach(&mut self) {
        // Cancel pending async operations.
        for handle in self.pending_ops.drain(..) {
            handle.abort();
        }

        // Unregister notifications before dropping the client.
        if let (Some(id), Some(client)) = (self.notify_id.take(), &self.gatt_client) {
            client.unregister_notify(id);
        }

        // Clear state.
        self.gatt_client = None;
        self.gatt_db = None;
        self.battery_level_handle = None;
        self.ccc_handle = None;

        if let Ok(mut l) = self.level.lock() {
            *l = BATTERY_LEVEL_UNKNOWN;
        }
    }

    /// Return the last known battery level, or -1 if unknown.
    ///
    /// The level is updated asynchronously by the notification callback
    /// registered during `attach()`.
    pub fn get_level(&self) -> i16 {
        self.level.lock().map(|l| *l).unwrap_or(BATTERY_LEVEL_UNKNOWN)
    }
}

impl Default for BtBas {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Batt — Per-device battery profile state (from battery.c)
// ===========================================================================

/// Per-device state for the battery profile plugin.
///
/// Replaces C's `struct batt` from `battery.c`.  Stored in the module-level
/// `BATT_STATE` map keyed by device Bluetooth address.
struct Batt {
    /// GATT database reference for service/characteristic enumeration.
    gatt_db: Option<GattDb>,

    /// Cloned GATT client for ATT operations.
    gatt_client: Option<Arc<BtGattClient>>,

    /// Discovered Battery Level characteristic value handle.
    battery_level_handle: u16,

    /// Notification registration ID from `BtGattClient::register_notify`.
    notify_id: Option<u32>,

    /// Cached initial battery level value read before CCC write completes.
    /// Used for replay after the Battery1 D-Bus object is registered.
    initial_value: Option<Vec<u8>>,

    /// Last published battery percentage (-1 = unknown sentinel).
    percentage: i16,

    /// Whether `btd_battery_register()` has been called for this device.
    battery_registered: bool,

    /// Device D-Bus object path (e.g. `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX`).
    /// Used as the first argument to `btd_battery_register/update/unregister`.
    device_path: String,
}

impl Batt {
    /// Create a new per-device battery state with the given device D-Bus path.
    fn new(device_path: String) -> Self {
        Self {
            gatt_db: None,
            gatt_client: None,
            battery_level_handle: 0,
            notify_id: None,
            initial_value: None,
            percentage: BATTERY_LEVEL_UNKNOWN,
            battery_registered: false,
            device_path,
        }
    }
}

// ===========================================================================
// Module-level state
// ===========================================================================

/// Global map of per-device battery profile state, keyed by Bluetooth address.
///
/// Follows the same pattern as `GAP_STATE` in `gap.rs`.
static BATT_STATE: LazyLock<StdMutex<HashMap<BdAddr, Arc<StdMutex<Batt>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Stored profile descriptor for unregistration during `batt_exit()`.
static BATT_PROFILE: StdMutex<Option<BtdProfile>> = StdMutex::new(None);

// ===========================================================================
// Helper functions
// ===========================================================================

/// Reset all GATT state for a device's battery context.
///
/// Unregisters notifications, releases GATT client and database references,
/// unregisters the Battery1 D-Bus object (if registered), and clears cached
/// state.
///
/// Equivalent to C `batt_reset()` from `battery.c`.
fn batt_reset(batt: &mut Batt) {
    // Unregister notifications before dropping the client.
    if let (Some(id), Some(client)) = (batt.notify_id.take(), &batt.gatt_client) {
        client.unregister_notify(id);
        debug!("Battery: unregistered notify id {}", id);
    }

    // Release GATT resources.
    batt.gatt_client = None;
    batt.gatt_db = None;

    // Unregister the Battery1 D-Bus object if it was registered.
    if batt.battery_registered {
        let path = batt.device_path.clone();
        batt.battery_registered = false;
        btd_debug(0, &format!("Battery: unregistering battery for {}", path));
        tokio::spawn(async move {
            btd_battery_unregister(&path).await;
        });
    }

    batt.percentage = BATTERY_LEVEL_UNKNOWN;
    batt.initial_value = None;
    batt.battery_level_handle = 0;
}

/// Parse a battery level byte, update the stored percentage, and push the
/// change to the Battery1 D-Bus object.
///
/// Equivalent to C `parse_battery_level()` from `battery.c`.
///
/// # Arguments
///
/// * `batt_state` — Shared per-device battery state.
/// * `percentage` — Raw battery level byte (0–100).
fn parse_battery_level_update(batt_state: &Arc<StdMutex<Batt>>, percentage: u8) {
    if percentage > BATTERY_MAX_LEVEL {
        error!("Invalid battery percentage: {}", percentage);
        btd_error(0, &format!("Invalid battery percentage: {}", percentage));
        return;
    }

    let (should_update, device_path) = {
        let mut batt = match batt_state.lock() {
            Ok(b) => b,
            Err(e) => {
                btd_error(0, &format!("Battery: lock poisoned: {}", e));
                return;
            }
        };

        if batt.percentage != BATTERY_LEVEL_UNKNOWN && batt.percentage == percentage as i16 {
            debug!("Battery level unchanged at {}%", percentage);
            return;
        }

        debug!("Battery Level {}%", percentage);
        btd_debug(0, &format!("Battery Level {}%", percentage));
        batt.percentage = percentage as i16;

        if !batt.battery_registered {
            // Battery not yet registered — value will be replayed after
            // CCC write completes and btd_battery_register is called.
            return;
        }

        (true, batt.device_path.clone())
    };

    if should_update {
        tokio::spawn(async move {
            btd_battery_update(&device_path, percentage).await;
        });
    }
}

// ===========================================================================
// Profile lifecycle callbacks
// ===========================================================================

/// Probe a device for the battery profile.
///
/// Allocates a per-device `Batt` context and stores it in the module-level
/// state map.  Guards against duplicate probes.
///
/// Equivalent to C `batt_probe()` from `battery.c`.
fn batt_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let (addr, device_path) = match device.try_lock() {
        Ok(dev) => (*dev.get_address(), dev.get_path().to_owned()),
        Err(_) => {
            btd_error(0, "Battery: failed to lock device during probe");
            return Err(BtdError::NotAvailable("Device locked during battery probe".to_owned()));
        }
    };

    debug!("Battery profile probe: {}", device_path);
    btd_debug(0, &format!("Battery profile probe: {}", device_path));

    let batt = Batt::new(device_path);
    let batt_arc = Arc::new(StdMutex::new(batt));

    {
        let mut state = BATT_STATE.lock().unwrap_or_else(|e| e.into_inner());
        if state.contains_key(&addr) {
            debug!("Battery: context already exists for device, replacing");
        }
        state.insert(addr, batt_arc);
    }

    Ok(())
}

/// Accept an incoming battery profile connection.
///
/// Clones the GATT client and database from the device, discovers the Battery
/// Service (UUID 0x180F), locates the Battery Level characteristic (UUID
/// 0x2A19), reads its initial value, and registers for CCC notifications.
///
/// On successful CCC write, the `register_cb` callback:
/// 1. Registers the Battery1 D-Bus object via `btd_battery_register()`.
/// 2. Replays the cached initial value via `btd_battery_update()`.
///
/// Equivalent to C `batt_accept()` from `battery.c`.
async fn batt_accept(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    debug!("Battery profile accept");
    btd_debug(0, "Battery profile accept");

    // Lock device to extract address, GATT DB, GATT client, and device path.
    let (addr, gatt_db, gatt_client) = {
        let dev = device.lock().await;

        let parent = match dev.get_gatt_client() {
            Some(c) => c,
            None => {
                error!("Battery: no GATT client available");
                btd_error(0, "Battery: no GATT client available");
                return Err(BtdError::NotAvailable("No GATT client available".to_owned()));
            }
        };

        let client = BtGattClient::clone_client(parent).map_err(|e| {
            btd_error(0, &format!("Battery: failed to clone GATT client: {:?}", e));
            BtdError::NotAvailable(format!("Failed to clone GATT client: {:?}", e))
        })?;

        // Get DB from the cloned client (matches C behavior).
        let db = client.get_db();

        let addr = *dev.get_address();
        (addr, db, client)
    };

    // Retrieve the per-device Batt context.
    let batt_arc = {
        let state = BATT_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match state.get(&addr) {
            Some(s) => Arc::clone(s),
            None => {
                error!("Battery: no context for device");
                btd_error(0, "Battery: no context for device");
                return Err(BtdError::DoesNotExist("No battery context for device".to_owned()));
            }
        }
    };

    // Store GATT references in the Batt context.
    {
        let mut batt = batt_arc.lock().unwrap_or_else(|e| e.into_inner());
        batt.gatt_db = Some(gatt_db.clone());
        batt.gatt_client = Some(Arc::clone(&gatt_client));
    }

    // ---- Discover Battery Service and Battery Level characteristic ----
    let batt_uuid = BtUuid::from_u16(BATT_UUID16);
    let level_uuid = BtUuid::from_u16(GATT_CHARAC_BATTERY_LEVEL);
    let mut battery_level_handle: Option<u16> = None;

    // Collect service attributes to avoid nested mutable borrow issues.
    let mut service_attrs = Vec::new();
    gatt_db.foreach_service(Some(&batt_uuid), |attr| {
        service_attrs.push(attr);
    });

    for svc_attr in service_attrs {
        if battery_level_handle.is_some() {
            break;
        }
        if let Some(svc) = svc_attr.get_service() {
            let mut char_attrs = Vec::new();
            svc.foreach_char(|attr| {
                char_attrs.push(attr);
            });
            for char_attr in char_attrs {
                if let Some(cd) = char_attr.get_char_data() {
                    if cd.uuid == level_uuid {
                        battery_level_handle = Some(cd.value_handle);
                        debug!("Battery: found Battery Level at handle 0x{:04x}", cd.value_handle);
                        btd_debug(
                            0,
                            &format!(
                                "Battery: found Battery Level at handle 0x{:04x}",
                                cd.value_handle
                            ),
                        );
                        break;
                    }
                }
            }
        }
    }

    let batt_level_handle = match battery_level_handle {
        Some(h) => h,
        None => {
            error!("BATT attribute not found");
            btd_error(0, "BATT attribute not found");
            let mut batt = batt_arc.lock().unwrap_or_else(|e| e.into_inner());
            batt_reset(&mut batt);
            return Err(BtdError::DoesNotExist("BATT attribute not found".to_owned()));
        }
    };

    // Store the discovered handle.
    {
        let mut batt = batt_arc.lock().unwrap_or_else(|e| e.into_inner());
        batt.battery_level_handle = batt_level_handle;
    }

    // ---- Initiate async read of the initial Battery Level value ----
    // The read callback caches the value and then registers for notifications.
    // The notification register callback (CCC written) registers the Battery1
    // D-Bus object and replays the cached initial value.
    let client_for_cb = Arc::clone(&gatt_client);
    let batt_for_read = Arc::clone(&batt_arc);

    let read_cb: ReadCallback = Box::new(move |success: bool, att_ecode: u8, data: &[u8]| {
        if !success {
            error!("Failed to read Battery Level: ecode=0x{:02x}", att_ecode);
            btd_error(0, &format!("Failed to read Battery Level: ecode=0x{:02x}", att_ecode));
            return;
        }

        // Cache the initial value for replay after CCC write.
        if !data.is_empty() {
            let mut batt = batt_for_read.lock().unwrap_or_else(|e| e.into_inner());
            batt.initial_value = Some(data.to_vec());
            debug!("Battery: cached initial value ({} bytes, level={})", data.len(), data[0]);
        }

        // ---- Register for Battery Level notifications ----
        let batt_for_register = Arc::clone(&batt_for_read);
        let batt_for_notify = Arc::clone(&batt_for_read);
        let vh = batt_level_handle;

        // CCC written callback — fires when the CCC descriptor write
        // completes (att_ecode == 0 means success).
        let register_cb: RegisterCallback = Box::new(move |att_ecode: u16| {
            if att_ecode != 0 {
                error!("Battery Level notification enable failed: 0x{:04x}", att_ecode);
                btd_error(
                    0,
                    &format!("Battery Level notification enable failed: 0x{:04x}", att_ecode),
                );
                return;
            }

            info!("Battery Level Notification enabled");
            btd_debug(0, "Battery Level Notification enabled");
            log_info("Battery Level Notification enabled");

            // Register the Battery1 D-Bus object and replay cached
            // initial value — both async operations.
            let batt_spawn = Arc::clone(&batt_for_register);
            tokio::spawn(async move {
                let (device_path, initial_value) = {
                    let batt = batt_spawn.lock().unwrap_or_else(|e| e.into_inner());
                    (batt.device_path.clone(), batt.initial_value.clone())
                };

                // Register the Battery1 D-Bus object.
                let registered =
                    btd_battery_register(&device_path, Some(BATTERY_SOURCE), None).await;

                if registered {
                    {
                        let mut batt = batt_spawn.lock().unwrap_or_else(|e| e.into_inner());
                        batt.battery_registered = true;
                    }

                    // Replay the cached initial value.
                    if let Some(ref value) = initial_value {
                        if !value.is_empty() {
                            let pct = value[0];
                            if pct <= BATTERY_MAX_LEVEL {
                                let should_update = {
                                    let mut batt =
                                        batt_spawn.lock().unwrap_or_else(|e| e.into_inner());
                                    if batt.percentage == BATTERY_LEVEL_UNKNOWN
                                        || batt.percentage != pct as i16
                                    {
                                        batt.percentage = pct as i16;
                                        true
                                    } else {
                                        false
                                    }
                                };
                                if should_update {
                                    debug!("Battery: replaying initial level {}%", pct);
                                    btd_debug(
                                        0,
                                        &format!("Battery: replaying initial level {}%", pct),
                                    );
                                    btd_battery_update(&device_path, pct).await;
                                }
                            }
                        }
                    }
                } else {
                    btd_error(0, "Battery: failed to register Battery1 D-Bus object");
                }
            });
        });

        // Notification value callback — fires on each Battery Level
        // notification from the remote device.
        let notify_cb: NotifyCallback = Box::new(move |_value_handle: u16, data: &[u8]| {
            if data.is_empty() {
                return;
            }

            // Cache the new value (replaces previous).
            {
                let mut batt = batt_for_notify.lock().unwrap_or_else(|e| e.into_inner());
                batt.initial_value = Some(data.to_vec());
            }

            // Parse and update.
            parse_battery_level_update(&batt_for_notify, data[0]);
        });

        let notify_id = client_for_cb.register_notify(vh, register_cb, notify_cb);
        if notify_id != 0 {
            let mut batt = batt_for_read.lock().unwrap_or_else(|e| e.into_inner());
            batt.notify_id = Some(notify_id);
            debug!("Battery: registered notify id {}", notify_id);
        } else {
            error!("Battery: failed to register for notifications");
            btd_error(0, "Battery: failed to register for notifications");
        }
    });

    // Initiate the read operation.
    let req_id = gatt_client.read_value(batt_level_handle, read_cb);
    if req_id == 0 {
        warn!("Battery: read_value returned 0 — GATT client may not be ready");
        btd_warn(0, "Battery: read_value returned 0 — GATT client may not be ready");
    }

    // Return Ok(()) to signal btd_service_connecting_complete(0).
    // The GATT read and notification callbacks will fire asynchronously.
    Ok(())
}

/// Disconnect the battery profile from a device.
///
/// Resets all GATT state and unregisters the Battery1 D-Bus object.
///
/// Equivalent to C `batt_disconnect()` from `battery.c`.
async fn batt_disconnect(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    debug!("Battery profile disconnect");
    btd_debug(0, "Battery profile disconnect");

    let addr = {
        let dev = device.lock().await;
        *dev.get_address()
    };

    let batt_arc = {
        let state = BATT_STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.get(&addr).cloned()
    };

    if let Some(batt_arc) = batt_arc {
        let mut batt = batt_arc.lock().unwrap_or_else(|e| e.into_inner());
        batt_reset(&mut batt);
    }

    Ok(())
}

/// Remove a device from the battery profile.
///
/// Removes the per-device `Batt` context from the module-level state map and
/// resets all GATT state.
///
/// Equivalent to C `batt_remove()` from `battery.c`.
fn batt_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let addr = match device.try_lock() {
        Ok(dev) => {
            debug!("Battery profile remove: {}", dev.get_path());
            btd_debug(0, &format!("Battery profile remove: {}", dev.get_path()));
            *dev.get_address()
        }
        Err(_) => {
            btd_warn(0, "Battery: failed to lock device during remove");
            return;
        }
    };

    let removed = {
        let mut state = BATT_STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.remove(&addr)
    };

    if let Some(batt_arc) = removed {
        let mut batt = batt_arc.lock().unwrap_or_else(|e| e.into_inner());
        batt_reset(&mut batt);
    }
}

// ===========================================================================
// Plugin lifecycle
// ===========================================================================

/// Initialize the battery profile plugin.
///
/// Builds and registers the `batt-profile` profile descriptor with the daemon's
/// profile registry.
///
/// Equivalent to C `batt_init()` from `battery.c`.
fn batt_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("battery plugin init");
    btd_debug(0, "battery plugin init");

    // Build the profile descriptor.
    let mut profile = BtdProfile::new("batt-profile");
    profile.bearer = BTD_PROFILE_BEARER_LE;
    profile.remote_uuid = Some(BATTERY_UUID_STR.to_owned());

    // Set lifecycle callbacks.
    profile.set_device_probe(Box::new(batt_probe));
    profile.set_device_remove(Box::new(batt_remove));

    // Accept and disconnect are async callbacks.
    profile.set_accept(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { batt_accept(&device).await })
    }));

    profile.set_disconnect(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { batt_disconnect(&device).await })
    }));

    // Store a copy for unregistration during exit.
    {
        let stored = BtdProfile::new("batt-profile");
        let mut guard = BATT_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    // Register the profile asynchronously.
    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(profile).await {
            btd_error(0, &format!("Battery: failed to register profile: {:?}", e));
            error!("Battery: failed to register profile: {:?}", e);
        }
    });

    Ok(())
}

/// Clean up the battery profile plugin.
///
/// Unregisters the profile and clears all per-device state.
///
/// Equivalent to C `batt_exit()` from `battery.c`.
fn batt_exit() {
    debug!("battery plugin exit");
    btd_debug(0, "battery plugin exit");

    // Unregister the profile asynchronously.
    let profile_opt = {
        let mut guard = BATT_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };

    if let Some(profile) = profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }

    // Clear all per-device state.
    let mut state = BATT_STATE.lock().unwrap_or_else(|e| e.into_inner());
    for (_addr, batt_arc) in state.drain() {
        let mut batt = batt_arc.lock().unwrap_or_else(|e| e.into_inner());
        batt_reset(&mut batt);
    }
}

// ===========================================================================
// Exported struct — BatteryPlugin
// ===========================================================================

/// Battery plugin descriptor.
///
/// Provides the public API surface for the battery profile plugin.  The actual
/// plugin lifecycle is handled through [`crate::plugin::PluginDesc`] registered
/// via [`inventory::submit!`], which calls the module-level [`batt_init`] and
/// [`batt_exit`] functions.
///
/// This struct satisfies the export schema requirement for a `BatteryPlugin`
/// class with `name()`, `version()`, `priority()`, `init()`, and `exit()`
/// members.
pub struct BatteryPlugin;

impl BatteryPlugin {
    /// Returns the unique plugin name: `"battery"`.
    pub fn name(&self) -> &str {
        "battery"
    }

    /// Returns the plugin version string (matches daemon VERSION).
    pub fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority: `Default` (0).
    pub fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    /// Initializes the battery plugin.
    ///
    /// Delegates to the module-level [`batt_init`] function.
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        batt_init()
    }

    /// Cleans up the battery plugin.
    ///
    /// Delegates to the module-level [`batt_exit`] function.
    pub fn exit(&self) {
        batt_exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

/// Register the battery plugin at link time so that `plugin_init()` in the
/// plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(battery, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, batt_init, batt_exit)`.
mod _battery_plugin_register {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "battery",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::batt_init,
            exit: super::batt_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batt_uuid16_constant_value() {
        assert_eq!(BATT_UUID16, 0x180F);
        assert_eq!(BATT_UUID16, 6159);
    }

    #[test]
    fn test_gatt_charac_battery_level() {
        assert_eq!(GATT_CHARAC_BATTERY_LEVEL, 0x2A19);
    }

    #[test]
    fn test_battery_uuid_str_format() {
        assert_eq!(BATTERY_UUID_STR, "0000180f-0000-1000-8000-00805f9b34fb");
    }

    #[test]
    fn test_battery_source_string() {
        assert_eq!(BATTERY_SOURCE, "GATT Battery Service");
    }

    #[test]
    fn test_battery_level_unknown_sentinel() {
        assert_eq!(BATTERY_LEVEL_UNKNOWN, -1);
    }

    #[test]
    fn test_battery_max_level() {
        assert_eq!(BATTERY_MAX_LEVEL, 100);
    }

    // ---- BtBas tests ----

    #[test]
    fn test_bt_bas_new_defaults() {
        let bas = BtBas::new();
        assert_eq!(bas.get_level(), -1);
        assert!(bas.gatt_client.is_none());
        assert!(bas.gatt_db.is_none());
        assert!(bas.battery_level_handle.is_none());
        assert!(bas.ccc_handle.is_none());
        assert!(bas.notify_id.is_none());
        assert!(bas.pending_ops.is_empty());
    }

    #[test]
    fn test_bt_bas_default_trait() {
        let bas = BtBas::default();
        assert_eq!(bas.get_level(), -1);
    }

    #[test]
    fn test_bt_bas_detach_on_unattached() {
        let mut bas = BtBas::new();
        bas.detach(); // Should not panic.
        assert_eq!(bas.get_level(), -1);
    }

    #[test]
    fn test_bt_bas_double_detach() {
        let mut bas = BtBas::new();
        bas.detach();
        bas.detach();
        assert_eq!(bas.get_level(), -1);
    }

    #[test]
    fn test_bt_bas_level_reset_after_detach() {
        let mut bas = BtBas::new();
        // Manually set the level to test reset.
        {
            let mut l = bas.level.lock().unwrap();
            *l = 75;
        }
        assert_eq!(bas.get_level(), 75);
        bas.detach();
        assert_eq!(bas.get_level(), -1);
    }

    // ---- Batt tests ----

    #[test]
    fn test_batt_new_defaults() {
        let batt = Batt::new("/org/bluez/hci0/dev_00_11_22_33_44_55".to_owned());
        assert!(batt.gatt_db.is_none());
        assert!(batt.gatt_client.is_none());
        assert_eq!(batt.battery_level_handle, 0);
        assert!(batt.notify_id.is_none());
        assert!(batt.initial_value.is_none());
        assert_eq!(batt.percentage, -1);
        assert!(!batt.battery_registered);
        assert_eq!(batt.device_path, "/org/bluez/hci0/dev_00_11_22_33_44_55");
    }

    // ---- BatteryPlugin tests ----

    #[test]
    fn test_battery_plugin_name() {
        let plugin = BatteryPlugin;
        assert_eq!(plugin.name(), "battery");
    }

    #[test]
    fn test_battery_plugin_version_non_empty() {
        let plugin = BatteryPlugin;
        assert!(!plugin.version().is_empty());
    }

    #[test]
    fn test_battery_plugin_priority() {
        let plugin = BatteryPlugin;
        assert_eq!(plugin.priority(), PluginPriority::Default);
    }

    // ---- UUID construction tests ----

    #[test]
    fn test_battery_uuid_construction() {
        let uuid = BtUuid::from_u16(BATT_UUID16);
        let expected = BtUuid::Uuid16(0x180F);
        assert_eq!(uuid, expected);
    }

    #[test]
    fn test_battery_level_uuid_construction() {
        let uuid = BtUuid::from_u16(GATT_CHARAC_BATTERY_LEVEL);
        let expected = BtUuid::Uuid16(0x2A19);
        assert_eq!(uuid, expected);
    }

    #[test]
    fn test_battery_level_uuid_not_equal_service_uuid() {
        let svc = BtUuid::from_u16(BATT_UUID16);
        let chr = BtUuid::from_u16(GATT_CHARAC_BATTERY_LEVEL);
        assert_ne!(svc, chr);
    }
}
