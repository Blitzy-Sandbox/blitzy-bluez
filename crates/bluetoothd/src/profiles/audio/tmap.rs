// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Telephony and Media Audio Profile (TMAP) plugin — Rust rewrite of
// `profiles/audio/tmap.c`.
//
// Manages TMAP/TMAS (Telephony and Media Audio Service) GATT sessions
// for both client-side (discovering remote TMAS Role characteristic) and
// server-side (registering TMAS service in local GATT database) roles.
//
// Key responsibilities:
//   1. Profile lifecycle callbacks (probe, accept, disconnect, remove)
//   2. Server-side TMAS GATT registration via `BtTmap::add_db()`
//   3. Client-side TMAS attach/detach via `BtTmap::attach()`
//   4. Plugin registration via `inventory::submit!`


use std::sync::{Arc, Mutex};

use tracing::{debug, error};

use bluez_shared::audio::tmap::{BtTmap, TmapRole};

use crate::adapter::{BtdAdapter, adapter_get_path, btd_adapter_get_database};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{
    BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile, btd_profile_register, btd_profile_unregister,
};

// ===========================================================================
// Constants
// ===========================================================================

/// TMAS (Telephony and Media Audio Service) UUID string used as the
/// `remote_uuid` for profile matching.  TMAS is assigned UUID 0x1855.
const TMAS_UUID_STR: &str = "00001855-0000-1000-8000-00805f9b34fb";

// ===========================================================================
// Session Data
// ===========================================================================

/// Per-device TMAP session data, analogous to the `struct bt_tmap *` stored
/// via `btd_service_set_user_data()` in the C implementation.
///
/// Tracks the association between a remote Bluetooth device and the TMAP
/// protocol engine ([`BtTmap`]).
pub struct TmapData {
    /// Reference to the remote Bluetooth device.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// The TMAP protocol engine instance (shared via `Arc`; replaces
    /// C's `bt_tmap_ref`/`bt_tmap_unref` reference counting).
    pub tmap: Arc<BtTmap>,
}

// ===========================================================================
// Module-level State
// ===========================================================================

/// Global list of active TMAP sessions — protected by a `std::sync::Mutex`
/// for synchronous access from GATT callbacks.  Replaces the C pattern of
/// storing `struct bt_tmap *` in service user_data.
static SESSIONS: Mutex<Vec<TmapData>> = Mutex::new(Vec::new());

// ===========================================================================
// Debug Callback
// ===========================================================================

/// Debug callback passed to [`BtTmap::set_debug()`].  Forwards TMAP engine
/// trace messages into the structured `tracing` framework.
///
/// Rust equivalent of the C `tmap_debug()` function which calls
/// `DBG_IDX(0xffff, "%s", str)`.
fn tmap_debug(msg: &str) {
    debug!("TMAP: {}", msg);
}

// ===========================================================================
// Session Management Helpers
// ===========================================================================

/// Find a session index by device pointer comparison.
pub fn find_session_by_device(
    sessions: &[TmapData],
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Option<usize> {
    let dev_ptr = Arc::as_ptr(device);
    sessions.iter().position(|s| Arc::as_ptr(&s.device) == dev_ptr)
}

/// Add a new TMAP session, guarding against duplicates for the same device.
///
/// Configures the debug callback on the TMAP engine and stores the session
/// in the global sessions list.
fn tmap_data_add(tmap: &Arc<BtTmap>, device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("TMAP: failed to lock sessions for add");
            return;
        }
    };

    // Guard against duplicate sessions for the same device.
    let dev_ptr = Arc::as_ptr(device);
    if sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr) {
        debug!("TMAP: session already exists for device");
        return;
    }

    debug!("TMAP: adding session");

    // Configure debug callback on the TMAP engine.
    tmap.set_debug(Box::new(tmap_debug));

    sessions.push(TmapData { device: Arc::clone(device), tmap: Arc::clone(tmap) });
}

/// Remove a TMAP session by device pointer comparison.
///
/// The [`BtTmap`]'s `Drop` impl handles cleanup of global TMAP instances.
fn tmap_data_remove_by_device(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("TMAP: failed to lock sessions for remove");
            return;
        }
    };

    let dev_ptr = Arc::as_ptr(device);
    let before = sessions.len();
    sessions.retain(|s| Arc::as_ptr(&s.device) != dev_ptr);

    if sessions.len() < before {
        debug!("TMAP: session removed");
    }
}

// ===========================================================================
// Profile Callbacks — Client Side
// ===========================================================================

/// Profile probe callback — logs the newly discovered device advertising TMAS.
///
/// Rust equivalent of the C `tmap_probe()` function which retrieves the
/// device address via `btd_service_get_device()` and logs it with `DBG()`.
fn tmap_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let dev_guard = device.blocking_lock();
    let addr = dev_guard.get_address().to_string();
    drop(dev_guard);

    debug!("TMAP: probe {}", addr);
    Ok(())
}

/// Profile remove callback — cleans up TMAP session data when a device
/// is removed.
///
/// Rust equivalent of the C `tmap_remove()` function which logs the device
/// address and calls `remove_service()`.
fn tmap_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let dev_guard = device.blocking_lock();
    let addr = dev_guard.get_address().to_string();
    drop(dev_guard);

    debug!("TMAP: remove {}", addr);

    tmap_data_remove_by_device(device);
}

/// Accept callback — attaches the GATT client for remote TMAS service
/// discovery.
///
/// Rust equivalent of the C `tmap_accept()` → `add_service()` call chain.
/// Retrieves the device's GATT client and calls [`BtTmap::attach()`] to
/// initiate TMAS service discovery and TMAP Role characteristic reading
/// on the remote device.
fn tmap_accept(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let dev_guard = device.lock().await;
        let addr = dev_guard.get_address().to_string();
        let gatt_client = dev_guard.get_gatt_client().cloned();
        drop(dev_guard);

        debug!("TMAP: accept {}", addr);

        // Check if a session already exists for this device (equivalent to
        // the C check: `if (btd_service_get_user_data(service)) return -EEXIST`).
        {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            if sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr) {
                debug!("TMAP: session already exists for {}", addr);
                return Err(BtdError::already_exists());
            }
        }

        // Get the GATT client from the device.
        let client = match gatt_client {
            Some(c) => c,
            None => {
                error!("TMAP: no GATT client available for {}", addr);
                return Err(BtdError::not_available());
            }
        };

        // Attach the TMAP engine to the GATT client.  This initiates TMAS
        // service discovery and TMAP Role characteristic reading.
        let tmap = match BtTmap::attach(&client) {
            Some(t) => t,
            None => {
                error!("TMAP: failed to attach GATT client for {}", addr);
                return Err(BtdError::not_available());
            }
        };

        // Store session and configure debug callback.
        tmap_data_add(&tmap, &device);

        debug!("TMAP: accept complete — GATT client attached for {}", addr);
        Ok(())
    })
}

/// Disconnect callback — removes the TMAP session for the device.
///
/// Rust equivalent of the C `tmap_disconnect()` function which calls
/// `remove_service()` then `btd_service_disconnecting_complete(service, 0)`.
/// In the Rust profile framework, the `Ok(())` return from this async
/// callback signals the disconnection-complete state transition.
fn tmap_disconnect(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        debug!("TMAP: disconnect");

        tmap_data_remove_by_device(&device);

        debug!("TMAP: disconnect complete");
        Ok(())
    })
}

// ===========================================================================
// Server-Side Adapter Callbacks
// ===========================================================================

/// Adapter probe — registers the TMAS service in the adapter's local GATT
/// database.
///
/// Rust equivalent of the C `tmap_adapter_probe()` function which calls
/// `bt_tmap_add_db(btd_gatt_database_get_db(database))` and then
/// `bt_tmap_set_debug()`.  The initial role is empty (zero); it is set
/// later via `bt_tmap_set_role()` when actual capabilities are known,
/// matching the C behavior where `role_value` starts at 0.
fn tmap_server_probe(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) -> Result<(), BtdError> {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    match rt {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let path = adapter_get_path(&adapter_clone).await;
                    debug!("TMAP: Add TMAP server {}", path);

                    let database = btd_adapter_get_database(&adapter_clone).await;
                    if let Some(db) = database {
                        let gatt_db = db.get_db().await;
                        // Register the TMAS primary service with an empty role.
                        // The role is configured later when capabilities are
                        // determined, matching the C behaviour where
                        // `new0(struct bt_tmap, 1)` zero-initializes the role.
                        if let Some(tmap) = BtTmap::add_db(&gatt_db, TmapRole::empty()) {
                            tmap.set_debug(Box::new(tmap_debug));
                            debug!("TMAP: TMAS registered in local GATT DB on {}", path);
                        } else {
                            debug!(
                                "TMAP: TMAS already registered or registration failed on {}",
                                path
                            );
                        }
                    } else {
                        error!("TMAP: no GATT database on adapter {}", path);
                    }
                });
            });
        }
        Err(_) => {
            error!("TMAP: no tokio runtime for server probe");
        }
    }

    Ok(())
}

/// Adapter remove — finds and drops the TMAS service registration for
/// the adapter.
///
/// Rust equivalent of the C `tmap_adapter_remove()` function which calls
/// `bt_tmap_find(btd_gatt_database_get_db(database))` followed by
/// `bt_tmap_unref(tmap)`.  In Rust, the [`BtTmap`]'s `Drop` impl removes
/// the instance from the global registry when the last reference is dropped.
fn tmap_server_remove(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    if let Ok(handle) = rt {
        tokio::task::block_in_place(|| {
            handle.block_on(async {
                let path = adapter_get_path(&adapter_clone).await;
                debug!("TMAP: Remove TMAP server {}", path);

                let database = btd_adapter_get_database(&adapter_clone).await;
                if let Some(db) = database {
                    let gatt_db = db.get_db().await;
                    // Find the TMAP session associated with this adapter's
                    // GATT DB.  Dropping the returned `Arc<BtTmap>` triggers
                    // cleanup via `BtTmap::drop()`.
                    let _tmap = BtTmap::find(&gatt_db);
                }
            });
        });
    }
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the TMAP plugin.
///
/// Registers the TMAP profile with the daemon, configuring it as
/// experimental with the TMAS UUID for service matching.
///
/// Rust equivalent of the C `tmap_init()` function.
fn tmap_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("TMAP: initializing plugin");

    // Register the TMAP profile.
    tokio::spawn(async {
        let mut profile = BtdProfile::new("tmap");
        profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        profile.experimental = true;
        profile.remote_uuid = Some(TMAS_UUID_STR.to_string());

        // Device lifecycle callbacks.
        profile.set_device_probe(Box::new(tmap_probe));
        profile.set_device_remove(Box::new(tmap_remove));

        // Accept and disconnect use async callbacks (AcceptFn/DisconnectFn).
        profile.set_accept(Box::new(|device| tmap_accept(device)));
        profile.set_disconnect(Box::new(|device| tmap_disconnect(device)));

        // Adapter lifecycle callbacks (server-side TMAS registration).
        profile.set_adapter_probe(Box::new(tmap_server_probe));
        profile.set_adapter_remove(Box::new(tmap_server_remove));

        if let Err(e) = btd_profile_register(profile).await {
            error!("TMAP: failed to register profile: {}", e);
        } else {
            debug!("TMAP: profile registered");
        }
    });

    debug!("TMAP: plugin initialized");
    Ok(())
}

/// Shut down the TMAP plugin.
///
/// Unregisters the TMAP profile from the daemon and clears all remaining
/// sessions.
///
/// Rust equivalent of the C `tmap_exit()` function.
fn tmap_exit() {
    debug!("TMAP: shutting down plugin");

    // Unregister the profile.
    tokio::spawn(async {
        let profile = BtdProfile::new("tmap");
        btd_profile_unregister(&profile).await;
        debug!("TMAP: profile unregistered");
    });

    // Clear all remaining sessions.
    if let Ok(mut sessions) = SESSIONS.lock() {
        sessions.clear();
    }

    debug!("TMAP: plugin shut down");
}

// ===========================================================================
// Inventory Plugin Registration
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "tmap",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: tmap_init,
        exit: tmap_exit,
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::BtdAdapter;
    use crate::device::AddressType;
    use bluez_shared::gatt::db::GattDb;
    use bluez_shared::sys::bluetooth::BdAddr;

    /// Global test serialization lock — all TMAP tests must acquire this
    /// before touching the shared `SESSIONS` static.  This prevents
    /// cross-test interference and mutex poisoning when the test harness
    /// runs with `--test-threads>1`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: lock the global SESSIONS and clear it, recovering from
    /// any previous poison state.
    fn clear_sessions() {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.clear();
    }

    /// Helper: read the current session count, recovering from poison.
    fn session_count() -> usize {
        let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.len()
    }

    /// Helper: check if a session exists for the given device, recovering
    /// from poison.
    fn has_session_for(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> bool {
        let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        find_session_by_device(&sessions, device).is_some()
    }

    /// Helper: create a minimal test BtdDevice for use in unit tests.
    fn make_test_device() -> Arc<tokio::sync::Mutex<BtdDevice>> {
        let adapter = Arc::new(tokio::sync::Mutex::new(BtdAdapter::new_for_test(0)));
        let device =
            BtdDevice::new(adapter, BdAddr::default(), AddressType::Bredr, "/org/bluez/hci0");
        Arc::new(tokio::sync::Mutex::new(device))
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_tmas_uuid_str_is_correct() {
        assert_eq!(TMAS_UUID_STR, "00001855-0000-1000-8000-00805f9b34fb");
    }

    // -----------------------------------------------------------------------
    // Debug callback — smoke test
    // -----------------------------------------------------------------------

    #[test]
    fn test_tmap_debug_does_not_panic() {
        tmap_debug("test debug message");
        tmap_debug("");
        tmap_debug("special chars: <>&\"'");
    }

    // -----------------------------------------------------------------------
    // Session management helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_by_device_empty() {
        let sessions: Vec<TmapData> = Vec::new();
        let device = make_test_device();
        assert!(find_session_by_device(&sessions, &device).is_none());
    }

    #[test]
    fn test_tmap_data_remove_on_empty_sessions() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let device = make_test_device();
        tmap_data_remove_by_device(&device); // should not panic on empty
    }

    #[test]
    fn test_session_storage_add_and_find() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let gatt_db = GattDb::new();
        if let Some(tmap) = BtTmap::add_db(&gatt_db, TmapRole::CG) {
            let device = make_test_device();
            tmap_data_add(&tmap, &device);

            // Should find the session.
            assert_eq!(session_count(), 1);
            assert!(has_session_for(&device));

            // Cleanup.
            tmap_data_remove_by_device(&device);
            assert_eq!(session_count(), 0);
        }
    }

    #[test]
    fn test_session_prevents_duplicates() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let gatt_db = GattDb::new();
        if let Some(tmap) = BtTmap::add_db(&gatt_db, TmapRole::CG) {
            let device = make_test_device();
            tmap_data_add(&tmap, &device);
            tmap_data_add(&tmap, &device); // duplicate — should be ignored

            assert_eq!(session_count(), 1);

            // Cleanup.
            tmap_data_remove_by_device(&device);
            clear_sessions();
        }
    }

    #[test]
    fn test_multiple_devices_separate_sessions() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let gatt_db1 = GattDb::new();
        let gatt_db2 = GattDb::new();
        let tmap1 = BtTmap::add_db(&gatt_db1, TmapRole::CG);
        let tmap2 = BtTmap::add_db(&gatt_db2, TmapRole::CT);

        if let (Some(t1), Some(t2)) = (tmap1, tmap2) {
            let device1 = make_test_device();
            let device2 = make_test_device();

            tmap_data_add(&t1, &device1);
            tmap_data_add(&t2, &device2);

            assert_eq!(session_count(), 2);
            assert!(has_session_for(&device1));
            assert!(has_session_for(&device2));

            // Remove first device.
            tmap_data_remove_by_device(&device1);
            assert_eq!(session_count(), 1);
            assert!(!has_session_for(&device1));
            assert!(has_session_for(&device2));

            // Cleanup.
            tmap_data_remove_by_device(&device2);
            assert_eq!(session_count(), 0);
        }

        clear_sessions();
    }

    // -----------------------------------------------------------------------
    // Probe / remove — smoke tests (sync callbacks)
    // -----------------------------------------------------------------------

    #[test]
    fn test_tmap_probe_does_not_panic() {
        let device = make_test_device();
        let result = tmap_probe(&device);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tmap_remove_does_not_panic() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let device = make_test_device();
        tmap_remove(&device); // no session — should not panic
    }

    #[test]
    fn test_tmap_remove_with_session() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let gatt_db = GattDb::new();
        if let Some(tmap) = BtTmap::add_db(&gatt_db, TmapRole::UMS) {
            let device = make_test_device();
            tmap_data_add(&tmap, &device);
            assert_eq!(session_count(), 1);

            tmap_remove(&device);
            assert_eq!(session_count(), 0);
        }
    }
}
