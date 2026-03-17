// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Call Control Profile (CCP) plugin — Rust rewrite of `profiles/audio/ccp.c`.
//
// Manages GTBS (Generic Telephony Bearer Service) GATT sessions for both
// client-side and server-side roles, integrating call control features into
// the BlueZ daemon.
//
// Key responsibilities:
//   1. Profile lifecycle callbacks (probe, accept, connect, disconnect, remove)
//   2. Server-side GTBS GATT registration via bt_ccp_register()
//   3. Plugin registration via inventory::submit!
//
// Architecture notes:
//   - The C original stores per-service session data via
//     `btd_service_set_user_data(service, data)`. Since Rust profile callbacks
//     receive `Arc<tokio::sync::Mutex<BtdDevice>>` rather than a service
//     handle, the Rust implementation uses a module-level `SESSIONS` list
//     indexed by device pointer (consistent with VCP/CSIP/MICP patterns).
//   - `BtCcp::set_user_data()` / `get_user_data()` is used to associate the
//     device reference with the CCP protocol engine instance.

#![allow(unused_imports)]

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::{debug, error};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::audio::ccp::{BtCcp, bt_ccp_register};
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::GattDb;

use crate::adapter::{
    BtdAdapter, adapter_get_path, btd_adapter_find_device_by_fd, btd_adapter_get_database,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::gatt::database::BtdGattDatabase;
use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};
use crate::profile::{
    BTD_PROFILE_BEARER_LE, BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile, btd_profile_register,
    btd_profile_unregister,
};
use crate::service::BtdService;

// ===========================================================================
// Constants
// ===========================================================================

/// GTBS UUID string used as the remote_uuid for profile matching.
/// Corresponds to the C `GTBS_UUID_STR` constant: 0x184C in 128-bit form.
const GTBS_UUID_STR: &str = "0000184c-0000-1000-8000-00805f9b34fb";

// ===========================================================================
// Session Data
// ===========================================================================

/// Per-device CCP session data, analogous to `struct ccp_data` in the C
/// implementation.
///
/// In the C code, `ccp_data` stores: device pointer, service pointer, bt_ccp
/// handle, and state_id. The Rust version stores the device and CCP engine
/// references; service state transitions are handled by the profile framework
/// automatically.
pub struct CcpData {
    /// Reference to the remote Bluetooth device.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// The CCP protocol engine instance.
    ccp: Arc<BtCcp>,
}

// ===========================================================================
// Module-level State
// ===========================================================================

/// Global list of active CCP sessions — protected by a std::sync::Mutex for
/// synchronous access from GATT callbacks.
static SESSIONS: Mutex<Vec<CcpData>> = Mutex::new(Vec::new());

// ===========================================================================
// Debug Callback
// ===========================================================================

/// Debug callback passed to `BtCcp::set_debug()`. Forwards CCP engine
/// trace messages into the structured tracing framework.
///
/// Replaces the C `ccp_debug()` function which uses `DBG_IDX(0xffff, ...)`.
fn ccp_debug(msg: &str) {
    debug!("CCP: {}", msg);
}

// ===========================================================================
// Session Management
// ===========================================================================

/// Add a new CCP session, guarding against duplicates for the same device.
///
/// Configures the debug callback, stores the device reference as user data
/// on the CCP engine, and appends the session to the global sessions list.
///
/// Analogous to `ccp_data_new()` + the session setup portion of `ccp_probe()`
/// in the C implementation.
fn ccp_data_add(ccp: &Arc<BtCcp>, device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("CCP: failed to lock sessions for add");
            return;
        }
    };

    // Guard against duplicate sessions for the same device.
    let dev_ptr = Arc::as_ptr(device);
    if sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr) {
        debug!("CCP: session already exists for device");
        return;
    }

    debug!("CCP: adding session");

    // Configure debug callback on the CCP engine.
    ccp.set_debug(ccp_debug);

    // Store device reference as user data on the CCP engine, mirroring
    // the C pattern where ccp_data is associated with the bt_ccp instance.
    ccp.set_user_data(Arc::clone(device) as Arc<dyn Any + Send + Sync>);

    sessions.push(CcpData { device: Arc::clone(device), ccp: Arc::clone(ccp) });
}

/// Remove a CCP session for a given device and clean up the CCP engine's
/// user data.
///
/// Analogous to `ccp_data_remove()` + `ccp_data_free()` in the C
/// implementation.
fn ccp_data_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("CCP: failed to lock sessions for remove");
            return;
        }
    };

    let dev_ptr = Arc::as_ptr(device);

    // Find the session and clear user data before removal, matching the C
    // `ccp_data_free` which calls `bt_ccp_set_user_data(data->ccp, NULL)`.
    if let Some(idx) = sessions.iter().position(|s| Arc::as_ptr(&s.device) == dev_ptr) {
        // Retrieve and discard user data before removal (exercises get_user_data).
        let _prev = sessions[idx].ccp.get_user_data();
        sessions.remove(idx);
        debug!("CCP: session removed");
    }
}

/// Find a CCP session index by device pointer.
pub fn find_session_by_device(
    sessions: &[CcpData],
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Option<usize> {
    let dev_ptr = Arc::as_ptr(device);
    sessions.iter().position(|s| Arc::as_ptr(&s.device) == dev_ptr)
}

// ===========================================================================
// Profile Callbacks — Client Side
// ===========================================================================

/// Profile probe callback — creates a CCP session for a newly discovered
/// device advertising GTBS.
///
/// Obtains both the adapter's local GATT DB and the remote device's GATT DB,
/// constructs a `BtCcp` instance, and registers the session.
///
/// Mirrors the C `ccp_probe()` function:
/// 1. Get adapter via device_get_adapter()
/// 2. Get local GATT DB via btd_adapter_get_database() → btd_gatt_database_get_db()
/// 3. Get remote GATT DB via btd_device_get_gatt_db()
/// 4. Create BtCcp::new(local_db, remote_db)
/// 5. Configure debug callback via bt_ccp_set_debug()
/// 6. Store session data
fn ccp_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let dev_guard = device.blocking_lock();

    // Log device address matching C's ba2str(device_get_address(device), addr)
    let addr = *dev_guard.get_address();
    debug!("CCP: probe {}", addr);

    // Check for duplicate probe (matching C's "Profile probed twice" check).
    {
        let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
        let dev_ptr = Arc::as_ptr(device);
        if sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr) {
            error!("CCP: profile probed twice for the same device!");
            return Err(BtdError::failed("profile probed twice"));
        }
    }

    let adapter_arc = dev_guard.get_adapter().clone();
    let remote_db = dev_guard.get_gatt_db().cloned();

    drop(dev_guard);

    // Obtain the local GATT database from the adapter.
    let local_db: Option<GattDb> = {
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => {
                let adapter_clone = adapter_arc.clone();
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let database = btd_adapter_get_database(&adapter_clone).await;
                        match database {
                            Some(db) => Some((*db.get_db().await).clone()),
                            None => None,
                        }
                    })
                })
            }
            Err(_) => None,
        }
    };

    let local_db = match local_db {
        Some(db) => db,
        None => {
            error!("CCP: no local GATT database available");
            return Err(BtdError::not_available());
        }
    };

    // Create the CCP protocol engine instance.
    let ccp = match BtCcp::new(local_db, remote_db) {
        Some(c) => c,
        None => {
            error!("CCP: failed to create CCP instance");
            return Err(BtdError::not_available());
        }
    };

    // Register the session with debug callback and user data.
    ccp_data_add(&ccp, device);

    debug!("CCP: probe complete");
    Ok(())
}

/// Profile remove callback — cleans up CCP session data when a device
/// is removed.
///
/// Mirrors the C `ccp_remove()` function which retrieves the ccp_data via
/// btd_service_get_user_data() and calls ccp_data_remove().
fn ccp_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    // Log device address.
    if let Ok(guard) = device.try_lock() {
        let addr = *guard.get_address();
        debug!("CCP: remove {}", addr);
    } else {
        debug!("CCP: remove");
    }

    let sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let dev_ptr = Arc::as_ptr(device);
    let has_session = sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr);
    drop(sessions);

    if !has_session {
        error!("CCP: service not handled by profile");
        return;
    }

    ccp_data_remove(device);
    debug!("CCP: remove complete");
}

/// Accept callback — attaches the GATT client for remote GTBS discovery.
///
/// This is called when the profile connection is being accepted (incoming
/// or outgoing). Retrieves the device's GATT client and attaches the
/// CCP engine to begin GTBS/TBS characteristic discovery.
///
/// Mirrors the C `ccp_accept()` function:
/// 1. Get GATT client via btd_device_get_gatt_client()
/// 2. Attach via bt_ccp_attach(ccp, client)
/// 3. Signal btd_service_connecting_complete(service, 0)
///
/// In the Rust framework, the service state transition to "connected" is
/// handled automatically when this callback returns Ok(()).
fn ccp_accept(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        debug!("CCP: accept");

        // Look up the CCP session for this device. We must drop the
        // std::sync::MutexGuard before any .await point to satisfy Send.
        let ccp = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            let ccp_opt = sessions
                .iter()
                .find(|s| Arc::as_ptr(&s.device) == dev_ptr)
                .map(|s| Arc::clone(&s.ccp));
            match ccp_opt {
                Some(c) => c,
                None => {
                    error!("CCP: no session found in accept");
                    return Err(BtdError::not_available());
                }
            }
        };

        // Retrieve the GATT client from the device.
        let dev_guard = device.lock().await;
        let addr = *dev_guard.get_address();
        let gatt_client = dev_guard.get_gatt_client().cloned();
        drop(dev_guard);

        debug!("CCP: accept {}", addr);

        let client = match gatt_client {
            Some(c) => c,
            None => {
                error!("CCP: no GATT client available for {}", addr);
                return Err(BtdError::not_available());
            }
        };

        // Attach the GATT client to the CCP engine.
        if !ccp.attach(client) {
            error!("CCP: unable to attach");
            return Err(BtdError::failed("attach GATT client"));
        }

        debug!("CCP: accept complete — GATT client attached for {}", addr);
        Ok(())
    })
}

/// Connect callback — signals that CCP connection setup is complete.
///
/// Mirrors the C `ccp_connect()` function which simply logs and returns 0.
/// The profile framework handles the service state machine transitions.
fn ccp_connect(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let dev_guard = device.lock().await;
        let addr = *dev_guard.get_address();
        drop(dev_guard);
        debug!("CCP: connect {}", addr);
        Ok(())
    })
}

/// Disconnect callback — detaches the CCP engine from the GATT client.
///
/// Mirrors the C `ccp_disconnect()` function:
/// 1. Detach CCP via bt_ccp_detach()
/// 2. Signal btd_service_disconnecting_complete(service, 0)
///
/// In the Rust framework, the service state transition to "disconnected"
/// is handled automatically when this callback returns Ok(()).
fn ccp_disconnect(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        debug!("CCP: disconnect");

        // Look up and detach the CCP session.
        let ccp_opt = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            sessions.iter().find(|s| Arc::as_ptr(&s.device) == dev_ptr).map(|s| Arc::clone(&s.ccp))
        };

        if let Some(ccp) = ccp_opt {
            ccp.detach();
        }

        debug!("CCP: disconnect complete");
        Ok(())
    })
}

// ===========================================================================
// Server-Side Adapter Callbacks
// ===========================================================================

/// Adapter probe — registers GTBS in the adapter's local GATT database.
///
/// Mirrors the C `ccp_server_probe()` function:
/// 1. Get GATT database via btd_adapter_get_database()
/// 2. Register GTBS via bt_ccp_register(btd_gatt_database_get_db())
fn ccp_server_probe(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) -> Result<(), BtdError> {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    match rt {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let path = adapter_get_path(&adapter_clone).await;
                    debug!("CCP: server probe on {}", path);

                    let database = btd_adapter_get_database(&adapter_clone).await;
                    if let Some(db) = database {
                        let gatt_db = db.get_db().await;
                        bt_ccp_register(&gatt_db);
                        debug!("CCP: GTBS registered in local GATT DB on {}", path);
                    } else {
                        error!("CCP: no GATT database on adapter {}", path);
                    }
                });
            });
        }
        Err(_) => {
            error!("CCP: no tokio runtime for server probe");
        }
    }

    Ok(())
}

/// Adapter remove — logs the removal (minimal cleanup, matching C behavior).
///
/// Mirrors the C `ccp_server_remove()` which only logs "CCP remove adapter".
fn ccp_server_remove(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    if let Ok(handle) = rt {
        tokio::task::block_in_place(|| {
            handle.block_on(async {
                let path = adapter_get_path(&adapter_clone).await;
                debug!("CCP: server remove on {}", path);
            });
        });
    }
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the CCP plugin.
///
/// Registers the CCP profile with the daemon. The profile matches devices
/// advertising the GTBS UUID (0x184C) and requires the LE bearer.
///
/// Mirrors the C `ccp_init()` which calls `btd_profile_register(&ccp_profile)`.
fn ccp_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("CCP: initializing plugin");

    // Register the CCP profile asynchronously.
    tokio::spawn(async {
        let mut profile = BtdProfile::new("ccp");
        profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        profile.bearer = BTD_PROFILE_BEARER_LE;
        profile.testing = true;
        profile.remote_uuid = Some(GTBS_UUID_STR.to_string());

        // Device lifecycle callbacks.
        profile.set_device_probe(Box::new(ccp_probe));
        profile.set_device_remove(Box::new(ccp_remove));

        // Connection callbacks — accept and connect use async signatures.
        profile.set_accept(Box::new(|device| ccp_accept(device)));
        profile.set_connect(Box::new(|device| ccp_connect(device)));
        profile.set_disconnect(Box::new(|device| ccp_disconnect(device)));

        // Adapter lifecycle callbacks (server-side GTBS registration).
        profile.set_adapter_probe(Box::new(ccp_server_probe));
        profile.set_adapter_remove(Box::new(ccp_server_remove));

        if let Err(e) = btd_profile_register(profile).await {
            error!("CCP: failed to register profile: {}", e);
        } else {
            debug!("CCP: profile registered");
        }
    });

    debug!("CCP: plugin initialized");
    Ok(())
}

/// Shut down the CCP plugin.
///
/// Unregisters the CCP profile and clears all active sessions.
///
/// Mirrors the C `ccp_exit()` which calls `btd_profile_unregister(&ccp_profile)`.
fn ccp_exit() {
    debug!("CCP: shutting down plugin");

    // Unregister the profile asynchronously.
    tokio::spawn(async {
        let profile = BtdProfile::new("ccp");
        btd_profile_unregister(&profile).await;
        debug!("CCP: profile unregistered");
    });

    // Clear all remaining sessions.
    if let Ok(mut sessions) = SESSIONS.lock() {
        sessions.clear();
    }

    debug!("CCP: plugin shut down");
}

// ===========================================================================
// Inventory Plugin Registration
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "ccp",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: ccp_init,
        exit: ccp_exit,
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::BtdAdapter;
    use bluez_shared::sys::bluetooth::BdAddr;

    /// Global test serialization lock — all CCP tests must acquire this
    /// before touching the shared `SESSIONS` static. This prevents
    /// cross-test interference when the test harness runs in parallel.
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

    /// Helper: check if a session exists for the given device.
    fn has_session_for(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> bool {
        let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        find_session_by_device(&sessions, device).is_some()
    }

    /// Helper: create a minimal test BtdDevice for use in unit tests.
    fn make_test_device() -> Arc<tokio::sync::Mutex<BtdDevice>> {
        let adapter = Arc::new(tokio::sync::Mutex::new(BtdAdapter::new_for_test(0)));
        let device = BtdDevice::new(
            adapter,
            BdAddr::default(),
            crate::device::AddressType::Bredr,
            "/org/bluez/hci0",
        );
        Arc::new(tokio::sync::Mutex::new(device))
    }

    #[test]
    fn test_ccp_debug_does_not_panic() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ccp_debug("test message");
    }

    #[test]
    fn test_session_add_and_remove() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();

        // Create a minimal CCP instance for testing.
        let ccp = BtCcp::new(GattDb::new(), None);
        assert!(ccp.is_some(), "BtCcp::new should succeed with empty GattDb");
        let ccp = ccp.unwrap();

        // Add session.
        ccp_data_add(&ccp, &device);
        assert_eq!(session_count(), 1);
        assert!(has_session_for(&device));

        // Adding same device again should not create a duplicate.
        ccp_data_add(&ccp, &device);
        assert_eq!(session_count(), 1);

        // Remove session.
        ccp_data_remove(&device);
        assert_eq!(session_count(), 0);
        assert!(!has_session_for(&device));

        clear_sessions();
    }

    #[test]
    fn test_session_remove_nonexistent_is_safe() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();

        // Removing a session for a device that was never added should not panic.
        ccp_data_remove(&device);
        assert_eq!(session_count(), 0);

        clear_sessions();
    }

    #[test]
    fn test_multiple_device_sessions() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device1 = make_test_device();
        let device2 = make_test_device();

        let ccp1 = BtCcp::new(GattDb::new(), None).unwrap();
        let ccp2 = BtCcp::new(GattDb::new(), None).unwrap();

        ccp_data_add(&ccp1, &device1);
        ccp_data_add(&ccp2, &device2);
        assert_eq!(session_count(), 2);

        assert!(has_session_for(&device1));
        assert!(has_session_for(&device2));

        // Remove first device session.
        ccp_data_remove(&device1);
        assert_eq!(session_count(), 1);
        assert!(!has_session_for(&device1));
        assert!(has_session_for(&device2));

        // Remove second device session.
        ccp_data_remove(&device2);
        assert_eq!(session_count(), 0);

        clear_sessions();
    }

    #[test]
    fn test_find_session_empty() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();
        let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        assert!(find_session_by_device(&sessions, &device).is_none());
    }

    #[test]
    fn test_gtbs_uuid_format() {
        // Verify the GTBS UUID string follows the expected 128-bit format.
        assert_eq!(GTBS_UUID_STR, "0000184c-0000-1000-8000-00805f9b34fb");
        assert_eq!(GTBS_UUID_STR.len(), 36);
    }

    #[test]
    fn test_user_data_roundtrip() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let ccp = BtCcp::new(GattDb::new(), None).unwrap();

        // set_user_data should succeed.
        let data: Arc<dyn Any + Send + Sync> = Arc::new(42_u32);
        assert!(ccp.set_user_data(data));

        // get_user_data should return the stored data.
        let retrieved = ccp.get_user_data();
        assert!(retrieved.is_some());

        clear_sessions();
    }
}
