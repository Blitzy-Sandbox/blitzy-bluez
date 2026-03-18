// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Microphone Control Profile (MICP) plugin — Rust rewrite of
// `profiles/audio/micp.c`.
//
// Manages MICS (Microphone Control Service) GATT sessions for both
// client-side and server-side roles, tracking per-device mute state
// and bridging ready notifications into the profile lifecycle.
//
// Key responsibilities:
//   1. Profile lifecycle callbacks (probe, accept, disconnect, remove)
//   2. Server-side MICS GATT registration via `bt_micp_add_db()`
//   3. Remote client attach/detach tracking via `bt_micp_register()`
//   4. Ready notification handling via `BtMicp::ready_register()`
//   5. Plugin registration via `inventory::submit!`

use std::any::Any;
use std::sync::{Arc, Mutex};

use tracing::{debug, error};

use bluez_shared::audio::micp::{BtMicp, bt_micp_add_db, bt_micp_register, bt_micp_unregister};
use bluez_shared::gatt::db::GattDb;

use crate::adapter::{
    BtdAdapter, adapter_get_path, btd_adapter_find_device_by_fd, btd_adapter_get_database,
    btd_adapter_get_default,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{
    BTD_PROFILE_BEARER_LE, BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile, btd_profile_register,
    btd_profile_unregister,
};
// ===========================================================================
// Constants
// ===========================================================================

/// MICS (Microphone Control Service) UUID string used as the remote_uuid
/// for profile matching.  MICS is assigned UUID 0x1845.
const MICS_UUID_STR: &str = "00001845-0000-1000-8000-00805f9b34fb";

// ===========================================================================
// Session Data
// ===========================================================================

/// Per-device MICP session data, analogous to `struct micp_data` in the C
/// implementation.
///
/// Tracks the association between a remote Bluetooth device, the MICP
/// protocol engine (`BtMicp`), and the ready-callback registration ID.
pub struct MicpData {
    /// Reference to the remote Bluetooth device.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// The MICP protocol engine instance (shared via `Arc`; replaces
    /// C's `bt_micp_ref`/`bt_micp_unref` refcounting).
    micp: Arc<BtMicp>,
    /// Registration ID returned by `BtMicp::ready_register()`, used to
    /// unregister the ready callback in session teardown.
    ready_id: u32,
}

// ===========================================================================
// Module-level State
// ===========================================================================

/// Global list of active MICP sessions — protected by a `std::sync::Mutex`
/// for synchronous access from GATT callbacks.  Replaces the C
/// `static struct queue *sessions`.
static SESSIONS: Mutex<Vec<MicpData>> = Mutex::new(Vec::new());

/// Registration ID returned by `bt_micp_register()`, used for cleanup in
/// `micp_exit()`.
static MICP_REGISTER_ID: Mutex<u32> = Mutex::new(0);

// ===========================================================================
// Debug Callback
// ===========================================================================

/// Debug callback passed to `BtMicp::set_debug()`.  Forwards MICP engine
/// trace messages into the structured `tracing` framework.
fn micp_debug(msg: &str) {
    debug!("MICP: {}", msg);
}

// ===========================================================================
// Session Management Helpers
// ===========================================================================

/// Find a session index by device pointer comparison.
fn find_session_by_device(
    sessions: &[MicpData],
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Option<usize> {
    let dev_ptr = Arc::as_ptr(device);
    sessions.iter().position(|s| Arc::as_ptr(&s.device) == dev_ptr)
}

/// Find a session index by `BtMicp` raw pointer comparison.
pub fn find_session_by_micp(sessions: &[MicpData], micp: &BtMicp) -> Option<usize> {
    let target = micp as *const BtMicp;
    sessions.iter().position(|s| Arc::as_ptr(&s.micp) == target)
}

/// Add a new MICP session, guarding against duplicates for the same device.
///
/// Configures the debug callback on the MICP engine and stores the session
/// in the global sessions list.
fn micp_data_add(micp: &Arc<BtMicp>, device: &Arc<tokio::sync::Mutex<BtdDevice>>, ready_id: u32) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("MICP: failed to lock sessions for add");
            return;
        }
    };

    // Guard against duplicate sessions for the same device.
    let dev_ptr = Arc::as_ptr(device);
    if sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr) {
        debug!("MICP: session already exists for device");
        return;
    }

    debug!("MICP: adding session");

    // Configure debug callback on the MICP engine.
    micp.set_debug(micp_debug);

    sessions.push(MicpData { device: Arc::clone(device), micp: Arc::clone(micp), ready_id });
}

/// Remove a MICP session by matching the `BtMicp` engine instance pointer.
///
/// Unregisters the ready callback before removal to prevent stale callbacks.
fn micp_data_remove(micp: &Arc<BtMicp>) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("MICP: failed to lock sessions for remove");
            return;
        }
    };

    let micp_ptr = Arc::as_ptr(micp);
    let before = sessions.len();

    // Unregister ready callback and remove session.
    sessions.retain(|s| {
        if Arc::as_ptr(&s.micp) == micp_ptr {
            if s.ready_id != 0 {
                s.micp.ready_unregister(s.ready_id);
            }
            false // Remove this session
        } else {
            true // Keep this session
        }
    });

    if sessions.len() < before {
        debug!("MICP: session removed");
    }
}

// ===========================================================================
// Ready Callback
// ===========================================================================

/// Callback invoked when the MICP session becomes ready (MICS service
/// discovery and initial characteristic read complete on the remote device).
///
/// In the C original, this retrieves the service via `bt_micp_get_user_data()`
/// and calls `btd_service_connecting_complete(service, 0)`.  In the Rust
/// profile framework, the accept callback's `Ok(())` return handles the
/// state transition, so this callback logs the ready event for diagnostics.
fn micp_ready(_micp: &BtMicp) {
    debug!("MICP: session ready");
}

// ===========================================================================
// Remote Client Attach/Detach Callbacks
// ===========================================================================

/// Callback invoked when a remote GATT client attaches to the local MICS
/// server.  Maps the ATT file descriptor to a device and creates a session.
///
/// This corresponds to the C `micp_attached()` function.  The device lookup
/// via `btd_adapter_find_device_by_fd()` is currently a placeholder; once
/// device-FD tracking is wired in adapter.rs, this will create full sessions.
fn micp_attached(micp: &BtMicp) {
    debug!("MICP: remote client attached");

    // Check if a session already exists for this MICP engine.
    {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        let target = micp as *const BtMicp;
        if sessions.iter().any(|s| Arc::as_ptr(&s.micp) == target) {
            return;
        }
    }

    // Get ATT transport from the MICP engine to look up the owning device.
    let att_arc = match micp.get_att() {
        Some(a) => a,
        None => {
            error!("MICP: no ATT transport in remote attach");
            return;
        }
    };

    // Get the file descriptor from the ATT transport.
    let fd = {
        let att_guard = match att_arc.lock() {
            Ok(g) => g,
            Err(_) => {
                error!("MICP: failed to lock ATT");
                return;
            }
        };
        match att_guard.get_fd() {
            Ok(fd) => fd,
            Err(e) => {
                error!("MICP: failed to get ATT fd: {}", e);
                return;
            }
        }
    };

    // Look up the device by file descriptor via the default adapter.
    // This is an async operation that we bridge into the sync callback
    // context using `block_in_place`.
    let _device = {
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let adapter = btd_adapter_get_default().await;
                    match adapter {
                        Some(a) => btd_adapter_find_device_by_fd(&a, fd).await,
                        None => None,
                    }
                })
            }),
            Err(_) => None,
        }
    };

    if _device.is_none() {
        debug!("MICP: could not find device for fd {}", fd);
        // This is expected since btd_adapter_find_device_by_fd is a
        // placeholder returning None.  The session will be created once
        // the adapter-device FD mapping is fully wired.
    }

    // In the C original, if device is found, a session is created via
    // micp_data_add(data).  Since find_device_by_fd is not yet functional,
    // we log and return.
    debug!("MICP: remote client attach handling complete");
}

/// Callback invoked when a remote GATT client detaches from the local MICS
/// server.  Finds and removes the corresponding session.
///
/// This corresponds to the C `micp_detached()` function.
fn micp_detached(micp: &BtMicp) {
    debug!("MICP: remote client detached");

    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let target = micp as *const BtMicp;
    let before = sessions.len();

    // Unregister ready callbacks and remove matching session.
    sessions.retain(|s| {
        if Arc::as_ptr(&s.micp) == target {
            if s.ready_id != 0 {
                s.micp.ready_unregister(s.ready_id);
            }
            false
        } else {
            true
        }
    });

    if sessions.len() < before {
        debug!("MICP: remote client session removed");
    } else {
        error!("MICP: unable to find session for detached client");
    }
}

// ===========================================================================
// Profile Callbacks — Client Side
// ===========================================================================

/// Profile probe callback — creates a MICP session for a newly discovered
/// device advertising MICS.
///
/// Obtains both the adapter's local GATT DB and the remote device's GATT DB,
/// constructs a `BtMicp` instance, registers the ready callback, and stores
/// the session.
///
/// Corresponds to the C `micp_probe()` function.
fn micp_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    debug!("MICP: probe");

    // Check for duplicate probe — guard against double session creation.
    {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return Err(BtdError::failed("lock sessions")),
        };
        if find_session_by_device(&sessions, device).is_some() {
            error!("MICP: profile probed twice");
            return Err(BtdError::already_exists());
        }
    }

    let dev_guard = device.blocking_lock();

    let adapter_arc = dev_guard.get_adapter().clone();
    let remote_db = dev_guard.get_gatt_db().cloned();

    drop(dev_guard);

    // Obtain the local GATT database from the adapter.  This requires
    // bridging async adapter calls into the synchronous probe context
    // using `tokio::task::block_in_place`.
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
            error!("MICP: no local GATT database available");
            return Err(BtdError::not_available());
        }
    };

    // Create the MICP protocol engine instance.
    let micp = match BtMicp::new(local_db, remote_db) {
        Some(v) => v,
        None => {
            error!("MICP: failed to create MICP instance");
            return Err(BtdError::not_available());
        }
    };

    // Store a device reference as user data on the MICP engine.
    // In the C code, the service pointer is stored here via
    // `bt_micp_set_user_data(data->micp, service)`.  Since the Rust
    // profile framework passes devices (not services) to callbacks,
    // we store the device reference for consistency.
    let device_clone: Arc<tokio::sync::Mutex<BtdDevice>> = Arc::clone(device);
    let user_data: Arc<dyn Any + Send + Sync> = device_clone;
    micp.set_user_data(user_data);

    // Register the ready callback, which fires when MICS service
    // discovery completes on the remote device.
    let ready_id = micp.ready_register(micp_ready);

    // Add the session to the global sessions list.
    micp_data_add(&micp, device, ready_id);

    debug!("MICP: probe complete");
    Ok(())
}

/// Profile remove callback — cleans up MICP session data when a device
/// is removed.
///
/// Corresponds to the C `micp_remove()` function.
fn micp_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    debug!("MICP: remove");

    let sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let dev_ptr = Arc::as_ptr(device);
    let micp_opt =
        sessions.iter().find(|s| Arc::as_ptr(&s.device) == dev_ptr).map(|s| Arc::clone(&s.micp));

    drop(sessions);

    if let Some(micp) = micp_opt {
        micp_data_remove(&micp);
    } else {
        error!("MICP: no session found for device in remove");
    }

    debug!("MICP: remove complete");
}

/// Accept callback — attaches the GATT client for remote MICS discovery.
///
/// This is called when the profile connection is being accepted (incoming
/// or outgoing).  Retrieves the device's GATT client and attaches the
/// MICP engine to begin MICS characteristic discovery.
///
/// Corresponds to the C `micp_accept()` function.
fn micp_accept(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        debug!("MICP: accept");

        // Look up the MICP session for this device.  Drop the
        // std::sync::MutexGuard before any .await to satisfy Send.
        let micp = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            let micp_opt = sessions
                .iter()
                .find(|s| Arc::as_ptr(&s.device) == dev_ptr)
                .map(|s| Arc::clone(&s.micp));
            match micp_opt {
                Some(v) => v,
                None => {
                    error!("MICP: service not handled by profile");
                    return Err(BtdError::not_available());
                }
            }
        };

        // Retrieve the GATT client from the device.
        let dev_guard = device.lock().await;
        let gatt_client = dev_guard.get_gatt_client().cloned();
        drop(dev_guard);

        // Attach the GATT client to the MICP engine.
        if !micp.attach(gatt_client) {
            error!("MICP: failed to attach GATT client");
            return Err(BtdError::failed("attach GATT client"));
        }

        debug!("MICP: accept complete — GATT client attached");
        Ok(())
    })
}

/// Disconnect callback — detaches the MICP engine from the GATT client.
///
/// Corresponds to the C `micp_disconnect()` function.
fn micp_disconnect(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        debug!("MICP: disconnect");

        // Look up and detach the MICP session.
        let micp_opt = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            sessions.iter().find(|s| Arc::as_ptr(&s.device) == dev_ptr).map(|s| Arc::clone(&s.micp))
        };

        if let Some(micp) = micp_opt {
            micp.detach();
        } else {
            error!("MICP: service not handled by profile");
        }

        debug!("MICP: disconnect complete");
        Ok(())
    })
}

// ===========================================================================
// Server-Side Adapter Callbacks
// ===========================================================================

/// Adapter probe — registers MICS in the adapter's local GATT database.
///
/// Corresponds to the C `micp_server_probe()` function.
fn micp_server_probe(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) -> Result<(), BtdError> {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    match rt {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let path = adapter_get_path(&adapter_clone).await;
                    debug!("MICP: server probe on {}", path);

                    let database = btd_adapter_get_database(&adapter_clone).await;
                    if let Some(db) = database {
                        let gatt_db = db.get_db().await;
                        bt_micp_add_db(&gatt_db);
                        debug!("MICP: MICS registered in local GATT DB on {}", path);
                    } else {
                        error!("MICP: no GATT database on adapter {}", path);
                    }
                });
            });
        }
        Err(_) => {
            error!("MICP: no tokio runtime for server probe");
        }
    }

    Ok(())
}

/// Adapter remove — logs the removal (minimal cleanup, matching C behavior).
///
/// Corresponds to the C `micp_server_remove()` function.
fn micp_server_remove(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    if let Ok(handle) = rt {
        tokio::task::block_in_place(|| {
            handle.block_on(async {
                let path = adapter_get_path(&adapter_clone).await;
                debug!("MICP: server remove on {}", path);
            });
        });
    }
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the MICP plugin.
///
/// Registers the MICP profile with the daemon and sets up global
/// attach/detach callbacks for remote MICS client tracking.
///
/// Corresponds to the C `micp_init()` function.
fn micp_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("MICP: initializing plugin");

    // Register the MICP profile.
    tokio::spawn(async {
        let mut profile = BtdProfile::new("micp");
        profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        profile.bearer = BTD_PROFILE_BEARER_LE;
        profile.experimental = true;
        profile.remote_uuid = Some(MICS_UUID_STR.to_string());

        // Device lifecycle callbacks.
        profile.set_device_probe(Box::new(micp_probe));
        profile.set_device_remove(Box::new(micp_remove));

        // Accept and disconnect use async callbacks (AcceptFn/DisconnectFn).
        profile.set_accept(Box::new(|device| micp_accept(device)));
        profile.set_disconnect(Box::new(|device| micp_disconnect(device)));

        // Adapter lifecycle callbacks (server-side MICS registration).
        profile.set_adapter_probe(Box::new(micp_server_probe));
        profile.set_adapter_remove(Box::new(micp_server_remove));

        if let Err(e) = btd_profile_register(profile).await {
            error!("MICP: failed to register profile: {}", e);
        } else {
            debug!("MICP: profile registered");
        }
    });

    // Register global MICP attach/detach callbacks for remote client
    // session tracking.
    let attached_cb: Box<dyn Fn(&BtMicp) + Send + Sync> = Box::new(micp_attached);
    let detached_cb: Box<dyn Fn(&BtMicp) + Send + Sync> = Box::new(micp_detached);

    let id = bt_micp_register(Some(attached_cb), Some(detached_cb));

    {
        let mut micp_id = MICP_REGISTER_ID.lock().unwrap();
        *micp_id = id;
    }

    debug!("MICP: plugin initialized (register_id={})", id);
    Ok(())
}

/// Shut down the MICP plugin.
///
/// Unregisters the global attach/detach callbacks and the MICP profile.
///
/// Corresponds to the C `micp_exit()` function.
fn micp_exit() {
    debug!("MICP: shutting down plugin");

    // Unregister global MICP callbacks.
    let id = {
        let micp_id = MICP_REGISTER_ID.lock().unwrap();
        *micp_id
    };

    if id != 0 {
        bt_micp_unregister(id);
    }

    // Unregister the profile.
    tokio::spawn(async {
        let profile = BtdProfile::new("micp");
        btd_profile_unregister(&profile).await;
        debug!("MICP: profile unregistered");
    });

    // Clear all remaining sessions — unregister ready callbacks first.
    if let Ok(mut sessions) = SESSIONS.lock() {
        for session in sessions.iter() {
            if session.ready_id != 0 {
                session.micp.ready_unregister(session.ready_id);
            }
        }
        sessions.clear();
    }

    debug!("MICP: plugin shut down");
}

// ===========================================================================
// Inventory Plugin Registration
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "micp",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: micp_init,
        exit: micp_exit,
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::BtdAdapter;

    /// Global test serialization lock — all MICP tests must acquire this
    /// before touching the shared `SESSIONS` static.  Prevents cross-test
    /// interference when the test harness runs with `--test-threads>1`.
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
        use bluez_shared::sys::bluetooth::BdAddr;
        let adapter = Arc::new(tokio::sync::Mutex::new(BtdAdapter::new_for_test(0)));
        let device = BtdDevice::new(
            adapter,
            BdAddr::default(),
            crate::device::AddressType::Bredr,
            "/org/bluez/hci0",
        );
        Arc::new(tokio::sync::Mutex::new(device))
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_mics_uuid_str_is_correct() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // MICS = 0x1845
        assert_eq!(MICS_UUID_STR, "00001845-0000-1000-8000-00805f9b34fb");
    }

    // -----------------------------------------------------------------------
    // Debug callback — smoke tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_micp_debug_does_not_panic() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        micp_debug("test message");
        micp_debug("");
        micp_debug("special chars: <>&\"'");
    }

    // -----------------------------------------------------------------------
    // Ready callback — smoke test
    // -----------------------------------------------------------------------

    #[test]
    fn test_micp_ready_does_not_panic_with_default_micp() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        // Create a minimal BtMicp to pass to micp_ready.
        let db = GattDb::new();
        bt_micp_add_db(&db);
        if let Some(micp) = BtMicp::new(db, None) {
            micp_ready(&micp);
        }
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_starts_empty() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        assert_eq!(session_count(), 0);
    }

    #[test]
    fn test_micp_data_add_creates_session() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();
        let db = GattDb::new();
        bt_micp_add_db(&db);

        if let Some(micp) = BtMicp::new(db, None) {
            micp_data_add(&micp, &device, 0);
            assert_eq!(session_count(), 1);
            assert!(has_session_for(&device));

            // Clean up
            micp_data_remove(&micp);
        }
    }

    #[test]
    fn test_micp_data_add_prevents_duplicates() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();
        let db = GattDb::new();
        bt_micp_add_db(&db);

        if let Some(micp) = BtMicp::new(db, None) {
            micp_data_add(&micp, &device, 0);
            assert_eq!(session_count(), 1);

            // Adding same device again should be a no-op.
            micp_data_add(&micp, &device, 0);
            assert_eq!(session_count(), 1);

            // Clean up
            micp_data_remove(&micp);
        }
    }

    #[test]
    fn test_micp_data_remove_decrements_sessions() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();
        let db = GattDb::new();
        bt_micp_add_db(&db);

        if let Some(micp) = BtMicp::new(db, None) {
            micp_data_add(&micp, &device, 0);
            assert_eq!(session_count(), 1);

            micp_data_remove(&micp);
            assert_eq!(session_count(), 0);
        }
    }

    #[test]
    fn test_micp_data_remove_nonexistent_is_noop() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        if let Some(micp) = BtMicp::new(db, None) {
            // Remove without adding first — should not panic.
            micp_data_remove(&micp);
            assert_eq!(session_count(), 0);
        }
    }

    // -----------------------------------------------------------------------
    // Detached callback
    // -----------------------------------------------------------------------

    #[test]
    fn test_micp_detached_removes_session() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();
        let db = GattDb::new();
        bt_micp_add_db(&db);

        if let Some(micp) = BtMicp::new(db, None) {
            micp_data_add(&micp, &device, 0);
            assert_eq!(session_count(), 1);

            micp_detached(&micp);
            assert_eq!(session_count(), 0);
        }
    }

    #[test]
    fn test_micp_detached_no_session_does_not_panic() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        if let Some(micp) = BtMicp::new(db, None) {
            // Detaching without a session should log error but not panic.
            micp_detached(&micp);
            assert_eq!(session_count(), 0);
        }
    }

    // -----------------------------------------------------------------------
    // Find helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_by_device_returns_none_when_empty() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let device = make_test_device();
        let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        assert!(find_session_by_device(&sessions, &device).is_none());
    }

    #[test]
    fn test_find_session_by_micp_returns_none_when_empty() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let db = GattDb::new();
        bt_micp_add_db(&db);

        if let Some(micp) = BtMicp::new(db, None) {
            let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
            assert!(find_session_by_micp(&sessions, &micp).is_none());
        }
    }
}
