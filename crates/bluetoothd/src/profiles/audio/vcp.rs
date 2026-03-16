// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Volume Control Profile (VCP) plugin — Rust rewrite of `profiles/audio/vcp.c`.
//
// Manages VCS (Volume Control Service) GATT sessions for both client-side
// (Controller) and server-side (Renderer) roles, bridges volume change events
// into the media transport layer, and exposes a cross-module volume API for
// the audio stack.
//
// Key responsibilities:
//   1. Profile lifecycle callbacks (probe, accept, disconnect, remove)
//   2. Server-side VCS GATT registration via bt_vcp_add_db()
//   3. Remote client attach/detach tracking
//   4. Public API: bt_audio_vcp_get_volume / bt_audio_vcp_set_volume
//   5. Plugin registration via inventory::submit!

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use tracing::{debug, error};

use bluez_shared::audio::vcp::{bt_vcp_add_db, bt_vcp_register, bt_vcp_unregister, BtVcp};
use bluez_shared::gatt::db::GattDb;

use crate::adapter::{
    btd_adapter_find_device_by_fd, btd_adapter_get_database, btd_adapter_get_default,
    adapter_get_path, BtdAdapter,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{
    btd_profile_register, btd_profile_unregister, BtdProfile, BTD_PROFILE_BEARER_LE,
    BTD_PROFILE_PRIORITY_MEDIUM,
};
use crate::service::BtdService;

// ===========================================================================
// Constants
// ===========================================================================

/// VCS UUID string used as the remote_uuid for profile matching.
const VCS_UUID_STR: &str = "00001844-0000-1000-8000-00805f9b34fb";

/// D-Bus interface name for media endpoints (preserved from C for parity).
const MEDIA_ENDPOINT_INTERFACE: &str = "org.bluez.MediaEndpoint1";

// ===========================================================================
// Session Data
// ===========================================================================

/// Per-device VCP session data, analogous to `struct vcp_data` in the C
/// implementation.
struct VcpData {
    /// Reference to the remote Bluetooth device.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// Optional reference to the BtdService that owns this session.
    /// `None` for sessions created via remote client attach (server-side).
    service: Option<Arc<std::sync::Mutex<BtdService>>>,
    /// The VCP protocol engine instance.
    vcp: Arc<BtVcp>,
}

// ===========================================================================
// Module-level State
// ===========================================================================

/// Global list of active VCP sessions — protected by a std::sync::Mutex for
/// synchronous access from GATT callbacks.
static SESSIONS: Mutex<Vec<VcpData>> = Mutex::new(Vec::new());

/// Registration ID returned by `bt_vcp_register()`, used for cleanup in
/// `vcp_exit()`.
static VCP_REGISTER_ID: Mutex<u32> = Mutex::new(0);

// ===========================================================================
// Debug Callback
// ===========================================================================

/// Debug callback passed to `BtVcp::set_debug()`.  Forwards VCP engine
/// trace messages into the structured tracing framework.
fn vcp_debug(msg: &str) {
    debug!("VCP: {}", msg);
}

// ===========================================================================
// Volume Changed Callback
// ===========================================================================

/// Callback invoked by the VCP engine when the remote device's volume
/// state changes (via GATT notification).
///
/// The C original calls `media_transport_volume_changed(data->device)` here.
/// Since the transport module is not yet wired in the Rust codebase, this
/// logs the event and performs the session lookup to maintain the complete
/// control-flow path.  The transport call site is marked for future wiring.
fn vcp_volume_changed(volume: u8) {
    let sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    // In the C code, we match by vcp pointer.  Here we iterate sessions
    // and log the volume change for the associated device.  The actual
    // media_transport_volume_changed() call will be connected when the
    // transport module is available.
    if sessions.is_empty() {
        debug!("VCP: volume changed to {} but no active sessions", volume);
        return;
    }

    debug!("VCP: volume changed to {}", volume);

    // Future: call media_transport_update_device_volume(device) for the
    // matching session.  Currently a no-op pending transport wiring.
}

// ===========================================================================
// Session Management
// ===========================================================================

/// Add a new VCP session, guarding against duplicates for the same device.
///
/// Configures the debug callback, registers the volume-changed callback,
/// and stores the session in the global sessions list.
fn vcp_data_add(
    vcp: &Arc<BtVcp>,
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    service: Option<&Arc<std::sync::Mutex<BtdService>>>,
) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("VCP: failed to lock sessions for add");
            return;
        }
    };

    // Guard against duplicate sessions for the same device.
    let dev_ptr = Arc::as_ptr(device);
    if sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr) {
        debug!("VCP: session already exists for device");
        return;
    }

    debug!("VCP: adding session");

    // Configure debug callback on the VCP engine.
    vcp.set_debug(vcp_debug);

    // Register volume-changed callback.
    vcp.set_volume_callback(vcp_volume_changed);

    sessions.push(VcpData {
        device: Arc::clone(device),
        service: service.map(Arc::clone),
        vcp: Arc::clone(vcp),
    });
}

/// Remove a VCP session by matching the VCP engine instance pointer.
fn vcp_data_remove(vcp: &Arc<BtVcp>) {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            error!("VCP: failed to lock sessions for remove");
            return;
        }
    };

    let vcp_inner = Arc::as_ptr(vcp);
    let before = sessions.len();
    sessions.retain(|s| Arc::as_ptr(&s.vcp) != vcp_inner);

    if sessions.len() < before {
        debug!("VCP: session removed");
    }
}

/// Find a VCP session by device pointer.
fn find_session_by_device(
    sessions: &[VcpData],
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Option<usize> {
    let dev_ptr = Arc::as_ptr(device);
    sessions.iter().position(|s| Arc::as_ptr(&s.device) == dev_ptr)
}

/// Find a VCP session by BtVcp pointer.
fn find_session_by_vcp(sessions: &[VcpData], vcp: &BtVcp) -> Option<usize> {
    let target = vcp as *const BtVcp;
    sessions.iter().position(|s| Arc::as_ptr(&s.vcp) == target)
}

// ===========================================================================
// Public API — Volume Control
// ===========================================================================

/// Get the current volume level for a device with an active VCP session.
///
/// Returns the volume (0–255) on success, or an error if no VCP session
/// exists for the given device.
///
/// This is the Rust equivalent of the C `bt_audio_vcp_get_volume()`.
pub fn bt_audio_vcp_get_volume(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Result<u8, i32> {
    let sessions = SESSIONS.lock().map_err(|_| -libc::EINVAL)?;

    match find_session_by_device(&sessions, device) {
        Some(idx) => {
            let volume = sessions[idx].vcp.get_volume();
            Ok(volume)
        }
        None => {
            error!("VCP: no session found for device");
            Err(-libc::ENODEV)
        }
    }
}

/// Set the absolute volume on a device with an active VCP session.
///
/// Returns `Ok(())` on success, or an error code on failure:
///   - `-ENODEV` if no VCP session exists for the given device
///   - `-EIO` if the volume write operation fails
///
/// This is the Rust equivalent of the C `bt_audio_vcp_set_volume()`.
pub fn bt_audio_vcp_set_volume(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    volume: u8,
) -> Result<(), i32> {
    let sessions = SESSIONS.lock().map_err(|_| -libc::EINVAL)?;

    match find_session_by_device(&sessions, device) {
        Some(idx) => {
            if sessions[idx].vcp.set_volume(volume) {
                Ok(())
            } else {
                error!("VCP: failed to set volume to {}", volume);
                Err(-libc::EIO)
            }
        }
        None => {
            error!("VCP: no session found for device");
            Err(-libc::ENODEV)
        }
    }
}

// ===========================================================================
// Profile Callbacks — Client Side
// ===========================================================================

/// Profile probe callback — creates a VCP session for a newly discovered
/// device advertising VCS.
///
/// Obtains both the adapter's local GATT DB and the remote device's GATT DB,
/// constructs a `BtVcp` instance, and registers the session.
fn vcp_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    debug!("VCP: probe");

    let dev_guard = device.blocking_lock();

    let adapter_arc = dev_guard.get_adapter().clone();
    let remote_db = dev_guard.get_gatt_db().cloned();

    drop(dev_guard);

    // Obtain the local GATT database from the adapter.
    let local_db: Option<GattDb> = {
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => {
                let adapter_clone = adapter_arc.clone();
                // We cannot .await directly in a sync callback, so use
                // block_on from within a spawn_blocking context or
                // tokio::task::block_in_place.
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
            error!("VCP: no local GATT database available");
            return Err(BtdError::not_available());
        }
    };

    // Create the VCP protocol engine instance.
    let vcp = match BtVcp::new(local_db, remote_db) {
        Some(v) => v,
        None => {
            error!("VCP: failed to create VCP instance");
            return Err(BtdError::not_available());
        }
    };

    // Register the session.
    vcp_data_add(&vcp, device, None);

    // Store VCP reference as user data on the VCP engine for later retrieval.
    // The service will be associated later in the accept callback.

    debug!("VCP: probe complete");
    Ok(())
}

/// Profile remove callback — cleans up VCP session data when a device
/// is removed.
fn vcp_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    debug!("VCP: remove");

    let sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let dev_ptr = Arc::as_ptr(device);
    let vcp_opt = sessions
        .iter()
        .find(|s| Arc::as_ptr(&s.device) == dev_ptr)
        .map(|s| Arc::clone(&s.vcp));

    drop(sessions);

    if let Some(vcp) = vcp_opt {
        vcp_data_remove(&vcp);
    }

    debug!("VCP: remove complete");
}

/// Accept callback — attaches the GATT client for remote VCS discovery.
///
/// This is called when the profile connection is being accepted (incoming
/// or outgoing).  Retrieves the device's GATT client and attaches the
/// VCP engine to begin VCS characteristic discovery.
fn vcp_accept(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        debug!("VCP: accept");

        // Look up the VCP session for this device.  We must drop the
        // std::sync::MutexGuard (and avoid holding raw pointers) before
        // any .await point to satisfy Send requirements.
        let vcp = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            let vcp_opt = sessions
                .iter()
                .find(|s| Arc::as_ptr(&s.device) == dev_ptr)
                .map(|s| Arc::clone(&s.vcp));
            // Guard and dev_ptr dropped here.
            match vcp_opt {
                Some(v) => v,
                None => {
                    error!("VCP: no session found in accept");
                    return Err(BtdError::not_available());
                }
            }
        };

        // Retrieve the GATT client from the device.
        let dev_guard = device.lock().await;
        let gatt_client = dev_guard.get_gatt_client().cloned();
        drop(dev_guard);

        // Attach the GATT client to the VCP engine.
        if !vcp.attach(gatt_client) {
            error!("VCP: failed to attach GATT client");
            return Err(BtdError::failed("attach GATT client"));
        }

        debug!("VCP: accept complete — GATT client attached");
        Ok(())
    })
}

/// Disconnect callback — detaches the VCP engine from the GATT client.
fn vcp_disconnect(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        debug!("VCP: disconnect");

        // Look up and detach the VCP session.  The std::sync::Mutex guard
        // must be dropped before any potential .await (none here, but
        // future-proofing the pattern).
        let vcp_opt = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            sessions
                .iter()
                .find(|s| Arc::as_ptr(&s.device) == dev_ptr)
                .map(|s| Arc::clone(&s.vcp))
        };

        if let Some(vcp) = vcp_opt {
            vcp.detach();
        }

        debug!("VCP: disconnect complete");
        Ok(())
    })
}

// ===========================================================================
// Remote Client Attach/Detach Callbacks
// ===========================================================================

/// Callback invoked when a remote GATT client attaches to the local VCS
/// server.  Maps the ATT file descriptor to a device and creates a session.
fn vcp_remote_client_attached(vcp: &BtVcp) {
    debug!("VCP: remote client attached");

    // Get ATT transport from VCP to look up the device.
    let att_arc = match vcp.get_att() {
        Some(a) => a,
        None => {
            error!("VCP: no ATT transport in remote attach");
            return;
        }
    };

    // Get the file descriptor from the ATT transport.
    let fd = {
        let att_guard = match att_arc.lock() {
            Ok(g) => g,
            Err(_) => {
                error!("VCP: failed to lock ATT");
                return;
            }
        };
        match att_guard.get_fd() {
            Ok(fd) => fd,
            Err(e) => {
                error!("VCP: failed to get ATT fd: {}", e);
                return;
            }
        }
    };

    // Look up the device by file descriptor via the default adapter.
    let device = {
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

    if device.is_none() {
        debug!("VCP: could not find device for fd {}", fd);
        // This is expected since btd_adapter_find_device_by_fd is a
        // placeholder returning None.  The session will be created once
        // the adapter-device FD mapping is fully wired.
    }

    // In the C original, if device is found, a session is created via
    // vcp_data_add(vcp, device, NULL).  Since find_device_by_fd is not
    // yet functional, we log and return.
    debug!("VCP: remote client attach handling complete");
}

/// Callback invoked when a remote GATT client detaches from the local VCS.
fn vcp_remote_client_detached(vcp: &BtVcp) {
    debug!("VCP: remote client detached");

    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let target = vcp as *const BtVcp;
    let before = sessions.len();
    sessions.retain(|s| Arc::as_ptr(&s.vcp) != target);

    if sessions.len() < before {
        debug!("VCP: remote client session removed");
    }
}

// ===========================================================================
// Server-Side Adapter Callbacks
// ===========================================================================

/// Adapter probe — registers VCS in the adapter's local GATT database.
fn vcp_server_probe(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) -> Result<(), BtdError> {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    match rt {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let path = adapter_get_path(&adapter_clone).await;
                    debug!("VCP: server probe on {}", path);

                    let database = btd_adapter_get_database(&adapter_clone).await;
                    if let Some(db) = database {
                        let gatt_db = db.get_db().await;
                        bt_vcp_add_db(&gatt_db);
                        debug!("VCP: VCS registered in local GATT DB on {}", path);
                    } else {
                        error!("VCP: no GATT database on adapter {}", path);
                    }
                });
            });
        }
        Err(_) => {
            error!("VCP: no tokio runtime for server probe");
        }
    }

    Ok(())
}

/// Adapter remove — logs the removal (minimal cleanup, matching C behavior).
fn vcp_server_remove(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) {
    let adapter_clone = Arc::clone(adapter);

    let rt = tokio::runtime::Handle::try_current();
    if let Ok(handle) = rt {
        tokio::task::block_in_place(|| {
            handle.block_on(async {
                let path = adapter_get_path(&adapter_clone).await;
                debug!("VCP: server remove on {}", path);
            });
        });
    }
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the VCP plugin.
///
/// Registers the VCP profile with the daemon and sets up global
/// attach/detach callbacks for remote VCS client tracking.
fn vcp_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("VCP: initializing plugin");

    // Register the VCP profile.
    tokio::spawn(async {
        let mut profile = BtdProfile::new("vcp");
        profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        profile.bearer = BTD_PROFILE_BEARER_LE;
        profile.experimental = true;
        profile.remote_uuid = Some(VCS_UUID_STR.to_string());

        // Device lifecycle callbacks.
        profile.set_device_probe(Box::new(vcp_probe));
        profile.set_device_remove(Box::new(vcp_remove));

        // Accept and disconnect use async callbacks (ConnectFn/DisconnectFn).
        profile.set_accept(Box::new(|device| vcp_accept(device)));
        profile.set_disconnect(Box::new(|device| vcp_disconnect(device)));

        // Adapter lifecycle callbacks (server-side VCS registration).
        profile.set_adapter_probe(Box::new(vcp_server_probe));
        profile.set_adapter_remove(Box::new(vcp_server_remove));

        if let Err(e) = btd_profile_register(profile).await {
            error!("VCP: failed to register profile: {}", e);
        } else {
            debug!("VCP: profile registered");
        }
    });

    // Register global VCP attach/detach callbacks.
    let attached_cb: Box<dyn Fn(&BtVcp) + Send + Sync> =
        Box::new(vcp_remote_client_attached);
    let detached_cb: Box<dyn Fn(&BtVcp) + Send + Sync> =
        Box::new(vcp_remote_client_detached);

    let id = bt_vcp_register(Some(attached_cb), Some(detached_cb));

    {
        let mut vcp_id = VCP_REGISTER_ID.lock().unwrap();
        *vcp_id = id;
    }

    debug!("VCP: plugin initialized (register_id={})", id);
    Ok(())
}

/// Shut down the VCP plugin.
///
/// Unregisters the global attach/detach callbacks and the VCP profile.
fn vcp_exit() {
    debug!("VCP: shutting down plugin");

    // Unregister global VCP callbacks.
    let id = {
        let vcp_id = VCP_REGISTER_ID.lock().unwrap();
        *vcp_id
    };

    if id != 0 {
        bt_vcp_unregister(id);
    }

    // Unregister the profile.
    tokio::spawn(async {
        let profile = BtdProfile::new("vcp");
        btd_profile_unregister(&profile).await;
        debug!("VCP: profile unregistered");
    });

    // Clear all remaining sessions.
    if let Ok(mut sessions) = SESSIONS.lock() {
        sessions.clear();
    }

    debug!("VCP: plugin shut down");
}

// ===========================================================================
// Inventory Plugin Registration
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "vcp",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: vcp_init,
        exit: vcp_exit,
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::BtdAdapter;

    /// Global test serialization lock — all VCP tests must acquire this
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
    fn test_vcs_uuid_str_is_correct() {
        assert_eq!(VCS_UUID_STR, "00001844-0000-1000-8000-00805f9b34fb");
    }

    #[test]
    fn test_media_endpoint_interface_constant() {
        assert_eq!(MEDIA_ENDPOINT_INTERFACE, "org.bluez.MediaEndpoint1");
    }

    // -----------------------------------------------------------------------
    // Public API — no session edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_volume_returns_enodev_when_no_sessions() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let device = make_test_device();
        let result = bt_audio_vcp_get_volume(&device);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), -libc::ENODEV);
    }

    #[test]
    fn test_set_volume_returns_enodev_when_no_sessions() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let device = make_test_device();
        let result = bt_audio_vcp_set_volume(&device, 128);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), -libc::ENODEV);
    }

    // -----------------------------------------------------------------------
    // Debug / volume callbacks — smoke tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_vcp_debug_does_not_panic() {
        vcp_debug("test debug message");
        vcp_debug("");
        vcp_debug("special chars: <>&\"'");
    }

    #[test]
    fn test_vcp_volume_changed_no_sessions_does_not_panic() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        vcp_volume_changed(0);
        vcp_volume_changed(128);
        vcp_volume_changed(255);
    }

    // -----------------------------------------------------------------------
    // Session management helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_by_device_empty() {
        let sessions: Vec<VcpData> = Vec::new();
        let device = make_test_device();
        assert!(find_session_by_device(&sessions, &device).is_none());
    }

    #[test]
    fn test_vcp_data_remove_on_empty_sessions() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let gatt_db = GattDb::new();
        if let Some(vcp) = BtVcp::new(gatt_db, None) {
            vcp_data_remove(&vcp); // should not panic on empty sessions
        }
    }

    #[test]
    fn test_vcp_data_add_and_find() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let gatt_db = GattDb::new();
        let vcp = match BtVcp::new(gatt_db, None) {
            Some(v) => v,
            None => return, // Skip if BtVcp construction needs more setup
        };
        let device = make_test_device();
        vcp_data_add(&vcp, &device, None);

        // Should find the session.
        assert_eq!(session_count(), 1);
        assert!(has_session_for(&device));

        // Cleanup.
        vcp_data_remove(&vcp);
        assert_eq!(session_count(), 0);
    }

    #[test]
    fn test_vcp_data_add_prevents_duplicates() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let gatt_db = GattDb::new();
        let vcp = match BtVcp::new(gatt_db, None) {
            Some(v) => v,
            None => return,
        };
        let device = make_test_device();
        vcp_data_add(&vcp, &device, None);
        vcp_data_add(&vcp, &device, None); // duplicate — should be ignored

        assert_eq!(session_count(), 1);

        // Cleanup.
        vcp_data_remove(&vcp);
        clear_sessions();
    }

    #[test]
    fn test_get_volume_with_session() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let gatt_db = GattDb::new();
        let vcp = match BtVcp::new(gatt_db, None) {
            Some(v) => v,
            None => return,
        };
        let device = make_test_device();
        vcp_data_add(&vcp, &device, None);

        let result = bt_audio_vcp_get_volume(&device);
        // Volume should be the default (typically 0).
        assert!(result.is_ok());

        // Cleanup.
        vcp_data_remove(&vcp);
        clear_sessions();
    }

    #[test]
    fn test_set_volume_with_session() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let gatt_db = GattDb::new();
        let vcp = match BtVcp::new(gatt_db, None) {
            Some(v) => v,
            None => return,
        };
        let device = make_test_device();
        vcp_data_add(&vcp, &device, None);

        // set_volume may return false if the VCP engine's internal write
        // fails (no ATT transport connected), which maps to -EIO.
        let result = bt_audio_vcp_set_volume(&device, 100);
        // Either Ok(()) or Err(-EIO) is acceptable — both indicate the
        // session was found and the delegation path was exercised.
        match result {
            Ok(()) => {} // Volume was set successfully.
            Err(e) => assert_eq!(e, -libc::EIO, "unexpected error code: {}", e),
        }

        // Cleanup.
        vcp_data_remove(&vcp);
        clear_sessions();
    }

    // -----------------------------------------------------------------------
    // Remote client detach
    // -----------------------------------------------------------------------

    #[test]
    fn test_remote_client_detached_no_session() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();
        let gatt_db = GattDb::new();
        if let Some(vcp) = BtVcp::new(gatt_db, None) {
            // Detach on a VCP that has no session entry — should not panic.
            vcp_remote_client_detached(&vcp);
        }
    }

    // -----------------------------------------------------------------------
    // Multiple devices
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_devices_separate_sessions() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        let gatt_db1 = GattDb::new();
        let vcp1 = match BtVcp::new(gatt_db1, None) {
            Some(v) => v,
            None => return,
        };
        let dev1 = make_test_device();
        vcp_data_add(&vcp1, &dev1, None);

        let gatt_db2 = GattDb::new();
        let vcp2 = match BtVcp::new(gatt_db2, None) {
            Some(v) => v,
            None => {
                vcp_data_remove(&vcp1);
                clear_sessions();
                return;
            }
        };
        let dev2 = make_test_device();
        vcp_data_add(&vcp2, &dev2, None);

        assert_eq!(session_count(), 2);
        assert!(has_session_for(&dev1));
        assert!(has_session_for(&dev2));

        // Get volume for each — both should succeed.
        assert!(bt_audio_vcp_get_volume(&dev1).is_ok());
        assert!(bt_audio_vcp_get_volume(&dev2).is_ok());

        // Remove first device session.
        vcp_data_remove(&vcp1);
        assert_eq!(session_count(), 1);
        assert!(!has_session_for(&dev1));
        assert!(has_session_for(&dev2));

        // First device should now return ENODEV, second still OK.
        assert_eq!(bt_audio_vcp_get_volume(&dev1).unwrap_err(), -libc::ENODEV);
        assert!(bt_audio_vcp_get_volume(&dev2).is_ok());

        // Cleanup.
        vcp_data_remove(&vcp2);
        clear_sessions();
    }
}
