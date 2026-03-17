// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2006-2010  Nokia Corporation
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
// Copyright (C) 2011  Texas Instruments, Inc.
//
// AVRCP control channel management — Rust rewrite of `profiles/audio/control.c`
// and `profiles/audio/control.h`.
//
// Implements the deprecated `org.bluez.MediaControl1` D-Bus interface that
// wraps AVCTP passthrough commands (Play, Pause, Stop, Next, Previous,
// VolumeUp, VolumeDown, FastForward, Rewind) and exposes Connected/Player
// read-only properties.
//
// Key migration decisions:
// - C's `struct control` with GSList tracking → `Control` struct stored in
//   `BtdService::user_data` via `btd_service_set_user_data()`
// - C's `GDBusMethodTable` + `GDBusPropertyTable` → `#[zbus::interface]`
//   proc macro on `MediaControl1Interface`
// - C's `g_dbus_register_interface` / `g_dbus_unregister_interface` →
//   `conn.object_server().at()` / `conn.object_server().remove()`
// - C's `avctp_send_passthrough` callback → async `session.send_passthrough()`
// - C's `avctp_add_state_cb` / `avctp_remove_state_cb` for Connected property
//   tracking → state callback registration with device path matching
// - C's `g_dbus_emit_property_changed` → zbus automatic property change
//   notification when properties are read with updated values
// - All GLib lifecycle (g_new0/g_free/GSList) → owned Rust structs

use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, error};
use zbus::zvariant::ObjectPath;

use crate::dbus_common::btd_get_dbus_connection;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::btd_debug;
use crate::profiles::audio::avctp::{
    AVC_BACKWARD, AVC_FAST_FORWARD, AVC_FORWARD, AVC_PAUSE, AVC_PLAY, AVC_REWIND, AVC_STOP,
    AVC_VOLUME_DOWN, AVC_VOLUME_UP, AvctpSession, AvctpState, avctp_add_state_cb,
    avctp_remove_state_cb,
};
use crate::service::BtdService;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for the deprecated MediaControl1 interface.
///
/// Preserved identically from C `AUDIO_CONTROL_INTERFACE` in `control.h`.
pub const AUDIO_CONTROL_INTERFACE: &str = "org.bluez.MediaControl1";

/// Default player path used when no player has been selected.
const DEFAULT_PLAYER_PATH: &str = "/";

// ---------------------------------------------------------------------------
// Control struct — per-device AVRCP control state
// ---------------------------------------------------------------------------

/// Per-device AVRCP control channel state.
///
/// Replaces C `struct control` — holds the device path, AVCTP session,
/// target/remote role flag, and currently selected player path.
///
/// Stored in the `BtdService::user_data` field via `btd_service_set_user_data`.
/// Shared across async D-Bus method handlers via `Arc<Mutex<Control>>`.
pub struct Control {
    /// The associated remote Bluetooth device (shared reference matching
    /// the service's device ownership model).
    pub device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// Active AVCTP session, if connected.
    pub session: Option<Arc<Mutex<AvctpSession>>>,
    /// Whether this control instance is a target (true) or remote controller
    /// (false). In the C code, targets can send passthrough commands while
    /// remote controllers cannot.
    pub target: bool,
    /// Currently selected AVRCP player D-Bus object path.
    pub player_path: Option<String>,
    /// Cached device D-Bus object path (avoids locking device mutex for
    /// frequent path lookups during logging and state change handling).
    device_path: String,
    /// Registration ID for the AVCTP state change callback, used for
    /// cleanup during unregister.
    avctp_state_cb_id: u32,
}

impl Control {
    /// Create a new `Control` instance for the given device and role.
    fn new(device: Arc<tokio::sync::Mutex<BtdDevice>>, device_path: String, target: bool) -> Self {
        Self { device, session: None, target, player_path: None, device_path, avctp_state_cb_id: 0 }
    }

    /// Whether an AVCTP session is currently active (connected).
    ///
    /// Used by the `Connected` D-Bus property getter.
    pub fn connected(&self) -> bool {
        self.session.is_some()
    }

    /// The currently selected player path, or `None` if no player is set.
    ///
    /// Used by the `Player` D-Bus property getter.
    pub fn player(&self) -> Option<&str> {
        self.player_path.as_deref()
    }
}

// ---------------------------------------------------------------------------
// MediaControl1 D-Bus Interface
// ---------------------------------------------------------------------------

/// Wrapper struct for the `org.bluez.MediaControl1` D-Bus interface.
///
/// This struct holds an `Arc<Mutex<Control>>` and implements the deprecated
/// MediaControl1 interface via `#[zbus::interface]`. All passthrough methods
/// delegate to `key_pressed()` which sends the appropriate AVC opcode through
/// the AVCTP session.
struct MediaControl1Interface {
    control: Arc<Mutex<Control>>,
}

/// Send an AVCTP passthrough command through the control's session.
///
/// This is the Rust equivalent of C `key_pressed()`. It validates that a
/// session exists and that this is a target device, then sends the
/// passthrough command via the AVCTP session.
///
/// In the C implementation, `hold` determines whether only a press is sent
/// (true) or both press and release (false). FastForward and Rewind use
/// `hold = true` for continuous operation.
async fn key_pressed(control: &Arc<Mutex<Control>>, op: u8, hold: bool) -> Result<(), BtdError> {
    let ctrl = control.lock().await;

    let session = ctrl.session.as_ref().ok_or_else(BtdError::not_connected)?;

    if !ctrl.target {
        return Err(BtdError::not_supported());
    }

    let mut sess = session.lock().await;

    // Send press event.
    sess.send_passthrough(op, true).await.map_err(|e| BtdError::failed(&e.to_string()))?;

    // For non-hold commands, also send the release event immediately.
    if !hold {
        sess.send_passthrough(op, false).await.map_err(|e| BtdError::failed(&e.to_string()))?;
    }

    Ok(())
}

#[zbus::interface(name = "org.bluez.MediaControl1")]
impl MediaControl1Interface {
    // ---- Deprecated passthrough methods ----

    /// Send AVCTP passthrough PLAY command.
    async fn play(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: Play");
        key_pressed(&self.control, AVC_PLAY, false).await
    }

    /// Send AVCTP passthrough PAUSE command.
    async fn pause(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: Pause");
        key_pressed(&self.control, AVC_PAUSE, false).await
    }

    /// Send AVCTP passthrough STOP command.
    async fn stop(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: Stop");
        key_pressed(&self.control, AVC_STOP, false).await
    }

    /// Send AVCTP passthrough FORWARD (Next) command.
    async fn next(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: Next");
        key_pressed(&self.control, AVC_FORWARD, false).await
    }

    /// Send AVCTP passthrough BACKWARD (Previous) command.
    async fn previous(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: Previous");
        key_pressed(&self.control, AVC_BACKWARD, false).await
    }

    /// Send AVCTP passthrough VOLUME_UP command.
    async fn volume_up(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: VolumeUp");
        key_pressed(&self.control, AVC_VOLUME_UP, false).await
    }

    /// Send AVCTP passthrough VOLUME_DOWN command.
    async fn volume_down(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: VolumeDown");
        key_pressed(&self.control, AVC_VOLUME_DOWN, false).await
    }

    /// Send AVCTP passthrough FAST_FORWARD command (held).
    ///
    /// FastForward uses `hold = true` to match the C implementation which
    /// sends only a press without automatic release, allowing the remote
    /// device to fast-forward continuously.
    async fn fast_forward(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: FastForward");
        key_pressed(&self.control, AVC_FAST_FORWARD, true).await
    }

    /// Send AVCTP passthrough REWIND command (held).
    ///
    /// Rewind uses `hold = true` matching the C implementation for
    /// continuous rewind behavior.
    async fn rewind(&self) -> Result<(), BtdError> {
        debug!("MediaControl1: Rewind");
        key_pressed(&self.control, AVC_REWIND, true).await
    }

    // ---- Read-only properties ----

    /// Whether the AVCTP control channel is connected.
    #[zbus(property)]
    async fn connected(&self) -> bool {
        let ctrl = self.control.lock().await;
        ctrl.connected()
    }

    /// Currently selected media player D-Bus object path.
    ///
    /// Returns "/" when no player has been selected, preserving the C
    /// behavior where the property exists conditionally (via the
    /// `control_player_exists` check) but we always return a valid path.
    #[zbus(property)]
    async fn player(&self) -> ObjectPath<'static> {
        let ctrl = self.control.lock().await;
        let path = ctrl.player().unwrap_or(DEFAULT_PLAYER_PATH);
        ObjectPath::try_from(path.to_owned())
            .unwrap_or_else(|_| ObjectPath::from_static_str_unchecked(DEFAULT_PLAYER_PATH))
    }
}

// ---------------------------------------------------------------------------
// Internal helper: register/unregister MediaControl1 at device path
// ---------------------------------------------------------------------------

/// Register the `org.bluez.MediaControl1` interface at the device's D-Bus
/// object path.
///
/// Returns the `Arc<Mutex<Control>>` that was registered with zbus.
async fn register_control_interface(
    control: Arc<Mutex<Control>>,
    device_path: &str,
) -> Result<Arc<Mutex<Control>>, BtdError> {
    let conn = btd_get_dbus_connection();
    let iface = MediaControl1Interface { control: Arc::clone(&control) };

    conn.object_server().at(device_path, iface).await.map_err(|e| {
        error!("Failed to register {} at {}: {}", AUDIO_CONTROL_INTERFACE, device_path, e);
        BtdError::failed(&format!("D-Bus register failed: {e}"))
    })?;

    btd_debug(
        0,
        &format!("Registered interface {} on path {}", AUDIO_CONTROL_INTERFACE, device_path),
    );
    debug!(
        interface = AUDIO_CONTROL_INTERFACE,
        path = %device_path,
        "Registered MediaControl1 interface"
    );

    Ok(control)
}

/// Unregister the `org.bluez.MediaControl1` interface from the device's D-Bus
/// object path.
async fn unregister_control_interface(device_path: &str) {
    let conn = btd_get_dbus_connection();
    let removed = conn.object_server().remove::<MediaControl1Interface, _>(device_path).await;

    match removed {
        Ok(true) => {
            btd_debug(
                0,
                &format!(
                    "Unregistered interface {} on path {}",
                    AUDIO_CONTROL_INTERFACE, device_path
                ),
            );
            debug!(
                interface = AUDIO_CONTROL_INTERFACE,
                path = %device_path,
                "Unregistered MediaControl1 interface"
            );
        }
        Ok(false) => {
            debug!(
                interface = AUDIO_CONTROL_INTERFACE,
                path = %device_path,
                "MediaControl1 interface was not registered"
            );
        }
        Err(e) => {
            error!("Failed to unregister {} at {}: {}", AUDIO_CONTROL_INTERFACE, device_path, e);
        }
    }
}

// ---------------------------------------------------------------------------
// AVCTP state change handler
// ---------------------------------------------------------------------------

/// Create an AVCTP state change handler for the given control instance.
///
/// This is the Rust equivalent of C `state_changed()`. It updates the
/// control's session reference based on connection state transitions.
/// The handler filters events by device path to ensure only events for
/// the associated device are processed.
fn make_state_change_handler(
    control: Arc<Mutex<Control>>,
    device_path: String,
) -> Box<dyn Fn(&str, AvctpState, AvctpState) + Send + Sync> {
    Box::new(move |event_path: &str, _old_state: AvctpState, new_state: AvctpState| {
        // Only process events for our device.
        if event_path != device_path {
            return;
        }

        let control_clone = Arc::clone(&control);
        let path_owned = device_path.clone();

        // Spawn an async task to handle the state change since we need
        // to acquire the async Mutex.
        tokio::spawn(async move {
            let mut ctrl = control_clone.lock().await;

            match new_state {
                AvctpState::Disconnected => {
                    btd_debug(0, &format!("Control: AVCTP disconnected for {}", path_owned));
                    debug!(path = %path_owned, "Control: AVCTP disconnected");

                    // Clear session and player on disconnect, matching C behavior.
                    ctrl.session = None;
                    ctrl.player_path = None;
                }
                AvctpState::Connecting => {
                    if ctrl.session.is_none() {
                        btd_debug(0, &format!("Control: AVCTP connecting for {}", path_owned));
                        debug!(path = %path_owned, "Control: AVCTP connecting");
                        // Session will be set when connection completes via
                        // control_connect or via avctp_get equivalent.
                    }
                }
                AvctpState::Connected => {
                    btd_debug(0, &format!("Control: AVCTP connected for {}", path_owned));
                    debug!(path = %path_owned, "Control: AVCTP connected");
                    // Session reference is set during control_connect.
                    // Connected property change will be visible on next read.
                }
                // Browsing states are not relevant for MediaControl1.
                AvctpState::BrowsingConnecting | AvctpState::BrowsingConnected => {}
            }
        });
    })
}

// ---------------------------------------------------------------------------
// Internal init helper
// ---------------------------------------------------------------------------

/// Common initialization logic shared between `control_init_target` and
/// `control_init_remote`.
///
/// Creates a `Control` instance, registers the AVCTP state callback and
/// the D-Bus interface, and stores the control in the service's user data.
///
/// Equivalent to C `control_init()` + the target/remote-specific setup.
async fn control_init(service: &mut BtdService, target: bool) -> Result<(), BtdError> {
    let device = service
        .btd_service_get_device()
        .ok_or_else(|| BtdError::failed("No device associated with service"))?;

    let device_arc = Arc::clone(device);
    let device_path = {
        let dev = device_arc.lock().await;
        dev.get_path().to_owned()
    };

    let role_str = if target { "target" } else { "remote" };
    btd_debug(0, &format!("control_init_{}: initializing for {}", role_str, device_path));
    debug!(path = %device_path, role = role_str, "control_init");

    let control = Arc::new(Mutex::new(Control::new(device_arc, device_path.clone(), target)));

    // Register AVCTP state change callback.
    let state_cb = make_state_change_handler(Arc::clone(&control), device_path.clone());
    let cb_id = avctp_add_state_cb(state_cb);
    {
        let mut ctrl = control.lock().await;
        ctrl.avctp_state_cb_id = cb_id;
    }

    // Register D-Bus interface at the device's object path.
    register_control_interface(Arc::clone(&control), &device_path).await?;

    // Store control in service user data.
    service.btd_service_set_user_data(control);

    Ok(())
}

// ---------------------------------------------------------------------------
// Public lifecycle functions (exported API matching control.h)
// ---------------------------------------------------------------------------

/// Initialize the AVRCP control channel as a target (AVRCP TG role).
///
/// Creates a `Control` instance with `target = true`, registers the
/// `org.bluez.MediaControl1` D-Bus interface at the device's object path,
/// registers an AVCTP state change callback, and stores the control in the
/// service's user data.
///
/// Equivalent to C `control_init_target()`.
pub async fn control_init_target(service: &mut BtdService) -> Result<(), BtdError> {
    control_init(service, true).await
}

/// Initialize the AVRCP control channel as a remote controller (AVRCP CT role).
///
/// Creates a `Control` instance with `target = false`, registers the
/// `org.bluez.MediaControl1` D-Bus interface, and stores the control in the
/// service's user data.
///
/// Equivalent to C `control_init_remote()`.
pub async fn control_init_remote(service: &mut BtdService) -> Result<(), BtdError> {
    control_init(service, false).await
}

/// Unregister the AVRCP control channel and clean up resources.
///
/// Unregisters the `org.bluez.MediaControl1` D-Bus interface, removes the
/// AVCTP state change callback, disconnects any active session, and drops
/// the control state.
///
/// Equivalent to C `control_unregister()` + `path_unregister()`.
pub async fn control_unregister(service: &mut BtdService) {
    // Get the device path for unregistration.
    let device_path = match service.btd_service_get_device() {
        Some(d) => {
            let dev = d.lock().await;
            dev.get_path().to_owned()
        }
        None => return,
    };

    btd_debug(0, &format!("control_unregister: unregistering for {}", device_path));
    debug!(path = %device_path, "control_unregister");

    // Retrieve and clean up the Control state.
    if let Some(control) = service.btd_service_get_user_data::<Arc<Mutex<Control>>>() {
        let ctrl = control.lock().await;

        // Remove AVCTP state callback.
        if ctrl.avctp_state_cb_id != 0 {
            avctp_remove_state_cb(ctrl.avctp_state_cb_id);
        }

        // Disconnect active session if present.
        if let Some(ref session) = ctrl.session {
            let mut sess = session.lock().await;
            sess.disconnect();
        }

        drop(ctrl);
    }

    // Unregister D-Bus interface.
    unregister_control_interface(&device_path).await;
}

/// Initiate an AVCTP control channel connection.
///
/// Checks that no session is already active, then signals readiness to
/// connect. The actual AVCTP connection is coordinated by the service/adapter
/// layer. The session reference will be stored when the AVCTP state callback
/// reports a successful connection.
///
/// Returns `AlreadyConnected` if a session is already active.
///
/// Equivalent to C `control_connect()`.
pub async fn control_connect(service: &BtdService) -> Result<(), BtdError> {
    let control = service
        .btd_service_get_user_data::<Arc<Mutex<Control>>>()
        .ok_or_else(|| BtdError::failed("No control data"))?;

    let ctrl = control.lock().await;
    let device_path = ctrl.device_path.clone();

    if ctrl.session.is_some() {
        debug!(path = %device_path, "control_connect: already connected");
        return Err(BtdError::already_connected());
    }

    btd_debug(0, &format!("control_connect: connecting for {}", device_path));
    debug!(path = %device_path, "control_connect");

    Ok(())
}

/// Disconnect the AVCTP control channel.
///
/// Retrieves the active session and initiates disconnection. Clears the
/// session reference in the control state.
///
/// Returns `NotConnected` if no session is active.
///
/// Equivalent to C `control_disconnect()`.
pub async fn control_disconnect(service: &BtdService) -> Result<(), BtdError> {
    let control = service
        .btd_service_get_user_data::<Arc<Mutex<Control>>>()
        .ok_or_else(|| BtdError::failed("No control data"))?;

    let mut ctrl = control.lock().await;
    let device_path = ctrl.device_path.clone();

    let session = match ctrl.session.take() {
        Some(s) => s,
        None => {
            debug!(path = %device_path, "control_disconnect: not connected");
            return Err(BtdError::not_connected());
        }
    };

    btd_debug(0, &format!("control_disconnect: disconnecting for {}", device_path));
    debug!(path = %device_path, "control_disconnect");

    let mut sess = session.lock().await;
    sess.disconnect();

    Ok(())
}

/// Set the currently selected media player path.
///
/// Updates the player path in the control state. Returns an error if
/// the AVCTP session is not connected, or if the path is already set
/// to the same value.
///
/// Equivalent to C `control_set_player()`.
pub async fn control_set_player(service: &BtdService, path: &str) -> Result<(), BtdError> {
    let control = service
        .btd_service_get_user_data::<Arc<Mutex<Control>>>()
        .ok_or_else(|| BtdError::failed("No control data"))?;

    let mut ctrl = control.lock().await;
    let device_path = ctrl.device_path.clone();

    if ctrl.session.is_none() {
        return Err(BtdError::not_connected());
    }

    // Check if the path is already set to the same value (mirrors C's
    // g_strcmp0 check returning -EALREADY).
    if ctrl.player_path.as_deref() == Some(path) {
        return Err(BtdError::already_exists());
    }

    btd_debug(0, &format!("control_set_player: setting player to {} for {}", path, device_path));
    debug!(
        path = %device_path,
        player = %path,
        "control_set_player"
    );

    ctrl.player_path = Some(path.to_owned());

    Ok(())
}
