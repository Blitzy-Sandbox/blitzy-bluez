// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2025  Intel Corporation
//
// Bearer interfaces — Rust rewrite of `src/bearer.c` and `src/bearer.h`.
//
// Implements the experimental per-transport bearer D-Bus interfaces
// `org.bluez.Bearer.BREDR1` and `org.bluez.Bearer.LE1`.  Each interface
// is registered on a device's D-Bus object path and provides
// transport-specific Connect/Disconnect methods plus Adapter, Paired,
// Bonded, Connected read-only properties and a Disconnected signal.
//
// Key migration decisions:
// - C's `g_dbus_register_interface(…, bearer_methods, bearer_signals,
//   bearer_properties, …)` → two separate structs implementing
//   `#[zbus::interface]` (one per bearer type).
// - C's `timeout_add_seconds(DISCONNECT_TIMER, …)` → `tokio::spawn` +
//   `tokio::time::sleep` with `JoinHandle::abort()` for cancellation.
// - C's `struct queue *disconnects` (queued D-Bus reply messages) →
//   `Vec<oneshot::Sender>` delivering results when
//   `btd_bearer_disconnected()` fires.
// - C's `DBusMessage *connect` (single in-flight Connect reply) →
//   `Option<oneshot::Sender>` resolved by `btd_bearer_connected()`.
// - All GLib/dbus-1/gdbus references are eliminated.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tracing::debug;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::ObjectPath;

use bluez_shared::sys::bluetooth::{BDADDR_BREDR, BdAddr};
use bluez_shared::sys::mgmt::{
    MGMT_DEV_DISCONN_AUTH_FAILURE, MGMT_DEV_DISCONN_LOCAL_HOST,
    MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND, MGMT_DEV_DISCONN_REMOTE, MGMT_DEV_DISCONN_TIMEOUT,
    MGMT_DEV_DISCONN_UNKNOWN, MGMT_STATUS_DISCONNECTED,
};

use crate::adapter::{adapter_get_path, btd_adapter_disconnect_device};
use crate::dbus_common::btd_get_dbus_connection;
use crate::device::BtdDevice;
use crate::error::{BtdError, btd_error_bredr_errno, btd_error_le_errno};
use crate::log::{btd_debug, btd_error as btd_log_error, btd_warn};
use crate::profile::{BTD_PROFILE_BEARER_BREDR, BTD_PROFILE_BEARER_LE, BtdProfile};
use crate::service::BtdService;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for the BR/EDR bearer.
pub const BTD_BEARER_BREDR_INTERFACE: &str = "org.bluez.Bearer.BREDR1";

/// D-Bus interface name for the LE bearer.
pub const BTD_BEARER_LE_INTERFACE: &str = "org.bluez.Bearer.LE1";

/// Seconds to wait after disconnecting all services before tearing down
/// the underlying HCI link.  Matches C `#define DISCONNECT_TIMER 2`.
pub const DISCONNECT_TIMER: u64 = 2;

// ---------------------------------------------------------------------------
// BtdBearer — Core bearer state (replaces C `struct btd_bearer`)
// ---------------------------------------------------------------------------

/// Per-bearer state attached to a device.
///
/// One instance is created for each bearer type (BR/EDR and LE) when the
/// device is registered on D-Bus.  It tracks in-flight connect/disconnect
/// operations and manages the deferred link disconnect timer.
///
/// In the C code this is an opaque `struct btd_bearer` with `btd_bearer_new`,
/// `btd_bearer_destroy`, and several notification helpers.  In Rust the struct
/// is behind an `Arc<Mutex<…>>` shared between the D-Bus interface objects
/// and the owning device.
pub struct BtdBearer {
    /// The device that owns this bearer.
    device: Arc<Mutex<BtdDevice>>,
    /// Bearer address type: `BDADDR_BREDR` (0x00) for BR/EDR, or an LE
    /// address type (0x01 / 0x02) for the LE bearer.
    bearer_type: u8,
    /// D-Bus object path of the device (e.g. `/org/bluez/hci0/dev_XX_…`).
    path: String,
    /// Handle for the deferred disconnect timer task.
    /// `None` when no timer is running.
    disconn_timer: Option<JoinHandle<()>>,
    /// Sender for the one pending Connect() reply.
    /// Resolved by `btd_bearer_connected()`.
    connect_reply_tx: Option<oneshot::Sender<Result<(), BtdError>>>,
    /// Senders for all pending Disconnect() replies.
    /// All resolved by `btd_bearer_disconnected()`.
    disconnect_reply_txs: Vec<oneshot::Sender<Result<(), BtdError>>>,
    /// Whether the D-Bus interface was successfully registered.
    registered: bool,
}

impl BtdBearer {
    // -------------------------------------------------------------------
    // Lifecycle (replaces C btd_bearer_new / btd_bearer_destroy)
    // -------------------------------------------------------------------

    /// Create a new bearer for the given device and address type.
    ///
    /// Registers the corresponding D-Bus interface
    /// (`org.bluez.Bearer.BREDR1` or `org.bluez.Bearer.LE1`) at the
    /// device's object path.
    ///
    /// Equivalent to C `btd_bearer_new()`.
    pub fn btd_bearer_new(
        device: Arc<Mutex<BtdDevice>>,
        bearer_type: u8,
        path: String,
    ) -> Arc<Mutex<Self>> {
        let bearer = Arc::new(Mutex::new(Self {
            device,
            bearer_type,
            path,
            disconn_timer: None,
            connect_reply_tx: None,
            disconnect_reply_txs: Vec::new(),
            registered: false,
        }));

        // Spawn a task to register the D-Bus interface asynchronously.
        let bearer_clone = Arc::clone(&bearer);
        tokio::spawn(async move {
            let (bt, iface_name) = {
                let b = bearer_clone.lock().await;
                (b.bearer_type, bearer_interface(b.bearer_type).to_owned())
            };

            let conn = btd_get_dbus_connection();
            let obj_path = {
                let b = bearer_clone.lock().await;
                b.path.clone()
            };

            let register_result = if bt == BDADDR_BREDR {
                let iface = BearerBredr { bearer: Arc::clone(&bearer_clone) };
                conn.object_server().at(obj_path.as_str(), iface).await
            } else {
                let iface = BearerLe { bearer: Arc::clone(&bearer_clone) };
                conn.object_server().at(obj_path.as_str(), iface).await
            };

            match register_result {
                Ok(_) => {
                    let mut b = bearer_clone.lock().await;
                    b.registered = true;
                    debug!("Registered {} at {}", iface_name, b.path);
                }
                Err(e) => {
                    btd_log_error(
                        0,
                        &format!("Unable to register {} interface: {}", iface_name, e),
                    );
                }
            }
        });

        bearer
    }

    /// Destroy the bearer, unregistering its D-Bus interface.
    ///
    /// Cancels any pending connect/disconnect operations and removes
    /// the D-Bus interface from the object server.
    ///
    /// Equivalent to C `btd_bearer_destroy()`.
    pub fn btd_bearer_destroy(bearer: &Arc<Mutex<Self>>) {
        let bearer_clone = Arc::clone(bearer);
        tokio::spawn(async move {
            let (path, bt, registered) = {
                let mut b = bearer_clone.lock().await;
                // Cancel any outstanding disconnect timer.
                if let Some(handle) = b.disconn_timer.take() {
                    handle.abort();
                }
                // Drop pending connect reply (sender drops → receiver gets Err).
                b.connect_reply_tx.take();
                // Drop pending disconnect replies.
                b.disconnect_reply_txs.clear();
                (b.path.clone(), b.bearer_type, b.registered)
            };

            if !registered {
                return;
            }

            let conn = btd_get_dbus_connection();
            if bt == BDADDR_BREDR {
                let _ = conn.object_server().remove::<BearerBredr, _>(path.as_str()).await;
            } else {
                let _ = conn.object_server().remove::<BearerLe, _>(path.as_str()).await;
            }

            {
                let mut b = bearer_clone.lock().await;
                b.registered = false;
            }
        });
    }

    // -------------------------------------------------------------------
    // Property change notifications
    // -------------------------------------------------------------------

    /// Emit the `Paired` property-changed signal.
    ///
    /// Called when the pairing state of the bearer changes.
    /// Equivalent to C `btd_bearer_paired()`.
    pub fn btd_bearer_paired(bearer: &Arc<Mutex<Self>>) {
        let bearer_clone = Arc::clone(bearer);
        tokio::spawn(async move {
            let (path, bt, registered) = {
                let b = bearer_clone.lock().await;
                (b.path.clone(), b.bearer_type, b.registered)
            };
            if !registered {
                return;
            }
            emit_property_changed_paired(bt, &path).await;
        });
    }

    /// Emit the `Bonded` property-changed signal.
    ///
    /// Called when the bonding state of the bearer changes.
    /// Equivalent to C `btd_bearer_bonded()`.
    pub fn btd_bearer_bonded(bearer: &Arc<Mutex<Self>>) {
        let bearer_clone = Arc::clone(bearer);
        tokio::spawn(async move {
            let (path, bt, registered) = {
                let b = bearer_clone.lock().await;
                (b.path.clone(), b.bearer_type, b.registered)
            };
            if !registered {
                return;
            }
            emit_property_changed_bonded(bt, &path).await;
        });
    }

    /// Notify that the connection attempt completed.
    ///
    /// `err` is 0 on success, or a negative errno on failure.  When a
    /// Connect() D-Bus call is pending, the appropriate reply (success or
    /// transport-specific error) is sent via the oneshot channel.
    /// Afterwards the `Connected` property-changed signal is emitted.
    ///
    /// Equivalent to C `btd_bearer_connected()`.
    pub fn btd_bearer_connected(bearer: &Arc<Mutex<Self>>, err: i32) {
        let bearer_clone = Arc::clone(bearer);
        tokio::spawn(async move {
            let (tx, bt, path, registered) = {
                let mut b = bearer_clone.lock().await;
                let tx = b.connect_reply_tx.take();
                (tx, b.bearer_type, b.path.clone(), b.registered)
            };

            // Send the deferred reply for Connect().
            if let Some(tx) = tx {
                let result = if err == 0 {
                    Ok(())
                } else if bt == BDADDR_BREDR {
                    Err(btd_error_bredr_errno(-err))
                } else {
                    Err(btd_error_le_errno(-err))
                };
                let _ = tx.send(result);
            }

            if !registered {
                return;
            }

            // Emit Connected property changed.
            emit_property_changed_connected(bt, &path).await;
        });
    }

    /// Notify that the bearer has been disconnected.
    ///
    /// This function:
    /// 1. Calls `device_disconnect_watches_callback()` if no other bearer is
    ///    still connected (matching C behavior).
    /// 2. Sends success replies for all queued Disconnect() D-Bus calls.
    /// 3. Emits the `Connected` property-changed signal.
    /// 4. Maps the MGMT disconnect reason to a `org.bluez.Reason.*` name and
    ///    human-readable message, then emits the `Disconnected(s, s)` signal.
    ///
    /// Equivalent to C `btd_bearer_disconnected()`.
    pub fn btd_bearer_disconnected(bearer: &Arc<Mutex<Self>>, reason: u8) {
        let bearer_clone = Arc::clone(bearer);
        tokio::spawn(async move {
            let (path, bt, registered, device_arc, txs) = {
                let mut b = bearer_clone.lock().await;
                // Cancel any disconnect timer.
                if let Some(handle) = b.disconn_timer.take() {
                    handle.abort();
                }
                let txs = std::mem::take(&mut b.disconnect_reply_txs);
                (b.path.clone(), b.bearer_type, b.registered, Arc::clone(&b.device), txs)
            };

            // If the device has no remaining connections, fire disconnect
            // watches (matching C: `if (!btd_device_is_connected(…))`).
            {
                let dev = device_arc.lock().await;
                if !dev.is_connected() {
                    dev.disconnect_watches_callback(reason);
                }
            }

            // Send success replies for all pending Disconnect() calls.
            for tx in txs {
                let _ = tx.send(Ok(()));
            }

            if !registered {
                return;
            }

            // Map reason to D-Bus signal parameters.
            let (name, message) = disconnect_reason_to_dbus(reason);

            // Emit Connected property changed + Disconnected signal.
            emit_property_changed_connected(bt, &path).await;
            emit_disconnected_signal(bt, &path, name, message).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — D-Bus interface name resolution
// ---------------------------------------------------------------------------

/// Return the D-Bus interface name for the given address type.
///
/// Equivalent to C `bearer_interface()`.
fn bearer_interface(addr_type: u8) -> &'static str {
    if addr_type == BDADDR_BREDR { BTD_BEARER_BREDR_INTERFACE } else { BTD_BEARER_LE_INTERFACE }
}

// ---------------------------------------------------------------------------
// Internal helpers — disconnect reason mapping
// ---------------------------------------------------------------------------

/// Map an MGMT disconnect reason code to a `(name, message)` pair for the
/// `Disconnected` D-Bus signal.
///
/// Returns (`"org.bluez.Reason.*"`, `"human-readable message"`).
///
/// Equivalent to the `switch (reason)` block in C `btd_bearer_disconnected()`.
fn disconnect_reason_to_dbus(reason: u8) -> (&'static str, &'static str) {
    match reason {
        MGMT_DEV_DISCONN_UNKNOWN => ("org.bluez.Reason.Unknown", "Unspecified"),
        MGMT_DEV_DISCONN_TIMEOUT => ("org.bluez.Reason.Timeout", "Connection timeout"),
        MGMT_DEV_DISCONN_LOCAL_HOST => {
            ("org.bluez.Reason.Local", "Connection terminated by local host")
        }
        MGMT_DEV_DISCONN_REMOTE => {
            ("org.bluez.Reason.Remote", "Connection terminated by remote user")
        }
        MGMT_DEV_DISCONN_AUTH_FAILURE => (
            "org.bluez.Reason.Authentication",
            "Connection terminated due to authentication failure",
        ),
        MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND => {
            ("org.bluez.Reason.Suspend", "Connection terminated by local host for suspend")
        }
        _ => {
            btd_warn(0, &format!("Unknown disconnection value: {}", reason));
            ("org.bluez.Reason.Unknown", "Unspecified")
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — service disconnect by bearer type
// ---------------------------------------------------------------------------

/// Disconnect a single service if its profile belongs to the specified bearer.
///
/// Inspects the service's `BtdProfile.bearer` field and disconnects only
/// those services whose profile matches the requested bearer type.
///
/// This is the Rust equivalent of C `bearer_disconnect_service()` which was
/// used as a callback to `btd_device_foreach_service()`.
///
/// # Arguments
/// * `service` — a locked `BtdService` reference
/// * `bdaddr_type` — the bearer address type to disconnect
pub fn bearer_disconnect_service(service: &std::sync::Mutex<BtdService>, bdaddr_type: u8) {
    let mut svc = match service.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let profile: Arc<BtdProfile> = match svc.btd_service_get_profile() {
        Some(p) => Arc::clone(p),
        None => return,
    };

    // Validate the service has a device attached (matches C validation).
    if svc.btd_service_get_device().is_none() {
        return;
    }

    // Skip services that belong to the *other* bearer.
    if bdaddr_type == BDADDR_BREDR {
        if profile.bearer == BTD_PROFILE_BEARER_LE {
            return;
        }
    } else if profile.bearer == BTD_PROFILE_BEARER_BREDR {
        return;
    }

    let name = &profile.name;
    btd_debug(
        0,
        &format!(
            "Disconnecting profile {} for bearer addr type {}",
            if name.is_empty() { "(unknown)" } else { name.as_str() },
            bdaddr_type
        ),
    );

    let _ = svc.btd_service_disconnect();
}

/// Disconnect all services belonging to a specific bearer type.
///
/// Iterates the provided service list and disconnects those whose profile
/// matches the requested bearer type.
///
/// This is the public entry point for bearer-specific service disconnection.
/// Callers must supply the `BtdService` objects; the bearer module itself
/// does not maintain a service registry.
///
/// # Arguments
/// * `services` — slice of shared service references
/// * `bdaddr_type` — the bearer address type to filter by
pub fn bearer_disconnect_services(services: &[Arc<std::sync::Mutex<BtdService>>], bdaddr_type: u8) {
    for svc in services {
        bearer_disconnect_service(svc, bdaddr_type);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — property change and signal emission
// ---------------------------------------------------------------------------

/// Emit PropertyChanged for the Paired property.
async fn emit_property_changed_paired(bt: u8, path: &str) {
    let conn = btd_get_dbus_connection();
    if bt == BDADDR_BREDR {
        if let Ok(r) = conn.object_server().interface::<_, BearerBredr>(path).await {
            let iface = r.get().await;
            let emitter = r.signal_emitter();
            let _ = iface.paired_changed(emitter).await;
        }
    } else if let Ok(r) = conn.object_server().interface::<_, BearerLe>(path).await {
        let iface = r.get().await;
        let emitter = r.signal_emitter();
        let _ = iface.paired_changed(emitter).await;
    }
}

/// Emit PropertyChanged for the Bonded property.
async fn emit_property_changed_bonded(bt: u8, path: &str) {
    let conn = btd_get_dbus_connection();
    if bt == BDADDR_BREDR {
        if let Ok(r) = conn.object_server().interface::<_, BearerBredr>(path).await {
            let iface = r.get().await;
            let emitter = r.signal_emitter();
            let _ = iface.bonded_changed(emitter).await;
        }
    } else if let Ok(r) = conn.object_server().interface::<_, BearerLe>(path).await {
        let iface = r.get().await;
        let emitter = r.signal_emitter();
        let _ = iface.bonded_changed(emitter).await;
    }
}

/// Emit PropertyChanged for the Connected property.
async fn emit_property_changed_connected(bt: u8, path: &str) {
    let conn = btd_get_dbus_connection();
    if bt == BDADDR_BREDR {
        if let Ok(r) = conn.object_server().interface::<_, BearerBredr>(path).await {
            let iface = r.get().await;
            let emitter = r.signal_emitter();
            let _ = iface.connected_changed(emitter).await;
        }
    } else if let Ok(r) = conn.object_server().interface::<_, BearerLe>(path).await {
        let iface = r.get().await;
        let emitter = r.signal_emitter();
        let _ = iface.connected_changed(emitter).await;
    }
}

/// Emit the Disconnected signal.
async fn emit_disconnected_signal(bt: u8, path: &str, name: &str, message: &str) {
    let conn = btd_get_dbus_connection();
    if bt == BDADDR_BREDR {
        if let Ok(r) = conn.object_server().interface::<_, BearerBredr>(path).await {
            let emitter = r.signal_emitter();
            let _ = BearerBredr::disconnected(emitter, name, message).await;
        }
    } else if let Ok(r) = conn.object_server().interface::<_, BearerLe>(path).await {
        let emitter = r.signal_emitter();
        let _ = BearerLe::disconnected(emitter, name, message).await;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — connect / disconnect implementation
// ---------------------------------------------------------------------------

/// Perform the bearer-level connect sequence.
///
/// Checks for already-connected, in-progress bonding/connecting states, and
/// routes to the appropriate transport-specific connect function.
///
/// This stores a oneshot sender in the bearer so that when
/// `btd_bearer_connected()` is called asynchronously, the D-Bus reply can
/// be sent.
///
/// Equivalent to C `bearer_connect()`.
async fn bearer_connect_impl(bearer: &Arc<Mutex<BtdBearer>>) -> Result<(), BtdError> {
    let (tx, rx) = oneshot::channel();

    let (device_arc, bt) = {
        let mut b = bearer.lock().await;

        // Another connect attempt already in-flight?
        if b.connect_reply_tx.is_some() {
            return Err(BtdError::in_progress());
        }

        let device_arc = Arc::clone(&b.device);
        let bt = b.bearer_type;

        {
            let dev = device_arc.lock().await;

            // Already connected on this bearer?
            if dev.bdaddr_type_connected() {
                return Err(BtdError::already_connected());
            }

            // Bonding in progress?
            if dev.is_bonding() {
                return Err(BtdError::in_progress());
            }

            // Another connect attempt in-flight at device level?
            if dev.is_connecting() {
                return Err(BtdError::in_progress());
            }
        }

        // Store the reply sender — resolved by btd_bearer_connected().
        b.connect_reply_tx = Some(tx);
        (device_arc, bt)
    };

    // Initiate the appropriate transport-specific connection.
    if bt == BDADDR_BREDR {
        let mut dev = device_arc.lock().await;
        dev.connect_profiles();
    } else {
        let mut dev = device_arc.lock().await;
        dev.set_temporary(false);
        dev.connect_le();
    }

    // Await the connection result from btd_bearer_connected().
    // If the sender is dropped (e.g. bearer destroyed), treat as failure.
    rx.await.unwrap_or_else(|_| Err(BtdError::failed("Connection cancelled")))
}

/// Perform the bearer-level disconnect sequence.
///
/// Cancels bonding, cancels SDP browse, starts the deferred link disconnect
/// timer, and stores a oneshot sender so that when
/// `btd_bearer_disconnected()` fires, the D-Bus reply is sent.
///
/// Equivalent to C `bearer_disconnect()`.
async fn bearer_disconnect_impl(bearer: &Arc<Mutex<BtdBearer>>) -> Result<(), BtdError> {
    let (tx, rx) = oneshot::channel();

    let (device_arc, bearer_type) = {
        let mut b = bearer.lock().await;
        let device_arc = Arc::clone(&b.device);
        let bt = b.bearer_type;

        {
            let dev = device_arc.lock().await;

            // Not connected on this bearer?
            if !dev.bdaddr_type_connected() {
                return Err(BtdError::not_connected());
            }

            // Device-level disconnect already in progress?
            if dev.is_disconnecting() {
                return Err(BtdError::in_progress());
            }
        }

        // Queue the reply sender.
        b.disconnect_reply_txs.push(tx);

        (device_arc, bt)
    };

    // Cancel bonding (C passes MGMT_STATUS_DISCONNECTED but Rust API takes no args).
    // The constant MGMT_STATUS_DISCONNECTED is available for reference.
    let _status = MGMT_STATUS_DISCONNECTED;
    {
        let mut dev = device_arc.lock().await;
        dev.cancel_bonding();
    }

    // Cancel SDP browse.
    {
        let mut dev = device_arc.lock().await;
        dev.cancel_browse();
    }

    // Remove pending services.
    {
        let mut dev = device_arc.lock().await;
        dev.remove_pending_services();
    }

    debug!("Bearer disconnect initiated for type {} on device", bearer_type);

    // Start the deferred link disconnect timer if not already running.
    {
        let mut b = bearer.lock().await;
        if b.disconn_timer.is_none() {
            let bearer_for_timer = Arc::clone(bearer);
            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(DISCONNECT_TIMER)).await;
                bearer_disconnect_link(bearer_for_timer).await;
            });
            b.disconn_timer = Some(handle);
        }
    }

    // Await the disconnect result from btd_bearer_disconnected().
    rx.await.unwrap_or_else(|_| Err(BtdError::failed("Disconnect cancelled")))
}

/// Perform the actual link-level disconnect after the timer expires.
///
/// Equivalent to C `bearer_disconnect_link()`.
async fn bearer_disconnect_link(bearer: Arc<Mutex<BtdBearer>>) {
    let device_arc = {
        let mut b = bearer.lock().await;
        // Timer fired — clear the handle.
        b.disconn_timer = None;
        Arc::clone(&b.device)
    };

    let dev = device_arc.lock().await;
    // Only disconnect the link if the bearer is still connected.
    if dev.bdaddr_type_connected() {
        let adapter: Arc<Mutex<crate::adapter::BtdAdapter>> = Arc::clone(dev.get_adapter());
        let addr: BdAddr = *dev.get_address();
        drop(dev);
        let _ = btd_adapter_disconnect_device(&adapter, &addr).await;
    }
}

// ---------------------------------------------------------------------------
// D-Bus Interface: org.bluez.Bearer.BREDR1
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.Bearer.BREDR1`.
///
/// Registered at the device's object path to provide per-bearer (BR/EDR)
/// connection management.
///
/// Methods: Connect, Disconnect
/// Properties: Adapter (o), Paired (b), Bonded (b), Connected (b)
/// Signals: Disconnected(s, s)
pub struct BearerBredr {
    bearer: Arc<Mutex<BtdBearer>>,
}

#[zbus::interface(name = "org.bluez.Bearer.BREDR1")]
impl BearerBredr {
    /// Initiate a BR/EDR connection to the device.
    ///
    /// The call blocks until the connection completes or fails.  The result
    /// is delivered via `btd_bearer_connected()`.
    ///
    /// Errors:
    /// - `org.bluez.Error.AlreadyConnected` — device is already connected
    /// - `org.bluez.Error.InProgress` — bonding/connecting already running
    /// - transport-specific error mapped by `btd_error_bredr_errno()`
    async fn connect(&self) -> Result<(), BtdError> {
        bearer_connect_impl(&self.bearer).await
    }

    /// Initiate a BR/EDR disconnection from the device.
    ///
    /// The call blocks until the disconnect completes.  The result is
    /// delivered via `btd_bearer_disconnected()`.
    ///
    /// Errors:
    /// - `org.bluez.Error.NotConnected` — bearer is not connected
    /// - `org.bluez.Error.InProgress` — device-level disconnect in progress
    async fn disconnect(&self) -> Result<(), BtdError> {
        bearer_disconnect_impl(&self.bearer).await
    }

    /// The object path of the adapter that owns this device.
    #[zbus(property)]
    async fn adapter(&self) -> zbus::fdo::Result<ObjectPath<'_>> {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        let adapter = Arc::clone(dev.get_adapter());
        drop(dev);
        let path = adapter_get_path(&adapter).await;
        ObjectPath::try_from(path)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Invalid adapter path: {}", e)))
    }

    /// Whether the device is paired on the BR/EDR bearer.
    #[zbus(property)]
    async fn paired(&self) -> bool {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        dev.is_paired()
    }

    /// Whether the device is bonded on the BR/EDR bearer.
    #[zbus(property)]
    async fn bonded(&self) -> bool {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        dev.is_bonded()
    }

    /// Whether the BR/EDR bearer is currently connected.
    #[zbus(property)]
    async fn connected(&self) -> bool {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        dev.bdaddr_type_connected()
    }

    /// Emitted when the BR/EDR bearer disconnects.
    ///
    /// Parameters:
    /// - `name`: disconnect reason identifier (e.g. `org.bluez.Reason.Remote`)
    /// - `message`: human-readable description
    #[zbus(signal)]
    async fn disconnected(ctxt: &SignalEmitter<'_>, name: &str, message: &str) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// D-Bus Interface: org.bluez.Bearer.LE1
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.Bearer.LE1`.
///
/// Registered at the device's object path to provide per-bearer (LE)
/// connection management.
///
/// Methods: Connect, Disconnect
/// Properties: Adapter (o), Paired (b), Bonded (b), Connected (b)
/// Signals: Disconnected(s, s)
pub struct BearerLe {
    bearer: Arc<Mutex<BtdBearer>>,
}

#[zbus::interface(name = "org.bluez.Bearer.LE1")]
impl BearerLe {
    /// Initiate an LE connection to the device.
    ///
    /// The call blocks until the connection completes or fails.  The result
    /// is delivered via `btd_bearer_connected()`.
    ///
    /// Errors:
    /// - `org.bluez.Error.AlreadyConnected` — device is already connected
    /// - `org.bluez.Error.InProgress` — bonding/connecting already running
    /// - transport-specific error mapped by `btd_error_le_errno()`
    async fn connect(&self) -> Result<(), BtdError> {
        bearer_connect_impl(&self.bearer).await
    }

    /// Initiate an LE disconnection from the device.
    ///
    /// The call blocks until the disconnect completes.  The result is
    /// delivered via `btd_bearer_disconnected()`.
    ///
    /// Errors:
    /// - `org.bluez.Error.NotConnected` — bearer is not connected
    /// - `org.bluez.Error.InProgress` — device-level disconnect in progress
    async fn disconnect(&self) -> Result<(), BtdError> {
        bearer_disconnect_impl(&self.bearer).await
    }

    /// The object path of the adapter that owns this device.
    #[zbus(property)]
    async fn adapter(&self) -> zbus::fdo::Result<ObjectPath<'_>> {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        let adapter = Arc::clone(dev.get_adapter());
        drop(dev);
        let path = adapter_get_path(&adapter).await;
        ObjectPath::try_from(path)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Invalid adapter path: {}", e)))
    }

    /// Whether the device is paired on the LE bearer.
    #[zbus(property)]
    async fn paired(&self) -> bool {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        dev.is_paired()
    }

    /// Whether the device is bonded on the LE bearer.
    #[zbus(property)]
    async fn bonded(&self) -> bool {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        dev.is_bonded()
    }

    /// Whether the LE bearer is currently connected.
    #[zbus(property)]
    async fn connected(&self) -> bool {
        let device_arc = {
            let b = self.bearer.lock().await;
            Arc::clone(&b.device)
        };
        let dev = device_arc.lock().await;
        dev.bdaddr_type_connected()
    }

    /// Emitted when the LE bearer disconnects.
    ///
    /// Parameters:
    /// - `name`: disconnect reason identifier (e.g. `org.bluez.Reason.Remote`)
    /// - `message`: human-readable description
    #[zbus(signal)]
    async fn disconnected(ctxt: &SignalEmitter<'_>, name: &str, message: &str) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_constants() {
        assert_eq!(BTD_BEARER_BREDR_INTERFACE, "org.bluez.Bearer.BREDR1");
        assert_eq!(BTD_BEARER_LE_INTERFACE, "org.bluez.Bearer.LE1");
    }

    #[test]
    fn test_disconnect_timer_constant() {
        assert_eq!(DISCONNECT_TIMER, 2);
    }

    #[test]
    fn test_bearer_interface_helper() {
        assert_eq!(bearer_interface(BDADDR_BREDR), BTD_BEARER_BREDR_INTERFACE);
        assert_eq!(bearer_interface(0x01), BTD_BEARER_LE_INTERFACE);
        assert_eq!(bearer_interface(0x02), BTD_BEARER_LE_INTERFACE);
    }

    #[test]
    fn test_disconnect_reason_mapping_all_known() {
        let (n, m) = disconnect_reason_to_dbus(MGMT_DEV_DISCONN_UNKNOWN);
        assert_eq!(n, "org.bluez.Reason.Unknown");
        assert_eq!(m, "Unspecified");

        let (n, m) = disconnect_reason_to_dbus(MGMT_DEV_DISCONN_TIMEOUT);
        assert_eq!(n, "org.bluez.Reason.Timeout");
        assert_eq!(m, "Connection timeout");

        let (n, m) = disconnect_reason_to_dbus(MGMT_DEV_DISCONN_LOCAL_HOST);
        assert_eq!(n, "org.bluez.Reason.Local");
        assert_eq!(m, "Connection terminated by local host");

        let (n, m) = disconnect_reason_to_dbus(MGMT_DEV_DISCONN_REMOTE);
        assert_eq!(n, "org.bluez.Reason.Remote");
        assert_eq!(m, "Connection terminated by remote user");

        let (n, m) = disconnect_reason_to_dbus(MGMT_DEV_DISCONN_AUTH_FAILURE);
        assert_eq!(n, "org.bluez.Reason.Authentication");
        assert_eq!(m, "Connection terminated due to authentication failure");

        let (n, m) = disconnect_reason_to_dbus(MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND);
        assert_eq!(n, "org.bluez.Reason.Suspend");
        assert_eq!(m, "Connection terminated by local host for suspend");
    }

    #[test]
    fn test_disconnect_reason_mapping_unknown_value() {
        let (n, m) = disconnect_reason_to_dbus(0xFF);
        assert_eq!(n, "org.bluez.Reason.Unknown");
        assert_eq!(m, "Unspecified");

        let (n, m) = disconnect_reason_to_dbus(0x20);
        assert_eq!(n, "org.bluez.Reason.Unknown");
        assert_eq!(m, "Unspecified");
    }
}
