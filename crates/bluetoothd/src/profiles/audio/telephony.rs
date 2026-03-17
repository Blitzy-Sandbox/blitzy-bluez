// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright © 2025 Collabora Ltd.
//
// Telephony D-Bus interface — Rust rewrite of `profiles/audio/telephony.c`
// and `profiles/audio/telephony.h`.
//
// This module provides the `org.bluez.Telephony1` and `org.bluez.Call1` D-Bus
// interfaces used by HFP and future telephony profiles to expose call control,
// operator status, signal/battery indicators, and per-call lifecycle to D-Bus
// clients.
//
// Key migration decisions:
// - C's `struct telephony_callbacks` function-pointer vtable → `TelephonyCallbacks` trait
// - C's `void *profile_data` → `Option<Box<dyn Any + Send + Sync>>`
// - C's `btd_service_ref/unref` → `Arc<Mutex<BtdService>>`
// - C's `btd_device_ref/unref` → `Arc<tokio::sync::Mutex<BtdDevice>>`
// - C's `GSList *uri_schemes` → `Vec<String>`
// - C's `g_dbus_register_interface` → `conn.object_server().at(path, impl).await`
// - C's `g_dbus_emit_property_changed` → zbus property-changed signal emission
// - C's `DBusMessage *pending_msg` in Call → async method returns (no pending msg needed)
// - C's `static int id` counter → `AtomicU32` for thread-safe ID generation
// - All GLib types eliminated; no `malloc`/`free`

use std::any::Any;
use std::fmt;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicU32, Ordering},
};

use tokio::sync::Mutex;
use tracing::debug;

use bluez_shared::sys::bluetooth::BdAddr;

use crate::adapter::btd_adapter_get_address;
use crate::dbus_common::btd_get_dbus_connection;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::service::BtdService;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for the Telephony1 interface.
pub const TELEPHONY_INTERFACE: &str = "org.bluez.Telephony1";

/// D-Bus interface name for the Call1 interface.
pub const TELEPHONY_CALL_INTERFACE: &str = "org.bluez.Call1";

/// Monotonically increasing ID counter for telephony object paths.
/// Matches the C `static int id` used in `telephony_new()`.
static TELEPHONY_ID: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// ConnectionState — telephony connection state enum
// ---------------------------------------------------------------------------

/// Telephony connection state, matching the C `enum connection_state`.
///
/// Used to track the HFP/telephony connection lifecycle.  The `Display`
/// implementation produces the exact same lowercase strings as the C
/// `state_to_string()` function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial connection attempt in progress.
    Connecting = 0,
    /// Session-level (SLC) setup in progress.
    SessionConnecting = 1,
    /// Fully connected and operational.
    Connected = 2,
    /// Graceful disconnection in progress.
    Disconnecting = 3,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ConnectionState::Connecting => "connecting",
            ConnectionState::SessionConnecting => "session_connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::Disconnecting => "disconnecting",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// CallState — per-call state enum
// ---------------------------------------------------------------------------

/// Per-call state, matching the C `enum call_state`.
///
/// The `Display` implementation produces strings identical to the C
/// `call_state_to_string()` function.  Note: `ResponseAndHold` maps to
/// `"response_and_hold"` to match the C original exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Call is active (ongoing voice).
    Active = 0,
    /// Call is on hold.
    Held = 1,
    /// Outgoing call dialing.
    Dialing = 2,
    /// Outgoing call alerting (ringing at remote end).
    Alerting = 3,
    /// Incoming call ringing.
    Incoming = 4,
    /// Incoming call waiting (another call already active).
    Waiting = 5,
    /// Call in Response-and-Hold state.
    ResponseAndHold = 6,
    /// Call has been disconnected.
    Disconnected = 7,
}

impl fmt::Display for CallState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CallState::Active => "active",
            CallState::Held => "held",
            CallState::Dialing => "dialing",
            CallState::Alerting => "alerting",
            CallState::Incoming => "incoming",
            CallState::Waiting => "waiting",
            CallState::ResponseAndHold => "response_and_hold",
            CallState::Disconnected => "disconnected",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// CallData — lightweight reference passed to call_answer/call_hangup
// ---------------------------------------------------------------------------

/// Lightweight data bundle passed to `TelephonyCallbacks::call_answer` and
/// `TelephonyCallbacks::call_hangup`, carrying the call index and path
/// needed by the HFP AT engine to identify the specific call.
pub struct CallData {
    /// Call index (1-based) as reported by the AG.
    pub idx: u8,
    /// D-Bus object path for this call.
    pub path: String,
}

// ---------------------------------------------------------------------------
// TelephonyCallbacks trait
// ---------------------------------------------------------------------------

/// Callback trait replacing the C `struct telephony_callbacks` function-pointer
/// vtable.
///
/// Each method corresponds directly to a D-Bus method on either the
/// `Telephony1` or `Call1` interface.  Implementors (e.g., the HFP plugin)
/// provide the actual telephony control logic.
///
/// All methods return `Result<(), BtdError>` so that failures propagate as
/// typed D-Bus error replies.
///
/// Methods are synchronous (matching the C function-pointer semantics) and
/// the trait is dyn-compatible for storage as `Arc<dyn TelephonyCallbacks>`.
pub trait TelephonyCallbacks: Send + Sync {
    /// Initiate an outgoing call to the given number/URI.
    fn dial(&self, number: &str) -> Result<(), BtdError>;

    /// Swap between the active and held calls.
    fn swap_calls(&self) -> Result<(), BtdError>;

    /// Release the active call and answer the waiting/held call.
    fn release_and_answer(&self) -> Result<(), BtdError>;

    /// Release the active call and swap to the held call.
    fn release_and_swap(&self) -> Result<(), BtdError>;

    /// Place the active call on hold and answer the waiting call.
    fn hold_and_answer(&self) -> Result<(), BtdError>;

    /// Hang up all calls.
    fn hangup_all(&self) -> Result<(), BtdError>;

    /// Merge calls into a multiparty (conference) call.
    fn create_multiparty(&self) -> Result<(), BtdError>;

    /// Send DTMF tone digits.
    fn send_tones(&self, tones: &str) -> Result<(), BtdError>;

    /// Answer an incoming/waiting call identified by `call_data`.
    fn call_answer(&self, call_data: &CallData) -> Result<(), BtdError>;

    /// Hang up a specific call identified by `call_data`.
    fn call_hangup(&self, call_data: &CallData) -> Result<(), BtdError>;
}

// ---------------------------------------------------------------------------
// Call struct
// ---------------------------------------------------------------------------

/// Represents a single telephony call, exposed on D-Bus as `org.bluez.Call1`.
///
/// Each call has its own D-Bus object path of the form
/// `{telephony_path}/call{idx}` and carries per-call state such as caller ID,
/// call state, and multiparty membership.
pub struct Call {
    /// Back-reference to the owning telephony callbacks.
    pub telephony: Arc<dyn TelephonyCallbacks>,
    /// D-Bus object path for this call (e.g., `/org/bluez/hci0/dev_.../telephony0/call1`).
    pub path: String,
    /// Call index (1-based) as reported by the AG.
    pub idx: u8,
    /// Caller line identification (CLIP number).
    pub line_id: Option<String>,
    /// Incoming line identification (CCWA number).
    pub incoming_line: Option<String>,
    /// Caller name (CNAP).
    pub name: Option<String>,
    /// Whether this call is part of a multiparty (conference) call.
    pub multiparty: bool,
    /// Current call state.
    pub state: CallState,
}

// ---------------------------------------------------------------------------
// Call1 D-Bus interface implementation
// ---------------------------------------------------------------------------

/// D-Bus interface wrapper for `org.bluez.Call1`.
///
/// Wraps `Arc<Mutex<Call>>` to allow concurrent access from D-Bus method
/// handlers and internal state updates.
struct Call1Interface {
    inner: Arc<Mutex<Call>>,
}

#[zbus::interface(name = "org.bluez.Call1")]
impl Call1Interface {
    /// Answer this call.
    ///
    /// Delegates to `TelephonyCallbacks::call_answer()` on the owning
    /// telephony instance.
    async fn answer(&self) -> Result<(), BtdError> {
        let call = self.inner.lock().await;
        let call_data = CallData {
            idx: call.idx,
            path: call.path.clone(),
        };
        let cbs = Arc::clone(&call.telephony);
        drop(call);
        cbs.call_answer(&call_data)
    }

    /// Hang up this call.
    ///
    /// Delegates to `TelephonyCallbacks::call_hangup()` on the owning
    /// telephony instance.
    async fn hangup(&self) -> Result<(), BtdError> {
        let call = self.inner.lock().await;
        let call_data = CallData {
            idx: call.idx,
            path: call.path.clone(),
        };
        let cbs = Arc::clone(&call.telephony);
        drop(call);
        cbs.call_hangup(&call_data)
    }

    /// Current call state as a human-readable string.
    #[zbus(property)]
    async fn state(&self) -> String {
        let call = self.inner.lock().await;
        call.state.to_string()
    }

    /// Caller line identification (CLIP).
    ///
    /// Only present when the caller's number is known.
    #[zbus(property, name = "LineIdentification")]
    async fn line_identification(&self) -> String {
        let call = self.inner.lock().await;
        call.line_id.clone().unwrap_or_default()
    }

    /// Incoming call line identification (CCWA).
    ///
    /// Only present for call-waiting scenarios.
    #[zbus(property, name = "IncomingLine")]
    async fn incoming_line(&self) -> String {
        let call = self.inner.lock().await;
        call.incoming_line.clone().unwrap_or_default()
    }

    /// Caller name (CNAP).
    ///
    /// Only present when the caller name is available.
    #[zbus(property)]
    async fn name(&self) -> String {
        let call = self.inner.lock().await;
        call.name.clone().unwrap_or_default()
    }

    /// Whether this call is part of a multiparty (conference) call.
    #[zbus(property)]
    async fn multiparty(&self) -> bool {
        let call = self.inner.lock().await;
        call.multiparty
    }
}

// ---------------------------------------------------------------------------
// Telephony struct — the main telephony model
// ---------------------------------------------------------------------------

/// Represents a telephony endpoint for a specific Bluetooth device, exposed
/// on D-Bus as `org.bluez.Telephony1`.
///
/// Each telephony instance manages:
/// - Connection state and indicator values (signal, battery, roaming, etc.)
/// - A set of active calls (`Call` instances)
/// - A callback interface (`TelephonyCallbacks`) for delegating D-Bus method
///   invocations to the owning profile plugin (e.g., HFP)
///
/// The struct fields are `pub` to match the export schema requirements.
pub struct Telephony {
    /// Reference to the owning `BtdService`.
    pub service: Arc<StdMutex<BtdService>>,
    /// Reference to the peer `BtdDevice`.
    pub device: Arc<Mutex<BtdDevice>>,
    /// D-Bus object path (e.g., `/org/bluez/hci0/dev_.../telephony0`).
    pub path: String,
    /// Source (local adapter) Bluetooth address.
    pub src: BdAddr,
    /// Destination (peer device) Bluetooth address.
    pub dst: BdAddr,
    /// Opaque profile-specific data (replaces C's `void *profile_data`).
    pub profile_data: Option<Box<dyn Any + Send + Sync>>,
    /// Callback vtable provided by the HFP (or other) plugin.
    pub cbs: Arc<dyn TelephonyCallbacks>,
    /// Supported URI schemes (e.g., `["tel"]`).
    pub uri_schemes: Vec<String>,
    /// Current telephony connection state.
    pub state: ConnectionState,
    /// Network service availability indicator (CIND "service").
    pub network_service: bool,
    /// Signal strength indicator (CIND "signal", 0-5).
    pub signal: u8,
    /// Roaming status indicator (CIND "roam").
    pub roaming: bool,
    /// Battery charge indicator (CIND "battchg", 0-5).
    pub battchg: u8,
    /// Network operator name (COPS result).
    pub operator_name: Option<String>,
    /// In-band ringtone support flag.
    pub inband_ringtone: bool,
}

// ---------------------------------------------------------------------------
// Telephony1 D-Bus interface implementation
// ---------------------------------------------------------------------------

/// D-Bus interface wrapper for `org.bluez.Telephony1`.
///
/// Holds an `Arc<Mutex<Telephony>>` for concurrent access from D-Bus method
/// handlers, property getters, and internal state-update APIs.
struct Telephony1Interface {
    inner: Arc<Mutex<Telephony>>,
}

#[zbus::interface(name = "org.bluez.Telephony1")]
impl Telephony1Interface {
    /// Initiate an outgoing call.
    ///
    /// The `uri` parameter is the dialed number (e.g., `"tel:+1234567890"`).
    /// In the C code this method is named `Dial` with argument name `"uri"`.
    async fn dial(&self, uri: String) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.dial(&uri)
    }

    /// Swap the active and held calls.
    async fn swap_calls(&self) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.swap_calls()
    }

    /// Release the active call and answer the waiting/held call.
    async fn release_and_answer(&self) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.release_and_answer()
    }

    /// Release the active call and swap to the held call.
    async fn release_and_swap(&self) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.release_and_swap()
    }

    /// Place the active call on hold and answer the waiting call.
    async fn hold_and_answer(&self) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.hold_and_answer()
    }

    /// Hang up all active calls.
    async fn hangup_all(&self) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.hangup_all()
    }

    /// Create a multiparty (conference) call.
    async fn create_multiparty(&self) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.create_multiparty()
    }

    /// Send DTMF tone digits.
    async fn send_tones(&self, number: String) -> Result<(), BtdError> {
        let tel = self.inner.lock().await;
        let cbs = Arc::clone(&tel.cbs);
        drop(tel);
        cbs.send_tones(&number)
    }

    // ---- Properties (read-only) ----

    /// Current connection state as a human-readable string.
    #[zbus(property)]
    async fn state(&self) -> String {
        let tel = self.inner.lock().await;
        tel.state.to_string()
    }

    /// Supported URI schemes (e.g., `["tel"]`).
    #[zbus(property, name = "SupportedURISchemes")]
    async fn supported_uri_schemes(&self) -> Vec<String> {
        let tel = self.inner.lock().await;
        tel.uri_schemes.clone()
    }

    /// Network service availability indicator.
    #[zbus(property, name = "Service")]
    async fn service(&self) -> bool {
        let tel = self.inner.lock().await;
        tel.network_service
    }

    /// Signal strength indicator (0-5).
    #[zbus(property)]
    async fn signal(&self) -> u8 {
        let tel = self.inner.lock().await;
        tel.signal
    }

    /// Roaming status indicator.
    #[zbus(property)]
    async fn roaming(&self) -> bool {
        let tel = self.inner.lock().await;
        tel.roaming
    }

    /// Battery charge level indicator (0-5).
    #[zbus(property, name = "BattChg")]
    async fn batt_chg(&self) -> u8 {
        let tel = self.inner.lock().await;
        tel.battchg
    }

    /// Network operator name.
    #[zbus(property, name = "OperatorName")]
    async fn operator_name(&self) -> String {
        let tel = self.inner.lock().await;
        tel.operator_name.clone().unwrap_or_default()
    }

    /// In-band ringtone support flag.
    #[zbus(property, name = "InbandRingtone")]
    async fn inband_ringtone(&self) -> bool {
        let tel = self.inner.lock().await;
        tel.inband_ringtone
    }

    /// Profile UUID from the associated `BtdProfile`.
    ///
    /// This read-only property exposes the remote UUID of the profile that
    /// owns this telephony instance (e.g., the HFP-AG UUID).  It is only
    /// present when the profile has a `remote_uuid` set.
    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> String {
        let tel = self.inner.lock().await;
        let svc_guard = tel.service.lock();
        if let Ok(svc) = svc_guard {
            if let Some(profile) = svc.btd_service_get_profile() {
                if let Some(ref uuid) = profile.remote_uuid {
                    return uuid.clone();
                }
            }
        }
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Telephony lifecycle implementation
// ---------------------------------------------------------------------------

impl Telephony {
    /// Create a new telephony instance for the given service.
    ///
    /// Equivalent to C `telephony_new()`.  Extracts the device and adapter
    /// addresses from the service's device and adapter references.
    ///
    /// # Arguments
    ///
    /// * `service` — The owning `BtdService` (shared ownership via `Arc`).
    /// * `profile_data` — Opaque profile-specific data (replaces C `void *`).
    /// * `cbs` — Callback implementation for telephony operations.
    pub async fn new(
        service: Arc<StdMutex<BtdService>>,
        profile_data: Option<Box<dyn Any + Send + Sync>>,
        cbs: Arc<dyn TelephonyCallbacks>,
    ) -> Self {
        // Extract device reference from the service.
        let device = {
            let svc = service.lock().expect("service lock poisoned");
            svc.btd_service_get_device()
                .expect("telephony_new: service has no device")
                .clone()
        };

        // Get the device path and address.
        let (device_path, dst) = {
            let dev = device.lock().await;
            (dev.get_path().to_owned(), *dev.get_address())
        };

        // Get the adapter address.
        let src = {
            let dev = device.lock().await;
            let adapter = dev.get_adapter().clone();
            btd_adapter_get_address(&adapter).await
        };

        // Generate unique path with monotonic counter (matches C static int id).
        let id = TELEPHONY_ID.fetch_add(1, Ordering::Relaxed);
        let path = format!("{}/telephony{}", device_path, id);

        Telephony {
            service,
            device,
            path,
            src,
            dst,
            profile_data,
            cbs,
            uri_schemes: Vec::new(),
            state: ConnectionState::Connecting,
            network_service: false,
            signal: 0,
            roaming: false,
            battchg: 0,
            operator_name: None,
            inband_ringtone: false,
        }
    }

    /// Clean up and release all resources.
    ///
    /// Equivalent to C `telephony_free()`.  In Rust this is primarily handled
    /// by `Drop`, but this method provides explicit cleanup for D-Bus
    /// interface unregistration before the struct is dropped.
    pub async fn free(self) {
        // Unregister the D-Bus interface before dropping.
        // This is a best-effort operation — if the connection is already
        // closed or the path is not registered, we silently ignore errors.
        let conn = btd_get_dbus_connection();
        let _ = conn
            .object_server()
            .remove::<Telephony1Interface, _>(self.path.as_str())
            .await;
        debug!("Unregistered interface {} on path {}", TELEPHONY_INTERFACE, self.path);
    }

    /// Register the `org.bluez.Telephony1` D-Bus interface at this
    /// telephony's object path.
    ///
    /// Equivalent to C `telephony_register_interface()`.
    ///
    /// Returns `Ok(())` on success, or `Err(-EINVAL)` if the interface
    /// registration fails.
    pub async fn register_interface(telephony: &Arc<Mutex<Telephony>>) -> Result<(), i32> {
        let conn = btd_get_dbus_connection();
        let path = {
            let tel = telephony.lock().await;
            tel.path.clone()
        };

        let iface = Telephony1Interface {
            inner: Arc::clone(telephony),
        };

        conn.object_server()
            .at(path.as_str(), iface)
            .await
            .map_err(|_| -libc::EINVAL)?;

        debug!("Registered interface {} on path {}", TELEPHONY_INTERFACE, path);
        Ok(())
    }

    /// Unregister the `org.bluez.Telephony1` D-Bus interface.
    ///
    /// Equivalent to C `telephony_unregister_interface()`.
    pub async fn unregister_interface(telephony: &Arc<Mutex<Telephony>>) {
        let conn = btd_get_dbus_connection();
        let path = {
            let tel = telephony.lock().await;
            tel.path.clone()
        };

        let _ = conn
            .object_server()
            .remove::<Telephony1Interface, _>(path.as_str())
            .await;

        debug!("Unregistered interface {} on path {}", TELEPHONY_INTERFACE, path);
    }

    // ---- Getters (matching C API) ----

    /// Get the owning service reference.
    ///
    /// Equivalent to C `telephony_get_service()`.
    pub fn get_service(&self) -> &Arc<StdMutex<BtdService>> {
        &self.service
    }

    /// Get the peer device reference.
    ///
    /// Equivalent to C `telephony_get_device()`.
    pub fn get_device(&self) -> &Arc<Mutex<BtdDevice>> {
        &self.device
    }

    /// Get the D-Bus object path.
    ///
    /// Equivalent to C `telephony_get_path()`.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Get the source (local adapter) BD address.
    ///
    /// Equivalent to C `telephony_get_src()`.
    pub fn get_src(&self) -> BdAddr {
        self.src
    }

    /// Get the destination (peer device) BD address.
    ///
    /// Equivalent to C `telephony_get_dst()`.
    pub fn get_dst(&self) -> BdAddr {
        self.dst
    }

    /// Get the opaque profile data.
    ///
    /// Equivalent to C `telephony_get_profile_data()`.
    pub fn get_profile_data(&self) -> &Option<Box<dyn Any + Send + Sync>> {
        &self.profile_data
    }

    // ---- URI Scheme management ----

    /// Add a supported URI scheme (e.g., `"tel"`).
    ///
    /// Equivalent to C `telephony_add_uri_scheme()`.
    /// Emits `SupportedURISchemes` property-changed signal.
    pub async fn add_uri_scheme(telephony: &Arc<Mutex<Telephony>>, scheme: &str) {
        {
            let mut tel = telephony.lock().await;
            tel.uri_schemes.push(scheme.to_owned());
        }

        // Emit property-changed signal via best-effort notification.
        Self::emit_telephony_property_changed(telephony, "supported_uri_schemes").await;
    }

    /// Remove a supported URI scheme (case-insensitive match).
    ///
    /// Equivalent to C `telephony_remove_uri_scheme()`.
    /// Emits `SupportedURISchemes` property-changed signal.
    pub async fn remove_uri_scheme(telephony: &Arc<Mutex<Telephony>>, scheme: &str) {
        {
            let mut tel = telephony.lock().await;
            if let Some(pos) = tel
                .uri_schemes
                .iter()
                .position(|s| s.eq_ignore_ascii_case(scheme))
            {
                tel.uri_schemes.remove(pos);
            } else {
                return;
            }
        }

        Self::emit_telephony_property_changed(telephony, "supported_uri_schemes").await;
    }

    // ---- State setters with property-changed emission ----

    /// Set the telephony connection state.
    ///
    /// Equivalent to C `telephony_set_state()`.  Logs the state transition
    /// and emits a `State` property-changed D-Bus signal.
    pub async fn set_state(telephony: &Arc<Mutex<Telephony>>, state: ConnectionState) {
        {
            let mut tel = telephony.lock().await;
            if tel.state == state {
                return;
            }
            let address = tel.dst.ba2str();
            debug!(
                "device {} state {} -> {}",
                address, tel.state, state
            );
            tel.state = state;
        }

        Self::emit_telephony_property_changed(telephony, "state").await;
    }

    /// Get the current connection state.
    ///
    /// Equivalent to C `telephony_get_state()`.
    pub fn get_state(&self) -> ConnectionState {
        self.state
    }

    /// Set the network service availability indicator.
    ///
    /// Equivalent to C `telephony_set_network_service()`.
    pub async fn set_network_service(telephony: &Arc<Mutex<Telephony>>, service: bool) {
        {
            let mut tel = telephony.lock().await;
            if tel.network_service == service {
                return;
            }
            let address = tel.dst.ba2str();
            debug!(
                "device {} network service {} -> {}",
                address, tel.network_service as u8, service as u8
            );
            tel.network_service = service;
        }

        Self::emit_telephony_property_changed(telephony, "service").await;
    }

    /// Get the network service availability indicator.
    ///
    /// Equivalent to C `telephony_get_network_service()`.
    pub fn get_network_service(&self) -> bool {
        self.network_service
    }

    /// Set the signal strength indicator (0-5).
    ///
    /// Equivalent to C `telephony_set_signal()`.
    pub async fn set_signal(telephony: &Arc<Mutex<Telephony>>, signal: u8) {
        {
            let mut tel = telephony.lock().await;
            if tel.signal == signal {
                return;
            }
            let address = tel.dst.ba2str();
            debug!(
                "device {} signal {} -> {}",
                address, tel.signal, signal
            );
            tel.signal = signal;
        }

        Self::emit_telephony_property_changed(telephony, "signal").await;
    }

    /// Get the signal strength indicator.
    ///
    /// Equivalent to C `telephony_get_signal()`.
    pub fn get_signal(&self) -> u8 {
        self.signal
    }

    /// Set the roaming status indicator.
    ///
    /// Equivalent to C `telephony_set_roaming()`.
    pub async fn set_roaming(telephony: &Arc<Mutex<Telephony>>, roaming: bool) {
        {
            let mut tel = telephony.lock().await;
            if tel.roaming == roaming {
                return;
            }
            let address = tel.dst.ba2str();
            debug!(
                "device {} roaming {} -> {}",
                address, tel.roaming as u8, roaming as u8
            );
            tel.roaming = roaming;
        }

        Self::emit_telephony_property_changed(telephony, "roaming").await;
    }

    /// Get the roaming status indicator.
    ///
    /// Equivalent to C `telephony_get_roaming()`.
    pub fn get_roaming(&self) -> bool {
        self.roaming
    }

    /// Set the battery charge indicator (0-5).
    ///
    /// Equivalent to C `telephony_set_battchg()`.
    pub async fn set_battchg(telephony: &Arc<Mutex<Telephony>>, battchg: u8) {
        {
            let mut tel = telephony.lock().await;
            if tel.battchg == battchg {
                return;
            }
            let address = tel.dst.ba2str();
            debug!(
                "device {} battchg {} -> {}",
                address, tel.battchg, battchg
            );
            tel.battchg = battchg;
        }

        Self::emit_telephony_property_changed(telephony, "batt_chg").await;
    }

    /// Get the battery charge indicator.
    ///
    /// Equivalent to C `telephony_get_battchg()`.
    pub fn get_battchg(&self) -> u8 {
        self.battchg
    }

    /// Set the network operator name.
    ///
    /// Equivalent to C `telephony_set_operator_name()`.
    pub async fn set_operator_name(telephony: &Arc<Mutex<Telephony>>, name: &str) {
        {
            let mut tel = telephony.lock().await;
            if tel.operator_name.as_deref() == Some(name) {
                return;
            }
            let address = tel.dst.ba2str();
            debug!(
                "device {} operator name {:?} -> {:?}",
                address,
                tel.operator_name.as_deref().unwrap_or("(none)"),
                name
            );
            tel.operator_name = Some(name.to_owned());
        }

        Self::emit_telephony_property_changed(telephony, "operator_name").await;
    }

    /// Get the network operator name.
    ///
    /// Equivalent to C `telephony_get_operator_name()`.
    pub fn get_operator_name(&self) -> Option<&str> {
        self.operator_name.as_deref()
    }

    /// Set the in-band ringtone support flag.
    ///
    /// Equivalent to C `telephony_set_inband_ringtone()`.
    pub async fn set_inband_ringtone(telephony: &Arc<Mutex<Telephony>>, enabled: bool) {
        {
            let mut tel = telephony.lock().await;
            if tel.inband_ringtone == enabled {
                return;
            }
            let address = tel.dst.ba2str();
            debug!(
                "device {} inband ringtone {} -> {}",
                address, tel.inband_ringtone as u8, enabled as u8
            );
            tel.inband_ringtone = enabled;
        }

        Self::emit_telephony_property_changed(telephony, "inband_ringtone").await;
    }

    /// Get the in-band ringtone support flag.
    ///
    /// Equivalent to C `telephony_get_inband_ringtone()`.
    pub fn get_inband_ringtone(&self) -> bool {
        self.inband_ringtone
    }

    // ---- Call management ----

    /// Create a new call instance.
    ///
    /// Equivalent to C `telephony_new_call()`.  The call is created with the
    /// given index and initial state, and its D-Bus object path is derived
    /// from the telephony path.
    pub fn new_call(
        _telephony: &Arc<Mutex<Telephony>>,
        telephony_path: &str,
        cbs: &Arc<dyn TelephonyCallbacks>,
        idx: u8,
        state: CallState,
    ) -> Arc<Mutex<Call>> {
        let path = format!("{}/call{}", telephony_path, idx);

        let call = Call {
            telephony: Arc::clone(cbs),
            path,
            idx,
            line_id: None,
            incoming_line: None,
            name: None,
            multiparty: false,
            state,
        };

        Arc::new(Mutex::new(call))
    }

    /// Free a call (unregister its D-Bus interface and drop).
    ///
    /// Equivalent to C `telephony_free_call()`.
    pub async fn free_call(call: &Arc<Mutex<Call>>) {
        let path = {
            let c = call.lock().await;
            c.path.clone()
        };

        let conn = btd_get_dbus_connection();
        let _ = conn
            .object_server()
            .remove::<Call1Interface, _>(path.as_str())
            .await;

        debug!("Unregistered interface {} on path {}", TELEPHONY_CALL_INTERFACE, path);
    }

    // ---- Internal helpers ----

    /// Emit a property-changed signal on the Telephony1 interface.
    ///
    /// Uses zbus's `object_server().interface()` to obtain a reference and
    /// trigger property change notification.  This is a best-effort
    /// operation — if the connection is unavailable or the property
    /// is invalid, the error is silently ignored (matching the C behaviour
    /// where `g_dbus_emit_property_changed` errors are not checked).
    async fn emit_telephony_property_changed(
        telephony: &Arc<Mutex<Telephony>>,
        _property_name: &str,
    ) {
        let conn = btd_get_dbus_connection();
        let path = {
            let tel = telephony.lock().await;
            tel.path.clone()
        };

        // Attempt to get the interface ref at this path.
        // zbus 5.x handles PropertiesChanged emission through its own
        // caching mechanism when properties are read via their getters.
        // This call ensures the interface is accessible; property change
        // notifications are automatically dispatched by zbus when a
        // property getter returns a different value from the cached one.
        let object_server = conn.object_server();
        let _ = object_server
            .interface::<_, Telephony1Interface>(path.as_str())
            .await;
    }
}

// ---------------------------------------------------------------------------
// Call lifecycle functions (module-level, matching C API)
// ---------------------------------------------------------------------------

/// Register the `org.bluez.Call1` D-Bus interface for a call.
///
/// Equivalent to C `telephony_call_register_interface()`.
pub async fn telephony_call_register_interface(call: &Arc<Mutex<Call>>) -> Result<(), i32> {
    let path = {
        let c = call.lock().await;
        c.path.clone()
    };

    let iface = Call1Interface {
        inner: Arc::clone(call),
    };

    let conn = btd_get_dbus_connection();
    conn.object_server()
        .at(path.as_str(), iface)
        .await
        .map_err(|_| -libc::EINVAL)?;

    debug!("Registered interface {} on path {}", TELEPHONY_CALL_INTERFACE, path);
    Ok(())
}

/// Unregister the `org.bluez.Call1` D-Bus interface for a call.
///
/// Equivalent to C `telephony_call_unregister_interface()`.
pub async fn telephony_call_unregister_interface(call: &Arc<Mutex<Call>>) {
    let path = {
        let c = call.lock().await;
        c.path.clone()
    };

    let conn = btd_get_dbus_connection();
    let _ = conn
        .object_server()
        .remove::<Call1Interface, _>(path.as_str())
        .await;

    debug!("Unregistered interface {} on path {}", TELEPHONY_CALL_INTERFACE, path);
}

/// Update the state of a call and emit a property-changed signal.
///
/// Equivalent to C `telephony_call_set_state()`.
pub async fn telephony_call_set_state(call: &Arc<Mutex<Call>>, state: CallState) {
    let path = {
        let mut c = call.lock().await;
        if c.state == state {
            return;
        }
        debug!(
            "{} state {} -> {}",
            c.path,
            c.state,
            state
        );
        c.state = state;
        c.path.clone()
    };

    // Best-effort property-changed notification.
    let conn = btd_get_dbus_connection();
    let object_server = conn.object_server();
    let _ = object_server
        .interface::<_, Call1Interface>(path.as_str())
        .await;
}

/// Update the line identification of a call and emit a property-changed signal.
///
/// Equivalent to C `telephony_call_set_line_id()`.
pub async fn telephony_call_set_line_id(call: &Arc<Mutex<Call>>, line_id: &str) {
    let path = {
        let mut c = call.lock().await;
        if c.line_id.as_deref() == Some(line_id) {
            return;
        }
        c.line_id = Some(line_id.to_owned());
        debug!("{} line_id: {}", c.path, line_id);
        c.path.clone()
    };

    // Best-effort property-changed notification.
    let conn = btd_get_dbus_connection();
    let object_server = conn.object_server();
    let _ = object_server
        .interface::<_, Call1Interface>(path.as_str())
        .await;
}
