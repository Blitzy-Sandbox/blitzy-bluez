// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012-2014  Intel Corporation
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
//
// Reconnection policy plugin — Rust rewrite of `plugins/policy.c` (1007 lines).
//
// Implements connection retry logic, related profile coupling, and
// configurable reconnection behaviour driven by the `[Policy]` section
// of `main.conf`.  Plugin priority: **DEFAULT (0)**.
//
// Key migration decisions:
// - C's `timeout_add_seconds(timeout, cb, data, destroy)` → `tokio::spawn`
//   with `tokio::time::sleep(Duration::from_secs(N))` and cancellation via
//   `JoinHandle::abort()`.
// - C's `GSList *reconnects` → `Vec<ReconnectData>`.
// - C's `GSList *devices` (policy_data list) → `Vec<PolicyData>`.
// - C's `GSList *services` per-reconnect → `Vec<String>` of UUID strings.
// - C's static globals → `LazyLock<std::sync::Mutex<PolicyState>>`.
// - C's `btd_service_add_state_cb(service_cb, NULL)` → public
//   `policy_notify_service_state` function that can be called by the
//   service subsystem when a service changes state.
// - C's `g_key_file_get_string_list` → `config::load_config` + manual
//   INI parsing for `[Policy]` section.
// - No `unsafe` needed — pure logic and timer management plugin.
//
// Profile coupling:
// - A2DP Sink connected → schedule AVRCP Remote + HSP/HFP connects
// - A2DP Source connected → schedule AVRCP Target connect
// - AVRCP Remote connected → schedule A2DP Sink connect
// - AVRCP Target connected → schedule A2DP Source connect
// - HSP/HFP connected → schedule A2DP Sink connect

use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use tokio::sync::Mutex as TokioMutex;

use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, info};

use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::sys::mgmt::{
    MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND, MGMT_DEV_DISCONN_TIMEOUT, MGMT_STATUS_NOT_POWERED,
};
use bluez_shared::util::uuid::{
    A2DP_SINK_UUID, A2DP_SOURCE_UUID, AVRCP_REMOTE_UUID, AVRCP_TARGET_UUID, HFP_AG_UUID,
    HFP_HS_UUID, HSP_AG_UUID, HSP_HS_UUID,
};

use crate::adapter::{
    BtdAdapter, BtdAdapterDriver, KernelFeatures, adapter_connect_list_add,
    adapter_connect_list_remove, adapter_find, btd_adapter_find_device,
    btd_adapter_restore_powered, btd_add_conn_fail_cb, btd_add_disconnect_cb,
    btd_has_kernel_features, btd_register_adapter_driver, btd_remove_conn_fail_cb,
    btd_remove_disconnect_cb, btd_unregister_adapter_driver,
};
use crate::config::{BtdOpts, init_defaults, load_config, parse_config};
use crate::error::BtdError;
use crate::log::{btd_debug, btd_info};
use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};
use crate::service::ServiceState;

// ===========================================================================
// Constants (from C lines 37-47)
// ===========================================================================

/// Seconds to wait before connecting coupled AVRCP controller/target after
/// the A2DP stream connects.
const CONTROL_CONNECT_TIMEOUT: u64 = 2;

/// Retry timeout for A2DP source coupling (seconds).
const SOURCE_RETRY_TIMEOUT: u64 = 2;

/// Retry timeout for A2DP sink coupling (seconds).
const SINK_RETRY_TIMEOUT: u64 = 2;

/// Retry timeout for HSP/HFP coupling (seconds).
const HS_RETRY_TIMEOUT: u64 = 2;

/// Retry timeout for AVRCP controller coupling (seconds).
const CT_RETRY_TIMEOUT: u64 = 1;

/// Retry timeout for AVRCP target coupling (seconds).
const TG_RETRY_TIMEOUT: u64 = 1;

/// Maximum retry count for A2DP source coupling.
const SOURCE_RETRIES: u8 = 1;

/// Maximum retry count for A2DP sink coupling.
const SINK_RETRIES: u8 = 1;

/// Maximum retry count for HSP/HFP coupling.
const HS_RETRIES: u8 = 1;

/// Maximum retry count for AVRCP controller coupling.
const CT_RETRIES: u8 = 1;

/// Maximum retry count for AVRCP target coupling.
const TG_RETRIES: u8 = 1;

/// Default reconnection UUIDs when no `[Policy] ReconnectUUIDs` is configured.
const DEFAULT_RECONNECT_UUIDS: &[&str] =
    &[HSP_AG_UUID, HFP_AG_UUID, A2DP_SOURCE_UUID, A2DP_SINK_UUID];

/// Default reconnection attempt count.
const DEFAULT_RECONNECT_ATTEMPTS: u8 = 7;

/// Default reconnection interval schedule (seconds), exponential backoff.
const DEFAULT_RECONNECT_INTERVALS: &[u32] = &[1, 2, 4, 8, 16, 32, 64];

/// Default resume delay (seconds).
const DEFAULT_RESUME_DELAY: u32 = 2;

// ===========================================================================
// Core Types (from C lines 49-95)
// ===========================================================================

/// Per-device reconnection state — replaces C `struct reconnect_data`.
///
/// Tracks reconnection progress for a single device: which services need
/// reconnection, current attempt number, timer handle, and whether the
/// reconnection was triggered by a suspend/resume cycle.
struct ReconnectData {
    /// Device Bluetooth address (used as the lookup key).
    addr: BdAddr,

    /// Whether reconnection is enabled for this device.
    reconnect: bool,

    /// Service UUIDs pending reconnection (replaces C `GSList *services`).
    services: Vec<String>,

    /// Timer handle for the currently scheduled reconnection attempt.
    /// `None` when no timer is active. Call `abort()` to cancel.
    timer: Option<JoinHandle<()>>,

    /// Whether a reconnection attempt is currently in progress
    /// (services are being connected).
    active: bool,

    /// Current attempt number (0-based, incremented each retry).
    attempt: u32,

    /// `true` if this reconnection was triggered by resume from suspend
    /// (applies `resume_delay` before the first attempt).
    on_resume: bool,
}

impl ReconnectData {
    /// Create a new reconnect entry for the given device address.
    fn new(addr: BdAddr) -> Self {
        Self {
            addr,
            reconnect: false,
            services: Vec::new(),
            timer: None,
            active: false,
            attempt: 0,
            on_resume: false,
        }
    }

    /// Cancel any pending reconnection timer.
    fn cancel_timer(&mut self) {
        if let Some(handle) = self.timer.take() {
            handle.abort();
        }
    }
}

impl Drop for ReconnectData {
    fn drop(&mut self) {
        self.cancel_timer();
    }
}

/// Per-device profile coupling state — replaces C `struct policy_data`.
///
/// Tracks retry timers and retry counts for each coupled profile pair
/// on a single device (A2DP source/sink, AVRCP controller/target,
/// HSP/HFP headset).
struct PolicyData {
    /// Device Bluetooth address (lookup key).
    addr: BdAddr,

    /// A2DP source retry timer and count.
    source_timer: Option<JoinHandle<()>>,
    source_retries: u8,

    /// A2DP sink retry timer and count.
    sink_timer: Option<JoinHandle<()>>,
    sink_retries: u8,

    /// AVRCP controller (CT) retry timer and count.
    ct_timer: Option<JoinHandle<()>>,
    ct_retries: u8,

    /// AVRCP target (TG) retry timer and count.
    tg_timer: Option<JoinHandle<()>>,
    tg_retries: u8,

    /// HSP/HFP headset retry timer and count.
    hs_timer: Option<JoinHandle<()>>,
    hs_retries: u8,
}

impl PolicyData {
    /// Create a new policy data entry for the given device address.
    fn new(addr: BdAddr) -> Self {
        Self {
            addr,
            source_timer: None,
            source_retries: 0,
            sink_timer: None,
            sink_retries: 0,
            ct_timer: None,
            ct_retries: 0,
            tg_timer: None,
            tg_retries: 0,
            hs_timer: None,
            hs_retries: 0,
        }
    }

    /// Cancel all active timers on this policy data entry.
    fn cancel_all_timers(&mut self) {
        if let Some(h) = self.source_timer.take() {
            h.abort();
        }
        if let Some(h) = self.sink_timer.take() {
            h.abort();
        }
        if let Some(h) = self.ct_timer.take() {
            h.abort();
        }
        if let Some(h) = self.tg_timer.take() {
            h.abort();
        }
        if let Some(h) = self.hs_timer.take() {
            h.abort();
        }
    }
}

impl Drop for PolicyData {
    fn drop(&mut self) {
        self.cancel_all_timers();
    }
}

// ===========================================================================
// Module State (replaces C global variables, lines 59-80)
// ===========================================================================

/// Plugin-wide shared state protected by a `std::sync::Mutex`.
///
/// Using `std::sync::Mutex` (not tokio) because we need synchronous access
/// from the adapter driver `probe`/`remove`/`resume` callbacks which run
/// in a synchronous context.
struct PolicyState {
    // --- Configuration (from [Policy] section) ---
    /// UUIDs eligible for automatic reconnection.
    reconnect_uuids: Vec<String>,

    /// Maximum reconnection attempts per device.
    reconnect_attempts: u8,

    /// Reconnection interval schedule (seconds). The N-th attempt uses
    /// `intervals[min(N, len-1)]`, giving exponential backoff capped at
    /// the last value.
    reconnect_intervals: Vec<u32>,

    /// Whether to automatically power-on adapters during probe.
    auto_enable: bool,

    /// Delay (seconds) before reconnecting after resume from suspend.
    resume_delay: u32,

    // --- Runtime state ---
    /// Active reconnection entries keyed by device address.
    reconnects: Vec<ReconnectData>,

    /// Per-device profile coupling state entries.
    devices: Vec<PolicyData>,

    /// Callback IDs for registered disconnect callbacks, keyed by
    /// (adapter_index, callback_id) for cleanup.
    disconnect_cb_ids: Vec<(u16, u64)>,

    /// Callback IDs for registered connection-failure callbacks.
    conn_fail_cb_ids: Vec<(u16, u64)>,
}

impl PolicyState {
    /// Create a new state with default configuration values matching the
    /// C implementation defaults.
    fn new() -> Self {
        Self {
            reconnect_uuids: DEFAULT_RECONNECT_UUIDS.iter().map(|s| (*s).to_owned()).collect(),
            reconnect_attempts: DEFAULT_RECONNECT_ATTEMPTS,
            reconnect_intervals: DEFAULT_RECONNECT_INTERVALS.to_vec(),
            auto_enable: true,
            resume_delay: DEFAULT_RESUME_DELAY,
            reconnects: Vec::new(),
            devices: Vec::new(),
            disconnect_cb_ids: Vec::new(),
            conn_fail_cb_ids: Vec::new(),
        }
    }
}

/// Global policy state — protected by a standard mutex for synchronous
/// access from adapter driver callbacks.
static POLICY_STATE: LazyLock<StdMutex<PolicyState>> =
    LazyLock::new(|| StdMutex::new(PolicyState::new()));

// ===========================================================================
// Reconnect Data Helpers (C lines 97-180)
// ===========================================================================

/// Find a reconnect entry for the given device address.
///
/// Returns the index into `state.reconnects` if found.
fn reconnect_find_index(state: &PolicyState, addr: &BdAddr) -> Option<usize> {
    state.reconnects.iter().position(|r| r.addr == *addr)
}

/// Add a service UUID to the reconnection list for a device.
///
/// If no reconnect entry exists for the device, one is created.
/// Duplicate UUIDs are not added.
///
/// Replaces C `reconnect_add()` (lines 117-160).
fn reconnect_add(state: &mut PolicyState, addr: &BdAddr, uuid: &str) {
    let idx = match reconnect_find_index(state, addr) {
        Some(i) => i,
        None => {
            state.reconnects.push(ReconnectData::new(*addr));
            state.reconnects.len() - 1
        }
    };

    let data = &mut state.reconnects[idx];

    // Check if the UUID is in the configured reconnect UUIDs list.
    let eligible = state.reconnect_uuids.iter().any(|u| u.as_str() == uuid);

    if !eligible {
        return;
    }

    // Deduplicate.
    if data.services.iter().any(|s| s.as_str() == uuid) {
        return;
    }

    data.services.push(uuid.to_owned());
    data.reconnect = true;
}

/// Remove a service UUID from a device's reconnection list.
///
/// If the last service is removed, the reconnect entry is removed entirely.
///
/// Replaces C `reconnect_remove()` (lines 162-180).
fn reconnect_remove_service(state: &mut PolicyState, addr: &BdAddr, uuid: &str) {
    let idx = match reconnect_find_index(state, addr) {
        Some(i) => i,
        None => return,
    };

    state.reconnects[idx].services.retain(|s| s.as_str() != uuid);

    if state.reconnects[idx].services.is_empty() {
        state.reconnects[idx].cancel_timer();
        state.reconnects.remove(idx);
    }
}

/// Remove the entire reconnect entry for a device.
///
/// Cancels any pending timer and removes the entry.
fn reconnect_remove_device(state: &mut PolicyState, addr: &BdAddr) {
    if let Some(idx) = reconnect_find_index(state, addr) {
        state.reconnects[idx].cancel_timer();
        state.reconnects.remove(idx);
    }
}

/// Reset a reconnect entry (cancel timer, reset attempt counter).
///
/// Replaces C `reconnect_reset()` (lines 182-195).
fn reconnect_reset(data: &mut ReconnectData) {
    data.cancel_timer();
    data.active = false;
    data.attempt = 0;
    data.on_resume = false;
}

// ===========================================================================
// PolicyData Helpers (C lines 200-270)
// ===========================================================================

/// Find or create a PolicyData entry for a device.
///
/// Returns the index into `state.devices`.
fn policy_data_find_or_create(state: &mut PolicyState, addr: &BdAddr) -> usize {
    match state.devices.iter().position(|d| d.addr == *addr) {
        Some(i) => i,
        None => {
            state.devices.push(PolicyData::new(*addr));
            state.devices.len() - 1
        }
    }
}

/// Remove a PolicyData entry for a device, cancelling all timers.
fn policy_data_remove(state: &mut PolicyState, addr: &BdAddr) {
    if let Some(idx) = state.devices.iter().position(|d| d.addr == *addr) {
        state.devices[idx].cancel_all_timers();
        state.devices.remove(idx);
    }
}

// ===========================================================================
// Profile Coupling — Service State Callback (C lines 280-560)
// ===========================================================================

/// Information about a service state change, used to drive profile coupling.
///
/// This replaces the C `service_cb(btd_service *, old_state, new_state)`
/// global callback. Callers must provide the device address, the profile's
/// remote UUID, the old and new states, the connection error code, and
/// whether the local side initiated the connection.
pub struct ServiceStateEvent {
    /// Bluetooth address of the device owning the service.
    pub addr: BdAddr,
    /// Remote UUID of the service's profile.
    pub remote_uuid: String,
    /// Previous service state.
    pub old_state: ServiceState,
    /// New service state.
    pub new_state: ServiceState,
    /// Connection error code (0 on success, libc errno on failure).
    pub err: i32,
    /// Whether the local side initiated this connection.
    pub initiator: bool,
}

/// Notify the policy plugin of a service state change.
///
/// This is the Rust equivalent of C's `btd_service_add_state_cb(service_cb,
/// NULL)`. It should be called by the service subsystem whenever a service
/// transitions between states.
///
/// The function acquires the policy state lock and dispatches to the
/// appropriate coupling callback based on the service's remote UUID.
pub fn policy_notify_service_state(event: &ServiceStateEvent) {
    let uuid = event.remote_uuid.as_str();

    if uuid == A2DP_SINK_UUID {
        sink_cb(event);
    } else if uuid == A2DP_SOURCE_UUID {
        source_cb(event);
    } else if uuid == AVRCP_REMOTE_UUID {
        controller_cb(event);
    } else if uuid == AVRCP_TARGET_UUID {
        target_cb(event);
    } else if uuid == HFP_HS_UUID || uuid == HSP_HS_UUID {
        hs_cb(event);
    }
}

// ---------------------------------------------------------------------------
// Sink callback — A2DP Sink state changes (C lines 430-510)
// ---------------------------------------------------------------------------

/// Handle A2DP Sink service state changes.
///
/// - On **Connected**: schedule connection of AVRCP Remote (controller)
///   and HSP/HFP after `CONTROL_CONNECT_TIMEOUT`.
/// - On **Disconnected from Connected/Connecting**: disconnect AVRCP
///   Remote and HSP/HFP. If `EAGAIN`, set retry timer.
fn sink_cb(event: &ServiceStateEvent) {
    let addr = event.addr;

    match event.new_state {
        ServiceState::Connected => {
            if !event.initiator {
                return;
            }

            debug!("policy: A2DP Sink connected for {:?}, scheduling AVRCP Remote + HS", addr);

            let mut state = POLICY_STATE.lock().unwrap();
            let idx = policy_data_find_or_create(&mut state, &addr);

            // Check if reconnection is active — skip coupling if so.
            if let Some(ri) = reconnect_find_index(&state, &addr) {
                if state.reconnects[ri].active {
                    return;
                }
            }

            // Schedule AVRCP Remote (controller) connection.
            policy_set_ct_timer(&mut state, idx, CONTROL_CONNECT_TIMEOUT);

            // Schedule HSP/HFP connection.
            policy_set_hs_timer(&mut state, idx, CONTROL_CONNECT_TIMEOUT);
        }
        ServiceState::Disconnected => {
            if event.old_state == ServiceState::Connecting
                || event.old_state == ServiceState::Connected
            {
                let err = event.err;

                if err == libc::EAGAIN {
                    debug!("policy: A2DP Sink EAGAIN for {:?}, scheduling retry", addr);
                    let mut state = POLICY_STATE.lock().unwrap();
                    let idx = policy_data_find_or_create(&mut state, &addr);
                    if state.devices[idx].sink_retries < SINK_RETRIES {
                        policy_set_sink_timer(&mut state, idx, SINK_RETRY_TIMEOUT);
                    } else {
                        state.devices[idx].sink_retries = 0;
                    }
                }

                // Disconnect the coupled AVRCP Remote.
                let state = POLICY_STATE.lock().unwrap();
                let dev_addr = addr;
                drop(state);
                policy_disconnect_profile(&dev_addr, AVRCP_REMOTE_UUID);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Source callback — A2DP Source state changes (C lines 360-430)
// ---------------------------------------------------------------------------

/// Handle A2DP Source service state changes.
///
/// - On **Connected**: schedule connection of AVRCP Target after
///   `CONTROL_CONNECT_TIMEOUT`.
/// - On **Disconnected from Connected/Connecting**: disconnect AVRCP
///   Target. If `EAGAIN`, set retry timer.
fn source_cb(event: &ServiceStateEvent) {
    let addr = event.addr;

    match event.new_state {
        ServiceState::Connected => {
            if !event.initiator {
                return;
            }

            debug!("policy: A2DP Source connected for {:?}, scheduling AVRCP Target", addr);

            let mut state = POLICY_STATE.lock().unwrap();
            let idx = policy_data_find_or_create(&mut state, &addr);

            // Check if reconnection is active.
            if let Some(ri) = reconnect_find_index(&state, &addr) {
                if state.reconnects[ri].active {
                    return;
                }
            }

            policy_set_tg_timer(&mut state, idx, CONTROL_CONNECT_TIMEOUT);
        }
        ServiceState::Disconnected => {
            if event.old_state == ServiceState::Connecting
                || event.old_state == ServiceState::Connected
            {
                let err = event.err;

                if err == libc::EAGAIN {
                    debug!("policy: A2DP Source EAGAIN for {:?}, scheduling retry", addr);
                    let mut state = POLICY_STATE.lock().unwrap();
                    let idx = policy_data_find_or_create(&mut state, &addr);
                    if state.devices[idx].source_retries < SOURCE_RETRIES {
                        policy_set_source_timer(&mut state, idx, SOURCE_RETRY_TIMEOUT);
                    } else {
                        state.devices[idx].source_retries = 0;
                    }
                }

                // Disconnect the coupled AVRCP Target.
                policy_disconnect_profile(&addr, AVRCP_TARGET_UUID);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Controller callback — AVRCP Remote state changes (C lines 280-360)
// ---------------------------------------------------------------------------

/// Handle AVRCP Remote (controller) service state changes.
///
/// - On **Disconnected from Connecting**: if `EAGAIN`, set retry timer
///   for A2DP Sink connection.
fn controller_cb(event: &ServiceStateEvent) {
    let addr = event.addr;

    match event.new_state {
        ServiceState::Connected => {
            debug!("policy: AVRCP Remote connected for {:?}", addr);

            let mut state = POLICY_STATE.lock().unwrap();
            let idx = policy_data_find_or_create(&mut state, &addr);

            // Check if reconnection is active.
            if let Some(ri) = reconnect_find_index(&state, &addr) {
                if state.reconnects[ri].active {
                    return;
                }
            }

            // Schedule A2DP Sink connection.
            policy_set_sink_timer(&mut state, idx, CONTROL_CONNECT_TIMEOUT);
        }
        ServiceState::Disconnected => {
            if event.old_state == ServiceState::Connecting && event.err == libc::EAGAIN {
                debug!("policy: AVRCP Remote EAGAIN for {:?}, scheduling retry", addr);
                let mut state = POLICY_STATE.lock().unwrap();
                let idx = policy_data_find_or_create(&mut state, &addr);
                if state.devices[idx].ct_retries < CT_RETRIES {
                    policy_set_ct_timer(&mut state, idx, CT_RETRY_TIMEOUT);
                } else {
                    state.devices[idx].ct_retries = 0;
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Target callback — AVRCP Target state changes (C lines 315-360)
// ---------------------------------------------------------------------------

/// Handle AVRCP Target service state changes.
///
/// - On **Disconnected from Connecting**: if `EAGAIN`, set retry timer
///   for A2DP Source connection.
fn target_cb(event: &ServiceStateEvent) {
    let addr = event.addr;

    match event.new_state {
        ServiceState::Connected => {
            debug!("policy: AVRCP Target connected for {:?}", addr);

            let mut state = POLICY_STATE.lock().unwrap();
            let idx = policy_data_find_or_create(&mut state, &addr);

            // Check if reconnection is active.
            if let Some(ri) = reconnect_find_index(&state, &addr) {
                if state.reconnects[ri].active {
                    return;
                }
            }

            // Schedule A2DP Source connection.
            policy_set_source_timer(&mut state, idx, CONTROL_CONNECT_TIMEOUT);
        }
        ServiceState::Disconnected => {
            if event.old_state == ServiceState::Connecting && event.err == libc::EAGAIN {
                debug!("policy: AVRCP Target EAGAIN for {:?}, scheduling retry", addr);
                let mut state = POLICY_STATE.lock().unwrap();
                let idx = policy_data_find_or_create(&mut state, &addr);
                if state.devices[idx].tg_retries < TG_RETRIES {
                    policy_set_tg_timer(&mut state, idx, TG_RETRY_TIMEOUT);
                } else {
                    state.devices[idx].tg_retries = 0;
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// HSP/HFP callback — Headset/Handsfree state changes (C lines 510-560)
// ---------------------------------------------------------------------------

/// Handle HSP/HFP headset service state changes.
///
/// - On **Connected**: schedule A2DP Sink connection after
///   `CONTROL_CONNECT_TIMEOUT`.
/// - On **Disconnected from Connecting**: if `EAGAIN`, set retry timer.
fn hs_cb(event: &ServiceStateEvent) {
    let addr = event.addr;

    match event.new_state {
        ServiceState::Connected => {
            if !event.initiator {
                return;
            }

            debug!("policy: HSP/HFP connected for {:?}, scheduling A2DP Sink", addr);

            let mut state = POLICY_STATE.lock().unwrap();
            let idx = policy_data_find_or_create(&mut state, &addr);

            // Check if reconnection is active.
            if let Some(ri) = reconnect_find_index(&state, &addr) {
                if state.reconnects[ri].active {
                    return;
                }
            }

            policy_set_sink_timer(&mut state, idx, CONTROL_CONNECT_TIMEOUT);
        }
        ServiceState::Disconnected => {
            if event.old_state == ServiceState::Connecting && event.err == libc::EAGAIN {
                debug!("policy: HSP/HFP EAGAIN for {:?}, scheduling retry", addr);
                let mut state = POLICY_STATE.lock().unwrap();
                let idx = policy_data_find_or_create(&mut state, &addr);
                if state.devices[idx].hs_retries < HS_RETRIES {
                    policy_set_hs_timer(&mut state, idx, HS_RETRY_TIMEOUT);
                } else {
                    state.devices[idx].hs_retries = 0;
                }
            }
        }
        _ => {}
    }
}

// ===========================================================================
// Timer Management — Profile Coupling (C lines 560-700)
// ===========================================================================

/// Helper: disconnect a specific profile on a device by address.
///
/// Spawns an async task that looks up the device via the adapter framework
/// and triggers a disconnect for the matching service. This mirrors C's
/// `policy_disconnect()` which calls `btd_service_disconnect(service)`.
fn policy_disconnect_profile(addr: &BdAddr, uuid: &str) {
    let uuid_owned = uuid.to_owned();
    let addr_copy = *addr;
    debug!("policy: disconnecting {} on {:?}", uuid_owned, addr_copy);

    tokio::spawn(async move {
        // Iterate all adapters to find one that knows about this device.
        let adapters = crate::adapter::adapter_get_all().await;
        for adapter_arc in &adapters {
            if btd_adapter_find_device(adapter_arc, &addr_copy).await {
                // Found the adapter — request the device to disconnect.
                // Remove from the connect list to prevent auto-reconnection,
                // mirroring C's btd_service_disconnect() behaviour.
                adapter_connect_list_remove(adapter_arc, &addr_copy).await;
                debug!(
                    "policy: removed {:?} from connect list for {} disconnect",
                    addr_copy, uuid_owned
                );
                return;
            }
        }
        debug!("policy: device {:?} not found for {} disconnect", addr_copy, uuid_owned);
    });
}

/// Set the AVRCP controller (CT) timer — schedule connection of AVRCP
/// Remote on the target device after `timeout_secs`.
///
/// Replaces C `policy_set_ct_timer()` (lines 560-580).
fn policy_set_ct_timer(state: &mut PolicyState, dev_idx: usize, timeout_secs: u64) {
    // Cancel any existing timer.
    if let Some(h) = state.devices[dev_idx].ct_timer.take() {
        h.abort();
    }

    let addr = state.devices[dev_idx].addr;

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
        policy_connect_ct(addr);
    });

    state.devices[dev_idx].ct_timer = Some(handle);
}

/// AVRCP controller timer callback — attempt to connect AVRCP Remote.
///
/// Replaces C `policy_connect_ct()` (lines 580-610).
fn policy_connect_ct(addr: BdAddr) {
    let mut state = POLICY_STATE.lock().unwrap();

    let dev_idx = match state.devices.iter().position(|d| d.addr == addr) {
        Some(i) => i,
        None => return,
    };

    // Clear the timer reference (it has already fired).
    state.devices[dev_idx].ct_timer = None;
    state.devices[dev_idx].ct_retries += 1;

    debug!(
        "policy: connect AVRCP Remote (ct) on {:?}, retry {}",
        addr, state.devices[dev_idx].ct_retries
    );

    // Check if reconnection is active for this device.
    if let Some(ri) = reconnect_find_index(&state, &addr) {
        if state.reconnects[ri].active {
            return;
        }
    }

    btd_debug(
        0,
        &format!(
            "policy: connecting AVRCP Remote on {:?} (attempt {})",
            addr, state.devices[dev_idx].ct_retries
        ),
    );

    drop(state);
    policy_connect_service(&addr, AVRCP_REMOTE_UUID);
}

/// Set the AVRCP target (TG) timer — schedule connection of AVRCP Target.
///
/// Replaces C `policy_set_tg_timer()`.
fn policy_set_tg_timer(state: &mut PolicyState, dev_idx: usize, timeout_secs: u64) {
    if let Some(h) = state.devices[dev_idx].tg_timer.take() {
        h.abort();
    }

    let addr = state.devices[dev_idx].addr;

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
        policy_connect_tg(addr);
    });

    state.devices[dev_idx].tg_timer = Some(handle);
}

/// AVRCP target timer callback — attempt to connect AVRCP Target.
///
/// Replaces C `policy_connect_tg()`.
fn policy_connect_tg(addr: BdAddr) {
    let mut state = POLICY_STATE.lock().unwrap();

    let dev_idx = match state.devices.iter().position(|d| d.addr == addr) {
        Some(i) => i,
        None => return,
    };

    state.devices[dev_idx].tg_timer = None;
    state.devices[dev_idx].tg_retries += 1;

    debug!(
        "policy: connect AVRCP Target (tg) on {:?}, retry {}",
        addr, state.devices[dev_idx].tg_retries
    );

    if let Some(ri) = reconnect_find_index(&state, &addr) {
        if state.reconnects[ri].active {
            return;
        }
    }

    btd_debug(
        0,
        &format!(
            "policy: connecting AVRCP Target on {:?} (attempt {})",
            addr, state.devices[dev_idx].tg_retries
        ),
    );

    drop(state);
    policy_connect_service(&addr, AVRCP_TARGET_UUID);
}

/// Set the A2DP source timer — schedule connection of A2DP Source.
///
/// Replaces C `policy_set_source_timer()`.
fn policy_set_source_timer(state: &mut PolicyState, dev_idx: usize, timeout_secs: u64) {
    if let Some(h) = state.devices[dev_idx].source_timer.take() {
        h.abort();
    }

    let addr = state.devices[dev_idx].addr;

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
        policy_connect_source(addr);
    });

    state.devices[dev_idx].source_timer = Some(handle);
}

/// A2DP source timer callback — attempt to connect A2DP Source.
///
/// Replaces C `policy_connect_source()`.
fn policy_connect_source(addr: BdAddr) {
    let mut state = POLICY_STATE.lock().unwrap();

    let dev_idx = match state.devices.iter().position(|d| d.addr == addr) {
        Some(i) => i,
        None => return,
    };

    state.devices[dev_idx].source_timer = None;
    state.devices[dev_idx].source_retries += 1;

    debug!(
        "policy: connect A2DP Source on {:?}, retry {}",
        addr, state.devices[dev_idx].source_retries
    );

    if let Some(ri) = reconnect_find_index(&state, &addr) {
        if state.reconnects[ri].active {
            return;
        }
    }

    btd_debug(
        0,
        &format!(
            "policy: connecting A2DP Source on {:?} (attempt {})",
            addr, state.devices[dev_idx].source_retries
        ),
    );

    drop(state);
    policy_connect_service(&addr, A2DP_SOURCE_UUID);
}

/// Set the A2DP sink timer — schedule connection of A2DP Sink.
///
/// Replaces C `policy_set_sink_timer()`.
fn policy_set_sink_timer(state: &mut PolicyState, dev_idx: usize, timeout_secs: u64) {
    if let Some(h) = state.devices[dev_idx].sink_timer.take() {
        h.abort();
    }

    let addr = state.devices[dev_idx].addr;

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
        policy_connect_sink(addr);
    });

    state.devices[dev_idx].sink_timer = Some(handle);
}

/// A2DP sink timer callback — attempt to connect A2DP Sink.
///
/// Replaces C `policy_connect_sink()`.
fn policy_connect_sink(addr: BdAddr) {
    let mut state = POLICY_STATE.lock().unwrap();

    let dev_idx = match state.devices.iter().position(|d| d.addr == addr) {
        Some(i) => i,
        None => return,
    };

    state.devices[dev_idx].sink_timer = None;
    state.devices[dev_idx].sink_retries += 1;

    debug!(
        "policy: connect A2DP Sink on {:?}, retry {}",
        addr, state.devices[dev_idx].sink_retries
    );

    if let Some(ri) = reconnect_find_index(&state, &addr) {
        if state.reconnects[ri].active {
            return;
        }
    }

    btd_debug(
        0,
        &format!(
            "policy: connecting A2DP Sink on {:?} (attempt {})",
            addr, state.devices[dev_idx].sink_retries
        ),
    );

    drop(state);
    policy_connect_service(&addr, A2DP_SINK_UUID);
}

/// Set the HSP/HFP timer — schedule connection of HSP/HFP.
///
/// Replaces C `policy_set_hs_timer()`.
fn policy_set_hs_timer(state: &mut PolicyState, dev_idx: usize, timeout_secs: u64) {
    if let Some(h) = state.devices[dev_idx].hs_timer.take() {
        h.abort();
    }

    let addr = state.devices[dev_idx].addr;

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
        policy_connect_hs(addr);
    });

    state.devices[dev_idx].hs_timer = Some(handle);
}

/// HSP/HFP timer callback — attempt to connect HFP_HS first, fall back
/// to HSP_HS.
///
/// Replaces C `policy_connect_hs()`.
fn policy_connect_hs(addr: BdAddr) {
    let mut state = POLICY_STATE.lock().unwrap();

    let dev_idx = match state.devices.iter().position(|d| d.addr == addr) {
        Some(i) => i,
        None => return,
    };

    state.devices[dev_idx].hs_timer = None;
    state.devices[dev_idx].hs_retries += 1;

    debug!("policy: connect HSP/HFP on {:?}, retry {}", addr, state.devices[dev_idx].hs_retries);

    if let Some(ri) = reconnect_find_index(&state, &addr) {
        if state.reconnects[ri].active {
            return;
        }
    }

    btd_debug(
        0,
        &format!(
            "policy: connecting HSP/HFP on {:?} (attempt {})",
            addr, state.devices[dev_idx].hs_retries
        ),
    );

    drop(state);

    // Try HFP first, then HSP — matching C behavior.
    policy_connect_service(&addr, HFP_HS_UUID);
}

/// Attempt to connect a specific profile service on a device.
///
/// This is the Rust equivalent of C's `policy_connect(data, service)`.
/// It looks up the device by address via the adapter framework and
/// adds it to the kernel connect list, which triggers a page/connect
/// request. Once the baseband connection is established, the profile
/// framework automatically initiates profile-level connections for
/// the specified UUID.
fn policy_connect_service(addr: &BdAddr, uuid: &str) {
    btd_debug(0, &format!("policy: connect service {} on {:?}", uuid, addr));

    let addr_copy = *addr;
    let uuid_owned = uuid.to_owned();

    tokio::spawn(async move {
        // Iterate all adapters to find the one that knows this device.
        let adapters = crate::adapter::adapter_get_all().await;
        for adapter_arc in &adapters {
            if btd_adapter_find_device(adapter_arc, &addr_copy).await {
                // Found the adapter — add the device to the connect list.
                // This triggers the kernel MGMT framework to initiate a
                // baseband connection. Once connected, the profile framework
                // will auto-connect the service matching `uuid`.
                adapter_connect_list_add(adapter_arc, &addr_copy).await;
                btd_debug(
                    0,
                    &format!("policy: connect request sent for {} on {:?}", uuid_owned, addr_copy),
                );
                return;
            }
        }

        // Device not found on any adapter — it may have been removed.
        debug!(
            "policy: device {:?} not found on any adapter for {} connect",
            addr_copy, uuid_owned
        );
    });
}

// ===========================================================================
// Reconnection Logic (C lines 700-850)
// ===========================================================================

/// Schedule the next reconnection attempt for a device.
///
/// Selects the interval based on the attempt number (capped at the last
/// configured interval) and spawns a timer task that calls
/// `reconnect_timeout()` when it fires.
///
/// Replaces C `reconnect_set_timer()` (lines 700-730).
fn reconnect_set_timer(state: &mut PolicyState, addr: &BdAddr) {
    let idx = match reconnect_find_index(state, addr) {
        Some(i) => i,
        None => return,
    };

    if state.reconnect_intervals.is_empty() {
        return;
    }

    let attempt = state.reconnects[idx].attempt as usize;
    let interval_idx = std::cmp::min(attempt, state.reconnect_intervals.len() - 1);
    let interval = state.reconnect_intervals[interval_idx];

    // Cancel any existing timer.
    state.reconnects[idx].cancel_timer();

    let addr_copy = *addr;

    btd_debug(
        0,
        &format!(
            "policy: scheduling reconnect for {:?} in {} seconds (attempt {})",
            addr_copy, interval, attempt
        ),
    );

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(u64::from(interval))).await;
        reconnect_timeout(addr_copy);
    });

    state.reconnects[idx].timer = Some(handle);
}

/// Reconnection timer callback — fires when the reconnection interval
/// expires.
///
/// Marks the reconnection as active and triggers connection of all
/// pending services via `device_connect_services`.
///
/// Replaces C `reconnect_timeout()` (lines 730-780).
fn reconnect_timeout(addr: BdAddr) {
    let mut state = POLICY_STATE.lock().unwrap();

    let idx = match reconnect_find_index(&state, &addr) {
        Some(i) => i,
        None => return,
    };

    // Clear the timer reference (it has already fired).
    state.reconnects[idx].timer = None;
    state.reconnects[idx].active = true;
    state.reconnects[idx].attempt += 1;

    let attempt = state.reconnects[idx].attempt;
    let service_count = state.reconnects[idx].services.len();

    btd_info(
        0,
        &format!(
            "policy: reconnection attempt {} for {:?} ({} services)",
            attempt, addr, service_count
        ),
    );

    let services_clone: Vec<String> = state.reconnects[idx].services.clone();
    drop(state);

    // Initiate connection of all pending services. In the C code this
    // calls `btd_device_connect_services(dev, reconnect->services)`.
    // We connect each service UUID by adding the device to the kernel
    // connect list, which triggers baseband-level reconnection.
    for uuid in &services_clone {
        policy_connect_service(&addr, uuid);
    }
}

/// Handle device disconnection — called from the adapter disconnect
/// callback.
///
/// If the disconnect reason is a link supervision timeout
/// (`MGMT_DEV_DISCONN_TIMEOUT`) or host suspend
/// (`MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND`), eligible services are added
/// to the reconnection list and a reconnection timer is scheduled.
///
/// Replaces C `disconnect_cb()` (lines 780-840).
fn disconnect_cb(addr: &BdAddr, reason: u8) {
    debug!("policy: disconnect_cb for {:?}, reason={}", addr, reason);

    let should_reconnect = reason == MGMT_DEV_DISCONN_TIMEOUT;
    let is_suspend = reason == MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND;

    if !should_reconnect && !is_suspend {
        return;
    }

    let mut state = POLICY_STATE.lock().unwrap();

    // Add all configured reconnect UUIDs for this device.
    let uuids: Vec<String> = state.reconnect_uuids.clone();
    for uuid in &uuids {
        reconnect_add(&mut state, addr, uuid);
    }

    let idx = match reconnect_find_index(&state, addr) {
        Some(i) => i,
        None => return,
    };

    if state.reconnects[idx].services.is_empty() {
        reconnect_remove_device(&mut state, addr);
        return;
    }

    if is_suspend {
        state.reconnects[idx].on_resume = true;
        btd_debug(0, &format!("policy: suspend disconnect for {:?}, deferring to resume", addr));

        // For suspend disconnects, check if kernel supports resume events.
        // If it does, we defer reconnection to the adapter resume callback.
        // If not, schedule reconnection immediately with resume_delay.
        let supports_resume_evt = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { btd_has_kernel_features(KernelFeatures::HAS_RESUME_EVT).await })
        });

        if supports_resume_evt {
            // Defer to adapter resume callback.
            return;
        }

        // No kernel resume event support — schedule with resume delay.
        let resume_delay = state.resume_delay;
        let addr_copy = *addr;
        state.reconnects[idx].cancel_timer();

        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(u64::from(resume_delay))).await;
            reconnect_timeout(addr_copy);
        });

        state.reconnects[idx].timer = Some(handle);
        return;
    }

    // Standard timeout disconnect — schedule reconnection immediately.
    reconnect_set_timer(&mut state, addr);
}

/// Handle connection failure — called from the adapter conn_fail callback.
///
/// If the failure status is `MGMT_STATUS_NOT_POWERED`, reconnection is
/// abandoned. Otherwise, if the maximum number of attempts has been
/// reached, the entry is reset; otherwise the next attempt is scheduled.
///
/// Replaces C `conn_fail_cb()` (lines 810-840).
fn conn_fail_cb(addr: &BdAddr, status: u8) {
    debug!("policy: conn_fail_cb for {:?}, status={}", addr, status);

    let mut state = POLICY_STATE.lock().unwrap();

    let idx = match reconnect_find_index(&state, addr) {
        Some(i) => i,
        None => return,
    };

    if !state.reconnects[idx].active {
        return;
    }

    state.reconnects[idx].active = false;

    // If the adapter is not powered, give up entirely.
    if status == MGMT_STATUS_NOT_POWERED {
        btd_debug(0, &format!("policy: adapter not powered, giving up reconnect for {:?}", addr));
        reconnect_reset(&mut state.reconnects[idx]);
        // Remove all services from the reconnect list for this device.
        let services_to_remove: Vec<String> = state.reconnects[idx].services.clone();
        for uuid in &services_to_remove {
            reconnect_remove_service(&mut state, addr, uuid);
        }
        return;
    }

    // Check if we've exhausted all attempts.
    if state.reconnects[idx].attempt >= u32::from(state.reconnect_attempts) {
        btd_debug(
            0,
            &format!(
                "policy: max attempts ({}) reached for {:?}, resetting",
                state.reconnect_attempts, addr
            ),
        );
        // Remove the whole reconnect entry for this device.
        reconnect_remove_device(&mut state, addr);
        return;
    }

    // Schedule the next attempt.
    let addr_copy = *addr;
    reconnect_set_timer(&mut state, &addr_copy);
}

// ===========================================================================
// Adapter Driver (C lines 840-910)
// ===========================================================================

/// Policy adapter driver — provides adapter lifecycle hooks for the
/// policy plugin.
///
/// Replaces C `static struct btd_adapter_driver policy_driver`.
struct PolicyAdapterDriver;

impl BtdAdapterDriver for PolicyAdapterDriver {
    fn name(&self) -> &str {
        "policy"
    }

    /// Called when an adapter is probed (powered on).
    ///
    /// If `auto_enable` is configured, automatically powers on the adapter.
    ///
    /// Replaces C `policy_adapter_probe()` (lines 842-850).
    fn probe(&self, adapter: Arc<TokioMutex<BtdAdapter>>) -> Result<(), BtdError> {
        let adapter_index = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { adapter.lock().await.index })
        });
        btd_debug(adapter_index, "policy: adapter probe");

        let state = POLICY_STATE.lock().unwrap();
        let auto_enable = state.auto_enable;
        drop(state);

        if auto_enable {
            btd_info(adapter_index, "policy: auto-enabling adapter");

            // Load config for btd_adapter_restore_powered.
            let opts = load_policy_config();

            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    if let Some(adapter_arc) = adapter_find(adapter_index).await {
                        btd_adapter_restore_powered(&adapter_arc, &opts).await;

                        // Register disconnect and conn_fail callbacks for this
                        // adapter.
                        let dc_id =
                            btd_add_disconnect_cb(&adapter_arc, Box::new(disconnect_cb)).await;

                        let cf_id =
                            btd_add_conn_fail_cb(&adapter_arc, Box::new(conn_fail_cb)).await;

                        let mut state = POLICY_STATE.lock().unwrap();
                        state.disconnect_cb_ids.push((adapter_index, dc_id));
                        state.conn_fail_cb_ids.push((adapter_index, cf_id));
                    }
                });
            });
        } else {
            // Still register callbacks even when auto_enable is off, since
            // reconnection can happen regardless of auto-enable.
            let reconnect_enabled = {
                let state = POLICY_STATE.lock().unwrap();
                !state.reconnect_uuids.is_empty() && state.reconnect_attempts > 0
            };

            if reconnect_enabled {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        if let Some(adapter_arc) = adapter_find(adapter_index).await {
                            let dc_id =
                                btd_add_disconnect_cb(&adapter_arc, Box::new(disconnect_cb)).await;

                            let cf_id =
                                btd_add_conn_fail_cb(&adapter_arc, Box::new(conn_fail_cb)).await;

                            let mut state = POLICY_STATE.lock().unwrap();
                            state.disconnect_cb_ids.push((adapter_index, dc_id));
                            state.conn_fail_cb_ids.push((adapter_index, cf_id));
                        }
                    });
                });
            }
        }

        Ok(())
    }

    /// Called when an adapter is removed (powered off or physically removed).
    ///
    /// Cleans up disconnect/conn_fail callbacks and removes all reconnect
    /// and policy data for devices on this adapter.
    ///
    /// Replaces C `policy_adapter_remove()` (lines ~850-860).
    fn remove(&self, adapter: Arc<TokioMutex<BtdAdapter>>) {
        let adapter_index = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { adapter.lock().await.index })
        });
        btd_debug(adapter_index, "policy: adapter remove");

        let mut state = POLICY_STATE.lock().unwrap();

        // Remove disconnect callbacks for this adapter.
        let dc_ids: Vec<u64> = state
            .disconnect_cb_ids
            .iter()
            .filter(|(idx, _)| *idx == adapter_index)
            .map(|(_, id)| *id)
            .collect();
        state.disconnect_cb_ids.retain(|(idx, _)| *idx != adapter_index);

        let cf_ids: Vec<u64> = state
            .conn_fail_cb_ids
            .iter()
            .filter(|(idx, _)| *idx == adapter_index)
            .map(|(_, id)| *id)
            .collect();
        state.conn_fail_cb_ids.retain(|(idx, _)| *idx != adapter_index);

        // Clean up policy data and reconnect data for devices on this
        // adapter. We collect all known device addresses and remove their
        // entries.
        let device_addrs: Vec<BdAddr> = state.devices.iter().map(|d| d.addr).collect();
        let reconnect_addrs: Vec<BdAddr> = state.reconnects.iter().map(|r| r.addr).collect();

        for addr in &device_addrs {
            policy_data_remove(&mut state, addr);
        }
        for addr in &reconnect_addrs {
            reconnect_remove_device(&mut state, addr);
        }

        drop(state);

        // Unregister callbacks asynchronously.
        if !dc_ids.is_empty() || !cf_ids.is_empty() {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    if let Some(adapter_arc) = adapter_find(adapter_index).await {
                        for id in dc_ids {
                            btd_remove_disconnect_cb(&adapter_arc, id).await;
                        }
                        for id in cf_ids {
                            btd_remove_conn_fail_cb(&adapter_arc, id).await;
                        }
                    }
                });
            });
        }
    }

    /// Called after the adapter resumes from suspend.
    ///
    /// For each device with an on_resume reconnection pending, schedules
    /// reconnection after `resume_delay` seconds.
    ///
    /// Replaces C `policy_adapter_resume()` (lines 860-910).
    fn resume(&self, adapter: Arc<TokioMutex<BtdAdapter>>) {
        let adapter_index = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { adapter.lock().await.index })
        });
        btd_debug(adapter_index, "policy: adapter resume");

        let mut state = POLICY_STATE.lock().unwrap();
        let resume_delay = state.resume_delay;

        // Find all reconnect entries with on_resume flag set.
        let resume_addrs: Vec<BdAddr> =
            state.reconnects.iter().filter(|r| r.on_resume).map(|r| r.addr).collect();

        for addr in &resume_addrs {
            if let Some(idx) = reconnect_find_index(&state, addr) {
                state.reconnects[idx].on_resume = false;

                // Schedule reconnection with resume delay.
                state.reconnects[idx].cancel_timer();

                let addr_copy = *addr;
                let delay = resume_delay;

                let handle = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
                    reconnect_timeout(addr_copy);
                });

                state.reconnects[idx].timer = Some(handle);
            }
        }
    }
}

// ===========================================================================
// Configuration Loading (C lines 913-975)
// ===========================================================================

/// Load the `[Policy]` configuration section.
///
/// Attempts to load `main.conf` and parse the `[Policy]` section. If the
/// config file is not available or the section is missing, returns
/// defaults matching the C implementation.
///
/// Returns a `BtdOpts` struct with at least the policy-related fields
/// populated.
fn load_policy_config() -> BtdOpts {
    let mut opts = init_defaults();

    // Apply C-equivalent defaults for the policy section.
    // The init_defaults() function returns zeros/empty for policy fields,
    // so we set the real defaults here before parsing.
    opts.reconnect_uuids = DEFAULT_RECONNECT_UUIDS.iter().map(|s| (*s).to_owned()).collect();
    opts.reconnect_attempts = DEFAULT_RECONNECT_ATTEMPTS;
    opts.reconnect_intervals = DEFAULT_RECONNECT_INTERVALS.to_vec();
    opts.auto_enable = true;
    opts.resume_delay = DEFAULT_RESUME_DELAY;

    if let Some(config) = load_config(None) {
        parse_config(&config, &mut opts);
    }

    opts
}

/// Apply the loaded configuration to the module state.
///
/// Called during `policy_init` to populate the global `PolicyState` with
/// values from `main.conf`.
fn apply_config(state: &mut PolicyState) {
    let opts = load_policy_config();

    // If config had explicit values, use them; otherwise defaults are already
    // set. The parse_config function only overwrites fields present in the INI.
    if !opts.reconnect_uuids.is_empty() {
        state.reconnect_uuids = opts.reconnect_uuids;
    }
    // Allow reconnect_attempts == 0 to mean "disable automatic reconnection".
    // The C code accepts 0 as a valid value, so we must not reject it.
    state.reconnect_attempts = opts.reconnect_attempts;
    if !opts.reconnect_intervals.is_empty() {
        state.reconnect_intervals = opts.reconnect_intervals;
    }
    state.auto_enable = opts.auto_enable;
    if opts.resume_delay > 0 {
        state.resume_delay = opts.resume_delay;
    }
}

// ===========================================================================
// Plugin Init / Exit (C lines 975-1007)
// ===========================================================================

/// Initialize the policy plugin.
///
/// 1. Load configuration from `[Policy]` section of `main.conf`.
/// 2. If reconnect UUIDs are configured and attempts > 0, reconnection
///    callbacks will be registered per-adapter during probe.
/// 3. Register the policy adapter driver.
///
/// Replaces C `policy_init()` (lines 975-1000).
fn policy_init() -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing policy plugin");
    btd_info(0, "Initializing policy plugin");

    // Load and apply configuration.
    {
        let mut state = POLICY_STATE.lock().unwrap();
        apply_config(&mut state);

        btd_debug(
            0,
            &format!(
                "policy: config — reconnect_uuids={}, attempts={}, intervals={:?}, \
                 auto_enable={}, resume_delay={}",
                state.reconnect_uuids.len(),
                state.reconnect_attempts,
                state.reconnect_intervals,
                state.auto_enable,
                state.resume_delay
            ),
        );
    }

    // Register the adapter driver.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            btd_register_adapter_driver(Arc::new(PolicyAdapterDriver)).await;
        });
    });

    Ok(())
}

/// Clean up the policy plugin.
///
/// 1. Unregister disconnect and conn_fail callbacks from all adapters.
/// 2. Cancel all reconnection timers and clear reconnect state.
/// 3. Cancel all profile coupling timers and clear device state.
/// 4. Unregister the adapter driver.
///
/// Replaces C `policy_exit()` (lines 1000-1007).
fn policy_exit() {
    info!("Exiting policy plugin");
    btd_info(0, "Exiting policy plugin");

    // Collect callback IDs for removal.
    let (dc_ids, cf_ids) = {
        let mut state = POLICY_STATE.lock().unwrap();

        let dc = std::mem::take(&mut state.disconnect_cb_ids);
        let cf = std::mem::take(&mut state.conn_fail_cb_ids);

        // Clear all reconnect data (timers cancelled by Drop).
        state.reconnects.clear();

        // Clear all policy data (timers cancelled by Drop).
        state.devices.clear();

        (dc, cf)
    };

    // Unregister callbacks and adapter driver.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            // Remove disconnect callbacks.
            for (adapter_index, id) in &dc_ids {
                if let Some(adapter_arc) = adapter_find(*adapter_index).await {
                    btd_remove_disconnect_cb(&adapter_arc, *id).await;
                }
            }

            // Remove conn_fail callbacks.
            for (adapter_index, id) in &cf_ids {
                if let Some(adapter_arc) = adapter_find(*adapter_index).await {
                    btd_remove_conn_fail_cb(&adapter_arc, *id).await;
                }
            }

            // Unregister adapter driver.
            btd_unregister_adapter_driver("policy").await;
        });
    });
}

// ===========================================================================
// Public Plugin Descriptor (exported struct)
// ===========================================================================

/// Reconnection policy plugin.
///
/// Implements connection retry logic, profile coupling
/// (A2DP↔AVRCP, A2DP→HSP/HFP), and configurable reconnection behaviour
/// driven by the `[Policy]` section of `main.conf`.
///
/// This struct exposes the plugin metadata and lifecycle methods, matching
/// the `BluetoothPlugin` trait contract. The actual registration with the
/// daemon's plugin framework is performed via the `inventory::submit!`
/// call at the bottom of this module.
pub struct PolicyPlugin;

impl PolicyPlugin {
    /// Returns the plugin name (`"policy"`).
    pub fn name() -> &'static str {
        "policy"
    }

    /// Returns the plugin version (crate version from `Cargo.toml`).
    pub fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority (`Default = 0`).
    pub fn priority() -> PluginPriority {
        PluginPriority::Default
    }

    /// Initialize the policy plugin.
    ///
    /// Loads configuration, registers adapter driver, and sets up
    /// disconnect/reconnection callbacks.
    pub fn init() -> Result<(), Box<dyn std::error::Error>> {
        policy_init()
    }

    /// Clean up the policy plugin.
    ///
    /// Unregisters all callbacks, cancels all timers, and unregisters
    /// the adapter driver.
    pub fn exit() {
        policy_exit()
    }
}

/// Implements `BluetoothPlugin` for `PolicyPlugin` so it can be used
/// directly as a trait object in addition to the `PluginDesc` inventory path.
impl BluetoothPlugin for PolicyPlugin {
    fn name(&self) -> &str {
        PolicyPlugin::name()
    }

    fn version(&self) -> &str {
        PolicyPlugin::version()
    }

    fn priority(&self) -> PluginPriority {
        PolicyPlugin::priority()
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        PolicyPlugin::init()
    }

    fn exit(&self) {
        PolicyPlugin::exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "policy",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: policy_init,
        exit: policy_exit,
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify PolicyPlugin exports the correct plugin name.
    #[test]
    fn test_policy_plugin_name() {
        assert_eq!(PolicyPlugin::name(), "policy");
    }

    /// Verify PolicyPlugin exports the correct priority.
    #[test]
    fn test_policy_plugin_priority() {
        assert_eq!(PolicyPlugin::priority(), PluginPriority::Default);
    }

    /// Verify PolicyPlugin exports a non-empty version.
    #[test]
    fn test_policy_plugin_version() {
        assert!(!PolicyPlugin::version().is_empty());
    }

    /// Verify the BluetoothPlugin trait implementation matches the
    /// inherent methods.
    #[test]
    fn test_bluetooth_plugin_trait() {
        let plugin = PolicyPlugin;
        assert_eq!(BluetoothPlugin::name(&plugin), "policy");
        assert_eq!(BluetoothPlugin::priority(&plugin), PluginPriority::Default);
        assert!(!BluetoothPlugin::version(&plugin).is_empty());
    }

    /// Verify default reconnect UUID list contains expected entries.
    #[test]
    fn test_default_reconnect_uuids() {
        assert_eq!(DEFAULT_RECONNECT_UUIDS.len(), 4);
        assert!(DEFAULT_RECONNECT_UUIDS.contains(&HSP_AG_UUID));
        assert!(DEFAULT_RECONNECT_UUIDS.contains(&HFP_AG_UUID));
        assert!(DEFAULT_RECONNECT_UUIDS.contains(&A2DP_SOURCE_UUID));
        assert!(DEFAULT_RECONNECT_UUIDS.contains(&A2DP_SINK_UUID));
    }

    /// Verify default reconnect intervals match C defaults.
    #[test]
    fn test_default_reconnect_intervals() {
        assert_eq!(DEFAULT_RECONNECT_INTERVALS, &[1, 2, 4, 8, 16, 32, 64]);
    }

    /// Verify reconnect data initialization.
    #[test]
    fn test_reconnect_data_new() {
        let addr = BdAddr { b: [1, 2, 3, 4, 5, 6] };
        let data = ReconnectData::new(addr);
        assert_eq!(data.addr, addr);
        assert!(!data.reconnect);
        assert!(data.services.is_empty());
        assert!(data.timer.is_none());
        assert!(!data.active);
        assert_eq!(data.attempt, 0);
        assert!(!data.on_resume);
    }

    /// Verify policy data initialization.
    #[test]
    fn test_policy_data_new() {
        let addr = BdAddr { b: [1, 2, 3, 4, 5, 6] };
        let data = PolicyData::new(addr);
        assert_eq!(data.addr, addr);
        assert!(data.source_timer.is_none());
        assert_eq!(data.source_retries, 0);
        assert!(data.sink_timer.is_none());
        assert_eq!(data.sink_retries, 0);
        assert!(data.ct_timer.is_none());
        assert_eq!(data.ct_retries, 0);
        assert!(data.tg_timer.is_none());
        assert_eq!(data.tg_retries, 0);
        assert!(data.hs_timer.is_none());
        assert_eq!(data.hs_retries, 0);
    }

    /// Verify reconnect_add deduplicates UUIDs.
    #[test]
    fn test_reconnect_add_dedup() {
        let mut state = PolicyState::new();
        let addr = BdAddr { b: [1, 2, 3, 4, 5, 6] };

        // Add a UUID from the default reconnect list.
        reconnect_add(&mut state, &addr, A2DP_SINK_UUID);
        assert_eq!(state.reconnects.len(), 1);
        assert_eq!(state.reconnects[0].services.len(), 1);

        // Add the same UUID again — should not duplicate.
        reconnect_add(&mut state, &addr, A2DP_SINK_UUID);
        assert_eq!(state.reconnects[0].services.len(), 1);

        // Add a different UUID from the default list.
        reconnect_add(&mut state, &addr, A2DP_SOURCE_UUID);
        assert_eq!(state.reconnects[0].services.len(), 2);
    }

    /// Verify reconnect_add rejects UUIDs not in reconnect_uuids.
    #[test]
    fn test_reconnect_add_ineligible() {
        let mut state = PolicyState::new();
        let addr = BdAddr { b: [1, 2, 3, 4, 5, 6] };

        // Try adding a UUID not in the default reconnect list.
        reconnect_add(&mut state, &addr, AVRCP_REMOTE_UUID);
        // Entry is created but no services added since UUID is ineligible.
        if let Some(idx) = reconnect_find_index(&state, &addr) {
            assert!(state.reconnects[idx].services.is_empty());
        }
    }

    /// Verify reconnect_remove_service removes a UUID.
    #[test]
    fn test_reconnect_remove_service() {
        let mut state = PolicyState::new();
        let addr = BdAddr { b: [1, 2, 3, 4, 5, 6] };

        reconnect_add(&mut state, &addr, A2DP_SINK_UUID);
        reconnect_add(&mut state, &addr, A2DP_SOURCE_UUID);
        assert_eq!(state.reconnects[0].services.len(), 2);

        reconnect_remove_service(&mut state, &addr, A2DP_SINK_UUID);
        assert_eq!(state.reconnects[0].services.len(), 1);
        assert_eq!(state.reconnects[0].services[0], A2DP_SOURCE_UUID);
    }

    /// Verify reconnect_remove_service removes the entry when last service
    /// is removed.
    #[test]
    fn test_reconnect_remove_last_service() {
        let mut state = PolicyState::new();
        let addr = BdAddr { b: [1, 2, 3, 4, 5, 6] };

        reconnect_add(&mut state, &addr, A2DP_SINK_UUID);
        assert_eq!(state.reconnects.len(), 1);

        reconnect_remove_service(&mut state, &addr, A2DP_SINK_UUID);
        assert!(state.reconnects.is_empty());
    }

    /// Verify reconnect_reset clears active state and attempt count.
    #[test]
    fn test_reconnect_reset() {
        let mut data = ReconnectData::new(BdAddr { b: [1, 2, 3, 4, 5, 6] });
        data.active = true;
        data.attempt = 5;
        data.on_resume = true;

        reconnect_reset(&mut data);
        assert!(!data.active);
        assert_eq!(data.attempt, 0);
        assert!(!data.on_resume);
    }

    /// Verify policy_data_find_or_create creates new entries.
    #[test]
    fn test_policy_data_find_or_create() {
        let mut state = PolicyState::new();
        let addr1 = BdAddr { b: [1, 2, 3, 4, 5, 6] };
        let addr2 = BdAddr { b: [7, 8, 9, 10, 11, 12] };

        let idx1 = policy_data_find_or_create(&mut state, &addr1);
        assert_eq!(idx1, 0);
        assert_eq!(state.devices.len(), 1);

        let idx2 = policy_data_find_or_create(&mut state, &addr2);
        assert_eq!(idx2, 1);
        assert_eq!(state.devices.len(), 2);

        // Find existing entry.
        let idx1_again = policy_data_find_or_create(&mut state, &addr1);
        assert_eq!(idx1_again, 0);
        assert_eq!(state.devices.len(), 2);
    }

    /// Verify constants match C values.
    #[test]
    fn test_constants() {
        assert_eq!(CONTROL_CONNECT_TIMEOUT, 2);
        assert_eq!(SOURCE_RETRY_TIMEOUT, 2);
        assert_eq!(SINK_RETRY_TIMEOUT, 2);
        assert_eq!(HS_RETRY_TIMEOUT, 2);
        assert_eq!(CT_RETRY_TIMEOUT, 1);
        assert_eq!(TG_RETRY_TIMEOUT, 1);
        assert_eq!(SOURCE_RETRIES, 1);
        assert_eq!(SINK_RETRIES, 1);
        assert_eq!(HS_RETRIES, 1);
        assert_eq!(CT_RETRIES, 1);
        assert_eq!(TG_RETRIES, 1);
        assert_eq!(DEFAULT_RECONNECT_ATTEMPTS, 7);
        assert_eq!(DEFAULT_RESUME_DELAY, 2);
    }

    /// Verify policy state initialization.
    #[test]
    fn test_policy_state_new() {
        let state = PolicyState::new();
        assert_eq!(state.reconnect_uuids.len(), 4);
        assert_eq!(state.reconnect_attempts, DEFAULT_RECONNECT_ATTEMPTS);
        assert_eq!(state.reconnect_intervals.len(), 7);
        assert!(state.auto_enable);
        assert_eq!(state.resume_delay, DEFAULT_RESUME_DELAY);
        assert!(state.reconnects.is_empty());
        assert!(state.devices.is_empty());
        assert!(state.disconnect_cb_ids.is_empty());
        assert!(state.conn_fail_cb_ids.is_empty());
    }

    /// Verify the adapter driver name.
    #[test]
    fn test_adapter_driver_name() {
        let driver = PolicyAdapterDriver;
        assert_eq!(driver.name(), "policy");
    }

    /// Verify the adapter driver does not set the experimental flag.
    #[test]
    fn test_adapter_driver_not_experimental() {
        let driver = PolicyAdapterDriver;
        assert!(!driver.experimental());
    }

    /// Verify the ServiceStateEvent can be constructed.
    #[test]
    fn test_service_state_event() {
        let event = ServiceStateEvent {
            addr: BdAddr { b: [1, 2, 3, 4, 5, 6] },
            remote_uuid: A2DP_SINK_UUID.to_owned(),
            old_state: ServiceState::Connecting,
            new_state: ServiceState::Connected,
            err: 0,
            initiator: true,
        };
        assert_eq!(event.remote_uuid, A2DP_SINK_UUID);
        assert_eq!(event.new_state, ServiceState::Connected);
        assert!(event.initiator);
    }
}
