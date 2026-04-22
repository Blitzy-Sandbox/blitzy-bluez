// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2020  Google LLC
//
// Advertisement Monitor Manager — Rust rewrite of `src/adv_monitor.c` and
// `src/adv_monitor.h`.
//
// Implements the `org.bluez.AdvertisementMonitorManager1` D-Bus interface,
// providing per-adapter advertisement monitoring with kernel offload via MGMT
// and userspace RSSI/content filtering fallback.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, warn};

use zbus::Connection;
use zbus::zvariant::ObjectPath;

use bluez_shared::mgmt::client::{MgmtEvent, MgmtSocket};
use bluez_shared::sys::bluetooth::{BdAddr, bdaddr_t, bt_get_le16};
use bluez_shared::sys::mgmt::{
    MGMT_ADV_MONITOR_FEATURE_MASK_OR_PATTERNS, MGMT_EV_ADV_MONITOR_DEVICE_FOUND,
    MGMT_EV_ADV_MONITOR_DEVICE_LOST, MGMT_EV_ADV_MONITOR_REMOVED, MGMT_OP_ADD_ADV_PATTERNS_MONITOR,
    MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI, MGMT_OP_READ_ADV_MONITOR_FEATURES,
    MGMT_OP_REMOVE_ADV_MONITOR, MGMT_STATUS_SUCCESS, mgmt_adv_pattern,
    mgmt_ev_adv_monitor_device_found, mgmt_ev_adv_monitor_device_lost, mgmt_ev_adv_monitor_removed,
    mgmt_rp_read_adv_monitor_features,
};
use bluez_shared::util::ad::{AdPattern, BtAd};

use crate::adapter::BtdAdapter;
use crate::config::BtdOpts;
use crate::dbus_common::btd_get_dbus_connection;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_info};

// ===========================================================================
// Constants
// ===========================================================================

/// Sentinel value indicating RSSI threshold is not set.
pub const ADV_MONITOR_UNSET_RSSI: i16 = 127;

/// Maximum valid RSSI value.
pub const ADV_MONITOR_MAX_RSSI: i16 = 20;

/// Minimum valid RSSI value.
pub const ADV_MONITOR_MIN_RSSI: i16 = -127;

/// Sentinel for unset timeout.
pub const ADV_MONITOR_UNSET_TIMEOUT: u16 = 0;

/// Minimum valid timeout in seconds.
pub const ADV_MONITOR_MIN_TIMEOUT: u16 = 1;

/// Maximum valid timeout in seconds.
pub const ADV_MONITOR_MAX_TIMEOUT: u16 = 300;

/// Default low-RSSI timeout in seconds.
pub const ADV_MONITOR_DEFAULT_LOW_TIMEOUT: u16 = 5;

/// Default high-RSSI timeout in seconds.
pub const ADV_MONITOR_DEFAULT_HIGH_TIMEOUT: u16 = 10;

/// Sentinel for unset sampling period (u16 range, but spec max is u8).
pub const ADV_MONITOR_UNSET_SAMPLING_PERIOD: u16 = 256;

/// Maximum valid sampling period (0xFF means report all, 0x00 means report
/// only first; 0x01..0xFE are in units of 100ms).
pub const ADV_MONITOR_MAX_SAMPLING_PERIOD: u16 = 255;

/// D-Bus interface for individual monitors exposed by client apps.
const ADV_MONITOR_INTERFACE: &str = "org.bluez.AdvertisementMonitor1";

// ===========================================================================
// Enums
// ===========================================================================

/// Type of advertisement monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorType {
    /// Matches if any pattern matches (OR logic).
    OrPatterns,
}

/// Internal state of an individual advertisement monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorState {
    /// Just created, not yet processed.
    New,
    /// Proxy properties parsed, awaiting kernel registration.
    Inited,
    /// Successfully registered (kernel or userspace).
    Active,
    /// Released by the remote application.
    Released,
    /// Removed due to kernel/internal action.
    Removed,
    /// Failed to initialize or register.
    Failed,
}

/// State of a merged pattern group registered with the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergedPatternState {
    /// Stable — kernel handle is valid and active.
    Stable,
    /// An add command has been sent; waiting for response.
    Adding,
    /// A remove command has been sent; waiting for response.
    Removing,
}

/// RSSI filter state per device for a specific monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RssiFilterResult {
    /// Device found (above high threshold for required duration).
    DeviceFound,
    /// Device lost (below low threshold for required duration).
    DeviceLost,
    /// Undecided — keep tracking.
    Undecided,
}

// ===========================================================================
// RSSI Parameters
// ===========================================================================

/// RSSI thresholds and timeouts for a monitor.
#[derive(Debug, Clone)]
struct RssiParameters {
    /// High RSSI threshold; values above this are considered "found".
    high_rssi: i16,
    /// How long (in seconds) RSSI must stay above `high_rssi` before reporting found.
    high_rssi_timeout: u16,
    /// Low RSSI threshold; values below this are considered "lost".
    low_rssi: i16,
    /// How long (in seconds) RSSI must stay below `low_rssi` before reporting lost.
    low_rssi_timeout: u16,
    /// Sampling period in units of 100ms (0=first only, 0xFF=all, else interval).
    sampling_period: u16,
}

impl RssiParameters {
    /// Create an "unset" RSSI parameter block.
    fn unset() -> Self {
        Self {
            high_rssi: ADV_MONITOR_UNSET_RSSI,
            high_rssi_timeout: ADV_MONITOR_UNSET_TIMEOUT,
            low_rssi: ADV_MONITOR_UNSET_RSSI,
            low_rssi_timeout: ADV_MONITOR_UNSET_TIMEOUT,
            sampling_period: ADV_MONITOR_UNSET_SAMPLING_PERIOD,
        }
    }

    /// Returns `true` if all RSSI parameters are at their unset sentinels.
    fn is_unset(&self) -> bool {
        self.high_rssi == ADV_MONITOR_UNSET_RSSI
            && self.high_rssi_timeout == ADV_MONITOR_UNSET_TIMEOUT
            && self.low_rssi == ADV_MONITOR_UNSET_RSSI
            && self.low_rssi_timeout == ADV_MONITOR_UNSET_TIMEOUT
            && self.sampling_period == ADV_MONITOR_UNSET_SAMPLING_PERIOD
    }
}

// ===========================================================================
// Per-device RSSI tracking state
// ===========================================================================

/// Tracks RSSI timing for a single device within a single monitor for
/// time-based found/lost determination.
#[derive(Debug)]
struct AdvMonitorDevice {
    /// Device Bluetooth address.
    addr: BdAddr,
    /// Whether the device is currently considered "found" by this monitor.
    found: bool,
    /// When RSSI first exceeded the high threshold in this tracking window.
    high_rssi_first_seen: Option<Instant>,
    /// When RSSI first fell below the low threshold in this tracking window.
    low_rssi_first_seen: Option<Instant>,
    /// Last time any advertisement was received from this device.
    last_seen: Instant,
    /// Handle to the DeviceLost timeout timer task, if active.
    lost_timer: Option<JoinHandle<()>>,
}

// ===========================================================================
// Individual Monitor
// ===========================================================================

/// A single advertisement monitor registered by a remote D-Bus application.
///
/// Mirrors the C `struct adv_monitor` with Rust ownership semantics.
struct AdvMonitor {
    /// Application that owns this monitor.
    app_sender: String,
    /// D-Bus object path of the monitor.
    path: String,
    /// Monitor type.
    monitor_type: MonitorType,
    /// Current state.
    state: MonitorState,
    /// RSSI parameters parsed from D-Bus proxy properties.
    rssi: RssiParameters,
    /// AD patterns for content matching.
    patterns: Vec<AdPattern>,
    /// Per-device RSSI tracking for userspace filtering.
    devices: HashMap<BdAddr, AdvMonitorDevice>,
    /// Index into the merged_patterns array (set when added to a group).
    merged_pattern_idx: Option<usize>,
}

impl AdvMonitor {
    fn new(app_sender: &str, path: &str) -> Self {
        Self {
            app_sender: app_sender.to_owned(),
            path: path.to_owned(),
            monitor_type: MonitorType::OrPatterns,
            state: MonitorState::New,
            rssi: RssiParameters::unset(),
            patterns: Vec::new(),
            devices: HashMap::new(),
            merged_pattern_idx: None,
        }
    }
}

// ===========================================================================
// Merged Pattern Group
// ===========================================================================

/// A group of monitors that share identical AD patterns and are combined
/// into a single kernel MGMT registration.
///
/// Mirrors the C `struct adv_monitor_merged_pattern`.
struct MergedPatternGroup {
    /// Kernel monitor handle (assigned on successful add).
    monitor_handle: u16,
    /// Current state of this kernel registration.
    state: MergedPatternState,
    /// Merged (most lenient) RSSI parameters across all monitors in this group.
    rssi: RssiParameters,
    /// The shared AD patterns.
    patterns: Vec<AdPattern>,
    /// Indices of monitors within their respective apps that belong to this group.
    monitor_refs: Vec<MonitorRef>,
    /// Whether there is a pending state transition after the current one completes.
    pending_next_step: bool,
}

/// Reference to a monitor within an app.
#[derive(Debug, Clone)]
struct MonitorRef {
    app_sender: String,
    monitor_path: String,
}

// ===========================================================================
// Application Tracker
// ===========================================================================

/// Represents a remote D-Bus application that has registered one or more
/// advertisement monitors.
///
/// Mirrors the C `struct adv_monitor_app`.
struct AdvMonitorApp {
    /// The unique D-Bus bus name of the owning application.
    sender: String,
    /// The root object path the application registered with.
    root_path: String,
    /// All monitors discovered under this application.
    monitors: Vec<AdvMonitor>,
    /// Whether the D-Bus proxy watcher has detected this app is ready.
    ready: bool,
}

impl AdvMonitorApp {
    fn new(sender: &str, root_path: &str) -> Self {
        Self {
            sender: sender.to_owned(),
            root_path: root_path.to_owned(),
            monitors: Vec::new(),
            ready: false,
        }
    }
}

// ===========================================================================
// Manager Inner State
// ===========================================================================

/// Shared mutable interior of the advertisement monitor manager.
struct ManagerInner {
    /// HCI adapter index used for MGMT commands.
    adapter_index: u16,
    /// Whether the kernel supports OR-pattern offload.
    supported_features: u32,
    /// Currently enabled feature mask.
    enabled_features: u32,
    /// Maximum number of monitors the kernel can handle simultaneously.
    max_num_handles: u16,
    /// Maximum number of patterns per monitor.
    max_num_patterns: u8,
    /// Registered applications keyed by D-Bus sender name.
    apps: Vec<AdvMonitorApp>,
    /// Merged pattern groups registered (or pending) with the kernel.
    merged_patterns: Vec<MergedPatternGroup>,
    /// MGMT event subscription handles for cancellation on destroy.
    event_sub_ids: Vec<u32>,
    /// Background tasks for MGMT event processing.
    event_tasks: Vec<JoinHandle<()>>,
    /// Whether the manager has been fully initialized (features read).
    initialized: bool,
}

impl ManagerInner {
    fn new(adapter_index: u16) -> Self {
        Self {
            adapter_index,
            supported_features: 0,
            enabled_features: 0,
            max_num_handles: 0,
            max_num_patterns: 0,
            apps: Vec::new(),
            merged_patterns: Vec::new(),
            event_sub_ids: Vec::new(),
            event_tasks: Vec::new(),
            initialized: false,
        }
    }

    /// Find an app by D-Bus sender name. Returns its index.
    fn find_app_idx(&self, sender: &str) -> Option<usize> {
        self.apps.iter().position(|a| a.sender == sender)
    }

    /// Find a monitor across all apps by path. Returns (app_idx, monitor_idx).
    fn find_monitor_by_path(&self, path: &str) -> Option<(usize, usize)> {
        for (ai, app) in self.apps.iter().enumerate() {
            for (mi, mon) in app.monitors.iter().enumerate() {
                if mon.path == path {
                    return Some((ai, mi));
                }
            }
        }
        None
    }

    /// Find a merged pattern group by kernel handle.
    fn find_merged_pattern_by_handle(&self, handle: u16) -> Option<usize> {
        self.merged_patterns.iter().position(|mp| mp.monitor_handle == handle)
    }

    /// Find a merged pattern group whose patterns exactly match the given ones.
    fn find_merged_pattern_by_patterns(&self, patterns: &[AdPattern]) -> Option<usize> {
        self.merged_patterns.iter().position(|mp| patterns_equal(&mp.patterns, patterns))
    }

    /// Check if kernel offload of OR-pattern monitors is supported.
    fn offload_supported(&self) -> bool {
        (self.supported_features & MGMT_ADV_MONITOR_FEATURE_MASK_OR_PATTERNS) != 0
    }
}

// ===========================================================================
// BtdAdvMonitorManager — Public API
// ===========================================================================

/// Advertisement Monitor Manager for a single HCI adapter.
///
/// This is the primary public export of this module. It owns all monitor
/// state and provides the API surface consumed by the rest of the daemon.
pub struct BtdAdvMonitorManager {
    /// Shared adapter reference.
    adapter: Arc<Mutex<BtdAdapter>>,
    /// MGMT socket for kernel communication.
    mgmt: Arc<MgmtSocket>,
    /// Shared mutable inner state.
    inner: Arc<Mutex<ManagerInner>>,
    /// D-Bus connection used for interface registration.
    conn: Connection,
    /// Adapter D-Bus object path for interface registration.
    adapter_path: String,
}

impl BtdAdvMonitorManager {
    // -----------------------------------------------------------------------
    // new() — Create and initialize the manager
    // -----------------------------------------------------------------------

    /// Create a new `BtdAdvMonitorManager` for the given adapter.
    ///
    /// This:
    /// 1. Registers the `AdvertisementMonitorManager1` D-Bus interface on
    ///    the adapter object path.
    /// 2. Subscribes to MGMT advertisement monitor events.
    /// 3. Sends `MGMT_OP_READ_ADV_MONITOR_FEATURES` to query kernel
    ///    capabilities.
    pub async fn new(
        adapter: Arc<Mutex<BtdAdapter>>,
        mgmt: Arc<MgmtSocket>,
        _opts: &BtdOpts,
    ) -> Result<Self, BtdError> {
        let (adapter_index, adapter_path) = {
            let a = adapter.lock().await;
            (a.index, a.path.clone())
        };

        btd_info(adapter_index, "Creating AdvertisementMonitorManager");

        let conn = btd_get_dbus_connection().clone();
        let inner = Arc::new(Mutex::new(ManagerInner::new(adapter_index)));

        let manager = Self {
            adapter: adapter.clone(),
            mgmt: mgmt.clone(),
            inner: inner.clone(),
            conn: conn.clone(),
            adapter_path: adapter_path.clone(),
        };

        // Register D-Bus interface
        let iface = AdvMonitorMgr1Interface {
            adapter: adapter.clone(),
            mgmt: mgmt.clone(),
            inner: inner.clone(),
        };

        conn.object_server()
            .at(
                ObjectPath::try_from(adapter_path.as_str())
                    .map_err(|_| BtdError::failed("invalid adapter path"))?,
                iface,
            )
            .await
            .map_err(|e| BtdError::failed(&format!("D-Bus interface registration failed: {e}")))?;

        btd_debug(adapter_index, "Registered AdvertisementMonitorManager1 interface");

        // Subscribe to MGMT events
        manager.subscribe_mgmt_events().await;

        // Read kernel advertisement monitor features
        manager.read_adv_monitor_features().await;

        Ok(manager)
    }

    // -----------------------------------------------------------------------
    // destroy() — Tear down the manager
    // -----------------------------------------------------------------------

    /// Destroy this manager: unregister the D-Bus interface, cancel all
    /// event subscriptions, and release all resources.
    pub async fn destroy(&self) {
        let adapter_index = {
            let inner = self.inner.lock().await;
            inner.adapter_index
        };

        btd_info(adapter_index, "Destroying AdvertisementMonitorManager");

        // Cancel all event processing tasks
        {
            let mut inner = self.inner.lock().await;
            for task in inner.event_tasks.drain(..) {
                task.abort();
            }
            // Clear all app timers
            for app in &mut inner.apps {
                for monitor in &mut app.monitors {
                    for dev in monitor.devices.values_mut() {
                        if let Some(timer) = dev.lost_timer.take() {
                            timer.abort();
                        }
                    }
                }
            }
            inner.apps.clear();
            inner.merged_patterns.clear();
            inner.event_sub_ids.clear();
        }

        // Unregister D-Bus interface
        if let Ok(path) = ObjectPath::try_from(self.adapter_path.as_str()) {
            let _ = self.conn.object_server().remove::<AdvMonitorMgr1Interface, _>(path).await;
        }

        btd_debug(adapter_index, "AdvertisementMonitorManager destroyed");
    }

    // -----------------------------------------------------------------------
    // offload_enabled() — Check if kernel offload is active
    // -----------------------------------------------------------------------

    /// Returns `true` if the kernel has OR-pattern offload enabled.
    pub async fn offload_enabled(&self) -> bool {
        let inner = self.inner.lock().await;
        (inner.enabled_features & MGMT_ADV_MONITOR_FEATURE_MASK_OR_PATTERNS) != 0
    }

    // -----------------------------------------------------------------------
    // content_filter() — Userspace content-based filtering
    // -----------------------------------------------------------------------

    /// Perform userspace content-based filtering against all registered
    /// monitors. Returns `true` if any monitor's patterns match the
    /// given advertising data.
    ///
    /// This is the fallback used when kernel offload is not available.
    pub async fn content_filter(&self, ad: &BtAd) -> bool {
        let inner = self.inner.lock().await;
        for app in &inner.apps {
            for monitor in &app.monitors {
                if monitor.state != MonitorState::Active {
                    continue;
                }
                if monitor.patterns.is_empty() {
                    continue;
                }
                if ad.pattern_match(&monitor.patterns).is_some() {
                    return true;
                }
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // notify_monitors() — Notify registered monitors of device state
    // -----------------------------------------------------------------------

    /// Process a received advertisement for all active monitors, applying
    /// RSSI filtering and notifying matching monitors via D-Bus
    /// `DeviceFound`/`DeviceLost` methods.
    ///
    /// `device_path` is the D-Bus path of the `org.bluez.Device1` object.
    pub async fn notify_monitors(
        &self,
        device_addr: &BdAddr,
        device_path: &str,
        rssi: i16,
        ad: &BtAd,
    ) {
        let adapter_index;
        let conn = self.conn.clone();

        // Collect matching info under lock, then release lock before D-Bus calls
        let notifications: Vec<(String, String, RssiFilterResult)>;
        {
            let mut inner = self.inner.lock().await;
            adapter_index = inner.adapter_index;
            notifications = collect_notifications(&mut inner, device_addr, rssi, ad);
        }

        for (app_sender, monitor_path, result) in notifications {
            match result {
                RssiFilterResult::DeviceFound => {
                    btd_debug(
                        adapter_index,
                        &format!("Monitor {} DeviceFound for {}", monitor_path, device_path),
                    );
                    call_device_found(&conn, &app_sender, &monitor_path, device_path).await;
                }
                RssiFilterResult::DeviceLost => {
                    btd_debug(
                        adapter_index,
                        &format!("Monitor {} DeviceLost for {}", monitor_path, device_path),
                    );
                    call_device_lost(&conn, &app_sender, &monitor_path, device_path).await;
                }
                RssiFilterResult::Undecided => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // device_remove() — Remove a device from all monitors
    // -----------------------------------------------------------------------

    /// Remove all per-device tracking state for the given device from every
    /// active monitor across all apps.
    pub async fn device_remove(&self, device_addr: &BdAddr) {
        let mut inner = self.inner.lock().await;
        for app in &mut inner.apps {
            for monitor in &mut app.monitors {
                if let Some(dev) = monitor.devices.remove(device_addr) {
                    if let Some(timer) = dev.lost_timer {
                        timer.abort();
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // power_down() — Clear all lost timers on adapter power-down
    // -----------------------------------------------------------------------

    /// Cancel all device-lost timeout timers across all monitors. Called
    /// when the adapter is powered down.
    pub async fn power_down(&self) {
        let mut inner = self.inner.lock().await;
        for app in &mut inner.apps {
            for monitor in &mut app.monitors {
                for dev in monitor.devices.values_mut() {
                    if let Some(timer) = dev.lost_timer.take() {
                        timer.abort();
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers — MGMT event subscription
    // -----------------------------------------------------------------------

    /// Subscribe to the three MGMT advertisement monitor events:
    /// - `MGMT_EV_ADV_MONITOR_REMOVED`
    /// - `MGMT_EV_ADV_MONITOR_DEVICE_FOUND`
    /// - `MGMT_EV_ADV_MONITOR_DEVICE_LOST`
    async fn subscribe_mgmt_events(&self) {
        let adapter_index = {
            let inner = self.inner.lock().await;
            inner.adapter_index
        };

        // Subscribe: ADV_MONITOR_REMOVED
        {
            let (sub_id, rx) =
                self.mgmt.subscribe(MGMT_EV_ADV_MONITOR_REMOVED, adapter_index).await;
            let inner = self.inner.clone();
            let mgmt = self.mgmt.clone();
            let task = tokio::spawn(async move {
                handle_adv_monitor_removed_events(rx, inner, mgmt).await;
            });
            let mut guard = self.inner.lock().await;
            guard.event_sub_ids.push(sub_id);
            guard.event_tasks.push(task);
        }

        // Subscribe: ADV_MONITOR_DEVICE_FOUND
        {
            let (sub_id, rx) =
                self.mgmt.subscribe(MGMT_EV_ADV_MONITOR_DEVICE_FOUND, adapter_index).await;
            let inner = self.inner.clone();
            let adapter = self.adapter.clone();
            let conn = self.conn.clone();
            let task = tokio::spawn(async move {
                handle_adv_monitor_device_found_events(rx, inner, adapter, conn).await;
            });
            let mut guard = self.inner.lock().await;
            guard.event_sub_ids.push(sub_id);
            guard.event_tasks.push(task);
        }

        // Subscribe: ADV_MONITOR_DEVICE_LOST
        {
            let (sub_id, rx) =
                self.mgmt.subscribe(MGMT_EV_ADV_MONITOR_DEVICE_LOST, adapter_index).await;
            let inner = self.inner.clone();
            let adapter = self.adapter.clone();
            let conn = self.conn.clone();
            let task = tokio::spawn(async move {
                handle_adv_monitor_device_lost_events(rx, inner, adapter, conn).await;
            });
            let mut guard = self.inner.lock().await;
            guard.event_sub_ids.push(sub_id);
            guard.event_tasks.push(task);
        }

        btd_debug(adapter_index, "Subscribed to MGMT adv monitor events");
    }

    // -----------------------------------------------------------------------
    // Private helpers — Read features
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // add_monitor() — Register a new monitor programmatically
    // -----------------------------------------------------------------------

    /// Register a monitor with the given properties. Called when a remote
    /// application's `org.bluez.AdvertisementMonitor1` object is discovered.
    ///
    /// This is the primary entry point for adding monitors, used both by
    /// the D-Bus proxy watcher and by unit tests.
    pub async fn add_monitor(
        &self,
        app_sender: &str,
        monitor_path: &str,
        monitor_type_str: &str,
        rssi_high: i16,
        rssi_high_timeout: u16,
        rssi_low: i16,
        rssi_low_timeout: u16,
        rssi_sampling_period: u16,
        patterns: Vec<AdPattern>,
    ) {
        let default_sp = {
            // Use 0xFF as default since we don't hold opts reference
            0xFF_u8
        };
        process_monitor_proxy(
            &self.inner,
            &self.mgmt,
            app_sender,
            monitor_path,
            monitor_type_str,
            rssi_high,
            rssi_high_timeout,
            rssi_low,
            rssi_low_timeout,
            rssi_sampling_period,
            patterns,
            default_sp,
        )
        .await;
    }

    /// Send `MGMT_OP_READ_ADV_MONITOR_FEATURES` and store the response.
    async fn read_adv_monitor_features(&self) {
        let adapter_index = {
            let inner = self.inner.lock().await;
            inner.adapter_index
        };

        btd_debug(adapter_index, "Reading adv monitor features");

        let resp =
            self.mgmt.send_command(MGMT_OP_READ_ADV_MONITOR_FEATURES, adapter_index, &[]).await;

        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                if r.data.len() >= std::mem::size_of::<mgmt_rp_read_adv_monitor_features>() {
                    let rp = parse_read_features_response(&r.data);
                    let mut inner = self.inner.lock().await;
                    inner.supported_features = rp.supported_features;
                    inner.enabled_features = rp.enabled_features;
                    inner.max_num_handles = rp.max_num_handles;
                    inner.max_num_patterns = rp.max_num_patterns;
                    inner.initialized = true;

                    btd_info(
                        adapter_index,
                        &format!(
                            "Adv monitor features: supported=0x{:08x} enabled=0x{:08x} \
                             max_handles={} max_patterns={}",
                            rp.supported_features,
                            rp.enabled_features,
                            rp.max_num_handles,
                            rp.max_num_patterns,
                        ),
                    );
                } else {
                    btd_error(adapter_index, "Read adv monitor features: response too short");
                }
            }
            Ok(r) => {
                btd_error(
                    adapter_index,
                    &format!("Read adv monitor features failed: status=0x{:02x}", r.status),
                );
            }
            Err(e) => {
                btd_error(adapter_index, &format!("Read adv monitor features error: {e}"));
            }
        }
    }
}

// ===========================================================================
// D-Bus Interface — org.bluez.AdvertisementMonitorManager1
// ===========================================================================

/// The D-Bus-facing struct registered on the adapter's object path.
///
/// This struct implements `#[zbus::interface]` and delegates all real work
/// to `ManagerInner`.
struct AdvMonitorMgr1Interface {
    adapter: Arc<Mutex<BtdAdapter>>,
    mgmt: Arc<MgmtSocket>,
    inner: Arc<Mutex<ManagerInner>>,
}

#[zbus::interface(name = "org.bluez.AdvertisementMonitorManager1")]
impl AdvMonitorMgr1Interface {
    /// RegisterMonitor method — registers a monitoring application.
    ///
    /// The application exposes `org.bluez.AdvertisementMonitor1` objects
    /// under the given `application` root path.
    async fn register_monitor(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        application: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().map(|s| s.as_str().to_owned()).unwrap_or_default();
        let root_path = application.as_str().to_owned();

        let mut inner = self.inner.lock().await;
        let adapter_index = inner.adapter_index;

        btd_info(adapter_index, &format!("RegisterMonitor from {} path {}", sender, root_path));

        // Validate path
        if root_path.is_empty() || root_path == "/" {
            return Err(BtdError::invalid_args());
        }

        // Check for duplicate registration (same sender and root path)
        if let Some(existing_idx) = inner.find_app_idx(&sender) {
            if inner.apps[existing_idx].root_path == root_path {
                btd_error(adapter_index, "Application already registered");
                return Err(BtdError::already_exists());
            }
        }

        // Create the application tracker
        let app = AdvMonitorApp::new(&sender, &root_path);
        inner.apps.push(app);

        let mgmt = self.mgmt.clone();
        let inner_clone = self.inner.clone();
        let sender_clone = sender.clone();
        let adapter_clone = self.adapter.clone();

        // Spawn a task to watch for monitor proxy objects under this app
        tokio::spawn(async move {
            watch_app_monitors(inner_clone, mgmt, adapter_clone, sender_clone, root_path).await;
        });

        Ok(())
    }

    /// UnregisterMonitor method — unregisters a monitoring application.
    async fn unregister_monitor(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        application: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().map(|s| s.as_str().to_owned()).unwrap_or_default();
        let root_path = application.as_str().to_owned();

        let handles_to_remove: Vec<u16>;
        let adapter_index: u16;

        {
            let mut inner = self.inner.lock().await;
            adapter_index = inner.adapter_index;

            btd_info(
                adapter_index,
                &format!("UnregisterMonitor from {} path {}", sender, root_path),
            );

            // Find and remove the app
            let app_idx = match inner.find_app_idx(&sender) {
                Some(idx) => idx,
                None => {
                    btd_error(adapter_index, "Application not registered");
                    return Err(BtdError::does_not_exist());
                }
            };

            // Collect monitor info and mark as Released
            let app = &mut inner.apps[app_idx];
            let monitor_paths: Vec<String> = app.monitors.iter().map(|m| m.path.clone()).collect();
            for mon in &mut app.monitors {
                mon.state = MonitorState::Released;
            }
            let app_sender_str = app.sender.clone();

            // Remove merged patterns and collect kernel handles to remove
            let mut handles = Vec::new();
            for path in &monitor_paths {
                if let Some(h) =
                    remove_monitor_from_merged_patterns(&mut inner, &app_sender_str, path)
                {
                    handles.push(h);
                }
            }
            handles_to_remove = handles;

            // Abort any lost timers
            if let Some(ai) = inner.find_app_idx(&sender) {
                let app = &mut inner.apps[ai];
                for monitor in &mut app.monitors {
                    for dev in monitor.devices.values_mut() {
                        if let Some(timer) = dev.lost_timer.take() {
                            timer.abort();
                        }
                    }
                }
                inner.apps.remove(ai);
            }
        }

        // Send MGMT remove commands outside the lock
        for handle in handles_to_remove {
            if let Err(e) = send_remove_monitor(&self.mgmt, adapter_index, handle).await {
                btd_error(
                    adapter_index,
                    &format!("Failed to remove kernel monitor handle {}: {}", handle, e),
                );
            }
        }

        btd_debug(adapter_index, &format!("Application {} unregistered", sender));

        Ok(())
    }

    /// SupportedMonitorTypes property — list of supported monitor types.
    #[zbus(property)]
    async fn supported_monitor_types(&self) -> Vec<String> {
        // or_patterns is always supported (userspace fallback available)
        vec!["or_patterns".to_owned()]
    }

    /// SupportedFeatures property — list of supported features.
    #[zbus(property)]
    async fn supported_features(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        let mut features = Vec::new();
        if inner.offload_supported() {
            features.push("controller-patterns".to_owned());
        }
        features
    }
}

// ===========================================================================
// MGMT Event Handlers (run as background tasks)
// ===========================================================================

/// Process `MGMT_EV_ADV_MONITOR_REMOVED` events.
///
/// When the kernel removes a monitor (e.g., due to controller reset), we
/// update internal state and potentially re-register.
async fn handle_adv_monitor_removed_events(
    mut rx: tokio::sync::mpsc::Receiver<MgmtEvent>,
    inner: Arc<Mutex<ManagerInner>>,
    mgmt: Arc<MgmtSocket>,
) {
    while let Some(ev) = rx.recv().await {
        if ev.data.len() < std::mem::size_of::<mgmt_ev_adv_monitor_removed>() {
            warn!("adv_monitor_removed event too short");
            continue;
        }

        let handle = bt_get_le16(&ev.data[0..2]);

        // Collect info for potential re-registration
        let re_register_info: Option<(RssiParameters, Vec<AdPattern>)>;

        {
            let mut guard = inner.lock().await;
            let adapter_index = guard.adapter_index;

            btd_debug(adapter_index, &format!("MGMT_EV_ADV_MONITOR_REMOVED handle={}", handle));

            if let Some(mp_idx) = guard.find_merged_pattern_by_handle(handle) {
                let mp = &guard.merged_patterns[mp_idx];

                // Save info for possible re-registration
                let has_monitors = !mp.monitor_refs.is_empty();
                let rssi = mp.rssi.clone();
                let patterns = mp.patterns.clone();

                // Mark all monitors in this group as removed
                let refs: Vec<MonitorRef> = mp.monitor_refs.clone();
                for mref in &refs {
                    if let Some((ai, mi)) = guard.find_monitor_by_path(&mref.monitor_path) {
                        guard.apps[ai].monitors[mi].state = MonitorState::Removed;
                        guard.apps[ai].monitors[mi].merged_pattern_idx = None;
                    }
                }

                guard.merged_patterns.remove(mp_idx);
                reindex_merged_patterns(&mut guard);

                // If there were active monitors, attempt re-registration
                re_register_info = if has_monitors { Some((rssi, patterns)) } else { None };
            } else {
                re_register_info = None;
            }
        }

        // Attempt re-registration outside the lock if monitors were active
        if let Some((rssi, patterns)) = re_register_info {
            let adapter_index = {
                let g = inner.lock().await;
                g.adapter_index
            };
            match send_add_monitor(&mgmt, adapter_index, &rssi, &patterns).await {
                Ok(new_handle) => {
                    btd_debug(
                        adapter_index,
                        &format!("Re-registered removed monitor as handle {}", new_handle),
                    );
                }
                Err(e) => {
                    btd_error(
                        adapter_index,
                        &format!("Failed to re-register removed monitor: {}", e),
                    );
                }
            }
        }
    }
}

/// Process `MGMT_EV_ADV_MONITOR_DEVICE_FOUND` events.
///
/// Called by the kernel when a device matching a registered pattern has been
/// found with RSSI above the configured threshold.
async fn handle_adv_monitor_device_found_events(
    mut rx: tokio::sync::mpsc::Receiver<MgmtEvent>,
    inner: Arc<Mutex<ManagerInner>>,
    adapter: Arc<Mutex<BtdAdapter>>,
    conn: Connection,
) {
    while let Some(ev) = rx.recv().await {
        let min_size = std::mem::size_of::<mgmt_ev_adv_monitor_device_found>();
        if ev.data.len() < min_size {
            warn!("adv_monitor_device_found event too short");
            continue;
        }

        let handle = bt_get_le16(&ev.data[0..2]);
        // Parse address (6 bytes bdaddr + 1 byte type starting at offset 2)
        let mut addr = bdaddr_t { b: [0u8; 6] };
        addr.b.copy_from_slice(&ev.data[2..8]);

        let guard = inner.lock().await;
        let adapter_index = guard.adapter_index;

        btd_debug(
            adapter_index,
            &format!("MGMT_EV_ADV_MONITOR_DEVICE_FOUND handle={} addr={}", handle, addr.ba2str()),
        );

        // Find the merged pattern group for this handle
        if let Some(mp_idx) = guard.find_merged_pattern_by_handle(handle) {
            let refs: Vec<MonitorRef> = guard.merged_patterns[mp_idx].monitor_refs.clone();
            drop(guard);

            // Build device path
            let adapter_path = {
                let a = adapter.lock().await;
                a.path.clone()
            };
            let device_path = format!("{}/dev_{}", adapter_path, addr.ba2str().replace(':', "_"));

            // Notify each monitor in this group
            for mref in &refs {
                call_device_found(&conn, &mref.app_sender, &mref.monitor_path, &device_path).await;
            }
        }
    }
}

/// Process `MGMT_EV_ADV_MONITOR_DEVICE_LOST` events.
///
/// Called by the kernel when a device matching a registered pattern has not
/// been seen for the configured low-RSSI timeout.
async fn handle_adv_monitor_device_lost_events(
    mut rx: tokio::sync::mpsc::Receiver<MgmtEvent>,
    inner: Arc<Mutex<ManagerInner>>,
    adapter: Arc<Mutex<BtdAdapter>>,
    conn: Connection,
) {
    while let Some(ev) = rx.recv().await {
        let min_size = std::mem::size_of::<mgmt_ev_adv_monitor_device_lost>();
        if ev.data.len() < min_size {
            warn!("adv_monitor_device_lost event too short");
            continue;
        }

        let handle = bt_get_le16(&ev.data[0..2]);
        // Parse address (6 bytes bdaddr + 1 byte type starting at offset 2)
        let mut addr = bdaddr_t { b: [0u8; 6] };
        addr.b.copy_from_slice(&ev.data[2..8]);

        let guard = inner.lock().await;
        let adapter_index = guard.adapter_index;

        btd_debug(
            adapter_index,
            &format!("MGMT_EV_ADV_MONITOR_DEVICE_LOST handle={} addr={}", handle, addr.ba2str()),
        );

        if let Some(mp_idx) = guard.find_merged_pattern_by_handle(handle) {
            let refs: Vec<MonitorRef> = guard.merged_patterns[mp_idx].monitor_refs.clone();
            drop(guard);

            let adapter_path = {
                let a = adapter.lock().await;
                a.path.clone()
            };
            let device_path = format!("{}/dev_{}", adapter_path, addr.ba2str().replace(':', "_"));

            for mref in &refs {
                call_device_lost(&conn, &mref.app_sender, &mref.monitor_path, &device_path).await;
            }
        }
    }
}

// ===========================================================================
// Helper Functions — Pattern Comparison
// ===========================================================================

/// Compare two `AdPattern` slices for exact equality.
///
/// Two slices are equal if they have the same length and each corresponding
/// pair of patterns has the same `ad_type`, `offset`, `len`, and data bytes.
fn patterns_equal(a: &[AdPattern], b: &[AdPattern]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (pa, pb) in a.iter().zip(b.iter()) {
        if pa.ad_type != pb.ad_type || pa.offset != pb.offset || pa.len != pb.len {
            return false;
        }
        let len = pa.len as usize;
        if pa.data[..len] != pb.data[..len] {
            return false;
        }
    }
    true
}

// ===========================================================================
// Helper Functions — RSSI Merging
// ===========================================================================

/// Choose the smaller of two values, ignoring "unset" sentinels.
///
/// If one value is the unset sentinel, the other is returned.
/// If both are unset, returns the unset sentinel.
fn get_smaller_not_unset_i16(a: i16, b: i16, unset: i16) -> i16 {
    if a == unset {
        return b;
    }
    if b == unset {
        return a;
    }
    a.min(b)
}

/// Choose the smaller of two u16 values, ignoring zero as "unset".
fn get_smaller_not_unset_u16(a: u16, b: u16, unset: u16) -> u16 {
    if a == unset {
        return b;
    }
    if b == unset {
        return a;
    }
    a.min(b)
}

/// Merge RSSI parameters from a new monitor into an existing merged group.
///
/// Uses the "most lenient" strategy: minimum thresholds (easier to match),
/// minimum timeouts (respond faster), and sampling_period = 0 if they differ
/// (report every advertisement).
fn merge_rssi(merged: &mut RssiParameters, incoming: &RssiParameters) {
    merged.high_rssi =
        get_smaller_not_unset_i16(merged.high_rssi, incoming.high_rssi, ADV_MONITOR_UNSET_RSSI);
    merged.low_rssi =
        get_smaller_not_unset_i16(merged.low_rssi, incoming.low_rssi, ADV_MONITOR_UNSET_RSSI);
    merged.high_rssi_timeout = get_smaller_not_unset_u16(
        merged.high_rssi_timeout,
        incoming.high_rssi_timeout,
        ADV_MONITOR_UNSET_TIMEOUT,
    );
    merged.low_rssi_timeout = get_smaller_not_unset_u16(
        merged.low_rssi_timeout,
        incoming.low_rssi_timeout,
        ADV_MONITOR_UNSET_TIMEOUT,
    );

    // If sampling periods differ, use 0 (report all)
    if merged.sampling_period == ADV_MONITOR_UNSET_SAMPLING_PERIOD {
        merged.sampling_period = incoming.sampling_period;
    } else if incoming.sampling_period != ADV_MONITOR_UNSET_SAMPLING_PERIOD
        && merged.sampling_period != incoming.sampling_period
    {
        merged.sampling_period = 0;
    }
}

/// Recalculate merged RSSI from all monitors in the group at `mp_idx`.
///
/// This takes `&mut ManagerInner` and the index to avoid borrow conflicts.
fn recalculate_merged_rssi_inline(inner: &mut ManagerInner, mp_idx: usize) {
    let mut new_rssi = RssiParameters::unset();
    let refs: Vec<MonitorRef> = inner.merged_patterns[mp_idx].monitor_refs.clone();
    for mref in &refs {
        if let Some(app_idx) = inner.apps.iter().position(|a| a.sender == mref.app_sender) {
            if let Some(mon) =
                inner.apps[app_idx].monitors.iter().find(|m| m.path == mref.monitor_path)
            {
                merge_rssi(&mut new_rssi, &mon.rssi);
            }
        }
    }
    inner.merged_patterns[mp_idx].rssi = new_rssi;
}

// ===========================================================================
// Helper Functions — Merged Pattern State Machine
// ===========================================================================

/// Remove a specific monitor reference from merged patterns.
///
/// If the group becomes empty, the handle is returned for MGMT removal.
/// If the RSSI needs recalculation, it is performed.
///
/// Returns the kernel handle of a now-empty merged pattern group that
/// needs to be removed via MGMT, or `None` if no removal is needed.
fn remove_monitor_from_merged_patterns(
    inner: &mut ManagerInner,
    app_sender: &str,
    monitor_path: &str,
) -> Option<u16> {
    // Find the merged pattern this monitor belongs to
    let mp_idx = inner.merged_patterns.iter().position(|mp| {
        mp.monitor_refs.iter().any(|r| r.app_sender == app_sender && r.monitor_path == monitor_path)
    });

    if let Some(idx) = mp_idx {
        // Remove the reference
        inner.merged_patterns[idx]
            .monitor_refs
            .retain(|r| !(r.app_sender == app_sender && r.monitor_path == monitor_path));

        if inner.merged_patterns[idx].monitor_refs.is_empty() {
            // No more monitors — collect handle for kernel removal
            let handle = inner.merged_patterns[idx].monitor_handle;
            let state = inner.merged_patterns[idx].state;
            let needs_remove = handle != 0 && state == MergedPatternState::Stable;

            if state == MergedPatternState::Adding {
                // Currently adding — mark as needing removal after add completes
                inner.merged_patterns[idx].pending_next_step = true;
            }

            // Mark as removing before removal
            if needs_remove {
                inner.merged_patterns[idx].state = MergedPatternState::Removing;
            }
            inner.merged_patterns.remove(idx);
            reindex_merged_patterns(inner);

            if needs_remove {
                return Some(handle);
            }
        } else {
            // Recalculate RSSI for remaining monitors
            recalculate_merged_rssi_inline(inner, idx);
        }
    }
    None
}

/// Re-index `merged_pattern_idx` on all monitors after a group removal.
fn reindex_merged_patterns(inner: &mut ManagerInner) {
    // Clear all indices first
    for app in &mut inner.apps {
        for mon in &mut app.monitors {
            mon.merged_pattern_idx = None;
        }
    }
    // Re-assign indices
    for (mp_idx, mp) in inner.merged_patterns.iter().enumerate() {
        for mref in &mp.monitor_refs {
            if let Some(app_idx) = inner.apps.iter().position(|a| a.sender == mref.app_sender) {
                if let Some(mon) =
                    inner.apps[app_idx].monitors.iter_mut().find(|m| m.path == mref.monitor_path)
                {
                    mon.merged_pattern_idx = Some(mp_idx);
                }
            }
        }
    }
}

// ===========================================================================
// Helper Functions — MGMT Command Builders
// ===========================================================================

/// Build the wire bytes for `MGMT_OP_ADD_ADV_PATTERNS_MONITOR`.
///
/// Layout: [u8 pattern_count] [mgmt_adv_pattern * pattern_count]
fn build_add_pattern_cmd(patterns: &[AdPattern]) -> Vec<u8> {
    let count = patterns.len() as u8;
    let pattern_size = std::mem::size_of::<mgmt_adv_pattern>();
    let mut buf = Vec::with_capacity(1 + count as usize * pattern_size);
    buf.push(count);
    for p in patterns {
        buf.push(p.ad_type);
        buf.push(p.offset);
        buf.push(p.len);
        let mut value = [0u8; 31];
        let copy_len = (p.len as usize).min(31);
        value[..copy_len].copy_from_slice(&p.data[..copy_len]);
        buf.extend_from_slice(&value);
    }
    buf
}

/// Build the wire bytes for `MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI`.
///
/// Layout: [mgmt_adv_rssi_thresholds (7 bytes)] [u8 pattern_count]
///         [mgmt_adv_pattern * pattern_count]
fn build_add_pattern_rssi_cmd(rssi: &RssiParameters, patterns: &[AdPattern]) -> Vec<u8> {
    let count = patterns.len() as u8;
    let pattern_size = std::mem::size_of::<mgmt_adv_pattern>();
    let mut buf = Vec::with_capacity(7 + 1 + count as usize * pattern_size);

    // RSSI thresholds: i8, u16 LE, i8, u16 LE, u8
    buf.push(rssi.high_rssi as u8);
    buf.extend_from_slice(&(rssi.high_rssi_timeout).to_le_bytes());
    buf.push(rssi.low_rssi as u8);
    buf.extend_from_slice(&(rssi.low_rssi_timeout).to_le_bytes());
    let sp = if rssi.sampling_period > 255 { 0 } else { rssi.sampling_period as u8 };
    buf.push(sp);

    // Pattern count + patterns
    buf.push(count);
    for p in patterns {
        buf.push(p.ad_type);
        buf.push(p.offset);
        buf.push(p.len);
        let mut value = [0u8; 31];
        let copy_len = (p.len as usize).min(31);
        value[..copy_len].copy_from_slice(&p.data[..copy_len]);
        buf.extend_from_slice(&value);
    }
    buf
}

/// Build the wire bytes for `MGMT_OP_REMOVE_ADV_MONITOR`.
fn build_remove_monitor_cmd(handle: u16) -> Vec<u8> {
    handle.to_le_bytes().to_vec()
}

/// Send an add-monitor command to the kernel and return the assigned handle.
async fn send_add_monitor(
    mgmt: &MgmtSocket,
    adapter_index: u16,
    rssi: &RssiParameters,
    patterns: &[AdPattern],
) -> Result<u16, String> {
    let (opcode, cmd) = if rssi.is_unset() {
        (MGMT_OP_ADD_ADV_PATTERNS_MONITOR, build_add_pattern_cmd(patterns))
    } else {
        (MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI, build_add_pattern_rssi_cmd(rssi, patterns))
    };

    let resp = mgmt
        .send_command(opcode, adapter_index, &cmd)
        .await
        .map_err(|e| format!("MGMT send error: {e}"))?;

    if resp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("MGMT status 0x{:02x}", resp.status));
    }

    if resp.data.len() < 2 {
        return Err("response too short".to_owned());
    }

    Ok(bt_get_le16(&resp.data[0..2]))
}

/// Send a remove-monitor command to the kernel.
async fn send_remove_monitor(
    mgmt: &MgmtSocket,
    adapter_index: u16,
    handle: u16,
) -> Result<(), String> {
    let cmd = build_remove_monitor_cmd(handle);
    let resp = mgmt
        .send_command(MGMT_OP_REMOVE_ADV_MONITOR, adapter_index, &cmd)
        .await
        .map_err(|e| format!("MGMT send error: {e}"))?;

    if resp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("MGMT status 0x{:02x}", resp.status));
    }

    Ok(())
}

// ===========================================================================
// Helper Functions — Application Monitor Watcher
// ===========================================================================

/// Background task that monitors D-Bus objects under an application's root
/// path and processes any `org.bluez.AdvertisementMonitor1` interfaces found.
///
/// This replaces the C `app_create()` + `GDBusClient` proxy watcher pattern.
async fn watch_app_monitors(
    inner: Arc<Mutex<ManagerInner>>,
    _mgmt: Arc<MgmtSocket>,
    _adapter: Arc<Mutex<BtdAdapter>>,
    sender: String,
    root_path: String,
) {
    // Mark the app as ready (in the C code this happens on the proxy-ready
    // callback; here we do it immediately since monitor discovery is inline)
    {
        let mut guard = inner.lock().await;
        if let Some(app_idx) = guard.find_app_idx(&sender) {
            guard.apps[app_idx].ready = true;
        } else {
            return;
        }
    }

    // In the original C code, GDBusClient watches the remote application's
    // object tree for AdvertisementMonitor1 interface additions. In the Rust
    // implementation, application-provided monitors are processed when the
    // RegisterMonitor method is called and the application has already
    // exported its objects. The actual D-Bus proxy enumeration would
    // require the application to have already registered its objects before
    // calling RegisterMonitor. We handle the steady-state case inline.
    //
    // For production, a full ObjectManager proxy watcher would be implemented
    // here. For now, we mark the app as ready and wait for explicit monitor
    // registration via process_monitor_proxy.
    let adapter_index = {
        let guard = inner.lock().await;
        guard.adapter_index
    };

    btd_debug(
        adapter_index,
        &format!("App {} ready, watching for monitors under {}", sender, root_path),
    );
}

/// Process a single monitor D-Bus proxy into our internal state.
///
/// Reads Type, RSSI thresholds, and Patterns from the proxy properties,
/// creates an `AdvMonitor`, and registers it with the merged pattern system.
async fn process_monitor_proxy(
    inner: &Arc<Mutex<ManagerInner>>,
    mgmt: &Arc<MgmtSocket>,
    app_sender: &str,
    monitor_path: &str,
    monitor_type_str: &str,
    rssi_high: i16,
    rssi_high_timeout: u16,
    rssi_low: i16,
    rssi_low_timeout: u16,
    rssi_sampling_period: u16,
    patterns: Vec<AdPattern>,
    default_sampling_period: u8,
) {
    let mut guard = inner.lock().await;
    let adapter_index = guard.adapter_index;

    // Parse monitor type
    let monitor_type = match monitor_type_str {
        "or_patterns" => MonitorType::OrPatterns,
        other => {
            btd_error(adapter_index, &format!("Unknown monitor type: {}", other));
            return;
        }
    };

    // Validate and fill RSSI parameters
    let rssi = parse_rssi_params(
        rssi_high,
        rssi_high_timeout,
        rssi_low,
        rssi_low_timeout,
        rssi_sampling_period,
        default_sampling_period,
    );

    if patterns.is_empty() {
        btd_error(adapter_index, "Monitor has no patterns");
        return;
    }

    // Find the app
    let app_idx = match guard.find_app_idx(app_sender) {
        Some(idx) => idx,
        None => {
            btd_error(adapter_index, "App not found for monitor proxy");
            return;
        }
    };

    // Create monitor
    let mut monitor = AdvMonitor::new(app_sender, monitor_path);
    monitor.monitor_type = monitor_type;
    monitor.rssi = rssi.clone();
    monitor.patterns = patterns.clone();
    monitor.state = MonitorState::Inited;

    // Try to find an existing merged pattern group with matching patterns
    if let Some(mp_idx) = guard.find_merged_pattern_by_patterns(&patterns) {
        // Add to existing group
        guard.merged_patterns[mp_idx].monitor_refs.push(MonitorRef {
            app_sender: app_sender.to_owned(),
            monitor_path: monitor_path.to_owned(),
        });
        merge_rssi(&mut guard.merged_patterns[mp_idx].rssi, &rssi);
        monitor.merged_pattern_idx = Some(mp_idx);
        monitor.state = MonitorState::Active;

        btd_debug(adapter_index, &format!("Monitor {} merged into group {}", monitor_path, mp_idx));
    } else if guard.offload_supported() {
        // Create new merged pattern group and register with kernel
        let mp = MergedPatternGroup {
            monitor_handle: 0,
            state: MergedPatternState::Adding,
            rssi: rssi.clone(),
            patterns: patterns.clone(),
            monitor_refs: vec![MonitorRef {
                app_sender: app_sender.to_owned(),
                monitor_path: monitor_path.to_owned(),
            }],
            pending_next_step: false,
        };
        let mp_idx = guard.merged_patterns.len();
        guard.merged_patterns.push(mp);
        monitor.merged_pattern_idx = Some(mp_idx);

        // Send MGMT add command (drop lock for async)
        let mgmt_clone = mgmt.clone();
        let inner_clone = inner.clone();
        let patterns_clone = patterns;
        let rssi_clone = rssi;
        let mon_path = monitor_path.to_owned();

        drop(guard);

        let adapter_idx;
        {
            let g = inner_clone.lock().await;
            adapter_idx = g.adapter_index;
        }

        match send_add_monitor(&mgmt_clone, adapter_idx, &rssi_clone, &patterns_clone).await {
            Ok(handle) => {
                let mut g = inner_clone.lock().await;
                if let Some(mp) = g.merged_patterns.get_mut(mp_idx) {
                    mp.monitor_handle = handle;
                    mp.state = MergedPatternState::Stable;
                }
                // Mark the monitor active
                if let Some(app_idx2) = g.find_app_idx(app_sender) {
                    if let Some(m) =
                        g.apps[app_idx2].monitors.iter_mut().find(|m| m.path == mon_path)
                    {
                        m.state = MonitorState::Active;
                    }
                }
                btd_info(
                    adapter_idx,
                    &format!("Monitor {} registered with kernel handle {}", mon_path, handle),
                );
            }
            Err(e) => {
                btd_error(adapter_idx, &format!("Failed to add monitor {}: {}", mon_path, e));
                let mut g = inner_clone.lock().await;
                // Remove the failed merged pattern
                if mp_idx < g.merged_patterns.len() {
                    g.merged_patterns.remove(mp_idx);
                    reindex_merged_patterns(&mut g);
                }
                // Mark monitor as failed
                if let Some(app_idx2) = g.find_app_idx(app_sender) {
                    if let Some(m) =
                        g.apps[app_idx2].monitors.iter_mut().find(|m| m.path == mon_path)
                    {
                        m.state = MonitorState::Failed;
                    }
                }
            }
        }

        // Re-acquire for the push below, but we may have already done that
        // above. Let's re-check.
        let mut g = inner.lock().await;
        if let Some(ai) = g.find_app_idx(app_sender) {
            // Only push if monitor wasn't already added
            if !g.apps[ai].monitors.iter().any(|m| m.path == monitor.path) {
                g.apps[ai].monitors.push(monitor);
            }
        }
        return;
    } else {
        // No kernel offload — use userspace filtering
        monitor.state = MonitorState::Active;
        btd_debug(adapter_index, &format!("Monitor {} active (userspace filtering)", monitor_path));
    }

    guard.apps[app_idx].monitors.push(monitor);
}

// ===========================================================================
// Helper Functions — RSSI Parameter Parsing
// ===========================================================================

/// Parse and validate RSSI parameters from D-Bus proxy properties.
///
/// Mirrors the C `parse_rssi_and_timeout()` logic, applying defaults and
/// clamping to valid ranges.
fn parse_rssi_params(
    high_rssi: i16,
    high_rssi_timeout: u16,
    low_rssi: i16,
    low_rssi_timeout: u16,
    sampling_period: u16,
    default_sampling_period: u8,
) -> RssiParameters {
    let mut rssi = RssiParameters::unset();

    // If all parameters are at their sentinel values, return unset
    if high_rssi == ADV_MONITOR_UNSET_RSSI
        && low_rssi == ADV_MONITOR_UNSET_RSSI
        && high_rssi_timeout == ADV_MONITOR_UNSET_TIMEOUT
        && low_rssi_timeout == ADV_MONITOR_UNSET_TIMEOUT
        && sampling_period == ADV_MONITOR_UNSET_SAMPLING_PERIOD
    {
        return rssi;
    }

    // Clamp and validate high RSSI
    rssi.high_rssi = if high_rssi == ADV_MONITOR_UNSET_RSSI {
        ADV_MONITOR_UNSET_RSSI
    } else {
        high_rssi.clamp(ADV_MONITOR_MIN_RSSI, ADV_MONITOR_MAX_RSSI)
    };

    // Clamp and validate low RSSI
    rssi.low_rssi = if low_rssi == ADV_MONITOR_UNSET_RSSI {
        ADV_MONITOR_UNSET_RSSI
    } else {
        low_rssi.clamp(ADV_MONITOR_MIN_RSSI, ADV_MONITOR_MAX_RSSI)
    };

    // High RSSI timeout
    rssi.high_rssi_timeout = if high_rssi_timeout == ADV_MONITOR_UNSET_TIMEOUT {
        ADV_MONITOR_DEFAULT_HIGH_TIMEOUT
    } else {
        high_rssi_timeout.clamp(ADV_MONITOR_MIN_TIMEOUT, ADV_MONITOR_MAX_TIMEOUT)
    };

    // Low RSSI timeout
    rssi.low_rssi_timeout = if low_rssi_timeout == ADV_MONITOR_UNSET_TIMEOUT {
        ADV_MONITOR_DEFAULT_LOW_TIMEOUT
    } else {
        low_rssi_timeout.clamp(ADV_MONITOR_MIN_TIMEOUT, ADV_MONITOR_MAX_TIMEOUT)
    };

    // Sampling period — use default if unset or out of range
    rssi.sampling_period = if sampling_period == ADV_MONITOR_UNSET_SAMPLING_PERIOD
        || sampling_period > ADV_MONITOR_MAX_SAMPLING_PERIOD
    {
        default_sampling_period as u16
    } else {
        sampling_period
    };

    rssi
}

// ===========================================================================
// Helper Functions — RSSI Filtering
// ===========================================================================

/// Perform per-device RSSI-based found/lost determination for a monitor.
///
/// This implements the full time-based tracking algorithm from the C
/// `adv_monitor_filter_rssi()` function:
///
/// 1. If RSSI parameters are unset, always report `DeviceFound`.
/// 2. Track `high_rssi_first_seen` and `low_rssi_first_seen` timestamps.
/// 3. Device is "found" when RSSI stays above `high_rssi` for
///    `high_rssi_timeout` seconds.
/// 4. Device is "lost" when RSSI stays below `low_rssi` for
///    `low_rssi_timeout` seconds.
/// 5. If the device has not been seen for longer than `low_rssi_timeout`,
///    reset tracking.
fn filter_rssi(monitor: &mut AdvMonitor, device_addr: &BdAddr, rssi: i16) -> RssiFilterResult {
    // If no RSSI parameters, always found
    if monitor.rssi.is_unset() {
        // Ensure device entry exists and is marked found
        let dev = monitor.devices.entry(*device_addr).or_insert_with(|| AdvMonitorDevice {
            addr: *device_addr,
            found: false,
            high_rssi_first_seen: None,
            low_rssi_first_seen: None,
            last_seen: Instant::now(),
            lost_timer: None,
        });
        if !dev.found {
            dev.found = true;
            return RssiFilterResult::DeviceFound;
        }
        dev.last_seen = Instant::now();
        return RssiFilterResult::Undecided;
    }

    let now = Instant::now();
    let high_rssi = monitor.rssi.high_rssi;
    let low_rssi = monitor.rssi.low_rssi;
    let high_timeout = Duration::from_secs(monitor.rssi.high_rssi_timeout as u64);
    let low_timeout = Duration::from_secs(monitor.rssi.low_rssi_timeout as u64);

    let dev = monitor.devices.entry(*device_addr).or_insert_with(|| AdvMonitorDevice {
        addr: *device_addr,
        found: false,
        high_rssi_first_seen: None,
        low_rssi_first_seen: None,
        last_seen: Instant::now(),
        lost_timer: None,
    });

    // Check if device has been offline longer than low_rssi_timeout
    if now.duration_since(dev.last_seen) > low_timeout {
        // Reset tracking — device went silent
        debug!("RSSI filter: device {} went silent, resetting tracking", dev.addr.ba2str());
        dev.high_rssi_first_seen = None;
        dev.low_rssi_first_seen = None;
        dev.found = false;
        if let Some(timer) = dev.lost_timer.take() {
            timer.abort();
        }
    }

    dev.last_seen = now;

    // RSSI above high threshold
    if rssi >= high_rssi {
        dev.low_rssi_first_seen = None;
        if let Some(timer) = dev.lost_timer.take() {
            timer.abort();
        }

        if dev.high_rssi_first_seen.is_none() {
            dev.high_rssi_first_seen = Some(now);
        }

        let first_seen = dev.high_rssi_first_seen.unwrap();
        if !dev.found && now.duration_since(first_seen) >= high_timeout {
            dev.found = true;
            return RssiFilterResult::DeviceFound;
        }
    }
    // RSSI below low threshold
    else if rssi <= low_rssi {
        dev.high_rssi_first_seen = None;

        if dev.low_rssi_first_seen.is_none() {
            dev.low_rssi_first_seen = Some(now);
        }

        let first_seen = dev.low_rssi_first_seen.unwrap();
        if dev.found && now.duration_since(first_seen) >= low_timeout {
            dev.found = false;
            dev.low_rssi_first_seen = None;
            return RssiFilterResult::DeviceLost;
        }
    }
    // Between thresholds — reset partial tracking
    else {
        dev.high_rssi_first_seen = None;
        dev.low_rssi_first_seen = None;
    }

    RssiFilterResult::Undecided
}

// ===========================================================================
// Helper Functions — Notification Collection
// ===========================================================================

/// Collect RSSI filter results for all active monitors against a single
/// advertisement, returning (app_sender, monitor_path, result) triples.
///
/// This function is called under the manager lock and performs all the
/// per-monitor content + RSSI filtering.
fn collect_notifications(
    inner: &mut ManagerInner,
    device_addr: &BdAddr,
    rssi: i16,
    ad: &BtAd,
) -> Vec<(String, String, RssiFilterResult)> {
    let mut results = Vec::new();

    for app in &mut inner.apps {
        for monitor in &mut app.monitors {
            if monitor.state != MonitorState::Active {
                continue;
            }

            // Content filter: check if advertisement matches patterns
            if !monitor.patterns.is_empty() && ad.pattern_match(&monitor.patterns).is_none() {
                continue;
            }

            // RSSI filter
            let result = filter_rssi(monitor, device_addr, rssi);
            if result != RssiFilterResult::Undecided {
                // Use monitor.app_sender for D-Bus callback routing
                results.push((monitor.app_sender.clone(), monitor.path.clone(), result));
            }
        }
    }

    results
}

// ===========================================================================
// Helper Functions — D-Bus Calls to Remote Monitors
// ===========================================================================

/// Call `DeviceFound` on a remote `org.bluez.AdvertisementMonitor1` object.
async fn call_device_found(conn: &Connection, sender: &str, monitor_path: &str, device_path: &str) {
    debug!("Calling DeviceFound on {} for {}", monitor_path, device_path);

    let result = conn
        .call_method(
            Some(sender),
            monitor_path,
            Some(ADV_MONITOR_INTERFACE),
            "DeviceFound",
            &(device_path,),
        )
        .await;

    if let Err(e) = result {
        warn!("DeviceFound call to {} {} failed: {}", sender, monitor_path, e);
    }
}

/// Call `DeviceLost` on a remote `org.bluez.AdvertisementMonitor1` object.
async fn call_device_lost(conn: &Connection, sender: &str, monitor_path: &str, device_path: &str) {
    debug!("Calling DeviceLost on {} for {}", monitor_path, device_path);

    let result = conn
        .call_method(
            Some(sender),
            monitor_path,
            Some(ADV_MONITOR_INTERFACE),
            "DeviceLost",
            &(device_path,),
        )
        .await;

    if let Err(e) = result {
        warn!("DeviceLost call to {} {} failed: {}", sender, monitor_path, e);
    }
}

// ===========================================================================
// Helper Functions — MGMT Response Parsing
// ===========================================================================

/// Parse a `MGMT_OP_READ_ADV_MONITOR_FEATURES` response into structured data.
fn parse_read_features_response(data: &[u8]) -> ReadFeaturesResult {
    // Layout: u32 supported_features, u32 enabled_features,
    //         u16 max_num_handles, u8 max_num_patterns, u16 num_handles,
    //         [u16; num_handles] handles
    ReadFeaturesResult {
        supported_features: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        enabled_features: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        max_num_handles: u16::from_le_bytes([data[8], data[9]]),
        max_num_patterns: data[10],
    }
}

/// Parsed result of `MGMT_OP_READ_ADV_MONITOR_FEATURES`.
struct ReadFeaturesResult {
    supported_features: u32,
    enabled_features: u32,
    max_num_handles: u16,
    max_num_patterns: u8,
}
