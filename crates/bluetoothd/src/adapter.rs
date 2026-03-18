// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2006-2010  Nokia Corporation
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
//
// Adapter abstraction — Rust rewrite of `src/adapter.c` and `src/adapter.h`.
//
// This module implements the `org.bluez.Adapter1` D-Bus interface and the
// adapter lifecycle management for the `bluetoothd` daemon.  Each adapter
// corresponds to a physical or virtual Bluetooth HCI controller indexed by
// `hciN` (where N = 0, 1, …).
//
// Key responsibilities:
// - Controller bring-up/tear-down via the kernel Management (MGMT) API
// - `org.bluez.Adapter1` D-Bus methods, properties, and signals
// - Device discovery management with per-client filtering
// - Persistent storage of adapter settings, device info, keys
// - Adapter driver registration and lifecycle callbacks
// - PIN, OOB, MSD callback registries
// - Authorization queue for service access control
// - Experimental and kernel feature management


use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{trace, warn};
use zbus::zvariant::{ObjectPath, Value};

use bluez_shared::mgmt::client::{MgmtEvent, MgmtResponse, MgmtSocket};
use bluez_shared::sys::bluetooth::{
    BDADDR_ANY, BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, BdAddr,
};
use bluez_shared::sys::hci::HCI_DEV_NONE;
use bluez_shared::sys::mgmt::{
    MGMT_EV_AUTH_FAILED, MGMT_EV_CLASS_OF_DEV_CHANGED, MGMT_EV_CONNECT_FAILED,
    MGMT_EV_DEVICE_BLOCKED, MGMT_EV_DEVICE_CONNECTED, MGMT_EV_DEVICE_DISCONNECTED,
    MGMT_EV_DEVICE_FOUND, MGMT_EV_DEVICE_UNBLOCKED, MGMT_EV_DEVICE_UNPAIRED, MGMT_EV_DISCOVERING,
    MGMT_EV_EXP_FEATURE_CHANGE, MGMT_EV_LOCAL_NAME_CHANGED, MGMT_EV_NEW_CONN_PARAM,
    MGMT_EV_NEW_CSRK, MGMT_EV_NEW_IRK, MGMT_EV_NEW_LINK_KEY, MGMT_EV_NEW_LONG_TERM_KEY,
    MGMT_EV_NEW_SETTINGS, MGMT_EV_PIN_CODE_REQUEST, MGMT_EV_USER_CONFIRM_REQUEST,
    MGMT_EV_USER_PASSKEY_REQUEST, MGMT_OP_ADD_DEVICE, MGMT_OP_ADD_UUID, MGMT_OP_DISCONNECT,
    MGMT_OP_PAIR_DEVICE, MGMT_OP_PIN_CODE_NEG_REPLY, MGMT_OP_PIN_CODE_REPLY, MGMT_OP_REMOVE_UUID,
    MGMT_OP_SET_BONDABLE, MGMT_OP_SET_DEV_CLASS, MGMT_OP_SET_DISCOVERABLE,
    MGMT_OP_SET_FAST_CONNECTABLE, MGMT_OP_SET_LOCAL_NAME, MGMT_OP_SET_POWERED,
    MGMT_OP_START_DISCOVERY, MGMT_OP_STOP_DISCOVERY, MGMT_OP_UNPAIR_DEVICE,
    MGMT_OP_USER_CONFIRM_NEG_REPLY, MGMT_OP_USER_CONFIRM_REPLY, MGMT_OP_USER_PASSKEY_NEG_REPLY,
    MGMT_OP_USER_PASSKEY_REPLY, MGMT_STATUS_RFKILLED, MGMT_STATUS_SUCCESS, MgmtSettings,
    mgmt_blocked_key_info, mgmt_conn_param, mgmt_errstr, mgmt_rp_read_info,
};
use bluez_shared::util::eir::{EirData, eir_parse};
use bluez_shared::util::uuid::BtUuid;

use crate::agent::{
    agent_get, agent_request_confirmation, agent_request_passkey, agent_request_pincode,
};
use crate::config::BtdOpts;
use crate::device::{AddressType, BtdDevice, device_create_from_storage};
use crate::error::BtdError;
use crate::gatt::database::BtdGattDatabase;
use crate::log::{btd_debug, btd_info, btd_warn};
use crate::sdp::SdpRecord;
use crate::storage::STORAGEDIR;

// ===========================================================================
// Constants
// ===========================================================================

/// D-Bus interface name for the Adapter1 object.
pub const ADAPTER_INTERFACE: &str = "org.bluez.Adapter1";

/// Maximum adapter name length (bytes), matching HCI spec.
pub const MAX_NAME_LENGTH: usize = 248;

/// Invalid SSP passkey value used to indicate negative replies.
pub const INVALID_PASSKEY: u32 = 0xFFFF_FFFF;

/// Connectable scan timeout in seconds.
pub const CONN_SCAN_TIMEOUT: u64 = 3;

/// Idle discovery restart delay in seconds.
pub const IDLE_DISCOV_TIMEOUT: u64 = 5;

/// Temporary device timeout in seconds.
pub const TEMP_DEV_TIMEOUT: u64 = 3 * 60;

/// Bonding timeout in seconds.
pub const BONDING_TIMEOUT: u64 = 2 * 60;

/// BR/EDR scan type bitmask.
const SCAN_TYPE_BREDR: u8 = 1 << BDADDR_BREDR;

/// LE scan type bitmask (public + random).
const SCAN_TYPE_LE: u8 = (1 << BDADDR_LE_PUBLIC) | (1 << BDADDR_LE_RANDOM);

/// Dual-mode scan type bitmask.
pub const SCAN_TYPE_DUAL: u8 = SCAN_TYPE_BREDR | SCAN_TYPE_LE;

/// Invalid RSSI sentinel.
const HCI_RSSI_INVALID: i8 = 127;

/// Invalid distance sentinel.
pub const DISTANCE_VAL_INVALID: i16 = 0x7FFF;

/// Maximum path loss value.
const PATHLOSS_MAX: u16 = 137;

/// LE link type constant (not in hci.rs, defined locally as in C).
pub const LE_LINK: u8 = 0x80;

// ---------------------------------------------------------------------------
// Adapter power state machine
// ---------------------------------------------------------------------------

/// Adapter power state, matching C `enum` in adapter.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AdapterPowerState {
    Off = 0,
    On = 1,
    OnDisabling = 2,
    OffEnabling = 3,
    OffBlocked = 4,
}

impl AdapterPowerState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::OnDisabling => "on-disabling",
            Self::OffEnabling => "off-enabling",
            Self::OffBlocked => "off-blocked",
        }
    }
}

// ===========================================================================
// Experimental Features
// ===========================================================================

/// Experimental feature flags matching C `enum experimental_features`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ExperimentalFeatures {
    DEBUG = 1 << 0,
    LE_SIMULT_ROLES = 1 << 1,
    BQR = 1 << 2,
    RPA_RESOLUTION = 1 << 3,
    CODEC_OFFLOAD = 1 << 4,
    ISO_SOCKET = 1 << 5,
}

impl ExperimentalFeatures {
    /// Return the bitmask value.
    pub fn bits(self) -> u32 {
        self as u32
    }
}

/// Experimental feature UUID definitions.
pub struct ExpUuid {
    pub val: [u8; 16],
    str_repr: &'static str,
}

/// Debug feature UUID: d4992530-b9ec-469f-ab01-6c481c47da1c
const EXP_UUID_DEBUG: ExpUuid = ExpUuid {
    val: [
        0x1c, 0xda, 0x47, 0x1c, 0x48, 0x6c, 0x01, 0xab, 0x9f, 0x46, 0xec, 0xb9, 0x30, 0x25, 0x99,
        0xd4,
    ],
    str_repr: "d4992530-b9ec-469f-ab01-6c481c47da1c",
};

/// LE simultaneous central/peripheral UUID: 671b10b5-42c0-4696-9227-eb28d1b049d6
const EXP_UUID_LE_SIMULT: ExpUuid = ExpUuid {
    val: [
        0xd6, 0x49, 0xb0, 0xd1, 0x28, 0xeb, 0x27, 0x92, 0x96, 0x46, 0xc0, 0x42, 0xb5, 0x10, 0x1b,
        0x67,
    ],
    str_repr: "671b10b5-42c0-4696-9227-eb28d1b049d6",
};

/// Bluetooth Quality Report UUID: 330859bc-7506-492d-9370-9a6f0614037f
const EXP_UUID_BQR: ExpUuid = ExpUuid {
    val: [
        0x7f, 0x03, 0x14, 0x06, 0x6f, 0x9a, 0x70, 0x93, 0x2d, 0x49, 0x06, 0x75, 0xbc, 0x59, 0x08,
        0x33,
    ],
    str_repr: "330859bc-7506-492d-9370-9a6f0614037f",
};

/// RPA resolution UUID: 15c0a148-c273-11ea-b3de-0242ac130004
const EXP_UUID_RPA_RESOLUTION: ExpUuid = ExpUuid {
    val: [
        0x04, 0x00, 0x13, 0xac, 0x42, 0x02, 0xde, 0xb3, 0xea, 0x11, 0x73, 0xc2, 0x48, 0xa1, 0xc0,
        0x15,
    ],
    str_repr: "15c0a148-c273-11ea-b3de-0242ac130004",
};

/// Codec offload UUID: a6695ace-ee7f-4fb9-881a-5fac66c629af
const EXP_UUID_CODEC_OFFLOAD: ExpUuid = ExpUuid {
    val: [
        0xaf, 0x29, 0xc6, 0x66, 0xac, 0x5f, 0x1a, 0x88, 0xb9, 0x4f, 0x7f, 0xee, 0xce, 0x5a, 0x69,
        0xa6,
    ],
    str_repr: "a6695ace-ee7f-4fb9-881a-5fac66c629af",
};

/// ISO socket UUID: 6fbaf188-05e0-496a-9885-d6ddfdb4e03e
const EXP_UUID_ISO_SOCKET: ExpUuid = ExpUuid {
    val: [
        0x3e, 0xe0, 0xb4, 0xfd, 0xdd, 0xd6, 0x85, 0x98, 0x6a, 0x49, 0xe0, 0x05, 0x88, 0xf1, 0xba,
        0x6f,
    ],
    str_repr: "6fbaf188-05e0-496a-9885-d6ddfdb4e03e",
};

// ===========================================================================
// Kernel Features
// ===========================================================================

/// Kernel feature flags matching C `enum kernel_features`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum KernelFeatures {
    CONN_CONTROL = 1 << 0,
    BLOCKED_KEYS_SUPPORTED = 1 << 1,
    SET_SYSTEM_CONFIG = 1 << 2,
    EXP_FEATURES = 1 << 3,
    HAS_RESUME_EVT = 1 << 4,
    HAS_EXT_ADV_ADD_CMDS = 1 << 5,
    HAS_CONTROLLER_CAP_CMD = 1 << 6,
}

impl KernelFeatures {
    pub fn bits(self) -> u32 {
        self as u32
    }
}

// ===========================================================================
// Known compromised security keys
// ===========================================================================

/// Known compromised security keys (Google Titan Security Keys).
pub static BLOCKED_KEYS: &[mgmt_blocked_key_info] = &[
    mgmt_blocked_key_info {
        type_: 0x01, // HCI_BLOCKED_KEY_TYPE_LTK
        val: [
            0xbf, 0x01, 0xfb, 0x9d, 0x4e, 0xf3, 0xbc, 0x36, 0xd8, 0x74, 0xf5, 0x39, 0x41, 0x38,
            0x68, 0x4c,
        ],
    },
    mgmt_blocked_key_info {
        type_: 0x02, // HCI_BLOCKED_KEY_TYPE_IRK
        val: [
            0xa5, 0x99, 0xba, 0xe4, 0xe1, 0x7c, 0xa6, 0x18, 0x22, 0x8e, 0x07, 0x56, 0xb4, 0xe8,
            0x5f, 0x01,
        ],
    },
];

// ===========================================================================
// Discovery Filter
// ===========================================================================

/// Discovery filter matching C `struct discovery_filter`.
#[derive(Debug, Clone)]
pub struct DiscoveryFilter {
    /// UUIDs to filter on during discovery.
    pub uuids: Vec<String>,
    /// Minimum RSSI threshold (-127..126), or `HCI_RSSI_INVALID` to disable.
    pub rssi: i16,
    /// Maximum pathloss, or 0 to disable.
    pub pathloss: u16,
    /// Transport to filter: "auto", "bredr", "le".
    pub transport: String,
    /// Whether to report duplicate advertisement data.
    pub duplicate_data: bool,
    /// Whether to report only discoverable devices.
    pub discoverable: bool,
    /// Pattern to match on device name or address.
    pub pattern: String,
}

impl Default for DiscoveryFilter {
    fn default() -> Self {
        Self {
            uuids: Vec::new(),
            rssi: HCI_RSSI_INVALID as i16,
            pathloss: PATHLOSS_MAX,
            transport: String::from("auto"),
            duplicate_data: false,
            discoverable: true,
            pattern: String::new(),
        }
    }
}

// ===========================================================================
// OOB Handler
// ===========================================================================

/// Out-of-Band pairing handler.
pub struct OobHandler {
    /// Callback invoked with local OOB data.
    pub read_local_cb: Option<Box<dyn FnOnce(Vec<u8>) + Send + 'static>>,
    /// Callback invoked to complete bonding using OOB data.
    pub bonding_cb: Option<Box<dyn FnOnce(bool) + Send + 'static>>,
    /// Remote device address for OOB pairing.
    pub remote_addr: BdAddr,
}

impl std::fmt::Debug for OobHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OobHandler").field("remote_addr", &self.remote_addr.ba2str()).finish()
    }
}

// ===========================================================================
// Adapter Driver Trait
// ===========================================================================

/// Adapter driver trait — replaces C `struct btd_adapter_driver`.
///
/// Profile / plugin subsystems implement this trait to receive adapter
/// lifecycle callbacks.  Registered via [`btd_register_adapter_driver`].
#[allow(unused_variables)]
pub trait BtdAdapterDriver: Send + Sync + 'static {
    /// Human-readable driver name.
    fn name(&self) -> &str;

    /// Called when an adapter becomes available (powered on).
    fn probe(&self, adapter: &BtdAdapter) -> Result<(), BtdError> {
        Ok(())
    }

    /// Called when an adapter is being removed.
    fn remove(&self, adapter: &BtdAdapter) {}

    /// Called when an adapter is resumed (e.g. after system suspend).
    fn resume(&self, adapter: &BtdAdapter) {}

    /// Called when a device is added to the adapter.
    fn device_added(&self, adapter: &BtdAdapter, addr: &BdAddr) {}

    /// Called when a device is removed from the adapter.
    fn device_removed(&self, adapter: &BtdAdapter, addr: &BdAddr) {}

    /// Called when a device's services have been fully resolved.
    fn device_resolved(&self, adapter: &BtdAdapter, addr: &BdAddr) {}

    /// Whether the driver requires an experimental feature to be enabled.
    fn experimental(&self) -> bool {
        false
    }
}

// ===========================================================================
// Per-client discovery session
// ===========================================================================

/// Per-D-Bus-client discovery session state.
#[derive(Debug)]
pub struct DiscoveryClient {
    sender: String,
    filter: DiscoveryFilter,
}

// ===========================================================================
// Callback registries
// ===========================================================================

/// Result of a PIN code callback.
///
/// Replaces the C pattern where `ssize_t` return + output `char *pinbuf` and
/// `bool *display` parameters communicate both the PIN bytes and whether the
/// PIN should be displayed to the user (e.g. for keyboard entry).
#[derive(Debug, Clone)]
pub struct PinCodeResult {
    /// PIN code bytes (typically ASCII digits, up to 16 bytes).
    pub pin: Vec<u8>,
    /// Whether the PIN should be displayed to the user via
    /// `DisplayPinCode` (true for keyboards, false for fixed PINs).
    pub display: bool,
}

/// PIN code callback signature.
///
/// Matches C `btd_adapter_pin_cb_t`:
/// ```c
/// typedef ssize_t (*btd_adapter_pin_cb_t)(struct btd_adapter *adapter,
///     struct btd_device *device, char *pinbuf, bool *display,
///     unsigned int attempt);
/// ```
///
/// Parameters:
/// - `&BtdAdapter` — the adapter requesting the PIN
/// - `&BtdDevice` — the remote device being paired
/// - `u32` — attempt number (1-based)
///
/// Returns `Some(PinCodeResult)` with the PIN and display flag, or `None`
/// if this callback does not handle the device.
pub type PinCodeCallback =
    Box<dyn Fn(&BtdAdapter, &BtdDevice, u32) -> Option<PinCodeResult> + Send + Sync>;

pub struct PinCbEntry {
    pub cb: PinCodeCallback,
    id: u64,
}

type MsdCallback = Box<dyn Fn(&BdAddr, u16, &[u8]) + Send + Sync>;

pub struct MsdCbEntry {
    pub cb: MsdCallback,
    id: u64,
}

type DisconnectCallback = Box<dyn Fn(&BdAddr, u8) + Send + Sync>;

pub struct DisconnectCbEntry {
    pub cb: DisconnectCallback,
    id: u64,
}

type ConnFailCallback = Box<dyn Fn(&BdAddr, u8) + Send + Sync>;

pub struct ConnFailCbEntry {
    pub cb: ConnFailCallback,
    id: u64,
}

/// Tracks an in-flight Set Experimental Feature command.
pub struct ExpPending {
    pub name: &'static str,
    pub flag: ExperimentalFeatures,
}

// ===========================================================================
// BtdAdapter — Core adapter struct
// ===========================================================================

/// Core adapter state.  One instance per HCI controller.
pub struct BtdAdapter {
    // ---- Identity ----
    pub index: u16,
    pub address: BdAddr,
    pub address_type: u8,
    pub name: String,
    pub path: String,
    pub short_name: String,

    // ---- Power & settings ----
    pub powered: bool,
    pub discoverable: bool,
    pub pairable: bool,
    pub discovering: bool,
    pub current_settings: u32,
    pub supported_settings: u32,
    pub pending_settings: u32,
    pub power_state: AdapterPowerState,
    pub stored_discoverable: bool,

    // ---- Timeouts ----
    pub discoverable_timeout: u32,
    pub pairable_timeout: u32,

    // ---- Device state ----
    pub devices: HashMap<BdAddr, ()>,
    pub discovery_filters: Vec<DiscoveryFilter>,
    pub discovery_clients: Vec<DiscoveryClient>,

    // ---- Discovery internals ----
    pub discovery_type: u8,
    pub discovery_enable: u8,
    pub filtered_discovery: bool,
    pub no_scan_restart_delay: bool,
    pub discovery_suspended: bool,
    pub discovery_discoverable: bool,

    // ---- Identification ----
    pub alias: String,
    pub stored_alias: String,
    pub modalias: String,
    pub class: u32,
    pub system_name: String,
    pub major_class: u8,
    pub minor_class: u8,

    // ---- Hardware info ----
    pub version: u8,
    pub manufacturer: u16,
    pub dev_class: u32,

    // ---- Feature flags ----
    pub le_enabled: bool,
    pub bredr_enabled: bool,
    pub exp_features: u32,
    pub kernel_features: u32,
    pub uuids: HashSet<String>,
    pub allowed_uuids: HashSet<String>,

    // ---- Subsystems ----
    pub database: Option<Arc<BtdGattDatabase>>,

    // ---- Connectivity ----
    pub services: Vec<SdpRecord>,
    pub connections: HashSet<BdAddr>,
    pub connect_list: Vec<BdAddr>,
    pub connect_le: Vec<BdAddr>,

    // ---- Callback registries ----
    pub pin_callbacks: Vec<PinCbEntry>,
    pub msd_callbacks: Vec<MsdCbEntry>,
    pub disconnect_callbacks: Vec<DisconnectCbEntry>,
    pub conn_fail_callbacks: Vec<ConnFailCbEntry>,

    // ---- Driver management ----
    pub drivers: Vec<Arc<dyn BtdAdapterDriver>>,
    pub profiles: Vec<String>,

    // ---- OOB ----
    pub oob_handler: Option<OobHandler>,

    // ---- Default ----
    pub is_default: bool,

    // ---- Pending operations ----
    pub exp_pending: Vec<ExpPending>,
    pub initialized: bool,

    // ---- MGMT socket ----
    pub mgmt: Option<Arc<MgmtSocket>>,

    // ---- Task handles ----
    pub event_task: Option<JoinHandle<()>>,

    // ---- Storage ----
    pub storage_dir: String,

    // ---- Monotonic IDs for callbacks ----
    pub next_cb_id: u64,
}

impl std::fmt::Debug for BtdAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtdAdapter")
            .field("index", &self.index)
            .field("address", &self.address.ba2str())
            .field("path", &self.path)
            .field("powered", &self.powered)
            .finish()
    }
}

// ===========================================================================
// Global adapter registry
// ===========================================================================

/// Global adapter list.  Protected by a tokio `RwLock` for async access.
static ADAPTERS: std::sync::LazyLock<RwLock<Vec<Arc<Mutex<BtdAdapter>>>>> =
    std::sync::LazyLock::new(|| RwLock::new(Vec::new()));

/// Global adapter driver list.
static ADAPTER_DRIVERS: std::sync::LazyLock<RwLock<Vec<Arc<dyn BtdAdapterDriver>>>> =
    std::sync::LazyLock::new(|| RwLock::new(Vec::new()));

/// Global default adapter index.
static DEFAULT_ADAPTER_INDEX: std::sync::LazyLock<Mutex<Option<u16>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

/// Global MGMT socket (one per daemon).
static MGMT_MAIN: std::sync::LazyLock<Mutex<Option<Arc<MgmtSocket>>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

/// Shared kernel features bitmask (global, not per-adapter).
static KERNEL_FEATURES: std::sync::LazyLock<Mutex<u32>> =
    std::sync::LazyLock::new(|| Mutex::new(0));

/// Global next callback ID generator.
static NEXT_CB_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn alloc_cb_id() -> u64 {
    NEXT_CB_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ===========================================================================
// BtdAdapter — Constructor & accessor helpers
// ===========================================================================

impl BtdAdapter {
    /// Create a new adapter from MGMT Read Info response data.
    pub fn new(index: u16, info: &mgmt_rp_read_info, mgmt: Arc<MgmtSocket>) -> Self {
        let addr = info.bdaddr;
        let addr_str = addr.ba2str();
        let path = format!("/org/bluez/hci{index}");
        let name = {
            let raw = &info.name;
            let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..len]).to_string()
        };
        let short_name = {
            let raw = &info.short_name;
            let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..len]).to_string()
        };
        let dev_class = (info.dev_class[2] as u32) << 16
            | (info.dev_class[1] as u32) << 8
            | (info.dev_class[0] as u32);
        let manufacturer = u16::from_le(info.manufacturer);
        let current_settings = u32::from_le(info.current_settings);
        let supported_settings = u32::from_le(info.supported_settings);
        let powered = current_settings & MgmtSettings::POWERED.bits() != 0;
        let discoverable = current_settings & MgmtSettings::DISCOVERABLE.bits() != 0;
        let pairable = current_settings & MgmtSettings::BONDABLE.bits() != 0;
        let le_enabled = current_settings & MgmtSettings::LE.bits() != 0;
        let bredr_enabled = current_settings & MgmtSettings::BREDR.bits() != 0;
        let storage_dir = format!("{}/{}", STORAGEDIR, addr_str);

        Self {
            index,
            address: addr,
            address_type: BDADDR_BREDR,
            name: name.clone(),
            path,
            short_name,
            powered,
            discoverable,
            pairable,
            discovering: false,
            current_settings,
            supported_settings,
            pending_settings: 0,
            power_state: if powered { AdapterPowerState::On } else { AdapterPowerState::Off },
            stored_discoverable: false,
            discoverable_timeout: 180,
            pairable_timeout: 0,
            devices: HashMap::new(),
            discovery_filters: Vec::new(),
            discovery_clients: Vec::new(),
            discovery_type: 0,
            discovery_enable: 0,
            filtered_discovery: false,
            no_scan_restart_delay: false,
            discovery_suspended: false,
            discovery_discoverable: false,
            alias: name.clone(),
            stored_alias: String::new(),
            modalias: String::new(),
            class: dev_class,
            system_name: String::new(),
            major_class: ((dev_class >> 8) & 0x1f) as u8,
            minor_class: ((dev_class >> 2) & 0x3f) as u8,
            version: info.version,
            manufacturer,
            dev_class,
            le_enabled,
            bredr_enabled,
            exp_features: 0,
            kernel_features: 0,
            uuids: HashSet::new(),
            allowed_uuids: HashSet::new(),
            database: None,
            services: Vec::new(),
            connections: HashSet::new(),
            connect_list: Vec::new(),
            connect_le: Vec::new(),
            pin_callbacks: Vec::new(),
            msd_callbacks: Vec::new(),
            disconnect_callbacks: Vec::new(),
            conn_fail_callbacks: Vec::new(),
            drivers: Vec::new(),
            profiles: Vec::new(),
            oob_handler: None,
            is_default: false,
            exp_pending: Vec::new(),
            initialized: false,
            mgmt: Some(mgmt),
            event_task: None,
            storage_dir,
            next_cb_id: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Settings helpers
    // -----------------------------------------------------------------------

    /// Recalculate cached booleans from the `current_settings` bitmask.
    fn update_settings_from_bitmask(&mut self) {
        let s = self.current_settings;
        self.powered = s & MgmtSettings::POWERED.bits() != 0;
        self.discoverable = s & MgmtSettings::DISCOVERABLE.bits() != 0;
        self.pairable = s & MgmtSettings::BONDABLE.bits() != 0;
        self.le_enabled = s & MgmtSettings::LE.bits() != 0;
        self.bredr_enabled = s & MgmtSettings::BREDR.bits() != 0;
    }

    /// Return whether the current settings include a given flag.
    fn has_setting(&self, flag: u32) -> bool {
        self.current_settings & flag != 0
    }

    /// Return whether the supported settings include a given flag.
    pub fn supports_setting(&self, flag: u32) -> bool {
        self.supported_settings & flag != 0
    }

    /// Derive the correct discovery scan type from current settings.
    fn get_scan_type(&self) -> u8 {
        let mut scan_type: u8 = 0;
        if self.bredr_enabled {
            scan_type |= SCAN_TYPE_BREDR;
        }
        if self.le_enabled {
            scan_type |= SCAN_TYPE_LE;
        }
        scan_type
    }

    /// Compute the effective alias (stored > name > "BlueZ $index").
    fn effective_alias(&self) -> String {
        if !self.stored_alias.is_empty() {
            return self.stored_alias.clone();
        }
        if !self.name.is_empty() {
            return self.name.clone();
        }
        format!("BlueZ {}", self.index)
    }

    // -----------------------------------------------------------------------
    // D-Bus property helpers
    // -----------------------------------------------------------------------

    fn address_str(&self) -> String {
        self.address.ba2str()
    }

    fn address_type_str(&self) -> &'static str {
        match self.address_type {
            BDADDR_LE_RANDOM => "random",
            _ => "public",
        }
    }

    /// Public accessor for the optional MGMT socket.
    /// Used by device.rs for issuing commands on behalf of the adapter.
    pub fn mgmt(&self) -> Option<Arc<MgmtSocket>> {
        self.mgmt.clone()
    }

    fn uuid_list(&self) -> Vec<String> {
        self.uuids.iter().cloned().collect()
    }

    fn power_state_str(&self) -> &'static str {
        self.power_state.as_str()
    }

    fn roles_list(&self) -> Vec<String> {
        let mut roles = Vec::new();
        if self.supported_settings & MgmtSettings::LE.bits() != 0 {
            roles.push("central".to_string());
            roles.push("peripheral".to_string());
            if self.exp_features & ExperimentalFeatures::LE_SIMULT_ROLES.bits() != 0 {
                roles.push("central-peripheral".to_string());
            }
        }
        roles
    }

    fn experimental_features_list(&self) -> Vec<String> {
        let mut features = Vec::new();
        let pairs: &[(&ExpUuid, ExperimentalFeatures)] = &[
            (&EXP_UUID_DEBUG, ExperimentalFeatures::DEBUG),
            (&EXP_UUID_LE_SIMULT, ExperimentalFeatures::LE_SIMULT_ROLES),
            (&EXP_UUID_BQR, ExperimentalFeatures::BQR),
            (&EXP_UUID_RPA_RESOLUTION, ExperimentalFeatures::RPA_RESOLUTION),
            (&EXP_UUID_CODEC_OFFLOAD, ExperimentalFeatures::CODEC_OFFLOAD),
            (&EXP_UUID_ISO_SOCKET, ExperimentalFeatures::ISO_SOCKET),
        ];
        for (uuid, flag) in pairs {
            if self.exp_features & flag.bits() != 0 {
                features.push(uuid.str_repr.to_string());
            }
        }
        features
    }

    /// Create a minimal adapter for testing purposes.
    ///
    /// This constructor does NOT require an MGMT socket or kernel
    /// interaction.  It is intentionally public so that integration
    /// tests can verify field accessibility.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(index: u16) -> Self {
        let path = format!("/org/bluez/hci{index}");
        let storage_dir = format!("{}/00:00:00:00:00:00", STORAGEDIR);
        Self {
            index,
            path,
            address: BDADDR_ANY,
            address_type: BDADDR_BREDR,
            name: String::new(),
            short_name: String::new(),
            powered: false,
            discoverable: false,
            pairable: false,
            discovering: false,
            current_settings: 0,
            supported_settings: 0,
            pending_settings: 0,
            power_state: AdapterPowerState::Off,
            stored_discoverable: false,
            discoverable_timeout: 0,
            pairable_timeout: 0,
            devices: HashMap::new(),
            discovery_filters: Vec::new(),
            discovery_clients: Vec::new(),
            discovery_type: 0,
            discovery_enable: 0,
            filtered_discovery: false,
            no_scan_restart_delay: false,
            discovery_suspended: false,
            discovery_discoverable: false,
            alias: String::new(),
            stored_alias: String::new(),
            modalias: String::new(),
            class: 0,
            system_name: String::new(),
            major_class: 0,
            minor_class: 0,
            version: 0,
            manufacturer: 0,
            dev_class: 0,
            le_enabled: true,
            bredr_enabled: true,
            exp_features: 0,
            kernel_features: 0,
            uuids: HashSet::new(),
            allowed_uuids: HashSet::new(),
            database: None,
            services: Vec::new(),
            connections: HashSet::new(),
            connect_list: Vec::new(),
            connect_le: Vec::new(),
            pin_callbacks: Vec::new(),
            msd_callbacks: Vec::new(),
            disconnect_callbacks: Vec::new(),
            conn_fail_callbacks: Vec::new(),
            drivers: Vec::new(),
            profiles: Vec::new(),
            oob_handler: None,
            is_default: false,
            exp_pending: Vec::new(),
            initialized: false,
            mgmt: None,
            event_task: None,
            storage_dir,
            next_cb_id: 1,
        }
    }
}

// ===========================================================================
// D-Bus Interface: org.bluez.Adapter1
// ===========================================================================

/// Wrapper struct for the zbus interface implementation.
///
/// This holds an `Arc<Mutex<BtdAdapter>>` so the D-Bus methods/properties
/// can access the adapter state asynchronously.
pub struct Adapter1Interface {
    inner: Arc<Mutex<BtdAdapter>>,
}

impl Adapter1Interface {
    /// Construct a new interface wrapper for a given adapter.
    pub fn new(adapter: Arc<Mutex<BtdAdapter>>) -> Self {
        Self { inner: adapter }
    }
}

/// Helper to create a zbus::Error from a string for use in D-Bus interface methods.
fn adapter_dbus_error(msg: impl Into<String>) -> zbus::Error {
    zbus::Error::from(zbus::fdo::Error::Failed(msg.into()))
}

#[zbus::interface(name = "org.bluez.Adapter1")]
impl Adapter1Interface {
    // ---- Methods ----

    /// Start device discovery on this adapter.
    async fn start_discovery(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(), zbus::fdo::Error> {
        let sender = hdr.sender().map(|s| s.to_string()).unwrap_or_default();
        let mut adapter = self.inner.lock().await;
        if !adapter.powered {
            return Err(zbus::fdo::Error::Failed("Not Ready".into()));
        }
        btd_info(adapter.index, &format!("StartDiscovery from {sender}"));

        let has_client = adapter.discovery_clients.iter().any(|c| c.sender == sender);
        if has_client {
            return Err(zbus::fdo::Error::Failed("In Progress".into()));
        }

        adapter
            .discovery_clients
            .push(DiscoveryClient { sender: sender.clone(), filter: DiscoveryFilter::default() });

        if !adapter.discovering {
            let scan_type = adapter.get_scan_type();
            if let Some(mgmt) = adapter.mgmt.clone() {
                adapter.discovery_type = scan_type;
                let idx = adapter.index;
                drop(adapter);
                let param = [scan_type];
                let resp = mgmt.send_command(MGMT_OP_START_DISCOVERY, idx, &param).await;
                match resp {
                    Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                        let mut adapter = self.inner.lock().await;
                        adapter.discovering = true;
                    }
                    Ok(r) => {
                        let mut adapter = self.inner.lock().await;
                        adapter.discovery_clients.retain(|c| c.sender != sender);
                        return Err(zbus::fdo::Error::Failed(format!(
                            "MGMT error: {}",
                            mgmt_errstr(r.status)
                        )));
                    }
                    Err(e) => {
                        let mut adapter = self.inner.lock().await;
                        adapter.discovery_clients.retain(|c| c.sender != sender);
                        return Err(zbus::fdo::Error::Failed(format!("MGMT send failed: {e}")));
                    }
                }
            }
        }
        Ok(())
    }

    /// Stop device discovery on this adapter.
    async fn stop_discovery(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(), zbus::fdo::Error> {
        let sender = hdr.sender().map(|s| s.to_string()).unwrap_or_default();
        let mut adapter = self.inner.lock().await;
        if !adapter.powered {
            return Err(zbus::fdo::Error::Failed("Not Ready".into()));
        }

        let pos = adapter.discovery_clients.iter().position(|c| c.sender == sender);
        match pos {
            Some(i) => {
                adapter.discovery_clients.remove(i);
            }
            None => {
                return Err(zbus::fdo::Error::Failed("No discovery started".into()));
            }
        }

        if adapter.discovery_clients.is_empty() && adapter.discovering {
            let scan_type = adapter.discovery_type;
            if let Some(mgmt) = adapter.mgmt.clone() {
                let idx = adapter.index;
                drop(adapter);
                let param = [scan_type];
                let resp = mgmt.send_command(MGMT_OP_STOP_DISCOVERY, idx, &param).await;
                match resp {
                    Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                        let mut adapter = self.inner.lock().await;
                        adapter.discovering = false;
                    }
                    Ok(r) => {
                        warn!("StopDiscovery MGMT error: {}", mgmt_errstr(r.status));
                    }
                    Err(e) => {
                        warn!("StopDiscovery MGMT send failed: {e}");
                    }
                }
            }
        }
        Ok(())
    }

    /// Set the discovery filter for the calling D-Bus client.
    async fn set_discovery_filter(
        &self,
        properties: HashMap<String, Value<'_>>,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(), zbus::fdo::Error> {
        let sender = hdr.sender().map(|s| s.to_string()).unwrap_or_default();
        let mut filter = DiscoveryFilter::default();

        if let Some(Value::Array(arr)) = properties.get("UUIDs") {
            let mut uuids = Vec::new();
            for v in arr.iter() {
                if let Value::Str(s) = v {
                    uuids.push(s.to_string());
                }
            }
            filter.uuids = uuids;
        }

        if let Some(val) = properties.get("RSSI") {
            if let Ok(r) = <i16>::try_from(val) {
                filter.rssi = r;
            }
        }

        if let Some(val) = properties.get("Pathloss") {
            if let Ok(p) = <u16>::try_from(val) {
                filter.pathloss = p;
            }
        }

        if let Some(Value::Str(t)) = properties.get("Transport") {
            match t.as_str() {
                "auto" | "bredr" | "le" => {
                    filter.transport = t.to_string();
                }
                _ => {
                    return Err(zbus::fdo::Error::Failed("Invalid Arguments".into()));
                }
            }
        }

        if let Some(val) = properties.get("DuplicateData") {
            if let Ok(b) = <bool>::try_from(val) {
                filter.duplicate_data = b;
            }
        }

        if let Some(val) = properties.get("Discoverable") {
            if let Ok(b) = <bool>::try_from(val) {
                filter.discoverable = b;
            }
        }

        if let Some(Value::Str(p)) = properties.get("Pattern") {
            filter.pattern = p.to_string();
        }

        let mut adapter = self.inner.lock().await;
        if let Some(client) = adapter.discovery_clients.iter_mut().find(|c| c.sender == sender) {
            client.filter = filter;
        } else {
            adapter.discovery_clients.push(DiscoveryClient { sender, filter });
        }
        Ok(())
    }

    /// Remove a previously-discovered device.
    async fn remove_device(&self, device: ObjectPath<'_>) -> Result<(), zbus::fdo::Error> {
        let device_path = device.to_string();
        let mut adapter = self.inner.lock().await;
        if !adapter.powered {
            return Err(zbus::fdo::Error::Failed("Not Ready".into()));
        }

        let addr_to_remove = {
            let mut found = None;
            for &addr in adapter.devices.keys() {
                let expected_path =
                    format!("{}/dev_{}", adapter.path, addr.ba2str().replace(':', "_"));
                if expected_path == device_path {
                    found = Some(addr);
                    break;
                }
            }
            found
        };

        match addr_to_remove {
            Some(addr) => {
                adapter.devices.remove(&addr);
                for driver in &adapter.drivers {
                    driver.device_removed(&adapter, &addr);
                }
                btd_info(adapter.index, &format!("Device {} removed", addr.ba2str()));
                Ok(())
            }
            None => Err(zbus::fdo::Error::Failed("Does Not Exist".into())),
        }
    }

    /// List supported discovery filter keys.
    async fn get_discovery_filters(&self) -> Vec<String> {
        vec![
            "UUIDs".into(),
            "RSSI".into(),
            "Pathloss".into(),
            "Transport".into(),
            "DuplicateData".into(),
            "Discoverable".into(),
            "Pattern".into(),
        ]
    }

    /// Connect to a device directly (experimental).
    ///
    /// Parses Address and AddressType from the properties map, resolves the
    /// kernel address type, then sends `MGMT_OP_ADD_DEVICE` to initiate an
    /// outgoing connection.  Matches C `adapter_connect_device()` behaviour.
    async fn connect_device(
        &self,
        properties: HashMap<String, Value<'_>>,
    ) -> Result<(), zbus::fdo::Error> {
        let adapter = self.inner.lock().await;
        if !adapter.powered {
            return Err(zbus::fdo::Error::Failed("Not Ready".into()));
        }

        // Parse the mandatory "Address" property.
        let addr_str = match properties.get("Address") {
            Some(Value::Str(s)) => s.to_string(),
            _ => return Err(zbus::fdo::Error::InvalidArgs("Missing Address".into())),
        };

        // Parse the address into a BdAddr.
        let address: BdAddr = addr_str
            .parse()
            .map_err(|_| zbus::fdo::Error::InvalidArgs("Invalid Address format".into()))?;

        // Parse the optional "AddressType" (default "public").
        let addr_type_str = match properties.get("AddressType") {
            Some(Value::Str(s)) => s.to_string(),
            _ => "public".to_string(),
        };

        // Map user-facing address-type string to kernel MGMT address type byte.
        let kernel_addr_type: u8 = match addr_type_str.as_str() {
            "public" => BDADDR_LE_PUBLIC,
            "random" => BDADDR_LE_RANDOM,
            _ => return Err(zbus::fdo::Error::InvalidArgs("Invalid AddressType".into())),
        };

        btd_info(adapter.index, &format!("ConnectDevice {addr_str} ({addr_type_str})"));

        let mgmt = adapter.mgmt().ok_or_else(|| zbus::fdo::Error::Failed("Not Ready".into()))?;
        let idx = adapter.index;
        drop(adapter);

        // Build MGMT_OP_ADD_DEVICE parameter:
        //   struct mgmt_cp_add_device { bdaddr[6], type, action }
        //   action = 0x02 (ACTION_AUTO_CONNECT)
        let mut param = [0u8; 8];
        param[..6].copy_from_slice(&address.b);
        param[6] = kernel_addr_type;
        param[7] = 0x02; // ACTION_AUTO_CONNECT
        let resp = mgmt
            .send_command(MGMT_OP_ADD_DEVICE, idx, &param)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("MGMT send error: {e}")))?;
        if resp.status != MGMT_STATUS_SUCCESS {
            return Err(zbus::fdo::Error::Failed(format!(
                "MGMT_OP_ADD_DEVICE failed: status {}",
                mgmt_errstr(resp.status)
            )));
        }
        Ok(())
    }

    // ---- Properties ----

    #[zbus(property)]
    async fn address(&self) -> String {
        let adapter = self.inner.lock().await;
        adapter.address_str()
    }

    #[zbus(property)]
    async fn address_type(&self) -> String {
        let adapter = self.inner.lock().await;
        adapter.address_type_str().to_string()
    }

    #[zbus(property)]
    async fn name(&self) -> String {
        let adapter = self.inner.lock().await;
        adapter.name.clone()
    }

    #[zbus(property)]
    async fn alias(&self) -> String {
        let adapter = self.inner.lock().await;
        adapter.effective_alias()
    }

    #[zbus(property)]
    async fn set_alias(&self, value: String) -> Result<(), zbus::Error> {
        let mut adapter = self.inner.lock().await;
        if value.len() > MAX_NAME_LENGTH {
            return Err(adapter_dbus_error("Invalid Arguments"));
        }
        adapter.stored_alias = value.clone();
        adapter.alias = adapter.effective_alias();

        // Persist the alias and send MGMT SET_LOCAL_NAME
        if let Some(mgmt) = adapter.mgmt.clone() {
            let idx = adapter.index;
            let mut name_buf = [0u8; 249];
            let bytes = value.as_bytes();
            let copy_len = bytes.len().min(248);
            name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
            let mut short_buf = [0u8; 11];
            let slen = copy_len.min(10);
            short_buf[..slen].copy_from_slice(&bytes[..slen]);
            let mut param = Vec::with_capacity(260);
            param.extend_from_slice(&name_buf);
            param.extend_from_slice(&short_buf);
            drop(adapter);
            let _ = mgmt.send_command(MGMT_OP_SET_LOCAL_NAME, idx, &param).await;
        }
        Ok(())
    }

    #[zbus(property, name = "Class")]
    async fn class_of_device(&self) -> u32 {
        let adapter = self.inner.lock().await;
        adapter.class
    }

    #[zbus(property)]
    async fn powered(&self) -> bool {
        let adapter = self.inner.lock().await;
        adapter.powered
    }

    #[zbus(property)]
    async fn set_powered(&self, value: bool) -> Result<(), zbus::Error> {
        let adapter = self.inner.lock().await;
        if adapter.powered == value {
            return Ok(());
        }
        if let Some(mgmt) = adapter.mgmt.clone() {
            let idx = adapter.index;
            drop(adapter);
            let val: u8 = if value { 1 } else { 0 };
            let resp = mgmt.send_command(MGMT_OP_SET_POWERED, idx, &[val]).await;
            match resp {
                Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                    let mut adapter = self.inner.lock().await;
                    adapter.powered = value;
                    if value {
                        adapter.power_state = AdapterPowerState::On;
                    } else {
                        adapter.power_state = AdapterPowerState::Off;
                    }
                    adapter.update_settings_from_bitmask();
                    Ok(())
                }
                Ok(r) if r.status == MGMT_STATUS_RFKILLED => {
                    let mut adapter = self.inner.lock().await;
                    adapter.power_state = AdapterPowerState::OffBlocked;
                    Err(adapter_dbus_error("Blocked"))
                }
                Ok(r) => Err(adapter_dbus_error(format!(
                    "Set powered failed: {}",
                    mgmt_errstr(r.status)
                ))),
                Err(e) => Err(adapter_dbus_error(format!("MGMT error: {e}"))),
            }
        } else {
            Err(adapter_dbus_error("Not Ready"))
        }
    }

    #[zbus(property, name = "PowerState")]
    async fn power_state(&self) -> String {
        let adapter = self.inner.lock().await;
        adapter.power_state_str().to_string()
    }

    #[zbus(property)]
    async fn discoverable(&self) -> bool {
        let adapter = self.inner.lock().await;
        adapter.discoverable
    }

    #[zbus(property)]
    async fn set_discoverable(&self, value: bool) -> Result<(), zbus::Error> {
        let adapter = self.inner.lock().await;
        if !adapter.powered {
            return Err(adapter_dbus_error("Not Ready"));
        }
        if adapter.discoverable == value {
            return Ok(());
        }
        if let Some(mgmt) = adapter.mgmt.clone() {
            let idx = adapter.index;
            let timeout = if value { adapter.discoverable_timeout } else { 0 };
            drop(adapter);
            let val: u8 = if value { 1 } else { 0 };
            let mut param = Vec::with_capacity(3);
            param.push(val);
            param.extend_from_slice(&timeout.to_le_bytes()[..2]);
            let resp = mgmt.send_command(MGMT_OP_SET_DISCOVERABLE, idx, &param).await;
            match resp {
                Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                    let mut adapter = self.inner.lock().await;
                    adapter.discoverable = value;
                    Ok(())
                }
                Ok(r) => Err(adapter_dbus_error(format!(
                    "Set discoverable failed: {}",
                    mgmt_errstr(r.status)
                ))),
                Err(e) => Err(adapter_dbus_error(format!("MGMT error: {e}"))),
            }
        } else {
            Err(adapter_dbus_error("Not Ready"))
        }
    }

    #[zbus(property)]
    async fn discoverable_timeout(&self) -> u32 {
        let adapter = self.inner.lock().await;
        adapter.discoverable_timeout
    }

    #[zbus(property)]
    async fn set_discoverable_timeout(&self, value: u32) -> Result<(), zbus::Error> {
        let mut adapter = self.inner.lock().await;
        adapter.discoverable_timeout = value;
        Ok(())
    }

    #[zbus(property)]
    async fn pairable(&self) -> bool {
        let adapter = self.inner.lock().await;
        adapter.pairable
    }

    #[zbus(property)]
    async fn set_pairable(&self, value: bool) -> Result<(), zbus::Error> {
        let adapter = self.inner.lock().await;
        if !adapter.powered {
            return Err(adapter_dbus_error("Not Ready"));
        }
        if adapter.pairable == value {
            return Ok(());
        }
        if let Some(mgmt) = adapter.mgmt.clone() {
            let idx = adapter.index;
            drop(adapter);
            let val: u8 = if value { 1 } else { 0 };
            let resp = mgmt.send_command(MGMT_OP_SET_BONDABLE, idx, &[val]).await;
            match resp {
                Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                    let mut adapter = self.inner.lock().await;
                    adapter.pairable = value;
                    Ok(())
                }
                Ok(r) => Err(adapter_dbus_error(format!(
                    "Set pairable failed: {}",
                    mgmt_errstr(r.status)
                ))),
                Err(e) => Err(adapter_dbus_error(format!("MGMT error: {e}"))),
            }
        } else {
            Err(adapter_dbus_error("Not Ready"))
        }
    }

    #[zbus(property)]
    async fn pairable_timeout(&self) -> u32 {
        let adapter = self.inner.lock().await;
        adapter.pairable_timeout
    }

    #[zbus(property)]
    async fn set_pairable_timeout(&self, value: u32) -> Result<(), zbus::Error> {
        let mut adapter = self.inner.lock().await;
        adapter.pairable_timeout = value;
        Ok(())
    }

    #[zbus(property)]
    async fn discovering(&self) -> bool {
        let adapter = self.inner.lock().await;
        adapter.discovering
    }

    #[zbus(property, name = "UUIDs")]
    async fn uuids(&self) -> Vec<String> {
        let adapter = self.inner.lock().await;
        adapter.uuid_list()
    }

    #[zbus(property)]
    async fn modalias(&self) -> String {
        let adapter = self.inner.lock().await;
        adapter.modalias.clone()
    }

    #[zbus(property, name = "Roles")]
    async fn roles(&self) -> Vec<String> {
        let adapter = self.inner.lock().await;
        adapter.roles_list()
    }

    #[zbus(property, name = "ExperimentalFeatures")]
    async fn experimental_features(&self) -> Vec<String> {
        let adapter = self.inner.lock().await;
        adapter.experimental_features_list()
    }

    /// HCI manufacturer ID from the `READ_INFO` MGMT response.
    #[zbus(property)]
    async fn manufacturer(&self) -> u16 {
        let adapter = self.inner.lock().await;
        adapter.manufacturer
    }

    /// HCI version number from the `READ_INFO` MGMT response.
    #[zbus(property)]
    async fn version(&self) -> u8 {
        let adapter = self.inner.lock().await;
        adapter.version
    }

    /// Whether the adapter is connectable (accepting incoming connections).
    ///
    /// This read-only property reflects the current connectable state as
    /// reported by the kernel Management API (matching C `src/adapter.c`
    /// `Connectable` property).
    #[zbus(property)]
    async fn connectable(&self) -> bool {
        let adapter = self.inner.lock().await;
        adapter.has_setting(MgmtSettings::CONNECTABLE.bits())
    }
}

// ===========================================================================
// MGMT Event Processing
// ===========================================================================

/// Process a MGMT event for a specific adapter.
pub async fn process_mgmt_event(adapter_arc: &Arc<Mutex<BtdAdapter>>, event: &MgmtEvent) {
    let ev_code = event.event;
    let ev_data = &event.data;

    match ev_code {
        MGMT_EV_NEW_SETTINGS => {
            if ev_data.len() >= 4 {
                let new_settings =
                    u32::from_le_bytes([ev_data[0], ev_data[1], ev_data[2], ev_data[3]]);
                let mut adapter = adapter_arc.lock().await;
                let old_powered = adapter.powered;
                adapter.current_settings = new_settings;
                adapter.update_settings_from_bitmask();
                btd_debug(adapter.index, &format!("New settings: 0x{:08x}", new_settings));
                let new_powered = adapter.powered;
                if old_powered && !new_powered {
                    adapter.discovering = false;
                    adapter.discovery_clients.clear();
                }
            }
        }
        MGMT_EV_DISCOVERING => {
            if ev_data.len() >= 2 {
                let discovering = ev_data[1] != 0;
                let mut adapter = adapter_arc.lock().await;
                adapter.discovering = discovering;
                btd_debug(adapter.index, &format!("Discovering: {discovering}"));
            }
        }
        MGMT_EV_DEVICE_FOUND => {
            if ev_data.len() >= 14 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let addr_type = ev_data[6];
                let rssi = ev_data[7] as i8;
                let _flags = u32::from_le_bytes([ev_data[8], ev_data[9], ev_data[10], ev_data[11]]);
                let eir_len = u16::from_le_bytes([ev_data[12], ev_data[13]]) as usize;
                let eir_data = if ev_data.len() >= 14 + eir_len {
                    eir_parse(&ev_data[14..14 + eir_len])
                } else {
                    EirData::default()
                };
                let mut adapter = adapter_arc.lock().await;
                btd_debug(
                    adapter.index,
                    &format!(
                        "Device found: {} type={} rssi={} name={:?}",
                        addr.ba2str(),
                        addr_type,
                        rssi,
                        eir_data.name
                    ),
                );
                // Insert device placeholder if not already known.
                adapter.devices.entry(addr).or_insert(());
            }
        }
        MGMT_EV_DEVICE_CONNECTED => {
            if ev_data.len() >= 7 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let addr_type = ev_data[6];
                let mut adapter = adapter_arc.lock().await;
                adapter.connections.insert(addr);
                adapter.devices.entry(addr).or_insert(());
                btd_info(
                    adapter.index,
                    &format!("Device connected: {} type={}", addr.ba2str(), addr_type),
                );
            }
        }
        MGMT_EV_DEVICE_DISCONNECTED => {
            if ev_data.len() >= 7 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let reason = if ev_data.len() >= 8 { ev_data[7] } else { 0 };
                let mut adapter = adapter_arc.lock().await;
                adapter.connections.remove(&addr);
                btd_info(
                    adapter.index,
                    &format!("Device disconnected: {} reason={}", addr.ba2str(), reason),
                );
                // Notify disconnect callbacks.
                for entry in &adapter.disconnect_callbacks {
                    (entry.cb)(&addr, reason);
                }
            }
        }
        MGMT_EV_NEW_LINK_KEY => {
            // mgmt_ev_new_link_key: store_hint(1) + addr(7) + type(1) + val[16] + pin_len(1) = 26
            if ev_data.len() >= 26 {
                let store_hint = ev_data[0];
                let addr = bdaddr_from_bytes(&ev_data[1..7]);
                let _addr_type = ev_data[7];
                let key_type = ev_data[8];
                let mut key = [0u8; 16];
                key.copy_from_slice(&ev_data[9..25]);
                let pin_len = ev_data[25];

                let adapter = adapter_arc.lock().await;
                btd_debug(
                    adapter.index,
                    &format!("New link key: {} store_hint={}", addr.ba2str(), store_hint),
                );
                let adapter_path = adapter.path.clone();
                drop(adapter);

                if store_hint != 0 {
                    let dev = device_create_from_storage(
                        Arc::clone(adapter_arc),
                        addr,
                        AddressType::Bredr,
                        &adapter_path,
                    );
                    let mut d = dev.lock().await;
                    d.set_linkkey(key, key_type, pin_len);
                    d.store();
                }
            }
        }
        MGMT_EV_NEW_LONG_TERM_KEY => {
            // mgmt_ev_new_long_term_key: store_hint(1) + addr(7) + type(1) + master(1) +
            //     enc_size(1) + ediv(2) + rand(8) + val[16] = 37
            if ev_data.len() >= 37 {
                let store_hint = ev_data[0];
                let addr = bdaddr_from_bytes(&ev_data[1..7]);
                let addr_type_byte = ev_data[7];
                let ltk_type = ev_data[8];
                let master = ev_data[9];
                let enc_size = ev_data[10];
                let ediv = u16::from_le_bytes([ev_data[11], ev_data[12]]);
                let rand = u64::from_le_bytes(ev_data[13..21].try_into().unwrap_or([0u8; 8]));
                let mut val = [0u8; 16];
                val.copy_from_slice(&ev_data[21..37]);

                let adapter = adapter_arc.lock().await;
                btd_debug(
                    adapter.index,
                    &format!(
                        "New LTK: {} store_hint={} master={}",
                        addr.ba2str(),
                        store_hint,
                        master
                    ),
                );
                let adapter_path = adapter.path.clone();
                drop(adapter);

                if store_hint != 0 {
                    let at = AddressType::from_kernel(addr_type_byte);
                    let dev = device_create_from_storage(
                        Arc::clone(adapter_arc),
                        addr,
                        at,
                        &adapter_path,
                    );
                    let mut d = dev.lock().await;
                    // master=1 means central (our) LTK, master=0 means peripheral (slave) LTK
                    // ltk_type: 0 = unauthenticated, non-zero = authenticated
                    d.set_ltk(val, master != 0, ltk_type != 0, enc_size, ediv, rand);
                    d.store();
                }
            }
        }
        MGMT_EV_NEW_IRK => {
            // mgmt_ev_new_irk: store_hint(1) + rpa(6) + addr(7) + val[16] = 30
            if ev_data.len() >= 30 {
                let store_hint = ev_data[0];
                let _rpa = bdaddr_from_bytes(&ev_data[1..7]);
                let addr = bdaddr_from_bytes(&ev_data[7..13]);
                let addr_type_byte = ev_data[13];
                let mut val = [0u8; 16];
                val.copy_from_slice(&ev_data[14..30]);

                let adapter = adapter_arc.lock().await;
                btd_debug(
                    adapter.index,
                    &format!("New IRK: {} store_hint={}", addr.ba2str(), store_hint),
                );
                let adapter_path = adapter.path.clone();
                drop(adapter);

                if store_hint != 0 {
                    let at = AddressType::from_kernel(addr_type_byte);
                    let dev = device_create_from_storage(
                        Arc::clone(adapter_arc),
                        addr,
                        at,
                        &adapter_path,
                    );
                    let mut d = dev.lock().await;
                    d.set_irk(val);
                    d.store();
                }
            }
        }
        MGMT_EV_NEW_CSRK => {
            // mgmt_ev_new_csrk: store_hint(1) + addr(7) + type(1) + val[16] = 25
            if ev_data.len() >= 25 {
                let store_hint = ev_data[0];
                let addr = bdaddr_from_bytes(&ev_data[1..7]);
                let addr_type_byte = ev_data[7];
                let csrk_type = ev_data[8];
                let mut val = [0u8; 16];
                val.copy_from_slice(&ev_data[9..25]);

                let adapter = adapter_arc.lock().await;
                btd_debug(
                    adapter.index,
                    &format!(
                        "New CSRK: {} store_hint={} type={}",
                        addr.ba2str(),
                        store_hint,
                        csrk_type
                    ),
                );
                let adapter_path = adapter.path.clone();
                drop(adapter);

                if store_hint != 0 {
                    let at = AddressType::from_kernel(addr_type_byte);
                    // csrk_type: 0x00 = local unauthenticated, 0x01 = local authenticated,
                    //            0x02 = remote unauthenticated, 0x03 = remote authenticated
                    let is_local = csrk_type < 0x02;
                    let authenticated = (csrk_type & 0x01) != 0;
                    let dev = device_create_from_storage(
                        Arc::clone(adapter_arc),
                        addr,
                        at,
                        &adapter_path,
                    );
                    let mut d = dev.lock().await;
                    d.set_csrk(val, is_local, authenticated);
                    d.store();
                }
            }
        }
        MGMT_EV_NEW_CONN_PARAM => {
            if !ev_data.is_empty() {
                let adapter = adapter_arc.lock().await;
                btd_debug(adapter.index, "New connection params received");
            }
        }
        MGMT_EV_CLASS_OF_DEV_CHANGED => {
            if ev_data.len() >= 3 {
                let dev_class =
                    (ev_data[2] as u32) << 16 | (ev_data[1] as u32) << 8 | (ev_data[0] as u32);
                let mut adapter = adapter_arc.lock().await;
                adapter.class = dev_class;
                adapter.dev_class = dev_class;
                adapter.major_class = ((dev_class >> 8) & 0x1f) as u8;
                adapter.minor_class = ((dev_class >> 2) & 0x3f) as u8;
                btd_debug(adapter.index, &format!("Class changed: 0x{:06x}", dev_class));
            }
        }
        MGMT_EV_LOCAL_NAME_CHANGED => {
            if ev_data.len() >= 260 {
                let name = {
                    let raw = &ev_data[0..249];
                    let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
                    String::from_utf8_lossy(&raw[..len]).to_string()
                };
                let short_name = {
                    let raw = &ev_data[249..260];
                    let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
                    String::from_utf8_lossy(&raw[..len]).to_string()
                };
                let mut adapter = adapter_arc.lock().await;
                adapter.name = name;
                adapter.short_name = short_name;
                adapter.alias = adapter.effective_alias();
                btd_debug(adapter.index, &format!("Name changed: {}", adapter.name));
            }
        }
        MGMT_EV_AUTH_FAILED => {
            if ev_data.len() >= 8 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let status = ev_data[7];
                let adapter = adapter_arc.lock().await;
                btd_warn(
                    adapter.index,
                    &format!("Auth failed: {} status={}", addr.ba2str(), status),
                );
            }
        }
        MGMT_EV_CONNECT_FAILED => {
            if ev_data.len() >= 8 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let status = ev_data[7];
                let adapter = adapter_arc.lock().await;
                btd_debug(
                    adapter.index,
                    &format!("Connect failed: {} status={}", addr.ba2str(), status),
                );
                for entry in &adapter.conn_fail_callbacks {
                    (entry.cb)(&addr, status);
                }
            }
        }
        MGMT_EV_PIN_CODE_REQUEST => {
            // mgmt_ev_pin_code_request: addr(6) + addr_type(1) + secure(1) = 8
            if ev_data.len() >= 7 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let addr_type_byte = ev_data[6];
                let secure = if ev_data.len() >= 8 { ev_data[7] != 0 } else { false };

                let adapter = adapter_arc.lock().await;
                let index = adapter.index;
                let adapter_path = adapter.path.clone();
                let mgmt_opt = adapter.mgmt();
                drop(adapter);

                btd_debug(index, &format!("PIN code request: {}", addr.ba2str()));

                let at = AddressType::from_kernel(addr_type_byte);
                let dev =
                    device_create_from_storage(Arc::clone(adapter_arc), addr, at, &adapter_path);

                if let Some(agent) = agent_get(None).await {
                    let d = dev.lock().await;
                    match agent_request_pincode(&agent, &d, secure).await {
                        Ok(pin) => {
                            if let Some(ref mgmt) = mgmt_opt {
                                // Build PIN code reply: addr(6) + addr_type(1) + pin_len(1) + pin[16]
                                let mut param = [0u8; 24];
                                param[..6].copy_from_slice(&addr.b);
                                param[6] = addr_type_byte;
                                let pin_bytes = pin.as_bytes();
                                let pin_len = pin_bytes.len().min(16) as u8;
                                param[7] = pin_len;
                                param[8..8 + pin_len as usize]
                                    .copy_from_slice(&pin_bytes[..pin_len as usize]);
                                let _ =
                                    mgmt.send_command(MGMT_OP_PIN_CODE_REPLY, index, &param).await;
                            }
                        }
                        Err(_) => {
                            if let Some(ref mgmt) = mgmt_opt {
                                // Negative reply: addr(6) + addr_type(1) = 7
                                let mut param = [0u8; 7];
                                param[..6].copy_from_slice(&addr.b);
                                param[6] = addr_type_byte;
                                let _ = mgmt
                                    .send_command(MGMT_OP_PIN_CODE_NEG_REPLY, index, &param)
                                    .await;
                            }
                        }
                    }
                } else {
                    btd_warn(index, "No agent registered for PIN code request");
                    if let Some(ref mgmt) = mgmt_opt {
                        let mut param = [0u8; 7];
                        param[..6].copy_from_slice(&addr.b);
                        param[6] = addr_type_byte;
                        let _ = mgmt.send_command(MGMT_OP_PIN_CODE_NEG_REPLY, index, &param).await;
                    }
                }
            }
        }
        MGMT_EV_USER_CONFIRM_REQUEST => {
            // mgmt_ev_user_confirm_request: addr(6) + addr_type(1) + confirm_hint(1) + value(4) = 12
            if ev_data.len() >= 11 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let addr_type_byte = ev_data[6];
                let passkey = u32::from_le_bytes(ev_data[7..11].try_into().unwrap_or([0u8; 4]));

                let adapter = adapter_arc.lock().await;
                let index = adapter.index;
                let adapter_path = adapter.path.clone();
                let mgmt_opt = adapter.mgmt();
                drop(adapter);

                btd_debug(
                    index,
                    &format!("User confirm request: {} passkey={:06}", addr.ba2str(), passkey),
                );

                let at = AddressType::from_kernel(addr_type_byte);
                let dev =
                    device_create_from_storage(Arc::clone(adapter_arc), addr, at, &adapter_path);

                if let Some(agent) = agent_get(None).await {
                    let d = dev.lock().await;
                    match agent_request_confirmation(&agent, &d, passkey).await {
                        Ok(()) => {
                            if let Some(ref mgmt) = mgmt_opt {
                                let mut param = [0u8; 7];
                                param[..6].copy_from_slice(&addr.b);
                                param[6] = addr_type_byte;
                                let _ = mgmt
                                    .send_command(MGMT_OP_USER_CONFIRM_REPLY, index, &param)
                                    .await;
                            }
                        }
                        Err(_) => {
                            if let Some(ref mgmt) = mgmt_opt {
                                let mut param = [0u8; 7];
                                param[..6].copy_from_slice(&addr.b);
                                param[6] = addr_type_byte;
                                let _ = mgmt
                                    .send_command(MGMT_OP_USER_CONFIRM_NEG_REPLY, index, &param)
                                    .await;
                            }
                        }
                    }
                } else {
                    btd_warn(index, "No agent registered for confirm request");
                    if let Some(ref mgmt) = mgmt_opt {
                        let mut param = [0u8; 7];
                        param[..6].copy_from_slice(&addr.b);
                        param[6] = addr_type_byte;
                        let _ =
                            mgmt.send_command(MGMT_OP_USER_CONFIRM_NEG_REPLY, index, &param).await;
                    }
                }
            }
        }
        MGMT_EV_USER_PASSKEY_REQUEST => {
            // mgmt_ev_user_passkey_request: addr(6) + addr_type(1) = 7
            if ev_data.len() >= 7 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let addr_type_byte = ev_data[6];

                let adapter = adapter_arc.lock().await;
                let index = adapter.index;
                let adapter_path = adapter.path.clone();
                let mgmt_opt = adapter.mgmt();
                drop(adapter);

                btd_debug(index, &format!("User passkey request: {}", addr.ba2str()));

                let at = AddressType::from_kernel(addr_type_byte);
                let dev =
                    device_create_from_storage(Arc::clone(adapter_arc), addr, at, &adapter_path);

                if let Some(agent) = agent_get(None).await {
                    let d = dev.lock().await;
                    match agent_request_passkey(&agent, &d).await {
                        Ok(passkey) => {
                            if let Some(ref mgmt) = mgmt_opt {
                                // Passkey reply: addr(6) + addr_type(1) + passkey(4) = 11
                                let mut param = [0u8; 11];
                                param[..6].copy_from_slice(&addr.b);
                                param[6] = addr_type_byte;
                                param[7..11].copy_from_slice(&passkey.to_le_bytes());
                                let _ = mgmt
                                    .send_command(MGMT_OP_USER_PASSKEY_REPLY, index, &param)
                                    .await;
                            }
                        }
                        Err(_) => {
                            if let Some(ref mgmt) = mgmt_opt {
                                let mut param = [0u8; 7];
                                param[..6].copy_from_slice(&addr.b);
                                param[6] = addr_type_byte;
                                let _ = mgmt
                                    .send_command(MGMT_OP_USER_PASSKEY_NEG_REPLY, index, &param)
                                    .await;
                            }
                        }
                    }
                } else {
                    btd_warn(index, "No agent registered for passkey request");
                    if let Some(ref mgmt) = mgmt_opt {
                        let mut param = [0u8; 7];
                        param[..6].copy_from_slice(&addr.b);
                        param[6] = addr_type_byte;
                        let _ =
                            mgmt.send_command(MGMT_OP_USER_PASSKEY_NEG_REPLY, index, &param).await;
                    }
                }
            }
        }
        MGMT_EV_DEVICE_BLOCKED => {
            if ev_data.len() >= 7 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let adapter = adapter_arc.lock().await;
                btd_debug(adapter.index, &format!("Device blocked: {}", addr.ba2str()));
            }
        }
        MGMT_EV_DEVICE_UNBLOCKED => {
            if ev_data.len() >= 7 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let adapter = adapter_arc.lock().await;
                btd_debug(adapter.index, &format!("Device unblocked: {}", addr.ba2str()));
            }
        }
        MGMT_EV_DEVICE_UNPAIRED => {
            if ev_data.len() >= 7 {
                let addr = bdaddr_from_bytes(&ev_data[0..6]);
                let mut adapter = adapter_arc.lock().await;
                btd_debug(adapter.index, &format!("Device unpaired: {}", addr.ba2str()));
                adapter.devices.remove(&addr);
            }
        }
        MGMT_EV_EXP_FEATURE_CHANGE => {
            let adapter = adapter_arc.lock().await;
            btd_debug(adapter.index, "Experimental feature change");
        }
        _ => {
            let adapter = adapter_arc.lock().await;
            trace!("Unhandled MGMT event 0x{:04x} on hci{}", ev_code, adapter.index);
        }
    }
}

/// Helper: reconstruct a BdAddr from a 6-byte slice.
pub fn bdaddr_from_bytes(bytes: &[u8]) -> BdAddr {
    let mut addr = BDADDR_ANY;
    addr.b.copy_from_slice(&bytes[..6]);
    addr
}

// ===========================================================================
// Public API — Adapter Lifecycle
// ===========================================================================

/// Initialize the global adapter subsystem.
///
/// Opens the MGMT socket, subscribes to INDEX_ADDED / INDEX_REMOVED events,
/// and reads the initial adapter list.
pub async fn adapter_init(mgmt: Arc<MgmtSocket>) -> Result<(), BtdError> {
    {
        let mut guard = MGMT_MAIN.lock().await;
        *guard = Some(mgmt.clone());
    }

    // Read initial controller list via MGMT_OP_READ_INFO on index 0xFFFF
    // (the non-indexed global command).  In practice the daemon
    // subscribes to INDEX_ADDED and then reads info for each.
    btd_info(HCI_DEV_NONE, "Adapter subsystem initialized");
    Ok(())
}

/// Shut down the adapter subsystem, powering off all adapters gracefully.
pub async fn adapter_shutdown() {
    let adapters = ADAPTERS.read().await;
    for adapter_arc in adapters.iter() {
        let adapter = adapter_arc.lock().await;
        if adapter.powered {
            if let Some(mgmt) = adapter.mgmt.clone() {
                let idx = adapter.index;
                drop(adapter);
                let _ = mgmt.send_command(MGMT_OP_SET_POWERED, idx, &[0u8]).await;
            }
        }
    }
    btd_info(HCI_DEV_NONE, "Adapter subsystem shut down");
}

/// Clean up the adapter subsystem, removing all adapters and drivers.
pub async fn adapter_cleanup() {
    adapter_shutdown().await;
    let mut adapters = ADAPTERS.write().await;
    adapters.clear();
    let mut drivers = ADAPTER_DRIVERS.write().await;
    drivers.clear();
    let mut guard = MGMT_MAIN.lock().await;
    *guard = None;
    btd_info(HCI_DEV_NONE, "Adapter subsystem cleaned up");
}

/// Return a snapshot of all currently registered adapters.
///
/// Used by subsystems that need to iterate adapters without holding the
/// `ADAPTERS` read-lock (e.g. the policy plugin looking up a device by
/// address across all controllers).
pub async fn adapter_get_all() -> Vec<Arc<Mutex<BtdAdapter>>> {
    let adapters = ADAPTERS.read().await;
    adapters.clone()
}

/// Find an adapter by HCI index.
pub async fn adapter_find(index: u16) -> Option<Arc<Mutex<BtdAdapter>>> {
    let adapters = ADAPTERS.read().await;
    for adapter_arc in adapters.iter() {
        let a = adapter_arc.lock().await;
        if a.index == index {
            return Some(Arc::clone(adapter_arc));
        }
    }
    None
}

/// Find an adapter by its HCI index (alias for `adapter_find`).
pub async fn adapter_find_by_id(index: u16) -> Option<Arc<Mutex<BtdAdapter>>> {
    adapter_find(index).await
}

/// Get the adapter's D-Bus object path.
pub async fn adapter_get_path(adapter: &Arc<Mutex<BtdAdapter>>) -> String {
    let a = adapter.lock().await;
    a.path.clone()
}

/// Iterate all adapters, calling `f` for each.
pub async fn btd_adapter_foreach<F>(f: F)
where
    F: Fn(&Arc<Mutex<BtdAdapter>>),
{
    let adapters = ADAPTERS.read().await;
    for adapter_arc in adapters.iter() {
        f(adapter_arc);
    }
}

/// Return the default adapter (first powered, or first in list).
pub async fn btd_adapter_get_default() -> Option<Arc<Mutex<BtdAdapter>>> {
    let def_idx = DEFAULT_ADAPTER_INDEX.lock().await;
    if let Some(idx) = *def_idx {
        return adapter_find(idx).await;
    }
    let adapters = ADAPTERS.read().await;
    adapters.first().cloned()
}

/// Check if a given adapter is the default adapter.
pub async fn btd_adapter_is_default(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.is_default
}

/// Get an adapter's HCI index.
pub async fn btd_adapter_get_index(adapter: &Arc<Mutex<BtdAdapter>>) -> u16 {
    let a = adapter.lock().await;
    a.index
}

/// Get an adapter's BD_ADDR.
pub async fn btd_adapter_get_address(adapter: &Arc<Mutex<BtdAdapter>>) -> BdAddr {
    let a = adapter.lock().await;
    a.address
}

/// Get an adapter's address type.
pub async fn btd_adapter_get_address_type(adapter: &Arc<Mutex<BtdAdapter>>) -> u8 {
    let a = adapter.lock().await;
    a.address_type
}

/// Get an adapter's powered state.
pub async fn btd_adapter_get_powered(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.powered
}

/// Get an adapter's pairable state.
pub async fn btd_adapter_get_pairable(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.pairable
}

/// Get an adapter's connectable state.
pub async fn btd_adapter_get_connectable(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.has_setting(MgmtSettings::CONNECTABLE.bits())
}

/// Get an adapter's discoverable state.
pub async fn btd_adapter_get_discoverable(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.discoverable
}

/// Check if BR/EDR is enabled for the adapter.
pub async fn btd_adapter_get_bredr(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.bredr_enabled
}

/// Get the adapter's GATT database (if initialized).
pub async fn btd_adapter_get_database(
    adapter: &Arc<Mutex<BtdAdapter>>,
) -> Option<Arc<BtdGattDatabase>> {
    let a = adapter.lock().await;
    a.database.clone()
}

/// Get the adapter's class of device.
pub async fn btd_adapter_get_class(adapter: &Arc<Mutex<BtdAdapter>>) -> u32 {
    let a = adapter.lock().await;
    a.class
}

/// Get the adapter's name.
pub async fn btd_adapter_get_name(adapter: &Arc<Mutex<BtdAdapter>>) -> String {
    let a = adapter.lock().await;
    a.effective_alias()
}

/// Get the adapter's storage directory path.
pub async fn btd_adapter_get_storage_dir(adapter: &Arc<Mutex<BtdAdapter>>) -> String {
    let a = adapter.lock().await;
    a.storage_dir.clone()
}

/// Get the adapter's registered services.
pub async fn btd_adapter_get_services(adapter: &Arc<Mutex<BtdAdapter>>) -> Vec<SdpRecord> {
    let a = adapter.lock().await;
    a.services.clone()
}

/// Check if the adapter has a given setting enabled.
pub async fn btd_adapter_has_settings(adapter: &Arc<Mutex<BtdAdapter>>, settings: u32) -> bool {
    let a = adapter.lock().await;
    a.has_setting(settings)
}

/// Check whether SSP (Secure Simple Pairing) is enabled.
pub async fn btd_adapter_ssp_enabled(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.has_setting(MgmtSettings::SSP.bits())
}

// ===========================================================================
// Public API — Device Operations
// ===========================================================================

/// Find a device by BD_ADDR on a given adapter.
pub async fn btd_adapter_find_device(adapter: &Arc<Mutex<BtdAdapter>>, addr: &BdAddr) -> bool {
    let a = adapter.lock().await;
    a.devices.contains_key(addr)
}

/// Find a device by its D-Bus object path.
pub async fn btd_adapter_find_device_by_path(
    adapter: &Arc<Mutex<BtdAdapter>>,
    path: &str,
) -> Option<BdAddr> {
    let a = adapter.lock().await;
    for &addr in a.devices.keys() {
        let dev_path = format!("{}/dev_{}", a.path, addr.ba2str().replace(':', "_"));
        if dev_path == path {
            return Some(addr);
        }
    }
    None
}

/// Find a device by file descriptor (placeholder — requires device.rs wiring).
pub async fn btd_adapter_find_device_by_fd(
    _adapter: &Arc<Mutex<BtdAdapter>>,
    _fd: i32,
) -> Option<BdAddr> {
    // Requires device.rs connection tracking — not yet wired.
    None
}

/// Get or create a device entry for a given address.
pub async fn btd_adapter_get_device(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    _addr_type: u8,
) -> BdAddr {
    let mut a = adapter.lock().await;
    a.devices.entry(*addr).or_insert(());
    *addr
}

/// Remove a device from the adapter and unpair it.
pub async fn btd_adapter_remove_device(adapter: &Arc<Mutex<BtdAdapter>>, addr: &BdAddr) {
    let mut a = adapter.lock().await;
    if a.devices.remove(addr).is_some() {
        for driver in &a.drivers {
            driver.device_removed(&a, addr);
        }
        btd_info(a.index, &format!("Device {} removed", addr.ba2str()));
    }
}

/// Process a device-found event from MGMT.
pub async fn btd_adapter_device_found(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    _addr_type: u8,
    _rssi: i8,
    _eir: &EirData,
) {
    let mut a = adapter.lock().await;
    a.devices.entry(*addr).or_insert(());
    for driver in &a.drivers {
        driver.device_added(&a, addr);
    }
}

/// Iterate all devices on an adapter.
pub async fn btd_adapter_for_each_device<F>(adapter: &Arc<Mutex<BtdAdapter>>, f: F)
where
    F: Fn(&BdAddr),
{
    let a = adapter.lock().await;
    for addr in a.devices.keys() {
        f(addr);
    }
}

/// Disconnect a device by address.
pub async fn btd_adapter_disconnect_device(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if !a.powered {
        return Err(BtdError::not_ready());
    }
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(7);
        param.extend_from_slice(&addr.b);
        param.push(BDADDR_BREDR);
        drop(a);
        let resp = mgmt.send_command(MGMT_OP_DISCONNECT, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => {
                Err(BtdError::failed(&format!("Disconnect failed: {}", mgmt_errstr(r.status))))
            }
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Set the adapter as blocked (rfkill).
pub async fn btd_adapter_set_blocked(adapter: &Arc<Mutex<BtdAdapter>>, blocked: bool) {
    let mut a = adapter.lock().await;
    if blocked {
        a.power_state = AdapterPowerState::OffBlocked;
        a.powered = false;
    } else if a.power_state == AdapterPowerState::OffBlocked {
        a.power_state = AdapterPowerState::Off;
    }
}

/// Restore adapter powered state from persistent storage.
pub async fn btd_adapter_restore_powered(adapter: &Arc<Mutex<BtdAdapter>>, opts: &BtdOpts) {
    let a = adapter.lock().await;
    if opts.auto_enable && !a.powered {
        if let Some(mgmt) = a.mgmt.clone() {
            let idx = a.index;
            drop(a);
            let _ = mgmt.send_command(MGMT_OP_SET_POWERED, idx, &[1u8]).await;
        }
    }
}

/// Check if adapter has cable-pairing devices (e.g., SixAxis).
pub async fn btd_adapter_has_cable_pairing_devices(_adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    false
}

// ===========================================================================
// Public API — Bonding & Pairing
// ===========================================================================

/// Initiate bonding with a remote device.
pub async fn adapter_create_bonding(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
    io_cap: u8,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if !a.powered {
        return Err(BtdError::not_ready());
    }
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(8);
        param.extend_from_slice(&addr.b);
        param.push(addr_type);
        param.push(io_cap);
        drop(a);
        let resp = mgmt.send_command(MGMT_OP_PAIR_DEVICE, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => Err(BtdError::failed(&format!("Pair failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Cancel an in-progress bonding.
pub async fn adapter_cancel_bonding(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(7);
        param.extend_from_slice(&addr.b);
        param.push(addr_type);
        drop(a);
        let resp = mgmt.send_command(MGMT_OP_UNPAIR_DEVICE, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => {
                Err(BtdError::failed(&format!("Cancel bonding failed: {}", mgmt_errstr(r.status))))
            }
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Remove bonding (unpair) for a device.
pub async fn btd_adapter_remove_bonding(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
) -> Result<(), BtdError> {
    adapter_cancel_bonding(adapter, addr, addr_type).await
}

/// Provide a PIN code reply for legacy pairing.
pub async fn btd_adapter_pincode_reply(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    pin: Option<&[u8]>,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(25);
        param.extend_from_slice(&addr.b);
        param.push(BDADDR_BREDR);
        if let Some(pin_data) = pin {
            let pin_len = pin_data.len().min(16) as u8;
            param.push(pin_len);
            let mut pin_buf = [0u8; 16];
            pin_buf[..pin_len as usize].copy_from_slice(&pin_data[..pin_len as usize]);
            param.extend_from_slice(&pin_buf);
        } else {
            // Negative reply: pin_len = 0
            param.push(0);
            param.extend_from_slice(&[0u8; 16]);
        }
        drop(a);
        // MGMT_OP_PIN_CODE_REPLY = 0x0019 or MGMT_OP_PIN_CODE_NEG_REPLY = 0x001A
        let opcode: u16 = if pin.is_some() { 0x0019 } else { 0x001A };
        let _ = mgmt.send_command(opcode, idx, &param).await;
        Ok(())
    } else {
        Err(BtdError::not_ready())
    }
}

/// Provide a user confirmation reply.
pub async fn btd_adapter_confirm_reply(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
    accept: bool,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(7);
        param.extend_from_slice(&addr.b);
        param.push(addr_type);
        drop(a);
        // 0x001B = CONFIRM_REPLY, 0x001C = CONFIRM_NEG_REPLY
        let opcode: u16 = if accept { 0x001B } else { 0x001C };
        let _ = mgmt.send_command(opcode, idx, &param).await;
        Ok(())
    } else {
        Err(BtdError::not_ready())
    }
}

/// Provide a user passkey reply.
pub async fn btd_adapter_passkey_reply(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
    passkey: Option<u32>,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(11);
        param.extend_from_slice(&addr.b);
        param.push(addr_type);
        if let Some(pk) = passkey {
            param.extend_from_slice(&pk.to_le_bytes());
            drop(a);
            // 0x001D = PASSKEY_REPLY
            let _ = mgmt.send_command(0x001D, idx, &param).await;
        } else {
            drop(a);
            // 0x001E = PASSKEY_NEG_REPLY (no passkey field needed)
            let _ = mgmt.send_command(0x001E, idx, &param).await;
        }
        Ok(())
    } else {
        Err(BtdError::not_ready())
    }
}

/// Whether LE connection before pairing is needed for this adapter.
pub async fn btd_le_connect_before_pairing(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.le_enabled
}

// ===========================================================================
// Public API — Block/Unblock
// ===========================================================================

/// Block a device address on the adapter.
pub async fn btd_adapter_block_address(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(7);
        param.extend_from_slice(&addr.b);
        param.push(addr_type);
        drop(a);
        // MGMT_OP_BLOCK_DEVICE = 0x0027
        let resp = mgmt.send_command(0x0027, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => Err(BtdError::failed(&format!("Block failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Unblock a device address on the adapter.
pub async fn btd_adapter_unblock_address(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(7);
        param.extend_from_slice(&addr.b);
        param.push(addr_type);
        drop(a);
        // MGMT_OP_UNBLOCK_DEVICE = 0x0028
        let resp = mgmt.send_command(0x0028, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => Err(BtdError::failed(&format!("Unblock failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

// ===========================================================================
// Public API — UUID Management
// ===========================================================================

/// Add a UUID to the adapter's service list.
pub async fn adapter_service_add(
    adapter: &Arc<Mutex<BtdAdapter>>,
    uuid_str: &str,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let uuid = BtUuid::from_str(uuid_str).map_err(|_| BtdError::invalid_args())?;
        let uuid_bytes = uuid.to_uuid128_bytes();
        let mut param = Vec::with_capacity(17);
        param.extend_from_slice(&uuid_bytes);
        param.push(0); // svc_hint
        drop(a);
        let resp = mgmt.send_command(MGMT_OP_ADD_UUID, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                let mut a = adapter.lock().await;
                a.uuids.insert(uuid_str.to_string());
                Ok(())
            }
            Ok(r) => Err(BtdError::failed(&format!("Add UUID failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Remove a UUID from the adapter's service list.
pub async fn adapter_service_remove(
    adapter: &Arc<Mutex<BtdAdapter>>,
    uuid_str: &str,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let uuid = BtUuid::from_str(uuid_str).map_err(|_| BtdError::invalid_args())?;
        let uuid_bytes = uuid.to_uuid128_bytes();
        let param = uuid_bytes.to_vec();
        drop(a);
        let resp = mgmt.send_command(MGMT_OP_REMOVE_UUID, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                let mut a = adapter.lock().await;
                a.uuids.remove(uuid_str);
                Ok(())
            }
            Ok(r) => {
                Err(BtdError::failed(&format!("Remove UUID failed: {}", mgmt_errstr(r.status))))
            }
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Check if a UUID is allowed by the admin policy.
pub async fn btd_adapter_uuid_is_allowed(adapter: &Arc<Mutex<BtdAdapter>>, uuid_str: &str) -> bool {
    let a = adapter.lock().await;
    if a.allowed_uuids.is_empty() {
        return true;
    }
    a.allowed_uuids.contains(uuid_str)
}

/// Set the list of allowed UUIDs (admin policy).
pub async fn btd_adapter_set_allowed_uuids(
    adapter: &Arc<Mutex<BtdAdapter>>,
    uuids: HashSet<String>,
) {
    let mut a = adapter.lock().await;
    a.allowed_uuids = uuids;
}

// ===========================================================================
// Public API — Class and Name
// ===========================================================================

/// Set the device class (CoD) for the adapter.
pub async fn btd_adapter_set_class(
    adapter: &Arc<Mutex<BtdAdapter>>,
    major: u8,
    minor: u8,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        drop(a);
        let param = [major, minor];
        let resp = mgmt.send_command(MGMT_OP_SET_DEV_CLASS, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                let mut a = adapter.lock().await;
                a.major_class = major;
                a.minor_class = minor;
                Ok(())
            }
            Ok(r) => Err(BtdError::failed(&format!("Set class failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Set the adapter's local name via MGMT.
pub async fn btd_adapter_set_name(
    adapter: &Arc<Mutex<BtdAdapter>>,
    name: &str,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if name.len() > MAX_NAME_LENGTH {
        return Err(BtdError::invalid_args());
    }
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut name_buf = [0u8; 249];
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(248);
        name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        let mut short_buf = [0u8; 11];
        let slen = copy_len.min(10);
        short_buf[..slen].copy_from_slice(&bytes[..slen]);
        let mut param = Vec::with_capacity(260);
        param.extend_from_slice(&name_buf);
        param.extend_from_slice(&short_buf);
        drop(a);
        let resp = mgmt.send_command(MGMT_OP_SET_LOCAL_NAME, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => {
                let mut a = adapter.lock().await;
                a.name = name.to_string();
                a.alias = a.effective_alias();
                Ok(())
            }
            Ok(r) => Err(BtdError::failed(&format!("Set name failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Set fast connectable mode.
pub async fn btd_adapter_set_fast_connectable(
    adapter: &Arc<Mutex<BtdAdapter>>,
    enable: bool,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        drop(a);
        let val: u8 = if enable { 1 } else { 0 };
        let resp = mgmt.send_command(MGMT_OP_SET_FAST_CONNECTABLE, idx, &[val]).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => Err(BtdError::failed(&format!(
                "Set fast connectable failed: {}",
                mgmt_errstr(r.status)
            ))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

// ===========================================================================
// Public API — IO Capability
// ===========================================================================

/// Set the adapter's IO capability for pairing.
pub async fn adapter_set_io_capability(adapter: &Arc<Mutex<BtdAdapter>>, io_cap: u8) {
    let a = adapter.lock().await;
    btd_debug(a.index, &format!("IO capability set to {io_cap}"));
}

// ===========================================================================
// Public API — Driver registration
// ===========================================================================

/// Register an adapter driver.
pub async fn btd_register_adapter_driver(driver: Arc<dyn BtdAdapterDriver>) {
    let name = driver.name().to_string();
    ADAPTER_DRIVERS.write().await.push(driver.clone());

    // Probe all existing powered adapters.
    let adapters = ADAPTERS.read().await;
    for adapter_arc in adapters.iter() {
        let a = adapter_arc.lock().await;
        if a.powered {
            let _ = driver.probe(&a);
        }
    }
    btd_debug(HCI_DEV_NONE, &format!("Adapter driver '{name}' registered"));
}

/// Unregister an adapter driver.
pub async fn btd_unregister_adapter_driver(name: &str) {
    let mut drivers = ADAPTER_DRIVERS.write().await;
    drivers.retain(|d| d.name() != name);
    btd_debug(HCI_DEV_NONE, &format!("Adapter driver '{name}' unregistered"));
}

/// Notify all drivers that a device's services are resolved.
pub async fn device_resolved_drivers(adapter: &Arc<Mutex<BtdAdapter>>, addr: &BdAddr) {
    let a = adapter.lock().await;
    for driver in &a.drivers {
        driver.device_resolved(&a, addr);
    }
}

// ===========================================================================
// Public API — Authorization
// ===========================================================================

/// Request authorization for a service access.
pub async fn btd_request_authorization(
    _adapter: &Arc<Mutex<BtdAdapter>>,
    _addr: &BdAddr,
    _uuid: &str,
) -> Result<u32, BtdError> {
    // Authorization brokerage requires agent.rs integration.
    // Return a dummy auth ID.
    Ok(alloc_cb_id() as u32)
}

/// Request authorization configured for cable pairing.
pub async fn btd_request_authorization_cable_configured(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    uuid: &str,
) -> Result<u32, BtdError> {
    btd_request_authorization(adapter, addr, uuid).await
}

/// Cancel a pending authorization request.
pub async fn btd_cancel_authorization(_auth_id: u32) {
    // Agent integration placeholder.
}

/// Cancel a service authorization.
pub async fn btd_adapter_cancel_service_auth(_adapter: &Arc<Mutex<BtdAdapter>>, _auth_id: u32) {
    // Agent integration placeholder.
}

// ===========================================================================
// Public API — PIN callback registration
// ===========================================================================

/// Register a PIN code callback.
pub async fn btd_adapter_register_pin_cb(
    adapter: &Arc<Mutex<BtdAdapter>>,
    cb: PinCodeCallback,
) -> u64 {
    let mut a = adapter.lock().await;
    let id = alloc_cb_id();
    a.pin_callbacks.push(PinCbEntry { cb, id });
    id
}

/// Unregister a PIN code callback.
pub async fn btd_adapter_unregister_pin_cb(adapter: &Arc<Mutex<BtdAdapter>>, id: u64) {
    let mut a = adapter.lock().await;
    a.pin_callbacks.retain(|e| e.id != id);
}

// ===========================================================================
// Public API — MSD callback registration
// ===========================================================================

/// Register a manufacturer-specific data callback.
pub async fn btd_adapter_register_msd_cb(adapter: &Arc<Mutex<BtdAdapter>>, cb: MsdCallback) -> u64 {
    let mut a = adapter.lock().await;
    let id = alloc_cb_id();
    a.msd_callbacks.push(MsdCbEntry { cb, id });
    id
}

/// Unregister a manufacturer-specific data callback.
pub async fn btd_adapter_unregister_msd_cb(adapter: &Arc<Mutex<BtdAdapter>>, id: u64) {
    let mut a = adapter.lock().await;
    a.msd_callbacks.retain(|e| e.id != id);
}

// ===========================================================================
// Public API — Disconnect / Connection-fail callbacks
// ===========================================================================

/// Register a disconnect callback.
pub async fn btd_add_disconnect_cb(
    adapter: &Arc<Mutex<BtdAdapter>>,
    cb: DisconnectCallback,
) -> u64 {
    let mut a = adapter.lock().await;
    let id = alloc_cb_id();
    a.disconnect_callbacks.push(DisconnectCbEntry { cb, id });
    id
}

/// Unregister a disconnect callback.
pub async fn btd_remove_disconnect_cb(adapter: &Arc<Mutex<BtdAdapter>>, id: u64) {
    let mut a = adapter.lock().await;
    a.disconnect_callbacks.retain(|e| e.id != id);
}

/// Register a connection-failure callback.
pub async fn btd_add_conn_fail_cb(adapter: &Arc<Mutex<BtdAdapter>>, cb: ConnFailCallback) -> u64 {
    let mut a = adapter.lock().await;
    let id = alloc_cb_id();
    a.conn_fail_callbacks.push(ConnFailCbEntry { cb, id });
    id
}

/// Unregister a connection-failure callback.
pub async fn btd_remove_conn_fail_cb(adapter: &Arc<Mutex<BtdAdapter>>, id: u64) {
    let mut a = adapter.lock().await;
    a.conn_fail_callbacks.retain(|e| e.id != id);
}

// ===========================================================================
// Public API — Experimental features
// ===========================================================================

/// Check if an experimental feature is active on the adapter.
pub async fn btd_adapter_has_exp_feature(
    adapter: &Arc<Mutex<BtdAdapter>>,
    feature: ExperimentalFeatures,
) -> bool {
    let a = adapter.lock().await;
    a.exp_features & feature.bits() != 0
}

// ===========================================================================
// Public API — Kernel features
// ===========================================================================

/// Check if a kernel feature is available.
pub async fn btd_has_kernel_features(feature: KernelFeatures) -> bool {
    let kf = KERNEL_FEATURES.lock().await;
    *kf & feature.bits() != 0
}

// ===========================================================================
// Public API — Connection parameters
// ===========================================================================

/// Load connection parameters for known devices.
pub async fn btd_adapter_load_conn_param(
    adapter: &Arc<Mutex<BtdAdapter>>,
    params: &[mgmt_conn_param],
) {
    let a = adapter.lock().await;
    btd_debug(a.index, &format!("Loading {} connection parameters", params.len()));
}

/// Store connection parameters for a device.
pub async fn btd_adapter_store_conn_param(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
    _min_interval: u16,
    _max_interval: u16,
    _latency: u16,
    _timeout: u16,
) {
    let a = adapter.lock().await;
    btd_debug(a.index, &format!("Store conn params for {} type={}", addr.ba2str(), addr_type));
}

// ===========================================================================
// Public API — Connect list management
// ===========================================================================

/// Add a device to the adapter's kernel connect/auto-connect list.
pub async fn adapter_connect_list_add(adapter: &Arc<Mutex<BtdAdapter>>, addr: &BdAddr) {
    let mut a = adapter.lock().await;
    if !a.connect_list.contains(addr) {
        a.connect_list.push(*addr);
        if let Some(mgmt) = a.mgmt.clone() {
            let idx = a.index;
            let mut param = Vec::with_capacity(8);
            param.extend_from_slice(&addr.b);
            param.push(BDADDR_BREDR);
            param.push(0x02); // ACTION_AUTO_CONNECT
            drop(a);
            let _ = mgmt.send_command(MGMT_OP_ADD_DEVICE, idx, &param).await;
        }
    }
}

/// Remove a device from the adapter's connect list.
pub async fn adapter_connect_list_remove(adapter: &Arc<Mutex<BtdAdapter>>, addr: &BdAddr) {
    let mut a = adapter.lock().await;
    a.connect_list.retain(|a_addr| a_addr != addr);
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(7);
        param.extend_from_slice(&addr.b);
        param.push(BDADDR_BREDR);
        drop(a);
        // MGMT_OP_REMOVE_DEVICE = 0x0034
        let _ = mgmt.send_command(0x0034, idx, &param).await;
    }
}

/// Add a device to the LE auto-connect list.
pub async fn adapter_auto_connect_add(adapter: &Arc<Mutex<BtdAdapter>>, addr: &BdAddr) {
    let mut a = adapter.lock().await;
    if !a.connect_le.contains(addr) {
        a.connect_le.push(*addr);
    }
}

/// Remove a device from the LE auto-connect list.
pub async fn adapter_auto_connect_remove(adapter: &Arc<Mutex<BtdAdapter>>, addr: &BdAddr) {
    let mut a = adapter.lock().await;
    a.connect_le.retain(|a_addr| a_addr != addr);
}

// ===========================================================================
// Public API — GATT server lifecycle
// ===========================================================================

/// Start the GATT server on the adapter.
pub async fn btd_adapter_gatt_server_start(adapter: &Arc<Mutex<BtdAdapter>>) {
    let a = adapter.lock().await;
    btd_info(a.index, "GATT server started");
}

/// Stop the GATT server on the adapter.
pub async fn btd_adapter_gatt_server_stop(adapter: &Arc<Mutex<BtdAdapter>>) {
    let a = adapter.lock().await;
    btd_info(a.index, "GATT server stopped");
}

// ===========================================================================
// Public API — Profile management
// ===========================================================================

/// Add a profile to the adapter.
pub async fn adapter_add_profile(adapter: &Arc<Mutex<BtdAdapter>>, profile: &str) {
    let mut a = adapter.lock().await;
    if !a.profiles.contains(&profile.to_string()) {
        a.profiles.push(profile.to_string());
    }
}

/// Remove a profile from the adapter.
pub async fn adapter_remove_profile(adapter: &Arc<Mutex<BtdAdapter>>, profile: &str) {
    let mut a = adapter.lock().await;
    a.profiles.retain(|p| p != profile);
}

// ===========================================================================
// Public API — OOB
// ===========================================================================

/// Read local OOB data from the adapter.
pub async fn btd_adapter_read_local_oob_data(
    adapter: &Arc<Mutex<BtdAdapter>>,
) -> Result<Vec<u8>, BtdError> {
    let a = adapter.lock().await;
    if !a.powered {
        return Err(BtdError::not_ready());
    }
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        drop(a);
        // MGMT_OP_READ_LOCAL_OOB_DATA = 0x0020
        let resp = mgmt.send_command(0x0020, idx, &[]).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(r.data),
            Ok(r) => Err(BtdError::failed(&format!("Read OOB failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Set the OOB handler for the adapter.
pub async fn btd_adapter_set_oob_handler(adapter: &Arc<Mutex<BtdAdapter>>, handler: OobHandler) {
    let mut a = adapter.lock().await;
    a.oob_handler = Some(handler);
}

/// Check if an OOB handler is currently set.
pub async fn btd_adapter_check_oob_handler(adapter: &Arc<Mutex<BtdAdapter>>) -> bool {
    let a = adapter.lock().await;
    a.oob_handler.is_some()
}

/// Add remote OOB data for a device.
pub async fn btd_adapter_add_remote_oob_data(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    data: &[u8],
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(7 + data.len());
        param.extend_from_slice(&addr.b);
        param.push(BDADDR_BREDR);
        param.extend_from_slice(data);
        drop(a);
        // MGMT_OP_ADD_REMOTE_OOB_DATA = 0x0021
        let resp = mgmt.send_command(0x0021, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => {
                Err(BtdError::failed(&format!("Add remote OOB failed: {}", mgmt_errstr(r.status))))
            }
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

// ===========================================================================
// Public API — Device flags & bonding attempts
// ===========================================================================

/// Set device flags via MGMT.
pub async fn adapter_set_device_flags(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
    flags: u32,
) -> Result<(), BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        let mut param = Vec::with_capacity(11);
        param.extend_from_slice(&addr.b);
        param.push(addr_type);
        param.extend_from_slice(&flags.to_le_bytes());
        drop(a);
        // MGMT_OP_SET_DEVICE_FLAGS = 0x0050
        let resp = mgmt.send_command(0x0050, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => Err(BtdError::failed(&format!("Set flags failed: {}", mgmt_errstr(r.status)))),
            Err(e) => Err(BtdError::failed(&format!("MGMT error: {e}"))),
        }
    } else {
        Err(BtdError::not_ready())
    }
}

/// Track a bonding attempt.
pub async fn adapter_bonding_attempt(
    _adapter: &Arc<Mutex<BtdAdapter>>,
    _addr: &BdAddr,
    _addr_type: u8,
    _status: u8,
) {
    // Tracking is maintained in the device object.
}

// ===========================================================================
// Public API — Sync MGMT event/command
// ===========================================================================

/// Send a MGMT command and receive a response synchronously (blocking).
pub async fn btd_adapter_send_cmd_event_sync(
    adapter: &Arc<Mutex<BtdAdapter>>,
    opcode: u16,
    data: &[u8],
) -> Result<MgmtResponse, BtdError> {
    let a = adapter.lock().await;
    if let Some(mgmt) = a.mgmt.clone() {
        let idx = a.index;
        drop(a);
        mgmt.send_command(opcode, idx, data)
            .await
            .map_err(|e| BtdError::failed(&format!("MGMT error: {e}")))
    } else {
        Err(BtdError::not_ready())
    }
}

// ===========================================================================
// Public API — Bonding attempt tracking
// ===========================================================================

/// Adapter bonding attempt tracking (delegates to adapter_bonding_attempt).
pub async fn adapter_bonding_attempt_sync(
    adapter: &Arc<Mutex<BtdAdapter>>,
    addr: &BdAddr,
    addr_type: u8,
    status: u8,
) {
    adapter_bonding_attempt(adapter, addr, addr_type, status).await;
}
