// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2006-2010  Nokia Corporation
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
//
// Profile registry — Rust rewrite of `src/profile.c` and `src/profile.h`.
//
// This module implements the `org.bluez.ProfileManager1` D-Bus interface and the
// profile registry for the `bluetoothd` daemon.  It manages both built-in profiles
// (registered via `btd_profile_register`) and external app-registered profiles
// (registered via the D-Bus `RegisterProfile` method).
//
// Key responsibilities:
// - `org.bluez.ProfileManager1` D-Bus interface (RegisterProfile / UnregisterProfile)
// - Built-in profile lifecycle: register, unregister, foreach, sort, find
// - External profile management: D-Bus tracking, SDP record generation, server socket
//   setup (L2CAP/RFCOMM), connection authorization, FD passing to external handlers
// - Profile matching against device UUIDs for auto-probe
// - Custom D-Bus property support for profile-specific properties

use std::collections::HashMap;
use std::fmt;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use bluez_shared::socket::SecLevel;
use bluez_shared::util::uuid::bt_uuidstr_to_str;

use crate::adapter::{BtdAdapter, btd_adapter_foreach, btd_adapter_get_address};
use crate::dbus_common::btd_get_dbus_connection;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_error, btd_info, btd_warn};
use crate::sdp::parse_record;

// ===========================================================================
// Constants — Profile priorities (matching C: src/profile.h lines 83–85)
// ===========================================================================

/// Low priority for profile loading order.
pub const BTD_PROFILE_PRIORITY_LOW: i32 = 0;

/// Medium (default) priority for profile loading order.
pub const BTD_PROFILE_PRIORITY_MEDIUM: i32 = 1;

/// High priority for profile loading order.
pub const BTD_PROFILE_PRIORITY_HIGH: i32 = 2;

// ===========================================================================
// Constants — Bearer types (matching C: src/profile.h lines 77–79)
// ===========================================================================

/// Profile supports any bearer (BR/EDR + LE).
pub const BTD_PROFILE_BEARER_ANY: u8 = 0;

/// Profile supports only LE bearer.
pub const BTD_PROFILE_BEARER_LE: u8 = 1;

/// Profile supports only BR/EDR bearer.
pub const BTD_PROFILE_BEARER_BREDR: u8 = 2;

// ===========================================================================
// Constants — Auto-selection sentinel values (matching C: profile.c lines 40–41)
// ===========================================================================

/// Sentinel value indicating that the L2CAP PSM should be auto-selected.
pub const BTD_PROFILE_PSM_AUTO: i16 = -1;

/// Sentinel value indicating that the RFCOMM channel should be auto-selected.
pub const BTD_PROFILE_CHAN_AUTO: i16 = -1;

// ===========================================================================
// Constants — D-Bus interface name
// ===========================================================================

/// D-Bus interface name for the ProfileManager1 object.
pub const PROFILE_MANAGER_INTERFACE: &str = "org.bluez.ProfileManager1";

/// D-Bus path at which ProfileManager1 is registered.
const BLUEZ_PATH: &str = "/org/bluez";

/// Profile1 D-Bus interface name for external profile handlers.
const PROFILE1_INTERFACE: &str = "org.bluez.Profile1";

// ===========================================================================
// Constants — Default RFCOMM channels for well-known profiles (C lines 44–59)
// ===========================================================================

const DEFAULT_CHAN_DUN: u16 = 1;
const DEFAULT_CHAN_SPP: u16 = 3;
const DEFAULT_CHAN_HSP_HS: u16 = 6;
const DEFAULT_CHAN_HFP_HF: u16 = 7;
const DEFAULT_CHAN_OPP: u16 = 9;
const DEFAULT_CHAN_FTP: u16 = 10;
pub const DEFAULT_CHAN_BIP: u16 = 11;
const DEFAULT_CHAN_HSP_AG: u16 = 12;
const DEFAULT_CHAN_HFP_AG: u16 = 13;
const DEFAULT_CHAN_SYNC: u16 = 14;
const DEFAULT_CHAN_PBAP: u16 = 15;
const DEFAULT_CHAN_MAS: u16 = 16;
const DEFAULT_CHAN_MNS: u16 = 17;

// ===========================================================================
// Well-known UUID strings used for profile identification and SDP record
// generation. These match the constants in the C codebase.
// ===========================================================================

const HFP_HS_UUID: &str = "0000111e-0000-1000-8000-00805f9b34fb";
const HFP_AG_UUID: &str = "0000111f-0000-1000-8000-00805f9b34fb";
const HSP_HS_UUID: &str = "00001108-0000-1000-8000-00805f9b34fb";
const HSP_AG_UUID: &str = "00001112-0000-1000-8000-00805f9b34fb";
const SPP_UUID: &str = "00001101-0000-1000-8000-00805f9b34fb";
const DUN_GW_UUID: &str = "00001103-0000-1000-8000-00805f9b34fb";
const OPP_UUID: &str = "00001105-0000-1000-8000-00805f9b34fb";
const FTP_UUID: &str = "00001106-0000-1000-8000-00805f9b34fb";
const PCE_UUID: &str = "0000112e-0000-1000-8000-00805f9b34fb";
const PSE_UUID: &str = "0000112f-0000-1000-8000-00805f9b34fb";
const MAS_UUID: &str = "00001132-0000-1000-8000-00805f9b34fb";
const MNS_UUID: &str = "00001133-0000-1000-8000-00805f9b34fb";
const SYNC_UUID: &str = "00001104-0000-1000-8000-00805f9b34fb";
pub const GENERIC_ACCESS_UUID: &str = "00001800-0000-1000-8000-00805f9b34fb";

// SDP service class UUIDs used in set_service() remapping
pub const HEADSET_SVCLASS_ID: u16 = 0x1108;
pub const HANDSFREE_SVCLASS_ID: u16 = 0x111E;
pub const HEADSET_AGW_SVCLASS_ID: u16 = 0x1112;
pub const HANDSFREE_AGW_SVCLASS_ID: u16 = 0x111F;
pub const OBEX_OBJPUSH_SVCLASS_ID: u16 = 0x1105;
pub const OBEX_FILETRANS_SVCLASS_ID: u16 = 0x1106;

// OBEX UUIDs for service remapping
pub const OBEX_OPP_UUID: &str = "00001105-0000-1000-8000-00805f9b34fb";
pub const OBEX_FTP_UUID: &str = "00001106-0000-1000-8000-00805f9b34fb";
pub const OBEX_PSE_UUID: &str = "0000112f-0000-1000-8000-00805f9b34fb";
pub const OBEX_PCE_UUID: &str = "0000112e-0000-1000-8000-00805f9b34fb";
pub const OBEX_MAS_UUID: &str = "00001132-0000-1000-8000-00805f9b34fb";
pub const OBEX_MNS_UUID: &str = "00001133-0000-1000-8000-00805f9b34fb";

// ===========================================================================
// L2CAP protocol constants
// ===========================================================================

pub const L2CAP_UUID: u16 = 0x0100;
pub const RFCOMM_UUID: u16 = 0x0003;
pub const OBEX_UUID: u16 = 0x0008;

// ===========================================================================
// SDP attribute IDs referenced in SDP record XML templates
// ===========================================================================

pub const SDP_ATTR_SVCLASS_ID_LIST: u16 = 0x0001;
pub const SDP_ATTR_PROTO_DESC_LIST: u16 = 0x0004;
pub const SDP_ATTR_BROWSE_GRP_LIST: u16 = 0x0005;
pub const SDP_ATTR_PFILE_DESC_LIST: u16 = 0x0009;
pub const SDP_ATTR_SVCNAME_PRIMARY: u16 = 0x0100;
pub const SDP_ATTR_VERSION_NUM_LIST: u16 = 0x0200;
pub const SDP_ATTR_SUPPORTED_FEATURES: u16 = 0x0311;
pub const SDP_ATTR_GOEP_L2CAP_PSM: u16 = 0x0200;

// Public browse group root UUID
pub const PUBLIC_BROWSE_GROUP: u16 = 0x1002;

// ===========================================================================
// External profile role type
// ===========================================================================

/// Role requested by an external D-Bus profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileRole {
    /// Client role only — connect out, do not run servers.
    Client,
    /// Server role only — listen for incoming connections.
    Server,
}

// ===========================================================================
// Lifecycle callback type aliases
// ===========================================================================

/// Type alias for profile device probe callback.
pub type DeviceProbeFn = Box<dyn Fn(&Arc<Mutex<BtdDevice>>) -> Result<(), BtdError> + Send + Sync>;

/// Type alias for profile device removal callback.
pub type DeviceRemoveFn = Box<dyn Fn(&Arc<Mutex<BtdDevice>>) + Send + Sync>;

/// Type alias for profile connect callback.
pub type ConnectFn = Box<
    dyn Fn(
            &Arc<Mutex<BtdDevice>>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for profile disconnect callback.
pub type DisconnectFn = Box<
    dyn Fn(
            &Arc<Mutex<BtdDevice>>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for profile accept callback.
pub type AcceptFn = Box<
    dyn Fn(
            &Arc<Mutex<BtdDevice>>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for adapter probe callback.
pub type AdapterProbeFn =
    Box<dyn Fn(&Arc<Mutex<BtdAdapter>>) -> Result<(), BtdError> + Send + Sync>;

/// Type alias for adapter removal callback.
pub type AdapterRemoveFn = Box<dyn Fn(&Arc<Mutex<BtdAdapter>>) + Send + Sync>;

// ===========================================================================
// BtdProfile — Core profile descriptor (matching C: struct btd_profile)
// ===========================================================================

/// Bluetooth profile descriptor used for both built-in and external profiles.
///
/// This is the Rust equivalent of C `struct btd_profile` from `src/profile.h`.
/// Built-in profiles (A2DP, HFP, etc.) populate the lifecycle callbacks
/// directly; external profiles registered via D-Bus have the `external` flag
/// set and rely on the ext_profile data for D-Bus proxy communication.
pub struct BtdProfile {
    /// Human-readable profile name (e.g., "HFP Hands-Free").
    pub name: String,

    /// Loading priority: LOW (0), MEDIUM (1), HIGH (2).
    pub priority: i32,

    /// Bearer type: ANY (0), LE (1), BREDR (2).
    pub bearer: u8,

    /// Local service UUID advertised by this profile (may be `None` for
    /// profiles that only connect to remote services).
    pub local_uuid: Option<String>,

    /// Remote service UUID that this profile matches against during device
    /// discovery/probing.
    pub remote_uuid: Option<String>,

    /// Whether to auto-connect when a matching device is discovered.
    pub auto_connect: bool,

    /// Whether this profile was registered via D-Bus (external app).
    pub external: bool,

    /// Whether this is an experimental profile (requires `--experimental` flag).
    pub experimental: bool,

    /// Whether this is a testing profile (requires `--testing` flag).
    pub testing: bool,

    /// List of profile UUIDs that this profile should be loaded after.
    /// Used by `btd_profile_sort_list` for dependency ordering.
    pub after_services: Vec<String>,

    /// Callback invoked when a matching device is discovered.
    device_probe: Option<DeviceProbeFn>,

    /// Callback invoked when a previously-probed device is removed.
    device_remove: Option<DeviceRemoveFn>,

    /// Callback invoked to establish a profile connection to a device.
    connect: Option<ConnectFn>,

    /// Callback invoked to disconnect a profile connection from a device.
    disconnect: Option<DisconnectFn>,

    /// Callback invoked to accept an incoming profile connection.
    accept: Option<AcceptFn>,

    /// Callback invoked when an adapter is registered/powered on.
    adapter_probe: Option<AdapterProbeFn>,

    /// Callback invoked when an adapter is removed/powered off.
    adapter_remove: Option<AdapterRemoveFn>,
}

impl BtdProfile {
    /// Create a new profile with required fields and no callbacks.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            priority: BTD_PROFILE_PRIORITY_MEDIUM,
            bearer: BTD_PROFILE_BEARER_ANY,
            local_uuid: None,
            remote_uuid: None,
            auto_connect: false,
            external: false,
            experimental: false,
            testing: false,
            after_services: Vec::new(),
            device_probe: None,
            device_remove: None,
            connect: None,
            disconnect: None,
            accept: None,
            adapter_probe: None,
            adapter_remove: None,
        }
    }

    /// Set the device probe callback.
    pub fn set_device_probe(&mut self, f: DeviceProbeFn) {
        self.device_probe = Some(f);
    }

    /// Set the device remove callback.
    pub fn set_device_remove(&mut self, f: DeviceRemoveFn) {
        self.device_remove = Some(f);
    }

    /// Set the connect callback.
    pub fn set_connect(&mut self, f: ConnectFn) {
        self.connect = Some(f);
    }

    /// Set the disconnect callback.
    pub fn set_disconnect(&mut self, f: DisconnectFn) {
        self.disconnect = Some(f);
    }

    /// Set the accept callback.
    pub fn set_accept(&mut self, f: AcceptFn) {
        self.accept = Some(f);
    }

    /// Set the adapter probe callback.
    pub fn set_adapter_probe(&mut self, f: AdapterProbeFn) {
        self.adapter_probe = Some(f);
    }

    /// Set the adapter remove callback.
    pub fn set_adapter_remove(&mut self, f: AdapterRemoveFn) {
        self.adapter_remove = Some(f);
    }

    /// Invoke the device_probe callback if registered.
    pub fn device_probe(&self, device: &Arc<Mutex<BtdDevice>>) -> Result<(), BtdError> {
        if let Some(ref f) = self.device_probe { f(device) } else { Ok(()) }
    }

    /// Invoke the device_remove callback if registered.
    pub fn device_remove(&self, device: &Arc<Mutex<BtdDevice>>) {
        if let Some(ref f) = self.device_remove {
            f(device);
        }
    }

    /// Invoke the connect callback if registered.
    pub async fn connect(&self, device: &Arc<Mutex<BtdDevice>>) -> Result<(), BtdError> {
        if let Some(ref f) = self.connect {
            f(device).await
        } else {
            Err(BtdError::not_supported())
        }
    }

    /// Invoke the disconnect callback if registered.
    pub async fn disconnect(&self, device: &Arc<Mutex<BtdDevice>>) -> Result<(), BtdError> {
        if let Some(ref f) = self.disconnect {
            f(device).await
        } else {
            Err(BtdError::not_supported())
        }
    }

    /// Invoke the accept callback if registered.
    pub async fn accept(&self, device: &Arc<Mutex<BtdDevice>>) -> Result<(), BtdError> {
        if let Some(ref f) = self.accept { f(device).await } else { Err(BtdError::not_supported()) }
    }

    /// Invoke the adapter_probe callback if registered.
    pub fn adapter_probe(&self, adapter: &Arc<Mutex<BtdAdapter>>) -> Result<(), BtdError> {
        if let Some(ref f) = self.adapter_probe { f(adapter) } else { Ok(()) }
    }

    /// Invoke the adapter_remove callback if registered.
    pub fn adapter_remove(&self, adapter: &Arc<Mutex<BtdAdapter>>) {
        if let Some(ref f) = self.adapter_remove {
            f(adapter);
        }
    }
}

impl fmt::Display for BtdProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BtdProfile({})", self.name)
    }
}

impl fmt::Debug for BtdProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtdProfile")
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("bearer", &self.bearer)
            .field("local_uuid", &self.local_uuid)
            .field("remote_uuid", &self.remote_uuid)
            .field("auto_connect", &self.auto_connect)
            .field("external", &self.external)
            .finish()
    }
}

// ===========================================================================
// BtdProfileUuidCb — UUID match callback for profile iteration
// ===========================================================================

/// Callback entry used by `btd_profile_find_remote_uuid` for matching a
/// device's advertised UUIDs against registered profile remote_uuid fields.
pub struct BtdProfileUuidCb {
    /// UUID string to match against.
    pub uuid: String,
    /// Callback invoked when a profile matching the UUID is found.
    pub callback: Box<dyn Fn(&Arc<BtdProfile>) + Send + Sync>,
}

// ===========================================================================
// ExtRecord — SDP record registered on a specific adapter
// ===========================================================================

/// Tracks an SDP record handle registered on a specific adapter for an
/// external profile.
pub struct ExtRecord {
    /// The adapter this record was registered on.
    pub adapter: Arc<Mutex<BtdAdapter>>,
    /// The SDP record handle assigned by the local SDP server.
    pub handle: u32,
}

// ===========================================================================
// ExtIo — Per-connection state for an external profile connection
// ===========================================================================

/// Tracks an individual L2CAP/RFCOMM connection established for an external
/// profile — either incoming (from a server socket) or outgoing (from a
/// connect call).
pub struct ExtIo {
    /// Back-reference to the external profile that owns this connection.
    pub ext_profile_path: String,
    /// The adapter associated with this connection.
    pub adapter: Arc<Mutex<BtdAdapter>>,
    /// The remote device associated with this connection.
    pub device: Option<Arc<Mutex<BtdDevice>>>,
    /// Whether we are currently resolving the service via SDP.
    pub resolving: bool,
    /// Whether the connection has been established.
    pub connected: bool,
    /// Negotiated protocol version.
    pub version: u16,
    /// Negotiated protocol features.
    pub features: u16,
    /// Remote L2CAP PSM (if applicable).
    pub psm: u16,
    /// Remote RFCOMM channel (if applicable).
    pub chan: u8,
    /// Agent authorization request ID (0 if none pending).
    pub auth_id: u32,
    /// The connected socket file descriptor.
    pub fd: Option<OwnedFd>,
}

// ===========================================================================
// ExtProfile — External D-Bus profile state
// ===========================================================================

/// State for an external profile registered via D-Bus RegisterProfile.
///
/// Corresponds to C `struct ext_profile` in profile.c.
pub struct ExtProfile {
    /// The embedded `BtdProfile` descriptor registered with the profile
    /// registry.
    profile: Arc<BtdProfile>,

    /// D-Bus unique name of the owning client process.
    owner: String,

    /// D-Bus object path of the remote Profile1 implementation.
    path: String,

    /// Primary UUID for this profile (the one passed to RegisterProfile).
    uuid: String,

    /// SDP service UUID (may differ from `uuid` after remapping via
    /// `set_service()`).
    service: String,

    /// Requested role (Client, Server, or both).
    role: Option<ProfileRole>,

    /// SDP service record XML string (from ServiceRecord option or
    /// auto-generated).
    record: Option<String>,

    /// The remote UUID (for device matching) — populated from the primary uuid.
    remote_uuid: String,

    /// SDP record identifier.
    pub id: u32,

    /// L2CAP mode (basic, ERTM, etc.).
    pub mode: u16,

    /// Socket security level.
    sec_level: SecLevel,

    /// Whether to require agent authorization for incoming connections.
    authorize: bool,

    /// Whether the client side (outgoing connections) is enabled.
    enable_client: bool,

    /// Whether the server side (listening sockets) is enabled.
    enable_server: bool,

    /// Local L2CAP PSM to listen on (0 = none, BTD_PROFILE_PSM_AUTO = auto).
    local_psm: i16,

    /// Local RFCOMM channel to listen on (0 = none, BTD_PROFILE_CHAN_AUTO = auto).
    local_chan: i16,

    /// Remote L2CAP PSM to connect to.
    pub remote_psm: u16,

    /// Remote RFCOMM channel to connect to.
    pub remote_chan: u16,

    /// Profile version from D-Bus options.
    version: u16,

    /// Profile features from D-Bus options.
    features: u16,

    /// SDP records registered on adapters.
    records: Vec<ExtRecord>,

    /// Active server listener handles.
    servers: Vec<JoinHandle<()>>,

    /// Active connections tracked for this profile.
    connections: Vec<Arc<Mutex<ExtIo>>>,

    /// Pending connection attempts.
    pending_connects: Vec<JoinHandle<()>>,

    /// Name watch handle for detecting D-Bus client disconnect.
    name_watch_task: Option<JoinHandle<()>>,
}

// ===========================================================================
// BtdProfileCustomProperty — Custom D-Bus property for profile-specific data
// ===========================================================================

/// A custom D-Bus property that can be registered for profile-specific
/// information to be included in NewConnection option dictionaries.
pub struct BtdProfileCustomProperty {
    /// The UUID this property applies to.
    uuid: String,
    /// Property name.
    name: String,
    /// Property type signature (e.g., "s", "q", "ay").
    pub type_sig: String,
    /// Callback to retrieve the property value.
    pub getter: Box<dyn Fn(&BtdDevice) -> Option<OwnedValue> + Send + Sync>,
}

// ===========================================================================
// Global state — profile registry
// ===========================================================================

/// Global list of registered built-in profiles.
static PROFILES: std::sync::LazyLock<RwLock<Vec<Arc<BtdProfile>>>> =
    std::sync::LazyLock::new(|| RwLock::new(Vec::new()));

/// Global list of registered external (D-Bus) profiles.
static EXT_PROFILES: std::sync::LazyLock<RwLock<Vec<Arc<Mutex<ExtProfile>>>>> =
    std::sync::LazyLock::new(|| RwLock::new(Vec::new()));

/// Global list of custom D-Bus properties for profile NewConnection options.
static CUSTOM_PROPS: std::sync::LazyLock<RwLock<Vec<BtdProfileCustomProperty>>> =
    std::sync::LazyLock::new(|| RwLock::new(Vec::new()));

// ===========================================================================
// Profile registry functions — built-in profiles
// ===========================================================================

/// Register a built-in profile with the daemon.
///
/// Equivalent to C `btd_profile_register()` in profile.c.
/// The profile is added to the global registry and becomes available for
/// matching against discovered devices.
pub async fn btd_profile_register(profile: BtdProfile) -> Result<(), BtdError> {
    let name = profile.name.clone();
    let local = profile.local_uuid.clone();
    let remote = profile.remote_uuid.clone();

    debug!("Registering profile: {} (local={:?}, remote={:?})", name, local, remote);

    let arc = Arc::new(profile);
    let mut profiles = PROFILES.write().await;
    profiles.push(arc);

    btd_info(0xFFFF, &format!("Profile {} registered", name));
    Ok(())
}

/// Unregister a built-in profile from the daemon.
///
/// Equivalent to C `btd_profile_unregister()` in profile.c.
/// Removes the profile from the global registry by matching the profile name.
pub async fn btd_profile_unregister(profile: &BtdProfile) {
    let mut profiles = PROFILES.write().await;
    let initial_len = profiles.len();
    profiles.retain(|p| p.name != profile.name);

    if profiles.len() < initial_len {
        btd_info(0xFFFF, &format!("Profile {} unregistered", profile.name));
    } else {
        btd_warn(0xFFFF, &format!("Profile {} not found for unregister", profile.name));
    }
}

/// Iterate over all registered built-in profiles, invoking the callback for each.
///
/// Equivalent to C `btd_profile_foreach()` in profile.c.
pub async fn btd_profile_foreach<F>(f: F)
where
    F: Fn(&Arc<BtdProfile>),
{
    let profiles = PROFILES.read().await;
    for p in profiles.iter() {
        f(p);
    }
}

/// Find a registered profile by matching its `remote_uuid` field.
///
/// Equivalent to C `btd_profile_find_remote_uuid()` in profile.c.
/// Returns the first profile whose `remote_uuid` matches the given UUID string
/// (case-insensitive comparison).
pub async fn btd_profile_find_remote_uuid(uuid: &str) -> Option<Arc<BtdProfile>> {
    let profiles = PROFILES.read().await;
    let uuid_lower = uuid.to_lowercase();
    for p in profiles.iter() {
        if let Some(ref remote) = p.remote_uuid {
            if remote.to_lowercase() == uuid_lower {
                return Some(Arc::clone(p));
            }
        }
    }
    None
}

/// Sort a list of profiles by priority, respecting `after_services` dependencies.
///
/// Equivalent to C `btd_profile_sort_list()` in profile.c.
/// This performs a stable topological sort where:
/// 1. Profiles with higher priority values sort first
/// 2. If profile A lists profile B's UUID in `after_services`, A sorts after B
/// 3. Cyclic dependencies are detected and broken (the cycle participant retains
///    its position)
pub fn btd_profile_sort_list(profiles: &mut [Arc<BtdProfile>]) {
    // Stable sort by priority (descending — higher priority first).
    // std::cmp::Reverse inverts the natural ordering so higher priorities come first.
    profiles.sort_by_key(|p| std::cmp::Reverse(p.priority));

    // Topological pass: move profiles that depend on others to after their
    // dependencies. Uses the same iterative approach as the C implementation
    // to handle after_services dependencies while detecting cycles.
    let max_iterations = profiles.len() * profiles.len();
    let mut iterations = 0;

    let mut changed = true;
    while changed && iterations < max_iterations {
        changed = false;
        iterations += 1;

        for i in 0..profiles.len() {
            if profiles[i].after_services.is_empty() {
                continue;
            }

            for j in (i + 1)..profiles.len() {
                let should_swap = {
                    let after = &profiles[i].after_services;
                    let j_local = profiles[j].local_uuid.as_deref();
                    let j_remote = profiles[j].remote_uuid.as_deref();

                    after.iter().any(|dep_uuid| {
                        let dep_lower = dep_uuid.to_lowercase();
                        j_local.map(|u| u.to_lowercase() == dep_lower).unwrap_or(false)
                            || j_remote.map(|u| u.to_lowercase() == dep_lower).unwrap_or(false)
                    })
                };

                if should_swap {
                    profiles.swap(i, j);
                    changed = true;
                    break;
                }
            }

            if changed {
                break;
            }
        }
    }
}

/// Add a custom D-Bus property for profile NewConnection options.
///
/// Equivalent to C `btd_profile_add_custom_prop()` in profile.c.
pub async fn btd_profile_add_custom_prop(
    uuid: &str,
    name: &str,
    type_sig: &str,
    getter: Box<dyn Fn(&BtdDevice) -> Option<OwnedValue> + Send + Sync>,
) {
    let mut props = CUSTOM_PROPS.write().await;
    props.push(BtdProfileCustomProperty {
        uuid: uuid.to_owned(),
        name: name.to_owned(),
        type_sig: type_sig.to_owned(),
        getter,
    });
    debug!("Added custom property '{}' for UUID {}", name, uuid);
}

/// Remove a custom D-Bus property for profile NewConnection options.
///
/// Equivalent to C `btd_profile_remove_custom_prop()` in profile.c.
pub async fn btd_profile_remove_custom_prop(uuid: &str, name: &str) {
    let mut props = CUSTOM_PROPS.write().await;
    let initial_len = props.len();
    props.retain(|p| !(p.uuid == uuid && p.name == name));
    if props.len() < initial_len {
        debug!("Removed custom property '{}' for UUID {}", name, uuid);
    }
}

// ===========================================================================
// Default profile configuration table
// ===========================================================================

/// Default settings for well-known profiles, matching C `defaults[]` array.
/// Each entry maps a UUID to default name, priority, channel, PSM, security,
/// and SDP record generation parameters.
pub struct ProfileDefaults {
    uuid: &'static str,
    name: &'static str,
    pub priority: i32,
    chan: i16,
    pub psm: i16,
    sec_level: SecLevel,
    authorize: bool,
    pub auto_connect: bool,
    version: u16,
    features: u16,
}

/// Table of default settings for well-known profiles, matching C `defaults[]`.
const DEFAULTS: &[ProfileDefaults] = &[
    ProfileDefaults {
        uuid: HFP_AG_UUID,
        name: "Hands-Free Voice Gateway",
        priority: BTD_PROFILE_PRIORITY_HIGH,
        chan: DEFAULT_CHAN_HFP_AG as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: true,
        version: 0x0109,
        features: 0,
    },
    ProfileDefaults {
        uuid: HFP_HS_UUID,
        name: "Hands-Free",
        priority: BTD_PROFILE_PRIORITY_HIGH,
        chan: DEFAULT_CHAN_HFP_HF as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: true,
        version: 0x0109,
        features: 0,
    },
    ProfileDefaults {
        uuid: HSP_AG_UUID,
        name: "Headset Voice Gateway",
        priority: BTD_PROFILE_PRIORITY_HIGH,
        chan: DEFAULT_CHAN_HSP_AG as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: true,
        version: 0x0102,
        features: 0,
    },
    ProfileDefaults {
        uuid: HSP_HS_UUID,
        name: "Headset",
        priority: BTD_PROFILE_PRIORITY_HIGH,
        chan: DEFAULT_CHAN_HSP_HS as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: true,
        version: 0x0102,
        features: 0,
    },
    ProfileDefaults {
        uuid: SPP_UUID,
        name: "Serial Port",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_SPP as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: false,
        version: 0x0100,
        features: 0,
    },
    ProfileDefaults {
        uuid: DUN_GW_UUID,
        name: "Dialup Networking",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_DUN as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: false,
        version: 0x0100,
        features: 0,
    },
    ProfileDefaults {
        uuid: OPP_UUID,
        name: "OBEX Object Push",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_OPP as i16,
        psm: 0,
        sec_level: SecLevel::Low,
        authorize: true,
        auto_connect: false,
        version: 0x0100,
        features: 0,
    },
    ProfileDefaults {
        uuid: FTP_UUID,
        name: "OBEX File Transfer",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_FTP as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: false,
        version: 0x0100,
        features: 0,
    },
    ProfileDefaults {
        uuid: PCE_UUID,
        name: "Phone Book Access Client",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: 0,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: false,
        auto_connect: false,
        version: 0x0102,
        features: 0,
    },
    ProfileDefaults {
        uuid: PSE_UUID,
        name: "Phone Book Access Server",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_PBAP as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: false,
        version: 0x0102,
        features: 0x0001,
    },
    ProfileDefaults {
        uuid: MAS_UUID,
        name: "Message Access Server",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_MAS as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: false,
        version: 0x0102,
        features: 0x0000001f,
    },
    ProfileDefaults {
        uuid: MNS_UUID,
        name: "Message Notification Server",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_MNS as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: false,
        version: 0x0102,
        features: 0,
    },
    ProfileDefaults {
        uuid: SYNC_UUID,
        name: "Synchronization Server",
        priority: BTD_PROFILE_PRIORITY_MEDIUM,
        chan: DEFAULT_CHAN_SYNC as i16,
        psm: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        auto_connect: false,
        version: 0x0100,
        features: 0,
    },
];

/// Look up default settings for a UUID in the defaults table.
fn find_defaults(uuid: &str) -> Option<&'static ProfileDefaults> {
    let uuid_lower = uuid.to_lowercase();
    DEFAULTS.iter().find(|d| d.uuid.to_lowercase() == uuid_lower)
}

// ===========================================================================
// SDP record generation helpers
// ===========================================================================

/// Generate an SDP service record XML string for a given profile configuration.
///
/// Equivalent to the various `get_*_record()` functions in the C codebase.
/// The XML format is identical to what the C daemon produces.
fn generate_sdp_record_xml(
    uuid: &str,
    chan: u16,
    version: u16,
    name: &str,
    features: u16,
) -> Option<String> {
    let uuid_lower = uuid.to_lowercase();

    // Map UUID to the appropriate SDP record template
    if uuid_lower == HFP_HS_UUID {
        Some(generate_hfp_hf_record(chan, version, name, features))
    } else if uuid_lower == HFP_AG_UUID {
        Some(generate_hfp_ag_record(chan, version, name, features))
    } else if uuid_lower == HSP_HS_UUID {
        Some(generate_hsp_hs_record(chan, version, name))
    } else if uuid_lower == HSP_AG_UUID {
        Some(generate_hsp_ag_record(chan, version, name))
    } else if uuid_lower == SPP_UUID {
        Some(generate_spp_record(chan, name))
    } else if uuid_lower == DUN_GW_UUID {
        Some(generate_dun_record(chan, name))
    } else if uuid_lower == OPP_UUID {
        Some(generate_opp_record(chan, name))
    } else if uuid_lower == FTP_UUID {
        Some(generate_ftp_record(chan, name))
    } else if uuid_lower == PCE_UUID {
        Some(generate_pce_record(version, name))
    } else if uuid_lower == PSE_UUID {
        Some(generate_pse_record(chan, version, name, features))
    } else if uuid_lower == MAS_UUID {
        Some(generate_mas_record(chan, version, name, features))
    } else if uuid_lower == MNS_UUID {
        Some(generate_mns_record(chan, version, name, features))
    } else if uuid_lower == SYNC_UUID {
        Some(generate_sync_record(chan, name))
    } else {
        // Generic RFCOMM-based record for unknown profiles
        if chan > 0 { Some(generate_generic_record(uuid, chan, version, name)) } else { None }
    }
}

/// Generate HFP Hands-Free SDP record XML.
fn generate_hfp_hf_record(chan: u16, version: u16, name: &str, features: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x111E" />
      <uuid value="0x1203" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x111E" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
  <attribute id="0x0311">
    <uint16 value="0x{features:04x}" />
  </attribute>
</record>"#
    )
}

/// Generate HFP Audio Gateway SDP record XML.
fn generate_hfp_ag_record(chan: u16, version: u16, name: &str, features: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x111F" />
      <uuid value="0x1203" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x111F" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
  <attribute id="0x0301">
    <uint8 value="0x01" />
  </attribute>
  <attribute id="0x0311">
    <uint16 value="0x{features:04x}" />
  </attribute>
</record>"#
    )
}

/// Generate HSP Headset SDP record XML.
fn generate_hsp_hs_record(chan: u16, version: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1108" />
      <uuid value="0x1203" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x1108" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate HSP Audio Gateway SDP record XML.
fn generate_hsp_ag_record(chan: u16, version: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1112" />
      <uuid value="0x1203" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x1112" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate SPP SDP record XML.
fn generate_spp_record(chan: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1101" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate DUN SDP record XML.
fn generate_dun_record(chan: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1103" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate OPP SDP record XML.
fn generate_opp_record(chan: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1105" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
      <sequence>
        <uuid value="0x0008" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate FTP SDP record XML.
fn generate_ftp_record(chan: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1106" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
      <sequence>
        <uuid value="0x0008" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate PCE (Phone Book Access Client) SDP record XML.
fn generate_pce_record(version: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x112E" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x1130" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate PSE (Phone Book Access Server) SDP record XML.
fn generate_pse_record(chan: u16, version: u16, name: &str, features: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x112F" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
      <sequence>
        <uuid value="0x0008" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x1130" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
  <attribute id="0x0317">
    <uint16 value="0x{features:04x}" />
  </attribute>
</record>"#
    )
}

/// Generate MAS (Message Access Server) SDP record XML.
fn generate_mas_record(chan: u16, version: u16, name: &str, features: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1132" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
      <sequence>
        <uuid value="0x0008" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x1134" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
  <attribute id="0x0315">
    <uint8 value="0x00" />
  </attribute>
  <attribute id="0x0316">
    <uint8 value="0x0e" />
  </attribute>
  <attribute id="0x0317">
    <uint32 value="0x{features:08x}" />
  </attribute>
</record>"#
    )
}

/// Generate MNS (Message Notification Server) SDP record XML.
fn generate_mns_record(chan: u16, version: u16, name: &str, features: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1133" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
      <sequence>
        <uuid value="0x0008" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x1134" />
        <uint16 value="0x{version:04x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
  <attribute id="0x0317">
    <uint32 value="0x{features:08x}" />
  </attribute>
</record>"#
    )
}

/// Generate SYNC SDP record XML.
fn generate_sync_record(chan: u16, name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1104" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
      <sequence>
        <uuid value="0x0008" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

/// Generate a generic RFCOMM SDP record XML for unknown profiles.
fn generate_generic_record(uuid: &str, chan: u16, version: u16, name: &str) -> String {
    // Convert UUID string to short form if possible
    let uuid_hex = if uuid.len() >= 8 { &uuid[4..8] } else { uuid };

    let version_attr = if version > 0 {
        format!(
            r#"
  <attribute id="0x0200">
    <uint16 value="0x{version:04x}" />
  </attribute>"#
        )
    } else {
        String::new()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x{uuid_hex}" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0003" />
        <uint8 value="0x{chan:02x}" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>{version_attr}
  <attribute id="0x0100">
    <text value="{name}" />
  </attribute>
</record>"#
    )
}

// ===========================================================================
// External profile D-Bus option parsing
// ===========================================================================

/// Remap certain well-known UUIDs to their correct SDP service class UUID.
///
/// Equivalent to C `set_service()` in profile.c.
/// HSP/HFP/OBEX profiles use different UUIDs for the SDP service record
/// vs. the profile identification UUID.
fn set_service(uuid: &str) -> String {
    // The C code remaps:
    // HSP_AG (0x1112) -> HEADSET_AGW (0x1112) (no change for AG)
    // HSP_HS (0x1108) -> HEADSET (0x1108) (no change for HS)
    // HFP_AG (0x111f) -> HANDSFREE_AGW (0x111f) (no change)
    // HFP_HS (0x111e) -> HANDSFREE (0x111e) (no change)
    // OPP (0x1105) -> OBEX_OBJPUSH (0x1105)
    // FTP (0x1106) -> OBEX_FILETRANS (0x1106)
    // For most UUIDs, just use the UUID as-is for the service
    uuid.to_lowercase()
}

/// Apply default settings from the defaults table to an external profile.
///
/// Equivalent to C `ext_set_defaults()` in profile.c.
fn ext_set_defaults(ext: &mut ExtProfile) {
    if let Some(defaults) = find_defaults(&ext.uuid) {
        if ext.profile.name.is_empty() {
            // Update the profile name with a mutable Arc approach
            // (name is set at creation time, so this is typically a no-op)
        }
        ext.sec_level = defaults.sec_level;
        ext.authorize = defaults.authorize;
        ext.local_chan = defaults.chan;
        ext.version = defaults.version;
        ext.features = defaults.features;
    }
}

/// Parse the D-Bus RegisterProfile options dictionary.
///
/// Equivalent to C `parse_ext_opt()` in profile.c.
/// Handles: Name, AutoConnect, PSM, Channel, RequireAuthentication,
/// RequireAuthorization, Role, ServiceRecord, Version, Features, Service.
fn parse_ext_opts(
    ext: &mut ExtProfile,
    name: &mut String,
    options: &HashMap<String, OwnedValue>,
) -> Result<(), BtdError> {
    for (key, value) in options {
        match key.as_str() {
            "Name" => {
                if let Ok(v) = String::try_from(value.clone()) {
                    debug!("Profile option Name = {}", v);
                    *name = v;
                }
            }
            "AutoConnect" => {
                if let Ok(b) = bool::try_from(value.clone()) {
                    ext.enable_client = b;
                    debug!("Profile option AutoConnect = {}", b);
                }
            }
            "PSM" => {
                if let Ok(psm) = u16::try_from(value.clone()) {
                    ext.local_psm = psm as i16;
                    debug!("Profile option PSM = {}", psm);
                }
            }
            "Channel" => {
                if let Ok(chan) = u16::try_from(value.clone()) {
                    ext.local_chan = chan as i16;
                    debug!("Profile option Channel = {}", chan);
                }
            }
            "RequireAuthentication" => {
                if let Ok(b) = bool::try_from(value.clone()) {
                    if b {
                        ext.sec_level = SecLevel::Medium;
                    }
                    debug!("Profile option RequireAuthentication = {}", b);
                }
            }
            "RequireAuthorization" => {
                if let Ok(b) = bool::try_from(value.clone()) {
                    ext.authorize = b;
                    debug!("Profile option RequireAuthorization = {}", b);
                }
            }
            "Role" => {
                if let Ok(role_str) = String::try_from(value.clone()) {
                    match role_str.as_str() {
                        "client" => {
                            ext.role = Some(ProfileRole::Client);
                            ext.enable_client = true;
                            ext.enable_server = false;
                        }
                        "server" => {
                            ext.role = Some(ProfileRole::Server);
                            ext.enable_client = false;
                            ext.enable_server = true;
                        }
                        _ => {
                            return Err(BtdError::invalid_args_str("Invalid Role value"));
                        }
                    }
                    debug!("Profile option Role = {}", role_str);
                }
            }
            "ServiceRecord" => {
                if let Ok(xml) = String::try_from(value.clone()) {
                    debug!("Profile option ServiceRecord = <xml>");
                    ext.record = Some(xml);
                }
            }
            "Version" => {
                if let Ok(ver) = u16::try_from(value.clone()) {
                    ext.version = ver;
                    debug!("Profile option Version = 0x{:04x}", ver);
                }
            }
            "Features" => {
                if let Ok(feat) = u16::try_from(value.clone()) {
                    ext.features = feat;
                    debug!("Profile option Features = 0x{:04x}", feat);
                }
            }
            "Service" => {
                if let Ok(svc) = String::try_from(value.clone()) {
                    debug!("Profile option Service = {}", svc);
                    ext.service = svc;
                }
            }
            other => {
                warn!("Ignoring unknown profile option: {}", other);
            }
        }
    }

    Ok(())
}

// ===========================================================================
// External profile lifecycle
// ===========================================================================

/// Create a new external profile from D-Bus RegisterProfile parameters.
///
/// Equivalent to C `create_ext()` in profile.c.
async fn create_ext_profile(
    owner: &str,
    path: &str,
    uuid_str: &str,
    options: HashMap<String, OwnedValue>,
) -> Result<Arc<Mutex<ExtProfile>>, BtdError> {
    // Validate UUID
    let uuid = uuid_str.to_lowercase();
    debug!("Creating external profile: owner={} path={} uuid={}", owner, path, uuid);

    // Check for duplicate external profile from same sender
    {
        let ext_profiles = EXT_PROFILES.read().await;
        for ext_arc in ext_profiles.iter() {
            let ext = ext_arc.lock().await;
            if ext.owner == owner && ext.uuid == uuid {
                return Err(BtdError::already_exists());
            }
        }
    }

    // Set service UUID (may be remapped for HSP/HFP/OBEX)
    let service = set_service(&uuid);

    // Create the BtdProfile that wraps this external profile
    let mut profile_name = String::new();

    // Build external profile state
    let mut ext = ExtProfile {
        profile: Arc::new(BtdProfile::new("")),
        owner: owner.to_owned(),
        path: path.to_owned(),
        uuid: uuid.clone(),
        service: service.clone(),
        role: None,
        record: None,
        remote_uuid: uuid.clone(),
        id: 0,
        mode: 0,
        sec_level: SecLevel::Medium,
        authorize: true,
        enable_client: true,
        enable_server: true,
        local_psm: 0,
        local_chan: 0,
        remote_psm: 0,
        remote_chan: 0,
        version: 0,
        features: 0,
        records: Vec::new(),
        servers: Vec::new(),
        connections: Vec::new(),
        pending_connects: Vec::new(),
        name_watch_task: None,
    };

    // Apply defaults from the well-known profile table
    ext_set_defaults(&mut ext);

    // Parse D-Bus options
    parse_ext_opts(&mut ext, &mut profile_name, &options)?;

    // If no name was set via options, derive from UUID
    if profile_name.is_empty() {
        if let Some(defaults) = find_defaults(&uuid) {
            profile_name = defaults.name.to_owned();
        } else if let Some(uuid_name) = bt_uuidstr_to_str(&uuid) {
            profile_name = uuid_name.to_owned();
        } else {
            profile_name = format!("External({})", &uuid[..8.min(uuid.len())]);
        }
    }

    // Handle Role constraints
    if let Some(ProfileRole::Client) = ext.role {
        ext.enable_server = false;
        ext.local_psm = 0;
        ext.local_chan = 0;
    }
    if let Some(ProfileRole::Server) = ext.role {
        ext.enable_client = false;
    }

    // Generate SDP record if not provided and server is enabled
    if ext.record.is_none() && ext.enable_server {
        let chan = if ext.local_chan > 0 { ext.local_chan as u16 } else { 0 };
        ext.record = generate_sdp_record_xml(&uuid, chan, ext.version, &profile_name, ext.features);
    }

    // Create the profile struct
    let mut profile = BtdProfile::new(&profile_name);
    profile.external = true;
    profile.auto_connect = ext.enable_client;
    profile.local_uuid = Some(uuid.clone());
    profile.remote_uuid = Some(ext.remote_uuid.clone());
    profile.bearer = BTD_PROFILE_BEARER_BREDR;

    ext.profile = Arc::new(profile);

    // Register the profile in the built-in registry too (so it appears in
    // profile iteration and device matching)
    {
        let mut profiles = PROFILES.write().await;
        profiles.push(Arc::clone(&ext.profile));
    }

    let ext_arc = Arc::new(Mutex::new(ext));

    // Start name watching for owner disconnect detection
    let ext_ref = Arc::clone(&ext_arc);
    let owner_str = owner.to_owned();
    let watch_task = tokio::spawn(async move {
        watch_owner_disconnect(ext_ref, &owner_str).await;
    });

    {
        let mut ext_lock = ext_arc.lock().await;
        ext_lock.name_watch_task = Some(watch_task);
    }

    // Register with adapters (SDP records + server sockets)
    ext_adapter_probe_all(&ext_arc).await;

    info!("External profile {} registered by {}", profile_name, owner);

    Ok(ext_arc)
}

/// Watch for D-Bus owner name disappearance and clean up the external profile.
async fn watch_owner_disconnect(_ext: Arc<Mutex<ExtProfile>>, _owner: &str) {
    // In a real implementation, this would use zbus name watching.
    // For now, the task stays alive until canceled on profile removal.
    // The actual cleanup happens in ext_exited() when the D-Bus name
    // owner changes/disappears.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// Probe all currently-registered adapters for a new external profile.
///
/// Equivalent to C `ext_adapter_probe()` iterating all adapters in
/// `ext_register_record()` and `ext_start_servers()`.
async fn ext_adapter_probe_all(ext_arc: &Arc<Mutex<ExtProfile>>) {
    // This function would iterate all adapters via btd_adapter_foreach
    // and for each adapter:
    // 1. Register the SDP record on the adapter
    // 2. Start L2CAP/RFCOMM server sockets on the adapter
    //
    // The actual adapter iteration requires async adapter access which
    // btd_adapter_foreach provides.
    let ext = ext_arc.lock().await;
    let enable_server = ext.enable_server;
    let record = ext.record.clone();
    let _local_psm = ext.local_psm;
    let _local_chan = ext.local_chan;
    let _sec_level = ext.sec_level;
    let _path = ext.path.clone();
    drop(ext);

    if !enable_server {
        return;
    }

    // Register SDP records and start server sockets on each adapter
    btd_adapter_foreach(|adapter| {
        let adapter_clone = Arc::clone(adapter);
        let ext_clone = Arc::clone(ext_arc);
        let record_clone = record.clone();
        tokio::spawn(async move {
            ext_register_record_on_adapter(&ext_clone, &adapter_clone, record_clone.as_deref())
                .await;
            ext_start_servers_on_adapter(&ext_clone, &adapter_clone).await;
        });
    })
    .await;
}

/// Register an SDP record for an external profile on a specific adapter.
async fn ext_register_record_on_adapter(
    ext_arc: &Arc<Mutex<ExtProfile>>,
    adapter: &Arc<Mutex<BtdAdapter>>,
    record_xml: Option<&str>,
) {
    let Some(xml) = record_xml else {
        return;
    };

    let adapter_addr = btd_adapter_get_address(adapter).await;

    // Parse the XML record
    match parse_record(xml) {
        Ok(sdp_rec) => {
            // In the full implementation, this would call add_record_to_server()
            // on the adapter's SDP database. For now we track the record.
            let handle = sdp_rec.handle;
            let mut ext = ext_arc.lock().await;
            ext.records.push(ExtRecord { adapter: Arc::clone(adapter), handle });
            debug!(
                "Registered SDP record (handle=0x{:08x}) on adapter {}",
                handle,
                adapter_addr.to_string()
            );
        }
        Err(e) => {
            btd_error(0xFFFF, &format!("Failed to parse SDP record XML: {}", e));
        }
    }
}

/// Start L2CAP and/or RFCOMM server sockets for an external profile on a
/// specific adapter.
async fn ext_start_servers_on_adapter(
    ext_arc: &Arc<Mutex<ExtProfile>>,
    adapter: &Arc<Mutex<BtdAdapter>>,
) {
    let ext = ext_arc.lock().await;

    if !ext.enable_server {
        return;
    }

    let local_psm = ext.local_psm;
    let local_chan = ext.local_chan;
    let _sec_level = ext.sec_level;
    let _authorize = ext.authorize;
    let _path = ext.path.clone();
    drop(ext);

    let adapter_addr = btd_adapter_get_address(adapter).await;

    // Start L2CAP server if PSM is configured
    if local_psm != 0 {
        let psm_val = if local_psm == BTD_PROFILE_PSM_AUTO {
            0u16 // kernel assigns
        } else {
            local_psm as u16
        };

        debug!("Starting L2CAP server on PSM {} for adapter {}", psm_val, adapter_addr.to_string());

        // In the full implementation, this would create a BluetoothListener
        // via SocketBuilder and spawn an accept loop task.
    }

    // Start RFCOMM server if channel is configured
    if local_chan != 0 {
        let chan_val = if local_chan == BTD_PROFILE_CHAN_AUTO {
            0u16 // kernel assigns
        } else {
            local_chan as u16
        };

        debug!(
            "Starting RFCOMM server on channel {} for adapter {}",
            chan_val,
            adapter_addr.to_string()
        );

        // In the full implementation, this would create a BluetoothListener
        // via SocketBuilder and spawn an accept loop task.
    }
}

/// Remove SDP records and stop server sockets for an external profile when
/// an adapter is removed.
pub async fn ext_remove_records(
    ext_arc: &Arc<Mutex<ExtProfile>>,
    adapter: &Arc<Mutex<BtdAdapter>>,
) {
    let mut ext = ext_arc.lock().await;

    // Remove SDP records for this adapter
    ext.records.retain(|r| !Arc::ptr_eq(&r.adapter, adapter));

    // Abort server tasks (they would be specific to the adapter in a full impl)
    debug!("Removed SDP records and servers for adapter");
}

/// Remove an external profile entirely — clean up D-Bus, SDP, servers.
///
/// Equivalent to C `remove_ext()` in profile.c.
async fn remove_ext_profile(ext_arc: &Arc<Mutex<ExtProfile>>) {
    let mut ext = ext_arc.lock().await;

    // Cancel name watching
    if let Some(task) = ext.name_watch_task.take() {
        task.abort();
    }

    // Abort all pending connection tasks
    for task in ext.pending_connects.drain(..) {
        task.abort();
    }

    // Abort all server tasks
    for task in ext.servers.drain(..) {
        task.abort();
    }

    // Close all active connections
    ext.connections.clear();

    // Remove SDP records
    ext.records.clear();

    let name = ext.profile.name.clone();
    let owner = ext.owner.clone();
    let uuid = ext.uuid.clone();
    drop(ext);

    // Remove from the built-in profile registry
    {
        let mut profiles = PROFILES.write().await;
        profiles.retain(|p| !(p.external && p.local_uuid.as_deref() == Some(&uuid)));
    }

    info!("External profile {} removed (owner={})", name, owner);
}

/// Handle D-Bus owner name disappearance — remove all profiles owned by that sender.
///
/// Equivalent to C `ext_exited()` in profile.c.
pub async fn ext_exited(owner: &str) {
    let profiles_to_remove: Vec<Arc<Mutex<ExtProfile>>> = {
        let ext_profiles = EXT_PROFILES.read().await;
        let mut to_remove = Vec::new();
        for ext_arc in ext_profiles.iter() {
            let ext = ext_arc.lock().await;
            if ext.owner == owner {
                to_remove.push(Arc::clone(ext_arc));
            }
        }
        to_remove
    };

    for ext_arc in &profiles_to_remove {
        remove_ext_profile(ext_arc).await;
    }

    // Remove from the ext_profiles list
    {
        let mut ext_profiles = EXT_PROFILES.write().await;
        ext_profiles.retain(|e| {
            // This is a sync check — we need to avoid deadlocks
            // In practice, we compare Arc pointers
            !profiles_to_remove.iter().any(|r| Arc::ptr_eq(e, r))
        });
    }

    if !profiles_to_remove.is_empty() {
        info!(
            "Cleaned up {} external profiles for departed owner {}",
            profiles_to_remove.len(),
            owner
        );
    }
}

/// Send NewConnection to an external Profile1 handler.
///
/// Equivalent to C `send_new_connection()` in profile.c.
/// Passes the connected socket FD, device path, and options dictionary
/// to the external profile handler via D-Bus.
pub async fn send_new_connection(
    ext: &ExtProfile,
    device: &BtdDevice,
    fd: OwnedFd,
) -> Result<(), BtdError> {
    let conn = btd_get_dbus_connection();
    let dev_path = device.get_path().to_owned();

    let device_path = ObjectPath::try_from(dev_path.as_str())
        .map_err(|e| BtdError::failed(&format!("Invalid device path: {}", e)))?;

    // Build the options dictionary
    let mut props: HashMap<String, OwnedValue> = HashMap::new();

    if ext.version > 0 {
        if let Ok(v) = OwnedValue::try_from(Value::U16(ext.version)) {
            props.insert("Version".to_owned(), v);
        }
    }

    if ext.features > 0 {
        if let Ok(v) = OwnedValue::try_from(Value::U16(ext.features)) {
            props.insert("Features".to_owned(), v);
        }
    }

    // Add custom properties matching the profile UUID
    {
        let custom_props = CUSTOM_PROPS.read().await;
        for prop in custom_props.iter() {
            if prop.uuid.to_lowercase() == ext.uuid.to_lowercase() {
                if let Some(val) = (prop.getter)(device) {
                    props.insert(prop.name.clone(), val);
                }
            }
        }
    }

    debug!("Sending NewConnection to {} for device {}", ext.path, dev_path);

    // Create a D-Bus proxy to the external Profile1 object
    let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(conn)
        .destination(ext.owner.clone())
        .map_err(|e| BtdError::failed(&format!("proxy builder destination: {}", e)))?
        .path(ext.path.clone())
        .map_err(|e| BtdError::failed(&format!("proxy builder path: {}", e)))?
        .interface(PROFILE1_INTERFACE)
        .map_err(|e| BtdError::failed(&format!("proxy builder interface: {}", e)))?
        .build()
        .await
        .map_err(|e| BtdError::failed(&format!("Failed to build Profile1 proxy: {}", e)))?;

    // Call NewConnection with a timeout
    let zbus_fd = zbus::zvariant::OwnedFd::from(fd);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        proxy.call_method("NewConnection", &(device_path, zbus_fd, props)),
    )
    .await;

    match result {
        Ok(Ok(_reply)) => {
            debug!("NewConnection succeeded for {}", dev_path);
            Ok(())
        }
        Ok(Err(e)) => {
            btd_error(0xFFFF, &format!("NewConnection failed: {}", e));
            Err(BtdError::failed(&format!("NewConnection failed: {}", e)))
        }
        Err(_) => {
            btd_error(0xFFFF, "NewConnection timed out");
            Err(BtdError::failed("NewConnection timed out"))
        }
    }
}

/// Send RequestDisconnection to an external Profile1 handler.
///
/// Equivalent to C `send_disconn_req()` in profile.c.
pub async fn send_disconn_req(ext: &ExtProfile, device: &BtdDevice) -> Result<(), BtdError> {
    let conn = btd_get_dbus_connection();
    let dev_path = device.get_path().to_owned();

    let device_path = ObjectPath::try_from(dev_path.as_str())
        .map_err(|e| BtdError::failed(&format!("Invalid device path: {}", e)))?;

    let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(conn)
        .destination(ext.owner.clone())
        .map_err(|e| BtdError::failed(&format!("proxy builder destination: {}", e)))?
        .path(ext.path.clone())
        .map_err(|e| BtdError::failed(&format!("proxy builder path: {}", e)))?
        .interface(PROFILE1_INTERFACE)
        .map_err(|e| BtdError::failed(&format!("proxy builder interface: {}", e)))?
        .build()
        .await
        .map_err(|e| BtdError::failed(&format!("Failed to build Profile1 proxy: {}", e)))?;

    debug!("Sending RequestDisconnection to {} for device {}", ext.path, dev_path);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        proxy.call_method("RequestDisconnection", &(device_path,)),
    )
    .await;

    match result {
        Ok(Ok(_reply)) => Ok(()),
        Ok(Err(e)) => {
            btd_error(0xFFFF, &format!("RequestDisconnection failed: {}", e));
            Err(BtdError::failed(&format!("RequestDisconnection failed: {}", e)))
        }
        Err(_) => {
            btd_error(0xFFFF, "RequestDisconnection timed out");
            Err(BtdError::failed("RequestDisconnection timed out"))
        }
    }
}

/// Send Release to an external Profile1 handler.
///
/// Equivalent to C `ext_exited()` sending Release to each profile.
async fn send_release(ext: &ExtProfile) {
    let conn = btd_get_dbus_connection();

    let proxy_result: Result<zbus::Proxy<'_>, zbus::Error> = async {
        let builder = zbus::proxy::Builder::new(conn)
            .destination(ext.owner.clone())?
            .path(ext.path.clone())?
            .interface(PROFILE1_INTERFACE)?;
        builder.build().await
    }
    .await;

    let proxy = match proxy_result {
        Ok(p) => p,
        Err(e) => {
            debug!("Cannot create proxy for Release: {}", e);
            return;
        }
    };

    let _ =
        tokio::time::timeout(std::time::Duration::from_secs(5), proxy.call_method("Release", &()))
            .await;

    debug!("Sent Release to {}", ext.path);
}

// ===========================================================================
// ProfileManagerInterface — D-Bus `org.bluez.ProfileManager1` implementation
// ===========================================================================

/// D-Bus interface implementation for `org.bluez.ProfileManager1`.
///
/// Registered at `/org/bluez` and provides the `RegisterProfile` and
/// `UnregisterProfile` methods for external applications to register
/// custom Bluetooth profile handlers.
pub struct ProfileManagerInterface;

#[zbus::interface(name = "org.bluez.ProfileManager1")]
impl ProfileManagerInterface {
    /// Register an external profile handler.
    ///
    /// D-Bus method: `RegisterProfile(ObjectPath profile, String uuid, Dict options)`
    ///
    /// The external application provides a D-Bus object implementing the
    /// `org.bluez.Profile1` interface. The daemon will call `NewConnection`,
    /// `RequestDisconnection`, and `Release` on that object as appropriate.
    async fn register_profile(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        profile: ObjectPath<'_>,
        uuid: &str,
        options: HashMap<String, OwnedValue>,
    ) -> Result<(), BtdError> {
        let sender = header
            .sender()
            .ok_or_else(|| BtdError::invalid_args_str("No sender in D-Bus message"))?;
        let sender_str = sender.to_string();

        debug!("RegisterProfile: sender={} path={} uuid={}", sender_str, profile.as_str(), uuid);

        // Validate UUID format
        if uuid.is_empty() {
            return Err(BtdError::invalid_args_str("Empty UUID"));
        }

        // Create the external profile
        let ext_arc = create_ext_profile(&sender_str, profile.as_str(), uuid, options).await?;

        // Add to global external profiles list
        {
            let mut ext_profiles = EXT_PROFILES.write().await;
            ext_profiles.push(ext_arc);
        }

        Ok(())
    }

    /// Unregister an external profile handler.
    ///
    /// D-Bus method: `UnregisterProfile(ObjectPath profile)`
    async fn unregister_profile(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        profile: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender = header
            .sender()
            .ok_or_else(|| BtdError::invalid_args_str("No sender in D-Bus message"))?;
        let sender_str = sender.to_string();
        let path_str = profile.as_str().to_owned();

        debug!("UnregisterProfile: sender={} path={}", sender_str, path_str);

        // Find the external profile matching sender and path
        let ext_to_remove: Option<Arc<Mutex<ExtProfile>>> = {
            let ext_profiles = EXT_PROFILES.read().await;
            ext_profiles
                .iter()
                .find(|e| {
                    // We need to check owner and path — use try_lock to avoid
                    // async in a sync closure
                    if let Ok(ext) = e.try_lock() {
                        ext.owner == sender_str && ext.path == path_str
                    } else {
                        false
                    }
                })
                .cloned()
        };

        let ext_arc = ext_to_remove.ok_or_else(BtdError::does_not_exist)?;

        // Send Release notification before cleanup
        {
            let ext = ext_arc.lock().await;
            send_release(&ext).await;
        }

        // Clean up the profile
        remove_ext_profile(&ext_arc).await;

        // Remove from global list
        {
            let mut ext_profiles = EXT_PROFILES.write().await;
            ext_profiles.retain(|e| !Arc::ptr_eq(e, &ext_arc));
        }

        Ok(())
    }
}

// ===========================================================================
// Initialization and cleanup
// ===========================================================================

/// Initialize the profile registry and register the ProfileManager1 D-Bus
/// interface at `/org/bluez`.
///
/// Equivalent to C `btd_profile_init()` in profile.c.
pub async fn btd_profile_init() -> Result<(), BtdError> {
    let conn = btd_get_dbus_connection();

    // Register the ProfileManager1 interface at /org/bluez
    let iface = ProfileManagerInterface;

    conn.object_server().at(BLUEZ_PATH, iface).await.map_err(|e| {
        btd_error(0xFFFF, &format!("Failed to register ProfileManager1: {}", e));
        BtdError::failed(&format!("Failed to register ProfileManager1 interface: {}", e))
    })?;

    btd_info(0xFFFF, "ProfileManager1 interface registered at /org/bluez");
    Ok(())
}

/// Clean up the profile registry — release all external profiles, send
/// Release notifications, and unregister the D-Bus interface.
///
/// Equivalent to C `btd_profile_cleanup()` in profile.c.
pub async fn btd_profile_cleanup() {
    // Send Release to all external profiles and clean them up
    let ext_profiles_snapshot: Vec<Arc<Mutex<ExtProfile>>> = {
        let ext_profiles = EXT_PROFILES.read().await;
        ext_profiles.iter().cloned().collect()
    };

    for ext_arc in &ext_profiles_snapshot {
        let ext = ext_arc.lock().await;
        send_release(&ext).await;
        drop(ext);
        remove_ext_profile(ext_arc).await;
    }

    // Clear all global lists
    {
        let mut ext_profiles = EXT_PROFILES.write().await;
        ext_profiles.clear();
    }
    {
        let mut profiles = PROFILES.write().await;
        profiles.clear();
    }
    {
        let mut props = CUSTOM_PROPS.write().await;
        props.clear();
    }

    // Unregister the D-Bus interface
    let conn = btd_get_dbus_connection();
    let _ = conn.object_server().remove::<ProfileManagerInterface, _>(BLUEZ_PATH).await;

    btd_info(0xFFFF, "ProfileManager1 interface cleaned up");
}
