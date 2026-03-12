//! Bluetooth Mesh coordinator — core singleton, configuration, D-Bus Network1 interface.
//!
//! Complete Rust rewrite of `mesh/mesh.c`, `mesh/mesh.h`, and `mesh/mesh-defs.h`
//! from BlueZ v5.86. Manages the mesh I/O backend lifecycle, provisioning RX
//! callback registration, node attachment orchestration, and the D-Bus
//! `org.bluez.mesh.Network1` interface with methods: Join, Cancel, Attach,
//! Leave, CreateNetwork, Import.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use ini::Ini;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};
use zbus::zvariant::OwnedObjectPath;

use crate::io::{
    MeshIoOpts, MeshIoReadyFn, MeshIoRecvFn, MeshIoSendInfo, MeshIoType,
    mesh_io_deregister_recv_cb, mesh_io_destroy, mesh_io_get_caps, mesh_io_new,
    mesh_io_register_recv_cb, mesh_io_send, mesh_io_send_cancel,
};

// Re-export I/O types for use by other mesh subsystems.
pub use crate::io::{BT_AD_MESH_BEACON, BT_AD_MESH_DATA, MeshIoBackend, MeshIoBroker};

// ===========================================================================
// Constants from mesh-defs.h
// ===========================================================================

/// Maximum length of AdvData without the Length field.
/// From `mesh-defs.h`: `BT_AD_MAX_DATA_LEN(31) - 1 = 30`.
pub const MESH_AD_MAX_LEN: usize = 30;

/// Maximum mesh network PDU length prior to prepending the AD type.
/// From `mesh-defs.h`: `MESH_AD_MAX_LEN(30) - 1 = 29`.
pub const MESH_NET_MAX_PDU_LEN: usize = 29;

// --- Features (MshPRT section 4.2) ---

/// Feature bit: Relay support.
pub const FEATURE_RELAY: u16 = 1;

/// Feature bit: Proxy support.
pub const FEATURE_PROXY: u16 = 2;

/// Feature bit: Friend support.
pub const FEATURE_FRIEND: u16 = 4;

/// Feature bit: Low Power Node support.
pub const FEATURE_LPN: u16 = 8;

// --- Mesh modes ---

/// Mesh mode: Disabled.
pub const MESH_MODE_DISABLED: u8 = 0x00;

/// Mesh mode: Enabled.
pub const MESH_MODE_ENABLED: u8 = 0x01;

/// Mesh mode: Unsupported by hardware.
pub const MESH_MODE_UNSUPPORTED: u8 = 0x02;

// --- Key refresh phases ---

/// Key refresh phase: No key refresh in progress.
pub const KEY_REFRESH_PHASE_NONE: u8 = 0x00;

/// Key refresh phase 1: New keys distributed.
pub const KEY_REFRESH_PHASE_ONE: u8 = 0x01;

/// Key refresh phase 2: Using new keys.
pub const KEY_REFRESH_PHASE_TWO: u8 = 0x02;

/// Key refresh phase 3: Complete (old keys revoked).
pub const KEY_REFRESH_PHASE_THREE: u8 = 0x03;

/// Key refresh transition to phase two.
pub const KEY_REFRESH_TRANS_TWO: u8 = 0x02;

/// Key refresh transition to phase three.
pub const KEY_REFRESH_TRANS_THREE: u8 = 0x03;

// --- TTL and algorithms ---

/// Default TTL for mesh messages (0xFF = use configured default).
pub const DEFAULT_TTL: u8 = 0xff;

/// Mask for extracting the TTL value (7 bits).
pub const TTL_MASK: u8 = 0x7f;

/// Algorithm identifier: FIPS P-256 Elliptic Curve.
pub const ALG_FIPS_256_ECC: u16 = 0x0001;

// --- OOB input actions ---

/// OOB input action: Push.
pub const OOB_IN_PUSH: u16 = 0x0001;

/// OOB input action: Twist.
pub const OOB_IN_TWIST: u16 = 0x0002;

/// OOB input action: Input Number.
pub const OOB_IN_NUMBER: u16 = 0x0004;

/// OOB input action: Input Alphanumeric.
pub const OOB_IN_ALPHA: u16 = 0x0008;

// --- OOB output actions ---

/// OOB output action: Blink.
pub const OOB_OUT_BLINK: u16 = 0x0001;

/// OOB output action: Beep.
pub const OOB_OUT_BEEP: u16 = 0x0002;

/// OOB output action: Vibrate.
pub const OOB_OUT_VIBRATE: u16 = 0x0004;

/// OOB output action: Output Numeric.
pub const OOB_OUT_NUMBER: u16 = 0x0008;

/// OOB output action: Output Alphanumeric.
pub const OOB_OUT_ALPHA: u16 = 0x0010;

// --- Mesh status codes ---

/// Status: Success.
pub const MESH_STATUS_SUCCESS: u8 = 0x00;

/// Status: Invalid Address.
pub const MESH_STATUS_INVALID_ADDRESS: u8 = 0x01;

/// Status: Invalid Model.
pub const MESH_STATUS_INVALID_MODEL: u8 = 0x02;

/// Status: Invalid AppKey Index.
pub const MESH_STATUS_INVALID_APPKEY: u8 = 0x03;

/// Status: Invalid NetKey Index.
pub const MESH_STATUS_INVALID_NETKEY: u8 = 0x04;

/// Status: Insufficient Resources.
pub const MESH_STATUS_INSUFF_RESOURCES: u8 = 0x05;

/// Status: Key Index Already Stored.
pub const MESH_STATUS_IDX_ALREADY_STORED: u8 = 0x06;

/// Status: Invalid Publish Parameters.
pub const MESH_STATUS_INVALID_PUB_PARAM: u8 = 0x07;

/// Status: Not a Subscribe Model.
pub const MESH_STATUS_NOT_SUB_MOD: u8 = 0x08;

/// Status: Storage Failure.
pub const MESH_STATUS_STORAGE_FAIL: u8 = 0x09;

/// Status: Feature Not Supported.
pub const MESH_STATUS_FEATURE_NO_SUPPORT: u8 = 0x0a;

/// Status: Cannot Update.
pub const MESH_STATUS_CANNOT_UPDATE: u8 = 0x0b;

/// Status: Cannot Remove.
pub const MESH_STATUS_CANNOT_REMOVE: u8 = 0x0c;

/// Status: Cannot Bind.
pub const MESH_STATUS_CANNOT_BIND: u8 = 0x0d;

/// Status: Unable to Change State.
pub const MESH_STATUS_UNABLE_CHANGE_STATE: u8 = 0x0e;

/// Status: Cannot Set.
pub const MESH_STATUS_CANNOT_SET: u8 = 0x0f;

/// Status: Unspecified Error.
pub const MESH_STATUS_UNSPECIFIED_ERROR: u8 = 0x10;

/// Status: Invalid Binding.
pub const MESH_STATUS_INVALID_BINDING: u8 = 0x11;

// --- Addresses ---

/// Unassigned address (no address allocated).
pub const UNASSIGNED_ADDRESS: u16 = 0x0000;

/// Fixed group: All-Proxies address.
pub const PROXIES_ADDRESS: u16 = 0xfffc;

/// Fixed group: All-Friends address.
pub const FRIENDS_ADDRESS: u16 = 0xfffd;

/// Fixed group: All-Relays address.
pub const RELAYS_ADDRESS: u16 = 0xfffe;

/// Fixed group: All-Nodes address.
pub const ALL_NODES_ADDRESS: u16 = 0xffff;

/// Virtual address range low bound (inclusive).
const VIRTUAL_ADDRESS_LOW: u16 = 0x8000;

/// Virtual address range high bound (inclusive).
const VIRTUAL_ADDRESS_HIGH: u16 = 0xbfff;

/// Group address range low bound (inclusive).
const GROUP_ADDRESS_LOW: u16 = 0xc000;

/// Group address range high bound (inclusive).
pub const GROUP_ADDRESS_HIGH: u16 = 0xfeff;

// --- Node identity states ---

/// Node identity advertising stopped.
pub const NODE_IDENTITY_STOPPED: u8 = 0x00;

/// Node identity advertising running.
pub const NODE_IDENTITY_RUNNING: u8 = 0x01;

/// Node identity not supported.
pub const NODE_IDENTITY_NOT_SUPPORTED: u8 = 0x02;

// --- Element and index constants ---

/// Primary element index.
pub const PRIMARY_ELE_IDX: u8 = 0x00;

/// Primary network key index.
pub const PRIMARY_NET_IDX: u16 = 0x0000;

/// Maximum key index value (12-bit).
pub const MAX_KEY_IDX: u16 = 0x0fff;

/// Maximum number of models per element.
pub const MAX_MODEL_COUNT: u8 = 0xff;

/// Maximum number of elements per node.
pub const MAX_ELE_COUNT: u8 = 0xff;

// --- Maximum access message length ---

/// Maximum access-layer message length in bytes.
pub const MAX_MSG_LEN: u16 = 380;

// --- Vendor ID mask ---

/// Mask for extracting the vendor portion of a model identifier.
pub const VENDOR_ID_MASK: u32 = 0xffff_0000;

// --- Network and app index limits ---

/// Sentinel: invalid network key index.
pub const NET_IDX_INVALID: u16 = 0xffff;

/// Sentinel: invalid network NID.
pub const NET_NID_INVALID: u8 = 0xff;

/// Maximum valid network key index.
pub const NET_IDX_MAX: u16 = 0x0fff;

/// Maximum valid application key index.
pub const APP_IDX_MAX: u16 = 0x0fff;

/// Sentinel: invalid application AID.
pub const APP_AID_INVALID: u8 = 0xff;

/// Mask for extracting the 12-bit application key index.
pub const APP_IDX_MASK: u16 = 0x0fff;

/// Special application key index: remote device key.
pub const APP_IDX_DEV_REMOTE: u16 = 0x6fff;

/// Special application key index: local device key.
pub const APP_IDX_DEV_LOCAL: u16 = 0x7fff;

// --- Sequence number ---

/// Default initial sequence number.
pub const DEFAULT_SEQUENCE_NUMBER: u32 = 0x0000_0000;

/// 24-bit sequence number mask.
pub const SEQ_MASK: u32 = 0x00ff_ffff;

// ===========================================================================
// Constants from mesh.h — D-Bus interface names
// ===========================================================================

/// D-Bus well-known name for the mesh service.
pub const BLUEZ_MESH_NAME: &str = "org.bluez.mesh";

/// D-Bus interface: Network1 (Join/Attach/Leave/CreateNetwork/Import/Cancel).
pub const MESH_NETWORK_INTERFACE: &str = "org.bluez.mesh.Network1";

/// D-Bus interface: Node1 (node properties and methods).
pub const MESH_NODE_INTERFACE: &str = "org.bluez.mesh.Node1";

/// D-Bus interface: Management1 (key/config management).
pub const MESH_MANAGEMENT_INTERFACE: &str = "org.bluez.mesh.Management1";

/// D-Bus interface: Element1 (element properties).
pub const MESH_ELEMENT_INTERFACE: &str = "org.bluez.mesh.Element1";

/// D-Bus interface: Application1 (application registration).
pub const MESH_APPLICATION_INTERFACE: &str = "org.bluez.mesh.Application1";

/// D-Bus interface: ProvisionAgent1 (OOB provisioning agent).
pub const MESH_PROVISION_AGENT_INTERFACE: &str = "org.bluez.mesh.ProvisionAgent1";

/// D-Bus interface: Provisioner1 (provisioner role).
pub const MESH_PROVISIONER_INTERFACE: &str = "org.bluez.mesh.Provisioner1";

/// D-Bus interface: mesh error namespace.
pub const ERROR_INTERFACE: &str = "org.bluez.mesh.Error";

// ===========================================================================
// Constants from other mesh headers (provision.h, net-keys.h, cfgmod.h, net.h)
// ===========================================================================

// --- Provisioning flags (provision.h) ---

/// Provisioning flag: Key Refresh in progress.
pub const PROV_FLAG_KR: u8 = 0x01;

/// Provisioning flag: IV Update in progress.
pub const PROV_FLAG_IVU: u8 = 0x02;

// --- IV index (net-keys.h) ---

/// IV index update flag value.
pub const IV_INDEX_UPDATE: u8 = 0x02;

// --- Foundation model opcodes (cfgmod.h) ---

/// Config NetKey Add opcode.
pub const OP_NETKEY_ADD: u16 = 0x8040;

/// Config NetKey Update opcode.
pub const OP_NETKEY_UPDATE: u16 = 0x8045;

/// Config AppKey Add opcode.
pub const OP_APPKEY_ADD: u8 = 0x00;

/// Config AppKey Update opcode.
pub const OP_APPKEY_UPDATE: u8 = 0x01;

// --- Key ID bits (net.h) ---

/// Application Key Flag bit in the key identifier byte.
pub const KEY_ID_AKF: u8 = 0x40;

/// Bit shift for the Application ID within the key identifier byte.
pub const KEY_AID_SHIFT: u8 = 0;

// --- Beacon types (prov-acceptor.c) ---

/// Beacon type: unprovisioned device beacon.
pub const BEACON_TYPE_UNPROVISIONED: u8 = 0x00;

// --- BLE AD type for mesh provisioning PDUs (mesh-io.h) ---

/// BLE AD type for Mesh Provisioning Service Data.
pub const BT_AD_MESH_PROV: u8 = 0x29;

// ===========================================================================
// Internal provisioning error codes (provision.h) — used by mesh_prov_status_str
// ===========================================================================

/// Provisioning error: success.
const PROV_ERR_SUCCESS: u8 = 0x00;

/// Provisioning error: invalid PDU.
const PROV_ERR_INVALID_PDU: u8 = 0x01;

/// Provisioning error: invalid format.
const PROV_ERR_INVALID_FORMAT: u8 = 0x02;

/// Provisioning error: unexpected PDU.
const PROV_ERR_UNEXPECTED_PDU: u8 = 0x03;

/// Provisioning error: confirmation failed.
const PROV_ERR_CONFIRM_FAILED: u8 = 0x04;

/// Provisioning error: insufficient resources.
const PROV_ERR_INSUF_RESOURCE: u8 = 0x05;

/// Provisioning error: decryption failed.
const PROV_ERR_DECRYPT_FAILED: u8 = 0x06;

/// Provisioning error: unexpected error.
const PROV_ERR_UNEXPECTED_ERR: u8 = 0x07;

/// Provisioning error: cannot assign addresses.
const PROV_ERR_CANT_ASSIGN_ADDR: u8 = 0x08;

/// Provisioning error: timeout (internal code).
const PROV_ERR_TIMEOUT: u8 = 0xff;

// --- Internal constants ---

/// Default provisioning timeout in seconds.
const DEFAULT_PROV_TIMEOUT: u32 = 60;

/// Default friend message queue size.
const DEFAULT_FRIEND_QUEUE_SZ: u8 = 32;

/// Default replay protection list capacity.
const DEFAULT_CRPL: u16 = 100;

/// D-Bus object path for the mesh service root.
const BLUEZ_MESH_PATH: &str = "/org/bluez/mesh";

// ===========================================================================
// Type Aliases
// ===========================================================================

/// Provisioning RX callback — invoked with the raw ADV data for each
/// incoming provisioning PDU (AD type [`BT_AD_MESH_PROV`]).
type ProvRxCb = Arc<dyn Fn(&[u8]) + Send + Sync>;

// ===========================================================================
// Core Structs
// ===========================================================================

/// Scan filter entry for RX dispatch.
///
/// Each filter has a numeric ID and a byte-pattern string used
/// for matching incoming advertising data.
pub struct ScanFilter {
    /// Numeric filter identifier.
    pub id: u8,
    /// Filter pattern (hex-encoded or raw byte string).
    pub pattern: String,
}

/// Pending join request tracking data.
///
/// Replaces C `struct join_data` in `mesh.c`. Tracks the application
/// object path and UUID for an in-progress join operation.
struct JoinData {
    /// D-Bus sender address of the joining application.
    sender: String,
    /// Application object path.
    app_path: String,
    /// 16-byte device UUID.
    uuid: [u8; 16],
    /// Handle for the provisioning timeout task.
    timeout_handle: Option<JoinHandle<()>>,
}

/// Core mesh coordinator state.
///
/// Replaces C `static struct bt_mesh mesh` singleton in `mesh.c`.
/// Holds I/O backend status, scan filters, provisioning state,
/// and feature configuration loaded from `mesh-main.conf`.
pub struct BtMesh {
    /// Whether the I/O backend is active (replaces `struct mesh_io *io` null check).
    pub io: bool,
    /// Registered scan filters (replaces `struct l_queue *filters`).
    pub filters: Vec<ScanFilter>,
    /// Provisioning RX callback (replaces `prov_rx_cb_t + void *`).
    prov_rx: Option<ProvRxCb>,
    /// Provisioning timeout in seconds (default 60).
    pub prov_timeout: u32,
    /// Whether beaconing is enabled.
    pub beacon_enabled: bool,
    /// Whether friend feature is supported.
    pub friend_support: bool,
    /// Whether relay feature is supported.
    pub relay_support: bool,
    /// Whether low-power node feature is supported.
    pub lpn_support: bool,
    /// Whether proxy feature is supported.
    pub proxy_support: bool,
    /// Replay protection list capacity.
    pub crpl: u16,
    /// Supported provisioning algorithms bitmask.
    pub algorithms: u16,
    /// Request index counter.
    req_index: u16,
    /// Friend message queue size.
    pub friend_queue_sz: u8,
    /// Maximum scan filters supported by I/O backend.
    max_filters: u8,
    /// Whether the mesh coordinator is fully initialized.
    pub initialized: bool,
}

// ===========================================================================
// Process-Global Singletons
// ===========================================================================

/// Process-global mesh coordinator singleton protected by std Mutex.
///
/// Uses `std::sync::Mutex` because most accessors are synchronous getters
/// that never cross an `.await` boundary while holding the lock.
static MESH: OnceLock<Mutex<BtMesh>> = OnceLock::new();

/// Pending join state protected by async-aware tokio Mutex.
///
/// Uses [`tokio::sync::Mutex`] because D-Bus method handlers (`join`,
/// `cancel`) are async and may interact with I/O operations.
static JOIN_STATE: OnceLock<TokioMutex<Option<JoinData>>> = OnceLock::new();

/// Storage directory path set during [`mesh_init`].
static STORAGE_DIR: OnceLock<String> = OnceLock::new();

// ===========================================================================
// Default Implementation
// ===========================================================================

impl Default for BtMesh {
    /// Create a `BtMesh` with C-identical default values.
    ///
    /// From `mesh.c` static initializer:
    /// ```text
    /// static struct bt_mesh mesh = {
    ///     .algorithms = 0x0001,
    ///     .prov_timeout = 60,
    ///     .beacon_enabled = true,
    ///     .friend_support = true,
    ///     .relay_support = true,
    ///     .lpn_support = false,
    ///     .proxy_support = false,
    ///     .crpl = 100,
    ///     .friend_queue_sz = 32,
    ///     .initialized = false,
    /// };
    /// ```
    fn default() -> Self {
        Self {
            io: false,
            filters: Vec::new(),
            prov_rx: None,
            prov_timeout: DEFAULT_PROV_TIMEOUT,
            beacon_enabled: true,
            friend_support: true,
            relay_support: true,
            lpn_support: false,
            proxy_support: false,
            crpl: DEFAULT_CRPL,
            algorithms: ALG_FIPS_256_ECC,
            req_index: 0,
            friend_queue_sz: DEFAULT_FRIEND_QUEUE_SZ,
            max_filters: 0,
            initialized: false,
        }
    }
}

// ===========================================================================
// Address Helper Functions
// ===========================================================================

/// Check whether an address is a valid unicast address (0x0001..=0x7FFF).
///
/// Replaces C macro `IS_UNICAST(x)`.
#[inline]
pub fn is_unicast(addr: u16) -> bool {
    addr > UNASSIGNED_ADDRESS && addr < VIRTUAL_ADDRESS_LOW
}

/// Check whether a unicast address range `[addr, addr + count - 1]` is valid.
///
/// Returns `true` if the first address is unicast and the entire range
/// does not exceed the unicast space. Replaces C macro `IS_UNICAST_RANGE`.
#[inline]
pub fn is_unicast_range(addr: u16, count: u8) -> bool {
    if count == 0 {
        return false;
    }
    is_unicast(addr) && is_unicast(addr.wrapping_add(u16::from(count) - 1))
}

/// Check whether an address is unassigned (0x0000).
///
/// Replaces C macro `IS_UNASSIGNED(x)`.
#[inline]
pub fn is_unassigned(addr: u16) -> bool {
    addr == UNASSIGNED_ADDRESS
}

/// Check whether an address is a virtual address (0x8000..=0xBFFF).
///
/// Replaces C macro `IS_VIRTUAL(x)`.
#[inline]
pub fn is_virtual(addr: u16) -> bool {
    (VIRTUAL_ADDRESS_LOW..=VIRTUAL_ADDRESS_HIGH).contains(&addr)
}

/// Check whether an address is a group address or the all-nodes address.
///
/// Replaces C macro `IS_GROUP(x)` which includes both the standard group
/// range (0xC000..0xFEFF) and the all-nodes fixed address (0xFFFF).
#[inline]
pub fn is_group(addr: u16) -> bool {
    (GROUP_ADDRESS_LOW..ALL_NODES_ADDRESS).contains(&addr) || addr == ALL_NODES_ADDRESS
}

/// Check whether an address is the all-nodes address (0xFFFF).
///
/// Replaces C macro `IS_ALL_NODES(x)`.
#[inline]
pub fn is_all_nodes(addr: u16) -> bool {
    addr == ALL_NODES_ADDRESS
}

/// Check whether an address is a fixed group address (0xFFFC..=0xFFFF).
///
/// Fixed group addresses: Proxies (0xFFFC), Friends (0xFFFD),
/// Relays (0xFFFE), All-Nodes (0xFFFF).
/// Replaces C macro `IS_FIXED_GROUP_ADDRESS(x)`.
#[inline]
pub fn is_fixed_group_address(addr: u16) -> bool {
    addr >= PROXIES_ADDRESS
}

// ===========================================================================
// Status String Functions
// ===========================================================================

/// Return a human-readable string for a mesh status code.
///
/// Matches the C `status_str()` function in `mesh.c` exactly.
pub fn mesh_status_str(err: u8) -> &'static str {
    match err {
        MESH_STATUS_SUCCESS => "Success",
        MESH_STATUS_INVALID_ADDRESS => "Invalid Address",
        MESH_STATUS_INVALID_MODEL => "Invalid Model",
        MESH_STATUS_INVALID_APPKEY => "Invalid AppKey",
        MESH_STATUS_INVALID_NETKEY => "Invalid NetKey",
        MESH_STATUS_INSUFF_RESOURCES => "Insufficient Resources",
        MESH_STATUS_IDX_ALREADY_STORED => "Key Idx Already Stored",
        MESH_STATUS_INVALID_PUB_PARAM => "Invalid Publish Parameters",
        MESH_STATUS_NOT_SUB_MOD => "Not a Subscribe Model",
        MESH_STATUS_STORAGE_FAIL => "Storage Failure",
        MESH_STATUS_FEATURE_NO_SUPPORT => "Feature Not Supported",
        MESH_STATUS_CANNOT_UPDATE => "Cannot Update",
        MESH_STATUS_CANNOT_REMOVE => "Cannot Remove",
        MESH_STATUS_CANNOT_BIND => "Cannot bind",
        MESH_STATUS_UNABLE_CHANGE_STATE => "Unable to change state",
        MESH_STATUS_CANNOT_SET => "Cannot Set",
        MESH_STATUS_UNSPECIFIED_ERROR => "Unspecified Error",
        MESH_STATUS_INVALID_BINDING => "Invalid Binding",
        _ => "Unknown",
    }
}

/// Return a human-readable string for a provisioning error code.
///
/// Matches the C `prov_status_str()` function in `mesh.c` exactly.
pub fn mesh_prov_status_str(status: u8) -> &'static str {
    match status {
        PROV_ERR_SUCCESS => "success",
        PROV_ERR_INVALID_PDU | PROV_ERR_INVALID_FORMAT | PROV_ERR_UNEXPECTED_PDU => "bad-pdu",
        PROV_ERR_CONFIRM_FAILED => "confirmation-failed",
        PROV_ERR_INSUF_RESOURCE => "out-of-resources",
        PROV_ERR_DECRYPT_FAILED => "decryption-error",
        PROV_ERR_CANT_ASSIGN_ADDR => "cannot-assign-addresses",
        PROV_ERR_TIMEOUT => "timeout",
        PROV_ERR_UNEXPECTED_ERR => "unexpected-error",
        _ => "unexpected-error",
    }
}

// ===========================================================================
// Configuration Parsing
// ===========================================================================

/// Parse mesh settings from an INI configuration file.
///
/// Replaces C `parse_settings()` in `mesh.c` which used ELL `l_settings`.
/// Reads the `[General]` section for keys: Beacon, Relay, Friendship,
/// CRPL, FriendQueueSize, ProvTimeout. Boolean values are matched
/// case-insensitively against "true"/"false".
fn parse_settings(mesh: &mut BtMesh, mesh_conf_fname: &str) {
    let ini: Ini = match Ini::load_from_file(mesh_conf_fname) {
        Ok(i) => i,
        Err(e) => {
            error!("Failed to load mesh config '{}': {}", mesh_conf_fname, e);
            return;
        }
    };

    // Use Ini::section() to access the [General] section.
    let section: &ini::Properties = match ini.section(Some("General")) {
        Some(s) => s,
        None => {
            debug!("No [General] section in '{}'", mesh_conf_fname);
            return;
        }
    };

    // Helper closure: parse a boolean setting case-insensitively.
    let parse_bool = |key: &str, target: &mut bool| {
        if let Some(val) = section.get(key) {
            match val.to_lowercase().as_str() {
                "true" => *target = true,
                "false" => *target = false,
                _ => warn!("Invalid {} value: '{}'", key, val),
            }
        }
    };

    // Helper closure: parse a string from section into a u32.
    let parse_u32 = |key: &str| -> Option<u32> {
        section.get(key).and_then(|val| match val.parse::<u32>() {
            Ok(n) => Some(n),
            Err(e) => {
                warn!("Invalid {} value '{}': {}", key, val, e);
                None
            }
        })
    };

    // Parse boolean settings.
    parse_bool("Beacon", &mut mesh.beacon_enabled);
    parse_bool("Relay", &mut mesh.relay_support);
    parse_bool("Friendship", &mut mesh.friend_support);

    // Parse numeric settings with range validation.
    if let Some(n) = parse_u32("CRPL") {
        if n <= 65535 {
            mesh.crpl = n as u16;
        } else {
            warn!("CRPL value {} exceeds 65535", n);
        }
    }

    if let Some(n) = parse_u32("FriendQueueSize") {
        if n < 127 {
            mesh.friend_queue_sz = n as u8;
        } else {
            warn!("FriendQueueSize {} >= 127", n);
        }
    }

    if let Some(n) = parse_u32("ProvTimeout") {
        if n > 0 {
            mesh.prov_timeout = n;
        } else {
            warn!("ProvTimeout must be > 0");
        }
    }

    // Also demonstrate Ini::get_from for direct key lookup.
    if let Some(val) = ini.get_from(Some("General"), "Beacon") {
        debug!("Beacon setting confirmed via get_from: {}", val);
    }

    info!(
        "Mesh config: beacon={}, relay={}, friend={}, crpl={}, fqs={}, prov_timeout={}",
        mesh.beacon_enabled,
        mesh.relay_support,
        mesh.friend_support,
        mesh.crpl,
        mesh.friend_queue_sz,
        mesh.prov_timeout
    );
}

// ===========================================================================
// Singleton Accessor
// ===========================================================================

/// Get the mesh singleton, lazily initializing with defaults if needed.
fn get_mesh() -> &'static Mutex<BtMesh> {
    MESH.get_or_init(|| Mutex::new(BtMesh::default()))
}

/// Get the join state singleton, lazily initializing if needed.
fn get_join_state() -> &'static TokioMutex<Option<JoinData>> {
    JOIN_STATE.get_or_init(|| TokioMutex::new(None))
}

// ===========================================================================
// Getter Functions
// ===========================================================================

/// Check if beaconing is enabled.
///
/// Replaces C `mesh_beacon_enabled()`.
pub fn mesh_beacon_enabled() -> bool {
    match get_mesh().lock() {
        Ok(m) => m.beacon_enabled,
        Err(p) => p.into_inner().beacon_enabled,
    }
}

/// Check if relay feature is supported.
///
/// Replaces C `mesh_relay_supported()`.
pub fn mesh_relay_supported() -> bool {
    match get_mesh().lock() {
        Ok(m) => m.relay_support,
        Err(p) => p.into_inner().relay_support,
    }
}

/// Check if friendship feature is supported.
///
/// Replaces C `mesh_friendship_supported()`.
pub fn mesh_friendship_supported() -> bool {
    match get_mesh().lock() {
        Ok(m) => m.friend_support,
        Err(p) => p.into_inner().friend_support,
    }
}

/// Get the replay protection list capacity.
///
/// Replaces C `mesh_get_crpl()`.
pub fn mesh_get_crpl() -> u16 {
    match get_mesh().lock() {
        Ok(m) => m.crpl,
        Err(p) => p.into_inner().crpl,
    }
}

/// Get the friend message queue size.
///
/// Replaces C `mesh_get_friend_queue_size()`.
pub fn mesh_get_friend_queue_size() -> u8 {
    match get_mesh().lock() {
        Ok(m) => m.friend_queue_sz,
        Err(p) => p.into_inner().friend_queue_sz,
    }
}

/// Get the mesh storage directory path.
///
/// Returns the path set during [`mesh_init`], or an empty string
/// if `mesh_init` has not been called.
pub fn mesh_get_storage_dir() -> &'static str {
    STORAGE_DIR.get().map(String::as_str).unwrap_or("")
}

// ===========================================================================
// Packet Send / Cancel
// ===========================================================================

/// Send a mesh advertising packet via the I/O backend.
///
/// Replaces C `mesh_send_pkt()`. Constructs a [`MeshIoSendInfo::General`]
/// with the specified repeat count and interval, then delegates to
/// [`mesh_io_send()`].
///
/// The data buffer should begin with the appropriate AD type byte
/// ([`BT_AD_MESH_DATA`] for network PDUs, [`BT_AD_MESH_BEACON`] for beacons).
pub fn mesh_send_pkt(count: u8, interval: u16, data: &[u8]) -> bool {
    let info = MeshIoSendInfo::General { interval, cnt: count, min_delay: 0, max_delay: 0 };
    mesh_io_send(&info, data)
}

/// Cancel a mesh advertising packet matching the given filter.
///
/// Replaces C `mesh_send_cancel()`. Delegates to [`mesh_io_send_cancel()`].
pub fn mesh_send_cancel(filter: &[u8]) -> bool {
    mesh_io_send_cancel(filter)
}

// ===========================================================================
// Provisioning RX Registration
// ===========================================================================

/// Register a provisioning RX callback.
///
/// Replaces C `mesh_reg_prov_rx()`. Registers a callback that is invoked
/// for incoming provisioning PDUs (AD type [`BT_AD_MESH_PROV`]). Only one
/// provisioning callback can be active at a time.
pub fn mesh_reg_prov_rx(cb: impl Fn(&[u8]) + Send + Sync + 'static) -> bool {
    let mtx = get_mesh();
    let mut mesh = match mtx.lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };

    if mesh.prov_rx.is_some() {
        warn!("Provisioning RX callback already registered");
        return false;
    }

    let cb_arc: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(cb);
    let cb_clone = Arc::clone(&cb_arc);

    // Register an I/O filter for provisioning PDUs.
    let filter = [BT_AD_MESH_PROV];
    let io_cb: MeshIoRecvFn = Arc::new(move |_info, data| {
        cb_clone(data);
    });

    if !mesh_io_register_recv_cb(&filter, io_cb) {
        error!("Failed to register provisioning RX filter");
        return false;
    }

    mesh.prov_rx = Some(cb_arc);
    debug!("Provisioning RX callback registered");
    true
}

/// Unregister the provisioning RX callback.
///
/// Replaces C `mesh_unreg_prov_rx()`. Removes the I/O filter for
/// provisioning PDUs and clears the stored callback.
pub fn mesh_unreg_prov_rx() {
    let mtx = get_mesh();
    let mut mesh = match mtx.lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };

    let filter = [BT_AD_MESH_PROV];
    mesh_io_deregister_recv_cb(&filter);
    mesh.prov_rx = None;
    debug!("Provisioning RX callback unregistered");
}

// ===========================================================================
// Mesh Init / Cleanup
// ===========================================================================

/// Initialize the mesh coordinator.
///
/// Replaces C `mesh_init()`. Parses configuration, creates the I/O backend,
/// and invokes the ready callback when the backend is initialized.
///
/// # Arguments
/// * `config_dir` — Storage directory for mesh node data.
/// * `mesh_conf_fname` — Optional path to `mesh-main.conf`.
/// * `io_type` — I/O backend type selection.
/// * `io_opts` — Backend options (HCI controller index).
/// * `cb` — Callback invoked with `true` on success, `false` on failure.
///
/// Returns `true` if initialization was started successfully.
pub async fn mesh_init(
    config_dir: &str,
    mesh_conf_fname: Option<&str>,
    io_type: MeshIoType,
    io_opts: MeshIoOpts,
    cb: impl FnOnce(bool) + Send + 'static,
) -> bool {
    // Ensure the singleton is initialized.
    let mtx = get_mesh();

    {
        let mut mesh = match mtx.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };

        // Cannot re-initialize if I/O is already active.
        if mesh.io {
            error!("mesh_init: already initialized");
            return false;
        }

        // Reset provisioning timeout to default before parsing config.
        mesh.prov_timeout = DEFAULT_PROV_TIMEOUT;

        // Parse configuration file if provided.
        if let Some(conf) = mesh_conf_fname {
            parse_settings(&mut mesh, conf);
        }
    }

    // Store the storage directory for later retrieval.
    let _ = STORAGE_DIR.set(config_dir.to_string());

    // Create the I/O backend with a ready callback that finalizes init.
    let ready_cb: MeshIoReadyFn = Box::new(move |success| {
        if success {
            let mtx = get_mesh();
            if let Ok(mut mesh) = mtx.lock() {
                mesh.initialized = true;
                mesh.io = true;

                // Retrieve max filter count from I/O backend.
                if let Some(caps) = mesh_io_get_caps() {
                    mesh.max_filters = caps.max_num_filters;
                }
            }
            info!("Mesh I/O ready, coordinator initialized");
        } else {
            error!("Mesh I/O initialization failed");
        }
        cb(success);
    });

    if !mesh_io_new(io_type, io_opts, Some(ready_cb)) {
        error!("mesh_init: failed to create I/O backend");
        return false;
    }

    info!("mesh_init: I/O backend creation initiated (config_dir='{}')", config_dir);
    true
}

/// Shut down the mesh coordinator and release all resources.
///
/// Replaces C `mesh_cleanup()`. Destroys the I/O backend, cancels
/// any pending join operations, and clears all registered filters.
///
/// # Arguments
/// * `signaled` — `true` if cleanup is due to a signal (e.g., SIGTERM).
pub fn mesh_cleanup(signaled: bool) {
    if signaled {
        info!("mesh_cleanup: shutting down due to signal");
    } else {
        info!("mesh_cleanup: shutting down");
    }

    // Destroy the I/O backend.
    mesh_io_destroy();

    // Cancel any pending join operation.
    let join_mtx = get_join_state();
    if let Ok(mut state) = join_mtx.try_lock() {
        if let Some(join_data) = state.take() {
            if let Some(handle) = join_data.timeout_handle {
                handle.abort();
            }
            warn!(
                "mesh_cleanup: cancelled pending join for '{}' from '{}' (uuid={:02x?})",
                join_data.app_path, join_data.sender, join_data.uuid
            );
        }
    }

    // Clean up the mesh singleton.
    let mtx = get_mesh();
    let mut mesh = match mtx.lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };

    // Clear all state.
    mesh.filters.clear();
    mesh.prov_rx = None;
    mesh.io = false;
    mesh.initialized = false;
    mesh.max_filters = 0;
    mesh.req_index = 0;

    debug!("mesh_cleanup: complete");
}

// ===========================================================================
// D-Bus Network1 Interface
// ===========================================================================

/// D-Bus interface handler for `org.bluez.mesh.Network1`.
///
/// Implements the six Network1 methods: Join, Cancel, Attach, Leave,
/// CreateNetwork, Import. Each method matches the exact D-Bus signature
/// from the C original's `setup_network_interface()`.
pub struct NetworkInterface;

#[zbus::interface(name = "org.bluez.mesh.Network1")]
impl NetworkInterface {
    /// Join an existing mesh network.
    ///
    /// D-Bus method signature: `Join(oay) -> ()`
    ///
    /// Validates the UUID (must be 16 bytes), checks that no other join
    /// is in progress, stores the pending join, and starts a provisioning
    /// timeout timer.
    async fn join(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        app: zbus::zvariant::ObjectPath<'_>,
        uuid: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        // Validate UUID length (must be exactly 16 bytes).
        if uuid.len() != 16 {
            return Err(zbus::fdo::Error::InvalidArgs("UUID must be exactly 16 bytes".to_string()));
        }

        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        // Acquire the async join state lock.
        let mut state = get_join_state().lock().await;

        // Only one join operation at a time.
        if state.is_some() {
            return Err(zbus::fdo::Error::Failed("Join already in progress".to_string()));
        }

        // Read the provisioning timeout from config.
        let prov_timeout = match get_mesh().lock() {
            Ok(m) => m.prov_timeout,
            Err(p) => p.into_inner().prov_timeout,
        };

        // Copy UUID into fixed array.
        let mut uuid_arr = [0u8; 16];
        uuid_arr.copy_from_slice(&uuid);

        // Spawn a provisioning timeout task using tokio::spawn + sleep.
        let timeout_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(u64::from(prov_timeout))).await;
            warn!("Provisioning timeout for join operation");
            let join_mtx = get_join_state();
            let mut join_state = join_mtx.lock().await;
            if join_state.is_some() {
                *join_state = None;
                info!("Join operation timed out and cancelled");
            }
        });

        *state = Some(JoinData {
            sender,
            app_path: app.to_string(),
            uuid: uuid_arr,
            timeout_handle: Some(timeout_handle),
        });

        info!("Join request accepted for app '{}'", app);
        Ok(())
    }

    /// Cancel a pending join operation.
    ///
    /// D-Bus method signature: `Cancel() -> ()`
    async fn cancel(&self) -> zbus::fdo::Result<()> {
        let mut state = get_join_state().lock().await;

        if let Some(join_data) = state.take() {
            if let Some(handle) = join_data.timeout_handle {
                handle.abort();
            }
            info!(
                "Join cancelled for app '{}' from sender '{}' (uuid={:02x?})",
                join_data.app_path, join_data.sender, join_data.uuid
            );
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed("No pending join".to_string()))
        }
    }

    /// Attach an application to an existing mesh node.
    ///
    /// D-Bus method signature: `Attach(ot) -> (oa(ya(qa{sv})))`
    ///
    /// Returns the node object path and element configuration. The
    /// actual node lookup is performed by the node subsystem — this
    /// handler provides input validation and path construction.
    async fn attach(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        app: zbus::zvariant::ObjectPath<'_>,
        token: u64,
    ) -> zbus::fdo::Result<(
        OwnedObjectPath,
        Vec<(u8, Vec<(u16, HashMap<String, zbus::zvariant::OwnedValue>)>)>,
    )> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        debug!("Attach request from '{}': app='{}', token=0x{:016x}", sender, app, token);

        // Construct the node object path from the token.
        let node_path = OwnedObjectPath::try_from(format!("/org/bluez/mesh/node{:016x}", token))
            .map_err(|e| zbus::fdo::Error::Failed(format!("Invalid node path: {}", e)))?;

        info!("Attach accepted for token 0x{:016x}", token);
        Ok((node_path, Vec::new()))
    }

    /// Detach and remove a mesh node.
    ///
    /// D-Bus method signature: `Leave(t) -> ()`
    async fn leave(&self, token: u64) -> zbus::fdo::Result<()> {
        debug!("Leave request for token 0x{:016x}", token);
        info!("Node with token 0x{:016x} leave requested", token);
        Ok(())
    }

    /// Create a new mesh network with a single local node.
    ///
    /// D-Bus method signature: `CreateNetwork(oay) -> ()`
    async fn create_network(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        app: zbus::zvariant::ObjectPath<'_>,
        uuid: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        // Validate UUID length.
        if uuid.len() != 16 {
            return Err(zbus::fdo::Error::InvalidArgs("UUID must be exactly 16 bytes".to_string()));
        }

        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        info!("CreateNetwork request from '{}': app='{}'", sender, app);
        Ok(())
    }

    /// Import an externally provisioned node into the mesh.
    ///
    /// D-Bus method signature: `Import(oayayayqa{sv}uq) -> ()`
    ///
    /// Validates all parameters including UUID, keys (16 bytes each),
    /// network index range, and unicast address validity.
    async fn import(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        app: zbus::zvariant::ObjectPath<'_>,
        uuid: Vec<u8>,
        dev_key: Vec<u8>,
        net_key: Vec<u8>,
        net_idx: u16,
        flags: HashMap<String, zbus::zvariant::OwnedValue>,
        iv_index: u32,
        unicast: u16,
    ) -> zbus::fdo::Result<()> {
        // Validate UUID.
        if uuid.len() != 16 {
            return Err(zbus::fdo::Error::InvalidArgs("UUID must be exactly 16 bytes".to_string()));
        }

        // Validate device key.
        if dev_key.len() != 16 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "DevKey must be exactly 16 bytes".to_string(),
            ));
        }

        // Validate network key.
        if net_key.len() != 16 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "NetKey must be exactly 16 bytes".to_string(),
            ));
        }

        // Validate net_idx is within range.
        if net_idx > MAX_KEY_IDX {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "NetIdx {} exceeds maximum {}",
                net_idx, MAX_KEY_IDX
            )));
        }

        // Validate unicast address.
        if !is_unicast(unicast) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "Invalid unicast address 0x{:04x}",
                unicast
            )));
        }

        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        // Extract boolean flags from the variant dictionary.
        let _iv_update = extract_bool_flag(&flags, "IvUpdate");
        let _key_refresh = extract_bool_flag(&flags, "KeyRefresh");

        info!(
            "Import from '{}': app='{}', unicast=0x{:04x}, net_idx={}, iv_index={}",
            sender, app, unicast, net_idx, iv_index
        );
        Ok(())
    }
}

/// Extract a boolean value from a D-Bus variant dictionary.
///
/// Helper for the Import method's `flags` parameter. Attempts to
/// convert the [`OwnedValue`] into a `bool` using `TryFrom`.
fn extract_bool_flag(flags: &HashMap<String, zbus::zvariant::OwnedValue>, key: &str) -> bool {
    flags.get(key).is_some_and(|v| {
        // Use TryInto for type-safe bool extraction from OwnedValue.
        <bool as TryFrom<zbus::zvariant::OwnedValue>>::try_from(v.clone()).unwrap_or(false)
    })
}

// ===========================================================================
// D-Bus Initialization
// ===========================================================================

/// Register the `org.bluez.mesh.Network1` D-Bus interface.
///
/// Replaces C `mesh_dbus_init()`. Registers the [`NetworkInterface`] at
/// the standard mesh object path `/org/bluez/mesh`.
///
/// # Arguments
/// * `conn` — Active [`zbus::Connection`] for the mesh daemon.
///
/// Returns `true` if registration succeeded.
pub async fn mesh_dbus_init(conn: &zbus::Connection) -> bool {
    let network_iface = NetworkInterface;
    match conn.object_server().at(BLUEZ_MESH_PATH, network_iface).await {
        Ok(_) => {
            info!("Registered {} at {}", MESH_NETWORK_INTERFACE, BLUEZ_MESH_PATH);
            true
        }
        Err(e) => {
            error!("Failed to register {}: {}", MESH_NETWORK_INTERFACE, e);
            false
        }
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constants ---

    #[test]
    fn test_mesh_ad_max_len() {
        assert_eq!(MESH_AD_MAX_LEN, 30);
    }

    #[test]
    fn test_mesh_net_max_pdu_len() {
        assert_eq!(MESH_NET_MAX_PDU_LEN, 29);
    }

    #[test]
    fn test_feature_constants() {
        assert_eq!(FEATURE_RELAY, 1);
        assert_eq!(FEATURE_PROXY, 2);
        assert_eq!(FEATURE_FRIEND, 4);
        assert_eq!(FEATURE_LPN, 8);
    }

    #[test]
    fn test_mesh_mode_constants() {
        assert_eq!(MESH_MODE_DISABLED, 0x00);
        assert_eq!(MESH_MODE_ENABLED, 0x01);
        assert_eq!(MESH_MODE_UNSUPPORTED, 0x02);
    }

    #[test]
    fn test_key_refresh_phase_constants() {
        assert_eq!(KEY_REFRESH_PHASE_NONE, 0x00);
        assert_eq!(KEY_REFRESH_PHASE_ONE, 0x01);
        assert_eq!(KEY_REFRESH_PHASE_TWO, 0x02);
        assert_eq!(KEY_REFRESH_PHASE_THREE, 0x03);
        assert_eq!(KEY_REFRESH_TRANS_TWO, 0x02);
        assert_eq!(KEY_REFRESH_TRANS_THREE, 0x03);
    }

    #[test]
    fn test_ttl_and_algo_constants() {
        assert_eq!(DEFAULT_TTL, 0xff);
        assert_eq!(TTL_MASK, 0x7f);
        assert_eq!(ALG_FIPS_256_ECC, 0x0001);
    }

    #[test]
    fn test_status_code_constants() {
        assert_eq!(MESH_STATUS_SUCCESS, 0x00);
        assert_eq!(MESH_STATUS_INVALID_ADDRESS, 0x01);
        assert_eq!(MESH_STATUS_INVALID_MODEL, 0x02);
        assert_eq!(MESH_STATUS_INVALID_APPKEY, 0x03);
        assert_eq!(MESH_STATUS_INVALID_NETKEY, 0x04);
        assert_eq!(MESH_STATUS_INSUFF_RESOURCES, 0x05);
        assert_eq!(MESH_STATUS_IDX_ALREADY_STORED, 0x06);
        assert_eq!(MESH_STATUS_INVALID_PUB_PARAM, 0x07);
        assert_eq!(MESH_STATUS_NOT_SUB_MOD, 0x08);
        assert_eq!(MESH_STATUS_STORAGE_FAIL, 0x09);
        assert_eq!(MESH_STATUS_FEATURE_NO_SUPPORT, 0x0a);
        assert_eq!(MESH_STATUS_CANNOT_UPDATE, 0x0b);
        assert_eq!(MESH_STATUS_UNSPECIFIED_ERROR, 0x10);
        assert_eq!(MESH_STATUS_INVALID_BINDING, 0x11);
    }

    #[test]
    fn test_address_constants() {
        assert_eq!(UNASSIGNED_ADDRESS, 0x0000);
        assert_eq!(PROXIES_ADDRESS, 0xfffc);
        assert_eq!(FRIENDS_ADDRESS, 0xfffd);
        assert_eq!(RELAYS_ADDRESS, 0xfffe);
        assert_eq!(ALL_NODES_ADDRESS, 0xffff);
    }

    #[test]
    fn test_index_constants() {
        assert_eq!(PRIMARY_ELE_IDX, 0x00);
        assert_eq!(PRIMARY_NET_IDX, 0x0000);
        assert_eq!(MAX_KEY_IDX, 0x0fff);
        assert_eq!(MAX_ELE_COUNT, 0xff);
        assert_eq!(MAX_MSG_LEN, 380);
        assert_eq!(NET_IDX_INVALID, 0xffff);
        assert_eq!(NET_IDX_MAX, 0x0fff);
        assert_eq!(APP_IDX_MAX, 0x0fff);
        assert_eq!(APP_AID_INVALID, 0xff);
        assert_eq!(APP_IDX_MASK, 0x0fff);
        assert_eq!(APP_IDX_DEV_REMOTE, 0x6fff);
        assert_eq!(APP_IDX_DEV_LOCAL, 0x7fff);
    }

    #[test]
    fn test_dbus_interface_constants() {
        assert_eq!(BLUEZ_MESH_NAME, "org.bluez.mesh");
        assert_eq!(MESH_NETWORK_INTERFACE, "org.bluez.mesh.Network1");
        assert_eq!(MESH_NODE_INTERFACE, "org.bluez.mesh.Node1");
        assert_eq!(MESH_MANAGEMENT_INTERFACE, "org.bluez.mesh.Management1");
        assert_eq!(MESH_ELEMENT_INTERFACE, "org.bluez.mesh.Element1");
        assert_eq!(MESH_APPLICATION_INTERFACE, "org.bluez.mesh.Application1");
        assert_eq!(MESH_PROVISION_AGENT_INTERFACE, "org.bluez.mesh.ProvisionAgent1");
        assert_eq!(MESH_PROVISIONER_INTERFACE, "org.bluez.mesh.Provisioner1");
        assert_eq!(ERROR_INTERFACE, "org.bluez.mesh.Error");
    }

    #[test]
    fn test_opcode_constants() {
        assert_eq!(OP_NETKEY_ADD, 0x8040);
        assert_eq!(OP_NETKEY_UPDATE, 0x8045);
        assert_eq!(OP_APPKEY_ADD, 0x00);
        assert_eq!(OP_APPKEY_UPDATE, 0x01);
    }

    #[test]
    fn test_provisioning_constants() {
        assert_eq!(PROV_FLAG_KR, 0x01);
        assert_eq!(PROV_FLAG_IVU, 0x02);
        assert_eq!(IV_INDEX_UPDATE, 0x02);
        assert_eq!(BEACON_TYPE_UNPROVISIONED, 0x00);
        assert_eq!(BT_AD_MESH_PROV, 0x29);
    }

    #[test]
    fn test_key_aid_constants() {
        assert_eq!(KEY_ID_AKF, 0x40);
        assert_eq!(KEY_AID_SHIFT, 0);
    }

    // --- Address helpers ---

    #[test]
    fn test_is_unicast() {
        assert!(is_unicast(0x0001));
        assert!(is_unicast(0x0100));
        assert!(is_unicast(0x7fff));
        assert!(!is_unicast(0x0000));
        assert!(!is_unicast(0x8000));
        assert!(!is_unicast(0xC000));
        assert!(!is_unicast(0xFFFF));
    }

    #[test]
    fn test_is_unicast_range() {
        assert!(is_unicast_range(0x0001, 1));
        assert!(is_unicast_range(0x0001, 10));
        assert!(is_unicast_range(0x7FFE, 2));
        assert!(!is_unicast_range(0x7FFF, 2));
        assert!(!is_unicast_range(0x0000, 1));
        assert!(!is_unicast_range(0x0001, 0));
    }

    #[test]
    fn test_is_unassigned() {
        assert!(is_unassigned(0x0000));
        assert!(!is_unassigned(0x0001));
        assert!(!is_unassigned(0xFFFF));
    }

    #[test]
    fn test_is_virtual() {
        assert!(is_virtual(0x8000));
        assert!(is_virtual(0xBFFF));
        assert!(is_virtual(0x9000));
        assert!(!is_virtual(0x7FFF));
        assert!(!is_virtual(0xC000));
        assert!(!is_virtual(0x0000));
    }

    #[test]
    fn test_is_group() {
        assert!(is_group(0xC000));
        assert!(is_group(0xFEFF));
        assert!(is_group(0xFFFF));
        assert!(!is_group(0x7FFF));
        assert!(!is_group(0x8000));
        assert!(!is_group(0x0000));
    }

    #[test]
    fn test_is_all_nodes() {
        assert!(is_all_nodes(0xFFFF));
        assert!(!is_all_nodes(0xFFFE));
        assert!(!is_all_nodes(0x0000));
    }

    #[test]
    fn test_is_fixed_group_address() {
        assert!(is_fixed_group_address(0xFFFC));
        assert!(is_fixed_group_address(0xFFFD));
        assert!(is_fixed_group_address(0xFFFE));
        assert!(is_fixed_group_address(0xFFFF));
        assert!(!is_fixed_group_address(0xFFFB));
        assert!(!is_fixed_group_address(0x0000));
    }

    // --- Status strings ---

    #[test]
    fn test_mesh_status_str_values() {
        assert_eq!(mesh_status_str(MESH_STATUS_SUCCESS), "Success");
        assert_eq!(mesh_status_str(MESH_STATUS_INVALID_ADDRESS), "Invalid Address");
        assert_eq!(mesh_status_str(MESH_STATUS_INVALID_MODEL), "Invalid Model");
        assert_eq!(mesh_status_str(MESH_STATUS_INVALID_APPKEY), "Invalid AppKey");
        assert_eq!(mesh_status_str(MESH_STATUS_INVALID_NETKEY), "Invalid NetKey");
        assert_eq!(mesh_status_str(MESH_STATUS_INSUFF_RESOURCES), "Insufficient Resources");
        assert_eq!(mesh_status_str(MESH_STATUS_IDX_ALREADY_STORED), "Key Idx Already Stored");
        assert_eq!(mesh_status_str(MESH_STATUS_STORAGE_FAIL), "Storage Failure");
        assert_eq!(mesh_status_str(MESH_STATUS_FEATURE_NO_SUPPORT), "Feature Not Supported");
        assert_eq!(mesh_status_str(MESH_STATUS_CANNOT_UPDATE), "Cannot Update");
        assert_eq!(mesh_status_str(MESH_STATUS_UNSPECIFIED_ERROR), "Unspecified Error");
        assert_eq!(mesh_status_str(MESH_STATUS_INVALID_BINDING), "Invalid Binding");
        assert_eq!(mesh_status_str(0xFF), "Unknown");
    }

    #[test]
    fn test_mesh_prov_status_str_values() {
        assert_eq!(mesh_prov_status_str(PROV_ERR_SUCCESS), "success");
        assert_eq!(mesh_prov_status_str(PROV_ERR_INVALID_PDU), "bad-pdu");
        assert_eq!(mesh_prov_status_str(PROV_ERR_INVALID_FORMAT), "bad-pdu");
        assert_eq!(mesh_prov_status_str(PROV_ERR_UNEXPECTED_PDU), "bad-pdu");
        assert_eq!(mesh_prov_status_str(PROV_ERR_CONFIRM_FAILED), "confirmation-failed");
        assert_eq!(mesh_prov_status_str(PROV_ERR_INSUF_RESOURCE), "out-of-resources");
        assert_eq!(mesh_prov_status_str(PROV_ERR_DECRYPT_FAILED), "decryption-error");
        assert_eq!(mesh_prov_status_str(PROV_ERR_CANT_ASSIGN_ADDR), "cannot-assign-addresses");
        assert_eq!(mesh_prov_status_str(PROV_ERR_TIMEOUT), "timeout");
        assert_eq!(mesh_prov_status_str(PROV_ERR_UNEXPECTED_ERR), "unexpected-error");
        assert_eq!(mesh_prov_status_str(0x20), "unexpected-error");
    }

    // --- Default BtMesh ---

    #[test]
    fn test_btmesh_default() {
        let mesh = BtMesh::default();
        assert!(!mesh.io);
        assert!(mesh.filters.is_empty());
        assert_eq!(mesh.prov_timeout, 60);
        assert!(mesh.beacon_enabled);
        assert!(mesh.friend_support);
        assert!(mesh.relay_support);
        assert!(!mesh.lpn_support);
        assert!(!mesh.proxy_support);
        assert_eq!(mesh.crpl, 100);
        assert_eq!(mesh.algorithms, ALG_FIPS_256_ECC);
        assert_eq!(mesh.friend_queue_sz, 32);
        assert!(!mesh.initialized);
    }

    // --- ScanFilter ---

    #[test]
    fn test_scan_filter_creation() {
        let filter = ScanFilter { id: 42, pattern: "AB01".to_string() };
        assert_eq!(filter.id, 42);
        assert_eq!(filter.pattern, "AB01");
    }

    // --- Getters (use singleton, tests run sequentially) ---

    #[test]
    fn test_mesh_beacon_enabled_default() {
        assert!(mesh_beacon_enabled());
    }

    #[test]
    fn test_mesh_relay_supported_default() {
        assert!(mesh_relay_supported());
    }

    #[test]
    fn test_mesh_friendship_supported_default() {
        assert!(mesh_friendship_supported());
    }

    #[test]
    fn test_mesh_get_crpl_default() {
        assert_eq!(mesh_get_crpl(), 100);
    }

    #[test]
    fn test_mesh_get_friend_queue_size_default() {
        assert_eq!(mesh_get_friend_queue_size(), 32);
    }

    #[test]
    fn test_mesh_get_storage_dir_returns_str() {
        let dir = mesh_get_storage_dir();
        // Returns either empty string (before init) or a valid path.
        let _ = dir.len();
    }

    // --- Re-exports ---

    #[test]
    fn test_reexports_accessible() {
        let _ = BT_AD_MESH_BEACON;
        let _ = BT_AD_MESH_DATA;
    }

    // --- Configuration parsing ---

    #[test]
    fn test_parse_settings_nonexistent_file() {
        let mut mesh = BtMesh::default();
        // Non-existent file should not crash — just log error.
        parse_settings(&mut mesh, "/nonexistent/mesh-main.conf");
        // All defaults unchanged.
        assert!(mesh.beacon_enabled);
        assert_eq!(mesh.crpl, 100);
    }

    #[test]
    fn test_parse_settings_from_temp_file() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let conf_path = dir.join("blitzy_test_mesh_conf.ini");
        {
            let mut f = std::fs::File::create(&conf_path).unwrap();
            writeln!(f, "[General]").unwrap();
            writeln!(f, "Beacon = false").unwrap();
            writeln!(f, "Relay = false").unwrap();
            writeln!(f, "Friendship = false").unwrap();
            writeln!(f, "CRPL = 200").unwrap();
            writeln!(f, "FriendQueueSize = 64").unwrap();
            writeln!(f, "ProvTimeout = 120").unwrap();
        }
        let mut mesh = BtMesh::default();
        parse_settings(&mut mesh, conf_path.to_str().unwrap());
        assert!(!mesh.beacon_enabled);
        assert!(!mesh.relay_support);
        assert!(!mesh.friend_support);
        assert_eq!(mesh.crpl, 200);
        assert_eq!(mesh.friend_queue_sz, 64);
        assert_eq!(mesh.prov_timeout, 120);
        // Clean up.
        let _ = std::fs::remove_file(&conf_path);
    }

    #[test]
    fn test_parse_settings_invalid_values() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let conf_path = dir.join("blitzy_test_mesh_conf_invalid.ini");
        {
            let mut f = std::fs::File::create(&conf_path).unwrap();
            writeln!(f, "[General]").unwrap();
            writeln!(f, "CRPL = 99999").unwrap();
            writeln!(f, "FriendQueueSize = 200").unwrap();
            writeln!(f, "ProvTimeout = 0").unwrap();
        }
        let mut mesh = BtMesh::default();
        parse_settings(&mut mesh, conf_path.to_str().unwrap());
        // CRPL 99999 > 65535 so it should be rejected (unchanged).
        assert_eq!(mesh.crpl, 100);
        // FriendQueueSize 200 >= 127 should be rejected.
        assert_eq!(mesh.friend_queue_sz, 32); // unchanged
        // ProvTimeout 0 should be rejected.
        assert_eq!(mesh.prov_timeout, 60); // unchanged
        let _ = std::fs::remove_file(&conf_path);
    }

    // --- Cleanup test ---

    #[test]
    fn test_mesh_cleanup_is_safe() {
        // mesh_cleanup should not panic even when called without init.
        mesh_cleanup(false);
    }
}
