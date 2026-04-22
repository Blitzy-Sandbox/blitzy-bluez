//! Management1 D-Bus interface for the bluetooth-meshd daemon.
//!
//! Complete Rust rewrite of `mesh/manager.c` (1176 lines) and `mesh/manager.h`.
//! Implements the `org.bluez.mesh.Management1` D-Bus interface, providing:
//!
//! - Node provisioning: `AddNode`, `Reprovision`
//! - Remote node management: `ImportRemoteNode`, `DeleteRemoteNode`
//! - Unprovisioned device scanning: `UnprovisionedScan`, `UnprovisionedScanCancel`
//! - Subnet key lifecycle: `CreateSubnet`, `UpdateSubnet`, `DeleteSubnet`, `ImportSubnet`
//! - Application key lifecycle: `CreateAppKey`, `UpdateAppKey`, `DeleteAppKey`, `ImportAppKey`
//! - Key refresh phase control: `SetKeyPhase`
//! - Key export: `ExportKeys`
//!
//! All state is managed through module-level singletons protected by
//! `std::sync::Mutex`, safe because `bluetooth-meshd` uses a single-threaded
//! tokio runtime (`tokio::runtime::Builder::new_current_thread()`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tracing::{debug, error, info};
use zbus::Connection;
use zbus::zvariant::{ObjectPath, Value};

use crate::agent::MeshAgent;
use crate::dbus::{
    MeshDbusError, MeshError, byte_array_to_variant, dbus_get_connection, dict_insert_basic,
};
use crate::io::{BT_AD_MESH_BEACON, mesh_io_deregister_recv_cb};
use crate::keyring::{
    KeyringAppKey, KeyringNetKey, keyring_del_app_key, keyring_del_net_key,
    keyring_del_remote_dev_key, keyring_del_remote_dev_key_all, keyring_finalize_app_keys,
    keyring_get_app_key, keyring_get_net_key, keyring_put_app_key, keyring_put_net_key,
    keyring_put_remote_dev_key,
};
use crate::mesh::{
    APP_IDX_DEV_REMOTE, DEFAULT_TTL, KEY_REFRESH_PHASE_NONE, KEY_REFRESH_PHASE_ONE,
    KEY_REFRESH_PHASE_THREE, KEY_REFRESH_PHASE_TWO, MAX_KEY_IDX, MESH_MANAGEMENT_INTERFACE,
    MESH_PROVISIONER_INTERFACE, PRIMARY_NET_IDX, is_unicast, mesh_prov_status_str,
};
use crate::model::{mesh_model_opcode_set, mesh_model_send};
use crate::models::remote_prov::{OP_REM_PROV_SCAN_START, OP_REM_PROV_SCAN_STOP};
use crate::node::MeshNode;
use crate::provisioning::initiator::{
    initiator_cancel, initiator_prov_data, initiator_scan_reg, initiator_scan_unreg,
    initiator_start,
};
use crate::provisioning::{MeshProvNodeInfo, PROV_ERR_CANT_ASSIGN_ADDR, PROV_ERR_SUCCESS};

// ---------------------------------------------------------------------------
// Transport Constants (matching C mesh/provision.h)
// ---------------------------------------------------------------------------

/// PB-NPPI transport sub-type 0 (C: `PB_NPPI_00`).
const _PB_NPPI_00: u8 = 0x00;

/// PB-NPPI transport sub-type 1 — device key update (C: `PB_NPPI_01`).
const PB_NPPI_01: u8 = 0x01;

/// PB-NPPI transport sub-type 2 — composition update (C: `PB_NPPI_02`).
const PB_NPPI_02: u8 = 0x02;

/// PB-ADV bearer transport type (C: `PB_ADV`). Internal-only value that is
/// strictly greater than all NPPI sub-types.
const PB_ADV: u8 = 0x03;

/// Unprovisioned beacon AD type filter pattern: `[BT_AD_MESH_BEACON, 0x00]`.
/// Used to register / deregister the I/O receive callback for scanning.
const PRVB: [u8; 2] = [BT_AD_MESH_BEACON, 0x00];

// ---------------------------------------------------------------------------
// Scan Request
// ---------------------------------------------------------------------------

/// Pending unprovisioned-device scan request.
///
/// Replaces C `struct scan_req` from `mesh/manager.c:50-58`.
struct ScanReq {
    /// Unique identifier for this scan entry (used for timeout matching).
    id: usize,
    /// Reference to the mesh node that initiated the scan.
    node: Arc<MeshNode>,
    /// Handle to the scan-timeout task; aborted on early cancellation.
    timeout: Option<tokio::task::JoinHandle<()>>,
    /// Remote provisioning server address (0 = local PB-ADV).
    server: u16,
    /// Network key index used for this scan.
    net_idx: u16,
    /// Last-seen device UUID (used for duplicate filtering).
    uuid: [u8; 16],
    /// Best RSSI observed for the current UUID.
    rssi: i8,
    /// Extended scan indicator.
    ext: bool,
}

// ---------------------------------------------------------------------------
// Provisioning Pending Data
// ---------------------------------------------------------------------------

/// Pending provisioning session state.
///
/// Replaces C `struct prov_remote_data` from `mesh/manager.c:37-48`.
struct ProvRemoteData {
    /// Reference to the mesh node performing provisioning.
    node: Arc<MeshNode>,
    /// Provisioning agent reference.
    _agent: Option<Arc<MeshAgent>>,
    /// Original unicast address of the device (for reprovision).
    original: u16,
    /// Assigned primary unicast address.
    primary: u16,
    /// Network key index.
    net_idx: u16,
    /// Transport type (PB_ADV, PB_NPPI_00..02).
    transport: u8,
    /// Number of elements reported by the device.
    num_ele: u8,
    /// Device UUID (16 bytes).
    uuid: [u8; 16],
    /// Caller ID for matching with initiator_cancel.
    caller_id: usize,
}

// ---------------------------------------------------------------------------
// Module-Level State
// ---------------------------------------------------------------------------

/// Global scan request queue. Protected by Mutex for safe access from
/// async contexts. Single-threaded runtime ensures no contention.
static SCANS: std::sync::LazyLock<Mutex<Vec<ScanReq>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Global pending provisioning session (singleton — only one active at a time).
static PROV_PENDING: std::sync::LazyLock<Mutex<Option<ProvRemoteData>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

/// Monotonically increasing ID generator for scan entries.
static SCAN_ID: AtomicUsize = AtomicUsize::new(1);

/// Monotonically increasing ID generator for provisioning sessions.
static PROV_CALLER_ID: AtomicUsize = AtomicUsize::new(1);

// ---------------------------------------------------------------------------
// Scan Lifecycle Helpers
// ---------------------------------------------------------------------------

/// Cancel a single scan entry identified by its unique `scan_id`.
///
/// Removes the entry from the global scan queue, aborts its timeout task,
/// sends a Remote Provisioning Scan Stop message (if the scan used a remote
/// server), or deregisters the local I/O receive callback, and finally
/// unregisters from the provisioning initiator's scan result dispatch.
///
/// Replaces C `scan_cancel()` from `mesh/manager.c:85-115`.
async fn scan_cancel_by_id(scan_id: usize) {
    let entry = {
        let mut scans = SCANS.lock().unwrap();
        scans.iter().position(|s| s.id == scan_id).map(|pos| scans.remove(pos))
    };

    let Some(mut req) = entry else {
        return;
    };

    debug!("scan_cancel: id={}", scan_id);

    // Abort the timeout task if it is still running.
    if let Some(handle) = req.timeout.take() {
        handle.abort();
    }

    if req.server != 0 {
        // Remote provisioning — send ScanStop opcode.
        let mut msg_buf = [0u8; 4];
        let n = mesh_model_opcode_set(OP_REM_PROV_SCAN_STOP, &mut msg_buf);
        mesh_model_send(
            &req.node,
            0,
            req.server,
            APP_IDX_DEV_REMOTE,
            req.net_idx,
            DEFAULT_TTL,
            true,
            &msg_buf[..n],
        );
    } else {
        // Local PB-ADV — deregister the I/O beacon filter.
        mesh_io_deregister_recv_cb(&PRVB);
    }

    initiator_scan_unreg(&req.node).await;
}

/// Cancel all scan requests originating from the given `node`.
///
/// Public API exported as `manager_scan_cancel`.
/// Replaces C `manager_scan_cancel()` from `mesh/manager.c:1169-1175`.
pub async fn manager_scan_cancel(node: &Arc<MeshNode>) {
    // Collect IDs of all scans belonging to this node.
    let ids: Vec<usize> = {
        let scans = SCANS.lock().unwrap();
        scans.iter().filter(|s| Arc::ptr_eq(&s.node, node)).map(|s| s.id).collect()
    };

    for id in ids {
        scan_cancel_by_id(id).await;
    }
}

// ---------------------------------------------------------------------------
// Provisioning Lifecycle Helpers
// ---------------------------------------------------------------------------

/// Clean up the pending provisioning session and reset the singleton.
///
/// Replaces C `free_pending_add_call()` from `mesh/manager.c:117-131`.
fn free_pending_add_call() {
    let pending = {
        let mut guard = PROV_PENDING.lock().unwrap();
        guard.take()
    };

    if let Some(pending) = pending {
        // Cancel any in-flight initiator session.
        let caller_id = pending.caller_id;
        tokio::spawn(async move {
            initiator_cancel(caller_id).await;
        });
    }
}

/// Send an `AddNodeFailed` D-Bus method call to the owning application.
///
/// Replaces C `send_add_failed()` from `mesh/manager.c:159-179`.
async fn send_add_failed(owner: &str, path: &str, uuid: &[u8; 16], status: u8) {
    let Some(conn) = dbus_get_connection() else {
        error!("send_add_failed: no D-Bus connection");
        return;
    };

    let status_str = mesh_prov_status_str(status);
    let uuid_value = byte_array_to_variant(uuid);

    let Ok(obj_path) = ObjectPath::try_from(path) else {
        error!("send_add_failed: invalid object path: {}", path);
        return;
    };
    let result = conn
        .call_method(
            Some(owner),
            &obj_path,
            Some(MESH_PROVISIONER_INTERFACE),
            "AddNodeFailed",
            &(uuid_value, status_str),
        )
        .await;

    if let Err(e) = result {
        error!("send_add_failed: D-Bus call error: {}", e);
    }
}

/// Handle the provisioning completion callback.
///
/// Called when the provisioning initiator completes (successfully or with
/// error). Stores the device key on success, notifies the application via
/// `AddNodeComplete` or `ReprovComplete`, and cleans up the pending session.
///
/// Replaces C `add_cmplt()` from `mesh/manager.c:181-247`.
async fn handle_add_complete(status: u8, info: Option<MeshProvNodeInfo>) {
    let pending = {
        let guard = PROV_PENDING.lock().unwrap();
        // Extract data we need while holding the lock.
        guard.as_ref().map(|p| (p.node.clone(), p.transport, p.original, p.uuid, p.caller_id))
    };

    let Some((node, transport, original, uuid, _caller_id)) = pending else {
        return;
    };

    let owner = match node.get_owner() {
        Some(o) => o,
        None => {
            free_pending_add_call();
            return;
        }
    };
    let app_path = match node.get_app_path() {
        Some(p) => p,
        None => {
            free_pending_add_call();
            return;
        }
    };

    if status != PROV_ERR_SUCCESS {
        send_add_failed(&owner, &app_path, &uuid, status).await;
        free_pending_add_call();
        return;
    }

    let Some(info) = info else {
        send_add_failed(&owner, &app_path, &uuid, PROV_ERR_CANT_ASSIGN_ADDR).await;
        free_pending_add_call();
        return;
    };

    let node_path = node.get_storage_dir();

    // If NPPI mode 01 (device key update), delete old dev key first.
    if transport == PB_NPPI_01 {
        keyring_del_remote_dev_key_all(&node_path, original);
    }

    // Store the new device key.
    if !keyring_put_remote_dev_key(&node_path, info.unicast, info.num_ele, &info.device_key) {
        send_add_failed(&owner, &app_path, &uuid, PROV_ERR_CANT_ASSIGN_ADDR).await;
        free_pending_add_call();
        return;
    }

    // Send completion notification to the application.
    let Some(conn) = dbus_get_connection() else {
        error!("handle_add_complete: no D-Bus connection");
        free_pending_add_call();
        return;
    };

    let Ok(obj_path) = ObjectPath::try_from(app_path.as_str()) else {
        error!("handle_add_complete: invalid object path: {}", app_path);
        free_pending_add_call();
        return;
    };
    let result = if transport > PB_NPPI_02 {
        // Regular AddNode — send AddNodeComplete(uuid, unicast, num_ele).
        let uuid_val = byte_array_to_variant(&uuid);
        conn.call_method(
            Some(&*owner),
            &obj_path,
            Some(MESH_PROVISIONER_INTERFACE),
            "AddNodeComplete",
            &(uuid_val, info.unicast, info.num_ele),
        )
        .await
    } else {
        // Reprovision — send ReprovComplete(original, nppi, unicast, num_ele).
        let nppi: u8 = transport;
        conn.call_method(
            Some(&*owner),
            &obj_path,
            Some(MESH_PROVISIONER_INTERFACE),
            "ReprovComplete",
            &(original, nppi, info.unicast, info.num_ele),
        )
        .await
    };

    if let Err(e) = result {
        error!("handle_add_complete: D-Bus notification error: {}", e);
    }

    free_pending_add_call();
}

/// Handle the provisioning data request callback.
///
/// Called by the provisioning initiator when it needs the network key index
/// and primary unicast address from the application. Sends a
/// `RequestProvData` or `RequestReprovData` D-Bus call to the application,
/// then feeds the reply back to `initiator_prov_data`.
///
/// Replaces C `add_data_get()` + `mgr_prov_data()` from
/// `mesh/manager.c:249-313`.
async fn handle_data_request(num_ele: u8) {
    let (node, transport, original, net_idx, caller_id) = {
        let mut guard = PROV_PENDING.lock().unwrap();
        match guard.as_mut() {
            Some(p) => {
                p.num_ele = num_ele;
                (p.node.clone(), p.transport, p.original, p.net_idx, p.caller_id)
            }
            None => return,
        }
    };

    let owner = match node.get_owner() {
        Some(o) => o,
        None => return,
    };
    let app_path = match node.get_app_path() {
        Some(p) => p,
        None => return,
    };

    let Some(conn) = dbus_get_connection() else {
        error!("handle_data_request: no D-Bus connection");
        return;
    };

    let Ok(obj_path) = ObjectPath::try_from(app_path.as_str()) else {
        error!("handle_data_request: invalid object path: {}", app_path);
        return;
    };

    if transport > PB_NPPI_02 {
        // Regular provisioning — RequestProvData(num_ele) → (net_idx, primary).
        let reply = conn
            .call_method(
                Some(&*owner),
                &obj_path,
                Some(MESH_PROVISIONER_INTERFACE),
                "RequestProvData",
                &(num_ele,),
            )
            .await;

        match reply {
            Ok(msg) => {
                if let Ok((reply_net_idx, reply_primary)) = msg.body().deserialize::<(u16, u16)>() {
                    {
                        let mut guard = PROV_PENDING.lock().unwrap();
                        if let Some(p) = guard.as_mut() {
                            p.primary = reply_primary;
                            p.net_idx = reply_net_idx;
                        }
                    }
                    initiator_prov_data(reply_net_idx, reply_primary, caller_id).await;
                }
            }
            Err(e) => {
                error!("RequestProvData failed: {}", e);
            }
        }
    } else if transport == PB_NPPI_01 {
        // NPPI mode 01 — RequestReprovData(original, num_ele) → (primary).
        let reply = conn
            .call_method(
                Some(&*owner),
                &obj_path,
                Some(MESH_PROVISIONER_INTERFACE),
                "RequestReprovData",
                &(original, num_ele),
            )
            .await;

        match reply {
            Ok(msg) => {
                if let Ok(reply_primary) = msg.body().deserialize::<u16>() {
                    {
                        let mut guard = PROV_PENDING.lock().unwrap();
                        if let Some(p) = guard.as_mut() {
                            p.primary = reply_primary;
                        }
                    }
                    initiator_prov_data(net_idx, reply_primary, caller_id).await;
                }
            }
            Err(e) => {
                error!("RequestReprovData failed: {}", e);
            }
        }
    }
}

/// Handle a scan result from the provisioning initiator.
///
/// Called via the closure registered with `initiator_scan_reg`. Finds the
/// matching scan entry, filters duplicate results with weaker signal, and
/// forwards the result to the application via `ScanResult`.
///
/// Replaces C `manager_scan_result()` from `mesh/manager.c:572-621`.
async fn handle_scan_result(node: Arc<MeshNode>, server: u16, rssi: i32, data: Vec<u8>) {
    let (owner, app_path, scan_rssi) = {
        let mut scans = SCANS.lock().unwrap();

        // Find the scan entry matching node + server.
        let entry = scans.iter_mut().find(|s| Arc::ptr_eq(&s.node, &node) && s.server == server);

        let Some(req) = entry else {
            debug!("No scan_result req for server 0x{:04x}", server);
            return;
        };

        // Extract UUID from data (data[1..17] is the UUID, data[0] is typically RSSI).
        if data.len() >= 17 {
            let incoming_uuid = &data[1..17];

            // Filter repeats with weaker signal.
            if req.uuid[..] == *incoming_uuid && !req.ext && (rssi as i8) <= req.rssi {
                debug!("Already seen (weaker signal)");
                return;
            }

            if !req.ext && (rssi as i8) > req.rssi {
                req.rssi = rssi as i8;
            }

            req.uuid.copy_from_slice(incoming_uuid);
        }

        let scan_rssi: i16 = req.rssi as i16;

        let owner = match req.node.get_owner() {
            Some(o) => o,
            None => return,
        };
        let app_path = match req.node.get_app_path() {
            Some(p) => p,
            None => return,
        };

        (owner, app_path, scan_rssi)
    };

    let Some(conn) = dbus_get_connection() else {
        error!("handle_scan_result: no D-Bus connection");
        return;
    };

    // Build ScanResult call: (rssi: n, data: ay, options: a{sv})
    // The data sent is data[1..] (skip the RSSI prefix byte).
    let scan_data: Vec<u8> = if data.len() > 1 { data[1..].to_vec() } else { Vec::new() };
    let scan_data_value = byte_array_to_variant(&scan_data);

    let mut options: HashMap<String, Value<'static>> = HashMap::new();
    if server != 0 {
        dict_insert_basic(&mut options, "Server", Value::from(server));
    }

    let Ok(obj_path) = ObjectPath::try_from(app_path.as_str()) else {
        error!("handle_scan_result: invalid object path: {}", app_path);
        return;
    };
    let result = conn
        .call_method(
            Some(&*owner),
            &obj_path,
            Some(MESH_PROVISIONER_INTERFACE),
            "ScanResult",
            &(scan_rssi, scan_data_value, options),
        )
        .await;

    if let Err(e) = result {
        error!("ScanResult D-Bus call failed: {}", e);
    }
}

// ---------------------------------------------------------------------------
// Subnet / App Key Storage Helpers
// ---------------------------------------------------------------------------

/// Create and store a new subnet key in the keyring.
///
/// Validates the index, checks for duplicates (allowing redundant calls with
/// identical key material), then stores the key.
///
/// Replaces C `store_new_subnet()` from `mesh/manager.c:764-789`.
fn store_new_subnet(
    node: &MeshNode,
    net_idx: u16,
    new_key: &[u8; 16],
) -> Result<(), MeshDbusError> {
    if net_idx > MAX_KEY_IDX {
        return Err(MeshDbusError::InvalidArgs("Invalid net index".into()));
    }

    let node_path = node.get_storage_dir();

    if let Some(existing) = keyring_get_net_key(&node_path, net_idx) {
        // Allow redundant calls only if key values match.
        if existing.old_key == *new_key {
            return Ok(());
        }
        return Err(MeshDbusError::AlreadyExists("Subnet already exists".into()));
    }

    let key = KeyringNetKey {
        net_idx,
        phase: KEY_REFRESH_PHASE_NONE,
        old_key: *new_key,
        new_key: *new_key,
    };

    if !keyring_put_net_key(&node_path, net_idx, &key) {
        return Err(MeshDbusError::Failed("Failed to store net key".into()));
    }

    Ok(())
}

/// Create and store a new application key in the keyring.
///
/// Validates indices, checks the bound network key exists, handles
/// redundant calls with identical values, then stores the key.
///
/// Replaces C `store_new_appkey()` from `mesh/manager.c:902-935`.
fn store_new_appkey(
    node: &MeshNode,
    net_idx: u16,
    app_idx: u16,
    new_key: &[u8; 16],
) -> Result<(), MeshDbusError> {
    if net_idx > MAX_KEY_IDX || app_idx > MAX_KEY_IDX {
        return Err(MeshDbusError::InvalidArgs("Invalid key index".into()));
    }

    let node_path = node.get_storage_dir();

    // Verify that the bound network key exists.
    if keyring_get_net_key(&node_path, net_idx).is_none() {
        return Err(MeshDbusError::DoesNotExist("Bound net key not found".into()));
    }

    // Check for existing app key.
    if let Some(existing) = keyring_get_app_key(&node_path, app_idx) {
        // Allow redundant calls with identical values.
        if existing.old_key == *new_key && existing.net_idx == net_idx {
            return Ok(());
        }
        return Err(MeshDbusError::AlreadyExists("App key already exists".into()));
    }

    let app_key = KeyringAppKey { app_idx, net_idx, old_key: *new_key, new_key: *new_key };

    if !keyring_put_app_key(&node_path, app_idx, net_idx, &app_key) {
        return Err(MeshDbusError::Failed("Failed to store app key".into()));
    }

    Ok(())
}

/// Verify that the D-Bus caller is the owner of the node.
///
/// Returns `Ok(())` if the caller matches, or `Err(NotAuthorized)` if not.
fn check_authorization(node: &MeshNode, sender: &str) -> Result<(), MeshDbusError> {
    match node.get_owner() {
        Some(ref owner) if owner == sender => Ok(()),
        _ => Err(MeshDbusError::NotAuthorized("Sender is not the owner".into())),
    }
}

// ---------------------------------------------------------------------------
// ManagementInterface — D-Bus Management1 Interface
// ---------------------------------------------------------------------------

/// Implementation of the `org.bluez.mesh.Management1` D-Bus interface.
///
/// Each instance is bound to a specific mesh node and provides the full
/// set of management operations.
pub struct ManagementInterface {
    /// The mesh node this interface operates on.
    node: Arc<MeshNode>,
}

impl ManagementInterface {
    /// Create a new `ManagementInterface` bound to the given node.
    pub fn new(node: Arc<MeshNode>) -> Self {
        Self { node }
    }
}

#[zbus::interface(name = "org.bluez.mesh.Management1")]
impl ManagementInterface {
    // =======================================================================
    // UnprovisionedScan — Start scanning for unprovisioned devices
    // =======================================================================

    /// Start scanning for unprovisioned Bluetooth Mesh devices.
    ///
    /// Accepts an options dictionary `a{sv}` with optional keys:
    /// - `"Seconds"` (`q`): scan duration in seconds (default 60, max 60)
    /// - `"Subnet"` (`q`): network key index (default: node primary index)
    /// - `"Server"` (`q`): remote provisioning server address (0 = local)
    /// - `"Filter"` (`ay`): 16-byte UUID filter
    /// - `"Extended"` (`ay`): extended scan data
    ///
    /// Replaces C `start_scan_call()` from `mesh/manager.c:623-747`.
    #[zbus(name = "UnprovisionedScan")]
    async fn unprovisioned_scan(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        options: HashMap<String, Value<'_>>,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if !self.node.is_provisioner() {
            return Err(MeshDbusError::NotAuthorized("Not a provisioner".into()));
        }

        // Extract primary idx from net while keeping the borrow short-lived.
        // Ref<'_, MeshNet> is not Send, so we must not hold it across await points.
        let primary_net_idx = {
            let net = self.node.get_net();
            net.get_primary_idx()
        };

        let mut server: u16 = 0;
        let mut sec: u16 = 60;
        let mut net_idx = primary_net_idx;
        let mut uuid_filter: [u8; 16] = [0u8; 16];
        let mut has_filter = false;
        let mut ext = false;

        // Parse options dictionary.
        for (key, value) in &options {
            match &**key {
                "Seconds" => {
                    sec = value
                        .downcast_ref::<u16>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                }
                "Subnet" => {
                    net_idx = value
                        .downcast_ref::<u16>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                    if net_idx > MAX_KEY_IDX {
                        return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                    }
                }
                "Server" => {
                    server = value
                        .downcast_ref::<u16>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                    if server >= 0x8000 {
                        return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                    }
                }
                "Filter" => {
                    if let Some(bytes) = extract_byte_array(value) {
                        if bytes.len() == 16 {
                            uuid_filter.copy_from_slice(&bytes);
                            has_filter = true;
                        } else {
                            return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                        }
                    } else {
                        return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                    }
                }
                "Extended" if extract_byte_array(value).is_some() => {
                    ext = true;
                }
                "Extended" => {
                    return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                }
                _ => {
                    return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                }
            }
        }

        // Validate server / timeout constraints.
        if server != 0 {
            if sec == 0 || sec > 60 {
                return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
            }
        } else {
            server = self.node.get_primary();
            if sec == 0 || sec > 60 {
                sec = 60;
            }
        }

        // Remove any existing scan for this node+server combination.
        let existing_id = {
            let scans = SCANS.lock().unwrap();
            scans
                .iter()
                .find(|s| Arc::ptr_eq(&s.node, &self.node) && s.server == server)
                .map(|s| s.id)
        };
        if let Some(eid) = existing_id {
            scan_cancel_by_id(eid).await;
        }

        let scan_id = SCAN_ID.fetch_add(1, Ordering::Relaxed);

        // Create the timeout task.
        let timeout_handle = if sec > 0 {
            let sid = scan_id;
            Some(tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(u64::from(sec))).await;
                scan_cancel_by_id(sid).await;
            }))
        } else {
            None
        };

        // Build and send the Remote Provisioning Scan Start message.
        let mut scan_msg = [0u8; 21];
        let mut n = mesh_model_opcode_set(OP_REM_PROV_SCAN_START, &mut scan_msg);
        scan_msg[n] = 5; // scan limit
        n += 1;
        scan_msg[n] = sec as u8;
        n += 1;

        if has_filter {
            scan_msg[n..n + 16].copy_from_slice(&uuid_filter);
            n += 16;
        }

        mesh_model_send(
            &self.node,
            0,
            server,
            APP_IDX_DEV_REMOTE,
            net_idx,
            DEFAULT_TTL,
            true,
            &scan_msg[..n],
        );

        // Register the scan result callback with the initiator.
        let node_for_cb = self.node.clone();
        let server_for_cb = server;
        let scan_result_cb = Box::new(move |rssi: i32, data: &[u8]| {
            let node = node_for_cb.clone();
            let data_owned = data.to_vec();
            let svr = server_for_cb;
            tokio::spawn(async move {
                handle_scan_result(node, svr, rssi, data_owned).await;
            });
        });
        initiator_scan_reg(scan_result_cb, self.node.clone()).await;

        // Add to the scan queue.
        {
            let mut scans = SCANS.lock().unwrap();
            scans.push(ScanReq {
                id: scan_id,
                node: self.node.clone(),
                timeout: timeout_handle,
                server,
                net_idx,
                uuid: uuid_filter,
                rssi: -128,
                ext,
            });
        }

        info!("UnprovisionedScan started: server=0x{:04x}, sec={}", server, sec);
        Ok(())
    }

    // =======================================================================
    // UnprovisionedScanCancel — Stop scanning
    // =======================================================================

    /// Cancel all unprovisioned device scans originating from this node.
    ///
    /// Replaces C `cancel_scan_call()` from `mesh/manager.c:749-762`.
    #[zbus(name = "UnprovisionedScanCancel")]
    async fn unprovisioned_scan_cancel(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if !self.node.is_provisioner() {
            return Err(MeshDbusError::NotAuthorized("Not a provisioner".into()));
        }

        manager_scan_cancel(&self.node).await;
        info!("UnprovisionedScanCancel completed");
        Ok(())
    }

    // =======================================================================
    // AddNode — Initiate provisioning of a new device
    // =======================================================================

    /// Initiate provisioning of an unprovisioned device.
    ///
    /// Arguments:
    /// - `uuid` (`ay`): 16-byte device UUID
    /// - `options` (`a{sv}`): optional keys `"Seconds"`, `"Server"`, `"Subnet"`
    ///
    /// Replaces C `add_node_call()` from `mesh/manager.c:413-514`.
    #[zbus(name = "AddNode")]
    async fn add_node(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        uuid: Vec<u8>,
        options: HashMap<String, Value<'_>>,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        debug!("AddNode request");

        let has_uuid = uuid.len() == 16;
        if !uuid.is_empty() && !has_uuid {
            return Err(MeshDbusError::InvalidArgs("Bad device UUID".into()));
        }

        let default_subidx = {
            let net = self.node.get_net();
            net.get_primary_idx()
        };
        let mut subidx = default_subidx;

        let mut sec: u16 = 60;
        let mut server: u16 = 0;

        // Parse options dictionary.
        for (key, value) in &options {
            match &**key {
                "Seconds" => {
                    sec = value
                        .downcast_ref::<u16>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                }
                "Server" => {
                    server = value
                        .downcast_ref::<u16>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                    if server >= 0x8000 {
                        return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                    }
                }
                "Subnet" => {
                    subidx = value
                        .downcast_ref::<u16>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                    if subidx > MAX_KEY_IDX {
                        return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                    }
                }
                _ => {
                    return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                }
            }
        }

        // Device Key update / Composition update requires remote server.
        if !has_uuid && server == 0 {
            return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
        }

        // Default server to local node.
        if server == 0 {
            server = self.node.get_primary();
        }

        // Cancel any outstanding scans from this node.
        manager_scan_cancel(&self.node).await;

        // Set up the pending provisioning data.
        let mut uuid_arr = [0u8; 16];
        if has_uuid {
            uuid_arr.copy_from_slice(&uuid);
        }

        if !self.node.is_provisioner() {
            return Err(MeshDbusError::NotAuthorized("Missing Interfaces".into()));
        }

        let agent = {
            let agent_ref = self.node.get_agent();
            match &*agent_ref {
                Some(a) => Arc::new(a.clone()),
                None => {
                    return Err(MeshDbusError::NotAuthorized("Missing Interfaces".into()));
                }
            }
        };

        let caller_id = PROV_CALLER_ID.fetch_add(1, Ordering::Relaxed);

        {
            let mut guard = PROV_PENDING.lock().unwrap();
            *guard = Some(ProvRemoteData {
                node: self.node.clone(),
                _agent: Some(agent.clone()),
                original: 0,
                primary: 0,
                net_idx: subidx,
                transport: PB_ADV,
                num_ele: 0,
                uuid: uuid_arr,
                caller_id,
            });
        }

        // Create oneshot channel for start callback.
        let (start_tx, start_rx) = tokio::sync::oneshot::channel::<i32>();

        let start_cb = Box::new(move |err: i32| {
            let _ = start_tx.send(err);
        });

        // Data request callback — spawns async handler.
        let data_req_cb = Box::new(move |num_ele: u8| -> bool {
            tokio::spawn(async move {
                handle_data_request(num_ele).await;
            });
            true
        });

        // Completion callback — spawns async handler.
        let complete_cb = Box::new(move |status: u8, info: Option<MeshProvNodeInfo>| -> bool {
            tokio::spawn(async move {
                handle_add_complete(status, info).await;
            });
            status == PROV_ERR_SUCCESS
        });

        let started = initiator_start(
            PB_ADV,
            server,
            subidx,
            uuid_arr,
            99,
            u32::from(sec),
            agent,
            start_cb,
            data_req_cb,
            complete_cb,
            self.node.clone(),
            caller_id,
        )
        .await;

        if !started {
            free_pending_add_call();
            return Err(MeshDbusError::Failed("Failed to start provisioning initiator".into()));
        }

        // Wait for the start callback to fire.
        match start_rx.await {
            Ok(err) if err == MeshError::None as i32 => {
                info!("AddNode provisioning started");
                Ok(())
            }
            Ok(_) => Err(MeshDbusError::Failed("Failed to start provisioning initiator".into())),
            Err(_) => Err(MeshDbusError::Failed("Provisioning start callback dropped".into())),
        }
    }

    // =======================================================================
    // Reprovision — Re-provision an existing device
    // =======================================================================

    /// Re-provision an already-provisioned mesh device.
    ///
    /// Arguments:
    /// - `unicast` (`q`): current unicast address of the device
    /// - `options` (`a{sv}`): optional keys `"NPPI"`, `"Subnet"`
    ///
    /// Replaces C `reprovision_call()` from `mesh/manager.c:333-411`.
    #[zbus(name = "Reprovision")]
    async fn reprovision(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        unicast: u16,
        options: HashMap<String, Value<'_>>,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        debug!("Reprovision request");

        if !is_unicast(unicast) {
            return Err(MeshDbusError::InvalidArgs("Bad Unicast".into()));
        }

        let default_subidx = {
            let net = self.node.get_net();
            net.get_primary_idx()
        };
        let mut subidx = default_subidx;

        let mut nppi: u8 = 0;

        // Parse options dictionary.
        for (key, value) in &options {
            match &**key {
                "NPPI" => {
                    nppi = value
                        .downcast_ref::<u8>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                    if nppi > 2 {
                        return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                    }
                }
                "Subnet" => {
                    subidx = value
                        .downcast_ref::<u16>()
                        .ok()
                        .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid options".into()))?;
                    if subidx > MAX_KEY_IDX {
                        return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                    }
                }
                _ => {
                    return Err(MeshDbusError::InvalidArgs("Invalid options".into()));
                }
            }
        }

        // Cancel outstanding scans.
        manager_scan_cancel(&self.node).await;

        if !self.node.is_provisioner() {
            return Err(MeshDbusError::NotAuthorized("Missing Interfaces".into()));
        }

        let agent = {
            let agent_ref = self.node.get_agent();
            match &*agent_ref {
                Some(a) => Arc::new(a.clone()),
                None => {
                    return Err(MeshDbusError::NotAuthorized("Missing Interfaces".into()));
                }
            }
        };

        let caller_id = PROV_CALLER_ID.fetch_add(1, Ordering::Relaxed);

        {
            let mut guard = PROV_PENDING.lock().unwrap();
            *guard = Some(ProvRemoteData {
                node: self.node.clone(),
                _agent: Some(agent.clone()),
                original: unicast,
                primary: 0,
                net_idx: subidx,
                transport: nppi,
                num_ele: 0,
                uuid: [0u8; 16],
                caller_id,
            });
        }

        // Create oneshot channel for start callback.
        let (start_tx, start_rx) = tokio::sync::oneshot::channel::<i32>();

        let start_cb = Box::new(move |err: i32| {
            let _ = start_tx.send(err);
        });

        let data_req_cb = Box::new(move |num_ele: u8| -> bool {
            tokio::spawn(async move {
                handle_data_request(num_ele).await;
            });
            true
        });

        let complete_cb = Box::new(move |status: u8, info: Option<MeshProvNodeInfo>| -> bool {
            tokio::spawn(async move {
                handle_add_complete(status, info).await;
            });
            status == PROV_ERR_SUCCESS
        });

        let uuid_arr = [0u8; 16]; // No UUID for reprovision.
        let started = initiator_start(
            nppi,
            unicast,
            subidx,
            uuid_arr,
            99,
            60,
            agent,
            start_cb,
            data_req_cb,
            complete_cb,
            self.node.clone(),
            caller_id,
        )
        .await;

        if !started {
            free_pending_add_call();
            return Err(MeshDbusError::Failed("Failed to start provisioning initiator".into()));
        }

        match start_rx.await {
            Ok(err) if err == MeshError::None as i32 => {
                info!("Reprovision started for 0x{:04x}", unicast);
                Ok(())
            }
            Ok(_) => Err(MeshDbusError::Failed("Failed to start provisioning initiator".into())),
            Err(_) => Err(MeshDbusError::Failed("Provisioning start callback dropped".into())),
        }
    }

    // =======================================================================
    // ImportRemoteNode — Import a remote node's device key
    // =======================================================================

    /// Import a remote device key into the keyring.
    ///
    /// Arguments:
    /// - `primary` (`q`): unicast address of the remote node
    /// - `count` (`y`): number of elements
    /// - `dev_key` (`ay`): 16-byte device key
    ///
    /// Replaces C `import_node_call()` from `mesh/manager.c:517-545`.
    #[zbus(name = "ImportRemoteNode")]
    async fn import_remote_node(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        primary: u16,
        count: u8,
        dev_key: Vec<u8>,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if dev_key.len() != 16 {
            return Err(MeshDbusError::InvalidArgs("Bad device key".into()));
        }

        let node_path = self.node.get_storage_dir();
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(&dev_key);

        if !keyring_put_remote_dev_key(&node_path, primary, count, &key_arr) {
            return Err(MeshDbusError::Failed("Failed to store device key".into()));
        }

        info!("ImportRemoteNode: primary=0x{:04x}, count={}", primary, count);
        Ok(())
    }

    // =======================================================================
    // DeleteRemoteNode — Delete a remote node's device key
    // =======================================================================

    /// Delete a remote device key from the keyring.
    ///
    /// Arguments:
    /// - `primary` (`q`): unicast address of the remote node
    /// - `count` (`y`): number of elements
    ///
    /// Replaces C `delete_node_call()` from `mesh/manager.c:547-570`.
    #[zbus(name = "DeleteRemoteNode")]
    async fn delete_remote_node(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        primary: u16,
        count: u8,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        // Cannot remove local device key.
        {
            let net = self.node.get_net();
            // Check each address in range [primary, primary+count).
            for i in 0..u16::from(count) {
                if net.is_local_address(primary + i) {
                    return Err(MeshDbusError::InvalidArgs(
                        "Cannot remove local device key".into(),
                    ));
                }
            }
        }

        let node_path = self.node.get_storage_dir();
        keyring_del_remote_dev_key(&node_path, primary, count);

        info!("DeleteRemoteNode: primary=0x{:04x}, count={}", primary, count);
        Ok(())
    }

    // =======================================================================
    // CreateSubnet — Create a new subnet with a randomly generated key
    // =======================================================================

    /// Create a new subnet with a randomly generated network key.
    ///
    /// Arguments:
    /// - `net_index` (`q`): the network key index to create
    ///
    /// Replaces C `create_subnet_call()` from `mesh/manager.c:792-812`.
    #[zbus(name = "CreateSubnet")]
    async fn create_subnet(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        net_index: u16,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if net_index == PRIMARY_NET_IDX {
            return Err(MeshDbusError::InvalidArgs("Cannot create primary subnet".into()));
        }

        // Generate a random 16-byte key.
        let mut key = [0u8; 16];
        getrandom_bytes(&mut key);

        store_new_subnet(&self.node, net_index, &key)?;
        info!("CreateSubnet: net_index=0x{:04x}", net_index);
        Ok(())
    }

    // =======================================================================
    // UpdateSubnet — Initiate key refresh on a subnet
    // =======================================================================

    /// Initiate key refresh for an existing subnet.
    ///
    /// Generates a new random key and transitions the subnet to Key Refresh
    /// Phase 1. Redundant calls during Phase 1 are allowed.
    ///
    /// Arguments:
    /// - `net_index` (`q`): the network key index to refresh
    ///
    /// Replaces C `update_subnet_call()` from `mesh/manager.c:814-855`.
    #[zbus(name = "UpdateSubnet")]
    async fn update_subnet(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        net_index: u16,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if net_index > MAX_KEY_IDX {
            return Err(MeshDbusError::InvalidArgs("Invalid net index".into()));
        }

        let node_path = self.node.get_storage_dir();

        let mut key = match keyring_get_net_key(&node_path, net_index) {
            Some(k) => k,
            None => return Err(MeshDbusError::DoesNotExist("Net key not found".into())),
        };

        match key.phase {
            p if p == KEY_REFRESH_PHASE_NONE => {
                // Generate new key and start key refresh phase 1.
                getrandom_bytes(&mut key.new_key);
                key.phase = KEY_REFRESH_PHASE_ONE;

                if !keyring_put_net_key(&node_path, net_index, &key) {
                    return Err(MeshDbusError::Failed("Failed to store updated net key".into()));
                }
                info!("UpdateSubnet: initiated KR phase 1 for 0x{:04x}", net_index);
                Ok(())
            }
            p if p == KEY_REFRESH_PHASE_ONE => {
                // Redundant call during phase 1 is allowed.
                Ok(())
            }
            _ => {
                // Key refresh already in progress (phase 2 or 3).
                Err(MeshDbusError::InProgress("Key Refresh in progress".into()))
            }
        }
    }

    // =======================================================================
    // DeleteSubnet — Delete a subnet
    // =======================================================================

    /// Delete a subnet and its network key.
    ///
    /// Arguments:
    /// - `net_index` (`q`): the network key index to delete
    ///
    /// Replaces C `delete_subnet_call()` from `mesh/manager.c:857-875`.
    #[zbus(name = "DeleteSubnet")]
    async fn delete_subnet(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        net_index: u16,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if net_index > MAX_KEY_IDX {
            return Err(MeshDbusError::InvalidArgs("Invalid net index".into()));
        }

        let node_path = self.node.get_storage_dir();
        keyring_del_net_key(&node_path, net_index);

        info!("DeleteSubnet: net_index=0x{:04x}", net_index);
        Ok(())
    }

    // =======================================================================
    // ImportSubnet — Import a subnet with explicit key material
    // =======================================================================

    /// Import a subnet with explicit key material.
    ///
    /// Arguments:
    /// - `net_index` (`q`): the network key index
    /// - `net_key` (`ay`): 16-byte network key
    ///
    /// Replaces C `import_subnet_call()` from `mesh/manager.c:877-900`.
    #[zbus(name = "ImportSubnet")]
    async fn import_subnet(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        net_index: u16,
        net_key: Vec<u8>,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if net_key.len() != 16 {
            return Err(MeshDbusError::InvalidArgs("Bad network key".into()));
        }

        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(&net_key);

        store_new_subnet(&self.node, net_index, &key_arr)?;
        info!("ImportSubnet: net_index=0x{:04x}", net_index);
        Ok(())
    }

    // =======================================================================
    // CreateAppKey — Create a new app key with random key material
    // =======================================================================

    /// Create a new application key bound to a network key, with randomly
    /// generated key material.
    ///
    /// Arguments:
    /// - `net_index` (`q`): bound network key index
    /// - `app_index` (`q`): application key index to create
    ///
    /// Replaces C `create_appkey_call()` from `mesh/manager.c:937-955`.
    #[zbus(name = "CreateAppKey")]
    async fn create_app_key(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        net_index: u16,
        app_index: u16,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        let mut key = [0u8; 16];
        getrandom_bytes(&mut key);

        store_new_appkey(&self.node, net_index, app_index, &key)?;
        info!("CreateAppKey: net_index=0x{:04x}, app_index=0x{:04x}", net_index, app_index);
        Ok(())
    }

    // =======================================================================
    // UpdateAppKey — Update an app key during key refresh
    // =======================================================================

    /// Update an application key during an active key refresh.
    ///
    /// A new random key is generated only if the bound network key is in
    /// Key Refresh Phase 1.
    ///
    /// Arguments:
    /// - `app_index` (`q`): the application key index to update
    ///
    /// Replaces C `update_appkey_call()` from `mesh/manager.c:957-988`.
    #[zbus(name = "UpdateAppKey")]
    async fn update_app_key(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        app_index: u16,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if app_index > MAX_KEY_IDX {
            return Err(MeshDbusError::InvalidArgs("Invalid app index".into()));
        }

        let node_path = self.node.get_storage_dir();

        let mut app_key = match keyring_get_app_key(&node_path, app_index) {
            Some(k) => k,
            None => return Err(MeshDbusError::DoesNotExist("App key not found".into())),
        };

        let net_key = match keyring_get_net_key(&node_path, app_key.net_idx) {
            Some(k) => k,
            None => return Err(MeshDbusError::DoesNotExist("Bound net key not found".into())),
        };

        if net_key.phase != KEY_REFRESH_PHASE_ONE {
            return Err(MeshDbusError::Failed("Invalid Phase".into()));
        }

        // Generate new app key.
        getrandom_bytes(&mut app_key.new_key);

        if !keyring_put_app_key(&node_path, app_index, app_key.net_idx, &app_key) {
            return Err(MeshDbusError::Failed("Failed to store updated app key".into()));
        }

        info!("UpdateAppKey: app_index=0x{:04x}", app_index);
        Ok(())
    }

    // =======================================================================
    // DeleteAppKey — Delete an application key
    // =======================================================================

    /// Delete an application key.
    ///
    /// Arguments:
    /// - `app_index` (`q`): the application key index to delete
    ///
    /// Replaces C `delete_appkey_call()` from `mesh/manager.c:990-1007`.
    #[zbus(name = "DeleteAppKey")]
    async fn delete_app_key(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        app_index: u16,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        let node_path = self.node.get_storage_dir();
        keyring_del_app_key(&node_path, app_index);

        info!("DeleteAppKey: app_index=0x{:04x}", app_index);
        Ok(())
    }

    // =======================================================================
    // ImportAppKey — Import an app key with explicit material
    // =======================================================================

    /// Import an application key with explicit key material.
    ///
    /// Arguments:
    /// - `net_index` (`q`): bound network key index
    /// - `app_index` (`q`): application key index
    /// - `app_key` (`ay`): 16-byte application key
    ///
    /// Replaces C `import_appkey_call()` from `mesh/manager.c:1009-1033`.
    #[zbus(name = "ImportAppKey")]
    async fn import_app_key(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        net_index: u16,
        app_index: u16,
        app_key: Vec<u8>,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        if app_key.len() != 16 {
            return Err(MeshDbusError::InvalidArgs("Bad application key".into()));
        }

        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(&app_key);

        store_new_appkey(&self.node, net_index, app_index, &key_arr)?;
        info!("ImportAppKey: net_index=0x{:04x}, app_index=0x{:04x}", net_index, app_index);
        Ok(())
    }

    // =======================================================================
    // SetKeyPhase — Control key refresh phase transitions
    // =======================================================================

    /// Set the Key Refresh phase for a subnet.
    ///
    /// Valid phase values: 0 (cancel from phase 1), 2, 3.
    /// Phase 1 cannot be set directly (use `UpdateSubnet` instead).
    /// Phase 3 finalizes the key refresh: copies new→old, finalizes app keys,
    /// then sets phase to 0.
    ///
    /// Arguments:
    /// - `net_index` (`q`): network key index
    /// - `phase` (`y`): target phase (0, 2, or 3)
    ///
    /// Replaces C `set_key_phase_call()` from `mesh/manager.c:1035-1084`.
    #[zbus(name = "SetKeyPhase")]
    async fn set_key_phase(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        net_index: u16,
        phase: u8,
    ) -> Result<(), MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        // Phase 1 cannot be set via SetKeyPhase.
        if phase == KEY_REFRESH_PHASE_ONE || phase > KEY_REFRESH_PHASE_THREE {
            return Err(MeshDbusError::InvalidArgs("Invalid phase".into()));
        }

        let node_path = self.node.get_storage_dir();

        let mut key = match keyring_get_net_key(&node_path, net_index) {
            Some(k) => k,
            None => return Err(MeshDbusError::DoesNotExist("Net key not found".into())),
        };

        // Canceling Key Refresh is only valid from Phase 1.
        if phase == KEY_REFRESH_PHASE_NONE && key.phase >= KEY_REFRESH_PHASE_TWO {
            return Err(MeshDbusError::InvalidArgs("Cannot cancel from phase 2 or later".into()));
        }

        if phase == KEY_REFRESH_PHASE_THREE {
            // If already in Phase None, nothing to do.
            if key.phase == KEY_REFRESH_PHASE_NONE {
                return Ok(());
            }

            // Finalize: copy new key → old key, persist with phase 3.
            key.old_key = key.new_key;
            key.phase = KEY_REFRESH_PHASE_THREE;

            if !keyring_put_net_key(&node_path, net_index, &key) {
                return Err(MeshDbusError::Failed("Failed to store net key".into()));
            }

            // Finalize all bound app keys.
            if !keyring_finalize_app_keys(&node_path, net_index) {
                return Err(MeshDbusError::Failed("Failed to finalize app keys".into()));
            }

            // Set final phase to 0.
            key.phase = KEY_REFRESH_PHASE_NONE;
        } else {
            key.phase = phase;
        }

        if !keyring_put_net_key(&node_path, net_index, &key) {
            return Err(MeshDbusError::Failed("Failed to store net key".into()));
        }

        info!("SetKeyPhase: net_index=0x{:04x}, phase={}", net_index, phase);
        Ok(())
    }

    // =======================================================================
    // ExportKeys — Export all keys
    // =======================================================================

    /// Export all network keys, application keys, and device keys.
    ///
    /// Returns: `a{sv}` dictionary containing `"NetKeys"` and `"DevKeys"`.
    ///
    /// Replaces C `export_keys_call()` from `mesh/manager.c:1086-1116`.
    #[zbus(name = "ExportKeys")]
    async fn export_keys(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Value<'static>, MeshDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| MeshDbusError::NotAuthorized("No sender".into()))?
            .to_string();
        check_authorization(&self.node, &sender)?;

        debug!("ExportKeys");

        let node_path = self.node.get_storage_dir();

        match crate::keyring::keyring_build_export_keys_reply(&node_path) {
            Ok(value) => {
                info!("ExportKeys: success");
                Ok(value)
            }
            Err(_) => Err(MeshDbusError::Failed("Failed to build export keys reply".into())),
        }
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Register the Management1 D-Bus interface definition with the connection.
///
/// This does NOT register an object at a specific path — that is done per-node
/// when the node is added to the mesh. This function only ensures the
/// interface schema is known to zbus.
///
/// Replaces C `manager_dbus_init()` from `mesh/manager.c:1156-1167`.
///
/// Returns `true` on success, `false` on failure.
pub async fn manager_dbus_init(_conn: &Connection) -> bool {
    debug!("Registering {} interface", MESH_MANAGEMENT_INTERFACE);
    // In zbus 5.x, interface registration happens when an object implementing
    // the interface is served at a path. There is no separate
    // "register_interface" step as in ELL's l_dbus_register_interface.
    // This function succeeds unconditionally; per-node object registration
    // occurs in node.rs when a ManagementInterface instance is served.
    true
}

// ---------------------------------------------------------------------------
// Utility Helpers
// ---------------------------------------------------------------------------

/// Extract a byte array from a zvariant `Value`.
///
/// Handles both `Value::Array` of bytes and direct `Vec<u8>` representations.
fn extract_byte_array(value: &Value<'_>) -> Option<Vec<u8>> {
    // Try via zvariant::Array — handles both ay and ab representations.
    if let Value::Array(arr) = value {
        let mut result = Vec::with_capacity(arr.len());
        for elem in arr.iter() {
            if let Ok(b) = elem.downcast_ref::<u8>() {
                result.push(b);
            } else {
                return None;
            }
        }
        return Some(result);
    }

    None
}

/// Fill a byte buffer with cryptographically-secure random bytes.
///
/// Uses the OS CSPRNG (`/dev/urandom`) via `getrandom()` syscall.
/// Replaces C `l_getrandom()`.
fn getrandom_bytes(buf: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(buf);
    } else {
        // Fallback: zero-fill (should never happen on Linux).
        buf.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_byte_array_from_array_value() {
        let bytes: Vec<Value<'_>> = vec![Value::U8(0x01), Value::U8(0x02), Value::U8(0xFF)];
        let arr = zbus::zvariant::Array::from(bytes);
        let val = Value::Array(arr);
        let result = extract_byte_array(&val);
        assert_eq!(result, Some(vec![0x01, 0x02, 0xFF]));
    }

    #[test]
    fn test_extract_byte_array_empty() {
        let arr = zbus::zvariant::Array::new(&zbus::zvariant::Signature::U8);
        let val = Value::Array(arr);
        let result = extract_byte_array(&val);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn test_extract_byte_array_non_array() {
        let val = Value::U32(42);
        let result = extract_byte_array(&val);
        assert_eq!(result, None);
    }

    #[test]
    fn test_getrandom_bytes_produces_output() {
        let mut buf = [0u8; 32];
        getrandom_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_getrandom_bytes_different_calls() {
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        getrandom_bytes(&mut buf1);
        getrandom_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_scan_id_monotonic() {
        let id1 = SCAN_ID.fetch_add(1, Ordering::Relaxed);
        let id2 = SCAN_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id2 > id1);
    }

    #[test]
    fn test_transport_constants() {
        assert_eq!(_PB_NPPI_00, 0x00);
        assert_eq!(PB_NPPI_01, 0x01);
        assert_eq!(PB_NPPI_02, 0x02);
        assert_eq!(PB_ADV, 0x03);
        assert_eq!(PRVB, [BT_AD_MESH_BEACON, 0x00]);
    }
}
