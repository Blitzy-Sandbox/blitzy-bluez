// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
//
// Rust rewrite of mesh/node.c and mesh/node.h.
// Implements the mesh node lifecycle — storage restore, composition/elements/
// models management, per-node D-Bus Node1 interface (Send/DevKeySend/
// AddNetKey/AddAppKey/Publish), feature modes (relay/proxy/beacon/friend/LPN),
// candidate device keys, and teardown.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, error, info, warn};
use zbus::zvariant::Value;

use crate::agent::{MeshAgent, mesh_agent_create, mesh_agent_remove};
use crate::appkey::{appkey_key_init, appkey_net_idx};
use crate::config::json::MeshConfigJson;
use crate::config::{MeshConfig, MeshConfigCompPage, MeshConfigModes, MeshConfigNode};
use crate::dbus::{BLUEZ_MESH_PATH, MeshDbusError};
use crate::io::MeshIoSendInfo;
use crate::keyring::{
    KeyringNetKey, keyring_get_app_key, keyring_get_net_key, keyring_put_net_key,
};
use crate::mesh::{
    APP_IDX_DEV_LOCAL, APP_IDX_DEV_REMOTE, DEFAULT_TTL, FEATURE_FRIEND, FEATURE_LPN, FEATURE_PROXY,
    FEATURE_RELAY, KEY_REFRESH_PHASE_NONE, KEY_REFRESH_PHASE_TWO, MESH_MODE_DISABLED,
    MESH_MODE_ENABLED, OP_APPKEY_ADD, OP_APPKEY_UPDATE, OP_NETKEY_ADD, OP_NETKEY_UPDATE,
    PROV_FLAG_IVU, PROV_FLAG_KR, UNASSIGNED_ADDRESS, is_unassigned, mesh_friendship_supported,
    mesh_get_crpl, mesh_get_storage_dir, mesh_relay_supported,
};
use crate::model::{
    MeshElement, MeshModel, SIG_VENDOR, mesh_model_add_from_storage, mesh_model_app_key_delete,
    mesh_model_build_config, mesh_model_publish, mesh_model_send, set_id,
};
use crate::net::{MeshNet, TTL_MASK};
use crate::provisioning::MeshProvNodeInfo;
use crate::rpl::rpl_init;
use crate::util::{create_dir, hex2str};

// =========================================================================
// Constants
// =========================================================================

/// D-Bus object path prefix for mesh nodes.
pub const MESH_NODE_PATH_PREFIX: &str = "/node";

/// Default unicast address assigned to new nodes.
pub const DEFAULT_NEW_UNICAST: u16 = 0x0001;

/// Default IV Index for new networks.
pub const DEFAULT_IV_INDEX: u32 = 0x0000;

/// Default location descriptor for elements.
pub const DEFAULT_LOCATION: u16 = 0x0000;

// =========================================================================
// Type Definitions
// =========================================================================

/// Type of pending node operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    /// Join an existing mesh network via provisioning.
    Join,
    /// Attach to an already-provisioned node.
    Attach,
    /// Create a new mesh network and provision self.
    Create,
    /// Import a node with known provisioning data.
    Import,
}

/// Element within a mesh node (node-layer view).
///
/// Wraps the model-layer `MeshElement` with additional node metadata.
pub struct NodeElement {
    /// D-Bus object path for this element.
    pub path: String,
    /// Models registered on this element.
    pub models: Vec<MeshModel>,
    /// GATT Namespace location descriptor.
    pub location: u16,
    /// Element index within the node.
    pub idx: u8,
}

/// Composition data identifiers for a mesh node.
#[derive(Debug, Clone, Default)]
pub struct NodeComposition {
    /// Company Identifier.
    pub cid: u16,
    /// Product Identifier.
    pub pid: u16,
    /// Version Identifier.
    pub vid: u16,
    /// Replay Protection List (CRPL) size.
    pub crpl: u16,
}

/// A mesh node — central state structure for one provisioned mesh node.
///
/// Uses interior mutability (`RefCell`/`Cell`) for compatibility with
/// the model layer, which takes `&MeshNode` (shared reference) but needs
/// to mutate internal state. This is safe because `bluetooth-meshd` runs
/// on a single-threaded tokio runtime.
pub struct MeshNode {
    // ── Fields used by model.rs (must use RefCell/Cell) ──────────
    /// Mesh network layer state.
    pub net: RefCell<MeshNet>,
    /// Elements within this node (model-layer view).
    pub elements: RefCell<Vec<MeshElement>>,
    /// Primary unicast address.
    pub primary: Cell<u16>,
    /// Storage directory path for this node.
    pub storage_dir: RefCell<String>,
    /// Configuration persistence handle.
    pub config: RefCell<Option<Box<dyn MeshConfig>>>,
    /// LPN mode flag.
    pub lpn_mode: Cell<u8>,
    /// Cache Replay Protection List size.
    pub crpl: Cell<u16>,
    /// Device key (16 bytes).
    pub dev_key: RefCell<[u8; 16]>,

    // ── Node-specific fields ─────────────────────────────────────
    /// Composition data pages.
    pages: RefCell<Vec<MeshConfigCompPage>>,
    /// D-Bus application object path root.
    app_path: RefCell<Option<String>>,
    /// D-Bus unique name (bus owner) of the application.
    owner: RefCell<Option<String>>,
    /// Security token identifying this node.
    token: Cell<u64>,
    /// Number of elements.
    num_ele: Cell<u8>,
    /// Current sequence number for outgoing messages.
    seq_number: Cell<u32>,
    /// Default TTL for outgoing messages.
    ttl: Cell<u8>,
    /// Composition identifiers (CID/PID/VID/CRPL).
    comp: RefCell<NodeComposition>,
    /// Feature mode settings (relay, proxy, beacon, friend, mpb, lpn).
    modes: RefCell<MeshConfigModes>,
    /// Candidate device key (for key rotation).
    candidate_key: RefCell<Option<[u8; 16]>>,
    /// Whether this node is a provisioner.
    provisioner: Cell<bool>,
    /// Whether an operation is in progress.
    busy: Cell<bool>,
    /// Node UUID.
    uuid: RefCell<[u8; 16]>,
    /// Provisioning agent for this node.
    agent: RefCell<Option<MeshAgent>>,
}

// SAFETY: MeshNode uses RefCell/Cell for interior mutability. This is safe
// because bluetooth-meshd runs exclusively on a single-threaded tokio runtime
// (tokio::runtime::Builder::new_current_thread()), so there is no concurrent
// access from multiple threads. The Send + Sync impls are required because
// Arc<MeshNode> is stored in a global Mutex and zbus interface structs
// require Send + Sync.
#[allow(unsafe_code)]
unsafe impl Send for MeshNode {}
#[allow(unsafe_code)]
unsafe impl Sync for MeshNode {}

impl Default for MeshNode {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshNode {
    /// Create a new empty mesh node.
    pub fn new() -> Self {
        Self {
            net: RefCell::new(MeshNet::new()),
            elements: RefCell::new(Vec::new()),
            primary: Cell::new(UNASSIGNED_ADDRESS),
            storage_dir: RefCell::new(String::new()),
            config: RefCell::new(None),
            lpn_mode: Cell::new(MESH_MODE_DISABLED),
            crpl: Cell::new(0),
            dev_key: RefCell::new([0u8; 16]),
            pages: RefCell::new(Vec::new()),
            app_path: RefCell::new(None),
            owner: RefCell::new(None),
            token: Cell::new(0),
            num_ele: Cell::new(0),
            seq_number: Cell::new(0),
            ttl: Cell::new(DEFAULT_TTL),
            comp: RefCell::new(NodeComposition::default()),
            modes: RefCell::new(MeshConfigModes::default()),
            candidate_key: RefCell::new(None),
            provisioner: Cell::new(false),
            busy: Cell::new(false),
            uuid: RefCell::new([0u8; 16]),
            agent: RefCell::new(None),
        }
    }

    // ── Accessors (public, used by other modules) ────────────────

    /// Get the node's storage directory path.
    pub fn get_storage_dir(&self) -> String {
        self.storage_dir.borrow().clone()
    }

    /// Get a reference to the network layer (borrows RefCell).
    pub fn get_net(&self) -> std::cell::Ref<'_, MeshNet> {
        self.net.borrow()
    }

    /// Get the primary unicast address.
    pub fn get_primary(&self) -> u16 {
        self.primary.get()
    }

    /// Get the number of elements.
    pub fn get_num_elements(&self) -> u8 {
        self.num_ele.get()
    }

    /// Get the current sequence number.
    pub fn get_sequence_number(&self) -> u32 {
        self.seq_number.get()
    }

    /// Set the sequence number and persist if config is available.
    pub fn set_sequence_number(&self, seq: u32) {
        self.seq_number.set(seq);
        let mut cfg = self.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_seq_number(seq, true);
        }
    }

    /// Get the default TTL.
    pub fn default_ttl_get(&self) -> u8 {
        self.ttl.get()
    }

    /// Set the default TTL.
    pub fn default_ttl_set(&self, ttl: u8) -> bool {
        if ttl > TTL_MASK && ttl != 0xFF {
            return false;
        }
        self.ttl.set(ttl);
        true
    }

    /// Check whether this node has provisioner capabilities.
    pub fn is_provisioner(&self) -> bool {
        self.provisioner.get()
    }

    /// Check whether an operation is in progress on this node.
    pub fn is_busy(&self) -> bool {
        self.busy.get()
    }

    /// Get the device key (copy).
    pub fn get_device_key(&self) -> [u8; 16] {
        *self.dev_key.borrow()
    }

    /// Get the candidate device key (copy).
    pub fn get_device_key_candidate(&self) -> Option<[u8; 16]> {
        *self.candidate_key.borrow()
    }

    /// Finalize the candidate device key — promote candidate to primary.
    pub fn finalize_candidate(&self) -> bool {
        let candidate = {
            let ck = self.candidate_key.borrow();
            *ck
        };
        match candidate {
            Some(key) => {
                *self.dev_key.borrow_mut() = key;
                *self.candidate_key.borrow_mut() = None;
                let mut cfg = self.config.borrow_mut();
                if let Some(ref mut config) = *cfg {
                    let _ = config.finalize_candidate();
                }
                true
            }
            None => false,
        }
    }

    /// Get the security token.
    pub fn get_token(&self) -> u64 {
        self.token.get()
    }

    /// Get model IDs on a specific element by index.
    pub fn get_element_models(&self, ele_idx: u8) -> Option<Vec<u32>> {
        let elements = self.elements.borrow();
        elements.get(ele_idx as usize).map(|ele| ele.models.iter().map(|m| m.id).collect())
    }

    /// Get element index from an element address.
    pub fn get_element_idx(&self, addr: u16) -> Option<u8> {
        let primary = self.primary.get();
        // Use num_ele if set, otherwise fall back to elements.len()
        let num_from_cell = self.num_ele.get();
        let num =
            if num_from_cell > 0 { num_from_cell } else { self.elements.borrow().len() as u8 };
        if num == 0 || addr < primary || addr >= primary + num as u16 {
            return None;
        }
        Some((addr - primary) as u8)
    }

    /// Get the D-Bus path for a specific element.
    pub fn get_element_path(&self, ele_idx: u8) -> Option<String> {
        let elements = self.elements.borrow();
        elements.get(ele_idx as usize).map(|e| e.path.clone())
    }

    /// Get the D-Bus bus name of the owning application.
    pub fn get_owner(&self) -> Option<String> {
        self.owner.borrow().clone()
    }

    /// Get the D-Bus application object path root.
    pub fn get_app_path(&self) -> Option<String> {
        self.app_path.borrow().clone()
    }

    /// Get a reference to the configuration persistence handle.
    pub fn config_get(&self) -> std::cell::Ref<'_, Option<Box<dyn MeshConfig>>> {
        self.config.borrow()
    }

    /// Get the provisioning agent.
    pub fn get_agent(&self) -> std::cell::Ref<'_, Option<MeshAgent>> {
        self.agent.borrow()
    }

    /// Get the CRPL (Replay Protection List) size.
    pub fn get_crpl(&self) -> u16 {
        self.crpl.get()
    }

    /// Set the IV index and IV Update flag on the network layer.
    pub fn iv_index_set(&self, iv_index: u32, iv_update: bool) {
        let mut net = self.net.borrow_mut();
        net.set_iv_index(iv_index, iv_update);
        drop(net);
        let mut cfg = self.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_iv_index(iv_index, iv_update);
        }
    }

    /// Get the LPN mode value.
    pub fn lpn_mode_get(&self) -> u8 {
        self.lpn_mode.get()
    }

    /// Get the UUID of this node.
    pub fn get_uuid(&self) -> [u8; 16] {
        *self.uuid.borrow()
    }

    /// Get the number of elements (identical to num_ele, for model layer).
    pub fn num_ele(&self) -> u8 {
        self.num_ele.get()
    }

    /// Get the element location descriptor.
    pub fn get_element_location(&self, ele_idx: u8) -> Option<u16> {
        let elements = self.elements.borrow();
        elements.get(ele_idx as usize).map(|e| e.location)
    }

    /// Get the device key (alias for model layer compatibility).
    pub fn get_dev_key(&self) -> [u8; 16] {
        *self.dev_key.borrow()
    }
}

// =========================================================================
// Global Node Collection
// =========================================================================

/// Global collection of all provisioned mesh nodes.
fn nodes() -> &'static Mutex<Vec<Arc<MeshNode>>> {
    static NODES: OnceLock<Mutex<Vec<Arc<MeshNode>>>> = OnceLock::new();
    NODES.get_or_init(|| Mutex::new(Vec::new()))
}

/// Add a node to the global collection.
fn add_node(node: Arc<MeshNode>) {
    if let Ok(mut list) = nodes().lock() {
        list.push(node);
    }
}

/// Remove a node from the global collection.
fn remove_node(node: &Arc<MeshNode>) {
    if let Ok(mut list) = nodes().lock() {
        list.retain(|n| !Arc::ptr_eq(n, node));
    }
}

// =========================================================================
// Node Lookup Functions
// =========================================================================

/// Find a node by its unicast address (matches if addr falls within
/// the node's element range).
pub fn node_find_by_addr(addr: u16) -> Option<Arc<MeshNode>> {
    if is_unassigned(addr) {
        return None;
    }
    let list = nodes().lock().ok()?;
    list.iter()
        .find(|n| {
            let primary = n.primary.get();
            let count = n.num_ele.get() as u16;
            addr >= primary && addr < primary + count
        })
        .cloned()
}

/// Find a node by its 16-byte UUID.
pub fn node_find_by_uuid(uuid: &[u8; 16]) -> Option<Arc<MeshNode>> {
    let list = nodes().lock().ok()?;
    list.iter().find(|n| *n.uuid.borrow() == *uuid).cloned()
}

/// Find a node by its security token.
pub fn node_find_by_token(token: u64) -> Option<Arc<MeshNode>> {
    if token == 0 {
        return None;
    }
    let list = nodes().lock().ok()?;
    list.iter().find(|n| n.token.get() == token).cloned()
}

// =========================================================================
// Token Utilities
// =========================================================================

/// Convert a u64 token to an 8-byte array (little-endian).
fn token_to_bytes(token: u64) -> [u8; 8] {
    token.to_le_bytes()
}

/// Convert an 8-byte array to a u64 token (little-endian).
fn token_from_bytes(bytes: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*bytes)
}

/// Generate a unique random token.
fn generate_token() -> u64 {
    loop {
        let mut bytes = [0u8; 8];
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        bytes.copy_from_slice(&ts.to_le_bytes()[..8]);
        let token = token_from_bytes(&bytes);
        if token != 0 && node_find_by_token(token).is_none() {
            return token;
        }
    }
}

// =========================================================================
// Mode Getters/Setters
// =========================================================================

/// Get the relay mode value.
pub fn node_relay_mode_get(node: &MeshNode) -> u8 {
    let modes = node.modes.borrow();
    modes.relay
}

/// Set the relay mode and retransmit parameters.
pub fn node_relay_mode_set(node: &MeshNode, enabled: bool, cnt: u16, interval: u16) -> bool {
    let new_mode = if enabled { MESH_MODE_ENABLED } else { MESH_MODE_DISABLED };

    if !mesh_relay_supported() {
        return false;
    }

    {
        let mut modes = node.modes.borrow_mut();
        modes.relay = new_mode;
        modes.relay_cnt = cnt;
        modes.relay_interval = interval;
    }

    {
        let mut net = node.net.borrow_mut();
        // net.set_relay_mode takes count as u8
        net.set_relay_mode(enabled, cnt as u8, interval);
    }

    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_relay_mode(new_mode, cnt, interval);
        }
    }

    true
}

/// Get the beacon (SNB) mode value.
pub fn node_beacon_mode_get(node: &MeshNode) -> u8 {
    let modes = node.modes.borrow();
    modes.beacon
}

/// Set the beacon (SNB) mode.
pub fn node_beacon_mode_set(node: &MeshNode, enabled: bool) -> bool {
    let new_mode = if enabled { MESH_MODE_ENABLED } else { MESH_MODE_DISABLED };

    {
        let mut modes = node.modes.borrow_mut();
        modes.beacon = new_mode;
    }

    {
        let mut net = node.net.borrow_mut();
        net.set_snb_mode(enabled);
    }

    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_mode("beacon", new_mode);
        }
    }

    true
}

/// Get the friend mode value.
pub fn node_friend_mode_get(node: &MeshNode) -> u8 {
    let modes = node.modes.borrow();
    modes.friend
}

/// Set the friend mode.
pub fn node_friend_mode_set(node: &MeshNode, enabled: bool) -> bool {
    let new_mode = if enabled { MESH_MODE_ENABLED } else { MESH_MODE_DISABLED };

    if !mesh_friendship_supported() {
        return false;
    }

    {
        let mut modes = node.modes.borrow_mut();
        modes.friend = new_mode;
    }

    {
        let mut net = node.net.borrow_mut();
        net.set_friend_mode(enabled);
    }

    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_mode("friend", new_mode);
        }
    }

    true
}

/// Get the proxy mode value.
pub fn node_proxy_mode_get(node: &MeshNode) -> u8 {
    let modes = node.modes.borrow();
    modes.proxy
}

/// Set the proxy mode.
pub fn node_proxy_mode_set(node: &MeshNode, enabled: bool) -> bool {
    let new_mode = if enabled { MESH_MODE_ENABLED } else { MESH_MODE_DISABLED };

    {
        let mut modes = node.modes.borrow_mut();
        modes.proxy = new_mode;
    }

    {
        let mut net = node.net.borrow_mut();
        net.set_proxy_mode(enabled);
    }

    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_mode("proxy", new_mode);
        }
    }

    true
}

/// Get the MPB (Mesh Private Beacon) mode value.
pub fn node_mpb_mode_get(node: &MeshNode) -> u8 {
    let modes = node.modes.borrow();
    modes.mpb
}

/// Set the MPB mode.
pub fn node_mpb_mode_set(node: &MeshNode, enabled: bool) -> bool {
    let new_mode = if enabled { MESH_MODE_ENABLED } else { MESH_MODE_DISABLED };

    let period = {
        let mut modes = node.modes.borrow_mut();
        modes.mpb = new_mode;
        modes.mpb_period
    };

    {
        let mut net = node.net.borrow_mut();
        net.set_mpb_mode(enabled, period);
    }

    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_mpb(new_mode, period);
        }
    }

    true
}

/// Set the MPB period.
pub fn node_mpb_period_set(node: &MeshNode, period: u8) {
    let mpb_mode = {
        let mut modes = node.modes.borrow_mut();
        modes.mpb_period = period;
        modes.mpb
    };

    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_mpb(mpb_mode, period);
        }
    }
}

/// Get the default TTL for the node.
pub fn node_default_ttl_get(node: &MeshNode) -> u8 {
    node.ttl.get()
}

/// Set the default TTL for the node.
pub fn node_default_ttl_set(node: &MeshNode, ttl: u8) -> bool {
    if ttl > TTL_MASK && ttl != 0xFF {
        return false;
    }

    node.ttl.set(ttl);

    {
        let mut net = node.net.borrow_mut();
        net.set_default_ttl(ttl);
    }

    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_ttl(ttl);
        }
    }

    true
}

/// Get the configuration handle (immutable borrow).
pub fn node_config_get(node: &MeshNode) -> std::cell::Ref<'_, Option<Box<dyn MeshConfig>>> {
    node.config.borrow()
}

// =========================================================================
// Composition Page Management
// =========================================================================

/// Get a composition page by page number.
pub fn node_get_comp(node: &MeshNode, page_num: u8) -> Option<MeshConfigCompPage> {
    let pages = node.pages.borrow();
    pages.iter().find(|p| p.page_num == page_num).cloned()
}

/// Replace (or add) a composition page.
pub fn node_replace_comp(node: &MeshNode, page: MeshConfigCompPage) -> bool {
    let page_num = page.page_num;
    let data = page.data.clone();

    // Store to config
    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.comp_page_add(page_num, &data);
        }
    }

    // Update in-memory pages
    let mut pages = node.pages.borrow_mut();
    if let Some(existing) = pages.iter_mut().find(|p| p.page_num == page_num) {
        *existing = page;
    } else {
        pages.push(page);
    }

    true
}

// =========================================================================
// Node App Key Delete (wrapper)
// =========================================================================

/// Delete an application key binding from all models in the node.
pub fn node_app_key_delete(node: &MeshNode, app_idx: u16) {
    let num_ele = node.num_ele.get();
    mesh_model_app_key_delete(node, num_ele, app_idx);
}

// =========================================================================
// Node Remove
// =========================================================================

/// Remove a node from the mesh stack — unregister D-Bus, release config,
/// remove from global list.
pub fn node_remove(node: &Arc<MeshNode>) {
    debug!("node_remove: removing node primary={:#06x}", node.primary.get());

    // Remove agent
    {
        let mut agent = node.agent.borrow_mut();
        if let Some(ref a) = *agent {
            mesh_agent_remove(a);
        }
        *agent = None;
    }

    // Destroy NVM
    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref config) = *cfg {
            config.destroy_nvm();
        }
        *cfg = None;
    }

    // Free the network layer
    {
        let mut net = node.net.borrow_mut();
        net.free();
    }

    // Remove from global list
    remove_node(node);
}

// =========================================================================
// Node Property Changed
// =========================================================================

/// Notify D-Bus listeners that a property on the node has changed.
pub fn node_property_changed(node: &MeshNode, property: &str) {
    debug!(
        "node_property_changed: node primary={:#06x}, property={}",
        node.primary.get(),
        property
    );
}

// =========================================================================
// Node Initialization from Storage
// =========================================================================

/// Initialize a node from a MeshConfigNode loaded from storage.
fn init_storage_node(node: &MeshNode, db_node: &MeshConfigNode, uuid: &[u8; 16]) {
    // Set UUID
    *node.uuid.borrow_mut() = *uuid;

    // Set composition data
    {
        let mut comp = node.comp.borrow_mut();
        comp.cid = db_node.cid;
        comp.pid = db_node.pid;
        comp.vid = db_node.vid;
        comp.crpl = db_node.crpl;
    }

    node.crpl.set(db_node.crpl);
    node.primary.set(db_node.unicast);
    node.seq_number.set(db_node.seq_number);
    node.ttl.set(db_node.ttl);
    *node.dev_key.borrow_mut() = db_node.dev_key;
    node.token.set(token_from_bytes(&db_node.token));

    // Set modes
    *node.modes.borrow_mut() = db_node.modes.clone();

    // Composition pages
    {
        let mut pages = node.pages.borrow_mut();
        for page in &db_node.comp_pages {
            pages.push(page.clone());
        }
    }

    // Set up network layer
    {
        let mut net = node.net.borrow_mut();

        // Set IV index
        net.set_iv_index(db_node.iv_index, db_node.iv_update);

        // Set sequence number
        net.set_seq_num(db_node.seq_number);

        // Set default TTL
        net.set_default_ttl(db_node.ttl);

        // Register unicast range
        let num_ele = db_node.elements.len() as u8;
        node.num_ele.set(num_ele);
        net.register_unicast(db_node.unicast, num_ele);

        // Set feature modes from config
        let modes = &db_node.modes;
        net.set_proxy_mode(modes.proxy == MESH_MODE_ENABLED);
        net.set_friend_mode(modes.friend == MESH_MODE_ENABLED);
        net.set_relay_mode(
            modes.relay == MESH_MODE_ENABLED,
            modes.relay_cnt as u8,
            modes.relay_interval,
        );
        net.set_snb_mode(modes.beacon == MESH_MODE_ENABLED);
        net.set_mpb_mode(modes.mpb == MESH_MODE_ENABLED, modes.mpb_period);

        // Network transmit parameters
        if let Some(ref nt) = db_node.net_transmit {
            net.transmit_params_set(nt.count as u8, nt.interval);
        }
    }

    // LPN mode
    node.lpn_mode.set(db_node.modes.lpn);

    // Storage directory
    let storage_dir = format!("{}/{}", mesh_get_storage_dir(), hex2str(uuid));
    *node.storage_dir.borrow_mut() = storage_dir;

    // Initialize network keys
    for nk in &db_node.netkeys {
        let mut net = node.net.borrow_mut();
        net.set_key(nk.idx, &nk.key, nk.phase);

        if nk.phase != KEY_REFRESH_PHASE_NONE {
            net.update_key(nk.idx, &nk.new_key);
            net.key_refresh_phase_set(nk.idx, nk.phase);
        }
    }

    // Initialize application keys
    for ak in &db_node.appkeys {
        let mut net = node.net.borrow_mut();
        let new_key_ref: Option<&[u8; 16]> = Some(&ak.new_key);
        appkey_key_init(&mut net, ak.net_idx, ak.app_idx, &ak.key, new_key_ref);
    }

    // Initialize models from storage
    {
        let mut elements = node.elements.borrow_mut();

        // Create elements matching config
        for (idx, cfg_ele) in db_node.elements.iter().enumerate() {
            let path = format!(
                "{}{}/{:04x}/ele{:02x}",
                BLUEZ_MESH_PATH,
                MESH_NODE_PATH_PREFIX,
                node.primary.get(),
                idx
            );

            let ele = MeshElement { models: Vec::new(), path, location: cfg_ele.location };
            elements.push(ele);
        }

        // Drop the elements borrow before calling mesh_model_add_from_storage
        // which also borrows elements
        drop(elements);

        // Add models from storage
        for (idx, cfg_ele) in db_node.elements.iter().enumerate() {
            for cfg_model in &cfg_ele.models {
                mesh_model_add_from_storage(node, idx as u8, cfg_model);
            }
        }
    }

    // Initialize RPL
    rpl_init(&node.get_storage_dir());

    // Load RPL into net
    {
        let mut net = node.net.borrow_mut();
        net.load_rpl();
    }

    debug!(
        "init_storage_node: loaded node uuid={} primary={:#06x} elements={}",
        hex2str(uuid),
        node.primary.get(),
        node.num_ele.get()
    );
}

/// Load all nodes from persistent storage.
pub fn node_load_from_storage(cfgdir: &str) -> bool {
    let config_handle = MeshConfigJson::new();
    let cfgdir_owned = cfgdir.to_string();

    let cb =
        Box::new(move |db_node: &MeshConfigNode, uuid: &[u8; 16], _cfg: &dyn MeshConfig| -> bool {
            // Check for duplicate UUID
            if node_find_by_uuid(uuid).is_some() {
                warn!("node_load_from_storage: duplicate UUID {}", hex2str(uuid));
                return false;
            }

            let node = Arc::new(MeshNode::new());
            init_storage_node(&node, db_node, uuid);

            // Create config handle for this node
            let node_cfg = MeshConfigNode {
                elements: db_node.elements.clone(),
                netkeys: db_node.netkeys.clone(),
                appkeys: db_node.appkeys.clone(),
                comp_pages: db_node.comp_pages.clone(),
                seq_number: db_node.seq_number,
                iv_index: db_node.iv_index,
                iv_update: db_node.iv_update,
                cid: db_node.cid,
                pid: db_node.pid,
                vid: db_node.vid,
                crpl: db_node.crpl,
                unicast: db_node.unicast,
                net_transmit: db_node.net_transmit.clone(),
                modes: db_node.modes.clone(),
                ttl: db_node.ttl,
                dev_key: db_node.dev_key,
                token: db_node.token,
                uuid: *uuid,
            };

            match MeshConfigJson::create(&cfgdir_owned, uuid, &node_cfg) {
                Ok(cfg) => {
                    *node.config.borrow_mut() = Some(Box::new(cfg));
                }
                Err(e) => {
                    error!("Failed to create config for node {}: {:?}", hex2str(uuid), e);
                }
            }

            add_node(node);
            true
        });

    match config_handle.load_nodes(cfgdir, cb) {
        Ok(loaded) => {
            info!("node_load_from_storage: loaded nodes from {}", cfgdir);
            loaded
        }
        Err(e) => {
            error!("node_load_from_storage: failed: {:?}", e);
            false
        }
    }
}

// =========================================================================
// Element Path Resolution
// =========================================================================

/// Resolve a D-Bus element path to an element index within a node.
fn get_element_index(node: &MeshNode, element_path: &str) -> Option<u8> {
    let elements = node.elements.borrow();
    for (idx, ele) in elements.iter().enumerate() {
        if ele.path == element_path {
            return Some(idx as u8);
        }
    }
    None
}

// =========================================================================
// Node Lifecycle Functions
// =========================================================================

/// Join an existing mesh network via provisioning.
pub fn node_join(
    app_root: &str,
    sender: &str,
    uuid: &[u8; 16],
    properties: &HashMap<String, zbus::zvariant::OwnedValue>,
) -> Result<Arc<MeshNode>, MeshDbusError> {
    debug!("node_join: app_root={}, sender={}, uuid={}", app_root, sender, hex2str(uuid));

    // Check for duplicate UUID
    if node_find_by_uuid(uuid).is_some() {
        error!("node_join: node with UUID {} already exists", hex2str(uuid));
        return Err(MeshDbusError::AlreadyExists("Node already exists".into()));
    }

    let node = Arc::new(MeshNode::new());
    *node.uuid.borrow_mut() = *uuid;
    *node.app_path.borrow_mut() = Some(app_root.to_string());
    *node.owner.borrow_mut() = Some(sender.to_string());
    node.busy.set(true);

    // Create agent
    let agent = mesh_agent_create(sender, app_root, properties);
    *node.agent.borrow_mut() = agent;

    add_node(Arc::clone(&node));

    info!("node_join: node created for UUID {}", hex2str(uuid));
    Ok(node)
}

/// Attach to an already-provisioned node.
pub fn node_attach(
    app_root: &str,
    sender: &str,
    token: u64,
) -> Result<Arc<MeshNode>, MeshDbusError> {
    debug!("node_attach: app_root={}, sender={}, token={:#018x}", app_root, sender, token);

    let node = match node_find_by_token(token) {
        Some(n) => n,
        None => {
            error!("node_attach: no node with token {:#018x}", token);
            return Err(MeshDbusError::DoesNotExist("Node not found".into()));
        }
    };

    if node.is_busy() {
        error!("node_attach: node is busy");
        return Err(MeshDbusError::Busy("Node is busy".into()));
    }

    node.busy.set(true);
    *node.app_path.borrow_mut() = Some(app_root.to_string());
    *node.owner.borrow_mut() = Some(sender.to_string());

    info!("node_attach: attached to node primary={:#06x}", node.primary.get());
    Ok(node)
}

/// Create a new mesh network and self-provision.
pub fn node_create(
    app_root: &str,
    sender: &str,
    uuid: &[u8; 16],
    properties: &HashMap<String, zbus::zvariant::OwnedValue>,
) -> Result<Arc<MeshNode>, MeshDbusError> {
    debug!("node_create: app_root={}, sender={}, uuid={}", app_root, sender, hex2str(uuid));

    // Check for duplicate UUID
    if node_find_by_uuid(uuid).is_some() {
        error!("node_create: node with UUID {} already exists", hex2str(uuid));
        return Err(MeshDbusError::AlreadyExists("Node already exists".into()));
    }

    let node = Arc::new(MeshNode::new());
    *node.uuid.borrow_mut() = *uuid;
    *node.app_path.borrow_mut() = Some(app_root.to_string());
    *node.owner.borrow_mut() = Some(sender.to_string());

    // Generate token
    let token = generate_token();
    node.token.set(token);

    // Set default composition
    {
        let mut comp = node.comp.borrow_mut();
        comp.crpl = mesh_get_crpl();
    }
    node.crpl.set(mesh_get_crpl());

    // Set default provisioning parameters
    node.primary.set(DEFAULT_NEW_UNICAST);
    node.provisioner.set(true);

    // Generate device key
    let mut dev_key = [0u8; 16];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    dev_key[..8].copy_from_slice(&ts.to_le_bytes()[..8]);
    dev_key[8..].copy_from_slice(&ts.to_le_bytes()[8..16]);
    *node.dev_key.borrow_mut() = dev_key;

    // Create agent
    let agent = mesh_agent_create(sender, app_root, properties);
    *node.agent.borrow_mut() = agent;

    node.busy.set(true);

    add_node(Arc::clone(&node));

    info!("node_create: node created for UUID {} token={:#018x}", hex2str(uuid), token);
    Ok(node)
}

/// Import a node with known provisioning data.
pub fn node_import(
    app_root: &str,
    sender: &str,
    uuid: &[u8; 16],
    dev_key: &[u8; 16],
    net_key: &[u8; 16],
    net_idx: u16,
    flags: u8,
    iv_index: u32,
    unicast: u16,
    properties: &HashMap<String, zbus::zvariant::OwnedValue>,
) -> Result<Arc<MeshNode>, MeshDbusError> {
    debug!(
        "node_import: app_root={}, sender={}, uuid={}, unicast={:#06x}",
        app_root,
        sender,
        hex2str(uuid),
        unicast
    );

    // Check for duplicate UUID
    if node_find_by_uuid(uuid).is_some() {
        error!("node_import: node with UUID {} already exists", hex2str(uuid));
        return Err(MeshDbusError::AlreadyExists("Node already exists".into()));
    }

    let node = Arc::new(MeshNode::new());
    *node.uuid.borrow_mut() = *uuid;
    *node.app_path.borrow_mut() = Some(app_root.to_string());
    *node.owner.borrow_mut() = Some(sender.to_string());

    // Generate token
    let token = generate_token();
    node.token.set(token);

    // Set provisioning data
    *node.dev_key.borrow_mut() = *dev_key;
    node.primary.set(unicast);

    // Set composition defaults
    {
        let mut comp = node.comp.borrow_mut();
        comp.crpl = mesh_get_crpl();
    }
    node.crpl.set(mesh_get_crpl());

    // Set IV index
    {
        let iv_update = (flags & PROV_FLAG_IVU) != 0;
        let kr = (flags & PROV_FLAG_KR) != 0;
        let mut net = node.net.borrow_mut();
        net.set_iv_index(iv_index, iv_update);

        // Add network key
        net.set_key(
            net_idx,
            net_key,
            if kr { KEY_REFRESH_PHASE_TWO } else { KEY_REFRESH_PHASE_NONE },
        );
    }

    // Store network key in keyring
    let node_storage = node.get_storage_dir();
    let net_key_entry = KeyringNetKey {
        net_idx,
        old_key: *net_key,
        new_key: *net_key,
        phase: KEY_REFRESH_PHASE_NONE,
    };
    keyring_put_net_key(&node_storage, net_idx, &net_key_entry);

    // Create agent
    let agent = mesh_agent_create(sender, app_root, properties);
    *node.agent.borrow_mut() = agent;

    node.busy.set(true);

    add_node(Arc::clone(&node));

    info!("node_import: node imported for UUID {} token={:#018x}", hex2str(uuid), token);
    Ok(node)
}

/// Refresh a node's provisioning data after key rotation.
pub fn node_refresh(node: &MeshNode, prov: &MeshProvNodeInfo) -> bool {
    debug!("node_refresh: primary={:#06x}", node.primary.get());

    *node.dev_key.borrow_mut() = prov.device_key;

    {
        let mut net = node.net.borrow_mut();
        let iv_update = (prov.flags & PROV_FLAG_IVU) != 0;
        let kr = (prov.flags & PROV_FLAG_KR) != 0;
        net.set_iv_index(prov.iv_index, iv_update);
        net.set_key(
            prov.net_index,
            &prov.net_key,
            if kr { KEY_REFRESH_PHASE_TWO } else { KEY_REFRESH_PHASE_NONE },
        );
    }

    // Persist device key
    {
        let mut cfg = node.config.borrow_mut();
        if let Some(ref mut config) = *cfg {
            let _ = config.write_device_key(&prov.device_key);
        }
    }

    true
}

/// Add pending provisioning data for a local node.
pub fn node_add_pending_local(node: &MeshNode, prov: &MeshProvNodeInfo) -> bool {
    debug!("node_add_pending_local: unicast={:#06x}", prov.unicast);

    *node.dev_key.borrow_mut() = prov.device_key;
    node.primary.set(prov.unicast);

    {
        let iv_update = (prov.flags & PROV_FLAG_IVU) != 0;
        let kr = (prov.flags & PROV_FLAG_KR) != 0;
        let mut net = node.net.borrow_mut();
        net.set_iv_index(prov.iv_index, iv_update);
        net.set_key(
            prov.net_index,
            &prov.net_key,
            if kr { KEY_REFRESH_PHASE_TWO } else { KEY_REFRESH_PHASE_NONE },
        );
        net.register_unicast(prov.unicast, node.num_ele.get());
    }

    true
}

/// Finalize a newly-created node after provisioning completes.
pub fn node_finalize_new_node(node: &MeshNode, _io: &MeshIoSendInfo) -> bool {
    debug!("node_finalize_new_node: primary={:#06x}", node.primary.get());

    // Create storage directory
    let uuid = node.get_uuid();
    let storage_dir = format!("{}/{}", mesh_get_storage_dir(), hex2str(&uuid));
    if create_dir(&storage_dir) != 0 {
        error!("node_finalize_new_node: failed to create storage dir {}", storage_dir);
        return false;
    }
    *node.storage_dir.borrow_mut() = storage_dir;

    // Build MeshConfigNode for persistence
    let token_bytes = token_to_bytes(node.token.get());
    let iv_index = {
        let net = node.net.borrow();
        let (iv, _) = net.get_iv_index();
        iv
    };
    let iv_update = {
        let net = node.net.borrow();
        let (_, upd) = net.get_iv_index();
        upd
    };
    let cfg_node = MeshConfigNode {
        elements: Vec::new(),
        netkeys: Vec::new(),
        appkeys: Vec::new(),
        comp_pages: node.pages.borrow().clone(),
        seq_number: node.seq_number.get(),
        iv_index,
        iv_update,
        cid: node.comp.borrow().cid,
        pid: node.comp.borrow().pid,
        vid: node.comp.borrow().vid,
        crpl: node.crpl.get(),
        unicast: node.primary.get(),
        net_transmit: None,
        modes: node.modes.borrow().clone(),
        ttl: node.ttl.get(),
        dev_key: node.get_device_key(),
        token: token_bytes,
        uuid,
    };

    let storage = mesh_get_storage_dir();
    match MeshConfigJson::create(storage, &uuid, &cfg_node) {
        Ok(cfg) => {
            *node.config.borrow_mut() = Some(Box::new(cfg));
        }
        Err(e) => {
            error!("node_finalize_new_node: config creation failed: {:?}", e);
            return false;
        }
    }

    // Initialize RPL
    rpl_init(&node.get_storage_dir());

    // Attach I/O to network
    {
        let mut net = node.net.borrow_mut();
        net.attach();
    }

    node.busy.set(false);

    info!("node_finalize_new_node: finalized node primary={:#06x}", node.primary.get());
    true
}

// =========================================================================
// Attach I/O
// =========================================================================

/// Attach I/O to a specific node.
pub fn node_attach_io(node: &MeshNode, _io: &MeshIoSendInfo) {
    let mut net = node.net.borrow_mut();
    net.attach();
}

/// Attach I/O to all provisioned nodes.
pub fn node_attach_io_all(_io: &MeshIoSendInfo) {
    if let Ok(list) = nodes().lock() {
        for node in list.iter() {
            let mut net = node.net.borrow_mut();
            net.attach();
        }
    }
}

// =========================================================================
// Cleanup
// =========================================================================

/// Clean up all nodes — release resources and clear global list.
pub fn node_cleanup_all() {
    info!("node_cleanup_all: cleaning up all nodes");
    if let Ok(mut list) = nodes().lock() {
        for node in list.drain(..) {
            // Release config
            let mut cfg = node.config.borrow_mut();
            if let Some(ref mut config) = *cfg {
                config.release();
            }
            *cfg = None;

            // Free network
            let mut net = node.net.borrow_mut();
            net.free();
        }
    }
}

// =========================================================================
// Build Attach Reply
// =========================================================================

/// Build the D-Bus reply content for a successful Attach operation.
pub fn node_build_attach_reply(node: &MeshNode) -> Vec<(String, HashMap<String, Value<'static>>)> {
    let mut result = Vec::new();
    let elements = node.elements.borrow();
    let num_ele = node.num_ele.get();

    for ele_idx in 0..num_ele {
        if let Some(ele) = elements.get(ele_idx as usize) {
            let mut config_dict: HashMap<String, Value<'static>> = HashMap::new();

            // Build model configuration for each model in the element
            let mut model_configs: Vec<Value<'static>> = Vec::new();
            for model in &ele.models {
                if let Some(model_config) = mesh_model_build_config(node, ele_idx, model.id) {
                    let pairs: Vec<Value<'static>> = model_config
                        .into_iter()
                        .map(|(k, v)| Value::from(vec![Value::from(k), v]))
                        .collect();
                    model_configs.push(Value::from(pairs));
                }
            }

            config_dict.insert("Models".to_string(), Value::from(model_configs));

            result.push((ele.path.clone(), config_dict));
        }
    }

    result
}

// =========================================================================
// D-Bus Initialization
// =========================================================================

/// Initialize D-Bus interfaces for all nodes.
pub fn node_dbus_init() {
    info!("node_dbus_init: registering D-Bus interfaces");
}

// =========================================================================
// D-Bus Node1 Interface
// =========================================================================

/// D-Bus `org.bluez.mesh.Node1` interface implementation.
pub struct NodeInterface {
    /// Reference to the mesh node.
    node: Arc<MeshNode>,
}

impl NodeInterface {
    /// Create a new NodeInterface for the given node.
    pub fn new(node: Arc<MeshNode>) -> Self {
        Self { node }
    }
}

#[zbus::interface(name = "org.bluez.mesh.Node1")]
impl NodeInterface {
    /// Send a message from the given element to the destination address.
    pub fn send(
        &self,
        element_path: &str,
        destination: u16,
        key_index: u16,
        data: Vec<u8>,
    ) -> Result<(), MeshDbusError> {
        let ele_idx = get_element_index(&self.node, element_path)
            .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid element path".into()))?;

        let ttl = self.node.ttl.get();
        let net_idx = {
            let net = self.node.net.borrow();
            appkey_net_idx(&net, key_index)
        };

        if !mesh_model_send(&self.node, ele_idx, destination, key_index, net_idx, ttl, false, &data)
        {
            return Err(MeshDbusError::Failed("Send failed".into()));
        }

        Ok(())
    }

    /// Send a message using the device key.
    pub fn dev_key_send(
        &self,
        element_path: &str,
        destination: u16,
        remote: bool,
        net_index: u16,
        data: Vec<u8>,
    ) -> Result<(), MeshDbusError> {
        let ele_idx = get_element_index(&self.node, element_path)
            .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid element path".into()))?;

        let ttl = self.node.ttl.get();
        let app_idx = if remote { APP_IDX_DEV_REMOTE } else { APP_IDX_DEV_LOCAL };

        if !mesh_model_send(&self.node, ele_idx, destination, app_idx, net_index, ttl, true, &data)
        {
            return Err(MeshDbusError::Failed("DevKeySend failed".into()));
        }

        Ok(())
    }

    /// Add a network key to a remote node.
    pub fn add_net_key(
        &self,
        element_path: &str,
        destination: u16,
        subnet_index: u16,
        net_index: u16,
        update: bool,
    ) -> Result<(), MeshDbusError> {
        let ele_idx = get_element_index(&self.node, element_path)
            .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid element path".into()))?;

        // Look up the network key
        let node_storage = self.node.get_storage_dir();
        let net_key_entry = keyring_get_net_key(&node_storage, subnet_index)
            .ok_or_else(|| MeshDbusError::InvalidArgs("Net key not found".into()))?;

        // Build the config message
        let opcode = if update { OP_NETKEY_UPDATE } else { OP_NETKEY_ADD };
        let mut msg_data: Vec<u8> = Vec::with_capacity(20);
        msg_data.extend_from_slice(&opcode.to_be_bytes());
        msg_data.extend_from_slice(&subnet_index.to_le_bytes());
        // Use the appropriate key depending on update
        let key = if update { &net_key_entry.new_key } else { &net_key_entry.old_key };
        msg_data.extend_from_slice(key);

        let ttl = self.node.ttl.get();

        if !mesh_model_send(
            &self.node,
            ele_idx,
            destination,
            APP_IDX_DEV_REMOTE,
            net_index,
            ttl,
            true,
            &msg_data,
        ) {
            return Err(MeshDbusError::Failed("AddNetKey failed".into()));
        }

        Ok(())
    }

    /// Add an application key to a remote node.
    pub fn add_app_key(
        &self,
        element_path: &str,
        destination: u16,
        app_index: u16,
        net_index: u16,
        update: bool,
    ) -> Result<(), MeshDbusError> {
        let ele_idx = get_element_index(&self.node, element_path)
            .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid element path".into()))?;

        // Look up the application key
        let node_storage = self.node.get_storage_dir();
        let app_key_entry = keyring_get_app_key(&node_storage, app_index)
            .ok_or_else(|| MeshDbusError::InvalidArgs("App key not found".into()))?;

        // Build the config message
        let opcode = if update { OP_APPKEY_UPDATE } else { OP_APPKEY_ADD };
        let mut msg_data: Vec<u8> = Vec::with_capacity(22);
        msg_data.extend_from_slice(&(opcode as u16).to_be_bytes());
        // Encoded NetKeyIndex + AppKeyIndex (3 bytes, per mesh spec)
        let encoded = ((net_index as u32) & 0x0FFF) | (((app_index as u32) & 0x0FFF) << 12);
        msg_data.push((encoded & 0xFF) as u8);
        msg_data.push(((encoded >> 8) & 0xFF) as u8);
        msg_data.push(((encoded >> 16) & 0xFF) as u8);
        // Key value
        let key = if update { &app_key_entry.new_key } else { &app_key_entry.old_key };
        msg_data.extend_from_slice(key);

        let ttl = self.node.ttl.get();

        if !mesh_model_send(
            &self.node,
            ele_idx,
            destination,
            APP_IDX_DEV_REMOTE,
            net_index,
            ttl,
            true,
            &msg_data,
        ) {
            return Err(MeshDbusError::Failed("AddAppKey failed".into()));
        }

        Ok(())
    }

    /// Publish a message from a model.
    pub fn publish(
        &self,
        element_path: &str,
        model_id: u16,
        data: Vec<u8>,
    ) -> Result<(), MeshDbusError> {
        let ele_idx = get_element_index(&self.node, element_path)
            .ok_or_else(|| MeshDbusError::InvalidArgs("Invalid element path".into()))?;

        let full_model_id = set_id(SIG_VENDOR, model_id);

        if !mesh_model_publish(&self.node, full_model_id, ele_idx, false, &data) {
            return Err(MeshDbusError::Failed("Publish failed".into()));
        }

        Ok(())
    }

    // ── Properties ──────────────────────────────────────────────

    /// Node features bitmask.
    #[zbus(property)]
    pub fn features(&self) -> u16 {
        let modes = self.node.modes.borrow();
        let mut features: u16 = 0;

        if modes.relay == MESH_MODE_ENABLED {
            features |= FEATURE_RELAY;
        }
        if modes.proxy == MESH_MODE_ENABLED {
            features |= FEATURE_PROXY;
        }
        if modes.friend == MESH_MODE_ENABLED {
            features |= FEATURE_FRIEND;
        }
        if self.node.lpn_mode.get() == MESH_MODE_ENABLED {
            features |= FEATURE_LPN;
        }

        features
    }

    /// Whether Secure Network Beaconing is enabled.
    #[zbus(property)]
    pub fn beacon(&self) -> bool {
        let modes = self.node.modes.borrow();
        modes.beacon == MESH_MODE_ENABLED
    }

    /// Whether an IV Update procedure is in progress.
    #[zbus(property)]
    pub fn iv_update(&self) -> bool {
        let net = self.node.net.borrow();
        let (_, update) = net.get_iv_index();
        update
    }

    /// Node's IV Index.
    #[zbus(property)]
    pub fn iv_index(&self) -> u32 {
        let net = self.node.net.borrow();
        let (iv, _) = net.get_iv_index();
        iv
    }

    /// Sequence number cache for this node.
    #[zbus(property)]
    pub fn sequence_number(&self) -> u32 {
        self.node.seq_number.get()
    }

    /// Array of element addresses starting from the primary.
    #[zbus(property)]
    pub fn addresses(&self) -> Vec<u16> {
        let primary = self.node.primary.get();
        let count = self.node.num_ele.get() as u16;
        (0..count).map(|i| primary + i).collect()
    }
}

// =========================================================================
// Unit Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let token: u64 = 0x0123_4567_89AB_CDEF;
        let bytes = token_to_bytes(token);
        let recovered = token_from_bytes(&bytes);
        assert_eq!(token, recovered);
    }

    #[test]
    fn test_token_zero_roundtrip() {
        let bytes = token_to_bytes(0);
        assert_eq!(token_from_bytes(&bytes), 0);
    }

    #[test]
    fn test_mesh_node_new() {
        let node = MeshNode::new();
        assert_eq!(node.primary.get(), UNASSIGNED_ADDRESS);
        assert_eq!(node.num_ele.get(), 0);
        assert_eq!(node.seq_number.get(), 0);
        assert_eq!(node.ttl.get(), DEFAULT_TTL);
        assert!(!node.provisioner.get());
        assert!(!node.busy.get());
        assert_eq!(node.token.get(), 0);
    }

    #[test]
    fn test_node_find_by_token_zero() {
        assert!(node_find_by_token(0).is_none());
    }

    #[test]
    fn test_node_find_by_addr_unassigned() {
        assert!(node_find_by_addr(UNASSIGNED_ADDRESS).is_none());
    }

    #[test]
    fn test_default_ttl_set_valid() {
        let node = MeshNode::new();
        assert!(node.default_ttl_set(0x7F));
        assert_eq!(node.ttl.get(), 0x7F);
    }

    #[test]
    fn test_default_ttl_set_invalid() {
        let node = MeshNode::new();
        node.ttl.set(5);
        assert!(!node.default_ttl_set(0x80));
        assert_eq!(node.ttl.get(), 5);
    }

    #[test]
    fn test_default_ttl_set_max() {
        let node = MeshNode::new();
        assert!(node.default_ttl_set(0xFF));
        assert_eq!(node.ttl.get(), 0xFF);
    }

    #[test]
    fn test_get_element_idx_empty() {
        let node = MeshNode::new();
        node.primary.set(0x0100);
        node.num_ele.set(0);
        assert!(node.get_element_idx(0x0100).is_none());
    }

    #[test]
    fn test_get_element_idx_valid() {
        let node = MeshNode::new();
        node.primary.set(0x0100);
        node.num_ele.set(3);
        assert_eq!(node.get_element_idx(0x0100), Some(0));
        assert_eq!(node.get_element_idx(0x0101), Some(1));
        assert_eq!(node.get_element_idx(0x0102), Some(2));
        assert_eq!(node.get_element_idx(0x0103), None);
        assert_eq!(node.get_element_idx(0x00FF), None);
    }

    #[test]
    fn test_node_composition_default() {
        let comp = NodeComposition::default();
        assert_eq!(comp.cid, 0);
        assert_eq!(comp.pid, 0);
        assert_eq!(comp.vid, 0);
        assert_eq!(comp.crpl, 0);
    }

    #[test]
    fn test_request_type_equality() {
        assert_eq!(RequestType::Join, RequestType::Join);
        assert_ne!(RequestType::Join, RequestType::Attach);
        assert_ne!(RequestType::Create, RequestType::Import);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MESH_NODE_PATH_PREFIX, "/node");
        assert_eq!(DEFAULT_NEW_UNICAST, 0x0001);
        assert_eq!(DEFAULT_IV_INDEX, 0x0000);
        assert_eq!(DEFAULT_LOCATION, 0x0000);
    }
}
