// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2018-2019 Intel Corporation. All rights reserved.
//
// Rust rewrite of mesh/mesh-config.h — defines the MeshConfig trait and all
// persisted data model structs used by the mesh configuration persistence layer.

//! Mesh configuration persistence layer.
//!
//! This module defines the [`MeshConfig`] trait (replacing the C function-pointer
//! API from `mesh-config.h`) and all data model structs that represent the
//! persisted state of a Bluetooth Mesh node. The [`json`] sub-module provides
//! the concrete JSON-backed implementation.
//!
//! # Data Model
//!
//! The configuration hierarchy is:
//! - [`MeshConfigNode`] — complete node state (elements, keys, modes, addresses)
//!   - [`MeshConfigElement`] — one element within the node
//!     - [`MeshConfigModel`] — one model within an element
//!       - [`MeshConfigPub`] — publication configuration
//!       - [`MeshConfigSub`] — subscription address entry
//!   - [`MeshConfigNetKey`] — network key with refresh phase
//!   - [`MeshConfigAppKey`] — application key bound to a network key
//!   - [`MeshConfigCompPage`] — composition data page
//!   - [`MeshConfigModes`] — feature mode settings (relay, proxy, friend, etc.)
//!   - [`MeshConfigTransmit`] — retransmit parameters
//!
//! # Key Refresh Phases
//!
//! Network key refresh proceeds through three phases:
//! - [`KEY_REFRESH_PHASE_NONE`] (0) — no refresh in progress
//! - [`KEY_REFRESH_PHASE_ONE`] (1) — distributing new keys
//! - [`KEY_REFRESH_PHASE_TWO`] (2) — switching to new keys

pub mod json;

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Minimum composition data size in bytes.
/// Corresponds to C `#define MIN_COMP_SIZE 14` in `mesh/mesh-config.h`.
pub const MIN_COMP_SIZE: usize = 14;

/// Key refresh phase: no refresh in progress.
pub const KEY_REFRESH_PHASE_NONE: u8 = 0;

/// Key refresh phase: distributing new keys to all nodes.
pub const KEY_REFRESH_PHASE_ONE: u8 = 1;

/// Key refresh phase: switching to new keys, revoking old.
pub const KEY_REFRESH_PHASE_TWO: u8 = 2;

// ============================================================================
// Error Type
// ============================================================================

/// Errors that can occur during mesh configuration persistence operations.
///
/// Maps all failure modes from the C mesh-config API (which returned `bool`
/// success/failure) into typed, descriptive error variants.
#[derive(Debug, thiserror::Error)]
pub enum MeshConfigError {
    /// Filesystem I/O error during config read or write.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing or serialization error (from `serde_json`).
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration data is structurally invalid.
    #[error("Invalid configuration: {0}")]
    Invalid(String),

    /// Requested key index was not found in the key list.
    #[error("Key not found: index {0}")]
    KeyNotFound(u16),

    /// Requested element address does not exist in the node.
    #[error("Element not found at address {0}")]
    ElementNotFound(u16),

    /// Requested model ID was not found within the element.
    #[error("Model not found: id {0}")]
    ModelNotFound(u32),

    /// Node creation failed (directory or file operations).
    #[error("Node creation failed")]
    CreationFailed,
}

// ============================================================================
// Callback Types
// ============================================================================

/// Status callback invoked after an asynchronous save operation completes.
///
/// The `bool` parameter indicates success (`true`) or failure (`false`).
/// Replaces C `typedef void (*mesh_config_status_func_t)(void *user_data, bool result)`.
/// The `user_data` pointer is captured within the closure per AAP directive
/// to replace `callback + void *user_data` with idiomatic Rust closures.
pub type MeshConfigStatusFn = Box<dyn FnOnce(bool) + Send>;

/// Node callback invoked for each loaded node during [`MeshConfig::load_nodes`].
///
/// Receives:
/// - `&MeshConfigNode` — the parsed node configuration data
/// - `&[u8; 16]` — the 16-byte UUID of the node
/// - `&dyn MeshConfig` — the configuration handle for this node
///
/// Returns `true` to continue loading additional nodes, `false` to stop.
/// Replaces C `typedef bool (*mesh_config_node_func_t)(struct mesh_config_node *,
/// const uint8_t uuid[16], struct mesh_config *, void *user_data)`.
pub type MeshConfigNodeFn =
    Box<dyn FnMut(&MeshConfigNode, &[u8; 16], &dyn MeshConfig) -> bool + Send>;

// ============================================================================
// Data Model Structs
// ============================================================================

/// Subscription address entry for a mesh model.
///
/// Replaces C `struct mesh_config_sub` which uses a C union for `grp`/`label`.
/// In Rust, both fields are always present; the [`virt`](MeshConfigSub::virt)
/// flag determines which field carries the active address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigSub {
    /// Whether this is a virtual address subscription.
    /// When `true`, [`virt_addr`](MeshConfigSub::virt_addr) holds the 16-byte label UUID.
    /// When `false`, [`addr`](MeshConfigSub::addr) holds the group address.
    pub virt: bool,

    /// Group address (meaningful when `virt == false`).
    pub addr: u16,

    /// Virtual label UUID (meaningful when `virt == true`), 16 bytes.
    pub virt_addr: [u8; 16],
}

/// Publication configuration for a mesh model.
///
/// Replaces C `struct mesh_config_pub`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigPub {
    /// Whether publication uses a virtual destination address.
    pub virt: bool,

    /// Publication destination address (group or fixed address).
    pub addr: u16,

    /// AppKey index used for publishing.
    pub idx: u16,

    /// Time-To-Live for published messages.
    pub ttl: u16,

    /// Publication period (encoded per Bluetooth Mesh specification).
    /// Uses `u32` to match C `uint32_t` and accommodate large period values.
    pub period: u32,

    /// Retransmit interval in milliseconds.
    pub retransmit_interval: u16,

    /// Number of publication retransmissions.
    pub retransmit_count: u16,

    /// Friendship security credentials flag.
    /// `true` = use friendship credentials, `false` = use normal credentials.
    pub credential: bool,

    /// Virtual label UUID (meaningful when `virt == true`), 16 bytes.
    pub virt_addr: [u8; 16],
}

/// Model configuration within an element.
///
/// Replaces C `struct mesh_config_model`. The C struct uses raw arrays with
/// explicit count fields (`num_bindings`, `num_subs`); in Rust these are
/// implicit via `Vec::len()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigModel {
    /// Subscription address list.
    pub subs: Vec<MeshConfigSub>,

    /// Publication settings (`None` if no publication is configured).
    pub pub_state: Option<MeshConfigPub>,

    /// Bound AppKey indices.
    pub bindings: Vec<u16>,

    /// Model ID: SIG 16-bit (stored in lower 16 bits) or vendor 32-bit
    /// (company_id in upper 16 bits, model_id in lower 16 bits).
    pub id: u32,

    /// Whether this is a vendor model (`true`) or SIG model (`false`).
    pub vendor: bool,

    /// Whether subscriptions are enabled for this model.
    pub sub_enabled: bool,

    /// Whether publication is enabled for this model.
    pub pub_enabled: bool,
}

/// Element within a mesh node.
///
/// Replaces C `struct mesh_config_element`. The C struct uses
/// `struct l_queue *models`; in Rust this becomes `Vec<MeshConfigModel>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigElement {
    /// Models within this element.
    pub models: Vec<MeshConfigModel>,

    /// GATT location descriptor.
    pub location: u16,

    /// Element index (0-based, relative to the node's primary unicast address).
    pub index: u8,
}

/// Node feature mode settings.
///
/// Replaces C `struct mesh_config_modes`. The C struct uses a nested anonymous
/// struct for relay parameters; in Rust these are flattened to individual fields.
///
/// Mode values: `0` = disabled, `1` = enabled, `2` = unsupported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MeshConfigModes {
    /// Relay retransmit interval in milliseconds.
    pub relay_interval: u16,

    /// Relay retransmit count.
    pub relay_cnt: u16,

    /// Relay mode state (0=disabled, 1=enabled, 2=unsupported).
    pub relay: u8,

    /// Low Power Node mode.
    pub lpn: u8,

    /// Friend mode.
    pub friend: u8,

    /// Proxy mode.
    pub proxy: u8,

    /// Beacon mode.
    pub beacon: u8,

    /// Mesh Private Beacon (MPB) mode.
    pub mpb: u8,

    /// MPB period.
    pub mpb_period: u8,
}

/// Network key configuration.
///
/// Replaces C `struct mesh_config_netkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigNetKey {
    /// Network key index (0–4095).
    pub idx: u16,

    /// Key refresh phase: [`KEY_REFRESH_PHASE_NONE`] (0),
    /// [`KEY_REFRESH_PHASE_ONE`] (1), or [`KEY_REFRESH_PHASE_TWO`] (2).
    pub phase: u8,

    /// Current network key (16 bytes).
    pub key: [u8; 16],

    /// New network key during key refresh (16 bytes).
    /// All zeros when not in a key refresh phase.
    pub new_key: [u8; 16],
}

/// Application key configuration.
///
/// Replaces C `struct mesh_config_appkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigAppKey {
    /// Bound network key index.
    pub net_idx: u16,

    /// Application key index (0–4095).
    pub app_idx: u16,

    /// Current application key (16 bytes).
    pub key: [u8; 16],

    /// New application key during key refresh (16 bytes).
    /// All zeros when not in a key refresh phase.
    pub new_key: [u8; 16],
}

/// Transmit parameters for network or publication retransmissions.
///
/// Replaces C `struct mesh_config_transmit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigTransmit {
    /// Retransmit interval in milliseconds.
    pub interval: u16,

    /// Number of retransmissions.
    pub count: u16,
}

/// Composition data page.
///
/// Replaces C `struct mesh_config_comp_page`. The C struct uses a flexible
/// array member (`uint8_t data[]`) with a separate `uint16_t len` field;
/// in Rust, `Vec<u8>` carries its own length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigCompPage {
    /// Composition page number.
    pub page_num: u8,

    /// Raw composition data bytes.
    pub data: Vec<u8>,
}

/// Complete in-memory representation of a mesh node's configuration.
///
/// Replaces C `struct mesh_config_node`. All ELL queue pointers
/// (`l_queue *elements`, etc.) become `Vec<T>` in Rust. The optional
/// `net_transmit` pointer becomes `Option<MeshConfigTransmit>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfigNode {
    /// Node elements (ordered by element index).
    pub elements: Vec<MeshConfigElement>,

    /// Network keys provisioned on this node.
    pub netkeys: Vec<MeshConfigNetKey>,

    /// Application keys provisioned on this node.
    pub appkeys: Vec<MeshConfigAppKey>,

    /// Composition data pages.
    pub comp_pages: Vec<MeshConfigCompPage>,

    /// Current sequence number for outgoing messages.
    pub seq_number: u32,

    /// Current IV Index.
    pub iv_index: u32,

    /// Whether an IV Update procedure is in progress.
    pub iv_update: bool,

    /// Company ID from composition data.
    pub cid: u16,

    /// Product ID from composition data.
    pub pid: u16,

    /// Version ID from composition data.
    pub vid: u16,

    /// Replay Protection List size from composition data.
    pub crpl: u16,

    /// Primary unicast address.
    pub unicast: u16,

    /// Network transmit parameters (optional — `None` if not configured).
    pub net_transmit: Option<MeshConfigTransmit>,

    /// Feature mode settings (relay, proxy, friend, beacon, MPB, LPN).
    pub modes: MeshConfigModes,

    /// Default TTL for outgoing messages.
    pub ttl: u8,

    /// Device key (16 bytes).
    pub dev_key: [u8; 16],

    /// Security token (8 bytes) used for node identification.
    pub token: [u8; 8],

    /// Node UUID (16 bytes). Populated after loading from the directory name;
    /// not stored within the node JSON file itself.
    #[serde(skip)]
    pub uuid: [u8; 16],
}

// ============================================================================
// MeshConfig Trait
// ============================================================================

/// Mesh node configuration persistence interface.
///
/// This trait replaces the collection of C API functions declared in
/// `mesh/mesh-config.h`. The [`json`] sub-module provides the concrete
/// [`json::MeshConfigJson`] implementation backed by JSON files.
///
/// All mutating methods return `Result<bool, MeshConfigError>` where the
/// inner `bool` indicates whether the operation produced a meaningful state
/// change (matching the C API's `bool` return convention).
pub trait MeshConfig: Send + Sync {
    // === Lifecycle ===

    /// Load all mesh nodes from the given storage directory.
    ///
    /// Scans `cfgdir` for subdirectories whose names are 32-character hex
    /// strings (16-byte UUIDs). For each valid subdirectory, loads and parses
    /// `node.json`, then invokes `cb` with the parsed node data, UUID, and
    /// a reference to the configuration handle.
    ///
    /// Returns `Ok(true)` if at least one node was loaded successfully.
    fn load_nodes(&self, cfgdir: &str, cb: MeshConfigNodeFn) -> Result<bool, MeshConfigError>;

    /// Release this configuration handle, freeing associated resources.
    ///
    /// After calling this method, the handle should not be used again.
    fn release(&mut self);

    /// Destroy the persistent storage (NVM) directory for this node.
    ///
    /// Deletes the node's configuration directory from the filesystem.
    fn destroy_nvm(&self);

    /// Save the current configuration state to persistent storage.
    ///
    /// When `no_wait` is `true`, the save is performed immediately (synchronous).
    /// When `no_wait` is `false`, the save may be deferred for efficiency.
    ///
    /// The optional `cb` callback is invoked with the save result once complete.
    fn save(&self, no_wait: bool, cb: Option<MeshConfigStatusFn>) -> Result<bool, MeshConfigError>;

    /// Reset the element array from the given node data.
    ///
    /// Rebuilds the elements section in the persisted configuration from
    /// the provided [`MeshConfigNode`] data, replacing any existing elements.
    fn reset(&mut self, node: &MeshConfigNode);

    /// Create a new node configuration in the given storage directory.
    ///
    /// Creates a directory named after the hex-encoded `uuid`, builds the
    /// initial JSON representation from `node`, and saves it to disk.
    fn create(
        cfgdir: &str,
        uuid: &[u8; 16],
        node: &MeshConfigNode,
    ) -> Result<Self, MeshConfigError>
    where
        Self: Sized;

    // === Network Transmit ===

    /// Write network transmit parameters (count and interval).
    fn write_net_transmit(&mut self, count: u16, interval: u16) -> Result<bool, MeshConfigError>;

    // === Device Key ===

    /// Write the device key (16 bytes) to persistent storage.
    fn write_device_key(&mut self, key: &[u8; 16]) -> Result<bool, MeshConfigError>;

    /// Write a candidate device key for key rotation.
    fn write_candidate(&mut self, key: &[u8; 16]) -> Result<bool, MeshConfigError>;

    /// Read the current candidate device key, if one exists.
    fn read_candidate(&self) -> Option<[u8; 16]>;

    /// Finalize the candidate device key, promoting it to the active device key.
    ///
    /// Reads the candidate key, removes both the candidate and current device key,
    /// then writes the candidate as the new device key.
    fn finalize_candidate(&mut self) -> Result<bool, MeshConfigError>;

    // === Token ===

    /// Write the security token (8 bytes) to persistent storage.
    fn write_token(&mut self, token: &[u8; 8]) -> Result<bool, MeshConfigError>;

    // === Sequence Number ===

    /// Write the sequence number to persistent storage.
    ///
    /// When `cache` is `true`, the write uses a caching strategy that batches
    /// updates to reduce disk I/O (writes a value ahead of the actual sequence
    /// number). When `cache` is `false`, the exact value is written immediately.
    fn write_seq_number(&mut self, seq: u32, cache: bool) -> Result<bool, MeshConfigError>;

    // === Unicast Address ===

    /// Write the primary unicast address.
    fn write_unicast(&mut self, unicast: u16) -> Result<bool, MeshConfigError>;

    // === Relay Mode ===

    /// Write relay mode state and retransmit parameters.
    ///
    /// `mode`: 0=disabled, 1=enabled, 2=unsupported.
    fn write_relay_mode(
        &mut self,
        mode: u8,
        count: u16,
        interval: u16,
    ) -> Result<bool, MeshConfigError>;

    // === Mesh Private Beacon (MPB) ===

    /// Write MPB mode and period.
    ///
    /// `mode`: 0=disabled, 1=enabled, 2=unsupported.
    fn write_mpb(&mut self, mode: u8, period: u8) -> Result<bool, MeshConfigError>;

    // === TTL ===

    /// Write the default TTL value.
    fn write_ttl(&mut self, ttl: u8) -> Result<bool, MeshConfigError>;

    // === Generic Mode Write ===

    /// Write a named mode value (e.g., "proxy", "friend", "beacon").
    ///
    /// `keyword` identifies which mode to update.
    /// `value`: 0=disabled, 1=enabled, 2=unsupported.
    fn write_mode(&mut self, keyword: &str, value: u8) -> Result<bool, MeshConfigError>;

    /// Write a named mode value with optional save control.
    ///
    /// Same as [`write_mode`](MeshConfig::write_mode), but when `save` is
    /// `false`, the change is applied in-memory without persisting to disk.
    fn write_mode_ex(
        &mut self,
        keyword: &str,
        value: u8,
        save: bool,
    ) -> Result<bool, MeshConfigError>;

    // === Composition Pages ===

    /// Add or replace a composition data page.
    ///
    /// `page` is the page number; `data` is the raw composition data bytes.
    /// If a page with the same number already exists, it is replaced.
    fn comp_page_add(&mut self, page: u8, data: &[u8]) -> Result<bool, MeshConfigError>;

    /// Delete a composition data page by page number.
    fn comp_page_del(&mut self, page: u8);

    // === Model Bindings ===

    /// Add an AppKey binding to a model.
    fn model_binding_add(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        app_idx: u16,
    ) -> Result<bool, MeshConfigError>;

    /// Remove an AppKey binding from a model.
    fn model_binding_del(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        app_idx: u16,
    ) -> Result<bool, MeshConfigError>;

    // === Model Publication ===

    /// Set the publication configuration for a model.
    fn model_pub_add(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        pub_config: &MeshConfigPub,
    ) -> Result<bool, MeshConfigError>;

    /// Remove the publication configuration from a model.
    fn model_pub_del(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
    ) -> Result<bool, MeshConfigError>;

    /// Enable or disable publication for a model.
    fn model_pub_enable(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        enable: bool,
    ) -> Result<bool, MeshConfigError>;

    // === Model Subscriptions ===

    /// Add a subscription address to a model.
    fn model_sub_add(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        sub: &MeshConfigSub,
    ) -> Result<bool, MeshConfigError>;

    /// Remove a subscription address from a model.
    fn model_sub_del(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        sub: &MeshConfigSub,
    ) -> Result<bool, MeshConfigError>;

    /// Remove all subscriptions from a model.
    fn model_sub_del_all(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
    ) -> Result<bool, MeshConfigError>;

    /// Enable or disable subscriptions for a model.
    fn model_sub_enable(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        enable: bool,
    ) -> Result<bool, MeshConfigError>;

    // === Application Keys ===

    /// Add a new application key.
    fn app_key_add(
        &mut self,
        net_idx: u16,
        app_idx: u16,
        key: &[u8; 16],
    ) -> Result<bool, MeshConfigError>;

    /// Update an existing application key (for key refresh).
    ///
    /// The current key is preserved as the old key, and the new key is written.
    fn app_key_update(
        &mut self,
        net_idx: u16,
        app_idx: u16,
        key: &[u8; 16],
    ) -> Result<bool, MeshConfigError>;

    /// Delete an application key.
    fn app_key_del(&mut self, net_idx: u16, app_idx: u16) -> Result<bool, MeshConfigError>;

    // === Network Keys ===

    /// Add a new network key.
    fn net_key_add(&mut self, idx: u16, key: &[u8; 16]) -> Result<bool, MeshConfigError>;

    /// Update an existing network key (initiates key refresh phase 1).
    ///
    /// The current key is preserved as the old key, and the new key is written.
    fn net_key_update(&mut self, idx: u16, key: &[u8; 16]) -> Result<bool, MeshConfigError>;

    /// Delete a network key.
    fn net_key_del(&mut self, idx: u16) -> Result<bool, MeshConfigError>;

    /// Set the key refresh phase for a network key.
    ///
    /// `phase`: [`KEY_REFRESH_PHASE_NONE`] (0), [`KEY_REFRESH_PHASE_ONE`] (1),
    /// or [`KEY_REFRESH_PHASE_TWO`] (2).
    ///
    /// When transitioning to phase NONE, bound application keys have their
    /// old keys cleaned up automatically.
    fn net_key_set_phase(&mut self, idx: u16, phase: u8) -> Result<bool, MeshConfigError>;

    // === IV Index ===

    /// Write the IV Index and IV Update flag.
    fn write_iv_index(&mut self, iv_index: u32, iv_update: bool) -> Result<bool, MeshConfigError>;

    // === Composition Data IDs ===

    /// Update the Company ID in composition data.
    fn update_company_id(&mut self, cid: u16) -> Result<bool, MeshConfigError>;

    /// Update the Product ID in composition data.
    fn update_product_id(&mut self, pid: u16) -> Result<bool, MeshConfigError>;

    /// Update the Version ID in composition data.
    fn update_version_id(&mut self, vid: u16) -> Result<bool, MeshConfigError>;

    /// Update the Replay Protection List (CRPL) size in composition data.
    fn update_crpl(&mut self, crpl: u16) -> Result<bool, MeshConfigError>;
}
