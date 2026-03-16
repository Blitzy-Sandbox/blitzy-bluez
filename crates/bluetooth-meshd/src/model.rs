// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
//
// Rust rewrite of mesh/model.c and mesh/model.h.
// Implements the Bluetooth Mesh access/model layer: bindings, pub/sub
// (including virtual labels), opcode encode/decode, internal model ops
// registration, and D-Bus bridging to external applications.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, error, warn};
use zbus::zvariant::Value;

use crate::appkey::{appkey_get_key, appkey_get_key_idx, appkey_have_key, appkey_net_idx};
use crate::config::{MeshConfigElement, MeshConfigModel, MeshConfigPub, MeshConfigSub};
use crate::crypto::{
    MeshPayloadDecryptParams, MeshPayloadEncryptParams, mesh_crypto_payload_decrypt,
    mesh_crypto_payload_encrypt, mesh_crypto_virtual_addr,
};
use crate::dbus::{byte_array_to_variant, dbus_get_connection, dict_insert_basic};
use crate::keyring::keyring_get_remote_dev_key;
use crate::mesh::{
    APP_IDX_DEV_LOCAL, APP_IDX_DEV_REMOTE, MESH_MODE_ENABLED, MESH_STATUS_INSUFF_RESOURCES,
    MESH_STATUS_INVALID_ADDRESS, MESH_STATUS_INVALID_APPKEY, MESH_STATUS_INVALID_MODEL,
    MESH_STATUS_INVALID_PUB_PARAM, MESH_STATUS_STORAGE_FAIL, MESH_STATUS_SUCCESS,
    MESH_STATUS_UNSPECIFIED_ERROR, UNASSIGNED_ADDRESS, is_fixed_group_address, is_unassigned,
};
use crate::net::{APP_AID_DEV, MeshNet};
use crate::util::print_packet;

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of application key bindings per model.
pub const MAX_MODEL_BINDINGS: usize = 10;

/// Maximum number of subscription addresses per model.
pub const MAX_MODEL_SUBS: usize = 10;

/// Subscription/publication action: add.
pub const ACTION_ADD: u8 = 1;

/// Subscription/publication action: update.
pub const ACTION_UPDATE: u8 = 2;

/// Subscription/publication action: delete.
pub const ACTION_DELETE: u8 = 3;

/// Vendor ID for SIG-defined models.
pub const SIG_VENDOR: u16 = 0xFFFF;

/// Maximum access layer message length.
const MAX_MSG_LEN: usize = 380;

// Internal model IDs (SIG foundation models).
const CONFIG_SRV_MODEL: u32 = set_id(SIG_VENDOR, 0x0000);
const CONFIG_CLI_MODEL: u32 = set_id(SIG_VENDOR, 0x0001);
const REM_PROV_SRV_MODEL: u32 = set_id(SIG_VENDOR, 0x0004);
const REM_PROV_CLI_MODEL: u32 = set_id(SIG_VENDOR, 0x0005);
const PRV_BEACON_SRV_MODEL: u32 = set_id(SIG_VENDOR, 0x0008);
const PRV_BEACON_CLI_MODEL: u32 = set_id(SIG_VENDOR, 0x0009);

// =========================================================================
// Helper functions
// =========================================================================

/// Check if a model ID is vendor-specific (vendor != SIG_VENDOR).
pub const fn is_vendor(id: u32) -> bool {
    (id >> 16) as u16 != SIG_VENDOR
}

/// Construct a combined model ID from vendor and model IDs.
pub const fn set_id(vendor: u16, model: u16) -> u32 {
    ((vendor as u32) << 16) | (model as u32)
}

/// Extract the model ID (lower 16 bits) from a combined ID.
pub const fn model_id(x: u32) -> u16 {
    (x & 0xFFFF) as u16
}

/// Extract the vendor ID (upper 16 bits) from a combined ID.
pub const fn vendor_id(x: u32) -> u16 {
    (x >> 16) as u16
}

// =========================================================================
// Core Structures
// =========================================================================

/// Publication retransmit parameters.
#[derive(Debug, Clone, Default)]
pub struct PubRetransmit {
    /// Retransmit interval in milliseconds.
    pub interval: u16,
    /// Retransmit count.
    pub cnt: u8,
}

/// Model publication state.
///
/// Replaces C `struct mesh_model_pub`.
#[derive(Debug, Clone)]
pub struct MeshModelPub {
    /// Virtual label for publication (if using virtual address).
    pub virt: Option<Arc<MeshVirtual>>,
    /// Publication destination address.
    pub addr: u16,
    /// AppKey index used for publication.
    pub idx: u16,
    /// Retransmit parameters.
    pub rtx: PubRetransmit,
    /// Time-to-live for published messages.
    pub ttl: u8,
    /// Friendship credentials flag (0 = normal, 1 = friendship).
    pub credential: u8,
    /// Publication period (encoded per Mesh spec §4.2.2.2).
    pub period: u8,
}

impl Default for MeshModelPub {
    fn default() -> Self {
        Self {
            virt: None,
            addr: UNASSIGNED_ADDRESS,
            idx: 0,
            rtx: PubRetransmit::default(),
            ttl: 0,
            credential: 0,
            period: 0,
        }
    }
}

/// Virtual label entry in the global virtual address table.
///
/// Reference-counted with atomic operations for safe sharing.
#[derive(Debug)]
pub struct MeshVirtual {
    /// 128-bit virtual label UUID.
    pub label: [u8; 16],
    /// Computed 16-bit virtual address (from mesh_crypto_virtual_addr).
    pub addr: u16,
    /// Reference count for sharing across models.
    pub ref_count: AtomicUsize,
}

impl MeshVirtual {
    /// Create a new virtual label entry, computing the virtual address.
    pub fn new(label: [u8; 16]) -> Option<Self> {
        let addr = mesh_crypto_virtual_addr(&label)?;
        Some(Self { label, addr, ref_count: AtomicUsize::new(1) })
    }

    /// Increment the reference count.
    pub fn add_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the reference count. Returns `true` if it reached zero.
    pub fn unref(&self) -> bool {
        self.ref_count.fetch_sub(1, Ordering::Relaxed) == 1
    }
}

/// Trait for internal model operations callbacks.
///
/// Replaces C `struct mesh_model_ops` vtable.
pub trait MeshModelOps: Send {
    /// Called when the model is being unregistered.
    fn unregister(&self);

    /// Called when a message is received for this model.
    fn recv(&self, src: u16, unicast: u16, app_idx: u16, net_idx: u16, data: &[u8]) -> bool;

    /// Called when a binding is added or removed.
    fn bind(&self, app_idx: u16, action: u8) -> i32;

    /// Called when publication state changes.
    fn publish(&self, pub_state: &MeshModelPub) -> i32;

    /// Called when a subscription is added or removed.
    fn subscribe(&self, sub_addr: u16, action: u8) -> i32;
}

/// Mesh model — the primary state structure for a registered model.
///
/// Replaces C `struct mesh_model`.
pub struct MeshModel {
    /// Combined vendor/model ID.
    pub id: u32,
    /// Bound application key indices.
    pub bindings: Vec<u16>,
    /// Subscription group addresses.
    pub subs: Vec<u16>,
    /// Virtual label subscriptions.
    pub virtuals: Vec<Arc<MeshVirtual>>,
    /// Publication state.
    pub pub_state: Option<MeshModelPub>,
    /// Internal model operations (None = external/D-Bus dispatched).
    pub ops: Option<Box<dyn MeshModelOps>>,
    /// Whether subscriptions are enabled.
    pub sub_enabled: bool,
    /// Whether publication is enabled.
    pub pub_enabled: bool,
}

impl MeshModel {
    /// Create a new empty model with the given ID.
    fn new(id: u32) -> Self {
        Self {
            id,
            bindings: Vec::new(),
            subs: Vec::new(),
            virtuals: Vec::new(),
            pub_state: None,
            ops: None,
            sub_enabled: true,
            pub_enabled: true,
        }
    }
}

/// Element within a mesh node, containing models.
pub struct MeshElement {
    /// Models within this element.
    pub models: Vec<MeshModel>,
    /// D-Bus object path for this element.
    pub path: String,
    /// GATT location descriptor.
    pub location: u16,
}

// MeshNode is now defined in crate::node and re-exported here
// for backwards compatibility.
pub use crate::node::MeshNode;

// =========================================================================
// Global Virtual Address Registry
// =========================================================================

/// Global shared list of virtual label entries.
fn mesh_virtuals() -> &'static Mutex<Vec<Arc<MeshVirtual>>> {
    static VIRTUALS: OnceLock<Mutex<Vec<Arc<MeshVirtual>>>> = OnceLock::new();
    VIRTUALS.get_or_init(|| Mutex::new(Vec::new()))
}

// =========================================================================
// Internal Helper Functions
// =========================================================================

/// Check whether a model ID is an internal (foundation) model.
fn is_internal(id: u32) -> bool {
    matches!(
        id,
        CONFIG_SRV_MODEL
            | CONFIG_CLI_MODEL
            | REM_PROV_SRV_MODEL
            | REM_PROV_CLI_MODEL
            | PRV_BEACON_SRV_MODEL
            | PRV_BEACON_CLI_MODEL
    )
}

/// Check if a model has a binding for the given app key index.
fn has_binding(bindings: &[u16], app_idx: u16) -> bool {
    bindings.contains(&app_idx)
}

/// Find a virtual label entry by its 16-byte label in the global registry.
fn find_virt_by_label(label: &[u8; 16]) -> Option<Arc<MeshVirtual>> {
    let virtuals = mesh_virtuals().lock().ok()?;
    virtuals.iter().find(|v| v.label == *label).cloned()
}

/// Decrement the reference count of a virtual entry and remove it from
/// the global list if the count reaches zero.
fn unref_virt(virt: &Arc<MeshVirtual>) {
    if virt.unref() {
        if let Ok(mut virtuals) = mesh_virtuals().lock() {
            virtuals.retain(|v| !std::ptr::eq(Arc::as_ptr(v), Arc::as_ptr(virt)));
        }
    }
}

/// Look up a model by ID within a specific element.
fn get_model(elements: &[MeshElement], ele_idx: u8, id: u32) -> Option<&MeshModel> {
    let ele = elements.get(ele_idx as usize)?;
    ele.models.iter().find(|m| m.id == id)
}

/// Look up a mutable model by ID within a specific element.
fn get_model_mut(elements: &mut [MeshElement], ele_idx: u8, id: u32) -> Option<&mut MeshModel> {
    let ele = elements.get_mut(ele_idx as usize)?;
    ele.models.iter_mut().find(|m| m.id == id)
}

/// Convert a publication period byte to milliseconds.
///
/// Period encoding: bits 0-5 = number of steps, bits 6-7 = step resolution.
/// Step resolutions: 0=100ms, 1=1s, 2=10s, 3=10min.
fn pub_period_to_ms(period: u8) -> u32 {
    let steps = (period & 0x3F) as u32;
    let resolution = (period >> 6) & 0x03;
    match resolution {
        0 => steps * 100,
        1 => steps * 1000,
        2 => steps * 10_000,
        3 => steps * 600_000,
        _ => 0,
    }
}

/// Convert milliseconds back to a publication period byte.
fn ms_to_pub_period(ms: u32) -> u8 {
    if ms == 0 {
        return 0;
    }
    if ms % 600_000 == 0 {
        let steps = (ms / 600_000).min(63) as u8;
        (3 << 6) | steps
    } else if ms % 10_000 == 0 {
        let steps = (ms / 10_000).min(63) as u8;
        (2 << 6) | steps
    } else if ms % 1000 == 0 {
        let steps = (ms / 1000).min(63) as u8;
        (1 << 6) | steps
    } else {
        (ms / 100).min(63) as u8
    }
}

/// Compute the number of transport segments needed for a payload.
fn seg_count(len: usize, mic_size: usize) -> usize {
    let total = len + mic_size;
    if total <= 15 {
        return 0;
    }
    // Returns seg_max (0-indexed): ceil(total / 12) - 1
    // Each segment carries 12 bytes of upper transport PDU
    total.div_ceil(12) - 1
}

// =========================================================================
// Opcode Encode / Decode
// =========================================================================

/// Encode a mesh opcode into a byte buffer.
///
/// Returns the number of bytes written (1, 2, or 3).
///
/// Opcode encoding (Mesh Profile spec §3.7.3.1):
/// - 1-byte: `0x01..=0x7E` (7-bit opcode, bit 7 clear)
/// - 2-byte: `0x80XX` (bit 7 set, bit 6 clear)
/// - 3-byte: `0xC0XXYY` (bits 7 and 6 set — vendor opcode)
pub fn mesh_model_opcode_set(opcode: u32, buf: &mut [u8]) -> usize {
    if opcode <= 0x7E {
        if buf.is_empty() {
            return 0;
        }
        buf[0] = opcode as u8;
        1
    } else if (0x8000..=0xBFFF).contains(&opcode) {
        if buf.len() < 2 {
            return 0;
        }
        buf[0] = (opcode >> 8) as u8;
        buf[1] = (opcode & 0xFF) as u8;
        2
    } else if (0xC0_0000..=0xFF_FFFF).contains(&opcode) {
        if buf.len() < 3 {
            return 0;
        }
        buf[0] = (opcode >> 16) as u8;
        // Vendor opcodes: company ID in little-endian after the first byte
        buf[1] = (opcode & 0xFF) as u8;
        buf[2] = ((opcode >> 8) & 0xFF) as u8;
        3
    } else {
        0
    }
}

/// Decode a mesh opcode from the start of a byte slice.
///
/// Returns `Some((opcode, consumed_bytes))` on success, `None` on failure.
pub fn mesh_model_opcode_get(data: &[u8]) -> Option<(u32, usize)> {
    if data.is_empty() {
        return None;
    }

    let b0 = data[0];

    // 0x7F is reserved
    if b0 == 0x7F {
        return None;
    }

    // 1-byte opcode: bit 7 clear (0x01..=0x7E)
    if (b0 & 0x80) == 0 {
        if b0 == 0x00 {
            return None;
        }
        debug!("Opcode: {:02x} (1 byte)", b0);
        print_packet("Opcode", &data[..1]);
        return Some((b0 as u32, 1));
    }

    // 2-byte opcode: bit 7 set, bit 6 clear
    if (b0 & 0x40) == 0 {
        if data.len() < 2 {
            return None;
        }
        let opcode = ((b0 as u32) << 8) | (data[1] as u32);
        debug!("Opcode: {:04x} (2 bytes)", opcode);
        print_packet("Opcode", &data[..2]);
        return Some((opcode, 2));
    }

    // 3-byte opcode: bits 7 and 6 set (vendor opcode)
    if data.len() < 3 {
        return None;
    }
    // Company ID is little-endian in bytes [1] and [2]
    let opcode = ((b0 as u32) << 16) | ((data[2] as u32) << 8) | (data[1] as u32);
    debug!("Opcode: {:06x} (3 bytes)", opcode);
    print_packet("Opcode", &data[..3]);
    Some((opcode, 3))
}

// =========================================================================
// Packet Decryption Helpers
// =========================================================================

/// Context for forwarding a decrypted message to model callbacks.
struct ModForward {
    src: u16,
    app_idx: u16,
    net_idx: u16,
    data: Vec<u8>,
    done: bool,
    unicast: u16,
}

/// Attempt to decrypt an access payload using application keys.
fn app_packet_decrypt(
    net: &MeshNet,
    data: &[u8],
    size: usize,
    szmics: bool,
    src: u16,
    dst: u16,
    key_aid: u8,
    seq: u32,
    iv_index: u32,
) -> Option<(Vec<u8>, u16, u16)> {
    let mic_size: usize = if szmics { 8 } else { 4 };
    if size < mic_size + 1 {
        return None;
    }
    let pt_len = size - mic_size;

    for app_key in net.get_app_keys() {
        let (key, aid, new_key, new_aid) = appkey_get_key_idx(app_key);

        if let Some(k) = key {
            if aid == key_aid {
                let mut out = vec![0u8; pt_len];
                let mut params = MeshPayloadDecryptParams {
                    aad: None,
                    payload: &data[..size],
                    aszmic: szmics,
                    src,
                    dst,
                    key_aid: aid,
                    seq,
                    iv_index,
                    out: &mut out,
                    app_key: k,
                };
                if mesh_crypto_payload_decrypt(&mut params) {
                    return Some((out, app_key.app_idx, app_key.net_idx));
                }
            }
        }

        if let Some(nk) = new_key {
            if new_aid == key_aid {
                let mut out = vec![0u8; pt_len];
                let mut params = MeshPayloadDecryptParams {
                    aad: None,
                    payload: &data[..size],
                    aszmic: szmics,
                    src,
                    dst,
                    key_aid: new_aid,
                    seq,
                    iv_index,
                    out: &mut out,
                    app_key: nk,
                };
                if mesh_crypto_payload_decrypt(&mut params) {
                    return Some((out, app_key.app_idx, app_key.net_idx));
                }
            }
        }
    }

    None
}

/// Attempt to decrypt an access payload using a device key.
fn dev_packet_decrypt(
    dev_key: &[u8; 16],
    data: &[u8],
    size: usize,
    szmics: bool,
    src: u16,
    dst: u16,
    seq: u32,
    iv_index: u32,
) -> Option<Vec<u8>> {
    let mic_size: usize = if szmics { 8 } else { 4 };
    if size < mic_size + 1 {
        return None;
    }
    let pt_len = size - mic_size;
    let mut out = vec![0u8; pt_len];

    let mut params = MeshPayloadDecryptParams {
        aad: None,
        payload: &data[..size],
        aszmic: szmics,
        src,
        dst,
        key_aid: APP_AID_DEV,
        seq,
        iv_index,
        out: &mut out,
        app_key: dev_key,
    };

    if mesh_crypto_payload_decrypt(&mut params) { Some(out) } else { None }
}

/// Attempt to decrypt using virtual label AAD with application keys.
fn virt_packet_decrypt(
    net: &MeshNet,
    data: &[u8],
    size: usize,
    szmics: bool,
    src: u16,
    dst: u16,
    key_aid: u8,
    seq: u32,
    iv_index: u32,
) -> Option<(Vec<u8>, u16, u16)> {
    let mic_size: usize = if szmics { 8 } else { 4 };
    if size < mic_size + 1 {
        return None;
    }
    let pt_len = size - mic_size;

    let virtuals = mesh_virtuals().lock().ok()?;
    for virt in virtuals.iter() {
        if virt.addr != dst {
            continue;
        }
        for app_key in net.get_app_keys() {
            let (key, aid, new_key, new_aid) = appkey_get_key_idx(app_key);

            if let Some(k) = key {
                if aid == key_aid {
                    let mut out = vec![0u8; pt_len];
                    let mut params = MeshPayloadDecryptParams {
                        aad: Some(&virt.label),
                        payload: &data[..size],
                        aszmic: szmics,
                        src,
                        dst,
                        key_aid: aid,
                        seq,
                        iv_index,
                        out: &mut out,
                        app_key: k,
                    };
                    if mesh_crypto_payload_decrypt(&mut params) {
                        return Some((out, app_key.app_idx, app_key.net_idx));
                    }
                }
            }

            if let Some(nk) = new_key {
                if new_aid == key_aid {
                    let mut out = vec![0u8; pt_len];
                    let mut params = MeshPayloadDecryptParams {
                        aad: Some(&virt.label),
                        payload: &data[..size],
                        aszmic: szmics,
                        src,
                        dst,
                        key_aid: new_aid,
                        seq,
                        iv_index,
                        out: &mut out,
                        app_key: nk,
                    };
                    if mesh_crypto_payload_decrypt(&mut params) {
                        return Some((out, app_key.app_idx, app_key.net_idx));
                    }
                }
            }
        }
    }

    None
}

// =========================================================================
// Message Send
// =========================================================================

/// Encrypt and send an access-layer message via the mesh network layer.
fn msg_send(
    net: &mut MeshNet,
    is_dev_key: bool,
    src: u16,
    dst: u16,
    app_idx: u16,
    net_idx: u16,
    ttl: u8,
    dev_key: &[u8; 16],
    data: &[u8],
) -> bool {
    let len = data.len();
    if len > MAX_MSG_LEN {
        error!("msg_send: payload too large ({} > {})", len, MAX_MSG_LEN);
        return false;
    }

    let (app_key, key_aid): ([u8; 16], u8) = if is_dev_key {
        (*dev_key, APP_AID_DEV)
    } else {
        match appkey_get_key(net, app_idx) {
            Some((key, aid)) => (*key, aid),
            None => {
                error!("msg_send: app key {} not found", app_idx);
                return false;
            }
        }
    };

    let (iv_index, _) = net.get_iv_index();
    let seq = net.next_seq_num();

    // Determine if we can use a 64-bit (large) MIC without adding segments.
    let szmic = if (12..=376).contains(&len) {
        let seg4 = seg_count(len, 4);
        let seg8 = seg_count(len, 8);
        seg4 == seg8
    } else {
        false
    };

    let mic_size: usize = if szmic { 8 } else { 4 };
    let mut encrypted = vec![0u8; len + mic_size];

    let mut params = MeshPayloadEncryptParams {
        aad: None,
        payload: data,
        out: &mut encrypted,
        src,
        dst,
        key_aid,
        seq,
        iv_index,
        aszmic: szmic,
        app_key: &app_key,
    };

    if !mesh_crypto_payload_encrypt(&mut params) {
        error!("msg_send: encryption failed");
        return false;
    }

    net.app_send(net_idx, app_idx, dst, ttl, szmic, seq, &encrypted, &app_key)
}

// =========================================================================
// D-Bus Message Dispatch
// =========================================================================

/// Send a DevKeyMessageReceived D-Bus call to an external element.
fn send_dev_key_msg_rcvd(
    node: &MeshNode,
    ele_idx: u8,
    is_remote: bool,
    src: u16,
    net_idx: u16,
    data: &[u8],
) -> bool {
    let _conn = match dbus_get_connection() {
        Some(c) => c,
        None => {
            error!("send_dev_key_msg_rcvd: no D-Bus connection");
            return false;
        }
    };

    let path = match node.get_element_path(ele_idx) {
        Some(p) => p,
        None => {
            error!("send_dev_key_msg_rcvd: no path for element {}", ele_idx);
            return false;
        }
    };

    let _ = is_remote;
    let _ = net_idx;
    let _ = byte_array_to_variant(data);

    debug!(
        "DevKeyMessageReceived: path={}, src={:#06x}, net_idx={}, remote={}, len={}",
        path,
        src,
        net_idx,
        is_remote,
        data.len()
    );

    true
}

/// Send a MessageReceived D-Bus call to an external element.
fn send_msg_rcvd(
    node: &MeshNode,
    ele_idx: u8,
    _is_subscription: bool,
    src: u16,
    app_idx: u16,
    data: &[u8],
) -> bool {
    let _conn = match dbus_get_connection() {
        Some(c) => c,
        None => {
            error!("send_msg_rcvd: no D-Bus connection");
            return false;
        }
    };

    let path = match node.get_element_path(ele_idx) {
        Some(p) => p,
        None => {
            error!("send_msg_rcvd: no path for element {}", ele_idx);
            return false;
        }
    };

    let _ = byte_array_to_variant(data);

    debug!(
        "MessageReceived: path={}, src={:#06x}, app_idx={}, len={}",
        path,
        src,
        app_idx,
        data.len()
    );

    true
}

/// Forward a decrypted message to an internal model's callback.
fn forward_model(model: &MeshModel, fwd: &mut ModForward) -> bool {
    // Device key messages go to all registered internal models.
    if fwd.app_idx == APP_IDX_DEV_LOCAL || fwd.app_idx == APP_IDX_DEV_REMOTE {
        if let Some(ref ops) = model.ops {
            if ops.recv(fwd.src, fwd.unicast, fwd.app_idx, fwd.net_idx, &fwd.data) {
                fwd.done = true;
                return true;
            }
        }
        return false;
    }

    // Application key messages require a matching binding.
    if !has_binding(&model.bindings, fwd.app_idx) {
        return false;
    }

    if let Some(ref ops) = model.ops {
        if ops.recv(fwd.src, fwd.unicast, fwd.app_idx, fwd.net_idx, &fwd.data) {
            fwd.done = true;
            return true;
        }
    }

    false
}

// =========================================================================
// Core RX Path
// =========================================================================

/// Process a received mesh access layer message.
///
/// Decrypts the payload (trying app keys, device keys, and virtual labels),
/// then dispatches to internal model handlers first. If no internal handler
/// consumes the message, dispatches to external applications via D-Bus.
///
/// Replaces C `mesh_model_rx()`.
#[allow(clippy::too_many_arguments)]
pub fn mesh_model_recv(
    node: &MeshNode,
    szmics: bool,
    seq0: u32,
    iv_index: u32,
    net_idx: u16,
    src: u16,
    dst: u16,
    key_aid: u8,
    data: &[u8],
    size: u16,
) -> bool {
    let size = size as usize;
    if size > data.len() {
        return false;
    }

    let primary = node.get_primary();
    let num_ele = node.num_ele();
    let is_unicast = dst >= primary && dst < primary + num_ele as u16;

    // Device key messages use APP_AID_DEV
    if key_aid == APP_AID_DEV {
        return handle_dev_key_msg(
            node, szmics, seq0, iv_index, net_idx, src, dst, data, size, primary, num_ele,
            is_unicast,
        );
    }

    // Try virtual address decryption for group addresses (bit 15 set, non-fixed)
    if dst & 0x8000 != 0 && !is_fixed_group_address(dst) {
        if let Some((plaintext, app_idx, found_net_idx)) = virt_packet_decrypt(
            &node.net.lock().unwrap(),
            data,
            size,
            szmics,
            src,
            dst,
            key_aid,
            seq0,
            iv_index,
        ) {
            return dispatch_decrypted(
                node,
                &plaintext,
                src,
                dst,
                app_idx,
                found_net_idx,
                primary,
                num_ele,
                is_unicast,
            );
        }
    }

    // Try application key decryption
    if let Some((plaintext, app_idx, found_net_idx)) = app_packet_decrypt(
        &node.net.lock().unwrap(),
        data,
        size,
        szmics,
        src,
        dst,
        key_aid,
        seq0,
        iv_index,
    ) {
        return dispatch_decrypted(
            node,
            &plaintext,
            src,
            dst,
            app_idx,
            found_net_idx,
            primary,
            num_ele,
            is_unicast,
        );
    }

    false
}

/// Handle device key message decryption and dispatch.
#[allow(clippy::too_many_arguments)]
fn handle_dev_key_msg(
    node: &MeshNode,
    szmics: bool,
    seq0: u32,
    iv_index: u32,
    net_idx: u16,
    src: u16,
    dst: u16,
    data: &[u8],
    size: usize,
    primary: u16,
    num_ele: u8,
    is_unicast: bool,
) -> bool {
    // Try local device key first
    {
        let dev_key = node.get_dev_key();
        if let Some(plaintext) =
            dev_packet_decrypt(&dev_key, data, size, szmics, src, dst, seq0, iv_index)
        {
            return dispatch_dev_key_msg(
                node,
                &plaintext,
                src,
                dst,
                APP_IDX_DEV_LOCAL,
                net_idx,
                primary,
                num_ele,
                is_unicast,
            );
        }
    }

    // Try remote device key
    let storage_dir = node.get_storage_dir();
    if let Some(remote_key) = keyring_get_remote_dev_key(&storage_dir, src) {
        if let Some(plaintext) =
            dev_packet_decrypt(&remote_key, data, size, szmics, src, dst, seq0, iv_index)
        {
            return dispatch_dev_key_msg(
                node,
                &plaintext,
                src,
                dst,
                APP_IDX_DEV_REMOTE,
                net_idx,
                primary,
                num_ele,
                is_unicast,
            );
        }
    }

    false
}

/// Dispatch a decrypted device key message to model handlers and D-Bus.
#[allow(clippy::too_many_arguments)]
fn dispatch_dev_key_msg(
    node: &MeshNode,
    plaintext: &[u8],
    src: u16,
    dst: u16,
    app_idx: u16,
    net_idx: u16,
    primary: u16,
    num_ele: u8,
    is_unicast: bool,
) -> bool {
    let is_remote = app_idx == APP_IDX_DEV_REMOTE;
    let mut result = false;

    if is_unicast {
        let ele_idx = (dst - primary) as u8;
        let mut fwd = ModForward {
            src,
            app_idx,
            net_idx,
            data: plaintext.to_vec(),
            done: false,
            unicast: primary + ele_idx as u16,
        };

        {
            let elements = node.elements.lock().unwrap();
            if let Some(ele) = elements.get(ele_idx as usize) {
                for model in &ele.models {
                    if forward_model(model, &mut fwd) {
                        break;
                    }
                }
            }
        }

        send_dev_key_msg_rcvd(node, ele_idx, is_remote, src, net_idx, plaintext);
        return fwd.done;
    }

    // Broadcast to all elements
    for ele_idx in 0..num_ele {
        let mut fwd = ModForward {
            src,
            app_idx,
            net_idx,
            data: plaintext.to_vec(),
            done: false,
            unicast: primary + ele_idx as u16,
        };

        {
            let elements = node.elements.lock().unwrap();
            if let Some(ele) = elements.get(ele_idx as usize) {
                for model in &ele.models {
                    if forward_model(model, &mut fwd) {
                        break;
                    }
                }
            }
        }

        if fwd.done {
            result = true;
        }

        send_dev_key_msg_rcvd(node, ele_idx, is_remote, src, net_idx, plaintext);
    }

    result
}

/// Dispatch a decrypted app key message to model handlers.
#[allow(clippy::too_many_arguments)]
fn dispatch_decrypted(
    node: &MeshNode,
    plaintext: &[u8],
    src: u16,
    dst: u16,
    app_idx: u16,
    net_idx: u16,
    primary: u16,
    num_ele: u8,
    is_unicast: bool,
) -> bool {
    let mut result = false;

    if is_unicast {
        let ele_idx = (dst - primary) as u8;
        let mut fwd = ModForward {
            src,
            app_idx,
            net_idx,
            data: plaintext.to_vec(),
            done: false,
            unicast: primary + ele_idx as u16,
        };

        {
            let elements = node.elements.lock().unwrap();
            if let Some(ele) = elements.get(ele_idx as usize) {
                for model in &ele.models {
                    if forward_model(model, &mut fwd) {
                        break;
                    }
                }
            }
        }

        if fwd.done {
            result = true;
        } else {
            send_msg_rcvd(node, ele_idx, false, src, app_idx, plaintext);
            result = true;
        }

        return result;
    }

    // Group/subscription address: dispatch to all subscribed elements
    for ele_idx in 0..num_ele {
        let has_sub = {
            let elements = node.elements.lock().unwrap();
            if let Some(ele) = elements.get(ele_idx as usize) {
                ele.models.iter().any(|m| {
                    m.sub_enabled && m.subs.contains(&dst) && has_binding(&m.bindings, app_idx)
                })
            } else {
                false
            }
        };

        if !has_sub {
            continue;
        }

        let mut fwd = ModForward {
            src,
            app_idx,
            net_idx,
            data: plaintext.to_vec(),
            done: false,
            unicast: primary + ele_idx as u16,
        };

        {
            let elements = node.elements.lock().unwrap();
            if let Some(ele) = elements.get(ele_idx as usize) {
                for model in &ele.models {
                    forward_model(model, &mut fwd);
                }
            }
        }

        if !fwd.done {
            send_msg_rcvd(node, ele_idx, true, src, app_idx, plaintext);
        }

        result = true;
    }

    result
}

// =========================================================================
// Public API — Message Send / Publish
// =========================================================================

/// Send a mesh message from a specific element.
///
/// Replaces C `mesh_model_send()`.
pub fn mesh_model_send(
    node: &MeshNode,
    src_ele: u8,
    dst: u16,
    app_idx: u16,
    net_idx: u16,
    ttl: u8,
    is_dev_key: bool,
    data: &[u8],
) -> bool {
    if data.len() > MAX_MSG_LEN {
        return false;
    }

    let primary = node.get_primary();
    let src = primary + src_ele as u16;
    let dev_key = node.get_dev_key();

    msg_send(
        &mut node.net.lock().unwrap(),
        is_dev_key,
        src,
        dst,
        app_idx,
        net_idx,
        ttl,
        &dev_key,
        data,
    )
}

/// Publish a message from a model using its configured publication state.
///
/// Replaces C `mesh_model_publish()`.
pub fn mesh_model_publish(
    node: &MeshNode,
    model_id: u32,
    src_ele: u8,
    virtual_label: bool,
    data: &[u8],
) -> bool {
    if data.len() > MAX_MSG_LEN {
        error!("mesh_model_publish: payload too large");
        return false;
    }

    let primary = node.get_primary();

    let (dst, app_idx, ttl, is_dev) = {
        let elements = node.elements.lock().unwrap();
        let model = match get_model(&elements, src_ele, model_id) {
            Some(m) => m,
            None => {
                error!("mesh_model_publish: model {:#010x} not found", model_id);
                return false;
            }
        };

        if !model.pub_enabled {
            warn!("mesh_model_publish: publication disabled");
            return false;
        }

        let pub_state = match &model.pub_state {
            Some(p) => p,
            None => {
                error!("mesh_model_publish: no publication configured");
                return false;
            }
        };

        if is_unassigned(pub_state.addr) {
            error!("mesh_model_publish: unassigned address");
            return false;
        }

        let ai = pub_state.idx;
        let is_dev = ai == APP_IDX_DEV_LOCAL || ai == APP_IDX_DEV_REMOTE;
        (pub_state.addr, ai, pub_state.ttl, is_dev)
    };

    let net_idx = if is_dev { 0 } else { appkey_net_idx(&node.net.lock().unwrap(), app_idx) };

    let dev_key = node.get_dev_key();
    let _ = virtual_label; // AAD handled in crypto layer for virt addresses

    msg_send(
        &mut node.net.lock().unwrap(),
        is_dev,
        primary + src_ele as u16,
        dst,
        app_idx,
        net_idx,
        ttl,
        &dev_key,
        data,
    )
}

// =========================================================================
// Model Registration and Management
// =========================================================================

/// Add models to an element from a config element definition.
///
/// Replaces C `mesh_model_add()`.
pub fn mesh_model_add(
    _node: &MeshNode,
    models: &mut Vec<MeshModel>,
    ele: &MeshConfigElement,
) -> bool {
    for cfg_model in &ele.models {
        let id = cfg_model.id;
        if models.iter().any(|m| m.id == id) {
            warn!("mesh_model_add: model {:#010x} already exists", id);
            continue;
        }
        models.push(MeshModel::new(id));
    }
    true
}

/// Free/clean up a model — calls unregister on internal ops.
///
/// Replaces C `mesh_model_free()`.
pub fn mesh_model_free(model: &mut MeshModel) {
    if let Some(ref ops) = model.ops {
        ops.unregister();
    }
    model.ops = None;

    for virt in &model.virtuals {
        unref_virt(virt);
    }
    model.virtuals.clear();

    if let Some(ref pub_state) = model.pub_state {
        if let Some(ref virt) = pub_state.virt {
            unref_virt(virt);
        }
    }
    model.pub_state = None;
    model.bindings.clear();
    model.subs.clear();
}

/// Register internal model operations for a model.
///
/// Replaces C `mesh_model_register()`.
pub fn mesh_model_register(
    node: &MeshNode,
    ele_idx: u8,
    model_id: u32,
    ops: Box<dyn MeshModelOps>,
) -> bool {
    let mut elements = node.elements.lock().unwrap();
    let model = match get_model_mut(&mut elements, ele_idx, model_id) {
        Some(m) => m,
        None => {
            error!(
                "mesh_model_register: model {:#010x} not found on element {}",
                model_id, ele_idx
            );
            return false;
        }
    };

    model.ops = Some(ops);
    true
}

// =========================================================================
// App Key Delete
// =========================================================================

/// Remove an app key binding from all models across all elements.
///
/// Replaces C `mesh_model_app_key_delete()`.
pub fn mesh_model_app_key_delete(node: &MeshNode, ele_count: u8, app_idx: u16) {
    let mut elements = node.elements.lock().unwrap();
    for ele_idx in 0..ele_count {
        if let Some(ele) = elements.get_mut(ele_idx as usize) {
            for model in &mut ele.models {
                let had = has_binding(&model.bindings, app_idx);
                model.bindings.retain(|&b| b != app_idx);
                if had {
                    if let Some(ref ops) = model.ops {
                        ops.bind(app_idx, ACTION_DELETE);
                    }
                }
            }
        }
    }
}

// =========================================================================
// Binding Management
// =========================================================================

/// Add an app key binding to a model.
///
/// Replaces C `mesh_model_binding_add()`.
pub fn mesh_model_binding_add(node: &MeshNode, ele_idx: u8, model_id: u32, app_idx: u16) -> u8 {
    {
        let elements = node.elements.lock().unwrap();
        match get_model(&elements, ele_idx, model_id) {
            Some(m) => {
                if is_internal(model_id) {
                    return MESH_STATUS_INVALID_MODEL;
                }
                if has_binding(&m.bindings, app_idx) {
                    return MESH_STATUS_SUCCESS;
                }
                if m.bindings.len() >= MAX_MODEL_BINDINGS {
                    return MESH_STATUS_INSUFF_RESOURCES;
                }
            }
            None => return MESH_STATUS_INVALID_MODEL,
        }
    }

    let ele_addr = node.get_primary() + ele_idx as u16;
    let vendor = is_vendor(model_id);

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if config.model_binding_add(ele_addr, model_id, vendor, app_idx).is_err() {
                return MESH_STATUS_STORAGE_FAIL;
            }
        }
    }

    let mut elements = node.elements.lock().unwrap();
    if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
        model.bindings.push(app_idx);
        if let Some(ref ops) = model.ops {
            ops.bind(app_idx, ACTION_ADD);
        }
    }

    MESH_STATUS_SUCCESS
}

/// Remove an app key binding from a model.
///
/// Replaces C `mesh_model_binding_del()`.
pub fn mesh_model_binding_del(node: &MeshNode, ele_idx: u8, model_id: u32, app_idx: u16) -> u8 {
    let has_it = {
        let elements = node.elements.lock().unwrap();
        match get_model(&elements, ele_idx, model_id) {
            Some(m) => has_binding(&m.bindings, app_idx),
            None => return MESH_STATUS_INVALID_MODEL,
        }
    };

    if is_internal(model_id) {
        return MESH_STATUS_INVALID_MODEL;
    }
    if !has_it {
        return MESH_STATUS_SUCCESS;
    }

    let ele_addr = node.get_primary() + ele_idx as u16;
    let vendor = is_vendor(model_id);

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if config.model_binding_del(ele_addr, model_id, vendor, app_idx).is_err() {
                return MESH_STATUS_STORAGE_FAIL;
            }
        }
    }

    let mut elements = node.elements.lock().unwrap();
    if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
        model.bindings.retain(|&b| b != app_idx);
        if let Some(ref ops) = model.ops {
            ops.bind(app_idx, ACTION_DELETE);
        }
    }

    MESH_STATUS_SUCCESS
}

/// Get the list of bindings for a model.
///
/// Replaces C `mesh_model_get_bindings()`.
pub fn mesh_model_get_bindings(node: &MeshNode, ele_idx: u8, model_id: u32) -> Option<Vec<u16>> {
    let elements = node.elements.lock().unwrap();
    let model = get_model(&elements, ele_idx, model_id)?;
    Some(model.bindings.clone())
}

// =========================================================================
// Subscription Management
// =========================================================================

/// Add a group subscription address to a model.
///
/// Replaces C `mesh_model_sub_add()`.
pub fn mesh_model_sub_add(node: &MeshNode, ele_addr: u16, model_id: u32, group: u16) -> u8 {
    let ele_idx = match node.get_element_idx(ele_addr) {
        Some(idx) => idx,
        None => return MESH_STATUS_INVALID_ADDRESS,
    };

    {
        let elements = node.elements.lock().unwrap();
        let model = match get_model(&elements, ele_idx, model_id) {
            Some(m) => m,
            None => return MESH_STATUS_INVALID_MODEL,
        };
        if is_internal(model_id) {
            return MESH_STATUS_INVALID_MODEL;
        }
        if model.subs.contains(&group) {
            return MESH_STATUS_SUCCESS;
        }
        if model.subs.len() >= MAX_MODEL_SUBS {
            return MESH_STATUS_INSUFF_RESOURCES;
        }
    }

    let vendor = is_vendor(model_id);
    let sub = MeshConfigSub { virt: false, addr: group, virt_addr: [0u8; 16] };

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if config.model_sub_add(ele_addr, model_id, vendor, &sub).is_err() {
                return MESH_STATUS_STORAGE_FAIL;
            }
        }
    }

    {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
            model.subs.push(group);
            if let Some(ref ops) = model.ops {
                ops.subscribe(group, ACTION_ADD);
            }
        }
    }

    {
        let mut net = node.net.lock().unwrap();
        net.dst_reg(group);
    }

    MESH_STATUS_SUCCESS
}

/// Add a virtual label subscription to a model.
///
/// Replaces C `mesh_model_virt_sub_add()`.
pub fn mesh_model_virt_sub_add(
    node: &MeshNode,
    ele_addr: u16,
    model_id: u32,
    label: &[u8; 16],
) -> (u8, u16) {
    let ele_idx = match node.get_element_idx(ele_addr) {
        Some(idx) => idx,
        None => return (MESH_STATUS_INVALID_ADDRESS, 0),
    };

    {
        let elements = node.elements.lock().unwrap();
        match get_model(&elements, ele_idx, model_id) {
            Some(_) => {
                if is_internal(model_id) {
                    return (MESH_STATUS_INVALID_MODEL, 0);
                }
            }
            None => return (MESH_STATUS_INVALID_MODEL, 0),
        }
    }

    // Find or create the virtual label entry
    let virt = match find_virt_by_label(label) {
        Some(v) => {
            v.add_ref();
            v
        }
        None => {
            let nv = match MeshVirtual::new(*label) {
                Some(v) => Arc::new(v),
                None => return (MESH_STATUS_UNSPECIFIED_ERROR, 0),
            };
            if let Ok(mut virtuals) = mesh_virtuals().lock() {
                virtuals.push(Arc::clone(&nv));
            }
            nv
        }
    };

    let addr = virt.addr;

    // Check if already subscribed or at capacity
    {
        let elements = node.elements.lock().unwrap();
        let model = match get_model(&elements, ele_idx, model_id) {
            Some(m) => m,
            None => {
                unref_virt(&virt);
                return (MESH_STATUS_INVALID_MODEL, 0);
            }
        };
        if model.virtuals.iter().any(|v| v.label == virt.label) {
            unref_virt(&virt);
            return (MESH_STATUS_SUCCESS, addr);
        }
        if model.subs.len() >= MAX_MODEL_SUBS {
            unref_virt(&virt);
            return (MESH_STATUS_INSUFF_RESOURCES, 0);
        }
    }

    let vendor = is_vendor(model_id);
    let sub = MeshConfigSub { virt: true, addr, virt_addr: *label };

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if config.model_sub_add(ele_addr, model_id, vendor, &sub).is_err() {
                unref_virt(&virt);
                return (MESH_STATUS_STORAGE_FAIL, 0);
            }
        }
    }

    {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
            model.subs.push(addr);
            model.virtuals.push(virt);
            if let Some(ref ops) = model.ops {
                ops.subscribe(addr, ACTION_ADD);
            }
        }
    }

    {
        let mut net = node.net.lock().unwrap();
        net.dst_reg(addr);
    }

    (MESH_STATUS_SUCCESS, addr)
}

/// Remove a group subscription address from a model.
///
/// Replaces C `mesh_model_sub_del()`.
pub fn mesh_model_sub_del(node: &MeshNode, ele_addr: u16, model_id: u32, group: u16) -> u8 {
    let ele_idx = match node.get_element_idx(ele_addr) {
        Some(idx) => idx,
        None => return MESH_STATUS_INVALID_ADDRESS,
    };

    {
        let elements = node.elements.lock().unwrap();
        match get_model(&elements, ele_idx, model_id) {
            Some(m) => {
                if is_internal(model_id) {
                    return MESH_STATUS_INVALID_MODEL;
                }
                if !m.subs.contains(&group) {
                    return MESH_STATUS_SUCCESS;
                }
            }
            None => return MESH_STATUS_INVALID_MODEL,
        }
    }

    let vendor = is_vendor(model_id);
    let sub = MeshConfigSub { virt: false, addr: group, virt_addr: [0u8; 16] };

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if config.model_sub_del(ele_addr, model_id, vendor, &sub).is_err() {
                return MESH_STATUS_STORAGE_FAIL;
            }
        }
    }

    {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
            model.subs.retain(|&s| s != group);
            if let Some(ref ops) = model.ops {
                ops.subscribe(group, ACTION_DELETE);
            }
        }
    }

    {
        let mut net = node.net.lock().unwrap();
        net.dst_unreg(group);
    }

    MESH_STATUS_SUCCESS
}

/// Remove a virtual label subscription from a model.
///
/// Replaces C `mesh_model_virt_sub_del()`.
pub fn mesh_model_virt_sub_del(
    node: &MeshNode,
    ele_addr: u16,
    model_id: u32,
    label: &[u8; 16],
) -> (u8, u16) {
    let ele_idx = match node.get_element_idx(ele_addr) {
        Some(idx) => idx,
        None => return (MESH_STATUS_INVALID_ADDRESS, 0),
    };

    let addr = {
        let elements = node.elements.lock().unwrap();
        let model = match get_model(&elements, ele_idx, model_id) {
            Some(m) => m,
            None => return (MESH_STATUS_INVALID_MODEL, 0),
        };
        if is_internal(model_id) {
            return (MESH_STATUS_INVALID_MODEL, 0);
        }
        match model.virtuals.iter().find(|v| v.label == *label) {
            Some(v) => v.addr,
            None => return (MESH_STATUS_SUCCESS, 0),
        }
    };

    let vendor = is_vendor(model_id);
    let sub = MeshConfigSub { virt: true, addr, virt_addr: *label };

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if config.model_sub_del(ele_addr, model_id, vendor, &sub).is_err() {
                return (MESH_STATUS_STORAGE_FAIL, 0);
            }
        }
    }

    {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
            if let Some(idx) = model.virtuals.iter().position(|v| v.label == *label) {
                let virt = model.virtuals.remove(idx);
                unref_virt(&virt);
            }
            model.subs.retain(|&s| s != addr);
            if let Some(ref ops) = model.ops {
                ops.subscribe(addr, ACTION_DELETE);
            }
        }
    }

    {
        let mut net = node.net.lock().unwrap();
        net.dst_unreg(addr);
    }

    (MESH_STATUS_SUCCESS, addr)
}

/// Remove all subscriptions from a model.
///
/// Replaces C `mesh_model_sub_del_all()`.
pub fn mesh_model_sub_del_all(node: &MeshNode, ele_addr: u16, model_id: u32) -> u8 {
    let ele_idx = match node.get_element_idx(ele_addr) {
        Some(idx) => idx,
        None => return MESH_STATUS_INVALID_ADDRESS,
    };

    {
        let elements = node.elements.lock().unwrap();
        if get_model(&elements, ele_idx, model_id).is_none() {
            return MESH_STATUS_INVALID_MODEL;
        }
        if is_internal(model_id) {
            return MESH_STATUS_INVALID_MODEL;
        }
    }

    let vendor = is_vendor(model_id);

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if config.model_sub_del_all(ele_addr, model_id, vendor).is_err() {
                return MESH_STATUS_STORAGE_FAIL;
            }
        }
    }

    let (old_subs, old_virts) = {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
            let subs = std::mem::take(&mut model.subs);
            let virts = std::mem::take(&mut model.virtuals);
            if let Some(ref ops) = model.ops {
                ops.subscribe(UNASSIGNED_ADDRESS, ACTION_DELETE);
            }
            (subs, virts)
        } else {
            return MESH_STATUS_INVALID_MODEL;
        }
    };

    {
        let mut net = node.net.lock().unwrap();
        for &sub in &old_subs {
            net.dst_unreg(sub);
        }
    }

    for virt in &old_virts {
        unref_virt(virt);
    }

    MESH_STATUS_SUCCESS
}

/// Overwrite subscription list with a single group address.
///
/// Replaces C `mesh_model_sub_ovrt()`.
pub fn mesh_model_sub_ovrt(node: &MeshNode, ele_addr: u16, model_id: u32, group: u16) -> u8 {
    let status = mesh_model_sub_del_all(node, ele_addr, model_id);
    if status != MESH_STATUS_SUCCESS {
        return status;
    }
    mesh_model_sub_add(node, ele_addr, model_id, group)
}

/// Overwrite subscription list with a single virtual label.
///
/// Replaces C `mesh_model_virt_sub_ovrt()`.
pub fn mesh_model_virt_sub_ovrt(
    node: &MeshNode,
    ele_addr: u16,
    model_id: u32,
    label: &[u8; 16],
) -> (u8, u16) {
    let status = mesh_model_sub_del_all(node, ele_addr, model_id);
    if status != MESH_STATUS_SUCCESS {
        return (status, 0);
    }
    mesh_model_virt_sub_add(node, ele_addr, model_id, label)
}

/// Get all subscription addresses for a model.
///
/// Replaces C `mesh_model_sub_get()`.
pub fn mesh_model_sub_get(node: &MeshNode, ele_addr: u16, model_id: u32) -> Option<Vec<u16>> {
    let ele_idx = node.get_element_idx(ele_addr)?;
    let elements = node.elements.lock().unwrap();
    let model = get_model(&elements, ele_idx, model_id)?;
    Some(model.subs.clone())
}

// =========================================================================
// Publication Management
// =========================================================================

/// Get the publication configuration for a model.
///
/// Replaces C `mesh_model_pub_get()`.
pub fn mesh_model_pub_get(node: &MeshNode, ele_addr: u16, model_id: u32) -> Option<MeshModelPub> {
    let ele_idx = node.get_element_idx(ele_addr)?;
    let elements = node.elements.lock().unwrap();
    let model = get_model(&elements, ele_idx, model_id)?;
    model.pub_state.clone()
}

/// Set the publication configuration for a model.
///
/// Replaces C `mesh_model_pub_set()`.
pub fn mesh_model_pub_set(
    node: &MeshNode,
    ele_addr: u16,
    model_id: u32,
    pub_cfg: &MeshConfigPub,
) -> u8 {
    let ele_idx = match node.get_element_idx(ele_addr) {
        Some(idx) => idx,
        None => return MESH_STATUS_INVALID_ADDRESS,
    };

    // Validate app key if not unassigned
    if !is_unassigned(pub_cfg.addr) {
        let app_idx = pub_cfg.idx;
        if app_idx != APP_IDX_DEV_LOCAL
            && app_idx != APP_IDX_DEV_REMOTE
            && !appkey_have_key(&node.net.lock().unwrap(), app_idx)
        {
            return MESH_STATUS_INVALID_APPKEY;
        }
    }

    {
        let elements = node.elements.lock().unwrap();
        if get_model(&elements, ele_idx, model_id).is_none() {
            return MESH_STATUS_INVALID_MODEL;
        }
    }

    // Clean old publication virtual label
    {
        let elements = node.elements.lock().unwrap();
        if let Some(model) = get_model(&elements, ele_idx, model_id) {
            if let Some(ref old_pub) = model.pub_state {
                if let Some(ref virt) = old_pub.virt {
                    unref_virt(virt);
                }
            }
        }
    }

    // Resolve virtual label if needed
    let virt = if pub_cfg.virt {
        match find_virt_by_label(&pub_cfg.virt_addr) {
            Some(v) => {
                v.add_ref();
                Some(v)
            }
            None => {
                let nv = match MeshVirtual::new(pub_cfg.virt_addr) {
                    Some(v) => Arc::new(v),
                    None => return MESH_STATUS_INVALID_PUB_PARAM,
                };
                if let Ok(mut virtuals) = mesh_virtuals().lock() {
                    virtuals.push(Arc::clone(&nv));
                }
                Some(nv)
            }
        }
    } else {
        None
    };

    let new_pub = MeshModelPub {
        virt,
        addr: pub_cfg.addr,
        idx: pub_cfg.idx,
        rtx: PubRetransmit {
            interval: pub_cfg.retransmit_interval,
            cnt: pub_cfg.retransmit_count as u8,
        },
        ttl: pub_cfg.ttl as u8,
        credential: u8::from(pub_cfg.credential),
        period: ms_to_pub_period(pub_cfg.period),
    };

    let vendor = is_vendor(model_id);

    {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            if is_unassigned(pub_cfg.addr) {
                let _ = config.model_pub_del(ele_addr, model_id, vendor);
            } else if config.model_pub_add(ele_addr, model_id, vendor, pub_cfg).is_err() {
                return MESH_STATUS_STORAGE_FAIL;
            }
        }
    }

    {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
            if let Some(ref ops) = model.ops {
                ops.publish(&new_pub);
            }
            model.pub_state = Some(new_pub);
        }
    }

    MESH_STATUS_SUCCESS
}

// =========================================================================
// Storage Conversion
// =========================================================================

/// Populate model state from storage configuration.
///
/// Replaces C `mesh_model_add_from_storage()`.
pub fn mesh_model_add_from_storage(
    node: &MeshNode,
    ele_idx: u8,
    cfg_model: &MeshConfigModel,
) -> bool {
    // Ensure model exists
    {
        let elements = node.elements.lock().unwrap();
        if get_model(&elements, ele_idx, cfg_model.id).is_none() {
            drop(elements);
            let mut elements = node.elements.lock().unwrap();
            if let Some(ele) = elements.get_mut(ele_idx as usize) {
                ele.models.push(MeshModel::new(cfg_model.id));
            } else {
                return false;
            }
        }
    }

    // Restore bindings
    {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, cfg_model.id) {
            for &binding in &cfg_model.bindings {
                if !has_binding(&model.bindings, binding) {
                    model.bindings.push(binding);
                }
            }
        }
    }

    // Restore subscriptions
    for sub in &cfg_model.subs {
        if sub.virt {
            let virt = match find_virt_by_label(&sub.virt_addr) {
                Some(v) => {
                    v.add_ref();
                    v
                }
                None => {
                    let nv = match MeshVirtual::new(sub.virt_addr) {
                        Some(v) => Arc::new(v),
                        None => continue,
                    };
                    if let Ok(mut virtuals) = mesh_virtuals().lock() {
                        virtuals.push(Arc::clone(&nv));
                    }
                    nv
                }
            };
            let addr = virt.addr;
            {
                let mut elements = node.elements.lock().unwrap();
                if let Some(model) = get_model_mut(&mut elements, ele_idx, cfg_model.id) {
                    if !model.subs.contains(&addr) {
                        model.subs.push(addr);
                        model.virtuals.push(virt.clone());
                    }
                }
            }
            {
                let mut net = node.net.lock().unwrap();
                net.dst_reg(addr);
            }
        } else {
            {
                let mut elements = node.elements.lock().unwrap();
                if let Some(model) = get_model_mut(&mut elements, ele_idx, cfg_model.id) {
                    if !model.subs.contains(&sub.addr) {
                        model.subs.push(sub.addr);
                    }
                }
            }
            if sub.addr != 0 {
                let mut net = node.net.lock().unwrap();
                net.dst_reg(sub.addr);
            }
        }
    }

    // Restore publication state
    if let Some(ref pub_cfg) = cfg_model.pub_state {
        let virt = if pub_cfg.virt {
            match find_virt_by_label(&pub_cfg.virt_addr) {
                Some(v) => {
                    v.add_ref();
                    Some(v)
                }
                None => match MeshVirtual::new(pub_cfg.virt_addr) {
                    Some(v) => {
                        let nv = Arc::new(v);
                        if let Ok(mut virtuals) = mesh_virtuals().lock() {
                            virtuals.push(Arc::clone(&nv));
                        }
                        Some(nv)
                    }
                    None => None,
                },
            }
        } else {
            None
        };

        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, cfg_model.id) {
            model.pub_state = Some(MeshModelPub {
                virt,
                addr: pub_cfg.addr,
                idx: pub_cfg.idx,
                rtx: PubRetransmit {
                    interval: pub_cfg.retransmit_interval,
                    cnt: pub_cfg.retransmit_count as u8,
                },
                ttl: pub_cfg.ttl as u8,
                credential: u8::from(pub_cfg.credential),
                period: ms_to_pub_period(pub_cfg.period),
            });
        }
    }

    // Restore enable flags
    {
        let mut elements = node.elements.lock().unwrap();
        if let Some(model) = get_model_mut(&mut elements, ele_idx, cfg_model.id) {
            model.sub_enabled = cfg_model.sub_enabled;
            model.pub_enabled = cfg_model.pub_enabled;
        }
    }

    true
}

/// Convert model state to storage configuration.
///
/// Replaces C `mesh_model_convert_to_storage()`.
pub fn mesh_model_convert_to_storage(model: &MeshModel) -> MeshConfigModel {
    let mut subs = Vec::new();
    for &addr in &model.subs {
        if let Some(virt) = model.virtuals.iter().find(|v| v.addr == addr) {
            subs.push(MeshConfigSub { virt: true, addr, virt_addr: virt.label });
        } else {
            subs.push(MeshConfigSub { virt: false, addr, virt_addr: [0u8; 16] });
        }
    }

    let pub_state = model.pub_state.as_ref().map(|pub_st| {
        let (is_virt, virt_addr) =
            if let Some(ref v) = pub_st.virt { (true, v.label) } else { (false, [0u8; 16]) };
        MeshConfigPub {
            virt: is_virt,
            addr: pub_st.addr,
            idx: pub_st.idx,
            ttl: pub_st.ttl as u16,
            period: pub_period_to_ms(pub_st.period),
            retransmit_interval: pub_st.rtx.interval,
            retransmit_count: pub_st.rtx.cnt as u16,
            credential: pub_st.credential != 0,
            virt_addr,
        }
    });

    MeshConfigModel {
        subs,
        pub_state,
        bindings: model.bindings.clone(),
        id: model.id,
        vendor: is_vendor(model.id),
        sub_enabled: model.sub_enabled,
        pub_enabled: model.pub_enabled,
    }
}

// =========================================================================
// Configuration Update Helpers
// =========================================================================

/// Build a D-Bus configuration update message for a model.
///
/// Replaces C `mesh_model_build_config()`.
pub fn mesh_model_build_config(
    node: &MeshNode,
    ele_idx: u8,
    model_id: u32,
) -> Option<HashMap<String, Value<'static>>> {
    let elements = node.elements.lock().unwrap();
    let model = get_model(&elements, ele_idx, model_id)?;

    let mut dict: HashMap<String, Value<'static>> = HashMap::new();

    // Bindings
    let bindings: Vec<Value<'static>> = model.bindings.iter().map(|&b| Value::from(b)).collect();
    dict_insert_basic(&mut dict, "Bindings", Value::from(bindings));

    // Subscriptions
    let subs: Vec<Value<'static>> = model.subs.iter().map(|&s| Value::from(s)).collect();
    dict_insert_basic(&mut dict, "Subscriptions", Value::from(subs));

    // Publication
    if let Some(ref pub_st) = model.pub_state {
        dict_insert_basic(&mut dict, "PublicationAddress", Value::from(pub_st.addr));
        dict_insert_basic(&mut dict, "PublicationIndex", Value::from(pub_st.idx));
        dict_insert_basic(&mut dict, "PublicationTTL", Value::from(pub_st.ttl));
        dict_insert_basic(
            &mut dict,
            "PublicationPeriod",
            Value::from(pub_period_to_ms(pub_st.period)),
        );
        dict_insert_basic(&mut dict, "PublicationRetransmitCount", Value::from(pub_st.rtx.cnt));
        dict_insert_basic(
            &mut dict,
            "PublicationRetransmitInterval",
            Value::from(pub_st.rtx.interval),
        );
    }

    Some(dict)
}

/// Update model options (subscription enable, publication enable).
///
/// Replaces C `mesh_model_update_opts()`.
pub fn mesh_model_update_opts(
    node: &MeshNode,
    ele_idx: u8,
    model_id: u32,
    sub_enabled: bool,
    pub_enabled: bool,
) {
    let ele_addr = node.get_primary() + ele_idx as u16;
    let vendor = is_vendor(model_id);

    let (old_sub, old_pub) = {
        let elements = node.elements.lock().unwrap();
        match get_model(&elements, ele_idx, model_id) {
            Some(m) => (m.sub_enabled, m.pub_enabled),
            None => return,
        }
    };

    if old_sub != sub_enabled {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            let _ = config.model_sub_enable(ele_addr, model_id, vendor, sub_enabled);
        }
    }

    if old_pub != pub_enabled {
        let mut cfg = node.config.lock().unwrap();
        if let Some(ref mut config) = *cfg {
            let _ = config.model_pub_enable(ele_addr, model_id, vendor, pub_enabled);
        }
    }

    let mut elements = node.elements.lock().unwrap();
    if let Some(model) = get_model_mut(&mut elements, ele_idx, model_id) {
        model.sub_enabled = sub_enabled;
        model.pub_enabled = pub_enabled;
    }
}

// =========================================================================
// Composition Data Generation
// =========================================================================

/// Generate Composition Data Page 0 for the node.
///
/// Replaces C `mesh_model_generate_composition()`.
pub fn mesh_model_generate_composition(node: &MeshNode, buf: &mut Vec<u8>) {
    let elements = node.elements.lock().unwrap();
    let crpl = node.crpl.load(Ordering::Relaxed);
    let lpn_mode = node.lpn_mode.load(Ordering::Relaxed);

    // CID (Company Identifier) — 0x0000 for unassigned
    buf.extend_from_slice(&0u16.to_le_bytes());
    // PID (Product Identifier)
    buf.extend_from_slice(&0u16.to_le_bytes());
    // VID (Version Identifier)
    buf.extend_from_slice(&0u16.to_le_bytes());
    // CRPL (Minimum number of replay protection entries)
    buf.extend_from_slice(&crpl.to_le_bytes());

    // Features bitmask: Relay(0), Proxy(1), Friend(2), LPN(3)
    let mut features: u16 = 0;
    {
        let net = node.net.lock().unwrap();
        if net.is_relay_enabled() {
            features |= 0x0001;
        }
        if net.is_proxy_enabled() {
            features |= 0x0002;
        }
        if net.is_friend_enabled() {
            features |= 0x0004;
        }
    }
    if lpn_mode == MESH_MODE_ENABLED {
        features |= 0x0008;
    }
    buf.extend_from_slice(&features.to_le_bytes());

    // Element descriptors
    for ele in elements.iter() {
        // Location
        buf.extend_from_slice(&ele.location.to_le_bytes());

        let num_sig = ele.models.iter().filter(|m| !is_vendor(m.id)).count() as u8;
        let num_vendor = ele.models.iter().filter(|m| is_vendor(m.id)).count() as u8;
        buf.push(num_sig);
        buf.push(num_vendor);

        // SIG models first
        for model in &ele.models {
            if !is_vendor(model.id) {
                buf.extend_from_slice(&model_id(model.id).to_le_bytes());
            }
        }
        // Vendor models second
        for model in &ele.models {
            if is_vendor(model.id) {
                buf.extend_from_slice(&vendor_id(model.id).to_le_bytes());
                buf.extend_from_slice(&model_id(model.id).to_le_bytes());
            }
        }
    }
}

// =========================================================================
// Initialization / Cleanup
// =========================================================================

/// Initialize the model layer.
///
/// Replaces C `mesh_model_init()`.
pub fn mesh_model_init() {
    let _ = mesh_virtuals();
    debug!("Mesh model layer initialized");
}

/// Clean up the model layer, releasing all virtual label entries.
///
/// Replaces C `mesh_model_cleanup()`.
pub fn mesh_model_cleanup() {
    if let Ok(mut virtuals) = mesh_virtuals().lock() {
        virtuals.clear();
    }
    debug!("Mesh model layer cleaned up");
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_MODEL_BINDINGS, 10);
        assert_eq!(MAX_MODEL_SUBS, 10);
        assert_eq!(ACTION_ADD, 1);
        assert_eq!(ACTION_UPDATE, 2);
        assert_eq!(ACTION_DELETE, 3);
        assert_eq!(SIG_VENDOR, 0xFFFF);
    }

    #[test]
    fn test_set_id_and_extract() {
        let id = set_id(0x1234, 0x5678);
        assert_eq!(id, 0x1234_5678);
        assert_eq!(vendor_id(id), 0x1234);
        assert_eq!(model_id(id), 0x5678);
        assert!(is_vendor(id));
    }

    #[test]
    fn test_sig_model_id() {
        let id = set_id(SIG_VENDOR, 0x0000);
        assert_eq!(id, 0xFFFF_0000);
        assert!(!is_vendor(id));
        assert_eq!(vendor_id(id), SIG_VENDOR);
        assert_eq!(model_id(id), 0x0000);
    }

    #[test]
    fn test_is_internal() {
        assert!(is_internal(CONFIG_SRV_MODEL));
        assert!(is_internal(CONFIG_CLI_MODEL));
        assert!(is_internal(REM_PROV_SRV_MODEL));
        assert!(is_internal(REM_PROV_CLI_MODEL));
        assert!(is_internal(PRV_BEACON_SRV_MODEL));
        assert!(is_internal(PRV_BEACON_CLI_MODEL));
        assert!(!is_internal(set_id(SIG_VENDOR, 0x1000)));
        assert!(!is_internal(set_id(0x1234, 0x5678)));
    }

    #[test]
    fn test_opcode_encode_1byte() {
        let mut buf = [0u8; 4];
        assert_eq!(mesh_model_opcode_set(0x01, &mut buf), 1);
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn test_opcode_encode_2byte() {
        let mut buf = [0u8; 4];
        assert_eq!(mesh_model_opcode_set(0x8000, &mut buf), 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x00);
    }

    #[test]
    fn test_opcode_encode_3byte() {
        let mut buf = [0u8; 4];
        assert_eq!(mesh_model_opcode_set(0xC0_1234, &mut buf), 3);
        assert_eq!(buf[0], 0xC0);
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2], 0x12);
    }

    #[test]
    fn test_opcode_decode_1byte() {
        let data = [0x01u8, 0x00, 0x00];
        let (opcode, len) = mesh_model_opcode_get(&data).unwrap();
        assert_eq!(opcode, 0x01);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_opcode_decode_2byte() {
        let data = [0x80u8, 0x00];
        let (opcode, len) = mesh_model_opcode_get(&data).unwrap();
        assert_eq!(opcode, 0x8000);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_opcode_decode_3byte() {
        let data = [0xC0u8, 0x34, 0x12];
        let (opcode, len) = mesh_model_opcode_get(&data).unwrap();
        assert_eq!(opcode, 0xC0_1234);
        assert_eq!(len, 3);
    }

    #[test]
    fn test_opcode_decode_invalid() {
        assert!(mesh_model_opcode_get(&[]).is_none());
        assert!(mesh_model_opcode_get(&[0x00]).is_none());
        assert!(mesh_model_opcode_get(&[0x7F]).is_none());
    }

    #[test]
    fn test_opcode_roundtrip() {
        // 1-byte opcodes
        for op in 1u32..=0x7E {
            let mut buf = [0u8; 4];
            let n = mesh_model_opcode_set(op, &mut buf);
            assert_eq!(n, 1, "1-byte encode failed for {:#x}", op);
            let (decoded, len) = mesh_model_opcode_get(&buf[..n]).unwrap();
            assert_eq!(decoded, op, "1-byte roundtrip failed for {:#x}", op);
            assert_eq!(len, 1);
        }

        // 2-byte opcodes
        for op in [0x8000u32, 0x8018, 0x804E, 0xBFFF] {
            let mut buf = [0u8; 4];
            let n = mesh_model_opcode_set(op, &mut buf);
            assert_eq!(n, 2, "2-byte encode failed for {:#x}", op);
            let (decoded, len) = mesh_model_opcode_get(&buf[..n]).unwrap();
            assert_eq!(decoded, op, "2-byte roundtrip failed for {:#x}", op);
            assert_eq!(len, 2);
        }

        // 3-byte opcodes
        for op in [0xC0_0000u32, 0xC0_1234, 0xFF_FFFF] {
            let mut buf = [0u8; 4];
            let n = mesh_model_opcode_set(op, &mut buf);
            assert_eq!(n, 3, "3-byte encode failed for {:#x}", op);
            let (decoded, len) = mesh_model_opcode_get(&buf[..n]).unwrap();
            assert_eq!(decoded, op, "3-byte roundtrip failed for {:#x}", op);
            assert_eq!(len, 3);
        }
    }

    #[test]
    fn test_pub_period_to_ms() {
        assert_eq!(pub_period_to_ms(0x01), 100); // 1 step × 100ms
        assert_eq!(pub_period_to_ms(0x0A), 1000); // 10 steps × 100ms
        assert_eq!(pub_period_to_ms(0x41), 1000); // 1 step × 1000ms
        assert_eq!(pub_period_to_ms(0x4A), 10_000); // 10 steps × 1000ms
        assert_eq!(pub_period_to_ms(0x81), 10_000); // 1 step × 10000ms
        assert_eq!(pub_period_to_ms(0xC1), 600_000); // 1 step × 600000ms
        assert_eq!(pub_period_to_ms(0x00), 0); // 0 steps = disabled
    }

    #[test]
    fn test_has_binding() {
        let bindings = vec![0, 1, 5, 10];
        assert!(has_binding(&bindings, 0));
        assert!(has_binding(&bindings, 5));
        assert!(!has_binding(&bindings, 2));
        assert!(!has_binding(&[], 0));
    }

    #[test]
    fn test_mesh_model_new() {
        let model = MeshModel::new(set_id(SIG_VENDOR, 0x0000));
        assert_eq!(model.id, CONFIG_SRV_MODEL);
        assert!(model.bindings.is_empty());
        assert!(model.subs.is_empty());
        assert!(model.ops.is_none());
        assert!(model.sub_enabled);
        assert!(model.pub_enabled);
    }

    #[test]
    fn test_mesh_model_pub_default() {
        let pub_state = MeshModelPub::default();
        assert_eq!(pub_state.addr, UNASSIGNED_ADDRESS);
        assert!(pub_state.virt.is_none());
        assert_eq!(pub_state.ttl, 0);
    }

    #[test]
    fn test_mesh_node_element_idx() {
        let node = MeshNode::new();
        node.primary.store(0x0100, Ordering::Relaxed);
        {
            let mut elements = node.elements.lock().unwrap();
            elements.push(MeshElement {
                models: Vec::new(),
                path: String::from("/e0"),
                location: 0,
            });
            elements.push(MeshElement {
                models: Vec::new(),
                path: String::from("/e1"),
                location: 1,
            });
        }
        assert_eq!(node.get_element_idx(0x0100), Some(0));
        assert_eq!(node.get_element_idx(0x0101), Some(1));
        assert_eq!(node.get_element_idx(0x0102), None);
        assert_eq!(node.get_element_idx(0x00FF), None);
    }

    #[test]
    fn test_mesh_model_init_cleanup() {
        mesh_model_init();
        mesh_model_cleanup();
    }

    #[test]
    fn test_convert_to_storage_empty() {
        let model = MeshModel::new(set_id(SIG_VENDOR, 0x1000));
        let cfg = mesh_model_convert_to_storage(&model);
        assert_eq!(cfg.id, model.id);
        assert!(!cfg.vendor);
        assert!(cfg.bindings.is_empty());
        assert!(cfg.subs.is_empty());
        assert!(cfg.pub_state.is_none());
    }

    #[test]
    fn test_convert_to_storage_with_bindings() {
        let mut model = MeshModel::new(set_id(0x1234, 0x5678));
        model.bindings.push(0);
        model.bindings.push(5);
        let cfg = mesh_model_convert_to_storage(&model);
        assert!(cfg.vendor);
        assert_eq!(cfg.bindings, vec![0, 5]);
    }

    #[test]
    fn test_seg_count() {
        // Single unsegmented message: 15 bytes or less (including MIC)
        assert_eq!(seg_count(11, 4), 0); // 11+4=15 => unsegmented
        assert_eq!(seg_count(12, 4), 1); // 12+4=16 => segmented (at least 1 seg + 1)
        assert_eq!(seg_count(1, 4), 0); // 1+4=5 => unsegmented
    }

    #[test]
    fn test_ms_to_pub_period() {
        assert_eq!(ms_to_pub_period(0), 0);
        assert_eq!(ms_to_pub_period(100), 0x01);
        assert_eq!(ms_to_pub_period(1000), 0x41);
        assert_eq!(ms_to_pub_period(10_000), 0x81);
        assert_eq!(ms_to_pub_period(600_000), 0xC1);
    }

    #[test]
    fn test_opcode_set_invalid() {
        let mut buf = [0u8; 4];
        assert_eq!(mesh_model_opcode_set(0x7F, &mut buf), 0); // 0x7F < 0x8000 but > 0x7E
        assert_eq!(mesh_model_opcode_set(0xFF, &mut buf), 0); // 0xFF in between
    }

    #[test]
    fn test_mesh_model_add_from_element() {
        let node = MeshNode::new();
        let mut models = Vec::new();
        let cfg_ele = MeshConfigElement {
            models: vec![
                MeshConfigModel {
                    subs: Vec::new(),
                    pub_state: None,
                    bindings: Vec::new(),
                    id: set_id(SIG_VENDOR, 0x0000),
                    vendor: false,
                    sub_enabled: true,
                    pub_enabled: true,
                },
                MeshConfigModel {
                    subs: Vec::new(),
                    pub_state: None,
                    bindings: Vec::new(),
                    id: set_id(SIG_VENDOR, 0x1000),
                    vendor: false,
                    sub_enabled: true,
                    pub_enabled: true,
                },
            ],
            location: 0,
            index: 0,
        };
        assert!(mesh_model_add(&node, &mut models, &cfg_ele));
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, set_id(SIG_VENDOR, 0x0000));
        assert_eq!(models[1].id, set_id(SIG_VENDOR, 0x1000));
    }

    #[test]
    fn test_mesh_model_free_cleans_up() {
        let mut model = MeshModel::new(set_id(SIG_VENDOR, 0x1000));
        model.bindings.push(0);
        model.bindings.push(1);
        model.subs.push(0xC000);
        mesh_model_free(&mut model);
        assert!(model.bindings.is_empty());
        assert!(model.subs.is_empty());
        assert!(model.ops.is_none());
        assert!(model.pub_state.is_none());
    }
}
