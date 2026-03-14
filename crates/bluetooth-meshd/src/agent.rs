// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2024 BlueZ Project
//
//! Bluetooth Mesh provisioning agent management.
//!
//! Complete Rust rewrite of `mesh/agent.c` (~450 lines) and `mesh/agent.h`
//! from BlueZ v5.86.  Tracks D-Bus `ProvisionAgent1` objects registered by
//! external applications, parses their provisioning capabilities and OOB
//! information, and serialises async prompt/display/key-request D-Bus
//! method calls with one-request-at-a-time enforcement and cancellation
//! support.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::oneshot;
use tracing::{debug, error};
use zbus::zvariant::{OwnedValue, Value};

use crate::crypto;
use crate::dbus::{DEFAULT_DBUS_TIMEOUT, MeshError, dbus_get_connection};
use crate::mesh::MESH_PROVISION_AGENT_INTERFACE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// OOB Info bit indicating URI hash is present (Mesh Profile Table 3.54).
const OOB_INFO_URI_HASH: u16 = 0x0002;

/// Index of the `Push` entry in [`CAP_TABLE`], used as the base offset
/// when mapping initiator/non-initiator action indices to the correct
/// capability table row.  Mirrors the C `MESH_AGENT_REQUEST_PUSH` value.
const CAP_TABLE_INPUT_BASE: usize = 5;

// ---------------------------------------------------------------------------
// Provisioning capability table — exact match of C `cap_table[]`
// ---------------------------------------------------------------------------

/// Entry mapping an action string to output/input capability bit flags.
struct ProvAction {
    action: &'static str,
    output: u16,
    input: u16,
    size: u8,
}

/// Provisioning capability table — indices 0–8 match the C
/// `agent_request_type_t` enum values for capability-related request types.
///
/// Index layout:
///   0 blink, 1 beep, 2 vibrate, 3 out-numeric, 4 out-alpha,
///   5 push, 6 twist, 7 in-numeric, 8 in-alpha
static CAP_TABLE: [ProvAction; 9] = [
    ProvAction { action: "blink", output: 0x0001, input: 0x0000, size: 1 },
    ProvAction { action: "beep", output: 0x0002, input: 0x0000, size: 1 },
    ProvAction { action: "vibrate", output: 0x0004, input: 0x0000, size: 1 },
    ProvAction { action: "out-numeric", output: 0x0008, input: 0x0000, size: 8 },
    ProvAction { action: "out-alpha", output: 0x0010, input: 0x0000, size: 8 },
    ProvAction { action: "push", output: 0x0000, input: 0x0001, size: 1 },
    ProvAction { action: "twist", output: 0x0000, input: 0x0002, size: 1 },
    ProvAction { action: "in-numeric", output: 0x0000, input: 0x0004, size: 8 },
    ProvAction { action: "in-alpha", output: 0x0000, input: 0x0008, size: 8 },
];

// ---------------------------------------------------------------------------
// OOB information table — exact match of C `oob_table[]`
// ---------------------------------------------------------------------------

/// Entry mapping an OOB info string to its bit mask.
struct OobInfoEntry {
    oob: &'static str,
    mask: u16,
}

/// OOB information table — exact match of C `oob_table[]` in agent.c.
static OOB_TABLE: [OobInfoEntry; 12] = [
    OobInfoEntry { oob: "other", mask: 0x0001 },
    OobInfoEntry { oob: "uri", mask: 0x0002 },
    OobInfoEntry { oob: "machine-code-2d", mask: 0x0004 },
    OobInfoEntry { oob: "barcode", mask: 0x0008 },
    OobInfoEntry { oob: "nfc", mask: 0x0010 },
    OobInfoEntry { oob: "number", mask: 0x0020 },
    OobInfoEntry { oob: "string", mask: 0x0040 },
    OobInfoEntry { oob: "on-box", mask: 0x0800 },
    OobInfoEntry { oob: "in-box", mask: 0x1000 },
    OobInfoEntry { oob: "on-paper", mask: 0x2000 },
    OobInfoEntry { oob: "in-manual", mask: 0x4000 },
    OobInfoEntry { oob: "on-device", mask: 0x8000 },
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Provisioning capabilities for a mesh agent.
///
/// Direct Rust translation of C `struct mesh_agent_prov_caps` from
/// `mesh/agent.h` lines 13–22.  All fields are public so that the
/// provisioning subsystem can read them directly.
#[derive(Debug, Clone, Default)]
pub struct MeshAgentProvCaps {
    /// 32-bit hash derived from the device URI via `mesh_crypto_s1`.
    pub uri_hash: u32,
    /// OOB information bitmask (Table 3.54 of Mesh Profile v1.0).
    pub oob_info: u16,
    /// Output OOB action bitmask (blink, beep, vibrate, numeric, alpha).
    pub output_action: u16,
    /// Input OOB action bitmask (push, twist, numeric, alpha).
    pub input_action: u16,
    /// Public key type (0 = none, 1 = OOB public key available).
    pub pub_type: u8,
    /// Static OOB type (0 = none, 1 = static OOB available).
    pub static_type: u8,
    /// Maximum output OOB size (1 for single-action, 8 for numeric/alpha).
    pub output_size: u8,
    /// Maximum input OOB size (1 for single-action, 8 for numeric/alpha).
    pub input_size: u8,
}

/// Mesh provisioning agent — tracks a D-Bus ProvisionAgent1 object.
///
/// Replaces C `struct mesh_agent` from `mesh/agent.c`.  The caller owns
/// the returned `MeshAgent` value; the internal agent registry tracks
/// liveness and pending-request state by path.
#[derive(Debug, Clone)]
pub struct MeshAgent {
    /// D-Bus object path of the external ProvisionAgent1 object.
    pub path: String,
    /// D-Bus unique-name (sender) that owns the agent object.
    pub owner: String,
    /// Parsed provisioning capabilities and OOB information.
    pub caps: MeshAgentProvCaps,
}

// ---------------------------------------------------------------------------
// Callback type aliases (Rust equivalents of C callback typedefs)
// ---------------------------------------------------------------------------

/// Simple completion callback — replaces `mesh_agent_cb_t`.
///
/// Receives `Ok(())` on success or `Err(error_code)` on failure, where
/// the error code maps to `MeshError` discriminant values.
pub type MeshAgentCb = Box<dyn FnOnce(Result<(), i32>) + Send>;

/// Key-data callback — replaces `mesh_agent_key_cb_t`.
///
/// Receives the key bytes on success or an error code on failure.
pub type MeshAgentKeyCb = Box<dyn FnOnce(Result<Vec<u8>, i32>) + Send>;

/// Numeric-value callback — replaces `mesh_agent_number_cb_t`.
///
/// Receives the numeric value on success or an error code on failure.
pub type MeshAgentNumberCb = Box<dyn FnOnce(Result<u32, i32>) + Send>;

// ---------------------------------------------------------------------------
// Internal agent registry
// ---------------------------------------------------------------------------

/// Per-agent internal state tracked in the global registry.
///
/// This is separate from the public [`MeshAgent`] struct so that the
/// registry can manage pending-request cancellation without the caller
/// needing mutable access to a global lock.
struct AgentEntry {
    /// Cancellation sender for the currently pending async request.
    /// `Some(tx)` means a request is in flight; `None` means idle.
    cancel_tx: Option<oneshot::Sender<()>>,
}

/// Global agent registry mapping D-Bus object paths to internal state.
///
/// Replaces the C `static struct l_queue *agents`.
struct AgentRegistry {
    entries: HashMap<String, AgentEntry>,
}

impl AgentRegistry {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }
}

/// Process-global agent registry.
static REGISTRY: OnceLock<Mutex<AgentRegistry>> = OnceLock::new();

/// Obtain a reference to the global agent registry, initialising it on
/// first access.
fn registry() -> &'static Mutex<AgentRegistry> {
    REGISTRY.get_or_init(|| Mutex::new(AgentRegistry::new()))
}

// ---------------------------------------------------------------------------
// Value extraction helpers
// ---------------------------------------------------------------------------

/// Extract an array of strings from a zbus `OwnedValue`.
///
/// Handles both direct `Array<Str>` values and variant-wrapped arrays,
/// matching the D-Bus `v → as` pattern used in `a{sv}` property dicts.
fn extract_string_array(value: &OwnedValue) -> Vec<String> {
    // OwnedValue implements Deref<Target = Value<'static>>, auto-deref applies.
    extract_string_array_inner(value)
}

/// Recursive inner helper for [`extract_string_array`].
fn extract_string_array_inner(v: &Value<'_>) -> Vec<String> {
    match v {
        Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr.iter() {
                if let Value::Str(s) = item {
                    result.push(s.to_string());
                }
            }
            result
        }
        Value::Value(inner) => extract_string_array_inner(inner),
        _ => Vec::new(),
    }
}

/// Extract a single string from a zbus `OwnedValue`.
///
/// Handles both direct `Str` values and variant-wrapped strings.
fn extract_string(value: &OwnedValue) -> Option<String> {
    // OwnedValue implements Deref<Target = Value<'static>>, auto-deref applies.
    extract_string_inner(value)
}

/// Recursive inner helper for [`extract_string`].
fn extract_string_inner(v: &Value<'_>) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.to_string()),
        Value::Value(inner) => extract_string_inner(inner),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Property parsing — mirrors C parse_prov_caps / parse_oob_info /
// parse_properties
// ---------------------------------------------------------------------------

/// Parse the `Capabilities` property (D-Bus type `as`) into capability
/// bit flags.
///
/// Mirrors C `parse_prov_caps()` in agent.c lines 102–137.
fn parse_prov_caps(caps: &mut MeshAgentProvCaps, value: &OwnedValue) -> bool {
    let strings = extract_string_array(value);
    if strings.is_empty() {
        return false;
    }

    for s in &strings {
        // Check against the capability action table
        for entry in &CAP_TABLE {
            if s.as_str() == entry.action {
                caps.output_action |= entry.output;
                if entry.output != 0 && caps.output_size < entry.size {
                    caps.output_size = entry.size;
                }
                caps.input_action |= entry.input;
                if entry.input != 0 && caps.input_size < entry.size {
                    caps.input_size = entry.size;
                }
                break;
            }
        }

        // Check special capability strings not in the table
        if s == "public-oob" {
            caps.pub_type = 1;
        } else if s == "static-oob" {
            caps.static_type = 1;
        }
    }

    true
}

/// Parse the `OutOfBandInfo` property (D-Bus type `as`) into OOB info
/// bit flags.
///
/// Mirrors C `parse_oob_info()` in agent.c lines 139–158.
fn parse_oob_info(caps: &mut MeshAgentProvCaps, value: &OwnedValue) -> bool {
    let strings = extract_string_array(value);
    if strings.is_empty() {
        return false;
    }

    for s in &strings {
        for entry in &OOB_TABLE {
            if s.as_str() == entry.oob {
                caps.oob_info |= entry.mask;
            }
        }
    }

    true
}

/// Parse a full `a{sv}` property dictionary into agent capabilities.
///
/// Handles three property keys:
/// - `"Capabilities"` — array of capability strings
/// - `"URI"` — device URI string (hashed via `mesh_crypto_s1`)
/// - `"OutOfBandInfo"` — array of OOB info strings
///
/// Mirrors C `parse_properties()` in agent.c lines 160–193.
fn parse_properties(
    caps: &mut MeshAgentProvCaps,
    properties: &HashMap<String, OwnedValue>,
) -> bool {
    *caps = MeshAgentProvCaps::default();

    for (key, value) in properties {
        match key.as_str() {
            "Capabilities" => {
                if !parse_prov_caps(caps, value) {
                    return false;
                }
            }
            "URI" => {
                if let Some(uri_string) = extract_string(value) {
                    // Compute S1 hash of the URI string and extract
                    // the first 4 bytes as big-endian u32.
                    // Matches C: mesh_crypto_s1(str, len, salt);
                    //            uri_hash = salt[0]<<24 | salt[1]<<16 |
                    //                       salt[2]<<8  | salt[3]
                    if let Some(salt) = crypto::mesh_crypto_s1(uri_string.as_bytes()) {
                        caps.uri_hash = u32::from_be_bytes([salt[0], salt[1], salt[2], salt[3]]);
                        caps.oob_info |= OOB_INFO_URI_HASH;
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            "OutOfBandInfo" => {
                if !parse_oob_info(caps, value) {
                    return false;
                }
            }
            _ => {
                // Ignore unknown properties — forward compatibility.
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Agent lifecycle functions
// ---------------------------------------------------------------------------

/// Initialise the global agent registry.
///
/// Idempotent — safe to call multiple times.  Mirrors C `mesh_agent_init`.
pub fn mesh_agent_init() {
    let _ = registry();
    debug!("Mesh agent subsystem initialised");
}

/// Destroy all tracked agents and cancel any pending requests.
///
/// Mirrors C `mesh_agent_cleanup` which calls `l_queue_destroy(agents,
/// agent_free)`.
pub fn mesh_agent_cleanup() {
    let mut reg = registry().lock().unwrap();
    // Cancel any pending requests before clearing
    for (path, entry) in reg.entries.drain() {
        if let Some(tx) = entry.cancel_tx {
            let _ = tx.send(());
            debug!("Cancelled pending request for agent {path}");
        }
    }
    debug!("Mesh agent subsystem cleaned up");
}

/// Create a new agent from D-Bus properties and register it.
///
/// Returns a [`MeshAgent`] on success, or `None` if the property parsing
/// fails.  If an agent with the same `path` already exists, it is replaced.
///
/// Mirrors C `mesh_agent_create` in agent.c lines 268–285.
pub fn mesh_agent_create(
    path: &str,
    owner: &str,
    properties: &HashMap<String, OwnedValue>,
) -> Option<MeshAgent> {
    let mut caps = MeshAgentProvCaps::default();

    if !parse_properties(&mut caps, properties) {
        error!("Failed to parse agent properties for {path}");
        return None;
    }

    let agent = MeshAgent { path: path.to_owned(), owner: owner.to_owned(), caps };

    // Register in the global registry
    let mut reg = registry().lock().unwrap();
    reg.entries.insert(path.to_owned(), AgentEntry { cancel_tx: None });

    debug!("Created mesh agent: path={path} owner={owner}");
    Some(agent)
}

/// Remove an agent from the registry and cancel any pending request.
///
/// Mirrors C `mesh_agent_remove` in agent.c lines 243–250.
pub fn mesh_agent_remove(agent: &MeshAgent) {
    let mut reg = registry().lock().unwrap();
    if let Some(entry) = reg.entries.remove(&agent.path) {
        if let Some(tx) = entry.cancel_tx {
            let _ = tx.send(());
        }
        debug!("Removed mesh agent: path={}", agent.path);
    }
}

/// Cancel any pending request for this agent and send a `Cancel` D-Bus
/// method call to the external ProvisionAgent1 object.
///
/// Mirrors C `mesh_agent_cancel` in agent.c lines 731–746.
pub fn mesh_agent_cancel(agent: &MeshAgent) {
    // Signal the pending async operation to abort
    let cancel_tx = {
        let mut reg = registry().lock().unwrap();
        match reg.entries.get_mut(&agent.path) {
            Some(entry) => entry.cancel_tx.take(),
            None => return,
        }
    };

    if let Some(tx) = cancel_tx {
        let _ = tx.send(());
        debug!("Signalled cancellation for agent {}", agent.path);
    }

    // Fire-and-forget Cancel D-Bus method call to the external agent
    let owner = agent.owner.clone();
    let path = agent.path.clone();
    tokio::spawn(async move {
        if let Err(e) = send_cancel_to_agent(&owner, &path).await {
            debug!("Cancel D-Bus call to {path} failed: {e:?}");
        }
    });
}

/// Return a reference to the agent's provisioning capabilities.
///
/// Mirrors C `mesh_agent_get_caps` in agent.c lines 287–293.
pub fn mesh_agent_get_caps(agent: &MeshAgent) -> &MeshAgentProvCaps {
    &agent.caps
}

// ---------------------------------------------------------------------------
// D-Bus proxy helpers
// ---------------------------------------------------------------------------

/// Build a `zbus::Proxy` targeting the agent's D-Bus object on the
/// `org.bluez.mesh.ProvisionAgent1` interface.
///
/// Uses the [`DEFAULT_DBUS_TIMEOUT`] constant to bound proxy method calls.
async fn build_agent_proxy(owner: &str, path: &str) -> Result<zbus::Proxy<'static>, MeshError> {
    let conn = dbus_get_connection().ok_or_else(|| {
        error!("D-Bus connection not available");
        MeshError::Failed
    })?;
    // Convert to owned strings so that the proxy satisfies 'static lifetime.
    let owned_dest = owner.to_owned();
    let owned_path = path.to_owned();
    let owned_iface = MESH_PROVISION_AGENT_INTERFACE.to_owned();
    zbus::proxy::Builder::new(conn)
        .destination(owned_dest)
        .map_err(|e| {
            error!("Invalid agent destination '{owner}': {e}");
            MeshError::Failed
        })?
        .path(owned_path)
        .map_err(|e| {
            error!("Invalid agent path '{path}': {e}");
            MeshError::Failed
        })?
        .interface(owned_iface)
        .map_err(|e| {
            error!("Invalid interface: {e}");
            MeshError::Failed
        })?
        .build()
        .await
        .map_err(|e| {
            error!("Failed to build agent proxy for {path}: {e}");
            MeshError::Failed
        })
}

/// Send a fire-and-forget `Cancel` method call to an external agent.
async fn send_cancel_to_agent(owner: &str, path: &str) -> Result<(), MeshError> {
    let proxy = build_agent_proxy(owner, path).await?;
    proxy.call_noreply("Cancel", &()).await.map_err(|e| {
        error!("Cancel call to {path} failed: {e}");
        MeshError::Failed
    })
}

// ---------------------------------------------------------------------------
// Pending request management
// ---------------------------------------------------------------------------

/// Acquire a pending-request slot for the agent.
///
/// Returns a [`oneshot::Receiver`] that the caller uses in `select!` for
/// cancellation.  Returns `Err(MeshError::DoesNotExist)` if the agent is
/// not registered, or `Err(MeshError::Busy)` if another request is already
/// in flight.
fn acquire_pending(agent: &MeshAgent) -> Result<oneshot::Receiver<()>, MeshError> {
    let mut reg = registry().lock().unwrap();
    let entry = reg.entries.get_mut(&agent.path).ok_or(MeshError::DoesNotExist)?;
    if entry.cancel_tx.is_some() {
        return Err(MeshError::Busy);
    }
    let (tx, rx) = oneshot::channel();
    entry.cancel_tx = Some(tx);
    Ok(rx)
}

/// Release the pending-request slot for the agent.
fn release_pending(agent: &MeshAgent) {
    let mut reg = registry().lock().unwrap();
    if let Some(entry) = reg.entries.get_mut(&agent.path) {
        entry.cancel_tx = None;
    }
}

// ---------------------------------------------------------------------------
// Async D-Bus agent methods
// ---------------------------------------------------------------------------

/// Call `DisplayString(s)` on the external ProvisionAgent1 object.
///
/// Mirrors C `mesh_agent_display_string` in agent.c lines 617–651.
pub async fn mesh_agent_display_string(agent: &MeshAgent, value: &str) -> Result<(), MeshError> {
    let cancel_rx = acquire_pending(agent)?;

    let result = async {
        let proxy = build_agent_proxy(&agent.owner, &agent.path).await?;
        debug!("Send DisplayString request to {} {}", agent.owner, agent.path);
        let body = (value,);
        let timeout_dur = Duration::from_secs(u64::from(DEFAULT_DBUS_TIMEOUT));
        tokio::select! {
            res = proxy.call::<_, _, ()>("DisplayString", &body) => {
                res.map_err(|e| {
                    error!("Agent DisplayString failed: {e}");
                    MeshError::Failed
                })
            }
            _ = cancel_rx => {
                debug!("DisplayString cancelled for {}", agent.path);
                Err(MeshError::Failed)
            }
            _ = tokio::time::sleep(timeout_dur) => {
                error!("DisplayString timed out for {}", agent.path);
                Err(MeshError::Failed)
            }
        }
    }
    .await;

    release_pending(agent);
    result
}

/// Call `DisplayNumeric(s, u)` on the external ProvisionAgent1 object.
///
/// The `action` parameter is an output-action index (0–4).  When
/// `initiator` is `true` the index is offset by [`CAP_TABLE_INPUT_BASE`]
/// to select the corresponding input-side action string.
///
/// Mirrors C `mesh_agent_display_number` in agent.c lines 653–671.
pub async fn mesh_agent_display_number(
    agent: &MeshAgent,
    initiator: bool,
    action: u8,
    count: u32,
) -> Result<(), MeshError> {
    let idx = if initiator { action as usize + CAP_TABLE_INPUT_BASE } else { action as usize };
    if idx >= CAP_TABLE.len() {
        return Err(MeshError::InvalidArgs);
    }
    let action_str = CAP_TABLE[idx].action;

    let cancel_rx = acquire_pending(agent)?;

    let result = async {
        let proxy = build_agent_proxy(&agent.owner, &agent.path).await?;
        debug!("Send DisplayNumeric request to {} {}", agent.owner, agent.path);
        let body = (action_str, count);
        let timeout_dur = Duration::from_secs(u64::from(DEFAULT_DBUS_TIMEOUT));
        tokio::select! {
            res = proxy.call::<_, _, ()>("DisplayNumeric", &body) => {
                res.map_err(|e| {
                    error!("Agent DisplayNumeric failed: {e}");
                    MeshError::Failed
                })
            }
            _ = cancel_rx => {
                debug!("DisplayNumeric cancelled for {}", agent.path);
                Err(MeshError::Failed)
            }
            _ = tokio::time::sleep(timeout_dur) => {
                error!("DisplayNumeric timed out for {}", agent.path);
                Err(MeshError::Failed)
            }
        }
    }
    .await;

    release_pending(agent);
    result
}

/// Call `PromptNumeric(s) → u` on the external ProvisionAgent1 object.
///
/// The `action` parameter is an input-action index.  When `initiator`
/// is `false` the index is offset by [`CAP_TABLE_INPUT_BASE`].
///
/// Mirrors C `mesh_agent_prompt_number` in agent.c lines 673–692.
pub async fn mesh_agent_prompt_number(
    agent: &MeshAgent,
    initiator: bool,
    action: u8,
) -> Result<u32, MeshError> {
    let idx = if !initiator { action as usize + CAP_TABLE_INPUT_BASE } else { action as usize };
    if idx >= CAP_TABLE.len() {
        return Err(MeshError::InvalidArgs);
    }
    let action_str = CAP_TABLE[idx].action;

    let cancel_rx = acquire_pending(agent)?;

    let result = async {
        let proxy = build_agent_proxy(&agent.owner, &agent.path).await?;
        debug!("Send PromptNumeric \"{action_str}\" request to {} {}", agent.owner, agent.path);
        let body = (action_str,);
        let timeout_dur = Duration::from_secs(u64::from(DEFAULT_DBUS_TIMEOUT));
        tokio::select! {
            res = proxy.call::<_, _, u32>("PromptNumeric", &body) => {
                res.map_err(|e| {
                    error!("Agent PromptNumeric failed: {e}");
                    MeshError::Failed
                })
            }
            _ = cancel_rx => {
                debug!("PromptNumeric cancelled for {}", agent.path);
                Err(MeshError::Failed)
            }
            _ = tokio::time::sleep(timeout_dur) => {
                error!("PromptNumeric timed out for {}", agent.path);
                Err(MeshError::Failed)
            }
        }
    }
    .await;

    release_pending(agent);
    result
}

/// Call `PromptStatic(s) → ay` on the external ProvisionAgent1 object
/// with an alphanumeric action string.
///
/// If `initiator` is `true`, sends `"out-alpha"`; otherwise `"in-alpha"`.
///
/// Mirrors C `mesh_agent_prompt_alpha` in agent.c lines 694–707.
pub async fn mesh_agent_prompt_alpha(
    agent: &MeshAgent,
    initiator: bool,
) -> Result<Vec<u8>, MeshError> {
    let action_str = if initiator {
        CAP_TABLE[4].action // "out-alpha" (index 4)
    } else {
        CAP_TABLE[8].action // "in-alpha"  (index 8)
    };

    prompt_static_inner(agent, action_str, 16).await
}

/// Call `PromptStatic(s) → ay` with `"static-oob"` action.
///
/// Mirrors C `mesh_agent_request_static` in agent.c lines 709–714.
pub async fn mesh_agent_request_static(agent: &MeshAgent) -> Result<Vec<u8>, MeshError> {
    prompt_static_inner(agent, "static-oob", 16).await
}

/// Call `PrivateKey() → ay` on the external ProvisionAgent1 object.
///
/// Validates that the returned key is exactly 32 bytes.
///
/// Mirrors C `mesh_agent_request_private_key` in agent.c lines 716–722.
pub async fn mesh_agent_request_private_key(agent: &MeshAgent) -> Result<Vec<u8>, MeshError> {
    request_key_inner(agent, "PrivateKey", 32).await
}

/// Call `PublicKey() → ay` on the external ProvisionAgent1 object.
///
/// Validates that the returned key is exactly 64 bytes.
///
/// Mirrors C `mesh_agent_request_public_key` in agent.c lines 724–729.
pub async fn mesh_agent_request_public_key(agent: &MeshAgent) -> Result<Vec<u8>, MeshError> {
    request_key_inner(agent, "PublicKey", 64).await
}

/// Refresh agent capabilities by calling `org.freedesktop.DBus.Properties.GetAll`
/// on the external ProvisionAgent1 object.
///
/// On success the agent's [`MeshAgentProvCaps`] are replaced with the
/// freshly parsed values.
///
/// Mirrors C `mesh_agent_refresh` in agent.c lines 360–384.
pub async fn mesh_agent_refresh(agent: &mut MeshAgent) -> Result<(), MeshError> {
    // Verify the agent is still registered
    {
        let reg = registry().lock().unwrap();
        if !reg.entries.contains_key(&agent.path) {
            return Err(MeshError::DoesNotExist);
        }
    }

    let conn = dbus_get_connection().ok_or_else(|| {
        error!("D-Bus connection not available");
        MeshError::Failed
    })?;

    // Build a proxy targeting the standard Properties interface with
    // owned strings to satisfy 'static lifetime requirements.
    let owned_dest = agent.owner.clone();
    let owned_path = agent.path.clone();
    let proxy: zbus::Proxy<'static> = zbus::proxy::Builder::new(conn)
        .destination(owned_dest)
        .map_err(|e| {
            error!("Invalid destination for refresh: {e}");
            MeshError::Failed
        })?
        .path(owned_path)
        .map_err(|e| {
            error!("Invalid path for refresh: {e}");
            MeshError::Failed
        })?
        .interface("org.freedesktop.DBus.Properties".to_owned())
        .map_err(|e| {
            error!("Invalid interface for refresh: {e}");
            MeshError::Failed
        })?
        .build()
        .await
        .map_err(|e| {
            error!("Failed to build Properties proxy: {e}");
            MeshError::Failed
        })?;

    // Call GetAll(s interface) → a{sv}
    let props: HashMap<String, OwnedValue> = proxy
        .call::<_, _, HashMap<String, OwnedValue>>("GetAll", &(MESH_PROVISION_AGENT_INTERFACE,))
        .await
        .map_err(|e| {
            error!("Agent properties refresh failed: {e}");
            MeshError::Failed
        })?;

    if !parse_properties(&mut agent.caps, &props) {
        error!("Failed to parse refreshed properties for {}", agent.path);
        return Err(MeshError::Failed);
    }

    debug!("Refreshed capabilities for agent {}", agent.path);
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal async helpers
// ---------------------------------------------------------------------------

/// Shared implementation for `PromptStatic`-based methods (prompt_alpha,
/// request_static).
///
/// Calls `PromptStatic(s action) → ay` and validates the response length.
///
/// Mirrors the C `prompt_input()` function in agent.c lines 540–580 when
/// called with `numeric = false`.
async fn prompt_static_inner(
    agent: &MeshAgent,
    action_str: &str,
    expected_len: usize,
) -> Result<Vec<u8>, MeshError> {
    let cancel_rx = acquire_pending(agent)?;

    let result = async {
        let proxy = build_agent_proxy(&agent.owner, &agent.path).await?;
        debug!("Send PromptStatic \"{action_str}\" request to {} {}", agent.owner, agent.path);
        let body = (action_str,);
        let timeout_dur = Duration::from_secs(u64::from(DEFAULT_DBUS_TIMEOUT));
        tokio::select! {
            res = proxy.call::<_, _, Vec<u8>>("PromptStatic", &body) => {
                match res {
                    Ok(key) => {
                        if key.len() != expected_len {
                            error!(
                                "Bad PromptStatic response length: {} (need {expected_len})",
                                key.len()
                            );
                            Err(MeshError::Failed)
                        } else {
                            Ok(key)
                        }
                    }
                    Err(e) => {
                        error!("Agent PromptStatic failed: {e}");
                        Err(MeshError::Failed)
                    }
                }
            }
            _ = cancel_rx => {
                debug!("PromptStatic cancelled for {}", agent.path);
                Err(MeshError::Failed)
            }
            _ = tokio::time::sleep(timeout_dur) => {
                error!("PromptStatic timed out for {}", agent.path);
                Err(MeshError::Failed)
            }
        }
    }
    .await;

    release_pending(agent);
    result
}

/// Shared implementation for key-request methods (request_private_key,
/// request_public_key).
///
/// Calls the named method (no arguments) → `ay` and validates the
/// response length.
///
/// Mirrors the C `request_key()` function in agent.c lines 582–615.
async fn request_key_inner(
    agent: &MeshAgent,
    method_name: &str,
    expected_len: usize,
) -> Result<Vec<u8>, MeshError> {
    let cancel_rx = acquire_pending(agent)?;

    let result = async {
        let proxy = build_agent_proxy(&agent.owner, &agent.path).await?;
        debug!("Send {method_name} request to {} {}", agent.owner, agent.path);
        let body = ();
        let timeout_dur = Duration::from_secs(u64::from(DEFAULT_DBUS_TIMEOUT));
        tokio::select! {
            res = proxy.call::<_, _, Vec<u8>>(method_name, &body) => {
                match res {
                    Ok(key) => {
                        if key.len() != expected_len {
                            error!(
                                "Bad {method_name} response length: {} (need {expected_len})",
                                key.len()
                            );
                            Err(MeshError::Failed)
                        } else {
                            Ok(key)
                        }
                    }
                    Err(e) => {
                        error!("Agent {method_name} failed: {e}");
                        Err(MeshError::Failed)
                    }
                }
            }
            _ = cancel_rx => {
                debug!("{method_name} cancelled for {}", agent.path);
                Err(MeshError::Failed)
            }
            _ = tokio::time::sleep(timeout_dur) => {
                error!("{method_name} timed out for {}", agent.path);
                Err(MeshError::Failed)
            }
        }
    }
    .await;

    release_pending(agent);
    result
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the capability table has the correct size and action strings.
    #[test]
    fn cap_table_matches_c() {
        assert_eq!(CAP_TABLE.len(), 9);
        assert_eq!(CAP_TABLE[0].action, "blink");
        assert_eq!(CAP_TABLE[4].action, "out-alpha");
        assert_eq!(CAP_TABLE[5].action, "push");
        assert_eq!(CAP_TABLE[8].action, "in-alpha");
    }

    /// Verify the OOB table has the correct size and masks.
    #[test]
    fn oob_table_matches_c() {
        assert_eq!(OOB_TABLE.len(), 12);
        assert_eq!(OOB_TABLE[0].oob, "other");
        assert_eq!(OOB_TABLE[0].mask, 0x0001);
        assert_eq!(OOB_TABLE[11].oob, "on-device");
        assert_eq!(OOB_TABLE[11].mask, 0x8000);
    }

    /// Verify default MeshAgentProvCaps is all zeroes.
    #[test]
    fn default_caps_are_zero() {
        let caps = MeshAgentProvCaps::default();
        assert_eq!(caps.uri_hash, 0);
        assert_eq!(caps.oob_info, 0);
        assert_eq!(caps.output_action, 0);
        assert_eq!(caps.input_action, 0);
        assert_eq!(caps.pub_type, 0);
        assert_eq!(caps.static_type, 0);
        assert_eq!(caps.output_size, 0);
        assert_eq!(caps.input_size, 0);
    }

    /// Verify that the input base offset constant matches the Push index.
    #[test]
    fn input_base_is_push_index() {
        assert_eq!(CAP_TABLE_INPUT_BASE, 5);
        assert_eq!(CAP_TABLE[CAP_TABLE_INPUT_BASE].action, "push");
    }

    /// Verify init/cleanup cycle does not panic.
    #[test]
    fn init_cleanup_cycle() {
        mesh_agent_init();
        mesh_agent_cleanup();
        // Second cycle should also work
        mesh_agent_init();
        mesh_agent_cleanup();
    }

    /// Verify agent creation with empty properties fails gracefully
    /// (since Capabilities are not present, parse_prov_caps won't
    /// be called, and empty properties dict is valid — no mandatory keys).
    #[test]
    fn create_agent_empty_properties() {
        mesh_agent_init();
        let props = HashMap::new();
        let agent = mesh_agent_create("/test/agent1", "org.test.App", &props);
        // Empty properties are acceptable (no mandatory keys fail)
        assert!(agent.is_some());
        if let Some(ref a) = agent {
            assert_eq!(a.path, "/test/agent1");
            assert_eq!(a.owner, "org.test.App");
            assert_eq!(a.caps.output_action, 0);
        }
        if let Some(ref a) = agent {
            mesh_agent_remove(a);
        }
        mesh_agent_cleanup();
    }

    /// Verify agent removal clears the registry entry.
    #[test]
    fn remove_agent() {
        mesh_agent_init();
        let props = HashMap::new();
        let agent = mesh_agent_create("/test/agent2", "org.test.App", &props)
            .expect("agent creation should succeed");
        // Agent should be in registry
        {
            let reg = registry().lock().unwrap();
            assert!(reg.entries.contains_key("/test/agent2"));
        }
        mesh_agent_remove(&agent);
        // Agent should be gone
        {
            let reg = registry().lock().unwrap();
            assert!(!reg.entries.contains_key("/test/agent2"));
        }
        mesh_agent_cleanup();
    }

    /// Verify get_caps returns a reference to the agent's capabilities.
    #[test]
    fn get_caps_returns_ref() {
        let agent = MeshAgent {
            path: "/test/caps".into(),
            owner: "org.test".into(),
            caps: MeshAgentProvCaps { uri_hash: 42, oob_info: 0x0002, ..Default::default() },
        };
        let caps = mesh_agent_get_caps(&agent);
        assert_eq!(caps.uri_hash, 42);
        assert_eq!(caps.oob_info, 0x0002);
    }

    /// Verify display_number index bounds checking.
    #[tokio::test]
    async fn display_number_invalid_action() {
        mesh_agent_init();
        let props = HashMap::new();
        let agent = mesh_agent_create("/test/bounds", "org.test.App", &props).expect("create");
        // action=10 with initiator=false → index 10 ≥ 9 → InvalidArgs
        let result = mesh_agent_display_number(&agent, false, 10, 0).await;
        assert!(matches!(result, Err(MeshError::InvalidArgs)));
        mesh_agent_remove(&agent);
        mesh_agent_cleanup();
    }

    /// Verify prompt_number index bounds checking.
    #[tokio::test]
    async fn prompt_number_invalid_action() {
        mesh_agent_init();
        let props = HashMap::new();
        let agent = mesh_agent_create("/test/bounds2", "org.test.App", &props).expect("create");
        // action=5 with initiator=false → index 5+5=10 ≥ 9 → InvalidArgs
        let result = mesh_agent_prompt_number(&agent, false, 5).await;
        assert!(matches!(result, Err(MeshError::InvalidArgs)));
        mesh_agent_remove(&agent);
        mesh_agent_cleanup();
    }
}
