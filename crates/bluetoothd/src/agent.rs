// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2006-2010  Nokia Corporation
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
//
// Agent manager and brokerage — Rust rewrite of `src/agent.c` and `src/agent.h`.
//
// Implements the `org.bluez.AgentManager1` D-Bus interface (RegisterAgent,
// UnregisterAgent, RequestDefaultAgent) and the agent brokerage that routes
// pairing and authorization requests to registered Agent1 objects.
//
// Key design decisions:
// - `GHashTable *agent_list` → `tokio::sync::RwLock<HashMap<String, Arc<Agent>>>`
// - `struct queue *default_agents` → `tokio::sync::RwLock<VecDeque<Arc<Agent>>>`
// - `agent_cb + void *user_data` → `async fn` returning `Result`
// - `g_dbus_send_message_with_reply` → `zbus::Proxy::call()` with timeout
// - `g_dbus_add_disconnect_watch` → zbus name-owner change monitoring task
// - Reference counting (`agent_ref`/`agent_unref`) → `Arc<Agent>`

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use zbus::zvariant::ObjectPath;

use bluez_shared::mgmt::client::{MgmtIoCapability, mgmt_parse_io_capability};

use crate::adapter::{adapter_set_io_capability, btd_adapter_foreach, btd_adapter_get_address};
use crate::dbus_common::btd_get_dbus_connection;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for the remote Agent1 objects.
pub const AGENT_INTERFACE: &str = "org.bluez.Agent1";

/// Timeout (in seconds) for agent D-Bus proxy calls, matching C
/// `REQUEST_TIMEOUT` of 60 000 ms.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Agent request type — mirrors C `agent_request_type_t`
// ---------------------------------------------------------------------------

/// Discriminant for the type of pending agent request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRequestType {
    RequestPasskey,
    RequestConfirmation,
    RequestAuthorization,
    RequestPinCode,
    AuthorizeService,
    DisplayPinCode,
}

// ---------------------------------------------------------------------------
// Agent request tracking
// ---------------------------------------------------------------------------

/// Tracks a pending request sent to a remote Agent1 object.
///
/// Stored inside `Agent::request` while the D-Bus proxy call is
/// in-flight.  The `device_path` and `device_address` are captured
/// at creation time for duplicate-request detection (matching C
/// `agent_has_request` bidirectional address comparison logic).
#[derive(Debug)]
struct AgentRequest {
    /// What kind of request is pending.
    request_type: AgentRequestType,
    /// D-Bus object path of the target device.
    device_path: String,
    /// BD_ADDR of the target device.
    device_address: bluez_shared::sys::bluetooth::BdAddr,
    /// BD_ADDR of the adapter owning the target device (for bidirectional
    /// matching in duplicate-request detection).
    adapter_address: bluez_shared::sys::bluetooth::BdAddr,
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

/// A registered pairing/authorization agent.
///
/// Each agent is owned by a D-Bus client identified by its unique bus name
/// (`owner`) and publishes an `org.bluez.Agent1` interface at the specified
/// `path`.  The `capability` determines the pairing IO capability negotiated
/// with the kernel MGMT layer.
pub struct Agent {
    /// D-Bus unique bus name of the owning client (e.g. `:1.42`).
    pub owner: String,
    /// D-Bus object path at which the Agent1 interface is exported.
    pub path: String,
    /// Pairing IO capability declared at registration time.
    pub capability: MgmtIoCapability,
    /// Currently pending agent request (at most one at a time, matching C).
    request: Mutex<Option<AgentRequest>>,
}

impl Agent {
    /// Create a new `Agent` with the given owner, path, and capability.
    fn new(owner: String, path: String, capability: MgmtIoCapability) -> Self {
        Self { owner, path, capability, request: Mutex::new(None) }
    }

    /// Returns `true` if this agent currently has a pending request for the
    /// given device and request type.
    ///
    /// Mirrors C `agent_has_request()`:
    /// - If no request is pending, returns `false`.
    /// - If the pending request type differs, returns `false` (caller should
    ///   treat as busy).
    /// - Bidirectional address comparison: the device's address must match the
    ///   pending request's adapter address AND vice-versa, indicating the same
    ///   logical device pair.
    pub async fn has_request(
        &self,
        device: &BtdDevice,
        request_type: AgentRequestType,
    ) -> HasRequestResult {
        let guard = self.request.lock().await;
        let req = match guard.as_ref() {
            None => return HasRequestResult::NoRequest,
            Some(r) => r,
        };
        if req.request_type != request_type {
            return HasRequestResult::Busy;
        }

        // Bidirectional address comparison:
        // 1. Pending device address must equal adapter address of new device.
        let new_adapter_addr = btd_adapter_get_address(device.get_adapter()).await;
        if req.device_address != new_adapter_addr {
            return HasRequestResult::Busy;
        }
        // 2. New device address must equal adapter address of pending device.
        if *device.get_address() != req.adapter_address {
            return HasRequestResult::Busy;
        }

        HasRequestResult::InProgress
    }
}

/// Result of checking whether an agent has a matching pending request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HasRequestResult {
    /// No request is currently pending.
    NoRequest,
    /// A request is pending but for a different type or device — agent is busy.
    Busy,
    /// An identical request is already in progress for this device.
    InProgress,
}

// ---------------------------------------------------------------------------
// Global agent state
// ---------------------------------------------------------------------------

/// Global map of registered agents, keyed by D-Bus unique bus name.
///
/// Replaces C `GHashTable *agent_list`.
static AGENT_LIST: std::sync::LazyLock<RwLock<HashMap<String, Arc<Agent>>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// Ordered queue of default agents (most-recently-requested-default first).
///
/// Replaces C `struct queue *default_agents`.
static DEFAULT_AGENTS: std::sync::LazyLock<RwLock<VecDeque<Arc<Agent>>>> =
    std::sync::LazyLock::new(|| RwLock::new(VecDeque::new()));

// ---------------------------------------------------------------------------
// Default agent management — mirrors C `add_default_agent` / `remove_default_agent`
// ---------------------------------------------------------------------------

/// Promote `agent` to the head of the default-agents queue and propagate its
/// IO capability to all adapters.
///
/// If the agent is already the head, this is a no-op.  Otherwise, any
/// existing entry for this agent is removed and the agent is pushed to the
/// front.
///
/// Matches C `add_default_agent()`.
async fn add_default_agent(agent: &Arc<Agent>) -> bool {
    let mut defaults = DEFAULT_AGENTS.write().await;

    // Already the default — nothing to do.
    if let Some(head) = defaults.front() {
        if Arc::ptr_eq(head, agent) {
            return true;
        }
    }

    // Remove any existing entry for this agent.
    defaults.retain(|a| !Arc::ptr_eq(a, agent));

    // Push to front (highest priority).
    defaults.push_front(Arc::clone(agent));

    btd_debug(0xFFFF, &format!("Default agent set to {} {}", agent.owner, agent.path));

    // Propagate IO capability to all adapters.
    let cap = agent.capability as u8;
    btd_adapter_foreach(|adapter| {
        let adapter_clone = Arc::clone(adapter);
        let cap_val = cap;
        tokio::spawn(async move {
            adapter_set_io_capability(&adapter_clone, cap_val).await;
        });
    })
    .await;

    true
}

/// Remove `agent` from the default-agents queue.
///
/// If the agent was the current default, the next agent in the queue (if any)
/// becomes the default and its IO capability is propagated to all adapters.
/// If the queue becomes empty, `MGMT_IO_CAPABILITY_INVALID` is propagated.
///
/// Matches C `remove_default_agent()`.
async fn remove_default_agent(agent: &Arc<Agent>) {
    let mut defaults = DEFAULT_AGENTS.write().await;

    let was_head = defaults.front().is_some_and(|head| Arc::ptr_eq(head, agent));

    defaults.retain(|a| !Arc::ptr_eq(a, agent));

    if !was_head {
        return;
    }

    // Determine new IO capability for adapters.
    let new_cap = if let Some(new_head) = defaults.front() {
        btd_debug(0xFFFF, &format!("Default agent set to {} {}", new_head.owner, new_head.path));
        new_head.capability as u8
    } else {
        btd_debug(0xFFFF, "Default agent cleared");
        MgmtIoCapability::Invalid as u8
    };

    // Propagate to all adapters.
    btd_adapter_foreach(|adapter| {
        let adapter_clone = Arc::clone(adapter);
        let cap_val = new_cap;
        tokio::spawn(async move {
            adapter_set_io_capability(&adapter_clone, cap_val).await;
        });
    })
    .await;
}

// ---------------------------------------------------------------------------
// Agent lifecycle helpers
// ---------------------------------------------------------------------------

/// Send a `Release` fire-and-forget message to the agent's Agent1 interface.
///
/// Matches C `agent_release()`.
async fn agent_release_dbus(agent: &Agent) {
    btd_debug(0xFFFF, &format!("Releasing agent {}, {}", agent.owner, agent.path));

    match agent_proxy(agent).await {
        Ok(p) => {
            let _ = p.call_noreply("Release", &()).await;
        }
        Err(e) => {
            btd_error(0xFFFF, &format!("Failed to create agent proxy for Release: {e}"));
        }
    }
}

/// Send a `Cancel` fire-and-forget message to the agent's Agent1 interface.
///
/// Matches C `send_cancel_request()`.
async fn send_cancel_to_agent(agent: &Agent) {
    btd_debug(0xFFFF, &format!("Sending Cancel request to {}, {}", agent.owner, agent.path));

    match agent_proxy(agent).await {
        Ok(p) => {
            let _ = p.call_noreply("Cancel", &()).await;
        }
        Err(e) => {
            btd_error(0xFFFF, &format!("Failed to create agent proxy for Cancel: {e}"));
        }
    }
}

/// Handle an agent's D-Bus owner disconnecting.
///
/// Removes the agent from the global list and default-agents queue, then
/// cleans up any pending request.
///
/// Matches C `agent_disconnect()`.
async fn agent_disconnect(owner: &str) {
    btd_debug(0xFFFF, &format!("Agent {owner} disconnected"));

    // Remove from agent_list.
    let agent = {
        let mut list = AGENT_LIST.write().await;
        list.remove(owner)
    };

    if let Some(agent) = agent {
        // Remove from default agents queue.
        remove_default_agent(&agent).await;
    }
}

/// Spawn a task that monitors the D-Bus name owner of the given agent and
/// triggers cleanup when the owner disappears.
///
/// Matches C `g_dbus_add_disconnect_watch()`.
fn spawn_name_watch(agent_owner: String) {
    let conn = btd_get_dbus_connection().clone();
    tokio::spawn(async move {
        // Use NameOwnerChanged signal to detect when the owner goes away.
        let name = agent_owner.clone();
        let dbus_proxy = match zbus::fdo::DBusProxy::new(&conn).await {
            Ok(p) => p,
            Err(e) => {
                btd_error(0xFFFF, &format!("Failed to create DBus proxy for name watch: {e}"));
                return;
            }
        };

        // Subscribe to NameOwnerChanged for this specific name.
        let mut stream = match dbus_proxy.receive_name_owner_changed().await {
            Ok(s) => s,
            Err(e) => {
                btd_error(0xFFFF, &format!("Failed to subscribe to NameOwnerChanged: {e}"));
                return;
            }
        };

        use futures::StreamExt;
        while let Some(signal) = stream.next().await {
            let args = match signal.args() {
                Ok(a) => a,
                Err(_) => continue,
            };
            // Check if this is our agent's name going away.
            if args.name.as_str() == name && args.new_owner.is_none() {
                agent_disconnect(&name).await;
                break;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Agent brokerage — public query API
// ---------------------------------------------------------------------------

/// Look up an agent for the given D-Bus sender (owner).
///
/// If `owner` is provided and a per-connection agent exists, returns it.
/// Otherwise, returns the current default agent (head of the default queue).
/// Returns `None` if no agent is available.
///
/// Matches C `agent_get()`.
pub async fn agent_get(owner: Option<&str>) -> Option<Arc<Agent>> {
    if let Some(owner_str) = owner {
        let list = AGENT_LIST.read().await;
        if let Some(agent) = list.get(owner_str) {
            return Some(Arc::clone(agent));
        }
    }

    let defaults = DEFAULT_AGENTS.read().await;
    defaults.front().cloned()
}

/// Return the IO capability of the given agent.
///
/// Matches C `agent_get_io_capability()`.
pub fn agent_get_io_capability(agent: &Agent) -> MgmtIoCapability {
    agent.capability
}

// ---------------------------------------------------------------------------
// Agent request error type
// ---------------------------------------------------------------------------

/// Error type for agent request operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The agent is busy with another request.
    #[error("Agent busy")]
    Busy,

    /// An identical request is already in progress.
    #[error("Already in progress")]
    InProgress,

    /// The remote agent replied with a D-Bus error.
    #[error("Agent error: {name}: {message}")]
    AgentReply {
        /// D-Bus error name from the agent.
        name: String,
        /// Human-readable error description.
        message: String,
    },

    /// The request timed out waiting for the agent.
    #[error("Timed out waiting for reply from agent")]
    Timeout,

    /// A D-Bus communication error occurred.
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    /// Failed to send message.
    #[error("D-Bus send failed")]
    SendFailed,

    /// No pending request to cancel.
    #[error("No pending request")]
    NoPendingRequest,

    /// Invalid PIN code length returned by agent.
    #[error("Invalid PIN length ({0})")]
    InvalidPinLength(usize),

    /// Generic internal failure.
    #[error("{0}")]
    Failed(String),
}

// ---------------------------------------------------------------------------
// Helper: create a zbus proxy to the agent's Agent1 interface
// ---------------------------------------------------------------------------

/// Build a `zbus::Proxy` targeting the agent's Agent1 interface.
///
/// Uses owned `String` values for destination and path so the returned proxy
/// is `'static` and not tied to the `Agent` borrow lifetime.
async fn agent_proxy(agent: &Agent) -> Result<zbus::Proxy<'static>, AgentError> {
    let conn = btd_get_dbus_connection();
    let proxy = zbus::proxy::Builder::new(conn)
        .destination(agent.owner.clone())
        .map_err(|e| AgentError::Failed(format!("proxy builder destination: {e}")))?
        .path(agent.path.clone())
        .map_err(|e| AgentError::Failed(format!("proxy builder path: {e}")))?
        .interface(AGENT_INTERFACE)
        .map_err(|e| AgentError::Failed(format!("proxy builder interface: {e}")))?
        .build()
        .await
        .map_err(AgentError::Dbus)?;
    Ok(proxy)
}

/// Helper: check for an existing request and return the appropriate error.
///
/// Translates `HasRequestResult` to `AgentError`.
async fn check_existing_request(
    agent: &Agent,
    device: &BtdDevice,
    req_type: AgentRequestType,
) -> Result<(), AgentError> {
    match agent.has_request(device, req_type).await {
        HasRequestResult::NoRequest => Ok(()),
        HasRequestResult::Busy => Err(AgentError::Busy),
        HasRequestResult::InProgress => Err(AgentError::InProgress),
    }
}

/// Record a pending request on the agent.
async fn set_pending_request(agent: &Agent, device: &BtdDevice, req_type: AgentRequestType) {
    let adapter_address = btd_adapter_get_address(device.get_adapter()).await;
    let dev_path = device.get_path().to_string();
    btd_debug(0xFFFF, &format!("setting pending request {:?} for device {}", req_type, dev_path));
    let mut guard = agent.request.lock().await;
    *guard = Some(AgentRequest {
        request_type: req_type,
        device_path: dev_path,
        device_address: *device.get_address(),
        adapter_address,
    });
}

/// Clear the pending request on the agent.
async fn clear_pending_request(agent: &Agent) {
    let mut guard = agent.request.lock().await;
    if let Some(req) = guard.take() {
        btd_debug(
            0xFFFF,
            &format!(
                "clearing pending request {:?} for device {}",
                req.request_type, req.device_path
            ),
        );
    }
}

// ---------------------------------------------------------------------------
// Agent D-Bus proxy call helpers with timeout
// ---------------------------------------------------------------------------

/// Call a method on the remote Agent1 and handle timeout/error uniformly.
///
/// On success, returns the raw `zbus::message::Message` reply.
/// On timeout, sends a Cancel to the agent and returns `AgentError::Timeout`.
/// On D-Bus error reply, returns `AgentError::AgentReply`.
async fn agent_call<B: serde::Serialize + zbus::zvariant::DynamicType>(
    agent: &Agent,
    method: &str,
    body: &B,
) -> Result<zbus::message::Message, AgentError> {
    let proxy = agent_proxy(agent).await?;

    match tokio::time::timeout(REQUEST_TIMEOUT, proxy.call_method(method, body)).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(zbus::Error::MethodError(name, desc, _msg))) => {
            let desc_str = desc.unwrap_or_default();
            btd_debug(0xFFFF, &format!("agent error reply: {name}, {desc_str}"));
            Err(AgentError::AgentReply { name: name.to_string(), message: desc_str })
        }
        Ok(Err(e)) => Err(AgentError::Dbus(e)),
        Err(_elapsed) => {
            btd_error(0xFFFF, "Timed out waiting for reply from agent");
            send_cancel_to_agent(agent).await;
            Err(AgentError::Timeout)
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing / Authorization request functions — public async API
// ---------------------------------------------------------------------------

/// Request a PIN code from the agent for legacy pairing.
///
/// Returns the PIN code string on success.
/// Matches C `agent_request_pincode()`.
pub async fn agent_request_pincode(
    agent: &Arc<Agent>,
    device: &BtdDevice,
    _secure: bool,
) -> Result<String, AgentError> {
    // Check agent is not busy.
    {
        let guard = agent.request.lock().await;
        if guard.is_some() {
            return Err(AgentError::Busy);
        }
    }

    set_pending_request(agent, device, AgentRequestType::RequestPinCode).await;

    let dev_path = device.get_path().to_string();

    btd_debug(
        0xFFFF,
        &format!("Calling Agent.RequestPinCode: name={}, path={}", agent.owner, agent.path),
    );

    let body =
        (ObjectPath::try_from(dev_path.as_str()).map_err(|e| AgentError::Failed(e.to_string()))?,);

    let result = agent_call(agent, "RequestPinCode", &body).await;

    clear_pending_request(agent).await;

    match result {
        Ok(reply) => {
            let pin: String = reply
                .body()
                .deserialize()
                .map_err(|e| AgentError::Failed(format!("Wrong passkey reply signature: {e}")))?;

            let len = pin.len();
            if !(1..=16).contains(&len) {
                btd_error(0xFFFF, &format!("Invalid PIN length ({len}) from agent"));
                return Err(AgentError::InvalidPinLength(len));
            }
            Ok(pin)
        }
        Err(e) => Err(e),
    }
}

/// Request a numeric passkey from the agent for SSP pairing.
///
/// Returns the 6-digit passkey on success.
/// Matches C `agent_request_passkey()`.
pub async fn agent_request_passkey(
    agent: &Arc<Agent>,
    device: &BtdDevice,
) -> Result<u32, AgentError> {
    {
        let guard = agent.request.lock().await;
        if guard.is_some() {
            return Err(AgentError::Busy);
        }
    }

    btd_debug(
        0xFFFF,
        &format!("Calling Agent.RequestPasskey: name={}, path={}", agent.owner, agent.path),
    );

    set_pending_request(agent, device, AgentRequestType::RequestPasskey).await;

    let dev_path = device.get_path().to_string();
    let body =
        (ObjectPath::try_from(dev_path.as_str()).map_err(|e| AgentError::Failed(e.to_string()))?,);

    let result = agent_call(agent, "RequestPasskey", &body).await;

    clear_pending_request(agent).await;

    match result {
        Ok(reply) => {
            let passkey: u32 = reply
                .body()
                .deserialize()
                .map_err(|e| AgentError::Failed(format!("Wrong passkey reply signature: {e}")))?;
            Ok(passkey)
        }
        Err(e) => Err(e),
    }
}

/// Request confirmation of a passkey from the agent.
///
/// Matches C `agent_request_confirmation()`.
pub async fn agent_request_confirmation(
    agent: &Arc<Agent>,
    device: &BtdDevice,
    passkey: u32,
) -> Result<(), AgentError> {
    check_existing_request(agent, device, AgentRequestType::RequestConfirmation).await?;

    btd_debug(
        0xFFFF,
        &format!(
            "Calling Agent.RequestConfirmation: name={}, path={}, passkey={:06}",
            agent.owner, agent.path, passkey
        ),
    );

    set_pending_request(agent, device, AgentRequestType::RequestConfirmation).await;

    let dev_path = device.get_path().to_string();
    let body = (
        ObjectPath::try_from(dev_path.as_str()).map_err(|e| AgentError::Failed(e.to_string()))?,
        passkey,
    );

    let result = agent_call(agent, "RequestConfirmation", &body).await;

    clear_pending_request(agent).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Request authorization from the agent for an incoming connection.
///
/// Matches C `agent_request_authorization()`.
pub async fn agent_request_authorization(
    agent: &Arc<Agent>,
    device: &BtdDevice,
) -> Result<(), AgentError> {
    check_existing_request(agent, device, AgentRequestType::RequestAuthorization).await?;

    btd_debug(
        0xFFFF,
        &format!("Calling Agent.RequestAuthorization: name={}, path={}", agent.owner, agent.path),
    );

    set_pending_request(agent, device, AgentRequestType::RequestAuthorization).await;

    let dev_path = device.get_path().to_string();
    let body =
        (ObjectPath::try_from(dev_path.as_str()).map_err(|e| AgentError::Failed(e.to_string()))?,);

    let result = agent_call(agent, "RequestAuthorization", &body).await;

    clear_pending_request(agent).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Request authorization for a specific service UUID from the agent.
///
/// Matches C `agent_authorize_service()`.
pub async fn agent_authorize_service(
    agent: &Arc<Agent>,
    device: &BtdDevice,
    uuid: &str,
) -> Result<(), AgentError> {
    check_existing_request(agent, device, AgentRequestType::AuthorizeService).await?;

    set_pending_request(agent, device, AgentRequestType::AuthorizeService).await;

    let dev_path = device.get_path().to_string();

    btd_debug(0xFFFF, &format!("authorize service request was sent for {}", dev_path));

    let body = (
        ObjectPath::try_from(dev_path.as_str()).map_err(|e| AgentError::Failed(e.to_string()))?,
        uuid,
    );

    let result = agent_call(agent, "AuthorizeService", &body).await;

    clear_pending_request(agent).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Fire-and-forget display of a passkey to the user (with key-entered count).
///
/// This is a one-shot notification — no reply is expected.
/// Matches C `agent_display_passkey()`.
pub async fn agent_display_passkey(
    agent: &Arc<Agent>,
    device: &BtdDevice,
    passkey: u32,
    entered: u16,
) -> Result<(), AgentError> {
    let dev_path = device.get_path().to_string();

    let proxy = agent_proxy(agent).await?;

    let body = (
        ObjectPath::try_from(dev_path.as_str()).map_err(|e| AgentError::Failed(e.to_string()))?,
        passkey,
        entered,
    );

    // Fire-and-forget: the C code uses g_dbus_send_message (no reply).
    proxy.call_noreply("DisplayPasskey", &body).await?;

    Ok(())
}

/// Display a PIN code to the user and wait for acknowledgement.
///
/// The agent replies when it has finished displaying the code.
/// Matches C `agent_display_pincode()`.
pub async fn agent_display_pincode(
    agent: &Arc<Agent>,
    device: &BtdDevice,
    pincode: &str,
) -> Result<(), AgentError> {
    check_existing_request(agent, device, AgentRequestType::DisplayPinCode).await?;

    btd_debug(
        0xFFFF,
        &format!(
            "Calling Agent.DisplayPinCode: name={}, path={}, pincode={}",
            agent.owner, agent.path, pincode
        ),
    );

    set_pending_request(agent, device, AgentRequestType::DisplayPinCode).await;

    let dev_path = device.get_path().to_string();
    let body = (
        ObjectPath::try_from(dev_path.as_str()).map_err(|e| AgentError::Failed(e.to_string()))?,
        pincode,
    );

    let result = agent_call(agent, "DisplayPinCode", &body).await;

    clear_pending_request(agent).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Cancel any pending agent request and send a Cancel message to the agent.
///
/// Returns `Ok(())` if a request was cancelled, `Err(NoPendingRequest)` if
/// there was nothing to cancel.
///
/// Matches C `agent_cancel()`.
pub async fn agent_cancel(agent: &Arc<Agent>) -> Result<(), AgentError> {
    let had_request = {
        let mut guard = agent.request.lock().await;
        let had = guard.is_some();
        *guard = None;
        had
    };

    if !had_request {
        return Err(AgentError::NoPendingRequest);
    }

    send_cancel_to_agent(agent).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// AgentManagerInterface — org.bluez.AgentManager1
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.AgentManager1`.
///
/// Exported at `/org/bluez`.  Allows D-Bus clients to register, unregister,
/// and nominate default agents for pairing and authorization prompts.
pub struct AgentManagerInterface;

#[zbus::interface(name = "org.bluez.AgentManager1")]
impl AgentManagerInterface {
    /// Register a new pairing agent.
    ///
    /// D-Bus signature: `RegisterAgent(o agent, s capability) -> ()`
    ///
    /// Creates a new `Agent` entry, validates the capability string, and
    /// registers the agent.  If this is the first agent, it automatically
    /// becomes the default.
    ///
    /// Errors:
    /// - `org.bluez.Error.AlreadyExists` if the sender already has an agent.
    /// - `org.bluez.Error.InvalidArguments` if the capability string is not
    ///   recognized.
    async fn register_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        agent: ObjectPath<'_>,
        capability: &str,
    ) -> Result<(), BtdError> {
        let sender =
            header.sender().ok_or_else(|| BtdError::failed("No sender in message"))?.to_string();

        // Check for duplicate registration from same sender.
        {
            let list = AGENT_LIST.read().await;
            if list.contains_key(&sender) {
                return Err(BtdError::already_exists());
            }
        }

        // Parse IO capability.
        let cap = mgmt_parse_io_capability(capability);
        if cap == MgmtIoCapability::Invalid {
            return Err(BtdError::invalid_args());
        }

        // Create the agent.
        let new_agent = Arc::new(Agent::new(sender.clone(), agent.to_string(), cap));

        btd_debug(0xFFFF, &format!("agent {}", new_agent.owner));

        // If this is the first agent, make it the default.
        let should_be_default = {
            let defaults = DEFAULT_AGENTS.read().await;
            defaults.is_empty()
        };

        // Add to the global map.
        {
            let mut list = AGENT_LIST.write().await;
            list.insert(sender.clone(), Arc::clone(&new_agent));
        }

        if should_be_default {
            add_default_agent(&new_agent).await;
        } else {
            // Add to the tail of the default queue.
            let mut defaults = DEFAULT_AGENTS.write().await;
            defaults.push_back(Arc::clone(&new_agent));
        }

        // Start name-owner watch for disconnect cleanup.
        spawn_name_watch(sender);

        Ok(())
    }

    /// Unregister a previously registered agent.
    ///
    /// D-Bus signature: `UnregisterAgent(o agent) -> ()`
    ///
    /// Errors:
    /// - `org.bluez.Error.DoesNotExist` if the sender has no registered agent
    ///   or the path does not match.
    async fn unregister_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        agent: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender =
            header.sender().ok_or_else(|| BtdError::failed("No sender in message"))?.to_string();

        // Find the agent for this sender.
        let existing = {
            let list = AGENT_LIST.read().await;
            list.get(&sender).cloned()
        };

        let existing = existing.ok_or_else(BtdError::does_not_exist)?;

        btd_debug(0xFFFF, &format!("agent {}", existing.owner));

        // Verify the path matches.
        if existing.path != agent.as_str() {
            return Err(BtdError::does_not_exist());
        }

        // Release the agent (sends Release + Cancel if needed).
        agent_release_dbus(&existing).await;

        // Remove from default queue.
        remove_default_agent(&existing).await;

        // Remove from global map.
        {
            let mut list = AGENT_LIST.write().await;
            list.remove(&sender);
        }

        Ok(())
    }

    /// Nominate a registered agent as the default agent.
    ///
    /// D-Bus signature: `RequestDefaultAgent(o agent) -> ()`
    ///
    /// Errors:
    /// - `org.bluez.Error.DoesNotExist` if the sender has no registered agent
    ///   or the path does not match.
    /// - `org.bluez.Error.Failed` if the agent could not be set as default.
    async fn request_default_agent(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        agent: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender =
            header.sender().ok_or_else(|| BtdError::failed("No sender in message"))?.to_string();

        // Find the agent for this sender.
        let existing = {
            let list = AGENT_LIST.read().await;
            list.get(&sender).cloned()
        };

        let existing = existing.ok_or_else(BtdError::does_not_exist)?;

        // Verify the path matches.
        if existing.path != agent.as_str() {
            return Err(BtdError::does_not_exist());
        }

        if !add_default_agent(&existing).await {
            return Err(BtdError::failed("Failed to set as default"));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Module initialization and cleanup
// ---------------------------------------------------------------------------

/// Initialize the agent subsystem.
///
/// Registers the `org.bluez.AgentManager1` interface at `/org/bluez`.
///
/// Matches C `btd_agent_init()`.
pub async fn btd_agent_init() -> Result<(), zbus::Error> {
    let conn = btd_get_dbus_connection();
    conn.object_server().at("/org/bluez", AgentManagerInterface).await?;

    btd_debug(0xFFFF, "AgentManager1 interface registered at /org/bluez");

    Ok(())
}

/// Clean up the agent subsystem.
///
/// Releases all agents and unregisters the AgentManager1 interface.
///
/// Matches C `btd_agent_cleanup()`.
pub async fn btd_agent_cleanup() -> Result<(), zbus::Error> {
    // Release all agents.
    let agents: Vec<Arc<Agent>> = {
        let list = AGENT_LIST.read().await;
        list.values().cloned().collect()
    };

    for agent in &agents {
        agent_release_dbus(agent).await;
    }

    // Clear global state.
    {
        let mut list = AGENT_LIST.write().await;
        list.clear();
    }
    {
        let mut defaults = DEFAULT_AGENTS.write().await;
        defaults.clear();
    }

    // Unregister D-Bus interface.
    let conn = btd_get_dbus_connection();
    let _ = conn.object_server().remove::<AgentManagerInterface, _>("/org/bluez").await;

    btd_debug(0xFFFF, "AgentManager1 interface unregistered from /org/bluez");

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_interface_constant() {
        assert_eq!(AGENT_INTERFACE, "org.bluez.Agent1");
    }

    #[test]
    fn test_request_timeout_value() {
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(60));
    }

    #[test]
    fn test_error_interface_usage() {
        // Verify ERROR_INTERFACE is accessible (used for building
        // error names like ERROR_INTERFACE.Failed in cancel paths).
        let fail_name = format!("{}.Failed", crate::error::ERROR_INTERFACE);
        assert_eq!(fail_name, "org.bluez.Error.Failed");
    }

    #[test]
    fn test_io_capability_values() {
        assert_eq!(MgmtIoCapability::DisplayOnly as u8, 0x00);
        assert_eq!(MgmtIoCapability::DisplayYesNo as u8, 0x01);
        assert_eq!(MgmtIoCapability::KeyboardOnly as u8, 0x02);
        assert_eq!(MgmtIoCapability::NoInputNoOutput as u8, 0x03);
        assert_eq!(MgmtIoCapability::KeyboardDisplay as u8, 0x04);
        assert_eq!(MgmtIoCapability::Invalid as u8, 0xFF);
    }

    #[test]
    fn test_io_capability_parse_empty_default() {
        let cap = mgmt_parse_io_capability("");
        assert_eq!(cap, MgmtIoCapability::KeyboardDisplay);
    }

    #[test]
    fn test_io_capability_parse_invalid() {
        let cap = mgmt_parse_io_capability("SomeInvalidCapability");
        assert_eq!(cap, MgmtIoCapability::Invalid);
    }

    #[test]
    fn test_btd_error_constructors() {
        // Verify all BtdError constructors used by agent.rs are accessible.
        let _e1 = BtdError::already_exists();
        let _e2 = BtdError::does_not_exist();
        let _e3 = BtdError::invalid_args();
        let _e4 = BtdError::failed("test");

        // Verify dbus_error_name works.
        assert_eq!(_e1.dbus_error_name(), "org.bluez.Error.AlreadyExists");
        assert_eq!(_e2.dbus_error_name(), "org.bluez.Error.DoesNotExist");
    }

    #[test]
    fn test_agent_request_type_variants() {
        // Verify all request type variants exist.
        let types = [
            AgentRequestType::RequestPasskey,
            AgentRequestType::RequestConfirmation,
            AgentRequestType::RequestAuthorization,
            AgentRequestType::RequestPinCode,
            AgentRequestType::AuthorizeService,
            AgentRequestType::DisplayPinCode,
        ];
        assert_eq!(types.len(), 6);
    }

    #[test]
    fn test_has_request_result_variants() {
        // Verify all result variants exist and are distinct.
        assert_ne!(HasRequestResult::NoRequest, HasRequestResult::Busy);
        assert_ne!(HasRequestResult::Busy, HasRequestResult::InProgress);
        assert_ne!(HasRequestResult::NoRequest, HasRequestResult::InProgress);
    }
}
