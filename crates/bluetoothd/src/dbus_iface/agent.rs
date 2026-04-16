// SPDX-License-Identifier: GPL-2.0-or-later
//
// org.bluez.AgentManager1 and org.bluez.Agent1 D-Bus interface implementations.

use std::sync::{Arc, Mutex};

use zbus::fdo;
use zbus::zvariant::ObjectPath;

use crate::agent::AgentManager;
use crate::agent::IoCapability;

// ---------------------------------------------------------------------------
// org.bluez.AgentManager1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.AgentManager1.
///
/// Allows D-Bus clients to register and manage pairing agents.
pub struct AgentManager1Iface {
    manager: Arc<Mutex<AgentManager>>,
}

impl AgentManager1Iface {
    /// Create a new interface wrapping the given agent manager.
    pub fn new(manager: Arc<Mutex<AgentManager>>) -> Self {
        Self { manager }
    }
}

/// Parse a D-Bus capability string into an `IoCapability`.
fn parse_capability(cap: &str) -> fdo::Result<IoCapability> {
    match cap {
        "DisplayOnly" => Ok(IoCapability::DisplayOnly),
        "DisplayYesNo" => Ok(IoCapability::DisplayYesNo),
        "KeyboardOnly" => Ok(IoCapability::KeyboardOnly),
        "NoInputNoOutput" => Ok(IoCapability::NoInputNoOutput),
        "KeyboardDisplay" => Ok(IoCapability::KeyboardDisplay),
        "" => Ok(IoCapability::KeyboardDisplay), // default
        _ => Err(fdo::Error::InvalidArgs(format!(
            "Unknown capability: {}",
            cap
        ))),
    }
}

#[zbus::interface(name = "org.bluez.AgentManager1")]
impl AgentManager1Iface {
    /// Register a new pairing agent at the given object path.
    async fn register_agent(
        &self,
        agent: ObjectPath<'_>,
        capability: String,
    ) -> fdo::Result<()> {
        let cap = parse_capability(&capability)?;
        let mut mgr = self.manager.lock().unwrap();
        mgr.register_agent(agent.to_string(), String::new(), cap)
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }

    /// Unregister a previously registered agent.
    async fn unregister_agent(&self, agent: ObjectPath<'_>) -> fdo::Result<()> {
        let mut mgr = self.manager.lock().unwrap();
        mgr.unregister_agent(agent.as_str(), "")
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }

    /// Designate an already-registered agent as the default.
    async fn request_default_agent(&self, agent: ObjectPath<'_>) -> fdo::Result<()> {
        let mut mgr = self.manager.lock().unwrap();
        mgr.request_default(agent.as_str(), "")
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }
}

// ---------------------------------------------------------------------------
// org.bluez.Agent1 — interface definition for agent callbacks
// ---------------------------------------------------------------------------

/// D-Bus interface definition for org.bluez.Agent1.
///
/// This struct represents the agent-side callbacks that a pairing agent must
/// implement. In practice the daemon *calls* these methods on the agent's
/// D-Bus object; this definition is provided so that zbus can generate proxy
/// types for outgoing calls.
pub struct Agent1Iface;

#[zbus::interface(name = "org.bluez.Agent1")]
impl Agent1Iface {
    /// Called to release the agent (daemon is shutting down or agent was
    /// unregistered).
    async fn release(&self) -> fdo::Result<()> {
        Ok(())
    }

    /// Request a PIN code for legacy pairing.
    async fn request_pin_code(&self, _device: ObjectPath<'_>) -> fdo::Result<String> {
        Err(fdo::Error::Failed("Not implemented".into()))
    }

    /// Display a PIN code.
    async fn display_pin_code(
        &self,
        _device: ObjectPath<'_>,
        _pincode: String,
    ) -> fdo::Result<()> {
        Ok(())
    }

    /// Request a passkey for SSP pairing.
    async fn request_passkey(&self, _device: ObjectPath<'_>) -> fdo::Result<u32> {
        Err(fdo::Error::Failed("Not implemented".into()))
    }

    /// Display a passkey with progress indicator.
    async fn display_passkey(
        &self,
        _device: ObjectPath<'_>,
        _passkey: u32,
        _entered: u16,
    ) -> fdo::Result<()> {
        Ok(())
    }

    /// Request user confirmation of a passkey.
    async fn request_confirmation(
        &self,
        _device: ObjectPath<'_>,
        _passkey: u32,
    ) -> fdo::Result<()> {
        Err(fdo::Error::Failed("Not implemented".into()))
    }

    /// Request user authorization.
    async fn request_authorization(&self, _device: ObjectPath<'_>) -> fdo::Result<()> {
        Err(fdo::Error::Failed("Not implemented".into()))
    }

    /// Authorize a service connection.
    async fn authorize_service(
        &self,
        _device: ObjectPath<'_>,
        _uuid: String,
    ) -> fdo::Result<()> {
        Err(fdo::Error::Failed("Not implemented".into()))
    }

    /// Cancel the current agent request.
    async fn cancel(&self) -> fdo::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_manager1_creation() {
        let mgr = Arc::new(Mutex::new(AgentManager::new()));
        let iface = AgentManager1Iface::new(mgr);
        assert!(iface.manager.lock().unwrap().get_default().is_none());
    }

    #[test]
    fn test_parse_capability() {
        assert_eq!(
            parse_capability("DisplayOnly").unwrap(),
            IoCapability::DisplayOnly
        );
        assert_eq!(
            parse_capability("DisplayYesNo").unwrap(),
            IoCapability::DisplayYesNo
        );
        assert_eq!(
            parse_capability("KeyboardOnly").unwrap(),
            IoCapability::KeyboardOnly
        );
        assert_eq!(
            parse_capability("NoInputNoOutput").unwrap(),
            IoCapability::NoInputNoOutput
        );
        assert_eq!(
            parse_capability("KeyboardDisplay").unwrap(),
            IoCapability::KeyboardDisplay
        );
        // Empty defaults to KeyboardDisplay.
        assert_eq!(
            parse_capability("").unwrap(),
            IoCapability::KeyboardDisplay
        );
        // Unknown must fail.
        assert!(parse_capability("Invalid").is_err());
    }

    #[test]
    fn test_agent1_creation() {
        let _agent = Agent1Iface;
    }
}
