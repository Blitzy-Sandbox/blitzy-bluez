// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Pairing agent implementation

use zbus::fdo;

/// Agent capability mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCapability {
    DisplayOnly,
    DisplayYesNo,
    KeyboardOnly,
    NoInputNoOutput,
    KeyboardDisplay,
}

impl AgentCapability {
    /// D-Bus string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DisplayOnly => "DisplayOnly",
            Self::DisplayYesNo => "DisplayYesNo",
            Self::KeyboardOnly => "KeyboardOnly",
            Self::NoInputNoOutput => "NoInputNoOutput",
            Self::KeyboardDisplay => "KeyboardDisplay",
        }
    }
}

/// Whether to auto-accept or prompt interactively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentMode {
    /// Automatically accept all pairing requests.
    Auto,
    /// Prompt the user for each pairing decision.
    Interactive,
}

/// The pairing agent, registered on D-Bus as an org.bluez.Agent1 object.
pub struct Agent {
    mode: AgentMode,
    capability: AgentCapability,
}

impl Agent {
    /// Create a new agent with the given mode and capability.
    pub fn new(mode: AgentMode, capability: AgentCapability) -> Self {
        Self { mode, capability }
    }

    /// Default auto-accept agent.
    pub fn default_auto() -> Self {
        Self::new(AgentMode::Auto, AgentCapability::KeyboardDisplay)
    }

    /// The capability string for D-Bus registration.
    pub fn capability_str(&self) -> &'static str {
        self.capability.as_str()
    }

    /// The D-Bus object path where this agent is registered.
    pub fn object_path() -> &'static str {
        "/org/bluez/agent"
    }
}

/// D-Bus interface implementation for org.bluez.Agent1.
#[zbus::interface(name = "org.bluez.Agent1")]
impl Agent {
    /// Called when the daemon needs a PIN code for pairing.
    async fn request_pin_code(&self, _device: zbus::zvariant::ObjectPath<'_>) -> fdo::Result<String> {
        match self.mode {
            AgentMode::Auto => Ok("0000".to_string()),
            AgentMode::Interactive => {
                // In a full implementation this would prompt via the shell.
                Ok("0000".to_string())
            }
        }
    }

    /// Display a PIN code (informational, no return value expected).
    async fn display_pin_code(
        &self,
        _device: zbus::zvariant::ObjectPath<'_>,
        pincode: &str,
    ) -> fdo::Result<()> {
        println!("PIN code: {pincode}");
        Ok(())
    }

    /// Request a 6-digit numeric passkey.
    async fn request_passkey(&self, _device: zbus::zvariant::ObjectPath<'_>) -> fdo::Result<u32> {
        match self.mode {
            AgentMode::Auto => Ok(0),
            AgentMode::Interactive => Ok(0),
        }
    }

    /// Display a passkey during pairing.
    async fn display_passkey(
        &self,
        _device: zbus::zvariant::ObjectPath<'_>,
        passkey: u32,
        _entered: u16,
    ) -> fdo::Result<()> {
        println!("Passkey: {passkey:06}");
        Ok(())
    }

    /// Request confirmation for a passkey.
    async fn request_confirmation(
        &self,
        _device: zbus::zvariant::ObjectPath<'_>,
        passkey: u32,
    ) -> fdo::Result<()> {
        match self.mode {
            AgentMode::Auto => {
                println!("Auto-confirming passkey: {passkey:06}");
                Ok(())
            }
            AgentMode::Interactive => {
                println!("Confirm passkey {passkey:06}? (auto-accepted)");
                Ok(())
            }
        }
    }

    /// Request authorization for a device.
    async fn request_authorization(
        &self,
        _device: zbus::zvariant::ObjectPath<'_>,
    ) -> fdo::Result<()> {
        match self.mode {
            AgentMode::Auto => Ok(()),
            AgentMode::Interactive => Ok(()),
        }
    }

    /// Authorize a specific service UUID.
    async fn authorize_service(
        &self,
        _device: zbus::zvariant::ObjectPath<'_>,
        _uuid: &str,
    ) -> fdo::Result<()> {
        Ok(())
    }

    /// Cancel a pending agent request.
    async fn cancel(&self) -> fdo::Result<()> {
        println!("Agent request cancelled");
        Ok(())
    }

    /// Called when the agent is unregistered.
    async fn release(&self) -> fdo::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_agent() {
        let agent = Agent::default_auto();
        assert_eq!(agent.mode, AgentMode::Auto);
        assert_eq!(agent.capability_str(), "KeyboardDisplay");
    }

    #[test]
    fn test_agent_object_path() {
        assert_eq!(Agent::object_path(), "/org/bluez/agent");
    }
}
