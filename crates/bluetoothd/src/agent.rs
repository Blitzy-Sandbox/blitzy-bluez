// SPDX-License-Identifier: GPL-2.0-or-later
//
// D-Bus pairing agent management replacing src/agent.c (1,061 LOC).
// Manages registration of pairing agents and selection of the default agent
// used for authorization and passkey display/input during pairing.

use crate::error::BtdError;

/// I/O capability of a pairing agent, as defined by the Bluetooth Core Spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoCapability {
    DisplayOnly,
    DisplayYesNo,
    KeyboardOnly,
    NoInputNoOutput,
    KeyboardDisplay,
}

impl IoCapability {
    /// Returns the D-Bus string representation of this capability.
    pub fn as_str(&self) -> &'static str {
        match self {
            IoCapability::DisplayOnly => "DisplayOnly",
            IoCapability::DisplayYesNo => "DisplayYesNo",
            IoCapability::KeyboardOnly => "KeyboardOnly",
            IoCapability::NoInputNoOutput => "NoInputNoOutput",
            IoCapability::KeyboardDisplay => "KeyboardDisplay",
        }
    }
}

/// Information about a registered pairing agent.
#[derive(Debug, Clone)]
pub struct AgentInfo {
    /// D-Bus object path of the agent.
    pub path: String,
    /// D-Bus unique name of the agent's owner.
    pub owner: String,
    /// I/O capability reported by the agent.
    pub capability: IoCapability,
}

/// Manages registered D-Bus pairing agents.
#[derive(Debug)]
pub struct AgentManager {
    default_agent: Option<AgentInfo>,
    agents: Vec<AgentInfo>,
}

impl AgentManager {
    /// Creates a new, empty agent manager.
    pub fn new() -> Self {
        Self {
            default_agent: None,
            agents: Vec::new(),
        }
    }

    /// Registers a new pairing agent.
    ///
    /// Returns an error if an agent with the same path and owner is already
    /// registered.
    pub fn register_agent(
        &mut self,
        path: String,
        owner: String,
        capability: IoCapability,
    ) -> Result<(), BtdError> {
        if self
            .agents
            .iter()
            .any(|a| a.path == path && a.owner == owner)
        {
            return Err(BtdError::new(
                crate::error::ERROR_ALREADY_EXISTS,
                "Agent already registered",
            ));
        }

        self.agents.push(AgentInfo {
            path,
            owner,
            capability,
        });
        Ok(())
    }

    /// Removes a previously registered agent.
    ///
    /// If the removed agent was the default, the default is cleared.
    pub fn unregister_agent(&mut self, path: &str, owner: &str) -> Result<(), BtdError> {
        let idx = self
            .agents
            .iter()
            .position(|a| a.path == path && a.owner == owner)
            .ok_or_else(|| {
                BtdError::new(
                    crate::error::ERROR_DOES_NOT_EXIST,
                    "Agent not registered",
                )
            })?;

        self.agents.remove(idx);

        // Clear default if it pointed to the removed agent.
        if let Some(ref def) = self.default_agent {
            if def.path == path && def.owner == owner {
                self.default_agent = None;
            }
        }

        Ok(())
    }

    /// Marks an already-registered agent as the default.
    pub fn request_default(&mut self, path: &str, owner: &str) -> Result<(), BtdError> {
        let agent = self
            .agents
            .iter()
            .find(|a| a.path == path && a.owner == owner)
            .ok_or_else(|| {
                BtdError::new(
                    crate::error::ERROR_DOES_NOT_EXIST,
                    "Agent not registered",
                )
            })?
            .clone();

        self.default_agent = Some(agent);
        Ok(())
    }

    /// Returns the current default agent, if one is set.
    pub fn get_default(&self) -> Option<&AgentInfo> {
        self.default_agent.as_ref()
    }
}

impl Default for AgentManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_register() {
        let mut mgr = AgentManager::new();
        assert!(mgr
            .register_agent(
                "/test/agent".into(),
                ":1.1".into(),
                IoCapability::DisplayYesNo,
            )
            .is_ok());

        // Duplicate registration must fail.
        assert!(mgr
            .register_agent(
                "/test/agent".into(),
                ":1.1".into(),
                IoCapability::DisplayYesNo,
            )
            .is_err());

        // Same path, different owner is fine.
        assert!(mgr
            .register_agent(
                "/test/agent".into(),
                ":1.2".into(),
                IoCapability::KeyboardOnly,
            )
            .is_ok());
    }

    #[test]
    fn test_agent_default() {
        let mut mgr = AgentManager::new();
        mgr.register_agent(
            "/test/agent".into(),
            ":1.1".into(),
            IoCapability::DisplayYesNo,
        )
        .unwrap();

        assert!(mgr.get_default().is_none());

        mgr.request_default("/test/agent", ":1.1").unwrap();
        let def = mgr.get_default().unwrap();
        assert_eq!(def.path, "/test/agent");
        assert_eq!(def.owner, ":1.1");

        // Unregistering the default agent clears the default.
        mgr.unregister_agent("/test/agent", ":1.1").unwrap();
        assert!(mgr.get_default().is_none());
    }

    #[test]
    fn test_io_capability_str() {
        assert_eq!(IoCapability::DisplayOnly.as_str(), "DisplayOnly");
        assert_eq!(IoCapability::DisplayYesNo.as_str(), "DisplayYesNo");
        assert_eq!(IoCapability::KeyboardOnly.as_str(), "KeyboardOnly");
        assert_eq!(IoCapability::NoInputNoOutput.as_str(), "NoInputNoOutput");
        assert_eq!(IoCapability::KeyboardDisplay.as_str(), "KeyboardDisplay");
    }
}
