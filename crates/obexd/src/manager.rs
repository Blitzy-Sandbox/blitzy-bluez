// SPDX-License-Identifier: GPL-2.0-or-later
//! Session manager — replaces obexd/src/manager.c.
//!
//! Manages OBEX sessions and agent registrations. Exposes:
//! - org.bluez.obex.AgentManager1 (RegisterAgent, UnregisterAgent)
//! - org.bluez.obex.Client1 (CreateSession, RemoveSession)

use std::collections::HashMap;

/// A registered OBEX agent.
#[derive(Debug, Clone)]
pub struct ObexAgent {
    /// D-Bus object path of the agent.
    pub path: String,
    /// D-Bus sender (bus name) of the agent owner.
    pub owner: String,
}

/// Represents an active OBEX session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Unique session identifier.
    pub id: u64,
    /// D-Bus object path for this session.
    pub object_path: String,
    /// Remote device address.
    pub destination: String,
    /// OBEX target (e.g., "opp", "ftp", "pbap", "map").
    pub target: String,
}

/// Manages active sessions and agent registrations.
pub struct SessionManager {
    sessions: HashMap<u64, SessionInfo>,
    agents: Vec<ObexAgent>,
    next_id: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            agents: Vec::new(),
            next_id: 1,
        }
    }

    /// Register an OBEX agent. Returns `false` if already registered.
    pub fn register_agent(&mut self, path: String, owner: String) -> bool {
        if self.agents.iter().any(|a| a.path == path) {
            return false;
        }
        self.agents.push(ObexAgent { path, owner });
        true
    }

    /// Unregister an agent by path. Returns `false` if not found.
    pub fn unregister_agent(&mut self, path: &str) -> bool {
        let before = self.agents.len();
        self.agents.retain(|a| a.path != path);
        self.agents.len() < before
    }

    /// Create a new session. Returns the session info.
    pub fn create_session(&mut self, destination: String, target: String) -> SessionInfo {
        let id = self.next_id;
        self.next_id += 1;

        let object_path = format!("/org/bluez/obex/client/session{id}");
        let info = SessionInfo {
            id,
            object_path,
            destination,
            target,
        };
        self.sessions.insert(id, info.clone());
        info
    }

    /// Remove a session by ID. Returns `true` if found and removed.
    pub fn remove_session(&mut self, id: u64) -> bool {
        self.sessions.remove(&id).is_some()
    }

    /// Look up a session by ID.
    pub fn get_session(&self, id: u64) -> Option<&SessionInfo> {
        self.sessions.get(&id)
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Number of registered agents.
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_register_unregister() {
        let mut mgr = SessionManager::new();
        assert!(mgr.register_agent("/agent1".into(), ":1.0".into()));
        assert!(!mgr.register_agent("/agent1".into(), ":1.0".into())); // duplicate
        assert_eq!(mgr.agent_count(), 1);

        assert!(mgr.unregister_agent("/agent1"));
        assert!(!mgr.unregister_agent("/agent1")); // already gone
        assert_eq!(mgr.agent_count(), 0);
    }

    #[test]
    fn session_create_remove() {
        let mut mgr = SessionManager::new();
        let session = mgr.create_session("AA:BB:CC:DD:EE:FF".into(), "opp".into());
        assert_eq!(session.target, "opp");
        assert_eq!(mgr.session_count(), 1);

        assert!(mgr.get_session(session.id).is_some());
        assert!(mgr.remove_session(session.id));
        assert_eq!(mgr.session_count(), 0);
    }
}
