// SPDX-License-Identifier: GPL-2.0-or-later
//! Object Push Profile (OPP) — replaces obexd/plugins/opp.c.
//!
//! Implements the OBEX Object Push service for receiving and sending
//! files via simple push operations.

use crate::server::ObexService;

/// Decision for an incoming OPP transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OppAcceptPolicy {
    /// Accept all incoming files.
    AcceptAll,
    /// Reject all incoming files.
    RejectAll,
    /// Ask the registered agent for each file.
    AskAgent,
}

/// Object Push Profile service.
pub struct OppService {
    /// Policy for incoming files.
    pub accept_policy: OppAcceptPolicy,
    /// Root directory for saving received files.
    pub root_dir: String,
}

impl OppService {
    pub fn new(root_dir: String) -> Self {
        Self {
            accept_policy: OppAcceptPolicy::AskAgent,
            root_dir,
        }
    }

    /// Check whether an incoming file should be accepted based on current policy.
    pub fn should_accept(&self, _filename: &str, _size: u64) -> bool {
        match self.accept_policy {
            OppAcceptPolicy::AcceptAll => true,
            OppAcceptPolicy::RejectAll => false,
            OppAcceptPolicy::AskAgent => {
                // TODO: query the registered agent via D-Bus
                true
            }
        }
    }

    /// Compute the full path for saving a received file.
    pub fn save_path(&self, filename: &str) -> String {
        format!("{}/{}", self.root_dir, filename)
    }
}

impl ObexService for OppService {
    fn name(&self) -> &str {
        "Object Push"
    }

    fn target(&self) -> Option<&[u8]> {
        // OPP has no target UUID — it is the default service
        None
    }

    fn handle_connection(&self, _session_id: u64) {
        // TODO: handle incoming OPP connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opp_accept_policy() {
        let mut opp = OppService::new("/tmp/opp".into());
        opp.accept_policy = OppAcceptPolicy::AcceptAll;
        assert!(opp.should_accept("photo.jpg", 1024));

        opp.accept_policy = OppAcceptPolicy::RejectAll;
        assert!(!opp.should_accept("photo.jpg", 1024));

        assert_eq!(opp.save_path("photo.jpg"), "/tmp/opp/photo.jpg");
        assert_eq!(opp.name(), "Object Push");
        assert!(opp.target().is_none());
    }
}
