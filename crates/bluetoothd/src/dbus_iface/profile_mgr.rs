// SPDX-License-Identifier: GPL-2.0-or-later
//
// org.bluez.ProfileManager1 D-Bus interface implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zbus::fdo;
use zbus::zvariant::{ObjectPath, OwnedValue};

use crate::profile::{ProfileEntry, ProfileManager};

/// D-Bus interface object for org.bluez.ProfileManager1.
pub struct ProfileManager1Iface {
    manager: Arc<Mutex<ProfileManager>>,
}

impl ProfileManager1Iface {
    /// Create a new interface wrapping the given profile manager.
    pub fn new(manager: Arc<Mutex<ProfileManager>>) -> Self {
        Self { manager }
    }
}

/// Helper to extract a string value from D-Bus variant options.
fn opt_string(options: &HashMap<String, OwnedValue>, key: &str) -> String {
    options
        .get(key)
        .and_then(|v| v.downcast_ref::<&str>().ok())
        .unwrap_or("")
        .to_string()
}

/// Helper to extract a u16 value from D-Bus variant options.
fn opt_u16(options: &HashMap<String, OwnedValue>, key: &str) -> Option<u16> {
    options
        .get(key)
        .and_then(|v| v.downcast_ref::<u16>().ok())
}

/// Helper to extract a bool value from D-Bus variant options.
fn opt_bool(options: &HashMap<String, OwnedValue>, key: &str, default: bool) -> bool {
    options
        .get(key)
        .and_then(|v| v.downcast_ref::<bool>().ok())
        .unwrap_or(default)
}

#[zbus::interface(name = "org.bluez.ProfileManager1")]
impl ProfileManager1Iface {
    /// Register a Bluetooth profile.
    async fn register_profile(
        &self,
        profile: ObjectPath<'_>,
        uuid: String,
        options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<()> {
        let entry = ProfileEntry {
            uuid,
            path: profile.to_string(),
            name: opt_string(&options, "Name"),
            channel: opt_u16(&options, "Channel"),
            psm: opt_u16(&options, "PSM"),
            auto_connect: opt_bool(&options, "AutoConnect", false),
        };

        let mut mgr = self.manager.lock().unwrap();
        mgr.register_profile(entry)
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }

    /// Unregister a previously registered profile.
    async fn unregister_profile(&self, profile: ObjectPath<'_>) -> fdo::Result<()> {
        let mut mgr = self.manager.lock().unwrap();
        mgr.unregister_profile(profile.as_str())
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_manager1_creation() {
        let mgr = Arc::new(Mutex::new(ProfileManager::new()));
        let iface = ProfileManager1Iface::new(mgr);
        assert!(iface.manager.lock().unwrap().find_by_uuid("any").is_none());
    }
}
