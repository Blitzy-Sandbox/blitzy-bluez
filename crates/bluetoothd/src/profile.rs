// SPDX-License-Identifier: GPL-2.0-or-later
//
// Profile registration and UUID dispatch replacing src/profile.c (2,742 LOC).
// Manages Bluetooth profile objects registered over D-Bus and provides lookup
// by UUID so the daemon can route incoming connections to the right profile.

use bluez_shared::BdAddr;

use crate::error::BtdError;

/// A Bluetooth profile that can handle connections.
///
/// Implementors are registered with the daemon and receive connect/disconnect
/// callbacks when a remote device establishes or tears down a profile session.
pub trait BtdProfile: Send + Sync + 'static {
    /// Human-readable name of the profile.
    fn name(&self) -> &str;

    /// Called when a remote device connects to this profile (stub).
    fn connect(&self, _addr: &BdAddr) {}

    /// Called when a remote device disconnects from this profile (stub).
    fn disconnect(&self, _addr: &BdAddr) {}
}

/// A registered profile entry.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    /// UUID of the profile service record.
    pub uuid: String,
    /// D-Bus object path of the profile.
    pub path: String,
    /// Human-readable profile name.
    pub name: String,
    /// RFCOMM channel number, if applicable.
    pub channel: Option<u16>,
    /// L2CAP PSM, if applicable.
    pub psm: Option<u16>,
    /// Whether this profile should auto-connect on device discovery.
    pub auto_connect: bool,
}

/// Manages registered Bluetooth profiles.
#[derive(Debug)]
pub struct ProfileManager {
    registered: Vec<ProfileEntry>,
}

impl ProfileManager {
    /// Creates a new, empty profile manager.
    pub fn new() -> Self {
        Self {
            registered: Vec::new(),
        }
    }

    /// Registers a profile.
    ///
    /// Returns an error if a profile with the same path is already registered.
    pub fn register_profile(&mut self, entry: ProfileEntry) -> Result<(), BtdError> {
        if self.registered.iter().any(|e| e.path == entry.path) {
            return Err(BtdError::new(
                crate::error::ERROR_ALREADY_EXISTS,
                "Profile already registered",
            ));
        }

        self.registered.push(entry);
        Ok(())
    }

    /// Removes a previously registered profile by path.
    pub fn unregister_profile(&mut self, path: &str) -> Result<(), BtdError> {
        let idx = self
            .registered
            .iter()
            .position(|e| e.path == path)
            .ok_or_else(|| {
                BtdError::new(
                    crate::error::ERROR_DOES_NOT_EXIST,
                    "Profile not registered",
                )
            })?;

        self.registered.remove(idx);
        Ok(())
    }

    /// Finds a registered profile by UUID.
    pub fn find_by_uuid(&self, uuid: &str) -> Option<&ProfileEntry> {
        self.registered.iter().find(|e| e.uuid == uuid)
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(path: &str, uuid: &str) -> ProfileEntry {
        ProfileEntry {
            uuid: uuid.into(),
            path: path.into(),
            name: "Test Profile".into(),
            channel: Some(1),
            psm: None,
            auto_connect: true,
        }
    }

    fn entry_with_priority(path: &str, uuid: &str, psm: Option<u16>) -> ProfileEntry {
        ProfileEntry {
            uuid: uuid.into(),
            path: path.into(),
            name: format!("Profile {}", path),
            channel: None,
            psm,
            auto_connect: false,
        }
    }

    // ---- Register (from test-profile.c) ----

    #[test]
    fn test_profile_register() {
        let mut mgr = ProfileManager::new();
        assert!(mgr
            .register_profile(sample_entry("/test/profile", "0000110a-0000-1000-8000-00805f9b34fb"))
            .is_ok());

        // Duplicate path must fail
        assert!(mgr
            .register_profile(sample_entry("/test/profile", "0000110b-0000-1000-8000-00805f9b34fb"))
            .is_err());
    }

    // ---- Find by UUID (from test-profile.c) ----

    #[test]
    fn test_profile_find_by_uuid() {
        let mut mgr = ProfileManager::new();
        mgr.register_profile(sample_entry("/test/a2dp", "0000110a-0000-1000-8000-00805f9b34fb"))
            .unwrap();
        mgr.register_profile(sample_entry("/test/hfp", "0000111e-0000-1000-8000-00805f9b34fb"))
            .unwrap();

        let entry = mgr
            .find_by_uuid("0000110a-0000-1000-8000-00805f9b34fb")
            .unwrap();
        assert_eq!(entry.path, "/test/a2dp");

        assert!(mgr.find_by_uuid("nonexistent").is_none());
    }

    // ---- Unregister (from test-profile.c) ----

    #[test]
    fn test_profile_unregister() {
        let mut mgr = ProfileManager::new();
        mgr.register_profile(sample_entry("/test/profile", "0000110a-0000-1000-8000-00805f9b34fb"))
            .unwrap();

        assert!(mgr.unregister_profile("/test/profile").is_ok());
        assert!(mgr
            .find_by_uuid("0000110a-0000-1000-8000-00805f9b34fb")
            .is_none());

        // Double-unregister must fail
        assert!(mgr.unregister_profile("/test/profile").is_err());
    }

    // ---- Multiple profiles with different UUIDs (from test-profile.c sort tests) ----

    #[test]
    fn test_profile_multiple_register() {
        let mut mgr = ProfileManager::new();
        for i in 0..6 {
            mgr.register_profile(entry_with_priority(
                &format!("/test/profile/{}", i),
                &format!("0000{:04x}-0000-1000-8000-00805f9b34fb", 0x1100 + i),
                Some(i as u16 + 1),
            ))
            .unwrap();
        }

        // All 6 should be registered
        for i in 0..6 {
            let uuid = format!("0000{:04x}-0000-1000-8000-00805f9b34fb", 0x1100 + i);
            assert!(mgr.find_by_uuid(&uuid).is_some());
        }
    }

    // ---- Same UUID, different paths ----

    #[test]
    fn test_profile_same_uuid_different_paths() {
        let mut mgr = ProfileManager::new();
        let uuid = "0000110a-0000-1000-8000-00805f9b34fb";
        mgr.register_profile(sample_entry("/test/a", uuid)).unwrap();
        mgr.register_profile(sample_entry("/test/b", uuid)).unwrap();
        // find_by_uuid returns the first match
        let entry = mgr.find_by_uuid(uuid).unwrap();
        assert_eq!(entry.path, "/test/a");
    }

    // ---- Unregister then re-register ----

    #[test]
    fn test_profile_unregister_reregister() {
        let mut mgr = ProfileManager::new();
        let uuid = "0000110a-0000-1000-8000-00805f9b34fb";
        mgr.register_profile(sample_entry("/test/profile", uuid))
            .unwrap();
        mgr.unregister_profile("/test/profile").unwrap();
        // Should be able to re-register the same path
        assert!(mgr
            .register_profile(sample_entry("/test/profile", uuid))
            .is_ok());
    }

    // ---- Auto-connect flag ----

    #[test]
    fn test_profile_auto_connect() {
        let mut mgr = ProfileManager::new();
        let entry = ProfileEntry {
            uuid: "test-uuid".into(),
            path: "/test/ac".into(),
            name: "AC".into(),
            channel: None,
            psm: None,
            auto_connect: true,
        };
        mgr.register_profile(entry).unwrap();
        let found = mgr.find_by_uuid("test-uuid").unwrap();
        assert!(found.auto_connect);
    }

    // ---- Default construction ----

    #[test]
    fn test_profile_manager_default() {
        let mgr = ProfileManager::default();
        assert!(mgr.find_by_uuid("anything").is_none());
    }
}
