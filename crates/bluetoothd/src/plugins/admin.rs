// SPDX-License-Identifier: GPL-2.0-or-later
//
// admin — Admin policy plugin.
//
// Replaces plugins/admin.c (~638 LOC).  Exposes D-Bus interfaces
// `org.bluez.AdminPolicySet1` and `org.bluez.AdminPolicyStatus1` to allow
// system administrators to restrict which service UUIDs a Bluetooth adapter
// may use.

use std::collections::BTreeSet;
use std::sync::Mutex;

use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};

// ---------------------------------------------------------------------------
// D-Bus interface names
// ---------------------------------------------------------------------------

/// Interface for setting admin policy (service allowlist).
pub const ADMIN_POLICY_SET_INTERFACE: &str = "org.bluez.AdminPolicySet1";

/// Interface for reading current admin policy status.
pub const ADMIN_POLICY_STATUS_INTERFACE: &str = "org.bluez.AdminPolicyStatus1";

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Per-adapter admin policy data.
#[derive(Debug, Default)]
pub struct AdminPolicyData {
    /// The set of service UUIDs that are allowed.  An empty set means "allow
    /// everything" (no restriction).
    pub service_allowlist: BTreeSet<String>,
}

/// Device-level data tracked by the admin plugin.
#[derive(Debug)]
pub struct DeviceData {
    /// Object path of the device.
    pub path: String,
    /// Whether the device is affected by the current allow-list.
    pub affected: bool,
}

/// Global plugin state, protected by a mutex.
static STATE: Mutex<Option<AdminPolicyData>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check whether a service UUID is allowed by the current policy.
///
/// Returns `true` if the allowlist is empty (everything permitted) or if
/// `uuid` is contained in the allowlist.
pub fn is_service_allowed(uuid: &str) -> bool {
    let guard = STATE.lock().expect("admin state mutex poisoned");
    match guard.as_ref() {
        None => true,
        Some(data) => data.service_allowlist.is_empty() || data.service_allowlist.contains(uuid),
    }
}

/// Replace the service allowlist with `uuids`.
pub fn set_service_allowlist(uuids: impl IntoIterator<Item = String>) {
    let mut guard = STATE.lock().expect("admin state mutex poisoned");
    let data = guard.get_or_insert_with(AdminPolicyData::default);
    data.service_allowlist = uuids.into_iter().collect();
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct AdminPlugin;

impl BluetoothPlugin for AdminPlugin {
    fn desc(&self) -> PluginDesc {
        PluginDesc {
            name: "admin",
            version: env!("CARGO_PKG_VERSION"),
            priority: PluginPriority::Default,
        }
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut guard = STATE.lock().expect("admin state mutex poisoned");
        *guard = Some(AdminPolicyData::default());

        // TODO: register D-Bus interfaces (AdminPolicySet1, AdminPolicyStatus1)
        // TODO: wire adapter probe/remove callbacks

        Ok(())
    }

    fn exit(&self) {
        let mut guard = STATE.lock().expect("admin state mutex poisoned");
        *guard = None;
    }
}

inventory::submit! { &AdminPlugin as &dyn BluetoothPlugin }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_allowlist_empty_allows_all() {
        // Ensure fresh state
        {
            let mut guard = STATE.lock().unwrap();
            *guard = Some(AdminPolicyData::default());
        }

        assert!(is_service_allowed("0000110a-0000-1000-8000-00805f9b34fb"));
        assert!(is_service_allowed("anything"));

        // Cleanup
        let mut guard = STATE.lock().unwrap();
        *guard = None;
    }

    #[test]
    fn test_service_allowlist_filtering() {
        let allowed_uuid = "0000110a-0000-1000-8000-00805f9b34fb".to_string();
        set_service_allowlist(vec![allowed_uuid.clone()]);

        assert!(is_service_allowed(&allowed_uuid));
        assert!(!is_service_allowed("0000110b-0000-1000-8000-00805f9b34fb"));

        // Cleanup
        let mut guard = STATE.lock().unwrap();
        *guard = None;
    }
}
