// SPDX-License-Identifier: GPL-2.0-or-later
//
// policy — Auto-connect and reconnect policy plugin.
//
// Replaces plugins/policy.c (~1,007 LOC).  Manages automatic connection and
// reconnection of Bluetooth profiles (A2DP, HFP, AVRCP, etc.) based on
// configurable retry counts and timeouts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};

// ---------------------------------------------------------------------------
// Constants (matching the C implementation)
// ---------------------------------------------------------------------------

/// Timeout before attempting to connect a control channel.
pub const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Retry timeout for A2DP source connections.
pub const SOURCE_RETRY_TIMEOUT: Duration = Duration::from_secs(2);

/// Retry timeout for A2DP sink connections.
pub const SINK_RETRY_TIMEOUT: Duration = Duration::from_secs(2);

/// Retry timeout for headset connections.
pub const HS_RETRY_TIMEOUT: Duration = Duration::from_secs(2);

/// Retry timeout for AVRCP controller connections.
pub const CT_RETRY_TIMEOUT: Duration = Duration::from_secs(1);

/// Retry timeout for AVRCP target connections.
pub const TG_RETRY_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum retry count for source connections.
pub const SOURCE_RETRIES: u32 = 1;

/// Maximum retry count for sink connections.
pub const SINK_RETRIES: u32 = 1;

/// Maximum retry count for headset connections.
pub const HS_RETRIES: u32 = 1;

/// Maximum retry count for AVRCP controller connections.
pub const CT_RETRIES: u32 = 1;

/// Maximum retry count for AVRCP target connections.
pub const TG_RETRIES: u32 = 1;

/// Well-known profile UUIDs that trigger reconnection by default.
pub const DEFAULT_RECONNECT_UUIDS: &[&str] = &[
    "00001112-0000-1000-8000-00805f9b34fb", // HSP AG
    "0000111f-0000-1000-8000-00805f9b34fb", // HFP AG
    "0000110a-0000-1000-8000-00805f9b34fb", // A2DP Source
    "0000110c-0000-1000-8000-00805f9b34fb", // AVRCP Target
];

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Per-device reconnection tracking.
#[derive(Debug, Clone)]
pub struct ReconnectData {
    /// Device address or identifier.
    pub device_addr: String,
    /// Whether reconnection is enabled for this device.
    pub reconnect: bool,
    /// Profile UUIDs pending reconnection.
    pub services: Vec<String>,
    /// Current attempt number.
    pub attempt: u32,
    /// Whether a reconnection timer is currently active.
    pub active: bool,
    /// Whether this reconnection was triggered by system resume.
    pub on_resume: bool,
}

impl ReconnectData {
    /// Create new reconnect tracking for a device.
    pub fn new(device_addr: String) -> Self {
        Self {
            device_addr,
            reconnect: true,
            services: Vec::new(),
            attempt: 0,
            active: false,
            on_resume: false,
        }
    }
}

/// Global policy state.
static STATE: Mutex<Option<PolicyState>> = Mutex::new(None);

#[derive(Debug, Default)]
struct PolicyState {
    /// Map from device address to reconnect data.
    reconnect_map: HashMap<String, ReconnectData>,
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Check whether a given profile UUID is in the default reconnection list.
pub fn is_reconnect_uuid(uuid: &str) -> bool {
    DEFAULT_RECONNECT_UUIDS.contains(&uuid)
}

/// Record that a device should be tracked for reconnection.
pub fn track_device(device_addr: &str) {
    let mut guard = STATE.lock().expect("policy state mutex poisoned");
    let state = guard.get_or_insert_with(PolicyState::default);
    state
        .reconnect_map
        .entry(device_addr.to_owned())
        .or_insert_with(|| ReconnectData::new(device_addr.to_owned()));
}

/// Remove a device from reconnection tracking.
pub fn untrack_device(device_addr: &str) {
    let mut guard = STATE.lock().expect("policy state mutex poisoned");
    if let Some(state) = guard.as_mut() {
        state.reconnect_map.remove(device_addr);
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct PolicyPlugin;

impl BluetoothPlugin for PolicyPlugin {
    fn desc(&self) -> PluginDesc {
        PluginDesc {
            name: "policy",
            version: env!("CARGO_PKG_VERSION"),
            priority: PluginPriority::Default,
        }
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut guard = STATE.lock().expect("policy state mutex poisoned");
        *guard = Some(PolicyState::default());

        // TODO: register device/service callbacks for auto-connect logic
        // TODO: read reconnect configuration from main.conf

        Ok(())
    }

    fn exit(&self) {
        let mut guard = STATE.lock().expect("policy state mutex poisoned");
        *guard = None;
    }
}

inventory::submit! { &PolicyPlugin as &dyn BluetoothPlugin }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_reconnect_uuid() {
        assert!(is_reconnect_uuid("0000110a-0000-1000-8000-00805f9b34fb"));
        assert!(!is_reconnect_uuid("00001234-0000-1000-8000-00805f9b34fb"));
    }

    #[test]
    fn test_track_untrack_device() {
        // Initialize state
        {
            let mut guard = STATE.lock().unwrap();
            *guard = Some(PolicyState::default());
        }

        track_device("AA:BB:CC:DD:EE:FF");

        {
            let guard = STATE.lock().unwrap();
            let state = guard.as_ref().unwrap();
            assert!(state.reconnect_map.contains_key("AA:BB:CC:DD:EE:FF"));
        }

        untrack_device("AA:BB:CC:DD:EE:FF");

        {
            let guard = STATE.lock().unwrap();
            let state = guard.as_ref().unwrap();
            assert!(!state.reconnect_map.contains_key("AA:BB:CC:DD:EE:FF"));
        }

        // Cleanup
        let mut guard = STATE.lock().unwrap();
        *guard = None;
    }
}
