// SPDX-License-Identifier: GPL-2.0-or-later
//
// neard — NFC-triggered Bluetooth pairing plugin.
//
// Replaces plugins/neard.c (~897 LOC).  Registers as an NFC handover agent
// with neard (the Linux NFC daemon) over D-Bus, enabling Bluetooth pairing
// through NFC tap using Out-of-Band (OOB) data.

use std::sync::Mutex;

use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};

// ---------------------------------------------------------------------------
// D-Bus constants
// ---------------------------------------------------------------------------

/// Well-known D-Bus name for neard.
pub const NEARD_NAME: &str = "org.neard";

/// Root object path for neard.
pub const NEARD_PATH: &str = "/";

/// neard Manager interface.
pub const NEARD_MANAGER_INTERFACE: &str = "org.neard.Manager";

/// Handover agent interface implemented by this plugin.
pub const AGENT_INTERFACE: &str = "org.neard.HandoverAgent";

/// Object path for our handover agent.
pub const AGENT_PATH: &str = "/org/bluez/neard_handover_agent";

/// Carrier type string registered with neard.
pub const AGENT_CARRIER_TYPE: &str = "bluetooth";

/// Maximum OOB EIR data size for NFC MIME type.
pub const NFC_OOB_EIR_MAX: usize = 255;

// ---------------------------------------------------------------------------
// Connection Power State (Bluetooth NFC Forum spec)
// ---------------------------------------------------------------------------

/// Connection Power State values used in NFC handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionPowerState {
    /// Bluetooth is actively connected.
    Active,
    /// Bluetooth radio is off.
    Inactive,
    /// Bluetooth is powering up.
    Activating,
    /// State is unknown.
    #[default]
    Unknown,
}

impl ConnectionPowerState {
    /// Parse from a D-Bus string property.
    pub fn parse(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "inactive" => Self::Inactive,
            "activating" => Self::Activating,
            _ => Self::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// OOB parameters
// ---------------------------------------------------------------------------

/// Out-of-Band pairing parameters exchanged via NFC.
#[derive(Debug, Clone, Default)]
pub struct OobParams {
    /// Remote device BD_ADDR (6 bytes).
    pub address: [u8; 6],
    /// Class of Device.
    pub class: u32,
    /// Remote device name.
    pub name: Option<String>,
    /// Service UUIDs advertised by the remote device.
    pub services: Vec<String>,
    /// Simple Pairing Hash C (16 bytes).
    pub hash: Option<Vec<u8>>,
    /// Simple Pairing Randomizer R (16 bytes).
    pub randomizer: Option<Vec<u8>>,
    /// PIN code (for legacy pairing).
    pub pin: Option<Vec<u8>>,
    /// Connection power state of the remote device.
    pub power_state: ConnectionPowerState,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
#[allow(dead_code)]
struct NeardState {
    /// Whether the neard D-Bus name is currently available.
    neard_present: bool,
    /// Whether agent registration has been postponed (neard not yet up).
    agent_register_postpone: bool,
}

static STATE: Mutex<Option<NeardState>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct NeardPlugin;

impl BluetoothPlugin for NeardPlugin {
    fn desc(&self) -> PluginDesc {
        PluginDesc {
            name: "neard",
            version: env!("CARGO_PKG_VERSION"),
            priority: PluginPriority::Default,
        }
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut guard = STATE.lock().expect("neard state mutex poisoned");
        *guard = Some(NeardState::default());

        // TODO: watch for neard D-Bus name owner changes
        // TODO: register as handover agent when neard appears
        // TODO: implement RequestOOB / PushOOB / Release agent methods

        Ok(())
    }

    fn exit(&self) {
        // TODO: unregister handover agent
        // TODO: remove D-Bus name watch

        let mut guard = STATE.lock().expect("neard state mutex poisoned");
        *guard = None;
    }
}

inventory::submit! { &NeardPlugin as &dyn BluetoothPlugin }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_power_state_parsing() {
        assert_eq!(
            ConnectionPowerState::parse("active"),
            ConnectionPowerState::Active
        );
        assert_eq!(
            ConnectionPowerState::parse("inactive"),
            ConnectionPowerState::Inactive
        );
        assert_eq!(
            ConnectionPowerState::parse("activating"),
            ConnectionPowerState::Activating
        );
        assert_eq!(
            ConnectionPowerState::parse("bogus"),
            ConnectionPowerState::Unknown
        );
    }

    #[test]
    fn test_oob_params_default() {
        let params = OobParams::default();
        assert_eq!(params.address, [0u8; 6]);
        assert_eq!(params.class, 0);
        assert!(params.name.is_none());
        assert!(params.hash.is_none());
        assert_eq!(params.power_state, ConnectionPowerState::Unknown);
    }
}
