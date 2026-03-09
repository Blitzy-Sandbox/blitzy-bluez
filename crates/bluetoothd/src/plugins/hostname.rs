// SPDX-License-Identifier: GPL-2.0-or-later
//
// hostname — Hostname-based adapter name plugin.
//
// Replaces plugins/hostname.c (~366 LOC).  Sets the Bluetooth adapter's
// friendly name from the system hostname and watches for hostname changes
// via D-Bus (org.freedesktop.hostname1).

use std::sync::Mutex;

use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};

// ---------------------------------------------------------------------------
// Bluetooth device class constants (baseband assigned numbers)
// ---------------------------------------------------------------------------

/// Major class: Miscellaneous.
pub const MAJOR_CLASS_MISCELLANEOUS: u8 = 0x00;
/// Major class: Computer.
pub const MAJOR_CLASS_COMPUTER: u8 = 0x01;

/// Minor class: Uncategorized.
pub const MINOR_CLASS_UNCATEGORIZED: u8 = 0x00;
/// Minor class: Desktop workstation.
pub const MINOR_CLASS_DESKTOP: u8 = 0x01;
/// Minor class: Server-class computer.
pub const MINOR_CLASS_SERVER: u8 = 0x02;
/// Minor class: Laptop.
pub const MINOR_CLASS_LAPTOP: u8 = 0x03;
/// Minor class: Handheld device.
pub const MINOR_CLASS_HANDHELD: u8 = 0x04;
/// Minor class: Palm-sized device.
pub const MINOR_CLASS_PALM_SIZED: u8 = 0x05;
/// Minor class: Wearable computer.
pub const MINOR_CLASS_WEARABLE: u8 = 0x06;
/// Minor class: Tablet.
pub const MINOR_CLASS_TABLET: u8 = 0x07;

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
#[allow(dead_code)]
struct HostnameState {
    /// "Pretty" hostname from hostnamed (e.g. "John's Laptop").
    pretty_hostname: Option<String>,
    /// Static hostname (e.g. "johns-laptop").
    static_hostname: Option<String>,
    /// Transient hostname.
    transient_hostname: Option<String>,
    /// Major device class derived from chassis type.
    major_class: u8,
    /// Minor device class derived from chassis type.
    minor_class: u8,
}

static STATE: Mutex<Option<HostnameState>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Return the best hostname to use as the adapter name.
///
/// Prefers the pretty hostname; falls back to the static hostname, then
/// the transient hostname.
pub fn get_hostname() -> Option<String> {
    let guard = STATE.lock().expect("hostname state mutex poisoned");
    let state = guard.as_ref()?;

    // Prefer non-empty pretty hostname.
    if let Some(ref h) = state.pretty_hostname {
        if !h.is_empty() {
            return Some(h.clone());
        }
    }
    // Fallback to static hostname only if pretty hostname was already
    // received (even if empty).
    if state.pretty_hostname.is_some() {
        if let Some(ref h) = state.static_hostname {
            if !h.is_empty() {
                return Some(h.clone());
            }
        }
    }
    state.transient_hostname.clone()
}

/// Update hostname values (typically called from D-Bus property changes).
pub fn update_hostnames(
    pretty: Option<String>,
    static_hn: Option<String>,
    transient: Option<String>,
) {
    let mut guard = STATE.lock().expect("hostname state mutex poisoned");
    let state = guard.get_or_insert_with(HostnameState::default);
    if let Some(p) = pretty {
        state.pretty_hostname = Some(p);
    }
    if let Some(s) = static_hn {
        state.static_hostname = Some(s);
    }
    if let Some(t) = transient {
        state.transient_hostname = Some(t);
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct HostnamePlugin;

impl BluetoothPlugin for HostnamePlugin {
    fn desc(&self) -> PluginDesc {
        PluginDesc {
            name: "hostname",
            version: env!("CARGO_PKG_VERSION"),
            priority: PluginPriority::Default,
        }
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut guard = STATE.lock().expect("hostname state mutex poisoned");
        *guard = Some(HostnameState::default());

        // TODO: query org.freedesktop.hostname1 for initial values
        // TODO: subscribe to PropertiesChanged signals for hostname updates
        // TODO: set adapter name and device class from hostname / chassis

        Ok(())
    }

    fn exit(&self) {
        let mut guard = STATE.lock().expect("hostname state mutex poisoned");
        *guard = None;
    }
}

inventory::submit! { &HostnamePlugin as &dyn BluetoothPlugin }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_preference() {
        // Initialize state
        {
            let mut guard = STATE.lock().unwrap();
            *guard = Some(HostnameState::default());
        }

        // No hostnames set yet — returns None (transient is None).
        assert!(get_hostname().is_none());

        // Set transient hostname.
        update_hostnames(None, None, Some("transient-host".into()));
        assert_eq!(get_hostname().as_deref(), Some("transient-host"));

        // Set pretty hostname — should take precedence.
        update_hostnames(Some("My Pretty Laptop".into()), None, None);
        assert_eq!(get_hostname().as_deref(), Some("My Pretty Laptop"));

        // Empty pretty hostname + static hostname => fallback to static.
        update_hostnames(Some(String::new()), Some("static-host".into()), None);
        assert_eq!(get_hostname().as_deref(), Some("static-host"));

        // Cleanup
        let mut guard = STATE.lock().unwrap();
        *guard = None;
    }
}
