// SPDX-License-Identifier: GPL-2.0-or-later
//
// Battery-related D-Bus interface implementations:
//   - org.bluez.Battery1
//   - org.bluez.BatteryProviderManager1

use std::sync::{Arc, Mutex};

use zbus::fdo;
use zbus::zvariant::ObjectPath;

// ---------------------------------------------------------------------------
// org.bluez.Battery1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.Battery1.
///
/// Exposes the battery level of a connected Bluetooth device.
pub struct Battery1Iface {
    percentage: u8,
    source: String,
}

impl Battery1Iface {
    /// Create a new battery interface with the given percentage and source.
    pub fn new(percentage: u8, source: &str) -> Self {
        Self {
            percentage,
            source: source.into(),
        }
    }
}

#[zbus::interface(name = "org.bluez.Battery1")]
impl Battery1Iface {
    #[zbus(property)]
    async fn percentage(&self) -> u8 {
        self.percentage
    }

    #[zbus(property)]
    async fn source(&self) -> &str {
        &self.source
    }
}

// ---------------------------------------------------------------------------
// BatteryProviderManager internal state
// ---------------------------------------------------------------------------

/// Tracks registered battery providers.
#[derive(Debug)]
pub struct BatteryProviderRegistry {
    providers: Vec<String>,
}

impl BatteryProviderRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Register a provider by its D-Bus path.
    pub fn register(&mut self, path: &str) -> Result<(), String> {
        if self.providers.iter().any(|p| p == path) {
            return Err("Provider already registered".into());
        }
        self.providers.push(path.into());
        Ok(())
    }

    /// Unregister a provider by its D-Bus path.
    pub fn unregister(&mut self, path: &str) -> Result<(), String> {
        let idx = self
            .providers
            .iter()
            .position(|p| p == path)
            .ok_or_else(|| "Provider not registered".to_string())?;
        self.providers.remove(idx);
        Ok(())
    }

    /// Number of registered providers.
    pub fn count(&self) -> usize {
        self.providers.len()
    }
}

impl Default for BatteryProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// org.bluez.BatteryProviderManager1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.BatteryProviderManager1.
pub struct BatteryProviderManager1Iface {
    registry: Arc<Mutex<BatteryProviderRegistry>>,
}

impl BatteryProviderManager1Iface {
    /// Create a new interface wrapping the given registry.
    pub fn new(registry: Arc<Mutex<BatteryProviderRegistry>>) -> Self {
        Self { registry }
    }
}

#[zbus::interface(name = "org.bluez.BatteryProviderManager1")]
impl BatteryProviderManager1Iface {
    /// Register a battery provider.
    async fn register_battery_provider(
        &self,
        provider: ObjectPath<'_>,
    ) -> fdo::Result<()> {
        let mut reg = self.registry.lock().unwrap();
        reg.register(provider.as_str())
            .map_err(fdo::Error::Failed)
    }

    /// Unregister a battery provider.
    async fn unregister_battery_provider(
        &self,
        provider: ObjectPath<'_>,
    ) -> fdo::Result<()> {
        let mut reg = self.registry.lock().unwrap();
        reg.unregister(provider.as_str())
            .map_err(fdo::Error::Failed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_battery1_creation() {
        let iface = Battery1Iface::new(85, "HFP");
        assert_eq!(iface.percentage, 85);
        assert_eq!(iface.source, "HFP");
    }

    #[test]
    fn test_battery_provider_registry() {
        let mut reg = BatteryProviderRegistry::new();
        assert_eq!(reg.count(), 0);

        reg.register("/test/provider1").unwrap();
        assert_eq!(reg.count(), 1);

        // Duplicate must fail.
        assert!(reg.register("/test/provider1").is_err());

        reg.unregister("/test/provider1").unwrap();
        assert_eq!(reg.count(), 0);

        // Double-unregister must fail.
        assert!(reg.unregister("/test/provider1").is_err());
    }

    #[test]
    fn test_battery_provider_manager1_creation() {
        let reg = Arc::new(Mutex::new(BatteryProviderRegistry::new()));
        let iface = BatteryProviderManager1Iface::new(reg);
        assert_eq!(iface.registry.lock().unwrap().count(), 0);
    }
}
