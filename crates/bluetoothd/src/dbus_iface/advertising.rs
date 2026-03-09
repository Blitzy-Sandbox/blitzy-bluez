// SPDX-License-Identifier: GPL-2.0-or-later
//
// LE advertising D-Bus interface implementations:
//   - org.bluez.LEAdvertisingManager1
//   - org.bluez.LEAdvertisement1

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zbus::fdo;
use zbus::zvariant::{ObjectPath, OwnedValue};

use crate::advertising::{AdvManager, AdvType, Advertisement};

// ---------------------------------------------------------------------------
// org.bluez.LEAdvertisingManager1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.LEAdvertisingManager1.
pub struct LEAdvertisingManager1Iface {
    manager: Arc<Mutex<AdvManager>>,
}

impl LEAdvertisingManager1Iface {
    /// Create a new interface wrapping the given advertising manager.
    pub fn new(manager: Arc<Mutex<AdvManager>>) -> Self {
        Self { manager }
    }
}

#[zbus::interface(name = "org.bluez.LEAdvertisingManager1")]
impl LEAdvertisingManager1Iface {
    /// Register an LE advertisement object.
    async fn register_advertisement(
        &self,
        advertisement: ObjectPath<'_>,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<()> {
        let adv = Advertisement {
            adv_type: AdvType::Peripheral,
            service_uuids: Vec::new(),
            manufacturer_data: HashMap::new(),
            service_data: HashMap::new(),
            local_name: None,
            appearance: None,
            duration: 2,
            timeout: 0,
            path: advertisement.to_string(),
            owner: String::new(),
        };

        let mut mgr = self.manager.lock().unwrap();
        mgr.register(adv)
            .map_err(|e| fdo::Error::Failed(e.message.clone()))?;
        Ok(())
    }

    /// Unregister a previously registered advertisement.
    async fn unregister_advertisement(
        &self,
        advertisement: ObjectPath<'_>,
    ) -> fdo::Result<()> {
        let mut mgr = self.manager.lock().unwrap();
        mgr.unregister(advertisement.as_str())
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }
}

// ---------------------------------------------------------------------------
// org.bluez.LEAdvertisement1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.LEAdvertisement1.
///
/// Represents a single LE advertisement with its properties. In practice this
/// is implemented by the advertising client; this struct provides the interface
/// definition for use by the daemon when introspecting client objects.
pub struct LEAdvertisement1Iface {
    adv_type: String,
    service_uuids: Vec<String>,
    manufacturer_data: HashMap<u16, Vec<u8>>,
    service_data: HashMap<String, Vec<u8>>,
    local_name: Option<String>,
    appearance: Option<u16>,
    duration: u16,
    timeout: u16,
    includes: Vec<String>,
}

impl LEAdvertisement1Iface {
    /// Create a new LE advertisement interface with default values.
    pub fn new(adv_type: &str) -> Self {
        Self {
            adv_type: adv_type.into(),
            service_uuids: Vec::new(),
            manufacturer_data: HashMap::new(),
            service_data: HashMap::new(),
            local_name: None,
            appearance: None,
            duration: 2,
            timeout: 0,
            includes: Vec::new(),
        }
    }
}

#[zbus::interface(name = "org.bluez.LEAdvertisement1")]
impl LEAdvertisement1Iface {
    /// Release this advertisement (daemon is removing it).
    async fn release(&self) -> fdo::Result<()> {
        Ok(())
    }

    // ── Properties ───────────────────────────────────────────────────

    #[zbus(property)]
    async fn r#type(&self) -> &str {
        &self.adv_type
    }

    #[zbus(property)]
    async fn service_uuids(&self) -> Vec<String> {
        self.service_uuids.clone()
    }

    #[zbus(property)]
    async fn manufacturer_data(&self) -> HashMap<u16, OwnedValue> {
        self.manufacturer_data
            .iter()
            .map(|(k, v)| {
                let val: zbus::zvariant::Value<'_> = v.as_slice().into();
                (*k, val.try_to_owned().unwrap())
            })
            .collect()
    }

    #[zbus(property)]
    async fn service_data(&self) -> HashMap<String, OwnedValue> {
        self.service_data
            .iter()
            .map(|(k, v)| {
                let val: zbus::zvariant::Value<'_> = v.as_slice().into();
                (k.clone(), val.try_to_owned().unwrap())
            })
            .collect()
    }

    #[zbus(property)]
    async fn local_name(&self) -> &str {
        self.local_name.as_deref().unwrap_or("")
    }

    #[zbus(property)]
    async fn appearance(&self) -> u16 {
        self.appearance.unwrap_or(0)
    }

    #[zbus(property)]
    async fn duration(&self) -> u16 {
        self.duration
    }

    #[zbus(property)]
    async fn timeout(&self) -> u16 {
        self.timeout
    }

    #[zbus(property)]
    async fn includes(&self) -> Vec<String> {
        self.includes.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_le_adv_manager1_creation() {
        let mgr = Arc::new(Mutex::new(AdvManager::new(4)));
        let iface = LEAdvertisingManager1Iface::new(mgr);
        assert_eq!(iface.manager.lock().unwrap().active_count(), 0);
    }

    #[test]
    fn test_le_advertisement1_creation() {
        let iface = LEAdvertisement1Iface::new("peripheral");
        assert_eq!(iface.adv_type, "peripheral");
        assert!(iface.service_uuids.is_empty());
        assert_eq!(iface.duration, 2);
        assert_eq!(iface.timeout, 0);
    }
}
