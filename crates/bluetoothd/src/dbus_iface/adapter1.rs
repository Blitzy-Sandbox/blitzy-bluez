// SPDX-License-Identifier: GPL-2.0-or-later
//
// org.bluez.Adapter1 D-Bus interface implementation.

use std::collections::HashMap;

use zbus::fdo;
use zbus::zvariant::{ObjectPath, OwnedValue};

use crate::adapter::{BtdAdapter, DiscoveryFilter};

/// D-Bus interface object for org.bluez.Adapter1.
///
/// Wraps a [`BtdAdapter`] and exposes its properties and methods on D-Bus.
pub struct Adapter1Iface {
    adapter: BtdAdapter,
}

impl Adapter1Iface {
    /// Create a new interface object wrapping the given adapter.
    pub fn new(adapter: BtdAdapter) -> Self {
        Self { adapter }
    }
}

#[zbus::interface(name = "org.bluez.Adapter1")]
impl Adapter1Iface {
    // -- Methods ----------------------------------------------------------

    /// Start device discovery (inquiry + LE scan).
    async fn start_discovery(&self) -> fdo::Result<()> {
        // Try async mgmt path first, fall back to sync
        match self.adapter.start_discovery_async().await {
            Ok(()) => Ok(()),
            Err(e) => {
                // If no mgmt client, use sync fallback
                if e.message.contains("no management client") {
                    self.adapter
                        .start_discovery()
                        .map_err(|e| fdo::Error::Failed(e.message.clone()))
                } else {
                    Err(fdo::Error::Failed(e.message.clone()))
                }
            }
        }
    }

    /// Stop device discovery.
    async fn stop_discovery(&self) -> fdo::Result<()> {
        match self.adapter.stop_discovery_async().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.message.contains("no management client") {
                    self.adapter
                        .stop_discovery()
                        .map_err(|e| fdo::Error::Failed(e.message.clone()))
                } else {
                    Err(fdo::Error::Failed(e.message.clone()))
                }
            }
        }
    }

    /// Remove a device by its D-Bus object path.
    async fn remove_device(&self, device: ObjectPath<'_>) -> fdo::Result<()> {
        self.adapter
            .remove_device(device.as_str())
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }

    /// Set discovery filter parameters.
    async fn set_discovery_filter(
        &self,
        properties: HashMap<String, OwnedValue>,
    ) -> fdo::Result<()> {
        let mut filter = DiscoveryFilter::default();

        if let Some(val) = properties.get("UUIDs") {
            if let Ok(arr) = <Vec<String>>::try_from(val.clone()) {
                filter.uuids = arr;
            }
        }

        if let Some(val) = properties.get("RSSI") {
            if let Ok(rssi) = i16::try_from(val.clone()) {
                filter.rssi = Some(rssi);
            }
        }

        if let Some(val) = properties.get("Pathloss") {
            if let Ok(pl) = u16::try_from(val.clone()) {
                filter.pathloss = Some(pl);
            }
        }

        if let Some(val) = properties.get("Transport") {
            if let Ok(s) = String::try_from(val.clone()) {
                filter.transport = Some(s);
            }
        }

        if let Some(val) = properties.get("DuplicateData") {
            if let Ok(b) = bool::try_from(val.clone()) {
                filter.duplicate_data = Some(b);
            }
        }

        if let Some(val) = properties.get("Discoverable") {
            if let Ok(b) = bool::try_from(val.clone()) {
                filter.discoverable = Some(b);
            }
        }

        if let Some(val) = properties.get("Pattern") {
            if let Ok(s) = String::try_from(val.clone()) {
                filter.pattern = Some(s);
            }
        }

        self.adapter.set_discovery_filter(filter);
        Ok(())
    }

    /// Return the list of available discovery filter names.
    async fn get_discovery_filters(&self) -> fdo::Result<Vec<String>> {
        Ok(vec![
            "UUIDs".into(),
            "RSSI".into(),
            "Pathloss".into(),
            "Transport".into(),
            "DuplicateData".into(),
            "Discoverable".into(),
            "Pattern".into(),
        ])
    }

    /// Connect a device by its properties (e.g. address).
    async fn connect_device(
        &self,
        _properties: HashMap<String, OwnedValue>,
    ) -> fdo::Result<()> {
        // Stub — requires full device resolution logic.
        Err(fdo::Error::NotSupported(
            "ConnectDevice not yet implemented".into(),
        ))
    }

    // -- Properties -------------------------------------------------------

    /// The Bluetooth device address.
    #[zbus(property)]
    async fn address(&self) -> String {
        self.adapter.address().to_string()
    }

    /// The Bluetooth address type ("public" or "random").
    #[zbus(property)]
    async fn address_type(&self) -> String {
        "public".into()
    }

    /// The system name of the adapter.
    #[zbus(property)]
    async fn name(&self) -> String {
        self.adapter.name()
    }

    /// The user-visible alias.
    #[zbus(property)]
    async fn alias(&self) -> String {
        self.adapter.alias()
    }

    #[zbus(property)]
    async fn set_alias(&self, value: String) -> zbus::Result<()> {
        // Try async path; fall back to sync
        match self.adapter.set_alias_async(&value).await {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.message.contains("no management client") {
                    self.adapter.set_alias(&value);
                    Ok(())
                } else {
                    Err(zbus::Error::Failure(e.message.clone()))
                }
            }
        }
    }

    /// Class of Device (24-bit).
    #[zbus(property)]
    async fn class(&self) -> u32 {
        self.adapter.class_of_device()
    }

    /// Whether the adapter radio is powered on.
    #[zbus(property)]
    async fn powered(&self) -> bool {
        self.adapter.powered()
    }

    #[zbus(property)]
    async fn set_powered(&self, value: bool) -> zbus::Result<()> {
        match self.adapter.set_powered_async(value).await {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.message.contains("no management client") {
                    self.adapter.set_powered(value);
                    Ok(())
                } else {
                    Err(zbus::Error::Failure(e.message.clone()))
                }
            }
        }
    }

    /// Whether the adapter is visible to other devices.
    #[zbus(property)]
    async fn discoverable(&self) -> bool {
        self.adapter.discoverable()
    }

    #[zbus(property)]
    async fn set_discoverable(&self, value: bool) -> zbus::Result<()> {
        match self.adapter.set_discoverable_async(value, 0).await {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.message.contains("no management client") {
                    self.adapter.set_discoverable(value, 0);
                    Ok(())
                } else {
                    Err(zbus::Error::Failure(e.message.clone()))
                }
            }
        }
    }

    /// Discoverable timeout in seconds.
    #[zbus(property)]
    async fn discoverable_timeout(&self) -> u32 {
        0
    }

    #[zbus(property)]
    async fn set_discoverable_timeout(&self, _value: u32) -> zbus::Result<()> {
        Ok(())
    }

    /// Whether pairing is allowed.
    #[zbus(property)]
    async fn pairable(&self) -> bool {
        self.adapter.pairable()
    }

    #[zbus(property)]
    async fn set_pairable(&self, value: bool) -> zbus::Result<()> {
        match self.adapter.set_pairable_async(value).await {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.message.contains("no management client") {
                    self.adapter.set_pairable(value);
                    Ok(())
                } else {
                    Err(zbus::Error::Failure(e.message.clone()))
                }
            }
        }
    }

    /// Pairable timeout in seconds.
    #[zbus(property)]
    async fn pairable_timeout(&self) -> u32 {
        0
    }

    #[zbus(property)]
    async fn set_pairable_timeout(&self, _value: u32) -> zbus::Result<()> {
        Ok(())
    }

    /// Whether discovery is in progress.
    #[zbus(property)]
    async fn discovering(&self) -> bool {
        self.adapter.discovering()
    }

    /// Service UUIDs advertised by this adapter.
    #[zbus(property, name = "UUIDs")]
    async fn uuids(&self) -> Vec<String> {
        Vec::new()
    }

    /// Modalias string.
    #[zbus(property)]
    async fn modalias(&self) -> String {
        String::new()
    }

    /// Supported LE roles.
    #[zbus(property)]
    async fn roles(&self) -> Vec<String> {
        vec!["central".into(), "peripheral".into()]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bluez_shared::addr::BdAddr;

    #[test]
    fn test_adapter1_iface_creation() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);
        let iface = Adapter1Iface::new(adapter);
        // Verify the wrapper holds the adapter correctly.
        assert_eq!(iface.adapter.index(), 0);
    }
}
