// SPDX-License-Identifier: GPL-2.0-or-later
//
// org.bluez.Device1 D-Bus interface implementation.

use std::collections::HashMap;

use zbus::fdo;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use crate::adapter::BtdAdapter;
use crate::device::BtdDevice;

/// D-Bus interface object for org.bluez.Device1.
pub struct Device1Iface {
    device: BtdDevice,
    adapter: Option<BtdAdapter>,
}

impl Device1Iface {
    /// Create a new interface object wrapping the given device.
    pub fn new(device: BtdDevice) -> Self {
        Self {
            device,
            adapter: None,
        }
    }

    /// Create a new interface object with an adapter reference for mgmt operations.
    pub fn with_adapter(device: BtdDevice, adapter: BtdAdapter) -> Self {
        Self {
            device,
            adapter: Some(adapter),
        }
    }
}

#[zbus::interface(name = "org.bluez.Device1")]
impl Device1Iface {
    // -- Methods ----------------------------------------------------------

    /// Initiate a connection to this device.
    async fn connect(&self) -> fdo::Result<()> {
        // Use sync connect for now; real mgmt connect would go through adapter
        self.device
            .connect()
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }

    /// Disconnect from this device.
    async fn disconnect(&self) -> fdo::Result<()> {
        if let Some(adapter) = &self.adapter {
            let addr = self.device.address();
            let addr_type = self.device.address_type();
            match adapter.disconnect_device(addr, addr_type).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !e.message.contains("no management client") {
                        return Err(fdo::Error::Failed(e.message.clone()));
                    }
                    // Fall through to sync path
                }
            }
        }
        self.device
            .disconnect()
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }

    /// Connect a specific profile by UUID.
    async fn connect_profile(&self, _uuid: String) -> fdo::Result<()> {
        Err(fdo::Error::NotSupported(
            "ConnectProfile not yet implemented".into(),
        ))
    }

    /// Disconnect a specific profile by UUID.
    async fn disconnect_profile(&self, _uuid: String) -> fdo::Result<()> {
        Err(fdo::Error::NotSupported(
            "DisconnectProfile not yet implemented".into(),
        ))
    }

    /// Initiate pairing with this device.
    async fn pair(&self) -> fdo::Result<()> {
        if let Some(adapter) = &self.adapter {
            let addr = self.device.address();
            let addr_type = self.device.address_type();
            let io_cap = self.device.io_capability();
            return adapter
                .pair_device(addr, addr_type, io_cap)
                .await
                .map_err(|e| fdo::Error::Failed(e.message.clone()));
        }
        Err(fdo::Error::NotSupported(
            "Pair requires management client".into(),
        ))
    }

    /// Cancel an ongoing pairing attempt.
    async fn cancel_pairing(&self) -> fdo::Result<()> {
        if let Some(adapter) = &self.adapter {
            let addr = self.device.address();
            let addr_type = self.device.address_type();
            return adapter
                .cancel_pair_device(addr, addr_type)
                .await
                .map_err(|e| fdo::Error::Failed(e.message.clone()));
        }
        Err(fdo::Error::NotSupported(
            "CancelPairing requires management client".into(),
        ))
    }

    // -- Properties -------------------------------------------------------

    #[zbus(property)]
    async fn address(&self) -> String {
        self.device.address().to_string()
    }

    #[zbus(property)]
    async fn address_type(&self) -> String {
        match self.device.address_type() {
            0 => "public".into(),
            _ => "random".into(),
        }
    }

    #[zbus(property)]
    async fn name(&self) -> fdo::Result<String> {
        self.device
            .name()
            .ok_or_else(|| fdo::Error::Failed("Name not available".into()))
    }

    #[zbus(property)]
    async fn alias(&self) -> String {
        self.device
            .alias()
            .unwrap_or_else(|| self.device.address().to_string())
    }

    #[zbus(property)]
    async fn set_alias(&self, value: String) -> zbus::Result<()> {
        self.device.set_alias(Some(&value));
        Ok(())
    }

    #[zbus(property)]
    async fn class(&self) -> u32 {
        self.device.class_of_device()
    }

    #[zbus(property)]
    async fn appearance(&self) -> u16 {
        self.device.appearance()
    }

    #[zbus(property)]
    async fn icon(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    async fn paired(&self) -> bool {
        self.device.paired()
    }

    #[zbus(property)]
    async fn bonded(&self) -> bool {
        self.device.bonded()
    }

    #[zbus(property)]
    async fn trusted(&self) -> bool {
        self.device.trusted()
    }

    #[zbus(property)]
    async fn set_trusted(&self, value: bool) -> zbus::Result<()> {
        self.device.set_trusted(value);
        Ok(())
    }

    #[zbus(property)]
    async fn blocked(&self) -> bool {
        self.device.blocked()
    }

    #[zbus(property)]
    async fn set_blocked(&self, value: bool) -> zbus::Result<()> {
        self.device.set_blocked(value);
        Ok(())
    }

    #[zbus(property)]
    async fn legacy_pairing(&self) -> bool {
        false
    }

    #[zbus(property, name = "RSSI")]
    async fn rssi(&self) -> fdo::Result<i16> {
        self.device
            .rssi()
            .map(i16::from)
            .ok_or_else(|| fdo::Error::Failed("RSSI not available".into()))
    }

    #[zbus(property)]
    async fn connected(&self) -> bool {
        self.device.connected()
    }

    #[zbus(property, name = "UUIDs")]
    async fn uuids(&self) -> Vec<String> {
        self.device.uuids()
    }

    #[zbus(property)]
    async fn modalias(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    async fn adapter(&self) -> ObjectPath<'static> {
        let path = self.device.adapter_path();
        ObjectPath::try_from(path).unwrap_or_else(|_| {
            ObjectPath::try_from("/org/bluez/hci0").unwrap()
        })
    }

    #[zbus(property)]
    async fn manufacturer_data(&self) -> HashMap<u16, OwnedValue> {
        self.device
            .manufacturer_data()
            .into_iter()
            .filter_map(|(k, v)| {
                OwnedValue::try_from(Value::from(v)).ok().map(|val| (k, val))
            })
            .collect()
    }

    #[zbus(property)]
    async fn service_data(&self) -> HashMap<String, OwnedValue> {
        self.device
            .service_data()
            .into_iter()
            .filter_map(|(k, v)| {
                OwnedValue::try_from(Value::from(v)).ok().map(|val| (k, val))
            })
            .collect()
    }

    #[zbus(property)]
    async fn tx_power(&self) -> fdo::Result<i16> {
        self.device
            .tx_power()
            .map(i16::from)
            .ok_or_else(|| fdo::Error::Failed("TxPower not available".into()))
    }

    #[zbus(property)]
    async fn services_resolved(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn advertising_flags(&self) -> Vec<u8> {
        Vec::new()
    }

    #[zbus(property)]
    async fn advertising_data(&self) -> HashMap<u8, OwnedValue> {
        HashMap::new()
    }

    #[zbus(property)]
    async fn wake_allowed(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn set_wake_allowed(&self, _value: bool) -> zbus::Result<()> {
        Ok(())
    }

    #[zbus(property)]
    async fn sets(&self) -> Vec<ObjectPath<'static>> {
        Vec::new()
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
    fn test_device1_iface_creation() {
        let device = BtdDevice::new("/org/bluez/hci0", BdAddr::ANY, 0);
        let iface = Device1Iface::new(device);
        assert_eq!(iface.device.address(), BdAddr::ANY);
        assert!(iface.adapter.is_none());
    }

    #[test]
    fn test_device1_iface_with_adapter() {
        let device = BtdDevice::new("/org/bluez/hci0", BdAddr::ANY, 0);
        let adapter = BtdAdapter::new(0, BdAddr::ANY);
        let iface = Device1Iface::with_adapter(device, adapter);
        assert!(iface.adapter.is_some());
    }
}
