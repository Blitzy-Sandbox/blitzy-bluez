// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT-related D-Bus interface implementations:
//   - org.bluez.GattManager1
//   - org.bluez.GattService1
//   - org.bluez.GattCharacteristic1
//   - org.bluez.GattDescriptor1

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zbus::fdo;
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedValue};

use crate::gatt_database::GattDatabase;

// ---------------------------------------------------------------------------
// org.bluez.GattManager1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.GattManager1.
pub struct GattManager1Iface {
    db: Arc<Mutex<GattDatabase>>,
}

impl GattManager1Iface {
    /// Create a new GATT manager interface wrapping the given database.
    pub fn new(db: Arc<Mutex<GattDatabase>>) -> Self {
        Self { db }
    }
}

#[zbus::interface(name = "org.bluez.GattManager1")]
impl GattManager1Iface {
    /// Register a GATT application object hierarchy.
    async fn register_application(
        &self,
        application: ObjectPath<'_>,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<()> {
        let mut db = self.db.lock().unwrap();
        db.register_application(application.to_string(), String::new())
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }

    /// Unregister a previously registered application.
    async fn unregister_application(
        &self,
        application: ObjectPath<'_>,
    ) -> fdo::Result<()> {
        let mut db = self.db.lock().unwrap();
        db.unregister_application(application.as_str())
            .map_err(|e| fdo::Error::Failed(e.message.clone()))
    }
}

// ---------------------------------------------------------------------------
// org.bluez.GattService1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.GattService1.
pub struct GattService1Iface {
    uuid: String,
    primary: bool,
    device: Option<ObjectPath<'static>>,
    includes: Vec<ObjectPath<'static>>,
    handle: u16,
}

impl GattService1Iface {
    /// Create a new GATT service interface.
    pub fn new(uuid: String, primary: bool, handle: u16) -> Self {
        Self {
            uuid,
            primary,
            device: None,
            includes: Vec::new(),
            handle,
        }
    }
}

#[zbus::interface(name = "org.bluez.GattService1")]
impl GattService1Iface {
    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> &str {
        &self.uuid
    }

    #[zbus(property)]
    async fn primary(&self) -> bool {
        self.primary
    }

    #[zbus(property)]
    async fn device(&self) -> fdo::Result<ObjectPath<'_>> {
        self.device
            .as_ref()
            .map(|p| p.as_ref())
            .ok_or_else(|| fdo::Error::Failed("No device associated".into()))
    }

    #[zbus(property)]
    async fn includes(&self) -> Vec<ObjectPath<'_>> {
        self.includes.iter().map(|p| p.as_ref()).collect()
    }

    #[zbus(property)]
    async fn handle(&self) -> u16 {
        self.handle
    }
}

// ---------------------------------------------------------------------------
// org.bluez.GattCharacteristic1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.GattCharacteristic1.
pub struct GattCharacteristic1Iface {
    uuid: String,
    service: ObjectPath<'static>,
    value: Vec<u8>,
    notifying: bool,
    flags: Vec<String>,
    handle: u16,
    mtu: u16,
}

impl GattCharacteristic1Iface {
    /// Create a new GATT characteristic interface.
    pub fn new(uuid: String, service: ObjectPath<'static>, flags: Vec<String>, handle: u16) -> Self {
        Self {
            uuid,
            service,
            value: Vec::new(),
            notifying: false,
            flags,
            handle,
            mtu: 23,
        }
    }
}

#[zbus::interface(name = "org.bluez.GattCharacteristic1")]
impl GattCharacteristic1Iface {
    /// Read the characteristic value.
    async fn read_value(
        &self,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<Vec<u8>> {
        Ok(self.value.clone())
    }

    /// Write a value to the characteristic.
    async fn write_value(
        &mut self,
        value: Vec<u8>,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<()> {
        self.value = value;
        Ok(())
    }

    /// Acquire a write file descriptor.
    async fn acquire_write(
        &self,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<(OwnedFd, u16)> {
        Err(fdo::Error::NotSupported(
            "AcquireWrite not yet implemented".into(),
        ))
    }

    /// Acquire a notify file descriptor.
    async fn acquire_notify(
        &self,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<(OwnedFd, u16)> {
        Err(fdo::Error::NotSupported(
            "AcquireNotify not yet implemented".into(),
        ))
    }

    /// Start sending notifications/indications.
    async fn start_notify(&mut self) -> fdo::Result<()> {
        if self.notifying {
            return Err(fdo::Error::Failed("Already notifying".into()));
        }
        self.notifying = true;
        Ok(())
    }

    /// Stop sending notifications/indications.
    async fn stop_notify(&mut self) -> fdo::Result<()> {
        if !self.notifying {
            return Err(fdo::Error::Failed("Not notifying".into()));
        }
        self.notifying = false;
        Ok(())
    }

    /// Confirm an indication was received.
    async fn confirm(&self) -> fdo::Result<()> {
        Ok(())
    }

    // ── Properties ───────────────────────────────────────────────────

    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> &str {
        &self.uuid
    }

    #[zbus(property)]
    async fn service(&self) -> ObjectPath<'_> {
        self.service.as_ref()
    }

    #[zbus(property)]
    async fn value(&self) -> &[u8] {
        &self.value
    }

    #[zbus(property)]
    async fn notifying(&self) -> bool {
        self.notifying
    }

    #[zbus(property)]
    async fn flags(&self) -> Vec<String> {
        self.flags.clone()
    }

    #[zbus(property)]
    async fn handle(&self) -> u16 {
        self.handle
    }

    #[zbus(property, name = "MTU")]
    async fn mtu(&self) -> u16 {
        self.mtu
    }
}

// ---------------------------------------------------------------------------
// org.bluez.GattDescriptor1
// ---------------------------------------------------------------------------

/// D-Bus interface object for org.bluez.GattDescriptor1.
pub struct GattDescriptor1Iface {
    uuid: String,
    characteristic: ObjectPath<'static>,
    value: Vec<u8>,
    handle: u16,
    flags: Vec<String>,
}

impl GattDescriptor1Iface {
    /// Create a new GATT descriptor interface.
    pub fn new(
        uuid: String,
        characteristic: ObjectPath<'static>,
        flags: Vec<String>,
        handle: u16,
    ) -> Self {
        Self {
            uuid,
            characteristic,
            value: Vec::new(),
            handle,
            flags,
        }
    }
}

#[zbus::interface(name = "org.bluez.GattDescriptor1")]
impl GattDescriptor1Iface {
    /// Read the descriptor value.
    async fn read_value(
        &self,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<Vec<u8>> {
        Ok(self.value.clone())
    }

    /// Write a value to the descriptor.
    async fn write_value(
        &mut self,
        value: Vec<u8>,
        _options: HashMap<String, OwnedValue>,
    ) -> fdo::Result<()> {
        self.value = value;
        Ok(())
    }

    // ── Properties ───────────────────────────────────────────────────

    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> &str {
        &self.uuid
    }

    #[zbus(property)]
    async fn characteristic(&self) -> ObjectPath<'_> {
        self.characteristic.as_ref()
    }

    #[zbus(property)]
    async fn value(&self) -> &[u8] {
        &self.value
    }

    #[zbus(property)]
    async fn handle(&self) -> u16 {
        self.handle
    }

    #[zbus(property)]
    async fn flags(&self) -> Vec<String> {
        self.flags.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gatt_manager1_creation() {
        let db = Arc::new(Mutex::new(GattDatabase::new()));
        let iface = GattManager1Iface::new(db.clone());
        assert_eq!(iface.db.lock().unwrap().service_count(), 0);
    }

    #[test]
    fn test_gatt_service1_creation() {
        let iface = GattService1Iface::new(
            "0000180f-0000-1000-8000-00805f9b34fb".into(),
            true,
            1,
        );
        assert_eq!(iface.uuid, "0000180f-0000-1000-8000-00805f9b34fb");
        assert!(iface.primary);
        assert_eq!(iface.handle, 1);
    }

    #[test]
    fn test_gatt_characteristic1_creation() {
        let service_path = ObjectPath::try_from("/org/bluez/hci0/service0001").unwrap().into();
        let iface = GattCharacteristic1Iface::new(
            "00002a19-0000-1000-8000-00805f9b34fb".into(),
            service_path,
            vec!["read".into(), "notify".into()],
            2,
        );
        assert_eq!(iface.uuid, "00002a19-0000-1000-8000-00805f9b34fb");
        assert_eq!(iface.flags.len(), 2);
        assert_eq!(iface.handle, 2);
        assert!(!iface.notifying);
    }

    #[test]
    fn test_gatt_descriptor1_creation() {
        let char_path = ObjectPath::try_from("/org/bluez/hci0/service0001/char0002").unwrap().into();
        let iface = GattDescriptor1Iface::new(
            "00002902-0000-1000-8000-00805f9b34fb".into(),
            char_path,
            vec!["read".into(), "write".into()],
            3,
        );
        assert_eq!(iface.uuid, "00002902-0000-1000-8000-00805f9b34fb");
        assert_eq!(iface.handle, 3);
    }
}
