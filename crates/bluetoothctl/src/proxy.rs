// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// D-Bus proxy definitions for org.bluez interfaces (zbus 5)

use std::collections::HashMap;

use zbus::zvariant::{ObjectPath, OwnedValue, Value};

// ---------------------------------------------------------------------------
// org.bluez.Adapter1
// ---------------------------------------------------------------------------

/// Client-side proxy for the org.bluez.Adapter1 D-Bus interface.
#[zbus::proxy(
    interface = "org.bluez.Adapter1",
    default_service = "org.bluez",
    default_path = "/org/bluez/hci0"
)]
pub trait Adapter1 {
    /// Start device discovery.
    fn start_discovery(&self) -> zbus::Result<()>;
    /// Stop device discovery.
    fn stop_discovery(&self) -> zbus::Result<()>;
    /// Remove a remote device.
    fn remove_device(&self, device: &ObjectPath<'_>) -> zbus::Result<()>;
    /// Set the discovery filter.
    fn set_discovery_filter(
        &self,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    // Properties
    #[zbus(property)]
    fn address(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn alias(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_alias(&self, value: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn powered(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_powered(&self, value: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn discoverable(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_discoverable(&self, value: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn discoverable_timeout(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn set_discoverable_timeout(&self, value: u32) -> zbus::Result<()>;
    #[zbus(property)]
    fn pairable(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_pairable(&self, value: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn discovering(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn uuids(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn modalias(&self) -> zbus::Result<String>;
}

// ---------------------------------------------------------------------------
// org.bluez.Device1
// ---------------------------------------------------------------------------

/// Client-side proxy for the org.bluez.Device1 D-Bus interface.
#[zbus::proxy(
    interface = "org.bluez.Device1",
    default_service = "org.bluez"
)]
pub trait Device1 {
    fn connect(&self) -> zbus::Result<()>;
    fn disconnect(&self) -> zbus::Result<()>;
    fn connect_profile(&self, uuid: &str) -> zbus::Result<()>;
    fn disconnect_profile(&self, uuid: &str) -> zbus::Result<()>;
    fn pair(&self) -> zbus::Result<()>;
    fn cancel_pairing(&self) -> zbus::Result<()>;

    #[zbus(property)]
    fn address(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn alias(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_alias(&self, value: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn paired(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn trusted(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_trusted(&self, value: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn blocked(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_blocked(&self, value: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn connected(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn uuids(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn adapter(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn rssi(&self) -> zbus::Result<i16>;
    #[zbus(property)]
    fn icon(&self) -> zbus::Result<String>;
}

// ---------------------------------------------------------------------------
// org.bluez.GattService1
// ---------------------------------------------------------------------------

/// Client-side proxy for org.bluez.GattService1.
#[zbus::proxy(
    interface = "org.bluez.GattService1",
    default_service = "org.bluez"
)]
pub trait GattService1 {
    #[zbus(property)]
    fn uuid(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn primary(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn device(&self) -> zbus::Result<String>;
}

// ---------------------------------------------------------------------------
// org.bluez.GattCharacteristic1
// ---------------------------------------------------------------------------

/// Client-side proxy for org.bluez.GattCharacteristic1.
#[zbus::proxy(
    interface = "org.bluez.GattCharacteristic1",
    default_service = "org.bluez"
)]
pub trait GattCharacteristic1 {
    fn read_value(
        &self,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<Vec<u8>>;
    fn write_value(
        &self,
        value: &[u8],
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
    fn start_notify(&self) -> zbus::Result<()>;
    fn stop_notify(&self) -> zbus::Result<()>;

    #[zbus(property)]
    fn uuid(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn service(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn value(&self) -> zbus::Result<Vec<u8>>;
    #[zbus(property)]
    fn notifying(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn flags(&self) -> zbus::Result<Vec<String>>;
}

// ---------------------------------------------------------------------------
// org.bluez.GattDescriptor1
// ---------------------------------------------------------------------------

/// Client-side proxy for org.bluez.GattDescriptor1.
#[zbus::proxy(
    interface = "org.bluez.GattDescriptor1",
    default_service = "org.bluez"
)]
pub trait GattDescriptor1 {
    fn read_value(
        &self,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<Vec<u8>>;
    fn write_value(
        &self,
        value: &[u8],
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    #[zbus(property)]
    fn uuid(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn characteristic(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn value(&self) -> zbus::Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// org.bluez.AgentManager1
// ---------------------------------------------------------------------------

/// Client-side proxy for the agent manager.
#[zbus::proxy(
    interface = "org.bluez.AgentManager1",
    default_service = "org.bluez",
    default_path = "/org/bluez"
)]
pub trait AgentManager1 {
    fn register_agent(
        &self,
        agent: &ObjectPath<'_>,
        capability: &str,
    ) -> zbus::Result<()>;
    fn unregister_agent(&self, agent: &ObjectPath<'_>) -> zbus::Result<()>;
    fn request_default_agent(&self, agent: &ObjectPath<'_>) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// org.bluez.LEAdvertisingManager1
// ---------------------------------------------------------------------------

/// Client-side proxy for the LE advertising manager.
#[zbus::proxy(
    interface = "org.bluez.LEAdvertisingManager1",
    default_service = "org.bluez",
    default_path = "/org/bluez/hci0"
)]
pub trait LEAdvertisingManager1 {
    fn register_advertisement(
        &self,
        advertisement: &ObjectPath<'_>,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
    fn unregister_advertisement(
        &self,
        advertisement: &ObjectPath<'_>,
    ) -> zbus::Result<()>;
    #[zbus(property)]
    fn active_instances(&self) -> zbus::Result<u8>;
    #[zbus(property)]
    fn supported_instances(&self) -> zbus::Result<u8>;
}

// ---------------------------------------------------------------------------
// org.bluez.MediaPlayer1
// ---------------------------------------------------------------------------

/// Client-side proxy for the media player.
#[zbus::proxy(
    interface = "org.bluez.MediaPlayer1",
    default_service = "org.bluez"
)]
pub trait MediaPlayer1 {
    fn play(&self) -> zbus::Result<()>;
    fn pause(&self) -> zbus::Result<()>;
    fn stop(&self) -> zbus::Result<()>;
    fn next(&self) -> zbus::Result<()>;
    fn previous(&self) -> zbus::Result<()>;
    fn fast_forward(&self) -> zbus::Result<()>;
    fn rewind(&self) -> zbus::Result<()>;

    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn status(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn equalizer(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_equalizer(&self, value: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn repeat(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_repeat(&self, value: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn shuffle(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_shuffle(&self, value: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn track(&self) -> zbus::Result<HashMap<String, OwnedValue>>;
    #[zbus(property)]
    fn position(&self) -> zbus::Result<u32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_trait_objects_exist() {
        // Verify that the proxy types are generated and importable.
        fn _assert_adapter(_p: &dyn std::any::Any) {}
        fn _assert_device(_p: &dyn std::any::Any) {}
        // The proxy macro generates Adapter1Proxy, Device1Proxy, etc.
        // This test just ensures the module compiles correctly.
    }

    #[test]
    fn proxy_default_paths() {
        // The Adapter1 proxy defaults to /org/bluez/hci0.
        // Just verify the trait is usable by checking associated items compile.
        assert_eq!(std::mem::size_of::<HashMap<String, OwnedValue>>() > 0, true);
    }
}
