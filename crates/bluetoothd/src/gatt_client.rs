// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT client (remote service proxy) replacing src/gatt-client.c.
// Provides a local proxy for GATT services, characteristics, and descriptors
// discovered on a remote device, exposed over D-Bus.

/// Proxy for a GATT characteristic on a remote device.
#[derive(Debug, Clone)]
pub struct GattCharProxy {
    /// D-Bus object path.
    pub path: String,
    /// Characteristic UUID.
    pub uuid: String,
    /// Property flags (e.g. "read", "write", "notify").
    pub flags: Vec<String>,
}

/// Proxy for a GATT service on a remote device.
#[derive(Debug, Clone)]
pub struct GattServiceProxy {
    /// D-Bus object path.
    pub path: String,
    /// Service UUID.
    pub uuid: String,
    /// Whether this is a primary service.
    pub primary: bool,
    /// Characteristics belonging to this service.
    pub characteristics: Vec<GattCharProxy>,
}

/// Client-side GATT proxy for a connected remote device.
#[derive(Debug)]
pub struct GattClient {
    services: Vec<GattServiceProxy>,
    connected: bool,
}

impl GattClient {
    /// Creates a new, disconnected GATT client with no services.
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
            connected: false,
        }
    }

    /// Updates the connection state.
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// Returns whether the client is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Returns the number of discovered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }
}

impl Default for GattClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gatt_client_new() {
        let client = GattClient::new();
        assert!(!client.is_connected());
        assert_eq!(client.service_count(), 0);
    }

    #[test]
    fn test_gatt_client_connected() {
        let mut client = GattClient::new();
        assert!(!client.is_connected());

        client.set_connected(true);
        assert!(client.is_connected());

        client.set_connected(false);
        assert!(!client.is_connected());
    }
}
