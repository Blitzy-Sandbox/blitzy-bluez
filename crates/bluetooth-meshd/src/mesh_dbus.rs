// SPDX-License-Identifier: GPL-2.0-or-later
//
// D-Bus interfaces for bluetooth-meshd — replaces mesh/dbus.c + mesh/manager.c
//
// Defines org.bluez.mesh.Network1, org.bluez.mesh.Management1, org.bluez.mesh.Node1

use zbus::interface;

/// D-Bus object path for the mesh service.
pub const MESH_OBJECT_PATH: &str = "/org/bluez/mesh";

/// org.bluez.mesh.Network1 interface.
pub struct MeshNetwork;

#[interface(name = "org.bluez.mesh.Network1")]
impl MeshNetwork {
    /// Join a mesh network.
    async fn join(
        &self,
        _app_path: zbus::zvariant::ObjectPath<'_>,
        _uuid: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Network1.Join called");
        Ok(())
    }

    /// Cancel an ongoing join operation.
    async fn cancel(&self) -> zbus::fdo::Result<()> {
        tracing::info!("Network1.Cancel called");
        Ok(())
    }

    /// Attach to an existing node.
    async fn attach(
        &self,
        _app_path: zbus::zvariant::ObjectPath<'_>,
        _token: u64,
    ) -> zbus::fdo::Result<(zbus::zvariant::ObjectPath<'static>, Vec<(u8, Vec<(u16, std::collections::HashMap<String, zbus::zvariant::OwnedValue>)>)>)> {
        tracing::info!("Network1.Attach called");
        Err(zbus::fdo::Error::NotSupported(
            "not yet implemented".into(),
        ))
    }

    /// Leave the mesh network.
    async fn leave(&self, _token: u64) -> zbus::fdo::Result<()> {
        tracing::info!("Network1.Leave called");
        Ok(())
    }

    /// Create a new mesh network.
    async fn create_network(
        &self,
        _app_path: zbus::zvariant::ObjectPath<'_>,
        _uuid: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Network1.CreateNetwork called");
        Ok(())
    }
}

/// org.bluez.mesh.Management1 interface.
pub struct MeshManagement;

#[interface(name = "org.bluez.mesh.Management1")]
impl MeshManagement {
    /// Start scanning for unprovisioned devices.
    async fn unprovisioned_scan(
        &self,
        _options: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Management1.UnprovisionedScan called");
        Ok(())
    }

    /// Add (provision) a new node.
    async fn add_node(
        &self,
        _uuid: Vec<u8>,
        _options: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Management1.AddNode called");
        Ok(())
    }

    /// Create a subnet.
    async fn create_subnet(&self, _net_index: u16) -> zbus::fdo::Result<()> {
        tracing::info!("Management1.CreateSubnet called");
        Ok(())
    }

    /// Delete a subnet.
    async fn delete_subnet(&self, _net_index: u16) -> zbus::fdo::Result<()> {
        tracing::info!("Management1.DeleteSubnet called");
        Ok(())
    }

    /// Add an application key.
    async fn add_app_key(
        &self,
        _app_index: u16,
        _net_index: u16,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Management1.AddAppKey called");
        Ok(())
    }

    /// Delete an application key.
    async fn delete_app_key(&self, _app_index: u16) -> zbus::fdo::Result<()> {
        tracing::info!("Management1.DeleteAppKey called");
        Ok(())
    }

    /// Set key refresh phase for a subnet.
    async fn set_key_phase(
        &self,
        _net_index: u16,
        _phase: u8,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Management1.SetKeyPhase called");
        Ok(())
    }
}

/// org.bluez.mesh.Node1 interface.
pub struct MeshNodeDbus;

#[interface(name = "org.bluez.mesh.Node1")]
impl MeshNodeDbus {
    /// Send a mesh message.
    async fn send(
        &self,
        _element_path: zbus::zvariant::ObjectPath<'_>,
        _destination: u16,
        _key_index: u16,
        _data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Node1.Send called");
        Ok(())
    }

    /// Send with device key.
    async fn dev_key_send(
        &self,
        _element_path: zbus::zvariant::ObjectPath<'_>,
        _destination: u16,
        _remote: bool,
        _net_index: u16,
        _data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Node1.DevKeySend called");
        Ok(())
    }

    /// Publish a message.
    async fn publish(
        &self,
        _element_path: zbus::zvariant::ObjectPath<'_>,
        _model_id: u16,
        _data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Node1.Publish called");
        Ok(())
    }

    /// Add a network key to a remote node.
    async fn add_net_key(
        &self,
        _element_path: zbus::zvariant::ObjectPath<'_>,
        _destination: u16,
        _subnet_index: u16,
        _net_index: u16,
        _update: bool,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Node1.AddNetKey called");
        Ok(())
    }

    /// Add an application key to a remote node.
    async fn add_app_key(
        &self,
        _element_path: zbus::zvariant::ObjectPath<'_>,
        _destination: u16,
        _app_index: u16,
        _net_index: u16,
        _update: bool,
    ) -> zbus::fdo::Result<()> {
        tracing::info!("Node1.AddAppKey called");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_path() {
        assert_eq!(MESH_OBJECT_PATH, "/org/bluez/mesh");
    }
}
