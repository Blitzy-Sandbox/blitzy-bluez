// SPDX-License-Identifier: GPL-2.0-or-later
//
// Mesh node management — replaces mesh/node.c
//
// Represents a Bluetooth Mesh node with elements, keys, and state tracking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::model::MeshModel;

/// State of a mesh node in the provisioning/configuration lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Unprovisioned,
    Provisioning,
    Provisioned,
    Configured,
}

/// A single element within a mesh node.
#[derive(Debug, Clone)]
pub struct MeshElement {
    /// Element index (0-based).
    pub index: u8,
    /// GATT Bluetooth Namespace descriptor location.
    pub location: u16,
    /// Models hosted on this element.
    pub models: Vec<MeshModel>,
}

impl MeshElement {
    pub fn new(index: u8, location: u16) -> Self {
        Self {
            index,
            location,
            models: Vec::new(),
        }
    }

    pub fn add_model(&mut self, model: MeshModel) {
        self.models.push(model);
    }
}

/// A Bluetooth Mesh node.
#[derive(Debug)]
pub struct MeshNode {
    /// Primary unicast address assigned during provisioning.
    pub unicast_addr: u16,
    /// Number of elements this node supports.
    pub num_elements: u8,
    /// Elements indexed by element index.
    pub elements: HashMap<u8, MeshElement>,
    /// Primary network key index.
    pub net_key_index: u16,
    /// Application key indices bound to this node.
    pub app_keys: Vec<u16>,
    /// Device key (128-bit).
    pub device_key: [u8; 16],
    /// Default TTL for outgoing messages.
    pub ttl: u8,
    /// Current state.
    pub state: NodeState,
    /// Sequence number counter (atomic for thread-safe increment).
    sequence_number: AtomicU32,
}

impl MeshNode {
    /// Create a new unprovisioned mesh node.
    pub fn new(num_elements: u8) -> Self {
        Self {
            unicast_addr: 0,
            num_elements,
            elements: HashMap::new(),
            net_key_index: 0,
            app_keys: Vec::new(),
            device_key: [0u8; 16],
            ttl: 7,
            state: NodeState::Unprovisioned,
            sequence_number: AtomicU32::new(0),
        }
    }

    /// Add an element to this node. Returns an error if the index is out of range.
    pub fn add_element(&mut self, element: MeshElement) -> Result<(), &'static str> {
        if element.index >= self.num_elements {
            return Err("element index exceeds num_elements");
        }
        self.elements.insert(element.index, element);
        Ok(())
    }

    /// Get a reference to an element by index.
    pub fn get_element(&self, index: u8) -> Option<&MeshElement> {
        self.elements.get(&index)
    }

    /// Get a mutable reference to an element by index.
    pub fn get_element_mut(&mut self, index: u8) -> Option<&mut MeshElement> {
        self.elements.get_mut(&index)
    }

    /// Set the default TTL. Must be 0 or in range 2..=127 per spec.
    pub fn set_ttl(&mut self, ttl: u8) -> Result<(), &'static str> {
        if ttl == 1 || ttl > 127 {
            return Err("TTL must be 0 or 2..=127");
        }
        self.ttl = ttl;
        Ok(())
    }

    /// Get and increment the sequence number (SEQ) atomically.
    pub fn next_sequence(&self) -> u32 {
        self.sequence_number.fetch_add(1, Ordering::Relaxed)
    }

    /// Get current sequence number without incrementing.
    pub fn current_sequence(&self) -> u32 {
        self.sequence_number.load(Ordering::Relaxed)
    }

    /// Transition the node to a new state.
    pub fn set_state(&mut self, state: NodeState) {
        self.state = state;
    }

    /// Assign a unicast address to this node (called during provisioning).
    pub fn set_unicast_addr(&mut self, addr: u16) {
        self.unicast_addr = addr;
    }

    /// Set the device key.
    pub fn set_device_key(&mut self, key: [u8; 16]) {
        self.device_key = key;
    }

    /// Add an application key index binding.
    pub fn bind_app_key(&mut self, app_key_index: u16) {
        if !self.app_keys.contains(&app_key_index) {
            self.app_keys.push(app_key_index);
        }
    }

    /// Remove an application key index binding.
    pub fn unbind_app_key(&mut self, app_key_index: u16) {
        self.app_keys.retain(|&k| k != app_key_index);
    }
}

/// D-Bus interface path for mesh nodes.
pub const MESH_NODE_IFACE: &str = "org.bluez.mesh.Node1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation_and_elements() {
        let mut node = MeshNode::new(3);
        assert_eq!(node.state, NodeState::Unprovisioned);
        assert_eq!(node.num_elements, 3);

        let elem0 = MeshElement::new(0, 0x0100);
        let elem1 = MeshElement::new(1, 0x0101);
        assert!(node.add_element(elem0).is_ok());
        assert!(node.add_element(elem1).is_ok());

        // Out of range
        let elem_bad = MeshElement::new(5, 0x0000);
        assert!(node.add_element(elem_bad).is_err());

        assert!(node.get_element(0).is_some());
        assert!(node.get_element(2).is_none());
    }

    #[test]
    fn test_ttl_validation() {
        let mut node = MeshNode::new(1);
        assert!(node.set_ttl(0).is_ok());
        assert!(node.set_ttl(7).is_ok());
        assert!(node.set_ttl(127).is_ok());
        assert!(node.set_ttl(1).is_err()); // 1 is reserved
        assert!(node.set_ttl(128).is_err()); // > 127
    }

    #[test]
    fn test_sequence_number() {
        let node = MeshNode::new(1);
        assert_eq!(node.next_sequence(), 0);
        assert_eq!(node.next_sequence(), 1);
        assert_eq!(node.next_sequence(), 2);
        assert_eq!(node.current_sequence(), 3);
    }
}
