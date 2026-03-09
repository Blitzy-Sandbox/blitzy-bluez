// SPDX-License-Identifier: GPL-2.0-or-later
//
// Mesh models — replaces mesh/model.c
//
// Defines SIG and vendor model identifiers, publish/subscribe state.

use std::collections::HashSet;

/// A mesh model identifier — either a SIG model (16-bit) or vendor model (company + model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelId {
    /// SIG-defined model (16-bit).
    Sig(u16),
    /// Vendor-defined model (company_id, model_id).
    Vendor(u16, u16),
}

// Well-known SIG model IDs.
impl ModelId {
    pub const CONFIG_SERVER: Self = Self::Sig(0x0000);
    pub const CONFIG_CLIENT: Self = Self::Sig(0x0001);
    pub const HEALTH_SERVER: Self = Self::Sig(0x0002);
    pub const HEALTH_CLIENT: Self = Self::Sig(0x0003);
    pub const GENERIC_ONOFF_SERVER: Self = Self::Sig(0x1000);
    pub const GENERIC_ONOFF_CLIENT: Self = Self::Sig(0x1001);
    pub const GENERIC_LEVEL_SERVER: Self = Self::Sig(0x1002);
    pub const GENERIC_LEVEL_CLIENT: Self = Self::Sig(0x1003);
    pub const SENSOR_SERVER: Self = Self::Sig(0x1100);
    pub const SENSOR_CLIENT: Self = Self::Sig(0x1102);
    pub const SCENE_SERVER: Self = Self::Sig(0x1203);
    pub const SCENE_CLIENT: Self = Self::Sig(0x1205);
}

/// Publish parameters for a model.
#[derive(Debug, Clone)]
pub struct PublishInfo {
    /// Destination address for published messages.
    pub address: u16,
    /// Application key index used for publishing.
    pub app_key_index: u16,
    /// TTL for published messages (0 = use node default).
    pub ttl: u8,
    /// Publish period in milliseconds.
    pub period_ms: u32,
    /// Number of retransmissions.
    pub retransmit_count: u8,
    /// Interval between retransmissions in 50ms steps.
    pub retransmit_interval: u8,
}

/// A mesh model instance on an element.
#[derive(Debug, Clone)]
pub struct MeshModel {
    /// Model identifier.
    pub model_id: ModelId,
    /// Subscription addresses (group or virtual).
    pub subscriptions: HashSet<u16>,
    /// Bound application key indices.
    pub bindings: Vec<u16>,
    /// Publish configuration (if set).
    pub publish_info: Option<PublishInfo>,
}

impl MeshModel {
    pub fn new(model_id: ModelId) -> Self {
        Self {
            model_id,
            subscriptions: HashSet::new(),
            bindings: Vec::new(),
            publish_info: None,
        }
    }

    /// Add a subscription address.
    pub fn subscribe(&mut self, addr: u16) -> bool {
        self.subscriptions.insert(addr)
    }

    /// Remove a subscription address.
    pub fn unsubscribe(&mut self, addr: u16) -> bool {
        self.subscriptions.remove(&addr)
    }

    /// Bind an application key to this model.
    pub fn bind_key(&mut self, app_key_index: u16) -> Result<(), &'static str> {
        if self.bindings.contains(&app_key_index) {
            return Err("key already bound");
        }
        self.bindings.push(app_key_index);
        Ok(())
    }

    /// Unbind an application key from this model.
    pub fn unbind_key(&mut self, app_key_index: u16) -> bool {
        let len = self.bindings.len();
        self.bindings.retain(|&k| k != app_key_index);
        self.bindings.len() < len
    }

    /// Set publish info.
    pub fn set_publish(&mut self, info: PublishInfo) {
        self.publish_info = Some(info);
    }

    /// Clear publish info.
    pub fn clear_publish(&mut self) {
        self.publish_info = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_subscriptions() {
        let mut model = MeshModel::new(ModelId::GENERIC_ONOFF_SERVER);
        assert!(model.subscribe(0xC001));
        assert!(!model.subscribe(0xC001)); // duplicate
        assert!(model.unsubscribe(0xC001));
        assert!(!model.unsubscribe(0xC001)); // already removed
    }

    #[test]
    fn test_model_key_binding() {
        let mut model = MeshModel::new(ModelId::Vendor(0x1234, 0x0001));
        assert!(model.bind_key(0).is_ok());
        assert!(model.bind_key(1).is_ok());
        assert!(model.bind_key(0).is_err()); // already bound
        assert!(model.unbind_key(0));
        assert!(!model.unbind_key(0)); // already unbound
    }
}
