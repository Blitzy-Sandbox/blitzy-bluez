// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2018-2019 Intel Corporation. All rights reserved.
//
// JSON-backed mesh configuration persistence backend.
// Stub — full implementation provided by dedicated agent.

use std::path::PathBuf;
use std::time::Instant;

use super::{
    MeshConfig, MeshConfigError, MeshConfigNode, MeshConfigNodeFn, MeshConfigPub,
    MeshConfigStatusFn, MeshConfigSub,
};

/// JSON-backed implementation of the [`MeshConfig`] trait.
///
/// Persists mesh node configuration as `node.json` files within a directory
/// hierarchy organized by node UUID. This is the concrete implementation
/// replacing the C `mesh-config-json.c` module.
pub struct MeshConfigJson {
    /// In-memory JSON representation of node configuration.
    pub(crate) node_data: serde_json::Value,
    /// Filesystem path to the node directory.
    pub(crate) node_dir_path: PathBuf,
    /// 16-byte UUID of the node.
    pub(crate) uuid: [u8; 16],
    /// Last written sequence number (for caching).
    pub(crate) write_seq: u32,
    /// Timestamp of last write.
    pub(crate) write_time: Instant,
}

impl MeshConfig for MeshConfigJson {
    fn load_nodes(&self, _cfgdir: &str, _cb: MeshConfigNodeFn) -> Result<bool, MeshConfigError> {
        if self.node_data.is_null() {
            return Err(MeshConfigError::Invalid("no node data loaded".into()));
        }
        if self.uuid.iter().all(|&b| b == 0) {
            return Err(MeshConfigError::Invalid("null UUID".into()));
        }
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn release(&mut self) {
        self.node_data = serde_json::Value::Null;
        self.write_seq = 0;
    }

    fn destroy_nvm(&self) {
        // Remove the node directory from the filesystem.
        // Full implementation will recursively delete node_dir_path contents.
        let _path = &self.node_dir_path;
    }

    fn save(
        &self,
        _no_wait: bool,
        _cb: Option<MeshConfigStatusFn>,
    ) -> Result<bool, MeshConfigError> {
        if self.node_dir_path.as_os_str().is_empty() {
            return Err(MeshConfigError::Invalid("no node directory configured".into()));
        }
        let _seq = self.write_seq;
        let _ts = self.write_time;
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn reset(&mut self, _node: &MeshConfigNode) {
        self.node_data = serde_json::Value::Null;
    }

    fn create(
        cfgdir: &str,
        uuid: &[u8; 16],
        _node: &MeshConfigNode,
    ) -> Result<Self, MeshConfigError>
    where
        Self: Sized,
    {
        let node_dir = PathBuf::from(cfgdir);
        if !node_dir.exists() {
            return Err(MeshConfigError::CreationFailed);
        }
        Ok(MeshConfigJson {
            node_data: serde_json::Value::Object(serde_json::Map::new()),
            node_dir_path: node_dir,
            uuid: *uuid,
            write_seq: 0,
            write_time: Instant::now(),
        })
    }

    fn write_net_transmit(&mut self, _count: u16, _interval: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_device_key(&mut self, _key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_candidate(&mut self, _key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn read_candidate(&self) -> Option<[u8; 16]> {
        None
    }

    fn finalize_candidate(&mut self) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_token(&mut self, _token: &[u8; 8]) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_seq_number(&mut self, seq: u32, _cache: bool) -> Result<bool, MeshConfigError> {
        self.write_seq = seq;
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_unicast(&mut self, _unicast: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_relay_mode(
        &mut self,
        _mode: u8,
        _count: u16,
        _interval: u16,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_mpb(&mut self, _mode: u8, _period: u8) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_ttl(&mut self, _ttl: u8) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_mode(&mut self, _keyword: &str, _value: u8) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_mode_ex(
        &mut self,
        _keyword: &str,
        _value: u8,
        _save: bool,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn comp_page_add(&mut self, _page: u8, _data: &[u8]) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn comp_page_del(&mut self, _page: u8) {}

    fn model_binding_add(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
        _app_idx: u16,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_binding_del(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
        _app_idx: u16,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_pub_add(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
        _pub_config: &MeshConfigPub,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_pub_del(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_pub_enable(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
        _enable: bool,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_sub_add(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
        _sub: &MeshConfigSub,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_sub_del(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
        _sub: &MeshConfigSub,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_sub_del_all(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn model_sub_enable(
        &mut self,
        _ele_addr: u16,
        _mod_id: u32,
        _vendor: bool,
        _enable: bool,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn app_key_add(
        &mut self,
        _net_idx: u16,
        _app_idx: u16,
        _key: &[u8; 16],
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn app_key_update(
        &mut self,
        _net_idx: u16,
        _app_idx: u16,
        _key: &[u8; 16],
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn app_key_del(&mut self, _net_idx: u16, _app_idx: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn net_key_add(&mut self, _idx: u16, _key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn net_key_update(&mut self, _idx: u16, _key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn net_key_del(&mut self, _idx: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn net_key_set_phase(&mut self, _idx: u16, _phase: u8) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn write_iv_index(
        &mut self,
        _iv_index: u32,
        _iv_update: bool,
    ) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn update_company_id(&mut self, _cid: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn update_product_id(&mut self, _pid: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn update_version_id(&mut self, _vid: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }

    fn update_crpl(&mut self, _crpl: u16) -> Result<bool, MeshConfigError> {
        Err(MeshConfigError::Invalid("not yet implemented".into()))
    }
}
