// SPDX-License-Identifier: GPL-2.0-or-later
//
// LE link layer simulation replacing emulator/le.c
//
// Simulates LE controller behavior: advertising, scanning, connection
// establishment, and data channel management.

use std::sync::{Arc, Mutex};

/// LE address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeAddrType {
    Public = 0x00,
    Random = 0x01,
    PublicIdentity = 0x02,
    RandomIdentity = 0x03,
}

impl LeAddrType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Random,
            0x02 => Self::PublicIdentity,
            0x03 => Self::RandomIdentity,
            _ => Self::Public,
        }
    }
}

/// LE advertising state.
#[derive(Debug, Clone)]
pub struct LeAdvState {
    pub enabled: bool,
    pub adv_type: u8,
    pub own_addr_type: u8,
    pub direct_addr_type: u8,
    pub direct_addr: [u8; 6],
    pub adv_data: Vec<u8>,
    pub scan_rsp_data: Vec<u8>,
    pub filter_policy: u8,
    pub adv_interval_min: u16,
    pub adv_interval_max: u16,
    pub channel_map: u8,
}

impl Default for LeAdvState {
    fn default() -> Self {
        Self {
            enabled: false,
            adv_type: 0x00,
            own_addr_type: 0x00,
            direct_addr_type: 0x00,
            direct_addr: [0; 6],
            adv_data: Vec::new(),
            scan_rsp_data: Vec::new(),
            filter_policy: 0x00,
            adv_interval_min: 0x0800,
            adv_interval_max: 0x0800,
            channel_map: 0x07,
        }
    }
}

/// LE scan state.
#[derive(Debug, Clone)]
pub struct LeScanState {
    pub enabled: bool,
    pub scan_type: u8,
    pub own_addr_type: u8,
    pub filter_policy: u8,
    pub filter_dup: bool,
    pub scan_interval: u16,
    pub scan_window: u16,
}

impl Default for LeScanState {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_type: 0x00,
            own_addr_type: 0x00,
            filter_policy: 0x00,
            filter_dup: false,
            scan_interval: 0x0010,
            scan_window: 0x0010,
        }
    }
}

/// Extended advertising set.
#[derive(Debug, Clone)]
pub struct LeExtAdvSet {
    pub handle: u8,
    pub enabled: bool,
    pub adv_type: u16,
    pub own_addr_type: u8,
    pub direct_addr_type: u8,
    pub direct_addr: [u8; 6],
    pub random_addr: [u8; 6],
    pub filter_policy: u8,
    pub adv_data: Vec<u8>,
    pub scan_rsp_data: Vec<u8>,
    pub sid: u8,
    pub broadcast_id: u32,
}

impl LeExtAdvSet {
    pub fn new(handle: u8) -> Self {
        Self {
            handle,
            enabled: false,
            adv_type: 0,
            own_addr_type: 0,
            direct_addr_type: 0,
            direct_addr: [0; 6],
            random_addr: [0; 6],
            filter_policy: 0,
            adv_data: Vec::new(),
            scan_rsp_data: Vec::new(),
            sid: 0,
            broadcast_id: 0,
        }
    }
}

/// Periodic advertising state.
#[derive(Debug, Clone)]
pub struct LePerAdvState {
    pub enabled: bool,
    pub properties: u16,
    pub min_interval: u16,
    pub max_interval: u16,
    pub data: Vec<u8>,
}

impl Default for LePerAdvState {
    fn default() -> Self {
        Self {
            enabled: false,
            properties: 0,
            min_interval: 0x0006,
            max_interval: 0x0050,
            data: Vec::new(),
        }
    }
}

/// Accept list entry.
#[derive(Debug, Clone)]
pub struct LeAlEntry {
    pub addr_type: u8,
    pub addr: [u8; 6],
}

/// Resolving list entry.
#[derive(Debug, Clone)]
pub struct LeRlEntry {
    pub addr_type: u8,
    pub addr: [u8; 6],
    pub peer_irk: [u8; 16],
    pub local_irk: [u8; 16],
}

/// LE controller state.
pub struct BtLe {
    inner: Arc<Mutex<BtLeInner>>,
}

#[allow(dead_code)]
struct BtLeInner {
    features: [u8; 8],
    states: [u8; 8],
    event_mask: [u8; 8],
    adv: LeAdvState,
    scan: LeScanState,
    ext_adv_sets: Vec<LeExtAdvSet>,
    per_adv: LePerAdvState,
    accept_list: Vec<LeAlEntry>,
    resolving_list: Vec<LeRlEntry>,
    al_max_len: u8,
    rl_max_len: u8,
    rl_enabled: bool,
    rl_timeout: u16,
}

impl BtLe {
    /// Create a new LE controller.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BtLeInner {
                features: [0; 8],
                states: [0xff; 8],
                event_mask: [0x1f; 8],
                adv: LeAdvState::default(),
                scan: LeScanState::default(),
                ext_adv_sets: Vec::new(),
                per_adv: LePerAdvState::default(),
                accept_list: Vec::new(),
                resolving_list: Vec::new(),
                al_max_len: 16,
                rl_max_len: 16,
                rl_enabled: false,
                rl_timeout: 0x0384,
            })),
        }
    }

    /// Clone the Arc for sharing.
    pub fn clone_ref(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Set LE features.
    pub fn set_features(&self, features: &[u8; 8]) {
        self.inner.lock().unwrap().features = *features;
    }

    /// Get LE features.
    pub fn get_features(&self) -> [u8; 8] {
        self.inner.lock().unwrap().features
    }

    /// Set LE states.
    pub fn set_states(&self, states: &[u8; 8]) {
        self.inner.lock().unwrap().states = *states;
    }

    /// Get LE states.
    pub fn get_states(&self) -> [u8; 8] {
        self.inner.lock().unwrap().states
    }

    /// Set accept list max length.
    pub fn set_al_len(&self, len: u8) {
        self.inner.lock().unwrap().al_max_len = len;
    }

    /// Set resolving list max length.
    pub fn set_rl_len(&self, len: u8) {
        self.inner.lock().unwrap().rl_max_len = len;
    }

    /// Add to accept list.
    pub fn al_add(&self, addr_type: u8, addr: &[u8; 6]) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.accept_list.len() >= inner.al_max_len as usize {
            return false;
        }
        // Check for duplicates
        if inner
            .accept_list
            .iter()
            .any(|e| e.addr_type == addr_type && e.addr == *addr)
        {
            return false;
        }
        inner.accept_list.push(LeAlEntry {
            addr_type,
            addr: *addr,
        });
        true
    }

    /// Remove from accept list.
    pub fn al_remove(&self, addr_type: u8, addr: &[u8; 6]) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.accept_list.len();
        inner
            .accept_list
            .retain(|e| !(e.addr_type == addr_type && e.addr == *addr));
        inner.accept_list.len() < before
    }

    /// Clear accept list.
    pub fn al_clear(&self) {
        self.inner.lock().unwrap().accept_list.clear();
    }

    /// Get accept list size.
    pub fn al_size(&self) -> usize {
        self.inner.lock().unwrap().accept_list.len()
    }

    /// Add to resolving list.
    pub fn rl_add(
        &self,
        addr_type: u8,
        addr: &[u8; 6],
        peer_irk: &[u8; 16],
        local_irk: &[u8; 16],
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.resolving_list.len() >= inner.rl_max_len as usize {
            return false;
        }
        inner.resolving_list.push(LeRlEntry {
            addr_type,
            addr: *addr,
            peer_irk: *peer_irk,
            local_irk: *local_irk,
        });
        true
    }

    /// Clear resolving list.
    pub fn rl_clear(&self) {
        self.inner.lock().unwrap().resolving_list.clear();
    }

    /// Enable/disable address resolution.
    pub fn set_rl_enabled(&self, enabled: bool) {
        self.inner.lock().unwrap().rl_enabled = enabled;
    }

    /// Set advertising parameters.
    pub fn set_adv_params(
        &self,
        adv_type: u8,
        own_addr_type: u8,
        direct_addr_type: u8,
        direct_addr: &[u8; 6],
        filter_policy: u8,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.adv.adv_type = adv_type;
        inner.adv.own_addr_type = own_addr_type;
        inner.adv.direct_addr_type = direct_addr_type;
        inner.adv.direct_addr = *direct_addr;
        inner.adv.filter_policy = filter_policy;
    }

    /// Set advertising data.
    pub fn set_adv_data(&self, data: &[u8]) {
        self.inner.lock().unwrap().adv.adv_data = data.to_vec();
    }

    /// Set scan response data.
    pub fn set_scan_rsp_data(&self, data: &[u8]) {
        self.inner.lock().unwrap().adv.scan_rsp_data = data.to_vec();
    }

    /// Enable/disable advertising.
    pub fn set_adv_enable(&self, enabled: bool) {
        self.inner.lock().unwrap().adv.enabled = enabled;
    }

    /// Check if advertising is enabled.
    pub fn is_adv_enabled(&self) -> bool {
        self.inner.lock().unwrap().adv.enabled
    }

    /// Set scan parameters.
    pub fn set_scan_params(&self, scan_type: u8, own_addr_type: u8, filter_policy: u8) {
        let mut inner = self.inner.lock().unwrap();
        inner.scan.scan_type = scan_type;
        inner.scan.own_addr_type = own_addr_type;
        inner.scan.filter_policy = filter_policy;
    }

    /// Enable/disable scanning.
    pub fn set_scan_enable(&self, enabled: bool, filter_dup: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.scan.enabled = enabled;
        inner.scan.filter_dup = filter_dup;
    }

    /// Check if scanning is enabled.
    pub fn is_scan_enabled(&self) -> bool {
        self.inner.lock().unwrap().scan.enabled
    }

    /// Add an extended advertising set.
    pub fn add_ext_adv_set(&self, handle: u8) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.ext_adv_sets.iter().any(|s| s.handle == handle) {
            return false;
        }
        inner.ext_adv_sets.push(LeExtAdvSet::new(handle));
        true
    }

    /// Remove an extended advertising set.
    pub fn remove_ext_adv_set(&self, handle: u8) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.ext_adv_sets.len();
        inner.ext_adv_sets.retain(|s| s.handle != handle);
        inner.ext_adv_sets.len() < before
    }

    /// Clear all extended advertising sets.
    pub fn clear_ext_adv_sets(&self) {
        self.inner.lock().unwrap().ext_adv_sets.clear();
    }
}

impl Default for BtLe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_le_accept_list() {
        let le = BtLe::new();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

        assert!(le.al_add(0, &addr));
        assert!(!le.al_add(0, &addr)); // duplicate
        assert_eq!(le.al_size(), 1);

        assert!(le.al_remove(0, &addr));
        assert_eq!(le.al_size(), 0);
    }

    #[test]
    fn test_le_accept_list_max() {
        let le = BtLe::new();
        le.set_al_len(2);

        let addr1 = [0x01; 6];
        let addr2 = [0x02; 6];
        let addr3 = [0x03; 6];

        assert!(le.al_add(0, &addr1));
        assert!(le.al_add(0, &addr2));
        assert!(!le.al_add(0, &addr3)); // full
    }

    #[test]
    fn test_le_resolving_list() {
        let le = BtLe::new();
        let addr = [0x01; 6];
        let irk = [0xAA; 16];

        assert!(le.rl_add(0, &addr, &irk, &irk));
        le.set_rl_enabled(true);
        le.rl_clear();
    }

    #[test]
    fn test_le_adv_state() {
        let le = BtLe::new();
        assert!(!le.is_adv_enabled());
        le.set_adv_enable(true);
        assert!(le.is_adv_enabled());
        le.set_adv_data(&[0x02, 0x01, 0x06]);
    }

    #[test]
    fn test_le_scan_state() {
        let le = BtLe::new();
        assert!(!le.is_scan_enabled());
        le.set_scan_enable(true, false);
        assert!(le.is_scan_enabled());
    }

    #[test]
    fn test_le_ext_adv() {
        let le = BtLe::new();
        assert!(le.add_ext_adv_set(0));
        assert!(!le.add_ext_adv_set(0)); // duplicate
        assert!(le.add_ext_adv_set(1));
        assert!(le.remove_ext_adv_set(0));
        le.clear_ext_adv_sets();
    }

    #[test]
    fn test_le_features() {
        let le = BtLe::new();
        let feat = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        le.set_features(&feat);
        assert_eq!(le.get_features(), feat);
    }

    #[test]
    fn test_le_addr_type() {
        assert_eq!(LeAddrType::from_u8(0), LeAddrType::Public);
        assert_eq!(LeAddrType::from_u8(1), LeAddrType::Random);
        assert_eq!(LeAddrType::from_u8(2), LeAddrType::PublicIdentity);
        assert_eq!(LeAddrType::from_u8(3), LeAddrType::RandomIdentity);
        assert_eq!(LeAddrType::from_u8(99), LeAddrType::Public);
    }
}
