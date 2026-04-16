// SPDX-License-Identifier: GPL-2.0-or-later
//
// Application key management — replaces mesh/appkey.c

use std::collections::HashMap;

/// An application key bound to a network key.
#[derive(Debug, Clone)]
pub struct AppKey {
    /// Application key index (12-bit).
    pub index: u16,
    /// Bound network key index.
    pub net_key_index: u16,
    /// Current 128-bit key.
    pub key: [u8; 16],
    /// Updated key during key refresh (if any).
    pub updated_key: Option<[u8; 16]>,
}

impl AppKey {
    pub fn new(index: u16, net_key_index: u16, key: [u8; 16]) -> Self {
        Self {
            index,
            net_key_index,
            key,
            updated_key: None,
        }
    }
}

/// Storage for application keys.
#[derive(Debug, Default)]
pub struct AppKeyStore {
    keys: HashMap<u16, AppKey>,
}

impl AppKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a new application key. Returns error if index already exists.
    pub fn add(&mut self, key: AppKey) -> Result<(), &'static str> {
        if self.keys.contains_key(&key.index) {
            return Err("app key index already exists");
        }
        self.keys.insert(key.index, key);
        Ok(())
    }

    /// Remove an application key by index.
    pub fn remove(&mut self, index: u16) -> Option<AppKey> {
        self.keys.remove(&index)
    }

    /// Get an application key by index.
    pub fn get(&self, index: u16) -> Option<&AppKey> {
        self.keys.get(&index)
    }

    /// Update an application key (for key refresh).
    pub fn update(&mut self, index: u16, new_key: [u8; 16]) -> Result<(), &'static str> {
        match self.keys.get_mut(&index) {
            Some(k) => {
                k.updated_key = Some(new_key);
                Ok(())
            }
            None => Err("app key not found"),
        }
    }

    /// Complete key refresh for a key: swap updated_key into key.
    pub fn finalize_refresh(&mut self, index: u16) -> Result<(), &'static str> {
        match self.keys.get_mut(&index) {
            Some(k) => match k.updated_key.take() {
                Some(new) => {
                    k.key = new;
                    Ok(())
                }
                None => Err("no updated key pending"),
            },
            None => Err("app key not found"),
        }
    }

    /// List all application key indices.
    pub fn indices(&self) -> Vec<u16> {
        self.keys.keys().copied().collect()
    }

    /// List all application key indices bound to a specific network key.
    pub fn indices_for_net_key(&self, net_key_index: u16) -> Vec<u16> {
        self.keys
            .values()
            .filter(|k| k.net_key_index == net_key_index)
            .map(|k| k.index)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_remove_get() {
        let mut store = AppKeyStore::new();
        let key = AppKey::new(0, 0, [0xAA; 16]);
        assert!(store.add(key).is_ok());
        assert!(store.add(AppKey::new(0, 0, [0xBB; 16])).is_err()); // dup

        assert!(store.get(0).is_some());
        assert!(store.get(1).is_none());

        let removed = store.remove(0);
        assert!(removed.is_some());
        assert!(store.get(0).is_none());
    }

    #[test]
    fn test_key_refresh() {
        let mut store = AppKeyStore::new();
        store.add(AppKey::new(5, 0, [0x11; 16])).unwrap();

        store.update(5, [0x22; 16]).unwrap();
        assert_eq!(store.get(5).unwrap().updated_key, Some([0x22; 16]));

        store.finalize_refresh(5).unwrap();
        assert_eq!(store.get(5).unwrap().key, [0x22; 16]);
        assert!(store.get(5).unwrap().updated_key.is_none());
    }
}
