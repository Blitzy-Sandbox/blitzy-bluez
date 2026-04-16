// SPDX-License-Identifier: GPL-2.0-or-later
//
// LE advertisement manager replacing src/advertising.c (2,161 LOC).
// Manages Bluetooth Low Energy advertising instances registered over D-Bus,
// enforcing the controller's maximum advertisement limit.

use std::collections::HashMap;

use crate::error::BtdError;

/// Type of LE advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvType {
    Broadcast,
    Peripheral,
}

impl AdvType {
    /// Returns the D-Bus string representation of this advertisement type.
    pub fn as_str(&self) -> &'static str {
        match self {
            AdvType::Broadcast => "broadcast",
            AdvType::Peripheral => "peripheral",
        }
    }
}

/// A registered LE advertisement instance.
#[derive(Debug, Clone)]
pub struct Advertisement {
    /// Type of advertisement.
    pub adv_type: AdvType,
    /// Service UUIDs to include in the advertisement.
    pub service_uuids: Vec<String>,
    /// Manufacturer-specific data keyed by company ID.
    pub manufacturer_data: HashMap<u16, Vec<u8>>,
    /// Service data keyed by service UUID.
    pub service_data: HashMap<String, Vec<u8>>,
    /// Local name to include in the advertisement.
    pub local_name: Option<String>,
    /// GAP appearance value.
    pub appearance: Option<u16>,
    /// Duration in seconds of each advertisement.
    pub duration: u16,
    /// Timeout in seconds after which the advertisement is removed.
    pub timeout: u16,
    /// D-Bus object path of the advertisement.
    pub path: String,
    /// D-Bus unique name of the advertisement's owner.
    pub owner: String,
}

/// Manages LE advertisement instances, enforcing a controller-specific limit.
#[derive(Debug)]
pub struct AdvManager {
    advertisements: Vec<Advertisement>,
    max_advs: u8,
}

impl AdvManager {
    /// Creates a new advertisement manager with the given maximum instance
    /// count.
    pub fn new(max: u8) -> Self {
        Self {
            advertisements: Vec::new(),
            max_advs: max,
        }
    }

    /// Registers a new advertisement, returning its instance ID (0-based
    /// index).
    ///
    /// Returns an error if the maximum number of advertisements has been
    /// reached.
    pub fn register(&mut self, adv: Advertisement) -> Result<u8, BtdError> {
        if self.advertisements.len() >= self.max_advs as usize {
            return Err(BtdError::new(
                crate::error::ERROR_NOT_PERMITTED,
                "Maximum advertisements reached",
            ));
        }

        let id = self.advertisements.len() as u8;
        self.advertisements.push(adv);
        Ok(id)
    }

    /// Removes an advertisement by its D-Bus object path.
    pub fn unregister(&mut self, path: &str) -> Result<(), BtdError> {
        let idx = self
            .advertisements
            .iter()
            .position(|a| a.path == path)
            .ok_or_else(|| {
                BtdError::new(
                    crate::error::ERROR_DOES_NOT_EXIST,
                    "Advertisement not registered",
                )
            })?;

        self.advertisements.remove(idx);
        Ok(())
    }

    /// Returns the number of currently active advertisements.
    pub fn active_count(&self) -> usize {
        self.advertisements.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_adv(path: &str) -> Advertisement {
        Advertisement {
            adv_type: AdvType::Peripheral,
            service_uuids: vec!["0000180f-0000-1000-8000-00805f9b34fb".into()],
            manufacturer_data: HashMap::new(),
            service_data: HashMap::new(),
            local_name: Some("TestDevice".into()),
            appearance: None,
            duration: 2,
            timeout: 0,
            path: path.into(),
            owner: ":1.1".into(),
        }
    }

    #[test]
    fn test_adv_register() {
        let mut mgr = AdvManager::new(4);
        let id = mgr.register(sample_adv("/test/adv0")).unwrap();
        assert_eq!(id, 0);
        assert_eq!(mgr.active_count(), 1);

        let id = mgr.register(sample_adv("/test/adv1")).unwrap();
        assert_eq!(id, 1);
        assert_eq!(mgr.active_count(), 2);
    }

    #[test]
    fn test_adv_max_limit() {
        let mut mgr = AdvManager::new(2);
        mgr.register(sample_adv("/test/adv0")).unwrap();
        mgr.register(sample_adv("/test/adv1")).unwrap();

        // Third registration must fail.
        assert!(mgr.register(sample_adv("/test/adv2")).is_err());
    }

    #[test]
    fn test_adv_unregister() {
        let mut mgr = AdvManager::new(4);
        mgr.register(sample_adv("/test/adv0")).unwrap();
        mgr.register(sample_adv("/test/adv1")).unwrap();

        mgr.unregister("/test/adv0").unwrap();
        assert_eq!(mgr.active_count(), 1);

        // Double-unregister must fail.
        assert!(mgr.unregister("/test/adv0").is_err());
    }
}
