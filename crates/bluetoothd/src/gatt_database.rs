// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT local database management replacing src/gatt-database.c (4,306 LOC).
// Manages locally registered GATT applications (services, characteristics,
// descriptors) exposed over D-Bus and mapped into the attribute database.

use crate::error::BtdError;

/// A GATT service registered via an application.
#[derive(Debug, Clone)]
pub struct GattAppService {
    /// D-Bus object path of the service.
    pub path: String,
    /// Service UUID.
    pub uuid: String,
    /// Whether this is a primary (vs. secondary) service.
    pub primary: bool,
    /// Handle range (start, end) allocated in the attribute database.
    pub handles: (u16, u16),
}

/// Manages GATT applications and their services in the local database.
#[derive(Debug)]
pub struct GattDatabase {
    services: Vec<GattAppService>,
    next_handle: u16,
}

impl GattDatabase {
    /// Creates a new, empty GATT database.
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
            next_handle: 1,
        }
    }

    /// Registers a GATT application, allocating handle ranges for its
    /// services.
    ///
    /// In this initial implementation a single service per application is
    /// assumed, with a fixed handle span of 16.
    pub fn register_application(
        &mut self,
        path: String,
        owner: String,
    ) -> Result<(), BtdError> {
        if self.services.iter().any(|s| s.path == path) {
            return Err(BtdError::new(
                crate::error::ERROR_ALREADY_EXISTS,
                "Application already registered",
            ));
        }

        let start = self.next_handle;
        let end = start + 15; // reserve 16 handles
        self.next_handle = end + 1;

        self.services.push(GattAppService {
            path,
            uuid: owner,
            primary: true,
            handles: (start, end),
        });

        Ok(())
    }

    /// Removes a previously registered application by path.
    pub fn unregister_application(&mut self, path: &str) -> Result<(), BtdError> {
        let idx = self
            .services
            .iter()
            .position(|s| s.path == path)
            .ok_or_else(|| {
                BtdError::new(
                    crate::error::ERROR_DOES_NOT_EXIST,
                    "Application not registered",
                )
            })?;

        self.services.remove(idx);
        Ok(())
    }

    /// Returns the number of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }
}

impl Default for GattDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gatt_db_register() {
        let mut db = GattDatabase::new();
        db.register_application("/test/app1".into(), ":1.1".into())
            .unwrap();
        assert_eq!(db.service_count(), 1);

        // Verify handle allocation.
        let svc = &db.services[0];
        assert_eq!(svc.handles, (1, 16));
        assert!(svc.primary);

        // Second application gets the next handle range.
        db.register_application("/test/app2".into(), ":1.2".into())
            .unwrap();
        assert_eq!(db.services[1].handles, (17, 32));
        assert_eq!(db.service_count(), 2);

        // Duplicate path must fail.
        assert!(db
            .register_application("/test/app1".into(), ":1.1".into())
            .is_err());
    }

    #[test]
    fn test_gatt_db_unregister() {
        let mut db = GattDatabase::new();
        db.register_application("/test/app".into(), ":1.1".into())
            .unwrap();

        db.unregister_application("/test/app").unwrap();
        assert_eq!(db.service_count(), 0);

        // Double-unregister must fail.
        assert!(db.unregister_application("/test/app").is_err());
    }
}
