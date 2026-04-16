// SPDX-License-Identifier: GPL-2.0-or-later
//
// SDP server stub replacing src/sdpd-server.c, sdpd-request.c,
// sdpd-service.c, sdpd-database.c (~4K LOC)
//
// The SDP server manages the Service Discovery Protocol database and
// handles SDP queries from remote BR/EDR devices.

use std::collections::HashMap;

/// An SDP service record.
#[derive(Debug, Clone)]
pub struct SdpRecord {
    pub handle: u32,
    pub service_class_uuids: Vec<u16>,
    pub profile_descriptors: Vec<(u16, u16)>,
    pub name: String,
    pub description: String,
    pub provider: String,
    pub attrs: HashMap<u16, Vec<u8>>,
}

/// SDP server state.
#[derive(Debug, Default)]
pub struct SdpServer {
    records: Vec<SdpRecord>,
    next_handle: u32,
}

impl SdpServer {
    /// Create a new SDP server.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            next_handle: 0x00010000,
        }
    }

    /// Start the SDP server.
    pub fn start(&mut self) -> Result<(), std::io::Error> {
        // On Linux this would open an L2CAP socket on PSM 1.
        // Stub for now.
        Ok(())
    }

    /// Stop the SDP server.
    pub fn stop(&mut self) {
        self.records.clear();
    }

    /// Register a service record and return its handle.
    pub fn register_record(&mut self, mut record: SdpRecord) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        record.handle = handle;
        self.records.push(record);
        handle
    }

    /// Unregister a service record by handle.
    pub fn unregister_record(&mut self, handle: u32) -> bool {
        let len = self.records.len();
        self.records.retain(|r| r.handle != handle);
        self.records.len() < len
    }

    /// Find records matching a service class UUID.
    pub fn search(&self, uuid: u16) -> Vec<&SdpRecord> {
        self.records
            .iter()
            .filter(|r| r.service_class_uuids.contains(&uuid))
            .collect()
    }

    /// Get a record by handle.
    pub fn get_record(&self, handle: u32) -> Option<&SdpRecord> {
        self.records.iter().find(|r| r.handle == handle)
    }

    /// Get the number of registered records.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a minimal SDP record
    fn make_record(uuid: u16, name: &str) -> SdpRecord {
        SdpRecord {
            handle: 0,
            service_class_uuids: vec![uuid],
            profile_descriptors: vec![(uuid, 0x0100)],
            name: name.to_string(),
            description: String::new(),
            provider: String::new(),
            attrs: HashMap::new(),
        }
    }

    // ---- Lifecycle tests (from test-sdp.c setup/teardown) ----

    #[test]
    fn test_sdp_server_lifecycle() {
        let mut server = SdpServer::new();
        assert!(server.start().is_ok());
        assert_eq!(server.record_count(), 0);
        server.stop();
    }

    // ---- Register/unregister (from test-sdp.c register_serial_port) ----

    #[test]
    fn test_register_serial_port() {
        let mut server = SdpServer::new();
        // Serial Port Profile UUID from test-sdp.c
        let record = make_record(0x1101, "Serial Port");
        let handle = server.register_record(record);
        assert_eq!(server.record_count(), 1);
        assert!(server.get_record(handle).is_some());

        let results = server.search(0x1101);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Serial Port");
    }

    // ---- Search miss ----

    #[test]
    fn test_search_miss() {
        let mut server = SdpServer::new();
        server.register_record(make_record(0x1101, "SP"));
        assert!(server.search(0x1102).is_empty());
    }

    // ---- Unregister ----

    #[test]
    fn test_unregister() {
        let mut server = SdpServer::new();
        let handle = server.register_record(make_record(0x1101, "SP"));
        assert!(server.unregister_record(handle));
        assert_eq!(server.record_count(), 0);
        assert!(!server.unregister_record(handle)); // double-unregister fails
    }

    // ---- Multiple records (from test-sdp.c multiple service registrations) ----

    #[test]
    fn test_multiple_records() {
        let mut server = SdpServer::new();
        for i in 0..5 {
            server.register_record(make_record(0x1100 + i, &format!("Service {}", i)));
        }
        assert_eq!(server.record_count(), 5);
    }

    // ---- Handle auto-increment ----

    #[test]
    fn test_handle_auto_increment() {
        let mut server = SdpServer::new();
        let h1 = server.register_record(make_record(0x1101, "A"));
        let h2 = server.register_record(make_record(0x1102, "B"));
        assert_eq!(h2, h1 + 1);
    }

    // ---- Search with multiple matching records ----

    #[test]
    fn test_search_multiple_matches() {
        let mut server = SdpServer::new();
        // Register multiple records with the same service class UUID
        server.register_record(make_record(0x1101, "SP1"));
        server.register_record(make_record(0x1101, "SP2"));
        server.register_record(make_record(0x1102, "Other"));
        let results = server.search(0x1101);
        assert_eq!(results.len(), 2);
    }

    // ---- Get record by handle ----

    #[test]
    fn test_get_record_by_handle() {
        let mut server = SdpServer::new();
        let h = server.register_record(make_record(0x1101, "TestSP"));
        let rec = server.get_record(h).unwrap();
        assert_eq!(rec.name, "TestSP");
        assert_eq!(rec.handle, h);

        // Non-existent handle
        assert!(server.get_record(0xDEADBEEF).is_none());
    }

    // ---- Attribute storage (from test-sdp.c sdp_attr_add) ----

    #[test]
    fn test_attribute_storage() {
        let mut server = SdpServer::new();
        let mut record = make_record(0x1101, "SP");
        // SDP_ATTR_RECORD_HANDLE = 0x0000
        record.attrs.insert(0x0000, vec![0x00, 0x01, 0x00, 0x00]);
        // SDP_ATTR_BROWSE_GROUP = 0x0005
        record.attrs.insert(0x0005, vec![0x10, 0x02]);
        let h = server.register_record(record);
        let r = server.get_record(h).unwrap();
        assert_eq!(r.attrs.len(), 2);
        assert_eq!(r.attrs[&0x0000], vec![0x00, 0x01, 0x00, 0x00]);
    }

    // ---- Profile descriptors ----

    #[test]
    fn test_profile_descriptors() {
        let mut server = SdpServer::new();
        let mut record = make_record(0x1101, "SP");
        record.profile_descriptors = vec![
            (0x1101, 0x0100), // Serial Port v1.0
            (0x1108, 0x0102), // Headset v1.2
        ];
        let h = server.register_record(record);
        let r = server.get_record(h).unwrap();
        assert_eq!(r.profile_descriptors.len(), 2);
        assert_eq!(r.profile_descriptors[0], (0x1101, 0x0100));
        assert_eq!(r.profile_descriptors[1], (0x1108, 0x0102));
    }

    // ---- Stop clears all records ----

    #[test]
    fn test_stop_clears_records() {
        let mut server = SdpServer::new();
        server.register_record(make_record(0x1101, "A"));
        server.register_record(make_record(0x1102, "B"));
        assert_eq!(server.record_count(), 2);
        server.stop();
        assert_eq!(server.record_count(), 0);
    }

    // ---- Unregister middle record ----

    #[test]
    fn test_unregister_middle() {
        let mut server = SdpServer::new();
        let h1 = server.register_record(make_record(0x1101, "A"));
        let h2 = server.register_record(make_record(0x1102, "B"));
        let h3 = server.register_record(make_record(0x1103, "C"));
        assert!(server.unregister_record(h2));
        assert_eq!(server.record_count(), 2);
        assert!(server.get_record(h1).is_some());
        assert!(server.get_record(h2).is_none());
        assert!(server.get_record(h3).is_some());
    }

    // ---- Multiple UUIDs per record ----

    #[test]
    fn test_multiple_uuids_per_record() {
        let mut server = SdpServer::new();
        let record = SdpRecord {
            handle: 0,
            service_class_uuids: vec![0x1101, 0x1102],
            profile_descriptors: vec![],
            name: "Multi".to_string(),
            description: String::new(),
            provider: String::new(),
            attrs: HashMap::new(),
        };
        server.register_record(record);
        assert_eq!(server.search(0x1101).len(), 1);
        assert_eq!(server.search(0x1102).len(), 1);
        assert_eq!(server.search(0x1103).len(), 0);
    }
}
