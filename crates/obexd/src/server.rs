// SPDX-License-Identifier: GPL-2.0-or-later
//! OBEX server — replaces obexd/src/server.c.
//!
//! Manages transport listeners and dispatches incoming OBEX connections
//! to the appropriate service handler.

use std::collections::HashMap;
use std::sync::Arc;

/// Transport type for OBEX connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObexTransport {
    /// Bluetooth RFCOMM/L2CAP transport.
    Bluetooth,
    /// USB transport.
    Usb,
}

/// A registered OBEX service handler.
pub trait ObexService: Send + Sync {
    /// Service name for identification.
    fn name(&self) -> &str;

    /// Target UUID for this service (if any).
    fn target(&self) -> Option<&[u8]>;

    /// Handle an incoming OBEX connection (stub).
    fn handle_connection(&self, session_id: u64);
}

/// The OBEX server that accepts incoming connections and dispatches them.
pub struct ObexServer {
    transport: ObexTransport,
    services: Vec<Arc<dyn ObexService>>,
    next_session_id: u64,
    /// Active session IDs mapped to service name.
    active_sessions: HashMap<u64, String>,
}

impl ObexServer {
    /// Create a new OBEX server with the given transport.
    pub fn new(transport: ObexTransport) -> Self {
        Self {
            transport,
            services: Vec::new(),
            next_session_id: 1,
            active_sessions: HashMap::new(),
        }
    }

    /// Register a service handler.
    pub fn register_service(&mut self, service: Arc<dyn ObexService>) {
        self.services.push(service);
    }

    /// Return the transport type.
    pub fn transport(&self) -> ObexTransport {
        self.transport
    }

    /// Return the number of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Accept an incoming connection and dispatch to a matching service.
    /// Returns the session ID if a matching service was found.
    pub fn accept_connection(&mut self, target: Option<&[u8]>) -> Option<u64> {
        let service = self.find_service(target)?;
        let session_id = self.next_session_id;
        self.next_session_id += 1;

        let name = service.name().to_string();
        service.handle_connection(session_id);
        self.active_sessions.insert(session_id, name);

        Some(session_id)
    }

    /// Close a session by ID.
    pub fn close_session(&mut self, session_id: u64) -> bool {
        self.active_sessions.remove(&session_id).is_some()
    }

    /// Find a service matching the given target UUID.
    fn find_service(&self, target: Option<&[u8]>) -> Option<Arc<dyn ObexService>> {
        for service in &self.services {
            match (service.target(), target) {
                (Some(st), Some(t)) if st == t => return Some(Arc::clone(service)),
                (None, None) => return Some(Arc::clone(service)),
                _ => continue,
            }
        }
        None
    }

    /// Return the number of active sessions.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyService {
        svc_name: &'static str,
        svc_target: Option<&'static [u8]>,
    }

    impl ObexService for DummyService {
        fn name(&self) -> &str {
            self.svc_name
        }
        fn target(&self) -> Option<&[u8]> {
            self.svc_target
        }
        fn handle_connection(&self, _session_id: u64) {}
    }

    #[test]
    fn server_register_and_accept() {
        let mut server = ObexServer::new(ObexTransport::Bluetooth);
        assert_eq!(server.service_count(), 0);

        server.register_service(Arc::new(DummyService {
            svc_name: "OPP",
            svc_target: None,
        }));
        assert_eq!(server.service_count(), 1);

        let sid = server.accept_connection(None);
        assert!(sid.is_some());
        assert_eq!(server.active_session_count(), 1);

        assert!(server.close_session(sid.unwrap()));
        assert_eq!(server.active_session_count(), 0);
    }

    #[test]
    fn server_reject_unknown_target() {
        let mut server = ObexServer::new(ObexTransport::Usb);
        server.register_service(Arc::new(DummyService {
            svc_name: "FTP",
            svc_target: Some(b"\xF9\xEC\x7B\xC4\x95\x3C"),
        }));

        // No match for different target
        assert!(server.accept_connection(Some(b"\x00\x00")).is_none());
        // No match for None target
        assert!(server.accept_connection(None).is_none());
    }
}
