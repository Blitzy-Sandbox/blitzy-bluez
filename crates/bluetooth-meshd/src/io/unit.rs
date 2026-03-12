// Bluetooth Mesh I/O — Unit-test backend using Unix datagram sockets.
//
// Stub: will be replaced by the implementation agent for unit.rs.
// This file provides the minimal type needed by mod.rs::create_backend().

use super::{MeshIoBackend, MeshIoCaps, MeshIoOpts, MeshIoRecvFn, MeshIoSendInfo, MeshIoState};

/// Unit-test I/O backend using Unix datagram sockets.
#[derive(Default)]
pub struct UnitBackend;

impl UnitBackend {
    /// Create a new (uninitialised) unit-test backend instance.
    pub fn new() -> Self {
        Self
    }
}

impl MeshIoBackend for UnitBackend {
    fn init(&mut self, _io: &mut MeshIoState, _opts: &MeshIoOpts) -> bool {
        false
    }

    fn destroy(&mut self, _io: &mut MeshIoState) -> bool {
        true
    }

    fn caps(&self, _io: &MeshIoState) -> Option<MeshIoCaps> {
        Some(MeshIoCaps { max_num_filters: 255, window_accuracy: 50 })
    }

    fn send(&mut self, _io: &mut MeshIoState, _info: &MeshIoSendInfo, _data: &[u8]) -> bool {
        false
    }

    fn register_recv(&mut self, _io: &mut MeshIoState, _filter: &[u8], _cb: MeshIoRecvFn) -> bool {
        true
    }

    fn deregister_recv(&mut self, _io: &mut MeshIoState, _filter: &[u8]) -> bool {
        true
    }

    fn cancel(&mut self, _io: &mut MeshIoState, _data: &[u8]) -> bool {
        false
    }
}
