// Bluetooth Mesh I/O — MGMT mesh backend + controller enumeration.
//
// Stub: will be replaced by the implementation agent for mgmt.rs.
// This file provides the minimal type needed by mod.rs::create_backend().

use super::{MeshIoBackend, MeshIoCaps, MeshIoOpts, MeshIoRecvFn, MeshIoSendInfo, MeshIoState};

/// Controller alert callback type — called by MGMT enumeration for each
/// discovered controller with (index, up, powered, mesh_support).
pub type CtlAlertFn = fn(i32, bool, bool, bool);

/// Store the controller alert callback for use during MGMT enumeration.
///
/// Called by `mesh_io_new` in Auto mode to register `ctl_alert` as the
/// callback invoked when controllers are discovered or removed.
pub fn register_ctl_alert(_cb: CtlAlertFn) {
    // Stub — the full implementation will store the callback and use it
    // during mesh_mgmt_list() controller enumeration.
}

/// MGMT-based mesh I/O backend using kernel mesh extensions.
#[derive(Default)]
pub struct MgmtBackend;

impl MgmtBackend {
    /// Create a new (uninitialised) MGMT backend instance.
    pub fn new() -> Self {
        Self
    }
}

impl MeshIoBackend for MgmtBackend {
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
