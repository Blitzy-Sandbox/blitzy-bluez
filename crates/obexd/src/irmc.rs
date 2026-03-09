// SPDX-License-Identifier: GPL-2.0-or-later
//! IrMC Sync Profile — replaces obexd/plugins/irmc.c.
//!
//! Implements the IrMC synchronization service for calendar,
//! phonebook, and notes objects.

use crate::server::ObexService;

/// IrMC Sync target UUID (IRMC-SYNC).
pub const IRMC_TARGET_UUID: [u8; 9] = *b"IRMC-SYNC";

/// Types of IrMC objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrmcObjectType {
    /// Phonebook (pb.vcf).
    Phonebook,
    /// Calendar (cal.vcs).
    Calendar,
    /// Notes (nt.vnt).
    Notes,
}

impl IrmcObjectType {
    /// OBEX path prefix for this object type.
    pub fn path_prefix(&self) -> &'static str {
        match self {
            Self::Phonebook => "telecom/pb",
            Self::Calendar => "telecom/cal",
            Self::Notes => "telecom/nt",
        }
    }

    /// Default filename for this type.
    pub fn default_filename(&self) -> &'static str {
        match self {
            Self::Phonebook => "pb.vcf",
            Self::Calendar => "cal.vcs",
            Self::Notes => "nt.vnt",
        }
    }
}

/// IrMC Sync service handler.
pub struct IrmcService {
    /// Root directory for IrMC object storage.
    pub root_dir: String,
}

impl IrmcService {
    pub fn new(root_dir: String) -> Self {
        Self { root_dir }
    }

    /// Get the full path for a given object type.
    pub fn object_path(&self, obj_type: IrmcObjectType) -> String {
        format!(
            "{}/{}/{}",
            self.root_dir,
            obj_type.path_prefix(),
            obj_type.default_filename()
        )
    }
}

impl ObexService for IrmcService {
    fn name(&self) -> &str {
        "IrMC Sync"
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&IRMC_TARGET_UUID)
    }

    fn handle_connection(&self, _session_id: u64) {
        // TODO: handle incoming IrMC connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irmc_object_paths() {
        let svc = IrmcService::new("/data/irmc".into());

        assert_eq!(
            svc.object_path(IrmcObjectType::Phonebook),
            "/data/irmc/telecom/pb/pb.vcf"
        );
        assert_eq!(
            svc.object_path(IrmcObjectType::Calendar),
            "/data/irmc/telecom/cal/cal.vcs"
        );
        assert_eq!(
            svc.object_path(IrmcObjectType::Notes),
            "/data/irmc/telecom/nt/nt.vnt"
        );
        assert_eq!(svc.name(), "IrMC Sync");
    }
}
