// SPDX-License-Identifier: GPL-2.0-or-later
//! File transfer state machine — replaces obexd/src/transfer.c.
//!
//! Tracks progress of individual OBEX file transfers and exposes
//! the org.bluez.obex.Transfer1 D-Bus interface.

/// Transfer status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Active,
    Suspended,
    Complete,
    Error,
}

impl TransferStatus {
    /// D-Bus string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Complete => "complete",
            Self::Error => "error",
        }
    }
}

/// An OBEX file transfer.
///
/// Exposes org.bluez.obex.Transfer1:
/// - Methods: Cancel, Suspend, Resume
/// - Properties: Status, Session, Name, Type, Time, Size, Transferred, Filename
pub struct Transfer {
    /// Unique transfer identifier.
    pub id: u64,
    /// Session ID this transfer belongs to.
    pub session_id: u64,
    /// Local filename (if applicable).
    pub filename: Option<String>,
    /// Object name (remote).
    pub name: Option<String>,
    /// MIME type.
    pub content_type: Option<String>,
    /// Total size in bytes (if known).
    pub size: Option<u64>,
    /// Bytes transferred so far.
    pub transferred: u64,
    /// Current status.
    pub status: TransferStatus,
}

impl Transfer {
    /// Create a new transfer in `Queued` status.
    pub fn new(id: u64, session_id: u64) -> Self {
        Self {
            id,
            session_id,
            filename: None,
            name: None,
            content_type: None,
            size: None,
            transferred: 0,
            status: TransferStatus::Queued,
        }
    }

    /// D-Bus object path for this transfer.
    pub fn object_path(&self) -> String {
        format!("/org/bluez/obex/client/session{}/transfer{}", self.session_id, self.id)
    }

    /// Start the transfer.
    pub fn start(&mut self) {
        if self.status == TransferStatus::Queued {
            self.status = TransferStatus::Active;
        }
    }

    /// Record progress (bytes received/sent in this chunk).
    pub fn progress(&mut self, bytes: u64) {
        if self.status == TransferStatus::Active {
            self.transferred += bytes;
            if let Some(total) = self.size {
                if self.transferred >= total {
                    self.transferred = total;
                    self.status = TransferStatus::Complete;
                }
            }
        }
    }

    /// Cancel the transfer.
    pub fn cancel(&mut self) {
        match self.status {
            TransferStatus::Queued | TransferStatus::Active | TransferStatus::Suspended => {
                self.status = TransferStatus::Error;
            }
            _ => {}
        }
    }

    /// Suspend the transfer.
    pub fn suspend(&mut self) {
        if self.status == TransferStatus::Active {
            self.status = TransferStatus::Suspended;
        }
    }

    /// Resume a suspended transfer.
    pub fn resume(&mut self) {
        if self.status == TransferStatus::Suspended {
            self.status = TransferStatus::Active;
        }
    }

    /// Percentage complete (0..100), or None if size is unknown.
    pub fn percent_complete(&self) -> Option<u8> {
        self.size.map(|total| {
            if total == 0 {
                100
            } else {
                ((self.transferred * 100) / total).min(100) as u8
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_lifecycle() {
        let mut t = Transfer::new(1, 10);
        assert_eq!(t.status, TransferStatus::Queued);

        t.size = Some(1000);
        t.start();
        assert_eq!(t.status, TransferStatus::Active);

        t.progress(500);
        assert_eq!(t.transferred, 500);
        assert_eq!(t.percent_complete(), Some(50));

        t.suspend();
        assert_eq!(t.status, TransferStatus::Suspended);

        // Progress ignored while suspended
        t.progress(100);
        assert_eq!(t.transferred, 500);

        t.resume();
        assert_eq!(t.status, TransferStatus::Active);

        t.progress(500);
        assert_eq!(t.status, TransferStatus::Complete);
        assert_eq!(t.percent_complete(), Some(100));
    }

    #[test]
    fn transfer_cancel() {
        let mut t = Transfer::new(2, 10);
        t.start();
        t.cancel();
        assert_eq!(t.status, TransferStatus::Error);
    }

    #[test]
    fn transfer_object_path() {
        let t = Transfer::new(3, 5);
        assert_eq!(t.object_path(), "/org/bluez/obex/client/session5/transfer3");
    }
}
