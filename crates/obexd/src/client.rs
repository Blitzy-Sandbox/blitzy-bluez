// SPDX-License-Identifier: GPL-2.0-or-later
//! OBEX client — replaces obexd/client/ directory.
//!
//! Provides a client-side OBEX interface exposing D-Bus services:
//! - org.bluez.obex.Session1
//! - org.bluez.obex.ObjectPush1
//! - org.bluez.obex.FileTransfer1
//! - org.bluez.obex.PhonebookAccess1
//! - org.bluez.obex.MessageAccess1

/// Properties for an OBEX client session (org.bluez.obex.Session1).
#[derive(Debug, Clone)]
pub struct SessionProperties {
    /// Source adapter address.
    pub source: String,
    /// Destination device address.
    pub destination: String,
    /// RFCOMM channel or L2CAP PSM.
    pub channel: u16,
    /// Target service (e.g., "opp", "ftp", "pbap", "map").
    pub target: String,
    /// Root folder for file operations.
    pub root: String,
}

/// OBEX client for initiating outgoing transfers and sessions.
pub struct ObexClient {
    /// Active sessions.
    sessions: Vec<ClientSession>,
    next_id: u64,
}

/// A client-side OBEX session.
#[derive(Debug, Clone)]
pub struct ClientSession {
    pub id: u64,
    pub properties: SessionProperties,
    pub object_path: String,
}

impl ObexClient {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            next_id: 1,
        }
    }

    /// Create a new session to a remote device.
    /// org.bluez.obex.Client1.CreateSession
    pub fn create_session(&mut self, props: SessionProperties) -> &ClientSession {
        let id = self.next_id;
        self.next_id += 1;

        let object_path = format!("/org/bluez/obex/client/session{id}");
        let session = ClientSession {
            id,
            properties: props,
            object_path,
        };
        self.sessions.push(session);
        self.sessions.last().unwrap()
    }

    /// Remove a session by ID.
    /// org.bluez.obex.Client1.RemoveSession
    pub fn remove_session(&mut self, id: u64) -> bool {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.id != id);
        self.sessions.len() < before
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: u64) -> Option<&ClientSession> {
        self.sessions.iter().find(|s| s.id == id)
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for ObexClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Object Push operations (org.bluez.obex.ObjectPush1).
pub struct ObjectPush;

impl ObjectPush {
    /// Send a file to the remote device (stub).
    pub fn send_file(_session_id: u64, _filename: &str) -> Result<String, &'static str> {
        // TODO: initiate OPP transfer
        Ok("/org/bluez/obex/client/session1/transfer1".to_string())
    }

    /// Pull the remote device's default business card (stub).
    pub fn pull_business_card(_session_id: u64) -> Result<String, &'static str> {
        Ok("/org/bluez/obex/client/session1/transfer2".to_string())
    }

    /// Exchange business cards (stub).
    pub fn exchange_business_cards(
        _session_id: u64,
        _local_file: &str,
    ) -> Result<String, &'static str> {
        Ok("/org/bluez/obex/client/session1/transfer3".to_string())
    }
}

/// File Transfer operations (org.bluez.obex.FileTransfer1).
pub struct FileTransfer;

impl FileTransfer {
    /// Change to a sub-folder (stub).
    pub fn change_folder(_session_id: u64, _folder: &str) -> Result<(), &'static str> {
        Ok(())
    }

    /// Create a new folder (stub).
    pub fn create_folder(_session_id: u64, _folder: &str) -> Result<(), &'static str> {
        Ok(())
    }

    /// List contents of current folder (stub).
    pub fn list_folder(_session_id: u64) -> Result<Vec<FileEntry>, &'static str> {
        Ok(Vec::new())
    }

    /// Get a file from the remote device (stub).
    pub fn get_file(
        _session_id: u64,
        _target_file: &str,
        _source: &str,
    ) -> Result<String, &'static str> {
        Ok("/org/bluez/obex/client/session1/transfer1".to_string())
    }

    /// Put a file to the remote device (stub).
    pub fn put_file(
        _session_id: u64,
        _source: &str,
        _target: &str,
    ) -> Result<String, &'static str> {
        Ok("/org/bluez/obex/client/session1/transfer1".to_string())
    }

    /// Copy a file on the remote device (stub).
    pub fn copy_file(
        _session_id: u64,
        _source: &str,
        _target: &str,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    /// Move a file on the remote device (stub).
    pub fn move_file(
        _session_id: u64,
        _source: &str,
        _target: &str,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    /// Delete a file on the remote device (stub).
    pub fn delete(_session_id: u64, _file: &str) -> Result<(), &'static str> {
        Ok(())
    }
}

/// A file entry returned by folder listing.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
    pub permissions: Option<String>,
}

/// Phonebook Access operations (org.bluez.obex.PhonebookAccess1).
pub struct PhonebookAccess;

impl PhonebookAccess {
    /// Select a phonebook (stub).
    pub fn select(
        _session_id: u64,
        _location: &str,
        _phonebook: &str,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    /// Pull all entries from selected phonebook (stub).
    pub fn pull_all(_session_id: u64) -> Result<(String, u16), &'static str> {
        Ok((String::new(), 0))
    }

    /// Pull a single vCard entry (stub).
    pub fn pull(_session_id: u64, _vcard: &str) -> Result<String, &'static str> {
        Ok(String::new())
    }

    /// List vCard entries (stub).
    pub fn list(_session_id: u64) -> Result<Vec<(String, String)>, &'static str> {
        Ok(Vec::new())
    }

    /// Search the phonebook (stub).
    pub fn search(
        _session_id: u64,
        _field: &str,
        _value: &str,
    ) -> Result<Vec<(String, String)>, &'static str> {
        Ok(Vec::new())
    }

    /// Get the phonebook size (stub).
    pub fn get_size(_session_id: u64) -> Result<u16, &'static str> {
        Ok(0)
    }

    /// Force updating of database version counters (stub).
    pub fn update_version(_session_id: u64) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Message Access operations (org.bluez.obex.MessageAccess1).
pub struct MessageAccess;

impl MessageAccess {
    /// Set the current folder (stub).
    pub fn set_folder(_session_id: u64, _folder: &str) -> Result<(), &'static str> {
        Ok(())
    }

    /// List sub-folders (stub).
    pub fn list_folders(_session_id: u64) -> Result<Vec<String>, &'static str> {
        Ok(Vec::new())
    }

    /// List messages in current folder (stub).
    pub fn list_messages(
        _session_id: u64,
        _folder: &str,
    ) -> Result<Vec<MessageEntry>, &'static str> {
        Ok(Vec::new())
    }

    /// List available filter fields (stub).
    pub fn list_filter_fields(_session_id: u64) -> Result<Vec<String>, &'static str> {
        Ok(vec![
            "subject".into(),
            "timestamp".into(),
            "sender".into(),
            "recipient".into(),
            "type".into(),
            "size".into(),
            "status".into(),
        ])
    }

    /// Force a refresh of the inbox (stub).
    pub fn update_inbox(_session_id: u64) -> Result<(), &'static str> {
        Ok(())
    }

    /// Push a message (stub).
    pub fn push_message(
        _session_id: u64,
        _folder: &str,
        _content: &str,
    ) -> Result<String, &'static str> {
        Ok("/org/bluez/obex/client/session1/transfer1".to_string())
    }
}

/// A message entry returned by message listing.
#[derive(Debug, Clone)]
pub struct MessageEntry {
    pub handle: String,
    pub subject: String,
    pub sender: String,
    pub recipient: String,
    pub msg_type: String,
    pub read: bool,
    pub datetime: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_session_lifecycle() {
        let mut client = ObexClient::new();
        assert_eq!(client.session_count(), 0);

        let props = SessionProperties {
            source: "00:11:22:33:44:55".into(),
            destination: "AA:BB:CC:DD:EE:FF".into(),
            channel: 1,
            target: "opp".into(),
            root: "/".into(),
        };

        let session = client.create_session(props);
        let id = session.id;
        assert_eq!(client.session_count(), 1);
        assert!(client.get_session(id).is_some());

        assert!(client.remove_session(id));
        assert_eq!(client.session_count(), 0);
    }

    #[test]
    fn message_access_filter_fields() {
        let fields = MessageAccess::list_filter_fields(1).unwrap();
        assert!(fields.contains(&"subject".to_string()));
        assert!(fields.contains(&"sender".to_string()));
    }
}
