// SPDX-License-Identifier: GPL-2.0-or-later
//! Message Access Profile (MAP) — replaces obexd/plugins/mas.c + mns.c.
//!
//! Implements the OBEX Message Access service for accessing messages
//! (SMS, MMS, Email) on a remote device.

use crate::server::ObexService;

/// MAP MAS target UUID (bb582b40-420c-11db-b0de-0800200c9a66).
pub const MAP_MAS_TARGET_UUID: [u8; 16] = [
    0xBB, 0x58, 0x2B, 0x40, 0x42, 0x0C, 0x11, 0xDB, 0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A,
    0x66,
];

/// MAP MNS target UUID (bb582b41-420c-11db-b0de-0800200c9a66).
pub const MAP_MNS_TARGET_UUID: [u8; 16] = [
    0xBB, 0x58, 0x2B, 0x41, 0x42, 0x0C, 0x11, 0xDB, 0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A,
    0x66,
];

/// Message type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Email,
    SmsGsm,
    SmsCdma,
    Mms,
}

impl MessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::SmsGsm => "SMS_GSM",
            Self::SmsCdma => "SMS_CDMA",
            Self::Mms => "MMS",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "EMAIL" => Some(Self::Email),
            "SMS_GSM" => Some(Self::SmsGsm),
            "SMS_CDMA" => Some(Self::SmsCdma),
            "MMS" => Some(Self::Mms),
            _ => None,
        }
    }
}

/// MAP application parameters.
#[derive(Debug, Clone, Default)]
pub struct MapAppParams {
    /// Maximum number of entries to list.
    pub max_list_count: Option<u16>,
    /// Offset of first entry to return.
    pub list_start_offset: Option<u16>,
    /// Filter by message type bitmask.
    pub filter_message_type: Option<u8>,
    /// Filter period begin (ISO 8601).
    pub filter_period_begin: Option<String>,
    /// Filter period end (ISO 8601).
    pub filter_period_end: Option<String>,
    /// Filter by read status (0=unread, 1=read, 2=both).
    pub filter_read_status: Option<u8>,
    /// Maximum subject length to return.
    pub subject_length: Option<u8>,
    /// Parameter mask for message listing.
    pub parameter_mask: Option<u32>,
}

/// A message listing entry.
#[derive(Debug, Clone)]
pub struct MessageEntry {
    /// Message handle.
    pub handle: String,
    /// Subject line.
    pub subject: String,
    /// Date/time (ISO 8601).
    pub datetime: String,
    /// Sender display name.
    pub sender_name: String,
    /// Sender addressing (e.g. phone number or email).
    pub sender_addressing: String,
    /// Recipient display name.
    pub recipient_name: String,
    /// Message type.
    pub msg_type: MessageType,
    /// Message size in bytes.
    pub size: u32,
    /// Reception status ("complete", "fractioned", "notification").
    pub reception_status: String,
    /// Attachment size in bytes.
    pub attachment_size: u32,
    /// Priority flag.
    pub priority: bool,
    /// Read status.
    pub read: bool,
}

impl MessageEntry {
    /// Create a new message entry with required fields; optional fields default.
    pub fn new(
        handle: impl Into<String>,
        subject: impl Into<String>,
        msg_type: MessageType,
    ) -> Self {
        Self {
            handle: handle.into(),
            subject: subject.into(),
            datetime: String::new(),
            sender_name: String::new(),
            sender_addressing: String::new(),
            recipient_name: String::new(),
            msg_type,
            size: 0,
            reception_status: "complete".into(),
            attachment_size: 0,
            priority: false,
            read: false,
        }
    }
}

/// A MAP message-listing XML document.
pub struct MessageListing {
    pub entries: Vec<MessageEntry>,
}

impl MessageListing {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: MessageEntry) {
        self.entries.push(entry);
    }

    /// Generate a MAP message-listing XML document per the MAP specification.
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(
            "<!DOCTYPE MAP-msg-listing SYSTEM \"MAP-msg-listing.dtd\">\n",
        );
        xml.push_str("<MAP-msg-listing version=\"1.0\">\n");

        for entry in &self.entries {
            xml.push_str(&format!(
                "  <msg handle=\"{}\"",
                entry.handle
            ));
            if !entry.subject.is_empty() {
                xml.push_str(&format!(" subject=\"{}\"", entry.subject));
            }
            if !entry.datetime.is_empty() {
                xml.push_str(&format!(" datetime=\"{}\"", entry.datetime));
            }
            if !entry.sender_name.is_empty() {
                xml.push_str(&format!(
                    " sender_name=\"{}\"",
                    entry.sender_name
                ));
            }
            if !entry.sender_addressing.is_empty() {
                xml.push_str(&format!(
                    " sender_addressing=\"{}\"",
                    entry.sender_addressing
                ));
            }
            if !entry.recipient_name.is_empty() {
                xml.push_str(&format!(
                    " recipient_name=\"{}\"",
                    entry.recipient_name
                ));
            }
            xml.push_str(&format!(" type=\"{}\"", entry.msg_type.as_str()));
            xml.push_str(&format!(" size=\"{}\"", entry.size));
            xml.push_str(&format!(
                " reception_status=\"{}\"",
                entry.reception_status
            ));
            xml.push_str(&format!(
                " attachment_size=\"{}\"",
                entry.attachment_size
            ));
            xml.push_str(&format!(
                " priority=\"{}\"",
                if entry.priority { "yes" } else { "no" }
            ));
            xml.push_str(&format!(
                " read=\"{}\"",
                if entry.read { "yes" } else { "no" }
            ));
            xml.push_str(" />\n");
        }

        xml.push_str("</MAP-msg-listing>\n");
        xml
    }
}

impl Default for MessageListing {
    fn default() -> Self {
        Self::new()
    }
}

/// Message Access Profile service (MAS).
pub struct MapService {
    /// Current folder path.
    pub current_folder: String,
}

impl MapService {
    pub fn new() -> Self {
        Self {
            current_folder: String::new(),
        }
    }

    /// Set the current folder for browsing.
    pub fn set_folder(&mut self, folder: &str) {
        if folder.is_empty() {
            self.current_folder.clear();
        } else if folder == ".." {
            if let Some(pos) = self.current_folder.rfind('/') {
                self.current_folder.truncate(pos);
            } else {
                self.current_folder.clear();
            }
        } else if self.current_folder.is_empty() {
            self.current_folder = folder.to_string();
        } else {
            self.current_folder = format!("{}/{}", self.current_folder, folder);
        }
    }

    /// List messages in the current folder (stub).
    pub fn list_messages(&self, _params: &MapAppParams) -> Vec<MessageEntry> {
        // TODO: actually list messages
        Vec::new()
    }

    /// Push a message (stub).
    pub fn push_message(&self, _folder: &str, _content: &[u8]) -> Result<String, &'static str> {
        // TODO: actually push message, return handle
        Ok("0001".to_string())
    }

    /// Update message read status (stub).
    pub fn set_read_status(
        &self,
        _handle: &str,
        _read: bool,
    ) -> Result<(), &'static str> {
        // TODO: actually update status
        Ok(())
    }
}

impl Default for MapService {
    fn default() -> Self {
        Self::new()
    }
}

impl ObexService for MapService {
    fn name(&self) -> &str {
        "Message Access"
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&MAP_MAS_TARGET_UUID)
    }

    fn handle_connection(&self, _session_id: u64) {
        // TODO: handle incoming MAP connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_conversions() {
        assert_eq!(MessageType::Email.as_str(), "EMAIL");
        assert_eq!(MessageType::parse("SMS_GSM"), Some(MessageType::SmsGsm));
        assert_eq!(MessageType::parse("UNKNOWN"), None);
    }

    #[test]
    fn map_folder_navigation() {
        let mut map = MapService::new();
        assert_eq!(map.current_folder, "");

        map.set_folder("telecom");
        assert_eq!(map.current_folder, "telecom");

        map.set_folder("msg");
        assert_eq!(map.current_folder, "telecom/msg");

        map.set_folder("..");
        assert_eq!(map.current_folder, "telecom");

        map.set_folder("");
        assert_eq!(map.current_folder, "");
    }

    #[test]
    fn message_listing_xml_basic() {
        let mut listing = MessageListing::new();
        let mut msg = MessageEntry::new("0001", "Hello", MessageType::SmsGsm);
        msg.datetime = "20240315T143000".into();
        msg.sender_name = "Alice".into();
        msg.sender_addressing = "+1234567890".into();
        msg.recipient_name = "Bob".into();
        msg.size = 128;
        msg.read = true;
        listing.add_entry(msg);

        let xml = listing.to_xml();
        assert!(xml.contains("<MAP-msg-listing version=\"1.0\">"));
        assert!(xml.contains("handle=\"0001\""));
        assert!(xml.contains("subject=\"Hello\""));
        assert!(xml.contains("type=\"SMS_GSM\""));
        assert!(xml.contains("sender_name=\"Alice\""));
        assert!(xml.contains("sender_addressing=\"+1234567890\""));
        assert!(xml.contains("recipient_name=\"Bob\""));
        assert!(xml.contains("size=\"128\""));
        assert!(xml.contains("read=\"yes\""));
        assert!(xml.contains("priority=\"no\""));
        assert!(xml.contains("</MAP-msg-listing>"));
    }

    #[test]
    fn message_listing_xml_multiple() {
        let mut listing = MessageListing::new();

        let mut m1 = MessageEntry::new("0001", "First", MessageType::Email);
        m1.priority = true;
        m1.attachment_size = 2048;
        listing.add_entry(m1);

        let m2 = MessageEntry::new("0002", "Second", MessageType::Mms);
        listing.add_entry(m2);

        let xml = listing.to_xml();
        assert!(xml.contains("handle=\"0001\""));
        assert!(xml.contains("handle=\"0002\""));
        assert!(xml.contains("priority=\"yes\""));
        assert!(xml.contains("attachment_size=\"2048\""));
        assert!(xml.contains("type=\"EMAIL\""));
        assert!(xml.contains("type=\"MMS\""));
    }
}
