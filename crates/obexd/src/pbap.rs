// SPDX-License-Identifier: GPL-2.0-or-later
//! Phonebook Access Profile (PBAP) — replaces obexd/plugins/pbap.c.
//!
//! Implements the OBEX Phonebook Access service for exposing phone
//! contact information via vCard format.

use crate::server::ObexService;

/// PBAP target UUID (796135f0-f0c5-11d8-0966-0800200c9a66).
pub const PBAP_TARGET_UUID: [u8; 16] = [
    0x79, 0x61, 0x35, 0xF0, 0xF0, 0xC5, 0x11, 0xD8, 0x09, 0x66, 0x08, 0x00, 0x20, 0x0C, 0x9A,
    0x66,
];

/// Phonebook repositories available via PBAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhonebookRepository {
    /// Main phonebook (telecom/pb).
    Phonebook,
    /// Incoming call history (telecom/ich).
    IncomingCalls,
    /// Outgoing call history (telecom/och).
    OutgoingCalls,
    /// Missed call history (telecom/mch).
    MissedCalls,
    /// Combined call history (telecom/cch).
    CombinedCalls,
    /// SIM1 phonebook.
    Sim1,
}

impl PhonebookRepository {
    /// OBEX path for this repository.
    pub fn path(&self) -> &'static str {
        match self {
            Self::Phonebook => "telecom/pb",
            Self::IncomingCalls => "telecom/ich",
            Self::OutgoingCalls => "telecom/och",
            Self::MissedCalls => "telecom/mch",
            Self::CombinedCalls => "telecom/cch",
            Self::Sim1 => "SIM1/telecom/pb",
        }
    }

    /// Parse a repository from its path string.
    pub fn from_path(path: &str) -> Option<Self> {
        match path {
            "telecom/pb" => Some(Self::Phonebook),
            "telecom/ich" => Some(Self::IncomingCalls),
            "telecom/och" => Some(Self::OutgoingCalls),
            "telecom/mch" => Some(Self::MissedCalls),
            "telecom/cch" => Some(Self::CombinedCalls),
            "SIM1/telecom/pb" => Some(Self::Sim1),
            _ => None,
        }
    }
}

/// vCard format versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VCardFormat {
    /// vCard 2.1
    V21,
    /// vCard 3.0
    V30,
}

/// PBAP application parameters.
#[derive(Debug, Clone, Default)]
pub struct PbapAppParams {
    /// Sort order (0=indexed, 1=alphabetical, 2=phonetical).
    pub order: Option<u8>,
    /// Search value string.
    pub search_value: Option<String>,
    /// Search property (0=Name, 1=Number, 2=Sound).
    pub search_property: Option<u8>,
    /// Maximum number of entries to list.
    pub max_list_count: Option<u16>,
    /// Offset of first entry to return.
    pub list_start_offset: Option<u16>,
    /// Property filter bitmask.
    pub filter: Option<u64>,
    /// vCard format (0=2.1, 1=3.0).
    pub format: Option<VCardFormat>,
    /// Phonebook size (returned in response).
    pub phonebook_size: Option<u16>,
    /// Number of new missed calls (returned in response).
    pub new_missed_calls: Option<u8>,
}

/// Bitfield filter for selecting which vCard properties to include.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VCardFilter(pub u64);

impl VCardFilter {
    pub const VERSION: u64 = 1 << 0;
    pub const FN: u64 = 1 << 1;
    pub const N: u64 = 1 << 2;
    pub const PHOTO: u64 = 1 << 3;
    pub const ADR: u64 = 1 << 5;
    pub const TEL: u64 = 1 << 7;
    pub const EMAIL: u64 = 1 << 8;
    pub const TITLE: u64 = 1 << 12;
    pub const ORG: u64 = 1 << 16;
    pub const NOTE: u64 = 1 << 17;
    pub const URL: u64 = 1 << 18;

    /// All fields enabled.
    pub const ALL: u64 = u64::MAX;

    /// Check whether a specific field bit is set.
    pub fn includes(self, field: u64) -> bool {
        // A filter of 0 means "return all properties" per PBAP spec.
        self.0 == 0 || (self.0 & field) != 0
    }
}


/// A vCard representation with standard properties.
#[derive(Debug, Clone, Default)]
pub struct VCard {
    /// Structured name (N property): family;given;middle;prefix;suffix.
    pub name: String,
    /// Formatted name (FN property).
    pub formatted_name: Option<String>,
    /// Phone numbers with optional type (e.g. "CELL", "HOME", "WORK").
    pub phones: Vec<(String, String)>,
    /// Email addresses.
    pub emails: Vec<String>,
    /// Postal addresses (formatted single-line for simplicity).
    pub addresses: Vec<String>,
    /// Organization name.
    pub org: Option<String>,
    /// Title / job position.
    pub title: Option<String>,
    /// Free-form note.
    pub note: Option<String>,
    /// URL.
    pub url: Option<String>,
    /// Base64-encoded photo data.
    pub photo: Option<String>,
}

impl VCard {
    /// Create a VCard with just a name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Generate a vCard 2.1 string.
    pub fn to_vcard21(&self) -> String {
        self.to_vcard_string(VCardFormat::V21, VCardFilter::default())
    }

    /// Generate a vCard 3.0 string.
    pub fn to_vcard30(&self) -> String {
        self.to_vcard_string(VCardFormat::V30, VCardFilter::default())
    }

    /// Generate a vCard string in the specified format, applying the filter.
    pub fn to_vcard_string(&self, format: VCardFormat, filter: VCardFilter) -> String {
        let version = match format {
            VCardFormat::V21 => "2.1",
            VCardFormat::V30 => "3.0",
        };

        let mut s = String::new();
        s.push_str("BEGIN:VCARD\r\n");
        s.push_str(&format!("VERSION:{version}\r\n"));

        if filter.includes(VCardFilter::N) {
            s.push_str(&format!("N:{}\r\n", self.name));
        }

        if filter.includes(VCardFilter::FN) {
            let fn_val = self
                .formatted_name
                .as_deref()
                .unwrap_or(&self.name);
            s.push_str(&format!("FN:{fn_val}\r\n"));
        }

        if filter.includes(VCardFilter::TEL) {
            for (tel_type, number) in &self.phones {
                if tel_type.is_empty() {
                    s.push_str(&format!("TEL:{number}\r\n"));
                } else {
                    match format {
                        VCardFormat::V21 => {
                            s.push_str(&format!("TEL;{tel_type}:{number}\r\n"));
                        }
                        VCardFormat::V30 => {
                            s.push_str(&format!(
                                "TEL;TYPE={tel_type}:{number}\r\n"
                            ));
                        }
                    }
                }
            }
        }

        if filter.includes(VCardFilter::EMAIL) {
            for email in &self.emails {
                s.push_str(&format!("EMAIL:{email}\r\n"));
            }
        }

        if filter.includes(VCardFilter::ADR) {
            for addr in &self.addresses {
                s.push_str(&format!("ADR:{addr}\r\n"));
            }
        }

        if filter.includes(VCardFilter::ORG) {
            if let Some(ref org) = self.org {
                s.push_str(&format!("ORG:{org}\r\n"));
            }
        }

        if filter.includes(VCardFilter::TITLE) {
            if let Some(ref title) = self.title {
                s.push_str(&format!("TITLE:{title}\r\n"));
            }
        }

        if filter.includes(VCardFilter::NOTE) {
            if let Some(ref note) = self.note {
                s.push_str(&format!("NOTE:{note}\r\n"));
            }
        }

        if filter.includes(VCardFilter::URL) {
            if let Some(ref url) = self.url {
                s.push_str(&format!("URL:{url}\r\n"));
            }
        }

        if filter.includes(VCardFilter::PHOTO) {
            if let Some(ref photo) = self.photo {
                match format {
                    VCardFormat::V21 => {
                        s.push_str(&format!(
                            "PHOTO;ENCODING=BASE64;TYPE=JPEG:{photo}\r\n"
                        ));
                    }
                    VCardFormat::V30 => {
                        s.push_str(&format!(
                            "PHOTO;ENCODING=b;TYPE=JPEG:{photo}\r\n"
                        ));
                    }
                }
            }
        }

        s.push_str("END:VCARD\r\n");
        s
    }
}

/// Parse a phonebook path to determine the repository.
pub fn parse_phonebook_path(path: &str) -> Option<PhonebookRepository> {
    // Strip leading slashes and trailing .vcf if present.
    let path = path.trim_start_matches('/');
    let path = path.strip_suffix(".vcf").unwrap_or(path);
    PhonebookRepository::from_path(path)
}

/// Phonebook Access Profile service.
pub struct PbapService {
    /// Current repository being accessed.
    pub current_repo: PhonebookRepository,
}

impl PbapService {
    pub fn new() -> Self {
        Self {
            current_repo: PhonebookRepository::Phonebook,
        }
    }

    /// Select a phonebook repository.
    pub fn select(&mut self, repo: PhonebookRepository) {
        self.current_repo = repo;
    }

    /// Pull all contacts from the current repository (stub).
    pub fn pull_all(&self, _params: &PbapAppParams) -> Vec<VCard> {
        // TODO: actually read phonebook data
        Vec::new()
    }
}

impl Default for PbapService {
    fn default() -> Self {
        Self::new()
    }
}

impl ObexService for PbapService {
    fn name(&self) -> &str {
        "Phonebook Access"
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&PBAP_TARGET_UUID)
    }

    fn handle_connection(&self, _session_id: u64) {
        // TODO: handle incoming PBAP connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phonebook_repository_paths() {
        assert_eq!(PhonebookRepository::Phonebook.path(), "telecom/pb");
        assert_eq!(PhonebookRepository::MissedCalls.path(), "telecom/mch");
        assert_eq!(PhonebookRepository::Sim1.path(), "SIM1/telecom/pb");

        assert_eq!(
            PhonebookRepository::from_path("telecom/pb"),
            Some(PhonebookRepository::Phonebook)
        );
        assert_eq!(PhonebookRepository::from_path("invalid"), None);
    }

    #[test]
    fn vcard21_generation() {
        let mut vc = VCard::with_name("Doe;John;;;");
        vc.phones.push(("CELL".into(), "+1234567890".into()));
        vc.emails.push("john@example.com".into());

        let text = vc.to_vcard21();
        assert!(text.contains("BEGIN:VCARD"));
        assert!(text.contains("VERSION:2.1"));
        assert!(text.contains("N:Doe;John;;;"));
        assert!(text.contains("TEL;CELL:+1234567890"));
        assert!(text.contains("EMAIL:john@example.com"));
        assert!(text.contains("END:VCARD"));
    }

    #[test]
    fn vcard30_with_all_fields() {
        let mut vc = VCard::with_name("Smith;Jane;;;");
        vc.formatted_name = Some("Jane Smith".into());
        vc.phones.push(("WORK".into(), "+9876543210".into()));
        vc.emails.push("jane@corp.com".into());
        vc.addresses.push(";;123 Main St;City;ST;12345;US".into());
        vc.org = Some("Acme Corp".into());
        vc.title = Some("Engineer".into());
        vc.note = Some("VIP contact".into());
        vc.url = Some("https://example.com".into());

        let text = vc.to_vcard30();
        assert!(text.contains("VERSION:3.0"));
        assert!(text.contains("FN:Jane Smith"));
        assert!(text.contains("TEL;TYPE=WORK:+9876543210"));
        assert!(text.contains("ORG:Acme Corp"));
        assert!(text.contains("TITLE:Engineer"));
        assert!(text.contains("NOTE:VIP contact"));
        assert!(text.contains("URL:https://example.com"));
        assert!(text.contains("ADR:;;123 Main St;City;ST;12345;US"));
    }

    #[test]
    fn vcard_filter() {
        let mut vc = VCard::with_name("Test;User;;;");
        vc.phones.push(("".into(), "555-1234".into()));
        vc.emails.push("test@test.com".into());
        vc.org = Some("TestOrg".into());

        // Only include N and TEL
        let filter = VCardFilter(VCardFilter::N | VCardFilter::TEL | VCardFilter::VERSION);
        let text = vc.to_vcard_string(VCardFormat::V21, filter);
        assert!(text.contains("N:Test;User;;;"));
        assert!(text.contains("TEL:555-1234"));
        // FN, EMAIL, ORG should be excluded
        assert!(!text.contains("FN:"));
        assert!(!text.contains("EMAIL:"));
        assert!(!text.contains("ORG:"));
    }

    #[test]
    fn parse_phonebook_paths() {
        assert_eq!(
            parse_phonebook_path("telecom/pb"),
            Some(PhonebookRepository::Phonebook)
        );
        assert_eq!(
            parse_phonebook_path("/telecom/ich"),
            Some(PhonebookRepository::IncomingCalls)
        );
        assert_eq!(
            parse_phonebook_path("telecom/mch.vcf"),
            Some(PhonebookRepository::MissedCalls)
        );
        assert_eq!(parse_phonebook_path("invalid/path"), None);
    }
}
