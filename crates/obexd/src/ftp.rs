// SPDX-License-Identifier: GPL-2.0-or-later
//! File Transfer Profile (FTP) — replaces obexd/plugins/ftp.c.
//!
//! Implements directory browsing, file get/put/delete, and folder
//! navigation via the OBEX FTP service.

use crate::server::ObexService;

/// FTP target UUID (F9EC7BC4-953C-11D2-984E-525400DC9E09).
pub const FTP_TARGET_UUID: [u8; 16] = [
    0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E,
    0x09,
];

/// An entry in a folder listing.
#[derive(Debug, Clone)]
pub struct FolderEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Modified time as ISO 8601 string (e.g. "20240101T120000Z").
    pub modified: Option<String>,
    /// Created time as ISO 8601 string.
    pub created: Option<String>,
    /// User permission (read/write/delete).
    pub user_perm: String,
    /// MIME type for files.
    pub mime_type: Option<String>,
    /// Whether this is a parent-directory entry (".").
    pub is_parent: bool,
}

impl FolderEntry {
    /// Create a file entry with the given name and size.
    pub fn file(name: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            is_dir: false,
            size,
            modified: None,
            created: None,
            user_perm: "R".to_string(),
            mime_type: None,
            is_parent: false,
        }
    }

    /// Create a folder entry with the given name.
    pub fn folder(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_dir: true,
            size: 0,
            modified: None,
            created: None,
            user_perm: "RW".to_string(),
            mime_type: None,
            is_parent: false,
        }
    }

    /// Create a parent-directory entry (".").
    pub fn parent() -> Self {
        Self {
            name: String::new(),
            is_dir: true,
            size: 0,
            modified: None,
            created: None,
            user_perm: String::new(),
            mime_type: None,
            is_parent: true,
        }
    }
}

/// Folder listing capable of generating OBEX folder-listing XML.
pub struct FolderListing {
    pub entries: Vec<FolderEntry>,
    /// Whether to include a parent-directory element.
    pub include_parent: bool,
}

impl FolderListing {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            include_parent: false,
        }
    }

    pub fn add_entry(&mut self, entry: FolderEntry) {
        self.entries.push(entry);
    }

    /// Generate the folder-listing XML document per the OBEX FTP specification.
    ///
    /// Produces a well-formed XML document with:
    /// - XML declaration and DTD reference
    /// - Optional parent-folder element
    /// - File entries with name, size, modified, created, type, user-perm
    /// - Folder entries with name, modified, created, user-perm
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(
            "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">\n",
        );
        xml.push_str("<folder-listing version=\"1.0\">\n");

        // Parent-directory element (special "." entry)
        if self.include_parent {
            xml.push_str("  <parent-folder />\n");
        }

        for entry in &self.entries {
            if entry.is_parent {
                xml.push_str("  <parent-folder />\n");
                continue;
            }

            let tag = if entry.is_dir { "folder" } else { "file" };
            xml.push_str(&format!(
                "  <{tag} name=\"{}\"",
                xml_escape(&entry.name)
            ));
            if !entry.is_dir {
                xml.push_str(&format!(" size=\"{}\"", entry.size));
            }
            if let Some(ref modified) = entry.modified {
                xml.push_str(&format!(" modified=\"{modified}\""));
            }
            if let Some(ref created) = entry.created {
                xml.push_str(&format!(" created=\"{created}\""));
            }
            if let Some(ref mime) = entry.mime_type {
                xml.push_str(&format!(" type=\"{mime}\""));
            }
            if !entry.user_perm.is_empty() {
                xml.push_str(&format!(" user-perm=\"{}\"", entry.user_perm));
            }
            xml.push_str(" />\n");
        }

        xml.push_str("</folder-listing>\n");
        xml
    }
}

/// Escape special XML characters in attribute values.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

impl Default for FolderListing {
    fn default() -> Self {
        Self::new()
    }
}

/// FTP service handler.
pub struct FtpService {
    /// Root directory for FTP access.
    pub root_dir: String,
    /// Current working directory (relative to root).
    pub current_dir: String,
}

impl FtpService {
    pub fn new(root_dir: String) -> Self {
        Self {
            root_dir,
            current_dir: String::new(),
        }
    }

    /// Get the full path of the current directory.
    pub fn current_path(&self) -> String {
        if self.current_dir.is_empty() {
            self.root_dir.clone()
        } else {
            format!("{}/{}", self.root_dir, self.current_dir)
        }
    }

    /// Navigate to a subdirectory (SetPath).
    pub fn set_path(&mut self, path: &str) -> Result<(), &'static str> {
        if path.is_empty() {
            // Go to root
            self.current_dir.clear();
            Ok(())
        } else if path == ".." {
            // Go up one level
            if let Some(pos) = self.current_dir.rfind('/') {
                self.current_dir.truncate(pos);
            } else {
                self.current_dir.clear();
            }
            Ok(())
        } else if path.contains("..") {
            Err("Path traversal not allowed")
        } else {
            if self.current_dir.is_empty() {
                self.current_dir = path.to_string();
            } else {
                self.current_dir = format!("{}/{}", self.current_dir, path);
            }
            Ok(())
        }
    }
}

impl ObexService for FtpService {
    fn name(&self) -> &str {
        "File Transfer"
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&FTP_TARGET_UUID)
    }

    fn handle_connection(&self, _session_id: u64) {
        // TODO: handle incoming FTP connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_listing_xml() {
        let mut listing = FolderListing::new();
        let mut dir_entry = FolderEntry::folder("Documents");
        dir_entry.modified = Some("20240101T120000Z".into());
        listing.add_entry(dir_entry);

        let mut file_entry = FolderEntry::file("photo.jpg", 4096);
        file_entry.user_perm = "R".into();
        listing.add_entry(file_entry);

        let xml = listing.to_xml();
        assert!(xml.contains("<folder-listing version=\"1.0\">"));
        assert!(xml.contains("<folder name=\"Documents\""));
        assert!(xml.contains("<file name=\"photo.jpg\" size=\"4096\""));
        assert!(xml.contains("</folder-listing>"));
    }

    #[test]
    fn folder_listing_with_parent_and_type() {
        let mut listing = FolderListing::new();
        listing.include_parent = true;

        let mut f = FolderEntry::file("readme.txt", 256);
        f.mime_type = Some("text/plain".into());
        f.modified = Some("20240315T083000Z".into());
        f.created = Some("20240101T000000Z".into());
        listing.add_entry(f);

        let xml = listing.to_xml();
        assert!(xml.contains("<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">"));
        assert!(xml.contains("<parent-folder />"));
        assert!(xml.contains("type=\"text/plain\""));
        assert!(xml.contains("created=\"20240101T000000Z\""));
        assert!(xml.contains("modified=\"20240315T083000Z\""));
    }

    #[test]
    fn folder_listing_xml_escape() {
        let mut listing = FolderListing::new();
        listing.add_entry(FolderEntry::file("file&name<>.txt", 10));
        let xml = listing.to_xml();
        assert!(xml.contains("name=\"file&amp;name&lt;&gt;.txt\""));
    }

    #[test]
    fn folder_listing_parent_entry() {
        let mut listing = FolderListing::new();
        listing.add_entry(FolderEntry::parent());
        listing.add_entry(FolderEntry::folder("sub"));
        let xml = listing.to_xml();
        assert!(xml.contains("<parent-folder />"));
        assert!(xml.contains("<folder name=\"sub\""));
    }

    #[test]
    fn ftp_navigation() {
        let mut ftp = FtpService::new("/data/ftp".into());
        assert_eq!(ftp.current_path(), "/data/ftp");

        ftp.set_path("subdir").unwrap();
        assert_eq!(ftp.current_path(), "/data/ftp/subdir");

        ftp.set_path("inner").unwrap();
        assert_eq!(ftp.current_path(), "/data/ftp/subdir/inner");

        ftp.set_path("..").unwrap();
        assert_eq!(ftp.current_path(), "/data/ftp/subdir");

        ftp.set_path("").unwrap();
        assert_eq!(ftp.current_path(), "/data/ftp");

        assert!(ftp.set_path("../escape").is_err());
    }
}
