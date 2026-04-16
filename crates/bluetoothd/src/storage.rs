// SPDX-License-Identifier: GPL-2.0-or-later
//
// Persistent storage helpers replacing src/storage.c, src/textfile.c,
// and src/settings.h
//
// Manages the /var/lib/bluetooth/<adapter>/<device>/ directory structure
// for storing adapter settings, device keys, and GATT cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default storage directory for BlueZ state.
pub const STORAGE_DIR: &str = "/var/lib/bluetooth";

/// Storage manager for a single adapter.
#[derive(Debug)]
pub struct Storage {
    base_dir: PathBuf,
}

impl Storage {
    /// Create a storage instance for the given adapter address.
    pub fn new(adapter_addr: &str) -> Self {
        Self {
            base_dir: PathBuf::from(STORAGE_DIR).join(adapter_addr),
        }
    }

    /// Create a storage instance with a custom base directory.
    pub fn with_base(base: &Path, adapter_addr: &str) -> Self {
        Self {
            base_dir: base.join(adapter_addr),
        }
    }

    /// Get the base directory path.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Get the path for a device's storage directory.
    pub fn device_dir(&self, device_addr: &str) -> PathBuf {
        self.base_dir.join(device_addr)
    }

    /// Get the path for a device's info file.
    pub fn device_info_path(&self, device_addr: &str) -> PathBuf {
        self.device_dir(device_addr).join("info")
    }

    /// Get the path for adapter settings.
    pub fn adapter_settings_path(&self) -> PathBuf {
        self.base_dir.join("settings")
    }

    /// Get the path for the GATT cache of a device.
    pub fn gatt_cache_path(&self, device_addr: &str) -> PathBuf {
        self.base_dir.join("cache").join(device_addr)
    }

    /// Read a key-value INI-style file into a HashMap of section → (key → value).
    pub fn read_info_file(
        path: &Path,
    ) -> Result<HashMap<String, HashMap<String, String>>, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut current_section = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len() - 1].to_string();
                sections.entry(current_section.clone()).or_default();
            } else if let Some((key, value)) = line.split_once('=') {
                sections
                    .entry(current_section.clone())
                    .or_default()
                    .insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        Ok(sections)
    }

    /// Write sections to an INI-style file.
    pub fn write_info_file(
        path: &Path,
        sections: &HashMap<String, HashMap<String, String>>,
    ) -> Result<(), std::io::Error> {
        use std::io::Write;
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;

        let mut f = std::fs::File::create(path)?;
        for (section, entries) in sections {
            writeln!(f, "[{}]", section)?;
            for (key, value) in entries {
                writeln!(f, "{}={}", key, value)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }

    /// List all stored device addresses for this adapter.
    pub fn list_devices(&self) -> Vec<String> {
        let mut devices = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.base_dir) else {
            return devices;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Device addresses are XX:XX:XX:XX:XX:XX format
            if name.len() == 17
                && name.chars().filter(|&c| c == ':').count() == 5
                && entry.path().join("info").exists()
            {
                devices.push(name);
            }
        }
        devices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_paths() {
        let s = Storage::new("00:11:22:33:44:55");
        assert_eq!(
            s.base_dir(),
            Path::new("/var/lib/bluetooth/00:11:22:33:44:55")
        );
        assert_eq!(
            s.device_info_path("AA:BB:CC:DD:EE:FF"),
            PathBuf::from("/var/lib/bluetooth/00:11:22:33:44:55/AA:BB:CC:DD:EE:FF/info")
        );
        assert_eq!(
            s.gatt_cache_path("AA:BB:CC:DD:EE:FF"),
            PathBuf::from("/var/lib/bluetooth/00:11:22:33:44:55/cache/AA:BB:CC:DD:EE:FF")
        );
    }

    #[test]
    fn test_read_write_info_file() {
        let dir = std::env::temp_dir().join("bluez_test_storage");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("info");
        let mut sections = HashMap::new();
        let mut general = HashMap::new();
        general.insert("Name".to_string(), "TestDevice".to_string());
        general.insert("Paired".to_string(), "true".to_string());
        sections.insert("General".to_string(), general);

        Storage::write_info_file(&path, &sections).unwrap();
        let read_back = Storage::read_info_file(&path).unwrap();
        assert_eq!(
            read_back["General"]["Name"],
            "TestDevice"
        );
        assert_eq!(
            read_back["General"]["Paired"],
            "true"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_custom_base() {
        let s = Storage::with_base(Path::new("/tmp/bt"), "00:11:22:33:44:55");
        assert_eq!(s.base_dir(), Path::new("/tmp/bt/00:11:22:33:44:55"));
    }

    #[test]
    fn test_list_devices_empty() {
        let s = Storage::new("FF:FF:FF:FF:FF:FF");
        assert!(s.list_devices().is_empty());
    }

    // ---------------------------------------------------------------
    // Tests ported from unit/test-textfile.c
    // ---------------------------------------------------------------

    /// test_delete from test-textfile.c: put a key, delete it, verify get returns None.
    #[test]
    fn test_c_textfile_delete() {
        let dir = std::env::temp_dir().join("bluez_test_textfile_delete");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("info");
        let key = "00:00:00:00:00:00";
        let section = "General";

        // Write a key
        let mut sections = HashMap::new();
        let mut entries = HashMap::new();
        entries.insert(key.to_string(), String::new());
        sections.insert(section.to_string(), entries);
        Storage::write_info_file(&path, &sections).unwrap();

        // Read back — key should exist
        let read = Storage::read_info_file(&path).unwrap();
        assert!(read.get(section).unwrap().contains_key(key));

        // Overwrite with the key removed
        let mut sections = HashMap::new();
        sections.insert(section.to_string(), HashMap::new());
        Storage::write_info_file(&path, &sections).unwrap();

        // Read back — key should not exist
        let read = Storage::read_info_file(&path).unwrap();
        assert!(
            !read
                .get(section)
                .map(|e| e.contains_key(key))
                .unwrap_or(false)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// test_overwrite from test-textfile.c: write key, overwrite with new value,
    /// overwrite again, then delete.
    #[test]
    fn test_c_textfile_overwrite() {
        let dir = std::env::temp_dir().join("bluez_test_textfile_overwrite");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("info");
        let key = "00:00:00:00:00:00";
        let section = "General";

        // Put empty value
        let mut sections = HashMap::new();
        let mut entries = HashMap::new();
        entries.insert(key.to_string(), String::new());
        sections.insert(section.to_string(), entries);
        Storage::write_info_file(&path, &sections).unwrap();

        // Overwrite with "Test"
        sections
            .get_mut(section)
            .unwrap()
            .insert(key.to_string(), "Test".to_string());
        Storage::write_info_file(&path, &sections).unwrap();

        // Overwrite again (same value)
        Storage::write_info_file(&path, &sections).unwrap();

        // Read back
        let read = Storage::read_info_file(&path).unwrap();
        assert_eq!(read[section][key], "Test");

        // Delete key
        sections.get_mut(section).unwrap().remove(key);
        Storage::write_info_file(&path, &sections).unwrap();

        let read = Storage::read_info_file(&path).unwrap();
        assert!(
            !read
                .get(section)
                .map(|e| e.contains_key(key))
                .unwrap_or(false)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// test_multiple from test-textfile.c: write many keys with varying value
    /// lengths, overwrite some, delete some, verify correctness.
    #[test]
    fn test_c_textfile_multiple() {
        let dir = std::env::temp_dir().join("bluez_test_textfile_multiple");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("info");
        let section = "General";
        let max = 10usize;

        let mut sections = HashMap::new();
        let mut entries = HashMap::new();

        // Write keys 01..0A with value = "x" repeated i times
        for i in 1..=max {
            let key = format!("00:00:00:00:00:{:02X}", i);
            let value: String = "x".repeat(i);
            entries.insert(key, value);
        }
        sections.insert(section.to_string(), entries);
        Storage::write_info_file(&path, &sections).unwrap();

        // Verify all values
        let read = Storage::read_info_file(&path).unwrap();
        for i in 1..=max {
            let key = format!("00:00:00:00:00:{:02X}", i);
            let expected: String = "x".repeat(i);
            assert_eq!(read[section][&key], expected, "Mismatch at key {}", key);
        }

        // Overwrite key 0A with 'y' repeated max times
        sections
            .get_mut(section)
            .unwrap()
            .insert(
                format!("00:00:00:00:00:{:02X}", max),
                "y".repeat(max),
            );

        // Overwrite key 01 with 'z' repeated max times
        sections
            .get_mut(section)
            .unwrap()
            .insert(
                "00:00:00:00:00:01".to_string(),
                "z".repeat(max),
            );

        Storage::write_info_file(&path, &sections).unwrap();

        // Verify updated values
        let read = Storage::read_info_file(&path).unwrap();
        assert_eq!(
            read[section]["00:00:00:00:00:01"],
            "z".repeat(max)
        );
        assert_eq!(
            read[section][&format!("00:00:00:00:00:{:02X}", max)],
            "y".repeat(max)
        );

        // Verify unchanged values
        for i in 2..max {
            let key = format!("00:00:00:00:00:{:02X}", i);
            assert_eq!(
                read[section][&key].len(),
                i,
                "Length mismatch at key {}",
                key
            );
        }

        // Delete key 02 and key (max-3)
        sections
            .get_mut(section)
            .unwrap()
            .remove("00:00:00:00:00:02");
        sections
            .get_mut(section)
            .unwrap()
            .remove(&format!("00:00:00:00:00:{:02X}", max - 3));
        Storage::write_info_file(&path, &sections).unwrap();

        // Verify deleted keys are gone
        let read = Storage::read_info_file(&path).unwrap();
        assert!(
            !read[section].contains_key("00:00:00:00:00:02"),
            "Key 02 should be deleted"
        );
        assert!(
            !read[section].contains_key(&format!("00:00:00:00:00:{:02X}", max - 3)),
            "Key {:02X} should be deleted",
            max - 3
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
