// SPDX-License-Identifier: GPL-2.0-or-later
//
// Mesh configuration — replaces mesh/mesh-main.conf parsing

use std::fs;
use std::io;
use std::path::Path;

use serde::Deserialize;

/// Top-level mesh daemon configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MeshConfig {
    /// Enable beacon feature.
    pub beacon: bool,
    /// Enable relay feature.
    pub relay: bool,
    /// Enable friend feature.
    pub friend: bool,
    /// Enable proxy feature.
    pub proxy: bool,
    /// Default TTL for published messages.
    pub default_ttl: u8,
    /// Provisioning timeout in seconds.
    pub provision_timeout: u32,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            beacon: true,
            relay: true,
            friend: false,
            proxy: false,
            default_ttl: 7,
            provision_timeout: 60,
        }
    }
}

impl MeshConfig {
    /// Load configuration from a file in simple `key = value` format.
    ///
    /// Lines starting with `#` or empty lines are ignored.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let content = fs::read_to_string(path)?;
        let mut config = Self::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "Beacon" => config.beacon = value.eq_ignore_ascii_case("true"),
                    "Relay" => config.relay = value.eq_ignore_ascii_case("true"),
                    "Friend" => config.friend = value.eq_ignore_ascii_case("true"),
                    "Proxy" => config.proxy = value.eq_ignore_ascii_case("true"),
                    "DefaultTTL" => {
                        if let Ok(v) = value.parse::<u8>() {
                            config.default_ttl = v;
                        }
                    }
                    "ProvisionTimeout" => {
                        if let Ok(v) = value.parse::<u32>() {
                            config.provision_timeout = v;
                        }
                    }
                    _ => {} // ignore unknown keys
                }
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = MeshConfig::default();
        assert!(cfg.beacon);
        assert!(cfg.relay);
        assert!(!cfg.friend);
        assert!(!cfg.proxy);
        assert_eq!(cfg.default_ttl, 7);
        assert_eq!(cfg.provision_timeout, 60);
    }

    #[test]
    fn test_load_config() {
        let dir = std::env::temp_dir().join("mesh_config_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test.conf");
        fs::write(
            &path,
            "# Mesh config\nBeacon = false\nRelay = true\nDefaultTTL = 5\n",
        )
        .unwrap();

        let cfg = MeshConfig::load(&path).unwrap();
        assert!(!cfg.beacon);
        assert!(cfg.relay);
        assert_eq!(cfg.default_ttl, 5);

        let _ = fs::remove_dir_all(&dir);
    }
}
