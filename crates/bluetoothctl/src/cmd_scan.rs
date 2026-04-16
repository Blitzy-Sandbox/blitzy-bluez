// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Scan commands: scan on/off, filter configuration

use crate::shell::{CmdEntry, Menu};

/// Scan filter configuration.
#[derive(Debug, Default)]
pub struct ScanFilter {
    pub uuids: Vec<String>,
    pub rssi: Option<i16>,
    pub pathloss: Option<u16>,
    pub transport: Option<String>,
    pub duplicate_data: Option<bool>,
    pub discoverable: Option<bool>,
}

impl ScanFilter {
    /// Clear all filter settings.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Return the scan command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "scan",
            help: "Scan for devices <on/off>",
            handler: cmd_scan,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "scan.uuids",
            help: "Set scan UUID filter",
            handler: cmd_scan_uuids,
            menu: Menu::Scan,
        },
        CmdEntry {
            name: "scan.rssi",
            help: "Set scan RSSI filter",
            handler: cmd_scan_rssi,
            menu: Menu::Scan,
        },
        CmdEntry {
            name: "scan.pathloss",
            help: "Set scan pathloss filter",
            handler: cmd_scan_pathloss,
            menu: Menu::Scan,
        },
        CmdEntry {
            name: "scan.transport",
            help: "Set scan transport filter [le/bredr/auto]",
            handler: cmd_scan_transport,
            menu: Menu::Scan,
        },
        CmdEntry {
            name: "scan.duplicate-data",
            help: "Set duplicate data filter <on/off>",
            handler: cmd_scan_duplicate_data,
            menu: Menu::Scan,
        },
        CmdEntry {
            name: "scan.discoverable",
            help: "Set discoverable filter <on/off>",
            handler: cmd_scan_discoverable,
            menu: Menu::Scan,
        },
        CmdEntry {
            name: "scan.clear",
            help: "Clear scan filter",
            handler: cmd_scan_clear,
            menu: Menu::Scan,
        },
    ]
}

fn cmd_scan(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on") => "Starting discovery (requires D-Bus)".to_string(),
        Some("off") => "Stopping discovery (requires D-Bus)".to_string(),
        _ => "Usage: scan <on/off>".to_string(),
    }
}

fn cmd_scan_uuids(args: &[&str], _adapter: Option<&str>) -> String {
    if args.is_empty() {
        "Usage: scan.uuids <uuid> [uuid...]".to_string()
    } else {
        format!("Set UUID filter: {}", args.join(", "))
    }
}

fn cmd_scan_rssi(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().and_then(|s| s.parse::<i16>().ok()) {
        Some(v) => format!("Set RSSI filter: {v}"),
        None => "Usage: scan.rssi <value>".to_string(),
    }
}

fn cmd_scan_pathloss(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().and_then(|s| s.parse::<u16>().ok()) {
        Some(v) => format!("Set pathloss filter: {v}"),
        None => "Usage: scan.pathloss <value>".to_string(),
    }
}

fn cmd_scan_transport(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some(t @ ("le" | "bredr" | "auto")) => format!("Set transport filter: {t}"),
        _ => "Usage: scan.transport <le/bredr/auto>".to_string(),
    }
}

fn cmd_scan_duplicate_data(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on") => "Set duplicate data filter: on".to_string(),
        Some("off") => "Set duplicate data filter: off".to_string(),
        _ => "Usage: scan.duplicate-data <on/off>".to_string(),
    }
}

fn cmd_scan_discoverable(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on") => "Set discoverable filter: on".to_string(),
        Some("off") => "Set discoverable filter: off".to_string(),
        _ => "Usage: scan.discoverable <on/off>".to_string(),
    }
}

fn cmd_scan_clear(_args: &[&str], _adapter: Option<&str>) -> String {
    "Scan filter cleared".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_on_off() {
        assert!(cmd_scan(&["on"], None).contains("Starting"));
        assert!(cmd_scan(&["off"], None).contains("Stopping"));
        assert!(cmd_scan(&[], None).contains("Usage"));
    }

    #[test]
    fn test_scan_filter_clear() {
        let mut f = ScanFilter::default();
        f.rssi = Some(-50);
        f.clear();
        assert!(f.rssi.is_none());
    }
}
