// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Advertisement monitor commands

use crate::shell::{CmdEntry, Menu};

/// Return the monitor command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "monitor.rssi-sampling-period",
            help: "Set RSSI sampling period <value>",
            handler: cmd_rssi_sampling,
            menu: Menu::Monitor,
        },
        CmdEntry {
            name: "monitor.get-supported-info",
            help: "Get supported monitor features",
            handler: cmd_get_supported_info,
            menu: Menu::Monitor,
        },
        CmdEntry {
            name: "monitor.add-or-pattern",
            help: "Add OR pattern monitor",
            handler: cmd_add_or_pattern,
            menu: Menu::Monitor,
        },
        CmdEntry {
            name: "monitor.remove",
            help: "Remove advertisement monitor <index>",
            handler: cmd_remove,
            menu: Menu::Monitor,
        },
        CmdEntry {
            name: "monitor.print",
            help: "Print advertisement monitor details",
            handler: cmd_print,
            menu: Menu::Monitor,
        },
    ]
}

fn cmd_rssi_sampling(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().and_then(|s| s.parse::<u16>().ok()) {
        Some(v) => format!("Set RSSI sampling period: {v}"),
        None => "Usage: monitor.rssi-sampling-period <value>".to_string(),
    }
}

fn cmd_get_supported_info(_args: &[&str], _adapter: Option<&str>) -> String {
    "Supported monitor features (requires D-Bus)".to_string()
}

fn cmd_add_or_pattern(args: &[&str], _adapter: Option<&str>) -> String {
    if args.is_empty() {
        "Usage: monitor.add-or-pattern <type> <offset> <data>".to_string()
    } else {
        format!("Adding OR pattern: {}", args.join(" "))
    }
}

fn cmd_remove(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(idx) => format!("Removing monitor {idx} (requires D-Bus)"),
        None => "Usage: monitor.remove <index>".to_string(),
    }
}

fn cmd_print(_args: &[&str], _adapter: Option<&str>) -> String {
    "Monitor details (requires D-Bus)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_commands() {
        assert!(cmd_rssi_sampling(&["100"], None).contains("100"));
        assert!(cmd_get_supported_info(&[], None).contains("Supported"));
    }
}
