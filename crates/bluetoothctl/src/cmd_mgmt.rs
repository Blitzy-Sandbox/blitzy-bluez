// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Management commands: mgmt.select, mgmt.revision, mgmt.version

use crate::shell::{CmdEntry, Menu};

/// Return the management command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "mgmt.select",
            help: "Select management interface <index>",
            handler: cmd_select,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "mgmt.revision",
            help: "Show management interface revision",
            handler: cmd_revision,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "mgmt.version",
            help: "Show management interface version",
            handler: cmd_version,
            menu: Menu::Main,
        },
    ]
}

fn cmd_select(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(idx) => format!("Selected management index: {idx}"),
        None => "Usage: mgmt.select <index>".to_string(),
    }
}

fn cmd_revision(_args: &[&str], _adapter: Option<&str>) -> String {
    "Management revision (requires mgmt socket)".to_string()
}

fn cmd_version(_args: &[&str], _adapter: Option<&str>) -> String {
    "Management version (requires mgmt socket)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mgmt_select() {
        let out = cmd_select(&["0"], None);
        assert!(out.contains("0"));
    }
}
