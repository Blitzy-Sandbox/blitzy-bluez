// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Admin policy commands: allow-list, blocklist management

use crate::shell::{CmdEntry, Menu};

/// Return the admin command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "admin.allow",
            help: "Manage allowed service UUIDs",
            handler: cmd_admin_allow,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "admin.blocklist",
            help: "Manage blocked service UUIDs",
            handler: cmd_admin_blocklist,
            menu: Menu::Main,
        },
    ]
}

fn cmd_admin_allow(args: &[&str], _adapter: Option<&str>) -> String {
    if args.is_empty() {
        "Current allow list: (requires D-Bus)".to_string()
    } else {
        format!("Setting allow list: {} (requires D-Bus)", args.join(", "))
    }
}

fn cmd_admin_blocklist(args: &[&str], _adapter: Option<&str>) -> String {
    if args.is_empty() {
        "Current blocklist: (requires D-Bus)".to_string()
    } else {
        format!("Setting blocklist: {} (requires D-Bus)", args.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_commands() {
        let out = cmd_admin_allow(&[], None);
        assert!(out.contains("allow list"));
        let out = cmd_admin_blocklist(&["uuid1"], None);
        assert!(out.contains("uuid1"));
    }
}
