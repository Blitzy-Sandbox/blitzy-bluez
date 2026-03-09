// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Adapter commands: list, show, select, power, pairable, discoverable, alias, etc.

use crate::shell::{CmdEntry, Menu};

/// Return the adapter command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "list",
            help: "List available controllers",
            handler: cmd_list,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "show",
            help: "Show controller info [ctrl]",
            handler: cmd_show,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "select",
            help: "Select default controller <ctrl>",
            handler: cmd_select,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "power",
            help: "Set controller power <on/off>",
            handler: cmd_power,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "pairable",
            help: "Set controller pairable <on/off>",
            handler: cmd_pairable,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "discoverable",
            help: "Set controller discoverable <on/off>",
            handler: cmd_discoverable,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "discoverable-timeout",
            help: "Set discoverable timeout <seconds>",
            handler: cmd_discoverable_timeout,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "alias",
            help: "Set controller alias <name>",
            handler: cmd_alias,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "reset-alias",
            help: "Reset controller alias",
            handler: cmd_reset_alias,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "system-alias",
            help: "Set system alias <name>",
            handler: cmd_system_alias,
            menu: Menu::Main,
        },
    ]
}

fn adapter_path(adapter: Option<&str>) -> String {
    let idx = adapter.unwrap_or("hci0");
    format!("/org/bluez/{idx}")
}

fn cmd_list(_args: &[&str], _adapter: Option<&str>) -> String {
    // In a full implementation, this would enumerate via D-Bus ObjectManager.
    "Controller listing requires D-Bus connection".to_string()
}

fn cmd_show(args: &[&str], adapter: Option<&str>) -> String {
    let path = if let Some(ctrl) = args.first() {
        format!("/org/bluez/{ctrl}")
    } else {
        adapter_path(adapter)
    };
    format!("Show controller at {path} (requires D-Bus connection)")
}

fn cmd_select(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(ctrl) => format!("Selected controller: {ctrl}"),
        None => "Usage: select <ctrl>".to_string(),
    }
}

fn parse_on_off(val: Option<&&str>) -> Result<bool, String> {
    match val.copied() {
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        _ => Err("Usage: <on/off>".to_string()),
    }
}

fn cmd_power(args: &[&str], adapter: Option<&str>) -> String {
    match parse_on_off(args.first()) {
        Ok(state) => {
            let path = adapter_path(adapter);
            format!(
                "Setting power {} on {path} (requires D-Bus)",
                if state { "on" } else { "off" }
            )
        }
        Err(e) => format!("power: {e}"),
    }
}

fn cmd_pairable(args: &[&str], adapter: Option<&str>) -> String {
    match parse_on_off(args.first()) {
        Ok(state) => {
            let path = adapter_path(adapter);
            format!(
                "Setting pairable {} on {path} (requires D-Bus)",
                if state { "on" } else { "off" }
            )
        }
        Err(e) => format!("pairable: {e}"),
    }
}

fn cmd_discoverable(args: &[&str], adapter: Option<&str>) -> String {
    match parse_on_off(args.first()) {
        Ok(state) => {
            let path = adapter_path(adapter);
            format!(
                "Setting discoverable {} on {path} (requires D-Bus)",
                if state { "on" } else { "off" }
            )
        }
        Err(e) => format!("discoverable: {e}"),
    }
}

fn cmd_discoverable_timeout(args: &[&str], adapter: Option<&str>) -> String {
    match args.first().and_then(|s| s.parse::<u32>().ok()) {
        Some(secs) => {
            let path = adapter_path(adapter);
            format!("Setting discoverable timeout to {secs}s on {path} (requires D-Bus)")
        }
        None => "Usage: discoverable-timeout <seconds>".to_string(),
    }
}

fn cmd_alias(args: &[&str], adapter: Option<&str>) -> String {
    match args.first() {
        Some(name) => {
            let path = adapter_path(adapter);
            format!("Setting alias to '{name}' on {path} (requires D-Bus)")
        }
        None => "Usage: alias <name>".to_string(),
    }
}

fn cmd_reset_alias(_args: &[&str], adapter: Option<&str>) -> String {
    let path = adapter_path(adapter);
    format!("Resetting alias on {path} (requires D-Bus)")
}

fn cmd_system_alias(args: &[&str], adapter: Option<&str>) -> String {
    match args.first() {
        Some(name) => {
            let path = adapter_path(adapter);
            format!("Setting system alias to '{name}' on {path} (requires D-Bus)")
        }
        None => "Usage: system-alias <name>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_path_default() {
        assert_eq!(adapter_path(None), "/org/bluez/hci0");
    }

    #[test]
    fn test_adapter_path_custom() {
        assert_eq!(adapter_path(Some("hci1")), "/org/bluez/hci1");
    }

    #[test]
    fn test_parse_on_off() {
        assert_eq!(parse_on_off(Some(&"on")), Ok(true));
        assert_eq!(parse_on_off(Some(&"off")), Ok(false));
        assert!(parse_on_off(None).is_err());
    }
}
