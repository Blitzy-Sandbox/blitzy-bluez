// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Advertising commands: advertise on/off, configure advertisement parameters

use crate::shell::{CmdEntry, Menu};

/// Advertisement configuration.
#[derive(Debug, Default)]
pub struct AdvertiseConfig {
    pub name: Option<String>,
    pub appearance: Option<u16>,
    pub duration: Option<u16>,
    pub timeout: Option<u16>,
    pub tx_power: bool,
    pub uuids: Vec<String>,
    pub discoverable: bool,
    pub secondary: Option<String>,
}

impl AdvertiseConfig {
    /// Clear all advertisement settings.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Return the advertise command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "advertise",
            help: "Advertise <on/off/peripheral/broadcast>",
            handler: cmd_advertise,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "advertise.name",
            help: "Set advertisement local name",
            handler: cmd_adv_name,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.appearance",
            help: "Set advertisement appearance <value>",
            handler: cmd_adv_appearance,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.duration",
            help: "Set advertisement duration <seconds>",
            handler: cmd_adv_duration,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.timeout",
            help: "Set advertisement timeout <seconds>",
            handler: cmd_adv_timeout,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.tx-power",
            help: "Set TX power inclusion <on/off>",
            handler: cmd_adv_tx_power,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.uuids",
            help: "Set service UUIDs",
            handler: cmd_adv_uuids,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.service",
            help: "Set service data <uuid> <data>",
            handler: cmd_adv_service,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.manufacturer",
            help: "Set manufacturer data <id> <data>",
            handler: cmd_adv_manufacturer,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.data",
            help: "Set raw advertisement data <type> <data>",
            handler: cmd_adv_data,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.discoverable",
            help: "Set discoverable flag <on/off>",
            handler: cmd_adv_discoverable,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.secondary",
            help: "Set secondary PHY <1M/2M/Coded>",
            handler: cmd_adv_secondary,
            menu: Menu::Advertise,
        },
        CmdEntry {
            name: "advertise.clear",
            help: "Clear advertisement configuration",
            handler: cmd_adv_clear,
            menu: Menu::Advertise,
        },
    ]
}

fn cmd_advertise(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on" | "peripheral") => "Starting advertising (requires D-Bus)".to_string(),
        Some("broadcast") => "Starting broadcast advertising (requires D-Bus)".to_string(),
        Some("off") => "Stopping advertising (requires D-Bus)".to_string(),
        _ => "Usage: advertise <on/off/peripheral/broadcast>".to_string(),
    }
}

fn cmd_adv_name(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(name) => format!("Set advertisement name: {name}"),
        None => "Usage: advertise.name <name>".to_string(),
    }
}

fn cmd_adv_appearance(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().and_then(|s| s.parse::<u16>().ok()) {
        Some(v) => format!("Set appearance: {v:#06x}"),
        None => "Usage: advertise.appearance <value>".to_string(),
    }
}

fn cmd_adv_duration(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().and_then(|s| s.parse::<u16>().ok()) {
        Some(v) => format!("Set duration: {v}s"),
        None => "Usage: advertise.duration <seconds>".to_string(),
    }
}

fn cmd_adv_timeout(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().and_then(|s| s.parse::<u16>().ok()) {
        Some(v) => format!("Set timeout: {v}s"),
        None => "Usage: advertise.timeout <seconds>".to_string(),
    }
}

fn cmd_adv_tx_power(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on") => "TX power: enabled".to_string(),
        Some("off") => "TX power: disabled".to_string(),
        _ => "Usage: advertise.tx-power <on/off>".to_string(),
    }
}

fn cmd_adv_uuids(args: &[&str], _adapter: Option<&str>) -> String {
    if args.is_empty() {
        "Usage: advertise.uuids <uuid> [uuid...]".to_string()
    } else {
        format!("Set UUIDs: {}", args.join(", "))
    }
}

fn cmd_adv_service(args: &[&str], _adapter: Option<&str>) -> String {
    if args.len() < 2 {
        "Usage: advertise.service <uuid> <data>".to_string()
    } else {
        format!("Set service data: uuid={} data={}", args[0], args[1..].join(" "))
    }
}

fn cmd_adv_manufacturer(args: &[&str], _adapter: Option<&str>) -> String {
    if args.len() < 2 {
        "Usage: advertise.manufacturer <id> <data>".to_string()
    } else {
        format!("Set manufacturer data: id={} data={}", args[0], args[1..].join(" "))
    }
}

fn cmd_adv_data(args: &[&str], _adapter: Option<&str>) -> String {
    if args.len() < 2 {
        "Usage: advertise.data <type> <data>".to_string()
    } else {
        format!("Set raw data: type={} data={}", args[0], args[1..].join(" "))
    }
}

fn cmd_adv_discoverable(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on") => "Discoverable: enabled".to_string(),
        Some("off") => "Discoverable: disabled".to_string(),
        _ => "Usage: advertise.discoverable <on/off>".to_string(),
    }
}

fn cmd_adv_secondary(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some(phy @ ("1M" | "2M" | "Coded")) => format!("Secondary PHY: {phy}"),
        _ => "Usage: advertise.secondary <1M/2M/Coded>".to_string(),
    }
}

fn cmd_adv_clear(_args: &[&str], _adapter: Option<&str>) -> String {
    "Advertisement configuration cleared".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertise_on_off() {
        assert!(cmd_advertise(&["on"], None).contains("Starting"));
        assert!(cmd_advertise(&["off"], None).contains("Stopping"));
        assert!(cmd_advertise(&["peripheral"], None).contains("Starting"));
    }

    #[test]
    fn test_advertise_config_clear() {
        let mut cfg = AdvertiseConfig::default();
        cfg.name = Some("test".to_string());
        cfg.clear();
        assert!(cfg.name.is_none());
    }
}
