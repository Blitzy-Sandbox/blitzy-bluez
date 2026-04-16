// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Device commands: devices, paired-devices, info, pair, trust, connect, etc.

use crate::shell::{CmdEntry, Menu};

/// Return the device command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "devices",
            help: "List available devices",
            handler: cmd_devices,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "paired-devices",
            help: "List paired devices",
            handler: cmd_paired_devices,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "info",
            help: "Device information [dev]",
            handler: cmd_info,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "pair",
            help: "Pair with a device <dev>",
            handler: cmd_pair,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "cancel-pairing",
            help: "Cancel pairing [dev]",
            handler: cmd_cancel_pairing,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "trust",
            help: "Trust a device <dev>",
            handler: cmd_trust,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "untrust",
            help: "Untrust a device <dev>",
            handler: cmd_untrust,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "block",
            help: "Block a device <dev>",
            handler: cmd_block,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "unblock",
            help: "Unblock a device <dev>",
            handler: cmd_unblock,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "remove",
            help: "Remove a device <dev>",
            handler: cmd_remove,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "connect",
            help: "Connect to a device <dev>",
            handler: cmd_connect,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "disconnect",
            help: "Disconnect from a device [dev]",
            handler: cmd_disconnect,
            menu: Menu::Main,
        },
    ]
}

/// Convert a Bluetooth address to a D-Bus device path.
fn device_path(adapter: Option<&str>, addr: &str) -> String {
    let idx = adapter.unwrap_or("hci0");
    let mangled = addr.replace(':', "_");
    format!("/org/bluez/{idx}/dev_{mangled}")
}

fn require_dev<'a>(args: &'a [&str], cmd: &str) -> Result<&'a str, String> {
    args.first()
        .copied()
        .ok_or_else(|| format!("Usage: {cmd} <dev>"))
}

fn cmd_devices(_args: &[&str], _adapter: Option<&str>) -> String {
    "Device listing requires D-Bus connection".to_string()
}

fn cmd_paired_devices(_args: &[&str], _adapter: Option<&str>) -> String {
    "Paired device listing requires D-Bus connection".to_string()
}

fn cmd_info(args: &[&str], adapter: Option<&str>) -> String {
    let path = match args.first() {
        Some(dev) => device_path(adapter, dev),
        None => return "Usage: info [dev]".to_string(),
    };
    format!("Device info for {path} (requires D-Bus)")
}

fn cmd_pair(args: &[&str], adapter: Option<&str>) -> String {
    match require_dev(args, "pair") {
        Ok(dev) => {
            let path = device_path(adapter, dev);
            format!("Pairing with {path} (requires D-Bus)")
        }
        Err(e) => e,
    }
}

fn cmd_cancel_pairing(args: &[&str], adapter: Option<&str>) -> String {
    match args.first() {
        Some(dev) => {
            let path = device_path(adapter, dev);
            format!("Cancelling pairing on {path} (requires D-Bus)")
        }
        None => "Cancel pairing on current device (requires D-Bus)".to_string(),
    }
}

fn cmd_trust(args: &[&str], adapter: Option<&str>) -> String {
    match require_dev(args, "trust") {
        Ok(dev) => {
            let path = device_path(adapter, dev);
            format!("Trusting {path} (requires D-Bus)")
        }
        Err(e) => e,
    }
}

fn cmd_untrust(args: &[&str], adapter: Option<&str>) -> String {
    match require_dev(args, "untrust") {
        Ok(dev) => {
            let path = device_path(adapter, dev);
            format!("Untrusting {path} (requires D-Bus)")
        }
        Err(e) => e,
    }
}

fn cmd_block(args: &[&str], adapter: Option<&str>) -> String {
    match require_dev(args, "block") {
        Ok(dev) => {
            let path = device_path(adapter, dev);
            format!("Blocking {path} (requires D-Bus)")
        }
        Err(e) => e,
    }
}

fn cmd_unblock(args: &[&str], adapter: Option<&str>) -> String {
    match require_dev(args, "unblock") {
        Ok(dev) => {
            let path = device_path(adapter, dev);
            format!("Unblocking {path} (requires D-Bus)")
        }
        Err(e) => e,
    }
}

fn cmd_remove(args: &[&str], adapter: Option<&str>) -> String {
    match require_dev(args, "remove") {
        Ok(dev) => {
            let path = device_path(adapter, dev);
            format!("Removing {path} (requires D-Bus)")
        }
        Err(e) => e,
    }
}

fn cmd_connect(args: &[&str], adapter: Option<&str>) -> String {
    match require_dev(args, "connect") {
        Ok(dev) => {
            let path = device_path(adapter, dev);
            format!("Connecting to {path} (requires D-Bus)")
        }
        Err(e) => e,
    }
}

fn cmd_disconnect(args: &[&str], adapter: Option<&str>) -> String {
    match args.first() {
        Some(dev) => {
            let path = device_path(adapter, dev);
            format!("Disconnecting from {path} (requires D-Bus)")
        }
        None => "Disconnecting from current device (requires D-Bus)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_path() {
        let p = device_path(None, "AA:BB:CC:DD:EE:FF");
        assert_eq!(p, "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF");
    }

    #[test]
    fn test_device_path_custom_adapter() {
        let p = device_path(Some("hci1"), "11:22:33:44:55:66");
        assert_eq!(p, "/org/bluez/hci1/dev_11_22_33_44_55_66");
    }

    #[test]
    fn test_require_dev_missing() {
        assert!(require_dev(&[], "pair").is_err());
    }
}
