// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// GATT commands: attribute browsing, read/write, notify, service registration

use crate::shell::{CmdEntry, Menu};

/// Return the GATT command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "list-attributes",
            help: "List attributes [dev]",
            handler: cmd_list_attributes,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "select-attribute",
            help: "Select attribute <path/uuid>",
            handler: cmd_select_attribute,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "read",
            help: "Read attribute value",
            handler: cmd_read,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "write",
            help: "Write attribute value <data>",
            handler: cmd_write,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "acquire-write",
            help: "Acquire write file descriptor",
            handler: cmd_acquire_write,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "acquire-notify",
            help: "Acquire notify file descriptor",
            handler: cmd_acquire_notify,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "notify",
            help: "Toggle notifications <on/off>",
            handler: cmd_notify,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "register-application",
            help: "Register GATT application",
            handler: cmd_register_application,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "unregister-application",
            help: "Unregister GATT application",
            handler: cmd_unregister_application,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "register-service",
            help: "Register GATT service <uuid>",
            handler: cmd_register_service,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "register-characteristic",
            help: "Register GATT characteristic <uuid> <flags>",
            handler: cmd_register_characteristic,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "register-descriptor",
            help: "Register GATT descriptor <uuid>",
            handler: cmd_register_descriptor,
            menu: Menu::Gatt,
        },
        CmdEntry {
            name: "unregister-service",
            help: "Unregister GATT service",
            handler: cmd_unregister_service,
            menu: Menu::Gatt,
        },
    ]
}

/// A GATT service entry for display: (path, uuid, characteristics).
pub type GattServiceEntry = (String, String, Vec<(String, String)>);

/// Format a GATT attribute hierarchy for display.
pub fn format_attribute_tree(services: &[GattServiceEntry]) -> String {
    let mut out = String::new();
    for (svc_path, svc_uuid, chars) in services {
        out.push_str(&format!("Service {svc_path} ({svc_uuid})\n"));
        for (char_path, char_uuid) in chars {
            out.push_str(&format!("  Characteristic {char_path} ({char_uuid})\n"));
        }
    }
    out
}

fn cmd_list_attributes(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(dev) => format!("Listing attributes for {dev} (requires D-Bus)"),
        None => "Listing attributes for current device (requires D-Bus)".to_string(),
    }
}

fn cmd_select_attribute(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(path) => format!("Selected attribute: {path}"),
        None => "Usage: select-attribute <path/uuid>".to_string(),
    }
}

fn cmd_read(_args: &[&str], _adapter: Option<&str>) -> String {
    "Read attribute (requires D-Bus and selected attribute)".to_string()
}

fn cmd_write(args: &[&str], _adapter: Option<&str>) -> String {
    if args.is_empty() {
        "Usage: write <hex-data>".to_string()
    } else {
        format!("Write {} (requires D-Bus and selected attribute)", args.join(" "))
    }
}

fn cmd_acquire_write(_args: &[&str], _adapter: Option<&str>) -> String {
    "Acquire write fd (requires D-Bus and selected attribute)".to_string()
}

fn cmd_acquire_notify(_args: &[&str], _adapter: Option<&str>) -> String {
    "Acquire notify fd (requires D-Bus and selected attribute)".to_string()
}

fn cmd_notify(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on") => "Starting notifications (requires D-Bus)".to_string(),
        Some("off") => "Stopping notifications (requires D-Bus)".to_string(),
        _ => "Usage: notify <on/off>".to_string(),
    }
}

fn cmd_register_application(_args: &[&str], _adapter: Option<&str>) -> String {
    "Registering GATT application (requires D-Bus)".to_string()
}

fn cmd_unregister_application(_args: &[&str], _adapter: Option<&str>) -> String {
    "Unregistering GATT application (requires D-Bus)".to_string()
}

fn cmd_register_service(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(uuid) => format!("Registering service {uuid}"),
        None => "Usage: register-service <uuid>".to_string(),
    }
}

fn cmd_register_characteristic(args: &[&str], _adapter: Option<&str>) -> String {
    if args.len() < 2 {
        "Usage: register-characteristic <uuid> <flags>".to_string()
    } else {
        format!("Registering characteristic {} with flags {}", args[0], args[1..].join(","))
    }
}

fn cmd_register_descriptor(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(uuid) => format!("Registering descriptor {uuid}"),
        None => "Usage: register-descriptor <uuid>".to_string(),
    }
}

fn cmd_unregister_service(_args: &[&str], _adapter: Option<&str>) -> String {
    "Unregistering GATT service (requires D-Bus)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_attribute_tree() {
        let services = vec![(
            "/svc/001".to_string(),
            "0000180a-0000-1000-8000-00805f9b34fb".to_string(),
            vec![(
                "/svc/001/char/001".to_string(),
                "00002a29-0000-1000-8000-00805f9b34fb".to_string(),
            )],
        )];
        let out = format_attribute_tree(&services);
        assert!(out.contains("Service /svc/001"));
        assert!(out.contains("Characteristic /svc/001/char/001"));
    }

    #[test]
    fn test_notify_usage() {
        assert!(cmd_notify(&[], None).contains("Usage"));
        assert!(cmd_notify(&["on"], None).contains("Starting"));
    }

    #[test]
    fn test_select_attribute() {
        let out = cmd_select_attribute(&["/some/path"], None);
        assert!(out.contains("Selected attribute: /some/path"));
    }
}
