// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Interactive shell implementation

use std::collections::HashMap;

use rustyline::completion::Completer;
use rustyline::error::ReadlineError;
use rustyline::{Helper, Highlighter, Hinter, Validator};

use crate::cmd_adapter;
use crate::cmd_admin;
use crate::cmd_advertise;
use crate::cmd_device;
use crate::cmd_gatt;
use crate::cmd_mgmt;
use crate::cmd_monitor;
use crate::cmd_player;
use crate::cmd_scan;

/// A menu groups commands under a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Menu {
    Main,
    Scan,
    Advertise,
    Monitor,
    Gatt,
}

impl Menu {
    /// Return the prompt prefix for this menu.
    pub fn prefix(self) -> &'static str {
        match self {
            Menu::Main => "",
            Menu::Scan => "Scan",
            Menu::Advertise => "Advertise",
            Menu::Monitor => "Monitor",
            Menu::Gatt => "GATT",
        }
    }
}

/// Callback type for command execution.
type CmdHandler = fn(args: &[&str], adapter: Option<&str>) -> String;

/// Registration entry for a single CLI command.
pub struct CmdEntry {
    pub name: &'static str,
    pub help: &'static str,
    pub handler: CmdHandler,
    pub menu: Menu,
}

/// Build the full command table.
fn build_commands() -> Vec<CmdEntry> {
    let mut cmds = Vec::new();

    // Built-in commands (always available)
    cmds.push(CmdEntry {
        name: "version",
        help: "Display version",
        handler: |_, _| format!("bluetoothctl: {}", env!("CARGO_PKG_VERSION")),
        menu: Menu::Main,
    });

    // Adapter commands
    cmds.extend(cmd_adapter::commands());
    // Device commands
    cmds.extend(cmd_device::commands());
    // Scan commands
    cmds.extend(cmd_scan::commands());
    // GATT commands
    cmds.extend(cmd_gatt::commands());
    // Advertise commands
    cmds.extend(cmd_advertise::commands());
    // Admin commands
    cmds.extend(cmd_admin::commands());
    // Monitor commands
    cmds.extend(cmd_monitor::commands());
    // Player commands
    cmds.extend(cmd_player::commands());
    // Mgmt commands
    cmds.extend(cmd_mgmt::commands());

    cmds
}

/// Rustyline helper providing tab-completion.
#[derive(Helper, Validator, Highlighter, Hinter)]
struct ShellHelper {
    names: Vec<String>,
}

impl Completer for ShellHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        let prefix = &line[..pos];
        let start = prefix.rfind(' ').map_or(0, |i| i + 1);
        let word = &prefix[start..];
        let matches: Vec<String> = self
            .names
            .iter()
            .filter(|n| n.starts_with(word))
            .cloned()
            .collect();
        Ok((start, matches))
    }
}

/// The interactive shell.
pub struct Shell {
    adapter: Option<String>,
    #[allow(dead_code)]
    monitor: bool,
    menu: Menu,
    commands: Vec<CmdEntry>,
    /// Lookup from command name to index in `commands`.
    index: HashMap<String, usize>,
}

impl Shell {
    /// Create a new shell instance.
    pub fn new(adapter: Option<&str>, monitor: bool) -> Self {
        let commands = build_commands();
        let index = commands
            .iter()
            .enumerate()
            .map(|(i, c)| (c.name.to_string(), i))
            .collect();
        Self {
            adapter: adapter.map(String::from),
            monitor,
            menu: Menu::Main,
            commands,
            index,
        }
    }

    /// Format the prompt string.
    fn prompt(&self) -> String {
        let ctrl = self.adapter.as_deref().unwrap_or("bluetooth");
        let prefix = self.menu.prefix();
        if prefix.is_empty() {
            format!("[{ctrl}]# ")
        } else {
            format!("[{ctrl}:{prefix}]# ")
        }
    }

    /// Dispatch a single command line. Returns output text.
    pub fn dispatch(&mut self, line: &str) -> Option<String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }
        let cmd_name = parts[0];
        let args = &parts[1..];

        // Built-in navigation commands
        match cmd_name {
            "quit" | "exit" => return Some("__QUIT__".to_string()),
            "help" => return Some(self.help_text()),
            "back" => {
                self.menu = Menu::Main;
                return Some(String::new());
            }
            "menu" => {
                if let Some(name) = args.first() {
                    match *name {
                        "scan" => self.menu = Menu::Scan,
                        "advertise" => self.menu = Menu::Advertise,
                        "monitor" => self.menu = Menu::Monitor,
                        "gatt" => self.menu = Menu::Gatt,
                        other => return Some(format!("Unknown menu: {other}")),
                    }
                    return Some(String::new());
                }
                return Some("Usage: menu <name>".to_string());
            }
            _ => {}
        }

        if let Some(&idx) = self.index.get(cmd_name) {
            let entry = &self.commands[idx];
            let output = (entry.handler)(args, self.adapter.as_deref());
            Some(output)
        } else {
            Some(format!("Unknown command: {cmd_name}"))
        }
    }

    /// Generate help text for the current menu.
    fn help_text(&self) -> String {
        let mut out = String::from("Available commands:\n");
        out.push_str("  help            Show this help\n");
        out.push_str("  quit/exit       Quit the program\n");
        out.push_str("  back            Return to main menu\n");
        out.push_str("  menu <name>     Enter a submenu (scan, advertise, monitor, gatt)\n");
        out.push_str("  version         Display version\n");
        for cmd in &self.commands {
            if cmd.menu == self.menu || cmd.menu == Menu::Main {
                out.push_str(&format!("  {:<16}{}\n", cmd.name, cmd.help));
            }
        }
        out
    }

    /// Run the shell in interactive mode (read-eval-print loop).
    pub async fn run_interactive(&mut self) {
        let names: Vec<String> = {
            let mut n: Vec<String> = self.commands.iter().map(|c| c.name.to_string()).collect();
            n.extend(["help", "quit", "exit", "back", "menu", "version"].map(String::from));
            n.sort();
            n.dedup();
            n
        };

        let helper = ShellHelper { names };
        let config = rustyline::Config::builder()
            .auto_add_history(true)
            .build();
        let mut rl = rustyline::Editor::with_config(config).expect("failed to create editor");
        rl.set_helper(Some(helper));

        loop {
            let prompt = self.prompt();
            match rl.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some(output) = self.dispatch(line) {
                        if output == "__QUIT__" {
                            break;
                        }
                        if !output.is_empty() {
                            println!("{output}");
                        }
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
                Err(e) => {
                    eprintln!("Error: {e}");
                    break;
                }
            }
        }
    }

    /// Run a single command (non-interactive / one-shot mode).
    pub async fn run_command(&mut self, line: &str, _timeout: Option<u64>) {
        if let Some(output) = self.dispatch(line) {
            if output != "__QUIT__" && !output.is_empty() {
                println!("{output}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_version() {
        let mut shell = Shell::new(None, false);
        let out = shell.dispatch("version").unwrap();
        assert!(out.contains("bluetoothctl:"));
    }

    #[test]
    fn test_dispatch_unknown_command() {
        let mut shell = Shell::new(None, false);
        let out = shell.dispatch("xyzzy").unwrap();
        assert!(out.contains("Unknown command"));
    }

    #[test]
    fn test_menu_navigation() {
        let mut shell = Shell::new(None, false);
        assert_eq!(shell.menu, Menu::Main);
        shell.dispatch("menu scan");
        assert_eq!(shell.menu, Menu::Scan);
        shell.dispatch("back");
        assert_eq!(shell.menu, Menu::Main);
    }
}
