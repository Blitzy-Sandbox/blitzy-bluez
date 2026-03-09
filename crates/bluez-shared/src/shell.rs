// SPDX-License-Identifier: GPL-2.0-or-later
//
// Interactive shell helpers replacing src/shared/shell.c
//
// Provides a menu-driven interactive shell for Bluetooth CLI tools
// (bluetoothctl, etc.). Uses rustyline for line editing instead of
// GNU readline.

use std::collections::HashMap;

// Terminal color codes matching C shell.h
pub const COLOR_OFF: &str = "\x1B[0m";
pub const COLOR_RED: &str = "\x1B[0;91m";
pub const COLOR_GREEN: &str = "\x1B[0;92m";
pub const COLOR_YELLOW: &str = "\x1B[0;93m";
pub const COLOR_BLUE: &str = "\x1B[0;94m";
pub const COLOR_BOLDGRAY: &str = "\x1B[1;30m";
pub const COLOR_BOLDWHITE: &str = "\x1B[1;37m";
pub const COLOR_HIGHLIGHT: &str = "\x1B[1;39m";

/// A single menu entry (command).
#[derive(Clone)]
pub struct ShellMenuEntry {
    /// Command name.
    pub cmd: String,
    /// Argument description (for help text).
    pub arg: String,
    /// Human-readable description.
    pub desc: String,
    /// Command handler.
    pub func: fn(args: &[&str]),
}

/// A menu containing multiple command entries.
#[derive(Clone)]
pub struct ShellMenu {
    /// Menu name.
    pub name: String,
    /// Menu description.
    pub desc: String,
    /// Command entries.
    pub entries: Vec<ShellMenuEntry>,
}

impl ShellMenu {
    /// Create a new menu.
    pub fn new(name: &str, desc: &str) -> Self {
        Self {
            name: name.to_string(),
            desc: desc.to_string(),
            entries: Vec::new(),
        }
    }

    /// Add a command entry.
    pub fn add_entry(&mut self, cmd: &str, arg: &str, desc: &str, func: fn(&[&str])) {
        self.entries.push(ShellMenuEntry {
            cmd: cmd.to_string(),
            arg: arg.to_string(),
            desc: desc.to_string(),
            func,
        });
    }

    /// Find an entry by command name.
    pub fn find_entry(&self, cmd: &str) -> Option<&ShellMenuEntry> {
        self.entries.iter().find(|e| e.cmd == cmd)
    }
}

/// Shell state.
pub struct BtShell {
    /// Main menu.
    main_menu: Option<ShellMenu>,
    /// Current active menu.
    current_menu: Option<String>,
    /// Submenus.
    submenus: Vec<ShellMenu>,
    /// Environment variables.
    env: HashMap<String, String>,
    /// Prompt string.
    prompt: String,
    /// Prompt color.
    prompt_color: String,
    /// Timeout in seconds (0 = no timeout).
    pub timeout: u32,
    /// Whether the shell is in non-interactive mode.
    pub non_interactive: bool,
}

impl BtShell {
    /// Create a new shell instance.
    pub fn new() -> Self {
        Self {
            main_menu: None,
            current_menu: None,
            submenus: Vec::new(),
            env: HashMap::new(),
            prompt: String::new(),
            prompt_color: COLOR_BLUE.to_string(),
            timeout: 0,
            non_interactive: false,
        }
    }

    /// Set the main menu.
    pub fn set_menu(&mut self, menu: ShellMenu) {
        let name = menu.name.clone();
        self.main_menu = Some(menu);
        self.current_menu = Some(name);
    }

    /// Add a submenu.
    pub fn add_submenu(&mut self, menu: ShellMenu) {
        self.submenus.push(menu);
    }

    /// Remove a submenu by name.
    pub fn remove_submenu(&mut self, name: &str) -> bool {
        let len = self.submenus.len();
        self.submenus.retain(|m| m.name != name);
        self.submenus.len() < len
    }

    /// Set the prompt string and color.
    pub fn set_prompt(&mut self, prompt: &str, color: &str) {
        self.prompt = prompt.to_string();
        self.prompt_color = color.to_string();
    }

    /// Get the formatted prompt.
    pub fn get_prompt(&self) -> String {
        if self.prompt.is_empty() {
            return String::new();
        }
        format!("{}{}{}> ", self.prompt_color, self.prompt, COLOR_OFF)
    }

    /// Set an environment variable.
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env.insert(name.to_string(), value.to_string());
    }

    /// Get an environment variable.
    pub fn get_env(&self, name: &str) -> Option<&str> {
        self.env.get(name).map(|s| s.as_str())
    }

    /// Get the active menu (current or main).
    fn active_menu(&self) -> Option<&ShellMenu> {
        if let Some(ref name) = self.current_menu {
            // Check submenus first
            if let Some(sub) = self.submenus.iter().find(|m| &m.name == name) {
                return Some(sub);
            }
        }
        self.main_menu.as_ref()
    }

    /// Execute a command line.
    pub fn exec(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return false;
        }

        let cmd = parts[0];
        let args = &parts[1..];

        // Check for menu.command syntax
        if let Some(dot_pos) = cmd.find('.') {
            let menu_name = &cmd[..dot_pos];
            let sub_cmd = &cmd[dot_pos + 1..];
            if let Some(menu) = self.submenus.iter().find(|m| m.name == menu_name) {
                if let Some(entry) = menu.find_entry(sub_cmd) {
                    (entry.func)(args);
                    return true;
                }
            }
            return false;
        }

        // Look up in active menu
        if let Some(menu) = self.active_menu() {
            if let Some(entry) = menu.find_entry(cmd) {
                (entry.func)(args);
                return true;
            }
        }

        false
    }

    /// Print the current menu.
    pub fn print_menu(&self) {
        if let Some(menu) = self.active_menu() {
            println!("{}Menu {}:{}", COLOR_HIGHLIGHT, menu.name, COLOR_OFF);
            println!("Available commands:");
            println!("-------------------");
            for entry in &menu.entries {
                let cmd_width = 48 - entry.cmd.len();
                println!(
                    "{}{} {:width$} {}{}",
                    COLOR_HIGHLIGHT,
                    entry.cmd,
                    entry.arg,
                    entry.desc,
                    COLOR_OFF,
                    width = cmd_width,
                );
            }
        }

        if !self.submenus.is_empty() {
            println!();
            for sub in &self.submenus {
                println!(
                    "{}{} {:width$} {}{}",
                    COLOR_BLUE,
                    sub.name,
                    "",
                    sub.desc,
                    COLOR_OFF,
                    width = 48 - sub.name.len(),
                );
            }
        }
    }

    /// Get completions for a partial command.
    pub fn complete(&self, partial: &str) -> Vec<String> {
        let mut completions = Vec::new();

        if let Some(menu) = self.active_menu() {
            for entry in &menu.entries {
                if entry.cmd.starts_with(partial) {
                    completions.push(entry.cmd.clone());
                }
            }
        }

        // Also complete submenu names
        for sub in &self.submenus {
            if sub.name.starts_with(partial) {
                completions.push(format!("{}.", sub.name));
            }
        }

        completions
    }
}

impl Default for BtShell {
    fn default() -> Self {
        Self::new()
    }
}

/// Print colored text.
pub fn shell_print(color: &str, text: &str) {
    println!("{}{}{}", color, text, COLOR_OFF);
}

/// Print a hex dump of data.
pub fn shell_hexdump(buf: &[u8]) {
    for (i, chunk) in buf.chunks(16).enumerate() {
        let offset = i * 16;
        print!("  {:08x}  ", offset);
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }
        // Pad if less than 16 bytes
        for j in chunk.len()..16 {
            print!("   ");
            if j == 7 {
                print!(" ");
            }
        }
        print!(" ");
        for byte in chunk {
            if *byte >= 0x20 && *byte < 0x7f {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_cmd(_args: &[&str]) {}

    #[test]
    fn test_shell_menu() {
        let mut menu = ShellMenu::new("main", "Main menu");
        menu.add_entry("help", "", "Show help", dummy_cmd);
        menu.add_entry("quit", "", "Quit", dummy_cmd);

        assert_eq!(menu.entries.len(), 2);
        assert!(menu.find_entry("help").is_some());
        assert!(menu.find_entry("nonexistent").is_none());
    }

    #[test]
    fn test_shell_exec() {
        let mut shell = BtShell::new();
        let mut menu = ShellMenu::new("main", "Main menu");
        menu.add_entry("test", "[arg]", "Test command", dummy_cmd);
        shell.set_menu(menu);

        assert!(shell.exec("test arg1 arg2"));
        assert!(!shell.exec("nonexistent"));
    }

    #[test]
    fn test_shell_env() {
        let mut shell = BtShell::new();
        assert!(shell.get_env("key").is_none());
        shell.set_env("key", "value");
        assert_eq!(shell.get_env("key"), Some("value"));
    }

    #[test]
    fn test_shell_completions() {
        let mut shell = BtShell::new();
        let mut menu = ShellMenu::new("main", "Main menu");
        menu.add_entry("help", "", "Help", dummy_cmd);
        menu.add_entry("history", "", "History", dummy_cmd);
        menu.add_entry("quit", "", "Quit", dummy_cmd);
        shell.set_menu(menu);

        let completions = shell.complete("h");
        assert_eq!(completions.len(), 2);
        assert!(completions.contains(&"help".to_string()));
        assert!(completions.contains(&"history".to_string()));
    }

    #[test]
    fn test_shell_prompt() {
        let mut shell = BtShell::new();
        assert_eq!(shell.get_prompt(), "");
        shell.set_prompt("bluetooth", COLOR_BLUE);
        let prompt = shell.get_prompt();
        assert!(prompt.contains("bluetooth"));
    }

    #[test]
    fn test_hexdump() {
        // Just verify it doesn't panic
        shell_hexdump(&[0x00, 0x01, 0x02, 0x41, 0x42]);
        shell_hexdump(&[0u8; 32]);
        shell_hexdump(&[]);
    }

    #[test]
    fn test_submenu() {
        let mut shell = BtShell::new();
        let mut main = ShellMenu::new("main", "Main");
        main.add_entry("help", "", "Help", dummy_cmd);
        shell.set_menu(main);

        let mut sub = ShellMenu::new("scan", "Scan commands");
        sub.add_entry("on", "", "Start scanning", dummy_cmd);
        shell.add_submenu(sub);

        assert!(shell.exec("scan.on"));
        assert!(!shell.exec("scan.off"));
        assert!(shell.remove_submenu("scan"));
        assert!(!shell.remove_submenu("scan"));
    }
}
