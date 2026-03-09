// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Media player commands

use crate::shell::{CmdEntry, Menu};

/// Return the media player command entries.
pub fn commands() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            name: "player.show",
            help: "Show player info",
            handler: cmd_show,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.select",
            help: "Select media player <path>",
            handler: cmd_select,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.play",
            help: "Start playback",
            handler: cmd_play,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.pause",
            help: "Pause playback",
            handler: cmd_pause,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.stop",
            help: "Stop playback",
            handler: cmd_stop,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.next",
            help: "Next track",
            handler: cmd_next,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.previous",
            help: "Previous track",
            handler: cmd_previous,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.fast-forward",
            help: "Fast forward",
            handler: cmd_fast_forward,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.rewind",
            help: "Rewind",
            handler: cmd_rewind,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.equalizer",
            help: "Set equalizer <on/off>",
            handler: cmd_equalizer,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.repeat",
            help: "Set repeat <off/single/all/group>",
            handler: cmd_repeat,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.shuffle",
            help: "Set shuffle <off/all/group>",
            handler: cmd_shuffle,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.scan",
            help: "Set scan <off/all/group>",
            handler: cmd_player_scan,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.change-folder",
            help: "Change folder <path>",
            handler: cmd_change_folder,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.list-items",
            help: "List items in current folder",
            handler: cmd_list_items,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.search",
            help: "Search for items <string>",
            handler: cmd_search,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.queue",
            help: "Queue item <path>",
            handler: cmd_queue,
            menu: Menu::Main,
        },
        CmdEntry {
            name: "player.show-item",
            help: "Show item details <path>",
            handler: cmd_show_item,
            menu: Menu::Main,
        },
    ]
}

fn cmd_show(_args: &[&str], _adapter: Option<&str>) -> String {
    "Player info (requires D-Bus)".to_string()
}

fn cmd_select(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(path) => format!("Selected player: {path}"),
        None => "Usage: player.select <path>".to_string(),
    }
}

fn cmd_play(_args: &[&str], _adapter: Option<&str>) -> String {
    "Play (requires D-Bus)".to_string()
}

fn cmd_pause(_args: &[&str], _adapter: Option<&str>) -> String {
    "Pause (requires D-Bus)".to_string()
}

fn cmd_stop(_args: &[&str], _adapter: Option<&str>) -> String {
    "Stop (requires D-Bus)".to_string()
}

fn cmd_next(_args: &[&str], _adapter: Option<&str>) -> String {
    "Next (requires D-Bus)".to_string()
}

fn cmd_previous(_args: &[&str], _adapter: Option<&str>) -> String {
    "Previous (requires D-Bus)".to_string()
}

fn cmd_fast_forward(_args: &[&str], _adapter: Option<&str>) -> String {
    "Fast forward (requires D-Bus)".to_string()
}

fn cmd_rewind(_args: &[&str], _adapter: Option<&str>) -> String {
    "Rewind (requires D-Bus)".to_string()
}

fn cmd_equalizer(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some("on") => "Equalizer: on (requires D-Bus)".to_string(),
        Some("off") => "Equalizer: off (requires D-Bus)".to_string(),
        _ => "Usage: player.equalizer <on/off>".to_string(),
    }
}

fn cmd_repeat(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some(v @ ("off" | "single" | "all" | "group")) => {
            format!("Repeat: {v} (requires D-Bus)")
        }
        _ => "Usage: player.repeat <off/single/all/group>".to_string(),
    }
}

fn cmd_shuffle(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some(v @ ("off" | "all" | "group")) => format!("Shuffle: {v} (requires D-Bus)"),
        _ => "Usage: player.shuffle <off/all/group>".to_string(),
    }
}

fn cmd_player_scan(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first().copied() {
        Some(v @ ("off" | "all" | "group")) => format!("Scan: {v} (requires D-Bus)"),
        _ => "Usage: player.scan <off/all/group>".to_string(),
    }
}

fn cmd_change_folder(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(path) => format!("Change folder: {path} (requires D-Bus)"),
        None => "Usage: player.change-folder <path>".to_string(),
    }
}

fn cmd_list_items(_args: &[&str], _adapter: Option<&str>) -> String {
    "List items (requires D-Bus)".to_string()
}

fn cmd_search(args: &[&str], _adapter: Option<&str>) -> String {
    if args.is_empty() {
        "Usage: player.search <string>".to_string()
    } else {
        format!("Search: {} (requires D-Bus)", args.join(" "))
    }
}

fn cmd_queue(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(path) => format!("Queue: {path} (requires D-Bus)"),
        None => "Usage: player.queue <path>".to_string(),
    }
}

fn cmd_show_item(args: &[&str], _adapter: Option<&str>) -> String {
    match args.first() {
        Some(path) => format!("Show item: {path} (requires D-Bus)"),
        None => "Usage: player.show-item <path>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_player_select() {
        let out = cmd_select(&["/player1"], None);
        assert!(out.contains("/player1"));
    }

    #[test]
    fn test_player_repeat() {
        assert!(cmd_repeat(&["all"], None).contains("all"));
        assert!(cmd_repeat(&[], None).contains("Usage"));
    }
}
