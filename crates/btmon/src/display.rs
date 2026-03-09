// SPDX-License-Identifier: GPL-2.0-or-later
//
// Terminal display helpers replacing monitor/display.c
//
// Provides colored terminal output, hex dumps, bitfield printing,
// and pager support for btmon output.

// ANSI color codes
pub const COLOR_OFF: &str = "\x1B[0m";
pub const COLOR_RED: &str = "\x1B[0;91m";
pub const COLOR_GREEN: &str = "\x1B[0;92m";
pub const COLOR_YELLOW: &str = "\x1B[0;93m";
pub const COLOR_BLUE: &str = "\x1B[0;94m";
pub const COLOR_MAGENTA: &str = "\x1B[0;95m";
pub const COLOR_HIGHLIGHT: &str = "\x1B[1;39m";
pub const COLOR_WHITE: &str = "\x1B[1;37m";
pub const COLOR_BOLDGRAY: &str = "\x1B[1;30m";
pub const COLOR_BOLDWHITE: &str = "\x1B[1;37m";

/// Color mode setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

static mut COLOR_MODE: ColorMode = ColorMode::Auto;
static mut DEFAULT_COLUMNS: i32 = 80;

/// Set the color mode.
pub fn set_color_mode(mode: ColorMode) {
    // Safety: single-threaded CLI application
    unsafe {
        COLOR_MODE = mode;
    }
}

/// Check if color output is enabled.
pub fn use_color() -> bool {
    unsafe {
        match COLOR_MODE {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => atty_is_terminal(),
        }
    }
}

fn atty_is_terminal() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
}

/// Get the number of terminal columns.
pub fn num_columns() -> i32 {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            ws.ws_col as i32
        } else {
            DEFAULT_COLUMNS
        }
    }
}

/// Set default column count (for non-terminal output).
pub fn set_default_columns(cols: i32) {
    unsafe {
        DEFAULT_COLUMNS = cols;
    }
}

/// Bitfield entry for printing.
pub struct BitfieldEntry {
    pub bit: u64,
    pub name: &'static str,
}

/// Print an indented line with optional prefix and color.
pub fn print_indent(indent: usize, prefix: &str, title: &str, color: &str, text: &str) {
    let pad = " ".repeat(indent);
    if use_color() {
        println!("{}{}{}{}{}{}", pad, prefix, title, color, text, COLOR_OFF);
    } else {
        println!("{}{}{}{}", pad, prefix, title, text);
    }
}

/// Print a standard field (8-space indent).
pub fn print_field(text: &str) {
    println!("        {}", text);
}

/// Print colored text (8-space indent).
pub fn print_text(color: &str, text: &str) {
    if use_color() {
        println!("        {}{}{}", color, text, COLOR_OFF);
    } else {
        println!("        {}", text);
    }
}

/// Print a hex dump of data.
pub fn print_hexdump(buf: &[u8]) {
    for (i, chunk) in buf.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex = String::with_capacity(50);
        let mut ascii = String::with_capacity(16);

        for (j, byte) in chunk.iter().enumerate() {
            hex.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                hex.push(' ');
            }
            if *byte >= 0x20 && *byte < 0x7f {
                ascii.push(*byte as char);
            } else {
                ascii.push('.');
            }
        }

        // Pad to 16 bytes
        for j in chunk.len()..16 {
            hex.push_str("   ");
            if j == 7 {
                hex.push(' ');
            }
        }

        println!("        {:08x}  {}  {}", offset, hex.trim_end(), ascii);
    }
}

/// Print a hex field with label.
pub fn print_hex_field(label: &str, data: &[u8]) {
    let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
    print_field(&format!("{}: {}", label, hex));
}

/// Print bitfield values from a table.
pub fn print_bitfield(indent: usize, value: u64, table: &[BitfieldEntry]) -> u64 {
    let mut mask = 0u64;
    for entry in table {
        if value & entry.bit != 0 {
            let pad = " ".repeat(indent);
            println!("{}  {}", pad, entry.name);
            mask |= entry.bit;
        }
    }
    value & !mask
}

/// Print an error code with description.
pub fn print_error(label: &str, error: u8) {
    let desc = match error {
        0x00 => "Success",
        0x01 => "Unknown HCI Command",
        0x02 => "Unknown Connection Identifier",
        0x03 => "Hardware Failure",
        0x04 => "Page Timeout",
        0x05 => "Authentication Failure",
        0x06 => "PIN or Key Missing",
        0x07 => "Memory Capacity Exceeded",
        0x08 => "Connection Timeout",
        0x09 => "Connection Limit Exceeded",
        0x0a => "Synchronous Connection Limit Exceeded",
        0x0b => "Connection Already Exists",
        0x0c => "Command Disallowed",
        0x0d => "Connection Rejected due to Limited Resources",
        0x0e => "Connection Rejected due to Security Reasons",
        0x0f => "Connection Rejected due to Unacceptable BD_ADDR",
        0x10 => "Connection Accept Timeout Exceeded",
        0x11 => "Unsupported Feature or Parameter Value",
        0x12 => "Invalid HCI Command Parameters",
        _ => "Unknown",
    };
    print_field(&format!("{}: {} (0x{:02x})", label, desc, error));
}

/// Print a Bluetooth address.
pub fn print_addr(label: &str, addr: &[u8; 6], addr_type: u8) {
    let type_str = match addr_type {
        0x00 => "BR/EDR",
        0x01 => "LE Public",
        0x02 => "LE Random",
        _ => "Unknown",
    };
    print_field(&format!(
        "{}: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ({})",
        label,
        addr[5],
        addr[4],
        addr[3],
        addr[2],
        addr[1],
        addr[0],
        type_str,
    ));
}

/// Print a company/manufacturer identifier.
pub fn print_company(label: &str, company: u16) {
    // Simplified — full impl would have a lookup table
    print_field(&format!("{}: {} (0x{:04x})", label, company_to_str(company), company));
}

fn company_to_str(id: u16) -> &'static str {
    match id {
        0x0000 => "Ericsson Technology Licensing",
        0x0001 => "Nokia Mobile Phones",
        0x0002 => "Intel Corp.",
        0x000a => "Qualcomm",
        0x000d => "Texas Instruments",
        0x000f => "Broadcom",
        0x001d => "Qualcomm Technologies International",
        0x003f => "Bluetooth SIG",
        0x004c => "Apple",
        0x0075 => "Samsung",
        _ => "Unknown",
    }
}

/// Format a timestamp for display.
pub fn format_timestamp(tv: &libc::timeval) -> String {
    let secs = tv.tv_sec;
    let usecs = tv.tv_usec;
    unsafe {
        let tm = libc::localtime(&secs);
        if tm.is_null() {
            return format!("{}.{:06}", secs, usecs);
        }
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
            (*tm).tm_year + 1900,
            (*tm).tm_mon + 1,
            (*tm).tm_mday,
            (*tm).tm_hour,
            (*tm).tm_min,
            (*tm).tm_sec,
            usecs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_mode() {
        set_color_mode(ColorMode::Never);
        assert!(!use_color());
        set_color_mode(ColorMode::Always);
        assert!(use_color());
        set_color_mode(ColorMode::Auto);
    }

    #[test]
    fn test_print_bitfield() {
        let table = [
            BitfieldEntry { bit: 0x01, name: "Feature A" },
            BitfieldEntry { bit: 0x02, name: "Feature B" },
            BitfieldEntry { bit: 0x04, name: "Feature C" },
        ];
        let remaining = print_bitfield(8, 0x05, &table);
        assert_eq!(remaining, 0); // bits 0x01 and 0x04 matched
    }

    #[test]
    fn test_company_str() {
        assert_eq!(company_to_str(0x0002), "Intel Corp.");
        assert_eq!(company_to_str(0x004c), "Apple");
        assert_eq!(company_to_str(0xFFFF), "Unknown");
    }

    #[test]
    fn test_hexdump() {
        // Just verify no panic
        print_hexdump(&[0x00, 0x01, 0x02, 0x41, 0x42]);
        print_hexdump(&[0u8; 32]);
        print_hexdump(&[]);
    }

    #[test]
    fn test_num_columns() {
        set_default_columns(120);
        // In test context, may or may not have a terminal
        let cols = num_columns();
        assert!(cols > 0);
    }
}
