// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Output formatting helpers

/// Check whether the output is a terminal that likely supports color.
pub fn supports_color() -> bool {
    std::env::var("NO_COLOR").is_err() && atty_stdout()
}

fn atty_stdout() -> bool {
    // Simple heuristic: on Unix we can check isatty
    #[cfg(unix)]
    {
        extern "C" {
            fn isatty(fd: std::ffi::c_int) -> std::ffi::c_int;
        }
        // SAFETY: isatty on fd 1 (stdout) is always safe to call.
        unsafe { isatty(1) != 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Wrap `text` in ANSI bold if color is supported.
pub fn bold(text: &str) -> String {
    if supports_color() {
        format!("\x1b[1m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Wrap `text` in ANSI blue if color is supported.
pub fn blue(text: &str) -> String {
    if supports_color() {
        format!("\x1b[34m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Wrap `text` in ANSI yellow if color is supported.
pub fn yellow(text: &str) -> String {
    if supports_color() {
        format!("\x1b[33m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Format an adapter info line.
pub fn format_adapter_info(name: &str, address: &str, powered: bool) -> String {
    let state = if powered { "on" } else { "off" };
    format!(
        "Controller {} {} [{}]",
        bold(address),
        name,
        if powered {
            blue(state)
        } else {
            yellow(state)
        }
    )
}

/// Format a device info line.
pub fn format_device_info(address: &str, name: &str) -> String {
    format!("Device {} {}", bold(address), name)
}

/// Format a UUID with optional human-readable name.
pub fn format_uuid(uuid: &str, resolved_name: Option<&str>) -> String {
    match resolved_name {
        Some(n) => format!("{uuid} ({n})"),
        None => uuid.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_device_info_contains_address() {
        let info = format_device_info("AA:BB:CC:DD:EE:FF", "MyDevice");
        assert!(info.contains("AA:BB:CC:DD:EE:FF"));
        assert!(info.contains("MyDevice"));
    }
}
