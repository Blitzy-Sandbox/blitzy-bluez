// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014 Intel Corporation
 * Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
 *
 * display.rs — Terminal output formatting, ANSI color management,
 *              pager fork/exec, hexdump and bitfield printing.
 *
 * Complete Rust rewrite of monitor/display.c + monitor/display.h from BlueZ v5.86.
 * Provides foundational formatting used by all other btmon modules.
 */

use std::io::{self, Write};
use std::os::unix::io::IntoRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};

// ============================================================================
// ANSI Color Escape Constants (from display.h lines 21-41)
// ============================================================================

/// Reset all attributes.
pub const COLOR_OFF: &str = "\x1B[0m";

/// Standard foreground black.
pub const COLOR_BLACK: &str = "\x1B[0;30m";

/// Standard foreground red.
pub const COLOR_RED: &str = "\x1B[0;31m";

/// Standard foreground green.
pub const COLOR_GREEN: &str = "\x1B[0;32m";

/// Standard foreground yellow.
pub const COLOR_YELLOW: &str = "\x1B[0;33m";

/// Standard foreground blue.
pub const COLOR_BLUE: &str = "\x1B[0;34m";

/// Standard foreground magenta.
pub const COLOR_MAGENTA: &str = "\x1B[0;35m";

/// Standard foreground cyan.
pub const COLOR_CYAN: &str = "\x1B[0;36m";

/// Standard foreground white.
pub const COLOR_WHITE: &str = "\x1B[0;37m";

/// White background with black text — used for unknown/unrecognised items.
pub const COLOR_WHITE_BG: &str = "\x1B[0;47;30m";

/// Bold default color — used for prominent text.
pub const COLOR_HIGHLIGHT: &str = "\x1B[1;39m";

/// Bold red.
pub const COLOR_RED_BOLD: &str = "\x1B[1;31m";

/// Bold green.
pub const COLOR_GREEN_BOLD: &str = "\x1B[1;32m";

/// Bold blue.
pub const COLOR_BLUE_BOLD: &str = "\x1B[1;34m";

/// Bold magenta.
pub const COLOR_MAGENTA_BOLD: &str = "\x1B[1;35m";

/// Error severity — bold red, same as `COLOR_RED_BOLD`.
pub const COLOR_ERROR: &str = "\x1B[1;31m";

/// Warning severity — bold text.
pub const COLOR_WARN: &str = "\x1B[1m";

/// Informational severity — attribute reset, same as `COLOR_OFF`.
pub const COLOR_INFO: &str = "\x1B[0m";

/// Debug severity — white/grey, same as `COLOR_WHITE`.
pub const COLOR_DEBUG: &str = "\x1B[0;37m";

// ============================================================================
// HCI / Protocol Packet-Type Color Aliases
// (from monitor/packet.c color assignments in C source)
// ============================================================================

/// HCI command packets — blue.
pub const COLOR_HCI_COMMAND: &str = "\x1B[0;34m";

/// Unknown HCI commands — white background.
pub const COLOR_HCI_COMMAND_UNKNOWN: &str = "\x1B[0;47;30m";

/// HCI data packets — cyan (matching ACL data coloring).
pub const COLOR_HCI_DATA: &str = "\x1B[0;36m";

/// HCI event packets — magenta.
pub const COLOR_HCI_EVENT: &str = "\x1B[0;35m";

/// Unknown HCI events — white background.
pub const COLOR_HCI_EVENT_UNKNOWN: &str = "\x1B[0;47;30m";

/// HCI ACL data packets — cyan.
pub const COLOR_HCI_ACLDATA: &str = "\x1B[0;36m";

/// HCI SCO data packets — yellow.
pub const COLOR_HCI_SCODATA: &str = "\x1B[0;33m";

/// HCI ISO data packets — yellow.
pub const COLOR_HCI_ISODATA: &str = "\x1B[0;33m";

/// PHY-layer packets — blue.
pub const COLOR_PHY_PACKET: &str = "\x1B[0;34m";

/// Management API events — bold magenta (matches CTRL_EVENT in C source).
pub const COLOR_MGMT_EVENT: &str = "\x1B[1;35m";

/// System notes — attribute reset.
pub const COLOR_SYSTEM_NOTE: &str = "\x1B[0m";

/// Vendor diagnostic messages — yellow.
pub const COLOR_VENDOR_DIAG: &str = "\x1B[0;33m";

/// Update notifications — yellow.
pub const COLOR_UPDATE: &str = "\x1B[0;33m";

// ============================================================================
// Terminal Width Fallback
// ============================================================================

/// Default terminal width when TIOCGWINSZ ioctl fails or stdout is not a TTY.
pub const FALLBACK_TERMINAL_WIDTH: i32 = 80;

// ============================================================================
// Monitor Color Policy Enum
// ============================================================================

/// Controls whether ANSI color escapes are emitted in output.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MonitorColor {
    /// Detect automatically based on isatty(stdout) or active pager.
    Auto,
    /// Always emit color escapes regardless of terminal status.
    Always,
    /// Never emit color escapes.
    Never,
}

// ============================================================================
// Bitfield Data Structure
// ============================================================================

/// Describes a single bit position and its human-readable label for bitfield
/// printing. Used by `print_bitfield` to iterate a table of bit definitions.
pub struct BitfieldData {
    /// Bit position (0-63) within the value.
    pub bit: u64,
    /// Human-readable label for this bit.
    pub str_val: &'static str,
}

// ============================================================================
// Module-Level Mutable State
//
// Matches the C static globals: pager_pid, default_pager_num_columns,
// setting_monitor_color, and two caching sentinels (cached_use_color,
// cached_num_columns).  AtomicI32 is used for simple cached values;
// Mutex protects the pager child handle and color setting.
// ============================================================================

/// Current color output policy (default: Auto).
static MONITOR_COLOR: Mutex<MonitorColor> = Mutex::new(MonitorColor::Auto);

/// PID of the spawned pager child process, if active.
static PAGER_PID: Mutex<Option<u32>> = Mutex::new(None);

/// Handle to the spawned pager child process for clean wait-on-close.
static PAGER_CHILD: Mutex<Option<Child>> = Mutex::new(None);

/// Fallback column count when TIOCGWINSZ is unavailable.
static DEFAULT_PAGER_NUM_COLUMNS: AtomicI32 = AtomicI32::new(FALLBACK_TERMINAL_WIDTH);

/// Cached result of `use_color()`:  -1 = not yet computed, 0 = false, 1 = true.
static CACHED_USE_COLOR: AtomicI32 = AtomicI32::new(-1);

/// Cached terminal column count:  -1 = not yet computed.
static CACHED_NUM_COLUMNS: AtomicI32 = AtomicI32::new(-1);

// ============================================================================
// Color Management
// ============================================================================

/// Set the color output policy.  Resets the cached auto-detection result so
/// the next call to `use_color()` re-evaluates.
pub fn set_monitor_color(color: MonitorColor) {
    if let Ok(mut mc) = MONITOR_COLOR.lock() {
        *mc = color;
    }
    // Invalidate cached value so use_color() recomputes
    CACHED_USE_COLOR.store(-1, Ordering::Relaxed);
}

/// Returns `true` if ANSI color escape sequences should be emitted.
///
/// Behaviour mirrors the C implementation exactly:
///   - `Always` → true
///   - `Never`  → false
///   - `Auto`   → `isatty(STDOUT_FILENO) || pager_pid > 0`, cached after first call
pub fn use_color() -> bool {
    // Read the current policy
    let color = MONITOR_COLOR.lock().map(|c| *c).unwrap_or(MonitorColor::Auto);

    match color {
        MonitorColor::Always => true,
        MonitorColor::Never => false,
        MonitorColor::Auto => {
            // Return cached value if already computed
            let cached = CACHED_USE_COLOR.load(Ordering::Relaxed);
            if cached >= 0 {
                return cached != 0;
            }

            let pager_active = PAGER_PID.lock().map(|p| p.is_some()).unwrap_or(false);
            let is_tty = nix::unistd::isatty(libc::STDOUT_FILENO).unwrap_or(false);
            let result = is_tty || pager_active;

            CACHED_USE_COLOR.store(i32::from(result), Ordering::Relaxed);
            result
        }
    }
}

// ============================================================================
// Terminal Width Detection
// ============================================================================

/// Override the fallback column count used when the terminal width cannot be
/// detected via ioctl.
pub fn set_default_pager_num_columns(columns: i32) {
    DEFAULT_PAGER_NUM_COLUMNS.store(columns, Ordering::Relaxed);
}

/// Returns the number of terminal columns, cached after first call.
///
/// Tries TIOCGWINSZ via ioctl first; falls back to the default pager column
/// count (initially `FALLBACK_TERMINAL_WIDTH`).
pub fn num_columns() -> i32 {
    let cached = CACHED_NUM_COLUMNS.load(Ordering::Relaxed);
    if cached >= 0 {
        return cached;
    }

    let cols = get_terminal_width().unwrap_or(0);
    let result =
        if cols == 0 { DEFAULT_PAGER_NUM_COLUMNS.load(Ordering::Relaxed) } else { i32::from(cols) };

    CACHED_NUM_COLUMNS.store(result, Ordering::Relaxed);
    result
}

/// Query the terminal width via TIOCGWINSZ ioctl on stdout.
/// Returns `None` if the ioctl fails or reports zero columns.
///
/// Delegates to `sys::terminal::get_terminal_width()` — the actual unsafe
/// ioctl call is confined to the designated FFI boundary module.
fn get_terminal_width() -> Option<u16> {
    crate::sys::terminal::get_terminal_width()
}

// ============================================================================
// Pager Management
// ============================================================================

/// Spawn a pager process and redirect stdout through it.
///
/// Replicates the C `open_pager()` logic:
///  1. If a pager is already active, return immediately.
///  2. Check `$PAGER` — skip if empty or `"cat"`.
///  3. Skip if stdout is not a TTY.
///  4. Cache terminal width before the TTY is replaced by a pipe.
///  5. Try pager programs: `$PAGER` (direct, then via `/bin/sh -c`),
///     `"pager"`, `"less"`, `"more"`.
///  6. On success, redirect stdout to the pager's stdin pipe and store the PID.
pub fn open_pager() {
    // If pager is already active, do nothing
    if let Ok(pid) = PAGER_PID.lock() {
        if pid.is_some() {
            return;
        }
    }

    // Read $PAGER — if explicitly set to empty or "cat", disable pager
    let pager_env = std::env::var("PAGER").ok();
    if let Some(ref pager) = pager_env {
        if pager.is_empty() || pager == "cat" {
            return;
        }
    }

    // Only use a pager when stdout is a terminal
    if !nix::unistd::isatty(libc::STDOUT_FILENO).unwrap_or(false) {
        return;
    }

    // Cache terminal width before forking — the pipe will not be a TTY
    num_columns();

    // Build the ordered list of pager candidates to try
    let mut candidates: Vec<PagerCandidate> = Vec::new();

    if let Some(ref pager) = pager_env {
        // Custom $PAGER: try direct exec first, then via shell
        candidates.push(PagerCandidate::Direct(pager.clone()));
        candidates.push(PagerCandidate::Shell(pager.clone()));
    }
    // Fallback chain: pager → less → more
    candidates.push(PagerCandidate::Direct("pager".to_string()));
    candidates.push(PagerCandidate::Direct("less".to_string()));
    candidates.push(PagerCandidate::Direct("more".to_string()));

    for candidate in &candidates {
        if try_spawn_pager(candidate) {
            return;
        }
    }
}

/// Candidate pager program specification.
enum PagerCandidate {
    /// Execute the program directly (execlp-style).
    Direct(String),
    /// Execute via `/bin/sh -c <cmd>` for shell-syntax pager commands.
    Shell(String),
}

/// Attempt to spawn a pager subprocess and redirect stdout to its stdin pipe.
/// Returns `true` on success.
///
/// Fd redirection (dup2/close) is delegated to `sys::terminal::redirect_stdout`
/// — the designated FFI boundary module.
fn try_spawn_pager(candidate: &PagerCandidate) -> bool {
    let mut cmd = match candidate {
        PagerCandidate::Direct(prog) => Command::new(prog),
        PagerCandidate::Shell(shell_cmd) => {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(shell_cmd);
            c
        }
    };

    cmd.stdin(Stdio::piped());

    // Replicate setenv("LESS", "FRSX", 0) — only set if not already present
    if std::env::var_os("LESS").is_none() {
        cmd.env("LESS", "FRSX");
    }

    match cmd.spawn() {
        Ok(mut child) => {
            let child_id = child.id();

            if let Some(stdin) = child.stdin.take() {
                let write_fd = stdin.into_raw_fd();

                // Redirect our stdout to the pager pipe — all unsafe dup2/close
                // operations are confined to the sys::terminal FFI boundary.
                if !crate::sys::terminal::redirect_stdout(write_fd) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }

            // Store pager PID and child handle
            if let Ok(mut pid) = PAGER_PID.lock() {
                *pid = Some(child_id);
            }
            if let Ok(mut ch) = PAGER_CHILD.lock() {
                *ch = Some(child);
            }

            // Invalidate the use_color cache so it re-checks with pager active
            CACHED_USE_COLOR.store(-1, Ordering::Relaxed);

            true
        }
        Err(_) => false,
    }
}

/// Close the active pager, flush remaining output, and wait for the pager
/// process to exit.
///
/// Replicates the C `close_pager()` logic:
///  1. Flush stdout, then close the fd (signals EOF to pager).
///  2. Send SIGCONT to wake the pager (it may be stopped/paused).
///  3. Wait for the pager process to terminate.
///
/// Stdout close is delegated to `sys::terminal::close_stdout` — the
/// designated FFI boundary module.
pub fn close_pager() {
    let pid = PAGER_PID.lock().map(|p| *p).unwrap_or(None);

    if pid.is_none() {
        return;
    }

    let pid = pid.unwrap();

    // Flush any buffered output, then close stdout fd to signal EOF to pager.
    let _ = io::stdout().flush();
    crate::sys::terminal::close_stdout();

    // Send SIGCONT to wake the pager in case it is stopped/paused
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as libc::c_int),
        nix::sys::signal::Signal::SIGCONT,
    );

    // Wait for the pager to exit — Child::wait handles EINTR internally
    if let Ok(mut child_guard) = PAGER_CHILD.lock() {
        if let Some(ref mut child) = *child_guard {
            let _ = child.wait();
        }
        *child_guard = None;
    }

    // Reset pager state
    if let Ok(mut p) = PAGER_PID.lock() {
        *p = None;
    }
}

// ============================================================================
// Formatting Macros
//
// These macros replicate the C preprocessor macros from display.h.
// They are exported at the crate root via #[macro_export] so all btmon
// modules can use them directly.
// ============================================================================

/// Core indented output macro.  Mirrors the C `print_indent` macro:
///
/// ```text
/// printf("%*c%s%s%s%s" fmt "%s\n",
///        indent, ' ',
///        use_color() ? color1 : "", prefix, title,
///        use_color() ? color2 : "",
///        /* args */,
///        use_color() ? COLOR_OFF : "");
/// ```
///
/// The `%*c` pad produces `indent` characters of space, then the prefix/title
/// are bracketed by color escapes, followed by the formatted content and a
/// trailing COLOR_OFF + newline.
#[macro_export]
macro_rules! print_indent {
    ($indent:expr, $color1:expr, $prefix:expr, $title:expr, $color2:expr, $($arg:tt)*) => {{
        let _use_col = $crate::display::use_color();
        print!("{:>width$}{}{}{}{}",
            ' ',
            if _use_col { $color1 } else { "" },
            $prefix,
            $title,
            if _use_col { $color2 } else { "" },
            width = ($indent) as usize);
        print!($($arg)*);
        if _use_col {
            println!("{}", $crate::display::COLOR_OFF);
        } else {
            println!();
        }
    }};
}

/// Print formatted text at indent 8 with an optional color.
/// Equivalent to the C `print_text(color, fmt, ...)` macro.
#[macro_export]
macro_rules! print_text {
    ($color:expr, $($arg:tt)*) => {{
        $crate::print_indent!(
            8,
            $crate::display::COLOR_OFF,
            "",
            "",
            $color,
            $($arg)*
        );
    }};
}

/// Print a field label and value at indent 8 with no color highlighting.
/// Equivalent to the C `print_field(fmt, ...)` macro.
#[macro_export]
macro_rules! print_field {
    ($($arg:tt)*) => {{
        $crate::print_indent!(
            8,
            $crate::display::COLOR_OFF,
            "",
            "",
            $crate::display::COLOR_OFF,
            $($arg)*
        );
    }};
}

// ============================================================================
// Bitfield Printing
// ============================================================================

/// Iterate a bitfield table, printing each set bit's label and clearing it
/// from the returned mask.
///
/// Returns the remaining mask (bits not matched by any table entry), which
/// the caller can use to report unknown/reserved bits.
///
/// Mirrors the C `print_bitfield()` inline function from display.h.
pub fn print_bitfield(indent: i32, val: u64, table: &[BitfieldData]) -> u64 {
    let mut mask = val;

    for entry in table {
        if val & (1u64 << entry.bit) != 0 {
            print_field!("{:>width$}{}", ' ', entry.str_val, width = indent as usize);
            mask &= !(1u64 << entry.bit);
        }
    }

    mask
}

// ============================================================================
// Hexdump Functions
// ============================================================================

/// Format and print a byte buffer as a hex + ASCII dump.
///
/// Produces 16-byte lines in the exact format of the C `print_hexdump()`:
///
/// ```text
/// XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX  ................
/// ```
///
/// Layout (68-byte working buffer per line):
///   - Positions  0–47: hex pairs with trailing spaces (`(i%16)*3`)
///   - Positions 47–48: separator (two spaces)
///   - Positions 49–64: printable ASCII or `.`
///   - Position     65: NUL terminator
///
/// Non-printable bytes (outside 0x20..=0x7e) are rendered as `.` in the
/// ASCII column, matching C `isprint()` in the "C" locale.
pub fn print_hexdump(buf: &[u8]) {
    const HEXDIGITS: &[u8; 16] = b"0123456789abcdef";

    if buf.is_empty() {
        return;
    }

    // Working buffer — 68 bytes, initialised to spaces.
    let mut line = [b' '; 68];

    for (i, &byte) in buf.iter().enumerate() {
        let pos = i % 16;

        // Hex pair at (pos * 3) .. (pos * 3 + 2)
        line[pos * 3] = HEXDIGITS[(byte >> 4) as usize];
        line[pos * 3 + 1] = HEXDIGITS[(byte & 0x0f) as usize];
        line[pos * 3 + 2] = b' ';

        // ASCII representation at (pos + 49)
        line[pos + 49] = if (0x20..=0x7e).contains(&byte) { byte } else { b'.' };

        // Emit a complete 16-byte line
        if (i + 1) % 16 == 0 {
            line[47] = b' ';
            line[48] = b' ';
            line[65] = 0;
            let s = std::str::from_utf8(&line[..65]).unwrap_or("");
            print_text!(COLOR_WHITE, "{}", s);
            // Reset first char (matches C behaviour, harmless on next iteration)
            line[0] = b' ';
        }
    }

    // Handle final partial line (< 16 bytes)
    if buf.len() % 16 > 0 {
        let remaining = buf.len() % 16;
        for j in remaining..16 {
            line[j * 3] = b' ';
            line[j * 3 + 1] = b' ';
            line[j * 3 + 2] = b' ';
            line[j + 49] = b' ';
        }
        line[47] = b' ';
        line[48] = b' ';
        line[65] = 0;
        let s = std::str::from_utf8(&line[..65]).unwrap_or("");
        print_text!(COLOR_WHITE, "{}", s);
    }
}

/// Print a labelled hex dump: `"{label} ({len} octets):"` header followed
/// by the hex + ASCII dump body.  If `data` is empty, prints just the label
/// line with no dump.
pub fn print_hex_field(label: &str, data: &[u8]) {
    if data.is_empty() {
        print_field!("{}: ", label);
        return;
    }
    print_field!("{} ({} octet{}):", label, data.len(), if data.len() == 1 { "" } else { "s" });
    print_hexdump(data);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Color Constant Tests
    // ====================================================================

    #[test]
    fn test_color_constants_are_valid_ansi() {
        let all_colors: &[&str] = &[
            COLOR_OFF,
            COLOR_BLACK,
            COLOR_RED,
            COLOR_GREEN,
            COLOR_YELLOW,
            COLOR_BLUE,
            COLOR_MAGENTA,
            COLOR_CYAN,
            COLOR_WHITE,
            COLOR_WHITE_BG,
            COLOR_HIGHLIGHT,
            COLOR_RED_BOLD,
            COLOR_GREEN_BOLD,
            COLOR_BLUE_BOLD,
            COLOR_MAGENTA_BOLD,
            COLOR_ERROR,
            COLOR_WARN,
            COLOR_INFO,
            COLOR_DEBUG,
        ];
        for color in all_colors {
            assert!(color.starts_with("\x1B["), "Color {} missing ESC[", color);
            assert!(color.ends_with('m'), "Color {} missing 'm'", color);
        }
    }

    #[test]
    fn test_exact_ansi_escape_values() {
        assert_eq!(COLOR_OFF, "\x1B[0m");
        assert_eq!(COLOR_BLACK, "\x1B[0;30m");
        assert_eq!(COLOR_RED, "\x1B[0;31m");
        assert_eq!(COLOR_GREEN, "\x1B[0;32m");
        assert_eq!(COLOR_YELLOW, "\x1B[0;33m");
        assert_eq!(COLOR_BLUE, "\x1B[0;34m");
        assert_eq!(COLOR_MAGENTA, "\x1B[0;35m");
        assert_eq!(COLOR_CYAN, "\x1B[0;36m");
        assert_eq!(COLOR_WHITE, "\x1B[0;37m");
        assert_eq!(COLOR_WHITE_BG, "\x1B[0;47;30m");
        assert_eq!(COLOR_HIGHLIGHT, "\x1B[1;39m");
        assert_eq!(COLOR_RED_BOLD, "\x1B[1;31m");
        assert_eq!(COLOR_GREEN_BOLD, "\x1B[1;32m");
        assert_eq!(COLOR_BLUE_BOLD, "\x1B[1;34m");
        assert_eq!(COLOR_MAGENTA_BOLD, "\x1B[1;35m");
        assert_eq!(COLOR_ERROR, "\x1B[1;31m");
        assert_eq!(COLOR_WARN, "\x1B[1m");
        assert_eq!(COLOR_INFO, "\x1B[0m");
        assert_eq!(COLOR_DEBUG, "\x1B[0;37m");
    }

    #[test]
    fn test_color_severity_aliases() {
        assert_eq!(COLOR_ERROR, COLOR_RED_BOLD);
        assert_eq!(COLOR_INFO, COLOR_OFF);
        assert_eq!(COLOR_DEBUG, COLOR_WHITE);
    }

    #[test]
    fn test_hci_color_aliases() {
        assert_eq!(COLOR_HCI_COMMAND, COLOR_BLUE);
        assert_eq!(COLOR_HCI_COMMAND_UNKNOWN, COLOR_WHITE_BG);
        assert_eq!(COLOR_HCI_DATA, COLOR_CYAN);
        assert_eq!(COLOR_HCI_EVENT, COLOR_MAGENTA);
        assert_eq!(COLOR_HCI_EVENT_UNKNOWN, COLOR_WHITE_BG);
        assert_eq!(COLOR_HCI_ACLDATA, COLOR_CYAN);
        assert_eq!(COLOR_HCI_SCODATA, COLOR_YELLOW);
        assert_eq!(COLOR_HCI_ISODATA, COLOR_YELLOW);
        assert_eq!(COLOR_PHY_PACKET, COLOR_BLUE);
        assert_eq!(COLOR_MGMT_EVENT, COLOR_MAGENTA_BOLD);
        assert_eq!(COLOR_SYSTEM_NOTE, COLOR_OFF);
        assert_eq!(COLOR_VENDOR_DIAG, COLOR_YELLOW);
        assert_eq!(COLOR_UPDATE, COLOR_YELLOW);
    }

    #[test]
    fn test_hci_color_constants_valid_ansi() {
        let hci_colors: &[&str] = &[
            COLOR_HCI_COMMAND,
            COLOR_HCI_COMMAND_UNKNOWN,
            COLOR_HCI_DATA,
            COLOR_HCI_EVENT,
            COLOR_HCI_EVENT_UNKNOWN,
            COLOR_HCI_ACLDATA,
            COLOR_HCI_SCODATA,
            COLOR_HCI_ISODATA,
            COLOR_PHY_PACKET,
            COLOR_MGMT_EVENT,
            COLOR_SYSTEM_NOTE,
            COLOR_VENDOR_DIAG,
            COLOR_UPDATE,
        ];
        for color in hci_colors {
            assert!(color.starts_with("\x1B["));
            assert!(color.ends_with('m'));
        }
    }

    // ====================================================================
    // Enum and Struct Tests
    // ====================================================================

    #[test]
    fn test_monitor_color_enum_variants() {
        let auto = MonitorColor::Auto;
        let always = MonitorColor::Always;
        let never = MonitorColor::Never;
        assert_ne!(auto, always);
        assert_ne!(auto, never);
        assert_ne!(always, never);
        // Copy semantics
        let auto2 = auto;
        assert_eq!(auto, auto2);
    }

    #[test]
    fn test_bitfield_data_struct_construction() {
        let entry = BitfieldData { bit: 3, str_val: "Test Bit" };
        assert_eq!(entry.bit, 3);
        assert_eq!(entry.str_val, "Test Bit");
    }

    // ====================================================================
    // Fallback Width
    // ====================================================================

    #[test]
    fn test_fallback_terminal_width() {
        assert_eq!(FALLBACK_TERMINAL_WIDTH, 80);
    }

    // ====================================================================
    // Color Policy
    // ====================================================================

    #[test]
    fn test_color_always() {
        set_monitor_color(MonitorColor::Always);
        assert!(use_color());
        set_monitor_color(MonitorColor::Auto);
    }

    #[test]
    fn test_color_never() {
        set_monitor_color(MonitorColor::Never);
        assert!(!use_color());
        set_monitor_color(MonitorColor::Auto);
    }

    // ====================================================================
    // Terminal Width
    // ====================================================================

    #[test]
    fn test_num_columns_returns_positive() {
        let cols = num_columns();
        assert!(cols > 0, "Expected positive columns, got {}", cols);
    }

    #[test]
    fn test_set_default_pager_num_columns_no_panic() {
        set_default_pager_num_columns(120);
        set_default_pager_num_columns(FALLBACK_TERMINAL_WIDTH);
    }

    // ====================================================================
    // Bitfield Printing
    // ====================================================================

    #[test]
    fn test_print_bitfield_empty_table() {
        let mask = print_bitfield(8, 0xFF, &[]);
        assert_eq!(mask, 0xFF, "Empty table should leave mask unchanged");
    }

    #[test]
    fn test_print_bitfield_no_bits_set() {
        let table =
            [BitfieldData { bit: 0, str_val: "Bit 0" }, BitfieldData { bit: 1, str_val: "Bit 1" }];
        let mask = print_bitfield(8, 0, &table);
        assert_eq!(mask, 0);
    }

    #[test]
    fn test_print_bitfield_all_matched() {
        let table = [BitfieldData { bit: 0, str_val: "A" }, BitfieldData { bit: 2, str_val: "C" }];
        // val = 0b0101 = 5
        let mask = print_bitfield(8, 5, &table);
        assert_eq!(mask, 0, "All set bits matched");
    }

    #[test]
    fn test_print_bitfield_partial_match() {
        let table = [BitfieldData { bit: 0, str_val: "A" }];
        // val = 0b1001 = 9 → bit 0 matched, bit 3 unmatched
        let mask = print_bitfield(8, 9, &table);
        assert_eq!(mask, 8, "Bit 3 should remain (8 = 1<<3)");
    }

    #[test]
    fn test_print_bitfield_high_bits() {
        let table = [BitfieldData { bit: 63, str_val: "Highest" }];
        let mask = print_bitfield(8, 1u64 << 63, &table);
        assert_eq!(mask, 0, "Bit 63 should be matched and cleared");
    }

    // ====================================================================
    // Hexdump
    // ====================================================================

    #[test]
    fn test_hexdump_empty() {
        print_hexdump(&[]);
    }

    #[test]
    fn test_hexdump_single_byte() {
        print_hexdump(&[0x42]);
    }

    #[test]
    fn test_hexdump_exactly_16() {
        print_hexdump(&[0x00; 16]);
    }

    #[test]
    fn test_hexdump_17_bytes() {
        print_hexdump(&[0xFF; 17]);
    }

    #[test]
    fn test_hexdump_32_bytes() {
        print_hexdump(&[0x41; 32]);
    }

    #[test]
    fn test_hexdump_33_bytes() {
        print_hexdump(&[0x30; 33]);
    }

    #[test]
    fn test_hex_field_with_data() {
        print_hex_field("Payload", &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_hex_field_empty() {
        print_hex_field("Empty", &[]);
    }

    // ====================================================================
    // Pager (safe no-op tests)
    // ====================================================================

    #[test]
    fn test_close_pager_when_not_active() {
        close_pager();
    }

    // ====================================================================
    // Macro Compilation Tests (via invocation)
    // ====================================================================

    #[test]
    fn test_print_field_macro_compiles() {
        set_monitor_color(MonitorColor::Never);
        print_field!("Test: {}", 42);
        set_monitor_color(MonitorColor::Auto);
    }

    #[test]
    fn test_print_text_macro_compiles() {
        set_monitor_color(MonitorColor::Never);
        print_text!(COLOR_WHITE, "Hello {}", "world");
        set_monitor_color(MonitorColor::Auto);
    }

    #[test]
    fn test_print_indent_macro_compiles() {
        set_monitor_color(MonitorColor::Never);
        print_indent!(12, COLOR_BLUE, "> ", "Title", COLOR_OFF, "value: {}", 99);
        set_monitor_color(MonitorColor::Auto);
    }
}
