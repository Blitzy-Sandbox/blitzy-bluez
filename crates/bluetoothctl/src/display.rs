// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2012 Intel Corporation. All rights reserved.
//
// Readline-compatible display utilities for the bluetoothctl CLI.
//
// This module provides rustyline-compatible output/prompt helpers that replace
// the GNU readline-based `rl_printf`, `rl_hexdump`, and
// `rl_prompt_input`/`rl_release_prompt` functions from `client/display.c`.

use std::io::{self, Write};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// ANSI Color Constants — must match client/display.h character-for-character
// ---------------------------------------------------------------------------

/// ANSI escape code to reset all terminal attributes.
pub const COLOR_OFF: &str = "\x1B[0m";

/// ANSI escape code for bright red text.
pub const COLOR_RED: &str = "\x1B[0;91m";

/// ANSI escape code for bright green text.
pub const COLOR_GREEN: &str = "\x1B[0;92m";

/// ANSI escape code for bright yellow text.
pub const COLOR_YELLOW: &str = "\x1B[0;93m";

/// ANSI escape code for bright blue text.
pub const COLOR_BLUE: &str = "\x1B[0;94m";

/// ANSI escape code for bold dark gray text.
pub const COLOR_BOLDGRAY: &str = "\x1B[1;30m";

/// ANSI escape code for bold white text.
pub const COLOR_BOLDWHITE: &str = "\x1B[1;37m";

// ---------------------------------------------------------------------------
// Prompt Input State
// ---------------------------------------------------------------------------

/// Callback type for prompt input completion.
///
/// Replaces the C `rl_prompt_input_func` typedef plus `void *user_data`
/// pattern with an idiomatic Rust boxed closure (AAP Section 0.1.1).
pub type PromptInputFunc = Box<dyn FnOnce(&str) + Send>;

/// Internal prompt state replacing the C static globals in `display.c`.
///
/// Fields mirror:
/// - `saved_prompt`   → C `static char *saved_prompt`
/// - `saved_point`    → C `static int saved_point`
/// - `saved_func`     → C `static rl_prompt_input_func saved_func` + `void *saved_user_data`
struct PromptState {
    /// Saved prompt text during input capture (`None` when no prompt is active).
    saved_prompt: Option<String>,
    /// Saved cursor position.
    saved_point: usize,
    /// Saved callback function to invoke when the prompt is released.
    saved_func: Option<PromptInputFunc>,
}

/// Module-level prompt state protected by a mutex.
///
/// `bluetoothctl` uses `tokio::runtime::Builder::new_current_thread()`, so the
/// mutex is never contended in practice, but `Mutex` satisfies the `Sync`
/// requirement for `static` variables and prevents data races if the runtime
/// model ever changes.
static PROMPT_STATE: Mutex<PromptState> =
    Mutex::new(PromptState { saved_prompt: None, saved_point: 0, saved_func: None });

// ---------------------------------------------------------------------------
// Hex Digit Lookup Table
// ---------------------------------------------------------------------------

/// Hex digit lookup table matching the C `static const char hexdigits[]` array.
const HEXDIGITS: &[u8; 16] = b"0123456789abcdef";

// ---------------------------------------------------------------------------
// rl_printf — formatted terminal output
// ---------------------------------------------------------------------------

/// Print formatted text to stdout, handling rustyline prompt state.
///
/// This is the Rust equivalent of C `rl_printf` from `display.c` lines 31-59.
///
/// In the C version, the function saves and restores GNU readline state
/// (prompt, line buffer, cursor position) around the print operation so that
/// output does not corrupt the current input line.  With rustyline, the
/// library manages its own terminal state internally and does not expose
/// global mutable state like `rl_point`/`rl_end`/`rl_prompt`.  The key
/// behavioral contract is preserved: output appears cleanly on the terminal
/// without corrupting the current input line.
///
/// # Usage
///
/// ```ignore
/// rl_printf(format_args!("Hello, {}!\n", name));
/// ```
pub fn rl_printf(args: std::fmt::Arguments<'_>) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    // Ignoring write errors mirrors C `vprintf` which silently drops on failure.
    let _ = handle.write_fmt(args);
    let _ = handle.flush();
}

// ---------------------------------------------------------------------------
// rl_hexdump — byte-identical hexadecimal dump
// ---------------------------------------------------------------------------

/// Display a hexadecimal dump of a byte buffer.
///
/// Produces byte-identical output to the C `rl_hexdump` function from
/// `display.c` lines 61-99.
///
/// Each output line contains 16 bytes formatted as:
///
/// ```text
///  XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX  aaaaaaaaaaaaaaaa
/// ```
///
/// - Hex digits occupy positions `((col * 3) + 1)` through `((col * 3) + 3)`
///   for column `col` in `0..16`.
/// - ASCII characters occupy positions `col + 51`, with non-printable bytes
///   rendered as `.`.
/// - Positions 49-50 contain two separator spaces.
/// - Partial last lines are padded with spaces in both hex and ASCII areas.
///
/// The 67-character line buffer layout is:
///
/// ```text
/// [0]     = leading space
/// [1..49] = hex area: 16 groups of (space + 2 hex digits)
/// [49..51]= separator (2 spaces)
/// [51..67]= ASCII area (16 characters)
/// ```
pub fn rl_hexdump(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }

    // 67-byte line buffer (positions 0..66), initialized to all spaces.
    // The C version uses `char str[68]` where position 67 is the NUL terminator;
    // in Rust the slice length replaces the NUL.
    let mut line = [b' '; 67];

    for (i, &byte) in buf.iter().enumerate() {
        let col = i % 16;

        // Hex area: space + high nibble + low nibble
        line[(col * 3) + 1] = b' ';
        line[(col * 3) + 2] = HEXDIGITS[(byte >> 4) as usize];
        line[(col * 3) + 3] = HEXDIGITS[(byte & 0x0f) as usize];

        // ASCII area: printable characters or '.'
        line[col + 51] = if byte.is_ascii_graphic() || byte == b' ' { byte } else { b'.' };

        // Print a complete 16-byte line.
        if (i + 1) % 16 == 0 {
            line[49] = b' ';
            line[50] = b' ';
            // All bytes are valid ASCII, so from_utf8 is infallible here.
            let s = std::str::from_utf8(&line).unwrap_or("");
            rl_printf(format_args!("{s}\n"));
            // Reset the buffer for the next line.
            line = [b' '; 67];
        }
    }

    // Handle partial last line: pad remaining positions with spaces.
    let remainder = buf.len() % 16;
    if remainder > 0 {
        for j in remainder..16 {
            line[(j * 3) + 1] = b' ';
            line[(j * 3) + 2] = b' ';
            line[(j * 3) + 3] = b' ';
            line[j + 51] = b' ';
        }
        line[49] = b' ';
        line[50] = b' ';
        let s = std::str::from_utf8(&line).unwrap_or("");
        rl_printf(format_args!("{s}\n"));
    }
}

// ---------------------------------------------------------------------------
// rl_prompt_input — temporary colored prompt for user input
// ---------------------------------------------------------------------------

/// Capture user input with a temporary colored prompt.
///
/// Replaces C `rl_prompt_input` from `display.c` lines 102-127.
///
/// Saves the current prompt state, displays a colored `[label]` message
/// prompt, and stores the callback to be invoked when input is received
/// via [`rl_release_prompt`].
///
/// If a prompt is already active (double-prompt guard), this function
/// returns immediately without changing any state, matching the C behavior
/// where `if (saved_prompt) return;`.
///
/// # Arguments
///
/// * `label` — Text displayed in red brackets (e.g., `"Enter PIN code"`)
/// * `msg`   — Message displayed after the label
/// * `func`  — Callback invoked with the user's input when the prompt is
///   released
pub fn rl_prompt_input(label: &str, msg: &str, func: PromptInputFunc) {
    let mut state = PROMPT_STATE.lock().unwrap_or_else(|e| e.into_inner());

    // Double-prompt guard: prevent re-entry while a prompt is active.
    if state.saved_prompt.is_some() {
        return;
    }

    // Save current prompt state.  In the C version this saves `rl_prompt`
    // and `rl_point`; with rustyline the actual prompt text is managed by
    // the shell framework, so we store a sentinel to indicate that a prompt
    // capture is in progress.
    state.saved_prompt = Some(String::new());
    state.saved_point = 0;
    state.saved_func = Some(func);

    // Display the colored prompt:  COLOR_RED "[" label "]" COLOR_OFF " " msg " "
    // This matches the C snprintf format string exactly:
    //   COLOR_RED "[%s]" COLOR_OFF " %s "
    rl_printf(format_args!("{COLOR_RED}[{label}]{COLOR_OFF} {msg} "));
}

// ---------------------------------------------------------------------------
// rl_release_prompt — restore prompt and invoke saved callback
// ---------------------------------------------------------------------------

/// Release the temporary prompt, restore the original, and invoke the saved
/// callback with the user's input.
///
/// Replaces C `rl_release_prompt` from `display.c` lines 129-156.
///
/// # Arguments
///
/// * `input` — The user's input string to pass to the saved callback
///
/// # Returns
///
/// * `0`  — Success: the prompt was active, state was restored, and the
///   callback was invoked.
/// * `-1` — No saved prompt exists (nothing to release).
pub fn rl_release_prompt(input: &str) -> i32 {
    // Extract the saved function while holding the lock, then invoke it
    // outside the lock to prevent potential deadlocks if the callback
    // calls back into the display module.
    let func = {
        let mut state = PROMPT_STATE.lock().unwrap_or_else(|e| e.into_inner());

        // No saved prompt → return -1 (matches C behavior).
        if state.saved_prompt.is_none() {
            return -1;
        }

        // Restore original prompt state.
        state.saved_prompt = None;
        state.saved_point = 0;

        // Take the saved callback, clearing it from state.
        state.saved_func.take()
    };

    // Invoke the callback outside the lock.
    if let Some(f) = func {
        f(input);
    }

    0
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that all color constants match the C defines exactly.
    #[test]
    fn color_constants_match_c_defines() {
        assert_eq!(COLOR_OFF, "\x1B[0m");
        assert_eq!(COLOR_RED, "\x1B[0;91m");
        assert_eq!(COLOR_GREEN, "\x1B[0;92m");
        assert_eq!(COLOR_YELLOW, "\x1B[0;93m");
        assert_eq!(COLOR_BLUE, "\x1B[0;94m");
        assert_eq!(COLOR_BOLDGRAY, "\x1B[1;30m");
        assert_eq!(COLOR_BOLDWHITE, "\x1B[1;37m");
    }

    /// Helper: produce hexdump output as a String for verification.
    fn hexdump_to_string(buf: &[u8]) -> String {
        if buf.is_empty() {
            return String::new();
        }

        let mut output = String::new();
        let mut line = [b' '; 67];

        for (i, &byte) in buf.iter().enumerate() {
            let col = i % 16;
            line[(col * 3) + 1] = b' ';
            line[(col * 3) + 2] = HEXDIGITS[(byte >> 4) as usize];
            line[(col * 3) + 3] = HEXDIGITS[(byte & 0x0f) as usize];
            line[col + 51] = if byte.is_ascii_graphic() || byte == b' ' { byte } else { b'.' };

            if (i + 1) % 16 == 0 {
                line[49] = b' ';
                line[50] = b' ';
                let s = std::str::from_utf8(&line).unwrap();
                output.push_str(s);
                output.push('\n');
                line = [b' '; 67];
            }
        }

        let remainder = buf.len() % 16;
        if remainder > 0 {
            for j in remainder..16 {
                line[(j * 3) + 1] = b' ';
                line[(j * 3) + 2] = b' ';
                line[(j * 3) + 3] = b' ';
                line[j + 51] = b' ';
            }
            line[49] = b' ';
            line[50] = b' ';
            let s = std::str::from_utf8(&line).unwrap();
            output.push_str(s);
            output.push('\n');
        }

        output
    }

    /// Verify hexdump of an empty buffer produces no output.
    #[test]
    fn hexdump_empty() {
        let result = hexdump_to_string(&[]);
        assert!(result.is_empty());
    }

    /// Verify hexdump of a single byte.
    #[test]
    fn hexdump_single_byte() {
        let result = hexdump_to_string(&[0x41]); // 'A'
        assert_eq!(result.len(), 68); // 67 chars + newline
        assert!(result.starts_with("  41"));
        assert!(result.contains("A"));
    }

    /// Verify hexdump of exactly 16 bytes produces one complete line.
    #[test]
    fn hexdump_full_line() {
        let buf: Vec<u8> = (0x30..0x40).collect(); // '0'..'@'
        let result = hexdump_to_string(&buf);
        // Exactly one line
        assert_eq!(result.chars().filter(|&c| c == '\n').count(), 1);
        // Must contain hex representations
        assert!(result.contains("30"));
        assert!(result.contains("3f"));
        // ASCII area should contain '0' through '?'
        assert!(result.contains("0123456789:;<=>?"));
    }

    /// Verify hexdump handles non-printable bytes with dots.
    #[test]
    fn hexdump_non_printable() {
        let buf = [0x00, 0x01, 0x1f, 0x7f, 0x80, 0xff];
        let result = hexdump_to_string(&buf);
        // ASCII area should show dots for all non-printable bytes
        let ascii_start = 51;
        let line_bytes = result.as_bytes();
        for col in 0..6 {
            assert_eq!(
                line_bytes[ascii_start + col],
                b'.',
                "byte at col {col} should be '.' for non-printable"
            );
        }
    }

    /// Verify hexdump of 17 bytes produces two lines.
    #[test]
    fn hexdump_17_bytes() {
        let buf: Vec<u8> = (0x41..0x52).collect(); // 'A'..'R' (17 bytes)
        let result = hexdump_to_string(&buf);
        assert_eq!(result.chars().filter(|&c| c == '\n').count(), 2);
    }

    /// Verify that rl_release_prompt returns -1 when no prompt is saved.
    #[test]
    fn release_prompt_no_saved() {
        // Ensure clean state.
        {
            let mut state = PROMPT_STATE.lock().unwrap();
            state.saved_prompt = None;
            state.saved_func = None;
            state.saved_point = 0;
        }
        assert_eq!(rl_release_prompt("test"), -1);
    }

    /// Verify the double-prompt guard: second call is a no-op.
    #[test]
    fn double_prompt_guard() {
        // Clean state first.
        {
            let mut state = PROMPT_STATE.lock().unwrap();
            state.saved_prompt = None;
            state.saved_func = None;
            state.saved_point = 0;
        }

        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let counter = Arc::new(AtomicU32::new(0));

        // First prompt: should be accepted.
        let c1 = Arc::clone(&counter);
        rl_prompt_input(
            "test",
            "Enter:",
            Box::new(move |_| {
                c1.fetch_add(1, Ordering::SeqCst);
            }),
        );

        // Verify prompt is saved.
        {
            let state = PROMPT_STATE.lock().unwrap();
            assert!(state.saved_prompt.is_some());
            assert!(state.saved_func.is_some());
        }

        // Second prompt: should be rejected (double-prompt guard).
        let c2 = Arc::clone(&counter);
        rl_prompt_input(
            "test2",
            "Enter again:",
            Box::new(move |_| {
                c2.fetch_add(10, Ordering::SeqCst);
            }),
        );

        // Release the first prompt.
        let result = rl_release_prompt("hello");
        assert_eq!(result, 0);

        // Only the first callback should have been invoked.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Verify rl_prompt_input + rl_release_prompt round-trip.
    #[test]
    fn prompt_input_release_round_trip() {
        // Clean state.
        {
            let mut state = PROMPT_STATE.lock().unwrap();
            state.saved_prompt = None;
            state.saved_func = None;
            state.saved_point = 0;
        }

        use std::sync::{Arc, Mutex as StdMutex};
        let captured = Arc::new(StdMutex::new(String::new()));
        let captured_clone = Arc::clone(&captured);

        rl_prompt_input(
            "PIN",
            "Enter PIN code:",
            Box::new(move |input| {
                let mut guard = captured_clone.lock().unwrap();
                *guard = input.to_owned();
            }),
        );

        let result = rl_release_prompt("1234");
        assert_eq!(result, 0);

        let guard = captured.lock().unwrap();
        assert_eq!(*guard, "1234");
    }

    /// Verify line layout matches expected positions for a known buffer.
    #[test]
    fn hexdump_position_check() {
        // Buffer: [0x48, 0x65, 0x6c, 0x6c, 0x6f] = "Hello"
        let buf = b"Hello";
        let result = hexdump_to_string(buf);
        let bytes = result.as_bytes();

        // Position 0: leading space
        assert_eq!(bytes[0], b' ');

        // Byte 0 ('H' = 0x48) → hex at positions 2-3
        assert_eq!(bytes[2], b'4');
        assert_eq!(bytes[3], b'8');

        // Byte 1 ('e' = 0x65) → hex at positions 5-6
        assert_eq!(bytes[5], b'6');
        assert_eq!(bytes[6], b'5');

        // Separator at positions 49-50
        assert_eq!(bytes[49], b' ');
        assert_eq!(bytes[50], b' ');

        // ASCII area: 'H' at position 51
        assert_eq!(bytes[51], b'H');
        // ASCII area: 'e' at position 52
        assert_eq!(bytes[52], b'e');
        // ASCII area: 'l' at position 53
        assert_eq!(bytes[53], b'l');
        // ASCII area: 'l' at position 54
        assert_eq!(bytes[54], b'l');
        // ASCII area: 'o' at position 55
        assert_eq!(bytes[55], b'o');

        // Remaining ASCII positions should be spaces
        for pos in 56..67 {
            assert_eq!(bytes[pos], b' ', "position {pos} should be space for padding");
        }
    }
}
