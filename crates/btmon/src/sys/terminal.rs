// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * sys/terminal.rs — Designated unsafe FFI boundary for terminal I/O and pager
 *                   management operations.
 *
 * This module confines all `unsafe` code related to terminal ioctl, fd
 * duplication, and fd closing to a single FFI boundary site per AAP
 * Section 0.7.4.  All functions exported from this module present safe Rust
 * interfaces to their callers.
 *
 * Unsafe categories present:
 *   - `kernel_ioctl` — TIOCGWINSZ ioctl to query terminal dimensions
 *   - `process_control` — dup2() for stdout redirection, close() for fd teardown
 *
 * Every `unsafe` block has a corresponding `// SAFETY:` invariant comment.
 */

use std::os::unix::io::RawFd;

/// Query the terminal width via TIOCGWINSZ ioctl on stdout.
///
/// Returns `None` if the ioctl fails or reports zero columns.
///
/// # Safety Boundary
///
/// Internally calls `libc::ioctl(STDOUT_FILENO, TIOCGWINSZ, &mut ws)`.
/// The `winsize` struct is fully initialised before the call, and
/// `STDOUT_FILENO` is a well-known file descriptor guaranteed to exist.
pub fn get_terminal_width() -> Option<u16> {
    let ws = bluez_shared::sys::ffi_helpers::bt_get_winsize(libc::STDOUT_FILENO).ok()?;
    if ws.ws_col == 0 { None } else { Some(ws.ws_col) }
}

/// Duplicate `source_fd` onto `STDOUT_FILENO` via `dup2()`, then close the
/// original `source_fd`.
///
/// Returns `true` on success, `false` if `dup2()` fails (in which case
/// `source_fd` is also closed for cleanup).
///
/// # Safety Boundary
///
/// Internally calls `libc::dup2(source_fd, STDOUT_FILENO)` and
/// `libc::close(source_fd)`.  The caller must guarantee `source_fd` is a
/// valid, open file descriptor.
pub fn redirect_stdout(source_fd: RawFd) -> bool {
    use bluez_shared::sys::ffi_helpers;
    if ffi_helpers::bt_dup2(source_fd, libc::STDOUT_FILENO).is_err() {
        let _ = ffi_helpers::bt_close_fd(source_fd);
        return false;
    }
    let _ = ffi_helpers::bt_close_fd(source_fd);
    true
}

/// Close `STDOUT_FILENO`.
///
/// Used to signal EOF to a pager process whose stdin is connected to our
/// stdout via a pipe.
///
/// # Safety Boundary
///
/// Internally calls `libc::close(STDOUT_FILENO)`.  The caller must ensure
/// that stdout has been previously redirected to a pipe (via `redirect_stdout`)
/// so that closing it produces the desired EOF signal.
pub fn close_stdout() {
    let _ = bluez_shared::sys::ffi_helpers::bt_close_fd(libc::STDOUT_FILENO);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `get_terminal_width` returns a valid value or `None` without
    /// panicking — exercises the ioctl unsafe path.
    #[test]
    fn test_get_terminal_width_no_panic() {
        // In CI/test environments stdout is often not a TTY, so None is expected.
        // The key assertion is that the unsafe ioctl path does not panic or segfault.
        let _width = get_terminal_width();
    }
}
