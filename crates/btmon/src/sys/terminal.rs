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
    let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: ioctl with TIOCGWINSZ reads terminal dimensions into a valid,
    // fully-initialised winsize struct.  STDOUT_FILENO is a well-known fd.
    let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if ret < 0 || ws.ws_col == 0 { None } else { Some(ws.ws_col) }
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
    // SAFETY: dup2 is a well-defined POSIX syscall; source_fd is required by
    // the caller's contract to be a valid open fd, and STDOUT_FILENO (1) is a
    // well-known fd number.
    let dup_result = unsafe { libc::dup2(source_fd, libc::STDOUT_FILENO) };
    if dup_result < 0 {
        // dup2 failed — close source_fd to avoid leaking
        // SAFETY: source_fd is a valid open fd per caller contract.
        unsafe {
            libc::close(source_fd);
        }
        return false;
    }

    // Close the original source_fd — stdout now owns the pipe end.
    // SAFETY: source_fd is a valid open fd that has been successfully dup'd.
    unsafe {
        libc::close(source_fd);
    }
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
    // SAFETY: STDOUT_FILENO (1) is a well-known fd that we previously dup2'd
    // to the pager pipe.  Closing it signals EOF to the pager's stdin.
    unsafe {
        libc::close(libc::STDOUT_FILENO);
    }
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
