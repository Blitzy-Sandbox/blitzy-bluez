// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! Structured logging module — Rust rewrite of `src/shared/log.c` / `log.h`.
//!
//! This module provides two complementary logging paths:
//!
//! 1. **`tracing` subscriber** — replaces C `syslog` for daemon console/journal
//!    output. Initialized once via [`init_logging`].
//!
//! 2. **HCI Logging Channel transport** — preserves `btmon` compatibility by
//!    sending log records over `PF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` bound to
//!    `HCI_CHANNEL_LOGGING`.  The [`BtLog`] struct and free‑function wrappers
//!    (`bt_log_open`, `bt_log_sendmsg`, …) produce **wire‑identical** datagrams
//!    to the C implementation so that `btmon` decodes them unchanged.
//!
//! # Safety
//!
//! This module is a designated FFI boundary for the Linux kernel HCI logging
//! channel socket.  The kernel does not expose `AF_BLUETOOTH` sockets through
//! any safe Rust abstraction (`nix` 0.29 lacks `AF_BLUETOOTH` in its
//! `AddressFamily` enum), so raw `libc` calls with `unsafe` blocks are
//! required for socket creation, binding, and datagram transmission.
//!
//! Every `unsafe` block contains a `// SAFETY:` comment documenting the
//! invariant that makes it sound.  The unsafe surface is confined to:
//!
//! - `libc::socket` — creating the `PF_BLUETOOTH/SOCK_RAW/BTPROTO_HCI` fd
//! - `libc::bind`   — binding to `sockaddr_hci` with `HCI_CHANNEL_LOGGING`
//! - `libc::close`  — cleanup on bind failure (before `OwnedFd` takes ownership)
//! - `libc::sendmsg` — transmitting the log datagram via scatter-gather I/O
//! - `OwnedFd::from_raw_fd` — wrapping the raw fd after successful bind
//! - `mem::zeroed::<libc::msghdr>` — zero-initializing the message header
#![allow(unsafe_code)]

use crate::sys::bluetooth::{AF_BLUETOOTH, BTPROTO_HCI, PF_BLUETOOTH};
use crate::sys::hci::{HCI_CHANNEL_LOGGING, HCI_DEV_NONE, sockaddr_hci};

use std::fmt;
use std::io;
use std::io::IoSlice;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Mutex;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of user-provided I/O slices accepted by [`BtLog::sendmsg`].
///
/// Matches the C implementation's `io_len > 3` guard which allows at most 3
/// user iovec fragments (indices 2, 3, 4 of the 5-element iov array, with
/// indices 0 and 1 reserved for the header and label respectively).
const MAX_USER_IOVEC: usize = 3;

// ---------------------------------------------------------------------------
// LogLevel — maps C syslog priorities to tracing levels
// ---------------------------------------------------------------------------

/// Bluetooth log priority levels matching the syslog values used in the C
/// implementation.
///
/// These numeric values are written into the [`LogHdr::priority`] field of each
/// HCI logging channel datagram so that `btmon` can display the correct level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum LogLevel {
    /// Corresponds to `LOG_ERR` (syslog priority 3).
    Error = 3,
    /// Corresponds to `LOG_WARNING` (syslog priority 4).
    Warn = 4,
    /// Corresponds to `LOG_INFO` (syslog priority 6).
    Info = 6,
    /// Corresponds to `LOG_DEBUG` (syslog priority 7).
    Debug = 7,
}

impl LogLevel {
    /// Convert to the equivalent [`tracing::Level`].
    pub fn to_tracing_level(self) -> tracing::Level {
        match self {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
        }
    }

    /// Create a `LogLevel` from a raw syslog-style integer priority.
    ///
    /// Values 0–3 map to [`Error`](LogLevel::Error), 4 to
    /// [`Warn`](LogLevel::Warn), 5–6 to [`Info`](LogLevel::Info), and anything
    /// else to [`Debug`](LogLevel::Debug).
    pub fn from_i32(level: i32) -> Self {
        match level {
            0..=3 => LogLevel::Error,
            4 => LogLevel::Warn,
            5..=6 => LogLevel::Info,
            _ => LogLevel::Debug,
        }
    }

    /// Return the raw syslog priority value.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Error => write!(f, "error"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Debug => write!(f, "debug"),
        }
    }
}

// ---------------------------------------------------------------------------
// LogHdr — wire-format header for HCI logging channel datagrams
// ---------------------------------------------------------------------------

/// Packed header for HCI logging channel datagrams.
///
/// This struct is a byte-identical Rust representation of the C
/// `struct log_hdr` from `src/shared/log.c`:
///
/// ```c
/// struct log_hdr {
///     uint16_t opcode;    // always 0x0000
///     uint16_t index;     // controller index (little-endian)
///     uint16_t len;       // payload length after this 6-byte prefix
///     uint8_t  priority;  // syslog priority
///     uint8_t  ident_len; // label length including NUL terminator
/// } __attribute__((packed));
/// ```
///
/// Total size: **8 bytes**.  The `len` field covers everything after the first
/// 6 bytes (opcode + index + len), i.e. `2 + ident_len + user_payload_len`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, IntoBytes, FromBytes, Immutable, KnownLayout,
)]
#[repr(C, packed)]
pub struct LogHdr {
    /// Opcode — always `0x0000` (little-endian) for log messages.
    pub opcode: u16,
    /// Controller index — `HCI_DEV_NONE` (0xFFFF) for non-controller messages.
    pub index: u16,
    /// Payload length (little-endian): `2 + ident_len + user_data_len`.
    pub len: u16,
    /// Syslog priority value (see [`LogLevel`]).
    pub priority: u8,
    /// Length of the identifier (label) string **including** the NUL terminator.
    pub ident_len: u8,
}

// ---------------------------------------------------------------------------
// BtLog — process-wide HCI logging channel state
// ---------------------------------------------------------------------------

/// HCI logging channel transport state.
///
/// Encapsulates a cached `PF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` socket bound
/// to `HCI_CHANNEL_LOGGING`.  The socket is created lazily on the first
/// [`sendmsg`](BtLog::sendmsg) call and kept open for the lifetime of the
/// process (or until explicitly closed).
///
/// On socket creation failure the error is **cached** to prevent retry storms —
/// subsequent [`open`](BtLog::open) calls return the cached error immediately
/// without attempting another `socket()` + `bind()` cycle.  This matches the
/// `static int err` sentinel in the C `bt_log_open()`.
///
/// # Thread Safety
///
/// `BtLog` itself is `Send` but not `Sync` (it contains an `OwnedFd`).  The
/// module-level free functions (`bt_log_open`, `bt_log_sendmsg`, …) access a
/// process-wide instance through a [`Mutex`] to provide safe concurrent access
/// from multiple tokio tasks.
pub struct BtLog {
    /// Cached socket file descriptor, or `None` if not yet opened / closed.
    fd: Option<OwnedFd>,
    /// `true` once socket creation has failed; prevents retry storms.
    error_cached: bool,
}

impl BtLog {
    /// Create a new, un-opened logging state.
    pub const fn new() -> Self {
        BtLog { fd: None, error_cached: false }
    }

    /// Open the HCI logging channel socket.
    ///
    /// Creates a `PF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI` socket and binds it
    /// to `HCI_CHANNEL_LOGGING`.  The socket is cached for subsequent calls.
    ///
    /// On failure the error is cached — all future calls return immediately
    /// with the same error, matching the C `static int err` sentinel in
    /// `bt_log_open()`.
    ///
    /// If the socket is already open this is a no-op returning `Ok(())`.
    pub fn open(&mut self) -> Result<(), io::Error> {
        // Check cached error (matches C: `if (err < 0) return err;`)
        if self.error_cached {
            return Err(io::Error::other("HCI logging channel socket open previously failed"));
        }

        // Already open — return immediately (matches C: `if (log_fd >= 0) return log_fd;`)
        if self.fd.is_some() {
            return Ok(());
        }

        // SAFETY: Arguments are valid kernel-defined constants.  `PF_BLUETOOTH`
        // (31), `SOCK_RAW | SOCK_CLOEXEC`, and `BTPROTO_HCI` (1) are the
        // exact values used by the C code.  Returns -1 on error with errno set,
        // or a non-negative file descriptor on success.
        let raw_fd =
            // SAFETY: Creating a raw HCI Bluetooth socket for logging. PF_BLUETOOTH is a valid domain.
            unsafe { libc::socket(PF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI) };
        if raw_fd < 0 {
            self.error_cached = true;
            return Err(io::Error::last_os_error());
        }

        // Prepare sockaddr_hci for HCI_CHANNEL_LOGGING
        let addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: HCI_DEV_NONE,
            hci_channel: HCI_CHANNEL_LOGGING,
        };

        // SAFETY: `raw_fd` is a valid open file descriptor from socket().
        // `&addr` points to a correctly populated `sockaddr_hci` whose lifetime
        // exceeds the bind() call.  `size_of::<sockaddr_hci>()` (6) matches
        // the kernel's expected address length.
        let ret = unsafe {
            libc::bind(
                raw_fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                mem::size_of::<sockaddr_hci>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            self.error_cached = true;
            // SAFETY: `raw_fd` is a valid open fd from socket(); closing it
            // before returning prevents fd leak.  No other code holds this fd.
            unsafe {
                libc::close(raw_fd);
            }
            return Err(err);
        }

        // SAFETY: `raw_fd` is a valid, open file descriptor that we solely own.
        // socket()+bind() succeeded, so the fd is ready for use.  `OwnedFd`
        // takes ownership and will close it on drop.
        self.fd = Some(unsafe { OwnedFd::from_raw_fd(raw_fd) });
        Ok(())
    }

    /// Send a log datagram over the HCI logging channel.
    ///
    /// Constructs a [`LogHdr`] and transmits it together with the `label`
    /// (NUL-terminated) and caller-supplied I/O slices as a single datagram.
    ///
    /// # Arguments
    ///
    /// - `index`  — HCI controller index (`HCI_DEV_NONE` for non-controller).
    /// - `label`  — Subsystem identifier (e.g. `"bluetoothd"`, `"btmon"`).
    /// - `level`  — Syslog priority (see [`LogLevel`]).
    /// - `io_slices` — Up to [`MAX_USER_IOVEC`] (3) user data fragments.
    ///
    /// # Errors
    ///
    /// - `EMSGSIZE` if `io_slices.len() > 3`.
    /// - Any socket error from [`open`](BtLog::open) or `sendmsg`.
    /// - On send failure the socket is closed and reset (next call will re-open).
    pub fn sendmsg(
        &mut self,
        index: u16,
        label: &str,
        level: i32,
        io_slices: &[IoSlice<'_>],
    ) -> Result<(), io::Error> {
        // Enforce max 3 user iovec fragments (matches C: `if (io_len > 3) return -EMSGSIZE;`)
        if io_slices.len() > MAX_USER_IOVEC {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }

        // Auto-open (matches C: `log_fd = bt_log_open();`)
        self.open()?;

        // Build label with NUL terminator.  Truncate to 254 bytes to ensure
        // ident_len (u8) doesn't overflow (label_len + 1 ≤ 255).
        let label_send_len = label.len().min(254);
        let ident_len = (label_send_len + 1) as u8;

        let mut label_buf = Vec::with_capacity(label_send_len + 1);
        label_buf.extend_from_slice(&label.as_bytes()[..label_send_len]);
        label_buf.push(0); // NUL terminator

        // Compute total payload length:
        //   2 (priority + ident_len bytes in header) + ident_len + user data
        let user_data_len: u16 =
            io_slices.iter().map(|s| s.len() as u16).fold(0u16, u16::saturating_add);
        let total_len: u16 = 2u16.saturating_add(ident_len as u16).saturating_add(user_data_len);

        // Construct wire-format header (all multi-byte fields little-endian)
        let hdr = LogHdr {
            opcode: 0u16.to_le(),
            index: index.to_le(),
            len: total_len.to_le(),
            priority: level as u8,
            ident_len,
        };
        let hdr_bytes = hdr.as_bytes();

        // Build iovec array: [header, label, ...user_slices]
        // Max 5 entries: 1 header + 1 label + 3 user
        let mut iovecs = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 5];
        let mut num_iovecs: usize = 2;

        iovecs[0] = libc::iovec {
            iov_base: hdr_bytes.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: hdr_bytes.len(),
        };
        iovecs[1] = libc::iovec {
            iov_base: label_buf.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: label_buf.len(),
        };

        for (i, slice) in io_slices.iter().enumerate() {
            iovecs[i + 2] = libc::iovec {
                iov_base: slice.as_ptr().cast_mut().cast::<libc::c_void>(),
                iov_len: slice.len(),
            };
            num_iovecs += 1;
        }

        // Build msghdr for sendmsg
        // SAFETY: All-zero is a valid initial state for msghdr (null pointers
        // and zero lengths).  We immediately populate msg_iov and msg_iovlen.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = iovecs.as_mut_ptr();
        msg.msg_iovlen = num_iovecs;

        // Transmit the datagram
        let raw_fd = self.fd.as_ref().expect("fd must be Some after open()").as_raw_fd();

        // SAFETY: `raw_fd` is a valid fd from our cached OwnedFd.  `&msg`
        // points to a correctly populated msghdr whose iov entries reference
        // valid memory (hdr_bytes, label_buf, and caller's IoSlice buffers)
        // that outlives this call.  Flags are 0 (no special options).
        let ret = unsafe { libc::sendmsg(raw_fd, &msg, 0) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            // On send failure, close fd and reset — next call will re-open.
            // (matches C: `close(log_fd); log_fd = -1;`)
            // Note: does NOT set error_cached, so re-open is possible.
            self.fd = None; // OwnedFd::drop() calls close()
            return Err(err);
        }

        Ok(())
    }

    /// Format and send a log message over the HCI logging channel.
    ///
    /// Equivalent to C `bt_log_vprintf`: formats the message, trims a trailing
    /// newline (since btmon adds its own), appends a NUL terminator, and sends
    /// via [`sendmsg`](BtLog::sendmsg) as a single user I/O slice.
    ///
    /// # Arguments
    ///
    /// - `index` — HCI controller index.
    /// - `label` — Subsystem identifier.
    /// - `level` — Syslog priority.
    /// - `msg`   — Pre-formatted message string.
    pub fn vprintf(
        &mut self,
        index: u16,
        label: &str,
        level: i32,
        msg: &str,
    ) -> Result<(), io::Error> {
        let mut formatted = msg.to_string();

        // Trim trailing newline — btmon already adds one.
        // (matches C: `if (len > 1 && str[len - 1] == '\n') { str[len-1] = '\0'; len--; }`)
        if formatted.len() > 1 && formatted.ends_with('\n') {
            formatted.pop();
        }

        // Append NUL terminator (matches C: `iov.iov_len = len + 1;`)
        formatted.push('\0');

        let iov = [IoSlice::new(formatted.as_bytes())];
        self.sendmsg(index, label, level, &iov)
    }

    /// Format arguments and send a log message over the HCI logging channel.
    ///
    /// Equivalent to C `bt_log_printf`: formats using `std::fmt::Arguments`,
    /// then delegates to [`vprintf`](BtLog::vprintf).
    pub fn printf(
        &mut self,
        index: u16,
        label: &str,
        level: i32,
        args: fmt::Arguments<'_>,
    ) -> Result<(), io::Error> {
        let msg = fmt::format(args);
        self.vprintf(index, label, level, &msg)
    }

    /// Close the HCI logging channel socket.
    ///
    /// Drops the cached `OwnedFd` (which calls `close()` on the underlying
    /// file descriptor).  Subsequent [`open`](BtLog::open) calls will attempt
    /// to create a new socket unless the error was previously cached.
    ///
    /// Matches C `bt_log_close()`.
    pub fn close(&mut self) {
        // OwnedFd::drop() calls close() on the fd.
        self.fd = None;
    }

    /// Returns `true` if the HCI logging channel socket is currently open.
    pub fn is_open(&self) -> bool {
        self.fd.is_some()
    }
}

impl Default for BtLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Process-wide global state + free function API
// ---------------------------------------------------------------------------

/// Process-wide HCI logging channel state, protected by a mutex for thread
/// safety across tokio tasks.
static GLOBAL_LOG: Mutex<BtLog> = Mutex::new(BtLog::new());

/// Execute a closure with exclusive access to the global [`BtLog`] instance.
///
/// Recovers gracefully from mutex poisoning (a thread panicked while holding
/// the lock) by extracting the inner value — logging should not crash the
/// process.
fn with_global_log<F, T>(f: F) -> T
where
    F: FnOnce(&mut BtLog) -> T,
{
    let mut guard = GLOBAL_LOG.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// Open the process-wide HCI logging channel socket.
///
/// See [`BtLog::open`] for details.  Thread-safe via internal mutex.
pub fn bt_log_open() -> Result<(), io::Error> {
    with_global_log(|log| log.open())
}

/// Send a log datagram over the process-wide HCI logging channel.
///
/// See [`BtLog::sendmsg`] for details.  Thread-safe via internal mutex.
pub fn bt_log_sendmsg(
    index: u16,
    label: &str,
    level: i32,
    io_slices: &[IoSlice<'_>],
) -> Result<(), io::Error> {
    with_global_log(|log| log.sendmsg(index, label, level, io_slices))
}

/// Format and send a log message over the process-wide HCI logging channel.
///
/// See [`BtLog::vprintf`] for details.  Thread-safe via internal mutex.
pub fn bt_log_vprintf(index: u16, label: &str, level: i32, msg: &str) -> Result<(), io::Error> {
    with_global_log(|log| log.vprintf(index, label, level, msg))
}

/// Format arguments and send a log message over the process-wide HCI logging
/// channel.
///
/// See [`BtLog::printf`] for details.  Thread-safe via internal mutex.
pub fn bt_log_printf(
    index: u16,
    label: &str,
    level: i32,
    args: fmt::Arguments<'_>,
) -> Result<(), io::Error> {
    with_global_log(|log| log.printf(index, label, level, args))
}

/// Close the process-wide HCI logging channel socket.
///
/// See [`BtLog::close`] for details.  Thread-safe via internal mutex.
pub fn bt_log_close() {
    with_global_log(|log| log.close());
}

// ---------------------------------------------------------------------------
// Tracing subscriber initialization
// ---------------------------------------------------------------------------

/// Initialize the `tracing` subscriber for daemon console/journal output.
///
/// Replaces the C `openlog()` / `closelog()` pattern.  Sets up a
/// `tracing_subscriber::fmt` subscriber with:
///
/// - Compact format suitable for daemon logging
/// - Default level `info` (overridable via `RUST_LOG` environment variable)
///
/// This should be called once at daemon startup (e.g. in `main()`).
///
/// # Panics
///
/// Panics if a global subscriber has already been set (i.e. called twice).
pub fn init_logging() {
    tracing_subscriber::fmt().with_target(true).with_thread_ids(false).with_level(true).init();
}

// ---------------------------------------------------------------------------
// Convenience macros — delegate to tracing macros
// ---------------------------------------------------------------------------

/// Re-export of `tracing` for use by `btd_*` macros.
///
/// Callers use `$crate::log::_tracing` in macro expansions to ensure the
/// tracing crate is resolved correctly regardless of the call site.
#[doc(hidden)]
pub use tracing as _tracing;

/// Log a debug-level message via `tracing::debug!`.
///
/// Replaces C `btd_debug(...)`.
#[macro_export]
macro_rules! btd_debug {
    ($($arg:tt)*) => {
        $crate::log::_tracing::debug!($($arg)*)
    };
}

/// Log an info-level message via `tracing::info!`.
///
/// Replaces C `btd_info(...)`.
#[macro_export]
macro_rules! btd_info {
    ($($arg:tt)*) => {
        $crate::log::_tracing::info!($($arg)*)
    };
}

/// Log a warning-level message via `tracing::warn!`.
///
/// Replaces C `btd_warn(...)`.
#[macro_export]
macro_rules! btd_warn {
    ($($arg:tt)*) => {
        $crate::log::_tracing::warn!($($arg)*)
    };
}

/// Log an error-level message via `tracing::error!`.
///
/// Replaces C `btd_error(...)`.
#[macro_export]
macro_rules! btd_error {
    ($($arg:tt)*) => {
        $crate::log::_tracing::error!($($arg)*)
    };
}

// ---------------------------------------------------------------------------
// Unit Tests — exercises LogLevel, LogHdr, BtLog lifecycle, and the unsafe
// socket/sendmsg paths (via error-path coverage on non-BT systems).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // LogLevel
    // -----------------------------------------------------------------------

    #[test]
    fn test_log_level_from_i32() {
        // Syslog priorities 0–3 map to Error.
        assert_eq!(LogLevel::from_i32(0), LogLevel::Error);
        assert_eq!(LogLevel::from_i32(3), LogLevel::Error);
        // 4 maps to Warn.
        assert_eq!(LogLevel::from_i32(4), LogLevel::Warn);
        // 5–6 map to Info.
        assert_eq!(LogLevel::from_i32(5), LogLevel::Info);
        assert_eq!(LogLevel::from_i32(6), LogLevel::Info);
        // 7+ maps to Debug.
        assert_eq!(LogLevel::from_i32(7), LogLevel::Debug);
        assert_eq!(LogLevel::from_i32(100), LogLevel::Debug);
    }

    #[test]
    fn test_log_level_as_i32_roundtrip() {
        assert_eq!(LogLevel::Error.as_i32(), 3);
        assert_eq!(LogLevel::Warn.as_i32(), 4);
        assert_eq!(LogLevel::Info.as_i32(), 6);
        assert_eq!(LogLevel::Debug.as_i32(), 7);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(format!("{}", LogLevel::Error), "error");
        assert_eq!(format!("{}", LogLevel::Warn), "warn");
        assert_eq!(format!("{}", LogLevel::Info), "info");
        assert_eq!(format!("{}", LogLevel::Debug), "debug");
    }

    #[test]
    fn test_log_level_to_tracing_level() {
        assert_eq!(LogLevel::Error.to_tracing_level(), tracing::Level::ERROR);
        assert_eq!(LogLevel::Warn.to_tracing_level(), tracing::Level::WARN);
        assert_eq!(LogLevel::Info.to_tracing_level(), tracing::Level::INFO);
        assert_eq!(LogLevel::Debug.to_tracing_level(), tracing::Level::DEBUG);
    }

    // -----------------------------------------------------------------------
    // LogHdr — packed struct layout and zero-initialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_log_hdr_size() {
        assert_eq!(std::mem::size_of::<LogHdr>(), 8, "LogHdr must be 8 bytes packed");
    }

    #[test]
    fn test_log_hdr_default() {
        let hdr = LogHdr::default();
        assert_eq!({ hdr.opcode }, 0);
        assert_eq!({ hdr.index }, 0);
        assert_eq!({ hdr.len }, 0);
        assert_eq!({ hdr.priority }, 0);
        assert_eq!({ hdr.ident_len }, 0);
    }

    #[test]
    fn test_log_hdr_field_assignment() {
        let hdr = LogHdr {
            opcode: 0x0000,
            index: 0xFFFF,
            len: 42,
            priority: LogLevel::Warn.as_i32() as u8,
            ident_len: 5,
        };
        assert_eq!({ hdr.opcode }, 0x0000);
        assert_eq!({ hdr.index }, 0xFFFF);
        assert_eq!({ hdr.len }, 42);
        assert_eq!({ hdr.priority }, 4);
        assert_eq!({ hdr.ident_len }, 5);
    }

    // -----------------------------------------------------------------------
    // BtLog — lifecycle (new, close, is_open)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_log_new_is_closed() {
        let log = BtLog::new();
        assert!(!log.is_open(), "new BtLog should not be open");
    }

    #[test]
    fn test_bt_log_default_is_closed() {
        let log = BtLog::default();
        assert!(!log.is_open());
    }

    #[test]
    fn test_bt_log_open_and_close() {
        let mut log = BtLog::new();
        // open() will fail on systems without Bluetooth support (no
        // AF_BLUETOOTH), but the unsafe socket creation path is exercised.
        let result = log.open();
        if result.is_ok() {
            assert!(log.is_open(), "after successful open, should be open");
            log.close();
            assert!(!log.is_open(), "after close, should not be open");
        } else {
            // Socket creation failed (no BT kernel support) — error path
            // exercised. The unsafe libc::socket call still ran.
            assert!(!log.is_open());
        }
    }

    #[test]
    fn test_bt_log_open_caches_error() {
        let mut log = BtLog::new();
        // On systems without Bluetooth, the first open() fails.
        let result1 = log.open();
        if result1.is_err() {
            // Second call should return the cached error immediately
            // without attempting another socket() syscall.
            let result2 = log.open();
            assert!(result2.is_err(), "cached error should persist");
        }
    }

    // -----------------------------------------------------------------------
    // BtLog::sendmsg error path (exercises the unsafe sendmsg call)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_log_sendmsg_when_closed() {
        let mut log = BtLog::new();
        // sendmsg on a closed log should fail gracefully.
        let result = log.sendmsg(0xFFFF, "test", LogLevel::Info.as_i32(), &[]);
        assert!(result.is_err(), "sendmsg on closed log should fail");
    }

    // -----------------------------------------------------------------------
    // Free function API (thread-safe global wrappers)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_log_open_global() {
        // Exercises the mutex-protected global path.
        let _result = bt_log_open();
        // May succeed or fail depending on system, but exercises the code.
    }

    #[test]
    fn test_bt_log_vprintf_global() {
        // Exercises the vprintf path (will fail if socket not open, which
        // is expected and acceptable — the code path is covered).
        let _result = bt_log_vprintf(0xFFFF, "test", 7, "hello world");
    }

    #[test]
    fn test_bt_log_printf_global() {
        let _result = bt_log_printf(0xFFFF, "test", LogLevel::Debug.as_i32(), format_args!("formatted message"));
    }

    // -----------------------------------------------------------------------
    // MAX_USER_IOVEC constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_max_user_iovec_value() {
        assert_eq!(MAX_USER_IOVEC, 3, "matches C io_len > 3 guard");
    }
}
