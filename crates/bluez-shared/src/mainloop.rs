// SPDX-License-Identifier: GPL-2.0-or-later
//
// Main loop abstraction replacing src/shared/mainloop.c + mainloop-notify.c
//
// C's epoll-based mainloop is replaced by tokio's runtime. Signal handling
// uses tokio::signal. sd_notify is handled via a Unix datagram socket.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

/// Exit status for the main loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Success,
    Failure,
}

/// Main loop controller. Shared via `Arc` to allow signaling shutdown from
/// signal handlers, D-Bus methods, etc.
///
/// Replaces C's `mainloop_init()` / `mainloop_run()` / `mainloop_quit()`.
///
/// ```ignore
/// let mainloop = Mainloop::new();
/// let ml = mainloop.clone();
///
/// // In a signal handler or D-Bus method:
/// ml.quit();
///
/// // In the main task:
/// let status = mainloop.run_with_signal().await;
/// ```
#[derive(Clone)]
pub struct Mainloop {
    inner: Arc<MainloopInner>,
}

struct MainloopInner {
    shutdown: Notify,
    terminated: AtomicBool,
    exit_success: AtomicBool,
}

impl Mainloop {
    /// Create a new mainloop controller.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MainloopInner {
                shutdown: Notify::new(),
                terminated: AtomicBool::new(false),
                exit_success: AtomicBool::new(true),
            }),
        }
    }

    /// Signal the mainloop to quit with success status.
    ///
    /// Replaces C's `mainloop_quit()` and `mainloop_exit_success()`.
    pub fn quit(&self) {
        self.inner.exit_success.store(true, Ordering::SeqCst);
        self.inner.terminated.store(true, Ordering::SeqCst);
        self.inner.shutdown.notify_waiters();
    }

    /// Signal the mainloop to quit with failure status.
    ///
    /// Replaces C's `mainloop_exit_failure()`.
    pub fn quit_with_failure(&self) {
        self.inner.exit_success.store(false, Ordering::SeqCst);
        self.inner.terminated.store(true, Ordering::SeqCst);
        self.inner.shutdown.notify_waiters();
    }

    /// Check if the mainloop has been signaled to quit.
    pub fn is_terminated(&self) -> bool {
        self.inner.terminated.load(Ordering::SeqCst)
    }

    /// Wait for the shutdown signal. Returns the exit status.
    ///
    /// This is the simplest form — just waits for `quit()` to be called.
    pub async fn run(&self) -> ExitStatus {
        self.inner.shutdown.notified().await;
        self.exit_status()
    }

    /// Run the mainloop with SIGINT and SIGTERM signal handling.
    ///
    /// Replaces C's `mainloop_run_with_signal()`. Automatically calls `quit()`
    /// when SIGINT or SIGTERM is received.
    ///
    /// The provided `signal_handler` is called with the signal number before
    /// the mainloop exits. Pass `|_| {}` if you don't need custom handling.
    pub async fn run_with_signal<F>(&self, mut signal_handler: F) -> ExitStatus
    where
        F: FnMut(SignalKind),
    {
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("failed to register SIGINT handler");
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = self.inner.shutdown.notified() => {}
            _ = sigint.recv() => {
                signal_handler(SignalKind::Interrupt);
                self.quit();
            }
            _ = sigterm.recv() => {
                signal_handler(SignalKind::Terminate);
                self.quit();
            }
        }

        self.exit_status()
    }

    /// Get the current exit status.
    pub fn exit_status(&self) -> ExitStatus {
        if self.inner.exit_success.load(Ordering::SeqCst) {
            ExitStatus::Success
        } else {
            ExitStatus::Failure
        }
    }
}

impl Default for Mainloop {
    fn default() -> Self {
        Self::new()
    }
}

/// Signal types that the mainloop handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    Interrupt,
    Terminate,
}

/// Send a sd_notify message to systemd.
///
/// Replaces C's `mainloop_sd_notify()`. Reads the `NOTIFY_SOCKET` environment
/// variable and sends the state string to it.
///
/// Common state strings:
/// - `"READY=1"` — service startup complete
/// - `"STOPPING=1"` — service is shutting down
/// - `"STATUS=Starting up"` — status message
/// - `"WATCHDOG=1"` — watchdog keep-alive
pub fn sd_notify(state: &str) -> io::Result<()> {
    use std::os::unix::net::UnixDatagram;

    let sock_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(path) => path,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "NOTIFY_SOCKET not set",
            ));
        }
    };

    // Must be an abstract socket (@...) or absolute path
    if !sock_path.starts_with('@') && !sock_path.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET must start with @ or /",
        ));
    }

    let socket = UnixDatagram::unbound()?;

    // Abstract sockets: replace leading '@' with null byte
    if let Some(abstract_name) = sock_path.strip_prefix('@') {
        use std::os::unix::io::AsRawFd;

        let mut storage: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        storage.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = abstract_name.as_bytes();
        let max_len = storage.sun_path.len() - 1;
        let copy_len = bytes.len().min(max_len);
        // sun_path[0] stays 0 (abstract), copy rest starting at [1]
        for (i, &b) in bytes[..copy_len].iter().enumerate() {
            storage.sun_path[i + 1] = b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sa_family_t>() + 1 + copy_len;

        let fd = socket.as_raw_fd();
        // SAFETY: valid fd and sockaddr
        let ret = unsafe {
            libc::sendto(
                fd,
                state.as_ptr() as *const libc::c_void,
                state.len(),
                libc::MSG_NOSIGNAL,
                &storage as *const libc::sockaddr_un as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }

    // Regular path socket
    socket.send_to(state.as_bytes(), &sock_path)?;
    Ok(())
}

/// Build a tokio runtime suitable for BlueZ daemons.
///
/// Creates a multi-threaded runtime. Call this from `main()`:
/// ```ignore
/// fn main() {
///     let rt = bluez_shared::mainloop::build_runtime().unwrap();
///     rt.block_on(async {
///         let mainloop = Mainloop::new();
///         // ... start services ...
///         mainloop.run_with_signal(|sig| { /* handle signal */ }).await;
///     });
/// }
/// ```
pub fn build_runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_mainloop_quit() {
        let ml = Mainloop::new();
        let ml2 = ml.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ml2.quit();
        });

        let status = ml.run().await;
        assert_eq!(status, ExitStatus::Success);
    }

    #[tokio::test]
    async fn test_mainloop_quit_failure() {
        let ml = Mainloop::new();
        let ml2 = ml.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ml2.quit_with_failure();
        });

        let status = ml.run().await;
        assert_eq!(status, ExitStatus::Failure);
    }

    #[tokio::test]
    async fn test_mainloop_is_terminated() {
        let ml = Mainloop::new();
        assert!(!ml.is_terminated());
        ml.quit();
        assert!(ml.is_terminated());
    }

    #[test]
    fn test_build_runtime() {
        let rt = build_runtime();
        assert!(rt.is_ok());
    }

    #[test]
    fn test_sd_notify_no_socket() {
        // Without NOTIFY_SOCKET set, should return error
        std::env::remove_var("NOTIFY_SOCKET");
        let result = sd_notify("READY=1");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_trait() {
        let ml = Mainloop::default();
        assert!(!ml.is_terminated());
    }
}
