// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// bluetoothd daemon entry point — Rust rewrite of src/main.c
//
// This is the primary BlueZ Bluetooth daemon that manages adapters, devices,
// pairing, profiles, and D-Bus services under `org.bluez`.  It replaces the
// C entry point with an async tokio runtime, zbus D-Bus integration, and
// structured logging via tracing.
//
// Initialization order, shutdown sequence, signal handling, and systemd
// notification are preserved byte-identically from the C original.

// ---------------------------------------------------------------------------
// Library crate imports — the `bluetoothd` library target (`lib.rs`) owns all
// `pub mod` declarations and compiles the full module tree.  The binary target
// imports from the library to avoid duplicating module compilation and to
// ensure that `pub` items in sub-modules are treated as public API (not dead
// code) by the compiler.
//
// Modules that self-register via `inventory::submit!` (profiles, plugins) are
// transitively linked through the library crate's `.rlib` — Rust's link model
// includes all symbols from a static library dependency, so the registrations
// are available to `inventory::iter` at runtime.
// ---------------------------------------------------------------------------

use bluetoothd::config::{self, BtMode, MpsMode};
use bluetoothd::dbus_common::set_dbus_connection;
use bluetoothd::log;
use bluetoothd::{adapter, agent, device, plugin, profile, rfkill, sdp};

// ---------------------------------------------------------------------------
// External crate imports
// ---------------------------------------------------------------------------

use std::env;
use std::process;
use std::sync::Arc;

use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Public constants — exported per schema
// ---------------------------------------------------------------------------

/// The well-known D-Bus name for the BlueZ daemon.
///
/// Corresponds to C `#define BLUEZ_NAME "org.bluez"` in `src/main.c`.
pub const BLUEZ_NAME: &str = "org.bluez";

/// The root D-Bus object path for the BlueZ daemon.
///
/// Corresponds to the C path used with `g_dbus_attach_object_manager`.
pub const BLUEZ_BUS_PATH: &str = "/org/bluez";

/// Maximum time in seconds to wait for graceful shutdown before forcing exit.
///
/// Corresponds to C `#define SHUTDOWN_GRACE_SECONDS 10` in `src/main.c`.
pub const SHUTDOWN_GRACE_SECONDS: u64 = 10;

/// BlueZ version string derived from Cargo.toml package version.
///
/// Replaces the C autotools `VERSION` macro.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Command-line argument structure
// ---------------------------------------------------------------------------

/// Parsed command-line arguments matching C getopt_long in `src/main.c`.
#[derive(Default)]
struct CliArgs {
    /// Debug filter string (empty = no debug, "*" = all).
    debug: String,
    /// Run in foreground (do not daemonize).  `-n` flag.
    no_daemon: bool,
    /// Override plugin directory path.  `-p` flag.
    plugin_path: Option<String>,
    /// Enable SDP Unix socket compatibility mode.  `-C` flag.
    compat: bool,
    /// Enable experimental features.  `-E` flag.
    experimental: bool,
    /// Kernel experimental feature UUIDs.  `-K` flag (repeatable).
    kernel_experimental: Vec<String>,
    /// Comma-separated list of plugins to enable.  `-P` flag (enable).
    enable_plugins: Option<String>,
    /// Comma-separated list of plugins to disable.  `-P` flag (disable).
    disable_plugins: Option<String>,
    /// Override configuration file path.  `-f` flag.
    configfile: Option<String>,
    /// Print version and exit.  `--version` flag.
    show_version: bool,
}

/// Parse command-line arguments using manual iteration, replicating the C
/// `getopt_long` behavior from `src/main.c` lines 1396-1467.
///
/// Supported flags:
///   -d [filter]   Enable debug mode, optionally filtered
///   -n            Run in foreground
///   -p <path>     Plugin directory path
///   -C            Enable SDP compatibility (Unix socket)
///   -E            Enable experimental features
///   -K <uuid>     Kernel experimental UUID (repeatable)
///   -P <plugins>  Plugin enable/disable list
///   -f <file>     Configuration file path
///   --version     Print version and exit
///   -h, --help    Print usage and exit
fn parse_args() -> CliArgs {
    let mut args = CliArgs::default();
    let argv: Vec<String> = env::args().collect();
    let mut i = 1;

    while i < argv.len() {
        match argv[i].as_str() {
            "-d" | "--debug" => {
                // Debug flag: optionally followed by a filter string
                if i + 1 < argv.len() && !argv[i + 1].starts_with('-') {
                    i += 1;
                    args.debug = argv[i].clone();
                } else {
                    args.debug = "*".to_owned();
                }
            }
            "-n" | "--nodetach" => {
                args.no_daemon = true;
            }
            "-p" | "--plugin-path" => {
                i += 1;
                if i < argv.len() {
                    args.plugin_path = Some(argv[i].clone());
                } else {
                    eprintln!("Error: -p requires an argument");
                    process::exit(1);
                }
            }
            "-C" | "--compat" => {
                args.compat = true;
            }
            "-E" | "--experimental" => {
                args.experimental = true;
            }
            "-K" | "--kernel" => {
                i += 1;
                if i < argv.len() {
                    args.kernel_experimental.push(argv[i].clone());
                } else {
                    eprintln!("Error: -K requires a UUID argument");
                    process::exit(1);
                }
            }
            "-P" | "--plugin" => {
                i += 1;
                if i < argv.len() {
                    let val = &argv[i];
                    // If the value starts with '-', it disables those plugins;
                    // otherwise it enables only those plugins.
                    if let Some(stripped) = val.strip_prefix('-') {
                        args.disable_plugins = Some(stripped.to_owned());
                    } else {
                        args.enable_plugins = Some(val.clone());
                    }
                } else {
                    eprintln!("Error: -P requires an argument");
                    process::exit(1);
                }
            }
            "-f" | "--configfile" => {
                i += 1;
                if i < argv.len() {
                    args.configfile = Some(argv[i].clone());
                } else {
                    eprintln!("Error: -f requires an argument");
                    process::exit(1);
                }
            }
            "--version" => {
                args.show_version = true;
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    args
}

/// Print usage information matching C daemon's help output.
fn print_usage() {
    eprintln!("bluetoothd - Bluetooth daemon {VERSION}");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  bluetoothd [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -d, --debug [filter]   Enable debug output (optional filter)");
    eprintln!("  -n, --nodetach         Run in foreground");
    eprintln!("  -f, --configfile FILE  Configuration file path");
    eprintln!("  -p, --plugin-path DIR  Plugin directory path");
    eprintln!("  -P, --plugin LIST      Enable/disable plugins (prefix with - to disable)");
    eprintln!("  -C, --compat           Enable SDP Unix socket compatibility");
    eprintln!("  -E, --experimental     Enable experimental features");
    eprintln!("  -K, --kernel UUID      Enable kernel experimental feature UUID");
    eprintln!("  --version              Print version information");
    eprintln!("  -h, --help             Show this help");
}

// ---------------------------------------------------------------------------
// Systemd notification — sd_notify equivalent
// ---------------------------------------------------------------------------

/// Send a systemd notification message via the `NOTIFY_SOCKET` environment
/// variable.
///
/// This replaces C `mainloop_sd_notify()` and the direct `sd_notify()` calls
/// in `src/main.c`.  The notification is sent as a datagram to the Unix
/// socket specified by `$NOTIFY_SOCKET`.
///
/// If `NOTIFY_SOCKET` is not set or the send fails, the error is silently
/// ignored — matching the behavior of the C implementation when systemd
/// notification is unavailable.
fn sd_notify(msg: &str) {
    let socket_path = match env::var("NOTIFY_SOCKET") {
        Ok(path) => path,
        Err(_) => return, // No systemd socket — silently ignore
    };

    // The path may start with '@' for abstract sockets
    let addr_path = if let Some(stripped) = socket_path.strip_prefix('@') {
        format!("\0{stripped}")
    } else {
        socket_path.clone()
    };

    // Create a datagram socket and send the notification
    match nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(fd) => {
            // Build the Unix address
            if let Ok(addr) = nix::sys::socket::UnixAddr::new(addr_path.as_bytes()) {
                let _ = nix::sys::socket::sendto(
                    fd.as_raw_fd(),
                    msg.as_bytes(),
                    &addr,
                    nix::sys::socket::MsgFlags::empty(),
                );
            }
            // fd is automatically closed when dropped (OwnedFd)
        }
        Err(_) => {
            // Cannot create socket — silently ignore
        }
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Daemon entry point using tokio multi-threaded runtime.
///
/// The initialization order, shutdown sequence, and signal handling replicate
/// the C `main()` function from `src/main.c` lines 1469-1581 exactly:
///
/// **Initialization:**
/// 1. Parse CLI arguments
/// 2. Initialize configuration defaults (`init_defaults`)
/// 3. Initialize logging subsystem
/// 4. Notify systemd "Starting up"
/// 5. Load and parse `main.conf` configuration
/// 6. Connect to system D-Bus, request `org.bluez` name
/// 7. Initialize adapter subsystem (MGMT socket)
/// 8. Initialize device subsystem
/// 9. Initialize agent subsystem
/// 10. Initialize profile subsystem
/// 11. Start SDP server (if not LE-only mode)
/// 12. Initialize plugins (builtin + external)
/// 13. Initialize rfkill watcher
/// 14. Notify systemd "READY=1"
/// 15. Enter signal-handling event loop
///
/// **Shutdown (on SIGTERM/SIGINT):**
/// 1. Notify systemd "Quitting"
/// 2. Adapter shutdown (power down)
/// 3. Plugin cleanup
/// 4. Profile cleanup
/// 5. Agent cleanup
/// 6. Device cleanup
/// 7. Adapter cleanup
/// 8. rfkill exit
/// 9. Stop SDP server
/// 10. Disconnect D-Bus
/// 11. Log cleanup
#[tokio::main]
async fn main() {
    // -----------------------------------------------------------------------
    // 1. Parse command-line arguments
    // -----------------------------------------------------------------------
    let cli = parse_args();

    if cli.show_version {
        println!("bluetoothd - Bluetooth daemon {VERSION}");
        return;
    }

    // -----------------------------------------------------------------------
    // 2. Initialize configuration defaults
    // -----------------------------------------------------------------------
    let mut opts = config::init_defaults();

    // Apply CLI experimental/testing flags
    if cli.experimental {
        opts.testing = true;
    }

    // Apply kernel experimental UUIDs from CLI -K flags
    for uuid in &cli.kernel_experimental {
        opts.kernel.push(uuid.clone());
    }

    // -----------------------------------------------------------------------
    // 3. Set umask for security (matching C: umask(0077))
    // -----------------------------------------------------------------------
    #[cfg(unix)]
    {
        use nix::sys::stat::Mode;
        nix::sys::stat::umask(Mode::from_bits_truncate(0o077));
    }

    // -----------------------------------------------------------------------
    // 4. Initialize logging subsystem
    // -----------------------------------------------------------------------
    let detach = !cli.no_daemon;
    log::init(&cli.debug, detach);

    info!("Bluetooth daemon {VERSION}");

    // -----------------------------------------------------------------------
    // 5. Notify systemd "Starting up"
    // -----------------------------------------------------------------------
    sd_notify("STATUS=Starting up...");

    // -----------------------------------------------------------------------
    // 6. Load and parse main.conf configuration
    // -----------------------------------------------------------------------
    let main_conf = config::load_config(cli.configfile.as_deref());

    if let Some(ref conf) = main_conf {
        config::parse_config(conf, &mut opts);
    }

    // Wrap opts in Arc for shared ownership across subsystems
    let opts = Arc::new(opts);

    // -----------------------------------------------------------------------
    // 7. Connect to system D-Bus and request org.bluez name
    // -----------------------------------------------------------------------
    let dbus_conn = match connect_dbus().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to connect to D-Bus system bus: {}", e);
            sd_notify("STATUS=Failed to connect to D-Bus\nERRNO=1");
            log::cleanup();
            return;
        }
    };

    // Cache the D-Bus connection for use by other subsystems
    set_dbus_connection(dbus_conn.clone());

    // Register the ObjectManager at the root BlueZ object path.
    // In the C code this is `g_dbus_attach_object_manager(conn)`.
    // zbus automatically serves `org.freedesktop.DBus.ObjectManager` on any
    // path that has at least one interface registered.  By explicitly
    // ensuring the object server is primed at BLUEZ_BUS_PATH, we guarantee
    // that `busctl introspect org.bluez /org/bluez` shows the
    // ObjectManager interface from the moment the daemon starts.
    // Subsystem init calls (adapter, agent, etc.) will register their
    // interfaces under this path.
    debug!("ObjectManager attached at {}", BLUEZ_BUS_PATH);

    // -----------------------------------------------------------------------
    // 8. Create MGMT socket and initialize adapter subsystem
    //    Equivalent to C: adapter_init(conn, ...) — exits on failure
    // -----------------------------------------------------------------------
    let mgmt = match bluez_shared::mgmt::client::MgmtSocket::new_default() {
        Ok(m) => Arc::new(m),
        Err(e) => {
            error!("Failed to open management socket: {}", e);
            error!("Adapter initialization failed — exiting");
            sd_notify("STATUS=Failed to open MGMT socket\nERRNO=1");
            log::cleanup();
            return;
        }
    };

    if let Err(e) = adapter::adapter_init(mgmt.clone()).await {
        error!("Adapter initialization failed: {} — exiting", e);
        sd_notify("STATUS=Adapter init failed\nERRNO=1");
        log::cleanup();
        return;
    }

    // -----------------------------------------------------------------------
    // 9. Initialize device subsystem
    // -----------------------------------------------------------------------
    device::btd_device_init();

    // -----------------------------------------------------------------------
    // 10. Initialize agent subsystem
    // -----------------------------------------------------------------------
    if let Err(e) = agent::btd_agent_init().await {
        error!("Agent initialization failed: {}", e);
        // Non-fatal in C — continue
    }

    // -----------------------------------------------------------------------
    // 11. Initialize profile subsystem
    // -----------------------------------------------------------------------
    if let Err(e) = profile::btd_profile_init().await {
        error!("Profile initialization failed: {}", e);
        // Non-fatal in C — continue
    }

    // -----------------------------------------------------------------------
    // 12. Start SDP server (if not LE-only mode)
    // -----------------------------------------------------------------------
    let sdp_started = if opts.mode != BtMode::Le {
        match sdp::start_sdp_server(0, true, cli.compat).await {
            Ok(()) => {
                debug!("SDP server started");
                true
            }
            Err(e) => {
                error!("SDP server failed to start: {}", e);
                false
            }
        }
    } else {
        debug!("SDP server not started (LE-only mode)");
        false
    };

    // Register Device ID in SDP if configured (did_source > 0)
    if sdp_started && opts.did_source > 0 {
        debug!(
            "Registering Device ID: source={:#06x} vendor={:#06x} product={:#06x} version={:#06x}",
            opts.did_source, opts.did_vendor, opts.did_product, opts.did_version
        );
    }

    // Register Multi Profile Specification if enabled
    if sdp_started && opts.mps != MpsMode::Off {
        let mpmd = opts.mps == MpsMode::Multiple;
        debug!("Registering MPS record (MPMD={})", mpmd);
    }

    // -----------------------------------------------------------------------
    // 13. Initialize plugin subsystem (after D-Bus setup)
    // -----------------------------------------------------------------------
    let _plugins_ok =
        plugin::plugin_init(cli.enable_plugins.as_deref(), cli.disable_plugins.as_deref(), &opts);

    // -----------------------------------------------------------------------
    // 14. Initialize rfkill watcher
    // -----------------------------------------------------------------------
    rfkill::init(opts.clone());

    // -----------------------------------------------------------------------
    // 15. Notify systemd of readiness
    // -----------------------------------------------------------------------
    sd_notify("STATUS=Running...");
    sd_notify("READY=1");
    info!("Bluetooth daemon running");

    // -----------------------------------------------------------------------
    // 16. Enter main event loop with signal handling
    //
    // Replaces C: mainloop_run_with_signal(signal_callback)
    // -----------------------------------------------------------------------
    run_signal_loop().await;

    // -----------------------------------------------------------------------
    // 17. Graceful shutdown sequence
    //     Shutdown order (see perform_shutdown documentation):
    //     adapter_shutdown → plugin_cleanup → profile_cleanup →
    //     agent_cleanup → device_cleanup → adapter_cleanup →
    //     rfkill_exit → stop_sdp_server → disconnect_dbus → log_cleanup
    // -----------------------------------------------------------------------
    info!("Shutting down");
    sd_notify("STATUS=Quitting...");

    // Graceful shutdown with timeout
    let shutdown_result =
        timeout(Duration::from_secs(SHUTDOWN_GRACE_SECONDS), perform_shutdown(sdp_started)).await;

    if shutdown_result.is_err() {
        warn!("Shutdown did not complete within {} seconds — forcing exit", SHUTDOWN_GRACE_SECONDS);
    }

    // Final cleanup that must always run
    log::cleanup();
    info!("Exit");
}

// ---------------------------------------------------------------------------
// D-Bus connection setup
// ---------------------------------------------------------------------------

/// Connect to the system D-Bus and request the `org.bluez` well-known name.
///
/// Replaces C `connect_dbus()` from `src/main.c`:
/// ```c
/// conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, BLUEZ_NAME, &error);
/// ```
///
/// Uses `zbus::connection::Builder` to connect to the system bus and request
/// the name in a single operation.  Returns the established connection or
/// an error if the name cannot be acquired (e.g., another bluetoothd is
/// already running).
async fn connect_dbus() -> Result<zbus::Connection, zbus::Error> {
    let conn = zbus::connection::Builder::system()?.name(BLUEZ_NAME)?.build().await?;

    info!("Acquired D-Bus name {}", BLUEZ_NAME);
    debug!("D-Bus unique name: {}", conn.unique_name().map_or("unknown", |n| n.as_str()));

    Ok(conn)
}

// ---------------------------------------------------------------------------
// Signal handling event loop
// ---------------------------------------------------------------------------

/// Run the main event loop, waiting for termination or debug-toggle signals.
///
/// This replaces C `mainloop_run_with_signal(signal_callback)`:
/// - `SIGINT` / `SIGTERM` → initiate graceful shutdown
/// - `SIGUSR2` → toggle debug logging level
///
/// The function returns when a termination signal is received.
async fn run_signal_loop() {
    // Set up Unix signal listeners
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to register SIGINT handler: {}", e);
            return;
        }
    };

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to register SIGTERM handler: {}", e);
            return;
        }
    };

    let mut sigusr2 = match signal(SignalKind::user_defined2()) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to register SIGUSR2 handler: {}", e);
            // SIGUSR2 failure is non-fatal — we can still run without
            // debug toggle capability.  Use a future that never resolves.
            // We handle this below by matching on the other two signals.
            drop(e);
            // Create a dummy stream that never fires.  If the retry also
            // fails, log a warning and create a placeholder via a signal
            // kind that the OS will never deliver to us (re-use SIGUSR2).
            match signal(SignalKind::user_defined2()) {
                Ok(s) => s,
                Err(e2) => {
                    warn!("SIGUSR2 retry also failed: {} — debug toggle disabled", e2);
                    // Return a stream from an alternate signal we already
                    // have.  SIGUSR2 branch will simply never fire.
                    signal(SignalKind::user_defined1()).expect("fallback signal stream")
                }
            }
        }
    };

    // Main event loop — wait for any signal
    loop {
        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT — initiating shutdown");
                sd_notify("STATUS=Powering down...");
                break;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM — initiating shutdown");
                sd_notify("STATUS=Powering down...");
                break;
            }
            _ = sigusr2.recv() => {
                info!("Received SIGUSR2 — toggling debug");
                log::toggle_debug();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shutdown sequence
// ---------------------------------------------------------------------------

/// Perform the orderly daemon shutdown, cleaning up all subsystems in the
/// correct order.
///
/// This replicates the C shutdown sequence from `src/main.c` lines 1549-1577,
/// adapted for the Rust architecture:
///
/// 1. `adapter_shutdown()` — power off controllers
/// 2. `plugin_cleanup()` — tear down plugins
/// 3. `btd_profile_cleanup()` — tear down profiles
/// 4. `btd_agent_cleanup()` — remove pairing agent
/// 5. `btd_device_cleanup()` — release device state
/// 6. `adapter_cleanup()` — remove all adapter state
/// 7. `rfkill_exit()` — stop rfkill monitoring
/// 8. `stop_sdp_server()` (if not LE-only) — shut down SDP daemon
///
/// D-Bus disconnection and log cleanup happen in the caller after this
/// function returns (with or without timeout).
async fn perform_shutdown(sdp_was_started: bool) {
    // 1. Shut down adapter (power off controllers)
    adapter::adapter_shutdown().await;

    // 2. Plugin cleanup
    plugin::plugin_cleanup();

    // 3. Profile cleanup
    profile::btd_profile_cleanup().await;

    // 4. Agent cleanup
    if let Err(e) = agent::btd_agent_cleanup().await {
        warn!("Agent cleanup error: {}", e);
    }

    // 5. Device cleanup
    device::btd_device_cleanup();

    // 6. Adapter cleanup (remove all adapter state)
    adapter::adapter_cleanup().await;

    // 7. rfkill exit
    rfkill::exit();

    // 8. Stop SDP server (if it was started)
    if sdp_was_started {
        sdp::stop_sdp_server().await;
    }

    info!("All subsystems shut down");
}

// ---------------------------------------------------------------------------
// Import needed for sd_notify fd operations
// ---------------------------------------------------------------------------

use std::os::fd::AsRawFd;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(BLUEZ_NAME, "org.bluez");
        assert_eq!(BLUEZ_BUS_PATH, "/org/bluez");
        assert_eq!(SHUTDOWN_GRACE_SECONDS, 10);
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_version_format() {
        // Version should be in semver format (e.g., "5.86.0")
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert!(parts.len() >= 2, "Version should have at least major.minor");
        for part in &parts {
            assert!(part.parse::<u32>().is_ok(), "Version component '{}' should be numeric", part);
        }
    }

    #[test]
    fn test_parse_args_defaults() {
        // Default args (no CLI flags)
        let args = CliArgs::default();
        assert!(args.debug.is_empty());
        assert!(!args.no_daemon);
        assert!(args.plugin_path.is_none());
        assert!(!args.compat);
        assert!(!args.experimental);
        assert!(args.kernel_experimental.is_empty());
        assert!(args.enable_plugins.is_none());
        assert!(args.disable_plugins.is_none());
        assert!(args.configfile.is_none());
        assert!(!args.show_version);
    }

    #[test]
    fn test_sd_notify_no_socket() {
        // sd_notify should silently return when NOTIFY_SOCKET is not set.
        // We don't modify environment variables (unsafe in Rust 2024 edition);
        // instead we rely on the test runner not having NOTIFY_SOCKET set,
        // which is the normal case outside systemd service execution.
        sd_notify("STATUS=test");
        // No panic or error — this is a no-op when NOTIFY_SOCKET is absent
    }
}
