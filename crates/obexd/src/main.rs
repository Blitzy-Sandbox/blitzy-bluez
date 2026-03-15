// SPDX-License-Identifier: GPL-2.0-or-later
//
// OBEX Server — Rust rewrite of `obexd/src/main.c`
//
// Daemon entry point for the BlueZ OBEX server (`obexd`).  Provides the
// `org.bluez.obex` D-Bus service for Bluetooth Object Exchange — file
// transfer (OPP/FTP), phonebook access (PBAP), message access (MAP),
// basic imaging (BIP), and synchronisation (IrMC/SyncEvolution).
//
// The startup and shutdown sequences preserve the exact ordering of the
// C original to maintain identical external behaviour at every interface
// boundary.

// ============================================================================
// Module imports
// ============================================================================

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use bitflags::bitflags;
use thiserror::Error;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use bluez_shared::log::{bt_log_close, bt_log_open, init_logging};

// ============================================================================
// OBEX Service Constants (from obexd/src/obexd.h)
// ============================================================================

bitflags! {
    /// OBEX service type bitmask.
    ///
    /// Values match the C `OBEX_*` defines in `obexd/src/obexd.h` exactly.
    /// Used to filter which service drivers are applicable for a given
    /// transport or session context.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ObexServices: u16 {
        /// Object Push Profile.
        const OPP           = 1 << 1;
        /// File Transfer Profile.
        const FTP           = 1 << 2;
        /// Basic Imaging Profile.
        const BIP           = 1 << 3;
        /// Phone Book Access Profile.
        const PBAP          = 1 << 4;
        /// IrMC Synchronisation.
        const IRMC          = 1 << 5;
        /// Nokia PC Suite.
        const PCSUITE       = 1 << 6;
        /// SyncEvolution.
        const SYNCEVOLUTION = 1 << 7;
        /// Message Access Service.
        const MAS           = 1 << 8;
        /// Message Notification Service.
        const MNS           = 1 << 9;
    }
}

// ============================================================================
// Well-known constants
// ============================================================================

/// Default capability file path — matches C `DEFAULT_CAP_FILE`
/// (constructed from `CONFIGDIR "/capability.xml"`).
const DEFAULT_CAP_FILE: &str = "/etc/bluetooth/capability.xml";

/// D-Bus well-known name — matches C `OBEXD_SERVICE` from `manager.h`.
const OBEXD_SERVICE: &str = "org.bluez.obex";

// ============================================================================
// Daemon Configuration
// ============================================================================

/// Daemon configuration parsed from command-line arguments.
///
/// Matches the C global option variables in `obexd/src/main.c`:
///
/// | C Global              | Rust Field    |
/// |-----------------------|---------------|
/// | `option_debug`        | `debug`       |
/// | `option_detach`       | `detach`      |
/// | `option_root`         | `root`        |
/// | `option_root_setup`   | `root_setup`  |
/// | `option_capability`   | `capability`  |
/// | `option_plugin`       | `plugin`      |
/// | `option_noplugin`     | `noplugin`    |
/// | `option_autoaccept`   | `auto_accept` |
/// | `option_symlinks`     | `symlinks`    |
/// | `option_system_bus`   | `system_bus`  |
#[derive(Debug)]
pub struct ObexdConfig {
    /// Debug selector string.  `Some("*")` enables all debug, `None`
    /// means debug is disabled.  Comma/colon/space separated tokens
    /// matched against module names.
    pub debug: Option<String>,
    /// Whether to run as a background daemon (default: `true`).
    /// `--nodetach` sets this to `false`.
    pub detach: bool,
    /// Root folder for OBEX file operations.  Defaults to
    /// `$XDG_CACHE_HOME/obexd`.  Relative paths are resolved against
    /// `$HOME`.
    pub root: PathBuf,
    /// Optional setup script executed to create the root folder.
    pub root_setup: Option<PathBuf>,
    /// Capability description file (XML).  Defaults to
    /// `/etc/bluetooth/capability.xml`.
    pub capability: PathBuf,
    /// Comma-separated glob patterns of plugins to include.
    pub plugin: Option<String>,
    /// Comma-separated glob patterns of plugins to exclude.
    pub noplugin: Option<String>,
    /// Automatically accept incoming push requests without agent
    /// authorisation.
    pub auto_accept: bool,
    /// Allow symlinks that lead outside the root folder.
    pub symlinks: bool,
    /// Use the D-Bus system bus instead of the session bus.
    pub system_bus: bool,
}

impl Default for ObexdConfig {
    fn default() -> Self {
        Self {
            debug: None,
            detach: true,
            root: PathBuf::new(),
            root_setup: None,
            capability: PathBuf::from(DEFAULT_CAP_FILE),
            plugin: None,
            noplugin: None,
            auto_accept: false,
            symlinks: false,
            system_bus: false,
        }
    }
}

/// Process-wide daemon configuration.  Populated once during startup,
/// then immutably shared for the lifetime of the process.
static CONFIG: OnceLock<ObexdConfig> = OnceLock::new();

/// Flag toggled by `SIGUSR2` to enable all debug output at runtime.
/// Matches C `__obex_log_enable_debug()`.
static DEBUG_ALL_ENABLED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Error Types
// ============================================================================

/// Typed error enum for OBEX daemon lifecycle failures.
///
/// Each variant maps to a specific init step that can fail, replacing
/// the C `exit(EXIT_FAILURE)` calls with structured error reporting.
#[derive(Debug, Error)]
pub enum ObexdError {
    /// `manager_init()` failed — AgentManager1 D-Bus registration error.
    #[error("Manager initialization failed")]
    ManagerInitFailed,

    /// `obex_server_init()` failed — no transports or services available.
    #[error("Server initialization failed")]
    ServerInitFailed,

    /// `client_manager_init()` failed — Client1 D-Bus registration error.
    #[error("Client manager initialization failed")]
    ClientManagerInitFailed,

    /// Root folder does not exist and setup script failed or was absent.
    #[error("Root folder setup failed: {}", path.display())]
    RootFolderSetupFailed {
        /// The root folder path that could not be set up.
        path: PathBuf,
    },

    /// D-Bus connection or name acquisition failed.
    #[error("D-Bus connection failed")]
    DbusConnectionFailed,

    /// Unix signal handler setup failed.
    #[error("Signal setup failed")]
    SignalSetupFailed,
}

// ============================================================================
// Option Accessor Functions (matching C API from obexd/src/obexd.h)
// ============================================================================

/// Return whether auto-accept is enabled.
///
/// Matches C `gboolean obex_option_auto_accept(void)`.
pub fn obex_option_auto_accept() -> bool {
    CONFIG.get().is_some_and(|c| c.auto_accept)
}

/// Return the resolved root folder path.
///
/// Matches C `const char *obex_option_root_folder(void)`.
pub fn obex_option_root_folder() -> &'static Path {
    CONFIG.get().map_or(Path::new(""), |c| c.root.as_path())
}

/// Return whether symlinks outside root are allowed.
///
/// Matches C `gboolean obex_option_symlinks(void)`.
pub fn obex_option_symlinks() -> bool {
    CONFIG.get().is_some_and(|c| c.symlinks)
}

/// Return the capability file path.
///
/// Matches C `const char *obex_option_capability(void)`.
pub fn obex_option_capability() -> &'static Path {
    CONFIG.get().map_or(Path::new(DEFAULT_CAP_FILE), |c| c.capability.as_path())
}

// ============================================================================
// CLI Argument Parsing
// ============================================================================

/// Parse command-line arguments into an [`ObexdConfig`].
///
/// Replaces the C `GOptionContext` + `GOptionEntry` table.  Matching
/// behaviour:
///
/// - `-d` / `--debug`          — optional arg, default `"*"`
/// - `-p` / `--plugin NAME`    — required arg
/// - `-P` / `--noplugin NAME`  — required arg
/// - `-n` / `--nodetach`       — flag (reverses default `detach=true`)
/// - `-r` / `--root PATH`      — required arg
/// - `-S` / `--root-setup SCRIPT` — required arg
/// - `-l` / `--symlinks`       — flag
/// - `-c` / `--capability FILE` — required arg
/// - `-a` / `--auto-accept`    — flag
/// - `-s` / `--system-bus`     — flag
///
/// For `-d`, GOption's `G_OPTION_FLAG_OPTIONAL_ARG` means the value
/// must be attached (`-dVALUE`, `--debug=VALUE`); a bare `-d` or
/// `--debug` uses `"*"`.
fn parse_args() -> ObexdConfig {
    let mut config = ObexdConfig::default();
    let args: Vec<String> = env::args().collect();
    let mut i = 1;

    while i < args.len() {
        let arg = &args[i];

        // ---- Debug (optional argument) ----
        if arg == "-d" || arg == "--debug" {
            // Bare flag: no value → default "*"
            config.debug = Some("*".to_string());
        } else if let Some(value) = arg.strip_prefix("-d") {
            // Attached short form: -dVALUE
            if !value.is_empty() {
                config.debug = Some(value.to_string());
            } else {
                config.debug = Some("*".to_string());
            }
        } else if let Some(value) = arg.strip_prefix("--debug=") {
            config.debug = Some(if value.is_empty() { "*".to_string() } else { value.to_string() });
        }
        // ---- Plugin (required argument) ----
        else if arg == "-p" || arg == "--plugin" {
            i += 1;
            if i < args.len() {
                config.plugin = Some(args[i].clone());
            }
        } else if let Some(value) = arg.strip_prefix("--plugin=") {
            config.plugin = Some(value.to_string());
        }
        // ---- NoPlugin (required argument) ----
        else if arg == "-P" || arg == "--noplugin" {
            i += 1;
            if i < args.len() {
                config.noplugin = Some(args[i].clone());
            }
        } else if let Some(value) = arg.strip_prefix("--noplugin=") {
            config.noplugin = Some(value.to_string());
        }
        // ---- NoDetach (flag) ----
        else if arg == "-n" || arg == "--nodetach" {
            config.detach = false;
        }
        // ---- Root folder (required argument) ----
        else if arg == "-r" || arg == "--root" {
            i += 1;
            if i < args.len() {
                config.root = PathBuf::from(&args[i]);
            }
        } else if let Some(value) = arg.strip_prefix("--root=") {
            config.root = PathBuf::from(value);
        }
        // ---- Root setup script (required argument) ----
        else if arg == "-S" || arg == "--root-setup" {
            i += 1;
            if i < args.len() {
                config.root_setup = Some(PathBuf::from(&args[i]));
            }
        } else if let Some(value) = arg.strip_prefix("--root-setup=") {
            config.root_setup = Some(PathBuf::from(value));
        }
        // ---- Symlinks (flag) ----
        else if arg == "-l" || arg == "--symlinks" {
            config.symlinks = true;
        }
        // ---- Capability file (required argument) ----
        else if arg == "-c" || arg == "--capability" {
            i += 1;
            if i < args.len() {
                config.capability = PathBuf::from(&args[i]);
            }
        } else if let Some(value) = arg.strip_prefix("--capability=") {
            config.capability = PathBuf::from(value);
        }
        // ---- Auto-accept (flag) ----
        else if arg == "-a" || arg == "--auto-accept" {
            config.auto_accept = true;
        }
        // ---- System bus (flag) ----
        else if arg == "-s" || arg == "--system-bus" {
            config.system_bus = true;
        }
        // ---- Unknown ----
        else {
            eprintln!("Unknown option: {arg}");
            std::process::exit(1);
        }

        i += 1;
    }

    config
}

// ============================================================================
// Root Folder Resolution and Setup
// ============================================================================

/// Resolve the root folder path, applying defaults and relative-path
/// resolution.
///
/// Matches the C logic in `main()` (lines 293-308):
///
/// 1. If no `--root` specified → default to `$XDG_CACHE_HOME/obexd` and
///    create with `g_mkdir_with_parents(root, 0700)`.
/// 2. If root path is relative → prepend `$HOME`.
/// 3. If no `--capability` specified → default to `CONFIGDIR/capability.xml`.
fn resolve_root_folder(config: &mut ObexdConfig) {
    // Default root: $XDG_CACHE_HOME/obexd
    if config.root.as_os_str().is_empty() {
        let cache_dir = env::var("XDG_CACHE_HOME").map(PathBuf::from).unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".cache")
        });
        config.root = cache_dir.join("obexd");

        // Create directory tree with 0700 permissions
        if let Err(e) = fs::create_dir_all(&config.root) {
            error!("Failed to create dir({}): {}", config.root.display(), e);
        } else {
            // Set permissions to 0700 (owner-only)
            let _ = fs::set_permissions(&config.root, fs::Permissions::from_mode(0o700));
        }
    }

    // Resolve relative paths against $HOME
    if !config.root.is_absolute() {
        if let Ok(home) = env::var("HOME") {
            config.root = PathBuf::from(home).join(&config.root);
        }
    }

    // Default capability file (if still at the initial default, that's fine;
    // this matches the C: `if (option_capability == NULL)` which only triggers
    // when capability was never set).
}

/// Check whether a path is an existing directory.
///
/// Matches C `is_dir()` — logs an error and returns `false` on failure.
fn is_dir(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) => meta.is_dir(),
        Err(e) => {
            error!("stat({}): {}", path.display(), e);
            false
        }
    }
}

/// Verify the root folder exists, optionally running a setup script.
///
/// Matches C `root_folder_setup()` (lines 208-234):
///
/// 1. If root directory already exists → return `true`.
/// 2. If no setup script → return `false`.
/// 3. Execute setup script with root path as argument.
/// 4. Verify the script created the directory.
fn root_folder_setup(root: &Path, root_setup: Option<&Path>) -> bool {
    if is_dir(root) {
        return true;
    }

    let setup_script = match root_setup {
        Some(script) => script,
        None => return false,
    };

    debug!("Setting up {} using {}", root.display(), setup_script.display());

    let status = std::process::Command::new(setup_script).arg(root).status();

    match status {
        Ok(exit_status) => {
            if !exit_status.success() {
                let code = exit_status.code().unwrap_or(-1);
                error!("{} exited with status {}", setup_script.display(), code);
                return false;
            }
        }
        Err(e) => {
            error!("Unable to execute {}: {}", setup_script.display(), e);
            return false;
        }
    }

    is_dir(root)
}

// ============================================================================
// Logging Initialization
// ============================================================================

/// Set up the `tracing` subscriber for daemon output.
///
/// Replaces C `__obex_log_init(option_debug, option_detach)`:
///
/// - **No debug selector** → use [`init_logging()`] for basic `info`-level
///   output (fmt subscriber with target names and levels).
/// - **Debug selector specified** → build a custom subscriber with
///   [`EnvFilter`] translating the comma/colon/space-separated token
///   list into per-module trace directives.
/// - **HCI logging channel** → always opens via [`bt_log_open()`] for
///   btmon compatibility.
fn setup_logging(debug_opt: Option<&str>, _detach: bool) {
    if let Some(debug_str) = debug_opt {
        DEBUG_ALL_ENABLED.store(true, Ordering::Relaxed);

        // Translate OBEX-style debug selectors to tracing EnvFilter
        let filter_str = if debug_str == "*" {
            "debug".to_string()
        } else {
            // Start with info baseline; enable debug for selected modules.
            // The C code splits by `:, ` and pattern-matches against file
            // names; we map tokens directly to tracing filter directives.
            let mut filter = "info".to_string();
            for token in debug_str.split([',', ':', ' ']) {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    filter.push_str(&format!(",{trimmed}=debug"));
                }
            }
            filter
        };

        let env_filter = EnvFilter::try_new(&filter_str).unwrap_or_else(|_| EnvFilter::new("info"));

        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_level(true)
                    .with_thread_ids(false),
            )
            .init();
    } else {
        // Default: use bluez-shared's basic logging setup (info level,
        // fmt subscriber to stderr).
        init_logging();
    }

    // Open HCI logging channel for btmon compatibility — non-fatal on
    // failure (socket may not be available outside a running system).
    if let Err(e) = bt_log_open() {
        // Use warn level because the socket is expected to fail in
        // development environments.
        warn!("HCI logging channel not available: {e}");
    }
}

/// Enable all debug output at runtime.
///
/// Called in response to `SIGUSR2`, matching C `__obex_log_enable_debug()`.
/// Sets the global debug flag so that callers can check it.
fn enable_all_debug() {
    DEBUG_ALL_ENABLED.store(true, Ordering::Relaxed);
    info!("Debug logging enabled via SIGUSR2");
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// OBEX daemon entry point.
///
/// Uses `#[tokio::main]` with the default multi-thread runtime flavour
/// (per AAP Section 0.7.1: obexd uses `new_multi_thread()`).
///
/// The startup and shutdown sequences match the C `main()` exactly:
///
/// **Startup:**
/// 1. Parse CLI arguments
/// 2. Initialise logging
/// 3. Disable logind if `--system-bus`
/// 4. Set up signal handlers (SIGINT/SIGTERM/SIGUSR2)
/// 5. Acquire D-Bus connection and well-known name
/// 6. `manager_init()` — register AgentManager1
/// 7. Resolve root folder
/// 8. `plugin_init()` — load plugins
/// 9. `obex_server_init()` — start transports
/// 10. `root_folder_setup()` — verify/create root
/// 11. `client_manager_init()` — register Client1
/// 12. Main loop (await shutdown signal)
///
/// **Shutdown (reverse):**
/// 1. `client_manager_exit()`
/// 2. `obex_server_exit()`
/// 3. `plugin_cleanup()`
/// 4. `manager_cleanup()`
/// 5. Close logging
#[tokio::main]
async fn main() -> ExitCode {
    // ── Step 1: Parse CLI arguments ──────────────────────────────────
    let mut config = parse_args();

    // ── Step 2: Initialise logging ───────────────────────────────────
    setup_logging(config.debug.as_deref(), config.detach);

    info!("OBEX daemon {}", env!("CARGO_PKG_VERSION"));

    // ── Step 3: Disable logind for system-bus mode ───────────────────
    // In the C code, `logind_set(FALSE)` disables systemd-logind seat
    // tracking.  The Rust daemon does not integrate with sd-login; this
    // is a no-op log for behavioural documentation.
    if config.system_bus {
        debug!("System bus mode — logind monitoring disabled");
    }

    debug!("Entering main loop");

    // ── Step 4: Set up signal handlers ───────────────────────────────
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set up SIGINT handler: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set up SIGTERM handler: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut sigusr2 = match signal(SignalKind::user_defined2()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set up SIGUSR2 handler: {e}");
            return ExitCode::FAILURE;
        }
    };

    // ── Step 5: Acquire D-Bus connection and well-known name ─────────
    let conn = if config.system_bus {
        match zbus::connection::Builder::system() {
            Ok(builder) => match builder.name(OBEXD_SERVICE) {
                Ok(b) => match b.build().await {
                    Ok(c) => c,
                    Err(e) => {
                        error!("D-Bus system bus connection failed: {e}");
                        return ExitCode::FAILURE;
                    }
                },
                Err(e) => {
                    error!("D-Bus name request failed: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                error!("D-Bus system bus builder failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match zbus::connection::Builder::session() {
            Ok(builder) => match builder.name(OBEXD_SERVICE) {
                Ok(b) => match b.build().await {
                    Ok(c) => c,
                    Err(e) => {
                        error!("D-Bus session bus connection failed: {e}");
                        return ExitCode::FAILURE;
                    }
                },
                Err(e) => {
                    error!("D-Bus name request failed: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                error!("D-Bus session bus builder failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    // ── Step 6: Initialise D-Bus manager (AgentManager1) ─────────────
    if let Err(e) = obexd::server::manager_init(&conn).await {
        error!("manager_init failed: {e}");
        return ExitCode::FAILURE;
    }

    // ── Step 7: Resolve root folder ──────────────────────────────────
    resolve_root_folder(&mut config);

    // ── Step 8: Store config globally (after all mutations) ──────────
    let plugin_include = config.plugin.clone();
    let noplugin_exclude = config.noplugin.clone();
    CONFIG.set(config).expect("CONFIG already initialized");
    let config_ref = CONFIG.get().expect("CONFIG must be set");

    // ── Step 9: Initialise plugins ───────────────────────────────────
    obexd::plugins::plugin_init(plugin_include.as_deref(), noplugin_exclude.as_deref());

    // ── Step 10: Start OBEX server ───────────────────────────────────
    if let Err(e) = obexd::server::obex_server_init().await {
        error!("obex_server_init failed: {e}");
        return ExitCode::FAILURE;
    }

    // ── Step 11: Verify root folder (run setup script if needed) ─────
    if !root_folder_setup(&config_ref.root, config_ref.root_setup.as_deref()) {
        error!("Unable to setup root folder {}", config_ref.root.display());
        return ExitCode::FAILURE;
    }

    // ── Step 12: Initialise client manager ───────────────────────────
    if let Err(e) = obexd::client::client_manager_init(&conn).await {
        error!("client_manager_init failed: {e}");
        return ExitCode::FAILURE;
    }

    // ── Step 13: Main loop — await shutdown signal ───────────────────
    info!("OBEX daemon running");

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                info!("Terminating");
                break;
            }
            _ = sigterm.recv() => {
                info!("Terminating");
                break;
            }
            _ = sigusr2.recv() => {
                enable_all_debug();
            }
        }
    }

    // ── Shutdown (reverse of init) ───────────────────────────────────
    obexd::client::client_manager_exit(&conn).await;
    obexd::server::obex_server_exit().await;
    obexd::plugins::plugin_cleanup();
    obexd::server::manager_cleanup(&conn).await;

    // ── Cleanup logging ──────────────────────────────────────────────
    bt_log_close();

    info!("OBEX daemon exited");

    ExitCode::SUCCESS
}
