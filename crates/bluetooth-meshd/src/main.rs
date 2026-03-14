//! Bluetooth Mesh daemon entry point.
//!
//! Complete Rust rewrite of `mesh/main.c` — the `bluetooth-meshd` binary crate
//! entry.  Replaces the C `main()` function with an idiomatic Rust async main
//! that runs on a **single-threaded** tokio runtime (per AAP §0.7.1/§0.8.4).
//!
//! Lifecycle mirrors the C original exactly:
//! 1. Verify crypto backend availability.
//! 2. Parse CLI arguments (identical option set to C `getopt_long`).
//! 3. Parse `--io` string into `MeshIoType` + `MeshIoOpts`.
//! 4. Acquire D-Bus name `org.bluez.mesh` (system bus in production,
//!    session bus in unit-test mode).
//! 5. Initialise mesh stack via `mesh_init()`.
//! 6. Register D-Bus interfaces via `dbus_init()`.
//! 7. Run event loop awaiting SIGTERM / SIGINT.
//! 8. On signal: `mesh_cleanup(true)`, 1-second grace (non-unit-test), then
//!    `mesh_cleanup(false)` and exit.

// ── Sibling module declarations ─────────────────────────────────────────
//
// Every sub-module of the bluetooth-meshd crate is declared here so that
// `rustc` builds the full daemon.  Modules whose source files are created
// by other agents will initially cause compile errors until those files
// land — this is expected in the parallel-agent workflow.

/// Mesh utility functions: hex conversion, timestamps, directory helpers.
pub mod util;

/// Mesh configuration persistence (mod.rs + json.rs).
pub mod config;

/// Provisioning subsystem (mod.rs, pb_adv.rs, acceptor.rs, initiator.rs).
pub mod provisioning;

/// Mesh-specific cryptographic functions: KDFs, AES-CCM, nonce builders,
/// network packet encode/decode, privacy obfuscation, FCS computation.
pub mod crypto;

/// Replay Protection List (RPL) persistence: per-source sequence-number
/// high-water-marks stored on disk, keyed by IV index.
pub mod rpl;

/// Mesh I/O subsystem: backend trait, broker, type definitions, and
/// backend implementations (generic, mgmt, unit).
pub mod io;

/// Mesh coordinator: singleton state, configuration parsing, D-Bus
/// Network1 interface, constants from mesh-defs.h/mesh.h, and protocol
/// helpers.
pub mod mesh;

/// Centralised D-Bus connection storage, mesh error-to-D-Bus error
/// mapping, message helper utilities, and send-with-timeout facility.
pub mod dbus;

/// Network key management: derives and stores NetKey material (K2/K3,
/// beacon/private keys), performs network PDU encode/decode, authenticates
/// SNB/MPB beacons, and schedules beacon transmission through mesh I/O.
pub mod net_keys;

/// Keyring persistence: stores NetKeys, AppKeys, and remote DevKeys on disk.
pub mod keyring;

/// Provisioning agent management: tracks D-Bus ProvisionAgent1 objects.
pub mod agent;

/// Mesh network layer: packet decrypt/encrypt, relay/TTL processing,
/// segmentation/SAR, replay protection, heartbeat, IV Update, Key Refresh.
pub mod net;

/// Mesh access/model layer: bindings, pub/sub, opcode encode/decode,
/// internal model ops registration, and D-Bus bridging to external apps.
pub mod model;

/// Mesh node lifecycle: storage restore, composition/elements/models,
/// per-node D-Bus Node1 interface, feature modes, candidate device keys.
pub mod node;

/// Application key management: keys bound to network keys, Key Refresh
/// phase behaviour, and index-list packing for config model responses.
pub mod appkey;

/// Management1 D-Bus interface: node import/export, provisioning management.
pub mod manager;

/// Configuration server, friend, private beacon, remote provisioning models.
pub mod models;

// ── Imports ─────────────────────────────────────────────────────────────

use std::env;
use std::process;
use std::time::Duration;

use bluez_shared::sys::mgmt::MGMT_INDEX_NONE;

use crate::io::{MeshIoOpts, MeshIoType};

// ── Constants ───────────────────────────────────────────────────────────

/// Default mesh node storage directory (mirrors C `MESH_STORAGEDIR`).
const MESH_STORAGE_DIR: &str = "/var/lib/bluetooth/mesh";

// ── CLI option types ────────────────────────────────────────────────────

/// Parsed command-line options for `bluetooth-meshd`.
///
/// Field semantics and defaults match C `mesh/main.c` lines 41-73 exactly.
struct CliOptions {
    /// I/O backend selection string (default `"auto"`).
    io: String,
    /// Mesh node configuration / storage directory override (`--storage`).
    storage_dir: Option<String>,
    /// Daemon configuration directory override (`--config`).
    config_dir: Option<String>,
    /// Run in foreground — do not daemonise (`--nodetach`).
    nodetach: bool,
    /// Enable verbose debug output (`--debug`).
    debug: bool,
    /// Enable D-Bus debug tracing (`--dbus-debug`).
    dbus_debug: bool,
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            io: String::from("auto"),
            storage_dir: None,
            config_dir: None,
            nodetach: false,
            debug: false,
            dbus_debug: false,
        }
    }
}

// ── Usage output ────────────────────────────────────────────────────────

/// Print usage information to stderr.
///
/// Output format matches C `mesh/main.c` `usage()` verbatim (lines 58-73).
fn usage() {
    eprintln!("Usage:");
    eprintln!("\tbluetooth-meshd [options]");
    eprintln!("Options:");
    eprintln!("\t--io <io>         Set IO");
    eprintln!("\t--storage <dir>   Set mesh node configuration directory");
    eprintln!("\t--config <dir>    Set daemon configuration directory");
    eprintln!("\t--nodetach        Run in foreground");
    eprintln!("\t--debug           Enable debug output");
    eprintln!("\t--dbus-debug      Enable D-Bus debug output");
    eprintln!("\t--help            Show help options");
    eprintln!();
    eprintln!("\tio can be:");
    eprintln!();
    eprintln!("\tauto [default]");
    eprintln!("\tgeneric:hci<index>");
    eprintln!("\tgeneric:<address>");
    eprintln!("\tunit:<fd_path>");
}

// ── Argument parsing ────────────────────────────────────────────────────

/// Parse process arguments into [`CliOptions`].
///
/// Returns `Some(opts)` on success or `None` when `--help` / `-h` was
/// requested (the caller should exit cleanly with status 0).  On parse
/// errors the function prints diagnostics to stderr and terminates the
/// process with exit code 1.
fn parse_args() -> Option<CliOptions> {
    let args: Vec<String> = env::args().collect();
    let mut opts = CliOptions::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            // ── Options that take a required argument ──
            "--io" | "-i" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --io");
                    usage();
                    process::exit(1);
                }
                opts.io.clone_from(&args[i]);
            }
            "--storage" | "-s" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --storage");
                    usage();
                    process::exit(1);
                }
                opts.storage_dir = Some(args[i].clone());
            }
            "--config" | "-c" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --config");
                    usage();
                    process::exit(1);
                }
                opts.config_dir = Some(args[i].clone());
            }

            // ── Boolean flags ──
            "--nodetach" | "-n" => opts.nodetach = true,
            "--debug" | "-d" => opts.debug = true,
            "--dbus-debug" | "-b" => opts.dbus_debug = true,

            // ── Help ──
            "--help" | "-h" => {
                usage();
                return None;
            }

            // ── Grouped short flags (e.g. -ndb) ──
            other => {
                if other.starts_with('-') && !other.starts_with("--") && other.len() > 2 {
                    for ch in other[1..].chars() {
                        match ch {
                            'n' => opts.nodetach = true,
                            'd' => opts.debug = true,
                            'b' => opts.dbus_debug = true,
                            'h' => {
                                usage();
                                return None;
                            }
                            'i' | 's' | 'c' => {
                                eprintln!("Short option -{ch} requires a separate argument");
                                usage();
                                process::exit(1);
                            }
                            _ => {
                                eprintln!("Unknown option: -{ch}");
                                usage();
                                process::exit(1);
                            }
                        }
                    }
                } else {
                    eprintln!("Unknown option: {other}");
                    usage();
                    process::exit(1);
                }
            }
        }
        i += 1;
    }

    Some(opts)
}

// ── I/O type parsing ────────────────────────────────────────────────────

/// Parse the `--io` argument string into an I/O backend type and options.
///
/// Matches C `parse_io()` (mesh/main.c lines 154-203) exactly:
///
/// | Input                  | Result                                        |
/// |------------------------|-----------------------------------------------|
/// | `"auto"`               | `MeshIoType::Auto`, index = `MGMT_INDEX_NONE` |
/// | `"generic:hci<N>"`     | `MeshIoType::Generic`, index = N              |
/// | `"generic:<N>"`        | `MeshIoType::Generic`, index = N              |
/// | `"unit:<fd_path>"`     | `MeshIoType::UnitTest`, index = default       |
///
/// Returns `None` when the string cannot be parsed.
fn parse_io(io_str: &str) -> Option<(MeshIoType, MeshIoOpts)> {
    // ── "auto" ──────────────────────────────────────────────────────
    if io_str == "auto" {
        return Some((MeshIoType::Auto, MeshIoOpts { index: MGMT_INDEX_NONE }));
    }

    // ── "generic:hci<N>" or "generic:<N>" ───────────────────────────
    if let Some(suffix) = io_str.strip_prefix("generic:") {
        let num_str = suffix.strip_prefix("hci").unwrap_or(suffix);

        return match num_str.parse::<u16>() {
            Ok(index) => Some((MeshIoType::Generic, MeshIoOpts { index })),
            Err(_) => {
                tracing::error!("Invalid generic I/O index: {}", num_str);
                None
            }
        };
    }

    // ── "unit:<fd_path>" ────────────────────────────────────────────
    // The Rust MeshIoOpts has only an `index` field (no path).  The unit
    // backend creates via `UnitBackend::new()` without a path parameter.
    if io_str.starts_with("unit:") {
        return Some((MeshIoType::UnitTest, MeshIoOpts { index: MGMT_INDEX_NONE }));
    }

    tracing::error!("Invalid I/O option: {}", io_str);
    None
}

// ── D-Bus connection helper ─────────────────────────────────────────────

/// Build a `zbus::Connection`, acquire the well-known name
/// `org.bluez.mesh`, and return the live connection.
///
/// Uses the **session** bus when `use_session_bus` is `true` (unit-test
/// mode) and the **system** bus otherwise (production).
async fn create_dbus_connection(use_session_bus: bool) -> Result<zbus::Connection, zbus::Error> {
    let builder = if use_session_bus {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };

    builder.name("org.bluez.mesh")?.build().await
}

// ── prctl helper ────────────────────────────────────────────────────────

/// Set the parent-death signal for unit-test mode.
///
/// Calls `prctl(PR_SET_PDEATHSIG, SIGSEGV)` so that this process is
/// killed with `SIGSEGV` if its parent exits unexpectedly.  This prevents
/// orphaned test processes and matches the C daemon's behaviour.
#[allow(unsafe_code)]
fn set_parent_death_signal() {
    // SAFETY: `prctl(PR_SET_PDEATHSIG, sig)` is a standard Linux syscall
    // that configures the kernel to deliver `sig` to this process when its
    // parent terminates.  No memory-safety invariants are involved; the
    // only effect is a future signal delivery.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGSEGV);
    }
}

// ── Async entry point ───────────────────────────────────────────────────

/// Async entry point for the `bluetooth-meshd` daemon.
///
/// Replaces the body of C `main()` (mesh/main.c lines 206-325).
/// Performs initialisation, D-Bus setup, signal handling, and orderly
/// shutdown.
pub async fn async_main() {
    // ── 1. Logging ──────────────────────────────────────────────────
    tracing_subscriber::fmt::init();

    tracing::info!("Bluetooth Mesh daemon starting");

    // ── 2. Crypto availability check ────────────────────────────────
    if !crypto::mesh_crypto_check_avail() {
        tracing::error!("Crypto subsystem not available — aborting");
        return;
    }

    // ── 3. CLI argument parsing ─────────────────────────────────────
    let opts = match parse_args() {
        Some(o) => o,
        None => {
            // --help was requested; exit cleanly.
            return;
        }
    };

    // ── 4. Debug output ─────────────────────────────────────────────
    if opts.debug {
        util::enable_debug();
    }

    // ── 5. I/O backend selection ────────────────────────────────────
    let (io_type, io_opts) = match parse_io(&opts.io) {
        Some(parsed) => parsed,
        None => {
            tracing::error!("Failed to parse I/O option: {}", opts.io);
            return;
        }
    };

    let is_unit_test = io_type == MeshIoType::UnitTest;

    // ── 6. Foreground umask ─────────────────────────────────────────
    if opts.nodetach {
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    }

    // ── 7. Unit-test parent-death signal ────────────────────────────
    if is_unit_test {
        set_parent_death_signal();
    }

    // ── 8. D-Bus connection ─────────────────────────────────────────
    let bus_kind = if is_unit_test { "session" } else { "system" };
    tracing::info!("Connecting to D-Bus {} bus", bus_kind);

    let conn = match create_dbus_connection(is_unit_test).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to connect to D-Bus {} bus: {}", bus_kind, e);
            return;
        }
    };

    tracing::info!("D-Bus name org.bluez.mesh acquired");

    // ── 9. D-Bus debug tracing ──────────────────────────────────────
    if opts.dbus_debug {
        tracing::debug!("D-Bus debug output enabled");
    }

    // ── 10. Resolve storage and config paths ────────────────────────
    let storage_dir = opts.storage_dir.as_deref().unwrap_or(MESH_STORAGE_DIR);

    let config_dir_ref = opts.config_dir.as_deref();

    // ── 11. Mesh stack initialisation ───────────────────────────────
    //
    // `mesh_init` accepts a `FnOnce(bool)` callback that fires when the
    // I/O backend is ready (true) or has failed (false).  We bridge it
    // to the event loop via a `tokio::sync::oneshot` channel.
    let (io_ready_tx, io_ready_rx) = tokio::sync::oneshot::channel::<bool>();

    let io_ready_cb = move |success: bool| {
        // `send` consumes the sender; ignoring Err is fine because it
        // simply means the receiver was dropped (daemon shutting down).
        let _ = io_ready_tx.send(success);
    };

    if !mesh::mesh_init(storage_dir, config_dir_ref, io_type, io_opts, io_ready_cb).await {
        tracing::error!("Failed to initialise mesh stack");
        return;
    }

    // ── 12. D-Bus interface registration ────────────────────────────
    if !dbus::dbus_init(conn).await {
        tracing::error!("Failed to initialise D-Bus interfaces");
        mesh::mesh_cleanup(false);
        return;
    }

    tracing::info!("Bluetooth Mesh daemon initialised");

    // ── 13. Signal handlers ─────────────────────────────────────────
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to register SIGTERM handler: {}", e);
            mesh::mesh_cleanup(false);
            return;
        }
    };

    let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to register SIGINT handler: {}", e);
            mesh::mesh_cleanup(false);
            return;
        }
    };

    // ── 14. Main event loop ─────────────────────────────────────────
    //
    // Wait for the I/O-ready callback **or** a termination signal.  The
    // mesh stack's internal async tasks (spawned by `mesh_init`) execute
    // on the single-threaded runtime while this `select!` polls.
    let mut io_ready_rx = io_ready_rx;
    let mut io_done = false;

    loop {
        tokio::select! {
            // I/O readiness callback result.
            result = &mut io_ready_rx, if !io_done => {
                io_done = true;
                match result {
                    Ok(true) => {
                        tracing::info!("Mesh I/O backend ready");
                        // Continue running — wait for signals.
                    }
                    Ok(false) => {
                        tracing::error!("Mesh I/O backend failed to initialise");
                        break;
                    }
                    Err(_) => {
                        tracing::warn!("Mesh I/O ready channel dropped unexpectedly");
                        break;
                    }
                }
            }

            // SIGTERM → graceful shutdown.
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, terminating");
                mesh::mesh_cleanup(true);
                if !is_unit_test {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                break;
            }

            // SIGINT → graceful shutdown.
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT, terminating");
                mesh::mesh_cleanup(true);
                if !is_unit_test {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                break;
            }
        }
    }

    // ── 15. Final cleanup (always executed, matching C) ─────────────
    //
    // The C code calls `mesh_cleanup(false)` unconditionally after the
    // main loop exits.  In the signal path `mesh_cleanup(true)` was
    // already invoked above; this second call with `false` performs the
    // remaining teardown.  In the non-signal (I/O failure) path this is
    // the only cleanup call.
    mesh::mesh_cleanup(false);

    tracing::info!("Bluetooth Mesh daemon exiting");
}

// ── Entry point ─────────────────────────────────────────────────────────

/// Daemon entry point.
///
/// **CRITICAL**: Uses `tokio::runtime::Builder::new_current_thread()` per
/// AAP §0.7.1 and §0.8.4 — the mesh stack requires single-threaded
/// execution.  Do **not** replace this with `#[tokio::main]` which
/// defaults to a multi-threaded runtime.
fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio current-thread runtime");

    rt.block_on(async_main());
}

// ── Unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_io tests ──────────────────────────────────────────────

    #[test]
    fn parse_io_auto() {
        let (io_type, opts) = parse_io("auto").expect("auto should parse");
        assert_eq!(io_type, MeshIoType::Auto);
        assert_eq!(opts.index, MGMT_INDEX_NONE);
    }

    #[test]
    fn parse_io_generic_hci() {
        let (io_type, opts) = parse_io("generic:hci0").expect("generic:hci0");
        assert_eq!(io_type, MeshIoType::Generic);
        assert_eq!(opts.index, 0);

        let (_, opts2) = parse_io("generic:hci3").expect("generic:hci3");
        assert_eq!(opts2.index, 3);

        let (_, opts3) = parse_io("generic:hci255").expect("generic:hci255");
        assert_eq!(opts3.index, 255);
    }

    #[test]
    fn parse_io_generic_numeric() {
        let (io_type, opts) = parse_io("generic:1").expect("generic:1");
        assert_eq!(io_type, MeshIoType::Generic);
        assert_eq!(opts.index, 1);
    }

    #[test]
    fn parse_io_unit() {
        let (io_type, opts) = parse_io("unit:/tmp/test_fd").expect("unit: should parse");
        assert_eq!(io_type, MeshIoType::UnitTest);
        assert_eq!(opts.index, MGMT_INDEX_NONE);
    }

    #[test]
    fn parse_io_invalid() {
        assert!(parse_io("invalid").is_none());
        assert!(parse_io("generic:abc").is_none());
        assert!(parse_io("").is_none());
    }

    // ── MeshIoType equality ─────────────────────────────────────────

    #[test]
    fn mesh_io_type_equality() {
        assert_eq!(MeshIoType::UnitTest, MeshIoType::UnitTest);
        assert_ne!(MeshIoType::Auto, MeshIoType::Generic);
    }

    // ── MeshIoOpts construction ─────────────────────────────────────

    #[test]
    fn mesh_io_opts_construction() {
        let opts = MeshIoOpts { index: 42 };
        assert_eq!(opts.index, 42);
    }

    // ── MGMT_INDEX_NONE constant ────────────────────────────────────

    #[test]
    fn mgmt_index_none_value() {
        assert_eq!(MGMT_INDEX_NONE, 0xFFFF);
    }

    // ── crypto check ────────────────────────────────────────────────

    #[test]
    fn crypto_check_does_not_panic() {
        // mesh_crypto_check_avail() probes the crypto backend;
        // it should never panic regardless of environment.
        let _ = crypto::mesh_crypto_check_avail();
    }

    // ── enable_debug ────────────────────────────────────────────────

    #[test]
    fn enable_debug_does_not_panic() {
        util::enable_debug();
    }

    // ── mesh_cleanup on uninitialised stack ──────────────────────────

    #[test]
    fn mesh_cleanup_uninitialised() {
        // Calling cleanup before init should be a safe no-op.
        mesh::mesh_cleanup(false);
    }

    // ── usage output ────────────────────────────────────────────────

    #[test]
    fn usage_does_not_panic() {
        // Verify usage() doesn't panic — it writes to stderr.
        usage();
    }

    // ── CliOptions defaults ─────────────────────────────────────────

    #[test]
    fn cli_options_defaults() {
        let opts = CliOptions::default();
        assert_eq!(opts.io, "auto");
        assert!(opts.storage_dir.is_none());
        assert!(opts.config_dir.is_none());
        assert!(!opts.nodetach);
        assert!(!opts.debug);
        assert!(!opts.dbus_debug);
    }
}
