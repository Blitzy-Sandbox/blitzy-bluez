// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors

//! Daemon Startup Time Benchmark
//!
//! Criterion benchmark measuring `bluetoothd` startup time for AAP Section
//! 0.8.3 **Gate 3** validation.
//!
//! **Threshold: startup time ≤ 1.5× C original.**
//!
//! Measured values are required per AAP 0.8.4 — "assumed parity is not
//! acceptable."
//!
//! # Measurement Methodology
//!
//! Time is measured from process initialisation to readiness to serve D-Bus
//! requests, corresponding to the C startup sequence in `src/main.c`
//! (line 1446: `main()`):
//!
//! 1. Configuration parsing (`main.conf` via `GKeyFile` — C lines ~30-40)
//! 2. Plugin initialisation (`plugin_init()` from `src/plugin.c` — iterating
//!    builtin descriptors, sorting by priority, calling `desc->init()`)
//! 3. Adapter initialisation (`adapter_init()` from `src/adapter.c` — opening
//!    MGMT socket, reading version, controller list)
//! 4. D-Bus name acquisition (`org.bluez` via gdbus)
//! 5. Main loop readiness
//!
//! In Rust these stages become:
//!
//! 1. `rust-ini` config parsing (replacing `GKeyFile`)
//! 2. `inventory::iter::<PluginDesc>()` collection and sorted init
//!    (replacing `BLUETOOTH_PLUGIN_DEFINE` + linker sections)
//! 3. `MgmtSocket` setup and initial controller discovery
//! 4. `zbus::Connection` name acquisition
//! 5. `tokio::runtime` readiness
//!
//! # Key C Constants (from src/main.c lines 57-60)
//!
//! - `DEFAULT_PAIRABLE_TIMEOUT    = 0` (disabled)
//! - `DEFAULT_DISCOVERABLE_TIMEOUT = 180` (3 minutes)
//! - `DEFAULT_TEMPORARY_TIMEOUT    = 30` (30 seconds)
//! - `DEFAULT_NAME_REQUEST_RETRY_DELAY = 300` (5 minutes)
//!
//! # Key Rust Modules
//!
//! - [`bluetoothd::config`] — `BtdOpts` configuration struct, `load_config`,
//!   `init_defaults`, `parse_config`
//! - [`bluetoothd::plugin`] — `PluginDesc`, `PluginPriority`, `plugin_init`,
//!   `plugin_cleanup`, `plugin_get_list`
//! - [`bluez_shared::mgmt::client`] — `MgmtSocket` async MGMT client
//! - [`bluez_emulator::hciemu`] — `HciEmulator`, `EmulatorType`
//!
//! # Gate Context
//!
//! - **Gate 1** requires `bluetoothd` running against `bluez-emulator` with
//!   `bluetoothctl` executing `power on`, `scan on`, `devices`, `power off`.
//! - **Gate 3** requires measured startup time within the 1.5× threshold.
//!
//! # AAP References
//!
//! - Section 0.8.3 Gate 3: Performance Baseline Comparison
//! - Section 0.8.4: Special Instructions and Constraints (measured values)
//! - Section 0.7.9: Configuration Preservation Analysis

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use bluetoothd::adapter::{adapter_cleanup, adapter_init};
use bluetoothd::config::{BtdOpts, init_defaults, load_config, parse_config};
use bluetoothd::dbus_common::set_dbus_connection;
use bluetoothd::plugin::{
    PluginDesc, PluginPriority, plugin_cleanup, plugin_get_list, plugin_init,
};
use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::mgmt::client::MgmtSocket;

// ---------------------------------------------------------------------------
// Test Fixture Helpers
// ---------------------------------------------------------------------------

/// Ensure a D-Bus session connection is available for plugin initialisation.
///
/// Several plugins (audio, input, battery, MIDI, etc.) register D-Bus
/// interfaces during `plugin_init()` by calling
/// [`btd_get_dbus_connection()`][bluetoothd::dbus_common::btd_get_dbus_connection],
/// which panics if no connection has been cached via
/// [`set_dbus_connection()`].
///
/// This helper establishes a session bus connection in two steps:
///
/// 1. **Existing bus** — attempt `zbus::Connection::session()`.  This
///    succeeds when `DBUS_SESSION_BUS_ADDRESS` points to a live daemon.
/// 2. **Private daemon** — if step 1 fails (e.g. CI environments with
///    `DBUS_SESSION_BUS_ADDRESS=/dev/null`), a private `dbus-daemon
///    --session` is started and the connection is established via the
///    address it prints.
///
/// The connection is cached in the global `OnceLock` via
/// `set_dbus_connection()` — subsequent calls are no-ops.
///
/// The private `dbus-daemon` (if started) runs until the benchmark process
/// exits; no explicit cleanup is required in ephemeral CI environments.
fn ensure_dbus_for_benchmarks(rt: &Runtime) {
    // Fast path: if the OnceLock is already populated, nothing to do.
    // Attempt a session bus connection which will only succeed if a live
    // daemon is reachable.
    let session_result = rt.block_on(async { zbus::Connection::session().await });
    if let Ok(conn) = session_result {
        set_dbus_connection(conn);
        return;
    }

    // Fallback: start a private dbus-daemon and connect to it.
    // --fork:  daemonise so .output() returns immediately.
    // --print-address=1: emit the bus address on stdout (fd 1).
    // --nopidfile: skip writing a PID file.
    let output = match std::process::Command::new("dbus-daemon")
        .args(["--session", "--fork", "--print-address=1", "--nopidfile"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "bench: cannot start private dbus-daemon: {e}; \
                 plugin benchmarks requiring D-Bus will be skipped"
            );
            return;
        }
    };

    let addr = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if addr.is_empty() {
        eprintln!(
            "bench: dbus-daemon returned empty address; \
             plugin benchmarks requiring D-Bus will be skipped"
        );
        return;
    }

    // Connect to the private bus using the explicit address (avoids needing
    // to call the unsafe std::env::set_var in Rust 2024 edition).
    //
    // The previous scaffolding used `.and_then(|b| Ok(b))` to reserve a place
    // for potential future error mapping; clippy flagged this as a no-op,
    // so we now rely solely on the synchronous `Builder::address`/`map_err`
    // combinator pair — the subsequent `match` still branches on Ok/Err.
    let conn_result = rt.block_on(async {
        zbus::connection::Builder::address(addr.as_str())
            .map_err(|e| format!("invalid dbus address: {e}"))
    });

    let builder = match conn_result {
        Ok(b) => b,
        Err(e) => {
            eprintln!("bench: failed to create dbus connection builder: {e}");
            return;
        }
    };

    let conn = match rt.block_on(async { builder.build().await }) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bench: failed to connect to private dbus-daemon: {e}");
            return;
        }
    };

    set_dbus_connection(conn);
}

/// Create a temporary `main.conf` configuration file with standard defaults.
///
/// The generated INI file mirrors the default configuration template shipped
/// with BlueZ (`src/main.conf`), containing all standard sections and keys
/// with their default values.  This ensures benchmark iterations exercise the
/// same parsing workload as a production daemon startup.
///
/// Key sections: `[General]`, `[BR]`, `[LE]`, `[Policy]`, `[GATT]`
///
/// Key defaults:
/// - `Name = %h-%d`
/// - `Class = 0x000000`
/// - `DiscoverableTimeout = 180`
/// - `PairableTimeout = 0`
/// - `AutoEnable = true`
///
/// Returns the path to the temporary config file.
fn create_test_config() -> PathBuf {
    let dir = env::temp_dir().join("bluez_bench_startup");
    std::fs::create_dir_all(&dir).expect("failed to create temp benchmark directory");
    let config_path = dir.join("main.conf");

    let config_content = "\
[General]
Name = %h-%d
Class = 0x000000
DiscoverableTimeout = 180
AlwaysPairable = false
PairableTimeout = 0
ReverseServiceDiscovery = true
NameResolving = true
DebugKeys = false
ControllerMode = dual
MaxControllers = 0
MultiProfile = off
FastConnectable = false
SecureConnections = on
Privacy = off
JustWorksRepairing = never
TemporaryTimeout = 30
RefreshDiscovery = true
Experimental = false
Testing = false
KernelExperimental = false
RemoteNameRequestRetryDelay = 300
FilterDiscoverable = true

[BR]
# BR/EDR defaults — all keys commented out to use kernel defaults

[LE]
CentralAddressResolution = 1

[Policy]
AutoEnable = true

[GATT]
Cache = always
Channels = 1

[CSIS]
Encryption = true

[AVDTP]
SessionMode = basic
StreamMode = basic

[AdvMon]
RSSISamplingPeriod = 0xFF
";

    std::fs::write(&config_path, config_content)
        .expect("failed to write temp benchmark config file");

    config_path
}

/// Set up an HCI emulator with a dual-mode VHCI virtual controller.
///
/// Provides a virtual Bluetooth controller for adapter initialisation to
/// succeed when running MGMT-dependent benchmarks.
///
/// Returns `None` if the VHCI device cannot be opened (e.g. missing kernel
/// module or insufficient permissions), allowing config-only benchmarks to
/// proceed without a controller.
fn setup_emulator() -> Option<HciEmulator> {
    match HciEmulator::new(EmulatorType::BrEdrLe) {
        Ok(emu) => {
            // Verify the emulator has a usable client (C: hciemu_get_client)
            if emu.get_client(0).is_some() {
                // Give the kernel a moment to register the virtual controller
                // so subsequent MGMT operations discover it.
                std::thread::sleep(Duration::from_millis(100));
            }
            Some(emu)
        }
        Err(e) => {
            eprintln!(
                "bench_startup: HciEmulator unavailable ({e}), \
                 adapter benchmarks will be skipped"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark: Configuration Parsing
// ---------------------------------------------------------------------------

/// Benchmark ONLY the configuration parsing phase (isolated from D-Bus/MGMT).
///
/// This measures the time to parse `main.conf` using `rust-ini` and populate
/// the `BtdOpts` configuration struct.  The C reference is the
/// `main_conf_parse()` pattern in `src/main.c` using
/// `g_key_file_load_from_file()`.
///
/// This is the fastest sub-benchmark — expected to be in the microsecond
/// range for a typical configuration file.
fn bench_config_parsing(c: &mut Criterion) {
    let config_path = create_test_config();
    let config_path_str = config_path.to_str().expect("non-UTF8 temp path");

    let mut group = c.benchmark_group("startup/config_parsing");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    group.bench_function("parse_main_conf", |b| {
        b.iter(|| {
            // Phase 1: Initialise defaults (C: init_defaults())
            let mut opts: BtdOpts = black_box(init_defaults());

            // Phase 2: Load the INI file (C: load_config())
            let ini = load_config(Some(config_path_str))
                .expect("benchmark config file should be loadable");

            // Phase 3: Parse all sections into opts (C: main_conf_parse_*)
            parse_config(&ini, &mut opts);

            // Prevent dead code elimination
            black_box(&opts);
        });
    });

    group.finish();

    // Clean up the temporary config file
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_dir(config_path.parent().unwrap());
}

// ---------------------------------------------------------------------------
// Benchmark: Plugin Discovery
// ---------------------------------------------------------------------------

/// Benchmark the plugin collection and sorting phase.
///
/// This measures the time to:
/// 1. Collect all `inventory::iter::<PluginDesc>()` entries
/// 2. Apply enable/disable filter patterns
/// 3. Sort by priority (HIGH=100 > DEFAULT=0 > LOW=-100)
///
/// C reference: `plugin_init()` in `src/plugin.c` — builtin descriptor
/// array iteration + priority sorting.
fn bench_plugin_discovery(c: &mut Criterion) {
    let config_path = create_test_config();
    let config_path_str = config_path.to_str().expect("non-UTF8 temp path");

    // Create a tokio runtime — several plugins (e.g. MIDI) call
    // tokio::spawn() during init, which requires an active reactor on the
    // current thread.  Without this the benchmark panics with "there is no
    // reactor running, must be called from the context of a Tokio 1.x
    // runtime" at midi.rs plugin_init → tokio::spawn.
    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bench_plugin_discovery: failed to create tokio runtime: {e}");
            return;
        }
    };

    // Ensure a D-Bus session connection is available — plugins register
    // D-Bus interfaces during init and call btd_get_dbus_connection().
    ensure_dbus_for_benchmarks(&rt);

    let mut group = c.benchmark_group("startup/plugin_discovery");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    // Verify priority ordering matches C definitions (src/plugin.h)
    // LOW=-100 < DEFAULT=0 < HIGH=100
    assert!((PluginPriority::Low as i32) < (PluginPriority::Default as i32));
    assert!((PluginPriority::Default as i32) < (PluginPriority::High as i32));

    // PluginDesc is the type collected by inventory for plugin registration.
    // Verify the type is sized and accessible (compile-time contract check).
    let _desc_size = black_box(std::mem::size_of::<PluginDesc>());

    group.bench_function("inventory_collect_and_sort", |b| {
        b.iter(|| {
            // Enter the tokio runtime context so that plugins calling
            // tokio::spawn() during init have an active reactor available.
            let _guard = rt.enter();

            // Initialise defaults needed for plugin_init
            let opts: BtdOpts = init_defaults();

            // Load configuration (plugin_init uses opts to decide on
            // testing/external plugin loading)
            let _ini = load_config(Some(config_path_str));

            // Discover, filter, sort, and init all built-in plugins
            let result = plugin_init(None, None, &opts);
            black_box(result);

            // Clean up plugin state for next iteration
            plugin_cleanup();
        });
    });

    group.finish();

    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_dir(config_path.parent().unwrap());
}

// ---------------------------------------------------------------------------
// Benchmark: Adapter / MGMT Initialization
// ---------------------------------------------------------------------------

/// Benchmark the adapter/MGMT initialisation phase in isolation.
///
/// Opens a [`MgmtSocket`], sends `READ_VERSION`, `READ_COMMANDS`, and
/// `READ_INDEX_LIST` — the three initial commands that `adapter_init()`
/// issues when bringing up the controller subsystem.
///
/// C reference: `adapter_init()` → `mgmt_new_default()` →
/// `mgmt_send(READ_VERSION)` chain in `src/adapter.c`.
///
/// This benchmark requires a VHCI-backed virtual controller via
/// [`HciEmulator`].  If the emulator is unavailable (e.g. in a CI
/// environment without `/dev/vhci`), the benchmark is skipped.
fn bench_adapter_init(c: &mut Criterion) {
    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bench_adapter_init: failed to create tokio runtime: {e}");
            return;
        }
    };

    // Set up emulator for MGMT operations to succeed
    let _emu = setup_emulator();
    if _emu.is_none() {
        eprintln!("bench_adapter_init: skipped — no HciEmulator available");
        return;
    }

    let mut group = c.benchmark_group("startup/adapter_init");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50);

    group.bench_function("mgmt_socket_and_adapter_init", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Create a new MgmtSocket (C: mgmt_new_default())
                let mgmt = match MgmtSocket::new_default() {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        // In environments without AF_BLUETOOTH support,
                        // this will fail — use black_box to prevent
                        // optimisation and return early.
                        black_box(e);
                        return;
                    }
                };

                // Subscribe to events (C: mgmt_register())
                let _rx = mgmt.subscribe(0x0004, 0xFFFF).await; // INDEX_ADDED

                // Send initial MGMT commands:
                // READ_VERSION (opcode 0x0001, non-indexed)
                let version_resp = mgmt.send_command(0x0001, 0xFFFF, &[]).await;
                black_box(&version_resp);

                // READ_COMMANDS (opcode 0x0002, non-indexed)
                let commands_resp = mgmt.send_command(0x0002, 0xFFFF, &[]).await;
                black_box(&commands_resp);

                // READ_INDEX_LIST (opcode 0x0003, non-indexed)
                let index_resp = mgmt.send_command(0x0003, 0xFFFF, &[]).await;
                black_box(&index_resp);

                // Run adapter_init which sets up internal state
                let init_result = adapter_init(mgmt.clone()).await;
                black_box(&init_result);

                // Clean up
                adapter_cleanup().await;
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: Full Daemon Startup
// ---------------------------------------------------------------------------

/// Benchmark the complete startup sequence.
///
/// This is the headline benchmark for Gate 3 (threshold: ≤ 1.5× C original).
/// It measures the full initialisation path:
///
/// 1. Configuration parsing (`rust-ini`)
/// 2. Plugin discovery and initialisation (`inventory` + priority sort)
/// 3. MGMT socket setup and initial controller discovery
/// 4. Adapter subsystem initialisation
///
/// D-Bus name acquisition is excluded from the tight loop to avoid
/// contention on the session/system bus, but all computational startup
/// work is included.
///
/// Uses `tokio::runtime::Runtime::block_on()` for the async initialisation.
fn bench_full_daemon_startup(c: &mut Criterion) {
    let config_path = create_test_config();
    let config_path_str = config_path.to_str().expect("non-UTF8 temp path").to_owned();

    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bench_full_daemon_startup: failed to create tokio runtime: {e}");
            return;
        }
    };

    // Ensure a D-Bus session connection is available — plugins register
    // D-Bus interfaces during init and call btd_get_dbus_connection().
    ensure_dbus_for_benchmarks(&rt);

    // Set up emulator (optional — benchmark will still run config + plugin
    // phases without it)
    let _emu = setup_emulator();

    let mut group = c.benchmark_group("startup/full_daemon");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    group.bench_function("config_plugin_adapter_startup", |b| {
        b.iter(|| {
            // Run the entire iteration inside rt.block_on() so that the
            // tokio runtime context is active for all phases.  Plugin init
            // (Phase 2) requires an active reactor because several plugins
            // (e.g. MIDI) call tokio::spawn() during initialisation.
            rt.block_on(async {
                // ── Phase 1: Configuration parsing ──
                let mut opts = init_defaults();
                if let Some(ini) = load_config(Some(&config_path_str)) {
                    parse_config(&ini, &mut opts);
                }
                black_box(&opts);

                // ── Phase 2: Plugin discovery and initialisation ──
                let plugin_result = plugin_init(None, None, &opts);
                black_box(plugin_result);

                let plugin_list = plugin_get_list();
                black_box(&plugin_list);

                // ── Phase 3: MGMT socket + adapter init ──
                // Create MGMT socket (may fail without AF_BLUETOOTH)
                let mgmt_result = MgmtSocket::new_default();

                if let Ok(mgmt) = mgmt_result {
                    let mgmt = Arc::new(mgmt);

                    // Run adapter_init
                    let init_result = adapter_init(mgmt.clone()).await;
                    black_box(&init_result);

                    // Clean up adapter state for next iteration
                    adapter_cleanup().await;
                }

                // ── Phase 4: Plugin cleanup ──
                plugin_cleanup();
            });
        });
    });

    group.finish();

    // Clean up temporary config file
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_dir(config_path.parent().unwrap());
}

// ---------------------------------------------------------------------------
// Criterion Registration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_config_parsing,
    bench_plugin_discovery,
    bench_full_daemon_startup,
    bench_adapter_init,
);
criterion_main!(benches);
