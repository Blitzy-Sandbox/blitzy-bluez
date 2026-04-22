// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012  Intel Corporation. All rights reserved.
//
//! GAP D-Bus interface tester — Rust rewrite of `tools/gap-tester.c`.
//!
//! Verifies that `org.bluez.Adapter1` D-Bus interface becomes available
//! with a matching BD_ADDR after creating an HCI emulator with a virtual
//! Bluetooth controller.
//!
//! This is the simplest integration tester — it registers a single test
//! case ("Adapter setup") that:
//! 1. Creates an HCI emulator (BR/EDR + LE dual-mode virtual controller)
//! 2. Connects to the system D-Bus and monitors for adapter appearance
//! 3. Verifies the adapter's Address property matches the emulator's BD_ADDR
//! 4. Passes if the adapter is found within the timeout period

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::tester::{
    TestCallback, tester_add, tester_init, tester_print, tester_run, tester_setup_complete,
    tester_setup_failed, tester_teardown_complete, tester_test_passed,
};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/// D-Bus ObjectManager `GetManagedObjects` return type.
///
/// Maps object paths → interface names → property names → property values.
/// D-Bus signature: `a{oa{sa{sv}}}`.
type ManagedObjects = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>;

// ---------------------------------------------------------------------------
// Test State
// ---------------------------------------------------------------------------

/// Shared mutable state for the GAP test case.
///
/// Replaces the C global variables:
/// - `dbus_conn`      (`DBusConnection *`)
/// - `dbus_client`    (`GDBusClient *`)
/// - `adapter_proxy`  (`GDBusProxy *`)
/// - `hciemu_stack`   (`struct hciemu *`)
///
/// Wrapped in `Arc<Mutex<>>` for safe sharing between tester callbacks
/// and the spawned async D-Bus monitoring task.
struct GapTestState {
    /// HCI emulator creating a virtual Bluetooth controller via VHCI.
    hciemu: Option<HciEmulator>,
}

// ---------------------------------------------------------------------------
// D-Bus Property Comparison
// ---------------------------------------------------------------------------

/// Compare a string property on a D-Bus proxy against an expected value.
///
/// Rust equivalent of C `compare_string_property()` (gap-tester.c:43-58).
/// Uses `zbus::Proxy::get_property` to read the named property and compare
/// it to the expected value.
///
/// Returns `true` if the property exists, is a string, and matches the
/// expected value.  Returns `false` on any error (property not found,
/// wrong type, D-Bus communication failure).
async fn compare_string_property(proxy: &zbus::Proxy<'_>, name: &str, value: &str) -> bool {
    match proxy.get_property::<String>(name).await {
        Ok(v) => v == value,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Adapter Discovery
// ---------------------------------------------------------------------------

/// Poll the D-Bus ObjectManager for the appearance of `org.bluez.Adapter1`
/// with a matching BD_ADDR.
///
/// Replaces the C `proxy_added()` callback (gap-tester.c:60-75) and the
/// GDBusClient proxy handler registration.  Instead of event-driven
/// monitoring via `g_dbus_client_set_proxy_handlers`, this function polls
/// `GetManagedObjects` on the `org.bluez` ObjectManager every 500 ms for
/// up to 30 seconds.
///
/// When an adapter with a matching `Address` property is found, returns
/// `Ok(())`.  If the timeout expires without finding a matching adapter,
/// returns an error.
async fn wait_for_adapter(
    expected_address: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Connect to the system D-Bus
    // (replaces g_dbus_setup_private(DBUS_BUS_SYSTEM, NULL, NULL))
    let connection = zbus::Connection::system().await?;

    tracing::info!("Connected to daemon");

    // Poll for adapter appearance (up to 30 seconds = 60 × 500 ms)
    for _ in 0..60 {
        // Query ObjectManager for all managed objects under /org/bluez
        // (replaces g_dbus_client_new + g_dbus_client_set_proxy_handlers)
        if let Ok(om_proxy) = zbus::Proxy::new(
            &connection,
            "org.bluez",
            "/org/bluez",
            "org.freedesktop.DBus.ObjectManager",
        )
        .await
        {
            let objects: Result<ManagedObjects, _> = om_proxy.call("GetManagedObjects", &()).await;

            if let Ok(objects) = objects {
                for (path, interfaces) in &objects {
                    if interfaces.contains_key("org.bluez.Adapter1") {
                        // Found an adapter interface — verify Address property
                        // (replaces compare_string_property in proxy_added)
                        if let Ok(adapter_proxy) = zbus::Proxy::new(
                            &connection,
                            "org.bluez",
                            path.as_str(),
                            "org.bluez.Adapter1",
                        )
                        .await
                        {
                            if compare_string_property(&adapter_proxy, "Address", &expected_address)
                                .await
                            {
                                tracing::info!("Found adapter");
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    Err("Timeout waiting for org.bluez.Adapter1 with matching address".into())
}

// ---------------------------------------------------------------------------
// Test Lifecycle Callbacks
// ---------------------------------------------------------------------------

/// Setup callback: create HCI emulator and start D-Bus adapter monitoring.
///
/// Replaces C `test_setup()` (gap-tester.c:94-106) combined with
/// `connect_handler()` (gap-tester.c:26-31) and `proxy_added()`
/// (gap-tester.c:60-75).
///
/// 1. Creates a BR/EDR+LE HCI emulator (C: `hciemu_new(HCIEMU_TYPE_BREDRLE)`)
/// 2. Retrieves the emulator's BD_ADDR for verification
/// 3. Spawns an async task that polls D-Bus for the adapter
/// 4. Calls `tester_setup_complete()` when the adapter is found
fn gap_test_setup(state: &Arc<Mutex<GapTestState>>) {
    // Create HCI emulator
    // (C: connect_handler → hciemu_new(HCIEMU_TYPE_BREDRLE))
    let emu = match HciEmulator::new(EmulatorType::BrEdrLe) {
        Ok(e) => e,
        Err(err) => {
            tester_print(&format!("Failed to create HCI emulator: {err}"));
            tester_setup_failed();
            return;
        }
    };

    // Get the emulator's BD_ADDR for adapter address verification
    // (C: hciemu_get_address(hciemu_stack))
    let emu_address = emu.get_address();

    // Store emulator in shared state
    state.lock().unwrap_or_else(|e| e.into_inner()).hciemu = Some(emu);

    // Spawn async task to monitor D-Bus for adapter appearance.
    // The task calls tester_setup_complete() when the adapter with
    // matching address is found, or tester_setup_failed() on error.
    tokio::spawn(async move {
        match wait_for_adapter(emu_address).await {
            Ok(()) => {
                tester_setup_complete();
            }
            Err(err) => {
                tester_print(&format!("Adapter monitoring failed: {err}"));
                tester_setup_failed();
            }
        }
    });
}

/// Run callback: the test passes if setup completed successfully.
///
/// Replaces C `test_run()` (gap-tester.c:108-111) which simply calls
/// `tester_test_passed()`.  The test logic is entirely in the setup
/// phase — if the adapter was found with a matching address, the test
/// passes.
fn gap_test_run() {
    tester_test_passed();
}

/// Teardown callback: clean up HCI emulator and signal completion.
///
/// Replaces C `test_teardown()` (gap-tester.c:113-117) and
/// `disconnect_handler()` (gap-tester.c:33-41).
///
/// Drops the HCI emulator (Rust ownership replaces `hciemu_unref`) and
/// signals teardown completion to the test harness.
fn gap_test_teardown(state: &Arc<Mutex<GapTestState>>) {
    tester_print("Disconnected from daemon");

    // Drop HCI emulator (C: hciemu_unref(hciemu_stack); hciemu_stack = NULL;)
    state.lock().unwrap_or_else(|e| e.into_inner()).hciemu = None;

    // Signal teardown completion
    // (C: tester_teardown_complete() in disconnect_handler)
    tester_teardown_complete();
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

/// GAP D-Bus interface tester entry point.
///
/// Replaces C `main()` (gap-tester.c:119-126):
/// 1. Initializes the tracing subscriber for structured logging
/// 2. Parses command-line arguments via the tester framework
/// 3. Registers the single "Adapter setup" test case
/// 4. Executes the test suite and exits with the result code
fn main() {
    // Initialize structured logging (replaces printf-based output)
    tracing_subscriber::fmt::init();

    // Initialize tester framework from CLI args
    // (C: tester_init(&argc, &argv))
    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    // Create shared test state
    let state = Arc::new(Mutex::new(GapTestState { hciemu: None }));

    // Build setup callback
    let setup_state = Arc::clone(&state);
    let setup_cb: TestCallback = Arc::new(move |_data: &dyn Any| {
        gap_test_setup(&setup_state);
    });

    // Build run callback — test passes if setup completed successfully
    let run_cb: TestCallback = Arc::new(|_data: &dyn Any| {
        gap_test_run();
    });

    // Build teardown callback
    let teardown_state = Arc::clone(&state);
    let teardown_cb: TestCallback = Arc::new(move |_data: &dyn Any| {
        gap_test_teardown(&teardown_state);
    });

    // Register the single "Adapter setup" test case
    // (C: tester_add("Adapter setup", NULL, test_setup, test_run, test_teardown))
    tester_add::<()>("Adapter setup", None, Some(setup_cb), Some(run_cb), Some(teardown_cb));

    // Run the test suite and exit with result code
    // (C: return tester_run())
    std::process::exit(tester_run());
}
