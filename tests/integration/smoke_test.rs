// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (C) 2024 BlueZ Contributors
 *
 * Integration smoke test exercising the full bluetoothd daemon lifecycle
 * through 6 core operations: power on, scan, pair, connect, disconnect,
 * power off — satisfying AAP Gate 8: Integration Sign-Off Checklist.
 *
 * All tests operate against a virtual HCI controller provided by the
 * bluez-emulator crate (VHCI-backed), with a private dbus-daemon session
 * for full test isolation. No real Bluetooth hardware is required.
 */

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::time::{sleep, timeout};

use zbus::Connection;
use zbus::connection::Builder as ConnectionBuilder;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use bluez_emulator::{EmulatorType, HciEmulator};
use bluez_shared::sys::bluetooth::BdAddr;

// ---------------------------------------------------------------------------
// Constants — generous timeouts for CI environments
// ---------------------------------------------------------------------------

/// Maximum time to wait for the bluetoothd daemon to start and register
/// the `org.bluez` bus name.
const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Polling interval when waiting for D-Bus state changes.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Maximum time to wait for the adapter object to appear at
/// `/org/bluez/hci0`.
const ADAPTER_WAIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum time to wait for a remote device object to appear during
/// discovery.
const DEVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum time to wait for a D-Bus property to reach an expected value
/// (e.g., `Powered: true`, `Paired: true`, `Connected: true`).
const PROPERTY_CHANGE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum time for a single D-Bus method call to return.
const DBUS_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for the complete pairing operation (which may involve
/// multiple round-trips between agent and daemon).
const PAIRING_TIMEOUT: Duration = Duration::from_secs(20);

/// Timeout for introspection calls.
const INTROSPECT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// AutoAcceptAgent — implements org.bluez.Agent1 for pairing
// ---------------------------------------------------------------------------

/// A minimal agent that auto-accepts all pairing requests.
///
/// Registered at `/test/agent` with `NoInputNoOutput` capability.
/// Every pairing callback returns success immediately, enabling
/// unattended pairing in integration tests.
struct AutoAcceptAgent;

#[zbus::interface(name = "org.bluez.Agent1")]
impl AutoAcceptAgent {
    /// Called when the daemon needs a PIN code for legacy pairing.
    /// Returns the default PIN "0000".
    async fn request_pin_code(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        _device: ObjectPath<'_>,
    ) -> zbus::fdo::Result<String> {
        eprintln!("[AutoAcceptAgent] RequestPinCode — returning '0000'");
        Ok("0000".to_owned())
    }

    /// Called when the daemon needs a numeric passkey for SSP pairing.
    /// Returns 0 (any passkey is accepted).
    async fn request_passkey(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        _device: ObjectPath<'_>,
    ) -> zbus::fdo::Result<u32> {
        eprintln!("[AutoAcceptAgent] RequestPasskey — returning 0");
        Ok(0)
    }

    /// Called to display a PIN code to the user. No-op for auto-accept.
    async fn display_pin_code(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        _device: ObjectPath<'_>,
        _pincode: &str,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[AutoAcceptAgent] DisplayPinCode — no-op");
        Ok(())
    }

    /// Called to display a passkey to the user. No-op for auto-accept.
    async fn display_passkey(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        _device: ObjectPath<'_>,
        _passkey: u32,
        _entered: u16,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[AutoAcceptAgent] DisplayPasskey — no-op");
        Ok(())
    }

    /// Called for numeric comparison confirmation. Auto-accepts.
    async fn request_confirmation(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        _device: ObjectPath<'_>,
        _passkey: u32,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[AutoAcceptAgent] RequestConfirmation — auto-accepting");
        Ok(())
    }

    /// Called for authorization of a connection. Auto-accepts.
    async fn request_authorization(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        _device: ObjectPath<'_>,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[AutoAcceptAgent] RequestAuthorization — auto-accepting");
        Ok(())
    }

    /// Called to authorize a specific service UUID. Auto-accepts.
    async fn authorize_service(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
        _device: ObjectPath<'_>,
        _uuid: &str,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[AutoAcceptAgent] AuthorizeService — auto-accepting");
        Ok(())
    }

    /// Called when a pairing operation is cancelled. No-op.
    async fn cancel(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[AutoAcceptAgent] Cancel");
        Ok(())
    }

    /// Called when the agent is unregistered. No-op.
    async fn release(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        eprintln!("[AutoAcceptAgent] Release");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SmokeTestFixture — manages daemon + emulator + dbus lifecycle
// ---------------------------------------------------------------------------

/// Test fixture managing the full lifecycle of:
/// - A private `dbus-daemon` session bus for test isolation
/// - An `HciEmulator` providing a virtual VHCI-backed Bluetooth controller
/// - The Rust `bluetoothd` daemon process
/// - A `zbus::Connection` to the private bus
///
/// Each test creates its own fixture instance for complete isolation.
struct SmokeTestFixture {
    /// PID of the private dbus-daemon process (for SIGTERM during teardown).
    bus_pid: i32,
    /// The D-Bus session bus address string (retained for diagnostic use).
    #[allow(dead_code)]
    bus_address: String,
    /// The bluetoothd daemon child process.
    daemon_process: Option<Child>,
    /// Async D-Bus connection to the private session bus.
    connection: Connection,
    /// HCI emulator providing the virtual controller.
    emulator: HciEmulator,
}

impl SmokeTestFixture {
    /// Set up the complete test fixture:
    ///
    /// 1. Launch a private `dbus-daemon --session` for isolation.
    /// 2. Create an `HciEmulator` with `EmulatorType::BrEdrLe` (dual-mode).
    /// 3. Spawn `bluetoothd --nodetach --experimental` on the private bus.
    /// 4. Wait for the `org.bluez` bus name to be registered.
    /// 5. Wait for the adapter object to appear at `/org/bluez/hci0`.
    async fn setup() -> Result<Self, String> {
        // Step 1: Launch private dbus-daemon.
        eprintln!("[SmokeTestFixture] Launching private dbus-daemon...");
        let bus_output = Command::new("dbus-daemon")
            .args(["--session", "--fork", "--print-address", "--print-pid"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Failed to launch dbus-daemon: {e}"))?;

        if !bus_output.status.success() {
            return Err(format!(
                "dbus-daemon failed: {}",
                String::from_utf8_lossy(&bus_output.stderr)
            ));
        }

        let stdout_str = String::from_utf8_lossy(&bus_output.stdout);
        let mut lines = stdout_str.lines();
        let bus_address = lines.next().ok_or("dbus-daemon produced no address")?.trim().to_owned();
        let bus_pid_str = lines.next().unwrap_or("0").trim().to_owned();
        let bus_pid: i32 = bus_pid_str.parse().unwrap_or(0);

        eprintln!("[SmokeTestFixture] Private dbus-daemon at {bus_address} (pid={bus_pid})");

        // Step 2: Create HCI emulator with dual-mode controller (requires /dev/vhci).
        eprintln!("[SmokeTestFixture] Creating HCI emulator (BrEdrLe)...");
        let emulator = HciEmulator::new(EmulatorType::BrEdrLe)
            .map_err(|e| format!("HciEmulator::new failed: {e}"))?;
        eprintln!("[SmokeTestFixture] HCI emulator created successfully");

        // Step 3: Locate and spawn bluetoothd.
        let daemon_bin =
            find_daemon_binary().ok_or("Could not find bluetoothd binary in target directory")?;
        eprintln!("[SmokeTestFixture] Spawning bluetoothd from {daemon_bin:?}...");

        let daemon_child = Command::new(&daemon_bin)
            .args(["--nodetach", "--experimental"])
            .env("DBUS_SESSION_BUS_ADDRESS", &bus_address)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn bluetoothd: {e}"))?;

        eprintln!("[SmokeTestFixture] bluetoothd spawned (pid={})", daemon_child.id());

        // Step 4: Connect to private D-Bus session and wait for org.bluez.
        eprintln!("[SmokeTestFixture] Connecting to private D-Bus session...");
        let connection = timeout(DAEMON_STARTUP_TIMEOUT, async {
            loop {
                match ConnectionBuilder::address(bus_address.as_str())
                    .expect("valid bus address")
                    .build()
                    .await
                {
                    Ok(conn) => return conn,
                    Err(_) => sleep(POLL_INTERVAL).await,
                }
            }
        })
        .await
        .map_err(|_| "Timed out connecting to private D-Bus session".to_owned())?;

        eprintln!("[SmokeTestFixture] D-Bus connection established, waiting for org.bluez...");

        // Wait for the org.bluez name to appear on the bus.
        timeout(DAEMON_STARTUP_TIMEOUT, async {
            loop {
                let proxy = zbus::fdo::DBusProxy::new(&connection)
                    .await
                    .expect("Failed to create DBusProxy");

                match proxy.name_has_owner("org.bluez".try_into().unwrap()).await {
                    Ok(true) => {
                        eprintln!("[SmokeTestFixture] org.bluez name acquired");
                        return;
                    }
                    _ => sleep(POLL_INTERVAL).await,
                }
            }
        })
        .await
        .map_err(|_| "Timed out waiting for org.bluez name to appear on D-Bus".to_owned())?;

        // Step 5: Wait for adapter at /org/bluez/hci0.
        eprintln!("[SmokeTestFixture] Waiting for adapter at /org/bluez/hci0...");
        timeout(ADAPTER_WAIT_TIMEOUT, async {
            loop {
                match introspect_at(&connection, "/org/bluez/hci0").await {
                    Ok(xml) if xml.contains("org.bluez.Adapter1") => {
                        eprintln!("[SmokeTestFixture] Adapter1 found at /org/bluez/hci0");
                        return;
                    }
                    _ => sleep(POLL_INTERVAL).await,
                }
            }
        })
        .await
        .map_err(|_| "Timed out waiting for Adapter1 at /org/bluez/hci0".to_owned())?;

        Ok(SmokeTestFixture {
            bus_pid,
            bus_address,
            daemon_process: Some(daemon_child),
            connection,
            emulator,
        })
    }

    /// Tear down the fixture: SIGTERM the daemon, kill the dbus-daemon.
    fn teardown(&mut self) {
        // Kill bluetoothd with SIGTERM for graceful shutdown.
        if let Some(ref mut child) = self.daemon_process {
            let pid = child.id();
            eprintln!("[SmokeTestFixture] Sending SIGTERM to bluetoothd (pid={pid})...");
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
            // Wait briefly for graceful exit.
            let _ = child.wait();
            eprintln!("[SmokeTestFixture] bluetoothd exited");
        }
        self.daemon_process = None;

        // Kill the private dbus-daemon.
        if self.bus_pid > 0 {
            eprintln!(
                "[SmokeTestFixture] Sending SIGTERM to dbus-daemon (pid={})...",
                self.bus_pid
            );
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(self.bus_pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }

        eprintln!("[SmokeTestFixture] Teardown complete");
    }
}

impl Drop for SmokeTestFixture {
    fn drop(&mut self) {
        self.teardown();
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Find the bluetoothd binary in the Cargo target directory.
fn find_daemon_binary() -> Option<std::path::PathBuf> {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Check debug build first.
    let debug_path = manifest_dir.join("target").join("debug").join("bluetoothd");
    if debug_path.exists() {
        return Some(debug_path);
    }

    // Check release build.
    let release_path = manifest_dir.join("target").join("release").join("bluetoothd");
    if release_path.exists() {
        return Some(release_path);
    }

    // Check CARGO_BIN_EXE_bluetoothd environment variable.
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_bluetoothd") {
        let pb = std::path::PathBuf::from(&p);
        if pb.exists() {
            return Some(pb);
        }
    }

    None
}

/// Introspect a D-Bus object and return the raw XML string.
async fn introspect_at(conn: &Connection, path: &str) -> Result<String, String> {
    let object_path =
        ObjectPath::try_from(path).map_err(|e| format!("Invalid object path '{path}': {e}"))?;

    let result = timeout(INTROSPECT_TIMEOUT, async {
        let proxy = zbus::fdo::IntrospectableProxy::builder(conn)
            .destination("org.bluez")
            .expect("valid bus name")
            .path(object_path)
            .expect("valid path")
            .build()
            .await
            .map_err(|e| format!("Failed to create IntrospectableProxy at {path}: {e}"))?;

        proxy.introspect().await.map_err(|e| format!("Introspect call failed at {path}: {e}"))
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(format!("Introspect timed out at {path}")),
    }
}

/// Set a D-Bus property via `org.freedesktop.DBus.Properties.Set`.
async fn set_property(
    conn: &Connection,
    path: &str,
    interface: &str,
    property: &str,
    value: Value<'_>,
) -> Result<(), String> {
    let object_path =
        ObjectPath::try_from(path).map_err(|e| format!("Invalid path '{path}': {e}"))?;

    let proxy = zbus::fdo::PropertiesProxy::builder(conn)
        .destination("org.bluez")
        .expect("valid bus name")
        .path(object_path)
        .expect("valid path")
        .build()
        .await
        .map_err(|e| format!("PropertiesProxy build failed at {path}: {e}"))?;

    timeout(DBUS_CALL_TIMEOUT, async {
        proxy
            .set(interface.try_into().unwrap(), property, value)
            .await
            .map_err(|e| format!("Set {interface}.{property} failed at {path}: {e}"))
    })
    .await
    .map_err(|_| format!("Set {interface}.{property} timed out at {path}"))?
}

/// Get a D-Bus property via `org.freedesktop.DBus.Properties.Get`.
async fn get_property(
    conn: &Connection,
    path: &str,
    interface: &str,
    property: &str,
) -> Result<OwnedValue, String> {
    let object_path =
        ObjectPath::try_from(path).map_err(|e| format!("Invalid path '{path}': {e}"))?;

    let proxy = zbus::fdo::PropertiesProxy::builder(conn)
        .destination("org.bluez")
        .expect("valid bus name")
        .path(object_path)
        .expect("valid path")
        .build()
        .await
        .map_err(|e| format!("PropertiesProxy build failed at {path}: {e}"))?;

    timeout(DBUS_CALL_TIMEOUT, async {
        proxy
            .get(interface.try_into().unwrap(), property)
            .await
            .map_err(|e| format!("Get {interface}.{property} failed at {path}: {e}"))
    })
    .await
    .map_err(|_| format!("Get {interface}.{property} timed out at {path}"))?
}

/// Call a D-Bus method with no arguments and no return value.
async fn call_void_method(
    conn: &Connection,
    path: &str,
    interface: &str,
    method: &str,
) -> Result<(), String> {
    timeout(DBUS_CALL_TIMEOUT, async {
        conn.call_method(Some("org.bluez"), path, Some(interface), method, &())
            .await
            .map_err(|e| format!("{interface}.{method}() failed at {path}: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|_| format!("{interface}.{method}() timed out at {path}"))?
}

/// Wait for a boolean D-Bus property to reach the expected value by polling.
async fn wait_for_bool_property(
    conn: &Connection,
    path: &str,
    interface: &str,
    property: &str,
    expected: bool,
    wait_timeout: Duration,
) -> Result<(), String> {
    timeout(wait_timeout, async {
        loop {
            match get_property(conn, path, interface, property).await {
                Ok(val) => {
                    if let Ok(b) = <bool>::try_from(&val) {
                        if b == expected {
                            return Ok(());
                        }
                    }
                }
                Err(_) => { /* property might not exist yet, keep polling */ }
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| format!("Timed out waiting for {interface}.{property} == {expected} at {path}"))?
}

/// Configure the emulator's client host to be discoverable for BR/EDR
/// inquiry scanning and LE advertising.
fn configure_emulator_peer(emulator: &HciEmulator) {
    if let Some(mut host) = emulator.client_get_host() {
        eprintln!("[SmokeTest] Configuring emulator peer host...");

        // Verify the host supports BR/EDR (dual-mode).
        assert!(
            host.bredr_capable(),
            "Emulator BtHost should be BR/EDR capable for dual-mode test"
        );

        // Enable BR/EDR page scan + inquiry scan (0x03 = both enabled).
        host.write_scan_enable(0x03);

        // Enable SSP mode for Secure Simple Pairing support.
        host.write_ssp_mode(0x01);

        // Enable LE host support.
        host.write_le_host_supported(0x01);

        // Set IO capability to NoInputNoOutput for auto-accept pairing.
        host.set_io_capability(0x03);

        // Set authentication requirements: MITM not required, general bonding.
        host.set_auth_req(0x01);

        // Enable Secure Connections support.
        host.set_sc_support(true);

        // Set a default PIN code for legacy pairing fallback.
        host.set_pin_code(b"0000");

        // Set LE advertising data with discoverable flags and a local name.
        host.set_adv_data(&[
            0x02, 0x01, 0x06, // Flags: LE General Discoverable + BR/EDR Not Supported
            0x05, 0x09, b'T', b'e', b's', b't', // Complete Local Name: "Test"
        ]);

        // Enable LE advertising.
        host.set_adv_enable(0x01);

        eprintln!("[SmokeTest] Emulator peer configured: scan+SSP+LE adv enabled");
    } else {
        eprintln!("[SmokeTest] WARNING: No client host available on emulator");
    }
}

/// Retrieve the emulator peer's BD_ADDR formatted as "XX:XX:XX:XX:XX:XX".
fn get_emulator_peer_address(emulator: &HciEmulator) -> Option<String> {
    let raw_addr = emulator.get_client_bdaddr()?;
    // raw_addr is a [u8; 6] in LSB-first order — convert via BdAddr.
    let bd = BdAddr { b: raw_addr };
    Some(format!("{bd}"))
}

/// Wait for any device object to appear under `/org/bluez/hci0/` during
/// discovery, returning the full D-Bus object path.
async fn wait_for_device_discovery(
    conn: &Connection,
    wait_timeout: Duration,
) -> Result<String, String> {
    timeout(wait_timeout, async {
        loop {
            // Use ObjectManager.GetManagedObjects to find device paths.
            let result = conn
                .call_method(
                    Some("org.bluez"),
                    "/",
                    Some("org.freedesktop.DBus.ObjectManager"),
                    "GetManagedObjects",
                    &(),
                )
                .await;

            if let Ok(reply) = result {
                let body = reply.body();
                if let Ok(objects) = body.deserialize::<HashMap<
                    zbus::zvariant::OwnedObjectPath,
                    HashMap<String, HashMap<String, OwnedValue>>,
                >>() {
                    for (path, interfaces) in &objects {
                        let path_str = path.as_str();
                        if path_str.starts_with("/org/bluez/hci0/dev_")
                            && interfaces.contains_key("org.bluez.Device1")
                        {
                            return Ok(path_str.to_owned());
                        }
                    }
                }
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| "Timed out waiting for device discovery".to_owned())?
}

/// Register the `AutoAcceptAgent` on the D-Bus connection and set it as
/// the default agent for bluetoothd.
async fn register_auto_accept_agent(conn: &Connection) -> Result<(), String> {
    // Serve the agent at /test/agent.
    conn.object_server()
        .at("/test/agent", AutoAcceptAgent)
        .await
        .map_err(|e| format!("Failed to serve AutoAcceptAgent at /test/agent: {e}"))?;

    // Register with AgentManager1.
    let agent_path = ObjectPath::try_from("/test/agent").unwrap();

    conn.call_method(
        Some("org.bluez"),
        "/org/bluez",
        Some("org.bluez.AgentManager1"),
        "RegisterAgent",
        &(agent_path, "NoInputNoOutput"),
    )
    .await
    .map_err(|e| format!("RegisterAgent failed: {e}"))?;

    eprintln!("[SmokeTest] AutoAcceptAgent registered at /test/agent");

    // Make it the default agent.
    let agent_path = ObjectPath::try_from("/test/agent").unwrap();
    conn.call_method(
        Some("org.bluez"),
        "/org/bluez",
        Some("org.bluez.AgentManager1"),
        "RequestDefaultAgent",
        &(agent_path,),
    )
    .await
    .map_err(|e| format!("RequestDefaultAgent failed: {e}"))?;

    eprintln!("[SmokeTest] AutoAcceptAgent set as default agent");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test: Daemon boots and registers on D-Bus
// ---------------------------------------------------------------------------

/// Verify that the Rust `bluetoothd` boots successfully, acquires the
/// `org.bluez` D-Bus name, exports the `ObjectManager` interface at
/// `/org/bluez`, and registers at least one adapter (hci0).
///
/// This is the simplest smoke test — Gate 1 baseline verification.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_daemon_boots_and_registers_on_dbus() {
    let fixture = SmokeTestFixture::setup().await.expect("SmokeTestFixture setup failed");

    // Verify org.bluez name is owned.
    let dbus_proxy =
        zbus::fdo::DBusProxy::new(&fixture.connection).await.expect("Failed to create DBusProxy");
    let owned = dbus_proxy
        .name_has_owner("org.bluez".try_into().unwrap())
        .await
        .expect("NameHasOwner call failed");
    assert!(owned, "org.bluez name should be owned on the bus");

    // Verify /org/bluez exists and exports ObjectManager.
    let root_xml = introspect_at(&fixture.connection, "/org/bluez")
        .await
        .expect("Failed to introspect /org/bluez");
    assert!(
        root_xml.contains("org.freedesktop.DBus.ObjectManager"),
        "/org/bluez must export ObjectManager interface"
    );

    // Verify at least one adapter (hci0) appears.
    let adapter_xml = introspect_at(&fixture.connection, "/org/bluez/hci0")
        .await
        .expect("Failed to introspect /org/bluez/hci0");
    assert!(
        adapter_xml.contains("org.bluez.Adapter1"),
        "/org/bluez/hci0 must export org.bluez.Adapter1"
    );

    eprintln!("[test_daemon_boots_and_registers_on_dbus] PASSED");
}

// ---------------------------------------------------------------------------
// Test: Power cycle
// ---------------------------------------------------------------------------

/// Verify that the adapter can be powered on and off multiple times
/// without stale state or failures.
///
/// Sequence: power on → verify → power off → verify → power on → verify
/// → power off → clean teardown.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_power_cycle() {
    let fixture = SmokeTestFixture::setup().await.expect("SmokeTestFixture setup failed");

    let adapter_path = "/org/bluez/hci0";
    let adapter_iface = "org.bluez.Adapter1";

    // --- Cycle 1: Power On ---
    eprintln!("[test_power_cycle] Cycle 1: Power On");
    set_property(&fixture.connection, adapter_path, adapter_iface, "Powered", Value::from(true))
        .await
        .expect("Failed to set Powered=true (cycle 1)");

    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Powered",
        true,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Powered did not become true (cycle 1)");

    let powered = get_property(&fixture.connection, adapter_path, adapter_iface, "Powered")
        .await
        .expect("Failed to read Powered (cycle 1)");
    assert!(<bool>::try_from(&powered).unwrap(), "Powered should be true after first power on");

    // --- Cycle 1: Power Off ---
    eprintln!("[test_power_cycle] Cycle 1: Power Off");
    set_property(&fixture.connection, adapter_path, adapter_iface, "Powered", Value::from(false))
        .await
        .expect("Failed to set Powered=false (cycle 1)");

    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Powered",
        false,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Powered did not become false (cycle 1)");

    let powered = get_property(&fixture.connection, adapter_path, adapter_iface, "Powered")
        .await
        .expect("Failed to read Powered (cycle 1 off)");
    assert!(!<bool>::try_from(&powered).unwrap(), "Powered should be false after first power off");

    // --- Cycle 2: Power On (no stale state) ---
    eprintln!("[test_power_cycle] Cycle 2: Power On");
    set_property(&fixture.connection, adapter_path, adapter_iface, "Powered", Value::from(true))
        .await
        .expect("Failed to set Powered=true (cycle 2)");

    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Powered",
        true,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Powered did not become true (cycle 2)");

    let powered = get_property(&fixture.connection, adapter_path, adapter_iface, "Powered")
        .await
        .expect("Failed to read Powered (cycle 2)");
    assert!(
        <bool>::try_from(&powered).unwrap(),
        "Powered should be true after second power on (no stale state)"
    );

    // --- Cycle 2: Power Off ---
    eprintln!("[test_power_cycle] Cycle 2: Power Off");
    set_property(&fixture.connection, adapter_path, adapter_iface, "Powered", Value::from(false))
        .await
        .expect("Failed to set Powered=false (cycle 2)");

    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Powered",
        false,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Powered did not become false (cycle 2)");

    // Verify adapter still accessible on D-Bus after power off.
    let xml = introspect_at(&fixture.connection, adapter_path)
        .await
        .expect("Adapter should remain on D-Bus after power off");
    assert!(
        xml.contains("org.bluez.Adapter1"),
        "Adapter1 interface should persist after power off"
    );

    eprintln!("[test_power_cycle] PASSED");
}

// ---------------------------------------------------------------------------
// Test: Full 6-operation lifecycle smoke test
// ---------------------------------------------------------------------------

/// Exercise the complete Bluetooth lifecycle — the 6 core operations
/// required by AAP Gate 8:
///
/// 1. Power On
/// 2. Scan (Discovery)
/// 3. Pair
/// 4. Connect
/// 5. Disconnect
/// 6. Power Off
///
/// All operations use the HCI emulator as a virtual peer device.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_full_lifecycle_smoke() {
    let fixture = SmokeTestFixture::setup().await.expect("SmokeTestFixture setup failed");

    let adapter_path = "/org/bluez/hci0";
    let adapter_iface = "org.bluez.Adapter1";
    let device_iface = "org.bluez.Device1";

    // -----------------------------------------------------------------------
    // Operation 1: Power On
    // -----------------------------------------------------------------------
    eprintln!("[test_full_lifecycle_smoke] === Operation 1: Power On ===");

    // Read initial Powered state — should be false.
    let powered_val = get_property(&fixture.connection, adapter_path, adapter_iface, "Powered")
        .await
        .expect("Failed to read initial Powered property");
    let initially_powered = <bool>::try_from(&powered_val).unwrap_or(false);
    eprintln!("[Op1] Initial Powered state: {initially_powered}");

    // Set Powered = true.
    set_property(&fixture.connection, adapter_path, adapter_iface, "Powered", Value::from(true))
        .await
        .expect("Failed to set Powered=true");

    // Wait for Powered to become true.
    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Powered",
        true,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Powered did not become true");

    // Verify Powered is now true.
    let powered_val = get_property(&fixture.connection, adapter_path, adapter_iface, "Powered")
        .await
        .expect("Failed to read Powered after power on");
    assert!(<bool>::try_from(&powered_val).unwrap(), "Powered should be true after power on");

    // Read Address — should be a valid BD_ADDR (XX:XX:XX:XX:XX:XX).
    let addr_val = get_property(&fixture.connection, adapter_path, adapter_iface, "Address")
        .await
        .expect("Failed to read Address property");
    let address: String = addr_val.try_into().expect("Address should be a string");
    eprintln!("[Op1] Adapter Address: {address}");
    assert_eq!(
        address.len(),
        17,
        "Address should be 17 chars (XX:XX:XX:XX:XX:XX), got '{address}'"
    );
    // Verify colon-separated hex format.
    let octets: Vec<&str> = address.split(':').collect();
    assert_eq!(octets.len(), 6, "Address should have 6 octets, got {}: '{address}'", octets.len());
    for octet in &octets {
        assert_eq!(
            octet.len(),
            2,
            "Each octet should be 2 hex chars, got '{octet}' in '{address}'"
        );
        assert!(
            octet.chars().all(|c| c.is_ascii_hexdigit()),
            "Non-hex character in octet '{octet}' of address '{address}'"
        );
    }

    // Read AddressType — should be "public" or "random".
    let addr_type_val =
        get_property(&fixture.connection, adapter_path, adapter_iface, "AddressType")
            .await
            .expect("Failed to read AddressType property");
    let addr_type: String = addr_type_val.try_into().expect("AddressType should be a string");
    eprintln!("[Op1] Adapter AddressType: {addr_type}");
    assert!(
        addr_type == "public" || addr_type == "random",
        "AddressType should be 'public' or 'random', got '{addr_type}'"
    );

    eprintln!("[Op1] Power On — PASSED");

    // -----------------------------------------------------------------------
    // Operation 2: Scan (Discovery)
    // -----------------------------------------------------------------------
    eprintln!("[test_full_lifecycle_smoke] === Operation 2: Scan (Discovery) ===");

    // Configure the emulator peer to be discoverable.
    configure_emulator_peer(&fixture.emulator);

    // Get peer address for later verification.
    let peer_address = get_emulator_peer_address(&fixture.emulator);
    eprintln!("[Op2] Emulator peer address: {peer_address:?}");

    // Register agent before discovery (needed for pairing in Op3).
    register_auto_accept_agent(&fixture.connection)
        .await
        .expect("Failed to register auto-accept agent");

    // Start discovery.
    call_void_method(&fixture.connection, adapter_path, adapter_iface, "StartDiscovery")
        .await
        .expect("StartDiscovery failed");

    // Verify Discovering is true.
    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Discovering",
        true,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Discovering did not become true");

    let discovering_val =
        get_property(&fixture.connection, adapter_path, adapter_iface, "Discovering")
            .await
            .expect("Failed to read Discovering property");
    assert!(
        <bool>::try_from(&discovering_val).unwrap(),
        "Discovering should be true after StartDiscovery"
    );

    // Wait for a device object to appear.
    let device_path = wait_for_device_discovery(&fixture.connection, DEVICE_WAIT_TIMEOUT)
        .await
        .expect("No device discovered during scan");

    eprintln!("[Op2] Discovered device at: {device_path}");

    // Verify device path format: /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX
    assert!(
        device_path.starts_with("/org/bluez/hci0/dev_"),
        "Device path has wrong prefix: {device_path}"
    );
    let dev_suffix = device_path.strip_prefix("/org/bluez/hci0/dev_").unwrap();
    assert_eq!(
        dev_suffix.len(),
        17,
        "Device BD_ADDR suffix should be 17 chars (XX_XX_XX_XX_XX_XX), got '{dev_suffix}'"
    );

    // Read discovered device's Address property.
    let dev_addr_val = get_property(&fixture.connection, &device_path, device_iface, "Address")
        .await
        .expect("Failed to read device Address property");
    let dev_address: String = dev_addr_val.try_into().expect("Device Address should be a string");
    eprintln!("[Op2] Device Address from D-Bus: {dev_address}");

    // If we know the peer address, verify it matches.
    if let Some(ref expected_addr) = peer_address {
        assert_eq!(
            dev_address.to_uppercase(),
            expected_addr.to_uppercase(),
            "Discovered device address should match emulator peer address"
        );
    }

    // Stop discovery.
    call_void_method(&fixture.connection, adapter_path, adapter_iface, "StopDiscovery")
        .await
        .expect("StopDiscovery failed");

    // Wait for Discovering to become false.
    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Discovering",
        false,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Discovering did not become false after StopDiscovery");

    eprintln!("[Op2] Scan (Discovery) — PASSED");

    // -----------------------------------------------------------------------
    // Operation 3: Pair
    // -----------------------------------------------------------------------
    eprintln!("[test_full_lifecycle_smoke] === Operation 3: Pair ===");

    // Agent already registered in Op2. Call Pair() on the device.
    let pair_result = timeout(PAIRING_TIMEOUT, async {
        conn_call_void(&fixture.connection, &device_path, device_iface, "Pair").await
    })
    .await;

    match pair_result {
        Ok(Ok(())) => eprintln!("[Op3] Pair() completed successfully"),
        Ok(Err(e)) => {
            // Some pairing errors are acceptable if the device ends up paired
            // (e.g., already paired, or profile-specific errors).
            eprintln!("[Op3] Pair() returned error (may be acceptable): {e}");
        }
        Err(_) => {
            eprintln!("[Op3] Pair() timed out — checking Paired property anyway");
        }
    }

    // Wait for Paired to become true.
    wait_for_bool_property(
        &fixture.connection,
        &device_path,
        device_iface,
        "Paired",
        true,
        PAIRING_TIMEOUT,
    )
    .await
    .expect("Device did not become Paired=true");

    let paired_val = get_property(&fixture.connection, &device_path, device_iface, "Paired")
        .await
        .expect("Failed to read Paired property");
    assert!(<bool>::try_from(&paired_val).unwrap(), "Paired should be true after pairing");

    eprintln!("[Op3] Pair — PASSED");

    // -----------------------------------------------------------------------
    // Operation 4: Connect
    // -----------------------------------------------------------------------
    eprintln!("[test_full_lifecycle_smoke] === Operation 4: Connect ===");

    let connect_result = timeout(DBUS_CALL_TIMEOUT, async {
        conn_call_void(&fixture.connection, &device_path, device_iface, "Connect").await
    })
    .await;

    match connect_result {
        Ok(Ok(())) => eprintln!("[Op4] Connect() completed successfully"),
        Ok(Err(e)) => {
            // Connection may fail for profile-specific reasons on emulator,
            // but the Connected property should still reflect the ACL state.
            eprintln!("[Op4] Connect() returned error (may be acceptable): {e}");
        }
        Err(_) => {
            eprintln!("[Op4] Connect() timed out — checking Connected property anyway");
        }
    }

    // Wait for Connected to become true.
    wait_for_bool_property(
        &fixture.connection,
        &device_path,
        device_iface,
        "Connected",
        true,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Device did not become Connected=true");

    let connected_val = get_property(&fixture.connection, &device_path, device_iface, "Connected")
        .await
        .expect("Failed to read Connected property");
    assert!(<bool>::try_from(&connected_val).unwrap(), "Connected should be true after Connect");

    eprintln!("[Op4] Connect — PASSED");

    // -----------------------------------------------------------------------
    // Operation 5: Disconnect
    // -----------------------------------------------------------------------
    eprintln!("[test_full_lifecycle_smoke] === Operation 5: Disconnect ===");

    let disconnect_result = timeout(DBUS_CALL_TIMEOUT, async {
        conn_call_void(&fixture.connection, &device_path, device_iface, "Disconnect").await
    })
    .await;

    match disconnect_result {
        Ok(Ok(())) => eprintln!("[Op5] Disconnect() completed successfully"),
        Ok(Err(e)) => {
            eprintln!("[Op5] Disconnect() returned error: {e}");
        }
        Err(_) => {
            eprintln!("[Op5] Disconnect() timed out — checking Connected property anyway");
        }
    }

    // Wait for Connected to become false.
    wait_for_bool_property(
        &fixture.connection,
        &device_path,
        device_iface,
        "Connected",
        false,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Device did not become Connected=false after Disconnect");

    let connected_val = get_property(&fixture.connection, &device_path, device_iface, "Connected")
        .await
        .expect("Failed to read Connected after disconnect");
    assert!(
        !<bool>::try_from(&connected_val).unwrap(),
        "Connected should be false after Disconnect"
    );

    eprintln!("[Op5] Disconnect — PASSED");

    // -----------------------------------------------------------------------
    // Operation 6: Power Off
    // -----------------------------------------------------------------------
    eprintln!("[test_full_lifecycle_smoke] === Operation 6: Power Off ===");

    set_property(&fixture.connection, adapter_path, adapter_iface, "Powered", Value::from(false))
        .await
        .expect("Failed to set Powered=false");

    wait_for_bool_property(
        &fixture.connection,
        adapter_path,
        adapter_iface,
        "Powered",
        false,
        PROPERTY_CHANGE_TIMEOUT,
    )
    .await
    .expect("Powered did not become false");

    let powered_val = get_property(&fixture.connection, adapter_path, adapter_iface, "Powered")
        .await
        .expect("Failed to read Powered after power off");
    assert!(!<bool>::try_from(&powered_val).unwrap(), "Powered should be false after power off");

    // Verify the adapter remains on D-Bus (object not removed, just powered down).
    let xml = introspect_at(&fixture.connection, adapter_path)
        .await
        .expect("Adapter should remain on D-Bus after power off");
    assert!(
        xml.contains("org.bluez.Adapter1"),
        "Adapter1 interface should persist after power off"
    );

    eprintln!("[Op6] Power Off — PASSED");

    eprintln!("[test_full_lifecycle_smoke] === ALL 6 OPERATIONS PASSED ===");
}

// ---------------------------------------------------------------------------
// Internal helper: call a void D-Bus method (used by lifecycle test)
// ---------------------------------------------------------------------------

/// Call a void D-Bus method on org.bluez, returning any error as a string.
/// Unlike `call_void_method`, this does not wrap in a timeout (caller manages).
async fn conn_call_void(
    conn: &Connection,
    path: &str,
    interface: &str,
    method: &str,
) -> Result<(), String> {
    conn.call_method(Some("org.bluez"), path, Some(interface), method, &())
        .await
        .map_err(|e| format!("{interface}.{method}() failed at {path}: {e}"))?;
    Ok(())
}
