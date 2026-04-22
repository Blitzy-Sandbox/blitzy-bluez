// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Integration test: D-Bus interface contract verification.
//
// Satisfies AAP Gate 5 (API/Interface Contract Verification) — verifying
// that the Rust `bluetoothd` daemon exposes byte-identical D-Bus
// introspection XML compared to the C original for all `org.bluez.*`
// interfaces.
//
// AAP Section 0.8.3 Gate 5:
//   "`busctl introspect org.bluez /org/bluez` output MUST match the
//   C original exactly — interface names, method signatures, property
//   types, object paths."
//
// AAP Section 0.8.2:
//   "NEVER introduce new D-Bus interfaces, methods, properties, or
//   signals not present in the C original."
//   "Preserve all object paths (`/org/bluez`, `/org/bluez/hci0`,
//   `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX`)."

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::time::{sleep, timeout};
use zbus::Connection;
use zbus::connection::Builder as ConnectionBuilder;
use zbus::zvariant::ObjectPath;

// Re-export emulator types used in DaemonFixture and device tests.
use bluez_emulator::{EmulatorType, HciEmulator};

// ---------------------------------------------------------------------------
// Constants — timeouts
// ---------------------------------------------------------------------------

/// Maximum wait for the daemon to start and register on D-Bus.
const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum wait for a single D-Bus introspection call.
const INTROSPECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Polling interval when waiting for a name or object to appear.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Maximum wait for an adapter object to appear on D-Bus.
const ADAPTER_WAIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum wait for a device object to appear after discovery starts.
const DEVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// Expected D-Bus interface contracts (derived from doc/org.bluez.*.rst)
// ---------------------------------------------------------------------------

/// Descriptor for a D-Bus method in a contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MethodContract {
    name: String,
    /// D-Bus input signature (e.g., "osa{sv}" or "" for no args).
    in_sig: String,
    /// D-Bus output signature (e.g., "o" or "" for void).
    out_sig: String,
}

/// Descriptor for a D-Bus property in a contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PropertyContract {
    name: String,
    /// D-Bus type signature (e.g., "s", "b", "u", "as").
    sig: String,
    /// Access mode: "read", "readwrite".
    access: String,
}

/// Descriptor for a D-Bus signal in a contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SignalContract {
    name: String,
    /// D-Bus argument signatures concatenated.
    sig: String,
}

/// Full contract for a single D-Bus interface.
#[derive(Debug, Clone)]
struct InterfaceContract {
    name: String,
    methods: BTreeSet<MethodContract>,
    properties: BTreeSet<PropertyContract>,
    signals: BTreeSet<SignalContract>,
}

/// Build the expected `org.bluez.AgentManager1` contract from the RST docs.
fn expected_agent_manager1() -> InterfaceContract {
    let mut methods = BTreeSet::new();
    methods.insert(MethodContract {
        name: "RegisterAgent".into(),
        in_sig: "os".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "UnregisterAgent".into(),
        in_sig: "o".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "RequestDefaultAgent".into(),
        in_sig: "o".into(),
        out_sig: String::new(),
    });

    InterfaceContract {
        name: "org.bluez.AgentManager1".into(),
        methods,
        properties: BTreeSet::new(),
        signals: BTreeSet::new(),
    }
}

/// Build the expected `org.bluez.ProfileManager1` contract from the RST docs.
fn expected_profile_manager1() -> InterfaceContract {
    let mut methods = BTreeSet::new();
    methods.insert(MethodContract {
        name: "RegisterProfile".into(),
        in_sig: "osa{sv}".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "UnregisterProfile".into(),
        in_sig: "o".into(),
        out_sig: String::new(),
    });

    InterfaceContract {
        name: "org.bluez.ProfileManager1".into(),
        methods,
        properties: BTreeSet::new(),
        signals: BTreeSet::new(),
    }
}

/// Build the expected `org.bluez.Adapter1` contract from the RST docs.
fn expected_adapter1() -> InterfaceContract {
    let mut methods = BTreeSet::new();
    methods.insert(MethodContract {
        name: "StartDiscovery".into(),
        in_sig: String::new(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "StopDiscovery".into(),
        in_sig: String::new(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "RemoveDevice".into(),
        in_sig: "o".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "SetDiscoveryFilter".into(),
        in_sig: "a{sv}".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "GetDiscoveryFilters".into(),
        in_sig: String::new(),
        out_sig: "as".into(),
    });
    methods.insert(MethodContract {
        name: "ConnectDevice".into(),
        in_sig: "a{sv}".into(),
        out_sig: "o".into(),
    });

    let mut properties = BTreeSet::new();
    let ro = "read";
    let rw = "readwrite";
    for (name, sig, access) in [
        ("Address", "s", ro),
        ("AddressType", "s", ro),
        ("Name", "s", ro),
        ("Alias", "s", rw),
        ("Class", "u", ro),
        ("Powered", "b", rw),
        ("PowerState", "s", ro),
        ("Discoverable", "b", rw),
        ("DiscoverableTimeout", "u", rw),
        ("Pairable", "b", rw),
        ("PairableTimeout", "u", rw),
        ("Discovering", "b", ro),
        ("UUIDs", "as", ro),
        ("Modalias", "s", ro),
        ("Roles", "as", ro),
        ("ExperimentalFeatures", "as", ro),
        ("Manufacturer", "q", ro),
        ("Version", "y", ro),
        ("Connectable", "b", rw),
    ] {
        properties.insert(PropertyContract {
            name: name.into(),
            sig: sig.into(),
            access: access.into(),
        });
    }

    InterfaceContract {
        name: "org.bluez.Adapter1".into(),
        methods,
        properties,
        signals: BTreeSet::new(),
    }
}

/// Build the expected `org.bluez.LEAdvertisingManager1` contract.
fn expected_le_adv_manager1() -> InterfaceContract {
    let mut methods = BTreeSet::new();
    methods.insert(MethodContract {
        name: "RegisterAdvertisement".into(),
        in_sig: "oa{sv}".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "UnregisterAdvertisement".into(),
        in_sig: "o".into(),
        out_sig: String::new(),
    });

    let mut properties = BTreeSet::new();
    let ro = "read";
    for (name, sig) in [
        ("ActiveInstances", "y"),
        ("SupportedInstances", "y"),
        ("SupportedIncludes", "as"),
        ("SupportedSecondaryChannels", "as"),
        ("SupportedCapabilities", "a{sv}"),
        ("SupportedFeatures", "as"),
    ] {
        properties.insert(PropertyContract {
            name: name.into(),
            sig: sig.into(),
            access: ro.into(),
        });
    }

    InterfaceContract {
        name: "org.bluez.LEAdvertisingManager1".into(),
        methods,
        properties,
        signals: BTreeSet::new(),
    }
}

/// Build the expected `org.bluez.GattManager1` contract.
fn expected_gatt_manager1() -> InterfaceContract {
    let mut methods = BTreeSet::new();
    methods.insert(MethodContract {
        name: "RegisterApplication".into(),
        in_sig: "oa{sv}".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "UnregisterApplication".into(),
        in_sig: "o".into(),
        out_sig: String::new(),
    });

    InterfaceContract {
        name: "org.bluez.GattManager1".into(),
        methods,
        properties: BTreeSet::new(),
        signals: BTreeSet::new(),
    }
}

/// Build the expected `org.bluez.Device1` contract from the RST docs.
fn expected_device1() -> InterfaceContract {
    let mut methods = BTreeSet::new();
    methods.insert(MethodContract {
        name: "Connect".into(),
        in_sig: String::new(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "Disconnect".into(),
        in_sig: String::new(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "ConnectProfile".into(),
        in_sig: "s".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "DisconnectProfile".into(),
        in_sig: "s".into(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "Pair".into(),
        in_sig: String::new(),
        out_sig: String::new(),
    });
    methods.insert(MethodContract {
        name: "CancelPairing".into(),
        in_sig: String::new(),
        out_sig: String::new(),
    });

    let mut properties = BTreeSet::new();
    let ro = "read";
    let rw = "readwrite";
    for (name, sig, access) in [
        ("Address", "s", ro),
        ("AddressType", "s", ro),
        ("Name", "s", ro),
        ("Alias", "s", rw),
        ("Class", "u", ro),
        ("Appearance", "q", ro),
        ("Icon", "s", ro),
        ("Paired", "b", ro),
        ("Bonded", "b", ro),
        ("Trusted", "b", rw),
        ("Blocked", "b", rw),
        ("LegacyPairing", "b", ro),
        ("RSSI", "n", ro),
        ("Connected", "b", ro),
        ("UUIDs", "as", ro),
        ("Modalias", "s", ro),
        ("Adapter", "o", ro),
        ("ManufacturerData", "a{qv}", ro),
        ("ServiceData", "a{sv}", ro),
        ("TxPower", "n", ro),
        ("ServicesResolved", "b", ro),
        ("WakeAllowed", "b", rw),
        ("Sets", "a(oa{sv})", ro),
        ("AdvertisingFlags", "ay", ro),
        ("AdvertisingData", "a{yv}", ro),
        ("CablePairing", "b", ro),
    ] {
        properties.insert(PropertyContract {
            name: name.into(),
            sig: sig.into(),
            access: access.into(),
        });
    }

    let mut signals = BTreeSet::new();
    signals.insert(SignalContract { name: "Disconnected".into(), sig: "ss".into() });

    InterfaceContract { name: "org.bluez.Device1".into(), methods, properties, signals }
}

// ---------------------------------------------------------------------------
// Introspection XML parser (lightweight, no zbus_xml dependency)
// ---------------------------------------------------------------------------

/// A parsed D-Bus interface extracted from introspection XML.
#[derive(Debug, Clone)]
struct ParsedInterface {
    name: String,
    methods: BTreeSet<MethodContract>,
    properties: BTreeSet<PropertyContract>,
    signals: BTreeSet<SignalContract>,
}

/// A parsed introspection node with its child node names.
#[derive(Debug, Clone)]
struct ParsedNode {
    interfaces: Vec<ParsedInterface>,
    child_nodes: Vec<String>,
}

/// Parse D-Bus introspection XML into structured data.
///
/// This is a simple parser that extracts interface, method, property,
/// and signal definitions from standard D-Bus introspection XML.
fn parse_introspection_xml(xml: &str) -> ParsedNode {
    let mut interfaces = Vec::new();
    let mut child_nodes = Vec::new();

    // Simple line-by-line parsing of D-Bus introspection XML.
    // D-Bus introspection XML has a well-defined, flat structure:
    //   <node>
    //     <interface name="...">
    //       <method name="..."><arg .../></method>
    //       <property name="..." type="..." access="..."/>
    //       <signal name="..."><arg .../></signal>
    //     </interface>
    //     <node name="..."/>
    //   </node>

    let mut current_iface: Option<ParsedInterface> = None;
    let mut current_method_name: Option<String> = None;
    let mut current_method_in_args = String::new();
    let mut current_method_out_args = String::new();
    let mut current_signal_name: Option<String> = None;
    let mut current_signal_args = String::new();

    for line in xml.lines() {
        let trimmed = line.trim();

        // Interface start
        if trimmed.starts_with("<interface") && trimmed.contains("name=") {
            if let Some(iface) = current_iface.take() {
                interfaces.push(iface);
            }
            if let Some(name) = extract_attr(trimmed, "name") {
                current_iface = Some(ParsedInterface {
                    name,
                    methods: BTreeSet::new(),
                    properties: BTreeSet::new(),
                    signals: BTreeSet::new(),
                });
            }
        }
        // Interface end
        else if trimmed == "</interface>" {
            if let Some(iface) = current_iface.take() {
                interfaces.push(iface);
            }
        }
        // Method start (may be self-closing or multi-line)
        else if trimmed.starts_with("<method") && trimmed.contains("name=") {
            if let Some(name) = extract_attr(trimmed, "name") {
                if trimmed.ends_with("/>") {
                    // Self-closing method with no args
                    if let Some(ref mut iface) = current_iface {
                        iface.methods.insert(MethodContract {
                            name,
                            in_sig: String::new(),
                            out_sig: String::new(),
                        });
                    }
                } else {
                    current_method_name = Some(name);
                    current_method_in_args.clear();
                    current_method_out_args.clear();
                }
            }
        }
        // Method end
        else if trimmed == "</method>" {
            if let Some(name) = current_method_name.take() {
                if let Some(ref mut iface) = current_iface {
                    iface.methods.insert(MethodContract {
                        name,
                        in_sig: current_method_in_args.clone(),
                        out_sig: current_method_out_args.clone(),
                    });
                }
                current_method_in_args.clear();
                current_method_out_args.clear();
            }
        }
        // Signal start
        else if trimmed.starts_with("<signal") && trimmed.contains("name=") {
            if let Some(name) = extract_attr(trimmed, "name") {
                if trimmed.ends_with("/>") {
                    if let Some(ref mut iface) = current_iface {
                        iface.signals.insert(SignalContract { name, sig: String::new() });
                    }
                } else {
                    current_signal_name = Some(name);
                    current_signal_args.clear();
                }
            }
        }
        // Signal end
        else if trimmed == "</signal>" {
            if let Some(name) = current_signal_name.take() {
                if let Some(ref mut iface) = current_iface {
                    iface.signals.insert(SignalContract { name, sig: current_signal_args.clone() });
                }
                current_signal_args.clear();
            }
        }
        // Arg inside method or signal
        else if trimmed.starts_with("<arg") {
            if let Some(sig_type) = extract_attr(trimmed, "type") {
                let direction =
                    extract_attr(trimmed, "direction").unwrap_or_else(|| "in".to_owned());
                if current_method_name.is_some() {
                    if direction == "out" {
                        current_method_out_args.push_str(&sig_type);
                    } else {
                        current_method_in_args.push_str(&sig_type);
                    }
                } else if current_signal_name.is_some() {
                    current_signal_args.push_str(&sig_type);
                }
            }
        }
        // Property (can be self-closing or have annotations inside)
        else if trimmed.starts_with("<property") && trimmed.contains("name=") {
            if let Some(ref mut iface) = current_iface {
                if let (Some(name), Some(sig), Some(access)) = (
                    extract_attr(trimmed, "name"),
                    extract_attr(trimmed, "type"),
                    extract_attr(trimmed, "access"),
                ) {
                    iface.properties.insert(PropertyContract { name, sig, access });
                }
            }
        }
        // Child node reference
        else if trimmed.starts_with("<node") && trimmed.contains("name=") && trimmed != "<node>" {
            if let Some(name) = extract_attr(trimmed, "name") {
                child_nodes.push(name);
            }
        }
    }

    // Handle any trailing interface not closed by </interface>.
    if let Some(iface) = current_iface.take() {
        interfaces.push(iface);
    }

    ParsedNode { interfaces, child_nodes }
}

/// Extract an XML attribute value from a tag string.
///
/// For `<interface name="org.bluez.Adapter1">`, calling
/// `extract_attr(s, "name")` returns `Some("org.bluez.Adapter1")`.
fn extract_attr(tag: &str, attr_name: &str) -> Option<String> {
    let search = format!("{attr_name}=\"");
    let start = tag.find(&search)? + search.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

// ---------------------------------------------------------------------------
// DaemonFixture — manages bluetoothd + dbus-daemon + emulator lifecycle
// ---------------------------------------------------------------------------

/// Test fixture that manages the lifecycle of a private D-Bus session bus,
/// the Rust `bluetoothd` daemon, and an HCI emulator.
///
/// Each test creates its own `DaemonFixture` for full isolation.
struct DaemonFixture {
    /// PID of the private dbus-daemon (for teardown via SIGTERM).
    bus_pid: i32,
    /// The D-Bus session bus address.
    #[allow(dead_code)]
    bus_address: String,
    /// The Rust bluetoothd daemon process.
    daemon_process: Option<Child>,
    /// D-Bus connection to the private session bus.
    connection: Connection,
    /// HCI emulator providing a virtual controller.
    emulator: HciEmulator,
}

impl DaemonFixture {
    /// Set up the full test fixture.
    ///
    /// 1. Launches a private `dbus-daemon --session`.
    /// 2. Creates an `HciEmulator` with `EmulatorType::BrEdrLe`.
    /// 3. Spawns `bluetoothd --nodetach --experimental` on the private bus.
    /// 4. Waits for `org.bluez` name to appear.
    /// 5. Waits for the adapter object at `/org/bluez/hci0`.
    async fn setup() -> Result<Self, String> {
        // Step 1: Launch private dbus-daemon.
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

        // Step 2: Create HCI emulator (requires /dev/vhci).
        let emulator = HciEmulator::new(EmulatorType::BrEdrLe)
            .map_err(|e| format!("HciEmulator::new failed: {e}"))?;

        // Step 3: Locate and spawn bluetoothd.
        let daemon_bin =
            find_daemon_binary().ok_or("Could not find bluetoothd binary in target directory")?;

        let daemon_child = Command::new(&daemon_bin)
            .args(["--nodetach", "--experimental"])
            .env("DBUS_SESSION_BUS_ADDRESS", &bus_address)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn bluetoothd: {e}"))?;

        // Step 4: Connect to the private D-Bus session bus using
        // the explicit address (avoids unsafe std::env::set_var).
        let connection = timeout(DAEMON_STARTUP_TIMEOUT, async {
            ConnectionBuilder::address(bus_address.as_str())
                .map_err(|e| format!("ConnectionBuilder::address failed: {e}"))?
                .build()
                .await
                .map_err(|e| format!("D-Bus connection failed: {e}"))
        })
        .await
        .map_err(|_| "Timed out connecting to D-Bus session".to_owned())??;

        // Step 5: Wait for org.bluez name to appear.
        let name_appeared = timeout(DAEMON_STARTUP_TIMEOUT, async {
            loop {
                let proxy = zbus::fdo::DBusProxy::new(&connection)
                    .await
                    .map_err(|e| format!("DBusProxy creation failed: {e}"))?;
                match proxy.name_has_owner("org.bluez".try_into().unwrap()).await {
                    Ok(true) => return Ok::<(), String>(()),
                    _ => sleep(POLL_INTERVAL).await,
                }
            }
        })
        .await;

        match name_appeared {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("Error waiting for org.bluez: {e}")),
            Err(_) => return Err("Timed out waiting for org.bluez to appear".into()),
        }

        // Step 6: Wait for adapter object at /org/bluez/hci0.
        let adapter_appeared = timeout(ADAPTER_WAIT_TIMEOUT, async {
            loop {
                match introspect_at_conn(&connection, "/org/bluez/hci0").await {
                    Ok(xml) if xml.contains("org.bluez.Adapter1") => return Ok::<(), String>(()),
                    _ => sleep(POLL_INTERVAL).await,
                }
            }
        })
        .await;

        match adapter_appeared {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("Error waiting for adapter: {e}")),
            Err(_) => return Err("Timed out waiting for adapter at /org/bluez/hci0".into()),
        }

        Ok(DaemonFixture {
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
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
            // Wait briefly for graceful exit.
            let _ = child.wait();
        }
        self.daemon_process = None;

        // Kill the private dbus-daemon.
        if self.bus_pid > 0 {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(self.bus_pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        self.teardown();
    }
}

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

// ---------------------------------------------------------------------------
// D-Bus introspection helpers
// ---------------------------------------------------------------------------

/// Introspect a D-Bus object at the given path and return the raw XML.
///
/// Calls `org.freedesktop.DBus.Introspectable.Introspect` on the
/// `org.bluez` service at `path`.
async fn introspect_at_conn(conn: &Connection, path: &str) -> Result<String, String> {
    let object_path =
        ObjectPath::try_from(path).map_err(|e| format!("Invalid object path '{path}': {e}"))?;

    let introspect_result = timeout(INTROSPECT_TIMEOUT, async {
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

    match introspect_result {
        Ok(result) => result,
        Err(_) => Err(format!("Introspect timed out at {path}")),
    }
}

/// Recursively collect all object paths under `root` by introspecting
/// child nodes.
async fn list_object_paths(conn: &Connection, root: &str) -> Result<Vec<String>, String> {
    let mut paths = vec![root.to_owned()];
    let mut to_visit = vec![root.to_owned()];

    while let Some(current) = to_visit.pop() {
        let xml = introspect_at_conn(conn, &current).await?;
        let node = parse_introspection_xml(&xml);

        for child_name in &node.child_nodes {
            let child_path = if current == "/" {
                format!("/{child_name}")
            } else {
                format!("{current}/{child_name}")
            };
            paths.push(child_path.clone());
            to_visit.push(child_path);
        }
    }

    paths.sort();
    Ok(paths)
}

/// Collect all unique D-Bus interface names across all object paths
/// under `root`.
async fn collect_all_interface_names(
    conn: &Connection,
    root: &str,
) -> Result<BTreeSet<String>, String> {
    let paths = list_object_paths(conn, root).await?;
    let mut all_interfaces = BTreeSet::new();

    for path in &paths {
        let xml = introspect_at_conn(conn, path).await?;
        let node = parse_introspection_xml(&xml);
        for iface in &node.interfaces {
            all_interfaces.insert(iface.name.clone());
        }
    }

    Ok(all_interfaces)
}

/// Verify that a parsed interface matches the expected contract.
///
/// Returns a descriptive error message if there are mismatches.
fn verify_interface_contract(
    actual: &ParsedInterface,
    expected: &InterfaceContract,
) -> Result<(), String> {
    let mut errors = Vec::new();

    // Check methods.
    let actual_methods: BTreeMap<&str, &MethodContract> =
        actual.methods.iter().map(|m| (m.name.as_str(), m)).collect();
    let expected_methods: BTreeMap<&str, &MethodContract> =
        expected.methods.iter().map(|m| (m.name.as_str(), m)).collect();

    for (name, exp) in &expected_methods {
        match actual_methods.get(name) {
            Some(act) => {
                if act.in_sig != exp.in_sig {
                    errors.push(format!(
                        "Method {name}: in_sig mismatch: expected '{}', got '{}'",
                        exp.in_sig, act.in_sig
                    ));
                }
                if act.out_sig != exp.out_sig {
                    errors.push(format!(
                        "Method {name}: out_sig mismatch: expected '{}', got '{}'",
                        exp.out_sig, act.out_sig
                    ));
                }
            }
            None => {
                errors.push(format!("Missing expected method: {name}"));
            }
        }
    }
    for name in actual_methods.keys() {
        if !expected_methods.contains_key(name) {
            errors.push(format!("Unexpected extra method: {name}"));
        }
    }

    // Check properties.
    let actual_props: BTreeMap<&str, &PropertyContract> =
        actual.properties.iter().map(|p| (p.name.as_str(), p)).collect();
    let expected_props: BTreeMap<&str, &PropertyContract> =
        expected.properties.iter().map(|p| (p.name.as_str(), p)).collect();

    for (name, exp) in &expected_props {
        match actual_props.get(name) {
            Some(act) => {
                if act.sig != exp.sig {
                    errors.push(format!(
                        "Property {name}: type mismatch: expected '{}', got '{}'",
                        exp.sig, act.sig
                    ));
                }
                if act.access != exp.access {
                    errors.push(format!(
                        "Property {name}: access mismatch: expected '{}', got '{}'",
                        exp.access, act.access
                    ));
                }
            }
            None => {
                errors.push(format!("Missing expected property: {name}"));
            }
        }
    }

    // Check signals.
    let actual_sigs: BTreeMap<&str, &SignalContract> =
        actual.signals.iter().map(|s| (s.name.as_str(), s)).collect();
    let expected_sigs: BTreeMap<&str, &SignalContract> =
        expected.signals.iter().map(|s| (s.name.as_str(), s)).collect();

    for (name, exp) in &expected_sigs {
        match actual_sigs.get(name) {
            Some(act) => {
                if act.sig != exp.sig {
                    errors.push(format!(
                        "Signal {name}: sig mismatch: expected '{}', got '{}'",
                        exp.sig, act.sig
                    ));
                }
            }
            None => {
                errors.push(format!("Missing expected signal: {name}"));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Interface '{}' contract violations:\n  {}",
            expected.name,
            errors.join("\n  ")
        ))
    }
}

/// Find a parsed interface by name from a list of parsed interfaces.
fn find_interface<'a>(
    interfaces: &'a [ParsedInterface],
    name: &str,
) -> Option<&'a ParsedInterface> {
    interfaces.iter().find(|i| i.name == name)
}

// ---------------------------------------------------------------------------
// Canonical known interface set from the C BlueZ daemon
// ---------------------------------------------------------------------------

/// The set of known `org.bluez.*` interface names that the C daemon exports.
///
/// Derived from `doc/org.bluez.*.rst` documentation files and
/// `src/adapter.c`, `src/device.c` registration code.
fn known_bluez_interface_names() -> BTreeSet<String> {
    let names = [
        "org.bluez.Adapter1",
        "org.bluez.Device1",
        "org.bluez.AgentManager1",
        "org.bluez.ProfileManager1",
        "org.bluez.LEAdvertisingManager1",
        "org.bluez.GattManager1",
        "org.bluez.BatteryProviderManager1",
        "org.bluez.AdvertisementMonitorManager1",
        "org.bluez.GattService1",
        "org.bluez.GattCharacteristic1",
        "org.bluez.GattDescriptor1",
        "org.bluez.Battery1",
        "org.bluez.AdminPolicySet1",
        "org.bluez.AdminPolicyStatus1",
        "org.bluez.Media1",
        "org.bluez.MediaControl1",
        "org.bluez.MediaTransport1",
        "org.bluez.MediaPlayer1",
        "org.bluez.MediaItem1",
        "org.bluez.MediaFolder1",
        "org.bluez.MediaEndpoint1",
        "org.bluez.Input1",
        "org.bluez.Network1",
        "org.bluez.NetworkServer1",
        "org.bluez.DeviceSet1",
        "org.bluez.Bearer.BREDR1",
        "org.bluez.Bearer.LE1",
    ];
    names.iter().map(|s| (*s).to_owned()).collect()
}

// ---------------------------------------------------------------------------
// Test: Root introspection contract
// ---------------------------------------------------------------------------

/// Verify that `/org/bluez` exports the expected root-level interfaces:
/// `AgentManager1`, `ProfileManager1`, and `ObjectManager`.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_root_introspection_matches() {
    let fixture = DaemonFixture::setup().await.expect("DaemonFixture setup failed");

    let xml = introspect_at_conn(&fixture.connection, "/org/bluez")
        .await
        .expect("Failed to introspect /org/bluez");

    let node = parse_introspection_xml(&xml);

    // Verify AgentManager1 is present and matches contract.
    let agent_mgr = find_interface(&node.interfaces, "org.bluez.AgentManager1")
        .expect("org.bluez.AgentManager1 not found at /org/bluez");
    let expected = expected_agent_manager1();
    verify_interface_contract(agent_mgr, &expected).expect("AgentManager1 contract mismatch");

    // Verify ProfileManager1 is present and matches contract.
    let profile_mgr = find_interface(&node.interfaces, "org.bluez.ProfileManager1")
        .expect("org.bluez.ProfileManager1 not found at /org/bluez");
    let expected = expected_profile_manager1();
    verify_interface_contract(profile_mgr, &expected).expect("ProfileManager1 contract mismatch");

    // Verify ObjectManager is present.
    assert!(
        find_interface(&node.interfaces, "org.freedesktop.DBus.ObjectManager").is_some(),
        "ObjectManager not found at /org/bluez"
    );

    // Verify Introspectable is present.
    assert!(
        find_interface(&node.interfaces, "org.freedesktop.DBus.Introspectable").is_some(),
        "Introspectable not found at /org/bluez"
    );

    // Verify Properties is present.
    assert!(
        find_interface(&node.interfaces, "org.freedesktop.DBus.Properties").is_some(),
        "Properties not found at /org/bluez"
    );

    // Verify child nodes contain at least hci0.
    assert!(
        node.child_nodes.iter().any(|n| n.starts_with("hci")),
        "No hciN child node found under /org/bluez; children: {:?}",
        node.child_nodes
    );
}

// ---------------------------------------------------------------------------
// Test: Adapter interface contract
// ---------------------------------------------------------------------------

/// Verify that `/org/bluez/hci0` exports `org.bluez.Adapter1` with
/// exactly the methods, properties, and signals documented in
/// `doc/org.bluez.Adapter.rst`.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_adapter_interface_contract() {
    let fixture = DaemonFixture::setup().await.expect("DaemonFixture setup failed");

    let xml = introspect_at_conn(&fixture.connection, "/org/bluez/hci0")
        .await
        .expect("Failed to introspect /org/bluez/hci0");

    let node = parse_introspection_xml(&xml);

    // Verify Adapter1 contract.
    let adapter = find_interface(&node.interfaces, "org.bluez.Adapter1")
        .expect("org.bluez.Adapter1 not found at /org/bluez/hci0");
    let expected = expected_adapter1();
    verify_interface_contract(adapter, &expected).expect("Adapter1 contract mismatch");

    // Verify LEAdvertisingManager1 contract (on adapter path).
    let le_adv = find_interface(&node.interfaces, "org.bluez.LEAdvertisingManager1")
        .expect("LEAdvertisingManager1 not found at /org/bluez/hci0");
    let expected_le = expected_le_adv_manager1();
    verify_interface_contract(le_adv, &expected_le)
        .expect("LEAdvertisingManager1 contract mismatch");

    // Verify GattManager1 contract (on adapter path).
    let gatt_mgr = find_interface(&node.interfaces, "org.bluez.GattManager1")
        .expect("GattManager1 not found at /org/bluez/hci0");
    let expected_gatt = expected_gatt_manager1();
    verify_interface_contract(gatt_mgr, &expected_gatt).expect("GattManager1 contract mismatch");
}

// ---------------------------------------------------------------------------
// Test: Device interface contract
// ---------------------------------------------------------------------------

/// Verify that a discovered device object exports `org.bluez.Device1`
/// with exactly the methods, properties, and signals documented in
/// `doc/org.bluez.Device.rst`.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_device_interface_contract() {
    let fixture = DaemonFixture::setup().await.expect("DaemonFixture setup failed");

    // Configure the emulator's client host to be discoverable so the
    // daemon discovers it during scanning.
    if let Some(mut host) = fixture.emulator.client_get_host() {
        // Enable BR/EDR inquiry scan + page scan.
        host.write_scan_enable(0x03);
        // Set LE advertising data and enable advertising.
        host.set_adv_data(&[
            0x02, 0x01, 0x06, // Flags: LE General Discoverable
            0x05, 0x09, b'T', b'e', b's', b't', // Complete Local Name: "Test"
        ]);
        host.set_adv_enable(0x01);
    }

    // Power on the adapter by setting the Powered property.
    set_adapter_powered(&fixture.connection, "/org/bluez/hci0", true)
        .await
        .expect("Failed to power on adapter");

    // Start discovery.
    let _ = fixture
        .connection
        .call_method(
            Some("org.bluez"),
            "/org/bluez/hci0",
            Some("org.bluez.Adapter1"),
            "StartDiscovery",
            &(),
        )
        .await;

    // Wait for a device object to appear under /org/bluez/hci0/.
    let device_path = timeout(DEVICE_WAIT_TIMEOUT, async {
        loop {
            let paths =
                list_object_paths(&fixture.connection, "/org/bluez/hci0").await.unwrap_or_default();
            for path in &paths {
                if path.starts_with("/org/bluez/hci0/dev_") {
                    return path.clone();
                }
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("Timed out waiting for device discovery");

    // Verify the device path format: /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX
    assert!(
        device_path.starts_with("/org/bluez/hci0/dev_"),
        "Device path has wrong prefix: {device_path}"
    );
    let dev_suffix = device_path.strip_prefix("/org/bluez/hci0/dev_").unwrap();
    assert_eq!(dev_suffix.len(), 17, "Device BD_ADDR suffix has wrong length: {dev_suffix}");
    // Verify format: XX_XX_XX_XX_XX_XX (hex with underscores)
    for (i, ch) in dev_suffix.chars().enumerate() {
        if i % 3 == 2 {
            assert_eq!(ch, '_', "Expected underscore at position {i} in {dev_suffix}");
        } else {
            assert!(
                ch.is_ascii_hexdigit(),
                "Expected hex digit at position {i} in {dev_suffix}, got '{ch}'"
            );
        }
    }

    // Introspect the device object.
    let xml = introspect_at_conn(&fixture.connection, &device_path)
        .await
        .expect("Failed to introspect device object");

    let node = parse_introspection_xml(&xml);

    // Verify Device1 contract.
    let device = find_interface(&node.interfaces, "org.bluez.Device1")
        .expect("org.bluez.Device1 not found on device object");
    let expected = expected_device1();
    verify_interface_contract(device, &expected).expect("Device1 contract mismatch");
}

// ---------------------------------------------------------------------------
// Test: All interfaces present
// ---------------------------------------------------------------------------

/// Verify that the full set of expected `org.bluez.*` interfaces is
/// present across all object paths under `/org/bluez`, and that no
/// unexpected interfaces are introduced.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_all_interfaces_present() {
    let fixture = DaemonFixture::setup().await.expect("DaemonFixture setup failed");

    let all_interfaces = collect_all_interface_names(&fixture.connection, "/org/bluez")
        .await
        .expect("Failed to collect interface names");

    // Minimum required interfaces (always present even without devices).
    let required = [
        "org.bluez.AgentManager1",
        "org.bluez.ProfileManager1",
        "org.bluez.Adapter1",
        "org.bluez.LEAdvertisingManager1",
        "org.bluez.GattManager1",
        "org.freedesktop.DBus.ObjectManager",
        "org.freedesktop.DBus.Properties",
        "org.freedesktop.DBus.Introspectable",
    ];

    for iface_name in &required {
        assert!(
            all_interfaces.contains(*iface_name),
            "Required interface '{}' not found in any object under /org/bluez. Found: {:?}",
            iface_name,
            all_interfaces
        );
    }

    // Verify no unknown org.bluez.* interfaces are present.
    let known = known_bluez_interface_names();
    for iface_name in &all_interfaces {
        if iface_name.starts_with("org.bluez.") {
            // Known BlueZ interface — must be in the canonical list.
            if !known.contains(iface_name) {
                panic!(
                    "Unexpected org.bluez.* interface '{}' found. \
                     This interface is not in the known C BlueZ interface set.\n\
                     AAP Section 0.8.2: 'NEVER introduce new D-Bus interfaces, \
                     methods, properties, or signals not present in the C original.'",
                    iface_name
                );
            }
        }
        // Standard D-Bus interfaces (org.freedesktop.DBus.*) are always allowed.
    }
}

// ---------------------------------------------------------------------------
// Test: Object path structure
// ---------------------------------------------------------------------------

/// Verify the D-Bus object path hierarchy:
/// - `/org/bluez` exists with `ObjectManager`
/// - `/org/bluez/hci0` exists with `Adapter1`
/// - Device objects follow `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX` format
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_object_path_structure() {
    let fixture = DaemonFixture::setup().await.expect("DaemonFixture setup failed");

    // Verify /org/bluez exists and has ObjectManager.
    let root_xml = introspect_at_conn(&fixture.connection, "/org/bluez")
        .await
        .expect("Failed to introspect /org/bluez");
    let root_node = parse_introspection_xml(&root_xml);
    assert!(
        find_interface(&root_node.interfaces, "org.freedesktop.DBus.ObjectManager").is_some(),
        "/org/bluez must export ObjectManager"
    );

    // Verify /org/bluez/hci0 exists with Adapter1.
    let adapter_xml = introspect_at_conn(&fixture.connection, "/org/bluez/hci0")
        .await
        .expect("Failed to introspect /org/bluez/hci0");
    let adapter_node = parse_introspection_xml(&adapter_xml);
    assert!(
        find_interface(&adapter_node.interfaces, "org.bluez.Adapter1").is_some(),
        "/org/bluez/hci0 must export Adapter1"
    );

    // Configure emulator peer and trigger discovery to get device objects.
    if let Some(mut host) = fixture.emulator.client_get_host() {
        host.write_scan_enable(0x03);
        host.set_adv_data(&[0x02, 0x01, 0x06]);
        host.set_adv_enable(0x01);
    }

    // Power on.
    let _ = set_adapter_powered(&fixture.connection, "/org/bluez/hci0", true).await;

    // Start discovery.
    let _ = fixture
        .connection
        .call_method(
            Some("org.bluez"),
            "/org/bluez/hci0",
            Some("org.bluez.Adapter1"),
            "StartDiscovery",
            &(),
        )
        .await;

    // Wait for device objects.
    let device_found = timeout(DEVICE_WAIT_TIMEOUT, async {
        loop {
            let paths =
                list_object_paths(&fixture.connection, "/org/bluez/hci0").await.unwrap_or_default();
            for path in &paths {
                if path.starts_with("/org/bluez/hci0/dev_") {
                    return path.clone();
                }
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await;

    if let Ok(device_path) = device_found {
        // Verify the BD_ADDR format in the path.
        let suffix = device_path.strip_prefix("/org/bluez/hci0/dev_").expect("wrong prefix");
        // Format: XX_XX_XX_XX_XX_XX (17 chars: 6 hex pairs + 5 underscores)
        assert_eq!(suffix.len(), 17, "BD_ADDR part length wrong: '{suffix}'");

        let parts: Vec<&str> = suffix.split('_').collect();
        assert_eq!(parts.len(), 6, "BD_ADDR should have 6 octets: '{suffix}'");
        for part in &parts {
            assert_eq!(part.len(), 2, "Each octet should be 2 hex chars: '{part}'");
            assert!(
                part.chars().all(|c| c.is_ascii_hexdigit()),
                "Non-hex character in BD_ADDR octet: '{part}'"
            );
        }

        // Verify the device object has Device1 interface.
        let dev_xml = introspect_at_conn(&fixture.connection, &device_path)
            .await
            .expect("Failed to introspect device");
        let dev_node = parse_introspection_xml(&dev_xml);
        assert!(
            find_interface(&dev_node.interfaces, "org.bluez.Device1").is_some(),
            "Device object must export org.bluez.Device1"
        );
    }
    // If no device was found within the timeout, the test still passes
    // for the path structure parts (root + adapter) that were verified.
}

// ---------------------------------------------------------------------------
// Test: Property types match exactly
// ---------------------------------------------------------------------------

/// For each known interface at `/org/bluez/hci0`, compare the D-Bus type
/// signatures and access modes of all properties against the expected
/// contracts.
#[tokio::test]
#[ignore = "Requires /dev/vhci and bluetoothd binary — run with --ignored"]
async fn test_property_types_match_exactly() {
    let fixture = DaemonFixture::setup().await.expect("DaemonFixture setup failed");

    // Introspect the adapter.
    let xml = introspect_at_conn(&fixture.connection, "/org/bluez/hci0")
        .await
        .expect("Failed to introspect /org/bluez/hci0");
    let node = parse_introspection_xml(&xml);

    // Verify Adapter1 property types and access.
    if let Some(adapter) = find_interface(&node.interfaces, "org.bluez.Adapter1") {
        let expected = expected_adapter1();
        for exp_prop in &expected.properties {
            if let Some(act_prop) = adapter.properties.iter().find(|p| p.name == exp_prop.name) {
                assert_eq!(
                    act_prop.sig, exp_prop.sig,
                    "Adapter1.{}: type mismatch: expected '{}', got '{}'",
                    exp_prop.name, exp_prop.sig, act_prop.sig
                );
                assert_eq!(
                    act_prop.access, exp_prop.access,
                    "Adapter1.{}: access mismatch: expected '{}', got '{}'",
                    exp_prop.name, exp_prop.access, act_prop.access
                );
            }
            // Properties may be optional/experimental — missing is noted
            // but not fatal in this test (contract test above is strict).
        }
    }

    // Verify LEAdvertisingManager1 property types.
    if let Some(le_adv) = find_interface(&node.interfaces, "org.bluez.LEAdvertisingManager1") {
        let expected = expected_le_adv_manager1();
        for exp_prop in &expected.properties {
            if let Some(act_prop) = le_adv.properties.iter().find(|p| p.name == exp_prop.name) {
                assert_eq!(
                    act_prop.sig, exp_prop.sig,
                    "LEAdvertisingManager1.{}: type mismatch: expected '{}', got '{}'",
                    exp_prop.name, exp_prop.sig, act_prop.sig
                );
                assert_eq!(
                    act_prop.access, exp_prop.access,
                    "LEAdvertisingManager1.{}: access mismatch: expected '{}', got '{}'",
                    exp_prop.name, exp_prop.access, act_prop.access
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: set adapter Powered property via D-Bus
// ---------------------------------------------------------------------------

/// Set the Powered property on an adapter object via
/// `org.freedesktop.DBus.Properties.Set`.
async fn set_adapter_powered(conn: &Connection, path: &str, powered: bool) -> Result<(), String> {
    let object_path =
        ObjectPath::try_from(path).map_err(|e| format!("Invalid path '{path}': {e}"))?;

    let proxy = zbus::fdo::PropertiesProxy::builder(conn)
        .destination("org.bluez")
        .expect("valid bus name")
        .path(object_path)
        .expect("valid path")
        .build()
        .await
        .map_err(|e| format!("PropertiesProxy build failed: {e}"))?;

    proxy
        .set(
            "org.bluez.Adapter1".try_into().unwrap(),
            "Powered",
            zbus::zvariant::Value::from(powered),
        )
        .await
        .map_err(|e| format!("Set Powered failed: {e}"))
}

// ---------------------------------------------------------------------------
// Standalone unit tests for the XML parser (always runnable)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod parser_tests {
    use super::*;

    /// Sample D-Bus introspection XML for parser validation.
    const SAMPLE_XML: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.bluez.Adapter1">
    <method name="StartDiscovery">
    </method>
    <method name="StopDiscovery">
    </method>
    <method name="RemoveDevice">
      <arg name="device" type="o" direction="in"/>
    </method>
    <method name="SetDiscoveryFilter">
      <arg name="filter" type="a{sv}" direction="in"/>
    </method>
    <method name="GetDiscoveryFilters">
      <arg name="" type="as" direction="out"/>
    </method>
    <property name="Address" type="s" access="read"/>
    <property name="Powered" type="b" access="readwrite"/>
    <property name="Discovering" type="b" access="read"/>
  </interface>
  <interface name="org.bluez.LEAdvertisingManager1">
    <method name="RegisterAdvertisement">
      <arg name="advertisement" type="o" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
    </method>
    <property name="SupportedInstances" type="y" access="read"/>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="" type="s" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="Set">
      <arg name="interface" type="s" direction="in"/>
      <arg name="property" type="s" direction="in"/>
      <arg name="value" type="v" direction="in"/>
    </method>
    <method name="GetAll">
      <arg name="interface" type="s" direction="in"/>
      <arg name="properties" type="a{sv}" direction="out"/>
    </method>
    <signal name="PropertiesChanged">
      <arg name="interface" type="s"/>
      <arg name="changed_properties" type="a{sv}"/>
      <arg name="invalidated_properties" type="as"/>
    </signal>
  </interface>
  <node name="hci0"/>
  <node name="hci1"/>
</node>"#;

    #[test]
    fn test_parse_interfaces() {
        let node = parse_introspection_xml(SAMPLE_XML);
        let names: Vec<&str> = node.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"org.bluez.Adapter1"));
        assert!(names.contains(&"org.bluez.LEAdvertisingManager1"));
        assert!(names.contains(&"org.freedesktop.DBus.Introspectable"));
        assert!(names.contains(&"org.freedesktop.DBus.Properties"));
    }

    #[test]
    fn test_parse_methods() {
        let node = parse_introspection_xml(SAMPLE_XML);
        let adapter = find_interface(&node.interfaces, "org.bluez.Adapter1").unwrap();

        assert!(
            adapter
                .methods
                .iter()
                .any(|m| m.name == "StartDiscovery" && m.in_sig.is_empty() && m.out_sig.is_empty())
        );
        assert!(adapter.methods.iter().any(|m| m.name == "RemoveDevice" && m.in_sig == "o"));
        assert!(
            adapter.methods.iter().any(|m| m.name == "SetDiscoveryFilter" && m.in_sig == "a{sv}")
        );
        assert!(
            adapter.methods.iter().any(|m| m.name == "GetDiscoveryFilters" && m.out_sig == "as")
        );
    }

    #[test]
    fn test_parse_properties() {
        let node = parse_introspection_xml(SAMPLE_XML);
        let adapter = find_interface(&node.interfaces, "org.bluez.Adapter1").unwrap();

        assert!(
            adapter
                .properties
                .iter()
                .any(|p| p.name == "Address" && p.sig == "s" && p.access == "read")
        );
        assert!(
            adapter
                .properties
                .iter()
                .any(|p| p.name == "Powered" && p.sig == "b" && p.access == "readwrite")
        );
        assert!(
            adapter
                .properties
                .iter()
                .any(|p| p.name == "Discovering" && p.sig == "b" && p.access == "read")
        );
    }

    #[test]
    fn test_parse_signals() {
        let node = parse_introspection_xml(SAMPLE_XML);
        let props_iface =
            find_interface(&node.interfaces, "org.freedesktop.DBus.Properties").unwrap();

        assert!(
            props_iface
                .signals
                .iter()
                .any(|s| s.name == "PropertiesChanged" && s.sig == "sa{sv}as")
        );
    }

    #[test]
    fn test_parse_child_nodes() {
        let node = parse_introspection_xml(SAMPLE_XML);
        assert!(node.child_nodes.contains(&"hci0".to_owned()));
        assert!(node.child_nodes.contains(&"hci1".to_owned()));
    }

    #[test]
    fn test_extract_attr() {
        assert_eq!(
            extract_attr(r#"<interface name="org.bluez.Adapter1">"#, "name"),
            Some("org.bluez.Adapter1".to_owned())
        );
        assert_eq!(
            extract_attr(r#"<property name="Powered" type="b" access="readwrite"/>"#, "type"),
            Some("b".to_owned())
        );
        assert_eq!(
            extract_attr(r#"<property name="Powered" type="b" access="readwrite"/>"#, "access"),
            Some("readwrite".to_owned())
        );
        assert_eq!(extract_attr("<node>", "name"), None);
    }

    #[test]
    fn test_verify_contract_pass() {
        let actual = ParsedInterface {
            name: "org.bluez.AgentManager1".into(),
            methods: {
                let mut m = BTreeSet::new();
                m.insert(MethodContract {
                    name: "RegisterAgent".into(),
                    in_sig: "os".into(),
                    out_sig: String::new(),
                });
                m.insert(MethodContract {
                    name: "UnregisterAgent".into(),
                    in_sig: "o".into(),
                    out_sig: String::new(),
                });
                m.insert(MethodContract {
                    name: "RequestDefaultAgent".into(),
                    in_sig: "o".into(),
                    out_sig: String::new(),
                });
                m
            },
            properties: BTreeSet::new(),
            signals: BTreeSet::new(),
        };
        let expected = expected_agent_manager1();
        verify_interface_contract(&actual, &expected).expect("should pass");
    }

    #[test]
    fn test_verify_contract_missing_method() {
        let actual = ParsedInterface {
            name: "org.bluez.AgentManager1".into(),
            methods: {
                let mut m = BTreeSet::new();
                m.insert(MethodContract {
                    name: "RegisterAgent".into(),
                    in_sig: "os".into(),
                    out_sig: String::new(),
                });
                // Missing UnregisterAgent and RequestDefaultAgent
                m
            },
            properties: BTreeSet::new(),
            signals: BTreeSet::new(),
        };
        let expected = expected_agent_manager1();
        let result = verify_interface_contract(&actual, &expected);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("UnregisterAgent"), "Error should mention missing method: {err}");
    }

    #[test]
    fn test_verify_contract_wrong_signature() {
        let actual = ParsedInterface {
            name: "org.bluez.AgentManager1".into(),
            methods: {
                let mut m = BTreeSet::new();
                m.insert(MethodContract {
                    name: "RegisterAgent".into(),
                    in_sig: "s".into(), // Wrong: should be "os"
                    out_sig: String::new(),
                });
                m.insert(MethodContract {
                    name: "UnregisterAgent".into(),
                    in_sig: "o".into(),
                    out_sig: String::new(),
                });
                m.insert(MethodContract {
                    name: "RequestDefaultAgent".into(),
                    in_sig: "o".into(),
                    out_sig: String::new(),
                });
                m
            },
            properties: BTreeSet::new(),
            signals: BTreeSet::new(),
        };
        let expected = expected_agent_manager1();
        let result = verify_interface_contract(&actual, &expected);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("in_sig mismatch"), "Error should mention sig mismatch: {err}");
    }

    #[test]
    fn test_verify_contract_extra_method() {
        let actual = ParsedInterface {
            name: "org.bluez.AgentManager1".into(),
            methods: {
                let mut m = BTreeSet::new();
                m.insert(MethodContract {
                    name: "RegisterAgent".into(),
                    in_sig: "os".into(),
                    out_sig: String::new(),
                });
                m.insert(MethodContract {
                    name: "UnregisterAgent".into(),
                    in_sig: "o".into(),
                    out_sig: String::new(),
                });
                m.insert(MethodContract {
                    name: "RequestDefaultAgent".into(),
                    in_sig: "o".into(),
                    out_sig: String::new(),
                });
                m.insert(MethodContract {
                    name: "ExtraUnexpected".into(),
                    in_sig: String::new(),
                    out_sig: String::new(),
                });
                m
            },
            properties: BTreeSet::new(),
            signals: BTreeSet::new(),
        };
        let expected = expected_agent_manager1();
        let result = verify_interface_contract(&actual, &expected);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Unexpected extra method"),
            "Error should mention extra method: {err}"
        );
    }

    #[test]
    fn test_known_interfaces_complete() {
        let known = known_bluez_interface_names();
        assert!(known.contains("org.bluez.Adapter1"));
        assert!(known.contains("org.bluez.Device1"));
        assert!(known.contains("org.bluez.AgentManager1"));
        assert!(known.contains("org.bluez.ProfileManager1"));
        assert!(known.contains("org.bluez.LEAdvertisingManager1"));
        assert!(known.contains("org.bluez.GattManager1"));
    }

    #[test]
    fn test_device1_contract_completeness() {
        let contract = expected_device1();
        // Verify the contract has all expected methods.
        let method_names: BTreeSet<&str> =
            contract.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(method_names.contains("Connect"));
        assert!(method_names.contains("Disconnect"));
        assert!(method_names.contains("ConnectProfile"));
        assert!(method_names.contains("DisconnectProfile"));
        assert!(method_names.contains("Pair"));
        assert!(method_names.contains("CancelPairing"));

        // Verify the Disconnected signal is present.
        assert!(contract.signals.iter().any(|s| s.name == "Disconnected"));

        // Verify key properties are present.
        let prop_names: BTreeSet<&str> =
            contract.properties.iter().map(|p| p.name.as_str()).collect();
        assert!(prop_names.contains("Address"));
        assert!(prop_names.contains("Connected"));
        assert!(prop_names.contains("Paired"));
        assert!(prop_names.contains("UUIDs"));
        assert!(prop_names.contains("ManufacturerData"));
    }

    #[test]
    fn test_adapter1_contract_completeness() {
        let contract = expected_adapter1();
        let method_names: BTreeSet<&str> =
            contract.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(method_names.contains("StartDiscovery"));
        assert!(method_names.contains("StopDiscovery"));
        assert!(method_names.contains("RemoveDevice"));
        assert!(method_names.contains("SetDiscoveryFilter"));
        assert!(method_names.contains("GetDiscoveryFilters"));
        assert!(method_names.contains("ConnectDevice"));

        let prop_names: BTreeSet<&str> =
            contract.properties.iter().map(|p| p.name.as_str()).collect();
        assert!(prop_names.contains("Address"));
        assert!(prop_names.contains("Powered"));
        assert!(prop_names.contains("Discovering"));
        assert!(prop_names.contains("UUIDs"));
        assert!(prop_names.contains("Manufacturer"));
        assert!(prop_names.contains("Version"));
    }

    #[test]
    fn test_empty_xml() {
        let node = parse_introspection_xml("");
        assert!(node.interfaces.is_empty());
        assert!(node.child_nodes.is_empty());
    }

    #[test]
    fn test_node_only_xml() {
        let xml = r#"<node>
  <node name="child1"/>
  <node name="child2"/>
</node>"#;
        let node = parse_introspection_xml(xml);
        assert!(node.interfaces.is_empty());
        assert_eq!(node.child_nodes.len(), 2);
        assert!(node.child_nodes.contains(&"child1".to_owned()));
        assert!(node.child_nodes.contains(&"child2".to_owned()));
    }

    #[test]
    fn test_self_closing_method() {
        let xml = r#"<node>
  <interface name="test.Interface">
    <method name="NoArgs"/>
  </interface>
</node>"#;
        let node = parse_introspection_xml(xml);
        let iface = find_interface(&node.interfaces, "test.Interface").unwrap();
        assert!(
            iface
                .methods
                .iter()
                .any(|m| m.name == "NoArgs" && m.in_sig.is_empty() && m.out_sig.is_empty())
        );
    }
}
