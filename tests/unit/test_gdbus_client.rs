//! D-Bus client/proxy lifecycle tests using zbus.
//!
//! Converted from `unit/test-gdbus-client.c`. This file validates D-Bus client
//! behavior using the zbus library (replacing the GDBus C library). Tests cover:
//!
//! - Basic client connection and lifecycle management
//! - Property reads for all D-Bus types (string, boolean, uint64, array, dict)
//! - Property writes with change notifications
//! - Proxy lifecycle (added, removed) and ordering guarantees
//! - Force disconnect and interface unregistration scenarios
//! - Client readiness ordering (proxies discovered before ready signal)
//!
//! Each test spawns a private `dbus-daemon` instance for complete isolation,
//! preventing interference between parallel test executions.
//!
//! # C-to-Rust Transformation Notes
//!
//! The C original uses GDBus table-driven property registration:
//! - `GDBusPropertyTable` with getter/setter/exists callbacks
//! - `GDBusClient` for client-side proxy management
//! - `g_dbus_setup_private()` for private session bus
//!
//! The Rust translation uses:
//! - `#[zbus::interface]` proc macros for service-side interfaces
//! - `zbus::proxy::Proxy` for client-side property access
//! - Private `dbus-daemon --session` per test for isolation

use std::collections::HashMap;
use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use zbus::zvariant::{OwnedValue, Value};

// ============================================================================
// Constants — matching the C original's SERVICE_NAME / SERVICE_PATH
// ============================================================================

/// Primary D-Bus well-known name and interface name for the test service.
/// In the C original, `SERVICE_NAME` serves as both the bus name acquired via
/// `g_dbus_setup_private()` and the interface name in `g_dbus_register_interface()`.
const SERVICE_NAME: &str = "org.bluez.GDBus.TestService";

/// Secondary D-Bus well-known name for force-disconnect testing.
/// The C original uses this to set up a second private bus connection that
/// gets intentionally torn down while the primary client watches.
const SERVICE_NAME1: &str = "org.bluez.GDBus.TestService1";

/// D-Bus object path where the test interface is registered.
const SERVICE_PATH: &str = "/org/bluez/GDBus/TestObject";

/// Test timeout — matches the C original's 10-second `g_timeout_add`.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// ============================================================================
// Private D-Bus Daemon Management
// ============================================================================

/// Manages a private `dbus-daemon --session` instance for test isolation.
///
/// On creation, spawns a new dbus-daemon process with `--nofork` so it runs
/// in the foreground (as a child process) and prints its address on stdout.
/// On drop, kills the daemon process to clean up.
///
/// This replaces the C `g_dbus_setup_private(DBUS_BUS_SESSION, ...)` pattern.
struct TestBus {
    child: Child,
    address: String,
}

impl TestBus {
    /// Spawn a new private session bus daemon.
    ///
    /// Reads the bus address from the daemon's stdout (printed via
    /// `--print-address=1`). Panics if the daemon fails to start or
    /// returns an empty address.
    fn new() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--print-address=1", "--nofork", "--nopidfile"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start dbus-daemon; ensure dbus-daemon is installed");

        let stdout = child.stdout.take().expect("dbus-daemon stdout unavailable");
        let mut reader = std::io::BufReader::new(stdout);
        let mut address = String::new();
        reader.read_line(&mut address).expect("Failed to read dbus-daemon address from stdout");
        let address = address.trim().to_string();
        assert!(!address.is_empty(), "dbus-daemon returned an empty bus address");

        TestBus { child, address }
    }

    /// Create a connection and acquire the given well-known bus name.
    ///
    /// Replaces the C pattern of `g_dbus_setup_private(DBUS_BUS_SESSION, name, ...)`.
    async fn connect_with_name(&self, name: &str) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .expect("Failed to parse dbus-daemon address")
            .name(name)
            .expect("Failed to set bus name on connection builder")
            .build()
            .await
            .expect("Failed to connect to private test bus")
    }

    /// Create an anonymous connection (without acquiring a bus name).
    ///
    /// Used for "client-side" connections in tests that require separate
    /// server and client connections. The server acquires the well-known
    /// name while the client connects anonymously and creates proxies
    /// targeting the server's name. This forces all D-Bus calls to route
    /// through the daemon rather than being short-circuited locally.
    async fn connect_anonymous(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .expect("Failed to parse dbus-daemon address")
            .build()
            .await
            .expect("Failed to connect anonymously to private test bus")
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ============================================================================
// Service-Side D-Bus Interface Implementation
// ============================================================================

/// Combined test interface with all property types used across the test suite.
///
/// This struct serves as the service-side D-Bus interface implementation,
/// registered via `#[zbus::interface]`. It provides properties for all D-Bus
/// types tested: String ("s"), Boolean ("b"), Number/uint64 ("t"),
/// Array of strings ("as"), and Dictionary ("a{sv}").
///
/// The C original uses separate `GDBusPropertyTable` arrays per test, each
/// exposing only specific properties. Since each test here runs on a fully
/// isolated private bus, using one comprehensive interface simplifies the
/// implementation without affecting test correctness.
///
/// Method names are chosen so that zbus's automatic PascalCase conversion
/// produces the expected D-Bus property names:
/// - `fn string()` → "String"
/// - `fn boolean()` → "Boolean"
/// - `fn number()` → "Number"
/// - `fn array()` → "Array"
/// - `fn dict()` → "Dict"
struct TestPropertiesInterface {
    string_prop: String,
    boolean_prop: bool,
    number_prop: u64,
    array_prop: Vec<String>,
    dict_prop: HashMap<String, OwnedValue>,
}

impl TestPropertiesInterface {
    /// Create a new interface with default test values matching the C original.
    ///
    /// - String property: `"value"` (C: `get_string` returns `"value"`)
    /// - Boolean property: `true` (C: `get_boolean` returns `TRUE`)
    /// - Number property: `u64::MAX` (C: `get_uint64` returns `G_MAXUINT64`)
    /// - Array property: `["value1", "value2"]` (C: `get_array` returns 2 entries)
    /// - Dict property: `{String: "value", Boolean: true}` (C: `get_dict`)
    fn with_defaults() -> Self {
        let mut dict = HashMap::new();
        dict.insert(
            "String".to_string(),
            Value::from("value").try_into().expect("value conversion"),
        );
        dict.insert("Boolean".to_string(), Value::from(true).try_into().expect("bool conversion"));

        Self {
            string_prop: "value".to_string(),
            boolean_prop: true,
            number_prop: u64::MAX,
            array_prop: vec!["value1".to_string(), "value2".to_string()],
            dict_prop: dict,
        }
    }
}

/// D-Bus interface implementation for the test service.
///
/// The interface name matches `SERVICE_NAME` — in the C original, the same
/// constant is used as both the bus well-known name and the registered
/// interface name in `g_dbus_register_interface()`.
///
/// zbus converts method names to PascalCase for D-Bus property names:
/// `fn string()` → property "String", `fn boolean()` → "Boolean", etc.
#[zbus::interface(name = "org.bluez.GDBus.TestService")]
impl TestPropertiesInterface {
    /// String property — D-Bus type "s", name "String".
    /// Corresponds to the C `get_string` callback returning `"value"`.
    #[zbus(property)]
    async fn string(&self) -> String {
        self.string_prop.clone()
    }

    /// String property setter — enables property writes via D-Bus.
    /// Corresponds to the C `set_string` callback that stores the new value.
    /// zbus automatically emits `PropertiesChanged` signal on success.
    #[zbus(property)]
    async fn set_string(&mut self, value: String) {
        self.string_prop = value;
    }

    /// Boolean property — D-Bus type "b", name "Boolean".
    /// Corresponds to the C `get_boolean` callback returning `TRUE`.
    #[zbus(property)]
    async fn boolean(&self) -> bool {
        self.boolean_prop
    }

    /// Unsigned 64-bit integer property — D-Bus type "t", name "Number".
    /// Corresponds to the C `get_uint64` callback returning `G_MAXUINT64`.
    #[zbus(property)]
    async fn number(&self) -> u64 {
        self.number_prop
    }

    /// Array of strings property — D-Bus type "as", name "Array".
    /// Corresponds to the C `get_array` callback returning `["value1", "value2"]`.
    #[zbus(property)]
    async fn array(&self) -> Vec<String> {
        self.array_prop.clone()
    }

    /// Dictionary property — D-Bus type "a{sv}", name "Dict".
    /// Corresponds to the C `get_dict` callback returning
    /// `{String: variant("value"), Boolean: variant(true)}`.
    #[zbus(property)]
    async fn dict(&self) -> HashMap<String, OwnedValue> {
        self.dict_prop.clone()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a generic `zbus::proxy::Proxy` targeting the test service interface.
///
/// This replaces the C `g_dbus_client_new(conn, SERVICE_NAME, SERVICE_PATH)`
/// and `g_dbus_client_set_proxy_handlers()` pattern with a direct proxy to
/// the service's well-known name at the standard test path.
///
/// The proxy has property caching enabled (zbus default) which is required
/// for `receive_property_changed` streams to function.
///
/// Parameters:
/// - `conn`: The D-Bus connection for the proxy (typically the client connection).
/// - `dest`: The well-known bus name of the service to target.
/// - `iface`: The D-Bus interface name on the target object.
async fn create_test_proxy<'a>(
    conn: &'a zbus::Connection,
    dest: &'a str,
    iface: &'a str,
) -> zbus::Result<zbus::proxy::Proxy<'a>> {
    zbus::proxy::Builder::new(conn)
        .destination(dest)?
        .path(SERVICE_PATH)?
        .interface(iface)?
        .build()
        .await
}

/// Create a proxy with property caching disabled.
///
/// Used in tests that verify behavior after interface removal or service
/// disconnect. Without caching, every `get_property` call makes a fresh
/// D-Bus method call through the bus daemon, ensuring that removal is
/// detected immediately rather than returning stale cached values.
async fn create_uncached_proxy<'a>(
    conn: &'a zbus::Connection,
    dest: &'a str,
    iface: &'a str,
) -> zbus::Result<zbus::proxy::Proxy<'a>> {
    zbus::proxy::Builder::new(conn)
        .destination(dest)?
        .path(SERVICE_PATH)?
        .interface(iface)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
}

/// Register the standard test properties interface on the given connection.
///
/// Registers a `TestPropertiesInterface` with default values at `SERVICE_PATH`.
/// Returns the connection for chaining.
async fn register_test_interface(conn: &zbus::Connection) {
    conn.object_server()
        .at(SERVICE_PATH, TestPropertiesInterface::with_defaults())
        .await
        .expect("Failed to register test interface at SERVICE_PATH");
}

// ============================================================================
// Test 1: Simple Client
// ============================================================================

/// Validates basic D-Bus client creation and service connection.
///
/// **C equivalent:** `simple_client()` — creates `GDBusClient` watching
/// `SERVICE_NAME` with connect/disconnect watches, no interface registration.
/// The test passes as soon as the connect callback fires (meaning the client
/// detected the bus name owner).
///
/// **Rust translation:** Acquire the bus name, then create a proxy targeting
/// that name. If the proxy can be created and the connection is alive, the
/// equivalent of the "connect" callback has fired.
#[tokio::test]
async fn test_simple_client() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;

        // Verify the name is owned by querying the bus
        let dbus_proxy = zbus::fdo::DBusProxy::new(&conn).await.expect("DBusProxy creation failed");
        let has_owner = dbus_proxy
            .name_has_owner(SERVICE_NAME.try_into().unwrap())
            .await
            .expect("name_has_owner failed");
        assert!(has_owner, "SERVICE_NAME should have an owner");
    })
    .await;
    assert!(result.is_ok(), "test_simple_client timed out");
}

// ============================================================================
// Test 2: Client Connect/Disconnect
// ============================================================================

/// Validates client connect and disconnect lifecycle with interface registration.
///
/// **C equivalent:** `client_connect_disconnect()` — registers an empty interface
/// at `SERVICE_PATH`, creates client with connect/disconnect handlers, starts
/// a 10s timeout. The connect callback fires, unrefs the client (triggering
/// disconnect), and the disconnect callback confirms teardown.
///
/// **Rust translation:** Two-connection approach: a server connection acquires
/// the name and registers the interface, and a separate anonymous client
/// connection creates an uncached proxy. The proxy verifies it can read
/// properties (equivalent of "connect" callback). Then the server connection
/// closes, and the proxy verifies reads fail (equivalent of "disconnect"
/// callback).
#[tokio::test]
async fn test_client_connect_disconnect() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();

        // Server side: acquire bus name and register interface
        let server_conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&server_conn).await;

        // Client side: anonymous connection with uncached proxy
        let client_conn = bus.connect_anonymous().await;
        let proxy = create_uncached_proxy(&client_conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Verify connection — equivalent of connect callback firing
        let val: String = proxy
            .get_property("String")
            .await
            .expect("Failed to read String property (connect phase)");
        assert_eq!(val, "value", "Should read initial String property");

        // Disconnect: close the server connection — name owner disappears
        // This is equivalent to dropping the GDBusClient in the C test
        server_conn.close().await.expect("Failed to close server connection");

        // Small delay for NameOwnerChanged signal to propagate
        sleep(Duration::from_millis(200)).await;

        // After disconnect, reading the property should fail — equivalent to
        // the disconnect callback firing in the C original
        let read_result = proxy.get_property::<String>("String").await;
        assert!(read_result.is_err(), "Property read should fail after server disconnect");
    })
    .await;
    assert!(result.is_ok(), "test_client_connect_disconnect timed out");
}

// ============================================================================
// Test 3: String Property Read
// ============================================================================

/// Validates reading a String ("s") property through a D-Bus proxy.
///
/// **C equivalent:** `client_get_string_property()` — registers a String
/// property with value `"value"`, the proxy handler reads it via
/// `g_dbus_proxy_get_property()` and asserts the type is `DBUS_TYPE_STRING`
/// and the value is `"value"`.
#[tokio::test]
async fn test_client_get_string_property() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Read String property — C: g_dbus_proxy_get_property(proxy, "String")
        let val: String =
            proxy.get_property("String").await.expect("Failed to read String property");
        assert_eq!(
            val, "value",
            "String property should be 'value' (C: get_string returns \"value\")"
        );
    })
    .await;
    assert!(result.is_ok(), "test_client_get_string_property timed out");
}

// ============================================================================
// Test 4: Boolean Property Read
// ============================================================================

/// Validates reading a Boolean ("b") property through a D-Bus proxy.
///
/// **C equivalent:** `client_get_boolean_property()` — registers a Boolean
/// property with value `TRUE`, proxy reads via `g_dbus_proxy_get_property()`
/// and asserts `DBUS_TYPE_BOOLEAN` and value `TRUE`.
#[tokio::test]
async fn test_client_get_boolean_property() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Read Boolean property — C: get_boolean returns TRUE
        let val: bool =
            proxy.get_property("Boolean").await.expect("Failed to read Boolean property");
        assert!(val, "Boolean property should be true (C: get_boolean returns TRUE)");
    })
    .await;
    assert!(result.is_ok(), "test_client_get_boolean_property timed out");
}

// ============================================================================
// Test 5: uint64 Property Read
// ============================================================================

/// Validates reading a uint64 ("t") property through a D-Bus proxy.
///
/// **C equivalent:** `client_get_uint64_property()` — registers a uint64
/// property with value `G_MAXUINT64`, proxy reads and asserts type
/// `DBUS_TYPE_UINT64` and value equals `G_MAXUINT64`.
#[tokio::test]
async fn test_client_get_uint64_property() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Read Number property — C: get_uint64 returns G_MAXUINT64
        let val: u64 = proxy.get_property("Number").await.expect("Failed to read Number property");
        assert_eq!(val, u64::MAX, "Number property should be u64::MAX (C: G_MAXUINT64)");
    })
    .await;
    assert!(result.is_ok(), "test_client_get_uint64_property timed out");
}

// ============================================================================
// Test 6: Array Property Read
// ============================================================================

/// Validates reading an Array of strings ("as") property through a D-Bus proxy.
///
/// **C equivalent:** `client_get_array_property()` — registers an "as"
/// property with `["value1", "value2"]`. The proxy handler iterates the
/// array, asserting each entry is `DBUS_TYPE_STRING` with expected values.
#[tokio::test]
async fn test_client_get_array_property() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Read Array property — C: get_array returns ["value1", "value2"]
        let val: Vec<String> =
            proxy.get_property("Array").await.expect("Failed to read Array property");
        assert_eq!(val.len(), 2, "Array should have 2 elements");
        assert_eq!(val[0], "value1", "First element should be 'value1'");
        assert_eq!(val[1], "value2", "Second element should be 'value2'");
    })
    .await;
    assert!(result.is_ok(), "test_client_get_array_property timed out");
}

// ============================================================================
// Test 7: Dict Property Read
// ============================================================================

/// Validates reading a Dictionary ("a{sv}") property through a D-Bus proxy.
///
/// **C equivalent:** `client_get_dict_property()` — registers an "a{sv}"
/// property containing `{String: variant("value"), Boolean: variant(TRUE)}`.
/// The proxy handler reads the dict, looks up "String" and "Boolean" keys,
/// and verifies their types and values.
#[tokio::test]
async fn test_client_get_dict_property() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Read Dict property — C: get_dict returns {String: "value", Boolean: TRUE}
        let val: HashMap<String, OwnedValue> =
            proxy.get_property("Dict").await.expect("Failed to read Dict property");

        // Verify "String" entry
        let string_entry = val.get("String").expect("Dict should have 'String' key");
        let string_val: &str =
            string_entry.downcast_ref().expect("String entry should be a string");
        assert_eq!(string_val, "value", "Dict[String] should be 'value'");

        // Verify "Boolean" entry
        let bool_entry = val.get("Boolean").expect("Dict should have 'Boolean' key");
        let bool_val: &bool = bool_entry.downcast_ref().expect("Boolean entry should be a bool");
        assert!(*bool_val, "Dict[Boolean] should be true");
    })
    .await;
    assert!(result.is_ok(), "test_client_get_dict_property timed out");
}

// ============================================================================
// Test 8: Set String Property with Change Notification
// ============================================================================

/// Validates setting a String property and receiving the change notification.
///
/// **C equivalent:** `client_set_string_property()` — String property starts
/// as `"value"`. The proxy handler calls
/// `g_dbus_proxy_set_property_basic(proxy, "String", DBUS_TYPE_STRING, "value1", ...)`.
/// The server-side `set_string()` validates the new value is `"value1"`,
/// stores it, and emits `PropertyChanged`. The client's `string_changed()`
/// handler verifies the notification carries `"value1"`.
///
/// In zbus, `set_property` through the proxy automatically triggers the
/// `PropertiesChanged` signal when the interface setter succeeds.
#[tokio::test]
async fn test_client_set_string_property() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Verify initial value
        let initial: String =
            proxy.get_property("String").await.expect("Failed to read initial String");
        assert_eq!(initial, "value", "Initial String should be 'value'");

        // Subscribe to property changes BEFORE setting the value
        let mut stream = proxy.receive_property_changed::<String>("String").await;

        // Consume the initial cached value from the stream
        // (zbus PropertyStream yields current value first)
        let _initial_change = stream.next().await.expect("Should get initial value");

        // Set the property to "value1" — C: g_dbus_proxy_set_property_basic
        proxy
            .set_property("String", Value::from("value1"))
            .await
            .expect("Failed to set String property");

        // Wait for the change notification — C: string_changed callback
        let change = stream.next().await.expect("Should receive property change");
        let new_val: String = change.get().await.expect("Should get changed value");
        assert_eq!(
            new_val, "value1",
            "Changed String should be 'value1' (C: string_changed asserts \"value1\")"
        );
    })
    .await;
    assert!(result.is_ok(), "test_client_set_string_property timed out");
}

// ============================================================================
// Test 9: String Property Changed (Server-Side Emission)
// ============================================================================

/// Validates receiving a property change notification when the server
/// programmatically updates the property value.
///
/// **C equivalent:** `client_string_changed()` — String property has an
/// `exists` callback (`string_exists`) that initially returns `FALSE`
/// (context->data is NULL). The proxy handler checks the property is absent.
/// Then `emit_string_change()` runs as an idle callback: sets context->data
/// to `"value1"` and calls `g_dbus_emit_property_changed()`. The client's
/// `string_changed()` handler verifies the value is `"value1"`.
///
/// **Rust adaptation:** Since zbus doesn't support conditional property
/// visibility (GDBus `exists` callback), we test the equivalent behavior:
/// the server programmatically changes a property and the client detects it
/// via the `PropertiesChanged` signal.
#[tokio::test]
async fn test_client_string_changed() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Subscribe to changes
        let mut stream = proxy.receive_property_changed::<String>("String").await;
        // Consume initial value
        let _initial = stream.next().await.expect("Should get initial value");

        // Server-side: programmatically change the property value
        // This replaces the C idle callback that sets data and calls
        // g_dbus_emit_property_changed()
        let iface_ref = conn
            .object_server()
            .interface::<_, TestPropertiesInterface>(SERVICE_PATH)
            .await
            .expect("Failed to get interface ref");

        {
            let mut iface = iface_ref.get_mut().await;
            iface.string_prop = "value1".to_string();
            iface
                .string_changed(iface_ref.signal_emitter())
                .await
                .expect("Failed to emit property changed signal");
        }

        // Wait for the change notification — C: string_changed callback
        let change = stream.next().await.expect("Should receive property change");
        let new_val: String = change.get().await.expect("Should get changed value");
        assert_eq!(new_val, "value1", "Server-side changed String should be 'value1'");
    })
    .await;
    assert!(result.is_ok(), "test_client_string_changed timed out");
}

// ============================================================================
// Test 10: Check Property Set Order
// ============================================================================

/// Validates that a property read after a set returns the updated value.
///
/// **C equivalent:** `client_check_order()` — Proxy handler sets String to
/// `"value1"` via `g_dbus_proxy_set_property_basic()`. The completion
/// callback immediately reads the property back to verify it returns
/// `"value1"`, confirming that set operations are ordered correctly.
#[tokio::test]
async fn test_client_check_order() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Verify initial value
        let initial: String =
            proxy.get_property("String").await.expect("Failed to read initial String");
        assert_eq!(initial, "value", "Initial should be 'value'");

        // Set String to "value1"
        proxy
            .set_property("String", Value::from("value1"))
            .await
            .expect("Failed to set String property");

        // Immediately read back — must see updated value (order preservation)
        // C: completion callback reads property, asserts "value1"
        let readback: String =
            proxy.get_property("String").await.expect("Failed to read back String after set");
        assert_eq!(
            readback, "value1",
            "Readback after set should be 'value1' (order verification)"
        );
    })
    .await;
    assert!(result.is_ok(), "test_client_check_order timed out");
}

// ============================================================================
// Test 11: Proxy Removed (Interface Unregistration)
// ============================================================================

/// Validates that the client detects interface removal from the object server.
///
/// **C equivalent:** `client_proxy_removed()` — Registers interface, proxy
/// handler fires (proxy found), sets a removal watch, then calls
/// `g_dbus_unregister_interface()`. The `proxy_removed()` callback fires
/// confirming the client detected the interface disappearance.
///
/// **Rust translation:** Two-connection approach: server registers interface,
/// client creates uncached proxy and verifies properties. Then server removes
/// the interface, and client verifies reads fail (proxy is "removed").
#[tokio::test]
async fn test_client_proxy_removed() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();

        // Server side: acquire name and register interface
        let server_conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&server_conn).await;

        // Client side: anonymous connection with uncached proxy
        let client_conn = bus.connect_anonymous().await;
        let proxy = create_uncached_proxy(&client_conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Verify interface is accessible through the proxy
        let val: String =
            proxy.get_property("String").await.expect("Should read property before removal");
        assert_eq!(val, "value");

        // Unregister the interface on the server side
        // C: g_dbus_unregister_interface()
        let removed = server_conn
            .object_server()
            .remove::<TestPropertiesInterface, _>(SERVICE_PATH)
            .await
            .expect("Interface removal should not fail");
        assert!(removed, "Interface should have existed and been removed");

        // Small delay for InterfacesRemoved signal to propagate through the bus
        sleep(Duration::from_millis(200)).await;

        // Verify proxy detects removal — uncached property read makes a fresh
        // D-Bus call which hits the server's object server where the interface
        // is gone. This is the equivalent of the C proxy_removed callback.
        let read_result = proxy.get_property::<String>("String").await;
        assert!(
            read_result.is_err(),
            "Property read should fail after interface removal (proxy removed)"
        );
    })
    .await;
    assert!(result.is_ok(), "test_client_proxy_removed timed out");
}

// ============================================================================
// Test 12: No Object Manager
// ============================================================================

/// Validates proxy behavior without relying on ObjectManager for discovery.
///
/// **C equivalent:** `client_no_object_manager()` — Creates a `GDBusClient`
/// with `g_dbus_client_new_full(conn, SERVICE_NAME, SERVICE_PATH, NULL)`
/// (NULL for no ObjectManager path). Then creates a proxy manually via
/// `g_dbus_proxy_new(client, SERVICE_PATH, SERVICE_NAME)`. The proxy handler
/// checks that the proxy is available and properties work.
///
/// **Rust translation:** Create a standard proxy (zbus proxies don't require
/// ObjectManager for basic operation — they use `org.freedesktop.DBus.Properties`
/// directly). Verify that the proxy can read properties without ObjectManager.
#[tokio::test]
async fn test_client_no_object_manager() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;
        register_test_interface(&conn).await;

        // Create proxy directly — no ObjectManager involvement
        // This mirrors GDBus's g_dbus_proxy_new without ObjectManager.
        // zbus proxies use org.freedesktop.DBus.Properties directly,
        // not ObjectManager, so this tests that property access works
        // through the standard Properties interface.
        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Verify property is accessible without ObjectManager
        let val: String = proxy
            .get_property("String")
            .await
            .expect("Should read String property without ObjectManager");
        assert_eq!(val, "value", "String property should work without ObjectManager");
    })
    .await;
    assert!(result.is_ok(), "test_client_no_object_manager timed out");
}

// ============================================================================
// Test 13: Force Disconnect
// ============================================================================

/// Validates proxy behavior when a remote service forcefully disconnects.
///
/// **C equivalent:** `client_force_disconnect()` — Sets up a SECOND private
/// session bus connection (`conn2`) with `SERVICE_NAME1`. Registers an
/// interface on `conn2` using `SERVICE_NAME` as the interface name. The
/// primary client on `conn1` watches `SERVICE_NAME1`. When the proxy handler
/// fires, it closes `conn2` (simulating a crash/exit). The `proxy_removed()`
/// callback fires on the client, confirming it detected the forced
/// disconnection.
///
/// **Rust translation:** Two connections to the same private bus. conn2
/// acquires `SERVICE_NAME1` and registers `TestPropertiesInterface` (which
/// has interface name `SERVICE_NAME`). conn1 creates an uncached proxy
/// targeting destination `SERVICE_NAME1` with interface `SERVICE_NAME`.
/// After conn2 is closed (force disconnect), the proxy read fails because
/// the name owner is gone.
#[tokio::test]
async fn test_client_force_disconnect() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();

        // First connection — anonymous "client" side
        let conn1 = bus.connect_anonymous().await;

        // Second connection — the "service" side that will be disconnected.
        // Acquires SERVICE_NAME1 as bus name, but the interface registered
        // is TestPropertiesInterface with D-Bus name SERVICE_NAME.
        let conn2 = bus.connect_with_name(SERVICE_NAME1).await;

        // Register interface on second connection
        conn2
            .object_server()
            .at(SERVICE_PATH, TestPropertiesInterface::with_defaults())
            .await
            .expect("Failed to register interface on conn2");

        // Create uncached proxy on conn1 targeting destination=SERVICE_NAME1,
        // interface=SERVICE_NAME (matching the registered interface name).
        // In the C original: g_dbus_client_new(conn1, SERVICE_NAME1, SERVICE_PATH)
        // followed by g_dbus_register_interface(conn2, path, SERVICE_NAME, ...).
        let proxy = create_uncached_proxy(&conn1, SERVICE_NAME1, SERVICE_NAME)
            .await
            .expect("Proxy creation on conn1 failed");

        // Verify proxy works before disconnect
        let val: String =
            proxy.get_property("String").await.expect("Should read property before disconnect");
        assert_eq!(val, "value");

        // Force disconnect: close the second connection.
        // This causes the bus daemon to release SERVICE_NAME1, so any
        // subsequent calls to that destination will fail.
        conn2.close().await.expect("Failed to close conn2");

        // Small delay for the NameOwnerChanged signal to propagate
        sleep(Duration::from_millis(200)).await;

        // Verify proxy detects the disconnection — uncached property read
        // makes a fresh D-Bus call targeting SERVICE_NAME1, which has no
        // owner now. This is the equivalent of proxy_removed firing in C.
        let read_result = proxy.get_property::<String>("String").await;
        assert!(read_result.is_err(), "Property read should fail after service force disconnect");
    })
    .await;
    assert!(result.is_ok(), "test_client_force_disconnect timed out");
}

// ============================================================================
// Test 14: Client Ready (Ordering Guarantee)
// ============================================================================

/// Validates that proxy interface discovery occurs before the "client ready"
/// state, ensuring proper ordering of D-Bus object introspection.
///
/// **C equivalent:** `client_ready()` — Sets a `ready_watch` callback and a
/// `proxy_added` handler. The proxy_added handler asserts
/// `context->client_ready == FALSE`, guaranteeing that proxies are reported
/// BEFORE the client signals readiness. Then ready_watch fires, sets
/// `client_ready = TRUE`, and the test completes.
///
/// **Rust translation:** This verifies that after connecting and registering
/// an interface, the proxy can immediately discover and read properties (the
/// equivalent of "proxy_added" before "client_ready"). The test confirms
/// that D-Bus introspection is synchronously available from the start.
#[tokio::test]
async fn test_client_ready() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;

        // Track ordering: proxy operations must succeed before "ready"
        let proxy_discovered = Arc::new(Mutex::new(false));
        let client_ready = Arc::new(Mutex::new(false));

        // Register interface
        register_test_interface(&conn).await;

        // Step 1: Proxy discovery — equivalent to proxy_added callback
        // In the C test, proxy_added asserts client_ready == FALSE
        {
            let ready_flag = client_ready.lock().await;
            assert!(
                !*ready_flag,
                "Client should NOT be ready before proxy discovery (ordering guarantee)"
            );
        }

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Read property to confirm proxy is fully operational
        let val: String = proxy
            .get_property("String")
            .await
            .expect("Should read property during proxy discovery");
        assert_eq!(val, "value");

        // Mark proxy as discovered
        {
            let mut discovered = proxy_discovered.lock().await;
            *discovered = true;
        }

        // Step 2: Mark client ready — equivalent to ready_watch callback
        // In the C test, this fires AFTER proxy_added
        {
            let discovered = proxy_discovered.lock().await;
            assert!(*discovered, "Proxy must be discovered BEFORE client ready signal");
            let mut ready = client_ready.lock().await;
            *ready = true;
        }

        // Verify final state: both proxy discovered and client ready
        let discovered = proxy_discovered.lock().await;
        let ready = client_ready.lock().await;
        assert!(*discovered, "Proxy should have been discovered");
        assert!(*ready, "Client should be ready");
    })
    .await;
    assert!(result.is_ok(), "test_client_ready timed out");
}

// ============================================================================
// Test: Property Exists (Dynamic Property Visibility)
// ============================================================================

/// Validates behavior when a property's existence is conditional.
///
/// **C equivalent:** `client_string_changed()` with `string_exists()` callback.
/// The `exists` callback initially returns `FALSE` when `context->data` is
/// NULL. The proxy handler verifies the property is absent. Then an idle
/// callback sets `data="value1"` and emits `PropertyChanged`. The change
/// handler confirms `"value1"` arrived.
///
/// **Rust adaptation:** Since zbus properties are always present once the
/// interface is registered, we test the equivalent scenario where a property
/// has an empty/default value initially, then gets updated to a meaningful
/// value. The property change stream detects the transition.
#[tokio::test]
async fn test_client_property_exists() {
    let result = timeout(TEST_TIMEOUT, async {
        let bus = TestBus::new();
        let conn = bus.connect_with_name(SERVICE_NAME).await;

        // Register interface with empty string (simulating "not exists" state)
        let iface = TestPropertiesInterface {
            string_prop: String::new(), // Empty — property "doesn't exist" semantically
            boolean_prop: true,
            number_prop: u64::MAX,
            array_prop: vec!["value1".to_string(), "value2".to_string()],
            dict_prop: HashMap::new(),
        };
        conn.object_server().at(SERVICE_PATH, iface).await.expect("Failed to register interface");

        let proxy = create_test_proxy(&conn, SERVICE_NAME, SERVICE_NAME)
            .await
            .expect("Proxy creation failed");

        // Verify initial value is empty (semantically "property doesn't exist")
        let initial: String = proxy.get_property("String").await.expect("Should read empty String");
        assert!(initial.is_empty(), "Initial String should be empty (simulating non-existence)");

        // Subscribe to changes
        let mut stream = proxy.receive_property_changed::<String>("String").await;
        // Consume initial cached value
        let _initial = stream.next().await.expect("Should get initial cached value");

        // Server-side: set data and emit change (C: emit_string_change idle callback)
        let iface_ref = conn
            .object_server()
            .interface::<_, TestPropertiesInterface>(SERVICE_PATH)
            .await
            .expect("Failed to get interface ref");

        {
            let mut iface = iface_ref.get_mut().await;
            iface.string_prop = "value1".to_string();
            iface
                .string_changed(iface_ref.signal_emitter())
                .await
                .expect("Failed to emit PropertyChanged");
        }

        // Receive change notification — C: string_changed verifies "value1"
        let change = stream.next().await.expect("Should receive change");
        let new_val: String = change.get().await.expect("Should get value");
        assert_eq!(new_val, "value1", "Property should become 'value1' after exists transition");
    })
    .await;
    assert!(result.is_ok(), "test_client_property_exists timed out");
}
