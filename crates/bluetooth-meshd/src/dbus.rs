//! Centralized D-Bus connection storage, mesh error-to-D-Bus error mapping,
//! message helper utilities, and send-with-timeout facility for the
//! bluetooth-meshd daemon.
//!
//! Replaces `mesh/dbus.c` (187 lines), `mesh/dbus.h` (32 lines), and
//! incorporates `mesh/error.h` (28 lines) from the original C BlueZ codebase.
//! Uses `zbus` instead of ELL's `l_dbus`.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use tracing::{debug, error};
use zbus::Connection;
use zbus::Message;
use zbus::zvariant::Value;

use crate::mesh;

// ---------------------------------------------------------------------------
// Phase 1 — Constants
// ---------------------------------------------------------------------------

/// Root D-Bus object path for the mesh service.
/// Mirrors `BLUEZ_MESH_PATH` from `mesh/dbus.h`.
pub const BLUEZ_MESH_PATH: &str = "/org/bluez/mesh";

/// Well-known D-Bus service name claimed by bluetooth-meshd.
/// Mirrors `BLUEZ_MESH_SERVICE` from `mesh/dbus.h`.
pub const BLUEZ_MESH_SERVICE: &str = "org.bluez.mesh";

/// Default timeout (in seconds) for D-Bus method calls that await a reply.
/// Mirrors `DEFAULT_DBUS_TIMEOUT` from `mesh/dbus.h` (value: 30).
pub const DEFAULT_DBUS_TIMEOUT: u32 = 30;

/// Prefix for all mesh-specific D-Bus error names.
/// Mirrors `ERROR_INTERFACE` originally defined in `mesh/mesh.h` and
/// referenced throughout `mesh/dbus.c`.
pub const ERROR_INTERFACE: &str = "org.bluez.mesh.Error";

// ---------------------------------------------------------------------------
// Phase 2 — Mesh Error Enum
// ---------------------------------------------------------------------------

/// Numeric error codes used internally by the mesh daemon.
///
/// Direct 1:1 mapping of the C `enum mesh_error` from `mesh/error.h`.
/// The discriminant values (0–10) are ABI-stable and must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MeshError {
    /// No error — success sentinel.
    None = 0,
    /// Generic operation failure.
    Failed = 1,
    /// Caller lacks authorization.
    NotAuthorized = 2,
    /// Requested object was not found.
    NotFound = 3,
    /// One or more arguments are invalid.
    InvalidArgs = 4,
    /// An equivalent operation is already in progress.
    InProgress = 5,
    /// The subsystem is busy and cannot service the request.
    Busy = 6,
    /// The entity already exists.
    AlreadyExists = 7,
    /// The target entity does not exist.
    DoesNotExist = 8,
    /// The operation was canceled.
    Canceled = 9,
    /// The requested feature is not implemented.
    NotImplemented = 10,
}

impl MeshError {
    /// Return the fully-qualified D-Bus error name for this error code.
    ///
    /// For [`MeshError::None`], returns an empty string (the sentinel value
    /// is never sent on the bus).
    #[inline]
    pub fn dbus_name(self) -> &'static str {
        let idx = self as usize;
        if idx < ERROR_TABLE.len() {
            ERROR_TABLE[idx].dbus_err
        } else {
            ERROR_TABLE[MeshError::Failed as usize].dbus_err
        }
    }

    /// Return the default human-readable description for this error code.
    ///
    /// Used when no custom description is supplied to [`dbus_error`].
    #[inline]
    pub fn default_description(self) -> &'static str {
        let idx = self as usize;
        if idx < ERROR_TABLE.len() {
            ERROR_TABLE[idx].default_desc
        } else {
            ERROR_TABLE[MeshError::Failed as usize].default_desc
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 2.2 — Error Table
// ---------------------------------------------------------------------------

/// Internal lookup entry mapping a [`MeshError`] discriminant to a D-Bus
/// error name string and a human-readable default description.
struct ErrorEntry {
    /// Fully-qualified D-Bus error name (e.g. `"org.bluez.mesh.Error.Failed"`).
    dbus_err: &'static str,
    /// Default description sent when the caller does not supply one.
    default_desc: &'static str,
}

/// Static error table indexed by [`MeshError`] discriminant.
///
/// Entry 0 (`None`) carries empty strings — it is never sent on the bus.
/// All other entries correspond 1:1 with the C `error_table[]` in
/// `mesh/dbus.c`, preserving identical D-Bus error names and default
/// messages.
static ERROR_TABLE: &[ErrorEntry] = &[
    // 0 — None (no-error sentinel, never transmitted)
    ErrorEntry { dbus_err: "", default_desc: "" },
    // 1 — Failed
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.Failed", default_desc: "Operation failed" },
    // 2 — NotAuthorized
    ErrorEntry {
        dbus_err: "org.bluez.mesh.Error.NotAuthorized",
        default_desc: "Permission denied",
    },
    // 3 — NotFound
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.NotFound", default_desc: "Object not found" },
    // 4 — InvalidArgs
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.InvalidArgs", default_desc: "Invalid arguments" },
    // 5 — InProgress
    ErrorEntry {
        dbus_err: "org.bluez.mesh.Error.InProgress",
        default_desc: "Operation already in progress",
    },
    // 6 — Busy
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.Busy", default_desc: "Busy" },
    // 7 — AlreadyExists
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.AlreadyExists", default_desc: "Already exists" },
    // 8 — DoesNotExist
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.DoesNotExist", default_desc: "Does not exist" },
    // 9 — Canceled
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.Canceled", default_desc: "Operation canceled" },
    // 10 — NotImplemented
    ErrorEntry { dbus_err: "org.bluez.mesh.Error.NotImplemented", default_desc: "Not implemented" },
];

// ---------------------------------------------------------------------------
// Phase 4 — D-Bus Error Type (zbus-compatible)
// ---------------------------------------------------------------------------

/// D-Bus-transmittable error type for mesh interface methods.
///
/// Uses `zbus::DBusError` derive to generate correct D-Bus error names with
/// the `org.bluez.mesh.Error` prefix.  Each variant maps to a specific
/// D-Bus error name (e.g. `org.bluez.mesh.Error.Failed`).
///
/// A special `#[zbus(error)]` variant wraps `zbus::Error` so that proxy
/// method calls can return this type directly.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.bluez.mesh.Error")]
pub enum MeshDbusError {
    /// Wraps a raw `zbus::Error` — enables `From<zbus::Error>` conversion
    /// so that D-Bus transport errors propagate transparently.
    #[zbus(error)]
    ZBus(zbus::Error),

    /// Generic operation failure.
    Failed(String),

    /// Caller lacks authorization.
    NotAuthorized(String),

    /// Requested object was not found.
    NotFound(String),

    /// One or more arguments are invalid.
    InvalidArgs(String),

    /// An equivalent operation is already in progress.
    InProgress(String),

    /// The subsystem is busy.
    Busy(String),

    /// The entity already exists.
    AlreadyExists(String),

    /// The target entity does not exist.
    DoesNotExist(String),

    /// The operation was canceled.
    Canceled(String),

    /// The requested feature is not implemented.
    NotImplemented(String),
}

// ---------------------------------------------------------------------------
// Phase 3 — D-Bus Connection Management
// ---------------------------------------------------------------------------

/// Process-global storage for the D-Bus connection handle.
///
/// Initialised once during [`dbus_init`] and never replaced.  Using
/// [`OnceLock`] guarantees thread-safe one-shot initialization without
/// requiring a mutex on every read.
static DBUS_CONNECTION: OnceLock<Connection> = OnceLock::new();

/// Store the D-Bus connection for later retrieval.
///
/// If a connection has already been stored, the call is silently ignored
/// (matching the C behaviour where the global pointer is set only once).
pub fn dbus_set_connection(conn: Connection) {
    let _ = DBUS_CONNECTION.set(conn);
}

/// Retrieve the stored D-Bus connection, if any.
///
/// Returns `None` before [`dbus_init`] has completed successfully.
pub fn dbus_get_connection() -> Option<&'static Connection> {
    DBUS_CONNECTION.get()
}

/// Initialize the mesh daemon's D-Bus interfaces and store the connection.
///
/// Replaces the C `dbus_init(struct l_dbus *bus)` function.  Calls each
/// subsystem's D-Bus registration routine in order:
///
/// 1. [`mesh::mesh_dbus_init`] — registers the `org.bluez.mesh.Network1`
///    interface.
///
/// Once all subsystem interfaces are registered the connection is stored
/// via [`dbus_set_connection`] for global access.
///
/// # Returns
///
/// `true` on success, `false` if any subsystem registration fails.
pub async fn dbus_init(conn: Connection) -> bool {
    // --- 1. Register the Network1 interface (mesh module) ----------------
    if !mesh::mesh_dbus_init(&conn).await {
        error!("Failed to initialize mesh D-Bus interface");
        return false;
    }

    // Store the connection for later use by other modules.
    dbus_set_connection(conn);
    debug!("D-Bus initialized for bluetooth-meshd");
    true
}

// ---------------------------------------------------------------------------
// Phase 4.1 — Error Helper
// ---------------------------------------------------------------------------

/// Convert a [`MeshError`] into a [`MeshDbusError`] suitable for returning
/// from a D-Bus interface method.
///
/// If `err` is [`MeshError::None`] or falls outside the valid range, it
/// defaults to [`MeshError::Failed`] — matching the C `dbus_error()`
/// behaviour.  When `description` is `None` the default description from
/// the error table is used.
pub fn dbus_error(err: MeshError, description: Option<&str>) -> MeshDbusError {
    let idx = err as usize;

    // Default to Failed for out-of-range or None (matching C behaviour).
    let idx = if idx == 0 || idx >= ERROR_TABLE.len() { MeshError::Failed as usize } else { idx };

    let entry = &ERROR_TABLE[idx];
    let desc = description.unwrap_or(entry.default_desc).to_owned();

    match idx {
        1 => MeshDbusError::Failed(desc),
        2 => MeshDbusError::NotAuthorized(desc),
        3 => MeshDbusError::NotFound(desc),
        4 => MeshDbusError::InvalidArgs(desc),
        5 => MeshDbusError::InProgress(desc),
        6 => MeshDbusError::Busy(desc),
        7 => MeshDbusError::AlreadyExists(desc),
        8 => MeshDbusError::DoesNotExist(desc),
        9 => MeshDbusError::Canceled(desc),
        10 => MeshDbusError::NotImplemented(desc),
        // Unreachable after the bounds check above, but be safe.
        _ => MeshDbusError::Failed(desc),
    }
}

// ---------------------------------------------------------------------------
// Phase 5 — D-Bus Message Helpers
// ---------------------------------------------------------------------------

/// Check whether a given interface name is present in an ObjectManager-style
/// `a{sa{sv}}` dictionary.
///
/// Replaces the C `dbus_match_interface()` which iterates ELL
/// `l_dbus_message_iter` entries of `(sa{sv})`.  With `zbus`, the data
/// arrives as a `HashMap<String, HashMap<String, Value>>`.
pub fn dbus_match_interface(
    interfaces: &HashMap<String, HashMap<String, Value<'_>>>,
    match_name: &str,
) -> bool {
    interfaces.contains_key(match_name)
}

/// Wrap a byte slice as a `zbus::zvariant::Value` suitable for inclusion
/// in D-Bus message bodies or variant dictionaries.
///
/// Replaces the C `dbus_append_byte_array()` which manually pushes bytes
/// into an ELL message builder.  With `zbus`, `Vec<u8>` serializes
/// directly to the D-Bus `ay` type.
pub fn byte_array_to_variant<'a>(data: &[u8]) -> Value<'a> {
    Value::from(data.to_vec())
}

/// Insert a basic-type key/value pair into a `HashMap<String, Value>`
/// that represents a D-Bus `a{sv}` dictionary.
///
/// Replaces the C `dbus_append_dict_entry_basic()` which uses ELL
/// message builder APIs.
pub fn dict_insert_basic<'a>(
    dict: &mut HashMap<String, Value<'a>>,
    key: &str,
    value: impl Into<Value<'a>>,
) {
    dict.insert(key.to_owned(), value.into());
}

// ---------------------------------------------------------------------------
// Phase 6 — Send-with-Timeout
// ---------------------------------------------------------------------------

/// Send a D-Bus message through the connection, enforcing a timeout.
///
/// Replaces the C `dbus_send_with_timeout()` pattern where
/// `l_dbus_send_with_reply` is combined with `l_timeout_create` and a
/// cancel-on-expiry callback.  Here, `tokio::time::timeout` enforces
/// the deadline around the `Connection::send` call.
///
/// # Returns
///
/// * `Ok(())` — the message was sent within the deadline.
/// * `Err(MeshDbusError::Failed(_))` — the underlying D-Bus send failed.
/// * `Err(MeshDbusError::Failed(_))` — the send did not complete within
///   `timeout_secs` seconds.
pub async fn send_with_timeout(
    conn: &Connection,
    msg: Message,
    timeout_secs: u64,
) -> Result<(), MeshDbusError> {
    let duration = Duration::from_secs(timeout_secs);

    match tokio::time::timeout(duration, conn.send(&msg)).await {
        Ok(Ok(())) => {
            debug!("D-Bus message sent successfully");
            Ok(())
        }
        Ok(Err(e)) => {
            error!("D-Bus send failed: {}", e);
            Err(MeshDbusError::Failed(format!("D-Bus send error: {e}")))
        }
        Err(_elapsed) => {
            error!("D-Bus send timed out after {}s", timeout_secs);
            Err(MeshDbusError::Failed(format!("D-Bus send timed out after {timeout_secs}s")))
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4 supplementary — Conversion from MeshError to MeshDbusError
// ---------------------------------------------------------------------------

impl From<MeshError> for MeshDbusError {
    /// Convert a [`MeshError`] into the corresponding [`MeshDbusError`],
    /// using the default description from the error table.
    fn from(err: MeshError) -> Self {
        dbus_error(err, Option::None)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_c_originals() {
        assert_eq!(BLUEZ_MESH_PATH, "/org/bluez/mesh");
        assert_eq!(BLUEZ_MESH_SERVICE, "org.bluez.mesh");
        assert_eq!(DEFAULT_DBUS_TIMEOUT, 30);
        assert_eq!(ERROR_INTERFACE, "org.bluez.mesh.Error");
    }

    #[test]
    fn mesh_error_discriminants() {
        assert_eq!(MeshError::None as u8, 0);
        assert_eq!(MeshError::Failed as u8, 1);
        assert_eq!(MeshError::NotAuthorized as u8, 2);
        assert_eq!(MeshError::NotFound as u8, 3);
        assert_eq!(MeshError::InvalidArgs as u8, 4);
        assert_eq!(MeshError::InProgress as u8, 5);
        assert_eq!(MeshError::Busy as u8, 6);
        assert_eq!(MeshError::AlreadyExists as u8, 7);
        assert_eq!(MeshError::DoesNotExist as u8, 8);
        assert_eq!(MeshError::Canceled as u8, 9);
        assert_eq!(MeshError::NotImplemented as u8, 10);
    }

    #[test]
    fn error_table_length() {
        // 11 entries: None(0) through NotImplemented(10).
        assert_eq!(ERROR_TABLE.len(), 11);
    }

    #[test]
    fn dbus_error_defaults_to_failed_for_none() {
        let err = dbus_error(MeshError::None, Option::None);
        assert!(matches!(err, MeshDbusError::Failed(_)));
    }

    #[test]
    fn dbus_error_uses_custom_description() {
        let err = dbus_error(MeshError::NotFound, Some("custom message"));
        match err {
            MeshDbusError::NotFound(desc) => assert_eq!(desc, "custom message"),
            other => panic!("Expected NotFound, got: {other:?}"),
        }
    }

    #[test]
    fn dbus_error_uses_default_description() {
        let err = dbus_error(MeshError::Busy, Option::None);
        match err {
            MeshDbusError::Busy(desc) => assert_eq!(desc, "Busy"),
            other => panic!("Expected Busy, got: {other:?}"),
        }
    }

    #[test]
    fn dbus_error_all_variants() {
        // Verify each MeshError variant maps to the correct MeshDbusError
        // variant with the default description from the error table.
        let cases: &[(MeshError, &str)] = &[
            (MeshError::Failed, "Operation failed"),
            (MeshError::NotAuthorized, "Permission denied"),
            (MeshError::NotFound, "Object not found"),
            (MeshError::InvalidArgs, "Invalid arguments"),
            (MeshError::InProgress, "Operation already in progress"),
            (MeshError::Busy, "Busy"),
            (MeshError::AlreadyExists, "Already exists"),
            (MeshError::DoesNotExist, "Does not exist"),
            (MeshError::Canceled, "Operation canceled"),
            (MeshError::NotImplemented, "Not implemented"),
        ];

        for &(code, expected_desc) in cases {
            let err = dbus_error(code, Option::None);
            let desc = match &err {
                MeshDbusError::Failed(d)
                | MeshDbusError::NotAuthorized(d)
                | MeshDbusError::NotFound(d)
                | MeshDbusError::InvalidArgs(d)
                | MeshDbusError::InProgress(d)
                | MeshDbusError::Busy(d)
                | MeshDbusError::AlreadyExists(d)
                | MeshDbusError::DoesNotExist(d)
                | MeshDbusError::Canceled(d)
                | MeshDbusError::NotImplemented(d) => d.as_str(),
                MeshDbusError::ZBus(_) => panic!("Unexpected ZBus variant"),
            };
            assert_eq!(desc, expected_desc, "Mismatch for {code:?}");
        }
    }

    #[test]
    fn dbus_match_interface_found() {
        let mut interfaces: HashMap<String, HashMap<String, Value<'_>>> = HashMap::new();
        interfaces.insert("org.bluez.mesh.Network1".to_owned(), HashMap::new());
        assert!(dbus_match_interface(&interfaces, "org.bluez.mesh.Network1"));
    }

    #[test]
    fn dbus_match_interface_not_found() {
        let interfaces: HashMap<String, HashMap<String, Value<'_>>> = HashMap::new();
        assert!(!dbus_match_interface(&interfaces, "org.bluez.mesh.Network1"));
    }

    #[test]
    fn byte_array_to_variant_round_trip() {
        let data: &[u8] = &[0x01, 0x02, 0x03, 0xFF];
        let val = byte_array_to_variant(data);
        // The value should be an Array of u8.
        match &val {
            Value::Array(arr) => assert_eq!(arr.len(), 4),
            other => panic!("Expected Array, got: {other:?}"),
        }
    }

    #[test]
    fn dict_insert_basic_string_value() {
        let mut dict: HashMap<String, Value<'_>> = HashMap::new();
        dict_insert_basic(&mut dict, "Name", Value::from("TestNode".to_owned()));
        assert!(dict.contains_key("Name"));
    }

    #[test]
    fn dict_insert_basic_u32_value() {
        let mut dict: HashMap<String, Value<'_>> = HashMap::new();
        dict_insert_basic(&mut dict, "Index", Value::from(42u32));
        assert!(dict.contains_key("Index"));
    }

    #[test]
    fn mesh_error_to_dbus_error_conversion() {
        let dbus_err: MeshDbusError = MeshError::Canceled.into();
        match dbus_err {
            MeshDbusError::Canceled(desc) => {
                assert_eq!(desc, "Operation canceled");
            }
            other => panic!("Expected Canceled, got: {other:?}"),
        }
    }

    #[test]
    fn error_table_dbus_names_use_correct_prefix() {
        for (i, entry) in ERROR_TABLE.iter().enumerate() {
            if i == 0 {
                // None entry has empty strings.
                assert!(entry.dbus_err.is_empty());
                continue;
            }
            assert!(
                entry.dbus_err.starts_with(ERROR_INTERFACE),
                "Entry {i} does not start with ERROR_INTERFACE: {}",
                entry.dbus_err
            );
        }
    }
}
