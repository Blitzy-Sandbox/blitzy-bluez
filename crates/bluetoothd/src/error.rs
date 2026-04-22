// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2006-2010  Nokia Corporation
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
// Copyright (C) 2007-2008  Fabien Chevalier <fabchevalier@free.fr>
//
// D-Bus error reply mapping — converts internal error codes to org.bluez.Error.* D-Bus error
// names. Every error name, message string, and errno mapping is preserved byte-identically from
// the original C implementation (src/error.c, src/error.h).

use nix::errno::Errno;

// ---------------------------------------------------------------------------
// D-Bus error interface prefix constants
// ---------------------------------------------------------------------------

/// Base D-Bus error interface name for BlueZ errors (`org.bluez.Error`).
pub const ERROR_INTERFACE: &str = "org.bluez.Error";

/// D-Bus error interface name for BR/EDR-specific errors (`org.bluez.Error.BREDR`).
pub const ERROR_INTERFACE_BREDR: &str = "org.bluez.Error.BREDR";

// ---------------------------------------------------------------------------
// BR/EDR connection failure reason strings
// ---------------------------------------------------------------------------

/// BR/EDR connection error: already connected.
pub const ERR_BREDR_CONN_ALREADY_CONNECTED: &str = "br-connection-already-connected";

/// BR/EDR connection error: page timeout.
pub const ERR_BREDR_CONN_PAGE_TIMEOUT: &str = "br-connection-page-timeout";

/// BR/EDR connection error: SDP search failure.
pub const ERR_BREDR_CONN_SDP_SEARCH: &str = "br-connection-sdp-search";

/// BR/EDR connection error: socket creation failure.
pub const ERR_BREDR_CONN_CREATE_SOCKET: &str = "br-connection-create-socket";

/// BR/EDR connection error: invalid arguments.
pub const ERR_BREDR_CONN_INVALID_ARGUMENTS: &str = "br-connection-invalid-argument";

/// BR/EDR connection error: adapter not powered.
pub const ERR_BREDR_CONN_ADAPTER_NOT_POWERED: &str = "br-connection-adapter-not-powered";

/// BR/EDR connection error: operation not supported.
pub const ERR_BREDR_CONN_NOT_SUPPORTED: &str = "br-connection-not-supported";

/// BR/EDR connection error: bad socket.
pub const ERR_BREDR_CONN_BAD_SOCKET: &str = "br-connection-bad-socket";

/// BR/EDR connection error: memory allocation failure.
pub const ERR_BREDR_CONN_MEMORY_ALLOC: &str = "br-connection-memory-allocation";

/// BR/EDR connection error: busy.
pub const ERR_BREDR_CONN_BUSY: &str = "br-connection-busy";

/// BR/EDR connection error: concurrent connection limit reached.
pub const ERR_BREDR_CONN_CNCR_CONNECT_LIMIT: &str = "br-connection-concurrent-connection-limit";

/// BR/EDR connection error: timeout.
pub const ERR_BREDR_CONN_TIMEOUT: &str = "br-connection-timeout";

/// BR/EDR connection error: connection refused.
pub const ERR_BREDR_CONN_REFUSED: &str = "br-connection-refused";

/// BR/EDR connection error: aborted by remote.
pub const ERR_BREDR_CONN_ABORT_BY_REMOTE: &str = "br-connection-aborted-by-remote";

/// BR/EDR connection error: aborted by local.
pub const ERR_BREDR_CONN_ABORT_BY_LOCAL: &str = "br-connection-aborted-by-local";

/// BR/EDR connection error: LMP protocol error.
pub const ERR_BREDR_CONN_LMP_PROTO_ERROR: &str = "br-connection-lmp-protocol-error";

/// BR/EDR connection error: canceled.
pub const ERR_BREDR_CONN_CANCELED: &str = "br-connection-canceled";

/// BR/EDR connection error: key missing.
pub const ERR_BREDR_CONN_KEY_MISSING: &str = "br-connection-key-missing";

/// BR/EDR connection error: unknown failure.
pub const ERR_BREDR_CONN_UNKNOWN: &str = "br-connection-unknown";

// ---------------------------------------------------------------------------
// LE connection failure reason strings
// ---------------------------------------------------------------------------

/// LE connection error: invalid arguments.
pub const ERR_LE_CONN_INVALID_ARGUMENTS: &str = "le-connection-invalid-arguments";

/// LE connection error: adapter not powered.
pub const ERR_LE_CONN_ADAPTER_NOT_POWERED: &str = "le-connection-adapter-not-powered";

/// LE connection error: operation not supported.
pub const ERR_LE_CONN_NOT_SUPPORTED: &str = "le-connection-not-supported";

/// LE connection error: already connected.
pub const ERR_LE_CONN_ALREADY_CONNECTED: &str = "le-connection-already-connected";

/// LE connection error: bad socket.
pub const ERR_LE_CONN_BAD_SOCKET: &str = "le-connection-bad-socket";

/// LE connection error: memory allocation failure.
pub const ERR_LE_CONN_MEMORY_ALLOC: &str = "le-connection-memory-allocation";

/// LE connection error: busy.
pub const ERR_LE_CONN_BUSY: &str = "le-connection-busy";

/// LE connection error: connection refused.
pub const ERR_LE_CONN_REFUSED: &str = "le-connection-refused";

/// LE connection error: socket creation failure.
pub const ERR_LE_CONN_CREATE_SOCKET: &str = "le-connection-create-socket";

/// LE connection error: timeout.
pub const ERR_LE_CONN_TIMEOUT: &str = "le-connection-timeout";

/// LE connection error: concurrent connection limit (sync connect limit).
pub const ERR_LE_CONN_SYNC_CONNECT_LIMIT: &str = "le-connection-concurrent-connection-limit";

/// LE connection error: aborted by remote.
pub const ERR_LE_CONN_ABORT_BY_REMOTE: &str = "le-connection-abort-by-remote";

/// LE connection error: aborted by local.
pub const ERR_LE_CONN_ABORT_BY_LOCAL: &str = "le-connection-abort-by-local";

/// LE connection error: link-layer protocol error.
pub const ERR_LE_CONN_LL_PROTO_ERROR: &str = "le-connection-link-layer-protocol-error";

/// LE connection error: GATT browsing failure.
pub const ERR_LE_CONN_GATT_BROWSE: &str = "le-connection-gatt-browsing";

/// LE connection error: key missing.
pub const ERR_LE_CONN_KEY_MISSING: &str = "le-connection-key-missing";

/// LE connection error: unknown failure.
pub const ERR_LE_CONN_UNKNOWN: &str = "le-connection-unknown";

// ---------------------------------------------------------------------------
// BtdError — Typed D-Bus error enum
// ---------------------------------------------------------------------------

/// BlueZ daemon error type mapping to `org.bluez.Error.*` D-Bus error names.
///
/// Each variant carries a human-readable message string that is transmitted as the D-Bus error
/// description. The `dbus_error_name()` method returns the fully-qualified D-Bus error name for
/// the variant. The enum implements `zbus::DBusError` so it can be used directly as the error
/// type in `#[zbus::interface]` method return types.
///
/// All error names and default messages are preserved byte-identically from the C daemon.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BtdError {
    /// `org.bluez.Error.InvalidArguments` — invalid arguments in a method call.
    #[error("{0}")]
    InvalidArguments(String),

    /// `org.bluez.Error.InProgress` — operation already in progress.
    #[error("{0}")]
    InProgress(String),

    /// `org.bluez.Error.AlreadyExists` — the requested resource already exists.
    #[error("{0}")]
    AlreadyExists(String),

    /// `org.bluez.Error.NotSupported` — operation is not supported.
    #[error("{0}")]
    NotSupported(String),

    /// `org.bluez.Error.NotConnected` — device is not connected.
    #[error("{0}")]
    NotConnected(String),

    /// `org.bluez.Error.AlreadyConnected` — device is already connected.
    #[error("{0}")]
    AlreadyConnected(String),

    /// `org.bluez.Error.NotAvailable` — operation currently not available.
    #[error("{0}")]
    NotAvailable(String),

    /// `org.bluez.Error.DoesNotExist` — the requested resource does not exist.
    #[error("{0}")]
    DoesNotExist(String),

    /// `org.bluez.Error.NotAuthorized` — operation not authorized.
    #[error("{0}")]
    NotAuthorized(String),

    /// `org.bluez.Error.NotPermitted` — operation not permitted.
    #[error("{0}")]
    NotPermitted(String),

    /// `org.bluez.Error.NoSuchAdapter` — no adapter with the given path exists.
    #[error("{0}")]
    NoSuchAdapter(String),

    /// `org.bluez.Error.AgentNotAvailable` — no pairing agent is registered.
    #[error("{0}")]
    AgentNotAvailable(String),

    /// `org.bluez.Error.NotReady` — resource is not ready.
    #[error("{0}")]
    NotReady(String),

    /// `org.bluez.Error.BREDR.ProfileUnavailable` — no more profiles to connect to.
    ///
    /// Note: this variant uses the `org.bluez.Error.BREDR` prefix, not `org.bluez.Error`.
    #[error("{0}")]
    ProfileUnavailable(String),

    /// `org.bluez.Error.Failed` — generic failure with a custom message.
    #[error("{0}")]
    Failed(String),
}

// ---------------------------------------------------------------------------
// D-Bus error name constants (fully-qualified, used by dbus_error_name())
// ---------------------------------------------------------------------------

/// Fully-qualified D-Bus error name for `InvalidArguments`.
const DBUS_ERR_INVALID_ARGUMENTS: &str = "org.bluez.Error.InvalidArguments";
/// Fully-qualified D-Bus error name for `InProgress`.
const DBUS_ERR_IN_PROGRESS: &str = "org.bluez.Error.InProgress";
/// Fully-qualified D-Bus error name for `AlreadyExists`.
const DBUS_ERR_ALREADY_EXISTS: &str = "org.bluez.Error.AlreadyExists";
/// Fully-qualified D-Bus error name for `NotSupported`.
const DBUS_ERR_NOT_SUPPORTED: &str = "org.bluez.Error.NotSupported";
/// Fully-qualified D-Bus error name for `NotConnected`.
const DBUS_ERR_NOT_CONNECTED: &str = "org.bluez.Error.NotConnected";
/// Fully-qualified D-Bus error name for `AlreadyConnected`.
const DBUS_ERR_ALREADY_CONNECTED: &str = "org.bluez.Error.AlreadyConnected";
/// Fully-qualified D-Bus error name for `NotAvailable`.
const DBUS_ERR_NOT_AVAILABLE: &str = "org.bluez.Error.NotAvailable";
/// Fully-qualified D-Bus error name for `DoesNotExist`.
const DBUS_ERR_DOES_NOT_EXIST: &str = "org.bluez.Error.DoesNotExist";
/// Fully-qualified D-Bus error name for `NotAuthorized`.
const DBUS_ERR_NOT_AUTHORIZED: &str = "org.bluez.Error.NotAuthorized";
/// Fully-qualified D-Bus error name for `NotPermitted`.
const DBUS_ERR_NOT_PERMITTED: &str = "org.bluez.Error.NotPermitted";
/// Fully-qualified D-Bus error name for `NoSuchAdapter`.
const DBUS_ERR_NO_SUCH_ADAPTER: &str = "org.bluez.Error.NoSuchAdapter";
/// Fully-qualified D-Bus error name for `AgentNotAvailable`.
const DBUS_ERR_AGENT_NOT_AVAILABLE: &str = "org.bluez.Error.AgentNotAvailable";
/// Fully-qualified D-Bus error name for `NotReady`.
const DBUS_ERR_NOT_READY: &str = "org.bluez.Error.NotReady";
/// Fully-qualified D-Bus error name for `ProfileUnavailable` (BREDR prefix).
const DBUS_ERR_PROFILE_UNAVAILABLE: &str = "org.bluez.Error.BREDR.ProfileUnavailable";
/// Fully-qualified D-Bus error name for `Failed`.
const DBUS_ERR_FAILED: &str = "org.bluez.Error.Failed";

// ---------------------------------------------------------------------------
// BtdError — convenience constructors (matching C btd_error_* functions)
// ---------------------------------------------------------------------------

impl BtdError {
    /// Returns the fully-qualified D-Bus error name for this error variant.
    ///
    /// This matches the exact error names produced by the C daemon:
    /// - Most variants use the `org.bluez.Error.<Variant>` pattern
    /// - `ProfileUnavailable` uses `org.bluez.Error.BREDR.ProfileUnavailable`
    pub fn dbus_error_name(&self) -> &'static str {
        match self {
            Self::InvalidArguments(_) => DBUS_ERR_INVALID_ARGUMENTS,
            Self::InProgress(_) => DBUS_ERR_IN_PROGRESS,
            Self::AlreadyExists(_) => DBUS_ERR_ALREADY_EXISTS,
            Self::NotSupported(_) => DBUS_ERR_NOT_SUPPORTED,
            Self::NotConnected(_) => DBUS_ERR_NOT_CONNECTED,
            Self::AlreadyConnected(_) => DBUS_ERR_ALREADY_CONNECTED,
            Self::NotAvailable(_) => DBUS_ERR_NOT_AVAILABLE,
            Self::DoesNotExist(_) => DBUS_ERR_DOES_NOT_EXIST,
            Self::NotAuthorized(_) => DBUS_ERR_NOT_AUTHORIZED,
            Self::NotPermitted(_) => DBUS_ERR_NOT_PERMITTED,
            Self::NoSuchAdapter(_) => DBUS_ERR_NO_SUCH_ADAPTER,
            Self::AgentNotAvailable(_) => DBUS_ERR_AGENT_NOT_AVAILABLE,
            Self::NotReady(_) => DBUS_ERR_NOT_READY,
            Self::ProfileUnavailable(_) => DBUS_ERR_PROFILE_UNAVAILABLE,
            Self::Failed(_) => DBUS_ERR_FAILED,
        }
    }

    /// Returns the message string carried by this error.
    fn message(&self) -> &str {
        match self {
            Self::InvalidArguments(s)
            | Self::InProgress(s)
            | Self::AlreadyExists(s)
            | Self::NotSupported(s)
            | Self::NotConnected(s)
            | Self::AlreadyConnected(s)
            | Self::NotAvailable(s)
            | Self::DoesNotExist(s)
            | Self::NotAuthorized(s)
            | Self::NotPermitted(s)
            | Self::NoSuchAdapter(s)
            | Self::AgentNotAvailable(s)
            | Self::NotReady(s)
            | Self::ProfileUnavailable(s)
            | Self::Failed(s) => s,
        }
    }

    // -- Convenience constructors preserving exact C daemon messages --

    /// Creates an `InvalidArguments` error with the default message
    /// `"Invalid arguments in method call"`.
    ///
    /// Equivalent to C `btd_error_invalid_args()`.
    pub fn invalid_args() -> Self {
        Self::InvalidArguments("Invalid arguments in method call".to_owned())
    }

    /// Creates an `InvalidArguments` error with a custom message string.
    ///
    /// Equivalent to C `btd_error_invalid_args_str()`.
    pub fn invalid_args_str(msg: &str) -> Self {
        Self::InvalidArguments(msg.to_owned())
    }

    /// Creates an `InProgress` error with the default message
    /// `"Operation already in progress"`.
    ///
    /// Equivalent to C `btd_error_busy()`. Note: the C function name is `busy` but it
    /// produces an `InProgress` D-Bus error, which is preserved here.
    pub fn busy() -> Self {
        Self::InProgress("Operation already in progress".to_owned())
    }

    /// Creates an `AlreadyExists` error with the default message `"Already Exists"`.
    ///
    /// Equivalent to C `btd_error_already_exists()`.
    pub fn already_exists() -> Self {
        Self::AlreadyExists("Already Exists".to_owned())
    }

    /// Creates a `NotSupported` error with the default message
    /// `"Operation is not supported"`.
    ///
    /// Equivalent to C `btd_error_not_supported()`.
    pub fn not_supported() -> Self {
        Self::NotSupported("Operation is not supported".to_owned())
    }

    /// Creates a `NotConnected` error with the default message `"Not Connected"`.
    ///
    /// Equivalent to C `btd_error_not_connected()`.
    pub fn not_connected() -> Self {
        Self::NotConnected("Not Connected".to_owned())
    }

    /// Creates an `AlreadyConnected` error with the default message `"Already Connected"`.
    ///
    /// Equivalent to C `btd_error_already_connected()`.
    pub fn already_connected() -> Self {
        Self::AlreadyConnected("Already Connected".to_owned())
    }

    /// Creates an `InProgress` error with the default message `"In Progress"`.
    ///
    /// Equivalent to C `btd_error_in_progress()`.
    pub fn in_progress() -> Self {
        Self::InProgress("In Progress".to_owned())
    }

    /// Creates an `InProgress` error with a custom message string.
    ///
    /// Equivalent to C `btd_error_in_progress_str()`.
    pub fn in_progress_str(msg: &str) -> Self {
        Self::InProgress(msg.to_owned())
    }

    /// Creates a `NotAvailable` error with the default message
    /// `"Operation currently not available"`.
    ///
    /// Equivalent to C `btd_error_not_available()`.
    pub fn not_available() -> Self {
        Self::NotAvailable("Operation currently not available".to_owned())
    }

    /// Creates a `NotAvailable` error with a custom message string.
    ///
    /// Equivalent to C `btd_error_not_available_str()`.
    pub fn not_available_str(msg: &str) -> Self {
        Self::NotAvailable(msg.to_owned())
    }

    /// Creates a `DoesNotExist` error with the default message `"Does Not Exist"`.
    ///
    /// Equivalent to C `btd_error_does_not_exist()`.
    pub fn does_not_exist() -> Self {
        Self::DoesNotExist("Does Not Exist".to_owned())
    }

    /// Creates a `NotAuthorized` error with the default message
    /// `"Operation Not Authorized"`.
    ///
    /// Equivalent to C `btd_error_not_authorized()`.
    pub fn not_authorized() -> Self {
        Self::NotAuthorized("Operation Not Authorized".to_owned())
    }

    /// Creates a `NotPermitted` error with a custom message string.
    ///
    /// Equivalent to C `btd_error_not_permitted()`.
    pub fn not_permitted(msg: &str) -> Self {
        Self::NotPermitted(msg.to_owned())
    }

    /// Creates a `NoSuchAdapter` error with the default message `"No such adapter"`.
    ///
    /// Equivalent to C `btd_error_no_such_adapter()`.
    pub fn no_such_adapter() -> Self {
        Self::NoSuchAdapter("No such adapter".to_owned())
    }

    /// Creates an `AgentNotAvailable` error with the default message
    /// `"Agent Not Available"`.
    ///
    /// Equivalent to C `btd_error_agent_not_available()`.
    pub fn agent_not_available() -> Self {
        Self::AgentNotAvailable("Agent Not Available".to_owned())
    }

    /// Creates a `NotReady` error with the default message `"Resource Not Ready"`.
    ///
    /// Equivalent to C `btd_error_not_ready()`.
    pub fn not_ready() -> Self {
        Self::NotReady("Resource Not Ready".to_owned())
    }

    /// Creates a `NotReady` error with a custom message string.
    ///
    /// Equivalent to C `btd_error_not_ready_str()`.
    pub fn not_ready_str(msg: &str) -> Self {
        Self::NotReady(msg.to_owned())
    }

    /// Creates a `ProfileUnavailable` error with the default message
    /// `"No more profiles to connect to"`.
    ///
    /// Equivalent to C `btd_error_profile_unavailable()`.
    /// Uses `org.bluez.Error.BREDR.ProfileUnavailable` as the D-Bus error name.
    pub fn profile_unavailable() -> Self {
        Self::ProfileUnavailable("No more profiles to connect to".to_owned())
    }

    /// Creates a `Failed` error with a custom message string.
    ///
    /// Equivalent to C `btd_error_failed()`.
    pub fn failed(msg: &str) -> Self {
        Self::Failed(msg.to_owned())
    }
}

// ---------------------------------------------------------------------------
// zbus::DBusError trait implementation — enables BtdError as the error type
// in #[zbus::interface] method return types (Result<T, BtdError>).
// ---------------------------------------------------------------------------

impl zbus::DBusError for BtdError {
    /// Returns the fully-qualified D-Bus error name for this error.
    fn name(&self) -> zbus::names::ErrorName<'_> {
        // All error name strings are compile-time constants known to be valid D-Bus error names
        // (they contain at least two dot-separated elements with valid characters).
        zbus::names::ErrorName::from_static_str_unchecked(self.dbus_error_name())
    }

    /// Returns the human-readable error description.
    fn description(&self) -> Option<&str> {
        Some(self.message())
    }

    /// Builds a D-Bus error reply message for the given method call header.
    fn create_reply(
        &self,
        call: &zbus::message::Header<'_>,
    ) -> zbus::Result<zbus::message::Message> {
        let name = self.name();
        let desc = self.message();
        zbus::message::Message::error(call, name)?.build(&(desc,))
    }
}

// ---------------------------------------------------------------------------
// Conversion from BtdError to zbus::Error for contexts that require it.
// ---------------------------------------------------------------------------

impl From<BtdError> for zbus::Error {
    fn from(err: BtdError) -> Self {
        let name = err.dbus_error_name().to_owned();
        let desc = err.message().to_owned();
        // Construct a zbus::Error that carries the D-Bus error name and description.
        // MethodError is the canonical representation of a D-Bus error reply in zbus.
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name)
                .expect("BtdError D-Bus error names are always valid"),
            Some(desc),
            // A placeholder message is required by the MethodError variant.
            // This path is used when BtdError is converted outside of a method handler context.
            zbus::message::Message::method_call("/", "Err")
                .expect("default message construction should not fail")
                .build(&())
                .expect("default message build should not fail"),
        )
    }
}

// ---------------------------------------------------------------------------
// Conversion from zbus::fdo::Error to BtdError for interoperability.
// ---------------------------------------------------------------------------

impl From<zbus::fdo::Error> for BtdError {
    fn from(err: zbus::fdo::Error) -> Self {
        Self::Failed(err.to_string())
    }
}

impl From<zbus::Error> for BtdError {
    fn from(err: zbus::Error) -> Self {
        match err {
            zbus::Error::FDO(fdo) => Self::from(*fdo),
            other => Self::Failed(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Errno-to-D-Bus-error mapping functions
// ---------------------------------------------------------------------------

/// Maps a negative errno value to a BR/EDR connection failure reason string.
///
/// The mapping follows the C `btd_error_bredr_str()` function exactly.
fn btd_error_bredr_str(err: i32) -> &'static str {
    match Errno::from_raw(-err) {
        Errno::EALREADY | Errno::EISCONN => ERR_BREDR_CONN_ALREADY_CONNECTED,
        Errno::EHOSTDOWN => ERR_BREDR_CONN_PAGE_TIMEOUT,
        Errno::EIO => ERR_BREDR_CONN_CREATE_SOCKET,
        Errno::EINVAL => ERR_BREDR_CONN_INVALID_ARGUMENTS,
        Errno::EHOSTUNREACH => ERR_BREDR_CONN_ADAPTER_NOT_POWERED,
        Errno::EOPNOTSUPP | Errno::EPROTONOSUPPORT => ERR_BREDR_CONN_NOT_SUPPORTED,
        Errno::EBADFD => ERR_BREDR_CONN_BAD_SOCKET,
        Errno::ENOMEM => ERR_BREDR_CONN_MEMORY_ALLOC,
        Errno::EBUSY => ERR_BREDR_CONN_BUSY,
        Errno::EMLINK => ERR_BREDR_CONN_CNCR_CONNECT_LIMIT,
        Errno::ETIMEDOUT => ERR_BREDR_CONN_TIMEOUT,
        Errno::ECONNREFUSED => ERR_BREDR_CONN_REFUSED,
        Errno::ECONNRESET => ERR_BREDR_CONN_ABORT_BY_REMOTE,
        Errno::ECONNABORTED => ERR_BREDR_CONN_ABORT_BY_LOCAL,
        Errno::EPROTO => ERR_BREDR_CONN_LMP_PROTO_ERROR,
        Errno::EBADE => ERR_BREDR_CONN_KEY_MISSING,
        _ => ERR_BREDR_CONN_UNKNOWN,
    }
}

/// Maps a negative errno value to an LE connection failure reason string.
///
/// The mapping follows the C `btd_error_le_str()` function exactly.
fn btd_error_le_str(err: i32) -> &'static str {
    match Errno::from_raw(-err) {
        Errno::EINVAL => ERR_LE_CONN_INVALID_ARGUMENTS,
        Errno::EHOSTUNREACH => ERR_LE_CONN_ADAPTER_NOT_POWERED,
        Errno::EOPNOTSUPP | Errno::EPROTONOSUPPORT => ERR_LE_CONN_NOT_SUPPORTED,
        Errno::EALREADY | Errno::EISCONN => ERR_LE_CONN_ALREADY_CONNECTED,
        Errno::EBADFD => ERR_LE_CONN_BAD_SOCKET,
        Errno::ENOMEM => ERR_LE_CONN_MEMORY_ALLOC,
        Errno::EBUSY => ERR_LE_CONN_BUSY,
        Errno::ECONNREFUSED => ERR_LE_CONN_REFUSED,
        Errno::EIO => ERR_LE_CONN_CREATE_SOCKET,
        Errno::ETIMEDOUT => ERR_LE_CONN_TIMEOUT,
        Errno::EMLINK => ERR_LE_CONN_SYNC_CONNECT_LIMIT,
        Errno::ECONNRESET => ERR_LE_CONN_ABORT_BY_REMOTE,
        Errno::ECONNABORTED => ERR_LE_CONN_ABORT_BY_LOCAL,
        Errno::EPROTO => ERR_LE_CONN_LL_PROTO_ERROR,
        Errno::EBADE => ERR_LE_CONN_KEY_MISSING,
        _ => ERR_LE_CONN_UNKNOWN,
    }
}

/// Maps a negative errno value to a `BtdError` representing a BR/EDR connection failure.
///
/// Special case: `ENOPROTOOPT` maps to `BtdError::ProfileUnavailable` (the C function
/// `btd_error_bredr_errno()` delegates to `btd_error_profile_unavailable()` for this errno).
/// All other errno values produce `BtdError::Failed` with the appropriate BR/EDR reason string.
pub fn btd_error_bredr_errno(err: i32) -> BtdError {
    if Errno::from_raw(err) == Errno::ENOPROTOOPT {
        BtdError::profile_unavailable()
    } else {
        BtdError::failed(btd_error_bredr_str(err))
    }
}

/// Maps a negative errno value to a `BtdError` representing an LE connection failure.
///
/// All errno values produce `BtdError::Failed` with the appropriate LE reason string.
pub fn btd_error_le_errno(err: i32) -> BtdError {
    BtdError::failed(btd_error_le_str(err))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_interface_constants() {
        assert_eq!(ERROR_INTERFACE, "org.bluez.Error");
        assert_eq!(ERROR_INTERFACE_BREDR, "org.bluez.Error.BREDR");
    }

    #[test]
    fn test_dbus_error_names() {
        assert_eq!(BtdError::invalid_args().dbus_error_name(), "org.bluez.Error.InvalidArguments");
        assert_eq!(BtdError::busy().dbus_error_name(), "org.bluez.Error.InProgress");
        assert_eq!(BtdError::already_exists().dbus_error_name(), "org.bluez.Error.AlreadyExists");
        assert_eq!(BtdError::not_supported().dbus_error_name(), "org.bluez.Error.NotSupported");
        assert_eq!(BtdError::not_connected().dbus_error_name(), "org.bluez.Error.NotConnected");
        assert_eq!(
            BtdError::already_connected().dbus_error_name(),
            "org.bluez.Error.AlreadyConnected"
        );
        assert_eq!(BtdError::in_progress().dbus_error_name(), "org.bluez.Error.InProgress");
        assert_eq!(BtdError::not_available().dbus_error_name(), "org.bluez.Error.NotAvailable");
        assert_eq!(BtdError::does_not_exist().dbus_error_name(), "org.bluez.Error.DoesNotExist");
        assert_eq!(BtdError::not_authorized().dbus_error_name(), "org.bluez.Error.NotAuthorized");
        assert_eq!(
            BtdError::not_permitted("test").dbus_error_name(),
            "org.bluez.Error.NotPermitted"
        );
        assert_eq!(BtdError::no_such_adapter().dbus_error_name(), "org.bluez.Error.NoSuchAdapter");
        assert_eq!(
            BtdError::agent_not_available().dbus_error_name(),
            "org.bluez.Error.AgentNotAvailable"
        );
        assert_eq!(BtdError::not_ready().dbus_error_name(), "org.bluez.Error.NotReady");
        assert_eq!(
            BtdError::profile_unavailable().dbus_error_name(),
            "org.bluez.Error.BREDR.ProfileUnavailable"
        );
        assert_eq!(BtdError::failed("test").dbus_error_name(), "org.bluez.Error.Failed");
    }

    #[test]
    fn test_default_error_messages() {
        assert_eq!(BtdError::invalid_args().to_string(), "Invalid arguments in method call");
        assert_eq!(BtdError::busy().to_string(), "Operation already in progress");
        assert_eq!(BtdError::already_exists().to_string(), "Already Exists");
        assert_eq!(BtdError::not_supported().to_string(), "Operation is not supported");
        assert_eq!(BtdError::not_connected().to_string(), "Not Connected");
        assert_eq!(BtdError::already_connected().to_string(), "Already Connected");
        assert_eq!(BtdError::in_progress().to_string(), "In Progress");
        assert_eq!(BtdError::not_available().to_string(), "Operation currently not available");
        assert_eq!(BtdError::does_not_exist().to_string(), "Does Not Exist");
        assert_eq!(BtdError::not_authorized().to_string(), "Operation Not Authorized");
        assert_eq!(BtdError::no_such_adapter().to_string(), "No such adapter");
        assert_eq!(BtdError::agent_not_available().to_string(), "Agent Not Available");
        assert_eq!(BtdError::not_ready().to_string(), "Resource Not Ready");
        assert_eq!(BtdError::profile_unavailable().to_string(), "No more profiles to connect to");
        assert_eq!(BtdError::failed("oops").to_string(), "oops");
    }

    #[test]
    fn test_custom_message_constructors() {
        let err = BtdError::invalid_args_str("bad param");
        assert_eq!(err.to_string(), "bad param");
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.InvalidArguments");

        let err = BtdError::in_progress_str("still working");
        assert_eq!(err.to_string(), "still working");
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.InProgress");

        let err = BtdError::not_available_str("try later");
        assert_eq!(err.to_string(), "try later");
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.NotAvailable");

        let err = BtdError::not_ready_str("warming up");
        assert_eq!(err.to_string(), "warming up");
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.NotReady");

        let err = BtdError::not_permitted("denied");
        assert_eq!(err.to_string(), "denied");
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.NotPermitted");
    }

    #[test]
    fn test_bredr_errno_mapping() {
        // EALREADY -> already connected
        assert_eq!(
            btd_error_bredr_str(-(Errno::EALREADY as i32)),
            ERR_BREDR_CONN_ALREADY_CONNECTED
        );
        // EISCONN -> already connected
        assert_eq!(btd_error_bredr_str(-(Errno::EISCONN as i32)), ERR_BREDR_CONN_ALREADY_CONNECTED);
        // EHOSTDOWN -> page timeout
        assert_eq!(btd_error_bredr_str(-(Errno::EHOSTDOWN as i32)), ERR_BREDR_CONN_PAGE_TIMEOUT);
        // EIO -> create socket
        assert_eq!(btd_error_bredr_str(-(Errno::EIO as i32)), ERR_BREDR_CONN_CREATE_SOCKET);
        // EINVAL -> invalid arguments
        assert_eq!(btd_error_bredr_str(-(Errno::EINVAL as i32)), ERR_BREDR_CONN_INVALID_ARGUMENTS);
        // EHOSTUNREACH -> adapter not powered
        assert_eq!(
            btd_error_bredr_str(-(Errno::EHOSTUNREACH as i32)),
            ERR_BREDR_CONN_ADAPTER_NOT_POWERED
        );
        // EOPNOTSUPP -> not supported
        assert_eq!(btd_error_bredr_str(-(Errno::EOPNOTSUPP as i32)), ERR_BREDR_CONN_NOT_SUPPORTED);
        // EPROTONOSUPPORT -> not supported
        assert_eq!(
            btd_error_bredr_str(-(Errno::EPROTONOSUPPORT as i32)),
            ERR_BREDR_CONN_NOT_SUPPORTED
        );
        // EBADFD -> bad socket
        assert_eq!(btd_error_bredr_str(-(Errno::EBADFD as i32)), ERR_BREDR_CONN_BAD_SOCKET);
        // ENOMEM -> memory alloc
        assert_eq!(btd_error_bredr_str(-(Errno::ENOMEM as i32)), ERR_BREDR_CONN_MEMORY_ALLOC);
        // EBUSY -> busy
        assert_eq!(btd_error_bredr_str(-(Errno::EBUSY as i32)), ERR_BREDR_CONN_BUSY);
        // EMLINK -> concurrent connect limit
        assert_eq!(btd_error_bredr_str(-(Errno::EMLINK as i32)), ERR_BREDR_CONN_CNCR_CONNECT_LIMIT);
        // ETIMEDOUT -> timeout
        assert_eq!(btd_error_bredr_str(-(Errno::ETIMEDOUT as i32)), ERR_BREDR_CONN_TIMEOUT);
        // ECONNREFUSED -> refused
        assert_eq!(btd_error_bredr_str(-(Errno::ECONNREFUSED as i32)), ERR_BREDR_CONN_REFUSED);
        // ECONNRESET -> abort by remote
        assert_eq!(
            btd_error_bredr_str(-(Errno::ECONNRESET as i32)),
            ERR_BREDR_CONN_ABORT_BY_REMOTE
        );
        // ECONNABORTED -> abort by local
        assert_eq!(
            btd_error_bredr_str(-(Errno::ECONNABORTED as i32)),
            ERR_BREDR_CONN_ABORT_BY_LOCAL
        );
        // EPROTO -> LMP protocol error
        assert_eq!(btd_error_bredr_str(-(Errno::EPROTO as i32)), ERR_BREDR_CONN_LMP_PROTO_ERROR);
        // EBADE -> key missing
        assert_eq!(btd_error_bredr_str(-(Errno::EBADE as i32)), ERR_BREDR_CONN_KEY_MISSING);
        // Unknown errno -> unknown
        assert_eq!(btd_error_bredr_str(-(Errno::EPERM as i32)), ERR_BREDR_CONN_UNKNOWN);
    }

    #[test]
    fn test_le_errno_mapping() {
        assert_eq!(btd_error_le_str(-(Errno::EINVAL as i32)), ERR_LE_CONN_INVALID_ARGUMENTS);
        assert_eq!(
            btd_error_le_str(-(Errno::EHOSTUNREACH as i32)),
            ERR_LE_CONN_ADAPTER_NOT_POWERED
        );
        assert_eq!(btd_error_le_str(-(Errno::EOPNOTSUPP as i32)), ERR_LE_CONN_NOT_SUPPORTED);
        assert_eq!(btd_error_le_str(-(Errno::EPROTONOSUPPORT as i32)), ERR_LE_CONN_NOT_SUPPORTED);
        assert_eq!(btd_error_le_str(-(Errno::EALREADY as i32)), ERR_LE_CONN_ALREADY_CONNECTED);
        assert_eq!(btd_error_le_str(-(Errno::EISCONN as i32)), ERR_LE_CONN_ALREADY_CONNECTED);
        assert_eq!(btd_error_le_str(-(Errno::EBADFD as i32)), ERR_LE_CONN_BAD_SOCKET);
        assert_eq!(btd_error_le_str(-(Errno::ENOMEM as i32)), ERR_LE_CONN_MEMORY_ALLOC);
        assert_eq!(btd_error_le_str(-(Errno::EBUSY as i32)), ERR_LE_CONN_BUSY);
        assert_eq!(btd_error_le_str(-(Errno::ECONNREFUSED as i32)), ERR_LE_CONN_REFUSED);
        assert_eq!(btd_error_le_str(-(Errno::EIO as i32)), ERR_LE_CONN_CREATE_SOCKET);
        assert_eq!(btd_error_le_str(-(Errno::ETIMEDOUT as i32)), ERR_LE_CONN_TIMEOUT);
        assert_eq!(btd_error_le_str(-(Errno::EMLINK as i32)), ERR_LE_CONN_SYNC_CONNECT_LIMIT);
        assert_eq!(btd_error_le_str(-(Errno::ECONNRESET as i32)), ERR_LE_CONN_ABORT_BY_REMOTE);
        assert_eq!(btd_error_le_str(-(Errno::ECONNABORTED as i32)), ERR_LE_CONN_ABORT_BY_LOCAL);
        assert_eq!(btd_error_le_str(-(Errno::EPROTO as i32)), ERR_LE_CONN_LL_PROTO_ERROR);
        assert_eq!(btd_error_le_str(-(Errno::EBADE as i32)), ERR_LE_CONN_KEY_MISSING);
        assert_eq!(btd_error_le_str(-(Errno::EPERM as i32)), ERR_LE_CONN_UNKNOWN);
    }

    #[test]
    fn test_btd_error_bredr_errno_enoprotoopt() {
        // ENOPROTOOPT should map to ProfileUnavailable
        let err = btd_error_bredr_errno(Errno::ENOPROTOOPT as i32);
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.BREDR.ProfileUnavailable");
        assert_eq!(err.to_string(), "No more profiles to connect to");
    }

    #[test]
    fn test_btd_error_bredr_errno_regular() {
        // Regular errno values produce Failed with the bredr string
        let err = btd_error_bredr_errno(-(Errno::EHOSTDOWN as i32));
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.Failed");
        assert_eq!(err.to_string(), ERR_BREDR_CONN_PAGE_TIMEOUT);
    }

    #[test]
    fn test_btd_error_le_errno() {
        let err = btd_error_le_errno(-(Errno::EINVAL as i32));
        assert_eq!(err.dbus_error_name(), "org.bluez.Error.Failed");
        assert_eq!(err.to_string(), ERR_LE_CONN_INVALID_ARGUMENTS);
    }

    #[test]
    fn test_zbus_dbus_error_trait() {
        use zbus::DBusError;

        let err = BtdError::invalid_args();
        assert_eq!(err.name().as_str(), "org.bluez.Error.InvalidArguments");
        assert_eq!(err.description(), Some("Invalid arguments in method call"));

        let err = BtdError::profile_unavailable();
        assert_eq!(err.name().as_str(), "org.bluez.Error.BREDR.ProfileUnavailable");
        assert_eq!(err.description(), Some("No more profiles to connect to"));
    }

    #[test]
    fn test_bredr_connection_error_strings() {
        assert_eq!(ERR_BREDR_CONN_ALREADY_CONNECTED, "br-connection-already-connected");
        assert_eq!(ERR_BREDR_CONN_PAGE_TIMEOUT, "br-connection-page-timeout");
        assert_eq!(ERR_BREDR_CONN_SDP_SEARCH, "br-connection-sdp-search");
        assert_eq!(ERR_BREDR_CONN_CREATE_SOCKET, "br-connection-create-socket");
        assert_eq!(ERR_BREDR_CONN_INVALID_ARGUMENTS, "br-connection-invalid-argument");
        assert_eq!(ERR_BREDR_CONN_ADAPTER_NOT_POWERED, "br-connection-adapter-not-powered");
        assert_eq!(ERR_BREDR_CONN_NOT_SUPPORTED, "br-connection-not-supported");
        assert_eq!(ERR_BREDR_CONN_BAD_SOCKET, "br-connection-bad-socket");
        assert_eq!(ERR_BREDR_CONN_MEMORY_ALLOC, "br-connection-memory-allocation");
        assert_eq!(ERR_BREDR_CONN_BUSY, "br-connection-busy");
        assert_eq!(ERR_BREDR_CONN_CNCR_CONNECT_LIMIT, "br-connection-concurrent-connection-limit");
        assert_eq!(ERR_BREDR_CONN_TIMEOUT, "br-connection-timeout");
        assert_eq!(ERR_BREDR_CONN_REFUSED, "br-connection-refused");
        assert_eq!(ERR_BREDR_CONN_ABORT_BY_REMOTE, "br-connection-aborted-by-remote");
        assert_eq!(ERR_BREDR_CONN_ABORT_BY_LOCAL, "br-connection-aborted-by-local");
        assert_eq!(ERR_BREDR_CONN_LMP_PROTO_ERROR, "br-connection-lmp-protocol-error");
        assert_eq!(ERR_BREDR_CONN_CANCELED, "br-connection-canceled");
        assert_eq!(ERR_BREDR_CONN_KEY_MISSING, "br-connection-key-missing");
        assert_eq!(ERR_BREDR_CONN_UNKNOWN, "br-connection-unknown");
    }

    #[test]
    fn test_le_connection_error_strings() {
        assert_eq!(ERR_LE_CONN_INVALID_ARGUMENTS, "le-connection-invalid-arguments");
        assert_eq!(ERR_LE_CONN_ADAPTER_NOT_POWERED, "le-connection-adapter-not-powered");
        assert_eq!(ERR_LE_CONN_NOT_SUPPORTED, "le-connection-not-supported");
        assert_eq!(ERR_LE_CONN_ALREADY_CONNECTED, "le-connection-already-connected");
        assert_eq!(ERR_LE_CONN_BAD_SOCKET, "le-connection-bad-socket");
        assert_eq!(ERR_LE_CONN_MEMORY_ALLOC, "le-connection-memory-allocation");
        assert_eq!(ERR_LE_CONN_BUSY, "le-connection-busy");
        assert_eq!(ERR_LE_CONN_REFUSED, "le-connection-refused");
        assert_eq!(ERR_LE_CONN_CREATE_SOCKET, "le-connection-create-socket");
        assert_eq!(ERR_LE_CONN_TIMEOUT, "le-connection-timeout");
        assert_eq!(ERR_LE_CONN_SYNC_CONNECT_LIMIT, "le-connection-concurrent-connection-limit");
        assert_eq!(ERR_LE_CONN_ABORT_BY_REMOTE, "le-connection-abort-by-remote");
        assert_eq!(ERR_LE_CONN_ABORT_BY_LOCAL, "le-connection-abort-by-local");
        assert_eq!(ERR_LE_CONN_LL_PROTO_ERROR, "le-connection-link-layer-protocol-error");
        assert_eq!(ERR_LE_CONN_GATT_BROWSE, "le-connection-gatt-browsing");
        assert_eq!(ERR_LE_CONN_KEY_MISSING, "le-connection-key-missing");
        assert_eq!(ERR_LE_CONN_UNKNOWN, "le-connection-unknown");
    }

    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(BtdError::invalid_args());
        assert_eq!(err.to_string(), "Invalid arguments in method call");
    }

    #[test]
    fn test_error_clone() {
        let err = BtdError::failed("cloneable");
        let err2 = err.clone();
        assert_eq!(err.to_string(), err2.to_string());
        assert_eq!(err.dbus_error_name(), err2.dbus_error_name());
    }
}
