// SPDX-License-Identifier: GPL-2.0-or-later
//
// D-Bus error definitions replacing src/error.c/error.h

use std::fmt;

/// Standard BlueZ D-Bus error names.
pub const ERROR_REJECTED: &str = "org.bluez.Error.Rejected";
pub const ERROR_CANCELED: &str = "org.bluez.Error.Canceled";
pub const ERROR_INVALID_ARGUMENTS: &str = "org.bluez.Error.InvalidArguments";
pub const ERROR_ALREADY_EXISTS: &str = "org.bluez.Error.AlreadyExists";
pub const ERROR_DOES_NOT_EXIST: &str = "org.bluez.Error.DoesNotExist";
pub const ERROR_IN_PROGRESS: &str = "org.bluez.Error.InProgress";
pub const ERROR_NOT_IN_PROGRESS: &str = "org.bluez.Error.NotInProgress";
pub const ERROR_ALREADY_CONNECTED: &str = "org.bluez.Error.AlreadyConnected";
pub const ERROR_NOT_CONNECTED: &str = "org.bluez.Error.NotConnected";
pub const ERROR_NOT_SUPPORTED: &str = "org.bluez.Error.NotSupported";
pub const ERROR_NOT_AUTHORIZED: &str = "org.bluez.Error.NotAuthorized";
pub const ERROR_NOT_AVAILABLE: &str = "org.bluez.Error.NotAvailable";
pub const ERROR_NOT_READY: &str = "org.bluez.Error.NotReady";
pub const ERROR_FAILED: &str = "org.bluez.Error.Failed";
pub const ERROR_NOT_PERMITTED: &str = "org.bluez.Error.NotPermitted";
pub const ERROR_AUTH_CANCELED: &str = "org.bluez.Error.AuthenticationCanceled";
pub const ERROR_AUTH_FAILED: &str = "org.bluez.Error.AuthenticationFailed";
pub const ERROR_AUTH_REJECTED: &str = "org.bluez.Error.AuthenticationRejected";
pub const ERROR_AUTH_TIMEOUT: &str = "org.bluez.Error.AuthenticationTimeout";
pub const ERROR_CONNECTION_ATTEMPT_FAILED: &str = "org.bluez.Error.ConnectionAttemptFailed";

/// A BlueZ D-Bus error.
#[derive(Debug, Clone)]
pub struct BtdError {
    pub name: &'static str,
    pub message: String,
}

impl BtdError {
    pub fn new(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            message: message.into(),
        }
    }

    pub fn failed(msg: impl Into<String>) -> Self {
        Self::new(ERROR_FAILED, msg)
    }

    pub fn not_ready(msg: impl Into<String>) -> Self {
        Self::new(ERROR_NOT_READY, msg)
    }

    pub fn not_supported(msg: impl Into<String>) -> Self {
        Self::new(ERROR_NOT_SUPPORTED, msg)
    }

    pub fn invalid_arguments(msg: impl Into<String>) -> Self {
        Self::new(ERROR_INVALID_ARGUMENTS, msg)
    }

    pub fn not_available(msg: impl Into<String>) -> Self {
        Self::new(ERROR_NOT_AVAILABLE, msg)
    }

    pub fn in_progress(msg: impl Into<String>) -> Self {
        Self::new(ERROR_IN_PROGRESS, msg)
    }

    pub fn already_connected(msg: impl Into<String>) -> Self {
        Self::new(ERROR_ALREADY_CONNECTED, msg)
    }

    pub fn not_connected(msg: impl Into<String>) -> Self {
        Self::new(ERROR_NOT_CONNECTED, msg)
    }
}

impl fmt::Display for BtdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.message)
    }
}

impl std::error::Error for BtdError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BtdError::failed("test error");
        assert_eq!(err.to_string(), "org.bluez.Error.Failed: test error");
    }

    #[test]
    fn test_error_constructors() {
        assert_eq!(BtdError::not_ready("x").name, ERROR_NOT_READY);
        assert_eq!(BtdError::not_supported("x").name, ERROR_NOT_SUPPORTED);
        assert_eq!(BtdError::invalid_arguments("x").name, ERROR_INVALID_ARGUMENTS);
        assert_eq!(BtdError::in_progress("x").name, ERROR_IN_PROGRESS);
    }
}
