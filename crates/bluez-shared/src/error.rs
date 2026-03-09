// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite

use std::fmt;

/// Top-level error type for bluez-shared operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("HCI error: {0}")]
    Hci(HciError),
    #[error("management error: {0}")]
    Mgmt(MgmtStatus),
    #[error("ATT error: {0}")]
    Att(AttError),
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid parameters")]
    InvalidParams,
    #[error("not supported")]
    NotSupported,
}

/// HCI error codes from the Bluetooth specification (Core Spec Vol 1, Part F).
/// Values from `monitor/bt.h` `BT_HCI_ERR_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HciError {
    Success = 0x00,
    UnknownCommand = 0x01,
    UnknownConnectionId = 0x02,
    HardwareFailure = 0x03,
    PageTimeout = 0x04,
    AuthFailure = 0x05,
    PinOrKeyMissing = 0x06,
    MemCapacityExceeded = 0x07,
    ConnectionTimeout = 0x08,
    ConnectionLimitExceeded = 0x09,
    SyncConnectionLimitExceeded = 0x0A,
    ConnectionAlreadyExists = 0x0B,
    CommandDisallowed = 0x0C,
    RejectedLimitedResources = 0x0D,
    RejectedSecurity = 0x0E,
    RejectedBdAddr = 0x0F,
    ConnectionAcceptTimeout = 0x10,
    UnsupportedFeature = 0x11,
    InvalidParameters = 0x12,
    RemoteUserTerminated = 0x13,
    RemoteLowResources = 0x14,
    RemotePowerOff = 0x15,
    LocalHostTerminated = 0x16,
    RepeatedAttempts = 0x17,
    PairingNotAllowed = 0x18,
    UnknownLmpPdu = 0x19,
    UnsupportedRemoteFeature = 0x1A,
    ScoOffsetRejected = 0x1B,
    ScoIntervalRejected = 0x1C,
    ScoAirModeRejected = 0x1D,
    InvalidLmpParameters = 0x1E,
    UnspecifiedError = 0x1F,
    UnsupportedLmpParameterValue = 0x20,
    RoleChangeNotAllowed = 0x21,
    LmpResponseTimeout = 0x22,
    LmpTransactionCollision = 0x23,
    LmpPduNotAllowed = 0x24,
    EncModeNotAcceptable = 0x25,
    LinkKeyCannotBeChanged = 0x26,
    RequestedQosNotSupported = 0x27,
    InstantPassed = 0x28,
    PairingWithUnitKeyNotSupported = 0x29,
    DifferentTransactionCollision = 0x2A,
    QosUnacceptableParameter = 0x2C,
    QosRejected = 0x2D,
    ChannelClassNotSupported = 0x2E,
    InsufficientSecurity = 0x2F,
    ParameterOutOfRange = 0x30,
    RoleSwitchPending = 0x32,
    ReservedSlotViolation = 0x34,
    RoleSwitchFailed = 0x35,
    ExtInquiryResponseTooLarge = 0x36,
    SimplePairingNotSupported = 0x37,
    HostBusyPairing = 0x38,
    ConnectionRejectedNoChannel = 0x39,
    ControllerBusy = 0x3A,
    UnacceptableConnectionParameters = 0x3B,
    AdvTimeout = 0x3C,
    ConnectionTerminatedMicFailure = 0x3D,
    ConnectionFailedToEstablish = 0x3E,
    MacConnectionFailed = 0x3F,
    CoarseClockAdjRejected = 0x40,
    Type0SubmapNotDefined = 0x41,
    UnknownAdvertisingId = 0x42,
    LimitReached = 0x43,
    Cancelled = 0x44,
    PacketTooLong = 0x45,
}

impl HciError {
    pub fn from_u8(code: u8) -> Option<Self> {
        // Only valid codes
        match code {
            0x00 => Some(Self::Success),
            0x01 => Some(Self::UnknownCommand),
            0x02 => Some(Self::UnknownConnectionId),
            0x03 => Some(Self::HardwareFailure),
            0x04 => Some(Self::PageTimeout),
            0x05 => Some(Self::AuthFailure),
            0x06 => Some(Self::PinOrKeyMissing),
            0x07 => Some(Self::MemCapacityExceeded),
            0x08 => Some(Self::ConnectionTimeout),
            0x09 => Some(Self::ConnectionLimitExceeded),
            0x0A => Some(Self::SyncConnectionLimitExceeded),
            0x0B => Some(Self::ConnectionAlreadyExists),
            0x0C => Some(Self::CommandDisallowed),
            0x0D => Some(Self::RejectedLimitedResources),
            0x0E => Some(Self::RejectedSecurity),
            0x0F => Some(Self::RejectedBdAddr),
            0x10 => Some(Self::ConnectionAcceptTimeout),
            0x11 => Some(Self::UnsupportedFeature),
            0x12 => Some(Self::InvalidParameters),
            0x13 => Some(Self::RemoteUserTerminated),
            0x14 => Some(Self::RemoteLowResources),
            0x15 => Some(Self::RemotePowerOff),
            0x16 => Some(Self::LocalHostTerminated),
            0x17 => Some(Self::RepeatedAttempts),
            0x18 => Some(Self::PairingNotAllowed),
            0x19 => Some(Self::UnknownLmpPdu),
            0x1A => Some(Self::UnsupportedRemoteFeature),
            0x1B => Some(Self::ScoOffsetRejected),
            0x1C => Some(Self::ScoIntervalRejected),
            0x1D => Some(Self::ScoAirModeRejected),
            0x1E => Some(Self::InvalidLmpParameters),
            0x1F => Some(Self::UnspecifiedError),
            0x20 => Some(Self::UnsupportedLmpParameterValue),
            0x21 => Some(Self::RoleChangeNotAllowed),
            0x22 => Some(Self::LmpResponseTimeout),
            0x23 => Some(Self::LmpTransactionCollision),
            0x24 => Some(Self::LmpPduNotAllowed),
            0x25 => Some(Self::EncModeNotAcceptable),
            0x26 => Some(Self::LinkKeyCannotBeChanged),
            0x27 => Some(Self::RequestedQosNotSupported),
            0x28 => Some(Self::InstantPassed),
            0x29 => Some(Self::PairingWithUnitKeyNotSupported),
            0x2A => Some(Self::DifferentTransactionCollision),
            0x2C => Some(Self::QosUnacceptableParameter),
            0x2D => Some(Self::QosRejected),
            0x2E => Some(Self::ChannelClassNotSupported),
            0x2F => Some(Self::InsufficientSecurity),
            0x30 => Some(Self::ParameterOutOfRange),
            0x32 => Some(Self::RoleSwitchPending),
            0x34 => Some(Self::ReservedSlotViolation),
            0x35 => Some(Self::RoleSwitchFailed),
            0x36 => Some(Self::ExtInquiryResponseTooLarge),
            0x37 => Some(Self::SimplePairingNotSupported),
            0x38 => Some(Self::HostBusyPairing),
            0x39 => Some(Self::ConnectionRejectedNoChannel),
            0x3A => Some(Self::ControllerBusy),
            0x3B => Some(Self::UnacceptableConnectionParameters),
            0x3C => Some(Self::AdvTimeout),
            0x3D => Some(Self::ConnectionTerminatedMicFailure),
            0x3E => Some(Self::ConnectionFailedToEstablish),
            0x3F => Some(Self::MacConnectionFailed),
            0x40 => Some(Self::CoarseClockAdjRejected),
            0x41 => Some(Self::Type0SubmapNotDefined),
            0x42 => Some(Self::UnknownAdvertisingId),
            0x43 => Some(Self::LimitReached),
            0x44 => Some(Self::Cancelled),
            0x45 => Some(Self::PacketTooLong),
            _ => None,
        }
    }
}

impl fmt::Display for HciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Success => "Success",
            Self::UnknownCommand => "Unknown HCI Command",
            Self::UnknownConnectionId => "Unknown Connection Identifier",
            Self::HardwareFailure => "Hardware Failure",
            Self::PageTimeout => "Page Timeout",
            Self::AuthFailure => "Authentication Failure",
            Self::PinOrKeyMissing => "PIN or Key Missing",
            Self::MemCapacityExceeded => "Memory Capacity Exceeded",
            Self::ConnectionTimeout => "Connection Timeout",
            Self::ConnectionLimitExceeded => "Connection Limit Exceeded",
            Self::SyncConnectionLimitExceeded => "Synchronous Connection Limit Exceeded",
            Self::ConnectionAlreadyExists => "Connection Already Exists",
            Self::CommandDisallowed => "Command Disallowed",
            Self::RejectedLimitedResources => "Connection Rejected Limited Resources",
            Self::RejectedSecurity => "Connection Rejected Security Reasons",
            Self::RejectedBdAddr => "Connection Rejected Unacceptable BD_ADDR",
            Self::ConnectionAcceptTimeout => "Connection Accept Timeout Exceeded",
            Self::UnsupportedFeature => "Unsupported Feature or Parameter Value",
            Self::InvalidParameters => "Invalid HCI Command Parameters",
            Self::RemoteUserTerminated => "Remote User Terminated Connection",
            Self::RemoteLowResources => "Remote Device Terminated Low Resources",
            Self::RemotePowerOff => "Remote Device Terminated Power Off",
            Self::LocalHostTerminated => "Connection Terminated by Local Host",
            Self::RepeatedAttempts => "Repeated Attempts",
            Self::PairingNotAllowed => "Pairing Not Allowed",
            Self::UnknownLmpPdu => "Unknown LMP PDU",
            Self::UnsupportedRemoteFeature => "Unsupported Remote Feature",
            Self::ScoOffsetRejected => "SCO Offset Rejected",
            Self::ScoIntervalRejected => "SCO Interval Rejected",
            Self::ScoAirModeRejected => "SCO Air Mode Rejected",
            Self::InvalidLmpParameters => "Invalid LMP Parameters",
            Self::UnspecifiedError => "Unspecified Error",
            Self::UnsupportedLmpParameterValue => "Unsupported LMP Parameter Value",
            Self::RoleChangeNotAllowed => "Role Change Not Allowed",
            Self::LmpResponseTimeout => "LMP Response Timeout",
            Self::LmpTransactionCollision => "LMP/LL Error Transaction Collision",
            Self::LmpPduNotAllowed => "LMP PDU Not Allowed",
            Self::EncModeNotAcceptable => "Encryption Mode Not Acceptable",
            Self::LinkKeyCannotBeChanged => "Link Key Cannot Be Changed",
            Self::RequestedQosNotSupported => "Requested QoS Not Supported",
            Self::InstantPassed => "Instant Passed",
            Self::PairingWithUnitKeyNotSupported => "Pairing With Unit Key Not Supported",
            Self::DifferentTransactionCollision => "Different Transaction Collision",
            Self::QosUnacceptableParameter => "QoS Unacceptable Parameter",
            Self::QosRejected => "QoS Rejected",
            Self::ChannelClassNotSupported => "Channel Classification Not Supported",
            Self::InsufficientSecurity => "Insufficient Security",
            Self::ParameterOutOfRange => "Parameter Out Of Mandatory Range",
            Self::RoleSwitchPending => "Role Switch Pending",
            Self::ReservedSlotViolation => "Reserved Slot Violation",
            Self::RoleSwitchFailed => "Role Switch Failed",
            Self::ExtInquiryResponseTooLarge => "Extended Inquiry Response Too Large",
            Self::SimplePairingNotSupported => "Secure Simple Pairing Not Supported",
            Self::HostBusyPairing => "Host Busy - Pairing",
            Self::ConnectionRejectedNoChannel => "Connection Rejected - No Suitable Channel",
            Self::ControllerBusy => "Controller Busy",
            Self::UnacceptableConnectionParameters => "Unacceptable Connection Parameters",
            Self::AdvTimeout => "Advertising Timeout",
            Self::ConnectionTerminatedMicFailure => "Connection Terminated MIC Failure",
            Self::ConnectionFailedToEstablish => "Connection Failed to be Established",
            Self::MacConnectionFailed => "MAC Connection Failed",
            Self::CoarseClockAdjRejected => "Coarse Clock Adjustment Rejected",
            Self::Type0SubmapNotDefined => "Type0 Submap Not Defined",
            Self::UnknownAdvertisingId => "Unknown Advertising Identifier",
            Self::LimitReached => "Limit Reached",
            Self::Cancelled => "Operation Cancelled by Host",
            Self::PacketTooLong => "Packet Too Long",
        };
        f.write_str(s)
    }
}

/// Management API status codes. Corresponds to `MGMT_STATUS_*` from `mgmt.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MgmtStatus {
    Success = 0x00,
    UnknownCommand = 0x01,
    NotConnected = 0x02,
    Failed = 0x03,
    ConnectFailed = 0x04,
    AuthFailed = 0x05,
    NotPaired = 0x06,
    NoResources = 0x07,
    Timeout = 0x08,
    AlreadyConnected = 0x09,
    Busy = 0x0A,
    Rejected = 0x0B,
    NotSupported = 0x0C,
    InvalidParams = 0x0D,
    Disconnected = 0x0E,
    NotPowered = 0x0F,
    Cancelled = 0x10,
    InvalidIndex = 0x11,
    Rfkilled = 0x12,
    AlreadyPaired = 0x13,
    PermissionDenied = 0x14,
}

impl MgmtStatus {
    pub fn from_u8(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Success),
            0x01 => Some(Self::UnknownCommand),
            0x02 => Some(Self::NotConnected),
            0x03 => Some(Self::Failed),
            0x04 => Some(Self::ConnectFailed),
            0x05 => Some(Self::AuthFailed),
            0x06 => Some(Self::NotPaired),
            0x07 => Some(Self::NoResources),
            0x08 => Some(Self::Timeout),
            0x09 => Some(Self::AlreadyConnected),
            0x0A => Some(Self::Busy),
            0x0B => Some(Self::Rejected),
            0x0C => Some(Self::NotSupported),
            0x0D => Some(Self::InvalidParams),
            0x0E => Some(Self::Disconnected),
            0x0F => Some(Self::NotPowered),
            0x10 => Some(Self::Cancelled),
            0x11 => Some(Self::InvalidIndex),
            0x12 => Some(Self::Rfkilled),
            0x13 => Some(Self::AlreadyPaired),
            0x14 => Some(Self::PermissionDenied),
            _ => None,
        }
    }

    pub fn is_success(&self) -> bool {
        *self == Self::Success
    }
}

impl fmt::Display for MgmtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Success => "Success",
            Self::UnknownCommand => "Unknown Command",
            Self::NotConnected => "Not Connected",
            Self::Failed => "Failed",
            Self::ConnectFailed => "Connect Failed",
            Self::AuthFailed => "Authentication Failed",
            Self::NotPaired => "Not Paired",
            Self::NoResources => "No Resources",
            Self::Timeout => "Timeout",
            Self::AlreadyConnected => "Already Connected",
            Self::Busy => "Busy",
            Self::Rejected => "Rejected",
            Self::NotSupported => "Not Supported",
            Self::InvalidParams => "Invalid Parameters",
            Self::Disconnected => "Disconnected",
            Self::NotPowered => "Not Powered",
            Self::Cancelled => "Cancelled",
            Self::InvalidIndex => "Invalid Index",
            Self::Rfkilled => "RFKilled",
            Self::AlreadyPaired => "Already Paired",
            Self::PermissionDenied => "Permission Denied",
        };
        f.write_str(s)
    }
}

/// ATT protocol error codes. Corresponds to `BT_ATT_ERROR_*` from `att-types.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AttError {
    InvalidHandle = 0x01,
    ReadNotPermitted = 0x02,
    WriteNotPermitted = 0x03,
    InvalidPdu = 0x04,
    Authentication = 0x05,
    RequestNotSupported = 0x06,
    InvalidOffset = 0x07,
    Authorization = 0x08,
    PrepareQueueFull = 0x09,
    AttributeNotFound = 0x0A,
    AttributeNotLong = 0x0B,
    InsufficientEncryptionKeySize = 0x0C,
    InvalidAttributeValueLen = 0x0D,
    Unlikely = 0x0E,
    InsufficientEncryption = 0x0F,
    UnsupportedGroupType = 0x10,
    InsufficientResources = 0x11,
    DbOutOfSync = 0x12,
    ValueNotAllowed = 0x13,
    // Application/profile error range: 0x80-0x9F
    // Common profile errors
    WriteRequestRejected = 0xFC,
    CccImproperlyConfigured = 0xFD,
    AlreadyInProgress = 0xFE,
    OutOfRange = 0xFF,
}

impl AttError {
    pub fn from_u8(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::InvalidHandle),
            0x02 => Some(Self::ReadNotPermitted),
            0x03 => Some(Self::WriteNotPermitted),
            0x04 => Some(Self::InvalidPdu),
            0x05 => Some(Self::Authentication),
            0x06 => Some(Self::RequestNotSupported),
            0x07 => Some(Self::InvalidOffset),
            0x08 => Some(Self::Authorization),
            0x09 => Some(Self::PrepareQueueFull),
            0x0A => Some(Self::AttributeNotFound),
            0x0B => Some(Self::AttributeNotLong),
            0x0C => Some(Self::InsufficientEncryptionKeySize),
            0x0D => Some(Self::InvalidAttributeValueLen),
            0x0E => Some(Self::Unlikely),
            0x0F => Some(Self::InsufficientEncryption),
            0x10 => Some(Self::UnsupportedGroupType),
            0x11 => Some(Self::InsufficientResources),
            0x12 => Some(Self::DbOutOfSync),
            0x13 => Some(Self::ValueNotAllowed),
            0xFC => Some(Self::WriteRequestRejected),
            0xFD => Some(Self::CccImproperlyConfigured),
            0xFE => Some(Self::AlreadyInProgress),
            0xFF => Some(Self::OutOfRange),
            _ => None,
        }
    }
}

impl fmt::Display for AttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidHandle => "Invalid Handle",
            Self::ReadNotPermitted => "Read Not Permitted",
            Self::WriteNotPermitted => "Write Not Permitted",
            Self::InvalidPdu => "Invalid PDU",
            Self::Authentication => "Authentication Required",
            Self::RequestNotSupported => "Request Not Supported",
            Self::InvalidOffset => "Invalid Offset",
            Self::Authorization => "Authorization Required",
            Self::PrepareQueueFull => "Prepare Queue Full",
            Self::AttributeNotFound => "Attribute Not Found",
            Self::AttributeNotLong => "Attribute Not Long",
            Self::InsufficientEncryptionKeySize => "Insufficient Encryption Key Size",
            Self::InvalidAttributeValueLen => "Invalid Attribute Value Length",
            Self::Unlikely => "Unlikely Error",
            Self::InsufficientEncryption => "Insufficient Encryption",
            Self::UnsupportedGroupType => "Unsupported Group Type",
            Self::InsufficientResources => "Insufficient Resources",
            Self::DbOutOfSync => "Database Out of Sync",
            Self::ValueNotAllowed => "Value Not Allowed",
            Self::WriteRequestRejected => "Write Request Rejected",
            Self::CccImproperlyConfigured => "CCC Improperly Configured",
            Self::AlreadyInProgress => "Already in Progress",
            Self::OutOfRange => "Out of Range",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hci_error_roundtrip() {
        for code in 0x00..=0x45u8 {
            if let Some(e) = HciError::from_u8(code) {
                assert_eq!(e as u8, code);
                // Ensure Display doesn't panic
                let _ = e.to_string();
            }
        }
    }

    #[test]
    fn test_hci_error_specific() {
        assert_eq!(HciError::from_u8(0x00), Some(HciError::Success));
        assert_eq!(HciError::from_u8(0x05), Some(HciError::AuthFailure));
        assert_eq!(HciError::from_u8(0x16), Some(HciError::LocalHostTerminated));
        assert_eq!(HciError::from_u8(0x3E), Some(HciError::ConnectionFailedToEstablish));
        assert_eq!(HciError::from_u8(0xFF), None);
    }

    #[test]
    fn test_mgmt_status_roundtrip() {
        for code in 0x00..=0x14u8 {
            let status = MgmtStatus::from_u8(code).unwrap();
            assert_eq!(status as u8, code);
            let _ = status.to_string();
        }
        assert_eq!(MgmtStatus::from_u8(0x15), None);
    }

    #[test]
    fn test_mgmt_status_success() {
        assert!(MgmtStatus::Success.is_success());
        assert!(!MgmtStatus::Failed.is_success());
    }

    #[test]
    fn test_att_error_roundtrip() {
        let codes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0xFC, 0xFD, 0xFE, 0xFF,
        ];
        for code in codes {
            let e = AttError::from_u8(code).unwrap();
            assert_eq!(e as u8, code);
            let _ = e.to_string();
        }
        assert_eq!(AttError::from_u8(0x00), None);
        assert_eq!(AttError::from_u8(0x80), None);
    }

    #[test]
    fn test_error_enum() {
        let e = Error::Hci(HciError::AuthFailure);
        assert!(e.to_string().contains("Authentication Failure"));

        let e = Error::Mgmt(MgmtStatus::NotPowered);
        assert!(e.to_string().contains("Not Powered"));

        let e = Error::Att(AttError::InvalidHandle);
        assert!(e.to_string().contains("Invalid Handle"));
    }
}
