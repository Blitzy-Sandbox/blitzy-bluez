// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2014 Google Inc.
// Copyright 2023 NXP

//! ATT (Attribute Protocol) type definitions.
//!
//! This module is a complete Rust rewrite of `src/shared/att-types.h` from the
//! BlueZ C codebase. It defines all ATT protocol constants, opcodes, error
//! codes, permission bitflags, GATT property bitflags, and packed PDU
//! structures used throughout the Bluetooth stack.
//!
//! All constant values are wire-format compatible with the original C
//! definitions and have been verified byte-for-byte against the C header.
//!
//! Both typed Rust enums and raw integer constants (matching the C `#define`
//! names exactly) are provided for maximum flexibility and interoperability
//! with code that operates on raw protocol bytes.
//!
//! Bitfield types use the [`bitflags`] crate for type-safe bitwise
//! manipulation of ATT permissions, GATT characteristic properties, extended
//! properties, and client/server feature flags.

use bitflags::bitflags;

// =====================================================================
// Channel and Transport Constants
// =====================================================================

/// ATT fixed L2CAP channel ID (CID 4).
pub const BT_ATT_CID: u16 = 4;

/// ATT fixed L2CAP PSM for LE connections.
pub const BT_ATT_PSM: u16 = 31;

/// Enhanced ATT (EATT) L2CAP PSM.
pub const BT_ATT_EATT_PSM: u16 = 0x27;

// =====================================================================
// Security Levels
// =====================================================================

/// ATT security level classification.
///
/// Security levels are ordered from lowest (`Auto`) to highest (`Fips`),
/// matching the kernel `BT_SECURITY_*` constants. The `PartialOrd`/`Ord`
/// derivation follows this natural ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AttSecurityLevel {
    /// Automatic security level selection (no requirement).
    Auto = 0,
    /// Low security — no encryption required.
    Low = 1,
    /// Medium security — encryption required but unauthenticated key allowed.
    Medium = 2,
    /// High security — encryption with an authenticated key required.
    High = 3,
    /// FIPS security — encryption with a FIPS-approved key required.
    Fips = 4,
}

/// Raw constant for [`AttSecurityLevel::Auto`].
pub const BT_ATT_SECURITY_AUTO: u8 = 0;
/// Raw constant for [`AttSecurityLevel::Low`].
pub const BT_ATT_SECURITY_LOW: u8 = 1;
/// Raw constant for [`AttSecurityLevel::Medium`].
pub const BT_ATT_SECURITY_MEDIUM: u8 = 2;
/// Raw constant for [`AttSecurityLevel::High`].
pub const BT_ATT_SECURITY_HIGH: u8 = 3;
/// Raw constant for [`AttSecurityLevel::Fips`].
pub const BT_ATT_SECURITY_FIPS: u8 = 4;

impl TryFrom<u8> for AttSecurityLevel {
    type Error = u8;

    /// Converts a raw `u8` value to an `AttSecurityLevel`.
    ///
    /// Returns `Err(value)` if the value does not correspond to a valid
    /// security level (i.e., not in the range 0..=4).
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Auto),
            1 => Ok(Self::Low),
            2 => Ok(Self::Medium),
            3 => Ok(Self::High),
            4 => Ok(Self::Fips),
            _ => Err(value),
        }
    }
}

// =====================================================================
// MTU Constants
// =====================================================================

/// Default LE ATT MTU (23 bytes), per Bluetooth Core Specification.
pub const BT_ATT_DEFAULT_LE_MTU: u16 = 23;

/// Maximum LE ATT MTU (517 bytes).
pub const BT_ATT_MAX_LE_MTU: u16 = 517;

/// Maximum ATT attribute value length (512 bytes).
pub const BT_ATT_MAX_VALUE_LEN: u16 = 512;

// =====================================================================
// Channel Type Constants
// =====================================================================

/// BR/EDR transport channel type.
pub const BT_ATT_BREDR: u8 = 0x00;

/// LE transport channel type.
pub const BT_ATT_LE: u8 = 0x01;

/// Enhanced ATT (EATT) transport channel type.
pub const BT_ATT_EATT: u8 = 0x02;

/// Local (non-socket) transport for testing purposes.
pub const BT_ATT_LOCAL: u8 = 0xFF;

// =====================================================================
// ATT Protocol Opcodes
// =====================================================================

/// ATT protocol opcode as a typed enum.
///
/// All 31 standard ATT opcodes are represented. Values match the Bluetooth
/// Core Specification and the original C `#define` constants exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AttOpcode {
    /// Error Response (0x01).
    ErrorRsp = 0x01,
    /// Exchange MTU Request (0x02).
    MtuReq = 0x02,
    /// Exchange MTU Response (0x03).
    MtuRsp = 0x03,
    /// Find Information Request (0x04).
    FindInfoReq = 0x04,
    /// Find Information Response (0x05).
    FindInfoRsp = 0x05,
    /// Find By Type Value Request (0x06).
    FindByTypeReq = 0x06,
    /// Find By Type Value Response (0x07).
    FindByTypeRsp = 0x07,
    /// Read By Type Request (0x08).
    ReadByTypeReq = 0x08,
    /// Read By Type Response (0x09).
    ReadByTypeRsp = 0x09,
    /// Read Request (0x0A).
    ReadReq = 0x0A,
    /// Read Response (0x0B).
    ReadRsp = 0x0B,
    /// Read Blob Request (0x0C).
    ReadBlobReq = 0x0C,
    /// Read Blob Response (0x0D).
    ReadBlobRsp = 0x0D,
    /// Read Multiple Request (0x0E).
    ReadMultReq = 0x0E,
    /// Read Multiple Response (0x0F).
    ReadMultRsp = 0x0F,
    /// Read By Group Type Request (0x10).
    ReadByGrpTypeReq = 0x10,
    /// Read By Group Type Response (0x11).
    ReadByGrpTypeRsp = 0x11,
    /// Write Request (0x12).
    WriteReq = 0x12,
    /// Write Response (0x13).
    WriteRsp = 0x13,
    /// Write Command (0x52) — no response expected.
    WriteCmd = 0x52,
    /// Signed Write Command (0xD2) — authenticated, no response.
    SignedWriteCmd = 0xD2,
    /// Prepare Write Request (0x16).
    PrepWriteReq = 0x16,
    /// Prepare Write Response (0x17).
    PrepWriteRsp = 0x17,
    /// Execute Write Request (0x18).
    ExecWriteReq = 0x18,
    /// Execute Write Response (0x19).
    ExecWriteRsp = 0x19,
    /// Handle Value Notification (0x1B) — server-initiated, no confirmation.
    HandleNfy = 0x1B,
    /// Handle Value Indication (0x1D) — server-initiated, confirmation required.
    HandleInd = 0x1D,
    /// Handle Value Confirmation (0x1E).
    HandleConf = 0x1E,
    /// Read Multiple Variable Length Request (0x20).
    ReadMultVlReq = 0x20,
    /// Read Multiple Variable Length Response (0x21).
    ReadMultVlRsp = 0x21,
    /// Handle Value Notification Multiple (0x23).
    HandleNfyMult = 0x23,
}

// Raw opcode constants matching C `#define` names exactly.

/// `BT_ATT_OP_ERROR_RSP` — Error Response.
pub const BT_ATT_OP_ERROR_RSP: u8 = 0x01;
/// `BT_ATT_OP_MTU_REQ` — Exchange MTU Request.
pub const BT_ATT_OP_MTU_REQ: u8 = 0x02;
/// `BT_ATT_OP_MTU_RSP` — Exchange MTU Response.
pub const BT_ATT_OP_MTU_RSP: u8 = 0x03;
/// `BT_ATT_OP_FIND_INFO_REQ` — Find Information Request.
pub const BT_ATT_OP_FIND_INFO_REQ: u8 = 0x04;
/// `BT_ATT_OP_FIND_INFO_RSP` — Find Information Response.
pub const BT_ATT_OP_FIND_INFO_RSP: u8 = 0x05;
/// `BT_ATT_OP_FIND_BY_TYPE_REQ` — Find By Type Value Request.
pub const BT_ATT_OP_FIND_BY_TYPE_REQ: u8 = 0x06;
/// `BT_ATT_OP_FIND_BY_TYPE_RSP` — Find By Type Value Response.
pub const BT_ATT_OP_FIND_BY_TYPE_RSP: u8 = 0x07;
/// `BT_ATT_OP_READ_BY_TYPE_REQ` — Read By Type Request.
pub const BT_ATT_OP_READ_BY_TYPE_REQ: u8 = 0x08;
/// `BT_ATT_OP_READ_BY_TYPE_RSP` — Read By Type Response.
pub const BT_ATT_OP_READ_BY_TYPE_RSP: u8 = 0x09;
/// `BT_ATT_OP_READ_REQ` — Read Request.
pub const BT_ATT_OP_READ_REQ: u8 = 0x0A;
/// `BT_ATT_OP_READ_RSP` — Read Response.
pub const BT_ATT_OP_READ_RSP: u8 = 0x0B;
/// `BT_ATT_OP_READ_BLOB_REQ` — Read Blob Request.
pub const BT_ATT_OP_READ_BLOB_REQ: u8 = 0x0C;
/// `BT_ATT_OP_READ_BLOB_RSP` — Read Blob Response.
pub const BT_ATT_OP_READ_BLOB_RSP: u8 = 0x0D;
/// `BT_ATT_OP_READ_MULT_REQ` — Read Multiple Request.
pub const BT_ATT_OP_READ_MULT_REQ: u8 = 0x0E;
/// `BT_ATT_OP_READ_MULT_RSP` — Read Multiple Response.
pub const BT_ATT_OP_READ_MULT_RSP: u8 = 0x0F;
/// `BT_ATT_OP_READ_BY_GRP_TYPE_REQ` — Read By Group Type Request.
pub const BT_ATT_OP_READ_BY_GRP_TYPE_REQ: u8 = 0x10;
/// `BT_ATT_OP_READ_BY_GRP_TYPE_RSP` — Read By Group Type Response.
pub const BT_ATT_OP_READ_BY_GRP_TYPE_RSP: u8 = 0x11;
/// `BT_ATT_OP_WRITE_REQ` — Write Request.
pub const BT_ATT_OP_WRITE_REQ: u8 = 0x12;
/// `BT_ATT_OP_WRITE_RSP` — Write Response.
pub const BT_ATT_OP_WRITE_RSP: u8 = 0x13;
/// `BT_ATT_OP_WRITE_CMD` — Write Command.
pub const BT_ATT_OP_WRITE_CMD: u8 = 0x52;
/// `BT_ATT_OP_SIGNED_WRITE_CMD` — Signed Write Command.
pub const BT_ATT_OP_SIGNED_WRITE_CMD: u8 = 0xD2;
/// `BT_ATT_OP_PREP_WRITE_REQ` — Prepare Write Request.
pub const BT_ATT_OP_PREP_WRITE_REQ: u8 = 0x16;
/// `BT_ATT_OP_PREP_WRITE_RSP` — Prepare Write Response.
pub const BT_ATT_OP_PREP_WRITE_RSP: u8 = 0x17;
/// `BT_ATT_OP_EXEC_WRITE_REQ` — Execute Write Request.
pub const BT_ATT_OP_EXEC_WRITE_REQ: u8 = 0x18;
/// `BT_ATT_OP_EXEC_WRITE_RSP` — Execute Write Response.
pub const BT_ATT_OP_EXEC_WRITE_RSP: u8 = 0x19;
/// `BT_ATT_OP_HANDLE_NFY` — Handle Value Notification.
pub const BT_ATT_OP_HANDLE_NFY: u8 = 0x1B;
/// `BT_ATT_OP_HANDLE_IND` — Handle Value Indication.
pub const BT_ATT_OP_HANDLE_IND: u8 = 0x1D;
/// `BT_ATT_OP_HANDLE_CONF` — Handle Value Confirmation.
pub const BT_ATT_OP_HANDLE_CONF: u8 = 0x1E;
/// `BT_ATT_OP_READ_MULT_VL_REQ` — Read Multiple Variable Length Request.
pub const BT_ATT_OP_READ_MULT_VL_REQ: u8 = 0x20;
/// `BT_ATT_OP_READ_MULT_VL_RSP` — Read Multiple Variable Length Response.
pub const BT_ATT_OP_READ_MULT_VL_RSP: u8 = 0x21;
/// `BT_ATT_OP_HANDLE_NFY_MULT` — Handle Value Notification Multiple.
pub const BT_ATT_OP_HANDLE_NFY_MULT: u8 = 0x23;

/// Special opcode value to register a handler that receives all ATT
/// request and command PDUs (legacy server catch-all).
pub const BT_ATT_ALL_REQUESTS: u8 = 0x00;

impl TryFrom<u8> for AttOpcode {
    type Error = u8;

    /// Converts a raw `u8` value to an [`AttOpcode`].
    ///
    /// Returns `Err(value)` if the byte does not correspond to a valid
    /// ATT opcode.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::ErrorRsp),
            0x02 => Ok(Self::MtuReq),
            0x03 => Ok(Self::MtuRsp),
            0x04 => Ok(Self::FindInfoReq),
            0x05 => Ok(Self::FindInfoRsp),
            0x06 => Ok(Self::FindByTypeReq),
            0x07 => Ok(Self::FindByTypeRsp),
            0x08 => Ok(Self::ReadByTypeReq),
            0x09 => Ok(Self::ReadByTypeRsp),
            0x0A => Ok(Self::ReadReq),
            0x0B => Ok(Self::ReadRsp),
            0x0C => Ok(Self::ReadBlobReq),
            0x0D => Ok(Self::ReadBlobRsp),
            0x0E => Ok(Self::ReadMultReq),
            0x0F => Ok(Self::ReadMultRsp),
            0x10 => Ok(Self::ReadByGrpTypeReq),
            0x11 => Ok(Self::ReadByGrpTypeRsp),
            0x12 => Ok(Self::WriteReq),
            0x13 => Ok(Self::WriteRsp),
            0x16 => Ok(Self::PrepWriteReq),
            0x17 => Ok(Self::PrepWriteRsp),
            0x18 => Ok(Self::ExecWriteReq),
            0x19 => Ok(Self::ExecWriteRsp),
            0x1B => Ok(Self::HandleNfy),
            0x1D => Ok(Self::HandleInd),
            0x1E => Ok(Self::HandleConf),
            0x20 => Ok(Self::ReadMultVlReq),
            0x21 => Ok(Self::ReadMultVlRsp),
            0x23 => Ok(Self::HandleNfyMult),
            0x52 => Ok(Self::WriteCmd),
            0xD2 => Ok(Self::SignedWriteCmd),
            _ => Err(value),
        }
    }
}

// =====================================================================
// ATT Error Codes
// =====================================================================

/// ATT standard error codes returned in Error Response PDUs.
///
/// These 19 codes are defined by the Bluetooth Core Specification and
/// cover the range 0x01..=0x13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AttError {
    /// Invalid handle (0x01).
    InvalidHandle = 0x01,
    /// Read not permitted (0x02).
    ReadNotPermitted = 0x02,
    /// Write not permitted (0x03).
    WriteNotPermitted = 0x03,
    /// Invalid PDU (0x04).
    InvalidPdu = 0x04,
    /// Insufficient authentication (0x05).
    Authentication = 0x05,
    /// Request not supported (0x06).
    RequestNotSupported = 0x06,
    /// Invalid offset (0x07).
    InvalidOffset = 0x07,
    /// Insufficient authorization (0x08).
    Authorization = 0x08,
    /// Prepare queue full (0x09).
    PrepareQueueFull = 0x09,
    /// Attribute not found (0x0A).
    AttributeNotFound = 0x0A,
    /// Attribute not long (0x0B).
    AttributeNotLong = 0x0B,
    /// Insufficient encryption key size (0x0C).
    InsufficientEncryptionKeySize = 0x0C,
    /// Invalid attribute value length (0x0D).
    InvalidAttributeValueLen = 0x0D,
    /// Unlikely error (0x0E).
    Unlikely = 0x0E,
    /// Insufficient encryption (0x0F).
    InsufficientEncryption = 0x0F,
    /// Unsupported group type (0x10).
    UnsupportedGroupType = 0x10,
    /// Insufficient resources (0x11).
    InsufficientResources = 0x11,
    /// Database out of sync (0x12).
    DbOutOfSync = 0x12,
    /// Value not allowed (0x13).
    ValueNotAllowed = 0x13,
}

// Raw error code constants matching C `#define` names exactly.

/// Invalid handle.
pub const BT_ATT_ERROR_INVALID_HANDLE: u8 = 0x01;
/// Read not permitted.
pub const BT_ATT_ERROR_READ_NOT_PERMITTED: u8 = 0x02;
/// Write not permitted.
pub const BT_ATT_ERROR_WRITE_NOT_PERMITTED: u8 = 0x03;
/// Invalid PDU.
pub const BT_ATT_ERROR_INVALID_PDU: u8 = 0x04;
/// Insufficient authentication.
pub const BT_ATT_ERROR_AUTHENTICATION: u8 = 0x05;
/// Request not supported.
pub const BT_ATT_ERROR_REQUEST_NOT_SUPPORTED: u8 = 0x06;
/// Invalid offset.
pub const BT_ATT_ERROR_INVALID_OFFSET: u8 = 0x07;
/// Insufficient authorization.
pub const BT_ATT_ERROR_AUTHORIZATION: u8 = 0x08;
/// Prepare queue full.
pub const BT_ATT_ERROR_PREPARE_QUEUE_FULL: u8 = 0x09;
/// Attribute not found.
pub const BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
/// Attribute not long.
pub const BT_ATT_ERROR_ATTRIBUTE_NOT_LONG: u8 = 0x0B;
/// Insufficient encryption key size.
pub const BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE: u8 = 0x0C;
/// Invalid attribute value length.
pub const BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN: u8 = 0x0D;
/// Unlikely error.
pub const BT_ATT_ERROR_UNLIKELY: u8 = 0x0E;
/// Insufficient encryption.
pub const BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION: u8 = 0x0F;
/// Unsupported group type.
pub const BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE: u8 = 0x10;
/// Insufficient resources.
pub const BT_ATT_ERROR_INSUFFICIENT_RESOURCES: u8 = 0x11;
/// Database out of sync.
pub const BT_ATT_ERROR_DB_OUT_OF_SYNC: u8 = 0x12;
/// Value not allowed.
pub const BT_ATT_ERROR_VALUE_NOT_ALLOWED: u8 = 0x13;

// Common Profile and Service Error Codes (Bluetooth Core Supplement,
// Sections 1.2 and 2). Error codes 0xE0–0xFB are reserved for future use.

/// Write request rejected (0xFC).
pub const BT_ERROR_WRITE_REQUEST_REJECTED: u8 = 0xFC;
/// Client Characteristic Configuration descriptor improperly configured (0xFD).
pub const BT_ERROR_CCC_IMPROPERLY_CONFIGURED: u8 = 0xFD;
/// Procedure already in progress (0xFE).
pub const BT_ERROR_ALREADY_IN_PROGRESS: u8 = 0xFE;
/// Out of range (0xFF).
pub const BT_ERROR_OUT_OF_RANGE: u8 = 0xFF;

impl TryFrom<u8> for AttError {
    type Error = u8;

    /// Converts a raw `u8` value to an [`AttError`].
    ///
    /// Only standard ATT error codes (0x01..=0x13) are recognized.
    /// Returns `Err(value)` for any other byte.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::InvalidHandle),
            0x02 => Ok(Self::ReadNotPermitted),
            0x03 => Ok(Self::WriteNotPermitted),
            0x04 => Ok(Self::InvalidPdu),
            0x05 => Ok(Self::Authentication),
            0x06 => Ok(Self::RequestNotSupported),
            0x07 => Ok(Self::InvalidOffset),
            0x08 => Ok(Self::Authorization),
            0x09 => Ok(Self::PrepareQueueFull),
            0x0A => Ok(Self::AttributeNotFound),
            0x0B => Ok(Self::AttributeNotLong),
            0x0C => Ok(Self::InsufficientEncryptionKeySize),
            0x0D => Ok(Self::InvalidAttributeValueLen),
            0x0E => Ok(Self::Unlikely),
            0x0F => Ok(Self::InsufficientEncryption),
            0x10 => Ok(Self::UnsupportedGroupType),
            0x11 => Ok(Self::InsufficientResources),
            0x12 => Ok(Self::DbOutOfSync),
            0x13 => Ok(Self::ValueNotAllowed),
            _ => Err(value),
        }
    }
}

// =====================================================================
// Packed PDU Structures
// =====================================================================

/// ATT Error Response PDU (packed, wire-format compatible).
///
/// This struct is `#[repr(C, packed)]` to produce byte-identical layout to
/// the C `struct bt_att_pdu_error_rsp`. Total size is exactly 4 bytes:
///
/// | Offset | Size | Field    |
/// |--------|------|----------|
/// | 0      | 1    | `opcode` |
/// | 1      | 2    | `handle` |
/// | 3      | 1    | `ecode`  |
///
/// The `handle` field is stored in little-endian byte order on the wire.
/// Callers should use `u16::from_le` / `u16::to_le` when
/// reading/writing this field.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct BtAttPduErrorRsp {
    /// Opcode of the request that generated the error.
    pub opcode: u8,
    /// Attribute handle that caused the error (little-endian on wire).
    pub handle: u16,
    /// Error code from the [`AttError`] enum or a profile-specific code.
    pub ecode: u8,
}

// =====================================================================
// ATT Permission Bitflags
// =====================================================================

bitflags! {
    /// ATT attribute permission bitmask.
    ///
    /// Permissions are grouped into Access (read/write), Encryption,
    /// Authentication, Authorization, and Secure categories. Combined
    /// masks (`ENCRYPT`, `AUTHEN`, `SECURE`, `READ_MASK`, `WRITE_MASK`)
    /// are provided for convenience.
    ///
    /// Backed by `u16` because the Secure permission bits (0x0100,
    /// 0x0200) exceed the `u8` range.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AttPermissions: u16 {
        /// Read access permitted.
        const READ          = 0x0001;
        /// Write access permitted.
        const WRITE         = 0x0002;
        /// Read requires encryption.
        const READ_ENCRYPT  = 0x0004;
        /// Write requires encryption.
        const WRITE_ENCRYPT = 0x0008;
        /// Read or write requires encryption (combined).
        const ENCRYPT       = Self::READ_ENCRYPT.bits() | Self::WRITE_ENCRYPT.bits();
        /// Read requires authentication.
        const READ_AUTHEN   = 0x0010;
        /// Write requires authentication.
        const WRITE_AUTHEN  = 0x0020;
        /// Read or write requires authentication (combined).
        const AUTHEN        = Self::READ_AUTHEN.bits() | Self::WRITE_AUTHEN.bits();
        /// Authorization required.
        const AUTHOR        = 0x0040;
        /// No permission required (attribute-level override).
        const NONE          = 0x0080;
        /// Read requires Secure Connections.
        const READ_SECURE   = 0x0100;
        /// Write requires Secure Connections.
        const WRITE_SECURE  = 0x0200;
        /// Read or write requires Secure Connections (combined).
        const SECURE        = Self::READ_SECURE.bits() | Self::WRITE_SECURE.bits();
        /// Mask of all read-related permission bits.
        const READ_MASK     = Self::READ.bits()
                            | Self::READ_ENCRYPT.bits()
                            | Self::READ_AUTHEN.bits()
                            | Self::READ_SECURE.bits();
        /// Mask of all write-related permission bits.
        const WRITE_MASK    = Self::WRITE.bits()
                            | Self::WRITE_ENCRYPT.bits()
                            | Self::WRITE_AUTHEN.bits()
                            | Self::WRITE_SECURE.bits();
    }
}

// Raw permission constants matching C `#define` names exactly.

/// Read access permitted.
pub const BT_ATT_PERM_READ: u16 = 0x0001;
/// Write access permitted.
pub const BT_ATT_PERM_WRITE: u16 = 0x0002;
/// Read requires encryption.
pub const BT_ATT_PERM_READ_ENCRYPT: u16 = 0x0004;
/// Write requires encryption.
pub const BT_ATT_PERM_WRITE_ENCRYPT: u16 = 0x0008;
/// Read or write requires encryption (combined).
pub const BT_ATT_PERM_ENCRYPT: u16 = BT_ATT_PERM_READ_ENCRYPT | BT_ATT_PERM_WRITE_ENCRYPT;
/// Read requires authentication.
pub const BT_ATT_PERM_READ_AUTHEN: u16 = 0x0010;
/// Write requires authentication.
pub const BT_ATT_PERM_WRITE_AUTHEN: u16 = 0x0020;
/// Read or write requires authentication (combined).
pub const BT_ATT_PERM_AUTHEN: u16 = BT_ATT_PERM_READ_AUTHEN | BT_ATT_PERM_WRITE_AUTHEN;
/// Authorization required.
pub const BT_ATT_PERM_AUTHOR: u16 = 0x0040;
/// No permission required.
pub const BT_ATT_PERM_NONE: u16 = 0x0080;
/// Read requires Secure Connections.
pub const BT_ATT_PERM_READ_SECURE: u16 = 0x0100;
/// Write requires Secure Connections.
pub const BT_ATT_PERM_WRITE_SECURE: u16 = 0x0200;
/// Read or write requires Secure Connections (combined).
pub const BT_ATT_PERM_SECURE: u16 = BT_ATT_PERM_READ_SECURE | BT_ATT_PERM_WRITE_SECURE;
/// Mask of all read-related permission bits.
pub const BT_ATT_PERM_READ_MASK: u16 =
    BT_ATT_PERM_READ | BT_ATT_PERM_READ_ENCRYPT | BT_ATT_PERM_READ_AUTHEN | BT_ATT_PERM_READ_SECURE;
/// Mask of all write-related permission bits.
pub const BT_ATT_PERM_WRITE_MASK: u16 = BT_ATT_PERM_WRITE
    | BT_ATT_PERM_WRITE_ENCRYPT
    | BT_ATT_PERM_WRITE_AUTHEN
    | BT_ATT_PERM_WRITE_SECURE;

// =====================================================================
// GATT Characteristic Properties Bitflags
// =====================================================================

bitflags! {
    /// GATT Characteristic Properties bitmask (8-bit).
    ///
    /// Defines how the characteristic value can be used as specified in
    /// the Bluetooth Core Specification, Vol 3 Part G, Section 3.3.1.1.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GattChrcProperties: u8 {
        /// Permits broadcasts of the characteristic value.
        const BROADCAST         = 0x01;
        /// Permits reads of the characteristic value.
        const READ              = 0x02;
        /// Permits writes without response.
        const WRITE_WITHOUT_RESP = 0x04;
        /// Permits writes of the characteristic value.
        const WRITE             = 0x08;
        /// Permits notifications of the characteristic value.
        const NOTIFY            = 0x10;
        /// Permits indications of the characteristic value.
        const INDICATE          = 0x20;
        /// Permits signed writes to the characteristic value.
        const AUTH              = 0x40;
        /// Additional characteristic properties in the extended properties descriptor.
        const EXT_PROP          = 0x80;
    }
}

// Raw characteristic property constants matching C `#define` names exactly.

/// Permits broadcasts.
pub const BT_GATT_CHRC_PROP_BROADCAST: u8 = 0x01;
/// Permits reads.
pub const BT_GATT_CHRC_PROP_READ: u8 = 0x02;
/// Permits writes without response.
pub const BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP: u8 = 0x04;
/// Permits writes.
pub const BT_GATT_CHRC_PROP_WRITE: u8 = 0x08;
/// Permits notifications.
pub const BT_GATT_CHRC_PROP_NOTIFY: u8 = 0x10;
/// Permits indications.
pub const BT_GATT_CHRC_PROP_INDICATE: u8 = 0x20;
/// Permits signed writes.
pub const BT_GATT_CHRC_PROP_AUTH: u8 = 0x40;
/// Extended properties descriptor present.
pub const BT_GATT_CHRC_PROP_EXT_PROP: u8 = 0x80;

// =====================================================================
// GATT Characteristic Extended Properties Bitflags
// =====================================================================

bitflags! {
    /// GATT Characteristic Extended Properties bitmask (8-bit).
    ///
    /// Read from the Characteristic Extended Properties descriptor
    /// (UUID 0x2900).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GattChrcExtProperties: u8 {
        /// Reliable Write enabled.
        const RELIABLE_WRITE = 0x01;
        /// Writable Auxiliaries enabled.
        const WRITABLE_AUX   = 0x02;
    }
}

// Raw extended property constants matching C `#define` names exactly.

/// Reliable Write enabled.
pub const BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE: u8 = 0x01;
/// Writable Auxiliaries enabled.
pub const BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX: u8 = 0x02;

// =====================================================================
// GATT Client Features Bitflags
// =====================================================================

bitflags! {
    /// GATT Client Supported Features bitmask (8-bit).
    ///
    /// Written by the client to the Client Supported Features characteristic
    /// (UUID 0x2B29) to indicate supported features.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GattClientFeatures: u8 {
        /// Robust Caching supported.
        const ROBUST_CACHING = 0x01;
        /// Enhanced ATT Bearer (EATT) supported.
        const EATT           = 0x02;
        /// Multiple Handle Value Notifications supported.
        const NFY_MULTI      = 0x04;
    }
}

// Raw client feature constants matching C `#define` names exactly.

/// Robust Caching supported.
pub const BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING: u8 = 0x01;
/// EATT supported.
pub const BT_GATT_CHRC_CLI_FEAT_EATT: u8 = 0x02;
/// Multiple Handle Value Notifications supported.
pub const BT_GATT_CHRC_CLI_FEAT_NFY_MULTI: u8 = 0x04;

// =====================================================================
// GATT Server Features Bitflags
// =====================================================================

bitflags! {
    /// GATT Server Supported Features bitmask (8-bit).
    ///
    /// Read from the Server Supported Features characteristic
    /// (UUID 0x2B3A) to discover server capabilities.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GattServerFeatures: u8 {
        /// Enhanced ATT Bearer (EATT) supported by the server.
        const EATT = 0x01;
    }
}

// Raw server feature constant matching C `#define` name exactly.

/// EATT supported by the server.
pub const BT_GATT_CHRC_SERVER_FEAT_EATT: u8 = 0x01;

// =====================================================================
// Unit Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn error_rsp_pdu_size_is_4_bytes() {
        assert_eq!(mem::size_of::<BtAttPduErrorRsp>(), 4);
    }

    #[test]
    fn security_level_ordering() {
        assert!(AttSecurityLevel::Auto < AttSecurityLevel::Low);
        assert!(AttSecurityLevel::Low < AttSecurityLevel::Medium);
        assert!(AttSecurityLevel::Medium < AttSecurityLevel::High);
        assert!(AttSecurityLevel::High < AttSecurityLevel::Fips);
    }

    #[test]
    fn security_level_try_from_valid() {
        assert_eq!(AttSecurityLevel::try_from(0), Ok(AttSecurityLevel::Auto));
        assert_eq!(AttSecurityLevel::try_from(1), Ok(AttSecurityLevel::Low));
        assert_eq!(AttSecurityLevel::try_from(2), Ok(AttSecurityLevel::Medium));
        assert_eq!(AttSecurityLevel::try_from(3), Ok(AttSecurityLevel::High));
        assert_eq!(AttSecurityLevel::try_from(4), Ok(AttSecurityLevel::Fips));
    }

    #[test]
    fn security_level_try_from_invalid() {
        assert_eq!(AttSecurityLevel::try_from(5), Err(5));
        assert_eq!(AttSecurityLevel::try_from(255), Err(255));
    }

    #[test]
    fn opcode_enum_values_match_constants() {
        assert_eq!(AttOpcode::ErrorRsp as u8, BT_ATT_OP_ERROR_RSP);
        assert_eq!(AttOpcode::MtuReq as u8, BT_ATT_OP_MTU_REQ);
        assert_eq!(AttOpcode::MtuRsp as u8, BT_ATT_OP_MTU_RSP);
        assert_eq!(AttOpcode::FindInfoReq as u8, BT_ATT_OP_FIND_INFO_REQ);
        assert_eq!(AttOpcode::FindInfoRsp as u8, BT_ATT_OP_FIND_INFO_RSP);
        assert_eq!(AttOpcode::FindByTypeReq as u8, BT_ATT_OP_FIND_BY_TYPE_REQ);
        assert_eq!(AttOpcode::FindByTypeRsp as u8, BT_ATT_OP_FIND_BY_TYPE_RSP);
        assert_eq!(AttOpcode::ReadByTypeReq as u8, BT_ATT_OP_READ_BY_TYPE_REQ);
        assert_eq!(AttOpcode::ReadByTypeRsp as u8, BT_ATT_OP_READ_BY_TYPE_RSP);
        assert_eq!(AttOpcode::ReadReq as u8, BT_ATT_OP_READ_REQ);
        assert_eq!(AttOpcode::ReadRsp as u8, BT_ATT_OP_READ_RSP);
        assert_eq!(AttOpcode::ReadBlobReq as u8, BT_ATT_OP_READ_BLOB_REQ);
        assert_eq!(AttOpcode::ReadBlobRsp as u8, BT_ATT_OP_READ_BLOB_RSP);
        assert_eq!(AttOpcode::ReadMultReq as u8, BT_ATT_OP_READ_MULT_REQ);
        assert_eq!(AttOpcode::ReadMultRsp as u8, BT_ATT_OP_READ_MULT_RSP);
        assert_eq!(AttOpcode::ReadByGrpTypeReq as u8, BT_ATT_OP_READ_BY_GRP_TYPE_REQ);
        assert_eq!(AttOpcode::ReadByGrpTypeRsp as u8, BT_ATT_OP_READ_BY_GRP_TYPE_RSP);
        assert_eq!(AttOpcode::WriteReq as u8, BT_ATT_OP_WRITE_REQ);
        assert_eq!(AttOpcode::WriteRsp as u8, BT_ATT_OP_WRITE_RSP);
        assert_eq!(AttOpcode::WriteCmd as u8, BT_ATT_OP_WRITE_CMD);
        assert_eq!(AttOpcode::SignedWriteCmd as u8, BT_ATT_OP_SIGNED_WRITE_CMD);
        assert_eq!(AttOpcode::PrepWriteReq as u8, BT_ATT_OP_PREP_WRITE_REQ);
        assert_eq!(AttOpcode::PrepWriteRsp as u8, BT_ATT_OP_PREP_WRITE_RSP);
        assert_eq!(AttOpcode::ExecWriteReq as u8, BT_ATT_OP_EXEC_WRITE_REQ);
        assert_eq!(AttOpcode::ExecWriteRsp as u8, BT_ATT_OP_EXEC_WRITE_RSP);
        assert_eq!(AttOpcode::HandleNfy as u8, BT_ATT_OP_HANDLE_NFY);
        assert_eq!(AttOpcode::HandleInd as u8, BT_ATT_OP_HANDLE_IND);
        assert_eq!(AttOpcode::HandleConf as u8, BT_ATT_OP_HANDLE_CONF);
        assert_eq!(AttOpcode::ReadMultVlReq as u8, BT_ATT_OP_READ_MULT_VL_REQ);
        assert_eq!(AttOpcode::ReadMultVlRsp as u8, BT_ATT_OP_READ_MULT_VL_RSP);
        assert_eq!(AttOpcode::HandleNfyMult as u8, BT_ATT_OP_HANDLE_NFY_MULT);
    }

    #[test]
    fn opcode_try_from_roundtrip() {
        let opcodes = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x18, 0x19, 0x1B, 0x1D, 0x1E, 0x20, 0x21,
            0x23, 0x52, 0xD2,
        ];
        for raw in opcodes {
            let opcode = AttOpcode::try_from(raw).unwrap();
            assert_eq!(opcode as u8, raw);
        }
    }

    #[test]
    fn opcode_try_from_invalid() {
        assert!(AttOpcode::try_from(0x00).is_err());
        assert!(AttOpcode::try_from(0x14).is_err());
        assert!(AttOpcode::try_from(0x15).is_err());
        assert!(AttOpcode::try_from(0x1A).is_err());
        assert!(AttOpcode::try_from(0x1C).is_err());
        assert!(AttOpcode::try_from(0xFF).is_err());
    }

    #[test]
    fn error_enum_values_match_constants() {
        assert_eq!(AttError::InvalidHandle as u8, BT_ATT_ERROR_INVALID_HANDLE);
        assert_eq!(AttError::ReadNotPermitted as u8, BT_ATT_ERROR_READ_NOT_PERMITTED);
        assert_eq!(AttError::WriteNotPermitted as u8, BT_ATT_ERROR_WRITE_NOT_PERMITTED);
        assert_eq!(AttError::InvalidPdu as u8, BT_ATT_ERROR_INVALID_PDU);
        assert_eq!(AttError::Authentication as u8, BT_ATT_ERROR_AUTHENTICATION);
        assert_eq!(AttError::RequestNotSupported as u8, BT_ATT_ERROR_REQUEST_NOT_SUPPORTED);
        assert_eq!(AttError::InvalidOffset as u8, BT_ATT_ERROR_INVALID_OFFSET);
        assert_eq!(AttError::Authorization as u8, BT_ATT_ERROR_AUTHORIZATION);
        assert_eq!(AttError::PrepareQueueFull as u8, BT_ATT_ERROR_PREPARE_QUEUE_FULL);
        assert_eq!(AttError::AttributeNotFound as u8, BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND);
        assert_eq!(AttError::AttributeNotLong as u8, BT_ATT_ERROR_ATTRIBUTE_NOT_LONG);
        assert_eq!(
            AttError::InsufficientEncryptionKeySize as u8,
            BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE
        );
        assert_eq!(
            AttError::InvalidAttributeValueLen as u8,
            BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN
        );
        assert_eq!(AttError::Unlikely as u8, BT_ATT_ERROR_UNLIKELY);
        assert_eq!(AttError::InsufficientEncryption as u8, BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION);
        assert_eq!(AttError::UnsupportedGroupType as u8, BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE);
        assert_eq!(AttError::InsufficientResources as u8, BT_ATT_ERROR_INSUFFICIENT_RESOURCES);
        assert_eq!(AttError::DbOutOfSync as u8, BT_ATT_ERROR_DB_OUT_OF_SYNC);
        assert_eq!(AttError::ValueNotAllowed as u8, BT_ATT_ERROR_VALUE_NOT_ALLOWED);
    }

    #[test]
    fn error_try_from_roundtrip() {
        for raw in 0x01u8..=0x13 {
            let error = AttError::try_from(raw).unwrap();
            assert_eq!(error as u8, raw);
        }
    }

    #[test]
    fn error_try_from_invalid() {
        assert!(AttError::try_from(0x00).is_err());
        assert!(AttError::try_from(0x14).is_err());
        assert!(AttError::try_from(0xFF).is_err());
    }

    #[test]
    fn common_profile_error_values() {
        assert_eq!(BT_ERROR_WRITE_REQUEST_REJECTED, 0xFC);
        assert_eq!(BT_ERROR_CCC_IMPROPERLY_CONFIGURED, 0xFD);
        assert_eq!(BT_ERROR_ALREADY_IN_PROGRESS, 0xFE);
        assert_eq!(BT_ERROR_OUT_OF_RANGE, 0xFF);
    }

    #[test]
    fn channel_constants() {
        assert_eq!(BT_ATT_CID, 4);
        assert_eq!(BT_ATT_PSM, 31);
        assert_eq!(BT_ATT_EATT_PSM, 0x27);
    }

    #[test]
    fn mtu_constants() {
        assert_eq!(BT_ATT_DEFAULT_LE_MTU, 23);
        assert_eq!(BT_ATT_MAX_LE_MTU, 517);
        assert_eq!(BT_ATT_MAX_VALUE_LEN, 512);
    }

    #[test]
    fn channel_type_constants() {
        assert_eq!(BT_ATT_BREDR, 0x00);
        assert_eq!(BT_ATT_LE, 0x01);
        assert_eq!(BT_ATT_EATT, 0x02);
        assert_eq!(BT_ATT_LOCAL, 0xFF);
    }

    #[test]
    fn permission_bitflags_combined_values() {
        assert_eq!(AttPermissions::ENCRYPT.bits(), 0x000C);
        assert_eq!(AttPermissions::AUTHEN.bits(), 0x0030);
        assert_eq!(AttPermissions::SECURE.bits(), 0x0300);
        assert_eq!(AttPermissions::READ_MASK.bits(), 0x0115);
        assert_eq!(AttPermissions::WRITE_MASK.bits(), 0x022A);
    }

    #[test]
    fn permission_raw_constants_match_bitflags() {
        assert_eq!(BT_ATT_PERM_READ, AttPermissions::READ.bits());
        assert_eq!(BT_ATT_PERM_WRITE, AttPermissions::WRITE.bits());
        assert_eq!(BT_ATT_PERM_ENCRYPT, AttPermissions::ENCRYPT.bits());
        assert_eq!(BT_ATT_PERM_AUTHEN, AttPermissions::AUTHEN.bits());
        assert_eq!(BT_ATT_PERM_AUTHOR, AttPermissions::AUTHOR.bits());
        assert_eq!(BT_ATT_PERM_NONE, AttPermissions::NONE.bits());
        assert_eq!(BT_ATT_PERM_SECURE, AttPermissions::SECURE.bits());
        assert_eq!(BT_ATT_PERM_READ_MASK, AttPermissions::READ_MASK.bits());
        assert_eq!(BT_ATT_PERM_WRITE_MASK, AttPermissions::WRITE_MASK.bits());
    }

    #[test]
    fn permission_bitwise_operations() {
        let perms = AttPermissions::READ | AttPermissions::WRITE_ENCRYPT;
        assert!(perms.contains(AttPermissions::READ));
        assert!(perms.contains(AttPermissions::WRITE_ENCRYPT));
        assert!(!perms.contains(AttPermissions::WRITE));
    }

    #[test]
    fn gatt_chrc_properties_all_bits() {
        let all = GattChrcProperties::BROADCAST
            | GattChrcProperties::READ
            | GattChrcProperties::WRITE_WITHOUT_RESP
            | GattChrcProperties::WRITE
            | GattChrcProperties::NOTIFY
            | GattChrcProperties::INDICATE
            | GattChrcProperties::AUTH
            | GattChrcProperties::EXT_PROP;
        assert_eq!(all.bits(), 0xFF);
    }

    #[test]
    fn gatt_chrc_properties_raw_constants() {
        assert_eq!(BT_GATT_CHRC_PROP_BROADCAST, 0x01);
        assert_eq!(BT_GATT_CHRC_PROP_READ, 0x02);
        assert_eq!(BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP, 0x04);
        assert_eq!(BT_GATT_CHRC_PROP_WRITE, 0x08);
        assert_eq!(BT_GATT_CHRC_PROP_NOTIFY, 0x10);
        assert_eq!(BT_GATT_CHRC_PROP_INDICATE, 0x20);
        assert_eq!(BT_GATT_CHRC_PROP_AUTH, 0x40);
        assert_eq!(BT_GATT_CHRC_PROP_EXT_PROP, 0x80);
    }

    #[test]
    fn gatt_ext_properties() {
        assert_eq!(GattChrcExtProperties::RELIABLE_WRITE.bits(), 0x01);
        assert_eq!(GattChrcExtProperties::WRITABLE_AUX.bits(), 0x02);
        assert_eq!(BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE, 0x01);
        assert_eq!(BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX, 0x02);
    }

    #[test]
    fn gatt_client_features() {
        assert_eq!(GattClientFeatures::ROBUST_CACHING.bits(), 0x01);
        assert_eq!(GattClientFeatures::EATT.bits(), 0x02);
        assert_eq!(GattClientFeatures::NFY_MULTI.bits(), 0x04);
        assert_eq!(BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING, 0x01);
        assert_eq!(BT_GATT_CHRC_CLI_FEAT_EATT, 0x02);
        assert_eq!(BT_GATT_CHRC_CLI_FEAT_NFY_MULTI, 0x04);
    }

    #[test]
    fn gatt_server_features() {
        assert_eq!(GattServerFeatures::EATT.bits(), 0x01);
        assert_eq!(BT_GATT_CHRC_SERVER_FEAT_EATT, 0x01);
    }

    #[test]
    fn all_requests_special_opcode() {
        assert_eq!(BT_ATT_ALL_REQUESTS, 0x00);
    }
}
