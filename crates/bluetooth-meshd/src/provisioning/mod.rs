// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2018-2019 Intel Corporation. All rights reserved.
//
// Rust rewrite of mesh/prov.h, mesh/provision.h, mesh/pb-adv.h, mesh/mesh-defs.h
// Foundational module for the provisioning subsystem: shared types, constants,
// PDU structures, callback type aliases, error codes, and sub-module re-exports.

// Sub-module declarations for the provisioning subsystem
pub mod acceptor;
pub mod initiator;
pub mod pb_adv;

// ---------------------------------------------------------------------------
// Provisioning PDU Opcode Constants (from provision.h)
// These raw u8 constants mirror the C #define values exactly for pattern
// matching in the acceptor and initiator state machines.
// ---------------------------------------------------------------------------

/// Provisioning Invite opcode (0x00)
pub const PROV_INVITE: u8 = 0x00;
/// Provisioning Capabilities opcode (0x01)
pub const PROV_CAPS: u8 = 0x01;
/// Provisioning Start opcode (0x02)
pub const PROV_START: u8 = 0x02;
/// Provisioning Public Key opcode (0x03)
pub const PROV_PUB_KEY: u8 = 0x03;
/// Provisioning Input Complete opcode (0x04)
pub const PROV_INP_CMPLT: u8 = 0x04;
/// Provisioning Confirmation opcode (0x05)
pub const PROV_CONFIRM: u8 = 0x05;
/// Provisioning Random opcode (0x06)
pub const PROV_RANDOM: u8 = 0x06;
/// Provisioning Data opcode (0x07)
pub const PROV_DATA: u8 = 0x07;
/// Provisioning Complete opcode (0x08)
pub const PROV_COMPLETE: u8 = 0x08;
/// Provisioning Failed opcode (0x09)
pub const PROV_FAILED: u8 = 0x09;
/// Sentinel value indicating no valid opcode / idle state (0xFF)
pub const PROV_NONE: u8 = 0xFF;

/// Total number of provisioning PDU opcodes (0x00 through 0x09 inclusive).
pub const PROV_NUM_OPCODES: usize = 10;

// ---------------------------------------------------------------------------
// Provisioning PDU Opcode Enum
// ---------------------------------------------------------------------------

/// Provisioning PDU opcodes as a typed enum.
/// Each variant's discriminant matches the on-wire opcode value exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProvOpcode {
    /// Invite (attention timer)
    Invite = 0x00,
    /// Capabilities response
    Caps = 0x01,
    /// Start provisioning with selected parameters
    Start = 0x02,
    /// Public key exchange
    PubKey = 0x03,
    /// Input complete notification
    InpCmplt = 0x04,
    /// Confirmation value
    Confirm = 0x05,
    /// Random value
    Random = 0x06,
    /// Encrypted provisioning data
    Data = 0x07,
    /// Provisioning complete
    Complete = 0x08,
    /// Provisioning failed with error code
    Failed = 0x09,
}

// ---------------------------------------------------------------------------
// Expected PDU Size Array (from prov-initiator.c lines 40-51)
// ---------------------------------------------------------------------------

/// Expected size (in bytes, including the opcode byte) of each provisioning
/// PDU, indexed by opcode value. A size of 0 would indicate an invalid opcode
/// at that index. All values match the C `expected_pdu_size[]` array exactly.
pub const EXPECTED_PDU_SIZE: [u16; PROV_NUM_OPCODES] = [
    2,  // PROV_INVITE (0x00): opcode + attention_duration
    12, // PROV_CAPS (0x01): opcode + 11 bytes capabilities
    6,  // PROV_START (0x02): opcode + 5 bytes start params
    65, // PROV_PUB_KEY (0x03): opcode + 64 bytes public key
    1,  // PROV_INP_CMPLT (0x04): opcode only
    17, // PROV_CONFIRM (0x05): opcode + 16 bytes confirmation
    17, // PROV_RANDOM (0x06): opcode + 16 bytes random
    34, // PROV_DATA (0x07): opcode + 25 bytes encrypted + 8 bytes MIC
    1,  // PROV_COMPLETE (0x08): opcode only
    2,  // PROV_FAILED (0x09): opcode + 1 byte error code
];

// ---------------------------------------------------------------------------
// Provisioning Error Code Constants (from provision.h)
// ---------------------------------------------------------------------------

/// Provisioning succeeded (no error)
pub const PROV_ERR_SUCCESS: u8 = 0x00;
/// PDU received was prohibited for the current state
pub const PROV_ERR_PROHIBITED_PDU: u8 = 0x01;
/// PDU had invalid format
pub const PROV_ERR_INVALID_FORMAT: u8 = 0x02;
/// Unexpected PDU received
pub const PROV_ERR_UNEXPECTED_PDU: u8 = 0x03;
/// Confirmation value did not match
pub const PROV_ERR_CONFIRM_FAILED: u8 = 0x04;
/// Insufficient resources to complete provisioning
pub const PROV_ERR_RESOURCES: u8 = 0x05;
/// Decryption of provisioning data failed
pub const PROV_ERR_DECRYPT_FAILED: u8 = 0x06;
/// Unexpected error occurred
pub const PROV_ERR_UNEXPECTED_ERR: u8 = 0x07;
/// Cannot assign unicast address (address space exhausted)
pub const PROV_ERR_CANT_ASSIGN_ADDR: u8 = 0x08;
/// Provisioning timed out (internal, not sent on wire)
pub const PROV_ERR_TIMEOUT: u8 = 0xFF;

// ---------------------------------------------------------------------------
// Provisioning Error Enum
// ---------------------------------------------------------------------------

/// Provisioning error codes sent in a PROV_FAILED PDU.
/// Each variant's discriminant matches the on-wire error code exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProvError {
    /// The PDU received was not expected at this state
    ProhibitedPdu = 0x01,
    /// The PDU format was invalid
    InvalidPduFormat = 0x02,
    /// An unexpected PDU was received
    UnexpectedPdu = 0x03,
    /// The confirmation values did not match
    ConfirmFailed = 0x04,
    /// Insufficient resources to continue
    OutOfResources = 0x05,
    /// Decryption failed
    DecryptFailed = 0x06,
    /// An unexpected error occurred
    UnexpectedError = 0x07,
    /// The provisioner is unable to assign addresses
    CannotAssignAddr = 0x08,
}

// ---------------------------------------------------------------------------
// Authentication Method Constants (from provision.h)
// ---------------------------------------------------------------------------

/// No OOB authentication
pub const AUTH_METHOD_NO_OOB: u8 = 0x00;
/// Static OOB authentication
pub const AUTH_METHOD_STATIC: u8 = 0x01;
/// Output OOB authentication
pub const AUTH_METHOD_OUTPUT: u8 = 0x02;
/// Input OOB authentication
pub const AUTH_METHOD_INPUT: u8 = 0x03;

// ---------------------------------------------------------------------------
// OOB Action Bitmask Constants (from mesh-defs.h)
// ---------------------------------------------------------------------------

/// Output OOB action: Blink
pub const OOB_OUT_ACTION_BLINK: u16 = 0x0001;
/// Output OOB action: Numeric display
pub const OOB_OUT_ACTION_NUMBER: u16 = 0x0008;
/// Output OOB action: Alphanumeric display
pub const OOB_OUT_ACTION_ALPHA: u16 = 0x0010;

/// Input OOB action: Push button
pub const OOB_IN_ACTION_PUSH: u16 = 0x0001;
/// Input OOB action: Numeric input
pub const OOB_IN_ACTION_NUMBER: u16 = 0x0004;
/// Input OOB action: Alphanumeric input
pub const OOB_IN_ACTION_ALPHA: u16 = 0x0008;

// ---------------------------------------------------------------------------
// OOB Information Flags (from provision.h / mesh-defs.h)
// ---------------------------------------------------------------------------

/// OOB info: URI hash is available
pub const OOB_INFO_URI_HASH: u16 = 0x0002;

// ---------------------------------------------------------------------------
// Algorithm Constants (from mesh-defs.h)
// ---------------------------------------------------------------------------

/// FIPS P-256 Elliptic Curve algorithm bitmask
pub const ALG_FIPS_256_ECC: u16 = 0x0001;

// ---------------------------------------------------------------------------
// Transport Type Constants (from provision.h)
// ---------------------------------------------------------------------------

/// PB-ADV provisioning bearer transport
pub const TRANSPORT_PB_ADV: u8 = 0;
/// NPPI (Node Provisioning Protocol Interface) transport
pub const TRANSPORT_NPPI: u8 = 1;

// ---------------------------------------------------------------------------
// Callback Type Aliases
// ---------------------------------------------------------------------------

/// Callback to transmit a provisioning PDU over the bearer.
///
/// Mirrors C `prov_trans_tx_t`: `bool (*)(void *trans_data, void *data, uint16_t len)`
/// The data slice contains the complete provisioning PDU to transmit.
/// Returns `true` if the PDU was accepted for transmission, `false` on failure.
pub type ProvTransTx = Box<dyn FnMut(&[u8]) -> bool + Send>;

/// Called when the provisioning bearer link opens.
///
/// Mirrors C `mesh_prov_open_func_t`:
/// `void (*)(void *user_data, prov_trans_tx_t trans_tx, void *trans_data, uint8_t transport)`
///
/// Parameters: (user_data handle, transmit callback, trans_data handle, transport type)
pub type ProvOpenCb = Box<dyn FnMut(usize, ProvTransTx, usize, u8) + Send>;

/// Called when the provisioning bearer link closes.
///
/// Mirrors C `mesh_prov_close_func_t`:
/// `void (*)(void *user_data, uint8_t reason)`
///
/// Parameters: (user_data handle, close reason code)
pub type ProvCloseCb = Box<dyn FnMut(usize, u8) + Send>;

/// Called when a provisioning PDU is received from the bearer.
///
/// Mirrors C `mesh_prov_receive_func_t`:
/// `void (*)(void *user_data, const void *data, uint16_t size)`
///
/// Parameters: (user_data handle, PDU data slice)
pub type ProvRxCb = Box<dyn FnMut(usize, &[u8]) + Send>;

/// Called when an outbound provisioning message is acknowledged by the bearer.
///
/// Mirrors C `mesh_prov_ack_func_t`:
/// `void (*)(void *user_data, uint8_t msg_num)`
///
/// Parameters: (user_data handle, acknowledged message number)
pub type ProvAckCb = Box<dyn FnMut(usize, u8) + Send>;

/// Completion callback for provisioning (used by both acceptor and initiator).
///
/// Called when the provisioning procedure completes (success or failure).
/// On success, the `MeshProvNodeInfo` contains the provisioned node information.
/// Returns `true` to indicate the caller should keep the session state.
pub type ProvCompleteCb = Box<dyn FnOnce(u8, Option<MeshProvNodeInfo>) -> bool + Send>;

// ---------------------------------------------------------------------------
// PDU Structures
// ---------------------------------------------------------------------------

/// Provisioning Invite structure.
///
/// Mirrors C `struct prov_invite` from prov.h (1 byte on wire).
/// Sent by the provisioner to begin provisioning, carrying the attention
/// timer duration in seconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProvInvite {
    /// Attention timer value in seconds (0 = off)
    pub attention: u8,
}

/// Provisioning Capabilities structure.
///
/// Mirrors C `struct mesh_net_prov_caps` from prov.h (11 bytes on wire).
/// Sent by the device in response to a Provisioning Invite.
#[derive(Debug, Clone, Copy, Default)]
pub struct MeshNetProvCaps {
    /// Number of elements supported by the device
    pub num_ele: u8,
    /// Supported algorithms bitmask (bit 0 = FIPS P-256)
    pub algorithms: u16,
    /// Supported public key types (0 = no OOB, 1 = OOB available)
    pub pub_type: u8,
    /// Supported static OOB types (0 = not available, 1 = available)
    pub static_type: u8,
    /// Maximum size of output OOB supported
    pub output_size: u8,
    /// Supported output OOB actions bitmask
    pub output_action: u16,
    /// Maximum size of input OOB supported
    pub input_size: u8,
    /// Supported input OOB actions bitmask
    pub input_action: u16,
}

impl MeshNetProvCaps {
    /// Serialize capabilities to an 11-byte big-endian wire format array.
    ///
    /// Field order matches the C packed struct exactly:
    /// `[num_ele(1), algorithms(2 BE), pub_type(1), static_type(1),
    ///   output_size(1), output_action(2 BE), input_size(1), input_action(2 BE)]`
    pub fn to_bytes(self) -> [u8; 11] {
        let alg = self.algorithms.to_be_bytes();
        let out_act = self.output_action.to_be_bytes();
        let in_act = self.input_action.to_be_bytes();
        [
            self.num_ele,
            alg[0],
            alg[1],
            self.pub_type,
            self.static_type,
            self.output_size,
            out_act[0],
            out_act[1],
            self.input_size,
            in_act[0],
            in_act[1],
        ]
    }

    /// Deserialize capabilities from an 11-byte big-endian wire format slice.
    /// Returns `None` if the slice is too short.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 11 {
            return None;
        }
        Some(Self {
            num_ele: data[0],
            algorithms: u16::from_be_bytes([data[1], data[2]]),
            pub_type: data[3],
            static_type: data[4],
            output_size: data[5],
            output_action: u16::from_be_bytes([data[6], data[7]]),
            input_size: data[8],
            input_action: u16::from_be_bytes([data[9], data[10]]),
        })
    }
}

/// Provisioning Start structure.
///
/// Mirrors C `struct prov_start` from prov.h (5 bytes on wire).
/// Sent by the provisioner to select provisioning parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProvStart {
    /// Algorithm to use (0 = FIPS P-256)
    pub algorithm: u8,
    /// Public key type (0 = no OOB public key, 1 = OOB public key used)
    pub pub_key: u8,
    /// Authentication method (0 = no OOB, 1 = static, 2 = output, 3 = input)
    pub auth_method: u8,
    /// Authentication action (specific to auth_method)
    pub auth_action: u8,
    /// Authentication size (number of digits/characters)
    pub auth_size: u8,
}

impl ProvStart {
    /// Serialize start parameters to a 5-byte wire format array.
    /// All fields are single bytes, so no endian conversion is needed.
    pub fn to_bytes(self) -> [u8; 5] {
        [self.algorithm, self.pub_key, self.auth_method, self.auth_action, self.auth_size]
    }

    /// Deserialize start parameters from a 5-byte wire format slice.
    /// Returns `None` if the slice is too short.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        Some(Self {
            algorithm: data[0],
            pub_key: data[1],
            auth_method: data[2],
            auth_action: data[3],
            auth_size: data[4],
        })
    }
}

/// Confirmation Input structure.
///
/// Mirrors C `struct conf_input` from prov.h (145 bytes on wire).
/// Concatenation of invite, capabilities, start parameters, and both
/// public keys used to derive the confirmation salt.
#[derive(Debug, Clone)]
pub struct ConfInput {
    /// Provisioning Invite data (1 byte: attention)
    pub invite: ProvInvite,
    /// Provisioning Capabilities (11 bytes)
    pub caps: MeshNetProvCaps,
    /// Provisioning Start parameters (5 bytes)
    pub start: ProvStart,
    /// Provisioner's public key (64 bytes: X || Y coordinates)
    pub prv_pub_key: [u8; 64],
    /// Device's public key (64 bytes: X || Y coordinates)
    pub dev_pub_key: [u8; 64],
}

impl Default for ConfInput {
    fn default() -> Self {
        Self {
            invite: ProvInvite::default(),
            caps: MeshNetProvCaps::default(),
            start: ProvStart::default(),
            prv_pub_key: [0u8; 64],
            dev_pub_key: [0u8; 64],
        }
    }
}

impl ConfInput {
    /// Serialize the confirmation inputs to a 145-byte wire-order vector.
    ///
    /// Byte layout matches the C `__attribute__((packed)) struct conf_input`:
    /// - `invite.attention` (1 byte)
    /// - `caps` fields (11 bytes, multi-byte fields in big-endian)
    /// - `start` fields (5 bytes)
    /// - `prv_pub_key` (64 bytes)
    /// - `dev_pub_key` (64 bytes)
    ///
    /// Total: 1 + 11 + 5 + 64 + 64 = 145 bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(145);
        // Invite: 1 byte
        buf.push(self.invite.attention);
        // Caps: 11 bytes (big-endian for multi-byte fields)
        buf.extend_from_slice(&self.caps.to_bytes());
        // Start: 5 bytes
        buf.extend_from_slice(&self.start.to_bytes());
        // Provisioner public key: 64 bytes
        buf.extend_from_slice(&self.prv_pub_key);
        // Device public key: 64 bytes
        buf.extend_from_slice(&self.dev_pub_key);
        buf
    }
}

/// Provisioning Data structure.
///
/// Mirrors C `struct prov_data` from prov.h (25 bytes on wire before encryption).
/// Contains the network key and node configuration assigned during provisioning.
#[derive(Debug, Clone)]
pub struct ProvData {
    /// Network key (16 bytes)
    pub net_key: [u8; 16],
    /// Network key index (big-endian on wire)
    pub net_idx: u16,
    /// Flags (Key Refresh: bit 0, IV Update: bit 1)
    pub flags: u8,
    /// Current IV index (big-endian on wire)
    pub iv_index: u32,
    /// Primary unicast address assigned to the device (big-endian on wire)
    pub primary: u16,
}

impl ProvData {
    /// Serialize provisioning data to a 25-byte big-endian wire format array.
    ///
    /// Field order: `[net_key(16), net_idx(2 BE), flags(1), iv_index(4 BE), primary(2 BE)]`
    pub fn to_bytes(&self) -> [u8; 25] {
        let mut buf = [0u8; 25];
        buf[0..16].copy_from_slice(&self.net_key);
        buf[16..18].copy_from_slice(&self.net_idx.to_be_bytes());
        buf[18] = self.flags;
        buf[19..23].copy_from_slice(&self.iv_index.to_be_bytes());
        buf[23..25].copy_from_slice(&self.primary.to_be_bytes());
        buf
    }

    /// Deserialize provisioning data from a 25-byte big-endian wire format slice.
    /// Returns `None` if the slice is too short.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 25 {
            return None;
        }
        let mut net_key = [0u8; 16];
        net_key.copy_from_slice(&data[0..16]);
        Some(Self {
            net_key,
            net_idx: u16::from_be_bytes([data[16], data[17]]),
            flags: data[18],
            iv_index: u32::from_be_bytes([data[19], data[20], data[21], data[22]]),
            primary: u16::from_be_bytes([data[23], data[24]]),
        })
    }
}

/// Result of a successful provisioning procedure.
///
/// Mirrors C `struct mesh_prov_node_info` from provision.h.
/// Contains all information needed to configure the newly provisioned node.
#[derive(Debug, Clone)]
pub struct MeshProvNodeInfo {
    /// Device key derived during provisioning (16 bytes)
    pub device_key: [u8; 16],
    /// Network key assigned to the device (16 bytes)
    pub net_key: [u8; 16],
    /// Network key index
    pub net_index: u16,
    /// Provisioning flags (Key Refresh, IV Update)
    pub flags: u8,
    /// IV index at time of provisioning
    pub iv_index: u32,
    /// Primary unicast address assigned
    pub unicast: u16,
    /// Number of elements on the provisioned device
    pub num_ele: u8,
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Reverse byte order of a 256-bit (32-byte) number in place.
///
/// Used for ECDH key byte-order conversion between the ECC library's
/// native byte order and the Mesh specification's wire byte order.
/// Mirrors C `swap_u256_bytes()` from prov-initiator.c:
/// ```c
/// for (i = 0; i < 16; i++) {
///     u256[i] ^= u256[31 - i];
///     u256[31 - i] ^= u256[i];
///     u256[i] ^= u256[31 - i];
/// }
/// ```
pub fn swap_u256_bytes(buf: &mut [u8; 32]) {
    buf.reverse();
}

/// Compute 10 raised to the given power.
///
/// Used to generate the modulus for numeric OOB display/input values.
/// Mirrors C `digit_mod()` from prov-initiator.c:
/// ```c
/// uint32_t ret = 1;
/// while (power--) ret *= 10;
/// return ret;
/// ```
///
/// - `digit_mod(0)` returns `1`
/// - `digit_mod(1)` returns `10`
/// - `digit_mod(8)` returns `100_000_000`
pub fn digit_mod(power: u8) -> u32 {
    10_u32.pow(u32::from(power))
}
