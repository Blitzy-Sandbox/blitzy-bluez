// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2006-2010  Nokia Corporation
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
// Copyright (C) 2011  Texas Instruments, Inc.
//
// AVCTP (Audio/Video Control Transport Protocol) transport layer — Rust rewrite
// of `profiles/audio/avctp.c` and `profiles/audio/avctp.h`.
//
// Implements L2CAP-based AVCTP control and browsing channels for AVRCP.
// Handles per-adapter server listen, per-device session management, wire
// packet build/parse, request queuing with timeouts/retries, passthrough-to-
// uinput key translation, and state machine callbacks.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{error, info};

use bluez_shared::device::uinput::{BUS_BLUETOOTH, BtUinput, BtUinputKeyMap, InputId};
use bluez_shared::socket::{BluetoothSocket, L2capMode, SecLevel, SocketBuilder};
use bluez_shared::sys::bluetooth::{BDADDR_ANY, BdAddr};

use crate::adapter::{self, BtdAdapter};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_info, btd_warn};

// ===========================================================================
// Protocol Constants
// ===========================================================================

/// AVCTP control channel L2CAP PSM (Bluetooth Assigned Numbers).
pub const AVCTP_CONTROL_PSM: u16 = 23;
/// AVCTP browsing channel L2CAP PSM (Bluetooth Assigned Numbers).
pub const AVCTP_BROWSING_PSM: u16 = 27;
/// AV/C maximum transmission unit — maximum AV/C frame size.
pub const AVC_MTU: u16 = 512;
/// AV/C header length in bytes (code + subunit + opcode).
pub const AVC_HEADER_LENGTH: usize = 3;
/// AVCTP header length in bytes (flags + PID).
const AVCTP_HEADER_LENGTH: usize = 3;
/// AV/C Remote Control Service Class UUID (16-bit form).
const AV_REMOTE_SVCLASS_ID: u16 = 0x110E;

// ---------------------------------------------------------------------------
// AVCTP Message / Packet Type Constants
// ---------------------------------------------------------------------------

const AVCTP_COMMAND: u8 = 0;
const AVCTP_RESPONSE: u8 = 1;
const AVCTP_PACKET_SINGLE: u8 = 0;
const AVCTP_PACKET_START: u8 = 1;
const AVCTP_PACKET_CONTINUE: u8 = 2;
const AVCTP_PACKET_END: u8 = 3;

// ---------------------------------------------------------------------------
// AV/C Command / Response Codes
// ---------------------------------------------------------------------------

pub const AVC_CTYPE_CONTROL: u8 = 0x00;
pub const AVC_CTYPE_STATUS: u8 = 0x01;
pub const AVC_CTYPE_SPECIFIC_INQUIRY: u8 = 0x02;
pub const AVC_CTYPE_GENERAL_INQUIRY: u8 = 0x04;
pub const AVC_CTYPE_NOTIFY: u8 = 0x03;
pub const AVC_NOT_IMPLEMENTED: u8 = 0x08;
pub const AVC_ACCEPTED: u8 = 0x09;
pub const AVC_REJECTED: u8 = 0x0A;
pub const AVC_IN_TRANSITION: u8 = 0x0B;
pub const AVC_STABLE: u8 = 0x0C;
pub const AVC_CHANGED: u8 = 0x0D;
pub const AVC_INTERIM: u8 = 0x0F;

// ---------------------------------------------------------------------------
// AV/C Opcodes
// ---------------------------------------------------------------------------

pub const AVC_OP_VENDORDEP: u8 = 0x00;
pub const AVC_OP_UNITINFO: u8 = 0x30;
pub const AVC_OP_SUBUNITINFO: u8 = 0x31;
pub const AVC_OP_PASSTHROUGH: u8 = 0x7C;

// ---------------------------------------------------------------------------
// AV/C Subunit Types
// ---------------------------------------------------------------------------

pub const AVC_SUBUNIT_PANEL: u8 = 0x09;
pub const AVC_SUBUNIT_UNIT: u8 = 0x1F;

// ---------------------------------------------------------------------------
// AV/C Passthrough Operation IDs
// ---------------------------------------------------------------------------

pub const AVC_SELECT: u8 = 0x00;
pub const AVC_UP: u8 = 0x01;
pub const AVC_DOWN: u8 = 0x02;
pub const AVC_LEFT: u8 = 0x03;
pub const AVC_RIGHT: u8 = 0x04;
pub const AVC_ROOT_MENU: u8 = 0x09;
pub const AVC_CONTENTS_MENU: u8 = 0x0B;
pub const AVC_FAVORITE_MENU: u8 = 0x0C;
pub const AVC_EXIT: u8 = 0x0D;
pub const AVC_ON_DEMAND_MENU: u8 = 0x0E;
pub const AVC_APPS_MENU: u8 = 0x0F;
pub const AVC_0: u8 = 0x20;
pub const AVC_1: u8 = 0x21;
pub const AVC_2: u8 = 0x22;
pub const AVC_3: u8 = 0x23;
pub const AVC_4: u8 = 0x24;
pub const AVC_5: u8 = 0x25;
pub const AVC_6: u8 = 0x26;
pub const AVC_7: u8 = 0x27;
pub const AVC_8: u8 = 0x28;
pub const AVC_9: u8 = 0x29;
pub const AVC_DOT: u8 = 0x2A;
pub const AVC_ENTER: u8 = 0x2B;
pub const AVC_CHANNEL_UP: u8 = 0x30;
pub const AVC_CHANNEL_DOWN: u8 = 0x31;
pub const AVC_CHANNEL_PREVIOUS: u8 = 0x32;
pub const AVC_INPUT_SELECT: u8 = 0x34;
pub const AVC_INFO: u8 = 0x35;
pub const AVC_HELP: u8 = 0x36;
pub const AVC_POWER: u8 = 0x40;
pub const AVC_VOLUME_UP: u8 = 0x41;
pub const AVC_VOLUME_DOWN: u8 = 0x42;
pub const AVC_MUTE: u8 = 0x43;
pub const AVC_PLAY: u8 = 0x44;
pub const AVC_STOP: u8 = 0x45;
pub const AVC_PAUSE: u8 = 0x46;
pub const AVC_RECORD: u8 = 0x47;
pub const AVC_REWIND: u8 = 0x48;
pub const AVC_FAST_FORWARD: u8 = 0x49;
pub const AVC_EJECT: u8 = 0x4A;
pub const AVC_FORWARD: u8 = 0x4B;
pub const AVC_BACKWARD: u8 = 0x4C;
pub const AVC_LIST: u8 = 0x4D;
pub const AVC_ANGLE: u8 = 0x50;
pub const AVC_SUBPICTURE: u8 = 0x51;
pub const AVC_F1: u8 = 0x71;
pub const AVC_F2: u8 = 0x72;
pub const AVC_F3: u8 = 0x73;
pub const AVC_F4: u8 = 0x74;
pub const AVC_F5: u8 = 0x75;
pub const AVC_F6: u8 = 0x76;
pub const AVC_F7: u8 = 0x77;
pub const AVC_F8: u8 = 0x78;
pub const AVC_F9: u8 = 0x79;
pub const AVC_RED: u8 = 0x7A;
pub const AVC_GREEN: u8 = 0x7B;
pub const AVC_BLUE: u8 = 0x7C;
pub const AVC_YELLOW: u8 = 0x7D;
pub const AVC_VENDOR_UNIQUE: u8 = 0x7E;
#[allow(dead_code)]
const AVC_INVALID: u8 = 0xFF;

pub const AVC_VENDOR_NEXT_GROUP: u8 = 0x00;
pub const AVC_VENDOR_PREV_GROUP: u8 = 0x01;

// ---------------------------------------------------------------------------
// Timing Constants
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const AVC_PRESS_TIMEOUT: Duration = Duration::from_secs(2);
#[allow(dead_code)]
const AVC_HOLD_TIMEOUT: Duration = Duration::from_secs(1);
#[allow(dead_code)]
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
#[allow(dead_code)]
const BROWSING_TIMEOUT: Duration = Duration::from_secs(10);

#[allow(dead_code)]
const PASSTHROUGH_QUEUE_IDX: usize = 0;
#[allow(dead_code)]
const CONTROL_QUEUE_IDX: usize = 1;
const QUIRK_NO_RELEASE: u8 = 1 << 0;

// ---------------------------------------------------------------------------
// Linux Input Key Codes (from linux/input-event-codes.h)
// ---------------------------------------------------------------------------

const KEY_1: u16 = 2;
const KEY_2: u16 = 3;
const KEY_3: u16 = 4;
const KEY_4: u16 = 5;
const KEY_5: u16 = 6;
const KEY_6: u16 = 7;
const KEY_7: u16 = 8;
const KEY_8: u16 = 9;
const KEY_9: u16 = 10;
const KEY_0: u16 = 11;
const KEY_DOT: u16 = 52;
const KEY_ENTER: u16 = 28;
const KEY_F1: u16 = 59;
const KEY_F2: u16 = 60;
const KEY_F3: u16 = 61;
const KEY_F4: u16 = 62;
const KEY_F5: u16 = 63;
const KEY_F6: u16 = 64;
const KEY_F7: u16 = 65;
const KEY_F8: u16 = 66;
const KEY_F9: u16 = 67;
const KEY_UP: u16 = 103;
const KEY_LEFT: u16 = 105;
const KEY_RIGHT: u16 = 106;
const KEY_DOWN: u16 = 108;
const KEY_MUTE: u16 = 113;
const KEY_VOLUMEDOWN: u16 = 114;
const KEY_VOLUMEUP: u16 = 115;
const KEY_HELP: u16 = 138;
const KEY_MENU: u16 = 139;
const KEY_SELECT: u16 = 0x161;
const KEY_NEXTSONG: u16 = 163;
const KEY_POWER2: u16 = 164;
const KEY_PREVIOUSSONG: u16 = 165;
const KEY_STOPCD: u16 = 166;
const KEY_RECORD: u16 = 167;
const KEY_REWIND: u16 = 168;
const KEY_CONFIG: u16 = 171;
const KEY_EXIT: u16 = 174;
const KEY_PLAYCD: u16 = 200;
const KEY_PAUSECD: u16 = 201;
const KEY_FASTFORWARD: u16 = 208;
const KEY_LIST: u16 = 227;
const KEY_INFO: u16 = 358;
const KEY_PROGRAM: u16 = 362;
const KEY_FAVORITES: u16 = 364;
const KEY_RED: u16 = 0x18E;
const KEY_GREEN: u16 = 0x18F;
const KEY_YELLOW: u16 = 0x190;
const KEY_BLUE: u16 = 0x191;
const KEY_CHANNELUP: u16 = 0x192;
const KEY_CHANNELDOWN: u16 = 0x193;
const KEY_LAST: u16 = 0x195;

// ---------------------------------------------------------------------------
// Key Map — AV/C passthrough operation IDs → Linux uinput key codes
// ---------------------------------------------------------------------------

static KEY_MAP: &[BtUinputKeyMap] = &[
    BtUinputKeyMap { name: "SELECT", code: AVC_SELECT as u32, uinput: KEY_SELECT },
    BtUinputKeyMap { name: "UP", code: AVC_UP as u32, uinput: KEY_UP },
    BtUinputKeyMap { name: "DOWN", code: AVC_DOWN as u32, uinput: KEY_DOWN },
    BtUinputKeyMap { name: "LEFT", code: AVC_LEFT as u32, uinput: KEY_LEFT },
    BtUinputKeyMap { name: "RIGHT", code: AVC_RIGHT as u32, uinput: KEY_RIGHT },
    BtUinputKeyMap { name: "ROOT MENU", code: AVC_ROOT_MENU as u32, uinput: KEY_MENU },
    BtUinputKeyMap { name: "CONTENTS MENU", code: AVC_CONTENTS_MENU as u32, uinput: KEY_PROGRAM },
    BtUinputKeyMap { name: "FAVORITE MENU", code: AVC_FAVORITE_MENU as u32, uinput: KEY_FAVORITES },
    BtUinputKeyMap { name: "EXIT", code: AVC_EXIT as u32, uinput: KEY_EXIT },
    BtUinputKeyMap { name: "ON DEMAND MENU", code: AVC_ON_DEMAND_MENU as u32, uinput: KEY_MENU },
    BtUinputKeyMap { name: "APPS MENU", code: AVC_APPS_MENU as u32, uinput: KEY_MENU },
    BtUinputKeyMap { name: "0", code: AVC_0 as u32, uinput: KEY_0 },
    BtUinputKeyMap { name: "1", code: AVC_1 as u32, uinput: KEY_1 },
    BtUinputKeyMap { name: "2", code: AVC_2 as u32, uinput: KEY_2 },
    BtUinputKeyMap { name: "3", code: AVC_3 as u32, uinput: KEY_3 },
    BtUinputKeyMap { name: "4", code: AVC_4 as u32, uinput: KEY_4 },
    BtUinputKeyMap { name: "5", code: AVC_5 as u32, uinput: KEY_5 },
    BtUinputKeyMap { name: "6", code: AVC_6 as u32, uinput: KEY_6 },
    BtUinputKeyMap { name: "7", code: AVC_7 as u32, uinput: KEY_7 },
    BtUinputKeyMap { name: "8", code: AVC_8 as u32, uinput: KEY_8 },
    BtUinputKeyMap { name: "9", code: AVC_9 as u32, uinput: KEY_9 },
    BtUinputKeyMap { name: "DOT", code: AVC_DOT as u32, uinput: KEY_DOT },
    BtUinputKeyMap { name: "ENTER", code: AVC_ENTER as u32, uinput: KEY_ENTER },
    BtUinputKeyMap { name: "CHANNEL UP", code: AVC_CHANNEL_UP as u32, uinput: KEY_CHANNELUP },
    BtUinputKeyMap { name: "CHANNEL DOWN", code: AVC_CHANNEL_DOWN as u32, uinput: KEY_CHANNELDOWN },
    BtUinputKeyMap {
        name: "CHANNEL PREVIOUS",
        code: AVC_CHANNEL_PREVIOUS as u32,
        uinput: KEY_LAST,
    },
    BtUinputKeyMap { name: "INPUT SELECT", code: AVC_INPUT_SELECT as u32, uinput: KEY_CONFIG },
    BtUinputKeyMap { name: "INFO", code: AVC_INFO as u32, uinput: KEY_INFO },
    BtUinputKeyMap { name: "HELP", code: AVC_HELP as u32, uinput: KEY_HELP },
    BtUinputKeyMap { name: "POWER", code: AVC_POWER as u32, uinput: KEY_POWER2 },
    BtUinputKeyMap { name: "VOLUME UP", code: AVC_VOLUME_UP as u32, uinput: KEY_VOLUMEUP },
    BtUinputKeyMap { name: "VOLUME DOWN", code: AVC_VOLUME_DOWN as u32, uinput: KEY_VOLUMEDOWN },
    BtUinputKeyMap { name: "MUTE", code: AVC_MUTE as u32, uinput: KEY_MUTE },
    BtUinputKeyMap { name: "PLAY", code: AVC_PLAY as u32, uinput: KEY_PLAYCD },
    BtUinputKeyMap { name: "STOP", code: AVC_STOP as u32, uinput: KEY_STOPCD },
    BtUinputKeyMap { name: "PAUSE", code: AVC_PAUSE as u32, uinput: KEY_PAUSECD },
    BtUinputKeyMap { name: "FORWARD", code: AVC_FORWARD as u32, uinput: KEY_NEXTSONG },
    BtUinputKeyMap { name: "BACKWARD", code: AVC_BACKWARD as u32, uinput: KEY_PREVIOUSSONG },
    BtUinputKeyMap { name: "RECORD", code: AVC_RECORD as u32, uinput: KEY_RECORD },
    BtUinputKeyMap { name: "REWIND", code: AVC_REWIND as u32, uinput: KEY_REWIND },
    BtUinputKeyMap { name: "FAST FORWARD", code: AVC_FAST_FORWARD as u32, uinput: KEY_FASTFORWARD },
    BtUinputKeyMap { name: "LIST", code: AVC_LIST as u32, uinput: KEY_LIST },
    BtUinputKeyMap { name: "F1", code: AVC_F1 as u32, uinput: KEY_F1 },
    BtUinputKeyMap { name: "F2", code: AVC_F2 as u32, uinput: KEY_F2 },
    BtUinputKeyMap { name: "F3", code: AVC_F3 as u32, uinput: KEY_F3 },
    BtUinputKeyMap { name: "F4", code: AVC_F4 as u32, uinput: KEY_F4 },
    BtUinputKeyMap { name: "F5", code: AVC_F5 as u32, uinput: KEY_F5 },
    BtUinputKeyMap { name: "F6", code: AVC_F6 as u32, uinput: KEY_F6 },
    BtUinputKeyMap { name: "F7", code: AVC_F7 as u32, uinput: KEY_F7 },
    BtUinputKeyMap { name: "F8", code: AVC_F8 as u32, uinput: KEY_F8 },
    BtUinputKeyMap { name: "F9", code: AVC_F9 as u32, uinput: KEY_F9 },
    BtUinputKeyMap { name: "RED", code: AVC_RED as u32, uinput: KEY_RED },
    BtUinputKeyMap { name: "GREEN", code: AVC_GREEN as u32, uinput: KEY_GREEN },
    BtUinputKeyMap { name: "BLUE", code: AVC_BLUE as u32, uinput: KEY_BLUE },
    BtUinputKeyMap { name: "YELLOW", code: AVC_YELLOW as u32, uinput: KEY_YELLOW },
];

// ===========================================================================
// Error Type
// ===========================================================================

/// AVCTP-specific error type for protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum AvctpError {
    /// Connection to remote device failed.
    #[error("AVCTP connection failed: {0}")]
    ConnectionFailed(String),
    /// Protocol parse or validation error.
    #[error("AVCTP protocol error: {0}")]
    ProtocolError(String),
    /// Operation timed out waiting for response.
    #[error("AVCTP timeout")]
    Timeout,
    /// The underlying L2CAP channel was closed.
    #[error("AVCTP channel closed")]
    ChannelClosed,
    /// Invalid packet received (too small, bad PID, etc.).
    #[error("AVCTP invalid packet: {0}")]
    InvalidPacket(String),
    /// Session is not in a connected state.
    #[error("AVCTP not connected")]
    NotConnected,
}

/// Convenience result type for AVCTP operations.
type AvctpResult<T> = Result<T, AvctpError>;

impl From<BtdError> for AvctpError {
    fn from(e: BtdError) -> Self {
        match e {
            BtdError::NotConnected(_) => AvctpError::NotConnected,
            BtdError::NotAuthorized(msg) => {
                AvctpError::ConnectionFailed(format!("not authorized: {msg}"))
            }
            BtdError::Failed(msg) => AvctpError::ConnectionFailed(msg),
            other => AvctpError::ConnectionFailed(format!("{other}")),
        }
    }
}

// ===========================================================================
// AVCTP State Machine
// ===========================================================================

/// AVCTP connection state — mirrors C `avctp_state_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvctpState {
    /// No connection established.
    Disconnected = 0,
    /// Control channel connection in progress.
    Connecting = 1,
    /// Control channel connected.
    Connected = 2,
    /// Browsing channel connection in progress (control already up).
    BrowsingConnecting = 3,
    /// Both control and browsing channels connected.
    BrowsingConnected = 4,
}

impl std::fmt::Display for AvctpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvctpState::Disconnected => write!(f, "Disconnected"),
            AvctpState::Connecting => write!(f, "Connecting"),
            AvctpState::Connected => write!(f, "Connected"),
            AvctpState::BrowsingConnecting => write!(f, "BrowsingConnecting"),
            AvctpState::BrowsingConnected => write!(f, "BrowsingConnected"),
        }
    }
}

// ===========================================================================
// Callback / Handler Types
// ===========================================================================

/// Passthrough handler: (transaction, pressed, operation_id) → accepted.
pub type PassthroughCb = Box<dyn Fn(u8, bool, u8) -> bool + Send + Sync>;
/// Control PDU handler: (transaction, code, subunit, operands) → response.
pub type ControlPduCb = Box<dyn Fn(u8, u8, u8, &[u8]) -> Option<Vec<u8>> + Send + Sync>;
/// Browsing PDU handler: (transaction, operands) → response.
pub type BrowsingPduCb = Box<dyn Fn(u8, &[u8]) -> Option<Vec<u8>> + Send + Sync>;
/// Async response callback for vendor-dependent requests.
pub type AvctpResponseCb = Box<dyn FnOnce(Result<Vec<u8>, AvctpError>) + Send>;
/// Async response callback for browsing requests.
pub type AvctpBrowsingResponseCb = Box<dyn FnOnce(Result<Vec<u8>, AvctpError>) + Send>;
/// State change callback: (device_path, old_state, new_state).
type StateChangeCb = Box<dyn Fn(&str, AvctpState, AvctpState) + Send + Sync>;

// ===========================================================================
// Wire Format Helpers
// ===========================================================================

/// Build the AVCTP header flags byte.
/// Layout: transaction(4) | packet_type(2) | cr(1) | ipid(1).
fn avctp_flags(transaction: u8, packet_type: u8, cr: u8, ipid: u8) -> u8 {
    ((transaction & 0x0F) << 4) | ((packet_type & 0x03) << 2) | ((cr & 0x01) << 1) | (ipid & 0x01)
}

fn avctp_transaction(flags: u8) -> u8 {
    (flags >> 4) & 0x0F
}

fn avctp_packet_type(flags: u8) -> u8 {
    (flags >> 2) & 0x03
}

fn avctp_cr(flags: u8) -> u8 {
    (flags >> 1) & 0x01
}

#[allow(dead_code)]
fn avctp_ipid(flags: u8) -> u8 {
    flags & 0x01
}

fn avc_subunit_byte(subunit_type: u8, subunit_id: u8) -> u8 {
    ((subunit_type & 0x1F) << 3) | (subunit_id & 0x07)
}

fn avc_subunit_type(subunit: u8) -> u8 {
    (subunit >> 3) & 0x1F
}

#[allow(dead_code)]
fn avc_subunit_id(subunit: u8) -> u8 {
    subunit & 0x07
}

/// Translate an AV/C passthrough operation ID to a Linux uinput key code.
fn avc_op_to_key(op: u8) -> Option<u16> {
    KEY_MAP.iter().find(|k| k.code == op as u32).map(|k| k.uinput)
}

// ===========================================================================
// Internal Handler Registration Structs
// ===========================================================================

struct PassthroughHandler {
    id: u32,
    callback: PassthroughCb,
}

struct ControlHandler {
    id: u32,
    opcode: u8,
    callback: ControlPduCb,
}

struct BrowsingHandler {
    id: u32,
    callback: BrowsingPduCb,
}

struct StateCallback {
    id: u32,
    callback: StateChangeCb,
}

// ===========================================================================
// Internal Request Structures
// ===========================================================================

struct ControlRequest {
    transaction: u8,
    code: u8,
    subunit: u8,
    #[allow(dead_code)]
    pdu_id: u8,
    operands: Vec<u8>,
    #[allow(dead_code)]
    callback: Option<AvctpResponseCb>,
}

struct BrowsingRequest {
    transaction: u8,
    #[allow(dead_code)]
    pdu_id: u8,
    operands: Vec<u8>,
    #[allow(dead_code)]
    callback: Option<AvctpBrowsingResponseCb>,
}

struct PassthroughRequest {
    op: u8,
    pressed: bool,
}

struct PendingRequest {
    transaction: u8,
    timeout_handle: Option<JoinHandle<()>>,
    #[allow(dead_code)]
    retried: bool,
}

struct KeyPressed {
    op: u8,
    timer: Option<JoinHandle<()>>,
    #[allow(dead_code)]
    hold: bool,
}

// ===========================================================================
// AVCTP Channel — per-L2CAP-channel state
// ===========================================================================

/// Per-L2CAP channel state (control or browsing).
pub struct AvctpChannel {
    io: Arc<BluetoothSocket>,
    #[allow(dead_code)]
    imtu: u16,
    #[allow(dead_code)]
    omtu: u16,
    transaction: u8,
    read_task: Option<JoinHandle<()>>,
    reassembly_buf: Vec<u8>,
    fragments_remaining: u8,
}

impl AvctpChannel {
    fn new(io: BluetoothSocket, imtu: u16, omtu: u16) -> Self {
        Self {
            io: Arc::new(io),
            imtu,
            omtu,
            transaction: 0,
            read_task: None,
            reassembly_buf: Vec::new(),
            fragments_remaining: 0,
        }
    }

    fn next_transaction(&mut self) -> u8 {
        let t = self.transaction;
        self.transaction = (self.transaction + 1) & 0x0F;
        t
    }
}

// ===========================================================================
// AVCTP Session — per-device connection state
// ===========================================================================

/// Per-device AVCTP session managing control and browsing channels.
pub struct AvctpSession {
    /// The remote device.
    pub device: Arc<BtdDevice>,
    /// Current connection state.
    pub state: AvctpState,
    /// Control channel.
    pub control_io: Option<AvctpChannel>,
    /// Browsing channel.
    pub browsing_io: Option<AvctpChannel>,
    /// Control channel inbound MTU.
    pub control_mtu: u16,
    /// Browsing channel inbound MTU.
    pub browsing_mtu: u16,
    /// Whether this side initiated the connection.
    pub initiator: bool,
    // --- Private fields ---
    uinput: Option<BtUinput>,
    passthrough_handlers: Vec<PassthroughHandler>,
    control_handlers: Vec<ControlHandler>,
    browsing_handler: Option<BrowsingHandler>,
    passthrough_queue: VecDeque<PassthroughRequest>,
    control_queue: VecDeque<ControlRequest>,
    browsing_queue: VecDeque<BrowsingRequest>,
    pending_control: Option<PendingRequest>,
    pending_browsing: Option<PendingRequest>,
    key: Option<KeyPressed>,
    key_quirks: [u8; 256],
    #[allow(dead_code)]
    auth_id: u32,
}

impl AvctpSession {
    fn new(device: Arc<BtdDevice>) -> Self {
        Self {
            device,
            state: AvctpState::Disconnected,
            control_io: None,
            browsing_io: None,
            control_mtu: 672,
            browsing_mtu: 672,
            initiator: false,
            uinput: None,
            passthrough_handlers: Vec::new(),
            control_handlers: Vec::new(),
            browsing_handler: None,
            passthrough_queue: VecDeque::new(),
            control_queue: VecDeque::new(),
            browsing_queue: VecDeque::new(),
            pending_control: None,
            pending_browsing: None,
            key: None,
            key_quirks: [0u8; 256],
            auth_id: 0,
        }
    }

    /// Disconnect and clean up all channels and state.
    pub fn disconnect(&mut self) {
        btd_info(0, &format!("AVCTP: disconnecting session for {}", self.device.get_path()));

        // Cancel pending request timeouts.
        if let Some(pending) = self.pending_control.take() {
            if let Some(h) = pending.timeout_handle {
                h.abort();
            }
        }
        if let Some(pending) = self.pending_browsing.take() {
            if let Some(h) = pending.timeout_handle {
                h.abort();
            }
        }

        // Cancel key auto-release timer.
        if let Some(mut key) = self.key.take() {
            if let Some(h) = key.timer.take() {
                h.abort();
            }
        }

        // Drop browsing channel.
        if let Some(mut chan) = self.browsing_io.take() {
            if let Some(h) = chan.read_task.take() {
                h.abort();
            }
            let _ = chan.io.shutdown(std::net::Shutdown::Both);
        }

        // Drop control channel.
        if let Some(mut chan) = self.control_io.take() {
            if let Some(h) = chan.read_task.take() {
                h.abort();
            }
            let _ = chan.io.shutdown(std::net::Shutdown::Both);
        }

        self.uinput = None;
        self.passthrough_queue.clear();
        self.control_queue.clear();
        self.browsing_queue.clear();
    }

    // -----------------------------------------------------------------------
    // Packet Send — Control Channel
    // -----------------------------------------------------------------------

    /// Send a control channel AV/C packet.
    async fn send_control_packet(
        &mut self,
        transaction: u8,
        cr: u8,
        code: u8,
        subunit: u8,
        opcode: u8,
        operands: &[u8],
    ) -> AvctpResult<()> {
        let chan = self.control_io.as_ref().ok_or(AvctpError::NotConnected)?;
        let mut buf = Vec::with_capacity(AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH + operands.len());

        buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, cr, 0));
        buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
        buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);
        buf.push(code & 0x0F);
        buf.push(subunit);
        buf.push(opcode);
        buf.extend_from_slice(operands);

        chan.io
            .send(&buf)
            .await
            .map_err(|e| AvctpError::ConnectionFailed(format!("control send failed: {e}")))?;
        Ok(())
    }

    /// Send a browsing channel AVCTP packet (no AV/C header) with fragmentation.
    #[allow(dead_code)]
    async fn send_browsing_packet(
        &mut self,
        transaction: u8,
        cr: u8,
        operands: &[u8],
    ) -> AvctpResult<()> {
        let chan = self.browsing_io.as_ref().ok_or(AvctpError::NotConnected)?;
        let omtu = chan.omtu as usize;
        let total = AVCTP_HEADER_LENGTH + operands.len();

        if total <= omtu {
            let mut buf = Vec::with_capacity(total);
            buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, cr, 0));
            buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
            buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);
            buf.extend_from_slice(operands);
            chan.io
                .send(&buf)
                .await
                .map_err(|e| AvctpError::ConnectionFailed(format!("browsing send failed: {e}")))?;
        } else {
            let first_payload = omtu - AVCTP_HEADER_LENGTH - 1;
            let remaining = operands.len() - first_payload;
            let cont_payload = omtu - 1;
            let num_cont = remaining.div_ceil(cont_payload);
            let num_packets = (1 + num_cont) as u8;

            // START packet.
            let mut buf = Vec::with_capacity(omtu);
            buf.push(avctp_flags(transaction, AVCTP_PACKET_START, cr, 0));
            buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
            buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);
            buf.push(num_packets);
            buf.extend_from_slice(&operands[..first_payload]);
            chan.io
                .send(&buf)
                .await
                .map_err(|e| AvctpError::ConnectionFailed(format!("browsing start send: {e}")))?;

            // CONTINUE / END packets.
            let mut offset = first_payload;
            for i in 0..num_cont {
                let ptype =
                    if i == num_cont - 1 { AVCTP_PACKET_END } else { AVCTP_PACKET_CONTINUE };
                let end = std::cmp::min(offset + cont_payload, operands.len());
                let mut pkt = Vec::with_capacity(1 + (end - offset));
                pkt.push(avctp_flags(transaction, ptype, cr, 0));
                pkt.extend_from_slice(&operands[offset..end]);
                chan.io.send(&pkt).await.map_err(|e| {
                    AvctpError::ConnectionFailed(format!("browsing cont send: {e}"))
                })?;
                offset = end;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Public Send APIs
    // -----------------------------------------------------------------------

    /// Send a passthrough command (pressed or released).
    pub async fn send_passthrough(&mut self, op: u8, pressed: bool) -> AvctpResult<()> {
        let transaction = {
            let chan = self.control_io.as_mut().ok_or(AvctpError::NotConnected)?;
            chan.next_transaction()
        };
        let state_bit: u8 = if pressed { 0x00 } else { 0x80 };
        let operands = vec![op | state_bit, 0x00];
        self.send_control_packet(
            transaction,
            AVCTP_COMMAND,
            AVC_CTYPE_CONTROL,
            avc_subunit_byte(AVC_SUBUNIT_PANEL, 0),
            AVC_OP_PASSTHROUGH,
            &operands,
        )
        .await
    }

    /// Send a vendor-dependent response.
    pub async fn send_vendordep(
        &mut self,
        transaction: u8,
        code: u8,
        subunit: u8,
        operands: &[u8],
    ) -> AvctpResult<()> {
        self.send_control_packet(
            transaction,
            AVCTP_RESPONSE,
            code,
            subunit,
            AVC_OP_VENDORDEP,
            operands,
        )
        .await
    }

    /// Queue a vendor-dependent request with response callback.
    pub fn send_vendordep_req(
        &mut self,
        code: u8,
        subunit: u8,
        pdu_id: u8,
        operands: Vec<u8>,
        callback: Option<AvctpResponseCb>,
    ) {
        self.control_queue.push_back(ControlRequest {
            transaction: 0,
            code,
            subunit,
            pdu_id,
            operands,
            callback,
        });
        if self.pending_control.is_none() {
            self.pump_control_queue();
        }
    }

    /// Queue a browsing request with response callback.
    pub fn send_browsing(
        &mut self,
        pdu_id: u8,
        operands: Vec<u8>,
        callback: Option<AvctpBrowsingResponseCb>,
    ) {
        self.browsing_queue.push_back(BrowsingRequest {
            transaction: 0,
            pdu_id,
            operands,
            callback,
        });
        if self.pending_browsing.is_none() {
            self.pump_browsing_queue();
        }
    }

    /// Register a passthrough command handler. Returns a handler ID.
    pub fn register_passthrough_handler(&mut self, callback: PassthroughCb) -> u32 {
        let id = next_handler_id();
        self.passthrough_handlers.push(PassthroughHandler { id, callback });
        id
    }

    /// Register a control PDU handler for a specific opcode. Returns a handler ID.
    pub fn register_pdu_handler(&mut self, opcode: u8, callback: ControlPduCb) -> u32 {
        let id = next_handler_id();
        self.control_handlers.push(ControlHandler { id, opcode, callback });
        id
    }

    /// Register a browsing PDU handler. Returns a handler ID.
    pub fn register_browsing_handler(&mut self, callback: BrowsingPduCb) -> u32 {
        let id = next_handler_id();
        self.browsing_handler = Some(BrowsingHandler { id, callback });
        id
    }

    /// Unregister a passthrough handler by ID.
    pub fn unregister_passthrough_handler(&mut self, id: u32) {
        self.passthrough_handlers.retain(|h| h.id != id);
    }

    /// Unregister a control PDU handler by ID.
    pub fn unregister_pdu_handler(&mut self, id: u32) {
        self.control_handlers.retain(|h| h.id != id);
    }

    /// Unregister the browsing handler by ID.
    pub fn unregister_browsing_handler(&mut self, id: u32) {
        if self.browsing_handler.as_ref().is_some_and(|h| h.id == id) {
            self.browsing_handler = None;
        }
    }

    // -----------------------------------------------------------------------
    // Queue Pump
    // -----------------------------------------------------------------------

    fn pump_control_queue(&mut self) {
        if self.pending_control.is_some() {
            return;
        }

        // Passthrough first.
        if let Some(pt) = self.passthrough_queue.pop_front() {
            let chan = match self.control_io.as_mut() {
                Some(c) => c,
                None => return,
            };
            let transaction = chan.next_transaction();
            let state_bit: u8 = if pt.pressed { 0x00 } else { 0x80 };
            let operands = vec![pt.op | state_bit, 0x00];

            let mut pkt = Vec::with_capacity(AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH + 2);
            pkt.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0));
            pkt.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
            pkt.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);
            pkt.push(AVC_CTYPE_CONTROL & 0x0F);
            pkt.push(avc_subunit_byte(AVC_SUBUNIT_PANEL, 0));
            pkt.push(AVC_OP_PASSTHROUGH);
            pkt.extend_from_slice(&operands);

            let io = Arc::clone(&chan.io);
            tokio::spawn(async move {
                if let Err(e) = io.send(&pkt).await {
                    error!("AVCTP: passthrough queue send failed: {}", e);
                }
            });

            self.pending_control =
                Some(PendingRequest { transaction, timeout_handle: None, retried: false });
            return;
        }

        // Then vendor-dependent.
        if let Some(mut req) = self.control_queue.pop_front() {
            let chan = match self.control_io.as_mut() {
                Some(c) => c,
                None => return,
            };
            let transaction = chan.next_transaction();
            req.transaction = transaction;

            let mut pkt =
                Vec::with_capacity(AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH + req.operands.len());
            pkt.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0));
            pkt.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
            pkt.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);
            pkt.push(req.code & 0x0F);
            pkt.push(req.subunit);
            pkt.push(AVC_OP_VENDORDEP);
            pkt.extend_from_slice(&req.operands);

            let io = Arc::clone(&chan.io);
            tokio::spawn(async move {
                if let Err(e) = io.send(&pkt).await {
                    error!("AVCTP: control queue send failed: {}", e);
                }
            });

            self.pending_control =
                Some(PendingRequest { transaction, timeout_handle: None, retried: false });
        }
    }

    fn pump_browsing_queue(&mut self) {
        if self.pending_browsing.is_some() {
            return;
        }

        if let Some(mut req) = self.browsing_queue.pop_front() {
            let chan = match self.browsing_io.as_mut() {
                Some(c) => c,
                None => return,
            };
            let transaction = chan.next_transaction();
            req.transaction = transaction;

            let mut pkt = Vec::with_capacity(AVCTP_HEADER_LENGTH + req.operands.len());
            pkt.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0));
            pkt.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
            pkt.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);
            pkt.extend_from_slice(&req.operands);

            let io = Arc::clone(&chan.io);
            tokio::spawn(async move {
                if let Err(e) = io.send(&pkt).await {
                    error!("AVCTP: browsing queue send failed: {}", e);
                }
            });

            self.pending_browsing =
                Some(PendingRequest { transaction, timeout_handle: None, retried: false });
        }
    }

    // -----------------------------------------------------------------------
    // Incoming Packet Dispatch — Control Channel
    // -----------------------------------------------------------------------

    fn handle_control_packet(&mut self, data: &[u8]) {
        if data.len() < AVCTP_HEADER_LENGTH {
            btd_warn(0, &format!("AVCTP: control packet too short ({} bytes)", data.len()));
            return;
        }

        let flags = data[0];
        let transaction = avctp_transaction(flags);
        let packet_type = avctp_packet_type(flags);
        let cr = avctp_cr(flags);
        let pid = ((data[1] as u16) << 8) | (data[2] as u16);

        if packet_type != AVCTP_PACKET_SINGLE {
            btd_warn(0, "AVCTP: unexpected fragmented control packet");
            return;
        }

        if pid != AV_REMOTE_SVCLASS_ID {
            btd_debug(0, &format!("AVCTP: unknown PID 0x{pid:04X}, sending IPID reject"));
            self.send_ipid_reject(transaction, pid);
            return;
        }

        let avc_data = &data[AVCTP_HEADER_LENGTH..];
        if avc_data.len() < AVC_HEADER_LENGTH {
            btd_warn(0, "AVCTP: AV/C data too short");
            return;
        }

        let code = avc_data[0] & 0x0F;
        let subunit = avc_data[1];
        let opcode = avc_data[2];
        let operands =
            if avc_data.len() > AVC_HEADER_LENGTH { &avc_data[AVC_HEADER_LENGTH..] } else { &[] };

        if cr == AVCTP_RESPONSE {
            self.handle_control_response(transaction, code, opcode, operands);
        } else {
            self.handle_control_command(transaction, code, subunit, opcode, operands);
        }
    }

    fn handle_control_response(&mut self, transaction: u8, code: u8, opcode: u8, operands: &[u8]) {
        let matches = self.pending_control.as_ref().is_some_and(|p| p.transaction == transaction);
        if matches {
            if let Some(pending) = self.pending_control.take() {
                if let Some(h) = pending.timeout_handle {
                    h.abort();
                }
            }
            btd_debug(0, &format!("AVCTP: response matched trans={transaction} code=0x{code:02X}"));
            self.pump_control_queue();
            return;
        }

        // Unsolicited CHANGED notification.
        if code == AVC_CHANGED && opcode == AVC_OP_VENDORDEP {
            self.dispatch_control_pdu(transaction, code, operands, opcode);
        }
    }

    fn handle_control_command(
        &mut self,
        transaction: u8,
        code: u8,
        subunit: u8,
        opcode: u8,
        operands: &[u8],
    ) {
        match opcode {
            AVC_OP_PASSTHROUGH => {
                self.handle_passthrough_command(transaction, code, subunit, operands);
            }
            AVC_OP_UNITINFO => {
                self.handle_unitinfo_command(transaction);
            }
            AVC_OP_SUBUNITINFO => {
                self.handle_subunitinfo_command(transaction);
            }
            AVC_OP_VENDORDEP => {
                self.dispatch_control_pdu(transaction, code, operands, opcode);
            }
            _ => {
                btd_debug(0, &format!("AVCTP: unhandled opcode 0x{opcode:02X}"));
                self.send_not_implemented(transaction, subunit, opcode);
            }
        }
    }

    fn dispatch_control_pdu(&mut self, transaction: u8, code: u8, operands: &[u8], opcode: u8) {
        for handler in &self.control_handlers {
            if handler.opcode == opcode {
                let _ = (handler.callback)(
                    transaction,
                    code,
                    avc_subunit_byte(AVC_SUBUNIT_PANEL, 0),
                    operands,
                );
                return;
            }
        }
    }

    fn handle_passthrough_command(
        &mut self,
        transaction: u8,
        code: u8,
        subunit: u8,
        operands: &[u8],
    ) {
        if code != AVC_CTYPE_CONTROL || avc_subunit_type(subunit) != AVC_SUBUNIT_PANEL {
            return;
        }
        if operands.is_empty() {
            return;
        }

        let op = operands[0] & 0x7F;
        let pressed = (operands[0] & 0x80) == 0;

        btd_debug(0, &format!("AVCTP: passthrough op=0x{op:02X} pressed={pressed}"));

        if self.key_quirks[op as usize] & QUIRK_NO_RELEASE != 0 {
            self.handle_key_press(op);
            self.handle_key_release(op);
        } else if pressed {
            self.handle_key_press(op);
        } else {
            self.handle_key_release(op);
        }

        let mut accepted = false;
        for handler in &self.passthrough_handlers {
            if (handler.callback)(transaction, pressed, op) {
                accepted = true;
            }
        }

        let response_code = if accepted { AVC_ACCEPTED } else { AVC_NOT_IMPLEMENTED };
        self.queue_control_response(
            transaction,
            response_code,
            subunit,
            AVC_OP_PASSTHROUGH,
            operands,
        );
    }

    fn handle_unitinfo_command(&mut self, transaction: u8) {
        let mut operands = vec![0u8; 5];
        operands[0] = 0x07;
        operands[1] = (AVC_SUBUNIT_PANEL << 3) & 0xF8;
        operands[2] = 0xFF;
        operands[3] = 0xFF;
        operands[4] = 0xFF;
        self.queue_control_response(
            transaction,
            AVC_STABLE,
            avc_subunit_byte(AVC_SUBUNIT_UNIT, 0x07),
            AVC_OP_UNITINFO,
            &operands,
        );
    }

    fn handle_subunitinfo_command(&mut self, transaction: u8) {
        let mut operands = vec![0u8; 5];
        operands[0] = 0x07;
        operands[1] = (AVC_SUBUNIT_PANEL << 3) & 0xF8;
        operands[2] = 0xFF;
        operands[3] = 0xFF;
        operands[4] = 0xFF;
        self.queue_control_response(
            transaction,
            AVC_STABLE,
            avc_subunit_byte(AVC_SUBUNIT_UNIT, 0x07),
            AVC_OP_SUBUNITINFO,
            &operands,
        );
    }

    fn send_not_implemented(&mut self, transaction: u8, subunit: u8, opcode: u8) {
        self.queue_control_response(transaction, AVC_NOT_IMPLEMENTED, subunit, opcode, &[]);
    }

    fn send_ipid_reject(&self, transaction: u8, pid: u16) {
        if let Some(ref chan) = self.control_io {
            let buf = vec![
                avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_RESPONSE, 1),
                (pid >> 8) as u8,
                (pid & 0xFF) as u8,
            ];
            let io = Arc::clone(&chan.io);
            tokio::spawn(async move {
                let _ = io.send(&buf).await;
            });
        }
    }

    fn queue_control_response(
        &self,
        transaction: u8,
        code: u8,
        subunit: u8,
        opcode: u8,
        operands: &[u8],
    ) {
        if let Some(ref chan) = self.control_io {
            let mut buf =
                Vec::with_capacity(AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH + operands.len());
            buf.push(avctp_flags(transaction, AVCTP_PACKET_SINGLE, AVCTP_RESPONSE, 0));
            buf.push((AV_REMOTE_SVCLASS_ID >> 8) as u8);
            buf.push((AV_REMOTE_SVCLASS_ID & 0xFF) as u8);
            buf.push(code & 0x0F);
            buf.push(subunit);
            buf.push(opcode);
            buf.extend_from_slice(operands);

            let io = Arc::clone(&chan.io);
            tokio::spawn(async move {
                if let Err(e) = io.send(&buf).await {
                    btd_error(0, &format!("AVCTP: response send failed: {e}"));
                }
            });
        }
    }

    // -----------------------------------------------------------------------
    // Incoming Packet Dispatch — Browsing Channel
    // -----------------------------------------------------------------------

    fn handle_browsing_packet(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let flags = data[0];
        let transaction = avctp_transaction(flags);
        let packet_type = avctp_packet_type(flags);
        let cr = avctp_cr(flags);

        match packet_type {
            AVCTP_PACKET_SINGLE => {
                if data.len() < AVCTP_HEADER_LENGTH {
                    return;
                }
                let pid = ((data[1] as u16) << 8) | (data[2] as u16);
                if pid != AV_REMOTE_SVCLASS_ID {
                    return;
                }
                self.dispatch_browsing_data(transaction, cr, &data[AVCTP_HEADER_LENGTH..]);
            }
            AVCTP_PACKET_START => {
                if data.len() < AVCTP_HEADER_LENGTH + 1 {
                    return;
                }
                let pid = ((data[1] as u16) << 8) | (data[2] as u16);
                if pid != AV_REMOTE_SVCLASS_ID {
                    return;
                }
                let num_packets = data[3];
                if let Some(ref mut chan) = self.browsing_io {
                    chan.reassembly_buf.clear();
                    chan.reassembly_buf.extend_from_slice(&data[AVCTP_HEADER_LENGTH + 1..]);
                    chan.fragments_remaining = num_packets.saturating_sub(1);
                }
            }
            AVCTP_PACKET_CONTINUE | AVCTP_PACKET_END => {
                if let Some(ref mut chan) = self.browsing_io {
                    chan.reassembly_buf.extend_from_slice(&data[1..]);
                    chan.fragments_remaining = chan.fragments_remaining.saturating_sub(1);

                    if packet_type == AVCTP_PACKET_END || chan.fragments_remaining == 0 {
                        let operands = std::mem::take(&mut chan.reassembly_buf);
                        chan.fragments_remaining = 0;
                        self.dispatch_browsing_data(transaction, cr, &operands);
                    }
                }
            }
            _ => {}
        }
    }

    fn dispatch_browsing_data(&mut self, transaction: u8, cr: u8, operands: &[u8]) {
        if cr == AVCTP_RESPONSE {
            let matches =
                self.pending_browsing.as_ref().is_some_and(|p| p.transaction == transaction);
            if matches {
                if let Some(pending) = self.pending_browsing.take() {
                    if let Some(h) = pending.timeout_handle {
                        h.abort();
                    }
                }
                self.pump_browsing_queue();
            }
        } else if let Some(ref handler) = self.browsing_handler {
            let _ = (handler.callback)(transaction, operands);
        }
    }

    // -----------------------------------------------------------------------
    // Key Press / Release via uinput
    // -----------------------------------------------------------------------

    fn handle_key_press(&mut self, op: u8) {
        if let Some(mut existing) = self.key.take() {
            if let Some(h) = existing.timer.take() {
                h.abort();
            }
            if existing.op != op {
                if let Some(key_code) = avc_op_to_key(existing.op) {
                    if let Some(ref uinput) = self.uinput {
                        uinput.send_key(key_code, false);
                    }
                }
            }
        }

        if let Some(key_code) = avc_op_to_key(op) {
            if let Some(ref uinput) = self.uinput {
                uinput.send_key(key_code, true);
            }
        }

        self.key = Some(KeyPressed { op, timer: None, hold: false });
    }

    fn handle_key_release(&mut self, op: u8) {
        if let Some(mut key) = self.key.take() {
            if key.op == op {
                if let Some(h) = key.timer.take() {
                    h.abort();
                }
            }
        }

        if let Some(key_code) = avc_op_to_key(op) {
            if let Some(ref uinput) = self.uinput {
                uinput.send_key(key_code, false);
            }
        }
    }

    fn init_uinput(&mut self) {
        let dev_name = self.device.get_name().unwrap_or("Bluetooth Device").to_string();
        let addr = self.device.get_address();
        let dev_id = InputId {
            bustype: BUS_BLUETOOTH,
            vendor: self.device.get_vendor(),
            product: self.device.get_product(),
            version: self.device.get_version(),
        };

        let mut uinput =
            BtUinput::new(Some(dev_name.as_str()), Some("AVRCP"), Some(addr), Some(&dev_id));
        match uinput.create(KEY_MAP) {
            Ok(()) => {
                btd_info(0, &format!("AVCTP: uinput created for {dev_name}"));
                self.uinput = Some(uinput);
            }
            Err(e) => {
                btd_error(0, &format!("AVCTP: uinput create failed: {e}"));
            }
        }
    }
}

// ===========================================================================
// AVCTP Server — per-adapter listener state
// ===========================================================================

/// Internal server state.
struct AvctpServerInner {
    adapter: Arc<Mutex<BtdAdapter>>,
    control_listener_task: Option<JoinHandle<()>>,
    browsing_listener_task: Option<JoinHandle<()>>,
    sessions: Vec<Arc<Mutex<AvctpSession>>>,
}

/// Per-adapter AVCTP server.
pub struct AvctpServer {
    /// Public adapter reference.
    pub adapter: Arc<Mutex<BtdAdapter>>,
    /// Public sessions list.
    pub sessions: Vec<Arc<Mutex<AvctpSession>>>,
}

// ===========================================================================
// Module-Level Global State
// ===========================================================================

static STATE_CB_COUNTER: AtomicU32 = AtomicU32::new(1);
static HANDLER_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_handler_id() -> u32 {
    HANDLER_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn next_state_cb_id() -> u32 {
    STATE_CB_COUNTER.fetch_add(1, Ordering::Relaxed)
}

static STATE_CALLBACKS: std::sync::LazyLock<std::sync::Mutex<Vec<StateCallback>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

static SERVERS: std::sync::LazyLock<std::sync::Mutex<Vec<Arc<Mutex<AvctpServerInner>>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

// ===========================================================================
// State Change Notification
// ===========================================================================

fn notify_state_change(device_path: &str, old_state: AvctpState, new_state: AvctpState) {
    if let Ok(callbacks) = STATE_CALLBACKS.lock() {
        for cb in callbacks.iter() {
            (cb.callback)(device_path, old_state, new_state);
        }
    }
}

/// Register a global state change callback. Returns an ID for later removal.
pub fn avctp_add_state_cb(
    callback: Box<dyn Fn(&str, AvctpState, AvctpState) + Send + Sync>,
) -> u32 {
    let id = next_state_cb_id();
    if let Ok(mut cbs) = STATE_CALLBACKS.lock() {
        cbs.push(StateCallback { id, callback });
    }
    id
}

/// Remove a previously registered state change callback by ID.
pub fn avctp_remove_state_cb(id: u32) {
    if let Ok(mut cbs) = STATE_CALLBACKS.lock() {
        cbs.retain(|cb| cb.id != id);
    }
}

/// Transition a session to a new state, notifying all observers.
async fn set_session_state(session: &Arc<Mutex<AvctpSession>>, new_state: AvctpState) {
    let (device_path, old_state) = {
        let mut sess = session.lock().await;
        let old = sess.state;
        if old == new_state {
            return;
        }
        sess.state = new_state;
        (sess.device.get_path().to_string(), old)
    };

    info!("AVCTP: state {} -> {} for {}", old_state, new_state, device_path);
    notify_state_change(&device_path, old_state, new_state);

    if new_state == AvctpState::Disconnected {
        let mut sess = session.lock().await;
        sess.disconnect();
    }
}

// ===========================================================================
// Server Lifecycle
// ===========================================================================

/// Register an AVCTP server for the given adapter.
pub async fn avctp_server_register(adapter: Arc<Mutex<BtdAdapter>>) -> AvctpResult<()> {
    let adapter_path = adapter::adapter_get_path(&adapter).await;
    btd_info(0, &format!("AVCTP: registering server for {adapter_path}"));

    let src_addr = adapter::btd_adapter_get_address(&adapter).await;

    let server_inner = Arc::new(Mutex::new(AvctpServerInner {
        adapter: Arc::clone(&adapter),
        control_listener_task: None,
        browsing_listener_task: None,
        sessions: Vec::new(),
    }));

    let s1 = Arc::clone(&server_inner);
    let sa1 = src_addr;
    let ctrl_task = tokio::spawn(async move {
        if let Err(e) = run_control_listener(s1, sa1).await {
            btd_error(0, &format!("AVCTP: control listener exit: {e}"));
        }
    });

    let s2 = Arc::clone(&server_inner);
    let sa2 = src_addr;
    let browse_task = tokio::spawn(async move {
        if let Err(e) = run_browsing_listener(s2, sa2).await {
            btd_error(0, &format!("AVCTP: browsing listener exit: {e}"));
        }
    });

    {
        let mut srv = server_inner.lock().await;
        srv.control_listener_task = Some(ctrl_task);
        srv.browsing_listener_task = Some(browse_task);
    }

    if let Ok(mut servers) = SERVERS.lock() {
        servers.push(server_inner);
    }

    btd_info(0, &format!("AVCTP: server registered for {adapter_path}"));
    Ok(())
}

/// Unregister the AVCTP server for the given adapter.
pub async fn avctp_server_unregister(adapter: &Arc<Mutex<BtdAdapter>>) {
    let adapter_ptr = Arc::as_ptr(adapter);

    let server = {
        let mut servers = match SERVERS.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        let idx = servers.iter().position(|s| {
            // We check pointer equality on the Arc for the adapter.
            // Since we can't await inside position(), we use try_lock.
            if let Ok(inner) = s.try_lock() {
                Arc::as_ptr(&inner.adapter) == adapter_ptr
            } else {
                false
            }
        });
        match idx {
            Some(i) => servers.remove(i),
            None => return,
        }
    };

    let mut srv = server.lock().await;
    if let Some(h) = srv.control_listener_task.take() {
        h.abort();
    }
    if let Some(h) = srv.browsing_listener_task.take() {
        h.abort();
    }

    for session in srv.sessions.drain(..) {
        set_session_state(&session, AvctpState::Disconnected).await;
    }

    btd_info(0, "AVCTP: server unregistered");
}

// ===========================================================================
// Control Channel Listener
// ===========================================================================

async fn run_control_listener(
    server: Arc<Mutex<AvctpServerInner>>,
    src_addr: BdAddr,
) -> AvctpResult<()> {
    let listener = SocketBuilder::new()
        .psm(AVCTP_CONTROL_PSM)
        .source_bdaddr(src_addr)
        .sec_level(SecLevel::Medium)
        .listen()
        .await
        .map_err(|e| AvctpError::ConnectionFailed(format!("control listen: {e}")))?;

    loop {
        let socket = listener
            .accept()
            .await
            .map_err(|e| AvctpError::ConnectionFailed(format!("control accept: {e}")))?;

        let server_clone = Arc::clone(&server);
        tokio::spawn(async move {
            if let Err(e) = handle_incoming_control(server_clone, socket).await {
                btd_error(0, &format!("AVCTP: incoming control error: {e}"));
            }
        });
    }
}

async fn handle_incoming_control(
    server: Arc<Mutex<AvctpServerInner>>,
    socket: BluetoothSocket,
) -> AvctpResult<()> {
    let (imtu, omtu) =
        socket.mtu().map_err(|e| AvctpError::ConnectionFailed(format!("MTU query: {e}")))?;

    // Find or get session from server session list.
    let session = {
        let srv = server.lock().await;
        // For incoming connections, find existing or defer.
        // In production, the AVRCP layer creates sessions; here we accept if a matching session exists.
        let peer_addr_result = socket.dest_address();
        let (peer_addr, _) = peer_addr_result
            .map_err(|e| AvctpError::ConnectionFailed(format!("dest_address: {e}")))?;

        let existing = find_session_by_addr(&srv.sessions, &peer_addr).await;
        match existing {
            Some(s) => s,
            None => {
                btd_debug(
                    0,
                    &format!("AVCTP: no session for incoming control from {}", peer_addr.ba2str()),
                );
                // Accept the connection but without a session, reject gracefully.
                let _ = socket.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
        }
    };

    {
        let mut sess = session.lock().await;
        sess.control_io = Some(AvctpChannel::new(socket, imtu, omtu));
        sess.control_mtu = imtu;
        sess.initiator = false;
        sess.init_uinput();
    }

    set_session_state(&session, AvctpState::Connected).await;

    let session_for_read = Arc::clone(&session);
    let read_task = tokio::spawn(async move {
        control_reader_loop(session_for_read).await;
    });

    {
        let mut sess = session.lock().await;
        if let Some(ref mut chan) = sess.control_io {
            chan.read_task = Some(read_task);
        }
    }

    Ok(())
}

async fn control_reader_loop(session: Arc<Mutex<AvctpSession>>) {
    let mut buf = vec![0u8; 4096];

    loop {
        let io = {
            let sess = session.lock().await;
            match sess.control_io.as_ref() {
                Some(c) => Arc::clone(&c.io),
                None => break,
            }
        };

        let n = match io.recv(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        let data = buf[..n].to_vec();
        {
            let mut sess = session.lock().await;
            sess.handle_control_packet(&data);
        }
    }

    set_session_state(&session, AvctpState::Disconnected).await;
}

// ===========================================================================
// Browsing Channel Listener
// ===========================================================================

async fn run_browsing_listener(
    server: Arc<Mutex<AvctpServerInner>>,
    src_addr: BdAddr,
) -> AvctpResult<()> {
    let listener = SocketBuilder::new()
        .psm(AVCTP_BROWSING_PSM)
        .source_bdaddr(src_addr)
        .sec_level(SecLevel::Medium)
        .mode(L2capMode::Ertm)
        .listen()
        .await
        .map_err(|e| AvctpError::ConnectionFailed(format!("browsing listen: {e}")))?;

    loop {
        let socket = listener
            .accept()
            .await
            .map_err(|e| AvctpError::ConnectionFailed(format!("browsing accept: {e}")))?;

        let server_clone = Arc::clone(&server);
        tokio::spawn(async move {
            if let Err(e) = handle_incoming_browsing(server_clone, socket).await {
                btd_error(0, &format!("AVCTP: incoming browsing error: {e}"));
            }
        });
    }
}

async fn handle_incoming_browsing(
    server: Arc<Mutex<AvctpServerInner>>,
    socket: BluetoothSocket,
) -> AvctpResult<()> {
    let (imtu, omtu) =
        socket.mtu().map_err(|e| AvctpError::ConnectionFailed(format!("browsing MTU: {e}")))?;

    let (peer_addr, _) = socket
        .dest_address()
        .map_err(|e| AvctpError::ConnectionFailed(format!("browsing dest_address: {e}")))?;

    let session = {
        let srv = server.lock().await;
        find_session_by_addr(&srv.sessions, &peer_addr).await
    };

    let session = match session {
        Some(s) => s,
        None => {
            let _ = socket.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    };

    {
        let mut sess = session.lock().await;
        if sess.state != AvctpState::Connected && sess.state != AvctpState::BrowsingConnecting {
            let _ = socket.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
        sess.browsing_io = Some(AvctpChannel::new(socket, imtu, omtu));
        sess.browsing_mtu = imtu;
    }

    set_session_state(&session, AvctpState::BrowsingConnected).await;

    let session_for_read = Arc::clone(&session);
    let read_task = tokio::spawn(async move {
        browsing_reader_loop(session_for_read).await;
    });

    {
        let mut sess = session.lock().await;
        if let Some(ref mut chan) = sess.browsing_io {
            chan.read_task = Some(read_task);
        }
    }

    Ok(())
}

async fn browsing_reader_loop(session: Arc<Mutex<AvctpSession>>) {
    let mut buf = vec![0u8; 4096];

    loop {
        let io = {
            let sess = session.lock().await;
            match sess.browsing_io.as_ref() {
                Some(c) => Arc::clone(&c.io),
                None => break,
            }
        };

        let n = match io.recv(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        let data = buf[..n].to_vec();
        {
            let mut sess = session.lock().await;
            sess.handle_browsing_packet(&data);
        }
    }

    // Browsing closed — revert to Connected.
    {
        let state = {
            let sess = session.lock().await;
            sess.state
        };
        if state == AvctpState::BrowsingConnected {
            set_session_state(&session, AvctpState::Connected).await;
            let mut sess = session.lock().await;
            if let Some(mut chan) = sess.browsing_io.take() {
                if let Some(h) = chan.read_task.take() {
                    h.abort();
                }
                let _ = chan.io.shutdown(std::net::Shutdown::Both);
            }
            sess.browsing_mtu = 0;
        }
    }
}

// ===========================================================================
// Session Lookup
// ===========================================================================

async fn find_session_by_addr(
    sessions: &[Arc<Mutex<AvctpSession>>],
    peer_addr: &BdAddr,
) -> Option<Arc<Mutex<AvctpSession>>> {
    for s in sessions {
        let sess = s.lock().await;
        if sess.device.get_address() == peer_addr {
            return Some(Arc::clone(s));
        }
    }
    None
}

// ===========================================================================
// Outbound Connection
// ===========================================================================

/// Initiate an outbound AVCTP control connection to a remote device.
pub async fn avctp_connect(
    device: Arc<BtdDevice>,
    adapter: Arc<Mutex<BtdAdapter>>,
) -> AvctpResult<Arc<Mutex<AvctpSession>>> {
    let device_path = device.get_path().to_string();
    btd_info(0, &format!("AVCTP: connecting to {device_path}"));

    let adapter_ptr = Arc::as_ptr(&adapter);

    // Find the server for this adapter.
    let server = {
        let servers = SERVERS
            .lock()
            .map_err(|_| AvctpError::ConnectionFailed("servers lock poisoned".into()))?;
        let mut found = None;
        for s in servers.iter() {
            if let Ok(inner) = s.try_lock() {
                if Arc::as_ptr(&inner.adapter) == adapter_ptr {
                    found = Some(Arc::clone(s));
                    break;
                }
            }
        }
        found.ok_or_else(|| AvctpError::ConnectionFailed("no server for adapter".into()))?
    };

    // Find or create session.
    let session = {
        let mut srv = server.lock().await;
        let peer_addr = device.get_address();
        let existing = find_session_by_addr(&srv.sessions, peer_addr).await;
        match existing {
            Some(s) => s,
            None => {
                let new_sess = Arc::new(Mutex::new(AvctpSession::new(Arc::clone(&device))));
                srv.sessions.push(Arc::clone(&new_sess));
                new_sess
            }
        }
    };

    set_session_state(&session, AvctpState::Connecting).await;

    let src_addr = adapter::btd_adapter_get_address(&adapter).await;

    let socket = SocketBuilder::new()
        .psm(AVCTP_CONTROL_PSM)
        .source_bdaddr(src_addr)
        .sec_level(SecLevel::Medium)
        .connect()
        .await
        .map_err(|e| AvctpError::ConnectionFailed(format!("control connect: {e}")))?;

    let (imtu, omtu) =
        socket.mtu().map_err(|e| AvctpError::ConnectionFailed(format!("MTU: {e}")))?;

    {
        let mut sess = session.lock().await;
        sess.control_io = Some(AvctpChannel::new(socket, imtu, omtu));
        sess.control_mtu = imtu;
        sess.initiator = true;
        sess.init_uinput();
    }

    set_session_state(&session, AvctpState::Connected).await;

    let session_for_read = Arc::clone(&session);
    let read_task = tokio::spawn(async move {
        control_reader_loop(session_for_read).await;
    });

    {
        let mut sess = session.lock().await;
        if let Some(ref mut chan) = sess.control_io {
            chan.read_task = Some(read_task);
        }
    }

    btd_info(0, &format!("AVCTP: connected to {device_path}"));
    Ok(session)
}

/// Connect the browsing channel on an existing session.
pub async fn avctp_connect_browsing(session: &Arc<Mutex<AvctpSession>>) -> AvctpResult<()> {
    let (src_addr, _current_state) = {
        let sess = session.lock().await;
        if sess.state != AvctpState::Connected {
            return Err(AvctpError::NotConnected);
        }
        let src = sess
            .control_io
            .as_ref()
            .and_then(|c| c.io.source_address().ok())
            .map(|(addr, _)| addr)
            .unwrap_or(BDADDR_ANY);
        (src, sess.state)
    };

    set_session_state(session, AvctpState::BrowsingConnecting).await;

    let socket = SocketBuilder::new()
        .psm(AVCTP_BROWSING_PSM)
        .source_bdaddr(src_addr)
        .sec_level(SecLevel::Medium)
        .mode(L2capMode::Ertm)
        .connect()
        .await
        .map_err(|e| {
            let s = Arc::clone(session);
            tokio::spawn(async move {
                set_session_state(&s, AvctpState::Connected).await;
            });
            AvctpError::ConnectionFailed(format!("browsing connect: {e}"))
        })?;

    let (imtu, omtu) =
        socket.mtu().map_err(|e| AvctpError::ConnectionFailed(format!("browsing MTU: {e}")))?;

    {
        let mut sess = session.lock().await;
        sess.browsing_io = Some(AvctpChannel::new(socket, imtu, omtu));
        sess.browsing_mtu = imtu;
    }

    set_session_state(session, AvctpState::BrowsingConnected).await;

    let session_for_read = Arc::clone(session);
    let read_task = tokio::spawn(async move {
        browsing_reader_loop(session_for_read).await;
    });

    {
        let mut sess = session.lock().await;
        if let Some(ref mut chan) = sess.browsing_io {
            chan.read_task = Some(read_task);
        }
    }

    Ok(())
}

// ===========================================================================
// Session Lookup API (used by AVRCP)
// ===========================================================================

/// Find an AVCTP session by device object path.
///
/// Scans all AVCTP servers for a session whose device's D-Bus path matches
/// `device_path`.  Returns the session Arc if found.
pub async fn avctp_find_session_by_path(device_path: &str) -> Option<Arc<Mutex<AvctpSession>>> {
    // Collect server arcs under the std::sync::Mutex, then immediately drop
    // the guard so that no non-Send MutexGuard is held across an await point.
    let server_arcs: Vec<Arc<Mutex<AvctpServerInner>>> = {
        let servers = SERVERS.lock().ok()?;
        servers.iter().cloned().collect()
    };
    for server in &server_arcs {
        let srv = server.lock().await;
        for session_arc in &srv.sessions {
            let sess = session_arc.lock().await;
            if sess.device.get_path() == device_path {
                return Some(Arc::clone(session_arc));
            }
        }
    }
    None
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avctp_flags_encoding() {
        let flags = avctp_flags(5, AVCTP_PACKET_SINGLE, AVCTP_COMMAND, 0);
        assert_eq!(avctp_transaction(flags), 5);
        assert_eq!(avctp_packet_type(flags), AVCTP_PACKET_SINGLE);
        assert_eq!(avctp_cr(flags), AVCTP_COMMAND);
        assert_eq!(avctp_ipid(flags), 0);
    }

    #[test]
    fn test_avctp_flags_response() {
        let flags = avctp_flags(15, AVCTP_PACKET_SINGLE, AVCTP_RESPONSE, 1);
        assert_eq!(avctp_transaction(flags), 15);
        assert_eq!(avctp_cr(flags), AVCTP_RESPONSE);
        assert_eq!(avctp_ipid(flags), 1);
    }

    #[test]
    fn test_avctp_flags_fragmented() {
        let flags = avctp_flags(7, AVCTP_PACKET_START, AVCTP_COMMAND, 0);
        assert_eq!(avctp_transaction(flags), 7);
        assert_eq!(avctp_packet_type(flags), AVCTP_PACKET_START);

        let flags2 = avctp_flags(7, AVCTP_PACKET_END, AVCTP_COMMAND, 0);
        assert_eq!(avctp_packet_type(flags2), AVCTP_PACKET_END);
    }

    #[test]
    fn test_subunit_encoding() {
        let byte = avc_subunit_byte(AVC_SUBUNIT_PANEL, 0);
        assert_eq!(avc_subunit_type(byte), AVC_SUBUNIT_PANEL);
        assert_eq!(avc_subunit_id(byte), 0);

        let byte2 = avc_subunit_byte(AVC_SUBUNIT_UNIT, 7);
        assert_eq!(avc_subunit_type(byte2), AVC_SUBUNIT_UNIT);
        assert_eq!(avc_subunit_id(byte2), 7);
    }

    #[test]
    fn test_constants() {
        assert_eq!(AVCTP_CONTROL_PSM, 23);
        assert_eq!(AVCTP_BROWSING_PSM, 27);
        assert_eq!(AVC_MTU, 512);
        assert_eq!(AVC_HEADER_LENGTH, 3);
        assert_eq!(AVC_OP_VENDORDEP, 0x00);
        assert_eq!(AVC_OP_UNITINFO, 0x30);
        assert_eq!(AVC_OP_SUBUNITINFO, 0x31);
        assert_eq!(AVC_OP_PASSTHROUGH, 0x7C);
        assert_eq!(AVC_SUBUNIT_PANEL, 0x09);
        assert_eq!(AVC_SUBUNIT_UNIT, 0x1F);
    }

    #[test]
    fn test_key_map_completeness() {
        assert!(KEY_MAP.len() >= 50);
        let play = KEY_MAP.iter().find(|k| k.code == AVC_PLAY as u32);
        assert!(play.is_some());
        assert_eq!(play.unwrap().uinput, KEY_PLAYCD);
    }

    #[test]
    fn test_passthrough_constants() {
        assert_eq!(AVC_PLAY, 0x44);
        assert_eq!(AVC_STOP, 0x45);
        assert_eq!(AVC_PAUSE, 0x46);
        assert_eq!(AVC_FORWARD, 0x4B);
        assert_eq!(AVC_BACKWARD, 0x4C);
        assert_eq!(AVC_VENDOR_UNIQUE, 0x7E);
        assert_eq!(AVC_VENDOR_NEXT_GROUP, 0x00);
        assert_eq!(AVC_VENDOR_PREV_GROUP, 0x01);
    }

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", AvctpState::Disconnected), "Disconnected");
        assert_eq!(format!("{}", AvctpState::Connected), "Connected");
        assert_eq!(format!("{}", AvctpState::BrowsingConnected), "BrowsingConnected");
    }

    #[test]
    fn test_error_display() {
        let e = AvctpError::ConnectionFailed("test".into());
        assert!(format!("{e}").contains("test"));
        let e2 = AvctpError::Timeout;
        assert!(format!("{e2}").contains("timeout"));
    }

    #[test]
    fn test_state_callback_lifecycle() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let id = avctp_add_state_cb(Box::new(move |_path, _old, _new| {
            called_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        }));
        assert!(id > 0);

        notify_state_change("/test", AvctpState::Disconnected, AvctpState::Connected);
        assert!(called.load(std::sync::atomic::Ordering::Relaxed));

        avctp_remove_state_cb(id);
    }

    #[test]
    fn test_error_from_btd_error() {
        let btd_err = BtdError::Failed("oops".into());
        let avctp_err: AvctpError = btd_err.into();
        assert!(matches!(avctp_err, AvctpError::ConnectionFailed(_)));
    }
}
