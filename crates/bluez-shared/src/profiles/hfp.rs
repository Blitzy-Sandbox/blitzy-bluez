// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012-2014 Intel Corporation. All rights reserved.

//! HFP (Hands-Free Profile) AT command engine.
//!
//! Idiomatic Rust rewrite of `src/shared/hfp.c` and `src/shared/hfp.h`.
//! Implements both the Audio Gateway (AG) side ([`HfpGw`]) and the
//! Hands-Free (HF) side ([`HfpHf`]) of the HFP protocol, including AT
//! command parsing/generation, SLC (Service Level Connection) establishment,
//! indicator negotiation, and call management.

use std::collections::VecDeque;
use std::os::fd::RawFd;

use crate::util::ringbuf::RingBuf;
use tracing::debug;

// ---------------------------------------------------------------------------
// Bitflag types
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// HF (Hands-Free) feature flags — 12 flags per HFP 1.8 specification.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HfFeatures: u32 {
        const ECNR                              = 0x0000_0001;
        const THREE_WAY                         = 0x0000_0002;
        const CLIP                              = 0x0000_0004;
        const VOICE_RECOGNITION                 = 0x0000_0008;
        const REMOTE_VOLUME_CONTROL             = 0x0000_0010;
        const ENHANCED_CALL_STATUS              = 0x0000_0020;
        const ENHANCED_CALL_CONTROL             = 0x0000_0040;
        const CODEC_NEGOTIATION                 = 0x0000_0080;
        const HF_INDICATORS                     = 0x0000_0100;
        const ESCO_S4_T2                        = 0x0000_0200;
        const ENHANCED_VOICE_RECOGNITION_STATUS = 0x0000_0400;
        const VOICE_RECOGNITION_TEXT            = 0x0000_0800;
    }
}

bitflags::bitflags! {
    /// AG (Audio Gateway) feature flags — 14 flags per HFP 1.8 specification.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AgFeatures: u32 {
        const THREE_WAY                         = 0x0000_0001;
        const ECNR                              = 0x0000_0002;
        const VOICE_RECOGNITION                 = 0x0000_0004;
        const IN_BAND_RING_TONE                 = 0x0000_0008;
        const ATTACH_VOICE_TAG                  = 0x0000_0010;
        const REJECT_CALL                       = 0x0000_0020;
        const ENHANCED_CALL_STATUS              = 0x0000_0040;
        const ENHANCED_CALL_CONTROL             = 0x0000_0080;
        const EXTENDED_RES_CODE                 = 0x0000_0100;
        const CODEC_NEGOTIATION                 = 0x0000_0200;
        const HF_INDICATORS                     = 0x0000_0400;
        const ESCO_S4_T2                        = 0x0000_0800;
        const ENHANCED_VOICE_RECOGNITION_STATUS = 0x0000_1000;
        const VOICE_RECOGNITION_TEXT            = 0x0000_2000;
    }
}

bitflags::bitflags! {
    /// CHLD (call hold) operation flags — 7 flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChldFlags: u8 {
        const CHLD_0  = 1 << 0;
        const CHLD_1  = 1 << 1;
        const CHLD_2  = 1 << 2;
        const CHLD_3  = 1 << 3;
        const CHLD_4  = 1 << 4;
        const CHLD_1X = 1 << 5;
        const CHLD_2X = 1 << 6;
    }
}

/// Default HF feature set used during SLC initialisation (matches C lines 33-39).
const HFP_HF_FEATURES: HfFeatures = HfFeatures::ECNR
    .union(HfFeatures::THREE_WAY)
    .union(HfFeatures::CLIP)
    .union(HfFeatures::ENHANCED_CALL_STATUS)
    .union(HfFeatures::ESCO_S4_T2);

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// AT result codes returned by the AG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HfpResult {
    Ok = 0,
    Connect = 1,
    Ring = 2,
    NoCarrier = 3,
    Error = 4,
    // 5 is intentionally skipped (gap in HFP spec)
    NoDialtone = 6,
    Busy = 7,
    NoAnswer = 8,
    Delayed = 9,
    Rejected = 10,
    CmeError = 11,
}

/// CME error codes as defined by HFP specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HfpError {
    AgFailure = 0,
    NoConnectionToPhone = 1,
    OperationNotAllowed = 3,
    OperationNotSupported = 4,
    PhSimPinRequired = 5,
    SimNotInserted = 10,
    SimPinRequired = 11,
    SimPukRequired = 12,
    SimFailure = 13,
    SimBusy = 14,
    IncorrectPassword = 16,
    SimPin2Required = 17,
    SimPuk2Required = 18,
    MemoryFull = 20,
    InvalidIndex = 21,
    MemoryFailure = 23,
    TextStringTooLong = 24,
    InvalidCharsInTextString = 25,
    DialStringTooLong = 26,
    InvalidCharsInDialString = 27,
    NoNetworkService = 30,
    NetworkTimeout = 31,
    NetworkNotAllowed = 32,
}

impl HfpError {
    /// Convert a raw `u32` wire value to the matching variant, defaulting
    /// to `AgFailure` for unknown codes (matching C behaviour).
    fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::AgFailure,
            1 => Self::NoConnectionToPhone,
            3 => Self::OperationNotAllowed,
            4 => Self::OperationNotSupported,
            5 => Self::PhSimPinRequired,
            10 => Self::SimNotInserted,
            11 => Self::SimPinRequired,
            12 => Self::SimPukRequired,
            13 => Self::SimFailure,
            14 => Self::SimBusy,
            16 => Self::IncorrectPassword,
            17 => Self::SimPin2Required,
            18 => Self::SimPuk2Required,
            20 => Self::MemoryFull,
            21 => Self::InvalidIndex,
            23 => Self::MemoryFailure,
            24 => Self::TextStringTooLong,
            25 => Self::InvalidCharsInTextString,
            26 => Self::DialStringTooLong,
            27 => Self::InvalidCharsInDialString,
            30 => Self::NoNetworkService,
            31 => Self::NetworkTimeout,
            32 => Self::NetworkNotAllowed,
            _ => Self::AgFailure,
        }
    }
}

/// AT command type as determined by the gateway parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpGwCmdType {
    Read,
    Set,
    Test,
    Command,
}

/// CIND indicator identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HfpIndicator {
    Service = 0,
    Call = 1,
    Callsetup = 2,
    Callheld = 3,
    Signal = 4,
    Roam = 5,
    Battchg = 6,
}

/// Number of CIND indicator slots (sentinel value replacing C `HFP_INDICATOR_LAST`).
pub const INDICATOR_COUNT: usize = 7;

/// CIND call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HfpCall {
    CindCallNone = 0,
    CindCallInProgress = 1,
}

/// CIND call-setup state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HfpCallSetup {
    None = 0,
    Incoming = 1,
    Dialing = 2,
    Alerting = 3,
}

/// CIND call-held state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HfpCallHeld {
    None = 0,
    HoldAndActive = 1,
    Hold = 2,
}

/// CLCC call status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HfpCallStatus {
    Active = 0,
    Held = 1,
    Dialing = 2,
    Alerting = 3,
    Incoming = 4,
    Waiting = 5,
    ResponseAndHold = 6,
}

impl HfpCallStatus {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Held),
            2 => Some(Self::Dialing),
            3 => Some(Self::Alerting),
            4 => Some(Self::Incoming),
            5 => Some(Self::Waiting),
            6 => Some(Self::ResponseAndHold),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Callback type aliases
// ---------------------------------------------------------------------------

/// GW-side AT command handler invoked when a registered prefix is matched.
type GwCmdHandler = Box<dyn Fn(&mut HfpContext, HfpGwCmdType) + Send>;

/// GW-side fallback handler invoked for unrecognised AT commands.
type GwCommandCallback = Box<dyn Fn(&str) + Send>;

/// HF-side response callback invoked when the AG replies to a command.
type HfResponseCallback = Box<dyn FnOnce(HfpResult, HfpError) + Send>;

/// HF-side unsolicited event handler invoked for matching prefixes.
type HfEventHandler = Box<dyn Fn(&mut HfpContext) + Send>;

/// Debug tracing callback.
type DebugCallback = Box<dyn Fn(&str) + Send>;

/// Disconnect notification callback.
type DisconnectCallback = Box<dyn FnOnce() + Send>;

// ---------------------------------------------------------------------------
// HfpContext — AT command / response parser
// ---------------------------------------------------------------------------

/// Parser context for AT command parameters / response data.
///
/// Mirrors the C `struct hfp_context` from `hfp.c` line 71-74.
pub struct HfpContext {
    data: Vec<u8>,
    offset: usize,
}

impl HfpContext {
    /// Create a new context wrapping the given data slice.
    pub fn new(data: &[u8]) -> Self {
        Self { data: data.to_vec(), offset: 0 }
    }

    /// Skip ASCII whitespace at the current offset.
    fn skip_whitespace(&mut self) {
        while self.offset < self.data.len() && self.data[self.offset] == b' ' {
            self.offset += 1;
        }
    }

    /// Parse a decimal integer at the current position.
    ///
    /// Advances past the number and any trailing whitespace and comma.
    /// Returns `None` if no digits are found at the current position.
    pub fn get_number(&mut self) -> Option<u32> {
        self.skip_whitespace();

        let start = self.offset;
        let mut val: u32 = 0;
        let mut found_digit = false;

        while self.offset < self.data.len() {
            let ch = self.data[self.offset];
            if ch.is_ascii_digit() {
                val = val.saturating_mul(10).saturating_add(u32::from(ch - b'0'));
                self.offset += 1;
                found_digit = true;
            } else {
                break;
            }
        }

        if !found_digit {
            self.offset = start;
            return None;
        }

        self.skip_whitespace();
        if self.offset < self.data.len() && self.data[self.offset] == b',' {
            self.offset += 1;
        }

        Some(val)
    }

    /// Parse a decimal integer, returning `default` when the current position
    /// points at a comma (empty field).
    pub fn get_number_default(&mut self, default: u32) -> Option<u32> {
        self.skip_whitespace();

        if self.offset < self.data.len() && self.data[self.offset] == b',' {
            self.offset += 1;
            return Some(default);
        }

        self.get_number()
    }

    /// Expect and consume an opening parenthesis.
    pub fn open_container(&mut self) -> bool {
        self.skip_whitespace();
        if self.offset < self.data.len() && self.data[self.offset] == b'(' {
            self.offset += 1;
            return true;
        }
        false
    }

    /// Expect and consume a closing parenthesis plus optional trailing comma.
    pub fn close_container(&mut self) -> bool {
        self.skip_whitespace();
        if self.offset < self.data.len() && self.data[self.offset] == b')' {
            self.offset += 1;
            self.skip_whitespace();
            if self.offset < self.data.len() && self.data[self.offset] == b',' {
                self.offset += 1;
            }
            return true;
        }
        false
    }

    /// Check whether the current byte is a closing parenthesis without consuming.
    pub fn is_container_close(&self) -> bool {
        self.offset < self.data.len() && self.data[self.offset] == b')'
    }

    /// Parse a quoted string.
    ///
    /// Expects a `"` opening quote, reads up to `max_len` characters until
    /// the closing `"`, and advances past optional whitespace and comma.
    pub fn get_string(&mut self, max_len: usize) -> Option<String> {
        self.skip_whitespace();

        if self.offset >= self.data.len() || self.data[self.offset] != b'"' {
            return None;
        }
        self.offset += 1;

        let start = self.offset;
        let mut count = 0usize;
        while self.offset < self.data.len() && self.data[self.offset] != b'"' && count < max_len {
            self.offset += 1;
            count += 1;
        }

        if self.offset >= self.data.len() || self.data[self.offset] != b'"' {
            return None;
        }

        let s = String::from_utf8_lossy(&self.data[start..self.offset]).into_owned();
        self.offset += 1;

        self.skip_whitespace();
        if self.offset < self.data.len() && self.data[self.offset] == b',' {
            self.offset += 1;
        }

        Some(s)
    }

    /// Parse an unquoted string (no quotes, no parentheses).
    ///
    /// Reads up to `max_len` characters until a NUL, comma, or close-paren.
    pub fn get_unquoted_string(&mut self, max_len: usize) -> Option<String> {
        self.skip_whitespace();

        if self.offset < self.data.len() {
            let ch = self.data[self.offset];
            if ch == b'"' || ch == b')' || ch == b'(' {
                return None;
            }
        } else {
            return None;
        }

        let start = self.offset;
        let mut count = 0usize;
        while self.offset < self.data.len() && count < max_len {
            let ch = self.data[self.offset];
            if ch == b'\0' || ch == b',' || ch == b')' {
                break;
            }
            self.offset += 1;
            count += 1;
        }

        let s = String::from_utf8_lossy(&self.data[start..self.offset]).into_owned();

        if self.offset < self.data.len() && self.data[self.offset] == b',' {
            self.offset += 1;
        }

        Some(s)
    }

    /// Check whether there is more data to parse.
    pub fn has_next(&self) -> bool {
        self.offset < self.data.len() && self.data[self.offset] != b'\0'
    }

    /// Skip the current field (advance to past the next comma or end of data).
    pub fn skip_field(&mut self) {
        while self.offset < self.data.len() {
            let ch = self.data[self.offset];
            if ch == b'\0' || ch == b',' {
                break;
            }
            self.offset += 1;
        }
        if self.offset < self.data.len() && self.data[self.offset] == b',' {
            self.offset += 1;
        }
    }

    /// Parse a range in the form `N-M`.
    ///
    /// On failure the offset is restored and `None` is returned.
    pub fn get_range(&mut self) -> Option<(u32, u32)> {
        let saved = self.offset;

        let min = match self.get_number() {
            Some(v) => v,
            None => {
                self.offset = saved;
                return None;
            }
        };

        if self.offset >= self.data.len() || self.data[self.offset] != b'-' {
            self.offset = saved;
            return None;
        }
        self.offset += 1;

        let max = match self.get_number() {
            Some(v) => v,
            None => {
                self.offset = saved;
                return None;
            }
        };

        Some((min, max))
    }
}

// ---------------------------------------------------------------------------
// Internal supporting types
// ---------------------------------------------------------------------------

/// Registered AT command handler on the GW side.
struct CmdHandler {
    prefix: String,
    callback: GwCmdHandler,
}

/// Pending command response on the HF side.
struct CmdResponse {
    resp_cb: Option<HfResponseCallback>,
}

/// Registered unsolicited event handler on the HF side.
struct EventHandler {
    prefix: String,
    callback: HfEventHandler,
}

/// CIND indicator state used by the HF side.
#[derive(Clone, Default)]
struct Indicator {
    index: u8,
    min: u32,
    max: u32,
    val: u32,
    active: bool,
}

/// A tracked call on the HF side.
pub struct HfCall {
    pub id: u32,
    pub status: HfpCallStatus,
    pub line_id: Option<String>,
    pub call_type: u32,
    pub mpty: bool,
}

/// Type alias for the call-line-id-updated callback to satisfy complexity limits.
type CallLineIdUpdatedCb = Box<dyn Fn(u32, &str, u32) + Send>;

/// HF-side session callbacks (9 callback slots).
#[derive(Default)]
pub struct HfpHfCallbacks {
    pub session_ready: Option<Box<dyn Fn(HfpResult, HfpError) + Send>>,
    pub update_indicator: Option<Box<dyn Fn(HfpIndicator, u32) + Send>>,
    pub update_operator: Option<Box<dyn Fn(&str) + Send>>,
    pub update_inband_ring: Option<Box<dyn Fn(bool) + Send>>,
    pub call_added: Option<Box<dyn Fn(u32, HfpCallStatus) + Send>>,
    pub call_removed: Option<Box<dyn Fn(u32) + Send>>,
    pub call_status_updated: Option<Box<dyn Fn(u32, HfpCallStatus) + Send>>,
    pub call_line_id_updated: Option<CallLineIdUpdatedCb>,
    pub call_mpty_updated: Option<Box<dyn Fn(u32, bool) + Send>>,
}

/// Standard ring buffer capacity for HFP AT command I/O (4096 bytes).
const HFP_BUF_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// SLC (Service Level Connection) state machine
// ---------------------------------------------------------------------------

/// States in the SLC establishment chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlcState {
    /// No SLC in progress.
    Idle,
    /// Sent AT+BRSF, waiting for +BRSF unsolicited + OK.
    WaitBrsf,
    /// Sent AT+CIND=?, waiting for +CIND unsolicited + OK.
    WaitCind,
    /// Sent AT+CIND?, waiting for +CIND status unsolicited + OK.
    WaitCindStatus,
    /// Sent AT+CMER, waiting for OK.
    WaitCmer,
    /// Sent AT+CHLD=?, waiting for +CHLD unsolicited + OK.
    WaitChld,
    /// Sent AT+COPS=3,0, waiting for OK.
    WaitCopsConf,
    /// Sent AT+COPS?, waiting for +COPS unsolicited + OK.
    WaitCops,
    /// Sent AT+CLIP=1, waiting for OK.
    WaitClip,
    /// Sent AT+CCWA=1, waiting for OK.
    WaitCcwa,
    /// Sent AT+CMEE=1, waiting for OK.
    WaitCmee,
    /// Sent AT+NREC=0, waiting for OK.
    WaitNrec,
}

// ---------------------------------------------------------------------------
// HfpGw — Audio Gateway side
// ---------------------------------------------------------------------------

/// Audio Gateway (AG) side of the HFP AT command engine.
///
/// Manages RFCOMM I/O buffering, parses incoming AT commands from the HF,
/// dispatches them to registered prefix handlers, and sends result/info/error
/// responses back.
pub struct HfpGw {
    fd: RawFd,
    close_on_unref: bool,
    read_buf: RingBuf,
    write_buf: RingBuf,
    cmd_handlers: Vec<CmdHandler>,
    writer_active: bool,
    result_pending: bool,
    command_callback: Option<GwCommandCallback>,
    debug_callback: Option<DebugCallback>,
    disconnect_callback: Option<DisconnectCallback>,
    in_disconnect: bool,
}

impl HfpGw {
    /// Create a new `HfpGw` wrapping the given RFCOMM file descriptor.
    ///
    /// Returns `None` if the ring buffers cannot be allocated.
    pub fn new(fd: RawFd) -> Option<Self> {
        let read_buf = RingBuf::new(HFP_BUF_SIZE)?;
        let write_buf = RingBuf::new(HFP_BUF_SIZE)?;

        Some(Self {
            fd,
            close_on_unref: false,
            read_buf,
            write_buf,
            cmd_handlers: Vec::new(),
            writer_active: false,
            result_pending: false,
            command_callback: None,
            debug_callback: None,
            disconnect_callback: None,
            in_disconnect: false,
        })
    }

    /// Return the underlying file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Replace the debug callback.
    pub fn set_debug(&mut self, cb: Option<DebugCallback>) {
        self.debug_callback = cb;
    }

    /// When set, marks that the fd should be closed by the owner when done.
    pub fn set_close_on_unref(&mut self, close: bool) {
        self.close_on_unref = close;
    }

    /// Return the close-on-unref flag.
    pub fn close_on_unref(&self) -> bool {
        self.close_on_unref
    }

    /// Install the disconnect handler invoked when the remote peer closes.
    pub fn set_disconnect_handler(&mut self, cb: Option<DisconnectCallback>) {
        self.disconnect_callback = cb;
    }

    /// Trigger a disconnect, invoking the registered disconnect handler.
    pub fn disconnect(&mut self) {
        if self.in_disconnect {
            return;
        }
        self.in_disconnect = true;
        if let Some(cb) = self.disconnect_callback.take() {
            cb();
        }
        self.in_disconnect = false;
    }

    /// Set the fallback handler for AT commands that have no registered prefix.
    pub fn set_command_handler(&mut self, cb: Option<GwCommandCallback>) {
        self.command_callback = cb;
    }

    /// Register an AT command handler for the given prefix.
    ///
    /// Returns `false` if a handler with the same prefix already exists.
    pub fn register(&mut self, prefix: &str, callback: GwCmdHandler) -> bool {
        if self.cmd_handlers.iter().any(|h| h.prefix == prefix) {
            return false;
        }
        self.cmd_handlers.push(CmdHandler { prefix: prefix.to_owned(), callback });
        true
    }

    /// Unregister the AT command handler for the given prefix.
    ///
    /// Returns `false` if no handler was found.
    pub fn unregister(&mut self, prefix: &str) -> bool {
        let before = self.cmd_handlers.len();
        self.cmd_handlers.retain(|h| h.prefix != prefix);
        self.cmd_handlers.len() < before
    }

    /// Send a final result code (only `Ok` and `Error` are accepted).
    ///
    /// Returns `false` for any other result variant.
    pub fn send_result(&mut self, result: HfpResult) -> bool {
        let text = match result {
            HfpResult::Ok => "\r\nOK\r\n",
            HfpResult::Error => "\r\nERROR\r\n",
            _ => return false,
        };

        if self.write_buf.printf(format_args!("{text}")).is_err() {
            return false;
        }

        self.result_pending = false;
        self.writer_active = true;
        self.process_input();

        true
    }

    /// Send a `+CME ERROR` response with the given error code.
    pub fn send_error(&mut self, error: HfpError) -> bool {
        let code = error as u32;
        if self.write_buf.printf(format_args!("\r\n+CME ERROR: {code}\r\n")).is_err() {
            return false;
        }

        self.result_pending = false;
        self.writer_active = true;
        self.process_input();

        true
    }

    /// Send an informational (intermediate) response line.
    ///
    /// If a result is pending the writer is NOT woken — the final result
    /// write will do that.
    pub fn send_info(&mut self, info: &str) -> bool {
        if self.write_buf.printf(format_args!("\r\n{info}\r\n")).is_err() {
            return false;
        }

        if !self.result_pending {
            self.writer_active = true;
        }

        true
    }

    /// Return a reference to the write buffer for the caller to flush.
    pub fn write_buf(&self) -> &RingBuf {
        &self.write_buf
    }

    /// Return a mutable reference to the write buffer.
    pub fn write_buf_mut(&mut self) -> &mut RingBuf {
        &mut self.write_buf
    }

    /// Return a mutable reference to the read buffer for the caller to fill.
    pub fn read_buf_mut(&mut self) -> &mut RingBuf {
        &mut self.read_buf
    }

    // -- AT command parsing -------------------------------------------------

    /// Handle a single AT command line extracted from the read buffer.
    ///
    /// Faithfully reproduces the C `handle_at_command()` (lines 245-322).
    fn handle_at_command(&mut self, data: &[u8]) {
        let len = data.len();
        if len == 0 {
            return;
        }

        // Skip leading whitespace
        let mut pos = 0usize;
        while pos < len && data[pos] == b' ' {
            pos += 1;
        }

        let remaining = len - pos;
        if remaining < 2 {
            return;
        }

        // Must start with "AT" (case insensitive)
        let a = data[pos].to_ascii_uppercase();
        let t = data[pos + 1].to_ascii_uppercase();
        if a != b'A' || t != b'T' {
            return;
        }
        pos += 2;

        if pos >= len {
            // bare "AT" — treat as command with empty prefix
            self.dispatch_command("", data, HfpGwCmdType::Command, pos);
            return;
        }

        // Determine prefix
        let first_after_at = data[pos];

        let prefix: String;
        if first_after_at.is_ascii_alphabetic() {
            // Single alpha prefix (e.g. ATD, ATA)
            prefix = String::from(char::from(first_after_at).to_ascii_uppercase());
            pos += 1;
        } else {
            // Extended command: read until separator
            let start = pos;
            while pos < len {
                let ch = data[pos];
                if ch == b';' || ch == b'?' || ch == b'=' || ch == b'\0' {
                    break;
                }
                pos += 1;
            }
            let pref_len = pos - start;
            if !(2..=17).contains(&pref_len) {
                return;
            }
            prefix = data[start..pos].iter().map(|&b| char::from(b).to_ascii_uppercase()).collect();
        }

        // Determine command type
        let cmd_type;
        if prefix.starts_with('D') {
            cmd_type = HfpGwCmdType::Set;
        } else if pos < len && data[pos] == b'=' {
            pos += 1;
            if pos < len && data[pos] == b'?' {
                pos += 1;
                cmd_type = HfpGwCmdType::Test;
            } else {
                cmd_type = HfpGwCmdType::Set;
            }
        } else if pos < len && data[pos] == b'?' {
            pos += 1;
            cmd_type = HfpGwCmdType::Read;
        } else {
            cmd_type = HfpGwCmdType::Command;
        }

        self.dispatch_command(&prefix, data, cmd_type, pos);
    }

    /// Dispatch a parsed AT command to the matching handler or fallback.
    fn dispatch_command(
        &mut self,
        prefix: &str,
        full_data: &[u8],
        cmd_type: HfpGwCmdType,
        data_offset: usize,
    ) {
        let handler_idx = self.cmd_handlers.iter().position(|h| h.prefix == prefix);

        if let Some(idx) = handler_idx {
            self.result_pending = true;
            let param_data =
                if data_offset < full_data.len() { &full_data[data_offset..] } else { &[] };
            let mut ctx = HfpContext::new(param_data);
            (self.cmd_handlers[idx].callback)(&mut ctx, cmd_type);
        } else if let Some(ref cb) = self.command_callback {
            let cmd_str = String::from_utf8_lossy(full_data);
            cb(&cmd_str);
        } else {
            self.result_pending = true;
            let _ = self.send_result(HfpResult::Error);
        }
    }

    /// Process buffered input from the read ring buffer.
    ///
    /// Searches for `\r`-terminated AT command lines and dispatches them.
    fn process_input(&mut self) {
        loop {
            if self.result_pending {
                return;
            }

            if self.read_buf.is_empty() {
                return;
            }

            let (first, second) = self.read_buf.peek(0);
            let data: Vec<u8> = match second {
                Some(s) => {
                    let mut v = Vec::with_capacity(first.len() + s.len());
                    v.extend_from_slice(first);
                    v.extend_from_slice(s);
                    v
                }
                None => first.to_vec(),
            };

            // Search for \r (command terminator on GW receiving side)
            let cr_pos = match data.iter().position(|&b| b == b'\r') {
                Some(p) => p,
                None => return,
            };

            let line = data[..cr_pos].to_vec();

            let mut total_drain = cr_pos + 1;
            // Also skip a trailing \n if present
            if total_drain < data.len() && data[total_drain] == b'\n' {
                total_drain += 1;
            }

            // Drain the consumed bytes BEFORE dispatching the command.
            // `send_result()` / `send_error()` re-enter `process_input()`
            // to flush follow-on commands; the data must already be consumed
            // so the recursive call does not re-process the same line.
            self.read_buf.drain(total_drain);

            if !line.is_empty() {
                debug!("GW: received AT command ({} bytes)", line.len());
                self.handle_at_command(&line);
            }
        }
    }

    /// Feed data into the read buffer and trigger processing.
    ///
    /// This is the primary data-ingestion method. In an async context the
    /// caller reads from the RFCOMM socket into a temporary buffer and then
    /// calls this method.
    pub fn receive_data(&mut self, data: &[u8]) {
        let _ = self.read_buf.write_bytes(data);
        self.process_input();
    }

    /// Return the number of bytes available for reading from the write buffer.
    pub fn pending_write(&self) -> usize {
        self.write_buf.len()
    }

    /// Drain up to `count` bytes from the write buffer (after the caller has
    /// written them to the socket).
    pub fn drain_written(&mut self, count: usize) {
        self.write_buf.drain(count);
        if self.write_buf.is_empty() {
            self.writer_active = false;
        }
    }
}

// ---------------------------------------------------------------------------
// HfpHf — Hands-Free side
// ---------------------------------------------------------------------------

/// Hands-Free (HF) side of the HFP AT command engine.
///
/// Sends AT commands to the AG, processes responses and unsolicited events,
/// manages SLC (Service Level Connection) establishment, and tracks call
/// state.
pub struct HfpHf {
    fd: RawFd,
    close_on_unref: bool,
    read_buf: RingBuf,
    write_buf: RingBuf,
    writer_active: bool,
    cmd_queue: VecDeque<CmdResponse>,
    event_handlers: Vec<EventHandler>,
    debug_callback: Option<DebugCallback>,
    disconnect_callback: Option<DisconnectCallback>,
    in_disconnect: bool,
    callbacks: Option<HfpHfCallbacks>,
    features: AgFeatures,
    ag_ind: [Indicator; INDICATOR_COUNT],
    service: bool,
    signal: u8,
    roaming: bool,
    battchg: u8,
    chlds: ChldFlags,
    session_active: bool,
    slc_state: SlcState,
    clcc_in_progress: bool,
    calls: Vec<HfCall>,
    updated_calls: Vec<u32>,
    dialing_number: Option<String>,
}

impl HfpHf {
    /// Create a new `HfpHf` wrapping the given RFCOMM file descriptor.
    pub fn new(fd: RawFd) -> Option<Self> {
        let read_buf = RingBuf::new(HFP_BUF_SIZE)?;
        let write_buf = RingBuf::new(HFP_BUF_SIZE)?;

        Some(Self {
            fd,
            close_on_unref: false,
            read_buf,
            write_buf,
            writer_active: false,
            cmd_queue: VecDeque::new(),
            event_handlers: Vec::new(),
            debug_callback: None,
            disconnect_callback: None,
            in_disconnect: false,
            callbacks: None,
            features: AgFeatures::empty(),
            ag_ind: std::array::from_fn(|_| Indicator::default()),
            service: false,
            signal: 0,
            roaming: false,
            battchg: 0,
            chlds: ChldFlags::empty(),
            session_active: false,
            slc_state: SlcState::Idle,
            clcc_in_progress: false,
            calls: Vec::new(),
            updated_calls: Vec::new(),
            dialing_number: None,
        })
    }

    /// Return the underlying file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    // -- Debug & lifecycle --------------------------------------------------

    /// Replace the debug callback.
    pub fn set_debug(&mut self, cb: Option<DebugCallback>) {
        self.debug_callback = cb;
    }

    /// When set, marks that the fd should be closed by the owner when done.
    pub fn set_close_on_unref(&mut self, close: bool) {
        self.close_on_unref = close;
    }

    /// Return the close-on-unref flag.
    pub fn close_on_unref(&self) -> bool {
        self.close_on_unref
    }

    /// Install the disconnect handler.
    pub fn set_disconnect_handler(&mut self, cb: Option<DisconnectCallback>) {
        self.disconnect_callback = cb;
    }

    /// Trigger a disconnect.
    pub fn disconnect(&mut self) {
        if self.in_disconnect {
            return;
        }
        self.in_disconnect = true;
        if let Some(cb) = self.disconnect_callback.take() {
            cb();
        }
        self.in_disconnect = false;
    }

    // -- Event handler registration -----------------------------------------

    /// Register an unsolicited event handler for the given prefix.
    pub fn register(&mut self, prefix: &str, callback: HfEventHandler) -> bool {
        if self.event_handlers.iter().any(|h| h.prefix == prefix) {
            return false;
        }
        self.event_handlers.push(EventHandler { prefix: prefix.to_owned(), callback });
        true
    }

    /// Unregister the event handler for the given prefix.
    pub fn unregister(&mut self, prefix: &str) -> bool {
        let before = self.event_handlers.len();
        self.event_handlers.retain(|h| h.prefix != prefix);
        self.event_handlers.len() < before
    }

    // -- Command sending ----------------------------------------------------

    /// Send an AT command to the AG and enqueue a response callback.
    pub fn send_command(&mut self, command: &str, resp_cb: Option<HfResponseCallback>) -> bool {
        if self.write_buf.printf(format_args!("{command}\r")).is_err() {
            return false;
        }

        self.cmd_queue.push_back(CmdResponse { resp_cb });
        self.writer_active = true;

        true
    }

    /// Return a reference to the write buffer for the caller to flush.
    pub fn write_buf(&self) -> &RingBuf {
        &self.write_buf
    }

    /// Return a mutable reference to the write buffer.
    pub fn write_buf_mut(&mut self) -> &mut RingBuf {
        &mut self.write_buf
    }

    /// Return a mutable reference to the read buffer for the caller to fill.
    pub fn read_buf_mut(&mut self) -> &mut RingBuf {
        &mut self.read_buf
    }

    /// Return the number of bytes available for reading from the write buffer.
    pub fn pending_write(&self) -> usize {
        self.write_buf.len()
    }

    /// Drain up to `count` bytes from the write buffer.
    pub fn drain_written(&mut self, count: usize) {
        self.write_buf.drain(count);
        if self.write_buf.is_empty() {
            self.writer_active = false;
        }
    }

    // -- Response / event processing ----------------------------------------

    /// Determine if the given data line is a final response.
    fn is_response(data: &[u8]) -> Option<(HfpResult, HfpError)> {
        if data == b"OK" {
            return Some((HfpResult::Ok, HfpError::AgFailure));
        }
        if data == b"ERROR" {
            return Some((HfpResult::Error, HfpError::AgFailure));
        }
        if data == b"NO CARRIER" {
            return Some((HfpResult::NoCarrier, HfpError::AgFailure));
        }
        if data == b"NO ANSWER" {
            return Some((HfpResult::NoAnswer, HfpError::AgFailure));
        }
        if data == b"BUSY" {
            return Some((HfpResult::Busy, HfpError::AgFailure));
        }
        if data == b"DELAYED" {
            return Some((HfpResult::Delayed, HfpError::AgFailure));
        }
        if data == b"BLACKLISTED" {
            return Some((HfpResult::Rejected, HfpError::AgFailure));
        }
        if data.starts_with(b"+CME ERROR: ") {
            let rest = &data[12..];
            let code_str = String::from_utf8_lossy(rest);
            let code = code_str.trim().parse::<u32>().unwrap_or(0);
            return Some((HfpResult::CmeError, HfpError::from_u32(code)));
        }

        None
    }

    /// Extract the prefix and data offset from an AT response/event line.
    fn extract_prefix(data: &[u8]) -> (String, usize) {
        let len = data.len();
        let mut pos = 0usize;

        while pos < len {
            let ch = data[pos];
            if ch == b';' || ch == b':' || ch == b'\0' {
                break;
            }
            pos += 1;
        }

        let prefix: String =
            data[..pos].iter().map(|&b| char::from(b).to_ascii_uppercase()).collect();

        // Skip past separator and whitespace
        let data_start = if pos < len && (data[pos] == b':' || data[pos] == b';') {
            let mut ds = pos + 1;
            while ds < len && data[ds] == b' ' {
                ds += 1;
            }
            ds
        } else {
            pos
        };

        (prefix, data_start)
    }

    /// Process a single response/event line from the AG.
    fn call_prefix_handler(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // Check if this is a final response
        if let Some((result, error)) = Self::is_response(data) {
            // If SLC is in progress, route response to SLC handler
            if self.slc_state != SlcState::Idle {
                self.handle_slc_response(result, error);
                return;
            }
            // If CLCC is in progress, route to CLCC response handler
            if self.clcc_in_progress {
                self.handle_clcc_response(result, error);
                return;
            }
            // Otherwise, deliver to cmd_queue
            if let Some(cmd) = self.cmd_queue.pop_front() {
                if let Some(cb) = cmd.resp_cb {
                    cb(result, error);
                }
            }
            return;
        }

        // It's an unsolicited event — extract prefix
        let (prefix, data_start) = Self::extract_prefix(data);

        // During SLC, handle SLC-specific prefixes
        if self.slc_state != SlcState::Idle {
            let param_data = &data[data_start..];
            if self.handle_slc_event(&prefix, param_data) {
                return;
            }
        }

        // Session-active built-in handlers
        if self.session_active {
            let param_data = &data[data_start..];
            if self.handle_builtin_event(&prefix, param_data) {
                return;
            }
        }

        // Fall through to user-registered event handlers
        let handler_idx = self.event_handlers.iter().position(|h| h.prefix == prefix);
        if let Some(idx) = handler_idx {
            let param_data = &data[data_start..];
            let mut ctx = HfpContext::new(param_data);
            (self.event_handlers[idx].callback)(&mut ctx);
        }
    }

    /// Search for `\r\n` delimiter in data.
    fn find_cr_lf(data: &[u8]) -> Option<usize> {
        data.windows(2).position(|w| w == b"\r\n")
    }

    /// Process buffered input from the HF read buffer.
    fn process_input(&mut self) {
        loop {
            if self.read_buf.is_empty() {
                return;
            }

            let (first, second) = self.read_buf.peek(0);
            let data: Vec<u8> = match second {
                Some(s) => {
                    let mut v = Vec::with_capacity(first.len() + s.len());
                    v.extend_from_slice(first);
                    v.extend_from_slice(s);
                    v
                }
                None => first.to_vec(),
            };

            let crlf_pos = match Self::find_cr_lf(&data) {
                Some(p) => p,
                None => return,
            };

            let line = data[..crlf_pos].to_vec();
            let total_drain = crlf_pos + 2;

            if !line.is_empty() {
                debug!("HF: received response ({} bytes)", line.len());
                self.call_prefix_handler(&line);
            }

            self.read_buf.drain(total_drain);
        }
    }

    /// Feed data into the read buffer and trigger processing.
    pub fn receive_data(&mut self, data: &[u8]) {
        let _ = self.read_buf.write_bytes(data);
        self.process_input();
    }

    // -- Session management -------------------------------------------------

    /// Register HF session callbacks.
    pub fn session_register(&mut self, callbacks: HfpHfCallbacks) -> bool {
        self.callbacks = Some(callbacks);
        true
    }

    /// Start SLC (Service Level Connection) establishment.
    ///
    /// Returns `true` if the initial AT+BRSF command was sent successfully.
    pub fn session(&mut self) -> bool {
        let feat = HFP_HF_FEATURES.bits();
        let cmd = format!("AT+BRSF={feat}");
        self.slc_state = SlcState::WaitBrsf;
        self.send_command_internal(&cmd)
    }

    // -- SLC chain (state machine) ------------------------------------------

    /// Send a command internally during SLC (no user callback).
    fn send_command_internal(&mut self, command: &str) -> bool {
        if self.write_buf.printf(format_args!("{command}\r")).is_err() {
            return false;
        }
        self.writer_active = true;
        true
    }

    /// Handle an unsolicited event during SLC establishment.
    ///
    /// Returns `true` if the event was consumed by the SLC handler.
    fn handle_slc_event(&mut self, prefix: &str, param_data: &[u8]) -> bool {
        match self.slc_state {
            SlcState::WaitBrsf if prefix == "+BRSF" => {
                let mut ctx = HfpContext::new(param_data);
                self.slc_brsf_cb(&mut ctx);
                true
            }
            SlcState::WaitCind if prefix == "+CIND" => {
                let mut ctx = HfpContext::new(param_data);
                self.slc_cind_cb(&mut ctx);
                true
            }
            SlcState::WaitCindStatus if prefix == "+CIND" => {
                let mut ctx = HfpContext::new(param_data);
                self.slc_cind_status_cb(&mut ctx);
                true
            }
            SlcState::WaitChld if prefix == "+CHLD" => {
                let mut ctx = HfpContext::new(param_data);
                self.slc_chld_cb(&mut ctx);
                true
            }
            SlcState::WaitCops if prefix == "+COPS" => {
                let mut ctx = HfpContext::new(param_data);
                self.handle_cops_event(&mut ctx);
                true
            }
            _ => false,
        }
    }

    /// Handle a final response during SLC establishment.
    fn handle_slc_response(&mut self, result: HfpResult, error: HfpError) {
        // Pop the SLC command from cmd_queue if present
        let _ = self.cmd_queue.pop_front();

        match self.slc_state {
            SlcState::WaitBrsf => self.slc_brsf_resp(result, error),
            SlcState::WaitCind => self.slc_cind_resp(result, error),
            SlcState::WaitCindStatus => self.slc_cind_status_resp(result, error),
            SlcState::WaitCmer => self.slc_cmer_resp(result, error),
            SlcState::WaitChld => self.slc_chld_resp(result, error),
            SlcState::WaitCopsConf => self.slc_cops_conf_resp(result, error),
            SlcState::WaitCops => self.slc_cops_resp(result, error),
            SlcState::WaitClip => self.slc_clip_resp(result, error),
            SlcState::WaitCcwa => self.slc_ccwa_resp(result, error),
            SlcState::WaitCmee => self.slc_cmee_resp(result, error),
            SlcState::WaitNrec => self.slc_nrec_resp(result, error),
            SlcState::Idle => {}
        }
    }

    /// Process +BRSF response: parse AG features.
    fn slc_brsf_cb(&mut self, ctx: &mut HfpContext) {
        if let Some(val) = ctx.get_number() {
            self.features = AgFeatures::from_bits_truncate(val);
            debug!("HF: AG features = {:?}", self.features);
        }
    }

    /// After +BRSF OK: send AT+CIND=? to query indicator descriptions.
    fn slc_brsf_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        self.slc_state = SlcState::WaitCind;
        let _ = self.send_command_internal("AT+CIND=?");
    }

    /// Process +CIND=? response: parse indicator descriptions.
    ///
    /// Indicators come in two value-range formats:
    ///   - Dash range:   `("callsetup",(0-3))`  — parsed by `get_range()`
    ///   - Comma pair:   `("service",(0,1))`     — fallback to two `get_number()` calls
    ///
    /// The C original (`src/shared/hfp.c` `slc_cind_cb`) tries `get_range`
    /// first, and falls back to two `get_number` calls when the dash is absent.
    fn slc_cind_cb(&mut self, ctx: &mut HfpContext) {
        let mut index: u8 = 1;
        while ctx.has_next() {
            if !ctx.open_container() {
                break;
            }
            let name = match ctx.get_string(255) {
                Some(n) => n,
                None => break,
            };
            if !ctx.open_container() {
                break;
            }
            // Try dash-range first (e.g. 0-3), then fall back to comma pair (e.g. 0,1)
            let range = match ctx.get_range() {
                Some(r) => Some(r),
                None => {
                    let min = ctx.get_number();
                    let max = ctx.get_number();
                    match (min, max) {
                        (Some(mn), Some(mx)) => Some((mn, mx)),
                        _ => None,
                    }
                }
            };
            if !ctx.close_container() {
                break;
            }
            if !ctx.close_container() {
                break;
            }
            if let Some((min, max)) = range {
                self.set_indicator_parameters(index, &name, min, max);
            }
            index += 1;
        }
    }

    /// After +CIND=? OK: send AT+CIND? to query status.
    fn slc_cind_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        self.slc_state = SlcState::WaitCindStatus;
        let _ = self.send_command_internal("AT+CIND?");
    }

    /// Process +CIND? response: parse indicator current values.
    fn slc_cind_status_cb(&mut self, ctx: &mut HfpContext) {
        for ind in &mut self.ag_ind {
            if let Some(val) = ctx.get_number() {
                ind.val = val;
            }
        }
    }

    /// After +CIND? OK: send AT+CMER to enable indicator reporting.
    fn slc_cind_status_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        self.slc_state = SlcState::WaitCmer;
        let _ = self.send_command_internal("AT+CMER=3,0,0,1");
    }

    /// After AT+CMER OK: optionally query CHLD support.
    fn slc_cmer_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        if self.features.contains(AgFeatures::THREE_WAY) {
            self.slc_state = SlcState::WaitChld;
            let _ = self.send_command_internal("AT+CHLD=?");
        } else {
            // Skip CHLD, proceed directly
            self.slc_chld_resp(HfpResult::Ok, HfpError::AgFailure);
        }
    }

    /// Process +CHLD=? response: parse supported CHLD operations.
    fn slc_chld_cb(&mut self, ctx: &mut HfpContext) {
        if !ctx.open_container() {
            return;
        }
        while !ctx.is_container_close() {
            if let Some(s) = ctx.get_unquoted_string(3) {
                match s.as_str() {
                    "0" => self.chlds |= ChldFlags::CHLD_0,
                    "1" => self.chlds |= ChldFlags::CHLD_1,
                    "1x" | "1X" => self.chlds |= ChldFlags::CHLD_1X,
                    "2" => self.chlds |= ChldFlags::CHLD_2,
                    "2x" | "2X" => self.chlds |= ChldFlags::CHLD_2X,
                    "3" => self.chlds |= ChldFlags::CHLD_3,
                    "4" => self.chlds |= ChldFlags::CHLD_4,
                    other => {
                        debug!("HF: unsupported CHLD value: {other}");
                    }
                }
            } else {
                break;
            }
        }
        let _ = ctx.close_container();
    }

    /// After +CHLD=? OK: send AT+COPS=3,0 to set operator format.
    fn slc_chld_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        self.slc_state = SlcState::WaitCopsConf;
        let _ = self.send_command_internal("AT+COPS=3,0");
    }

    /// After AT+COPS=3,0 OK: query operator name.
    fn slc_cops_conf_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        self.slc_state = SlcState::WaitCops;
        let _ = self.send_command_internal("AT+COPS?");
    }

    /// Process +COPS event during SLC.
    fn handle_cops_event(&mut self, ctx: &mut HfpContext) {
        let _ = ctx.get_number(); // mode
        let _ = ctx.get_number(); // format
        let name = ctx.get_string(255).unwrap_or_default();
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_operator {
                cb(&name);
            }
        }
    }

    /// After AT+COPS? OK: enable CLIP.
    fn slc_cops_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        self.slc_state = SlcState::WaitClip;
        let _ = self.send_command_internal("AT+CLIP=1");
    }

    /// After AT+CLIP=1 OK: optionally enable CCWA.
    fn slc_clip_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        if self.features.contains(AgFeatures::THREE_WAY) {
            self.slc_state = SlcState::WaitCcwa;
            let _ = self.send_command_internal("AT+CCWA=1");
        } else {
            self.slc_ccwa_resp(HfpResult::Ok, HfpError::AgFailure);
        }
    }

    /// After AT+CCWA=1 OK: optionally enable CMEE.
    fn slc_ccwa_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        if self.features.contains(AgFeatures::EXTENDED_RES_CODE) {
            self.slc_state = SlcState::WaitCmee;
            let _ = self.send_command_internal("AT+CMEE=1");
        } else {
            self.slc_cmee_resp(HfpResult::Ok, HfpError::AgFailure);
        }
    }

    /// After AT+CMEE=1 OK: optionally disable NREC.
    fn slc_cmee_resp(&mut self, result: HfpResult, error: HfpError) {
        if result != HfpResult::Ok {
            self.slc_state = SlcState::Idle;
            self.notify_session_ready(result, error);
            return;
        }
        if self.features.contains(AgFeatures::ECNR) {
            self.slc_state = SlcState::WaitNrec;
            let _ = self.send_command_internal("AT+NREC=0");
        } else {
            self.slc_nrec_resp(HfpResult::Ok, HfpError::AgFailure);
        }
    }

    /// Final SLC step: mark session active.
    fn slc_nrec_resp(&mut self, _result: HfpResult, _error: HfpError) {
        self.slc_state = SlcState::Idle;
        self.session_active = true;

        self.notify_session_ready(HfpResult::Ok, HfpError::AgFailure);

        // Dispatch initial indicator values now that session is active
        for i in 0..INDICATOR_COUNT {
            if self.ag_ind[i].active {
                let val = self.ag_ind[i].val as u8;
                self.dispatch_indicator(i, val);
            }
        }

        // Send initial CLCC if enhanced call status
        if self.features.contains(AgFeatures::ENHANCED_CALL_STATUS) {
            self.send_clcc();
        }
    }

    /// Notify the session_ready callback.
    fn notify_session_ready(&self, result: HfpResult, error: HfpError) {
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.session_ready {
                cb(result, error);
            }
        }
    }

    // -- Built-in unsolicited event handlers --------------------------------

    /// Handle built-in unsolicited events (active after SLC establishment).
    ///
    /// Returns `true` if the event was consumed.
    fn handle_builtin_event(&mut self, prefix: &str, param_data: &[u8]) -> bool {
        match prefix {
            "+CIEV" => {
                let mut ctx = HfpContext::new(param_data);
                self.handle_ciev(&mut ctx);
                true
            }
            "+BSIR" => {
                let mut ctx = HfpContext::new(param_data);
                self.handle_bsir(&mut ctx);
                true
            }
            "+CCWA" => {
                let mut ctx = HfpContext::new(param_data);
                self.handle_ccwa(&mut ctx);
                true
            }
            "+CLIP" => {
                let mut ctx = HfpContext::new(param_data);
                self.handle_clip(&mut ctx);
                true
            }
            "+COPS" => {
                let mut ctx = HfpContext::new(param_data);
                self.handle_cops_event(&mut ctx);
                true
            }
            "+CLCC" => {
                let mut ctx = HfpContext::new(param_data);
                self.handle_clcc_entry(&mut ctx);
                true
            }
            _ => false,
        }
    }

    // -- CIEV indicator processing ------------------------------------------

    /// +CIEV handler: parse index and value, dispatch to indicator handler.
    fn handle_ciev(&mut self, ctx: &mut HfpContext) {
        let index = match ctx.get_number() {
            Some(v) => v as u8,
            None => return,
        };
        let val = match ctx.get_number() {
            Some(v) => v as u8,
            None => return,
        };

        // Find the indicator with matching wire index.
        for i in 0..INDICATOR_COUNT {
            if self.ag_ind[i].index == index && self.ag_ind[i].active {
                self.dispatch_indicator(i, val);
                return;
            }
        }
    }

    /// Dispatch an indicator value change to the appropriate handler.
    fn dispatch_indicator(&mut self, ind_slot: usize, val: u8) {
        match ind_slot {
            0 => self.ciev_service(val),
            1 => self.ciev_call(val),
            2 => self.ciev_callsetup(val),
            3 => self.ciev_callheld(val),
            4 => self.ciev_signal(val),
            5 => self.ciev_roam(val),
            6 => self.ciev_battchg(val),
            _ => {}
        }
    }

    /// CIEV "service" indicator.
    fn ciev_service(&mut self, val: u8) {
        if val > 1 {
            return;
        }
        self.service = val != 0;
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_indicator {
                cb(HfpIndicator::Service, u32::from(val));
            }
        }
    }

    /// CIEV "call" indicator.
    fn ciev_call(&mut self, val: u8) {
        if val > 1 {
            return;
        }

        if self.features.contains(AgFeatures::ENHANCED_CALL_STATUS) {
            self.send_clcc();
            return;
        }

        if val == HfpCall::CindCallNone as u8 {
            // Remove all calls
            let ids: Vec<u32> = self.calls.iter().map(|c| c.id).collect();
            for id in ids {
                if let Some(ref cbs) = self.callbacks {
                    if let Some(ref cb) = cbs.call_removed {
                        cb(id);
                    }
                }
            }
            self.calls.clear();
        } else {
            // Call in progress — transition a setup call to active
            if !self.update_call_to_active() {
                let id = self.next_call_index();
                self.call_new(id, HfpCallStatus::Active, None, 0, false);
            }
        }

        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_indicator {
                cb(HfpIndicator::Call, u32::from(val));
            }
        }
    }

    /// CIEV "callsetup" indicator.
    fn ciev_callsetup(&mut self, val: u8) {
        if val > 3 {
            return;
        }

        if self.features.contains(AgFeatures::ENHANCED_CALL_STATUS) {
            if val != HfpCallSetup::None as u8 {
                self.send_clcc();
            }
        } else {
            match val {
                0 => {
                    // Setup NONE — remove setup/incoming/waiting calls
                    let remove_ids: Vec<u32> = self
                        .calls
                        .iter()
                        .filter(|c| {
                            matches!(
                                c.status,
                                HfpCallStatus::Dialing
                                    | HfpCallStatus::Alerting
                                    | HfpCallStatus::Incoming
                                    | HfpCallStatus::Waiting
                            )
                        })
                        .map(|c| c.id)
                        .collect();
                    for id in &remove_ids {
                        if let Some(ref cbs) = self.callbacks {
                            if let Some(ref cb) = cbs.call_removed {
                                cb(*id);
                            }
                        }
                    }
                    self.calls.retain(|c| !remove_ids.contains(&c.id));
                }
                1 => {
                    // Incoming call
                    let id = self.next_call_index();
                    self.call_new(id, HfpCallStatus::Incoming, None, 0, false);
                }
                2 => {
                    // Dialing
                    let existing =
                        self.calls.iter_mut().find(|c| c.status == HfpCallStatus::Incoming);
                    if let Some(call) = existing {
                        call.status = HfpCallStatus::Dialing;
                        let cid = call.id;
                        if let Some(ref cbs) = self.callbacks {
                            if let Some(ref cb) = cbs.call_status_updated {
                                cb(cid, HfpCallStatus::Dialing);
                            }
                        }
                    } else {
                        let id = self.next_call_index();
                        let num = self.dialing_number.clone();
                        self.call_new(id, HfpCallStatus::Dialing, num.as_deref(), 0, false);
                    }
                }
                3 => {
                    // Alerting
                    let existing =
                        self.calls.iter_mut().find(|c| c.status == HfpCallStatus::Dialing);
                    if let Some(call) = existing {
                        call.status = HfpCallStatus::Alerting;
                        let cid = call.id;
                        if let Some(ref cbs) = self.callbacks {
                            if let Some(ref cb) = cbs.call_status_updated {
                                cb(cid, HfpCallStatus::Alerting);
                            }
                        }
                    } else {
                        let id = self.next_call_index();
                        let num = self.dialing_number.clone();
                        self.call_new(id, HfpCallStatus::Alerting, num.as_deref(), 0, false);
                    }
                }
                _ => {}
            }
        }

        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_indicator {
                cb(HfpIndicator::Callsetup, u32::from(val));
            }
        }
    }

    /// CIEV "callheld" indicator.
    fn ciev_callheld(&mut self, val: u8) {
        if val > 2 {
            return;
        }
        if self.features.contains(AgFeatures::ENHANCED_CALL_STATUS) {
            self.send_clcc();
            return;
        }
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_indicator {
                cb(HfpIndicator::Callheld, u32::from(val));
            }
        }
    }

    /// CIEV "signal" indicator.
    fn ciev_signal(&mut self, val: u8) {
        if val > 5 {
            return;
        }
        self.signal = val;
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_indicator {
                cb(HfpIndicator::Signal, u32::from(val));
            }
        }
    }

    /// CIEV "roam" indicator.
    fn ciev_roam(&mut self, val: u8) {
        if val > 1 {
            return;
        }
        self.roaming = val != 0;
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_indicator {
                cb(HfpIndicator::Roam, u32::from(val));
            }
        }
    }

    /// CIEV "battchg" indicator.
    fn ciev_battchg(&mut self, val: u8) {
        if val > 5 {
            return;
        }
        self.battchg = val;
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_indicator {
                cb(HfpIndicator::Battchg, u32::from(val));
            }
        }
    }

    // -- Unsolicited event handlers -----------------------------------------

    /// +BSIR handler: in-band ring setting.
    fn handle_bsir(&mut self, ctx: &mut HfpContext) {
        let val = match ctx.get_number() {
            Some(v) => v,
            None => return,
        };
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.update_inband_ring {
                cb(val != 0);
            }
        }
    }

    /// +CCWA handler: call waiting notification.
    fn handle_ccwa(&mut self, ctx: &mut HfpContext) {
        if self.features.contains(AgFeatures::ENHANCED_CALL_STATUS) {
            self.send_clcc();
            return;
        }
        let number = ctx.get_string(255);
        let call_type = ctx.get_number().unwrap_or(0);
        let id = self.next_call_index();
        self.call_new(id, HfpCallStatus::Waiting, number.as_deref(), call_type, false);
    }

    /// +CLIP handler: caller line identification.
    fn handle_clip(&mut self, ctx: &mut HfpContext) {
        let number = match ctx.get_string(255) {
            Some(n) => n,
            None => return,
        };
        let call_type = ctx.get_number().unwrap_or(0);

        let incoming = self.calls.iter_mut().find(|c| c.status == HfpCallStatus::Incoming);
        if let Some(call) = incoming {
            call.line_id = Some(number.clone());
            call.call_type = call_type;
            let cid = call.id;
            if let Some(ref cbs) = self.callbacks {
                if let Some(ref cb) = cbs.call_line_id_updated {
                    cb(cid, &number, call_type);
                }
            }
        }
    }

    /// +CLCC handler: current call list entry.
    fn handle_clcc_entry(&mut self, ctx: &mut HfpContext) {
        let id = match ctx.get_number() {
            Some(v) => v,
            None => return,
        };
        let _dir = ctx.get_number(); // direction (not stored)
        let status_val = match ctx.get_number() {
            Some(v) => v,
            None => return,
        };
        let _mode = ctx.get_number(); // mode (not stored)
        let mpty_val = ctx.get_number().unwrap_or(0);
        let number = ctx.get_string(255);
        let call_type = ctx.get_number().unwrap_or(0);

        let status = match HfpCallStatus::from_u32(status_val) {
            Some(s) => s,
            None => return,
        };
        let mpty = mpty_val != 0;

        self.updated_calls.push(id);

        let existing = self.calls.iter_mut().find(|c| c.id == id);
        if let Some(call) = existing {
            if call.status != status {
                call.status = status;
                if let Some(ref cbs) = self.callbacks {
                    if let Some(ref cb) = cbs.call_status_updated {
                        cb(id, status);
                    }
                }
            }
            if call.mpty != mpty {
                call.mpty = mpty;
                if let Some(ref cbs) = self.callbacks {
                    if let Some(ref cb) = cbs.call_mpty_updated {
                        cb(id, mpty);
                    }
                }
            }
            if number.is_some() && call.line_id != number {
                let num_str = number.as_deref().unwrap_or("");
                call.line_id.clone_from(&number);
                call.call_type = call_type;
                if let Some(ref cbs) = self.callbacks {
                    if let Some(ref cb) = cbs.call_line_id_updated {
                        cb(id, num_str, call_type);
                    }
                }
            }
        } else {
            self.call_new(id, status, number.as_deref(), call_type, mpty);
        }
    }

    /// Handle AT+CLCC response (reconcile call list).
    fn handle_clcc_response(&mut self, _result: HfpResult, _error: HfpError) {
        // Pop from cmd_queue if present
        let _ = self.cmd_queue.pop_front();

        self.clcc_in_progress = false;

        let updated = self.updated_calls.clone();
        let remove_ids: Vec<u32> =
            self.calls.iter().filter(|c| !updated.contains(&c.id)).map(|c| c.id).collect();

        for id in &remove_ids {
            if let Some(ref cbs) = self.callbacks {
                if let Some(ref cb) = cbs.call_removed {
                    cb(*id);
                }
            }
        }
        self.calls.retain(|c| !remove_ids.contains(&c.id));
        self.updated_calls.clear();
    }

    // -- Indicator management -----------------------------------------------

    /// Map an indicator name to its slot and configure parameters.
    fn set_indicator_parameters(&mut self, index: u8, name: &str, min: u32, max: u32) {
        let slot = match name {
            "service" if min == 0 && max == 1 => Some(HfpIndicator::Service as usize),
            "call" if min == 0 && max == 1 => Some(HfpIndicator::Call as usize),
            "callsetup" if min == 0 && max == 3 => Some(HfpIndicator::Callsetup as usize),
            "callheld" if min == 0 && max == 2 => Some(HfpIndicator::Callheld as usize),
            "signal" if min == 0 && max == 5 => Some(HfpIndicator::Signal as usize),
            "roam" if min == 0 && max == 1 => Some(HfpIndicator::Roam as usize),
            "battchg" if min == 0 && max == 5 => Some(HfpIndicator::Battchg as usize),
            _ => None,
        };

        if let Some(idx) = slot {
            self.ag_ind[idx].index = index;
            self.ag_ind[idx].min = min;
            self.ag_ind[idx].max = max;
            self.ag_ind[idx].active = true;
        }
    }

    // -- Call management ----------------------------------------------------

    /// Find the next unused call ID (starting from 1).
    fn next_call_index(&self) -> u32 {
        let mut id: u32 = 1;
        loop {
            if !self.calls.iter().any(|c| c.id == id) {
                return id;
            }
            id += 1;
        }
    }

    /// Create a new tracked call and notify callback.
    fn call_new(
        &mut self,
        id: u32,
        status: HfpCallStatus,
        number: Option<&str>,
        call_type: u32,
        mpty: bool,
    ) {
        if let Some(ref cbs) = self.callbacks {
            if let Some(ref cb) = cbs.call_added {
                cb(id, status);
            }
        }
        self.calls.push(HfCall { id, status, line_id: number.map(String::from), call_type, mpty });
    }

    /// Update the first call matching a setup/incoming status to ACTIVE.
    fn update_call_to_active(&mut self) -> bool {
        for call in &mut self.calls {
            match call.status {
                HfpCallStatus::Dialing | HfpCallStatus::Alerting | HfpCallStatus::Incoming => {
                    let old_status = call.status;
                    call.status = HfpCallStatus::Active;
                    let cid = call.id;
                    if let Some(ref cbs) = self.callbacks {
                        if let Some(ref cb) = cbs.call_status_updated {
                            cb(cid, HfpCallStatus::Active);
                        }
                    }
                    debug!("HF: call {} status {:?} -> Active", cid, old_status);
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Send AT+CLCC to query current call list.
    fn send_clcc(&mut self) {
        if self.clcc_in_progress {
            return;
        }
        self.clcc_in_progress = true;
        self.updated_calls.clear();
        let _ = self.send_command_internal("AT+CLCC");
    }

    // -- Call operations (public) -------------------------------------------

    /// Initiate a dial operation.
    ///
    /// - `None` or empty → last-number redial (AT+BLDN)
    /// - Starts with `>` → memory dial (ATD>N;)
    /// - Otherwise → regular dial (ATD<number>;)
    pub fn dial(&mut self, number: Option<&str>, resp_cb: Option<HfResponseCallback>) -> bool {
        match number {
            None | Some("") => self.send_command("AT+BLDN", resp_cb),
            Some(num) if num.starts_with('>') => {
                let digits = &num[1..];
                if digits.is_empty() || digits.len() > 10 {
                    return false;
                }
                if !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                let cmd = format!("ATD{num};");
                self.dialing_number = Some(num.to_owned());
                self.send_command(&cmd, resp_cb)
            }
            Some(num) => {
                if num.is_empty() || num.len() > 80 {
                    return false;
                }
                if !num.bytes().all(|b| {
                    b.is_ascii_digit()
                        || b == b'A'
                        || b == b'B'
                        || b == b'C'
                        || b == b'D'
                        || b == b'#'
                        || b == b'*'
                        || b == b'+'
                        || b == b','
                }) {
                    return false;
                }
                let cmd = format!("ATD{num};");
                self.dialing_number = Some(num.to_owned());
                self.send_command(&cmd, resp_cb)
            }
        }
    }

    /// Release held call and accept waiting call (AT+CHLD=1).
    pub fn release_and_accept(&mut self, resp_cb: Option<HfResponseCallback>) -> bool {
        if !self.chlds.contains(ChldFlags::CHLD_1) {
            return false;
        }
        let has_target = self
            .calls
            .iter()
            .any(|c| c.status == HfpCallStatus::Waiting || c.status == HfpCallStatus::Held);
        if !has_target {
            return false;
        }
        self.send_command("AT+CHLD=1", resp_cb)
    }

    /// Swap active and held calls (AT+CHLD=2).
    pub fn swap_calls(&mut self, resp_cb: Option<HfResponseCallback>) -> bool {
        if !self.chlds.contains(ChldFlags::CHLD_2) {
            return false;
        }
        self.send_command("AT+CHLD=2", resp_cb)
    }

    /// Answer an incoming call by ID.
    pub fn call_answer(&mut self, id: u32, resp_cb: Option<HfResponseCallback>) -> bool {
        let status = match self.calls.iter().find(|c| c.id == id) {
            Some(c) => c.status,
            None => return false,
        };
        if status != HfpCallStatus::Incoming {
            return false;
        }
        self.send_command("ATA", resp_cb)
    }

    /// Hang up a call by ID.
    ///
    /// For active/setup calls: sends AT+CHUP.
    /// For waiting/held calls with CHLD_0 support: sends AT+CHLD=0.
    pub fn call_hangup(&mut self, id: u32, resp_cb: Option<HfResponseCallback>) -> bool {
        let status = match self.calls.iter().find(|c| c.id == id) {
            Some(c) => c.status,
            None => return false,
        };
        match status {
            HfpCallStatus::Active
            | HfpCallStatus::Dialing
            | HfpCallStatus::Alerting
            | HfpCallStatus::Incoming => self.send_command("AT+CHUP", resp_cb),
            HfpCallStatus::Waiting | HfpCallStatus::Held => {
                if !self.chlds.contains(ChldFlags::CHLD_0) {
                    return false;
                }
                self.send_command("AT+CHLD=0", resp_cb)
            }
            _ => false,
        }
    }

    // -- Call query ----------------------------------------------------------

    /// Get the line ID (phone number) of a call by ID.
    pub fn call_get_number(&self, id: u32) -> Option<&str> {
        self.calls.iter().find(|c| c.id == id).and_then(|c| c.line_id.as_deref())
    }

    /// Get the multiparty flag of a call by ID.
    pub fn call_get_multiparty(&self, id: u32) -> Option<bool> {
        self.calls.iter().find(|c| c.id == id).map(|c| c.mpty)
    }
}
