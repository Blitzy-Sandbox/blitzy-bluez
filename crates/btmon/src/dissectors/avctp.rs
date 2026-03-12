// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 * Copyright (C) 2011-2014 Intel Corporation
 * Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>
 *
 * avctp.rs — AVCTP/AVRCP protocol dissector.
 *
 * Complete Rust rewrite of monitor/avctp.c (2,545 lines) + monitor/avctp.h
 * from BlueZ v5.86.  Decodes AVCTP transaction/packet type/message type
 * headers and full AVRCP decoding: Unit Info, Subunit Info, Pass Through,
 * Vendor Dependent (Get Capabilities, List/Get Player App Settings, Get
 * Element Attributes, Play Status, Register Notification, Set Absolute
 * Volume, Set Addressed/Browsed Player, Get Folder Items, Change Path,
 * Get Item Attributes, Play Item, Search, Add To Now Playing).  Browsing
 * channel message decoding with continuation state tracking across
 * fragmented packets.
 */

use std::cell::RefCell;

use crate::display::{
    COLOR_BLUE, COLOR_ERROR, COLOR_MAGENTA, COLOR_OFF, COLOR_WHITE_BG, print_hexdump,
};
use crate::{print_field, print_indent, print_text};

// ============================================================================
// Local L2capFrame definition (mirrors l2cap.rs export contract).
// Defined locally per D4 rules since l2cap.rs is not in depends_on_files.
// ============================================================================

/// L2CAP frame cursor struct used by all dissectors.
///
/// This is a local definition matching the API contract that will be
/// exported by `crates/btmon/src/dissectors/l2cap.rs`.  When that module
/// is created it will be the canonical source; until then, this local
/// definition enables independent compilation.
#[derive(Clone)]
pub struct L2capFrame {
    pub index: u16,
    pub in_: bool,
    pub handle: u16,
    pub ident: u8,
    pub cid: u16,
    pub psm: u16,
    pub chan: u16,
    pub mode: u8,
    pub seq_num: u8,
    /// The full payload buffer.
    data: Vec<u8>,
    /// Current read position within `data`.
    pos: usize,
    /// Remaining bytes available for reading from the current position.
    pub size: u16,
}

impl L2capFrame {
    /// Read one byte from the frame, advancing the cursor.
    pub fn get_u8(&mut self) -> Option<u8> {
        if (self.size as usize) < 1 {
            return None;
        }
        let val = self.data[self.pos];
        self.pos += 1;
        self.size -= 1;
        Some(val)
    }

    /// Read a big-endian u16 from the frame, advancing the cursor.
    pub fn get_be16(&mut self) -> Option<u16> {
        if (self.size as usize) < 2 {
            return None;
        }
        let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        self.size -= 2;
        Some(val)
    }

    /// Read a big-endian u32 from the frame, advancing the cursor.
    pub fn get_be32(&mut self) -> Option<u32> {
        if (self.size as usize) < 4 {
            return None;
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        let val = u32::from_be_bytes(buf);
        self.pos += 4;
        self.size -= 4;
        Some(val)
    }

    /// Read a big-endian u64 from the frame, advancing the cursor.
    pub fn get_be64(&mut self) -> Option<u64> {
        if (self.size as usize) < 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        let val = u64::from_be_bytes(buf);
        self.pos += 8;
        self.size -= 8;
        Some(val)
    }

    /// Advance the cursor by `offset` bytes without reading.
    pub fn pull(&mut self, offset: usize) -> bool {
        if (self.size as usize) < offset {
            return false;
        }
        self.pos += offset;
        self.size -= offset as u16;
        true
    }

    /// Return a slice of the remaining un-consumed data.
    pub fn remaining_data(&self) -> &[u8] {
        let end = self.pos + self.size as usize;
        &self.data[self.pos..end]
    }
}

// ============================================================================
// AVC ctype constants (avctp.c lines 36–47)
// ============================================================================

const AVC_CTYPE_CONTROL: u8 = 0x0;
const AVC_CTYPE_STATUS: u8 = 0x1;
const AVC_CTYPE_SPECIFIC_INQUIRY: u8 = 0x2;
const AVC_CTYPE_NOTIFY: u8 = 0x3;
const AVC_CTYPE_GENERAL_INQUIRY: u8 = 0x4;
const AVC_CTYPE_NOT_IMPLEMENTED: u8 = 0x8;
const AVC_CTYPE_ACCEPTED: u8 = 0x9;
const AVC_CTYPE_REJECTED: u8 = 0xA;
const AVC_CTYPE_IN_TRANSITION: u8 = 0xB;
const AVC_CTYPE_STABLE: u8 = 0xC;
const AVC_CTYPE_CHANGED: u8 = 0xD;
const AVC_CTYPE_INTERIM: u8 = 0xF;

// ============================================================================
// AVC subunit type constants (avctp.c lines 49–63)
// ============================================================================

const AVC_SUBUNIT_MONITOR: u8 = 0x00;
const AVC_SUBUNIT_AUDIO: u8 = 0x01;
const AVC_SUBUNIT_PRINTER: u8 = 0x02;
const AVC_SUBUNIT_DISC: u8 = 0x03;
const AVC_SUBUNIT_TAPE: u8 = 0x04;
const AVC_SUBUNIT_TUNER: u8 = 0x05;
const AVC_SUBUNIT_CA: u8 = 0x06;
const AVC_SUBUNIT_CAMERA: u8 = 0x07;
const AVC_SUBUNIT_PANEL: u8 = 0x09;
const AVC_SUBUNIT_BULLETIN_BOARD: u8 = 0x0a;
const AVC_SUBUNIT_CAMERA_STORAGE: u8 = 0x0b;
const AVC_SUBUNIT_VENDOR_UNIQUE: u8 = 0x0c;
const AVC_SUBUNIT_EXTENDED: u8 = 0x1e;
const AVC_SUBUNIT_UNIT: u8 = 0x1f;

// ============================================================================
// AVC opcodes (avctp.c lines 65–69)
// ============================================================================

const AVC_OP_VENDORDEP: u8 = 0x00;
const AVC_OP_UNITINFO: u8 = 0x30;
const AVC_OP_SUBUNITINFO: u8 = 0x31;
const AVC_OP_PASSTHROUGH: u8 = 0x7c;

// ============================================================================
// AVRCP notification events (avctp.c lines 71–84)
// ============================================================================

const AVRCP_EVENT_PLAYBACK_STATUS_CHANGED: u8 = 0x01;
const AVRCP_EVENT_TRACK_CHANGED: u8 = 0x02;
const AVRCP_EVENT_TRACK_REACHED_END: u8 = 0x03;
const AVRCP_EVENT_TRACK_REACHED_START: u8 = 0x04;
const AVRCP_EVENT_PLAYBACK_POS_CHANGED: u8 = 0x05;
const AVRCP_EVENT_BATT_STATUS_CHANGED: u8 = 0x06;
const AVRCP_EVENT_SYSTEM_STATUS_CHANGED: u8 = 0x07;
const AVRCP_EVENT_PLAYER_APPLICATION_SETTING_CHANGED: u8 = 0x08;
const AVRCP_EVENT_NOW_PLAYING_CONTENT_CHANGED: u8 = 0x09;
const AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED: u8 = 0x0a;
const AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED: u8 = 0x0b;
const AVRCP_EVENT_UIDS_CHANGED: u8 = 0x0c;
const AVRCP_EVENT_VOLUME_CHANGED: u8 = 0x0d;

// ============================================================================
// AVRCP error status codes (avctp.c lines 86–108)
// ============================================================================

const AVRCP_STATUS_INVALID_COMMAND: u8 = 0x00;
const AVRCP_STATUS_INVALID_PARAMETER: u8 = 0x01;
const AVRCP_STATUS_NOT_FOUND: u8 = 0x02;
const AVRCP_STATUS_INTERNAL_ERROR: u8 = 0x03;
const AVRCP_STATUS_SUCCESS: u8 = 0x04;
const AVRCP_STATUS_UID_CHANGED: u8 = 0x05;
const AVRCP_STATUS_INVALID_DIRECTION: u8 = 0x07;
const AVRCP_STATUS_NOT_DIRECTORY: u8 = 0x08;
const AVRCP_STATUS_DOES_NOT_EXIST: u8 = 0x09;
const AVRCP_STATUS_INVALID_SCOPE: u8 = 0x0a;
const AVRCP_STATUS_OUT_OF_BOUNDS: u8 = 0x0b;
const AVRCP_STATUS_IS_DIRECTORY: u8 = 0x0c;
const AVRCP_STATUS_MEDIA_IN_USE: u8 = 0x0d;
const AVRCP_STATUS_NOW_PLAYING_LIST_FULL: u8 = 0x0e;
const AVRCP_STATUS_SEARCH_NOT_SUPPORTED: u8 = 0x0f;
const AVRCP_STATUS_SEARCH_IN_PROGRESS: u8 = 0x10;
const AVRCP_STATUS_INVALID_PLAYER_ID: u8 = 0x11;
const AVRCP_STATUS_PLAYER_NOT_BROWSABLE: u8 = 0x12;
const AVRCP_STATUS_PLAYER_NOT_ADDRESSED: u8 = 0x13;
const AVRCP_STATUS_NO_VALID_SEARCH_RESULTS: u8 = 0x14;
const AVRCP_STATUS_NO_AVAILABLE_PLAYERS: u8 = 0x15;
const AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED: u8 = 0x16;

// ============================================================================
// AVRCP PDU IDs (avctp.c lines 110–135)
// ============================================================================

const AVRCP_GET_CAPABILITIES: u8 = 0x10;
const AVRCP_LIST_PLAYER_ATTRIBUTES: u8 = 0x11;
const AVRCP_LIST_PLAYER_VALUES: u8 = 0x12;
const AVRCP_GET_CURRENT_PLAYER_VALUE: u8 = 0x13;
const AVRCP_SET_PLAYER_VALUE: u8 = 0x14;
const AVRCP_GET_PLAYER_ATTRIBUTE_TEXT: u8 = 0x15;
const AVRCP_GET_PLAYER_VALUE_TEXT: u8 = 0x16;
const AVRCP_DISPLAYABLE_CHARSET: u8 = 0x17;
const AVRCP_CT_BATTERY_STATUS: u8 = 0x18;
const AVRCP_GET_ELEMENT_ATTRIBUTES: u8 = 0x20;
const AVRCP_GET_PLAY_STATUS: u8 = 0x30;
const AVRCP_REGISTER_NOTIFICATION: u8 = 0x31;
const AVRCP_REQUEST_CONTINUING: u8 = 0x40;
const AVRCP_ABORT_CONTINUING: u8 = 0x41;
const AVRCP_SET_ABSOLUTE_VOLUME: u8 = 0x50;
const AVRCP_SET_ADDRESSED_PLAYER: u8 = 0x60;
const AVRCP_SET_BROWSED_PLAYER: u8 = 0x70;
const AVRCP_GET_FOLDER_ITEMS: u8 = 0x71;
const AVRCP_CHANGE_PATH: u8 = 0x72;
const AVRCP_GET_ITEM_ATTRIBUTES: u8 = 0x73;
const AVRCP_PLAY_ITEM: u8 = 0x74;
const AVRCP_GET_TOTAL_NUMBER_OF_ITEMS: u8 = 0x75;
const AVRCP_SEARCH: u8 = 0x80;
const AVRCP_ADD_TO_NOW_PLAYING: u8 = 0x90;
const AVRCP_GENERAL_REJECT: u8 = 0xA0;

// ============================================================================
// AVRCP packet types (avctp.c lines 137–141)
// ============================================================================

const AVRCP_PACKET_TYPE_SINGLE: u8 = 0x00;
const AVRCP_PACKET_TYPE_START: u8 = 0x01;
const AVRCP_PACKET_TYPE_CONTINUING: u8 = 0x02;
const AVRCP_PACKET_TYPE_END: u8 = 0x03;

// ============================================================================
// Player attributes (avctp.c lines 143–148)
// ============================================================================

const AVRCP_ATTRIBUTE_ILEGAL: u8 = 0x00;
const AVRCP_ATTRIBUTE_EQUALIZER: u8 = 0x01;
const AVRCP_ATTRIBUTE_REPEAT_MODE: u8 = 0x02;
const AVRCP_ATTRIBUTE_SHUFFLE: u8 = 0x03;
const AVRCP_ATTRIBUTE_SCAN: u8 = 0x04;

// ============================================================================
// Media attributes (avctp.c lines 150–159)
// ============================================================================

const AVRCP_MEDIA_ATTRIBUTE_ILLEGAL: u32 = 0x00;
const AVRCP_MEDIA_ATTRIBUTE_TITLE: u32 = 0x01;
const AVRCP_MEDIA_ATTRIBUTE_ARTIST: u32 = 0x02;
const AVRCP_MEDIA_ATTRIBUTE_ALBUM: u32 = 0x03;
const AVRCP_MEDIA_ATTRIBUTE_TRACK: u32 = 0x04;
const AVRCP_MEDIA_ATTRIBUTE_TOTAL: u32 = 0x05;
const AVRCP_MEDIA_ATTRIBUTE_GENRE: u32 = 0x06;
const AVRCP_MEDIA_ATTRIBUTE_DURATION: u32 = 0x07;
const AVRCP_MEDIA_ATTRIBUTE_IMG_HANDLE: u32 = 0x08;

// ============================================================================
// Play status (avctp.c lines 161–167)
// ============================================================================

const AVRCP_PLAY_STATUS_STOPPED: u8 = 0x00;
const AVRCP_PLAY_STATUS_PLAYING: u8 = 0x01;
const AVRCP_PLAY_STATUS_PAUSED: u8 = 0x02;
const AVRCP_PLAY_STATUS_FWD_SEEK: u8 = 0x03;
const AVRCP_PLAY_STATUS_REV_SEEK: u8 = 0x04;
const AVRCP_PLAY_STATUS_ERROR: u8 = 0xFF;

// ============================================================================
// Media scope (avctp.c lines 169–173)
// ============================================================================

const AVRCP_MEDIA_PLAYER_LIST: u8 = 0x00;
const AVRCP_MEDIA_PLAYER_VFS: u8 = 0x01;
const AVRCP_MEDIA_SEARCH: u8 = 0x02;
const AVRCP_MEDIA_NOW_PLAYING: u8 = 0x03;

// ============================================================================
// Media item types (avctp.c lines 175–178)
// ============================================================================

const AVRCP_MEDIA_PLAYER_ITEM_TYPE: u8 = 0x01;
const AVRCP_FOLDER_ITEM_TYPE: u8 = 0x02;
const AVRCP_MEDIA_ELEMENT_ITEM_TYPE: u8 = 0x03;

// ============================================================================
// Panel pass-through operands (avctp.c lines 180–192)
// ============================================================================

const AVC_PANEL_VOLUME_UP: u8 = 0x41;
const AVC_PANEL_VOLUME_DOWN: u8 = 0x42;
const AVC_PANEL_MUTE: u8 = 0x43;
const AVC_PANEL_PLAY: u8 = 0x44;
const AVC_PANEL_STOP: u8 = 0x45;
const AVC_PANEL_PAUSE: u8 = 0x46;
const AVC_PANEL_RECORD: u8 = 0x47;
const AVC_PANEL_REWIND: u8 = 0x48;
const AVC_PANEL_FAST_FORWARD: u8 = 0x49;
const AVC_PANEL_EJECT: u8 = 0x4a;
const AVC_PANEL_FORWARD: u8 = 0x4b;
const AVC_PANEL_BACKWARD: u8 = 0x4c;

// ============================================================================
// Internal structs
// ============================================================================

/// Internal AVCTP frame with parsed header fields.
struct AvctpFrame {
    hdr: u8,
    pt: u8,
    l2cap_frame: L2capFrame,
}

/// Continuation state for fragmented AVRCP element attribute responses.
#[derive(Clone, Copy, Default)]
struct AvrcpContinuing {
    num: u16,
    size: u16,
}

thread_local! {
    static AVRCP_CONTINUING: RefCell<AvrcpContinuing> =
        const { RefCell::new(AvrcpContinuing { num: 0, size: 0 }) };
    /// Static attribute for list_player_values request/response correlation.
    static LIST_PLAYER_VALUES_ATTR: RefCell<u8> = const { RefCell::new(0) };
    /// Static attribute for get_player_value_text request/response correlation.
    static GET_PLAYER_VALUE_TEXT_ATTR: RefCell<u8> = const { RefCell::new(0) };
}

// ============================================================================
// Helper functions
// ============================================================================

/// Produce a padding string equivalent to C's `printf("%*c", width, ' ')`.
///
/// For the space character, this produces `max(1, |width|)` spaces, matching
/// C behavior where `%*c` with negative width causes left-justification.
fn pad(width: i32) -> String {
    let n = std::cmp::max(1, width.unsigned_abs() as usize);
    " ".repeat(n)
}

/// Check if a byte is printable (matching C `isprint()`).
fn is_printable(c: u8) -> bool {
    (0x20..=0x7e).contains(&c)
}

/// Print a string of bytes, replacing non-printable chars with '.'.
fn print_string_bytes(frame: &mut L2capFrame, len: u16) -> bool {
    for _ in 0..len {
        let c = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print!("{}", if is_printable(c) { c as char } else { '.' });
    }
    println!();
    true
}

// ============================================================================
// String lookup functions (avctp.c lines 206–777)
// ============================================================================

fn ctype2str(ctype: u8) -> &'static str {
    match ctype & 0x0f {
        AVC_CTYPE_CONTROL => "Control",
        AVC_CTYPE_STATUS => "Status",
        AVC_CTYPE_SPECIFIC_INQUIRY => "Specific Inquiry",
        AVC_CTYPE_NOTIFY => "Notify",
        AVC_CTYPE_GENERAL_INQUIRY => "General Inquiry",
        AVC_CTYPE_NOT_IMPLEMENTED => "Not Implemented",
        AVC_CTYPE_ACCEPTED => "Accepted",
        AVC_CTYPE_REJECTED => "Rejected",
        AVC_CTYPE_IN_TRANSITION => "In Transition",
        AVC_CTYPE_STABLE => "Stable",
        AVC_CTYPE_CHANGED => "Changed",
        AVC_CTYPE_INTERIM => "Interim",
        _ => "Unknown",
    }
}

fn subunit2str(subunit: u8) -> &'static str {
    match subunit {
        AVC_SUBUNIT_MONITOR => "Monitor",
        AVC_SUBUNIT_AUDIO => "Audio",
        AVC_SUBUNIT_PRINTER => "Printer",
        AVC_SUBUNIT_DISC => "Disc",
        AVC_SUBUNIT_TAPE => "Tape",
        AVC_SUBUNIT_TUNER => "Tuner",
        AVC_SUBUNIT_CA => "CA",
        AVC_SUBUNIT_CAMERA => "Camera",
        AVC_SUBUNIT_PANEL => "Panel",
        AVC_SUBUNIT_BULLETIN_BOARD => "Bulletin Board",
        AVC_SUBUNIT_CAMERA_STORAGE => "Camera Storage",
        AVC_SUBUNIT_VENDOR_UNIQUE => "Vendor Unique",
        AVC_SUBUNIT_EXTENDED => "Extended to next byte",
        AVC_SUBUNIT_UNIT => "Unit",
        _ => "Reserved",
    }
}

fn opcode2str(opcode: u8) -> &'static str {
    match opcode {
        AVC_OP_VENDORDEP => "Vendor Dependent",
        AVC_OP_UNITINFO => "Unit Info",
        AVC_OP_SUBUNITINFO => "Subunit Info",
        AVC_OP_PASSTHROUGH => "Passthrough",
        _ => "Unknown",
    }
}

fn cap2str(cap: u8) -> &'static str {
    match cap {
        0x2 => "CompanyID",
        0x3 => "EventsID",
        _ => "Unknown",
    }
}

fn event2str(event: u8) -> &'static str {
    match event {
        AVRCP_EVENT_PLAYBACK_STATUS_CHANGED => "EVENT_PLAYBACK_STATUS_CHANGED",
        AVRCP_EVENT_TRACK_CHANGED => "EVENT_TRACK_CHANGED",
        AVRCP_EVENT_TRACK_REACHED_END => "EVENT_TRACK_REACHED_END",
        AVRCP_EVENT_TRACK_REACHED_START => "EVENT_TRACK_REACHED_START",
        AVRCP_EVENT_PLAYBACK_POS_CHANGED => "EVENT_PLAYBACK_POS_CHANGED",
        AVRCP_EVENT_BATT_STATUS_CHANGED => "EVENT_BATT_STATUS_CHANGED",
        AVRCP_EVENT_SYSTEM_STATUS_CHANGED => "EVENT_SYSTEM_STATUS_CHANGED",
        AVRCP_EVENT_PLAYER_APPLICATION_SETTING_CHANGED => {
            "EVENT_PLAYER_APPLICATION_SETTING_CHANGED"
        }
        AVRCP_EVENT_NOW_PLAYING_CONTENT_CHANGED => "EVENT_NOW_PLAYING_CONTENT_CHANGED",
        AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED => "EVENT_AVAILABLE_PLAYERS_CHANGED",
        AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED => "EVENT_ADDRESSED_PLAYER_CHANGED",
        AVRCP_EVENT_UIDS_CHANGED => "EVENT_UIDS_CHANGED",
        AVRCP_EVENT_VOLUME_CHANGED => "EVENT_VOLUME_CHANGED",
        _ => "Reserved",
    }
}

fn error2str(status: u8) -> &'static str {
    match status {
        AVRCP_STATUS_INVALID_COMMAND => "Invalid Command",
        AVRCP_STATUS_INVALID_PARAMETER => "Invalid Parameter",
        AVRCP_STATUS_NOT_FOUND => "Not Found",
        AVRCP_STATUS_INTERNAL_ERROR => "Internal Error",
        AVRCP_STATUS_SUCCESS => "Success",
        AVRCP_STATUS_UID_CHANGED => "UID Changed",
        AVRCP_STATUS_INVALID_DIRECTION => "Invalid Direction",
        AVRCP_STATUS_NOT_DIRECTORY => "Not a Directory",
        AVRCP_STATUS_DOES_NOT_EXIST => "Does Not Exist",
        AVRCP_STATUS_INVALID_SCOPE => "Invalid Scope",
        AVRCP_STATUS_OUT_OF_BOUNDS => "Range Out of Bounds",
        AVRCP_STATUS_IS_DIRECTORY => "UID is a Directory",
        AVRCP_STATUS_MEDIA_IN_USE => "Media in Use",
        AVRCP_STATUS_NOW_PLAYING_LIST_FULL => "Now Playing List Full",
        AVRCP_STATUS_SEARCH_NOT_SUPPORTED => "Search Not Supported",
        AVRCP_STATUS_SEARCH_IN_PROGRESS => "Search in Progress",
        AVRCP_STATUS_INVALID_PLAYER_ID => "Invalid Player ID",
        AVRCP_STATUS_PLAYER_NOT_BROWSABLE => "Player Not Browsable",
        AVRCP_STATUS_PLAYER_NOT_ADDRESSED => "Player Not Addressed",
        AVRCP_STATUS_NO_VALID_SEARCH_RESULTS => "No Valid Search Result",
        AVRCP_STATUS_NO_AVAILABLE_PLAYERS => "No Available Players",
        AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED => "Addressed Player Changed",
        _ => "Unknown",
    }
}

fn pdu2str(pduid: u8) -> &'static str {
    match pduid {
        AVRCP_GET_CAPABILITIES => "GetCapabilities",
        AVRCP_LIST_PLAYER_ATTRIBUTES => "ListPlayerApplicationSettingAttributes",
        AVRCP_LIST_PLAYER_VALUES => "ListPlayerApplicationSettingValues",
        AVRCP_GET_CURRENT_PLAYER_VALUE => "GetCurrentPlayerApplicationSettingValue",
        AVRCP_SET_PLAYER_VALUE => "SetPlayerApplicationSettingValue",
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT => "GetPlayerApplicationSettingAttributeText",
        AVRCP_GET_PLAYER_VALUE_TEXT => "GetPlayerApplicationSettingValueText",
        AVRCP_DISPLAYABLE_CHARSET => "InformDisplayableCharacterSet",
        AVRCP_CT_BATTERY_STATUS => "InformBatteryStatusOfCT",
        AVRCP_GET_ELEMENT_ATTRIBUTES => "GetElementAttributes",
        AVRCP_GET_PLAY_STATUS => "GetPlayStatus",
        AVRCP_REGISTER_NOTIFICATION => "RegisterNotification",
        AVRCP_REQUEST_CONTINUING => "RequestContinuingResponse",
        AVRCP_ABORT_CONTINUING => "AbortContinuingResponse",
        AVRCP_SET_ABSOLUTE_VOLUME => "SetAbsoluteVolume",
        AVRCP_SET_ADDRESSED_PLAYER => "SetAddressedPlayer",
        AVRCP_SET_BROWSED_PLAYER => "SetBrowsedPlayer",
        AVRCP_GET_FOLDER_ITEMS => "GetFolderItems",
        AVRCP_CHANGE_PATH => "ChangePath",
        AVRCP_GET_ITEM_ATTRIBUTES => "GetItemAttributes",
        AVRCP_PLAY_ITEM => "PlayItem",
        AVRCP_GET_TOTAL_NUMBER_OF_ITEMS => "GetTotalNumOfItems",
        AVRCP_SEARCH => "Search",
        AVRCP_ADD_TO_NOW_PLAYING => "AddToNowPlaying",
        AVRCP_GENERAL_REJECT => "GeneralReject",
        _ => "Unknown",
    }
}

fn pt2str(pt: u8) -> &'static str {
    match pt {
        AVRCP_PACKET_TYPE_SINGLE => "Single",
        AVRCP_PACKET_TYPE_START => "Start",
        AVRCP_PACKET_TYPE_CONTINUING => "Continuing",
        AVRCP_PACKET_TYPE_END => "End",
        _ => "Unknown",
    }
}

fn attr2str(attr: u8) -> &'static str {
    match attr {
        AVRCP_ATTRIBUTE_ILEGAL => "Illegal",
        AVRCP_ATTRIBUTE_EQUALIZER => "Equalizer ON/OFF Status",
        AVRCP_ATTRIBUTE_REPEAT_MODE => "Repeat Mode Status",
        AVRCP_ATTRIBUTE_SHUFFLE => "Shuffle ON/OFF Status",
        AVRCP_ATTRIBUTE_SCAN => "Scan ON/OFF Status",
        _ => "Unknown",
    }
}

fn value2str(attr: u8, value: u8) -> &'static str {
    match attr {
        AVRCP_ATTRIBUTE_ILEGAL => "Illegal",
        AVRCP_ATTRIBUTE_EQUALIZER => match value {
            0x01 => "OFF",
            0x02 => "ON",
            _ => "Reserved",
        },
        AVRCP_ATTRIBUTE_REPEAT_MODE => match value {
            0x01 => "OFF",
            0x02 => "Single Track Repeat",
            0x03 => "All Track Repeat",
            0x04 => "Group Repeat",
            _ => "Reserved",
        },
        AVRCP_ATTRIBUTE_SHUFFLE => match value {
            0x01 => "OFF",
            0x02 => "All Track Shuffle",
            0x03 => "Group Shuffle",
            _ => "Reserved",
        },
        AVRCP_ATTRIBUTE_SCAN => match value {
            0x01 => "OFF",
            0x02 => "All Track Scan",
            0x03 => "Group Scan",
            _ => "Reserved",
        },
        _ => "Unknown",
    }
}

fn charset2str(charset: u16) -> &'static str {
    match charset {
        1 | 2 => "Reserved",
        3 => "ASCII",
        4 => "ISO_8859-1",
        5 => "ISO_8859-2",
        6 => "ISO_8859-3",
        7 => "ISO_8859-4",
        8 => "ISO_8859-5",
        9 => "ISO_8859-6",
        10 => "ISO_8859-7",
        11 => "ISO_8859-8",
        12 => "ISO_8859-9",
        106 => "UTF-8",
        _ => "Unknown",
    }
}

fn mediattr2str(attr: u32) -> &'static str {
    match attr {
        AVRCP_MEDIA_ATTRIBUTE_ILLEGAL => "Illegal",
        AVRCP_MEDIA_ATTRIBUTE_TITLE => "Title",
        AVRCP_MEDIA_ATTRIBUTE_ARTIST => "Artist",
        AVRCP_MEDIA_ATTRIBUTE_ALBUM => "Album",
        AVRCP_MEDIA_ATTRIBUTE_TRACK => "Track",
        AVRCP_MEDIA_ATTRIBUTE_TOTAL => "Track Total",
        AVRCP_MEDIA_ATTRIBUTE_GENRE => "Genre",
        AVRCP_MEDIA_ATTRIBUTE_DURATION => "Track duration",
        AVRCP_MEDIA_ATTRIBUTE_IMG_HANDLE => "Imaging handle",
        _ => "Reserved",
    }
}

fn playstatus2str(status: u8) -> &'static str {
    match status {
        AVRCP_PLAY_STATUS_STOPPED => "STOPPED",
        AVRCP_PLAY_STATUS_PLAYING => "PLAYING",
        AVRCP_PLAY_STATUS_PAUSED => "PAUSED",
        AVRCP_PLAY_STATUS_FWD_SEEK => "FWD_SEEK",
        AVRCP_PLAY_STATUS_REV_SEEK => "REV_SEEK",
        AVRCP_PLAY_STATUS_ERROR => "ERROR",
        _ => "Unknown",
    }
}

fn status2str(status: u8) -> &'static str {
    match status {
        0x0 => "NORMAL",
        0x1 => "WARNING",
        0x2 => "CRITICAL",
        0x3 => "EXTERNAL",
        0x4 => "FULL_CHARGE",
        _ => "Reserved",
    }
}

fn scope2str(scope: u8) -> &'static str {
    match scope {
        AVRCP_MEDIA_PLAYER_LIST => "Media Player List",
        AVRCP_MEDIA_PLAYER_VFS => "Media Player Virtual Filesystem",
        AVRCP_MEDIA_SEARCH => "Search",
        AVRCP_MEDIA_NOW_PLAYING => "Now Playing",
        _ => "Unknown",
    }
}

fn op2str(op: u8) -> &'static str {
    match op & 0x7f {
        AVC_PANEL_VOLUME_UP => "VOLUME UP",
        AVC_PANEL_VOLUME_DOWN => "VOLUME DOWN",
        AVC_PANEL_MUTE => "MUTE",
        AVC_PANEL_PLAY => "PLAY",
        AVC_PANEL_STOP => "STOP",
        AVC_PANEL_PAUSE => "PAUSE",
        AVC_PANEL_RECORD => "RECORD",
        AVC_PANEL_REWIND => "REWIND",
        AVC_PANEL_FAST_FORWARD => "FAST FORWARD",
        AVC_PANEL_EJECT => "EJECT",
        AVC_PANEL_FORWARD => "FORWARD",
        AVC_PANEL_BACKWARD => "BACKWARD",
        _ => "UNKNOWN",
    }
}

fn type2str(t: u8) -> &'static str {
    match t {
        AVRCP_MEDIA_PLAYER_ITEM_TYPE => "Media Player",
        AVRCP_FOLDER_ITEM_TYPE => "Folder",
        AVRCP_MEDIA_ELEMENT_ITEM_TYPE => "Media Element",
        _ => "Unknown",
    }
}

fn playertype2str(t: u8) -> &'static str {
    match t & 0x0F {
        0x01 => "Audio",
        0x02 => "Video",
        0x03 => "Audio, Video",
        0x04 => "Audio Broadcasting",
        0x05 => "Audio, Audio Broadcasting",
        0x06 => "Video, Audio Broadcasting",
        0x07 => "Audio, Video, Audio Broadcasting",
        0x08 => "Video Broadcasting",
        0x09 => "Audio, Video Broadcasting",
        0x0A => "Video, Video Broadcasting",
        0x0B => "Audio, Video, Video Broadcasting",
        0x0C => "Audio Broadcasting, Video Broadcasting",
        0x0D => "Audio, Audio Broadcasting, Video Broadcasting",
        0x0E => "Video, Audio Broadcasting, Video Broadcasting",
        0x0F => "Audio, Video, Audio Broadcasting, Video Broadcasting",
        _ => "None",
    }
}

fn playersubtype2str(subtype: u32) -> &'static str {
    match subtype & 0x03 {
        0x01 => "Audio Book",
        0x02 => "Podcast",
        0x03 => "Audio Book, Podcast",
        _ => "None",
    }
}

fn foldertype2str(t: u8) -> &'static str {
    match t {
        0x00 => "Mixed",
        0x01 => "Titles",
        0x02 => "Albums",
        0x03 => "Artists",
        0x04 => "Genres",
        0x05 => "Playlists",
        0x06 => "Years",
        _ => "Reserved",
    }
}

fn elementtype2str(t: u8) -> &'static str {
    match t {
        0x00 => "Audio",
        0x01 => "Video",
        _ => "Reserved",
    }
}

fn dir2str(dir: u8) -> &'static str {
    match dir {
        0x00 => "Folder Up",
        0x01 => "Folder Down",
        _ => "Reserved",
    }
}

// ============================================================================
// Control channel AVRCP PDU handlers (avctp.c lines 779–1606)
// ============================================================================

fn avrcp_passthrough_packet(avctp_frame: &mut AvctpFrame, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let op = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!(
        "{}Operation: 0x{:02x} ({} {})",
        pad(indent - 8),
        op,
        op2str(op),
        if op & 0x80 != 0 { "Released" } else { "Pressed" }
    );

    let len = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{}Length: 0x{:02x}", pad(indent - 8), len);

    print_hexdump(frame.remaining_data());
    true
}

fn avrcp_get_capabilities(avctp_frame: &mut AvctpFrame, _ctype: u8, len: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let cap = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{}CapabilityID: 0x{:02x} ({})", pad(indent - 8), cap, cap2str(cap));

    if len == 1 {
        return true;
    }

    let count = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{}CapabilityCount: 0x{:02x}", pad(indent - 8), count);

    match cap {
        0x2 => {
            for _ in 0..count {
                let c0 = match frame.get_u8() {
                    Some(v) => v,
                    None => return false,
                };
                let c1 = match frame.get_u8() {
                    Some(v) => v,
                    None => return false,
                };
                let c2 = match frame.get_u8() {
                    Some(v) => v,
                    None => return false,
                };
                print_field!(
                    "{}{}: 0x{:02x}{:02x}{:02x}",
                    pad(indent - 8),
                    cap2str(cap),
                    c0,
                    c1,
                    c2
                );
            }
        }
        0x3 => {
            for _ in 0..count {
                let event = match frame.get_u8() {
                    Some(v) => v,
                    None => return false,
                };
                print_field!(
                    "{}{}: 0x{:02x} ({})",
                    pad(indent - 8),
                    cap2str(cap),
                    event,
                    event2str(event)
                );
            }
        }
        _ => {
            print_hexdump(frame.remaining_data());
        }
    }

    true
}

fn avrcp_list_player_attributes(
    avctp_frame: &mut AvctpFrame,
    _ctype: u8,
    len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if len == 0 {
        return true;
    }

    let num = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), num);

    for _ in 0..num {
        let attr = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));
    }

    true
}

fn avrcp_list_player_values(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        // Response path
        let attr_val = LIST_PLAYER_VALUES_ATTR.with(|a| *a.borrow());

        let num = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}ValueCount: 0x{:02x}", pad(indent - 8), num);

        for _ in 0..num {
            let value = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!(
                "{}ValueID: 0x{:02x} ({})",
                pad(indent - 8),
                value,
                value2str(attr_val, value)
            );
        }
        return true;
    }

    // Command path
    let attr = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    LIST_PLAYER_VALUES_ATTR.with(|a| *a.borrow_mut() = attr);

    print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));

    true
}

fn avrcp_get_current_player_value(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    let num = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        // Response
        print_field!("{}ValueCount: 0x{:02x}", pad(indent - 8), num);

        for _ in 0..num {
            let attr = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));
            let value = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!(
                "{}ValueID: 0x{:02x} ({})",
                pad(indent - 8),
                value,
                value2str(attr, value)
            );
        }
        return true;
    }

    // Command
    print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), num);

    for _ in 0..num {
        let attr = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));
    }

    true
}

fn avrcp_set_player_value(avctp_frame: &mut AvctpFrame, ctype: u8, _len: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        return true;
    }

    let num = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), num);

    for _ in 0..num {
        let attr = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));
        let value = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}ValueID: 0x{:02x} ({})", pad(indent - 8), value, value2str(attr, value));
    }

    true
}

fn avrcp_get_player_attribute_text(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    let num = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), num);

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        // Response
        for _ in 0..num {
            let attr = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));
            let charset = match frame.get_be16() {
                Some(v) => v,
                None => return false,
            };
            print_field!(
                "{}CharsetID: 0x{:04x} ({})",
                pad(indent - 8),
                charset,
                charset2str(charset)
            );
            let str_len = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}StringLength: 0x{:02x}", pad(indent - 8), str_len);

            print!("String: ");
            if !print_string_bytes(frame, u16::from(str_len)) {
                return false;
            }
        }
        return true;
    }

    // Command
    for _ in 0..num {
        let attr = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));
    }

    true
}

fn avrcp_get_player_value_text(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        // Response
        let attr_val = GET_PLAYER_VALUE_TEXT_ATTR.with(|a| *a.borrow());

        let num = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}ValueCount: 0x{:02x}", pad(indent - 8), num);

        for _ in 0..num {
            let value = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!(
                "{}ValueID: 0x{:02x} ({})",
                pad(indent - 8),
                value,
                value2str(attr_val, value)
            );
            let charset = match frame.get_be16() {
                Some(v) => v,
                None => return false,
            };
            // Note: "CharsetIDID" is the original C typo — must reproduce
            print_field!(
                "{}CharsetIDID: 0x{:02x} ({})",
                pad(indent - 8),
                charset,
                charset2str(charset)
            );
            let str_len = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}StringLength: 0x{:02x}", pad(indent - 8), str_len);

            print!("String: ");
            if !print_string_bytes(frame, u16::from(str_len)) {
                return false;
            }
        }
        return true;
    }

    // Command
    let attr = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    GET_PLAYER_VALUE_TEXT_ATTR.with(|a| *a.borrow_mut() = attr);

    print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));

    let num = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}ValueCount: 0x{:02x}", pad(indent - 8), num);

    for _ in 0..num {
        let value = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}ValueID: 0x{:02x} ({})", pad(indent - 8), value, value2str(attr, value));
    }

    true
}

fn avrcp_displayable_charset(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        return true;
    }

    let num = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!("{}CharsetCount: 0x{:02x}", pad(indent - 8), num);

    for _ in 0..num {
        let charset = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));
    }

    true
}

fn avrcp_get_element_attributes(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype <= AVC_CTYPE_GENERAL_INQUIRY {
        // Command path
        let id = match frame.get_be64() {
            Some(v) => v,
            None => return false,
        };

        print_field!(
            "{}Identifier: 0x{:x} ({})",
            pad(indent - 8),
            id,
            if id != 0 { "Reserved" } else { "PLAYING" }
        );

        let num = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), num);

        for _ in 0..num {
            let attr = match frame.get_be32() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}AttributeID: 0x{:08x} ({})", pad(indent - 8), attr, mediattr2str(attr));
        }
        return true;
    }

    // Response path — handles continuation
    let pt = avctp_frame.pt;
    let frame = &mut avctp_frame.l2cap_frame;
    let mut remaining_len = len;
    let mut num: u16;

    match pt {
        AVRCP_PACKET_TYPE_SINGLE | AVRCP_PACKET_TYPE_START => {
            let n = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            num = u16::from(n);

            AVRCP_CONTINUING.with(|c| c.borrow_mut().num = num);
            print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), n);
            remaining_len = remaining_len.wrapping_sub(1);
        }
        AVRCP_PACKET_TYPE_CONTINUING | AVRCP_PACKET_TYPE_END => {
            num = AVRCP_CONTINUING.with(|c| c.borrow().num);
            print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), num as u8);

            let cont_size = AVRCP_CONTINUING.with(|c| c.borrow().size);
            if cont_size > 0 {
                let size = if cont_size > remaining_len {
                    AVRCP_CONTINUING.with(|c| {
                        c.borrow_mut().size -= remaining_len;
                    });
                    remaining_len
                } else {
                    AVRCP_CONTINUING.with(|c| c.borrow_mut().size = 0);
                    cont_size
                };

                let mut attrval = String::new();
                for _ in 0..size {
                    let c = match frame.get_u8() {
                        Some(v) => v,
                        None => {
                            AVRCP_CONTINUING.with(|c| {
                                let mut cont = c.borrow_mut();
                                cont.num = 0;
                                cont.size = 0;
                            });
                            return false;
                        }
                    };
                    if is_printable(c) {
                        attrval.push(c as char);
                    } else {
                        attrval.push('.');
                    }
                }
                print_field!("{}ContinuingAttributeValue: {}", pad(indent - 8), attrval);
                remaining_len = remaining_len.wrapping_sub(size);
            }
        }
        _ => {
            AVRCP_CONTINUING.with(|c| {
                let mut cont = c.borrow_mut();
                cont.num = 0;
                cont.size = 0;
            });
            return false;
        }
    }

    while num > 0 && remaining_len > 0 {
        let attr = match frame.get_be32() {
            Some(v) => v,
            None => {
                AVRCP_CONTINUING.with(|c| {
                    let mut cont = c.borrow_mut();
                    cont.num = 0;
                    cont.size = 0;
                });
                return false;
            }
        };
        print_field!("{}Attribute: 0x{:08x} ({})", pad(indent - 8), attr, mediattr2str(attr));

        let charset = match frame.get_be16() {
            Some(v) => v,
            None => {
                AVRCP_CONTINUING.with(|c| {
                    let mut cont = c.borrow_mut();
                    cont.num = 0;
                    cont.size = 0;
                });
                return false;
            }
        };
        print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));

        let mut attrlen = match frame.get_be16() {
            Some(v) => v,
            None => {
                AVRCP_CONTINUING.with(|c| {
                    let mut cont = c.borrow_mut();
                    cont.num = 0;
                    cont.size = 0;
                });
                return false;
            }
        };
        print_field!("{}AttributeValueLength: 0x{:04x}", pad(indent - 8), attrlen);

        // sizeof(attr) + sizeof(charset) + sizeof(attrlen) = 4 + 2 + 2 = 8
        remaining_len = remaining_len.wrapping_sub(8);
        num -= 1;

        let mut attrval = String::new();
        while attrlen > 0 && remaining_len > 0 {
            let c = match frame.get_u8() {
                Some(v) => v,
                None => {
                    AVRCP_CONTINUING.with(|c| {
                        let mut cont = c.borrow_mut();
                        cont.num = 0;
                        cont.size = 0;
                    });
                    return false;
                }
            };
            if is_printable(c) {
                attrval.push(c as char);
            } else {
                attrval.push('.');
            }
            attrlen -= 1;
            remaining_len = remaining_len.wrapping_sub(1);
        }
        print_field!("{}AttributeValue: {}", pad(indent - 8), attrval);

        if attrlen > 0 {
            AVRCP_CONTINUING.with(|c| c.borrow_mut().size = attrlen);
        }
    }

    AVRCP_CONTINUING.with(|c| c.borrow_mut().num = num);
    true
}

fn avrcp_get_play_status(avctp_frame: &mut AvctpFrame, ctype: u8, _len: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype <= AVC_CTYPE_GENERAL_INQUIRY {
        return true;
    }

    let song_len = match frame.get_be32() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}SongLength: 0x{:08x} ({} milliseconds)", pad(indent - 8), song_len, song_len);

    let song_pos = match frame.get_be32() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}SongPosition: 0x{:08x} ({} milliseconds)", pad(indent - 8), song_pos, song_pos);

    let status = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}PlayStatus: 0x{:02x} ({})", pad(indent - 8), status, playstatus2str(status));

    true
}

fn avrcp_register_notification(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype <= AVC_CTYPE_GENERAL_INQUIRY {
        // Command
        let event = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}EventID: 0x{:02x} ({})", pad(indent - 8), event, event2str(event));

        let interval = match frame.get_be32() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Interval: 0x{:08x} ({} seconds)", pad(indent - 8), interval, interval);
        return true;
    }

    // Response
    let event = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}EventID: 0x{:02x} ({})", pad(indent - 8), event, event2str(event));

    match event {
        AVRCP_EVENT_PLAYBACK_STATUS_CHANGED => {
            let status = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!(
                "{}PlayStatus: 0x{:02x} ({})",
                pad(indent - 8),
                status,
                playstatus2str(status)
            );
        }
        AVRCP_EVENT_TRACK_CHANGED => {
            let id = match frame.get_be64() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}Identifier: 0x{:16x} ({})", pad(indent - 8), id, id);
        }
        AVRCP_EVENT_PLAYBACK_POS_CHANGED => {
            let interval = match frame.get_be32() {
                Some(v) => v,
                None => return false,
            };
            print_field!(
                "{}Position: 0x{:08x} ({} milliseconds)",
                pad(indent - 8),
                interval,
                interval
            );
        }
        AVRCP_EVENT_BATT_STATUS_CHANGED => {
            let status = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!(
                "{}BatteryStatus: 0x{:02x} ({})",
                pad(indent - 8),
                status,
                status2str(status)
            );
        }
        AVRCP_EVENT_SYSTEM_STATUS_CHANGED => {
            let status = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}SystemStatus: 0x{:02x} ", pad(indent - 8), status);
            match status {
                0x00 => println!("(POWER_ON)"),
                0x01 => println!("(POWER_OFF)"),
                0x02 => println!("(UNPLUGGED)"),
                _ => println!("(UNKNOWN)"),
            }
        }
        AVRCP_EVENT_PLAYER_APPLICATION_SETTING_CHANGED => {
            let count = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), count);

            for _ in 0..count {
                let attr = match frame.get_u8() {
                    Some(v) => v,
                    None => return false,
                };
                print_field!("{}AttributeID: 0x{:02x} ({})", pad(indent - 8), attr, attr2str(attr));

                let value = match frame.get_u8() {
                    Some(v) => v,
                    None => return false,
                };
                print_field!(
                    "{}ValueID: 0x{:02x} ({})",
                    pad(indent - 8),
                    value,
                    value2str(attr, value)
                );
            }
        }
        AVRCP_EVENT_VOLUME_CHANGED => {
            let mut status = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            status &= 0x7F;
            print_field!(
                "{}Volume: {:.2}% ({}/127)",
                pad(indent - 8),
                f64::from(status) / 1.27,
                status
            );
        }
        AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED => {
            let uid = match frame.get_be16() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}PlayerID: 0x{:04x} ({})", pad(indent - 8), uid, uid);
            let uid2 = match frame.get_be16() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uid2, uid2);
        }
        AVRCP_EVENT_UIDS_CHANGED => {
            let uid = match frame.get_be16() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uid, uid);
        }
        AVRCP_EVENT_TRACK_REACHED_END
        | AVRCP_EVENT_TRACK_REACHED_START
        | AVRCP_EVENT_NOW_PLAYING_CONTENT_CHANGED
        | AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED => {
            // No additional data
        }
        _ => {}
    }

    true
}

fn avrcp_set_absolute_volume(
    avctp_frame: &mut AvctpFrame,
    _ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    let mut value = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    value &= 0x7F;
    print_field!("{}Volume: {:.2}% ({}/127)", pad(indent - 8), f64::from(value) / 1.27, value);

    true
}

fn avrcp_set_addressed_player(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        // Response
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));
        return true;
    }

    // Command
    let id = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}PlayerID: 0x{:04x} ({})", pad(indent - 8), id, id);

    true
}

fn avrcp_play_item(avctp_frame: &mut AvctpFrame, ctype: u8, _len: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        // Response
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));
        return true;
    }

    // Command
    let scope = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Scope: 0x{:02x} ({})", pad(indent - 8), scope, scope2str(scope));

    let uid = match frame.get_be64() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UID: 0x{:16x} ({})", pad(indent - 8), uid, uid);

    let uidcounter = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

    true
}

fn avrcp_add_to_now_playing(
    avctp_frame: &mut AvctpFrame,
    ctype: u8,
    _len: u16,
    indent: i32,
) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    if ctype > AVC_CTYPE_GENERAL_INQUIRY {
        // Response
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));
        return true;
    }

    // Command
    let scope = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Scope: 0x{:02x} ({})", pad(indent - 8), scope, scope2str(scope));

    let uid = match frame.get_be64() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UID: 0x{:16x} ({})", pad(indent - 8), uid, uid);

    let uidcounter = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

    true
}

// ============================================================================
// Dispatch and routing functions (avctp.c lines 1632–1737)
// ============================================================================

fn avrcp_rejected_packet(avctp_frame: &mut AvctpFrame, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    let status = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

    true
}

fn avrcp_pdu_packet(avctp_frame: &mut AvctpFrame, ctype: u8, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;

    let pduid = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    let pt = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    let len = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    // Store packet type for continuation logic
    avctp_frame.pt = pt;

    print_indent!(
        indent,
        COLOR_OFF,
        "AVRCP",
        "",
        COLOR_OFF,
        " {}: pt {} len 0x{:04x}",
        pdu2str(pduid),
        pt2str(pt),
        len
    );

    if frame.size.wrapping_sub(frame.pos as u16) != len {
        print_text!(COLOR_ERROR, "PDU malformed");
        print_hexdump(frame.remaining_data());
        return false;
    }

    if ctype == AVC_CTYPE_REJECTED {
        return avrcp_rejected_packet(avctp_frame, indent + 2);
    }

    let inner_indent = indent + 2;

    match pduid {
        AVRCP_GET_CAPABILITIES => avrcp_get_capabilities(avctp_frame, ctype, len, inner_indent),
        AVRCP_LIST_PLAYER_ATTRIBUTES => {
            avrcp_list_player_attributes(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_LIST_PLAYER_VALUES => avrcp_list_player_values(avctp_frame, ctype, len, inner_indent),
        AVRCP_GET_CURRENT_PLAYER_VALUE => {
            avrcp_get_current_player_value(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_SET_PLAYER_VALUE => avrcp_set_player_value(avctp_frame, ctype, len, inner_indent),
        AVRCP_GET_PLAYER_ATTRIBUTE_TEXT => {
            avrcp_get_player_attribute_text(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_GET_PLAYER_VALUE_TEXT => {
            avrcp_get_player_value_text(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_DISPLAYABLE_CHARSET => {
            avrcp_displayable_charset(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_GET_ELEMENT_ATTRIBUTES => {
            avrcp_get_element_attributes(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_GET_PLAY_STATUS => avrcp_get_play_status(avctp_frame, ctype, len, inner_indent),
        AVRCP_REGISTER_NOTIFICATION => {
            avrcp_register_notification(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_SET_ABSOLUTE_VOLUME => {
            avrcp_set_absolute_volume(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_SET_ADDRESSED_PLAYER => {
            avrcp_set_addressed_player(avctp_frame, ctype, len, inner_indent)
        }
        AVRCP_PLAY_ITEM => avrcp_play_item(avctp_frame, ctype, len, inner_indent),
        AVRCP_ADD_TO_NOW_PLAYING => avrcp_add_to_now_playing(avctp_frame, ctype, len, inner_indent),
        _ => {
            print_hexdump(avctp_frame.l2cap_frame.remaining_data());
            true
        }
    }
}

fn avrcp_control_packet(avctp_frame: &mut AvctpFrame) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let indent: i32 = 2;

    let ctype = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    let address = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    let opcode = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };

    print_field!(
        "{}AV/C: {}: address 0x{:02x} opcode 0x{:02x}",
        pad(indent - 8),
        ctype2str(ctype),
        address,
        opcode
    );

    let subunit = (address >> 3) & 0x1f;
    print_field!("{}Subunit: {} ({})", pad(indent - 8), subunit, subunit2str(subunit));

    print_field!("{}Opcode: {} ({})", pad(indent - 8), opcode, opcode2str(opcode));

    // Non-Panel subunit — dump raw
    if subunit != 0x09 {
        print_hexdump(frame.remaining_data());
        return true;
    }

    // Not Implemented response — dump raw
    if ctype == AVC_CTYPE_NOT_IMPLEMENTED {
        print_hexdump(frame.remaining_data());
        return true;
    }

    match opcode {
        0x7c => {
            // Pass Through
            avrcp_passthrough_packet(avctp_frame, 10)
        }
        0x00 => {
            // Vendor Dependent
            let frame = &mut avctp_frame.l2cap_frame;
            let c0 = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            let c1 = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            let c2 = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}CompanyID: 0x{:02x}{:02x}{:02x}", pad(indent - 8), c0, c1, c2);
            avrcp_pdu_packet(avctp_frame, ctype, 10)
        }
        _ => {
            print_hexdump(avctp_frame.l2cap_frame.remaining_data());
            true
        }
    }
}

// ============================================================================
// Browsing channel handlers (avctp.c lines 1739-2444)
// ============================================================================

fn avrcp_change_path(avctp_frame: &mut AvctpFrame, size: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let is_response = (avctp_frame.hdr & 0x02) != 0;

    if is_response {
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

        if status != 0x04 {
            return true;
        }

        let items = match frame.get_be32() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Number of Items: 0x{:08x} ({})", pad(indent - 8), items, items);
        return true;
    }

    // Command
    if size < 11 {
        print_text!(COLOR_ERROR, "PDU malformed");
        print_hexdump(frame.remaining_data());
        return false;
    }

    let uidcounter = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

    let direction = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Direction: 0x{:02x} ({})", pad(indent - 8), direction, dir2str(direction));

    let folder_uid = match frame.get_be64() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}FolderUID: 0x{:16x} ({})", pad(indent - 8), folder_uid, folder_uid);

    true
}

struct FeatureEntry {
    bit: u8,
    name: &'static str,
}

static FEATURES_TABLE: &[FeatureEntry] = &[
    FeatureEntry { bit: 58, name: "Group Navigation" },
    FeatureEntry { bit: 59, name: "Browsing" },
    FeatureEntry { bit: 60, name: "Searching" },
    FeatureEntry { bit: 61, name: "AddToNowPlaying" },
    FeatureEntry { bit: 62, name: "UIDs unique" },
    FeatureEntry { bit: 63, name: "Only Browsable when Addressed" },
    FeatureEntry { bit: 64, name: "Only Searchable when Addressed" },
    FeatureEntry { bit: 65, name: "NowPlaying" },
    FeatureEntry { bit: 66, name: "UID Persistency" },
];

fn print_features(indent: i32, features: &[u8; 16]) {
    for bit in 0..=126u8 {
        let byte_idx = (bit / 8) as usize;
        let bit_pos = bit % 8;
        if byte_idx < 16 && (features[byte_idx] & (1 << bit_pos)) != 0 {
            let mut found = false;
            for entry in FEATURES_TABLE {
                if entry.bit == bit {
                    print_field!("{}{} ({})", pad(indent - 8), entry.name, bit);
                    found = true;
                    break;
                }
            }
            if !found {
                if bit > 66 {
                    print_text!(COLOR_WHITE_BG, "{}Unknown bit {} ", pad(indent - 8), bit);
                } else {
                    print_field!("{}Reserved ({})", pad(indent - 8), bit);
                }
            }
        }
    }
}

fn avrcp_media_player_item(frame: &mut L2capFrame, indent: i32) -> bool {
    let player_id = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}PlayerID: 0x{:04x} ({})", pad(indent - 8), player_id, player_id);

    let player_type = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!(
        "{}PlayerType: 0x{:02x} ({})",
        pad(indent - 8),
        player_type,
        playertype2str(player_type)
    );

    let player_subtype = match frame.get_be32() {
        Some(v) => v,
        None => return false,
    };
    print_field!(
        "{}PlayerSubType: 0x{:08x} ({})",
        pad(indent - 8),
        player_subtype,
        playersubtype2str(player_subtype)
    );

    let play_status = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!(
        "{}PlayStatus: 0x{:02x} ({})",
        pad(indent - 8),
        play_status,
        playstatus2str(play_status)
    );

    let mut features = [0u8; 16];
    for byte in &mut features {
        *byte = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
    }

    print!("{}Features: 0x", pad(indent));
    for b in &features {
        print!("{:02x}", b);
    }
    println!();

    print_features(indent, &features);

    let charset = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));

    let name_len = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}NameLength: 0x{:04x} ({})", pad(indent - 8), name_len, name_len);

    print!("{}Name: ", pad(indent));
    if !print_string_bytes(frame, name_len) {
        return false;
    }

    true
}

fn avrcp_folder_item(frame: &mut L2capFrame, _size: u16, indent: i32) -> bool {
    let uid = match frame.get_be64() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}FolderUID: 0x{:16x} ({})", pad(indent - 8), uid, uid);

    let folder_type = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!(
        "{}FolderType: 0x{:02x} ({})",
        pad(indent - 8),
        folder_type,
        foldertype2str(folder_type)
    );

    let is_playable = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!(
        "{}IsPlayable: 0x{:02x} ({})",
        pad(indent - 8),
        is_playable,
        if is_playable != 0 { "True" } else { "False" }
    );

    let charset = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));

    let name_len = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}NameLength: 0x{:04x} ({})", pad(indent - 8), name_len, name_len);

    print!("{}Name: ", pad(indent));
    if !print_string_bytes(frame, name_len) {
        return false;
    }

    true
}

fn avrcp_attribute_entry_list(frame: &mut L2capFrame, count: u8, indent: i32) -> bool {
    for _ in 0..count {
        let attr = match frame.get_be32() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Attribute: 0x{:08x} ({})", pad(indent - 8), attr, mediattr2str(attr));

        let charset = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));

        let vlen = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeValueLength: 0x{:04x}", pad(indent - 8), vlen);

        print!("{}AttributeValue: ", pad(indent));
        if !print_string_bytes(frame, vlen) {
            return false;
        }
    }

    true
}

fn avrcp_media_element_item(frame: &mut L2capFrame, indent: i32) -> bool {
    let uid = match frame.get_be64() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}ElementUID: 0x{:16x} ({})", pad(indent - 8), uid, uid);

    let etype = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}ElementType: 0x{:02x} ({})", pad(indent - 8), etype, elementtype2str(etype));

    let charset = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));

    let name_len = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}NameLength: 0x{:04x} ({})", pad(indent - 8), name_len, name_len);

    print!("{}Name: ", pad(indent));
    if !print_string_bytes(frame, name_len) {
        return false;
    }

    let attr_count = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), attr_count);

    avrcp_attribute_entry_list(frame, attr_count, indent)
}

fn avrcp_general_reject(avctp_frame: &mut AvctpFrame, _size: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let is_response = (avctp_frame.hdr & 0x02) != 0;

    if !is_response {
        print_text!(COLOR_ERROR, "PDU malformed");
        print_hexdump(frame.remaining_data());
        return true;
    }

    let status = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

    true
}

fn avrcp_get_total_number_of_items(avctp_frame: &mut AvctpFrame, size: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let is_response = (avctp_frame.hdr & 0x02) != 0;

    if is_response {
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

        if status != 0x04 {
            return true;
        }

        let uidcounter = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

        let items = match frame.get_be32() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Number of Items: 0x{:08x} ({})", pad(indent - 8), items, items);
        return true;
    }

    // Command — C uses indent-8 with indent=2 -> negative width -> pad handles it
    if size < 4 {
        print_text!(COLOR_ERROR, "PDU malformed");
        print_hexdump(frame.remaining_data());
        return false;
    }

    let scope = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Scope: 0x{:02x} ({})", pad(indent - 8), scope, scope2str(scope));

    true
}

fn avrcp_search_item(avctp_frame: &mut AvctpFrame, _size: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let is_response = (avctp_frame.hdr & 0x02) != 0;

    if is_response {
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

        if status != 0x04 {
            return true;
        }

        let uidcounter = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

        let items = match frame.get_be32() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Number of Items: 0x{:08x} ({})", pad(indent - 8), items, items);
        return true;
    }

    // Command
    let charset = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));

    let str_len = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Length: 0x{:04x} ({})", pad(indent - 8), str_len, str_len);

    print!("{}String: ", pad(indent));
    if !print_string_bytes(frame, str_len) {
        return false;
    }

    true
}

fn avrcp_get_item_attributes(avctp_frame: &mut AvctpFrame, size: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let is_response = (avctp_frame.hdr & 0x02) != 0;

    if is_response {
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

        if status != 0x04 {
            return true;
        }

        let count = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), count);

        return avrcp_attribute_entry_list(frame, count, indent);
    }

    // Command
    if size < 12 {
        print_text!(COLOR_ERROR, "PDU malformed");
        print_hexdump(frame.remaining_data());
        return false;
    }

    let scope = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Scope: 0x{:02x} ({})", pad(indent - 8), scope, scope2str(scope));

    let uid = match frame.get_be64() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UID: 0x{:016x} ({})", pad(indent - 8), uid, uid);

    let uidcounter = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

    let count = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), count);

    for _ in 0..count {
        let attr = match frame.get_be32() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeID: 0x{:08x} ({})", pad(indent - 8), attr, mediattr2str(attr));
    }

    true
}

fn avrcp_get_folder_items(avctp_frame: &mut AvctpFrame, size: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let is_response = (avctp_frame.hdr & 0x02) != 0;

    if is_response {
        let status = match frame.get_u8() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

        if status != 0x04 {
            return true;
        }

        let uidcounter = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

        let num_items = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Number of Items: 0x{:04x} ({})", pad(indent - 8), num_items, num_items);

        for _ in 0..num_items {
            let item_type = match frame.get_u8() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}Type: 0x{:02x} ({})", pad(indent - 8), item_type, type2str(item_type));

            let item_len = match frame.get_be16() {
                Some(v) => v,
                None => return false,
            };
            print_field!("{}Length: 0x{:04x} ({})", pad(indent - 8), item_len, item_len);

            match item_type {
                0x01 => {
                    if !avrcp_media_player_item(frame, indent) {
                        return false;
                    }
                }
                0x02 => {
                    if !avrcp_folder_item(frame, item_len, indent) {
                        return false;
                    }
                }
                0x03 => {
                    if !avrcp_media_element_item(frame, indent) {
                        return false;
                    }
                }
                _ => {
                    print_hexdump(frame.remaining_data());
                }
            }
        }
        return true;
    }

    // Command path
    let scope = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Scope: 0x{:02x} ({})", pad(indent - 8), scope, scope2str(scope));

    let start = match frame.get_be32() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}StartItem: 0x{:08x} ({})", pad(indent - 8), start, start);

    let end = match frame.get_be32() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}EndItem: 0x{:08x} ({})", pad(indent - 8), end, end);

    let count = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}AttributeCount: 0x{:02x}", pad(indent - 8), count);

    // C code returns false here (line 2322) — intentional
    if count == 0 && size > 10 {
        return false;
    }

    for _ in 0..count {
        let attr = match frame.get_be32() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}AttributeID: 0x{:08x} ({})", pad(indent - 8), attr, mediattr2str(attr));
    }

    false
}

fn avrcp_set_browsed_player(avctp_frame: &mut AvctpFrame, _size: u16, indent: i32) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let is_response = (avctp_frame.hdr & 0x02) != 0;

    if !is_response {
        let player_id = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}PlayerID: 0x{:04x} ({})", pad(indent - 8), player_id, player_id);
        return true;
    }

    // Response
    let status = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Status: 0x{:02x} ({})", pad(indent - 8), status, error2str(status));

    if status != 0x04 {
        return true;
    }

    let uidcounter = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}UIDCounter: 0x{:04x} ({})", pad(indent - 8), uidcounter, uidcounter);

    let num_items = match frame.get_be32() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Number of Items: 0x{:08x} ({})", pad(indent - 8), num_items, num_items);

    let charset = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}CharsetID: 0x{:04x} ({})", pad(indent - 8), charset, charset2str(charset));

    let folder_depth = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    print_field!("{}Folder Depth: 0x{:02x} ({})", pad(indent - 8), folder_depth, folder_depth);

    for _ in 0..folder_depth {
        let name_len = match frame.get_be16() {
            Some(v) => v,
            None => return false,
        };
        print_field!("{}Folder Name Length: 0x{:04x} ({})", pad(indent - 8), name_len, name_len);
        print!("{}Folder: ", pad(indent));
        if !print_string_bytes(frame, name_len) {
            return false;
        }
    }

    true
}

fn avrcp_browsing_packet(avctp_frame: &mut AvctpFrame) -> bool {
    let frame = &mut avctp_frame.l2cap_frame;
    let indent: i32 = 2;

    let pduid = match frame.get_u8() {
        Some(v) => v,
        None => return false,
    };
    let len = match frame.get_be16() {
        Some(v) => v,
        None => return false,
    };

    print_indent!(
        indent,
        COLOR_OFF,
        "AVRCP",
        "",
        COLOR_OFF,
        " {}: len 0x{:04x}",
        pdu2str(pduid),
        len
    );

    let inner_indent = indent + 2;

    match pduid {
        AVRCP_SET_BROWSED_PLAYER => avrcp_set_browsed_player(avctp_frame, len, inner_indent),
        AVRCP_GET_FOLDER_ITEMS => avrcp_get_folder_items(avctp_frame, len, inner_indent),
        AVRCP_CHANGE_PATH => avrcp_change_path(avctp_frame, len, inner_indent),
        AVRCP_GET_ITEM_ATTRIBUTES => avrcp_get_item_attributes(avctp_frame, len, inner_indent),
        AVRCP_SEARCH => avrcp_search_item(avctp_frame, len, inner_indent),
        AVRCP_GET_TOTAL_NUMBER_OF_ITEMS => {
            avrcp_get_total_number_of_items(avctp_frame, len, inner_indent)
        }
        AVRCP_GENERAL_REJECT => avrcp_general_reject(avctp_frame, len, inner_indent),
        _ => {
            print_hexdump(avctp_frame.l2cap_frame.remaining_data());
            true
        }
    }
}

// ============================================================================
// Top-level AVRCP/AVCTP dispatch (avctp.c lines 2489–2545)
// ============================================================================

fn avrcp_packet(avctp_frame: &mut AvctpFrame) {
    let psm = avctp_frame.l2cap_frame.psm;
    let result = match psm {
        0x17 => avrcp_control_packet(avctp_frame),
        0x1b => avrcp_browsing_packet(avctp_frame),
        _ => {
            print_hexdump(avctp_frame.l2cap_frame.remaining_data());
            return;
        }
    };

    if !result {
        print_text!(COLOR_ERROR, "PDU malformed");
        print_hexdump(avctp_frame.l2cap_frame.remaining_data());
    }
}

/// Decode an AVCTP packet from the given L2CAP frame.
///
/// This is the public entry point for the AVCTP/AVRCP dissector.
/// It parses the 3-byte AVCTP header, prints a colored summary line,
/// and dispatches to the appropriate AVRCP decoder for control (PSM 0x17)
/// or browsing (PSM 0x1B) channels.
pub fn avctp_packet(frame: &L2capFrame) {
    let mut l2cap_frame = frame.clone();

    let hdr = match l2cap_frame.get_u8() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "PDU malformed");
            print_hexdump(l2cap_frame.remaining_data());
            return;
        }
    };

    let pid = match l2cap_frame.get_be16() {
        Some(v) => v,
        None => {
            print_text!(COLOR_ERROR, "PDU malformed");
            print_hexdump(l2cap_frame.remaining_data());
            return;
        }
    };

    let pdu_color = if l2cap_frame.in_ { COLOR_MAGENTA } else { COLOR_BLUE };

    let channel_str = if l2cap_frame.psm == 23 { "Control" } else { "Browsing" };

    let cr_str = if hdr & 0x02 != 0 { "Response" } else { "Command" };

    print_indent!(
        6,
        pdu_color,
        "AVCTP",
        "",
        COLOR_OFF,
        " {}: {}: type 0x{:02x} label {} PID 0x{:04x}",
        channel_str,
        cr_str,
        hdr & 0x0c,
        hdr >> 4,
        pid
    );

    if pid == 0x110e || pid == 0x110c {
        let mut avctp_frame = AvctpFrame { hdr, pt: 0, l2cap_frame };
        avrcp_packet(&mut avctp_frame);
    } else {
        print_hexdump(l2cap_frame.remaining_data());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an L2capFrame from raw data bytes for testing
    fn make_frame(data: &[u8], psm: u16, incoming: bool) -> L2capFrame {
        L2capFrame {
            index: 0,
            in_: incoming,
            handle: 0,
            ident: 0,
            cid: 0,
            psm,
            chan: 0,
            mode: 0,
            seq_num: 0,
            data: data.to_vec(),
            pos: 0,
            size: data.len() as u16,
        }
    }

    #[test]
    fn test_l2cap_frame_get_u8() {
        let mut frame = make_frame(&[0xAB, 0xCD], 0x17, true);
        assert_eq!(frame.get_u8(), Some(0xAB));
        assert_eq!(frame.get_u8(), Some(0xCD));
        assert_eq!(frame.get_u8(), None);
    }

    #[test]
    fn test_l2cap_frame_get_be16() {
        let mut frame = make_frame(&[0x11, 0x0E], 0x17, true);
        assert_eq!(frame.get_be16(), Some(0x110E));
        assert_eq!(frame.get_be16(), None);
    }

    #[test]
    fn test_l2cap_frame_get_be32() {
        let mut frame = make_frame(&[0x00, 0x01, 0x02, 0x03], 0x17, true);
        assert_eq!(frame.get_be32(), Some(0x00010203));
    }

    #[test]
    fn test_l2cap_frame_get_be64() {
        let mut frame = make_frame(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07], 0x17, true);
        assert_eq!(frame.get_be64(), Some(0x0001020304050607));
    }

    #[test]
    fn test_l2cap_frame_remaining_data() {
        let mut frame = make_frame(&[0x01, 0x02, 0x03], 0x17, true);
        let _ = frame.get_u8();
        assert_eq!(frame.remaining_data(), &[0x02, 0x03]);
    }

    #[test]
    fn test_ctype2str() {
        assert_eq!(ctype2str(0x0), "Control");
        assert_eq!(ctype2str(0x1), "Status");
        assert_eq!(ctype2str(0x9), "Accepted");
        assert_eq!(ctype2str(0xa), "Rejected");
        assert_eq!(ctype2str(0xf), "Interim");
    }

    #[test]
    fn test_subunit2str() {
        assert_eq!(subunit2str(0x09), "Panel");
        assert_eq!(subunit2str(0x1f), "Unit");
    }

    #[test]
    fn test_opcode2str() {
        assert_eq!(opcode2str(0x00), "Vendor Dependent");
        assert_eq!(opcode2str(0x30), "Unit Info");
        assert_eq!(opcode2str(0x31), "Subunit Info");
        assert_eq!(opcode2str(0x7c), "Passthrough");
    }

    #[test]
    fn test_pdu2str() {
        assert_eq!(pdu2str(0x10), "GetCapabilities");
        assert_eq!(pdu2str(0x20), "GetElementAttributes");
        assert_eq!(pdu2str(0x31), "RegisterNotification");
        assert_eq!(pdu2str(0x50), "SetAbsoluteVolume");
        assert_eq!(pdu2str(0x71), "GetFolderItems");
        assert_eq!(pdu2str(0xA0), "GeneralReject");
    }

    #[test]
    fn test_event2str() {
        assert_eq!(event2str(0x01), "EVENT_PLAYBACK_STATUS_CHANGED");
        assert_eq!(event2str(0x02), "EVENT_TRACK_CHANGED");
        assert_eq!(event2str(0x0d), "EVENT_VOLUME_CHANGED");
    }

    #[test]
    fn test_error2str() {
        assert_eq!(error2str(0x00), "Invalid Command");
        assert_eq!(error2str(0x04), "Success");
    }

    #[test]
    fn test_op2str() {
        assert_eq!(op2str(0x41), "VOLUME UP");
        assert_eq!(op2str(0x44), "PLAY");
        assert_eq!(op2str(0x46), "PAUSE");
        assert_eq!(op2str(0x4B), "FORWARD");
        assert_eq!(op2str(0x4C), "BACKWARD");
    }

    #[test]
    fn test_mediattr2str() {
        assert_eq!(mediattr2str(0x01), "Title");
        assert_eq!(mediattr2str(0x02), "Artist");
        assert_eq!(mediattr2str(0x03), "Album");
        assert_eq!(mediattr2str(0x07), "Track duration");
    }

    #[test]
    fn test_playstatus2str() {
        assert_eq!(playstatus2str(0x00), "STOPPED");
        assert_eq!(playstatus2str(0x01), "PLAYING");
        assert_eq!(playstatus2str(0x02), "PAUSED");
    }

    #[test]
    fn test_scope2str() {
        assert_eq!(scope2str(0x00), "Media Player List");
        assert_eq!(scope2str(0x01), "Media Player Virtual Filesystem");
        assert_eq!(scope2str(0x03), "Now Playing");
    }

    #[test]
    fn test_pad() {
        assert_eq!(pad(4).len(), 4);
        assert_eq!(pad(0).len(), 1);
        assert_eq!(pad(-6).len(), 6);
    }

    #[test]
    fn test_is_printable() {
        assert!(is_printable(b'A'));
        assert!(is_printable(b'z'));
        assert!(is_printable(b' '));
        assert!(!is_printable(0x00));
        assert!(!is_printable(0x7f));
        assert!(!is_printable(0x1f));
    }

    #[test]
    fn test_avctp_packet_basic_control() {
        // AVCTP header: label=0, single, command, PID=0x110E
        // AVC: ctype=status(1), address=0x48 (subunit=panel=9), opcode=0x00 (Vendor Dep)
        // Company ID: 0x001958 (BT SIG)
        // AVRCP PDU: GetCapabilities(0x10), single(0x00), len=0x0001
        // CapabilityID: 0x03 (Events)
        let data: Vec<u8> = vec![
            0x01, // AVCTP hdr: label=0, single, command
            0x11, 0x0E, // PID = 0x110E (AVRCP)
            0x01, // ctype = Status
            0x48, // address: subunit=Panel(9), subunit_type=0
            0x00, // opcode = Vendor Dependent
            0x00, 0x19, 0x58, // Company ID (BT SIG)
            0x10, // PDU ID = GetCapabilities
            0x00, // Packet type = Single
            0x00, 0x01, // Parameter length = 1
            0x03, // CapabilityID = Events
        ];
        let frame = make_frame(&data, 0x17, false);
        // This exercises the full decode path without panicking
        avctp_packet(&frame);
    }

    #[test]
    fn test_avctp_packet_set_absolute_volume() {
        // AVCTP header: label=1, single, command, PID=0x110E
        let data: Vec<u8> = vec![
            0x10, // hdr: label=1, single, command
            0x11, 0x0E, // PID
            0x00, // ctype = Control
            0x48, // address: Panel
            0x00, // opcode = Vendor Dependent
            0x00, 0x19, 0x58, // Company ID
            0x50, // PDU = SetAbsoluteVolume
            0x00, // Single
            0x00, 0x01, // len = 1
            0x40, // volume = 64 (50.39%)
        ];
        let frame = make_frame(&data, 0x17, true);
        avctp_packet(&frame);
    }

    #[test]
    fn test_avctp_packet_browsing_channel() {
        // Browsing: SetBrowsedPlayer command
        let data: Vec<u8> = vec![
            0x00, // AVCTP hdr: label=0, single, command
            0x11, 0x0E, // PID
            0x70, // PDU = SetBrowsedPlayer
            0x00, 0x02, // len = 2
            0x00, 0x01, // PlayerID = 1
        ];
        let frame = make_frame(&data, 0x1B, false);
        avctp_packet(&frame);
    }

    #[test]
    fn test_avctp_packet_unknown_pid() {
        // Unknown PID — should hexdump
        let data: Vec<u8> = vec![
            0x00, // AVCTP hdr
            0xFF, 0xFF, // Unknown PID
            0x01, 0x02, 0x03, // payload
        ];
        let frame = make_frame(&data, 0x17, true);
        avctp_packet(&frame);
    }

    #[test]
    fn test_avctp_packet_passthrough() {
        // Pass Through command
        let data: Vec<u8> = vec![
            0x00, // AVCTP hdr
            0x11, 0x0E, // PID
            0x00, // ctype = Control
            0x48, // Panel
            0x7C, // opcode = Pass Through
            0x44, // op = Stop, Pressed
            0x00, // length = 0
        ];
        let frame = make_frame(&data, 0x17, false);
        avctp_packet(&frame);
    }

    #[test]
    fn test_avctp_short_frame() {
        // Too short — should print PDU malformed
        let data: Vec<u8> = vec![0x00];
        let frame = make_frame(&data, 0x17, true);
        avctp_packet(&frame);
    }

    #[test]
    fn test_dir2str() {
        assert_eq!(dir2str(0x00), "Folder Up");
        assert_eq!(dir2str(0x01), "Folder Down");
        assert_eq!(dir2str(0x02), "Reserved");
    }

    #[test]
    fn test_charset2str() {
        assert_eq!(charset2str(106), "UTF-8");
        assert_eq!(charset2str(0x00), "Unknown");
        assert_eq!(charset2str(1), "Reserved");
        assert_eq!(charset2str(2), "Reserved");
    }

    #[test]
    fn test_pt2str() {
        assert_eq!(pt2str(0x00), "Single");
        assert_eq!(pt2str(0x01), "Start");
        assert_eq!(pt2str(0x02), "Continuing");
        assert_eq!(pt2str(0x03), "End");
    }

    #[test]
    fn test_value2str_equalizer() {
        assert_eq!(value2str(0x01, 0x01), "OFF");
        assert_eq!(value2str(0x01, 0x02), "ON");
    }

    #[test]
    fn test_value2str_repeat() {
        assert_eq!(value2str(0x02, 0x01), "OFF");
        assert_eq!(value2str(0x02, 0x02), "Single Track Repeat");
        assert_eq!(value2str(0x02, 0x03), "All Track Repeat");
        assert_eq!(value2str(0x02, 0x04), "Group Repeat");
    }

    #[test]
    fn test_value2str_shuffle() {
        assert_eq!(value2str(0x03, 0x01), "OFF");
        assert_eq!(value2str(0x03, 0x02), "All Track Shuffle");
        assert_eq!(value2str(0x03, 0x03), "Group Shuffle");
    }

    #[test]
    fn test_type2str() {
        assert_eq!(type2str(0x01), "Media Player");
        assert_eq!(type2str(0x02), "Folder");
        assert_eq!(type2str(0x03), "Media Element");
    }
}
