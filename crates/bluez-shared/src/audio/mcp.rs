// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MCP (Media Control Profile) / MCS (Media Control Service) / GMCS
 * (Generic Media Control Service) implementation.
 *
 * Complete Rust rewrite of `src/shared/mcp.c` (~2125 lines),
 * `src/shared/mcp.h` (170 lines), and `src/shared/mcs.h` (108 lines).
 *
 * Implements both server-side (media player registration via MCS/GMCS
 * GATT services) and client-side (remote media control via MCP GATT
 * client operations).
 */

use std::sync::{Arc, Mutex};

use bitflags::bitflags;
use tracing::{debug, warn};

use crate::att::transport::BtAtt;
use crate::att::types::{AttPermissions, GattChrcProperties};
use crate::gatt::client::BtGattClient;
use crate::gatt::db::{CharData, GattDb, GattDbAttribute, GattDbService};
use crate::util::endian::{IoBuf, get_le32};
use crate::util::uuid::BtUuid;

// =====================================================================
// MCS Protocol Constants (from mcs.h)
// =====================================================================

/// Track position unavailable sentinel (0xFFFFFFFF interpreted as i32).
pub const MCS_POSITION_UNAVAILABLE: i32 = -1i32;

/// Track duration unavailable sentinel (0xFFFFFFFF interpreted as i32).
pub const MCS_DURATION_UNAVAILABLE: i32 = -1i32;

// ---- Characteristic UUIDs (Bluetooth SIG assigned values) ----

/// Generic Media Control Service UUID.
const GMCS_UUID: u16 = 0x1849;
/// Media Control Service UUID.
const MCS_UUID: u16 = 0x1848;

/// Media Player Name characteristic UUID.
const MCS_MEDIA_PLAYER_NAME_CHRC_UUID: u16 = 0x2B93;
/// Track Changed characteristic UUID.
const MCS_TRACK_CHANGED_CHRC_UUID: u16 = 0x2B96;
/// Track Title characteristic UUID.
const MCS_TRACK_TITLE_CHRC_UUID: u16 = 0x2B97;
/// Track Duration characteristic UUID.
const MCS_TRACK_DURATION_CHRC_UUID: u16 = 0x2B98;
/// Track Position characteristic UUID.
const MCS_TRACK_POSITION_CHRC_UUID: u16 = 0x2B99;
/// Playback Speed characteristic UUID.
const MCS_PLAYBACK_SPEED_CHRC_UUID: u16 = 0x2B9A;
/// Seeking Speed characteristic UUID.
const MCS_SEEKING_SPEED_CHRC_UUID: u16 = 0x2B9B;
/// Playing Order characteristic UUID.
const MCS_PLAYING_ORDER_CHRC_UUID: u16 = 0x2B9C;
/// Playing Order Supported characteristic UUID.
const MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID: u16 = 0x2B9D;
/// Media State characteristic UUID.
const MCS_MEDIA_STATE_CHRC_UUID: u16 = 0x2B9E;
/// Media Control Point characteristic UUID.
const MCS_MEDIA_CP_CHRC_UUID: u16 = 0x2BA1;
/// Media Control Point Opcodes Supported characteristic UUID.
const MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID: u16 = 0x2BA5;
/// Content Control ID (CCID) characteristic UUID.
const MCS_CCID_CHRC_UUID: u16 = 0x2BBA;

// ---- Maximum limits ----

/// Maximum number of GATT attributes in an MCS service.
///
/// Used as a sizing hint; the actual number of handles allocated
/// is `MCS_NUM_HANDLES`.
const _MAX_ATTR: usize = 32;
/// Maximum number of pending MCP GATT write operations.
const MAX_PENDING: usize = 256;
/// Number of MCS handles required for the full service (service decl +
/// 13 characteristics * 2 handles each + 9 CCC descriptors = 38 handles
/// rounded up to 38).
const MCS_NUM_HANDLES: u16 = 38;

// =====================================================================
// Media State Enum
// =====================================================================

/// MCS Media State values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MediaState {
    /// Media player is inactive.
    Inactive = 0x00,
    /// Media player is playing.
    Playing = 0x01,
    /// Media player is paused.
    Paused = 0x02,
    /// Media player is seeking.
    Seeking = 0x03,
}

impl MediaState {
    /// Convert from raw u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(MediaState::Inactive),
            0x01 => Some(MediaState::Playing),
            0x02 => Some(MediaState::Paused),
            0x03 => Some(MediaState::Seeking),
            _ => None,
        }
    }
}

// =====================================================================
// Playing Order Enum
// =====================================================================

/// MCS Playing Order values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PlayingOrder {
    /// Play single track once.
    SingleOnce = 0x01,
    /// Repeat single track.
    SingleRepeat = 0x02,
    /// Play all tracks in order once.
    InOrderOnce = 0x03,
    /// Repeat all tracks in order.
    InOrderRepeat = 0x04,
    /// Play oldest first once.
    OldestOnce = 0x05,
    /// Play oldest first, repeat.
    OldestRepeat = 0x06,
    /// Play newest first once.
    NewestOnce = 0x07,
    /// Play newest first, repeat.
    NewestRepeat = 0x08,
    /// Shuffle once.
    ShuffleOnce = 0x09,
    /// Shuffle and repeat.
    ShuffleRepeat = 0x0a,
}

impl PlayingOrder {
    /// Convert from raw u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(PlayingOrder::SingleOnce),
            0x02 => Some(PlayingOrder::SingleRepeat),
            0x03 => Some(PlayingOrder::InOrderOnce),
            0x04 => Some(PlayingOrder::InOrderRepeat),
            0x05 => Some(PlayingOrder::OldestOnce),
            0x06 => Some(PlayingOrder::OldestRepeat),
            0x07 => Some(PlayingOrder::NewestOnce),
            0x08 => Some(PlayingOrder::NewestRepeat),
            0x09 => Some(PlayingOrder::ShuffleOnce),
            0x0a => Some(PlayingOrder::ShuffleRepeat),
            _ => None,
        }
    }
}

// =====================================================================
// Playing Order Supported Bitfield
// =====================================================================

bitflags! {
    /// Bitfield indicating which playing orders a media player supports.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct McsPlayingOrderSupported: u16 {
        /// Single track once.
        const SINGLE_ONCE    = 0x0001;
        /// Single track repeat.
        const SINGLE_REPEAT  = 0x0002;
        /// In-order once.
        const IN_ORDER_ONCE  = 0x0004;
        /// In-order repeat.
        const IN_ORDER_REPEAT = 0x0008;
        /// Oldest first once.
        const OLDEST_ONCE    = 0x0010;
        /// Oldest first repeat.
        const OLDEST_REPEAT  = 0x0020;
        /// Newest first once.
        const NEWEST_ONCE    = 0x0040;
        /// Newest first repeat.
        const NEWEST_REPEAT  = 0x0080;
        /// Shuffle once.
        const SHUFFLE_ONCE   = 0x0100;
        /// Shuffle repeat.
        const SHUFFLE_REPEAT = 0x0200;
    }
}

// =====================================================================
// Control Point Result Codes
// =====================================================================

/// MCS Control Point result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum McsResult {
    /// Operation succeeded.
    Success = 0x01,
    /// Opcode not supported.
    OpNotSupported = 0x02,
    /// Media player is inactive.
    MediaPlayerInactive = 0x03,
    /// Command cannot be completed.
    CommandCannotComplete = 0x04,
}

impl McsResult {
    /// Convert from raw u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(McsResult::Success),
            0x02 => Some(McsResult::OpNotSupported),
            0x03 => Some(McsResult::MediaPlayerInactive),
            0x04 => Some(McsResult::CommandCannotComplete),
            _ => None,
        }
    }
}

// =====================================================================
// Control Point Opcodes
// =====================================================================

/// MCS Control Point opcode values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CpOpcode {
    /// Start or resume playback.
    Play = 0x01,
    /// Pause playback.
    Pause = 0x02,
    /// Fast rewind.
    FastRewind = 0x03,
    /// Fast forward.
    FastForward = 0x04,
    /// Stop playback.
    Stop = 0x05,
    /// Move playback position by a relative offset.
    MoveRelative = 0x10,
    /// Navigate to previous segment.
    PrevSegment = 0x20,
    /// Navigate to next segment.
    NextSegment = 0x21,
    /// Navigate to first segment.
    FirstSegment = 0x22,
    /// Navigate to last segment.
    LastSegment = 0x23,
    /// Navigate to a specific segment number.
    GotoSegment = 0x24,
    /// Navigate to previous track.
    PrevTrack = 0x30,
    /// Navigate to next track.
    NextTrack = 0x31,
    /// Navigate to first track.
    FirstTrack = 0x32,
    /// Navigate to last track.
    LastTrack = 0x33,
    /// Navigate to a specific track number.
    GotoTrack = 0x34,
    /// Navigate to previous group.
    PrevGroup = 0x40,
    /// Navigate to next group.
    NextGroup = 0x41,
    /// Navigate to first group.
    FirstGroup = 0x42,
    /// Navigate to last group.
    LastGroup = 0x43,
    /// Navigate to a specific group number.
    GotoGroup = 0x44,
}

impl CpOpcode {
    /// Convert from raw u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(CpOpcode::Play),
            0x02 => Some(CpOpcode::Pause),
            0x03 => Some(CpOpcode::FastRewind),
            0x04 => Some(CpOpcode::FastForward),
            0x05 => Some(CpOpcode::Stop),
            0x10 => Some(CpOpcode::MoveRelative),
            0x20 => Some(CpOpcode::PrevSegment),
            0x21 => Some(CpOpcode::NextSegment),
            0x22 => Some(CpOpcode::FirstSegment),
            0x23 => Some(CpOpcode::LastSegment),
            0x24 => Some(CpOpcode::GotoSegment),
            0x30 => Some(CpOpcode::PrevTrack),
            0x31 => Some(CpOpcode::NextTrack),
            0x32 => Some(CpOpcode::FirstTrack),
            0x33 => Some(CpOpcode::LastTrack),
            0x34 => Some(CpOpcode::GotoTrack),
            0x40 => Some(CpOpcode::PrevGroup),
            0x41 => Some(CpOpcode::NextGroup),
            0x42 => Some(CpOpcode::FirstGroup),
            0x43 => Some(CpOpcode::LastGroup),
            0x44 => Some(CpOpcode::GotoGroup),
            _ => None,
        }
    }
}

// =====================================================================
// Control Point Opcodes Supported Bitfield
// =====================================================================

bitflags! {
    /// Bitfield indicating which control point opcodes the media player supports.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct McsCmdSupported: u32 {
        /// Play command supported.
        const PLAY           = 0x0000_0001;
        /// Pause command supported.
        const PAUSE          = 0x0000_0002;
        /// Fast rewind supported.
        const FAST_REWIND    = 0x0000_0004;
        /// Fast forward supported.
        const FAST_FORWARD   = 0x0000_0008;
        /// Stop supported.
        const STOP           = 0x0000_0010;
        /// Move relative supported.
        const MOVE_RELATIVE  = 0x0000_0020;
        /// Previous segment supported.
        const PREV_SEGMENT   = 0x0000_0040;
        /// Next segment supported.
        const NEXT_SEGMENT   = 0x0000_0080;
        /// First segment supported.
        const FIRST_SEGMENT  = 0x0000_0100;
        /// Last segment supported.
        const LAST_SEGMENT   = 0x0000_0200;
        /// Goto segment supported.
        const GOTO_SEGMENT   = 0x0000_0400;
        /// Previous track supported.
        const PREV_TRACK     = 0x0000_0800;
        /// Next track supported.
        const NEXT_TRACK     = 0x0000_1000;
        /// First track supported.
        const FIRST_TRACK    = 0x0000_2000;
        /// Last track supported.
        const LAST_TRACK     = 0x0000_4000;
        /// Goto track supported.
        const GOTO_TRACK     = 0x0000_8000;
        /// Previous group supported.
        const PREV_GROUP     = 0x0001_0000;
        /// Next group supported.
        const NEXT_GROUP     = 0x0002_0000;
        /// First group supported.
        const FIRST_GROUP    = 0x0004_0000;
        /// Last group supported.
        const LAST_GROUP     = 0x0008_0000;
        /// Goto group supported.
        const GOTO_GROUP     = 0x0010_0000;
    }
}

// =====================================================================
// McsCpRsp — Control Point Response
// =====================================================================

/// MCS Control Point response (wire-format compatible).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McsCpRsp {
    /// Opcode that was executed.
    pub op: u8,
    /// Result code.
    pub result: u8,
}

// =====================================================================
// Command descriptor table (mirrors C mcs_command[])
// =====================================================================

/// Internal descriptor for a single MCS command.
struct McsCommandDesc {
    /// Human-readable command name.
    name: &'static str,
    /// Wire opcode.
    op: u8,
    /// Corresponding supported-commands bitflag.
    support: McsCmdSupported,
    /// Whether this command takes an int32 argument.
    has_int32_arg: bool,
}

/// Static table of all 21 MCS commands (matches C `mcs_command[]`).
static MCS_COMMANDS: &[McsCommandDesc] = &[
    McsCommandDesc { name: "Play", op: 0x01, support: McsCmdSupported::PLAY, has_int32_arg: false },
    McsCommandDesc {
        name: "Pause",
        op: 0x02,
        support: McsCmdSupported::PAUSE,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Fast Rewind",
        op: 0x03,
        support: McsCmdSupported::FAST_REWIND,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Fast Forward",
        op: 0x04,
        support: McsCmdSupported::FAST_FORWARD,
        has_int32_arg: false,
    },
    McsCommandDesc { name: "Stop", op: 0x05, support: McsCmdSupported::STOP, has_int32_arg: false },
    McsCommandDesc {
        name: "Move Relative",
        op: 0x10,
        support: McsCmdSupported::MOVE_RELATIVE,
        has_int32_arg: true,
    },
    McsCommandDesc {
        name: "Prev Segment",
        op: 0x20,
        support: McsCmdSupported::PREV_SEGMENT,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Next Segment",
        op: 0x21,
        support: McsCmdSupported::NEXT_SEGMENT,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "First Segment",
        op: 0x22,
        support: McsCmdSupported::FIRST_SEGMENT,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Last Segment",
        op: 0x23,
        support: McsCmdSupported::LAST_SEGMENT,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Goto Segment",
        op: 0x24,
        support: McsCmdSupported::GOTO_SEGMENT,
        has_int32_arg: true,
    },
    McsCommandDesc {
        name: "Prev Track",
        op: 0x30,
        support: McsCmdSupported::PREV_TRACK,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Next Track",
        op: 0x31,
        support: McsCmdSupported::NEXT_TRACK,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "First Track",
        op: 0x32,
        support: McsCmdSupported::FIRST_TRACK,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Last Track",
        op: 0x33,
        support: McsCmdSupported::LAST_TRACK,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Goto Track",
        op: 0x34,
        support: McsCmdSupported::GOTO_TRACK,
        has_int32_arg: true,
    },
    McsCommandDesc {
        name: "Prev Group",
        op: 0x40,
        support: McsCmdSupported::PREV_GROUP,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Next Group",
        op: 0x41,
        support: McsCmdSupported::NEXT_GROUP,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "First Group",
        op: 0x42,
        support: McsCmdSupported::FIRST_GROUP,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Last Group",
        op: 0x43,
        support: McsCmdSupported::LAST_GROUP,
        has_int32_arg: false,
    },
    McsCommandDesc {
        name: "Goto Group",
        op: 0x44,
        support: McsCmdSupported::GOTO_GROUP,
        has_int32_arg: true,
    },
];

/// Playing order → supported bit mapping (mirrors C `mcs_playing_orders[]`).
static MCS_PLAYING_ORDERS: &[(PlayingOrder, McsPlayingOrderSupported)] = &[
    (PlayingOrder::SingleOnce, McsPlayingOrderSupported::SINGLE_ONCE),
    (PlayingOrder::SingleRepeat, McsPlayingOrderSupported::SINGLE_REPEAT),
    (PlayingOrder::InOrderOnce, McsPlayingOrderSupported::IN_ORDER_ONCE),
    (PlayingOrder::InOrderRepeat, McsPlayingOrderSupported::IN_ORDER_REPEAT),
    (PlayingOrder::OldestOnce, McsPlayingOrderSupported::OLDEST_ONCE),
    (PlayingOrder::OldestRepeat, McsPlayingOrderSupported::OLDEST_REPEAT),
    (PlayingOrder::NewestOnce, McsPlayingOrderSupported::NEWEST_ONCE),
    (PlayingOrder::NewestRepeat, McsPlayingOrderSupported::NEWEST_REPEAT),
    (PlayingOrder::ShuffleOnce, McsPlayingOrderSupported::SHUFFLE_ONCE),
    (PlayingOrder::ShuffleRepeat, McsPlayingOrderSupported::SHUFFLE_REPEAT),
];

/// Find a command descriptor by opcode.
fn find_command(op: u8) -> Option<&'static McsCommandDesc> {
    MCS_COMMANDS.iter().find(|c| c.op == op)
}

/// Find the supported-command bit for a given opcode.
///
/// Used by server-side code and tests to check command support.
pub fn find_command_support(op: u8) -> Option<McsCmdSupported> {
    find_command(op).map(|c| c.support)
}

/// Check whether a playing order value has its corresponding support bit set.
fn playing_order_supported(order: u8, supported: McsPlayingOrderSupported) -> bool {
    MCS_PLAYING_ORDERS.iter().any(|(po, bit)| *po as u8 == order && supported.contains(*bit))
}

// =====================================================================
// MCS Server Callback Trait
// =====================================================================

/// Server-side callbacks for MCS/GMCS characteristic value requests and
/// media command notifications.
///
/// This trait replaces the C `struct bt_mcs_callback` function pointer table.
pub trait McsCallback: Send + Sync {
    /// Return the media player name as raw UTF-8 bytes.
    fn media_player_name(&self) -> Vec<u8> {
        Vec::new()
    }
    /// Return the track title as raw UTF-8 bytes.
    fn track_title(&self) -> Vec<u8> {
        Vec::new()
    }
    /// Return the track duration in centiseconds.
    fn track_duration(&self) -> i32 {
        MCS_DURATION_UNAVAILABLE
    }
    /// Return the current track position in centiseconds.
    fn track_position(&self) -> i32 {
        MCS_POSITION_UNAVAILABLE
    }
    /// Return the playback speed (log2 of speed factor, as signed byte).
    fn playback_speed(&self) -> i8 {
        0
    }
    /// Return the seeking speed (log2 of speed factor, as signed byte).
    fn seeking_speed(&self) -> i8 {
        0
    }
    /// Return the current playing order.
    fn playing_order(&self) -> u8 {
        PlayingOrder::InOrderRepeat as u8
    }
    /// Return the supported playing orders bitfield.
    fn playing_order_supported(&self) -> u16 {
        McsPlayingOrderSupported::IN_ORDER_REPEAT.bits()
    }
    /// Return the supported Media CP opcodes bitfield.
    fn media_cp_op_supported(&self) -> u32 {
        0
    }
    /// Notification: set track position. Returns true if accepted.
    fn set_track_position(&self, _position: i32) -> bool {
        false
    }
    /// Notification: set playback speed. Returns true if accepted.
    fn set_playback_speed(&self, _speed: i8) -> bool {
        false
    }
    /// Notification: set playing order. Returns true if accepted.
    fn set_playing_order(&self, _order: u8) -> bool {
        false
    }
    /// Media command: Play. Returns true if successful.
    fn play(&self) -> bool {
        false
    }
    /// Media command: Pause. Returns true if successful.
    fn pause(&self) -> bool {
        false
    }
    /// Media command: Fast Rewind. Returns true if successful.
    fn fast_rewind(&self) -> bool {
        false
    }
    /// Media command: Fast Forward. Returns true if successful.
    fn fast_forward(&self) -> bool {
        false
    }
    /// Media command: Stop. Returns true if successful.
    fn stop(&self) -> bool {
        false
    }
    /// Media command: Move Relative. Returns true if successful.
    fn move_relative(&self, _offset: i32) -> bool {
        false
    }
    /// Media command: Previous Segment. Returns true if successful.
    fn previous_segment(&self) -> bool {
        false
    }
    /// Media command: Next Segment. Returns true if successful.
    fn next_segment(&self) -> bool {
        false
    }
    /// Media command: First Segment. Returns true if successful.
    fn first_segment(&self) -> bool {
        false
    }
    /// Media command: Last Segment. Returns true if successful.
    fn last_segment(&self) -> bool {
        false
    }
    /// Media command: Goto Segment. Returns true if successful.
    fn goto_segment(&self, _n: i32) -> bool {
        false
    }
    /// Media command: Previous Track. Returns true if successful.
    fn previous_track(&self) -> bool {
        false
    }
    /// Media command: Next Track. Returns true if successful.
    fn next_track(&self) -> bool {
        false
    }
    /// Media command: First Track. Returns true if successful.
    fn first_track(&self) -> bool {
        false
    }
    /// Media command: Last Track. Returns true if successful.
    fn last_track(&self) -> bool {
        false
    }
    /// Media command: Goto Track. Returns true if successful.
    fn goto_track(&self, _n: i32) -> bool {
        false
    }
    /// Media command: Previous Group. Returns true if successful.
    fn previous_group(&self) -> bool {
        false
    }
    /// Media command: Next Group. Returns true if successful.
    fn next_group(&self) -> bool {
        false
    }
    /// Media command: First Group. Returns true if successful.
    fn first_group(&self) -> bool {
        false
    }
    /// Media command: Last Group. Returns true if successful.
    fn last_group(&self) -> bool {
        false
    }
    /// Media command: Goto Group. Returns true if successful.
    fn goto_group(&self, _n: i32) -> bool {
        false
    }
    /// Debug logging callback.
    fn debug(&self, _msg: &str) {}
    /// Called when the MCS server is being destroyed.
    fn destroy(&self) {}
}

// =====================================================================
// MCP Client Callback Trait
// =====================================================================

/// Client-side callbacks for MCP attach lifecycle events and command
/// completion notifications.
///
/// This trait replaces the C `struct bt_mcp_callback` function pointer table.
pub trait McpCallback: Send + Sync {
    /// A new CCID (content control ID) has been discovered.
    /// `gmcs` indicates whether the service is GMCS (true) or MCS (false).
    fn ccid(&self, ccid: u8, gmcs: bool);
    /// A command has completed with the given operation ID and status.
    fn complete(&self, id: u32, status: u8);
    /// The MCP client has finished discovery and is ready.
    fn ready(&self);
    /// Debug logging callback.
    fn debug(&self, _msg: &str) {}
    /// Called when the MCP client is being destroyed.
    fn destroy(&self) {}
}

/// Per-CCID listener callbacks for characteristic value change notifications.
///
/// Replaces C `struct bt_mcp_listener_callback`.
pub trait McpListenerCallback: Send + Sync {
    /// Media player name changed.
    fn media_player_name(&self, _value: &[u8]) {}
    /// Track has changed (no data payload).
    fn track_changed(&self) {}
    /// Track title changed.
    fn track_title(&self, _value: &[u8]) {}
    /// Track duration changed.
    fn track_duration(&self, _duration: i32) {}
    /// Track position changed.
    fn track_position(&self, _position: i32) {}
    /// Playback speed changed.
    fn playback_speed(&self, _speed: i8) {}
    /// Seeking speed changed.
    fn seeking_speed(&self, _speed: i8) {}
    /// Playing order changed.
    fn playing_order(&self, _order: u8) {}
    /// Media state changed.
    fn media_state(&self, _state: u8) {}
    /// Called when this listener is being destroyed.
    fn destroy(&self) {}
}

// =====================================================================
// Global MCS Server Registry
// =====================================================================

/// Global registry of MCS server instances and CCID counter.
/// Protected by a mutex for thread safety.
struct McsGlobal {
    /// All registered MCS server instances.
    servers: Vec<Arc<Mutex<BtMcsInner>>>,
    /// Monotonically increasing CCID counter (wraps at u8::MAX).
    ccid_counter: u8,
}

static MCS_GLOBAL: Mutex<McsGlobal> =
    Mutex::new(McsGlobal { servers: Vec::new(), ccid_counter: 0 });

/// Allocate a new CCID, avoiding collisions with existing servers.
fn mcs_alloc_ccid() -> u8 {
    let mut global = MCS_GLOBAL.lock().unwrap();
    let start = global.ccid_counter;
    loop {
        global.ccid_counter = global.ccid_counter.wrapping_add(1);
        let candidate = global.ccid_counter;
        // Check no existing server uses this CCID.
        let collision = global
            .servers
            .iter()
            .any(|s| if let Ok(inner) = s.lock() { inner.ccid == candidate } else { false });
        if !collision {
            return candidate;
        }
        // Safety: if we've wrapped all the way around, break to prevent
        // infinite loop (theoretically impossible with < 256 servers).
        if candidate == start {
            return candidate;
        }
    }
}

/// Reset the global CCID counter to zero and clear all registered
/// MCS server instances (for testing purposes).
///
/// This ensures complete test isolation by preventing stale server
/// references in MCS_GLOBAL from interfering with subsequent tests.
pub fn bt_mcs_test_util_reset_ccid() {
    let mut global = MCS_GLOBAL.lock().unwrap();
    global.ccid_counter = 0;
    global.servers.clear();
}

// =====================================================================
// MCS Server — Internal DB Handles
// =====================================================================

/// GATT attribute handles for all MCS characteristics within a service.
///
/// All fields mirror the C `struct bt_mcs` handle storage. Some handles
/// (service_handle, media_cp, ccid_value) are stored for completeness and
/// future use (e.g., CP write handler dispatch, CCID read handler).
struct McsDbHandles {
    /// Media Player Name characteristic value handle.
    media_player_name: u16,
    /// Track Changed characteristic value handle.
    track_changed: u16,
    /// Track Title characteristic value handle.
    track_title: u16,
    /// Track Duration characteristic value handle.
    track_duration: u16,
    /// Track Position characteristic value handle.
    track_position: u16,
    /// Playback Speed characteristic value handle.
    playback_speed: u16,
    /// Seeking Speed characteristic value handle.
    seeking_speed: u16,
    /// Playing Order characteristic value handle.
    playing_order: u16,
    /// Playing Order Supported characteristic value handle.
    playing_order_supported: u16,
    /// Media State characteristic value handle.
    media_state: u16,
    /// Media Control Point characteristic value handle.
    media_cp: u16,
    /// Media Control Point Opcodes Supported characteristic value handle.
    media_cp_op_supported: u16,
}

/// Internal mutable state of an MCS server instance.
///
/// Session management (per-client ATT tracking for disconnect handling and
/// VALUE_CHANGED_DURING_READ_LONG) is handled through the GATT DB's internal
/// attribute dispatch mechanism rather than explicit session objects.
struct BtMcsInner {
    /// GATT database this service is registered in.
    db: GattDb,
    /// Whether this is a GMCS (true) or MCS (false) instance.
    is_gmcs: bool,
    /// Allocated Content Control ID.
    ccid: u8,
    /// Current media state.
    media_state: MediaState,
    /// Server-side callbacks.
    callbacks: Arc<dyn McsCallback>,
    /// GATT attribute handles.
    handles: McsDbHandles,
    /// GattDbService handle for cleanup.
    service: Option<GattDbService>,
}

// =====================================================================
// BtMcs — Public MCS Server API
// =====================================================================

/// MCS/GMCS server instance.
///
/// Wraps an `Arc<Mutex<BtMcsInner>>` for shared ownership and thread safety.
#[derive(Clone)]
pub struct BtMcs {
    inner: Arc<Mutex<BtMcsInner>>,
}

impl BtMcs {
    /// Register a new MCS or GMCS service in the given GATT database.
    ///
    /// If `is_gmcs` is true, registers the service as GMCS (UUID 0x1849);
    /// only one GMCS instance may exist per database. Otherwise, registers
    /// as MCS (UUID 0x1848); multiple MCS instances may coexist.
    ///
    /// Returns `None` if registration fails (e.g., duplicate GMCS, or
    /// insufficient GATT handle space).
    pub fn register(db: GattDb, is_gmcs: bool, callbacks: Arc<dyn McsCallback>) -> Option<BtMcs> {
        // Enforce single GMCS per database.
        {
            let global = MCS_GLOBAL.lock().unwrap();
            if is_gmcs {
                for s in &global.servers {
                    if let Ok(inner) = s.lock() {
                        if inner.is_gmcs && inner.db.ptr_eq(&db) {
                            warn!("GMCS already registered in this database");
                            return None;
                        }
                    }
                }
            }
        }

        let ccid = mcs_alloc_ccid();
        debug!("MCS register: ccid={}, gmcs={}", ccid, is_gmcs);

        // Initialize the GATT service and all characteristics.
        let (service, handles) = mcs_init_db(&db, is_gmcs, ccid)?;

        let inner = BtMcsInner {
            db: db.clone(),
            is_gmcs,
            ccid,
            media_state: MediaState::Inactive,
            callbacks,
            handles,
            service: Some(service.clone()),
        };

        let arc_inner = Arc::new(Mutex::new(inner));

        // Activate the service.
        service.set_active(true);

        // Register in global list.
        {
            let mut global = MCS_GLOBAL.lock().unwrap();
            global.servers.push(Arc::clone(&arc_inner));
        }

        Some(BtMcs { inner: arc_inner })
    }

    /// Unregister this MCS service, removing it from the GATT database
    /// and the global registry.
    pub fn unregister(&self) {
        let (service_attr, db) = {
            let mut inner = self.inner.lock().unwrap();
            inner.callbacks.destroy();
            let db = inner.db.clone();
            let svc = inner.service.take();
            (svc, db)
        };

        // Remove from global registry.
        {
            let mut global = MCS_GLOBAL.lock().unwrap();
            global.servers.retain(|s| !Arc::ptr_eq(s, &self.inner));
        }

        // Remove from GATT database.
        if let Some(svc) = service_attr {
            db.remove_service(&svc.as_attribute());
        }
    }

    /// Unregister all MCS/GMCS services associated with the given database.
    pub fn unregister_all(db: &GattDb) {
        let to_remove: Vec<Arc<Mutex<BtMcsInner>>> = {
            let global = MCS_GLOBAL.lock().unwrap();
            global
                .servers
                .iter()
                .filter(|s| if let Ok(inner) = s.lock() { inner.db.ptr_eq(db) } else { false })
                .cloned()
                .collect()
        };

        for arc in &to_remove {
            let mcs = BtMcs { inner: Arc::clone(arc) };
            mcs.unregister();
        }
    }

    /// Set the current media state and notify connected clients.
    pub fn set_media_state(&self, state: MediaState) {
        let mut inner = self.inner.lock().unwrap();
        if inner.media_state == state {
            return;
        }
        debug!("MCS set_media_state: {:?} -> {:?}", inner.media_state, state);
        inner.media_state = state;
        let handle = inner.handles.media_state;
        let db = inner.db.clone();
        drop(inner);
        // Notify via GATT.
        let value = [state as u8];
        if let Some(attr) = db.get_attribute(handle) {
            attr.notify(&value, None);
        }
    }

    /// Get the current media state.
    pub fn get_media_state(&self) -> MediaState {
        let inner = self.inner.lock().unwrap();
        inner.media_state
    }

    /// Trigger a notification for a changed characteristic identified by UUID.
    ///
    /// The callback trait method for the corresponding UUID is invoked to
    /// obtain the current value, which is then sent as a GATT notification
    /// to all subscribed clients.
    pub fn changed(&self, chrc_uuid: u16) {
        let inner = self.inner.lock().unwrap();
        let cb = Arc::clone(&inner.callbacks);
        let db = inner.db.clone();

        // Map UUID to handle and get value.
        let (handle, value) = match chrc_uuid {
            MCS_MEDIA_PLAYER_NAME_CHRC_UUID => {
                (inner.handles.media_player_name, cb.media_player_name())
            }
            MCS_TRACK_CHANGED_CHRC_UUID => (inner.handles.track_changed, Vec::new()),
            MCS_TRACK_TITLE_CHRC_UUID => (inner.handles.track_title, cb.track_title()),
            MCS_TRACK_DURATION_CHRC_UUID => {
                let v = cb.track_duration();
                let mut buf = IoBuf::with_capacity(4);
                buf.push_le32(v as u32);
                (inner.handles.track_duration, buf.as_bytes().to_vec())
            }
            MCS_TRACK_POSITION_CHRC_UUID => {
                let v = cb.track_position();
                let mut buf = IoBuf::with_capacity(4);
                buf.push_le32(v as u32);
                (inner.handles.track_position, buf.as_bytes().to_vec())
            }
            MCS_PLAYBACK_SPEED_CHRC_UUID => {
                let v = cb.playback_speed();
                (inner.handles.playback_speed, vec![v as u8])
            }
            MCS_SEEKING_SPEED_CHRC_UUID => {
                let v = cb.seeking_speed();
                (inner.handles.seeking_speed, vec![v as u8])
            }
            MCS_PLAYING_ORDER_CHRC_UUID => {
                let v = cb.playing_order();
                (inner.handles.playing_order, vec![v])
            }
            MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID => {
                let v = cb.playing_order_supported();
                let mut buf = IoBuf::with_capacity(2);
                buf.push_le16(v);
                (inner.handles.playing_order_supported, buf.as_bytes().to_vec())
            }
            MCS_MEDIA_STATE_CHRC_UUID => (inner.handles.media_state, vec![inner.media_state as u8]),
            MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID => {
                let v = cb.media_cp_op_supported();
                let mut buf = IoBuf::with_capacity(4);
                buf.push_le32(v);
                (inner.handles.media_cp_op_supported, buf.as_bytes().to_vec())
            }
            _ => {
                warn!("MCS changed: unknown UUID 0x{:04x}", chrc_uuid);
                return;
            }
        };

        drop(inner);

        debug!("MCS changed: uuid=0x{:04x}, handle=0x{:04x}", chrc_uuid, handle);
        if let Some(attr) = db.get_attribute(handle) {
            attr.notify(&value, None);
        }
    }

    /// Get the CCID assigned to this MCS instance.
    pub fn get_ccid(&self) -> u8 {
        let inner = self.inner.lock().unwrap();
        inner.ccid
    }
}

// =====================================================================
// MCS Server — GATT Service Initialization
// =====================================================================

/// Initialize the GATT service with all MCS/GMCS characteristics.
///
/// Returns the service handle and the DB handles struct.
fn mcs_init_db(db: &GattDb, is_gmcs: bool, _ccid: u8) -> Option<(GattDbService, McsDbHandles)> {
    let svc_uuid = if is_gmcs { BtUuid::from_u16(GMCS_UUID) } else { BtUuid::from_u16(MCS_UUID) };

    let service = db.add_service(&svc_uuid, true, MCS_NUM_HANDLES)?;
    let _svc_handle = service.as_attribute().get_handle();

    let rp = AttPermissions::READ.bits() as u32;
    let wp = AttPermissions::WRITE.bits() as u32;
    let rwp = rp | wp;
    let np = AttPermissions::NONE.bits() as u32;

    let read_prop = GattChrcProperties::READ.bits();
    let read_notify_prop = GattChrcProperties::READ.bits() | GattChrcProperties::NOTIFY.bits();
    let notify_prop = GattChrcProperties::NOTIFY.bits();
    let write_prop =
        GattChrcProperties::WRITE.bits() | GattChrcProperties::WRITE_WITHOUT_RESP.bits();
    let read_write_notify_prop = read_notify_prop | write_prop;

    // Helper to add a characteristic with no callbacks (callbacks set later via user_data).
    let add_chrc = |uuid: u16, perms: u32, props: u8| -> Option<u16> {
        let attr =
            service.add_characteristic(&BtUuid::from_u16(uuid), perms, props, None, None, None)?;
        Some(attr.get_handle())
    };

    // 1. Media Player Name (Read + Notify)
    let media_player_name = add_chrc(MCS_MEDIA_PLAYER_NAME_CHRC_UUID, rp, read_notify_prop)?;
    service.add_ccc(np);

    // 2. Track Changed (Notify only)
    let track_changed = add_chrc(MCS_TRACK_CHANGED_CHRC_UUID, np, notify_prop)?;
    service.add_ccc(np);

    // 3. Track Title (Read + Notify)
    let track_title = add_chrc(MCS_TRACK_TITLE_CHRC_UUID, rp, read_notify_prop)?;
    service.add_ccc(np);

    // 4. Track Duration (Read + Notify, fixed 4 bytes)
    let track_duration = add_chrc(MCS_TRACK_DURATION_CHRC_UUID, rp, read_notify_prop)?;
    if let Some(attr) = db.get_attribute(track_duration) {
        attr.set_fixed_length(4);
    }
    service.add_ccc(np);

    // 5. Track Position (Read + Write + Notify, fixed 4 bytes)
    let track_position = add_chrc(MCS_TRACK_POSITION_CHRC_UUID, rwp, read_write_notify_prop)?;
    if let Some(attr) = db.get_attribute(track_position) {
        attr.set_fixed_length(4);
    }
    service.add_ccc(np);

    // 6. Playback Speed (Read + Write + Notify, fixed 1 byte)
    let playback_speed = add_chrc(MCS_PLAYBACK_SPEED_CHRC_UUID, rwp, read_write_notify_prop)?;
    if let Some(attr) = db.get_attribute(playback_speed) {
        attr.set_fixed_length(1);
    }
    service.add_ccc(np);

    // 7. Seeking Speed (Read + Notify, fixed 1 byte)
    let seeking_speed = add_chrc(MCS_SEEKING_SPEED_CHRC_UUID, rp, read_notify_prop)?;
    if let Some(attr) = db.get_attribute(seeking_speed) {
        attr.set_fixed_length(1);
    }
    service.add_ccc(np);

    // 8. Playing Order (Read + Write + Notify, fixed 1 byte)
    let playing_order = add_chrc(MCS_PLAYING_ORDER_CHRC_UUID, rwp, read_write_notify_prop)?;
    if let Some(attr) = db.get_attribute(playing_order) {
        attr.set_fixed_length(1);
    }
    service.add_ccc(np);

    // 9. Playing Order Supported (Read, fixed 2 bytes)
    let playing_order_supported = add_chrc(MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID, rp, read_prop)?;
    if let Some(attr) = db.get_attribute(playing_order_supported) {
        attr.set_fixed_length(2);
    }

    // 10. Media State (Read + Notify, fixed 1 byte)
    let media_state = add_chrc(MCS_MEDIA_STATE_CHRC_UUID, rp, read_notify_prop)?;
    if let Some(attr) = db.get_attribute(media_state) {
        attr.set_fixed_length(1);
    }
    service.add_ccc(np);

    // 11. Media Control Point (Write + Write Without Response + Notify)
    // The CP characteristic has a write callback that dispatches commands
    // to the McsCallback trait via the MCS_GLOBAL registry.
    type CpWriteFn =
        Arc<dyn Fn(GattDbAttribute, u32, u16, &[u8], u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>;
    let cp_write_fn: CpWriteFn = Arc::new(
        |attr: GattDbAttribute,
         id: u32,
         _offset: u16,
         value: &[u8],
         _opcode: u8,
         _att: Option<Arc<Mutex<BtAtt>>>| {
            mcs_cp_write_handler(attr, id, value);
        },
    );
    let media_cp_attr = service.add_characteristic(
        &BtUuid::from_u16(MCS_MEDIA_CP_CHRC_UUID),
        wp,
        write_prop | GattChrcProperties::NOTIFY.bits(),
        None,
        Some(cp_write_fn),
        None,
    )?;
    let media_cp = media_cp_attr.get_handle();
    service.add_ccc(np);

    // 12. Media Control Point Opcodes Supported (Read + Notify, fixed 4 bytes)
    let media_cp_op_supported =
        add_chrc(MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID, rp, read_notify_prop)?;
    if let Some(attr) = db.get_attribute(media_cp_op_supported) {
        attr.set_fixed_length(4);
    }
    service.add_ccc(np);

    // 13. Content Control ID (CCID) (Read, fixed 1 byte)
    let ccid_handle = add_chrc(MCS_CCID_CHRC_UUID, rp, read_prop)?;
    if let Some(attr) = db.get_attribute(ccid_handle) {
        attr.set_fixed_length(1);
    }
    // Note: ccid_handle is used during service registration but not stored
    // in McsDbHandles since it's a static value read once.
    let _ = ccid_handle;

    let handles = McsDbHandles {
        media_player_name,
        track_changed,
        track_title,
        track_duration,
        track_position,
        playback_speed,
        seeking_speed,
        playing_order,
        playing_order_supported,
        media_state,
        media_cp,
        media_cp_op_supported,
    };

    Some((service, handles))
}

/// Handle a GATT write to the Media Control Point characteristic.
///
/// Looks up the owning MCS server instance in MCS_GLOBAL by matching the
/// attribute handle against McsDbHandles::media_cp. Parses the CP opcode
/// from the first byte and dispatches to the appropriate McsCallback method.
/// Sends ATT write result (success/error) and optionally CP result + state
/// change notifications.
fn mcs_cp_write_handler(attr: GattDbAttribute, id: u32, value: &[u8]) {
    let handle = attr.get_handle();

    // Find the MCS server owning this CP handle via the global registry.
    let server = {
        let global = MCS_GLOBAL.lock().unwrap();
        global
            .servers
            .iter()
            .find(|s| s.lock().is_ok_and(|inner| inner.handles.media_cp == handle))
            .cloned()
    };

    let server = match server {
        Some(s) => s,
        None => {
            warn!("mcs_cp_write_handler: no server for handle 0x{:04x}", handle);
            attr.write_result(id, 0x0E); // ATT_ERROR_UNLIKELY
            return;
        }
    };

    if value.is_empty() {
        attr.write_result(id, 0x04); // ATT_ERROR_INVALID_PDU
        return;
    }

    let opcode_byte = value[0];

    // Dispatch the command to the McsCallback. The callback returns true
    // for success or false when the operation cannot be performed (e.g.,
    // media player is inactive).
    let result = {
        let inner = server.lock().unwrap();
        match CpOpcode::from_u8(opcode_byte) {
            Some(CpOpcode::Play) => inner.callbacks.play(),
            Some(CpOpcode::Pause) => inner.callbacks.pause(),
            Some(CpOpcode::FastRewind) => inner.callbacks.fast_rewind(),
            Some(CpOpcode::FastForward) => inner.callbacks.fast_forward(),
            Some(CpOpcode::Stop) => inner.callbacks.stop(),
            Some(CpOpcode::MoveRelative) if value.len() >= 5 => {
                let offset = i32::from_le_bytes([value[1], value[2], value[3], value[4]]);
                inner.callbacks.move_relative(offset)
            }
            Some(CpOpcode::PrevSegment) => inner.callbacks.previous_segment(),
            Some(CpOpcode::NextSegment) => inner.callbacks.next_segment(),
            Some(CpOpcode::FirstSegment) => inner.callbacks.first_segment(),
            Some(CpOpcode::LastSegment) => inner.callbacks.last_segment(),
            Some(CpOpcode::GotoSegment) if value.len() >= 5 => {
                let n = i32::from_le_bytes([value[1], value[2], value[3], value[4]]);
                inner.callbacks.goto_segment(n)
            }
            Some(CpOpcode::PrevTrack) => inner.callbacks.previous_track(),
            Some(CpOpcode::NextTrack) => inner.callbacks.next_track(),
            Some(CpOpcode::FirstTrack) => inner.callbacks.first_track(),
            Some(CpOpcode::LastTrack) => inner.callbacks.last_track(),
            Some(CpOpcode::GotoTrack) if value.len() >= 5 => {
                let n = i32::from_le_bytes([value[1], value[2], value[3], value[4]]);
                inner.callbacks.goto_track(n)
            }
            Some(CpOpcode::PrevGroup) => inner.callbacks.previous_group(),
            Some(CpOpcode::NextGroup) => inner.callbacks.next_group(),
            Some(CpOpcode::FirstGroup) => inner.callbacks.first_group(),
            Some(CpOpcode::LastGroup) => inner.callbacks.last_group(),
            Some(CpOpcode::GotoGroup) if value.len() >= 5 => {
                let n = i32::from_le_bytes([value[1], value[2], value[3], value[4]]);
                inner.callbacks.goto_group(n)
            }
            _ => false,
        }
    };

    // Acknowledge the write to the GATT client.
    attr.write_result(id, 0);

    // Determine the CP response result code.
    let result_code =
        if result { McsResult::Success as u8 } else { McsResult::MediaPlayerInactive as u8 };

    // Determine state transitions for successful commands.
    if result {
        let mut inner = server.lock().unwrap();
        let new_state = match CpOpcode::from_u8(opcode_byte) {
            Some(CpOpcode::Play) => Some(MediaState::Playing),
            Some(CpOpcode::Pause) => Some(MediaState::Paused),
            Some(CpOpcode::Stop) => Some(MediaState::Paused),
            Some(CpOpcode::FastRewind) | Some(CpOpcode::FastForward) => Some(MediaState::Seeking),
            _ => None,
        };
        if let Some(ns) = new_state {
            if inner.media_state != ns {
                inner.media_state = ns;
                let state_handle = inner.handles.media_state;
                let db = inner.db.clone();
                drop(inner);
                // Notify state change.
                if let Some(state_attr) = db.get_attribute(state_handle) {
                    state_attr.notify(&[ns as u8], None);
                }
            } else {
                drop(inner);
            }
        } else {
            drop(inner);
        }

        // For Stop: also notify track position reset to 0.
        if CpOpcode::from_u8(opcode_byte) == Some(CpOpcode::Stop) {
            let inner = server.lock().unwrap();
            let tp_handle = inner.handles.track_position;
            let db = inner.db.clone();
            drop(inner);
            if let Some(tp_attr) = db.get_attribute(tp_handle) {
                tp_attr.notify(&[0, 0, 0, 0], None);
            }
        }
    }

    // Send CP result notification: [opcode, result_code].
    let inner = server.lock().unwrap();
    let cp_handle = inner.handles.media_cp;
    let db = inner.db.clone();
    drop(inner);
    if let Some(cp_attr) = db.get_attribute(cp_handle) {
        cp_attr.notify(&[opcode_byte, result_code], None);
    }
}

// =====================================================================
// MCP Client — Internal Structures
// =====================================================================

/// Per-characteristic handle mapping for a discovered MCP service instance.
struct McpServiceHandles {
    /// Service declaration handle.
    service_handle: u16,
    /// CCID for this service instance.
    ccid: u8,
    /// Whether this is GMCS.
    is_gmcs: bool,
    /// Media Player Name value handle.
    media_player_name: u16,
    /// Track Changed value handle.
    track_changed: u16,
    /// Track Title value handle.
    track_title: u16,
    /// Track Duration value handle.
    track_duration: u16,
    /// Track Position value handle.
    track_position: u16,
    /// Playback Speed value handle.
    playback_speed: u16,
    /// Seeking Speed value handle.
    seeking_speed: u16,
    /// Playing Order value handle.
    playing_order: u16,
    /// Playing Order Supported value handle.
    playing_order_supported: u16,
    /// Media State value handle.
    media_state: u16,
    /// Media Control Point value handle.
    media_cp: u16,
    /// Media Control Point Opcodes Supported value handle.
    media_cp_op_supported: u16,
    /// Content Control ID value handle.
    ccid_value: u16,
    /// Cached supported playing order bitfield.
    playing_order_supported_val: u16,
    /// Cached supported commands bitfield.
    cmd_supported_val: u32,
}

impl McpServiceHandles {
    fn new(service_handle: u16, is_gmcs: bool) -> Self {
        Self {
            service_handle,
            ccid: 0,
            is_gmcs,
            media_player_name: 0,
            track_changed: 0,
            track_title: 0,
            track_duration: 0,
            track_position: 0,
            playback_speed: 0,
            seeking_speed: 0,
            playing_order: 0,
            playing_order_supported: 0,
            media_state: 0,
            media_cp: 0,
            media_cp_op_supported: 0,
            ccid_value: 0,
            playing_order_supported_val: 0,
            cmd_supported_val: 0,
        }
    }
}

/// A pending MCP GATT write operation.
struct McpPending {
    /// Unique operation ID.
    id: u32,
    /// CP opcode (for matching completion callbacks).
    op: u8,
    /// CCID of the target service.
    ccid: u8,
    /// GATT client write request ID.
    client_id: u32,
}

/// Per-service notification registration IDs.
struct McpNotifyIds {
    ids: Vec<u32>,
}

/// Internal mutable state of an MCP client instance.
struct BtMcpInner {
    /// Whether discovering GMCS (true) or MCS (false).
    gmcs: bool,
    /// GATT client engine.
    client: Arc<BtGattClient>,
    /// Idle callback registration ID for ready notification.
    idle_id: u32,
    /// GattDb service change notification ID.
    db_id: u32,
    /// Whether the client has fired the ready callback.
    ready: bool,
    /// Discovered service instances.
    services: Vec<McpServiceHandles>,
    /// Per-service notification registration IDs.
    notify_ids: Vec<McpNotifyIds>,
    /// Pending GATT write operations.
    pending: Vec<McpPending>,
    /// Next pending operation ID (wrapping).
    next_pending_id: u32,
    /// Client-side callbacks.
    callbacks: Arc<dyn McpCallback>,
    /// Per-CCID listener callbacks.
    listeners: Vec<(u8, Arc<dyn McpListenerCallback>)>,
}

// =====================================================================
// BtMcp — Public MCP Client API
// =====================================================================

/// MCP client instance for discovering and controlling remote MCS/GMCS
/// services.
///
/// Wraps `Arc<Mutex<BtMcpInner>>` for shared ownership.
#[derive(Clone)]
pub struct BtMcp {
    inner: Arc<Mutex<BtMcpInner>>,
}

impl BtMcp {
    /// Attach an MCP client to a GATT client connection.
    ///
    /// Discovers GMCS or MCS services in the remote database, reads initial
    /// characteristic values, registers for notifications, and fires the
    /// `ready` callback when discovery completes.
    pub fn attach(
        client: Arc<BtGattClient>,
        gmcs: bool,
        callbacks: Arc<dyn McpCallback>,
    ) -> Arc<BtMcp> {
        let db = client.get_db();

        let inner = BtMcpInner {
            gmcs,
            client: Arc::clone(&client),
            idle_id: 0,
            db_id: 0,
            ready: false,
            services: Vec::new(),
            notify_ids: Vec::new(),
            pending: Vec::new(),
            next_pending_id: 1,
            callbacks,
            listeners: Vec::new(),
        };

        let mcp = Arc::new(BtMcp { inner: Arc::new(Mutex::new(inner)) });

        // Discover services in the remote database.
        let svc_uuid = if gmcs { BtUuid::from_u16(GMCS_UUID) } else { BtUuid::from_u16(MCS_UUID) };

        let mcp_clone = Arc::clone(&mcp);
        db.foreach_service(Some(&svc_uuid), move |attr| {
            mcp_discover_service(&mcp_clone, &attr);
        });

        // Register for DB service addition/removal notifications.
        let mcp_added = Arc::clone(&mcp);
        let mcp_removed = Arc::clone(&mcp);
        let db_id = db.register(
            Some(move |attr: GattDbAttribute| {
                mcp_service_added(&mcp_added, &attr);
            }),
            Some(move |attr: GattDbAttribute| {
                mcp_service_removed(&mcp_removed, &attr);
            }),
        );

        {
            let mut inner = mcp.inner.lock().unwrap();
            inner.db_id = db_id;

            // If no services were found, fire ready callback via idle.
            if inner.services.is_empty() {
                let mcp_idle = Arc::clone(&mcp);
                let idle_id = client.idle_register(Box::new(move || {
                    let mut inner = mcp_idle.inner.lock().unwrap();
                    if !inner.ready {
                        inner.ready = true;
                        let cb = Arc::clone(&inner.callbacks);
                        drop(inner);
                        cb.ready();
                    }
                }));
                inner.idle_id = idle_id;
            }
        }

        mcp
    }

    /// Detach the MCP client, cleaning up all resources.
    pub fn detach(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.callbacks.destroy();

        // Cancel all pending writes.
        for p in &inner.pending {
            if p.client_id != 0 {
                inner.client.cancel(p.client_id);
            }
        }
        inner.pending.clear();

        // Unregister all notification handlers.
        for nids in &inner.notify_ids {
            for &id in &nids.ids {
                inner.client.unregister_notify(id);
            }
        }
        inner.notify_ids.clear();

        // Destroy all listeners.
        for (_ccid, listener) in &inner.listeners {
            listener.destroy();
        }
        inner.listeners.clear();

        // Unregister idle callback.
        if inner.idle_id != 0 {
            inner.client.idle_unregister(inner.idle_id);
            inner.idle_id = 0;
        }

        // Unregister DB notification.
        if inner.db_id != 0 {
            let db = inner.client.get_db();
            db.unregister(inner.db_id);
            inner.db_id = 0;
        }

        inner.services.clear();
    }

    /// Add a listener for characteristic value change notifications for a
    /// specific CCID.
    pub fn add_listener(&self, ccid: u8, listener: Arc<dyn McpListenerCallback>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        // Verify the CCID exists in discovered services.
        let found = inner.services.iter().any(|s| s.ccid == ccid);
        if !found {
            return false;
        }
        inner.listeners.push((ccid, listener));
        true
    }

    // ---- Playback Control Commands ----

    /// Send Play command. Returns operation ID.
    pub fn play(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::Play as u8, None)
    }

    /// Send Pause command. Returns operation ID.
    pub fn pause(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::Pause as u8, None)
    }

    /// Send Fast Rewind command. Returns operation ID.
    pub fn fast_rewind(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::FastRewind as u8, None)
    }

    /// Send Fast Forward command. Returns operation ID.
    pub fn fast_forward(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::FastForward as u8, None)
    }

    /// Send Stop command. Returns operation ID.
    pub fn stop(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::Stop as u8, None)
    }

    /// Send Move Relative command. Returns operation ID.
    pub fn move_relative(&self, ccid: u8, offset: i32) -> u32 {
        self.mcp_command(ccid, CpOpcode::MoveRelative as u8, Some(offset))
    }

    // ---- Segment Navigation Commands ----

    /// Previous segment. Returns operation ID.
    pub fn previous_segment(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::PrevSegment as u8, None)
    }

    /// Next segment. Returns operation ID.
    pub fn next_segment(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::NextSegment as u8, None)
    }

    /// First segment. Returns operation ID.
    pub fn first_segment(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::FirstSegment as u8, None)
    }

    /// Last segment. Returns operation ID.
    pub fn last_segment(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::LastSegment as u8, None)
    }

    /// Goto specific segment. Returns operation ID.
    pub fn goto_segment(&self, ccid: u8, n: i32) -> u32 {
        self.mcp_command(ccid, CpOpcode::GotoSegment as u8, Some(n))
    }

    // ---- Track Navigation Commands ----

    /// Previous track. Returns operation ID.
    pub fn previous_track(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::PrevTrack as u8, None)
    }

    /// Next track. Returns operation ID.
    pub fn next_track(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::NextTrack as u8, None)
    }

    /// First track. Returns operation ID.
    pub fn first_track(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::FirstTrack as u8, None)
    }

    /// Last track. Returns operation ID.
    pub fn last_track(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::LastTrack as u8, None)
    }

    /// Goto specific track. Returns operation ID.
    pub fn goto_track(&self, ccid: u8, n: i32) -> u32 {
        self.mcp_command(ccid, CpOpcode::GotoTrack as u8, Some(n))
    }

    // ---- Group Navigation Commands ----

    /// Previous group. Returns operation ID.
    pub fn previous_group(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::PrevGroup as u8, None)
    }

    /// Next group. Returns operation ID.
    pub fn next_group(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::NextGroup as u8, None)
    }

    /// First group. Returns operation ID.
    pub fn first_group(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::FirstGroup as u8, None)
    }

    /// Last group. Returns operation ID.
    pub fn last_group(&self, ccid: u8) -> u32 {
        self.mcp_command(ccid, CpOpcode::LastGroup as u8, None)
    }

    /// Goto specific group. Returns operation ID.
    pub fn goto_group(&self, ccid: u8, n: i32) -> u32 {
        self.mcp_command(ccid, CpOpcode::GotoGroup as u8, Some(n))
    }

    // ---- Set Value Commands ----

    /// Set the track position for a specific CCID. Returns operation ID.
    pub fn set_track_position(&self, ccid: u8, position: i32) -> u32 {
        let inner = self.inner.lock().unwrap();
        let svc = match inner.services.iter().find(|s| s.ccid == ccid) {
            Some(s) => s,
            None => return 0,
        };
        let handle = svc.track_position;
        if handle == 0 {
            return 0;
        }
        let value = (position as u32).to_le_bytes();
        let client = Arc::clone(&inner.client);
        drop(inner);

        let mcp_ref = self.inner.clone();
        let pending_id = {
            let mut inner = mcp_ref.lock().unwrap();
            let id = inner.next_pending_id;
            inner.next_pending_id = inner.next_pending_id.wrapping_add(1);
            if inner.next_pending_id == 0 {
                inner.next_pending_id = 1;
            }
            id
        };

        let mcp_cb = self.inner.clone();
        let client_id = client.write_value(
            handle,
            &value,
            Box::new(move |success, att_ecode| {
                let inner = mcp_cb.lock().unwrap();
                let cb = Arc::clone(&inner.callbacks);
                drop(inner);
                cb.complete(pending_id, if success { 0 } else { att_ecode });
            }),
        );

        if client_id == 0 {
            return 0;
        }

        {
            let mut inner = mcp_ref.lock().unwrap();
            inner.pending.push(McpPending {
                id: pending_id,
                op: 0, // Not a CP command
                ccid,
                client_id,
            });
        }
        pending_id
    }

    /// Set the playback speed for a specific CCID. Returns operation ID.
    pub fn set_playback_speed(&self, ccid: u8, speed: i8) -> u32 {
        let inner = self.inner.lock().unwrap();
        let svc = match inner.services.iter().find(|s| s.ccid == ccid) {
            Some(s) => s,
            None => return 0,
        };
        let handle = svc.playback_speed;
        if handle == 0 {
            return 0;
        }
        let value = [speed as u8];
        let client = Arc::clone(&inner.client);
        drop(inner);

        let mcp_ref = self.inner.clone();
        let pending_id = {
            let mut inner = mcp_ref.lock().unwrap();
            let id = inner.next_pending_id;
            inner.next_pending_id = inner.next_pending_id.wrapping_add(1);
            if inner.next_pending_id == 0 {
                inner.next_pending_id = 1;
            }
            id
        };

        let mcp_cb = self.inner.clone();
        let client_id = client.write_value(
            handle,
            &value,
            Box::new(move |success, att_ecode| {
                let inner = mcp_cb.lock().unwrap();
                let cb = Arc::clone(&inner.callbacks);
                drop(inner);
                cb.complete(pending_id, if success { 0 } else { att_ecode });
            }),
        );

        if client_id == 0 {
            return 0;
        }

        {
            let mut inner = mcp_ref.lock().unwrap();
            inner.pending.push(McpPending { id: pending_id, op: 0, ccid, client_id });
        }
        pending_id
    }

    /// Set the playing order for a specific CCID. Returns operation ID.
    ///
    /// Validates that the requested order is supported by the remote player
    /// before sending the write.
    pub fn set_playing_order(&self, ccid: u8, order: u8) -> u32 {
        let inner = self.inner.lock().unwrap();
        let svc = match inner.services.iter().find(|s| s.ccid == ccid) {
            Some(s) => s,
            None => return 0,
        };

        // Check if the order is supported.
        let supported =
            McsPlayingOrderSupported::from_bits_truncate(svc.playing_order_supported_val);
        if !playing_order_supported(order, supported) {
            debug!("MCP set_playing_order: order 0x{:02x} not supported", order);
            return 0;
        }

        let handle = svc.playing_order;
        if handle == 0 {
            return 0;
        }
        let value = [order];
        let client = Arc::clone(&inner.client);
        drop(inner);

        let mcp_ref = self.inner.clone();
        let pending_id = {
            let mut inner = mcp_ref.lock().unwrap();
            let id = inner.next_pending_id;
            inner.next_pending_id = inner.next_pending_id.wrapping_add(1);
            if inner.next_pending_id == 0 {
                inner.next_pending_id = 1;
            }
            id
        };

        let mcp_cb = self.inner.clone();
        let client_id = client.write_value(
            handle,
            &value,
            Box::new(move |success, att_ecode| {
                let inner = mcp_cb.lock().unwrap();
                let cb = Arc::clone(&inner.callbacks);
                drop(inner);
                cb.complete(pending_id, if success { 0 } else { att_ecode });
            }),
        );

        if client_id == 0 {
            return 0;
        }

        {
            let mut inner = mcp_ref.lock().unwrap();
            inner.pending.push(McpPending { id: pending_id, op: 0, ccid, client_id });
        }
        pending_id
    }

    // ---- Query Functions ----

    /// Get the supported playing order bitfield for a specific CCID.
    pub fn get_supported_playing_order(&self, ccid: u8) -> u16 {
        let inner = self.inner.lock().unwrap();
        inner
            .services
            .iter()
            .find(|s| s.ccid == ccid)
            .map(|s| s.playing_order_supported_val)
            .unwrap_or(0)
    }

    /// Get the supported commands bitfield for a specific CCID.
    pub fn get_supported_commands(&self, ccid: u8) -> u32 {
        let inner = self.inner.lock().unwrap();
        inner.services.iter().find(|s| s.ccid == ccid).map(|s| s.cmd_supported_val).unwrap_or(0)
    }

    // ---- Internal Command Dispatch ----

    /// Internal: Send an MCS control point command via Write Without Response.
    fn mcp_command(&self, ccid: u8, op: u8, arg: Option<i32>) -> u32 {
        let mut inner = self.inner.lock().unwrap();
        let svc = match inner.services.iter().find(|s| s.ccid == ccid) {
            Some(s) => s,
            None => {
                debug!("MCP command: no service for ccid={}", ccid);
                return 0;
            }
        };

        let handle = svc.media_cp;
        if handle == 0 {
            debug!("MCP command: no media CP handle for ccid={}", ccid);
            return 0;
        }

        // Check if the command is supported.
        let cmd = match find_command(op) {
            Some(c) => c,
            None => {
                debug!("MCP command: unknown opcode 0x{:02x}", op);
                return 0;
            }
        };

        let supported = McsCmdSupported::from_bits_truncate(svc.cmd_supported_val);
        if !supported.contains(cmd.support) {
            debug!("MCP command: {} not supported", cmd.name);
            return 0;
        }

        // Validate argument presence matches command descriptor.
        if cmd.has_int32_arg && arg.is_none() {
            debug!("MCP command: {} requires int32 argument", cmd.name);
            return 0;
        }

        // Enforce pending limit.
        if inner.pending.len() >= MAX_PENDING {
            warn!("MCP command: too many pending operations");
            return 0;
        }

        // Allocate pending ID.
        let pending_id = inner.next_pending_id;
        inner.next_pending_id = inner.next_pending_id.wrapping_add(1);
        if inner.next_pending_id == 0 {
            inner.next_pending_id = 1;
        }

        // Build command PDU.
        let mut buf = IoBuf::with_capacity(5);
        buf.push_u8(op);
        if let Some(val) = arg {
            buf.push_le32(val as u32);
        }

        let client = Arc::clone(&inner.client);

        // Use Write Without Response for CP commands.
        let client_id = client.write_without_response(handle, false, buf.as_bytes());

        if client_id == 0 {
            debug!("MCP command: write_without_response failed");
            return 0;
        }

        inner.pending.push(McpPending { id: pending_id, op, ccid, client_id });

        drop(inner);

        debug!("MCP command: {} (op=0x{:02x}) sent, id={}", cmd.name, op, pending_id);
        pending_id
    }
}

/// Get a reference to the underlying GATT client (for testing).
pub fn bt_mcp_test_util_get_client(mcp: &BtMcp) -> Arc<BtGattClient> {
    let inner = mcp.inner.lock().unwrap();
    Arc::clone(&inner.client)
}

// =====================================================================
// MCP Client — Service Discovery Helpers
// =====================================================================

/// Discover an MCS/GMCS service and enumerate its characteristics.
fn mcp_discover_service(mcp: &Arc<BtMcp>, attr: &GattDbAttribute) {
    let svc_uuid = match attr.get_service_uuid() {
        Some(u) => u,
        None => return,
    };

    let is_gmcs = svc_uuid == BtUuid::from_u16(GMCS_UUID);
    let is_mcs = svc_uuid == BtUuid::from_u16(MCS_UUID);

    if !is_gmcs && !is_mcs {
        return;
    }

    let svc_handle = attr.get_handle();
    let mut handles = McpServiceHandles::new(svc_handle, is_gmcs);

    // Get the service handle for iteration.
    let db = {
        let inner = mcp.inner.lock().unwrap();
        inner.client.get_db()
    };

    if let Some(_svc) = db.get_service(svc_handle) {
        // First pass: find CCID characteristic.
        let svc_obj = gatt_db_service_from_attr(&db, svc_handle);
        if let Some(ref svc_obj) = svc_obj {
            svc_obj.foreach_char(|char_attr| {
                if let Some(char_data) = char_attr.get_char_data() {
                    if char_data.uuid == BtUuid::from_u16(MCS_CCID_CHRC_UUID) {
                        handles.ccid_value = char_data.value_handle;
                    }
                }
            });
        }

        // Second pass: map all characteristic UUIDs to handles.
        if let Some(ref svc_obj) = svc_obj {
            svc_obj.foreach_char(|char_attr| {
                if let Some(char_data) = char_attr.get_char_data() {
                    map_chrc_uuid_to_handle(&mut handles, &char_data);
                }
            });
        }
    }

    // Read the CCID value.
    let ccid_handle = handles.ccid_value;
    if ccid_handle != 0 {
        let mcp_clone = Arc::clone(mcp);
        let inner = mcp.inner.lock().unwrap();
        let client = Arc::clone(&inner.client);
        drop(inner);

        client.read_value(
            ccid_handle,
            Box::new(move |success, _ecode, data| {
                if success && !data.is_empty() {
                    let ccid = data[0];
                    let mut inner = mcp_clone.inner.lock().unwrap();

                    // Update CCID and store handles.
                    let svc_idx = inner.services.len();
                    let mut h = handles;
                    h.ccid = ccid;
                    inner.services.push(h);

                    let is_gmcs_val = inner.services[svc_idx].is_gmcs;
                    let cb = Arc::clone(&inner.callbacks);
                    let client = Arc::clone(&inner.client);
                    drop(inner);

                    // Notify callback about new CCID.
                    cb.ccid(ccid, is_gmcs_val);

                    // Read all other characteristics and register notifications.
                    mcp_read_characteristics(&mcp_clone, svc_idx, &client);

                    // Check if we should fire the ready callback.
                    mcp_check_ready(&mcp_clone, &client);
                }
            }),
        );
    }

    // Store service handles even if CCID read hasn't completed yet.
    // (Will be updated when CCID read completes.)
}

/// Helper to construct a GattDbService from a service declaration handle.
fn gatt_db_service_from_attr(db: &GattDb, handle: u16) -> Option<GattDbService> {
    // GattDb doesn't directly expose GattDbService construction from a handle,
    // but get_attribute + get_service achieves the same thing via the service
    // method on GattDbAttribute.
    let attr = db.get_attribute(handle)?;
    let svc = attr.get_service()?;
    Some(svc)
}

/// Map a characteristic's UUID to the appropriate handle in McpServiceHandles.
fn map_chrc_uuid_to_handle(handles: &mut McpServiceHandles, char_data: &CharData) {
    let uuid_val = match char_data.uuid {
        BtUuid::Uuid16(v) => v,
        _ => return,
    };

    let vh = char_data.value_handle;

    match uuid_val {
        MCS_MEDIA_PLAYER_NAME_CHRC_UUID => handles.media_player_name = vh,
        MCS_TRACK_CHANGED_CHRC_UUID => handles.track_changed = vh,
        MCS_TRACK_TITLE_CHRC_UUID => handles.track_title = vh,
        MCS_TRACK_DURATION_CHRC_UUID => handles.track_duration = vh,
        MCS_TRACK_POSITION_CHRC_UUID => handles.track_position = vh,
        MCS_PLAYBACK_SPEED_CHRC_UUID => handles.playback_speed = vh,
        MCS_SEEKING_SPEED_CHRC_UUID => handles.seeking_speed = vh,
        MCS_PLAYING_ORDER_CHRC_UUID => handles.playing_order = vh,
        MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID => handles.playing_order_supported = vh,
        MCS_MEDIA_STATE_CHRC_UUID => handles.media_state = vh,
        MCS_MEDIA_CP_CHRC_UUID => handles.media_cp = vh,
        MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID => handles.media_cp_op_supported = vh,
        MCS_CCID_CHRC_UUID => handles.ccid_value = vh,
        _ => {}
    }
}

/// Read initial characteristic values and register for notifications.
fn mcp_read_characteristics(mcp: &Arc<BtMcp>, svc_idx: usize, client: &Arc<BtGattClient>) {
    let inner = mcp.inner.lock().unwrap();
    if svc_idx >= inner.services.len() {
        return;
    }
    let svc = &inner.services[svc_idx];

    // Characteristic handles that need initial reads.
    let read_handles: Vec<(u16, u16)> = vec![
        (svc.media_player_name, MCS_MEDIA_PLAYER_NAME_CHRC_UUID),
        (svc.track_title, MCS_TRACK_TITLE_CHRC_UUID),
        (svc.track_duration, MCS_TRACK_DURATION_CHRC_UUID),
        (svc.track_position, MCS_TRACK_POSITION_CHRC_UUID),
        (svc.playback_speed, MCS_PLAYBACK_SPEED_CHRC_UUID),
        (svc.seeking_speed, MCS_SEEKING_SPEED_CHRC_UUID),
        (svc.playing_order, MCS_PLAYING_ORDER_CHRC_UUID),
        (svc.playing_order_supported, MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID),
        (svc.media_state, MCS_MEDIA_STATE_CHRC_UUID),
        (svc.media_cp_op_supported, MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID),
    ];

    // Characteristic handles that need notification registration.
    let notify_handles: Vec<u16> = vec![
        svc.media_player_name,
        svc.track_changed,
        svc.track_title,
        svc.track_duration,
        svc.track_position,
        svc.playback_speed,
        svc.seeking_speed,
        svc.playing_order,
        svc.media_state,
        svc.media_cp,
        svc.media_cp_op_supported,
    ];

    let ccid = svc.ccid;
    drop(inner);

    // Register for notifications on each characteristic.
    let mut notify_ids = McpNotifyIds { ids: Vec::new() };
    for handle in &notify_handles {
        if *handle == 0 {
            continue;
        }
        let h = *handle;
        let mcp_notify = Arc::clone(mcp);
        let reg_id = client.register_notify(
            h,
            Box::new(|_ecode| {
                // Notification registration complete (ignore errors).
            }),
            Box::new(move |_value_handle, data| {
                mcp_handle_notification(&mcp_notify, ccid, h, data);
            }),
        );
        if reg_id != 0 {
            notify_ids.ids.push(reg_id);
        }
    }

    {
        let mut inner = mcp.inner.lock().unwrap();
        inner.notify_ids.push(notify_ids);
    }

    // Read initial values.
    for (handle, uuid) in &read_handles {
        if *handle == 0 {
            continue;
        }
        let h = *handle;
        let u = *uuid;
        let mcp_read = Arc::clone(mcp);
        client.read_value(
            h,
            Box::new(move |success, _ecode, data| {
                if success {
                    mcp_update_cached_value(&mcp_read, ccid, u, data);
                }
            }),
        );
    }
}

/// Handle an incoming GATT notification for an MCP-monitored characteristic.
fn mcp_handle_notification(mcp: &Arc<BtMcp>, ccid: u8, handle: u16, data: &[u8]) {
    // Gather service state and listener list under a single lock, then
    // release before any callback dispatch to avoid deadlock.
    let (uuid, listeners) = {
        let inner = mcp.inner.lock().unwrap();
        let svc = match inner.services.iter().find(|s| s.ccid == ccid) {
            Some(s) => s,
            None => return,
        };

        let uuid = match handle_to_uuid(svc, handle) {
            Some(u) => u,
            None => return,
        };

        let listeners: Vec<Arc<dyn McpListenerCallback>> = inner
            .listeners
            .iter()
            .filter(|(c, _)| *c == ccid)
            .map(|(_, l)| Arc::clone(l))
            .collect();

        // Update cached values while we still have the lock.
        if uuid != MCS_MEDIA_CP_CHRC_UUID {
            mcp_update_cached_value_inner(svc, uuid, data);
        }

        (uuid, listeners)
    };
    // Lock is now released — safe to dispatch callbacks.

    // For CP response, handle completion callback.
    if uuid == MCS_MEDIA_CP_CHRC_UUID && data.len() >= 2 {
        let op = data[0];
        let result = data[1];
        let mut inner = mcp.inner.lock().unwrap();
        if let Some(pos) = inner.pending.iter().position(|p| p.op == op && p.ccid == ccid) {
            let pending = inner.pending.remove(pos);
            let cb = Arc::clone(&inner.callbacks);
            drop(inner);
            cb.complete(pending.id, result);
        }
        return;
    }

    // Notify listeners.
    for listener in &listeners {
        dispatch_listener_notification(listener, uuid, data);
    }

    // For media player name change, re-read all characteristics.
    if uuid == MCS_MEDIA_PLAYER_NAME_CHRC_UUID {
        let (client, svc_idx) = {
            let inner = mcp.inner.lock().unwrap();
            let client = Arc::clone(&inner.client);
            let idx = inner.services.iter().position(|s| s.ccid == ccid);
            (client, idx)
        };
        if let Some(idx) = svc_idx {
            mcp_read_characteristics(mcp, idx, &client);
        }
    }
}

/// Map a value handle back to the characteristic UUID for a service.
fn handle_to_uuid(svc: &McpServiceHandles, handle: u16) -> Option<u16> {
    if handle == svc.media_player_name {
        return Some(MCS_MEDIA_PLAYER_NAME_CHRC_UUID);
    }
    if handle == svc.track_changed {
        return Some(MCS_TRACK_CHANGED_CHRC_UUID);
    }
    if handle == svc.track_title {
        return Some(MCS_TRACK_TITLE_CHRC_UUID);
    }
    if handle == svc.track_duration {
        return Some(MCS_TRACK_DURATION_CHRC_UUID);
    }
    if handle == svc.track_position {
        return Some(MCS_TRACK_POSITION_CHRC_UUID);
    }
    if handle == svc.playback_speed {
        return Some(MCS_PLAYBACK_SPEED_CHRC_UUID);
    }
    if handle == svc.seeking_speed {
        return Some(MCS_SEEKING_SPEED_CHRC_UUID);
    }
    if handle == svc.playing_order {
        return Some(MCS_PLAYING_ORDER_CHRC_UUID);
    }
    if handle == svc.playing_order_supported {
        return Some(MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID);
    }
    if handle == svc.media_state {
        return Some(MCS_MEDIA_STATE_CHRC_UUID);
    }
    if handle == svc.media_cp {
        return Some(MCS_MEDIA_CP_CHRC_UUID);
    }
    if handle == svc.media_cp_op_supported {
        return Some(MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID);
    }
    if handle == svc.ccid_value {
        return Some(MCS_CCID_CHRC_UUID);
    }
    None
}

/// Update cached values from GATT read results or notifications.
fn mcp_update_cached_value(mcp: &Arc<BtMcp>, ccid: u8, uuid: u16, data: &[u8]) {
    let mut inner = mcp.inner.lock().unwrap();
    if let Some(svc) = inner.services.iter_mut().find(|s| s.ccid == ccid) {
        match uuid {
            MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID if data.len() >= 2 => {
                svc.playing_order_supported_val = u16::from_le_bytes([data[0], data[1]]);
            }
            MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID if data.len() >= 4 => {
                svc.cmd_supported_val = get_le32(data);
            }
            _ => {}
        }
    }

    // Dispatch to listeners.
    let listeners: Vec<Arc<dyn McpListenerCallback>> =
        inner.listeners.iter().filter(|(c, _)| *c == ccid).map(|(_, l)| Arc::clone(l)).collect();
    drop(inner);

    for listener in &listeners {
        dispatch_listener_notification(listener, uuid, data);
    }
}

/// Update cached values on the service handles (non-locking variant).
fn mcp_update_cached_value_inner(_svc: &McpServiceHandles, _uuid: u16, _data: &[u8]) {
    // Cached values are updated via mcp_update_cached_value which takes
    // the lock. This function exists for the notification path where the
    // inner lock is already held. In practice, the playing_order_supported
    // and cmd_supported values are only updated from mcp_update_cached_value.
}

/// Dispatch a notification to a listener based on UUID.
fn dispatch_listener_notification(listener: &Arc<dyn McpListenerCallback>, uuid: u16, data: &[u8]) {
    match uuid {
        MCS_MEDIA_PLAYER_NAME_CHRC_UUID => listener.media_player_name(data),
        MCS_TRACK_CHANGED_CHRC_UUID => listener.track_changed(),
        MCS_TRACK_TITLE_CHRC_UUID => listener.track_title(data),
        MCS_TRACK_DURATION_CHRC_UUID => {
            if data.len() >= 4 {
                let duration = get_le32(data) as i32;
                listener.track_duration(duration);
            }
        }
        MCS_TRACK_POSITION_CHRC_UUID => {
            if data.len() >= 4 {
                let position = get_le32(data) as i32;
                listener.track_position(position);
            }
        }
        MCS_PLAYBACK_SPEED_CHRC_UUID => {
            if !data.is_empty() {
                listener.playback_speed(data[0] as i8);
            }
        }
        MCS_SEEKING_SPEED_CHRC_UUID => {
            if !data.is_empty() {
                listener.seeking_speed(data[0] as i8);
            }
        }
        MCS_PLAYING_ORDER_CHRC_UUID => {
            if !data.is_empty() {
                listener.playing_order(data[0]);
            }
        }
        MCS_MEDIA_STATE_CHRC_UUID => {
            if !data.is_empty() {
                listener.media_state(data[0]);
            }
        }
        _ => {}
    }
}

/// Check if all services have been discovered and fire ready callback.
fn mcp_check_ready(mcp: &Arc<BtMcp>, client: &Arc<BtGattClient>) {
    let mut inner = mcp.inner.lock().unwrap();
    if inner.ready {
        return;
    }

    // Fire ready via idle callback to allow all reads to complete first.
    if inner.idle_id == 0 {
        let mcp_idle = Arc::clone(mcp);
        let idle_id = client.idle_register(Box::new(move || {
            let mut inner = mcp_idle.inner.lock().unwrap();
            if !inner.ready {
                inner.ready = true;
                let cb = Arc::clone(&inner.callbacks);
                drop(inner);
                cb.ready();
            }
        }));
        inner.idle_id = idle_id;
    }
}

/// Handle a new service being added to the remote GATT database.
fn mcp_service_added(mcp: &Arc<BtMcp>, attr: &GattDbAttribute) {
    let svc_uuid = match attr.get_service_uuid() {
        Some(u) => u,
        None => return,
    };

    let expected = {
        let inner = mcp.inner.lock().unwrap();
        if inner.gmcs { BtUuid::from_u16(GMCS_UUID) } else { BtUuid::from_u16(MCS_UUID) }
    };

    if svc_uuid == expected {
        mcp_discover_service(mcp, attr);
    }
}

/// Handle a service being removed from the remote GATT database.
fn mcp_service_removed(mcp: &Arc<BtMcp>, attr: &GattDbAttribute) {
    let handle = attr.get_handle();
    let mut inner = mcp.inner.lock().unwrap();
    inner.services.retain(|s| s.service_handle != handle);
}
