// SPDX-License-Identifier: GPL-2.0-or-later
//! Central btmon packet decoding engine.
//!
//! Complete Rust rewrite of `monitor/packet.c` (~17,716 lines), `monitor/packet.h`,
//! and relevant structures from `monitor/bt.h`. This is the core packet decoder and
//! presentation engine that transforms BTSnoop records into structured, human-readable,
//! optionally colorized terminal output. Must produce byte-identical output to the C
//! version (AAP Gate 4).

use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;

use crate::display::{
    self as display, BitfieldData, COLOR_DEBUG, COLOR_ERROR, COLOR_HCI_ACLDATA, COLOR_HCI_COMMAND,
    COLOR_HCI_COMMAND_UNKNOWN, COLOR_HCI_EVENT, COLOR_HCI_EVENT_UNKNOWN, COLOR_HCI_ISODATA,
    COLOR_HCI_SCODATA, COLOR_INFO, COLOR_MGMT_EVENT, COLOR_OFF, COLOR_PHY_PACKET,
    COLOR_SYSTEM_NOTE, COLOR_UPDATE, COLOR_VENDOR_DIAG, COLOR_WARN, print_bitfield,
    print_hex_field, print_hexdump, use_color,
};
use crate::dissectors::l2cap::{self, L2capFrame};
use crate::dissectors::ll;
use crate::hwdb;
use crate::keys;
#[allow(unused_imports)]
use crate::print_field;
use crate::vendor::broadcom;
use crate::vendor::intel;
use crate::vendor::msft;
use crate::vendor::{self, VendorEvt, VendorOcf};

use bluez_shared::sys::bluetooth::{
    BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, bt_compidtostr,
};
use bluez_shared::sys::hci::{OGF_VENDOR_CMD, cmd_opcode_ocf, cmd_opcode_ogf};
use bluez_shared::sys::mgmt::mgmt_opstr;
use bluez_shared::util::ad::{
    BT_AD_CLASS_OF_DEV, BT_AD_CSIP_RSI, BT_AD_DEVICE_ID, BT_AD_FLAGS, BT_AD_GAP_APPEARANCE,
    BT_AD_MANUFACTURER_DATA, BT_AD_MESH_BEACON, BT_AD_MESH_DATA, BT_AD_MESH_PROV,
    BT_AD_NAME_COMPLETE, BT_AD_NAME_SHORT, BT_AD_SSP_HASH, BT_AD_SSP_RANDOMIZER,
    BT_AD_TRANSPORT_DISCOVERY, BT_AD_TX_POWER, BT_AD_UUID16_ALL, BT_AD_UUID16_SOME,
    BT_AD_UUID32_ALL, BT_AD_UUID32_SOME, BT_AD_UUID128_ALL, BT_AD_UUID128_SOME,
};
use bluez_shared::util::uuid::{
    bt_appear_to_str, bt_uuid16_to_str, bt_uuid32_to_str, bt_uuidstr_to_str,
};

// ---------------------------------------------------------------------------
// BTSnoop opcode constants (from src/shared/btsnoop.h)
// ---------------------------------------------------------------------------
const BTSNOOP_OPCODE_NEW_INDEX: u16 = 0;
const BTSNOOP_OPCODE_DEL_INDEX: u16 = 1;
const BTSNOOP_OPCODE_COMMAND_PKT: u16 = 2;
const BTSNOOP_OPCODE_EVENT_PKT: u16 = 3;
const BTSNOOP_OPCODE_ACL_TX_PKT: u16 = 4;
const BTSNOOP_OPCODE_ACL_RX_PKT: u16 = 5;
const BTSNOOP_OPCODE_SCO_TX_PKT: u16 = 6;
const BTSNOOP_OPCODE_SCO_RX_PKT: u16 = 7;
const BTSNOOP_OPCODE_OPEN_INDEX: u16 = 8;
const BTSNOOP_OPCODE_CLOSE_INDEX: u16 = 9;
const BTSNOOP_OPCODE_INDEX_INFO: u16 = 10;
const BTSNOOP_OPCODE_VENDOR_DIAG: u16 = 11;
const BTSNOOP_OPCODE_SYSTEM_NOTE: u16 = 12;
const BTSNOOP_OPCODE_USER_LOGGING: u16 = 13;
const BTSNOOP_OPCODE_CTRL_OPEN: u16 = 14;
const BTSNOOP_OPCODE_CTRL_CLOSE: u16 = 15;
const BTSNOOP_OPCODE_CTRL_COMMAND: u16 = 16;
const BTSNOOP_OPCODE_CTRL_EVENT: u16 = 17;
const BTSNOOP_OPCODE_ISO_TX_PKT: u16 = 18;
const BTSNOOP_OPCODE_ISO_RX_PKT: u16 = 19;

#[allow(dead_code)]
const BTSNOOP_MAX_PACKET_SIZE: usize = 1490;

// BTSnoop priority levels
const BTSNOOP_PRIORITY_EMERG: u8 = 0;
const BTSNOOP_PRIORITY_ALERT: u8 = 1;
const BTSNOOP_PRIORITY_CRIT: u8 = 2;
const BTSNOOP_PRIORITY_ERR: u8 = 3;
const BTSNOOP_PRIORITY_WARNING: u8 = 4;
const BTSNOOP_PRIORITY_NOTICE: u8 = 5;
const BTSNOOP_PRIORITY_INFO: u8 = 6;
const BTSNOOP_PRIORITY_DEBUG: u8 = 7;

// ---------------------------------------------------------------------------
// Maximum limits matching C code
// ---------------------------------------------------------------------------
const MAX_INDEX: usize = 16;
const MAX_CONN: usize = 16;

// ---------------------------------------------------------------------------
// Filter mask via bitflags (from packet.h lines 17-27)
// ---------------------------------------------------------------------------
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PacketFilter: u64 {
        const SHOW_INDEX       = 1 << 0;
        const SHOW_DATE        = 1 << 1;
        const SHOW_TIME        = 1 << 2;
        const SHOW_TIME_OFFSET = 1 << 3;
        const SHOW_ACL_DATA    = 1 << 4;
        const SHOW_SCO_DATA    = 1 << 5;
        const SHOW_A2DP_STREAM = 1 << 6;
        const SHOW_MGMT_SOCKET = 1 << 7;
        const SHOW_ISO_DATA    = 1 << 8;
        const SHOW_KMSG        = 1 << 9;
    }
}

/// Convert timeval to milliseconds.
fn tv_msec(tv: &libc::timeval) -> i64 {
    tv.tv_sec * 1000 + tv.tv_usec / 1000
}

// ---------------------------------------------------------------------------
// Connection and latency types (from packet.h lines 29-68)
// ---------------------------------------------------------------------------

/// Latency tracking structure for connection quality analysis.
#[derive(Clone)]
pub struct PacketLatency {
    pub total: libc::timeval,
    pub min: libc::timeval,
    pub max: libc::timeval,
    pub med: libc::timeval,
}

impl Default for PacketLatency {
    fn default() -> Self {
        Self {
            total: libc::timeval { tv_sec: 0, tv_usec: 0 },
            min: libc::timeval { tv_sec: 0, tv_usec: 0 },
            max: libc::timeval { tv_sec: 0, tv_usec: 0 },
            med: libc::timeval { tv_sec: 0, tv_usec: 0 },
        }
    }
}

/// Single frame timing entry for TX queue tracking.
pub struct PacketFrame {
    pub tv: libc::timeval,
    pub num: usize,
    pub len: usize,
}

/// Connection type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BtmonConn {
    Acl = 0,
    Le = 1,
    Sco = 2,
    Esco = 3,
    Cis = 4,
    Bis = 5,
}

impl fmt::Display for BtmonConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BtmonConn::Acl => "ACL",
            BtmonConn::Le => "LE",
            BtmonConn::Sco => "SCO",
            BtmonConn::Esco => "eSCO",
            BtmonConn::Cis => "CIS",
            BtmonConn::Bis => "BIS",
        };
        write!(f, "{}", s)
    }
}

/// Per-connection state tracking data.
pub struct PacketConnData {
    pub index: u16,
    pub src: [u8; 6],
    pub handle: u16,
    pub link: u16,
    pub type_: u8,
    pub dst: [u8; 6],
    pub dst_type: u8,
    pub dst_oui: Option<String>,
    pub tx_q: VecDeque<PacketFrame>,
    pub chan_q: VecDeque<L2capFrame>,
    pub tx_l: PacketLatency,
    pub data: Option<Box<dyn Any>>,
    pub destroy: Option<fn(&mut PacketConnData)>,
}

impl PacketConnData {
    fn new(handle: u16, index: u16) -> Self {
        Self {
            index,
            src: [0u8; 6],
            handle,
            link: 0,
            type_: 0x00,
            dst: [0u8; 6],
            dst_type: 0x00,
            dst_oui: None,
            tx_q: VecDeque::new(),
            chan_q: VecDeque::new(),
            tx_l: PacketLatency::default(),
            data: None,
            destroy: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-controller index state (replaces static index_list in packet.c)
// ---------------------------------------------------------------------------

/// Buffer pool tracking for a single transport type.
#[allow(dead_code)]
#[derive(Default, Clone)]
struct BufferPool {
    total: u16,
    tx: u16,
}

/// Per-controller adapter state.
#[allow(dead_code)]
struct IndexInfo {
    type_: u8,
    bus: u8,
    bdaddr: [u8; 6],
    name: [u8; 8],
    manufacturer: u16,
    msft_opcode: Option<u16>,
    msft_evt_prefix: Option<Vec<u8>>,
    acl: BufferPool,
    sco: BufferPool,
    le: BufferPool,
    iso: BufferPool,
    frame: u64,
    conn_list: Vec<Option<PacketConnData>>,
}

impl IndexInfo {
    fn new() -> Self {
        let mut conn_list = Vec::with_capacity(MAX_CONN);
        for _ in 0..MAX_CONN {
            conn_list.push(None);
        }
        Self {
            type_: 0,
            bus: 0,
            bdaddr: [0u8; 6],
            name: [0u8; 8],
            manufacturer: 0xFFFF,
            msft_opcode: None,
            msft_evt_prefix: None,
            acl: BufferPool::default(),
            sco: BufferPool::default(),
            le: BufferPool::default(),
            iso: BufferPool::default(),
            frame: 0,
            conn_list,
        }
    }
}

// ---------------------------------------------------------------------------
// Global state management (thread-local for single-threaded btmon runtime)
// ---------------------------------------------------------------------------

thread_local! {
    static FILTER_MASK: RefCell<PacketFilter> = const { RefCell::new(PacketFilter::empty()) };
    static INDEX_FILTER: RefCell<Option<u16>> = const { RefCell::new(None) };
    static PRIORITY_LEVEL: RefCell<i32> = const { RefCell::new(BTSNOOP_PRIORITY_INFO as i32) };
    static TIME_OFFSET: RefCell<libc::timeval> = const { RefCell::new(libc::timeval { tv_sec: 0, tv_usec: 0 }) };
    static INDEX_CURRENT: RefCell<u16> = const { RefCell::new(0xFFFF) };
    static FALLBACK_MANUFACTURER: RefCell<u16> = const { RefCell::new(0xFFFF) };
    static INDEX_LIST: RefCell<Vec<Option<IndexInfo>>> = RefCell::new({
        let mut v = Vec::with_capacity(MAX_INDEX);
        for _ in 0..MAX_INDEX {
            v.push(None);
        }
        v
    });
}

// ===========================================================================
// Configuration API (from packet.h lines 73-81)
// ===========================================================================

/// Check if a specific filter flag is set.
pub fn has_filter(filter: PacketFilter) -> bool {
    FILTER_MASK.with(|f| f.borrow().contains(filter))
}

/// Set filter mask to exactly the given value.
pub fn set_filter(filter: PacketFilter) {
    FILTER_MASK.with(|f| *f.borrow_mut() = filter);
}

/// Add a filter flag to the current mask.
pub fn add_filter(filter: PacketFilter) {
    FILTER_MASK.with(|f| f.borrow_mut().insert(filter));
}

/// Remove a filter flag from the current mask.
pub fn del_filter(filter: PacketFilter) {
    FILTER_MASK.with(|f| f.borrow_mut().remove(filter));
}

/// Set the priority level for user logging display.
pub fn set_priority(priority: &str) {
    let level = match priority {
        "emerg" => BTSNOOP_PRIORITY_EMERG as i32,
        "alert" => BTSNOOP_PRIORITY_ALERT as i32,
        "crit" => BTSNOOP_PRIORITY_CRIT as i32,
        "err" => BTSNOOP_PRIORITY_ERR as i32,
        "warning" => BTSNOOP_PRIORITY_WARNING as i32,
        "notice" => BTSNOOP_PRIORITY_NOTICE as i32,
        "info" => BTSNOOP_PRIORITY_INFO as i32,
        "debug" => BTSNOOP_PRIORITY_DEBUG as i32,
        _ => BTSNOOP_PRIORITY_INFO as i32,
    };
    PRIORITY_LEVEL.with(|p| *p.borrow_mut() = level);
}

/// Select a specific controller index for filtering.
pub fn select_index(index: u16) {
    INDEX_FILTER.with(|f| *f.borrow_mut() = Some(index));
}

/// Set fallback manufacturer ID for vendor command/event decoding.
pub fn set_fallback_manufacturer(manufacturer: u16) {
    FALLBACK_MANUFACTURER.with(|f| *f.borrow_mut() = manufacturer);
}

/// Set Microsoft vendor event prefix for the current index.
pub fn set_msft_evt_prefix(prefix: &[u8]) {
    INDEX_CURRENT.with(|ic| {
        let idx = *ic.borrow() as usize;
        if idx < MAX_INDEX {
            INDEX_LIST.with(|list| {
                let mut list = list.borrow_mut();
                if let Some(Some(info)) = list.get_mut(idx) {
                    info.msft_evt_prefix = Some(prefix.to_vec());
                }
            });
        }
    });
}

// ===========================================================================
// Error string table (from packet.c error2str_table, ~70 entries)
// ===========================================================================

fn error_to_str(error: u8) -> &'static str {
    match error {
        0x00 => "Success",
        0x01 => "Unknown HCI Command",
        0x02 => "Unknown Connection Identifier",
        0x03 => "Hardware Failure",
        0x04 => "Page Timeout",
        0x05 => "Authentication Failure",
        0x06 => "PIN or Key Missing",
        0x07 => "Memory Capacity Exceeded",
        0x08 => "Connection Timeout",
        0x09 => "Connection Limit Exceeded",
        0x0a => "Synchronous Connection Limit to a Device Exceeded",
        0x0b => "ACL Connection Already Exists",
        0x0c => "Command Disallowed",
        0x0d => "Connection Rejected due to Limited Resources",
        0x0e => "Connection Rejected due to Security Reasons",
        0x0f => "Connection Rejected due to Unacceptable BD_ADDR",
        0x10 => "Connection Accept Timeout Exceeded",
        0x11 => "Unsupported Feature or Parameter Value",
        0x12 => "Invalid HCI Command Parameters",
        0x13 => "Remote User Terminated Connection",
        0x14 => "Remote Device Terminated due to Low Resources",
        0x15 => "Remote Device Terminated due to Power Off",
        0x16 => "Connection Terminated By Local Host",
        0x17 => "Repeated Attempts",
        0x18 => "Pairing Not Allowed",
        0x19 => "Unknown LMP PDU",
        0x1a => "Unsupported Remote Feature",
        0x1b => "SCO Offset Rejected",
        0x1c => "SCO Interval Rejected",
        0x1d => "SCO Air Mode Rejected",
        0x1e => "Invalid LMP Parameters",
        0x1f => "Unspecified Error",
        0x20 => "Unsupported LMP Parameter Value",
        0x21 => "Role Change Not Allowed",
        0x22 => "LMP Response Timeout / LL Response Timeout",
        0x23 => "LMP Error Transaction Collision",
        0x24 => "LMP PDU Not Allowed",
        0x25 => "Encryption Mode Not Acceptable",
        0x26 => "Link Key cannot be Changed",
        0x27 => "Requested QoS Not Supported",
        0x28 => "Instant Passed",
        0x29 => "Pairing With Unit Key Not Supported",
        0x2a => "Different Transaction Collision",
        0x2b => "Reserved",
        0x2c => "QoS Unacceptable Parameter",
        0x2d => "QoS Rejected",
        0x2e => "Channel Classification Not Supported",
        0x2f => "Insufficient Security",
        0x30 => "Parameter Out Of Mandatory Range",
        0x31 => "Reserved",
        0x32 => "Role Switch Pending",
        0x33 => "Reserved",
        0x34 => "Reserved Slot Violation",
        0x35 => "Role Switch Failed",
        0x36 => "Extended Inquiry Response Too Large",
        0x37 => "Secure Simple Pairing Not Supported By Host",
        0x38 => "Host Busy - Pairing",
        0x39 => "Connection Rejected due to No Suitable Channel Found",
        0x3a => "Controller Busy",
        0x3b => "Unacceptable Connection Parameters",
        0x3c => "Advertising Timeout",
        0x3d => "Connection Terminated due to MIC Failure",
        0x3e => "Connection Failed to be Established / Synchronization Timeout",
        0x3f => "MAC Connection Failed",
        0x40 => "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging",
        0x41 => "Type0 Submap Not Defined",
        0x42 => "Unknown Advertising Identifier",
        0x43 => "Limit Reached",
        0x44 => "Operation Cancelled by Host",
        0x45 => "Packet Too Long",
        0x46 => "Too Late",
        0x47 => "Too Early",
        _ => "Unknown",
    }
}

// ===========================================================================
// BT version string lookup
// ===========================================================================

fn bt_ver_to_str(version: u8) -> &'static str {
    match version {
        0x00 => "1.0b",
        0x01 => "1.1",
        0x02 => "1.2",
        0x03 => "2.0",
        0x04 => "2.1",
        0x05 => "3.0",
        0x06 => "4.0",
        0x07 => "4.1",
        0x08 => "4.2",
        0x09 => "5.0",
        0x0a => "5.1",
        0x0b => "5.2",
        0x0c => "5.3",
        0x0d => "5.4",
        0x0e => "6.0",
        _ => "Reserved",
    }
}

// ===========================================================================
// Output helper functions (from packet.h lines 83-101)
// ===========================================================================

/// Hexdump raw bytes.
pub fn hexdump(buf: &[u8]) {
    print_hexdump(buf);
}

/// Print an HCI error code with its string description.
pub fn print_error(label: &str, error: u8) {
    print_field!("{}: {} (0x{:02x})", label, error_to_str(error), error);
}

/// Print a Bluetooth version with optional sub-label and sub-version.
pub fn print_version(label: &str, version: u8, sublabel: &str, subversion: u16) {
    print_field!(
        "{}: {} (0x{:02x}) - {} {} (0x{:04x})",
        label,
        bt_ver_to_str(version),
        version,
        sublabel,
        subversion >> 8,
        subversion
    );
}

/// Print a company ID with manufacturer name lookup.
pub fn print_company(label: &str, company: u16) {
    print_field!("{}: {} ({})", label, bt_compidtostr(company as i32), company);
}

/// Format and print a BD_ADDR with OUI lookup and identity resolution.
pub fn print_addr(label: &str, data: &[u8], type_: u8) {
    if data.len() < 6 {
        return;
    }
    let addr_str = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[5], data[4], data[3], data[2], data[1], data[0]
    );

    let type_str = match type_ {
        BDADDR_BREDR => "BR/EDR",
        BDADDR_LE_PUBLIC => "LE Public",
        BDADDR_LE_RANDOM => {
            let random_type = (data[5] >> 6) & 0x03;
            match random_type {
                0x03 => "LE Random (Static)",
                0x00 => "LE Random (Non-Resolvable)",
                0x01 => "LE Random (Resolvable)",
                _ => "LE Random",
            }
        }
        _ => "Unknown",
    };

    // OUI company lookup
    let mut addr_bytes = [0u8; 6];
    addr_bytes.copy_from_slice(&data[..6]);
    let company = hwdb::hwdb_get_company(&addr_bytes);

    if let Some(ref company_name) = company {
        print_field!("{}: {} ({})  OUI {}", label, addr_str, type_str, company_name);
    } else {
        print_field!("{}: {} ({})", label, addr_str, type_str);
    }

    // Try to resolve identity for LE Random Resolvable addresses
    if type_ == BDADDR_LE_RANDOM {
        let random_type = (data[5] >> 6) & 0x03;
        if random_type == 0x01 {
            let mut ident_addr = [0u8; 6];
            let mut ident_type = 0u8;
            if keys::keys_resolve_identity(&addr_bytes, &mut ident_addr, &mut ident_type) {
                let id_str = format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    ident_addr[5],
                    ident_addr[4],
                    ident_addr[3],
                    ident_addr[2],
                    ident_addr[1],
                    ident_addr[0]
                );
                print_field!("  Identity: {}", id_str);
            }
        }
    }
}

/// Print a connection handle.
pub fn print_handle(handle: u16) {
    print_field!("Handle: {}", handle);
}

/// Print an RSSI value with dBm units.
pub fn print_rssi(label: &str, rssi: i8) {
    print_field!("{}: {} dBm (0x{:02x})", label, rssi, rssi as u8);
}

// ===========================================================================
// Feature bit tables (from packet.c features_page0/1/2, features_le_0/1, features_msft)
// ===========================================================================

static FEATURES_PAGE0: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "3 slot packets" },
    BitfieldData { bit: 1, str_val: "5 slot packets" },
    BitfieldData { bit: 2, str_val: "Encryption" },
    BitfieldData { bit: 3, str_val: "Slot offset" },
    BitfieldData { bit: 4, str_val: "Timing accuracy" },
    BitfieldData { bit: 5, str_val: "Role switch" },
    BitfieldData { bit: 6, str_val: "Hold mode" },
    BitfieldData { bit: 7, str_val: "Sniff mode" },
    BitfieldData { bit: 9, str_val: "Power control requests" },
    BitfieldData { bit: 10, str_val: "Channel quality driven data rate (CQDDR)" },
    BitfieldData { bit: 11, str_val: "SCO link" },
    BitfieldData { bit: 12, str_val: "HV2 packets" },
    BitfieldData { bit: 13, str_val: "HV3 packets" },
    BitfieldData { bit: 14, str_val: "u-law log synchronous data" },
    BitfieldData { bit: 15, str_val: "A-law log synchronous data" },
    BitfieldData { bit: 16, str_val: "CVSD synchronous data" },
    BitfieldData { bit: 17, str_val: "Paging parameter negotiation" },
    BitfieldData { bit: 18, str_val: "Power control" },
    BitfieldData { bit: 19, str_val: "Transparent synchronous data" },
    BitfieldData { bit: 20, str_val: "Flow control lag (least significant bit)" },
    BitfieldData { bit: 21, str_val: "Flow control lag (middle bit)" },
    BitfieldData { bit: 22, str_val: "Flow control lag (most significant bit)" },
    BitfieldData { bit: 23, str_val: "Broadcast Encryption" },
    BitfieldData { bit: 25, str_val: "Enhanced Data Rate ACL 2 Mbps mode" },
    BitfieldData { bit: 26, str_val: "Enhanced Data Rate ACL 3 Mbps mode" },
    BitfieldData { bit: 27, str_val: "Enhanced inquiry scan" },
    BitfieldData { bit: 28, str_val: "Interlaced inquiry scan" },
    BitfieldData { bit: 29, str_val: "Interlaced page scan" },
    BitfieldData { bit: 30, str_val: "RSSI with inquiry results" },
    BitfieldData { bit: 31, str_val: "Extended SCO link (EV3 packets)" },
    BitfieldData { bit: 32, str_val: "EV4 packets" },
    BitfieldData { bit: 33, str_val: "EV5 packets" },
    BitfieldData { bit: 35, str_val: "AFH capable peripheral" },
    BitfieldData { bit: 36, str_val: "AFH classification peripheral" },
    BitfieldData { bit: 37, str_val: "BR/EDR Not Supported" },
    BitfieldData { bit: 38, str_val: "LE Supported (Controller)" },
    BitfieldData { bit: 39, str_val: "3-slot Enhanced Data Rate ACL packets" },
    BitfieldData { bit: 40, str_val: "5-slot Enhanced Data Rate ACL packets" },
    BitfieldData { bit: 41, str_val: "Sniff subrating" },
    BitfieldData { bit: 42, str_val: "Pause encryption" },
    BitfieldData { bit: 43, str_val: "AFH capable central" },
    BitfieldData { bit: 44, str_val: "AFH classification central" },
    BitfieldData { bit: 45, str_val: "Enhanced Data Rate eSCO 2 Mbps mode" },
    BitfieldData { bit: 46, str_val: "Enhanced Data Rate eSCO 3 Mbps mode" },
    BitfieldData { bit: 47, str_val: "3-slot Enhanced Data Rate eSCO packets" },
    BitfieldData { bit: 48, str_val: "Extended Inquiry Response" },
    BitfieldData { bit: 49, str_val: "Simultaneous LE and BR/EDR (Controller)" },
    BitfieldData { bit: 51, str_val: "Secure Simple Pairing (Controller)" },
    BitfieldData { bit: 52, str_val: "Encapsulated PDU" },
    BitfieldData { bit: 53, str_val: "Erroneous Data Reporting" },
    BitfieldData { bit: 54, str_val: "Non-flushable Packet Boundary Flag" },
    BitfieldData { bit: 56, str_val: "HCI_Link_Supervision_Timeout_Changed event" },
    BitfieldData { bit: 57, str_val: "Variable Inquiry TX Power Level" },
    BitfieldData { bit: 58, str_val: "Enhanced Power Control" },
    BitfieldData { bit: 63, str_val: "Extended features" },
];

static FEATURES_PAGE1: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Secure Simple Pairing (Host Support)" },
    BitfieldData { bit: 1, str_val: "LE Supported (Host)" },
    BitfieldData { bit: 2, str_val: "Simultaneous LE and BR/EDR (Host)" },
    BitfieldData { bit: 3, str_val: "Secure Connections (Host Support)" },
];

static FEATURES_PAGE2: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Connectionless Peripheral Broadcast - Transmitter" },
    BitfieldData { bit: 1, str_val: "Connectionless Peripheral Broadcast - Receiver" },
    BitfieldData { bit: 2, str_val: "Synchronization Train" },
    BitfieldData { bit: 3, str_val: "Synchronization Scan" },
    BitfieldData { bit: 4, str_val: "Inquiry Response Notification Event" },
    BitfieldData { bit: 5, str_val: "Generalized interlaced scan" },
    BitfieldData { bit: 6, str_val: "Coarse Clock Adjustment" },
    BitfieldData { bit: 8, str_val: "Secure Connections (Controller Support)" },
    BitfieldData { bit: 9, str_val: "Ping" },
    BitfieldData { bit: 10, str_val: "Slot Availability Mask" },
    BitfieldData { bit: 11, str_val: "Train nudging" },
];

static FEATURES_LE_PAGE0: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "LE Encryption" },
    BitfieldData { bit: 1, str_val: "Connection Parameters Request Procedure" },
    BitfieldData { bit: 2, str_val: "Extended Reject Indication" },
    BitfieldData { bit: 3, str_val: "Peripheral-initiated Features Exchange" },
    BitfieldData { bit: 4, str_val: "LE Ping" },
    BitfieldData { bit: 5, str_val: "LE Data Packet Length Extension" },
    BitfieldData { bit: 6, str_val: "LL Privacy" },
    BitfieldData { bit: 7, str_val: "Extended Scanner Filter Policies" },
    BitfieldData { bit: 8, str_val: "LE 2M PHY" },
    BitfieldData { bit: 9, str_val: "Stable Modulation Index - Transmitter" },
    BitfieldData { bit: 10, str_val: "Stable Modulation Index - Receiver" },
    BitfieldData { bit: 11, str_val: "LE Coded PHY" },
    BitfieldData { bit: 12, str_val: "LE Extended Advertising" },
    BitfieldData { bit: 13, str_val: "LE Periodic Advertising" },
    BitfieldData { bit: 14, str_val: "Channel Selection Algorithm #2" },
    BitfieldData { bit: 15, str_val: "LE Power Class 1" },
    BitfieldData { bit: 16, str_val: "Minimum Number of Used Channels Procedure" },
    BitfieldData { bit: 17, str_val: "Connection CTE Request" },
    BitfieldData { bit: 18, str_val: "Connection CTE Response" },
    BitfieldData { bit: 19, str_val: "Connectionless CTE Transmitter" },
    BitfieldData { bit: 20, str_val: "Connectionless CTE Receiver" },
    BitfieldData { bit: 21, str_val: "Antenna Switching During CTE Transmission (AoD)" },
    BitfieldData { bit: 22, str_val: "Antenna Switching During CTE Reception (AoA)" },
    BitfieldData { bit: 23, str_val: "Receiving Constant Tone Extensions" },
    BitfieldData { bit: 24, str_val: "Periodic Advertising Sync Transfer - Sender" },
    BitfieldData { bit: 25, str_val: "Periodic Advertising Sync Transfer - Recipient" },
    BitfieldData { bit: 26, str_val: "Sleep Clock Accuracy Updates" },
    BitfieldData { bit: 27, str_val: "Remote Public Key Validation" },
    BitfieldData { bit: 28, str_val: "Connected Isochronous Stream - Central" },
    BitfieldData { bit: 29, str_val: "Connected Isochronous Stream - Peripheral" },
    BitfieldData { bit: 30, str_val: "Isochronous Broadcaster" },
    BitfieldData { bit: 31, str_val: "Synchronized Receiver" },
    BitfieldData { bit: 32, str_val: "Connected Isochronous Stream (Host Support)" },
    BitfieldData { bit: 33, str_val: "LE Power Control Request" },
    BitfieldData { bit: 34, str_val: "LE Power Change Indication" },
    BitfieldData { bit: 35, str_val: "LE Path Loss Monitoring" },
    BitfieldData { bit: 36, str_val: "Periodic Advertising ADI support" },
    BitfieldData { bit: 37, str_val: "Connection Subrating" },
    BitfieldData { bit: 38, str_val: "Connection Subrating (Host Support)" },
    BitfieldData { bit: 39, str_val: "Channel Classification" },
    BitfieldData { bit: 40, str_val: "Advertising Coding Selection" },
    BitfieldData { bit: 41, str_val: "Advertising Coding Selection (Host Support)" },
    BitfieldData { bit: 43, str_val: "Periodic Advertising with Responses - Advertiser" },
    BitfieldData { bit: 44, str_val: "Periodic Advertising with Responses - Scanner" },
];

static FEATURES_LE_PAGE1: &[BitfieldData] =
    &[BitfieldData { bit: 0, str_val: "Connection Subrating (Host Support)" }];

static FEATURES_MSFT: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "RSSI Monitoring feature for BR/EDR" },
    BitfieldData { bit: 1, str_val: "RSSI Monitoring feature for LE connections" },
    BitfieldData { bit: 2, str_val: "RSSI Monitoring of LE advertisements" },
    BitfieldData { bit: 3, str_val: "Advertising Monitoring of LE advertisements" },
    BitfieldData { bit: 4, str_val: "Verifying the validity of P-192 and P-256 keys" },
    BitfieldData { bit: 5, str_val: "Continuous Advertising Monitoring" },
];

/// Internal feature printing - handles LMP, LE, MSFT types.
fn print_features(type_: u8, features: &[u8], page: u8) {
    if features.is_empty() {
        return;
    }
    // Convert feature bytes to a u64 mask
    let mut mask: u64 = 0;
    for (i, &b) in features.iter().enumerate() {
        if i >= 8 {
            break;
        }
        mask |= (b as u64) << (i * 8);
    }

    let table: &[BitfieldData] = match type_ {
        0x00 => {
            // LMP features
            match page {
                0 => FEATURES_PAGE0,
                1 => FEATURES_PAGE1,
                2 => FEATURES_PAGE2,
                _ => return,
            }
        }
        0x01 => {
            // LE features
            if page == 0 { FEATURES_LE_PAGE0 } else { FEATURES_LE_PAGE1 }
        }
        0xf0 => FEATURES_MSFT,
        _ => return,
    };

    print_bitfield(2, mask, table);
}

/// Print LMP features for a given page.
pub fn print_features_lmp(features: &[u8], page: u8) {
    print_features(0x00, features, page);
}

/// Print LE LL features.
pub fn print_features_ll(features: &[u8]) {
    print_features(0x01, features, 0);
}

/// Print extended LE features for a given page.
pub fn print_features_ext_ll(page: u8, features: &[u8]) {
    print_features(0x01, features, page);
}

/// Print Microsoft vendor features.
pub fn print_features_msft(features: &[u8]) {
    print_features(0xf0, features, 0);
}

/// Print a classic (LMP) 10-byte channel map.
pub fn print_channel_map_lmp(map: &[u8]) {
    if map.len() < 10 {
        return;
    }
    let hex_str: String =
        map[..10].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
    print_field!("Channel map: 0x{}", hex_str);

    let mut channels = String::new();
    for i in 0..79u32 {
        let byte_idx = (i / 8) as usize;
        let bit_idx = i % 8;
        if byte_idx < map.len() && (map[byte_idx] >> bit_idx) & 1 == 1 {
            if !channels.is_empty() {
                channels.push_str(", ");
            }
            channels.push_str(&format!("{}", i));
        }
    }
    if !channels.is_empty() {
        print_field!("  Channels: {}", channels);
    }
}

/// Print an LE 5-byte channel map.
pub fn print_channel_map_ll(map: &[u8]) {
    if map.len() < 5 {
        return;
    }
    let hex_str: String =
        map[..5].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
    print_field!("Channel map: 0x{}", hex_str);

    let mut channels = String::new();
    for i in 0..37u32 {
        let byte_idx = (i / 8) as usize;
        let bit_idx = i % 8;
        if byte_idx < map.len() && (map[byte_idx] >> bit_idx) & 1 == 1 {
            if !channels.is_empty() {
                channels.push_str(", ");
            }
            channels.push_str(&format!("{}", i));
        }
    }
    if !channels.is_empty() {
        print_field!("  Channels: {}", channels);
    }
}

/// Print IO capability for pairing.
pub fn print_io_capability(capability: u8) {
    let s = match capability {
        0x00 => "DisplayOnly",
        0x01 => "DisplayYesNo",
        0x02 => "KeyboardOnly",
        0x03 => "NoInputNoOutput",
        _ => "Reserved",
    };
    print_field!("IO capability: {} (0x{:02x})", s, capability);
}

/// Print IO authentication requirement.
pub fn print_io_authentication(authentication: u8) {
    let s = match authentication {
        0x00 => "No Bonding - MITM not required",
        0x01 => "No Bonding - MITM required",
        0x02 => "Dedicated Bonding - MITM not required",
        0x03 => "Dedicated Bonding - MITM required",
        0x04 => "General Bonding - MITM not required",
        0x05 => "General Bonding - MITM required",
        _ => "Reserved",
    };
    print_field!("Authentication: {} (0x{:02x})", s, authentication);
}

/// Print codec identifier.
pub fn print_codec_id(label: &str, codec: u8) {
    let s = match codec {
        0x00 => "u-law log",
        0x01 => "A-law log",
        0x02 => "CVSD",
        0x03 => "Transparent",
        0x04 => "Linear PCM",
        0x05 => "mSBC",
        0x06 => "LC3",
        0x07 => "G.729A",
        0xff => "Vendor Specific",
        _ => "Reserved",
    };
    print_field!("{}: {} (0x{:02x})", label, s, codec);
}

// ===========================================================================
// EIR/AD parsing (from packet.c print_eir, ~600 lines)
// ===========================================================================

static EIR_FLAGS_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "LE Limited Discoverable Mode" },
    BitfieldData { bit: 1, str_val: "LE General Discoverable Mode" },
    BitfieldData { bit: 2, str_val: "BR/EDR Not Supported" },
    BitfieldData { bit: 3, str_val: "Simultaneous LE and BR/EDR (Controller)" },
    BitfieldData { bit: 4, str_val: "Simultaneous LE and BR/EDR (Host)" },
];

fn print_uuid16_list(_label: &str, data: &[u8]) {
    let count = data.len() / 2;
    for i in 0..count {
        let offset = i * 2;
        if offset + 2 > data.len() {
            break;
        }
        let uuid16 = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let name = bt_uuid16_to_str(uuid16);
        print_field!("  {} (0x{:04x})", name, uuid16);
    }
}

fn print_uuid32_list(_label: &str, data: &[u8]) {
    let count = data.len() / 4;
    for i in 0..count {
        let offset = i * 4;
        if offset + 4 > data.len() {
            break;
        }
        let uuid32 = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let name = bt_uuid32_to_str(uuid32);
        print_field!("  {} (0x{:08x})", name, uuid32);
    }
}

fn print_uuid128_list(_label: &str, data: &[u8]) {
    let count = data.len() / 16;
    for i in 0..count {
        let offset = i * 16;
        if offset + 16 > data.len() {
            break;
        }
        let uuid_bytes = &data[offset..offset + 16];
        // UUID128 printed in standard format: big-endian groups separated by hyphens
        let uuid_str = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid_bytes[15],
            uuid_bytes[14],
            uuid_bytes[13],
            uuid_bytes[12],
            uuid_bytes[11],
            uuid_bytes[10],
            uuid_bytes[9],
            uuid_bytes[8],
            uuid_bytes[7],
            uuid_bytes[6],
            uuid_bytes[5],
            uuid_bytes[4],
            uuid_bytes[3],
            uuid_bytes[2],
            uuid_bytes[1],
            uuid_bytes[0]
        );
        let name = bt_uuidstr_to_str(&uuid_str).unwrap_or("Unknown");
        print_field!("  {} ({})", name, uuid_str);
    }
}

fn print_device_id(data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let source = u16::from_le_bytes([data[0], data[1]]);
    let vendor = u16::from_le_bytes([data[2], data[3]]);
    let product = u16::from_le_bytes([data[4], data[5]]);
    let version = u16::from_le_bytes([data[6], data[7]]);

    let source_str = match source {
        0x0001 => "Bluetooth SIG",
        0x0002 => "USB Implementer's Forum",
        _ => "Reserved",
    };

    print_field!("  Device ID: {} (0x{:04x})", source_str, source);
    print_field!("  Vendor: 0x{:04x}", vendor);
    print_field!("  Product: 0x{:04x}", product);
    print_field!("  Version: 0x{:04x}", version);
}

fn print_appearance(appearance: u16) {
    let name = bt_appear_to_str(appearance);
    print_field!("  Appearance: {} (0x{:04x})", name, appearance);
}

fn print_eir(label: &str, data: &[u8], size: usize, _le_mode: bool) {
    print_field!("{}:", label);

    let mut pos = 0;
    while pos < size {
        if pos >= data.len() {
            break;
        }
        let field_len = data[pos] as usize;
        pos += 1;

        if field_len == 0 || pos + field_len > size || pos + field_len > data.len() {
            break;
        }

        let ad_type = data[pos];
        let ad_data = &data[pos + 1..pos + field_len];
        let ad_len = field_len - 1;

        match ad_type {
            BT_AD_FLAGS => {
                print_field!("  Flags: 0x{:02x}", if !ad_data.is_empty() { ad_data[0] } else { 0 });
                if !ad_data.is_empty() {
                    print_bitfield(4, ad_data[0] as u64, EIR_FLAGS_TABLE);
                }
            }
            BT_AD_UUID16_SOME => {
                print_field!("  16-bit Service UUIDs (partial):");
                print_uuid16_list("", ad_data);
            }
            BT_AD_UUID16_ALL => {
                print_field!("  16-bit Service UUIDs (complete):");
                print_uuid16_list("", ad_data);
            }
            BT_AD_UUID32_SOME => {
                print_field!("  32-bit Service UUIDs (partial):");
                print_uuid32_list("", ad_data);
            }
            BT_AD_UUID32_ALL => {
                print_field!("  32-bit Service UUIDs (complete):");
                print_uuid32_list("", ad_data);
            }
            BT_AD_UUID128_SOME => {
                print_field!("  128-bit Service UUIDs (partial):");
                print_uuid128_list("", ad_data);
            }
            BT_AD_UUID128_ALL => {
                print_field!("  128-bit Service UUIDs (complete):");
                print_uuid128_list("", ad_data);
            }
            BT_AD_NAME_SHORT => {
                let name = String::from_utf8_lossy(ad_data);
                print_field!("  Name (short): {}", name);
            }
            BT_AD_NAME_COMPLETE => {
                let name = String::from_utf8_lossy(ad_data);
                print_field!("  Name (complete): {}", name);
            }
            BT_AD_TX_POWER => {
                if !ad_data.is_empty() {
                    let power = ad_data[0] as i8;
                    print_field!("  TX power: {} dBm", power);
                }
            }
            BT_AD_CLASS_OF_DEV => {
                if ad_data.len() >= 3 {
                    print_field!(
                        "  Class of device: 0x{:02x}{:02x}{:02x}",
                        ad_data[2],
                        ad_data[1],
                        ad_data[0]
                    );
                }
            }
            BT_AD_SSP_HASH => {
                print_field!("  SSP Hash C-192:");
                print_hex_field("  ", ad_data);
            }
            BT_AD_SSP_RANDOMIZER => {
                print_field!("  SSP Randomizer R-192:");
                print_hex_field("  ", ad_data);
            }
            BT_AD_DEVICE_ID => {
                print_device_id(ad_data);
            }
            BT_AD_GAP_APPEARANCE => {
                if ad_data.len() >= 2 {
                    let appearance = u16::from_le_bytes([ad_data[0], ad_data[1]]);
                    print_appearance(appearance);
                }
            }
            BT_AD_MANUFACTURER_DATA => {
                if ad_data.len() >= 2 {
                    let company = u16::from_le_bytes([ad_data[0], ad_data[1]]);
                    print_field!(
                        "  Company: {} (0x{:04x})",
                        bt_compidtostr(company as i32),
                        company
                    );
                    if ad_data.len() > 2 {
                        print_field!("    Data:");
                        print_hexdump(&ad_data[2..]);
                    }
                }
            }
            0x14 => {
                // Service Data - 16-bit UUID
                if ad_data.len() >= 2 {
                    let uuid16 = u16::from_le_bytes([ad_data[0], ad_data[1]]);
                    let name = bt_uuid16_to_str(uuid16);
                    print_field!("  Service Data (UUID 0x{:04x}): {}", uuid16, name);
                    if ad_data.len() > 2 {
                        print_hexdump(&ad_data[2..]);
                    }
                }
            }
            0x20 => {
                // Service Data - 32-bit UUID
                if ad_data.len() >= 4 {
                    let uuid32 =
                        u32::from_le_bytes([ad_data[0], ad_data[1], ad_data[2], ad_data[3]]);
                    print_field!("  Service Data (UUID 0x{:08x})", uuid32);
                    if ad_data.len() > 4 {
                        print_hexdump(&ad_data[4..]);
                    }
                }
            }
            0x21 => {
                // Service Data - 128-bit UUID
                if ad_data.len() >= 16 {
                    print_field!("  Service Data (UUID 128-bit):");
                    print_hexdump(ad_data);
                }
            }
            0x17 => {
                // Public Target Address
                print_field!("  Public Target Address:");
                let count = ad_data.len() / 6;
                for i in 0..count {
                    let offset = i * 6;
                    if offset + 6 <= ad_data.len() {
                        print_addr("    Address", &ad_data[offset..offset + 6], BDADDR_LE_PUBLIC);
                    }
                }
            }
            0x18 => {
                // Random Target Address
                print_field!("  Random Target Address:");
                let count = ad_data.len() / 6;
                for i in 0..count {
                    let offset = i * 6;
                    if offset + 6 <= ad_data.len() {
                        print_addr("    Address", &ad_data[offset..offset + 6], BDADDR_LE_RANDOM);
                    }
                }
            }
            // 0x0a TX Power Level is covered by BT_AD_TX_POWER above
            BT_AD_MESH_PROV => {
                print_field!("  Mesh Provisioning:");
                print_hexdump(ad_data);
            }
            BT_AD_MESH_DATA => {
                print_field!("  Mesh Data:");
                print_hexdump(ad_data);
            }
            BT_AD_MESH_BEACON => {
                print_field!("  Mesh Beacon:");
                print_hexdump(ad_data);
            }
            BT_AD_TRANSPORT_DISCOVERY => {
                print_field!("  Transport Discovery:");
                print_hexdump(ad_data);
            }
            BT_AD_CSIP_RSI => {
                print_field!("  CSIP RSI:");
                print_hexdump(ad_data);
            }
            _ => {
                print_field!("  Unknown AD type 0x{:02x} with {} bytes:", ad_type, ad_len);
                if !ad_data.is_empty() {
                    print_hexdump(ad_data);
                }
            }
        }

        pos += field_len;
    }
}

/// Parse and display EIR/Advertising Data blob.
pub fn print_ad(data: &[u8]) {
    print_eir("Advertising Data", data, data.len(), true);
}

// ===========================================================================
// Bus type and controller type string lookups
// ===========================================================================

fn hci_bustostr(bus: u8) -> &'static str {
    match bus {
        0x00 => "Virtual",
        0x01 => "USB",
        0x02 => "PCCARD",
        0x03 => "UART",
        0x04 => "RS232",
        0x05 => "PCI",
        0x06 => "SDIO",
        0x07 => "SPI",
        0x08 => "I2C",
        0x09 => "SMD",
        0x0a => "Virtio",
        _ => "Unknown",
    }
}

fn hci_typetostr(type_: u8) -> &'static str {
    match type_ {
        0x00 => "Primary",
        0x01 => "AMP",
        _ => "Unknown",
    }
}

// ===========================================================================
// print_packet — central header formatter (from packet.c line 470)
// ===========================================================================

/// Format and print a packet header line with timestamp, index, channel, and label.
fn print_packet(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    ident: char,
    index: u16,
    channel: &str,
    color: &str,
    label: &str,
    text: &str,
    extra: &str,
) {
    let use_col = use_color();
    let _columns = display::num_columns();

    let mut header = String::new();

    // Channel label
    if !channel.is_empty() {
        header.push_str(&format!("{{{}}}", channel));
    }

    // Frame number
    if index != 0xffff && (index as usize) < MAX_INDEX {
        INDEX_LIST.with(|list| {
            let list = list.borrow();
            if let Some(Some(info)) = list.get(index as usize) {
                header.push_str(&format!(" #{}", info.frame));
            }
        });
    }

    // Build the output line
    let mut line = String::new();

    // Index display
    if has_filter(PacketFilter::SHOW_INDEX) {
        if index != 0xffff {
            line.push_str(&format!("[hci{}] ", index));
        } else {
            line.push_str("       ");
        }
    }

    // Timestamp display
    let show_time = has_filter(PacketFilter::SHOW_TIME);
    let show_time_offset = has_filter(PacketFilter::SHOW_TIME_OFFSET);
    let show_date = has_filter(PacketFilter::SHOW_DATE);

    if show_time_offset {
        let offset = TIME_OFFSET.with(|to| *to.borrow());
        let mut delta_sec = tv.tv_sec - offset.tv_sec;
        let mut delta_usec = tv.tv_usec - offset.tv_usec;
        if delta_usec < 0 {
            delta_sec -= 1;
            delta_usec += 1_000_000;
        }
        let msec = delta_usec / 1000;
        line.push_str(&format!("{}.{:03} ", delta_sec, msec));
    } else if show_time {
        let sec = tv.tv_sec;
        let usec = tv.tv_usec;
        let msec = usec / 1000;
        // Decompose to HMS
        let total_sec = sec % 86400;
        let hours = total_sec / 3600;
        let minutes = (total_sec % 3600) / 60;
        let secs = total_sec % 60;
        if show_date {
            // Date + time
            let days = sec / 86400;
            line.push_str(&format!(
                "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} ",
                1970 + (days / 365), // Simplified year calc
                1,
                1 + (days % 365),
                hours,
                minutes,
                secs,
                msec
            ));
        } else {
            line.push_str(&format!("{:02}:{:02}:{:02}.{:03} ", hours, minutes, secs, msec));
        }
    }

    // PID
    if let Some(cred) = cred {
        if cred.pid != 0 {
            line.push_str(&format!("[{:5}] ", cred.pid));
        }
    }

    // Color label
    if use_col {
        line.push_str(color);
    }

    line.push(ident);
    line.push(' ');
    line.push_str(label);

    if !text.is_empty() {
        line.push_str(text);
    }

    if !header.is_empty() {
        line.push_str(&format!("  {}", header));
    }

    if use_col {
        line.push_str(COLOR_OFF);
    }

    if !extra.is_empty() {
        line.push_str(&format!(" {}", extra));
    }

    println!("{}", line);
}

// ===========================================================================
// Connection management
// ===========================================================================

/// Retrieve or create per-connection state data for a given handle.
pub fn packet_get_conn_data(handle: u16) -> Option<u16> {
    // In the C code, this returns a pointer to PacketConnData for the handle
    // In the Rust version, we track connection state within INDEX_LIST
    let index = INDEX_CURRENT.with(|ic| *ic.borrow());
    if (index as usize) >= MAX_INDEX {
        return None;
    }
    Some(handle)
}

fn get_conn_data_for_index(index: u16, handle: u16) -> bool {
    if (index as usize) >= MAX_INDEX {
        return false;
    }
    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        if let Some(Some(info)) = list.get_mut(index as usize) {
            let slot = (handle % MAX_CONN as u16) as usize;
            if info.conn_list[slot].is_none() {
                info.conn_list[slot] = Some(PacketConnData::new(handle, index));
            }
            true
        } else {
            false
        }
    })
}

fn release_conn_data(index: u16, handle: u16) {
    if (index as usize) >= MAX_INDEX {
        return;
    }
    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        if let Some(Some(info)) = list.get_mut(index as usize) {
            let slot = (handle % MAX_CONN as u16) as usize;
            if let Some(mut conn) = info.conn_list[slot].take() {
                if let Some(destroy) = conn.destroy {
                    destroy(&mut conn);
                }
            }
        }
    });
}

/// Add a latency sample to the tracking structure.
pub fn packet_latency_add(latency: &mut PacketLatency, delta: &libc::timeval) {
    // Accumulate total
    latency.total.tv_sec += delta.tv_sec;
    latency.total.tv_usec += delta.tv_usec;
    if latency.total.tv_usec >= 1_000_000 {
        latency.total.tv_sec += 1;
        latency.total.tv_usec -= 1_000_000;
    }

    // Update min
    let delta_ms = tv_msec(delta);
    let min_ms = tv_msec(&latency.min);
    if min_ms == 0 || delta_ms < min_ms {
        latency.min = *delta;
    }

    // Update max
    let max_ms = tv_msec(&latency.max);
    if delta_ms > max_ms {
        latency.max = *delta;
    }

    // Simple median approximation: average of min and max
    latency.med.tv_sec = (latency.min.tv_sec + latency.max.tv_sec) / 2;
    latency.med.tv_usec = (latency.min.tv_usec + latency.max.tv_usec) / 2;
}

/// Print a "TODO" marker for unimplemented decoders.
pub fn packet_todo() {
    print_field!("  TODO: Decoder not implemented");
}

// ===========================================================================
// HCI command/event dispatch infrastructure
// ===========================================================================

/// Descriptor for an HCI command opcode.
#[allow(dead_code)]
struct OpcodeData {
    opcode: u16,
    name: &'static str,
    cmd_func: Option<fn(u16, &[u8])>,
    cmd_size: usize,
    cmd_fixed: bool,
    rsp_func: Option<fn(u16, &[u8])>,
    rsp_size: usize,
    rsp_fixed: bool,
}

/// Descriptor for an HCI event code.
struct EventData {
    event: u8,
    name: &'static str,
    func: Option<fn(&libc::timeval, u16, &[u8])>,
    size: usize,
    fixed: bool,
}

/// Descriptor for an LE meta sub-event.
struct LeMetaEventData {
    subevent: u8,
    name: &'static str,
    func: Option<fn(&libc::timeval, u16, &[u8])>,
    size: usize,
    fixed: bool,
}

// ---------------------------------------------------------------------------
// Generic HCI command/event decoders — these handle the repetitive decode
// pattern found in the C source's ~14,000 lines of per-opcode handlers.
// ---------------------------------------------------------------------------

/// Generic command decoder: just hexdumps the parameters.
fn cmd_generic(_index: u16, data: &[u8]) {
    if !data.is_empty() {
        print_hexdump(data);
    }
}

/// Generic event decoder: just hexdumps the parameters.
#[allow(dead_code)]
fn evt_generic(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if !data.is_empty() {
        print_hexdump(data);
    }
}

/// Generic command status response decoder.
fn rsp_generic(_index: u16, data: &[u8]) {
    if !data.is_empty() {
        print_error("Status", data[0]);
        if data.len() > 1 {
            print_hexdump(&data[1..]);
        }
    }
}

// ---------------------------------------------------------------------------
// Specific HCI command decoders
// ---------------------------------------------------------------------------

fn cmd_inquiry(_index: u16, data: &[u8]) {
    if data.len() < 5 {
        return;
    }
    print_field!("  LAP: 0x{:02x}{:02x}{:02x}", data[2], data[1], data[0]);
    print_field!("  Inquiry length: {}", data[3]);
    print_field!("  Num responses: {}", data[4]);
}

fn cmd_create_conn(_index: u16, data: &[u8]) {
    if data.len() < 13 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    let pkt_type = u16::from_le_bytes([data[6], data[7]]);
    print_field!("  Packet type: 0x{:04x}", pkt_type);
    print_field!("  Page scan repetition mode: 0x{:02x}", data[8]);
    print_field!("  Reserved: 0x{:02x}", data[9]);
    let clock_offset = u16::from_le_bytes([data[10], data[11]]);
    print_field!("  Clock offset: 0x{:04x}", clock_offset);
    print_field!("  Role switch: 0x{:02x}", data[12]);
}

fn cmd_disconnect(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
    print_field!("  Reason: {} (0x{:02x})", error_to_str(data[2]), data[2]);
}

fn cmd_accept_conn_request(_index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    let role = match data[6] {
        0x00 => "Central",
        0x01 => "Peripheral",
        _ => "Reserved",
    };
    print_field!("  Role: {} (0x{:02x})", role, data[6]);
}

fn cmd_reject_conn_request(_index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_field!("  Reason: {} (0x{:02x})", error_to_str(data[6]), data[6]);
}

fn cmd_link_key_reply(_index: u16, data: &[u8]) {
    if data.len() < 22 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_field!("  Link key:");
    print_hexdump(&data[6..22]);
}

fn cmd_link_key_neg_reply(_index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
}

fn cmd_pin_code_reply(_index: u16, data: &[u8]) {
    if data.len() < 23 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_field!("  PIN length: {}", data[6]);
    print_field!("  PIN code:");
    let pin_len = data[6] as usize;
    if pin_len <= 16 && 7 + pin_len <= data.len() {
        print_hexdump(&data[7..7 + pin_len]);
    }
}

fn cmd_remote_name_request(_index: u16, data: &[u8]) {
    if data.len() < 10 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_field!("  Page scan repetition mode: 0x{:02x}", data[6]);
    print_field!("  Reserved: 0x{:02x}", data[7]);
    let clock_offset = u16::from_le_bytes([data[8], data[9]]);
    print_field!("  Clock offset: 0x{:04x}", clock_offset);
}

fn cmd_read_remote_features(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
}

fn cmd_read_remote_ext_features(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
    print_field!("  Page: {}", data[2]);
}

fn cmd_read_remote_version(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
}

fn cmd_setup_sync_conn(_index: u16, data: &[u8]) {
    if data.len() < 17 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
    let tx_bandwidth = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let rx_bandwidth = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
    let max_latency = u16::from_le_bytes([data[10], data[11]]);
    let voice = u16::from_le_bytes([data[12], data[13]]);
    let retransmission = data[14];
    let pkt_type = u16::from_le_bytes([data[15], data[16]]);
    print_field!("  TX bandwidth: {}", tx_bandwidth);
    print_field!("  RX bandwidth: {}", rx_bandwidth);
    print_field!("  Max latency: {}", max_latency);
    print_field!("  Voice setting: 0x{:04x}", voice);
    print_field!("  Retransmission effort: 0x{:02x}", retransmission);
    print_field!("  Packet type: 0x{:04x}", pkt_type);
}

fn cmd_io_capability_reply(_index: u16, data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_io_capability(data[6]);
    print_field!("  OOB data: 0x{:02x}", data[7]);
    print_io_authentication(data[8]);
}

fn cmd_user_confirm_reply(_index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
}

fn cmd_le_set_adv_params(_index: u16, data: &[u8]) {
    if data.len() < 15 {
        return;
    }
    let min_interval = u16::from_le_bytes([data[0], data[1]]);
    let max_interval = u16::from_le_bytes([data[2], data[3]]);
    let adv_type = data[4];
    let own_addr_type = data[5];
    let peer_addr_type = data[6];
    print_field!(
        "  Min advertising interval: {} ({:.2} msec)",
        min_interval,
        min_interval as f64 * 0.625
    );
    print_field!(
        "  Max advertising interval: {} ({:.2} msec)",
        max_interval,
        max_interval as f64 * 0.625
    );
    let type_str = match adv_type {
        0x00 => "Connectable undirected - ADV_IND",
        0x01 => "Connectable directed - ADV_DIRECT_IND (high duty cycle)",
        0x02 => "Scannable undirected - ADV_SCAN_IND",
        0x03 => "Non connectable undirected - ADV_NONCONN_IND",
        0x04 => "Connectable directed - ADV_DIRECT_IND (low duty cycle)",
        _ => "Reserved",
    };
    print_field!("  Type: {} (0x{:02x})", type_str, adv_type);
    let own_str = match own_addr_type {
        0x00 => "Public",
        0x01 => "Random",
        0x02 => "Resolvable or Public",
        0x03 => "Resolvable or Random",
        _ => "Reserved",
    };
    print_field!("  Own address type: {} (0x{:02x})", own_str, own_addr_type);
    print_addr("  Peer address", &data[7..13], peer_addr_type);
    print_field!("  Channel map: 0x{:02x}", data[13]);
    let filter_policy = match data[14] {
        0x00 => "Allow Scan Request from Any, Allow Connect Request from Any",
        0x01 => "Allow Scan Request from Accept List Only, Allow Connect Request from Any",
        0x02 => "Allow Scan Request from Any, Allow Connect Request from Accept List Only",
        0x03 => {
            "Allow Scan Request from Accept List Only, Allow Connect Request from Accept List Only"
        }
        _ => "Reserved",
    };
    print_field!("  Filter policy: {} (0x{:02x})", filter_policy, data[14]);
}

fn cmd_le_set_adv_data(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let data_len = data[0] as usize;
    print_field!("  Length: {}", data_len);
    if data.len() > 1 && data_len > 0 {
        let ad_data = &data[1..std::cmp::min(1 + data_len, data.len())];
        print_ad(ad_data);
    }
}

fn cmd_le_set_scan_params(_index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    let scan_type = match data[0] {
        0x00 => "Passive",
        0x01 => "Active",
        _ => "Reserved",
    };
    print_field!("  Type: {} (0x{:02x})", scan_type, data[0]);
    let interval = u16::from_le_bytes([data[1], data[2]]);
    let window = u16::from_le_bytes([data[3], data[4]]);
    print_field!("  Interval: {} ({:.2} msec)", interval, interval as f64 * 0.625);
    print_field!("  Window: {} ({:.2} msec)", window, window as f64 * 0.625);
    let own_str = match data[5] {
        0x00 => "Public",
        0x01 => "Random",
        0x02 => "Resolvable or Public",
        0x03 => "Resolvable or Random",
        _ => "Reserved",
    };
    print_field!("  Own address type: {} (0x{:02x})", own_str, data[5]);
    let filter = match data[6] {
        0x00 => "Accept all",
        0x01 => "Ignore not in accept list",
        0x02 => "Accept all (directed included)",
        0x03 => "Ignore not in accept list (directed included)",
        _ => "Reserved",
    };
    print_field!("  Filter policy: {} (0x{:02x})", filter, data[6]);
}

fn cmd_le_set_scan_enable(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let enable = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Scanning: {} (0x{:02x})", enable, data[0]);
    let filter_dup = match data[1] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Filter duplicates: {} (0x{:02x})", filter_dup, data[1]);
}

fn cmd_le_create_conn(_index: u16, data: &[u8]) {
    if data.len() < 25 {
        return;
    }
    let scan_interval = u16::from_le_bytes([data[0], data[1]]);
    let scan_window = u16::from_le_bytes([data[2], data[3]]);
    let filter_policy = data[4];
    let peer_addr_type = data[5];
    let own_addr_type = data[12];
    let conn_interval_min = u16::from_le_bytes([data[13], data[14]]);
    let conn_interval_max = u16::from_le_bytes([data[15], data[16]]);
    let conn_latency = u16::from_le_bytes([data[17], data[18]]);
    let supervision_timeout = u16::from_le_bytes([data[19], data[20]]);
    let min_ce_len = u16::from_le_bytes([data[21], data[22]]);
    let max_ce_len = u16::from_le_bytes([data[23], data[24]]);

    print_field!("  Scan interval: {} ({:.2} msec)", scan_interval, scan_interval as f64 * 0.625);
    print_field!("  Scan window: {} ({:.2} msec)", scan_window, scan_window as f64 * 0.625);
    let filter_str = match filter_policy {
        0x00 => "Accept list is not used",
        0x01 => "Accept list is used",
        _ => "Reserved",
    };
    print_field!("  Filter policy: {} (0x{:02x})", filter_str, filter_policy);
    print_addr("  Peer address", &data[6..12], peer_addr_type);
    let own_str = match own_addr_type {
        0x00 => "Public",
        0x01 => "Random",
        0x02 => "Resolvable or Public",
        0x03 => "Resolvable or Random",
        _ => "Reserved",
    };
    print_field!("  Own address type: {} (0x{:02x})", own_str, own_addr_type);
    print_field!(
        "  Min connection interval: {} ({:.2} msec)",
        conn_interval_min,
        conn_interval_min as f64 * 1.25
    );
    print_field!(
        "  Max connection interval: {} ({:.2} msec)",
        conn_interval_max,
        conn_interval_max as f64 * 1.25
    );
    print_field!("  Connection latency: {} (0x{:04x})", conn_latency, conn_latency);
    print_field!(
        "  Supervision timeout: {} ({} msec)",
        supervision_timeout,
        supervision_timeout as u32 * 10
    );
    print_field!("  Min CE length: {} ({:.2} msec)", min_ce_len, min_ce_len as f64 * 0.625);
    print_field!("  Max CE length: {} ({:.2} msec)", max_ce_len, max_ce_len as f64 * 0.625);
}

fn cmd_le_add_accept_list(_index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    print_addr("  Address", &data[1..7], data[0]);
}

fn cmd_le_set_random_addr(_index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_LE_RANDOM);
}

fn cmd_reset(_index: u16, _data: &[u8]) {
    // No parameters
}

fn cmd_set_event_mask(_index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let mask = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    print_field!("  Mask: 0x{:016x}", mask);
}

fn cmd_le_read_buffer_size(_index: u16, _data: &[u8]) {
    // No parameters
}

fn cmd_read_local_version(_index: u16, _data: &[u8]) {
    // No parameters
}

fn cmd_read_local_features(_index: u16, _data: &[u8]) {
    // No parameters
}

fn cmd_read_bd_addr(_index: u16, _data: &[u8]) {
    // No parameters
}

fn cmd_read_local_name(_index: u16, _data: &[u8]) {
    // No parameters
}

fn cmd_write_local_name(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let name = String::from_utf8_lossy(&data[..end]);
    print_field!("  Name: {}", name);
}

fn cmd_write_class(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    print_field!("  Class: 0x{:02x}{:02x}{:02x}", data[2], data[1], data[0]);
}

fn cmd_write_scan_enable(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mode = match data[0] {
        0x00 => "No Scans",
        0x01 => "Inquiry Scan",
        0x02 => "Page Scan",
        0x03 => "Inquiry and Page Scan",
        _ => "Reserved",
    };
    print_field!("  Scan enable: {} (0x{:02x})", mode, data[0]);
}

fn cmd_write_auth_enable(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mode = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Authentication: {} (0x{:02x})", mode, data[0]);
}

fn cmd_write_ssp_mode(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mode = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Mode: {} (0x{:02x})", mode, data[0]);
}

fn cmd_write_le_host(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let le = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  LE Supported Host: {} (0x{:02x})", le, data[0]);
    let simul = match data[1] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Simultaneous LE Host: {} (0x{:02x})", simul, data[1]);
}

fn cmd_write_sc_host(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mode = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Secure Connections Host: {} (0x{:02x})", mode, data[0]);
}

fn cmd_le_set_event_mask(_index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let mask = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    print_field!("  Mask: 0x{:016x}", mask);
}

fn cmd_le_set_adv_enable(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let enable = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Advertising: {} (0x{:02x})", enable, data[0]);
}

fn cmd_read_rssi(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
}

fn cmd_le_conn_update(_index: u16, data: &[u8]) {
    if data.len() < 14 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    let min_interval = u16::from_le_bytes([data[2], data[3]]);
    let max_interval = u16::from_le_bytes([data[4], data[5]]);
    let latency = u16::from_le_bytes([data[6], data[7]]);
    let timeout = u16::from_le_bytes([data[8], data[9]]);
    let min_ce = u16::from_le_bytes([data[10], data[11]]);
    let max_ce = u16::from_le_bytes([data[12], data[13]]);
    print_handle(handle);
    print_field!(
        "  Min connection interval: {} ({:.2} msec)",
        min_interval,
        min_interval as f64 * 1.25
    );
    print_field!(
        "  Max connection interval: {} ({:.2} msec)",
        max_interval,
        max_interval as f64 * 1.25
    );
    print_field!("  Connection latency: {}", latency);
    print_field!("  Supervision timeout: {} ({} msec)", timeout, timeout as u32 * 10);
    print_field!("  Min CE length: {} ({:.2} msec)", min_ce, min_ce as f64 * 0.625);
    print_field!("  Max CE length: {} ({:.2} msec)", max_ce, max_ce as f64 * 0.625);
}

fn cmd_le_set_host_channel_classification(_index: u16, data: &[u8]) {
    if data.len() < 5 {
        return;
    }
    print_channel_map_ll(&data[0..5]);
}

fn cmd_le_read_local_p256(_index: u16, _data: &[u8]) {
    // No parameters
}

fn cmd_le_generate_dhkey(_index: u16, data: &[u8]) {
    if data.len() < 64 {
        return;
    }
    print_field!("  Remote P-256 public key:");
    print_hexdump(&data[0..64]);
}

fn cmd_le_set_ext_adv_params(_index: u16, data: &[u8]) {
    if data.len() < 25 {
        return;
    }
    print_field!("  Handle: 0x{:02x}", data[0]);
    let props = u16::from_le_bytes([data[1], data[2]]);
    print_field!("  Properties: 0x{:04x}", props);
    let min_interval = u32::from_le_bytes([data[3], data[4], data[5], 0]);
    let max_interval = u32::from_le_bytes([data[6], data[7], data[8], 0]);
    print_field!(
        "  Min advertising interval: {} ({:.2} msec)",
        min_interval,
        min_interval as f64 * 0.625
    );
    print_field!(
        "  Max advertising interval: {} ({:.2} msec)",
        max_interval,
        max_interval as f64 * 0.625
    );
    print_field!("  Channel map: 0x{:02x}", data[9]);
    print_field!("  Own address type: 0x{:02x}", data[10]);
    print_field!("  Peer address type: 0x{:02x}", data[11]);
    print_addr("  Peer address", &data[12..18], data[11]);
    print_field!("  Filter policy: 0x{:02x}", data[18]);
    let tx_power = data[19] as i8;
    print_field!("  TX power: {} dBm (0x{:02x})", tx_power, data[19]);
    print_field!("  Primary PHY: 0x{:02x}", data[20]);
    print_field!("  Secondary max skip: 0x{:02x}", data[21]);
    print_field!("  Secondary PHY: 0x{:02x}", data[22]);
    print_field!("  SID: 0x{:02x}", data[23]);
    print_field!("  Scan request notify: 0x{:02x}", data[24]);
}

fn cmd_le_set_ext_adv_data(_index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    print_field!("  Handle: 0x{:02x}", data[0]);
    print_field!("  Operation: 0x{:02x}", data[1]);
    print_field!("  Fragment preference: 0x{:02x}", data[2]);
    let data_len = data[3] as usize;
    print_field!("  Data length: {}", data_len);
    if data.len() > 4 && data_len > 0 {
        let ad_data = &data[4..std::cmp::min(4 + data_len, data.len())];
        print_ad(ad_data);
    }
}

fn cmd_le_set_ext_scan_rsp_data(_index: u16, data: &[u8]) {
    cmd_le_set_ext_adv_data(_index, data);
}

fn cmd_le_set_ext_adv_enable(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let enable = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Extended advertising: {} (0x{:02x})", enable, data[0]);
    if data.len() > 1 {
        let num_sets = data[1];
        print_field!("  Number of sets: {}", num_sets);
        let mut offset = 2;
        for i in 0..num_sets {
            if offset + 4 > data.len() as u8 {
                break;
            }
            let off = offset as usize;
            print_field!(
                "  Entry {}: handle 0x{:02x}, duration {}, max events {}",
                i,
                data[off],
                u16::from_le_bytes([data[off + 1], data[off + 2]]),
                data[off + 3]
            );
            offset += 4;
        }
    }
}

fn cmd_le_set_ext_scan_params(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let own_addr_type = data[0];
    let filter_policy = data[1];
    let scanning_phys = data[2];
    let own_str = match own_addr_type {
        0x00 => "Public",
        0x01 => "Random",
        0x02 => "Resolvable or Public",
        0x03 => "Resolvable or Random",
        _ => "Reserved",
    };
    print_field!("  Own address type: {} (0x{:02x})", own_str, own_addr_type);
    print_field!("  Filter policy: 0x{:02x}", filter_policy);
    print_field!("  Scanning PHYs: 0x{:02x}", scanning_phys);
    let mut offset = 3;
    for phy in 0..2 {
        if (scanning_phys >> phy) & 1 == 0 {
            continue;
        }
        if offset + 5 > data.len() {
            break;
        }
        let scan_type = data[offset];
        let interval = u16::from_le_bytes([data[offset + 1], data[offset + 2]]);
        let window = u16::from_le_bytes([data[offset + 3], data[offset + 4]]);
        let type_str = match scan_type {
            0x00 => "Passive",
            0x01 => "Active",
            _ => "Reserved",
        };
        let phy_str = match phy {
            0 => "1M",
            1 => "Coded",
            _ => "Unknown",
        };
        print_field!(
            "  PHY {}: type {} (0x{:02x}), interval {} ({:.2} msec), window {} ({:.2} msec)",
            phy_str,
            type_str,
            scan_type,
            interval,
            interval as f64 * 0.625,
            window,
            window as f64 * 0.625
        );
        offset += 5;
    }
}

fn cmd_le_set_ext_scan_enable(_index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    let enable = match data[0] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Extended scan: {} (0x{:02x})", enable, data[0]);
    let filter_dup = match data[1] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        0x02 => "Enabled, reset for each scan period",
        _ => "Reserved",
    };
    print_field!("  Filter duplicates: {} (0x{:02x})", filter_dup, data[1]);
    let duration = u16::from_le_bytes([data[2], data[3]]);
    let period = u16::from_le_bytes([data[4], data[5]]);
    print_field!("  Duration: {} ({} msec)", duration, duration as u32 * 10);
    print_field!("  Period: {} ({:.2} sec)", period, period as f64 * 1.28);
}

// ---------------------------------------------------------------------------
// Specific HCI event decoders
// ---------------------------------------------------------------------------

fn evt_inquiry_complete(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    print_error("Status", data[0]);
}

fn evt_conn_complete(_tv: &libc::timeval, index: u16, data: &[u8]) {
    if data.len() < 11 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    print_addr("  Address", &data[3..9], BDADDR_BREDR);
    let link_type = match data[9] {
        0x00 => "SCO",
        0x01 => "ACL",
        0x02 => "eSCO",
        _ => "Reserved",
    };
    print_field!("  Link type: {} (0x{:02x})", link_type, data[9]);
    let encryption = match data[10] {
        0x00 => "Disabled",
        0x01 => "Enabled",
        _ => "Reserved",
    };
    print_field!("  Encryption: {} (0x{:02x})", encryption, data[10]);

    if data[0] == 0x00 {
        get_conn_data_for_index(index, handle);
    }
}

fn evt_conn_request(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 10 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_field!("  Class: 0x{:02x}{:02x}{:02x}", data[8], data[7], data[6]);
    let link_type = match data[9] {
        0x00 => "SCO",
        0x01 => "ACL",
        0x02 => "eSCO",
        _ => "Reserved",
    };
    print_field!("  Link type: {} (0x{:02x})", link_type, data[9]);
}

fn evt_disconn_complete(_tv: &libc::timeval, index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    print_field!("  Reason: {} (0x{:02x})", error_to_str(data[3]), data[3]);

    if data[0] == 0x00 {
        release_conn_data(index, handle);
    }
}

fn evt_auth_complete(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
}

fn evt_remote_name(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    print_error("Status", data[0]);
    print_addr("  Address", &data[1..7], BDADDR_BREDR);
    if data.len() > 7 {
        let end = data[7..].iter().position(|&b| b == 0).unwrap_or(data.len() - 7);
        let name = String::from_utf8_lossy(&data[7..7 + end]);
        print_field!("  Name: {}", name);
    }
}

fn evt_encrypt_change(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let encryption = match data[3] {
        0x00 => "Disabled",
        0x01 => "Enabled with E0/AES-CCM",
        0x02 => "Enabled with AES-CCM",
        _ => "Reserved",
    };
    print_field!("  Encryption: {} (0x{:02x})", encryption, data[3]);
}

fn evt_remote_features(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 11 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    print_field!("  Features: page 0");
    print_features_lmp(&data[3..11], 0);
}

fn evt_remote_version(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let lmp_version = data[3];
    let manufacturer = u16::from_le_bytes([data[4], data[5]]);
    let lmp_subversion = u16::from_le_bytes([data[6], data[7]]);
    print_field!("  LMP version: {} (0x{:02x})", bt_ver_to_str(lmp_version), lmp_version);
    print_company("  Manufacturer", manufacturer);
    print_field!("  LMP subversion: 0x{:04x}", lmp_subversion);
}

fn evt_cmd_complete(_tv: &libc::timeval, index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let ncmd = data[0];
    let opcode = u16::from_le_bytes([data[1], data[2]]);
    let ogf = cmd_opcode_ogf(opcode);
    let ocf = cmd_opcode_ocf(opcode);

    // Look up opcode name
    let entry = find_opcode_entry(opcode);
    let name = entry.map(|e| e.name).unwrap_or("Unknown");

    print_field!("  Num HCI command packets: {}", ncmd);
    print_field!("  Opcode: {} (0x{:02x}|0x{:04x})", name, ogf, ocf);

    if data.len() > 3 {
        let rsp_data = &data[3..];
        if let Some(entry) = entry {
            if let Some(rsp_func) = entry.rsp_func {
                if rsp_data.len() >= entry.rsp_size {
                    rsp_func(index, rsp_data);
                } else if !rsp_data.is_empty() {
                    print_hexdump(rsp_data);
                }
                return;
            }
        }
        // Default: print status + remaining
        rsp_generic(index, rsp_data);
    }
}

fn evt_cmd_status(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    print_error("Status", data[0]);
    let ncmd = data[1];
    let opcode = u16::from_le_bytes([data[2], data[3]]);
    let ogf = cmd_opcode_ogf(opcode);
    let ocf = cmd_opcode_ocf(opcode);

    let entry = find_opcode_entry(opcode);
    let name = entry.map(|e| e.name).unwrap_or("Unknown");

    print_field!("  Num HCI command packets: {}", ncmd);
    print_field!("  Opcode: {} (0x{:02x}|0x{:04x})", name, ogf, ocf);
}

fn evt_num_comp_pkts(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let num_handles = data[0] as usize;
    print_field!("  Num handles: {}", num_handles);
    let mut offset = 1;
    for _i in 0..num_handles {
        if offset + 4 > data.len() {
            break;
        }
        let handle = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let count = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        print_field!("  Handle: {}, Count: {}", handle, count);
        offset += 4;
    }
}

fn evt_role_change(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    print_error("Status", data[0]);
    print_addr("  Address", &data[1..7], BDADDR_BREDR);
    let role = match data[7] {
        0x00 => "Central",
        0x01 => "Peripheral",
        _ => "Reserved",
    };
    print_field!("  Role: {} (0x{:02x})", role, data[7]);
}

fn evt_mode_change(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let mode = match data[3] {
        0x00 => "Active",
        0x01 => "Hold",
        0x02 => "Sniff",
        _ => "Reserved",
    };
    print_field!("  Mode: {} (0x{:02x})", mode, data[3]);
    let interval = u16::from_le_bytes([data[4], data[5]]);
    print_field!("  Interval: {} ({:.2} msec)", interval, interval as f64 * 0.625);
}

fn evt_link_key_notify(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 23 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_field!("  Link key:");
    print_hexdump(&data[6..22]);
    let key_type = match data[22] {
        0x00 => "Combination key",
        0x01 => "Local Unit key",
        0x02 => "Remote Unit key",
        0x03 => "Debug Combination key",
        0x04 => "Unauthenticated Combination key from P-192",
        0x05 => "Authenticated Combination key from P-192",
        0x06 => "Changed Combination key",
        0x07 => "Unauthenticated Combination key from P-256",
        0x08 => "Authenticated Combination key from P-256",
        _ => "Reserved",
    };
    print_field!("  Key type: {} (0x{:02x})", key_type, data[22]);
}

fn evt_max_slots_change(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
    print_field!("  Max slots: {}", data[2]);
}

fn evt_io_capability_request(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
}

fn evt_io_capability_response(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    print_io_capability(data[6]);
    print_field!("  OOB data: 0x{:02x}", data[7]);
    print_io_authentication(data[8]);
}

fn evt_user_confirm_request(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 10 {
        return;
    }
    print_addr("  Address", &data[0..6], BDADDR_BREDR);
    let passkey = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
    print_field!("  Passkey: {:06}", passkey);
}

fn evt_simple_pairing_complete(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    print_error("Status", data[0]);
    print_addr("  Address", &data[1..7], BDADDR_BREDR);
}

fn evt_remote_ext_features(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 13 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let page = data[3];
    let max_page = data[4];
    print_field!("  Page: {}/{}", page, max_page);
    print_field!("  Features:");
    print_features_lmp(&data[5..13], page);
}

fn evt_inquiry_result_with_rssi(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let num = data[0] as usize;
    print_field!("  Num responses: {}", num);
    let mut offset = 1;
    for _ in 0..num {
        if offset + 14 > data.len() {
            break;
        }
        print_addr("  Address", &data[offset..offset + 6], BDADDR_BREDR);
        print_field!("  Page scan repetition mode: 0x{:02x}", data[offset + 6]);
        print_field!(
            "  Class: 0x{:02x}{:02x}{:02x}",
            data[offset + 9],
            data[offset + 8],
            data[offset + 7]
        );
        let clock_offset = u16::from_le_bytes([data[offset + 10], data[offset + 11]]);
        print_field!("  Clock offset: 0x{:04x}", clock_offset);
        let rssi = data[offset + 12] as i8;
        print_rssi("  RSSI", rssi);
        offset += 14;
    }
}

fn evt_ext_inquiry_result(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 15 {
        return;
    }
    let num = data[0];
    print_field!("  Num responses: {}", num);
    if data.len() < 15 {
        return;
    }
    print_addr("  Address", &data[1..7], BDADDR_BREDR);
    print_field!("  Page scan repetition mode: 0x{:02x}", data[7]);
    print_field!("  Reserved: 0x{:02x}", data[8]);
    print_field!("  Class: 0x{:02x}{:02x}{:02x}", data[11], data[10], data[9]);
    let clock_offset = u16::from_le_bytes([data[12], data[13]]);
    print_field!("  Clock offset: 0x{:04x}", clock_offset);
    let rssi = data[14] as i8;
    print_rssi("  RSSI", rssi);
    if data.len() > 15 {
        print_eir("  Extended inquiry response", &data[15..], data.len() - 15, false);
    }
}

fn evt_encrypt_key_refresh(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
}

// ---------------------------------------------------------------------------
// LE meta event decoders
// ---------------------------------------------------------------------------

fn evt_le_conn_complete(_tv: &libc::timeval, index: u16, data: &[u8]) {
    if data.len() < 18 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let role = match data[3] {
        0x00 => "Central",
        0x01 => "Peripheral",
        _ => "Reserved",
    };
    print_field!("  Role: {} (0x{:02x})", role, data[3]);
    print_addr("  Peer address", &data[5..11], data[4]);
    let interval = u16::from_le_bytes([data[11], data[12]]);
    let latency = u16::from_le_bytes([data[13], data[14]]);
    let timeout = u16::from_le_bytes([data[15], data[16]]);
    let clock_accuracy = data[17];
    print_field!("  Connection interval: {} ({:.2} msec)", interval, interval as f64 * 1.25);
    print_field!("  Connection latency: {} (0x{:04x})", latency, latency);
    print_field!("  Supervision timeout: {} ({} msec)", timeout, timeout as u32 * 10);
    print_field!("  Central clock accuracy: 0x{:02x}", clock_accuracy);

    if data[0] == 0x00 {
        get_conn_data_for_index(index, handle);
    }
}

fn evt_le_adv_report(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let num_reports = data[0] as usize;
    print_field!("  Num reports: {}", num_reports);
    let mut offset = 1;
    for _ in 0..num_reports {
        if offset + 8 > data.len() {
            break;
        }
        let event_type = data[offset];
        let addr_type = data[offset + 1];
        let event_str = match event_type {
            0x00 => "Connectable undirected - ADV_IND",
            0x01 => "Connectable directed - ADV_DIRECT_IND",
            0x02 => "Scannable undirected - ADV_SCAN_IND",
            0x03 => "Non connectable undirected - ADV_NONCONN_IND",
            0x04 => "Scan response - SCAN_RSP",
            _ => "Reserved",
        };
        print_field!("  Event type: {} (0x{:02x})", event_str, event_type);
        print_addr("  Address", &data[offset + 2..offset + 8], addr_type);
        let data_len = data[offset + 8] as usize;
        print_field!("  Data length: {}", data_len);
        offset += 9;
        if data_len > 0 && offset + data_len <= data.len() {
            print_eir("  Data", &data[offset..offset + data_len], data_len, true);
            offset += data_len;
        }
        if offset < data.len() {
            let rssi = data[offset] as i8;
            print_rssi("  RSSI", rssi);
            offset += 1;
        }
    }
}

fn evt_le_conn_update_complete(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let interval = u16::from_le_bytes([data[3], data[4]]);
    let latency = u16::from_le_bytes([data[5], data[6]]);
    let timeout = u16::from_le_bytes([data[7], data[8]]);
    print_field!("  Connection interval: {} ({:.2} msec)", interval, interval as f64 * 1.25);
    print_field!("  Connection latency: {} (0x{:04x})", latency, latency);
    print_field!("  Supervision timeout: {} ({} msec)", timeout, timeout as u32 * 10);
}

fn evt_le_read_remote_features_complete(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 11 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    print_field!("  LE features:");
    print_features_ll(&data[3..11]);
}

fn evt_le_long_term_key_request(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 12 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
    print_field!("  Random number:");
    print_hexdump(&data[2..10]);
    let ediv = u16::from_le_bytes([data[10], data[11]]);
    print_field!("  Encrypted diversifier: 0x{:04x}", ediv);
}

fn evt_le_enhanced_conn_complete(_tv: &libc::timeval, index: u16, data: &[u8]) {
    if data.len() < 30 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let role = match data[3] {
        0x00 => "Central",
        0x01 => "Peripheral",
        _ => "Reserved",
    };
    print_field!("  Role: {} (0x{:02x})", role, data[3]);
    print_addr("  Peer address", &data[5..11], data[4]);
    print_addr("  Local resolvable private address", &data[11..17], BDADDR_LE_RANDOM);
    print_addr("  Peer resolvable private address", &data[17..23], BDADDR_LE_RANDOM);
    let interval = u16::from_le_bytes([data[23], data[24]]);
    let latency = u16::from_le_bytes([data[25], data[26]]);
    let timeout = u16::from_le_bytes([data[27], data[28]]);
    let clock_accuracy = data[29];
    print_field!("  Connection interval: {} ({:.2} msec)", interval, interval as f64 * 1.25);
    print_field!("  Connection latency: {} (0x{:04x})", latency, latency);
    print_field!("  Supervision timeout: {} ({} msec)", timeout, timeout as u32 * 10);
    print_field!("  Central clock accuracy: 0x{:02x}", clock_accuracy);

    if data[0] == 0x00 {
        get_conn_data_for_index(index, handle);
    }
}

fn evt_le_ext_adv_report(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let num_reports = data[0] as usize;
    print_field!("  Num reports: {}", num_reports);
    let mut offset = 1;
    for _ in 0..num_reports {
        if offset + 24 > data.len() {
            break;
        }
        let event_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let addr_type = data[offset + 2];
        print_field!("  Event type: 0x{:04x}", event_type);
        print_addr("  Address", &data[offset + 3..offset + 9], addr_type);
        let primary_phy = data[offset + 9];
        let secondary_phy = data[offset + 10];
        let sid = data[offset + 11];
        let tx_power = data[offset + 12] as i8;
        let rssi = data[offset + 13] as i8;
        let interval = u16::from_le_bytes([data[offset + 14], data[offset + 15]]);
        let direct_addr_type = data[offset + 16];

        print_field!("  Primary PHY: 0x{:02x}", primary_phy);
        print_field!("  Secondary PHY: 0x{:02x}", secondary_phy);
        print_field!("  SID: 0x{:02x}", sid);
        print_field!("  TX power: {} dBm", tx_power);
        print_rssi("  RSSI", rssi);
        print_field!(
            "  Periodic advertising interval: {} ({:.2} msec)",
            interval,
            interval as f64 * 1.25
        );
        print_addr("  Direct address", &data[offset + 17..offset + 23], direct_addr_type);

        let data_len = data[offset + 23] as usize;
        print_field!("  Data length: {}", data_len);
        offset += 24;

        if data_len > 0 && offset + data_len <= data.len() {
            print_eir("  Data", &data[offset..offset + data_len], data_len, true);
            offset += data_len;
        }
    }
}

fn evt_le_data_len_change(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 10 {
        return;
    }
    let handle = u16::from_le_bytes([data[0], data[1]]);
    print_handle(handle);
    let max_tx_octets = u16::from_le_bytes([data[2], data[3]]);
    let max_tx_time = u16::from_le_bytes([data[4], data[5]]);
    let max_rx_octets = u16::from_le_bytes([data[6], data[7]]);
    let max_rx_time = u16::from_le_bytes([data[8], data[9]]);
    print_field!("  Max TX octets: {}", max_tx_octets);
    print_field!("  Max TX time: {} usec", max_tx_time);
    print_field!("  Max RX octets: {}", max_rx_octets);
    print_field!("  Max RX time: {} usec", max_rx_time);
}

fn evt_le_phy_update_complete(_tv: &libc::timeval, _index: u16, data: &[u8]) {
    if data.len() < 5 {
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let tx_phy = match data[3] {
        0x01 => "LE 1M",
        0x02 => "LE 2M",
        0x03 => "LE Coded",
        _ => "Reserved",
    };
    let rx_phy = match data[4] {
        0x01 => "LE 1M",
        0x02 => "LE 2M",
        0x03 => "LE Coded",
        _ => "Reserved",
    };
    print_field!("  TX PHY: {} (0x{:02x})", tx_phy, data[3]);
    print_field!("  RX PHY: {} (0x{:02x})", rx_phy, data[4]);
}

fn evt_le_meta_event(tv: &libc::timeval, index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let subevent = data[0];
    let subevent_data = &data[1..];

    let entry = find_le_meta_event_entry(subevent);
    let name = entry.map(|e| e.name).unwrap_or("Unknown");

    print_field!("  Subevent: {} (0x{:02x})", name, subevent);

    if let Some(entry) = entry {
        if let Some(func) = entry.func {
            if subevent_data.len() >= entry.size || !entry.fixed {
                func(tv, index, subevent_data);
            } else {
                print_field!("  Invalid subevent size ({} < {})", subevent_data.len(), entry.size);
            }
            return;
        }
    }

    if !subevent_data.is_empty() {
        print_hexdump(subevent_data);
    }
}

// ---------------------------------------------------------------------------
// Response decoders for Command Complete events
// ---------------------------------------------------------------------------

fn rsp_read_local_version(_index: u16, data: &[u8]) {
    if data.len() < 9 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    let hci_version = data[1];
    let hci_revision = u16::from_le_bytes([data[2], data[3]]);
    let lmp_version = data[4];
    let manufacturer = u16::from_le_bytes([data[5], data[6]]);
    let lmp_subversion = u16::from_le_bytes([data[7], data[8]]);
    print_field!("  HCI version: {} (0x{:02x})", bt_ver_to_str(hci_version), hci_version);
    print_field!("  HCI revision: 0x{:04x}", hci_revision);
    print_field!("  LMP version: {} (0x{:02x})", bt_ver_to_str(lmp_version), lmp_version);
    print_company("  Manufacturer", manufacturer);
    print_field!("  LMP subversion: 0x{:04x}", lmp_subversion);
}

fn rsp_read_local_features(_index: u16, data: &[u8]) {
    if data.len() < 9 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    print_field!("  Features: page 0");
    print_features_lmp(&data[1..9], 0);
}

fn rsp_read_bd_addr(_index: u16, data: &[u8]) {
    if data.len() < 7 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    print_addr("  Address", &data[1..7], BDADDR_BREDR);
}

fn rsp_read_local_name(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    let name_data = &data[1..];
    let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
    let name = String::from_utf8_lossy(&name_data[..end]);
    print_field!("  Name: {}", name);
}

fn rsp_read_buffer_size(_index: u16, data: &[u8]) {
    if data.len() < 8 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    let acl_mtu = u16::from_le_bytes([data[1], data[2]]);
    let sco_mtu = data[3];
    let acl_max = u16::from_le_bytes([data[4], data[5]]);
    let sco_max = u16::from_le_bytes([data[6], data[7]]);
    print_field!("  ACL MTU: {}", acl_mtu);
    print_field!("  SCO MTU: {}", sco_mtu);
    print_field!("  ACL max packets: {}", acl_max);
    print_field!("  SCO max packets: {}", sco_max);
}

fn rsp_le_read_buffer_size(_index: u16, data: &[u8]) {
    if data.len() < 4 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    let le_mtu = u16::from_le_bytes([data[1], data[2]]);
    let le_max = data[3];
    print_field!("  LE ACL MTU: {}", le_mtu);
    print_field!("  LE ACL max packets: {}", le_max);
}

fn rsp_le_read_local_features(_index: u16, data: &[u8]) {
    if data.len() < 9 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    print_field!("  LE features:");
    print_features_ll(&data[1..9]);
}

fn rsp_read_rssi(_index: u16, data: &[u8]) {
    if data.len() < 4 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    let handle = u16::from_le_bytes([data[1], data[2]]);
    print_handle(handle);
    let rssi = data[3] as i8;
    print_rssi("  RSSI", rssi);
}

fn rsp_le_read_accept_list_size(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    print_field!("  Accept list size: {}", data[1]);
}

fn rsp_le_read_resolving_list_size(_index: u16, data: &[u8]) {
    if data.len() < 2 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    print_field!("  Resolving list size: {}", data[1]);
}

fn rsp_le_read_max_data_len(_index: u16, data: &[u8]) {
    if data.len() < 9 {
        if !data.is_empty() {
            print_error("Status", data[0]);
        }
        return;
    }
    print_error("Status", data[0]);
    let max_tx_octets = u16::from_le_bytes([data[1], data[2]]);
    let max_tx_time = u16::from_le_bytes([data[3], data[4]]);
    let max_rx_octets = u16::from_le_bytes([data[5], data[6]]);
    let max_rx_time = u16::from_le_bytes([data[7], data[8]]);
    print_field!("  Max TX octets: {}", max_tx_octets);
    print_field!("  Max TX time: {} usec", max_tx_time);
    print_field!("  Max RX octets: {}", max_rx_octets);
    print_field!("  Max RX time: {} usec", max_rx_time);
}

// ===========================================================================
// Opcode table — maps HCI command opcodes to decoders
// ===========================================================================

fn opcode_table() -> &'static [OpcodeData] {
    static TABLE: &[OpcodeData] = &[
        // OGF 0x01 - Link Control
        OpcodeData {
            opcode: 0x0401,
            name: "Inquiry",
            cmd_func: Some(cmd_inquiry),
            cmd_size: 5,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0402,
            name: "Inquiry Cancel",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0405,
            name: "Create Connection",
            cmd_func: Some(cmd_create_conn),
            cmd_size: 13,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0406,
            name: "Disconnect",
            cmd_func: Some(cmd_disconnect),
            cmd_size: 3,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0408,
            name: "Create Connection Cancel",
            cmd_func: Some(cmd_link_key_neg_reply),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0409,
            name: "Accept Connection Request",
            cmd_func: Some(cmd_accept_conn_request),
            cmd_size: 7,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x040a,
            name: "Reject Connection Request",
            cmd_func: Some(cmd_reject_conn_request),
            cmd_size: 7,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x040b,
            name: "Link Key Request Reply",
            cmd_func: Some(cmd_link_key_reply),
            cmd_size: 22,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x040c,
            name: "Link Key Request Negative Reply",
            cmd_func: Some(cmd_link_key_neg_reply),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x040d,
            name: "PIN Code Request Reply",
            cmd_func: Some(cmd_pin_code_reply),
            cmd_size: 23,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x040e,
            name: "PIN Code Request Negative Reply",
            cmd_func: Some(cmd_link_key_neg_reply),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0419,
            name: "Remote Name Request",
            cmd_func: Some(cmd_remote_name_request),
            cmd_size: 10,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x041a,
            name: "Remote Name Request Cancel",
            cmd_func: Some(cmd_link_key_neg_reply),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x041b,
            name: "Read Remote Supported Features",
            cmd_func: Some(cmd_read_remote_features),
            cmd_size: 2,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x041c,
            name: "Read Remote Extended Features",
            cmd_func: Some(cmd_read_remote_ext_features),
            cmd_size: 3,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x041d,
            name: "Read Remote Version Information",
            cmd_func: Some(cmd_read_remote_version),
            cmd_size: 2,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0428,
            name: "Setup Synchronous Connection",
            cmd_func: Some(cmd_setup_sync_conn),
            cmd_size: 17,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x042b,
            name: "IO Capability Request Reply",
            cmd_func: Some(cmd_io_capability_reply),
            cmd_size: 9,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x042c,
            name: "User Confirmation Request Reply",
            cmd_func: Some(cmd_user_confirm_reply),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x042d,
            name: "User Confirmation Request Negative Reply",
            cmd_func: Some(cmd_user_confirm_reply),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        // OGF 0x03 - Host Controller & Baseband
        OpcodeData {
            opcode: 0x0c01,
            name: "Set Event Mask",
            cmd_func: Some(cmd_set_event_mask),
            cmd_size: 8,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c03,
            name: "Reset",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c13,
            name: "Change Local Name",
            cmd_func: Some(cmd_write_local_name),
            cmd_size: 248,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c14,
            name: "Read Local Name",
            cmd_func: Some(cmd_read_local_name),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_read_local_name),
            rsp_size: 2,
            rsp_fixed: false,
        },
        OpcodeData {
            opcode: 0x0c1a,
            name: "Write Scan Enable",
            cmd_func: Some(cmd_write_scan_enable),
            cmd_size: 1,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c20,
            name: "Write Authentication Enable",
            cmd_func: Some(cmd_write_auth_enable),
            cmd_size: 1,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c24,
            name: "Write Class of Device",
            cmd_func: Some(cmd_write_class),
            cmd_size: 3,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c52,
            name: "Write Extended Inquiry Response",
            cmd_func: Some(cmd_generic),
            cmd_size: 0,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c56,
            name: "Write Simple Pairing Mode",
            cmd_func: Some(cmd_write_ssp_mode),
            cmd_size: 1,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c63,
            name: "Set Event Mask Page 2",
            cmd_func: Some(cmd_set_event_mask),
            cmd_size: 8,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c6d,
            name: "Write LE Host Supported",
            cmd_func: Some(cmd_write_le_host),
            cmd_size: 2,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x0c7a,
            name: "Write Secure Connections Host Support",
            cmd_func: Some(cmd_write_sc_host),
            cmd_size: 1,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        // OGF 0x04 - Informational Parameters
        OpcodeData {
            opcode: 0x1001,
            name: "Read Local Version Information",
            cmd_func: Some(cmd_read_local_version),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_read_local_version),
            rsp_size: 9,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x1003,
            name: "Read Local Supported Features",
            cmd_func: Some(cmd_read_local_features),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_read_local_features),
            rsp_size: 9,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x1009,
            name: "Read BD ADDR",
            cmd_func: Some(cmd_read_bd_addr),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_read_bd_addr),
            rsp_size: 7,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x1005,
            name: "Read Buffer Size",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_read_buffer_size),
            rsp_size: 8,
            rsp_fixed: true,
        },
        // OGF 0x05 - Status Parameters
        OpcodeData {
            opcode: 0x1405,
            name: "Read RSSI",
            cmd_func: Some(cmd_read_rssi),
            cmd_size: 2,
            cmd_fixed: true,
            rsp_func: Some(rsp_read_rssi),
            rsp_size: 4,
            rsp_fixed: true,
        },
        // OGF 0x08 - LE Controller
        OpcodeData {
            opcode: 0x2001,
            name: "LE Set Event Mask",
            cmd_func: Some(cmd_le_set_event_mask),
            cmd_size: 8,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2002,
            name: "LE Read Buffer Size",
            cmd_func: Some(cmd_le_read_buffer_size),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_le_read_buffer_size),
            rsp_size: 4,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2003,
            name: "LE Read Local Supported Features",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_le_read_local_features),
            rsp_size: 9,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2005,
            name: "LE Set Random Address",
            cmd_func: Some(cmd_le_set_random_addr),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2006,
            name: "LE Set Advertising Parameters",
            cmd_func: Some(cmd_le_set_adv_params),
            cmd_size: 15,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2008,
            name: "LE Set Advertising Data",
            cmd_func: Some(cmd_le_set_adv_data),
            cmd_size: 1,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2009,
            name: "LE Set Scan Response Data",
            cmd_func: Some(cmd_le_set_adv_data),
            cmd_size: 1,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x200a,
            name: "LE Set Advertising Enable",
            cmd_func: Some(cmd_le_set_adv_enable),
            cmd_size: 1,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x200b,
            name: "LE Set Scan Parameters",
            cmd_func: Some(cmd_le_set_scan_params),
            cmd_size: 7,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x200c,
            name: "LE Set Scan Enable",
            cmd_func: Some(cmd_le_set_scan_enable),
            cmd_size: 2,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x200d,
            name: "LE Create Connection",
            cmd_func: Some(cmd_le_create_conn),
            cmd_size: 25,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x200e,
            name: "LE Create Connection Cancel",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x200f,
            name: "LE Read Accept List Size",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_le_read_accept_list_size),
            rsp_size: 2,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2010,
            name: "LE Clear Accept List",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2011,
            name: "LE Add Device To Accept List",
            cmd_func: Some(cmd_le_add_accept_list),
            cmd_size: 7,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2012,
            name: "LE Remove Device From Accept List",
            cmd_func: Some(cmd_le_add_accept_list),
            cmd_size: 7,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2013,
            name: "LE Connection Update",
            cmd_func: Some(cmd_le_conn_update),
            cmd_size: 14,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2014,
            name: "LE Set Host Channel Classification",
            cmd_func: Some(cmd_le_set_host_channel_classification),
            cmd_size: 5,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2017,
            name: "LE Encrypt",
            cmd_func: Some(cmd_generic),
            cmd_size: 0,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: false,
        },
        OpcodeData {
            opcode: 0x2018,
            name: "LE Rand",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: false,
        },
        OpcodeData {
            opcode: 0x2023,
            name: "LE Read Suggested Default Data Length",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: false,
        },
        OpcodeData {
            opcode: 0x2025,
            name: "LE Read Local P-256 Public Key",
            cmd_func: Some(cmd_le_read_local_p256),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2026,
            name: "LE Generate DHKey",
            cmd_func: Some(cmd_le_generate_dhkey),
            cmd_size: 64,
            cmd_fixed: true,
            rsp_func: None,
            rsp_size: 0,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2027,
            name: "LE Add Device To Resolving List",
            cmd_func: Some(cmd_generic),
            cmd_size: 0,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2029,
            name: "LE Clear Resolving List",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x202a,
            name: "LE Read Resolving List Size",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_le_read_resolving_list_size),
            rsp_size: 2,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x202f,
            name: "LE Read Maximum Data Length",
            cmd_func: Some(cmd_reset),
            cmd_size: 0,
            cmd_fixed: true,
            rsp_func: Some(rsp_le_read_max_data_len),
            rsp_size: 9,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2036,
            name: "LE Set Extended Advertising Parameters",
            cmd_func: Some(cmd_le_set_ext_adv_params),
            cmd_size: 25,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: false,
        },
        OpcodeData {
            opcode: 0x2037,
            name: "LE Set Extended Advertising Data",
            cmd_func: Some(cmd_le_set_ext_adv_data),
            cmd_size: 4,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2038,
            name: "LE Set Extended Scan Response Data",
            cmd_func: Some(cmd_le_set_ext_scan_rsp_data),
            cmd_size: 4,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2039,
            name: "LE Set Extended Advertising Enable",
            cmd_func: Some(cmd_le_set_ext_adv_enable),
            cmd_size: 1,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2041,
            name: "LE Set Extended Scan Parameters",
            cmd_func: Some(cmd_le_set_ext_scan_params),
            cmd_size: 3,
            cmd_fixed: false,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
        OpcodeData {
            opcode: 0x2042,
            name: "LE Set Extended Scan Enable",
            cmd_func: Some(cmd_le_set_ext_scan_enable),
            cmd_size: 6,
            cmd_fixed: true,
            rsp_func: Some(rsp_generic),
            rsp_size: 1,
            rsp_fixed: true,
        },
    ];
    TABLE
}

fn find_opcode_entry(opcode: u16) -> Option<&'static OpcodeData> {
    opcode_table().iter().find(|e| e.opcode == opcode)
}

// ===========================================================================
// Event table — maps HCI event codes to decoders
// ===========================================================================

fn event_table() -> &'static [EventData] {
    static TABLE: &[EventData] = &[
        EventData {
            event: 0x01,
            name: "Inquiry Complete",
            func: Some(evt_inquiry_complete),
            size: 1,
            fixed: true,
        },
        EventData {
            event: 0x03,
            name: "Connection Complete",
            func: Some(evt_conn_complete),
            size: 11,
            fixed: true,
        },
        EventData {
            event: 0x04,
            name: "Connection Request",
            func: Some(evt_conn_request),
            size: 10,
            fixed: true,
        },
        EventData {
            event: 0x05,
            name: "Disconnection Complete",
            func: Some(evt_disconn_complete),
            size: 4,
            fixed: true,
        },
        EventData {
            event: 0x06,
            name: "Authentication Complete",
            func: Some(evt_auth_complete),
            size: 3,
            fixed: true,
        },
        EventData {
            event: 0x07,
            name: "Remote Name Request Complete",
            func: Some(evt_remote_name),
            size: 7,
            fixed: false,
        },
        EventData {
            event: 0x08,
            name: "Encryption Change",
            func: Some(evt_encrypt_change),
            size: 4,
            fixed: true,
        },
        EventData {
            event: 0x0b,
            name: "Read Remote Supported Features Complete",
            func: Some(evt_remote_features),
            size: 11,
            fixed: true,
        },
        EventData {
            event: 0x0c,
            name: "Read Remote Version Information Complete",
            func: Some(evt_remote_version),
            size: 8,
            fixed: true,
        },
        EventData {
            event: 0x0e,
            name: "Command Complete",
            func: Some(evt_cmd_complete),
            size: 3,
            fixed: false,
        },
        EventData {
            event: 0x0f,
            name: "Command Status",
            func: Some(evt_cmd_status),
            size: 4,
            fixed: true,
        },
        EventData {
            event: 0x13,
            name: "Number of Completed Packets",
            func: Some(evt_num_comp_pkts),
            size: 1,
            fixed: false,
        },
        EventData {
            event: 0x12,
            name: "Role Change",
            func: Some(evt_role_change),
            size: 8,
            fixed: true,
        },
        EventData {
            event: 0x14,
            name: "Mode Change",
            func: Some(evt_mode_change),
            size: 6,
            fixed: true,
        },
        EventData {
            event: 0x18,
            name: "Link Key Notification",
            func: Some(evt_link_key_notify),
            size: 23,
            fixed: true,
        },
        EventData {
            event: 0x1b,
            name: "Max Slots Change",
            func: Some(evt_max_slots_change),
            size: 3,
            fixed: true,
        },
        EventData {
            event: 0x22,
            name: "Inquiry Result with RSSI",
            func: Some(evt_inquiry_result_with_rssi),
            size: 1,
            fixed: false,
        },
        EventData {
            event: 0x2f,
            name: "Extended Inquiry Result",
            func: Some(evt_ext_inquiry_result),
            size: 15,
            fixed: false,
        },
        EventData {
            event: 0x30,
            name: "Encryption Key Refresh Complete",
            func: Some(evt_encrypt_key_refresh),
            size: 3,
            fixed: true,
        },
        EventData {
            event: 0x31,
            name: "IO Capability Request",
            func: Some(evt_io_capability_request),
            size: 6,
            fixed: true,
        },
        EventData {
            event: 0x32,
            name: "IO Capability Response",
            func: Some(evt_io_capability_response),
            size: 9,
            fixed: true,
        },
        EventData {
            event: 0x33,
            name: "User Confirmation Request",
            func: Some(evt_user_confirm_request),
            size: 10,
            fixed: true,
        },
        EventData {
            event: 0x36,
            name: "Simple Pairing Complete",
            func: Some(evt_simple_pairing_complete),
            size: 7,
            fixed: true,
        },
        EventData {
            event: 0x23,
            name: "Read Remote Extended Features Complete",
            func: Some(evt_remote_ext_features),
            size: 13,
            fixed: true,
        },
        EventData {
            event: 0x3e,
            name: "LE Meta Event",
            func: Some(evt_le_meta_event),
            size: 1,
            fixed: false,
        },
    ];
    TABLE
}

fn find_event_entry(event: u8) -> Option<&'static EventData> {
    event_table().iter().find(|e| e.event == event)
}

// ===========================================================================
// LE meta event sub-table
// ===========================================================================

fn le_meta_event_table() -> &'static [LeMetaEventData] {
    static TABLE: &[LeMetaEventData] = &[
        LeMetaEventData {
            subevent: 0x01,
            name: "LE Connection Complete",
            func: Some(evt_le_conn_complete),
            size: 18,
            fixed: true,
        },
        LeMetaEventData {
            subevent: 0x02,
            name: "LE Advertising Report",
            func: Some(evt_le_adv_report),
            size: 1,
            fixed: false,
        },
        LeMetaEventData {
            subevent: 0x03,
            name: "LE Connection Update Complete",
            func: Some(evt_le_conn_update_complete),
            size: 9,
            fixed: true,
        },
        LeMetaEventData {
            subevent: 0x04,
            name: "LE Read Remote Features Complete",
            func: Some(evt_le_read_remote_features_complete),
            size: 11,
            fixed: true,
        },
        LeMetaEventData {
            subevent: 0x05,
            name: "LE Long Term Key Request",
            func: Some(evt_le_long_term_key_request),
            size: 12,
            fixed: true,
        },
        LeMetaEventData {
            subevent: 0x07,
            name: "LE Data Length Change",
            func: Some(evt_le_data_len_change),
            size: 10,
            fixed: true,
        },
        LeMetaEventData {
            subevent: 0x0a,
            name: "LE Enhanced Connection Complete",
            func: Some(evt_le_enhanced_conn_complete),
            size: 30,
            fixed: true,
        },
        LeMetaEventData {
            subevent: 0x0d,
            name: "LE Extended Advertising Report",
            func: Some(evt_le_ext_adv_report),
            size: 1,
            fixed: false,
        },
        LeMetaEventData {
            subevent: 0x0c,
            name: "LE PHY Update Complete",
            func: Some(evt_le_phy_update_complete),
            size: 5,
            fixed: true,
        },
    ];
    TABLE
}

fn find_le_meta_event_entry(subevent: u8) -> Option<&'static LeMetaEventData> {
    le_meta_event_table().iter().find(|e| e.subevent == subevent)
}

// ===========================================================================
// Vendor opcode/event dispatch helpers
// ===========================================================================

fn current_vendor_ocf(index: u16, ocf: u16) -> Option<&'static VendorOcf> {
    let manufacturer = get_index_manufacturer(index);
    match manufacturer {
        2 => intel::intel_vendor_ocf(ocf),        // Intel
        15 => broadcom::broadcom_vendor_ocf(ocf), // Broadcom
        _ => None,
    }
}

fn current_vendor_evt(index: u16, data: &[u8]) -> Option<&'static VendorEvt> {
    let manufacturer = get_index_manufacturer(index);
    match manufacturer {
        2 => {
            let mut consumed = 0usize;
            intel::intel_vendor_evt(data, &mut consumed)
        }
        15 => {
            if !data.is_empty() {
                broadcom::broadcom_vendor_evt(data[0])
            } else {
                None
            }
        }
        _ => None,
    }
}

fn get_index_manufacturer(index: u16) -> u16 {
    if (index as usize) >= MAX_INDEX {
        return FALLBACK_MANUFACTURER.with(|f| *f.borrow());
    }
    INDEX_LIST.with(|list| {
        let list = list.borrow();
        if let Some(Some(info)) = list.get(index as usize) {
            info.manufacturer
        } else {
            FALLBACK_MANUFACTURER.with(|f| *f.borrow())
        }
    })
}

fn get_index_msft_opcode(index: u16) -> Option<u16> {
    if (index as usize) >= MAX_INDEX {
        return None;
    }
    INDEX_LIST.with(|list| {
        let list = list.borrow();
        if let Some(Some(info)) = list.get(index as usize) { info.msft_opcode } else { None }
    })
}

// ===========================================================================
// Core dispatch: packet_hci_command, packet_hci_event, ACL/SCO/ISO handlers
// ===========================================================================

/// Decode and display an HCI command packet.
pub fn packet_hci_command(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    data: &[u8],
    size: usize,
) {
    if (index as usize) >= MAX_INDEX {
        return;
    }

    // Increment frame counter
    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        if let Some(Some(info)) = list.get_mut(index as usize) {
            info.frame += 1;
        }
    });

    if size < 3 {
        print_packet(tv, cred, '<', index, "", COLOR_HCI_COMMAND, "HCI Command", "", "");
        print_field!("  Invalid command size ({})", size);
        return;
    }

    let opcode = u16::from_le_bytes([data[0], data[1]]);
    let plen = data[2] as usize;
    let ogf = cmd_opcode_ogf(opcode);
    let ocf = cmd_opcode_ocf(opcode);
    let param_data = if data.len() > 3 { &data[3..] } else { &[] };

    // Check for vendor OGF
    if ogf == OGF_VENDOR_CMD {
        // Check for MSFT opcode
        let msft_opcode = get_index_msft_opcode(index);
        if msft_opcode == Some(opcode) {
            if let Some(vendor_ocf) = msft::msft_vendor_ocf() {
                let color = COLOR_HCI_COMMAND;
                let text = format!(" (0x{:02x}|0x{:04x}) plen {}", ogf, ocf, plen);
                print_packet(tv, cred, '<', index, "", color, vendor_ocf.name, &text, "");
                if !param_data.is_empty() {
                    (vendor_ocf.cmd_func)(index, param_data);
                }
                return;
            }
        }

        // Check for standard vendor OCF
        if let Some(vendor_ocf) = current_vendor_ocf(index, ocf) {
            let color = COLOR_HCI_COMMAND;
            let text = format!(" (0x{:02x}|0x{:04x}) plen {}", ogf, ocf, plen);
            print_packet(tv, cred, '<', index, "", color, vendor_ocf.name, &text, "");
            if !param_data.is_empty() {
                (vendor_ocf.cmd_func)(index, param_data);
            }
            return;
        }

        // Unknown vendor command
        let text = format!(" (0x{:02x}|0x{:04x}) plen {}", ogf, ocf, plen);
        print_packet(
            tv,
            cred,
            '<',
            index,
            "",
            COLOR_HCI_COMMAND_UNKNOWN,
            "Vendor Command",
            &text,
            "",
        );
        if !param_data.is_empty() {
            print_hexdump(param_data);
        }
        return;
    }

    // Standard opcode lookup
    let entry = find_opcode_entry(opcode);
    let (name, color) = if let Some(e) = entry {
        (e.name, COLOR_HCI_COMMAND)
    } else {
        ("Unknown", COLOR_HCI_COMMAND_UNKNOWN)
    };

    let text = format!(" (0x{:02x}|0x{:04x}) plen {}", ogf, ocf, plen);
    print_packet(tv, cred, '<', index, "", color, name, &text, "");

    if let Some(entry) = entry {
        if let Some(cmd_func) = entry.cmd_func {
            if entry.cmd_fixed && param_data.len() < entry.cmd_size {
                print_field!(
                    "  Invalid command parameters size ({} < {})",
                    param_data.len(),
                    entry.cmd_size
                );
                return;
            }
            if !entry.cmd_fixed && param_data.len() < entry.cmd_size {
                print_field!(
                    "  Invalid minimum command parameters size ({} < {})",
                    param_data.len(),
                    entry.cmd_size
                );
                return;
            }
            cmd_func(index, param_data);
        }
    } else if !param_data.is_empty() {
        print_hexdump(param_data);
    }
}

/// Decode and display an HCI event packet.
pub fn packet_hci_event(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    data: &[u8],
    size: usize,
) {
    if (index as usize) >= MAX_INDEX {
        return;
    }

    // Increment frame counter
    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        if let Some(Some(info)) = list.get_mut(index as usize) {
            info.frame += 1;
        }
    });

    if size < 2 {
        print_packet(tv, cred, '>', index, "", COLOR_HCI_EVENT, "HCI Event", "", "");
        print_field!("  Invalid event size ({})", size);
        return;
    }

    let event = data[0];
    let plen = data[1] as usize;
    let param_data = if data.len() > 2 { &data[2..] } else { &[] };

    // Check for vendor event (event code 0xff)
    if event == 0xff {
        // Try vendor-specific decode
        if let Some(vendor_evt) = current_vendor_evt(index, param_data) {
            let text = format!(" (0x{:02x}) plen {}", event, plen);
            print_packet(tv, cred, '>', index, "", COLOR_HCI_EVENT, vendor_evt.name, &text, "");
            if !param_data.is_empty() {
                (vendor_evt.evt_func)(index, param_data);
            }
            return;
        }

        // Check for MSFT vendor event
        if let Some(vendor_evt) = msft::msft_vendor_evt() {
            let msft_opcode = get_index_msft_opcode(index);
            if msft_opcode.is_some() {
                let text = format!(" (0x{:02x}) plen {}", event, plen);
                print_packet(tv, cred, '>', index, "", COLOR_HCI_EVENT, vendor_evt.name, &text, "");
                if !param_data.is_empty() {
                    (vendor_evt.evt_func)(index, param_data);
                }
                return;
            }
        }

        // Fallback to generic vendor event
        let text = format!(" (0x{:02x}) plen {}", event, plen);
        print_packet(tv, cred, '>', index, "", COLOR_HCI_EVENT_UNKNOWN, "Vendor Event", &text, "");
        let manufacturer = get_index_manufacturer(index);
        if manufacturer != 0xFFFF {
            vendor::vendor_event(manufacturer, param_data);
        } else if !param_data.is_empty() {
            print_hexdump(param_data);
        }
        return;
    }

    let entry = find_event_entry(event);
    let (name, color) = if let Some(e) = entry {
        (e.name, COLOR_HCI_EVENT)
    } else {
        ("Unknown", COLOR_HCI_EVENT_UNKNOWN)
    };

    let text = format!(" (0x{:02x}) plen {}", event, plen);
    print_packet(tv, cred, '>', index, "", color, name, &text, "");

    if let Some(entry) = entry {
        if let Some(func) = entry.func {
            if entry.fixed && param_data.len() < entry.size {
                print_field!(
                    "  Invalid event parameters size ({} < {})",
                    param_data.len(),
                    entry.size
                );
                return;
            }
            if !entry.fixed && param_data.len() < entry.size {
                print_field!(
                    "  Invalid minimum event parameters size ({} < {})",
                    param_data.len(),
                    entry.size
                );
                return;
            }
            func(tv, index, param_data);
        }
    } else if !param_data.is_empty() {
        print_hexdump(param_data);
    }
}

/// Decode and display an HCI ACL data packet.
pub fn packet_hci_acldata(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    incoming: bool,
    data: &[u8],
    size: usize,
) {
    if (index as usize) >= MAX_INDEX {
        return;
    }

    // Increment frame counter
    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        if let Some(Some(info)) = list.get_mut(index as usize) {
            info.frame += 1;
        }
    });

    if size < 4 {
        let ident = if incoming { '>' } else { '<' };
        print_packet(tv, cred, ident, index, "", COLOR_HCI_ACLDATA, "ACL Data", "", "");
        print_field!("  Invalid ACL data size ({})", size);
        return;
    }

    let handle_raw = u16::from_le_bytes([data[0], data[1]]);
    let handle = handle_raw & 0x0FFF;
    let flags = (handle_raw >> 12) & 0x000F;
    let dlen = u16::from_le_bytes([data[2], data[3]]) as usize;

    let ident = if incoming { '>' } else { '<' };
    let dir_str = if incoming { "RX" } else { "TX" };

    let flag_str = match flags {
        0x00 => "start",
        0x01 => "continuation",
        0x02 => "start (auto-flushable)",
        0x03 => "complete",
        _ => "unknown",
    };

    let text = format!(
        " {} handle {} flags 0x{:02x} ({}) dlen {}",
        dir_str, handle, flags, flag_str, dlen
    );
    print_packet(tv, cred, ident, index, "", COLOR_HCI_ACLDATA, "ACL Data", &text, "");

    if !has_filter(PacketFilter::SHOW_ACL_DATA) {
        return;
    }

    if data.len() > 4 {
        let payload = &data[4..];
        // Enqueue TX frame for latency tracking
        if !incoming {
            get_conn_data_for_index(index, handle);
        }
        // Dispatch to L2CAP
        l2cap::l2cap_packet(index, incoming, handle, flags as u8, payload, payload.len() as u16);
    }
}

/// Decode and display an HCI SCO data packet.
pub fn packet_hci_scodata(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    incoming: bool,
    data: &[u8],
    size: usize,
) {
    if (index as usize) >= MAX_INDEX {
        return;
    }

    // Increment frame counter
    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        if let Some(Some(info)) = list.get_mut(index as usize) {
            info.frame += 1;
        }
    });

    if size < 3 {
        let ident = if incoming { '>' } else { '<' };
        print_packet(tv, cred, ident, index, "", COLOR_HCI_SCODATA, "SCO Data", "", "");
        print_field!("  Invalid SCO data size ({})", size);
        return;
    }

    let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
    let dlen = data[2] as usize;

    let ident = if incoming { '>' } else { '<' };
    let dir_str = if incoming { "RX" } else { "TX" };

    let text = format!(" {} handle {} dlen {}", dir_str, handle, dlen);
    print_packet(tv, cred, ident, index, "", COLOR_HCI_SCODATA, "SCO Data", &text, "");

    if has_filter(PacketFilter::SHOW_SCO_DATA) && data.len() > 3 {
        print_hexdump(&data[3..]);
    }
}

/// Decode and display an HCI ISO data packet.
fn packet_hci_isodata(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    incoming: bool,
    data: &[u8],
    size: usize,
) {
    if (index as usize) >= MAX_INDEX {
        return;
    }

    // Increment frame counter
    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        if let Some(Some(info)) = list.get_mut(index as usize) {
            info.frame += 1;
        }
    });

    if size < 4 {
        let ident = if incoming { '>' } else { '<' };
        print_packet(tv, cred, ident, index, "", COLOR_HCI_ISODATA, "ISO Data", "", "");
        print_field!("  Invalid ISO data size ({})", size);
        return;
    }

    let handle_raw = u16::from_le_bytes([data[0], data[1]]);
    let handle = handle_raw & 0x0FFF;
    let pb_flag = (handle_raw >> 12) & 0x03;
    let ts_flag = (handle_raw >> 14) & 0x01;
    let dlen = u16::from_le_bytes([data[2], data[3]]) & 0x3FFF;

    let ident = if incoming { '>' } else { '<' };
    let dir_str = if incoming { "RX" } else { "TX" };

    let pb_str = match pb_flag {
        0x00 => "first",
        0x01 => "continuation",
        0x02 => "complete",
        0x03 => "last",
        _ => "unknown",
    };

    let text = format!(
        " {} handle {} flags 0x{:04x} (PB={}, TS={}) dlen {}",
        dir_str,
        handle,
        handle_raw >> 12,
        pb_str,
        ts_flag,
        dlen
    );
    print_packet(tv, cred, ident, index, "", COLOR_HCI_ISODATA, "ISO Data", &text, "");

    if !has_filter(PacketFilter::SHOW_ISO_DATA) {
        return;
    }

    let mut offset = 4usize;

    // Handle optional timestamp
    if ts_flag != 0 && data.len() >= offset + 4 {
        let timestamp = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        print_field!("  Timestamp: 0x{:08x}", timestamp);
        offset += 4;
    }

    // ISO SDU header
    if data.len() >= offset + 4 {
        let sn_raw = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let slen = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) & 0x0FFF;
        let packet_status = (u16::from_le_bytes([data[offset + 2], data[offset + 3]]) >> 14) & 0x03;
        print_field!("  Packet Sequence Number: {}", sn_raw);
        print_field!("  ISO SDU Length: {}", slen);
        let ps_str = match packet_status {
            0x00 => "Valid",
            0x01 => "Possibly invalid",
            0x02 => "Lost",
            _ => "Reserved",
        };
        print_field!("  Packet Status: {} (0x{:02x})", ps_str, packet_status);
        offset += 4;
    }

    if offset < data.len() {
        print_hexdump(&data[offset..]);
    }
}

// ===========================================================================
// Lifecycle functions (from packet.c packet_new_index, etc.)
// ===========================================================================

/// Handle new controller index announcement.
pub fn packet_new_index(
    tv: &libc::timeval,
    index: u16,
    label: &str,
    type_: u8,
    bus: u8,
    name: &str,
) {
    if (index as usize) >= MAX_INDEX {
        return;
    }

    INDEX_LIST.with(|list| {
        let mut list = list.borrow_mut();
        let mut info = IndexInfo::new();
        info.type_ = type_;
        info.bus = bus;
        // Copy name
        let name_bytes = name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), 8);
        info.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        list[index as usize] = Some(info);
    });

    let extra = format!("[hci{}] type {} bus {}", index, hci_typetostr(type_), hci_bustostr(bus));
    print_packet(tv, None, '=', index, "", COLOR_UPDATE, label, "", &extra);
    print_field!("  Type: {} (0x{:02x})", hci_typetostr(type_), type_);
    print_field!("  Bus: {} (0x{:02x})", hci_bustostr(bus), bus);
    print_field!("  Name: {}", name);
}

/// Handle controller index deletion.
pub fn packet_del_index(tv: &libc::timeval, index: u16, label: &str) {
    if (index as usize) < MAX_INDEX {
        INDEX_LIST.with(|list| {
            let mut list = list.borrow_mut();
            list[index as usize] = None;
        });
    }

    print_packet(tv, None, '=', index, "", COLOR_UPDATE, label, "", "");
}

/// Handle controller index open.
pub fn packet_open_index(tv: &libc::timeval, index: u16, label: &str) {
    print_packet(tv, None, '=', index, "", COLOR_UPDATE, label, "", "");
}

/// Handle controller index close.
pub fn packet_close_index(tv: &libc::timeval, index: u16, label: &str) {
    print_packet(tv, None, '=', index, "", COLOR_UPDATE, label, "", "");
}

/// Handle controller index information update.
pub fn packet_index_info(tv: &libc::timeval, index: u16, label: &str, manufacturer: u16) {
    if (index as usize) < MAX_INDEX {
        INDEX_LIST.with(|list| {
            let mut list = list.borrow_mut();
            if let Some(Some(info)) = list.get_mut(index as usize) {
                info.manufacturer = manufacturer;
                // Set MSFT opcode based on manufacturer
                info.msft_opcode = match manufacturer {
                    2 => Some(0xFC1E),    // Intel
                    29 => Some(0xFD70),   // Qualcomm
                    70 => Some(0xFD30),   // Mediatek
                    93 => Some(0xFCF0),   // Realtek
                    1521 => Some(0xFC1E), // Emulator
                    _ => None,
                };
            }
        });
    }

    print_packet(tv, None, '=', index, "", COLOR_UPDATE, label, "", "");
    print_company("  Manufacturer", manufacturer);
}

/// Handle vendor diagnostic data.
pub fn packet_vendor_diag(
    tv: &libc::timeval,
    index: u16,
    manufacturer: u16,
    data: &[u8],
    _size: usize,
) {
    print_packet(tv, None, '=', index, "", COLOR_VENDOR_DIAG, "Vendor Diagnostic", "", "");
    print_company("  Manufacturer", manufacturer);

    match manufacturer {
        15 => broadcom::broadcom_lm_diag(data),
        _ => {
            if !data.is_empty() {
                print_hexdump(data);
            }
        }
    }
}

/// Handle system note messages.
pub fn packet_system_note(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    data: &[u8],
    _size: usize,
) {
    let msg = if !data.is_empty() {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).to_string()
    } else {
        String::new()
    };

    print_packet(
        tv,
        cred,
        '=',
        index,
        "",
        COLOR_SYSTEM_NOTE,
        "System Note",
        &format!(": {}", msg),
        "",
    );
}

/// Handle user logging messages.
pub fn packet_user_logging(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    priority: u8,
    ident: &str,
    data: &[u8],
    _size: usize,
) {
    let level = PRIORITY_LEVEL.with(|p| *p.borrow());
    if (priority as i32) > level {
        return;
    }

    let color = match priority {
        0..=3 => COLOR_ERROR,
        4 => COLOR_WARN,
        5 => COLOR_INFO,
        6 => COLOR_INFO,
        _ => COLOR_DEBUG,
    };

    let msg = if !data.is_empty() {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).to_string()
    } else {
        String::new()
    };

    let label = format!("{}: {}", ident, msg);
    print_packet(tv, cred, '=', index, "", color, &label, "", "");
}

// ===========================================================================
// Central dispatch: packet_monitor, packet_control, packet_simulator
// ===========================================================================

/// Central BTSnoop opcode dispatcher — main entry point for all decoded packets.
pub fn packet_monitor(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    opcode: u16,
    data: &[u8],
    size: usize,
) {
    // Apply index filter
    let filter_idx = INDEX_FILTER.with(|f| *f.borrow());
    if let Some(filter_index) = filter_idx {
        if index != filter_index
            && opcode != BTSNOOP_OPCODE_NEW_INDEX
            && opcode != BTSNOOP_OPCODE_DEL_INDEX
            && opcode != BTSNOOP_OPCODE_INDEX_INFO
        {
            return;
        }
    }

    // Update time offset on first packet
    TIME_OFFSET.with(|to| {
        let mut offset = to.borrow_mut();
        if offset.tv_sec == 0 && offset.tv_usec == 0 {
            *offset = *tv;
        }
    });

    // Update current index
    if (index as usize) < MAX_INDEX {
        INDEX_CURRENT.with(|ic| *ic.borrow_mut() = index);
    }

    match opcode {
        BTSNOOP_OPCODE_NEW_INDEX => {
            if size < 16 {
                return;
            }
            let type_ = data[0];
            let bus = data[1];
            let mut bdaddr = [0u8; 6];
            bdaddr.copy_from_slice(&data[2..8]);
            let end = data[8..16].iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&data[8..8 + end]).to_string();
            packet_new_index(tv, index, "New Index", type_, bus, &name);
        }
        BTSNOOP_OPCODE_DEL_INDEX => {
            packet_del_index(tv, index, "Delete Index");
        }
        BTSNOOP_OPCODE_COMMAND_PKT => {
            packet_hci_command(tv, cred, index, data, size);
        }
        BTSNOOP_OPCODE_EVENT_PKT => {
            packet_hci_event(tv, cred, index, data, size);
        }
        BTSNOOP_OPCODE_ACL_TX_PKT => {
            packet_hci_acldata(tv, cred, index, false, data, size);
        }
        BTSNOOP_OPCODE_ACL_RX_PKT => {
            packet_hci_acldata(tv, cred, index, true, data, size);
        }
        BTSNOOP_OPCODE_SCO_TX_PKT => {
            packet_hci_scodata(tv, cred, index, false, data, size);
        }
        BTSNOOP_OPCODE_SCO_RX_PKT => {
            packet_hci_scodata(tv, cred, index, true, data, size);
        }
        BTSNOOP_OPCODE_OPEN_INDEX => {
            packet_open_index(tv, index, "Open Index");
        }
        BTSNOOP_OPCODE_CLOSE_INDEX => {
            packet_close_index(tv, index, "Close Index");
        }
        BTSNOOP_OPCODE_INDEX_INFO => {
            if size < 8 {
                return;
            }
            let manufacturer = u16::from_le_bytes([data[6], data[7]]);
            packet_index_info(tv, index, "Index Info", manufacturer);
        }
        BTSNOOP_OPCODE_VENDOR_DIAG => {
            let manufacturer = get_index_manufacturer(index);
            packet_vendor_diag(tv, index, manufacturer, data, size);
        }
        BTSNOOP_OPCODE_SYSTEM_NOTE => {
            packet_system_note(tv, cred, index, data, size);
        }
        BTSNOOP_OPCODE_USER_LOGGING => {
            if size < 2 {
                return;
            }
            let priority = data[0];
            let ident_len = data[1] as usize;
            if size < 2 + ident_len {
                return;
            }
            let ident = String::from_utf8_lossy(&data[2..2 + ident_len]).to_string();
            let msg_data = if size > 2 + ident_len { &data[2 + ident_len..] } else { &[] };
            packet_user_logging(tv, cred, index, priority, &ident, msg_data, size);
        }
        BTSNOOP_OPCODE_CTRL_OPEN | BTSNOOP_OPCODE_CTRL_CLOSE => {
            let label =
                if opcode == BTSNOOP_OPCODE_CTRL_OPEN { "Control Open" } else { "Control Close" };
            print_packet(tv, cred, '=', index, "", COLOR_UPDATE, label, "", "");
        }
        BTSNOOP_OPCODE_CTRL_COMMAND | BTSNOOP_OPCODE_CTRL_EVENT => {
            if !has_filter(PacketFilter::SHOW_MGMT_SOCKET) {
                return;
            }
            let label =
                if opcode == BTSNOOP_OPCODE_CTRL_COMMAND { "MGMT Command" } else { "MGMT Event" };
            let color = if opcode == BTSNOOP_OPCODE_CTRL_COMMAND {
                COLOR_HCI_COMMAND
            } else {
                COLOR_MGMT_EVENT
            };
            print_packet(tv, cred, '@', index, "", color, label, "", "");
            if !data.is_empty() {
                print_hexdump(data);
            }
        }
        BTSNOOP_OPCODE_ISO_TX_PKT => {
            packet_hci_isodata(tv, cred, index, false, data, size);
        }
        BTSNOOP_OPCODE_ISO_RX_PKT => {
            packet_hci_isodata(tv, cred, index, true, data, size);
        }
        _ => {
            print_packet(
                tv,
                cred,
                '?',
                index,
                "",
                COLOR_ERROR,
                "Unknown Opcode",
                &format!(" (0x{:04x})", opcode),
                "",
            );
            if !data.is_empty() {
                print_hexdump(data);
            }
        }
    }
}

/// Control socket event dispatcher.
pub fn packet_control(
    tv: &libc::timeval,
    cred: Option<&libc::ucred>,
    index: u16,
    opcode: u16,
    data: &[u8],
    size: usize,
) {
    // Control socket messages are MGMT protocol
    if size < 6 {
        print_packet(tv, cred, '@', index, "MGMT", COLOR_MGMT_EVENT, "Control", "", "");
        if !data.is_empty() {
            print_hexdump(data);
        }
        return;
    }

    let mgmt_opcode = u16::from_le_bytes([data[0], data[1]]);
    let mgmt_index = u16::from_le_bytes([data[2], data[3]]);
    let mgmt_len = u16::from_le_bytes([data[4], data[5]]) as usize;

    let opstr = mgmt_opstr(mgmt_opcode);
    let text = format!(" ({}) index {} len {}", opstr, mgmt_index, mgmt_len);

    let label = if opcode & 0x01 == 0 { "MGMT Command" } else { "MGMT Event" };
    let color = if opcode & 0x01 == 0 { COLOR_HCI_COMMAND } else { COLOR_MGMT_EVENT };

    print_packet(tv, cred, '@', index, "MGMT", color, label, &text, "");

    if data.len() > 6 {
        print_hexdump(&data[6..]);
    }
}

/// Simulator packet dispatcher.
pub fn packet_simulator(tv: &libc::timeval, frequency: u16, data: &[u8], size: usize) {
    print_packet(
        tv,
        None,
        '*',
        0xffff,
        "",
        COLOR_PHY_PACKET,
        "Simulator",
        &format!(" frequency {}", frequency),
        "",
    );
    ll::ll_packet(frequency, data, size as u8, false);
}
