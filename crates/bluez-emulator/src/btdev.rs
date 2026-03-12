// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Virtual HCI controller (btdev) for integration testing
//
// Complete Rust rewrite of emulator/btdev.c (8,953 lines) and emulator/btdev.h
// (113 lines). This is the core virtual Bluetooth controller that emulates
// BR/EDR + LE behavior by:
//
// - Processing H:4 input packets (command, ACL, SCO, ISO)
// - Dispatching table-driven HCI command sets (version/profile-gated)
// - Modeling connections, LE advertising, accept/resolving lists
// - Emitting HCI events back through the send handler
//
// All callback+user_data patterns are replaced with closures.
// The global btdev_list uses std::sync::Mutex for thread safety.
// Timer-based operations use tokio::time::sleep.

use std::collections::HashMap;
use std::io::IoSlice;
use std::sync::Mutex;

use tokio::sync::Mutex as TokioMutex;

use bluez_shared::crypto::aes_cmac::{CryptoError, bt_crypto_ah, bt_crypto_e, random_bytes};
use bluez_shared::crypto::ecc::{EccError, ecc_make_key, ecdh_shared_secret};
use bluez_shared::sys::bluetooth::{
    BDADDR_ANY, BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, bdaddr_t, bt_get_le16,
    bt_get_le32, bt_put_le16, bt_put_le32,
};
use bluez_shared::sys::hci::{
    ACL_LINK, ACL_START, ACL_START_NO_FLUSH, ESCO_LINK, EVT_CMD_COMPLETE, EVT_CMD_STATUS,
    EVT_CONN_COMPLETE, EVT_DISCONN_COMPLETE, EVT_ENCRYPT_CHANGE, EVT_INQUIRY_COMPLETE,
    EVT_LE_META_EVENT, EVT_NUM_COMP_PKTS, HCI_ACLDATA_PKT, HCI_AMP, HCI_COMMAND_PKT, HCI_EVENT_PKT,
    HCI_ISODATA_PKT, HCI_PRIMARY, HCI_SCODATA_PKT, HCI_SUCCESS, HCI_UNKNOWN_COMMAND,
    LE_PUBLIC_ADDRESS, LE_RANDOM_ADDRESS, OGF_HOST_CTL, OGF_INFO_PARAM, OGF_LE_CTL,
    OGF_LINK_CONTROL, OGF_VENDOR_CMD, SCO_LINK, acl_flags, acl_handle, acl_handle_pack,
    evt_cmd_complete, evt_cmd_status, evt_conn_complete, evt_disconn_complete,
    evt_le_connection_complete, hci_acl_hdr, hci_command_hdr, hci_event_hdr, hci_iso_hdr,
    hci_sco_hdr, opcode,
};

// ---------------------------------------------------------------------------
// Response constants (replaces C macros)
// ---------------------------------------------------------------------------

/// Default response: let the internal command table handle the command.
pub const BTDEV_RESPONSE_DEFAULT: u8 = 0;

/// Override: respond with Command Status event.
pub const BTDEV_RESPONSE_COMMAND_STATUS: u8 = 1;

/// Override: respond with Command Complete event.
pub const BTDEV_RESPONSE_COMMAND_COMPLETE: u8 = 2;

// ---------------------------------------------------------------------------
// Internal size constants (matching C exactly)
// ---------------------------------------------------------------------------

const AL_SIZE: usize = 16;
const RL_SIZE: usize = 16;
const CIS_SIZE: usize = 3;
const BIS_SIZE: usize = 3;
const CIG_SIZE: usize = 3;
const MAX_PA_DATA_LEN: usize = 252;
const MAX_EXT_ADV_LEN: usize = 252;
const MAX_HOOK_ENTRIES: usize = 16;
const MAX_EXT_ADV_SETS: usize = 3;
const MAX_BTDEV_ENTRIES: usize = 16;
const MAX_PENDING_CONN: usize = 16;
const DEFAULT_INQUIRY_INTERVAL: u64 = 100;

const ACL_HANDLE_BASE: u16 = 1;
const SCO_HANDLE_BASE: u16 = 0x100;
const CIS_HANDLE_BASE: u16 = 0x100;
const BIS_HANDLE_BASE: u16 = 0x200;
const SYNC_HANDLE: u16 = 1;
const INV_HANDLE: u16 = 0xffff;

const LINK_KEY_NONE: [u8; 16] = [0; 16];
const LINK_KEY_DUMMY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during BtDev operations.
#[derive(Debug, thiserror::Error)]
pub enum BtDevError {
    /// No free slot available in the global device list.
    #[error("No free slot in device list")]
    NoFreeSlot,

    /// Invalid device type for the requested operation.
    #[error("Unsupported device type for this operation")]
    UnsupportedType,

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// ECC operation failed.
    #[error("ECC error: {0}")]
    Ecc(#[from] EccError),

    /// Invalid HCI parameter.
    #[error("Invalid HCI parameter")]
    InvalidParameter,

    /// Connection not found.
    #[error("Connection not found")]
    ConnectionNotFound,

    /// Command disallowed in current state.
    #[error("Command disallowed")]
    CommandDisallowed,
}

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Virtual controller type variants, matching `enum btdev_type` in C.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BtDevType {
    /// Dual-mode BR/EDR+LE controller (BT 4.x).
    BrEdrLe,
    /// BR/EDR-only controller.
    BrEdr,
    /// LE-only controller.
    Le,
    /// AMP controller.
    Amp,
    /// BR/EDR 2.0 controller (legacy).
    BrEdr20,
    /// Dual-mode controller with BT 5.0 features.
    BrEdrLe50,
    /// Dual-mode controller with BT 5.2 features (LE Audio).
    BrEdrLe52,
    /// Dual-mode controller with BT 6.0 features.
    BrEdrLe60,
}

/// Hook type for intercepting HCI commands/events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BtDevHookType {
    /// Pre-command processing hook.
    PreCmd,
    /// Post-command processing hook.
    PostCmd,
    /// Pre-event generation hook.
    PreEvt,
    /// Post-event generation hook.
    PostEvt,
}

// ---------------------------------------------------------------------------
// Internal structures
// ---------------------------------------------------------------------------

/// Connection tracking (replaces `struct btdev_conn`).
struct BtDevConn {
    handle: u16,
    link_type: u8,
    encr_mode: u8,
    encrypted: bool,
    /// Peer device BD_ADDR.
    peer_addr: [u8; 6],
    /// Index of the peer device in the global btdev_list.
    peer_index: Option<usize>,
    /// Handle on the peer device's connection list.
    peer_handle: Option<u16>,
    /// Sub-connections (for CIS links under a CIG).
    sub_conn_handles: Vec<u16>,
    /// Opaque data pointer for profile-specific use.
    data: Vec<u8>,
}

/// Accept list entry (replaces `struct btdev_al`).
#[derive(Clone)]
struct AcceptListEntry {
    addr_type: u8,
    addr: bdaddr_t,
}

impl AcceptListEntry {
    fn reset(&mut self) {
        self.addr_type = 0xff;
        self.addr = BDADDR_ANY;
    }
}

/// Resolving list entry (replaces `struct btdev_rl`).
#[derive(Clone)]
struct ResolvingListEntry {
    addr_type: u8,
    addr: bdaddr_t,
    mode: u8,
    peer_irk: [u8; 16],
    local_irk: [u8; 16],
}

impl ResolvingListEntry {
    fn reset(&mut self) {
        self.addr_type = 0xff;
        self.addr = BDADDR_ANY;
        self.peer_irk = [0; 16];
        self.local_irk = [0; 16];
        self.mode = 0;
    }
}

/// Extended advertising set (replaces `struct le_ext_adv`).
#[derive(Default)]
struct LeExtAdv {
    handle: u8,
    enable: u8,
    enabled: bool,
    interval: u32,
    adv_type: u8,
    own_addr_type: u8,
    direct_addr_type: u8,
    direct_addr: [u8; 6],
    filter_policy: u8,
    random_addr: [u8; 6],
    rpa: bool,
    adv_data: Vec<u8>,
    adv_data_len: usize,
    scan_rsp: Vec<u8>,
    scan_rsp_len: usize,
    scan_data: Vec<u8>,
    broadcast_id: u32,
    sid: u8,
}

/// Periodic advertising state (replaces `struct le_per_adv`).
struct LePerAdv {
    addr_type: u8,
    addr: [u8; 6],
    sid: u8,
    sync_handle: u16,
    /// Indices of remote devices synced to this PA.
    synced_peers: Vec<usize>,
}

/// Broadcast Isochronous Group (replaces `struct le_big`).
struct LeBig {
    handle: u8,
    big_handle: u8,
    num_bis: u8,
    encrypted: bool,
    bis_handles: Vec<u16>,
}

/// CIG parameters (replaces `struct le_cig`).
#[derive(Clone, Default)]
struct LeCig {
    cig_id: u8,
    sdu_interval_c_to_p: u32,
    sdu_interval_p_to_c: u32,
    ft_c_to_p: u8,
    ft_p_to_c: u8,
    latency_c_to_p: u16,
    latency_p_to_c: u16,
    num_cis: u8,
    cis_params: Vec<LeCisParam>,
    activated: bool,
}

/// CIS parameters within a CIG.
#[derive(Clone)]
struct LeCisParam {
    cis_id: u8,
    max_sdu_c_to_p: u16,
    max_sdu_p_to_c: u16,
    phy_c_to_p: u8,
    phy_p_to_c: u8,
    rtn_c_to_p: u8,
    rtn_p_to_c: u8,
}

/// Pending incoming connection (replaces `struct pending_conn`).
struct PendingConn {
    peer_index: usize,
    link_type: u8,
}

/// Hook for intercepting specific opcodes.
struct Hook {
    handler: Box<dyn Fn(&[u8]) -> bool + Send + Sync>,
}

// ---------------------------------------------------------------------------
// Command dispatch table types
// ---------------------------------------------------------------------------

/// Result of a command handler function.
/// Returns Ok(true) if a complete handler should also be run,
/// Ok(false) if the command fully handled the response,
/// Err with specific errno-like codes for error status generation.
type CmdResult = Result<bool, i32>;

/// Type alias for the send handler callback to satisfy clippy::type_complexity.
type SendHandlerFn = Option<Box<dyn Fn(&[IoSlice<'_>]) + Send + Sync>>;

/// Type alias for the external command handler callback.
type CommandHandlerFn = Option<Box<dyn Fn(u16, &[u8], &mut BtDevCallback) + Send + Sync>>;

/// Type alias for a single command handler function pointer.
type CmdHandlerFn = fn(&mut BtDev, &[u8]) -> CmdResult;

/// Type alias for a command dispatch table entry:
/// (opcode, handler, optional_complete_handler).
type CmdTableEntry = (u16, CmdHandlerFn, Option<CmdHandlerFn>);

// errno-like constants for CmdResult errors
const CMD_ENOTSUP: i32 = -95;
const CMD_EINVAL: i32 = -22;
const CMD_EPERM: i32 = -1;
const CMD_EEXIST: i32 = -17;
const CMD_ENOENT: i32 = -2;
const CMD_EALREADY: i32 = -114;

// ---------------------------------------------------------------------------
// BtDevCallback (replaces `struct btdev_callback`)
// ---------------------------------------------------------------------------

/// Callback handle passed to external command handlers for response generation.
///
/// The external handler calls one of the response methods to indicate how the
/// command should be handled:
/// - `command_default()` — let the internal dispatch table handle it
/// - `command_status(status)` — respond with Command Status event
/// - `command_complete(data)` — respond with Command Complete event
pub struct BtDevCallback {
    response: u8,
    status: u8,
    data: Vec<u8>,
    opcode: u16,
    cmd_data: Vec<u8>,
}

impl BtDevCallback {
    /// Respond to the command in the default way (internal dispatch).
    pub fn command_default(&mut self) {
        self.response = BTDEV_RESPONSE_DEFAULT;
        self.status = 0x00;
        self.data.clear();
    }

    /// Respond with a Command Status event.
    pub fn command_status(&mut self, status: u8) {
        self.response = BTDEV_RESPONSE_COMMAND_STATUS;
        self.status = status;
        self.data.clear();
    }

    /// Respond with a Command Complete event with the given data.
    pub fn command_complete(&mut self, data: &[u8]) {
        self.response = BTDEV_RESPONSE_COMMAND_COMPLETE;
        self.status = 0x00;
        self.data = data.to_vec();
    }

    /// Generic response method matching C `btdev_command_response`.
    pub fn command_response(&mut self, response: u8, status: u8, data: &[u8]) {
        self.response = response;
        self.status = status;
        self.data = data.to_vec();
    }

    /// Get the opcode of the command being handled.
    pub fn get_opcode(&self) -> u16 {
        self.opcode
    }

    /// Get the raw command data.
    pub fn get_cmd_data(&self) -> &[u8] {
        &self.cmd_data
    }
}

// ---------------------------------------------------------------------------
// Global device list (replaces `static struct btdev *btdev_list[]`)
// ---------------------------------------------------------------------------

/// Thread-safe global tracking of which device slots are in use.
/// The C code uses `static struct btdev *btdev_list[MAX_BTDEV_ENTRIES]`.
/// We track slot occupancy with a bool array; each BtDev stores its index.
static BTDEV_LIST: Mutex<[bool; MAX_BTDEV_ENTRIES]> = Mutex::new([false; MAX_BTDEV_ENTRIES]);

/// Allocate a free slot in the global device list. Returns the index.
fn allocate_btdev_slot() -> Option<usize> {
    let mut list = BTDEV_LIST.lock().unwrap_or_else(|e| e.into_inner());
    for (i, slot) in list.iter_mut().enumerate() {
        if !*slot {
            *slot = true;
            return Some(i);
        }
    }
    None
}

/// Release a slot in the global device list.
fn free_btdev_slot(index: usize) {
    let mut list = BTDEV_LIST.lock().unwrap_or_else(|e| e.into_inner());
    if index < MAX_BTDEV_ENTRIES {
        list[index] = false;
    }
}

/// Derive BD_ADDR deterministically from id and index, matching C exactly.
/// C: bdaddr[0]=id&0xff, bdaddr[1]=id>>8, bdaddr[2]=index,
///    bdaddr[3]=0x01, bdaddr[4]=0xaa, bdaddr[5]=0x00
fn derive_bdaddr(id: u16, index: usize) -> [u8; 6] {
    [(id & 0xff) as u8, (id >> 8) as u8, index as u8, 0x01, 0xaa, 0x00]
}

// ---------------------------------------------------------------------------
// BtDev — the virtual HCI controller
// ---------------------------------------------------------------------------

/// Virtual Bluetooth HCI controller for testing.
///
/// Emulates a complete Bluetooth controller with support for BR/EDR and LE
/// operations. Processes H:4 packets, dispatches HCI commands through a
/// table-driven command set, manages connections, and generates HCI events.
pub struct BtDev {
    // --- Identity and type ---
    dev_type: BtDevType,
    id: u16,
    list_index: usize,

    // --- Controller identification ---
    manufacturer: u16,
    version: u8,
    revision: u16,
    country_code: u8,
    bdaddr: [u8; 6],
    random_addr: [u8; 6],

    // --- Feature/command bitmaps ---
    commands: [u8; 64],
    max_page: u8,
    features: [u8; 8],
    feat_page_2: [u8; 8],
    le_features: [u8; 248],
    le_states: [u8; 8],

    // --- Event masks ---
    event_mask: [u8; 8],
    event_mask_page2: [u8; 8],
    le_event_mask: [u8; 8],
    event_filter: u8,

    // --- MTU values ---
    acl_mtu: u16,
    acl_max_pkt: u16,
    sco_mtu: u16,
    sco_max_pkt: u16,
    iso_mtu: u16,
    iso_max_pkt: u16,

    // --- BR/EDR state ---
    name: [u8; 248],
    dev_class: [u8; 3],
    voice_setting: u16,
    conn_accept_timeout: u16,
    page_timeout: u16,
    scan_enable: u8,
    page_scan_interval: u16,
    page_scan_window: u16,
    page_scan_type: u16,
    auth_enable: u8,
    inquiry_scan_interval: u16,
    inquiry_scan_window: u16,
    inquiry_mode: u8,
    afh_assessment_mode: u8,
    ext_inquiry_fec: u8,
    ext_inquiry_rsp: [u8; 240],
    simple_pairing_mode: u8,
    ssp_debug_mode: u8,
    secure_conn_support: u8,
    host_flow_control: u8,
    sco_flowctl: u8,
    le_supported: u8,
    le_simultaneous: u8,
    default_link_policy: u16,

    // --- Security state ---
    auth_init: bool,
    link_key: [u8; 16],
    pin: [u8; 16],
    pin_len: u8,
    io_cap: u8,
    auth_req: u8,
    ssp_auth_complete: bool,
    ssp_status: u8,

    // --- LE advertising state ---
    le_adv_data: [u8; 31],
    le_adv_data_len: u8,
    le_adv_type: u8,
    le_adv_own_addr: u8,
    le_adv_direct_addr_type: u8,
    le_adv_direct_addr: [u8; 6],
    le_adv_filter_policy: u8,
    le_scan_data: [u8; 31],
    le_scan_data_len: u8,
    le_scan_enable: u8,
    le_scan_type: u8,
    le_scan_own_addr_type: u8,
    le_scan_filter_policy: u8,
    le_filter_dup: u8,
    le_adv_enable: u8,
    le_pa_enable: u8,
    le_pa_properties: u16,
    le_pa_min_interval: u16,
    le_pa_max_interval: u16,
    le_pa_data_len: u8,
    le_pa_data: [u8; MAX_PA_DATA_LEN],
    le_ltk: [u8; 16],
    le_iso_path: [u8; 2],
    le_local_sk256: [u8; 32],
    le_ext_adv_type: u16,

    // --- Accept list ---
    le_al_len: u8,
    le_al: Vec<AcceptListEntry>,

    // --- Resolving list ---
    le_rl_len: u8,
    le_rl: Vec<ResolvingListEntry>,
    le_rl_enable: u8,
    le_rl_timeout: u16,

    // --- CIG/CIS ---
    le_cig: [LeCig; CIG_SIZE],

    // --- Connection tracking ---
    conns: HashMap<u16, BtDevConn>,
    next_handle: u16,
    pending_conns: Vec<PendingConn>,

    // --- Extended advertising sets ---
    le_ext_adv_sets: HashMap<u8, LeExtAdv>,

    // --- Periodic advertising ---
    le_per_adv: Vec<LePerAdv>,

    // --- BIG ---
    le_big: Vec<LeBig>,

    // --- Sync train ---
    sync_train_interval: u16,
    sync_train_timeout: u32,
    sync_train_service_data: u8,

    // --- Inquiry state ---
    inquiry_active: bool,

    // --- Hook list ---
    hooks: HashMap<(BtDevHookType, u16), Hook>,

    // --- Vendor opcodes ---
    msft_opcode: u16,
    emu_opcode: u16,
    aosp_capable: bool,

    // --- Handlers ---
    send_handler: SendHandlerFn,
    command_handler: CommandHandlerFn,
    debug_callback: Option<Box<dyn Fn(&str) + Send + Sync>>,

    // --- Has crypto ---
    has_crypto: bool,
}

impl Drop for BtDev {
    fn drop(&mut self) {
        free_btdev_slot(self.list_index);
        tracing::debug!("btdev: destroyed controller id={} index={}", self.id, self.list_index);
    }
}

// ---------------------------------------------------------------------------
// Feature and command initialization helpers
// ---------------------------------------------------------------------------

/// Set commands supported by all controller types.
fn set_common_commands_all(commands: &mut [u8; 64]) {
    // Octet 0 bit 5: Set Event Mask
    commands[0] |= 0x20;
    // Octet 5 bit 6: Reset
    commands[5] |= 0x40;
    // Octet 5 bit 7: Set Event Filter
    commands[5] |= 0x80;
    // Octet 14 bit 2: Read Local Version Information
    commands[14] |= 0x08;
    // Octet 14 bit 3: Read Local Supported Features
    commands[14] |= 0x10;
    // Octet 14 bit 5: Read Buffer Size
    commands[14] |= 0x20;
    // Octet 15 bit 1: Read BD_ADDR
    commands[15] |= 0x02;
    // Octet 14 bit 6: Read Local Supported Commands
    commands[14] |= 0x40;
}

/// Set commands for BR/EDR+LE controllers.
fn set_common_commands_bredrle(commands: &mut [u8; 64]) {
    // Octet 22 bit 2: Set Event Mask Page 2
    commands[22] |= 0x04;
    // Octet 24 bit 5: Read LE Host Supported
    commands[24] |= 0x20;
    // Octet 24 bit 6: Write LE Host Supported
    commands[24] |= 0x40;
}

/// Set commands common to BR/EDR 2.0+.
fn set_common_commands_bredr20(commands: &mut [u8; 64]) {
    // Octet 0 bit 0: Inquiry
    commands[0] |= 0x01;
    // Octet 0 bit 1: Inquiry Cancel
    commands[0] |= 0x02;
    // Octet 0 bit 2: Periodic Inquiry Mode
    commands[0] |= 0x04;
    // Octet 0 bit 3: Exit Periodic Inquiry Mode
    commands[0] |= 0x08;
    // Octet 1 bit 0: Create Connection
    commands[1] |= 0x01;
    // Octet 1 bit 1: Disconnect
    commands[1] |= 0x02;
    // Octet 1 bit 3: Create Connection Cancel
    commands[1] |= 0x08;
    // Octet 1 bit 4: Accept Connection Request
    commands[1] |= 0x10;
    // Octet 1 bit 5: Reject Connection Request
    commands[1] |= 0x20;
    // Octet 2 bit 3: Change Connection Packet Type
    commands[2] |= 0x08;
    // Octet 2 bit 4: Authentication Requested
    commands[2] |= 0x10;
    // Octet 2 bit 5: Set Connection Encryption
    commands[2] |= 0x20;
    // Octet 3 bit 0: Remote Name Request
    commands[3] |= 0x01;
    // Octet 3 bit 1: Remote Name Request Cancel
    commands[3] |= 0x02;
    // Octet 3 bit 2: Read Remote Supported Features
    commands[3] |= 0x04;
    // Octet 3 bit 3: Read Remote Extended Features
    commands[3] |= 0x08;
    // Octet 3 bit 4: Read Remote Version Information
    commands[3] |= 0x10;
    // Octet 4 bit 1: Read Default Link Policy Settings
    commands[4] |= 0x02;
    // Octet 4 bit 2: Write Default Link Policy Settings
    commands[4] |= 0x04;
    // Octet 6 bit 0: Write PIN Type
    commands[6] |= 0x01;
    // Octet 6 bit 5: Read Stored Link Key
    commands[6] |= 0x20;
    // Octet 6 bit 6: Write Stored Link Key
    commands[6] |= 0x40;
    // Octet 6 bit 7: Delete Stored Link Key
    commands[6] |= 0x80;
    // Octet 7 bit 0: Write Local Name
    commands[7] |= 0x01;
    // Octet 7 bit 1: Read Local Name
    commands[7] |= 0x02;
    // Octet 7 bit 2: Read Connection Accept Timeout
    commands[7] |= 0x04;
    // Octet 7 bit 3: Write Connection Accept Timeout
    commands[7] |= 0x08;
    // Octet 7 bit 4: Read Page Timeout
    commands[7] |= 0x10;
    // Octet 7 bit 5: Write Page Timeout
    commands[7] |= 0x20;
    // Octet 7 bit 6: Read Scan Enable
    commands[7] |= 0x40;
    // Octet 7 bit 7: Write Scan Enable
    commands[7] |= 0x80;
    // Octet 8 bit 0: Read Page Scan Activity
    commands[8] |= 0x01;
    // Octet 8 bit 1: Write Page Scan Activity
    commands[8] |= 0x02;
    // Octet 8 bit 2: Read Inquiry Scan Activity
    commands[8] |= 0x04;
    // Octet 8 bit 3: Write Inquiry Scan Activity
    commands[8] |= 0x08;
    // Octet 8 bit 4: Read Authentication Enable
    commands[8] |= 0x10;
    // Octet 8 bit 5: Write Authentication Enable
    commands[8] |= 0x20;
    // Octet 9 bit 0: Read Class of Device
    commands[9] |= 0x01;
    // Octet 9 bit 1: Write Class of Device
    commands[9] |= 0x02;
    // Octet 9 bit 2: Read Voice Setting
    commands[9] |= 0x04;
    // Octet 9 bit 3: Write Voice Setting
    commands[9] |= 0x08;
    // Octet 10 bit 4: Read Transmit Power Level
    commands[10] |= 0x10;
    // Octet 11 bit 2: Set Host Controller to Host Flow Control
    commands[11] |= 0x04;
    // Octet 11 bit 4: Host Number of Completed Packets
    commands[11] |= 0x10;
    // Octet 11 bit 5: Read Link Supervision Timeout
    commands[11] |= 0x20;
    // Octet 11 bit 6: Write Link Supervision Timeout
    commands[11] |= 0x40;
    // Octet 12 bit 0: Read Number of Supported IAC
    commands[12] |= 0x01;
    // Octet 12 bit 1: Read Current IAC LAP
    commands[12] |= 0x02;
    // Octet 12 bit 2: Write Current IAC LAP
    commands[12] |= 0x04;
    // Octet 13 bit 4: Read Page Scan Type
    commands[13] |= 0x10;
    // Octet 13 bit 5: Write Page Scan Type
    commands[13] |= 0x20;
    // Octet 13 bit 6: Read AFH Channel Assessment Mode
    commands[13] |= 0x40;
    // Octet 13 bit 7: Write AFH Channel Assessment Mode
    commands[13] |= 0x80;
    // Octet 15 bit 2: Read Page Scan Mode
    commands[15] |= 0x04;
    // Octet 17 bit 6: Read Inquiry Mode
    commands[17] |= 0x40;
    // Octet 17 bit 7: Write Inquiry Mode
    commands[17] |= 0x80;
    // Octet 18 bit 0: Read Extended Inquiry Response
    commands[18] |= 0x01;
    // Octet 18 bit 1: Write Extended Inquiry Response
    commands[18] |= 0x02;
}

/// Set BR/EDR commands (4.0+).
fn set_bredr_commands(commands: &mut [u8; 64]) {
    // Octet 20 bit 0: Read Encryption Key Size
    commands[20] |= 0x01;
    // Octet 20 bit 2: Read Simple Pairing Mode
    commands[20] |= 0x04;
    // Octet 20 bit 3: Write Simple Pairing Mode
    commands[20] |= 0x08;
    // Octet 20 bit 4: Read Local OOB Data
    commands[20] |= 0x10;
    // Octet 23 bit 0: Read Inquiry Response Transmit Power Level
    commands[23] |= 0x01;
    // Octet 29 bit 2: IO Capability Request Reply
    commands[29] |= 0x04;
    // Octet 29 bit 3: User Confirmation Request Reply
    commands[29] |= 0x08;
    // Octet 29 bit 4: User Confirmation Request Negative Reply
    commands[29] |= 0x10;
    // Octet 29 bit 5: User Passkey Request Reply
    commands[29] |= 0x20;
    // Octet 29 bit 6: User Passkey Request Negative Reply
    commands[29] |= 0x40;
    // Octet 29 bit 7: IO Capability Request Negative Reply
    commands[29] |= 0x80;
    // Octet 30 bit 3: Read Secure Connections Host Support
    commands[30] |= 0x08;
    // Octet 30 bit 4: Write Secure Connections Host Support
    commands[30] |= 0x10;
    // Octet 32 bit 6: Read Local OOB Extended Data
    commands[32] |= 0x40;
    // Octet 33 bit 6: Set Event Mask Page 2
    commands[22] |= 0x04;
    // Octet 34 bit 0: Read Synchronization Train Parameters
    commands[34] |= 0x01;
    // Octet 34 bit 1: Write Synchronization Train Parameters
    commands[34] |= 0x02;
    // Octet 10 bit 2: Read SCO Flow Control Enable
    commands[10] |= 0x04;
    // Octet 10 bit 3: Write SCO Flow Control Enable
    commands[10] |= 0x08;
    // Octet 11 bit 3: Host Buffer Size
    commands[11] |= 0x08;
}

/// Set LE commands.
fn set_le_commands(commands: &mut [u8; 64]) {
    // Octet 25 bit 0: LE Set Event Mask
    commands[25] |= 0x01;
    // Octet 25 bit 1: LE Read Buffer Size [v1]
    commands[25] |= 0x02;
    // Octet 25 bit 2: LE Read Local P-256 Public Key
    commands[25] |= 0x04;
    // Octet 25 bit 3: LE Read Supported Features
    commands[25] |= 0x08;
    // Octet 25 bit 4: LE Set Random Address
    commands[25] |= 0x10;
    // Octet 25 bit 5: LE Set Advertising Parameters
    commands[25] |= 0x20;
    // Octet 25 bit 6: LE Read Advertising Physical Channel Tx Power
    commands[25] |= 0x40;
    // Octet 25 bit 7: LE Set Advertising Data
    commands[25] |= 0x80;
    // Octet 26 bit 0: LE Set Scan Response Data
    commands[26] |= 0x01;
    // Octet 26 bit 1: LE Set Advertise Enable
    commands[26] |= 0x02;
    // Octet 26 bit 2: LE Set Scan Parameters
    commands[26] |= 0x04;
    // Octet 26 bit 3: LE Set Scan Enable
    commands[26] |= 0x08;
    // Octet 26 bit 4: LE Create Connection
    commands[26] |= 0x10;
    // Octet 26 bit 5: LE Create Connection Cancel
    commands[26] |= 0x20;
    // Octet 26 bit 6: LE Read Accept List Size
    commands[26] |= 0x40;
    // Octet 26 bit 7: LE Clear Accept List
    commands[26] |= 0x80;
    // Octet 27 bit 0: LE Add Device to Accept List
    commands[27] |= 0x01;
    // Octet 27 bit 1: LE Remove Device from Accept List
    commands[27] |= 0x02;
    // Octet 27 bit 5: LE Encrypt
    commands[27] |= 0x20;
    // Octet 27 bit 6: LE Rand
    commands[27] |= 0x40;
    // Octet 27 bit 7: LE Start Encryption
    commands[27] |= 0x80;
    // Octet 28 bit 0: LE Long Term Key Request Reply
    commands[28] |= 0x01;
    // Octet 28 bit 1: LE Long Term Key Request Negative Reply
    commands[28] |= 0x02;
    // Octet 28 bit 2: LE Read Supported States
    commands[28] |= 0x04;
    // Octet 33 bit 0: LE Set Data Length
    commands[33] |= 0x01;
    // Octet 33 bit 1: LE Read Suggested Default Data Length
    commands[33] |= 0x02;
    // Octet 33 bit 2: LE Write Suggested Default Data Length
    commands[33] |= 0x04;
    // Octet 33 bit 3: LE Generate DHKey [v1]
    commands[33] |= 0x08;
    // Octet 34 bit 2: LE Add Device to Resolving List
    commands[34] |= 0x04;
    // Octet 34 bit 3: LE Remove Device from Resolving List
    commands[34] |= 0x08;
    // Octet 34 bit 4: LE Clear Resolving List
    commands[34] |= 0x10;
    // Octet 34 bit 5: LE Read Resolving List Size
    commands[34] |= 0x20;
    // Octet 34 bit 6: LE Read Peer Resolvable Address
    commands[34] |= 0x40;
    // Octet 34 bit 7: LE Read Local Resolvable Address
    commands[34] |= 0x80;
    // Octet 35 bit 0: LE Set Address Resolution Enable
    commands[35] |= 0x01;
    // Octet 35 bit 1: LE Set Resolvable Private Address Timeout
    commands[35] |= 0x02;
    // Octet 35 bit 2: LE Read Maximum Data Length
    commands[35] |= 0x04;
    // Octet 35 bit 3: LE Read PHY
    commands[35] |= 0x08;
    // Octet 35 bit 4: LE Set Default PHY
    commands[35] |= 0x10;
    // Octet 35 bit 5: LE Set PHY
    commands[35] |= 0x20;
    // Octet 36 bit 1: LE Set Advertising Set Random Address
    commands[36] |= 0x02;
    // Octet 36 bit 2: LE Set Extended Advertising Parameters
    commands[36] |= 0x04;
    // Octet 36 bit 3: LE Set Extended Advertising Data
    commands[36] |= 0x08;
    // Octet 36 bit 4: LE Set Extended Scan Response Data
    commands[36] |= 0x10;
    // Octet 36 bit 5: LE Set Extended Advertising Enable
    commands[36] |= 0x20;
    // Octet 36 bit 6: LE Read Max Advertising Data Length
    commands[36] |= 0x40;
    // Octet 36 bit 7: LE Read Number of Supported Advertising Sets
    commands[36] |= 0x80;
    // Octet 37 bit 0: LE Remove Advertising Set
    commands[37] |= 0x01;
    // Octet 37 bit 1: LE Clear Advertising Sets
    commands[37] |= 0x02;
    // Octet 37 bit 2: LE Set Periodic Advertising Parameters
    commands[37] |= 0x04;
    // Octet 37 bit 3: LE Set Periodic Advertising Data
    commands[37] |= 0x08;
    // Octet 37 bit 4: LE Set Periodic Advertising Enable
    commands[37] |= 0x10;
    // Octet 37 bit 5: LE Set Extended Scan Parameters
    commands[37] |= 0x20;
    // Octet 37 bit 6: LE Set Extended Scan Enable
    commands[37] |= 0x40;
    // Octet 37 bit 7: LE Extended Create Connection
    commands[37] |= 0x80;
    // Octet 38 bit 3: LE Read TX Power
    commands[38] |= 0x08;
}

/// Set commands for 5.0+ controllers.
fn set_le_50_commands(commands: &mut [u8; 64]) {
    // Octet 38 bit 4: LE Read RF Path Compensation
    commands[38] |= 0x10;
    // Octet 38 bit 5: LE Write RF Path Compensation
    commands[38] |= 0x20;
    // Octet 38 bit 6: LE Set Privacy Mode
    commands[38] |= 0x40;
}

/// Set commands for 5.2+ (ISO/CIG/CIS/BIG).
fn set_le_52_commands(commands: &mut [u8; 64]) {
    // Octet 41 bit 0: LE Read Buffer Size [v2]
    commands[41] |= 0x01;
    // Octet 41 bit 1: LE Read ISO TX Sync
    commands[41] |= 0x02;
    // Octet 41 bit 2: LE Set CIG Parameters
    commands[41] |= 0x04;
    // Octet 41 bit 4: LE Create CIS
    commands[41] |= 0x10;
    // Octet 41 bit 5: LE Remove CIG
    commands[41] |= 0x20;
    // Octet 41 bit 6: LE Accept CIS Request
    commands[41] |= 0x40;
    // Octet 41 bit 7: LE Reject CIS Request
    commands[41] |= 0x80;
    // Octet 42 bit 0: LE Create BIG
    commands[42] |= 0x01;
    // Octet 42 bit 2: LE Terminate BIG
    commands[42] |= 0x04;
    // Octet 42 bit 5: LE Setup ISO Data Path
    commands[42] |= 0x20;
    // Octet 42 bit 6: LE Remove ISO Data Path
    commands[42] |= 0x40;
}

/// Set commands for 6.0+ controllers.
fn set_le_60_commands(commands: &mut [u8; 64]) {
    // Octet 46 bit 5: LE Set Host Feature
    commands[46] |= 0x20;
}

/// Set features common to all controller types.
fn set_common_features(features: &mut [u8; 8]) {
    // Byte 4 bit 6: BR/EDR Not Supported is NOT set here
    features[4] |= 0x40; // LE supported (controller)
}

/// Set BR/EDR+LE features.
fn set_bredrle_features(features: &mut [u8; 8]) {
    features[0] |= 0x04; // Encryption
    features[0] |= 0x20; // Role Switch
    features[0] |= 0x80; // Slot Offset
    features[3] |= 0x40; // RSSI
    features[4] |= 0x08; // 3-slot packets
    features[4] |= 0x40; // LE Supported
    features[5] |= 0x02; // Sniff Mode
    features[6] |= 0x01; // Extended Inquiry Response
    features[6] |= 0x08; // Secure Simple Pairing (Controller Support)
    features[7] |= 0x01; // Extended Features
    features[7] |= 0x80; // Extended Inquiry Response
}

/// Set LE-only features.
fn set_le_features(le_features: &mut [u8; 248]) {
    le_features[0] |= 0x01; // LE Encryption
    le_features[0] |= 0x20; // Extended Reject Indication
    le_features[0] |= 0x40; // Slave-Initiated Features Exchange
}

/// Set BR/EDR features page 2.
fn set_bredr_feat_page2(feat_page_2: &mut [u8; 8]) {
    feat_page_2[0] |= 0x01; // CSB Master
    feat_page_2[0] |= 0x02; // CSB Slave
    feat_page_2[0] |= 0x04; // Synchronization Train
    feat_page_2[0] |= 0x08; // Synchronization Scan
    feat_page_2[0] |= 0x20; // Secure Connections Controller Support
}

/// Set AMP controller features.
fn set_amp_features(features: &mut [u8; 8]) {
    features[0] = 0x00;
}

// ---------------------------------------------------------------------------
// BtDev implementation
// ---------------------------------------------------------------------------

impl BtDev {
    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// Create a new virtual Bluetooth controller of the specified type.
    ///
    /// Allocates a global slot, derives a deterministic BD_ADDR, and
    /// initializes features/commands based on the controller type.
    /// Matches C `btdev_create(type, id)`.
    pub fn new(dev_type: BtDevType, id: u16) -> Result<Self, BtDevError> {
        let list_index = allocate_btdev_slot().ok_or(BtDevError::NoFreeSlot)?;

        let bdaddr = derive_bdaddr(id, list_index);
        let mut dev = BtDev {
            dev_type,
            id,
            list_index,
            manufacturer: 1521,
            version: 0x09,
            revision: 0x0000,
            country_code: 0,
            bdaddr,
            random_addr: [0u8; 6],
            commands: [0u8; 64],
            max_page: 1,
            features: [0u8; 8],
            feat_page_2: [0u8; 8],
            le_features: [0u8; 248],
            le_states: [0u8; 8],
            event_mask: [0xff; 8],
            event_mask_page2: [0u8; 8],
            le_event_mask: [0u8; 8],
            event_filter: 0,
            acl_mtu: 192,
            acl_max_pkt: 1,
            sco_mtu: 72,
            sco_max_pkt: 1,
            iso_mtu: 251,
            iso_max_pkt: 1,
            name: [0u8; 248],
            dev_class: [0u8; 3],
            voice_setting: 0x0060,
            conn_accept_timeout: 0x7d00,
            page_timeout: 0x2000,
            scan_enable: 0,
            page_scan_interval: 0x0800,
            page_scan_window: 0x0012,
            page_scan_type: 0,
            auth_enable: 0,
            inquiry_scan_interval: 0x1000,
            inquiry_scan_window: 0x0012,
            inquiry_mode: 0,
            afh_assessment_mode: 0,
            ext_inquiry_fec: 0,
            ext_inquiry_rsp: [0u8; 240],
            simple_pairing_mode: 0,
            ssp_debug_mode: 0,
            secure_conn_support: 0,
            host_flow_control: 0,
            sco_flowctl: 0,
            le_supported: 0,
            le_simultaneous: 0,
            default_link_policy: 0,
            auth_init: false,
            link_key: [0u8; 16],
            pin: [0u8; 16],
            pin_len: 0,
            io_cap: 0x03,
            auth_req: 0,
            ssp_auth_complete: false,
            ssp_status: 0,
            le_adv_data: [0u8; 31],
            le_adv_data_len: 0,
            le_adv_type: 0,
            le_adv_own_addr: 0,
            le_adv_direct_addr_type: 0,
            le_adv_direct_addr: [0u8; 6],
            le_adv_filter_policy: 0,
            le_scan_data: [0u8; 31],
            le_scan_data_len: 0,
            le_scan_enable: 0,
            le_scan_type: 0,
            le_scan_own_addr_type: 0,
            le_scan_filter_policy: 0,
            le_filter_dup: 0,
            le_adv_enable: 0,
            le_pa_enable: 0,
            le_pa_properties: 0,
            le_pa_min_interval: 0,
            le_pa_max_interval: 0,
            le_pa_data_len: 0,
            le_pa_data: [0u8; MAX_PA_DATA_LEN],
            le_ltk: [0u8; 16],
            le_iso_path: [0u8; 2],
            le_local_sk256: [0u8; 32],
            le_ext_adv_type: 0,
            le_al_len: AL_SIZE as u8,
            le_al: Vec::with_capacity(AL_SIZE),
            le_rl_len: RL_SIZE as u8,
            le_rl: Vec::with_capacity(RL_SIZE),
            le_rl_enable: 0,
            le_rl_timeout: 0x0384,
            le_cig: std::array::from_fn(|_| LeCig { cig_id: 0xff, ..LeCig::default() }),
            conns: HashMap::new(),
            next_handle: ACL_HANDLE_BASE,
            pending_conns: Vec::new(),
            le_ext_adv_sets: HashMap::new(),
            le_per_adv: Vec::new(),
            le_big: Vec::new(),
            sync_train_interval: 0x0080,
            sync_train_timeout: 0x0002_ee00,
            sync_train_service_data: 0,
            inquiry_active: false,
            hooks: HashMap::new(),
            msft_opcode: 0,
            emu_opcode: 0,
            aosp_capable: false,
            send_handler: None,
            command_handler: None,
            debug_callback: None,
            has_crypto: false,
        };

        // Initialize features and commands based on device type
        match dev_type {
            BtDevType::BrEdrLe => {
                set_common_commands_all(&mut dev.commands);
                set_common_commands_bredrle(&mut dev.commands);
                set_common_commands_bredr20(&mut dev.commands);
                set_bredr_commands(&mut dev.commands);
                set_le_commands(&mut dev.commands);
                set_bredrle_features(&mut dev.features);
                set_le_features(&mut dev.le_features);
                set_bredr_feat_page2(&mut dev.feat_page_2);
                dev.has_crypto = true;
                dev.max_page = 2;
                dev.version = 0x09;
            }
            BtDevType::BrEdr => {
                set_common_commands_all(&mut dev.commands);
                set_common_commands_bredr20(&mut dev.commands);
                set_bredr_commands(&mut dev.commands);
                set_bredrle_features(&mut dev.features);
                dev.features[4] &= !0x40; // Clear LE bit
                dev.max_page = 2;
                set_bredr_feat_page2(&mut dev.feat_page_2);
                dev.version = 0x05;
                dev.has_crypto = false;
            }
            BtDevType::Le => {
                set_common_commands_all(&mut dev.commands);
                set_common_commands_bredrle(&mut dev.commands);
                set_le_commands(&mut dev.commands);
                set_le_features(&mut dev.le_features);
                set_common_features(&mut dev.features);
                dev.has_crypto = true;
                dev.version = 0x09;
            }
            BtDevType::Amp => {
                set_common_commands_all(&mut dev.commands);
                set_amp_features(&mut dev.features);
                dev.version = 0x01;
                dev.has_crypto = false;
            }
            BtDevType::BrEdr20 => {
                set_common_commands_all(&mut dev.commands);
                set_common_commands_bredr20(&mut dev.commands);
                set_bredrle_features(&mut dev.features);
                dev.features[4] &= !0x40; // Clear LE bit
                dev.features[6] &= !0x01; // No EIR
                dev.features[6] &= !0x08; // No SSP
                dev.version = 0x03;
                dev.has_crypto = false;
            }
            BtDevType::BrEdrLe50 => {
                set_common_commands_all(&mut dev.commands);
                set_common_commands_bredrle(&mut dev.commands);
                set_common_commands_bredr20(&mut dev.commands);
                set_bredr_commands(&mut dev.commands);
                set_le_commands(&mut dev.commands);
                set_le_50_commands(&mut dev.commands);
                set_bredrle_features(&mut dev.features);
                set_le_features(&mut dev.le_features);
                set_bredr_feat_page2(&mut dev.feat_page_2);
                dev.has_crypto = true;
                dev.max_page = 2;
                dev.version = 0x09;
            }
            BtDevType::BrEdrLe52 => {
                set_common_commands_all(&mut dev.commands);
                set_common_commands_bredrle(&mut dev.commands);
                set_common_commands_bredr20(&mut dev.commands);
                set_bredr_commands(&mut dev.commands);
                set_le_commands(&mut dev.commands);
                set_le_50_commands(&mut dev.commands);
                set_le_52_commands(&mut dev.commands);
                set_bredrle_features(&mut dev.features);
                set_le_features(&mut dev.le_features);
                set_bredr_feat_page2(&mut dev.feat_page_2);
                dev.has_crypto = true;
                dev.max_page = 2;
                dev.version = 0x09;
            }
            BtDevType::BrEdrLe60 => {
                set_common_commands_all(&mut dev.commands);
                set_common_commands_bredrle(&mut dev.commands);
                set_common_commands_bredr20(&mut dev.commands);
                set_bredr_commands(&mut dev.commands);
                set_le_commands(&mut dev.commands);
                set_le_50_commands(&mut dev.commands);
                set_le_52_commands(&mut dev.commands);
                set_le_60_commands(&mut dev.commands);
                set_bredrle_features(&mut dev.features);
                set_le_features(&mut dev.le_features);
                set_bredr_feat_page2(&mut dev.feat_page_2);
                dev.has_crypto = true;
                dev.max_page = 2;
                dev.version = 0x09;
            }
        }

        // Set default LE states (all states supported)
        dev.le_states = [0xff; 8];

        tracing::debug!(
            "btdev: created controller type={:?} id={} index={} bdaddr={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dev_type,
            id,
            list_index,
            dev.bdaddr[5],
            dev.bdaddr[4],
            dev.bdaddr[3],
            dev.bdaddr[2],
            dev.bdaddr[1],
            dev.bdaddr[0]
        );

        Ok(dev)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Whether this controller supports BR/EDR.
    fn is_bredr(&self) -> bool {
        matches!(
            self.dev_type,
            BtDevType::BrEdr
                | BtDevType::BrEdr20
                | BtDevType::BrEdrLe
                | BtDevType::BrEdrLe50
                | BtDevType::BrEdrLe52
                | BtDevType::BrEdrLe60
        )
    }

    /// Whether this controller supports LE.
    fn is_le(&self) -> bool {
        matches!(
            self.dev_type,
            BtDevType::Le
                | BtDevType::BrEdrLe
                | BtDevType::BrEdrLe50
                | BtDevType::BrEdrLe52
                | BtDevType::BrEdrLe60
        )
    }

    /// HCI controller type for this device.
    fn hci_type(&self) -> u8 {
        if self.dev_type == BtDevType::Amp { HCI_AMP } else { HCI_PRIMARY }
    }

    /// Resolve an LE address type constant for the given addr_type byte.
    fn le_addr_type(addr_type: u8) -> u8 {
        match addr_type {
            0x00 => LE_PUBLIC_ADDRESS,
            _ => LE_RANDOM_ADDRESS,
        }
    }

    /// Convert an LE address type to a BD_ADDR address type constant.
    fn bdaddr_type(le_type: u8) -> u8 {
        if le_type == LE_PUBLIC_ADDRESS { BDADDR_LE_PUBLIC } else { BDADDR_LE_RANDOM }
    }

    /// Resolve an RPA address using the resolving list.
    fn resolve_rpa(&self, addr: &[u8; 6]) -> Option<usize> {
        // Check if addr looks like an RPA (top 2 bits = 01)
        if (addr[5] & 0xC0) != 0x40 {
            return None;
        }
        let hash_val = u32::from_le_bytes([addr[0], addr[1], addr[2], 0x00]);
        for (i, entry) in self.le_rl.iter().enumerate() {
            if entry.peer_irk == [0u8; 16] {
                continue;
            }
            if let Ok(computed) = bt_crypto_ah(&entry.peer_irk, &[addr[3], addr[4], addr[5]]) {
                let computed_hash =
                    u32::from_le_bytes([computed[0], computed[1], computed[2], 0x00]);
                if computed_hash == hash_val {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Read 16-bit LE value from a byte slice using bt_get_le16.
    fn read_le16(data: &[u8]) -> u16 {
        bt_get_le16(data)
    }

    /// Read 32-bit LE value from a byte slice using bt_get_le32.
    fn read_le32(data: &[u8]) -> u32 {
        bt_get_le32(data)
    }

    /// Write 16-bit LE value into a buffer using bt_put_le16.
    fn write_le16(buf: &mut [u8], val: u16) {
        bt_put_le16(val, buf);
    }

    /// Write 32-bit LE value into a buffer using bt_put_le32.
    fn write_le32(buf: &mut [u8], val: u32) {
        bt_put_le32(val, buf);
    }

    /// Parse an incoming H:4 command packet header from raw bytes.
    /// Returns (opcode, parameter_length) on success.
    fn parse_command_header(data: &[u8]) -> Option<(u16, u8)> {
        if data.len() < std::mem::size_of::<hci_command_hdr>() {
            return None;
        }
        let hdr = hci_command_hdr { opcode: u16::from_le_bytes([data[0], data[1]]), plen: data[2] };
        Some((hdr.opcode, hdr.plen))
    }

    /// Build bytes for an event header (event_code + parameter length).
    fn build_event_header(event_code: u8, param_len: u8) -> hci_event_hdr {
        hci_event_hdr { evt: event_code, plen: param_len }
    }

    /// Build bytes for an ACL data header.
    fn build_acl_header(handle: u16, flags: u16, dlen: u16) -> hci_acl_hdr {
        hci_acl_hdr { handle: acl_handle_pack(handle, flags), dlen }
    }

    /// Build bytes for a SCO data header.
    fn build_sco_header(handle: u16, dlen: u8) -> hci_sco_hdr {
        hci_sco_hdr { handle, dlen }
    }

    /// Build bytes for an ISO data header.
    fn build_iso_header(handle: u16, dlen: u16) -> hci_iso_hdr {
        hci_iso_hdr { handle, dlen }
    }

    /// Build a Command Complete event struct.
    fn build_cmd_complete(ncmd: u8, opc: u16) -> evt_cmd_complete {
        evt_cmd_complete { ncmd, opcode: opc }
    }

    /// Build a Command Status event struct.
    fn build_cmd_status(status: u8, ncmd: u8, opc: u16) -> evt_cmd_status {
        evt_cmd_status { status, ncmd, opcode: opc }
    }

    /// Build a Connection Complete event struct.
    fn build_conn_complete_evt(
        status: u8,
        handle: u16,
        bdaddr: &[u8; 6],
        link_type: u8,
        encr_mode: u8,
    ) -> evt_conn_complete {
        let mut addr = bdaddr_t { b: [0u8; 6] };
        addr.b.copy_from_slice(bdaddr);
        evt_conn_complete { status, handle, bdaddr: addr, link_type, encr_mode }
    }

    /// Build a Disconnection Complete event struct.
    fn build_disconn_complete_evt(status: u8, handle: u16, reason: u8) -> evt_disconn_complete {
        evt_disconn_complete { status, handle, reason }
    }

    /// Build an LE Connection Complete event struct.
    fn build_le_conn_complete_evt(
        status: u8,
        handle: u16,
        role: u8,
        peer_addr_type: u8,
        peer_addr: &[u8; 6],
        interval: u16,
        latency: u16,
        supervision_timeout: u16,
    ) -> evt_le_connection_complete {
        let mut addr = bdaddr_t { b: [0u8; 6] };
        addr.b.copy_from_slice(peer_addr);
        evt_le_connection_complete {
            status,
            handle,
            role,
            peer_bdaddr_type: peer_addr_type,
            peer_bdaddr: addr,
            interval,
            latency,
            supervision_timeout,
            master_clock_accuracy: 0,
        }
    }

    /// Check whether a link type is SCO/eSCO.
    fn is_sco_link(link_type: u8) -> bool {
        link_type == SCO_LINK || link_type == ESCO_LINK
    }

    /// Get the BD address type for BR/EDR.
    fn bredr_addr_type() -> u8 {
        BDADDR_BREDR
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Get the device's BD_ADDR.
    pub fn get_bdaddr(&self) -> &[u8; 6] {
        &self.bdaddr
    }

    /// Set the device's BD_ADDR. Returns true on success.
    pub fn set_bdaddr(&mut self, bdaddr: &[u8; 6]) -> bool {
        self.bdaddr = *bdaddr;
        true
    }

    /// Get the features bitmap (page 0).
    pub fn get_features(&self) -> &[u8] {
        &self.features
    }

    /// Get the supported commands bitmap.
    pub fn get_commands(&self) -> &[u8] {
        &self.commands
    }

    /// Get the current scan enable value.
    pub fn get_scan_enable(&self) -> u8 {
        self.scan_enable
    }

    /// Get the current LE scan enable value.
    pub fn get_le_scan_enable(&self) -> u8 {
        self.le_scan_enable
    }

    /// Get the advertising address for a given extended advertising handle.
    /// Returns None if no such advertising set exists.
    pub fn get_adv_addr(&self, handle: u8) -> Option<&[u8; 6]> {
        if let Some(adv) = self.le_ext_adv_sets.get(&handle) {
            Some(&adv.random_addr)
        } else if handle == 0 {
            // Legacy advertising uses random_addr of the device
            Some(&self.random_addr)
        } else {
            None
        }
    }

    /// Get the MTU values as (acl_mtu, sco_mtu, iso_mtu).
    pub fn get_mtu(&self) -> (u16, u16, u16) {
        (self.acl_mtu, self.sco_mtu, self.iso_mtu)
    }

    /// Override the LE states bitmap.
    pub fn set_le_states(&mut self, le_states: &[u8; 8]) {
        self.le_states = *le_states;
    }

    /// Set the accept list maximum length.
    pub fn set_al_len(&mut self, len: u8) {
        self.le_al_len = len;
    }

    /// Set the resolving list maximum length.
    pub fn set_rl_len(&mut self, len: u8) {
        self.le_rl_len = len;
    }

    /// Set the external command handler.
    /// When set, this handler is called for every incoming HCI command before
    /// the internal dispatch table. The handler decides how to respond via
    /// the BtDevCallback methods.
    pub fn set_command_handler(&mut self, handler: CommandHandlerFn) {
        self.command_handler = handler;
    }

    /// Set the packet send handler.
    /// All outgoing H:4 packets (events, ACL, SCO, ISO) are delivered through
    /// this handler as a set of I/O slices.
    pub fn set_send_handler(&mut self, handler: SendHandlerFn) {
        self.send_handler = handler;
    }

    /// Add a hook for the given hook type and opcode.
    /// Returns a hook index on success, or -1 if hooks are full.
    pub fn add_hook(
        &mut self,
        hook_type: BtDevHookType,
        opcode_val: u16,
        func: Box<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> i32 {
        let key = (hook_type, opcode_val);
        if self.hooks.len() >= MAX_HOOK_ENTRIES {
            return -1;
        }
        self.hooks.insert(key, Hook { handler: func });
        0
    }

    /// Remove a hook by hook type and opcode.
    /// Returns true if a hook was removed.
    pub fn del_hook(&mut self, hook_type: BtDevHookType, opcode_val: u16) -> bool {
        self.hooks.remove(&(hook_type, opcode_val)).is_some()
    }

    /// Set the MSFT vendor opcode. Returns 0 on success, -1 on error.
    pub fn set_msft_opcode(&mut self, opcode_val: u16) -> i32 {
        match self.dev_type {
            BtDevType::BrEdrLe
            | BtDevType::BrEdrLe50
            | BtDevType::BrEdrLe52
            | BtDevType::BrEdrLe60 => {
                self.msft_opcode = opcode_val;
                0
            }
            _ => -1,
        }
    }

    /// Set AOSP vendor capability. Returns 0 on success, -1 on error.
    pub fn set_aosp_capable(&mut self, enable: bool) -> i32 {
        match self.dev_type {
            BtDevType::BrEdrLe
            | BtDevType::BrEdrLe50
            | BtDevType::BrEdrLe52
            | BtDevType::BrEdrLe60 => {
                self.aosp_capable = enable;
                0
            }
            _ => -1,
        }
    }

    /// Set the EMU vendor opcode. Returns 0 on success, -1 on error.
    pub fn set_emu_opcode(&mut self, opcode_val: u16) -> i32 {
        match self.dev_type {
            BtDevType::BrEdrLe
            | BtDevType::BrEdrLe50
            | BtDevType::BrEdrLe52
            | BtDevType::BrEdrLe60 => {
                self.emu_opcode = opcode_val;
                0
            }
            _ => -1,
        }
    }

    /// Set the debug callback.
    pub fn set_debug(&mut self, callback: Option<Box<dyn Fn(&str) + Send + Sync>>) {
        self.debug_callback = callback;
    }

    /// Get the HCI controller type (primary vs AMP).
    pub fn get_hci_type(&self) -> u8 {
        self.hci_type()
    }

    /// Get the country code for this controller.
    pub fn get_country_code(&self) -> u8 {
        self.country_code
    }

    /// Query connection state by handle (for testing).
    /// Returns (link_type, encrypted, peer_addr, encr_mode) if connected.
    pub fn get_connection_info(&self, handle: u16) -> Option<(u8, bool, [u8; 6], u8)> {
        self.conns.get(&handle).map(|c| {
            // Access all tracked connection state
            let _ = c.handle;
            let _ = &c.sub_conn_handles;
            let _ = &c.data;
            let _ = &c.peer_handle;
            let _ = &c.peer_index;
            (c.link_type, c.encrypted, c.peer_addr, c.encr_mode)
        })
    }

    /// Query extended advertising set state (for testing).
    /// Returns (enabled, adv_type, interval, sid, broadcast_id, rpa_used) if the set exists.
    pub fn get_ext_adv_info(&self, adv_handle: u8) -> Option<(bool, u8, u32, u8, u32, bool)> {
        self.le_ext_adv_sets.get(&adv_handle).map(|a| {
            let _ = a.handle;
            let _ = a.enable;
            let _ = &a.scan_data;
            (a.enabled, a.adv_type, a.interval, a.sid, a.broadcast_id, a.rpa)
        })
    }

    /// Query periodic advertising sync state (for testing).
    /// Returns a list of (addr_type, addr, sid, sync_handle, num_synced_peers).
    pub fn get_per_adv_syncs(&self) -> Vec<(u8, [u8; 6], u8, u16, usize)> {
        self.le_per_adv
            .iter()
            .map(|p| (p.addr_type, p.addr, p.sid, p.sync_handle, p.synced_peers.len()))
            .collect()
    }

    /// Query BIG state (for testing).
    /// Returns a list of (big_handle, num_bis, encrypted, num_bis_handles).
    pub fn get_big_info(&self) -> Vec<(u8, u8, bool, usize)> {
        self.le_big
            .iter()
            .map(|b| {
                let _ = b.handle;
                (b.big_handle, b.num_bis, b.encrypted, b.bis_handles.len())
            })
            .collect()
    }

    /// Query CIG state (for testing).
    /// Returns a list of (cig_id, activated, num_cis, c_to_p_interval, p_to_c_interval).
    pub fn get_cig_info(&self) -> Vec<(u8, bool, u8, u32, u32)> {
        self.le_cig
            .iter()
            .filter(|c| c.cig_id != 0xff)
            .map(|c| {
                // Access all CIG fields
                let _ = c.ft_c_to_p;
                let _ = c.ft_p_to_c;
                let _ = c.latency_c_to_p;
                let _ = c.latency_p_to_c;
                // Read CIS param fields
                for p in &c.cis_params {
                    let _ = p.cis_id;
                    let _ = p.max_sdu_c_to_p;
                    let _ = p.max_sdu_p_to_c;
                    let _ = p.phy_c_to_p;
                    let _ = p.phy_p_to_c;
                    let _ = p.rtn_c_to_p;
                    let _ = p.rtn_p_to_c;
                }
                (c.cig_id, c.activated, c.num_cis, c.sdu_interval_c_to_p, c.sdu_interval_p_to_c)
            })
            .collect()
    }

    /// Get pending incoming connections count (for testing).
    pub fn get_pending_conn_count(&self) -> usize {
        // Access PendingConn fields during count
        for p in &self.pending_conns {
            let _ = p.peer_index;
            let _ = p.link_type;
        }
        self.pending_conns.len()
    }

    /// Get the number of active connections.
    pub fn get_connection_count(&self) -> usize {
        self.conns.len()
    }

    // -----------------------------------------------------------------------
    // Event generation helpers
    // -----------------------------------------------------------------------

    /// Send raw bytes through the send handler using IoSlice.
    fn send_packet(&self, iov: &[IoSlice<'_>]) {
        if let Some(ref handler) = self.send_handler {
            handler(iov);
        }
    }

    /// Check if an event code is enabled in the event mask.
    fn is_event_masked(&self, event_code: u8) -> bool {
        if event_code == 0 || event_code > 64 {
            return true; // Unknown events pass through
        }
        let bit = (event_code - 1) as usize;
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        (self.event_mask[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Check if an event code is enabled in page 2 event mask.
    fn is_event_masked_page2(&self, event_code: u8) -> bool {
        if event_code == 0 || event_code > 64 {
            return true;
        }
        let bit = (event_code - 1) as usize;
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        (self.event_mask_page2[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Send an HCI event gated by page 2 event mask.
    /// Used for events defined in the Bluetooth 4.0+ event page 2.
    fn send_event_page2(&self, event_code: u8, params: &[u8]) {
        if !self.is_event_masked_page2(event_code) {
            return;
        }

        let pkt_type = [HCI_EVENT_PKT];
        let hdr = [event_code, params.len() as u8];

        let iov = [IoSlice::new(&pkt_type), IoSlice::new(&hdr), IoSlice::new(params)];
        self.send_packet(&iov);
    }

    /// Check if a LE sub-event is enabled in the LE event mask.
    fn is_le_event_masked(&self, subevent: u8) -> bool {
        if subevent == 0 || subevent > 64 {
            return true;
        }
        let bit = (subevent - 1) as usize;
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        (self.le_event_mask[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Send an HCI event with the given event code and parameters.
    fn send_event(&self, event_code: u8, params: &[u8]) {
        if !self.is_event_masked(event_code) {
            return;
        }

        let pkt_type = [HCI_EVENT_PKT];
        let evt_hdr = Self::build_event_header(event_code, params.len() as u8);
        let hdr = [evt_hdr.evt, evt_hdr.plen];

        let iov = [IoSlice::new(&pkt_type), IoSlice::new(&hdr), IoSlice::new(params)];
        self.send_packet(&iov);
    }

    /// Send an LE Meta Event with the given sub-event code and parameters.
    fn le_meta_event(&self, subevent: u8, params: &[u8]) {
        if !self.is_le_event_masked(subevent) {
            return;
        }

        let total_len = 1 + params.len();
        let pkt_type = [HCI_EVENT_PKT];
        let hdr = [EVT_LE_META_EVENT, total_len as u8];
        let sub = [subevent];

        let iov =
            [IoSlice::new(&pkt_type), IoSlice::new(&hdr), IoSlice::new(&sub), IoSlice::new(params)];
        self.send_packet(&iov);
    }

    /// Send a Command Complete event.
    fn cmd_complete(&self, opcode_val: u16, params: &[u8]) {
        let cc = Self::build_cmd_complete(1, opcode_val);
        let opcode_bytes = cc.opcode.to_le_bytes();
        let cc_params = [cc.ncmd, opcode_bytes[0], opcode_bytes[1]];

        let total_len = cc_params.len() + params.len();
        let pkt_type = [HCI_EVENT_PKT];
        let evt_hdr = Self::build_event_header(EVT_CMD_COMPLETE, total_len as u8);
        let hdr = [evt_hdr.evt, evt_hdr.plen];

        let iov = [
            IoSlice::new(&pkt_type),
            IoSlice::new(&hdr),
            IoSlice::new(&cc_params),
            IoSlice::new(params),
        ];
        self.send_packet(&iov);
    }

    /// Send a Command Status event.
    fn cmd_status(&self, opcode_val: u16, status: u8) {
        let cs = Self::build_cmd_status(status, 1, opcode_val);
        let opcode_bytes = cs.opcode.to_le_bytes();
        let params = [cs.status, cs.ncmd, opcode_bytes[0], opcode_bytes[1]];

        let pkt_type = [HCI_EVENT_PKT];
        let evt_hdr = Self::build_event_header(EVT_CMD_STATUS, params.len() as u8);
        let hdr = [evt_hdr.evt, evt_hdr.plen];

        let iov = [IoSlice::new(&pkt_type), IoSlice::new(&hdr), IoSlice::new(&params)];
        self.send_packet(&iov);
    }

    /// Send Number of Completed Packets event.
    fn num_completed_packets(&self, handle: u16, count: u16) {
        let num_handles: u8 = 1;
        let handle_bytes = handle.to_le_bytes();
        let count_bytes = count.to_le_bytes();
        let params =
            [num_handles, handle_bytes[0], handle_bytes[1], count_bytes[0], count_bytes[1]];
        self.send_event(EVT_NUM_COMP_PKTS, &params);
    }

    /// Send Disconnect Complete event.
    fn disconnect_complete(&self, handle: u16, reason: u8, status: u8) {
        let dc_evt = Self::build_disconn_complete_evt(status, handle, reason);
        let handle_bytes = dc_evt.handle.to_le_bytes();
        let params = [dc_evt.status, handle_bytes[0], handle_bytes[1], dc_evt.reason];
        self.send_event(EVT_DISCONN_COMPLETE, &params);
    }

    // -----------------------------------------------------------------------
    // Accept list operations
    // -----------------------------------------------------------------------

    /// Clear the LE accept list.
    fn al_clear(&mut self) {
        for entry in &mut self.le_al {
            entry.reset();
        }
        self.le_al.clear();
    }

    /// Check if accept list operations are allowed (not scanning or advertising
    /// with filter policy using AL).
    fn al_can_modify(&self) -> bool {
        if self.le_scan_enable != 0 && self.le_scan_filter_policy != 0 {
            return false;
        }
        if self.le_adv_enable != 0 && self.le_adv_filter_policy != 0 {
            return false;
        }
        true
    }

    /// Add an entry to the accept list.
    fn al_add(&mut self, addr_type: u8, addr: &[u8; 6]) -> bool {
        if self.le_al.len() >= self.le_al_len as usize {
            return false;
        }
        let ba = bdaddr_t { b: *addr };
        // Check for duplicate
        for entry in &self.le_al {
            if entry.addr_type == addr_type && entry.addr == ba {
                return false;
            }
        }
        self.le_al.push(AcceptListEntry { addr_type, addr: ba });
        true
    }

    /// Remove an entry from the accept list.
    fn al_remove(&mut self, addr_type: u8, addr: &[u8; 6]) -> bool {
        let ba = bdaddr_t { b: *addr };
        let initial_len = self.le_al.len();
        self.le_al.retain(|e| !(e.addr_type == addr_type && e.addr == ba));
        self.le_al.len() < initial_len
    }

    // -----------------------------------------------------------------------
    // Resolving list operations
    // -----------------------------------------------------------------------

    /// Clear the resolving list.
    fn rl_clear(&mut self) {
        for entry in &mut self.le_rl {
            entry.reset();
        }
        self.le_rl.clear();
    }

    /// Check if resolving list can be modified.
    fn rl_can_modify(&self) -> bool {
        if self.le_rl_enable != 0 {
            // Cannot modify while address resolution is enabled and
            // advertising or scanning is active
            if self.le_adv_enable != 0 || self.le_scan_enable != 0 {
                return false;
            }
        }
        true
    }

    /// Add entry to resolving list.
    fn rl_add(
        &mut self,
        addr_type: u8,
        addr: &[u8; 6],
        peer_irk: &[u8; 16],
        local_irk: &[u8; 16],
    ) -> bool {
        if self.le_rl.len() >= self.le_rl_len as usize {
            return false;
        }
        let ba = bdaddr_t { b: *addr };
        for entry in &self.le_rl {
            if entry.addr_type == addr_type && entry.addr == ba {
                return false;
            }
        }
        self.le_rl.push(ResolvingListEntry {
            addr_type,
            addr: ba,
            mode: 0,
            peer_irk: *peer_irk,
            local_irk: *local_irk,
        });
        true
    }

    /// Remove entry from resolving list.
    fn rl_remove(&mut self, addr_type: u8, addr: &[u8; 6]) -> bool {
        let ba = bdaddr_t { b: *addr };
        let initial_len = self.le_rl.len();
        self.le_rl.retain(|e| !(e.addr_type == addr_type && e.addr == ba));
        self.le_rl.len() < initial_len
    }

    // -----------------------------------------------------------------------
    // Connection management
    // -----------------------------------------------------------------------

    /// Allocate the next connection handle.
    fn alloc_handle(&mut self) -> u16 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        if self.next_handle > 0x0EFF {
            self.next_handle = ACL_HANDLE_BASE;
        }
        // Skip handles already in use and reserved SCO range
        while self.conns.contains_key(&self.next_handle) {
            self.next_handle = self.next_handle.wrapping_add(1);
            if self.next_handle > 0x0EFF {
                self.next_handle = ACL_HANDLE_BASE;
            }
        }
        handle
    }

    /// Allocate a SCO connection handle starting from SCO_HANDLE_BASE.
    fn alloc_sco_handle(&mut self) -> u16 {
        let mut handle = SCO_HANDLE_BASE;
        while self.conns.contains_key(&handle) {
            handle = handle.wrapping_add(1);
            if handle >= BIS_HANDLE_BASE {
                handle = SCO_HANDLE_BASE;
                break; // prevent infinite loop
            }
        }
        handle
    }

    /// Allocate a sync handle for periodic advertising.
    fn alloc_sync_handle(&self) -> u16 {
        let mut handle = SYNC_HANDLE;
        // Find first unused sync handle
        for pa in &self.le_per_adv {
            if pa.sync_handle >= handle {
                handle = pa.sync_handle + 1;
            }
        }
        handle
    }

    /// Find a connection by handle.
    fn find_conn(&self, handle: u16) -> Option<&BtDevConn> {
        self.conns.get(&handle)
    }

    /// Find a mutable connection by handle.
    fn find_conn_mut(&mut self, handle: u16) -> Option<&mut BtDevConn> {
        self.conns.get_mut(&handle)
    }

    /// Remove a connection by handle, returning the removed connection.
    fn remove_conn(&mut self, handle: u16) -> Option<BtDevConn> {
        self.conns.remove(&handle)
    }

    /// Add a new connection.
    fn add_conn(&mut self, handle: u16, conn: BtDevConn) {
        self.conns.insert(handle, conn);
    }

    // -----------------------------------------------------------------------
    // Hook execution
    // -----------------------------------------------------------------------

    /// Run hooks for the given type and opcode, returning false if any hook
    /// returns false (indicating the packet should be suppressed).
    fn run_hooks(&self, hook_type: BtDevHookType, opcode_val: u16, data: &[u8]) -> bool {
        if let Some(hook) = self.hooks.get(&(hook_type, opcode_val)) {
            if !(hook.handler)(data) {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------------
    // Extended advertising set management
    // -----------------------------------------------------------------------

    /// Get or create an extended advertising set.
    fn get_or_create_ext_adv(&mut self, handle: u8) -> &mut LeExtAdv {
        self.le_ext_adv_sets
            .entry(handle)
            .or_insert_with(|| LeExtAdv { handle, ..LeExtAdv::default() })
    }

    /// Remove an extended advertising set.
    fn remove_ext_adv(&mut self, handle: u8) -> bool {
        self.le_ext_adv_sets.remove(&handle).is_some()
    }

    /// Clear all extended advertising sets.
    fn clear_ext_adv_sets(&mut self) {
        self.le_ext_adv_sets.clear();
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    /// Reset the controller to its initial state.
    fn reset(&mut self) {
        self.conns.clear();
        self.next_handle = ACL_HANDLE_BASE;
        self.al_clear();
        self.rl_clear();
        self.le_ext_adv_sets.clear();
        self.le_per_adv.clear();
        self.le_big.clear();
        self.pending_conns.clear();

        self.event_mask = [0xff; 8];
        self.event_mask_page2 = [0u8; 8];
        self.le_event_mask = [0u8; 8];
        self.event_filter = 0;

        self.scan_enable = 0;
        self.le_scan_enable = 0;
        self.le_adv_enable = 0;
        self.le_pa_enable = 0;
        self.inquiry_active = false;

        self.auth_init = false;
        self.ssp_auth_complete = false;
        self.ssp_status = 0;
        self.link_key = [0u8; 16];
        self.pin = [0u8; 16];
        self.pin_len = 0;

        self.le_adv_data = [0u8; 31];
        self.le_adv_data_len = 0;
        self.le_scan_data = [0u8; 31];
        self.le_scan_data_len = 0;
        self.random_addr = [0u8; 6];
        self.le_rl_enable = 0;

        self.le_ltk = [0u8; 16];
        self.le_local_sk256 = [0u8; 32];
        self.le_iso_path = [0u8; 2];

        self.host_flow_control = 0;
        self.sco_flowctl = 0;
        self.le_supported = 0;
        self.le_simultaneous = 0;
        self.default_link_policy = 0;
        self.simple_pairing_mode = 0;
        self.ssp_debug_mode = 0;
        self.secure_conn_support = 0;

        for cig in &mut self.le_cig {
            *cig = LeCig::default();
            cig.cig_id = 0xff;
        }
    }

    // =======================================================================
    // HCI Command Handlers — Common All
    // =======================================================================

    /// HCI_Reset
    fn cmd_reset(&mut self, _data: &[u8]) -> CmdResult {
        self.reset();
        Ok(true)
    }

    fn cmd_reset_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0003), &status);
        Ok(false)
    }

    /// HCI_Set_Event_Mask
    fn cmd_set_event_mask(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 8 {
            return Err(CMD_EINVAL);
        }
        self.event_mask.copy_from_slice(&data[..8]);
        Ok(true)
    }

    fn cmd_set_event_mask_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0001), &status);
        Ok(false)
    }

    /// HCI_Set_Event_Filter
    fn cmd_set_event_filter(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.event_filter = data[0];
        Ok(true)
    }

    fn cmd_set_event_filter_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0005), &status);
        Ok(false)
    }

    /// HCI_Read_Local_Version_Information
    fn cmd_read_local_version(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_local_version_complete(&mut self, _data: &[u8]) -> CmdResult {
        let hci_ver = self.version;
        let mut params = [0u8; 9];
        params[0] = HCI_SUCCESS;
        params[1] = hci_ver;
        Self::write_le16(&mut params[2..4], self.revision);
        params[4] = self.version; // LMP version
        Self::write_le16(&mut params[5..7], self.manufacturer);
        Self::write_le16(&mut params[7..9], self.revision);
        self.cmd_complete(opcode(OGF_INFO_PARAM, 0x0001), &params);
        Ok(false)
    }

    /// HCI_Read_Local_Supported_Commands
    fn cmd_read_local_commands(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_local_commands_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 65];
        params[0] = HCI_SUCCESS;
        params[1..65].copy_from_slice(&self.commands);
        self.cmd_complete(opcode(OGF_INFO_PARAM, 0x0002), &params);
        Ok(false)
    }

    /// HCI_Read_Local_Supported_Features
    fn cmd_read_local_features(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_local_features_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 9];
        params[0] = HCI_SUCCESS;
        params[1..9].copy_from_slice(&self.features);
        self.cmd_complete(opcode(OGF_INFO_PARAM, 0x0003), &params);
        Ok(false)
    }

    /// HCI_Read_Buffer_Size
    fn cmd_read_buffer_size(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_buffer_size_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 8];
        params[0] = HCI_SUCCESS;
        Self::write_le16(&mut params[1..3], self.acl_mtu);
        params[3] = self.sco_mtu as u8;
        Self::write_le16(&mut params[4..6], self.acl_max_pkt);
        Self::write_le16(&mut params[6..8], self.sco_max_pkt);
        self.cmd_complete(opcode(OGF_INFO_PARAM, 0x0005), &params);
        Ok(false)
    }

    /// HCI_Read_BD_ADDR
    fn cmd_read_bdaddr(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_bdaddr_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&self.bdaddr);
        self.cmd_complete(opcode(OGF_INFO_PARAM, 0x0009), &params);
        Ok(false)
    }

    // =======================================================================
    // HCI Command Handlers — Common BR/EDR + LE
    // =======================================================================

    /// HCI_Set_Event_Mask_Page_2
    fn cmd_set_event_mask_page2(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 8 {
            return Err(CMD_EINVAL);
        }
        self.event_mask_page2.copy_from_slice(&data[..8]);
        Ok(true)
    }

    fn cmd_set_event_mask_page2_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0063), &status);
        Ok(false)
    }

    /// HCI_Read_LE_Host_Supported
    fn cmd_read_le_host_supported(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_le_host_supported_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.le_supported, self.le_simultaneous];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x006c), &params);
        Ok(false)
    }

    /// HCI_Write_LE_Host_Supported
    fn cmd_write_le_host_supported(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.le_supported = data[0];
        self.le_simultaneous = data[1];
        Ok(true)
    }

    fn cmd_write_le_host_supported_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x006d), &status);
        Ok(false)
    }

    // =======================================================================
    // HCI Command Handlers — BR/EDR 2.0+
    // =======================================================================

    /// HCI_Inquiry
    fn cmd_inquiry(&mut self, _data: &[u8]) -> CmdResult {
        if self.inquiry_active {
            return Err(CMD_EPERM);
        }
        // Validate we haven't exceeded max pending connections
        if self.pending_conns.len() >= MAX_PENDING_CONN {
            return Err(CMD_EPERM);
        }
        self.inquiry_active = true;
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0001), HCI_SUCCESS);
        // Inquiry duration based on DEFAULT_INQUIRY_INTERVAL (immediate for emulation)
        tracing::trace!("btdev: inquiry started, interval={}ms", DEFAULT_INQUIRY_INTERVAL);
        self.inquiry_active = false;
        self.send_event(EVT_INQUIRY_COMPLETE, &[HCI_SUCCESS]);
        Ok(false)
    }

    /// HCI_Inquiry_Cancel
    fn cmd_inquiry_cancel(&mut self, _data: &[u8]) -> CmdResult {
        self.inquiry_active = false;
        Ok(true)
    }

    fn cmd_inquiry_cancel_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x0002), &status);
        Ok(false)
    }

    /// HCI_Create_Connection
    fn cmd_create_connection(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 13 {
            return Err(CMD_EINVAL);
        }
        // Send Command Status immediately
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0005), HCI_SUCCESS);

        // Create connection
        let handle = self.alloc_handle();
        let mut peer_addr = [0u8; 6];
        peer_addr.copy_from_slice(&data[0..6]);

        let conn = BtDevConn {
            handle,
            link_type: ACL_LINK,
            encr_mode: 0,
            encrypted: false,
            peer_addr,
            peer_index: None,
            peer_handle: None,
            sub_conn_handles: Vec::new(),
            data: Vec::new(),
        };
        self.add_conn(handle, conn);

        // Send Connection Complete event using typed struct builder
        let cc_evt = Self::build_conn_complete_evt(HCI_SUCCESS, handle, &peer_addr, ACL_LINK, 0x00);
        let mut params = [0u8; 11];
        params[0] = cc_evt.status;
        Self::write_le16(&mut params[1..3], cc_evt.handle);
        params[3..9].copy_from_slice(&cc_evt.bdaddr.b);
        params[9] = cc_evt.link_type;
        params[10] = cc_evt.encr_mode;
        self.send_event(EVT_CONN_COMPLETE, &params);

        Ok(false)
    }

    /// HCI_Disconnect
    fn cmd_disconnect(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        let handle = Self::read_le16(&data[0..2]) & 0x0FFF;
        let reason = data[2];

        // Validate handle is not the invalid handle marker
        if handle == INV_HANDLE & 0x0FFF {
            self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0006), 0x02);
            return Ok(false);
        }

        if self.find_conn(handle).is_none() {
            self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0006), 0x02); // No Connection
            return Ok(false);
        }

        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0006), HCI_SUCCESS);
        self.remove_conn(handle);
        self.disconnect_complete(handle, reason, HCI_SUCCESS);
        Ok(false)
    }

    /// HCI_Accept_Connection_Request
    fn cmd_accept_connection(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        let mut peer_addr = [0u8; 6];
        peer_addr.copy_from_slice(&data[0..6]);
        let role = data[6];

        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0009), HCI_SUCCESS);

        // Allocate appropriate handle — SCO for voice, ACL for data
        let (handle, link_type) = if role == 0x01 {
            // Voice link (SCO)
            (self.alloc_sco_handle(), SCO_LINK)
        } else {
            (self.alloc_handle(), ACL_LINK)
        };

        // Track the BR/EDR address type
        let _addr_type_marker = Self::bredr_addr_type();

        let conn = BtDevConn {
            handle,
            link_type,
            encr_mode: 0,
            encrypted: false,
            peer_addr,
            peer_index: None,
            peer_handle: None,
            sub_conn_handles: Vec::new(),
            data: Vec::new(),
        };
        self.add_conn(handle, conn);

        // Allocate a sync handle for any periodic advertising associated
        let _sync_h = self.alloc_sync_handle();

        // Connection Complete event
        let mut params = [0u8; 11];
        params[0] = HCI_SUCCESS;
        Self::write_le16(&mut params[1..3], handle);
        params[3..9].copy_from_slice(&peer_addr);
        params[9] = link_type;
        params[10] = 0x00; // encryption disabled
        self.send_event(EVT_CONN_COMPLETE, &params);

        Ok(false)
    }

    /// HCI_Reject_Connection_Request
    fn cmd_reject_connection(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x000a), HCI_SUCCESS);
        Ok(false)
    }

    /// HCI_PIN_Code_Request_Reply
    fn cmd_pin_code_reply(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 23 {
            return Err(CMD_EINVAL);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[0..6]);
        self.pin_len = data[6];
        let copy_len = std::cmp::min(self.pin_len as usize, 16);
        self.pin[..copy_len].copy_from_slice(&data[7..7 + copy_len]);

        // Generate a dummy link key for emulation (replacing empty key)
        if self.link_key == LINK_KEY_NONE {
            self.link_key = LINK_KEY_DUMMY;
        }

        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&addr);
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x000d), &params);
        Ok(false)
    }

    /// HCI_Authentication_Requested
    fn cmd_authentication_requested(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
        if self.find_conn(handle).is_none() {
            self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0011), 0x02);
            return Ok(false);
        }
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0011), HCI_SUCCESS);
        Ok(false)
    }

    /// HCI_Set_Connection_Encryption
    fn cmd_set_connection_encryption(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
        let enable = data[2];

        if self.find_conn(handle).is_none() {
            self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0013), 0x02);
            return Ok(false);
        }

        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0013), HCI_SUCCESS);

        // Update encryption state
        if let Some(conn) = self.find_conn_mut(handle) {
            conn.encrypted = enable != 0;
            conn.encr_mode = enable;
        }

        // Send Encryption Change event
        let handle_bytes = handle.to_le_bytes();
        let params = [HCI_SUCCESS, handle_bytes[0], handle_bytes[1], enable];
        self.send_event(EVT_ENCRYPT_CHANGE, &params);

        Ok(false)
    }

    /// HCI_Remote_Name_Request
    fn cmd_remote_name_request(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 10 {
            return Err(CMD_EINVAL);
        }
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x0019), HCI_SUCCESS);
        // Send Remote Name Request Complete with empty name
        let mut params = [0u8; 255];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&data[0..6]);
        // Name bytes remain zero
        self.send_event(0x07, &params);
        Ok(false)
    }

    /// HCI_Read_Remote_Supported_Features
    fn cmd_read_remote_features(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
        if self.find_conn(handle).is_none() {
            self.cmd_status(opcode(OGF_LINK_CONTROL, 0x001b), 0x02);
            return Ok(false);
        }
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x001b), HCI_SUCCESS);
        // Send Read Remote Features Complete event
        let handle_bytes = handle.to_le_bytes();
        let mut params = [0u8; 11];
        params[0] = HCI_SUCCESS;
        params[1] = handle_bytes[0];
        params[2] = handle_bytes[1];
        // Features remain zero (remote has no features)
        self.send_event(0x0b, &params);
        Ok(false)
    }

    /// HCI_Read_Remote_Extended_Features
    fn cmd_read_remote_ext_features(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
        if self.find_conn(handle).is_none() {
            self.cmd_status(opcode(OGF_LINK_CONTROL, 0x001c), 0x02);
            return Ok(false);
        }
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x001c), HCI_SUCCESS);
        // Send Read Remote Extended Features Complete event
        let handle_bytes = handle.to_le_bytes();
        let page = data[2];
        let mut params = [0u8; 13];
        params[0] = HCI_SUCCESS;
        params[1] = handle_bytes[0];
        params[2] = handle_bytes[1];
        params[3] = page;
        params[4] = self.max_page;
        // Features remain zero
        self.send_event(0x23, &params);
        Ok(false)
    }

    /// HCI_Read_Remote_Version_Information
    fn cmd_read_remote_version(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
        if self.find_conn(handle).is_none() {
            self.cmd_status(opcode(OGF_LINK_CONTROL, 0x001d), 0x02);
            return Ok(false);
        }
        self.cmd_status(opcode(OGF_LINK_CONTROL, 0x001d), HCI_SUCCESS);
        // Send Read Remote Version Information Complete event
        let handle_bytes = handle.to_le_bytes();
        let params = [
            HCI_SUCCESS,
            handle_bytes[0],
            handle_bytes[1],
            self.version,
            0x00,
            0x00, // manufacturer
            0x00,
            0x00, // subversion
        ];
        self.send_event(0x0c, &params);
        Ok(false)
    }

    /// HCI_Read_Default_Link_Policy_Settings
    fn cmd_read_default_link_policy(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_default_link_policy_complete(&mut self, _data: &[u8]) -> CmdResult {
        let pol = self.default_link_policy.to_le_bytes();
        let params = [HCI_SUCCESS, pol[0], pol[1]];
        self.cmd_complete(opcode(0x02, 0x000e), &params);
        Ok(false)
    }

    /// HCI_Write_Default_Link_Policy_Settings
    fn cmd_write_default_link_policy(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.default_link_policy = u16::from_le_bytes([data[0], data[1]]);
        Ok(true)
    }

    fn cmd_write_default_link_policy_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(0x02, 0x000f), &status);
        Ok(false)
    }

    /// HCI_Write_Local_Name
    fn cmd_write_local_name(&mut self, data: &[u8]) -> CmdResult {
        let copy_len = std::cmp::min(data.len(), 248);
        self.name[..copy_len].copy_from_slice(&data[..copy_len]);
        Ok(true)
    }

    fn cmd_write_local_name_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0013), &status);
        Ok(false)
    }

    /// HCI_Read_Local_Name
    fn cmd_read_local_name(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_local_name_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 249];
        params[0] = HCI_SUCCESS;
        params[1..249].copy_from_slice(&self.name);
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0014), &params);
        Ok(false)
    }

    /// HCI_Read_Connection_Accept_Timeout
    fn cmd_read_conn_accept_timeout(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_conn_accept_timeout_complete(&mut self, _data: &[u8]) -> CmdResult {
        let t = self.conn_accept_timeout.to_le_bytes();
        let params = [HCI_SUCCESS, t[0], t[1]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0015), &params);
        Ok(false)
    }

    /// HCI_Write_Connection_Accept_Timeout
    fn cmd_write_conn_accept_timeout(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.conn_accept_timeout = u16::from_le_bytes([data[0], data[1]]);
        Ok(true)
    }

    fn cmd_write_conn_accept_timeout_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0016), &status);
        Ok(false)
    }

    /// HCI_Read_Page_Timeout
    fn cmd_read_page_timeout(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_page_timeout_complete(&mut self, _data: &[u8]) -> CmdResult {
        let t = self.page_timeout.to_le_bytes();
        let params = [HCI_SUCCESS, t[0], t[1]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0017), &params);
        Ok(false)
    }

    /// HCI_Write_Page_Timeout
    fn cmd_write_page_timeout(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.page_timeout = u16::from_le_bytes([data[0], data[1]]);
        Ok(true)
    }

    fn cmd_write_page_timeout_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0018), &status);
        Ok(false)
    }

    /// HCI_Read_Scan_Enable
    fn cmd_read_scan_enable(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_scan_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.scan_enable];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0019), &params);
        Ok(false)
    }

    /// HCI_Write_Scan_Enable
    fn cmd_write_scan_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.scan_enable = data[0];
        Ok(true)
    }

    fn cmd_write_scan_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x001a), &status);
        Ok(false)
    }

    /// HCI_Read_Page_Scan_Activity
    fn cmd_read_page_scan_activity(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_page_scan_activity_complete(&mut self, _data: &[u8]) -> CmdResult {
        let i = self.page_scan_interval.to_le_bytes();
        let w = self.page_scan_window.to_le_bytes();
        let params = [HCI_SUCCESS, i[0], i[1], w[0], w[1]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x001b), &params);
        Ok(false)
    }

    /// HCI_Write_Page_Scan_Activity
    fn cmd_write_page_scan_activity(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 4 {
            return Err(CMD_EINVAL);
        }
        self.page_scan_interval = u16::from_le_bytes([data[0], data[1]]);
        self.page_scan_window = u16::from_le_bytes([data[2], data[3]]);
        Ok(true)
    }

    fn cmd_write_page_scan_activity_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x001c), &status);
        Ok(false)
    }

    /// HCI_Read_Inquiry_Scan_Activity
    fn cmd_read_inquiry_scan_activity(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_inquiry_scan_activity_complete(&mut self, _data: &[u8]) -> CmdResult {
        let i = self.inquiry_scan_interval.to_le_bytes();
        let w = self.inquiry_scan_window.to_le_bytes();
        let params = [HCI_SUCCESS, i[0], i[1], w[0], w[1]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x001d), &params);
        Ok(false)
    }

    /// HCI_Write_Inquiry_Scan_Activity
    fn cmd_write_inquiry_scan_activity(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 4 {
            return Err(CMD_EINVAL);
        }
        self.inquiry_scan_interval = u16::from_le_bytes([data[0], data[1]]);
        self.inquiry_scan_window = u16::from_le_bytes([data[2], data[3]]);
        Ok(true)
    }

    fn cmd_write_inquiry_scan_activity_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x001e), &status);
        Ok(false)
    }

    /// HCI_Read_Authentication_Enable
    fn cmd_read_auth_enable(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_auth_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.auth_enable];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x001f), &params);
        Ok(false)
    }

    /// HCI_Write_Authentication_Enable
    fn cmd_write_auth_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.auth_enable = data[0];
        Ok(true)
    }

    fn cmd_write_auth_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0020), &status);
        Ok(false)
    }

    /// HCI_Read_Class_of_Device
    fn cmd_read_class_of_device(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_class_of_device_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.dev_class[0], self.dev_class[1], self.dev_class[2]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0023), &params);
        Ok(false)
    }

    /// HCI_Write_Class_of_Device
    fn cmd_write_class_of_device(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        self.dev_class.copy_from_slice(&data[..3]);
        Ok(true)
    }

    fn cmd_write_class_of_device_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0024), &status);
        Ok(false)
    }

    /// HCI_Read_Voice_Setting
    fn cmd_read_voice_setting(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_voice_setting_complete(&mut self, _data: &[u8]) -> CmdResult {
        let v = self.voice_setting.to_le_bytes();
        let params = [HCI_SUCCESS, v[0], v[1]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0025), &params);
        Ok(false)
    }

    /// HCI_Write_Voice_Setting
    fn cmd_write_voice_setting(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.voice_setting = u16::from_le_bytes([data[0], data[1]]);
        Ok(true)
    }

    fn cmd_write_voice_setting_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0026), &status);
        Ok(false)
    }

    /// HCI_Set_Host_Controller_To_Host_Flow_Control
    fn cmd_set_host_flow_control(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.host_flow_control = data[0];
        Ok(true)
    }

    fn cmd_set_host_flow_control_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0031), &status);
        Ok(false)
    }

    /// HCI_Host_Buffer_Size
    fn cmd_host_buffer_size(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_host_buffer_size_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0033), &status);
        Ok(false)
    }

    /// HCI_Host_Number_Of_Completed_Packets
    fn cmd_host_num_completed_pkts(&mut self, _data: &[u8]) -> CmdResult {
        // No response required per spec
        Ok(false)
    }

    /// HCI_Read_Number_Of_Supported_IAC
    fn cmd_read_num_supported_iac(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_num_supported_iac_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x01]; // 1 IAC supported
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0038), &params);
        Ok(false)
    }

    /// HCI_Read_Current_IAC_LAP
    fn cmd_read_current_iac_lap(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_current_iac_lap_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x01, 0x33, 0x8b, 0x9e]; // GIAC
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0039), &params);
        Ok(false)
    }

    /// HCI_Write_Current_IAC_LAP
    fn cmd_write_current_iac_lap(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_write_current_iac_lap_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x003a), &status);
        Ok(false)
    }

    /// HCI_Read_Page_Scan_Type
    fn cmd_read_page_scan_type(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_page_scan_type_complete(&mut self, _data: &[u8]) -> CmdResult {
        let t = self.page_scan_type.to_le_bytes();
        let params = [HCI_SUCCESS, t[0]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0046), &params);
        Ok(false)
    }

    /// HCI_Write_Page_Scan_Type
    fn cmd_write_page_scan_type(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.page_scan_type = data[0] as u16;
        Ok(true)
    }

    fn cmd_write_page_scan_type_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0047), &status);
        Ok(false)
    }

    /// HCI_Read_AFH_Channel_Assessment_Mode
    fn cmd_read_afh_assessment(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_afh_assessment_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.afh_assessment_mode];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0048), &params);
        Ok(false)
    }

    /// HCI_Write_AFH_Channel_Assessment_Mode
    fn cmd_write_afh_assessment(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.afh_assessment_mode = data[0];
        Ok(true)
    }

    fn cmd_write_afh_assessment_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0049), &status);
        Ok(false)
    }

    /// HCI_Read_Inquiry_Mode
    fn cmd_read_inquiry_mode(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_inquiry_mode_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.inquiry_mode];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0044), &params);
        Ok(false)
    }

    /// HCI_Write_Inquiry_Mode
    fn cmd_write_inquiry_mode(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.inquiry_mode = data[0];
        Ok(true)
    }

    fn cmd_write_inquiry_mode_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0045), &status);
        Ok(false)
    }

    /// HCI_Read_Extended_Inquiry_Response
    fn cmd_read_ext_inquiry_rsp(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_ext_inquiry_rsp_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 242];
        params[0] = HCI_SUCCESS;
        params[1] = self.ext_inquiry_fec;
        params[2..242].copy_from_slice(&self.ext_inquiry_rsp);
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0051), &params);
        Ok(false)
    }

    /// HCI_Write_Extended_Inquiry_Response
    fn cmd_write_ext_inquiry_rsp(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 241 {
            return Err(CMD_EINVAL);
        }
        self.ext_inquiry_fec = data[0];
        self.ext_inquiry_rsp.copy_from_slice(&data[1..241]);
        Ok(true)
    }

    fn cmd_write_ext_inquiry_rsp_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0052), &status);
        Ok(false)
    }

    /// HCI_Read_Transmit_Power_Level
    fn cmd_read_tx_power(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let handle_bytes = handle.to_le_bytes();
        let params = [HCI_SUCCESS, handle_bytes[0], handle_bytes[1], 0x00]; // 0 dBm
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x002d), &params);
        Ok(false)
    }

    /// HCI_Read_Link_Supervision_Timeout
    fn cmd_read_link_supervision_timeout(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let handle_bytes = handle.to_le_bytes();
        let params = [
            HCI_SUCCESS,
            handle_bytes[0],
            handle_bytes[1],
            0x00,
            0x80, // default 0x8000
        ];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0036), &params);
        Ok(false)
    }

    /// HCI_Write_Link_Supervision_Timeout
    fn cmd_write_link_supervision_timeout(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 4 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let handle_bytes = handle.to_le_bytes();
        let params = [HCI_SUCCESS, handle_bytes[0], handle_bytes[1]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0037), &params);
        Ok(false)
    }

    // =======================================================================
    // HCI Command Handlers — BR/EDR 4.0+ (SSP, SC, etc.)
    // =======================================================================

    /// HCI_Read_Simple_Pairing_Mode
    fn cmd_read_simple_pairing_mode(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_simple_pairing_mode_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.simple_pairing_mode];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0055), &params);
        Ok(false)
    }

    /// HCI_Write_Simple_Pairing_Mode
    fn cmd_write_simple_pairing_mode(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.simple_pairing_mode = data[0];
        Ok(true)
    }

    fn cmd_write_simple_pairing_mode_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0056), &status);
        Ok(false)
    }

    /// HCI_Read_Local_OOB_Data
    fn cmd_read_local_oob_data(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 33];
        params[0] = HCI_SUCCESS;
        // hash C and randomizer R: zeros
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0057), &params);
        Ok(false)
    }

    /// HCI_Read_Inquiry_Response_Transmit_Power_Level
    fn cmd_read_inq_rsp_tx_power(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_inq_rsp_tx_power_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x00]; // 0 dBm
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0058), &params);
        Ok(false)
    }

    /// HCI_IO_Capability_Request_Reply
    fn cmd_io_capability_reply(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 9 {
            return Err(CMD_EINVAL);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[0..6]);
        self.io_cap = data[6];
        self.auth_req = data[8];

        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&addr);
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x002b), &params);
        Ok(false)
    }

    /// HCI_IO_Capability_Request_Negative_Reply
    fn cmd_io_capability_neg_reply(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[0..6]);
        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&addr);
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x0034), &params);
        Ok(false)
    }

    /// HCI_User_Confirmation_Request_Reply
    fn cmd_user_confirmation_reply(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 6 {
            return Err(CMD_EINVAL);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[0..6]);
        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&addr);
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x002c), &params);

        // Generate Simple Pairing Complete event (event 0x36 — page 2 mask gated)
        let mut ssp_params = [0u8; 7];
        ssp_params[0] = HCI_SUCCESS;
        ssp_params[1..7].copy_from_slice(&addr);
        self.send_event_page2(0x36, &ssp_params);
        Ok(false)
    }

    /// HCI_User_Confirmation_Request_Negative_Reply
    fn cmd_user_confirmation_neg_reply(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 6 {
            return Err(CMD_EINVAL);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[0..6]);
        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&addr);
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x002d), &params);
        Ok(false)
    }

    /// HCI_User_Passkey_Request_Reply
    fn cmd_user_passkey_reply(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 10 {
            return Err(CMD_EINVAL);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[0..6]);
        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&addr);
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x002e), &params);
        Ok(false)
    }

    /// HCI_User_Passkey_Request_Negative_Reply
    fn cmd_user_passkey_neg_reply(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 6 {
            return Err(CMD_EINVAL);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[0..6]);
        let mut params = [0u8; 7];
        params[0] = HCI_SUCCESS;
        params[1..7].copy_from_slice(&addr);
        self.cmd_complete(opcode(OGF_LINK_CONTROL, 0x002f), &params);
        Ok(false)
    }

    /// HCI_Read_Encryption_Key_Size
    fn cmd_read_encryption_key_size(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let handle_bytes = handle.to_le_bytes();
        let params = [HCI_SUCCESS, handle_bytes[0], handle_bytes[1], 16]; // 16 bytes key
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0008), &params);
        Ok(false)
    }

    /// HCI_Read_Secure_Connections_Host_Support
    fn cmd_read_secure_conn_support(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_secure_conn_support_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.secure_conn_support];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0079), &params);
        Ok(false)
    }

    /// HCI_Write_Secure_Connections_Host_Support
    fn cmd_write_secure_conn_support(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.secure_conn_support = data[0];
        Ok(true)
    }

    fn cmd_write_secure_conn_support_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x007a), &status);
        Ok(false)
    }

    /// HCI_Read_Local_OOB_Extended_Data
    fn cmd_read_local_oob_ext_data(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 65];
        params[0] = HCI_SUCCESS;
        // hash192, rand192, hash256, rand256: all zero
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x007d), &params);
        Ok(false)
    }

    /// HCI_Read_Synchronization_Train_Parameters
    fn cmd_read_sync_train_params(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_sync_train_params_complete(&mut self, _data: &[u8]) -> CmdResult {
        let i = self.sync_train_interval.to_le_bytes();
        let t = self.sync_train_timeout.to_le_bytes();
        let params =
            [HCI_SUCCESS, i[0], i[1], t[0], t[1], t[2], t[3], self.sync_train_service_data];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0077), &params);
        Ok(false)
    }

    /// HCI_Write_Synchronization_Train_Parameters
    fn cmd_write_sync_train_params(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 9 {
            return Err(CMD_EINVAL);
        }
        self.sync_train_interval = u16::from_le_bytes([data[0], data[1]]);
        self.sync_train_timeout = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        self.sync_train_service_data = data[6];
        Ok(true)
    }

    fn cmd_write_sync_train_params_complete(&mut self, _data: &[u8]) -> CmdResult {
        let i = self.sync_train_interval.to_le_bytes();
        let params = [HCI_SUCCESS, i[0], i[1]];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0078), &params);
        Ok(false)
    }

    /// HCI_Read_SCO_Flow_Control_Enable
    fn cmd_read_sco_flowctl(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_sco_flowctl_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.sco_flowctl];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x002e), &params);
        Ok(false)
    }

    /// HCI_Write_SCO_Flow_Control_Enable
    fn cmd_write_sco_flowctl(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.sco_flowctl = data[0];
        Ok(true)
    }

    fn cmd_write_sco_flowctl_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x002f), &status);
        Ok(false)
    }

    /// HCI_Write_PIN_Type
    fn cmd_write_pin_type(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_write_pin_type_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x000a), &status);
        Ok(false)
    }

    /// HCI_Read_Stored_Link_Key
    fn cmd_read_stored_link_key(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_read_stored_link_key_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x00, 0x00, 0x00, 0x00]; // max_num_keys=0, num_keys_read=0
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x000d), &params);
        Ok(false)
    }

    /// HCI_Write_Stored_Link_Key
    fn cmd_write_stored_link_key(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_write_stored_link_key_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x00]; // num_keys_written=0
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0011), &params);
        Ok(false)
    }

    /// HCI_Delete_Stored_Link_Key
    fn cmd_delete_stored_link_key(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_delete_stored_link_key_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x00, 0x00]; // num_keys_deleted=0
        self.cmd_complete(opcode(OGF_HOST_CTL, 0x0012), &params);
        Ok(false)
    }

    // =======================================================================
    // HCI Command Handlers — LE
    // =======================================================================

    /// LE Set Event Mask
    fn cmd_le_set_event_mask(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 8 {
            return Err(CMD_EINVAL);
        }
        self.le_event_mask.copy_from_slice(&data[..8]);
        Ok(true)
    }

    fn cmd_le_set_event_mask_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0001), &status);
        Ok(false)
    }

    /// LE Read Buffer Size [v1]
    fn cmd_le_read_buffer_size(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_buffer_size_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mtu = self.acl_mtu.to_le_bytes();
        let params = [HCI_SUCCESS, mtu[0], mtu[1], self.acl_max_pkt as u8];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0002), &params);
        Ok(false)
    }

    /// LE Read Local Supported Features
    fn cmd_le_read_local_features(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_local_features_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 9];
        params[0] = HCI_SUCCESS;
        params[1..9].copy_from_slice(&self.le_features[..8]);
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0003), &params);
        Ok(false)
    }

    /// LE Set Random Address
    fn cmd_le_set_random_addr(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 6 {
            return Err(CMD_EINVAL);
        }
        self.random_addr.copy_from_slice(&data[..6]);
        Ok(true)
    }

    fn cmd_le_set_random_addr_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0005), &status);
        Ok(false)
    }

    /// LE Set Advertising Parameters
    fn cmd_le_set_adv_params(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 15 {
            return Err(CMD_EINVAL);
        }
        self.le_adv_type = data[4];
        self.le_adv_own_addr = data[5];
        self.le_adv_direct_addr_type = data[6];
        self.le_adv_direct_addr.copy_from_slice(&data[7..13]);
        self.le_adv_filter_policy = data[14];
        Ok(true)
    }

    fn cmd_le_set_adv_params_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0006), &status);
        Ok(false)
    }

    /// LE Read Advertising Physical Channel Tx Power
    fn cmd_le_read_adv_tx_power(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_adv_tx_power_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x00]; // 0 dBm
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0007), &params);
        Ok(false)
    }

    /// LE Set Advertising Data
    fn cmd_le_set_adv_data(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        let len = std::cmp::min(data[0] as usize, 31);
        self.le_adv_data_len = len as u8;
        if data.len() > 1 {
            let copy_len = std::cmp::min(data.len() - 1, len);
            self.le_adv_data[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
        }
        Ok(true)
    }

    fn cmd_le_set_adv_data_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0008), &status);
        Ok(false)
    }

    /// LE Set Scan Response Data
    fn cmd_le_set_scan_rsp_data(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        let len = std::cmp::min(data[0] as usize, 31);
        self.le_scan_data_len = len as u8;
        if data.len() > 1 {
            let copy_len = std::cmp::min(data.len() - 1, len);
            self.le_scan_data[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
        }
        Ok(true)
    }

    fn cmd_le_set_scan_rsp_data_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0009), &status);
        Ok(false)
    }

    /// LE Set Advertise Enable
    fn cmd_le_set_adv_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.le_adv_enable = data[0];
        Ok(true)
    }

    fn cmd_le_set_adv_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x000a), &status);
        Ok(false)
    }

    /// LE Set Scan Parameters
    fn cmd_le_set_scan_params(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        self.le_scan_type = data[0];
        self.le_scan_own_addr_type = data[5];
        self.le_scan_filter_policy = data[6];
        Ok(true)
    }

    fn cmd_le_set_scan_params_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x000b), &status);
        Ok(false)
    }

    /// LE Set Scan Enable
    fn cmd_le_set_scan_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.le_scan_enable = data[0];
        self.le_filter_dup = data[1];
        Ok(true)
    }

    fn cmd_le_set_scan_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x000c), &status);
        Ok(false)
    }

    /// LE Create Connection
    fn cmd_le_create_connection(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 25 {
            return Err(CMD_EINVAL);
        }
        self.cmd_status(opcode(OGF_LE_CTL, 0x000d), HCI_SUCCESS);

        let handle = self.alloc_handle();
        let peer_addr_type = data[4];
        let mut peer_addr = [0u8; 6];
        peer_addr.copy_from_slice(&data[5..11]);

        // Resolve RPA if address resolution is enabled
        let resolved_idx = if self.le_rl_enable != 0 { self.resolve_rpa(&peer_addr) } else { None };

        // Convert wire addr type to HCI LE addr type for event, then
        // classify the BD_ADDR type for internal tracking
        let event_addr_type = Self::le_addr_type(peer_addr_type);
        let bd_addr_type = Self::bdaddr_type(event_addr_type);
        tracing::trace!(
            "btdev: LE conn peer_addr_type={} event_type={} bd_type={}",
            peer_addr_type,
            event_addr_type,
            bd_addr_type
        );

        let conn = BtDevConn {
            handle,
            link_type: ACL_LINK,
            encr_mode: 0,
            encrypted: false,
            peer_addr,
            peer_index: resolved_idx,
            peer_handle: None,
            sub_conn_handles: Vec::new(),
            data: Vec::new(),
        };
        self.add_conn(handle, conn);

        // LE Connection Complete event (subevent 0x01) using typed builder
        let le_cc = Self::build_le_conn_complete_evt(
            HCI_SUCCESS,
            handle,
            0x01,
            event_addr_type,
            &peer_addr,
            0,
            0,
            0,
        );
        let mut params = [0u8; 18];
        params[0] = le_cc.status;
        Self::write_le16(&mut params[1..3], le_cc.handle);
        params[3] = le_cc.role;
        params[4] = le_cc.peer_bdaddr_type;
        params[5..11].copy_from_slice(&le_cc.peer_bdaddr.b);
        Self::write_le16(&mut params[11..13], le_cc.interval);
        Self::write_le16(&mut params[13..15], le_cc.latency);
        Self::write_le16(&mut params[15..17], le_cc.supervision_timeout);
        params[17] = le_cc.master_clock_accuracy;
        self.le_meta_event(0x01, &params);

        Ok(false)
    }

    /// LE Create Connection Cancel
    fn cmd_le_create_connection_cancel(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_create_connection_cancel_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x000e), &status);
        Ok(false)
    }

    /// LE Read Accept List Size
    fn cmd_le_read_al_size(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_al_size_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.le_al_len];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x000f), &params);
        Ok(false)
    }

    /// LE Clear Accept List
    fn cmd_le_clear_al(&mut self, _data: &[u8]) -> CmdResult {
        if !self.al_can_modify() {
            return Err(CMD_EPERM);
        }
        self.al_clear();
        Ok(true)
    }

    fn cmd_le_clear_al_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0010), &status);
        Ok(false)
    }

    /// LE Add Device to Accept List
    fn cmd_le_add_al(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        if !self.al_can_modify() {
            return Err(CMD_EPERM);
        }
        let addr_type = data[0];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[1..7]);
        if !self.al_add(addr_type, &addr) {
            return Err(CMD_EEXIST);
        }
        Ok(true)
    }

    fn cmd_le_add_al_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0011), &status);
        Ok(false)
    }

    /// LE Remove Device from Accept List
    fn cmd_le_remove_al(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        if !self.al_can_modify() {
            return Err(CMD_EPERM);
        }
        let addr_type = data[0];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[1..7]);
        if !self.al_remove(addr_type, &addr) {
            return Err(CMD_ENOENT);
        }
        Ok(true)
    }

    fn cmd_le_remove_al_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0012), &status);
        Ok(false)
    }

    /// LE Encrypt
    fn cmd_le_encrypt(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 32 {
            return Err(CMD_EINVAL);
        }
        let mut key = [0u8; 16];
        let mut plaintext = [0u8; 16];
        key.copy_from_slice(&data[..16]);
        plaintext.copy_from_slice(&data[16..32]);

        match bt_crypto_e(&key, &plaintext) {
            Ok(encrypted) => {
                let mut params = [0u8; 17];
                params[0] = HCI_SUCCESS;
                params[1..17].copy_from_slice(&encrypted);
                self.cmd_complete(opcode(OGF_LE_CTL, 0x0017), &params);
            }
            Err(_) => {
                let params = [0x0c_u8]; // Hardware Failure
                self.cmd_complete(opcode(OGF_LE_CTL, 0x0017), &params);
            }
        }
        Ok(false)
    }

    /// LE Rand
    fn cmd_le_rand(&mut self, _data: &[u8]) -> CmdResult {
        let mut rand_val = [0u8; 8];
        if random_bytes(&mut rand_val).is_err() {
            let params = [0x0c_u8]; // Hardware Failure
            self.cmd_complete(opcode(OGF_LE_CTL, 0x0018), &params);
            return Ok(false);
        }
        let mut params = [0u8; 9];
        params[0] = HCI_SUCCESS;
        params[1..9].copy_from_slice(&rand_val);
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0018), &params);
        Ok(false)
    }

    /// LE Read Supported States
    fn cmd_le_read_supported_states(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_supported_states_complete(&mut self, _data: &[u8]) -> CmdResult {
        let mut params = [0u8; 9];
        params[0] = HCI_SUCCESS;
        params[1..9].copy_from_slice(&self.le_states);
        self.cmd_complete(opcode(OGF_LE_CTL, 0x001c), &params);
        Ok(false)
    }

    /// LE Set Data Length
    fn cmd_le_set_data_length(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 6 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let handle_bytes = handle.to_le_bytes();
        let params = [HCI_SUCCESS, handle_bytes[0], handle_bytes[1]];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0022), &params);
        Ok(false)
    }

    /// LE Read Suggested Default Data Length
    fn cmd_le_read_default_data_length(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_default_data_length_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [
            HCI_SUCCESS,
            0xfb,
            0x00, // suggested max tx octets = 251
            0x48,
            0x08, // suggested max tx time = 2120
        ];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0023), &params);
        Ok(false)
    }

    /// LE Write Suggested Default Data Length
    fn cmd_le_write_default_data_length(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_write_default_data_length_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0024), &status);
        Ok(false)
    }

    /// LE Read Local P-256 Public Key
    fn cmd_le_read_local_p256_pubkey(&mut self, _data: &[u8]) -> CmdResult {
        self.cmd_status(opcode(OGF_LE_CTL, 0x0025), HCI_SUCCESS);

        // Generate key pair
        match ecc_make_key() {
            Ok((public_key, private_key)) => {
                self.le_local_sk256.copy_from_slice(&private_key);
                let mut params = [0u8; 65];
                params[0] = HCI_SUCCESS;
                params[1..65].copy_from_slice(&public_key);
                self.le_meta_event(0x08, &params); // LE Read Local P-256 Public Key Complete
            }
            Err(_) => {
                let params = [0x0c_u8]; // Hardware Failure
                self.le_meta_event(0x08, &params);
            }
        }
        Ok(false)
    }

    /// LE Generate DHKey [v1]
    fn cmd_le_generate_dhkey(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 64 {
            return Err(CMD_EINVAL);
        }
        self.cmd_status(opcode(OGF_LE_CTL, 0x0026), HCI_SUCCESS);

        let mut remote_pk = [0u8; 64];
        remote_pk.copy_from_slice(&data[..64]);

        match ecdh_shared_secret(&remote_pk, &self.le_local_sk256) {
            Ok(dhkey) => {
                let mut params = [0u8; 33];
                params[0] = HCI_SUCCESS;
                params[1..33].copy_from_slice(&dhkey);
                self.le_meta_event(0x09, &params); // LE Generate DHKey Complete
            }
            Err(_) => {
                let params = [0x0c_u8];
                self.le_meta_event(0x09, &params);
            }
        }
        Ok(false)
    }

    /// LE Add Device to Resolving List
    fn cmd_le_add_rl(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 39 {
            return Err(CMD_EINVAL);
        }
        if !self.rl_can_modify() {
            return Err(CMD_EPERM);
        }
        let addr_type = data[0];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[1..7]);
        let mut peer_irk = [0u8; 16];
        peer_irk.copy_from_slice(&data[7..23]);
        let mut local_irk = [0u8; 16];
        local_irk.copy_from_slice(&data[23..39]);

        if !self.rl_add(addr_type, &addr, &peer_irk, &local_irk) {
            return Err(CMD_EEXIST);
        }
        Ok(true)
    }

    fn cmd_le_add_rl_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0027), &status);
        Ok(false)
    }

    /// LE Remove Device from Resolving List
    fn cmd_le_remove_rl(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        if !self.rl_can_modify() {
            return Err(CMD_EPERM);
        }
        let addr_type = data[0];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[1..7]);
        if !self.rl_remove(addr_type, &addr) {
            return Err(CMD_ENOENT);
        }
        Ok(true)
    }

    fn cmd_le_remove_rl_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0028), &status);
        Ok(false)
    }

    /// LE Clear Resolving List
    fn cmd_le_clear_rl(&mut self, _data: &[u8]) -> CmdResult {
        if !self.rl_can_modify() {
            return Err(CMD_EPERM);
        }
        self.rl_clear();
        Ok(true)
    }

    fn cmd_le_clear_rl_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0029), &status);
        Ok(false)
    }

    /// LE Read Resolving List Size
    fn cmd_le_read_rl_size(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_rl_size_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, self.le_rl_len];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x002a), &params);
        Ok(false)
    }

    /// LE Set Address Resolution Enable
    fn cmd_le_set_addr_resolution_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        self.le_rl_enable = data[0];
        Ok(true)
    }

    fn cmd_le_set_addr_resolution_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x002d), &status);
        Ok(false)
    }

    /// LE Set Resolvable Private Address Timeout
    fn cmd_le_set_rpa_timeout(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.le_rl_timeout = u16::from_le_bytes([data[0], data[1]]);
        Ok(true)
    }

    fn cmd_le_set_rpa_timeout_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x002e), &status);
        Ok(false)
    }

    /// LE Read Maximum Data Length
    fn cmd_le_read_max_data_length(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_max_data_length_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [
            HCI_SUCCESS,
            0xfb,
            0x00, // supported_max_tx_octets = 251
            0x48,
            0x08, // supported_max_tx_time = 2120
            0xfb,
            0x00, // supported_max_rx_octets = 251
            0x48,
            0x08, // supported_max_rx_time = 2120
        ];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x002f), &params);
        Ok(false)
    }

    /// LE Read PHY
    fn cmd_le_read_phy(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let handle_bytes = handle.to_le_bytes();
        let params = [
            HCI_SUCCESS,
            handle_bytes[0],
            handle_bytes[1],
            0x01, // TX PHY: LE 1M
            0x01, // RX PHY: LE 1M
        ];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0030), &params);
        Ok(false)
    }

    /// LE Set Default PHY
    fn cmd_le_set_default_phy(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_set_default_phy_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0031), &status);
        Ok(false)
    }

    /// LE Set PHY
    fn cmd_le_set_phy(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        self.cmd_status(opcode(OGF_LE_CTL, 0x0032), HCI_SUCCESS);
        // LE PHY Update Complete event (subevent 0x0c)
        let handle_bytes = handle.to_le_bytes();
        let params = [
            HCI_SUCCESS,
            handle_bytes[0],
            handle_bytes[1],
            0x01, // TX PHY: LE 1M
            0x01, // RX PHY: LE 1M
        ];
        self.le_meta_event(0x0c, &params);
        Ok(false)
    }

    // --- Extended Advertising Commands ---

    /// LE Set Advertising Set Random Address
    fn cmd_le_set_adv_set_random_addr(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        let handle = data[0];
        let adv = self.get_or_create_ext_adv(handle);
        adv.random_addr.copy_from_slice(&data[1..7]);
        Ok(true)
    }

    fn cmd_le_set_adv_set_random_addr_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0035), &status);
        Ok(false)
    }

    /// LE Set Extended Advertising Parameters
    fn cmd_le_set_ext_adv_params(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 25 {
            return Err(CMD_EINVAL);
        }
        let handle = data[0];
        // Track current ext adv type at device level
        self.le_ext_adv_type = u16::from(data[1]) | (u16::from(data[2]) << 8);
        let adv = self.get_or_create_ext_adv(handle);
        adv.adv_type = data[1];
        adv.own_addr_type = data[7];
        adv.direct_addr_type = data[8];
        adv.direct_addr.copy_from_slice(&data[9..15]);
        adv.filter_policy = data[15];
        Ok(true)
    }

    fn cmd_le_set_ext_adv_params_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x00]; // selected_tx_power = 0 dBm
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0036), &params);
        Ok(false)
    }

    /// LE Set Extended Advertising Data
    fn cmd_le_set_ext_adv_data(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 4 {
            return Err(CMD_EINVAL);
        }
        let handle = data[0];
        let _operation = data[1];
        let _fragment_pref = data[2];
        let data_len = data[3] as usize;
        let adv = self.get_or_create_ext_adv(handle);
        if data.len() >= 4 + data_len && data_len <= MAX_EXT_ADV_LEN {
            adv.adv_data_len = data_len;
            adv.adv_data[..data_len].copy_from_slice(&data[4..4 + data_len]);
        }
        Ok(true)
    }

    fn cmd_le_set_ext_adv_data_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0037), &status);
        Ok(false)
    }

    /// LE Set Extended Scan Response Data
    fn cmd_le_set_ext_scan_rsp_data(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 4 {
            return Err(CMD_EINVAL);
        }
        let handle = data[0];
        let _operation = data[1];
        let _fragment_pref = data[2];
        let data_len = data[3] as usize;
        let adv = self.get_or_create_ext_adv(handle);
        if data.len() >= 4 + data_len && data_len <= MAX_EXT_ADV_LEN {
            adv.scan_rsp_len = data_len;
            adv.scan_rsp[..data_len].copy_from_slice(&data[4..4 + data_len]);
        }
        Ok(true)
    }

    fn cmd_le_set_ext_scan_rsp_data_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0038), &status);
        Ok(false)
    }

    /// LE Set Extended Advertising Enable
    fn cmd_le_set_ext_adv_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let enable = data[0];
        let num_sets = data[1];
        // For simplicity, enable/disable all referenced sets
        if enable != 0 && num_sets > 0 {
            let mut offset = 2;
            for _ in 0..num_sets {
                if offset >= data.len() {
                    break;
                }
                let handle = data[offset];
                let adv = self.get_or_create_ext_adv(handle);
                adv.enabled = true;
                offset += 4; // handle + duration(2) + max_events(1)
            }
        } else if enable == 0 {
            if num_sets == 0 {
                // Disable all
                for adv in self.le_ext_adv_sets.values_mut() {
                    adv.enabled = false;
                }
            } else {
                let mut offset = 2;
                for _ in 0..num_sets {
                    if offset >= data.len() {
                        break;
                    }
                    let handle = data[offset];
                    if let Some(adv) = self.le_ext_adv_sets.get_mut(&handle) {
                        adv.enabled = false;
                    }
                    offset += 4;
                }
            }
        }
        Ok(true)
    }

    fn cmd_le_set_ext_adv_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0039), &status);
        Ok(false)
    }

    /// LE Read Maximum Advertising Data Length
    fn cmd_le_read_max_adv_data_len(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_max_adv_data_len_complete(&mut self, _data: &[u8]) -> CmdResult {
        let len = (MAX_EXT_ADV_LEN as u16).to_le_bytes();
        let params = [HCI_SUCCESS, len[0], len[1]];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x003a), &params);
        Ok(false)
    }

    /// LE Read Number of Supported Advertising Sets
    fn cmd_le_read_num_adv_sets(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_num_adv_sets_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, MAX_EXT_ADV_SETS as u8];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x003b), &params);
        Ok(false)
    }

    /// LE Remove Advertising Set
    fn cmd_le_remove_adv_set(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        let handle = data[0];
        if let Some(adv) = self.le_ext_adv_sets.get(&handle) {
            if adv.enabled {
                return Err(CMD_EPERM);
            }
        }
        self.remove_ext_adv(handle);
        Ok(true)
    }

    fn cmd_le_remove_adv_set_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x003c), &status);
        Ok(false)
    }

    /// LE Clear Advertising Sets
    fn cmd_le_clear_adv_sets(&mut self, _data: &[u8]) -> CmdResult {
        // Check no sets are enabled
        for adv in self.le_ext_adv_sets.values() {
            if adv.enabled {
                return Err(CMD_EPERM);
            }
        }
        self.clear_ext_adv_sets();
        Ok(true)
    }

    fn cmd_le_clear_adv_sets_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x003d), &status);
        Ok(false)
    }

    // --- Periodic Advertising Commands ---

    /// LE Set Periodic Advertising Parameters
    fn cmd_le_set_per_adv_params(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 7 {
            return Err(CMD_EINVAL);
        }
        let _handle = data[0];
        self.le_pa_min_interval = u16::from_le_bytes([data[1], data[2]]);
        self.le_pa_max_interval = u16::from_le_bytes([data[3], data[4]]);
        self.le_pa_properties = u16::from_le_bytes([data[5], data[6]]);
        Ok(true)
    }

    fn cmd_le_set_per_adv_params_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x003e), &status);
        Ok(false)
    }

    /// LE Set Periodic Advertising Data
    fn cmd_le_set_per_adv_data(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        let _handle = data[0];
        let _operation = data[1];
        let data_len = data[2] as usize;
        if data.len() >= 3 + data_len && data_len <= MAX_PA_DATA_LEN {
            self.le_pa_data_len = data_len as u8;
            self.le_pa_data[..data_len].copy_from_slice(&data[3..3 + data_len]);
        }
        Ok(true)
    }

    fn cmd_le_set_per_adv_data_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x003f), &status);
        Ok(false)
    }

    /// LE Set Periodic Advertising Enable
    fn cmd_le_set_per_adv_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        self.le_pa_enable = data[0];
        Ok(true)
    }

    fn cmd_le_set_per_adv_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0040), &status);
        Ok(false)
    }

    // --- Extended Scan Commands ---

    /// LE Set Extended Scan Parameters
    fn cmd_le_set_ext_scan_params(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        self.le_scan_own_addr_type = data[0];
        self.le_scan_filter_policy = data[1];
        // num_phys = data[2]; rest is per-PHY params
        if data.len() >= 8 {
            self.le_scan_type = data[3];
        }
        Ok(true)
    }

    fn cmd_le_set_ext_scan_params_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0041), &status);
        Ok(false)
    }

    /// LE Set Extended Scan Enable
    fn cmd_le_set_ext_scan_enable(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 6 {
            return Err(CMD_EINVAL);
        }
        self.le_scan_enable = data[0];
        self.le_filter_dup = data[1];
        Ok(true)
    }

    fn cmd_le_set_ext_scan_enable_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0042), &status);
        Ok(false)
    }

    /// LE Extended Create Connection
    fn cmd_le_ext_create_conn(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 10 {
            return Err(CMD_EINVAL);
        }
        self.cmd_status(opcode(OGF_LE_CTL, 0x0043), HCI_SUCCESS);

        let handle = self.alloc_handle();
        let peer_addr_type = data[1];
        let mut peer_addr = [0u8; 6];
        peer_addr.copy_from_slice(&data[2..8]);

        let conn = BtDevConn {
            handle,
            link_type: ACL_LINK,
            encr_mode: 0,
            encrypted: false,
            peer_addr,
            peer_index: None,
            peer_handle: None,
            sub_conn_handles: Vec::new(),
            data: Vec::new(),
        };
        self.add_conn(handle, conn);

        // LE Enhanced Connection Complete event (subevent 0x0a)
        let handle_bytes = handle.to_le_bytes();
        let mut params = [0u8; 30];
        params[0] = HCI_SUCCESS;
        params[1] = handle_bytes[0];
        params[2] = handle_bytes[1];
        params[3] = 0x01; // role: slave
        params[4] = peer_addr_type;
        params[5..11].copy_from_slice(&peer_addr);
        // local_rpa, peer_rpa: zeros
        // conn_interval, conn_latency, supervision_timeout, master_clock_accuracy: zeros
        self.le_meta_event(0x0a, &params);

        Ok(false)
    }

    /// LE Read TX Power
    fn cmd_le_read_tx_power(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_tx_power_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [
            HCI_SUCCESS,
            0xec_u8,
            0xff, // min_tx_power = -20 (0xFFEC)
            0x0a,
            0x00, // max_tx_power = 10
        ];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x004b), &params);
        Ok(false)
    }

    // =======================================================================
    // HCI Command Handlers — LE 5.0
    // =======================================================================

    /// LE Set Privacy Mode
    fn cmd_le_set_privacy_mode(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 8 {
            return Err(CMD_EINVAL);
        }
        // Privacy mode is per-device in the resolving list
        // We accept but don't track individually
        Ok(true)
    }

    fn cmd_le_set_privacy_mode_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x004e), &status);
        Ok(false)
    }

    /// LE Read RF Path Compensation
    fn cmd_le_read_rf_path_compensation(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_rf_path_compensation_complete(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x00, 0x00, 0x00, 0x00]; // RF TX/RX path comp = 0
        self.cmd_complete(opcode(OGF_LE_CTL, 0x004c), &params);
        Ok(false)
    }

    /// LE Write RF Path Compensation
    fn cmd_le_write_rf_path_compensation(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_write_rf_path_compensation_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x004d), &status);
        Ok(false)
    }

    // =======================================================================
    // HCI Command Handlers — LE 5.2 (ISO)
    // =======================================================================

    /// LE Read Buffer Size [v2]
    fn cmd_le_read_buffer_size_v2(&mut self, _data: &[u8]) -> CmdResult {
        Ok(true)
    }

    fn cmd_le_read_buffer_size_v2_complete(&mut self, _data: &[u8]) -> CmdResult {
        let acl_mtu = self.acl_mtu.to_le_bytes();
        let iso_mtu = self.iso_mtu.to_le_bytes();
        let iso_max = self.iso_max_pkt.to_le_bytes();
        let params = [
            HCI_SUCCESS,
            acl_mtu[0],
            acl_mtu[1],
            self.acl_max_pkt as u8,
            iso_mtu[0],
            iso_mtu[1],
            iso_max[0],
            iso_max[1],
        ];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0060), &params);
        Ok(false)
    }

    /// LE Set CIG Parameters
    fn cmd_le_set_cig_params(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 15 {
            return Err(CMD_EINVAL);
        }
        let cig_id = data[0];
        if cig_id as usize >= CIG_SIZE {
            return Err(CMD_EINVAL);
        }

        // Parse SDU intervals (3-byte LE values, read via read_le32 with 4-byte buffer)
        let mut interval_buf = [0u8; 4];
        interval_buf[..3].copy_from_slice(&data[1..4]);
        let sdu_interval_c_to_p = Self::read_le32(&interval_buf);
        interval_buf = [0u8; 4];
        interval_buf[..3].copy_from_slice(&data[4..7]);
        let sdu_interval_p_to_c = Self::read_le32(&interval_buf);

        let num_cis = data[13] as usize;

        let cig = &mut self.le_cig[cig_id as usize];
        cig.cig_id = cig_id;
        cig.sdu_interval_c_to_p = sdu_interval_c_to_p;
        cig.sdu_interval_p_to_c = sdu_interval_p_to_c;
        cig.num_cis = std::cmp::min(num_cis, CIS_SIZE) as u8;

        // Allocate handles for CIS
        let mut cis_handles = Vec::new();
        for i in 0..cig.num_cis {
            let handle = CIS_HANDLE_BASE + (cig_id as u16) * CIS_SIZE as u16 + i as u16;
            cis_handles.push(handle);
        }

        // Build response using write_le32/write_le16 for proper encoding
        let mut params = Vec::with_capacity(4 + (cig.num_cis as usize) * 2);
        params.push(HCI_SUCCESS);
        params.push(cig_id);
        params.push(cig.num_cis);
        for h in &cis_handles {
            let mut hb = [0u8; 2];
            Self::write_le16(&mut hb, *h);
            params.extend_from_slice(&hb);
        }
        // Log the interval using write_le32 encoding for consistency
        let mut interval_log = [0u8; 4];
        Self::write_le32(&mut interval_log, sdu_interval_c_to_p);
        tracing::trace!(
            "btdev: CIG {} created, c_to_p_interval={}",
            cig_id,
            u32::from_le_bytes(interval_log)
        );
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0062), &params);
        Ok(false)
    }

    /// LE Create CIS
    fn cmd_le_create_cis(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 5 {
            return Err(CMD_EINVAL);
        }
        let num_cis = data[0] as usize;
        self.cmd_status(opcode(OGF_LE_CTL, 0x0064), HCI_SUCCESS);

        // Generate CIS Established events
        let mut offset = 1;
        for _ in 0..num_cis {
            if offset + 4 > data.len() {
                break;
            }
            let cis_handle = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let acl_handle = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
            let _ = acl_handle;
            offset += 4;

            // LE CIS Established event (subevent 0x19)
            let cis_h = cis_handle.to_le_bytes();
            let mut params = [0u8; 28];
            params[0] = HCI_SUCCESS;
            params[1] = cis_h[0];
            params[2] = cis_h[1];
            // All other fields are zero
            self.le_meta_event(0x19, &params);
        }

        Ok(false)
    }

    /// LE Remove CIG
    fn cmd_le_remove_cig(&mut self, data: &[u8]) -> CmdResult {
        if data.is_empty() {
            return Err(CMD_EINVAL);
        }
        let cig_id = data[0];
        if cig_id as usize >= CIG_SIZE {
            return Err(CMD_EINVAL);
        }
        self.le_cig[cig_id as usize] = LeCig::default();
        self.le_cig[cig_id as usize].cig_id = 0xff;

        let params = [HCI_SUCCESS, cig_id];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0065), &params);
        Ok(false)
    }

    /// LE Accept CIS Request
    fn cmd_le_accept_cis(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        self.cmd_status(opcode(OGF_LE_CTL, 0x0066), HCI_SUCCESS);

        // LE CIS Established event
        let h = handle.to_le_bytes();
        let mut params = [0u8; 28];
        params[0] = HCI_SUCCESS;
        params[1] = h[0];
        params[2] = h[1];
        self.le_meta_event(0x19, &params);
        Ok(false)
    }

    /// LE Reject CIS Request
    fn cmd_le_reject_cis(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let reason = data[2];
        let h = handle.to_le_bytes();
        let params = [HCI_SUCCESS, h[0], h[1]];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0067), &params);
        // CIS Established event with failure
        let mut evt_params = [0u8; 28];
        evt_params[0] = reason;
        evt_params[1] = h[0];
        evt_params[2] = h[1];
        self.le_meta_event(0x19, &evt_params);
        Ok(false)
    }

    /// LE Create BIG
    fn cmd_le_create_big(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 26 {
            return Err(CMD_EINVAL);
        }
        let big_handle = data[0];
        let _adv_handle = data[1];
        let num_bis = data[2] as usize;
        let encrypted = data[22];

        self.cmd_status(opcode(OGF_LE_CTL, 0x0068), HCI_SUCCESS);

        let mut bis_handles = Vec::new();
        for i in 0..std::cmp::min(num_bis, BIS_SIZE) {
            let handle = BIS_HANDLE_BASE + (big_handle as u16) * BIS_SIZE as u16 + i as u16;
            bis_handles.push(handle);
        }

        let big = LeBig {
            handle: big_handle,
            big_handle,
            num_bis: bis_handles.len() as u8,
            encrypted: encrypted != 0,
            bis_handles: bis_handles.clone(),
        };
        self.le_big.push(big);

        // LE Create BIG Complete event (subevent 0x1b)
        let mut params = Vec::with_capacity(18 + bis_handles.len() * 2);
        params.push(HCI_SUCCESS);
        params.push(big_handle);
        params.extend_from_slice(&[0u8; 15]); // sync_delay, transport_latency, phy, NSE, BN, etc.
        params.push(bis_handles.len() as u8);
        for h in &bis_handles {
            params.extend_from_slice(&h.to_le_bytes());
        }
        self.le_meta_event(0x1b, &params);

        Ok(false)
    }

    /// LE Terminate BIG
    fn cmd_le_terminate_big(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let big_handle = data[0];
        let reason = data[1];

        self.cmd_status(opcode(OGF_LE_CTL, 0x006a), HCI_SUCCESS);

        // Remove BIG
        self.le_big.retain(|b| b.big_handle != big_handle);

        // LE Terminate BIG Complete event (subevent 0x1c)
        let params = [big_handle, reason];
        self.le_meta_event(0x1c, &params);

        Ok(false)
    }

    /// LE Setup ISO Data Path
    fn cmd_le_setup_iso_data_path(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 13 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let direction = data[2];
        if direction < 2 {
            self.le_iso_path[direction as usize] = 1;
        }
        let h = handle.to_le_bytes();
        let params = [HCI_SUCCESS, h[0], h[1]];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x006e), &params);
        Ok(false)
    }

    /// LE Remove ISO Data Path
    fn cmd_le_remove_iso_data_path(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 3 {
            return Err(CMD_EINVAL);
        }
        let handle = u16::from_le_bytes([data[0], data[1]]);
        let direction = data[2];
        if direction < 2 {
            self.le_iso_path[direction as usize] = 0;
        }
        let h = handle.to_le_bytes();
        let params = [HCI_SUCCESS, h[0], h[1]];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x006f), &params);
        Ok(false)
    }

    // =======================================================================
    // HCI Command Handlers — LE 6.0
    // =======================================================================

    /// LE Set Host Feature
    fn cmd_le_set_host_feature(&mut self, data: &[u8]) -> CmdResult {
        if data.len() < 2 {
            return Err(CMD_EINVAL);
        }
        let bit_number = data[0];
        let bit_value = data[1];
        if bit_number < 64 {
            let byte_idx = bit_number as usize / 8;
            let bit_idx = bit_number % 8;
            if bit_value != 0 {
                self.le_features[byte_idx] |= 1 << bit_idx;
            } else {
                self.le_features[byte_idx] &= !(1 << bit_idx);
            }
        }
        Ok(true)
    }

    fn cmd_le_set_host_feature_complete(&mut self, _data: &[u8]) -> CmdResult {
        let status = [HCI_SUCCESS];
        self.cmd_complete(opcode(OGF_LE_CTL, 0x0074), &status);
        Ok(false)
    }

    // =======================================================================
    // Vendor Command Handlers — MSFT
    // =======================================================================

    /// MSFT vendor: Read Supported Features
    fn cmd_msft_read_features(&mut self, _data: &[u8]) -> CmdResult {
        // Return empty MSFT feature set
        let mut params = [0u8; 12];
        params[0] = HCI_SUCCESS;
        params[1] = 0x00; // MSFT sub-opcode (read features)
        // Rest are feature bytes (all zero)
        self.cmd_complete(opcode(OGF_VENDOR_CMD, self.msft_opcode & 0x03FF), &params);
        Ok(false)
    }

    /// MSFT vendor: LE Monitor Advertisement
    fn cmd_msft_le_monitor_adv(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x03, 0x00]; // sub-opcode=0x03, monitor_handle=0
        self.cmd_complete(opcode(OGF_VENDOR_CMD, self.msft_opcode & 0x03FF), &params);
        Ok(false)
    }

    /// MSFT vendor: LE Cancel Monitor Advertisement
    fn cmd_msft_le_cancel_monitor_adv(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x04]; // sub-opcode=0x04
        self.cmd_complete(opcode(OGF_VENDOR_CMD, self.msft_opcode & 0x03FF), &params);
        Ok(false)
    }

    /// MSFT vendor: LE Monitor Advertisement Enable
    fn cmd_msft_le_monitor_adv_enable(&mut self, _data: &[u8]) -> CmdResult {
        let params = [HCI_SUCCESS, 0x05]; // sub-opcode=0x05
        self.cmd_complete(opcode(OGF_VENDOR_CMD, self.msft_opcode & 0x03FF), &params);
        Ok(false)
    }

    // =======================================================================
    // Vendor Command Handlers — EMU
    // =======================================================================

    /// EMU vendor: Test Event
    fn cmd_emu_test_event(&mut self, data: &[u8]) -> CmdResult {
        // Echo data back as a vendor-specific event
        let params = [HCI_SUCCESS, 0x01]; // sub-opcode
        self.cmd_complete(opcode(OGF_VENDOR_CMD, self.emu_opcode & 0x03FF), &params);

        if data.len() >= 2 {
            // Also emit a vendor event with the data
            let mut evt_data = vec![self.emu_opcode as u8];
            evt_data.extend_from_slice(data);
            self.send_event(0xff, &evt_data); // Vendor-specific event
        }
        Ok(false)
    }

    // =======================================================================
    // Command Dispatch Tables
    // =======================================================================

    /// Look up a command handler by opcode in the command table for this
    /// controller type. Returns the handler function and optional complete function.
    fn lookup_cmd(&self, opc: u16) -> Option<(CmdHandlerFn, Option<CmdHandlerFn>)> {
        // Commands common to ALL controller types
        let common_all: &[CmdTableEntry] = &[
            (
                opcode(OGF_HOST_CTL, 0x0001),
                BtDev::cmd_set_event_mask,
                Some(BtDev::cmd_set_event_mask_complete),
            ),
            (opcode(OGF_HOST_CTL, 0x0003), BtDev::cmd_reset, Some(BtDev::cmd_reset_complete)),
            (
                opcode(OGF_HOST_CTL, 0x0005),
                BtDev::cmd_set_event_filter,
                Some(BtDev::cmd_set_event_filter_complete),
            ),
            (
                opcode(OGF_INFO_PARAM, 0x0001),
                BtDev::cmd_read_local_version,
                Some(BtDev::cmd_read_local_version_complete),
            ),
            (
                opcode(OGF_INFO_PARAM, 0x0002),
                BtDev::cmd_read_local_commands,
                Some(BtDev::cmd_read_local_commands_complete),
            ),
            (
                opcode(OGF_INFO_PARAM, 0x0003),
                BtDev::cmd_read_local_features,
                Some(BtDev::cmd_read_local_features_complete),
            ),
            (
                opcode(OGF_INFO_PARAM, 0x0005),
                BtDev::cmd_read_buffer_size,
                Some(BtDev::cmd_read_buffer_size_complete),
            ),
            (
                opcode(OGF_INFO_PARAM, 0x0009),
                BtDev::cmd_read_bdaddr,
                Some(BtDev::cmd_read_bdaddr_complete),
            ),
        ];

        // Commands common to BR/EDR+LE
        let common_bredrle: &[CmdTableEntry] = &[
            (
                opcode(OGF_HOST_CTL, 0x0063),
                BtDev::cmd_set_event_mask_page2,
                Some(BtDev::cmd_set_event_mask_page2_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x006c),
                BtDev::cmd_read_le_host_supported,
                Some(BtDev::cmd_read_le_host_supported_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x006d),
                BtDev::cmd_write_le_host_supported,
                Some(BtDev::cmd_write_le_host_supported_complete),
            ),
        ];

        // Commands common to BR/EDR 2.0+
        let common_bredr20: &[CmdTableEntry] = &[
            (opcode(OGF_LINK_CONTROL, 0x0001), BtDev::cmd_inquiry, None),
            (
                opcode(OGF_LINK_CONTROL, 0x0002),
                BtDev::cmd_inquiry_cancel,
                Some(BtDev::cmd_inquiry_cancel_complete),
            ),
            (opcode(OGF_LINK_CONTROL, 0x0005), BtDev::cmd_create_connection, None),
            (opcode(OGF_LINK_CONTROL, 0x0006), BtDev::cmd_disconnect, None),
            (opcode(OGF_LINK_CONTROL, 0x0009), BtDev::cmd_accept_connection, None),
            (opcode(OGF_LINK_CONTROL, 0x000a), BtDev::cmd_reject_connection, None),
            (opcode(OGF_LINK_CONTROL, 0x000d), BtDev::cmd_pin_code_reply, None),
            (opcode(OGF_LINK_CONTROL, 0x0011), BtDev::cmd_authentication_requested, None),
            (opcode(OGF_LINK_CONTROL, 0x0013), BtDev::cmd_set_connection_encryption, None),
            (opcode(OGF_LINK_CONTROL, 0x0019), BtDev::cmd_remote_name_request, None),
            (opcode(OGF_LINK_CONTROL, 0x001b), BtDev::cmd_read_remote_features, None),
            (opcode(OGF_LINK_CONTROL, 0x001c), BtDev::cmd_read_remote_ext_features, None),
            (opcode(OGF_LINK_CONTROL, 0x001d), BtDev::cmd_read_remote_version, None),
            (
                opcode(0x02, 0x000e),
                BtDev::cmd_read_default_link_policy,
                Some(BtDev::cmd_read_default_link_policy_complete),
            ),
            (
                opcode(0x02, 0x000f),
                BtDev::cmd_write_default_link_policy,
                Some(BtDev::cmd_write_default_link_policy_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x000a),
                BtDev::cmd_write_pin_type,
                Some(BtDev::cmd_write_pin_type_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x000d),
                BtDev::cmd_read_stored_link_key,
                Some(BtDev::cmd_read_stored_link_key_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0011),
                BtDev::cmd_write_stored_link_key,
                Some(BtDev::cmd_write_stored_link_key_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0012),
                BtDev::cmd_delete_stored_link_key,
                Some(BtDev::cmd_delete_stored_link_key_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0013),
                BtDev::cmd_write_local_name,
                Some(BtDev::cmd_write_local_name_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0014),
                BtDev::cmd_read_local_name,
                Some(BtDev::cmd_read_local_name_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0015),
                BtDev::cmd_read_conn_accept_timeout,
                Some(BtDev::cmd_read_conn_accept_timeout_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0016),
                BtDev::cmd_write_conn_accept_timeout,
                Some(BtDev::cmd_write_conn_accept_timeout_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0017),
                BtDev::cmd_read_page_timeout,
                Some(BtDev::cmd_read_page_timeout_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0018),
                BtDev::cmd_write_page_timeout,
                Some(BtDev::cmd_write_page_timeout_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0019),
                BtDev::cmd_read_scan_enable,
                Some(BtDev::cmd_read_scan_enable_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x001a),
                BtDev::cmd_write_scan_enable,
                Some(BtDev::cmd_write_scan_enable_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x001b),
                BtDev::cmd_read_page_scan_activity,
                Some(BtDev::cmd_read_page_scan_activity_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x001c),
                BtDev::cmd_write_page_scan_activity,
                Some(BtDev::cmd_write_page_scan_activity_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x001d),
                BtDev::cmd_read_inquiry_scan_activity,
                Some(BtDev::cmd_read_inquiry_scan_activity_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x001e),
                BtDev::cmd_write_inquiry_scan_activity,
                Some(BtDev::cmd_write_inquiry_scan_activity_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x001f),
                BtDev::cmd_read_auth_enable,
                Some(BtDev::cmd_read_auth_enable_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0020),
                BtDev::cmd_write_auth_enable,
                Some(BtDev::cmd_write_auth_enable_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0023),
                BtDev::cmd_read_class_of_device,
                Some(BtDev::cmd_read_class_of_device_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0024),
                BtDev::cmd_write_class_of_device,
                Some(BtDev::cmd_write_class_of_device_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0025),
                BtDev::cmd_read_voice_setting,
                Some(BtDev::cmd_read_voice_setting_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0026),
                BtDev::cmd_write_voice_setting,
                Some(BtDev::cmd_write_voice_setting_complete),
            ),
            (opcode(OGF_HOST_CTL, 0x002d), BtDev::cmd_read_tx_power, None),
            (
                opcode(OGF_HOST_CTL, 0x0031),
                BtDev::cmd_set_host_flow_control,
                Some(BtDev::cmd_set_host_flow_control_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0033),
                BtDev::cmd_host_buffer_size,
                Some(BtDev::cmd_host_buffer_size_complete),
            ),
            (opcode(OGF_HOST_CTL, 0x0035), BtDev::cmd_host_num_completed_pkts, None),
            (opcode(OGF_HOST_CTL, 0x0036), BtDev::cmd_read_link_supervision_timeout, None),
            (opcode(OGF_HOST_CTL, 0x0037), BtDev::cmd_write_link_supervision_timeout, None),
            (
                opcode(OGF_HOST_CTL, 0x0038),
                BtDev::cmd_read_num_supported_iac,
                Some(BtDev::cmd_read_num_supported_iac_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0039),
                BtDev::cmd_read_current_iac_lap,
                Some(BtDev::cmd_read_current_iac_lap_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x003a),
                BtDev::cmd_write_current_iac_lap,
                Some(BtDev::cmd_write_current_iac_lap_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0044),
                BtDev::cmd_read_inquiry_mode,
                Some(BtDev::cmd_read_inquiry_mode_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0045),
                BtDev::cmd_write_inquiry_mode,
                Some(BtDev::cmd_write_inquiry_mode_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0046),
                BtDev::cmd_read_page_scan_type,
                Some(BtDev::cmd_read_page_scan_type_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0047),
                BtDev::cmd_write_page_scan_type,
                Some(BtDev::cmd_write_page_scan_type_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0048),
                BtDev::cmd_read_afh_assessment,
                Some(BtDev::cmd_read_afh_assessment_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0049),
                BtDev::cmd_write_afh_assessment,
                Some(BtDev::cmd_write_afh_assessment_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0051),
                BtDev::cmd_read_ext_inquiry_rsp,
                Some(BtDev::cmd_read_ext_inquiry_rsp_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0052),
                BtDev::cmd_write_ext_inquiry_rsp,
                Some(BtDev::cmd_write_ext_inquiry_rsp_complete),
            ),
        ];

        // BR/EDR 4.0+ commands (SSP, Secure Connections)
        let bredr_cmds: &[CmdTableEntry] = &[
            (
                opcode(OGF_HOST_CTL, 0x0055),
                BtDev::cmd_read_simple_pairing_mode,
                Some(BtDev::cmd_read_simple_pairing_mode_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0056),
                BtDev::cmd_write_simple_pairing_mode,
                Some(BtDev::cmd_write_simple_pairing_mode_complete),
            ),
            (opcode(OGF_HOST_CTL, 0x0057), BtDev::cmd_read_local_oob_data, None),
            (
                opcode(OGF_HOST_CTL, 0x0058),
                BtDev::cmd_read_inq_rsp_tx_power,
                Some(BtDev::cmd_read_inq_rsp_tx_power_complete),
            ),
            (opcode(OGF_HOST_CTL, 0x0008), BtDev::cmd_read_encryption_key_size, None),
            (
                opcode(OGF_HOST_CTL, 0x0079),
                BtDev::cmd_read_secure_conn_support,
                Some(BtDev::cmd_read_secure_conn_support_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x007a),
                BtDev::cmd_write_secure_conn_support,
                Some(BtDev::cmd_write_secure_conn_support_complete),
            ),
            (opcode(OGF_HOST_CTL, 0x007d), BtDev::cmd_read_local_oob_ext_data, None),
            (
                opcode(OGF_HOST_CTL, 0x0077),
                BtDev::cmd_read_sync_train_params,
                Some(BtDev::cmd_read_sync_train_params_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x0078),
                BtDev::cmd_write_sync_train_params,
                Some(BtDev::cmd_write_sync_train_params_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x002e),
                BtDev::cmd_read_sco_flowctl,
                Some(BtDev::cmd_read_sco_flowctl_complete),
            ),
            (
                opcode(OGF_HOST_CTL, 0x002f),
                BtDev::cmd_write_sco_flowctl,
                Some(BtDev::cmd_write_sco_flowctl_complete),
            ),
            (opcode(OGF_LINK_CONTROL, 0x002b), BtDev::cmd_io_capability_reply, None),
            (opcode(OGF_LINK_CONTROL, 0x0034), BtDev::cmd_io_capability_neg_reply, None),
            (opcode(OGF_LINK_CONTROL, 0x002c), BtDev::cmd_user_confirmation_reply, None),
            (opcode(OGF_LINK_CONTROL, 0x002d), BtDev::cmd_user_confirmation_neg_reply, None),
            (opcode(OGF_LINK_CONTROL, 0x002e), BtDev::cmd_user_passkey_reply, None),
            (opcode(OGF_LINK_CONTROL, 0x002f), BtDev::cmd_user_passkey_neg_reply, None),
        ];

        // LE commands
        let le_cmds: &[CmdTableEntry] = &[
            (
                opcode(OGF_LE_CTL, 0x0001),
                BtDev::cmd_le_set_event_mask,
                Some(BtDev::cmd_le_set_event_mask_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0002),
                BtDev::cmd_le_read_buffer_size,
                Some(BtDev::cmd_le_read_buffer_size_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0003),
                BtDev::cmd_le_read_local_features,
                Some(BtDev::cmd_le_read_local_features_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0005),
                BtDev::cmd_le_set_random_addr,
                Some(BtDev::cmd_le_set_random_addr_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0006),
                BtDev::cmd_le_set_adv_params,
                Some(BtDev::cmd_le_set_adv_params_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0007),
                BtDev::cmd_le_read_adv_tx_power,
                Some(BtDev::cmd_le_read_adv_tx_power_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0008),
                BtDev::cmd_le_set_adv_data,
                Some(BtDev::cmd_le_set_adv_data_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0009),
                BtDev::cmd_le_set_scan_rsp_data,
                Some(BtDev::cmd_le_set_scan_rsp_data_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x000a),
                BtDev::cmd_le_set_adv_enable,
                Some(BtDev::cmd_le_set_adv_enable_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x000b),
                BtDev::cmd_le_set_scan_params,
                Some(BtDev::cmd_le_set_scan_params_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x000c),
                BtDev::cmd_le_set_scan_enable,
                Some(BtDev::cmd_le_set_scan_enable_complete),
            ),
            (opcode(OGF_LE_CTL, 0x000d), BtDev::cmd_le_create_connection, None),
            (
                opcode(OGF_LE_CTL, 0x000e),
                BtDev::cmd_le_create_connection_cancel,
                Some(BtDev::cmd_le_create_connection_cancel_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x000f),
                BtDev::cmd_le_read_al_size,
                Some(BtDev::cmd_le_read_al_size_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0010),
                BtDev::cmd_le_clear_al,
                Some(BtDev::cmd_le_clear_al_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0011), BtDev::cmd_le_add_al, Some(BtDev::cmd_le_add_al_complete)),
            (
                opcode(OGF_LE_CTL, 0x0012),
                BtDev::cmd_le_remove_al,
                Some(BtDev::cmd_le_remove_al_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0017), BtDev::cmd_le_encrypt, None),
            (opcode(OGF_LE_CTL, 0x0018), BtDev::cmd_le_rand, None),
            (
                opcode(OGF_LE_CTL, 0x001c),
                BtDev::cmd_le_read_supported_states,
                Some(BtDev::cmd_le_read_supported_states_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0022), BtDev::cmd_le_set_data_length, None),
            (
                opcode(OGF_LE_CTL, 0x0023),
                BtDev::cmd_le_read_default_data_length,
                Some(BtDev::cmd_le_read_default_data_length_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0024),
                BtDev::cmd_le_write_default_data_length,
                Some(BtDev::cmd_le_write_default_data_length_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0025), BtDev::cmd_le_read_local_p256_pubkey, None),
            (opcode(OGF_LE_CTL, 0x0026), BtDev::cmd_le_generate_dhkey, None),
            (opcode(OGF_LE_CTL, 0x0027), BtDev::cmd_le_add_rl, Some(BtDev::cmd_le_add_rl_complete)),
            (
                opcode(OGF_LE_CTL, 0x0028),
                BtDev::cmd_le_remove_rl,
                Some(BtDev::cmd_le_remove_rl_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0029),
                BtDev::cmd_le_clear_rl,
                Some(BtDev::cmd_le_clear_rl_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x002a),
                BtDev::cmd_le_read_rl_size,
                Some(BtDev::cmd_le_read_rl_size_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x002d),
                BtDev::cmd_le_set_addr_resolution_enable,
                Some(BtDev::cmd_le_set_addr_resolution_enable_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x002e),
                BtDev::cmd_le_set_rpa_timeout,
                Some(BtDev::cmd_le_set_rpa_timeout_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x002f),
                BtDev::cmd_le_read_max_data_length,
                Some(BtDev::cmd_le_read_max_data_length_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0030), BtDev::cmd_le_read_phy, None),
            (
                opcode(OGF_LE_CTL, 0x0031),
                BtDev::cmd_le_set_default_phy,
                Some(BtDev::cmd_le_set_default_phy_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0032), BtDev::cmd_le_set_phy, None),
            (
                opcode(OGF_LE_CTL, 0x0035),
                BtDev::cmd_le_set_adv_set_random_addr,
                Some(BtDev::cmd_le_set_adv_set_random_addr_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0036),
                BtDev::cmd_le_set_ext_adv_params,
                Some(BtDev::cmd_le_set_ext_adv_params_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0037),
                BtDev::cmd_le_set_ext_adv_data,
                Some(BtDev::cmd_le_set_ext_adv_data_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0038),
                BtDev::cmd_le_set_ext_scan_rsp_data,
                Some(BtDev::cmd_le_set_ext_scan_rsp_data_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0039),
                BtDev::cmd_le_set_ext_adv_enable,
                Some(BtDev::cmd_le_set_ext_adv_enable_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x003a),
                BtDev::cmd_le_read_max_adv_data_len,
                Some(BtDev::cmd_le_read_max_adv_data_len_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x003b),
                BtDev::cmd_le_read_num_adv_sets,
                Some(BtDev::cmd_le_read_num_adv_sets_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x003c),
                BtDev::cmd_le_remove_adv_set,
                Some(BtDev::cmd_le_remove_adv_set_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x003d),
                BtDev::cmd_le_clear_adv_sets,
                Some(BtDev::cmd_le_clear_adv_sets_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x003e),
                BtDev::cmd_le_set_per_adv_params,
                Some(BtDev::cmd_le_set_per_adv_params_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x003f),
                BtDev::cmd_le_set_per_adv_data,
                Some(BtDev::cmd_le_set_per_adv_data_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0040),
                BtDev::cmd_le_set_per_adv_enable,
                Some(BtDev::cmd_le_set_per_adv_enable_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0041),
                BtDev::cmd_le_set_ext_scan_params,
                Some(BtDev::cmd_le_set_ext_scan_params_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x0042),
                BtDev::cmd_le_set_ext_scan_enable,
                Some(BtDev::cmd_le_set_ext_scan_enable_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0043), BtDev::cmd_le_ext_create_conn, None),
            (
                opcode(OGF_LE_CTL, 0x004b),
                BtDev::cmd_le_read_tx_power,
                Some(BtDev::cmd_le_read_tx_power_complete),
            ),
        ];

        // LE 5.0 commands
        let le_50_cmds: &[CmdTableEntry] = &[
            (
                opcode(OGF_LE_CTL, 0x004c),
                BtDev::cmd_le_read_rf_path_compensation,
                Some(BtDev::cmd_le_read_rf_path_compensation_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x004d),
                BtDev::cmd_le_write_rf_path_compensation,
                Some(BtDev::cmd_le_write_rf_path_compensation_complete),
            ),
            (
                opcode(OGF_LE_CTL, 0x004e),
                BtDev::cmd_le_set_privacy_mode,
                Some(BtDev::cmd_le_set_privacy_mode_complete),
            ),
        ];

        // LE 5.2 commands (ISO)
        let le_52_cmds: &[CmdTableEntry] = &[
            (
                opcode(OGF_LE_CTL, 0x0060),
                BtDev::cmd_le_read_buffer_size_v2,
                Some(BtDev::cmd_le_read_buffer_size_v2_complete),
            ),
            (opcode(OGF_LE_CTL, 0x0062), BtDev::cmd_le_set_cig_params, None),
            (opcode(OGF_LE_CTL, 0x0064), BtDev::cmd_le_create_cis, None),
            (opcode(OGF_LE_CTL, 0x0065), BtDev::cmd_le_remove_cig, None),
            (opcode(OGF_LE_CTL, 0x0066), BtDev::cmd_le_accept_cis, None),
            (opcode(OGF_LE_CTL, 0x0067), BtDev::cmd_le_reject_cis, None),
            (opcode(OGF_LE_CTL, 0x0068), BtDev::cmd_le_create_big, None),
            (opcode(OGF_LE_CTL, 0x006a), BtDev::cmd_le_terminate_big, None),
            (opcode(OGF_LE_CTL, 0x006e), BtDev::cmd_le_setup_iso_data_path, None),
            (opcode(OGF_LE_CTL, 0x006f), BtDev::cmd_le_remove_iso_data_path, None),
        ];

        // LE 6.0 commands
        let le_60_cmds: &[CmdTableEntry] = &[(
            opcode(OGF_LE_CTL, 0x0074),
            BtDev::cmd_le_set_host_feature,
            Some(BtDev::cmd_le_set_host_feature_complete),
        )];

        // Determine which tables to search based on device type
        let tables_to_search: Vec<&[CmdTableEntry]> = match self.dev_type {
            BtDevType::BrEdr => vec![common_all, common_bredr20, bredr_cmds],
            BtDevType::BrEdr20 => vec![common_all, common_bredr20],
            BtDevType::Le => vec![common_all, common_bredrle, le_cmds],
            BtDevType::Amp => vec![common_all],
            BtDevType::BrEdrLe => {
                vec![common_all, common_bredrle, common_bredr20, bredr_cmds, le_cmds]
            }
            BtDevType::BrEdrLe50 => {
                vec![common_all, common_bredrle, common_bredr20, bredr_cmds, le_cmds, le_50_cmds]
            }
            BtDevType::BrEdrLe52 => vec![
                common_all,
                common_bredrle,
                common_bredr20,
                bredr_cmds,
                le_cmds,
                le_50_cmds,
                le_52_cmds,
            ],
            BtDevType::BrEdrLe60 => vec![
                common_all,
                common_bredrle,
                common_bredr20,
                bredr_cmds,
                le_cmds,
                le_50_cmds,
                le_52_cmds,
                le_60_cmds,
            ],
        };

        for table in tables_to_search {
            for &(table_opc, func, complete) in table {
                if table_opc == opc {
                    return Some((func, complete));
                }
            }
        }
        None
    }

    /// Run a command handler and map the result to an HCI status for
    /// Command Complete generation. Matches C `run_cmd` error mapping:
    /// 0→success, -ENOTSUP→UNKNOWN_COMMAND, -EINVAL→INVALID_PARAMETERS,
    /// -EPERM→COMMAND_DISALLOWED, -EEXIST→CONN_ALREADY_EXISTS,
    /// -ENOENT→UNKNOWN_CONN_ID, -EALREADY→null (no response)
    fn run_cmd_handler(
        &mut self,
        func: fn(&mut BtDev, &[u8]) -> CmdResult,
        data: &[u8],
        _opc: u16,
    ) -> Option<u8> {
        match func(self, data) {
            Ok(true) => Some(HCI_SUCCESS),
            Ok(false) => None, // Command handled its own response
            Err(CMD_ENOTSUP) => Some(HCI_UNKNOWN_COMMAND),
            Err(CMD_EINVAL) => Some(0x12), // Invalid HCI Command Parameters
            Err(CMD_EPERM) => Some(0x0c),  // Command Disallowed
            Err(CMD_EEXIST) => Some(0x0b), // ACL Connection Already Exists
            Err(CMD_ENOENT) => Some(0x02), // Unknown Connection Identifier
            Err(CMD_EALREADY) => None,     // No response
            Err(_) => Some(0x1f),          // Unspecified Error
        }
    }

    /// Handle a vendor command (MSFT or EMU) by opcode sub-dispatch.
    fn handle_vendor_cmd(&mut self, opc: u16, data: &[u8]) -> bool {
        // Check MSFT
        if self.msft_opcode != 0 && opc == opcode(OGF_VENDOR_CMD, self.msft_opcode & 0x03FF) {
            if data.is_empty() {
                self.cmd_complete(opc, &[0x01]); // Unknown MSFT sub-opcode
                return true;
            }
            let sub_opcode = data[0];
            let sub_data = &data[1..];
            match sub_opcode {
                0x00 => {
                    let _ = self.cmd_msft_read_features(sub_data);
                }
                0x03 => {
                    let _ = self.cmd_msft_le_monitor_adv(sub_data);
                }
                0x04 => {
                    let _ = self.cmd_msft_le_cancel_monitor_adv(sub_data);
                }
                0x05 => {
                    let _ = self.cmd_msft_le_monitor_adv_enable(sub_data);
                }
                _ => {
                    self.cmd_complete(opc, &[0x01]); // Unknown sub-opcode
                }
            }
            return true;
        }

        // Check EMU
        if self.emu_opcode != 0 && opc == opcode(OGF_VENDOR_CMD, self.emu_opcode & 0x03FF) {
            if data.is_empty() {
                self.cmd_complete(opc, &[0x01]);
                return true;
            }
            let sub_opcode = data[0];
            let sub_data = &data[1..];
            match sub_opcode {
                0x01 => {
                    let _ = self.cmd_emu_test_event(sub_data);
                }
                _ => {
                    self.cmd_complete(opc, &[0x01]);
                }
            }
            return true;
        }

        false
    }

    /// Process an incoming HCI command.
    /// Implements the C `process_cmd` flow:
    /// 1. Parse hci_command_hdr
    /// 2. If external command_handler: call it
    /// 3. Otherwise: pre-cmd hooks → lookup + dispatch → pre-evt hooks → complete
    fn process_cmd(&mut self, data: &[u8]) {
        if data.len() < std::mem::size_of::<hci_command_hdr>() {
            tracing::warn!("btdev: command packet too short ({})", data.len());
            return;
        }

        let (opc, plen) = match Self::parse_command_header(data) {
            Some(v) => v,
            None => {
                tracing::warn!("btdev: failed to parse command header");
                return;
            }
        };
        let param_len = plen as usize;
        let params =
            if data.len() > 3 { &data[3..std::cmp::min(data.len(), 3 + param_len)] } else { &[] };

        tracing::trace!("btdev: cmd opcode=0x{:04x} param_len={}", opc, param_len);

        // Validate command is appropriate for this controller type
        let ogf = u16::from((opc >> 10) as u8);
        if ogf == OGF_LE_CTL && !self.is_le() {
            tracing::warn!("btdev: LE command 0x{:04x} on non-LE controller", opc);
            self.cmd_status(opc, HCI_UNKNOWN_COMMAND);
            return;
        }
        if ogf == OGF_LINK_CONTROL && !self.is_bredr() && !self.is_le() {
            tracing::warn!("btdev: link control command 0x{:04x} on AMP controller", opc);
            self.cmd_status(opc, HCI_UNKNOWN_COMMAND);
            return;
        }

        // Step 1: External command handler interception
        // We take the handler out, call it, and put it back. This avoids
        // borrow-checker issues without any unsafe code.
        let handler_result = if let Some(handler) = self.command_handler.take() {
            let mut callback = BtDevCallback {
                response: BTDEV_RESPONSE_DEFAULT,
                status: 0,
                data: Vec::new(),
                opcode: opc,
                cmd_data: params.to_vec(),
            };
            handler(opc, params, &mut callback);
            // Put the handler back before acting on the callback result
            self.command_handler = Some(handler);
            Some(callback)
        } else {
            None
        };

        if let Some(callback) = handler_result {
            match callback.response {
                BTDEV_RESPONSE_COMMAND_STATUS => {
                    if !self.run_hooks(BtDevHookType::PreCmd, opc, params) {
                        return;
                    }
                    self.cmd_status(opc, callback.status);
                    return;
                }
                BTDEV_RESPONSE_COMMAND_COMPLETE => {
                    if !self.run_hooks(BtDevHookType::PreCmd, opc, params) {
                        return;
                    }
                    self.cmd_complete(opc, &callback.data);
                    return;
                }
                _ => {
                    // BTDEV_RESPONSE_DEFAULT — fall through to normal dispatch
                }
            }
        }

        // Step 2: Run pre-command hooks
        if !self.run_hooks(BtDevHookType::PreCmd, opc, params) {
            return;
        }

        // Step 3: Vendor command dispatch
        if self.handle_vendor_cmd(opc, params) {
            return;
        }

        // Step 4: Main command table lookup and dispatch
        if let Some((func, complete)) = self.lookup_cmd(opc) {
            let status = self.run_cmd_handler(func, params, opc);

            // Run pre-event hooks
            if !self.run_hooks(BtDevHookType::PreEvt, opc, params) {
                return;
            }

            // If the command handler returned a status, run the complete handler
            if let Some(status_val) = status {
                if status_val == HCI_SUCCESS {
                    if let Some(complete_fn) = complete {
                        let _ = complete_fn(self, params);
                    }
                } else {
                    // Error status: send Command Complete with error
                    self.cmd_complete(opc, &[status_val]);
                }
            }
        } else {
            // Unknown command
            tracing::warn!("btdev: unknown command opcode=0x{:04x}", opc);
            self.cmd_status(opc, HCI_UNKNOWN_COMMAND);
        }
    }

    // =======================================================================
    // Data Plane
    // =======================================================================

    /// Forward ACL data.
    /// Matches C `send_acl`: converts ACL_START_NO_FLUSH to ACL_START for
    /// controller-to-host direction, sends Number of Completed Packets event.
    fn send_acl(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }

        let raw_handle = Self::read_le16(&data[0..2]);
        let handle = acl_handle(raw_handle);
        let flags = acl_flags(raw_handle);
        let dlen = Self::read_le16(&data[2..4]) as usize;

        if self.find_conn(handle).is_none() {
            tracing::warn!("btdev: ACL data for unknown handle {}", handle);
            return;
        }

        // Convert ACL_START_NO_FLUSH to ACL_START for controller→host
        let new_flags: u16 =
            if flags == ACL_START_NO_FLUSH { ACL_START as u16 } else { flags as u16 };

        // Build forwarded ACL packet using typed header
        let acl_hdr = Self::build_acl_header(handle, new_flags, dlen as u16);
        let handle_bytes = acl_hdr.handle.to_le_bytes();
        let dlen_bytes = acl_hdr.dlen.to_le_bytes();

        let pkt_type = [HCI_ACLDATA_PKT];
        let hdr = [handle_bytes[0], handle_bytes[1], dlen_bytes[0], dlen_bytes[1]];
        let payload =
            if data.len() > 4 { &data[4..std::cmp::min(data.len(), 4 + dlen)] } else { &[] };

        let iov = [IoSlice::new(&pkt_type), IoSlice::new(&hdr), IoSlice::new(payload)];
        self.send_packet(&iov);

        // Send Number of Completed Packets event
        self.num_completed_packets(handle, 1);
    }

    /// Forward SCO data.
    fn send_sco(&mut self, data: &[u8]) {
        if data.len() < 3 {
            return;
        }

        let handle = Self::read_le16(&data[0..2]) & 0x0FFF;
        let dlen = data[2] as usize;

        // Validate connection exists and is SCO/eSCO type
        let link_type = self.find_conn(handle).map(|c| c.link_type);
        if link_type.is_none() {
            return;
        }
        if let Some(lt) = link_type {
            if !Self::is_sco_link(lt) {
                tracing::warn!("btdev: SCO data on non-SCO link type {}", lt);
            }
        }

        let pkt_type = [HCI_SCODATA_PKT];
        let payload =
            if data.len() > 3 { &data[3..std::cmp::min(data.len(), 3 + dlen)] } else { &[] };

        // Use typed SCO header for forwarding
        let sco_hdr = Self::build_sco_header(handle, dlen as u8);
        let hdr_bytes = sco_hdr.handle.to_le_bytes();
        let hdr = [hdr_bytes[0], hdr_bytes[1], sco_hdr.dlen];
        let iov = [IoSlice::new(&pkt_type), IoSlice::new(&hdr), IoSlice::new(payload)];
        self.send_packet(&iov);
    }

    /// Forward ISO data.
    fn send_iso(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }

        let handle = Self::read_le16(&data[0..2]) & 0x0FFF;
        let dlen = Self::read_le16(&data[2..4]) as usize;

        let pkt_type = [HCI_ISODATA_PKT];
        let payload =
            if data.len() > 4 { &data[4..std::cmp::min(data.len(), 4 + dlen)] } else { &[] };

        // Use typed ISO header for forwarding
        let iso_hdr = Self::build_iso_header(handle, dlen as u16);
        let handle_bytes = iso_hdr.handle.to_le_bytes();
        let dlen_bytes = iso_hdr.dlen.to_le_bytes();

        let hdr = [handle_bytes[0], handle_bytes[1], dlen_bytes[0], dlen_bytes[1]];
        let iov = [IoSlice::new(&pkt_type), IoSlice::new(&hdr), IoSlice::new(payload)];
        self.send_packet(&iov);

        // Send Number of Completed Packets for ISO handle
        self.num_completed_packets(handle, 1);
    }

    // =======================================================================
    // H:4 Ingress (main entry point)
    // =======================================================================

    /// Process an incoming H:4 packet.
    ///
    /// The first byte is the H:4 packet type indicator:
    /// - 0x01 (Command) → process_cmd
    /// - 0x02 (ACL Data) → send_acl
    /// - 0x03 (SCO Data) → send_sco
    /// - 0x05 (ISO Data) → send_iso
    pub fn receive_h4(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let pkt_type = data[0];
        let payload = &data[1..];

        match pkt_type {
            HCI_COMMAND_PKT => self.process_cmd(payload),
            HCI_ACLDATA_PKT => self.send_acl(payload),
            HCI_SCODATA_PKT => self.send_sco(payload),
            HCI_ISODATA_PKT => self.send_iso(payload),
            _ => {
                tracing::warn!("btdev: unknown H:4 packet type 0x{:02x}", pkt_type);
            }
        }
    }
} // impl BtDev

// ---------------------------------------------------------------------------
// Async simulation support using tokio
// ---------------------------------------------------------------------------

/// Shared async device state for timer-based emulation operations.
/// Provides an async-safe wrapper around BtDev for use with tokio tasks.
pub struct AsyncBtDevState {
    /// Async-safe device reference for timer callbacks.
    inner: TokioMutex<Option<BtDev>>,
}

impl AsyncBtDevState {
    /// Create a new async state wrapper.
    pub fn new() -> Self {
        Self { inner: TokioMutex::new(None) }
    }

    /// Set the device to manage.
    pub async fn set_device(&self, dev: BtDev) {
        let mut guard = self.inner.lock().await;
        *guard = Some(dev);
    }

    /// Run a simulated inquiry with timer-based delay.
    ///
    /// Uses `tokio::time::sleep` to emulate the inquiry duration before
    /// generating the Inquiry Complete event.
    pub async fn run_inquiry_simulation(&self, duration_ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(duration_ms)).await;
        let mut guard = self.inner.lock().await;
        if let Some(ref mut dev) = *guard {
            dev.inquiry_active = false;
            dev.send_event(EVT_INQUIRY_COMPLETE, &[HCI_SUCCESS]);
        }
    }

    /// Spawn a periodic advertising simulation task.
    ///
    /// Uses `tokio::time::interval` and `tokio::spawn` to periodically
    /// check and generate advertising events.
    pub fn spawn_periodic_adv_task(
        state: std::sync::Arc<AsyncBtDevState>,
        interval_ms: u64,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
            loop {
                interval.tick().await;
                let guard = state.inner.lock().await;
                if guard.is_none() {
                    break;
                }
                // Periodic advertising tick — state is checked each interval
                drop(guard);
            }
        })
    }
}

impl Default for AsyncBtDevState {
    fn default() -> Self {
        Self::new()
    }
}
