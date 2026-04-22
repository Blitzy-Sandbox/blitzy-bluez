//! SDP record database — in-memory repository with access control and garbage collection.
//!
//! This module is a Rust rewrite of `src/sdpd-database.c` (record store, access
//! control, handle allocation, per-socket GC) and `src/sdpd-service.c` (built-in
//! record registration, MPS feature calculation, timestamp management, and
//! PDU-level registration helpers).
//!
//! The database stores SDP service records keyed by 32-bit handles using a
//! `BTreeMap` (naturally sorted, replacing the C sorted linked list). Access
//! control tracks which Bluetooth adapter address registered each record. A
//! socket-index enables garbage collection of records when a Unix-socket client
//! disconnects.

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, error, warn};

use bluez_shared::sys::bluetooth::{BDADDR_ANY, BdAddr};

use super::xml::{SdpData, SdpRecord};
use crate::log::{btd_debug, btd_error};

// ---------------------------------------------------------------------------
// SDP attribute IDs
// ---------------------------------------------------------------------------

/// Service record handle attribute.
pub const SDP_ATTR_RECORD_HANDLE: u16 = 0x0000;
/// Service class ID list attribute.
pub const SDP_ATTR_SVCLASS_ID_LIST: u16 = 0x0001;
/// Service database state attribute.
pub const SDP_ATTR_SVCDB_STATE: u16 = 0x0002;
/// Protocol descriptor list attribute.
pub const SDP_ATTR_PROTO_DESC_LIST: u16 = 0x0004;
/// Browse group list attribute.
pub const SDP_ATTR_BROWSE_GRP_LIST: u16 = 0x0005;
/// Language base attribute ID list.
pub const SDP_ATTR_LANG_BASE_ATTR_ID_LIST: u16 = 0x0006;
/// Bluetooth profile descriptor list attribute.
pub const SDP_ATTR_PFILE_DESC_LIST: u16 = 0x0009;
/// Group ID / Version number list / Specification ID (context-dependent).
pub const SDP_ATTR_GROUP_ID: u16 = 0x0200;
/// Vendor ID attribute (PnP).
pub const SDP_ATTR_VENDOR_ID: u16 = 0x0201;
/// Product ID attribute (PnP).
pub const SDP_ATTR_PRODUCT_ID: u16 = 0x0202;
/// Version attribute (PnP).
pub const SDP_ATTR_VERSION: u16 = 0x0203;
/// Primary record attribute (PnP).
pub const SDP_ATTR_PRIMARY_RECORD: u16 = 0x0204;
/// Vendor ID source attribute (PnP).
pub const SDP_ATTR_VENDOR_ID_SOURCE: u16 = 0x0205;
/// MPSD scenarios attribute (MPS).
const SDP_ATTR_MPSD_SCENARIOS: u16 = 0x0200;
/// MPMD scenarios attribute (MPS).
const SDP_ATTR_MPMD_SCENARIOS: u16 = 0x0201;
/// Supported profiles dependencies attribute (MPS).
const SDP_ATTR_MPS_DEPENDENCIES: u16 = 0x0202;
/// Service name offset from language base.
const SDP_ATTR_SVCNAME_PRIMARY: u16 = 0x0100;

// ---------------------------------------------------------------------------
// SDP service class UUIDs
// ---------------------------------------------------------------------------

/// SDP server service class UUID.
pub const SDP_SERVER_SVCLASS_ID: u16 = 0x1000;
/// Browse group descriptor service class UUID.
pub const BROWSE_GRP_DESC_SVCLASS_ID: u16 = 0x1001;
/// Public browse group UUID.
pub const PUBLIC_BROWSE_GROUP: u16 = 0x1002;
/// PnP Information service class UUID.
pub const PNP_INFO_SVCLASS_ID: u16 = 0x1200;
/// PnP Information profile UUID.
const PNP_INFO_PROFILE_ID: u16 = 0x1200;
/// Multi Profile Specification service class UUID.
pub const MPS_SVCLASS_ID: u16 = 0x113A;
/// Multi Profile Specification profile UUID.
const MPS_PROFILE_ID: u16 = 0x113A;
/// L2CAP protocol UUID.
pub const L2CAP_UUID: u16 = 0x0100;
/// SDP protocol UUID.
const SDP_UUID: u16 = 0x0001;

// Service class UUIDs used by MPS feature calculation.
const HANDSFREE_AGW_SVCLASS_ID: u16 = 0x111F;
const HANDSFREE_SVCLASS_ID: u16 = 0x111E;
const AUDIO_SOURCE_SVCLASS_ID: u16 = 0x110A;
const AUDIO_SINK_SVCLASS_ID: u16 = 0x110B;
const AV_REMOTE_SVCLASS_ID: u16 = 0x110E;
const AV_REMOTE_TARGET_SVCLASS_ID: u16 = 0x110C;
const DIALUP_NET_SVCLASS_ID: u16 = 0x1103;
const NAP_SVCLASS_ID: u16 = 0x1116;
const PANU_SVCLASS_ID: u16 = 0x1115;
const PBAP_PSE_SVCLASS_ID: u16 = 0x112F;
const PBAP_PCE_SVCLASS_ID: u16 = 0x112E;

// ---------------------------------------------------------------------------
// SDP record handle / server constants
// ---------------------------------------------------------------------------

/// Reserved handle for the SDP server record itself.
pub const SDP_SERVER_RECORD_HANDLE: u32 = 0x0000_0000;
/// First user-allocatable handle.
const FIRST_USER_HANDLE: u32 = 0x0001_0000;
/// Sentinel indicating "allocate a new handle".
pub const SDP_HANDLE_ALLOC: u32 = 0xFFFF_FFFF;
/// SDP PSM for L2CAP.
pub const SDP_PSM: u16 = 0x0001;
/// Enable backward-compatible L2CAP PSM attribute.
pub const SDP_SERVER_FLAG_COMPAT: u32 = 1 << 0;
/// Force central (master) role on L2CAP connections.
pub const SDP_SERVER_FLAG_CENTRAL: u32 = 1 << 1;
/// Persistent record flag — record survives socket disconnect.
pub const SDP_SERVER_FLAG_PERSISTENT: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// MPSD bitmask constants (Multi Profile Single Device)
// ---------------------------------------------------------------------------
const MPSD_AON_HFP_AG_AVRCP: u64 = 1 << 0;
const MPSD_AON_HFP_AG_ACS: u64 = 1 << 1;
const MPSD_AON_HFP_AG_AVRCP_ACS: u64 = 1 << 2;
const MPSD_AON_HFP_HF_ACS: u64 = 1 << 3;
const MPSD_AON_HFP_AG_A2DP_SRC: u64 = 1 << 4;
const MPSD_AON_HFP_AG_A2DP_SRC_AVRCP: u64 = 1 << 5;
const MPSD_AON_HFP_HF_A2DP_SNK: u64 = 1 << 6;
const MPSD_AON_HFP_AG_DUN: u64 = 1 << 7;
const MPSD_AON_HFP_AG_A2DP_SRC_DUN: u64 = 1 << 8;
const MPSD_AON_HFP_AG_A2DP_SRC_DUN_AVRCP: u64 = 1 << 9;
const MPSD_AON_HFP_AG_DUN_AVRCP: u64 = 1 << 10;
const MPSD_AON_A2DP_SRC_AVRCP: u64 = 1 << 11;
const MPSD_AON_HFP_HF_A2DP_SNK_AVRCP: u64 = 1 << 12;
const MPSD_AON_A2DP_SNK_AVRCP: u64 = 1 << 13;
const MPSD_AON_HFP_HF_AVRCP: u64 = 1 << 14;
const MPSD_AON_HFP_AG_PAN_NAP: u64 = 1 << 15;
const MPSD_AON_HFP_HF_PAN_PANU: u64 = 1 << 16;
const MPSD_AON_A2DP_SRC_PAN_NAP: u64 = 1 << 17;
const MPSD_AON_A2DP_SNK_PAN_PANU: u64 = 1 << 18;
const MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP: u64 = 1 << 19;
const MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU: u64 = 1 << 20;
const MPSD_AON_HFP_AG_PAN_NAP_AVRCP: u64 = 1 << 21;
const MPSD_AON_HFP_HF_PAN_PANU_AVRCP: u64 = 1 << 22;
const MPSD_AON_A2DP_SRC_PAN_NAP_AVRCP: u64 = 1 << 23;
const MPSD_AON_A2DP_SNK_PAN_PANU_AVRCP: u64 = 1 << 24;
const MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP_AVRCP: u64 = 1 << 25;
const MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU_AVRCP: u64 = 1 << 26;
const MPSD_AON_DUN_PAN_NAP: u64 = 1 << 27;
const MPSD_AON_DUN_PAN_PANU: u64 = 1 << 28;
const MPSD_AON_A2DP_SRC_PBAP_SERVER: u64 = 1 << 29;
const MPSD_AON_A2DP_SNK_PBAP_CLI: u64 = 1 << 30;
const MPSD_AON_HFP_AG_A2DP_SRC_PBAP_SERVER: u64 = 1u64 << 31;
const MPSD_AON_HFP_HF_A2DP_SNK_PBAP_CLI: u64 = 1u64 << 32;
const MPSD_AON_HFP_AG_PBAP_SERVER: u64 = 1u64 << 33;
const MPSD_AON_HFP_HF_PBAP_CLI: u64 = 1u64 << 34;
const MPSD_AON_HFP_AG_A2DP_AVRCP_PBAP: u64 = 1u64 << 35;
const MPSD_AON_HFP_HF_A2DP_AVRCP_PBAP: u64 = 1u64 << 36;
const MPSD_AON_DUN_DT: u64 = 1u64 << 37;

// ---------------------------------------------------------------------------
// MPMD bitmask constants (Multi Profile Multi Device)
// ---------------------------------------------------------------------------
const MPMD_AON_HFP_AG_AVRCP: u64 = 1 << 0;
const MPMD_AON_HFP_AG_A2DP_SRC: u64 = 1 << 1;
const MPMD_AON_HFP_AG_A2DP_SRC_AVRCP: u64 = 1 << 2;
const MPMD_AON_HFP_HF_A2DP_SNK: u64 = 1 << 3;
const MPMD_AON_HFP_HF_AVRCP: u64 = 1 << 4;
const MPMD_AON_HFP_HF_A2DP_SNK_AVRCP: u64 = 1 << 5;
const MPMD_AON_A2DP_SRC_AVRCP: u64 = 1 << 6;
const MPMD_AON_A2DP_SNK_AVRCP: u64 = 1 << 7;
const MPMD_AON_HFP_AG_PAN_NAP: u64 = 1 << 8;
const MPMD_AON_HFP_HF_PAN_PANU: u64 = 1 << 9;
const MPMD_AON_A2DP_SRC_PAN_NAP: u64 = 1 << 10;
const MPMD_AON_A2DP_SNK_PAN_PANU: u64 = 1 << 11;
const MPMD_AON_A2DP_SRC_PBAP_SERVER: u64 = 1 << 12;
const MPMD_AON_A2DP_SNK_PBAP_CLI: u64 = 1 << 13;
const MPMD_AON_HFP_AG_PBAP_SERVER: u64 = 1 << 14;
const MPMD_AON_HFP_HF_PBAP_CLI: u64 = 1 << 15;
const MPMD_AON_AVRCP_CT_A2DP_SNK: u64 = 1 << 16;
const MPMD_AON_DUN_DT: u64 = 1 << 17;
const MPMD_AON_AVRCP_CT_ONLY: u64 = 1 << 18;

// ---------------------------------------------------------------------------
// MPSD aggregate masks — per-profile feature sets
// ---------------------------------------------------------------------------

const MPS_MPSD_HFP_AG: u64 = MPSD_AON_HFP_AG_AVRCP
    | MPSD_AON_HFP_AG_ACS
    | MPSD_AON_HFP_AG_AVRCP_ACS
    | MPSD_AON_HFP_AG_A2DP_SRC
    | MPSD_AON_HFP_AG_A2DP_SRC_AVRCP
    | MPSD_AON_HFP_AG_DUN
    | MPSD_AON_HFP_AG_A2DP_SRC_DUN
    | MPSD_AON_HFP_AG_A2DP_SRC_DUN_AVRCP
    | MPSD_AON_HFP_AG_DUN_AVRCP
    | MPSD_AON_HFP_AG_PAN_NAP
    | MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP
    | MPSD_AON_HFP_AG_PAN_NAP_AVRCP
    | MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP_AVRCP
    | MPSD_AON_HFP_AG_A2DP_SRC_PBAP_SERVER
    | MPSD_AON_HFP_AG_PBAP_SERVER
    | MPSD_AON_HFP_AG_A2DP_AVRCP_PBAP;

const MPS_MPSD_HFP_HF: u64 = MPSD_AON_HFP_HF_ACS
    | MPSD_AON_HFP_HF_A2DP_SNK
    | MPSD_AON_HFP_HF_A2DP_SNK_AVRCP
    | MPSD_AON_HFP_HF_AVRCP
    | MPSD_AON_HFP_HF_PAN_PANU
    | MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU
    | MPSD_AON_HFP_HF_PAN_PANU_AVRCP
    | MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU_AVRCP
    | MPSD_AON_HFP_HF_A2DP_SNK_PBAP_CLI
    | MPSD_AON_HFP_HF_PBAP_CLI
    | MPSD_AON_HFP_HF_A2DP_AVRCP_PBAP;

const MPS_MPSD_A2DP_SRC: u64 = MPSD_AON_HFP_AG_A2DP_SRC
    | MPSD_AON_HFP_AG_A2DP_SRC_AVRCP
    | MPSD_AON_HFP_AG_A2DP_SRC_DUN
    | MPSD_AON_HFP_AG_A2DP_SRC_DUN_AVRCP
    | MPSD_AON_A2DP_SRC_AVRCP
    | MPSD_AON_A2DP_SRC_PAN_NAP
    | MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP
    | MPSD_AON_A2DP_SRC_PAN_NAP_AVRCP
    | MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP_AVRCP
    | MPSD_AON_A2DP_SRC_PBAP_SERVER
    | MPSD_AON_HFP_AG_A2DP_SRC_PBAP_SERVER
    | MPSD_AON_HFP_AG_A2DP_AVRCP_PBAP;

const MPS_MPSD_A2DP_SNK: u64 = MPSD_AON_HFP_HF_A2DP_SNK
    | MPSD_AON_HFP_HF_A2DP_SNK_AVRCP
    | MPSD_AON_A2DP_SNK_AVRCP
    | MPSD_AON_A2DP_SNK_PAN_PANU
    | MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU
    | MPSD_AON_A2DP_SNK_PAN_PANU_AVRCP
    | MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU_AVRCP
    | MPSD_AON_A2DP_SNK_PBAP_CLI
    | MPSD_AON_HFP_HF_A2DP_SNK_PBAP_CLI
    | MPSD_AON_HFP_HF_A2DP_AVRCP_PBAP;

const MPS_MPSD_AVRCP_CT: u64 = MPS_MPSD_A2DP_SNK;
const MPS_MPSD_AVRCP_TG: u64 = MPS_MPSD_A2DP_SRC;

const MPS_MPSD_DUN_GW: u64 = MPSD_AON_HFP_AG_DUN
    | MPSD_AON_HFP_AG_A2DP_SRC_DUN
    | MPSD_AON_HFP_AG_A2DP_SRC_DUN_AVRCP
    | MPSD_AON_HFP_AG_DUN_AVRCP
    | MPSD_AON_DUN_PAN_NAP
    | MPSD_AON_DUN_PAN_PANU;

const MPS_MPSD_DUN_DT: u64 = MPSD_AON_DUN_DT;

const MPS_MPSD_PAN_NAP: u64 = MPSD_AON_HFP_AG_PAN_NAP
    | MPSD_AON_A2DP_SRC_PAN_NAP
    | MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP
    | MPSD_AON_HFP_AG_PAN_NAP_AVRCP
    | MPSD_AON_A2DP_SRC_PAN_NAP_AVRCP
    | MPSD_AON_HFP_AG_A2DP_SRC_PAN_NAP_AVRCP
    | MPSD_AON_DUN_PAN_NAP;

const MPS_MPSD_PAN_PANU: u64 = MPSD_AON_HFP_HF_PAN_PANU
    | MPSD_AON_A2DP_SNK_PAN_PANU
    | MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU
    | MPSD_AON_HFP_HF_PAN_PANU_AVRCP
    | MPSD_AON_A2DP_SNK_PAN_PANU_AVRCP
    | MPSD_AON_HFP_HF_A2DP_SNK_PAN_PANU_AVRCP
    | MPSD_AON_DUN_PAN_PANU;

const MPS_MPSD_PBAP_SRC: u64 = MPSD_AON_A2DP_SRC_PBAP_SERVER
    | MPSD_AON_HFP_AG_A2DP_SRC_PBAP_SERVER
    | MPSD_AON_HFP_AG_PBAP_SERVER
    | MPSD_AON_HFP_AG_A2DP_AVRCP_PBAP;

const MPS_MPSD_PBAP_CLI: u64 = MPSD_AON_A2DP_SNK_PBAP_CLI
    | MPSD_AON_HFP_HF_A2DP_SNK_PBAP_CLI
    | MPSD_AON_HFP_HF_PBAP_CLI
    | MPSD_AON_HFP_HF_A2DP_AVRCP_PBAP;

const MPS_MPSD_ALL: u64 = (1u64 << 38) - 1;

// ---------------------------------------------------------------------------
// MPMD aggregate masks — per-profile feature sets
// ---------------------------------------------------------------------------

const MPS_MPMD_HFP_AG: u64 = MPMD_AON_HFP_AG_AVRCP
    | MPMD_AON_HFP_AG_A2DP_SRC
    | MPMD_AON_HFP_AG_A2DP_SRC_AVRCP
    | MPMD_AON_HFP_AG_PAN_NAP
    | MPMD_AON_HFP_AG_PBAP_SERVER;

const MPS_MPMD_HFP_HF: u64 = MPMD_AON_HFP_HF_A2DP_SNK
    | MPMD_AON_HFP_HF_AVRCP
    | MPMD_AON_HFP_HF_A2DP_SNK_AVRCP
    | MPMD_AON_HFP_HF_PAN_PANU
    | MPMD_AON_HFP_HF_PBAP_CLI;

const MPS_MPMD_A2DP_SRC: u64 = MPMD_AON_HFP_AG_A2DP_SRC
    | MPMD_AON_HFP_AG_A2DP_SRC_AVRCP
    | MPMD_AON_A2DP_SRC_AVRCP
    | MPMD_AON_A2DP_SRC_PAN_NAP
    | MPMD_AON_A2DP_SRC_PBAP_SERVER;

const MPS_MPMD_A2DP_SNK: u64 = MPMD_AON_HFP_HF_A2DP_SNK
    | MPMD_AON_HFP_HF_A2DP_SNK_AVRCP
    | MPMD_AON_A2DP_SNK_AVRCP
    | MPMD_AON_A2DP_SNK_PAN_PANU
    | MPMD_AON_A2DP_SNK_PBAP_CLI;

const MPS_MPMD_AVRCP_CT: u64 = MPS_MPMD_A2DP_SNK | MPMD_AON_AVRCP_CT_A2DP_SNK;
const MPS_MPMD_AVRCP_CT_ONLY: u64 = MPMD_AON_AVRCP_CT_ONLY;
const MPS_MPMD_AVRCP_TG: u64 = MPS_MPMD_A2DP_SRC;
const MPS_MPMD_DUN_DT: u64 = MPMD_AON_DUN_DT;
const MPS_MPMD_ALL: u64 = (1u64 << 19) - 1;

/// Default MPS dependency bits value.
const MPS_DEFAULT_DEPS: u16 = 0x0001;

// ---------------------------------------------------------------------------
// Internal data structures
// ---------------------------------------------------------------------------

/// Access control entry tracking which adapter address registered a record.
///
/// The handle is implicit — it is the key in the `BTreeMap<u32, AccessEntry>`.
#[derive(Debug, Clone)]
struct AccessEntry {
    device: BdAddr,
}

/// Socket-to-record mapping for per-socket garbage collection.
#[derive(Debug, Clone)]
struct SocketIndex {
    sock: RawFd,
    handle: u32,
}

// ---------------------------------------------------------------------------
// SdpDatabase
// ---------------------------------------------------------------------------

/// In-memory SDP service record database with access control, handle allocation,
/// per-socket garbage collection, and built-in record registration.
pub struct SdpDatabase {
    /// Service records keyed by handle (naturally sorted via `BTreeMap`).
    records: BTreeMap<u32, SdpRecord>,
    /// Access control entries keyed by handle.
    access: BTreeMap<u32, AccessEntry>,
    /// Socket-to-record mappings for garbage collection on disconnect.
    socket_index: Vec<SocketIndex>,
    /// Next user-allocatable handle (starts at `FIRST_USER_HANDLE`).
    next_handle_counter: u32,
    /// Current database modification timestamp (epoch seconds).
    timestamp: u32,
    /// Fixed timestamp override for test determinism (`None` = use real time).
    fixed_timestamp: Option<u32>,
    /// Handle of the SDP server record (for DB-state attribute updates).
    server_handle: Option<u32>,
    /// Handle of the current MPS record (if registered).
    mps_handle: Option<u32>,
    /// Whether the MPS record was registered in MPMD mode.
    mps_mpmd: bool,
}

impl Default for SdpDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl SdpDatabase {
    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// Create a new, empty SDP database.
    pub fn new() -> Self {
        let ts = current_epoch_secs();
        Self {
            records: BTreeMap::new(),
            access: BTreeMap::new(),
            socket_index: Vec::new(),
            next_handle_counter: FIRST_USER_HANDLE,
            timestamp: ts,
            fixed_timestamp: None,
            server_handle: None,
            mps_handle: None,
            mps_mpmd: false,
        }
    }

    // -----------------------------------------------------------------------
    // Record CRUD
    // -----------------------------------------------------------------------

    /// Insert a record into the database and create an access control entry.
    ///
    /// The record's `handle` field must already be set. An access entry mapping
    /// `(src, handle)` is created to track which adapter registered the record.
    pub fn add_record(&mut self, src: &BdAddr, record: SdpRecord) {
        let handle = record.handle;
        debug!("adding record handle 0x{:08x}", handle);
        btd_debug(0, &format!("sdp: add record 0x{handle:08x}"));

        self.records.insert(handle, record);
        self.access.insert(handle, AccessEntry { device: *src });
        self.update_timestamp();
    }

    /// Look up a record by handle (immutable reference).
    pub fn find_record(&self, handle: u32) -> Option<&SdpRecord> {
        self.records.get(&handle)
    }

    /// Look up a record by handle (mutable reference).
    pub fn find_record_mut(&mut self, handle: u32) -> Option<&mut SdpRecord> {
        self.records.get_mut(&handle)
    }

    /// Remove a record by handle and return it (if found).
    ///
    /// Also removes the corresponding access entry. The caller is responsible
    /// for cleaning up any socket-index references via [`collect`].
    pub fn remove_record(&mut self, handle: u32) -> Option<SdpRecord> {
        let rec = self.records.remove(&handle);
        if rec.is_some() {
            debug!("removing record handle 0x{:08x}", handle);
            btd_debug(0, &format!("sdp: remove record 0x{handle:08x}"));
            self.access.remove(&handle);
            self.update_timestamp();
        } else {
            error!("record handle 0x{:08x} not found for removal", handle);
            btd_error(0, &format!("sdp: remove record 0x{handle:08x} not found"));
        }
        rec
    }

    /// Return a sorted list of all record handles in the database.
    pub fn get_record_list(&self) -> Vec<u32> {
        self.records.keys().copied().collect()
    }

    /// Check whether `src` is allowed to access the record with `handle`.
    ///
    /// Returns `true` if:
    /// - No access entry exists for the handle (unrestricted), or
    /// - The access entry's device matches `src`, or
    /// - Either the access entry's device or `src` is `BDADDR_ANY`.
    pub fn check_access(&self, handle: u32, src: &BdAddr) -> bool {
        let entry = match self.access.get(&handle) {
            Some(e) => e,
            None => {
                // No access restriction — allow.
                return true;
            }
        };

        if entry.device == *src {
            return true;
        }
        if entry.device == BDADDR_ANY || *src == BDADDR_ANY {
            return true;
        }

        warn!("access denied for handle 0x{:08x}", handle);
        btd_debug(0, &format!("sdp: access denied for handle 0x{handle:08x}"));
        false
    }

    /// Allocate and return the next available record handle.
    ///
    /// Handles start at `0x10000` and increment, skipping any handle already
    /// present in the database (matching the C `sdp_next_handle` behaviour).
    pub fn next_handle(&mut self) -> u32 {
        let mut handle = self.next_handle_counter;
        while self.records.contains_key(&handle) {
            handle = handle.wrapping_add(1);
            if handle < FIRST_USER_HANDLE {
                handle = FIRST_USER_HANDLE;
            }
        }
        self.next_handle_counter = handle.wrapping_add(1);
        if self.next_handle_counter < FIRST_USER_HANDLE {
            self.next_handle_counter = FIRST_USER_HANDLE;
        }
        debug!("allocated handle 0x{:08x}", handle);
        btd_debug(0, &format!("sdp: allocated handle 0x{handle:08x}"));
        handle
    }

    // -----------------------------------------------------------------------
    // Per-socket garbage collection
    // -----------------------------------------------------------------------

    /// Mark a record as owned by the given socket for garbage collection.
    ///
    /// When the socket disconnects, all records marked with its fd will be
    /// automatically removed via [`collect_all`].
    pub fn set_collectable(&mut self, handle: u32, sock: RawFd) {
        debug!("set_collectable: handle 0x{:08x} -> sock {}", handle, sock);
        btd_debug(0, &format!("sdp: collectable 0x{handle:08x} sock {sock}"));
        self.socket_index.push(SocketIndex { sock, handle });
    }

    /// Remove all records owned by `sock` and return them.
    ///
    /// Called when a Unix-socket client disconnects to garbage-collect any
    /// records it registered.
    pub fn collect_all(&mut self, sock: RawFd) -> Vec<SdpRecord> {
        // Gather handles belonging to this socket.
        let handles: Vec<u32> =
            self.socket_index.iter().filter(|si| si.sock == sock).map(|si| si.handle).collect();

        if handles.is_empty() {
            return Vec::new();
        }

        debug!("collect_all: sock {} has {} records", sock, handles.len());
        btd_debug(0, &format!("sdp: collect_all sock {sock} count {}", handles.len()));

        // Remove socket index entries for this socket.
        self.socket_index.retain(|si| si.sock != sock);

        // Remove records and access entries, collecting removed records.
        let mut removed = Vec::with_capacity(handles.len());
        for h in handles {
            if let Some(rec) = self.records.remove(&h) {
                self.access.remove(&h);
                removed.push(rec);
            }
        }

        if !removed.is_empty() {
            self.update_timestamp();
        }
        removed
    }

    /// Remove the socket-index entry for a specific record handle.
    ///
    /// Called when a record is explicitly removed (not via GC) to clean up
    /// the socket-index so it does not reference a stale handle.
    pub fn collect(&mut self, handle: u32) {
        self.socket_index.retain(|si| si.handle != handle);
    }

    // -----------------------------------------------------------------------
    // Database reset
    // -----------------------------------------------------------------------

    /// Clear the entire database: all records, access entries, and socket-index.
    ///
    /// Resets the handle counter to its initial value.
    pub fn reset(&mut self) {
        debug!("resetting SDP database");
        btd_debug(0, "sdp: database reset");
        self.records.clear();
        self.access.clear();
        self.socket_index.clear();
        self.next_handle_counter = FIRST_USER_HANDLE;
        self.server_handle = None;
        self.mps_handle = None;
        self.mps_mpmd = false;
        self.update_timestamp();
    }

    // -----------------------------------------------------------------------
    // Timestamp management
    // -----------------------------------------------------------------------

    /// Return the current database timestamp.
    ///
    /// If a fixed timestamp has been set (for testing), that value is returned;
    /// otherwise the current wall-clock epoch seconds are used.
    pub fn get_time(&self) -> u32 {
        self.fixed_timestamp.unwrap_or_else(current_epoch_secs)
    }

    /// Set a fixed timestamp for test determinism.
    ///
    /// Pass a non-zero value to lock the timestamp; `0` is also a valid fixed
    /// value. Use `update_timestamp` afterwards if a DB-state update is desired.
    pub fn set_fixed_timestamp(&mut self, ts: u32) {
        self.fixed_timestamp = Some(ts);
        debug!("fixed timestamp set to {}", ts);
        btd_debug(0, &format!("sdp: fixed timestamp {ts}"));
    }

    /// Update the database modification timestamp.
    ///
    /// If a server record is registered, updates the `SDP_ATTR_SVCDB_STATE`
    /// attribute on that record (matching the C `update_db_timestamp`).
    pub fn update_timestamp(&mut self) {
        let ts = self.get_time();
        self.timestamp = ts;

        // Update the SDP_ATTR_SVCDB_STATE on the server record if present.
        if let Some(handle) = self.server_handle {
            if let Some(rec) = self.records.get_mut(&handle) {
                rec.attrs.insert(SDP_ATTR_SVCDB_STATE, SdpData::UInt32(ts));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Built-in record registration
    // -----------------------------------------------------------------------

    /// Register the public browse group record.
    ///
    /// Creates a record with handle `SDP_SERVER_RECORD_HANDLE + 1` containing
    /// the browse group descriptor service class and the public browse group ID.
    pub fn register_public_browse_group(&mut self) {
        let handle = SDP_SERVER_RECORD_HANDLE + 1;
        let mut rec = SdpRecord::new(handle);

        // SDP_ATTR_RECORD_HANDLE
        rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));

        // Service class ID list: BROWSE_GRP_DESC_SVCLASS_ID
        rec.attrs.insert(
            SDP_ATTR_SVCLASS_ID_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(BROWSE_GRP_DESC_SVCLASS_ID)]),
        );

        // Browse group list: PUBLIC_BROWSE_GROUP
        rec.attrs.insert(
            SDP_ATTR_BROWSE_GRP_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
        );

        // Group ID: PUBLIC_BROWSE_GROUP
        rec.attrs.insert(SDP_ATTR_GROUP_ID, SdpData::Uuid16(PUBLIC_BROWSE_GROUP));

        debug!("registering public browse group (handle 0x{:08x})", handle);
        btd_debug(0, &format!("sdp: register browse group 0x{handle:08x}"));
        self.records.insert(handle, rec);
        self.access.insert(handle, AccessEntry { device: BDADDR_ANY });
    }

    /// Register the SDP server service record.
    ///
    /// Creates a record with handle `SDP_SERVER_RECORD_HANDLE` containing the
    /// SDP server service class, L2CAP protocol descriptor (PSM 1), and version
    /// information. If `compat` is true, an L2CAP PSM attribute is included
    /// for backward compatibility with older clients.
    pub fn register_server_service(&mut self, compat: bool) {
        let handle = SDP_SERVER_RECORD_HANDLE;
        let mut rec = SdpRecord::new(handle);

        // SDP_ATTR_RECORD_HANDLE
        rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));

        // Service class ID list: SDP_SERVER_SVCLASS_ID
        rec.attrs.insert(
            SDP_ATTR_SVCLASS_ID_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(SDP_SERVER_SVCLASS_ID)]),
        );

        // Browse group list: PUBLIC_BROWSE_GROUP
        rec.attrs.insert(
            SDP_ATTR_BROWSE_GRP_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
        );

        // Protocol descriptor list: L2CAP(PSM=1) → SDP
        rec.attrs.insert(
            SDP_ATTR_PROTO_DESC_LIST,
            SdpData::Sequence(vec![
                SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(SDP_PSM)]),
                SdpData::Sequence(vec![SdpData::Uuid16(SDP_UUID)]),
            ]),
        );

        // Profile descriptor list: SDP version 1.0
        rec.attrs.insert(
            SDP_ATTR_PFILE_DESC_LIST,
            SdpData::Sequence(vec![SdpData::Sequence(vec![
                SdpData::Uuid16(SDP_SERVER_SVCLASS_ID),
                SdpData::UInt16(0x0100), // version 1.0
            ])]),
        );

        // Version number list (attribute 0x0200): [1, 0]
        rec.attrs.insert(
            SDP_ATTR_GROUP_ID, // 0x0200 used as version number list for SDP server
            SdpData::Sequence(vec![SdpData::UInt16(0x0100)]),
        );

        // SDP_ATTR_SVCDB_STATE — initial timestamp
        let ts = self.get_time();
        rec.attrs.insert(SDP_ATTR_SVCDB_STATE, SdpData::UInt32(ts));

        // Compat: add L2CAP PSM as a separate attribute for older clients.
        if compat {
            rec.attrs.insert(SDP_ATTR_GOEP_L2CAP_PSM, SdpData::UInt16(SDP_PSM));
        }

        debug!("registering server service (handle 0x{:08x}, compat={})", handle, compat);
        btd_debug(0, &format!("sdp: register server service 0x{handle:08x}"));

        self.server_handle = Some(handle);
        self.records.insert(handle, rec);
        self.access.insert(handle, AccessEntry { device: BDADDR_ANY });
    }

    /// Register a PnP Device Identification record.
    ///
    /// Creates a record with the PNP_INFO service class and the supplied
    /// vendor/product/version identification attributes.
    pub fn register_device_id(&mut self, source: u16, vendor: u16, product: u16, version: u16) {
        let handle = self.next_handle();
        let mut rec = SdpRecord::new(handle);

        // SDP_ATTR_RECORD_HANDLE
        rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));

        // Service class ID list: PNP_INFO_SVCLASS_ID
        rec.attrs.insert(
            SDP_ATTR_SVCLASS_ID_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(PNP_INFO_SVCLASS_ID)]),
        );

        // Browse group list: PUBLIC_BROWSE_GROUP
        rec.attrs.insert(
            SDP_ATTR_BROWSE_GRP_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
        );

        // Profile descriptor list: PnP Information 1.3
        rec.attrs.insert(
            SDP_ATTR_PFILE_DESC_LIST,
            SdpData::Sequence(vec![SdpData::Sequence(vec![
                SdpData::Uuid16(PNP_INFO_PROFILE_ID),
                SdpData::UInt16(0x0103), // version 1.3
            ])]),
        );

        // PnP-specific attributes (0x0200 – 0x0205)
        // 0x0200: SpecificationID = 0x0103 (Bluetooth SIG)
        rec.attrs.insert(0x0200, SdpData::UInt16(0x0103));
        // 0x0201: VendorID
        rec.attrs.insert(SDP_ATTR_VENDOR_ID, SdpData::UInt16(vendor));
        // 0x0202: ProductID
        rec.attrs.insert(SDP_ATTR_PRODUCT_ID, SdpData::UInt16(product));
        // 0x0203: Version
        rec.attrs.insert(SDP_ATTR_VERSION, SdpData::UInt16(version));
        // 0x0204: PrimaryRecord = true
        rec.attrs.insert(SDP_ATTR_PRIMARY_RECORD, SdpData::Bool(true));
        // 0x0205: VendorIDSource
        rec.attrs.insert(SDP_ATTR_VENDOR_ID_SOURCE, SdpData::UInt16(source));

        debug!(
            "registering device ID: source={}, vendor=0x{:04x}, product=0x{:04x}, version=0x{:04x}, handle=0x{:08x}",
            source, vendor, product, version, handle
        );
        btd_debug(0, &format!("sdp: register device ID 0x{handle:08x}"));

        self.records.insert(handle, rec);
        self.access.insert(handle, AccessEntry { device: BDADDR_ANY });
        self.update_timestamp();
    }

    /// Register or update the Multi Profile Specification (MPS) record.
    ///
    /// Dynamically calculates MPSD and MPMD feature bitmasks based on the
    /// currently registered service classes, then creates (or replaces) an MPS
    /// record in the database.
    pub fn register_mps(&mut self, mpmd: bool) {
        let mpsd_features = mps_mpsd_features(self);
        let mpmd_features = if mpmd { mps_mpmd_features(self) } else { 0 };

        // If an MPS record already exists, update its attributes in place.
        if let Some(mps_handle) = self.mps_handle {
            if let Some(rec) = self.records.get_mut(&mps_handle) {
                rec.attrs.insert(SDP_ATTR_MPSD_SCENARIOS, SdpData::UInt64(mpsd_features));
                if mpmd {
                    rec.attrs.insert(SDP_ATTR_MPMD_SCENARIOS, SdpData::UInt64(mpmd_features));
                }
                debug!("updated MPS record 0x{:08x}", mps_handle);
                btd_debug(0, &format!("sdp: updated MPS 0x{mps_handle:08x}"));
                self.mps_mpmd = mpmd;
                self.update_timestamp();
                return;
            }
        }

        // Create new MPS record.
        let handle = self.next_handle();
        let mut rec = SdpRecord::new(handle);

        rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));

        // Service class
        rec.attrs.insert(
            SDP_ATTR_SVCLASS_ID_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(MPS_SVCLASS_ID)]),
        );

        // Browse group
        rec.attrs.insert(
            SDP_ATTR_BROWSE_GRP_LIST,
            SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
        );

        // Profile descriptor: MPS version 1.0
        rec.attrs.insert(
            SDP_ATTR_PFILE_DESC_LIST,
            SdpData::Sequence(vec![SdpData::Sequence(vec![
                SdpData::Uuid16(MPS_PROFILE_ID),
                SdpData::UInt16(0x0100),
            ])]),
        );

        // MPSD features
        rec.attrs.insert(SDP_ATTR_MPSD_SCENARIOS, SdpData::UInt64(mpsd_features));

        // MPMD features (if applicable)
        if mpmd {
            rec.attrs.insert(SDP_ATTR_MPMD_SCENARIOS, SdpData::UInt64(mpmd_features));
        }

        // Dependencies
        rec.attrs.insert(SDP_ATTR_MPS_DEPENDENCIES, SdpData::UInt16(MPS_DEFAULT_DEPS));

        // Service name
        rec.attrs.insert(SDP_ATTR_SVCNAME_PRIMARY, SdpData::Text(b"Multi Profile".to_vec()));

        debug!("registering MPS record (handle 0x{:08x}, mpmd={})", handle, mpmd);
        btd_debug(0, &format!("sdp: register MPS 0x{handle:08x}"));

        self.mps_handle = Some(handle);
        self.mps_mpmd = mpmd;
        self.records.insert(handle, rec);
        self.access.insert(handle, AccessEntry { device: BDADDR_ANY });
        self.update_timestamp();
    }
}

// ---------------------------------------------------------------------------
// Free-standing helper: current epoch seconds
// ---------------------------------------------------------------------------

/// Return the current wall-clock time as Unix epoch seconds (u32).
fn current_epoch_secs() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// MPS feature calculation helpers
// ---------------------------------------------------------------------------

/// Check whether any record in the database has the given service class UUID
/// in its `SDP_ATTR_SVCLASS_ID_LIST`.
fn class_supported(db: &SdpDatabase, uuid16: u16) -> bool {
    for rec in db.records.values() {
        if let Some(SdpData::Sequence(items)) = rec.attrs.get(&SDP_ATTR_SVCLASS_ID_LIST) {
            for item in items {
                if let SdpData::Uuid16(u) = item {
                    if *u == uuid16 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Calculate the MPSD (Multi Profile Single Device) feature bitmask from the
/// set of currently registered services in the database.
///
/// Starts with all features enabled and clears bits for unsupported profiles,
/// matching the C `mps_mpsd_features()` logic.
fn mps_mpsd_features(db: &SdpDatabase) -> u64 {
    let mut features = MPS_MPSD_ALL;

    if !class_supported(db, HANDSFREE_AGW_SVCLASS_ID) {
        features &= !MPS_MPSD_HFP_AG;
    }
    if !class_supported(db, HANDSFREE_SVCLASS_ID) {
        features &= !MPS_MPSD_HFP_HF;
    }
    if !class_supported(db, AUDIO_SOURCE_SVCLASS_ID) {
        features &= !MPS_MPSD_A2DP_SRC;
    }
    if !class_supported(db, AUDIO_SINK_SVCLASS_ID) {
        features &= !MPS_MPSD_A2DP_SNK;
    }
    if !class_supported(db, AV_REMOTE_SVCLASS_ID) {
        features &= !MPS_MPSD_AVRCP_CT;
    }
    if !class_supported(db, AV_REMOTE_TARGET_SVCLASS_ID) {
        features &= !MPS_MPSD_AVRCP_TG;
    }
    if !class_supported(db, DIALUP_NET_SVCLASS_ID) {
        features &= !MPS_MPSD_DUN_GW;
    }
    if !class_supported(db, NAP_SVCLASS_ID) {
        features &= !MPS_MPSD_PAN_NAP;
    }
    if !class_supported(db, PANU_SVCLASS_ID) {
        features &= !MPS_MPSD_PAN_PANU;
    }
    if !class_supported(db, PBAP_PSE_SVCLASS_ID) {
        features &= !MPS_MPSD_PBAP_SRC;
    }
    if !class_supported(db, PBAP_PCE_SVCLASS_ID) {
        features &= !MPS_MPSD_PBAP_CLI;
    }

    // DUN DT always cleared (matching C behaviour — TODO-upstream).
    features &= !MPS_MPSD_DUN_DT;

    debug!("mpsd_features: 0x{:016x}", features);
    features
}

/// Calculate the MPMD (Multi Profile Multi Device) feature bitmask from the
/// set of currently registered services in the database.
///
/// Starts with all features enabled and clears bits for unsupported profiles.
/// Special AVRCP_CT_ONLY logic: the bit is cleared when A2DP Sink is supported.
fn mps_mpmd_features(db: &SdpDatabase) -> u64 {
    let mut features = MPS_MPMD_ALL;

    if !class_supported(db, HANDSFREE_AGW_SVCLASS_ID) {
        features &= !MPS_MPMD_HFP_AG;
    }
    if !class_supported(db, HANDSFREE_SVCLASS_ID) {
        features &= !MPS_MPMD_HFP_HF;
    }
    if !class_supported(db, AUDIO_SOURCE_SVCLASS_ID) {
        features &= !MPS_MPMD_A2DP_SRC;
    }
    if !class_supported(db, AUDIO_SINK_SVCLASS_ID) {
        features &= !MPS_MPMD_A2DP_SNK;
    }
    if !class_supported(db, AV_REMOTE_SVCLASS_ID) {
        features &= !MPS_MPMD_AVRCP_CT;
    }
    if !class_supported(db, AV_REMOTE_TARGET_SVCLASS_ID) {
        features &= !MPS_MPMD_AVRCP_TG;
    }

    // Special AVRCP_CT_ONLY logic: cleared when A2DP Sink IS supported.
    if class_supported(db, AUDIO_SINK_SVCLASS_ID) {
        features &= !MPS_MPMD_AVRCP_CT_ONLY;
    }

    // DUN DT always cleared (matching C behaviour).
    features &= !MPS_MPMD_DUN_DT;

    debug!("mpmd_features: 0x{:016x}", features);
    features
}

// ---------------------------------------------------------------------------
// Public API — high-level record management
// ---------------------------------------------------------------------------

/// Add a record to the SDP server database.
///
/// If `rec.handle` is `SDP_HANDLE_ALLOC` (0xFFFFFFFF), a new handle is
/// automatically allocated. Otherwise the caller-specified handle is used
/// (after checking for duplicates).
///
/// On success the record's handle is assigned and the record is inserted
/// into the database. The MPS record is updated if applicable.
///
/// Returns `Ok(handle)` on success, or `Err(msg)` if the handle is already
/// in use.
pub fn add_record_to_server(
    db: &mut SdpDatabase,
    src: &BdAddr,
    rec: &mut SdpRecord,
) -> Result<u32, String> {
    // Allocate handle if requested.
    if rec.handle == SDP_HANDLE_ALLOC {
        rec.handle = db.next_handle();
    } else if db.records.contains_key(&rec.handle) {
        let msg = format!("handle 0x{:08x} already in use", rec.handle);
        error!("{}", msg);
        btd_error(0, &format!("sdp: {msg}"));
        return Err(msg);
    }

    let handle = rec.handle;

    // Ensure record handle attribute is set.
    rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));

    // Add PUBLIC_BROWSE_GROUP to browse group list if absent.
    rec.attrs
        .entry(SDP_ATTR_BROWSE_GRP_LIST)
        .or_insert_with(|| SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]));

    db.add_record(src, rec.clone());

    // Update MPS record if one is registered.
    if db.mps_handle.is_some() {
        let mpmd = db.mps_mpmd;
        db.register_mps(mpmd);
    }

    Ok(handle)
}

/// Remove a record from the SDP server database by handle.
///
/// Refuses to remove the SDP server record (`SDP_SERVER_RECORD_HANDLE`).
/// Cleans up the socket-index entry and updates the MPS record.
///
/// Returns the removed record on success, or `Err(msg)` if the record was
/// not found or removal is not permitted.
pub fn remove_record_from_server(db: &mut SdpDatabase, handle: u32) -> Result<SdpRecord, String> {
    if handle == SDP_SERVER_RECORD_HANDLE {
        let msg = "cannot remove the SDP server record".to_string();
        error!("{}", msg);
        btd_error(0, &format!("sdp: {msg}"));
        return Err(msg);
    }

    // Clean up socket-index entry.
    db.collect(handle);

    match db.remove_record(handle) {
        Some(rec) => {
            // Update MPS record if one is registered.
            if db.mps_handle.is_some() {
                let mpmd = db.mps_mpmd;
                db.register_mps(mpmd);
            }
            Ok(rec)
        }
        None => {
            let msg = format!("record 0x{:08x} not found", handle);
            Err(msg)
        }
    }
}

// ---------------------------------------------------------------------------
// PDU binary helpers — SDP data element parsing
// ---------------------------------------------------------------------------

/// SDP data type descriptor (upper 5 bits of the header byte).
const SDP_TYPE_NIL: u8 = 0;
const SDP_TYPE_UINT: u8 = 1;
const SDP_TYPE_INT: u8 = 2;
const SDP_TYPE_UUID: u8 = 3;
const SDP_TYPE_TEXT: u8 = 4;
const SDP_TYPE_BOOL: u8 = 5;
const SDP_TYPE_SEQ: u8 = 6;
const SDP_TYPE_ALT: u8 = 7;
const SDP_TYPE_URL: u8 = 8;

/// Parse a single SDP data element from a binary buffer.
///
/// Returns `(element, bytes_consumed)` on success.
fn parse_sdp_data_element(buf: &[u8]) -> Result<(SdpData, usize), String> {
    if buf.is_empty() {
        return Err("empty buffer".into());
    }

    let header = buf[0];
    let dtype = (header >> 3) & 0x1f;
    let sdesc = header & 0x07;
    let mut pos: usize = 1;

    match dtype {
        SDP_TYPE_NIL => Ok((SdpData::Nil, 1)),

        SDP_TYPE_BOOL => {
            if buf.len() < 2 {
                return Err("bool: buffer too short".into());
            }
            Ok((SdpData::Bool(buf[1] != 0), 2))
        }

        SDP_TYPE_UINT => {
            let (val, consumed) = parse_uint_value(&buf[pos..], sdesc)?;
            Ok((val, pos + consumed))
        }

        SDP_TYPE_INT => {
            let (val, consumed) = parse_int_value(&buf[pos..], sdesc)?;
            Ok((val, pos + consumed))
        }

        SDP_TYPE_UUID => {
            let (val, consumed) = parse_uuid_value(&buf[pos..], sdesc)?;
            Ok((val, pos + consumed))
        }

        SDP_TYPE_TEXT => {
            let (data_len, hdr_extra) = parse_var_size(&buf[pos..], sdesc)?;
            pos += hdr_extra;
            if buf.len() < pos + data_len {
                return Err("text: buffer too short".into());
            }
            let text = buf[pos..pos + data_len].to_vec();
            Ok((SdpData::Text(text), pos + data_len))
        }

        SDP_TYPE_URL => {
            let (data_len, hdr_extra) = parse_var_size(&buf[pos..], sdesc)?;
            pos += hdr_extra;
            if buf.len() < pos + data_len {
                return Err("url: buffer too short".into());
            }
            let url = String::from_utf8_lossy(&buf[pos..pos + data_len]).into_owned();
            Ok((SdpData::Url(url), pos + data_len))
        }

        SDP_TYPE_SEQ | SDP_TYPE_ALT => {
            let (data_len, hdr_extra) = parse_var_size(&buf[pos..], sdesc)?;
            pos += hdr_extra;
            if buf.len() < pos + data_len {
                return Err("seq/alt: buffer too short".into());
            }
            let seq_buf = &buf[pos..pos + data_len];
            let mut items = Vec::new();
            let mut off = 0;
            while off < seq_buf.len() {
                let (item, consumed) = parse_sdp_data_element(&seq_buf[off..])?;
                items.push(item);
                off += consumed;
            }
            let elem = if dtype == SDP_TYPE_SEQ {
                SdpData::Sequence(items)
            } else {
                SdpData::Alternate(items)
            };
            Ok((elem, pos + data_len))
        }

        _ => Err(format!("unknown SDP data type {dtype}")),
    }
}

/// Parse an unsigned integer value given its size descriptor.
fn parse_uint_value(buf: &[u8], sdesc: u8) -> Result<(SdpData, usize), String> {
    match sdesc {
        0 => {
            if buf.is_empty() {
                return Err("uint8: buffer too short".into());
            }
            Ok((SdpData::UInt8(buf[0]), 1))
        }
        1 => {
            if buf.len() < 2 {
                return Err("uint16: buffer too short".into());
            }
            let v = u16::from_be_bytes([buf[0], buf[1]]);
            Ok((SdpData::UInt16(v), 2))
        }
        2 => {
            if buf.len() < 4 {
                return Err("uint32: buffer too short".into());
            }
            let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Ok((SdpData::UInt32(v), 4))
        }
        3 => {
            if buf.len() < 8 {
                return Err("uint64: buffer too short".into());
            }
            let v = u64::from_be_bytes(buf[..8].try_into().unwrap());
            Ok((SdpData::UInt64(v), 8))
        }
        4 => {
            if buf.len() < 16 {
                return Err("uint128: buffer too short".into());
            }
            let mut v = [0u8; 16];
            v.copy_from_slice(&buf[..16]);
            Ok((SdpData::UInt128(v), 16))
        }
        _ => Err(format!("uint: invalid size desc {sdesc}")),
    }
}

/// Parse a signed integer value given its size descriptor.
fn parse_int_value(buf: &[u8], sdesc: u8) -> Result<(SdpData, usize), String> {
    match sdesc {
        0 => {
            if buf.is_empty() {
                return Err("int8: buffer too short".into());
            }
            Ok((SdpData::Int8(buf[0] as i8), 1))
        }
        1 => {
            if buf.len() < 2 {
                return Err("int16: buffer too short".into());
            }
            let v = i16::from_be_bytes([buf[0], buf[1]]);
            Ok((SdpData::Int16(v), 2))
        }
        2 => {
            if buf.len() < 4 {
                return Err("int32: buffer too short".into());
            }
            let v = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Ok((SdpData::Int32(v), 4))
        }
        3 => {
            if buf.len() < 8 {
                return Err("int64: buffer too short".into());
            }
            let v = i64::from_be_bytes(buf[..8].try_into().unwrap());
            Ok((SdpData::Int64(v), 8))
        }
        4 => {
            if buf.len() < 16 {
                return Err("int128: buffer too short".into());
            }
            let mut v = [0u8; 16];
            v.copy_from_slice(&buf[..16]);
            Ok((SdpData::Int128(v), 16))
        }
        _ => Err(format!("int: invalid size desc {sdesc}")),
    }
}

/// Parse a UUID value given its size descriptor.
fn parse_uuid_value(buf: &[u8], sdesc: u8) -> Result<(SdpData, usize), String> {
    match sdesc {
        1 => {
            if buf.len() < 2 {
                return Err("uuid16: buffer too short".into());
            }
            let v = u16::from_be_bytes([buf[0], buf[1]]);
            Ok((SdpData::Uuid16(v), 2))
        }
        2 => {
            if buf.len() < 4 {
                return Err("uuid32: buffer too short".into());
            }
            let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Ok((SdpData::Uuid32(v), 4))
        }
        4 => {
            if buf.len() < 16 {
                return Err("uuid128: buffer too short".into());
            }
            let mut v = [0u8; 16];
            v.copy_from_slice(&buf[..16]);
            Ok((SdpData::Uuid128(v), 16))
        }
        _ => Err(format!("uuid: invalid size desc {sdesc}")),
    }
}

/// Parse a variable-length size from the buffer based on the size descriptor.
///
/// Returns `(data_length, header_bytes_consumed)`.
fn parse_var_size(buf: &[u8], sdesc: u8) -> Result<(usize, usize), String> {
    match sdesc {
        5 => {
            if buf.is_empty() {
                return Err("var size 8: buffer too short".into());
            }
            Ok((buf[0] as usize, 1))
        }
        6 => {
            if buf.len() < 2 {
                return Err("var size 16: buffer too short".into());
            }
            let v = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            Ok((v, 2))
        }
        7 => {
            if buf.len() < 4 {
                return Err("var size 32: buffer too short".into());
            }
            let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            Ok((v, 4))
        }
        _ => Err(format!("var size: invalid size desc {sdesc}")),
    }
}

/// Encode an SDP data element into its binary (wire format) representation.
fn encode_sdp_data_element(data: &SdpData) -> Vec<u8> {
    match data {
        SdpData::Nil => vec![0x00],
        SdpData::Bool(v) => vec![SDP_TYPE_BOOL << 3, u8::from(*v)],
        SdpData::UInt8(v) => vec![SDP_TYPE_UINT << 3, *v],
        SdpData::UInt16(v) => {
            let mut buf = vec![(SDP_TYPE_UINT << 3) | 1];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::UInt32(v) => {
            let mut buf = vec![(SDP_TYPE_UINT << 3) | 2];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::UInt64(v) => {
            let mut buf = vec![(SDP_TYPE_UINT << 3) | 3];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::UInt128(v) => {
            let mut buf = vec![(SDP_TYPE_UINT << 3) | 4];
            buf.extend_from_slice(v);
            buf
        }
        SdpData::Int8(v) => vec![SDP_TYPE_INT << 3, *v as u8],
        SdpData::Int16(v) => {
            let mut buf = vec![(SDP_TYPE_INT << 3) | 1];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::Int32(v) => {
            let mut buf = vec![(SDP_TYPE_INT << 3) | 2];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::Int64(v) => {
            let mut buf = vec![(SDP_TYPE_INT << 3) | 3];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::Int128(v) => {
            let mut buf = vec![(SDP_TYPE_INT << 3) | 4];
            buf.extend_from_slice(v);
            buf
        }
        SdpData::Uuid16(v) => {
            let mut buf = vec![(SDP_TYPE_UUID << 3) | 1];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::Uuid32(v) => {
            let mut buf = vec![(SDP_TYPE_UUID << 3) | 2];
            buf.extend_from_slice(&v.to_be_bytes());
            buf
        }
        SdpData::Uuid128(v) => {
            let mut buf = vec![(SDP_TYPE_UUID << 3) | 4];
            buf.extend_from_slice(v);
            buf
        }
        SdpData::Text(v) => encode_var_len_data(SDP_TYPE_TEXT, v),
        SdpData::Url(v) => encode_var_len_data(SDP_TYPE_URL, v.as_bytes()),
        SdpData::Sequence(items) => {
            let inner: Vec<u8> = items.iter().flat_map(encode_sdp_data_element).collect();
            encode_var_len_data(SDP_TYPE_SEQ, &inner)
        }
        SdpData::Alternate(items) => {
            let inner: Vec<u8> = items.iter().flat_map(encode_sdp_data_element).collect();
            encode_var_len_data(SDP_TYPE_ALT, &inner)
        }
    }
}

/// Encode variable-length data with an appropriate SDP header byte and size prefix.
fn encode_var_len_data(dtype: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut buf = Vec::with_capacity(5 + len);
    if len <= 0xFF {
        buf.push((dtype << 3) | 5);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push((dtype << 3) | 6);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push((dtype << 3) | 7);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(data);
    buf
}

/// Parse an SDP record from a binary PDU (list of attribute ID / value pairs).
///
/// `handle_expected`: if `SDP_HANDLE_ALLOC`, the handle is read from the first
/// 4 bytes of the PDU; otherwise the supplied value is used and no handle bytes
/// are consumed.
fn extract_pdu_record(buf: &[u8], handle_expected: u32) -> Result<(SdpRecord, usize), String> {
    let mut pos: usize = 0;
    let handle;

    if handle_expected != SDP_HANDLE_ALLOC {
        // Handle is embedded in the PDU.
        if buf.len() < 4 {
            return Err("pdu: too short for handle".into());
        }
        handle = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        pos = 4;
    } else {
        handle = SDP_HANDLE_ALLOC;
    }

    let mut rec = SdpRecord::new(handle);

    // Parse attribute ID / value pairs.
    while pos + 3 <= buf.len() {
        // Read attribute ID (2 bytes, big-endian).
        let attr_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;

        // Parse the attribute value as an SDP data element.
        match parse_sdp_data_element(&buf[pos..]) {
            Ok((data, consumed)) => {
                rec.attrs.insert(attr_id, data);
                pos += consumed;
            }
            Err(e) => {
                warn!("extract_pdu_record: attr 0x{:04x} parse error: {}", attr_id, e);
                break;
            }
        }
    }

    Ok((rec, pos))
}

// ---------------------------------------------------------------------------
// PDU-level registration functions
// ---------------------------------------------------------------------------

/// Process an SDP service register request from binary PDU data.
///
/// Parses the record from the request buffer, allocates a handle, adds the
/// record to the database, and returns a response buffer containing the new
/// handle.
///
/// # Parameters
/// - `db`: The SDP database.
/// - `buf`: Request PDU body (after SDP PDU header).
/// - `device`: Source adapter address of the registering client.
/// - `sock`: Socket file descriptor of the registering client.
/// - `flags`: Request flags (e.g., `SDP_SERVER_FLAG_PERSISTENT`).
///
/// # Returns
/// Response PDU body bytes on success, or an error status.
pub fn service_register_req(
    db: &mut SdpDatabase,
    buf: &[u8],
    device: &BdAddr,
    sock: RawFd,
    flags: u32,
) -> Result<Vec<u8>, u16> {
    if buf.is_empty() {
        error!("service_register_req: empty buffer");
        btd_error(0, "sdp: register req empty buffer");
        return Err(SDP_ERR_INVALID_SYNTAX);
    }

    // First byte is flags/opcode modifier; remaining is the record PDU.
    let _req_flags = buf[0];
    let pdu_data = &buf[1..];

    // Parse the record from the PDU.
    let (mut rec, _scanned) = extract_pdu_record(pdu_data, SDP_HANDLE_ALLOC).map_err(|e| {
        error!("service_register_req: parse error: {}", e);
        btd_error(0, &format!("sdp: register parse error: {e}"));
        SDP_ERR_INVALID_SYNTAX
    })?;

    // Allocate handle.
    rec.handle = db.next_handle();
    rec.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(rec.handle));

    // Add PUBLIC_BROWSE_GROUP if absent.
    rec.attrs
        .entry(SDP_ATTR_BROWSE_GRP_LIST)
        .or_insert_with(|| SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]));

    let handle = rec.handle;
    db.add_record(device, rec);

    // Mark as collectable (GC on socket disconnect) unless persistent.
    if flags & SDP_SERVER_FLAG_PERSISTENT == 0 {
        db.set_collectable(handle, sock);
    }

    // Update MPS record.
    if db.mps_handle.is_some() {
        let mpmd = db.mps_mpmd;
        db.register_mps(mpmd);
    }

    debug!("service_register_req: handle 0x{:08x}", handle);
    btd_debug(0, &format!("sdp: registered 0x{handle:08x}"));

    // Build response: the new handle as a UInt32 data element.
    Ok(encode_sdp_data_element(&SdpData::UInt32(handle)))
}

/// SDP error code for invalid syntax in a PDU.
const SDP_ERR_INVALID_SYNTAX: u16 = 0x0003;
/// SDP error code for an invalid record handle.
const SDP_ERR_INVALID_RECORD_HANDLE: u16 = 0x0002;

/// Process an SDP service update request from binary PDU data.
///
/// Parses the updated record from the request buffer, checks access control,
/// and replaces the existing record's attributes.
///
/// # Parameters
/// - `db`: The SDP database.
/// - `buf`: Request PDU body (after SDP PDU header).
/// - `device`: Source adapter address of the updating client.
///
/// # Returns
/// Empty response on success, or an error status.
pub fn service_update_req(
    db: &mut SdpDatabase,
    buf: &[u8],
    device: &BdAddr,
) -> Result<Vec<u8>, u16> {
    if buf.len() < 4 {
        error!("service_update_req: buffer too short");
        btd_error(0, "sdp: update req buffer too short");
        return Err(SDP_ERR_INVALID_SYNTAX);
    }

    // Parse the handle from the first 4 bytes.
    let handle = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let pdu_data = &buf[4..];

    // Check access.
    if !db.check_access(handle, device) {
        error!("service_update_req: access denied for 0x{:08x}", handle);
        btd_error(0, &format!("sdp: update access denied 0x{handle:08x}"));
        return Err(SDP_ERR_INVALID_RECORD_HANDLE);
    }

    // Find the existing record.
    let existing = match db.find_record_mut(handle) {
        Some(r) => r,
        None => {
            error!("service_update_req: record 0x{:08x} not found", handle);
            btd_error(0, &format!("sdp: update record 0x{handle:08x} not found"));
            return Err(SDP_ERR_INVALID_RECORD_HANDLE);
        }
    };

    // Parse the new record attributes from the PDU.
    let (new_rec, _scanned) = extract_pdu_record(pdu_data, SDP_HANDLE_ALLOC).map_err(|e| {
        error!("service_update_req: parse error: {}", e);
        btd_error(0, &format!("sdp: update parse error: {e}"));
        SDP_ERR_INVALID_SYNTAX
    })?;

    // Replace the existing record's attributes with the new ones, preserving
    // the original handle.
    existing.attrs = new_rec.attrs;
    existing.attrs.insert(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(handle));

    db.update_timestamp();

    debug!("service_update_req: updated 0x{:08x}", handle);
    btd_debug(0, &format!("sdp: updated 0x{handle:08x}"));

    // Empty response body on success.
    Ok(Vec::new())
}

/// Process an SDP service remove request from binary PDU data.
///
/// Parses the record handle from the request buffer, checks access control,
/// and removes the record from the database.
///
/// # Parameters
/// - `db`: The SDP database.
/// - `buf`: Request PDU body (after SDP PDU header).
/// - `device`: Source adapter address of the removing client.
///
/// # Returns
/// Empty response on success, or an error status.
pub fn service_remove_req(
    db: &mut SdpDatabase,
    buf: &[u8],
    device: &BdAddr,
) -> Result<Vec<u8>, u16> {
    if buf.len() < 4 {
        error!("service_remove_req: buffer too short");
        btd_error(0, "sdp: remove req buffer too short");
        return Err(SDP_ERR_INVALID_SYNTAX);
    }

    // Parse the handle from the first 4 bytes.
    let handle = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    // Check access.
    if !db.check_access(handle, device) {
        error!("service_remove_req: access denied for 0x{:08x}", handle);
        btd_error(0, &format!("sdp: remove access denied 0x{handle:08x}"));
        return Err(SDP_ERR_INVALID_RECORD_HANDLE);
    }

    // Clean up socket index.
    db.collect(handle);

    // Remove the record.
    match db.remove_record(handle) {
        Some(_rec) => {
            // Update MPS record.
            if db.mps_handle.is_some() {
                let mpmd = db.mps_mpmd;
                db.register_mps(mpmd);
            }

            debug!("service_remove_req: removed 0x{:08x}", handle);
            btd_debug(0, &format!("sdp: removed 0x{handle:08x}"));

            // Empty response body on success.
            Ok(Vec::new())
        }
        None => {
            error!("service_remove_req: record 0x{:08x} not found", handle);
            btd_error(0, &format!("sdp: remove 0x{handle:08x} not found"));
            Err(SDP_ERR_INVALID_RECORD_HANDLE)
        }
    }
}

// ---------------------------------------------------------------------------
// Constants re-exported for external use (L2CAP PSM compat attribute)
// ---------------------------------------------------------------------------

/// L2CAP PSM attribute value used in compat mode (re-exported for server.rs).
const SDP_ATTR_GOEP_L2CAP_PSM: u16 = 0x0200;

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal SDP record with the given handle and service class.
    fn make_record(handle: u32, svc_class: u16) -> SdpRecord {
        let mut rec = SdpRecord::new(handle);
        rec.attrs
            .insert(SDP_ATTR_SVCLASS_ID_LIST, SdpData::Sequence(vec![SdpData::Uuid16(svc_class)]));
        rec
    }

    #[test]
    fn test_new_database_is_empty() {
        let db = SdpDatabase::new();
        assert!(db.records.is_empty());
        assert!(db.access.is_empty());
        assert!(db.socket_index.is_empty());
        assert_eq!(db.next_handle_counter, FIRST_USER_HANDLE);
    }

    #[test]
    fn test_add_find_remove_record() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        let rec = make_record(0x10000, 0x1234);

        db.add_record(&src, rec);
        assert!(db.find_record(0x10000).is_some());
        assert!(db.find_record(0x99999).is_none());

        let removed = db.remove_record(0x10000);
        assert!(removed.is_some());
        assert!(db.find_record(0x10000).is_none());
    }

    #[test]
    fn test_get_record_list() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        db.add_record(&src, make_record(3, 0x1000));
        db.add_record(&src, make_record(1, 0x1001));
        db.add_record(&src, make_record(2, 0x1002));

        let list = db.get_record_list();
        assert_eq!(list, vec![1, 2, 3]); // BTreeMap ordering
    }

    #[test]
    fn test_check_access() {
        let mut db = SdpDatabase::new();
        let src_a = BdAddr { b: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] };
        let src_b = BdAddr { b: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] };

        db.add_record(&src_a, make_record(100, 0x1234));

        // Same address should succeed.
        assert!(db.check_access(100, &src_a));
        // Different address should fail.
        assert!(!db.check_access(100, &src_b));
        // BDADDR_ANY should always succeed.
        assert!(db.check_access(100, &BDADDR_ANY));
        // Non-existent handle: no access entry → allowed.
        assert!(db.check_access(999, &src_b));
    }

    #[test]
    fn test_handle_allocation() {
        let mut db = SdpDatabase::new();
        let h1 = db.next_handle();
        let h2 = db.next_handle();
        assert_eq!(h1, FIRST_USER_HANDLE);
        assert_eq!(h2, FIRST_USER_HANDLE + 1);
    }

    #[test]
    fn test_handle_allocation_skip_existing() {
        let mut db = SdpDatabase::new();
        // Pre-insert a record at the first user handle.
        db.records.insert(FIRST_USER_HANDLE, SdpRecord::new(FIRST_USER_HANDLE));

        let h = db.next_handle();
        assert_eq!(h, FIRST_USER_HANDLE + 1);
    }

    #[test]
    fn test_socket_gc_collect_all() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;

        db.add_record(&src, make_record(1, 0x1000));
        db.add_record(&src, make_record(2, 0x1001));
        db.add_record(&src, make_record(3, 0x1002));

        // Mark records 1 and 2 as owned by socket 42.
        db.set_collectable(1, 42);
        db.set_collectable(2, 42);
        // Record 3 owned by socket 99.
        db.set_collectable(3, 99);

        // Disconnect socket 42 — should remove records 1 and 2.
        let removed = db.collect_all(42);
        assert_eq!(removed.len(), 2);
        assert!(db.find_record(1).is_none());
        assert!(db.find_record(2).is_none());
        assert!(db.find_record(3).is_some());
    }

    #[test]
    fn test_socket_gc_collect_single() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;

        db.add_record(&src, make_record(1, 0x1000));
        db.set_collectable(1, 42);

        // Remove the single entry.
        db.collect(1);

        // Socket index should be empty; record still exists.
        assert!(db.socket_index.is_empty());
        assert!(db.find_record(1).is_some());
    }

    #[test]
    fn test_reset() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        db.add_record(&src, make_record(1, 0x1000));
        db.set_collectable(1, 42);

        db.reset();

        assert!(db.records.is_empty());
        assert!(db.access.is_empty());
        assert!(db.socket_index.is_empty());
        assert_eq!(db.next_handle_counter, FIRST_USER_HANDLE);
    }

    #[test]
    fn test_timestamp_fixed() {
        let mut db = SdpDatabase::new();
        db.set_fixed_timestamp(12345);
        assert_eq!(db.get_time(), 12345);
    }

    #[test]
    fn test_timestamp_real() {
        let db = SdpDatabase::new();
        let ts = db.get_time();
        // Should be a reasonable epoch timestamp (after 2020-01-01).
        assert!(ts > 1_577_836_800);
    }

    #[test]
    fn test_register_public_browse_group() {
        let mut db = SdpDatabase::new();
        db.register_public_browse_group();

        let handle = SDP_SERVER_RECORD_HANDLE + 1;
        let rec = db.find_record(handle).expect("browse group record");
        assert!(rec.attrs.contains_key(&SDP_ATTR_SVCLASS_ID_LIST));
        assert!(rec.attrs.contains_key(&SDP_ATTR_GROUP_ID));
    }

    #[test]
    fn test_register_server_service() {
        let mut db = SdpDatabase::new();
        db.register_server_service(false);

        let rec = db.find_record(SDP_SERVER_RECORD_HANDLE).expect("server record");
        assert!(rec.attrs.contains_key(&SDP_ATTR_SVCLASS_ID_LIST));
        assert!(rec.attrs.contains_key(&SDP_ATTR_PROTO_DESC_LIST));
        assert!(rec.attrs.contains_key(&SDP_ATTR_SVCDB_STATE));
    }

    #[test]
    fn test_register_server_service_compat() {
        let mut db = SdpDatabase::new();
        db.register_server_service(true);

        let rec = db.find_record(SDP_SERVER_RECORD_HANDLE).expect("server record");
        // Compat mode should have the L2CAP PSM attribute at 0x0200.
        assert!(rec.attrs.contains_key(&SDP_ATTR_GOEP_L2CAP_PSM));
    }

    #[test]
    fn test_register_device_id() {
        let mut db = SdpDatabase::new();
        db.register_device_id(0x0001, 0x1234, 0x5678, 0x0100);

        let list = db.get_record_list();
        assert!(!list.is_empty());

        let handle = list[0];
        let rec = db.find_record(handle).expect("device ID record");
        assert!(rec.attrs.contains_key(&SDP_ATTR_VENDOR_ID));
        assert!(rec.attrs.contains_key(&SDP_ATTR_PRODUCT_ID));

        // Check vendor ID value.
        if let Some(SdpData::UInt16(v)) = rec.attrs.get(&SDP_ATTR_VENDOR_ID) {
            assert_eq!(*v, 0x1234);
        } else {
            panic!("unexpected vendor ID type");
        }
    }

    #[test]
    fn test_register_mps() {
        let mut db = SdpDatabase::new();
        // Register a service so MPS has something to calculate features from.
        let src = BDADDR_ANY;
        db.add_record(&src, make_record(0x20000, AUDIO_SINK_SVCLASS_ID));

        db.register_mps(true);

        assert!(db.mps_handle.is_some());
        let handle = db.mps_handle.unwrap();
        let rec = db.find_record(handle).expect("MPS record");
        assert!(rec.attrs.contains_key(&SDP_ATTR_MPSD_SCENARIOS));
        assert!(rec.attrs.contains_key(&SDP_ATTR_MPMD_SCENARIOS));
    }

    #[test]
    fn test_add_record_to_server() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        let mut rec = make_record(SDP_HANDLE_ALLOC, 0x1234);

        let result = add_record_to_server(&mut db, &src, &mut rec);
        assert!(result.is_ok());
        let handle = result.unwrap();
        assert!(handle >= FIRST_USER_HANDLE);
        assert!(db.find_record(handle).is_some());
    }

    #[test]
    fn test_remove_record_from_server() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        let mut rec = make_record(SDP_HANDLE_ALLOC, 0x1234);

        let handle = add_record_to_server(&mut db, &src, &mut rec).unwrap();
        let result = remove_record_from_server(&mut db, handle);
        assert!(result.is_ok());
        assert!(db.find_record(handle).is_none());
    }

    #[test]
    fn test_remove_server_record_denied() {
        let mut db = SdpDatabase::new();
        db.register_server_service(false);

        let result = remove_record_from_server(&mut db, SDP_SERVER_RECORD_HANDLE);
        assert!(result.is_err());
        assert!(db.find_record(SDP_SERVER_RECORD_HANDLE).is_some());
    }

    #[test]
    fn test_class_supported() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        db.add_record(&src, make_record(1, 0x1234));

        assert!(class_supported(&db, 0x1234));
        assert!(!class_supported(&db, 0x5678));
    }

    #[test]
    fn test_mps_features_no_profiles() {
        let db = SdpDatabase::new();
        // No profiles registered — all bits should be cleared (features depend
        // on supported profiles, so unsupported profiles clear their bits).
        let features = mps_mpsd_features(&db);
        // DUN_DT is always cleared; with no profiles supported, most bits are 0.
        assert_eq!(features & MPS_MPSD_DUN_DT, 0);
    }

    #[test]
    fn test_parse_encode_roundtrip() {
        let data = SdpData::Sequence(vec![
            SdpData::UInt16(0x1234),
            SdpData::Uuid16(0x1000),
            SdpData::Text(b"hello".to_vec()),
        ]);

        let encoded = encode_sdp_data_element(&data);
        let (decoded, consumed) = parse_sdp_data_element(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_service_register_req() {
        let mut db = SdpDatabase::new();
        let device = BDADDR_ANY;

        // Build a minimal register request PDU.
        let mut pdu = Vec::new();
        pdu.push(0x00); // flags byte

        // Encode a simple record: one attribute (svclass ID list).
        let attr_id: u16 = SDP_ATTR_SVCLASS_ID_LIST;
        pdu.extend_from_slice(&attr_id.to_be_bytes());
        let attr_val = encode_sdp_data_element(&SdpData::Sequence(vec![SdpData::Uuid16(0x1234)]));
        pdu.extend_from_slice(&attr_val);

        let result = service_register_req(&mut db, &pdu, &device, 42, 0);
        assert!(result.is_ok());
        // There should now be one record in the DB.
        assert_eq!(db.records.len(), 1);
    }

    #[test]
    fn test_service_remove_req() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        let mut rec = make_record(SDP_HANDLE_ALLOC, 0x1234);
        let handle = add_record_to_server(&mut db, &src, &mut rec).unwrap();

        // Build remove request PDU.
        let pdu = handle.to_be_bytes().to_vec();

        let result = service_remove_req(&mut db, &pdu, &src);
        assert!(result.is_ok());
        assert!(db.find_record(handle).is_none());
    }

    #[test]
    fn test_find_record_mut() {
        let mut db = SdpDatabase::new();
        let src = BDADDR_ANY;
        db.add_record(&src, make_record(1, 0x1000));

        // Mutate the record.
        let rec = db.find_record_mut(1).unwrap();
        rec.attrs.insert(0x9999, SdpData::UInt8(42));

        // Verify mutation persisted.
        let rec = db.find_record(1).unwrap();
        assert_eq!(rec.attrs.get(&0x9999), Some(&SdpData::UInt8(42)));
    }

    #[test]
    fn test_update_timestamp_on_server_record() {
        let mut db = SdpDatabase::new();
        db.set_fixed_timestamp(1000);
        db.register_server_service(false);

        // Server record should have SVCDB_STATE = 1000.
        let rec = db.find_record(SDP_SERVER_RECORD_HANDLE).unwrap();
        if let Some(SdpData::UInt32(v)) = rec.attrs.get(&SDP_ATTR_SVCDB_STATE) {
            assert_eq!(*v, 1000);
        }

        // Change timestamp and trigger update.
        db.set_fixed_timestamp(2000);
        db.update_timestamp();

        let rec = db.find_record(SDP_SERVER_RECORD_HANDLE).unwrap();
        if let Some(SdpData::UInt32(v)) = rec.attrs.get(&SDP_ATTR_SVCDB_STATE) {
            assert_eq!(*v, 2000);
        }
    }
}
