//! Basic Audio Profile (BAP) state machine implementation.
//!
//! Manages PAC (Published Audio Capabilities) records, ASE (Audio Stream Endpoint)
//! lifecycle, codec configuration, QoS configuration, CIS establishment, and
//! broadcast audio for LE Audio.

use std::any::Any;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};

use bitflags::bitflags;
use tokio::time::Duration;
use tracing::{trace, warn};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::att::transport::BtAtt;
use crate::gatt::client::BtGattClient;
use crate::gatt::db::GattDb;
use crate::gatt::server::BtGattServer;
use crate::sys::bluetooth::{
    BT_ISO_QOS_BIG_UNSET, BT_ISO_QOS_BIS_UNSET, BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET,
    BT_ISO_SYNC_FACTOR, BT_ISO_SYNC_TIMEOUT, bt_iso_bcast_qos, bt_iso_io_qos, bt_iso_qos,
    bt_iso_ucast_qos,
};
use crate::util::endian::{get_le16, get_le24, get_le32, ltv_foreach};
use crate::util::uuid::BtUuid;

// ========================================================================
// ASCS Constants and Opcodes
// ========================================================================

/// ASCS Control Point opcode: Codec Configured.
pub const ASCS_CONFIG: u8 = 0x01;
/// ASCS Control Point opcode: QoS Configured.
pub const ASCS_QOS: u8 = 0x02;
/// ASCS Control Point opcode: Enabling.
pub const ASCS_ENABLE: u8 = 0x03;
/// ASCS Control Point opcode: Receiver Start Ready.
pub const ASCS_START: u8 = 0x04;
/// ASCS Control Point opcode: Disabling.
pub const ASCS_DISABLE: u8 = 0x05;
/// ASCS Control Point opcode: Receiver Stop Ready.
pub const ASCS_STOP: u8 = 0x06;
/// ASCS Control Point opcode: Update Metadata.
pub const ASCS_METADATA: u8 = 0x07;
/// ASCS Control Point opcode: Releasing.
pub const ASCS_RELEASE: u8 = 0x08;

/// ASCS QoS packing: Sequential.
pub const ASCS_QOS_PACKING_SEQ: u8 = 0x00;
/// ASCS QoS packing: Interleaved.
pub const ASCS_QOS_PACKING_INT: u8 = 0x01;
/// ASCS QoS framing: Unframed.
pub const ASCS_QOS_FRAMING_UNFRAMED: u8 = 0x00;
/// ASCS QoS framing: Framed.
pub const ASCS_QOS_FRAMING_FRAMED: u8 = 0x01;

/// BAP process timeout in seconds for ASCS Control Point operations.
pub const BAP_PROCESS_TIMEOUT: u64 = 10;
/// Number of sink ASEs per connection.
pub const NUM_SINKS: u8 = 2;
/// Number of source ASEs per connection.
pub const NUM_SOURCE: u8 = 2;
/// Total number of ASEs per connection (sinks + sources).
pub const NUM_ASES: u8 = NUM_SINKS + NUM_SOURCE;

// ASCS config target latency and PHY constants are expressed through
// the `BapConfigLatency` and `BapConfigPhy` public types respectively.

// PACS service/characteristic UUIDs.
const PACS_UUID: u16 = 0x1850;
const PAC_SINK_UUID: u16 = 0x2BC9;
const PAC_SINK_LOC_UUID: u16 = 0x2BCA;
const PAC_SOURCE_UUID: u16 = 0x2BCB;
const PAC_SOURCE_LOC_UUID: u16 = 0x2BCC;
const PAC_AVAIL_CTX_UUID: u16 = 0x2BCD;
const PAC_SUPP_CTX_UUID: u16 = 0x2BCE;

// ASCS service/characteristic UUIDs.
const ASCS_UUID: u16 = 0x184E;
const ASE_SINK_UUID: u16 = 0x2BC4;
const ASE_SOURCE_UUID: u16 = 0x2BC5;
const ASE_CP_UUID: u16 = 0x2BC6;

// ========================================================================
// ASCS Enums
// ========================================================================

/// ASCS response code indicating result of a Control Point operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AscsRspCode {
    Success = 0x00,
    NotSupported = 0x01,
    Truncated = 0x02,
    InvalidAse = 0x03,
    InvalidAseState = 0x04,
    InvalidDir = 0x05,
    CapUnsupported = 0x06,
    ConfUnsupported = 0x07,
    ConfRejected = 0x08,
    ConfInvalid = 0x09,
    MetadataUnsupported = 0x0a,
    MetadataRejected = 0x0b,
    MetadataInvalid = 0x0c,
    NoMem = 0x0d,
    Unspecified = 0x0e,
}

impl AscsRspCode {
    /// Convert from raw u8 wire value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Success),
            0x01 => Some(Self::NotSupported),
            0x02 => Some(Self::Truncated),
            0x03 => Some(Self::InvalidAse),
            0x04 => Some(Self::InvalidAseState),
            0x05 => Some(Self::InvalidDir),
            0x06 => Some(Self::CapUnsupported),
            0x07 => Some(Self::ConfUnsupported),
            0x08 => Some(Self::ConfRejected),
            0x09 => Some(Self::ConfInvalid),
            0x0a => Some(Self::MetadataUnsupported),
            0x0b => Some(Self::MetadataRejected),
            0x0c => Some(Self::MetadataInvalid),
            0x0d => Some(Self::NoMem),
            0x0e => Some(Self::Unspecified),
            _ => None,
        }
    }
}

/// ASCS response reason indicating which parameter caused the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AscsReason {
    None = 0x00,
    Codec = 0x01,
    CodecData = 0x02,
    Interval = 0x03,
    Framing = 0x04,
    Phy = 0x05,
    Sdu = 0x06,
    Rtn = 0x07,
    Latency = 0x08,
    Pd = 0x09,
    Cis = 0x0a,
}

impl AscsReason {
    /// Convert from raw u8 wire value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Codec),
            0x02 => Some(Self::CodecData),
            0x03 => Some(Self::Interval),
            0x04 => Some(Self::Framing),
            0x05 => Some(Self::Phy),
            0x06 => Some(Self::Sdu),
            0x07 => Some(Self::Rtn),
            0x08 => Some(Self::Latency),
            0x09 => Some(Self::Pd),
            0x0a => Some(Self::Cis),
            _ => None,
        }
    }
}

/// ASE (Audio Stream Endpoint) state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AscsAseState {
    Idle = 0x00,
    Config = 0x01,
    Qos = 0x02,
    Enabling = 0x03,
    Streaming = 0x04,
    Disabling = 0x05,
    Releasing = 0x06,
}

impl AscsAseState {
    /// Convert from raw u8 wire value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Idle),
            0x01 => Some(Self::Config),
            0x02 => Some(Self::Qos),
            0x03 => Some(Self::Enabling),
            0x04 => Some(Self::Streaming),
            0x05 => Some(Self::Disabling),
            0x06 => Some(Self::Releasing),
            _ => None,
        }
    }
}

// ========================================================================
// Wire-Format Packed Structures (ASCS)
// ========================================================================

/// BAP Codec identifier (5 bytes, wire format).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    IntoBytes,
    FromBytes,
    Immutable,
    KnownLayout,
    Unaligned,
)]
#[repr(C, packed)]
pub struct BapCodec {
    /// Codec ID (0x00-0x05 standard, 0xFF vendor-specific).
    pub id: u8,
    /// Company ID (valid when id == 0xFF).
    pub cid: u16,
    /// Vendor-specific codec ID (valid when id == 0xFF).
    pub vid: u16,
}

impl BapCodec {
    /// Create a standard codec identifier.
    pub fn new(id: u8) -> Self {
        Self { id, cid: 0, vid: 0 }
    }

    /// Create a vendor-specific codec identifier.
    pub fn new_vendor(id: u8, cid: u16, vid: u16) -> Self {
        Self { id, cid: cid.to_le(), vid: vid.to_le() }
    }
}

/// ASCS ASE response (per-ASE result in Control Point response).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsAseRsp {
    pub ase: u8,
    pub code: u8,
    pub reason: u8,
}

/// ASCS Control Point response header.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsCpRsp {
    pub op: u8,
    pub num_ase: u8,
}

/// ASCS ASE status header (common to all states).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsAseStatus {
    pub id: u8,
    pub state: u8,
}

/// ASCS ASE operation header.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsAseHdr {
    pub op: u8,
    pub num: u8,
}

/// ASCS ASE status for Codec Configured state.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsAseStatusConfig {
    pub framing: u8,
    pub phys: u8,
    pub rtn: u8,
    pub latency: u16,
    pub pd_min: [u8; 3],
    pub pd_max: [u8; 3],
    pub ppd_min: [u8; 3],
    pub ppd_max: [u8; 3],
    pub codec: BapCodec,
    pub cc_len: u8,
}

/// ASCS ASE status for QoS Configured state.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsAseStatusQos {
    pub cig_id: u8,
    pub cis_id: u8,
    pub interval: [u8; 3],
    pub framing: u8,
    pub phys: u8,
    pub sdu: u16,
    pub rtn: u8,
    pub latency: u16,
    pub pd: [u8; 3],
}

/// ASCS ASE status for Enabling/Streaming/Disabling states.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsAseStatusMetadata {
    pub cig_id: u8,
    pub cis_id: u8,
    pub len: u8,
}

/// ASCS Config Codec operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsConfig {
    pub ase: u8,
    pub latency: u8,
    pub phy: u8,
    pub codec: BapCodec,
    pub cc_len: u8,
}

/// ASCS QoS Config operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsQos {
    pub ase: u8,
    pub cig: u8,
    pub cis: u8,
    pub interval: [u8; 3],
    pub framing: u8,
    pub phy: u8,
    pub sdu: u16,
    pub rtn: u8,
    pub latency: u16,
    pub pd: [u8; 3],
}

/// ASCS Metadata operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsMetadata {
    pub ase: u8,
    pub len: u8,
}

/// ASCS Enable operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsEnable {
    pub ase: u8,
    pub len: u8,
}

/// ASCS Start operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsStart {
    pub ase: u8,
}

/// ASCS Disable operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsDisable {
    pub ase: u8,
}

/// ASCS Stop operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsStop {
    pub ase: u8,
}

/// ASCS Release operation per-ASE entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AscsRelease {
    pub ase: u8,
}

// ========================================================================
// BAP Type Definitions
// ========================================================================

bitflags! {
    /// BAP endpoint type flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BapType: u8 {
        const SINK = 0x01;
        const SOURCE = 0x02;
        const BCAST_SOURCE = 0x04;
        const BCAST_SINK = 0x08;
    }
}

/// BAP stream type (unicast or broadcast).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BapStreamType {
    Ucast = 0x01,
    Bcast = 0x02,
}

/// BAP stream state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BapStreamState {
    Idle = 0x00,
    Config = 0x01,
    Qos = 0x02,
    Enabling = 0x03,
    Streaming = 0x04,
    Disabling = 0x05,
    Releasing = 0x06,
}

impl BapStreamState {
    /// Convert from raw u8 wire value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Idle),
            0x01 => Some(Self::Config),
            0x02 => Some(Self::Qos),
            0x03 => Some(Self::Enabling),
            0x04 => Some(Self::Streaming),
            0x05 => Some(Self::Disabling),
            0x06 => Some(Self::Releasing),
            _ => None,
        }
    }
}

/// BAP config target latency preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BapConfigLatency {
    Low = 0x01,
    Balanced = 0x02,
    High = 0x03,
}

bitflags! {
    /// BAP config PHY flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BapConfigPhy: u8 {
        const PHY_1M = 0x01;
        const PHY_2M = 0x02;
        const PHY_CODEC = 0x04;
    }
}

/// LTV (Length-Type-Value) record for codec capabilities, configuration, and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtLtv {
    pub len: u8,
    pub type_: u8,
    pub value: Vec<u8>,
}

/// BAP I/O QoS parameters (shared between unicast and broadcast).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BapIoQos {
    pub interval: u32,
    pub latency: u16,
    pub sdu: u16,
    pub phys: u8,
    pub rtn: u8,
}

/// BAP unicast QoS parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BapUcastQos {
    pub cig_id: u8,
    pub cis_id: u8,
    pub framing: u8,
    pub delay: u32,
    pub target_latency: u8,
    pub io_qos: BapIoQos,
}

impl Default for BapUcastQos {
    fn default() -> Self {
        Self {
            cig_id: BT_ISO_QOS_CIG_UNSET,
            cis_id: BT_ISO_QOS_CIS_UNSET,
            framing: 0,
            delay: 0,
            target_latency: 0,
            io_qos: BapIoQos::default(),
        }
    }
}

/// BAP broadcast QoS parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BapBcastQos {
    pub big: u8,
    pub bis: u8,
    pub sync_factor: u8,
    pub packing: u8,
    pub framing: u8,
    pub encryption: u8,
    pub bcode: Option<Vec<u8>>,
    pub options: u8,
    pub skip: u16,
    pub sync_timeout: u16,
    pub sync_cte_type: u8,
    pub mse: u8,
    pub timeout: u16,
    pub pa_sync: u8,
    pub io_qos: BapIoQos,
    pub delay: u32,
}

impl Default for BapBcastQos {
    fn default() -> Self {
        Self {
            big: BT_ISO_QOS_BIG_UNSET,
            bis: BT_ISO_QOS_BIS_UNSET,
            sync_factor: BT_ISO_SYNC_FACTOR,
            packing: 0,
            framing: 0,
            encryption: 0,
            bcode: None,
            options: 0,
            skip: 0,
            sync_timeout: BT_ISO_SYNC_TIMEOUT,
            sync_cte_type: 0,
            mse: 0,
            timeout: BT_ISO_SYNC_TIMEOUT,
            pa_sync: 0,
            io_qos: BapIoQos::default(),
            delay: 0,
        }
    }
}

/// BAP QoS parameters (unicast or broadcast).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BapQos {
    Ucast(BapUcastQos),
    Bcast(BapBcastQos),
}

impl Default for BapQos {
    fn default() -> Self {
        BapQos::Ucast(BapUcastQos::default())
    }
}

/// PAC QoS information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BapPacQos {
    pub framing: u8,
    pub phys: u8,
    pub rtn: u8,
    pub latency: u16,
    pub pd_min: u32,
    pub pd_max: u32,
    pub ppd_min: u32,
    pub ppd_max: u32,
    pub location: u32,
    pub supported_context: u16,
    pub context: u16,
}

// ========================================================================
// BAP Debug Functions
// ========================================================================

// LTV type constants for codec capabilities.
const BAP_FREQ_LTV_TYPE: u8 = 1;
const BAP_DURATION_LTV_TYPE: u8 = 2;
const BAP_CHANNEL_ALLOCATION_LTV_TYPE: u8 = 3;
const BAP_FRAME_LEN_LTV_TYPE: u8 = 4;
const BAP_FRAME_COUNT_LTV_TYPE: u8 = 5;

/// Frequency lookup table for PAC capabilities debug (bitmask -> string).
static PAC_FREQ_TABLE: &[(u16, &str)] = &[
    (0x0001, "8 KHz"),
    (0x0002, "11.025 KHz"),
    (0x0004, "16 KHz"),
    (0x0008, "22.05 KHz"),
    (0x0010, "24 KHz"),
    (0x0020, "32 KHz"),
    (0x0040, "44.1 KHz"),
    (0x0080, "48 KHz"),
    (0x0100, "88.2 KHz"),
    (0x0200, "96 KHz"),
    (0x0400, "176.4 KHz"),
    (0x0800, "192 KHz"),
    (0x1000, "384 KHz"),
];

/// Duration lookup table for PAC capabilities debug (bitmask -> string).
static PAC_DURATION_TABLE: &[(u8, &str)] =
    &[(0x01, "7.5 ms"), (0x02, "10 ms"), (0x04, "Preferred: 7.5 ms"), (0x08, "Preferred: 10 ms")];

/// Channel allocation lookup table for PAC capabilities debug.
static PAC_CHANNEL_TABLE: &[(u32, &str)] = &[
    (0x00000001, "Front Left"),
    (0x00000002, "Front Right"),
    (0x00000004, "Front Center"),
    (0x00000008, "Low Frequency Effects 1"),
    (0x00000010, "Back Left"),
    (0x00000020, "Back Right"),
    (0x00000040, "Front Left of Center"),
    (0x00000080, "Front Right of Center"),
];

/// Channel location table for ASE configuration debug (full set).
static CHANNEL_LOCATION_TABLE: &[(u32, &str)] = &[
    (0x00000001, "Front Left"),
    (0x00000002, "Front Right"),
    (0x00000004, "Front Center"),
    (0x00000008, "Low Frequency Effects 1"),
    (0x00000010, "Back Left"),
    (0x00000020, "Back Right"),
    (0x00000040, "Front Left of Center"),
    (0x00000080, "Front Right of Center"),
    (0x00000100, "Back Center"),
    (0x00000200, "Low Frequency Effects 2"),
    (0x00000400, "Side Left"),
    (0x00000800, "Side Right"),
    (0x00001000, "Top Front Left"),
    (0x00002000, "Top Front Right"),
    (0x00004000, "Top Front Center"),
    (0x00008000, "Top Center"),
    (0x00010000, "Top Back Left"),
    (0x00020000, "Top Back Right"),
    (0x00040000, "Top Side Left"),
    (0x00080000, "Top Side Right"),
    (0x00100000, "Top Back Center"),
    (0x00200000, "Bottom Front Center"),
    (0x00400000, "Bottom Front Left"),
    (0x00800000, "Bottom Front Right"),
    (0x01000000, "Front Left Wide"),
    (0x02000000, "Front Right Wide"),
    (0x04000000, "Left Surround"),
    (0x08000000, "Right Surround"),
];

/// Context type table for metadata debug.
static PAC_CONTEXT_TABLE: &[(u16, &str)] = &[
    (0x0001, "Unspecified"),
    (0x0002, "Conversational"),
    (0x0004, "Media"),
    (0x0008, "Game"),
    (0x0010, "Instructional"),
    (0x0020, "Voice Assistants"),
    (0x0040, "Live"),
    (0x0080, "Sound Effects"),
    (0x0100, "Notifications"),
    (0x0200, "Ringtone"),
    (0x0400, "Alerts"),
    (0x0800, "Emergency Alarm"),
];

fn debug_pac_freq(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.len() < 2 {
        return;
    }
    let freq = get_le16(data);
    for &(mask, label) in PAC_FREQ_TABLE {
        if freq & mask != 0 {
            dbg(&format!("        {label}"));
        }
    }
}

fn debug_pac_duration(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.is_empty() {
        return;
    }
    let dur = data[0];
    for &(mask, label) in PAC_DURATION_TABLE {
        if dur & mask != 0 {
            dbg(&format!("        {label}"));
        }
    }
}

fn debug_pac_channels(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.is_empty() {
        return;
    }
    let ch = data[0];
    for &(mask, label) in PAC_CHANNEL_TABLE {
        let m8 = mask as u8;
        if ch & m8 != 0 {
            dbg(&format!("        {label}"));
        }
    }
}

fn debug_pac_frame_length(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.len() < 4 {
        return;
    }
    let min = get_le16(&data[0..2]);
    let max = get_le16(&data[2..4]);
    dbg(&format!("        Frame Length: {min} - {max}"));
}

fn debug_pac_sdu(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.is_empty() {
        return;
    }
    dbg(&format!("        Max SDU: {}", data[0]));
}

/// Parse and log codec capabilities LTV data. Returns true if all LTV records
/// parsed successfully, false if the data was malformed.
pub fn bap_debug_caps(data: &[u8], dbg: &mut dyn FnMut(&str)) -> bool {
    ltv_foreach(data, |ltv_type, value| {
        match ltv_type {
            BAP_FREQ_LTV_TYPE => {
                dbg("      Supported Sampling Frequencies:");
                debug_pac_freq(value, dbg);
            }
            BAP_DURATION_LTV_TYPE => {
                dbg("      Supported Frame Durations:");
                debug_pac_duration(value, dbg);
            }
            BAP_CHANNEL_ALLOCATION_LTV_TYPE => {
                dbg("      Supported Audio Channel Counts:");
                debug_pac_channels(value, dbg);
            }
            BAP_FRAME_LEN_LTV_TYPE => {
                dbg("      Supported Frame Length:");
                debug_pac_frame_length(value, dbg);
            }
            BAP_FRAME_COUNT_LTV_TYPE => {
                dbg("      Max Codec Frames Per SDU:");
                debug_pac_sdu(value, dbg);
            }
            _ => {
                dbg(&format!("      Unknown LTV Type: 0x{ltv_type:02x}"));
            }
        }
        true
    })
}

fn debug_ase_freq(val: u8, dbg: &mut dyn FnMut(&str)) {
    let desc = match val {
        0x01 => "8000 Hz",
        0x02 => "11025 Hz",
        0x03 => "16000 Hz",
        0x04 => "22050 Hz",
        0x05 => "24000 Hz",
        0x06 => "32000 Hz",
        0x07 => "44100 Hz",
        0x08 => "48000 Hz",
        0x09 => "88200 Hz",
        0x0a => "96000 Hz",
        0x0b => "176400 Hz",
        0x0c => "192000 Hz",
        0x0d => "384000 Hz",
        _ => "RFU",
    };
    dbg(&format!("        Sampling Frequency: {desc}"));
}

fn debug_ase_duration(val: u8, dbg: &mut dyn FnMut(&str)) {
    let desc = match val {
        0x00 => "7.5 ms",
        0x01 => "10 ms",
        _ => "RFU",
    };
    dbg(&format!("        Frame Duration: {desc}"));
}

fn debug_ase_location(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.len() < 4 {
        return;
    }
    let loc = get_le32(data);
    for &(mask, label) in CHANNEL_LOCATION_TABLE {
        if loc & mask != 0 {
            dbg(&format!("        Channel Location: {label}"));
        }
    }
}

fn debug_ase_frame_length(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.len() < 2 {
        return;
    }
    let val = get_le16(data);
    dbg(&format!("        Frame Length: {val}"));
}

fn debug_ase_blocks(data: &[u8], dbg: &mut dyn FnMut(&str)) {
    if data.is_empty() {
        return;
    }
    dbg(&format!("        Codec Frame Blocks Per SDU: {}", data[0]));
}

/// Parse and log codec configuration LTV data.
pub fn bap_debug_config(data: &[u8], dbg: &mut dyn FnMut(&str)) -> bool {
    ltv_foreach(data, |ltv_type, value| {
        match ltv_type {
            BAP_FREQ_LTV_TYPE => {
                if !value.is_empty() {
                    debug_ase_freq(value[0], dbg);
                }
            }
            BAP_DURATION_LTV_TYPE => {
                if !value.is_empty() {
                    debug_ase_duration(value[0], dbg);
                }
            }
            BAP_CHANNEL_ALLOCATION_LTV_TYPE => {
                debug_ase_location(value, dbg);
            }
            BAP_FRAME_LEN_LTV_TYPE => {
                debug_ase_frame_length(value, dbg);
            }
            BAP_FRAME_COUNT_LTV_TYPE => {
                debug_ase_blocks(value, dbg);
            }
            _ => {
                dbg(&format!("      Unknown Config LTV Type: 0x{ltv_type:02x}"));
            }
        }
        true
    })
}

fn debug_context(val: u16, dbg: &mut dyn FnMut(&str)) {
    for &(mask, label) in PAC_CONTEXT_TABLE {
        if val & mask != 0 {
            dbg(&format!("        {label}"));
        }
    }
}

/// Parse and log metadata LTV data.
pub fn bap_debug_metadata(data: &[u8], dbg: &mut dyn FnMut(&str)) -> bool {
    ltv_foreach(data, |ltv_type, value| {
        match ltv_type {
            0x01 => {
                dbg("      Preferred Audio Contexts:");
                if value.len() >= 2 {
                    debug_context(get_le16(value), dbg);
                }
            }
            0x02 => {
                dbg("      Streaming Audio Contexts:");
                if value.len() >= 2 {
                    debug_context(get_le16(value), dbg);
                }
            }
            0x03 => {
                let s = String::from_utf8_lossy(value);
                dbg(&format!("      Program Info: {s}"));
            }
            0x04 => {
                if value.len() >= 3 {
                    let lang = String::from_utf8_lossy(&value[..3]);
                    dbg(&format!("      Language: {lang}"));
                }
            }
            _ => {
                dbg(&format!("      Unknown Metadata LTV Type: 0x{ltv_type:02x}"));
            }
        }
        true
    })
}

// ========================================================================
// PAC Operations Trait
// ========================================================================

/// PAC operations trait replacing C struct bt_bap_pac_ops function pointers.
pub trait BapPacOps: Send + Sync {
    /// Select codec configuration for a local+remote PAC pair.
    fn select(
        &self,
        lpac: &BtBapPac,
        rpac: &BtBapPac,
        chan_alloc: u32,
        qos: &BapPacQos,
        cb: PacSelectCb,
    ) -> Result<(), i32>;

    /// Cancel a pending select operation.
    fn cancel_select(&self, lpac: &BtBapPac);

    /// Apply configuration to a stream.
    fn config(
        &self,
        stream: &BtBapStream,
        cfg: &[u8],
        qos: &BapQos,
        cb: Box<dyn FnOnce(Result<(), i32>) + Send>,
    ) -> Result<(), i32>;

    /// Clear configuration for a stream.
    fn clear(&self, stream: &BtBapStream);
}

// ========================================================================
// BtBapPac (Published Audio Capability)
// ========================================================================

struct BtBapPacInner {
    name: String,
    type_: BapType,
    codec: BapCodec,
    qos: BapPacQos,
    data: Vec<u8>,
    metadata: Vec<u8>,
    ops: Option<Arc<dyn BapPacOps>>,
    stream: Option<BtBapStream>,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
    bap: Option<Weak<Mutex<BtBapInner>>>,
}

/// Published Audio Capability record (replaces opaque `struct bt_bap_pac`).
#[derive(Clone)]
pub struct BtBapPac {
    inner: Arc<Mutex<BtBapPacInner>>,
}

impl BtBapPac {
    /// Create a new PAC record with the given parameters.
    pub fn new(
        name: &str,
        type_: BapType,
        codec: BapCodec,
        qos: &BapPacQos,
        data: &[u8],
        metadata: &[u8],
    ) -> Self {
        Self::new_inner(name, type_, codec, qos, data, metadata, None)
    }

    fn new_inner(
        name: &str,
        type_: BapType,
        codec: BapCodec,
        qos: &BapPacQos,
        data: &[u8],
        metadata: &[u8],
        ops: Option<Arc<dyn BapPacOps>>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BtBapPacInner {
                name: name.to_string(),
                type_,
                codec,
                qos: *qos,
                data: data.to_vec(),
                metadata: metadata.to_vec(),
                ops,
                stream: None,
                user_data: None,
                bap: None,
            })),
        }
    }

    /// Set the PAC operations handler.
    pub fn set_ops(&self, ops: Arc<dyn BapPacOps>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.ops = Some(ops);
        }
    }

    /// Remove this PAC, clearing its operations and stream.
    pub fn remove(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.ops = None;
            inner.stream = None;
        }
    }

    /// Get the PAC display name.
    pub fn get_name(&self) -> String {
        self.inner.lock().map(|i| i.name.clone()).unwrap_or_default()
    }

    /// Get the PAC type.
    pub fn get_type(&self) -> BapType {
        self.inner.lock().map(|i| i.type_).unwrap_or(BapType::empty())
    }

    /// Get the PAC audio locations bitmask.
    pub fn get_locations(&self) -> u32 {
        self.inner.lock().map(|i| i.qos.location).unwrap_or(0)
    }

    /// Get the PAC supported audio contexts bitmask.
    pub fn get_supported_context(&self) -> u16 {
        self.inner.lock().map(|i| i.qos.supported_context).unwrap_or(0)
    }

    /// Get the PAC available audio contexts bitmask.
    pub fn get_context(&self) -> u16 {
        self.inner.lock().map(|i| i.qos.context).unwrap_or(0)
    }

    /// Get the PAC QoS information.
    pub fn get_qos(&self) -> BapPacQos {
        self.inner.lock().map(|i| i.qos).unwrap_or_default()
    }

    /// Get the PAC codec capabilities data.
    pub fn get_data(&self) -> Vec<u8> {
        self.inner.lock().map(|i| i.data.clone()).unwrap_or_default()
    }

    /// Get the PAC metadata.
    pub fn get_metadata(&self) -> Vec<u8> {
        self.inner.lock().map(|i| i.metadata.clone()).unwrap_or_default()
    }

    /// Get the stream associated with this PAC.
    pub fn get_stream(&self) -> Option<BtBapStream> {
        self.inner.lock().ok().and_then(|i| i.stream.clone())
    }

    /// Get the vendor-specific codec identifier.
    pub fn get_vendor_codec(&self) -> BapCodec {
        self.inner.lock().map(|i| i.codec).unwrap_or_default()
    }

    /// Get the standard codec ID.
    pub fn get_codec(&self) -> u8 {
        self.inner.lock().map(|i| i.codec.id).unwrap_or(0)
    }

    /// Set the user data.
    pub fn set_user_data(&self, data: Arc<dyn Any + Send + Sync>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.user_data = Some(data);
        }
    }

    /// Get the user data.
    pub fn get_user_data(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.inner.lock().ok().and_then(|i| i.user_data.clone())
    }
}

// ========================================================================
// Callback Type Aliases
// ========================================================================

/// Callback invoked when a stream operation completes.
type StreamOpCb = Box<dyn FnOnce(&BtBapStream, u8) + Send>;

/// Callback invoked on stream connect state change.
type ConnectingCb = Box<dyn Fn(&BtBapStream, bool, i32) + Send + Sync>;

/// Callback invoked to probe a BIS.
type BisProbeFunc = Box<dyn Fn(u8, u8, u8, &[u8], &[u8], &BapQos) + Send + Sync>;

/// Callback invoked to request a broadcast code.
type BcodeFunc = Box<dyn Fn(&BtBapStream, Box<dyn FnOnce(i32) + Send>) + Send + Sync>;

/// PAC select completion callback.
type PacSelectCb = Box<dyn FnOnce(Result<(Vec<u8>, Vec<u8>, BapQos), i32>) + Send>;

// ========================================================================
// Callback Structures
// ========================================================================

struct BapPacChangedCb {
    id: u32,
    added: Box<dyn Fn(&BtBapPac) + Send + Sync>,
    removed_cb: Box<dyn Fn(&BtBapPac) + Send + Sync>,
}

struct BapReadyCb {
    id: u32,
    func: Box<dyn Fn(&BtBap) + Send + Sync>,
}

struct BapStateCb {
    id: u32,
    func: Box<dyn Fn(&BtBapStream, u8, u8) + Send + Sync>,
    connecting_cb: Option<ConnectingCb>,
}

struct BapBisCb {
    id: u32,
    probe_cb: BisProbeFunc,
    remove_cb: Box<dyn Fn(&BtBap) + Send + Sync>,
}

struct BapBcodeCb {
    id: u32,
    func: BcodeFunc,
}

// ========================================================================
// Internal Structures
// ========================================================================

/// Stream I/O state, shared across linked streams.
struct StreamIo {
    fd: Option<OwnedFd>,
    connecting: bool,
}

/// Pending ASCS Control Point request.
struct BapRequest {
    id: u32,
    stream: BtBapStream,
    op: u8,
    group: Vec<BapRequest>,
    data: Vec<u8>,
    func: Option<StreamOpCb>,
}

/// BAP endpoint (local or remote ASE).
struct BapEndpoint {
    attr_handle: u16,
    id: u8,
    dir: u8,
    old_state: u8,
    stream: Option<BtBapStream>,
    state_id: u32,
}

/// PACS service attribute handles.
#[derive(Default)]
struct BapPacs {
    sink_handle: u16,
    sink_loc_handle: u16,
    source_handle: u16,
    source_loc_handle: u16,
    context_handle: u16,
    supported_context_handle: u16,
}

/// ASCS service attribute handles.
#[derive(Default)]
struct BapAscs {
    ase_cp_handle: u16,
}

/// Global ID counter for callback registrations.
static NEXT_CB_ID: AtomicU32 = AtomicU32::new(1);

fn next_id() -> u32 {
    NEXT_CB_ID.fetch_add(1, Ordering::Relaxed)
}

// ========================================================================
// Global BAP Session Registry
// ========================================================================

struct BapGlobalCb {
    id: u32,
    added_cb: Box<dyn Fn(&BtBap) + Send + Sync>,
    removed_cb: Box<dyn Fn(&BtBap) + Send + Sync>,
}

struct BapRegistry {
    sessions: Vec<BtBap>,
    callbacks: Vec<BapGlobalCb>,
}

static BAP_REGISTRY: Mutex<Option<BapRegistry>> = Mutex::new(None);

fn with_registry<R>(f: impl FnOnce(&mut BapRegistry) -> R) -> R {
    let mut guard = BAP_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let reg =
        guard.get_or_insert_with(|| BapRegistry { sessions: Vec::new(), callbacks: Vec::new() });
    f(reg)
}

// ========================================================================
// BtBap Session
// ========================================================================

struct BtBapInner {
    ldb: GattDb,
    rdb: Option<GattDb>,
    att: Option<Arc<Mutex<BtAtt>>>,
    client: Option<Arc<BtGattClient>>,
    server: Option<Arc<BtGattServer>>,
    local_pacs: BapPacs,
    remote_pacs: BapPacs,
    local_ascs: BapAscs,
    remote_ascs: BapAscs,
    local_eps: Vec<BapEndpoint>,
    remote_eps: Vec<BapEndpoint>,
    streams: Vec<BtBapStream>,
    pac_list: Vec<BtBapPac>,
    remote_pac_list: Vec<BtBapPac>,
    pac_cbs: Vec<BapPacChangedCb>,
    ready_cbs: Vec<BapReadyCb>,
    state_cbs: Vec<BapStateCb>,
    bis_cbs: Vec<BapBisCb>,
    bcode_cbs: Vec<BapBcodeCb>,
    reqs: Vec<BapRequest>,
    process_timeout: Option<tokio::task::JoinHandle<()>>,
    ready: bool,
    debug_func: Option<Box<dyn FnMut(&str) + Send>>,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
}

/// BAP session (replaces opaque `struct bt_bap`). Arc-cloneable for shared ownership.
#[derive(Clone)]
pub struct BtBap {
    inner: Arc<Mutex<BtBapInner>>,
}

impl BtBap {
    fn new_inner(ldb: GattDb, rdb: Option<GattDb>) -> Self {
        let inner = BtBapInner {
            ldb,
            rdb,
            att: None,
            client: None,
            server: None,
            local_pacs: BapPacs::default(),
            remote_pacs: BapPacs::default(),
            local_ascs: BapAscs::default(),
            remote_ascs: BapAscs::default(),
            local_eps: Vec::new(),
            remote_eps: Vec::new(),
            streams: Vec::new(),
            pac_list: Vec::new(),
            remote_pac_list: Vec::new(),
            pac_cbs: Vec::new(),
            ready_cbs: Vec::new(),
            state_cbs: Vec::new(),
            bis_cbs: Vec::new(),
            bcode_cbs: Vec::new(),
            reqs: Vec::new(),
            process_timeout: None,
            ready: false,
            debug_func: None,
            user_data: None,
        };
        Self { inner: Arc::new(Mutex::new(inner)) }
    }

    /// Set the user data.
    pub fn set_user_data(&self, data: Arc<dyn Any + Send + Sync>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.user_data = Some(data);
        }
    }

    /// Get the user data.
    pub fn get_user_data(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.inner.lock().ok().and_then(|i| i.user_data.clone())
    }

    /// Get the underlying ATT transport.
    pub fn get_att(&self) -> Option<Arc<Mutex<BtAtt>>> {
        self.inner.lock().ok().and_then(|i| i.att.clone())
    }

    /// Get the local or remote GATT database.
    pub fn get_db(&self, remote: bool) -> Option<GattDb> {
        self.inner.lock().ok().and_then(
            |i| {
                if remote { i.rdb.clone() } else { Some(i.ldb.clone()) }
            },
        )
    }

    /// Set the debug callback.
    pub fn set_debug(&self, cb: Box<dyn FnMut(&str) + Send>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.debug_func = Some(cb);
        }
    }

    /// Attach a GATT client for remote service discovery and interaction.
    pub fn attach(&self, client: Arc<BtGattClient>) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if inner.client.is_some() {
            return false;
        }

        let rdb = client.get_db();
        inner.rdb = Some(rdb);
        inner.client = Some(client.clone());
        inner.ready = false;

        // Discover remote PACS service.
        let pacs_uuid = BtUuid::from_u16(PACS_UUID);
        let _self_clone = self.clone();
        let client_ref = client.clone();

        // Look for PACS service in the remote database.
        if let Some(ref rdb) = inner.rdb {
            let mut found_pacs = false;
            rdb.foreach_service(Some(&pacs_uuid), |attr| {
                let handle = attr.get_handle();
                found_pacs = true;
                trace!("Found PACS service at handle 0x{:04x}", handle);
            });

            // Look for ASCS service.
            let ascs_uuid = BtUuid::from_u16(ASCS_UUID);
            rdb.foreach_service(Some(&ascs_uuid), |attr| {
                let handle = attr.get_handle();
                trace!("Found ASCS service at handle 0x{:04x}", handle);
            });

            if found_pacs {
                // Discover PAC characteristics.
                self.discover_pacs(&mut inner, &client_ref);
                // Discover ASE characteristics.
                self.discover_ascs(&mut inner, &client_ref);
            }
        }

        let is_ready = inner.ready;
        drop(inner);

        // Notify ready after releasing the lock.
        if is_ready {
            self.notify_ready();
            self.notify_session_added();
        }

        true
    }

    /// Attach for broadcast operation (no GATT client needed).
    pub fn attach_broadcast(&self) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        inner.ready = true;
        true
    }

    /// Detach the GATT client and clean up.
    pub fn detach(&self) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(handle) = inner.process_timeout.take() {
            handle.abort();
        }
        inner.client = None;
        inner.att = None;
        inner.server = None;
        inner.ready = false;
        inner.reqs.clear();
        inner.remote_eps.clear();
        inner.local_eps.clear();

        // Log local service handle state before cleanup.
        trace!(
            "BAP detach: local_pacs sink=0x{:04x} source=0x{:04x}, ascs cp=0x{:04x}",
            inner.local_pacs.sink_handle,
            inner.local_pacs.source_handle,
            inner.local_ascs.ase_cp_handle,
        );
        inner.local_pacs = BapPacs::default();
        inner.local_ascs = BapAscs::default();

        // Collect remote PACs for removal notification.
        let removed_pacs: Vec<BtBapPac> = inner.remote_pac_list.drain(..).collect();

        // Release all streams.
        let streams: Vec<BtBapStream> = inner.streams.drain(..).collect();
        drop(inner);

        for pac in &removed_pacs {
            self.notify_pac_removed(pac);
        }

        for stream in &streams {
            stream.set_state_internal(BapStreamState::Idle);
        }

        self.notify_session_removed();
    }

    /// Register PAC change callback. Returns registration ID.
    pub fn pac_register(
        &self,
        added: Box<dyn Fn(&BtBapPac) + Send + Sync>,
        removed: Box<dyn Fn(&BtBapPac) + Send + Sync>,
    ) -> u32 {
        let id = next_id();
        if let Ok(mut inner) = self.inner.lock() {
            inner.pac_cbs.push(BapPacChangedCb { id, added, removed_cb: removed });
        }
        id
    }

    /// Unregister PAC change callback.
    pub fn pac_unregister(&self, id: u32) -> bool {
        if let Ok(mut inner) = self.inner.lock() {
            let before = inner.pac_cbs.len();
            inner.pac_cbs.retain(|cb| cb.id != id);
            return inner.pac_cbs.len() < before;
        }
        false
    }

    /// Register ready callback. Returns registration ID.
    pub fn ready_register(&self, func: Box<dyn Fn(&BtBap) + Send + Sync>) -> u32 {
        let id = next_id();
        if let Ok(mut inner) = self.inner.lock() {
            inner.ready_cbs.push(BapReadyCb { id, func });
        }
        id
    }

    /// Unregister ready callback.
    pub fn ready_unregister(&self, id: u32) -> bool {
        if let Ok(mut inner) = self.inner.lock() {
            let before = inner.ready_cbs.len();
            inner.ready_cbs.retain(|cb| cb.id != id);
            return inner.ready_cbs.len() < before;
        }
        false
    }

    /// Register stream state change callback. Returns registration ID.
    pub fn state_register(
        &self,
        func: Box<dyn Fn(&BtBapStream, u8, u8) + Send + Sync>,
        connecting: Option<ConnectingCb>,
    ) -> u32 {
        let id = next_id();
        if let Ok(mut inner) = self.inner.lock() {
            inner.state_cbs.push(BapStateCb { id, func, connecting_cb: connecting });
        }
        id
    }

    /// Unregister stream state change callback.
    pub fn state_unregister(&self, id: u32) -> bool {
        if let Ok(mut inner) = self.inner.lock() {
            let before = inner.state_cbs.len();
            inner.state_cbs.retain(|cb| cb.id != id);
            return inner.state_cbs.len() < before;
        }
        false
    }

    /// Iterate over PACs of the given type.
    pub fn foreach_pac(&self, type_: BapType, func: impl Fn(&BtBapPac)) {
        let pacs: Vec<BtBapPac> = {
            let inner = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let mut result = Vec::new();
            for pac in &inner.pac_list {
                if let Ok(pi) = pac.inner.lock() {
                    if pi.type_.intersects(type_) {
                        result.push(pac.clone());
                    }
                }
            }
            for pac in &inner.remote_pac_list {
                if let Ok(pi) = pac.inner.lock() {
                    if pi.type_.intersects(type_) {
                        result.push(pac.clone());
                    }
                }
            }
            result
        };
        for pac in &pacs {
            func(pac);
        }
    }

    /// Register BIS callback. Returns registration ID.
    pub fn bis_cb_register(
        &self,
        probe: BisProbeFunc,
        remove: Box<dyn Fn(&BtBap) + Send + Sync>,
    ) -> u32 {
        let id = next_id();
        if let Ok(mut inner) = self.inner.lock() {
            inner.bis_cbs.push(BapBisCb { id, probe_cb: probe, remove_cb: remove });
        }
        id
    }

    /// Unregister BIS callback.
    pub fn bis_cb_unregister(&self, id: u32) -> bool {
        if let Ok(mut inner) = self.inner.lock() {
            let before = inner.bis_cbs.len();
            inner.bis_cbs.retain(|cb| cb.id != id);
            return inner.bis_cbs.len() < before;
        }
        false
    }

    /// Register broadcast code callback. Returns registration ID.
    pub fn bcode_cb_register(&self, func: BcodeFunc) -> u32 {
        let id = next_id();
        if let Ok(mut inner) = self.inner.lock() {
            inner.bcode_cbs.push(BapBcodeCb { id, func });
        }
        id
    }

    /// Unregister broadcast code callback.
    pub fn bcode_cb_unregister(&self, id: u32) -> bool {
        if let Ok(mut inner) = self.inner.lock() {
            let before = inner.bcode_cbs.len();
            inner.bcode_cbs.retain(|cb| cb.id != id);
            return inner.bcode_cbs.len() < before;
        }
        false
    }

    /// Request broadcast code from registered callbacks.
    pub fn req_bcode(&self, stream: &BtBapStream, reply: Box<dyn FnOnce(i32) + Send>) {
        let _cbs: Vec<_> = {
            let inner = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            inner.bcode_cbs.iter().map(|cb| cb.id).collect()
        };
        // Invoke the first registered bcode callback.
        if let Ok(inner) = self.inner.lock() {
            if let Some(cb) = inner.bcode_cbs.first() {
                (cb.func)(stream, reply);
                return;
            }
        }
        // No callback registered, reply with error.
        reply(-1);
    }

    /// Create a new broadcast source PAC.
    pub fn new_bcast_source(&self, name: &str) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let pac = BtBapPac::new_inner(
            name,
            BapType::BCAST_SOURCE,
            BapCodec::default(),
            &BapPacQos::default(),
            &[],
            &[],
            None,
        );
        if let Ok(mut pi) = pac.inner.lock() {
            pi.bap = Some(Arc::downgrade(&self.inner));
        }
        inner.pac_list.push(pac);
        true
    }

    /// Update a broadcast source PAC with new codec configuration.
    pub fn update_bcast_source(
        &self,
        pac: &BtBapPac,
        codec: &BapCodec,
        data: &[u8],
        metadata: &[u8],
    ) {
        if let Ok(mut pi) = pac.inner.lock() {
            pi.codec = *codec;
            pi.data = data.to_vec();
            pi.metadata = metadata.to_vec();
        }
    }

    /// Check if a PAC is a local broadcast PAC.
    pub fn pac_bcast_is_local(&self, pac: &BtBapPac) -> bool {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let pac_ptr = Arc::as_ptr(&pac.inner);
        inner.pac_list.iter().any(|p| Arc::as_ptr(&p.inner) == pac_ptr)
    }

    /// Verify a BIS index against broadcast capabilities.
    pub fn verify_bis(&self, _bis_index: u8, caps: &[u8]) -> Option<BtBapPac> {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        for pac in &inner.pac_list {
            if let Ok(pi) = pac.inner.lock() {
                if pi.type_.contains(BapType::BCAST_SOURCE) && pi.data == caps {
                    return Some(pac.clone());
                }
            }
        }
        None
    }

    // ---- Internal helpers ----

    fn discover_pacs(&self, inner: &mut BtBapInner, client: &Arc<BtGattClient>) {
        let rdb = match &inner.rdb {
            Some(db) => db.clone(),
            None => return,
        };
        // Discover Sink PAC characteristic.
        let sink_uuid = BtUuid::from_u16(PAC_SINK_UUID);
        let mut sink_handles = Vec::new();
        rdb.foreach_service(None, |_attr| {});
        // Use read_by_type to find characteristics.
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &sink_uuid);
        for attr in &attrs {
            sink_handles.push(attr.get_handle());
        }
        if let Some(&h) = sink_handles.first() {
            inner.remote_pacs.sink_handle = h;
            let self_clone = self.clone();
            client.read_value(
                h,
                Box::new(move |success, _ecode, data| {
                    if success {
                        self_clone.on_pacs_read(BapType::SINK, data);
                    }
                }),
            );
        }

        // Discover Source PAC characteristic.
        let source_uuid = BtUuid::from_u16(PAC_SOURCE_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &source_uuid);
        if let Some(attr) = attrs.first() {
            let h = attr.get_handle();
            inner.remote_pacs.source_handle = h;
            let self_clone = self.clone();
            client.read_value(
                h,
                Box::new(move |success, _ecode, data| {
                    if success {
                        self_clone.on_pacs_read(BapType::SOURCE, data);
                    }
                }),
            );
        }

        // Discover context characteristics.
        let avail_uuid = BtUuid::from_u16(PAC_AVAIL_CTX_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &avail_uuid);
        if let Some(attr) = attrs.first() {
            inner.remote_pacs.context_handle = attr.get_handle();
        }

        let supp_uuid = BtUuid::from_u16(PAC_SUPP_CTX_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &supp_uuid);
        if let Some(attr) = attrs.first() {
            inner.remote_pacs.supported_context_handle = attr.get_handle();
        }

        // Discover audio locations.
        let sink_loc_uuid = BtUuid::from_u16(PAC_SINK_LOC_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &sink_loc_uuid);
        if let Some(attr) = attrs.first() {
            inner.remote_pacs.sink_loc_handle = attr.get_handle();
        }

        let source_loc_uuid = BtUuid::from_u16(PAC_SOURCE_LOC_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &source_loc_uuid);
        if let Some(attr) = attrs.first() {
            inner.remote_pacs.source_loc_handle = attr.get_handle();
        }
    }

    fn discover_ascs(&self, inner: &mut BtBapInner, client: &Arc<BtGattClient>) {
        let rdb = match &inner.rdb {
            Some(db) => db.clone(),
            None => return,
        };

        // Discover Sink ASE characteristics.
        let sink_uuid = BtUuid::from_u16(ASE_SINK_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &sink_uuid);
        for attr in &attrs {
            let h = attr.get_handle();
            let ep = BapEndpoint {
                attr_handle: h,
                id: 0,
                dir: BapType::SINK.bits(),
                old_state: AscsAseState::Idle as u8,
                stream: None,
                state_id: 0,
            };
            inner.remote_eps.push(ep);
            // Register for notifications on this ASE.
            let self_clone = self.clone();
            let handle = h;
            client.register_notify(
                h,
                Box::new(move |_status| {
                    trace!("ASE sink notify registered for handle 0x{:04x}", handle);
                }),
                Box::new(move |_handle, data| {
                    self_clone.on_ase_notification(data);
                }),
            );
        }

        // Discover Source ASE characteristics.
        let source_uuid = BtUuid::from_u16(ASE_SOURCE_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &source_uuid);
        for attr in &attrs {
            let h = attr.get_handle();
            let ep = BapEndpoint {
                attr_handle: h,
                id: 0,
                dir: BapType::SOURCE.bits(),
                old_state: AscsAseState::Idle as u8,
                stream: None,
                state_id: 0,
            };
            inner.remote_eps.push(ep);
            let self_clone = self.clone();
            let handle = h;
            client.register_notify(
                h,
                Box::new(move |_status| {
                    trace!("ASE source notify registered for handle 0x{:04x}", handle);
                }),
                Box::new(move |_handle, data| {
                    self_clone.on_ase_notification(data);
                }),
            );
        }

        // Discover ASE Control Point.
        let cp_uuid = BtUuid::from_u16(ASE_CP_UUID);
        let attrs = rdb.read_by_type(0x0001, 0xFFFF, &cp_uuid);
        if let Some(attr) = attrs.first() {
            inner.remote_ascs.ase_cp_handle = attr.get_handle();
            let self_clone = self.clone();
            let handle = attr.get_handle();
            client.register_notify(
                handle,
                Box::new(move |_status| {
                    trace!("ASE CP notify registered for handle 0x{:04x}", handle);
                }),
                Box::new(move |_handle, data| {
                    self_clone.on_cp_notification(data);
                }),
            );
        }

        // Mark as ready once discovery is complete.
        inner.ready = true;
        // Note: notify_ready is called by the attach() method after
        // discover_pacs/discover_ascs return, since we hold a &mut borrow.
    }

    fn on_pacs_read(&self, pac_type: BapType, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let num_pac = data[0];
        let mut offset = 1usize;

        for _ in 0..num_pac {
            if offset + 5 > data.len() {
                break;
            }
            // Parse codec ID (5 bytes).
            let codec = BapCodec {
                id: data[offset],
                cid: u16::from_le_bytes([data[offset + 1], data[offset + 2]]),
                vid: u16::from_le_bytes([data[offset + 3], data[offset + 4]]),
            };
            offset += 5;

            // Parse codec capabilities length + data.
            if offset >= data.len() {
                break;
            }
            let cc_len = data[offset] as usize;
            offset += 1;
            if offset + cc_len > data.len() {
                break;
            }
            let cc_data = &data[offset..offset + cc_len];
            offset += cc_len;

            // Parse metadata length + data.
            if offset >= data.len() {
                break;
            }
            let meta_len = data[offset] as usize;
            offset += 1;
            if offset + meta_len > data.len() {
                break;
            }
            let meta_data = &data[offset..offset + meta_len];
            offset += meta_len;

            let pac = BtBapPac::new_inner(
                "",
                pac_type,
                codec,
                &BapPacQos::default(),
                cc_data,
                meta_data,
                None,
            );
            if let Ok(mut pi) = pac.inner.lock() {
                pi.bap = Some(Arc::downgrade(&self.inner));
            }

            // Notify callbacks.
            let _cbs: Vec<_> = {
                if let Ok(inner) = self.inner.lock() {
                    inner.pac_cbs.iter().map(|cb| cb.id).collect()
                } else {
                    Vec::new()
                }
            };
            if let Ok(inner) = self.inner.lock() {
                for cb in &inner.pac_cbs {
                    (cb.added)(&pac);
                }
            }

            if let Ok(mut inner) = self.inner.lock() {
                inner.remote_pac_list.push(pac);
            }
        }
    }

    fn on_ase_notification(&self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let ase_id = data[0];
        let state = data[1];

        trace!("ASE notification: id={}, state={}", ase_id, state);

        // Find the endpoint matching this ASE ID or attribute.
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        // Look up the endpoint by ASE ID.
        let ep_idx = inner.remote_eps.iter().position(|ep| ep.id == ase_id);
        if ep_idx.is_none() {
            // If no endpoint has this ID yet, assign it to one that has id == 0.
            if let Some(idx) = inner.remote_eps.iter().position(|ep| ep.id == 0) {
                inner.remote_eps[idx].id = ase_id;
            }
        }

        // Update stream state based on notification.
        let ep_idx = inner.remote_eps.iter().position(|ep| ep.id == ase_id);
        if let Some(idx) = ep_idx {
            let ep = &inner.remote_eps[idx];
            trace!(
                "ASE ep: handle=0x{:04x}, dir={}, state_id={}, old_state={}",
                ep.attr_handle, ep.dir, ep.state_id, ep.old_state,
            );
            let old_state = inner.remote_eps[idx].old_state;
            inner.remote_eps[idx].old_state = state;

            if let Some(ref stream) = inner.remote_eps[idx].stream {
                if let Some(new_state) = BapStreamState::from_u8(state) {
                    let stream_clone = stream.clone();
                    let _state_cbs: Vec<_> = inner.state_cbs.iter().map(|cb| cb.id).collect();
                    drop(inner);
                    stream_clone.set_state_internal(new_state);
                    // Notify state callbacks.
                    if let Ok(inner) = self.inner.lock() {
                        for cb in &inner.state_cbs {
                            (cb.func)(&stream_clone, old_state, state);
                        }
                    }
                    return;
                }
            }
        }

        // Parse state-specific data and potentially create/configure streams.
        if let Some(new_state) = AscsAseState::from_u8(state) {
            match new_state {
                AscsAseState::Config => {
                    self.handle_config_notification(&mut inner, ase_id, &data[2..]);
                }
                AscsAseState::Qos => {
                    self.handle_qos_notification(&mut inner, ase_id, &data[2..]);
                }
                _ => {}
            }
        }
    }

    fn handle_config_notification(&self, inner: &mut BtBapInner, ase_id: u8, data: &[u8]) {
        let cfg_size = std::mem::size_of::<AscsAseStatusConfig>();
        if data.len() < cfg_size {
            return;
        }
        if let Ok(cfg) = AscsAseStatusConfig::read_from_bytes(&data[..cfg_size]) {
            let cc_len = cfg.cc_len as usize;
            let cc_start = cfg_size;
            let cc_data = if cc_start + cc_len <= data.len() {
                &data[cc_start..cc_start + cc_len]
            } else {
                &[]
            };
            trace!("ASE {} Config: codec_id={}, cc_len={}", ase_id, cfg.codec.id, cc_len);
            // Update endpoint stream config.
            if let Some(ep) = inner.remote_eps.iter_mut().find(|ep| ep.id == ase_id) {
                if let Some(ref stream) = ep.stream {
                    if let Ok(mut si) = stream.inner.lock() {
                        si.config = cc_data.to_vec();
                    }
                }
            }
        }
    }

    fn handle_qos_notification(&self, inner: &mut BtBapInner, ase_id: u8, data: &[u8]) {
        let qos_size = std::mem::size_of::<AscsAseStatusQos>();
        if data.len() < qos_size {
            return;
        }
        if let Ok(qos) = AscsAseStatusQos::read_from_bytes(&data[..qos_size]) {
            let interval = get_le24(&qos.interval);
            let pd = get_le24(&qos.pd);
            let cig_id = qos.cig_id;
            let cis_id = qos.cis_id;
            let framing = qos.framing;
            let phys = qos.phys;
            let sdu = { qos.sdu };
            let rtn = qos.rtn;
            let latency = { qos.latency };
            trace!(
                "ASE {} QoS: cig={}, cis={}, interval={}, sdu={}",
                ase_id, cig_id, cis_id, interval, sdu
            );
            if let Some(ep) = inner.remote_eps.iter_mut().find(|ep| ep.id == ase_id) {
                if let Some(ref stream) = ep.stream {
                    if let Ok(mut si) = stream.inner.lock() {
                        si.qos = BapQos::Ucast(BapUcastQos {
                            cig_id,
                            cis_id,
                            framing,
                            delay: pd,
                            target_latency: 0,
                            io_qos: BapIoQos {
                                interval,
                                latency: u16::from_le(latency),
                                sdu: u16::from_le(sdu),
                                phys,
                                rtn,
                            },
                        });
                    }
                }
            }
        }
    }

    fn on_cp_notification(&self, data: &[u8]) {
        let rsp_size = std::mem::size_of::<AscsCpRsp>();
        if data.len() < rsp_size {
            return;
        }
        if let Ok(rsp) = AscsCpRsp::read_from_bytes(&data[..rsp_size]) {
            trace!("ASE CP response: op={}, num_ase={}", rsp.op, rsp.num_ase);
            let ase_rsp_size = std::mem::size_of::<AscsAseRsp>();
            let mut offset = rsp_size;
            for _ in 0..rsp.num_ase {
                if offset + ase_rsp_size > data.len() {
                    break;
                }
                if let Ok(ase_rsp) =
                    AscsAseRsp::read_from_bytes(&data[offset..offset + ase_rsp_size])
                {
                    trace!(
                        "  ASE {} response: code={}, reason={}",
                        ase_rsp.ase, ase_rsp.code, ase_rsp.reason
                    );
                }
                offset += ase_rsp_size;
            }
            // Process next pending request.
            self.process_next_request();
        }
    }

    fn notify_ready(&self) {
        let is_ready = self.inner.lock().ok().is_some_and(|i| i.ready);
        if is_ready {
            self.notify_ready_dispatch();
        }
    }

    fn notify_ready_dispatch(&self) {
        let self_ref = self.clone();
        if let Ok(inner) = self.inner.lock() {
            for cb in &inner.ready_cbs {
                (cb.func)(&self_ref);
            }
        }
    }

    /// Notify all registered callbacks that a PAC has been removed.
    pub fn notify_pac_removed(&self, pac: &BtBapPac) {
        if let Ok(inner) = self.inner.lock() {
            for cb in &inner.pac_cbs {
                (cb.removed_cb)(pac);
            }
        }
    }

    /// Notify all state callbacks about a connecting event.
    pub fn notify_connecting(&self, stream: &BtBapStream, connected: bool, err: i32) {
        if let Ok(inner) = self.inner.lock() {
            for cb in &inner.state_cbs {
                if let Some(ref connecting_cb) = cb.connecting_cb {
                    (connecting_cb)(stream, connected, err);
                }
            }
        }
    }

    /// Notify all BIS probe callbacks.
    pub fn notify_bis_probe(
        &self,
        sid: u8,
        bis: u8,
        sgrp: u8,
        caps: &[u8],
        meta: &[u8],
        qos: &BapQos,
    ) {
        if let Ok(inner) = self.inner.lock() {
            for cb in &inner.bis_cbs {
                (cb.probe_cb)(sid, bis, sgrp, caps, meta, qos);
            }
        }
    }

    /// Notify all BIS remove callbacks.
    pub fn notify_bis_remove(&self) {
        let self_ref = self.clone();
        if let Ok(inner) = self.inner.lock() {
            for cb in &inner.bis_cbs {
                (cb.remove_cb)(&self_ref);
            }
        }
    }

    /// Notify global registry that this session was added.
    pub fn notify_session_added(&self) {
        with_registry(|reg| {
            for cb in &reg.callbacks {
                (cb.added_cb)(self);
            }
        });
    }

    /// Notify global registry that this session is being removed.
    pub fn notify_session_removed(&self) {
        with_registry(|reg| {
            for cb in &reg.callbacks {
                (cb.removed_cb)(self);
            }
        });
    }

    /// Get the local GATT server if available.
    pub fn get_server(&self) -> Option<Arc<BtGattServer>> {
        self.inner.lock().ok()?.server.clone()
    }

    /// Access the local endpoint configuration for an ASE by index.
    pub fn find_local_ep(&self, ase_id: u8) -> Option<(u16, u8, u32)> {
        let inner = self.inner.lock().ok()?;
        inner
            .local_eps
            .iter()
            .find(|ep| ep.id == ase_id)
            .map(|ep| (ep.attr_handle, ep.dir, ep.state_id))
    }

    /// Get local PACS handle information.
    pub fn get_local_pacs_info(&self) -> Option<(u16, u16)> {
        let inner = self.inner.lock().ok()?;
        Some((inner.local_pacs.sink_handle, inner.local_pacs.source_handle))
    }

    /// Get local ASCS handle information.
    pub fn get_local_ascs_cp(&self) -> Option<u16> {
        let inner = self.inner.lock().ok()?;
        Some(inner.local_ascs.ase_cp_handle)
    }

    /// Get the grouped requests for the current pending request.
    pub fn get_current_request_group_len(&self) -> usize {
        self.inner.lock().ok().map_or(0, |i| i.reqs.first().map_or(0, |r| r.group.len()))
    }

    fn process_next_request(&self) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(handle) = inner.process_timeout.take() {
            handle.abort();
        }
        if inner.reqs.is_empty() {
            return;
        }
        let req = inner.reqs.remove(0);
        // Process grouped requests alongside the primary request.
        let group_count = req.group.len();
        if group_count > 0 {
            trace!("BAP processing request with {} grouped sub-requests", group_count);
        }
        let cp_handle = inner.remote_ascs.ase_cp_handle;
        let client = inner.client.clone();
        drop(inner);

        if let Some(client) = client {
            if cp_handle != 0 && !req.data.is_empty() {
                let _self_clone = self.clone();
                client.write_value(
                    cp_handle,
                    &req.data,
                    Box::new(move |success, ecode| {
                        if !success {
                            warn!("ASCS CP write failed: ecode=0x{:02x}", ecode);
                        }
                    }),
                );

                // Start process timeout.
                let self_timeout = self.clone();
                let handle = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(BAP_PROCESS_TIMEOUT)).await;
                    warn!("BAP process timeout expired");
                    self_timeout.process_next_request();
                });
                if let Ok(mut inner) = self.inner.lock() {
                    inner.process_timeout = Some(handle);
                }
            }
        }

        // Invoke the request callback if present.
        if let Some(func) = req.func {
            func(&req.stream, req.op);
        }
    }

    fn enqueue_request(
        &self,
        stream: &BtBapStream,
        op: u8,
        data: Vec<u8>,
        func: Option<StreamOpCb>,
    ) -> u32 {
        let id = next_id();
        let req = BapRequest { id, stream: stream.clone(), op, group: Vec::new(), data, func };
        let should_process = {
            let mut inner = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return 0,
            };
            let was_empty = inner.reqs.is_empty();
            inner.reqs.push(req);
            was_empty
        };
        if should_process {
            self.process_next_request();
        }
        id
    }
}

// ========================================================================
// BtBapStream
// ========================================================================

struct BtBapStreamInner {
    bap: Option<Weak<Mutex<BtBapInner>>>,
    lpac: Option<BtBapPac>,
    rpac: Option<BtBapPac>,
    qos: BapQos,
    config: Vec<u8>,
    metadata: Vec<u8>,
    state: BapStreamState,
    dir: u8,
    location: u32,
    io: Option<Arc<Mutex<StreamIo>>>,
    links: Vec<BtBapStream>,
    locked: bool,
    user_data: Option<Arc<dyn Any + Send + Sync>>,
    ep: Option<usize>, // index into remote_eps
}

/// BAP audio stream (replaces opaque `struct bt_bap_stream`).
#[derive(Clone)]
pub struct BtBapStream {
    inner: Arc<Mutex<BtBapStreamInner>>,
}

impl BtBapStream {
    /// Create a new BAP stream.
    pub fn new(bap: &BtBap, lpac: BtBapPac, rpac: BtBapPac, qos: &BapQos, data: &[u8]) -> Self {
        let dir = {
            if let Ok(pi) = rpac.inner.lock() {
                if pi.type_.contains(BapType::SINK) {
                    BapType::SINK.bits()
                } else {
                    BapType::SOURCE.bits()
                }
            } else {
                0
            }
        };

        let stream_inner = BtBapStreamInner {
            bap: Some(Arc::downgrade(&bap.inner)),
            lpac: Some(lpac),
            rpac: Some(rpac),
            qos: qos.clone(),
            config: data.to_vec(),
            metadata: Vec::new(),
            state: BapStreamState::Idle,
            dir,
            location: 0,
            io: None,
            links: Vec::new(),
            locked: false,
            user_data: None,
            ep: None,
        };
        let stream = Self { inner: Arc::new(Mutex::new(stream_inner)) };

        // Register stream with BAP session.
        if let Ok(mut bap_inner) = bap.inner.lock() {
            bap_inner.streams.push(stream.clone());
        }

        stream
    }

    /// Lock the stream (prevent state changes).
    pub fn lock(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.locked = true;
        }
    }

    /// Unlock the stream (allow state changes).
    pub fn unlock(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.locked = false;
        }
    }

    /// Get the parent BAP session.
    pub fn get_session(&self) -> Option<BtBap> {
        let inner = self.inner.lock().ok()?;
        let weak = inner.bap.as_ref()?;
        let arc = weak.upgrade()?;
        Some(BtBap { inner: arc })
    }

    /// Get the current stream state.
    pub fn get_state(&self) -> BapStreamState {
        self.inner.lock().map(|i| i.state).unwrap_or(BapStreamState::Idle)
    }

    /// Set user data on the stream.
    pub fn set_user_data(&self, data: Arc<dyn Any + Send + Sync>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.user_data = Some(data);
        }
    }

    /// Get user data from the stream.
    pub fn get_user_data(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.inner.lock().ok().and_then(|i| i.user_data.clone())
    }

    /// Configure codec (transitions Idle → Config or Config → Config).
    pub fn config(&self, qos: &BapQos, data: &[u8], func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        let current = self.get_state();
        if current != BapStreamState::Idle && current != BapStreamState::Config {
            return 0;
        }

        // Update local config.
        if let Ok(mut inner) = self.inner.lock() {
            inner.qos = qos.clone();
            inner.config = data.to_vec();
        }

        // Build ASCS Config PDU.
        let pdu = self.build_config_pdu(data);
        if pdu.is_empty() {
            return 0;
        }

        bap.enqueue_request(self, ASCS_CONFIG, pdu, func)
    }

    /// Configure QoS (transitions Config → QoS).
    pub fn qos(&self, qos: &BapQos, func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        if self.get_state() != BapStreamState::Config {
            return 0;
        }

        if let Ok(mut inner) = self.inner.lock() {
            inner.qos = qos.clone();
        }

        let pdu = self.build_qos_pdu(qos);
        if pdu.is_empty() {
            return 0;
        }

        bap.enqueue_request(self, ASCS_QOS, pdu, func)
    }

    /// Enable stream (transitions QoS → Enabling).
    pub fn enable(&self, enable_links: bool, metadata: &[u8], func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        if self.get_state() != BapStreamState::Qos {
            return 0;
        }

        if let Ok(mut inner) = self.inner.lock() {
            inner.metadata = metadata.to_vec();
        }

        let pdu = self.build_enable_pdu(metadata);
        if pdu.is_empty() {
            return 0;
        }

        let id = bap.enqueue_request(self, ASCS_ENABLE, pdu, func);

        if enable_links {
            let links = self.get_links_snapshot();
            for link in &links {
                if link.get_state() == BapStreamState::Qos {
                    let link_pdu = link.build_enable_pdu(metadata);
                    if !link_pdu.is_empty() {
                        bap.enqueue_request(link, ASCS_ENABLE, link_pdu, None);
                    }
                }
            }
        }

        id
    }

    /// Start (Receiver Start Ready, transitions Enabling → Streaming).
    pub fn start(&self, func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        if self.get_state() != BapStreamState::Enabling {
            return 0;
        }

        let pdu = self.build_simple_pdu(ASCS_START);
        if pdu.is_empty() {
            return 0;
        }

        bap.enqueue_request(self, ASCS_START, pdu, func)
    }

    /// Disable stream (transitions Enabling/Streaming → Disabling).
    pub fn disable(&self, disable_links: bool, func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        let current = self.get_state();
        if current != BapStreamState::Enabling && current != BapStreamState::Streaming {
            return 0;
        }

        let pdu = self.build_simple_pdu(ASCS_DISABLE);
        if pdu.is_empty() {
            return 0;
        }

        let id = bap.enqueue_request(self, ASCS_DISABLE, pdu, func);

        if disable_links {
            let links = self.get_links_snapshot();
            for link in &links {
                let ls = link.get_state();
                if ls == BapStreamState::Enabling || ls == BapStreamState::Streaming {
                    let link_pdu = link.build_simple_pdu(ASCS_DISABLE);
                    if !link_pdu.is_empty() {
                        bap.enqueue_request(link, ASCS_DISABLE, link_pdu, None);
                    }
                }
            }
        }

        id
    }

    /// Stop stream (transitions Disabling → QoS).
    pub fn stop(&self, func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        if self.get_state() != BapStreamState::Disabling {
            return 0;
        }

        let pdu = self.build_simple_pdu(ASCS_STOP);
        if pdu.is_empty() {
            return 0;
        }

        bap.enqueue_request(self, ASCS_STOP, pdu, func)
    }

    /// Update metadata (valid in Enabling/Streaming states).
    pub fn metadata(&self, metadata: &[u8], func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        let current = self.get_state();
        if current != BapStreamState::Enabling && current != BapStreamState::Streaming {
            return 0;
        }

        if let Ok(mut inner) = self.inner.lock() {
            inner.metadata = metadata.to_vec();
        }

        let pdu = self.build_metadata_pdu(metadata);
        if pdu.is_empty() {
            return 0;
        }

        bap.enqueue_request(self, ASCS_METADATA, pdu, func)
    }

    /// Release stream (transitions any active state → Releasing → Idle).
    pub fn release(&self, func: Option<StreamOpCb>) -> u32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return 0,
        };
        let current = self.get_state();
        if current == BapStreamState::Idle || current == BapStreamState::Releasing {
            return 0;
        }

        let pdu = self.build_simple_pdu(ASCS_RELEASE);
        if pdu.is_empty() {
            return 0;
        }

        bap.enqueue_request(self, ASCS_RELEASE, pdu, func)
    }

    /// Cancel a pending operation.
    pub fn cancel(&self, id: u32) -> i32 {
        let bap = match self.get_session() {
            Some(b) => b,
            None => return -1,
        };
        if let Ok(mut inner) = bap.inner.lock() {
            let before = inner.reqs.len();
            inner.reqs.retain(|r| r.id != id);
            if inner.reqs.len() < before {
                return 0;
            }
        }
        -1
    }

    /// Get stream direction.
    pub fn get_dir(&self) -> u8 {
        self.inner.lock().map(|i| i.dir).unwrap_or(0)
    }

    /// Get stream location.
    pub fn get_location(&self) -> u32 {
        self.inner.lock().map(|i| i.location).unwrap_or(0)
    }

    /// Get codec configuration data.
    pub fn get_config(&self) -> Vec<u8> {
        self.inner.lock().map(|i| i.config.clone()).unwrap_or_default()
    }

    /// Get stream QoS configuration.
    pub fn get_qos(&self) -> BapQos {
        self.inner.lock().map(|i| i.qos.clone()).unwrap_or_default()
    }

    /// Get stream metadata.
    pub fn get_metadata(&self) -> Vec<u8> {
        self.inner.lock().map(|i| i.metadata.clone()).unwrap_or_default()
    }

    /// Get the raw I/O file descriptor.
    pub fn get_io(&self) -> Option<RawFd> {
        let inner = self.inner.lock().ok()?;
        let sio = inner.io.as_ref()?;
        let sio_inner = sio.lock().ok()?;
        sio_inner.fd.as_ref().map(|fd| fd.as_raw_fd())
    }

    /// Set the I/O file descriptor for this stream.
    pub fn set_io(&self, fd: OwnedFd) -> bool {
        if let Ok(mut inner) = self.inner.lock() {
            let sio = Arc::new(Mutex::new(StreamIo { fd: Some(fd), connecting: false }));
            inner.io = Some(sio);
            return true;
        }
        false
    }

    /// Check whether two `BtBapStream` handles reference the same underlying
    /// stream (identity check via `Arc::ptr_eq`).
    pub fn same_stream(&self, other: &BtBapStream) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Link this stream's I/O with another stream.
    pub fn io_link(&self, other: &BtBapStream) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.links.push(other.clone());
        }
        if let Ok(mut other_inner) = other.inner.lock() {
            other_inner.links.push(self.clone());
        }
    }

    /// Unlink this stream's I/O from another stream.
    pub fn io_unlink(&self, other: &BtBapStream) {
        let other_ptr = Arc::as_ptr(&other.inner);
        if let Ok(mut inner) = self.inner.lock() {
            inner.links.retain(|l| Arc::as_ptr(&l.inner) != other_ptr);
        }
        let self_ptr = Arc::as_ptr(&self.inner);
        if let Ok(mut other_inner) = other.inner.lock() {
            other_inner.links.retain(|l| Arc::as_ptr(&l.inner) != self_ptr);
        }
    }

    /// Get linked streams.
    pub fn io_get_links(&self) -> Vec<BtBapStream> {
        self.inner.lock().map(|i| i.links.clone()).unwrap_or_default()
    }

    /// Get I/O QoS for this stream.
    pub fn io_get_qos(&self) -> BapIoQos {
        self.inner
            .lock()
            .map(|i| match &i.qos {
                BapQos::Ucast(u) => u.io_qos,
                BapQos::Bcast(b) => b.io_qos,
            })
            .unwrap_or_default()
    }

    /// Get effective I/O direction.
    pub fn io_dir(&self) -> u8 {
        self.get_dir()
    }

    /// Mark I/O as connecting with the given fd.
    pub fn io_connecting(&self, fd: OwnedFd) {
        if let Ok(mut inner) = self.inner.lock() {
            let sio = Arc::new(Mutex::new(StreamIo { fd: Some(fd), connecting: true }));
            inner.io = Some(sio);
        }
    }

    /// Check if I/O is in connecting state.
    pub fn io_is_connecting(&self) -> bool {
        self.inner.lock().ok().is_some_and(|i| {
            i.io.as_ref().is_some_and(|sio| sio.lock().ok().is_some_and(|s| s.connecting))
        })
    }

    /// Get BASE (Broadcast Audio Source Endpoint) data.
    pub fn get_base(&self) -> Option<Vec<u8>> {
        let inner = self.inner.lock().ok()?;
        if let Some(ref lpac) = inner.lpac {
            let pi = lpac.inner.lock().ok()?;
            if pi.type_.contains(BapType::BCAST_SOURCE) {
                return Some(pi.data.clone());
            }
        }
        None
    }

    // ---- Internal helpers ----

    fn set_state_internal(&self, new_state: BapStreamState) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.state = new_state;
        }
    }

    fn get_ase_id(&self) -> u8 {
        if let Ok(inner) = self.inner.lock() {
            if let Some(bap_weak) = &inner.bap {
                if let Some(bap_arc) = bap_weak.upgrade() {
                    if let Ok(bap_inner) = bap_arc.lock() {
                        if let Some(idx) = inner.ep {
                            if idx < bap_inner.remote_eps.len() {
                                return bap_inner.remote_eps[idx].id;
                            }
                        }
                    }
                }
            }
        }
        0
    }

    fn get_links_snapshot(&self) -> Vec<BtBapStream> {
        self.inner.lock().map(|i| i.links.clone()).unwrap_or_default()
    }

    fn build_config_pdu(&self, cc_data: &[u8]) -> Vec<u8> {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let ase_id = self.get_ase_id();

        let target_latency = match &inner.qos {
            BapQos::Ucast(u) => u.target_latency,
            BapQos::Bcast(_) => BapConfigLatency::Balanced as u8,
        };

        let phy = match &inner.qos {
            BapQos::Ucast(u) => u.io_qos.phys,
            BapQos::Bcast(b) => b.io_qos.phys,
        };

        let codec = if let Some(ref rpac) = inner.rpac {
            if let Ok(pi) = rpac.inner.lock() { pi.codec } else { BapCodec::default() }
        } else {
            BapCodec::default()
        };

        // Header: op + num ASEs.
        let mut pdu = Vec::with_capacity(2 + 1 + 1 + 1 + 5 + 1 + cc_data.len());
        pdu.push(ASCS_CONFIG); // op
        pdu.push(1); // num ASEs
        pdu.push(ase_id);
        pdu.push(target_latency);
        pdu.push(phy);
        // Codec ID (5 bytes).
        pdu.push(codec.id);
        pdu.extend_from_slice(&codec.cid.to_le_bytes());
        pdu.extend_from_slice(&codec.vid.to_le_bytes());
        // CC length + data.
        pdu.push(cc_data.len() as u8);
        pdu.extend_from_slice(cc_data);

        pdu
    }

    fn build_qos_pdu(&self, qos: &BapQos) -> Vec<u8> {
        let ase_id = self.get_ase_id();
        match qos {
            BapQos::Ucast(u) => {
                let mut pdu = Vec::with_capacity(2 + 15);
                pdu.push(ASCS_QOS);
                pdu.push(1); // num ASEs
                pdu.push(ase_id);
                pdu.push(u.cig_id);
                pdu.push(u.cis_id);
                // SDU interval (3 bytes LE).
                let interval = u.io_qos.interval;
                pdu.push((interval & 0xFF) as u8);
                pdu.push(((interval >> 8) & 0xFF) as u8);
                pdu.push(((interval >> 16) & 0xFF) as u8);
                pdu.push(u.framing);
                pdu.push(u.io_qos.phys);
                pdu.extend_from_slice(&u.io_qos.sdu.to_le_bytes());
                pdu.push(u.io_qos.rtn);
                pdu.extend_from_slice(&u.io_qos.latency.to_le_bytes());
                // Presentation delay (3 bytes LE).
                let pd = u.delay;
                pdu.push((pd & 0xFF) as u8);
                pdu.push(((pd >> 8) & 0xFF) as u8);
                pdu.push(((pd >> 16) & 0xFF) as u8);
                pdu
            }
            BapQos::Bcast(_) => {
                // Broadcast doesn't use ASCS QoS command.
                Vec::new()
            }
        }
    }

    fn build_enable_pdu(&self, metadata: &[u8]) -> Vec<u8> {
        let ase_id = self.get_ase_id();
        let mut pdu = Vec::with_capacity(2 + 1 + 1 + metadata.len());
        pdu.push(ASCS_ENABLE);
        pdu.push(1); // num ASEs
        pdu.push(ase_id);
        pdu.push(metadata.len() as u8);
        pdu.extend_from_slice(metadata);
        pdu
    }

    fn build_simple_pdu(&self, opcode: u8) -> Vec<u8> {
        let ase_id = self.get_ase_id();
        vec![opcode, 1, ase_id]
    }

    fn build_metadata_pdu(&self, metadata: &[u8]) -> Vec<u8> {
        let ase_id = self.get_ase_id();
        let mut pdu = Vec::with_capacity(2 + 1 + 1 + metadata.len());
        pdu.push(ASCS_METADATA);
        pdu.push(1); // num ASEs
        pdu.push(ase_id);
        pdu.push(metadata.len() as u8);
        pdu.extend_from_slice(metadata);
        pdu
    }
}

/// Convert stream state to human-readable string.
pub fn bt_bap_stream_statestr(state: u8) -> &'static str {
    match BapStreamState::from_u8(state) {
        Some(BapStreamState::Idle) => "idle",
        Some(BapStreamState::Config) => "config",
        Some(BapStreamState::Qos) => "qos",
        Some(BapStreamState::Enabling) => "enabling",
        Some(BapStreamState::Streaming) => "streaming",
        Some(BapStreamState::Disabling) => "disabling",
        Some(BapStreamState::Releasing) => "releasing",
        None => "unknown",
    }
}

// ========================================================================
// Public PAC API Functions
// ========================================================================

/// Add a vendor-specific PAC record with full options (ops callback).
pub fn bt_bap_add_vendor_pac_full(
    _db: &GattDb,
    name: &str,
    type_: u8,
    id: u8,
    cid: u16,
    vid: u16,
    qos: &BapPacQos,
    data: &[u8],
    metadata: &[u8],
    ops: Arc<dyn BapPacOps>,
) -> BtBapPac {
    let bap_type = BapType::from_bits_truncate(type_);
    let codec = BapCodec::new_vendor(id, cid, vid);
    BtBapPac::new_inner(name, bap_type, codec, qos, data, metadata, Some(ops))
}

/// Add a vendor-specific PAC record.
pub fn bt_bap_add_vendor_pac(
    _db: &GattDb,
    name: &str,
    type_: u8,
    id: u8,
    cid: u16,
    vid: u16,
    qos: &BapPacQos,
    data: &[u8],
    metadata: &[u8],
) -> BtBapPac {
    let bap_type = BapType::from_bits_truncate(type_);
    let codec = BapCodec::new_vendor(id, cid, vid);
    BtBapPac::new_inner(name, bap_type, codec, qos, data, metadata, None)
}

/// Add a standard PAC record (non-vendor, cid=0, vid=0).
pub fn bt_bap_add_pac(
    _db: &GattDb,
    name: &str,
    type_: u8,
    id: u8,
    qos: &BapPacQos,
    data: &[u8],
    metadata: &[u8],
) -> BtBapPac {
    let bap_type = BapType::from_bits_truncate(type_);
    let codec = BapCodec::new(id);
    BtBapPac::new_inner(name, bap_type, codec, qos, data, metadata, None)
}

// ========================================================================
// Public BAP Session API Functions
// ========================================================================

/// Create a new BAP session.
pub fn bt_bap_new(ldb: GattDb, rdb: Option<GattDb>) -> BtBap {
    BtBap::new_inner(ldb, rdb)
}

/// Register a global BAP session callback. Returns registration ID.
pub fn bt_bap_register(
    added: Box<dyn Fn(&BtBap) + Send + Sync>,
    removed: Box<dyn Fn(&BtBap) + Send + Sync>,
) -> u32 {
    let id = next_id();
    with_registry(|reg| {
        reg.callbacks.push(BapGlobalCb { id, added_cb: added, removed_cb: removed });
    });
    id
}

/// Unregister a global BAP session callback.
pub fn bt_bap_unregister(id: u32) -> bool {
    let mut removed = false;
    with_registry(|reg| {
        let before = reg.callbacks.len();
        reg.callbacks.retain(|cb| cb.id != id);
        removed = reg.callbacks.len() < before;
    });
    removed
}

/// Find a BAP session by ATT transport and GATT database.
pub fn bt_bap_get_session(att: &Arc<Mutex<BtAtt>>, _db: &GattDb) -> Option<BtBap> {
    let mut result = None;
    with_registry(|reg| {
        for bap in &reg.sessions {
            if let Ok(inner) = bap.inner.lock() {
                if let Some(ref bap_att) = inner.att {
                    if Arc::ptr_eq(bap_att, att) {
                        result = Some(bap.clone());
                        return;
                    }
                }
            }
        }
    });
    result
}

/// Create a new BAP stream.
pub fn bt_bap_stream_new(
    bap: &BtBap,
    lpac: BtBapPac,
    rpac: BtBapPac,
    qos: &BapQos,
    data: &[u8],
) -> BtBapStream {
    BtBapStream::new(bap, lpac, rpac, qos, data)
}

// ========================================================================
// Broadcast BASE Parsing
// ========================================================================

/// Merge Level 2 and Level 3 codec capabilities.
pub fn bt_bap_merge_caps(l2_caps: &[u8], l3_caps: &[u8]) -> Vec<u8> {
    if l3_caps.is_empty() {
        return l2_caps.to_vec();
    }
    if l2_caps.is_empty() {
        return l3_caps.to_vec();
    }

    let mut merged = l2_caps.to_vec();
    ltv_foreach(l3_caps, |ltv_type, ltv_data| {
        let mut new_merged = Vec::new();
        let mut off = 0;
        while off < merged.len() {
            let len = merged[off] as usize;
            if len == 0 || off + 1 + len > merged.len() {
                break;
            }
            let entry_type = merged[off + 1];
            if entry_type != ltv_type {
                new_merged.extend_from_slice(&merged[off..off + 1 + len]);
            }
            off += 1 + len;
        }
        new_merged.push((1 + ltv_data.len()) as u8);
        new_merged.push(ltv_type);
        new_merged.extend_from_slice(ltv_data);
        merged = new_merged;
        true
    });

    merged
}

/// Parse a Broadcast Audio Source Endpoint (BASE) structure.
pub fn bt_bap_parse_base(
    sid: u8,
    base: &[u8],
    qos: &mut BapQos,
    debug: impl Fn(&str),
    mut handler: impl FnMut(u8, u8, u8, &[u8], &[u8], &BapQos),
) -> bool {
    if base.len() < 8 {
        return false;
    }
    let mut offset = 0;
    let pd = (base[offset] as u32)
        | ((base[offset + 1] as u32) << 8)
        | ((base[offset + 2] as u32) << 16);
    offset += 3;
    debug(&format!("Presentation Delay: {} us", pd));

    if offset >= base.len() {
        return false;
    }
    let num_subgroups = base[offset];
    offset += 1;
    debug(&format!("Number of Subgroups: {}", num_subgroups));

    for sgrp in 0..num_subgroups {
        if offset >= base.len() {
            break;
        }
        let num_bis = base[offset];
        offset += 1;
        debug(&format!("  Subgroup {}: {} BIS", sgrp, num_bis));

        if offset + 5 > base.len() {
            break;
        }
        let codec = BapCodec {
            id: base[offset],
            cid: u16::from_le_bytes([base[offset + 1], base[offset + 2]]),
            vid: u16::from_le_bytes([base[offset + 3], base[offset + 4]]),
        };
        offset += 5;
        {
            let c_id = codec.id;
            let c_cid = { codec.cid };
            let c_vid = { codec.vid };
            debug(&format!("  Codec: id=0x{:02x} cid=0x{:04x} vid=0x{:04x}", c_id, c_cid, c_vid));
        }

        if offset >= base.len() {
            break;
        }
        let l2_cc_len = base[offset] as usize;
        offset += 1;
        if offset + l2_cc_len > base.len() {
            break;
        }
        let l2_cc = base[offset..offset + l2_cc_len].to_vec();
        offset += l2_cc_len;

        if offset >= base.len() {
            break;
        }
        let l2_meta_len = base[offset] as usize;
        offset += 1;
        if offset + l2_meta_len > base.len() {
            break;
        }
        let l2_meta = base[offset..offset + l2_meta_len].to_vec();
        offset += l2_meta_len;

        if let BapQos::Bcast(bqos) = qos {
            bqos.delay = pd;
        }

        for _ in 0..num_bis {
            if offset >= base.len() {
                break;
            }
            let bis_index = base[offset];
            offset += 1;
            if offset >= base.len() {
                break;
            }
            let l3_cc_len = base[offset] as usize;
            offset += 1;
            if offset + l3_cc_len > base.len() {
                break;
            }
            let l3_cc = &base[offset..offset + l3_cc_len];
            offset += l3_cc_len;

            let merged_cc = bt_bap_merge_caps(&l2_cc, l3_cc);
            debug(&format!(
                "    BIS {}: cc_len={}, meta_len={}",
                bis_index,
                merged_cc.len(),
                l2_meta.len()
            ));
            handler(sgrp, bis_index, sid, &merged_cc, &l2_meta, qos);
        }
    }
    true
}

// ========================================================================
// QoS Conversion Functions
// ========================================================================

/// Default PA QoS for sink (broadcast).
///
/// This is a `bt_iso_qos` union initialized with broadcast defaults
/// matching the C `BAP_SINK_PA_QOS` constant.
pub fn bap_sink_pa_qos() -> bt_iso_qos {
    bt_iso_qos {
        bcast: bt_iso_bcast_qos {
            big: BT_ISO_QOS_BIG_UNSET,
            bis: BT_ISO_QOS_BIS_UNSET,
            sync_factor: BT_ISO_SYNC_FACTOR,
            packing: 0,
            framing: 0,
            in_qos: bt_iso_io_qos::default(),
            out_qos: bt_iso_io_qos::default(),
            encryption: 0,
            bcode: [0u8; 16],
            options: 0,
            skip: 0,
            sync_timeout: BT_ISO_SYNC_TIMEOUT,
            sync_cte_type: 0,
            mse: 0,
            timeout: 0,
        },
    }
}

/// A lazily-initialized default PA QoS for sink.
pub static BAP_SINK_PA_QOS: std::sync::LazyLock<bt_iso_qos> =
    std::sync::LazyLock::new(bap_sink_pa_qos);

/// Convert kernel unicast ISO QoS to BAP QoS (safe: reads typed struct, not union).
pub fn bap_iso_ucast_to_bap_qos(ucast: &bt_iso_ucast_qos) -> BapQos {
    BapQos::Ucast(BapUcastQos {
        cig_id: ucast.cig,
        cis_id: ucast.cis,
        framing: ucast.framing,
        delay: 0,
        target_latency: 0,
        io_qos: BapIoQos {
            interval: ucast.in_qos.interval,
            latency: ucast.in_qos.latency,
            sdu: ucast.in_qos.sdu,
            phys: ucast.in_qos.phys,
            rtn: ucast.in_qos.rtn,
        },
    })
}

/// Convert kernel broadcast ISO QoS to BAP QoS (safe: reads typed struct, not union).
pub fn bap_iso_bcast_to_bap_qos(bcast: &bt_iso_bcast_qos) -> BapQos {
    BapQos::Bcast(BapBcastQos {
        big: bcast.big,
        bis: bcast.bis,
        sync_factor: bcast.sync_factor,
        packing: bcast.packing,
        framing: bcast.framing,
        encryption: bcast.encryption,
        bcode: if bcast.bcode == [0u8; 16] { None } else { Some(bcast.bcode.to_vec()) },
        options: bcast.options,
        skip: bcast.skip,
        sync_timeout: bcast.sync_timeout,
        sync_cte_type: bcast.sync_cte_type,
        mse: bcast.mse,
        timeout: bcast.timeout,
        pa_sync: 0,
        io_qos: BapIoQos {
            interval: bcast.in_qos.interval,
            latency: bcast.in_qos.latency,
            sdu: bcast.in_qos.sdu,
            phys: bcast.in_qos.phys,
            rtn: bcast.in_qos.rtn,
        },
        delay: 0,
    })
}

/// Convert kernel ISO QoS to BAP QoS.
///
/// Since `bt_iso_qos` is a C union (reading requires `unsafe`), this function
/// accepts a discriminant (`is_bcast`) and the individual QoS structs so the
/// caller — which knows the context — can extract the variant safely at the
/// FFI boundary.
///
/// If `is_bcast` is true, `bcast` is used; otherwise `ucast` is used.
pub fn bap_iso_qos_to_bap_qos(
    is_bcast: bool,
    ucast: &bt_iso_ucast_qos,
    bcast: &bt_iso_bcast_qos,
) -> BapQos {
    if is_bcast { bap_iso_bcast_to_bap_qos(bcast) } else { bap_iso_ucast_to_bap_qos(ucast) }
}

/// Convert BAP QoS to kernel ISO QoS union (safe: constructing a union is safe).
/// Helper to construct a `bt_iso_io_qos` from BAP I/O QoS, avoiding FUS
/// with a private `_pad` field.
fn make_iso_io_qos(bap_io: &BapIoQos) -> bt_iso_io_qos {
    let mut q = bt_iso_io_qos::default();
    q.interval = bap_io.interval;
    q.latency = bap_io.latency;
    q.sdu = bap_io.sdu;
    q.phys = bap_io.phys;
    q.rtn = bap_io.rtn;
    q
}

pub fn bap_qos_to_iso_qos(bap_qos: &BapQos) -> bt_iso_qos {
    match bap_qos {
        BapQos::Ucast(u) => bt_iso_qos {
            ucast: bt_iso_ucast_qos {
                cig: u.cig_id,
                cis: u.cis_id,
                sca: 0,
                packing: 0,
                framing: u.framing,
                in_qos: make_iso_io_qos(&u.io_qos),
                out_qos: bt_iso_io_qos::default(),
            },
        },
        BapQos::Bcast(b) => {
            let mut bcode = [0u8; 16];
            if let Some(ref bc) = b.bcode {
                let len = bc.len().min(16);
                bcode[..len].copy_from_slice(&bc[..len]);
            }
            bt_iso_qos {
                bcast: bt_iso_bcast_qos {
                    big: b.big,
                    bis: b.bis,
                    sync_factor: b.sync_factor,
                    packing: b.packing,
                    framing: b.framing,
                    in_qos: make_iso_io_qos(&b.io_qos),
                    out_qos: bt_iso_io_qos::default(),
                    encryption: b.encryption,
                    bcode,
                    options: b.options,
                    skip: b.skip,
                    sync_timeout: b.sync_timeout,
                    sync_cte_type: b.sync_cte_type,
                    mse: b.mse,
                    timeout: b.timeout,
                },
            }
        }
    }
}
