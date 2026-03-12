// SPDX-License-Identifier: GPL-2.0-or-later
//
// crates/bluez-emulator/src/bthost.rs - In-memory Bluetooth Host model
//
// Complete Rust rewrite of BlueZ emulator/bthost.c and emulator/bthost.h.
// Provides an emulated host that speaks H:4 transport, manages HCI command
// credit flow, ACL/SCO/ISO packet framing, L2CAP signaling, minimal RFCOMM,
// and SMP routing.

use std::collections::{HashMap, VecDeque};
use std::io::IoSlice;

use bytes::{BufMut, BytesMut};

use bluez_shared::sys::bluetooth::{
    BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, BT_VOICE_CVSD_16BIT,
};
use bluez_shared::sys::hci::{
    ACL_CONT, ACL_START, ACL_START_NO_FLUSH, EVT_AUTH_COMPLETE, EVT_CMD_COMPLETE, EVT_CMD_STATUS,
    EVT_CONN_COMPLETE, EVT_CONN_REQUEST, EVT_DISCONN_COMPLETE, EVT_ENCRYPT_CHANGE,
    EVT_IO_CAPABILITY_REQUEST, EVT_IO_CAPABILITY_RESPONSE, EVT_LE_CONN_COMPLETE, EVT_LE_META_EVENT,
    EVT_LINK_KEY_NOTIFY, EVT_LINK_KEY_REQ, EVT_NUM_COMP_PKTS, EVT_PIN_CODE_REQ,
    EVT_SIMPLE_PAIRING_COMPLETE, EVT_USER_CONFIRM_REQUEST, HCI_ACL_HDR_SIZE, HCI_ACLDATA_PKT,
    HCI_COMMAND_HDR_SIZE, HCI_COMMAND_PKT, HCI_EVENT_PKT, HCI_ISO_HDR_SIZE, HCI_ISODATA_PKT,
    HCI_SCO_HDR_SIZE, HCI_SCODATA_PKT, OCF_ACCEPT_CONN_REQ, OCF_ACCEPT_SYNC_CONN_REQ,
    OCF_AUTH_REQUESTED, OCF_CREATE_CONN, OCF_DISCONNECT, OCF_IO_CAPABILITY_REPLY,
    OCF_LE_CREATE_CONN, OCF_LE_LTK_NEG_REPLY, OCF_LE_LTK_REPLY, OCF_LE_SET_ADVERTISE_ENABLE,
    OCF_LE_SET_ADVERTISING_DATA, OCF_LE_SET_ADVERTISING_PARAMETERS, OCF_LE_SET_EXT_ADV_ENABLE,
    OCF_LE_START_ENCRYPTION, OCF_LINK_KEY_NEG_REPLY, OCF_PIN_CODE_NEG_REPLY, OCF_PIN_CODE_REPLY,
    OCF_READ_BD_ADDR, OCF_READ_LOCAL_FEATURES, OCF_RESET, OCF_SET_CONN_ENCRYPT,
    OCF_SETUP_SYNC_CONN, OCF_USER_CONFIRM_NEG_REPLY, OCF_USER_CONFIRM_REPLY, OCF_WRITE_SCAN_ENABLE,
    OCF_WRITE_SIMPLE_PAIRING_MODE, OGF_HOST_CTL, OGF_INFO_PARAM, OGF_LE_CTL, OGF_LINK_CONTROL,
    acl_flags, acl_handle, acl_handle_pack, opcode,
};
use bluez_shared::sys::l2cap::{
    L2CAP_CMD_HDR_SIZE, L2CAP_CONF_REQ, L2CAP_CONF_RSP, L2CAP_CONF_SUCCESS, L2CAP_CONN_REQ,
    L2CAP_CONN_RSP, L2CAP_CR_BAD_PSM, L2CAP_CR_SUCCESS, L2CAP_CS_NO_INFO, L2CAP_DISCONN_REQ,
    L2CAP_DISCONN_RSP, L2CAP_ECRED_CONN_REQ, L2CAP_ECRED_CONN_RSP, L2CAP_FC_L2CAP, L2CAP_HDR_SIZE,
    L2CAP_INFO_REQ, L2CAP_INFO_RSP, L2CAP_IT_FEAT_MASK, L2CAP_LE_CONN_REQ, L2CAP_LE_CONN_RSP,
};

// ---- Local HCI OCF constants not in bluez-shared ----
const OCF_WRITE_LE_HOST_SUPPORTED: u16 = 0x006D; // OGF_HOST_CTL
const OCF_WRITE_SC_SUPPORT: u16 = 0x007A; // OGF_HOST_CTL
const OCF_LE_SET_EXT_ADV_PARAMS: u16 = 0x0036;
const OCF_LE_SET_EXT_ADV_DATA: u16 = 0x0037;
const OCF_LE_SET_EXT_SCAN_PARAMS: u16 = 0x0041;
const OCF_LE_SET_EXT_SCAN_ENABLE: u16 = 0x0042;
const OCF_LE_EXT_CREATE_CONN: u16 = 0x0043;
const OCF_LE_SET_PA_PARAMS: u16 = 0x003E;
const OCF_LE_SET_PA_DATA: u16 = 0x003F;
const OCF_LE_SET_PA_ENABLE: u16 = 0x0040;
// OCF_LE_PA_CREATE_SYNC_TRANSFER = 0x005A (handled via PAST_SET_INFO)
const OCF_LE_PAST_SET_INFO: u16 = 0x005B;
const OCF_LE_PAST_PARAMS: u16 = 0x005C;
// OCF_LE_SET_DEFAULT_PAST_PARAMS = 0x005D (not needed in bthost)
const OCF_LE_SET_CIG_PARAMS: u16 = 0x0062;
const OCF_LE_CREATE_CIS: u16 = 0x0064;
const OCF_LE_ACCEPT_CIS: u16 = 0x0066;
const OCF_LE_CREATE_BIG: u16 = 0x0068;
const OCF_LE_TERMINATE_BIG: u16 = 0x006A;
// OCF_LE_BIG_CREATE_SYNC = 0x006B (not needed in bthost)

// ---- Local HCI event constants not in bluez-shared ----
const EVT_SYNC_CONN_COMPLETE: u8 = 0x2C;
const EVT_LE_ENHANCED_CONN_COMPLETE: u8 = 0x0A;
const EVT_LE_ENHANCED_CONN_COMPLETE_V2: u8 = 0x29;
const EVT_LE_EXT_ADV_REPORT: u8 = 0x0D;
const EVT_LE_PA_SYNC_ESTABLISHED: u8 = 0x0E;
const EVT_LE_PA_SYNC_ESTABLISHED_V2: u8 = 0x24;
const EVT_LE_CIS_ESTABLISHED: u8 = 0x19;
const EVT_LE_CIS_REQUEST: u8 = 0x1A;
const EVT_LE_CREATE_BIG_COMPLETE: u8 = 0x1B;
const EVT_LE_BIG_SYNC_ESTABLISHED: u8 = 0x1D;
// EVT_LE_BIG_INFO_ADV_REPORT = 0x22 (not handled in bthost)

// L2CAP fixed-channel constants
// ---- Local L2CAP constants not in bluez-shared ----
const L2CAP_CID_BREDR_SIG: u16 = 0x0001;
const L2CAP_CID_LE_SIG: u16 = 0x0005;
const L2CAP_CID_SMP: u16 = 0x0006;
const L2CAP_CID_SMP_BREDR: u16 = 0x0007;
const L2CAP_IT_FIXED_CHAN: u16 = 0x0003;
const L2CAP_FC_SIG_BREDR: u64 = 0x0002;
// L2CAP_FC_SMP = 0x0040 (LE SMP handled via CID dispatch, not fixed chan bitmap)
const L2CAP_FC_SMP_BREDR: u64 = 0x0080;
const L2CAP_FEAT_FIXED_CHAN: u32 = 0x0000_0080;
const L2CAP_CONN_PARAM_REQ: u8 = 0x12;
const L2CAP_LE_CONN_PARAM_RSP: u8 = 0x13;
const L2CAP_LE_FLOWCTL_CREDS: u8 = 0x16;

// RFCOMM constants
const RFCOMM_PSM: u16 = 0x0003;
const RFCOMM_SABM: u8 = 0x2F;
const RFCOMM_DISC: u8 = 0x43;
const RFCOMM_UA: u8 = 0x63;
const RFCOMM_DM: u8 = 0x0F;
const RFCOMM_UIH: u8 = 0xEF;
const RFCOMM_PF: u8 = 0x10;
const RFCOMM_MCC_CMD: u8 = 1;
const RFCOMM_MCC_PN: u8 = 0x20;
const RFCOMM_MCC_MSC: u8 = 0x38;
const fn rfcomm_addr(cr: u8, dlci: u8) -> u8 {
    (dlci << 2) | (cr << 1) | 0x01
}
const fn rfcomm_ctrl(ft: u8, pf: u8) -> u8 {
    (ft & 0xEF) | (pf << 4)
}
const fn rfcomm_len8(len: u8) -> u8 {
    (len << 1) | 1
}
const fn rfcomm_mcc_type(cr: u8, mcc: u8) -> u8 {
    (mcc << 2) | (cr << 1) | 0x01
}
const BT_PA_MAX_DATA_LEN: usize = 252;
const BAA_SERVICE_UUID16: u16 = 0x1851;

// RFCOMM CRC table (ITU-T V.41 reversed)
#[rustfmt::skip]
const RFCOMM_CRC_TABLE: [u8; 256] = [
    0x00,0x91,0xE3,0x72,0x07,0x96,0xE4,0x75,0x0E,0x9F,0xED,0x7C,0x09,0x98,0xEA,0x7B,
    0x1C,0x8D,0xFF,0x6E,0x1B,0x8A,0xF8,0x69,0x12,0x83,0xF1,0x60,0x15,0x84,0xF6,0x67,
    0x38,0xA9,0xDB,0x4A,0x3F,0xAE,0xDC,0x4D,0x36,0xA7,0xD5,0x44,0x31,0xA0,0xD2,0x43,
    0x24,0xB5,0xC7,0x56,0x23,0xB2,0xC0,0x51,0x2A,0xBB,0xC9,0x58,0x2D,0xBC,0xCE,0x5F,
    0x70,0xE1,0x93,0x02,0x77,0xE6,0x94,0x05,0x7E,0xEF,0x9D,0x0C,0x79,0xE8,0x9A,0x0B,
    0x6C,0xFD,0x8F,0x1E,0x6B,0xFA,0x88,0x19,0x62,0xF3,0x81,0x10,0x65,0xF4,0x86,0x17,
    0x48,0xD9,0xAB,0x3A,0x4F,0xDE,0xAC,0x3D,0x46,0xD7,0xA5,0x34,0x41,0xD0,0xA2,0x33,
    0x54,0xC5,0xB7,0x26,0x53,0xC2,0xB0,0x21,0x5A,0xCB,0xB9,0x28,0x5D,0xCC,0xBE,0x2F,
    0xE0,0x71,0x03,0x92,0xE7,0x76,0x04,0x95,0xEE,0x7F,0x0D,0x9C,0xE9,0x78,0x0A,0x9B,
    0xFC,0x6D,0x1F,0x8E,0xFB,0x6A,0x18,0x89,0xF2,0x63,0x11,0x80,0xF5,0x64,0x16,0x87,
    0xD8,0x49,0x3B,0xAA,0xDF,0x4E,0x3C,0xAD,0xD6,0x47,0x35,0xA4,0xD1,0x40,0x32,0xA3,
    0xC4,0x55,0x27,0xB6,0xC3,0x52,0x20,0xB1,0xCA,0x5B,0x29,0xB8,0xCD,0x5C,0x2E,0xBF,
    0x90,0x01,0x73,0xE2,0x97,0x06,0x74,0xE5,0x9E,0x0F,0x7D,0xEC,0x99,0x08,0x7A,0xEB,
    0x8C,0x1D,0x6F,0xFE,0x8B,0x1A,0x68,0xF9,0x82,0x13,0x61,0xF0,0x85,0x14,0x66,0xF7,
    0xA8,0x39,0x4B,0xDA,0xAF,0x3E,0x4C,0xDD,0xA6,0x37,0x45,0xD4,0xA1,0x30,0x42,0xD3,
    0xB4,0x25,0x57,0xC6,0xB3,0x22,0x50,0xC1,0xBA,0x2B,0x59,0xC8,0xBD,0x2C,0x5E,0xCF,
];

fn rfcomm_fcs2(d: &[u8]) -> u8 {
    let c = RFCOMM_CRC_TABLE[(0xFFu8 ^ d[0]) as usize];
    0xFF - RFCOMM_CRC_TABLE[(c ^ d[1]) as usize]
}

fn rfcomm_fcs3(d: &[u8]) -> u8 {
    let c = RFCOMM_CRC_TABLE[(0xFFu8 ^ d[0]) as usize];
    let c = RFCOMM_CRC_TABLE[(c ^ d[1]) as usize];
    0xFF - RFCOMM_CRC_TABLE[(c ^ d[2]) as usize]
}

// ---------------------------------------------------------------------------
// SMP trait
// ---------------------------------------------------------------------------
/// Security Manager Protocol operations required by BtHost.
pub trait SmpManager: Send + Sync {
    fn conn_add(
        &mut self,
        handle: u16,
        ia: &[u8; 6],
        ia_type: u8,
        ra: &[u8; 6],
        ra_type: u8,
        smp_over_bredr: bool,
    );
    fn conn_del(&mut self, handle: u16);
    fn conn_encrypted(&mut self, handle: u16, encrypt: u8);
    fn data(&mut self, handle: u16, data: &[u8]);
    fn bredr_data(&mut self, handle: u16, data: &[u8]);
    fn get_ltk(&self, handle: u16) -> Option<[u8; 16]>;
    fn pair(&mut self, handle: u16, io_cap: u8, auth_req: u8);
}
struct NoopSmpManager;
impl SmpManager for NoopSmpManager {
    fn conn_add(&mut self, _: u16, _: &[u8; 6], _: u8, _: &[u8; 6], _: u8, _: bool) {}
    fn conn_del(&mut self, _: u16) {}
    fn conn_encrypted(&mut self, _: u16, _: u8) {}
    fn data(&mut self, _: u16, _: &[u8]) {}
    fn bredr_data(&mut self, _: u16, _: &[u8]) {}
    fn get_ltk(&self, _: u16) -> Option<[u8; 16]> {
        None
    }
    fn pair(&mut self, _: u16, _: u8, _: u8) {}
}

// ---------------------------------------------------------------------------
// Internal structures
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq, Eq)]
enum L2capMode {
    Basic,
    LeCred,
    LeEnhCred,
}

struct CidHook {
    cid: u16,
    func: Box<dyn Fn(&[u8]) + Send + Sync>,
}
struct ScoHook {
    func: Box<dyn Fn(&[u8], u8) + Send + Sync>,
}
struct IsoHook {
    func: Box<dyn Fn(&[u8]) + Send + Sync>,
}
struct RfcommChanHook {
    func: Box<dyn Fn(&[u8]) + Send + Sync>,
}

struct L2conn {
    scid: u16,
    dcid: u16,
    psm: u16,
    mtu: u16,
    mode: L2capMode,
    _rx_mps: u16,
    tx_mps: u16,
    _rx_credits: u16,
    tx_credits: u16,
    _recv_data: Vec<u8>,
    _recv_len: u16,
}
struct RcConn {
    dlci: u8,
    cid: u16,
    _active: bool,
    _mtu: u16,
    chan_hooks: Vec<RfcommChanHook>,
}
struct BtConn {
    _handle: u16,
    addr: [u8; 6],
    addr_type: u8,
    encr_mode: u8,
    next_cid: u16,
    l2conns: Vec<L2conn>,
    rfcomm_chans: Vec<RcConn>,
    cid_hooks: Vec<CidHook>,
    sco_hooks: Vec<ScoHook>,
    iso_hooks: Vec<IsoHook>,
    _smp_conn_active: bool,
    fixed_chan: u64,
    acl_buf: Vec<u8>,
    iso_buf: Vec<u8>,
}
struct L2capServer {
    psm: u16,
    connect_cb: Box<dyn Fn(u16, u16) + Send + Sync>,
    disconn_cb: Option<Box<dyn Fn(u16, u16) + Send + Sync>>,
    mtu: u16,
    mps: u16,
    credits: u16,
}
type L2capReqCb = Box<dyn Fn(u8, &[u8]) + Send + Sync>;

struct RfcommServer {
    channel: u8,
    connect_cb: Box<dyn Fn(u16, u16, bool) + Send + Sync>,
}
struct L2capPendingReq {
    handle: u16,
    ident: u8,
    code: u8,
    data: Vec<u8>,
    cb: Option<L2capReqCb>,
}
struct RfcommConnectionData {
    channel: u8,
    cb: Box<dyn Fn(u16, u16, bool) + Send + Sync>,
}
struct Cmd {
    data: Vec<u8>,
}
struct LeExtAdv {
    _addr_type: u8,
    addr: [u8; 6],
    _direct_addr_type: u8,
    _direct_addr: [u8; 6],
}

// ---------------------------------------------------------------------------
// BtHost — the main public type
// ---------------------------------------------------------------------------

/// In-memory Bluetooth Host model for HCI emulator testing.
///
/// Speaks H:4 transport protocol, tracks HCI command credits, manages
type SendHandler = Box<dyn Fn(&[IoSlice<'_>]) + Send + Sync>;
type CmdCompleteCb = Box<dyn Fn(u16, u8, &[u8]) + Send + Sync>;

/// connections, and implements L2CAP signaling, minimal RFCOMM, and SMP
/// routing. This is a behavioural clone of the C `struct bthost`.
pub struct BtHost {
    send_handler: Option<SendHandler>,
    ncmd: u8,
    cmd_queue: VecDeque<Cmd>,
    connections: HashMap<u16, BtConn>,
    l2cap_servers: Vec<L2capServer>,
    rfcomm_servers: Vec<RfcommServer>,
    l2cap_pending: Vec<L2capPendingReq>,
    bdaddr: [u8; 6],
    features: [u8; 8],
    acl_mtu: u16,
    iso_mtu: u16,
    pin: Option<Vec<u8>>,
    io_capability: u8,
    auth_req: u8,
    sc_support: bool,
    reject_user_confirm: bool,
    ssp_mode: bool,
    le_host_supported: bool,
    ready_cb: Option<Box<dyn FnOnce() + Send>>,
    cmd_complete_cb: Option<CmdCompleteCb>,
    connect_cb: Option<Box<dyn Fn(u16) + Send + Sync>>,
    sco_cb: Option<Box<dyn Fn(u16) + Send + Sync>>,
    iso_cb: Option<Box<dyn Fn(u16) + Send + Sync>>,
    debug_callback: Option<Box<dyn Fn(&str) + Send + Sync>>,
    smp: Box<dyn SmpManager>,
    conn_init: bool,
    le: bool,
    sig_ident: u8,
    rfcomm_conn_data: Option<RfcommConnectionData>,
    le_ext_advs: Vec<LeExtAdv>,
}

impl Default for BtHost {
    fn default() -> Self {
        Self::new()
    }
}

impl BtHost {
    /// Create a new BtHost instance (replaces `bthost_create`).
    pub fn new() -> Self {
        Self {
            send_handler: None,
            ncmd: 1,
            cmd_queue: VecDeque::new(),
            connections: HashMap::new(),
            l2cap_servers: Vec::new(),
            rfcomm_servers: Vec::new(),
            l2cap_pending: Vec::new(),
            bdaddr: [0u8; 6],
            features: [0u8; 8],
            acl_mtu: u16::MAX,
            iso_mtu: u16::MAX,
            pin: None,
            io_capability: 0x03,
            auth_req: 0x00,
            sc_support: false,
            reject_user_confirm: false,
            ssp_mode: false,
            le_host_supported: false,
            ready_cb: None,
            cmd_complete_cb: None,
            connect_cb: None,
            sco_cb: None,
            iso_cb: None,
            debug_callback: None,
            smp: Box::new(NoopSmpManager),
            conn_init: false,
            le: false,
            sig_ident: 0,
            rfcomm_conn_data: None,
            le_ext_advs: Vec::new(),
        }
    }

    /// Boot the emulated host (replaces `bthost_start`).
    ///
    /// Sends HCI Reset, Read Local Features, and Read BD_ADDR.
    pub fn start(&mut self) {
        self.ncmd = 1;
        self.send_command(opcode(OGF_HOST_CTL, OCF_RESET), &[]);
        self.send_command(opcode(OGF_INFO_PARAM, OCF_READ_LOCAL_FEATURES), &[]);
        self.send_command(opcode(OGF_INFO_PARAM, OCF_READ_BD_ADDR), &[]);
    }

    // -----------------------------------------------------------------------
    // Configuration setters
    // -----------------------------------------------------------------------

    /// Set the callback invoked to transmit H:4 packets to the controller.
    pub fn set_send_handler(&mut self, handler: impl Fn(&[IoSlice<'_>]) + Send + Sync + 'static) {
        self.send_handler = Some(Box::new(handler));
    }

    pub fn set_acl_mtu(&mut self, mtu: u16) {
        self.acl_mtu = mtu;
    }
    pub fn set_iso_mtu(&mut self, mtu: u16) {
        self.iso_mtu = mtu;
    }

    pub fn set_debug(&mut self, callback: impl Fn(&str) + Send + Sync + 'static) {
        self.debug_callback = Some(Box::new(callback));
    }

    pub fn notify_ready(&mut self, cb: impl FnOnce() + Send + 'static) {
        self.ready_cb = Some(Box::new(cb));
    }

    pub fn set_cmd_complete_cb(&mut self, cb: impl Fn(u16, u8, &[u8]) + Send + Sync + 'static) {
        self.cmd_complete_cb = Some(Box::new(cb));
    }

    pub fn set_connect_cb(&mut self, cb: impl Fn(u16) + Send + Sync + 'static) {
        self.connect_cb = Some(Box::new(cb));
    }

    pub fn set_sco_cb(&mut self, cb: impl Fn(u16) + Send + Sync + 'static) {
        self.sco_cb = Some(Box::new(cb));
    }

    pub fn set_iso_cb(&mut self, cb: impl Fn(u16) + Send + Sync + 'static) {
        self.iso_cb = Some(Box::new(cb));
    }

    // -----------------------------------------------------------------------
    // Internal packet send helpers
    // -----------------------------------------------------------------------

    fn debug_log(&self, msg: &str) {
        if let Some(ref cb) = self.debug_callback {
            cb(msg);
        }
    }

    fn send_packet(&self, data: &[u8]) {
        if let Some(ref handler) = self.send_handler {
            handler(&[IoSlice::new(data)]);
        }
    }

    fn send_command(&mut self, op: u16, params: &[u8]) {
        let plen = params.len() as u8;
        let mut buf = Vec::with_capacity(1 + HCI_COMMAND_HDR_SIZE + params.len());
        buf.push(HCI_COMMAND_PKT);
        buf.extend_from_slice(&op.to_le_bytes());
        buf.push(plen);
        buf.extend_from_slice(params);
        if self.ncmd > 0 {
            self.send_packet(&buf);
            self.ncmd -= 1;
        } else {
            self.cmd_queue.push_back(Cmd { data: buf });
        }
    }

    fn next_cmd(&mut self) {
        if self.ncmd > 0 {
            if let Some(cmd) = self.cmd_queue.pop_front() {
                self.send_packet(&cmd.data);
                self.ncmd -= 1;
            }
        }
    }

    fn next_sig_ident(&mut self) -> u8 {
        self.sig_ident = self.sig_ident.wrapping_add(1);
        if self.sig_ident == 0 {
            self.sig_ident = 1;
        }
        self.sig_ident
    }

    /// Send an ACL data packet, fragmenting to `acl_mtu` if necessary.
    fn send_acl_raw(&self, handle: u16, cid: u16, data: &[u8], sdu_prefix: bool) {
        let l2cap_payload_len = if sdu_prefix { data.len() + 2 } else { data.len() };
        // Build complete L2CAP frame: hdr + optional SDU len + data
        let mut l2cap_frame = BytesMut::with_capacity(L2CAP_HDR_SIZE + l2cap_payload_len);
        l2cap_frame.extend_from_slice(&(l2cap_payload_len as u16).to_le_bytes());
        l2cap_frame.extend_from_slice(&cid.to_le_bytes());
        if sdu_prefix {
            l2cap_frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        l2cap_frame.extend_from_slice(data);

        let max_frag = if self.acl_mtu < u16::MAX {
            (self.acl_mtu as usize).saturating_sub(1 + HCI_ACL_HDR_SIZE)
        } else {
            usize::MAX
        };

        let total = l2cap_frame.len();
        let mut offset = 0usize;
        let mut first = true;
        while offset < total {
            let chunk = (total - offset).min(max_frag);
            let flags: u16 = if first { 0x0000 } else { 0x0001 };
            let hflags = acl_handle_pack(handle, flags);
            let dlen = chunk as u16;
            let mut pkt = Vec::with_capacity(1 + HCI_ACL_HDR_SIZE + chunk);
            pkt.push(HCI_ACLDATA_PKT);
            pkt.extend_from_slice(&hflags.to_le_bytes());
            pkt.extend_from_slice(&dlen.to_le_bytes());
            pkt.extend_from_slice(&l2cap_frame[offset..offset + chunk]);
            self.send_packet(&pkt);
            offset += chunk;
            first = false;
        }
    }

    /// Send L2CAP signaling command on the appropriate CID.
    fn l2cap_sig_send(&mut self, handle: u16, is_le: bool, code: u8, ident: u8, data: &[u8]) {
        let cid = if is_le { L2CAP_CID_LE_SIG } else { L2CAP_CID_BREDR_SIG };
        let mut sig = Vec::with_capacity(L2CAP_CMD_HDR_SIZE + data.len());
        sig.push(code);
        let ident_val = if ident == 0 { self.next_sig_ident() } else { ident };
        sig.push(ident_val);
        sig.extend_from_slice(&(data.len() as u16).to_le_bytes());
        sig.extend_from_slice(data);
        self.send_acl_raw(handle, cid, &sig, false);
    }

    /// Send data on a specific L2CAP CID, handling LE credit-based segmentation.
    fn send_cid_internal(&self, handle: u16, cid: u16, data: &[u8]) {
        // Check for LE credit-based channel (find l2conn by scid matching cid)
        if let Some(conn) = self.connections.get(&handle) {
            if let Some(l2) = conn.l2conns.iter().find(|l| l.scid == cid) {
                if l2.mode == L2capMode::LeCred || l2.mode == L2capMode::LeEnhCred {
                    // Segment to tx_mps
                    let mps = l2.tx_mps as usize;
                    if mps == 0 {
                        return;
                    }
                    let total = data.len();
                    let mut off = 0;
                    let mut first_seg = true;
                    while off < total {
                        let seg_max = if first_seg { mps.saturating_sub(2) } else { mps };
                        let chunk = (total - off).min(seg_max);
                        if first_seg {
                            // First segment includes SDU length
                            let mut seg = Vec::with_capacity(2 + chunk);
                            seg.extend_from_slice(&(total as u16).to_le_bytes());
                            seg.extend_from_slice(&data[off..off + chunk]);
                            self.send_acl_raw(handle, l2.dcid, &seg, false);
                            first_seg = false;
                        } else {
                            self.send_acl_raw(handle, l2.dcid, &data[off..off + chunk], false);
                        }
                        off += chunk;
                    }
                    return;
                }
            }
        }
        // Regular L2CAP channel — find dcid
        let dcid = if let Some(conn) = self.connections.get(&handle) {
            conn.l2conns.iter().find(|l| l.scid == cid).map(|l| l.dcid).unwrap_or(cid)
        } else {
            cid
        };
        self.send_acl_raw(handle, dcid, data, false);
    }

    /// Send ISO data, fragmenting to iso_mtu if necessary.
    fn send_iso_internal(
        &self,
        handle: u16,
        ts: bool,
        sn: u16,
        timestamp: u32,
        pkt_status: u8,
        data: &[u8],
    ) {
        let sdu_len = data.len() as u16;
        let data_hdr_len: usize = if ts { 8 } else { 4 };
        let max_frag = if self.iso_mtu < u16::MAX {
            (self.iso_mtu as usize).saturating_sub(1 + HCI_ISO_HDR_SIZE)
        } else {
            usize::MAX
        };

        let total_payload = data_hdr_len + data.len();
        if total_payload <= max_frag {
            // Single complete packet (PB=0b10)
            let mut pkt = BytesMut::with_capacity(1 + HCI_ISO_HDR_SIZE + total_payload);
            pkt.put_u8(HCI_ISODATA_PKT);
            let h = (handle & 0x0FFF)
                | (0x02 << 12) // PB = complete
                | if ts { 1 << 14 } else { 0 };
            pkt.put_u16_le(h);
            pkt.put_u16_le(total_payload as u16);
            if ts {
                pkt.put_u32_le(timestamp);
            }
            pkt.put_u16_le(sn);
            let slen = sdu_len | ((pkt_status as u16 & 0x03) << 14);
            pkt.put_u16_le(slen);
            pkt.put_slice(data);
            let frozen = pkt.freeze();
            self.send_packet(&frozen);
        } else {
            // Fragmented
            let mut remaining = data;
            let mut first = true;
            while !remaining.is_empty() || first {
                let pb = if first {
                    0x00 // first fragment
                } else if remaining.len() + (if first { data_hdr_len } else { 0 }) <= max_frag {
                    0x03 // last fragment
                } else {
                    0x01 // continuation
                };
                let hdr_this = if first { data_hdr_len } else { 0 };
                let space = max_frag.saturating_sub(hdr_this);
                let chunk = remaining.len().min(space);
                let dlen = hdr_this + chunk;
                let mut pkt = BytesMut::with_capacity(1 + HCI_ISO_HDR_SIZE + dlen);
                pkt.put_u8(HCI_ISODATA_PKT);
                let h = (handle & 0x0FFF) | ((pb as u16) << 12) | if ts { 1u16 << 14 } else { 0 };
                pkt.put_u16_le(h);
                pkt.put_u16_le(dlen as u16);
                if first {
                    if ts {
                        pkt.put_u32_le(timestamp);
                    }
                    pkt.put_u16_le(sn);
                    let slen = sdu_len | ((pkt_status as u16 & 0x03) << 14);
                    pkt.put_u16_le(slen);
                }
                pkt.put_slice(&remaining[..chunk]);
                let frozen = pkt.freeze();
                self.send_packet(&frozen);
                remaining = &remaining[chunk..];
                first = false;
            }
        }
    }

    // -----------------------------------------------------------------------
    // H:4 Receive entry point
    // -----------------------------------------------------------------------

    /// Receive an H:4 packet from the controller.
    pub fn receive_h4(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match data[0] {
            HCI_EVENT_PKT => self.process_evt(&data[1..]),
            HCI_ACLDATA_PKT => self.process_acl(&data[1..]),
            HCI_SCODATA_PKT => self.process_sco(&data[1..]),
            HCI_ISODATA_PKT => self.process_iso(&data[1..]),
            _ => self.debug_log(&format!("bthost: unknown H4 type 0x{:02x}", data[0])),
        }
    }

    fn process_evt(&mut self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let evt = data[0];
        let plen = data[1] as usize;
        if data.len() < 2 + plen {
            return;
        }
        let params = &data[2..2 + plen];
        match evt {
            EVT_CMD_COMPLETE => self.evt_cmd_complete(params),
            EVT_CMD_STATUS => self.evt_cmd_status(params),
            EVT_CONN_COMPLETE => self.evt_conn_complete(params),
            EVT_CONN_REQUEST => self.evt_conn_request(params),
            EVT_DISCONN_COMPLETE => self.evt_disconn_complete(params),
            EVT_NUM_COMP_PKTS => {}
            EVT_AUTH_COMPLETE => self.evt_auth_complete(params),
            EVT_PIN_CODE_REQ => self.evt_pin_code_request(params),
            EVT_LINK_KEY_REQ => self.evt_link_key_request(params),
            EVT_LINK_KEY_NOTIFY => {}
            EVT_ENCRYPT_CHANGE => self.evt_encrypt_change(params),
            EVT_IO_CAPABILITY_REQUEST => self.evt_io_capability_request(params),
            EVT_IO_CAPABILITY_RESPONSE => {}
            EVT_USER_CONFIRM_REQUEST => self.evt_user_confirm_request(params),
            EVT_SIMPLE_PAIRING_COMPLETE => {}
            EVT_SYNC_CONN_COMPLETE => self.evt_sync_conn_complete(params),
            EVT_LE_META_EVENT => self.evt_le_meta(params),
            _ => self.debug_log(&format!("bthost: unhandled evt 0x{:02x}", evt)),
        }
    }

    fn evt_cmd_complete(&mut self, data: &[u8]) {
        if data.len() < 3 {
            return;
        }
        let ncmd = data[0];
        let op = u16::from_le_bytes([data[1], data[2]]);
        let status = if data.len() > 3 { data[3] } else { 0 };
        let params = if data.len() > 3 { &data[3..] } else { &[] };
        self.ncmd = ncmd;
        if let Some(ref cb) = self.cmd_complete_cb {
            cb(op, status, params);
        }
        match op {
            op if op == opcode(OGF_HOST_CTL, OCF_RESET) => {}
            op if op == opcode(OGF_INFO_PARAM, OCF_READ_LOCAL_FEATURES) => {
                if params.len() >= 9 {
                    self.features.copy_from_slice(&params[1..9]);
                }
            }
            op if op == opcode(OGF_INFO_PARAM, OCF_READ_BD_ADDR) => {
                if params.len() >= 7 {
                    self.bdaddr.copy_from_slice(&params[1..7]);
                }
                if let Some(cb) = self.ready_cb.take() {
                    cb();
                }
            }
            op if op == opcode(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE) => {}
            op if op == opcode(OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE) => {}
            op if op == opcode(OGF_HOST_CTL, OCF_WRITE_LE_HOST_SUPPORTED) => {}
            op if op == opcode(OGF_HOST_CTL, OCF_WRITE_SC_SUPPORT) => {}
            op if op == opcode(OGF_LINK_CONTROL, OCF_PIN_CODE_REPLY) => {}
            op if op == opcode(OGF_LINK_CONTROL, OCF_PIN_CODE_NEG_REPLY) => {}
            op if op == opcode(OGF_LINK_CONTROL, OCF_LINK_KEY_NEG_REPLY) => {}
            op if op == opcode(OGF_LINK_CONTROL, OCF_IO_CAPABILITY_REPLY) => {}
            op if op == opcode(OGF_LINK_CONTROL, OCF_USER_CONFIRM_REPLY) => {}
            op if op == opcode(OGF_LINK_CONTROL, OCF_USER_CONFIRM_NEG_REPLY) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_LTK_REPLY) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_LTK_NEG_REPLY) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_PARAMS) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_DATA) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_ENABLE) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_PA_PARAMS) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_PA_ENABLE) => {}
            op if op == opcode(OGF_LE_CTL, OCF_LE_SET_PA_DATA) => {}
            _ => {
                self.debug_log(&format!("bthost: unhandled cmd_complete 0x{:04x}", op));
            }
        }
        self.next_cmd();
    }

    fn evt_cmd_status(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        self.ncmd = data[1];
        self.next_cmd();
    }

    fn evt_conn_complete(&mut self, data: &[u8]) {
        if data.len() < 11 {
            return;
        }
        let status = data[0];
        let handle = u16::from_le_bytes([data[1], data[2]]);
        if status != 0 {
            return;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[3..9]);
        let encr_mode = data[10];
        let conn = BtConn {
            _handle: handle,
            addr,
            addr_type: BDADDR_BREDR,
            next_cid: 0x0040,
            l2conns: Vec::new(),
            cid_hooks: Vec::new(),
            sco_hooks: Vec::new(),
            iso_hooks: Vec::new(),
            rfcomm_chans: Vec::new(),
            _smp_conn_active: false,
            encr_mode,
            fixed_chan: 0x0002,
            acl_buf: Vec::new(),
            iso_buf: Vec::new(),
        };
        self.connections.insert(handle, conn);
        self.init_conn(handle);
    }

    fn init_conn(&mut self, handle: u16) {
        let (addr_type, remote_addr) = self
            .connections
            .get(&handle)
            .map(|c| (c.addr_type, c.addr))
            .unwrap_or((BDADDR_BREDR, [0u8; 6]));
        let is_bredr = addr_type == BDADDR_BREDR;
        if is_bredr {
            let mut req = Vec::with_capacity(2);
            req.extend_from_slice(&L2CAP_IT_FEAT_MASK.to_le_bytes());
            self.l2cap_sig_send(handle, false, L2CAP_INFO_REQ, 0, &req);
        }
        if !is_bredr {
            // ia = local, ra = remote, smp_over_bredr = false for LE
            let ia = self.bdaddr;
            let ia_type = if self.conn_init { BDADDR_LE_PUBLIC } else { addr_type };
            self.smp.conn_add(handle, &ia, ia_type, &remote_addr, addr_type, false);
        }
        if let Some(ref cb) = self.connect_cb {
            cb(handle);
        }
    }

    fn evt_disconn_complete(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let handle = u16::from_le_bytes([data[1], data[2]]);
        self.smp.conn_del(handle);
        if let Some(conn) = self.connections.remove(&handle) {
            for l2 in &conn.l2conns {
                if let Some(srv) = self.l2cap_servers.iter().find(|s| s.psm == l2.psm) {
                    if let Some(ref dcb) = srv.disconn_cb {
                        dcb(handle, l2.scid);
                    }
                }
            }
        }
        self.l2cap_pending.retain(|p| p.handle != handle);
    }

    fn evt_auth_complete(&mut self, data: &[u8]) {
        if data.len() < 3 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let handle = u16::from_le_bytes([data[1], data[2]]);
        let mut p = [0u8; 3];
        p[0..2].copy_from_slice(&handle.to_le_bytes());
        p[2] = 0x01;
        self.send_command(opcode(OGF_LINK_CONTROL, OCF_SET_CONN_ENCRYPT), &p);
    }

    fn evt_pin_code_request(&mut self, data: &[u8]) {
        if data.len() < 6 {
            return;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[..6]);
        if let Some(ref pin) = self.pin {
            let plen = pin.len().min(16) as u8;
            let mut p = [0u8; 23];
            p[0..6].copy_from_slice(&addr);
            p[6] = plen;
            p[7..7 + plen as usize].copy_from_slice(&pin[..plen as usize]);
            self.send_command(opcode(OGF_LINK_CONTROL, OCF_PIN_CODE_REPLY), &p);
        } else {
            self.send_command(opcode(OGF_LINK_CONTROL, OCF_PIN_CODE_NEG_REPLY), &addr);
        }
    }

    fn evt_link_key_request(&mut self, data: &[u8]) {
        if data.len() < 6 {
            return;
        }
        self.send_command(opcode(OGF_LINK_CONTROL, OCF_LINK_KEY_NEG_REPLY), &data[..6]);
    }

    fn evt_encrypt_change(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let handle = u16::from_le_bytes([data[1], data[2]]);
        let encr = data[3];
        if let Some(conn) = self.connections.get_mut(&handle) {
            conn.encr_mode = encr;
        }
        self.smp.conn_encrypted(handle, encr);
    }

    fn evt_io_capability_request(&mut self, data: &[u8]) {
        if data.len() < 6 {
            return;
        }
        let mut p = [0u8; 9];
        p[0..6].copy_from_slice(&data[..6]);
        p[6] = self.io_capability;
        p[7] = 0x00;
        p[8] = self.auth_req;
        self.send_command(opcode(OGF_LINK_CONTROL, OCF_IO_CAPABILITY_REPLY), &p);
    }

    fn evt_user_confirm_request(&mut self, data: &[u8]) {
        if data.len() < 6 {
            return;
        }
        if self.reject_user_confirm {
            self.send_command(opcode(OGF_LINK_CONTROL, OCF_USER_CONFIRM_NEG_REPLY), &data[..6]);
        } else {
            self.send_command(opcode(OGF_LINK_CONTROL, OCF_USER_CONFIRM_REPLY), &data[..6]);
        }
    }

    fn evt_sync_conn_complete(&mut self, data: &[u8]) {
        if data.len() < 17 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let handle = u16::from_le_bytes([data[1], data[2]]);
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[3..9]);
        let conn = BtConn {
            _handle: handle,
            addr,
            addr_type: BDADDR_BREDR,
            next_cid: 0x0040,
            l2conns: Vec::new(),
            cid_hooks: Vec::new(),
            sco_hooks: Vec::new(),
            iso_hooks: Vec::new(),
            rfcomm_chans: Vec::new(),
            _smp_conn_active: false,
            encr_mode: 0,
            fixed_chan: 0,
            acl_buf: Vec::new(),
            iso_buf: Vec::new(),
        };
        self.connections.insert(handle, conn);
        if let Some(ref cb) = self.sco_cb {
            cb(handle);
        }
    }

    fn evt_conn_request(&mut self, data: &[u8]) {
        if data.len() < 10 {
            return;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[..6]);
        let link_type = data[9];
        if link_type == 0x01 {
            let mut p = [0u8; 21];
            p[0..6].copy_from_slice(&addr);
            p[6..10].copy_from_slice(&0x00001f40u32.to_le_bytes());
            p[10..14].copy_from_slice(&0x00001f40u32.to_le_bytes());
            p[14..16].copy_from_slice(&0x000Au16.to_le_bytes());
            p[16..18].copy_from_slice(&BT_VOICE_CVSD_16BIT.to_le_bytes());
            p[18] = 0x02;
            p[19..21].copy_from_slice(&0x003Fu16.to_le_bytes());
            self.send_command(opcode(OGF_LINK_CONTROL, OCF_ACCEPT_SYNC_CONN_REQ), &p);
        } else {
            let mut p = [0u8; 7];
            p[0..6].copy_from_slice(&addr);
            p[6] = 0x00;
            self.send_command(opcode(OGF_LINK_CONTROL, OCF_ACCEPT_CONN_REQ), &p);
        }
    }

    // -----------------------------------------------------------------------
    // LE Meta Event sub-dispatchers
    // -----------------------------------------------------------------------

    fn evt_le_meta(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let sub = data[0];
        let p = &data[1..];
        match sub {
            EVT_LE_CONN_COMPLETE => self.evt_le_conn_complete(p),
            EVT_LE_ENHANCED_CONN_COMPLETE | EVT_LE_ENHANCED_CONN_COMPLETE_V2 => {
                self.evt_le_enh_conn_complete(p)
            }
            EVT_LE_EXT_ADV_REPORT => self.evt_le_ext_adv_report(p),
            EVT_LE_CIS_ESTABLISHED => self.evt_le_cis_established(p),
            EVT_LE_CIS_REQUEST => self.evt_le_cis_req(p),
            EVT_LE_CREATE_BIG_COMPLETE => self.evt_le_big_complete(p),
            EVT_LE_BIG_SYNC_ESTABLISHED => self.evt_le_big_sync_established(p),
            EVT_LE_PA_SYNC_ESTABLISHED | EVT_LE_PA_SYNC_ESTABLISHED_V2 => {
                self.evt_le_pa_sync_established(p)
            }
            _ => self.debug_log(&format!("bthost: unhandled LE sub 0x{:02x}", sub)),
        }
    }

    fn evt_le_conn_complete(&mut self, data: &[u8]) {
        if data.len() < 18 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let handle = u16::from_le_bytes([data[1], data[2]]);
        let addr_type = data[4];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[5..11]);
        self.le = true;
        self.conn_init = true;
        let conn = BtConn {
            _handle: handle,
            addr,
            addr_type,
            next_cid: 0x0040,
            l2conns: Vec::new(),
            cid_hooks: Vec::new(),
            sco_hooks: Vec::new(),
            iso_hooks: Vec::new(),
            rfcomm_chans: Vec::new(),
            _smp_conn_active: false,
            encr_mode: 0,
            fixed_chan: 0x0002,
            acl_buf: Vec::new(),
            iso_buf: Vec::new(),
        };
        self.connections.insert(handle, conn);
        self.init_conn(handle);
    }

    fn evt_le_enh_conn_complete(&mut self, data: &[u8]) {
        if data.len() < 30 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let handle = u16::from_le_bytes([data[1], data[2]]);
        let addr_type = data[4];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&data[5..11]);
        self.le = true;
        self.conn_init = true;
        let conn = BtConn {
            _handle: handle,
            addr,
            addr_type,
            next_cid: 0x0040,
            l2conns: Vec::new(),
            cid_hooks: Vec::new(),
            sco_hooks: Vec::new(),
            iso_hooks: Vec::new(),
            rfcomm_chans: Vec::new(),
            _smp_conn_active: false,
            encr_mode: 0,
            fixed_chan: 0x0002,
            acl_buf: Vec::new(),
            iso_buf: Vec::new(),
        };
        self.connections.insert(handle, conn);
        self.init_conn(handle);
    }

    fn evt_le_ext_adv_report(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let num_reports = data[0] as usize;
        let mut offset: usize = 1;
        // Each LE ext adv report: 24 bytes fixed + data_len variable
        // Layout: event_type(2), addr_type(1), addr(6), primary_phy(1),
        //         secondary_phy(1), sid(1), tx_power(1), rssi(1),
        //         periodic_adv_interval(2), direct_addr_type(1), direct_addr(6),
        //         data_len(1), data(variable)
        for _ in 0..num_reports {
            if offset + 24 > data.len() {
                break;
            }
            let addr_type = data[offset + 2];
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&data[offset + 3..offset + 9]);
            let direct_addr_type = data[offset + 17];
            let mut direct_addr = [0u8; 6];
            direct_addr.copy_from_slice(&data[offset + 18..offset + 24]);
            let data_len = data[offset + 24] as usize;
            self.le_ext_advs.push(LeExtAdv {
                _addr_type: addr_type,
                addr,
                _direct_addr_type: direct_addr_type,
                _direct_addr: direct_addr,
            });
            offset += 25 + data_len;
        }
    }

    fn evt_le_cis_established(&mut self, data: &[u8]) {
        if data.len() < 3 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let handle = u16::from_le_bytes([data[1], data[2]]);
        let conn = BtConn {
            _handle: handle,
            addr: [0u8; 6],
            addr_type: BDADDR_LE_PUBLIC,
            next_cid: 0x0040,
            l2conns: Vec::new(),
            cid_hooks: Vec::new(),
            sco_hooks: Vec::new(),
            iso_hooks: Vec::new(),
            rfcomm_chans: Vec::new(),
            _smp_conn_active: false,
            encr_mode: 0,
            fixed_chan: 0,
            acl_buf: Vec::new(),
            iso_buf: Vec::new(),
        };
        self.connections.insert(handle, conn);
        if let Some(ref cb) = self.iso_cb {
            cb(handle);
        }
    }

    fn evt_le_cis_req(&mut self, data: &[u8]) {
        if data.len() < 7 {
            return;
        }
        let cis_handle = u16::from_le_bytes([data[2], data[3]]);
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_ACCEPT_CIS), &cis_handle.to_le_bytes());
    }

    fn evt_le_big_complete(&mut self, data: &[u8]) {
        if data.len() < 19 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let num_bis = data[18] as usize;
        if data.len() < 19 + num_bis * 2 {
            return;
        }
        let mut first_h = 0u16;
        for i in 0..num_bis {
            let o = 19 + i * 2;
            let h = u16::from_le_bytes([data[o], data[o + 1]]);
            if i == 0 {
                first_h = h;
            }
            let conn = BtConn {
                _handle: h,
                addr: [0u8; 6],
                addr_type: BDADDR_LE_PUBLIC,
                next_cid: 0x0040,
                l2conns: Vec::new(),
                cid_hooks: Vec::new(),
                sco_hooks: Vec::new(),
                iso_hooks: Vec::new(),
                rfcomm_chans: Vec::new(),
                _smp_conn_active: false,
                encr_mode: 0,
                fixed_chan: 0,
                acl_buf: Vec::new(),
                iso_buf: Vec::new(),
            };
            self.connections.insert(h, conn);
        }
        if num_bis > 0 {
            if let Some(ref cb) = self.iso_cb {
                cb(first_h);
            }
        }
    }

    fn evt_le_big_sync_established(&mut self, data: &[u8]) {
        if data.len() < 20 {
            return;
        }
        if data[0] != 0 {
            return;
        }
        let num_bis = data[19] as usize;
        if data.len() < 20 + num_bis * 2 {
            return;
        }
        for i in 0..num_bis {
            let o = 20 + i * 2;
            let h = u16::from_le_bytes([data[o], data[o + 1]]);
            let conn = BtConn {
                _handle: h,
                addr: [0u8; 6],
                addr_type: BDADDR_LE_PUBLIC,
                next_cid: 0x0040,
                l2conns: Vec::new(),
                cid_hooks: Vec::new(),
                sco_hooks: Vec::new(),
                iso_hooks: Vec::new(),
                rfcomm_chans: Vec::new(),
                _smp_conn_active: false,
                encr_mode: 0,
                fixed_chan: 0,
                acl_buf: Vec::new(),
                iso_buf: Vec::new(),
            };
            self.connections.insert(h, conn);
        }
    }

    fn evt_le_pa_sync_established(&mut self, data: &[u8]) {
        // C original does not process this event. Log and return.
        if data.is_empty() {
            return;
        }
        self.debug_log("LE PA Sync Established event received");
        let _ = data;
    }

    // -----------------------------------------------------------------------
    // ACL / SCO / ISO reassembly
    // -----------------------------------------------------------------------

    fn process_acl(&mut self, data: &[u8]) {
        if data.len() < HCI_ACL_HDR_SIZE {
            return;
        }
        let hdr_raw = u16::from_le_bytes([data[0], data[1]]);
        let handle = acl_handle(hdr_raw);
        let flags = acl_flags(hdr_raw);
        let dlen = u16::from_le_bytes([data[2], data[3]]) as usize;
        if data.len() < HCI_ACL_HDR_SIZE + dlen {
            return;
        }
        let payload = &data[HCI_ACL_HDR_SIZE..HCI_ACL_HDR_SIZE + dlen];

        match flags {
            ACL_START | ACL_START_NO_FLUSH => {
                // New L2CAP frame start
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.acl_buf.clear();
                    conn.acl_buf.extend_from_slice(payload);
                }
            }
            ACL_CONT => {
                // Continuation fragment
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.acl_buf.extend_from_slice(payload);
                }
            }
            _ => return,
        }

        // Check if we have a complete L2CAP frame
        let complete = if let Some(conn) = self.connections.get(&handle) {
            if conn.acl_buf.len() >= L2CAP_HDR_SIZE {
                let l2len = u16::from_le_bytes([conn.acl_buf[0], conn.acl_buf[1]]) as usize;
                conn.acl_buf.len() >= L2CAP_HDR_SIZE + l2len
            } else {
                false
            }
        } else {
            false
        };

        if complete {
            // Extract the complete L2CAP frame
            let frame = if let Some(conn) = self.connections.get_mut(&handle) {
                std::mem::take(&mut conn.acl_buf)
            } else {
                return;
            };
            self.process_l2cap(handle, &frame);
        }
    }

    fn process_sco(&mut self, data: &[u8]) {
        if data.len() < HCI_SCO_HDR_SIZE {
            return;
        }
        let hdr_raw = u16::from_le_bytes([data[0], data[1]]);
        let handle = hdr_raw & 0x0FFF;
        let pkt_status = ((hdr_raw >> 12) & 0x03) as u8;
        let dlen = data[2] as usize;
        if data.len() < HCI_SCO_HDR_SIZE + dlen {
            return;
        }
        let payload = &data[HCI_SCO_HDR_SIZE..HCI_SCO_HDR_SIZE + dlen];

        if let Some(conn) = self.connections.get(&handle) {
            for hook in &conn.sco_hooks {
                (hook.func)(payload, pkt_status);
            }
        }
    }

    fn process_iso(&mut self, data: &[u8]) {
        if data.len() < HCI_ISO_HDR_SIZE {
            return;
        }
        let hdr_raw = u16::from_le_bytes([data[0], data[1]]);
        let handle = hdr_raw & 0x0FFF;
        let pb = ((hdr_raw >> 12) & 0x03) as u8;
        let _ts_flag = (hdr_raw >> 14) & 0x01;
        let dlen = u16::from_le_bytes([data[2], data[3]]) as usize;
        if data.len() < HCI_ISO_HDR_SIZE + dlen {
            return;
        }
        let payload = &data[HCI_ISO_HDR_SIZE..HCI_ISO_HDR_SIZE + dlen];

        match pb {
            0x02 => {
                // Complete SDU
                if let Some(conn) = self.connections.get(&handle) {
                    for hook in &conn.iso_hooks {
                        (hook.func)(payload);
                    }
                }
            }
            0x00 => {
                // First fragment
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.iso_buf.clear();
                    conn.iso_buf.extend_from_slice(payload);
                }
            }
            0x01 => {
                // Continuation
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.iso_buf.extend_from_slice(payload);
                }
            }
            0x03 => {
                // Last fragment
                let complete_sdu = if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.iso_buf.extend_from_slice(payload);
                    std::mem::take(&mut conn.iso_buf)
                } else {
                    return;
                };
                if let Some(conn) = self.connections.get(&handle) {
                    for hook in &conn.iso_hooks {
                        (hook.func)(&complete_sdu);
                    }
                }
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // L2CAP frame dispatch
    // -----------------------------------------------------------------------

    fn process_l2cap(&mut self, handle: u16, frame: &[u8]) {
        if frame.len() < L2CAP_HDR_SIZE {
            return;
        }
        let l2len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
        let cid = u16::from_le_bytes([frame[2], frame[3]]);
        if frame.len() < L2CAP_HDR_SIZE + l2len {
            return;
        }
        let payload = &frame[L2CAP_HDR_SIZE..L2CAP_HDR_SIZE + l2len];

        match cid {
            L2CAP_CID_BREDR_SIG => self.l2cap_sig(handle, false, payload),
            L2CAP_CID_LE_SIG => self.l2cap_sig(handle, true, payload),
            L2CAP_CID_SMP => {
                self.smp.data(handle, payload);
            }
            L2CAP_CID_SMP_BREDR => {
                self.smp.bredr_data(handle, payload);
            }
            _ => self.process_l2cap_cid(handle, cid, payload),
        }
    }

    fn process_l2cap_cid(&mut self, handle: u16, cid: u16, data: &[u8]) {
        // Check CID hooks first
        if let Some(conn) = self.connections.get(&handle) {
            for hook in &conn.cid_hooks {
                if hook.cid == cid {
                    (hook.func)(data);
                    return;
                }
            }
        }

        // Check if this belongs to a credit-based channel that needs reassembly
        let psm = if let Some(conn) = self.connections.get(&handle) {
            conn.l2conns.iter().find(|l| l.dcid == cid).map(|l| (l.psm, l.scid, l.mode))
        } else {
            None
        };

        if let Some((psm_val, _scid, mode)) = psm {
            if mode == L2capMode::LeCred || mode == L2capMode::LeEnhCred {
                // LE credit-based: first 2 bytes of first segment = SDU length
                // For simplicity, deliver whole payload to hook (tester level)
                // Send credits back
                let mut cred_data = [0u8; 4];
                if let Some(conn) = self.connections.get(&handle) {
                    if let Some(l2) = conn.l2conns.iter().find(|l| l.dcid == cid) {
                        cred_data[0..2].copy_from_slice(&l2.scid.to_le_bytes());
                        cred_data[2..4].copy_from_slice(&1u16.to_le_bytes());
                    }
                }
                self.l2cap_sig_send(handle, true, L2CAP_LE_FLOWCTL_CREDS, 0, &cred_data);
            }
            // Check if PSM 3 = RFCOMM
            if psm_val == RFCOMM_PSM {
                self.process_rfcomm(handle, cid, data);
                return;
            }
        }

        // Check CID hooks again with scid mapping
        if let Some(conn) = self.connections.get(&handle) {
            if let Some(l2) = conn.l2conns.iter().find(|l| l.dcid == cid) {
                let scid = l2.scid;
                for hook in &conn.cid_hooks {
                    if hook.cid == scid {
                        (hook.func)(data);
                        return;
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // L2CAP Signaling (BR/EDR and LE)
    // -----------------------------------------------------------------------

    fn l2cap_sig(&mut self, handle: u16, is_le: bool, data: &[u8]) {
        let mut off = 0;
        while off + L2CAP_CMD_HDR_SIZE <= data.len() {
            let code = data[off];
            let ident = data[off + 1];
            let clen = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
            if off + L2CAP_CMD_HDR_SIZE + clen > data.len() {
                break;
            }
            let cmd_data = &data[off + L2CAP_CMD_HDR_SIZE..off + L2CAP_CMD_HDR_SIZE + clen];

            if is_le {
                self.l2cap_le_sig_cmd(handle, code, ident, cmd_data);
            } else {
                self.l2cap_bredr_sig_cmd(handle, code, ident, cmd_data);
            }
            off += L2CAP_CMD_HDR_SIZE + clen;
        }
    }

    fn l2cap_bredr_sig_cmd(&mut self, handle: u16, code: u8, ident: u8, data: &[u8]) {
        match code {
            L2CAP_CONN_REQ => self.l2cap_conn_req(handle, ident, data),
            L2CAP_CONN_RSP => self.l2cap_conn_rsp(handle, ident, data),
            L2CAP_CONF_REQ => self.l2cap_config_req(handle, ident, data),
            L2CAP_CONF_RSP => self.l2cap_config_rsp(handle, ident, data),
            L2CAP_DISCONN_REQ => self.l2cap_disconn_req(handle, ident, data),
            L2CAP_DISCONN_RSP => self.l2cap_disconn_rsp(handle, data),
            L2CAP_INFO_REQ => self.l2cap_info_req(handle, ident, data),
            L2CAP_INFO_RSP => self.l2cap_info_rsp(handle, data),
            0x01 => {} // Command Reject
            _ => {
                // Send Command Reject (reason: not understood)
                let mut rej = [0u8; 2];
                rej[0..2].copy_from_slice(&0x0000u16.to_le_bytes());
                self.l2cap_sig_send(handle, false, 0x01, ident, &rej);
            }
        }
    }

    fn l2cap_conn_req(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let psm = u16::from_le_bytes([data[0], data[1]]);
        let scid = u16::from_le_bytes([data[2], data[3]]);

        // Check if we have a server for this PSM
        let has_server = self.l2cap_servers.iter().any(|s| s.psm == psm);

        // Allocate a CID
        let dcid = if let Some(conn) = self.connections.get_mut(&handle) {
            let c = conn.next_cid;
            conn.next_cid += 1;
            c
        } else {
            return;
        };

        let (result, status) = if has_server {
            (L2CAP_CR_SUCCESS, L2CAP_CS_NO_INFO)
        } else {
            (L2CAP_CR_BAD_PSM, 0x0000u16)
        };

        // Send Connection Response
        let mut rsp = [0u8; 8];
        rsp[0..2].copy_from_slice(&dcid.to_le_bytes());
        rsp[2..4].copy_from_slice(&scid.to_le_bytes());
        rsp[4..6].copy_from_slice(&result.to_le_bytes());
        rsp[6..8].copy_from_slice(&status.to_le_bytes());
        self.l2cap_sig_send(handle, false, L2CAP_CONN_RSP, ident, &rsp);

        if result == L2CAP_CR_SUCCESS {
            // Add L2CAP channel
            if let Some(conn) = self.connections.get_mut(&handle) {
                conn.l2conns.push(L2conn {
                    scid: dcid,
                    dcid: scid,
                    psm,
                    mtu: 672,
                    tx_mps: 0,
                    _rx_mps: 0,
                    tx_credits: 0,
                    _rx_credits: 0,
                    mode: L2capMode::Basic,
                    _recv_data: Vec::new(),
                    _recv_len: 0,
                });
            }
            // Send Config Request
            let mut conf = [0u8; 4];
            conf[0..2].copy_from_slice(&scid.to_le_bytes());
            conf[2..4].copy_from_slice(&0x0000u16.to_le_bytes()); // flags
            self.l2cap_sig_send(handle, false, L2CAP_CONF_REQ, 0, &conf);
        }
    }

    fn l2cap_conn_rsp(&mut self, handle: u16, _ident: u8, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        let dcid = u16::from_le_bytes([data[0], data[1]]);
        let scid = u16::from_le_bytes([data[2], data[3]]);
        let result = u16::from_le_bytes([data[4], data[5]]);

        if result != L2CAP_CR_SUCCESS {
            return;
        }

        // Update the L2CAP channel with dcid
        if let Some(conn) = self.connections.get_mut(&handle) {
            if let Some(l2) = conn.l2conns.iter_mut().find(|l| l.scid == scid) {
                l2.dcid = dcid;
            }
        }

        // Send Config Request
        let mut conf = [0u8; 4];
        conf[0..2].copy_from_slice(&dcid.to_le_bytes());
        conf[2..4].copy_from_slice(&0x0000u16.to_le_bytes());
        self.l2cap_sig_send(handle, false, L2CAP_CONF_REQ, 0, &conf);

        // Handle pending L2CAP requests
        self.handle_pending_l2reqs(handle, scid, dcid);
    }

    fn l2cap_config_req(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let dcid = u16::from_le_bytes([data[0], data[1]]);

        // Send Config Response (always accept)
        let mut rsp = [0u8; 6];
        rsp[0..2].copy_from_slice(&dcid.to_le_bytes());
        rsp[2..4].copy_from_slice(&0x0000u16.to_le_bytes()); // flags
        rsp[4..6].copy_from_slice(&L2CAP_CONF_SUCCESS.to_le_bytes());
        self.l2cap_sig_send(handle, false, L2CAP_CONF_RSP, ident, &rsp);
    }

    fn l2cap_config_rsp(&mut self, handle: u16, _ident: u8, data: &[u8]) {
        if data.len() < 6 {
            return;
        }
        let scid = u16::from_le_bytes([data[0], data[1]]);
        let result = u16::from_le_bytes([data[4], data[5]]);

        if result != L2CAP_CONF_SUCCESS {
            return;
        }

        // Check if this was an RFCOMM channel, trigger SABM
        let psm = if let Some(conn) = self.connections.get(&handle) {
            conn.l2conns.iter().find(|l| l.scid == scid).map(|l| l.psm)
        } else {
            None
        };

        if psm == Some(RFCOMM_PSM) {
            // Send RFCOMM SABM on DLCI 0 (multiplexer start)
            if let Some(conn) = self.connections.get(&handle) {
                if let Some(l2) = conn.l2conns.iter().find(|l| l.scid == scid) {
                    let dcid = l2.dcid;
                    self.rfcomm_sabm_send(handle, dcid, 0);
                }
            }
        }

        // Notify L2CAP server connect callback
        if let Some(psm_val) = psm {
            let cb_idx = self.l2cap_servers.iter().position(|s| s.psm == psm_val);
            if let Some(idx) = cb_idx {
                let cb = &self.l2cap_servers[idx].connect_cb;
                cb(handle, scid);
            }
        }
    }

    fn l2cap_disconn_req(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let dcid = u16::from_le_bytes([data[0], data[1]]);
        let scid = u16::from_le_bytes([data[2], data[3]]);

        // Send Disconnection Response
        let mut rsp = [0u8; 4];
        rsp[0..2].copy_from_slice(&dcid.to_le_bytes());
        rsp[2..4].copy_from_slice(&scid.to_le_bytes());
        self.l2cap_sig_send(handle, false, L2CAP_DISCONN_RSP, ident, &rsp);

        // Remove channel and notify
        if let Some(conn) = self.connections.get_mut(&handle) {
            if let Some(pos) = conn.l2conns.iter().position(|l| l.scid == dcid) {
                let l2 = conn.l2conns.remove(pos);
                // Notify disconnect callback
                if let Some(srv) = self.l2cap_servers.iter().find(|s| s.psm == l2.psm) {
                    if let Some(ref dcb) = srv.disconn_cb {
                        dcb(handle, l2.scid);
                    }
                }
            }
        }
    }

    fn l2cap_disconn_rsp(&mut self, handle: u16, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let dcid = u16::from_le_bytes([data[0], data[1]]);
        let scid = u16::from_le_bytes([data[2], data[3]]);

        if let Some(conn) = self.connections.get_mut(&handle) {
            conn.l2conns.retain(|l| !(l.scid == scid && l.dcid == dcid));
        }
    }

    fn l2cap_info_req(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let info_type = u16::from_le_bytes([data[0], data[1]]);

        match info_type {
            L2CAP_IT_FEAT_MASK => {
                // Return extended features mask with FIXED_CHAN support
                let mut rsp = [0u8; 8];
                rsp[0..2].copy_from_slice(&info_type.to_le_bytes());
                rsp[2..4].copy_from_slice(&0x0000u16.to_le_bytes()); // success
                let feat: u32 = L2CAP_FC_L2CAP as u32 | L2CAP_FEAT_FIXED_CHAN;
                rsp[4..8].copy_from_slice(&feat.to_le_bytes());
                self.l2cap_sig_send(handle, false, L2CAP_INFO_RSP, ident, &rsp);
            }
            L2CAP_IT_FIXED_CHAN => {
                // Return fixed channels bitmap
                let mut rsp = [0u8; 12];
                rsp[0..2].copy_from_slice(&info_type.to_le_bytes());
                rsp[2..4].copy_from_slice(&0x0000u16.to_le_bytes()); // success
                let mut fc: u64 = L2CAP_FC_SIG_BREDR;
                if self.sc_support {
                    fc |= L2CAP_FC_SMP_BREDR;
                }
                rsp[4..12].copy_from_slice(&fc.to_le_bytes());
                self.l2cap_sig_send(handle, false, L2CAP_INFO_RSP, ident, &rsp);

                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.fixed_chan = fc;
                }
            }
            _ => {
                // Not supported
                let mut rsp = [0u8; 4];
                rsp[0..2].copy_from_slice(&info_type.to_le_bytes());
                rsp[2..4].copy_from_slice(&0x0001u16.to_le_bytes()); // not supported
                self.l2cap_sig_send(handle, false, L2CAP_INFO_RSP, ident, &rsp);
            }
        }
    }

    fn l2cap_info_rsp(&mut self, handle: u16, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let info_type = u16::from_le_bytes([data[0], data[1]]);
        let result = u16::from_le_bytes([data[2], data[3]]);

        if info_type == L2CAP_IT_FEAT_MASK && result == 0 {
            // Now request fixed channels
            let mut req = [0u8; 2];
            req[0..2].copy_from_slice(&L2CAP_IT_FIXED_CHAN.to_le_bytes());
            self.l2cap_sig_send(handle, false, L2CAP_INFO_REQ, 0, &req);
        } else if info_type == L2CAP_IT_FIXED_CHAN && result == 0 && data.len() >= 12 {
            let fc = u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]);
            if let Some(conn) = self.connections.get_mut(&handle) {
                conn.fixed_chan = fc;
            }
            // If SMP over BR/EDR is supported, init
            if fc & L2CAP_FC_SMP_BREDR != 0 {
                let ia = self.bdaddr;
                let remote_addr = self.connections.get(&handle).map(|c| c.addr).unwrap_or([0u8; 6]);
                self.smp.conn_add(handle, &ia, BDADDR_BREDR, &remote_addr, BDADDR_BREDR, true);
            }
        }
    }

    fn handle_pending_l2reqs(&mut self, handle: u16, scid: u16, dcid: u16) {
        let pending: Vec<L2capPendingReq> =
            self.l2cap_pending.drain(..).filter(|p| p.handle == handle).collect();
        let mut remaining: Vec<L2capPendingReq> = Vec::new();
        for req in pending {
            // Build request with the resolved CID and send
            let mut req_data = Vec::with_capacity(req.data.len());
            req_data.extend_from_slice(&req.data);
            self.l2cap_sig_send(handle, false, req.code, 0, &req_data);
            // Keep callback
            remaining.push(L2capPendingReq {
                handle,
                ident: req.ident,
                code: req.code,
                data: req.data,
                cb: req.cb,
            });
        }
        // Re-insert unmatched ones
        for p in remaining {
            self.l2cap_pending.push(p);
        }
        let _ = (scid, dcid); // used for routing
    }

    // -----------------------------------------------------------------------
    // L2CAP LE signaling
    // -----------------------------------------------------------------------

    fn l2cap_le_sig_cmd(&mut self, handle: u16, code: u8, ident: u8, data: &[u8]) {
        match code {
            0x01 => {} // Command Reject
            L2CAP_DISCONN_REQ => self.l2cap_disconn_req(handle, ident, data),
            L2CAP_DISCONN_RSP => self.l2cap_disconn_rsp(handle, data),
            L2CAP_CONN_PARAM_REQ => self.l2cap_conn_param_req(handle, ident, data),
            L2CAP_LE_CONN_REQ => self.l2cap_le_conn_req(handle, ident, data),
            L2CAP_LE_CONN_RSP => self.l2cap_le_conn_rsp(handle, ident, data),
            L2CAP_LE_FLOWCTL_CREDS => self.l2cap_le_flowctl_creds(handle, data),
            L2CAP_ECRED_CONN_REQ => self.l2cap_ecred_conn_req(handle, ident, data),
            L2CAP_ECRED_CONN_RSP => self.l2cap_ecred_conn_rsp(handle, ident, data),
            _ => {
                let mut rej = [0u8; 2];
                rej[0..2].copy_from_slice(&0x0000u16.to_le_bytes());
                self.l2cap_sig_send(handle, true, 0x01, ident, &rej);
            }
        }
    }

    fn l2cap_conn_param_req(&mut self, handle: u16, ident: u8, _data: &[u8]) {
        // Accept connection parameter update
        let rsp = 0x0000u16.to_le_bytes();
        self.l2cap_sig_send(handle, true, L2CAP_LE_CONN_PARAM_RSP, ident, &rsp);
    }

    fn l2cap_le_conn_req(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 10 {
            return;
        }
        let psm = u16::from_le_bytes([data[0], data[1]]);
        let scid = u16::from_le_bytes([data[2], data[3]]);
        let mtu = u16::from_le_bytes([data[4], data[5]]);
        let mps = u16::from_le_bytes([data[6], data[7]]);
        let credits = u16::from_le_bytes([data[8], data[9]]);

        let has_server = self.l2cap_servers.iter().any(|s| s.psm == psm);

        let dcid = if let Some(conn) = self.connections.get_mut(&handle) {
            let c = conn.next_cid;
            conn.next_cid += 1;
            c
        } else {
            return;
        };

        let (result, srv_mtu, srv_mps, srv_credits) = if has_server {
            let srv = self.l2cap_servers.iter().find(|s| s.psm == psm).unwrap();
            let m = if srv.mtu > 0 { srv.mtu } else { 672 };
            let p = if srv.mps > 0 { srv.mps } else { 672 };
            let c = if srv.credits > 0 { srv.credits } else { 1 };
            (0x0000u16, m, p, c)
        } else {
            (0x0002u16, 672u16, 672u16, 1u16) // PSM not supported
        };

        let mut rsp = [0u8; 10];
        rsp[0..2].copy_from_slice(&dcid.to_le_bytes());
        rsp[2..4].copy_from_slice(&srv_mtu.to_le_bytes());
        rsp[4..6].copy_from_slice(&srv_mps.to_le_bytes());
        rsp[6..8].copy_from_slice(&srv_credits.to_le_bytes());
        rsp[8..10].copy_from_slice(&result.to_le_bytes());
        self.l2cap_sig_send(handle, true, L2CAP_LE_CONN_RSP, ident, &rsp);

        if result == 0 {
            if let Some(conn) = self.connections.get_mut(&handle) {
                conn.l2conns.push(L2conn {
                    scid: dcid,
                    dcid: scid,
                    psm,
                    mtu,
                    tx_mps: mps,
                    _rx_mps: srv_mps,
                    tx_credits: credits,
                    _rx_credits: srv_credits,
                    mode: L2capMode::LeCred,
                    _recv_data: Vec::new(),
                    _recv_len: 0,
                });
            }
            // Notify server
            let cb_idx = self.l2cap_servers.iter().position(|s| s.psm == psm);
            if let Some(idx) = cb_idx {
                let cb = &self.l2cap_servers[idx].connect_cb;
                cb(handle, dcid);
            }
        }
    }

    fn l2cap_le_conn_rsp(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 10 {
            return;
        }
        let dcid = u16::from_le_bytes([data[0], data[1]]);
        let mtu = u16::from_le_bytes([data[2], data[3]]);
        let mps = u16::from_le_bytes([data[4], data[5]]);
        let credits = u16::from_le_bytes([data[6], data[7]]);
        let result = u16::from_le_bytes([data[8], data[9]]);

        if result != 0 {
            return;
        }

        // Find the pending L2CAP channel by ident
        let pending_idx =
            self.l2cap_pending.iter().position(|p| p.handle == handle && p.ident == ident);
        if let Some(idx) = pending_idx {
            let req = self.l2cap_pending.remove(idx);
            // Extract scid from the original request data
            if req.data.len() >= 4 {
                let scid = u16::from_le_bytes([req.data[2], req.data[3]]);
                if let Some(conn) = self.connections.get_mut(&handle) {
                    if let Some(l2) = conn.l2conns.iter_mut().find(|l| l.scid == scid) {
                        l2.dcid = dcid;
                        l2.mtu = mtu;
                        l2.tx_mps = mps;
                        l2.tx_credits = credits;
                    }
                }
                if let Some(cb) = req.cb {
                    cb(L2CAP_LE_CONN_RSP, data);
                }
            }
        }
    }

    fn l2cap_le_flowctl_creds(&mut self, handle: u16, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let cid = u16::from_le_bytes([data[0], data[1]]);
        let credits = u16::from_le_bytes([data[2], data[3]]);

        if let Some(conn) = self.connections.get_mut(&handle) {
            if let Some(l2) = conn.l2conns.iter_mut().find(|l| l.scid == cid) {
                l2.tx_credits = l2.tx_credits.saturating_add(credits);
            }
        }
    }

    fn l2cap_ecred_conn_req(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        let psm = u16::from_le_bytes([data[0], data[1]]);
        let mtu = u16::from_le_bytes([data[2], data[3]]);
        let mps = u16::from_le_bytes([data[4], data[5]]);
        let credits = u16::from_le_bytes([data[6], data[7]]);

        let has_server = self.l2cap_servers.iter().any(|s| s.psm == psm);
        let num_cids = (data.len() - 8) / 2;

        let (result, srv_mtu, srv_mps, srv_credits) = if has_server {
            let srv = self.l2cap_servers.iter().find(|s| s.psm == psm).unwrap();
            let m = if srv.mtu > 0 { srv.mtu } else { 672 };
            let p = if srv.mps > 0 { srv.mps } else { 672 };
            let c = if srv.credits > 0 { srv.credits } else { 1 };
            (0x0000u16, m, p, c)
        } else {
            (0x0002u16, 672u16, 672u16, 1u16)
        };

        let mut rsp = Vec::with_capacity(8 + num_cids * 2);
        rsp.extend_from_slice(&srv_mtu.to_le_bytes());
        rsp.extend_from_slice(&srv_mps.to_le_bytes());
        rsp.extend_from_slice(&srv_credits.to_le_bytes());
        rsp.extend_from_slice(&result.to_le_bytes());

        for i in 0..num_cids {
            let off = 8 + i * 2;
            let remote_scid = u16::from_le_bytes([data[off], data[off + 1]]);
            let dcid = if result == 0 {
                let c = if let Some(conn) = self.connections.get_mut(&handle) {
                    let c = conn.next_cid;
                    conn.next_cid += 1;
                    c
                } else {
                    0
                };
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.l2conns.push(L2conn {
                        scid: c,
                        dcid: remote_scid,
                        psm,
                        mtu,
                        tx_mps: mps,
                        _rx_mps: srv_mps,
                        tx_credits: credits,
                        _rx_credits: srv_credits,
                        mode: L2capMode::LeEnhCred,
                        _recv_data: Vec::new(),
                        _recv_len: 0,
                    });
                }
                c
            } else {
                0
            };
            rsp.extend_from_slice(&dcid.to_le_bytes());
        }

        self.l2cap_sig_send(handle, true, L2CAP_ECRED_CONN_RSP, ident, &rsp);

        if result == 0 {
            let cb_idx = self.l2cap_servers.iter().position(|s| s.psm == psm);
            if let Some(idx) = cb_idx {
                // Notify for each CID
                if let Some(conn) = self.connections.get(&handle) {
                    let scids: Vec<u16> = conn
                        .l2conns
                        .iter()
                        .filter(|l| l.psm == psm && l.mode == L2capMode::LeEnhCred)
                        .map(|l| l.scid)
                        .collect();
                    let cb = &self.l2cap_servers[idx].connect_cb;
                    for scid in scids {
                        cb(handle, scid);
                    }
                }
            }
        }
    }

    fn l2cap_ecred_conn_rsp(&mut self, handle: u16, ident: u8, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        let mtu = u16::from_le_bytes([data[0], data[1]]);
        let mps = u16::from_le_bytes([data[2], data[3]]);
        let credits = u16::from_le_bytes([data[4], data[5]]);
        let result = u16::from_le_bytes([data[6], data[7]]);

        if result != 0 {
            return;
        }

        let pending_idx =
            self.l2cap_pending.iter().position(|p| p.handle == handle && p.ident == ident);
        if let Some(idx) = pending_idx {
            let req = self.l2cap_pending.remove(idx);
            // Update channels with dcids from response
            let num_dcids = (data.len() - 8) / 2;
            for i in 0..num_dcids {
                let off = 8 + i * 2;
                let dcid = u16::from_le_bytes([data[off], data[off + 1]]);
                if let Some(conn) = self.connections.get_mut(&handle) {
                    // Find matching l2conn by position
                    if let Some(l2) = conn
                        .l2conns
                        .iter_mut()
                        .filter(|l| l.mode == L2capMode::LeEnhCred && l.dcid == 0)
                        .nth(i)
                    {
                        l2.dcid = dcid;
                        l2.mtu = mtu;
                        l2.tx_mps = mps;
                        l2.tx_credits = credits;
                    }
                }
            }
            if let Some(cb) = req.cb {
                cb(L2CAP_ECRED_CONN_RSP, data);
            }
        }
    }

    // -----------------------------------------------------------------------
    // RFCOMM processing (minimal, matches C bthost)
    // -----------------------------------------------------------------------

    fn process_rfcomm(&mut self, handle: u16, cid: u16, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let addr = data[0];
        let ctrl = data[1];
        let dlci = addr >> 2;
        let frame_type = ctrl & !RFCOMM_PF;
        match frame_type {
            RFCOMM_SABM => self.rfcomm_sabm_recv(handle, cid, dlci),
            RFCOMM_UA => self.rfcomm_ua_recv(handle, cid, dlci),
            RFCOMM_DM => {}
            RFCOMM_DISC => self.rfcomm_disc_recv(handle, cid, dlci),
            RFCOMM_UIH => self.rfcomm_uih_recv(handle, cid, dlci, data),
            _ => {}
        }
    }

    fn rfcomm_sabm_recv(&mut self, handle: u16, cid: u16, dlci: u8) {
        self.rfcomm_ua_send(handle, cid, dlci);
        if dlci > 0 {
            let channel = dlci >> 1;
            let srv_idx = self.rfcomm_servers.iter().position(|s| s.channel == channel);
            if let Some(idx) = srv_idx {
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.rfcomm_chans.push(RcConn {
                        dlci,
                        cid,
                        _active: true,
                        _mtu: 127,
                        chan_hooks: Vec::new(),
                    });
                }
                let cb = &self.rfcomm_servers[idx].connect_cb;
                cb(handle, cid, true);
            }
        }
    }

    fn rfcomm_ua_recv(&mut self, handle: u16, cid: u16, dlci: u8) {
        if dlci == 0 {
            if let Some(rcd) = self.rfcomm_conn_data.take() {
                let ch_dlci = rcd.channel << 1;
                self.rfcomm_sabm_send(handle, cid, ch_dlci);
                self.rfcomm_conn_data = Some(rcd);
            }
        } else {
            if let Some(conn) = self.connections.get_mut(&handle) {
                conn.rfcomm_chans.push(RcConn {
                    dlci,
                    cid,
                    _active: true,
                    _mtu: 127,
                    chan_hooks: Vec::new(),
                });
            }
            if let Some(rcd) = self.rfcomm_conn_data.take() {
                (rcd.cb)(handle, cid, true);
            }
        }
    }

    fn rfcomm_disc_recv(&mut self, handle: u16, cid: u16, dlci: u8) {
        self.rfcomm_ua_send(handle, cid, dlci);
        if let Some(conn) = self.connections.get_mut(&handle) {
            conn.rfcomm_chans.retain(|rc| rc.dlci != dlci);
        }
    }

    fn rfcomm_uih_recv(&mut self, handle: u16, cid: u16, dlci: u8, data: &[u8]) {
        if data.len() < 3 {
            return;
        }
        let len_byte = data[2];
        let (payload_off, payload_len) = if len_byte & 0x01 != 0 {
            (3usize, (len_byte >> 1) as usize)
        } else {
            if data.len() < 4 {
                return;
            }
            (4usize, ((len_byte as usize) >> 1) | ((data[3] as usize) << 7))
        };
        if dlci == 0 {
            if data.len() >= payload_off + payload_len {
                self.rfcomm_mcc_recv(handle, cid, &data[payload_off..payload_off + payload_len]);
            }
        } else if let Some(conn) = self.connections.get(&handle) {
            if let Some(rc) = conn.rfcomm_chans.iter().find(|r| r.dlci == dlci) {
                for hook in &rc.chan_hooks {
                    if data.len() >= payload_off + payload_len {
                        (hook.func)(&data[payload_off..payload_off + payload_len]);
                    }
                }
            }
        }
        let _ = cid;
    }

    fn rfcomm_mcc_recv(&mut self, handle: u16, cid: u16, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let mcc_type = data[0] >> 2;
        match mcc_type {
            RFCOMM_MCC_PN => self.rfcomm_pn_recv(handle, cid, data),
            RFCOMM_MCC_MSC => self.rfcomm_msc_recv(handle, cid, data),
            _ => {}
        }
    }

    fn rfcomm_pn_recv(&mut self, handle: u16, cid: u16, data: &[u8]) {
        if data.len() < 10 {
            return;
        }
        let ab = rfcomm_addr(1, 0);
        let c = rfcomm_ctrl(RFCOMM_UIH, 0);
        let mut rsp = Vec::with_capacity(data.len() + 4);
        rsp.push(ab);
        rsp.push(c);
        rsp.push(rfcomm_len8(data.len() as u8));
        let mut mcc = data.to_vec();
        // Response: clear command bit (CR=0) in MCC type field
        mcc[0] = rfcomm_mcc_type(0, RFCOMM_MCC_PN);
        rsp.extend_from_slice(&mcc);
        rsp.push(rfcomm_fcs2(&[ab, c]));
        self.send_acl_raw(handle, cid, &rsp, false);
    }

    fn rfcomm_msc_recv(&mut self, handle: u16, cid: u16, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        // Check if this is a command (CR bit set)
        if data[0] & (RFCOMM_MCC_CMD << 1) != 0 {
            let ab = rfcomm_addr(1, 0);
            let c = rfcomm_ctrl(RFCOMM_UIH, 0);
            let mut rsp = Vec::with_capacity(data.len() + 4);
            rsp.push(ab);
            rsp.push(c);
            rsp.push(rfcomm_len8(data.len() as u8));
            let mut mcc = data.to_vec();
            // Response: clear command bit, set EA
            mcc[0] = (mcc[0] & !0x02) | 0x01;
            rsp.extend_from_slice(&mcc);
            rsp.push(rfcomm_fcs2(&[ab, c]));
            self.send_acl_raw(handle, cid, &rsp, false);
        }
    }

    fn rfcomm_sabm_send(&self, handle: u16, cid: u16, dlci: u8) {
        let a = rfcomm_addr(1, dlci);
        let c = rfcomm_ctrl(RFCOMM_SABM, 1);
        let l = rfcomm_len8(0);
        let frame = [a, c, l, rfcomm_fcs3(&[a, c, l])];
        self.send_acl_raw(handle, cid, &frame, false);
    }

    fn rfcomm_ua_send(&self, handle: u16, cid: u16, dlci: u8) {
        let a = rfcomm_addr(1, dlci);
        let c = rfcomm_ctrl(RFCOMM_UA, 1);
        let l = rfcomm_len8(0);
        let frame = [a, c, l, rfcomm_fcs3(&[a, c, l])];
        self.send_acl_raw(handle, cid, &frame, false);
    }

    // -----------------------------------------------------------------------
    // Public API: Connection management
    // -----------------------------------------------------------------------

    /// Initiate an HCI Create Connection (BR/EDR or LE).
    pub fn hci_connect(&mut self, bdaddr: &[u8; 6], addr_type: u8) {
        self.conn_init = true;
        if addr_type == BDADDR_BREDR {
            self.le = false;
            let mut p = [0u8; 13];
            p[0..6].copy_from_slice(bdaddr);
            // pkt_type = 0xCC18 (DM1, DH1, DM3, DH3, DM5, DH5)
            p[6..8].copy_from_slice(&0xCC18u16.to_le_bytes());
            p[8] = 0x01; // page scan rep R1
            p[9] = 0x00; // reserved
            p[10..12].copy_from_slice(&0x0000u16.to_le_bytes()); // clock offset
            p[12] = 0x01; // allow role switch
            self.send_command(opcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), &p);
        } else {
            self.le = true;
            let mut p = [0u8; 25];
            // scan interval
            p[0..2].copy_from_slice(&0x0060u16.to_le_bytes());
            // scan window
            p[2..4].copy_from_slice(&0x0030u16.to_le_bytes());
            // filter policy = 0 (whitelist not used)
            p[4] = 0x00;
            // peer addr type
            p[5] = if addr_type == BDADDR_LE_RANDOM { 0x01 } else { 0x00 };
            p[6..12].copy_from_slice(bdaddr);
            // own addr type = public
            p[12] = 0x00;
            // conn interval min
            p[13..15].copy_from_slice(&0x0028u16.to_le_bytes());
            // conn interval max
            p[15..17].copy_from_slice(&0x0038u16.to_le_bytes());
            // latency
            p[17..19].copy_from_slice(&0x0000u16.to_le_bytes());
            // supervision timeout
            p[19..21].copy_from_slice(&0x002Au16.to_le_bytes());
            // min CE length
            p[21..23].copy_from_slice(&0x0000u16.to_le_bytes());
            // max CE length
            p[23..25].copy_from_slice(&0x0000u16.to_le_bytes());
            self.send_command(opcode(OGF_LE_CTL, OCF_LE_CREATE_CONN), &p);
        }
    }

    /// Initiate an HCI LE Extended Create Connection.
    pub fn hci_ext_connect(&mut self, bdaddr: &[u8; 6], addr_type: u8) {
        self.conn_init = true;
        self.le = true;
        let mut p = [0u8; 26];
        // filter policy
        p[0] = 0x00;
        // own addr type
        p[1] = 0x00;
        // peer addr type
        p[2] = if addr_type == BDADDR_LE_RANDOM { 0x01 } else { 0x00 };
        p[3..9].copy_from_slice(bdaddr);
        // PHY: 1M only
        p[9] = 0x01;
        // 1M params: scan interval, scan window, conn interval min/max, latency, sup timeout, min/max CE
        p[10..12].copy_from_slice(&0x0060u16.to_le_bytes());
        p[12..14].copy_from_slice(&0x0030u16.to_le_bytes());
        p[14..16].copy_from_slice(&0x0028u16.to_le_bytes());
        p[16..18].copy_from_slice(&0x0038u16.to_le_bytes());
        p[18..20].copy_from_slice(&0x0000u16.to_le_bytes());
        p[20..22].copy_from_slice(&0x002Au16.to_le_bytes());
        p[22..24].copy_from_slice(&0x0000u16.to_le_bytes());
        p[24..26].copy_from_slice(&0x0000u16.to_le_bytes());
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_EXT_CREATE_CONN), &p);
    }

    /// Send HCI Disconnect command.
    pub fn hci_disconnect(&mut self, handle: u16, reason: u8) {
        let mut p = [0u8; 3];
        p[0..2].copy_from_slice(&handle.to_le_bytes());
        p[2] = reason;
        self.send_command(opcode(OGF_LINK_CONTROL, OCF_DISCONNECT), &p);
    }

    /// Set up a SCO connection on an existing ACL handle.
    pub fn setup_sco(&mut self, acl_handle: u16, setting: u16) -> i32 {
        let conn = match self.connections.get(&acl_handle) {
            Some(c) => c,
            None => return -1,
        };
        let addr = conn.addr;
        let mut p = [0u8; 17];
        p[0..6].copy_from_slice(&addr);
        // transmit/receive bandwidth: 8000
        p[6..10].copy_from_slice(&0x00001f40u32.to_le_bytes());
        p[10..14].copy_from_slice(&0x00001f40u32.to_le_bytes());
        // voice setting
        p[14..16].copy_from_slice(&setting.to_le_bytes());
        // packet type
        p[16] = 0x3F;
        self.send_command(opcode(OGF_LINK_CONTROL, OCF_SETUP_SYNC_CONN), &p);
        0
    }

    /// Initiate LE Start Encryption.
    pub fn le_start_encrypt(&mut self, handle: u16, ltk: &[u8; 16]) {
        let mut p = [0u8; 28];
        p[0..2].copy_from_slice(&handle.to_le_bytes());
        // random number (8 bytes zero)
        // encrypted diversifier (2 bytes zero)
        p[12..28].copy_from_slice(ltk);
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_START_ENCRYPTION), &p);
    }

    // -----------------------------------------------------------------------
    // Public API: L2CAP services
    // -----------------------------------------------------------------------

    /// Register an L2CAP server for a given PSM.
    pub fn add_l2cap_server(
        &mut self,
        psm: u16,
        connect_cb: impl Fn(u16, u16) + Send + Sync + 'static,
        disconn_cb: Option<Box<dyn Fn(u16, u16) + Send + Sync>>,
    ) {
        self.l2cap_servers.push(L2capServer {
            psm,
            connect_cb: Box::new(connect_cb),
            disconn_cb,
            mtu: 0,
            mps: 0,
            credits: 0,
        });
    }

    /// Register an L2CAP server with custom MTU/MPS/credits.
    pub fn add_l2cap_server_custom(
        &mut self,
        psm: u16,
        mtu: u16,
        mps: u16,
        credits: u16,
        connect_cb: impl Fn(u16, u16) + Send + Sync + 'static,
        disconn_cb: Option<Box<dyn Fn(u16, u16) + Send + Sync>>,
    ) {
        self.l2cap_servers.push(L2capServer {
            psm,
            connect_cb: Box::new(connect_cb),
            disconn_cb,
            mtu,
            mps,
            credits,
        });
    }

    /// Send an L2CAP signaling request and register a callback for the response.
    pub fn l2cap_req(
        &mut self,
        handle: u16,
        req: u8,
        data: &[u8],
        cb: impl Fn(u8, &[u8]) + Send + Sync + 'static,
    ) -> bool {
        let ident = self.next_sig_ident();
        let is_le = if let Some(conn) = self.connections.get(&handle) {
            conn.addr_type != BDADDR_BREDR
        } else {
            false
        };
        self.l2cap_sig_send(handle, is_le, req, ident, data);

        // For LE connection requests, create the local channel entry
        if req == L2CAP_LE_CONN_REQ && data.len() >= 10 {
            let psm = u16::from_le_bytes([data[0], data[1]]);
            let scid = u16::from_le_bytes([data[2], data[3]]);
            let mtu = u16::from_le_bytes([data[4], data[5]]);
            let mps = u16::from_le_bytes([data[6], data[7]]);
            let credits = u16::from_le_bytes([data[8], data[9]]);
            if let Some(conn) = self.connections.get_mut(&handle) {
                conn.l2conns.push(L2conn {
                    scid,
                    dcid: 0,
                    psm,
                    mtu,
                    tx_mps: 0,
                    _rx_mps: mps,
                    tx_credits: 0,
                    _rx_credits: credits,
                    mode: L2capMode::LeCred,
                    _recv_data: Vec::new(),
                    _recv_len: 0,
                });
            }
        }

        self.l2cap_pending.push(L2capPendingReq {
            handle,
            ident,
            code: req,
            data: data.to_vec(),
            cb: Some(Box::new(cb)),
        });
        true
    }

    // -----------------------------------------------------------------------
    // Public API: Data hooks
    // -----------------------------------------------------------------------

    /// Add a hook for data received on a specific CID.
    pub fn add_cid_hook(
        &mut self,
        handle: u16,
        cid: u16,
        func: impl Fn(&[u8]) + Send + Sync + 'static,
    ) {
        if let Some(conn) = self.connections.get_mut(&handle) {
            conn.cid_hooks.push(CidHook { cid, func: Box::new(func) });
        }
    }

    /// Add a hook for SCO data received on a handle.
    pub fn add_sco_hook(&mut self, handle: u16, func: impl Fn(&[u8], u8) + Send + Sync + 'static) {
        if let Some(conn) = self.connections.get_mut(&handle) {
            conn.sco_hooks.push(ScoHook { func: Box::new(func) });
        }
    }

    /// Add a hook for ISO data received on a handle.
    pub fn add_iso_hook(&mut self, handle: u16, func: impl Fn(&[u8]) + Send + Sync + 'static) {
        if let Some(conn) = self.connections.get_mut(&handle) {
            conn.iso_hooks.push(IsoHook { func: Box::new(func) });
        }
    }

    /// Send data on a specific L2CAP CID.
    pub fn send_cid(&self, handle: u16, cid: u16, data: &[u8]) {
        self.send_cid_internal(handle, cid, data);
    }

    /// Send gathered data on a specific L2CAP CID.
    pub fn send_cid_v(&self, handle: u16, cid: u16, iov: &[IoSlice<'_>]) {
        let total: usize = iov.iter().map(|v| v.len()).sum();
        let mut buf = Vec::with_capacity(total);
        for v in iov {
            buf.extend_from_slice(v);
        }
        self.send_cid_internal(handle, cid, &buf);
    }

    /// Send SCO data.
    pub fn send_sco(&self, handle: u16, pkt_status: u8, iov: &[IoSlice<'_>]) {
        let total: usize = iov.iter().map(|v| v.len()).sum();
        let mut payload = Vec::with_capacity(total);
        for v in iov {
            payload.extend_from_slice(v);
        }
        let dlen = payload.len().min(255) as u8;
        let hdr_raw = (handle & 0x0FFF) | ((pkt_status as u16 & 0x03) << 12);
        let mut pkt = Vec::with_capacity(1 + HCI_SCO_HDR_SIZE + payload.len());
        pkt.push(HCI_SCODATA_PKT);
        pkt.extend_from_slice(&hdr_raw.to_le_bytes());
        pkt.push(dlen);
        pkt.extend_from_slice(&payload[..dlen as usize]);
        self.send_packet(&pkt);
    }

    /// Send ISO data with timestamp and sequence number.
    pub fn send_iso(
        &self,
        handle: u16,
        ts: bool,
        sn: u16,
        timestamp: u32,
        pkt_status: u8,
        iov: &[IoSlice<'_>],
    ) {
        let total: usize = iov.iter().map(|v| v.len()).sum();
        let mut payload = Vec::with_capacity(total);
        for v in iov {
            payload.extend_from_slice(v);
        }
        self.send_iso_internal(handle, ts, sn, timestamp, pkt_status, &payload);
    }

    /// Disconnect a specific L2CAP CID.
    pub fn disconnect_cid(&mut self, handle: u16, cid: u16) {
        let dcid = if let Some(conn) = self.connections.get(&handle) {
            conn.l2conns.iter().find(|l| l.scid == cid).map(|l| l.dcid)
        } else {
            None
        };

        if let Some(d) = dcid {
            let mut req = [0u8; 4];
            req[0..2].copy_from_slice(&d.to_le_bytes());
            req[2..4].copy_from_slice(&cid.to_le_bytes());
            let is_le = if let Some(conn) = self.connections.get(&handle) {
                conn.addr_type != BDADDR_BREDR
            } else {
                false
            };
            self.l2cap_sig_send(handle, is_le, L2CAP_DISCONN_REQ, 0, &req);
        }
    }

    // -----------------------------------------------------------------------
    // Public API: Advertising / Scanning / ISO
    // -----------------------------------------------------------------------

    /// Write Scan Enable.
    pub fn write_scan_enable(&mut self, enable: u8) {
        self.send_command(opcode(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE), &[enable]);
    }

    /// Set legacy advertising data.
    pub fn set_adv_data(&mut self, data: &[u8]) {
        let mut p = [0u8; 32];
        let dlen = data.len().min(31);
        p[0] = dlen as u8;
        p[1..1 + dlen].copy_from_slice(&data[..dlen]);
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA), &p);
    }

    /// Enable/disable legacy advertising.
    pub fn set_adv_enable(&mut self, enable: u8) {
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE), &[enable]);
    }

    /// Set extended advertising data.
    pub fn set_ext_adv_data(&mut self, data: &[u8]) {
        let mut p = Vec::with_capacity(4 + data.len());
        p.push(0x00); // handle
        p.push(0x03); // operation: complete
        p.push(0x01); // fragment preference
        p.push(data.len() as u8);
        p.extend_from_slice(data);
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_DATA), &p);
    }

    /// Set extended advertising parameters.
    pub fn set_ext_adv_params(&mut self) {
        let mut p = [0u8; 25];
        // handle=0, properties=connectable (0x0001), intervals, channel map, etc.
        p[1..3].copy_from_slice(&0x0001u16.to_le_bytes());
        // min/max interval (3 bytes each) = 0x000800
        p[3] = 0x00;
        p[4] = 0x08;
        p[5] = 0x00;
        p[6] = 0x00;
        p[7] = 0x08;
        p[8] = 0x00;
        p[9] = 0x07; // channel map: all
        p[10] = 0x00; // own addr type: public
        p[11] = 0x00; // peer addr type
        // peer addr: zeros
        p[18] = 0x00; // filter policy
        p[19] = 0x7F; // TX power: host has no preference
        p[20] = 0x01; // primary PHY: 1M
        p[21] = 0x00; // secondary max skip
        p[22] = 0x01; // secondary PHY: 1M
        p[23] = 0x00; // SID
        p[24] = 0x00; // scan req notify: disabled
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_PARAMS), &p);
    }

    /// Enable/disable extended advertising.
    pub fn set_ext_adv_enable(&mut self, enable: u8) {
        let mut p = [0u8; 6];
        p[0] = enable;
        p[1] = if enable != 0 { 1 } else { 0 }; // num sets
        // set 0: handle=0, duration=0, max events=0
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_ENABLE), &p);
    }

    /// Set periodic advertising parameters.
    pub fn set_pa_params(&mut self) {
        let mut p = [0u8; 7];
        // handle=0
        p[1..3].copy_from_slice(&0x0060u16.to_le_bytes()); // min interval
        p[3..5].copy_from_slice(&0x0078u16.to_le_bytes()); // max interval
        p[5..7].copy_from_slice(&0x0000u16.to_le_bytes()); // properties
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_PA_PARAMS), &p);
    }

    /// Set periodic advertising data (with fragmentation for large data).
    pub fn set_pa_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            let p = [0u8; 3]; // handle=0, operation=complete, length=0
            self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_PA_DATA), &p);
            return;
        }

        let max_frag = BT_PA_MAX_DATA_LEN;
        let mut offset = 0;
        while offset < data.len() {
            let chunk = (data.len() - offset).min(max_frag);
            let is_first = offset == 0;
            let is_last = offset + chunk >= data.len();
            let operation = match (is_first, is_last) {
                (true, true) => 0x03,   // Complete
                (true, false) => 0x01,  // First fragment
                (false, true) => 0x02,  // Last fragment
                (false, false) => 0x00, // Intermediate
            };
            let mut p = Vec::with_capacity(3 + chunk);
            p.push(0x00); // handle
            p.push(operation);
            p.push(chunk as u8);
            p.extend_from_slice(&data[offset..offset + chunk]);
            self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_PA_DATA), &p);
            offset += chunk;
        }
    }

    /// Enable/disable periodic advertising.
    pub fn set_pa_enable(&mut self, enable: u8) {
        let p = [enable, 0x00]; // enable, handle
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_PA_ENABLE), &p);
    }

    /// Set PAST mode (how to handle received PA sync transfers).
    pub fn set_past_mode(&mut self, mode: u8) {
        // C: bthost_set_past_mode sends LE_PAST_PARAMS (0x205C)
        // struct: handle(2), mode(1), skip(2), sync_timeout(2), cte_type(1)
        let mut p = [0u8; 8];
        // handle = 0x0000 (default)
        p[2] = mode;
        // skip, sync_timeout, cte_type stay 0
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_PAST_PARAMS), &p);
    }

    /// Set BASE data for broadcast audio.
    pub fn set_base(&mut self, data: &[u8]) {
        // Construct advertising data with service data for BAA_SERVICE UUID
        let svc_data_len = 2 + data.len(); // UUID16 + data
        let ad_len = 1 + svc_data_len; // type byte + svc_data
        let mut ad = Vec::with_capacity(1 + ad_len);
        ad.push(ad_len as u8); // length
        ad.push(0x16); // type: Service Data - 16-bit UUID
        ad.extend_from_slice(&BAA_SERVICE_UUID16.to_le_bytes());
        ad.extend_from_slice(data);
        self.set_pa_data(&ad);
    }

    /// Send PAST set info for a PA sync transfer.
    ///
    /// Sends the LE Periodic Advertising Sync Transfer command to the controller
    /// with the specified connection handle and service data.
    pub fn past_set_info(&mut self, handle: u16, service_data: u16) {
        // C: bthost_past_set_info sends LE_PAST_SET_INFO (0x205B)
        // struct: handle(2), service_data(2), adv_handle(1)
        let mut p = [0u8; 5];
        p[0] = handle as u8;
        p[1] = (handle >> 8) as u8;
        p[2] = service_data as u8;
        p[3] = (service_data >> 8) as u8;
        p[4] = 0x01; // adv_handle
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_PAST_SET_INFO), &p);
    }

    /// Create a BIG (Broadcast Isochronous Group).
    pub fn create_big(&mut self, num_bis: u8, params: &[u8]) {
        let mut p = Vec::with_capacity(1 + params.len());
        p.push(num_bis);
        p.extend_from_slice(params);
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_CREATE_BIG), &p);
    }

    /// Terminate a BIG.
    pub fn terminate_big(&mut self, big_handle: u8, reason: u8) {
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_TERMINATE_BIG), &[big_handle, reason]);
    }

    /// Search extended advertising reports for a matching address.
    pub fn search_ext_adv_addr(&self, addr: &[u8; 6]) -> bool {
        self.le_ext_advs.iter().any(|a| a.addr == *addr)
    }

    /// Set CIG parameters.
    pub fn set_cig_params(&mut self, params: &[u8]) {
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_CIG_PARAMS), params);
    }

    /// Create CIS connections.
    pub fn create_cis(&mut self, params: &[u8]) {
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_CREATE_CIS), params);
    }

    /// Set LE scan parameters.
    pub fn set_scan_params(&mut self) {
        let mut p = [0u8; 7];
        p[0] = 0x01; // own addr type public
        p[1] = 0x00; // filter policy: accept all
        p[2] = 0x01; // PHYs: 1M
        // 1M scan params: type=active, interval=0x0060, window=0x0030
        p[3] = 0x01;
        p[4..6].copy_from_slice(&0x0060u16.to_le_bytes());
        // Note: this is simplified; C code sends BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_EXT_SCAN_PARAMS), &p);
    }

    /// Enable/disable LE scanning.
    pub fn set_scan_enable(&mut self, enable: u8) {
        let mut p = [0u8; 6];
        p[0] = enable;
        p[1] = 0x00; // filter duplicates
        p[2..4].copy_from_slice(&0x0000u16.to_le_bytes()); // duration
        p[4..6].copy_from_slice(&0x0000u16.to_le_bytes()); // period
        self.send_command(opcode(OGF_LE_CTL, OCF_LE_SET_EXT_SCAN_ENABLE), &p);
    }

    // -----------------------------------------------------------------------
    // Public API: Security
    // -----------------------------------------------------------------------

    /// Write SSP (Secure Simple Pairing) mode.
    pub fn write_ssp_mode(&mut self, mode: u8) {
        self.ssp_mode = mode != 0;
        self.send_command(opcode(OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE), &[mode]);
    }

    /// Write LE Host Supported.
    pub fn write_le_host_supported(&mut self, le: u8) {
        self.le_host_supported = le != 0;
        let p = [le, 0x00]; // le host supported, simultaneous LE and BR/EDR
        self.send_command(opcode(OGF_HOST_CTL, OCF_WRITE_LE_HOST_SUPPORTED), &p);
    }

    /// Request authentication for an existing connection.
    pub fn request_auth(&mut self, handle: u16) {
        self.send_command(opcode(OGF_LINK_CONTROL, OCF_AUTH_REQUESTED), &handle.to_le_bytes());
    }

    /// Enable/disable Secure Connections support.
    pub fn set_sc_support(&mut self, enable: bool) {
        self.sc_support = enable;
        let val = if enable { 0x01u8 } else { 0x00u8 };
        self.send_command(opcode(OGF_HOST_CTL, OCF_WRITE_SC_SUPPORT), &[val]);
    }

    /// Set PIN code for legacy pairing.
    pub fn set_pin_code(&mut self, pin: &[u8]) {
        if pin.is_empty() {
            self.pin = None;
        } else {
            self.pin = Some(pin.to_vec());
        }
    }

    /// Set IO capability for SSP.
    pub fn set_io_capability(&mut self, cap: u8) {
        self.io_capability = cap;
    }

    /// Get current IO capability.
    pub fn get_io_capability(&self) -> u8 {
        self.io_capability
    }

    /// Set authentication requirements for SSP.
    pub fn set_auth_req(&mut self, req: u8) {
        self.auth_req = req;
    }

    /// Get current authentication requirements.
    pub fn get_auth_req(&self) -> u8 {
        self.auth_req
    }

    /// Set whether to reject user confirmation requests.
    pub fn set_reject_user_confirm(&mut self, reject: bool) {
        self.reject_user_confirm = reject;
    }

    /// Get whether user confirmation is rejected.
    pub fn get_reject_user_confirm(&self) -> bool {
        self.reject_user_confirm
    }

    /// Check if BR/EDR is supported (LMP feature check).
    pub fn bredr_capable(&self) -> bool {
        // features[4] bit 5 = BR/EDR Not Supported; if clear, BR/EDR is capable
        self.features[4] & (1 << 5) == 0
    }

    /// Get fixed channel bitmap for a connection.
    pub fn conn_get_fixed_chan(&self, handle: u16) -> u64 {
        self.connections.get(&handle).map(|c| c.fixed_chan).unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Public API: RFCOMM
    // -----------------------------------------------------------------------

    /// Register an RFCOMM server.
    pub fn add_rfcomm_server(
        &mut self,
        channel: u8,
        connect_cb: impl Fn(u16, u16, bool) + Send + Sync + 'static,
    ) {
        self.rfcomm_servers.push(RfcommServer { channel, connect_cb: Box::new(connect_cb) });
        // Also register L2CAP server for PSM 3 if not already registered
        if !self.l2cap_servers.iter().any(|s| s.psm == RFCOMM_PSM) {
            self.l2cap_servers.push(L2capServer {
                psm: RFCOMM_PSM,
                connect_cb: Box::new(|_, _| {}),
                disconn_cb: None,
                mtu: 0,
                mps: 0,
                credits: 0,
            });
        }
    }

    /// Initiate an RFCOMM connection.
    pub fn connect_rfcomm(
        &mut self,
        handle: u16,
        channel: u8,
        cb: impl Fn(u16, u16, bool) + Send + Sync + 'static,
    ) {
        self.rfcomm_conn_data = Some(RfcommConnectionData { channel, cb: Box::new(cb) });

        // Allocate L2CAP channel for RFCOMM PSM
        let scid = if let Some(conn) = self.connections.get_mut(&handle) {
            let c = conn.next_cid;
            conn.next_cid += 1;
            conn.l2conns.push(L2conn {
                scid: c,
                dcid: 0,
                psm: RFCOMM_PSM,
                mtu: 672,
                tx_mps: 0,
                _rx_mps: 0,
                tx_credits: 0,
                _rx_credits: 0,
                mode: L2capMode::Basic,
                _recv_data: Vec::new(),
                _recv_len: 0,
            });
            c
        } else {
            return;
        };

        // Send L2CAP Connection Request
        let mut req = [0u8; 4];
        req[0..2].copy_from_slice(&RFCOMM_PSM.to_le_bytes());
        req[2..4].copy_from_slice(&scid.to_le_bytes());
        self.l2cap_sig_send(handle, false, L2CAP_CONN_REQ, 0, &req);
    }

    /// Add a hook for RFCOMM channel data.
    pub fn add_rfcomm_chan_hook(
        &mut self,
        handle: u16,
        cid: u16,
        func: impl Fn(&[u8]) + Send + Sync + 'static,
    ) {
        if let Some(conn) = self.connections.get_mut(&handle) {
            for rc in &mut conn.rfcomm_chans {
                if rc.cid == cid {
                    rc.chan_hooks.push(RfcommChanHook { func: Box::new(func) });
                    return;
                }
            }
        }
    }

    /// Send data on an RFCOMM channel.
    pub fn send_rfcomm_data(&self, handle: u16, cid: u16, data: &[u8]) {
        // Find the RFCOMM channel to get DLCI
        let dlci = if let Some(conn) = self.connections.get(&handle) {
            conn.rfcomm_chans.iter().find(|r| r.cid == cid).map(|r| r.dlci)
        } else {
            None
        };

        let dlci = match dlci {
            Some(d) => d,
            None => return,
        };

        let a = rfcomm_addr(1, dlci);
        let c = rfcomm_ctrl(RFCOMM_UIH, 0);
        let dlen = data.len();

        let mut frame = Vec::with_capacity(4 + dlen);
        frame.push(a);
        frame.push(c);

        if dlen > 127 {
            frame.push(((dlen & 0x7F) << 1) as u8);
            frame.push((dlen >> 7) as u8);
        } else {
            frame.push(rfcomm_len8(dlen as u8));
        }

        frame.extend_from_slice(data);
        frame.push(rfcomm_fcs2(&[a, c]));

        self.send_acl_raw(handle, cid, &frame, false);
    }
}
