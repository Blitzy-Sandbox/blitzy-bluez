// SPDX-License-Identifier: GPL-2.0-or-later
//
// Virtual host stack replacing emulator/bthost.c
//
// Implements a minimal Bluetooth host: HCI command/event processing,
// L2CAP connection management, and hooks for test verification.

use std::sync::{Arc, Mutex};

use crate::smp::Smp;

// H4 packet types
const H4_CMD_PKT: u8 = 0x01;
const H4_ACL_PKT: u8 = 0x02;
const H4_EVT_PKT: u8 = 0x04;
const H4_ISO_PKT: u8 = 0x05;

// L2CAP CIDs
const L2CAP_CID_SIGNALING: u16 = 0x0001;
const L2CAP_CID_ATT: u16 = 0x0004;
const L2CAP_CID_LE_SIGNALING: u16 = 0x0005;
const L2CAP_CID_SMP: u16 = 0x0006;
const L2CAP_CID_SMP_BREDR: u16 = 0x0007;

// L2CAP signaling commands
#[allow(dead_code)]
const L2CAP_CONN_REQ: u8 = 0x02;
const L2CAP_CONN_RSP: u8 = 0x03;
const L2CAP_CONF_REQ: u8 = 0x04;
const L2CAP_CONF_RSP: u8 = 0x05;
const L2CAP_INFO_REQ: u8 = 0x0a;

/// L2CAP connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2capMode {
    Other,
    LeCred,
    LeEnhCred,
}

/// L2CAP connection.
#[derive(Debug)]
pub struct L2Conn {
    pub scid: u16,
    pub dcid: u16,
    pub psm: u16,
    pub rx_mps: u16,
    pub tx_mps: u16,
    pub rx_credits: u16,
    pub tx_credits: u16,
    pub mode: L2capMode,
}

/// ACL connection.
pub struct BtConn {
    pub handle: u16,
    pub bdaddr: [u8; 6],
    pub addr_type: u8,
    pub encrypted: bool,
    pub next_cid: u16,
    pub fixed_chan: u64,
    pub l2conns: Vec<L2Conn>,
}

impl BtConn {
    fn new(handle: u16, bdaddr: [u8; 6], addr_type: u8) -> Self {
        Self {
            handle,
            bdaddr,
            addr_type,
            encrypted: false,
            next_cid: 0x0040,
            fixed_chan: 0x02, // L2CAP signaling always supported
            l2conns: Vec::new(),
        }
    }

    fn alloc_cid(&mut self) -> u16 {
        let cid = self.next_cid;
        self.next_cid += 1;
        cid
    }
}

/// Outgoing packet handler.
pub type BtHostSendHandler = Box<dyn Fn(&[u8]) + Send + Sync>;

/// Connection callback.
pub type NewConnCb = Box<dyn Fn(u16) + Send + Sync>;

/// Accept ISO callback: returns accept/reject.
pub type AcceptIsoCb = Box<dyn Fn(u16) -> u8 + Send + Sync>;

/// L2CAP connect callback.
pub type L2capConnectCb = Box<dyn Fn(u16, u16) + Send + Sync>;

/// L2CAP disconnect callback.
pub type L2capDisconnectCb = Box<dyn Fn(u16, u16) + Send + Sync>;

/// CID data hook.
pub type CidHookFn = Box<dyn Fn(&[u8]) + Send + Sync>;

/// SCO data hook.
pub type ScoHookFn = Box<dyn Fn(&[u8], u8) + Send + Sync>;

/// ISO data hook.
pub type IsoHookFn = Box<dyn Fn(&[u8]) + Send + Sync>;

/// L2CAP server registration.
#[allow(dead_code)]
struct L2capServer {
    psm: u16,
    mtu: u16,
    mps: u16,
    credits: u16,
    connect_cb: Option<L2capConnectCb>,
    disconnect_cb: Option<L2capDisconnectCb>,
}

/// CID hook registration.
struct CidHook {
    handle: u16,
    cid: u16,
    func: CidHookFn,
}

#[allow(dead_code)]
struct BtHostInner {
    ready: bool,
    bdaddr: [u8; 6],
    features: [u8; 8],

    send_handler: Option<BtHostSendHandler>,

    // Command queue
    ncmd: u8,
    cmd_queue: Vec<Vec<u8>>,

    // Connections
    connections: Vec<BtConn>,

    // Callbacks
    new_conn_cb: Option<NewConnCb>,
    new_sco_cb: Option<NewConnCb>,
    accept_iso_cb: Option<AcceptIsoCb>,
    new_iso_cb: Option<NewConnCb>,

    // L2CAP
    l2cap_servers: Vec<L2capServer>,
    cid_hooks: Vec<CidHook>,
    l2cap_ident: u8,

    // MTU
    acl_mtu: u16,
    iso_mtu: u16,

    // Pairing
    pin: [u8; 16],
    pin_len: u8,
    io_capability: u8,
    auth_req: u8,
    reject_user_confirm: bool,

    // SMP
    smp: Smp,

    // LE
    le: bool,
    sc: bool,
    conn_init: bool,

    // Advertising
    adv_data: Vec<u8>,
    adv_enable: bool,
}

/// Virtual Bluetooth host protocol handler.
pub struct BtHost {
    inner: Arc<Mutex<BtHostInner>>,
}

impl BtHost {
    /// Create a new host instance.
    pub fn create() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BtHostInner {
                ready: false,
                bdaddr: [0; 6],
                features: [0; 8],
                send_handler: None,
                ncmd: 1,
                cmd_queue: Vec::new(),
                connections: Vec::new(),
                new_conn_cb: None,
                new_sco_cb: None,
                accept_iso_cb: None,
                new_iso_cb: None,
                l2cap_servers: Vec::new(),
                cid_hooks: Vec::new(),
                l2cap_ident: 1,
                acl_mtu: 192,
                iso_mtu: 251,
                pin: [0; 16],
                pin_len: 0,
                io_capability: 0x03, // NoInputNoOutput
                auth_req: 0x01, // Bonding
                reject_user_confirm: false,
                smp: Smp::new(),
                le: false,
                sc: false,
                conn_init: false,
                adv_data: Vec::new(),
                adv_enable: false,
            })),
        }
    }

    /// Clone the Arc reference.
    pub fn clone_ref(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Set the outgoing packet handler.
    pub fn set_send_handler(&self, handler: BtHostSendHandler) {
        self.inner.lock().unwrap().send_handler = Some(handler);
    }

    /// Set ACL MTU.
    pub fn set_acl_mtu(&self, mtu: u16) {
        self.inner.lock().unwrap().acl_mtu = mtu;
    }

    /// Set ISO MTU.
    pub fn set_iso_mtu(&self, mtu: u16) {
        self.inner.lock().unwrap().iso_mtu = mtu;
    }

    /// Set connection callback.
    pub fn set_connect_cb(&self, cb: NewConnCb) {
        self.inner.lock().unwrap().new_conn_cb = Some(cb);
    }

    /// Set SCO connection callback.
    pub fn set_sco_cb(&self, cb: NewConnCb) {
        self.inner.lock().unwrap().new_sco_cb = Some(cb);
    }

    /// Set IO capability for pairing.
    pub fn set_io_capability(&self, io_cap: u8) {
        let mut inner = self.inner.lock().unwrap();
        inner.io_capability = io_cap;
        inner.smp.set_io_capability(io_cap);
    }

    /// Get IO capability.
    pub fn get_io_capability(&self) -> u8 {
        self.inner.lock().unwrap().io_capability
    }

    /// Set auth requirements.
    pub fn set_auth_req(&self, auth_req: u8) {
        let mut inner = self.inner.lock().unwrap();
        inner.auth_req = auth_req;
        inner.smp.set_auth_req(auth_req);
    }

    /// Get auth requirements.
    pub fn get_auth_req(&self) -> u8 {
        self.inner.lock().unwrap().auth_req
    }

    /// Set whether to reject user confirmation.
    pub fn set_reject_user_confirm(&self, reject: bool) {
        self.inner.lock().unwrap().reject_user_confirm = reject;
    }

    /// Get reject_user_confirm setting.
    pub fn get_reject_user_confirm(&self) -> bool {
        self.inner.lock().unwrap().reject_user_confirm
    }

    /// Enable secure connections.
    pub fn set_sc_support(&self, enable: bool) {
        self.inner.lock().unwrap().sc = enable;
    }

    /// Set PIN code for legacy pairing.
    pub fn set_pin_code(&self, pin: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        let len = pin.len().min(16);
        inner.pin[..len].copy_from_slice(&pin[..len]);
        inner.pin_len = len as u8;
    }

    /// Check if BR/EDR capable.
    pub fn bredr_capable(&self) -> bool {
        // Check features byte 4 bit 6 (LE supported) - if LE only, no BR/EDR
        let inner = self.inner.lock().unwrap();
        inner.features[0] != 0 || !inner.le
    }

    /// Get fixed channels for a connection.
    pub fn conn_get_fixed_chan(&self, handle: u16) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner
            .connections
            .iter()
            .find(|c| c.handle == handle)
            .map(|c| c.fixed_chan)
            .unwrap_or(0)
    }

    /// Add a CID hook for data inspection.
    pub fn add_cid_hook(&self, handle: u16, cid: u16, func: CidHookFn) {
        self.inner.lock().unwrap().cid_hooks.push(CidHook {
            handle,
            cid,
            func,
        });
    }

    /// Add an L2CAP server.
    pub fn add_l2cap_server(
        &self,
        psm: u16,
        connect_cb: Option<L2capConnectCb>,
        disconnect_cb: Option<L2capDisconnectCb>,
    ) {
        self.inner.lock().unwrap().l2cap_servers.push(L2capServer {
            psm,
            mtu: 672,
            mps: 0,
            credits: 0,
            connect_cb,
            disconnect_cb,
        });
    }

    /// Add an L2CAP server with custom parameters.
    pub fn add_l2cap_server_custom(
        &self,
        psm: u16,
        mtu: u16,
        mps: u16,
        credits: u16,
        connect_cb: Option<L2capConnectCb>,
        disconnect_cb: Option<L2capDisconnectCb>,
    ) {
        self.inner.lock().unwrap().l2cap_servers.push(L2capServer {
            psm,
            mtu,
            mps,
            credits,
            connect_cb,
            disconnect_cb,
        });
    }

    /// Set advertising data.
    pub fn set_adv_data(&self, data: &[u8]) {
        self.inner.lock().unwrap().adv_data = data.to_vec();
    }

    /// Set advertising enable.
    pub fn set_adv_enable(&self, enable: bool) {
        self.inner.lock().unwrap().adv_enable = enable;
    }

    /// Process incoming H4 packet from the controller.
    pub fn receive_h4(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match data[0] {
            H4_EVT_PKT => self.process_evt(&data[1..]),
            H4_ACL_PKT => self.process_acl(&data[1..]),
            H4_ISO_PKT => self.process_iso(&data[1..]),
            _ => {}
        }
    }

    fn process_evt(&self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let event_code = data[0];
        let param_len = data[1] as usize;
        if data.len() < 2 + param_len {
            return;
        }
        let params = &data[2..2 + param_len];

        match event_code {
            0x0e => self.handle_cmd_complete(params),
            0x0f => self.handle_cmd_status(params),
            0x03 => self.handle_conn_complete(params),
            0x3e => self.handle_le_meta_event(params),
            0x05 => self.handle_disconn_complete(params),
            0x13 => self.handle_num_completed_packets(params),
            _ => {}
        }
    }

    fn handle_cmd_complete(&self, params: &[u8]) {
        if params.len() < 3 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.ncmd = params[0];
        let _opcode = u16::from_le_bytes([params[1], params[2]]);
        // Process any queued commands
        Self::process_cmd_queue(&mut inner);
    }

    fn handle_cmd_status(&self, params: &[u8]) {
        if params.len() < 4 {
            return;
        }
        let _status = params[0];
        let mut inner = self.inner.lock().unwrap();
        inner.ncmd = params[1];
        Self::process_cmd_queue(&mut inner);
    }

    fn handle_conn_complete(&self, params: &[u8]) {
        if params.len() < 11 {
            return;
        }
        let status = params[0];
        if status != 0x00 {
            return;
        }
        let handle = u16::from_le_bytes([params[1], params[2]]);
        let mut bdaddr = [0u8; 6];
        bdaddr.copy_from_slice(&params[3..9]);

        let mut inner = self.inner.lock().unwrap();
        inner.connections.push(BtConn::new(handle, bdaddr, 0x00));

        // Notify
        if let Some(ref cb) = inner.new_conn_cb {
            cb(handle);
        }
    }

    fn handle_le_meta_event(&self, params: &[u8]) {
        if params.is_empty() {
            return;
        }
        let sub_event = params[0];
        match sub_event {
            0x01 => self.handle_le_conn_complete(&params[1..]),
            0x0a => self.handle_le_enhanced_conn_complete(&params[1..]),
            _ => {}
        }
    }

    fn handle_le_conn_complete(&self, params: &[u8]) {
        if params.len() < 18 {
            return;
        }
        let status = params[0];
        if status != 0x00 {
            return;
        }
        let handle = u16::from_le_bytes([params[1], params[2]]);
        let _role = params[3];
        let addr_type = params[4];
        let mut bdaddr = [0u8; 6];
        bdaddr.copy_from_slice(&params[5..11]);

        let mut inner = self.inner.lock().unwrap();
        inner.le = true;
        inner
            .connections
            .push(BtConn::new(handle, bdaddr, addr_type));

        if let Some(ref cb) = inner.new_conn_cb {
            cb(handle);
        }
    }

    fn handle_le_enhanced_conn_complete(&self, params: &[u8]) {
        // Same structure as LE Connection Complete but with local/peer RPA
        self.handle_le_conn_complete(params);
    }

    fn handle_disconn_complete(&self, params: &[u8]) {
        if params.len() < 4 {
            return;
        }
        let _status = params[0];
        let handle = u16::from_le_bytes([params[1], params[2]]);

        let mut inner = self.inner.lock().unwrap();
        inner.connections.retain(|c| c.handle != handle);
    }

    fn handle_num_completed_packets(&self, _params: &[u8]) {
        // Flow control: update credits
    }

    fn process_acl(&self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let handle_flags = u16::from_le_bytes([data[0], data[1]]);
        let handle = handle_flags & 0x0FFF;
        let _pb_flag = (handle_flags >> 12) & 0x03;
        let _bc_flag = (handle_flags >> 14) & 0x03;
        let data_len = u16::from_le_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + data_len || data_len < 4 {
            return;
        }

        let l2cap_data = &data[4..4 + data_len];
        let l2cap_len = u16::from_le_bytes([l2cap_data[0], l2cap_data[1]]) as usize;
        let cid = u16::from_le_bytes([l2cap_data[2], l2cap_data[3]]);

        if l2cap_data.len() < 4 + l2cap_len {
            return;
        }

        let payload = &l2cap_data[4..4 + l2cap_len];

        match cid {
            L2CAP_CID_SIGNALING => self.handle_l2cap_signaling(handle, payload),
            L2CAP_CID_LE_SIGNALING => self.handle_le_l2cap_signaling(handle, payload),
            L2CAP_CID_ATT => self.handle_att(handle, payload),
            L2CAP_CID_SMP => self.handle_smp(handle, payload),
            L2CAP_CID_SMP_BREDR => self.handle_smp_bredr(handle, payload),
            _ => self.handle_cid_data(handle, cid, payload),
        }
    }

    fn handle_l2cap_signaling(&self, handle: u16, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let code = data[0];
        let _ident = data[1];
        let _length = u16::from_le_bytes([data[2], data[3]]);

        match code {
            L2CAP_INFO_REQ => {
                // Auto-respond to info requests
            }
            L2CAP_CONN_REQ => {
                // Handle incoming L2CAP connection request
                if data.len() >= 8 {
                    let psm = u16::from_le_bytes([data[4], data[5]]);
                    let scid = u16::from_le_bytes([data[6], data[7]]);
                    self.handle_l2cap_conn_req(handle, _ident, psm, scid);
                }
            }
            L2CAP_CONF_REQ => {
                // Auto-accept configuration
                if data.len() >= 6 {
                    let dcid = u16::from_le_bytes([data[4], data[5]]);
                    self.send_l2cap_conf_rsp(handle, _ident, dcid);
                }
            }
            _ => {}
        }
    }

    fn handle_l2cap_conn_req(&self, handle: u16, ident: u8, psm: u16, scid: u16) {
        let mut inner = self.inner.lock().unwrap();

        // Find server
        let has_server = inner.l2cap_servers.iter().any(|s| s.psm == psm);
        if !has_server {
            return;
        }

        // Find connection and allocate CID
        if let Some(conn) = inner.connections.iter_mut().find(|c| c.handle == handle) {
            let dcid = conn.alloc_cid();
            conn.l2conns.push(L2Conn {
                scid: dcid,
                dcid: scid,
                psm,
                rx_mps: 0,
                tx_mps: 0,
                rx_credits: 0,
                tx_credits: 0,
                mode: L2capMode::Other,
            });

            // Send response
            let mut rsp = vec![L2CAP_CONN_RSP, ident, 8, 0];
            rsp.extend_from_slice(&dcid.to_le_bytes());
            rsp.extend_from_slice(&scid.to_le_bytes());
            rsp.extend_from_slice(&0u16.to_le_bytes()); // result: success
            rsp.extend_from_slice(&0u16.to_le_bytes()); // status: no info
            Self::send_l2cap_inner(&inner, handle, L2CAP_CID_SIGNALING, &rsp);
        }
    }

    fn send_l2cap_conf_rsp(&self, handle: u16, ident: u8, dcid: u16) {
        let inner = self.inner.lock().unwrap();
        let mut rsp = vec![L2CAP_CONF_RSP, ident, 6, 0];
        rsp.extend_from_slice(&dcid.to_le_bytes());
        rsp.extend_from_slice(&0u16.to_le_bytes()); // flags
        rsp.extend_from_slice(&0u16.to_le_bytes()); // result: success
        Self::send_l2cap_inner(&inner, handle, L2CAP_CID_SIGNALING, &rsp);
    }

    fn handle_le_l2cap_signaling(&self, _handle: u16, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let _code = data[0];
        // Handle LE signaling commands
    }

    fn handle_att(&self, _handle: u16, _data: &[u8]) {
        // ATT protocol handling
    }

    fn handle_smp(&self, handle: u16, data: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(response) = inner.smp.process_data(handle, data) {
            // Send SMP response via L2CAP
            Self::send_l2cap_inner(&inner, handle, L2CAP_CID_SMP, &response);
        }
    }

    fn handle_smp_bredr(&self, _handle: u16, _data: &[u8]) {
        // BR/EDR SMP handling
    }

    fn handle_cid_data(&self, handle: u16, cid: u16, data: &[u8]) {
        let inner = self.inner.lock().unwrap();
        for hook in &inner.cid_hooks {
            if hook.handle == handle && hook.cid == cid {
                (hook.func)(data);
            }
        }
    }

    fn process_iso(&self, _data: &[u8]) {
        // ISO packet processing
    }

    /// Send an HCI command.
    pub fn send_cmd(&self, opcode: u16, params: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        let mut pkt = vec![H4_CMD_PKT];
        pkt.extend_from_slice(&opcode.to_le_bytes());
        pkt.push(params.len() as u8);
        pkt.extend_from_slice(params);

        if inner.ncmd > 0 {
            inner.ncmd -= 1;
            if let Some(ref handler) = inner.send_handler {
                handler(&pkt);
            }
        } else {
            inner.cmd_queue.push(pkt);
        }
    }

    /// Send data on an L2CAP CID.
    pub fn send_cid(&self, handle: u16, cid: u16, data: &[u8]) {
        let inner = self.inner.lock().unwrap();
        Self::send_l2cap_inner(&inner, handle, cid, data);
    }

    fn send_l2cap_inner(inner: &BtHostInner, handle: u16, cid: u16, data: &[u8]) {
        if let Some(ref handler) = inner.send_handler {
            let l2cap_len = data.len() as u16;
            let acl_len = (4 + data.len()) as u16;

            let mut pkt = vec![H4_ACL_PKT];
            // Handle with PB=00 (first, automatically flushable), BC=00
            pkt.extend_from_slice(&(handle & 0x0FFF).to_le_bytes());
            pkt.extend_from_slice(&acl_len.to_le_bytes());
            pkt.extend_from_slice(&l2cap_len.to_le_bytes());
            pkt.extend_from_slice(&cid.to_le_bytes());
            pkt.extend_from_slice(data);
            handler(&pkt);
        }
    }

    fn process_cmd_queue(inner: &mut BtHostInner) {
        while inner.ncmd > 0 && !inner.cmd_queue.is_empty() {
            let pkt = inner.cmd_queue.remove(0);
            inner.ncmd -= 1;
            if let Some(ref handler) = inner.send_handler {
                handler(&pkt);
            }
        }
    }

    /// Initiate HCI connection.
    pub fn hci_connect(&self, bdaddr: &[u8; 6], addr_type: u8) {
        if addr_type == 0x00 {
            // BR/EDR: Create Connection
            let mut params = Vec::new();
            params.extend_from_slice(bdaddr);
            params.extend_from_slice(&0xCC18u16.to_le_bytes()); // packet type
            params.push(0x02); // page scan rep mode
            params.push(0x00); // reserved
            params.extend_from_slice(&0x0000u16.to_le_bytes()); // clock offset
            params.push(0x01); // allow role switch
            self.send_cmd(0x0405, &params); // Create Connection
        } else {
            // LE: LE Create Connection
            let mut params = vec![0x60, 0x00]; // scan interval
            params.extend_from_slice(&[0x30, 0x00]); // scan window
            params.push(0x00); // filter policy: use peer addr
            params.push(addr_type);
            params.extend_from_slice(bdaddr);
            params.push(0x00); // own addr type
            params.extend_from_slice(&0x0018u16.to_le_bytes()); // conn interval min
            params.extend_from_slice(&0x0028u16.to_le_bytes()); // conn interval max
            params.extend_from_slice(&0x0000u16.to_le_bytes()); // latency
            params.extend_from_slice(&0x002au16.to_le_bytes()); // supervision timeout
            params.extend_from_slice(&0x0000u16.to_le_bytes()); // min CE length
            params.extend_from_slice(&0x0000u16.to_le_bytes()); // max CE length
            self.send_cmd(0x200d, &params); // LE Create Connection
        }
    }

    /// Disconnect an HCI connection.
    pub fn hci_disconnect(&self, handle: u16, reason: u8) {
        let mut params = Vec::new();
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(reason);
        self.send_cmd(0x0406, &params); // Disconnect
    }

    /// Write scan enable.
    pub fn write_scan_enable(&self, scan: u8) {
        self.send_cmd(0x0c1a, &[scan]);
    }

    /// Write SSP mode.
    pub fn write_ssp_mode(&self, mode: u8) {
        self.send_cmd(0x0c56, &[mode]);
    }

    /// Write LE host supported.
    pub fn write_le_host_supported(&self, mode: u8) {
        self.send_cmd(0x0c6d, &[mode, 0x00]);
    }

    /// Start the host (send initial commands).
    pub fn start(&self) {
        // Reset
        self.send_cmd(0x0c03, &[]);
        // Read Local Features
        self.send_cmd(0x1003, &[]);
        // Read BD Addr
        self.send_cmd(0x1009, &[]);
    }

    /// Initiate LE encryption.
    pub fn le_start_encrypt(&self, handle: u16, ltk: &[u8; 16]) {
        let mut params = Vec::new();
        params.extend_from_slice(&handle.to_le_bytes());
        params.extend_from_slice(&[0u8; 8]); // random
        params.extend_from_slice(&0u16.to_le_bytes()); // EDIV
        params.extend_from_slice(ltk);
        self.send_cmd(0x2019, &params); // LE Start Encryption
    }

    /// Set scan parameters.
    pub fn set_scan_params(&self, scan_type: u8, addr_type: u8, filter_policy: u8) {
        let mut params = vec![scan_type];
        params.extend_from_slice(&0x0010u16.to_le_bytes()); // interval
        params.extend_from_slice(&0x0010u16.to_le_bytes()); // window
        params.push(addr_type);
        params.push(filter_policy);
        self.send_cmd(0x200b, &params); // LE Set Scan Parameters
    }

    /// Set scan enable.
    pub fn set_scan_enable(&self, enable: u8) {
        self.send_cmd(0x200c, &[enable, 0x00]); // LE Set Scan Enable
    }
}

impl Default for BtHost {
    fn default() -> Self {
        Self::create()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_host() -> (BtHost, Arc<Mutex<Vec<Vec<u8>>>>) {
        let host = BtHost::create();
        let pkts: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let pkts_clone = pkts.clone();
        host.set_send_handler(Box::new(move |data| {
            pkts_clone.lock().unwrap().push(data.to_vec());
        }));
        (host, pkts)
    }

    #[test]
    fn test_bthost_create() {
        let host = BtHost::create();
        assert_eq!(host.get_io_capability(), 0x03);
        assert_eq!(host.get_auth_req(), 0x01);
    }

    #[test]
    fn test_bthost_send_cmd() {
        let (host, pkts) = setup_host();
        host.send_cmd(0x0c03, &[]); // Reset
        let sent = pkts.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0][0], H4_CMD_PKT);
        assert_eq!(u16::from_le_bytes([sent[0][1], sent[0][2]]), 0x0c03);
    }

    #[test]
    fn test_bthost_cmd_queue() {
        let (host, pkts) = setup_host();
        // Send first command (ncmd=1, so it sends immediately)
        host.send_cmd(0x0c03, &[]);
        // Send second (ncmd=0 now, so queued)
        host.send_cmd(0x1001, &[]);
        {
            let sent = pkts.lock().unwrap();
            assert_eq!(sent.len(), 1); // only first sent
        }

        // Simulate Command Complete event to release queue
        let mut evt = vec![H4_EVT_PKT, 0x0e, 4, 1]; // ncmd=1
        evt.extend_from_slice(&0x0c03u16.to_le_bytes());
        evt.push(0x00);
        host.receive_h4(&evt);

        let sent = pkts.lock().unwrap();
        assert_eq!(sent.len(), 2); // now both sent
    }

    #[test]
    fn test_bthost_conn_complete() {
        let (host, _pkts) = setup_host();
        let connected = Arc::new(Mutex::new(false));
        let cc = connected.clone();
        host.set_connect_cb(Box::new(move |_handle| {
            *cc.lock().unwrap() = true;
        }));

        // Simulate Connection Complete event
        let mut evt = vec![H4_EVT_PKT, 0x03, 11, 0x00]; // status=0
        evt.extend_from_slice(&0x0040u16.to_le_bytes()); // handle
        evt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // bdaddr
        evt.push(0x01); // link type
        evt.push(0x00); // encryption mode
        host.receive_h4(&evt);

        assert!(*connected.lock().unwrap());
        assert_eq!(host.conn_get_fixed_chan(0x0040), 0x02);
    }

    #[test]
    fn test_bthost_disconn() {
        let (host, _pkts) = setup_host();

        // Create connection
        let mut evt = vec![H4_EVT_PKT, 0x03, 11, 0x00];
        evt.extend_from_slice(&0x0040u16.to_le_bytes());
        evt.extend_from_slice(&[0; 6]);
        evt.push(0x01);
        evt.push(0x00);
        host.receive_h4(&evt);

        assert_eq!(host.conn_get_fixed_chan(0x0040), 0x02);

        // Simulate Disconnection Complete
        let mut evt = vec![H4_EVT_PKT, 0x05, 4, 0x00];
        evt.extend_from_slice(&0x0040u16.to_le_bytes());
        evt.push(0x16); // reason
        host.receive_h4(&evt);

        assert_eq!(host.conn_get_fixed_chan(0x0040), 0);
    }

    #[test]
    fn test_bthost_l2cap_server() {
        let (host, _pkts) = setup_host();
        host.add_l2cap_server(0x0001, None, None);
        host.add_l2cap_server_custom(0x001f, 512, 64, 10, None, None);
    }

    #[test]
    fn test_bthost_pairing_settings() {
        let host = BtHost::create();
        host.set_io_capability(0x01);
        assert_eq!(host.get_io_capability(), 0x01);
        host.set_auth_req(0x05);
        assert_eq!(host.get_auth_req(), 0x05);
        host.set_reject_user_confirm(true);
        assert!(host.get_reject_user_confirm());
        host.set_sc_support(true);
        host.set_pin_code(&[0x30, 0x30, 0x30, 0x30]);
    }

    #[test]
    fn test_bthost_send_cid() {
        let (host, pkts) = setup_host();
        host.send_cid(0x0040, L2CAP_CID_ATT, &[0x02, 0x01, 0x00, 0xff, 0xff]);

        let sent = pkts.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0][0], H4_ACL_PKT);
    }

    #[test]
    fn test_bthost_hci_connect() {
        let (host, pkts) = setup_host();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

        // BR/EDR connect
        host.hci_connect(&addr, 0x00);
        let sent = pkts.lock().unwrap();
        assert_eq!(sent[0][0], H4_CMD_PKT);
    }
}
