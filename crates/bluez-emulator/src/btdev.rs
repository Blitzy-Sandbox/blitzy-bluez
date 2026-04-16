// SPDX-License-Identifier: GPL-2.0-or-later
//
// Virtual Bluetooth device replacing emulator/btdev.c
//
// Emulates a Bluetooth controller by processing HCI commands and generating
// HCI events. Used for testing without real hardware. The command dispatch
// table pattern mirrors the C implementation.

use std::sync::{Arc, Mutex};

use crate::le::LeExtAdvSet;

// H4 packet types
const H4_CMD_PKT: u8 = 0x01;
const H4_ACL_PKT: u8 = 0x02;
const H4_SCO_PKT: u8 = 0x03;
const H4_EVT_PKT: u8 = 0x04;
const H4_ISO_PKT: u8 = 0x05;

// Response types for command handler callbacks
pub const BTDEV_RESPONSE_DEFAULT: u8 = 0;
pub const BTDEV_RESPONSE_COMMAND_STATUS: u8 = 1;
pub const BTDEV_RESPONSE_COMMAND_COMPLETE: u8 = 2;

// Limits
const AL_SIZE: usize = 16;
const RL_SIZE: usize = 16;
const MAX_HOOK_ENTRIES: usize = 16;

/// Device type (capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtDevType {
    BredrLe,
    Bredr,
    Le,
    Amp,
    Bredr20,
    BredrLe50,
    BredrLe52,
    BredrLe60,
}

impl BtDevType {
    pub fn supports_bredr(&self) -> bool {
        !matches!(self, Self::Le | Self::Amp)
    }

    pub fn supports_le(&self) -> bool {
        !matches!(self, Self::Bredr | Self::Bredr20 | Self::Amp)
    }
}

/// Hook type for intercepting commands/events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookType {
    PreCmd,
    PostCmd,
    PreEvt,
    PostEvt,
}

/// Outgoing packet handler.
pub type SendHandler = Box<dyn Fn(&[u8]) + Send + Sync>;

/// Custom command handler.
pub type CommandHandler =
    Box<dyn Fn(u16, &[u8], &BtDevHandle) + Send + Sync>;

/// Hook function: returns true to allow, false to block.
pub type HookFunc = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Handle for async command responses.
#[derive(Clone)]
pub struct BtDevHandle {
    inner: Arc<Mutex<BtDevInner>>,
}

impl BtDevHandle {
    /// Send a default response (let the device handle it).
    pub fn command_default(&self) {
        // No-op in default path
    }

    /// Send a command status event.
    pub fn command_status(&self, status: u8, opcode: u16) {
        let inner = self.inner.lock().unwrap();
        let evt = build_cmd_status(status, opcode, inner.ncmd);
        drop(inner);
        self.send_h4_event(&evt);
    }

    /// Send a command complete event.
    pub fn command_complete(&self, opcode: u16, data: &[u8]) {
        let inner = self.inner.lock().unwrap();
        let evt = build_cmd_complete(opcode, inner.ncmd, data);
        drop(inner);
        self.send_h4_event(&evt);
    }

    fn send_h4_event(&self, evt_data: &[u8]) {
        let inner = self.inner.lock().unwrap();
        if let Some(ref handler) = inner.send_handler {
            let mut pkt = vec![H4_EVT_PKT];
            pkt.extend_from_slice(evt_data);
            handler(&pkt);
        }
    }
}

/// Connection between two virtual devices.
#[derive(Debug)]
pub struct BtDevConn {
    pub handle: u16,
    pub link_type: u8,
    pub peer_addr: [u8; 6],
    pub peer_addr_type: u8,
    pub encrypted: bool,
}

/// Hook entry.
struct Hook {
    hook_type: HookType,
    opcode: u16,
    func: HookFunc,
}

#[allow(dead_code)]
struct BtDevInner {
    dev_type: BtDevType,
    id: u16,
    bdaddr: [u8; 6],
    random_addr: [u8; 6],
    name: [u8; 248],
    dev_class: [u8; 3],
    version: u8,
    manufacturer: u16,
    revision: u16,
    commands: [u8; 64],
    features: [u8; 8],
    le_features: [u8; 8],
    le_states: [u8; 8],
    event_mask: [u8; 8],
    le_event_mask: [u8; 8],
    ncmd: u8,

    // BR/EDR state
    scan_enable: u8,
    auth_enable: u8,
    simple_pairing_mode: u8,
    secure_conn_support: u8,
    inquiry_mode: u8,
    page_timeout: u16,
    voice_setting: u16,

    // LE state
    le_supported: u8,
    le_adv_data: [u8; 31],
    le_adv_data_len: u8,
    le_adv_type: u8,
    le_adv_own_addr: u8,
    le_adv_enable: u8,
    le_scan_data: [u8; 31],
    le_scan_data_len: u8,
    le_scan_enable: u8,
    le_scan_type: u8,
    le_scan_own_addr_type: u8,
    le_scan_filter_policy: u8,
    le_filter_dup: u8,
    le_pa_enable: u8,
    le_pa_data: Vec<u8>,
    le_ltk: [u8; 16],

    // Accept/Resolving lists
    le_al_len: u8,
    le_rl_len: u8,
    le_rl_enable: u8,

    // MTU
    acl_mtu: u16,
    acl_max_pkt: u16,
    sco_mtu: u16,
    sco_max_pkt: u16,
    iso_mtu: u16,
    iso_max_pkt: u16,

    // Connections
    connections: Vec<BtDevConn>,
    next_handle: u16,

    // Extended advertising
    ext_adv_sets: Vec<LeExtAdvSet>,

    // Hooks
    hooks: Vec<Hook>,

    // Vendor opcodes
    msft_opcode: u16,
    emu_opcode: u16,
    aosp_capable: bool,

    // Handlers
    send_handler: Option<SendHandler>,
    command_handler: Option<CommandHandler>,
}

/// Virtual Bluetooth device.
pub struct BtDev {
    inner: Arc<Mutex<BtDevInner>>,
}

impl BtDev {
    /// Create a new virtual device.
    pub fn create(dev_type: BtDevType, id: u16) -> Self {
        let mut commands = [0u8; 64];
        let mut features = [0u8; 8];
        let mut le_features = [0u8; 8];

        // Set default supported commands and features based on type
        Self::init_commands(&mut commands, dev_type);
        Self::init_features(&mut features, &mut le_features, dev_type);

        let mut bdaddr = [0u8; 6];
        // Generate address from id: 00:AA:01:00:00:id
        bdaddr[0] = id as u8;
        bdaddr[3] = 0x01;
        bdaddr[4] = 0xAA;

        let dev = BtDevInner {
            dev_type,
            id,
            bdaddr,
            random_addr: [0; 6],
            name: [0; 248],
            dev_class: [0; 3],
            version: 0x0d, // BT 5.4
            manufacturer: 0x003f, // Bluetooth SIG
            revision: 0x0001,
            commands,
            features,
            le_features,
            le_states: [0xff; 8],
            event_mask: [0xff; 8],
            le_event_mask: [0x1f; 8],
            ncmd: 1,
            scan_enable: 0,
            auth_enable: 0,
            simple_pairing_mode: 0,
            secure_conn_support: 0,
            inquiry_mode: 0,
            page_timeout: 0x2000,
            voice_setting: 0x0060,
            le_supported: if dev_type.supports_le() { 1 } else { 0 },
            le_adv_data: [0; 31],
            le_adv_data_len: 0,
            le_adv_type: 0,
            le_adv_own_addr: 0,
            le_adv_enable: 0,
            le_scan_data: [0; 31],
            le_scan_data_len: 0,
            le_scan_enable: 0,
            le_scan_type: 0,
            le_scan_own_addr_type: 0,
            le_scan_filter_policy: 0,
            le_filter_dup: 0,
            le_pa_enable: 0,
            le_pa_data: Vec::new(),
            le_ltk: [0; 16],
            le_al_len: AL_SIZE as u8,
            le_rl_len: RL_SIZE as u8,
            le_rl_enable: 0,
            acl_mtu: 192,
            acl_max_pkt: 1,
            sco_mtu: 64,
            sco_max_pkt: 1,
            iso_mtu: 251,
            iso_max_pkt: 1,
            connections: Vec::new(),
            next_handle: 0x0042,
            ext_adv_sets: Vec::new(),
            hooks: Vec::new(),
            msft_opcode: 0,
            emu_opcode: 0,
            aosp_capable: false,
            send_handler: None,
            command_handler: None,
        };

        Self {
            inner: Arc::new(Mutex::new(dev)),
        }
    }

    fn init_commands(commands: &mut [u8; 64], dev_type: BtDevType) {
        // Byte 0: Inquiry, Inquiry Cancel
        if dev_type.supports_bredr() {
            commands[0] = 0x23; // inquiry, inquiry cancel, create conn
        }
        // Byte 2: Disconnect
        commands[2] = 0x08; // disconnect
        // Byte 5: Set Event Mask
        commands[5] = 0x40; // set event mask
        // Byte 7: Set Event Filter, Read Stored Link Key
        commands[7] = 0x04; // set event filter
        // Byte 14: Read Local Version, Read Local Commands, Read Local Features
        commands[14] = 0xa8;
        // Byte 15: Read BD ADDR
        commands[15] = 0x02;

        if dev_type.supports_le() {
            // Byte 25: LE Set Event Mask
            commands[25] = 0x01;
            // Byte 26: LE commands
            commands[26] = 0xff;
            commands[27] = 0xff;
            commands[28] = 0xff;
        }
    }

    fn init_features(features: &mut [u8; 8], le_features: &mut [u8; 8], dev_type: BtDevType) {
        if dev_type.supports_bredr() {
            features[0] = 0xff; // 3-slot packets, ACL, SCO, etc.
            features[4] = 0x08; // AFH capable
            features[6] = 0x08; // SSP
        }
        if dev_type.supports_le() {
            features[4] |= 0x40; // LE supported
            le_features[0] = 0x01; // LE encryption
        }
    }

    /// Get a handle for async command responses.
    pub fn handle(&self) -> BtDevHandle {
        BtDevHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Clone the Arc reference.
    pub fn clone_ref(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Get the device BD address.
    pub fn get_bdaddr(&self) -> [u8; 6] {
        self.inner.lock().unwrap().bdaddr
    }

    /// Set the device BD address.
    pub fn set_bdaddr(&self, addr: &[u8; 6]) -> bool {
        self.inner.lock().unwrap().bdaddr = *addr;
        true
    }

    /// Get supported features.
    pub fn get_features(&self) -> [u8; 8] {
        self.inner.lock().unwrap().features
    }

    /// Get supported commands.
    pub fn get_commands(&self) -> [u8; 64] {
        self.inner.lock().unwrap().commands
    }

    /// Get scan enable state.
    pub fn get_scan_enable(&self) -> u8 {
        self.inner.lock().unwrap().scan_enable
    }

    /// Get LE scan enable state.
    pub fn get_le_scan_enable(&self) -> u8 {
        self.inner.lock().unwrap().le_scan_enable
    }

    /// Get MTU values.
    pub fn get_mtu(&self) -> (u16, u16, u16) {
        let inner = self.inner.lock().unwrap();
        (inner.acl_mtu, inner.sco_mtu, inner.iso_mtu)
    }

    /// Set LE states.
    pub fn set_le_states(&self, states: &[u8; 8]) {
        self.inner.lock().unwrap().le_states = *states;
    }

    /// Set accept list length.
    pub fn set_al_len(&self, len: u8) {
        self.inner.lock().unwrap().le_al_len = len;
    }

    /// Set resolving list length.
    pub fn set_rl_len(&self, len: u8) {
        self.inner.lock().unwrap().le_rl_len = len;
    }

    /// Set the outgoing packet handler.
    pub fn set_send_handler(&self, handler: SendHandler) {
        self.inner.lock().unwrap().send_handler = Some(handler);
    }

    /// Set a custom command handler (intercepts before default dispatch).
    pub fn set_command_handler(&self, handler: CommandHandler) {
        self.inner.lock().unwrap().command_handler = Some(handler);
    }

    /// Set MSFT vendor opcode.
    pub fn set_msft_opcode(&self, opcode: u16) {
        self.inner.lock().unwrap().msft_opcode = opcode;
    }

    /// Set AOSP capable flag.
    pub fn set_aosp_capable(&self, enable: bool) {
        self.inner.lock().unwrap().aosp_capable = enable;
    }

    /// Set emulator opcode.
    pub fn set_emu_opcode(&self, opcode: u16) {
        self.inner.lock().unwrap().emu_opcode = opcode;
    }

    /// Add a hook for intercepting commands/events.
    pub fn add_hook(&self, hook_type: HookType, opcode: u16, func: HookFunc) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.hooks.len() >= MAX_HOOK_ENTRIES {
            return false;
        }
        inner.hooks.push(Hook {
            hook_type,
            opcode,
            func,
        });
        true
    }

    /// Remove a hook.
    pub fn del_hook(&self, hook_type: HookType, opcode: u16) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.hooks.len();
        inner
            .hooks
            .retain(|h| !(h.hook_type == hook_type && h.opcode == opcode));
        inner.hooks.len() < before
    }

    /// Process an incoming H4 packet.
    pub fn receive_h4(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match data[0] {
            H4_CMD_PKT => self.process_cmd(&data[1..]),
            H4_ACL_PKT => self.process_acl(&data[1..]),
            H4_SCO_PKT => self.process_sco(&data[1..]),
            H4_ISO_PKT => self.process_iso(&data[1..]),
            _ => {}
        }
    }

    fn process_cmd(&self, data: &[u8]) {
        if data.len() < 3 {
            return;
        }
        let opcode = u16::from_le_bytes([data[0], data[1]]);
        let param_len = data[2] as usize;
        if data.len() < 3 + param_len {
            return;
        }
        let params = &data[3..3 + param_len];

        // Check pre-command hooks
        {
            let inner = self.inner.lock().unwrap();
            for hook in &inner.hooks {
                if hook.hook_type == HookType::PreCmd
                    && hook.opcode == opcode
                    && !(hook.func)(params)
                {
                    return; // Hook vetoed
                }
            }
        }

        // Check for custom command handler
        let has_custom = {
            let inner = self.inner.lock().unwrap();
            inner.command_handler.is_some()
        };
        if has_custom {
            let handle = self.handle();
            let inner = self.inner.lock().unwrap();
            if let Some(ref handler) = inner.command_handler {
                handler(opcode, params, &handle);
                return;
            }
        }

        // Default dispatch
        self.default_cmd(opcode, params);

        // Post-command hooks
        {
            let inner = self.inner.lock().unwrap();
            for hook in &inner.hooks {
                if hook.hook_type == HookType::PostCmd && hook.opcode == opcode {
                    (hook.func)(params);
                }
            }
        }
    }

    fn process_acl(&self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let handle_flags = u16::from_le_bytes([data[0], data[1]]);
        let _handle = handle_flags & 0x0FFF;
        let _data_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        // Forward ACL data to connected peer (simplified)
        // In full impl, would route via connection table
    }

    fn process_sco(&self, _data: &[u8]) {
        // SCO packet processing
    }

    fn process_iso(&self, _data: &[u8]) {
        // ISO packet processing
    }

    /// Default command dispatch.
    fn default_cmd(&self, opcode: u16, params: &[u8]) {
        // OGF (upper 6 bits) determines command group
        let ogf = (opcode >> 10) & 0x3F;

        match ogf {
            0x01 => self.cmd_link_control(opcode, params),
            0x02 => self.cmd_link_policy(opcode, params),
            0x03 => self.cmd_controller_baseband(opcode, params),
            0x04 => self.cmd_informational(opcode, params),
            0x05 => self.cmd_status_params(opcode, params),
            0x08 => self.cmd_le_controller(opcode, params),
            _ => self.cmd_unknown(opcode),
        }
    }

    fn cmd_unknown(&self, opcode: u16) {
        let inner = self.inner.lock().unwrap();
        let status = [BT_HCI_ERR_UNKNOWN_COMMAND];
        let evt = build_cmd_complete(opcode, inner.ncmd, &status);
        Self::send_event_inner(&inner, &evt);
    }

    fn cmd_link_control(&self, opcode: u16, params: &[u8]) {
        match opcode {
            BT_HCI_CMD_DISCONNECT => {
                if params.len() < 3 {
                    return;
                }
                let handle = u16::from_le_bytes([params[0], params[1]]);
                let reason = params[2];

                let mut inner = self.inner.lock().unwrap();
                // Send Command Status
                let status_evt = build_cmd_status(0x00, opcode, inner.ncmd);
                Self::send_event_inner(&inner, &status_evt);

                // Remove connection and send Disconnection Complete
                inner.connections.retain(|c| c.handle != handle);
                let mut evt = vec![0x00]; // status
                evt.extend_from_slice(&handle.to_le_bytes());
                evt.push(reason);
                let disc_evt = build_event(0x05, &evt); // Disconnection Complete
                Self::send_event_inner(&inner, &disc_evt);
            }
            _ => self.cmd_unknown(opcode),
        }
    }

    fn cmd_link_policy(&self, opcode: u16, _params: &[u8]) {
        self.cmd_unknown(opcode);
    }

    #[allow(clippy::single_match)]
    fn cmd_controller_baseband(&self, opcode: u16, params: &[u8]) {
        match opcode {
            BT_HCI_CMD_RESET => {
                let mut inner = self.inner.lock().unwrap();
                inner.scan_enable = 0;
                inner.le_adv_enable = 0;
                inner.le_scan_enable = 0;
                inner.connections.clear();
                let rsp = [0x00u8]; // success
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_SET_EVENT_MASK => {
                if params.len() >= 8 {
                    let mut inner = self.inner.lock().unwrap();
                    inner.event_mask.copy_from_slice(&params[..8]);
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_WRITE_SCAN_ENABLE => {
                if !params.is_empty() {
                    let mut inner = self.inner.lock().unwrap();
                    inner.scan_enable = params[0];
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_WRITE_LOCAL_NAME => {
                let mut inner = self.inner.lock().unwrap();
                let len = params.len().min(248);
                inner.name[..len].copy_from_slice(&params[..len]);
                let rsp = [0x00u8];
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_READ_LOCAL_NAME => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.name);
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_WRITE_SSP_MODE => {
                if !params.is_empty() {
                    let mut inner = self.inner.lock().unwrap();
                    inner.simple_pairing_mode = params[0];
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED => {
                if params.len() >= 2 {
                    let mut inner = self.inner.lock().unwrap();
                    inner.le_supported = params[0];
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_WRITE_SC_SUPPORT => {
                if !params.is_empty() {
                    let mut inner = self.inner.lock().unwrap();
                    inner.secure_conn_support = params[0];
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            _ => self.cmd_unknown(opcode),
        }
    }

    fn cmd_informational(&self, opcode: u16, _params: &[u8]) {
        match opcode {
            BT_HCI_CMD_READ_LOCAL_VERSION => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.push(inner.version);
                rsp.extend_from_slice(&inner.revision.to_le_bytes());
                rsp.push(inner.version); // LMP version
                rsp.extend_from_slice(&inner.manufacturer.to_le_bytes());
                rsp.extend_from_slice(&0x0000u16.to_le_bytes()); // LMP subversion
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_READ_LOCAL_COMMANDS => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.commands);
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_READ_LOCAL_FEATURES => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.features);
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_READ_BD_ADDR => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.bdaddr);
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_READ_BUFFER_SIZE => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.acl_mtu.to_le_bytes());
                rsp.push(inner.sco_mtu as u8);
                rsp.extend_from_slice(&inner.acl_max_pkt.to_le_bytes());
                rsp.extend_from_slice(&inner.sco_max_pkt.to_le_bytes());
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            _ => self.cmd_unknown(opcode),
        }
    }

    fn cmd_status_params(&self, opcode: u16, _params: &[u8]) {
        self.cmd_unknown(opcode);
    }

    fn cmd_le_controller(&self, opcode: u16, params: &[u8]) {
        match opcode {
            BT_HCI_CMD_LE_SET_EVENT_MASK => {
                if params.len() >= 8 {
                    let mut inner = self.inner.lock().unwrap();
                    inner.le_event_mask.copy_from_slice(&params[..8]);
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_LE_READ_BUFFER_SIZE => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.acl_mtu.to_le_bytes());
                rsp.push(inner.acl_max_pkt as u8);
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_LE_READ_LOCAL_FEATURES => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.le_features);
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_LE_SET_RANDOM_ADDRESS => {
                if params.len() >= 6 {
                    let mut inner = self.inner.lock().unwrap();
                    inner.random_addr.copy_from_slice(&params[..6]);
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_LE_SET_ADV_PARAMETERS => {
                let inner = self.inner.lock().unwrap();
                let rsp = [0x00u8];
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_LE_SET_ADV_DATA => {
                if !params.is_empty() {
                    let mut inner = self.inner.lock().unwrap();
                    let len = (params[0] as usize).min(31);
                    if params.len() > len {
                        inner.le_adv_data_len = len as u8;
                        inner.le_adv_data[..len].copy_from_slice(&params[1..1 + len]);
                    }
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_LE_SET_ADV_ENABLE => {
                if !params.is_empty() {
                    let mut inner = self.inner.lock().unwrap();
                    inner.le_adv_enable = params[0];
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_LE_SET_SCAN_PARAMETERS => {
                if params.len() >= 7 {
                    let mut inner = self.inner.lock().unwrap();
                    inner.le_scan_type = params[0];
                    inner.le_scan_own_addr_type = params[3]; // offset after interval/window
                    inner.le_scan_filter_policy = params[4];
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_LE_SET_SCAN_ENABLE => {
                if params.len() >= 2 {
                    let mut inner = self.inner.lock().unwrap();
                    inner.le_scan_enable = params[0];
                    inner.le_filter_dup = params[1];
                    let rsp = [0x00u8];
                    let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                    Self::send_event_inner(&inner, &evt);
                }
            }
            BT_HCI_CMD_LE_READ_ACCEPT_LIST_SIZE => {
                let inner = self.inner.lock().unwrap();
                let rsp = [0x00u8, inner.le_al_len];
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            BT_HCI_CMD_LE_READ_SUPPORTED_STATES => {
                let inner = self.inner.lock().unwrap();
                let mut rsp = vec![0x00u8]; // status
                rsp.extend_from_slice(&inner.le_states);
                let evt = build_cmd_complete(opcode, inner.ncmd, &rsp);
                Self::send_event_inner(&inner, &evt);
            }
            _ => self.cmd_unknown(opcode),
        }
    }

    fn send_event_inner(inner: &BtDevInner, evt_data: &[u8]) {
        if let Some(ref handler) = inner.send_handler {
            let mut pkt = vec![H4_EVT_PKT];
            pkt.extend_from_slice(evt_data);
            handler(&pkt);
        }
    }

    /// Send an event to the host.
    pub fn send_event(&self, event_code: u8, data: &[u8]) {
        let evt = build_event(event_code, data);
        let inner = self.inner.lock().unwrap();
        Self::send_event_inner(&inner, &evt);
    }

    /// Get the device type.
    pub fn get_type(&self) -> BtDevType {
        self.inner.lock().unwrap().dev_type
    }
}

// ---- HCI event builders ----

fn build_event(event_code: u8, data: &[u8]) -> Vec<u8> {
    let mut evt = Vec::with_capacity(2 + data.len());
    evt.push(event_code);
    evt.push(data.len() as u8);
    evt.extend_from_slice(data);
    evt
}

fn build_cmd_complete(opcode: u16, ncmd: u8, data: &[u8]) -> Vec<u8> {
    let param_len = 3 + data.len();
    let mut evt = Vec::with_capacity(2 + param_len);
    evt.push(0x0e); // Command Complete event code
    evt.push(param_len as u8);
    evt.push(ncmd);
    evt.extend_from_slice(&opcode.to_le_bytes());
    evt.extend_from_slice(data);
    evt
}

fn build_cmd_status(status: u8, opcode: u16, ncmd: u8) -> Vec<u8> {
    let mut evt = Vec::with_capacity(6);
    evt.push(0x0f); // Command Status event code
    evt.push(4); // param_len
    evt.push(status);
    evt.push(ncmd);
    evt.extend_from_slice(&opcode.to_le_bytes());
    evt
}

// ---- HCI opcode constants used by btdev ----
// These supplement the ones in bluez_shared::hci::defs

const BT_HCI_ERR_UNKNOWN_COMMAND: u8 = 0x01;
// Will be used when more commands are implemented
#[allow(dead_code)]
const BT_HCI_ERR_INVALID_PARAMETERS: u8 = 0x12;

// Common HCI commands (OGF 0x01 - Link Control)
const BT_HCI_CMD_DISCONNECT: u16 = 0x0406;

// OGF 0x03 - Controller & Baseband
const BT_HCI_CMD_RESET: u16 = 0x0c03;
const BT_HCI_CMD_SET_EVENT_MASK: u16 = 0x0c01;
const BT_HCI_CMD_WRITE_SCAN_ENABLE: u16 = 0x0c1a;
const BT_HCI_CMD_WRITE_LOCAL_NAME: u16 = 0x0c13;
const BT_HCI_CMD_READ_LOCAL_NAME: u16 = 0x0c14;
const BT_HCI_CMD_WRITE_SSP_MODE: u16 = 0x0c56;
const BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED: u16 = 0x0c6d;
const BT_HCI_CMD_WRITE_SC_SUPPORT: u16 = 0x0c7a;

// OGF 0x04 - Informational
const BT_HCI_CMD_READ_LOCAL_VERSION: u16 = 0x1001;
const BT_HCI_CMD_READ_LOCAL_COMMANDS: u16 = 0x1002;
const BT_HCI_CMD_READ_LOCAL_FEATURES: u16 = 0x1003;
const BT_HCI_CMD_READ_BD_ADDR: u16 = 0x1009;
const BT_HCI_CMD_READ_BUFFER_SIZE: u16 = 0x1005;

// OGF 0x08 - LE Controller
const BT_HCI_CMD_LE_SET_EVENT_MASK: u16 = 0x2001;
const BT_HCI_CMD_LE_READ_BUFFER_SIZE: u16 = 0x2002;
const BT_HCI_CMD_LE_READ_LOCAL_FEATURES: u16 = 0x2003;
const BT_HCI_CMD_LE_SET_RANDOM_ADDRESS: u16 = 0x2005;
const BT_HCI_CMD_LE_SET_ADV_PARAMETERS: u16 = 0x2006;
const BT_HCI_CMD_LE_SET_ADV_DATA: u16 = 0x2008;
const BT_HCI_CMD_LE_SET_ADV_ENABLE: u16 = 0x200a;
const BT_HCI_CMD_LE_SET_SCAN_PARAMETERS: u16 = 0x200b;
const BT_HCI_CMD_LE_SET_SCAN_ENABLE: u16 = 0x200c;
const BT_HCI_CMD_LE_READ_ACCEPT_LIST_SIZE: u16 = 0x200f;
const BT_HCI_CMD_LE_READ_SUPPORTED_STATES: u16 = 0x201c;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn setup_dev() -> (BtDev, Arc<Mutex<Vec<Vec<u8>>>>) {
        let dev = BtDev::create(BtDevType::BredrLe, 0);
        let pkts: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let pkts_clone = pkts.clone();
        dev.set_send_handler(Box::new(move |data| {
            pkts_clone.lock().unwrap().push(data.to_vec());
        }));
        (dev, pkts)
    }

    fn send_cmd(dev: &BtDev, opcode: u16, params: &[u8]) {
        let mut pkt = vec![H4_CMD_PKT];
        pkt.extend_from_slice(&opcode.to_le_bytes());
        pkt.push(params.len() as u8);
        pkt.extend_from_slice(params);
        dev.receive_h4(&pkt);
    }

    fn last_pkt(pkts: &Arc<Mutex<Vec<Vec<u8>>>>) -> Vec<u8> {
        pkts.lock().unwrap().last().cloned().unwrap_or_default()
    }

    #[test]
    fn test_btdev_create() {
        let dev = BtDev::create(BtDevType::BredrLe, 1);
        let addr = dev.get_bdaddr();
        assert_eq!(addr[0], 1); // id
        assert_eq!(dev.get_type(), BtDevType::BredrLe);
    }

    #[test]
    fn test_btdev_reset() {
        let (dev, pkts) = setup_dev();
        send_cmd(&dev, BT_HCI_CMD_RESET, &[]);
        let pkt = last_pkt(&pkts);
        assert_eq!(pkt[0], H4_EVT_PKT);
        assert_eq!(pkt[1], 0x0e); // Command Complete
        // Check status = success
        let status_offset = 2 + 1 + 1 + 2; // evt_hdr(2) + ncmd(1) + opcode(2)... wait
        // H4(1) + evt_code(1) + param_len(1) + ncmd(1) + opcode(2) + status(1)
        assert_eq!(pkt[6], 0x00); // status = success
    }

    #[test]
    fn test_btdev_read_bd_addr() {
        let (dev, pkts) = setup_dev();
        dev.set_bdaddr(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        send_cmd(&dev, BT_HCI_CMD_READ_BD_ADDR, &[]);
        let pkt = last_pkt(&pkts);
        assert_eq!(pkt[0], H4_EVT_PKT);
        assert_eq!(pkt[1], 0x0e); // Command Complete
        assert_eq!(pkt[6], 0x00); // status
        assert_eq!(&pkt[7..13], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_btdev_read_local_version() {
        let (dev, pkts) = setup_dev();
        send_cmd(&dev, BT_HCI_CMD_READ_LOCAL_VERSION, &[]);
        let pkt = last_pkt(&pkts);
        assert_eq!(pkt[0], H4_EVT_PKT);
        assert_eq!(pkt[6], 0x00); // status success
    }

    #[test]
    fn test_btdev_unknown_command() {
        let (dev, pkts) = setup_dev();
        send_cmd(&dev, 0xFFFF, &[]);
        let pkt = last_pkt(&pkts);
        assert_eq!(pkt[0], H4_EVT_PKT);
        assert_eq!(pkt[1], 0x0e); // Command Complete
        assert_eq!(pkt[6], BT_HCI_ERR_UNKNOWN_COMMAND);
    }

    #[test]
    fn test_btdev_le_set_adv_enable() {
        let (dev, pkts) = setup_dev();
        send_cmd(&dev, BT_HCI_CMD_LE_SET_ADV_ENABLE, &[0x01]);
        let pkt = last_pkt(&pkts);
        assert_eq!(pkt[6], 0x00); // success
        assert_eq!(dev.get_scan_enable(), 0); // scan not adv
    }

    #[test]
    fn test_btdev_hook() {
        let (dev, _pkts) = setup_dev();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();
        dev.add_hook(
            HookType::PreCmd,
            BT_HCI_CMD_RESET,
            Box::new(move |_data| {
                called_clone.store(true, Ordering::SeqCst);
                true // allow
            }),
        );
        send_cmd(&dev, BT_HCI_CMD_RESET, &[]);
        assert!(called.load(Ordering::SeqCst));

        // Test hook removal
        assert!(dev.del_hook(HookType::PreCmd, BT_HCI_CMD_RESET));
        assert!(!dev.del_hook(HookType::PreCmd, BT_HCI_CMD_RESET));
    }

    #[test]
    fn test_btdev_hook_veto() {
        let (dev, pkts) = setup_dev();
        dev.add_hook(
            HookType::PreCmd,
            BT_HCI_CMD_RESET,
            Box::new(|_data| false), // veto
        );
        send_cmd(&dev, BT_HCI_CMD_RESET, &[]);
        assert!(pkts.lock().unwrap().is_empty()); // no response
    }

    #[test]
    fn test_btdev_write_scan_enable() {
        let (dev, pkts) = setup_dev();
        send_cmd(&dev, BT_HCI_CMD_WRITE_SCAN_ENABLE, &[0x03]);
        assert_eq!(dev.get_scan_enable(), 0x03);
        let pkt = last_pkt(&pkts);
        assert_eq!(pkt[6], 0x00); // success
    }

    #[test]
    fn test_btdev_type_capabilities() {
        assert!(BtDevType::BredrLe.supports_bredr());
        assert!(BtDevType::BredrLe.supports_le());
        assert!(!BtDevType::Le.supports_bredr());
        assert!(BtDevType::Le.supports_le());
        assert!(BtDevType::Bredr.supports_bredr());
        assert!(!BtDevType::Bredr.supports_le());
    }

    #[test]
    fn test_btdev_mtu() {
        let dev = BtDev::create(BtDevType::BredrLe, 0);
        let (acl, sco, iso) = dev.get_mtu();
        assert_eq!(acl, 192);
        assert_eq!(sco, 64);
        assert_eq!(iso, 251);
    }
}
