// SPDX-License-Identifier: GPL-2.0-or-later
//
// Packet dispatch engine replacing monitor/packet.c (17,716 LOC)
//
// Main entry point for all HCI packet decoding. Dispatches packets by
// type (command, event, ACL, SCO, ISO) and delegates to protocol-specific
// sub-decoders (L2CAP, ATT, etc.).

pub mod att;
pub mod hci;
pub mod l2cap;
pub mod sdp;
pub mod smp;

use crate::display;
use crate::vendor;

// Packet filter flags
pub const FILTER_SHOW_INDEX: u64 = 1 << 0;
pub const FILTER_SHOW_DATE: u64 = 1 << 1;
pub const FILTER_SHOW_TIME: u64 = 1 << 2;
pub const FILTER_SHOW_TIME_OFFSET: u64 = 1 << 3;
pub const FILTER_SHOW_ACL_DATA: u64 = 1 << 4;
pub const FILTER_SHOW_SCO_DATA: u64 = 1 << 5;
pub const FILTER_SHOW_A2DP_STREAM: u64 = 1 << 6;
pub const FILTER_SHOW_MGMT_SOCKET: u64 = 1 << 7;
pub const FILTER_SHOW_ISO_DATA: u64 = 1 << 8;

// BTSnoop opcodes
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
#[allow(dead_code)]
const BTSNOOP_OPCODE_VENDOR_DIAG: u16 = 11;
const BTSNOOP_OPCODE_SYSTEM_NOTE: u16 = 12;
#[allow(dead_code)]
const BTSNOOP_OPCODE_USER_LOGGING: u16 = 13;
#[allow(dead_code)]
const BTSNOOP_OPCODE_CTRL_OPEN: u16 = 14;
#[allow(dead_code)]
const BTSNOOP_OPCODE_CTRL_CLOSE: u16 = 15;
#[allow(dead_code)]
const BTSNOOP_OPCODE_CTRL_COMMAND: u16 = 16;
#[allow(dead_code)]
const BTSNOOP_OPCODE_CTRL_EVENT: u16 = 17;
const BTSNOOP_OPCODE_ISO_TX_PKT: u16 = 18;
const BTSNOOP_OPCODE_ISO_RX_PKT: u16 = 19;

/// Per-index device state.
#[derive(Debug, Clone)]
pub struct IndexInfo {
    pub bus_type: u8,
    pub bdaddr: [u8; 6],
    pub name: String,
    pub manufacturer: u16,
    pub active: bool,
}

impl Default for IndexInfo {
    fn default() -> Self {
        Self {
            bus_type: 0,
            bdaddr: [0; 6],
            name: String::new(),
            manufacturer: 0xFFFF,
            active: false,
        }
    }
}

/// Packet monitor state.
pub struct MonitorState {
    filter: u64,
    selected_index: Option<u16>,
    indices: Vec<(u16, IndexInfo)>,
    decoding_enabled: bool,
}

impl MonitorState {
    /// Create a new monitor state.
    pub fn new() -> Self {
        Self {
            filter: FILTER_SHOW_TIME,
            selected_index: None,
            indices: Vec::new(),
            decoding_enabled: true,
        }
    }

    /// Set packet filter flags.
    pub fn set_filter(&mut self, filter: u64) {
        self.filter = filter;
    }

    /// Add filter flags.
    pub fn add_filter(&mut self, filter: u64) {
        self.filter |= filter;
    }

    /// Remove filter flags.
    pub fn del_filter(&mut self, filter: u64) {
        self.filter &= !filter;
    }

    /// Select a specific device index to display.
    pub fn select_index(&mut self, index: u16) {
        self.selected_index = Some(index);
    }

    /// Disable packet decoding (raw hex only).
    pub fn disable_decoding(&mut self) {
        self.decoding_enabled = false;
    }

    /// Get or create index info.
    fn get_or_create_index(&mut self, index: u16) -> &mut IndexInfo {
        if !self.indices.iter().any(|(i, _)| *i == index) {
            self.indices.push((index, IndexInfo::default()));
        }
        &mut self.indices.iter_mut().find(|(i, _)| *i == index).unwrap().1
    }

    /// Get index info.
    fn get_index(&self, index: u16) -> Option<&IndexInfo> {
        self.indices.iter().find(|(i, _)| *i == index).map(|(_, info)| info)
    }

    /// Get manufacturer for current index.
    fn get_manufacturer(&self, index: u16) -> u16 {
        self.get_index(index).map(|i| i.manufacturer).unwrap_or(0xFFFF)
    }

    /// Check if this index should be displayed.
    fn should_display(&self, index: u16) -> bool {
        match self.selected_index {
            Some(sel) => sel == index,
            None => true,
        }
    }

    /// Main dispatch for monitor channel packets.
    pub fn packet_monitor(
        &mut self,
        tv: Option<&libc::timeval>,
        index: u16,
        opcode: u16,
        data: &[u8],
    ) {
        match opcode {
            BTSNOOP_OPCODE_NEW_INDEX => self.handle_new_index(tv, index, data),
            BTSNOOP_OPCODE_DEL_INDEX => self.handle_del_index(tv, index),
            BTSNOOP_OPCODE_COMMAND_PKT => {
                if self.should_display(index) {
                    self.packet_hci_command(tv, index, data);
                }
            }
            BTSNOOP_OPCODE_EVENT_PKT => {
                if self.should_display(index) {
                    self.packet_hci_event(tv, index, data);
                }
            }
            BTSNOOP_OPCODE_ACL_TX_PKT => {
                if self.should_display(index) && self.filter & FILTER_SHOW_ACL_DATA != 0 {
                    self.packet_hci_acldata(tv, index, false, data);
                }
            }
            BTSNOOP_OPCODE_ACL_RX_PKT => {
                if self.should_display(index) && self.filter & FILTER_SHOW_ACL_DATA != 0 {
                    self.packet_hci_acldata(tv, index, true, data);
                }
            }
            BTSNOOP_OPCODE_SCO_TX_PKT | BTSNOOP_OPCODE_SCO_RX_PKT => {
                if self.should_display(index) && self.filter & FILTER_SHOW_SCO_DATA != 0 {
                    let incoming = opcode == BTSNOOP_OPCODE_SCO_RX_PKT;
                    self.print_packet_header(tv, index, if incoming { ">" } else { "<" },
                        "SCO Data", display::COLOR_YELLOW);
                    display::print_hexdump(data);
                }
            }
            BTSNOOP_OPCODE_ISO_TX_PKT | BTSNOOP_OPCODE_ISO_RX_PKT => {
                if self.should_display(index) && self.filter & FILTER_SHOW_ISO_DATA != 0 {
                    let incoming = opcode == BTSNOOP_OPCODE_ISO_RX_PKT;
                    self.print_packet_header(tv, index, if incoming { ">" } else { "<" },
                        "ISO Data", display::COLOR_YELLOW);
                    display::print_hexdump(data);
                }
            }
            BTSNOOP_OPCODE_OPEN_INDEX => {
                self.handle_open_index(tv, index);
            }
            BTSNOOP_OPCODE_CLOSE_INDEX => {
                self.handle_close_index(tv, index);
            }
            BTSNOOP_OPCODE_INDEX_INFO => {
                self.handle_index_info(tv, index, data);
            }
            BTSNOOP_OPCODE_SYSTEM_NOTE => {
                if self.should_display(index) {
                    self.print_packet_header(tv, index, "=", "System Note", display::COLOR_WHITE);
                    if let Ok(note) = std::str::from_utf8(data) {
                        display::print_text(display::COLOR_WHITE, note.trim_end_matches('\0'));
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_new_index(&mut self, tv: Option<&libc::timeval>, index: u16, data: &[u8]) {
        if data.len() < 15 {
            return;
        }
        let bus_type = data[0];
        let mut bdaddr = [0u8; 6];
        bdaddr.copy_from_slice(&data[1..7]);
        let name_end = data[7..15].iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&data[7..7 + name_end]).to_string();

        {
            let info = self.get_or_create_index(index);
            info.bus_type = bus_type;
            info.bdaddr = bdaddr;
            info.name = name.clone();
            info.active = true;
        }

        if self.should_display(index) {
            self.print_packet_header(tv, index, "=", "New Index", display::COLOR_GREEN);
            display::print_field(&format!(
                "Type: {}, Bus: {}, Address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, Name: {}",
                "Primary",
                bus_type,
                bdaddr[5], bdaddr[4], bdaddr[3],
                bdaddr[2], bdaddr[1], bdaddr[0],
                name,
            ));
        }
    }

    fn handle_del_index(&mut self, tv: Option<&libc::timeval>, index: u16) {
        if self.should_display(index) {
            self.print_packet_header(tv, index, "=", "Delete Index", display::COLOR_RED);
        }
        if let Some(info) = self.indices.iter_mut().find(|(i, _)| *i == index) {
            info.1.active = false;
        }
    }

    fn handle_open_index(&mut self, tv: Option<&libc::timeval>, index: u16) {
        if self.should_display(index) {
            self.print_packet_header(tv, index, "=", "Open Index", display::COLOR_GREEN);
        }
    }

    fn handle_close_index(&mut self, tv: Option<&libc::timeval>, index: u16) {
        if self.should_display(index) {
            self.print_packet_header(tv, index, "=", "Close Index", display::COLOR_RED);
        }
    }

    fn handle_index_info(&mut self, tv: Option<&libc::timeval>, index: u16, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        let mut bdaddr = [0u8; 6];
        bdaddr.copy_from_slice(&data[0..6]);
        let manufacturer = u16::from_le_bytes([data[6], data[7]]);

        {
            let info = self.get_or_create_index(index);
            info.bdaddr = bdaddr;
            info.manufacturer = manufacturer;
        }

        if self.should_display(index) {
            self.print_packet_header(tv, index, "=", "Index Info", display::COLOR_GREEN);
            display::print_addr("Address", &bdaddr, 0x00);
            display::print_company("Manufacturer", manufacturer);
        }
    }

    /// Decode an HCI command packet.
    pub fn packet_hci_command(
        &self,
        tv: Option<&libc::timeval>,
        index: u16,
        data: &[u8],
    ) {
        if data.len() < 3 {
            return;
        }
        let opcode = u16::from_le_bytes([data[0], data[1]]);
        let param_len = data[2] as usize;
        let ogf = (opcode >> 10) & 0x3F;
        let ocf = opcode & 0x03FF;

        // Look up in opcode table
        let entry = hci::find_opcode(opcode);
        let name = entry.map(|e| e.name).unwrap_or("Unknown");

        let color = if ogf == 0x3F {
            display::COLOR_MAGENTA // Vendor-specific
        } else {
            display::COLOR_BLUE
        };

        self.print_packet_header(tv, index, "<", &format!("HCI Command: {} (0x{:04x})", name, opcode), color);

        if !self.decoding_enabled {
            if data.len() > 3 {
                display::print_hexdump(&data[3..]);
            }
            return;
        }

        let params = if data.len() >= 3 + param_len {
            &data[3..3 + param_len]
        } else {
            &data[3..]
        };

        // Try standard decoder
        if let Some(entry) = entry {
            if let Some(cmd_func) = entry.cmd_func {
                cmd_func(params);
                return;
            }
        }

        // Try vendor-specific decoder
        if ogf == 0x3F {
            let manufacturer = self.get_manufacturer(index);
            if let Some(vnd) = vendor::vendor_ocf(manufacturer, ocf) {
                if let Some(cmd_func) = vnd.cmd_func {
                    cmd_func(params);
                    return;
                }
            }
        }

        // Fall back to hex dump
        if !params.is_empty() {
            display::print_hexdump(params);
        }
    }

    /// Decode an HCI event packet.
    pub fn packet_hci_event(
        &self,
        tv: Option<&libc::timeval>,
        index: u16,
        data: &[u8],
    ) {
        if data.len() < 2 {
            return;
        }
        let event_code = data[0];
        let param_len = data[1] as usize;

        let entry = hci::find_event(event_code);
        let name = entry.map(|e| e.name).unwrap_or("Unknown");

        self.print_packet_header(tv, index, ">", &format!("HCI Event: {} (0x{:02x})", name, event_code), display::COLOR_MAGENTA);

        if !self.decoding_enabled {
            if data.len() > 2 {
                display::print_hexdump(&data[2..]);
            }
            return;
        }

        let params = if data.len() >= 2 + param_len {
            &data[2..2 + param_len]
        } else {
            &data[2..]
        };

        if let Some(entry) = entry {
            if let Some(evt_func) = entry.evt_func {
                evt_func(index, params);
                return;
            }
        }

        if !params.is_empty() {
            display::print_hexdump(params);
        }
    }

    /// Decode an ACL data packet.
    pub fn packet_hci_acldata(
        &self,
        tv: Option<&libc::timeval>,
        index: u16,
        incoming: bool,
        data: &[u8],
    ) {
        if data.len() < 4 {
            return;
        }
        let handle_flags = u16::from_le_bytes([data[0], data[1]]);
        let handle = handle_flags & 0x0FFF;
        let pb_flag = (handle_flags >> 12) & 0x03;
        let bc_flag = (handle_flags >> 14) & 0x03;
        let data_len = u16::from_le_bytes([data[2], data[3]]);

        let dir = if incoming { ">" } else { "<" };
        self.print_packet_header(
            tv, index, dir,
            &format!("ACL Data TX/RX: Handle {} flags 0x{:02x}{:02x} dlen {}",
                handle, pb_flag, bc_flag, data_len),
            display::COLOR_YELLOW,
        );

        if data.len() > 4 {
            l2cap::decode_l2cap(index, incoming, handle, &data[4..]);
        }
    }

    fn print_packet_header(
        &self,
        tv: Option<&libc::timeval>,
        index: u16,
        direction: &str,
        title: &str,
        color: &str,
    ) {
        let time_str = if self.filter & FILTER_SHOW_TIME != 0 {
            tv.map(display::format_timestamp).unwrap_or_default()
        } else {
            String::new()
        };

        let index_str = if self.filter & FILTER_SHOW_INDEX != 0 {
            format!("[hci{}] ", index)
        } else {
            String::new()
        };

        if display::use_color() {
            println!(
                "{}{}{} {}{}{}",
                display::COLOR_BOLDGRAY,
                time_str,
                display::COLOR_OFF,
                index_str,
                color,
                title,
            );
            println!(
                "{}{}{}",
                color,
                direction.repeat(if direction.len() == 1 { 1 } else { 0 }),
                display::COLOR_OFF,
            );
        } else {
            println!("{} {}{}", time_str, index_str, title);
        }
    }
}

impl Default for MonitorState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_state_new() {
        let state = MonitorState::new();
        assert!(state.decoding_enabled);
        assert!(state.selected_index.is_none());
    }

    #[test]
    fn test_monitor_filter() {
        let mut state = MonitorState::new();
        state.set_filter(FILTER_SHOW_INDEX | FILTER_SHOW_TIME);
        state.add_filter(FILTER_SHOW_ACL_DATA);
        assert_ne!(state.filter & FILTER_SHOW_ACL_DATA, 0);
        state.del_filter(FILTER_SHOW_ACL_DATA);
        assert_eq!(state.filter & FILTER_SHOW_ACL_DATA, 0);
    }

    #[test]
    fn test_monitor_select_index() {
        let mut state = MonitorState::new();
        assert!(state.should_display(0));
        assert!(state.should_display(1));
        state.select_index(0);
        assert!(state.should_display(0));
        assert!(!state.should_display(1));
    }

    #[test]
    fn test_monitor_new_index() {
        let mut state = MonitorState::new();
        // New Index packet: type(1) + bdaddr(6) + name(8) = 15 bytes
        let mut data = vec![0x00]; // Primary type
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // addr
        data.extend_from_slice(b"hci0\0\0\0\0"); // name
        state.packet_monitor(None, 0, BTSNOOP_OPCODE_NEW_INDEX, &data);

        let info = state.get_index(0).unwrap();
        assert!(info.active);
        assert_eq!(info.name, "hci0");
    }

    #[test]
    fn test_monitor_index_info() {
        let mut state = MonitorState::new();
        let mut data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // addr
        data.extend_from_slice(&0x0002u16.to_le_bytes()); // Intel manufacturer
        state.packet_monitor(None, 0, BTSNOOP_OPCODE_INDEX_INFO, &data);

        let info = state.get_index(0).unwrap();
        assert_eq!(info.manufacturer, 0x0002);
    }

    #[test]
    fn test_monitor_hci_command() {
        let mut state = MonitorState::new();
        // Reset command: opcode=0x0c03, param_len=0
        let data = [0x03, 0x0c, 0x00];
        state.packet_hci_command(None, 0, &data);
    }

    #[test]
    fn test_monitor_hci_event() {
        let mut state = MonitorState::new();
        // Command Complete event: code=0x0e, len=4, ncmd=1, opcode=0x0c03, status=0
        let data = [0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00];
        state.packet_hci_event(None, 0, &data);
    }

    #[test]
    fn test_monitor_del_index() {
        let mut state = MonitorState::new();
        // First create the index
        let mut data = vec![0x00];
        data.extend_from_slice(&[0; 6]);
        data.extend_from_slice(b"hci0\0\0\0\0");
        state.packet_monitor(None, 0, BTSNOOP_OPCODE_NEW_INDEX, &data);
        assert!(state.get_index(0).unwrap().active);

        // Delete it
        state.packet_monitor(None, 0, BTSNOOP_OPCODE_DEL_INDEX, &[]);
        assert!(!state.get_index(0).unwrap().active);
    }
}
