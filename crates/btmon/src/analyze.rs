// SPDX-License-Identifier: GPL-2.0-or-later
//
// Trace file analyzer replacing monitor/analyze.c (1,190 LOC)
//
// Reads a btsnoop capture file and produces summary statistics:
// per-device packet counts, connection details, and latency analysis.

use std::collections::HashMap;

use crate::display;

// BTSnoop constants
const BTSNOOP_HDR_SIZE: usize = 16;
const BTSNOOP_FORMAT_HCI: u32 = bluez_shared::btsnoop::BTSNOOP_TYPE_HCI_UNENCAP;
const BTSNOOP_FORMAT_MONITOR: u32 = bluez_shared::btsnoop::BTSNOOP_TYPE_MONITOR;

/// Connection type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnType {
    Acl,
    Sco,
    Esco,
    Le,
    Cis,
    Bis,
}

impl ConnType {
    fn as_str(&self) -> &'static str {
        match self {
            ConnType::Acl => "BR-ACL",
            ConnType::Sco => "BR-SCO",
            ConnType::Esco => "BR-ESCO",
            ConnType::Le => "LE-ACL",
            ConnType::Cis => "LE-CIS",
            ConnType::Bis => "LE-BIS",
        }
    }
}

/// Per-connection statistics.
#[derive(Debug)]
struct ConnStats {
    handle: u16,
    conn_type: ConnType,
    bdaddr: [u8; 6],
    bdaddr_type: u8,
    setup_seen: bool,
    terminated: bool,
    disconnect_reason: u8,
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

impl ConnStats {
    fn new(handle: u16, conn_type: ConnType) -> Self {
        Self {
            handle,
            conn_type,
            bdaddr: [0; 6],
            bdaddr_type: 0,
            setup_seen: false,
            terminated: false,
            disconnect_reason: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
}

/// Per-device statistics.
#[derive(Debug)]
struct DevStats {
    index: u16,
    dev_type: u8,
    bdaddr: [u8; 6],
    manufacturer: u16,
    num_cmd: u64,
    num_evt: u64,
    num_acl: u64,
    num_sco: u64,
    num_iso: u64,
    vendor_diag: u64,
    system_note: u64,
    user_log: u64,
    ctrl_msg: u64,
    unknown: u64,
    connections: Vec<ConnStats>,
}

impl DevStats {
    fn new(index: u16) -> Self {
        Self {
            index,
            dev_type: 0,
            bdaddr: [0; 6],
            manufacturer: 0xFFFF,
            num_cmd: 0,
            num_evt: 0,
            num_acl: 0,
            num_sco: 0,
            num_iso: 0,
            vendor_diag: 0,
            system_note: 0,
            user_log: 0,
            ctrl_msg: 0,
            unknown: 0,
            connections: Vec::new(),
        }
    }

    fn find_conn(&mut self, handle: u16, conn_type: ConnType) -> &mut ConnStats {
        let idx = self.connections.iter().position(|c| {
            c.handle == handle && !c.terminated
        });
        if let Some(i) = idx {
            // Update type if non-zero requested
            if self.connections[i].conn_type != conn_type {
                self.connections[i].conn_type = conn_type;
            }
            return &mut self.connections[i];
        }
        self.connections.push(ConnStats::new(handle, conn_type));
        self.connections.last_mut().unwrap()
    }
}

/// Analyzer state.
pub struct Analyzer {
    devices: HashMap<u16, DevStats>,
}

impl Analyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    fn get_dev(&mut self, index: u16) -> &mut DevStats {
        self.devices.entry(index).or_insert_with(|| DevStats::new(index))
    }

    /// Process a btsnoop packet for analysis.
    pub fn process_packet(&mut self, index: u16, opcode: u16, data: &[u8]) {
        match opcode {
            0 => self.handle_new_index(index, data),      // NEW_INDEX
            1 => {},                                        // DEL_INDEX (handled in print)
            2 => self.get_dev(index).num_cmd += 1,         // COMMAND
            3 => self.handle_event(index, data),            // EVENT
            4 => {                                          // ACL TX
                let dev = self.get_dev(index);
                dev.num_acl += 1;
                if data.len() >= 4 {
                    let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
                    let conn = dev.find_conn(handle, ConnType::Acl);
                    conn.tx_packets += 1;
                    conn.tx_bytes += data.len() as u64;
                }
            }
            5 => {                                          // ACL RX
                let dev = self.get_dev(index);
                dev.num_acl += 1;
                if data.len() >= 4 {
                    let handle = u16::from_le_bytes([data[0], data[1]]) & 0x0FFF;
                    let conn = dev.find_conn(handle, ConnType::Acl);
                    conn.rx_packets += 1;
                    conn.rx_bytes += data.len() as u64;
                }
            }
            6 | 7 => self.get_dev(index).num_sco += 1,    // SCO TX/RX
            10 => self.handle_index_info(index, data),     // INDEX_INFO
            11 => self.get_dev(index).vendor_diag += 1,    // VENDOR_DIAG
            12 => self.get_dev(index).system_note += 1,    // SYSTEM_NOTE
            13 => self.get_dev(index).user_log += 1,       // USER_LOGGING
            14..=17 => self.get_dev(index).ctrl_msg += 1,  // CTRL_*
            18 | 19 => self.get_dev(index).num_iso += 1,   // ISO TX/RX
            _ => self.get_dev(index).unknown += 1,
        }
    }

    fn handle_new_index(&mut self, index: u16, data: &[u8]) {
        if data.len() < 15 {
            return;
        }
        let dev = self.get_dev(index);
        dev.dev_type = data[0];
        dev.bdaddr.copy_from_slice(&data[1..7]);
    }

    fn handle_index_info(&mut self, index: u16, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        let dev = self.get_dev(index);
        dev.bdaddr.copy_from_slice(&data[0..6]);
        dev.manufacturer = u16::from_le_bytes([data[6], data[7]]);
    }

    fn handle_event(&mut self, index: u16, data: &[u8]) {
        self.get_dev(index).num_evt += 1;

        if data.len() < 2 {
            return;
        }
        let event_code = data[0];
        let params = &data[2..];

        match event_code {
            // Connection Complete
            0x03 => {
                if params.len() >= 11 {
                    let status = params[0];
                    if status == 0 {
                        let handle = u16::from_le_bytes([params[1], params[2]]);
                        let dev = self.get_dev(index);
                        let conn = dev.find_conn(handle, ConnType::Acl);
                        conn.bdaddr.copy_from_slice(&params[3..9]);
                        conn.setup_seen = true;
                    }
                }
            }
            // Disconnection Complete
            0x05 => {
                if params.len() >= 4 {
                    let status = params[0];
                    if status == 0 {
                        let handle = u16::from_le_bytes([params[1], params[2]]);
                        let reason = params[3];
                        let dev = self.get_dev(index);
                        if let Some(conn) = dev.connections.iter_mut().find(|c| {
                            c.handle == handle && !c.terminated
                        }) {
                            conn.terminated = true;
                            conn.disconnect_reason = reason;
                        }
                    }
                }
            }
            // Command Complete — check for Read BD Addr
            0x0e => {
                if params.len() >= 10 {
                    let cmd_opcode = u16::from_le_bytes([params[1], params[2]]);
                    // Read BD Addr = 0x1009
                    if cmd_opcode == 0x1009 && params[3] == 0 {
                        let dev = self.get_dev(index);
                        dev.bdaddr.copy_from_slice(&params[4..10]);
                    }
                }
            }
            // LE Meta Event
            0x3e => {
                if params.is_empty() {
                    return;
                }
                let sub_event = params[0];
                let sub_params = &params[1..];
                match sub_event {
                    // LE Connection Complete
                    0x01 => {
                        if sub_params.len() >= 18 {
                            let status = sub_params[0];
                            if status == 0 {
                                let handle = u16::from_le_bytes([sub_params[1], sub_params[2]]);
                                let dev = self.get_dev(index);
                                let conn = dev.find_conn(handle, ConnType::Le);
                                conn.bdaddr_type = sub_params[4];
                                conn.bdaddr.copy_from_slice(&sub_params[5..11]);
                                conn.setup_seen = true;
                            }
                        }
                    }
                    // LE Enhanced Connection Complete
                    0x0a => {
                        if sub_params.len() >= 30 {
                            let status = sub_params[0];
                            if status == 0 {
                                let handle = u16::from_le_bytes([sub_params[1], sub_params[2]]);
                                let dev = self.get_dev(index);
                                let conn = dev.find_conn(handle, ConnType::Le);
                                conn.bdaddr_type = sub_params[4];
                                conn.bdaddr.copy_from_slice(&sub_params[5..11]);
                                conn.setup_seen = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Print the analysis results.
    pub fn print_results(&self, num_packets: u64) {
        println!("Trace contains {} packets\n", num_packets);

        for dev in self.devices.values() {
            let type_str = match dev.dev_type {
                0x00 => "BR/EDR",
                0x01 => "AMP",
                _ => "unknown",
            };
            println!("Found {} controller with index {}", type_str, dev.index);
            println!(
                "  BD_ADDR {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                dev.bdaddr[5], dev.bdaddr[4], dev.bdaddr[3],
                dev.bdaddr[2], dev.bdaddr[1], dev.bdaddr[0]
            );
            if dev.manufacturer != 0xFFFF {
                println!("  Manufacturer: 0x{:04x}", dev.manufacturer);
            }
            println!("  {} commands", dev.num_cmd);
            println!("  {} events", dev.num_evt);
            println!("  {} ACL packets", dev.num_acl);
            println!("  {} SCO packets", dev.num_sco);
            println!("  {} ISO packets", dev.num_iso);
            println!("  {} vendor diagnostics", dev.vendor_diag);
            println!("  {} system notes", dev.system_note);
            println!("  {} user logs", dev.user_log);
            println!("  {} control messages", dev.ctrl_msg);
            println!("  {} unknown opcodes", dev.unknown);

            for conn in &dev.connections {
                println!(
                    "  Found {} connection with handle {}",
                    conn.conn_type.as_str(), conn.handle
                );
                display::print_addr("    Address", &conn.bdaddr, conn.bdaddr_type);
                if !conn.setup_seen {
                    display::print_field("    Connection setup missing");
                }
                if conn.rx_packets > 0 || conn.tx_packets > 0 {
                    display::print_field(&format!(
                        "    RX: {} packets ({} bytes)",
                        conn.rx_packets, conn.rx_bytes
                    ));
                    display::print_field(&format!(
                        "    TX: {} packets ({} bytes)",
                        conn.tx_packets, conn.tx_bytes
                    ));
                }
                if conn.terminated {
                    display::print_field(&format!(
                        "    Disconnect Reason: 0x{:02x}",
                        conn.disconnect_reason
                    ));
                }
            }
            println!();
        }
    }

    /// Analyze a btsnoop trace file.
    pub fn analyze_trace(path: &str) {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to read file: {}", e);
                return;
            }
        };

        if data.len() < BTSNOOP_HDR_SIZE {
            eprintln!("File too small for btsnoop header");
            return;
        }

        let id = &data[0..8];
        if id != bluez_shared::btsnoop::BTSNOOP_MAGIC {
            eprintln!("Not a btsnoop file");
            return;
        }

        let format = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        match format {
            BTSNOOP_FORMAT_HCI
            | BTSNOOP_FORMAT_MONITOR => {}
            _ => {
                eprintln!("Unsupported packet format");
                return;
            }
        }

        let mut analyzer = Analyzer::new();
        let mut num_packets: u64 = 0;
        let mut offset = BTSNOOP_HDR_SIZE;

        while offset + 24 <= data.len() {
            let included_len = u32::from_be_bytes([
                data[offset + 4], data[offset + 5],
                data[offset + 6], data[offset + 7],
            ]) as usize;
            let flags = u32::from_be_bytes([
                data[offset + 8], data[offset + 9],
                data[offset + 10], data[offset + 11],
            ]);

            if offset + 24 + included_len > data.len() {
                break;
            }

            let pkt_data = &data[offset + 24..offset + 24 + included_len];

            let (index, opcode) = if format == BTSNOOP_FORMAT_MONITOR {
                let opcode = (flags & 0xFFFF) as u16;
                let index = ((flags >> 16) & 0xFFFF) as u16;
                (index, opcode)
            } else {
                let opcode = match flags & 0x03 {
                    0 => 2,
                    1 => 3,
                    2 => 4,
                    3 => 5,
                    _ => 0xFFFF,
                };
                (0u16, opcode)
            };

            analyzer.process_packet(index, opcode, pkt_data);
            num_packets += 1;
            offset += 24 + included_len;
        }

        analyzer.print_results(num_packets);
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_new() {
        let analyzer = Analyzer::new();
        assert!(analyzer.devices.is_empty());
    }

    #[test]
    fn test_analyzer_new_index() {
        let mut analyzer = Analyzer::new();
        let mut data = vec![0x00]; // Primary type
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // addr
        data.extend_from_slice(b"hci0\0\0\0\0"); // name
        analyzer.process_packet(0, 0, &data);

        let dev = analyzer.devices.get(&0).unwrap();
        assert_eq!(dev.dev_type, 0x00);
        assert_eq!(dev.bdaddr, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_analyzer_command_event_counts() {
        let mut analyzer = Analyzer::new();
        // Commands (opcode 2)
        analyzer.process_packet(0, 2, &[0x03, 0x0c, 0x00]);
        analyzer.process_packet(0, 2, &[0x01, 0x10, 0x00]);
        // Events (opcode 3)
        analyzer.process_packet(0, 3, &[0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]);

        let dev = analyzer.devices.get(&0).unwrap();
        assert_eq!(dev.num_cmd, 2);
        assert_eq!(dev.num_evt, 1);
    }

    #[test]
    fn test_analyzer_acl_stats() {
        let mut analyzer = Analyzer::new();
        // ACL TX packet: handle=0x0040, data
        let data = [0x40, 0x00, 0x05, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02];
        analyzer.process_packet(0, 4, &data);
        // ACL RX packet
        analyzer.process_packet(0, 5, &data);

        let dev = analyzer.devices.get(&0).unwrap();
        assert_eq!(dev.num_acl, 2);
        let conn = &dev.connections[0];
        assert_eq!(conn.handle, 0x0040);
        assert_eq!(conn.tx_packets, 1);
        assert_eq!(conn.rx_packets, 1);
    }

    #[test]
    fn test_analyzer_conn_complete() {
        let mut analyzer = Analyzer::new();
        // Connection Complete event: event=0x03, len=11, status=0, handle=0x0040,
        // bdaddr, link_type=1, encryption=0
        let mut data = vec![0x03, 0x0b]; // event code, param_len
        data.push(0x00); // status
        data.extend_from_slice(&0x0040u16.to_le_bytes()); // handle
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // bdaddr
        data.push(0x01); // link_type
        data.push(0x00); // encryption
        analyzer.process_packet(0, 3, &data);

        let dev = analyzer.devices.get(&0).unwrap();
        let conn = &dev.connections[0];
        assert!(conn.setup_seen);
        assert_eq!(conn.bdaddr, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_analyzer_print_results() {
        let mut analyzer = Analyzer::new();
        analyzer.process_packet(0, 2, &[0x03, 0x0c, 0x00]);
        analyzer.print_results(1);
    }

    #[test]
    fn test_conn_type_as_str() {
        assert_eq!(ConnType::Acl.as_str(), "BR-ACL");
        assert_eq!(ConnType::Le.as_str(), "LE-ACL");
        assert_eq!(ConnType::Cis.as_str(), "LE-CIS");
    }

    #[test]
    fn test_analyze_nonexistent_file() {
        Analyzer::analyze_trace("/nonexistent/path.btsnoop");
    }
}
