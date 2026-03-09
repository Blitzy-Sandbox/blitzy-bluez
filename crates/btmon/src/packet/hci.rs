// SPDX-License-Identifier: GPL-2.0-or-later
//
// HCI command and event decode tables replacing portions of monitor/packet.c
//
// Contains the opcode_table and event_table with decoder functions
// for standard HCI commands and events.

use crate::display;

/// HCI command table entry.
pub struct OpcodeEntry {
    pub opcode: u16,
    pub name: &'static str,
    pub cmd_func: Option<fn(&[u8])>,
    pub cmd_size: u8,
    pub cmd_fixed: bool,
    pub rsp_func: Option<fn(&[u8])>,
    pub rsp_size: u8,
    pub rsp_fixed: bool,
}

/// HCI event table entry.
pub struct EventEntry {
    pub event: u8,
    pub name: &'static str,
    pub evt_func: Option<fn(u16, &[u8])>,
    pub evt_size: u8,
    pub evt_fixed: bool,
}

// ---- Helper functions ----

fn le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn print_addr(label: &str, data: &[u8], offset: usize, addr_type: u8) {
    if data.len() >= offset + 6 {
        let addr: [u8; 6] = data[offset..offset + 6].try_into().unwrap();
        display::print_addr(label, &addr, addr_type);
    }
}

fn addr_type_str(t: u8) -> &'static str {
    match t {
        0x00 => "Public",
        0x01 => "Random",
        0x02 => "Public Identity",
        0x03 => "Random Static Identity",
        _ => "Unknown",
    }
}

fn phy_str(phy: u8) -> &'static str {
    match phy {
        0x01 => "LE 1M",
        0x02 => "LE 2M",
        0x03 => "LE Coded",
        _ => "Unknown",
    }
}

fn scan_type_str(t: u8) -> &'static str {
    match t {
        0x00 => "Passive",
        0x01 => "Active",
        _ => "Unknown",
    }
}

fn enable_str(v: u8) -> &'static str {
    if v == 0x00 { "Disabled" } else { "Enabled" }
}

fn filter_policy_str(p: u8) -> &'static str {
    match p {
        0x00 => "Accept All",
        0x01 => "White List Only",
        0x02 => "Accept All, Directed Allowed",
        0x03 => "White List Only, Directed Allowed",
        _ => "Unknown",
    }
}

fn adv_type_str(t: u8) -> &'static str {
    match t {
        0x00 => "Connectable Undirected - ADV_IND",
        0x01 => "Connectable Directed High Duty - ADV_DIRECT_IND",
        0x02 => "Scannable Undirected - ADV_SCAN_IND",
        0x03 => "Non-Connectable Undirected - ADV_NONCONN_IND",
        0x04 => "Scan Response - SCAN_RSP",
        _ => "Unknown",
    }
}

// ---- Command decoder functions ----

fn status_rsp(data: &[u8]) {
    if !data.is_empty() {
        display::print_error("Status", data[0]);
    }
}

fn inquiry_cmd(data: &[u8]) {
    if data.len() >= 5 {
        display::print_field(&format!(
            "LAP: 0x{:02x}{:02x}{:02x}",
            data[2], data[1], data[0]
        ));
        display::print_field(&format!("Length: {}", data[3]));
        display::print_field(&format!("Num Responses: {}", data[4]));
    }
}

fn disconnect_cmd(data: &[u8]) {
    if data.len() >= 3 {
        let handle = le_u16(data, 0);
        display::print_field(&format!("Handle: {}", handle));
        display::print_error("Reason", data[2]);
    }
}

fn read_bd_addr_rsp(data: &[u8]) {
    if data.len() >= 7 {
        display::print_error("Status", data[0]);
        let addr: [u8; 6] = data[1..7].try_into().unwrap();
        display::print_addr("Address", &addr, 0x00);
    }
}

fn read_local_version_rsp(data: &[u8]) {
    if data.len() >= 9 {
        display::print_error("Status", data[0]);
        display::print_field(&format!("HCI version: 0x{:02x}", data[1]));
        let revision = le_u16(data, 2);
        display::print_field(&format!("HCI revision: 0x{:04x}", revision));
        display::print_field(&format!("LMP version: 0x{:02x}", data[4]));
        let manufacturer = le_u16(data, 5);
        display::print_company("Manufacturer", manufacturer);
        let lmp_subversion = le_u16(data, 7);
        display::print_field(&format!("LMP subversion: 0x{:04x}", lmp_subversion));
    }
}

fn read_local_features_rsp(data: &[u8]) {
    if data.len() >= 9 {
        display::print_error("Status", data[0]);
        display::print_hex_field("Features", &data[1..9]);
    }
}

fn reset_cmd(_data: &[u8]) {
    // No parameters
}

fn set_event_mask_cmd(data: &[u8]) {
    if data.len() >= 8 {
        display::print_hex_field("Mask", &data[0..8]);
    }
}

fn write_local_name_cmd(data: &[u8]) {
    if !data.is_empty() {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let name = String::from_utf8_lossy(&data[..end]);
        display::print_field(&format!("Name: {}", name));
    }
}

fn read_local_name_rsp(data: &[u8]) {
    if !data.is_empty() {
        display::print_error("Status", data[0]);
        if data.len() > 1 {
            let end = data[1..].iter().position(|&b| b == 0).unwrap_or(data.len() - 1);
            let name = String::from_utf8_lossy(&data[1..1 + end]);
            display::print_field(&format!("Name: {}", name));
        }
    }
}

fn write_scan_enable_cmd(data: &[u8]) {
    if !data.is_empty() {
        let desc = match data[0] {
            0x00 => "No Scans",
            0x01 => "Inquiry Scan",
            0x02 => "Page Scan",
            0x03 => "Inquiry and Page Scan",
            _ => "Unknown",
        };
        display::print_field(&format!("Scan Enable: {} (0x{:02x})", desc, data[0]));
    }
}

fn write_page_scan_activity_cmd(data: &[u8]) {
    if data.len() >= 4 {
        let interval = le_u16(data, 0);
        let window = le_u16(data, 2);
        display::print_field(&format!("Interval: {} ({:.2} ms)", interval, interval as f64 * 0.625));
        display::print_field(&format!("Window: {} ({:.2} ms)", window, window as f64 * 0.625));
    }
}

fn write_class_of_device_cmd(data: &[u8]) {
    if data.len() >= 3 {
        display::print_field(&format!(
            "Class: 0x{:02x}{:02x}{:02x}",
            data[2], data[1], data[0]
        ));
    }
}

fn write_simple_pairing_mode_cmd(data: &[u8]) {
    if !data.is_empty() {
        display::print_field(&format!("Mode: {}", enable_str(data[0])));
    }
}

fn write_sc_host_support_cmd(data: &[u8]) {
    if !data.is_empty() {
        display::print_field(&format!("Support: {}", enable_str(data[0])));
    }
}

fn write_default_link_policy_cmd(data: &[u8]) {
    if data.len() >= 2 {
        let policy = le_u16(data, 0);
        display::print_field(&format!("Policy: 0x{:04x}", policy));
        if policy & 0x0001 != 0 { display::print_field("  Role Switch"); }
        if policy & 0x0002 != 0 { display::print_field("  Hold Mode"); }
        if policy & 0x0004 != 0 { display::print_field("  Sniff Mode"); }
        if policy & 0x0008 != 0 { display::print_field("  Park State"); }
    }
}

fn le_set_adv_params_cmd(data: &[u8]) {
    if data.len() >= 15 {
        let adv_min = le_u16(data, 0);
        let adv_max = le_u16(data, 2);
        let adv_type = data[4];
        let own_addr_type = data[5];
        let peer_addr_type = data[6];
        let channel_map = data[13];
        let filter_policy = data[14];

        display::print_field(&format!("Min interval: {} ({:.2} ms)", adv_min, adv_min as f64 * 0.625));
        display::print_field(&format!("Max interval: {} ({:.2} ms)", adv_max, adv_max as f64 * 0.625));
        display::print_field(&format!("Type: {} (0x{:02x})", adv_type_str(adv_type), adv_type));
        display::print_field(&format!("Own address type: {} (0x{:02x})", addr_type_str(own_addr_type), own_addr_type));
        display::print_field(&format!("Peer address type: {} (0x{:02x})", addr_type_str(peer_addr_type), peer_addr_type));
        print_addr("Peer address", data, 7, peer_addr_type);
        display::print_field(&format!("Channel map: 0x{:02x}", channel_map));
        display::print_field(&format!("Filter policy: {} (0x{:02x})", filter_policy_str(filter_policy), filter_policy));
    }
}

fn le_set_adv_data_cmd(data: &[u8]) {
    if !data.is_empty() {
        let len = data[0] as usize;
        display::print_field(&format!("Data length: {}", len));
        if data.len() > 1 {
            let end = (1 + len).min(data.len());
            display::print_hexdump(&data[1..end]);
        }
    }
}

fn le_set_scan_rsp_data_cmd(data: &[u8]) {
    if !data.is_empty() {
        let len = data[0] as usize;
        display::print_field(&format!("Data length: {}", len));
        if data.len() > 1 {
            let end = (1 + len).min(data.len());
            display::print_hexdump(&data[1..end]);
        }
    }
}

fn le_set_adv_enable_cmd(data: &[u8]) {
    if !data.is_empty() {
        display::print_field(&format!("Advertising: {}", enable_str(data[0])));
    }
}

fn le_set_scan_params_cmd(data: &[u8]) {
    if data.len() >= 7 {
        let scan_type = data[0];
        let interval = le_u16(data, 1);
        let window = le_u16(data, 3);
        let own_addr_type = data[5];
        let filter_policy = data[6];

        display::print_field(&format!("Type: {} (0x{:02x})", scan_type_str(scan_type), scan_type));
        display::print_field(&format!("Interval: {} ({:.2} ms)", interval, interval as f64 * 0.625));
        display::print_field(&format!("Window: {} ({:.2} ms)", window, window as f64 * 0.625));
        display::print_field(&format!("Own address type: {} (0x{:02x})", addr_type_str(own_addr_type), own_addr_type));
        display::print_field(&format!("Filter policy: {} (0x{:02x})", filter_policy_str(filter_policy), filter_policy));
    }
}

fn le_set_scan_enable_cmd(data: &[u8]) {
    if data.len() >= 2 {
        display::print_field(&format!("Scanning: {}", enable_str(data[0])));
        display::print_field(&format!("Filter duplicates: {}", enable_str(data[1])));
    }
}

fn le_create_conn_cmd(data: &[u8]) {
    if data.len() >= 25 {
        let scan_interval = le_u16(data, 0);
        let scan_window = le_u16(data, 2);
        let filter_policy = data[4];
        let peer_addr_type = data[5];
        let own_addr_type = data[12];
        let conn_interval_min = le_u16(data, 13);
        let conn_interval_max = le_u16(data, 15);
        let conn_latency = le_u16(data, 17);
        let supervision_timeout = le_u16(data, 19);
        let min_ce = le_u16(data, 21);
        let max_ce = le_u16(data, 23);

        display::print_field(&format!("Scan interval: {} ({:.2} ms)", scan_interval, scan_interval as f64 * 0.625));
        display::print_field(&format!("Scan window: {} ({:.2} ms)", scan_window, scan_window as f64 * 0.625));
        display::print_field(&format!("Filter policy: {} (0x{:02x})", filter_policy_str(filter_policy), filter_policy));
        display::print_field(&format!("Peer address type: {} (0x{:02x})", addr_type_str(peer_addr_type), peer_addr_type));
        print_addr("Peer address", data, 6, peer_addr_type);
        display::print_field(&format!("Own address type: {} (0x{:02x})", addr_type_str(own_addr_type), own_addr_type));
        display::print_field(&format!("Min connection interval: {} ({:.2} ms)", conn_interval_min, conn_interval_min as f64 * 1.25));
        display::print_field(&format!("Max connection interval: {} ({:.2} ms)", conn_interval_max, conn_interval_max as f64 * 1.25));
        display::print_field(&format!("Connection latency: {}", conn_latency));
        display::print_field(&format!("Supervision timeout: {} ({} ms)", supervision_timeout, supervision_timeout as u32 * 10));
        display::print_field(&format!("Min CE length: {} ({:.2} ms)", min_ce, min_ce as f64 * 0.625));
        display::print_field(&format!("Max CE length: {} ({:.2} ms)", max_ce, max_ce as f64 * 0.625));
    }
}

fn le_read_remote_features_cmd(data: &[u8]) {
    if data.len() >= 2 {
        let handle = le_u16(data, 0);
        display::print_field(&format!("Handle: {}", handle));
    }
}

fn le_start_encryption_cmd(data: &[u8]) {
    if data.len() >= 28 {
        let handle = le_u16(data, 0);
        display::print_field(&format!("Handle: {}", handle));
        display::print_hex_field("Random number", &data[2..10]);
        let ediv = le_u16(data, 10);
        display::print_field(&format!("Encrypted diversifier: 0x{:04x}", ediv));
        display::print_hex_field("Long term key", &data[12..28]);
    }
}

fn le_read_phy_cmd(data: &[u8]) {
    if data.len() >= 2 {
        let handle = le_u16(data, 0);
        display::print_field(&format!("Handle: {}", handle));
    }
}

fn le_read_phy_rsp(data: &[u8]) {
    if data.len() >= 5 {
        display::print_error("Status", data[0]);
        let handle = le_u16(data, 1);
        display::print_field(&format!("Handle: {}", handle));
        display::print_field(&format!("TX PHY: {} (0x{:02x})", phy_str(data[3]), data[3]));
        display::print_field(&format!("RX PHY: {} (0x{:02x})", phy_str(data[4]), data[4]));
    }
}

fn le_set_phy_cmd(data: &[u8]) {
    if data.len() >= 7 {
        let handle = le_u16(data, 0);
        let all_phys = data[2];
        let tx_phys = data[3];
        let rx_phys = data[4];
        let phy_options = le_u16(data, 5);

        display::print_field(&format!("Handle: {}", handle));
        display::print_field(&format!("All PHYs preference: 0x{:02x}", all_phys));
        display::print_field(&format!("TX PHYs preference: 0x{:02x}", tx_phys));
        display::print_field(&format!("RX PHYs preference: 0x{:02x}", rx_phys));
        display::print_field(&format!("PHY options: 0x{:04x}", phy_options));
    }
}

fn le_set_ext_adv_params_cmd(data: &[u8]) {
    if data.len() >= 25 {
        let handle = data[0];
        let evt_props = le_u16(data, 1);
        let prim_adv_phy = data[12];
        let sec_adv_max_skip = data[13];
        let sec_adv_phy = data[14];
        let sid = data[15];
        let scan_req_notify = data[16];

        display::print_field(&format!("Handle: {}", handle));
        display::print_field(&format!("Properties: 0x{:04x}", evt_props));
        // Decode min/max interval (3-byte values)
        let min_interval = data[3] as u32 | (data[4] as u32) << 8 | (data[5] as u32) << 16;
        let max_interval = data[6] as u32 | (data[7] as u32) << 8 | (data[8] as u32) << 16;
        display::print_field(&format!("Min interval: {} ({:.2} ms)", min_interval, min_interval as f64 * 0.625));
        display::print_field(&format!("Max interval: {} ({:.2} ms)", max_interval, max_interval as f64 * 0.625));
        display::print_field(&format!("Channel map: 0x{:02x}", data[9]));
        display::print_field(&format!("Own address type: {} (0x{:02x})", addr_type_str(data[10]), data[10]));
        display::print_field(&format!("Peer address type: {} (0x{:02x})", addr_type_str(data[11]), data[11]));
        display::print_field(&format!("Primary PHY: {} (0x{:02x})", phy_str(prim_adv_phy), prim_adv_phy));
        display::print_field(&format!("Secondary max skip: {}", sec_adv_max_skip));
        display::print_field(&format!("Secondary PHY: {} (0x{:02x})", phy_str(sec_adv_phy), sec_adv_phy));
        display::print_field(&format!("SID: 0x{:02x}", sid));
        display::print_field(&format!("Scan request notification: {}", enable_str(scan_req_notify)));
    }
}

fn le_set_ext_adv_data_cmd(data: &[u8]) {
    if data.len() >= 4 {
        let handle = data[0];
        let operation = data[1];
        let frag_pref = data[2];
        let data_len = data[3] as usize;

        let op_str = match operation {
            0x00 => "Intermediate fragment",
            0x01 => "First fragment",
            0x02 => "Last fragment",
            0x03 => "Complete data",
            _ => "Unknown",
        };

        display::print_field(&format!("Handle: {}", handle));
        display::print_field(&format!("Operation: {} (0x{:02x})", op_str, operation));
        display::print_field(&format!("Fragment preference: 0x{:02x}", frag_pref));
        display::print_field(&format!("Data length: {}", data_len));
        if data.len() > 4 {
            let end = (4 + data_len).min(data.len());
            display::print_hexdump(&data[4..end]);
        }
    }
}

fn le_set_ext_scan_params_cmd(data: &[u8]) {
    if data.len() >= 3 {
        let own_addr_type = data[0];
        let filter_policy = data[1];
        let num_phys = data[2] as usize;

        display::print_field(&format!("Own address type: {} (0x{:02x})", addr_type_str(own_addr_type), own_addr_type));
        display::print_field(&format!("Filter policy: {} (0x{:02x})", filter_policy_str(filter_policy), filter_policy));
        display::print_field(&format!("PHYs: {}", num_phys));

        let mut offset = 3;
        for i in 0..num_phys {
            if data.len() >= offset + 5 {
                let scan_type = data[offset];
                let interval = le_u16(data, offset + 1);
                let window = le_u16(data, offset + 3);
                display::print_field(&format!("Entry {}:", i));
                display::print_field(&format!("  Type: {} (0x{:02x})", scan_type_str(scan_type), scan_type));
                display::print_field(&format!("  Interval: {} ({:.2} ms)", interval, interval as f64 * 0.625));
                display::print_field(&format!("  Window: {} ({:.2} ms)", window, window as f64 * 0.625));
                offset += 5;
            }
        }
    }
}

fn le_set_ext_scan_enable_cmd(data: &[u8]) {
    if data.len() >= 6 {
        display::print_field(&format!("Scanning: {}", enable_str(data[0])));
        display::print_field(&format!("Filter duplicates: 0x{:02x}", data[1]));
        let duration = le_u16(data, 2);
        let period = le_u16(data, 4);
        display::print_field(&format!("Duration: {} ({} ms)", duration, duration as u32 * 10));
        display::print_field(&format!("Period: {} ({:.2} s)", period, period as f64 * 1.28));
    }
}

fn le_ext_create_conn_cmd(data: &[u8]) {
    if data.len() >= 10 {
        let filter_policy = data[0];
        let own_addr_type = data[1];
        let peer_addr_type = data[2];

        display::print_field(&format!("Filter policy: {} (0x{:02x})", filter_policy_str(filter_policy), filter_policy));
        display::print_field(&format!("Own address type: {} (0x{:02x})", addr_type_str(own_addr_type), own_addr_type));
        display::print_field(&format!("Peer address type: {} (0x{:02x})", addr_type_str(peer_addr_type), peer_addr_type));
        print_addr("Peer address", data, 3, peer_addr_type);
        let init_phys = data[9];
        display::print_field(&format!("Initiating PHYs: 0x{:02x}", init_phys));

        let mut offset = 10;
        let mut phy_idx = 0u8;
        while offset + 16 <= data.len() && phy_idx < 3 {
            let scan_interval = le_u16(data, offset);
            let scan_window = le_u16(data, offset + 2);
            let conn_interval_min = le_u16(data, offset + 4);
            let conn_interval_max = le_u16(data, offset + 6);
            let conn_latency = le_u16(data, offset + 8);
            let supervision_timeout = le_u16(data, offset + 10);
            let min_ce = le_u16(data, offset + 12);
            let max_ce = le_u16(data, offset + 14);

            display::print_field(&format!("PHY entry {}:", phy_idx));
            display::print_field(&format!("  Scan interval: {} ({:.2} ms)", scan_interval, scan_interval as f64 * 0.625));
            display::print_field(&format!("  Scan window: {} ({:.2} ms)", scan_window, scan_window as f64 * 0.625));
            display::print_field(&format!("  Min connection interval: {} ({:.2} ms)", conn_interval_min, conn_interval_min as f64 * 1.25));
            display::print_field(&format!("  Max connection interval: {} ({:.2} ms)", conn_interval_max, conn_interval_max as f64 * 1.25));
            display::print_field(&format!("  Connection latency: {}", conn_latency));
            display::print_field(&format!("  Supervision timeout: {} ({} ms)", supervision_timeout, supervision_timeout as u32 * 10));
            display::print_field(&format!("  Min CE length: {} ({:.2} ms)", min_ce, min_ce as f64 * 0.625));
            display::print_field(&format!("  Max CE length: {} ({:.2} ms)", max_ce, max_ce as f64 * 0.625));

            offset += 16;
            phy_idx += 1;
        }
    }
}

fn le_set_cig_params_cmd(data: &[u8]) {
    if data.len() >= 15 {
        let cig_id = data[0];
        let sdu_interval_c_to_p = data[1] as u32 | (data[2] as u32) << 8 | (data[3] as u32) << 16;
        let sdu_interval_p_to_c = data[4] as u32 | (data[5] as u32) << 8 | (data[6] as u32) << 16;
        let worst_case_sca = data[7];
        let packing = data[8];
        let framing = data[9];
        let max_transport_latency_c_to_p = le_u16(data, 10);
        let max_transport_latency_p_to_c = le_u16(data, 12);
        let cis_count = data[14] as usize;

        display::print_field(&format!("CIG ID: {}", cig_id));
        display::print_field(&format!("SDU interval C->P: {} us", sdu_interval_c_to_p));
        display::print_field(&format!("SDU interval P->C: {} us", sdu_interval_p_to_c));
        display::print_field(&format!("Worst case SCA: 0x{:02x}", worst_case_sca));
        display::print_field(&format!("Packing: {}", if packing == 0 { "Sequential" } else { "Interleaved" }));
        display::print_field(&format!("Framing: {}", if framing == 0 { "Unframed" } else { "Framed" }));
        display::print_field(&format!("Max transport latency C->P: {} ms", max_transport_latency_c_to_p));
        display::print_field(&format!("Max transport latency P->C: {} ms", max_transport_latency_p_to_c));
        display::print_field(&format!("CIS count: {}", cis_count));

        let mut offset = 15;
        for i in 0..cis_count {
            if data.len() >= offset + 9 {
                let cis_id = data[offset];
                let max_sdu_c_to_p = le_u16(data, offset + 1);
                let max_sdu_p_to_c = le_u16(data, offset + 3);
                let phy_c_to_p = data[offset + 5];
                let phy_p_to_c = data[offset + 6];
                let rtn_c_to_p = data[offset + 7];
                let rtn_p_to_c = data[offset + 8];

                display::print_field(&format!("CIS entry {}:", i));
                display::print_field(&format!("  CIS ID: {}", cis_id));
                display::print_field(&format!("  Max SDU C->P: {}", max_sdu_c_to_p));
                display::print_field(&format!("  Max SDU P->C: {}", max_sdu_p_to_c));
                display::print_field(&format!("  PHY C->P: {} (0x{:02x})", phy_str(phy_c_to_p), phy_c_to_p));
                display::print_field(&format!("  PHY P->C: {} (0x{:02x})", phy_str(phy_p_to_c), phy_p_to_c));
                display::print_field(&format!("  RTN C->P: {}", rtn_c_to_p));
                display::print_field(&format!("  RTN P->C: {}", rtn_p_to_c));
                offset += 9;
            }
        }
    }
}

fn le_create_cis_cmd(data: &[u8]) {
    if !data.is_empty() {
        let count = data[0] as usize;
        display::print_field(&format!("CIS count: {}", count));
        let mut offset = 1;
        for i in 0..count {
            if data.len() >= offset + 4 {
                let cis_handle = le_u16(data, offset);
                let acl_handle = le_u16(data, offset + 2);
                display::print_field(&format!("Entry {}:", i));
                display::print_field(&format!("  CIS handle: {}", cis_handle));
                display::print_field(&format!("  ACL handle: {}", acl_handle));
                offset += 4;
            }
        }
    }
}

fn le_setup_iso_data_path_cmd(data: &[u8]) {
    if data.len() >= 13 {
        let handle = le_u16(data, 0);
        let direction = data[2];
        let codec_id = data[3];
        let controller_delay = data[8] as u32 | (data[9] as u32) << 8 | (data[10] as u32) << 16;
        let codec_config_len = data[11] as usize;

        let dir_str = match direction {
            0x00 => "Input (Host to Controller)",
            0x01 => "Output (Controller to Host)",
            _ => "Unknown",
        };

        display::print_field(&format!("Handle: {}", handle));
        display::print_field(&format!("Data path direction: {} (0x{:02x})", dir_str, direction));
        display::print_field(&format!("Codec ID: 0x{:02x}", codec_id));
        display::print_hex_field("Company ID + Vendor Codec ID", &data[4..8]);
        display::print_field(&format!("Controller delay: {} us", controller_delay));
        display::print_field(&format!("Codec configuration length: {}", codec_config_len));
        if codec_config_len > 0 && data.len() > 12 {
            let end = (12 + codec_config_len).min(data.len());
            display::print_hexdump(&data[12..end]);
        }
    }
}

// ---- Event decoder functions ----

fn cmd_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let ncmd = data[0];
    let opcode = le_u16(data, 1);
    let ogf = (opcode >> 10) & 0x3F;
    let ocf = opcode & 0x03FF;

    display::print_field(&format!("Num HCI command packets: {}", ncmd));
    display::print_field(&format!(
        "Command opcode: 0x{:04x} (OGF 0x{:02x}, OCF 0x{:04x})",
        opcode, ogf, ocf
    ));

    if data.len() > 3 {
        // Look up opcode for response decoder
        if let Some(entry) = find_opcode(opcode) {
            if let Some(rsp_func) = entry.rsp_func {
                rsp_func(&data[3..]);
                return;
            }
        }
        display::print_hexdump(&data[3..]);
    }
}

fn cmd_status_evt(_index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    display::print_error("Status", data[0]);
    display::print_field(&format!("Num HCI command packets: {}", data[1]));
    let opcode = le_u16(data, 2);
    display::print_field(&format!("Command opcode: 0x{:04x}", opcode));
}

fn conn_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 11 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    display::print_field(&format!("Handle: {}", handle));
    let addr: [u8; 6] = data[3..9].try_into().unwrap();
    display::print_addr("Address", &addr, 0x00);
    display::print_field(&format!("Link type: 0x{:02x}", data[9]));
    display::print_field(&format!("Encryption: 0x{:02x}", data[10]));
}

fn disconn_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    display::print_field(&format!("Handle: {}", handle));
    display::print_error("Reason", data[3]);
}

fn auth_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    display::print_field(&format!("Handle: {}", handle));
}

fn encryption_change_evt(_index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    let encryption = data[3];
    let enc_str = match encryption {
        0x00 => "Disabled",
        0x01 => "Enabled with E0/AES-CCM",
        0x02 => "Enabled with AES-CCM (BR/EDR Secure Connections)",
        _ => "Unknown",
    };
    display::print_field(&format!("Handle: {}", handle));
    display::print_field(&format!("Encryption: {} (0x{:02x})", enc_str, encryption));
}

fn read_remote_version_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    let version = data[3];
    let manufacturer = le_u16(data, 4);
    let subversion = le_u16(data, 6);

    display::print_field(&format!("Handle: {}", handle));
    display::print_field(&format!("LMP version: 0x{:02x}", version));
    display::print_company("Manufacturer", manufacturer);
    display::print_field(&format!("LMP subversion: 0x{:04x}", subversion));
}

fn num_completed_packets_evt(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let num_handles = data[0] as usize;
    display::print_field(&format!("Num handles: {}", num_handles));
    for i in 0..num_handles {
        let offset = 1 + i * 4;
        if data.len() >= offset + 4 {
            let handle = le_u16(data, offset);
            let count = le_u16(data, offset + 2);
            display::print_field(&format!("  Handle: {}, Count: {}", handle, count));
        }
    }
}

fn link_key_notification_evt(_index: u16, data: &[u8]) {
    if data.len() < 23 {
        return;
    }
    let addr: [u8; 6] = data[0..6].try_into().unwrap();
    display::print_addr("Address", &addr, 0x00);
    display::print_hex_field("Link key", &data[6..22]);
    let key_type = data[22];
    let key_type_str = match key_type {
        0x00 => "Combination Key",
        0x01 => "Local Unit Key",
        0x02 => "Remote Unit Key",
        0x03 => "Debug Combination Key",
        0x04 => "Unauthenticated Combination Key from P-192",
        0x05 => "Authenticated Combination Key from P-192",
        0x06 => "Changed Combination Key",
        0x07 => "Unauthenticated Combination Key from P-256",
        0x08 => "Authenticated Combination Key from P-256",
        _ => "Unknown",
    };
    display::print_field(&format!("Key type: {} (0x{:02x})", key_type_str, key_type));
}

fn io_capability_request_evt(_index: u16, data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    let addr: [u8; 6] = data[0..6].try_into().unwrap();
    display::print_addr("Address", &addr, 0x00);
}

fn io_capability_response_evt(_index: u16, data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    let addr: [u8; 6] = data[0..6].try_into().unwrap();
    display::print_addr("Address", &addr, 0x00);

    let io_cap = data[6];
    let io_cap_str = match io_cap {
        0x00 => "DisplayOnly",
        0x01 => "DisplayYesNo",
        0x02 => "KeyboardOnly",
        0x03 => "NoInputNoOutput",
        _ => "Unknown",
    };
    display::print_field(&format!("IO capability: {} (0x{:02x})", io_cap_str, io_cap));

    let oob = data[7];
    display::print_field(&format!("OOB data present: {} (0x{:02x})", if oob == 0 { "No" } else { "Yes" }, oob));

    let auth_req = data[8];
    display::print_field(&format!("Authentication requirement: 0x{:02x}", auth_req));
}

fn user_confirm_request_evt(_index: u16, data: &[u8]) {
    if data.len() < 10 {
        return;
    }
    let addr: [u8; 6] = data[0..6].try_into().unwrap();
    display::print_addr("Address", &addr, 0x00);
    let passkey = le_u32(data, 6);
    display::print_field(&format!("Passkey: {:06}", passkey));
}

fn simple_pairing_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    display::print_error("Status", data[0]);
    let addr: [u8; 6] = data[1..7].try_into().unwrap();
    display::print_addr("Address", &addr, 0x00);
}

fn le_meta_evt(index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let sub_event = data[0];
    let entry = find_le_meta_event(sub_event);
    let name = entry.map(|e| e.name).unwrap_or("Unknown");
    display::print_field(&format!("Sub event: {} (0x{:02x})", name, sub_event));

    if let Some(entry) = entry {
        if let Some(evt_func) = entry.evt_func {
            evt_func(index, &data[1..]);
            return;
        }
    }
    if data.len() > 1 {
        display::print_hexdump(&data[1..]);
    }
}

fn le_conn_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 18 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    display::print_field(&format!("Handle: {}", handle));
    display::print_field(&format!("Role: {}", if data[3] == 0 { "Central" } else { "Peripheral" }));
    let addr: [u8; 6] = data[5..11].try_into().unwrap();
    display::print_addr("Peer Address", &addr, data[4]);
}

fn le_adv_report_evt(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let num_reports = data[0] as usize;
    display::print_field(&format!("Num reports: {}", num_reports));

    let mut offset = 1;
    for i in 0..num_reports {
        if data.len() < offset + 8 {
            break;
        }
        let event_type = data[offset];
        let addr_type = data[offset + 1];
        display::print_field(&format!("Entry {}:", i));
        display::print_field(&format!("  Event type: {} (0x{:02x})", adv_type_str(event_type), event_type));
        display::print_field(&format!("  Address type: {} (0x{:02x})", addr_type_str(addr_type), addr_type));

        if data.len() >= offset + 8 {
            let addr: [u8; 6] = data[offset + 2..offset + 8].try_into().unwrap();
            display::print_addr("  Address", &addr, addr_type);
        }

        offset += 8;
        if data.len() > offset {
            let data_len = data[offset] as usize;
            offset += 1;
            display::print_field(&format!("  Data length: {}", data_len));
            if data.len() >= offset + data_len {
                if data_len > 0 {
                    display::print_hexdump(&data[offset..offset + data_len]);
                }
                offset += data_len;
            }
            // RSSI
            if data.len() > offset {
                let rssi = data[offset] as i8;
                display::print_field(&format!("  RSSI: {} dBm", rssi));
                offset += 1;
            }
        }
    }
}

fn le_conn_update_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    let interval = le_u16(data, 3);
    let latency = le_u16(data, 5);
    let supervision_timeout = le_u16(data, 7);

    display::print_field(&format!("Handle: {}", handle));
    display::print_field(&format!("Connection interval: {} ({:.2} ms)", interval, interval as f64 * 1.25));
    display::print_field(&format!("Connection latency: {}", latency));
    display::print_field(&format!("Supervision timeout: {} ({} ms)", supervision_timeout, supervision_timeout as u32 * 10));
}

fn le_read_remote_features_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 11 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    display::print_field(&format!("Handle: {}", handle));
    display::print_hex_field("LE Features", &data[3..11]);
}

fn le_long_term_key_request_evt(_index: u16, data: &[u8]) {
    if data.len() < 12 {
        return;
    }
    let handle = le_u16(data, 0);
    display::print_field(&format!("Handle: {}", handle));
    display::print_hex_field("Random number", &data[2..10]);
    let ediv = le_u16(data, 10);
    display::print_field(&format!("Encrypted diversifier: 0x{:04x}", ediv));
}

fn le_data_length_change_evt(_index: u16, data: &[u8]) {
    if data.len() < 10 {
        return;
    }
    let handle = le_u16(data, 0);
    let max_tx_octets = le_u16(data, 2);
    let max_tx_time = le_u16(data, 4);
    let max_rx_octets = le_u16(data, 6);
    let max_rx_time = le_u16(data, 8);

    display::print_field(&format!("Handle: {}", handle));
    display::print_field(&format!("Max TX octets: {}", max_tx_octets));
    display::print_field(&format!("Max TX time: {} us", max_tx_time));
    display::print_field(&format!("Max RX octets: {}", max_rx_octets));
    display::print_field(&format!("Max RX time: {} us", max_rx_time));
}

fn le_phy_update_complete_evt(_index: u16, data: &[u8]) {
    if data.len() < 5 {
        return;
    }
    display::print_error("Status", data[0]);
    let handle = le_u16(data, 1);
    let tx_phy = data[3];
    let rx_phy = data[4];

    display::print_field(&format!("Handle: {}", handle));
    display::print_field(&format!("TX PHY: {} (0x{:02x})", phy_str(tx_phy), tx_phy));
    display::print_field(&format!("RX PHY: {} (0x{:02x})", phy_str(rx_phy), rx_phy));
}

fn le_ext_adv_report_evt(_index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let num_reports = data[0] as usize;
    display::print_field(&format!("Num reports: {}", num_reports));

    let mut offset = 1;
    for i in 0..num_reports {
        if data.len() < offset + 24 {
            break;
        }
        let event_type = le_u16(data, offset);
        let addr_type = data[offset + 2];
        display::print_field(&format!("Entry {}:", i));
        display::print_field(&format!("  Event type: 0x{:04x}", event_type));
        display::print_field(&format!("  Address type: {} (0x{:02x})", addr_type_str(addr_type), addr_type));

        let addr: [u8; 6] = data[offset + 3..offset + 9].try_into().unwrap();
        display::print_addr("  Address", &addr, addr_type);

        let primary_phy = data[offset + 9];
        let secondary_phy = data[offset + 10];
        let sid = data[offset + 11];
        let tx_power = data[offset + 12] as i8;
        let rssi = data[offset + 13] as i8;
        let periodic_adv_interval = le_u16(data, offset + 14);
        let direct_addr_type = data[offset + 16];

        display::print_field(&format!("  Primary PHY: {} (0x{:02x})", phy_str(primary_phy), primary_phy));
        display::print_field(&format!("  Secondary PHY: {} (0x{:02x})", phy_str(secondary_phy), secondary_phy));
        display::print_field(&format!("  SID: 0x{:02x}", sid));
        display::print_field(&format!("  TX power: {} dBm", tx_power));
        display::print_field(&format!("  RSSI: {} dBm", rssi));
        display::print_field(&format!("  Periodic advertising interval: {}", periodic_adv_interval));
        display::print_field(&format!("  Direct address type: {} (0x{:02x})", addr_type_str(direct_addr_type), direct_addr_type));

        if data.len() >= offset + 23 {
            let direct_addr: [u8; 6] = data[offset + 17..offset + 23].try_into().unwrap();
            display::print_addr("  Direct address", &direct_addr, direct_addr_type);
        }

        let data_len = data[offset + 23] as usize;
        offset += 24;
        display::print_field(&format!("  Data length: {}", data_len));
        if data.len() >= offset + data_len {
            if data_len > 0 {
                display::print_hexdump(&data[offset..offset + data_len]);
            }
            offset += data_len;
        }
    }
}

// ---- Opcode table ----

static OPCODE_TABLE: &[OpcodeEntry] = &[
    // OGF 0x01 - Link Control
    OpcodeEntry { opcode: 0x0401, name: "Inquiry", cmd_func: Some(inquiry_cmd), cmd_size: 5, cmd_fixed: true, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x0402, name: "Inquiry Cancel", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0406, name: "Disconnect", cmd_func: Some(disconnect_cmd), cmd_size: 3, cmd_fixed: true, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    // OGF 0x02 - Link Policy
    OpcodeEntry { opcode: 0x080f, name: "Write Default Link Policy Settings", cmd_func: Some(write_default_link_policy_cmd), cmd_size: 2, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    // OGF 0x03 - Controller & Baseband
    OpcodeEntry { opcode: 0x0c01, name: "Set Event Mask", cmd_func: Some(set_event_mask_cmd), cmd_size: 8, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c03, name: "Reset", cmd_func: Some(reset_cmd), cmd_size: 0, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c13, name: "Write Local Name", cmd_func: Some(write_local_name_cmd), cmd_size: 248, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c14, name: "Read Local Name", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: Some(read_local_name_rsp), rsp_size: 249, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c1a, name: "Write Scan Enable", cmd_func: Some(write_scan_enable_cmd), cmd_size: 1, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c1c, name: "Write Page Scan Activity", cmd_func: Some(write_page_scan_activity_cmd), cmd_size: 4, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c24, name: "Write Class of Device", cmd_func: Some(write_class_of_device_cmd), cmd_size: 3, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c56, name: "Write Simple Pairing Mode", cmd_func: Some(write_simple_pairing_mode_cmd), cmd_size: 1, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c6d, name: "Write LE Host Supported", cmd_func: None, cmd_size: 2, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x0c7a, name: "Write Secure Connections Support", cmd_func: Some(write_sc_host_support_cmd), cmd_size: 1, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    // OGF 0x04 - Informational
    OpcodeEntry { opcode: 0x1001, name: "Read Local Version Information", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: Some(read_local_version_rsp), rsp_size: 9, rsp_fixed: true },
    OpcodeEntry { opcode: 0x1002, name: "Read Local Supported Commands", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: None, rsp_size: 65, rsp_fixed: true },
    OpcodeEntry { opcode: 0x1003, name: "Read Local Supported Features", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: Some(read_local_features_rsp), rsp_size: 9, rsp_fixed: true },
    OpcodeEntry { opcode: 0x1005, name: "Read Buffer Size", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: None, rsp_size: 8, rsp_fixed: true },
    OpcodeEntry { opcode: 0x1009, name: "Read BD ADDR", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: Some(read_bd_addr_rsp), rsp_size: 7, rsp_fixed: true },
    // OGF 0x08 - LE Controller
    OpcodeEntry { opcode: 0x2001, name: "LE Set Event Mask", cmd_func: None, cmd_size: 8, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2002, name: "LE Read Buffer Size", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: None, rsp_size: 4, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2003, name: "LE Read Local P-256 Public Key", cmd_func: None, cmd_size: 0, cmd_fixed: true, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x2005, name: "LE Set Random Address", cmd_func: None, cmd_size: 6, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2006, name: "LE Set Advertising Parameters", cmd_func: Some(le_set_adv_params_cmd), cmd_size: 15, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2008, name: "LE Set Advertising Data", cmd_func: Some(le_set_adv_data_cmd), cmd_size: 32, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2009, name: "LE Set Scan Response Data", cmd_func: Some(le_set_scan_rsp_data_cmd), cmd_size: 32, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x200a, name: "LE Set Advertise Enable", cmd_func: Some(le_set_adv_enable_cmd), cmd_size: 1, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x200b, name: "LE Set Scan Parameters", cmd_func: Some(le_set_scan_params_cmd), cmd_size: 7, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x200c, name: "LE Set Scan Enable", cmd_func: Some(le_set_scan_enable_cmd), cmd_size: 2, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x200d, name: "LE Create Connection", cmd_func: Some(le_create_conn_cmd), cmd_size: 25, cmd_fixed: true, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x2016, name: "LE Read Remote Features", cmd_func: Some(le_read_remote_features_cmd), cmd_size: 2, cmd_fixed: true, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x2019, name: "LE Start Encryption", cmd_func: Some(le_start_encryption_cmd), cmd_size: 28, cmd_fixed: true, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x2030, name: "LE Read PHY", cmd_func: Some(le_read_phy_cmd), cmd_size: 2, cmd_fixed: true, rsp_func: Some(le_read_phy_rsp), rsp_size: 5, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2032, name: "LE Set PHY", cmd_func: Some(le_set_phy_cmd), cmd_size: 7, cmd_fixed: true, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x2036, name: "LE Set Extended Advertising Parameters", cmd_func: Some(le_set_ext_adv_params_cmd), cmd_size: 25, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2037, name: "LE Set Extended Advertising Data", cmd_func: Some(le_set_ext_adv_data_cmd), cmd_size: 4, cmd_fixed: false, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2041, name: "LE Set Extended Scan Parameters", cmd_func: Some(le_set_ext_scan_params_cmd), cmd_size: 3, cmd_fixed: false, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2042, name: "LE Set Extended Scan Enable", cmd_func: Some(le_set_ext_scan_enable_cmd), cmd_size: 6, cmd_fixed: true, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
    OpcodeEntry { opcode: 0x2043, name: "LE Extended Create Connection", cmd_func: Some(le_ext_create_conn_cmd), cmd_size: 10, cmd_fixed: false, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x2062, name: "LE Set CIG Parameters", cmd_func: Some(le_set_cig_params_cmd), cmd_size: 15, cmd_fixed: false, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x2064, name: "LE Create CIS", cmd_func: Some(le_create_cis_cmd), cmd_size: 1, cmd_fixed: false, rsp_func: None, rsp_size: 0, rsp_fixed: false },
    OpcodeEntry { opcode: 0x206e, name: "LE Setup ISO Data Path", cmd_func: Some(le_setup_iso_data_path_cmd), cmd_size: 13, cmd_fixed: false, rsp_func: Some(status_rsp), rsp_size: 1, rsp_fixed: true },
];

// ---- Event table ----

static EVENT_TABLE: &[EventEntry] = &[
    EventEntry { event: 0x01, name: "Inquiry Complete", evt_func: None, evt_size: 1, evt_fixed: true },
    EventEntry { event: 0x03, name: "Connection Complete", evt_func: Some(conn_complete_evt), evt_size: 11, evt_fixed: true },
    EventEntry { event: 0x05, name: "Disconnection Complete", evt_func: Some(disconn_complete_evt), evt_size: 4, evt_fixed: true },
    EventEntry { event: 0x06, name: "Authentication Complete", evt_func: Some(auth_complete_evt), evt_size: 3, evt_fixed: true },
    EventEntry { event: 0x08, name: "Encryption Change", evt_func: Some(encryption_change_evt), evt_size: 4, evt_fixed: true },
    EventEntry { event: 0x0c, name: "Read Remote Version Information Complete", evt_func: Some(read_remote_version_complete_evt), evt_size: 8, evt_fixed: true },
    EventEntry { event: 0x0e, name: "Command Complete", evt_func: Some(cmd_complete_evt), evt_size: 3, evt_fixed: false },
    EventEntry { event: 0x0f, name: "Command Status", evt_func: Some(cmd_status_evt), evt_size: 4, evt_fixed: true },
    EventEntry { event: 0x13, name: "Number of Completed Packets", evt_func: Some(num_completed_packets_evt), evt_size: 1, evt_fixed: false },
    EventEntry { event: 0x18, name: "Link Key Notification", evt_func: Some(link_key_notification_evt), evt_size: 23, evt_fixed: true },
    EventEntry { event: 0x31, name: "IO Capability Request", evt_func: Some(io_capability_request_evt), evt_size: 6, evt_fixed: true },
    EventEntry { event: 0x32, name: "IO Capability Response", evt_func: Some(io_capability_response_evt), evt_size: 9, evt_fixed: true },
    EventEntry { event: 0x33, name: "User Confirmation Request", evt_func: Some(user_confirm_request_evt), evt_size: 10, evt_fixed: true },
    EventEntry { event: 0x36, name: "Simple Pairing Complete", evt_func: Some(simple_pairing_complete_evt), evt_size: 7, evt_fixed: true },
    EventEntry { event: 0x3e, name: "LE Meta Event", evt_func: Some(le_meta_evt), evt_size: 1, evt_fixed: false },
    EventEntry { event: 0xff, name: "Vendor Specific", evt_func: None, evt_size: 0, evt_fixed: false },
];

// ---- LE Meta Event sub-table ----

static LE_META_EVENT_TABLE: &[EventEntry] = &[
    EventEntry { event: 0x01, name: "LE Connection Complete", evt_func: Some(le_conn_complete_evt), evt_size: 18, evt_fixed: true },
    EventEntry { event: 0x02, name: "LE Advertising Report", evt_func: Some(le_adv_report_evt), evt_size: 1, evt_fixed: false },
    EventEntry { event: 0x03, name: "LE Connection Update Complete", evt_func: Some(le_conn_update_complete_evt), evt_size: 9, evt_fixed: true },
    EventEntry { event: 0x04, name: "LE Read Remote Features Complete", evt_func: Some(le_read_remote_features_complete_evt), evt_size: 11, evt_fixed: true },
    EventEntry { event: 0x05, name: "LE Long Term Key Request", evt_func: Some(le_long_term_key_request_evt), evt_size: 12, evt_fixed: true },
    EventEntry { event: 0x07, name: "LE Data Length Change", evt_func: Some(le_data_length_change_evt), evt_size: 10, evt_fixed: true },
    EventEntry { event: 0x0a, name: "LE Enhanced Connection Complete", evt_func: Some(le_conn_complete_evt), evt_size: 30, evt_fixed: true },
    EventEntry { event: 0x0c, name: "LE PHY Update Complete", evt_func: Some(le_phy_update_complete_evt), evt_size: 5, evt_fixed: true },
    EventEntry { event: 0x0d, name: "LE Extended Advertising Report", evt_func: Some(le_ext_adv_report_evt), evt_size: 1, evt_fixed: false },
];

/// Find an opcode table entry.
pub fn find_opcode(opcode: u16) -> Option<&'static OpcodeEntry> {
    OPCODE_TABLE.iter().find(|e| e.opcode == opcode)
}

/// Find an event table entry.
pub fn find_event(event: u8) -> Option<&'static EventEntry> {
    EVENT_TABLE.iter().find(|e| e.event == event)
}

/// Find an LE meta-event table entry.
pub fn find_le_meta_event(sub_event: u8) -> Option<&'static EventEntry> {
    LE_META_EVENT_TABLE.iter().find(|e| e.event == sub_event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_opcode() {
        let entry = find_opcode(0x0c03).unwrap();
        assert_eq!(entry.name, "Reset");
        assert!(entry.cmd_func.is_some());

        let entry = find_opcode(0x1009).unwrap();
        assert_eq!(entry.name, "Read BD ADDR");
        assert!(entry.rsp_func.is_some());

        assert!(find_opcode(0xFFFF).is_none());
    }

    #[test]
    fn test_find_event() {
        let entry = find_event(0x0e).unwrap();
        assert_eq!(entry.name, "Command Complete");
        assert!(entry.evt_func.is_some());

        let entry = find_event(0x3e).unwrap();
        assert_eq!(entry.name, "LE Meta Event");

        assert!(find_event(0x80).is_none());
    }

    #[test]
    fn test_find_le_meta_event() {
        let entry = find_le_meta_event(0x01).unwrap();
        assert_eq!(entry.name, "LE Connection Complete");
        assert!(find_le_meta_event(0xFF).is_none());
    }

    #[test]
    fn test_cmd_decoders() {
        // Just verify no panic
        inquiry_cmd(&[0x33, 0x8B, 0x9E, 0x08, 0x00]);
        disconnect_cmd(&[0x40, 0x00, 0x13]);
        reset_cmd(&[]);
        status_rsp(&[0x00]);
        read_bd_addr_rsp(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        read_local_version_rsp(&[0x00, 0x0d, 0x01, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_evt_decoders() {
        // Just verify no panic
        cmd_complete_evt(0, &[0x01, 0x03, 0x0c, 0x00]);
        cmd_status_evt(0, &[0x00, 0x01, 0x03, 0x0c]);
        conn_complete_evt(0, &[0x00, 0x40, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x00]);
        disconn_complete_evt(0, &[0x00, 0x40, 0x00, 0x13]);
    }

    #[test]
    fn test_new_opcode_entries() {
        // Verify all new opcodes are findable
        assert_eq!(find_opcode(0x2006).unwrap().name, "LE Set Advertising Parameters");
        assert_eq!(find_opcode(0x2008).unwrap().name, "LE Set Advertising Data");
        assert_eq!(find_opcode(0x2009).unwrap().name, "LE Set Scan Response Data");
        assert_eq!(find_opcode(0x200a).unwrap().name, "LE Set Advertise Enable");
        assert_eq!(find_opcode(0x200b).unwrap().name, "LE Set Scan Parameters");
        assert_eq!(find_opcode(0x200c).unwrap().name, "LE Set Scan Enable");
        assert_eq!(find_opcode(0x200d).unwrap().name, "LE Create Connection");
        assert_eq!(find_opcode(0x2016).unwrap().name, "LE Read Remote Features");
        assert_eq!(find_opcode(0x2019).unwrap().name, "LE Start Encryption");
        assert_eq!(find_opcode(0x2036).unwrap().name, "LE Set Extended Advertising Parameters");
        assert_eq!(find_opcode(0x2037).unwrap().name, "LE Set Extended Advertising Data");
        assert_eq!(find_opcode(0x2041).unwrap().name, "LE Set Extended Scan Parameters");
        assert_eq!(find_opcode(0x2042).unwrap().name, "LE Set Extended Scan Enable");
        assert_eq!(find_opcode(0x2043).unwrap().name, "LE Extended Create Connection");
        assert_eq!(find_opcode(0x2030).unwrap().name, "LE Read PHY");
        assert_eq!(find_opcode(0x2032).unwrap().name, "LE Set PHY");
        assert_eq!(find_opcode(0x2062).unwrap().name, "LE Set CIG Parameters");
        assert_eq!(find_opcode(0x2064).unwrap().name, "LE Create CIS");
        assert_eq!(find_opcode(0x206e).unwrap().name, "LE Setup ISO Data Path");
        assert_eq!(find_opcode(0x080f).unwrap().name, "Write Default Link Policy Settings");
        assert_eq!(find_opcode(0x0c1a).unwrap().name, "Write Scan Enable");
        assert_eq!(find_opcode(0x0c1c).unwrap().name, "Write Page Scan Activity");
        assert_eq!(find_opcode(0x0c24).unwrap().name, "Write Class of Device");
        assert_eq!(find_opcode(0x0c13).unwrap().name, "Write Local Name");
        assert_eq!(find_opcode(0x0c14).unwrap().name, "Read Local Name");
        assert_eq!(find_opcode(0x0c01).unwrap().name, "Set Event Mask");
        assert_eq!(find_opcode(0x0c56).unwrap().name, "Write Simple Pairing Mode");
        assert_eq!(find_opcode(0x0c7a).unwrap().name, "Write Secure Connections Support");
    }

    #[test]
    fn test_new_event_entries() {
        assert_eq!(find_event(0x06).unwrap().name, "Authentication Complete");
        assert_eq!(find_event(0x08).unwrap().name, "Encryption Change");
        assert_eq!(find_event(0x0c).unwrap().name, "Read Remote Version Information Complete");
        assert_eq!(find_event(0x18).unwrap().name, "Link Key Notification");
        assert_eq!(find_event(0x31).unwrap().name, "IO Capability Request");
        assert_eq!(find_event(0x32).unwrap().name, "IO Capability Response");
        assert_eq!(find_event(0x33).unwrap().name, "User Confirmation Request");
        assert_eq!(find_event(0x36).unwrap().name, "Simple Pairing Complete");
    }

    #[test]
    fn test_new_le_meta_event_entries() {
        assert_eq!(find_le_meta_event(0x02).unwrap().name, "LE Advertising Report");
        assert_eq!(find_le_meta_event(0x03).unwrap().name, "LE Connection Update Complete");
        assert_eq!(find_le_meta_event(0x04).unwrap().name, "LE Read Remote Features Complete");
        assert_eq!(find_le_meta_event(0x05).unwrap().name, "LE Long Term Key Request");
        assert_eq!(find_le_meta_event(0x07).unwrap().name, "LE Data Length Change");
        assert_eq!(find_le_meta_event(0x0c).unwrap().name, "LE PHY Update Complete");
        assert_eq!(find_le_meta_event(0x0d).unwrap().name, "LE Extended Advertising Report");
    }

    #[test]
    fn test_decode_encryption_change() {
        // Status=0, Handle=0x0040, Encryption=0x01
        encryption_change_evt(0, &[0x00, 0x40, 0x00, 0x01]);
    }

    #[test]
    fn test_decode_le_advertising_report() {
        // 1 report, event_type=0x00, addr_type=0x01, addr=6 bytes, data_len=3, data, rssi=-50
        let mut data = vec![
            0x01, // num_reports
            0x00, // event_type: ADV_IND
            0x01, // addr_type: Random
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // address
            0x03, // data_length
            0x02, 0x01, 0x06, // ad data
            0xCE, // RSSI = -50
        ];
        le_adv_report_evt(0, &data);

        // also test empty
        le_adv_report_evt(0, &[]);
        le_adv_report_evt(0, &[0x00]);
    }

    #[test]
    fn test_decode_le_ext_adv_report() {
        // Minimal extended advertising report
        let mut data = vec![0x01]; // 1 report
        // event_type(2) + addr_type(1) + addr(6) + primary_phy(1) + secondary_phy(1)
        // + sid(1) + tx_power(1) + rssi(1) + periodic_adv_interval(2) + direct_addr_type(1)
        // + direct_addr(6) + data_len(1) = 24 bytes per entry
        data.extend_from_slice(&[
            0x00, 0x00, // event type
            0x01, // addr type: Random
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // address
            0x01, // primary PHY
            0x00, // secondary PHY
            0xFF, // SID
            0x7F, // TX power (127 = not available)
            0xCE, // RSSI = -50
            0x00, 0x00, // periodic adv interval
            0x00, // direct addr type
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // direct address
            0x00, // data length
        ]);
        le_ext_adv_report_evt(0, &data);
    }

    #[test]
    fn test_decode_le_scan_params_cmd() {
        // Active scan, interval=0x0010, window=0x0010, own_addr=public, filter=accept all
        le_set_scan_params_cmd(&[0x01, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_decode_le_adv_params_cmd() {
        // min=0x0800, max=0x0800, type=ADV_IND, own=public, peer=public, peer_addr, chan=0x07, filter=0x00
        let data = [
            0x00, 0x08, // min interval
            0x00, 0x08, // max interval
            0x00, // adv type
            0x00, // own addr type
            0x00, // peer addr type
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // peer addr
            0x07, // channel map
            0x00, // filter policy
        ];
        le_set_adv_params_cmd(&data);
    }

    #[test]
    fn test_decode_le_create_conn_cmd() {
        let data = [
            0x60, 0x00, // scan interval
            0x30, 0x00, // scan window
            0x00, // filter policy
            0x00, // peer addr type
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // peer addr
            0x00, // own addr type
            0x18, 0x00, // min interval
            0x28, 0x00, // max interval
            0x00, 0x00, // latency
            0xC8, 0x00, // supervision timeout
            0x00, 0x00, // min CE
            0x00, 0x00, // max CE
            0x00, 0x00, // padding for 25 bytes total
        ];
        le_create_conn_cmd(&data);
    }

    #[test]
    fn test_decode_write_cmds() {
        write_scan_enable_cmd(&[0x03]);
        write_page_scan_activity_cmd(&[0x00, 0x08, 0x12, 0x00]);
        write_class_of_device_cmd(&[0x0C, 0x02, 0x5A]);
        write_simple_pairing_mode_cmd(&[0x01]);
        write_sc_host_support_cmd(&[0x01]);
        write_default_link_policy_cmd(&[0x07, 0x00]);
        set_event_mask_cmd(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00]);
        write_local_name_cmd(b"BlueZ Test\0");
    }

    #[test]
    fn test_decode_io_capability_response() {
        let data = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // address
            0x01, // IO cap: DisplayYesNo
            0x00, // OOB: No
            0x05, // AuthReq
        ];
        io_capability_response_evt(0, &data);
    }

    #[test]
    fn test_decode_simple_pairing_complete() {
        let data = [
            0x00, // status
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // address
        ];
        simple_pairing_complete_evt(0, &data);
    }

    #[test]
    fn test_decode_link_key_notification() {
        let mut data = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // address (6)
        ];
        data.extend_from_slice(&[0u8; 16]); // link key (16)
        data.push(0x05); // key type
        link_key_notification_evt(0, &data);
    }

    #[test]
    fn test_decode_le_phy_update_complete() {
        le_phy_update_complete_evt(0, &[0x00, 0x40, 0x00, 0x02, 0x02]);
    }

    #[test]
    fn test_decode_le_data_length_change() {
        le_data_length_change_evt(0, &[
            0x40, 0x00, // handle
            0xFB, 0x00, // max tx octets
            0x48, 0x08, // max tx time
            0xFB, 0x00, // max rx octets
            0x48, 0x08, // max rx time
        ]);
    }
}
