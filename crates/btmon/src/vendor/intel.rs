// SPDX-License-Identifier: GPL-2.0-or-later
//
// Intel vendor-specific HCI command/event decoders replacing monitor/intel.c
//
// Decodes Intel-specific vendor commands (OGF 0x3F) and events.

use super::{VendorEvt, VendorOcf};
use crate::display;

fn status_rsp(data: &[u8]) {
    if !data.is_empty() {
        display::print_error("Status", data[0]);
    }
}

fn reset_cmd(data: &[u8]) {
    if data.len() >= 8 {
        display::print_field(&format!("Reset type: 0x{:02x}", data[0]));
        display::print_field(&format!("Patch enable: 0x{:02x}", data[1]));
    }
}

fn read_version_rsp(data: &[u8]) {
    if data.len() >= 10 {
        display::print_error("Status", data[0]);
        display::print_field(&format!("Hardware platform: 0x{:02x}", data[1]));
        display::print_field(&format!("Hardware variant: 0x{:02x}", data[2]));
        display::print_field(&format!("Hardware revision: 0x{:02x}", data[3]));
        display::print_field(&format!("Firmware variant: 0x{:02x}", data[4]));
        display::print_field(&format!("Firmware revision: 0x{:02x}", data[5]));
        display::print_field(&format!("Firmware build: {}", data[6] as u16 | (data[7] as u16) << 8));
    }
}

static VENDOR_OCF_TABLE: &[VendorOcf] = &[
    VendorOcf {
        ocf: 0x001,
        name: "Reset",
        cmd_func: Some(reset_cmd),
        cmd_size: 8,
        cmd_fixed: true,
        rsp_func: Some(status_rsp),
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x005,
        name: "Read Version",
        cmd_func: None,
        cmd_size: 0,
        cmd_fixed: true,
        rsp_func: Some(read_version_rsp),
        rsp_size: 10,
        rsp_fixed: false,
    },
    VendorOcf {
        ocf: 0x011,
        name: "Write BD Address",
        cmd_func: None,
        cmd_size: 6,
        cmd_fixed: true,
        rsp_func: Some(status_rsp),
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x031,
        name: "Set UART Baudrate",
        cmd_func: None,
        cmd_size: 4,
        cmd_fixed: true,
        rsp_func: Some(status_rsp),
        rsp_size: 1,
        rsp_fixed: true,
    },
];

static VENDOR_EVT_TABLE: &[VendorEvt] = &[
    VendorEvt {
        evt: 0x02,
        name: "Fatal Exception",
        evt_func: None,
        evt_size: 0,
        evt_fixed: false,
    },
    VendorEvt {
        evt: 0x05,
        name: "Bootup",
        evt_func: None,
        evt_size: 0,
        evt_fixed: false,
    },
    VendorEvt {
        evt: 0x06,
        name: "Default BD Data",
        evt_func: None,
        evt_size: 0,
        evt_fixed: false,
    },
];

/// Look up an Intel vendor command by OCF.
pub fn vendor_ocf(ocf: u16) -> Option<&'static VendorOcf> {
    VENDOR_OCF_TABLE.iter().find(|e| e.ocf == ocf)
}

/// Look up an Intel vendor event by event code.
pub fn vendor_evt(evt: u8) -> Option<&'static VendorEvt> {
    VENDOR_EVT_TABLE.iter().find(|e| e.evt == evt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intel_vendor_ocf() {
        assert_eq!(vendor_ocf(0x001).unwrap().name, "Reset");
        assert_eq!(vendor_ocf(0x005).unwrap().name, "Read Version");
        assert!(vendor_ocf(0xFFF).is_none());
    }

    #[test]
    fn test_intel_vendor_evt() {
        assert_eq!(vendor_evt(0x05).unwrap().name, "Bootup");
        assert!(vendor_evt(0xFF).is_none());
    }
}
