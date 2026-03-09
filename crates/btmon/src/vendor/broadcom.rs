// SPDX-License-Identifier: GPL-2.0-or-later
//
// Broadcom vendor-specific HCI decoders replacing monitor/broadcom.c

use super::{VendorEvt, VendorOcf};
use crate::display;

fn status_rsp(data: &[u8]) {
    if !data.is_empty() {
        display::print_error("Status", data[0]);
    }
}

static VENDOR_OCF_TABLE: &[VendorOcf] = &[
    VendorOcf {
        ocf: 0x001,
        name: "Write BD Address",
        cmd_func: None,
        cmd_size: 6,
        cmd_fixed: true,
        rsp_func: Some(status_rsp),
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x018,
        name: "Update UART Baud Rate",
        cmd_func: None,
        cmd_size: 6,
        cmd_fixed: true,
        rsp_func: Some(status_rsp),
        rsp_size: 1,
        rsp_fixed: true,
    },
    VendorOcf {
        ocf: 0x04e,
        name: "Write SCO PCM Int Param",
        cmd_func: None,
        cmd_size: 5,
        cmd_fixed: true,
        rsp_func: Some(status_rsp),
        rsp_size: 1,
        rsp_fixed: true,
    },
];

static VENDOR_EVT_TABLE: &[VendorEvt] = &[];

pub fn vendor_ocf(ocf: u16) -> Option<&'static VendorOcf> {
    VENDOR_OCF_TABLE.iter().find(|e| e.ocf == ocf)
}

pub fn vendor_evt(evt: u8) -> Option<&'static VendorEvt> {
    VENDOR_EVT_TABLE.iter().find(|e| e.evt == evt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcom_vendor_ocf() {
        assert_eq!(vendor_ocf(0x001).unwrap().name, "Write BD Address");
        assert!(vendor_ocf(0xFFF).is_none());
    }
}
