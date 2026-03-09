// SPDX-License-Identifier: GPL-2.0-or-later
//
// Vendor-specific HCI command/event decoders replacing monitor/vendor.c,
// monitor/intel.c, monitor/broadcom.c, monitor/msft.c
//
// Routes vendor-specific HCI commands/events to manufacturer-specific
// decoders based on the controller's manufacturer ID.

pub mod broadcom;
pub mod intel;
pub mod msft;

/// Vendor command/response decoder entry.
pub struct VendorOcf {
    pub ocf: u16,
    pub name: &'static str,
    pub cmd_func: Option<fn(&[u8])>,
    pub cmd_size: u8,
    pub cmd_fixed: bool,
    pub rsp_func: Option<fn(&[u8])>,
    pub rsp_size: u8,
    pub rsp_fixed: bool,
}

/// Vendor event decoder entry.
pub struct VendorEvt {
    pub evt: u8,
    pub name: &'static str,
    pub evt_func: Option<fn(&[u8])>,
    pub evt_size: u8,
    pub evt_fixed: bool,
}

/// Known manufacturer IDs for vendor-specific decoding.
pub const MANUFACTURER_INTEL: u16 = 0x0002;
pub const MANUFACTURER_BROADCOM: u16 = 0x000F;
pub const MANUFACTURER_QUALCOMM: u16 = 0x000A;
pub const MANUFACTURER_REALTEK: u16 = 0x005D;

/// Look up a vendor-specific command decoder.
pub fn vendor_ocf(manufacturer: u16, ocf: u16) -> Option<&'static VendorOcf> {
    match manufacturer {
        MANUFACTURER_INTEL => intel::vendor_ocf(ocf),
        MANUFACTURER_BROADCOM => broadcom::vendor_ocf(ocf),
        _ => None,
    }
}

/// Look up a vendor-specific event decoder.
pub fn vendor_evt(manufacturer: u16, evt: u8) -> Option<&'static VendorEvt> {
    match manufacturer {
        MANUFACTURER_INTEL => intel::vendor_evt(evt),
        MANUFACTURER_BROADCOM => broadcom::vendor_evt(evt),
        _ => None,
    }
}

/// Get the vendor name string.
pub fn vendor_str(manufacturer: u16) -> &'static str {
    match manufacturer {
        MANUFACTURER_INTEL => "Intel",
        MANUFACTURER_BROADCOM => "Broadcom",
        MANUFACTURER_QUALCOMM => "Qualcomm",
        MANUFACTURER_REALTEK => "Realtek",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_str() {
        assert_eq!(vendor_str(MANUFACTURER_INTEL), "Intel");
        assert_eq!(vendor_str(MANUFACTURER_BROADCOM), "Broadcom");
        assert_eq!(vendor_str(0xFFFF), "Unknown");
    }

    #[test]
    fn test_vendor_ocf_lookup() {
        // Intel Reset command
        let entry = vendor_ocf(MANUFACTURER_INTEL, 0x001);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().name, "Reset");

        // Unknown vendor
        assert!(vendor_ocf(0xFFFF, 0x001).is_none());
    }

    #[test]
    fn test_vendor_evt_lookup() {
        // Unknown vendor
        assert!(vendor_evt(0xFFFF, 0x01).is_none());
    }
}
