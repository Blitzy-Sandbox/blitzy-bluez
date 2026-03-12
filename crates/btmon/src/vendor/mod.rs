//! Vendor decoder module root, shared types, and default event dispatch.
//!
//! Rewrite of `monitor/vendor.c` (23 lines) + `monitor/vendor.h` (34 lines).
//! Defines the `VendorOcf` and `VendorEvt` descriptor structs used by all
//! vendor submodules (intel, broadcom, msft), provides the top-level
//! `vendor_event()` fallback dispatch function, and re-exports all vendor
//! submodules.

pub mod broadcom;
pub mod intel;
pub mod msft;

// ============================================================================
// Shared Descriptor Types
// ============================================================================

/// Vendor-specific HCI command/response descriptor.
///
/// Maps a vendor OCF code to its human-readable name and decoder functions
/// for both command and response directions, with minimum size requirements.
/// The function signature `fn(u16, &[u8])` replaces the C pattern
/// `void (*func)(uint16_t index, const void *data, uint8_t size)` —
/// the `&[u8]` slice encapsulates both data pointer and size.
pub struct VendorOcf {
    /// Vendor-specific opcode (OCF portion)
    pub ocf: u16,
    /// Human-readable command name
    pub name: &'static str,
    /// Command data decoder function: fn(controller_index, command_data)
    pub cmd_func: fn(u16, &[u8]),
    /// Minimum expected command data size in bytes
    pub cmd_size: usize,
    /// If true, command size must match exactly; if false, it is a minimum
    pub cmd_fixed: bool,
    /// Response data decoder function: fn(controller_index, response_data)
    pub rsp_func: fn(u16, &[u8]),
    /// Minimum expected response data size in bytes
    pub rsp_size: usize,
    /// If true, response size must match exactly; if false, it is a minimum
    pub rsp_fixed: bool,
}

/// Vendor-specific HCI event descriptor.
///
/// Maps a vendor event code to its human-readable name and decoder function
/// with minimum size requirements.
pub struct VendorEvt {
    /// Vendor-specific event code
    pub evt: u8,
    /// Human-readable event name
    pub name: &'static str,
    /// Event data decoder function: fn(controller_index, event_data)
    pub evt_func: fn(u16, &[u8]),
    /// Minimum expected event data size in bytes
    pub evt_size: usize,
    /// If true, event size must match exactly; if false, it is a minimum
    pub evt_fixed: bool,
}

// ============================================================================
// Default Vendor Event Dispatch
// ============================================================================

/// Default vendor event handler — hexdumps the entire event payload.
///
/// This matches the C `vendor_event()` in `vendor.c` which simply calls
/// `packet_hexdump(data, size)`. Actual vendor-specific dispatch happens
/// at a higher level in `packet.rs` based on manufacturer ID.
pub fn vendor_event(_manufacturer: u16, data: &[u8]) {
    crate::packet::hexdump(data);
}

#[cfg(test)]
mod tests {
    use super::{VendorEvt, VendorOcf, vendor_event};

    fn dummy_cmd(_index: u16, _data: &[u8]) {}
    fn dummy_rsp(_index: u16, _data: &[u8]) {}
    fn dummy_evt(_index: u16, _data: &[u8]) {}

    #[test]
    fn test_vendor_ocf_all_fields() {
        let ocf = VendorOcf {
            ocf: 0x0042,
            name: "TestCommand",
            cmd_func: dummy_cmd,
            cmd_size: 10,
            cmd_fixed: true,
            rsp_func: dummy_rsp,
            rsp_size: 5,
            rsp_fixed: false,
        };
        assert_eq!(ocf.ocf, 0x0042);
        assert_eq!(ocf.name, "TestCommand");
        assert_eq!(ocf.cmd_size, 10);
        assert!(ocf.cmd_fixed);
        assert_eq!(ocf.rsp_size, 5);
        assert!(!ocf.rsp_fixed);
    }

    #[test]
    fn test_vendor_ocf_fn_ptrs_callable() {
        let ocf = VendorOcf {
            ocf: 0x01,
            name: "FnTest",
            cmd_func: dummy_cmd,
            cmd_size: 0,
            cmd_fixed: false,
            rsp_func: dummy_rsp,
            rsp_size: 0,
            rsp_fixed: false,
        };
        (ocf.cmd_func)(0, &[]);
        (ocf.cmd_func)(1, &[0x01, 0x02]);
        (ocf.rsp_func)(0, &[0xFF]);
    }

    #[test]
    fn test_vendor_evt_all_fields() {
        let evt = VendorEvt {
            evt: 0x17,
            name: "TestEvent",
            evt_func: dummy_evt,
            evt_size: 3,
            evt_fixed: false,
        };
        assert_eq!(evt.evt, 0x17);
        assert_eq!(evt.name, "TestEvent");
        assert_eq!(evt.evt_size, 3);
        assert!(!evt.evt_fixed);
    }

    #[test]
    fn test_vendor_evt_fn_ptr_callable() {
        let evt = VendorEvt {
            evt: 0x00,
            name: "EvtTest",
            evt_func: dummy_evt,
            evt_size: 0,
            evt_fixed: true,
        };
        (evt.evt_func)(0, &[]);
        (evt.evt_func)(0xFFFF, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_vendor_event_empty_data() {
        vendor_event(0x0002, &[]);
    }

    #[test]
    fn test_vendor_event_with_data() {
        vendor_event(0x0002, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_vendor_event_unknown_manufacturer() {
        vendor_event(0xFFFF, &[0xAA]);
    }

    #[test]
    fn test_intel_submodule_accessible() {
        let _ = crate::vendor::intel::intel_vendor_ocf(0x001);
    }

    #[test]
    fn test_broadcom_submodule_accessible() {
        let _ = crate::vendor::broadcom::broadcom_vendor_ocf(0x0001);
    }

    #[test]
    fn test_msft_submodule_accessible() {
        let _ = crate::vendor::msft::msft_vendor_ocf();
    }
}
