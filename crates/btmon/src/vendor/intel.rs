//! Intel vendor HCI extension decoder for btmon.
//!
//! Stub — full implementation will be provided by the assigned agent.

use super::{VendorEvt, VendorOcf};

/// Returns Intel vendor OCF descriptor for the given opcode, if known.
pub fn intel_vendor_ocf(_ocf: u16) -> Option<&'static VendorOcf> {
    None
}

/// Returns Intel vendor event descriptor for the given event code, if known.
pub fn intel_vendor_evt(_evt: u8) -> Option<&'static VendorEvt> {
    None
}
