//! Broadcom vendor HCI extension decoder for btmon.
//!
//! Stub — full implementation will be provided by the assigned agent.

use super::{VendorEvt, VendorOcf};

/// Returns Broadcom vendor OCF descriptor for the given opcode, if known.
pub fn broadcom_vendor_ocf(_ocf: u16) -> Option<&'static VendorOcf> {
    None
}

/// Returns Broadcom vendor event descriptor for the given event code, if known.
pub fn broadcom_vendor_evt(_evt: u8) -> Option<&'static VendorEvt> {
    None
}

/// Decode Broadcom LM diagnostic events.
pub fn broadcom_lm_diag(_index: u16, _data: &[u8]) {}
