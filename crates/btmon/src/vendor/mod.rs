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
