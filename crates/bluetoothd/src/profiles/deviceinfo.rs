// SPDX-License-Identifier: GPL-2.0-or-later
//
// Device Information profile implementation (~499 LOC C).
//
// Device Information Service (DIS) — exposes manufacturer info, model number,
// serial number, firmware/hardware/software revisions, and PnP ID.

/// DIS characteristic UUIDs.
pub const DEVICE_INFO_SERVICE_UUID: u16 = 0x180A;
pub const MANUFACTURER_NAME_UUID: u16 = 0x2A29;
pub const MODEL_NUMBER_UUID: u16 = 0x2A24;
pub const SERIAL_NUMBER_UUID: u16 = 0x2A25;
pub const FIRMWARE_REVISION_UUID: u16 = 0x2A26;
pub const HARDWARE_REVISION_UUID: u16 = 0x2A27;
pub const SOFTWARE_REVISION_UUID: u16 = 0x2A28;
pub const SYSTEM_ID_UUID: u16 = 0x2A23;
pub const PNP_ID_UUID: u16 = 0x2A50;

/// PnP ID vendor ID source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpVendorIdSource {
    /// Bluetooth SIG assigned.
    BluetoothSig,
    /// USB Implementers Forum assigned.
    Usb,
}

/// PnP ID as defined in DIS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnpId {
    pub vendor_id_source: PnpVendorIdSource,
    pub vendor_id: u16,
    pub product_id: u16,
    pub product_version: u16,
}

/// Device Information profile plugin.
#[derive(Debug, Clone)]
pub struct DeviceInfoProfile {
    pub manufacturer_name: Option<String>,
    pub model_number: Option<String>,
    pub serial_number: Option<String>,
    pub firmware_revision: Option<String>,
    pub hardware_revision: Option<String>,
    pub software_revision: Option<String>,
    pub system_id: Option<[u8; 8]>,
    pub pnp_id: Option<PnpId>,
}

impl DeviceInfoProfile {
    pub fn new() -> Self {
        Self {
            manufacturer_name: None,
            model_number: None,
            serial_number: None,
            firmware_revision: None,
            hardware_revision: None,
            software_revision: None,
            system_id: None,
            pnp_id: None,
        }
    }

    /// Parse a PnP ID from a 7-byte GATT characteristic value.
    pub fn parse_pnp_id(data: &[u8]) -> Option<PnpId> {
        if data.len() < 7 {
            return None;
        }
        let source = match data[0] {
            1 => PnpVendorIdSource::BluetoothSig,
            2 => PnpVendorIdSource::Usb,
            _ => return None,
        };
        Some(PnpId {
            vendor_id_source: source,
            vendor_id: u16::from_le_bytes([data[1], data[2]]),
            product_id: u16::from_le_bytes([data[3], data[4]]),
            product_version: u16::from_le_bytes([data[5], data[6]]),
        })
    }
}

impl Default for DeviceInfoProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deviceinfo_defaults() {
        let di = DeviceInfoProfile::new();
        assert!(di.manufacturer_name.is_none());
        assert!(di.pnp_id.is_none());
    }

    #[test]
    fn test_parse_pnp_id() {
        // Vendor source = USB (2), vendor=0x1234, product=0x5678, version=0x0100
        let data = [0x02, 0x34, 0x12, 0x78, 0x56, 0x00, 0x01];
        let pnp = DeviceInfoProfile::parse_pnp_id(&data).unwrap();
        assert_eq!(pnp.vendor_id_source, PnpVendorIdSource::Usb);
        assert_eq!(pnp.vendor_id, 0x1234);
        assert_eq!(pnp.product_id, 0x5678);
        assert_eq!(pnp.product_version, 0x0100);
    }

    #[test]
    fn test_parse_pnp_id_too_short() {
        assert!(DeviceInfoProfile::parse_pnp_id(&[0x01, 0x00]).is_none());
    }
}
