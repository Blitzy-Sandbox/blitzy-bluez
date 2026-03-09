// SPDX-License-Identifier: GPL-2.0-or-later
//
// Input profile implementations (~4.4K LOC C).
//
// Covers HID (BR/EDR Human Interface Device) and HoG (HID over GATT for LE).

use bluez_shared::BdAddr;

// ---------------------------------------------------------------------------
// HID — Human Interface Device (BR/EDR)
// ---------------------------------------------------------------------------

/// HID protocol mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HidProtocol {
    Boot,
    #[default]
    Report,
}

/// HID report type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidReportType {
    Input,
    Output,
    Feature,
}

/// HID connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HidState {
    #[default]
    Disconnected,
    ConnectingControl,
    ConnectingInterrupt,
    Connected,
    Disconnecting,
}

/// A parsed HID report descriptor item.
#[derive(Debug, Clone)]
pub struct HidDescriptorItem {
    pub tag: u8,
    pub item_type: u8,
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// HID Report Descriptor Parsing
// ---------------------------------------------------------------------------

/// Errors from parsing a HID report descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Unexpected end of data while reading an item.
    UnexpectedEof,
    /// A long item (prefix 0xFE) was encountered; not supported.
    LongItemNotSupported,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of descriptor data"),
            Self::LongItemNotSupported => write!(f, "long items are not supported"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Item type extracted from bits [3:2] of the item prefix byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    Main,
    Global,
    Local,
    Reserved,
}

impl ItemType {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Main,
            1 => Self::Global,
            2 => Self::Local,
            _ => Self::Reserved,
        }
    }
}

/// Main item tags (bits [7:4] of prefix when item type == Main).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainTag {
    Input,
    Output,
    Feature,
    Collection,
    EndCollection,
    Unknown(u8),
}

impl MainTag {
    pub fn from_tag(tag: u8) -> Self {
        match tag {
            0x08 => Self::Input,       // 1000
            0x09 => Self::Output,      // 1001
            0x0B => Self::Feature,     // 1011
            0x0A => Self::Collection,  // 1010
            0x0C => Self::EndCollection,
            other => Self::Unknown(other),
        }
    }
}

/// Global item tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalTag {
    UsagePage,
    LogicalMinimum,
    LogicalMaximum,
    PhysicalMinimum,
    PhysicalMaximum,
    UnitExponent,
    Unit,
    ReportSize,
    ReportId,
    ReportCount,
    Push,
    Pop,
    Unknown(u8),
}

impl GlobalTag {
    pub fn from_tag(tag: u8) -> Self {
        match tag {
            0x00 => Self::UsagePage,
            0x01 => Self::LogicalMinimum,
            0x02 => Self::LogicalMaximum,
            0x03 => Self::PhysicalMinimum,
            0x04 => Self::PhysicalMaximum,
            0x05 => Self::UnitExponent,
            0x06 => Self::Unit,
            0x07 => Self::ReportSize,
            0x08 => Self::ReportId,
            0x09 => Self::ReportCount,
            0x0A => Self::Push,
            0x0B => Self::Pop,
            other => Self::Unknown(other),
        }
    }
}

/// A parsed report descriptor item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportItem {
    /// The item type (Main, Global, Local, Reserved).
    pub item_type: ItemType,
    /// Raw tag value (bits [7:4] of prefix).
    pub tag: u8,
    /// Size of data in bytes (0, 1, 2, or 4).
    pub size: u8,
    /// Item data payload.
    pub data: Vec<u8>,
}

/// Parse a HID report descriptor byte stream into a list of items.
///
/// Each short item has a 1-byte prefix:
///   - bits [1:0] = size (0, 1, 2, or 3 meaning 4 bytes)
///   - bits [3:2] = type (0=Main, 1=Global, 2=Local, 3=Reserved)
///   - bits [7:4] = tag
pub struct ReportDescriptor;

impl ReportDescriptor {
    pub fn parse(data: &[u8]) -> Result<Vec<ReportItem>, ParseError> {
        let mut items = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let prefix = data[offset];

            // Long item marker
            if prefix == 0xFE {
                return Err(ParseError::LongItemNotSupported);
            }

            let size_bits = prefix & 0x03;
            let data_size: u8 = if size_bits == 3 { 4 } else { size_bits };
            let item_type = ItemType::from_bits((prefix >> 2) & 0x03);
            let tag = (prefix >> 4) & 0x0F;

            offset += 1;
            if offset + data_size as usize > data.len() {
                return Err(ParseError::UnexpectedEof);
            }

            let item_data =
                data[offset..offset + data_size as usize].to_vec();
            offset += data_size as usize;

            items.push(ReportItem {
                item_type,
                tag,
                size: data_size,
                data: item_data,
            });
        }

        Ok(items)
    }
}

/// BR/EDR HID profile plugin.
#[derive(Debug)]
pub struct HidProfile {
    pub state: HidState,
    pub protocol: HidProtocol,
    pub remote_addr: Option<BdAddr>,
    pub report_descriptor: Vec<u8>,
    pub vendor_id: u16,
    pub product_id: u16,
    pub version: u16,
    pub subclass: u8,
    pub country_code: u8,
    pub virtual_cable: bool,
    pub reconnect_initiate: bool,
    pub boot_device: bool,
}

impl HidProfile {
    pub fn new() -> Self {
        Self {
            state: HidState::default(),
            protocol: HidProtocol::default(),
            remote_addr: None,
            report_descriptor: Vec::new(),
            vendor_id: 0,
            product_id: 0,
            version: 0,
            subclass: 0,
            country_code: 0,
            virtual_cable: true,
            reconnect_initiate: true,
            boot_device: false,
        }
    }
}

impl Default for HidProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HoG — HID over GATT
// ---------------------------------------------------------------------------

/// HoG connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HogState {
    #[default]
    Disconnected,
    Discovering,
    Connected,
}

/// A GATT HID report reference.
#[derive(Debug, Clone)]
pub struct HogReportRef {
    pub id: u8,
    pub report_type: HidReportType,
    pub handle: u16,
    pub ccc_handle: u16,
}

/// HID over GATT profile plugin.
#[derive(Debug)]
pub struct HogProfile {
    pub state: HogState,
    pub protocol: HidProtocol,
    pub remote_addr: Option<BdAddr>,
    pub report_map: Vec<u8>,
    pub reports: Vec<HogReportRef>,
    pub hid_info_flags: u8,
    pub hid_info_country: u8,
    pub hid_info_version: u16,
}

impl HogProfile {
    pub fn new() -> Self {
        Self {
            state: HogState::default(),
            protocol: HidProtocol::default(),
            remote_addr: None,
            report_map: Vec::new(),
            reports: Vec::new(),
            hid_info_flags: 0,
            hid_info_country: 0,
            hid_info_version: 0x0111, // HID 1.11
        }
    }
}

impl Default for HogProfile {
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

    // ---- HID defaults (from test-hog.c initialization) ----

    #[test]
    fn test_hid_defaults() {
        let hid = HidProfile::new();
        assert_eq!(hid.state, HidState::Disconnected);
        assert_eq!(hid.protocol, HidProtocol::Report);
        assert!(hid.virtual_cable);
        assert!(hid.reconnect_initiate);
        assert!(!hid.boot_device);
        assert_eq!(hid.vendor_id, 0);
        assert_eq!(hid.product_id, 0);
        assert_eq!(hid.subclass, 0);
    }

    // ---- HID protocol modes ----

    #[test]
    fn test_hid_protocol_modes() {
        let mut hid = HidProfile::new();
        assert_eq!(hid.protocol, HidProtocol::Report);
        hid.protocol = HidProtocol::Boot;
        assert_eq!(hid.protocol, HidProtocol::Boot);
    }

    // ---- HID state transitions ----

    #[test]
    fn test_hid_states() {
        let mut hid = HidProfile::new();
        assert_eq!(hid.state, HidState::Disconnected);
        hid.state = HidState::ConnectingControl;
        assert_eq!(hid.state, HidState::ConnectingControl);
        hid.state = HidState::ConnectingInterrupt;
        assert_eq!(hid.state, HidState::ConnectingInterrupt);
        hid.state = HidState::Connected;
        assert_eq!(hid.state, HidState::Connected);
        hid.state = HidState::Disconnecting;
        assert_eq!(hid.state, HidState::Disconnecting);
    }

    // ---- HID report descriptor storage ----

    #[test]
    fn test_hid_report_descriptor() {
        let mut hid = HidProfile::new();
        assert!(hid.report_descriptor.is_empty());
        let desc = vec![0x05, 0x01, 0x09, 0x06, 0xA1, 0x01]; // Usage Page: Generic Desktop, Usage: Keyboard
        hid.report_descriptor = desc.clone();
        assert_eq!(hid.report_descriptor, desc);
    }

    // ---- HoG defaults (from test-hog.c) ----

    #[test]
    fn test_hog_defaults() {
        let hog = HogProfile::new();
        assert_eq!(hog.state, HogState::Disconnected);
        assert_eq!(hog.hid_info_version, 0x0111);
        assert!(hog.reports.is_empty());
        assert!(hog.report_map.is_empty());
        assert_eq!(hog.hid_info_flags, 0);
        assert_eq!(hog.hid_info_country, 0);
    }

    // ---- HoG state transitions ----

    #[test]
    fn test_hog_states() {
        let mut hog = HogProfile::new();
        hog.state = HogState::Discovering;
        assert_eq!(hog.state, HogState::Discovering);
        hog.state = HogState::Connected;
        assert_eq!(hog.state, HogState::Connected);
    }

    // ---- HoG report references ----

    #[test]
    fn test_hog_report_ref() {
        let mut hog = HogProfile::new();
        hog.reports.push(HogReportRef {
            id: 1,
            report_type: HidReportType::Input,
            handle: 0x0010,
            ccc_handle: 0x0011,
        });
        hog.reports.push(HogReportRef {
            id: 2,
            report_type: HidReportType::Output,
            handle: 0x0020,
            ccc_handle: 0x0021,
        });
        assert_eq!(hog.reports.len(), 2);
        assert_eq!(hog.reports[0].report_type, HidReportType::Input);
        assert_eq!(hog.reports[1].report_type, HidReportType::Output);
    }

    // ---- HoG report map storage (from test-hog.c) ----

    #[test]
    fn test_hog_report_map() {
        let mut hog = HogProfile::new();
        let map = vec![0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01, 0xA1, 0x00];
        hog.report_map = map.clone();
        assert_eq!(hog.report_map, map);
    }

    // ---- HID report types ----

    #[test]
    fn test_hid_report_types() {
        // Verify the enum variants exist and are distinct
        assert_ne!(HidReportType::Input as u8, HidReportType::Output as u8);
        assert_ne!(HidReportType::Output as u8, HidReportType::Feature as u8);
    }

    // ---- Report descriptor parsing ----

    #[test]
    fn test_parse_keyboard_descriptor() {
        // Minimal keyboard descriptor fragment:
        // Usage Page (Generic Desktop) = 0x05 0x01
        // Usage (Keyboard)             = 0x09 0x06
        // Collection (Application)     = 0xA1 0x01
        // End Collection               = 0xC0
        let desc: &[u8] = &[0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0xC0];
        let items = ReportDescriptor::parse(desc).unwrap();
        assert_eq!(items.len(), 4);

        // Usage Page: Global, tag=0, size=1, data=[0x01]
        assert_eq!(items[0].item_type, ItemType::Global);
        assert_eq!(GlobalTag::from_tag(items[0].tag), GlobalTag::UsagePage);
        assert_eq!(items[0].data, vec![0x01]);

        // Usage: Local, tag=0, size=1, data=[0x06]
        assert_eq!(items[1].item_type, ItemType::Local);
        assert_eq!(items[1].data, vec![0x06]);

        // Collection (Application): Main, tag=0x0A, size=1, data=[0x01]
        assert_eq!(items[2].item_type, ItemType::Main);
        assert_eq!(MainTag::from_tag(items[2].tag), MainTag::Collection);
        assert_eq!(items[2].data, vec![0x01]);

        // End Collection: Main, tag=0x0C, size=0
        assert_eq!(items[3].item_type, ItemType::Main);
        assert_eq!(MainTag::from_tag(items[3].tag), MainTag::EndCollection);
        assert!(items[3].data.is_empty());
    }

    #[test]
    fn test_parse_mouse_descriptor_fragment() {
        // Mouse descriptor fragment:
        // Usage Page (Generic Desktop)  = 0x05 0x01
        // Usage (Mouse)                 = 0x09 0x02
        // Collection (Application)      = 0xA1 0x01
        //   Usage (Pointer)             = 0x09 0x01
        //   Collection (Physical)       = 0xA1 0x00
        //     Usage Page (Buttons)      = 0x05 0x09
        //     Usage Minimum (1)         = 0x19 0x01
        //     Usage Maximum (3)         = 0x29 0x03
        //     Logical Minimum (0)       = 0x15 0x00
        //     Logical Maximum (1)       = 0x25 0x01
        //     Report Count (3)          = 0x95 0x03
        //     Report Size (1)           = 0x75 0x01
        //     Input (Data,Var,Abs)      = 0x81 0x02
        //   End Collection              = 0xC0
        // End Collection                = 0xC0
        let desc: &[u8] = &[
            0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01, 0xA1, 0x00,
            0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01,
            0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0xC0, 0xC0,
        ];
        let items = ReportDescriptor::parse(desc).unwrap();
        assert_eq!(items.len(), 15);

        // First is Usage Page (Generic Desktop)
        assert_eq!(items[0].item_type, ItemType::Global);
        assert_eq!(items[0].data, vec![0x01]);

        // Find the Input item (tag 0x08 for Main)
        let input_item = items
            .iter()
            .find(|i| i.item_type == ItemType::Main && MainTag::from_tag(i.tag) == MainTag::Input)
            .unwrap();
        assert_eq!(input_item.data, vec![0x02]); // Data, Variable, Absolute
    }

    #[test]
    fn test_parse_empty_descriptor() {
        let items = ReportDescriptor::parse(&[]).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_parse_truncated_descriptor() {
        // Prefix says 1 byte of data, but no data follows
        let desc: &[u8] = &[0x05];
        let result = ReportDescriptor::parse(desc);
        assert_eq!(result, Err(ParseError::UnexpectedEof));
    }
}
