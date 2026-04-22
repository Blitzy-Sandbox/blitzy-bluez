// Bluetooth UUID normalization and lookup facilities.
//
// Complete Rust rewrite of BlueZ's UUID utilities from src/shared/util.c
// (lines 687-2142). Provides UUID16/UUID32/UUID128 conversion, lookup tables
// for ~888 UUID16 entries, ~49 UUID128 entries, ~342 appearance entries,
// and string-based UUID resolution.

use std::fmt;
use std::str::FromStr;

use super::endian::{get_le16, get_le32};

// Bluetooth SIG UUID base constant (standard Bluetooth base UUID).
pub const BT_UUID_BASE: &str = "00000000-0000-1000-8000-00805f9b34fb";

// Suffix portion of the Bluetooth SIG base UUID (bytes 5-16 in string form).
pub const BT_UUID_BASE_SUFFIX: &str = "-0000-1000-8000-00805f9b34fb";

// Well-known Bluetooth profile UUID constants.
pub const HSP_AG_UUID: &str = "00001112-0000-1000-8000-00805f9b34fb";
pub const HFP_AG_UUID: &str = "0000111f-0000-1000-8000-00805f9b34fb";
pub const A2DP_SOURCE_UUID: &str = "0000110a-0000-1000-8000-00805f9b34fb";
pub const A2DP_SINK_UUID: &str = "0000110b-0000-1000-8000-00805f9b34fb";
pub const AVRCP_TARGET_UUID: &str = "0000110c-0000-1000-8000-00805f9b34fb";
pub const AVRCP_REMOTE_UUID: &str = "0000110e-0000-1000-8000-00805f9b34fb";
pub const HFP_HS_UUID: &str = "0000111e-0000-1000-8000-00805f9b34fb";
pub const HSP_HS_UUID: &str = "00001108-0000-1000-8000-00805f9b34fb";
pub const HID_UUID: &str = "00001124-0000-1000-8000-00805f9b34fb";
pub const GATT_UUID: &str = "00001801-0000-1000-8000-00805f9b34fb";

// Bluetooth SIG base UUID as a 16-byte array in BlueZ wire format (little-endian).
// This is the base UUID with the 32-bit field at bytes 12..16 set to zero.
const BT_UUID_BASE_BYTES: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Represents a Bluetooth UUID in one of three standard sizes.
///
/// UUIDs can be 16-bit (assigned numbers), 32-bit (extended), or full 128-bit.
/// The 16-bit and 32-bit forms are shorthand for UUIDs that share the Bluetooth
/// SIG base UUID, with the short value inserted into the most significant 16 or 32 bits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BtUuid {
    /// 16-bit UUID (Bluetooth SIG assigned number).
    Uuid16(u16),
    /// 32-bit UUID (extended Bluetooth SIG number).
    Uuid32(u32),
    /// Full 128-bit UUID (16 bytes in BlueZ wire-format byte order).
    Uuid128([u8; 16]),
}

impl BtUuid {
    /// Creates a BtUuid from a 16-bit value.
    pub fn from_u16(val: u16) -> Self {
        BtUuid::Uuid16(val)
    }

    /// Creates a BtUuid from a 32-bit value.
    pub fn from_u32(val: u32) -> Self {
        BtUuid::Uuid32(val)
    }

    /// Creates a BtUuid from a 16-byte array in BlueZ wire format.
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        BtUuid::Uuid128(*bytes)
    }

    /// Expands this UUID to a full 128-bit byte array using the Bluetooth SIG base.
    ///
    /// For Uuid16 and Uuid32, the value is inserted into the Bluetooth SIG base UUID
    /// at the appropriate position (bytes 12-15 in BlueZ wire format).
    pub fn to_uuid128_bytes(&self) -> [u8; 16] {
        match self {
            BtUuid::Uuid16(val) => {
                let mut bytes = BT_UUID_BASE_BYTES;
                bytes[12] = (*val & 0xFF) as u8;
                bytes[13] = ((*val >> 8) & 0xFF) as u8;
                bytes
            }
            BtUuid::Uuid32(val) => {
                let mut bytes = BT_UUID_BASE_BYTES;
                bytes[12] = (*val & 0xFF) as u8;
                bytes[13] = ((*val >> 8) & 0xFF) as u8;
                bytes[14] = ((*val >> 16) & 0xFF) as u8;
                bytes[15] = ((*val >> 24) & 0xFF) as u8;
                bytes
            }
            BtUuid::Uuid128(bytes) => *bytes,
        }
    }

    /// Returns true if this UUID uses the standard Bluetooth SIG base.
    ///
    /// A UUID is considered a Bluetooth SIG UUID if its base portion
    /// (all bytes except the 32-bit value field) matches the standard base.
    pub fn is_bluetooth_sig(&self) -> bool {
        match self {
            BtUuid::Uuid16(_) | BtUuid::Uuid32(_) => true,
            BtUuid::Uuid128(bytes) => {
                // Check that the first 12 bytes match the base
                bytes[0..12] == BT_UUID_BASE_BYTES[0..12]
            }
        }
    }
}

impl fmt::Display for BtUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_uuid128_bytes();
        let s = format_uuid128_bytes(&bytes);
        f.write_str(&s)
    }
}

/// Error type for UUID parsing failures.
#[derive(Debug, Clone)]
pub struct ParseUuidError;

impl fmt::Display for ParseUuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid UUID string")
    }
}

impl FromStr for BtUuid {
    type Err = ParseUuidError;

    /// Parses a UUID from a string representation.
    ///
    /// Accepts the following formats:
    /// - "0x1800" or "0X1800" -- hexadecimal with prefix
    /// - "1800" -- plain hexadecimal (4 digits)
    /// - "6144" -- decimal integer
    /// - "00001800-0000-1000-8000-00805f9b34fb" -- full 128-bit UUID string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bt_uuid_str(s).ok_or(ParseUuidError)
    }
}

/// Internal parser for BtUuid from string. Used by both `BtUuid::from_str()`
/// and the `FromStr` trait implementation.
fn parse_bt_uuid_str(s: &str) -> Option<BtUuid> {
    let trimmed = s.trim();
    if trimmed.len() == 36 && trimmed.as_bytes()[8] == b'-' {
        // Full 128-bit UUID string
        let bytes = uuid_str_to_bytes(trimmed)?;
        Some(BtUuid::Uuid128(bytes))
    } else {
        // Try parsing as integer (hex with 0x prefix or decimal)
        let val = parse_uuid_int(trimmed)?;
        if val > u32::from(u16::MAX) {
            Some(BtUuid::Uuid32(val))
        } else if val > 0 {
            Some(BtUuid::Uuid16(val as u16))
        } else {
            Some(BtUuid::Uuid16(0))
        }
    }
}

/// Parses a UUID integer from a string, supporting 0x prefix and decimal.
fn parse_uuid_int(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        u32::from_str_radix(&s[2..], 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() <= 8 {
        // Try hex first for short strings that look like hex
        // But C's strtol with base 0 treats leading 0 as octal and pure digits as decimal
        // Match C behavior: pure digits = decimal, mixed = try hex
        if s.chars().all(|c| c.is_ascii_digit()) {
            s.parse::<u32>().ok()
        } else {
            u32::from_str_radix(s, 16).ok()
        }
    } else {
        s.parse::<u32>().ok()
    }
}

/// Converts a 128-bit UUID string to a 16-byte array in BlueZ wire format.
fn uuid_str_to_bytes(s: &str) -> Option<[u8; 16]> {
    // Expected format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    if s.len() != 36 {
        return None;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let time_low = u32::from_str_radix(parts[0], 16).ok()?;
    let time_mid = u16::from_str_radix(parts[1], 16).ok()?;
    let time_hi = u16::from_str_radix(parts[2], 16).ok()?;
    let clock_seq = u16::from_str_radix(parts[3], 16).ok()?;
    // Node is 6 bytes (48 bits)
    if parts[4].len() != 12 {
        return None;
    }
    let node_hi = u32::from_str_radix(&parts[4][0..8], 16).ok()?;
    let node_lo = u16::from_str_radix(&parts[4][8..12], 16).ok()?;

    // BlueZ wire format (little-endian):
    // bytes[0..2] = node_lo (LE16)
    // bytes[2..6] = node_hi (LE32)
    // bytes[6..8] = clock_seq (LE16)
    // bytes[8..10] = time_hi (LE16)
    // bytes[10..12] = time_mid (LE16)
    // bytes[12..16] = time_low (LE32)
    let mut bytes = [0u8; 16];
    bytes[0] = (node_lo & 0xFF) as u8;
    bytes[1] = ((node_lo >> 8) & 0xFF) as u8;
    bytes[2] = (node_hi & 0xFF) as u8;
    bytes[3] = ((node_hi >> 8) & 0xFF) as u8;
    bytes[4] = ((node_hi >> 16) & 0xFF) as u8;
    bytes[5] = ((node_hi >> 24) & 0xFF) as u8;
    bytes[6] = (clock_seq & 0xFF) as u8;
    bytes[7] = ((clock_seq >> 8) & 0xFF) as u8;
    bytes[8] = (time_hi & 0xFF) as u8;
    bytes[9] = ((time_hi >> 8) & 0xFF) as u8;
    bytes[10] = (time_mid & 0xFF) as u8;
    bytes[11] = ((time_mid >> 8) & 0xFF) as u8;
    bytes[12] = (time_low & 0xFF) as u8;
    bytes[13] = ((time_low >> 8) & 0xFF) as u8;
    bytes[14] = ((time_low >> 16) & 0xFF) as u8;
    bytes[15] = ((time_low >> 24) & 0xFF) as u8;
    Some(bytes)
}

/// Formats a 16-byte UUID (BlueZ wire format) as a standard UUID string.
fn format_uuid128_bytes(uuid: &[u8; 16]) -> String {
    // BlueZ byte layout for UUID string construction:
    // get_le32(&uuid[12]) -> time_low
    // get_le16(&uuid[10]) -> time_mid
    // get_le16(&uuid[8])  -> time_hi
    // get_le16(&uuid[6])  -> clock_seq
    // get_le32(&uuid[2])  -> node_hi
    // get_le16(&uuid[0])  -> node_lo
    let time_low = get_le32(&uuid[12..]);
    let time_mid = get_le16(&uuid[10..]);
    let time_hi = get_le16(&uuid[8..]);
    let clock_seq = get_le16(&uuid[6..]);
    let node_hi = get_le32(&uuid[2..]);
    let node_lo = get_le16(&uuid[0..]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:08x}{:04x}",
        time_low, time_mid, time_hi, clock_seq, node_hi, node_lo
    )
}

/// Entry in the UUID16 lookup table.
struct Uuid16Entry {
    uuid: u16,
    name: &'static str,
}

/// Lookup table for Bluetooth SIG assigned UUID16 values.
/// Contains ~888 entries matching the C uuid16_table[] from util.c.
static UUID16_TABLE: &[Uuid16Entry] = &[
    Uuid16Entry { uuid: 0x0001, name: "SDP" },
    Uuid16Entry { uuid: 0x0003, name: "RFCOMM" },
    Uuid16Entry { uuid: 0x0005, name: "TCS-BIN" },
    Uuid16Entry { uuid: 0x0007, name: "ATT" },
    Uuid16Entry { uuid: 0x0008, name: "OBEX" },
    Uuid16Entry { uuid: 0x000f, name: "BNEP" },
    Uuid16Entry { uuid: 0x0010, name: "UPNP" },
    Uuid16Entry { uuid: 0x0011, name: "HIDP" },
    Uuid16Entry { uuid: 0x0012, name: "Hardcopy Control Channel" },
    Uuid16Entry { uuid: 0x0014, name: "Hardcopy Data Channel" },
    Uuid16Entry { uuid: 0x0016, name: "Hardcopy Notification" },
    Uuid16Entry { uuid: 0x0017, name: "AVCTP" },
    Uuid16Entry { uuid: 0x0019, name: "AVDTP" },
    Uuid16Entry { uuid: 0x001b, name: "CMTP" },
    Uuid16Entry { uuid: 0x001e, name: "MCAP Control Channel" },
    Uuid16Entry { uuid: 0x001f, name: "MCAP Data Channel" },
    Uuid16Entry { uuid: 0x0100, name: "L2CAP" },
    Uuid16Entry { uuid: 0x1000, name: "Service Discovery Server Service Class" },
    Uuid16Entry { uuid: 0x1001, name: "Browse Group Descriptor Service Class" },
    Uuid16Entry { uuid: 0x1002, name: "Public Browse Root" },
    Uuid16Entry { uuid: 0x1101, name: "Serial Port" },
    Uuid16Entry { uuid: 0x1102, name: "LAN Access Using PPP" },
    Uuid16Entry { uuid: 0x1103, name: "Dialup Networking" },
    Uuid16Entry { uuid: 0x1104, name: "IrMC Sync" },
    Uuid16Entry { uuid: 0x1105, name: "OBEX Object Push" },
    Uuid16Entry { uuid: 0x1106, name: "OBEX File Transfer" },
    Uuid16Entry { uuid: 0x1107, name: "IrMC Sync Command" },
    Uuid16Entry { uuid: 0x1108, name: "Headset" },
    Uuid16Entry { uuid: 0x1109, name: "Cordless Telephony" },
    Uuid16Entry { uuid: 0x110a, name: "Audio Source" },
    Uuid16Entry { uuid: 0x110b, name: "Audio Sink" },
    Uuid16Entry { uuid: 0x110c, name: "A/V Remote Control Target" },
    Uuid16Entry { uuid: 0x110d, name: "Advanced Audio Distribution" },
    Uuid16Entry { uuid: 0x110e, name: "A/V Remote Control" },
    Uuid16Entry { uuid: 0x110f, name: "A/V Remote Control Controller" },
    Uuid16Entry { uuid: 0x1110, name: "Intercom" },
    Uuid16Entry { uuid: 0x1111, name: "Fax" },
    Uuid16Entry { uuid: 0x1112, name: "Headset AG" },
    Uuid16Entry { uuid: 0x1113, name: "WAP" },
    Uuid16Entry { uuid: 0x1114, name: "WAP Client" },
    Uuid16Entry { uuid: 0x1115, name: "PANU" },
    Uuid16Entry { uuid: 0x1116, name: "NAP" },
    Uuid16Entry { uuid: 0x1117, name: "GN" },
    Uuid16Entry { uuid: 0x1118, name: "Direct Printing" },
    Uuid16Entry { uuid: 0x1119, name: "Reference Printing" },
    Uuid16Entry { uuid: 0x111a, name: "Basic Imaging Profile" },
    Uuid16Entry { uuid: 0x111b, name: "Imaging Responder" },
    Uuid16Entry { uuid: 0x111c, name: "Imaging Automatic Archive" },
    Uuid16Entry { uuid: 0x111d, name: "Imaging Referenced Objects" },
    Uuid16Entry { uuid: 0x111e, name: "Handsfree" },
    Uuid16Entry { uuid: 0x111f, name: "Handsfree Audio Gateway" },
    Uuid16Entry { uuid: 0x1120, name: "Direct Printing Reference Objects Service" },
    Uuid16Entry { uuid: 0x1121, name: "Reflected UI" },
    Uuid16Entry { uuid: 0x1122, name: "Basic Printing" },
    Uuid16Entry { uuid: 0x1123, name: "Printing Status" },
    Uuid16Entry { uuid: 0x1124, name: "Human Interface Device Service" },
    Uuid16Entry { uuid: 0x1125, name: "Hardcopy Cable Replacement" },
    Uuid16Entry { uuid: 0x1126, name: "HCR Print" },
    Uuid16Entry { uuid: 0x1127, name: "HCR Scan" },
    Uuid16Entry { uuid: 0x1128, name: "Common ISDN Access" },
    Uuid16Entry { uuid: 0x112d, name: "SIM Access" },
    Uuid16Entry { uuid: 0x112e, name: "Phonebook Access Client" },
    Uuid16Entry { uuid: 0x112f, name: "Phonebook Access Server" },
    Uuid16Entry { uuid: 0x1130, name: "Phonebook Access" },
    Uuid16Entry { uuid: 0x1131, name: "Headset HS" },
    Uuid16Entry { uuid: 0x1132, name: "Message Access Server" },
    Uuid16Entry { uuid: 0x1133, name: "Message Notification Server" },
    Uuid16Entry { uuid: 0x1134, name: "Message Access Profile" },
    Uuid16Entry { uuid: 0x1135, name: "GNSS" },
    Uuid16Entry { uuid: 0x1136, name: "GNSS Server" },
    Uuid16Entry { uuid: 0x1137, name: "3D Display" },
    Uuid16Entry { uuid: 0x1138, name: "3D Glasses" },
    Uuid16Entry { uuid: 0x1139, name: "3D Synchronization" },
    Uuid16Entry { uuid: 0x113a, name: "MPS Profile" },
    Uuid16Entry { uuid: 0x113b, name: "MPS Service" },
    Uuid16Entry { uuid: 0x1200, name: "PnP Information" },
    Uuid16Entry { uuid: 0x1201, name: "Generic Networking" },
    Uuid16Entry { uuid: 0x1202, name: "Generic File Transfer" },
    Uuid16Entry { uuid: 0x1203, name: "Generic Audio" },
    Uuid16Entry { uuid: 0x1204, name: "Generic Telephony" },
    Uuid16Entry { uuid: 0x1205, name: "UPNP Service" },
    Uuid16Entry { uuid: 0x1206, name: "UPNP IP Service" },
    Uuid16Entry { uuid: 0x1300, name: "UPNP IP PAN" },
    Uuid16Entry { uuid: 0x1301, name: "UPNP IP LAP" },
    Uuid16Entry { uuid: 0x1302, name: "UPNP IP L2CAP" },
    Uuid16Entry { uuid: 0x1303, name: "Video Source" },
    Uuid16Entry { uuid: 0x1304, name: "Video Sink" },
    Uuid16Entry { uuid: 0x1305, name: "Video Distribution" },
    Uuid16Entry { uuid: 0x1400, name: "HDP" },
    Uuid16Entry { uuid: 0x1401, name: "HDP Source" },
    Uuid16Entry { uuid: 0x1402, name: "HDP Sink" },
    Uuid16Entry { uuid: 0x1800, name: "Generic Access Profile" },
    Uuid16Entry { uuid: 0x1801, name: "Generic Attribute Profile" },
    Uuid16Entry { uuid: 0x1802, name: "Immediate Alert" },
    Uuid16Entry { uuid: 0x1803, name: "Link Loss" },
    Uuid16Entry { uuid: 0x1804, name: "Tx Power" },
    Uuid16Entry { uuid: 0x1805, name: "Current Time Service" },
    Uuid16Entry { uuid: 0x1806, name: "Reference Time Update Service" },
    Uuid16Entry { uuid: 0x1807, name: "Next DST Change Service" },
    Uuid16Entry { uuid: 0x1808, name: "Glucose" },
    Uuid16Entry { uuid: 0x1809, name: "Health Thermometer" },
    Uuid16Entry { uuid: 0x180a, name: "Device Information" },
    Uuid16Entry { uuid: 0x180d, name: "Heart Rate" },
    Uuid16Entry { uuid: 0x180e, name: "Phone Alert Status Service" },
    Uuid16Entry { uuid: 0x180f, name: "Battery Service" },
    Uuid16Entry { uuid: 0x1810, name: "Blood Pressure" },
    Uuid16Entry { uuid: 0x1811, name: "Alert Notification Service" },
    Uuid16Entry { uuid: 0x1812, name: "Human Interface Device" },
    Uuid16Entry { uuid: 0x1813, name: "Scan Parameters" },
    Uuid16Entry { uuid: 0x1814, name: "Running Speed and Cadence" },
    Uuid16Entry { uuid: 0x1815, name: "Automation IO" },
    Uuid16Entry { uuid: 0x1816, name: "Cycling Speed and Cadence" },
    Uuid16Entry { uuid: 0x1818, name: "Cycling Power" },
    Uuid16Entry { uuid: 0x1819, name: "Location and Navigation" },
    Uuid16Entry { uuid: 0x181a, name: "Environmental Sensing" },
    Uuid16Entry { uuid: 0x181b, name: "Body Composition" },
    Uuid16Entry { uuid: 0x181c, name: "User Data" },
    Uuid16Entry { uuid: 0x181d, name: "Weight Scale" },
    Uuid16Entry { uuid: 0x181e, name: "Bond Management" },
    Uuid16Entry { uuid: 0x181f, name: "Continuous Glucose Monitoring" },
    Uuid16Entry { uuid: 0x1820, name: "Internet Protocol Support" },
    Uuid16Entry { uuid: 0x1821, name: "Indoor Positioning" },
    Uuid16Entry { uuid: 0x1822, name: "Pulse Oximeter" },
    Uuid16Entry { uuid: 0x1823, name: "HTTP Proxy" },
    Uuid16Entry { uuid: 0x1824, name: "Transport Discovery" },
    Uuid16Entry { uuid: 0x1825, name: "Object Transfer" },
    Uuid16Entry { uuid: 0x1826, name: "Fitness Machine" },
    Uuid16Entry { uuid: 0x1827, name: "Mesh Provisioning" },
    Uuid16Entry { uuid: 0x1828, name: "Mesh Proxy" },
    Uuid16Entry { uuid: 0x1843, name: "Audio Input Control" },
    Uuid16Entry { uuid: 0x1844, name: "Volume Control" },
    Uuid16Entry { uuid: 0x1845, name: "Volume Offset Control" },
    Uuid16Entry { uuid: 0x1846, name: "Coordinated Set Identification" },
    Uuid16Entry { uuid: 0x1848, name: "Media Control" },
    Uuid16Entry { uuid: 0x1849, name: "Generic Media Control" },
    Uuid16Entry { uuid: 0x184b, name: "Telephony Bearer" },
    Uuid16Entry { uuid: 0x184c, name: "Generic Telephony Bearer" },
    Uuid16Entry { uuid: 0x184d, name: "Microphone Control" },
    Uuid16Entry { uuid: 0x184e, name: "Audio Stream Control" },
    Uuid16Entry { uuid: 0x184f, name: "Broadcast Audio Scan" },
    Uuid16Entry { uuid: 0x1850, name: "Published Audio Capabilities" },
    Uuid16Entry { uuid: 0x1851, name: "Basic Audio Announcement" },
    Uuid16Entry { uuid: 0x1852, name: "Broadcast Audio Announcement" },
    Uuid16Entry { uuid: 0x1853, name: "Common Audio" },
    Uuid16Entry { uuid: 0x1854, name: "Hearing Aid" },
    Uuid16Entry { uuid: 0x1855, name: "Telephony and Media Audio" },
    Uuid16Entry { uuid: 0x1856, name: "Public Broadcast Announcement" },
    Uuid16Entry { uuid: 0x1858, name: "Gaming Audio" },
    Uuid16Entry { uuid: 0x185b, name: "Ranging Service" },
    Uuid16Entry { uuid: 0x2800, name: "Primary Service" },
    Uuid16Entry { uuid: 0x2801, name: "Secondary Service" },
    Uuid16Entry { uuid: 0x2802, name: "Include" },
    Uuid16Entry { uuid: 0x2803, name: "Characteristic" },
    Uuid16Entry { uuid: 0x2900, name: "Characteristic Extended Properties" },
    Uuid16Entry { uuid: 0x2901, name: "Characteristic User Description" },
    Uuid16Entry { uuid: 0x2902, name: "Client Characteristic Configuration" },
    Uuid16Entry { uuid: 0x2903, name: "Server Characteristic Configuration" },
    Uuid16Entry { uuid: 0x2904, name: "Characteristic Format" },
    Uuid16Entry { uuid: 0x2905, name: "Characteristic Aggregate Format" },
    Uuid16Entry { uuid: 0x2906, name: "Valid Range" },
    Uuid16Entry { uuid: 0x2907, name: "External Report Reference" },
    Uuid16Entry { uuid: 0x2908, name: "Report Reference" },
    Uuid16Entry { uuid: 0x2909, name: "Number of Digitals" },
    Uuid16Entry { uuid: 0x290a, name: "Value Trigger Setting" },
    Uuid16Entry { uuid: 0x290b, name: "Environmental Sensing Configuration" },
    Uuid16Entry { uuid: 0x290c, name: "Environmental Sensing Measurement" },
    Uuid16Entry { uuid: 0x290d, name: "Environmental Sensing Trigger Setting" },
    Uuid16Entry { uuid: 0x290e, name: "Time Trigger Setting" },
    Uuid16Entry { uuid: 0x2a00, name: "Device Name" },
    Uuid16Entry { uuid: 0x2a01, name: "Appearance" },
    Uuid16Entry { uuid: 0x2a02, name: "Peripheral Privacy Flag" },
    Uuid16Entry { uuid: 0x2a03, name: "Reconnection Address" },
    Uuid16Entry { uuid: 0x2a04, name: "Peripheral Preferred Connection Parameters" },
    Uuid16Entry { uuid: 0x2a05, name: "Service Changed" },
    Uuid16Entry { uuid: 0x2a06, name: "Alert Level" },
    Uuid16Entry { uuid: 0x2a07, name: "Tx Power Level" },
    Uuid16Entry { uuid: 0x2a08, name: "Date Time" },
    Uuid16Entry { uuid: 0x2a09, name: "Day of Week" },
    Uuid16Entry { uuid: 0x2a0a, name: "Day Date Time" },
    Uuid16Entry { uuid: 0x2a0c, name: "Exact Time 256" },
    Uuid16Entry { uuid: 0x2a0d, name: "DST Offset" },
    Uuid16Entry { uuid: 0x2a0e, name: "Time Zone" },
    Uuid16Entry { uuid: 0x2a0f, name: "Local Time Information" },
    Uuid16Entry { uuid: 0x2a11, name: "Time with DST" },
    Uuid16Entry { uuid: 0x2a12, name: "Time Accuracy" },
    Uuid16Entry { uuid: 0x2a13, name: "Time Source" },
    Uuid16Entry { uuid: 0x2a14, name: "Reference Time Information" },
    Uuid16Entry { uuid: 0x2a16, name: "Time Update Control Point" },
    Uuid16Entry { uuid: 0x2a17, name: "Time Update State" },
    Uuid16Entry { uuid: 0x2a18, name: "Glucose Measurement" },
    Uuid16Entry { uuid: 0x2a19, name: "Battery Level" },
    Uuid16Entry { uuid: 0x2a1c, name: "Temperature Measurement" },
    Uuid16Entry { uuid: 0x2a1d, name: "Temperature Type" },
    Uuid16Entry { uuid: 0x2a1e, name: "Intermediate Temperature" },
    Uuid16Entry { uuid: 0x2a21, name: "Measurement Interval" },
    Uuid16Entry { uuid: 0x2a22, name: "Boot Keyboard Input Report" },
    Uuid16Entry { uuid: 0x2a23, name: "System ID" },
    Uuid16Entry { uuid: 0x2a24, name: "Model Number String" },
    Uuid16Entry { uuid: 0x2a25, name: "Serial Number String" },
    Uuid16Entry { uuid: 0x2a26, name: "Firmware Revision String" },
    Uuid16Entry { uuid: 0x2a27, name: "Hardware Revision String" },
    Uuid16Entry { uuid: 0x2a28, name: "Software Revision String" },
    Uuid16Entry { uuid: 0x2a29, name: "Manufacturer Name String" },
    Uuid16Entry { uuid: 0x2a2a, name: "IEEE 11073-20601 Regulatory Cert. Data List" },
    Uuid16Entry { uuid: 0x2a2b, name: "Current Time" },
    Uuid16Entry { uuid: 0x2a2c, name: "Magnetic Declination" },
    Uuid16Entry { uuid: 0x2a31, name: "Scan Refresh" },
    Uuid16Entry { uuid: 0x2a32, name: "Boot Keyboard Output Report" },
    Uuid16Entry { uuid: 0x2a33, name: "Boot Mouse Input Report" },
    Uuid16Entry { uuid: 0x2a34, name: "Glucose Measurement Context" },
    Uuid16Entry { uuid: 0x2a35, name: "Blood Pressure Measurement" },
    Uuid16Entry { uuid: 0x2a36, name: "Intermediate Cuff Pressure" },
    Uuid16Entry { uuid: 0x2a37, name: "Heart Rate Measurement" },
    Uuid16Entry { uuid: 0x2a38, name: "Body Sensor Location" },
    Uuid16Entry { uuid: 0x2a39, name: "Heart Rate Control Point" },
    Uuid16Entry { uuid: 0x2a3f, name: "Alert Status" },
    Uuid16Entry { uuid: 0x2a40, name: "Ringer Control Point" },
    Uuid16Entry { uuid: 0x2a41, name: "Ringer Setting" },
    Uuid16Entry { uuid: 0x2a42, name: "Alert Category ID Bit Mask" },
    Uuid16Entry { uuid: 0x2a43, name: "Alert Category ID" },
    Uuid16Entry { uuid: 0x2a44, name: "Alert Notification Control Point" },
    Uuid16Entry { uuid: 0x2a45, name: "Unread Alert Status" },
    Uuid16Entry { uuid: 0x2a46, name: "New Alert" },
    Uuid16Entry { uuid: 0x2a47, name: "Supported New Alert Category" },
    Uuid16Entry { uuid: 0x2a48, name: "Supported Unread Alert Category" },
    Uuid16Entry { uuid: 0x2a49, name: "Blood Pressure Feature" },
    Uuid16Entry { uuid: 0x2a4a, name: "HID Information" },
    Uuid16Entry { uuid: 0x2a4b, name: "Report Map" },
    Uuid16Entry { uuid: 0x2a4c, name: "HID Control Point" },
    Uuid16Entry { uuid: 0x2a4d, name: "Report" },
    Uuid16Entry { uuid: 0x2a4e, name: "Protocol Mode" },
    Uuid16Entry { uuid: 0x2a4f, name: "Scan Interval Window" },
    Uuid16Entry { uuid: 0x2a50, name: "PnP ID" },
    Uuid16Entry { uuid: 0x2a51, name: "Glucose Feature" },
    Uuid16Entry { uuid: 0x2a52, name: "Record Access Control Point" },
    Uuid16Entry { uuid: 0x2a53, name: "RSC Measurement" },
    Uuid16Entry { uuid: 0x2a54, name: "RSC Feature" },
    Uuid16Entry { uuid: 0x2a55, name: "SC Control Point" },
    Uuid16Entry { uuid: 0x2a56, name: "Digital" },
    Uuid16Entry { uuid: 0x2a58, name: "Analog" },
    Uuid16Entry { uuid: 0x2a5a, name: "Aggregate" },
    Uuid16Entry { uuid: 0x2a5b, name: "CSC Measurement" },
    Uuid16Entry { uuid: 0x2a5c, name: "CSC Feature" },
    Uuid16Entry { uuid: 0x2a5d, name: "Sensor Location" },
    Uuid16Entry { uuid: 0x2a63, name: "Cycling Power Measurement" },
    Uuid16Entry { uuid: 0x2a64, name: "Cycling Power Vector" },
    Uuid16Entry { uuid: 0x2a65, name: "Cycling Power Feature" },
    Uuid16Entry { uuid: 0x2a66, name: "Cycling Power Control Point" },
    Uuid16Entry { uuid: 0x2a67, name: "Location and Speed" },
    Uuid16Entry { uuid: 0x2a68, name: "Navigation" },
    Uuid16Entry { uuid: 0x2a69, name: "Position Quality" },
    Uuid16Entry { uuid: 0x2a6a, name: "LN Feature" },
    Uuid16Entry { uuid: 0x2a6b, name: "LN Control Point" },
    Uuid16Entry { uuid: 0x2a6c, name: "Elevation" },
    Uuid16Entry { uuid: 0x2a6d, name: "Pressure" },
    Uuid16Entry { uuid: 0x2a6e, name: "Temperature" },
    Uuid16Entry { uuid: 0x2a6f, name: "Humidity" },
    Uuid16Entry { uuid: 0x2a70, name: "True Wind Speed" },
    Uuid16Entry { uuid: 0x2a71, name: "True Wind Direction" },
    Uuid16Entry { uuid: 0x2a72, name: "Apparent Wind Speed" },
    Uuid16Entry { uuid: 0x2a73, name: "Apparent Wind Direction" },
    Uuid16Entry { uuid: 0x2a74, name: "Gust Factor" },
    Uuid16Entry { uuid: 0x2a75, name: "Pollen Concentration" },
    Uuid16Entry { uuid: 0x2a76, name: "UV Index" },
    Uuid16Entry { uuid: 0x2a77, name: "Irradiance" },
    Uuid16Entry { uuid: 0x2a78, name: "Rainfall" },
    Uuid16Entry { uuid: 0x2a79, name: "Wind Chill" },
    Uuid16Entry { uuid: 0x2a7a, name: "Heat Index" },
    Uuid16Entry { uuid: 0x2a7b, name: "Dew Point" },
    Uuid16Entry { uuid: 0x2a7c, name: "Trend" },
    Uuid16Entry { uuid: 0x2a7d, name: "Descriptor Value Changed" },
    Uuid16Entry { uuid: 0x2a7e, name: "Aerobic Heart Rate Lower Limit" },
    Uuid16Entry { uuid: 0x2a7f, name: "Aerobic Threshold" },
    Uuid16Entry { uuid: 0x2a80, name: "Age" },
    Uuid16Entry { uuid: 0x2a81, name: "Anaerobic Heart Rate Lower Limit" },
    Uuid16Entry { uuid: 0x2a82, name: "Anaerobic Heart Rate Upper Limit" },
    Uuid16Entry { uuid: 0x2a83, name: "Anaerobic Threshold" },
    Uuid16Entry { uuid: 0x2a84, name: "Aerobic Heart Rate Upper Limit" },
    Uuid16Entry { uuid: 0x2a85, name: "Date of Birth" },
    Uuid16Entry { uuid: 0x2a86, name: "Date of Threshold Assessment" },
    Uuid16Entry { uuid: 0x2a87, name: "Email Address" },
    Uuid16Entry { uuid: 0x2a88, name: "Fat Burn Heart Rate Lower Limit" },
    Uuid16Entry { uuid: 0x2a89, name: "Fat Burn Heart Rate Upper Limit" },
    Uuid16Entry { uuid: 0x2a8a, name: "First Name" },
    Uuid16Entry { uuid: 0x2a8b, name: "Five Zone Heart Rate Limits" },
    Uuid16Entry { uuid: 0x2a8c, name: "Gender" },
    Uuid16Entry { uuid: 0x2a8d, name: "Heart Rate Max" },
    Uuid16Entry { uuid: 0x2a8e, name: "Height" },
    Uuid16Entry { uuid: 0x2a8f, name: "Hip Circumference" },
    Uuid16Entry { uuid: 0x2a90, name: "Last Name" },
    Uuid16Entry { uuid: 0x2a91, name: "Maximum Recommended Heart Rate" },
    Uuid16Entry { uuid: 0x2a92, name: "Resting Heart Rate" },
    Uuid16Entry { uuid: 0x2a93, name: "Sport Type for Aerobic/Anaerobic Thresholds" },
    Uuid16Entry { uuid: 0x2a94, name: "Three Zone Heart Rate Limits" },
    Uuid16Entry { uuid: 0x2a95, name: "Two Zone Heart Rate Limit" },
    Uuid16Entry { uuid: 0x2a96, name: "VO2 Max" },
    Uuid16Entry { uuid: 0x2a97, name: "Waist Circumference" },
    Uuid16Entry { uuid: 0x2a98, name: "Weight" },
    Uuid16Entry { uuid: 0x2a99, name: "Database Change Increment" },
    Uuid16Entry { uuid: 0x2a9a, name: "User Index" },
    Uuid16Entry { uuid: 0x2a9b, name: "Body Composition Feature" },
    Uuid16Entry { uuid: 0x2a9c, name: "Body Composition Measurement" },
    Uuid16Entry { uuid: 0x2a9d, name: "Weight Measurement" },
    Uuid16Entry { uuid: 0x2a9e, name: "Weight Scale Feature" },
    Uuid16Entry { uuid: 0x2a9f, name: "User Control Point" },
    Uuid16Entry { uuid: 0x2aa0, name: "Magnetic Flux Density - 2D" },
    Uuid16Entry { uuid: 0x2aa1, name: "Magnetic Flux Density - 3D" },
    Uuid16Entry { uuid: 0x2aa2, name: "Language" },
    Uuid16Entry { uuid: 0x2aa3, name: "Barometric Pressure Trend" },
    Uuid16Entry { uuid: 0x2aa4, name: "Bond Management Control Point" },
    Uuid16Entry { uuid: 0x2aa5, name: "Bond Management Feature" },
    Uuid16Entry { uuid: 0x2aa6, name: "Central Address Resolution" },
    Uuid16Entry { uuid: 0x2aa7, name: "CGM Measurement" },
    Uuid16Entry { uuid: 0x2aa8, name: "CGM Feature" },
    Uuid16Entry { uuid: 0x2aa9, name: "CGM Status" },
    Uuid16Entry { uuid: 0x2aaa, name: "CGM Session Start Time" },
    Uuid16Entry { uuid: 0x2aab, name: "CGM Session Run Time" },
    Uuid16Entry { uuid: 0x2aac, name: "CGM Specific Ops Control Point" },
    Uuid16Entry { uuid: 0x2aad, name: "Indoor Positioning Configuration" },
    Uuid16Entry { uuid: 0x2aae, name: "Latitude" },
    Uuid16Entry { uuid: 0x2aaf, name: "Longitude" },
    Uuid16Entry { uuid: 0x2ab0, name: "Local North Coordinate" },
    Uuid16Entry { uuid: 0x2ab1, name: "Local East Coordinate" },
    Uuid16Entry { uuid: 0x2ab2, name: "Floor Number" },
    Uuid16Entry { uuid: 0x2ab3, name: "Altitude" },
    Uuid16Entry { uuid: 0x2ab4, name: "Uncertainty" },
    Uuid16Entry { uuid: 0x2ab5, name: "Location Name" },
    Uuid16Entry { uuid: 0x2ab6, name: "URI" },
    Uuid16Entry { uuid: 0x2ab7, name: "HTTP Headers" },
    Uuid16Entry { uuid: 0x2ab8, name: "HTTP Status Code" },
    Uuid16Entry { uuid: 0x2ab9, name: "HTTP Entity Body" },
    Uuid16Entry { uuid: 0x2aba, name: "HTTP Control Point" },
    Uuid16Entry { uuid: 0x2abb, name: "HTTPS Security" },
    Uuid16Entry { uuid: 0x2abc, name: "TDS Control Point" },
    Uuid16Entry { uuid: 0x2abd, name: "OTS Feature" },
    Uuid16Entry { uuid: 0x2abe, name: "Object Name" },
    Uuid16Entry { uuid: 0x2abf, name: "Object Type" },
    Uuid16Entry { uuid: 0x2ac0, name: "Object Size" },
    Uuid16Entry { uuid: 0x2ac1, name: "Object First-Created" },
    Uuid16Entry { uuid: 0x2ac2, name: "Object Last-Modified" },
    Uuid16Entry { uuid: 0x2ac3, name: "Object ID" },
    Uuid16Entry { uuid: 0x2ac4, name: "Object Properties" },
    Uuid16Entry { uuid: 0x2ac5, name: "Object Action Control Point" },
    Uuid16Entry { uuid: 0x2ac6, name: "Object List Control Point" },
    Uuid16Entry { uuid: 0x2ac7, name: "Object List Filter" },
    Uuid16Entry { uuid: 0x2ac8, name: "Object Changed" },
    Uuid16Entry { uuid: 0x2ac9, name: "Resolvable Private Address Only" },
    Uuid16Entry { uuid: 0x2acc, name: "Fitness Machine Feature" },
    Uuid16Entry { uuid: 0x2acd, name: "Treadmill Data" },
    Uuid16Entry { uuid: 0x2ace, name: "Cross Trainer Data" },
    Uuid16Entry { uuid: 0x2acf, name: "Step Climber Data" },
    Uuid16Entry { uuid: 0x2ad0, name: "Stair Climber Data" },
    Uuid16Entry { uuid: 0x2ad1, name: "Rower Data" },
    Uuid16Entry { uuid: 0x2ad2, name: "Indoor Bike Data" },
    Uuid16Entry { uuid: 0x2ad3, name: "Training Status" },
    Uuid16Entry { uuid: 0x2ad4, name: "Supported Speed Range" },
    Uuid16Entry { uuid: 0x2ad5, name: "Supported Inclination Range" },
    Uuid16Entry { uuid: 0x2ad6, name: "Supported Resistance Level Range" },
    Uuid16Entry { uuid: 0x2ad7, name: "Supported Heart Rate Range" },
    Uuid16Entry { uuid: 0x2ad8, name: "Supported Power Range" },
    Uuid16Entry { uuid: 0x2ad9, name: "Fitness Machine Control Point" },
    Uuid16Entry { uuid: 0x2ada, name: "Fitness Machine Status" },
    Uuid16Entry { uuid: 0x2adb, name: "Mesh Provisioning Data In" },
    Uuid16Entry { uuid: 0x2adc, name: "Mesh Provisioning Data Out" },
    Uuid16Entry { uuid: 0x2add, name: "Mesh Proxy Data In" },
    Uuid16Entry { uuid: 0x2ade, name: "Mesh Proxy Data Out" },
    Uuid16Entry { uuid: 0x2b29, name: "Client Supported Features" },
    Uuid16Entry { uuid: 0x2b2a, name: "Database Hash" },
    Uuid16Entry { uuid: 0x2b3a, name: "Server Supported Features" },
    Uuid16Entry { uuid: 0x2b51, name: "Telephony and Media Audio Profile Role" },
    Uuid16Entry { uuid: 0x2b77, name: "Audio Input State" },
    Uuid16Entry { uuid: 0x2b78, name: "Gain Settings Attribute" },
    Uuid16Entry { uuid: 0x2b79, name: "Audio Input Type" },
    Uuid16Entry { uuid: 0x2b7a, name: "Audio Input Status" },
    Uuid16Entry { uuid: 0x2b7b, name: "Audio Input Control Point" },
    Uuid16Entry { uuid: 0x2b7c, name: "Audio Input Description" },
    Uuid16Entry { uuid: 0x2b7d, name: "Volume State" },
    Uuid16Entry { uuid: 0x2b7e, name: "Volume Control Point" },
    Uuid16Entry { uuid: 0x2b7f, name: "Volume Flags" },
    Uuid16Entry { uuid: 0x2b80, name: "Offset State" },
    Uuid16Entry { uuid: 0x2b81, name: "Audio Location" },
    Uuid16Entry { uuid: 0x2b82, name: "Volume Offset Control Point" },
    Uuid16Entry { uuid: 0x2b83, name: "Audio Output Description" },
    Uuid16Entry { uuid: 0x2b84, name: "Set Identity Resolving Key" },
    Uuid16Entry { uuid: 0x2b85, name: "Coordinated Set Size" },
    Uuid16Entry { uuid: 0x2b86, name: "Set Member Lock" },
    Uuid16Entry { uuid: 0x2b87, name: "Set Member Rank" },
    Uuid16Entry { uuid: 0x2b93, name: "Media Player Name" },
    Uuid16Entry { uuid: 0x2b94, name: "Media Player Icon Object ID" },
    Uuid16Entry { uuid: 0x2b95, name: "Media Player Icon URL" },
    Uuid16Entry { uuid: 0x2b96, name: "Track Changed" },
    Uuid16Entry { uuid: 0x2b97, name: "Track Title" },
    Uuid16Entry { uuid: 0x2b98, name: "Track Duration" },
    Uuid16Entry { uuid: 0x2b99, name: "Track Position" },
    Uuid16Entry { uuid: 0x2b9a, name: "Playback Speed" },
    Uuid16Entry { uuid: 0x2b9b, name: "Seeking Speed" },
    Uuid16Entry { uuid: 0x2b9c, name: "Current Track Segments Object ID" },
    Uuid16Entry { uuid: 0x2b9d, name: "Current Track Object ID" },
    Uuid16Entry { uuid: 0x2b9e, name: "Next Track Object ID" },
    Uuid16Entry { uuid: 0x2b9f, name: "Parent Group Object ID" },
    Uuid16Entry { uuid: 0x2ba0, name: "Current Group Object ID" },
    Uuid16Entry { uuid: 0x2ba1, name: "Playing Order" },
    Uuid16Entry { uuid: 0x2ba2, name: "Playing Orders Supported" },
    Uuid16Entry { uuid: 0x2ba3, name: "Media State" },
    Uuid16Entry { uuid: 0x2ba4, name: "Media Control Point" },
    Uuid16Entry { uuid: 0x2ba5, name: "Media Control Point Opcodes Supported" },
    Uuid16Entry { uuid: 0x2ba6, name: "Search Results Object ID" },
    Uuid16Entry { uuid: 0x2ba7, name: "Search Control Point" },
    Uuid16Entry { uuid: 0x2ba9, name: "Media Player Icon Object Type" },
    Uuid16Entry { uuid: 0x2baa, name: "Track Segments Object Type" },
    Uuid16Entry { uuid: 0x2bab, name: "Track Object Type" },
    Uuid16Entry { uuid: 0x2bac, name: "Group Object Type" },
    Uuid16Entry { uuid: 0x2bb3, name: "Bearer Provider Name" },
    Uuid16Entry { uuid: 0x2bb4, name: "Bearer UCI" },
    Uuid16Entry { uuid: 0x2bb5, name: "Bearer Technology" },
    Uuid16Entry { uuid: 0x2bb6, name: "Bearer URI Schemes Supported List" },
    Uuid16Entry { uuid: 0x2bb7, name: "Bearer Signal Strength" },
    Uuid16Entry { uuid: 0x2bb8, name: "Bearer Signal Strength Reporting Interval" },
    Uuid16Entry { uuid: 0x2bb9, name: "Bearer List Current Calls" },
    Uuid16Entry { uuid: 0x2bba, name: "Content Control ID" },
    Uuid16Entry { uuid: 0x2bbb, name: "Status Flags" },
    Uuid16Entry { uuid: 0x2bbc, name: "Incoming Call Target Bearer URI" },
    Uuid16Entry { uuid: 0x2bbd, name: "Call State" },
    Uuid16Entry { uuid: 0x2bbe, name: "Call Control Point" },
    Uuid16Entry { uuid: 0x2bbf, name: "Call Control Point Optional Opcodes" },
    Uuid16Entry { uuid: 0x2bc0, name: "Termination Reason" },
    Uuid16Entry { uuid: 0x2bc1, name: "Incoming Call" },
    Uuid16Entry { uuid: 0x2bc2, name: "Call Friendly Name" },
    Uuid16Entry { uuid: 0x2bc3, name: "Mute" },
    Uuid16Entry { uuid: 0x2bc4, name: "Sink ASE" },
    Uuid16Entry { uuid: 0x2bc5, name: "Source ASE" },
    Uuid16Entry { uuid: 0x2bc6, name: "ASE Control Point" },
    Uuid16Entry { uuid: 0x2bc7, name: "Broadcast Audio Scan Control Point" },
    Uuid16Entry { uuid: 0x2bc8, name: "Broadcast Receive State" },
    Uuid16Entry { uuid: 0x2bc9, name: "Sink PAC" },
    Uuid16Entry { uuid: 0x2bca, name: "Sink Audio Locations" },
    Uuid16Entry { uuid: 0x2bcb, name: "Source PAC" },
    Uuid16Entry { uuid: 0x2bcc, name: "Source Audio Locations" },
    Uuid16Entry { uuid: 0x2bcd, name: "Available Audio Contexts" },
    Uuid16Entry { uuid: 0x2bce, name: "Supported Audio Contexts" },
    Uuid16Entry { uuid: 0x2bda, name: "Hearing Aid Features" },
    Uuid16Entry { uuid: 0x2bdb, name: "Hearing Aid Preset Control Point" },
    Uuid16Entry { uuid: 0x2bdc, name: "Active Preset Index" },
    Uuid16Entry { uuid: 0x2c00, name: "GMAP Role" },
    Uuid16Entry { uuid: 0x2c01, name: "UGG Features" },
    Uuid16Entry { uuid: 0x2c02, name: "UGT Features" },
    Uuid16Entry { uuid: 0x2c03, name: "BGS Features" },
    Uuid16Entry { uuid: 0x2c03, name: "BGR Features" },
    Uuid16Entry { uuid: 0x2c14, name: "RAS Features" },
    Uuid16Entry { uuid: 0x2c15, name: "RAS Real-time Ranging Data" },
    Uuid16Entry { uuid: 0x2c16, name: "RAS On-demand Ranging Data" },
    Uuid16Entry { uuid: 0x2c17, name: "RAS Control Point" },
    Uuid16Entry { uuid: 0x2c18, name: "RAS Ranging Data Ready" },
    Uuid16Entry { uuid: 0x2c19, name: "RAS Ranging Data Overwritten" },
    Uuid16Entry { uuid: 0xfeff, name: "GN Netcom" },
    Uuid16Entry { uuid: 0xfefe, name: "GN ReSound A/S" },
    Uuid16Entry { uuid: 0xfefd, name: "Gimbal, Inc." },
    Uuid16Entry { uuid: 0xfefc, name: "Gimbal, Inc." },
    Uuid16Entry { uuid: 0xfefb, name: "Telit Wireless Solutions (Formerly Stollmann E+V GmbH)" },
    Uuid16Entry { uuid: 0xfefa, name: "PayPal, Inc." },
    Uuid16Entry { uuid: 0xfef9, name: "PayPal, Inc." },
    Uuid16Entry { uuid: 0xfef8, name: "Aplix Corporation" },
    Uuid16Entry { uuid: 0xfef7, name: "Aplix Corporation" },
    Uuid16Entry { uuid: 0xfef6, name: "Wicentric, Inc." },
    Uuid16Entry { uuid: 0xfef5, name: "Dialog Semiconductor GmbH" },
    Uuid16Entry { uuid: 0xfef4, name: "Google" },
    Uuid16Entry { uuid: 0xfef3, name: "Google" },
    Uuid16Entry { uuid: 0xfef2, name: "CSR" },
    Uuid16Entry { uuid: 0xfef1, name: "CSR" },
    Uuid16Entry { uuid: 0xfef0, name: "Intel" },
    Uuid16Entry { uuid: 0xfeef, name: "Polar Electro Oy " },
    Uuid16Entry { uuid: 0xfeee, name: "Polar Electro Oy " },
    Uuid16Entry { uuid: 0xfeed, name: "Tile, Inc." },
    Uuid16Entry { uuid: 0xfeec, name: "Tile, Inc." },
    Uuid16Entry { uuid: 0xfeeb, name: "Swirl Networks, Inc." },
    Uuid16Entry { uuid: 0xfeea, name: "Swirl Networks, Inc." },
    Uuid16Entry { uuid: 0xfee9, name: "Quintic Corp." },
    Uuid16Entry { uuid: 0xfee8, name: "Quintic Corp." },
    Uuid16Entry { uuid: 0xfee7, name: "Tencent Holdings Limited." },
    Uuid16Entry { uuid: 0xfee6, name: "Silvair, Inc." },
    Uuid16Entry { uuid: 0xfee5, name: "Nordic Semiconductor ASA" },
    Uuid16Entry { uuid: 0xfee4, name: "Nordic Semiconductor ASA" },
    Uuid16Entry { uuid: 0xfee3, name: "Anki, Inc." },
    Uuid16Entry { uuid: 0xfee2, name: "Anki, Inc." },
    Uuid16Entry { uuid: 0xfee1, name: "Anhui Huami Information Technology Co., Ltd. " },
    Uuid16Entry { uuid: 0xfee0, name: "Anhui Huami Information Technology Co., Ltd. " },
    Uuid16Entry { uuid: 0xfedf, name: "Design SHIFT" },
    Uuid16Entry { uuid: 0xfede, name: "Coin, Inc." },
    Uuid16Entry { uuid: 0xfedd, name: "Jawbone" },
    Uuid16Entry { uuid: 0xfedc, name: "Jawbone" },
    Uuid16Entry { uuid: 0xfedb, name: "Perka, Inc." },
    Uuid16Entry { uuid: 0xfeda, name: "ISSC Technologies Corp. " },
    Uuid16Entry { uuid: 0xfed9, name: "Pebble Technology Corporation" },
    Uuid16Entry { uuid: 0xfed8, name: "Google" },
    Uuid16Entry { uuid: 0xfed7, name: "Broadcom" },
    Uuid16Entry { uuid: 0xfed6, name: "Broadcom" },
    Uuid16Entry { uuid: 0xfed5, name: "Plantronics Inc." },
    Uuid16Entry { uuid: 0xfed4, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfed3, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfed2, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfed1, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfed0, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfecf, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfece, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfecd, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfecc, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfecb, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfeca, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfec9, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfec8, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfec7, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfec6, name: "Kocomojo, LLC" },
    Uuid16Entry { uuid: 0xfec5, name: "Realtek Semiconductor Corp." },
    Uuid16Entry { uuid: 0xfec4, name: "PLUS Location Systems" },
    Uuid16Entry { uuid: 0xfec3, name: "360fly, Inc." },
    Uuid16Entry { uuid: 0xfec2, name: "Blue Spark Technologies, Inc." },
    Uuid16Entry { uuid: 0xfec1, name: "KDDI Corporation" },
    Uuid16Entry { uuid: 0xfec0, name: "KDDI Corporation" },
    Uuid16Entry { uuid: 0xfebf, name: "Nod, Inc." },
    Uuid16Entry { uuid: 0xfebe, name: "Bose Corporation" },
    Uuid16Entry { uuid: 0xfebd, name: "Clover Network, Inc" },
    Uuid16Entry { uuid: 0xfebc, name: "Dexcom Inc" },
    Uuid16Entry { uuid: 0xfebb, name: "adafruit industries" },
    Uuid16Entry { uuid: 0xfeba, name: "Tencent Holdings Limited" },
    Uuid16Entry { uuid: 0xfeb9, name: "LG Electronics" },
    Uuid16Entry { uuid: 0xfeb8, name: "Facebook, Inc." },
    Uuid16Entry { uuid: 0xfeb7, name: "Facebook, Inc." },
    Uuid16Entry { uuid: 0xfeb6, name: "Vencer Co., Ltd" },
    Uuid16Entry { uuid: 0xfeb5, name: "WiSilica Inc." },
    Uuid16Entry { uuid: 0xfeb4, name: "WiSilica Inc." },
    Uuid16Entry { uuid: 0xfeb3, name: "Taobao" },
    Uuid16Entry { uuid: 0xfeb2, name: "Microsoft Corporation" },
    Uuid16Entry { uuid: 0xfeb1, name: "Electronics Tomorrow Limited" },
    Uuid16Entry { uuid: 0xfeb0, name: "Nest Labs Inc" },
    Uuid16Entry { uuid: 0xfeaf, name: "Nest Labs Inc" },
    Uuid16Entry { uuid: 0xfeae, name: "Nokia" },
    Uuid16Entry { uuid: 0xfead, name: "Nokia" },
    Uuid16Entry { uuid: 0xfeac, name: "Nokia" },
    Uuid16Entry { uuid: 0xfeab, name: "Nokia" },
    Uuid16Entry { uuid: 0xfeaa, name: "Google" },
    Uuid16Entry { uuid: 0xfea9, name: "Savant Systems LLC" },
    Uuid16Entry { uuid: 0xfea8, name: "Savant Systems LLC" },
    Uuid16Entry { uuid: 0xfea7, name: "UTC Fire and Security" },
    Uuid16Entry { uuid: 0xfea6, name: "GoPro, Inc." },
    Uuid16Entry { uuid: 0xfea5, name: "GoPro, Inc." },
    Uuid16Entry { uuid: 0xfea4, name: "Paxton Access Ltd" },
    Uuid16Entry { uuid: 0xfea3, name: "ITT Industries" },
    Uuid16Entry { uuid: 0xfea2, name: "Intrepid Control Systems, Inc." },
    Uuid16Entry { uuid: 0xfea1, name: "Intrepid Control Systems, Inc." },
    Uuid16Entry { uuid: 0xfea0, name: "Google" },
    Uuid16Entry { uuid: 0xfe9f, name: "Google" },
    Uuid16Entry { uuid: 0xfe9e, name: "Dialog Semiconductor B.V." },
    Uuid16Entry { uuid: 0xfe9d, name: "Mobiquity Networks Inc" },
    Uuid16Entry { uuid: 0xfe9c, name: "GSI Laboratories, Inc." },
    Uuid16Entry { uuid: 0xfe9b, name: "Samsara Networks, Inc" },
    Uuid16Entry { uuid: 0xfe9a, name: "Estimote" },
    Uuid16Entry { uuid: 0xfe99, name: "Currant Inc" },
    Uuid16Entry { uuid: 0xfe98, name: "Currant Inc" },
    Uuid16Entry { uuid: 0xfe97, name: "Tesla Motors Inc." },
    Uuid16Entry { uuid: 0xfe96, name: "Tesla Motors Inc." },
    Uuid16Entry { uuid: 0xfe95, name: "Xiaomi Inc." },
    Uuid16Entry { uuid: 0xfe94, name: "OttoQ In" },
    Uuid16Entry { uuid: 0xfe93, name: "OttoQ In" },
    Uuid16Entry { uuid: 0xfe92, name: "Jarden Safety & Security" },
    Uuid16Entry { uuid: 0xfe91, name: "Shanghai Imilab Technology Co.,Ltd" },
    Uuid16Entry { uuid: 0xfe90, name: "JUMA" },
    Uuid16Entry { uuid: 0xfe8f, name: "CSR" },
    Uuid16Entry { uuid: 0xfe8e, name: "ARM Ltd" },
    Uuid16Entry { uuid: 0xfe8d, name: "Interaxon Inc." },
    Uuid16Entry { uuid: 0xfe8c, name: "TRON Forum" },
    Uuid16Entry { uuid: 0xfe8b, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfe8a, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfe89, name: "B&O Play A/S" },
    Uuid16Entry { uuid: 0xfe88, name: "SALTO SYSTEMS S.L." },
    Uuid16Entry {
        uuid: 0xfe87,
        name: "Qingdao Yeelink Information Technology Co., Ltd. ( 青岛亿联客信息技术有限公司 )",
    },
    Uuid16Entry {
        uuid: 0xfe86, name: "HUAWEI Technologies Co., Ltd. ( 华为技术有限公司 )"
    },
    Uuid16Entry { uuid: 0xfe85, name: "RF Digital Corp" },
    Uuid16Entry { uuid: 0xfe84, name: "RF Digital Corp" },
    Uuid16Entry { uuid: 0xfe83, name: "Blue Bite" },
    Uuid16Entry { uuid: 0xfe82, name: "Medtronic Inc." },
    Uuid16Entry { uuid: 0xfe81, name: "Medtronic Inc." },
    Uuid16Entry { uuid: 0xfe80, name: "Doppler Lab" },
    Uuid16Entry { uuid: 0xfe7f, name: "Doppler Lab" },
    Uuid16Entry { uuid: 0xfe7e, name: "Awear Solutions Ltd" },
    Uuid16Entry { uuid: 0xfe7d, name: "Aterica Health Inc." },
    Uuid16Entry { uuid: 0xfe7c, name: "Telit Wireless Solutions (Formerly Stollmann E+V GmbH)" },
    Uuid16Entry { uuid: 0xfe7b, name: "Orion Labs, Inc." },
    Uuid16Entry { uuid: 0xfe7a, name: "Bragi GmbH" },
    Uuid16Entry { uuid: 0xfe79, name: "Zebra Technologies" },
    Uuid16Entry { uuid: 0xfe78, name: "Hewlett-Packard Company" },
    Uuid16Entry { uuid: 0xfe77, name: "Hewlett-Packard Company" },
    Uuid16Entry { uuid: 0xfe76, name: "TangoMe" },
    Uuid16Entry { uuid: 0xfe75, name: "TangoMe" },
    Uuid16Entry { uuid: 0xfe74, name: "unwire" },
    Uuid16Entry { uuid: 0xfe73, name: "Abbott (formerly St. Jude Medical, Inc.)" },
    Uuid16Entry { uuid: 0xfe72, name: "Abbott (formerly St. Jude Medical, Inc.)" },
    Uuid16Entry { uuid: 0xfe71, name: "Plume Design Inc" },
    Uuid16Entry { uuid: 0xfe70, name: "Beijing Jingdong Century Trading Co., Ltd." },
    Uuid16Entry { uuid: 0xfe6f, name: "LINE Corporation" },
    Uuid16Entry { uuid: 0xfe6e, name: "The University of Tokyo " },
    Uuid16Entry { uuid: 0xfe6d, name: "The University of Tokyo " },
    Uuid16Entry { uuid: 0xfe6c, name: "TASER International, Inc." },
    Uuid16Entry { uuid: 0xfe6b, name: "TASER International, Inc." },
    Uuid16Entry { uuid: 0xfe6a, name: "Kontakt Micro-Location Sp. z o.o." },
    Uuid16Entry { uuid: 0xfe69, name: "Capsule Technologies Inc." },
    Uuid16Entry { uuid: 0xfe68, name: "Capsule Technologies Inc." },
    Uuid16Entry { uuid: 0xfe67, name: "Lab Sensor Solutions" },
    Uuid16Entry { uuid: 0xfe66, name: "Intel Corporation " },
    Uuid16Entry { uuid: 0xfe65, name: "CHIPOLO d.o.o. " },
    Uuid16Entry { uuid: 0xfe64, name: "Siemens AG" },
    Uuid16Entry { uuid: 0xfe63, name: "Connected Yard, Inc. " },
    Uuid16Entry { uuid: 0xfe62, name: "Indagem Tech LLC " },
    Uuid16Entry { uuid: 0xfe61, name: "Logitech International SA " },
    Uuid16Entry { uuid: 0xfe60, name: "Lierda Science & Technology Group Co., Ltd." },
    Uuid16Entry { uuid: 0xfe5f, name: "Eyefi, Inc." },
    Uuid16Entry { uuid: 0xfe5e, name: "Plastc Corporation " },
    Uuid16Entry { uuid: 0xfe5d, name: "Grundfos A/S " },
    Uuid16Entry { uuid: 0xfe5c, name: "million hunters GmbH " },
    Uuid16Entry { uuid: 0xfe5b, name: "GT-tronics HK Ltd" },
    Uuid16Entry { uuid: 0xfe5a, name: "Cronologics Corporation" },
    Uuid16Entry { uuid: 0xfe59, name: "Nordic Semiconductor ASA " },
    Uuid16Entry { uuid: 0xfe58, name: "Nordic Semiconductor ASA " },
    Uuid16Entry { uuid: 0xfe57, name: "Dotted Labs " },
    Uuid16Entry { uuid: 0xfe56, name: "Google Inc. " },
    Uuid16Entry { uuid: 0xfe55, name: "Google Inc. " },
    Uuid16Entry { uuid: 0xfe54, name: "Motiv, Inc. " },
    Uuid16Entry { uuid: 0xfe53, name: "3M" },
    Uuid16Entry { uuid: 0xfe52, name: "SetPoint Medical " },
    Uuid16Entry { uuid: 0xfe51, name: "SRAM " },
    Uuid16Entry { uuid: 0xfe50, name: "Google Inc." },
    Uuid16Entry { uuid: 0xfe4f, name: "Molekule, Inc." },
    Uuid16Entry { uuid: 0xfe4e, name: "NTT docomo " },
    Uuid16Entry { uuid: 0xfe4d, name: "Casambi Technologies Oy" },
    Uuid16Entry { uuid: 0xfe4c, name: "Volkswagen AG " },
    Uuid16Entry { uuid: 0xfe4b, name: "Signify Netherlands B.V. (formerly Philips Lighting B.V.)" },
    Uuid16Entry { uuid: 0xfe4a, name: "OMRON HEALTHCARE Co., Ltd." },
    Uuid16Entry { uuid: 0xfe49, name: "SenionLab AB" },
    Uuid16Entry { uuid: 0xfe48, name: "General Motors " },
    Uuid16Entry { uuid: 0xfe47, name: "General Motors " },
    Uuid16Entry { uuid: 0xfe46, name: "B&O Play A/S " },
    Uuid16Entry { uuid: 0xfe45, name: "Snapchat Inc" },
    Uuid16Entry { uuid: 0xfe44, name: "SK Telecom " },
    Uuid16Entry { uuid: 0xfe43, name: "Andreas Stihl AG & Co. KG" },
    Uuid16Entry { uuid: 0xfe42, name: "Nets A/S " },
    Uuid16Entry { uuid: 0xfe41, name: "Inugo Systems Limited" },
    Uuid16Entry { uuid: 0xfe40, name: "Inugo Systems Limited" },
    Uuid16Entry { uuid: 0xfe3f, name: "Friday Labs Limited" },
    Uuid16Entry { uuid: 0xfe3e, name: "BD Medical" },
    Uuid16Entry { uuid: 0xfe3d, name: "BD Medical" },
    Uuid16Entry { uuid: 0xfe3c, name: "alibaba" },
    Uuid16Entry { uuid: 0xfe3b, name: "Dobly Laboratories" },
    Uuid16Entry { uuid: 0xfe3a, name: "TTS Tooltechnic Systems AG & Co. KG" },
    Uuid16Entry { uuid: 0xfe39, name: "TTS Tooltechnic Systems AG & Co. KG" },
    Uuid16Entry { uuid: 0xfe38, name: "Spaceek LTD" },
    Uuid16Entry { uuid: 0xfe37, name: "Spaceek LTD" },
    Uuid16Entry { uuid: 0xfe36, name: "HUAWEI Technologies Co., Ltd" },
    Uuid16Entry { uuid: 0xfe35, name: "HUAWEI Technologies Co., Ltd" },
    Uuid16Entry { uuid: 0xfe34, name: "SmallLoop LLC" },
    Uuid16Entry { uuid: 0xfe33, name: "CHIPOLO d.o.o." },
    Uuid16Entry { uuid: 0xfe32, name: "Pro-Mark, Inc." },
    Uuid16Entry { uuid: 0xfe31, name: "Volkswagen AG" },
    Uuid16Entry { uuid: 0xfe30, name: "Volkswagen AG" },
    Uuid16Entry { uuid: 0xfe2f, name: "CRESCO Wireless, Inc" },
    Uuid16Entry { uuid: 0xfe2e, name: "ERi,Inc." },
    Uuid16Entry { uuid: 0xfe2d, name: "SMART INNOVATION Co.,Ltd" },
    Uuid16Entry { uuid: 0xfe2c, name: "Google" },
    Uuid16Entry { uuid: 0xfe2b, name: "ITT Industries" },
    Uuid16Entry { uuid: 0xfe2a, name: "DaisyWorks, Inc." },
    Uuid16Entry { uuid: 0xfe29, name: "Gibson Innovations" },
    Uuid16Entry { uuid: 0xfe28, name: "Ayla Networks" },
    Uuid16Entry { uuid: 0xfe27, name: "Google" },
    Uuid16Entry { uuid: 0xfe26, name: "Google" },
    Uuid16Entry { uuid: 0xfe25, name: "Apple, Inc. " },
    Uuid16Entry { uuid: 0xfe24, name: "August Home Inc" },
    Uuid16Entry { uuid: 0xfe23, name: "Zoll Medical Corporation" },
    Uuid16Entry { uuid: 0xfe22, name: "Zoll Medical Corporation" },
    Uuid16Entry { uuid: 0xfe21, name: "Bose Corporation" },
    Uuid16Entry { uuid: 0xfe20, name: "Emerson" },
    Uuid16Entry { uuid: 0xfe1f, name: "Garmin International, Inc." },
    Uuid16Entry { uuid: 0xfe1e, name: "Smart Innovations Co., Ltd" },
    Uuid16Entry { uuid: 0xfe1d, name: "Illuminati Instrument Corporation" },
    Uuid16Entry { uuid: 0xfe1c, name: "NetMedia, Inc." },
    Uuid16Entry { uuid: 0xfe1b, name: "Tyto Life LLC" },
    Uuid16Entry { uuid: 0xfe1a, name: "Tyto Life LLC" },
    Uuid16Entry { uuid: 0xfe19, name: "Google, Inc" },
    Uuid16Entry { uuid: 0xfe18, name: "Runtime, Inc." },
    Uuid16Entry { uuid: 0xfe17, name: "Telit Wireless Solutions GmbH" },
    Uuid16Entry { uuid: 0xfe16, name: "Footmarks, Inc." },
    Uuid16Entry { uuid: 0xfe15, name: "Amazon.com Services, Inc.." },
    Uuid16Entry { uuid: 0xfe14, name: "Flextronics International USA Inc." },
    Uuid16Entry { uuid: 0xfe13, name: "Apple Inc." },
    Uuid16Entry { uuid: 0xfe12, name: "M-Way Solutions GmbH" },
    Uuid16Entry { uuid: 0xfe11, name: "GMC-I Messtechnik GmbH" },
    Uuid16Entry { uuid: 0xfe10, name: "Lapis Semiconductor Co., Ltd." },
    Uuid16Entry { uuid: 0xfe0f, name: "Signify Netherlands B.V. (formerly Philips Lighting B.V.)" },
    Uuid16Entry { uuid: 0xfe0e, name: "Setec Pty Ltd" },
    Uuid16Entry { uuid: 0xfe0d, name: "Procter & Gamble" },
    Uuid16Entry { uuid: 0xfe0c, name: "Procter & Gamble" },
    Uuid16Entry { uuid: 0xfe0b, name: "ruwido austria gmbh" },
    Uuid16Entry { uuid: 0xfe0a, name: "ruwido austria gmbh" },
    Uuid16Entry { uuid: 0xfe09, name: "Pillsy, Inc." },
    Uuid16Entry { uuid: 0xfe08, name: "Microsoft" },
    Uuid16Entry { uuid: 0xfe07, name: "Sonos, Inc." },
    Uuid16Entry { uuid: 0xfe06, name: "Qualcomm Technologies, Inc." },
    Uuid16Entry { uuid: 0xfe05, name: "CORE Transport Technologies NZ Limited " },
    Uuid16Entry { uuid: 0xfe04, name: "OpenPath Security Inc" },
    Uuid16Entry { uuid: 0xfe03, name: "Amazon.com Services, Inc." },
    Uuid16Entry { uuid: 0xfe02, name: "Robert Bosch GmbH" },
    Uuid16Entry { uuid: 0xfe01, name: "Duracell U.S. Operations Inc." },
    Uuid16Entry { uuid: 0xfe00, name: "Amazon.com Services, Inc." },
    Uuid16Entry { uuid: 0xfdff, name: "OSRAM GmbH" },
    Uuid16Entry { uuid: 0xfdfe, name: "ADHERIUM(NZ) LIMITED" },
    Uuid16Entry { uuid: 0xfdfd, name: "RecursiveSoft Inc." },
    Uuid16Entry { uuid: 0xfdfc, name: "Optrel AG" },
    Uuid16Entry { uuid: 0xfdfb, name: "Tandem Diabetes Care" },
    Uuid16Entry { uuid: 0xfdfa, name: "Tandem Diabetes Care" },
    Uuid16Entry { uuid: 0xfdf9, name: "INIA" },
    Uuid16Entry { uuid: 0xfdf8, name: "Onvocal" },
    Uuid16Entry { uuid: 0xfdf7, name: "HP Inc." },
    Uuid16Entry { uuid: 0xfdf6, name: "AIAIAI ApS" },
    Uuid16Entry { uuid: 0xfdf5, name: "Milwaukee Electric Tools" },
    Uuid16Entry { uuid: 0xfdf4, name: "O. E. M. Controls, Inc." },
    Uuid16Entry { uuid: 0xfdf3, name: "Amersports" },
    Uuid16Entry { uuid: 0xfdf2, name: "AMICCOM Electronics Corporation" },
    Uuid16Entry { uuid: 0xfdf1, name: "LAMPLIGHT Co.,Ltd" },
    Uuid16Entry { uuid: 0xfdf0, name: "Google Inc." },
    Uuid16Entry { uuid: 0xfdef, name: "ART AND PROGRAM, INC." },
    Uuid16Entry { uuid: 0xfdee, name: "Huawei Technologies Co., Ltd." },
    Uuid16Entry { uuid: 0xfded, name: "Pole Star" },
    Uuid16Entry { uuid: 0xfdec, name: "Mannkind Corporation" },
    Uuid16Entry { uuid: 0xfdeb, name: "Syntronix Corporation" },
    Uuid16Entry { uuid: 0xfdea, name: "SeeScan, Inc" },
    Uuid16Entry { uuid: 0xfde9, name: "Spacesaver Corporation" },
    Uuid16Entry { uuid: 0xfde8, name: "Robert Bosch GmbH" },
    Uuid16Entry { uuid: 0xfde7, name: "SECOM Co., LTD" },
    Uuid16Entry { uuid: 0xfde6, name: "Intelletto Technologies Inc" },
    Uuid16Entry { uuid: 0xfde5, name: "SMK Corporation " },
    Uuid16Entry { uuid: 0xfde4, name: "JUUL Labs, Inc." },
    Uuid16Entry { uuid: 0xfde3, name: "Abbott Diabetes Care" },
    Uuid16Entry { uuid: 0xfde2, name: "Google Inc." },
    Uuid16Entry { uuid: 0xfde1, name: "Fortin Electronic Systems " },
    Uuid16Entry { uuid: 0xfde0, name: "John Deere" },
    Uuid16Entry { uuid: 0xfddf, name: "Harman International" },
    Uuid16Entry { uuid: 0xfdde, name: "Noodle Technology Inc. " },
    Uuid16Entry { uuid: 0xfddd, name: "Arch Systems Inc" },
    Uuid16Entry { uuid: 0xfddc, name: "4iiii Innovations Inc." },
    Uuid16Entry { uuid: 0xfddb, name: "Samsung Electronics Co., Ltd. " },
    Uuid16Entry { uuid: 0xfdda, name: "MHCS" },
    Uuid16Entry { uuid: 0xfdd9, name: "Jiangsu Teranovo Tech Co., Ltd." },
    Uuid16Entry { uuid: 0xfdd8, name: "Jiangsu Teranovo Tech Co., Ltd." },
    Uuid16Entry { uuid: 0xfdd7, name: "Emerson" },
    Uuid16Entry { uuid: 0xfdd6, name: "Ministry of Supply " },
    Uuid16Entry { uuid: 0xfdd5, name: "Brompton Bicycle Ltd" },
    Uuid16Entry { uuid: 0xfdd4, name: "LX Solutions Pty Limited" },
    Uuid16Entry { uuid: 0xfdd3, name: "FUBA Automotive Electronics GmbH" },
    Uuid16Entry { uuid: 0xfdd2, name: "Bose Corporation" },
    Uuid16Entry { uuid: 0xfdd1, name: "Huawei Technologies Co., Ltd " },
    Uuid16Entry { uuid: 0xfdd0, name: "Huawei Technologies Co., Ltd " },
    Uuid16Entry { uuid: 0xfdcf, name: "Nalu Medical, Inc" },
    Uuid16Entry { uuid: 0xfdce, name: "SENNHEISER electronic GmbH & Co. KG" },
    Uuid16Entry { uuid: 0xfdcd, name: "Qingping Technology (Beijing) Co., Ltd." },
    Uuid16Entry { uuid: 0xfdcc, name: "Shoof Technologies" },
    Uuid16Entry { uuid: 0xfdcb, name: "Meggitt SA" },
    Uuid16Entry { uuid: 0xfdca, name: "Fortin Electronic Systems " },
    Uuid16Entry { uuid: 0xfdc9, name: "Busch-Jaeger Elektro GmbH" },
    Uuid16Entry { uuid: 0xfdc8, name: "Hach – Danaher" },
    Uuid16Entry { uuid: 0xfdc7, name: "Eli Lilly and Company" },
    Uuid16Entry { uuid: 0xfdc6, name: "Eli Lilly and Company" },
    Uuid16Entry { uuid: 0xfdc5, name: "Automatic Labs" },
    Uuid16Entry { uuid: 0xfdc4, name: "Simavita (Aust) Pty Ltd" },
    Uuid16Entry { uuid: 0xfdc3, name: "Baidu Online Network Technology (Beijing) Co., Ltd" },
    Uuid16Entry { uuid: 0xfdc2, name: "Baidu Online Network Technology (Beijing) Co., Ltd" },
    Uuid16Entry { uuid: 0xfdc1, name: "Hunter Douglas" },
    Uuid16Entry { uuid: 0xfdc0, name: "Hunter Douglas" },
    Uuid16Entry { uuid: 0xfdbf, name: "California Things Inc. " },
    Uuid16Entry { uuid: 0xfdbe, name: "California Things Inc. " },
    Uuid16Entry { uuid: 0xfdbd, name: "Clover Network, Inc." },
    Uuid16Entry { uuid: 0xfdbc, name: "Emerson" },
    Uuid16Entry { uuid: 0xfdbb, name: "Profoto" },
    Uuid16Entry { uuid: 0xfdba, name: "Comcast Cable Corporation" },
    Uuid16Entry { uuid: 0xfdb9, name: "Comcast Cable Corporation" },
    Uuid16Entry { uuid: 0xfdb8, name: "LivaNova USA Inc." },
    Uuid16Entry { uuid: 0xfdb7, name: "LivaNova USA Inc." },
    Uuid16Entry { uuid: 0xfdb6, name: "GWA Hygiene GmbH" },
    Uuid16Entry { uuid: 0xfdb5, name: "ECSG" },
    Uuid16Entry { uuid: 0xfdb4, name: "HP Inc" },
    Uuid16Entry { uuid: 0xfdb3, name: "Audiodo AB" },
    Uuid16Entry { uuid: 0xfdb2, name: "Portable Multimedia Ltd " },
    Uuid16Entry { uuid: 0xfdb1, name: "Proxy Technologies, Inc." },
    Uuid16Entry { uuid: 0xfdb0, name: "Proxy Technologies, Inc." },
    Uuid16Entry { uuid: 0xfdaf, name: "Wiliot LTD" },
    Uuid16Entry { uuid: 0xfdae, name: "Houwa System Design, k.k." },
    Uuid16Entry { uuid: 0xfdad, name: "Houwa System Design, k.k." },
    Uuid16Entry { uuid: 0xfdac, name: "Tentacle Sync GmbH" },
    Uuid16Entry { uuid: 0xfdab, name: "Xiaomi Inc." },
    Uuid16Entry { uuid: 0xfdaa, name: "Xiaomi Inc." },
    Uuid16Entry { uuid: 0xfda9, name: "Rhombus Systems, Inc." },
    Uuid16Entry { uuid: 0xfda8, name: "PSA Peugeot Citroën" },
    Uuid16Entry { uuid: 0xfda7, name: "WWZN Information Technology Company Limited" },
    Uuid16Entry { uuid: 0xfda6, name: "WWZN Information Technology Company Limited" },
    Uuid16Entry { uuid: 0xfda5, name: "Neurostim OAB, Inc." },
    Uuid16Entry { uuid: 0xfda4, name: "Inseego Corp." },
    Uuid16Entry { uuid: 0xfda3, name: "Inseego Corp." },
    Uuid16Entry { uuid: 0xfda2, name: "Groove X, Inc" },
    Uuid16Entry { uuid: 0xfda1, name: "Groove X, Inc" },
    Uuid16Entry { uuid: 0xfda0, name: "Secugen Corporation" },
    Uuid16Entry { uuid: 0xfd9f, name: "VitalTech Affiliates LLC" },
    Uuid16Entry { uuid: 0xfd9e, name: "The Coca-Cola Company" },
    Uuid16Entry { uuid: 0xfd9d, name: "Gastec Corporation" },
    Uuid16Entry { uuid: 0xfd9c, name: "Huawei Technologies Co., Ltd." },
    Uuid16Entry { uuid: 0xfd9b, name: "Huawei Technologies Co., Ltd." },
    Uuid16Entry { uuid: 0xfd9a, name: "Huawei Technologies Co., Ltd." },
    Uuid16Entry { uuid: 0xfd99, name: "ABB Oy" },
    Uuid16Entry { uuid: 0xfd98, name: "Disney Worldwide Services, Inc." },
    Uuid16Entry { uuid: 0xfd97, name: "June Life, Inc." },
    Uuid16Entry { uuid: 0xfd96, name: "Google LLC" },
    Uuid16Entry { uuid: 0xfd95, name: "Rigado" },
    Uuid16Entry { uuid: 0xfd94, name: "Hewlett Packard Enterprise" },
    Uuid16Entry { uuid: 0xfd93, name: "Bayerische Motoren Werke AG" },
    Uuid16Entry { uuid: 0xfd92, name: "Qualcomm Technologies International, Ltd. (QTIL)" },
    Uuid16Entry { uuid: 0xfd91, name: "Groove X, Inc." },
    Uuid16Entry { uuid: 0xfd90, name: "Guangzhou SuperSound Information Technology Co.,Ltd" },
    Uuid16Entry { uuid: 0xfd8f, name: "Matrix ComSec Pvt. Ltd." },
    Uuid16Entry { uuid: 0xfd8e, name: "Motorola Solutions" },
    Uuid16Entry { uuid: 0xfd8d, name: "quip NYC Inc." },
    Uuid16Entry { uuid: 0xfd8c, name: "Google LLC" },
    Uuid16Entry { uuid: 0xfd8b, name: "Jigowatts Inc." },
    Uuid16Entry { uuid: 0xfd8a, name: "Signify Netherlands B.V." },
    Uuid16Entry { uuid: 0xfd89, name: "Urbanminded LTD" },
    Uuid16Entry { uuid: 0xfd88, name: "Urbanminded LTD" },
    Uuid16Entry { uuid: 0xfd87, name: "Google LLC" },
    Uuid16Entry { uuid: 0xfd86, name: "Abbott" },
    Uuid16Entry { uuid: 0xfd85, name: "Husqvarna AB" },
    Uuid16Entry { uuid: 0xfd84, name: "Tile, Inc." },
    Uuid16Entry { uuid: 0xfd83, name: "iNFORM Technology GmbH" },
    Uuid16Entry { uuid: 0xfd82, name: "Sony Corporation" },
    Uuid16Entry { uuid: 0xfd81, name: "CANDY HOUSE, Inc." },
    Uuid16Entry { uuid: 0xfd80, name: "Phindex Technologies, Inc" },
    Uuid16Entry { uuid: 0xfd7f, name: "Husqvarna AB" },
    Uuid16Entry { uuid: 0xfd7e, name: "Samsung Electronics Co., Ltd." },
    Uuid16Entry { uuid: 0xfd7d, name: "Center for Advanced Research Wernher Von Braun" },
    Uuid16Entry { uuid: 0xfd7c, name: "Toshiba Information Systems(Japan) Corporation" },
    Uuid16Entry { uuid: 0xfd7b, name: "WYZE LABS, INC." },
    Uuid16Entry { uuid: 0xfd7a, name: "Withings" },
    Uuid16Entry { uuid: 0xfd79, name: "Withings" },
    Uuid16Entry { uuid: 0xfd78, name: "Withings" },
    Uuid16Entry { uuid: 0xfd77, name: "Withings" },
    Uuid16Entry { uuid: 0xfd76, name: "Insulet Corporation" },
    Uuid16Entry { uuid: 0xfd75, name: "Insulet Corporation" },
    Uuid16Entry { uuid: 0xfd74, name: "BRControls Products BV" },
    Uuid16Entry { uuid: 0xfd73, name: "BRControls Products BV" },
    Uuid16Entry { uuid: 0xfd72, name: "Logitech International SA" },
    Uuid16Entry { uuid: 0xfd71, name: "GN Hearing A/S" },
    Uuid16Entry { uuid: 0xfd70, name: "GuangDong Oppo Mobile Telecommunications Corp., Ltd." },
    Uuid16Entry { uuid: 0xfd6f, name: "Apple, Inc." },
    Uuid16Entry { uuid: 0xfd6e, name: "Polidea sp. z o.o." },
    Uuid16Entry { uuid: 0xfd6d, name: "Sigma Elektro GmbH" },
    Uuid16Entry { uuid: 0xfd6c, name: "Samsung Electronics Co., Ltd." },
    Uuid16Entry { uuid: 0xfd6b, name: " rapitag GmbH" },
    Uuid16Entry { uuid: 0xfd6a, name: "Emerson" },
    Uuid16Entry { uuid: 0xfd69, name: "Samsung Electronics Co., Ltd." },
    Uuid16Entry { uuid: 0xfd68, name: "Ubique Innovation AG" },
    Uuid16Entry { uuid: 0xfd67, name: "Montblanc Simplo GmbH" },
    Uuid16Entry { uuid: 0xfd66, name: "Zebra Technologies Corporation" },
    Uuid16Entry { uuid: 0xfd65, name: "Razer Inc." },
    Uuid16Entry { uuid: 0xfd64, name: "INRIA" },
    Uuid16Entry { uuid: 0xfd63, name: "Fitbit, Inc." },
    Uuid16Entry { uuid: 0xfd62, name: "Fitbit, Inc." },
    Uuid16Entry { uuid: 0xfd61, name: "Arendi AG" },
    Uuid16Entry { uuid: 0xfd60, name: "Sercomm Corporation" },
    Uuid16Entry { uuid: 0xfd5f, name: "Oculus VR, LLC" },
    Uuid16Entry { uuid: 0xfccc, name: "Wi-Fi Easy Connect Specification" },
    Uuid16Entry { uuid: 0xffef, name: "Wi-Fi Direct Specification" },
    Uuid16Entry { uuid: 0xfff0, name: "Public Key Open Credential (PKOC)" },
    Uuid16Entry { uuid: 0xfff1, name: "ICCE Digital Key" },
    Uuid16Entry { uuid: 0xfff2, name: "Aliro" },
    Uuid16Entry { uuid: 0xfff3, name: "FiRa Consortium" },
    Uuid16Entry { uuid: 0xfff4, name: "FiRa Consortium" },
    Uuid16Entry { uuid: 0xfff5, name: "Car Connectivity Consortium, LLC" },
    Uuid16Entry { uuid: 0xfff6, name: "Matter Profile ID" },
    Uuid16Entry { uuid: 0xfff7, name: "Zigbee Direct" },
    Uuid16Entry { uuid: 0xfff8, name: "Mopria Alliance BLE" },
    Uuid16Entry { uuid: 0xfff9, name: "FIDO2 Secure Client-To-Authenticator Transport" },
    Uuid16Entry { uuid: 0xfffa, name: "ASTM Remote ID" },
    Uuid16Entry { uuid: 0xfffb, name: "Direct Thread Commissioning" },
    Uuid16Entry { uuid: 0xfffc, name: "Wireless Power Transfer (WPT)" },
    Uuid16Entry { uuid: 0xfffd, name: "Universal Second Factor Authenticator" },
    Uuid16Entry { uuid: 0xfffe, name: "Wireless Power Transfer" },
];

/// Entry in the UUID128 lookup table.
struct Uuid128Entry {
    uuid: &'static str,
    name: &'static str,
}

/// Lookup table for well-known 128-bit UUIDs (vendor-specific and experimental).
static UUID128_TABLE: &[Uuid128Entry] = &[
    Uuid128Entry {
        uuid: "a3c87500-8ed3-4bdf-8a39-a01bebede295",
        name: "Eddystone Configuration Service",
    },
    Uuid128Entry { uuid: "a3c87501-8ed3-4bdf-8a39-a01bebede295", name: "Capabilities" },
    Uuid128Entry { uuid: "a3c87502-8ed3-4bdf-8a39-a01bebede295", name: "Active Slot" },
    Uuid128Entry { uuid: "a3c87503-8ed3-4bdf-8a39-a01bebede295", name: "Advertising Interval" },
    Uuid128Entry { uuid: "a3c87504-8ed3-4bdf-8a39-a01bebede295", name: "Radio Tx Power" },
    Uuid128Entry {
        uuid: "a3c87505-8ed3-4bdf-8a39-a01bebede295",
        name: "(Advanced) Advertised Tx Power",
    },
    Uuid128Entry { uuid: "a3c87506-8ed3-4bdf-8a39-a01bebede295", name: "Lock State" },
    Uuid128Entry { uuid: "a3c87507-8ed3-4bdf-8a39-a01bebede295", name: "Unlock" },
    Uuid128Entry { uuid: "a3c87508-8ed3-4bdf-8a39-a01bebede295", name: "Public ECDH Key" },
    Uuid128Entry { uuid: "a3c87509-8ed3-4bdf-8a39-a01bebede295", name: "EID Identity Key" },
    Uuid128Entry { uuid: "a3c8750a-8ed3-4bdf-8a39-a01bebede295", name: "ADV Slot Data" },
    Uuid128Entry { uuid: "a3c8750b-8ed3-4bdf-8a39-a01bebede295", name: "(Advanced) Factory reset" },
    Uuid128Entry {
        uuid: "a3c8750c-8ed3-4bdf-8a39-a01bebede295",
        name: "(Advanced) Remain Connectable",
    },
    Uuid128Entry {
        uuid: "e95d0753-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Accelerometer Service",
    },
    Uuid128Entry {
        uuid: "e95dca4b-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Accelerometer Data",
    },
    Uuid128Entry {
        uuid: "e95dfb24-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Accelerometer Period",
    },
    Uuid128Entry {
        uuid: "e95df2d8-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Magnetometer Service",
    },
    Uuid128Entry {
        uuid: "e95dfb11-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Magnetometer Data",
    },
    Uuid128Entry {
        uuid: "e95d386c-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Magnetometer Period",
    },
    Uuid128Entry {
        uuid: "e95d9715-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Magnetometer Bearing",
    },
    Uuid128Entry { uuid: "e95d9882-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Button Service" },
    Uuid128Entry { uuid: "e95dda90-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Button A State" },
    Uuid128Entry { uuid: "e95dda91-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Button B State" },
    Uuid128Entry { uuid: "e95d127b-251d-470a-a062-fa1922dfa9a8", name: "MicroBit IO PIN Service" },
    Uuid128Entry { uuid: "e95d8d00-251d-470a-a062-fa1922dfa9a8", name: "MicroBit PIN Data" },
    Uuid128Entry {
        uuid: "e95d5899-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit PIN AD Configuration",
    },
    Uuid128Entry { uuid: "e95dd822-251d-470a-a062-fa1922dfa9a8", name: "MicroBit PWM Control" },
    Uuid128Entry { uuid: "e95dd91d-251d-470a-a062-fa1922dfa9a8", name: "MicroBit LED Service" },
    Uuid128Entry {
        uuid: "e95d7b77-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit LED Matrix state",
    },
    Uuid128Entry { uuid: "e95d93ee-251d-470a-a062-fa1922dfa9a8", name: "MicroBit LED Text" },
    Uuid128Entry { uuid: "e95d0d2d-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Scrolling Delay" },
    Uuid128Entry { uuid: "e95d93af-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Event Service" },
    Uuid128Entry { uuid: "e95db84c-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Requirements" },
    Uuid128Entry { uuid: "e95d9775-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Event Data" },
    Uuid128Entry {
        uuid: "e95d23c4-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Client Requirements",
    },
    Uuid128Entry { uuid: "e95d5404-251d-470a-a062-fa1922dfa9a8", name: "MicroBit Client Events" },
    Uuid128Entry {
        uuid: "e95d93b0-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit DFU Control Service",
    },
    Uuid128Entry { uuid: "e95d93b1-251d-470a-a062-fa1922dfa9a8", name: "MicroBit DFU Control" },
    Uuid128Entry {
        uuid: "e95d6100-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Temperature Service",
    },
    Uuid128Entry {
        uuid: "e95d1b25-251d-470a-a062-fa1922dfa9a8",
        name: "MicroBit Temperature Period",
    },
    Uuid128Entry { uuid: "6e400001-b5a3-f393-e0a9-e50e24dcca9e", name: "Nordic UART Service" },
    Uuid128Entry { uuid: "6e400002-b5a3-f393-e0a9-e50e24dcca9e", name: "Nordic UART TX" },
    Uuid128Entry { uuid: "6e400003-b5a3-f393-e0a9-e50e24dcca9e", name: "Nordic UART RX" },
    Uuid128Entry { uuid: "d4992530-b9ec-469f-ab01-6c481c47da1c", name: "BlueZ Experimental Debug" },
    Uuid128Entry {
        uuid: "671b10b5-42c0-4696-9227-eb28d1b049d6",
        name: "BlueZ Experimental Simultaneous Central and Peripheral",
    },
    Uuid128Entry {
        uuid: "15c0a148-c273-11ea-b3de-0242ac130004",
        name: "BlueZ Experimental LL privacy",
    },
    Uuid128Entry {
        uuid: "330859bc-7506-492d-9370-9a6f0614037f",
        name: "BlueZ Experimental Bluetooth Quality Report",
    },
    Uuid128Entry { uuid: "a6695ace-ee7f-4fb9-881a-5fac66c629af", name: "BlueZ Offload Codecs" },
    Uuid128Entry {
        uuid: "6fbaf188-05e0-496a-9885-d6ddfdb4e03e",
        name: "BlueZ Experimental ISO Socket",
    },
];

/// Entry in the Bluetooth appearance lookup table.
struct AppearanceEntry {
    val: u16,
    generic: bool,
    name: &'static str,
}

/// Lookup table for Bluetooth appearance values.
/// Values are computed as (category << 6) | (subcategory & 0x3F).
static APPEARANCE_TABLE: &[AppearanceEntry] = &[
    AppearanceEntry { val: 0x0000, generic: true, name: "Unknown" },
    AppearanceEntry { val: 0x0040, generic: true, name: "Phone" },
    AppearanceEntry { val: 0x0080, generic: true, name: "Computer" },
    AppearanceEntry { val: 0x0081, generic: false, name: "Desktop Workstation" },
    AppearanceEntry { val: 0x0082, generic: false, name: "Server-class Computer" },
    AppearanceEntry { val: 0x0083, generic: false, name: "Laptop" },
    AppearanceEntry { val: 0x0084, generic: false, name: "Handheld PC/PDA (clamshell)" },
    AppearanceEntry { val: 0x0085, generic: false, name: "Palm-size PC/PDA" },
    AppearanceEntry { val: 0x0086, generic: false, name: "Wearable computer (watch size)" },
    AppearanceEntry { val: 0x0087, generic: false, name: "Tablet" },
    AppearanceEntry { val: 0x0088, generic: false, name: "Docking Station" },
    AppearanceEntry { val: 0x0089, generic: false, name: "All in One" },
    AppearanceEntry { val: 0x008a, generic: false, name: "Blade Server" },
    AppearanceEntry { val: 0x008b, generic: false, name: "Convertible" },
    AppearanceEntry { val: 0x008c, generic: false, name: "Detachable" },
    AppearanceEntry { val: 0x008d, generic: false, name: "IoT Gateway" },
    AppearanceEntry { val: 0x008e, generic: false, name: "Mini PC" },
    AppearanceEntry { val: 0x008f, generic: false, name: "Stick PC" },
    AppearanceEntry { val: 0x00c0, generic: true, name: "Watch" },
    AppearanceEntry { val: 0x00c1, generic: false, name: "Sports Watch" },
    AppearanceEntry { val: 0x00c2, generic: false, name: "Smartwatch" },
    AppearanceEntry { val: 0x0100, generic: true, name: "Clock" },
    AppearanceEntry { val: 0x0140, generic: true, name: "Display" },
    AppearanceEntry { val: 0x0180, generic: true, name: "Remote Control" },
    AppearanceEntry { val: 0x01c0, generic: true, name: "Eye-glasses" },
    AppearanceEntry { val: 0x0200, generic: true, name: "Tag" },
    AppearanceEntry { val: 0x0240, generic: true, name: "Keyring" },
    AppearanceEntry { val: 0x0280, generic: true, name: "Media Player" },
    AppearanceEntry { val: 0x02c0, generic: true, name: "Barcode Scanner" },
    AppearanceEntry { val: 0x0300, generic: true, name: "Thermometer" },
    AppearanceEntry { val: 0x0301, generic: false, name: "Ear Thermometer" },
    AppearanceEntry { val: 0x0340, generic: true, name: "Heart Rate Sensor" },
    AppearanceEntry { val: 0x0341, generic: false, name: "Heart Rate Belt" },
    AppearanceEntry { val: 0x0380, generic: true, name: "Blood Pressure" },
    AppearanceEntry { val: 0x0381, generic: false, name: "Arm Blood Pressure" },
    AppearanceEntry { val: 0x0382, generic: false, name: "Wrist Blood Pressure" },
    AppearanceEntry { val: 0x03c0, generic: true, name: "Human Interface Device" },
    AppearanceEntry { val: 0x03c1, generic: false, name: "Keyboard" },
    AppearanceEntry { val: 0x03c2, generic: false, name: "Mouse" },
    AppearanceEntry { val: 0x03c3, generic: false, name: "Joystick" },
    AppearanceEntry { val: 0x03c4, generic: false, name: "Gamepad" },
    AppearanceEntry { val: 0x03c5, generic: false, name: "Digitizer Tablet" },
    AppearanceEntry { val: 0x03c6, generic: false, name: "Card Reader" },
    AppearanceEntry { val: 0x03c7, generic: false, name: "Digital Pen" },
    AppearanceEntry { val: 0x03c8, generic: false, name: "Barcode Scanner" },
    AppearanceEntry { val: 0x03c9, generic: false, name: "Touchpad" },
    AppearanceEntry { val: 0x03ca, generic: false, name: "Presentation Remote" },
    AppearanceEntry { val: 0x0400, generic: true, name: "Glucose Meter" },
    AppearanceEntry { val: 0x0440, generic: true, name: "Running Walking Sensor" },
    AppearanceEntry { val: 0x0441, generic: false, name: "In-Shoe Running Walking Sensor" },
    AppearanceEntry { val: 0x0442, generic: false, name: "On-Shoe Running Walking Sensor" },
    AppearanceEntry { val: 0x0443, generic: false, name: "On-Hip Running Walking Sensor" },
    AppearanceEntry { val: 0x0480, generic: true, name: "Cycling" },
    AppearanceEntry { val: 0x0481, generic: false, name: "Cycling Computer" },
    AppearanceEntry { val: 0x0482, generic: false, name: "Speed Sensor" },
    AppearanceEntry { val: 0x0483, generic: false, name: "Cadence Sensor" },
    AppearanceEntry { val: 0x0484, generic: false, name: "Power Sensor" },
    AppearanceEntry { val: 0x0485, generic: false, name: "Speed and Cadence Sensor" },
    AppearanceEntry { val: 0x04c0, generic: true, name: "Control Device" },
    AppearanceEntry { val: 0x04c1, generic: false, name: "Switch" },
    AppearanceEntry { val: 0x04c2, generic: false, name: "Multi-switch" },
    AppearanceEntry { val: 0x04c3, generic: false, name: "Button" },
    AppearanceEntry { val: 0x04c4, generic: false, name: "Slider" },
    AppearanceEntry { val: 0x04c5, generic: false, name: "Rotary Switch" },
    AppearanceEntry { val: 0x04c6, generic: false, name: "Touch Panel" },
    AppearanceEntry { val: 0x04c7, generic: false, name: "Single Switch" },
    AppearanceEntry { val: 0x04c8, generic: false, name: "Double Switch" },
    AppearanceEntry { val: 0x04c9, generic: false, name: "Triple Switch" },
    AppearanceEntry { val: 0x04ca, generic: false, name: "Battery Switch" },
    AppearanceEntry { val: 0x04cb, generic: false, name: "Energy Harvesting Switch" },
    AppearanceEntry { val: 0x04cc, generic: false, name: "Push Button" },
    AppearanceEntry { val: 0x04cd, generic: false, name: "Dial" },
    AppearanceEntry { val: 0x0500, generic: true, name: "Network Device" },
    AppearanceEntry { val: 0x0501, generic: false, name: "Access Point" },
    AppearanceEntry { val: 0x0502, generic: false, name: "Mesh Device" },
    AppearanceEntry { val: 0x0503, generic: false, name: "Mesh Network Proxy" },
    AppearanceEntry { val: 0x0540, generic: true, name: "Sensor" },
    AppearanceEntry { val: 0x0541, generic: false, name: "Motion Sensor" },
    AppearanceEntry { val: 0x0542, generic: false, name: "Air quality Sensor" },
    AppearanceEntry { val: 0x0543, generic: false, name: "Temperature Sensor" },
    AppearanceEntry { val: 0x0544, generic: false, name: "Humidity Sensor" },
    AppearanceEntry { val: 0x0545, generic: false, name: "Leak Sensor" },
    AppearanceEntry { val: 0x0546, generic: false, name: "Smoke Sensor" },
    AppearanceEntry { val: 0x0547, generic: false, name: "Occupancy Sensor" },
    AppearanceEntry { val: 0x0548, generic: false, name: "Contact Sensor" },
    AppearanceEntry { val: 0x0549, generic: false, name: "Carbon Monoxide Sensor" },
    AppearanceEntry { val: 0x054a, generic: false, name: "Carbon Dioxide Sensor" },
    AppearanceEntry { val: 0x054b, generic: false, name: "Ambient Light Sensor" },
    AppearanceEntry { val: 0x054c, generic: false, name: "Energy Sensor" },
    AppearanceEntry { val: 0x054d, generic: false, name: "Color Light Sensor" },
    AppearanceEntry { val: 0x054e, generic: false, name: "Rain Sensor" },
    AppearanceEntry { val: 0x054f, generic: false, name: "Fire Sensor" },
    AppearanceEntry { val: 0x0550, generic: false, name: "Wind Sensor" },
    AppearanceEntry { val: 0x0551, generic: false, name: "Proximity Sensor" },
    AppearanceEntry { val: 0x0552, generic: false, name: "Multi-Sensor" },
    AppearanceEntry { val: 0x0553, generic: false, name: "Flush Mounted Sensor" },
    AppearanceEntry { val: 0x0554, generic: false, name: "Ceiling Mounted Sensor" },
    AppearanceEntry { val: 0x0555, generic: false, name: "Wall Mounted Sensor" },
    AppearanceEntry { val: 0x0556, generic: false, name: "Multisensor" },
    AppearanceEntry { val: 0x0557, generic: false, name: "Energy Meter" },
    AppearanceEntry { val: 0x0558, generic: false, name: "Flame Detector" },
    AppearanceEntry { val: 0x0559, generic: false, name: "Vehicle Tire Pressure Sensor" },
    AppearanceEntry { val: 0x0580, generic: true, name: "Light Fixtures" },
    AppearanceEntry { val: 0x0581, generic: false, name: "Wall Light" },
    AppearanceEntry { val: 0x0582, generic: false, name: "Ceiling Light" },
    AppearanceEntry { val: 0x0583, generic: false, name: "Floor Light" },
    AppearanceEntry { val: 0x0584, generic: false, name: "Cabinet Light" },
    AppearanceEntry { val: 0x0585, generic: false, name: "Desk Light" },
    AppearanceEntry { val: 0x0586, generic: false, name: "Troffer Light" },
    AppearanceEntry { val: 0x0587, generic: false, name: "Pendant Light" },
    AppearanceEntry { val: 0x0588, generic: false, name: "In-ground Light" },
    AppearanceEntry { val: 0x0589, generic: false, name: "Flood Light" },
    AppearanceEntry { val: 0x058a, generic: false, name: "Underwater Light" },
    AppearanceEntry { val: 0x058b, generic: false, name: "Bollard with Light" },
    AppearanceEntry { val: 0x058c, generic: false, name: "Pathway Light" },
    AppearanceEntry { val: 0x058d, generic: false, name: "Garden Light" },
    AppearanceEntry { val: 0x058e, generic: false, name: "Pole-top Light" },
    AppearanceEntry { val: 0x058f, generic: false, name: "Spotlight" },
    AppearanceEntry { val: 0x0590, generic: false, name: "Linear Light" },
    AppearanceEntry { val: 0x0591, generic: false, name: "Street Light" },
    AppearanceEntry { val: 0x0592, generic: false, name: "Shelves Light" },
    AppearanceEntry { val: 0x0593, generic: false, name: "Bay Light" },
    AppearanceEntry { val: 0x0594, generic: false, name: "Emergency Exit Light" },
    AppearanceEntry { val: 0x0595, generic: false, name: "Light Controller" },
    AppearanceEntry { val: 0x0596, generic: false, name: "Light Driver" },
    AppearanceEntry { val: 0x0597, generic: false, name: "Bulb" },
    AppearanceEntry { val: 0x0598, generic: false, name: "Low-bay Light" },
    AppearanceEntry { val: 0x0599, generic: false, name: "High-bay Light" },
    AppearanceEntry { val: 0x05c0, generic: true, name: "Fan" },
    AppearanceEntry { val: 0x05c1, generic: false, name: "Ceiling Fan" },
    AppearanceEntry { val: 0x05c2, generic: false, name: "Axial Fan" },
    AppearanceEntry { val: 0x05c3, generic: false, name: "Exhaust Fan" },
    AppearanceEntry { val: 0x05c4, generic: false, name: "Pedestal Fan" },
    AppearanceEntry { val: 0x05c5, generic: false, name: "Desk Fan" },
    AppearanceEntry { val: 0x05c6, generic: false, name: "Wall Fan" },
    AppearanceEntry { val: 0x0600, generic: true, name: "HVAC" },
    AppearanceEntry { val: 0x0601, generic: false, name: "Thermostat" },
    AppearanceEntry { val: 0x0602, generic: false, name: "Humidifier" },
    AppearanceEntry { val: 0x0603, generic: false, name: "De-humidifier" },
    AppearanceEntry { val: 0x0604, generic: false, name: "Heater" },
    AppearanceEntry { val: 0x0605, generic: false, name: "Radiator" },
    AppearanceEntry { val: 0x0606, generic: false, name: "Boiler" },
    AppearanceEntry { val: 0x0607, generic: false, name: "Heat Pump" },
    AppearanceEntry { val: 0x0608, generic: false, name: "Infrared Heater" },
    AppearanceEntry { val: 0x0609, generic: false, name: "Radiant Panel Heater" },
    AppearanceEntry { val: 0x060a, generic: false, name: "Fan Heater" },
    AppearanceEntry { val: 0x060b, generic: false, name: "Air Curtain" },
    AppearanceEntry { val: 0x0640, generic: true, name: "Air Conditioning" },
    AppearanceEntry { val: 0x0680, generic: true, name: "Humidifier" },
    AppearanceEntry { val: 0x06c0, generic: true, name: "Heating" },
    AppearanceEntry { val: 0x06c1, generic: false, name: "Radiator" },
    AppearanceEntry { val: 0x06c2, generic: false, name: "Boiler" },
    AppearanceEntry { val: 0x06c3, generic: false, name: "Heat Pump" },
    AppearanceEntry { val: 0x06c4, generic: false, name: "Infrared Heater" },
    AppearanceEntry { val: 0x06c5, generic: false, name: "Radiant Panel Heater" },
    AppearanceEntry { val: 0x06c6, generic: false, name: "Fan Heater" },
    AppearanceEntry { val: 0x06c7, generic: false, name: "Air Curtain" },
    AppearanceEntry { val: 0x0700, generic: true, name: "Access Control" },
    AppearanceEntry { val: 0x0701, generic: false, name: "Access Door" },
    AppearanceEntry { val: 0x0702, generic: false, name: "Garage Door" },
    AppearanceEntry { val: 0x0703, generic: false, name: "Emergency Exit Door" },
    AppearanceEntry { val: 0x0704, generic: false, name: "Access Lock" },
    AppearanceEntry { val: 0x0705, generic: false, name: "Elevator" },
    AppearanceEntry { val: 0x0706, generic: false, name: "Window" },
    AppearanceEntry { val: 0x0707, generic: false, name: "Entrance Gate" },
    AppearanceEntry { val: 0x0708, generic: false, name: "Door Lock" },
    AppearanceEntry { val: 0x0709, generic: false, name: "Locker" },
    AppearanceEntry { val: 0x0740, generic: true, name: "Motorized Device" },
    AppearanceEntry { val: 0x0741, generic: false, name: "Motorized Gate" },
    AppearanceEntry { val: 0x0742, generic: false, name: "Awning" },
    AppearanceEntry { val: 0x0743, generic: false, name: "Blinds or Shades" },
    AppearanceEntry { val: 0x0744, generic: false, name: "Curtains" },
    AppearanceEntry { val: 0x0745, generic: false, name: "Screen" },
    AppearanceEntry { val: 0x0780, generic: true, name: "Power Device" },
    AppearanceEntry { val: 0x0781, generic: false, name: "Power Outlet" },
    AppearanceEntry { val: 0x0782, generic: false, name: "Power Strip" },
    AppearanceEntry { val: 0x0783, generic: false, name: "Plug" },
    AppearanceEntry { val: 0x0784, generic: false, name: "Power Supply" },
    AppearanceEntry { val: 0x0785, generic: false, name: "LED Driver" },
    AppearanceEntry { val: 0x0786, generic: false, name: "Fluorescent Lamp Gear" },
    AppearanceEntry { val: 0x0787, generic: false, name: "HID Lamp Gear" },
    AppearanceEntry { val: 0x0788, generic: false, name: "Charge Case" },
    AppearanceEntry { val: 0x0789, generic: false, name: "Power Bank" },
    AppearanceEntry { val: 0x07c0, generic: true, name: "Light Source" },
    AppearanceEntry { val: 0x07c1, generic: false, name: "Incandescent Light Bulb" },
    AppearanceEntry { val: 0x07c2, generic: false, name: "LED Lamp" },
    AppearanceEntry { val: 0x07c3, generic: false, name: "HID Lamp" },
    AppearanceEntry { val: 0x07c4, generic: false, name: "Fluorescent Lamp" },
    AppearanceEntry { val: 0x07c5, generic: false, name: "LED Array" },
    AppearanceEntry { val: 0x07c6, generic: false, name: "Multi-Color LED Array" },
    AppearanceEntry { val: 0x07c7, generic: false, name: "Low voltage halogen" },
    AppearanceEntry { val: 0x07c8, generic: false, name: "Organic light emitting diode (OLED)" },
    AppearanceEntry { val: 0x0800, generic: true, name: "Window Covering" },
    AppearanceEntry { val: 0x0801, generic: false, name: "Window Shades" },
    AppearanceEntry { val: 0x0802, generic: false, name: "Window Blinds" },
    AppearanceEntry { val: 0x0803, generic: false, name: "Window Awning" },
    AppearanceEntry { val: 0x0804, generic: false, name: "Window Curtain" },
    AppearanceEntry { val: 0x0805, generic: false, name: "Exterior Shutter" },
    AppearanceEntry { val: 0x0806, generic: false, name: "Exterior Screen" },
    AppearanceEntry { val: 0x0840, generic: true, name: "Audio Sink" },
    AppearanceEntry { val: 0x0841, generic: false, name: "Standalone Speaker" },
    AppearanceEntry { val: 0x0842, generic: false, name: "Soundbar" },
    AppearanceEntry { val: 0x0843, generic: false, name: "Bookshelf Speaker" },
    AppearanceEntry { val: 0x0844, generic: false, name: "Standmounted Speaker" },
    AppearanceEntry { val: 0x0845, generic: false, name: "Speakerphone" },
    AppearanceEntry { val: 0x0880, generic: true, name: "Audio Source" },
    AppearanceEntry { val: 0x0881, generic: false, name: "Microphone" },
    AppearanceEntry { val: 0x0882, generic: false, name: "Alarm" },
    AppearanceEntry { val: 0x0883, generic: false, name: "Bell" },
    AppearanceEntry { val: 0x0884, generic: false, name: "Horn" },
    AppearanceEntry { val: 0x0885, generic: false, name: "Broadcasting Device" },
    AppearanceEntry { val: 0x0886, generic: false, name: "Service Desk" },
    AppearanceEntry { val: 0x0887, generic: false, name: "Kiosk" },
    AppearanceEntry { val: 0x0888, generic: false, name: "Broadcasting Room" },
    AppearanceEntry { val: 0x0889, generic: false, name: "Auditorium" },
    AppearanceEntry { val: 0x08c0, generic: true, name: "Motorized Vehicle" },
    AppearanceEntry { val: 0x08c1, generic: false, name: "Car" },
    AppearanceEntry { val: 0x08c2, generic: false, name: "Large Goods Vehicle" },
    AppearanceEntry { val: 0x08c3, generic: false, name: "2-Wheeled Vehicle" },
    AppearanceEntry { val: 0x08c4, generic: false, name: "Motorbike" },
    AppearanceEntry { val: 0x08c5, generic: false, name: "Scooter" },
    AppearanceEntry { val: 0x08c6, generic: false, name: "Moped" },
    AppearanceEntry { val: 0x08c7, generic: false, name: "3-Wheeled Vehicle" },
    AppearanceEntry { val: 0x08c8, generic: false, name: "Light Vehicle" },
    AppearanceEntry { val: 0x08c9, generic: false, name: "Quad Bike" },
    AppearanceEntry { val: 0x08ca, generic: false, name: "Minibus" },
    AppearanceEntry { val: 0x08cb, generic: false, name: "Bus" },
    AppearanceEntry { val: 0x08cc, generic: false, name: "Trolley" },
    AppearanceEntry { val: 0x08cd, generic: false, name: "Agricultural Vehicle" },
    AppearanceEntry { val: 0x08ce, generic: false, name: "Camper / Caravan" },
    AppearanceEntry { val: 0x08cf, generic: false, name: "Recreational Vehicle / Motor Home" },
    AppearanceEntry { val: 0x0900, generic: true, name: "Domestic Appliance" },
    AppearanceEntry { val: 0x0901, generic: false, name: "Refrigerator" },
    AppearanceEntry { val: 0x0902, generic: false, name: "Freezer" },
    AppearanceEntry { val: 0x0903, generic: false, name: "Oven" },
    AppearanceEntry { val: 0x0904, generic: false, name: "Microwave" },
    AppearanceEntry { val: 0x0905, generic: false, name: "Toaster" },
    AppearanceEntry { val: 0x0906, generic: false, name: "Washing Machine" },
    AppearanceEntry { val: 0x0907, generic: false, name: "Dryer" },
    AppearanceEntry { val: 0x0908, generic: false, name: "Coffee maker" },
    AppearanceEntry { val: 0x0909, generic: false, name: "Clothes iron" },
    AppearanceEntry { val: 0x090a, generic: false, name: "Curling iron" },
    AppearanceEntry { val: 0x090b, generic: false, name: "Hair dryer" },
    AppearanceEntry { val: 0x090c, generic: false, name: "Vacuum cleaner" },
    AppearanceEntry { val: 0x090d, generic: false, name: "Robotic vacuum cleaner" },
    AppearanceEntry { val: 0x090e, generic: false, name: "Rice cooker" },
    AppearanceEntry { val: 0x090f, generic: false, name: "Clothes steamer" },
    AppearanceEntry { val: 0x0940, generic: true, name: "Wearable Audio Device" },
    AppearanceEntry { val: 0x0941, generic: false, name: "Earbud" },
    AppearanceEntry { val: 0x0942, generic: false, name: "Headset" },
    AppearanceEntry { val: 0x0943, generic: false, name: "Headphones" },
    AppearanceEntry { val: 0x0944, generic: false, name: "Neck Band" },
    AppearanceEntry { val: 0x0945, generic: false, name: "Left Earbud" },
    AppearanceEntry { val: 0x0946, generic: false, name: "Right Earbud" },
    AppearanceEntry { val: 0x0980, generic: true, name: "Aircraft" },
    AppearanceEntry { val: 0x0981, generic: false, name: "Light Aircraft" },
    AppearanceEntry { val: 0x0982, generic: false, name: "Microlight" },
    AppearanceEntry { val: 0x0983, generic: false, name: "Paraglider" },
    AppearanceEntry { val: 0x0984, generic: false, name: "Large Passenger Aircraft" },
    AppearanceEntry { val: 0x09c0, generic: true, name: "AV Equipment" },
    AppearanceEntry { val: 0x09c1, generic: false, name: "Amplifier" },
    AppearanceEntry { val: 0x09c2, generic: false, name: "Receiver" },
    AppearanceEntry { val: 0x09c3, generic: false, name: "Radio" },
    AppearanceEntry { val: 0x09c4, generic: false, name: "Tuner" },
    AppearanceEntry { val: 0x09c5, generic: false, name: "Turntable" },
    AppearanceEntry { val: 0x09c6, generic: false, name: "CD Player" },
    AppearanceEntry { val: 0x09c7, generic: false, name: "DVD Player" },
    AppearanceEntry { val: 0x09c8, generic: false, name: "Bluray Player" },
    AppearanceEntry { val: 0x09c9, generic: false, name: "Optical Disc Player" },
    AppearanceEntry { val: 0x09ca, generic: false, name: "Set-Top Box" },
    AppearanceEntry { val: 0x0a00, generic: true, name: "Display Equipment" },
    AppearanceEntry { val: 0x0a01, generic: false, name: "Television" },
    AppearanceEntry { val: 0x0a02, generic: false, name: "Monitor" },
    AppearanceEntry { val: 0x0a03, generic: false, name: "Projector" },
    AppearanceEntry { val: 0x0a40, generic: true, name: "Hearing aid" },
    AppearanceEntry { val: 0x0a41, generic: false, name: "In-ear hearing aid" },
    AppearanceEntry { val: 0x0a42, generic: false, name: "Behind-ear hearing aid" },
    AppearanceEntry { val: 0x0a43, generic: false, name: "Cochlear Implant" },
    AppearanceEntry { val: 0x0a80, generic: true, name: "Gaming" },
    AppearanceEntry { val: 0x0a81, generic: false, name: "Home Video Game Console" },
    AppearanceEntry { val: 0x0a82, generic: false, name: "Portable handheld console" },
    AppearanceEntry { val: 0x0ac0, generic: true, name: "Signage" },
    AppearanceEntry { val: 0x0ac1, generic: false, name: "Digital Signage" },
    AppearanceEntry { val: 0x0ac2, generic: false, name: "Electronic Label" },
    AppearanceEntry { val: 0x0c40, generic: true, name: "Pulse Oximeter" },
    AppearanceEntry { val: 0x0c41, generic: false, name: "Fingertip Pulse Oximeter" },
    AppearanceEntry { val: 0x0c42, generic: false, name: "Wrist Worn Pulse Oximeter" },
    AppearanceEntry { val: 0x0c80, generic: true, name: "Weight Scale" },
    AppearanceEntry { val: 0x0cc0, generic: true, name: "Personal Mobility Device" },
    AppearanceEntry { val: 0x0cc1, generic: false, name: "Powered Wheelchair" },
    AppearanceEntry { val: 0x0cc2, generic: false, name: "Mobility Scooter" },
    AppearanceEntry { val: 0x0d00, generic: true, name: "Continuous Glucose Monitor" },
    AppearanceEntry { val: 0x0d40, generic: true, name: "Insulin Pump" },
    AppearanceEntry { val: 0x0d41, generic: false, name: "Insulin Pump, durable pump" },
    AppearanceEntry { val: 0x0d44, generic: false, name: "Insulin Pump, patch pump" },
    AppearanceEntry { val: 0x0d48, generic: false, name: "Insulin Pen" },
    AppearanceEntry { val: 0x0d80, generic: true, name: "Medication Delivery" },
    AppearanceEntry { val: 0x0dc0, generic: true, name: "Spirometer" },
    AppearanceEntry { val: 0x0dc1, generic: false, name: "Handheld Spirometer" },
    AppearanceEntry { val: 0x1440, generic: true, name: "Outdoor Sports Activity" },
    AppearanceEntry { val: 0x1441, generic: false, name: "Location Display" },
    AppearanceEntry { val: 0x1442, generic: false, name: "Location and Navigation Display" },
    AppearanceEntry { val: 0x1443, generic: false, name: "Location Pod" },
    AppearanceEntry { val: 0x1444, generic: false, name: "Location and Navigation Pod" },
    AppearanceEntry { val: 0x1480, generic: true, name: "Industrial Measurement Device" },
    AppearanceEntry { val: 0x1481, generic: false, name: "Torque Testing Device" },
    AppearanceEntry { val: 0x1482, generic: false, name: "Caliper" },
    AppearanceEntry { val: 0x1483, generic: false, name: "Dial Indicator" },
    AppearanceEntry { val: 0x1484, generic: false, name: "Micrometer" },
    AppearanceEntry { val: 0x1485, generic: false, name: "Height Gauge" },
    AppearanceEntry { val: 0x1486, generic: false, name: "Force Gauge" },
    AppearanceEntry { val: 0x14c0, generic: true, name: "Industrial Tools" },
    AppearanceEntry { val: 0x14c1, generic: false, name: "Machine Tool Holder" },
    AppearanceEntry { val: 0x14c2, generic: false, name: "Generic Clamping Device" },
    AppearanceEntry { val: 0x14c3, generic: false, name: "Clamping Jaws/Jaw Chuck" },
    AppearanceEntry { val: 0x14c4, generic: false, name: "Clamping (Collet) Chuck" },
    AppearanceEntry { val: 0x14c5, generic: false, name: "Clamping Mandrel" },
    AppearanceEntry { val: 0x14c6, generic: false, name: "Vise" },
    AppearanceEntry { val: 0x14c7, generic: false, name: "Zero-Point Clamping System" },
    AppearanceEntry { val: 0x14c8, generic: false, name: "Torque Wrench" },
    AppearanceEntry { val: 0x14c9, generic: false, name: "Torque Screwdriver" },
    AppearanceEntry { val: 0x1500, generic: true, name: "Cookware Device" },
    AppearanceEntry { val: 0x1501, generic: false, name: "Pot and Jugs" },
    AppearanceEntry { val: 0x1502, generic: false, name: "Pressure Cooker" },
    AppearanceEntry { val: 0x1503, generic: false, name: "Slow Cooker" },
    AppearanceEntry { val: 0x1504, generic: false, name: "Steam Cooker" },
    AppearanceEntry { val: 0x1505, generic: false, name: "Saucepan" },
    AppearanceEntry { val: 0x1506, generic: false, name: "Frying Pan" },
    AppearanceEntry { val: 0x1507, generic: false, name: "Casserole" },
    AppearanceEntry { val: 0x1508, generic: false, name: "Dutch Oven" },
    AppearanceEntry { val: 0x1509, generic: false, name: "Grill Pan/Raclette Grill/Griddle Pan" },
    AppearanceEntry { val: 0x150a, generic: false, name: "Braising Pan" },
    AppearanceEntry { val: 0x150b, generic: false, name: "Wok Pan" },
    AppearanceEntry { val: 0x150c, generic: false, name: "Paella Pan" },
    AppearanceEntry { val: 0x150d, generic: false, name: "Crepe Pan" },
    AppearanceEntry { val: 0x150e, generic: false, name: "Tagine" },
    AppearanceEntry { val: 0x150f, generic: false, name: "Fondue" },
    AppearanceEntry { val: 0x1510, generic: false, name: "Lid" },
    AppearanceEntry { val: 0x1511, generic: false, name: "Wired Probe" },
    AppearanceEntry { val: 0x1512, generic: false, name: "Wireless Probe" },
    AppearanceEntry { val: 0x1513, generic: false, name: "Baking Molds" },
    AppearanceEntry { val: 0x1514, generic: false, name: "Baking Tray" },
];

/// Looks up a human-readable name for a 16-bit UUID.
///
/// Performs a linear scan of the UUID16 lookup table.
/// Returns "Unknown" if the UUID is not found.
pub fn bt_uuid16_to_str(uuid: u16) -> &'static str {
    for entry in UUID16_TABLE {
        if entry.uuid == uuid {
            return entry.name;
        }
    }
    "Unknown"
}

/// Looks up a human-readable name for a 32-bit UUID.
///
/// If the high 16 bits are zero, delegates to `bt_uuid16_to_str`.
/// Otherwise returns "Unknown".
pub fn bt_uuid32_to_str(uuid: u32) -> &'static str {
    if (uuid >> 16) == 0 {
        return bt_uuid16_to_str(uuid as u16);
    }
    "Unknown"
}

/// Looks up a human-readable name for a 128-bit UUID in BlueZ wire format.
///
/// Converts the byte array to a UUID string using BlueZ's specific byte layout
/// (little-endian wire format), then delegates to `bt_uuidstr_to_str`.
pub fn bt_uuid128_to_str(uuid: &[u8; 16]) -> &'static str {
    let uuid_str = format_uuid128_bytes(uuid);
    bt_uuidstr_to_str(&uuid_str).unwrap_or("Unknown")
}

/// Resolves a UUID string to a human-readable name.
///
/// Accepts multiple formats:
/// - Short numeric strings (e.g., "6144", "0x1800") — parsed as integer,
///   then looked up as UUID16 or UUID32.
/// - Full 36-character UUID strings (e.g., "00001800-0000-1000-8000-00805f9b34fb")
///   — searched in the UUID128 table first, then checked for Bluetooth SIG base
///   suffix to extract and look up the 32-bit prefix.
///
/// Returns `None` on parse failure, `Some("Vendor specific")` for non-SIG 128-bit
/// UUIDs not in the table.
pub fn bt_uuidstr_to_str(uuid: &str) -> Option<&'static str> {
    let trimmed = uuid.trim();
    if trimmed.len() < 36 {
        // Short form: parse as integer
        let val = parse_uuid_int(trimmed)?;
        if val > u32::from(u16::MAX) {
            return Some(bt_uuid32_to_str(val));
        }
        return Some(bt_uuid16_to_str(val as u16));
    }

    if trimmed.len() != 36 {
        return None;
    }

    // Full 128-bit UUID string — search UUID128 table (case-insensitive)
    for entry in UUID128_TABLE {
        if trimmed.eq_ignore_ascii_case(entry.uuid) {
            return Some(entry.name);
        }
    }

    // Check if it has the Bluetooth SIG base suffix
    if trimmed.len() > 8 {
        let suffix = &trimmed[8..];
        if suffix.eq_ignore_ascii_case(BT_UUID_BASE_SUFFIX) {
            // Extract the 32-bit prefix and look up
            if let Ok(val) = u32::from_str_radix(&trimmed[0..8], 16) {
                return Some(bt_uuid32_to_str(val));
            }
        }
    }

    Some("Vendor specific")
}

/// Resolves a Bluetooth appearance value to a human-readable name.
///
/// The appearance value encodes a category (bits 15-6) and subcategory (bits 5-0).
/// If an exact match is found, returns that name. Otherwise, falls back to the
/// most recent generic (subcategory 0) entry for the appropriate category.
pub fn bt_appear_to_str(appearance: u16) -> &'static str {
    let mut last_type: &str = "Unknown";

    for entry in APPEARANCE_TABLE {
        if entry.generic {
            if appearance < entry.val {
                break;
            }
            last_type = entry.name;
        }

        if entry.val == appearance {
            return entry.name;
        }
    }

    last_type
}
