// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite

use std::fmt;
use std::str::FromStr;

/// The Bluetooth Base UUID: 00000000-0000-1000-8000-00805F9B34FB
/// Stored in big-endian (network byte order), matching the C implementation.
const BLUETOOTH_BASE_UUID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
];

/// Offset within the 128-bit base UUID where 16-bit values are inserted.
const BASE_UUID16_OFFSET: usize = 2;
/// Offset within the 128-bit base UUID where 32-bit values are inserted.
const BASE_UUID32_OFFSET: usize = 0;

/// Bluetooth UUID type. Can represent 16-bit, 32-bit, or 128-bit UUIDs.
///
/// Corresponds to `bt_uuid_t` from `uuid.h`. The 128-bit representation
/// stores bytes in big-endian (network) order, matching the C implementation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Uuid {
    Uuid16(u16),
    Uuid32(u32),
    Uuid128([u8; 16]),
}

impl Uuid {
    /// Create a 16-bit UUID. Corresponds to `bt_uuid16_create()`.
    pub fn from_u16(value: u16) -> Self {
        Uuid::Uuid16(value)
    }

    /// Create a 32-bit UUID. Corresponds to `bt_uuid32_create()`.
    pub fn from_u32(value: u32) -> Self {
        Uuid::Uuid32(value)
    }

    /// Create a 128-bit UUID from big-endian bytes. Corresponds to `bt_uuid128_create()`.
    pub fn from_u128_bytes(bytes: [u8; 16]) -> Self {
        Uuid::Uuid128(bytes)
    }

    /// Convert to 128-bit representation. Corresponds to `bt_uuid_to_uuid128()`.
    pub fn to_uuid128(&self) -> [u8; 16] {
        match *self {
            Uuid::Uuid16(v) => {
                let mut out = BLUETOOTH_BASE_UUID;
                let be = v.to_be_bytes();
                out[BASE_UUID16_OFFSET] = be[0];
                out[BASE_UUID16_OFFSET + 1] = be[1];
                out
            }
            Uuid::Uuid32(v) => {
                let mut out = BLUETOOTH_BASE_UUID;
                let be = v.to_be_bytes();
                out[BASE_UUID32_OFFSET..BASE_UUID32_OFFSET + 4].copy_from_slice(&be);
                out
            }
            Uuid::Uuid128(bytes) => bytes,
        }
    }

    /// Compare two UUIDs by converting both to 128-bit. Corresponds to `bt_uuid_cmp()`.
    pub fn cmp_as_uuid128(&self, other: &Uuid) -> std::cmp::Ordering {
        self.to_uuid128().cmp(&other.to_uuid128())
    }

    /// Check equality after expanding both to 128-bit form.
    pub fn eq_as_uuid128(&self, other: &Uuid) -> bool {
        self.to_uuid128() == other.to_uuid128()
    }

    /// Returns the byte length of the UUID type (2, 4, or 16).
    /// Corresponds to `bt_uuid_len()`.
    /// A UUID always has a non-zero length, so no `is_empty` is provided.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Uuid::Uuid16(_) => 2,
            Uuid::Uuid32(_) => 4,
            Uuid::Uuid128(_) => 16,
        }
    }

    /// Convert to little-endian bytes for wire transmission.
    /// UUID16 → 2 bytes LE, UUID32 → promoted to UUID128 then reversed,
    /// UUID128 → 16 bytes reversed from big-endian storage.
    /// Corresponds to `bt_uuid_to_le()`.
    pub fn to_le_bytes(&self, dst: &mut [u8]) -> Result<(), crate::error::Error> {
        match *self {
            Uuid::Uuid16(v) => {
                if dst.len() < 2 {
                    return Err(crate::error::Error::InvalidLength);
                }
                dst[..2].copy_from_slice(&v.to_le_bytes());
            }
            Uuid::Uuid32(v) => {
                // UUID32 is promoted to UUID128, then byte-swapped to LE
                let uuid128 = Uuid::Uuid32(v).to_uuid128();
                if dst.len() < 16 {
                    return Err(crate::error::Error::InvalidLength);
                }
                bswap_128(&uuid128, &mut dst[..16]);
            }
            Uuid::Uuid128(bytes) => {
                if dst.len() < 16 {
                    return Err(crate::error::Error::InvalidLength);
                }
                bswap_128(&bytes, &mut dst[..16]);
            }
        }
        Ok(())
    }

    /// Format as the full 128-bit UUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
    fn format_as_uuid128(&self) -> String {
        let d = self.to_uuid128();
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            d[0], d[1], d[2], d[3],
            d[4], d[5],
            d[6], d[7],
            d[8], d[9],
            d[10], d[11], d[12], d[13], d[14], d[15]
        )
    }
}

/// Reverse 16 bytes (swap big-endian ↔ little-endian for 128-bit values).
/// Corresponds to `bswap_128()`.
fn bswap_128(src: &[u8; 16], dst: &mut [u8]) {
    for i in 0..16 {
        dst[15 - i] = src[i];
    }
}

/// Display as lowercase 128-bit UUID string. Corresponds to `bt_uuid_to_string()`.
impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_as_uuid128())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Uuid::Uuid16(v) => write!(f, "Uuid16(0x{:04x})", v),
            Uuid::Uuid32(v) => write!(f, "Uuid32(0x{:08x})", v),
            Uuid::Uuid128(_) => write!(f, "Uuid128({})", self),
        }
    }
}

/// Parse error for Bluetooth UUIDs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid UUID string")]
pub struct ParseUuidError;

/// Parse from string. Supports the same formats as `bt_string_to_uuid()`:
/// - 4 hex chars (optionally prefixed with "0x") → UUID16
/// - 8 hex chars (optionally prefixed with "0x") → UUID32
/// - Full 128-bit "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" → UUID128
///   (if it matches the Bluetooth base UUID pattern, compresses to UUID16)
impl FromStr for Uuid {
    type Err = ParseUuidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try 128-bit format first
        if is_uuid128(s) {
            if is_base_uuid128(s) {
                // Compress to UUID16
                let short = &s[4..8];
                let v = u16::from_str_radix(short, 16).map_err(|_| ParseUuidError)?;
                return Ok(Uuid::Uuid16(v));
            }
            return parse_uuid128(s);
        }

        // Strip optional "0x" prefix
        let hex = s.strip_prefix("0x").unwrap_or(s);

        match hex.len() {
            4 => {
                let v = u16::from_str_radix(hex, 16).map_err(|_| ParseUuidError)?;
                Ok(Uuid::Uuid16(v))
            }
            8 => {
                let v = u32::from_str_radix(hex, 16).map_err(|_| ParseUuidError)?;
                Ok(Uuid::Uuid32(v))
            }
            _ => Err(ParseUuidError),
        }
    }
}

/// Check if a string is in 128-bit UUID format: 8-4-4-4-12 hex with dashes.
fn is_uuid128(s: &str) -> bool {
    s.len() == 36
        && s.as_bytes()[8] == b'-'
        && s.as_bytes()[13] == b'-'
        && s.as_bytes()[18] == b'-'
        && s.as_bytes()[23] == b'-'
}

/// Check if a 128-bit UUID string matches the Bluetooth base UUID pattern,
/// meaning it can be compressed to a 16-bit UUID.
fn is_base_uuid128(s: &str) -> bool {
    if !is_uuid128(s) {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    lower.starts_with("0000")
        && lower[9..].eq_ignore_ascii_case("0000-1000-8000-00805f9b34fb")
}

/// Parse a full 128-bit UUID string into bytes.
fn parse_uuid128(s: &str) -> Result<Uuid, ParseUuidError> {
    // Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(ParseUuidError);
    }

    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ParseUuidError)?;
    }

    Ok(Uuid::Uuid128(bytes))
}

/// Compare two UUID strings by parsing and comparing as 128-bit.
/// Corresponds to `bt_uuid_strcmp()`.
pub fn uuid_strcmp(a: &str, b: &str) -> Result<std::cmp::Ordering, ParseUuidError> {
    let ua: Uuid = a.parse()?;
    let ub: Uuid = b.parse()?;
    Ok(ua.cmp_as_uuid128(&ub))
}

// ---- Well-known UUID constants ----
// Service UUIDs from uuid.h

pub const GAP_UUID: &str = "00001800-0000-1000-8000-00805f9b34fb";
pub const GATT_UUID: &str = "00001801-0000-1000-8000-00805f9b34fb";
pub const IMMEDIATE_ALERT_UUID: &str = "00001802-0000-1000-8000-00805f9b34fb";
pub const LINK_LOSS_UUID: &str = "00001803-0000-1000-8000-00805f9b34fb";
pub const TX_POWER_UUID: &str = "00001804-0000-1000-8000-00805f9b34fb";
pub const BATTERY_UUID: &str = "0000180f-0000-1000-8000-00805f9b34fb";
pub const DEVICE_INFORMATION_UUID: &str = "0000180a-0000-1000-8000-00805f9b34fb";
pub const HEART_RATE_UUID: &str = "0000180d-0000-1000-8000-00805f9b34fb";
pub const HEALTH_THERMOMETER_UUID: &str = "00001809-0000-1000-8000-00805f9b34fb";
pub const SCAN_PARAMETERS_UUID: &str = "00001813-0000-1000-8000-00805f9b34fb";
pub const CYCLING_SC_UUID: &str = "00001816-0000-1000-8000-00805f9b34fb";
pub const RAS_UUID: &str = "0000185b-0000-1000-8000-00805f9b34fb";

pub const HSP_HS_UUID: &str = "00001108-0000-1000-8000-00805f9b34fb";
pub const HSP_AG_UUID: &str = "00001112-0000-1000-8000-00805f9b34fb";
pub const HFP_HS_UUID: &str = "0000111e-0000-1000-8000-00805f9b34fb";
pub const HFP_AG_UUID: &str = "0000111f-0000-1000-8000-00805f9b34fb";
pub const ADVANCED_AUDIO_UUID: &str = "0000110d-0000-1000-8000-00805f9b34fb";
pub const A2DP_SOURCE_UUID: &str = "0000110a-0000-1000-8000-00805f9b34fb";
pub const A2DP_SINK_UUID: &str = "0000110b-0000-1000-8000-00805f9b34fb";
pub const AVRCP_REMOTE_UUID: &str = "0000110e-0000-1000-8000-00805f9b34fb";
pub const AVRCP_TARGET_UUID: &str = "0000110c-0000-1000-8000-00805f9b34fb";

pub const PANU_UUID: &str = "00001115-0000-1000-8000-00805f9b34fb";
pub const NAP_UUID: &str = "00001116-0000-1000-8000-00805f9b34fb";
pub const GN_UUID: &str = "00001117-0000-1000-8000-00805f9b34fb";
pub const BNEP_SVC_UUID: &str = "0000000f-0000-1000-8000-00805f9b34fb";

pub const SPP_UUID: &str = "00001101-0000-1000-8000-00805f9b34fb";
pub const DUN_GW_UUID: &str = "00001103-0000-1000-8000-00805f9b34fb";
pub const HID_UUID: &str = "00001124-0000-1000-8000-00805f9b34fb";
pub const HOG_UUID: &str = "00001812-0000-1000-8000-00805f9b34fb";
pub const PNP_UUID: &str = "00001200-0000-1000-8000-00805f9b34fb";
pub const SAP_UUID: &str = "0000112d-0000-1000-8000-00805f9b34fb";

pub const HDP_UUID: &str = "00001400-0000-1000-8000-00805f9b34fb";
pub const HDP_SOURCE_UUID: &str = "00001401-0000-1000-8000-00805f9b34fb";
pub const HDP_SINK_UUID: &str = "00001402-0000-1000-8000-00805f9b34fb";

pub const OBEX_SYNC_UUID: &str = "00001104-0000-1000-8000-00805f9b34fb";
pub const OBEX_OPP_UUID: &str = "00001105-0000-1000-8000-00805f9b34fb";
pub const OBEX_FTP_UUID: &str = "00001106-0000-1000-8000-00805f9b34fb";
pub const OBEX_PCE_UUID: &str = "0000112e-0000-1000-8000-00805f9b34fb";
pub const OBEX_PSE_UUID: &str = "0000112f-0000-1000-8000-00805f9b34fb";
pub const OBEX_PBAP_UUID: &str = "00001130-0000-1000-8000-00805f9b34fb";
pub const OBEX_MAS_UUID: &str = "00001132-0000-1000-8000-00805f9b34fb";
pub const OBEX_MNS_UUID: &str = "00001133-0000-1000-8000-00805f9b34fb";
pub const OBEX_MAP_UUID: &str = "00001134-0000-1000-8000-00805f9b34fb";

pub const MESH_PROV_SVC_UUID: &str = "00001827-0000-1000-8000-00805f9b34fb";
pub const MESH_PROXY_SVC_UUID: &str = "00001828-0000-1000-8000-00805f9b34fb";

pub const ASHA_PROFILE_UUID: &str = "0000fdf0-0000-1000-8000-00805f9b34fb";

// GATT attribute type UUIDs (16-bit)
pub const GATT_PRIM_SVC_UUID: u16 = 0x2800;
pub const GATT_SND_SVC_UUID: u16 = 0x2801;
pub const GATT_INCLUDE_UUID: u16 = 0x2802;
pub const GATT_CHARAC_UUID: u16 = 0x2803;

// GATT characteristic types (16-bit)
pub const GATT_CHARAC_DEVICE_NAME: u16 = 0x2A00;
pub const GATT_CHARAC_APPEARANCE: u16 = 0x2A01;
pub const GATT_CHARAC_PERIPHERAL_PRIV_FLAG: u16 = 0x2A02;
pub const GATT_CHARAC_RECONNECTION_ADDRESS: u16 = 0x2A03;
pub const GATT_CHARAC_PERIPHERAL_PREF_CONN: u16 = 0x2A04;
pub const GATT_CHARAC_SERVICE_CHANGED: u16 = 0x2A05;
pub const GATT_CHARAC_BATTERY_LEVEL: u16 = 0x2A19;
pub const GATT_CHARAC_SYSTEM_ID: u16 = 0x2A23;
pub const GATT_CHARAC_MODEL_NUMBER_STRING: u16 = 0x2A24;
pub const GATT_CHARAC_SERIAL_NUMBER_STRING: u16 = 0x2A25;
pub const GATT_CHARAC_FIRMWARE_REVISION_STRING: u16 = 0x2A26;
pub const GATT_CHARAC_HARDWARE_REVISION_STRING: u16 = 0x2A27;
pub const GATT_CHARAC_SOFTWARE_REVISION_STRING: u16 = 0x2A28;
pub const GATT_CHARAC_MANUFACTURER_NAME_STRING: u16 = 0x2A29;
pub const GATT_CHARAC_PNP_ID: u16 = 0x2A50;
pub const GATT_CHARAC_CAR: u16 = 0x2AA6;

// GATT characteristic descriptors (16-bit)
pub const GATT_CHARAC_EXT_PROPER_UUID: u16 = 0x2900;
pub const GATT_CHARAC_USER_DESC_UUID: u16 = 0x2901;
pub const GATT_CLIENT_CHARAC_CFG_UUID: u16 = 0x2902;
pub const GATT_SERVER_CHARAC_CFG_UUID: u16 = 0x2903;
pub const GATT_CHARAC_FMT_UUID: u16 = 0x2904;
pub const GATT_CHARAC_AGREG_FMT_UUID: u16 = 0x2905;
pub const GATT_CHARAC_VALID_RANGE_UUID: u16 = 0x2906;
pub const GATT_EXTERNAL_REPORT_REFERENCE: u16 = 0x2907;
pub const GATT_REPORT_REFERENCE: u16 = 0x2908;

// GATT caching
pub const GATT_CHARAC_CLI_FEAT: u16 = 0x2B29;
pub const GATT_CHARAC_DB_HASH: u16 = 0x2B2A;
pub const GATT_CHARAC_SERVER_FEAT: u16 = 0x2B3A;

// Audio service UUIDs (16-bit)
pub const PACS_UUID: u16 = 0x1850;
pub const PAC_SINK_CHRC_UUID: u16 = 0x2BC9;
pub const PAC_SINK_LOC_CHRC_UUID: u16 = 0x2BCA;
pub const PAC_SOURCE_CHRC_UUID: u16 = 0x2BCB;
pub const PAC_SOURCE_LOC_CHRC_UUID: u16 = 0x2BCC;
pub const PAC_CONTEXT: u16 = 0x2BCD;
pub const PAC_SUPPORTED_CONTEXT: u16 = 0x2BCE;

pub const ASCS_UUID: u16 = 0x184E;
pub const ASE_SINK_UUID: u16 = 0x2BC4;
pub const ASE_SOURCE_UUID: u16 = 0x2BC5;
pub const ASE_CP_UUID: u16 = 0x2BC6;

pub const BASS_UUID: u16 = 0x184F;
pub const BCAST_AUDIO_SCAN_CP_UUID: u16 = 0x2BC7;
pub const BCAST_RECV_STATE_UUID: u16 = 0x2BC8;

pub const VCS_UUID: u16 = 0x1844;
pub const VOL_OFFSET_CS_UUID: u16 = 0x1845;
pub const AUDIO_INPUT_CS_UUID: u16 = 0x1843;
pub const VOL_STATE_CHRC_UUID: u16 = 0x2B7D;
pub const VOL_CP_CHRC_UUID: u16 = 0x2B7E;
pub const VOL_FLAG_CHRC_UUID: u16 = 0x2B7F;

pub const MCS_UUID: u16 = 0x1848;
pub const GMCS_UUID: u16 = 0x1849;
pub const CSIS_UUID: u16 = 0x1846;
pub const MICS_UUID: u16 = 0x184D;
pub const TBS_UUID: u16 = 0x184B;
pub const GTBS_UUID: u16 = 0x184C;
pub const TMAS_UUID: u16 = 0x1855;
pub const GMAS_UUID: u16 = 0x1858;
pub const ASHA_SERVICE: u16 = 0xFDF0;

// RAS characteristic UUIDs (16-bit)
pub const RAS_FEATURES_UUID: u16 = 0x2C14;
pub const RAS_REALTIME_DATA_UUID: u16 = 0x2C15;
pub const RAS_ONDEMAND_DATA_UUID: u16 = 0x2C16;
pub const RAS_CONTROL_POINT_UUID: u16 = 0x2C17;
pub const RAS_DATA_READY_UUID: u16 = 0x2C18;
pub const RAS_DATA_OVERWRITTEN_UUID: u16 = 0x2C19;

// Mesh characteristic UUIDs (16-bit)
pub const MESH_PROVISIONING_DATA_IN: u16 = 0x2ADB;
pub const MESH_PROVISIONING_DATA_OUT: u16 = 0x2ADC;
pub const MESH_PROXY_DATA_IN: u16 = 0x2ADD;
pub const MESH_PROXY_DATA_OUT: u16 = 0x2ADE;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn test_uuid16_create_and_display() {
        let uuid = Uuid::from_u16(0x1234);
        assert_eq!(uuid.to_string(), "00001234-0000-1000-8000-00805f9b34fb");
        assert_eq!(uuid.len(), 2);
    }

    #[test]
    fn test_uuid32_create_and_display() {
        let uuid = Uuid::from_u32(0x12345678);
        assert_eq!(uuid.to_string(), "12345678-0000-1000-8000-00805f9b34fb");
        assert_eq!(uuid.len(), 4);
    }

    #[test]
    fn test_uuid128_create_and_display() {
        let bytes: [u8; 16] = [
            0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
        ];
        let uuid = Uuid::from_u128_bytes(bytes);
        assert_eq!(uuid.to_string(), "f0000000-0000-1000-8000-00805f9b34fb");
        assert_eq!(uuid.len(), 16);
    }

    #[test]
    fn test_parse_uuid16() {
        let uuid: Uuid = "1234".parse().unwrap();
        assert_eq!(uuid, Uuid::Uuid16(0x1234));

        let uuid: Uuid = "0x1234".parse().unwrap();
        assert_eq!(uuid, Uuid::Uuid16(0x1234));
    }

    #[test]
    fn test_parse_uuid32() {
        let uuid: Uuid = "12345678".parse().unwrap();
        assert_eq!(uuid, Uuid::Uuid32(0x12345678));

        let uuid: Uuid = "0x12345678".parse().unwrap();
        assert_eq!(uuid, Uuid::Uuid32(0x12345678));
    }

    #[test]
    fn test_parse_uuid128() {
        let uuid: Uuid = "F0000000-0000-1000-8000-00805f9b34fb".parse().unwrap();
        let expected = [
            0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
        ];
        assert_eq!(uuid, Uuid::Uuid128(expected));
    }

    #[test]
    fn test_parse_base_uuid_compresses_to_uuid16() {
        // A 128-bit string matching the base UUID pattern should compress to UUID16
        let uuid: Uuid = "00001234-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert_eq!(uuid, Uuid::Uuid16(0x1234));

        let uuid: Uuid = "0000FFFF-0000-1000-8000-00805F9B34FB".parse().unwrap();
        assert_eq!(uuid, Uuid::Uuid16(0xFFFF));
    }

    #[test]
    fn test_non_base_uuid128_stays_128() {
        // F0000000 doesn't match 0000xxxx base pattern
        let uuid: Uuid = "F0000000-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert!(matches!(uuid, Uuid::Uuid128(_)));
    }

    #[test]
    fn test_uuid_base() {
        let uuid: Uuid = "0000".parse().unwrap();
        assert_eq!(uuid, Uuid::Uuid16(0x0000));
        assert_eq!(uuid.to_string(), "00000000-0000-1000-8000-00805f9b34fb");

        let binary = uuid.to_uuid128();
        assert_eq!(binary, BLUETOOTH_BASE_UUID);
    }

    #[test]
    fn test_uuid16_to_uuid128_binary() {
        let uuid = Uuid::from_u16(0x1234);
        let binary = uuid.to_uuid128();
        let expected: [u8; 16] = [
            0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
        ];
        assert_eq!(binary, expected);
    }

    #[test]
    fn test_uuid32_to_uuid128_binary() {
        let uuid = Uuid::from_u32(0x12345678);
        let binary = uuid.to_uuid128();
        let expected: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
        ];
        assert_eq!(binary, expected);
    }

    #[test]
    fn test_uuid_cmp_cross_type() {
        // UUID16(0x1234) should equal UUID128 with same expanded value
        let u16 = Uuid::from_u16(0x1234);
        let u128: Uuid = "00001234-0000-1000-8000-00805F9B34FB".parse().unwrap();
        // Note: the 128-bit string with base UUID pattern compresses to UUID16,
        // so they should be directly equal
        assert_eq!(u16, u128);
        assert_eq!(u16.cmp_as_uuid128(&u128), Ordering::Equal);
    }

    #[test]
    fn test_uuid_strcmp() {
        assert_eq!(
            uuid_strcmp("1234", "00001234-0000-1000-8000-00805f9b34fb").unwrap(),
            Ordering::Equal
        );
    }

    #[test]
    fn test_uuid_to_le() {
        let uuid = Uuid::from_u16(0x1234);
        let mut buf = [0u8; 2];
        uuid.to_le_bytes(&mut buf).unwrap();
        assert_eq!(buf, [0x34, 0x12]);

        let uuid = Uuid::from_u128_bytes([
            0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
        ]);
        let mut buf = [0u8; 16];
        uuid.to_le_bytes(&mut buf).unwrap();
        // Should be reversed
        assert_eq!(buf[0], 0xFB);
        assert_eq!(buf[15], 0xF0);
    }

    #[test]
    fn test_malformed_uuids() {
        let malformed = [
            "0",
            "01",
            "012",
            "xxxx",
            "xxxxx",
            "0xxxxx",
            "0123456",
            "012g4567",
            "012345678",
            "0x234567u9",
            "01234567890",
            "00001234-0000-1000-8000-00805F9B34F",
            "00001234-0000-1000-8000 00805F9B34FB",
            "00001234-0000-1000-8000-00805F9B34FBC",
            "00001234-0000-1000-800G-00805F9B34FB",
        ];
        for s in &malformed {
            assert!(s.parse::<Uuid>().is_err(), "should fail for {:?}", s);
        }
    }

    // ---------------------------------------------------------------
    // Tests ported from unit/test-uuid.c
    // ---------------------------------------------------------------

    /// From test-uuid.c: uuid_base test — parse "0000", check type and value.
    #[test]
    fn test_c_uuid_base_parse() {
        let uuid: Uuid = "0000".parse().unwrap();
        assert!(matches!(uuid, Uuid::Uuid16(0x0000)));
        let binary = uuid.to_uuid128();
        let expected: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
        ];
        assert_eq!(binary, expected);
    }

    /// From test-uuid.c: uuid_sixteen1 — parse "0x1234".
    #[test]
    fn test_c_uuid_sixteen1() {
        let uuid: Uuid = "0x1234".parse().unwrap();
        assert!(matches!(uuid, Uuid::Uuid16(0x1234)));
        let binary = uuid.to_uuid128();
        let expected: [u8; 16] = [
            0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
        ];
        assert_eq!(binary, expected);
    }

    /// From test-uuid.c: uuid_sixteen2 — parse "1234" (no prefix).
    #[test]
    fn test_c_uuid_sixteen2() {
        let uuid: Uuid = "1234".parse().unwrap();
        assert!(matches!(uuid, Uuid::Uuid16(0x1234)));
    }

    /// From test-uuid.c: uuid_32_1 — parse "0x12345678".
    #[test]
    fn test_c_uuid_32_1() {
        let uuid: Uuid = "0x12345678".parse().unwrap();
        assert!(matches!(uuid, Uuid::Uuid32(0x12345678)));
        let binary = uuid.to_uuid128();
        let expected: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
        ];
        assert_eq!(binary, expected);
    }

    /// From test-uuid.c: uuid_32_2 — parse "12345678" (no prefix).
    #[test]
    fn test_c_uuid_32_2() {
        let uuid: Uuid = "12345678".parse().unwrap();
        assert!(matches!(uuid, Uuid::Uuid32(0x12345678)));
    }

    /// From test-uuid.c: uuid_128 — parse full 128-bit UUID.
    #[test]
    fn test_c_uuid_128() {
        let uuid: Uuid = "F0000000-0000-1000-8000-00805f9b34fb".parse().unwrap();
        let expected: [u8; 16] = [
            0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
        ];
        assert!(matches!(uuid, Uuid::Uuid128(b) if b == expected));
    }

    /// From test-uuid.c: test_str — string roundtrip for uuid16.
    #[test]
    fn test_c_uuid_str_roundtrip_16() {
        let uuid: Uuid = "0x1234".parse().unwrap();
        let s = uuid.to_string();
        // The display should contain "1234" (case-insensitive)
        assert!(
            uuid_strcmp(&s, "1234").unwrap() == Ordering::Equal,
            "Expected uuid_strcmp({}, 1234) == Equal",
            s
        );
    }

    /// From test-uuid.c: test_str — string roundtrip for uuid32.
    #[test]
    fn test_c_uuid_str_roundtrip_32() {
        let uuid: Uuid = "0x12345678".parse().unwrap();
        let s = uuid.to_string();
        assert!(
            uuid_strcmp(&s, "12345678").unwrap() == Ordering::Equal,
            "Expected uuid_strcmp({}, 12345678) == Equal",
            s
        );
    }

    /// From test-uuid.c: test_cmp — compare UUID16 with expanded UUID128.
    #[test]
    fn test_c_uuid_cmp_base() {
        let u1: Uuid = "0000".parse().unwrap();
        let u2: Uuid = "00000000-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert!(u1.eq_as_uuid128(&u2));
    }

    /// From test-uuid.c: test_cmp for uuid_sixteen1.
    #[test]
    fn test_c_uuid_cmp_sixteen1() {
        let u1: Uuid = "0x1234".parse().unwrap();
        let u2: Uuid = "00001234-0000-1000-8000-00805F9B34FB".parse().unwrap();
        assert!(u1.eq_as_uuid128(&u2));
    }

    /// From test-uuid.c: test_cmp for uuid_32_1.
    #[test]
    fn test_c_uuid_cmp_32_1() {
        let u1: Uuid = "0x12345678".parse().unwrap();
        let u2: Uuid = "12345678-0000-1000-8000-00805F9B34FB".parse().unwrap();
        assert!(u1.eq_as_uuid128(&u2));
    }

    /// From test-uuid.c: test_cmp for uuid_128.
    #[test]
    fn test_c_uuid_cmp_128() {
        let u1: Uuid = "F0000000-0000-1000-8000-00805f9b34fb".parse().unwrap();
        let u2: Uuid = "F0000000-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert!(u1.eq_as_uuid128(&u2));
    }

    /// From test-uuid.c: compress tests — 128-bit UUIDs that should
    /// compress to UUID16 when they match the Bluetooth base.
    #[test]
    fn test_c_uuid_compress() {
        // "00001234-..." -> UUID16(0x1234)
        let u: Uuid = "00001234-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert!(matches!(u, Uuid::Uuid16(0x1234)));

        // "0000FFFF-..." -> UUID16(0xFFFF)
        let u: Uuid = "0000FFFF-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert!(matches!(u, Uuid::Uuid16(0xFFFF)));

        // Case-insensitive base check
        let u: Uuid = "0000FFFF-0000-1000-8000-00805F9B34FB".parse().unwrap();
        assert!(matches!(u, Uuid::Uuid16(0xFFFF)));

        // F0000000 doesn't match base -> stays UUID128
        let u: Uuid = "F0000000-0000-1000-8000-00805f9b34fb".parse().unwrap();
        assert!(matches!(u, Uuid::Uuid128(_)));
    }
}
