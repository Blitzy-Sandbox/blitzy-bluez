// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// EIR (Extended Inquiry Response) / AD (Advertising Data) parsing and generation.
//
// Complete Rust rewrite of BlueZ `src/eir.c` and `src/eir.h`. Provides parsing
// and generation of EIR data blobs which carry device name, class-of-device,
// UUID lists, manufacturer-specific data, service data, appearance, and other
// AD-type fields embedded in HCI inquiry results and LE advertising events.
//
// All GLib types (GSList, g_malloc, g_free, g_strdup, g_strstrip) have been
// replaced with idiomatic Rust owned types (Vec, String, Option). Memory
// management is automatic via Rust ownership and Drop semantics.

use super::endian::{get_le16, get_le32, put_le16};
use super::uuid::BtUuid;
use crate::sys::bluetooth::bdaddr_t;

// ============================================================================
// EIR Type Code Constants (from eir.h lines 17-43)
// ============================================================================

/// Flags (LE discovery mode, BR/EDR support).
pub const EIR_FLAGS: u8 = 0x01;
/// Incomplete list of 16-bit Service UUIDs.
pub const EIR_UUID16_SOME: u8 = 0x02;
/// Complete list of 16-bit Service UUIDs.
pub const EIR_UUID16_ALL: u8 = 0x03;
/// Incomplete list of 32-bit Service UUIDs.
pub const EIR_UUID32_SOME: u8 = 0x04;
/// Complete list of 32-bit Service UUIDs.
pub const EIR_UUID32_ALL: u8 = 0x05;
/// Incomplete list of 128-bit Service UUIDs.
pub const EIR_UUID128_SOME: u8 = 0x06;
/// Complete list of 128-bit Service UUIDs.
pub const EIR_UUID128_ALL: u8 = 0x07;
/// Shortened local name.
pub const EIR_NAME_SHORT: u8 = 0x08;
/// Complete local name.
pub const EIR_NAME_COMPLETE: u8 = 0x09;
/// TX Power Level.
pub const EIR_TX_POWER: u8 = 0x0a;
/// Class of Device.
pub const EIR_CLASS_OF_DEV: u8 = 0x0d;
/// Simple Pairing Hash C-192.
pub const EIR_SSP_HASH: u8 = 0x0e;
/// Simple Pairing Randomizer R-192.
pub const EIR_SSP_RANDOMIZER: u8 = 0x0f;
/// Device ID.
pub const EIR_DEVICE_ID: u8 = 0x10;
/// LE: Solicitation UUIDs, 16-bit.
pub const EIR_SOLICIT16: u8 = 0x14;
/// LE: Solicitation UUIDs, 128-bit.
pub const EIR_SOLICIT128: u8 = 0x15;
/// LE: Service Data - 16-bit UUID.
pub const EIR_SVC_DATA16: u8 = 0x16;
/// LE: Public Target Address.
pub const EIR_PUB_TRGT_ADDR: u8 = 0x17;
/// LE: Random Target Address.
pub const EIR_RND_TRGT_ADDR: u8 = 0x18;
/// GAP Appearance.
pub const EIR_GAP_APPEARANCE: u8 = 0x19;
/// LE: Solicitation UUIDs, 32-bit.
pub const EIR_SOLICIT32: u8 = 0x1f;
/// LE: Service Data - 32-bit UUID.
pub const EIR_SVC_DATA32: u8 = 0x20;
/// LE: Service Data - 128-bit UUID.
pub const EIR_SVC_DATA128: u8 = 0x21;
/// Transport Discovery Service.
pub const EIR_TRANSPORT_DISCOVERY: u8 = 0x26;
/// CSIP Resolvable Set Identifier.
pub const EIR_CSIP_RSI: u8 = 0x2e;
/// Broadcast Name.
pub const EIR_BC_NAME: u8 = 0x30;
/// Manufacturer Specific Data.
pub const EIR_MANUFACTURER_DATA: u8 = 0xff;

// ============================================================================
// EIR Flag Bit Constants
// ============================================================================

/// LE Limited Discoverable Mode.
pub const EIR_LIM_DISC: u8 = 0x01;
/// LE General Discoverable Mode.
pub const EIR_GEN_DISC: u8 = 0x02;
/// BR/EDR Not Supported.
pub const EIR_BREDR_UNSUP: u8 = 0x04;
/// Simultaneous LE and BR/EDR to Same Device Capable (Controller).
pub const EIR_CONTROLLER: u8 = 0x08;
/// Simultaneous LE and BR/EDR to Same Device Capable (Host).
pub const EIR_SIM_HOST: u8 = 0x10;

// ============================================================================
// EIR Data Length Limits
// ============================================================================

/// Maximum service data payload length: 240 (EIR) - 2 (length + type).
pub const EIR_SD_MAX_LEN: usize = 238;

/// Maximum manufacturer-specific data payload length: 240 - 2 (len+type) - 2 (company).
pub const EIR_MSD_MAX_LEN: usize = 236;

/// Maximum HCI EIR data length (from HCI specification).
const HCI_MAX_EIR_LENGTH: usize = 240;

/// Minimum OOB data length: 2 (length field) + 6 (BD_ADDR).
const EIR_OOB_MIN: usize = 8;

/// Size of a single UUID128 in bytes.
const SIZEOF_UUID128: usize = 16;

/// PnP Information Service Class ID (used to filter UUIDs in OOB generation).
const PNP_INFO_SVCLASS_ID: u16 = 0x1200;

// ============================================================================
// Data Structures
// ============================================================================

/// Manufacturer-specific data entry parsed from EIR/AD.
///
/// Contains the Bluetooth SIG-assigned company identifier and the
/// manufacturer-defined payload. Replaces C `struct eir_msd` with
/// `Vec<u8>` instead of a fixed-size array.
#[derive(Debug, Clone)]
pub struct EirMsd {
    /// Bluetooth SIG company identifier (little-endian in EIR wire format).
    pub company: u16,
    /// Manufacturer-specific data payload (max `EIR_MSD_MAX_LEN` bytes).
    pub data: Vec<u8>,
}

/// Service data entry parsed from EIR/AD.
///
/// Associates a UUID (as a string in standard 128-bit format) with
/// service-specific payload bytes. Replaces C `struct eir_sd` with
/// owned `String` and `Vec<u8>`.
#[derive(Debug, Clone)]
pub struct EirSd {
    /// UUID string representation (e.g., "00001800-0000-1000-8000-00805f9b34fb").
    pub uuid: String,
    /// Service-specific data payload (max `EIR_SD_MAX_LEN` bytes).
    pub data: Vec<u8>,
}

/// Generic AD (Advertising Data) type entry for unrecognized EIR types.
///
/// Stores the raw AD type code and payload for any EIR field not
/// specifically parsed. Replaces C `struct eir_ad`.
#[derive(Debug, Clone)]
pub struct EirAd {
    /// AD type code (the EIR_* constant).
    pub ad_type: u8,
    /// Raw data payload for this AD entry.
    pub data: Vec<u8>,
}

/// Parsed EIR (Extended Inquiry Response) data structure.
///
/// Aggregates all fields extracted from an EIR/AD data blob into a
/// single structure. Replaces C `struct eir_data`, with GSList replaced
/// by `Vec`, `char *` by `Option<String>`, and `uint8_t *` by `Option<Vec<u8>>`.
///
/// Memory management is automatic — all fields are owned types that
/// implement `Drop`, eliminating the need for `eir_data_free()`.
#[derive(Debug, Clone, Default)]
pub struct EirData {
    /// List of service UUID strings discovered in this EIR blob.
    pub services: Vec<String>,
    /// EIR flags byte (LE discovery mode, BR/EDR support indicators).
    pub flags: u32,
    /// Device name (short or complete), converted to valid UTF-8.
    pub name: Option<String>,
    /// Class of Device (3-byte value packed into lower 24 bits).
    pub class: u32,
    /// GAP Appearance value.
    pub appearance: u16,
    /// Whether the name is complete (`true`) or shortened (`false`).
    pub name_complete: bool,
    /// Whether a CSIP Resolvable Set Identifier is present.
    pub rsi: bool,
    /// TX Power Level in dBm. Default 127 indicates "not available".
    pub tx_power: i8,
    /// SSP Hash C-192 (16 bytes) if present.
    pub hash: Option<Vec<u8>>,
    /// SSP Randomizer R-192 (16 bytes) if present.
    pub randomizer: Option<Vec<u8>>,
    /// Bluetooth device address extracted from OOB data (6 bytes, LSB first).
    pub addr: [u8; 6],
    /// Device ID: vendor identifier.
    pub did_vendor: u16,
    /// Device ID: product identifier.
    pub did_product: u16,
    /// Device ID: version number.
    pub did_version: u16,
    /// Device ID: source (USB IF or Bluetooth SIG).
    pub did_source: u16,
    /// List of manufacturer-specific data entries.
    pub msd_list: Vec<EirMsd>,
    /// List of service data entries.
    pub sd_list: Vec<EirSd>,
    /// List of unrecognized AD entries.
    pub data_list: Vec<EirAd>,
}

/// Error returned when OOB data is invalid (too short or mismatched length).
///
/// This error is produced by [`eir_parse_oob`] when the input data does not
/// meet the minimum OOB size requirement or the embedded length field does
/// not match the actual data length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OobParseError;

impl core::fmt::Display for OobParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid OOB data")
    }
}

impl std::error::Error for OobParseError {}

// ============================================================================
// Private Helper Functions
// ============================================================================

/// Parse an array of little-endian 16-bit UUIDs from EIR data into UUID strings.
///
/// Each 2-byte chunk is read as a LE16 value and expanded to a full 128-bit
/// UUID string using the Bluetooth SIG base UUID. Matches C `eir_parse_uuid16`.
fn parse_uuid16(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 2 <= data.len() {
        let val = get_le16(&data[offset..]);
        let uuid = BtUuid::from_u16(val);
        result.push(uuid.to_string());
        offset += 2;
    }
    result
}

/// Parse an array of little-endian 32-bit UUIDs from EIR data into UUID strings.
///
/// Each 4-byte chunk is read as a LE32 value and expanded to a full 128-bit
/// UUID string using the Bluetooth SIG base UUID. Matches C `eir_parse_uuid32`.
fn parse_uuid32(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let val = get_le32(&data[offset..]);
        let uuid = BtUuid::from_u32(val);
        result.push(uuid.to_string());
        offset += 4;
    }
    result
}

/// Parse an array of 128-bit UUIDs from EIR data into UUID strings.
///
/// Each 16-byte chunk is byte-reversed (EIR uses reversed byte order relative
/// to the BlueZ internal UUID128 representation) before conversion to a UUID
/// string. Matches C `eir_parse_uuid128`.
fn parse_uuid128(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 16 <= data.len() {
        // UUID128 in EIR is already in BLE wire format (little-endian),
        // which matches the internal BtUuid byte layout used by
        // format_uuid128_bytes. No byte-reversal is needed.
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[offset..offset + 16]);
        let uuid = BtUuid::from_bytes(&bytes);
        result.push(uuid.to_string());
        offset += 16;
    }
    result
}

/// Convert raw name bytes from EIR data to a valid UTF-8 string.
///
/// Finds the longest valid UTF-8 prefix (matching C `strtoutf8` which truncates
/// at the first invalid byte), then trims leading/trailing whitespace (matching
/// C `g_strstrip`). Returns an owned `String`.
fn name_to_utf8(raw: &[u8]) -> String {
    let valid_len = match std::str::from_utf8(raw) {
        Ok(_) => raw.len(),
        Err(e) => e.valid_up_to(),
    };
    let s = std::str::from_utf8(&raw[..valid_len]).unwrap_or_default();
    s.trim().to_owned()
}

// ============================================================================
// Public API — Parsing
// ============================================================================

/// Parse an EIR (Extended Inquiry Response) data blob into an `EirData` struct.
///
/// Iterates through length-type-value triplets in the input byte slice,
/// extracting all recognized EIR fields into the returned structure.
/// Unrecognized AD types are stored in the `data_list` field.
///
/// The `flags` field is initialized to 0 and `tx_power` to 127 (indicating
/// "not available") before parsing begins, matching C `eir_parse` behavior.
///
/// # Arguments
/// * `data` — Raw EIR/AD byte data to parse
///
/// # Returns
/// Populated `EirData` with all parsed fields
pub fn eir_parse(data: &[u8]) -> EirData {
    let mut eir = EirData { tx_power: 127, ..EirData::default() };

    if data.is_empty() {
        return eir;
    }

    let eir_len = data.len();
    let mut offset: usize = 0;

    // Iterate through EIR LTV (Length-Type-Value) entries.
    // Need at least 2 bytes remaining: 1 for length, 1 for type.
    while offset + 1 < eir_len {
        let field_len = data[offset] as usize;

        // A zero length field signals the end of EIR data.
        if field_len == 0 {
            break;
        }

        let next = offset + field_len + 1;

        // Abort if this field extends beyond the available data.
        if next > eir_len {
            break;
        }

        let eir_type = data[offset + 1];
        let field_data = &data[offset + 2..next];

        match eir_type {
            EIR_UUID16_SOME | EIR_UUID16_ALL => {
                let uuids = parse_uuid16(field_data);
                eir.services.extend(uuids);
            }

            EIR_UUID32_SOME | EIR_UUID32_ALL => {
                let uuids = parse_uuid32(field_data);
                eir.services.extend(uuids);
            }

            EIR_UUID128_SOME | EIR_UUID128_ALL => {
                let uuids = parse_uuid128(field_data);
                eir.services.extend(uuids);
            }

            EIR_FLAGS => {
                if !field_data.is_empty() {
                    eir.flags = u32::from(field_data[0]);
                }
            }

            EIR_NAME_SHORT | EIR_NAME_COMPLETE | EIR_BC_NAME => {
                // Strip trailing NUL bytes (some vendors add them).
                let mut name_data = field_data;
                while !name_data.is_empty() && name_data[name_data.len() - 1] == 0 {
                    name_data = &name_data[..name_data.len() - 1];
                }
                eir.name = Some(name_to_utf8(name_data));
                eir.name_complete = eir_type != EIR_NAME_SHORT;
            }

            EIR_TX_POWER => {
                if !field_data.is_empty() {
                    eir.tx_power = field_data[0] as i8;
                }
            }

            EIR_CLASS_OF_DEV => {
                if field_data.len() >= 3 {
                    eir.class = u32::from(field_data[0])
                        | (u32::from(field_data[1]) << 8)
                        | (u32::from(field_data[2]) << 16);
                }
            }

            EIR_GAP_APPEARANCE => {
                if field_data.len() >= 2 {
                    eir.appearance = get_le16(field_data);
                }
            }

            EIR_SSP_HASH => {
                if field_data.len() >= 16 {
                    eir.hash = Some(field_data[..16].to_vec());
                }
            }

            EIR_SSP_RANDOMIZER => {
                if field_data.len() >= 16 {
                    eir.randomizer = Some(field_data[..16].to_vec());
                }
            }

            EIR_DEVICE_ID => {
                if field_data.len() >= 8 {
                    eir.did_source = get_le16(field_data);
                    eir.did_vendor = get_le16(&field_data[2..]);
                    eir.did_product = get_le16(&field_data[4..]);
                    eir.did_version = get_le16(&field_data[6..]);
                }
            }

            EIR_SVC_DATA16 => {
                if field_data.len() >= 2 && field_data.len() <= EIR_SD_MAX_LEN {
                    let uuid_val = get_le16(field_data);
                    let uuid = BtUuid::from_u16(uuid_val);
                    let sd = EirSd { uuid: uuid.to_string(), data: field_data[2..].to_vec() };
                    eir.sd_list.push(sd);
                }
            }

            EIR_SVC_DATA32 => {
                if field_data.len() >= 4 && field_data.len() <= EIR_SD_MAX_LEN {
                    let uuid_val = get_le32(field_data);
                    let uuid = BtUuid::from_u32(uuid_val);
                    let sd = EirSd { uuid: uuid.to_string(), data: field_data[4..].to_vec() };
                    eir.sd_list.push(sd);
                }
            }

            EIR_SVC_DATA128 => {
                if field_data.len() >= 16 && field_data.len() <= EIR_SD_MAX_LEN {
                    let mut uuid_bytes = [0u8; 16];
                    for k in 0..16 {
                        uuid_bytes[k] = field_data[16 - k - 1];
                    }
                    let uuid = BtUuid::from_bytes(&uuid_bytes);
                    let sd = EirSd { uuid: uuid.to_string(), data: field_data[16..].to_vec() };
                    eir.sd_list.push(sd);
                }
            }

            EIR_MANUFACTURER_DATA => {
                if field_data.len() >= 2 && field_data.len() <= 2 + EIR_MSD_MAX_LEN {
                    let msd =
                        EirMsd { company: get_le16(field_data), data: field_data[2..].to_vec() };
                    eir.msd_list.push(msd);
                }
            }

            _ => {
                // Store unrecognized AD types as generic entries.
                let ad = EirAd { ad_type: eir_type, data: field_data.to_vec() };
                eir.data_list.push(ad);
                // CSIP RSI sets the rsi flag in addition to being stored.
                if eir_type == EIR_CSIP_RSI {
                    eir.rsi = true;
                }
            }
        }

        offset = next;
    }

    eir
}

/// Parse OOB (Out-Of-Band) data containing a BD_ADDR and optional EIR fields.
///
/// OOB data format:
/// - Bytes 0-1: Total length (LE16), must match `data.len()`
/// - Bytes 2-7: BD_ADDR (6 bytes)
/// - Bytes 8+: Optional EIR data
///
/// # Arguments
/// * `data` — Raw OOB data to parse
///
/// # Returns
/// `Ok(EirData)` with the parsed fields and extracted BD_ADDR, or
/// `Err(OobParseError)` if the data is too short or the length field
/// doesn't match.
pub fn eir_parse_oob(data: &[u8]) -> Result<EirData, OobParseError> {
    if data.len() < EIR_OOB_MIN {
        return Err(OobParseError);
    }

    let total_len = get_le16(data) as usize;
    if total_len != data.len() {
        return Err(OobParseError);
    }

    // Parse optional EIR data following the 2-byte length + 6-byte address.
    let eir_payload = &data[8..];
    let mut eir = if eir_payload.is_empty() {
        EirData { tx_power: 127, ..EirData::default() }
    } else {
        eir_parse(eir_payload)
    };

    // Extract BD_ADDR from OOB data (bytes 2-7) using bdaddr_t.
    let addr = bdaddr_t { b: [data[2], data[3], data[4], data[5], data[6], data[7]] };
    eir.addr = addr.b;

    Ok(eir)
}

// ============================================================================
// Public API — Generation
// ============================================================================

/// Parameters for OOB (Out-Of-Band) pairing data generation.
///
/// Groups the device identity, security, and service information needed to build
/// an OOB data blob.
pub struct EirOobParams<'a> {
    /// BD_ADDR (6 bytes, LSB first).
    pub addr: &'a [u8; 6],
    /// Device name (truncated to 48 bytes if longer).
    pub name: Option<&'a str>,
    /// Class of Device (0 means omitted).
    pub cod: u32,
    /// SSP Hash C-192 (16 bytes) or `None`.
    pub hash: Option<&'a [u8]>,
    /// SSP Randomizer R-192 (16 bytes) or `None`.
    pub randomizer: Option<&'a [u8]>,
    /// Device ID vendor (0 means no Device ID entry).
    pub did_vendor: u16,
    /// Device ID product.
    pub did_product: u16,
    /// Device ID version.
    pub did_version: u16,
    /// Device ID source.
    pub did_source: u16,
    /// Service UUID strings to include.
    pub uuids: &'a [String],
}

/// Generate OOB (Out-Of-Band) pairing data from the given device parameters.
///
/// Builds a complete OOB data blob containing the BD_ADDR, optional EIR fields
/// (Class of Device, SSP hash/randomizer, name, Device ID), and UUID lists
/// (both UUID16 and UUID128 entries). The output format matches the C
/// `eir_create_oob` function byte-for-byte.
///
/// # Returns
/// Complete OOB data as a `Vec<u8>` with the length field at bytes 0-1.
pub fn eir_create_oob(params: &EirOobParams<'_>) -> Vec<u8> {
    let addr = params.addr;
    let name = params.name;
    let cod = params.cod;
    let hash = params.hash;
    let randomizer = params.randomizer;
    let did_vendor = params.did_vendor;
    let did_product = params.did_product;
    let did_version = params.did_version;
    let did_source = params.did_source;
    let uuids = params.uuids;
    let mut buf: Vec<u8> = Vec::with_capacity(2 + 6 + HCI_MAX_EIR_LENGTH);

    // Reserve 2 bytes for total length (filled at the end).
    buf.extend_from_slice(&[0u8; 2]);

    // BD_ADDR (6 bytes) — use bdaddr_t to access the .b field.
    let addr_obj = bdaddr_t { b: *addr };
    buf.extend_from_slice(&addr_obj.b);

    let mut eir_optional_len: usize = 0;

    // Class of Device (3 bytes + 2 header).
    if cod > 0 {
        buf.push(4); // field_len: 1 (type) + 3 (class)
        buf.push(EIR_CLASS_OF_DEV);
        buf.push((cod & 0xff) as u8);
        buf.push(((cod >> 8) & 0xff) as u8);
        buf.push(((cod >> 16) & 0xff) as u8);
        eir_optional_len += 5;
    }

    // SSP Hash C-192 (16 bytes + 2 header).
    if let Some(h) = hash {
        buf.push(17); // field_len: 1 (type) + 16 (hash)
        buf.push(EIR_SSP_HASH);
        let copy_len = h.len().min(16);
        buf.extend_from_slice(&h[..copy_len]);
        // Pad with zeros if hash is shorter than 16 bytes.
        buf.extend(std::iter::repeat_n(0u8, 16 - copy_len));
        eir_optional_len += 18;
    }

    // SSP Randomizer R-192 (16 bytes + 2 header).
    if let Some(r) = randomizer {
        buf.push(17); // field_len: 1 (type) + 16 (randomizer)
        buf.push(EIR_SSP_RANDOMIZER);
        let copy_len = r.len().min(16);
        buf.extend_from_slice(&r[..copy_len]);
        buf.extend(std::iter::repeat_n(0u8, 16 - copy_len));
        eir_optional_len += 18;
    }

    // Device name (variable length + 2 header).
    if let Some(n) = name {
        let name_bytes = n.as_bytes();
        if !name_bytes.is_empty() {
            let mut name_len = name_bytes.len();
            let name_type;
            if name_len > 48 {
                name_len = 48;
                name_type = EIR_NAME_SHORT;
            } else {
                name_type = EIR_NAME_COMPLETE;
            }
            buf.push((name_len + 1) as u8); // field_len: 1 (type) + name_len
            buf.push(name_type);
            buf.extend_from_slice(&name_bytes[..name_len]);
            eir_optional_len += name_len + 2;
        }
    }

    // Device ID (8 bytes + 2 header).
    if did_vendor != 0 {
        buf.push(9); // field_len: 1 (type) + 8 (DID fields)
        buf.push(EIR_DEVICE_ID);
        buf.push((did_source & 0xff) as u8);
        buf.push(((did_source >> 8) & 0xff) as u8);
        buf.push((did_vendor & 0xff) as u8);
        buf.push(((did_vendor >> 8) & 0xff) as u8);
        buf.push((did_product & 0xff) as u8);
        buf.push(((did_product >> 8) & 0xff) as u8);
        buf.push((did_version & 0xff) as u8);
        buf.push(((did_version >> 8) & 0xff) as u8);
        eir_optional_len += 10;
    }

    // --- UUID16 grouping ---
    // Collect all UUID16 candidates: Bluetooth SIG UUIDs that fit in 16 bits,
    // with value >= 0x1100 and not PnP Information Service Class ID.
    let mut uuid16_values: Vec<u16> = Vec::new();
    let mut uuid16_truncated = false;

    for uuid_str in uuids {
        if let Ok(bt_uuid) = uuid_str.parse::<BtUuid>() {
            let bytes = bt_uuid.to_uuid128_bytes();
            // Check if this is a UUID16 (Bluetooth SIG base with 16-bit value).
            if bt_uuid.is_bluetooth_sig() && bytes[14] == 0 && bytes[15] == 0 {
                let uuid16_val = get_le16(&bytes[12..]);

                // Filter: skip UUIDs below 0x1100 and PnP Info.
                if uuid16_val < 0x1100 || uuid16_val == PNP_INFO_SVCLASS_ID {
                    continue;
                }

                // Check space for this UUID16 (2 header + 2 UUID bytes).
                if eir_optional_len + 2 + 2 > HCI_MAX_EIR_LENGTH {
                    uuid16_truncated = true;
                    break;
                }

                // Skip duplicates.
                if uuid16_values.contains(&uuid16_val) {
                    continue;
                }

                uuid16_values.push(uuid16_val);
                eir_optional_len += 2; // UUID16 data bytes
            }
        }
    }

    if !uuid16_values.is_empty() {
        let len_byte = (uuid16_values.len() * 2 + 1) as u8;
        let type_byte = if uuid16_truncated { EIR_UUID16_SOME } else { EIR_UUID16_ALL };
        buf.push(len_byte);
        buf.push(type_byte);
        eir_optional_len += 2; // Header bytes

        for val in &uuid16_values {
            buf.push((val & 0xff) as u8);
            buf.push(((val >> 8) & 0xff) as u8);
        }
    }

    // --- UUID128 grouping ---
    // Process non-SIG UUID128 entries (those that don't match the BT base UUID).
    if eir_optional_len + 2 <= HCI_MAX_EIR_LENGTH {
        let uuid128_header_pos = buf.len();
        // Reserve 2 bytes for length+type header (filled below if needed).
        buf.extend_from_slice(&[0u8; 2]);

        let mut uuid128_count: usize = 0;
        let mut uuid128_truncated = false;
        let mut written_uuid128s: Vec<[u8; SIZEOF_UUID128]> = Vec::new();

        for uuid_str in uuids {
            if let Ok(bt_uuid) = uuid_str.parse::<BtUuid>() {
                // Only process UUID128 entries (non-SIG UUIDs).
                if bt_uuid.is_bluetooth_sig() {
                    continue;
                }

                let internal_bytes = bt_uuid.to_uuid128_bytes();

                // Check space for another UUID128 entry.
                if eir_optional_len + 2 + SIZEOF_UUID128 > HCI_MAX_EIR_LENGTH {
                    uuid128_truncated = true;
                    break;
                }

                // Reverse bytes for EIR wire format.
                let mut eir_bytes = [0u8; SIZEOF_UUID128];
                for k in 0..SIZEOF_UUID128 {
                    eir_bytes[k] = internal_bytes[SIZEOF_UUID128 - 1 - k];
                }

                // Check for duplicates among already-written UUID128s.
                if written_uuid128s.iter().any(|existing| existing == &eir_bytes) {
                    continue;
                }

                buf.extend_from_slice(&eir_bytes);
                written_uuid128s.push(eir_bytes);
                eir_optional_len += SIZEOF_UUID128;
                uuid128_count += 1;
            }
        }

        if uuid128_count > 0 || uuid128_truncated {
            // Fill in the reserved header bytes.
            buf[uuid128_header_pos] = (uuid128_count * SIZEOF_UUID128 + 1) as u8;
            buf[uuid128_header_pos + 1] =
                if uuid128_truncated { EIR_UUID128_SOME } else { EIR_UUID128_ALL };
            eir_optional_len += 2; // Header bytes
        } else {
            // No UUID128 entries written — remove the reserved header bytes.
            buf.truncate(uuid128_header_pos);
        }
    }

    // Write the total OOB length at the beginning of the buffer.
    let eir_total_len = (2 + 6 + eir_optional_len) as u16;
    put_le16(eir_total_len, &mut buf[0..2]);

    buf
}

// ============================================================================
// Public API — Lookup
// ============================================================================

/// Find a service data entry in the parsed EIR data by UUID string.
///
/// Searches the `sd_list` for an entry whose UUID matches the given string
/// (case-sensitive comparison, matching C `eir_get_service_data` behavior).
///
/// # Arguments
/// * `eir` — Parsed EIR data to search
/// * `uuid` — UUID string to match against
///
/// # Returns
/// Reference to the matching `EirSd` entry, or `None` if not found.
pub fn eir_get_service_data<'a>(eir: &'a EirData, uuid: &str) -> Option<&'a EirSd> {
    eir.sd_list.iter().find(|sd| sd.uuid == uuid)
}
