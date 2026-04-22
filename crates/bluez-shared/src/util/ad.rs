// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2015  Google Inc.
//
// Complete Rust rewrite of BlueZ's Advertising Data (AD) builder/parser
// from src/shared/ad.c and src/shared/ad.h. The BtAd struct replaces
// the opaque struct bt_ad with full ownership semantics, eliminating
// manual ref-counting and GLib containers.

use super::endian::IoBuf;
use super::endian::{get_le16, get_le32, put_le16, str_to_utf8, stris_utf8, strstrip};
use super::uuid::BtUuid;

// =============================================================================
// AD Type Code Constants (from ad.h lines 17-64)
// =============================================================================

/// Maximum legacy advertising data length (31 bytes).
pub const BT_AD_MAX_DATA_LEN: u8 = 31;
/// Maximum extended advertising data length (251 bytes).
pub const BT_EA_MAX_DATA_LEN: u8 = 251;
/// Maximum periodic advertising data length (252 bytes).
pub const BT_PA_MAX_DATA_LEN: u8 = 252;

/// AD type: Flags.
pub const BT_AD_FLAGS: u8 = 0x01;
/// AD type: Incomplete list of 16-bit service UUIDs.
pub const BT_AD_UUID16_SOME: u8 = 0x02;
/// AD type: Complete list of 16-bit service UUIDs.
pub const BT_AD_UUID16_ALL: u8 = 0x03;
/// AD type: Incomplete list of 32-bit service UUIDs.
pub const BT_AD_UUID32_SOME: u8 = 0x04;
/// AD type: Complete list of 32-bit service UUIDs.
pub const BT_AD_UUID32_ALL: u8 = 0x05;
/// AD type: Incomplete list of 128-bit service UUIDs.
pub const BT_AD_UUID128_SOME: u8 = 0x06;
/// AD type: Complete list of 128-bit service UUIDs.
pub const BT_AD_UUID128_ALL: u8 = 0x07;
/// AD type: Shortened local name.
pub const BT_AD_NAME_SHORT: u8 = 0x08;
/// AD type: Complete local name.
pub const BT_AD_NAME_COMPLETE: u8 = 0x09;
/// AD type: TX Power Level.
pub const BT_AD_TX_POWER: u8 = 0x0a;
/// AD type: Class of Device.
pub const BT_AD_CLASS_OF_DEV: u8 = 0x0d;
/// AD type: Simple Pairing Hash C-192.
pub const BT_AD_SSP_HASH: u8 = 0x0e;
/// AD type: Simple Pairing Randomizer R-192.
pub const BT_AD_SSP_RANDOMIZER: u8 = 0x0f;
/// AD type: Device ID / Security Manager TK Value.
pub const BT_AD_DEVICE_ID: u8 = 0x10;
/// AD type: Security Manager TK Value (same value as DEVICE_ID).
pub const BT_AD_SMP_TK: u8 = 0x10;
/// AD type: Security Manager Out of Band Flags.
pub const BT_AD_SMP_OOB_FLAGS: u8 = 0x11;
/// AD type: Peripheral Connection Interval Range.
pub const BT_AD_PERIPHERAL_CONN_INTERVAL: u8 = 0x12;
/// AD type: List of 16-bit Service Solicitation UUIDs.
pub const BT_AD_SOLICIT16: u8 = 0x14;
/// AD type: List of 128-bit Service Solicitation UUIDs.
pub const BT_AD_SOLICIT128: u8 = 0x15;
/// AD type: Service Data - 16-bit UUID.
pub const BT_AD_SERVICE_DATA16: u8 = 0x16;
/// AD type: Public Target Address.
pub const BT_AD_PUBLIC_ADDRESS: u8 = 0x17;
/// AD type: Random Target Address.
pub const BT_AD_RANDOM_ADDRESS: u8 = 0x18;
/// AD type: Appearance.
pub const BT_AD_GAP_APPEARANCE: u8 = 0x19;
/// AD type: Advertising Interval.
pub const BT_AD_ADVERTISING_INTERVAL: u8 = 0x1a;
/// AD type: LE Bluetooth Device Address.
pub const BT_AD_LE_DEVICE_ADDRESS: u8 = 0x1b;
/// AD type: LE Role.
pub const BT_AD_LE_ROLE: u8 = 0x1c;
/// AD type: Simple Pairing Hash C-256.
pub const BT_AD_SSP_HASH_P256: u8 = 0x1d;
/// AD type: Simple Pairing Randomizer R-256.
pub const BT_AD_SSP_RANDOMIZER_P256: u8 = 0x1e;
/// AD type: List of 32-bit Service Solicitation UUIDs.
pub const BT_AD_SOLICIT32: u8 = 0x1f;
/// AD type: Service Data - 32-bit UUID.
pub const BT_AD_SERVICE_DATA32: u8 = 0x20;
/// AD type: Service Data - 128-bit UUID.
pub const BT_AD_SERVICE_DATA128: u8 = 0x21;
/// AD type: LE Secure Connections Confirmation Value.
pub const BT_AD_LE_SC_CONFIRM_VALUE: u8 = 0x22;
/// AD type: LE Secure Connections Random Value.
pub const BT_AD_LE_SC_RANDOM_VALUE: u8 = 0x23;
/// AD type: URI.
pub const BT_AD_URI: u8 = 0x24;
/// AD type: Indoor Positioning.
pub const BT_AD_INDOOR_POSITIONING: u8 = 0x25;
/// AD type: Transport Discovery Data.
pub const BT_AD_TRANSPORT_DISCOVERY: u8 = 0x26;
/// AD type: LE Supported Features.
pub const BT_AD_LE_SUPPORTED_FEATURES: u8 = 0x27;
/// AD type: Channel Map Update Indication.
pub const BT_AD_CHANNEL_MAP_UPDATE_IND: u8 = 0x28;
/// AD type: PB-ADV (Mesh Provisioning).
pub const BT_AD_MESH_PROV: u8 = 0x29;
/// AD type: Mesh Message (Mesh Data).
pub const BT_AD_MESH_DATA: u8 = 0x2a;
/// AD type: Mesh Beacon.
pub const BT_AD_MESH_BEACON: u8 = 0x2b;
/// AD type: CSIP RSI (Coordinated Set Identification).
pub const BT_AD_CSIP_RSI: u8 = 0x2e;
/// AD type: 3D Information Data.
pub const BT_AD_3D_INFO_DATA: u8 = 0x3d;
/// AD type: Manufacturer Specific Data.
pub const BT_AD_MANUFACTURER_DATA: u8 = 0xff;

// =============================================================================
// LE Advertising Flags
// =============================================================================

/// LE Limited Discoverable Mode flag.
pub const BT_AD_FLAG_LIMITED: u8 = 0x01;
/// LE General Discoverable Mode flag.
pub const BT_AD_FLAG_GENERAL: u8 = 0x02;
/// BR/EDR Not Supported flag.
pub const BT_AD_FLAG_NO_BREDR: u8 = 0x04;

// =============================================================================
// Supporting Data Structures
// =============================================================================

/// Manufacturer-specific advertising data entry.
///
/// Replaces C `struct bt_ad_manufacturer_data` with owned data.
#[derive(Debug, Clone)]
pub struct ManufacturerData {
    /// Bluetooth SIG assigned Company Identifier.
    pub manufacturer_id: u16,
    /// Manufacturer-specific payload bytes.
    pub data: Vec<u8>,
}

/// Service data entry associated with a UUID.
///
/// Replaces C `struct bt_ad_service_data` with owned data.
#[derive(Debug, Clone)]
pub struct ServiceData {
    /// Service UUID (16-bit, 32-bit, or 128-bit).
    pub uuid: BtUuid,
    /// Service-specific payload bytes.
    pub data: Vec<u8>,
}

/// Generic AD data entry keyed by type code.
///
/// Replaces C `struct bt_ad_data` with owned data.
#[derive(Debug, Clone)]
pub struct AdData {
    /// AD type code identifying the data content.
    pub ad_type: u8,
    /// Raw AD payload bytes.
    pub data: Vec<u8>,
}

/// AD pattern for content-based matching against advertising data.
///
/// Replaces C `struct bt_ad_pattern`.
#[derive(Debug, Clone)]
pub struct AdPattern {
    /// AD type code to match against.
    pub ad_type: u8,
    /// Byte offset within the AD data to start matching.
    pub offset: u8,
    /// Number of bytes to match.
    pub len: u8,
    /// Pattern data buffer (up to BT_AD_MAX_DATA_LEN bytes used).
    pub data: [u8; BT_AD_MAX_DATA_LEN as usize],
}

// =============================================================================
// BtAd — Advertising Data Builder/Parser
// =============================================================================

/// Bluetooth Advertising Data builder and parser.
///
/// Replaces C `struct bt_ad` with full Rust ownership semantics.
/// All GLib containers (`struct queue*`) become `Vec<T>`, and manual
/// ref-counting (`bt_ad_ref`/`bt_ad_unref`) is replaced by Rust ownership.
pub struct BtAd {
    /// Maximum serialized AD length (default: BT_EA_MAX_DATA_LEN).
    max_len: u8,
    /// Local device name (None if unset).
    name: Option<String>,
    /// GAP Appearance value (u16::MAX = unset sentinel).
    appearance: u16,
    /// List of service UUIDs to advertise.
    service_uuids: Vec<BtUuid>,
    /// List of manufacturer-specific data entries.
    manufacturer_data: Vec<ManufacturerData>,
    /// List of solicitation UUIDs.
    solicit_uuids: Vec<BtUuid>,
    /// List of service data entries.
    service_data: Vec<ServiceData>,
    /// List of generic AD data entries (flags, TX power, etc.).
    data: Vec<AdData>,
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

/// Returns the wire byte length for a UUID (2 for UUID16, 4 for UUID32, 16 for UUID128).
fn uuid_byte_len(uuid: &BtUuid) -> usize {
    match uuid {
        BtUuid::Uuid16(_) => 2,
        BtUuid::Uuid32(_) => 4,
        BtUuid::Uuid128(_) => 16,
    }
}

/// Compares two UUIDs by expanding both to full 128-bit representation.
///
/// This matches the C behavior of `bt_uuid_cmp` which always converts
/// to UUID128 before comparison, enabling cross-type UUID equality.
fn uuid_eq(a: &BtUuid, b: &BtUuid) -> bool {
    a.to_uuid128_bytes() == b.to_uuid128_bytes()
}

/// Checks whether an AD type code falls within the valid range.
///
/// Valid types are BT_AD_FLAGS (0x01) through BT_AD_3D_INFO_DATA (0x3d),
/// plus BT_AD_MANUFACTURER_DATA (0xff).
fn ad_is_type_valid(ad_type: u8) -> bool {
    if ad_type < BT_AD_FLAGS {
        return false;
    }
    if ad_type > BT_AD_3D_INFO_DATA && ad_type != BT_AD_MANUFACTURER_DATA {
        return false;
    }
    true
}

/// List of standard AD types that are rejected by `add_data()`.
///
/// These types have dedicated setter methods and must not be set
/// via the generic `add_data()` interface.
const TYPE_REJECT_LIST: &[u8] = &[
    BT_AD_FLAGS,
    BT_AD_UUID16_SOME,
    BT_AD_UUID16_ALL,
    BT_AD_UUID32_SOME,
    BT_AD_UUID32_ALL,
    BT_AD_UUID128_SOME,
    BT_AD_UUID128_ALL,
    BT_AD_NAME_SHORT,
    BT_AD_NAME_COMPLETE,
    BT_AD_TX_POWER,
    BT_AD_CLASS_OF_DEV,
    BT_AD_SSP_HASH,
    BT_AD_SSP_RANDOMIZER,
    BT_AD_DEVICE_ID,
    BT_AD_SMP_OOB_FLAGS,
    BT_AD_PERIPHERAL_CONN_INTERVAL,
    BT_AD_SOLICIT16,
    BT_AD_SOLICIT128,
    BT_AD_SERVICE_DATA16,
    BT_AD_PUBLIC_ADDRESS,
    BT_AD_RANDOM_ADDRESS,
    BT_AD_GAP_APPEARANCE,
    BT_AD_ADVERTISING_INTERVAL,
    BT_AD_LE_DEVICE_ADDRESS,
    BT_AD_LE_ROLE,
    BT_AD_SSP_HASH_P256,
    BT_AD_SSP_RANDOMIZER_P256,
    BT_AD_SOLICIT32,
    BT_AD_SERVICE_DATA32,
    BT_AD_SERVICE_DATA128,
    BT_AD_LE_SC_CONFIRM_VALUE,
    BT_AD_LE_SC_RANDOM_VALUE,
    BT_AD_URI,
    BT_AD_INDOOR_POSITIONING,
    BT_AD_TRANSPORT_DISCOVERY,
    BT_AD_LE_SUPPORTED_FEATURES,
    BT_AD_CHANNEL_MAP_UPDATE_IND,
    BT_AD_MESH_PROV,
    BT_AD_MESH_DATA,
    BT_AD_MESH_BEACON,
    BT_AD_3D_INFO_DATA,
    BT_AD_MANUFACTURER_DATA,
];

// =============================================================================
// BtAd Implementation
// =============================================================================

impl Default for BtAd {
    fn default() -> Self {
        Self::new()
    }
}

impl BtAd {
    // =========================================================================
    // Constructors
    // =========================================================================

    /// Creates a new empty `BtAd` with default settings.
    ///
    /// Appearance is unset (sentinel value `u16::MAX`), maximum length
    /// defaults to `BT_EA_MAX_DATA_LEN` (251).
    pub fn new() -> Self {
        Self {
            max_len: BT_EA_MAX_DATA_LEN,
            name: None,
            appearance: u16::MAX,
            service_uuids: Vec::new(),
            manufacturer_data: Vec::new(),
            solicit_uuids: Vec::new(),
            service_data: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Parses raw AD bytes (length-type-value triplets) into a `BtAd`.
    ///
    /// Returns `None` if the data is empty or contains an invalid AD structure.
    /// Matches the C `bt_ad_new_with_data` parsing logic exactly, including
    /// deduplication of service UUIDs during parsing.
    pub fn new_with_data(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let mut ad = Self::new();
        let mut iov = IoBuf::from_bytes(data);

        while iov.remaining() > 0 {
            // Pull length byte
            let len = iov.pull_u8()?;
            if len == 0 {
                break;
            }

            if len as usize > iov.remaining() {
                break;
            }

            // Pull AD type byte
            let ad_type = iov.pull_u8()?;
            let data_len = (len - 1) as usize;

            if !ad_is_type_valid(ad_type) {
                // Skip invalid types but continue parsing
                iov.pull_mem(data_len)?;
                continue;
            }

            let field_data = iov.pull_mem(data_len)?;

            // Route to appropriate handler based on type
            ad_replace_data(&mut ad, ad_type, field_data);
        }

        Some(ad)
    }

    /// Sets the maximum serialized AD length.
    ///
    /// Returns `true` if the length was set successfully. The minimum
    /// value is `BT_AD_MAX_DATA_LEN` (31).
    pub fn set_max_len(&mut self, len: u8) -> bool {
        if len < BT_AD_MAX_DATA_LEN {
            return false;
        }
        self.max_len = len;
        true
    }

    // =========================================================================
    // Length Calculation
    // =========================================================================

    /// Calculates the total serialized AD length in bytes.
    ///
    /// This traverses all fields and computes the total LTV (length-type-value)
    /// byte count. Matches C's `bt_ad_length`.
    pub fn length(&self) -> usize {
        let mut length = 0usize;

        // Service UUIDs: grouped by UUID size, each group has 2-byte header
        length += uuid_list_length(&self.service_uuids);

        // Solicit UUIDs: grouped by UUID size, each group has 2-byte header
        length += uuid_list_length(&self.solicit_uuids);

        // Manufacturer data: each entry has 2-byte header + 2-byte ID + data
        for mfg in &self.manufacturer_data {
            length += 2 + 2 + mfg.data.len();
        }

        // Service data: each entry has 2-byte header + UUID bytes + data
        for sd in &self.service_data {
            length += 2 + uuid_byte_len(&sd.uuid) + sd.data.len();
        }

        // Name: 2-byte header + name bytes (may be truncated later in generate)
        length += name_length(&self.name, length, self.max_len);

        // Appearance: 2-byte header + 2-byte value
        if self.appearance != u16::MAX {
            length += 4;
        }

        // Generic data: each entry has 2-byte header + data
        for d in &self.data {
            length += 2 + d.data.len();
        }

        length
    }

    /// Serializes the `BtAd` into raw AD bytes suitable for advertising.
    ///
    /// Returns `None` if the total length exceeds `max_len` or the AD is empty.
    /// Serialization order matches C's `bt_ad_generate` exactly:
    /// service UUIDs → solicit UUIDs → manufacturer data → service data →
    /// name → appearance → generic data.
    pub fn generate(&self) -> Option<Vec<u8>> {
        let length = self.length();
        if length == 0 {
            return None;
        }
        if length > self.max_len as usize {
            return None;
        }

        let mut iov = IoBuf::with_capacity(length);

        // Serialize service UUIDs (grouped by type size)
        serialize_uuids(&mut iov, &self.service_uuids, false);

        // Serialize solicit UUIDs (grouped by type size)
        serialize_uuids(&mut iov, &self.solicit_uuids, true);

        // Serialize manufacturer data
        for mfg in &self.manufacturer_data {
            iov.push_u8((3 + mfg.data.len()) as u8);
            iov.push_u8(BT_AD_MANUFACTURER_DATA);
            iov.push_le16(mfg.manufacturer_id);
            iov.push_mem(&mfg.data);
        }

        // Serialize service data
        for sd in &self.service_data {
            let uuid_len = uuid_byte_len(&sd.uuid);
            iov.push_u8((1 + uuid_len + sd.data.len()) as u8);

            match &sd.uuid {
                BtUuid::Uuid16(v) => {
                    iov.push_u8(BT_AD_SERVICE_DATA16);
                    iov.push_le16(*v);
                }
                BtUuid::Uuid32(v) => {
                    iov.push_u8(BT_AD_SERVICE_DATA32);
                    iov.push_le32(*v);
                }
                BtUuid::Uuid128(v) => {
                    iov.push_u8(BT_AD_SERVICE_DATA128);
                    iov.push_mem(v);
                }
            }
            iov.push_mem(&sd.data);
        }

        // Serialize name (with possible truncation)
        serialize_name(&mut iov, &self.name, self.max_len);

        // Serialize appearance
        if self.appearance != u16::MAX {
            iov.push_u8(3);
            iov.push_u8(BT_AD_GAP_APPEARANCE);
            iov.push_le16(self.appearance);
        }

        // Serialize generic data
        for d in &self.data {
            iov.push_u8((1 + d.data.len()) as u8);
            iov.push_u8(d.ad_type);
            iov.push_mem(&d.data);
        }

        Some(iov.as_bytes().to_vec())
    }

    /// Returns `true` if no advertising data fields are set.
    pub fn is_empty(&self) -> bool {
        self.service_uuids.is_empty()
            && self.manufacturer_data.is_empty()
            && self.solicit_uuids.is_empty()
            && self.service_data.is_empty()
            && self.data.is_empty()
            && self.name.is_none()
            && self.appearance == u16::MAX
    }

    // =========================================================================
    // Service UUID Operations
    // =========================================================================

    /// Adds a service UUID to the advertising data.
    ///
    /// Note: This does NOT deduplicate — calling code may add the same UUID
    /// multiple times. The C `bt_ad_add_service_uuid` also does not deduplicate;
    /// deduplication occurs only during parsing in `new_with_data`.
    pub fn add_service_uuid(&mut self, uuid: &BtUuid) -> bool {
        self.service_uuids.push(uuid.clone());
        true
    }

    /// Checks whether the given UUID is present in the service UUID list.
    ///
    /// Uses full 128-bit comparison (cross-type), matching C's `bt_uuid_cmp`.
    pub fn has_service_uuid(&self, uuid: &BtUuid) -> bool {
        self.service_uuids.iter().any(|u| uuid_eq(u, uuid))
    }

    /// Removes the first occurrence of the given UUID from the service list.
    ///
    /// Returns `true` if found and removed.
    pub fn remove_service_uuid(&mut self, uuid: &BtUuid) -> bool {
        if let Some(pos) = self.service_uuids.iter().position(|u| uuid_eq(u, uuid)) {
            self.service_uuids.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes all service UUIDs.
    pub fn clear_service_uuid(&mut self) {
        self.service_uuids.clear();
    }

    // =========================================================================
    // Manufacturer Data Operations
    // =========================================================================

    /// Adds or updates manufacturer-specific data.
    ///
    /// If an entry with the same `manufacturer_id` exists:
    /// - If the data is identical, returns `false` (no change).
    /// - If the data differs, updates the existing entry in place.
    ///
    /// Returns `false` if the data exceeds the maximum AD field length.
    pub fn add_manufacturer_data(&mut self, id: u16, data: &[u8]) -> bool {
        // Check max length: header(2) + manufacturer_id(2) + data
        if data.len() > (self.max_len as usize).saturating_sub(4) {
            return false;
        }

        if let Some(existing) = self.manufacturer_data.iter_mut().find(|m| m.manufacturer_id == id)
        {
            if existing.data == data {
                return false;
            }
            existing.data = data.to_vec();
            return true;
        }

        self.manufacturer_data.push(ManufacturerData { manufacturer_id: id, data: data.to_vec() });
        true
    }

    /// Checks if manufacturer data matching the given entry exists.
    ///
    /// Compares both `manufacturer_id` and `data` for a full match.
    pub fn has_manufacturer_data(&self, data: &ManufacturerData) -> bool {
        self.manufacturer_data
            .iter()
            .any(|m| m.manufacturer_id == data.manufacturer_id && m.data == data.data)
    }

    /// Calls the given function for each manufacturer data entry.
    pub fn foreach_manufacturer_data(&self, mut func: impl FnMut(&ManufacturerData)) {
        for entry in &self.manufacturer_data {
            func(entry);
        }
    }

    /// Removes the manufacturer data entry with the given ID.
    ///
    /// Returns `true` if an entry was found and removed.
    pub fn remove_manufacturer_data(&mut self, manufacturer_id: u16) -> bool {
        if let Some(pos) =
            self.manufacturer_data.iter().position(|m| m.manufacturer_id == manufacturer_id)
        {
            self.manufacturer_data.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes all manufacturer data entries.
    pub fn clear_manufacturer_data(&mut self) {
        self.manufacturer_data.clear();
    }

    // =========================================================================
    // Solicit UUID Operations
    // =========================================================================

    /// Adds a solicitation UUID.
    pub fn add_solicit_uuid(&mut self, uuid: &BtUuid) -> bool {
        self.solicit_uuids.push(uuid.clone());
        true
    }

    /// Removes the first occurrence of the given solicitation UUID.
    ///
    /// Returns `true` if found and removed.
    pub fn remove_solicit_uuid(&mut self, uuid: &BtUuid) -> bool {
        if let Some(pos) = self.solicit_uuids.iter().position(|u| uuid_eq(u, uuid)) {
            self.solicit_uuids.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes all solicitation UUIDs.
    pub fn clear_solicit_uuid(&mut self) {
        self.solicit_uuids.clear();
    }

    // =========================================================================
    // Service Data Operations
    // =========================================================================

    /// Adds or updates service data for a given UUID.
    ///
    /// If service data for the same UUID already exists:
    /// - If the data is identical, returns `false`.
    /// - If the data differs, updates in place.
    ///
    /// Returns `false` if the data exceeds the maximum AD field length.
    pub fn add_service_data(&mut self, uuid: &BtUuid, data: &[u8]) -> bool {
        let u_len = uuid_byte_len(uuid);
        // Check max length: header(2) + uuid_bytes + data
        if data.len() > (self.max_len as usize).saturating_sub(2 + u_len) {
            return false;
        }

        if let Some(existing) = self.service_data.iter_mut().find(|s| uuid_eq(&s.uuid, uuid)) {
            if existing.data == data {
                return false;
            }
            existing.data = data.to_vec();
            return true;
        }

        self.service_data.push(ServiceData { uuid: uuid.clone(), data: data.to_vec() });
        true
    }

    /// Checks if service data matching the given entry exists.
    ///
    /// Compares UUID (via 128-bit expansion) and data for full match.
    pub fn has_service_data(&self, data: &ServiceData) -> bool {
        self.service_data.iter().any(|s| uuid_eq(&s.uuid, &data.uuid) && s.data == data.data)
    }

    /// Calls the given function for each service data entry.
    pub fn foreach_service_data(&self, mut func: impl FnMut(&ServiceData)) {
        for entry in &self.service_data {
            func(entry);
        }
    }

    /// Removes the service data entry for the given UUID.
    ///
    /// Returns `true` if found and removed.
    pub fn remove_service_data(&mut self, uuid: &BtUuid) -> bool {
        if let Some(pos) = self.service_data.iter().position(|s| uuid_eq(&s.uuid, uuid)) {
            self.service_data.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes all service data entries.
    pub fn clear_service_data(&mut self) {
        self.service_data.clear();
    }

    // =========================================================================
    // Name Operations
    // =========================================================================

    /// Sets the local device name for advertising.
    ///
    /// The name is validated as UTF-8. If invalid, it is converted using
    /// lossy UTF-8 conversion and leading/trailing whitespace is stripped.
    /// Returns `false` if the resulting name is empty.
    pub fn add_name(&mut self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }

        // In C: if (!strisutf8(name, len)) name = strtoutf8(name, len, NULL)
        //        then strstrip(name)
        // If valid UTF-8, use directly without stripping.
        let final_name = if stris_utf8(name.as_bytes()) {
            name.to_owned()
        } else {
            let converted = str_to_utf8(name.as_bytes());
            strstrip(&converted).to_owned()
        };

        if final_name.is_empty() {
            return false;
        }

        self.name = Some(final_name);
        true
    }

    /// Returns the current advertising name, if set.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Clears the advertising name.
    pub fn clear_name(&mut self) {
        self.name = None;
    }

    // =========================================================================
    // Appearance Operations
    // =========================================================================

    /// Sets the GAP Appearance value.
    pub fn add_appearance(&mut self, appearance: u16) -> bool {
        self.appearance = appearance;
        true
    }

    /// Clears the appearance (resets to unset sentinel).
    pub fn clear_appearance(&mut self) {
        self.appearance = u16::MAX;
    }

    // =========================================================================
    // Flags Operations
    // =========================================================================

    /// Sets the AD flags.
    ///
    /// Flags are stored as generic data with type `BT_AD_FLAGS`.
    /// Validates that `flags` has at most 1 byte and the top 3 bits are clear.
    pub fn add_flags(&mut self, flags: &[u8]) -> bool {
        if flags.len() > 1 {
            return false;
        }

        // Top 3 bits must be clear
        if !flags.is_empty() && (flags[0] & 0xe0) != 0 {
            return false;
        }

        // Store as generic data via the data vector
        self.replace_generic_data(BT_AD_FLAGS, flags)
    }

    /// Returns `true` if flags data is present.
    pub fn has_flags(&self) -> bool {
        self.data.iter().any(|d| d.ad_type == BT_AD_FLAGS)
    }

    /// Returns the flags byte value, or 0 if not set.
    pub fn get_flags(&self) -> u8 {
        for d in &self.data {
            if d.ad_type == BT_AD_FLAGS {
                if d.data.is_empty() {
                    return 0;
                }
                return d.data[0];
            }
        }
        0
    }

    /// Removes the flags data.
    pub fn clear_flags(&mut self) {
        self.data.retain(|d| d.ad_type != BT_AD_FLAGS);
    }

    // =========================================================================
    // Generic Data Operations
    // =========================================================================

    /// Adds a generic AD data entry.
    ///
    /// Standard AD types (flags, UUIDs, name, appearance, manufacturer data,
    /// service data) are rejected — use the dedicated methods instead.
    /// If an entry with the same `ad_type` already exists, it is replaced.
    pub fn add_data(&mut self, ad_type: u8, data: &[u8]) -> bool {
        if TYPE_REJECT_LIST.contains(&ad_type) {
            return false;
        }

        self.replace_generic_data(ad_type, data)
    }

    /// Checks whether generic data matching the given entry exists.
    ///
    /// If `data.data` is empty, matches by `ad_type` alone.
    /// Otherwise, matches both `ad_type` and `data` content.
    /// Returns a reference to the matching entry, or `None`.
    pub fn has_data(&self, data: &AdData) -> Option<&AdData> {
        self.data.iter().find(|d| {
            if d.ad_type != data.ad_type {
                return false;
            }
            if data.data.is_empty() {
                return true;
            }
            d.data == data.data
        })
    }

    /// Calls the given function for each generic AD data entry.
    pub fn foreach_data(&self, mut func: impl FnMut(&AdData)) {
        for entry in &self.data {
            func(entry);
        }
    }

    /// Removes the first generic data entry with the given type.
    ///
    /// Returns `true` if an entry was found and removed.
    pub fn remove_data(&mut self, ad_type: u8) -> bool {
        if let Some(pos) = self.data.iter().position(|d| d.ad_type == ad_type) {
            self.data.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes all generic AD data entries.
    pub fn clear_data(&mut self) {
        self.data.clear();
    }

    // =========================================================================
    // TX Power
    // =========================================================================

    /// Returns the TX Power Level from generic data, or 127 if not present.
    ///
    /// TX power is stored as a single signed byte in generic data with type
    /// `BT_AD_TX_POWER`. Returns 127 (max power) as sentinel when absent,
    /// matching C's `bt_ad_get_tx_power` behavior.
    pub fn get_tx_power(&self) -> i8 {
        for d in &self.data {
            if d.ad_type == BT_AD_TX_POWER {
                if d.data.len() != 1 {
                    return 127;
                }
                return d.data[0] as i8;
            }
        }
        127
    }

    // =========================================================================
    // Pattern Matching
    // =========================================================================

    /// Matches this AD against a list of patterns.
    ///
    /// Returns a reference to the first matching pattern, or `None`.
    /// Pattern matching dispatches by AD type:
    /// - `BT_AD_MANUFACTURER_DATA`: matches against manufacturer data
    /// - `BT_AD_SERVICE_DATA16/32/128`: matches against service data
    /// - All others: matches against generic data entries
    pub fn pattern_match<'a>(&self, patterns: &'a [AdPattern]) -> Option<&'a AdPattern> {
        patterns.iter().find(|pattern| pattern_match_single(self, pattern))
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /// Replaces or inserts generic data for the given AD type.
    fn replace_generic_data(&mut self, ad_type: u8, data: &[u8]) -> bool {
        if let Some(existing) = self.data.iter_mut().find(|d| d.ad_type == ad_type) {
            existing.data = data.to_vec();
        } else {
            self.data.push(AdData { ad_type, data: data.to_vec() });
        }
        true
    }
}

// =============================================================================
// Pattern Construction
// =============================================================================

/// Creates a new `AdPattern` for content matching.
///
/// Validates that `offset + len` does not exceed `BT_AD_MAX_DATA_LEN`.
/// Returns `None` if validation fails or if `data` is shorter than `len`.
pub fn pattern_new(ad_type: u8, offset: usize, len: usize, data: &[u8]) -> Option<AdPattern> {
    let max = BT_AD_MAX_DATA_LEN as usize;

    if offset >= max {
        return None;
    }
    if len > max {
        return None;
    }
    if offset + len > max {
        return None;
    }

    if data.len() < len {
        return None;
    }

    let mut pattern_data = [0u8; BT_AD_MAX_DATA_LEN as usize];
    pattern_data[..len].copy_from_slice(&data[..len]);

    Some(AdPattern { ad_type, offset: offset as u8, len: len as u8, data: pattern_data })
}

// =============================================================================
// Serialization Helper Functions
// =============================================================================

/// Calculates the total serialized length for a list of UUIDs.
///
/// UUIDs are grouped by size (16/32/128), with each group getting a
/// 2-byte header (length + type). Returns the total byte count.
fn uuid_list_length(uuids: &[BtUuid]) -> usize {
    if uuids.is_empty() {
        return 0;
    }

    let mut len = 0usize;
    let mut has_16 = false;
    let mut has_32 = false;
    let mut has_128 = false;

    for uuid in uuids {
        match uuid {
            BtUuid::Uuid16(_) => {
                if !has_16 {
                    len += 2; // header: length + type bytes
                    has_16 = true;
                }
                len += 2;
            }
            BtUuid::Uuid32(_) => {
                if !has_32 {
                    len += 2;
                    has_32 = true;
                }
                len += 4;
            }
            BtUuid::Uuid128(_) => {
                if !has_128 {
                    len += 2;
                    has_128 = true;
                }
                len += 16;
            }
        }
    }

    len
}

/// Calculates the name field length for serialization.
///
/// If the name would cause the total AD to exceed `max_len`, the name
/// may be truncated. When `pos >= max_len`, returns the full name length
/// (which will cause `generate()` to fail), matching C's overflow behavior.
fn name_length(name: &Option<String>, pos: usize, max_len: u8) -> usize {
    let name_str = match name {
        Some(n) => n,
        None => return 0,
    };

    // 2-byte header + name bytes
    let full_len = 2 + name_str.len();

    if pos >= max_len as usize {
        // C behavior: returns full length even though it will overflow
        return full_len;
    }

    let remaining = (max_len as usize) - pos;

    if full_len > remaining {
        // Truncated: use all remaining space
        remaining
    } else {
        full_len
    }
}

/// Serializes a list of UUIDs into LTV format.
///
/// Groups UUIDs by size (16-bit, 32-bit, 128-bit) and writes each
/// group with a single type header, matching C's `serialize_uuids`.
/// If `solicit` is true, uses solicit UUID type codes; otherwise,
/// uses service UUID type codes (with the ALL variant).
fn serialize_uuids(iov: &mut IoBuf, uuids: &[BtUuid], solicit: bool) {
    if uuids.is_empty() {
        return;
    }

    // Count UUIDs by size
    let count_16 = uuids.iter().filter(|u| matches!(u, BtUuid::Uuid16(_))).count();
    let count_32 = uuids.iter().filter(|u| matches!(u, BtUuid::Uuid32(_))).count();
    let count_128 = uuids.iter().filter(|u| matches!(u, BtUuid::Uuid128(_))).count();

    // Serialize 16-bit UUIDs
    if count_16 > 0 {
        let data_len = count_16 * 2;
        iov.push_u8((1 + data_len) as u8);
        if solicit {
            iov.push_u8(BT_AD_SOLICIT16);
        } else {
            iov.push_u8(BT_AD_UUID16_ALL);
        }
        for uuid in uuids {
            if let BtUuid::Uuid16(v) = uuid {
                iov.push_le16(*v);
            }
        }
    }

    // Serialize 32-bit UUIDs
    if count_32 > 0 {
        let data_len = count_32 * 4;
        iov.push_u8((1 + data_len) as u8);
        if solicit {
            iov.push_u8(BT_AD_SOLICIT32);
        } else {
            iov.push_u8(BT_AD_UUID32_ALL);
        }
        for uuid in uuids {
            if let BtUuid::Uuid32(v) = uuid {
                iov.push_le32(*v);
            }
        }
    }

    // Serialize 128-bit UUIDs
    if count_128 > 0 {
        let data_len = count_128 * 16;
        iov.push_u8((1 + data_len) as u8);
        if solicit {
            iov.push_u8(BT_AD_SOLICIT128);
        } else {
            iov.push_u8(BT_AD_UUID128_ALL);
        }
        for uuid in uuids {
            if let BtUuid::Uuid128(v) = uuid {
                iov.push_mem(v);
            }
        }
    }
}

/// Serializes the device name into the AD buffer.
///
/// If the name fits within the remaining space, uses `BT_AD_NAME_COMPLETE`.
/// If it must be truncated, uses `BT_AD_NAME_SHORT`.
fn serialize_name(iov: &mut IoBuf, name: &Option<String>, max_len: u8) {
    let name_str = match name {
        Some(n) => n,
        None => return,
    };

    let pos = iov.len();
    let remaining = if pos < max_len as usize {
        (max_len as usize) - pos
    } else {
        return;
    };

    // 2-byte header + name data
    let full_len = 2 + name_str.len();
    let name_bytes = name_str.as_bytes();

    if full_len <= remaining {
        // Complete name fits
        iov.push_u8((1 + name_bytes.len()) as u8);
        iov.push_u8(BT_AD_NAME_COMPLETE);
        iov.push_mem(name_bytes);
    } else if remaining >= 3 {
        // Truncated name (need at least 3 bytes: length + type + 1 char)
        let trunc_len = remaining - 2;
        iov.push_u8((1 + trunc_len) as u8);
        iov.push_u8(BT_AD_NAME_SHORT);
        iov.push_mem(&name_bytes[..trunc_len]);
    }
}

// =============================================================================
// Parsing Helper Functions
// =============================================================================

/// Routes parsed AD data to the appropriate field of a `BtAd`.
///
/// Matches C's `ad_replace_data` switch statement, dispatching by AD type
/// to populate UUIDs, name, manufacturer data, service data, or generic data.
fn ad_replace_data(ad: &mut BtAd, ad_type: u8, data: &[u8]) {
    match ad_type {
        BT_AD_UUID16_SOME | BT_AD_UUID16_ALL => {
            ad_replace_uuid16(ad, data);
        }
        BT_AD_UUID32_SOME | BT_AD_UUID32_ALL => {
            ad_replace_uuid32(ad, data);
        }
        BT_AD_UUID128_SOME | BT_AD_UUID128_ALL => {
            ad_replace_uuid128(ad, data);
        }
        BT_AD_NAME_SHORT | BT_AD_NAME_COMPLETE => {
            ad_replace_name(ad, data);
        }
        BT_AD_SOLICIT16 => {
            ad_replace_solicit_uuid16(ad, data);
        }
        BT_AD_SOLICIT32 => {
            ad_replace_solicit_uuid32(ad, data);
        }
        BT_AD_SOLICIT128 => {
            ad_replace_solicit_uuid128(ad, data);
        }
        BT_AD_SERVICE_DATA16 => {
            ad_replace_uuid16_data(ad, data);
        }
        BT_AD_SERVICE_DATA32 => {
            ad_replace_uuid32_data(ad, data);
        }
        BT_AD_SERVICE_DATA128 => {
            ad_replace_uuid128_data(ad, data);
        }
        BT_AD_MANUFACTURER_DATA => {
            ad_replace_manufacturer_data(ad, data);
        }
        _ => {
            // Store as generic data
            ad.replace_generic_data(ad_type, data);
        }
    }
}

/// Parses 16-bit service UUIDs from raw AD data using `IoBuf::pull_le16`.
fn ad_replace_uuid16(ad: &mut BtAd, data: &[u8]) {
    let mut iov = IoBuf::from_bytes(data);
    while let Some(val) = iov.pull_le16() {
        let uuid = BtUuid::from_u16(val);
        if !ad.has_service_uuid(&uuid) {
            ad.service_uuids.push(uuid);
        }
    }
}

/// Parses 32-bit service UUIDs from raw AD data using `IoBuf::pull_le32`.
fn ad_replace_uuid32(ad: &mut BtAd, data: &[u8]) {
    let mut iov = IoBuf::from_bytes(data);
    while let Some(val) = iov.pull_le32() {
        let uuid = BtUuid::from_u32(val);
        if !ad.has_service_uuid(&uuid) {
            ad.service_uuids.push(uuid);
        }
    }
}

/// Parses 128-bit service UUIDs from raw AD data.
///
/// The C code reads 16 bytes and passes them directly to `bt_uuid128_create`
/// which interprets them as a big-endian `uint128_t` and then stores them.
/// In Rust, `BtUuid::from_bytes` takes the 16-byte array directly.
fn ad_replace_uuid128(ad: &mut BtAd, data: &[u8]) {
    let mut offset = 0;
    while offset + 16 <= data.len() {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[offset..offset + 16]);
        let uuid = BtUuid::from_bytes(&bytes);
        if !ad.has_service_uuid(&uuid) {
            ad.service_uuids.push(uuid);
        }
        offset += 16;
    }
}

/// Parses a device name from raw AD data, with UTF-8 validation.
fn ad_replace_name(ad: &mut BtAd, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    if stris_utf8(data) {
        // Valid UTF-8 — use directly without stripping
        if let Ok(s) = core::str::from_utf8(data) {
            ad.name = Some(s.to_owned());
        }
    } else {
        // Invalid UTF-8 — convert with lossy and strip whitespace
        let converted = str_to_utf8(data);
        let stripped = strstrip(&converted);
        if !stripped.is_empty() {
            ad.name = Some(stripped.to_owned());
        }
    }
}

/// Parses 16-bit solicitation UUIDs from raw AD data using `IoBuf::pull_le16`.
fn ad_replace_solicit_uuid16(ad: &mut BtAd, data: &[u8]) {
    let mut iov = IoBuf::from_bytes(data);
    while let Some(val) = iov.pull_le16() {
        let uuid = BtUuid::from_u16(val);
        ad.solicit_uuids.push(uuid);
    }
}

/// Parses 32-bit solicitation UUIDs from raw AD data using `IoBuf::pull_le32`.
fn ad_replace_solicit_uuid32(ad: &mut BtAd, data: &[u8]) {
    let mut iov = IoBuf::from_bytes(data);
    while let Some(val) = iov.pull_le32() {
        let uuid = BtUuid::from_u32(val);
        ad.solicit_uuids.push(uuid);
    }
}

/// Parses 128-bit solicitation UUIDs from raw AD data.
fn ad_replace_solicit_uuid128(ad: &mut BtAd, data: &[u8]) {
    let mut offset = 0;
    while offset + 16 <= data.len() {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[offset..offset + 16]);
        let uuid = BtUuid::from_bytes(&bytes);
        ad.solicit_uuids.push(uuid);
        offset += 16;
    }
}

/// Parses 16-bit service data from raw AD data.
/// Uses standalone `get_le16` for the single UUID value extraction.
fn ad_replace_uuid16_data(ad: &mut BtAd, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let val = get_le16(data);
    let uuid = BtUuid::from_u16(val);
    let payload = &data[2..];
    ad.add_service_data(&uuid, payload);
}

/// Parses 32-bit service data from raw AD data.
/// Uses standalone `get_le32` for the single UUID value extraction.
fn ad_replace_uuid32_data(ad: &mut BtAd, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let val = get_le32(data);
    let uuid = BtUuid::from_u32(val);
    let payload = &data[4..];
    ad.add_service_data(&uuid, payload);
}

/// Parses 128-bit service data from raw AD data.
fn ad_replace_uuid128_data(ad: &mut BtAd, data: &[u8]) {
    if data.len() < 16 {
        return;
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[..16]);
    let uuid = BtUuid::from_bytes(&bytes);
    let payload = &data[16..];
    ad.add_service_data(&uuid, payload);
}

/// Parses manufacturer data from raw AD data.
/// Uses standalone `get_le16` for the single manufacturer ID extraction.
fn ad_replace_manufacturer_data(ad: &mut BtAd, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let id = get_le16(data);
    let payload = &data[2..];
    ad.add_manufacturer_data(id, payload);
}

// =============================================================================
// Pattern Matching Internals
// =============================================================================

/// Tests a single pattern against a `BtAd`.
///
/// Dispatches by pattern AD type to the appropriate collection.
fn pattern_match_single(ad: &BtAd, pattern: &AdPattern) -> bool {
    match pattern.ad_type {
        BT_AD_MANUFACTURER_DATA => match_manufacturer(ad, pattern),
        BT_AD_SERVICE_DATA16 | BT_AD_SERVICE_DATA32 | BT_AD_SERVICE_DATA128 => {
            match_service(ad, pattern)
        }
        _ => match_ad_data(ad, pattern),
    }
}

/// Matches a pattern against manufacturer data.
///
/// For each manufacturer data entry, builds a combined buffer consisting of
/// the manufacturer ID as LE16 followed by the data payload, then checks
/// if the pattern matches at the specified offset.
fn match_manufacturer(ad: &BtAd, pattern: &AdPattern) -> bool {
    let offset = pattern.offset as usize;
    let len = pattern.len as usize;
    let pattern_data = &pattern.data[..len];

    for mfg in &ad.manufacturer_data {
        // Build combined buffer: [manufacturer_id LE16] + [data]
        let total_len = 2 + mfg.data.len();
        if offset + len > total_len {
            continue;
        }
        let mut buf = Vec::with_capacity(total_len);
        let mut id_bytes = [0u8; 2];
        put_le16(mfg.manufacturer_id, &mut id_bytes);
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&mfg.data);

        if buf[offset..offset + len] == *pattern_data {
            return true;
        }
    }
    false
}

/// Matches a pattern against service data.
///
/// Compares the pattern against each service data entry's data payload
/// (NOT including the UUID bytes), at the specified offset.
fn match_service(ad: &BtAd, pattern: &AdPattern) -> bool {
    let offset = pattern.offset as usize;
    let len = pattern.len as usize;
    let pattern_data = &pattern.data[..len];

    for sd in &ad.service_data {
        if offset + len > sd.data.len() {
            continue;
        }
        if sd.data[offset..offset + len] == *pattern_data {
            return true;
        }
    }
    false
}

/// Matches a pattern against generic AD data entries.
///
/// Searches entries matching the pattern's AD type, then compares
/// the data at the specified offset.
fn match_ad_data(ad: &BtAd, pattern: &AdPattern) -> bool {
    let offset = pattern.offset as usize;
    let len = pattern.len as usize;
    let pattern_data = &pattern.data[..len];

    for d in &ad.data {
        if d.ad_type != pattern.ad_type {
            continue;
        }
        if offset + len > d.data.len() {
            continue;
        }
        if d.data[offset..offset + len] == *pattern_data {
            return true;
        }
    }
    false
}
