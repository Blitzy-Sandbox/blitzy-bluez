// SPDX-License-Identifier: GPL-2.0-or-later
//
// Bluetooth advertising data builder/parser replacing src/shared/ad.c
//
// Provides a builder for BLE advertising data (AD) structures, supporting
// service UUIDs, manufacturer data, service data, name, appearance, and
// generic AD entries. Supports both legacy (31 bytes) and extended (251 bytes)
// advertising.

use crate::uuid::Uuid;

// ---- AD Type Codes ----

pub const BT_AD_FLAGS: u8 = 0x01;
pub const BT_AD_UUID16_SOME: u8 = 0x02;
pub const BT_AD_UUID16_ALL: u8 = 0x03;
pub const BT_AD_UUID32_SOME: u8 = 0x04;
pub const BT_AD_UUID32_ALL: u8 = 0x05;
pub const BT_AD_UUID128_SOME: u8 = 0x06;
pub const BT_AD_UUID128_ALL: u8 = 0x07;
pub const BT_AD_NAME_SHORT: u8 = 0x08;
pub const BT_AD_NAME_COMPLETE: u8 = 0x09;
pub const BT_AD_TX_POWER: u8 = 0x0A;
pub const BT_AD_CLASS_OF_DEV: u8 = 0x0D;
pub const BT_AD_SSP_HASH: u8 = 0x0E;
pub const BT_AD_SSP_RANDOMIZER: u8 = 0x0F;
pub const BT_AD_DEVICE_ID: u8 = 0x10;
pub const BT_AD_SMP_TK: u8 = 0x10;
pub const BT_AD_SMP_OOB_FLAGS: u8 = 0x11;
pub const BT_AD_PERIPHERAL_CONN_INTERVAL: u8 = 0x12;
pub const BT_AD_SOLICIT16: u8 = 0x14;
pub const BT_AD_SOLICIT128: u8 = 0x15;
pub const BT_AD_SERVICE_DATA16: u8 = 0x16;
pub const BT_AD_PUBLIC_ADDRESS: u8 = 0x17;
pub const BT_AD_RANDOM_ADDRESS: u8 = 0x18;
pub const BT_AD_GAP_APPEARANCE: u8 = 0x19;
pub const BT_AD_ADVERTISING_INTERVAL: u8 = 0x1A;
pub const BT_AD_LE_DEVICE_ADDRESS: u8 = 0x1B;
pub const BT_AD_LE_ROLE: u8 = 0x1C;
pub const BT_AD_SSP_HASH_P256: u8 = 0x1D;
pub const BT_AD_SSP_RANDOMIZER_P256: u8 = 0x1E;
pub const BT_AD_SOLICIT32: u8 = 0x1F;
pub const BT_AD_SERVICE_DATA32: u8 = 0x20;
pub const BT_AD_SERVICE_DATA128: u8 = 0x21;
pub const BT_AD_LE_SC_CONFIRM_VALUE: u8 = 0x22;
pub const BT_AD_LE_SC_RANDOM_VALUE: u8 = 0x23;
pub const BT_AD_LE_SUPPORTED_FEATURES: u8 = 0x27;
pub const BT_AD_CHANNEL_MAP_UPDATE_IND: u8 = 0x28;
pub const BT_AD_MESH_PROV: u8 = 0x29;
pub const BT_AD_MESH_DATA: u8 = 0x2A;
pub const BT_AD_MESH_BEACON: u8 = 0x2B;
pub const BT_AD_3D_INFO_DATA: u8 = 0x3D;
pub const BT_AD_MANUFACTURER_DATA: u8 = 0xFF;

// ---- AD Flag Bits ----

pub const BT_AD_FLAG_LIMITED: u8 = 0x01;
pub const BT_AD_FLAG_GENERAL: u8 = 0x02;
pub const BT_AD_FLAG_NO_BREDR: u8 = 0x04;
pub const BT_AD_FLAG_LE_BREDR_CTRL: u8 = 0x08;
pub const BT_AD_FLAG_LE_BREDR_HOST: u8 = 0x10;

// ---- AD Length Limits ----

/// Maximum legacy advertising data length.
pub const BT_AD_MAX_DATA_LEN: usize = 31;
/// Maximum extended advertising data length.
pub const BT_EA_MAX_DATA_LEN: usize = 251;
/// Maximum periodic advertising data length.
pub const BT_PA_MAX_DATA_LEN: usize = 252;

/// Manufacturer-specific data entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManufacturerData {
    pub manufacturer_id: u16,
    pub data: Vec<u8>,
}

/// Service data entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceData {
    pub uuid: Uuid,
    pub data: Vec<u8>,
}

/// Generic AD data entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdData {
    pub ad_type: u8,
    pub data: Vec<u8>,
}

/// AD pattern for advertisement matching.
#[derive(Debug, Clone)]
pub struct AdPattern {
    pub ad_type: u8,
    pub offset: u8,
    pub data: Vec<u8>,
}

/// Bluetooth advertising data builder and parser.
///
/// Replaces C's `struct bt_ad`. Supports building and parsing BLE
/// advertising data structures (TLV format).
///
/// ```ignore
/// let mut ad = BtAd::new();
/// ad.add_service_uuid(Uuid::from_u16(0x180F));
/// ad.set_name("MyDevice");
/// let bytes = ad.generate();
/// ```
pub struct BtAd {
    max_len: usize,
    name: Option<String>,
    appearance: Option<u16>,
    service_uuids: Vec<Uuid>,
    solicit_uuids: Vec<Uuid>,
    manufacturer_data: Vec<ManufacturerData>,
    service_data: Vec<ServiceData>,
    data: Vec<AdData>,
}

impl BtAd {
    /// Create a new empty AD structure with default max length (251, extended).
    pub fn new() -> Self {
        Self {
            max_len: BT_EA_MAX_DATA_LEN,
            name: None,
            appearance: None,
            service_uuids: Vec::new(),
            solicit_uuids: Vec::new(),
            manufacturer_data: Vec::new(),
            service_data: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Parse AD data from raw TLV bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut ad = Self::new();
        let mut offset = 0;

        while offset < bytes.len() {
            let len = bytes[offset] as usize;
            if len == 0 || offset + 1 + len > bytes.len() {
                break;
            }

            let ad_type = bytes[offset + 1];
            let value = &bytes[offset + 2..offset + 1 + len];

            ad.parse_tlv(ad_type, value);
            offset += 1 + len;
        }

        ad
    }

    /// Set the maximum AD data length.
    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    /// Check if the AD data is empty.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.appearance.is_none()
            && self.service_uuids.is_empty()
            && self.solicit_uuids.is_empty()
            && self.manufacturer_data.is_empty()
            && self.service_data.is_empty()
            && self.data.is_empty()
    }

    // ---- Service UUIDs ----

    /// Add a service UUID.
    pub fn add_service_uuid(&mut self, uuid: Uuid) -> bool {
        if self.has_service_uuid(&uuid) {
            return false;
        }
        self.service_uuids.push(uuid);
        true
    }

    /// Check if a service UUID is present.
    pub fn has_service_uuid(&self, uuid: &Uuid) -> bool {
        self.service_uuids
            .iter()
            .any(|u| u.eq_as_uuid128(uuid))
    }

    /// Remove a service UUID.
    pub fn remove_service_uuid(&mut self, uuid: &Uuid) -> bool {
        let before = self.service_uuids.len();
        self.service_uuids
            .retain(|u| !u.eq_as_uuid128(uuid));
        self.service_uuids.len() != before
    }

    /// Clear all service UUIDs.
    pub fn clear_service_uuids(&mut self) {
        self.service_uuids.clear();
    }

    // ---- Solicit UUIDs ----

    pub fn add_solicit_uuid(&mut self, uuid: Uuid) -> bool {
        if self.solicit_uuids.iter().any(|u| u.eq_as_uuid128(&uuid)) {
            return false;
        }
        self.solicit_uuids.push(uuid);
        true
    }

    pub fn remove_solicit_uuid(&mut self, uuid: &Uuid) -> bool {
        let before = self.solicit_uuids.len();
        self.solicit_uuids.retain(|u| !u.eq_as_uuid128(uuid));
        self.solicit_uuids.len() != before
    }

    pub fn clear_solicit_uuids(&mut self) {
        self.solicit_uuids.clear();
    }

    // ---- Manufacturer Data ----

    /// Add or update manufacturer data. Returns false if data is identical.
    pub fn add_manufacturer_data(&mut self, id: u16, data: &[u8]) -> bool {
        if let Some(existing) = self
            .manufacturer_data
            .iter_mut()
            .find(|m| m.manufacturer_id == id)
        {
            if existing.data == data {
                return false;
            }
            existing.data = data.to_vec();
            return true;
        }
        self.manufacturer_data.push(ManufacturerData {
            manufacturer_id: id,
            data: data.to_vec(),
        });
        true
    }

    pub fn has_manufacturer_data(&self, id: u16) -> bool {
        self.manufacturer_data.iter().any(|m| m.manufacturer_id == id)
    }

    pub fn remove_manufacturer_data(&mut self, id: u16) -> bool {
        let before = self.manufacturer_data.len();
        self.manufacturer_data.retain(|m| m.manufacturer_id != id);
        self.manufacturer_data.len() != before
    }

    pub fn clear_manufacturer_data(&mut self) {
        self.manufacturer_data.clear();
    }

    /// Iterate over manufacturer data entries.
    pub fn foreach_manufacturer_data<F>(&self, mut f: F)
    where
        F: FnMut(&ManufacturerData),
    {
        for m in &self.manufacturer_data {
            f(m);
        }
    }

    // ---- Service Data ----

    /// Add or update service data. Returns false if data is identical.
    pub fn add_service_data(&mut self, uuid: Uuid, data: &[u8]) -> bool {
        if let Some(existing) = self
            .service_data
            .iter_mut()
            .find(|s| s.uuid.eq_as_uuid128(&uuid))
        {
            if existing.data == data {
                return false;
            }
            existing.data = data.to_vec();
            return true;
        }
        self.service_data.push(ServiceData {
            uuid,
            data: data.to_vec(),
        });
        true
    }

    pub fn has_service_data(&self, uuid: &Uuid) -> bool {
        self.service_data.iter().any(|s| s.uuid.eq_as_uuid128(uuid))
    }

    pub fn remove_service_data(&mut self, uuid: &Uuid) -> bool {
        let before = self.service_data.len();
        self.service_data.retain(|s| !s.uuid.eq_as_uuid128(uuid));
        self.service_data.len() != before
    }

    pub fn clear_service_data(&mut self) {
        self.service_data.clear();
    }

    pub fn foreach_service_data<F>(&self, mut f: F)
    where
        F: FnMut(&ServiceData),
    {
        for s in &self.service_data {
            f(s);
        }
    }

    // ---- Name ----

    pub fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_string());
    }

    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn clear_name(&mut self) {
        self.name = None;
    }

    // ---- Appearance ----

    pub fn set_appearance(&mut self, appearance: u16) {
        self.appearance = Some(appearance);
    }

    pub fn clear_appearance(&mut self) {
        self.appearance = None;
    }

    // ---- Flags ----

    pub fn add_flags(&mut self, flags: u8) -> bool {
        self.add_data(BT_AD_FLAGS, &[flags])
    }

    pub fn has_flags(&self) -> bool {
        self.data.iter().any(|d| d.ad_type == BT_AD_FLAGS)
    }

    pub fn get_flags(&self) -> Option<u8> {
        self.data
            .iter()
            .find(|d| d.ad_type == BT_AD_FLAGS)
            .and_then(|d| d.data.first().copied())
    }

    pub fn clear_flags(&mut self) {
        self.data.retain(|d| d.ad_type != BT_AD_FLAGS);
    }

    // ---- TX Power ----

    pub fn get_tx_power(&self) -> Option<i8> {
        self.data
            .iter()
            .find(|d| d.ad_type == BT_AD_TX_POWER)
            .and_then(|d| d.data.first().map(|&v| v as i8))
    }

    // ---- Generic Data ----

    /// Add generic AD data. Returns false if identical data already exists.
    pub fn add_data(&mut self, ad_type: u8, data: &[u8]) -> bool {
        // Check for types handled by dedicated APIs
        if is_dedicated_type(ad_type) && ad_type != BT_AD_FLAGS {
            return false;
        }

        if let Some(existing) = self.data.iter_mut().find(|d| d.ad_type == ad_type) {
            if existing.data == data {
                return false;
            }
            existing.data = data.to_vec();
            return true;
        }

        self.data.push(AdData {
            ad_type,
            data: data.to_vec(),
        });
        true
    }

    pub fn has_data(&self, ad_type: u8) -> bool {
        self.data.iter().any(|d| d.ad_type == ad_type)
    }

    pub fn remove_data(&mut self, ad_type: u8) -> bool {
        let before = self.data.len();
        self.data.retain(|d| d.ad_type != ad_type);
        self.data.len() != before
    }

    pub fn clear_data(&mut self) {
        self.data.clear();
    }

    pub fn foreach_data<F>(&self, mut f: F)
    where
        F: FnMut(&AdData),
    {
        for d in &self.data {
            f(d);
        }
    }

    // ---- Pattern Matching ----

    /// Check if the AD data matches any of the given patterns.
    /// Returns the index of the first matching pattern, or None.
    pub fn pattern_match(&self, patterns: &[AdPattern]) -> Option<usize> {
        for (i, pattern) in patterns.iter().enumerate() {
            if self.matches_pattern(pattern) {
                return Some(i);
            }
        }
        None
    }

    // ---- Serialization ----

    /// Generate serialized AD bytes in TLV format.
    pub fn generate(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.max_len);

        // Service UUIDs (grouped by size)
        self.serialize_uuid_group(&mut out, 2, BT_AD_UUID16_ALL);
        self.serialize_uuid_group(&mut out, 4, BT_AD_UUID32_ALL);
        self.serialize_uuid_group(&mut out, 16, BT_AD_UUID128_ALL);

        // Solicit UUIDs
        self.serialize_uuid_solicit_group(&mut out, 2, BT_AD_SOLICIT16);
        self.serialize_uuid_solicit_group(&mut out, 4, BT_AD_SOLICIT32);
        self.serialize_uuid_solicit_group(&mut out, 16, BT_AD_SOLICIT128);

        // Manufacturer data
        for m in &self.manufacturer_data {
            let len = 3 + m.data.len(); // type(1) + manufacturer_id(2) + data
            if out.len() + 1 + len > self.max_len {
                break;
            }
            out.push(len as u8);
            out.push(BT_AD_MANUFACTURER_DATA);
            out.extend_from_slice(&m.manufacturer_id.to_le_bytes());
            out.extend_from_slice(&m.data);
        }

        // Service data
        for s in &self.service_data {
            let uuid_len = s.uuid.len();
            let sd_type = match uuid_len {
                2 => BT_AD_SERVICE_DATA16,
                4 => BT_AD_SERVICE_DATA32,
                _ => BT_AD_SERVICE_DATA128,
            };
            let uuid_bytes = uuid_to_le_bytes(&s.uuid);
            let len = 1 + uuid_bytes.len() + s.data.len();
            if out.len() + 1 + len > self.max_len {
                break;
            }
            out.push(len as u8);
            out.push(sd_type);
            out.extend_from_slice(&uuid_bytes);
            out.extend_from_slice(&s.data);
        }

        // Name
        if let Some(name) = &self.name {
            let name_bytes = name.as_bytes();
            let available = self.max_len.saturating_sub(out.len() + 2);
            if available > 0 {
                let (ad_type, truncated) = if name_bytes.len() <= available {
                    (BT_AD_NAME_COMPLETE, name_bytes)
                } else {
                    (BT_AD_NAME_SHORT, &name_bytes[..available])
                };
                out.push((1 + truncated.len()) as u8);
                out.push(ad_type);
                out.extend_from_slice(truncated);
            }
        }

        // Appearance
        if let Some(appearance) = self.appearance {
            if out.len() + 4 <= self.max_len {
                out.push(3);
                out.push(BT_AD_GAP_APPEARANCE);
                out.extend_from_slice(&appearance.to_le_bytes());
            }
        }

        // Generic data
        for d in &self.data {
            let len = 1 + d.data.len();
            if out.len() + 1 + len > self.max_len {
                break;
            }
            out.push(len as u8);
            out.push(d.ad_type);
            out.extend_from_slice(&d.data);
        }

        out
    }

    /// Total serialized length.
    pub fn length(&self) -> usize {
        self.generate().len()
    }

    // ---- Internal ----

    fn parse_tlv(&mut self, ad_type: u8, value: &[u8]) {
        match ad_type {
            BT_AD_FLAGS => {
                if let Some(&flags) = value.first() {
                    self.add_flags(flags);
                }
            }
            BT_AD_UUID16_SOME | BT_AD_UUID16_ALL => {
                for chunk in value.chunks_exact(2) {
                    let uuid = Uuid::from_u16(u16::from_le_bytes([chunk[0], chunk[1]]));
                    self.add_service_uuid(uuid);
                }
            }
            BT_AD_UUID32_SOME | BT_AD_UUID32_ALL => {
                for chunk in value.chunks_exact(4) {
                    let uuid = Uuid::from_u32(u32::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3],
                    ]));
                    self.add_service_uuid(uuid);
                }
            }
            BT_AD_UUID128_SOME | BT_AD_UUID128_ALL => {
                for chunk in value.chunks_exact(16) {
                    let mut be = [0u8; 16];
                    be.copy_from_slice(chunk);
                    be.reverse();
                    self.add_service_uuid(Uuid::from_u128_bytes(be));
                }
            }
            BT_AD_NAME_SHORT | BT_AD_NAME_COMPLETE => {
                if let Ok(name) = std::str::from_utf8(value) {
                    self.set_name(name);
                }
            }
            BT_AD_GAP_APPEARANCE => {
                if value.len() >= 2 {
                    self.set_appearance(u16::from_le_bytes([value[0], value[1]]));
                }
            }
            BT_AD_MANUFACTURER_DATA => {
                if value.len() >= 2 {
                    let id = u16::from_le_bytes([value[0], value[1]]);
                    self.add_manufacturer_data(id, &value[2..]);
                }
            }
            BT_AD_SERVICE_DATA16 => {
                if value.len() >= 2 {
                    let uuid = Uuid::from_u16(u16::from_le_bytes([value[0], value[1]]));
                    self.add_service_data(uuid, &value[2..]);
                }
            }
            BT_AD_SERVICE_DATA32 => {
                if value.len() >= 4 {
                    let uuid = Uuid::from_u32(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                    self.add_service_data(uuid, &value[4..]);
                }
            }
            BT_AD_SERVICE_DATA128 => {
                if value.len() >= 16 {
                    let mut be = [0u8; 16];
                    be.copy_from_slice(&value[..16]);
                    be.reverse();
                    self.add_service_data(Uuid::from_u128_bytes(be), &value[16..]);
                }
            }
            BT_AD_SOLICIT16 => {
                for chunk in value.chunks_exact(2) {
                    self.add_solicit_uuid(Uuid::from_u16(u16::from_le_bytes([
                        chunk[0], chunk[1],
                    ])));
                }
            }
            BT_AD_SOLICIT32 => {
                for chunk in value.chunks_exact(4) {
                    self.add_solicit_uuid(Uuid::from_u32(u32::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3],
                    ])));
                }
            }
            BT_AD_SOLICIT128 => {
                for chunk in value.chunks_exact(16) {
                    let mut be = [0u8; 16];
                    be.copy_from_slice(chunk);
                    be.reverse();
                    self.add_solicit_uuid(Uuid::from_u128_bytes(be));
                }
            }
            _ => {
                self.data.push(AdData {
                    ad_type,
                    data: value.to_vec(),
                });
            }
        }
    }

    fn serialize_uuid_group(&self, out: &mut Vec<u8>, uuid_byte_len: usize, ad_type: u8) {
        let uuids: Vec<&Uuid> = self
            .service_uuids
            .iter()
            .filter(|u| u.len() == uuid_byte_len)
            .collect();

        if uuids.is_empty() {
            return;
        }

        let total_uuid_bytes: usize = uuids.len() * uuid_byte_len;
        let len = 1 + total_uuid_bytes;
        if out.len() + 1 + len > self.max_len {
            return;
        }

        out.push(len as u8);
        out.push(ad_type);
        for uuid in uuids {
            out.extend_from_slice(&uuid_to_le_bytes(uuid));
        }
    }

    fn serialize_uuid_solicit_group(
        &self,
        out: &mut Vec<u8>,
        uuid_byte_len: usize,
        ad_type: u8,
    ) {
        let uuids: Vec<&Uuid> = self
            .solicit_uuids
            .iter()
            .filter(|u| u.len() == uuid_byte_len)
            .collect();

        if uuids.is_empty() {
            return;
        }

        let total_uuid_bytes: usize = uuids.len() * uuid_byte_len;
        let len = 1 + total_uuid_bytes;
        if out.len() + 1 + len > self.max_len {
            return;
        }

        out.push(len as u8);
        out.push(ad_type);
        for uuid in uuids {
            out.extend_from_slice(&uuid_to_le_bytes(uuid));
        }
    }

    fn matches_pattern(&self, pattern: &AdPattern) -> bool {
        let offset = pattern.offset as usize;

        // Check manufacturer data
        if pattern.ad_type == BT_AD_MANUFACTURER_DATA {
            for m in &self.manufacturer_data {
                // Manufacturer data includes the 2-byte ID in offset calculation
                let full: Vec<u8> = m
                    .manufacturer_id
                    .to_le_bytes()
                    .iter()
                    .chain(m.data.iter())
                    .copied()
                    .collect();
                if offset + pattern.data.len() <= full.len()
                    && full[offset..offset + pattern.data.len()] == pattern.data
                {
                    return true;
                }
            }
            return false;
        }

        // Check service data
        for s in &self.service_data {
            let sd_type = match s.uuid.len() {
                2 => BT_AD_SERVICE_DATA16,
                4 => BT_AD_SERVICE_DATA32,
                _ => BT_AD_SERVICE_DATA128,
            };
            if sd_type == pattern.ad_type {
                let uuid_bytes = uuid_to_le_bytes(&s.uuid);
                let full: Vec<u8> = uuid_bytes
                    .iter()
                    .chain(s.data.iter())
                    .copied()
                    .collect();
                if offset + pattern.data.len() <= full.len()
                    && full[offset..offset + pattern.data.len()] == pattern.data
                {
                    return true;
                }
            }
        }

        // Check generic data
        for d in &self.data {
            if d.ad_type == pattern.ad_type
                && offset + pattern.data.len() <= d.data.len()
                && d.data[offset..offset + pattern.data.len()] == pattern.data
            {
                return true;
            }
        }

        false
    }
}

impl Default for BtAd {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an AD type is handled by dedicated APIs (not generic data).
fn is_dedicated_type(ad_type: u8) -> bool {
    matches!(
        ad_type,
        BT_AD_UUID16_SOME
            | BT_AD_UUID16_ALL
            | BT_AD_UUID32_SOME
            | BT_AD_UUID32_ALL
            | BT_AD_UUID128_SOME
            | BT_AD_UUID128_ALL
            | BT_AD_NAME_SHORT
            | BT_AD_NAME_COMPLETE
            | BT_AD_GAP_APPEARANCE
            | BT_AD_MANUFACTURER_DATA
            | BT_AD_SERVICE_DATA16
            | BT_AD_SERVICE_DATA32
            | BT_AD_SERVICE_DATA128
            | BT_AD_SOLICIT16
            | BT_AD_SOLICIT32
            | BT_AD_SOLICIT128
    )
}

/// Convert a UUID to little-endian bytes for AD serialization.
fn uuid_to_le_bytes(uuid: &Uuid) -> Vec<u8> {
    match uuid {
        Uuid::Uuid16(v) => v.to_le_bytes().to_vec(),
        Uuid::Uuid32(v) => v.to_le_bytes().to_vec(),
        Uuid::Uuid128(bytes) => {
            let mut le = *bytes;
            le.reverse();
            le.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let ad = BtAd::new();
        assert!(ad.is_empty());
    }

    #[test]
    fn test_service_uuid() {
        let mut ad = BtAd::new();
        assert!(ad.add_service_uuid(Uuid::from_u16(0x180F)));
        assert!(!ad.add_service_uuid(Uuid::from_u16(0x180F))); // duplicate
        assert!(ad.has_service_uuid(&Uuid::from_u16(0x180F)));
        assert!(ad.remove_service_uuid(&Uuid::from_u16(0x180F)));
        assert!(!ad.has_service_uuid(&Uuid::from_u16(0x180F)));
    }

    #[test]
    fn test_manufacturer_data() {
        let mut ad = BtAd::new();
        assert!(ad.add_manufacturer_data(0x004C, &[1, 2, 3]));
        assert!(!ad.add_manufacturer_data(0x004C, &[1, 2, 3])); // identical
        assert!(ad.add_manufacturer_data(0x004C, &[4, 5])); // update
        assert!(ad.has_manufacturer_data(0x004C));
    }

    #[test]
    fn test_name() {
        let mut ad = BtAd::new();
        ad.set_name("Test Device");
        assert_eq!(ad.get_name(), Some("Test Device"));
        ad.clear_name();
        assert_eq!(ad.get_name(), None);
    }

    #[test]
    fn test_flags() {
        let mut ad = BtAd::new();
        ad.add_flags(BT_AD_FLAG_GENERAL | BT_AD_FLAG_NO_BREDR);
        assert!(ad.has_flags());
        assert_eq!(ad.get_flags(), Some(0x06));
        ad.clear_flags();
        assert!(!ad.has_flags());
    }

    #[test]
    fn test_generate_and_parse() {
        let mut ad = BtAd::new();
        ad.add_service_uuid(Uuid::from_u16(0x180F));
        ad.set_name("Test");
        ad.add_flags(BT_AD_FLAG_GENERAL | BT_AD_FLAG_NO_BREDR);

        let bytes = ad.generate();
        assert!(!bytes.is_empty());

        // Parse back
        let parsed = BtAd::from_bytes(&bytes);
        assert!(parsed.has_service_uuid(&Uuid::from_u16(0x180F)));
        assert_eq!(parsed.get_name(), Some("Test"));
        assert_eq!(parsed.get_flags(), Some(0x06));
    }

    #[test]
    fn test_service_data() {
        let mut ad = BtAd::new();
        ad.add_service_data(Uuid::from_u16(0x180F), &[100]);
        assert!(ad.has_service_data(&Uuid::from_u16(0x180F)));

        let bytes = ad.generate();
        let parsed = BtAd::from_bytes(&bytes);
        assert!(parsed.has_service_data(&Uuid::from_u16(0x180F)));
    }

    #[test]
    fn test_pattern_match() {
        let mut ad = BtAd::new();
        ad.add_manufacturer_data(0x004C, &[0x02, 0x15, 0xAA]);

        let pattern = AdPattern {
            ad_type: BT_AD_MANUFACTURER_DATA,
            offset: 0,
            data: vec![0x4C, 0x00], // manufacturer ID in LE
        };

        assert_eq!(ad.pattern_match(&[pattern]), Some(0));
    }

    #[test]
    fn test_appearance() {
        let mut ad = BtAd::new();
        ad.set_appearance(0x0040); // Generic Phone

        let bytes = ad.generate();
        let parsed = BtAd::from_bytes(&bytes);
        assert_eq!(parsed.appearance, Some(0x0040));
    }

    #[test]
    fn test_name_truncation() {
        let mut ad = BtAd::new();
        ad.set_max_len(10);
        ad.set_name("Very Long Device Name");

        let bytes = ad.generate();
        // Should be truncated: len(1) + type(1) + truncated_name(8) = 10
        assert!(bytes.len() <= 10);
        assert_eq!(bytes[1], BT_AD_NAME_SHORT);
    }

    #[test]
    fn test_default_trait() {
        let ad = BtAd::default();
        assert!(ad.is_empty());
    }
}
